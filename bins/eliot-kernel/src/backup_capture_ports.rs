//! Kernel-owned capture ports: caller admission, frozen plan, snapshot relation,
//! owner-neutral evidence bundle, single-publication port, fail-closed errors.
//!
//! Architecture: I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); A13.6 Operational Recovery State (only identities,
//! opaque envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors — never semantic claims); I14.21 unknown-commit recovery (reconcile
//! by identity, never blind retry); I14.3 Control Reserve (bounded capture
//! work; budgets per owner and cumulatively); I7.20 agent-facing error contract
//! (typed refusals with exact reason, never silence or fabricated success).
//!
//! What this file owns: the capture admission gate
//! (`require_capture_admitted`), the frozen per-operation plan
//! (`FrozenCapturePlan` with finite `CaptureBudgets`), the cross-owner
//! snapshot relation (`SnapshotRelation`, where matching timestamps alone
//! prove nothing), the already-accepted owner-evidence bundle (`CapturePorts`),
//! the exactly-once publication port (`PublicationPort`), and the fail-closed
//! `KernelCaptureError` vocabulary with lossless mapping onto the accepted
//! `BackupError` seam (`KernelCaptureError::to_backup`).
//!
//! What this file deliberately does NOT own: any live owner channel, any
//! global cross-store transaction, stop-the-world barrier, or distributed
//! snapshot service. The ORS and canonical export are not one cross-store
//! transaction: each owner supplies its own coherent snapshot and this file
//! only records and validates their exact relation. No such transaction,
//! barrier, or service type exists anywhere in this file by construction.
//!
//! Capability cell: Kernel capture ownership (admission, plan freeze, relation
//! validation, evidence shape validation, publication identity).
//! Forbidden authority: no ORS row interpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no plaintext key
//! handling, no second archive format, no concrete Surreal/Host/Watchdog
//! binary dependency.

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupClass, BackupError, CanonicalRecord, ExportFence,
    HostStateAuditFence, OrsSnapshotFence, WatchdogSpoolFence,
};
use eliot_contracts::StateFence;
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;

/// Caller authentication behind one capture operation.
///
/// The value is owner-supplied admission evidence, never minted here: the
/// coordinator refuses any capture whose caller is not admitted before a
/// single protected source read or publication attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCallerAuth {
    /// Stable principal identity requesting the capture.
    pub principal: String,
    /// Capability the principal presents for capture.
    pub capability: String,
    /// Whether the caller is admitted for capture operations.
    pub admitted: bool,
}

/// Requires admitted capture authentication before any owner read.
///
/// Fails closed: a blank principal/capability refuses as invalid input, and an
/// unadmitted caller refuses as not admitted. Mirrors
/// `require_production_admitted` on the restore side.
pub fn require_capture_admitted(auth: &CaptureCallerAuth) -> Result<(), KernelCaptureError> {
    non_blank(&auth.principal, "capture.principal")?;
    non_blank(&auth.capability, "capture.capability")?;
    if auth.admitted {
        Ok(())
    } else {
        Err(KernelCaptureError::NotAdmitted)
    }
}

/// Finite per-owner and cumulative budgets bounding one capture operation.
///
/// Every bound is nonzero; the total byte budget must cover at least one owner
/// share. Capture performs no unbounded waits: work that does not fit the
/// frozen budgets refuses instead of consuming the control reserve silently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBudgets {
    /// Maximum snapshot pages consumed from any single owner.
    pub max_pages_per_owner: u64,
    /// Maximum evidence bytes accepted from any single owner.
    pub max_bytes_per_owner: u64,
    /// Maximum evidence bytes accepted across all owners.
    pub max_bytes_total: u64,
    /// Maximum enumerated work items across all owners.
    pub max_work_items: u64,
    /// Maximum admitted capture duration in milliseconds (ceiling only;
    /// capture never waits for a globally quiet instant).
    pub max_duration_ms: u64,
}

impl CaptureBudgets {
    /// Validates that every budget bound is nonzero and the total byte budget
    /// covers at least one owner share.
    pub fn validate(&self) -> Result<(), KernelCaptureError> {
        if self.max_pages_per_owner == 0 {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.max_pages_per_owner",
                reason: "budget must be nonzero",
            });
        }
        if self.max_bytes_per_owner == 0 {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.max_bytes_per_owner",
                reason: "budget must be nonzero",
            });
        }
        if self.max_bytes_total < self.max_bytes_per_owner {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.max_bytes_total",
                reason: "total budget must cover one owner share",
            });
        }
        if self.max_work_items == 0 {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.max_work_items",
                reason: "budget must be nonzero",
            });
        }
        if self.max_duration_ms == 0 {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.max_duration_ms",
                reason: "budget must be nonzero",
            });
        }
        Ok(())
    }

    /// Checks per-owner byte counts against the per-owner ceiling and their
    /// saturating sum against the cumulative ceiling.
    pub fn check_cumulative(&self, per_owner_bytes: &[u64]) -> Result<(), KernelCaptureError> {
        let mut total: u64 = 0;
        for bytes in per_owner_bytes {
            if *bytes > self.max_bytes_per_owner {
                return Err(KernelCaptureError::BudgetExceeded {
                    field: "capture.bytes_per_owner",
                });
            }
            total = total.saturating_add(*bytes);
        }
        if total > self.max_bytes_total {
            return Err(KernelCaptureError::BudgetExceeded {
                field: "capture.bytes_total",
            });
        }
        Ok(())
    }

    /// Checks per-owner item counts against the per-owner page ceiling and
    /// their saturating sum against the cumulative work ceiling.
    pub fn check_work_items(&self, per_owner_items: &[u64]) -> Result<(), KernelCaptureError> {
        let mut total: u64 = 0;
        for items in per_owner_items {
            if *items > self.max_pages_per_owner {
                return Err(KernelCaptureError::BudgetExceeded {
                    field: "capture.pages_per_owner",
                });
            }
            total = total.saturating_add(*items);
        }
        if total > self.max_work_items {
            return Err(KernelCaptureError::BudgetExceeded {
                field: "capture.work_items",
            });
        }
        Ok(())
    }
}

/// Frozen capture plan: the requested class, scope, source, schema, build and
/// policy bindings, and finite budgets admitted for exactly one operation.
///
/// The plan freezes before any owner read; later evidence must match it.
/// Capability absence yields an explicit class-specific refusal, never a
/// silent substitution of a weaker class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenCapturePlan {
    /// Requested backup class (`full_recovery`, `canonical_only_degraded`,
    /// `scope_export`).
    pub class: BackupClass,
    /// Declared scope for `scope_export`; forbidden for other classes.
    pub scope_id: Option<String>,
    /// Canonical source adapter identity the evidence must come from.
    pub source_adapter: String,
    /// Schema generation the evidence must conform to.
    pub schema_generation: String,
    /// Approved build manifest digest (64-hex) the capture is bound to.
    pub build_digest: String,
    /// Approved policy manifest digest (64-hex) the capture is bound to.
    pub policy_digest: String,
    /// Finite per-owner and cumulative budgets for the operation.
    pub budgets: CaptureBudgets,
}

impl FrozenCapturePlan {
    /// Validates the frozen plan shape: a scope export requires exactly one
    /// declared scope while non-scope classes refuse any scope (mirroring
    /// `BackupError::ScopeRequired` / `BackupError::ScopeUnexpected`), source
    /// bindings are non-blank, manifest digests are 64-hex, and budgets are
    /// finite.
    pub fn validate(&self) -> Result<(), KernelCaptureError> {
        match (&self.class, &self.scope_id) {
            (BackupClass::ScopeExport, Some(scope)) => {
                non_blank(scope, "capture.scope_id")?;
            }
            (BackupClass::ScopeExport, None) => {
                return Err(KernelCaptureError::InvalidInput {
                    field: "capture.scope_id",
                    reason: "scope export requires one declared scope",
                });
            }
            (_, Some(_)) => {
                return Err(KernelCaptureError::InvalidInput {
                    field: "capture.scope_id",
                    reason: "non-scope export cannot carry a scope",
                });
            }
            (_, None) => {}
        }
        non_blank(&self.source_adapter, "capture.source_adapter")?;
        non_blank(&self.schema_generation, "capture.schema_generation")?;
        if !is_hex64(&self.build_digest) {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.build_digest",
                reason: "must be a 64-hex digest",
            });
        }
        if !is_hex64(&self.policy_digest) {
            return Err(KernelCaptureError::InvalidInput {
                field: "capture.policy_digest",
                reason: "must be a 64-hex digest",
            });
        }
        self.budgets.validate()
    }
}

/// Exact relation between independently coherent owner snapshots.
///
/// Canonical, ORS, and Watchdog owners each provide their own coherent
/// snapshot; this record binds them: source installation and generation,
/// authority lineage, canonical receipt/event/outbox cursors, pending
/// operation identities and hashes, checkpoints, cutovers, spool signals and
/// gaps, per-owner capture times, and fence compatibility. Matching timestamps
/// alone prove nothing: a timestamp-only relation, empty cursors and lineage,
/// or incompatible fences refuse as incoherent. No global-transaction claim
/// exists anywhere in this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRelation {
    /// Source installation identity the snapshots were taken from.
    pub installation_id: String,
    /// Canonical store generation the snapshots were taken from.
    pub store_generation: String,
    /// Authority lineage the snapshots were taken under.
    pub authority_lineage: String,
    /// Highest canonical receipt cursor covered by the relation.
    pub receipt_cursor: u64,
    /// Highest canonical event cursor covered by the relation.
    pub event_cursor: u64,
    /// Highest canonical outbox cursor covered by the relation.
    pub outbox_cursor: u64,
    /// Pending operation identities at the ORS frontier.
    pub pending_operation_ids: Vec<String>,
    /// Pending operation hashes at the ORS frontier.
    pub pending_operation_hashes: Vec<String>,
    /// Job checkpoint identities covered by the relation.
    pub checkpoint_ids: Vec<String>,
    /// Generation cutover identities covered by the relation.
    pub cutover_ids: Vec<String>,
    /// Unresolved Watchdog spool signal digests covered by the relation.
    pub spool_signal_digests: Vec<String>,
    /// Explained Watchdog spool gaps covered by the relation.
    pub spool_gaps: Vec<String>,
    /// Per-owner capture times in milliseconds (observed only; never
    /// sufficient on their own).
    pub capture_time_ms_per_owner: Vec<(String, u64)>,
    /// Whether every carried owner fence is compatible with the export fence.
    pub fence_compatible: bool,
    /// Whether the relation carries timestamps alone with no cursor or
    /// lineage evidence (always refuses).
    pub timestamps_only: bool,
}

impl SnapshotRelation {
    /// Validates that the recorded relation is more than matching timestamps:
    /// timestamp-only relations refuse, incompatible fences refuse, and empty
    /// installation, generation, lineage, or cursor evidence refuses as
    /// incoherent.
    pub fn validate_relation(&self) -> Result<(), KernelCaptureError> {
        if self.timestamps_only {
            return Err(KernelCaptureError::RelationIncoherent(
                "timestamps alone prove nothing; cursors and lineage required".to_owned(),
            ));
        }
        if !self.fence_compatible {
            return Err(KernelCaptureError::RelationIncoherent(
                "owner fences are not compatible".to_owned(),
            ));
        }
        relation_text(&self.installation_id, "installation id")?;
        relation_text(&self.store_generation, "store generation")?;
        relation_text(&self.authority_lineage, "authority lineage")?;
        if self.receipt_cursor == 0 && self.event_cursor == 0 && self.outbox_cursor == 0 {
            return Err(KernelCaptureError::RelationIncoherent(
                "cursors are empty; timestamps alone prove nothing".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Per-execution capture port bundle: already-accepted owner evidence as plain
/// data references, plus the caller admission and the Kernel fence the
/// evidence must satisfy.
///
/// Every reference is caller-supplied owner evidence validated by
/// `validate_shapes` and re-checked at each coordinator gate. No live owner
/// handle, database read path, or snapshot service travels in this struct.
pub struct CapturePorts<'a> {
    /// Admitted caller authentication behind the capture.
    pub caller: &'a CaptureCallerAuth,
    /// The Kernel's current authority fence (never caller arithmetic).
    pub kernel_fence: &'a StateFence,
    /// Coherent canonical export fence binding the capture.
    pub export_fence: &'a ExportFence,
    /// Canonical event records carried by the capture.
    pub canonical_events: &'a [CanonicalRecord],
    /// Canonical projection records carried by the capture.
    pub projections: &'a [CanonicalRecord],
    /// Canonical write receipts carried by the capture.
    pub receipts: &'a [WriteReceipt],
    /// Sealed blob envelopes carried by the capture (never plaintext).
    pub blobs: &'a [BackupBlob],
    /// Purge ledger entries carried by the capture.
    pub purge_ledger: &'a [PurgeLedgerEntry],
    /// Checksummed config, policy, module, and build manifest artifacts.
    pub artifacts: &'a [BackupArtifact],
    /// Logical ORS snapshot fence, when the class carries one.
    pub ors_snapshot: Option<&'a OrsSnapshotFence>,
    /// Count of suspended recovery entries derived from the ORS snapshot.
    pub suspended_count: u64,
    /// Bounded Watchdog spool fence, when the class carries one.
    pub watchdog_spool: Option<&'a WatchdogSpoolFence>,
    /// Optional forensic Host audit fence (never active authority).
    pub host_audit: Option<&'a HostStateAuditFence>,
}

impl CapturePorts<'_> {
    /// Validates the structural shape of every carried evidence value by
    /// calling each element's own `validate`. Admission is decided by the
    /// coordinator through `require_capture_admitted`, not here.
    pub fn validate_shapes(&self) -> Result<(), KernelCaptureError> {
        non_blank(&self.caller.principal, "capture.principal")?;
        non_blank(&self.caller.capability, "capture.capability")?;
        self.kernel_fence
            .validate()
            .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        self.export_fence
            .validate()
            .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        for record in self.canonical_events.iter().chain(self.projections.iter()) {
            record
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        for receipt in self.receipts {
            receipt
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        for blob in self.blobs {
            blob.validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        for entry in self.purge_ledger {
            entry
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        for artifact in self.artifacts {
            artifact
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        if let Some(snapshot) = self.ors_snapshot {
            snapshot
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        if let Some(spool) = self.watchdog_spool {
            spool
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        if let Some(audit) = self.host_audit {
            audit
                .validate()
                .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        Ok(())
    }
}

/// One immutable verified archive bound to its single publication operation:
/// archive digest, operation identity, idempotency key, and durability note.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedArchive {
    /// Archive backup identity bound at build.
    pub backup_id: String,
    /// Deterministic digest of the complete encoded archive.
    pub archive_sha256: String,
    /// Publication operation identity (exactly one publish per operation).
    pub operation_id: String,
    /// Idempotency key binding backup identity and archive digest.
    pub idempotency_key: String,
    /// Owner durability note accompanying the receipt.
    pub durability_note: String,
}

/// Durable receipt for one publication operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    /// Publication operation identity the receipt answers for.
    pub operation_id: String,
    /// Archive digest the receipt confirms as durable.
    pub archive_sha256: String,
    /// Whether the archive is durably recorded by the owner.
    pub durable: bool,
}

/// Publication port over the admitted artifact/blob owner.
///
/// Exactly one `publish_once` call happens per admitted capture operation with
/// the exact operation identity and idempotency key. A lost publication
/// response reconciles the SAME operation by identity through `reconcile`:
/// the coordinator never publishes twice, and byte-equality of two archives
/// or a process exit code is never attribution of durability.
pub trait PublicationPort {
    /// Publishes the verified archive bytes exactly once under the given
    /// operation identity and idempotency key.
    fn publish_once(
        &mut self,
        operation_id: &str,
        idempotency_key: &str,
        bytes: &[u8],
    ) -> Result<PublicationReceipt, KernelCaptureError>;

    /// Reconciles a lost publication response by operation identity, adopting
    /// the owner's durable receipt for the same operation without a second
    /// publish.
    fn reconcile(&mut self, operation_id: &str) -> Result<PublicationReceipt, KernelCaptureError>;
}

/// Typed fail-closed errors for the Kernel capture owner.
///
/// Every variant refuses an effect, an admission, or a publication; none
/// fabricates success. All messages use a stable lowercase vocabulary.
#[derive(Clone, Debug, PartialEq)]
pub enum KernelCaptureError {
    /// The caller is not admitted for capture; effects are refused.
    NotAdmitted,
    /// A caller-supplied field is malformed.
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    /// A required class capability is absent; the capture refuses without
    /// silently substituting a weaker class.
    ClassCapabilityUnsupported {
        class: &'static str,
        capability: &'static str,
    },
    /// Owner snapshots do not form a coherent relation.
    RelationIncoherent(String),
    /// Referenced source material has no complete member denominator.
    DenominatorIncomplete(String),
    /// A per-owner or cumulative budget bound is exceeded.
    BudgetExceeded { field: &'static str },
    /// The capture was cancelled before completion.
    Cancelled,
    /// A required capability is explicitly unsupported here.
    Unsupported { reason: &'static str },
    /// The archive failed build, validation, or encoding.
    ArchiveInvalid(String),
    /// The publication outcome is unknown; reconcile by identity.
    PublicationUnknown(String),
    /// Owner-issued evidence is invalid or incoherent.
    OwnerEvidenceInvalid(String),
}

impl KernelCaptureError {
    /// Maps a Kernel capture refusal onto the accepted backup seam without
    /// losing the causal class.
    ///
    /// Shape refusals keep their accepted variant; class-capability and
    /// denominator refusals cross as a missing recovery component for the
    /// capture; cancellation crosses as a typed target failure; an unknown
    /// publication outcome crosses as rollback-required so the coordinator
    /// reconciles by identity instead of blind-retrying.
    #[must_use]
    pub fn to_backup(self) -> BackupError {
        match self {
            Self::NotAdmitted => BackupError::Target("capture not admitted".to_owned()),
            Self::InvalidInput { field, reason } => BackupError::InvalidField { field, reason },
            Self::ClassCapabilityUnsupported { .. } | Self::DenominatorIncomplete(_) => {
                BackupError::MissingRecoveryComponent("capture")
            }
            Self::RelationIncoherent(detail) => BackupError::FenceMismatch { subject: detail },
            Self::BudgetExceeded { field } => BackupError::LimitExceeded { field, limit: 0 },
            Self::Cancelled => BackupError::Target("capture cancelled".to_owned()),
            Self::Unsupported { reason } => {
                BackupError::RestoreCapabilityUnsupported { capability: reason }
            }
            Self::ArchiveInvalid(detail) | Self::OwnerEvidenceInvalid(detail) => {
                BackupError::Target(detail)
            }
            Self::PublicationUnknown(_) => BackupError::RestoreRollbackRequired,
        }
    }
}

impl std::fmt::Display for KernelCaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAdmitted => {
                write!(formatter, "capture caller is not admitted; effects refused")
            }
            Self::InvalidInput { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::ClassCapabilityUnsupported { class, capability } => {
                write!(
                    formatter,
                    "class {class} requires capability {capability}; no weaker class substituted"
                )
            }
            Self::RelationIncoherent(detail) => {
                write!(formatter, "snapshot relation incoherent: {detail}")
            }
            Self::DenominatorIncomplete(detail) => {
                write!(formatter, "capture denominator incomplete: {detail}")
            }
            Self::BudgetExceeded { field } => {
                write!(formatter, "capture budget exceeded: {field}")
            }
            Self::Cancelled => write!(formatter, "capture cancelled"),
            Self::Unsupported { reason } => {
                write!(formatter, "capture capability unsupported: {reason}")
            }
            Self::ArchiveInvalid(detail) => {
                write!(formatter, "capture archive invalid: {detail}")
            }
            Self::PublicationUnknown(detail) => {
                write!(formatter, "capture publication unknown: {detail}")
            }
            Self::OwnerEvidenceInvalid(detail) => {
                write!(formatter, "owner-issued capture evidence invalid: {detail}")
            }
        }
    }
}

impl std::error::Error for KernelCaptureError {}

fn non_blank(value: &str, field: &'static str) -> Result<(), KernelCaptureError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(KernelCaptureError::InvalidInput {
            field,
            reason: "must be non-blank with no control characters",
        });
    }
    Ok(())
}

fn relation_text(value: &str, what: &str) -> Result<(), KernelCaptureError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(KernelCaptureError::RelationIncoherent(format!(
            "{what} is empty"
        )));
    }
    Ok(())
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
