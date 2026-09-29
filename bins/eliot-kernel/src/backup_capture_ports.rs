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
//! the adapters onto accepted owner-neutral APIs only
//! (`owner_residency_key_digest`, `owner_suspended_recovery_refs`,
//! `owner_fence_dispositions`), the exactly-once publication port
//! (`PublicationPort`) together with the production retained-archive owner that
//! implements it (`KernelArchiveOwner`), and the fail-closed
//! `KernelCaptureError` vocabulary
//! with lossless mapping onto the accepted `BackupError` seam
//! (`KernelCaptureError::to_backup`).
//!
//! Every adapter below is a thin projection of an API an owner already
//! publishes. None of them derives a value the owner does not publish, keeps a
//! second copy of an owner's own rule, or invents an owner: the residency
//! digest, the suspended-recovery frontier and the fence member set are all
//! read from the owner that declares them, and an owner that refuses is
//! reported as a refusal rather than smoothed over.
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

use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupClass, BackupError, CanonicalRecord, ExportFence,
    HostStateAuditFence, OrsSnapshotFence, WatchdogSpoolFence, suspended_recovery_entries,
};
use eliot_contracts::{StateFence, sha256_hex};
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

    /// Checks the elapsed admitted duration against the frozen ceiling.
    ///
    /// `max_duration_ms` is a ceiling on the admitted operation, not a shape
    /// field: a capture that has already spent it cannot be completed inside
    /// the authorisation the caller granted, so the honest outcome is the typed
    /// [`KernelCaptureError::Cancelled`] rather than a silent overrun of the
    /// Control Reserve. I5.16 keeps incomplete coverage explicit, and A13.9
    /// requires a durable job to carry a budget — a budget nobody reads is not
    /// a bound.
    pub fn check_duration(&self, elapsed_ms: u64) -> Result<(), KernelCaptureError> {
        if elapsed_ms > self.max_duration_ms {
            return Err(KernelCaptureError::Cancelled);
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
    /// Pending operation identities at the ORS frontier, read through the
    /// archive owner's own suspended derivation
    /// ([`owner_suspended_recovery_refs`]).
    pub pending_operation_ids: Vec<String>,
    /// Pending operation hashes at the ORS frontier.
    ///
    /// EMPTY IS NOT A CLAIM. No accepted owner-neutral ORS type reports a
    /// per-operation hash: `OrsSnapshotFence` records identities, checkpoints
    /// and cutovers only. This vector therefore stays empty because the
    /// dimension is unreportable, and a reader must not read it as "the ORS
    /// owner reported no pending hashes" — the honest reading of I5.13's
    /// "identities and hashes" is that only the identities exist, and this
    /// owner records exactly what the owner gives rather than inventing the
    /// other half.
    pub pending_operation_hashes: Vec<String>,
    /// Job checkpoint identities covered by the relation.
    pub checkpoint_ids: Vec<String>,
    /// Generation cutover identities covered by the relation.
    pub cutover_ids: Vec<String>,
    /// Unresolved Watchdog spool signal digests covered by the relation, read
    /// from the Watchdog owner's own `unresolved_signal_digests`.
    pub spool_signal_digests: Vec<String>,
    /// Explained Watchdog spool gaps covered by the relation.
    ///
    /// EMPTY IS NOT A CLAIM, for the same reason as
    /// [`Self::pending_operation_hashes`]: no accepted owner-neutral Watchdog
    /// type reports a gap. `WatchdogSpoolFence` publishes a bounded set of
    /// unresolved signal digests and nothing else, and no document defines a
    /// gap vocabulary this owner could fill, so the dimension is recorded as
    /// unreportable rather than reported as "no gaps".
    pub spool_gaps: Vec<String>,
    /// Per-owner capture times in milliseconds (observed only; never
    /// sufficient on their own).
    ///
    /// EMPTY IS NOT A CLAIM. Every accepted owner-neutral type hands this owner
    /// already-acquired evidence and none of them reports the instant it was
    /// acquired, so there is one admitted operation rather than six per-owner
    /// clocks to record. Repeating this operation's own elapsed time once per
    /// owner would be an invented per-owner observation, so the vector stays
    /// empty and I5.13's "matching timestamps alone prove nothing" is honoured
    /// by never presenting a timestamp as evidence at all.
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

impl<'a> CapturePorts<'a> {
    /// Assembles the production evidence bundle from owner-issued values and
    /// validates every one of them before the bundle is usable.
    ///
    /// This is the only production construction site of [`CapturePorts`], and it
    /// adds nothing to what the caller passes: each argument is a value an owner
    /// already produced, validated here through that value's own `validate` and
    /// nothing else. It performs no defaulting, no empty-vector substitution and
    /// no optimistic admission — a caller that cannot supply a member the frozen
    /// class requires gets a typed refusal from [`Self::validate_shapes`] or
    /// from the coordinator's class gate, never a bundle that looks complete.
    ///
    /// The parameter list is one value per capture member domain. A builder
    /// would only move the same values from one place to another.
    #[allow(
        clippy::too_many_arguments,
        reason = "one owner-issued value per capture member domain; a builder would only move them"
    )]
    pub fn from_owner_evidence(
        caller: &'a CaptureCallerAuth,
        kernel_fence: &'a StateFence,
        export_fence: &'a ExportFence,
        canonical_events: &'a [CanonicalRecord],
        projections: &'a [CanonicalRecord],
        receipts: &'a [WriteReceipt],
        blobs: &'a [BackupBlob],
        purge_ledger: &'a [PurgeLedgerEntry],
        artifacts: &'a [BackupArtifact],
        ors_snapshot: Option<&'a OrsSnapshotFence>,
        suspended_count: u64,
        watchdog_spool: Option<&'a WatchdogSpoolFence>,
        host_audit: Option<&'a HostStateAuditFence>,
    ) -> Result<Self, KernelCaptureError> {
        let ports = CapturePorts {
            caller,
            kernel_fence,
            export_fence,
            canonical_events,
            projections,
            receipts,
            blobs,
            purge_ledger,
            artifacts,
            ors_snapshot,
            suspended_count,
            watchdog_spool,
            host_audit,
        };
        ports.validate_shapes()?;
        Ok(ports)
    }

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

// ---------------------------------------------------------------------------
// Adapters onto accepted owner-neutral APIs only.
//
// Every function in this section is a thin projection of an API an owner
// already publishes. None of them derives a value the owner does not publish,
// keeps a second copy of an owner's own rule, or invents an owner: a caller
// that wants a residency identity, a suspended frontier, or a fence member set
// asks the owner, and a refusal from the owner is reported as a refusal here
// rather than smoothed over.
// ---------------------------------------------------------------------------

/// Closed obligation-domain prefixes for members an owner's own fence declares.
///
/// The prefixes keep the owner domains disjoint, so a key produced by one owner
/// can never be mistaken for a key of another and a missing member of one
/// domain can never be masked by a surplus member of a different one. The
/// carried-content prefixes (`canonical:`, `receipt:`, `blob:`, `purge:`,
/// `artifact:`) live beside the coordinator that emits them
/// (`backup_capture::member_disposition_list`).
pub const MEMBER_DOMAIN_REVISION_HEAD: &str = "revision_head:";
/// Canonical ordering-head obligation domain (see [`MEMBER_DOMAIN_REVISION_HEAD`]).
pub const MEMBER_DOMAIN_ORDERING_HEAD: &str = "ordering_head:";
/// ORS pending-operation obligation domain (see [`MEMBER_DOMAIN_REVISION_HEAD`]).
pub const MEMBER_DOMAIN_ORS_PENDING: &str = "ors_pending:";
/// ORS job-checkpoint obligation domain (see [`MEMBER_DOMAIN_REVISION_HEAD`]).
pub const MEMBER_DOMAIN_ORS_CHECKPOINT: &str = "ors_checkpoint:";
/// ORS generation-cutover obligation domain (see [`MEMBER_DOMAIN_REVISION_HEAD`]).
pub const MEMBER_DOMAIN_ORS_CUTOVER: &str = "ors_cutover:";
/// Watchdog unresolved-spool-signal obligation domain.
pub const MEMBER_DOMAIN_WATCHDOG_SIGNAL: &str = "watchdog_signal:";
/// Forensic Host audit obligation domain; never active authority.
pub const MEMBER_DOMAIN_HOST_AUDIT: &str = "host_audit:";

/// The blob owner's own residency-key digest for one carried sealed envelope.
///
/// I5.12 derives the physical blob path from `<residency-key-digest>` and I5.13
/// requires every export and backup entry to preserve that opaque
/// residency-key digest, so the capture's blob member key IS the blob owner's
/// own derivation: `BlobLocator::residency_key_digest`, the same function the
/// owner uses for path derivation and receipt linkage. Re-deriving a look-alike
/// digest here would be a second scheme over the same value, and
/// `BackupBlob::locator.hash` is only the versioned CONTENT digest, which would
/// collapse two obligation domains over equal bytes into one logical object —
/// exactly what I5.13:42 and I5.12:13 forbid.
pub fn owner_residency_key_digest(blob: &BackupBlob) -> Result<String, KernelCaptureError> {
    blob.locator
        .residency_key_digest()
        .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))
}

/// The archive owner's own suspended-recovery frontier for one ORS snapshot.
///
/// I5.13 requires the `OrsSnapshotFence` to record "pending-operation
/// identities and hashes", and the identities it records ARE the frontier.
/// This adapter reads them through the accepted owner-neutral derivation
/// `suspended_recovery_entries`, which validates the fence first and then
/// turns every pending identity into one validated suspended `OrsOperation`
/// entry. Reading `pending_operation_ids` as a raw vector would skip that
/// validation and would accept an ORS fence the archive owner itself refuses;
/// an absent snapshot is an empty frontier, never a "none claimed" default.
pub fn owner_suspended_recovery_refs(
    snapshot: &OrsSnapshotFence,
) -> Result<Vec<String>, KernelCaptureError> {
    let entries = suspended_recovery_entries(snapshot)
        .map_err(|error| KernelCaptureError::OwnerEvidenceInvalid(error.to_string()))?;
    Ok(entries
        .into_iter()
        .map(|entry| entry.historical_ref)
        .collect())
}

/// One disposition for every member an OWNER declared, read from that owner's
/// own fence and never from a carried content list.
///
/// This is the INDEPENDENT expected set a capture denominator is checked
/// against. `ExportFence::revision_heads` / `ordering_heads` are the canonical
/// owner's declared order and history; `OrsSnapshotFence` declares its own
/// pending operations, job checkpoints, and generation cutovers;
/// `WatchdogSpoolFence` declares its own unresolved signals; and the optional
/// `HostStateAuditFence` declares its own forensic dispositions. Deriving the
/// same keys from the caller's carried records instead would compare one
/// caller-supplied list with itself: two copies of the same list agree with each
/// other whatever the owners declared, so they cannot state "every expected
/// source/member has one disposition" about a member no carried list mentions.
///
/// What this cannot do, and does not claim: it cannot detect a member an owner
/// omitted from its OWN fence before this owner saw it. A fence is the owner's
/// declaration; a fence that under-declares is that owner's evidence gap.
///
/// The ORS pending-operation dispositions are read through the owner's own
/// suspended derivation (see [`owner_suspended_recovery_refs`]), so an ORS
/// fence the archive owner refuses yields a refusal here rather than a
/// silently shortened frontier. The Host audit dispositions are labelled
/// `forensic`: I5.13:44 makes the audit optional and never restored as active
/// authority, so it can never satisfy a class denominator.
pub fn owner_fence_dispositions(
    export_fence: &ExportFence,
    ors_snapshot: Option<&OrsSnapshotFence>,
    watchdog_spool: Option<&WatchdogSpoolFence>,
    host_audit: Option<&HostStateAuditFence>,
) -> Result<Vec<(String, String)>, KernelCaptureError> {
    let mut dispositions = Vec::new();
    for head in &export_fence.revision_heads {
        dispositions.push((
            format!("{}{}", MEMBER_DOMAIN_REVISION_HEAD, head.key.as_str()),
            "captured".to_owned(),
        ));
    }
    for head in &export_fence.ordering_heads {
        dispositions.push((
            format!("{}{}", MEMBER_DOMAIN_ORDERING_HEAD, head.scope.as_str()),
            "captured".to_owned(),
        ));
    }
    if let Some(snapshot) = ors_snapshot {
        for pending in owner_suspended_recovery_refs(snapshot)? {
            dispositions.push((
                format!("{MEMBER_DOMAIN_ORS_PENDING}{pending}"),
                "suspended".to_owned(),
            ));
        }
        for checkpoint in &snapshot.job_checkpoint_ids {
            dispositions.push((
                format!("{MEMBER_DOMAIN_ORS_CHECKPOINT}{checkpoint}"),
                "captured".to_owned(),
            ));
        }
        for cutover in &snapshot.generation_cutover_ids {
            dispositions.push((
                format!("{MEMBER_DOMAIN_ORS_CUTOVER}{cutover}"),
                "captured".to_owned(),
            ));
        }
    }
    if let Some(spool) = watchdog_spool {
        for signal in &spool.unresolved_signal_digests {
            dispositions.push((
                format!("{MEMBER_DOMAIN_WATCHDOG_SIGNAL}{signal}"),
                "suspended".to_owned(),
            ));
        }
    }
    if let Some(audit) = host_audit {
        for disposition in &audit.observed_dispositions {
            dispositions.push((
                format!("{MEMBER_DOMAIN_HOST_AUDIT}{disposition}"),
                "forensic".to_owned(),
            ));
        }
    }
    Ok(dispositions)
}

/// One immutable verified archive bound to its single publication operation:
/// archive digest, operation identity, and idempotency key.
///
/// There is deliberately no durability field here. Durability is evidence the
/// OWNER issues — it is [`PublicationReceipt::durable`] — and a note this owner
/// wrote about its own publication would be a self-attested flag, not proof.
/// The coordinator compares the owner's receipt against these three identities
/// and nothing else.
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
}

/// Durable receipt for one publication operation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Publication operation identity the receipt answers for.
    pub operation_id: String,
    /// Archive digest the receipt confirms as durable.
    pub archive_sha256: String,
    /// Whether the archive is durably recorded by the owner.
    pub durable: bool,
}

impl PublicationReceipt {
    /// Validates the shape of a receipt read back from the retained-archive
    /// owner.
    ///
    /// This is the ONLY check `reconcile` applies to the recorded value: it
    /// validates the ORIGINAL record the owner wrote, and never substitutes a
    /// checksum recomputed over whatever bytes happen to be in hand. A receipt
    /// that does not claim durability, names a blank operation, or carries a
    /// non-digest archive value is refused as a typed failure rather than
    /// adopted.
    pub fn validate(&self) -> Result<(), KernelCaptureError> {
        non_blank(&self.operation_id, "publish.receipt.operation_id")?;
        if self.operation_id.len() > MAX_PUBLICATION_ID_LEN {
            return Err(KernelCaptureError::OwnerEvidenceInvalid(
                "publication receipt operation identity is not a bounded identity".to_owned(),
            ));
        }
        if !is_hex64(&self.archive_sha256) {
            return Err(KernelCaptureError::OwnerEvidenceInvalid(
                "publication receipt archive digest is not a 64-hex digest".to_owned(),
            ));
        }
        if !self.durable {
            return Err(KernelCaptureError::OwnerEvidenceInvalid(
                "publication receipt does not claim a durable archive".to_owned(),
            ));
        }
        Ok(())
    }
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

/// Retained-archive area below `<work_root>/.eliot`.
pub const CAPTURE_ARCHIVE_AREA: &str = "backup-archives";
/// File name of the encoded archive body inside one publication operation's
/// directory.
pub const CAPTURE_PUBLISHED_ARCHIVE_FILE: &str = "archive.ecxf";
/// File name of the owner-issued publication receipt inside one publication
/// operation's directory.
pub const CAPTURE_PUBLICATION_RECEIPT_FILE: &str = "publication-receipt.json";
/// Maximum accepted length of a publication operation identity or idempotency
/// key (bounded identities, I14.3).
pub const MAX_PUBLICATION_ID_LEN: usize = 128;

/// Kernel-owned retained-archive publication owner (issue #2569).
///
/// This is the missing production `PublicationPort` implementor. Before it
/// existed the only implementation in the tree was `MemPublisher` inside
/// `bins/eliot-kernel/tests/backup_capture.rs`, so no archive could reach
/// durable storage and `KernelBackupCapture::capture` had no non-test caller.
///
/// It uses the SAME ownership boundary this crate's isolated restore
/// destination already uses (`KernelIsolatedDestination` over
/// `<work_root>/.eliot/<area>`): the area is CONSTRUCTED below the canonical
/// work root, never accepted as an arbitrary path, and a publication operation
/// owns its directory by EXCLUSIVE CREATION of its two files rather than by a
/// predictable name. The directory component is the digest of the operation
/// identity, so a caller-chosen backup id can never name a path and a
/// reconciliation that knows only the operation identity still reaches exactly
/// one directory.
///
/// What it is NOT: a second archive format, a coordinator-side self-attestation,
/// or an in-memory stand-in. `durable` is set only after the archive body and
/// the receipt are both flushed to stable storage, and nothing here claims
/// recovery, activation, cutover, or readiness.
#[derive(Clone, Debug)]
pub struct KernelArchiveOwner {
    area: PathBuf,
}

impl KernelArchiveOwner {
    /// Binds the retained-archive owner to the Kernel work root. Fails closed
    /// on a relative or non-existent work root: there is no default root and no
    /// ambient-directory fallback.
    pub fn bind(work_root: &Path) -> Result<Self, KernelCaptureError> {
        if !work_root.is_absolute() {
            return Err(KernelCaptureError::InvalidInput {
                field: "publish.work_root",
                reason: "the work root must be absolute",
            });
        }
        if !work_root.is_dir() {
            return Err(KernelCaptureError::InvalidInput {
                field: "publish.work_root",
                reason: "the work root must be an existing directory",
            });
        }
        let area = work_root.join(".eliot").join(CAPTURE_ARCHIVE_AREA);
        std::fs::create_dir_all(&area).map_err(|error| {
            KernelCaptureError::OwnerEvidenceInvalid(format!(
                "retained-archive area could not be created: {error}"
            ))
        })?;
        Ok(Self { area })
    }

    /// The one directory this publication operation owns.
    fn operation_dir(&self, operation_id: &str) -> Result<PathBuf, KernelCaptureError> {
        let dir = self.area.join(sha256_hex(operation_id.as_bytes()));
        if !dir.starts_with(&self.area) {
            return Err(KernelCaptureError::OwnerEvidenceInvalid(
                "publication directory escapes the retained-archive area".to_owned(),
            ));
        }
        Ok(dir)
    }
}

impl PublicationPort for KernelArchiveOwner {
    /// Publishes the verified archive bytes exactly once, then issues the
    /// owner's own durable receipt for that operation.
    ///
    /// Order: validate the bounded identities, construct the operation's own
    /// directory, EXCLUSIVELY create the archive body, flush it, then
    /// EXCLUSIVELY create the receipt and flush it. Durability is claimed only
    /// after both writes are flushed. An operation whose directory already holds
    /// a body or a receipt is never written twice: exclusive creation refuses
    /// and the coordinator reconciles by identity instead, so this is
    /// exactly-once even across a lost response.
    fn publish_once(
        &mut self,
        operation_id: &str,
        idempotency_key: &str,
        bytes: &[u8],
    ) -> Result<PublicationReceipt, KernelCaptureError> {
        check_publication_id(operation_id, "publish.operation_id")?;
        check_publication_id(idempotency_key, "publish.idempotency_key")?;
        if bytes.is_empty() {
            return Err(KernelCaptureError::InvalidInput {
                field: "publish.bytes",
                reason: "an empty archive is not a publishable artifact",
            });
        }
        let dir = self.operation_dir(operation_id)?;
        std::fs::create_dir_all(&dir).map_err(|error| {
            KernelCaptureError::OwnerEvidenceInvalid(format!(
                "publication directory could not be created: {error}"
            ))
        })?;
        // This digest MINTES the content address of the exact bytes this call is
        // publishing. It never stands in for checking a recorded one: the
        // coordinator independently compares this value against the digest of
        // the bundle it built and validated, and that comparison is what binds
        // the receipt to this operation.
        let receipt = PublicationReceipt {
            operation_id: operation_id.to_owned(),
            archive_sha256: sha256_hex(bytes),
            durable: true,
        };
        write_owned(&dir.join(CAPTURE_PUBLISHED_ARCHIVE_FILE), bytes, operation_id)?;
        let encoded = serde_json::to_vec(&receipt).map_err(|error| {
            KernelCaptureError::OwnerEvidenceInvalid(format!(
                "publication receipt could not be encoded: {error}"
            ))
        })?;
        write_owned(
            &dir.join(CAPTURE_PUBLICATION_RECEIPT_FILE),
            &encoded,
            operation_id,
        )?;
        sync_directory(&dir)?;
        Ok(receipt)
    }

    /// Adopts this owner's OWN durable receipt for `operation_id` without a
    /// second publish.
    ///
    /// The recorded receipt is read back and validated through
    /// [`PublicationReceipt::validate`] — the original recorded value, not a
    /// fresh checksum over whatever bytes are in hand — and it must name THIS
    /// operation identity exactly. The body that exclusive creation committed
    /// for this operation must still be present, otherwise the receipt no longer
    /// describes a retained archive. Anything else is an unknown publication
    /// outcome, which crosses as `RestoreRollbackRequired` so the coordinator
    /// reconciles rather than blind-retries (I14.21).
    fn reconcile(&mut self, operation_id: &str) -> Result<PublicationReceipt, KernelCaptureError> {
        check_publication_id(operation_id, "publish.operation_id")?;
        let dir = self.operation_dir(operation_id)?;
        let unknown = || KernelCaptureError::PublicationUnknown(operation_id.to_owned());
        let raw =
            std::fs::read(dir.join(CAPTURE_PUBLICATION_RECEIPT_FILE)).map_err(|_| unknown())?;
        let receipt: PublicationReceipt = serde_json::from_slice(&raw).map_err(|_| unknown())?;
        receipt.validate()?;
        if receipt.operation_id != operation_id {
            return Err(unknown());
        }
        let body =
            std::fs::metadata(dir.join(CAPTURE_PUBLISHED_ARCHIVE_FILE)).map_err(|_| unknown())?;
        if !body.is_file() || body.len() == 0 {
            return Err(unknown());
        }
        Ok(receipt)
    }
}

/// Refuses an unbounded or malformed publication identity.
fn check_publication_id(value: &str, field: &'static str) -> Result<(), KernelCaptureError> {
    non_blank(value, field)?;
    if value.len() > MAX_PUBLICATION_ID_LEN {
        return Err(KernelCaptureError::InvalidInput {
            field,
            reason: "publication identities must be bounded",
        });
    }
    Ok(())
}

/// Creates one file this publication operation owns, refusing an existing one.
///
/// `create_new` IS the ownership claim: a predictable name is not ownership,
/// so this refuses rather than overwriting or appending. An existing file means
/// this operation already published, which is an unknown publication outcome for
/// the caller to reconcile by identity — never a second write. A body that was
/// created but whose receipt was not is deliberately left in place and reported
/// the same way, because a partially written publication is precisely the state
/// a blind retry would corrupt.
fn write_owned(
    path: &Path,
    bytes: &[u8],
    operation_id: &str,
) -> Result<(), KernelCaptureError> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => {
                KernelCaptureError::PublicationUnknown(operation_id.to_owned())
            }
            _ => KernelCaptureError::OwnerEvidenceInvalid(format!(
                "publication file could not be created: {error}"
            )),
        })?;
    file.write_all(bytes).map_err(|error| {
        KernelCaptureError::OwnerEvidenceInvalid(format!("publication write failed: {error}"))
    })?;
    file.sync_all().map_err(|error| {
        KernelCaptureError::OwnerEvidenceInvalid(format!("publication flush failed: {error}"))
    })?;
    Ok(())
}

/// Flushes the directory entry that names this operation's two created files.
///
/// Windows cannot flush a directory through an ordinary open, so the handle is
/// opened with `FILE_FLAG_BACKUP_SEMANTICS`, and the three errors Windows may
/// legitimately raise for a directory flush are absorbed for the same reason
/// this crate's restore journal adapter absorbs them: the entry cannot be
/// flushed rather than a write having been lost, and both file bodies were
/// already flushed unconditionally by [`write_owned`] before this call.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), KernelCaptureError> {
    std::fs::File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| {
            KernelCaptureError::OwnerEvidenceInvalid(format!(
                "publication directory flush failed: {error}"
            ))
        })
}

#[cfg(windows)]
fn sync_directory(directory: &Path) -> Result<(), KernelCaptureError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .and_then(|handle| handle.sync_all())
        .or_else(|error| match error.kind() {
            std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::Unsupported => Ok(()),
            _ => Err(error),
        })
        .map_err(|error| {
            KernelCaptureError::OwnerEvidenceInvalid(format!(
                "publication directory flush failed: {error}"
            ))
        })
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_directory: &Path) -> Result<(), KernelCaptureError> {
    Ok(())
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
