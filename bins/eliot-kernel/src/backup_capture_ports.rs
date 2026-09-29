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
//! (`PublicationPort`), and the fail-closed `KernelCaptureError` vocabulary
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

use std::collections::BTreeSet;

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupClass, BackupError, CanonicalRecord, ExportFence,
    HostStateAuditFence, OrsSnapshotFence, WatchdogSpoolFence, suspended_recovery_entries,
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
/// Canonical projection obligation domain.
pub const MEMBER_DOMAIN_PROJECTION: &str = "projection:";

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

/// Validates member identity uniqueness across the complete disposition set.
///
/// Identity is the obligation-domain-qualified member key; the disposition is
/// its state, not part of its identity. Counting `(key, disposition)` pairs
/// would let one member appear twice under different labels and falsely pass
/// the denominator. The archive validator owns canonical reference closure;
/// this check ensures that the coordinator's carried and owner-declared
/// dispositions form one unambiguous identity set around that validated
/// archive.
pub fn validate_disposition_identities(
    dispositions: &[(String, String)],
) -> Result<(), KernelCaptureError> {
    let mut identities = BTreeSet::new();
    for (identity, disposition) in dispositions {
        non_blank(identity, "capture.member_identity")?;
        non_blank(disposition, "capture.member_disposition")?;
        if !identities.insert(identity.as_str()) {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "member {identity} has more than one disposition"
            )));
        }
    }
    Ok(())
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
