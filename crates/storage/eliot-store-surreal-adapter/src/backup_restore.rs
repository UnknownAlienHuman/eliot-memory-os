//! Isolated canonical-restore surface for the `SurrealDB` store bridge.
//!
//! This module implements the I05-13/I05-04/I05-16/I05-27 isolated-restore,
//! purge-suppression, reference-closure and same-operation-reconciliation
//! semantics under the I15-14/I14-21/I07-20 durability and redaction envelope.
//! Every phase reaches the provider: [`prepare_isolated_destination`] inserts
//! the destination fence row with the destination owner's freshly derived
//! operational identity, `restore_canonical_batch` binds the restored members
//! and their durable receipt to that fence in one provider transaction, and
//! `validate_restore`/`reconcile_operation` derive their verdict from exact
//! durable readback. No record, query or credential prose ever crosses the error
//! boundary.
//!
//! Durable state: a private namespace inside the admitted recovery registry
//! table (the same physical table the Dreamer ledger uses, under the private
//! `client::backup_restore` seam). Four keyed row families carry it: the
//! destination fence row, the per-operation record row (members, per-phase
//! receipts and the exact restored/rejected/suppressed/unresolved denominator),
//! the archive-placement exclusivity row, and the current purge-ledger rows. No
//! new table, DDL, schema generation or second client exists; the unique
//! `(namespace, key)` index supplies insert-if-absent exclusion, exact replay
//! and changed-content conflict, and the destination fence compare-and-set
//! serializes concurrent restores of one destination.
//!
//! Evidence discipline: the current purge policy, the destination admission, the
//! isolation fence, the build/schema identity and the source binding are read
//! back from the destination owner's durable row — never from the incoming
//! batch's self-declared `purge_policy_revision`. A batch that claims a purge
//! policy the destination owner has not admitted is refused, and member
//! suppression is decided by the current purge-ledger readback, so records
//! purged after the archive was created can never become servable.
//!
//! Scope rules: only validated canonical logical batches are applied under the
//! canonical restore owner; live database files are never copied, archive text
//! is never executed as queries, old session/lease/grant/epoch state is never
//! imported, and invariant checks are never disabled. Nothing here activates an
//! installation, unblocks effects, or retires a source.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

use eliot_store_api::{
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, BACKUP_IO_RESTORE_SCHEMA_V1,
    BackupOperationReconciliation, BlobResidencyDomain, CanonicalRestoreBatch, IsolatedDestination,
    IsolatedRestorePort, IsolationEvidence, MAX_RESTORE_MEMBERS, OperationId, OperationIdentity,
    ReconciliationOutcome, RecoveryRecord, RequestMeta, RestoreValidationReceipt,
    SnapshotCompleteness, SnapshotSourceIdentity, StateFence, StoreError, StoreMutationDisposition,
    canonical_json_bytes, reconcile_same_operation, sha256_hex,
};
use serde::{Deserialize, Serialize};

use crate::client::RpcTransport;
use crate::{SurrealStoreAdapter, config::SurrealAdapterConfig, error::AdapterError};

/// Versioned schema tag accepted for isolated-restore documents.
pub const RESTORE_SCHEMA_V1: &str = BACKUP_IO_RESTORE_SCHEMA_V1;
/// Capability name advertised for isolated restore.
pub const RESTORE_CAPABILITY: &str = BACKUP_IO_CAPABILITY_ISOLATED_RESTORE;
/// Maximum members in one canonical restore batch.
pub const MAX_RESTORE_BATCH_MEMBERS: usize = MAX_RESTORE_MEMBERS;
/// Maximum cumulative restore bytes admitted by one batch.
pub const MAX_RESTORE_BYTES: u64 = 8_388_608;
/// Maximum restore duration in milliseconds admitted by one batch.
pub const MAX_RESTORE_DURATION_MS: u64 = 3_600_000;
/// Maximum age in milliseconds of a restoration admission before it is stale.
pub const MAX_ADMISSION_AGE_MS: i64 = 3_600_000;

/// Closed vocabulary of restore operations this adapter supports.
///
/// Anything outside this set — live database copies, raw queries, session,
/// lease, grant or epoch imports — is refused; there is no bypass path.
pub const SUPPORTED_RESTORE_OPERATIONS: &[&str] = &[
    "prepare_isolated_destination",
    "restore_canonical_batch",
    "validate_restore",
    "reconcile_operation",
];

/// Closed destination class label stored in the durable fence document.
const RESTORE_DESTINATION_CLASS: &str = "ISOLATED_RESTORE";
/// Closed isolation state label stored in the durable fence document.
const RESTORE_ISOLATION_STATE: &str = "ISOLATED";

/// Ceiling on distinct operation identities the shared projection may track at
/// once.
///
/// The in-process attempt map is keyed by admitted-but-caller-supplied operation
/// ids and is process-lifetime, so a caller that keeps failing with fresh ids is
/// refused rather than allowed to grow memory without limit. It reuses the batch
/// ceiling: one restore batch already bounds the member set of a single
/// operation, so the projection never needs to track more live operation
/// identities than that bound. Re-attempting a known identity reuses its slot and
/// never grows the map.
const MAX_RESTORE_TRACKED_ATTEMPTS: usize = MAX_RESTORE_BATCH_MEMBERS;

/// Closed per-member disposition of one canonical restore batch.
///
/// The frozen [`CanonicalRestoreBatch`] contract carries exactly one archive
/// member digest per batch, so a purge obligation is necessarily observed at
/// member-set granularity: an obligation names the archive member digest or the
/// source scope and therefore covers the whole member set of that batch. A
/// per-member split the contract cannot observe would be manufactured
/// accounting, so every member of the set carries the same observed
/// disposition while the exact per-member identities and counts are preserved.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MemberDisposition {
    /// Bound into the isolated destination under its fresh identity.
    Restored,
    /// Suppressed by the current purge ledger; never made servable.
    Suppressed,
    /// No durable outcome: the member keeps its original identity and the
    /// missing denominator stays visible.
    Unresolved,
}

/// Closed per-member durable record of one restored archive member.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreMemberRecord {
    /// Deterministic logical identity of this member inside the destination.
    /// It binds only the admitted archive member digest and the member index,
    /// so a retry, a resume or a later readback reuses the *original* member
    /// identity instead of minting a new one.
    member_ref: String,
    /// Zero-based position of the member inside the admitted member set.
    member_index: u64,
    /// Observed disposition for this member.
    disposition: MemberDisposition,
    /// Residency domain the member is bound under; never a source domain.
    residency_domain: String,
    /// Privacy domain the member is bound under; distinct from residency.
    privacy_domain: String,
    /// Retention domain the member is bound under; distinct from both.
    retention_domain: String,
    /// Purge policy revision the disposition was decided against.
    purge_policy_revision: u64,
}

/// Closed lifecycle state of one current purge-ledger obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PurgeLedgerState {
    /// The obligation is durably complete: the subject must never become
    /// servable again.
    Purged,
    /// The obligation is recorded but not complete. The subject must not become
    /// servable either, and the member can be reported neither restored nor
    /// resolved.
    Requested,
    /// The obligation is in progress under its owner.
    InProgress,
    /// The obligation is recorded as blocked. Fail-closed, not servable.
    Blocked,
}

impl PurgeLedgerState {
    /// Reports whether the obligation is durably complete.
    const fn is_purged(self) -> bool {
        matches!(self, Self::Purged)
    }
}

/// One current purge-ledger entry, as durably recorded by the destination's
/// privacy owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PurgeLedgerEntry {
    /// Subject the obligation applies to: an archive member digest, or a source
    /// installation scope.
    subject: String,
    /// Lifecycle state of the obligation.
    state: PurgeLedgerState,
    /// Purge policy revision the obligation was recorded at.
    purge_policy_revision: u64,
    /// Residency domain the obligation is scoped to.
    residency_domain: String,
    /// Privacy domain the obligation is scoped to.
    privacy_domain: String,
    /// Retention domain the obligation is scoped to.
    retention_domain: String,
}

impl PurgeLedgerEntry {
    /// Validates one ledger entry without interpreting its subject.
    fn validate(&self) -> Result<(), StoreError> {
        reject_blank_text(&self.subject, "restore.purge_subject")?;
        reject_blank_text(&self.residency_domain, "restore.purge_residency_domain")?;
        reject_blank_text(&self.privacy_domain, "restore.purge_privacy_domain")?;
        reject_blank_text(&self.retention_domain, "restore.purge_retention_domain")?;
        if self.purge_policy_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "purge ledger entry must carry a non-zero revision",
            });
        }
        Ok(())
    }
}

/// One exact per-phase restore receipt stored inside the destination row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestorePhaseReceipt {
    /// Closed phase label.
    phase: String,
    /// Operation identity the phase committed under.
    operation_id: String,
    /// Archive member digest the phase bound.
    archive_member_digest: String,
    /// Exact restored member count observed in this phase.
    restored_members: u64,
    /// Exact rejected member count observed in this phase.
    rejected_members: u64,
    /// Exact purge-suppressed member count observed in this phase.
    suppressed_members: u64,
    /// Exact unresolved member count observed in this phase.
    unresolved_members: u64,
    /// Total member denominator the phase accounted for.
    denominator_members: u64,
    /// Provider transaction time of the phase, in Unix milliseconds.
    committed_at_unix_ms: i64,
    /// Digest binding this phase receipt inside the destination row.
    receipt_digest: String,
}

/// Durable destination fence/admission document owned by the isolated
/// destination's own admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreDestinationDocument {
    /// Digest over the admitted external evidence. Re-binding a prepared
    /// destination to different evidence is refused, so the fence cannot be
    /// moved after admission.
    admission_digest: String,
    /// Destination id this fence belongs to.
    destination_id: String,
    /// Closed destination class; only an isolated restore destination is ever
    /// admitted here.
    destination_class: String,
    /// Fresh destination operational identity derived by the destination owner
    /// from its own admission. Source authority never enters this derivation.
    destination_identity: String,
    /// Source store the archive is admitted from.
    source_store_id: String,
    /// Source installation the archive is admitted from.
    source_installation_id: String,
    /// Digest binding the declared source pair this destination restores from.
    declared_source_digest: String,
    /// Opaque external admission handle; evidence, never an authority token.
    admission_handle: String,
    /// Admission time in Unix milliseconds.
    admitted_at_unix_ms: i64,
    /// Current purge policy revision bound by the destination owner. This is
    /// the authority a batch is checked against; the batch's own declared
    /// revision is only an expectation.
    purge_policy_revision: u64,
    /// Destination schema the restore targets.
    target_schema: String,
    /// Build identity of the restoring bridge that bound this destination.
    restore_build_identity: String,
    /// Closed isolation state; the destination is never active or foreign.
    isolation_state: String,
    /// Residency domain this destination binds members under.
    residency_domain: String,
    /// Privacy domain this destination binds members under.
    privacy_domain: String,
    /// Retention domain this destination binds members under.
    retention_domain: String,
    /// Number of restore operations durably applied into this destination.
    applied_operations: u64,
    /// Cumulative committed restore bytes for this destination.
    cumulative_bytes: u64,
    /// Preparation time in Unix milliseconds; the duration bound starts here.
    prepared_at_unix_ms: i64,
    /// Ordered per-phase receipts committed into this destination.
    phases: Vec<RestorePhaseReceipt>,
}

impl RestoreDestinationDocument {
    /// Validates the durable destination document fail-closed.
    fn validate(&self) -> Result<(), StoreError> {
        reject_blank_text(&self.admission_digest, "restore.admission_digest")?;
        reject_blank_text(&self.destination_id, "restore.destination_id")?;
        reject_blank_text(&self.destination_identity, "restore.destination_identity")?;
        reject_blank_text(&self.source_store_id, "restore.source_store_id")?;
        reject_blank_text(
            &self.source_installation_id,
            "restore.source_installation_id",
        )?;
        reject_blank_text(
            &self.declared_source_digest,
            "restore.declared_source_digest",
        )?;
        reject_blank_text(&self.admission_handle, "restore.admission_handle")?;
        reject_blank_text(&self.target_schema, "restore.target_schema")?;
        reject_blank_text(
            &self.restore_build_identity,
            "restore.restore_build_identity",
        )?;
        reject_blank_text(&self.residency_domain, "restore.residency_domain")?;
        reject_blank_text(&self.privacy_domain, "restore.privacy_domain")?;
        reject_blank_text(&self.retention_domain, "restore.retention_domain")?;
        if self.destination_class != RESTORE_DESTINATION_CLASS {
            return Err(StoreError::InvalidField {
                field: "restore.destination_class",
                reason: "destination fence is not an isolated restore destination",
            });
        }
        if self.isolation_state != RESTORE_ISOLATION_STATE {
            return Err(StoreError::InvalidField {
                field: "restore.isolation_state",
                reason: "destination is not an isolated restore fence",
            });
        }
        if self.purge_policy_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "current purge policy is unverified",
            });
        }
        if self.admitted_at_unix_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "restore.admitted_at_unix_ms",
                reason: "must be positive",
            });
        }
        Ok(())
    }

    /// Reports whether the presented admission evidence equals the durable one.
    fn evidence_matches(&self, evidence: &IsolationEvidence) -> bool {
        self.admission_handle == evidence.admission_handle
            && self.admitted_at_unix_ms == evidence.admitted_at_unix_ms
            && self.purge_policy_revision == evidence.purge_policy_revision
    }

    /// Digest over the admitted external evidence bound at preparation.
    fn admission_digest(
        destination: &IsolatedDestination,
        binding: &AdmissionBinding,
    ) -> Result<String, StoreError> {
        let shape = (
            destination.destination_id.as_str(),
            destination.source_store_id.as_str(),
            destination.source_installation_id.as_str(),
            destination.evidence.admission_handle.as_str(),
            destination.evidence.admitted_at_unix_ms,
            destination.evidence.purge_policy_revision,
            destination.target_schema.as_str(),
            binding.destination_identity.as_str(),
            binding.declared_source_digest.as_str(),
            binding.restore_build_identity.as_str(),
            binding.domains.residency.as_str(),
            binding.domains.privacy.as_str(),
            binding.domains.retention.as_str(),
        );
        Ok(sha256_hex(&canonical_digest_bytes(&shape)?))
    }
}

/// The destination-owner binding an isolated destination is admitted under.
struct AdmissionBinding {
    destination_identity: String,
    declared_source_digest: String,
    restore_build_identity: String,
    domains: RestoreDomains,
}

/// Closed label of the phase this port commits.
///
/// Every durable restore record is written in the apply phase; the validate
/// phase is a pure read gate and never advances the destination fence.
const RESTORE_PHASE_APPLIED: &str = "APPLIED";

/// Durable per-operation restore record: the members bound into the destination
/// plus the exact per-phase accounting of this batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreRecordDocument {
    /// Exact operation identity the record was committed under.
    operation: OperationIdentity,
    /// Destination the batch was bound into.
    destination_id: String,
    /// Fresh destination operational identity the members were bound under.
    destination_identity: String,
    /// Source identity digest the members were captured from.
    source_identity_digest: String,
    /// Archive member digest this record applies to.
    archive_member_digest: String,
    /// Schema the members were restored into.
    target_schema: String,
    /// Current purge policy revision the dispositions were decided against.
    current_purge_revision: u64,
    /// Expected-state identity: the state fence every expectation was admitted
    /// under.
    expected_state_fence: StateFence,
    /// Digests of the expected revision heads this record was admitted with.
    expected_revision_head_digests: Vec<String>,
    /// Digests of the expected ordering heads this record was admitted with.
    expected_ordering_head_digests: Vec<String>,
    /// Exact restored/rejected/suppressed/unresolved denominator.
    denominator: RestoreDenominator,
    /// Per-member durable dispositions, in member order.
    members: Vec<RestoreMemberRecord>,
    /// Closed phase label this record was committed in.
    phase: String,
    /// Completeness observed for this record.
    completeness: SnapshotCompleteness,
    /// Mutation disposition observed for this record.
    disposition: StoreMutationDisposition,
    /// First-write time in Unix milliseconds; the duration bound is measured
    /// from it, so an interrupted operation cannot be resumed after the bound.
    started_at_unix_ms: i64,
}

/// One bounded, redacted failure record preserved for an operation identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreFailureRecord {
    /// Closed phase label the failure was observed in.
    phase: String,
    /// Redacted failure classification; never provider prose.
    classification: String,
    /// Observation time in Unix milliseconds.
    observed_at_unix_ms: i64,
}

impl RestoreFailureRecord {
    /// Classifies one redacted failure label.
    fn classify(error: &StoreError) -> &'static str {
        match error {
            StoreError::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            StoreError::Unavailable => "UNAVAILABLE",
            StoreError::FenceMismatch => "FENCE_MISMATCH",
            StoreError::IdentityConflict => "IDENTITY_CONFLICT",
            StoreError::RevisionConflict => "REVISION_CONFLICT",
            StoreError::OrderingConflict => "ORDERING_CONFLICT",
            StoreError::ReceiptNotFound => "RECEIPT_NOT_FOUND",
            StoreError::MissingReceiptEnvelope => "UNKNOWN_OUTCOME",
            StoreError::InvalidReceipt => "INVALID_RECEIPT",
            StoreError::InvalidProjection => "INVALID_PROJECTION",
            StoreError::InvalidField { .. }
            | StoreError::Empty { .. }
            | StoreError::Duplicate { .. } => "INVALID_FIELD",
            _ => "RESTORE_REFUSED",
        }
    }

    /// Reconstructs the original typed failure from its redacted record.
    ///
    /// The reconstruction preserves the *class* of the original failure for a
    /// later bounded or cancelled attempt. It never invents a receipt, a proof
    /// of non-commit, or provider prose.
    fn restore(&self) -> StoreError {
        match self.classification.as_str() {
            "PAYLOAD_TOO_LARGE" => StoreError::PayloadTooLarge,
            "FENCE_MISMATCH" => StoreError::FenceMismatch,
            "IDENTITY_CONFLICT" => StoreError::IdentityConflict,
            "REVISION_CONFLICT" => StoreError::RevisionConflict,
            "ORDERING_CONFLICT" => StoreError::OrderingConflict,
            "RECEIPT_NOT_FOUND" => StoreError::ReceiptNotFound,
            "UNKNOWN_OUTCOME" => StoreError::MissingReceiptEnvelope,
            "INVALID_RECEIPT" => StoreError::InvalidReceipt,
            "INVALID_PROJECTION" => StoreError::InvalidProjection,
            "INVALID_FIELD" => StoreError::InvalidField {
                field: "restore.original_failure",
                reason: "the original restore failure was a validation refusal",
            },
            _ => StoreError::Unavailable,
        }
    }
}

/// Durable archive-placement exclusivity document: one placement of one
/// archive member into one destination, ever.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestorePlacementDocument {
    /// Destination the archive member was placed into.
    destination_id: String,
    /// Archive member digest that was placed.
    archive_member_digest: String,
    /// The one operation identity allowed to place this member.
    operation_id: String,
    /// Canonical request hash bound at placement.
    canonical_request_hash: String,
}

/// The three distinct obligation domains a restored member is bound under.
///
/// Residency, privacy and retention stay separate identities: equal bytes under
/// different domains are never coalesced, and an obligation observed in one
/// domain never silently widens into another.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RestoreDomains {
    residency: String,
    privacy: String,
    retention: String,
}

impl RestoreDomains {
    /// Derives the destination's own domain triple.
    ///
    /// Every component is bound to the destination's fresh operational identity
    /// and its privacy-scoped admission handle. Source domains are never
    /// reused, so a restored record can never be merged into a source-domain
    /// object.
    fn derive(destination: &IsolatedDestination, destination_identity: &str) -> Self {
        Self {
            residency: format!(
                "residency:{destination_identity}:{}",
                residency_label(BlobResidencyDomain::ContentBlob)
            ),
            privacy: format!(
                "privacy:{destination_identity}:{}",
                sha256_hex(destination.evidence.admission_handle.as_bytes())
            ),
            retention: format!(
                "retention:{destination_identity}:{}",
                sha256_hex(destination.target_schema.as_bytes())
            ),
        }
    }
}

/// Maps the closed residency discriminator to its durable label.
const fn residency_label(domain: BlobResidencyDomain) -> &'static str {
    match domain {
        BlobResidencyDomain::InlineCanonical => "inline_canonical",
        BlobResidencyDomain::ContentBlob => "content_blob",
        BlobResidencyDomain::ExternalReference => "external_reference",
    }
}

/// Exact restored/rejected/suppressed/unresolved denominator of a restore.
///
/// Every restored, rejected, purge-suppressed and unresolved member is
/// accounted: the parts must sum to the total, and completion additionally
/// requires zero unresolved members. The same shape is the durable
/// per-phase accounting persisted into the destination.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreDenominator {
    /// Members restored into the isolated destination.
    pub restored: u64,
    /// Members rejected by validation.
    pub rejected: u64,
    /// Members suppressed by the current purge policy.
    pub suppressed: u64,
    /// Members without a durable outcome.
    pub unresolved: u64,
    /// Total members the parts must sum to.
    pub total: u64,
}

impl RestoreDenominator {
    /// Builds a denominator whose total is the saturating sum of its parts.
    #[must_use]
    pub const fn new(restored: u64, rejected: u64, suppressed: u64, unresolved: u64) -> Self {
        Self {
            restored,
            rejected,
            suppressed,
            unresolved,
            total: restored
                .saturating_add(rejected)
                .saturating_add(suppressed)
                .saturating_add(unresolved),
        }
    }

    /// Validates that the parts sum exactly to the total.
    pub fn validate(&self) -> Result<(), StoreError> {
        let sum = self
            .restored
            .checked_add(self.rejected)
            .and_then(|partial| partial.checked_add(self.suppressed))
            .and_then(|partial| partial.checked_add(self.unresolved))
            .ok_or(StoreError::PayloadTooLarge)?;
        if sum != self.total {
            return Err(StoreError::InvalidField {
                field: "restore.member_counts",
                reason: "denominator parts must sum to the total",
            });
        }
        Ok(())
    }

    /// Reports completion: exact accounting with nothing unresolved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unresolved == 0 && self.validate().is_ok()
    }

    /// Members with a durable, observed outcome.
    const fn resolved(&self) -> u64 {
        self.restored
            .saturating_add(self.rejected)
            .saturating_add(self.suppressed)
    }
}

/// One provider-verified entry of the in-process restore projection.
#[derive(Clone, Debug)]
struct StoredRestoreEntry {
    operation: OperationIdentity,
    receipt: RestoreValidationReceipt,
}

/// One in-process attempt record of an operation identity.
///
/// It exists only to serialize concurrent same-operation attempts inside this
/// process and to preserve the *original* failure across bounded, cancelled and
/// retried attempts. It is never a receipt and never an outcome. A record left
/// behind by a finished attempt is bounded evidence, not a lock: it never
/// blocks a retry from reaching the provider's own durable reconciliation
/// readback, which is the only authority on whether the earlier attempt
/// committed.
#[derive(Clone, Debug)]
struct RestoreAttempt {
    phase: String,
    /// True only while an attempt of this identity is still running here.
    in_flight: bool,
    original_failure: Option<RestoreFailureRecord>,
}

/// In-process restore projection: durable-receipt cache, in-flight attempt
/// guard, and original-failure preservation.
///
/// This is **not** a source of truth. A receipt only enters [`Self::entries`]
/// after the provider confirmed it by exact durable readback, and restore
/// record rows are create-only, so a confirmed receipt is immutable: the cache
/// may only rescue availability when the provider is temporarily unreachable,
/// and it never decides whether an operation committed. Every verdict the port
/// returns is derived from the provider. A retained attempt record is likewise
/// not a gate: it refuses only a genuinely concurrent attempt and is bounded by
/// [`MAX_RESTORE_TRACKED_ATTEMPTS`], so a failed apply never makes its own
/// operation identity permanently un-retryable.
#[derive(Clone, Debug, Default)]
pub struct RestoreLedger {
    entries: HashMap<String, StoredRestoreEntry>,
    attempts: HashMap<String, RestoreAttempt>,
}

impl RestoreLedger {
    /// Builds an empty per-instance ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            attempts: HashMap::new(),
        }
    }

    /// Projects one provider-verified batch outcome into this process.
    ///
    /// The port calls this only *after* the provider transaction committed and
    /// the exact durable readback confirmed the counts, so a repeated
    /// same-operation input reconciles to the original receipt while the same
    /// operation with changed content conflicts. A missing entry stays unknown;
    /// callers reconcile through exact provider readback rather than assuming
    /// an outcome.
    pub fn commit(
        &mut self,
        batch: &CanonicalRestoreBatch,
        resolved: u64,
        unresolved: u64,
        completeness: SnapshotCompleteness,
        disposition: StoreMutationDisposition,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        batch.validate().map_err(redact_store_error)?;
        let counts = resolved
            .checked_add(unresolved)
            .ok_or(StoreError::PayloadTooLarge)?;
        if counts != batch.member_count {
            return Err(StoreError::InvalidField {
                field: "restore.member_counts",
                reason: "resolved and unresolved counts must sum to the denominator",
            });
        }
        let key = batch.operation.operation_id.as_str().to_owned();
        if let Some(existing) = self.entries.get(&key) {
            if reconcile_same_operation(&existing.operation, &batch.operation)?
                == ReconciliationOutcome::ReplayIdentity
            {
                return Ok(existing.receipt.clone());
            }
            return Err(StoreError::IdentityConflict);
        }
        let receipt = RestoreValidationReceipt {
            operation: batch.operation.clone(),
            destination: batch.destination.clone(),
            archive_member_digest: batch.archive_member_digest.clone(),
            resolved_members: resolved,
            unresolved_members: unresolved,
            denominator_members: batch.member_count,
            completeness,
            disposition,
        };
        receipt.validate().map_err(redact_store_error)?;
        self.entries.insert(
            key,
            StoredRestoreEntry {
                operation: batch.operation.clone(),
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    /// Reads back the provider-verified receipt cached for one operation
    /// identity, if any.
    ///
    /// Only a provider-confirmed receipt is ever cached, and record rows are
    /// create-only, so a cached receipt is immutable. It preserves an answer
    /// when the provider is temporarily unreachable after a confirmed commit;
    /// it is never used to decide that an operation did *not* commit.
    #[must_use]
    pub fn readback(&self, operation: &OperationIdentity) -> Option<RestoreValidationReceipt> {
        self.entries
            .get(operation.operation_id.as_str())
            .map(|entry| entry.receipt.clone())
    }

    /// Reconciles two identities for the same operation.
    pub fn reconcile(
        &self,
        first: &OperationIdentity,
        second: &OperationIdentity,
    ) -> Result<ReconciliationOutcome, StoreError> {
        reconcile_same_operation(first, second)
    }
}

static SHARED_RESTORE_LEDGER: OnceLock<Mutex<RestoreLedger>> = OnceLock::new();

/// Returns the shared process-global restore projection.
///
/// The projection carries the same attempt/receipt contract as a per-instance
/// [`RestoreLedger`]; per-instance ledgers remain available for isolated proof.
/// It is a cache and an ordering aid only — the provider remains the sole
/// authority for whether a restore operation committed.
#[must_use]
pub fn shared_restore_ledger() -> &'static Mutex<RestoreLedger> {
    SHARED_RESTORE_LEDGER.get_or_init(|| Mutex::new(RestoreLedger::new()))
}

/// Marks one operation identity as in flight for a phase.
///
/// The projection lock is taken only for the duration of this map update: it is
/// never held across a provider await, so a restore can never deadlock against
/// its own readback. A *concurrent* second in-process attempt of the same
/// operation identity while one is still in flight is refused with retryable
/// unavailability.
///
/// A retained original failure is deliberately **not** a gate. Refusing here
/// would make a failed apply permanently un-retryable, so the retry instead
/// falls through to the provider's durable reconciliation readback: that
/// readback, not a local marker, is the only thing that can honestly say
/// whether the earlier attempt committed. The original class stays reportable
/// through [`original_failure`].
///
/// The map is bounded by [`MAX_RESTORE_TRACKED_ATTEMPTS`]; a fresh identity
/// arriving at the ceiling is refused instead of growing the map.
fn begin_attempt(key: &str, phase: &str) -> Result<(), StoreError> {
    let mut ledger = shared_restore_ledger()
        .lock()
        .map_err(|_| unknown_outcome(key))?;
    if ledger
        .attempts
        .get(key)
        .is_some_and(|attempt| attempt.in_flight)
    {
        return Err(StoreError::Unavailable);
    }
    // A retry of a known identity reuses its own slot: the retained original
    // failure survives the new attempt, and the map does not grow. Only a key
    // that is not tracked yet competes for the bounded capacity.
    let retained = ledger
        .attempts
        .get(key)
        .and_then(|attempt| attempt.original_failure.clone());
    if retained.is_none() && ledger.attempts.len() >= MAX_RESTORE_TRACKED_ATTEMPTS {
        return Err(StoreError::PayloadTooLarge);
    }
    ledger.attempts.insert(
        key.to_owned(),
        RestoreAttempt {
            phase: phase.to_owned(),
            in_flight: true,
            original_failure: retained,
        },
    );
    Ok(())
}

/// Closes one attempt, preserving the first observed failure.
///
/// A successful attempt is evicted entirely. A failed one is retained only as
/// bounded evidence of *why* the operation first failed and is marked no longer
/// in flight, so a retry of the same identity is admitted and reaches the
/// durable reconciliation readback instead of being permanently refused. The
/// first observed class wins, so a bounded, cancelled or retried attempt still
/// reports the original failure rather than a newer one.
fn end_attempt(key: &str, failure: Option<&StoreError>) {
    let Ok(mut ledger) = shared_restore_ledger().lock() else {
        return;
    };
    let Some(error) = failure else {
        ledger.attempts.remove(key);
        return;
    };
    let Some(attempt) = ledger.attempts.get_mut(key) else {
        return;
    };
    attempt.in_flight = false;
    if attempt.original_failure.is_some() {
        return;
    }
    attempt.original_failure = Some(RestoreFailureRecord {
        phase: attempt.phase.clone(),
        classification: RestoreFailureRecord::classify(error).to_owned(),
        observed_at_unix_ms: current_unix_ms(),
    });
}

/// Returns the original failure observed for one operation identity.
fn original_failure(key: &str) -> Option<StoreError> {
    shared_restore_ledger().lock().ok().and_then(|ledger| {
        ledger
            .attempts
            .get(key)
            .and_then(|attempt| attempt.original_failure.as_ref())
            .map(RestoreFailureRecord::restore)
    })
}

/// Projects one provider-verified batch outcome into the shared projection.
fn project_verified_receipt(
    batch: &CanonicalRestoreBatch,
    receipt: &RestoreValidationReceipt,
) -> Result<(), StoreError> {
    let mut ledger = shared_restore_ledger()
        .lock()
        .map_err(|_| unknown_outcome(batch.operation.operation_id.as_str()))?;
    ledger.commit(
        batch,
        receipt.resolved_members,
        receipt.unresolved_members,
        receipt.completeness,
        receipt.disposition,
    )?;
    Ok(())
}

/// Reads the provider-verified receipt cached for one operation identity.
fn cached_receipt(operation: &OperationIdentity) -> Option<RestoreValidationReceipt> {
    shared_restore_ledger()
        .lock()
        .ok()
        .and_then(|ledger| ledger.readback(operation))
}

/// Maps projection-lock poisoning to the typed unknown outcome.
fn unknown_outcome(operation_id: &str) -> StoreError {
    AdapterError::UnknownOutcome {
        operation_id: operation_id.to_owned(),
    }
    .into_store_error()
}

/// Redacts a store error so no record, query or credential prose crosses.
///
/// Serialization payloads are replaced with bounded static text; every typed
/// variant — whose fields are already static or bounded digests — passes
/// through unchanged.
#[must_use]
pub fn redact_store_error(error: StoreError) -> StoreError {
    match error {
        StoreError::Serialization(_) => {
            StoreError::Serialization("canonical restore serialization failed".to_owned())
        }
        other => other,
    }
}

/// Returns the active store identity from admitted configuration.
///
/// Reads only the already-admitted [`SurrealAdapterConfig`] database and
/// installation id; there is no caller endpoint or credential override.
#[must_use]
pub fn active_store_identity(config: &SurrealAdapterConfig) -> (String, String) {
    (config.database.clone(), config.installation_id.clone())
}

/// Rejects blank or control-character text without echoing the value.
fn reject_blank_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    Ok(())
}

/// Rejects duplicate closure keys without echoing the values.
fn reject_duplicates<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(StoreError::Duplicate { field });
    }
    Ok(())
}

/// Returns the current wall-clock time in milliseconds since the Unix epoch.
fn current_unix_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Replaces provider or serialization prose with bounded static text.
fn redact_serialization(message: &str) -> String {
    const REDACTED: &str = "canonical restore serialization failed";
    if message.len() > 96 || message.chars().any(char::is_control) {
        return REDACTED.to_owned();
    }
    message.to_owned()
}

/// Canonicalizes a digest input, redacting any serialization prose.
fn canonical_digest_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    canonical_json_bytes(value)
        .map_err(|error| StoreError::Serialization(redact_serialization(&error.to_string())))
}

/// Encodes one durable document into its canonical payload and digest.
fn encode_document<T: Serialize>(document: &T) -> Result<(Vec<u8>, String), StoreError> {
    let bytes = canonical_digest_bytes(document)?;
    let digest = sha256_hex(&bytes);
    Ok((bytes, digest))
}

/// Validates an isolated destination against the active store identity.
///
/// Accepts only `IsolatedRestore` destinations whose identity differs from
/// both the source binding and the active store/installation. Source, active
/// and foreign destinations are refused with typed errors.
pub fn validate_isolated_destination(
    destination: &IsolatedDestination,
    active_store_id: &str,
    active_installation_id: &str,
) -> Result<(), StoreError> {
    destination.validate()?;
    reject_blank_text(&destination.source_store_id, "restore.source_store_id")?;
    reject_blank_text(
        &destination.source_installation_id,
        "restore.source_installation_id",
    )?;
    reject_blank_text(active_store_id, "restore.active_store_id")?;
    reject_blank_text(active_installation_id, "restore.active_installation_id")?;
    if destination.destination_id == active_store_id
        || destination.destination_id == active_installation_id
    {
        return Err(StoreError::InvalidField {
            field: "restore.destination_id",
            reason: "must differ from source/active installation",
        });
    }
    Ok(())
}

/// Validates one canonical restore batch against current admission evidence.
///
/// Checks the batch shape, destination isolation, expected schema, current
/// purge policy revision, admission freshness, and reference closure. A stale
/// or future admission, an unsupported schema, an unverified (zero) current
/// purge revision, or a purge revision that does not match the current policy
/// is refused before any write.
pub fn validate_restore_batch(
    batch: &CanonicalRestoreBatch,
    active_store_id: &str,
    active_installation_id: &str,
    expected_schema: &str,
    current_purge_revision: u64,
    now_unix_ms: i64,
) -> Result<(), StoreError> {
    batch.validate()?;
    validate_isolated_destination(&batch.destination, active_store_id, active_installation_id)?;
    if batch.target_schema != expected_schema {
        return Err(StoreError::InvalidField {
            field: "restore.target_schema",
            reason: "must match the admitted restore schema",
        });
    }
    if current_purge_revision == 0 {
        return Err(StoreError::InvalidField {
            field: "restore.purge_policy_revision",
            reason: "current purge policy is unverified",
        });
    }
    if batch.purge_policy_revision != current_purge_revision {
        return Err(StoreError::InvalidField {
            field: "restore.purge_policy_revision",
            reason: "must match the current purge policy",
        });
    }
    check_admission_freshness(&batch.destination.evidence, now_unix_ms)?;
    validate_reference_closure(batch)?;
    Ok(())
}

/// Validates the canonical reference/ordering closure of one restore batch.
///
/// Requires a non-empty, duplicate-free revision-head set with every head
/// validated, a duplicate-free validated ordering-head set, and a bounded
/// non-zero member count. Unverified derived data can never grant completion:
/// closure failure refuses the batch outright.
pub fn validate_reference_closure(batch: &CanonicalRestoreBatch) -> Result<(), StoreError> {
    batch.operation.validate()?;
    if batch.expected_revision_heads.is_empty() {
        return Err(StoreError::Empty {
            field: "restore.expected_revision_heads",
        });
    }
    reject_duplicates(
        batch
            .expected_revision_heads
            .iter()
            .map(|head| head.key.clone()),
        "restore.expected_revision_heads",
    )?;
    reject_duplicates(
        batch
            .expected_ordering_heads
            .iter()
            .map(|head| head.scope.clone()),
        "restore.expected_ordering_heads",
    )?;
    for head in &batch.expected_revision_heads {
        head.validate()?;
    }
    for head in &batch.expected_ordering_heads {
        head.validate()?;
    }
    if batch.member_count == 0 {
        return Err(StoreError::InvalidField {
            field: "restore.member_count",
            reason: "must be non-zero",
        });
    }
    if batch.member_count > MAX_RESTORE_BATCH_MEMBERS as u64 {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Reports whether archive content is suppressed by the current purge policy.
///
/// Content captured under any purge revision other than the current one —
/// including records purged after the archive was taken — must pass current
/// residency, privacy and retention suppression before becoming servable. An
/// unverified (zero) current revision suppresses everything.
#[must_use]
pub const fn is_suppressed_by_current_purge(
    archive_purge_revision: u64,
    current_purge_revision: u64,
) -> bool {
    current_purge_revision == 0 || archive_purge_revision != current_purge_revision
}

/// Derives a fresh destination operational identity for one restore operation.
///
/// The identity binds only the destination id, the operation id, the canonical
/// request hash and the admission handle, digested with [`sha256_hex`]. Source
/// store and installation authority never enter the derivation, so logical
/// identities and history are preserved while operational identity is new.
#[must_use]
pub fn new_destination_identity(
    destination: &IsolatedDestination,
    operation: &OperationIdentity,
) -> String {
    let material = (
        destination.destination_id.as_str(),
        operation.operation_id.as_str(),
        operation.canonical_request_hash.as_str(),
        destination.evidence.admission_handle.as_str(),
    );
    let bytes = canonical_json_bytes(&material).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(256);
        fallback.extend_from_slice(b"isolated-restore-v1");
        fallback.extend_from_slice(destination.destination_id.as_bytes());
        fallback.extend_from_slice(operation.operation_id.as_str().as_bytes());
        fallback.extend_from_slice(operation.canonical_request_hash.as_bytes());
        fallback.extend_from_slice(destination.evidence.admission_handle.as_bytes());
        fallback
    });
    let digest = sha256_hex(&bytes);
    format!("isolated-restore-{digest}")
}

/// Reports whether a restore operation name belongs to the closed vocabulary.
///
/// Only the four isolated-restore port operations are supported; every other
/// name — including physical-copy, query-execution and session/lease/grant
/// operations — is refused with no bypass path.
#[must_use]
pub fn is_supported_restore_operation(name: &str) -> bool {
    SUPPORTED_RESTORE_OPERATIONS.contains(&name)
}

/// Binds one build identity for the restoring bridge from admitted
/// configuration.
///
/// The binding covers the provider artifact digest, the admitted provider major
/// and the expected schema generation, so a destination prepared by one build
/// is never silently continued by another.
fn restore_build_identity(config: &SurrealAdapterConfig) -> String {
    let shape = (
        config.provider_artifact_digest.as_str(),
        config.expected_schema_generation.as_str(),
        crate::config::PINNED_SURREALDB_MAJOR,
    );
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(192);
        fallback.extend_from_slice(b"isolated-restore-build-v1");
        fallback.extend_from_slice(config.provider_artifact_digest.as_bytes());
        fallback.extend_from_slice(config.expected_schema_generation.as_str().as_bytes());
        fallback
    });
    sha256_hex(&bytes)
}

/// Digests the source pair an isolated destination restores from.
fn declared_source_digest(destination: &IsolatedDestination) -> String {
    let shape = (
        destination.source_store_id.as_str(),
        destination.source_installation_id.as_str(),
    );
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(128);
        fallback.extend_from_slice(b"isolated-restore-declared-source-v1");
        fallback.extend_from_slice(destination.source_store_id.as_bytes());
        fallback.extend_from_slice(destination.source_installation_id.as_bytes());
        fallback
    });
    sha256_hex(&bytes)
}

/// Digests the exact archive source identity of one batch.
fn source_identity_digest(source: &SnapshotSourceIdentity) -> String {
    let shape = (
        source.store_id.as_str(),
        source.installation_id.as_str(),
        source.schema.as_str(),
        source.generation.value(),
    );
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(160);
        fallback.extend_from_slice(b"isolated-restore-source-v1");
        fallback.extend_from_slice(source.store_id.as_bytes());
        fallback.extend_from_slice(source.installation_id.as_bytes());
        fallback.extend_from_slice(source.schema.as_bytes());
        fallback.extend_from_slice(source.generation.value().to_string().as_bytes());
        fallback
    });
    sha256_hex(&bytes)
}

/// Derives the deterministic restore operation identity of one destination
/// preparation.
///
/// `IsolatedDestination` carries no caller operation identity, so the
/// preparation identity is derived deterministically from the admitted
/// destination itself. This keeps the derived destination identity stable for
/// idempotent re-preparation and distinct per destination.
fn prepare_operation_identity(
    destination: &IsolatedDestination,
) -> Result<OperationIdentity, StoreError> {
    let digest = sha256_hex(&canonical_digest_bytes(&(
        destination.destination_id.as_str(),
        destination.evidence.admission_handle.as_str(),
        destination.evidence.admitted_at_unix_ms,
        destination.evidence.purge_policy_revision,
        destination.target_schema.as_str(),
    ))?);
    let identity = format!("restore-prepare-{digest}");
    Ok(OperationIdentity {
        operation_id: OperationId::new(identity.clone()).map_err(|_error| {
            StoreError::InvalidField {
                field: "restore.operation_id",
                reason: "derived preparation identity is invalid",
            }
        })?,
        idempotency_key: identity,
        canonical_request_hash: digest,
    })
}

/// Derives the deterministic member identity of one archive member inside a
/// destination.
///
/// The identity binds only the admitted archive member digest and the member
/// index, so a retry, a resume or a later readback reuses the *original* member
/// identity instead of minting a new one.
fn member_reference(archive_member_digest: &str, member_index: u64) -> String {
    let shape = ("restore-member-v1", archive_member_digest, member_index);
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(128);
        fallback.extend_from_slice(b"restore-member-v1");
        fallback.extend_from_slice(archive_member_digest.as_bytes());
        fallback.extend_from_slice(member_index.to_string().as_bytes());
        fallback
    });
    sha256_hex(&bytes)
}

/// Derives one deterministic registry row key.
fn registry_key(prefix: &str, material: &str) -> String {
    let bytes = canonical_json_bytes(&(prefix, material)).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(128);
        fallback.extend_from_slice(prefix.as_bytes());
        fallback.extend_from_slice(material.as_bytes());
        fallback
    });
    format!("{prefix}{}", sha256_hex(&bytes))
}

/// Derives the deterministic provider record id of one registry row.
fn registry_record_id(key: &str) -> Result<String, StoreError> {
    let bytes = canonical_digest_bytes(&eliot_store_api::RecoveryRecordKey {
        namespace: crate::client::RESTORE_NAMESPACE.to_owned(),
        key: key.to_owned(),
    })?;
    Ok(sha256_hex(&bytes))
}

/// Derives the destination fence row key for one destination id.
fn destination_key(destination_id: &str) -> String {
    registry_key(
        crate::client::RESTORE_KEY_DESTINATION_PREFIX,
        destination_id,
    )
}

/// Derives the per-operation record row key.
fn record_key(operation_id: &str) -> String {
    registry_key(crate::client::RESTORE_KEY_RECORD_PREFIX, operation_id)
}

/// Derives the archive-placement exclusivity row key.
fn placement_key(archive_member_digest: &str, destination_id: &str) -> Result<String, StoreError> {
    let digest = sha256_hex(&canonical_digest_bytes(&(
        archive_member_digest,
        destination_id,
    ))?);
    Ok(registry_key(
        crate::client::RESTORE_KEY_PLACEMENT_PREFIX,
        &digest,
    ))
}

/// Derives the current purge-ledger member row key for one archive member.
fn purge_member_key(archive_member_digest: &str) -> String {
    registry_key(
        crate::client::RESTORE_KEY_PURGE_MEMBER_PREFIX,
        archive_member_digest,
    )
}

/// Derives the current purge-ledger source-scope row key.
fn purge_scope_key(source_installation_id: &str) -> String {
    registry_key(
        crate::client::RESTORE_KEY_PURGE_SCOPE_PREFIX,
        source_installation_id,
    )
}

/// Builds one durable registry row from an encoded document.
fn registry_row(
    key: &str,
    schema: &str,
    fence: &StateFence,
    revision: u64,
    payload: Vec<u8>,
    value_digest: String,
) -> RecoveryRecord {
    RecoveryRecord {
        namespace: crate::client::RESTORE_NAMESPACE.to_owned(),
        key: key.to_owned(),
        state_fence: fence.clone(),
        revision,
        schema: schema.to_owned(),
        payload,
        value_digest,
    }
}

/// The destination fence row plus the durable row coordinates an apply
/// transaction must fence on.
struct DestinationFence {
    document: RestoreDestinationDocument,
    revision: u64,
    state_fence: StateFence,
}

/// Returns the connected, ready-to-serve provider transport for restore work.
///
/// Restore never constructs a client: it reuses the adapter's single provider
/// owner, its bounded session pool and the shared readiness gate, and it refuses
/// when the database is not migrated to the admitted generation.
async fn restore_transport(adapter: &SurrealStoreAdapter) -> Result<&RpcTransport, StoreError> {
    let transport = crate::apply::client(adapter)
        .await
        .map_err(AdapterError::into_store_error)?;
    crate::apply::ensure_ready(adapter, transport)
        .await
        .map_err(AdapterError::into_store_error)?;
    Ok(transport)
}

/// Refuses to run unless the fixed registry implements the isolated-restore
/// capability this module advertises.
///
/// The registry and the port must agree on one capability: a registry
/// re-exported under a different capability would otherwise execute statements
/// the port does not own, so the phase is refused instead.
fn check_registry_capability() -> Result<(), StoreError> {
    if crate::client::restore_capability() == RESTORE_CAPABILITY {
        Ok(())
    } else {
        Err(StoreError::UnknownOperation)
    }
}

/// Executes one closed restore read operation over the adapter's facade
/// session and returns its decoded statement results.
///
/// The pinned statement is looked up in the closed registry and executed here;
/// it is never handed back to a caller as an unexecuted string.
async fn execute_restore_read(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &'static str,
    bindings: serde_json::Map<String, serde_json::Value>,
) -> Result<crate::client::RpcResults, StoreError> {
    check_registry_capability()?;
    crate::client::validate_restore_operation(operation).map_err(AdapterError::into_store_error)?;
    let statement = crate::client::fixed_restore_statement(operation)
        .map_err(AdapterError::into_store_error)?;
    let mut response = crate::client::query(transport, config, operation, statement, bindings)
        .await
        .map_err(AdapterError::into_store_error)?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        // A read performs no mutation, so an unclassified provider rejection is
        // honest unavailability rather than an ambiguous commit — but a typed
        // rejection keeps its typed code instead of being collapsed into one.
        return Err(classify_restore_errors(&errors, StoreError::Unavailable));
    }
    Ok(response)
}

/// Classifies the provider statement errors of one closed restore operation.
///
/// The read and write paths share one closed classification, so a typed provider
/// rejection is never collapsed into a generic code on either lane: a
/// duplicate/unique-index rejection means a concurrent winner owns the row (an
/// identity conflict), a lost destination compare-and-set is a revision
/// conflict, and an absent destination fence refuses the operation. `fallback`
/// is the fail-closed answer for anything unclassified; it differs per lane
/// because a read mutated nothing while a write leaves its commit ambiguous.
fn classify_restore_errors(errors: &[String], fallback: StoreError) -> StoreError {
    if errors
        .iter()
        .any(|error| crate::client::is_restore_duplicate(error))
    {
        return StoreError::IdentityConflict;
    }
    if errors
        .iter()
        .any(|error| crate::client::is_restore_fence_race(error))
    {
        return StoreError::RevisionConflict;
    }
    if errors
        .iter()
        .any(|error| crate::client::is_restore_destination_absent(error))
    {
        return StoreError::InvalidField {
            field: "restore.destination_id",
            reason: "isolated destination is not prepared",
        };
    }
    fallback
}

/// Executes one closed restore write operation on the pooled normal-write lane.
///
/// Restore writes share the bounded normal-write lane with canonical reserved
/// writes: the port never takes the protected permit, the health/admin lane, or
/// any bypass of the maintenance-admission facade, so a restore cannot relabel
/// itself protected work.
async fn execute_restore_write(
    transport: &RpcTransport,
    operation: &'static str,
    bindings: serde_json::Map<String, serde_json::Value>,
) -> Result<(), StoreError> {
    check_registry_capability()?;
    crate::client::validate_restore_operation(operation).map_err(AdapterError::into_store_error)?;
    let statement = crate::client::fixed_restore_statement(operation)
        .map_err(AdapterError::into_store_error)?;
    let mut response = transport
        .query_write(operation, statement, bindings)
        .await
        .map_err(AdapterError::into_store_error)?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    // Any other statement error leaves the commit outcome ambiguous: the port
    // never reports success, non-application, or a fabricated receipt.
    Err(classify_restore_errors(
        &errors,
        StoreError::MissingReceiptEnvelope,
    ))
}

/// Reads one exact registry row, returning `None` only on a positive
/// absent-row observation.
async fn read_registry_row(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &'static str,
    key: &str,
) -> Result<Option<RecoveryRecord>, StoreError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "restore_namespace".to_owned(),
        serde_json::Value::String(crate::client::RESTORE_NAMESPACE.to_owned()),
    );
    bindings.insert(
        "restore_key".to_owned(),
        serde_json::Value::String(key.to_owned()),
    );
    let mut response = execute_restore_read(transport, config, operation, bindings).await?;
    let rows: Vec<RecoveryRecord> = response.take(0).map_err(AdapterError::into_store_error)?;
    if rows.len() > 1 {
        return Err(StoreError::InvalidReceipt);
    }
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    if row.namespace != crate::client::RESTORE_NAMESPACE || row.key != key {
        return Err(StoreError::InvalidReceipt);
    }
    if row.revision == 0 || sha256_hex(&row.payload) != row.value_digest {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(Some(row))
}

/// Reads and validates one destination fence row.
async fn read_destination_fence(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    destination_id: &str,
) -> Result<Option<DestinationFence>, StoreError> {
    let key = destination_key(destination_id);
    let Some(row) = read_registry_row(
        transport,
        config,
        crate::client::RESTORE_OPERATION_FENCE,
        &key,
    )
    .await?
    else {
        return Ok(None);
    };
    if row.schema != crate::client::RESTORE_SCHEMA_DESTINATION {
        return Err(StoreError::InvalidReceipt);
    }
    let document: RestoreDestinationDocument = decode_document(&row)?;
    document.validate()?;
    if document.destination_id != destination_id {
        return Err(StoreError::IdentityConflict);
    }
    Ok(Some(DestinationFence {
        document,
        revision: row.revision,
        state_fence: row.state_fence,
    }))
}

/// Reads and validates one per-operation record document.
async fn read_record_document(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &'static str,
    operation_id: &str,
) -> Result<Option<RestoreRecordDocument>, StoreError> {
    let key = record_key(operation_id);
    let Some(row) = read_registry_row(transport, config, operation, &key).await? else {
        return Ok(None);
    };
    if row.schema != crate::client::RESTORE_SCHEMA_RECORD {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(Some(decode_document(&row)?))
}

/// Decodes one durable registry document from its row payload.
fn decode_document<T: for<'de> Deserialize<'de>>(row: &RecoveryRecord) -> Result<T, StoreError> {
    serde_json::from_slice(&row.payload)
        .map_err(|error| AdapterError::Serialization(error.to_string()).into_store_error())
}

/// Reads the current purge ledger for one batch scope: the member obligation
/// and the source-scope obligation, in one dispatch.
async fn read_purge_ledger(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    archive_member_digest: &str,
    source_installation_id: &str,
) -> Result<(Option<PurgeLedgerEntry>, Option<PurgeLedgerEntry>), StoreError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "restore_namespace".to_owned(),
        serde_json::Value::String(crate::client::RESTORE_NAMESPACE.to_owned()),
    );
    bindings.insert(
        "restore_member_key".to_owned(),
        serde_json::Value::String(purge_member_key(archive_member_digest)),
    );
    bindings.insert(
        "restore_scope_key".to_owned(),
        serde_json::Value::String(purge_scope_key(source_installation_id)),
    );
    let mut response = execute_restore_read(
        transport,
        config,
        crate::client::RESTORE_OPERATION_PURGE_LEDGER,
        bindings,
    )
    .await?;
    let member_rows: Vec<RecoveryRecord> =
        response.take(0).map_err(AdapterError::into_store_error)?;
    let scope_rows: Vec<RecoveryRecord> =
        response.take(1).map_err(AdapterError::into_store_error)?;
    Ok((
        decode_purge_entry(member_rows.into_iter().next())?,
        decode_purge_entry(scope_rows.into_iter().next())?,
    ))
}

/// Decodes one purge-ledger row, refusing a foreign namespace or schema.
fn decode_purge_entry(row: Option<RecoveryRecord>) -> Result<Option<PurgeLedgerEntry>, StoreError> {
    let Some(row) = row else {
        return Ok(None);
    };
    if row.namespace != crate::client::RESTORE_NAMESPACE
        || row.schema != crate::client::RESTORE_SCHEMA_PURGE
    {
        return Err(StoreError::InvalidReceipt);
    }
    let entry: PurgeLedgerEntry = decode_document(&row)?;
    entry.validate()?;
    Ok(Some(entry))
}

/// Decision taken from the current purge-ledger readback.
enum PurgeDecision {
    /// No recorded obligation for this scope: the members may be restored.
    Clear,
    /// A durably complete obligation covers the whole member set.
    Suppressed,
    /// An obligation exists but is not durably complete, so the members can
    /// neither be restored nor reported resolved.
    Unresolved,
}

/// Decides the disposition of one member set from the current purge ledger.
///
/// A complete obligation suppresses the whole observed member set; a recorded
/// but incomplete obligation leaves it unresolved. Suppression is decided by the
/// durable ledger, never by the archive's own declared purge revision, so
/// records purged after the archive was created can never become servable.
fn decide_purge(
    member_entry: Option<&PurgeLedgerEntry>,
    scope_entry: Option<&PurgeLedgerEntry>,
) -> PurgeDecision {
    let entries = [member_entry, scope_entry];
    if entries
        .iter()
        .any(|entry| entry.is_some_and(|entry| !entry.state.is_purged()))
    {
        return PurgeDecision::Unresolved;
    }
    if entries.iter().any(Option::is_some) {
        return PurgeDecision::Suppressed;
    }
    PurgeDecision::Clear
}

/// Verifies the destination admission is current, not merely well-formed.
fn check_admission_freshness(
    evidence: &IsolationEvidence,
    now_unix_ms: i64,
) -> Result<(), StoreError> {
    let admitted_at = evidence.admitted_at_unix_ms;
    if admitted_at > now_unix_ms {
        return Err(StoreError::InvalidField {
            field: "restore.admitted_at_unix_ms",
            reason: "restore admission is not yet effective",
        });
    }
    if now_unix_ms - admitted_at > MAX_ADMISSION_AGE_MS {
        return Err(StoreError::InvalidField {
            field: "restore.admitted_at_unix_ms",
            reason: "restore admission is stale",
        });
    }
    Ok(())
}

/// Enforces the restore duration bound against one recorded start time.
fn check_duration(started_at_unix_ms: i64, now_unix_ms: i64) -> Result<(), StoreError> {
    if started_at_unix_ms <= 0 {
        return Err(StoreError::InvalidField {
            field: "restore.started_at_unix_ms",
            reason: "restore start time is unverified",
        });
    }
    let elapsed = now_unix_ms.saturating_sub(started_at_unix_ms);
    if elapsed < 0 {
        return Err(StoreError::InvalidField {
            field: "restore.started_at_unix_ms",
            reason: "restore start time is not yet effective",
        });
    }
    if u64::try_from(elapsed).is_ok_and(|elapsed| elapsed > MAX_RESTORE_DURATION_MS) {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Enforces the cumulative restore byte bound.
fn check_cumulative_bytes(cumulative: u64, added: u64) -> Result<(), StoreError> {
    if cumulative.saturating_add(added) > MAX_RESTORE_BYTES {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Refuses a phase whose operation identity was cancelled in the installed
/// write-execution generation, preserving the original failure class.
fn check_cancellation(
    adapter: &SurrealStoreAdapter,
    operation: &OperationIdentity,
) -> Result<(), StoreError> {
    let Some(execution) = adapter.execution_handle() else {
        return Ok(());
    };
    if execution.is_cancelled(&operation.operation_id) {
        // A cancelled phase reports the original failure when one exists, so a
        // bounded or cancelled attempt never masks why the operation first
        // failed.
        let key = operation.operation_id.as_str();
        if let Some(original) = original_failure(key) {
            return Err(original);
        }
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

/// Verifies the expected-state identity: every expected head must carry the
/// request's state fence, so a batch cannot bind heads from another fence.
fn check_expected_state(
    batch: &CanonicalRestoreBatch,
    ctx: &RequestMeta,
) -> Result<(), StoreError> {
    for head in &batch.expected_revision_heads {
        if head.state_fence != ctx.state_fence {
            return Err(StoreError::FenceMismatch);
        }
    }
    for head in &batch.expected_ordering_heads {
        if head.state_fence != ctx.state_fence {
            return Err(StoreError::FenceMismatch);
        }
    }
    Ok(())
}

/// Digests the expected revision/ordering heads of one batch.
fn expected_head_digests(batch: &CanonicalRestoreBatch) -> (Vec<String>, Vec<String>) {
    let revision_digests = batch
        .expected_revision_heads
        .iter()
        .map(|head| sha256_hex(&canonical_json_bytes(head).unwrap_or_default()))
        .collect();
    let ordering_digests = batch
        .expected_ordering_heads
        .iter()
        .map(|head| sha256_hex(&canonical_json_bytes(head).unwrap_or_default()))
        .collect();
    (revision_digests, ordering_digests)
}

/// Verifies that a durable record belongs to exactly this batch: same
/// operation identity and canonical request hash, destination, source identity,
/// member digest, schema, purge policy, expected state and denominator. Any
/// divergence is an identity conflict, never a silent overwrite.
#[allow(clippy::too_many_arguments)]
fn check_record_binding(
    document: &RestoreRecordDocument,
    batch: &CanonicalRestoreBatch,
    source_digest: &str,
    expected_state_fence: &StateFence,
    revision_digests: &[String],
    ordering_digests: &[String],
) -> Result<(), StoreError> {
    if document.operation.operation_id != batch.operation.operation_id
        || document.operation.canonical_request_hash != batch.operation.canonical_request_hash
        || document.destination_id != batch.destination.destination_id
        || document.archive_member_digest != batch.archive_member_digest
        || document.target_schema != batch.target_schema
        || document.current_purge_revision != batch.purge_policy_revision
        || document.source_identity_digest != source_digest
        || &document.expected_state_fence != expected_state_fence
        || document.expected_revision_head_digests != revision_digests
        || document.expected_ordering_head_digests != ordering_digests
        || document.denominator.total != batch.member_count
    {
        return Err(StoreError::IdentityConflict);
    }
    Ok(())
}

/// Re-derives completeness and disposition from the per-member durable records a
/// document actually carries.
///
/// The stored scalars are never trusted as the source of the verdict. A
/// member-set obligation resolves one disposition for the whole set, so an
/// honest document carries exactly one observed per-member disposition, and the
/// per-member tally must be exactly the durable denominator. A document whose
/// members disagree with each other, with the denominator, or that claims
/// `Complete` beside unresolved members is rejected rather than reported ready.
fn observed_outcome(
    document: &RestoreRecordDocument,
    denominator: &RestoreDenominator,
) -> Result<(SnapshotCompleteness, StoreMutationDisposition), StoreError> {
    let mut observed: Option<MemberDisposition> = None;
    let mut restored = 0_u64;
    let mut suppressed = 0_u64;
    let mut unresolved = 0_u64;
    for member in &document.members {
        match member.disposition {
            MemberDisposition::Restored => restored = restored.saturating_add(1),
            MemberDisposition::Suppressed => suppressed = suppressed.saturating_add(1),
            MemberDisposition::Unresolved => unresolved = unresolved.saturating_add(1),
        }
        if let Some(first) = observed {
            if first != member.disposition {
                return Err(StoreError::InvalidReceipt);
            }
        } else {
            observed = Some(member.disposition);
        }
    }
    // The per-member tally is the observation; the denominator only agrees with
    // it when the record is honest.
    if restored != denominator.restored
        || suppressed != denominator.suppressed
        || unresolved != denominator.unresolved
    {
        return Err(StoreError::InvalidReceipt);
    }
    match observed {
        Some(MemberDisposition::Restored) => Ok((
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )),
        Some(MemberDisposition::Suppressed) => Ok((
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::ProvenNotApplied,
        )),
        Some(MemberDisposition::Unresolved) => Ok((
            SnapshotCompleteness::Partial,
            StoreMutationDisposition::Partial,
        )),
        // A member set is non-empty by admission and its length was already
        // matched against the denominator, so an empty observation is
        // manufactured accounting rather than an empty restore.
        None => Err(StoreError::InvalidReceipt),
    }
}

/// Projects the store-neutral receipt from the exact durable record.
///
/// Completeness and disposition are **re-derived** from the members the record
/// actually carries, never copied from its stored scalars: a digest-valid row
/// claiming `Complete` beside unresolved members would otherwise be propagated
/// as ready, and the receipt contract enforces only `unresolved == 0` implies
/// `Complete`, not the converse. The stored values are then cross-checked
/// against the derivation and any disagreement fails closed.
fn receipt_from_document(
    document: &RestoreRecordDocument,
    batch: &CanonicalRestoreBatch,
) -> Result<RestoreValidationReceipt, StoreError> {
    let denominator = document.denominator;
    denominator.validate()?;
    if denominator.total != batch.member_count {
        return Err(StoreError::IdentityConflict);
    }
    if document.members.len() as u64 != batch.member_count {
        return Err(StoreError::InvalidReceipt);
    }
    let (completeness, disposition) = observed_outcome(document, &denominator)?;
    if document.completeness != completeness || document.disposition != disposition {
        return Err(StoreError::InvalidReceipt);
    }
    let receipt = RestoreValidationReceipt {
        operation: document.operation.clone(),
        destination: batch.destination.clone(),
        archive_member_digest: document.archive_member_digest.clone(),
        resolved_members: denominator.resolved(),
        unresolved_members: denominator.unresolved,
        denominator_members: denominator.total,
        completeness,
        disposition,
    };
    receipt.validate().map_err(redact_store_error)?;
    Ok(receipt)
}

/// Verifies one destination fence against the batch and the restoring build.
fn check_destination_fence(
    fence: &RestoreDestinationDocument,
    batch: &CanonicalRestoreBatch,
    build_identity: &str,
) -> Result<(), StoreError> {
    if fence.source_store_id != batch.destination.source_store_id
        || fence.source_installation_id != batch.destination.source_installation_id
    {
        return Err(StoreError::InvalidField {
            field: "restore.source_store_id",
            reason: "source identity does not match the admitted destination",
        });
    }
    if batch.source.store_id != batch.destination.source_store_id
        || batch.source.installation_id != batch.destination.source_installation_id
    {
        return Err(StoreError::InvalidField {
            field: "restore.source_store_id",
            reason: "batch source does not match its declared destination source",
        });
    }
    if fence.declared_source_digest != declared_source_digest(&batch.destination) {
        return Err(StoreError::IdentityConflict);
    }
    if fence.target_schema != batch.target_schema {
        return Err(StoreError::InvalidField {
            field: "restore.target_schema",
            reason: "destination schema does not match the admitted fence",
        });
    }
    if fence.restore_build_identity != build_identity {
        return Err(StoreError::InvalidField {
            field: "restore.restore_build_identity",
            reason: "restoring build identity does not match the destination fence",
        });
    }
    Ok(())
}

/// Builds the per-member durable dispositions for one member set.
fn member_records(
    batch: &CanonicalRestoreBatch,
    domains: &RestoreDomains,
    disposition: MemberDisposition,
    purge_revision: u64,
) -> Vec<RestoreMemberRecord> {
    // `member_count` is bounded by `validate_reference_closure`, so the
    // conversion cannot lose members; the fallback is the global ceiling.
    let count = usize::try_from(batch.member_count).unwrap_or(MAX_RESTORE_BATCH_MEMBERS);
    (0..count)
        .map(|index| {
            let member_index = u64::try_from(index).unwrap_or(u64::MAX);
            RestoreMemberRecord {
                member_ref: member_reference(&batch.archive_member_digest, member_index),
                member_index,
                disposition,
                residency_domain: domains.residency.clone(),
                privacy_domain: domains.privacy.clone(),
                retention_domain: domains.retention.clone(),
                purge_policy_revision: purge_revision,
            }
        })
        .collect()
}

/// Builds one per-phase receipt entry for the destination fence document.
fn phase_receipt(
    batch: &CanonicalRestoreBatch,
    denominator: RestoreDenominator,
    committed_at_unix_ms: i64,
) -> Result<RestorePhaseReceipt, StoreError> {
    let shape = (
        RESTORE_PHASE_APPLIED,
        batch.operation.operation_id.as_str(),
        batch.archive_member_digest.as_str(),
        denominator.restored,
        denominator.rejected,
        denominator.suppressed,
        denominator.unresolved,
        denominator.total,
        committed_at_unix_ms,
    );
    Ok(RestorePhaseReceipt {
        phase: RESTORE_PHASE_APPLIED.to_owned(),
        operation_id: batch.operation.operation_id.as_str().to_owned(),
        archive_member_digest: batch.archive_member_digest.clone(),
        restored_members: denominator.restored,
        rejected_members: denominator.rejected,
        suppressed_members: denominator.suppressed,
        unresolved_members: denominator.unresolved,
        denominator_members: denominator.total,
        committed_at_unix_ms,
        receipt_digest: sha256_hex(&canonical_digest_bytes(&shape)?),
    })
}

/// Binds one committed phase into the destination fence document.
fn destination_after_phase(
    destination: &RestoreDestinationDocument,
    receipt: RestorePhaseReceipt,
    document_bytes: u64,
) -> Result<RestoreDestinationDocument, StoreError> {
    let cumulative_bytes = destination
        .cumulative_bytes
        .checked_add(document_bytes)
        .ok_or(StoreError::PayloadTooLarge)?;
    let mut phases = destination.phases.clone();
    phases.push(receipt);
    Ok(RestoreDestinationDocument {
        applied_operations: destination.applied_operations.saturating_add(1),
        cumulative_bytes,
        phases,
        ..destination.clone()
    })
}

/// Builds a reconciliation record from a provider-verified cached receipt.
///
/// The cache is keyed by operation id alone, so the entry is **re-verified
/// against `first`** exactly the way the durable path re-verifies the record: a
/// cached operation id or canonical request hash that differs from the claim
/// being reconciled answers a question the caller never asked, so it is an
/// identity conflict rather than an answer. `outcome` is the classification
/// already derived from `first` against `second` and is carried through
/// unchanged, so a computed conflict can never be dropped in favour of the
/// cached receipt's own verdict. When the entry cannot be shown to belong to
/// `first`, the only honest answers are this refusal or an unknown outcome.
fn reconciliation_from_receipt(
    receipt: &RestoreValidationReceipt,
    first: &OperationIdentity,
    second: &OperationIdentity,
    outcome: ReconciliationOutcome,
) -> Result<BackupOperationReconciliation, StoreError> {
    if receipt.operation.operation_id != first.operation_id
        || receipt.operation.canonical_request_hash != first.canonical_request_hash
    {
        return Err(StoreError::IdentityConflict);
    }
    let reconciliation = BackupOperationReconciliation {
        operation: first.clone(),
        first_digest: first.canonical_request_hash.clone(),
        second_digest: second.canonical_request_hash.clone(),
        outcome,
    };
    reconciliation.validate().map_err(redact_store_error)?;
    Ok(reconciliation)
}

impl IsolatedRestorePort for SurrealStoreAdapter {
    /// Prepares an isolated restore destination.
    ///
    /// Verifies the external admission and the isolation fence, then binds the
    /// destination owner's freshly derived operational identity into a durable
    /// fence row inside one provider transaction. A destination that is already
    /// prepared is reconciled by exact readback: identical evidence replays,
    /// different evidence conflicts, and the fence is never re-bound.
    async fn prepare_isolated_destination(
        &self,
        ctx: &RequestMeta,
        destination: IsolatedDestination,
    ) -> Result<IsolationEvidence, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        let (active_store, active_installation) = active_store_identity(&self.config);
        validate_isolated_destination(&destination, &active_store, &active_installation)
            .map_err(redact_store_error)?;
        if destination.target_schema != self.config.expected_schema_generation.as_str() {
            return Err(StoreError::InvalidField {
                field: "restore.target_schema",
                reason: "isolated destination must target the admitted schema generation",
            });
        }
        let now = current_unix_ms();
        check_admission_freshness(&destination.evidence, now)?;
        let transport = restore_transport(self).await?;
        let prepare_identity = prepare_operation_identity(&destination)?;
        // The destination owner derives its own operational identity from its own
        // admission; source store/installation authority never enters it.
        let destination_identity = new_destination_identity(&destination, &prepare_identity);
        let binding = AdmissionBinding {
            declared_source_digest: declared_source_digest(&destination),
            restore_build_identity: restore_build_identity(&self.config),
            domains: RestoreDomains::derive(&destination, &destination_identity),
            destination_identity,
        };
        let admission_digest =
            RestoreDestinationDocument::admission_digest(&destination, &binding)?;
        let key = destination_key(&destination.destination_id);
        if let Some(existing) =
            read_destination_fence(transport, &self.config, &destination.destination_id).await?
        {
            // The destination fence binds once: identical evidence replays, any
            // other evidence is an identity conflict.
            if existing.document.admission_digest != admission_digest {
                return Err(StoreError::IdentityConflict);
            }
            return Ok(destination.evidence.clone());
        }
        let document = destination_document(&destination, &binding, admission_digest, now)?;
        let row = destination_registry_row(&document, &key, &ctx.state_fence)?;
        let bindings = prepare_bindings(&row)?;
        match execute_restore_write(
            transport,
            crate::client::RESTORE_OPERATION_PREPARE,
            bindings,
        )
        .await
        {
            Ok(()) => {}
            Err(StoreError::IdentityConflict) => {
                // A concurrent winner created the row first: reconcile by exact
                // readback instead of overwriting the fence.
                let existing =
                    read_destination_fence(transport, &self.config, &destination.destination_id)
                        .await?
                        .ok_or(StoreError::MissingReceiptEnvelope)?;
                if existing.document.admission_digest != document.admission_digest {
                    return Err(StoreError::IdentityConflict);
                }
            }
            Err(error) => return Err(error),
        }
        let confirmed =
            read_destination_fence(transport, &self.config, &destination.destination_id)
                .await?
                .ok_or(StoreError::MissingReceiptEnvelope)?;
        if confirmed.document.admission_digest != document.admission_digest {
            return Err(StoreError::IdentityConflict);
        }
        Ok(destination.evidence.clone())
    }

    /// Applies one canonical restore batch into the isolated destination.
    ///
    /// Before any write it verifies, from the destination owner's durable
    /// evidence: the current external admission, the destination isolation
    /// fence, the build/schema identity, the source binding, the current purge
    /// policy revision, the canonical closure and the complete operation
    /// identity. It then commits the restored members and their durable receipt
    /// in one provider transaction that also advances the destination fence, and
    /// derives the returned receipt from exact durable readback. A repeated
    /// same-operation input reconciles to the original receipt, changed content
    /// conflicts, and a lost response stays unknown.
    async fn restore_canonical_batch(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        let operation_key = batch.operation.operation_id.as_str().to_owned();
        begin_attempt(&operation_key, RESTORE_PHASE_APPLIED)?;
        let outcome = self
            .apply_canonical_batch(ctx, &batch)
            .await
            .map_err(redact_store_error);
        end_attempt(&operation_key, outcome.as_ref().err());
        outcome
    }

    /// Certifies one canonical restore batch as isolated-restore-ready.
    ///
    /// A pure ready gate: it never mutates. It re-verifies the destination
    /// admission, fence, build/schema identity, source binding, canonical
    /// closure and bounds, then derives the receipt from the exact durable
    /// record. Absent evidence, an unclosed denominator, unresolved members or
    /// an advanced destination purge policy all prevent readiness; nothing is
    /// ever reported complete from row counts.
    async fn validate_restore(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        batch.validate()?;
        check_cancellation(self, &batch.operation)?;
        check_expected_state(&batch, ctx)?;
        validate_reference_closure(&batch).map_err(redact_store_error)?;
        let (active_store, active_installation) = active_store_identity(&self.config);
        let now = current_unix_ms();
        let transport = restore_transport(self).await?;
        let fence = self
            .destination_fence(transport, &batch, &active_store, &active_installation)
            .await?;
        check_duration(fence.document.prepared_at_unix_ms, now)?;
        let source = self.source_binding(&batch, &fence.document)?;
        let record = self
            .read_record(
                transport,
                crate::client::RESTORE_OPERATION_VALIDATE,
                &batch,
                &source.digest,
                &ctx.state_fence,
            )
            .await?
            .ok_or(StoreError::ReceiptNotFound)?;
        // The record is only certifiable while it still sits at the
        // destination's current purge policy: a purge that advanced after the
        // restore prevents readiness instead of silently re-certifying it.
        if record.current_purge_revision != fence.document.purge_policy_revision {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "the destination purge policy advanced after this restore",
            });
        }
        let receipt = receipt_from_document(&record, &batch)?;
        project_verified_receipt(&batch, &receipt)?;
        Ok(receipt)
    }

    /// Reconciles one restore operation by its exact admitted identity.
    ///
    /// The verdict is derived from the exact durable record, not from comparing
    /// two caller claims: the durable canonical request hash must equal the
    /// first claim, and the second claim is classified against it. An absent
    /// record is not proof of non-commit, so it stays unknown.
    async fn reconcile_operation(
        &self,
        first: OperationIdentity,
        second: OperationIdentity,
    ) -> Result<BackupOperationReconciliation, StoreError> {
        let outcome = reconcile_same_operation(&first, &second).map_err(redact_store_error)?;
        let transport = restore_transport(self).await?;
        let operation_key = first.operation_id.as_str().to_owned();
        let durable = read_record_document(
            transport,
            &self.config,
            crate::client::RESTORE_OPERATION_RECONCILE,
            &operation_key,
        )
        .await?;
        if let Some(document) = durable {
            if document.operation.canonical_request_hash != first.canonical_request_hash {
                return Err(StoreError::IdentityConflict);
            }
            let reconciliation = BackupOperationReconciliation {
                operation: first,
                first_digest: document.operation.canonical_request_hash,
                second_digest: second.canonical_request_hash,
                outcome,
            };
            reconciliation.validate().map_err(redact_store_error)?;
            return Ok(reconciliation);
        }
        // No durable record is not proof of non-commit. A cached
        // provider-verified receipt is the only admitted answer, because a
        // confirmed receipt is immutable and create-only.
        //
        // The cache is re-verified here rather than trusted: it is keyed by
        // operation id alone, so an entry cached under a different canonical
        // request hash would otherwise answer for a claim the caller never
        // made, and the conflict already computed from `first` against
        // `second` would be discarded in favour of that entry's own verdict.
        if let Some(receipt) = cached_receipt(&first) {
            return reconciliation_from_receipt(&receipt, &first, &second, outcome);
        }
        Err(StoreError::MissingReceiptEnvelope)
    }
}

/// Builds the durable destination fence document bound at preparation.
fn destination_document(
    destination: &IsolatedDestination,
    binding: &AdmissionBinding,
    admission_digest: String,
    prepared_at_unix_ms: i64,
) -> Result<RestoreDestinationDocument, StoreError> {
    let document = RestoreDestinationDocument {
        admission_digest,
        destination_id: destination.destination_id.clone(),
        destination_class: RESTORE_DESTINATION_CLASS.to_owned(),
        destination_identity: binding.destination_identity.clone(),
        source_store_id: destination.source_store_id.clone(),
        source_installation_id: destination.source_installation_id.clone(),
        declared_source_digest: binding.declared_source_digest.clone(),
        admission_handle: destination.evidence.admission_handle.clone(),
        admitted_at_unix_ms: destination.evidence.admitted_at_unix_ms,
        purge_policy_revision: destination.evidence.purge_policy_revision,
        target_schema: destination.target_schema.clone(),
        restore_build_identity: binding.restore_build_identity.clone(),
        isolation_state: RESTORE_ISOLATION_STATE.to_owned(),
        residency_domain: binding.domains.residency.clone(),
        privacy_domain: binding.domains.privacy.clone(),
        retention_domain: binding.domains.retention.clone(),
        applied_operations: 0,
        cumulative_bytes: 0,
        prepared_at_unix_ms,
        phases: Vec::new(),
    };
    document.validate()?;
    Ok(document)
}

/// Encodes one destination fence document into its durable registry row.
fn destination_registry_row(
    document: &RestoreDestinationDocument,
    key: &str,
    fence: &StateFence,
) -> Result<RecoveryRecord, StoreError> {
    let (payload, value_digest) = encode_document(document)?;
    check_cumulative_bytes(0, u64::try_from(payload.len()).unwrap_or(u64::MAX))?;
    Ok(registry_row(
        key,
        crate::client::RESTORE_SCHEMA_DESTINATION,
        fence,
        1,
        payload,
        value_digest,
    ))
}

/// Builds the bound parameters of one prepare transaction.
fn prepare_bindings(
    row: &RecoveryRecord,
) -> Result<serde_json::Map<String, serde_json::Value>, StoreError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "restore_table".to_owned(),
        serde_json::Value::String(crate::client::RESTORE_REGISTRY_TABLE.to_owned()),
    );
    bindings.insert(
        "restore_destination_row_id".to_owned(),
        serde_json::Value::String(registry_record_id(&row.key)?),
    );
    bindings.insert("restore_destination_record".to_owned(), row_binding(row)?);
    Ok(bindings)
}

/// Encodes one durable registry row as a bound statement parameter.
fn row_binding(row: &RecoveryRecord) -> Result<serde_json::Value, StoreError> {
    serde_json::to_value(row)
        .map_err(|error| AdapterError::Serialization(error.to_string()).into_store_error())
}

impl SurrealStoreAdapter {
    /// Reads the destination fence row a batch is admitted against and verifies
    /// every pre-write admission condition from it.
    async fn destination_fence(
        &self,
        transport: &RpcTransport,
        batch: &CanonicalRestoreBatch,
        active_store: &str,
        active_installation: &str,
    ) -> Result<DestinationFence, StoreError> {
        validate_isolated_destination(&batch.destination, active_store, active_installation)
            .map_err(redact_store_error)?;
        check_admission_freshness(&batch.destination.evidence, current_unix_ms())?;
        let fence =
            read_destination_fence(transport, &self.config, &batch.destination.destination_id)
                .await?
                .ok_or(StoreError::InvalidField {
                    field: "restore.destination_id",
                    reason: "isolated destination is not prepared",
                })?;
        if !fence.document.evidence_matches(&batch.destination.evidence) {
            return Err(StoreError::IdentityConflict);
        }
        if fence.document.target_schema != batch.target_schema
            || batch.target_schema != self.config.expected_schema_generation.as_str()
        {
            return Err(StoreError::InvalidField {
                field: "restore.target_schema",
                reason: "destination schema does not match the admitted fence",
            });
        }
        if fence.document.restore_build_identity != restore_build_identity(&self.config) {
            return Err(StoreError::InvalidField {
                field: "restore.restore_build_identity",
                reason: "restoring build identity does not match the destination fence",
            });
        }
        // A batch captured under a purge policy the destination owner has never
        // admitted is refused; an older archive is resolved against the current
        // purge-ledger readback instead of being trusted.
        if batch.purge_policy_revision > fence.document.purge_policy_revision {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "archive declares a purge policy the destination has not admitted",
            });
        }
        Ok(fence)
    }

    /// Binds and verifies the source identity of one batch against the fence.
    fn source_binding(
        &self,
        batch: &CanonicalRestoreBatch,
        fence: &RestoreDestinationDocument,
    ) -> Result<SourceBinding, StoreError> {
        check_destination_fence(fence, batch, &restore_build_identity(&self.config))?;
        Ok(SourceBinding {
            digest: source_identity_digest(&batch.source),
            domains: RestoreDomains {
                residency: fence.residency_domain.clone(),
                privacy: fence.privacy_domain.clone(),
                retention: fence.retention_domain.clone(),
            },
        })
    }

    /// Reads the exact durable record of one batch, or `None` when absent.
    ///
    /// `operation` labels the fixed readback: the ready gate reads under the
    /// validate label, the apply path reconciles under the reconcile label.
    async fn read_record(
        &self,
        transport: &RpcTransport,
        operation: &'static str,
        batch: &CanonicalRestoreBatch,
        source_digest: &str,
        expected_state_fence: &StateFence,
    ) -> Result<Option<RestoreRecordDocument>, StoreError> {
        let (revision_digests, ordering_digests) = expected_head_digests(batch);
        let document = read_record_document(
            transport,
            &self.config,
            operation,
            batch.operation.operation_id.as_str(),
        )
        .await?;
        let Some(document) = document else {
            return Ok(None);
        };
        check_record_binding(
            &document,
            batch,
            source_digest,
            expected_state_fence,
            &revision_digests,
            &ordering_digests,
        )?;
        Ok(Some(document))
    }

    /// Applies one validated batch and returns the provider-derived receipt.
    #[allow(clippy::too_many_lines)]
    async fn apply_canonical_batch(
        &self,
        ctx: &RequestMeta,
        batch: &CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        batch.validate()?;
        let (active_store, active_installation) = active_store_identity(&self.config);
        check_cancellation(self, &batch.operation)?;
        check_expected_state(batch, ctx)?;
        let now = current_unix_ms();
        let transport = restore_transport(self).await?;
        let fence = self
            .destination_fence(transport, batch, &active_store, &active_installation)
            .await?;
        check_duration(fence.document.prepared_at_unix_ms, now)?;
        let source = self.source_binding(batch, &fence.document)?;
        // The destination owner's durable revision is the only authority for the
        // current purge policy: the batch's own revision is an expectation, and
        // a mismatch is stale admission refused before any write.
        if batch.purge_policy_revision != fence.document.purge_policy_revision {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "archive predates the current destination purge policy",
            });
        }
        validate_restore_batch(
            batch,
            &active_store,
            &active_installation,
            self.config.expected_schema_generation.as_str(),
            fence.document.purge_policy_revision,
            now,
        )
        .map_err(redact_store_error)?;
        // Durable reconciliation first: a repeated same-operation input returns
        // the original receipt, changed content conflicts, and nothing is ever
        // re-applied.
        if let Some(existing) = self
            .read_record(
                transport,
                crate::client::RESTORE_OPERATION_RECONCILE,
                batch,
                &source.digest,
                &ctx.state_fence,
            )
            .await?
        {
            // A resume of an interrupted operation stays inside the duration
            // bound measured from its first durable write, and keeps the
            // original member identities and missing denominator.
            check_duration(existing.started_at_unix_ms, now)?;
            let receipt = receipt_from_document(&existing, batch)?;
            project_verified_receipt(batch, &receipt)?;
            return Ok(receipt);
        }
        let (member_entry, scope_entry) = read_purge_ledger(
            transport,
            &self.config,
            &batch.archive_member_digest,
            &batch.source.installation_id,
        )
        .await?;
        let member_disposition = match decide_purge(member_entry.as_ref(), scope_entry.as_ref()) {
            PurgeDecision::Clear => MemberDisposition::Restored,
            PurgeDecision::Suppressed => MemberDisposition::Suppressed,
            PurgeDecision::Unresolved => MemberDisposition::Unresolved,
        };
        let member_count = batch.member_count;
        let denominator = match member_disposition {
            MemberDisposition::Restored => RestoreDenominator::new(member_count, 0, 0, 0),
            MemberDisposition::Suppressed => RestoreDenominator::new(0, 0, member_count, 0),
            MemberDisposition::Unresolved => RestoreDenominator::new(0, 0, 0, member_count),
        };
        denominator.validate()?;
        let (completeness, mutation) = if denominator.unresolved == 0 {
            if member_disposition == MemberDisposition::Restored {
                (
                    SnapshotCompleteness::Complete,
                    StoreMutationDisposition::Committed,
                )
            } else {
                (
                    SnapshotCompleteness::Complete,
                    StoreMutationDisposition::ProvenNotApplied,
                )
            }
        } else {
            (
                SnapshotCompleteness::Partial,
                StoreMutationDisposition::Partial,
            )
        };
        let members = member_records(
            batch,
            &source.domains,
            member_disposition,
            fence.document.purge_policy_revision,
        );
        let (revision_digests, ordering_digests) = expected_head_digests(batch);
        let document = RestoreRecordDocument {
            operation: batch.operation.clone(),
            destination_id: batch.destination.destination_id.clone(),
            destination_identity: fence.document.destination_identity.clone(),
            source_identity_digest: source.digest.clone(),
            archive_member_digest: batch.archive_member_digest.clone(),
            target_schema: batch.target_schema.clone(),
            current_purge_revision: fence.document.purge_policy_revision,
            expected_state_fence: ctx.state_fence.clone(),
            expected_revision_head_digests: revision_digests,
            expected_ordering_head_digests: ordering_digests,
            denominator,
            members,
            phase: RESTORE_PHASE_APPLIED.to_owned(),
            completeness,
            disposition: mutation,
            started_at_unix_ms: now,
        };
        let (payload, value_digest) = encode_document(&document)?;
        let document_bytes =
            u64::try_from(payload.len()).map_err(|_| StoreError::PayloadTooLarge)?;
        check_cumulative_bytes(fence.document.cumulative_bytes, document_bytes)?;
        let phase = phase_receipt(batch, denominator, now)?;
        let destination = destination_after_phase(&fence.document, phase, document_bytes)?;
        destination.validate()?;
        let (destination_payload, destination_digest) = encode_document(&destination)?;
        let destination_row = registry_row(
            &destination_key(&batch.destination.destination_id),
            crate::client::RESTORE_SCHEMA_DESTINATION,
            &ctx.state_fence,
            fence.revision.saturating_add(1),
            destination_payload,
            destination_digest,
        );
        let record_row_key = record_key(batch.operation.operation_id.as_str());
        let record_row = registry_row(
            &record_row_key,
            crate::client::RESTORE_SCHEMA_RECORD,
            &ctx.state_fence,
            1,
            payload,
            value_digest,
        );
        let placement = RestorePlacementDocument {
            destination_id: batch.destination.destination_id.clone(),
            archive_member_digest: batch.archive_member_digest.clone(),
            operation_id: batch.operation.operation_id.as_str().to_owned(),
            canonical_request_hash: batch.operation.canonical_request_hash.clone(),
        };
        let (placement_payload, placement_digest) = encode_document(&placement)?;
        let placement_key_value = placement_key(
            &batch.archive_member_digest,
            &batch.destination.destination_id,
        )?;
        let placement_row = registry_row(
            &placement_key_value,
            crate::client::RESTORE_SCHEMA_PLACEMENT,
            &ctx.state_fence,
            1,
            placement_payload,
            placement_digest,
        );
        let bindings = apply_bindings(
            &destination_row,
            &record_row,
            &placement_row,
            &record_row_key,
            &placement_key_value,
            &fence,
        )?;
        match execute_restore_write(transport, crate::client::RESTORE_OPERATION_APPLY, bindings)
            .await
        {
            Ok(()) => {}
            Err(StoreError::IdentityConflict) => {
                // A concurrent winner owns this operation identity or this
                // archive placement: reconcile by exact readback, never
                // re-apply under a new identity.
                if let Some(existing) = self
                    .read_record(
                        transport,
                        crate::client::RESTORE_OPERATION_RECONCILE,
                        batch,
                        &source.digest,
                        &ctx.state_fence,
                    )
                    .await?
                {
                    let receipt = receipt_from_document(&existing, batch)?;
                    project_verified_receipt(batch, &receipt)?;
                    return Ok(receipt);
                }
                return Err(StoreError::IdentityConflict);
            }
            Err(StoreError::RevisionConflict) => {
                // The destination fence moved: the exact record decides.
                if let Some(existing) = self
                    .read_record(
                        transport,
                        crate::client::RESTORE_OPERATION_RECONCILE,
                        batch,
                        &source.digest,
                        &ctx.state_fence,
                    )
                    .await?
                {
                    let receipt = receipt_from_document(&existing, batch)?;
                    project_verified_receipt(batch, &receipt)?;
                    return Ok(receipt);
                }
                return Err(StoreError::RevisionConflict);
            }
            Err(error) => return Err(error),
        }
        // The committed receipt is derived from exact durable readback; a lost
        // response stays unknown and is reconciled by operation identity.
        let committed = self
            .read_record(
                transport,
                crate::client::RESTORE_OPERATION_RECONCILE,
                batch,
                &source.digest,
                &ctx.state_fence,
            )
            .await?
            .ok_or(StoreError::MissingReceiptEnvelope)?;
        let receipt = receipt_from_document(&committed, batch)?;
        project_verified_receipt(batch, &receipt)?;
        Ok(receipt)
    }
}

/// Source identity binding of one batch plus the destination-owned domains its
/// members are restored under.
struct SourceBinding {
    digest: String,
    domains: RestoreDomains,
}

/// Builds the bound parameters of one apply transaction.
fn apply_bindings(
    destination_row: &RecoveryRecord,
    record_row: &RecoveryRecord,
    placement_row: &RecoveryRecord,
    record_row_key: &str,
    placement_row_key: &str,
    fence: &DestinationFence,
) -> Result<serde_json::Map<String, serde_json::Value>, StoreError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "restore_table".to_owned(),
        serde_json::Value::String(crate::client::RESTORE_REGISTRY_TABLE.to_owned()),
    );
    bindings.insert(
        "restore_namespace".to_owned(),
        serde_json::Value::String(crate::client::RESTORE_NAMESPACE.to_owned()),
    );
    bindings.insert(
        "restore_destination_key".to_owned(),
        serde_json::Value::String(destination_row.key.clone()),
    );
    bindings.insert(
        "restore_destination_row_id".to_owned(),
        serde_json::Value::String(registry_record_id(&destination_row.key)?),
    );
    bindings.insert(
        "restore_destination_record".to_owned(),
        row_binding(destination_row)?,
    );
    bindings.insert(
        "restore_expected_destination_revision".to_owned(),
        serde_json::Value::from(fence.revision),
    );
    bindings.insert(
        "restore_expected_destination_fence".to_owned(),
        serde_json::to_value(&fence.state_fence)
            .map_err(|error| AdapterError::Serialization(error.to_string()).into_store_error())?,
    );
    bindings.insert(
        "restore_record_row_id".to_owned(),
        serde_json::Value::String(registry_record_id(record_row_key)?),
    );
    bindings.insert("restore_record_row".to_owned(), row_binding(record_row)?);
    bindings.insert(
        "restore_placement_row_id".to_owned(),
        serde_json::Value::String(registry_record_id(placement_row_key)?),
    );
    bindings.insert(
        "restore_placement_row".to_owned(),
        row_binding(placement_row)?,
    );
    Ok(bindings)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_store_api::{DestinationClass, OperationId as TestOperationId};

    const TEST_HASH_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TEST_HASH_B: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn test_destination() -> IsolatedDestination {
        IsolatedDestination {
            destination_id: "isolated-dest-1".to_owned(),
            destination_class: DestinationClass::IsolatedRestore,
            source_store_id: "source-store".to_owned(),
            source_installation_id: "source-installation".to_owned(),
            evidence: IsolationEvidence {
                admission_handle: "admit-1".to_owned(),
                admitted_at_unix_ms: 1_700_000_000_000,
                purge_policy_revision: 3,
            },
            target_schema: "2.0.0".to_owned(),
        }
    }

    fn test_operation(id: &str, hash: &str) -> OperationIdentity {
        OperationIdentity {
            operation_id: TestOperationId::new(id).expect("valid test operation id"),
            idempotency_key: format!("idem-{id}"),
            canonical_request_hash: hash.to_owned(),
        }
    }

    #[test]
    fn denominator_accounting_is_exact() {
        let complete = RestoreDenominator::new(3, 1, 1, 0);
        assert_eq!(complete.total, 5);
        assert!(complete.validate().is_ok());
        assert!(complete.is_complete());

        let pending = RestoreDenominator::new(3, 1, 1, 2);
        assert!(pending.validate().is_ok());
        assert!(!pending.is_complete());

        let tampered = RestoreDenominator {
            total: 99,
            ..RestoreDenominator::new(1, 0, 0, 0)
        };
        assert!(tampered.validate().is_err());
        assert!(!tampered.is_complete());
    }

    #[test]
    fn suppression_covers_divergence_and_unverified_policy() {
        assert!(!is_suppressed_by_current_purge(3, 3));
        assert!(is_suppressed_by_current_purge(2, 3));
        assert!(is_suppressed_by_current_purge(4, 3));
        assert!(is_suppressed_by_current_purge(3, 0));
    }

    #[test]
    fn redaction_removes_payload_prose_and_keeps_typed_variants() {
        let redacted =
            redact_store_error(StoreError::Serialization("secret record bytes".to_owned()));
        match redacted {
            StoreError::Serialization(message) => {
                assert!(!message.contains("secret"));
            }
            other => panic!("expected redacted serialization, got {other:?}"),
        }
        let typed = StoreError::RevisionConflict;
        assert_eq!(redact_store_error(typed.clone()), typed);
    }

    #[test]
    fn supported_operations_are_closed() {
        for name in [
            "prepare_isolated_destination",
            "restore_canonical_batch",
            "validate_restore",
            "reconcile_operation",
        ] {
            assert!(is_supported_restore_operation(name));
        }
        for name in ["", "execute_named", "raw_sql", "live_db_copy"] {
            assert!(!is_supported_restore_operation(name));
        }
    }

    #[test]
    fn destination_identity_is_fresh_and_source_independent() {
        let destination = test_destination();
        let first = test_operation("op-1", TEST_HASH_A);
        let second = test_operation("op-2", TEST_HASH_A);
        assert_eq!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&destination, &first)
        );
        assert_ne!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&destination, &second)
        );
        let mut resourced = destination.clone();
        resourced.source_store_id = "other-source".to_owned();
        resourced.source_installation_id = "other-installation".to_owned();
        assert_eq!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&resourced, &first)
        );
        let mut renamed = destination.clone();
        renamed.destination_id = "isolated-dest-2".to_owned();
        assert_ne!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&renamed, &first)
        );
    }

    #[test]
    fn ledger_reconcile_is_same_operation_only() {
        let ledger = RestoreLedger::new();
        let first = test_operation("op-1", TEST_HASH_A);
        let replay = test_operation("op-1", TEST_HASH_A);
        let changed = test_operation("op-1", TEST_HASH_B);
        let foreign = test_operation("op-2", TEST_HASH_A);
        assert_eq!(
            ledger.reconcile(&first, &replay),
            Ok(ReconciliationOutcome::ReplayIdentity)
        );
        assert_eq!(
            ledger.reconcile(&first, &changed),
            Ok(ReconciliationOutcome::IdentityConflict)
        );
        assert!(ledger.reconcile(&first, &foreign).is_err());
        assert!(ledger.readback(&first).is_none());
    }

    #[test]
    fn isolated_destination_refuses_active_overlap() {
        let destination = test_destination();
        assert!(
            validate_isolated_destination(&destination, "active-store", "active-install").is_ok()
        );
        assert!(
            validate_isolated_destination(&destination, "isolated-dest-1", "active-install")
                .is_err()
        );
        assert!(
            validate_isolated_destination(&destination, "active-store", "isolated-dest-1").is_err()
        );
        let mut foreign = destination.clone();
        foreign.destination_class = DestinationClass::Foreign;
        assert!(validate_isolated_destination(&foreign, "active-store", "active-install").is_err());
    }
}
