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
//! `client::backup_restore` seam). Five keyed row families carry it: the
//! destination fence row, the per-operation record row (members, per-phase
//! receipts and the exact restored/rejected/suppressed/unresolved denominator),
//! the archive-placement exclusivity row, the archive-member carrier rows the
//! archive/artifact owner publishes, and the current purge-ledger rows. No new
//! table, DDL, schema generation or second client exists; the unique
//! `(namespace, key)` index supplies insert-if-absent exclusion, exact replay
//! and changed-content conflict, and the destination fence compare-and-set
//! serializes concurrent restores of one destination.
//!
//! Where the canonical bytes come from: a batch's [`SnapshotMember`] list
//! supplies identities, digests and residency metadata, and is never a payload
//! source. The retained reference the batch carries is the only content input,
//! and it reaches the port the way the owner contract intends: at admission this
//! port *publishes* each retained member as its own carrier row, keyed by that
//! batch's archive member digest, its admitted operation and the member's
//! domain-qualified logical identity, and every identity field of that row is
//! taken from the batch while only the payload, its owner-attested digest and
//! its declared length come from the retained reference. An importable member
//! that retains no payload is refused typed before any write, because a batch
//! that carries no content must not be able to answer with a well-formed
//! partial receipt. Resolution then reads those rows back — the ones this
//! operation wrote, under this operation's own key — and compares every field
//! against the batch's own member before the payload is used, including the
//! owner's attested payload digest, which is validated against the bytes the
//! carrier actually holds. A carrier this operation published and cannot read
//! back is an unresolved member, never a member with empty content. The resolved
//! payloads stay private to this execution path and are re-read out of the
//! destination before any receipt reports a member restored.
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
//!
//! Bounded execution: one batch is bounded on all four axes the contract names.
//! *Batches* by the member ceiling `MAX_RESTORE_MEMBERS`; *bytes* by the
//! cumulative `MAX_RESTORE_BYTES` accounting that now covers the canonical
//! payload bytes an apply imports, not only its bookkeeping document; *duration*
//! by `MAX_RESTORE_DURATION_MS`, measured from the destination's preparation and,
//! on a resume, from the operation's own first durable write; and *work* by the
//! shape of the single composed transaction, whose indexed clause families are
//! exactly the batch's head counts, its two purge obligations and its resolved
//! members. No unbounded retry, fan-out or background loop exists, so the work a
//! single apply can perform is the work its bounded shape already names.
//!
//! Local attempt ownership: an apply is owned by a private, non-cloneable
//! [`RestoreAttemptGuard`] acquired before the first suspension that needs
//! exclusion and bound to the destination/adapter owner namespace, the admitted
//! operation identity and a fresh *local bookkeeping incarnation*. The
//! incarnation is local-only: it is not a new external operation, lease or epoch.
//! Local ownership and effect exposure are separate facts — the slot records both
//! the first redacted failure and the highest provider-write exposure ever
//! observed — so a dropped future releases only its own incarnation while an
//! effect that may already have been submitted stays an exact-reconciliation
//! obligation. Releasing the guard is never provider cancellation and never
//! durable settlement.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

use eliot_store_api::{
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, BACKUP_IO_RESTORE_SCHEMA_V1,
    BackupOperationReconciliation, BlobResidencyDomain, CanonicalRestoreBatch, IsolatedDestination,
    IsolatedDestinationReceipt, IsolatedRestorePort, IsolationEvidence, MAX_RESTORE_MEMBERS,
    OperationId, OperationIdentity, OrderingHeadExpectation, ReconciliationOutcome, RecoveryRecord,
    RequestMeta, RestoreValidationReceipt, RetainedArchiveMember, RevisionHeadExpectation,
    SnapshotCompleteness, SnapshotMember, SnapshotMemberType, SnapshotSourceIdentity, StateFence,
    StoreBackupRequest, StoreError, StoreMutationDisposition, canonical_json_bytes,
    reconcile_same_operation, sha256_hex,
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

/// Ceiling on distinct owner-scoped attempt slots the shared projection may
/// track at once.
///
/// The in-process attempt map is keyed by admitted-but-caller-supplied operation
/// ids inside the destination/adapter owner namespace and is process-lifetime,
/// so a caller that keeps failing with fresh ids is refused rather than allowed
/// to grow memory without limit. It reuses the batch ceiling: one restore batch
/// already bounds the member set of a single operation, so the projection never
/// needs to track more live operation identities than that bound. Re-attempting
/// a known identity reuses its slot and never grows the map, and the ceiling is
/// not raised to accommodate a leaked incarnation.
const MAX_RESTORE_TRACKED_ATTEMPTS: usize = MAX_RESTORE_BATCH_MEMBERS;

/// Closed per-member disposition of one canonical restore batch.
///
/// A purge obligation is observed at archive-member-scope granularity, so it
/// opens or closes the whole member set; everything after that is decided per
/// member. One member's payload may resolve while its neighbour's does not, a
/// reference edge is never a row the import can write, and a member the
/// destination does not serve back is unresolved while its neighbours are
/// restored. Every member keeps its own identity and its own disposition, and a
/// split the contract cannot observe is never manufactured: the exact
/// per-member identities and counts are preserved either way.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MemberDisposition {
    /// Bound into the isolated destination under its fresh identity, with the
    /// canonical import read back out of the destination.
    Restored,
    /// Suppressed by the current purge ledger; never made servable.
    Suppressed,
    /// A reference edge: it names a canonical object rather than carrying one,
    /// so the record import has no row of its own to write and mints none. It
    /// stays in the denominator under its own identity, and its closure is
    /// proved by [`validate_reference_closure_against`].
    Rejected,
    /// No durable outcome: the member keeps its original identity and the
    /// missing denominator stays visible.
    Unresolved,
}

/// Closed per-member durable record of one restored archive member.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreMemberRecord {
    /// Deterministic logical identity of this member inside the destination.
    /// It binds only the admitted archive member digest and the member's own
    /// domain-qualified canonical logical identity, so a retry, a resume or a
    /// later readback reuses the *original* member identity instead of minting
    /// a new one.
    member_ref: String,
    /// Zero-based position of the member inside the admitted member list.
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
    /// Destination record address the canonical import wrote, present only for a
    /// member whose payload was actually resolved and imported.
    imported_record_id: Option<String>,
    /// Class token of the imported record, present exactly with
    /// [`Self::imported_record_id`].
    imported_class: Option<String>,
    /// Content digest this operation bound for this member's canonical import:
    /// the digest of the resolved payload validated against the archive owner's
    /// attested value. It is present exactly with [`Self::imported_record_id`],
    /// and the post-commit readback must reproduce it from the destination's own
    /// canonical read path before the member is reported `Restored`. A member
    /// without a `Restored` disposition never carries one, so it cannot claim an
    /// import it has no expectation for.
    imported_digest: Option<String>,
}

/// The canonical class one resolved archive member restores into.
///
/// Closed set, adapter-owned: each token names one physical class table through
/// the single owner in [`crate::schema`], and a token outside this set has no
/// destination, so a caller-selected class cannot exist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RestoreRecordClass {
    /// A durable write receipt of the captured commit.
    WriteReceipt,
    /// A revision head of the captured scope state.
    RevisionHead,
    /// An ordering head of the captured conflict-serialization scope.
    OrderingHead,
    /// A canonical semantic event.
    CanonicalEvent,
    /// A materialized projection publication.
    ProjectionRecord,
    /// A typed relation edge.
    RelationRecord,
    /// An outbox intent.
    OutboxEvent,
}

impl RestoreRecordClass {
    /// Every admitted class, in canonical order.
    const ALL: &'static [Self] = &[
        Self::WriteReceipt,
        Self::RevisionHead,
        Self::OrderingHead,
        Self::CanonicalEvent,
        Self::ProjectionRecord,
        Self::RelationRecord,
        Self::OutboxEvent,
    ];

    /// Parses one closed class token.
    fn parse(token: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|class| class.token() == token)
    }

    /// The durable token of this class.
    const fn token(self) -> &'static str {
        match self {
            Self::WriteReceipt => "write-receipt",
            Self::RevisionHead => "revision-head",
            Self::OrderingHead => "ordering-head",
            Self::CanonicalEvent => "canonical-event",
            Self::ProjectionRecord => "projection-record",
            Self::RelationRecord => "relation-record",
            Self::OutboxEvent => "outbox-event",
        }
    }

    /// The physical class table, named only by the single owner in
    /// [`crate::schema`].
    const fn table(self) -> &'static str {
        match self {
            Self::WriteReceipt => crate::schema::table::WRITE_RECEIPT,
            Self::RevisionHead => crate::schema::table::REVISION_HEAD,
            Self::OrderingHead => crate::schema::table::ORDERING_HEAD,
            Self::CanonicalEvent => crate::schema::table::CANONICAL_EVENT,
            Self::ProjectionRecord => crate::schema::table::PROJECTION_RECORD,
            Self::RelationRecord => crate::schema::table::RELATION_RECORD,
            Self::OutboxEvent => crate::schema::table::OUTBOX_EVENT,
        }
    }
}

/// One archive/artifact owner carrier row for a single canonical member.
///
/// The batch's [`SnapshotMember`] supplies identities, digests and residency
/// metadata only; it is not a payload source. These rows are the owner-side
/// carrier the resolution step reads back, and every field named here is
/// compared against the batch's own member before the payload is used. This port
/// publishes the row under the admitted operation, and the operation identity
/// travels inside the document, so a row that merely exists is never this
/// operation's evidence: its content is compared with the operation claiming it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveMemberCarrier {
    /// Admitted restore operation this carrier row was published under; a
    /// resolution under any other operation never reads this row.
    operation_id: String,
    /// Store id of the source snapshot this payload was captured from.
    source_store_id: String,
    /// Installation id of the source snapshot this payload was captured from.
    source_installation_id: String,
    /// Schema generation of the source snapshot.
    source_schema_generation: String,
    /// Archive commitment the payload belongs to.
    archive_member_digest: String,
    /// Member identity the payload answers for.
    member_id: String,
    /// Member type the payload answers for.
    member_type: SnapshotMemberType,
    /// Residency domain the payload was captured under.
    residency_domain: String,
    /// Content digest of the archive member this payload answers for.
    ///
    /// This is the *archive* commitment the batch member names, not a checksum of
    /// the payload: the capture contract derives a member's `content_digest` from
    /// the observed source row, so it binds carrier to member and never replaces
    /// the payload's own proof.
    content_digest: String,
    /// Owner-recorded digest of the resolved canonical payload bytes.
    ///
    /// This is the value the archive/artifact owner attested for the bytes it
    /// published. Resolution validates it against the payload it actually holds,
    /// so a carrier that claims one digest and carries other bytes is refused
    /// rather than accepted because its claim looked plausible.
    payload_digest: String,
    /// Actual byte length of the resolved canonical payload.
    byte_count: u64,
    /// Closed class this payload restores into.
    class: RestoreRecordClass,
    /// Destination record address derived from the member's own logical
    /// identity, so the same member always lands at the same address.
    record_id: String,
    /// The canonical logical payload itself.
    payload: serde_json::Value,
}

impl ArchiveMemberCarrier {
    /// Validates the carrier's own shape.
    fn validate(&self) -> Result<(), StoreError> {
        reject_blank_text(&self.operation_id, "restore.carrier_operation_id")?;
        reject_blank_text(&self.source_store_id, "restore.carrier_source_store_id")?;
        reject_blank_text(
            &self.source_installation_id,
            "restore.carrier_source_installation_id",
        )?;
        reject_blank_text(
            &self.source_schema_generation,
            "restore.carrier_source_schema_generation",
        )?;
        reject_blank_text(
            &self.archive_member_digest,
            "restore.carrier_archive_member_digest",
        )?;
        reject_blank_text(&self.member_id, "restore.carrier_member_id")?;
        reject_blank_text(&self.residency_domain, "restore.carrier_residency_domain")?;
        reject_blank_text(&self.content_digest, "restore.carrier_content_digest")?;
        reject_blank_text(&self.payload_digest, "restore.carrier_payload_digest")?;
        reject_blank_text(&self.record_id, "restore.carrier_record_id")?;
        if self.byte_count == 0 {
            return Err(StoreError::InvalidField {
                field: "restore.carrier_byte_count",
                reason: "resolved payload must carry a non-zero byte length",
            });
        }
        Ok(())
    }
}

/// One resolved canonical member ready to be imported into the destination.
///
/// Private to the adapter execution path: the resolved bytes are consumed by the
/// fixed apply transaction and then re-read through the destination's own
/// canonical read path. Nothing here is caller-visible, and a structural batch
/// validation cannot produce one.
struct ResolvedArchiveMember {
    /// Index of this member inside the admitted member list.
    member_index: u64,
    /// The batch member this payload answers for.
    member: SnapshotMember,
    /// Destination class the payload restores into.
    class: RestoreRecordClass,
    /// Destination record address derived from the member's own identity.
    record_id: String,
    /// The canonical logical payload bytes.
    payload: serde_json::Value,
    /// Digest of exactly those payload bytes, validated against the archive
    /// owner's own attested value at resolution. It is the content the
    /// post-commit readback must reproduce before the member may be reported
    /// `Restored`.
    payload_digest: String,
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
    /// Real store identity of the admitted process that performed the canonical
    /// import, read back from this adapter's own admitted configuration.
    ///
    /// A document whose label says `ISOLATED` does not select an isolated
    /// provider, so the receipt binds the actual destination process it was
    /// written by. A receipt whose bound store differs from the process
    /// re-deriving it is a record for another destination, never evidence for
    /// this one.
    destination_store_id: String,
    /// Real installation identity of the same admitted process.
    destination_installation_id: String,
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
            StoreError::MissingReceiptEnvelope | StoreError::UnknownOutcome { .. } => {
                "UNKNOWN_OUTCOME"
            }
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

/// Closed local bookkeeping state of one owner-scoped attempt slot.
///
/// Local ownership and effect exposure are separate facts and never collapse
/// into one another: a slot that was released cleanly can still owe an exact
/// provider reconciliation, and a slot that still holds a live owner may owe
/// nothing yet. The variants are ordered by increasing certainty, so merging two
/// observations is the maximum of the two and the highest observation is never
/// lowered by a later, less informed one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RestoreEffectState {
    /// No write was submitted by the invocation that observed this state.
    NoWriteSubmitted,
    /// A provider write may have been submitted: the request was handed to the
    /// transport and its result is not known here.
    WriteMayHaveBeenSubmitted,
    /// The provider answered the write. The answer is not yet an exact durable
    /// result, so the effect is still unproven.
    ResponseObserved,
    /// The exact durable result was read back and derived from the provider.
    /// This is the only state that discharges the reconciliation obligation.
    DurableResultVerified,
}

impl RestoreEffectState {
    /// Reports whether the slot's remote effect is still unproven.
    ///
    /// `NoWriteSubmitted` proves that nothing was sent and
    /// `DurableResultVerified` proves the exact outcome, so only the two
    /// intermediate states keep the slot reconciliation-required.
    const fn is_unproven(self) -> bool {
        matches!(
            self,
            Self::WriteMayHaveBeenSubmitted | Self::ResponseObserved
        )
    }
}

/// Effect exposure of one invocation, carried beside the uncertainty it
/// inherited from the slot it acquired.
///
/// The two halves are kept apart so a clean release can never read as proof of
/// non-commit: the inherited half is what an earlier incarnation may already
/// have submitted, and only the durable readback clears it.
#[derive(Clone, Copy, Debug)]
struct RestoreEffectExposure {
    /// Exposure inherited from the slot at acquisition time.
    inherited: RestoreEffectState,
    /// Exposure of this invocation alone.
    current: RestoreEffectState,
}

impl RestoreEffectExposure {
    /// Starts a fresh invocation against an already-tracked slot.
    const fn new(inherited: RestoreEffectState) -> Self {
        Self {
            inherited,
            current: RestoreEffectState::NoWriteSubmitted,
        }
    }

    /// The highest exposure ever observed for this slot.
    fn state(self) -> RestoreEffectState {
        self.inherited.max(self.current)
    }

    /// Reports whether the slot still owes an exact provider reconciliation.
    fn requires_reconciliation(self) -> bool {
        self.state().is_unproven()
    }

    /// Marks the instant before the first effectful transport poll.
    fn note_write_may_be_submitted(&mut self) {
        self.current = self
            .current
            .max(RestoreEffectState::WriteMayHaveBeenSubmitted);
    }

    /// Marks that the provider answered the write.
    fn note_response_observed(&mut self) {
        self.current = self.current.max(RestoreEffectState::ResponseObserved);
    }

    /// Marks that the exact durable result was verified.
    fn note_durable_result_verified(&mut self) {
        self.current = RestoreEffectState::DurableResultVerified;
    }
}

/// One in-process attempt slot of one destination/adapter owner's admitted
/// operation identity.
///
/// It exists only to serialize concurrent same-operation attempts inside this
/// process and to carry two independent facts forward across bounded,
/// cancelled, retried and dropped attempts: the *first* redacted failure and the
/// *highest* effect exposure. It is never a receipt and never an outcome. A slot
/// left behind by a released attempt is bounded evidence, not a lock: it never
/// blocks a retry from reaching the provider's own durable reconciliation
/// readback, which is the only authority on whether the earlier attempt
/// committed.
#[derive(Clone, Debug)]
struct RestoreAttempt {
    /// Closed phase label this slot was admitted for.
    phase: String,
    /// The local bookkeeping incarnation that owns the slot right now.
    incarnation: u64,
    /// True only while the owning incarnation is still live in this process.
    running: bool,
    /// Highest effect exposure ever observed for this slot; never lowered.
    effect_state: RestoreEffectState,
    /// First redacted failure observed for this slot; never overwritten,
    /// independently of the current effect certainty.
    first_failure: Option<RestoreFailureRecord>,
}

/// The bounded local bookkeeping facts of one attempt slot, as observed by a
/// reader that does not own it.
#[derive(Clone, Debug)]
struct RestoreAttemptState {
    /// First redacted failure observed for the slot.
    first_failure: Option<RestoreFailureRecord>,
    /// Highest effect exposure ever observed for the slot.
    effect_state: RestoreEffectState,
}

impl RestoreAttemptState {
    /// Reports whether the slot still owes an exact provider reconciliation.
    const fn requires_reconciliation(&self) -> bool {
        self.effect_state.is_unproven()
    }

    /// Reconstructs the first observed failure, if one was recorded.
    fn original_failure(&self) -> Option<StoreError> {
        self.first_failure
            .as_ref()
            .map(RestoreFailureRecord::restore)
    }
}

/// In-process restore projection: durable-receipt cache, owner-scoped attempt
/// slots, and original-failure preservation.
///
/// This is **not** a source of truth. A receipt only enters [`Self::entries`]
/// after the provider confirmed it by exact durable readback, and restore
/// record rows are create-only, so a confirmed receipt is immutable: the cache
/// may only rescue availability when the provider is temporarily unreachable,
/// and it never decides whether an operation committed. Every verdict the port
/// returns is derived from the provider. A retained attempt slot is likewise
/// not a gate: it refuses only a genuinely concurrent attempt, it is bounded by
/// [`MAX_RESTORE_TRACKED_ATTEMPTS`], and a retry always reaches the provider's
/// durable reconciliation readback first.
#[derive(Clone, Debug, Default)]
pub struct RestoreLedger {
    entries: HashMap<String, StoredRestoreEntry>,
    attempts: HashMap<String, RestoreAttempt>,
    /// Next local bookkeeping incarnation to hand out. Monotonic and
    /// process-local: it identifies one attempt's ownership of one slot and is
    /// never an external operation, lease or epoch.
    next_incarnation: u64,
}

impl RestoreLedger {
    /// Builds an empty per-instance ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            attempts: HashMap::new(),
            next_incarnation: 0,
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

/// Derives the owner-scoped key of one local restore-attempt slot.
///
/// Bare operation text is not a key. Two destination owners — or two adapters of
/// the same installation — may legitimately spell the same operation id, and the
/// cleanup of one owner's attempt must never release the other's. The key
/// therefore binds the adapter owner namespace (active database and
/// installation), the destination owner and the admitted operation identity; the
/// request commitment of that identity is bound durably by the create-only
/// record row, so a same-identity retry still reuses one slot here.
fn attempt_slot_key(
    active_store: &str,
    active_installation: &str,
    destination: &IsolatedDestination,
    operation: &OperationIdentity,
) -> String {
    let shape = (
        "restore-attempt-v1",
        active_store,
        active_installation,
        destination.destination_id.as_str(),
        operation.operation_id.as_str(),
    );
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(256);
        fallback.extend_from_slice(b"restore-attempt-v1");
        fallback.extend_from_slice(active_store.as_bytes());
        fallback.extend_from_slice(active_installation.as_bytes());
        fallback.extend_from_slice(destination.destination_id.as_bytes());
        fallback.extend_from_slice(operation.operation_id.as_str().as_bytes());
        fallback
    });
    sha256_hex(&bytes)
}

/// Private, non-cloneable owner of one local restore-attempt incarnation.
///
/// The guard is acquired before the first suspension that requires exclusion and
/// is bound to three things: the destination/adapter owner namespace, the
/// admitted logical operation identity, and a fresh *local bookkeeping
/// incarnation* of the slot. The incarnation only names this process's ownership
/// of one slot — it is not a new external operation, lease or epoch, and it
/// grants no authority over the destination.
///
/// Ownership and effect exposure are tracked apart. The guard carries what *this
/// invocation* may already have submitted, and the slot keeps the highest
/// exposure ever observed, so no release — not even an early return, an error
/// path, or a dropped pending future — can clear an effect that may already have
/// reached the provider.
struct RestoreAttemptGuard {
    /// Owner-scoped slot key, derived once so release never formats anything.
    key: String,
    /// The exact incarnation this guard owns.
    incarnation: u64,
    /// Operation identity this incarnation was admitted for; used only to type a
    /// conservative bookkeeping failure.
    operation_id: String,
    /// Effect exposure of this invocation beside the slot's inherited
    /// uncertainty.
    exposure: RestoreEffectExposure,
    /// False once explicit completion disarmed the destructor.
    armed: bool,
}

impl RestoreAttemptGuard {
    /// Acquires local ownership of one owner-scoped attempt slot.
    ///
    /// The projection lock is taken only for the duration of this map update: it
    /// is never held across a provider await, so a restore can never deadlock
    /// against its own readback. A *concurrent* second in-process attempt of the
    /// same owner-scoped identity while one is still live is refused with
    /// retryable unavailability.
    ///
    /// A retained first failure is deliberately **not** a gate. Refusing here
    /// would make a failed apply permanently un-retryable, so the retry instead
    /// falls through to the provider's durable reconciliation readback: that
    /// readback, not a local marker, is the only thing that can honestly say
    /// whether the earlier attempt committed. What the retained slot *does* carry
    /// forward is the effect exposure, which keeps the fresh-write branch closed
    /// until the exact durable result resolves it.
    ///
    /// The map is bounded by [`MAX_RESTORE_TRACKED_ATTEMPTS`]; a fresh slot
    /// arriving at the ceiling is refused instead of growing the map, and
    /// unreadable bookkeeping is a typed conservative failure rather than a
    /// clean absence.
    fn acquire(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
    ) -> Result<Self, StoreError> {
        let (active_store, active_installation) = active_store_identity(config);
        let key = attempt_slot_key(
            &active_store,
            &active_installation,
            &batch.destination,
            &batch.operation,
        );
        let operation_id = batch.operation.operation_id.as_str().to_owned();
        let mut ledger = shared_restore_ledger()
            .lock()
            .map_err(|_| unknown_outcome(&operation_id))?;
        if ledger
            .attempts
            .get(&key)
            .is_some_and(|attempt| attempt.running)
        {
            return Err(StoreError::Unavailable);
        }
        // A retry of a known identity reuses its own slot: the retained first
        // failure and the retained effect exposure survive the new attempt, and
        // the map does not grow. Only a slot that is not tracked yet competes for
        // the bounded capacity.
        let retained = ledger
            .attempts
            .get(&key)
            .map(|attempt| (attempt.first_failure.clone(), attempt.effect_state));
        if retained.is_none() && ledger.attempts.len() >= MAX_RESTORE_TRACKED_ATTEMPTS {
            return Err(StoreError::PayloadTooLarge);
        }
        // A fresh incarnation is never reused: an exhausted counter admits no new
        // attempt rather than letting a delayed finalizer match a later owner.
        let incarnation = ledger
            .next_incarnation
            .checked_add(1)
            .ok_or(StoreError::Unavailable)?;
        ledger.next_incarnation = incarnation;
        let (first_failure, effect_state) =
            retained.unwrap_or((None, RestoreEffectState::NoWriteSubmitted));
        let exposure = RestoreEffectExposure::new(effect_state);
        ledger.attempts.insert(
            key.clone(),
            RestoreAttempt {
                phase: RESTORE_PHASE_APPLIED.to_owned(),
                incarnation,
                running: true,
                effect_state,
                first_failure,
            },
        );
        Ok(Self {
            key,
            incarnation,
            operation_id,
            exposure,
            armed: true,
        })
    }

    /// Records the outcome of this incarnation and disarms the destructor.
    ///
    /// Consuming, so an incarnation can be completed exactly once and a
    /// completed guard is never finished again by `Drop`. The recorded outcome
    /// preserves the first observed failure and merges this incarnation's effect
    /// exposure into the slot. The slot is evicted only when nothing is left to
    /// reconcile; an uncertain effect keeps its slot and its recovery
    /// obligation.
    fn complete(mut self, outcome: Option<&StoreError>) -> Result<(), StoreError> {
        // Disarm first: a bookkeeping failure below must not be followed by a
        // second release attempt from the destructor.
        self.armed = false;
        if self.release(outcome).is_err() {
            return Err(unknown_outcome(&self.operation_id));
        }
        Ok(())
    }

    /// Releases this incarnation's local ownership into the slot.
    ///
    /// Returns a typed conservative failure when the bookkeeping is unreadable,
    /// and leaves the map untouched in that case: the slot, its running flag and
    /// its recovery obligation all survive, so no later reader can mistake poison
    /// for a completed cleanup. A guard whose incarnation no longer owns the
    /// slot — because a replacement was acquired after this one was displaced —
    /// releases nothing at all.
    fn release(&mut self, outcome: Option<&StoreError>) -> Result<(), StoreError> {
        let mut ledger = shared_restore_ledger()
            .lock()
            .map_err(|_| unknown_outcome(&self.operation_id))?;
        if ledger
            .attempts
            .get(&self.key)
            .is_none_or(|attempt| attempt.incarnation != self.incarnation)
        {
            return Ok(());
        }
        let merged = self
            .exposure
            .state()
            .max(ledger.attempts[&self.key].effect_state);
        if outcome.is_none() && !merged.is_unproven() {
            // Nothing is owed any more: the exact durable result is known, so the
            // bounded evidence leaves the map instead of accumulating in it.
            ledger.attempts.remove(&self.key);
            return Ok(());
        }
        let Some(attempt) = ledger.attempts.get_mut(&self.key) else {
            return Ok(());
        };
        attempt.running = false;
        attempt.effect_state = merged;
        if let Some(error) = outcome.filter(|_| attempt.first_failure.is_none()) {
            attempt.first_failure = Some(RestoreFailureRecord {
                phase: attempt.phase.clone(),
                classification: RestoreFailureRecord::classify(error).to_owned(),
                observed_at_unix_ms: current_unix_ms(),
            });
        }
        Ok(())
    }
}

impl Drop for RestoreAttemptGuard {
    /// Releases only this incarnation's local ownership.
    ///
    /// Bounded and synchronous by construction: one map update under the
    /// projection lock, never held across a provider await, with no RPC, no
    /// detached task, no async destructor, no recursive logging and no payload
    /// formatting. Dropping a pending apply future is **not** provider
    /// cancellation and **not** durable settlement: it releases the local
    /// running owner and merges this incarnation's exposure into the slot, so an
    /// effect that may already have been submitted stays uncertain and keeps its
    /// exact-reconciliation obligation. Unreadable bookkeeping keeps the slot
    /// untouched rather than reporting a cleanup that never happened.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // `Drop` has no channel to report a bookkeeping failure on; the retained
        // slot and the typed unknown outcome every later acquire returns are the
        // honest, bounded consequence.
        let _ = self.release(None);
    }
}

/// Reads the bounded local bookkeeping facts of one owner-scoped attempt slot.
///
/// An unreadable map is a typed conservative failure, never an absent attempt:
/// reporting "no original failure" from an unreadable map would turn unknown
/// bookkeeping into a clean answer.
fn restore_attempt_state(
    batch: &CanonicalRestoreBatch,
    config: &SurrealAdapterConfig,
) -> Result<Option<RestoreAttemptState>, StoreError> {
    let (active_store, active_installation) = active_store_identity(config);
    let key = attempt_slot_key(
        &active_store,
        &active_installation,
        &batch.destination,
        &batch.operation,
    );
    let ledger = shared_restore_ledger()
        .lock()
        .map_err(|_| unknown_outcome(batch.operation.operation_id.as_str()))?;
    Ok(ledger
        .attempts
        .get(&key)
        .map(|attempt| RestoreAttemptState {
            first_failure: attempt.first_failure.clone(),
            effect_state: attempt.effect_state,
        }))
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

/// Validates the structural canonical reference/ordering closure of a batch.
///
/// Structural only: it proves the batch's own head sets, its member ceiling and
/// the reference-digest coupling, and that a reference edge is not a self-edge.
/// It deliberately does **not** decide whether a reference *resolves*. A
/// `BTreeSet<content_digest>` membership test over the batch's own declarations
/// drops residency and type identity, so equal bytes in another obligation
/// domain would satisfy it and a member that never resolved would pass it.
/// Resolution is a separate typed step over the owner-resolved canonical
/// payloads — see [`validate_reference_closure_against`].
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
    // The declared count is only a restore obligation when the canonical records
    // behind it are named, so the two must agree before any closure is claimed.
    if batch.members.len() as u64 != batch.member_count {
        return Err(StoreError::InvalidField {
            field: "restore.member_count",
            reason: "must equal the admitted canonical member list",
        });
    }
    // The reference coupling is re-proved here; whether the edge *resolves* is
    // decided by the typed step over the resolved canonical payloads, never over
    // this batch's own declarations.
    for member in &batch.members {
        if member.member_type != SnapshotMemberType::Reference {
            continue;
        }
        let Some(reference) = member.reference_digest.as_deref() else {
            return Err(StoreError::InvalidField {
                field: "restore.reference_digest",
                reason: "reference member requires a reference digest",
            });
        };
        if reference == member.content_digest {
            return Err(StoreError::IdentityConflict);
        }
    }
    Ok(())
}

/// Resolves every reference edge this batch carries, against the member set that
/// is actually *present*.
///
/// `dispositions_by_member` maps each member's own deterministic destination
/// identity — [`member_reference`] over the admitted archive member digest — to
/// the disposition observed for *that* member at this exact point: the planned
/// set before an apply commit, the set re-read from the destination at receipt
/// time. Dispositions are therefore looked up by identity, never by position, so
/// no member's edge can be examined against another member's disposition and a
/// replay carrying a changed member set cannot borrow a disposition it was never
/// recorded with. A member with no entry is not a target and not an exempt edge.
///
/// This is the typed half of the closure, and it is deliberately not a
/// digest-membership test over the batch's own declarations. A reference edge
/// names its target only when some member of this batch
///
/// 1. carries the referenced content digest **under the same residency domain**
///    as the referring member. Equal bytes under a different obligation domain
///    are a different logical object (I5.13), so they are not the referenced
///    object; and
/// 2. is itself importable — a `Record` or `Blob` member rather than another
///    reference edge — so a reference chain is refused instead of followed.
///
/// **Every** reference member of the batch is examined, whatever its
/// disposition. An edge whose `reference_digest` names no member of the batch is
/// dangling in the archive itself, and no disposition of the referring member
/// can make it closed: a suppressed, unresolved or rejected edge all fail the
/// naming test, and a batch can never report a closed graph for a reference that
/// resolves to nothing. Only an edge the batch additionally claims to have
/// *closed* — a `Rejected` edge, which is what an importable batch records for a
/// reference — must additionally land on a member the destination actually
/// serves.
///
/// A member that is not present is not a target, so a batch cannot close a graph
/// it never imported. A cross-batch target, an object an authorized earlier
/// batch of the same restore plan already imported, is **not** resolvable here:
/// the #950 batch contract carries no record address for a member outside the
/// batch and this port never mints one. Such an edge fails closed rather than
/// being assumed present, and a reference member never gains a canonical row of
/// its own.
fn validate_reference_closure_against(
    batch: &CanonicalRestoreBatch,
    dispositions_by_member: &BTreeMap<String, MemberDisposition>,
) -> Result<(), StoreError> {
    if dispositions_by_member.len() != batch.members.len() {
        return Err(StoreError::InvalidReceipt);
    }
    for member in &batch.members {
        if member.member_type != SnapshotMemberType::Reference {
            continue;
        }
        let member_ref = member_reference(&batch.archive_member_digest, &member.logical_identity());
        let disposition = dispositions_by_member
            .get(&member_ref)
            .ok_or(StoreError::InvalidReceipt)?;
        let reference = member
            .reference_digest
            .as_deref()
            .ok_or(StoreError::InvalidField {
                field: "restore.reference_digest",
                reason: "reference member requires a reference digest",
            })?;
        // The target must be named by this batch under the referring member's own
        // obligation domain. This holds for every disposition: an edge naming
        // nothing in the batch is refused rather than excused.
        let named_target = batch.members.iter().any(|target| {
            target.content_digest == reference && target.residency.domain == member.residency.domain
        });
        if !named_target {
            return Err(StoreError::IdentityConflict);
        }
        // A `Rejected` edge is the batch's own claim that it closed the graph, so
        // the named member must additionally be served by the destination.
        if *disposition == MemberDisposition::Rejected {
            let served = batch.members.iter().any(|target| {
                if target.content_digest != reference
                    || target.residency.domain != member.residency.domain
                {
                    return false;
                }
                let target_ref =
                    member_reference(&batch.archive_member_digest, &target.logical_identity());
                dispositions_by_member.get(&target_ref) == Some(&MemberDisposition::Restored)
            });
            if !served {
                return Err(StoreError::IdentityConflict);
            }
        }
    }
    Ok(())
}

/// Keys a planned per-member disposition set by each member's own destination
/// identity.
///
/// The planned set is derived by iterating the batch's own members, so each entry
/// is that member's disposition under its own [`member_reference`] key. The guard
/// then looks dispositions up by identity, which is the same key the durable
/// readback path binds by, so one member's disposition can never be read as
/// another's.
fn dispositions_by_member(
    batch: &CanonicalRestoreBatch,
    dispositions: &[MemberDisposition],
) -> BTreeMap<String, MemberDisposition> {
    batch
        .members
        .iter()
        .zip(dispositions)
        .map(|(member, disposition)| {
            (
                member_reference(&batch.archive_member_digest, &member.logical_identity()),
                *disposition,
            )
        })
        .collect()
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
/// The identity binds only the admitted archive member digest and the member's
/// own domain-qualified canonical logical identity, so a retry, a resume or a
/// later readback reuses the *original* member identity instead of minting a new
/// one.
fn member_reference(archive_member_digest: &str, member_identity: &str) -> String {
    let shape = ("restore-member-v1", archive_member_digest, member_identity);
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(128);
        fallback.extend_from_slice(b"restore-member-v1");
        fallback.extend_from_slice(archive_member_digest.as_bytes());
        fallback.extend_from_slice(member_identity.as_bytes());
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

/// Derives the archive-member carrier row key for one batch member.
///
/// The key binds the admitted archive member digest, the admitted restore
/// operation and the member's own domain-qualified logical identity, so the
/// carrier row a batch resolves is the one this operation published for exactly
/// that member under exactly that archive — and a row another operation
/// published for the same member is not found, let alone reused. A caller cannot
/// name another member's carrier row.
fn archive_member_key(
    batch: &CanonicalRestoreBatch,
    member: &eliot_store_api::SnapshotMember,
) -> String {
    registry_key(
        crate::client::RESTORE_KEY_ARCHIVE_MEMBER_PREFIX,
        &format!(
            "{}:{}:{}:{}",
            batch.archive_member_digest,
            batch.operation.operation_id,
            member.member_id,
            member.logical_identity()
        ),
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
    // The current-purge precondition is checked first: an obligation recorded
    // between preflight and commit must be re-evaluated, never reported as the
    // weaker conflict class it happens to share a transaction with.
    if errors
        .iter()
        .any(|error| crate::client::is_restore_purge_ledger_changed(error))
    {
        return StoreError::InvalidField {
            field: "restore.purge_policy_revision",
            reason: "current purge obligations changed before this restore committed",
        };
    }
    if errors
        .iter()
        .any(|error| crate::client::is_restore_revision_head_changed(error))
    {
        return StoreError::RevisionConflict;
    }
    if errors
        .iter()
        .any(|error| crate::client::is_restore_ordering_head_changed(error))
    {
        return StoreError::OrderingConflict;
    }
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
///
/// `exposure` is the local bookkeeping of the caller that owns an attempt
/// incarnation, if any. The "may have been submitted" mark is set on the last
/// synchronous line before the transport poll — after the closed registry and
/// statement have been resolved, so a refusal that never reaches the wire is not
/// reported as a possible commit.
async fn execute_restore_write(
    transport: &RpcTransport,
    operation: &'static str,
    statement: String,
    bindings: serde_json::Map<String, serde_json::Value>,
    exposure: Option<&mut RestoreEffectExposure>,
) -> Result<(), StoreError> {
    check_registry_capability()?;
    crate::client::validate_restore_operation(operation).map_err(AdapterError::into_store_error)?;
    // The closed registry is still consulted for every write: the apply
    // transaction is the pinned bookkeeping half with its bounded per-batch
    // preconditions and canonical imports rendered from the same templates, and
    // refusing here means a caller-selected statement can never be composed
    // around the admitted registry.
    let pinned = crate::client::fixed_restore_statement(operation)
        .map_err(AdapterError::into_store_error)?;
    if !statement.starts_with(pinned) {
        return Err(AdapterError::NamedOperationUnavailable {
            operation: crate::client::RESTORE_ERROR_OPERATION.to_owned(),
        }
        .into_store_error());
    }
    let mut response = match exposure {
        Some(exposure) => {
            exposure.note_write_may_be_submitted();
            let response = transport.query_write(operation, &statement, bindings).await;
            if response.is_ok() {
                exposure.note_response_observed();
            }
            response
        }
        None => transport.query_write(operation, &statement, bindings).await,
    }
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

/// One current purge obligation exactly as the destination's privacy owner
/// recorded it.
///
/// The decoded entry decides the disposition; the registry row's own durable
/// revision is the value the commit transaction re-reads and compares. The two
/// are independent facts — the entry's `purge_policy_revision` is policy
/// provenance, not the row revision — so both travel separately and neither is
/// ever substituted for the other.
struct PurgeObservation {
    /// Registry row key this obligation is read under.
    key: String,
    /// Decoded obligation, absent only on a positive absent-row observation.
    entry: Option<PurgeLedgerEntry>,
    /// Durable registry revision the row was read at; `0` when the row is
    /// absent, so "no obligation recorded" and "an obligation moved" stay
    /// distinguishable at the commit precondition.
    row_revision: u64,
}

/// Reads the current purge ledger for one batch scope: the member obligation
/// and the source-scope obligation, in one dispatch.
async fn read_purge_ledger(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    archive_member_digest: &str,
    source_installation_id: &str,
) -> Result<(PurgeObservation, PurgeObservation), StoreError> {
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
        purge_observation(purge_member_key(archive_member_digest), member_rows)?,
        purge_observation(purge_scope_key(source_installation_id), scope_rows)?,
    ))
}

/// Folds one purge-ledger row family into its observation.
///
/// A family that returns more than one row cannot be ordered, so it is refused
/// rather than resolved to whichever row happened to arrive first.
fn purge_observation(
    key: String,
    rows: Vec<RecoveryRecord>,
) -> Result<PurgeObservation, StoreError> {
    if rows.len() > 1 {
        return Err(StoreError::InvalidReceipt);
    }
    let Some(row) = rows.into_iter().next() else {
        return Ok(PurgeObservation {
            key,
            entry: None,
            row_revision: 0,
        });
    };
    let row_revision = row.revision;
    Ok(PurgeObservation {
        entry: decode_purge_entry(Some(row))?,
        row_revision,
        key,
    })
}

/// One carrier row this operation publishes, with the document it encodes.
struct PublishedCarrier {
    /// Admitted member the carrier answers for.
    member: SnapshotMember,
    /// Carrier document published under this operation's own key.
    carrier: ArchiveMemberCarrier,
    /// Durable registry row that encodes it.
    row: RecoveryRecord,
}

/// Publishes the archive-member carrier rows this operation resolves from.
///
/// The port may only import a member whose canonical logical payload it holds
/// durably under its own operation, so this is where the owner contract's
/// retained reference becomes the carrier row [`read_archive_member`] reads
/// back. The whole bounded set lands in one provider transaction, so resolution
/// sees every member this operation retained or none of them — never a
/// half-published batch that would report some members restored and leave the
/// rest silently unresolved.
///
/// The retained reference is mandatory for every member this port would import:
/// an importable member that carries none is refused here, typed, before any
/// write. Degrading it to an unresolved member instead would hand back a
/// well-formed `Partial` receipt for a batch that never carried the content it
/// claims to restore, which is the same silent-zero path as a batch whose
/// payloads simply went missing. A member the current purge ledger keeps out of
/// the destination is never published, because it is never imported either.
///
/// Publication is create-only. A duplicate is resolved by reading this
/// operation's own row back and comparing its content, so an exact replay of
/// the same operation continues while a row carrying different content under
/// this operation's key is an identity conflict.
///
/// The retained bytes are charged to the same bound as the commit, and charged
/// *before* they land: a batch that would exceed the destination's byte bound is
/// refused, never written first and refused afterwards.
async fn publish_archive_member_carriers(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    batch: &CanonicalRestoreBatch,
    state_fence: &StateFence,
    cumulative_bytes: u64,
    exposure: &mut RestoreEffectExposure,
) -> Result<Vec<PublishedCarrier>, StoreError> {
    let mut published: Vec<PublishedCarrier> = Vec::new();
    for member in &batch.members {
        // A reference edge names a canonical object; it is not one. Publishing a
        // payload for it would let the import mint a destination record for an
        // edge, so no carrier is published for it.
        if member.member_type == SnapshotMemberType::Reference {
            continue;
        }
        let Some(retained) = batch
            .retained_members
            .iter()
            .find(|retained| retained.member_id == member.member_id)
        else {
            return Err(StoreError::InvalidField {
                field: "restore.retained_members",
                reason: "admitted member carries no retained archive payload",
            });
        };
        let carrier = carrier_for(batch, member, retained)?;
        let (payload, value_digest) = encode_document(&carrier)?;
        published.push(PublishedCarrier {
            member: member.clone(),
            carrier,
            row: registry_row(
                &archive_member_key(batch, member),
                crate::client::RESTORE_SCHEMA_ARCHIVE_MEMBER,
                state_fence,
                1,
                payload,
                value_digest,
            ),
        });
    }
    if published.is_empty() {
        return Ok(published);
    }
    check_cumulative_bytes(cumulative_bytes, carrier_payload_bytes(&published)?)?;
    let bindings = carrier_bindings(&published)?;
    match execute_restore_write(
        transport,
        crate::client::RESTORE_OPERATION_CARRIER_PUBLISH,
        crate::client::restore_carrier_statement(published.len()),
        bindings,
        Some(&mut *exposure),
    )
    .await
    {
        Ok(()) => Ok(published),
        Err(StoreError::IdentityConflict) => {
            for entry in &published {
                // A row already exists under this operation's own key. It is a
                // replay only when it carries exactly what this operation
                // publishes; anything else is content this operation does not
                // own, and a row that is simply not there leaves the member
                // unresolved rather than restored.
                if let Some(existing) =
                    read_archive_member(transport, config, batch, &entry.member).await?
                    && existing != entry.carrier
                {
                    return Err(StoreError::IdentityConflict);
                }
            }
            Ok(published)
        }
        Err(error) => Err(error),
    }
}

/// Builds the carrier document one member's retained reference publishes.
///
/// Every identity field is taken from the admitted batch and the member it
/// belongs to — the operation, the source, the archive, the member identity and
/// type, the residency domain and the archive content digest — so no caller can
/// publish a carrier for anything but the member it travels beside. Only the
/// payload, the owner's attested digest, its declared length, the closed class
/// and the destination address come from the retained reference, and the class
/// must be one this port owns: a member naming a class with no destination is
/// refused rather than mapped onto a table.
fn carrier_for(
    batch: &CanonicalRestoreBatch,
    member: &SnapshotMember,
    retained: &RetainedArchiveMember,
) -> Result<ArchiveMemberCarrier, StoreError> {
    // The payload is bounded by the member's *own* declared residency length
    // before it is parsed at all, so an over-long reference is refused instead
    // of decoded, and the resolution step's length check has an independent
    // expected value to compare the resolved bytes against.
    if u64::try_from(retained.payload.len()).ok() != Some(member.residency.byte_count) {
        return Err(StoreError::InvalidField {
            field: "restore.retained_member_payload",
            reason: "retained payload length does not match the member's declared byte count",
        });
    }
    let class = RestoreRecordClass::parse(&retained.class).ok_or(StoreError::InvalidField {
        field: "restore.retained_member_class",
        reason: "retained payload names an unknown canonical class",
    })?;
    let payload: serde_json::Value = serde_json::from_str(&retained.payload)
        .map_err(|error| AdapterError::Serialization(error.to_string()).into_store_error())?;
    let carrier = ArchiveMemberCarrier {
        operation_id: batch.operation.operation_id.as_str().to_owned(),
        source_store_id: batch.source.store_id.clone(),
        source_installation_id: batch.source.installation_id.clone(),
        source_schema_generation: batch.source.schema.clone(),
        archive_member_digest: batch.archive_member_digest.clone(),
        member_id: member.member_id.clone(),
        member_type: member.member_type,
        residency_domain: residency_label(member.residency.domain).to_owned(),
        content_digest: member.content_digest.clone(),
        payload_digest: retained.payload_digest.clone(),
        byte_count: retained.byte_count,
        class,
        record_id: retained.record_id.clone(),
        payload,
    };
    carrier.validate()?;
    Ok(carrier)
}

/// Binds one published carrier set into the carrier publication transaction.
///
/// The registry table and, per carrier, its derived record id and its encoded
/// row are bound values; no row content and no identifier is interpolated into
/// statement text, so nothing a caller supplies becomes a table or a query.
fn carrier_bindings(
    published: &[PublishedCarrier],
) -> Result<serde_json::Map<String, serde_json::Value>, StoreError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "restore_table".to_owned(),
        serde_json::Value::String(crate::client::RESTORE_REGISTRY_TABLE.to_owned()),
    );
    for (index, entry) in published.iter().enumerate() {
        bindings.insert(
            format!("restore_carrier_row_id{index}"),
            serde_json::Value::String(registry_record_id(&entry.row.key)?),
        );
        bindings.insert(
            format!("restore_carrier_record{index}"),
            row_binding(&entry.row)?,
        );
    }
    Ok(bindings)
}

/// Reads one archive/artifact owner carrier row for one batch member.
///
/// The key is derived from the batch's archive member digest, its admitted
/// operation and the member's own logical identity, so a carrier row for a
/// different member, a different archive, a different operation or a different
/// residency domain is simply not found: nothing the caller supplies selects a
/// row, and this operation only ever reads the row it published itself.
async fn read_archive_member(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    batch: &CanonicalRestoreBatch,
    member: &eliot_store_api::SnapshotMember,
) -> Result<Option<ArchiveMemberCarrier>, StoreError> {
    let key = archive_member_key(batch, member);
    let Some(row) = read_registry_row(
        transport,
        config,
        crate::client::RESTORE_OPERATION_ARCHIVE_MEMBERS,
        &key,
    )
    .await?
    else {
        return Ok(None);
    };
    if row.schema != crate::client::RESTORE_SCHEMA_ARCHIVE_MEMBER {
        return Err(StoreError::InvalidReceipt);
    }
    let carrier: ArchiveMemberCarrier = decode_document(&row)?;
    carrier.validate()?;
    if !carrier_answers_for(&carrier, batch, member) {
        return Err(StoreError::IdentityConflict);
    }
    Ok(Some(carrier))
}

/// Reports whether one carrier row actually answers for one batch member.
///
/// Nine independent facts must agree before the payload is used: the admitted
/// restore operation, the source store, the source installation, the source
/// schema generation, the archive commitment, the member identity, the member
/// type, the residency domain, the archive content digest and the declared byte
/// count. The byte count is compared against the *batch member's own* declared
/// residency length — an independent expected value, not a second copy of the
/// carrier's — and the payload's own digest is then validated separately in
/// [`resolve_archive_members`]. Any divergence is an identity conflict, never a
/// payload that is silently accepted because it looked plausible.
fn carrier_answers_for(
    carrier: &ArchiveMemberCarrier,
    batch: &CanonicalRestoreBatch,
    member: &eliot_store_api::SnapshotMember,
) -> bool {
    carrier.operation_id == batch.operation.operation_id.as_str()
        && carrier.source_store_id == batch.source.store_id
        && carrier.source_installation_id == batch.source.installation_id
        && carrier.source_schema_generation == batch.source.schema
        && carrier.archive_member_digest == batch.archive_member_digest
        && carrier.member_id == member.member_id
        && carrier.member_type == member.member_type
        && carrier.residency_domain == residency_label(member.residency.domain)
        && carrier.content_digest == member.content_digest
        && carrier.byte_count == member.residency.byte_count
}

/// Resolves every member of one batch into its canonical logical payload.
///
/// A member whose carrier row is absent resolves to `None`: it is an unresolved
/// member, not a member with empty content. A carrier whose own attested digest
/// or declared length disagrees with the payload it actually holds is refused
/// outright — the recorded value is validated, never replaced by a fresh
/// checksum over whatever happened to arrive. The resolved payloads are private
/// to this execution path and never become part of a caller-visible receipt.
async fn resolve_archive_members(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    batch: &CanonicalRestoreBatch,
) -> Result<Vec<Option<ResolvedArchiveMember>>, StoreError> {
    let mut resolved = Vec::with_capacity(batch.members.len());
    for (index, member) in batch.members.iter().enumerate() {
        // A reference edge names a canonical object; it is not one. Resolving it
        // to a payload of its own would let the import mint a destination record
        // for an edge, so no carrier row is read for it.
        if member.member_type == SnapshotMemberType::Reference {
            resolved.push(None);
            continue;
        }
        let Some(carrier) = read_archive_member(transport, config, batch, member).await? else {
            resolved.push(None);
            continue;
        };
        // The owner's own attested digest is checked against the bytes it
        // published, and the actual byte length against both the owner's record
        // and the batch member's own declaration. A carrier that fails either is
        // not a payload source.
        let payload_bytes = canonical_digest_bytes(&carrier.payload)?;
        let payload_digest = sha256_hex(&payload_bytes);
        if payload_bytes.is_empty() || payload_digest != carrier.payload_digest {
            return Err(StoreError::InvalidField {
                field: "restore.carrier_payload_digest",
                reason: "resolved payload does not match the owner-attested digest",
            });
        }
        if u64::try_from(payload_bytes.len()).ok() != Some(carrier.byte_count) {
            return Err(StoreError::InvalidField {
                field: "restore.carrier_byte_count",
                reason: "resolved payload length does not match the owner-recorded length",
            });
        }
        resolved.push(Some(ResolvedArchiveMember {
            member_index: u64::try_from(index).unwrap_or(u64::MAX),
            member: member.clone(),
            class: carrier.class,
            record_id: carrier.record_id,
            payload: carrier.payload,
            payload_digest,
        }));
    }
    Ok(resolved)
}

/// Reads one canonical row of the destination through its own read path.
///
/// The class table and the record id are bound parameters of one pinned read, so
/// nothing a caller supplies names a table. The result is the row's `body` — the
/// admitted logical document the canonical owner writes under it — or `None`
/// when the destination serves no such row. A `None` is an absent row, never a
/// row with empty content.
async fn read_canonical_body(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    class: RestoreRecordClass,
    record_id: &str,
) -> Result<Option<serde_json::Value>, StoreError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "restore_canonical_table".to_owned(),
        serde_json::Value::String(class.table().to_owned()),
    );
    bindings.insert(
        "restore_canonical_row_id".to_owned(),
        serde_json::Value::String(record_id.to_owned()),
    );
    let mut response = execute_restore_read(
        transport,
        config,
        crate::client::RESTORE_OPERATION_CANONICAL_READ,
        bindings,
    )
    .await?;
    let rows: Vec<serde_json::Value> = response.take(0).map_err(AdapterError::into_store_error)?;
    match rows.into_iter().next() {
        Some(row) if row.is_null() => Ok(None),
        Some(row) => Ok(Some(row)),
        None => Ok(None),
    }
}

/// The head field one canonical class publishes for compare-and-set purposes.
///
/// The destination's own head value is read through the record address the
/// canonical owner itself uses (`type::record(revision_head, revision_key)` and
/// `type::record(ordering_head, ordering_scope)`, per `schema::TX_UPSERT_REVISION`
/// and `schema::READ_REVISION_HEADS_BY_KEYS`), and the field is the one the owner
/// writes under `body` for that class. No caller chooses either the address or
/// the field.
const fn head_value_field(class: RestoreRecordClass) -> &'static str {
    match class {
        RestoreRecordClass::RevisionHead => "revision",
        _ => "sequence",
    }
}

/// Reads the destination's own head values for one batch's expected heads.
///
/// One bounded canonical read per head, in the batch's own order, so
/// `observed[index]` is the value the destination actually publishes for
/// `keys[index]` and `None` is a positive observation that it publishes no head
/// there. This is the *observed* half of the expected-state check: the batch's
/// heads are the input, these are the values they are compared against.
async fn read_destination_heads(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    class: RestoreRecordClass,
    keys: &[String],
) -> Result<Vec<Option<u64>>, StoreError> {
    let field = head_value_field(class);
    let mut observed = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(body) = read_canonical_body(transport, config, class, key).await? else {
            observed.push(None);
            continue;
        };
        // A head the destination DOES publish must carry its value; a present
        // record whose value field is missing or not a `u64` is a malformed
        // receipt, not an absent head, so it refuses instead of being reported
        // as `None`. `None` above is reserved for the one case it means: the
        // destination publishes no head at this key.
        observed.push(Some(
            body.get(field)
                .and_then(serde_json::Value::as_u64)
                .ok_or(StoreError::InvalidReceipt)?,
        ));
    }
    Ok(observed)
}

/// Compares the batch's expected head values with the destination's own.
///
/// The same rule the commit transaction applies, applied before the write so a
/// batch whose expectation has already moved is refused rather than submitted.
/// A head the destination publishes must carry exactly the revision or sequence
/// this operation was admitted against. A head it does not publish yet is the
/// create-from-floor case the canonical owner itself distinguishes
/// (`schema::TX_UPSERT_REVISION` compare-and-sets a present head,
/// `schema::TX_CREATE_REVISION` establishes an absent one), so absence is not a
/// contradiction here either — and this preflight must not be stricter than the
/// transaction guard it precedes. `mismatch` is the lane's typed conflict, so a
/// revision move never reads as an ordering move or the other way round.
fn check_observed_heads(
    expected: &[u64],
    observed: &[Option<u64>],
    mismatch: StoreError,
) -> Result<(), StoreError> {
    if expected.len() != observed.len() {
        return Err(StoreError::InvalidReceipt);
    }
    for (expected, observed) in expected.iter().zip(observed) {
        if !observed.is_none_or(|observed| observed == *expected) {
            return Err(mismatch);
        }
    }
    Ok(())
}

/// Re-reads one imported canonical record out of the destination and reports
/// whether it serves exactly the bytes this operation committed.
///
/// A `Restored` member is only `Restored` when the destination serves its row
/// back, in the closed class, at the address this operation recorded, **with the
/// content this operation bound into its own transaction**. The returned digest
/// is that readback: a member whose row is absent yields `None`, and so does a
/// row whose bytes digest to anything other than `expected_digest` — a row that
/// exists at the right address with the wrong content is not this member's
/// import. This is what separates a registered placement, a staged archive
/// handle and a completed canonical import — three different facts — and what
/// stops a metadata-only batch from reporting a complete import.
async fn read_imported_member(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    class: RestoreRecordClass,
    record_id: &str,
    expected_digest: &str,
) -> Result<Option<String>, StoreError> {
    let Some(body) = read_canonical_body(transport, config, class, record_id).await? else {
        return Ok(None);
    };
    let digest = sha256_hex(&canonical_digest_bytes(&body)?);
    Ok((digest == expected_digest).then_some(digest))
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
///
/// The two bookkeeping facts stay independent here. An older pre-effect refusal
/// may still be reported as the reason the operation first failed, but it never
/// stands in for the current effect certainty: while the owner-scoped slot still
/// owes an exact provider reconciliation, the cancellation answer is the typed
/// unknown outcome, and the first failure is preserved beside it rather than
/// overwritten by it.
fn check_cancellation(
    adapter: &SurrealStoreAdapter,
    batch: &CanonicalRestoreBatch,
) -> Result<(), StoreError> {
    let Some(execution) = adapter.execution_handle() else {
        return Ok(());
    };
    if !execution.is_cancelled(&batch.operation.operation_id) {
        return Ok(());
    }
    let state = restore_attempt_state(batch, &adapter.config)?;
    if state
        .as_ref()
        .is_some_and(RestoreAttemptState::requires_reconciliation)
    {
        return Err(unknown_outcome(batch.operation.operation_id.as_str()));
    }
    if let Some(original) = state.and_then(|state| state.original_failure()) {
        return Err(original);
    }
    Err(StoreError::Unavailable)
}

/// Verifies the expected-state identity: every expected head must carry the
/// request's state fence, so a batch cannot bind heads from another fence.
///
/// This is the *shape* half of the expected-state check. The *value* half — that
/// the destination's own revision/ordering heads actually carry the expected
/// revision and sequence — is made twice, and never by storing the expectation:
///
/// 1. before the write, by [`check_observed_heads`] over the values read back
///    from the destination through its own canonical read path; and
/// 2. inside the commit transaction itself, by
///    [`crate::client::restore_apply_statement`]'s indexed head guards, which
///    re-read each head and abort the whole commit on any divergence. The
///    preflight read narrows the failure; only the in-transaction guard is the
///    commit precondition, because a preflight observation can go stale before
///    the write lands.
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
///
/// The digest exists only to bind *this* batch's expectation into its durable
/// record, so a head that cannot be canonically encoded is a refusal rather than
/// a digest of empty bytes: a fallback would let two different head lists hash
/// to the same stored expectation. This stores the expectation; the destination's
/// actual head values are compared inside the commit transaction by
/// [`check_observed_heads`].
fn expected_head_digests(
    batch: &CanonicalRestoreBatch,
) -> Result<(Vec<String>, Vec<String>), StoreError> {
    fn digest<T: Serialize>(head: &T) -> Result<String, StoreError> {
        Ok(sha256_hex(&canonical_digest_bytes(head)?))
    }
    let revision_digests = batch
        .expected_revision_heads
        .iter()
        .map(digest::<RevisionHeadExpectation>)
        .collect::<Result<Vec<_>, _>>()?;
    let ordering_digests = batch
        .expected_ordering_heads
        .iter()
        .map(digest::<OrderingHeadExpectation>)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((revision_digests, ordering_digests))
}

/// Binds a durable record's per-member rows to this batch's members by each
/// member's own deterministic destination identity.
///
/// The binding key is [`member_reference`] — the admitted archive member digest
/// plus the member's domain-qualified logical identity — so a disposition
/// recorded for one member can never be read as the disposition of a different
/// one. A same-identity replay that carries a *different* member set names
/// members this operation never recorded, which is an identity conflict: changed
/// input conflicts, and only a byte-identical member set reconciles to the
/// original receipt.
///
/// Identity is what makes the downstream per-member lookup sound. A positional or
/// length-only coupling would let a replay place a reference edge at an index
/// whose durable disposition is `Restored`, where the closure guard skips it, and
/// report a closed graph that was never closed. Here both sides must be distinct,
/// fully covered and equal, so each batch member has exactly one durable row and
/// no row is left over.
fn recorded_members_by_identity<'record>(
    batch: &CanonicalRestoreBatch,
    document: &'record RestoreRecordDocument,
) -> Result<Vec<&'record RestoreMemberRecord>, StoreError> {
    let durable: BTreeSet<&str> = document
        .members
        .iter()
        .map(|row| row.member_ref.as_str())
        .collect();
    // A record names one member identity once; a repeat cannot be attributed to
    // a single member, so it is not a record this batch can be read back from.
    if durable.len() != document.members.len() {
        return Err(StoreError::InvalidReceipt);
    }
    let claimed: BTreeSet<String> = batch
        .members
        .iter()
        .map(|member| member_reference(&batch.archive_member_digest, &member.logical_identity()))
        .collect();
    if claimed.len() != batch.members.len() {
        return Err(StoreError::IdentityConflict);
    }
    if !claimed
        .iter()
        .all(|member_ref| durable.contains(member_ref.as_str()))
    {
        return Err(StoreError::IdentityConflict);
    }
    batch
        .members
        .iter()
        .map(|member| {
            let member_ref =
                member_reference(&batch.archive_member_digest, &member.logical_identity());
            document
                .members
                .iter()
                .find(|row| row.member_ref == member_ref)
                .ok_or(StoreError::IdentityConflict)
        })
        .collect()
}

/// Verifies that a durable record belongs to exactly this batch: same
/// operation identity and canonical request hash, destination, source identity,
/// member digest, schema, purge policy, expected state, denominator and member
/// set. Any divergence is an identity conflict, never a silent overwrite.
#[allow(clippy::too_many_arguments)]
fn check_record_binding(
    document: &RestoreRecordDocument,
    batch: &CanonicalRestoreBatch,
    source_digest: &str,
    expected_state_fence: &StateFence,
    revision_digests: &[String],
    ordering_digests: &[String],
    destination_store_id: &str,
    destination_installation_id: &str,
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
        // The record is evidence for the destination process that wrote it. A
        // record admitted under another store's identity answers for that
        // store, so it can never certify this one's canonical import.
        || document.destination_store_id != destination_store_id
        || document.destination_installation_id != destination_installation_id
    {
        return Err(StoreError::IdentityConflict);
    }
    // The denominator above is a count; the member *set* is bound here, by
    // identity. A same-operation replay that carries a different member set is
    // changed input, so it conflicts here rather than reconciling to a receipt
    // computed over a member list this operation never recorded.
    recorded_members_by_identity(batch, document)?;
    Ok(())
}

/// Re-derives completeness and disposition from the per-member durable records a
/// document actually carries.
///
/// The stored scalars are never trusted as the source of the verdict. Members
/// may legitimately hold different dispositions — a purge obligation covers one
/// archive member and not its neighbour, and a member whose payload did not
/// resolve is unresolved while the rest imported — so the tally is what decides,
/// not agreement across the set. The per-member tally must equal the durable
/// denominator, and a document whose members disagree with it is rejected rather
/// than reported ready.
///
/// Every `Restored` member must additionally carry the import evidence its own
/// readback produced. Without that, a metadata-only batch could still present a
/// complete committed receipt, which is exactly the failure this re-derivation
/// exists to prevent.
fn observed_outcome(
    document: &RestoreRecordDocument,
    denominator: &RestoreDenominator,
) -> Result<(SnapshotCompleteness, StoreMutationDisposition), StoreError> {
    let mut restored = 0_u64;
    let mut rejected = 0_u64;
    let mut suppressed = 0_u64;
    let mut unresolved = 0_u64;
    for member in &document.members {
        match member.disposition {
            MemberDisposition::Restored => {
                restored = restored.saturating_add(1);
                if member.imported_record_id.is_none()
                    || member.imported_class.is_none()
                    || member.imported_digest.is_none()
                {
                    return Err(StoreError::InvalidReceipt);
                }
            }
            MemberDisposition::Rejected => {
                rejected = rejected.saturating_add(1);
                if member.imported_record_id.is_some() {
                    return Err(StoreError::InvalidReceipt);
                }
            }
            MemberDisposition::Suppressed => {
                suppressed = suppressed.saturating_add(1);
                if member.imported_record_id.is_some() {
                    return Err(StoreError::InvalidReceipt);
                }
            }
            MemberDisposition::Unresolved => {
                unresolved = unresolved.saturating_add(1);
                if member.imported_record_id.is_some() {
                    return Err(StoreError::InvalidReceipt);
                }
            }
        }
    }
    // The per-member tally is the observation; the denominator only agrees with
    // it when the record is honest.
    if restored != denominator.restored
        || rejected != denominator.rejected
        || suppressed != denominator.suppressed
        || unresolved != denominator.unresolved
    {
        return Err(StoreError::InvalidReceipt);
    }
    if denominator.total == 0 {
        return Err(StoreError::InvalidReceipt);
    }
    if unresolved > 0 {
        return Ok((
            SnapshotCompleteness::Partial,
            StoreMutationDisposition::Partial,
        ));
    }
    if restored > 0 {
        return Ok((
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        ));
    }
    // Nothing was restored and nothing is unresolved: every member is
    // proven-not-applicable under the current purge ledger.
    Ok((
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::ProvenNotApplied,
    ))
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
///
/// One record per real canonical member of the batch, never per positional
/// index: the record's identity is derived from the member's own
/// domain-qualified logical identity, so a member that a retry, a resume or a
/// later readback re-observes keeps the identity it was first given. The list
/// length is the declared denominator, cross-checked by
/// `validate_reference_closure` before this runs.
///
/// The disposition is decided per member, not per member *set*: a member whose
/// payload could not be resolved, or whose import was not read back out of the
/// destination, is `Unresolved` even while its neighbours are `Restored`, and a
/// purge-suppressed member is `Suppressed` even while the rest imported. The
/// import evidence fields are populated only from a member's own readback, so a
/// `Restored` row can never exist without the canonical import it claims.
fn member_records(
    batch: &CanonicalRestoreBatch,
    domains: &RestoreDomains,
    dispositions: &[MemberDisposition],
    imports: &[Option<ImportedMemberEvidence>],
    purge_revision: u64,
) -> Result<Vec<RestoreMemberRecord>, StoreError> {
    if dispositions.len() != batch.members.len() || imports.len() != batch.members.len() {
        return Err(StoreError::InvalidReceipt);
    }
    batch
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let disposition = dispositions[index];
            let evidence = imports[index].as_ref();
            // Import evidence is exactly the readback of a committed canonical
            // write: it is present for a `Restored` member and absent otherwise,
            // so a suppressed or unresolved member can never carry one.
            if (disposition == MemberDisposition::Restored) != evidence.is_some() {
                return Err(StoreError::InvalidReceipt);
            }
            Ok(RestoreMemberRecord {
                member_ref: member_reference(
                    &batch.archive_member_digest,
                    &member.logical_identity(),
                ),
                member_index: u64::try_from(index).unwrap_or(u64::MAX),
                disposition,
                residency_domain: domains.residency.clone(),
                privacy_domain: domains.privacy.clone(),
                retention_domain: domains.retention.clone(),
                purge_policy_revision: purge_revision,
                imported_record_id: evidence.map(|evidence| evidence.record_id.clone()),
                imported_class: evidence.map(|evidence| evidence.class_token.to_owned()),
                imported_digest: evidence.map(|evidence| evidence.digest.clone()),
            })
        })
        .collect()
}

/// One member's canonical import: the address the commit wrote, the closed class
/// it was written into, and the digest of exactly the bytes that were written.
///
/// The digest is fixed *before* the commit — it is the digest of the resolved
/// payload this operation bound into its own transaction, validated at
/// resolution against the archive owner's attested value. The readback then has
/// to reproduce it, so the receipt answers "the destination serves these exact
/// bytes at this exact address", not merely "some row exists there".
struct ImportedMemberEvidence {
    /// Destination record address the import wrote.
    record_id: String,
    /// Closed class the record was imported into.
    class_token: &'static str,
    /// Digest of the bytes this operation bound for this member. A readback
    /// that does not reproduce it is not this member's import.
    digest: String,
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
        operation: OperationIdentity,
    ) -> Result<IsolatedDestinationReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        operation.validate()?;
        if StoreBackupRequest::prepare_destination_identity(&destination)? != operation {
            return Err(StoreError::IdentityConflict);
        }
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
            return Ok(IsolatedDestinationReceipt {
                operation,
                destination_id: existing.document.destination_id,
                admission_digest: existing.document.admission_digest,
            });
        }
        let document = destination_document(&destination, &binding, admission_digest, now)?;
        let row = destination_registry_row(&document, &key, &ctx.state_fence)?;
        let bindings = prepare_bindings(&row)?;
        match execute_restore_write(
            transport,
            crate::client::RESTORE_OPERATION_PREPARE,
            crate::client::fixed_restore_statement(crate::client::RESTORE_OPERATION_PREPARE)
                .map_err(AdapterError::into_store_error)?
                .to_owned(),
            bindings,
            // Destination preparation owns no admitted restore batch, so it owns
            // no attempt incarnation: there is no local bookkeeping obligation to
            // carry, and its own write is create-only and reconciled by readback
            // below.
            None,
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
        Ok(IsolatedDestinationReceipt {
            operation,
            destination_id: confirmed.document.destination_id,
            admission_digest: confirmed.document.admission_digest,
        })
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
    ///
    /// Local ownership of the owner-scoped attempt slot is held by one private
    /// guard across the whole apply. Every return path completes that guard
    /// explicitly, and a future dropped mid-apply releases only its own
    /// incarnation through `Drop`; neither can cancel a provider write that was
    /// already submitted, so both preserve the reconciliation obligation.
    async fn restore_canonical_batch(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        let mut attempt = RestoreAttemptGuard::acquire(&batch, &self.config)?;
        let outcome = self
            .apply_canonical_batch(ctx, &batch, &mut attempt.exposure)
            .await
            .map_err(redact_store_error);
        // A conservative bookkeeping failure outranks the phase's own outcome:
        // the outcome is only honest if its bookkeeping was recorded.
        attempt.complete(outcome.as_ref().err())?;
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
        check_cancellation(self, &batch)?;
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
        // Readiness requires the real canonical import evidence: every member the
        // record claims is re-read out of the destination's own canonical read
        // path, and a member the destination does not serve makes this batch's
        // result partial. This certifies the batch, not the whole destination —
        // the destination is only canonical-restore-ready once every admitted
        // batch of its restore plan has produced such a receipt.
        let receipt = self
            .receipt_from_observed_imports(transport, &record, &batch)
            .await?;
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
        // The canonical import is written through this adapter's single admitted
        // provider — the one the destination fence names. A document whose label
        // says ISOLATED does not select an isolated provider, so the real
        // binding is checked here: the batch's declared source must not be the
        // admitted process that performs the write, or the import would land in
        // the source's or the active store's canonical tables.
        if batch.source.store_id == active_store
            || batch.source.installation_id == active_installation
        {
            return Err(StoreError::InvalidField {
                field: "restore.source_store_id",
                reason: "restore must not write the source or active store",
            });
        }
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
        let (revision_digests, ordering_digests) = expected_head_digests(batch)?;
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
            &active_store_identity(&self.config).0,
            &active_store_identity(&self.config).1,
        )?;
        Ok(Some(document))
    }

    /// Applies one validated batch and returns the provider-derived receipt.
    ///
    /// `exposure` records what this invocation may already have submitted to the
    /// provider. It is local bookkeeping only: it never decides a verdict, and
    /// every returned receipt is still derived from exact durable readback.
    #[allow(clippy::too_many_lines)]
    async fn apply_canonical_batch(
        &self,
        ctx: &RequestMeta,
        batch: &CanonicalRestoreBatch,
        exposure: &mut RestoreEffectExposure,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        batch.validate()?;
        let (active_store, active_installation) = active_store_identity(&self.config);
        check_cancellation(self, batch)?;
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
            // original member identities and missing denominator. The receipt is
            // re-derived from the destination's own canonical readback, so an
            // exact repeat never re-applies and never re-asserts an import it
            // has not just observed.
            check_duration(existing.started_at_unix_ms, now)?;
            let receipt = self
                .receipt_from_observed_imports(transport, &existing, batch)
                .await?;
            exposure.note_durable_result_verified();
            project_verified_receipt(batch, &receipt)?;
            return Ok(receipt);
        }
        // Reacquiring local ownership is not permission to take the fresh-write
        // branch. This invocation has submitted nothing, but an earlier
        // incarnation of this same owner-scoped identity may have handed a write
        // to the provider that can still complete, and an absent record row is
        // not proof of non-commit. The obligation is therefore reported as the
        // typed unknown outcome and resolved by exact operation identity, never
        // by writing again.
        if exposure.requires_reconciliation() {
            return Err(unknown_outcome(batch.operation.operation_id.as_str()));
        }
        // Current purge obligations, read before the write. The same rows are
        // re-read inside the commit transaction, so an obligation recorded
        // between this observation and the commit refuses the batch instead of
        // leaving a stale `Restored` result behind.
        let (member_observation, scope_observation) = read_purge_ledger(
            transport,
            &self.config,
            &batch.archive_member_digest,
            &batch.source.installation_id,
        )
        .await?;
        let purge_observed = purge_commit_preconditions(&member_observation, &scope_observation);
        // The destination's own head values decide whether the batch's expected
        // state still holds. The batch's heads are an input; these are the
        // observed values the comparison is made against.
        let revision_expected: Vec<u64> = batch
            .expected_revision_heads
            .iter()
            .map(|head| head.expected_revision)
            .collect();
        let ordering_expected: Vec<u64> = batch
            .expected_ordering_heads
            .iter()
            .map(|head| head.expected_sequence)
            .collect();
        let revision_keys: Vec<String> = batch
            .expected_revision_heads
            .iter()
            .map(|head| head.key.as_str().to_owned())
            .collect();
        let ordering_keys: Vec<String> = batch
            .expected_ordering_heads
            .iter()
            .map(|head| head.scope.as_str().to_owned())
            .collect();
        check_observed_heads(
            &revision_expected,
            &read_destination_heads(
                transport,
                &self.config,
                RestoreRecordClass::RevisionHead,
                &revision_keys,
            )
            .await?,
            StoreError::RevisionConflict,
        )?;
        check_observed_heads(
            &ordering_expected,
            &read_destination_heads(
                transport,
                &self.config,
                RestoreRecordClass::OrderingHead,
                &ordering_keys,
            )
            .await?,
            StoreError::OrderingConflict,
        )?;
        // A purge obligation applies to the archive member scope, and the
        // residency, privacy and retention domains stay separate: an obligation
        // in one domain never silently widens into another.
        let scope_disposition = match decide_purge(
            member_observation.entry.as_ref(),
            scope_observation.entry.as_ref(),
        ) {
            PurgeDecision::Clear => MemberDisposition::Restored,
            PurgeDecision::Suppressed => MemberDisposition::Suppressed,
            PurgeDecision::Unresolved => MemberDisposition::Unresolved,
        };
        // Source resolution: every member's canonical logical payload is
        // obtained from the archive/artifact owner's carrier rows, before any
        // member is given a disposition. A member whose payload cannot be
        // resolved is unresolved, never restored. The carriers are published
        // first, under this exact admitted operation and only where the current
        // purge ledger leaves the member servable, so resolution reads back a row
        // this operation owns rather than one that happens to exist — and an
        // importable member that retained no payload is refused typed here,
        // before the commit, instead of being carried to a partial receipt.
        let published = if scope_disposition == MemberDisposition::Restored {
            publish_archive_member_carriers(
                transport,
                &self.config,
                batch,
                &ctx.state_fence,
                fence.document.cumulative_bytes,
                &mut *exposure,
            )
            .await?
        } else {
            Vec::new()
        };
        let resolved = resolve_archive_members(transport, &self.config, batch).await?;
        let imports: Vec<&ResolvedArchiveMember> = if scope_disposition
            == MemberDisposition::Restored
        {
            let imports: Vec<&ResolvedArchiveMember> = resolved
                .iter()
                .filter_map(Option::as_ref)
                .filter(|import| import.member.member_type != SnapshotMemberType::Reference)
                .collect();
            // Each resolved payload must still be the batch member it was
            // resolved for. Resolution is positional, so this re-proves the
            // binding rather than assuming it: a payload that is not equal to
            // the admitted member at its own index is not this batch's
            // payload, whatever its carrier row claimed.
            for import in &imports {
                let index =
                    usize::try_from(import.member_index).map_err(|_| StoreError::InvalidField {
                        field: "restore.member_index",
                        reason: "resolved member index is out of range",
                    })?;
                let member = batch.members.get(index).ok_or(StoreError::InvalidField {
                    field: "restore.member_index",
                    reason: "resolved member index is out of range",
                })?;
                if import.member != *member {
                    return Err(StoreError::IdentityConflict);
                }
            }
            imports
        } else {
            Vec::new()
        };
        // The canonical import, its operation receipt and the destination
        // bookkeeping all commit in one transaction. Each member's disposition
        // is planned here from the resolution and the current ledger, then
        // re-decided from the destination's own readback after the commit: a
        // member is `Restored` only when its row is actually served.
        let dispositions: Vec<MemberDisposition> = batch
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| match scope_disposition {
                MemberDisposition::Suppressed => MemberDisposition::Suppressed,
                MemberDisposition::Unresolved => MemberDisposition::Unresolved,
                // A reference edge is never a record the import can write, so it
                // is rejected as a row, not left unresolved. Its closure is
                // proved against this collected set below.
                MemberDisposition::Restored => {
                    if member.member_type == SnapshotMemberType::Reference {
                        MemberDisposition::Rejected
                    } else {
                        match resolved.get(index) {
                            Some(Some(_)) => MemberDisposition::Restored,
                            _ => MemberDisposition::Unresolved,
                        }
                    }
                }
                MemberDisposition::Rejected => MemberDisposition::Rejected,
            })
            .collect();
        // Typed closure, proved against the planned dispositions before anything
        // is written: an edge this batch claims to have closed must land on a
        // member this batch actually imports, in the same obligation domain.
        // Unverified derived data cannot grant completion, so a dangling edge
        // refuses the batch rather than being committed and reported.
        let planned_by_member = dispositions_by_member(batch, &dispositions);
        validate_reference_closure_against(batch, &planned_by_member)?;
        let denominator = denominator_of(&dispositions);
        denominator.validate()?;
        let (completeness, mutation) = planned_outcome(&dispositions);
        // The durable record names the class, the address and the exact content
        // digest this commit writes for each member. That digest is fixed here
        // from the payload already bound into the transaction, and the
        // post-commit readback has to reproduce it before the member can be
        // reported restored — so a record written without a matching import is
        // re-read as unresolved rather than certified.
        let planned = planned_evidence(batch, &imports);
        let members = member_records(
            batch,
            &source.domains,
            &dispositions,
            &planned,
            fence.document.purge_policy_revision,
        )?;
        let (revision_digests, ordering_digests) = expected_head_digests(batch)?;
        let document = RestoreRecordDocument {
            operation: batch.operation.clone(),
            destination_id: batch.destination.destination_id.clone(),
            destination_identity: fence.document.destination_identity.clone(),
            destination_store_id: active_store.clone(),
            destination_installation_id: active_installation.clone(),
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
        // The byte bound covers the canonical bytes this commit writes, not only
        // the bookkeeping document: a batch that imports a large payload inside a
        // small record is still a large restore, and the carrier rows it
        // published for those same payloads are bytes the destination received.
        let document_bytes = u64::try_from(payload.len())
            .map_err(|_| StoreError::PayloadTooLarge)?
            .checked_add(imported_payload_bytes(&imports)?)
            .ok_or(StoreError::PayloadTooLarge)?
            .checked_add(carrier_payload_bytes(&published)?)
            .ok_or(StoreError::PayloadTooLarge)?;
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
        let (shape, bindings) = apply_bindings(
            &destination_row,
            &record_row,
            &placement_row,
            &record_row_key,
            &placement_key_value,
            &fence,
            &ctx.state_fence,
            batch,
            &purge_observed,
            &imports,
        )?;
        match execute_restore_write(
            transport,
            crate::client::RESTORE_OPERATION_APPLY,
            crate::client::restore_apply_statement(shape),
            bindings,
            Some(&mut *exposure),
        )
        .await
        {
            Ok(()) => {}
            Err(StoreError::IdentityConflict | StoreError::RevisionConflict) => {
                // A concurrent winner owns this operation identity, this archive
                // placement, or the destination fence: reconcile by exact
                // readback, never re-apply under a new identity.
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
                    let receipt = self
                        .receipt_from_observed_imports(transport, &existing, batch)
                        .await?;
                    exposure.note_durable_result_verified();
                    project_verified_receipt(batch, &receipt)?;
                    return Ok(receipt);
                }
                return Err(StoreError::IdentityConflict);
            }
            Err(error) => return Err(error),
        }
        // The committed receipt is derived from the destination's own canonical
        // readback of every imported member, not from the bookkeeping the commit
        // just wrote. A lost response stays unknown and is reconciled by
        // operation identity.
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
        let receipt = self
            .receipt_from_observed_imports(transport, &committed, batch)
            .await?;
        exposure.note_durable_result_verified();
        project_verified_receipt(batch, &receipt)?;
        Ok(receipt)
    }

    /// Projects the receipt only after every member's canonical import has been
    /// re-read out of the destination.
    ///
    /// The durable record names what each member claimed — its closed class, its
    /// destination address and the digest of the bytes this operation committed
    /// for it; this observes what the destination actually serves. A member the
    /// destination does not return, or returns with different bytes, is
    /// `Unresolved`, so a batch whose bookkeeping committed while its import did
    /// not become servable reports partial instead of complete. The typed
    /// reference closure is then re-proved against what was observed, not
    /// against what was declared.
    async fn receipt_from_observed_imports(
        &self,
        transport: &RpcTransport,
        document: &RestoreRecordDocument,
        batch: &CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        // The rows are bound to this batch's members by identity, never by
        // position: a same-operation replay that carries a different member set
        // conflicts here, and every disposition below is read from the row this
        // very member was recorded with. They come back in batch member order,
        // which is the order the planned-set consumers below are indexed in.
        let recorded = recorded_members_by_identity(batch, document)?;
        let first = recorded.first().ok_or(StoreError::InvalidReceipt)?;
        let domains = RestoreDomains {
            residency: first.residency_domain.clone(),
            privacy: first.privacy_domain.clone(),
            retention: first.retention_domain.clone(),
        };
        let mut dispositions = Vec::with_capacity(recorded.len());
        let mut dispositions_by_member: BTreeMap<String, MemberDisposition> = BTreeMap::new();
        let mut evidence = Vec::with_capacity(recorded.len());
        for row in &recorded {
            // Only a claim that names a closed class, a record address *and* the
            // content digest this operation committed can be looked up in the
            // destination. A metadata-only record written before canonical import
            // named none of them, so it stays bookkeeping evidence: it is re-read
            // as `Unresolved` rather than being certified as imported data.
            let observed = match (
                row.disposition,
                row.imported_class.as_deref(),
                row.imported_record_id.as_deref(),
                row.imported_digest.as_deref(),
            ) {
                (
                    MemberDisposition::Restored,
                    Some(class_token),
                    Some(record_id),
                    Some(expected_digest),
                ) => {
                    let class = RestoreRecordClass::parse(class_token).ok_or({
                        StoreError::InvalidField {
                            field: "restore.imported_class",
                            reason: "unknown canonical class token",
                        }
                    })?;
                    read_imported_member(transport, &self.config, class, record_id, expected_digest)
                        .await?
                        .map(|digest| ImportedMemberEvidence {
                            record_id: record_id.to_owned(),
                            class_token: class.token(),
                            digest,
                        })
                }
                _ => None,
            };
            let disposition = match observed {
                Some(_) => MemberDisposition::Restored,
                None => match row.disposition {
                    MemberDisposition::Suppressed => MemberDisposition::Suppressed,
                    MemberDisposition::Rejected => MemberDisposition::Rejected,
                    MemberDisposition::Restored | MemberDisposition::Unresolved => {
                        MemberDisposition::Unresolved
                    }
                },
            };
            dispositions.push(disposition);
            // The closure guard reads dispositions by the member identity the row
            // was recorded under, so a disposition observed for one member can
            // never be examined against another member's reference edge.
            dispositions_by_member.insert(row.member_ref.clone(), disposition);
            evidence.push(observed);
        }
        validate_reference_closure_against(batch, &dispositions_by_member)?;
        let denominator = denominator_of(&dispositions);
        denominator.validate()?;
        let members = member_records(
            batch,
            &domains,
            &dispositions,
            &evidence,
            document.current_purge_revision,
        )?;
        let observed_document = RestoreRecordDocument {
            denominator,
            members,
            completeness: SnapshotCompleteness::Partial,
            disposition: StoreMutationDisposition::Partial,
            ..document.clone()
        };
        // The observed document is what the destination actually serves; the
        // receipt is projected from it, never from the pre-write claim.
        let (completeness, mutation) =
            observed_outcome(&observed_document, &observed_document.denominator)?;
        receipt_from_document(
            &RestoreRecordDocument {
                completeness,
                disposition: mutation,
                ..observed_document
            },
            batch,
        )
    }
}

/// Tallies the canonical payload bytes one apply transaction imports.
///
/// The bound must cover what the destination actually receives, so the resolved
/// payloads are measured in their canonical encoding rather than the count of
/// members being the only thing accounted for.
fn imported_payload_bytes(imports: &[&ResolvedArchiveMember]) -> Result<u64, StoreError> {
    let mut total = 0_u64;
    for member in imports {
        let bytes = u64::try_from(canonical_digest_bytes(&member.payload)?.len())
            .map_err(|_| StoreError::PayloadTooLarge)?;
        total = total
            .checked_add(bytes)
            .ok_or(StoreError::PayloadTooLarge)?;
    }
    Ok(total)
}

/// Tallies the retained-payload carrier bytes one apply published.
///
/// The publication is a real write into the destination, so it is accounted on
/// the same byte bound as the canonical import rather than being free because it
/// happened before the commit transaction.
fn carrier_payload_bytes(published: &[PublishedCarrier]) -> Result<u64, StoreError> {
    let mut total = 0_u64;
    for entry in published {
        let bytes =
            u64::try_from(entry.row.payload.len()).map_err(|_| StoreError::PayloadTooLarge)?;
        total = total
            .checked_add(bytes)
            .ok_or(StoreError::PayloadTooLarge)?;
    }
    Ok(total)
}

/// Tallies one per-member disposition list into the exact denominator.
fn denominator_of(dispositions: &[MemberDisposition]) -> RestoreDenominator {
    let count = |wanted: MemberDisposition| {
        u64::try_from(
            dispositions
                .iter()
                .filter(|disposition| **disposition == wanted)
                .count(),
        )
        .unwrap_or(u64::MAX)
    };
    RestoreDenominator::new(
        count(MemberDisposition::Restored),
        count(MemberDisposition::Rejected),
        count(MemberDisposition::Suppressed),
        count(MemberDisposition::Unresolved),
    )
}

/// Derives the pre-commit completeness and disposition of a planned batch.
///
/// This is the *plan*, recorded in the durable operation receipt. It is not the
/// verdict: [`observed_outcome`] re-derives completeness from the destination's
/// own readback, and a member whose import the destination does not serve turns
/// this plan into a partial result.
fn planned_outcome(
    dispositions: &[MemberDisposition],
) -> (SnapshotCompleteness, StoreMutationDisposition) {
    let denominator = denominator_of(dispositions);
    if denominator.unresolved > 0 {
        return (
            SnapshotCompleteness::Partial,
            StoreMutationDisposition::Partial,
        );
    }
    if denominator.restored > 0 {
        return (
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        );
    }
    (
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::ProvenNotApplied,
    )
}

/// Binds the class, the address and the content digest of each member this
/// commit will import.
///
/// The digest is the one already validated at resolution against the archive
/// owner's attested value, and it is what the post-commit readback must
/// reproduce. Binding it here is what makes the readback a content check rather
/// than a row-presence check.
fn planned_evidence(
    batch: &CanonicalRestoreBatch,
    imports: &[&ResolvedArchiveMember],
) -> Vec<Option<ImportedMemberEvidence>> {
    let mut evidence: Vec<Option<ImportedMemberEvidence>> =
        (0..batch.members.len()).map(|_| None).collect();
    for member in imports {
        let index = usize::try_from(member.member_index).unwrap_or(usize::MAX);
        let Some(slot) = evidence.get_mut(index) else {
            continue;
        };
        *slot = Some(ImportedMemberEvidence {
            record_id: member.record_id.clone(),
            class_token: member.class.token(),
            digest: member.payload_digest.clone(),
        });
    }
    evidence
}

/// Builds the commit preconditions for the current purge obligations.
///
/// Both observed obligations travel into the commit transaction as their
/// registry key and the exact durable revision the row was read at, with an
/// absent row bound as revision `0`. The transaction re-reads the same rows and
/// refuses unless the presence and revision are unchanged, so an obligation
/// recorded after this observation aborts the commit instead of leaving a stale
/// disposition behind.
///
/// Absence is still not proof that the authoritative privacy owner holds no
/// obligation: it is only the absence this port's own ledger records, and it is
/// carried as an explicit "absent" precondition rather than folded into a clear
/// result.
fn purge_commit_preconditions(
    member: &PurgeObservation,
    scope: &PurgeObservation,
) -> Vec<(String, u64)> {
    vec![
        (member.key.clone(), member.row_revision),
        (scope.key.clone(), scope.row_revision),
    ]
}

/// Source identity binding of one batch plus the destination-owned domains its
/// members are restored under.
struct SourceBinding {
    digest: String,
    domains: RestoreDomains,
}

/// Binds the durable bookkeeping half of one apply transaction.
///
/// The registry table, the destination fence compare-and-set values, the
/// per-operation record row and the archive-placement exclusivity row. All of
/// them are bound values: no row content and no identifier is interpolated into
/// statement text.
///
/// Two different fences are bound, and they are not interchangeable:
/// `restore_expected_destination_fence` is the destination row's own fence, the
/// value the fence compare-and-set must observe, while
/// `restore_expected_state_fence` is the state fence *this request* was admitted
/// under — the generation the batch's own expected heads were validated against
/// by [`check_expected_state`] and the value the in-transaction head guards
/// compare a destination head against.
#[allow(clippy::too_many_arguments)]
fn bookkeeping_bindings(
    destination_row: &RecoveryRecord,
    record_row: &RecoveryRecord,
    placement_row: &RecoveryRecord,
    record_row_key: &str,
    placement_row_key: &str,
    fence: &DestinationFence,
    expected_state_fence: &StateFence,
    bindings: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), StoreError> {
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
    bindings.insert(
        "restore_expected_state_fence".to_owned(),
        serde_json::to_value(expected_state_fence)
            .map_err(|error| AdapterError::Serialization(error.to_string()).into_store_error())?,
    );
    Ok(())
}

/// Binds the expected-head, purge-obligation and canonical-import half of one
/// apply transaction.
///
/// Each expected head travels as its key and the exact revision or sequence the
/// batch was admitted against, each observed purge obligation as its row address
/// and its observed revision, and each resolved canonical record as its class
/// table, its record address and its payload.
fn precondition_bindings(
    batch: &CanonicalRestoreBatch,
    purge_observed: &[(String, u64)],
    imports: &[&ResolvedArchiveMember],
    bindings: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), StoreError> {
    bindings.insert(
        "restore_revision_table".to_owned(),
        serde_json::Value::String(RestoreRecordClass::RevisionHead.table().to_owned()),
    );
    bindings.insert(
        "restore_ordering_table".to_owned(),
        serde_json::Value::String(RestoreRecordClass::OrderingHead.table().to_owned()),
    );
    for (index, head) in batch.expected_revision_heads.iter().enumerate() {
        bindings.insert(
            format!("restore_revision_key{index}"),
            serde_json::Value::String(head.key.as_str().to_owned()),
        );
        bindings.insert(
            format!("restore_expected_revision{index}"),
            serde_json::Value::from(head.expected_revision),
        );
    }
    for (index, head) in batch.expected_ordering_heads.iter().enumerate() {
        bindings.insert(
            format!("restore_ordering_scope{index}"),
            serde_json::Value::String(head.scope.as_str().to_owned()),
        );
        bindings.insert(
            format!("restore_expected_sequence{index}"),
            serde_json::Value::from(head.expected_sequence),
        );
    }
    for (index, (key, revision)) in purge_observed.iter().enumerate() {
        bindings.insert(
            format!("restore_purge_row_id{index}"),
            serde_json::Value::String(registry_record_id(key)?),
        );
        bindings.insert(
            format!("restore_expected_purge_revision{index}"),
            serde_json::Value::from(*revision),
        );
    }
    for (index, member) in imports.iter().enumerate() {
        bindings.insert(
            format!("restore_class_table{index}"),
            serde_json::Value::String(member.class.table().to_owned()),
        );
        bindings.insert(
            format!("restore_class_row_id{index}"),
            serde_json::Value::String(member.record_id.clone()),
        );
        bindings.insert(
            format!("restore_class_record{index}"),
            member.payload.clone(),
        );
    }
    Ok(())
}

/// Builds the bound parameters of one apply transaction.
///
/// Every parameter is a bound value. The count of each indexed family is
/// reported in the returned [`crate::client::RestoreApplyShape`] so the composed
/// statement and the bindings are rendered from one shape and cannot drift
/// apart.
#[allow(clippy::too_many_arguments)]
fn apply_bindings(
    destination_row: &RecoveryRecord,
    record_row: &RecoveryRecord,
    placement_row: &RecoveryRecord,
    record_row_key: &str,
    placement_row_key: &str,
    fence: &DestinationFence,
    expected_state_fence: &StateFence,
    batch: &CanonicalRestoreBatch,
    purge_observed: &[(String, u64)],
    imports: &[&ResolvedArchiveMember],
) -> Result<
    (
        crate::client::RestoreApplyShape,
        serde_json::Map<String, serde_json::Value>,
    ),
    StoreError,
> {
    let mut bindings = serde_json::Map::new();
    bookkeeping_bindings(
        destination_row,
        record_row,
        placement_row,
        record_row_key,
        placement_row_key,
        fence,
        expected_state_fence,
        &mut bindings,
    )?;
    precondition_bindings(batch, purge_observed, imports, &mut bindings)?;
    let shape = crate::client::RestoreApplyShape {
        revision_heads: batch.expected_revision_heads.len(),
        ordering_heads: batch.expected_ordering_heads.len(),
        purge_obligations: purge_observed.len(),
        imports: imports.len(),
    };
    Ok((shape, bindings))
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
