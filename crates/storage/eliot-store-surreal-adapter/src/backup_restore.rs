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
//! partial receipt. The retained reference's own recorded length and digest are
//! validated against the original bytes it carries before it is parsed at all,
//! so the digest that travels on is the owner's proof about its own record and
//! not a checksum of a locally re-derived encoding. Resolution then reads those
//! rows back — the ones this operation wrote, under this operation's own key —
//! and compares every field against the batch's own member before the payload is
//! used, including the owner's attested payload digest, which is re-proved
//! against the canonical encoding of the bytes the carrier actually holds. A
//! carrier this operation published and cannot read back is an unresolved
//! member, never a member with empty content. The resolved
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
//! observed, and that exposure is *per provider-write stage*, never one scalar
//! over the operation: carrier publication and canonical apply are two independent
//! obligations with two independent exposures, so neither stage's evidence can
//! stand in for the other's and no single "highest exposure" ever exists. The
//! per-stage model is what makes both remaining questions well posed: a
//! cancellation answer and the eviction predicate each consult EVERY stage
//! ([`RestoreStageExposure::any_unproven`], read by [`check_cancellation`] and by
//! a guard on release), while the fresh-write gate before the canonical apply
//! consults the apply stage alone ([`RestoreEffectExposure::apply_stage`]) because
//! the carrier stage is never answered from the apply's evidence: it is decided
//! by its own exact readback, and there are exactly five such call sites —
//! 1. [`SurrealStoreAdapter::resolve_carrier_stage`], immediately before the
//!    publication it governs, over the intended set of the invocation asking;
//! 2. the publication's own success arm, after the provider answered `Ok(())`;
//! 3. its duplicate arm, after the create-only transaction answered
//!    [`StoreError::IdentityConflict`];
//! 4. its refusal arm, when the write was handed to the transport and did not
//!    answer; and
//! 5. the reconciliation [`carrier_publication_for`] attempts on the disposition
//!    that publishes no carrier row of its own.
//!
//! Relaxing any one of them therefore cannot silently relax another. A stage this
//! slot already carries as proved is re-proved by (1) like any other owed stage,
//! because the slot key does not bind `canonical_request_hash`, so two requests
//! under one operation id share one slot. A dropped future releases only its own
//! incarnation while an effect that may already have been submitted stays an
//! exact-reconciliation obligation on that stage alone.
//! Releasing the guard is never provider cancellation and never durable
//! settlement.

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

    /// The store-owned key column that names one record of this class.
    ///
    /// The canonical write path binds exactly this column beside `body` for this
    /// table ([`crate::schema::TX_CREATE_RECEIPT`],
    /// [`crate::schema::TX_CREATE_REVISION`], [`crate::schema::TX_CREATE_EVENT`],
    /// [`crate::schema::TX_CREATE_PROJECTION`],
    /// [`crate::schema::TX_CREATE_RELATION`],
    /// [`crate::schema::TX_CREATE_OUTBOX`]) and the canonical read paths select on
    /// it ([`crate::schema::READ_RECEIPT_BY_OPERATION`],
    /// [`crate::schema::READ_REVISION_HEADS_BY_KEYS`],
    /// [`crate::schema::READ_ORDERING_HEADS_BY_SCOPES`]). It is the same
    /// declaration the capture side reads as this class's key
    /// (`crate::backup_snapshot::CANONICAL_SOURCE_CLASSES`), so a restored row
    /// carries the column the destination actually reads it by.
    const fn key_field(self) -> &'static str {
        match self {
            Self::WriteReceipt => "operation_id",
            Self::RevisionHead => "revision_key",
            Self::OrderingHead => "ordering_scope",
            Self::CanonicalEvent => "event_id",
            Self::ProjectionRecord => "publication_id",
            Self::RelationRecord => "relation_id",
            Self::OutboxEvent => "outbox_id",
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
    /// published. Publication validates it against the owner's *original*
    /// recorded payload, and resolution validates the same attested value
    /// against the canonical encoding of the payload the carrier actually
    /// holds, so a carrier that claims one digest and carries other bytes is
    /// refused rather than accepted because its claim looked plausible.
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

/// Closed local bookkeeping state of one provider-write stage of one
/// owner-scoped attempt slot.
///
/// Local ownership and effect exposure are separate facts and never collapse
/// into one another: a slot that was released cleanly can still owe an exact
/// provider reconciliation, and a slot that still holds a live owner may owe
/// nothing yet. The variants are ordered by increasing certainty, so merging two
/// observations *of the same stage* is the maximum of the two and the highest
/// observation is never lowered by a later, less informed one. Certainty is
/// never transferable between stages: one stage's exact durable result says
/// nothing whatever about the other stage's write.
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

/// Closed pair of the provider-write stages one restore operation performs.
///
/// These are the two independent provider writes this port makes under one
/// admitted operation identity: the archive-member carrier rows the batch
/// resolves from, and the canonical import that reads them back and commits the
/// destination bookkeeping. Database idempotency and external-effect idempotency
/// remain separate, so each stage carries its own effect identity and its own
/// reconciliation state; a committed canonical import never proves the carrier
/// publication occurred exactly once. The stages are named, not labelled, so
/// evidence about one can never be read as evidence about the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreWriteStage {
    /// Publication of this operation's own archive-member carrier rows.
    CarrierPublication,
    /// The canonical import of the resolved members into the destination.
    CanonicalApply,
}

/// Effect exposure of one slot, recorded per provider-write stage.
///
/// The carrier-publication half and the canonical-apply half are merged
/// separately. Collapsing them into one scalar would make a verified carrier
/// publication read as a verified apply — and an unknown apply read as an
/// unknown carrier — which is exactly the single bit of information the two
/// independent obligations do not share.
#[derive(Clone, Copy, Debug)]
struct RestoreStageExposure {
    /// Exposure of the archive-member carrier-publication stage.
    carrier: RestoreEffectState,
    /// Exposure of the canonical-apply stage.
    apply: RestoreEffectState,
}

impl RestoreStageExposure {
    /// Exposure of a slot that has never handed a provider write to the
    /// transport.
    const NONE: Self = Self {
        carrier: RestoreEffectState::NoWriteSubmitted,
        apply: RestoreEffectState::NoWriteSubmitted,
    };

    /// Merges two observations of the same slot, per stage.
    ///
    /// The maximum is taken inside each stage, so certainty is never raised in
    /// one stage by evidence about the other and never lowered inside one.
    ///
    /// Not `const`: [`RestoreEffectState`]'s [`Ord::max`] is not a `const fn`,
    /// and component-wise `max` per field is exactly the semantics this merge
    /// must keep, so it is never replaced by a derived `Ord` on the pair.
    fn merged(self, other: Self) -> Self {
        Self {
            carrier: self.carrier.max(other.carrier),
            apply: self.apply.max(other.apply),
        }
    }

    /// Reports whether *any* stage of the slot still owes an exact provider
    /// reconciliation.
    const fn any_unproven(self) -> bool {
        self.carrier.is_unproven() || self.apply.is_unproven()
    }
}

/// Effect exposure of one invocation, carried beside the uncertainty it
/// inherited from the slot it acquired.
///
/// The two halves are kept apart so a clean release can never read as proof of
/// non-commit, and each half is kept per stage so a clean carrier publication
/// can never read as a clean canonical apply: the inherited half is what an
/// earlier incarnation of each stage may already have submitted, and only that
/// stage's own durable readback clears it.
#[derive(Clone, Copy, Debug)]
struct RestoreEffectExposure {
    /// Exposure inherited from the slot at acquisition time, per stage.
    inherited: RestoreStageExposure,
    /// Exposure of this invocation's carrier-publication stage alone.
    carrier: RestoreEffectState,
    /// Exposure of this invocation's canonical-apply stage alone.
    apply: RestoreEffectState,
}

impl RestoreEffectExposure {
    /// Starts a fresh invocation against an already-tracked slot.
    const fn new(inherited: RestoreStageExposure) -> Self {
        Self {
            inherited,
            carrier: RestoreEffectState::NoWriteSubmitted,
            apply: RestoreEffectState::NoWriteSubmitted,
        }
    }

    /// The highest exposure ever observed for this slot, per stage.
    ///
    /// Not `const`: this merges through [`RestoreStageExposure::merged`], which
    /// cannot be `const` (see there). The result is per stage, never a single
    /// scalar over the pair.
    fn state(self) -> RestoreStageExposure {
        self.inherited.merged(RestoreStageExposure {
            carrier: self.carrier,
            apply: self.apply,
        })
    }

    /// The highest carrier-publication exposure ever observed for this slot.
    ///
    /// Not `const`: reaches [`Self::state`], hence `merged`.
    fn carrier_stage(self) -> RestoreEffectState {
        self.state().carrier
    }

    /// The highest canonical-apply exposure ever observed for this slot.
    ///
    /// Not `const`: reaches [`Self::state`], hence `merged`.
    fn apply_stage(self) -> RestoreEffectState {
        self.state().apply
    }

    /// Marks the instant before the effectful transport poll of one stage.
    fn note_write_may_be_submitted(&mut self, stage: RestoreWriteStage) {
        match stage {
            RestoreWriteStage::CarrierPublication => {
                self.carrier = self
                    .carrier
                    .max(RestoreEffectState::WriteMayHaveBeenSubmitted);
            }
            RestoreWriteStage::CanonicalApply => {
                self.apply = self
                    .apply
                    .max(RestoreEffectState::WriteMayHaveBeenSubmitted);
            }
        }
    }

    /// Marks that the provider answered one stage's write.
    fn note_response_observed(&mut self, stage: RestoreWriteStage) {
        match stage {
            RestoreWriteStage::CarrierPublication => {
                self.carrier = self.carrier.max(RestoreEffectState::ResponseObserved);
            }
            RestoreWriteStage::CanonicalApply => {
                self.apply = self.apply.max(RestoreEffectState::ResponseObserved);
            }
        }
    }

    /// Marks that every carrier row this operation published was read back
    /// exactly.
    ///
    /// This is evidence about the carrier-publication stage alone. An exact
    /// carrier readback proves nothing about the canonical import, which keeps
    /// its own state until its own durable record is read back.
    fn note_carrier_verified(&mut self) {
        self.carrier = RestoreEffectState::DurableResultVerified;
    }

    /// Marks that the canonical apply's exact durable record was read back.
    ///
    /// This is evidence about the canonical-apply stage alone. A pre-existing
    /// record read back on a resumed operation proves the apply and nothing
    /// else: no carrier row was read on that path, so the carrier stage keeps
    /// whatever certainty it has.
    fn note_apply_verified(&mut self) {
        self.apply = RestoreEffectState::DurableResultVerified;
    }
}

/// One in-process attempt slot of one destination/adapter owner's admitted
/// operation identity.
///
/// It exists only to serialize concurrent same-operation attempts inside this
/// process and to carry two independent facts forward across bounded,
/// cancelled, retried and dropped attempts: the *first* redacted failure and the
/// *highest* effect exposure of each provider-write stage. It is never a receipt
/// and never an outcome. A slot left behind by a released attempt is bounded
/// evidence, not a lock: it never blocks a retry from reaching the provider's own
/// durable reconciliation readback, which is the only authority on whether the
/// earlier attempt committed.
#[derive(Clone, Debug)]
struct RestoreAttempt {
    /// Closed phase label this slot was admitted for.
    phase: String,
    /// The local bookkeeping incarnation that owns the slot right now.
    incarnation: u64,
    /// True only while the owning incarnation is still live in this process.
    running: bool,
    /// Highest effect exposure ever observed for this slot, per stage; never
    /// lowered, and never raised in one stage by the other stage's evidence.
    effect_state: RestoreStageExposure,
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
    /// Highest effect exposure ever observed for the slot, per stage.
    effect_state: RestoreStageExposure,
}

impl RestoreAttemptState {
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
/// [`MAX_RESTORE_TRACKED_ATTEMPTS`], each of its provider-write stages keeps its
/// own exposure — the ledger stores a per-stage [`RestoreStageExposure`] pair, not
/// one scalar over the operation, so a slot retained for an unproven carrier stage
/// does not assert anything about the apply stage and vice versa — and a retry
/// always reaches the provider's durable reconciliation readback first. The two
/// stage-wise questions stay distinct here too: retention is decided per stage,
/// keeping a slot while [`RestoreStageExposure::any_unproven`] answers true, and
/// also while its canonical apply stage has not reached
/// [`RestoreEffectState::DurableResultVerified`] beside a submitted carrier
/// stage; the cancellation answer is
/// per stage too, as it
/// answers the typed unknown outcome while *either* stage still owes a
/// reconciliation, because a carrier publication is an external effect in its own
/// right and a verified apply says nothing about it.
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
    attempt_slot_key_from_components(
        active_store,
        active_installation,
        destination.destination_id.as_str(),
        operation.operation_id.as_str(),
    )
}

/// Derives the same owner-scoped slot key from its four scalar components.
///
/// Every caller must reach this one function, so a writer and a reader cannot
/// disagree about which slot they hold: the durable restore record carries the
/// destination owner and the admitted operation identity, which is how a caller
/// that holds only the record reaches the same slot. The tuple shape, its order
/// and the fallback byte layout are byte-identical to the derived key above, so
/// the digest is unchanged for the same inputs.
fn attempt_slot_key_from_components(
    active_store: &str,
    active_installation: &str,
    destination_id: &str,
    operation_id: &str,
) -> String {
    let shape = (
        "restore-attempt-v1",
        active_store,
        active_installation,
        destination_id,
        operation_id,
    );
    let bytes = canonical_json_bytes(&shape).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(256);
        fallback.extend_from_slice(b"restore-attempt-v1");
        fallback.extend_from_slice(active_store.as_bytes());
        fallback.extend_from_slice(active_installation.as_bytes());
        fallback.extend_from_slice(destination_id.as_bytes());
        fallback.extend_from_slice(operation_id.as_bytes());
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
/// Ownership and effect exposure are tracked apart, and per stage. The guard
/// carries what *this invocation* may already have submitted to each of the two
/// provider-write stages, and the slot keeps the highest exposure ever observed
/// for each stage, so no release — not even an early return, an error path, or a
/// dropped pending future — can clear an effect that may already have reached the
/// provider, and one stage's verified result can never clear the other stage's
/// uncertainty. There is no single "highest exposure" this guard hands back: the
/// accessors [`RestoreEffectExposure::carrier_stage`] and
/// [`RestoreEffectExposure::apply_stage`] each report one stage, and a release
/// asks the merged pair two different per-stage questions of them.
/// [`RestoreStageExposure::any_unproven`] decides whether a stage still owes an
/// exact reconciliation, so a release keeps a slot whose *carrier* stage is
/// unproven even when its apply stage is fully verified, which is what lets the
/// later carrier readback still find that obligation; and the canonical apply
/// stage decides whether this operation still owes a write, so a release also
/// keeps a slot whose apply stage is [`RestoreEffectState::NoWriteSubmitted`]
/// beside any stage that was submitted. That stage owes a write nobody has
/// performed yet and it is not unproven, so the pair-only question would collect
/// the evidence of a carrier publication that was already proved — unless
/// nothing was ever submitted, which is the one state that owes nothing.
struct RestoreAttemptGuard {
    /// Owner-scoped slot key, derived once so release never formats anything.
    key: String,
    /// The exact incarnation this guard owns.
    incarnation: u64,
    /// Operation identity this incarnation was admitted for; used only to type a
    /// conservative bookkeeping failure.
    operation_id: String,
    /// Effect exposure of this invocation beside the slot's inherited
    /// uncertainty, kept per provider-write stage.
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
    /// forward is the effect exposure of each provider-write stage, which keeps
    /// the fresh-write branch of that stage closed until its exact durable result
    /// resolves it.
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
        // failure and both retained per-stage effect exposures survive the new
        // attempt, and the map does not grow. Only a slot that is not tracked yet
        // competes for the bounded capacity.
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
        let (first_failure, effect_state) = retained.unwrap_or((None, RestoreStageExposure::NONE));
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
    /// exposure into the slot, per stage. The slot is evicted only when no stage
    /// is left to reconcile; an uncertain stage keeps its slot and its recovery
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
            .merged(ledger.attempts[&self.key].effect_state);
        if outcome.is_none()
            && !merged.any_unproven()
            && (merged.apply == RestoreEffectState::DurableResultVerified
                || matches!(
                    (merged.carrier, merged.apply),
                    (
                        RestoreEffectState::NoWriteSubmitted,
                        RestoreEffectState::NoWriteSubmitted
                    )
                ))
        {
            // Nothing is owed any more, so the bounded evidence leaves the map
            // instead of accumulating in it. Two states reach that answer, and
            // both are asked per stage rather than over the pair. A proven apply
            // answers it because "no stage is unproven" is a different question:
            // `NoWriteSubmitted` is not unproven, so an apply that has not
            // started at all reads as answered there, and a slot whose carrier
            // publication is proved while its apply is still owed must survive
            // this release. Collected as if it owed nothing, the next exact
            // invocation of the same identity finds no evidence of that
            // publication and issues a second carrier transaction. A slot on
            // which nothing was ever submitted answers it too, and the original
            // pair-only test was already right about that one: no stage is
            // unproven, the apply stage was never entered, and the only thing
            // such an entry carries that a fresh invocation would not re-derive
            // is a first failure recorded by an earlier incarnation, which this
            // release discards with the entry. Retaining it would spend a
            // slot of a bounded map on
            // an identity that wrote nothing and would let the ceiling be reached
            // by the cheapest possible schedule — acquire and drop, once per
            // slot — which is a worse failure mode than the one this conjunct
            // exists to close. A recorded outcome also retains every state, so
            // with no outcome recorded a slot is retained exactly when a
            // reconciliation is open, or when the apply stage has not reached
            // `DurableResultVerified` and something was actually submitted.
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
    /// running owner and merges this incarnation's per-stage exposure into the
    /// slot, so an effect that may already have been submitted stays uncertain
    /// and keeps its exact-reconciliation obligation on that stage alone.
    /// Unreadable bookkeeping keeps the slot untouched rather than reporting a
    /// cleanup that never happened.
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
/// The key is derived here from the same four components
/// [`RestoreAttemptGuard::acquire`] binds, so a reader can never observe a
/// different slot than the writer owns.
///
/// An unreadable map is a typed conservative failure, never an absent attempt:
/// reporting "no original failure" from an unreadable map would turn unknown
/// bookkeeping into a clean answer.
fn restore_attempt_state(
    batch: &CanonicalRestoreBatch,
    config: &SurrealAdapterConfig,
) -> Result<Option<RestoreAttemptState>, StoreError> {
    let (active_store, active_installation) = active_store_identity(config);
    let key = attempt_slot_key_from_components(
        &active_store,
        &active_installation,
        batch.destination.destination_id.as_str(),
        batch.operation.operation_id.as_str(),
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

/// Projects one provider-derived canonical-apply state into the owner-scoped
/// attempt slot it belongs to.
///
/// This is the only path that may discharge a stage obligation from outside the
/// attempt itself, and it is fed exclusively by exact provider evidence: the
/// durable restore record read back under the reconciled operation identity. The
/// in-process receipt cache is never a source for it — that cache is destroyed on
/// restart and is validated only against the caller's own claims, so setting a
/// verified state from it would assert a durability this process never observed.
///
/// No incarnation check applies, and none is needed: the projection lock is taken
/// once, never held across a provider await, and only the apply stage named by
/// the provider evidence is raised — the carrier stage keeps whatever certainty
/// it already had, because a committed canonical import proves nothing about the
/// carrier rows. The maximum is taken inside the stage, so this can raise a
/// stage's certainty from provider evidence but never lower it. An untracked slot
/// is a no-op: reconciliation may legitimately run for an operation this process
/// never attempted. The map is never cleared and no entry is evicted here.
///
/// **Known limit: this function can only RAISE the apply stage, never lower it.**
/// Its only input is a durable restore record read back under the reconciled
/// operation identity, so an *absent* final record carries no argument at all
/// about whether the apply transport was entered. The issue's repair item asks
/// that "absent final record plus proof the apply transport was never entered"
/// leave apply at [`RestoreEffectState::NoWriteSubmitted`]; that lowering is
/// deliberately **not** implemented, and the reason is a missing evidence class
/// rather than a missing branch:
///
/// * the only record of transport entry is the pre-poll mark
///   [`RestoreEffectExposure::note_write_may_be_submitted`], raised by
///   [`execute_restore_write`] immediately before the effectful poll;
/// * that mark lives on the guard's per-incarnation, in-process exposure.
///   [`RestoreAttemptGuard::release`] merges the per-stage maximum into the slot,
///   so the uncertainty survives *in memory* across a drop — but the slot is
///   process-local, is per operation identity, and is destroyed on restart, and no
///   durable artefact anywhere records "this incarnation handed an apply write
///   to the transport".
/// * the durable restore record itself cannot supply the missing proof, because it
///   is create-only inside the very transaction whose commit is in question: it is
///   present exactly when the write committed and absent both when the write did
///   not commit *and* when no write was ever built. Absence is therefore not
///   evidence of non-entry, and there is no other provider-side surface that
///   distinguishes the two.
///
/// Consequently an absent record leaves the apply stage exactly as this process
/// last observed it. Inventing a durable transport-entry marker to enable the
/// lowering would add an unproven write path to the canonical transaction, which
/// is forbidden; the item is therefore carried as a documented limit of this
/// projection rather than a silent gap. Any future implementation must first name
/// the evidence it will trust and show it cannot be forged by an aborted
/// transaction.
fn project_provider_apply_state(
    key: &str,
    operation_id: &str,
    provider_state: RestoreEffectState,
) -> Result<(), StoreError> {
    let mut ledger = shared_restore_ledger()
        .lock()
        .map_err(|_| unknown_outcome(operation_id))?;
    let Some(attempt) = ledger.attempts.get_mut(key) else {
        return Ok(());
    };
    attempt.effect_state.apply = attempt.effect_state.apply.max(provider_state);
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
/// incarnation, if any, and `stage` names which of the two provider-write stages
/// this write belongs to so the mark lands on that stage alone — a carrier
/// publication is never recorded against the canonical apply, or the reverse.
/// `None` for both means the caller owns no attempt incarnation and therefore
/// records no exposure; destination preparation takes that pair because it
/// commits no admitted restore batch. The "may have been submitted" mark is set
/// on the last synchronous line before the transport poll — after the closed
/// registry and statement have been resolved, so a refusal that never reaches the
/// wire is not reported as a possible commit.
async fn execute_restore_write(
    transport: &RpcTransport,
    operation: &'static str,
    statement: String,
    bindings: serde_json::Map<String, serde_json::Value>,
    stage: Option<RestoreWriteStage>,
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
    let mut response = match (stage, exposure) {
        (Some(stage), Some(exposure)) => {
            exposure.note_write_may_be_submitted(stage);
            let response = transport.query_write(operation, &statement, bindings).await;
            if response.is_ok() {
                exposure.note_response_observed(stage);
            }
            response
        }
        _ => transport.query_write(operation, &statement, bindings).await,
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

/// Verdict of one bounded exact carrier readback.
///
/// This is a verification verdict, not a member disposition: it answers only
/// whether the carrier rows this operation publishes are durably present and
/// exactly equal to what it would publish.
enum CarrierVerification {
    /// Every published row was found and equals the intended carrier exactly.
    Verified,
    /// At least one published row was absent. Publication is one create-only
    /// transaction over the whole bounded set, so an absent row is the only
    /// evidence this readback can obtain about that transaction. Absence is not
    /// by itself proof of non-commit: the issue records that "a missing row
    /// observed while the old transaction may still be running is insufficient",
    /// so what this variant authorises is the bounded readback, never an
    /// independent claim that nothing committed. See
    /// [`verify_archive_member_carriers`] for the per-call evidence.
    NotApplied,
}

/// Builds the exact carrier row set this operation publishes for one batch.
///
/// Nothing is written here. The set is the single comparison basis both for the
/// publication itself and for the exact readback that proves whether the rows
/// this operation published are durably present, so a verification can never
/// compare against a second, weaker expectation. Its byte accounting is the
/// publication's own, which is why a skipped publication still charges exactly
/// the bytes the destination already received.
///
/// The rationale for the two exclusions — a reference edge is never a payload of
/// its own, and an importable member that retained none is refused typed before
/// any write — belongs to the publication; see
/// [`publish_archive_member_carriers`].
fn intended_archive_member_carriers(
    batch: &CanonicalRestoreBatch,
    state_fence: &StateFence,
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
    Ok(published)
}

/// Reads back the carrier rows this operation publishes and requires every row it
/// reads to be present and exactly equal to the intended carrier.
///
/// The readback is bounded by the batch itself: it visits only the non-reference
/// members this operation would publish, whose count the admission already capped
/// at [`MAX_RESTORE_BATCH_MEMBERS`] in `validate_restore_batch`. No new cap is
/// introduced, and the loop *is* fail-fast: it stops at the first row that is
/// absent or divergent, so the rows after it are never read. That early stop is
/// fail-closed, not unsound — the caller raises the carrier stage only on
/// [`CarrierVerification::Verified`], so a stopped readback leaves the stage
/// unproven and still owed, and is never reported as a verified prefix.
///
/// Every row it reads must be present *and* equal. Presence alone is not proof (a
/// row under this operation's key is only this operation's evidence when its
/// content matches), and the comparison is the whole carrier value — payload,
/// payload digest, declared byte count, class and destination address included,
/// not only the identity facts [`read_archive_member`] already enforces. The
/// *first* row that is absent or divergent decides the whole verdict: a row
/// present under this operation's key carrying different content is an identity
/// conflict, and a row that is absent yields [`CarrierVerification::NotApplied`].
/// Because the loop returns on that first row, the two answers are mutually
/// exclusive per batch — an absent row at position *i* is reported as
/// `NotApplied` even when a divergent row sits later at *j > i*, and a divergent
/// row at *i* is reported as a conflict even when an absent row sits later — and
/// whichever verdict a batch gets, the stage is not marked verified.
///
/// `NotApplied` reports the one thing this bounded readback actually observed: no
/// row of the create-only publication is durably present at this operation
/// identity right now. It is deliberately *not* phrased as proof that the
/// transaction did not commit, because the issue is explicit that "a missing row
/// observed while the old transaction may still be running is insufficient"
/// (issue #2666, implementation item 4). What an absence authorises is bounded by
/// the card clause quoted at the republication site in
/// [`SurrealStoreAdapter::apply_canonical_batch`]; what it never authorises is a
/// blind second effect of the other stage, and a divergent row is never read as an
/// absence.
async fn verify_archive_member_carriers(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    batch: &CanonicalRestoreBatch,
    published: &[PublishedCarrier],
) -> Result<CarrierVerification, StoreError> {
    for entry in published {
        let Some(existing) = read_archive_member(transport, config, batch, &entry.member).await?
        else {
            return Ok(CarrierVerification::NotApplied);
        };
        if existing != entry.carrier {
            return Err(StoreError::IdentityConflict);
        }
    }
    Ok(CarrierVerification::Verified)
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
/// Publication is create-only, and a publication is *reported* only after it has
/// been read back: every row this transaction wrote is verified present and
/// exactly equal to the intended carrier before `Ok(published)` is returned, so a
/// lost or partially applied publication is a typed unresolved failure rather
/// than a success the resolution step would then discover on its own. A duplicate
/// is resolved by the same exact readback of this operation's own rows, so an
/// exact replay of the same operation continues while a row carrying different
/// content under this operation's key is an identity conflict.
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
    let published = intended_archive_member_carriers(batch, state_fence)?;
    if published.is_empty() {
        return Ok(published);
    }
    check_cumulative_bytes(cumulative_bytes, carrier_payload_bytes(&published)?)?;
    let bindings = carrier_bindings(&published)?;
    let verification = match execute_restore_write(
        transport,
        crate::client::RESTORE_OPERATION_CARRIER_PUBLISH,
        crate::client::restore_carrier_statement(published.len()),
        bindings,
        Some(RestoreWriteStage::CarrierPublication),
        Some(&mut *exposure),
    )
    .await
    {
        Ok(()) => verify_archive_member_carriers(transport, config, batch, &published).await?,
        Err(StoreError::IdentityConflict) => {
            // A row already exists under this operation's own key. It is a
            // replay only when it carries exactly what this operation
            // publishes; anything else is content this operation does not own.
            verify_archive_member_carriers(transport, config, batch, &published).await?
        }
        Err(error) => {
            // `carrier_stage` is the merged exposure for this slot, so this guard
            // reads the inherited stage as well as this invocation's own. In the
            // fresh case — a refusal raised before the transport poll, so this
            // invocation never reached the wire, with no earlier incarnation
            // leaving the stage unproven either — the merged stage is not
            // unproven, the refusal is not an ambiguous external effect, and the
            // typed refusal is returned unchanged. In the inherited case an
            // earlier incarnation of this slot did leave the carrier stage
            // unproven, and that standing obligation to reconcile outranks this
            // invocation's pre-poll refusal: the typed refusal is then not the
            // answer at all, and the bounded readback below decides it.
            if !exposure.carrier_stage().is_unproven() {
                return Err(error);
            }
            // The publication was handed to the provider and did not answer, so
            // the carrier stage is an unknown *external* effect in its own right
            // and a clean retryable refusal would misreport it. The exact carrier
            // rows under this operation identity are the only authority on
            // whether the create-only transaction committed, and they are read
            // here rather than assumed. This is the same bounded readback the
            // successful and duplicate arms use; no other provider call is made.
            return match verify_archive_member_carriers(transport, config, batch, &published)
                .await?
            {
                CarrierVerification::Verified => {
                    // It did commit: the rows this operation publishes are
                    // durably present and exactly equal, so the stage is raised
                    // here and nowhere else.
                    exposure.note_carrier_verified();
                    Ok(published)
                }
                CarrierVerification::NotApplied => {
                    // It did not commit. The stage stays unproven, no second
                    // publication is started, and no success is reported: the
                    // obligation is preserved for exact resolution by operation
                    // identity, and the answer is the typed unknown outcome
                    // rather than the transport-level refusal that reached this
                    // arm.
                    Err(unknown_outcome(batch.operation.operation_id.as_str()))
                }
            };
        }
    };
    match verification {
        CarrierVerification::Verified => {
            // The only site that may mark the carrier stage verified: the bounded
            // exact readback above returned full identity and content agreement
            // for every row this operation published. An empty published set is
            // not verification — it means there was nothing to publish.
            exposure.note_carrier_verified();
            Ok(published)
        }
        CarrierVerification::NotApplied => Err(StoreError::MissingReceiptEnvelope),
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
///
/// The owner's two attested facts about its own bytes are discharged *here*,
/// against the original recorded payload, before the payload is parsed into a
/// carrier: the declared length must be the actual length of the payload the
/// owner recorded, and the declared digest must validate exactly those bytes.
/// Nothing is recomputed over a locally re-derived encoding to satisfy them, so
/// the digest the carrier carries and the resolution step re-proves is a proof
/// about the owner's own record rather than a checksum of whatever this port
/// happened to decode. The resolution step's separate check then re-proves that
/// same attested value against the canonical encoding of the payload it holds,
/// which is the encoding the destination will serve back.
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
    // The owner's recorded length and digest describe exactly the payload string
    // it retained. Both are compared with those bytes rather than with a
    // re-encoding of them, so a reference whose own attestation does not hold is
    // refused here, typed, before any carrier row is published.
    if u64::try_from(retained.payload.len()).ok() != Some(retained.byte_count) {
        return Err(StoreError::InvalidField {
            field: "restore.retained_member_byte_count",
            reason: "retained payload length does not match the owner-recorded length",
        });
    }
    if sha256_hex(retained.payload.as_bytes()) != retained.payload_digest {
        return Err(StoreError::InvalidField {
            field: "restore.retained_member_payload_digest",
            reason: "retained payload does not match the owner-attested digest",
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
/// The bookkeeping facts stay independent here, and the stage separation is what
/// keeps them independent. An older pre-effect refusal may still be reported as
/// the reason the operation first failed, but it never stands in for the current
/// effect certainty: while *either* stage still owes an exact provider
/// reconciliation, the cancellation answer is the typed unknown outcome, and the
/// first failure is preserved beside it rather than overwritten by it.
///
/// The carrier-publication stage is an **external effect in its own right**, and
/// is therefore part of this answer, not an exception to it: I5.27 keeps database
/// idempotency and external-effect idempotency separate, so a carrier publication
/// that may already have committed is *not* covered by a verified apply. I5.19
/// says that if any canonical or external effect is unknown the operation remains
/// `UNKNOWN_OUTCOME`/`RECONCILING` and only dependent scopes pause; I14.21 says an
/// unknown outcome pauses the Ordering Scope, preserves the operation, and opens
/// Problem State with no blind duplicate effect. A cancellation is exactly the
/// moment where no blind duplicate effect may follow, so both stages are consulted
/// through [`RestoreStageExposure::any_unproven`].
///
/// Dropping the carrier stage from this predicate would not merely widen the
/// answer — it would downgrade an unknown *external* effect to a clean refusal
/// (the preserved original failure, or [`StoreError::Unavailable`]), which is the
/// weakening the repair list forbids: none of the repairs changes cancellation
/// semantics, and "preserve what is already correct" means `unknown_outcome` on
/// cancellation stays `unknown_outcome` on cancellation.
///
/// The retained slot is a separate property and not a substitute for this answer:
/// [`RestoreAttemptGuard::release`] merges this incarnation's per-stage exposure
/// into the slot and evicts it only when
/// [`RestoreStageExposure::any_unproven`] is false *and* either the canonical
/// apply stage has reached [`RestoreEffectState::DurableResultVerified`] or
/// nothing was ever submitted, so an unproven carrier stage, and an apply nobody
/// has performed yet beside a submitted carrier stage, keep the slot retained
/// rather than letting the evidence be collected, and
/// [`SurrealStoreAdapter::resolve_carrier_stage`] later performs the bounded exact
/// per-row carrier readback before any new provider write. That is why the carrier
/// obligation is not *lost*; it is not why it may be reported as absent here.
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
        .is_some_and(|state| state.effect_state.any_unproven())
    {
        return Err(unknown_outcome(batch.operation.operation_id.as_str()));
    }
    if let Some(original) = state.and_then(|state| state.original_failure()) {
        return Err(original);
    }
    Err(StoreError::Unavailable)
}

/// Reports whether deciding this operation's carrier stage requires reading this
/// batch's own carrier rows back before anything may be published or skipped.
///
/// It is the whole of the branch decision
/// [`SurrealStoreAdapter::resolve_carrier_stage`] makes before it reads anything,
/// hoisted out so that decision is executable without a live provider, in the
/// same shape and for the same reason as
/// [`purge_disposition_blocks_on_unproven_carrier`]. It has exactly one production
/// caller, [`SurrealStoreAdapter::resolve_carrier_stage`].
///
/// `true` for every stage except [`RestoreEffectState::NoWriteSubmitted`]:
///
/// * a stage that submitted no carrier write carries no obligation at all, so the
///   caller reaches the publication, which reads its own rows back exactly before
///   it reports anything;
/// * a stage marked unproven owes an exact reconciliation; and
/// * a stage this slot already carries as
///   [`RestoreEffectState::DurableResultVerified`] owes one too, because it was
///   proved for the intended set of whichever invocation proved it and the slot
///   key does not bind `canonical_request_hash` — see
///   [`SurrealStoreAdapter::resolve_carrier_stage`], which states the schedule.
///
/// A stage that is neither unproven nor proved is therefore answered by the
/// readback rather than by a shortcut, which is the fail-closed direction: a state
/// added to [`RestoreEffectState`] later is reconciled, not believed.
fn carrier_stage_requires_readback(exposure: RestoreEffectExposure) -> bool {
    exposure.carrier_stage() != RestoreEffectState::NoWriteSubmitted
}

/// Reports whether a purge disposition that publishes no carrier row must first
/// reconcile the carrier stage its slot still owes, before this operation may
/// proceed at all.
///
/// `scope_disposition` is what [`decide_purge`] decided from the *current*
/// purge-ledger readback, and that readback happens on every invocation, so one
/// operation identity can reach the canonical apply under a disposition that is
/// not [`MemberDisposition::Restored`] even though an earlier incarnation of the
/// same slot left the carrier publication unproven. `Restored` answers `false`
/// here, because that disposition reaches
/// [`SurrealStoreAdapter::resolve_carrier_stage`], which decides the carrier
/// stage by bounded exact carrier readback and, on an absent row, authorises the
/// same-identity carrier retry the card names.
///
/// Every other disposition publishes no carrier row *of its own*, so this
/// invocation makes no carrier write whose outcome it could be waiting for. That
/// is not the same as the standing obligation being undecidable: the write an
/// earlier incarnation of this same identity handed to the provider is still
/// settled by this operation's own rows, and reading them back is a read, not a
/// second effect. So this predicate is the card clause
/// "carrier unknown -> block only until carrier reconciliation" read as a gate on
/// reconciliation rather than as a permanent refusal, and
/// [`carrier_publication_for`] is where that reconciliation is attempted before
/// anything refuses. The refusal that survives it is exactly
/// `unknown_outcome(operation_id)`: the value [`publish_archive_member_carriers`]'s
/// **refusal arm** returns for `CarrierVerification::NotApplied` — the arm reached
/// when the write was handed to the transport and did not answer — and the value
/// [`check_cancellation`] returns while either stage owes a reconciliation. It is
/// not the value of that function's **final** `CarrierVerification::NotApplied`
/// arm, which answers [`StoreError::MissingReceiptEnvelope`]; the two arms are
/// named separately here so no reader merges them into one claim of equivalence.
/// Inherited uncertainty is never reset by an invocation that has not written:
/// the reconciliation can raise the stage only on its own exact readback, and a
/// verdict that proves nothing leaves it precisely where it was.
///
/// Every other decision is preserved: the purge reading, the disposition
/// mapping and the commit below are untouched, nothing is published and nothing
/// is written, and the refusal is the same typed value the carrier
/// publication's refusal arm already returns for an unproven write.
///
/// The exits are exactly these four, and there is no fifth:
///
/// 1. the bounded exact carrier readback over this operation's own rows proves
///    every one of them, which discharges the stage through the existing
///    [`RestoreEffectExposure::note_carrier_verified`] and lets this identity
///    proceed;
/// 2. that same readback finds an absent row — [`CarrierVerification::NotApplied`]
///    — which answers `unknown_outcome` and leaves the stage unproven and owed;
/// 3. that same readback finds a divergent row, which is the existing typed
///    [`StoreError::IdentityConflict`] that readback already returns; and
/// 4. a later invocation of the same identity reads a disposition whose subject
///    may be served again — a cleared ledger decides
///    [`MemberDisposition::Restored`], which reaches
///    [`SurrealStoreAdapter::resolve_carrier_stage`]; and its bounded exact
///    carrier readback, when it proves the carriers, discharges the stage and
///    authorises the same-identity carrier retry.
///
/// Exit 1 is bounded by the same thing every other exit is: the rows are read
/// back under this operation's own key, so a subject the current ledger keeps out
/// of the destination is proved only by rows this operation itself published.
/// Nothing here claims that an obligation always clears — a subject that must
/// never become servable again has no row to prove and no row to publish, so for
/// it the readback answers [`CarrierVerification::NotApplied`] every time and the
/// refusal stands until the ledger changes. The block stops the operation from
/// committing; it does not promise that the obligation ever clears on its own.
///
/// In particular [`SurrealStoreAdapter::reconcile_operation`] is **not** one of
/// the exits, and it is named here so the next reader does not assume otherwise.
/// It refreshes the slot from a durable record for the same identity, and the
/// only field it can move is `attempt.effect_state.apply`, raised by
/// [`project_provider_apply_state`] — whose entire body is one
/// `attempt.effect_state.apply = attempt.effect_state.apply.max(provider_state)`
/// assignment plus the lock and the missing-attempt early return. There is no
/// carrier projection there or anywhere else: the carrier stage is raised only
/// by [`RestoreEffectExposure::note_carrier_verified`], and it has exactly four
/// production call sites — two inside [`publish_archive_member_carriers`], which
/// raises it on the `Verified` verdict its refusal arm receives and again on the
/// `Verified` verdict its success/duplicate arm receives; one in
/// [`SurrealStoreAdapter::resolve_carrier_stage`], on the `Verified` verdict of
/// this invocation's own readback of its own intended set; and one in
/// [`carrier_publication_after_reconciliation`], which is *not* itself a readback
/// but the verdict-to-answer mapping the readback inside
/// [`carrier_publication_for`] feeds. A committed canonical import
/// is not evidence that the carrier publication happened exactly once, so
/// [`project_provider_apply_state`] cannot answer this predicate.
fn purge_disposition_blocks_on_unproven_carrier(
    scope_disposition: MemberDisposition,
    exposure: RestoreEffectExposure,
) -> bool {
    scope_disposition != MemberDisposition::Restored && exposure.carrier_stage().is_unproven()
}

/// Decides the published carrier set for the disposition that publishes no
/// carrier row of its own.
///
/// This is the whole non-`Restored` arm of the `let published` decision in
/// [`SurrealStoreAdapter::apply_canonical_batch`], hoisted out so that decision
/// is reachable from one place. It has exactly one production caller,
/// [`SurrealStoreAdapter::apply_canonical_batch`], and it does three things:
///
/// - it asks the one closed predicate
///   [`purge_disposition_blocks_on_unproven_carrier`], unchanged;
/// - when that predicate answers "blocks", it *attempts the reconciliation* the
///   card clause requires — "carrier unknown -> block only until carrier
///   reconciliation" is honoured by trying, not by skipping — and the readback's
///   own verdict decides, through
///   [`carrier_publication_after_reconciliation`]. No new error variant and no new
///   reason string is introduced here, and the refusal that survives is exactly
///   `unknown_outcome(operation_id)`: the value
///   [`publish_archive_member_carriers`]'s **refusal arm** returns for
///   `CarrierVerification::NotApplied` — the arm reached when the write was handed
///   to the transport and did not answer — and the value [`check_cancellation`]
///   returns while either stage owes a reconciliation. It is deliberately *not* the
///   value of that function's **final** `CarrierVerification::NotApplied` arm,
///   which answers [`StoreError::MissingReceiptEnvelope`]; the two arms are named
///   here rather than merged into one claim of equivalence;
/// - otherwise it returns an empty published set, because a disposition other
///   than [`MemberDisposition::Restored`] has no carrier row to publish.
///
/// The reconciliation is the production one, used unchanged.
/// [`intended_archive_member_carriers`] derives the intended set from the
/// admitted batch alone — the members, their retained references and the state
/// fence, no write and no provider call — and
/// [`verify_archive_member_carriers`] reads that set back through
/// [`read_archive_member`], whose fixed label
/// [`crate::client::RESTORE_OPERATION_ARCHIVE_MEMBERS`] is already one of the
/// entries `crate::client::validate_restore_operation` admits through the closed
/// `crate::client::RESTORE_PROVIDER_OBSERVATIONS` slice, so this arm needs no new
/// pinned write, no new operation vocabulary entry and no card amendment. The
/// readback is bounded by the same [`MAX_RESTORE_BATCH_MEMBERS`] members the
/// admission already capped, and it performs no provider write of any kind.
///
/// An intended set this operation cannot express, or an empty one, is not
/// verification, and on this branch both are answered with the same typed
/// unknown outcome — never with the stage raised on no evidence, and never with
/// the input diagnosis [`intended_archive_member_carriers`] would give on its own.
/// [`publish_archive_member_carriers`] already refuses to read an empty published
/// set as a proved stage ("there was nothing to publish"), and the reason both
/// cases refuse is the one spelled out at this branch's body: reaching it already
/// means an earlier incarnation's carrier write is unproven.
async fn carrier_publication_for(
    transport: &RpcTransport,
    config: &SurrealAdapterConfig,
    batch: &CanonicalRestoreBatch,
    state_fence: &StateFence,
    scope_disposition: MemberDisposition,
    exposure: &mut RestoreEffectExposure,
) -> Result<Vec<PublishedCarrier>, StoreError> {
    if !purge_disposition_blocks_on_unproven_carrier(scope_disposition, *exposure) {
        return Ok(Vec::new());
    }
    let operation_id = batch.operation.operation_id.as_str();
    // The reconciliation signal dominates the input diagnosis here, and it does so
    // unconditionally rather than by preference. This line is reachable only
    // after `purge_disposition_blocks_on_unproven_carrier` has answered true, and
    // that predicate is true only for an *unproven* carrier stage — which on this
    // arm means an EARLIER incarnation of this same identity is waiting on a
    // carrier write whose outcome is exactly unknown. The caller is therefore
    // being told "your JSON is malformed" when the fact that governs it is
    // "reconcile me", and the carrier stage is unproven by construction on every
    // single traversal of this branch.
    //
    // Collapsing the two onto one error loses that. The malformed input is
    // deterministic, so a later invocation re-refuses it identically once the
    // stage is discharged; answering `InvalidField` now instead invites a
    // corrected retry that meets the same unproven stage, and the operator reads
    // the correction as insufficient rather than as not yet reconcilable. The
    // unknown outcome carries the operation identity, so the reconciliation
    // reference survives the refusal.
    //
    // This is deliberately NOT what [`SurrealStoreAdapter::resolve_carrier_stage`]
    // does with the same builder, and the asymmetry is not an oversight. That arm
    // is reached for a `Restored` disposition, where no inherited-unknown carrier
    // write is in question, so its `?` propagates the typed
    // [`StoreError::InvalidField`] unchanged and the caller learns what is wrong
    // with the batch. Do not "fix" that one to match this one.
    //
    // Either way the stage is not raised and the obligation stays in the slot:
    // nothing below this line has written, and `release` keeps the slot retained
    // for as long as either stage is unproven.
    let Ok(intended) = intended_archive_member_carriers(batch, state_fence) else {
        return Err(unknown_outcome(operation_id));
    };
    if intended.is_empty() {
        return Err(unknown_outcome(operation_id));
    }
    // The readback's verdicts are its own: a divergent row arrives here as the
    // typed `IdentityConflict` `verify_archive_member_carriers` already returns,
    // and never as an absence.
    let verification = verify_archive_member_carriers(transport, config, batch, &intended).await?;
    carrier_publication_after_reconciliation(&verification, exposure, operation_id)
}

/// Turns one carrier reconciliation verdict into this arm's answer.
///
/// Provider-free and total over [`CarrierVerification`]'s two variants, so the
/// half of the arm's decision that follows the readback stays executable without
/// a provider, while the read that produces the verdict stays exactly the
/// production one. It has exactly one production caller,
/// [`carrier_publication_for`].
///
/// A proved set raises the stage through the same
/// [`RestoreEffectExposure::note_carrier_verified`] every other carrier readback
/// uses and then returns an empty published set: this member's payload is purged,
/// so nothing is published — which is the rule [`publish_archive_member_carriers`]
/// states for a member the current purge ledger keeps out of the destination,
/// because it is never imported either.
///
/// An absent row is not a licence to write: the stage stays unproven, no second
/// publication is started, no success is reported, and the answer is the typed
/// unknown outcome rather than the transport-level refusal that reached this
/// arm.
///
/// `operation_id` is a parameter rather than read from the exposure because the
/// exposure carries no identity: it is a pair of stages and nothing else.
fn carrier_publication_after_reconciliation(
    verification: &CarrierVerification,
    exposure: &mut RestoreEffectExposure,
    operation_id: &str,
) -> Result<Vec<PublishedCarrier>, StoreError> {
    match verification {
        CarrierVerification::Verified => {
            exposure.note_carrier_verified();
            Ok(Vec::new())
        }
        CarrierVerification::NotApplied => Err(unknown_outcome(operation_id)),
    }
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
            // no attempt incarnation and belongs to neither of this operation's
            // two write stages: there is no local bookkeeping obligation to
            // carry, and its own write is create-only and reconciled by readback
            // below.
            None,
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
    ///
    /// A record that *was* found is also the only competent evidence that may
    /// refresh the owner-scoped attempt slot: the canonical-apply stage of that
    /// identity is verified from the durable record this process just read, and
    /// the slot is refreshed incarnation-independently, because an obligation
    /// belongs to the identity rather than to the attempt that incurred it. The
    /// carrier stage is not touched by it — a committed canonical import is not
    /// evidence that the carrier publication happened exactly once — and the
    /// in-process receipt cache is never used to discharge either stage.
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
            // The durable record binds the destination owner and the admitted
            // operation identity, which are exactly the components the slot key
            // is derived from.
            let (active_store, active_installation) = active_store_identity(&self.config);
            let key = attempt_slot_key_from_components(
                &active_store,
                &active_installation,
                &document.destination_id,
                &operation_key,
            );
            project_provider_apply_state(
                &key,
                &operation_key,
                RestoreEffectState::DurableResultVerified,
            )?;
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

    /// Decides the archive-member carrier-publication stage of this operation.
    ///
    /// Returns the exact carrier set this operation would publish, and `Some` of
    /// it when there is no carrier work left for the caller to own: either the
    /// batch has nothing to publish, or *this invocation's own* bounded exact
    /// readback just proved every row of its own intended set. `None` means the
    /// caller still owns the publication.
    ///
    /// `Some` is a claim about work *owed*, not about durability. The empty
    /// branch returns after zero provider reads and raises nothing, and the
    /// readback branch is this invocation's fresh evidence — about its own rows,
    /// read back under its own key. The
    /// [`RestoreEffectExposure::note_carrier_verified`] call is the only thing
    /// that raises the stage to [`RestoreEffectState::DurableResultVerified`],
    /// and it happens on that readback path alone.
    ///
    /// The stage is decided on its own provider evidence, never on the apply's,
    /// and the branches are taken in exactly this order:
    ///
    /// * an empty published set — a batch with no importable member — carries no
    ///   write, so there is nothing to publish and nothing to owe, and the branch
    ///   raises nothing either;
    /// * a stage that submitted nothing is *not* unproven — it is
    ///   `NoWriteSubmitted`, which carries no obligation — so the closed
    ///   [`carrier_stage_requires_readback`] decision answers `false` before this
    ///   function makes any provider read at all, and the caller reaches the
    ///   publication, which reads its own rows back exactly before it reports
    ///   anything;
    /// * **every other stage is reconciled right here**, by the same bounded exact
    ///   readback the publication itself uses: a stage marked unproven (submitted
    ///   or answered but never proved) *and* an inherited
    ///   [`RestoreEffectState::DurableResultVerified`] alike. Full identity and
    ///   content agreement for every row proves the stage and returns `Some` of
    ///   the set, so the publication is skipped entirely; a divergent row is an
    ///   error and never reaches the publication at all; and an absent row yields
    ///   `None`, so the caller reaches the publication and republishes under that
    ///   same identity. That last verdict is the absence case the issue calls
    ///   insufficient on its own ("a missing row observed while the old
    ///   transaction may still be running is insufficient"), so what it
    ///   authorises here is exactly the card clause quoted at the republication
    ///   site in [`Self::apply_canonical_batch`] — a same-identity carrier retry,
    ///   nothing more, and never a blind second effect of the apply stage.
    ///
    /// An inherited proved stage is re-proved rather than believed, and the reason
    /// is the slot key: [`attempt_slot_key_from_components`] binds the owner
    /// namespace, the destination id and the operation id, and it does **not** bind
    /// `canonical_request_hash`. Two batches that share a destination and an
    /// operation id and differ only in their canonical request hash therefore share
    /// one slot, so a [`RestoreEffectState::DurableResultVerified`] this slot
    /// carries is evidence about the intended set of whichever invocation proved
    /// it — which may not be this one. Believing it would answer for a batch
    /// nobody read: the durable row behind it can be the other request's row, and
    /// [`carrier_answers_for`] compares the ten identity facts it compares
    /// (`class`, `record_id`, `payload` and `payload_digest` are not among them),
    /// so such a row is accepted and the import then takes its class, record id
    /// and payload **from that row** instead of from this request's own retained
    /// members. On the create-only path the same schedule is refused instead: the
    /// publication meets the existing row and answers the typed
    /// [`StoreError::IdentityConflict`].
    ///
    /// So "already verified" is not a shortcut here. Only this invocation's own
    /// readback of its own intended set can answer for this batch, which is what
    /// makes the evidence compared with THIS request rather than with an operation
    /// id several requests may share. Re-proving costs one bounded read of the rows
    /// this batch would publish, whose count admission already capped at
    /// [`MAX_RESTORE_BATCH_MEMBERS`], and it introduces no state, no field, no
    /// digest of the verified set, no extra write and no new typed error: the
    /// verdicts and the divergent-row error are the readback's own.
    async fn resolve_carrier_stage(
        &self,
        transport: &RpcTransport,
        batch: &CanonicalRestoreBatch,
        state_fence: &StateFence,
        exposure: &mut RestoreEffectExposure,
    ) -> Result<Option<Vec<PublishedCarrier>>, StoreError> {
        let published = intended_archive_member_carriers(batch, state_fence)?;
        // An empty intended set is answered here, before any read, and the reason it is
        // safe is NOT that "an empty batch imports nothing" — that was this
        // comment's earlier claim and it named a dependency that was never
        // checked. The real reason is that such a batch is refused outright,
        // further down, before the apply write.
        //
        // An empty intended set is reachable only through an all-`Reference`
        // batch: [`intended_archive_member_carriers`] skips exactly the
        // `SnapshotMemberType::Reference` members and refuses anything else that
        // carries no retained payload, `validate_reference_closure` refuses
        // `member_count == 0` and requires the member list to match it, and this
        // function is reached only after that admission. On the `Restored` arm
        // every `Reference` member is then planned as
        // [`MemberDisposition::Rejected`], and
        // [`validate_reference_closure_against`] requires a `Rejected` edge to
        // land on a member whose disposition is `Restored`. In an all-`Reference`
        // batch no member is `Restored`, so that check answers the typed
        // [`StoreError::IdentityConflict`] — and it runs on the planned
        // dispositions before the apply transaction is composed, so this branch
        // can neither raise a stage nor reach a receipt.
        //
        // Two of the file's three empty-set answers agree with that, and the
        // third is unreachable from production. `publish_archive_member_carriers`
        // states at its own `Verified` arm that an empty published set is not
        // verification, and `carrier_publication_for` refuses rather than raising
        // a stage on one. `publish_archive_member_carriers`' own empty guard
        // cannot be reached either: its single production caller is the `None`
        // arm of this function, and `None` here implies a non-empty intended set.
        //
        // Independently of all that, this branch raises nothing: it does not call
        // `note_carrier_verified`, so an inherited carrier stage stays exactly as
        // it was and keeps its slot retained. `Some` here means "no carrier work
        // is left for the caller", never "the carriers are durable".
        if published.is_empty() {
            return Ok(Some(published));
        }
        // One branch decision, and it is asked before this function reads
        // anything. A stage that submitted no carrier write carries no
        // obligation, so it answers `None` and the caller reaches the
        // publication, which reads its own rows back exactly before it reports
        // anything. Everything else — an unproven stage AND an inherited proved
        // one — goes through this invocation's own bounded exact readback below.
        if !carrier_stage_requires_readback(*exposure) {
            return Ok(None);
        }
        // The empty-intended-set return above precedes this call, so the readback
        // is never reached with an empty set and can never answer `Verified`
        // vacuously. Full identity and content agreement for every row of *this*
        // batch's intended set proves the stage and returns `Some` of the set, so
        // the publication is skipped entirely; a divergent row is the existing
        // typed `StoreError::IdentityConflict` that readback already returns and
        // never reaches the publication at all; and an absent row yields `None`,
        // so the caller reaches the publication and republishes under that same
        // identity. That last verdict is the absence case the issue calls
        // insufficient on its own ("a missing row observed while the old
        // transaction may still be running is insufficient"), so what it
        // authorises here is exactly the card clause quoted at the republication
        // site in [`Self::apply_canonical_batch`] — a same-identity carrier retry,
        // nothing more, and never a blind second effect of the apply stage.
        match verify_archive_member_carriers(transport, &self.config, batch, &published).await? {
            CarrierVerification::Verified => {
                exposure.note_carrier_verified();
                Ok(Some(published))
            }
            CarrierVerification::NotApplied => Ok(None),
        }
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
    /// provider, per provider-write stage. It is local bookkeeping only: it never
    /// decides a verdict, and every returned receipt is still derived from exact
    /// durable readback. The two stages are decided separately — the apply stage
    /// before anything is written here, and the carrier stage immediately before
    /// the publication it governs — so that a stage which *can* be proved never
    /// blocks the other stage, and a stage which cannot never proceeds.
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
            // A pre-existing record read back here is evidence about the
            // canonical-apply stage alone: `resolve_archive_members` was never
            // called on this path, so nothing about the carrier publication was
            // read.
            exposure.note_apply_verified();
            project_verified_receipt(batch, &receipt)?;
            return Ok(receipt);
        }
        // Reacquiring local ownership is not permission to take the fresh-write
        // branch, and the decision is made per provider-write stage. This
        // invocation has submitted nothing, but an earlier incarnation of this
        // same owner-scoped identity may have handed the *canonical apply* to the
        // provider in a way that can still complete, and the absent record row
        // read above is not proof of non-commit. The exact durable record under
        // this operation identity is the only authority, and it has already been
        // read: it is absent, so the apply stage stays unproven and the
        // obligation is reported as the typed unknown outcome and resolved by
        // exact operation identity, never by writing again. The carrier stage is
        // *not* decided here: its own exact readback is what can discharge it, and
        // it is decided below, before the publication it governs.
        if exposure.apply_stage().is_unproven() {
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
            // The carrier stage is decided before the publication it governs,
            // never after it. A proven stage continues on this same operation
            // identity and republishes nothing; an unproven-but-not-submitted
            // stage, and a stage whose exact readback above found no durable row,
            // both publish under that same identity.
            match self
                .resolve_carrier_stage(transport, batch, &ctx.state_fence, exposure)
                .await?
            {
                Some(proven) => proven,
                None => {
                    // GAP 5 of issue #2666 is settled by the card's own MAKE
                    // clause, quoted verbatim from
                    // ROOT-continuation/workstreams/swarm/cards/2666.md:
                    // "carrier unproven → allow a same-identity carrier retry".
                    // The clause — not the absent row alone — is what authorises
                    // this republication, because the issue is explicit that "a
                    // missing row observed while the old transaction may still be
                    // running is insufficient". A late commit of the previous
                    // publication therefore cannot produce a duplicate effect:
                    // a commit that lands after this readback makes this very
                    // transaction answer `IdentityConflict` on its own create-only
                    // key, and the duplicate arm of
                    // [`publish_archive_member_carriers`] resolves that by the
                    // same bounded exact readback - `Verified`, the carrier stage
                    // raised, and the apply continued exactly once, under a retry
                    // that carries the same state fence. The
                    // authorisation is bounded to the carrier stage: the apply
                    // stage keeps its own gate above and is never reopened here.
                    publish_archive_member_carriers(
                        transport,
                        &self.config,
                        batch,
                        &ctx.state_fence,
                        fence.document.cumulative_bytes,
                        &mut *exposure,
                    )
                    .await?
                }
            }
        } else {
            // A disposition that publishes no carrier row of its own also writes
            // none, so nothing below this branch commits canonical data — but the
            // carrier stage an earlier incarnation of this same identity may have
            // left unproven is still owed, and what settles it is this
            // operation's own carrier rows, read back exactly, not an assumption
            // about them. The disposition is re-read on every invocation, so it
            // can differ between two of them for one identity; the slot's carrier
            // stage cannot. This branch therefore performs the bounded exact
            // carrier reconciliation the card clause requires: "carrier unknown ->
            // block only until carrier reconciliation" bounds the refusal to what
            // the readback could not discharge, it does not forbid the readback.
            // Only an absent row, or an intended set with no row in it, still
            // refuses here; a divergent row is the typed conflict that readback
            // already returns.
            //
            // The whole arm is one call to [`carrier_publication_for`], which
            // owns that decision and refuses with the same typed value the
            // publication branch refuses with. It is the *only* production
            // caller of that helper, so this arm cannot grow a second path
            // around it.
            carrier_publication_for(
                transport,
                &self.config,
                batch,
                &ctx.state_fence,
                scope_disposition,
                exposure,
            )
            .await?
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
            Some(RestoreWriteStage::CanonicalApply),
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
                    exposure.note_apply_verified();
                    project_verified_receipt(batch, &receipt)?;
                    return Ok(receipt);
                }
                return Err(StoreError::IdentityConflict);
            }
            Err(error) => {
                // `apply_stage` is the merged exposure for this slot, so this
                // guard reads the inherited stage as well as this invocation's
                // own. In the fresh case — a refusal raised before the transport
                // poll, so this invocation never reached the wire, with no
                // earlier incarnation leaving the stage unproven either — the
                // merged stage is not unproven, the refusal is not an ambiguous
                // commit, and the typed refusal is returned unchanged. In the
                // inherited case an earlier incarnation of this slot did leave
                // the apply stage unproven, and that standing obligation to
                // reconcile outranks this invocation's pre-poll refusal: the
                // typed refusal is then not the answer at all, and the exact
                // record readback below decides it, answering with a
                // re-derived receipt on a verified readback or with the typed
                // unknown outcome otherwise.
                if !exposure.apply_stage().is_unproven() {
                    return Err(error);
                }
                // The write was handed to the provider and did not answer. The
                // exact durable record under this operation identity is the only
                // authority on whether it committed, and it is read here rather
                // than assumed: a present, fully re-bound record is competent
                // evidence the apply committed, and the receipt is derived from
                // that document alone.
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
                    exposure.note_apply_verified();
                    project_verified_receipt(batch, &receipt)?;
                    return Ok(receipt);
                }
                // An absent record is not proof of non-commit. The apply stage
                // stays unproven, no second apply is started, and no success is
                // reported: the obligation is preserved for exact resolution by
                // operation identity.
                return Err(unknown_outcome(batch.operation.operation_id.as_str()));
            }
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
        exposure.note_apply_verified();
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
/// table, its record address and the record document the destination's own
/// canonical read path selects by.
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
        // The record document is the class's own key column beside the admitted
        // logical body, which is the exact shape the canonical write path stores
        // and the exact shape the destination's canonical read paths select and
        // project. Binding `body` alone would create a row the destination
        // cannot read back by its own key, so the readback would report the
        // member unresolved for a row that did commit.
        let mut document = serde_json::Map::new();
        document.insert(
            member.class.key_field().to_owned(),
            serde_json::Value::String(member.record_id.clone()),
        );
        document.insert("body".to_owned(), member.payload.clone());
        bindings.insert(
            format!("restore_class_document{index}"),
            serde_json::Value::Object(document),
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
    use std::num::NonZeroU64;

    use crate::config::{PINNED_SURREALDB_MAJOR, SchemaGeneration};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_store_api::{
        BlobResidency, CONTRACT_VERSION, DestinationClass, OperationId as TestOperationId,
    };
    use secrecy::SecretString;

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

    /// Owner-scoped batch fixture: one destination owner plus one admitted
    /// operation identity, so every case below reaches its own attempt slot and
    /// no two cases can be mistaken for one another.
    fn scoped_batch(destination_id: &str, operation_id: &str) -> CanonicalRestoreBatch {
        let mut destination = test_destination();
        destination.destination_id = destination_id.to_owned();
        CanonicalRestoreBatch {
            contract_version: CONTRACT_VERSION,
            operation: test_operation(operation_id, TEST_HASH_A),
            source: SnapshotSourceIdentity {
                installation_id: "source-installation".to_owned(),
                store_id: "source-store".to_owned(),
                schema: "2.0.0".to_owned(),
                generation: ResourceGeneration::genesis(),
            },
            destination,
            archive_member_digest: TEST_HASH_B.to_owned(),
            target_schema: "2.0.0".to_owned(),
            purge_policy_revision: 3,
            expected_revision_heads: Vec::new(),
            expected_ordering_heads: Vec::new(),
            members: Vec::new(),
            member_count: 0,
            retained_members: Vec::new(),
        }
    }

    /// Adapter-owner fixture. Only `database` and `installation_id` reach the
    /// slot key, so every other field is inert configuration text here; nothing
    /// in these proofs opens a connection.
    fn scoped_config(database: &str, installation_id: &str) -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
            namespace: "eliot".to_owned(),
            database: database.to_owned(),
            username: "provider-user".to_owned(),
            password: SecretString::new("test-secret".into()),
            provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
            provider_bootstrap_password: SecretString::new("bootstrap-fixture-secret".into()),
            provider_bind_address: "127.0.0.1:18000".to_owned(),
            installation_id: installation_id.to_owned(),
            installation_profile: "portable_dev".to_owned(),
            runtime_state_roots_digest: TEST_HASH_A.to_owned(),
            provider_executable_path: "surreal.exe".to_owned(),
            provider_artifact_digest: TEST_HASH_B.to_owned(),
            provider_arguments: Vec::new(),
            store_data_root: "data".to_owned(),
            store_work_root: "work".to_owned(),
            store_temp_root: "tmp".to_owned(),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        }
    }

    /// Serializes the cases that read or write the process-global projection,
    /// so no case can observe another case's slots.
    fn ledger_serial() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        match SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Runs `action` against the shared projection under its lock. An unreadable
    /// projection is reported by the case's own assertions, never silently
    /// turned into an empty one.
    fn with_shared_ledger<R>(action: impl FnOnce(&mut RestoreLedger) -> R) -> R {
        match shared_restore_ledger().lock() {
            Ok(mut ledger) => action(&mut ledger),
            Err(poisoned) => action(&mut poisoned.into_inner()),
        }
    }

    /// Reads one owner-scoped slot back through the production key derivation.
    fn slot_for(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
    ) -> Option<RestoreAttempt> {
        let (active_store, active_installation) = active_store_identity(config);
        let key = attempt_slot_key(
            &active_store,
            &active_installation,
            &batch.destination,
            &batch.operation,
        );
        with_shared_ledger(|ledger| ledger.attempts.get(&key).cloned())
    }

    /// Drops one fixture slot so a case starts from an empty projection.
    fn forget_slot(batch: &CanonicalRestoreBatch, config: &SurrealAdapterConfig) {
        let (active_store, active_installation) = active_store_identity(config);
        let key = attempt_slot_key(
            &active_store,
            &active_installation,
            &batch.destination,
            &batch.operation,
        );
        with_shared_ledger(|ledger| {
            ledger.attempts.remove(&key);
        });
    }

    /// Acquires a guard for one fixture slot.
    fn acquire_guard(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
    ) -> RestoreAttemptGuard {
        match RestoreAttemptGuard::acquire(batch, config) {
            Ok(guard) => guard,
            Err(error) => panic!("a fresh owner-scoped slot must be acquirable: {error:?}"),
        }
    }

    /// Runs one whole attempt — acquire, mark, complete — and returns exactly
    /// what the release left behind in the shared projection.
    fn attempt_then_release(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
        mark: impl FnOnce(&mut RestoreEffectExposure),
        outcome: Option<&StoreError>,
    ) -> Option<RestoreAttempt> {
        forget_slot(batch, config);
        let mut guard = acquire_guard(batch, config);
        mark(&mut guard.exposure);
        assert!(
            guard.complete(outcome).is_ok(),
            "releasing a slot this incarnation still owns must not fail"
        );
        slot_for(batch, config)
    }

    /// Removes exactly the fixture rows a case inserted, so a failing assertion
    /// cannot leave the process-global projection full for the other cases.
    struct SlotCleanup {
        keys: Vec<String>,
    }

    impl Drop for SlotCleanup {
        fn drop(&mut self) {
            with_shared_ledger(|ledger| {
                for key in &self.keys {
                    ledger.attempts.remove(key);
                }
            });
        }
    }

    /// Fills the shared projection up to `MAX_RESTORE_TRACKED_ATTEMPTS` with
    /// inert placeholder slots. The ceiling is a property of the map's length,
    /// so the rows carry no effect exposure and no live owner.
    fn insert_ceiling_filler_slots() -> SlotCleanup {
        let mut keys: Vec<String> = Vec::new();
        with_shared_ledger(|ledger| {
            let mut index = 0usize;
            while ledger.attempts.len() < MAX_RESTORE_TRACKED_ATTEMPTS {
                let key = format!("ceiling-filler-{index}");
                index += 1;
                if ledger.attempts.contains_key(&key) {
                    continue;
                }
                ledger.attempts.insert(
                    key.clone(),
                    RestoreAttempt {
                        phase: RESTORE_PHASE_APPLIED.to_owned(),
                        incarnation: 1,
                        running: false,
                        effect_state: RestoreStageExposure::NONE,
                        first_failure: None,
                    },
                );
                keys.push(key);
            }
        });
        SlotCleanup { keys }
    }

    // WORK_UNIT_CASE: 2666/1 — component-wise merge, never a derived lexicographic max.
    #[test]
    fn stage_merge_keeps_both_maxima_instead_of_absorbing_the_apply_uncertainty() {
        let carrier_verified = RestoreStageExposure {
            carrier: RestoreEffectState::DurableResultVerified,
            apply: RestoreEffectState::NoWriteSubmitted,
        };
        let apply_unknown = RestoreStageExposure {
            carrier: RestoreEffectState::NoWriteSubmitted,
            apply: RestoreEffectState::WriteMayHaveBeenSubmitted,
        };
        // A derived `Ord` over the pair ranks `carrier_verified` above
        // `apply_unknown` on the carrier field alone, so its `max` would answer
        // `carrier_verified` and report "no apply write" for a slot that may
        // already have submitted one.
        let merged = carrier_verified.merged(apply_unknown);
        assert_eq!(
            merged.carrier,
            RestoreEffectState::DurableResultVerified,
            "the verified carrier stage is kept"
        );
        assert_eq!(
            merged.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "the losing side's apply uncertainty must not be absorbed away"
        );
        assert!(
            merged.any_unproven(),
            "an absorbed apply uncertainty would leave the slot looking reconciled"
        );
        let reversed = apply_unknown.merged(carrier_verified);
        assert_eq!(reversed.carrier, RestoreEffectState::DurableResultVerified);
        assert_eq!(
            reversed.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted
        );
    }

    // WORK_UNIT_CASE: 2666/2 — merge is idempotent and never lowers a stage.
    #[test]
    fn stage_merge_is_idempotent_and_never_lowers_a_stage() {
        let uncertain_apply = RestoreStageExposure {
            carrier: RestoreEffectState::NoWriteSubmitted,
            apply: RestoreEffectState::WriteMayHaveBeenSubmitted,
        };
        let answered_carrier = RestoreStageExposure {
            carrier: RestoreEffectState::ResponseObserved,
            apply: RestoreEffectState::NoWriteSubmitted,
        };
        let self_merged = uncertain_apply.merged(uncertain_apply);
        assert_eq!(self_merged.carrier, RestoreEffectState::NoWriteSubmitted);
        assert_eq!(
            self_merged.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted
        );

        let raised = uncertain_apply.merged(answered_carrier);
        assert_eq!(raised.carrier, RestoreEffectState::ResponseObserved);
        assert_eq!(raised.apply, RestoreEffectState::WriteMayHaveBeenSubmitted);
        assert!(raised.carrier >= uncertain_apply.carrier);
        assert!(raised.apply >= uncertain_apply.apply);
        assert!(raised.carrier >= answered_carrier.carrier);
        assert!(raised.apply >= answered_carrier.apply);

        // Re-merging the same or a lower observation is a no-op: a merge that
        // overwrote instead of took the maximum, or that flipped the fields,
        // would move one of these.
        let with_answer_again = raised.merged(answered_carrier);
        assert_eq!(with_answer_again.carrier, raised.carrier);
        assert_eq!(with_answer_again.apply, raised.apply);
        let with_self_again = raised.merged(raised);
        assert_eq!(with_self_again.carrier, raised.carrier);
        assert_eq!(with_self_again.apply, raised.apply);
        let with_weaker = raised.merged(uncertain_apply);
        assert_eq!(with_weaker.carrier, raised.carrier);
        assert_eq!(with_weaker.apply, raised.apply);

        stage_order_anchor_is_least_to_most_uncertainty();
    }

    /// Half of case 2: the exhaustive absolute anchor for the variant order.
    ///
    /// Every expected value below is a literal enum variant spelled out from the
    /// documented meaning of its state, and none of them is computed with `Ord`,
    /// `max`, `min` or a comparison. Production `merged` consumes that very same
    /// `Ord`, so an expectation derived from it would verify the merge law while
    /// proving nothing about the order itself: a ranking that placed
    /// `DurableResultVerified` below `WriteMayHaveBeenSubmitted` would make
    /// every per-stage `max` in production wrong and still pass an `Ord`-derived
    /// expectation. Only a literal table pins the anchor.
    fn stage_order_anchor_is_least_to_most_uncertainty() {
        use RestoreEffectState::{
            DurableResultVerified, NoWriteSubmitted, ResponseObserved, WriteMayHaveBeenSubmitted,
        };

        // The four variants in the documented order, least uncertainty first.
        let states = [
            NoWriteSubmitted,
            WriteMayHaveBeenSubmitted,
            ResponseObserved,
            DurableResultVerified,
        ];
        // Row is the left operand and column the right operand, both indexed by
        // the documented order above. The merged state is written out, never
        // derived: `NoWriteSubmitted` yields the other operand because nothing
        // was ever sent, `DurableResultVerified` yields itself because an exact
        // durable result is the only state that discharges the obligation, and
        // between the two unproven states a provider answer outranks a bare
        // transport entry, because an answer is more information than a
        // suspicion that a request may have been sent.
        let expected = [
            [
                NoWriteSubmitted,
                WriteMayHaveBeenSubmitted,
                ResponseObserved,
                DurableResultVerified,
            ],
            [
                WriteMayHaveBeenSubmitted,
                WriteMayHaveBeenSubmitted,
                ResponseObserved,
                DurableResultVerified,
            ],
            [
                ResponseObserved,
                ResponseObserved,
                ResponseObserved,
                DurableResultVerified,
            ],
            [
                DurableResultVerified,
                DurableResultVerified,
                DurableResultVerified,
                DurableResultVerified,
            ],
        ];
        // `is_unproven` is true for exactly the two middle variants: nothing
        // sent and an exact durable result both discharge the obligation, the
        // two in between do not. Spelled out positionally, so a reordered enum
        // cannot hide behind a predicate.
        let unproven_anchor = [false, true, true, false];

        for (left_index, left) in states.iter().enumerate() {
            assert_eq!(
                left.is_unproven(),
                unproven_anchor[left_index],
                "{left:?} must anchor exactly the documented unproven set"
            );
            for (right_index, right) in states.iter().enumerate() {
                let literal = expected[left_index][right_index];
                let same_stage = RestoreStageExposure {
                    carrier: *left,
                    apply: *left,
                }
                .merged(RestoreStageExposure {
                    carrier: *right,
                    apply: *right,
                });
                assert_eq!(
                    same_stage.carrier, literal,
                    "carrier: merging {left:?} with {right:?}"
                );
                assert_eq!(
                    same_stage.apply, literal,
                    "apply: merging {left:?} with {right:?}"
                );
                assert_eq!(
                    same_stage.carrier.is_unproven(),
                    literal.is_unproven(),
                    "the literal table and `is_unproven` must agree on {left:?}/{right:?}"
                );
                let reversed = RestoreStageExposure {
                    carrier: *right,
                    apply: *right,
                }
                .merged(RestoreStageExposure {
                    carrier: *left,
                    apply: *left,
                });
                assert_eq!(
                    reversed.carrier, literal,
                    "the merged state must not depend on which observation came first: {left:?}/{right:?}"
                );
            }
        }
    }

    // WORK_UNIT_CASE: 2666/3 — the predicate `check_cancellation` and eviction read.
    #[test]
    fn any_unproven_is_true_when_either_provider_write_stage_is_unproven() {
        use RestoreEffectState::{
            DurableResultVerified, NoWriteSubmitted, ResponseObserved, WriteMayHaveBeenSubmitted,
        };
        assert!(!RestoreEffectState::NoWriteSubmitted.is_unproven());
        assert!(RestoreEffectState::WriteMayHaveBeenSubmitted.is_unproven());
        assert!(RestoreEffectState::ResponseObserved.is_unproven());
        assert!(!RestoreEffectState::DurableResultVerified.is_unproven());
        assert_eq!(
            RestoreStageExposure::NONE.carrier,
            RestoreEffectState::NoWriteSubmitted
        );
        assert_eq!(
            RestoreStageExposure::NONE.apply,
            RestoreEffectState::NoWriteSubmitted
        );
        assert!(!RestoreStageExposure::NONE.any_unproven());

        let cases = [
            (NoWriteSubmitted, NoWriteSubmitted, false),
            (NoWriteSubmitted, DurableResultVerified, false),
            (DurableResultVerified, NoWriteSubmitted, false),
            (DurableResultVerified, DurableResultVerified, false),
            (WriteMayHaveBeenSubmitted, NoWriteSubmitted, true),
            (NoWriteSubmitted, WriteMayHaveBeenSubmitted, true),
            (ResponseObserved, NoWriteSubmitted, true),
            (NoWriteSubmitted, ResponseObserved, true),
            (WriteMayHaveBeenSubmitted, WriteMayHaveBeenSubmitted, true),
            (DurableResultVerified, WriteMayHaveBeenSubmitted, true),
            (WriteMayHaveBeenSubmitted, DurableResultVerified, true),
            (ResponseObserved, DurableResultVerified, true),
            (DurableResultVerified, ResponseObserved, true),
            (ResponseObserved, ResponseObserved, true),
        ];
        for (carrier, apply, expected) in cases {
            let exposure = RestoreStageExposure { carrier, apply };
            assert_eq!(
                exposure.any_unproven(),
                expected,
                "carrier={carrier:?} apply={apply:?}"
            );
        }
    }

    // WORK_UNIT_CASE: 2666/4 — the delegator and the component builder are one key.
    #[test]
    fn attempt_slot_key_is_one_owner_scoped_digest_over_four_components() {
        fn both_derivations(
            active_store: &str,
            active_installation: &str,
            destination_id: &str,
            operation_id: &str,
        ) -> (String, String) {
            let mut destination = test_destination();
            destination.destination_id = destination_id.to_owned();
            let operation = test_operation(operation_id, TEST_HASH_A);
            (
                attempt_slot_key(active_store, active_installation, &destination, &operation),
                attempt_slot_key_from_components(
                    active_store,
                    active_installation,
                    destination.destination_id.as_str(),
                    operation.operation_id.as_str(),
                ),
            )
        }

        let inputs = [
            (
                "active-store",
                "active-install",
                "isolated-dest-1",
                "op-key-plain",
            ),
            (
                "active-store",
                "active-install",
                "isolated-dest-1",
                "op-key-second",
            ),
            (
                "other-store",
                "active-install",
                "isolated-dest-1",
                "op-key-plain",
            ),
            (
                "active-store",
                "other-install",
                "isolated-dest-1",
                "op-key-plain",
            ),
            (
                "active-store",
                "active-install",
                "isolated-dest-2",
                "op-key-plain",
            ),
            // Quotes, backslashes and non-ASCII text force the canonical-JSON
            // byte layout to escape rather than concatenate.
            (
                "st\"o\\re",
                "inst\u{e9}\u{4e2d}",
                "dest-\"q\"\\-\u{fc}",
                "op-key-escapes",
            ),
        ];
        for (active_store, active_installation, destination_id, operation_id) in inputs {
            let (delegated, components) = both_derivations(
                active_store,
                active_installation,
                destination_id,
                operation_id,
            );
            assert_eq!(
                delegated, components,
                "writer and reader derivations must be byte-identical for {destination_id}/{operation_id}"
            );
        }
    }

    // WORK_UNIT_CASE: 2666/11 - the four components are bound separately.
    #[test]
    fn attempt_slot_key_binds_each_component_and_both_orderings() {
        fn both_derivations(
            active_store: &str,
            active_installation: &str,
            destination_id: &str,
            operation_id: &str,
        ) -> (String, String) {
            let mut destination = test_destination();
            destination.destination_id = destination_id.to_owned();
            let operation = test_operation(operation_id, TEST_HASH_A);
            (
                attempt_slot_key(active_store, active_installation, &destination, &operation),
                attempt_slot_key_from_components(
                    active_store,
                    active_installation,
                    destination.destination_id.as_str(),
                    operation.operation_id.as_str(),
                ),
            )
        }

        // Owner scoping: changing exactly one of the four bound components must
        // change the digest, so one namespace can never address another's slot.
        let baseline = both_derivations(
            "active-store",
            "active-install",
            "isolated-dest-1",
            "op-key-plain",
        )
        .0;
        let variants = [
            both_derivations(
                "other-store",
                "active-install",
                "isolated-dest-1",
                "op-key-plain",
            )
            .0,
            both_derivations(
                "active-store",
                "other-install",
                "isolated-dest-1",
                "op-key-plain",
            )
            .0,
            both_derivations(
                "active-store",
                "active-install",
                "isolated-dest-2",
                "op-key-plain",
            )
            .0,
            both_derivations(
                "active-store",
                "active-install",
                "isolated-dest-1",
                "op-key-other",
            )
            .0,
        ];
        for variant in &variants {
            assert_ne!(
                baseline, *variant,
                "every bound component must change the key"
            );
        }
        for (index, left) in variants.iter().enumerate() {
            for right in variants.iter().skip(index + 1) {
                assert_ne!(left, right, "distinct owners must not share one slot key");
            }
        }

        // The key is a digest of an ordered tuple, not a spelling: component
        // boundaries and component order must both be bound.
        assert_ne!(
            both_derivations("active-store", "active-install", "ab", "op-key-plain").0,
            both_derivations("active-store", "active-install", "a", "bop-key-plain").0,
            "a concatenated key would collide these two component boundaries"
        );
        assert_ne!(
            baseline,
            both_derivations(
                "active-store",
                "active-install",
                "op-key-plain",
                "isolated-dest-1"
            )
            .0,
            "destination and operation components must not be interchangeable"
        );
    }

    // WORK_UNIT_CASE: 2666/12 - a provider refresh may raise the apply stage, never lower it.
    #[test]
    fn provider_refresh_raises_the_apply_stage_and_never_lowers_or_crosses_it() {
        let _serial = ledger_serial();
        let config = scoped_config("store-project-apply", "install-project-apply");
        provider_refresh_raises_but_never_lowers_the_apply_stage(&config);
        provider_refresh_of_an_absent_slot_is_inert(&config);
    }

    /// Half of case 12: on an existing slot a refresh carrying a LOWER provider
    /// state leaves the inherited apply stage exactly where it was, a refresh
    /// carrying a HIGHER one raises it, and neither ever touches the carrier
    /// half of the same slot.
    fn provider_refresh_raises_but_never_lowers_the_apply_stage(config: &SurrealAdapterConfig) {
        let batch = scoped_batch("dest-project-apply", "op-project-apply");
        forget_slot(&batch, config);
        let (active_store, active_installation) = active_store_identity(config);
        let key = attempt_slot_key(
            &active_store,
            &active_installation,
            &batch.destination,
            &batch.operation,
        );
        let operation_id = batch.operation.operation_id.as_str();

        // A released earlier incarnation leaves the apply stage answered but
        // unproven, beside a carrier stage that is less informed still.
        let mut guard = acquire_guard(&batch, config);
        guard
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
        guard
            .exposure
            .note_response_observed(RestoreWriteStage::CanonicalApply);
        assert!(
            guard.complete(None).is_ok(),
            "the seeding incarnation must release the slot it owns"
        );

        // An assignment instead of the per-stage maximum would answer this slot
        // with "no apply write", and the next invocation would act on it.
        assert!(
            project_provider_apply_state(
                &key,
                operation_id,
                RestoreEffectState::WriteMayHaveBeenSubmitted,
            )
            .is_ok(),
            "a refresh of an existing slot must succeed"
        );
        let after_lower = slot_for(&batch, config);
        let Some(after_lower) = after_lower else {
            panic!("a refresh of an existing slot must not remove it")
        };
        assert_eq!(
            after_lower.effect_state.apply,
            RestoreEffectState::ResponseObserved,
            "a refresh carrying a lower provider state must not lower an inherited apply stage"
        );
        assert_eq!(
            after_lower.effect_state.carrier,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "an apply-stage refresh must never touch the carrier half of the same slot"
        );

        // An exact durable record read back under the reconciled identity is
        // competent evidence about the apply, and about nothing else.
        assert!(
            project_provider_apply_state(
                &key,
                operation_id,
                RestoreEffectState::DurableResultVerified,
            )
            .is_ok(),
            "a raising refresh must succeed"
        );
        let after_higher = slot_for(&batch, config);
        let Some(after_higher) = after_higher else {
            panic!("a raising refresh must keep the slot it raised")
        };
        assert_eq!(
            after_higher.effect_state.apply,
            RestoreEffectState::DurableResultVerified,
            "a refresh carrying a higher provider state must raise the apply stage"
        );
        assert_eq!(
            after_higher.effect_state.carrier,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "an exact apply record says nothing whatever about the carrier publication"
        );
        assert!(
            after_higher.effect_state.any_unproven(),
            "a verified apply must not discharge the carrier stage's own unproven obligation"
        );
        forget_slot(&batch, config);
    }

    /// Half of case 12: with no slot for the key the refresh is an inert early
    /// return. It must not admit a slot, and it must not fabricate certainty for
    /// an identity this process never observed.
    fn provider_refresh_of_an_absent_slot_is_inert(config: &SurrealAdapterConfig) {
        let batch = scoped_batch("dest-project-apply-absent", "op-project-apply-absent");
        forget_slot(&batch, config);
        let (active_store, active_installation) = active_store_identity(config);
        let key = attempt_slot_key(
            &active_store,
            &active_installation,
            &batch.destination,
            &batch.operation,
        );
        assert!(
            project_provider_apply_state(
                &key,
                batch.operation.operation_id.as_str(),
                RestoreEffectState::DurableResultVerified,
            )
            .is_ok(),
            "a refresh for an unknown key is an inert Ok, not an error"
        );
        assert!(
            slot_for(&batch, config).is_none(),
            "a refresh for an unknown key must leave the projection unchanged"
        );
    }

    // WORK_UNIT_CASE: 2666/5 — a displaced finalizer releases nothing at all.
    #[test]
    fn release_refuses_a_slot_whose_incarnation_has_moved_on() {
        let _serial = ledger_serial();
        let config = scoped_config("store-stale-incarnation", "install-stale-incarnation");
        let batch = scoped_batch("dest-stale-incarnation", "op-stale-incarnation");
        forget_slot(&batch, &config);

        let mut guard = acquire_guard(&batch, &config);
        let key = guard.key.clone();
        let acquired = guard.incarnation;
        guard
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
        let displaced = acquired + 1;
        with_shared_ledger(|ledger| {
            if let Some(attempt) = ledger.attempts.get_mut(&key) {
                attempt.incarnation = displaced;
            }
        });

        assert!(
            guard.release(None).is_ok(),
            "a displaced release is a no-op, not a bookkeeping failure"
        );
        let slot = slot_for(&batch, &config);
        let Some(slot) = slot else {
            panic!("a displaced release must not remove the current owner's slot")
        };
        assert_eq!(
            slot.incarnation, displaced,
            "a displaced finalizer must not restore the incarnation it lost"
        );
        assert!(
            slot.running,
            "a displaced finalizer must not clear the current owner's running flag"
        );
        assert_eq!(
            slot.effect_state.carrier,
            RestoreEffectState::NoWriteSubmitted,
            "a displaced release must not merge its own exposure into the new owner"
        );
        assert_eq!(
            slot.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted
        );
        assert!(slot.first_failure.is_none());
        assert!(
            !slot.effect_state.any_unproven(),
            "the displaced exposure was never merged, so nothing is owed on this slot"
        );

        // The destructor runs the same refused release and must be just as inert.
        drop(guard);
        let after_drop = slot_for(&batch, &config);
        let Some(after_drop) = after_drop else {
            panic!("the slot must still exist after the destructor refuses to release it")
        };
        assert_eq!(after_drop.incarnation, displaced);
        assert!(after_drop.running);
        assert_eq!(
            after_drop.effect_state.carrier,
            RestoreEffectState::NoWriteSubmitted
        );
        forget_slot(&batch, &config);
    }

    // WORK_UNIT_CASE: 2666/6 — a later, different outcome never overwrites the first.
    #[test]
    fn first_failure_is_preserved_across_a_later_different_outcome() {
        let _serial = ledger_serial();
        let config = scoped_config("store-first-failure", "install-first-failure");
        let batch = scoped_batch("dest-first-failure", "op-first-failure");
        forget_slot(&batch, &config);

        let first = acquire_guard(&batch, &config);
        assert!(first.complete(Some(&StoreError::FenceMismatch)).is_ok());

        let second = acquire_guard(&batch, &config);
        assert!(second.complete(Some(&StoreError::IdentityConflict)).is_ok());

        let slot = slot_for(&batch, &config);
        let Some(slot) = slot else {
            panic!("a recorded failure must keep its slot")
        };
        let Some(record) = slot.first_failure else {
            panic!("the first failure must be recorded")
        };
        assert_eq!(
            record.classification, "FENCE_MISMATCH",
            "the second, different failure must not overwrite the first"
        );
        assert_eq!(record.phase, RESTORE_PHASE_APPLIED);
        assert!(
            !slot.running,
            "the slot must be released between the two attempts"
        );

        // The bounded reader reconstructs the ORIGINAL failure class, so the
        // later outcome is invisible to every later attempt.
        let observed = restore_attempt_state(&batch, &config);
        let Ok(Some(observed)) = observed else {
            panic!("the reader must observe the retained slot")
        };
        assert_eq!(observed.original_failure(), Some(StoreError::FenceMismatch));
        forget_slot(&batch, &config);
    }

    // WORK_UNIT_CASE: 2666/7 — eviction needs a proven pair AND no recorded outcome.
    #[test]
    fn eviction_requires_every_stage_proven_and_no_recorded_outcome() {
        let _serial = ledger_serial();
        let config = scoped_config("store-eviction", "install-eviction");

        // An unproven carrier stage beside a verified apply stage retains.
        let unproven = scoped_batch("dest-evict-unproven", "op-evict-unproven");
        let retained = attempt_then_release(
            &unproven,
            &config,
            |exposure| {
                exposure.note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
                exposure.note_apply_verified();
            },
            None,
        );
        let Some(retained) = retained else {
            panic!("an unproven carrier stage must keep its slot even when the apply is verified")
        };
        assert!(!retained.running);
        assert_eq!(
            retained.effect_state.carrier,
            RestoreEffectState::WriteMayHaveBeenSubmitted
        );
        assert_eq!(
            retained.effect_state.apply,
            RestoreEffectState::DurableResultVerified
        );

        // Every stage proven and nothing recorded leaves the map.
        let proven = scoped_batch("dest-evict-proven", "op-evict-proven");
        let evicted = attempt_then_release(
            &proven,
            &config,
            |exposure| {
                exposure.note_carrier_verified();
                exposure.note_apply_verified();
            },
            None,
        );
        assert!(
            evicted.is_none(),
            "a fully proven pair owes no reconciliation and must leave the map"
        );

        // Every stage proven but a failure recorded still retains.
        let failed = scoped_batch("dest-evict-failed", "op-evict-failed");
        let kept = attempt_then_release(
            &failed,
            &config,
            |exposure| {
                exposure.note_carrier_verified();
                exposure.note_apply_verified();
            },
            Some(&StoreError::FenceMismatch),
        );
        let Some(kept) = kept else {
            panic!("a recorded outcome must keep its slot")
        };
        assert!(!kept.running);
        assert_eq!(
            kept.effect_state.carrier,
            RestoreEffectState::DurableResultVerified
        );
        assert_eq!(
            kept.effect_state.apply,
            RestoreEffectState::DurableResultVerified
        );
        assert!(kept.first_failure.is_some());

        forget_slot(&unproven, &config);
        forget_slot(&failed, &config);
    }

    // WORK_UNIT_CASE: 2666/8 — a verified carrier publication never reads as a verified apply.
    #[test]
    fn stage_marking_never_crosses_the_two_provider_writes() {
        let mut exposure = RestoreEffectExposure::new(RestoreStageExposure::NONE);
        exposure.note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
        exposure.note_response_observed(RestoreWriteStage::CanonicalApply);
        assert_eq!(
            exposure.carrier_stage(),
            RestoreEffectState::WriteMayHaveBeenSubmitted
        );
        assert_eq!(
            exposure.apply_stage(),
            RestoreEffectState::ResponseObserved,
            "a carrier-side note must not answer the apply stage"
        );
        assert!(exposure.state().carrier.is_unproven());
        assert!(exposure.state().apply.is_unproven());

        exposure.note_carrier_verified();
        assert_eq!(
            exposure.carrier_stage(),
            RestoreEffectState::DurableResultVerified
        );
        assert_eq!(
            exposure.apply_stage(),
            RestoreEffectState::ResponseObserved,
            "an exact carrier readback is evidence about the carrier stage alone"
        );
        assert!(!exposure.state().carrier.is_unproven());
        assert!(
            exposure.state().any_unproven(),
            "the apply stage still owes an exact durable record"
        );
        exposure.note_apply_verified();
        assert!(!exposure.state().any_unproven());

        // The other direction: an apply-side note must not answer the carrier
        // stage, and an inherited uncertainty is never lowered by this
        // incarnation's own, less informed, observation of the same slot.
        let mut resumed = RestoreEffectExposure::new(RestoreStageExposure {
            carrier: RestoreEffectState::ResponseObserved,
            apply: RestoreEffectState::NoWriteSubmitted,
        });
        resumed.note_write_may_be_submitted(RestoreWriteStage::CanonicalApply);
        assert_eq!(
            resumed.carrier_stage(),
            RestoreEffectState::ResponseObserved,
            "the inherited carrier uncertainty must survive an apply-side note"
        );
        assert_eq!(
            resumed.apply_stage(),
            RestoreEffectState::WriteMayHaveBeenSubmitted
        );
        resumed.note_apply_verified();
        assert_eq!(
            resumed.carrier_stage(),
            RestoreEffectState::ResponseObserved,
            "a verified apply says nothing whatever about the carrier publication"
        );
        assert!(resumed.state().any_unproven());
    }

    // WORK_UNIT_CASE: 2666/9 — live concurrency refused; the bound is on fresh slots.
    #[test]
    fn acquire_refuses_live_concurrency_and_bounds_only_a_fresh_slot() {
        let _serial = ledger_serial();
        let config = scoped_config("store-ceiling", "install-ceiling");
        concurrent_live_attempt_is_refused(&config);
        ceiling_refuses_only_a_fresh_slot(&config);
    }

    /// Half of case 9: a genuinely concurrent live attempt of one owner-scoped
    /// identity is refused with the typed retryable refusal, and the holder's
    /// own clean release still evicts its slot.
    fn concurrent_live_attempt_is_refused(config: &SurrealAdapterConfig) {
        let batch = scoped_batch("dest-live-attempt", "op-live-attempt");
        forget_slot(&batch, config);
        let holder = acquire_guard(&batch, config);
        assert_eq!(
            RestoreAttemptGuard::acquire(&batch, config).err(),
            Some(StoreError::Unavailable),
            "a concurrent live attempt must be refused as retryable unavailability"
        );
        assert!(
            RestoreAttemptGuard::acquire(&batch, config).is_err(),
            "the refusal must be repeatable, not a one-shot race"
        );
        drop(holder);
        assert!(
            slot_for(&batch, config).is_none(),
            "a clean release of a slot that submitted nothing leaves the map"
        );
        forget_slot(&batch, config);
    }

    /// Half of case 9: at `MAX_RESTORE_TRACKED_ATTEMPTS`, a fresh slot is refused
    /// instead of growing the map, while a retained slot of the same identity
    /// is reused rather than refused.
    fn ceiling_refuses_only_a_fresh_slot(config: &SurrealAdapterConfig) {
        let retained_batch = scoped_batch("dest-ceiling-retained", "op-ceiling-retained");
        forget_slot(&retained_batch, config);
        let mut first = acquire_guard(&retained_batch, config);
        first
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
        drop(first);
        assert!(
            slot_for(&retained_batch, config).is_some(),
            "the retained slot must exist before the map is filled"
        );

        let _cleanup = insert_ceiling_filler_slots();
        assert_eq!(
            with_shared_ledger(|ledger| ledger.attempts.len()),
            MAX_RESTORE_TRACKED_ATTEMPTS,
            "the fixture must reach the ceiling it is proving"
        );

        let fresh = scoped_batch("dest-ceiling-fresh", "op-ceiling-fresh");
        forget_slot(&fresh, config);
        assert_eq!(
            RestoreAttemptGuard::acquire(&fresh, config).err(),
            Some(StoreError::PayloadTooLarge),
            "a fresh slot arriving at the ceiling must be refused, not admitted"
        );

        let reused = RestoreAttemptGuard::acquire(&retained_batch, config);
        let Ok(reused) = reused else {
            panic!("a retained slot must be reused at the ceiling, never refused")
        };
        assert_eq!(
            reused.exposure.apply_stage(),
            RestoreEffectState::NoWriteSubmitted,
            "the reused attempt inherits the retained carrier uncertainty only"
        );
        assert!(reused.complete(None).is_ok());
        assert!(
            slot_for(&retained_batch, config).is_some(),
            "the inherited unproven stage must survive the reused attempt"
        );

        forget_slot(&retained_batch, config);
        forget_slot(&fresh, config);
    }

    // WORK_UNIT_CASE: 2666/10 — a drop merges the exposure, so uncertainty survives it.
    #[test]
    fn drop_merges_exposure_so_an_unproven_stage_survives_the_attempt() {
        let _serial = ledger_serial();
        let config = scoped_config("store-drop-retains", "install-drop-retains");
        let batch = scoped_batch("dest-drop-retains", "op-drop-retains");
        forget_slot(&batch, &config);

        let mut guard = acquire_guard(&batch, &config);
        guard
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CanonicalApply);
        let incarnation = guard.incarnation;
        drop(guard);

        let slot = slot_for(&batch, &config);
        let Some(slot) = slot else {
            panic!("a dropped attempt that may have submitted a write must keep its slot")
        };
        assert_eq!(
            slot.incarnation, incarnation,
            "the dropped incarnation's own slot is the one that survives"
        );
        assert!(
            !slot.running,
            "a drop releases the local running owner and nothing else"
        );
        assert_eq!(
            slot.effect_state.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "Drop merges this invocation's exposure; it never discards it"
        );
        assert_eq!(
            slot.effect_state.carrier,
            RestoreEffectState::NoWriteSubmitted,
            "a stage that was never touched is not invented"
        );
        assert!(slot.effect_state.any_unproven());
        assert!(
            slot.first_failure.is_none(),
            "a drop records uncertainty, not a failure"
        );

        // A later attempt of the same identity inherits the surviving obligation
        // and is never answered as a clean first write.
        let resumed = acquire_guard(&batch, &config);
        assert_eq!(
            resumed.exposure.apply_stage(),
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "the resumed attempt must inherit the unproven apply stage"
        );
        assert_eq!(
            resumed.exposure.carrier_stage(),
            RestoreEffectState::NoWriteSubmitted
        );
        drop(resumed);
        forget_slot(&batch, &config);
    }

    // WORK_UNIT_CASE: 2666/13 — retained unproven apply reaches the owner readback, then converges
    //
    // Third sentence of audit comment 5934351574: "repeated cancellations не
    // должны навсегда занимать operation solely из-за abandoned local
    // exposure." This case answers the two halves of that sentence. First, the
    // retained slot gates the fresh-write branch only and is never a substitute
    // for the exact durable record read, and it never manufactures a receipt.
    // Second, the slot converges and leaves the map in the same process once
    // competent provider evidence arrives, so a restart is never needed.
    //
    // Measured site of the gate this case pins: `apply_canonical_batch` at :4590,
    // `if exposure.apply_stage().is_unproven() { return
    // Err(unknown_outcome(...)) }` — the only predicate that closes the fresh-write
    // branch, reached after the exact record read at `read_record` and before the
    // carrier publication and the canonical-apply write.
    #[test]
    fn retained_unproven_apply_reaches_the_owner_readback_and_then_converges() {
        let _serial = ledger_serial();
        let config = scoped_config("store-owner-readback", "install-owner-readback");
        retained_unproven_apply_answers_the_typed_unknown(&config);
        competent_evidence_converges_the_slot_in_process(&config);
    }

    /// Half of case 13: after an abandoned in-flight apply, the next exact
    /// invocation of the same identity reacquires the slot, inherits the unproven
    /// apply stage, and therefore answers with the typed unknown outcome at the
    /// fresh-write gate instead of a fresh write or a fabricated receipt. A retry
    /// of that retry does not erase what it inherited.
    fn retained_unproven_apply_answers_the_typed_unknown(config: &SurrealAdapterConfig) {
        let batch = scoped_batch("dest-owner-readback", "op-owner-readback");
        forget_slot(&batch, config);
        let operation_id = batch.operation.operation_id.as_str();

        // The abandoned in-flight apply: the pre-poll mark is raised and the
        // pending future is then dropped without an explicit completion.
        let mut abandoned = acquire_guard(&batch, config);
        abandoned
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CanonicalApply);
        drop(abandoned);
        assert!(
            slot_for(&batch, config).is_some(),
            "an abandoned apply that may have been submitted must keep its slot"
        );

        // The subsequent exact invocation. Reacquisition grants local ownership
        // and nothing else: the predicate it must answer is the one
        // `apply_canonical_batch` consults on the apply stage before the
        // canonical-apply write, so an unproven inherited stage closes that
        // branch and hands the decision to the exact durable record read.
        let exact = acquire_guard(&batch, config);
        assert!(
            exact.exposure.apply_stage().is_unproven(),
            "reacquisition must inherit the unproven apply stage, so the fresh-write \
             branch stays closed and the exact durable record read decides"
        );
        assert_eq!(
            exact.exposure.carrier_stage(),
            RestoreEffectState::NoWriteSubmitted,
            "the apply stage's uncertainty says nothing about the carrier stage"
        );
        assert_eq!(
            unknown_outcome(operation_id),
            StoreError::MissingReceiptEnvelope,
            "the answer at that gate is the typed unknown outcome, never a receipt"
        );
        assert!(
            cached_receipt(&batch.operation).is_none(),
            "no receipt may be fabricated for an operation the provider never confirmed"
        );
        assert!(
            with_shared_ledger(|ledger| ledger.readback(&batch.operation)).is_none(),
            "the durable-receipt cache must hold nothing for an unconfirmed operation"
        );

        // The obligation survives this invocation too: an exact retry that is
        // itself cancelled must not erase the uncertainty it inherited.
        drop(exact);
        let observed = restore_attempt_state(&batch, config);
        let Ok(Some(observed)) = observed else {
            panic!("the bounded reader must still observe the retained slot")
        };
        assert_eq!(
            observed.effect_state.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "a cancelled retry must not reset the uncertainty it inherited"
        );
        assert!(observed.effect_state.any_unproven());
        assert!(observed.original_failure().is_none());
        forget_slot(&batch, config);
    }

    /// Half of case 13: competent provider evidence — the exact durable record
    /// read back under this operation identity, the only input `reconcile_operation`
    /// feeds the slot — discharges the stage, the fresh-write gate opens, and a
    /// clean completion evicts the bounded evidence so the identity is no longer
    /// occupied by its own local bookkeeping.
    fn competent_evidence_converges_the_slot_in_process(config: &SurrealAdapterConfig) {
        let batch = scoped_batch("dest-owner-converge", "op-owner-converge");
        forget_slot(&batch, config);
        let operation_id = batch.operation.operation_id.as_str();
        let (active_store, active_installation) = active_store_identity(config);
        let key = attempt_slot_key(
            &active_store,
            &active_installation,
            &batch.destination,
            &batch.operation,
        );

        let mut abandoned = acquire_guard(&batch, config);
        abandoned
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CanonicalApply);
        abandoned.exposure.note_carrier_verified();
        drop(abandoned);

        assert!(
            project_provider_apply_state(
                &key,
                operation_id,
                RestoreEffectState::DurableResultVerified,
            )
            .is_ok(),
            "an exact durable record read under this identity must refresh the slot"
        );

        let resolved = acquire_guard(&batch, config);
        assert_eq!(
            resolved.exposure.apply_stage(),
            RestoreEffectState::DurableResultVerified,
            "competent provider evidence must be able to discharge the retained apply"
        );
        assert!(
            !resolved.exposure.state().any_unproven(),
            "a verified apply beside a verified carrier leaves the identity owing nothing"
        );
        assert!(
            resolved.complete(None).is_ok(),
            "a fully proven slot must release cleanly"
        );
        assert!(
            slot_for(&batch, config).is_none(),
            "a settled identity must not stay occupied by its own local evidence"
        );
        forget_slot(&batch, config);
    }

    // WORK_UNIT_CASE: 2666/14 — each cancellation releases the running claim, consuming one slot
    #[test]
    fn repeated_cancellations_of_one_identity_never_pile_up_running_flags() {
        let _serial = ledger_serial();
        let config = scoped_config("store-repeat-cancel", "install-repeat-cancel");
        let batch = scoped_batch("dest-repeat-cancel", "op-repeat-cancel");
        forget_slot(&batch, &config);
        let baseline = with_shared_ledger(|ledger| ledger.attempts.len());

        for cycle in 0..5usize {
            let mut cancelled = match RestoreAttemptGuard::acquire(&batch, &config) {
                Ok(guard) => guard,
                Err(error) => panic!(
                    "cycle {cycle}: a released identity must stay re-acquirable, never \
                     permanently consumed by its own abandoned in-flight flag: {error:?}"
                ),
            };
            cancelled
                .exposure
                .note_write_may_be_submitted(RestoreWriteStage::CanonicalApply);
            drop(cancelled);

            let slot = slot_for(&batch, &config);
            let Some(slot) = slot else {
                panic!("cycle {cycle}: an abandoned apply must keep its slot")
            };
            assert!(
                !slot.running,
                "cycle {cycle}: dropping a pending future must clear the local running \
                 claim, which is the only thing the destructor may clear"
            );
            assert_eq!(
                slot.effect_state.apply,
                RestoreEffectState::WriteMayHaveBeenSubmitted,
                "cycle {cycle}: repeated cancellation must not decay the retained obligation"
            );
            assert!(
                slot.first_failure.is_none(),
                "cycle {cycle}: a cancellation is an abandoned obligation, not a failure"
            );
            assert_eq!(
                with_shared_ledger(|ledger| ledger.attempts.len()),
                baseline + 1,
                "cycle {cycle}: five cancellations of one identity must consume exactly one \
                 bounded slot, so an operation is occupied by its exposure rather than by \
                 the number of attempts"
            );
        }
        forget_slot(&batch, &config);
    }

    // WORK_UNIT_CASE: 2666/15 — a ceiling refusal is fail-closed and leaves the projection intact
    //
    // Measured sites: the bound is checked in `RestoreAttemptGuard::acquire` at
    // :1465 (`retained.is_none() && ledger.attempts.len() >=
    // MAX_RESTORE_TRACKED_ATTEMPTS`), which `restore_canonical_batch` reaches at
    // :4099 before `apply_canonical_batch` — and therefore before both provider
    // writes at :2889 (carrier publication) and :4883 (canonical apply). The
    // exposure gate the refusal must never be confused with is the per-stage
    // `apply_stage()` decision at :4590, which runs strictly later and only over
    // an already-acquired slot.
    #[test]
    fn ceiling_refusal_is_fail_closed_and_leaves_the_projection_intact() {
        let _serial = ledger_serial();
        let config = scoped_config("store-ceiling-intact", "install-ceiling-intact");
        let held = seed_held_reconcilable_identity(&config);
        let _filler = insert_ceiling_filler_slots();
        let before = attempt_map_lines();
        ceiling_refusal_is_inert(&config, &before);
        held_identity_stays_reconcilable_at_the_ceiling(&config, &held);
    }

    /// Seeds the one identity whose slot must survive the ceiling refusal: an
    /// unproven apply obligation beside a recorded first failure.
    fn seed_held_reconcilable_identity(config: &SurrealAdapterConfig) -> CanonicalRestoreBatch {
        let held = scoped_batch("dest-held-reconcilable", "op-held-reconcilable");
        forget_slot(&held, config);
        let mut seeding = acquire_guard(&held, config);
        seeding
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CanonicalApply);
        seeding.exposure.note_carrier_verified();
        assert!(
            seeding.complete(Some(&StoreError::FenceMismatch)).is_ok(),
            "the seeding incarnation must release the slot it owns"
        );
        held
    }

    /// Half of case 15: at the ceiling a fresh identity is refused by the
    /// unchanged bound, and the refusal is inert — it happens before any write, so
    /// it may not insert a slot, evict one, or rewrite the exposure or the failure
    /// of any slot already there. The ceiling value is pinned against the batch
    /// member ceiling it reuses, so widening it to hide a leak fails here.
    fn ceiling_refusal_is_inert(config: &SurrealAdapterConfig, before: &[String]) {
        assert_eq!(
            before.len(),
            MAX_RESTORE_BATCH_MEMBERS,
            "the fixture must reach MAX_RESTORE_TRACKED_ATTEMPTS, which is still the \
             unchanged batch member ceiling"
        );
        let fresh = scoped_batch("dest-ceiling-intact-new", "op-ceiling-intact-new");
        forget_slot(&fresh, config);
        assert_eq!(
            RestoreAttemptGuard::acquire(&fresh, config).err(),
            Some(StoreError::PayloadTooLarge),
            "a fresh slot arriving at the ceiling must be refused by the bound"
        );
        assert_eq!(
            attempt_map_lines(),
            *before,
            "a ceiling refusal must be inert: it may not insert, evict or rewrite a slot"
        );
        assert!(
            slot_for(&fresh, config).is_none(),
            "the refused identity must own no slot at all"
        );
        forget_slot(&fresh, config);
    }

    /// Half of case 15: the refusal is fail-closed and non-corrupting, so the held
    /// identity is still readable, still carries its exact obligation and its
    /// original failure, and is still reusable at the ceiling rather than refused
    /// together with the fresh one — and releasing it still retains the slot.
    fn held_identity_stays_reconcilable_at_the_ceiling(
        config: &SurrealAdapterConfig,
        held: &CanonicalRestoreBatch,
    ) {
        let observed = restore_attempt_state(held, config);
        let Ok(Some(observed)) = observed else {
            panic!("the held identity must survive the refusal")
        };
        assert_eq!(
            observed.effect_state.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "the refusal must not lower a retained obligation"
        );
        assert_eq!(
            observed.original_failure(),
            Some(StoreError::FenceMismatch),
            "the refusal must not drop or overwrite a retained first failure"
        );
        let reused = acquire_guard(held, config);
        assert_eq!(
            reused.exposure.apply_stage(),
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "a held identity must stay reconcilable at the ceiling"
        );
        assert_eq!(
            reused.exposure.carrier_stage(),
            RestoreEffectState::DurableResultVerified
        );
        assert!(reused.complete(None).is_ok());
        let retained = slot_for(held, config);
        let Some(retained) = retained else {
            panic!("an unproven obligation must never be evicted to free a slot")
        };
        assert!(!retained.running);
        assert_eq!(
            retained.effect_state.apply,
            RestoreEffectState::WriteMayHaveBeenSubmitted
        );
        forget_slot(held, config);
    }

    // WORK_UNIT_CASE: 2666/16 — a drop before the canonical apply retains the proved carriers
    //
    // The schedule this pins is the one the card's DONE clause names: a successful
    // carrier publication, a drop before the canonical apply, and a next exact
    // request that publishes no second time. Precisely: the retained carrier
    // stage is re-proved by `resolve_carrier_stage`, which answers it from THIS
    // invocation's own bounded exact carrier readback over this batch's own
    // intended set; the carrier rows this invocation then uses are read back from
    // the destination by `resolve_archive_members`, which re-proves payload
    // digest and length. So the rows are read back in that invocation, and by the
    // carrier-stage verdict itself — this case pins the accessors that verdict
    // consults and the closed decision it asks, and says so rather than claiming
    // more. The state that leaves the drop is
    // {carrier: DurableResultVerified, apply: NoWriteSubmitted}, which no other
    // case reaches: the eviction case covers {WMS, DRV}, {DRV, DRV} and
    // {DRV, DRV} plus a recorded outcome, and the drop case seeds only an
    // unproven apply beside an untouched carrier.
    //
    // The single mutation killed here is the eviction predicate in
    // `RestoreAttemptGuard::release`: reverting it to
    // `outcome.is_none() && !merged.any_unproven()` fails this case, because
    // `DurableResultVerified` and `NoWriteSubmitted` are both proven states, so
    // that predicate collects the slot and every retained-carrier assertion
    // below fails with it.
    //
    // Measured sites: the eviction predicate is the `if` at :1537, and the
    // republication decision is the closed `carrier_stage_requires_readback`
    // branch in [`SurrealStoreAdapter::resolve_carrier_stage`], whose single
    // production caller is the `Restored` arm of the `let published` decision.
    // That function is `async` over a live provider transport, so
    // this case drives the accessors its decision consults — `carrier_stage`,
    // `is_unproven` and `carrier_stage_requires_readback` — over the retained
    // exposure, the way case 2666/13 pins the apply-stage gate
    // `apply_canonical_batch` consults. It does not execute the readback itself;
    // case 2666/23 pins that branch decision.
    #[test]
    fn drop_before_the_canonical_apply_retains_the_proved_carrier_publication() {
        let _serial = ledger_serial();
        let config = scoped_config("store-drop-before-apply", "install-drop-before-apply");
        let batch = scoped_batch("dest-drop-before-apply", "op-drop-before-apply");
        forget_slot(&batch, &config);
        let baseline = with_shared_ledger(|ledger| ledger.attempts.len());

        drop_before_the_apply_keeps_the_proved_carriers(&batch, &config, baseline);
        the_next_exact_invocation_inherits_them(&batch, &config, baseline);
        the_recorded_and_completed_arms_are_unchanged(&batch, &config, baseline);
        forget_slot(&batch, &config);
    }

    /// Half of case 16: the carrier transaction reaches a successful provider
    /// response, the bounded exact readback of every carrier row of this
    /// operation fixes the stage, and the pending future is then dropped before
    /// the canonical apply write. The slot survives that drop, with the two
    /// stages no longer "unproven" and the apply stage still owing its write —
    /// the one pair the eviction predicate has to keep.
    fn drop_before_the_apply_keeps_the_proved_carriers(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
        baseline: usize,
    ) {
        // The marks are the production ones: `execute_restore_write` raises
        // `note_write_may_be_submitted` on the last synchronous line before the
        // transport poll and `note_response_observed` on the answer, and only the
        // bounded exact readback raises `note_carrier_verified`.
        let mut publisher = acquire_guard(batch, config);
        publisher
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
        publisher
            .exposure
            .note_response_observed(RestoreWriteStage::CarrierPublication);
        publisher.exposure.note_carrier_verified();
        drop(publisher);

        let Some(retained) = slot_for(batch, config) else {
            panic!(
                "a drop between a proved carrier publication and the canonical apply must \
                 keep its slot: the next exact invocation inherits the carrier evidence \
                 from here and nowhere else"
            )
        };
        assert!(
            !retained.running,
            "a drop releases the local running owner and nothing else"
        );
        assert_eq!(
            retained.effect_state.carrier,
            RestoreEffectState::DurableResultVerified,
            "the exact carrier readback is retained evidence, not a stage to perform again"
        );
        assert_eq!(
            retained.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted,
            "the canonical apply was never entered, so that stage still owes its write"
        );
        assert!(
            !retained.effect_state.any_unproven(),
            "both stages read as proven here, which is exactly why the release predicate \
             must ask the apply stage itself and not only the pair"
        );
        assert!(
            retained.first_failure.is_none(),
            "a drop records uncertainty, not a failure"
        );
        assert_eq!(
            with_shared_ledger(|ledger| ledger.attempts.len()),
            baseline + 1,
            "the retained slot is visible in the bounded map as one occupied slot"
        );
    }

    /// Half of case 16: the next exact invocation of the same operation identity
    /// reacquires that slot, so the carrier stage it consults is the retained
    /// one — which is what answers `resolve_carrier_stage` before the
    /// republication guard. Dropping that resumed invocation merges an untouched
    /// exposure into strictly higher retained stages, so the merge — never an
    /// overwrite — is pinned on the same state.
    fn the_next_exact_invocation_inherits_them(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
        baseline: usize,
    ) {
        let exact = acquire_guard(batch, config);
        assert_eq!(
            exact.exposure.carrier_stage(),
            RestoreEffectState::DurableResultVerified,
            "reacquisition must inherit the retained carrier publication, so the \
             inherited carrier stage is `DurableResultVerified` and `resolve_carrier_stage` \
             re-proves it against this request's own rows rather than answering \
             `Ok(None)`, which is what would authorise a second carrier publication. \
             A proved stage still owes that readback because the slot key does not bind \
             `canonical_request_hash`. This asserts the inherited STATE the decision reads; \
             the decision's readback is async over a live transport and is not executed here"
        );
        assert_eq!(
            exact.exposure.apply_stage(),
            RestoreEffectState::NoWriteSubmitted,
            "the apply of this invocation is still the one owed"
        );
        assert!(
            !exact.exposure.carrier_stage().is_unproven(),
            "the retained stage is a proved result, so it is not an *unproven* \
             readback obligation — and that is a statement about the accessor only: \
             `resolve_carrier_stage` still re-proves a proved stage against this \
             request's own rows, because the slot key does not bind \
             `canonical_request_hash`"
        );

        // The contrast that makes the branch decision legible is asserted below over a
        // slot that really went through `release`. An earlier version of this case also
        // asserted the same contrast over a freshly constructed
        // `RestoreEffectExposure::new(RestoreStageExposure::NONE)`; that was removed as
        // vacuous, because folding constants over `NONE` holds under every mutation of the
        // code under test and therefore proved nothing.

        // This invocation wrote nothing and is dropped too, so its own exposure
        // is `NoWriteSubmitted` on both stages while the slot's are strictly
        // higher. A mutation of the merge in `release` into a plain assignment of
        // this invocation's own state would answer `NoWriteSubmitted` for the
        // carrier here and hand the next invocation a second publication.
        drop(exact);
        let after_merge = slot_for(batch, config);
        let Some(after_merge) = after_merge else {
            panic!("the merged release must keep the slot it merged into")
        };
        assert_eq!(
            after_merge.effect_state.carrier,
            RestoreEffectState::DurableResultVerified,
            "a drop merges the retained maximum per stage, never overwrites it"
        );
        assert_eq!(
            after_merge.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted,
            "the inherited apply stage survives a later, less informed observation"
        );
        assert_eq!(
            with_shared_ledger(|ledger| ledger.attempts.len()),
            baseline + 1,
            "repeated cancellations of this identity consume exactly one bounded slot"
        );
    }

    /// Half of case 16: on the retained {carrier: `DurableResultVerified`, apply:
    /// `NoWriteSubmitted`} slot the typed-error arm and the completed arm behave
    /// exactly as they do today — a recorded outcome keeps the slot whatever its
    /// stages are, and only an apply that reached its own exact durable result
    /// lets a clean completion collect it.
    fn the_recorded_and_completed_arms_are_unchanged(
        batch: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
        baseline: usize,
    ) {
        let refused = acquire_guard(batch, config);
        assert!(
            refused.complete(Some(&StoreError::FenceMismatch)).is_ok(),
            "a recorded outcome must release the slot this incarnation owns"
        );
        let Some(after_error) = slot_for(batch, config) else {
            panic!("a recorded outcome must keep its slot")
        };
        assert!(
            !after_error.running,
            "an explicit completion releases the local running owner"
        );
        assert!(
            after_error.first_failure.is_some(),
            "a recorded outcome keeps the slot, so the first failure survives"
        );
        assert_eq!(
            after_error.effect_state.carrier,
            RestoreEffectState::DurableResultVerified,
            "the retained carrier stage is untouched by an unrelated refusal"
        );

        let mut settled = acquire_guard(batch, config);
        settled.exposure.note_apply_verified();
        assert!(
            settled.complete(None).is_ok(),
            "a fully proven slot must release cleanly"
        );
        assert!(
            slot_for(batch, config).is_none(),
            "with the apply stage itself proved and no recorded outcome, the bounded \
             evidence still leaves the map"
        );
        assert_eq!(
            with_shared_ledger(|ledger| ledger.attempts.len()),
            baseline,
            "the converged identity occupies no bounded slot afterwards"
        );
    }

    /// Projects the shared attempt map into one sorted line per slot, naming every
    /// fact a ceiling refusal must leave untouched. Sorting keeps the comparison
    /// independent of hash iteration order.
    fn attempt_map_lines() -> Vec<String> {
        with_shared_ledger(|ledger| {
            let mut lines: Vec<String> = ledger
                .attempts
                .iter()
                .map(|(key, attempt)| {
                    format!(
                        "{key}|{}|{}|{}|{:?}|{:?}|{:?}",
                        attempt.phase,
                        attempt.incarnation,
                        attempt.running,
                        attempt.effect_state.carrier,
                        attempt.effect_state.apply,
                        attempt.first_failure,
                    )
                })
                .collect();
            lines.sort();
            lines
        })
    }

    /// Canonical lineage of the fixture fence below. An `EpochLineageId` is a
    /// canonical UUID text by contract, so this is the shape the type demands and
    /// not a stand-in for any digest the carrier code computes.
    const CARRIER_FIXTURE_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// The durable fence the carrier rows are registered under.
    ///
    /// The fence is bound into each published *row*, never into the carrier
    /// document, so its value is inert for the identity and content comparisons
    /// these cases pin — exactly as it is for a fixture that opens no connection.
    fn carrier_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(CARRIER_FIXTURE_LINEAGE).expect("canonical lineage fixture"),
                NonZeroU64::new(1).expect("non-zero fixture epoch sequence"),
            )
            .expect("valid fixture epoch"),
            ResourceGeneration::genesis(),
        )
    }

    /// The canonical logical payload one retained member carries.
    fn carrier_payload_text(member_id: &str) -> String {
        format!(r#"{{"body":"{member_id}","revision":7}}"#)
    }

    /// One admitted batch member with real residency metadata.
    ///
    /// `content_digest` is the *archive* commitment the capture recorded for the
    /// member, not a checksum of the payload that travels beside it, so it comes
    /// from this module's fixture digests and never from `sha256_hex` over the
    /// payload. Members are told apart by `member_id`; the second and later
    /// members of a batch take the other fixture digest, so two members of one
    /// batch never claim one commitment.
    fn carrier_member(member_id: &str, payload: &str, content_digest: &str) -> SnapshotMember {
        SnapshotMember {
            member_id: member_id.to_owned(),
            member_type: SnapshotMemberType::Record,
            content_digest: content_digest.to_owned(),
            residency: BlobResidency {
                domain: BlobResidencyDomain::InlineCanonical,
                residency_digest: TEST_HASH_B.to_owned(),
                byte_count: u64::try_from(payload.len())
                    .expect("a fixture payload length always fits in u64"),
            },
            reference_digest: None,
        }
    }

    /// The retained reference for one member, with the owner's attested digest and
    /// declared length computed over the payload bytes it actually holds —
    /// `carrier_for` re-proves both, so a fixture constant standing in for either
    /// would be refused typed instead of publishing a carrier.
    fn retained_carrier_member(member_id: &str, payload: &str) -> RetainedArchiveMember {
        RetainedArchiveMember {
            member_id: member_id.to_owned(),
            class: RestoreRecordClass::WriteReceipt.token().to_owned(),
            record_id: format!("receipt-{member_id}"),
            payload_digest: sha256_hex(payload.as_bytes()),
            byte_count: u64::try_from(payload.len())
                .expect("a fixture payload length always fits in u64"),
            payload: payload.to_owned(),
        }
    }

    /// An owner-scoped batch that actually carries members and the retained
    /// payloads behind them.
    ///
    /// This is `scoped_batch` with the one thing it leaves empty filled in: a real
    /// member denominator and one retained reference per importable member. Every
    /// other field stays inert, so the carrier published from it is produced by
    /// `carrier_for` out of admitted values and never by a hand-written literal.
    fn carrier_batch(
        destination_id: &str,
        operation_id: &str,
        member_ids: &[&str],
    ) -> CanonicalRestoreBatch {
        let mut batch = scoped_batch(destination_id, operation_id);
        for (index, member_id) in member_ids.iter().enumerate() {
            let payload = carrier_payload_text(member_id);
            let content_digest = if index % 2 == 0 {
                TEST_HASH_A
            } else {
                TEST_HASH_B
            };
            batch
                .members
                .push(carrier_member(member_id, &payload, content_digest));
            batch
                .retained_members
                .push(retained_carrier_member(member_id, &payload));
        }
        batch.member_count = batch.members.len() as u64;
        batch
    }

    /// Applies one field mutation to the carrier a producer built, so each
    /// mutation below names the single fact it changes and nothing else.
    fn with_carrier_field(
        intended: &ArchiveMemberCarrier,
        mutate: impl FnOnce(&mut ArchiveMemberCarrier),
    ) -> ArchiveMemberCarrier {
        let mut mutated = intended.clone();
        mutate(&mut mutated);
        mutated
    }

    /// One single-fact divergence per clause of `carrier_answers_for`, in the
    /// order the comparator states them. Held here rather than in the case body
    /// so the case reads as the ten assertions it makes; the array length is
    /// itself asserted by the case, so dropping a fact still fails it.
    fn carrier_identity_fact_mutations(
        intended: &ArchiveMemberCarrier,
    ) -> [(&'static str, ArchiveMemberCarrier); 10] {
        [
            (
                "operation_id",
                with_carrier_field(intended, |carrier| {
                    carrier.operation_id = "op-carrier-identity-foreign".to_owned();
                }),
            ),
            (
                "source_store_id",
                with_carrier_field(intended, |carrier| {
                    carrier.source_store_id = "source-store-foreign".to_owned();
                }),
            ),
            (
                "source_installation_id",
                with_carrier_field(intended, |carrier| {
                    carrier.source_installation_id = "source-installation-foreign".to_owned();
                }),
            ),
            (
                "source_schema_generation",
                with_carrier_field(intended, |carrier| {
                    carrier.source_schema_generation = "2.0.1".to_owned();
                }),
            ),
            (
                "archive_member_digest",
                with_carrier_field(intended, |carrier| {
                    carrier.archive_member_digest = TEST_HASH_A.to_owned();
                }),
            ),
            (
                "member_id",
                with_carrier_field(intended, |carrier| {
                    carrier.member_id = "member-1-foreign".to_owned();
                }),
            ),
            (
                "member_type",
                with_carrier_field(intended, |carrier| {
                    carrier.member_type = SnapshotMemberType::Blob;
                }),
            ),
            (
                "residency_domain",
                with_carrier_field(intended, |carrier| {
                    carrier.residency_domain =
                        residency_label(BlobResidencyDomain::ContentBlob).to_owned();
                }),
            ),
            (
                "content_digest",
                with_carrier_field(intended, |carrier| {
                    carrier.content_digest = TEST_HASH_B.to_owned();
                }),
            ),
            (
                "byte_count",
                with_carrier_field(intended, |carrier| {
                    carrier.byte_count += 1;
                }),
            ),
        ]
    }

    // WORK_UNIT_CASE: 2666/17 — the readback's identity half decides on all ten facts.
    //
    // The card's MAKE clause fixes the carrier stage verified "only on full
    // identity+content match", and the identity half of that match is
    // `carrier_answers_for` (:3113-3128), the comparator `read_archive_member`
    // applies before it hands a row to the readback at all. Every one of the
    // sixteen existing `2666/N` cases builds a structurally empty batch, so not
    // one carrier was ever constructed and no clause of that conjunction was ever
    // exercised. This case builds the carrier through the only lawful producer —
    // `carrier_for` (:2984), reached through `intended_archive_member_carriers`
    // (:2751) — and then mutates each of the ten identity facts exactly once.
    //
    // Measured sites: the ten facts are the ten clauses of `carrier_answers_for`;
    // the values they are compared against are the ones `carrier_for` builds at
    // :3021-3036.
    //
    // The single mutation that would kill this case is any one of the ten clauses
    // being dropped or compared against the carrier's own value instead of the
    // batch's: `carrier.byte_count == carrier.byte_count`, for instance, leaves
    // every assertion here but the `byte_count` one passing.
    #[test]
    fn the_carrier_identity_comparator_decides_on_every_one_of_its_ten_facts() {
        let batch = carrier_batch(
            "dest-carrier-identity",
            "op-carrier-identity",
            &["member-1"],
        );
        let published = intended_archive_member_carriers(&batch, &carrier_fence())
            .expect("an importable member with a retained payload publishes exactly one row");
        assert_eq!(
            published.len(),
            1,
            "one importable member publishes one carrier row; an empty set would make \
             every assertion below vacuous"
        );
        let entry = &published[0];
        let member = &entry.member;
        assert_eq!(
            member.member_id, entry.carrier.member_id,
            "the published row travels beside the member it answers for"
        );
        assert!(
            carrier_answers_for(&entry.carrier, &batch, member),
            "the carrier the producer builds must answer for its own member, or every \
             negative fact below would be satisfied by a fixture that is wrong from \
             the start"
        );

        let intended = entry.carrier.clone();
        let mutations = carrier_identity_fact_mutations(&intended);
        assert_eq!(
            mutations.len(),
            10,
            "the comparator states ten independent facts; this case holds one mutation \
             for each of them so no fact can be dropped silently"
        );
        for (fact, divergent) in &mutations {
            assert_ne!(
                *divergent, intended,
                "the `{fact}` mutation must actually change the carrier, otherwise it \
                 asserts nothing"
            );
            assert!(
                !carrier_answers_for(divergent, &batch, member),
                "identity fact `{fact}` alone must make the comparator refuse: a row that \
                 disagrees with the admitted batch or its member is an identity \
                 conflict, never a payload accepted because it looked plausible"
            );
        }
    }

    // WORK_UNIT_CASE: 2666/18 — the four content fields participate in the derived
    // equality of `ArchiveMemberCarrier`, and `carrier_answers_for` reads none of
    // them.
    //
    // What this case proves, and only this, about the two facts it executes:
    // `payload`, `payload_digest`, `class` and `record_id` each take part in the
    // derived `PartialEq` for `ArchiveMemberCarrier` — a carrier that differs in
    // any one of them compares unequal to the intended row — and the identity
    // comparator `carrier_answers_for` (:3113-3128), the comparator
    // `read_archive_member` applies before it hands a row on at all, accepts all
    // four divergences unchanged.
    //
    // What it does NOT prove, and must not be read as proving: that the
    // production readback rejects such a row. `verify_archive_member_carriers`
    // (:2827) is `async` over a live `&RpcTransport` and is never executed here,
    // so the expression this case is written about — `if existing != entry.carrier`
    // (:2838) — is neither run nor observable from these pure seams. Narrowing
    // that production comparison to the identity facts, comparing
    // `carrier_answers_for(existing, ..)` instead of the whole value, therefore
    // leaves every assertion below passing, and this case says nothing about it.
    //
    // Measured sites: the derived `PartialEq` and the four fields it covers; the
    // intended values are the ones `carrier_for` (:2984) builds at :3031-3035.
    //
    // The single mutation that would kill this case is a change to either of the
    // two facts it does execute: dropping one of these four fields from the
    // derived equality, which fails that field's `assert_ne!`, or giving
    // `carrier_answers_for` a clause that reads one of them, which fails that
    // field's `carrier_answers_for` assertion.
    #[test]
    fn the_readback_whole_value_comparison_rejects_a_content_the_identity_comparator_accepts() {
        let batch = carrier_batch("dest-carrier-content", "op-carrier-content", &["member-1"]);
        let published = intended_archive_member_carriers(&batch, &carrier_fence())
            .expect("an importable member with a retained payload publishes exactly one row");
        assert_eq!(
            published.len(),
            1,
            "the content comparison needs a real intended row to diverge from"
        );
        let entry = &published[0];
        let intended = &entry.carrier;
        assert!(
            carrier_answers_for(intended, &batch, &entry.member),
            "the producer's carrier answers for its own member before content is compared"
        );

        let divergences: [(&'static str, ArchiveMemberCarrier); 4] = [
            (
                "payload",
                with_carrier_field(intended, |carrier| {
                    carrier.payload = serde_json::json!({"body": "forged", "revision": 7});
                }),
            ),
            (
                "payload_digest",
                with_carrier_field(intended, |carrier| {
                    carrier.payload_digest = TEST_HASH_A.to_owned();
                }),
            ),
            (
                "class",
                with_carrier_field(intended, |carrier| {
                    carrier.class = RestoreRecordClass::CanonicalEvent;
                }),
            ),
            (
                "record_id",
                with_carrier_field(intended, |carrier| {
                    carrier.record_id = "receipt-member-1-foreign".to_owned();
                }),
            ),
        ];
        assert_eq!(
            divergences.len(),
            4,
            "the whole-value comparison is pinned over exactly the four content fields \
             the identity comparator never reads"
        );
        for (content_fact, existing) in &divergences {
            assert_ne!(
                *existing, *intended,
                "a carrier whose `{content_fact}` differs must not compare equal to the \
                 intended row: `existing != entry.carrier` at :2838 is the only thing \
                 that turns this row into an identity conflict instead of a verified \
                 publication"
            );
            assert!(
                carrier_answers_for(existing, &batch, &entry.member),
                "`{content_fact}` is not an identity fact: the comparator must still \
                 accept this row, which is exactly why the content half needs the \
                 whole-value comparison and can never be left to `carrier_answers_for`"
            );
        }
    }

    // WORK_UNIT_CASE: 2666/19 — the intended set holds one row per importable
    // member, in admitted order, and its two exclusions hold.
    //
    // What this case proves, and only this: the basis the readback verifies is
    // complete. The intended set holds exactly one row per importable member, in
    // admitted order, so a set that silently omitted a member could never be a set
    // that verifies; an importable member that retained no payload is refused
    // typed rather than published as a short set; and a reference edge contributes
    // no row at all.
    //
    // What it does NOT prove, and must not be read as proving: anything at all
    // about the readback loop. `verify_archive_member_carriers` (:2827) is `async`
    // over a live `&RpcTransport` and is never executed here, so its *ordering*
    // property — that it returns at the first absent or divergent row, never reads
    // the rows after it, and can answer [`CarrierVerification::Verified`] only
    // when every row agreed — is unobservable from these pure seams. Restating the
    // loop here would be a mock of the function under proof, so it is not done.
    // In particular no claim is made that "a later row still diverges": the
    // divergence asserted below compares a mutated row against that row's own
    // intended value, and row 0 never participates in it.
    //
    // Measured sites: the membership of the intended set and its two exclusions
    // are `intended_archive_member_carriers` (:2756-2788).
    //
    // The single mutation that would kill this case is building the intended set
    // from the batch's declared count instead of from its admitted members — or
    // continuing past an importable member that retains nothing — which makes the
    // published-row assertions below fail.
    #[test]
    fn the_readback_basis_covers_every_importable_member_and_a_later_divergence_still_diverges() {
        let batch = carrier_batch(
            "dest-carrier-basis",
            "op-carrier-basis",
            &["member-1", "member-2"],
        );
        let published = intended_archive_member_carriers(&batch, &carrier_fence())
            .expect("both members retain a payload, so both rows are published");
        assert_eq!(
            published.len(),
            2,
            "the set the readback verifies must hold a row per importable member; a set \
             that silently omitted one would let a short publication read as verified"
        );
        assert_eq!(
            (
                published[0].member.member_id.as_str(),
                published[1].member.member_id.as_str()
            ),
            ("member-1", "member-2"),
            "rows keep admitted order, so the loop's per-row comparison reaches both \
             members of this batch"
        );
        for entry in &published {
            assert!(
                carrier_answers_for(&entry.carrier, &batch, &entry.member),
                "every published row must answer for the member it travels beside"
            );
        }

        // What this block establishes, and no more: each row of the intended set is
        // the value its own member publishes, and a carrier differing in one row's
        // payload is unequal to that row's own intended value. Row 0 is paired and
        // equal here; it is never compared against row 1's mutated value, so
        // nothing below observes how the readback loop would treat two rows at
        // once. See the marker comment.
        let first_row_intended =
            carrier_for(&batch, &published[0].member, &batch.retained_members[0])
                .expect("the first member's own retained payload publishes a carrier");
        assert_eq!(
            first_row_intended, published[0].carrier,
            "the earlier row equals exactly what its own member publishes, so the later \
             row's divergence below is not an artifact of a mispaired set"
        );
        let divergent_second = with_carrier_field(&published[1].carrier, |carrier| {
            carrier.payload = serde_json::json!({"body": "member-2", "revision": 8});
        });
        assert_ne!(
            divergent_second, published[1].carrier,
            "a later row whose payload differs is not equal to its intended row even \
             though every earlier row agrees: the readback compares each row, not the \
             set as a whole"
        );

        // An importable member that retains nothing is refused typed, so the set can
        // never be quietly short instead of absent.
        let mut without_retained = carrier_batch(
            "dest-carrier-basis-missing",
            "op-carrier-basis-missing",
            &["member-1"],
        );
        without_retained.retained_members.clear();
        assert!(
            matches!(
                intended_archive_member_carriers(&without_retained, &carrier_fence()),
                Err(StoreError::InvalidField { .. })
            ),
            "an importable member with no retained payload must be refused before any \
             write, never published as a set that omits its row"
        );

        // A reference edge names a canonical object; it is not a payload of its own,
        // so it contributes no row and no member of the set to verify.
        let mut with_reference_edge = carrier_batch(
            "dest-carrier-basis-edge",
            "op-carrier-basis-edge",
            &["member-1"],
        );
        let edge_payload = carrier_payload_text("member-edge");
        with_reference_edge.members.push(SnapshotMember {
            member_id: "member-edge".to_owned(),
            member_type: SnapshotMemberType::Reference,
            content_digest: TEST_HASH_B.to_owned(),
            residency: BlobResidency {
                domain: BlobResidencyDomain::InlineCanonical,
                residency_digest: TEST_HASH_B.to_owned(),
                byte_count: u64::try_from(edge_payload.len())
                    .expect("a fixture payload length always fits in u64"),
            },
            reference_digest: Some(TEST_HASH_A.to_owned()),
        });
        with_reference_edge.member_count = with_reference_edge.members.len() as u64;
        let with_edge = intended_archive_member_carriers(&with_reference_edge, &carrier_fence())
            .expect("a reference edge carries no payload and is skipped, not refused");
        assert_eq!(
            with_edge.len(),
            1,
            "a reference edge is never published, so the verified set is exactly the \
             importable members"
        );
        assert_eq!(
            with_edge[0].member.member_id, "member-1",
            "the published row is the importable member's own"
        );
    }

    /// One current purge-ledger entry over this batch's own archive member
    /// digest, in the state the case names.
    ///
    /// The subject is the batch's own digest, so the entry is exactly the
    /// member-scope obligation `read_purge_ledger` returns for this batch, and
    /// the three domain labels come from [`RestoreDomains::derive`] over the same
    /// destination rather than from text invented here. `PurgeLedgerEntry::validate`
    /// is run by the case, so a fixture that the destination could never have
    /// recorded fails instead of deciding a disposition.
    fn member_scope_purge_entry(
        batch: &CanonicalRestoreBatch,
        state: PurgeLedgerState,
    ) -> PurgeLedgerEntry {
        let domains =
            RestoreDomains::derive(&batch.destination, "dest-carrier-suppressed-identity");
        PurgeLedgerEntry {
            subject: batch.archive_member_digest.clone(),
            state,
            purge_policy_revision: batch.purge_policy_revision,
            residency_domain: domains.residency,
            privacy_domain: domains.privacy,
            retention_domain: domains.retention,
        }
    }

    // An earlier incarnation handed the carrier publication to the provider and never
    // learned what became of it: this helper acquires the real attempt guard, marks the
    // carrier stage may-have-been-submitted through the production pre-poll mark, drops
    // the guard so `release` merges the exposure back into the slot, and asserts the
    // slot still carries that unproven carrier stage and an untouched apply stage.
    // Nothing here is a hand-built exposure.
    fn abandoned_carrier_publication(batch: &CanonicalRestoreBatch, config: &SurrealAdapterConfig) {
        let mut abandoned = acquire_guard(batch, config);
        abandoned
            .exposure
            .note_write_may_be_submitted(RestoreWriteStage::CarrierPublication);
        drop(abandoned);
        let Some(retained) = slot_for(batch, config) else {
            panic!("an abandoned carrier publication must keep its slot")
        };
        assert_eq!(
            retained.effect_state.carrier,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "the abandoned incarnation left the carrier stage unproven, which is the \
             inherited uncertainty this case is about"
        );
        assert_eq!(
            retained.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted,
            "only the carrier stage was submitted, so the apply stage owes nothing yet"
        );
    }

    // WORK_UNIT_CASE: 2666/20 - a suppressed disposition no longer carries an
    // inherited unproven carrier stage past the carrier stage.
    //
    // The defect this pins: the carrier decision was reachable only on the
    // `Restored` branch, while `decide_purge` re-reads the CURRENT purge ledger on
    // every invocation, so one operation identity could reach the canonical apply
    // under `Suppressed`/`Unresolved` with a carrier stage an earlier incarnation
    // had left unproven. Nothing on that path publishes a carrier row, so the
    // obligation could not be discharged by a write of its own, and `release`
    // (:1540 `!merged.any_unproven()`) can never evict a slot that still carries
    // one. What discharges it is the bounded exact carrier readback this arm now
    // attempts, and a subject the ledger keeps out of the destination has no row
    // to prove, so for it the refusal stands until the ledger changes.
    //
    // What this case executes: the real guard lifecycle that produces the inherited
    // exposure (`RestoreAttemptGuard::acquire` / `Drop` -> `release`), the real
    // `decide_purge` over a real, validated ledger entry, the real decision
    // `apply_canonical_batch` consults, the real refusal value, and the real
    // retention predicate.
    //
    // The wiring is asserted BEHAVIOURALLY, not over this file's bytes. The
    // non-`Restored` arm of `apply_canonical_batch` is one call to the production
    // helper `carrier_publication_for`, whose single production caller is that
    // arm; the helper is now `async` because it performs the bounded exact carrier
    // reconciliation, so this case executes the two provider-free halves the
    // helper is made of — the closed predicate it consults, and
    // `carrier_publication_after_reconciliation`, the verdict-to-answer mapping
    // with exactly one production caller, the helper itself — over the same
    // inherited exposure the arm would be handed. The mutations this case kills
    // are exactly the ones those two bodies can carry: a mapping that answers
    // `Ok(Vec::new())` where it must refuse — mapping `NotApplied` to `Ok` — or a
    // predicate that no longer blocks — exempting `Suppressed`/`Unresolved` from
    // it, or swapping it for one that ignores the carrier stage. Each of those
    // leaves the assertions below observing `Ok` instead of the `UnknownOutcome`
    // naming this operation, or a carrier stage left unproven where it must be
    // raised.
    //
    // What this case does NOT kill, stated plainly because the helper is now
    // `async`: **no case executes `carrier_publication_for`'s own body.** It is
    // `async` over a live `&RpcTransport`, so a mutation *inside* it — deleting
    // its `!blocks` early return, deleting its empty-intended-set guard, or
    // answering `Ok(Vec::new())` before it ever asks the predicate — leaves this
    // case green, because the case supplies that helper's two provider-free halves
    // and nothing else. What bounds the residual risk is structural only: the
    // helper has exactly one production caller (the arm) and the mapping exactly
    // one (the helper), so neither can be skipped or given a second path without
    // one of those callers changing. An earlier revision of this case asserted the
    // same wiring by reading this file's own text with `include_str!`; that
    // assertion proved nothing, because `std::hint::black_box(false) && …` around
    // the call, naming the predicate in the arm's prose comment, or an earlier
    // duplicate of the predicate's signature would all have kept every asserted
    // byte and its ordering, so it was deleted rather than patched.
    //
    // What it does NOT cover, and does not claim: `apply_canonical_batch`,
    // `carrier_publication_for` and `verify_archive_member_carriers` are all
    // `async` over a live `&RpcTransport` obtained from `restore_transport(self)`,
    // so whether the arm is *reached* on any given invocation — and whether the
    // reconciliation it now attempts answers `Verified`, `NotApplied` or a
    // conflict against a real provider — cannot be observed here; the card assigns
    // those poll/drop proofs to the assembled-product test phase. The verdicts
    // below are therefore supplied to the production mapping, never obtained from
    // a readback.
    //
    // Measured sites: the hoisted arm inside the `let published = if
    // scope_disposition == MemberDisposition::Restored` arm; the helper and the
    // mapping it alone calls; the predicate it consults; the refusal it equals,
    // which is the carrier publication's *refusal* arm `NotApplied` value and the
    // `check_cancellation` value — not the publication's final `NotApplied` arm,
    // which is `StoreError::MissingReceiptEnvelope`; the apply-stage gate that does
    // NOT answer this schedule; the retention predicate in
    // `RestoreAttemptGuard::release`.
    #[test]
    fn a_suppressed_disposition_blocks_on_an_inherited_unproven_carrier_stage() {
        let _serial = ledger_serial();
        let config = scoped_config("store-carrier-suppressed", "install-carrier-suppressed");
        let batch = scoped_batch("dest-carrier-suppressed", "op-carrier-suppressed");
        forget_slot(&batch, &config);
        let operation_id = batch.operation.operation_id.as_str();

        // An earlier incarnation handed the carrier publication to the provider
        // and never learned what became of it.
        abandoned_carrier_publication(&batch, &config);

        // The later incarnation of the same identity. Reacquisition hands it the
        // retained stage and nothing else.
        let exact = acquire_guard(&batch, &config);
        assert_eq!(
            exact.exposure.carrier_stage(),
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "the later incarnation inherits the unproven carrier stage, so the \
             disposition it now reads is the only thing that can decide whether the \
             operation still owes a carrier reconciliation"
        );
        assert_eq!(
            exact.exposure.apply_stage(),
            RestoreEffectState::NoWriteSubmitted,
            "this incarnation submitted no apply, so the apply-stage gate at :4627 \
             does not answer this schedule at all"
        );
        assert!(
            !exact.exposure.apply_stage().is_unproven(),
            "the apply stage is not unproven here, which is exactly why the \
             per-stage apply gate cannot close this hole and the carrier stage must"
        );

        // The disposition, decided by the production `decide_purge` over an entry
        // the destination could actually have recorded.
        let purged = member_scope_purge_entry(&batch, PurgeLedgerState::Purged);
        let requested = member_scope_purge_entry(&batch, PurgeLedgerState::Requested);
        purged
            .validate()
            .expect("a member-scope entry over this batch's own digest is recordable");
        requested
            .validate()
            .expect("a requested obligation is recordable too, and is not complete");
        assert!(
            matches!(decide_purge(Some(&purged), None), PurgeDecision::Suppressed),
            "a durably complete obligation over the member scope suppresses it"
        );
        assert!(
            matches!(
                decide_purge(Some(&requested), None),
                PurgeDecision::Unresolved
            ),
            "a recorded but incomplete obligation leaves the scope unresolved"
        );
        assert!(
            matches!(decide_purge(None, None), PurgeDecision::Clear),
            "no recorded obligation is the only reading that reaches the carrier \
             publication branch, and the contrast is what makes the two suppressed \
             verdicts above legible"
        );

        // The decision the branch consults, over that inherited exposure.
        for suppressed in [MemberDisposition::Suppressed, MemberDisposition::Unresolved] {
            assert!(
                purge_disposition_blocks_on_unproven_carrier(suppressed, exact.exposure),
                "{suppressed:?} publishes no carrier row of its own, so an inherited \
                 unproven carrier stage must first be reconciled by the bounded exact \
                 readback instead of riding into the canonical apply"
            );
        }
        assert!(
            !purge_disposition_blocks_on_unproven_carrier(
                MemberDisposition::Restored,
                exact.exposure
            ),
            "the Restored branch reaches resolve_carrier_stage and answers the stage \
             by exact readback, so it must never be blocked here: that would close \
             the same-identity carrier retry the card clause requires"
        );

        // The contrast: nothing about the purge decision itself is blocked.
        suppressed_disposition_waves_through_an_answered_carrier_stage();

        // The refusal is the typed unknown outcome the carrier path already
        // returns for an unproven publication, naming this operation.
        assert_carrier_refusal_is_the_typed_unknown(operation_id);

        // The wiring itself, executed rather than asserted over this file's bytes.
        //
        // The non-`Restored` arm of `apply_canonical_batch` is exactly one call to
        // `carrier_publication_for`, and that helper has no other production caller.
        // The helper is `async` because it attempts the bounded exact carrier
        // reconciliation, so what this block executes is the two provider-free
        // halves it is made of — the closed predicate and
        // `carrier_publication_after_reconciliation`, the verdict-to-answer mapping
        // the helper alone calls — over the same inherited exposure the arm would
        // be handed.
        //
        // The mutations this kills are a helper or a mapping that answers
        // `Ok(Vec::new())` where it must refuse: the refusal replaced by an empty
        // published set, `Suppressed`/`Unresolved` exempted from the predicate, a
        // predicate swapped for one that ignores the carrier stage, or
        // `NotApplied` mapped to `Ok`. Every such mutation leaves the predicate
        // assertions above passing, and this block observes `Ok` where it requires
        // the typed `UnknownOutcome` naming this operation, or a carrier stage
        // raised where it must stay unproven. It reads no source text, so
        // `std::hint::black_box(false) && …` around a production call, the
        // predicate's name appearing in the arm's prose comment, and an earlier
        // duplicate of the predicate's signature all fail to affect it. What it
        // cannot observe is the arm's *reachability* on a live provider, nor the
        // readback that produces the verdict — see the marker comment above.
        let inherited = exact.exposure;
        carrier_publication_arm_decides_by_disposition_and_stage(inherited, operation_id);

        // The blocked invocation wrote nothing, so the obligation it inherited must
        // survive it untouched and keep the slot retained.
        drop(exact);
        let Some(after) = slot_for(&batch, &config) else {
            panic!("the blocked invocation must release only its local running owner")
        };
        assert_eq!(
            after.effect_state.carrier,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "inherited uncertainty is never reset by an invocation that has not \
             written: the carrier stage is exactly what it was"
        );
        assert_eq!(
            after.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted,
            "the refused invocation submitted no canonical apply"
        );
        assert!(
            after.effect_state.any_unproven(),
            "the open obligation is what keeps the slot retained, so the identity \
             waits for carrier reconciliation and is never silently evicted"
        );
        forget_slot(&batch, &config);
    }

    /// The production `carrier_publication_for` decision table, executed at the two
    /// provider-free halves that helper is made of. The arm consults the closed
    /// predicate and, when that predicate blocks, turns the bounded exact carrier
    /// reconciliation's own verdict into its answer; both halves have exactly one
    /// production caller each (the helper, and the arm for the helper). This
    /// executes both over the same inherited exposure the arm would be handed, so
    /// a predicate that ignores the carrier stage, a mapping that answers `Ok`
    /// where it must refuse, and a `NotApplied` mapped to `Ok` all fail here.
    ///
    /// It reads no source text, so a `black_box(false) &&` conjunct around a
    /// production call cannot hide from it. What it cannot observe is the arm's
    /// reachability on a live provider, nor the readback that produces the verdict
    /// it supplies here; see the marker comment.
    fn carrier_publication_arm_decides_by_disposition_and_stage(
        inherited: RestoreEffectExposure,
        operation_id: &str,
    ) {
        for suppressed in [MemberDisposition::Suppressed, MemberDisposition::Unresolved] {
            assert!(
                purge_disposition_blocks_on_unproven_carrier(suppressed, inherited),
                "{suppressed:?} owes a carrier reconciliation, so the arm must reach \
                 the bounded exact readback before it may proceed"
            );
            // An absent row is what the readback reports about that create-only
            // transaction, and it discharges nothing.
            let mut after_absence = inherited;
            match carrier_publication_after_reconciliation(
                &CarrierVerification::NotApplied,
                &mut after_absence,
                operation_id,
            ) {
                Err(refusal) => assert!(
                    matches!(
                        refusal,
                        StoreError::UnknownOutcome { operation_id: reported }
                            if reported.as_str() == operation_id
                    ),
                    "an absent carrier row leaves the arm's answer the existing typed \
                     unknown outcome over this operation identity — no new variant and \
                     no new reason string"
                ),
                Ok(_) => panic!(
                    "{suppressed:?} owes a carrier reconciliation that an absent row \
                     cannot discharge, so the arm must refuse instead of returning a \
                     carrier set"
                ),
            }
            assert!(
                after_absence.carrier_stage().is_unproven(),
                "a refused reconciliation leaves the carrier stage exactly where it \
                 was: inherited uncertainty is never reset by an invocation that has \
                 not written"
            );
            // Every row present and equal to the intended carrier discharges the
            // stage, and this disposition still publishes nothing of its own.
            let mut after_proof = inherited;
            let published = carrier_publication_after_reconciliation(
                &CarrierVerification::Verified,
                &mut after_proof,
                operation_id,
            )
            .expect("a proved carrier reconciliation owes nothing, so the arm proceeds");
            assert!(
                published.is_empty(),
                "{suppressed:?} publishes no carrier row of its own, so a proved stage \
                 yields an empty set rather than a publication"
            );
            assert_eq!(
                after_proof.carrier_stage(),
                RestoreEffectState::DurableResultVerified,
                "the exact readback raises the carrier stage through the same \
                 `note_carrier_verified` every other carrier readback uses"
            );
        }
        // A `Restored` disposition never takes that path at all: it is decided by
        // exact carrier readback in `resolve_carrier_stage`, and gating it here
        // would close the same-identity carrier retry the card clause requires.
        assert!(
            !purge_disposition_blocks_on_unproven_carrier(MemberDisposition::Restored, inherited),
            "Restored is exempt from the carrier gate: it reaches \
             `resolve_carrier_stage` and its bounded exact readback instead, so \
             nothing here may close that path"
        );

        for suppressed in [MemberDisposition::Suppressed, MemberDisposition::Unresolved] {
            // A carrier stage an exact readback already proved.
            let mut proved = RestoreEffectExposure::new(RestoreStageExposure {
                carrier: RestoreEffectState::WriteMayHaveBeenSubmitted,
                apply: RestoreEffectState::NoWriteSubmitted,
            });
            proved.note_carrier_verified();
            assert!(
                !purge_disposition_blocks_on_unproven_carrier(suppressed, proved),
                "a proved carrier stage owes nothing, so the arm proceeds with an \
                 empty published set rather than reading anything back"
            );
            // A carrier stage that was never submitted at all.
            let never = RestoreEffectExposure::new(RestoreStageExposure::NONE);
            assert!(
                !purge_disposition_blocks_on_unproven_carrier(suppressed, never),
                "a slot that never submitted a carrier write owes nothing, so the arm \
                 proceeds rather than reading anything back"
            );
        }
    }

    /// A slot that never submitted a carrier write proceeds, and a slot whose carrier
    /// stage was proved proceeds: the gate answers inherited uncertainty only, and
    /// never the purge decision itself.
    fn suppressed_disposition_waves_through_an_answered_carrier_stage() {
        let fresh = RestoreEffectExposure::new(RestoreStageExposure::NONE);
        assert!(
            !purge_disposition_blocks_on_unproven_carrier(MemberDisposition::Suppressed, fresh),
            "a suppressed batch whose slot never submitted a carrier write is \
             unchanged by this gate; the gate answers inherited uncertainty only"
        );
        let mut proved = RestoreEffectExposure::new(RestoreStageExposure {
            carrier: RestoreEffectState::WriteMayHaveBeenSubmitted,
            apply: RestoreEffectState::NoWriteSubmitted,
        });
        proved.note_carrier_verified();
        assert!(
            !purge_disposition_blocks_on_unproven_carrier(MemberDisposition::Suppressed, proved),
            "an exact carrier readback discharges the stage, so the same identity \
             proceeds under a suppressed disposition without waiting"
        );
    }

    /// The refusal the suppressed branch answers with is the typed unknown outcome the
    /// carrier path already returns for an unproven publication, naming this
    /// operation — not a retryable refusal and not a receipt failure.
    fn assert_carrier_refusal_is_the_typed_unknown(operation_id: &str) {
        let refusal = unknown_outcome(operation_id);
        assert!(
            matches!(
                &refusal,
                StoreError::UnknownOutcome { operation_id: reported }
                    if reported.as_str() == operation_id
            ),
            "the block must answer with the typed unknown outcome over this operation \
             identity, so it reconciles by identity instead of reporting success"
        );
        assert_ne!(
            refusal,
            StoreError::Unavailable,
            "a clean retryable refusal would understate an unknown external effect"
        );
        assert_ne!(
            refusal,
            StoreError::MissingReceiptEnvelope,
            "the refusal is not a receipt-envelope failure: nothing is missing, the \
             outcome is unknown"
        );
    }

    // WORK_UNIT_CASE: 2666/21 - a reconciliation that proved the carriers lifts the
    // suppressed-disposition block for every inherited carrier stage.
    //
    // What this pins: the card clause "carrier unknown -> block only until carrier
    // reconciliation" is only a bounded block if the reconciliation can end it. The
    // non-`Restored` arm of `apply_canonical_batch` consults the closed predicate
    // and, when that predicate answers "blocks", turns the bounded exact carrier
    // readback's own verdict into its answer through
    // `carrier_publication_after_reconciliation`. A proved set must therefore be an
    // exit for EVERY stage an earlier incarnation could have left, not only for one
    // hand-picked one, and the stage it leaves behind must be the production raise
    // rather than a silent continuation.
    //
    // What this case executes: the real `RestoreEffectExposure` constructor, the
    // real `note_carrier_verified` the reconciliation itself calls, the real
    // closed predicate, and the real verdict-to-answer mapping this module's
    // production helper alone calls. It asserts the returned `Result` and its exact
    // value, so a mapping that refused on `Verified`, returned a non-empty carrier
    // set, or skipped the raise fails here; and a predicate that blocked a proved
    // carrier stage fails on the predicate assertion.
    //
    // What it does NOT cover, and does not claim: the reconciliation itself is
    // `async` over a live `RpcTransport` inside the production helper, so NO case
    // here executes a carrier readback — the `CarrierVerification` this case
    // supplies to the production mapping is an input, never a result obtained from
    // a provider. For the same reason the ordering property of
    // `verify_archive_member_carriers` itself is deliberately NOT restated or
    // mocked here: restating it would be asserting a copy of the function under
    // proof rather than the function. Whether the arm reaches the readback on a
    // live provider, and what a real readback answers, stay with the controlled
    // poll/drop proofs the card assigns to the assembled-product test phase. The
    // case name is not weakened to hide this: it claims the block is liftable once
    // the reconciliation proves the carriers, and claims nothing about reaching it.
    #[test]
    fn a_proved_carrier_reconciliation_lifts_the_block_for_every_inherited_carrier_stage() {
        let _serial = ledger_serial();
        let config = scoped_config("store-carrier-reconciled", "install-carrier-reconciled");
        let batch = scoped_batch("dest-carrier-reconciled", "op-carrier-reconciled");
        forget_slot(&batch, &config);
        let operation_id = batch.operation.operation_id.as_str();

        // Every state the closed carrier stage can carry, including the two that
        // keep the slot reconciliation-required and the two that do not.
        let every_stage = [
            RestoreEffectState::NoWriteSubmitted,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            RestoreEffectState::ResponseObserved,
            RestoreEffectState::DurableResultVerified,
        ];
        // The control every loop below is read against: an unproven carrier stage,
        // which the predicate blocks for a suppressed disposition and never blocks
        // for a restored one.
        let unproven = RestoreEffectExposure::new(RestoreStageExposure {
            carrier: RestoreEffectState::WriteMayHaveBeenSubmitted,
            apply: RestoreEffectState::NoWriteSubmitted,
        });
        assert!(
            unproven.carrier_stage().is_unproven(),
            "the control exposure really does owe a carrier reconciliation, so the \
             `Restored` answer below is a contrast and not a tautology"
        );
        assert!(
            !purge_disposition_blocks_on_unproven_carrier(MemberDisposition::Restored, unproven),
            "`Restored` reaches `resolve_carrier_stage` and its own readback, so the \
             predicate must answer false for it even on this unproven exposure"
        );

        for stage in every_stage {
            let was_unproven = stage.is_unproven();
            assert_eq!(
                was_unproven,
                matches!(
                    stage,
                    RestoreEffectState::WriteMayHaveBeenSubmitted
                        | RestoreEffectState::ResponseObserved
                ),
                "the sweep covers the whole closed stage enum, and only the two \
                 intermediate states may keep the slot reconciliation-required"
            );
            let mut exposure = RestoreEffectExposure::new(RestoreStageExposure {
                carrier: stage,
                apply: RestoreEffectState::NoWriteSubmitted,
            });
            assert_eq!(
                exposure.carrier_stage(),
                stage,
                "an invocation inherits exactly the carrier stage its predecessor left"
            );
            // The one raise the production reconciliation performs, applied here
            // because the readback that would perform it needs a live provider.
            exposure.note_carrier_verified();
            assert_eq!(
                exposure.carrier_stage(),
                RestoreEffectState::DurableResultVerified,
                "the production raise lifts every prior stage, including the two that \
                 were unproven and the one that had submitted nothing at all"
            );
            assert!(
                !exposure.carrier_stage().is_unproven(),
                "after the raise the stage owes nothing whatever"
            );

            for suppressed in [MemberDisposition::Suppressed, MemberDisposition::Unresolved] {
                assert!(
                    !purge_disposition_blocks_on_unproven_carrier(suppressed, exposure),
                    "{suppressed:?} with a stage an exact carrier readback already \
                     proved owes nothing, so the block this case is about is lifted"
                );
                let published = carrier_publication_after_reconciliation(
                    &CarrierVerification::Verified,
                    &mut exposure,
                    operation_id,
                )
                .expect(
                    "a proved carrier reconciliation must not refuse: the block is \
                     bounded by the reconciliation, and this is the reconciliation",
                );
                assert!(
                    published.is_empty(),
                    "{suppressed:?} publishes no carrier row of its own, so the \
                     decision yields an empty published set and publishes nothing"
                );
                assert_eq!(
                    exposure.carrier_stage(),
                    RestoreEffectState::DurableResultVerified,
                    "the decision raised the carrier stage and left it raised"
                );
            }
        }

        forget_slot(&batch, &config);
    }

    // WORK_UNIT_CASE: 2666/22 - an unproven carrier stage with no reconciliation
    // still refuses, and refuses with this operation's own typed unknown outcome.
    //
    // What this pins: making the block reachable-for-lifting must not make it
    // optional. An invocation that inherits an unproven carrier stage and whose
    // reconciliation did not prove the rows still owes the obligation, still
    // publishes nothing, and still answers the typed
    // `StoreError::UnknownOutcome` over THIS operation identity — the card clause
    // "carrier unknown -> block only until carrier reconciliation" forbids a second
    // publication and forbids the fresh-write branch until the rows are read back.
    //
    // What this case executes: the real guard lifecycle that produces the inherited
    // exposure (`RestoreAttemptGuard::acquire` / `Drop` -> `release`, plus the
    // production pre-poll carrier mark), so the exposure is never hand-built here;
    // the real closed predicate; the real verdict-to-answer mapping; and the real
    // refusal value. It asserts the returned `Result` and its exact value, so a
    // mapping that answered `Ok` for an absent row, or a different variant, or an
    // operation id other than this one, fails here. The `Restored` contrast
    // assertion is the control: the same predicate must answer `false` for
    // `MemberDisposition::Restored` on that same unproven exposure, so this case
    // cannot pass by a predicate that blocks everything.
    //
    // What it does NOT cover, and does not claim: the reconciliation itself is
    // `async` over a live `RpcTransport` inside the production helper, so NO case
    // here executes a carrier readback; `CarrierVerification::NotApplied` is
    // supplied to the production mapping here, never obtained from a provider, and
    // the ordering property of `verify_archive_member_carriers` is deliberately not
    // restated or mocked here, because restating it would assert a copy of the
    // function under proof rather than the function. Whether the arm reaches the
    // readback on a live provider stays with the controlled poll/drop proofs the
    // card assigns to the assembled-product test phase.
    #[test]
    fn an_unreconciled_carrier_stage_still_refuses_this_operations_typed_unknown() {
        let _serial = ledger_serial();
        let config = scoped_config("store-carrier-unreconciled", "install-carrier-unreconciled");
        let batch = scoped_batch("dest-carrier-unreconciled", "op-carrier-unreconciled");
        forget_slot(&batch, &config);
        let operation_id = batch.operation.operation_id.as_str();

        // An earlier incarnation handed the carrier publication to the provider and
        // never learned what became of it, so this identity inherits an obligation.
        abandoned_carrier_publication(&batch, &config);
        let exact = acquire_guard(&batch, &config);
        let inherited = exact.exposure;
        assert!(
            inherited.carrier_stage().is_unproven(),
            "the inherited carrier stage is unproven, which is the only thing that \
             could make the arm wait"
        );

        // The control: the same predicate, the same unproven exposure, and a
        // disposition that reaches its own readback instead of this gate.
        assert!(
            !purge_disposition_blocks_on_unproven_carrier(MemberDisposition::Restored, inherited),
            "`Restored` must never be blocked here: it reaches `resolve_carrier_stage` \
             and the same-identity carrier retry the card clause requires"
        );

        for suppressed in [MemberDisposition::Suppressed, MemberDisposition::Unresolved] {
            assert!(
                purge_disposition_blocks_on_unproven_carrier(suppressed, inherited),
                "{suppressed:?} publishes no carrier row of its own, so an inherited \
                 unproven carrier stage is owed a reconciliation before the canonical \
                 apply may run"
            );
            let mut exposure = inherited;
            // `PublishedCarrier` carries no `Debug`, so the refusal is taken by
            // `let...else` rather than `expect_err`.
            let Err(refusal) = carrier_publication_after_reconciliation(
                &CarrierVerification::NotApplied,
                &mut exposure,
                operation_id,
            ) else {
                panic!(
                    "an absent carrier row discharges nothing, so the arm must refuse \
                     instead of returning a carrier set"
                );
            };
            assert!(
                matches!(
                    &refusal,
                    StoreError::UnknownOutcome { operation_id: reported }
                        if reported.as_str() == operation_id
                ),
                "the refusal is the existing typed unknown outcome over THIS \
                 operation identity: no new variant, no new reason string, and never a \
                 receipt for an effect nobody proved"
            );
            assert_eq!(
                refusal,
                unknown_outcome(operation_id),
                "and it is exactly the value the carrier publication's *refusal* arm \
                 returns for `NotApplied` and the value `check_cancellation` returns — \
                 not that function's final `NotApplied` arm, which is \
                 `StoreError::MissingReceiptEnvelope`"
            );
            assert!(
                exposure.carrier_stage().is_unproven(),
                "a refused reconciliation leaves the carrier stage exactly where it \
                 was: inherited uncertainty is never reset by an invocation that has \
                 not written"
            );

            // The refusal is conditional on the verdict, not a constant answer: the
            // same exposure with a proved set proceeds. Without this the case could
            // not distinguish a real decision from a blanket refusal.
            let mut proved = inherited;
            let published = carrier_publication_after_reconciliation(
                &CarrierVerification::Verified,
                &mut proved,
                operation_id,
            )
            .expect("the same exposure proceeds once the reconciliation proves the rows");
            assert!(
                published.is_empty(),
                "and a proved reconciliation under {suppressed:?} still publishes no \
                 carrier row of its own"
            );
        }

        // The refused invocation wrote nothing, so the obligation it inherited must
        // survive it untouched and keep the slot retained.
        drop(exact);
        let Some(after) = slot_for(&batch, &config) else {
            panic!("the refused invocation must release only its local running owner")
        };
        assert_eq!(
            after.effect_state.carrier,
            RestoreEffectState::WriteMayHaveBeenSubmitted,
            "the open obligation is exactly what it was before the refusal"
        );
        assert!(
            after.effect_state.any_unproven(),
            "which is what keeps the slot retained: the identity waits for carrier \
             reconciliation and is never silently evicted"
        );
        forget_slot(&batch, &config);
    }

    // WORK_UNIT_CASE: 2666/23 - an inherited proved carrier stage is re-proved by
    // this request's own readback of its own intended set, never believed.
    //
    // The defect this pins: `attempt_slot_key_from_components` binds the owner
    // namespace, the destination id and the operation id, and it does NOT bind
    // `canonical_request_hash`, so two admitted batches that share a destination
    // and an operation id and differ only in their canonical request hash share one
    // slot. `resolve_carrier_stage` answered an inherited
    // `DurableResultVerified` with `Ok(Some(..))` for the CURRENT batch's intended
    // set without reading anything back, so a stage that was proved for the FIRST
    // request's rows was believed for the SECOND request's. That belief is not
    // harmless: `carrier_answers_for` compares the ten identity facts it compares,
    // and `class`, `record_id`, `payload` and `payload_digest` are not among them,
    // so the first request's durable row answers for the second — and the import
    // then takes its class, record id and payload from that row rather than from
    // the second request's own retained members. The apply gate cannot catch it
    // (the second request submitted no apply) and `check_record_binding`, the only
    // place `canonical_request_hash` is compared, is never reached because no
    // record row exists yet. On the create-only path the same schedule is refused
    // instead, as the existing typed `IdentityConflict`.
    //
    // What this case executes: the production slot-key derivation over two real
    // batches that differ only in `canonical_request_hash`; the real
    // `RestoreAttemptGuard` lifecycle that puts a proved carrier stage into the
    // slot the second request then inherits; and the closed branch decision
    // `carrier_stage_requires_readback` — the whole decision
    // `resolve_carrier_stage` makes before it reads anything — over all four
    // states of the closed carrier stage.
    //
    // The single mutation this kills is a `carrier_stage_requires_readback` that
    // exempts a proved stage, which is exactly the bypass that was there:
    // `!= NoWriteSubmitted` replaced by `!is_unproven()` answers `false` for
    // `DurableResultVerified`, and the assertion over the inherited proved stage
    // then reads `false` and fails. The branch-order assertions fail the same way
    // if the never-submitted answer is dropped in the other direction.
    //
    // What it does NOT cover, and does not claim: `resolve_carrier_stage` and
    // `verify_archive_member_carriers` are `async` over a live `RpcTransport`, so
    // NO case here executes the readback. The case asserts the decision that
    // PRECEDES that readback and supplies verdicts to the production mapping; it
    // deliberately does not restate `verify_archive_member_carriers`' loop, because
    // restating it would be a mock of the function under proof. Whether the branch
    // is reached on a live provider, and what a real readback of the second
    // request's rows against the first request's row answers, stay with the
    // controlled poll/drop proofs the card assigns to the assembled-product test
    // phase. Re-inserting a bypass ABOVE the closed decision — a second early
    // return inside `resolve_carrier_stage` — is likewise not observable from
    // here; what bounds that residual risk is structural only, that the decision
    // has exactly one production caller.
    #[test]
    fn an_inherited_proved_carrier_stage_is_reproved_by_this_requests_own_readback() {
        let _serial = ledger_serial();
        let config = scoped_config("store-carrier-reproof", "install-carrier-reproof");
        let first = scoped_batch("dest-carrier-reproof", "op-carrier-reproof");
        forget_slot(&first, &config);
        // Two admitted requests under ONE operation id and ONE destination, which
        // differ only in the request commitment.
        let mut second = scoped_batch("dest-carrier-reproof", "op-carrier-reproof");
        second.operation.canonical_request_hash = TEST_HASH_B.to_owned();

        two_requests_under_one_operation_id_share_the_owner_slot(&first, &second, &config);
        let inherited = the_second_request_inherits_the_first_requests_proved_carrier_stage(
            &first, &second, &config,
        );
        the_carrier_stage_is_read_back_unless_it_submitted_nothing();
        a_proved_carrier_stage_is_answered_by_the_verdict_not_by_its_own_name(
            inherited,
            second.operation.operation_id.as_str(),
        );

        forget_slot(&second, &config);
    }

    /// Half of case 2666/23: the two requests really are different requests, and
    /// the owner-scoped slot key does not separate them. Executed over the
    /// production key derivation, so the fact the re-proof exists for is observed
    /// rather than asserted in prose.
    fn two_requests_under_one_operation_id_share_the_owner_slot(
        first: &CanonicalRestoreBatch,
        second: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
    ) {
        assert_ne!(
            first.operation.canonical_request_hash, second.operation.canonical_request_hash,
            "these are two different requests, not one request twice"
        );
        let (active_store, active_installation) = active_store_identity(config);
        assert_eq!(
            attempt_slot_key(
                &active_store,
                &active_installation,
                &first.destination,
                &first.operation
            ),
            attempt_slot_key(
                &active_store,
                &active_installation,
                &second.destination,
                &second.operation
            ),
            "the owner-scoped slot key binds the namespace, the destination and the \
             operation id and not `canonical_request_hash`, so both requests share \
             one slot — which is precisely why a stage proved for the first must be \
             re-proved for the second"
        );
    }

    /// Half of case 2666/23: the schedule the re-proof answers, produced by the
    /// real guard lifecycle rather than by a hand-built exposure. The first
    /// request's own readback proves its carriers and its apply is never
    /// submitted; the second request then reacquires the same slot and inherits
    /// that proved stage beside an apply stage that owes nothing.
    ///
    /// Returns the inherited exposure so the caller can hand the very same value
    /// to the verdict half. The guard it acquires is dropped before it returns,
    /// so the assertions here run against the merged slot rather than against a
    /// live owner.
    fn the_second_request_inherits_the_first_requests_proved_carrier_stage(
        first: &CanonicalRestoreBatch,
        second: &CanonicalRestoreBatch,
        config: &SurrealAdapterConfig,
    ) -> RestoreEffectExposure {
        let mut published_first = acquire_guard(first, config);
        published_first.exposure.note_carrier_verified();
        drop(published_first);
        let Some(after_first) = slot_for(first, config) else {
            panic!("a slot carrying a proved carrier stage must be retained")
        };
        assert_eq!(
            after_first.effect_state.carrier,
            RestoreEffectState::DurableResultVerified,
            "the first request's own exact readback raised its carrier stage"
        );
        assert_eq!(
            after_first.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted,
            "and it submitted no apply, which is why the apply-stage gate cannot \
             answer this schedule at all"
        );

        let second_request = acquire_guard(second, config);
        let inherited = second_request.exposure;
        assert_eq!(
            inherited.carrier_stage(),
            RestoreEffectState::DurableResultVerified,
            "so the second request begins with a stage that was proved for \
             somebody else's rows"
        );
        assert!(
            !inherited.apply_stage().is_unproven(),
            "and its own apply stage carries no obligation, so nothing before the \
             carrier stage refuses it"
        );

        // The re-proof is what the second request owes, and it is owed for a stage
        // this slot already calls proved.
        assert!(
            carrier_stage_requires_readback(inherited),
            "an inherited proved stage owes this request its own bounded exact \
             readback: the stage was proved for whichever invocation proved it, and \
             the slot key does not bind the request commitment"
        );

        drop(second_request);
        let Some(after_second) = slot_for(second, config) else {
            panic!("the second invocation must release only its local running owner")
        };
        assert_eq!(
            after_second.effect_state.carrier,
            RestoreEffectState::DurableResultVerified,
            "this invocation wrote nothing, so the merged carrier stage is exactly \
             what it inherited: never lowered, and never raised by an invocation \
             that read nothing"
        );
        assert_eq!(
            after_second.effect_state.apply,
            RestoreEffectState::NoWriteSubmitted,
            "this invocation submitted no canonical apply either"
        );
        inherited
    }

    /// Half of case 2666/23: the branch order of `resolve_carrier_stage`, over the
    /// whole closed carrier stage. Only a stage that submitted no carrier write
    /// skips the readback and reaches the publication; an unproven stage and a
    /// proved one both reach it.
    fn the_carrier_stage_is_read_back_unless_it_submitted_nothing() {
        for (stage, owes_readback) in [
            (RestoreEffectState::NoWriteSubmitted, false),
            (RestoreEffectState::WriteMayHaveBeenSubmitted, true),
            (RestoreEffectState::ResponseObserved, true),
            (RestoreEffectState::DurableResultVerified, true),
        ] {
            let exposure = RestoreEffectExposure::new(RestoreStageExposure {
                carrier: stage,
                apply: RestoreEffectState::NoWriteSubmitted,
            });
            assert_eq!(
                carrier_stage_requires_readback(exposure),
                owes_readback,
                "{stage:?} must map to {owes_readback}: only a stage that submitted \
                 no carrier write skips the readback and reaches the publication, and \
                 an unproven stage and a proved one both reach it"
            );
        }
    }

    /// Half of case 2666/23: the decision for a proved stage comes from the
    /// readback's verdict, never from the stage alone — one stage, two verdicts,
    /// two answers, on the inherited exposure the previous half returned. The
    /// mapping used here is this file's provider-free verdict-to-answer mapping,
    /// not a restatement of the readback that would produce a verdict.
    fn a_proved_carrier_stage_is_answered_by_the_verdict_not_by_its_own_name(
        inherited: RestoreEffectExposure,
        operation_id: &str,
    ) {
        let mut proved = inherited;
        let published = carrier_publication_after_reconciliation(
            &CarrierVerification::Verified,
            &mut proved,
            operation_id,
        )
        .expect("a readback that proves this request's own rows answers a publication");
        assert!(
            published.is_empty(),
            "and the caller then owns no carrier work: nothing is republished"
        );
        assert_eq!(
            proved.carrier_stage(),
            RestoreEffectState::DurableResultVerified,
            "the stage stays proved on the strength of this request's own rows"
        );
        let mut absent = inherited;
        let Err(refusal) = carrier_publication_after_reconciliation(
            &CarrierVerification::NotApplied,
            &mut absent,
            operation_id,
        ) else {
            panic!(
                "an absent row is not proof of non-commit, so the same proved stage \
                 must reach the publication instead of being answered here"
            );
        };
        assert!(
            matches!(
                &refusal,
                StoreError::UnknownOutcome { operation_id: reported }
                    if reported.as_str() == operation_id
            ),
            "so the same stage, the same request and a different verdict produce a \
             different answer: the stage alone decides nothing"
        );
    }
}
