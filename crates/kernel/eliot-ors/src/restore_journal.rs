//! Owner-neutral durable restore journal records (issue #957).
//!
//! The journal is an ORS recovery substrate, not a restore algorithm. It binds
//! the exact transaction and phase slot supplied by the future
//! `RestoreJournalPort` adapter to a source archive, destination, admitted
//! writer/fence, immutable request/body digests, predecessor and opaque
//! payload. The ORS owner never interprets the payload or grants authority.
//!
//! Every payload and receipt is a versioned [`RecoveryPayloadEnvelope`]. A
//! decoded envelope is still only opaque recovery material: its operation id,
//! fence and payload digest are checked against the journal row, while its
//! contents remain outside this owner's semantics.

use serde::{Deserialize, Serialize};

use crate::OrsError;
use crate::model::RecoveryPayloadEnvelope;

/// Stable journal row wire schema. The additive v2 migration adds owner
/// indexes and closure metadata without reinterpreting this row shape.
pub const RESTORE_JOURNAL_RECORD_SCHEMA: &str = "restore-journal-v1";
/// Additive journal table/index schema version owned by this module.
pub const RESTORE_JOURNAL_SCHEMA_VERSION: u32 = 2;
/// Maximum one opaque journal payload: one MiB. Larger payloads are separate
/// blob references, never inline journal rows.
pub const MAX_JOURNAL_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum rows returned by one bounded journal read.
pub const MAX_JOURNAL_PAGE_ENTRIES: usize = 256;
/// Maximum stream-key length: bounded opaque identities only.
pub const MAX_JOURNAL_STREAM_KEY_BYTES: usize = 512;
/// A journal history is bounded by the existing ORS recovery-page ceiling.
/// The value is an owner limit, not a restore phase or retention policy.
pub(crate) const MAX_JOURNAL_HISTORY_ENTRIES: usize = MAX_JOURNAL_PAGE_ENTRIES;
/// Aggregate journal bytes reuse the existing ORS backup byte ceiling rather
/// than introducing a second policy owner.
#[allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    reason = "the existing ORS backup byte ceiling is below the supported usize range"
)]
pub(crate) const MAX_JOURNAL_TOTAL_BYTES: usize = crate::backup_snapshot::MAX_BACKUP_BYTES as usize;
/// Aggregate table-scan work reuses the existing replay-page ceiling. A
/// corrupt or unexpectedly large history is rejected before it can become an
/// unbounded read or prune operation. This ceiling also bounds the durable
/// pruned phase-slot tombstones, which accumulate as history is pruned.
#[allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    reason = "the existing u16 replay-page ceiling fits the supported usize range"
)]
pub(crate) const MAX_JOURNAL_WORK_ENTRIES: usize =
    MAX_JOURNAL_PAGE_ENTRIES * crate::MAX_REPLAY_PAGE as usize;

/// Closed archive-class vocabulary bound in journal operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreJournalArchiveClass {
    FullRecovery,
    CanonicalOnlyDegraded,
    ScopeExport,
}

/// Exact predecessor for compare-and-append.
///
/// A genesis append carries `None`; every later append names the current head
/// `(sequence, digest)`. Two writers cannot both advance the same head: the
/// second compare fails against the advanced predecessor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalPredecessor {
    pub sequence: u64,
    pub digest: String,
}

impl JournalPredecessor {
    pub fn validate(&self) -> Result<(), OrsError> {
        crate::model::validate_digest(&self.digest, "journal.predecessor_digest")?;
        Ok(())
    }
}

/// One owner-neutral restore intent operation.
///
/// Every field is load-bearing identity or binding: the store layer verifies
/// the complete operation identity, the persisted stream binding, the opaque
/// envelope and the exact predecessor before appending. A replay is returned
/// only when that complete persisted identity and payload are identical.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalOperation {
    pub transaction_id: String,
    pub source_archive_id: String,
    pub archive_class: RestoreJournalArchiveClass,
    pub destination_ref: String,
    pub writer_id: String,
    pub writer_fence_digest: String,
    pub record_schema: String,
    pub phase_operation: String,
    pub request_digest: String,
    pub body_digest: String,
    pub expected_predecessor: Option<JournalPredecessor>,
    pub payload_handle: String,
}

impl RestoreJournalOperation {
    pub fn validate(&self) -> Result<(), OrsError> {
        text(&self.transaction_id, "journal.transaction_id")?;
        text(&self.source_archive_id, "journal.source_archive_id")?;
        text(&self.destination_ref, "journal.destination_ref")?;
        text(&self.writer_id, "journal.writer_id")?;
        crate::model::validate_digest(&self.writer_fence_digest, "journal.writer_fence_digest")?;
        if self.record_schema != RESTORE_JOURNAL_RECORD_SCHEMA {
            return Err(OrsError::InvalidField {
                field: "journal.record_schema",
                reason: "unsupported restore journal record schema",
            });
        }
        text(&self.phase_operation, "journal.phase_operation")?;
        crate::model::validate_digest(&self.request_digest, "journal.request_digest")?;
        crate::model::validate_digest(&self.body_digest, "journal.body_digest")?;
        if let Some(predecessor) = &self.expected_predecessor {
            predecessor.validate()?;
        }
        text(&self.payload_handle, "journal.payload_handle")?;
        Ok(())
    }

    /// Returns the deterministic phase-slot identity used by the unique
    /// operation index. It intentionally excludes mutable history so a changed
    /// source, writer, fence, predecessor or payload cannot be mistaken for a
    /// different operation in the same transaction/phase slot.
    pub fn phase_identity(&self, stream: &str) -> Result<String, OrsError> {
        phase_identity_for(stream, &self.transaction_id, &self.phase_operation)
    }

    /// Computes the complete operation identity over every operation field
    /// and the validated payload handle. The exact serialized envelope digest
    /// is checked separately for replay equality, so operation identity does
    /// not depend on a self-referential operation id inside that envelope.
    pub fn identity_sha256(&self, stream: &str) -> Result<String, OrsError> {
        self.validate()?;
        validate_stream_text(stream)?;
        let material = CompleteOperationIdentityMaterial {
            domain: "eliot.ors.restore-journal.operation",
            version: RESTORE_JOURNAL_SCHEMA_VERSION,
            stream,
            transaction_id: &self.transaction_id,
            source_archive_id: &self.source_archive_id,
            archive_class: self.archive_class,
            destination_ref: &self.destination_ref,
            writer_id: &self.writer_id,
            writer_fence_digest: &self.writer_fence_digest,
            record_schema: &self.record_schema,
            phase_operation: &self.phase_operation,
            request_digest: &self.request_digest,
            body_digest: &self.body_digest,
            expected_predecessor: &self.expected_predecessor,
            payload_handle: &self.payload_handle,
        };
        canonical_digest(&material)
    }

    /// Returns the complete operation identity embedded in the phase payload
    /// envelope's opaque operation/checkpoint id.
    pub fn identity(&self, stream: &str) -> Result<String, OrsError> {
        Ok(format!(
            "restore-journal-operation-v2:{}",
            self.identity_sha256(stream)?
        ))
    }

    /// Checks the immutable stream binding without interpreting any restore
    /// meaning.
    pub fn matches_binding(&self, binding: &RestoreJournalStreamBinding) -> bool {
        self.transaction_id == binding.transaction_id
            && self.source_archive_id == binding.source_archive_id
            && self.archive_class == binding.archive_class
            && self.destination_ref == binding.destination_ref
            && self.writer_id == binding.writer_id
            && self.writer_fence_digest == binding.writer_fence_digest
    }
}

/// One durably committed restore intent row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalEntry {
    pub operation: RestoreJournalOperation,
    pub sequence: u64,
    pub payload_sha256: String,
    pub payload: String,
}

impl RestoreJournalEntry {
    pub fn validate(&self) -> Result<(), OrsError> {
        self.operation.validate()?;
        let envelope =
            validate_envelope_bytes(&self.payload, &self.payload_sha256, "journal.payload")?;
        if envelope.expires_at_ms.is_some() {
            return Err(OrsError::InvalidField {
                field: "journal.payload_expiry",
                reason: "unresolved restore intent payload cannot expire",
            });
        }
        Ok(())
    }

    /// Validates the row's stream-specific envelope identity and fence.
    pub fn validate_for_stream(&self, stream: &str) -> Result<(), OrsError> {
        validate_stream_text(stream)?;
        self.validate()?;
        let envelope = decode_envelope(&self.payload, "journal.payload")?;
        let operation_identity = self.operation.identity(stream)?;
        if envelope.operation_or_checkpoint_id.as_str() != operation_identity.as_str()
            || envelope.state_fence.sha256 != self.operation.writer_fence_digest
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }

    /// Canonical digest binding this exact row for predecessor chains.
    pub fn digest(&self) -> Result<String, OrsError> {
        let bytes =
            serde_json::to_string(self).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(crate::model::sha256_hex(bytes.as_bytes()))
    }
}

/// One durably committed restore result row answering an exact intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalResult {
    pub transaction_id: String,
    pub phase_operation: String,
    pub intent_sequence: u64,
    pub receipt_sha256: String,
    pub receipt: String,
}

impl RestoreJournalResult {
    pub fn validate(&self) -> Result<(), OrsError> {
        text(&self.transaction_id, "journal_result.transaction_id")?;
        text(&self.phase_operation, "journal_result.phase_operation")?;
        validate_envelope_bytes(
            &self.receipt,
            &self.receipt_sha256,
            "journal_result.receipt",
        )?;
        Ok(())
    }

    /// Validates the result envelope against the exact intent it answers.
    pub fn validate_for_intent(
        &self,
        stream: &str,
        intent: &RestoreJournalEntry,
    ) -> Result<(), OrsError> {
        self.validate()?;
        intent.validate_for_stream(stream)?;
        let envelope = decode_envelope(&self.receipt, "journal_result.receipt")?;
        let operation_identity = intent.operation.identity(stream)?;
        if self.transaction_id != intent.operation.transaction_id
            || self.phase_operation != intent.operation.phase_operation
            || self.intent_sequence != intent.sequence
            || envelope.operation_or_checkpoint_id.as_str() != operation_identity.as_str()
            || envelope.state_fence.sha256 != intent.operation.writer_fence_digest
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }

    /// Canonical digest binding this exact row.
    pub fn digest(&self) -> Result<String, OrsError> {
        let bytes =
            serde_json::to_string(self).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(crate::model::sha256_hex(bytes.as_bytes()))
    }
}

/// Stream binding: the exact restore context every append on a stream carries.
///
/// Bound once per stream before the first append (idempotent for identical
/// bindings, conflicting otherwise) and persisted durably so resumed processes
/// observe the same binding. The ORS owner compares every later operation to
/// this row before it can advance the stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalStreamBinding {
    pub transaction_id: String,
    pub source_archive_id: String,
    pub archive_class: RestoreJournalArchiveClass,
    pub destination_ref: String,
    pub writer_id: String,
    pub writer_fence_digest: String,
}

impl RestoreJournalStreamBinding {
    pub fn validate(&self) -> Result<(), OrsError> {
        text(&self.transaction_id, "journal.transaction_id")?;
        text(&self.source_archive_id, "journal.source_archive_id")?;
        text(&self.destination_ref, "journal.destination_ref")?;
        text(&self.writer_id, "journal.writer_id")?;
        crate::model::validate_digest(&self.writer_fence_digest, "journal.writer_fence_digest")?;
        Ok(())
    }
}

/// Smallest retained resolved window the accepted retention policy may use.
///
/// Reclaiming every retained member while a prune fence exists leaves a
/// resuming owner with a fence and no retained row, which it cannot read as a
/// head. Retaining the newest resolved member is therefore a lower bound of
/// the policy rather than a tunable default.
pub const MIN_RETAINED_RESOLVED_MEMBERS: usize = 1;

/// The retained member count at which the accepted policy starts reclaiming.
///
/// It is half the existing record ceiling, not a second bound. Below it a
/// journal grows with no reclamation at all; from it on, every new phase
/// intent first reclaims resolved history instead of letting the stream reach
/// the ceiling. A stream whose unresolved frontier blocks reclamation keeps
/// growing and is refused by the existing ceiling exactly as before: the
/// accepted policy never evicts a recovery-needed member to make room.
pub const RETENTION_RECLAIM_FROM_MEMBERS: usize = MAX_JOURNAL_HISTORY_ENTRIES / 2;

/// What one retention pass did with the journal.
///
/// A disposition is an observation about reclamation, never about a
/// recovery-needed member: no disposition is reachable by evicting an
/// unresolved intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreJournalRetentionDisposition {
    /// The oldest contiguous resolved prefix was reclaimed.
    ReclaimedResolvedPrefix,
    /// No resolved member was reclaimable under the accepted window, so the
    /// pass changed nothing. Recovery-needed members stay retained.
    NoResolvedPrefixToReclaim,
    /// Reclaiming was refused because the retired phase-slot bound is full.
    /// Nothing was removed and no recovery-needed member was touched.
    RefusedRetiredSlotBound,
}

/// The visible frontier of what a retention pass refused to evict.
///
/// The frontier is reported rather than applied as a limit: a pass that cannot
/// reclaim stops at the first unresolved intent, keeps it and everything
/// newer, and records that boundary here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalRetentionFrontier {
    /// Recovery-needed members the pass refused to evict, counted at the
    /// pass. A pass never lowers this by eviction: only a durable result makes
    /// an unresolved member resolved.
    pub unresolved_members: u64,
    /// The oldest recovery-needed member. `None` means the pass refused
    /// nothing.
    pub oldest_unresolved_sequence: Option<u64>,
    /// Resolved members kept by the accepted window rather than because they
    /// are unresolved.
    pub policy_retained_members: u64,
}

/// The accepted retention policy for one restore journal.
///
/// Every bound is an existing owner ceiling, so retention introduces no second
/// policy owner. It reclaims the oldest contiguous RESOLVED prefix under those
/// ceilings and never evicts an unresolved intent to make room for a newer
/// one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalRetentionPolicy {
    /// Newest resolved members always retained as readable history.
    pub keep_resolved: usize,
    /// Record/history bound, reused from the existing owner ceiling.
    pub max_retained_members: usize,
    /// Aggregate byte bound, reused from the existing ORS byte ceiling.
    pub max_total_bytes: usize,
    /// Aggregate table-scan work bound, reused from the existing replay-page
    /// ceiling.
    pub max_work_entries: usize,
    /// Retained member count at which reclamation starts running on the
    /// append path, derived from the existing record ceiling.
    pub reclaim_from_members: usize,
}

impl RestoreJournalRetentionPolicy {
    /// The accepted production policy.
    pub fn accepted() -> Self {
        Self {
            keep_resolved: MIN_RETAINED_RESOLVED_MEMBERS,
            max_retained_members: MAX_JOURNAL_HISTORY_ENTRIES,
            max_total_bytes: MAX_JOURNAL_TOTAL_BYTES,
            max_work_entries: MAX_JOURNAL_WORK_ENTRIES,
            reclaim_from_members: RETENTION_RECLAIM_FROM_MEMBERS,
        }
    }

    /// Rejects a window that would strand a headless retained stream, exceed
    /// the owner ceiling it runs under, or claim bounds the journal does not
    /// actually enforce.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.keep_resolved < MIN_RETAINED_RESOLVED_MEMBERS
            || self.keep_resolved > MAX_JOURNAL_HISTORY_ENTRIES
        {
            return Err(OrsError::InvalidField {
                field: "journal.retention_keep_resolved",
                reason: "must retain at least one and at most the journal history bound",
            });
        }
        if self.max_retained_members != MAX_JOURNAL_HISTORY_ENTRIES
            || self.max_total_bytes != MAX_JOURNAL_TOTAL_BYTES
            || self.max_work_entries != MAX_JOURNAL_WORK_ENTRIES
            || self.reclaim_from_members != RETENTION_RECLAIM_FROM_MEMBERS
        {
            return Err(OrsError::InvalidField {
                field: "journal.retention_bounds",
                reason: "retention must run under the existing journal ceilings",
            });
        }
        Ok(())
    }
}

/// The durable decision one retention pass committed with its removals.
///
/// It is written in the same transaction as the rows it removed, so a
/// reclaimed set and the report of what it refused can never disagree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalRetentionRecord {
    /// Row schema this decision was written under.
    pub record_schema: String,
    /// Resolved window the pass ran under.
    pub keep_resolved: u64,
    /// Members this pass reclaimed.
    pub removed_members: u64,
    /// Phase slots retired in total after this pass. It is the same value the
    /// prune fence records, which is what keeps a reclaimed slot provably
    /// retired.
    pub retired_members: u64,
    /// What the pass did.
    pub disposition: RestoreJournalRetentionDisposition,
    /// What the pass refused to evict.
    pub frontier: RestoreJournalRetentionFrontier,
}

impl RestoreJournalRetentionRecord {
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.record_schema != RESTORE_JOURNAL_RECORD_SCHEMA {
            return Err(OrsError::InvalidField {
                field: "journal.retention_record_schema",
                reason: "unsupported restore journal retention record schema",
            });
        }
        if self.keep_resolved > u64::try_from(MAX_JOURNAL_HISTORY_ENTRIES).unwrap_or(u64::MAX) {
            return Err(OrsError::InvalidField {
                field: "journal.retention_keep_resolved",
                reason: "must be within the existing journal history bound",
            });
        }
        Ok(())
    }
}

/// What one production retention pass did and what it refused to evict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalRetentionReport {
    /// The stream the pass ran on.
    pub stream: String,
    /// The durable decision the pass committed together with its removals.
    pub record: RestoreJournalRetentionRecord,
    /// Recovery-needed members still retained after the pass, recomputed
    /// from current owner state. This is never lowered by eviction.
    pub surviving_unresolved_members: u64,
    /// The oldest surviving recovery-needed member, when the pass refused to
    /// evict one.
    pub oldest_surviving_unresolved: Option<u64>,
}

/// The full journal member denominator a recovery decision requires.
///
/// `members` counts the WHOLE journal, including members an accepted
/// retention pass already retired. A retained suffix can therefore still be
/// proved complete instead of being read as the entire history, and a
/// truncated or partially reclaimed journal fails the check instead of
/// producing a complete restore proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalMemberDenominator {
    /// Every member the requester requires to be accounted for, retained or
    /// retired.
    pub members: u64,
    /// Exact durable head the requester expects. `None` means the requester
    /// expects an exact new journal.
    pub head: Option<JournalPredecessor>,
}

impl RestoreJournalMemberDenominator {
    pub fn validate(&self) -> Result<(), OrsError> {
        if let Some(head) = &self.head {
            head.validate()?;
        }
        Ok(())
    }
}

/// One bounded, denominator-checked journal readback request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalReadbackRequest {
    pub stream: String,
    /// Page bound. The request is refused when the stream retains more
    /// members than one page can return, never truncated silently.
    pub limit: usize,
    pub denominator: RestoreJournalMemberDenominator,
}

impl RestoreJournalReadbackRequest {
    pub fn validate(&self) -> Result<(), OrsError> {
        text(&self.stream, "journal.stream")?;
        if self.limit == 0 || self.limit > MAX_JOURNAL_PAGE_ENTRIES {
            return Err(OrsError::InvalidField {
                field: "journal.page_limit",
                reason: "page limit must be between 1 and the journal page bound",
            });
        }
        self.denominator.validate()
    }
}

/// Whether a readback is admissible as complete restore proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreJournalCompleteness {
    /// The validated journal accounts for exactly the requested member
    /// denominator, retained and retired together.
    Complete,
    /// The validated journal is an exact new journal: bound, with no retained
    /// member, no retired phase slot and no prune fence. Zero entries is
    /// known-empty only here, never for unavailable or unvalidated storage.
    ExactNew,
}

/// A validated, denominator-checked journal readback.
///
/// Every field is an observation the owner proved from current durable state.
/// Nothing here is a caller assertion, and a stream whose members cannot be
/// accounted for never produces a value at all.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalReadback {
    pub stream: String,
    /// Every retained member, in sequence order. Bounded by the request page
    /// and the existing journal history ceiling.
    pub entries: Vec<RestoreJournalEntry>,
    /// Retained members returned in full.
    pub retained_members: u64,
    /// Members an accepted retention pass already retired on this stream.
    pub retired_members: u64,
    /// The full observed denominator: retained plus retired.
    pub total_members: u64,
    /// The durable head the readback proved.
    pub head: Option<JournalPredecessor>,
    /// The prune boundary when the returned rows are a retained suffix.
    pub history_fence: Option<JournalPredecessor>,
    pub completeness: RestoreJournalCompleteness,
    /// The last durable retention decision, so a reader also sees the
    /// frontier that refused to evict a recovery-needed member.
    pub retention: Option<RestoreJournalRetentionRecord>,
}

/// Which persisted row an append receipt proves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RestoreJournalReceiptKind {
    Intent,
    Result,
}

/// Owner-generated proof fields carried by an append receipt.
///
/// This is deliberately not a secret or a caller assertion. The owner
/// readback method compares every field below with the current Redb row and
/// its unique indexes before accepting a receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreJournalReceiptProof {
    pub(crate) schema: String,
    pub(crate) stream: String,
    pub(crate) phase_identity: String,
    pub(crate) kind: RestoreJournalReceiptKind,
    pub(crate) record_digest: String,
    pub(crate) replayed: bool,
}

/// Persisted receipt returned for one journal append.
///
/// The public observation fields remain source-compatible for the future
/// `RestoreJournalPort` adapter, but the private owner proof prevents a caller
/// from constructing a success-shaped receipt. A caller must present the value
/// to `RedbRecoveryStore::verify_restore_journal_receipt` (or use one of the
/// owner readback methods) before treating it as durable proof.
///
/// This type deliberately does NOT implement [`serde::Deserialize`]. Private
/// field visibility alone does not make the proof unforgeable: a derived
/// `Deserialize` would let any downstream crate populate the private field
/// from untrusted bytes, which would defeat the whole owner-issuance
/// property. The receipt is a live value produced by an owner append and must
/// not be reconstructible from a wire format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalAppendReceipt {
    pub transaction_id: String,
    pub phase_operation: String,
    pub sequence: u64,
    pub record_digest: String,
    /// Reports whether *this* call observed an already-durable row rather than
    /// appending one.
    ///
    /// It is a property of the call, not of the persisted row, so the first
    /// append of a row and an exact later replay of that same row are NOT
    /// equal receipts: the durable fields (`transaction_id`,
    /// `phase_operation`, `sequence`, `record_digest`) are identical, and only
    /// this flag differs. Every field the caller uses as durable proof is
    /// therefore stable across replays, and the private proof carries the same
    /// flag so the two can never disagree.
    pub replayed: bool,
    pub(crate) owner_readback: RestoreJournalReceiptProof,
}

/// Everything one owner-issued receipt needs, all read from current owner
/// state. Grouped so the constructor cannot be called with a partially derived
/// or mismatched set of fields.
pub(crate) struct RestoreJournalReceiptIssue<'a> {
    pub(crate) transaction_id: &'a str,
    pub(crate) phase_operation: &'a str,
    pub(crate) sequence: u64,
    pub(crate) record_digest: &'a str,
    pub(crate) stream: &'a str,
    pub(crate) phase_identity: &'a str,
    pub(crate) kind: RestoreJournalReceiptKind,
    pub(crate) replayed: bool,
}

impl RestoreJournalAppendReceipt {
    pub(crate) fn owner_issued(issue: &RestoreJournalReceiptIssue<'_>) -> Self {
        let record_digest = issue.record_digest.to_owned();
        Self {
            transaction_id: issue.transaction_id.to_owned(),
            phase_operation: issue.phase_operation.to_owned(),
            sequence: issue.sequence,
            record_digest: record_digest.clone(),
            replayed: issue.replayed,
            owner_readback: RestoreJournalReceiptProof {
                schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
                stream: issue.stream.to_owned(),
                phase_identity: issue.phase_identity.to_owned(),
                kind: issue.kind,
                record_digest,
                replayed: issue.replayed,
            },
        }
    }
}

#[derive(Serialize)]
struct PhaseIdentityMaterial<'a> {
    domain: &'static str,
    version: u32,
    stream: &'a str,
    transaction_id: &'a str,
    phase_operation: &'a str,
}

#[derive(Serialize)]
struct CompleteOperationIdentityMaterial<'a> {
    domain: &'static str,
    version: u32,
    stream: &'a str,
    transaction_id: &'a str,
    source_archive_id: &'a str,
    archive_class: RestoreJournalArchiveClass,
    destination_ref: &'a str,
    writer_id: &'a str,
    writer_fence_digest: &'a str,
    record_schema: &'a str,
    phase_operation: &'a str,
    request_digest: &'a str,
    body_digest: &'a str,
    expected_predecessor: &'a Option<JournalPredecessor>,
    payload_handle: &'a str,
}

pub(crate) fn phase_identity_for(
    stream: &str,
    transaction_id: &str,
    phase_operation: &str,
) -> Result<String, OrsError> {
    validate_stream_text(stream)?;
    text(transaction_id, "journal.transaction_id")?;
    text(phase_operation, "journal.phase_operation")?;
    let material = PhaseIdentityMaterial {
        domain: "eliot.ors.restore-journal.phase",
        version: RESTORE_JOURNAL_SCHEMA_VERSION,
        stream,
        transaction_id,
        phase_operation,
    };
    let digest = canonical_digest(&material)?;
    Ok(format!("restore-journal-phase-v2:{digest}"))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, OrsError> {
    let bytes =
        serde_json::to_string(value).map_err(|error| OrsError::Encoding(error.to_string()))?;
    Ok(crate::model::sha256_hex(bytes.as_bytes()))
}

fn decode_envelope(bytes: &str, field: &'static str) -> Result<RecoveryPayloadEnvelope, OrsError> {
    serde_json::from_str(bytes).map_err(|_| OrsError::InvalidField {
        field,
        reason: "must be a versioned RecoveryPayloadEnvelope",
    })
}

pub(crate) fn validate_envelope_bytes(
    bytes: &str,
    digest: &str,
    field: &'static str,
) -> Result<RecoveryPayloadEnvelope, OrsError> {
    if bytes.len() > MAX_JOURNAL_PAYLOAD_BYTES {
        return Err(OrsError::PayloadTooLarge);
    }
    crate::model::validate_digest(digest, "journal.envelope_sha256")?;
    if crate::model::sha256_hex(bytes.as_bytes()) != digest {
        return Err(OrsError::PayloadIntegrityMismatch);
    }
    let envelope = decode_envelope(bytes, field)?;
    envelope.validate()?;
    Ok(envelope)
}

fn validate_stream_text(value: &str) -> Result<(), OrsError> {
    text(value, "journal.stream")
}

fn text(value: &str, field: &'static str) -> Result<(), OrsError> {
    // Length first: `trim()` scans the whole string, so checking emptiness
    // before the bound would let an oversized blank input force an unbounded
    // scan before rejection.
    if value.len() > MAX_JOURNAL_STREAM_KEY_BYTES
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be non-blank bounded text with no control characters",
        });
    }
    Ok(())
}
