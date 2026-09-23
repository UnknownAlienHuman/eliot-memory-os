//! Owner-neutral durable restore journal records (issue #957).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! purge-first, suspended import, separate cutover authority); A13.6
//! Operational Recovery State (only identities, opaque envelopes, epochs,
//! suspended leases, checkpoints, intents, manifests, anchors — never
//! semantic claims); I5.13 backup classes; I14.21 unknown-commit recovery
//! (reconcile by identity, never blind retry).
//! Implementation: I5.16 common durable fields (explicit identity, fence,
//! schema, digests; inapplicable fields are explicit, never omitted);
//! I14.21 evidence-backed disposition; versioned table/record identity with
//! explicit idempotent migration.
//!
//! These records are owner-neutral: they bind restore transaction, source
//! archive, class, destination, admitted writer/fence digest, record schema,
//! phase operation, immutable request/body digests, expected predecessor, and
//! an opaque payload handle. They carry digests and handles only — never
//! credentials, never authority, never phase semantics. Payload bytes stay
//! opaque to this owner; encryption ownership follows existing ORS policy.
//! Kernel composition later adapts this journal to `RestoreJournalPort`
//! without reinterpreting any row.

use serde::{Deserialize, Serialize};

use crate::OrsError;

/// Versioned schema identity of every journal row written by this owner.
pub const RESTORE_JOURNAL_RECORD_SCHEMA: &str = "restore-journal-v1";
/// Additive journal table schema version owned by this module.
pub const RESTORE_JOURNAL_SCHEMA_VERSION: u32 = 1;
/// Maximum one opaque journal payload: one MiB. Larger payloads are separate
/// blob references, never inline journal rows.
pub const MAX_JOURNAL_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum rows returned by one bounded journal read.
pub const MAX_JOURNAL_PAGE_ENTRIES: usize = 256;
/// Maximum stream-key length: bounded opaque identities only.
pub const MAX_JOURNAL_STREAM_KEY_BYTES: usize = 512;

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
/// exact predecessor equality and digest bindings before appending, and
/// replays (never duplicates) an identical operation.
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
        if self.payload.len() > MAX_JOURNAL_PAYLOAD_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        crate::model::validate_digest(&self.payload_sha256, "journal.payload_sha256")?;
        if crate::model::sha256_hex(self.payload.as_bytes()) != self.payload_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
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

/// One durably committed restore result row answering an intent.
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
        crate::model::validate_digest(&self.receipt_sha256, "journal_result.receipt_sha256")?;
        if self.receipt.len() > MAX_JOURNAL_PAYLOAD_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        if crate::model::sha256_hex(self.receipt.as_bytes()) != self.receipt_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
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
/// bindings, conflicting otherwise) and persisted durably so resumed
/// processes observe the same bindings. Binds restore transaction,
/// source archive, class, destination, and the admitted writer/fence digest.
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

/// Persisted receipt returned for one journal append: the stored row plus
/// whether it was newly appended or replayed from an identical operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalAppendReceipt {
    pub transaction_id: String,
    pub phase_operation: String,
    pub sequence: u64,
    pub record_digest: String,
    pub replayed: bool,
}

fn text(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.trim().is_empty()
        || value.len() > MAX_JOURNAL_STREAM_KEY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be non-blank bounded text with no control characters",
        });
    }
    Ok(())
}
