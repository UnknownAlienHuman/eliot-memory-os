//! Durable post-#1709 host-event ingest journal (issue #1934, I7.23).
//!
//! The pure [`crate::normalize_acp_event`] adapter maps one ACP observation to
//! the closed [`NormalizedHostEventEnvelope`](eliot_agent_api::NormalizedHostEventEnvelope)
//! without creating a store, cursor, or authority. This module owns what that
//! pure step deliberately does not: the durable relation among
//!
//! ```text
//! immutable transport hash;
//! allowed raw bytes or a deterministic redacted representation;
//! redaction receipt (when original bytes cannot be retained);
//! normalized HostEventEnvelope;
//! adapter and transformation versions;
//! sequence/cursor and parent-child lineage;
//! requested and actual route references;
//! normalization warnings;
//! EventEnvelope disposition.
//! ```
//!
//! The durable relation is the commit precondition for publishing an
//! acknowledged cursor: [`DurableHostEventJournal::commit`] advances the
//! per-stream durable cursor only after the raw/hash record, the normalized
//! projection, and the disposition are stored together, and
//! [`DurableHostEventJournal::acknowledge`] can only acknowledge up to the
//! last committed sequence. A staged-but-uncommitted record (for example after
//! a pre-commit interruption) leaves the cursor unadvanced and is replayed on
//! reconnect via [`DurableHostEventJournal::pending_for_reconnect`]. Repeated
//! delivery of the same transport bytes or the same stream cursor is
//! idempotent: it returns the existing record without minting a second
//! normalized event or a second state application
//! ([`DurableHostEventJournal::record_application`]).
//!
//! Privacy is enforced fail-closed at ingest: [`stage_allowed`](DurableHostEventJournal::stage_allowed)
//! rejects bytes that carry secret values, provider-forbidden hidden
//! reasoning, or other denied content, and the deterministic redaction path
//! ([`stage_redacted`](DurableHostEventJournal::stage_redacted)) stores only
//! the redacted projection plus its receipt, never the original bytes.
//!
//! Per-stream cursors ([`StreamCursorState`]) are separate from logical turn
//! state and process state, which live with their own owners and never enter
//! this journal.

use std::collections::BTreeMap;

use eliot_agent_api::{
    ContractError, EventId, HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM,
    HostEventPrivacyClass, LowercaseSha256, NormalizedHostEventEnvelope,
    ProviderObservationLineage,
};
use eliot_contracts::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{ACP_NORMALIZER_IDENTITY, ACP_SCHEMA_VERSION, DEFAULT_MAX_FRAME_BYTES};

/// Transformation pipeline version bound into every durable record alongside
/// the adapter version.
pub const DURABLE_INGEST_TRANSFORMATION_VERSION: &str = "eliot-agent-acp/durable-ingest-v1";
/// Marker prefix of every deterministic redacted representation minted here.
pub const REDACTED_PROJECTION_MARKER: &str = "redacted/host-event-v1";
/// Maximum stream identifier length in bytes.
pub const MAX_STREAM_ID_BYTES: usize = 256;
/// Maximum redacted field classes carried by one redaction receipt.
pub const MAX_REDACTED_CLASSES: usize = 16;
/// Maximum length of one redacted class label in bytes.
pub const MAX_REDACTED_CLASS_BYTES: usize = 128;
/// Maximum normalization warnings carried by one durable record.
pub const MAX_INGEST_WARNINGS: usize = 16;

/// Substrings that must never be persisted as admissible raw bytes. Matched
/// case-insensitively against the lossy UTF-8 decoding of the transport bytes.
const DENIED_CONTENT_TOKENS: &[&str] = &[
    "secret",
    "passwd",
    "password",
    "bearer",
    "hidden_reasoning",
    "provider_hidden",
    "api_key",
];

/// Error returned by the durable host-event ingest journal.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IngestError {
    /// A framing value (stream, sequence, size, class label) is invalid.
    #[error("ingest input is invalid: {0}")]
    InvalidInput(&'static str),
    /// Admissible-raw staging carried denied content; use the redacted path.
    #[error("transport bytes carry denied content and cannot persist as raw")]
    PrivacyViolation,
    /// The supplied envelope does not bind the stored bytes or digest.
    #[error("envelope does not bind the stored source: {0}")]
    EnvelopeMismatch(&'static str),
    /// The same stream cursor or transport hash arrived with different bytes.
    #[error("conflicting duplicate delivery is quarantined")]
    ConflictingDuplicate,
    /// A stale cursor arrived with bytes that do not match the record.
    #[error("stale cursor delivery does not match the committed record")]
    StaleSequence,
    /// Commit would skip an undurabled sequence.
    #[error("commit would advance past an undurabled sequence")]
    CursorGap,
    /// No record exists for the requested stream cursor.
    #[error("no staged or committed record for the requested cursor")]
    UnknownRecord,
    /// The record is staged but not yet durably committed.
    #[error("record is staged but the durable relation is not committed")]
    NotCommitted,
    /// Acknowledgement reaches past the last durably committed sequence.
    #[error("acknowledgement reaches past the durable cursor")]
    AckBeyondDurable,
    /// A shared digest or envelope primitive rejected a value.
    #[error("contract primitive rejected the ingest value")]
    Contract(#[from] ContractError),
    /// Canonical JSON encoding of an envelope failed.
    #[error("envelope digest encoding failed")]
    DigestEncoding,
}

/// Key of one durable event: its stream plus its sequence within the stream.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventKey {
    /// Owning stream identifier.
    pub stream_id: String,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub sequence: u64,
}

/// Per-stream cursor state, persisted separately from logical turn state and
/// process state. `last_durable_sequence` advances only on commit;
/// `last_acked_sequence` advances only on acknowledgement up to the durable
/// cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamCursorState {
    /// Owning stream identifier.
    pub stream_id: String,
    /// Last sequence whose raw/hash, envelope, and disposition are durably
    /// related. Zero when nothing is committed.
    pub last_durable_sequence: u64,
    /// Last sequence the downstream consumer acknowledged. Never exceeds the
    /// durable cursor. Zero when nothing is acknowledged.
    pub last_acked_sequence: u64,
}

/// Why the original transport bytes could not be retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedactionReason {
    /// The transport bytes carried denied content detected at ingest.
    ForbiddenContentDetected,
    /// The caller declared the bytes out of scope before persistence.
    DeclaredOutOfScope,
}

/// Receipt stored whenever original bytes cannot be retained. It carries the
/// transport hash, the reason, and the deterministic marker, never source
/// content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionReceipt {
    /// Immutable hash of the original transport bytes.
    pub transport_hash: LowercaseSha256,
    /// Why redaction was required.
    pub reason: RedactionReason,
    /// Sorted redacted field classes (for example `secret`, `scope`).
    pub redacted_classes: Vec<String>,
    /// Deterministic projection marker. Always [`REDACTED_PROJECTION_MARKER`].
    pub marker: String,
    /// Normalizer version that minted the redaction.
    pub normalizer_version: String,
}

/// Stored source bytes: either the admissible raw bytes or the deterministic
/// redacted representation plus its receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredPayload {
    /// Admissible raw transport bytes, proven free of denied content.
    Allowed {
        /// Exact transport bytes.
        bytes: Vec<u8>,
    },
    /// Deterministic redacted projection. The original bytes are absent.
    Redacted {
        /// Deterministic projection bytes (see [`deterministic_redacted_bytes`]).
        bytes: Vec<u8>,
        /// Receipt exposing the redaction facts, not the source.
        receipt: RedactionReceipt,
    },
}

impl StoredPayload {
    /// Returns the stored bytes (raw or redacted projection).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Allowed { bytes } | Self::Redacted { bytes, .. } => bytes,
        }
    }

    /// Returns the redaction receipt, or `None` for admissible raw records.
    #[must_use]
    pub const fn redaction_receipt(&self) -> Option<&RedactionReceipt> {
        match self {
            Self::Allowed { .. } => None,
            Self::Redacted { receipt, .. } => Some(receipt),
        }
    }
}

/// Durable disposition of one normalized `HostEventEnvelope`: whether the
/// raw/hash, envelope, and disposition relation is committed, how many times
/// the envelope was applied to state, and whether it was acknowledged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordDisposition {
    /// True once the durable relation is committed and the cursor published.
    pub committed: bool,
    /// Number of state applications (0 or 1; duplicates never re-apply).
    pub applied_count: u32,
    /// True once acknowledged at or past this sequence.
    pub acked: bool,
}

/// One durable host-event record: the immutable transport hash, the stored
/// raw-or-redacted bytes, the normalized envelope, lineage/version/route
/// facts, and the disposition, stored together as the commit unit.
#[derive(Clone, Debug, PartialEq)]
pub struct DurableHostEventRecord {
    /// Owning stream identifier.
    pub stream_id: String,
    /// Monotonic sequence within the stream.
    pub sequence: u64,
    /// Immutable hash of the original transport bytes.
    pub transport_hash: LowercaseSha256,
    /// Stored raw or redacted bytes.
    pub stored: StoredPayload,
    /// Normalized envelope bound to the stored bytes.
    pub envelope: NormalizedHostEventEnvelope,
    /// Canonical digest of the normalized envelope.
    pub envelope_digest: LowercaseSha256,
    /// Adapter version that normalized the event.
    pub adapter_version: String,
    /// Transformation pipeline version.
    pub transformation_version: String,
    /// Requested route reference digest, when the lineage carries one.
    pub requested_route_digest: Option<LowercaseSha256>,
    /// Observed actual route reference digest, when one was observed.
    pub actual_route_digest: Option<LowercaseSha256>,
    /// Causal predecessor event identities carried at ingest.
    pub predecessors: Vec<EventId>,
    /// Normalization warnings. Bounded; never raw provider content.
    pub warnings: Vec<String>,
    /// Durable disposition of the envelope.
    pub disposition: RecordDisposition,
}

/// Outcome of staging one event: its key plus whether it was freshly staged
/// (`true`) or an idempotent replay of an identical delivery (`false`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageOutcome {
    /// Key of the staged (or replayed) record.
    pub key: EventKey,
    /// False when the delivery was an idempotent duplicate.
    pub fresh: bool,
}

/// One event awaiting (re)delivery on reconnect: sequences after the last
/// acknowledged cursor, in ascending order, flagged by commit state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayItem {
    /// Sequence to redeliver.
    pub sequence: u64,
    /// True when the durable relation is committed (acknowledgement pending);
    /// false when staged but uncommitted (commit pending).
    pub committed: bool,
    /// Immutable transport hash of the event.
    pub transport_hash: LowercaseSha256,
    /// Canonical digest of the normalized envelope.
    pub envelope_digest: LowercaseSha256,
}

/// Admissible-raw staging request: the exact transport bytes plus the
/// normalized envelope that must bind them.
#[derive(Clone, Debug)]
pub struct StageAllowed<'a> {
    /// Owning stream identifier.
    pub stream_id: &'a str,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub stream_sequence: u64,
    /// Exact admissible raw transport bytes. Stored verbatim.
    pub transport_bytes: &'a [u8],
    /// Normalized envelope binding `sha256(transport_bytes)`.
    pub envelope: NormalizedHostEventEnvelope,
    /// Requested route reference digest, when the lineage carries one.
    pub requested_route_digest: Option<LowercaseSha256>,
    /// Observed actual route reference digest, when one was observed.
    pub actual_route_digest: Option<LowercaseSha256>,
    /// Causal predecessor event identities.
    pub predecessors: Vec<EventId>,
    /// Normalization warnings. Bounded; never raw provider content.
    pub warnings: Vec<String>,
    /// Transformation pipeline version bound into the record.
    pub transformation_version: &'a str,
}

/// Redacted staging request: the original transport bytes (hashed and scanned
/// but never stored) plus the normalized envelope binding the deterministic
/// redacted projection.
#[derive(Clone, Debug)]
pub struct StageRedacted<'a> {
    /// Owning stream identifier.
    pub stream_id: &'a str,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub stream_sequence: u64,
    /// Original transport bytes. Used only for the immutable transport hash
    /// and the denied-content scan; never stored.
    pub transport_bytes: &'a [u8],
    /// Redacted field classes (for example `secret`, `scope`). Sorted into
    /// the deterministic projection; must be nonempty.
    pub redacted_classes: Vec<String>,
    /// Normalized envelope binding the deterministic redacted projection with
    /// a non-public privacy class.
    pub envelope: NormalizedHostEventEnvelope,
    /// Requested route reference digest, when the lineage carries one.
    pub requested_route_digest: Option<LowercaseSha256>,
    /// Observed actual route reference digest, when one was observed.
    pub actual_route_digest: Option<LowercaseSha256>,
    /// Causal predecessor event identities.
    pub predecessors: Vec<EventId>,
    /// Normalization warnings. Bounded; never raw provider content.
    pub warnings: Vec<String>,
    /// Transformation pipeline version bound into the record.
    pub transformation_version: &'a str,
}

/// Per-stream durable progress.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct StreamProgress {
    last_durable_sequence: u64,
    last_acked_sequence: u64,
}

/// Returns true when the bytes carry denied content that must never persist
/// as admissible raw. Matched case-insensitively over the lossy UTF-8
/// decoding; binary frames that decode to denied tokens are caught the same
/// way.
#[must_use]
pub fn contains_forbidden_content(bytes: &[u8]) -> bool {
    let decoded = String::from_utf8_lossy(bytes).to_lowercase();
    DENIED_CONTENT_TOKENS
        .iter()
        .any(|token| decoded.contains(token))
}

/// Builds the deterministic redacted projection for a transport hash and a
/// set of redacted classes. The output is a pure function of its inputs:
/// the same hash and class set always yields the same bytes, and the bytes
/// carry no source content beyond the hash itself.
#[must_use]
pub fn deterministic_redacted_bytes(transport_hash_hex: &str, sorted_classes: &[&str]) -> Vec<u8> {
    format!(
        "{REDACTED_PROJECTION_MARKER}:hash={transport_hash_hex}:classes={}",
        sorted_classes.join(",")
    )
    .into_bytes()
}

fn typed_digest(hex: String) -> Result<LowercaseSha256, IngestError> {
    serde_json::from_value(Value::String(hex)).map_err(|_| IngestError::InvalidInput("digest"))
}

fn validate_stream_id(stream_id: &str) -> Result<(), IngestError> {
    if stream_id.trim().is_empty() || stream_id.len() > MAX_STREAM_ID_BYTES {
        return Err(IngestError::InvalidInput("stream_id"));
    }
    if stream_id.chars().any(char::is_control) {
        return Err(IngestError::InvalidInput("stream_id"));
    }
    Ok(())
}

fn validate_common(
    stream_id: &str,
    sequence: u64,
    transport_bytes: &[u8],
    warnings: &[String],
    transformation_version: &str,
) -> Result<(), IngestError> {
    validate_stream_id(stream_id)?;
    if sequence == 0 {
        return Err(IngestError::InvalidInput("sequence"));
    }
    if transport_bytes.is_empty() || transport_bytes.len() > DEFAULT_MAX_FRAME_BYTES {
        return Err(IngestError::InvalidInput("transport_bytes"));
    }
    if warnings.len() > MAX_INGEST_WARNINGS {
        return Err(IngestError::InvalidInput("warnings"));
    }
    for warning in warnings {
        if warning.trim().is_empty() || warning.len() > MAX_REDACTED_CLASS_BYTES {
            return Err(IngestError::InvalidInput("warnings"));
        }
    }
    if transformation_version.trim().is_empty()
        || transformation_version.len() > MAX_STREAM_ID_BYTES
    {
        return Err(IngestError::InvalidInput("transformation_version"));
    }
    Ok(())
}

fn validate_classes(classes: &[String]) -> Result<Vec<String>, IngestError> {
    if classes.is_empty() || classes.len() > MAX_REDACTED_CLASSES {
        return Err(IngestError::InvalidInput("redacted_classes"));
    }
    let mut sorted: Vec<String> = classes.to_vec();
    for class in &sorted {
        if class.trim().is_empty() || class.len() > MAX_REDACTED_CLASS_BYTES {
            return Err(IngestError::InvalidInput("redacted_classes"));
        }
    }
    sorted.sort();
    sorted.dedup();
    Ok(sorted)
}

/// Durable host-event ingest journal: the commit precondition for publishing
/// stream cursors (issue #1934, I7.23).
///
/// Records are staged (uncommitted) and then committed as one durable unit;
/// only commits advance the per-stream durable cursor, only acknowledgements
/// up to the durable cursor advance the acked cursor, and reconnect replays
/// everything after the acked cursor. The journal is an in-memory durable
/// relation used by the bridge persistence owner; it performs no I/O, spawns
/// nothing, and grants no authority.
#[derive(Clone, Debug, Default)]
pub struct DurableHostEventJournal {
    progress: BTreeMap<String, StreamProgress>,
    records: BTreeMap<(String, u64), DurableHostEventRecord>,
    by_transport_hash: BTreeMap<String, (String, u64)>,
}

impl DurableHostEventJournal {
    /// Creates an empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stored records (staged plus committed).
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns the per-stream cursor state. Unknown streams report zero
    /// cursors; cursor state is never synthesized from turn or process state.
    #[must_use]
    pub fn cursor(&self, stream_id: &str) -> StreamCursorState {
        let progress = self.progress.get(stream_id).cloned().unwrap_or_default();
        StreamCursorState {
            stream_id: stream_id.to_owned(),
            last_durable_sequence: progress.last_durable_sequence,
            last_acked_sequence: progress.last_acked_sequence,
        }
    }

    /// Returns the record stored under a stream cursor, if any.
    #[must_use]
    pub fn get(&self, key: &EventKey) -> Option<&DurableHostEventRecord> {
        self.records.get(&(key.stream_id.clone(), key.sequence))
    }

    /// Stages admissible raw bytes plus their normalized envelope.
    ///
    /// Fails closed with [`IngestError::PrivacyViolation`] when the bytes
    /// carry denied content, and with [`IngestError::EnvelopeMismatch`] when
    /// the envelope does not bind `sha256(transport_bytes)`. An identical
    /// redelivery returns the existing key with `fresh: false`; a conflicting
    /// same-cursor or same-hash delivery is quarantined with
    /// [`IngestError::ConflictingDuplicate`]. Staging alone never advances a
    /// cursor.
    pub fn stage_allowed(
        &mut self,
        request: StageAllowed<'_>,
    ) -> Result<StageOutcome, IngestError> {
        validate_common(
            request.stream_id,
            request.stream_sequence,
            request.transport_bytes,
            &request.warnings,
            request.transformation_version,
        )?;
        if contains_forbidden_content(request.transport_bytes) {
            return Err(IngestError::PrivacyViolation);
        }
        let transport_hash = typed_digest(sha256_hex(request.transport_bytes))?;
        let stored = StoredPayload::Allowed {
            bytes: request.transport_bytes.to_vec(),
        };
        self.stage(
            request.stream_id,
            request.stream_sequence,
            transport_hash,
            stored,
            request.envelope,
            request.requested_route_digest,
            request.actual_route_digest,
            request.predecessors,
            request.warnings,
            request.transformation_version,
        )
    }

    /// Stages a redacted event: the original bytes are hashed and scanned but
    /// never stored. The stored bytes are the deterministic projection of the
    /// transport hash and the sorted redacted classes, and the envelope must
    /// bind that projection with a non-public privacy class. The stored
    /// record exposes the projection plus the [`RedactionReceipt`], never the
    /// source.
    pub fn stage_redacted(
        &mut self,
        request: StageRedacted<'_>,
    ) -> Result<StageOutcome, IngestError> {
        validate_common(
            request.stream_id,
            request.stream_sequence,
            request.transport_bytes,
            &request.warnings,
            request.transformation_version,
        )?;
        let sorted = validate_classes(&request.redacted_classes)?;
        let transport_hash = typed_digest(sha256_hex(request.transport_bytes))?;
        let reason = if contains_forbidden_content(request.transport_bytes) {
            RedactionReason::ForbiddenContentDetected
        } else {
            RedactionReason::DeclaredOutOfScope
        };
        let class_refs: Vec<&str> = sorted.iter().map(String::as_str).collect();
        let redacted_bytes = deterministic_redacted_bytes(transport_hash.as_str(), &class_refs);
        if request.envelope.normalization.privacy_class == HostEventPrivacyClass::PublicSummary {
            return Err(IngestError::EnvelopeMismatch("privacy_class"));
        }
        let stored = StoredPayload::Redacted {
            bytes: redacted_bytes,
            receipt: RedactionReceipt {
                transport_hash: transport_hash.clone(),
                reason,
                redacted_classes: sorted,
                marker: REDACTED_PROJECTION_MARKER.to_owned(),
                normalizer_version: ACP_SCHEMA_VERSION.to_owned(),
            },
        };
        self.stage(
            request.stream_id,
            request.stream_sequence,
            transport_hash,
            stored,
            request.envelope,
            request.requested_route_digest,
            request.actual_route_digest,
            request.predecessors,
            request.warnings,
            request.transformation_version,
        )
    }

    /// Commits the durable relation for one staged record: raw/hash record,
    /// normalized envelope, and disposition become durably related and the
    /// per-stream durable cursor advances to the record sequence. Commits
    /// require contiguity (`sequence == last_durable + 1`); anything else
    /// reports [`IngestError::CursorGap`]. Committing an already committed
    /// record is idempotent. A pre-commit interruption (no commit) leaves the
    /// cursor unadvanced by construction.
    pub fn commit(&mut self, key: &EventKey) -> Result<StreamCursorState, IngestError> {
        let record = self
            .records
            .get(&(key.stream_id.clone(), key.sequence))
            .ok_or(IngestError::UnknownRecord)?;
        if record.disposition.committed {
            return Ok(self.cursor(&key.stream_id));
        }
        let progress = self.progress.entry(key.stream_id.clone()).or_default();
        if key.sequence != progress.last_durable_sequence + 1 {
            return Err(IngestError::CursorGap);
        }
        progress.last_durable_sequence = key.sequence;
        if let Some(record) = self.records.get_mut(&(key.stream_id.clone(), key.sequence)) {
            record.disposition.committed = true;
        }
        Ok(self.cursor(&key.stream_id))
    }

    /// Acknowledges downstream receipt up to `sequence`. Acknowledgements at
    /// or below the durable cursor advance the acked cursor monotonically;
    /// anything past it reports [`IngestError::AckBeyondDurable`] and moves
    /// nothing.
    pub fn acknowledge(
        &mut self,
        stream_id: &str,
        sequence: u64,
    ) -> Result<StreamCursorState, IngestError> {
        validate_stream_id(stream_id)?;
        if sequence == 0 {
            return Err(IngestError::InvalidInput("sequence"));
        }
        let progress = self.progress.entry(stream_id.to_owned()).or_default();
        if sequence > progress.last_durable_sequence {
            return Err(IngestError::AckBeyondDurable);
        }
        if sequence > progress.last_acked_sequence {
            progress.last_acked_sequence = sequence;
        }
        let acked = progress.last_acked_sequence;
        for ((record_stream, record_sequence), record) in &mut self.records {
            if *record_stream == stream_id && *record_sequence <= acked {
                record.disposition.acked = true;
            }
        }
        Ok(self.cursor(stream_id))
    }

    /// Replays everything after the last acknowledged cursor for a stream, in
    /// ascending sequence order: committed-but-unacknowledged records for
    /// acknowledgement recovery, and staged-but-uncommitted records (for
    /// example after a pre-commit interruption) for commit recovery. Never
    /// synthesizes events; an empty journal replays nothing.
    #[must_use]
    pub fn pending_for_reconnect(&self, stream_id: &str) -> Vec<ReplayItem> {
        let acked = self
            .progress
            .get(stream_id)
            .map_or(0, |progress| progress.last_acked_sequence);
        let mut pending: Vec<ReplayItem> = self
            .records
            .iter()
            .filter(|((record_stream, record_sequence), _)| {
                *record_stream == stream_id && *record_sequence > acked
            })
            .map(|((_, sequence), record)| ReplayItem {
                sequence: *sequence,
                committed: record.disposition.committed,
                transport_hash: record.transport_hash.clone(),
                envelope_digest: record.envelope_digest.clone(),
            })
            .collect();
        pending.sort_by_key(|item| item.sequence);
        pending
    }

    /// Applies one committed envelope to state. The first call returns `true`;
    /// every later call for the same key returns `false` without a second
    /// application, so duplicate replays create no second state application.
    /// Staged-but-uncommitted records report [`IngestError::NotCommitted`].
    pub fn record_application(&mut self, key: &EventKey) -> Result<bool, IngestError> {
        let record = self
            .records
            .get_mut(&(key.stream_id.clone(), key.sequence))
            .ok_or(IngestError::UnknownRecord)?;
        if !record.disposition.committed {
            return Err(IngestError::NotCommitted);
        }
        if record.disposition.applied_count > 0 {
            return Ok(false);
        }
        record.disposition.applied_count = 1;
        Ok(true)
    }

    /// Shared staging core: envelope linkage checks, idempotent-duplicate
    /// detection, and staged insertion. Never advances a cursor.
    #[allow(clippy::too_many_arguments)]
    fn stage(
        &mut self,
        stream_id: &str,
        sequence: u64,
        transport_hash: LowercaseSha256,
        stored: StoredPayload,
        envelope: NormalizedHostEventEnvelope,
        requested_route_digest: Option<LowercaseSha256>,
        actual_route_digest: Option<LowercaseSha256>,
        predecessors: Vec<EventId>,
        warnings: Vec<String>,
        transformation_version: &str,
    ) -> Result<StageOutcome, IngestError> {
        if predecessors.len() > eliot_agent_api::MAX_HOST_EVENT_PREDECESSORS {
            return Err(IngestError::InvalidInput("predecessors"));
        }
        Self::check_envelope_linkage(&envelope, sequence, &stored)?;
        let envelope_digest = envelope
            .compute_digest()
            .map_err(|_| IngestError::DigestEncoding)?;
        if envelope_digest != envelope.normalization.output_digest {
            return Err(IngestError::EnvelopeMismatch("output_digest"));
        }
        let hash_hex = transport_hash.as_str().to_owned();
        let key = EventKey {
            stream_id: stream_id.to_owned(),
            sequence,
        };
        if let Some(existing) = self.records.get(&(stream_id.to_owned(), sequence)) {
            if existing.transport_hash.as_str() == hash_hex
                && existing.envelope_digest == envelope_digest
            {
                return Ok(StageOutcome { key, fresh: false });
            }
            return Err(IngestError::ConflictingDuplicate);
        }
        if self.by_transport_hash.contains_key(&hash_hex) {
            return Err(IngestError::ConflictingDuplicate);
        }
        let durable = self
            .progress
            .get(stream_id)
            .map_or(0, |progress| progress.last_durable_sequence);
        if sequence <= durable {
            return Err(IngestError::StaleSequence);
        }
        if envelope.producer_adapter_identity != ACP_NORMALIZER_IDENTITY {
            return Err(IngestError::EnvelopeMismatch("producer_adapter_identity"));
        }
        self.records.insert(
            (stream_id.to_owned(), sequence),
            DurableHostEventRecord {
                stream_id: stream_id.to_owned(),
                sequence,
                transport_hash,
                stored,
                envelope,
                envelope_digest,
                adapter_version: ACP_SCHEMA_VERSION.to_owned(),
                transformation_version: transformation_version.to_owned(),
                requested_route_digest,
                actual_route_digest,
                predecessors,
                warnings,
                disposition: RecordDisposition {
                    committed: false,
                    applied_count: 0,
                    acked: false,
                },
            },
        );
        self.by_transport_hash
            .insert(hash_hex, (stream_id.to_owned(), sequence));
        Ok(StageOutcome { key, fresh: true })
    }

    /// Checks that the envelope binds the stored bytes: schema version,
    /// stream sequence, `raw_source` digest over the stored bytes, and receipt
    /// coherence, plus framing validation for session lineage.
    fn check_envelope_linkage(
        envelope: &NormalizedHostEventEnvelope,
        sequence: u64,
        stored: &StoredPayload,
    ) -> Result<(), IngestError> {
        if envelope.schema_version != HOST_EVENT_CONTRACT_VERSION {
            return Err(IngestError::EnvelopeMismatch("schema_version"));
        }
        if envelope.sequence != sequence {
            return Err(IngestError::EnvelopeMismatch("sequence"));
        }
        if envelope.normalization.input_digest != envelope.raw_source.digest {
            return Err(IngestError::EnvelopeMismatch("input_digest"));
        }
        if envelope.raw_source.digest.algorithm != HOST_EVENT_DIGEST_ALGORITHM {
            return Err(IngestError::EnvelopeMismatch("digest_algorithm"));
        }
        let stored_hex = sha256_hex(stored.bytes());
        if stored_hex != envelope.raw_source.digest.digest.as_str() {
            return Err(IngestError::EnvelopeMismatch("raw_source"));
        }
        if matches!(
            envelope.lineage,
            ProviderObservationLineage::SessionObservation(_)
        ) {
            envelope
                .validate_as_session_observation()
                .map_err(IngestError::Contract)?;
        }
        Ok(())
    }
}
