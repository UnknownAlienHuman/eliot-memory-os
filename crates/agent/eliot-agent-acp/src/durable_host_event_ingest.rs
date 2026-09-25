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
    AdmittedRouteReceipt, CommittedHostEventIntake, ContractError, EventId,
    HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM, HostEventDeliveryDisposition,
    HostEventPrivacyClass, LowercaseSha256, NormalizedHostEventEnvelope, ProviderExecutionBinding,
    ProviderObservationLineage, QualifiedSourceDigest,
    host_event::HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM,
};
use eliot_contracts::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    ACP_NORMALIZER_IDENTITY, ACP_SCHEMA_VERSION, DEFAULT_MAX_FRAME_BYTES, decode_source_message,
};

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
/// Maximum staged-plus-committed records held by one journal.
///
/// I14.2 sizes the canonical-writes pool at 2048 items plus a byte cap with
/// `STORAGE_BACKPRESSURE` when no durable staging is available. The journal
/// mirrors that pool bound: staging past it fails closed with
/// [`IngestError::CapacityExhausted`] (typed backpressure), never with silent
/// loss or a best-effort downgrade of a durable event.
pub const MAX_JOURNAL_RECORDS: usize = 2048;
/// Maximum total stored payload bytes (raw plus redacted projections) held by
/// one journal. Bounds the byte half of the I14.2 canonical-writes pool.
/// Breach fails closed with [`IngestError::CapacityExhausted`].
pub const MAX_JOURNAL_STORED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum retained best-effort drop gaps. Gaps are coverage evidence, so a
/// full buffer first compacts gaps the acked cursor already passed and only
/// then retains the newest; unacknowledged coverage is never compacted away.
pub const MAX_DROPPED_GAPS: usize = 512;
/// Maximum replay items served by one reconnect page. Restart enumeration
/// walks [`DurableHostEventJournal::pending_page_for_reconnect`] with a
/// continuation instead of materializing an unbounded vector.
pub const MAX_PENDING_PAGE_ITEMS: usize = 128;
/// Committed-and-acknowledged records retained per stream for duplicate
/// suppression. Compaction evicts only acked records older than this window;
/// the per-stream durable/acked cursor facts in `progress` are never evicted,
/// so no cursor resets to zero and no unresolved stream is discarded.
pub const RETAIN_ACKED_RECORDS_PER_STREAM: usize = 512;

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
    /// A durable bound (record count or stored bytes) is exhausted. Typed
    /// backpressure in the I14.4 `STORAGE_BACKPRESSURE` sense: the staging is
    /// refused, the cursor does not move, and a durable event is never
    /// silently downgraded to best-effort. Idempotent replays of already
    /// stored records still succeed at capacity.
    #[error("durable ingest bound reached; staging refused under backpressure")]
    CapacityExhausted,
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

/// Durable phase of one normalized `HostEventEnvelope`, mirroring the I7.2
/// `EventAckReceipt` phases.
///
/// Advancing conditions (declared per cursor/record, enforced by the journal):
///
/// ```text
/// RECEIVED   staged raw/hash record plus bound envelope; cursor unadvanced.
/// DURABLE    committed: raw/hash record, normalized projection, and
///            disposition durably related; per-stream durable cursor advanced
///            contiguously (commit), never past a gap.
/// NORMALIZED committed with the linked normalized projection re-verified
///            (envelope digest recomputed against the stored bytes and the
///            declared output digest); failed re-verification reports DURABLE,
///            never a higher phase.
/// APPLIED    committed envelope applied to state exactly once
///            (record_application) with the consumed envelope digest bound as
///            the application receipt; duplicate replays return the existing
///            receipt without a second application.
/// ```
///
/// Rejections and unknown outcomes are never fabricated into records: they are
/// the typed [`IngestError`] returns (each carrying its exact reason) and, for
/// dropped best-effort observations, the retained [`BestEffortDropGap`]
/// coverage evidence. A forwarded gap accounts for missing coverage; it never
/// advances a cursor or converts absent events into applied ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordPhase {
    /// Staged but not yet durably committed.
    Received,
    /// Committed durable relation; projection linkage not (re-)verified.
    Durable,
    /// Committed with the linked normalized projection verified.
    Normalized,
    /// Committed envelope applied exactly once with bound receipt.
    Applied,
}

/// Durable disposition of one normalized `HostEventEnvelope`: whether the
/// raw/hash, envelope, and disposition relation is committed, whether the
/// linked normalized projection is verified, how many times the envelope was
/// applied to state, the bound application receipt, and whether it was
/// acknowledged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordDisposition {
    /// True once the durable relation is committed and the cursor published.
    pub committed: bool,
    /// True once the linked normalized projection is verified against the
    /// commit (set by [`DurableHostEventJournal::commit`], which durably
    /// relates the projection together with the raw/hash record).
    pub normalized: bool,
    /// Number of state applications (0 or 1; duplicates never re-apply).
    pub applied_count: u32,
    /// Digest of the normalized envelope consumed by the single recorded
    /// application. Bound on first application so a lost acknowledgement
    /// after commit replays to the existing phase/receipt instead of a second
    /// application. `None` until the first application.
    pub applied_receipt: Option<LowercaseSha256>,
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

impl DurableHostEventRecord {
    /// Returns the independently verifiable durable phase of this record.
    ///
    /// APPLIED requires the single recorded application with its bound
    /// receipt; NORMALIZED requires the commit plus a live re-verification of
    /// the linked normalized projection (envelope digest recomputed against
    /// the stored bytes and the declared output digest), so a corrupted
    /// projection reports DURABLE and never a higher phase; anything staged
    /// but uncommitted is RECEIVED. Failed normalization never creates a
    /// record at all: it stays a typed [`IngestError`] with its exact reason.
    #[must_use]
    pub fn phase(&self) -> RecordPhase {
        if self.disposition.applied_count > 0 && self.disposition.applied_receipt.is_some() {
            return RecordPhase::Applied;
        }
        if self.disposition.committed {
            let linked = self
                .envelope
                .compute_digest()
                .is_ok_and(|digest| digest == self.envelope_digest)
                && self.envelope_digest == self.envelope.normalization.output_digest;
            if linked || self.disposition.normalized {
                return RecordPhase::Normalized;
            }
            return RecordPhase::Durable;
        }
        RecordPhase::Received
    }

    /// Returns the linked normalization receipt (the normalized projection
    /// facts minted by the provider normalizer), or `None` before commit.
    /// The receipt travels with the record instead of being re-minted, so the
    /// Governor/coordinator intake re-verifies the same facts.
    #[must_use]
    pub fn normalization_receipt(&self) -> Option<&eliot_agent_api::HostEventNormalizationReceipt> {
        self.disposition
            .committed
            .then_some(&self.envelope.normalization)
    }
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
/// acknowledged cursor, in ascending order, flagged by commit state and
/// carrying the independently verifiable durable phase for acknowledgement
/// recovery (a lost acknowledgement after commit replays to this existing
/// phase/receipt, never to a duplicate normalization or application).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayItem {
    /// Sequence to redeliver.
    pub sequence: u64,
    /// True when the durable relation is committed (acknowledgement pending);
    /// false when staged but uncommitted (commit pending).
    pub committed: bool,
    /// Durable phase of the record (RECEIVED when staged-but-uncommitted,
    /// NORMALIZED-or-better once committed; see [`RecordPhase`]).
    pub phase: RecordPhase,
    /// Immutable transport hash of the event.
    pub transport_hash: LowercaseSha256,
    /// Canonical digest of the normalized envelope.
    pub envelope_digest: LowercaseSha256,
}

/// Exact authorized scope for one bounded reconnect page.
///
/// The scope names exactly one stream. Restart enumeration serves only the
/// presented stream: there is no wildcard, no listing, and no cross-stream
/// read, so a caller can only page the stream its scope authorizes. The
/// journal enforces the equality; the persistence owner binds the scope to
/// its own authorization before calling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingScope {
    stream_id: String,
}

impl PendingScope {
    /// Presents the authorized stream for one bounded page walk.
    pub fn new(stream_id: &str) -> Result<Self, IngestError> {
        validate_stream_id(stream_id)?;
        Ok(Self {
            stream_id: stream_id.to_owned(),
        })
    }

    /// Returns the authorized stream identifier.
    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

/// One bounded reconnect page: at most `MAX_PENDING_PAGE_ITEMS` replay items
/// in ascending sequence order plus the continuation for the next page
/// (`None` when the walk is complete). Bounded pages with continuations are
/// the only restart enumeration; nothing materializes an unbounded vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPage {
    /// Replay items of this page, in ascending sequence order.
    pub items: Vec<ReplayItem>,
    /// Resume-after sequence for the next page, or `None` when complete.
    pub continuation: Option<u64>,
}

/// Why a best-effort observation was dropped instead of retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BestEffortDropReason {
    /// The same stream cursor or transport hash arrived with different bytes.
    ConflictingDuplicate,
    /// A stale cursor arrived with bytes that do not match the record.
    StaleSequence,
}

/// Exact coverage gap emitted when a best-effort observation is dropped. The
/// dropped event is never fabricated into an observation and never advances
/// acknowledgement or cursor state: the gap preserves its stream, sequence,
/// transport hash, and envelope digest so forensic replay can distinguish a
/// deliberate best-effort drop from a blind interval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BestEffortDropGap {
    /// Owning stream identifier.
    pub stream_id: String,
    /// Dropped sequence within the stream.
    pub sequence: u64,
    /// Immutable hash of the dropped transport bytes.
    pub transport_hash: LowercaseSha256,
    /// Canonical digest of the dropped normalized envelope.
    pub envelope_digest: LowercaseSha256,
    /// Why the observation was dropped.
    pub reason: BestEffortDropReason,
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
    /// Normalized envelope binding the stored bytes under its declared
    /// source-digest algorithm (canonical message digest or raw-bytes
    /// digest for quarantine/redacted inputs).
    pub envelope: NormalizedHostEventEnvelope,
    /// Recorded #361 provider-execution binding. Required for execution-unit
    /// lineage (validated against the envelope before any mutation);
    /// forbidden for session-only lineage, which carries no attempt
    /// authority.
    pub binding: Option<&'a ProviderExecutionBinding>,
    /// Recorded #369 admitted-route receipt. Required for execution-unit
    /// lineage (the envelope must reference it by digest); forbidden for
    /// session-only lineage.
    pub admission: Option<&'a AdmittedRouteReceipt>,
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
    /// Recorded #361 provider-execution binding. Required for execution-unit
    /// lineage (validated against the envelope before any mutation);
    /// forbidden for session-only lineage.
    pub binding: Option<&'a ProviderExecutionBinding>,
    /// Recorded #369 admitted-route receipt. Required for execution-unit
    /// lineage (the envelope must reference it by digest); forbidden for
    /// session-only lineage.
    pub admission: Option<&'a AdmittedRouteReceipt>,
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
/// everything after the acked cursor through bounded pages with continuations
/// ([`DurableHostEventJournal::pending_page_for_reconnect`]). Identity is
/// stronger than content: deduplication keys on the admitted
/// producer/stream/event plus sequence relation, so identical transport bytes
/// staged under two distinct stream cursors are two distinct occurrences,
/// while changed bytes under one staged cursor are a quarantined
/// [`IngestError::ConflictingDuplicate`]. The journal is an in-memory durable
/// relation used by the bridge persistence owner; it performs no I/O, spawns
/// nothing, and grants no authority. Record/byte/gap/page bounds fail closed
/// with [`IngestError::CapacityExhausted`] (I14.4 `STORAGE_BACKPRESSURE`
/// semantics); compaction evicts only acknowledged records past the per-stream
/// retention window and never resets a cursor.
#[derive(Clone, Debug, Default)]
pub struct DurableHostEventJournal {
    progress: BTreeMap<String, StreamProgress>,
    records: BTreeMap<(String, u64), DurableHostEventRecord>,
    dropped_gaps: Vec<BestEffortDropGap>,
    stored_bytes: u64,
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

    /// Builds the coordinator-intake conversion view for one committed record
    /// (issues #371 W7/A27).
    ///
    /// Only committed records convert: the raw/hash record, the normalized
    /// projection, and the disposition must already be durably related, so a
    /// staged-but-uncommitted record reports [`IngestError::NotCommitted`].
    /// The view preserves event identity, sequence, producer generation,
    /// `StateFence`, causal predecessors, closed payload kind, delivery class,
    /// and acknowledgement state explicitly (see
    /// [`CommittedHostEventIntake`](eliot_agent_api::CommittedHostEventIntake)),
    /// plus the stable identity derived from the normalized input. The
    /// coordinator intake re-verifies every fact before observing.
    pub fn to_coordinator_intake(
        &self,
        key: &EventKey,
    ) -> Result<CommittedHostEventIntake, IngestError> {
        let record = self
            .records
            .get(&(key.stream_id.clone(), key.sequence))
            .ok_or(IngestError::UnknownRecord)?;
        if !record.disposition.committed {
            return Err(IngestError::NotCommitted);
        }
        CommittedHostEventIntake::from_envelope(&record.envelope, record.disposition.acked)
            .map_err(IngestError::Contract)
    }

    /// Returns every recorded best-effort drop gap for a stream, in record
    /// order. Dropped best-effort observations leave this exact coverage gap
    /// instead of advancing acknowledgement or cursor state.
    #[must_use]
    pub fn drop_gaps(&self, stream_id: &str) -> Vec<BestEffortDropGap> {
        self.dropped_gaps
            .iter()
            .filter(|gap| gap.stream_id == stream_id)
            .cloned()
            .collect()
    }

    /// Stages admissible raw bytes plus their normalized envelope.
    ///
    /// Disclosure/retention resolves before any durable write: the envelope
    /// must carry the positive `PublicSummary` privacy attestation from its
    /// declared contract (a caller safe flag or the mere absence of known
    /// substrings is not proof), and the bytes must additionally pass the
    /// denied-content quarantine scan. Anything else fails closed with
    /// [`IngestError::PrivacyViolation`] and the caller must use the explicit
    /// redacted path. An [`IngestError::EnvelopeMismatch`] fires when the
    /// envelope does not bind the stored bytes under its declared
    /// source-digest algorithm. An identical
    /// redelivery returns the existing key with `fresh: false`; a conflicting
    /// same-cursor delivery is quarantined with
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
        if request.envelope.normalization.privacy_class != HostEventPrivacyClass::PublicSummary {
            return Err(IngestError::PrivacyViolation);
        }
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
            request.binding,
            request.admission,
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
            request.binding,
            request.admission,
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
            // The commit durably relates the raw/hash record, the normalized
            // projection, and the disposition together, so the linked
            // projection verifies from here on (see
            // [`DurableHostEventRecord::phase`]).
            record.disposition.normalized = true;
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
        // Acknowledgement is the only compaction trigger: acknowledged records
        // past the per-stream retention window (and their passed coverage
        // gaps) become eligible for eviction here, never anywhere else.
        self.compact_acknowledged(stream_id);
        Ok(self.cursor(stream_id))
    }

    /// Evicts committed-and-acknowledged records older than the per-stream
    /// retention window, plus the coverage gaps their acked cursor passed.
    ///
    /// Only records with `sequence <= last_acked - RETAIN_ACKED_RECORDS…`
    /// are eligible: staged-but-uncommitted records, unacknowledged records,
    /// the retention window itself (duplicate suppression frontier), and the
    /// per-stream cursor facts are never touched, so compaction cannot reset
    /// a cursor or discard an unresolved stream. Returns the evicted record
    /// count.
    fn compact_acknowledged(&mut self, stream_id: &str) -> usize {
        let acked = self
            .progress
            .get(stream_id)
            .map_or(0, |progress| progress.last_acked_sequence);
        let floor = acked.saturating_sub(RETAIN_ACKED_RECORDS_PER_STREAM as u64);
        if floor == 0 {
            return 0;
        }
        let evictable: Vec<(String, u64)> = self
            .records
            .iter()
            .filter(|((record_stream, sequence), record)| {
                *record_stream == stream_id
                    && *sequence <= floor
                    && record.disposition.committed
                    && record.disposition.acked
            })
            .map(|(key, _)| key.clone())
            .collect();
        let mut evicted = 0;
        for key in evictable {
            if let Some(record) = self.records.remove(&key) {
                self.stored_bytes = self
                    .stored_bytes
                    .saturating_sub(record.stored.bytes().len() as u64);
                evicted += 1;
            }
        }
        self.dropped_gaps
            .retain(|gap| gap.stream_id != stream_id || gap.sequence > floor);
        evicted
    }

    /// Replays everything after the last acknowledged cursor for a stream, in
    /// ascending sequence order: committed-but-unacknowledged records for
    /// acknowledgement recovery, and staged-but-uncommitted records (for
    /// example after a pre-commit interruption) for commit recovery. Never
    /// synthesizes events; an empty journal replays nothing.
    ///
    /// The walk is a bounded-page loop over
    /// [`Self::pending_page_for_reconnect`] (`MAX_PENDING_PAGE_ITEMS` per
    /// page with a resume continuation), so replay work stays bounded even
    /// though the collected result covers the whole unacknowledged tail.
    #[must_use]
    pub fn pending_for_reconnect(&self, stream_id: &str) -> Vec<ReplayItem> {
        let Ok(scope) = PendingScope::new(stream_id) else {
            return Vec::new();
        };
        let mut items = Vec::new();
        let mut after = self
            .progress
            .get(stream_id)
            .map_or(0, |progress| progress.last_acked_sequence);
        while let Ok(page) =
            self.pending_page_for_reconnect(&scope, after, MAX_PENDING_PAGE_ITEMS)
        {
            let complete = page.continuation.is_none();
            if let Some(last) = page.items.last() {
                after = last.sequence;
            }
            items.extend(page.items);
            if complete {
                break;
            }
        }
        items
    }

    /// Serves one bounded reconnect page under an exact authorized scope.
    ///
    /// `after_sequence` resumes after the last item of the previous page (the
    /// acked cursor for the first page); `page_limit` must be within
    /// `1..=MAX_PENDING_PAGE_ITEMS`. The scope serves exactly its own stream:
    /// cross-stream reads are impossible by construction (no listing, no
    /// wildcard), which is the scope authorization for restart enumeration.
    /// `continuation` resumes the walk, or is `None` when the tail is fully
    /// served. Never synthesizes events.
    pub fn pending_page_for_reconnect(
        &self,
        scope: &PendingScope,
        after_sequence: u64,
        page_limit: usize,
    ) -> Result<PendingPage, IngestError> {
        if page_limit == 0 || page_limit > MAX_PENDING_PAGE_ITEMS {
            return Err(IngestError::InvalidInput("page_limit"));
        }
        let stream_id = scope.stream_id();
        let mut items: Vec<ReplayItem> = self
            .records
            .iter()
            .filter(|((record_stream, record_sequence), _)| {
                *record_stream == stream_id && *record_sequence > after_sequence
            })
            .map(|((_, sequence), record)| ReplayItem {
                sequence: *sequence,
                committed: record.disposition.committed,
                phase: record.phase(),
                transport_hash: record.transport_hash.clone(),
                envelope_digest: record.envelope_digest.clone(),
            })
            .collect();
        items.sort_by_key(|item| item.sequence);
        let continuation = if items.len() > page_limit {
            items.truncate(page_limit);
            items.last().map(|item| item.sequence)
        } else {
            None
        };
        Ok(PendingPage {
            items,
            continuation,
        })
    }

    /// Applies one committed envelope to state. The first call returns `true`;
    /// every later call for the same key returns `false` without a second
    /// application, so duplicate replays create no second state application.
    /// Staged-but-uncommitted records report [`IngestError::NotCommitted`].
    /// The first application binds the consumed envelope digest as the
    /// application receipt, so a lost acknowledgement after commit replays to
    /// the existing phase/receipt instead of duplicating the application.
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
        record.disposition.applied_receipt = Some(record.envelope_digest.clone());
        Ok(true)
    }

    /// Records the exact coverage gap when a best-effort observation is
    /// dropped instead of retained. Only best-effort envelopes leave gaps:
    /// durable conflicts stay errors without gap evidence. Gap recording is
    /// the only mutation on these paths; the call returns before any commit
    /// or acknowledgement, so acknowledgement and cursor advancement stay
    /// suppressed by construction. The retained gap buffer is bounded at
    /// `MAX_DROPPED_GAPS`: a full buffer first compacts gaps the acked cursor
    /// already passed, then retains the newest, so unacknowledged coverage is
    /// never compacted away while the buffer itself cannot grow without limit.
    #[allow(clippy::too_many_arguments)]
    fn record_best_effort_drop(
        &mut self,
        stream_id: &str,
        sequence: u64,
        transport_hash: &LowercaseSha256,
        envelope_digest: &LowercaseSha256,
        delivery: HostEventDeliveryDisposition,
        reason: BestEffortDropReason,
    ) {
        if delivery != HostEventDeliveryDisposition::BestEffortOrdered {
            return;
        }
        self.dropped_gaps.push(BestEffortDropGap {
            stream_id: stream_id.to_owned(),
            sequence,
            transport_hash: transport_hash.clone(),
            envelope_digest: envelope_digest.clone(),
            reason,
        });
        if self.dropped_gaps.len() <= MAX_DROPPED_GAPS {
            return;
        }
        // Bounded retention: first compact gaps whose stream cursor already
        // acknowledged them (eligible under the acknowledged rule); only under
        // sustained overflow past that does the buffer retain the newest and
        // release the oldest.
        let progress = &self.progress;
        self.dropped_gaps.retain(|gap| {
            gap.sequence
                > progress
                    .get(gap.stream_id.as_str())
                    .map_or(0, |state| state.last_acked_sequence)
        });
        if self.dropped_gaps.len() > MAX_DROPPED_GAPS {
            let overflow = self.dropped_gaps.len() - MAX_DROPPED_GAPS;
            self.dropped_gaps.drain(..overflow);
        }
    }

    /// Shared staging core: envelope linkage checks, idempotent-duplicate
    /// detection, and staged insertion. Never advances a cursor.
    ///
    /// Identity is stronger than content: the deduplication key is the
    /// admitted stream cursor `(stream_id, sequence)`. An identical redelivery
    /// under one cursor is idempotent; changed bytes under one cursor are a
    /// quarantined [`IngestError::ConflictingDuplicate`]; identical transport
    /// bytes under two distinct stream cursors are two distinct occurrences
    /// and stage independently (no cross-stream content index exists by
    /// design). Record and byte bounds fail closed with
    /// [`IngestError::CapacityExhausted`]; idempotent replays succeed at
    /// capacity because they store nothing new.
    #[allow(clippy::too_many_arguments)]
    fn stage(
        &mut self,
        stream_id: &str,
        sequence: u64,
        transport_hash: LowercaseSha256,
        stored: StoredPayload,
        envelope: NormalizedHostEventEnvelope,
        binding: Option<&ProviderExecutionBinding>,
        admission: Option<&AdmittedRouteReceipt>,
        requested_route_digest: Option<LowercaseSha256>,
        actual_route_digest: Option<LowercaseSha256>,
        predecessors: Vec<EventId>,
        warnings: Vec<String>,
        transformation_version: &str,
    ) -> Result<StageOutcome, IngestError> {
        if predecessors.len() > eliot_agent_api::MAX_HOST_EVENT_PREDECESSORS {
            return Err(IngestError::InvalidInput("predecessors"));
        }
        // Parent agreement before mutation: the predecessors carried at
        // ingest must equal the envelope's own `causal_predecessors`. A wrong
        // parent (divergent lineage columns for one record) is rejected here
        // instead of persisting two disagreeing parent claims.
        if predecessors != envelope.causal_predecessors {
            return Err(IngestError::EnvelopeMismatch("predecessors"));
        }
        Self::check_staging_context(
            &envelope,
            binding,
            admission,
            requested_route_digest.as_ref(),
            actual_route_digest.as_ref(),
        )?;
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
            self.record_best_effort_drop(
                stream_id,
                sequence,
                &transport_hash,
                &envelope_digest,
                envelope.delivery,
                BestEffortDropReason::ConflictingDuplicate,
            );
            return Err(IngestError::ConflictingDuplicate);
        }
        let durable = self
            .progress
            .get(stream_id)
            .map_or(0, |progress| progress.last_durable_sequence);
        if sequence <= durable {
            self.record_best_effort_drop(
                stream_id,
                sequence,
                &transport_hash,
                &envelope_digest,
                envelope.delivery,
                BestEffortDropReason::StaleSequence,
            );
            return Err(IngestError::StaleSequence);
        }
        if envelope.producer_adapter_identity != ACP_NORMALIZER_IDENTITY {
            return Err(IngestError::EnvelopeMismatch("producer_adapter_identity"));
        }
        if self.records.len() >= MAX_JOURNAL_RECORDS {
            return Err(IngestError::CapacityExhausted);
        }
        if self
            .stored_bytes
            .saturating_add(stored.bytes().len() as u64)
            > MAX_JOURNAL_STORED_BYTES
        {
            return Err(IngestError::CapacityExhausted);
        }
        self.stored_bytes = self
            .stored_bytes
            .saturating_add(stored.bytes().len() as u64);
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
                    normalized: false,
                    applied_count: 0,
                    applied_receipt: None,
                    acked: false,
                },
            },
        );
        Ok(StageOutcome { key, fresh: true })
    }

    /// Checks the staging lineage context before any mutation: an
    /// execution-unit envelope must arrive with its recorded #361 binding and
    /// #369 admission, validated exactly (wrong attempt, binding, fence,
    /// generation, cursor, or route reference rejects here); a session-only
    /// envelope must arrive without them, carrying no attempt authority and
    /// no admission reference. The carried requested/actual route digests must
    /// anchor the envelope's admission reference (see
    /// [`Self::check_route_digests`]).
    fn check_staging_context(
        envelope: &NormalizedHostEventEnvelope,
        binding: Option<&ProviderExecutionBinding>,
        admission: Option<&AdmittedRouteReceipt>,
        requested_route_digest: Option<&LowercaseSha256>,
        actual_route_digest: Option<&LowercaseSha256>,
    ) -> Result<(), IngestError> {
        match &envelope.lineage {
            ProviderObservationLineage::SessionObservation(_) => {
                if binding.is_some() {
                    return Err(IngestError::InvalidInput("binding/lineage"));
                }
                if admission.is_some() {
                    return Err(IngestError::InvalidInput("admission/lineage"));
                }
            }
            ProviderObservationLineage::ExecutionUnitObservation(_) => {
                let binding = binding.ok_or(IngestError::InvalidInput("binding/lineage"))?;
                let admission = admission.ok_or(IngestError::InvalidInput("admission/lineage"))?;
                envelope
                    .validate_for_lineage(binding, admission)
                    .map_err(IngestError::Contract)?;
            }
        }
        Self::check_route_digests(
            envelope.admitted_route_digest.as_ref(),
            requested_route_digest,
            actual_route_digest,
        )
    }

    /// Checks that the carried route-reference digests anchor the envelope's
    /// admission reference: session envelopes (no admission reference) carry
    /// no route digests; execution envelopes must carry at least one digest
    /// equal to the admission reference. Divergent route columns reject
    /// before any mutation.
    fn check_route_digests(
        admitted: Option<&LowercaseSha256>,
        requested: Option<&LowercaseSha256>,
        actual: Option<&LowercaseSha256>,
    ) -> Result<(), IngestError> {
        match admitted {
            None => {
                if requested.is_some() || actual.is_some() {
                    return Err(IngestError::EnvelopeMismatch("route_digest"));
                }
            }
            Some(admitted) => {
                if requested != Some(admitted) && actual != Some(admitted) {
                    return Err(IngestError::EnvelopeMismatch("route_digest"));
                }
            }
        }
        Ok(())
    }

    /// Checks that the envelope binds the stored bytes: schema version,
    /// stream sequence, `raw_source` digest over the stored bytes under its
    /// declared algorithm, and receipt coherence, plus framing validation for
    /// session lineage.
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
        Self::check_source_digest(&envelope.raw_source.digest, stored.bytes())?;
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

    /// Verifies the envelope source digest against the stored bytes under its
    /// declared algorithm qualifier. Canonical-JSON digests decode the stored
    /// bytes (bare or single-framed) and recompute over the canonical message
    /// (see
    /// [`QualifiedSourceDigest::verify_canonical_message`](eliot_agent_api::QualifiedSourceDigest::verify_canonical_message)),
    /// so whitespace/key-order variants of one message verify while the
    /// digest of unrelated bytes fails here before any cursor moves.
    /// Raw-bytes digests (typed quarantine, deterministic redacted
    /// projections) recompute over the stored bytes exactly. The immutable
    /// transport hash is preserved separately on the durable record either
    /// way, never collapsed into the semantic digest.
    fn check_source_digest(
        digest: &QualifiedSourceDigest,
        stored: &[u8],
    ) -> Result<(), IngestError> {
        if digest.algorithm == HOST_EVENT_DIGEST_ALGORITHM {
            let message = decode_source_message(stored)
                .map_err(|_| IngestError::EnvelopeMismatch("raw_source"))?;
            digest
                .verify_canonical_message(&message)
                .map_err(|_| IngestError::EnvelopeMismatch("raw_source"))?;
            return Ok(());
        }
        if digest.algorithm == HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM {
            digest
                .verify_raw_bytes(stored)
                .map_err(|_| IngestError::EnvelopeMismatch("raw_source"))?;
            return Ok(());
        }
        Err(IngestError::EnvelopeMismatch("digest_algorithm"))
    }
}
