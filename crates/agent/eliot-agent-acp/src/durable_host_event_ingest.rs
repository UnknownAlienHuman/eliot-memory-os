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
//! requested and actual route references plus the versioned validated
//! route-evidence relation binding them to their owners;
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

use eliot_agent_api::route_receipts::{
    COMMITTED_ROUTE_EVIDENCE_SCHEMA_VERSION, CommittedRouteEvidenceRelation,
};
use eliot_agent_api::{
    AdmittedRouteReceipt, CommittedHostEventIntake, ContractError, EventCursor, EventId,
    HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM, HostEventDeliveryDisposition,
    HostEventPrivacyClass, LowercaseSha256, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
    ProviderObservationLineage, QualifiedSourceDigest,
    host_event::HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM, route_fingerprint_digest_for,
};
use eliot_contracts::sha256_hex;
use eliot_evaluation_contracts::{
    CoverageBlindInterval, CoverageCompleteness, DenominatorOrigin, EvaluationContractError,
    EventCounts, MaterialActionCoverage, ObservationCoverageManifest, RunFingerprint,
    SequenceFaults, StreamCursorRange,
};
use eliot_receipts::ProofCeiling;
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
    /// A constructed coverage manifest failed contract validation. The exact
    /// denominator fault travels in the typed contract error; nothing is
    /// retained on this path.
    #[error("coverage manifest failed validation")]
    Manifest(#[from] EvaluationContractError),
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
///            live on every read (envelope digest recomputed against the
///            stored bytes and the declared output digest); failed
///            re-verification reports DURABLE, never a higher phase. The
///            commit-time `normalized` memo is never trusted here.
/// APPLIED    committed envelope applied to state exactly once with a
///            canonical application receipt bound by the state-application
///            owner (never self-minted by this journal); duplicate replays
///            return the existing receipt without a second application.
///            Until that owner binds its receipt the record reports
///            NORMALIZED-with-application-counted, never APPLIED.
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
/// linked normalized projection verified at commit time, how many times the
/// envelope was applied to state, the bound application receipt, and whether
/// it was acknowledged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordDisposition {
    /// True once the durable relation is committed and the cursor published.
    pub committed: bool,
    /// Commit-time memo that the linked normalized projection verified when
    /// the durable relation was committed. Never trusted by
    /// [`DurableHostEventRecord::phase`], which re-verifies the linkage live
    /// on every read; a corrupted projection still reports DURABLE.
    pub normalized: bool,
    /// Number of state applications (0 or 1; duplicates never re-apply).
    pub applied_count: u32,
    /// Canonical application receipt bound by the state-application owner on
    /// the single recorded application. This journal never mints it: a lost
    /// acknowledgement after commit replays to the existing count/phase, and
    /// only the owner's bound receipt advances the phase to APPLIED.
    /// `None` until the owner binds its receipt.
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
    /// Versioned validated route-evidence relation (issue #2645 W5). `Some`
    /// exactly for execution-unit lineage: resolved from the governing #369
    /// admission and the applicable #369 physical observation (or its explicit
    /// absence) by the staging gate before any mutation, carrying the
    /// role-qualified requested/actual digests plus the exact
    /// owner-resolvable admission and observation references. `None` exactly
    /// for session-only lineage, which carries no route authority.
    pub route_evidence: Option<CommittedRouteEvidenceRelation>,
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
    /// APPLIED requires the single recorded application with the canonical
    /// application receipt bound by the state-application owner; NORMALIZED
    /// requires the commit plus a live re-verification of the linked
    /// normalized projection on every read (envelope digest recomputed
    /// against the stored bytes and the declared output digest), so a
    /// corrupted projection reports DURABLE and never a higher phase — the
    /// commit-time `normalized` memo is evidence of what verified at commit,
    /// never a substitute for live verification. Anything staged but
    /// uncommitted is RECEIVED. Failed normalization never creates a record
    /// at all: it stays a typed [`IngestError`] with its exact reason.
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
            if linked {
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

/// Caller-resolved view of the allowed Tool/Facet manifest revision used by
/// [`DurableHostEventJournal::resolve_host_compliance_facts`]. The view
/// carries the revision-pinned digest every resolved fact binds plus the
/// declared and forbidden tool sets that decision resolves against; the
/// journal never invents permission facts from model output.
#[derive(Clone, Debug)]
pub struct AllowedHostManifestView<'a> {
    /// Revision-pinned allowed-manifest digest bound into resolved facts.
    pub manifest_digest: &'a str,
    /// Human revision label carried into the retained facts.
    pub manifest_revision: &'a str,
    /// Tool names the revision declares.
    pub declared_tool_names: &'a [String],
    /// Tool names the revision forbids.
    pub forbidden_tool_names: &'a [String],
}

/// One committed record resolved to host-observed compliance facts: retained
/// event identity, normalized envelope digest, bound transformation version,
/// and the tool or non-tool action identity with its declared/forbidden
/// decision resolved against the allowed revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHostRecord {
    /// Sequence within the owning stream.
    pub sequence: u64,
    /// Retained normalized event identity.
    pub event_id: String,
    /// Canonical digest of the retained normalized envelope.
    pub envelope_digest: String,
    /// Transformation pipeline version bound into the retained record.
    pub transformation_version: String,
    /// Retained tool identity for tool payloads; `None` for non-tool actions.
    pub tool_name: Option<String>,
    /// Stable payload tag for non-tool actions; `None` for tool payloads.
    pub non_tool_action: Option<String>,
    /// True when the allowed revision declares this tool.
    pub declared: bool,
    /// True when the allowed revision forbids this tool.
    pub forbidden: bool,
}

/// Compliance facts resolved from retained journal records for one stream:
/// the bound allowed-manifest revision, the exact stream cursor, and one row
/// per committed record in sequence order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHostComplianceFacts {
    /// Allowed-manifest digest every row binds.
    pub manifest_digest: String,
    /// Allowed-manifest revision label.
    pub manifest_revision: String,
    /// Exact stream cursor at resolution time.
    pub stream: StreamCursorState,
    /// One row per committed record, in sequence order.
    pub records: Vec<ResolvedHostRecord>,
}

/// Caller-declared denominator half of one coverage manifest, joined by
/// [`DurableHostEventJournal::record_coverage_manifest`] to the
/// journal-measured cursor, count, fault, and blind-interval facts for one
/// product/session/attempt/route fingerprint (issue #1936 W1, I7.23).
///
/// Every declaration here is evidence the journal cannot mint: the expected
/// sources/classes, the observable versus unobservable action split, the
/// missing-source reasons, the per-material-action coverage, the denominator
/// origin and sampling policy, the claimed completeness, and the invalidation
/// dependencies. The journal never invents these from model output, and the
/// joined manifest still validates fail-closed, so a declared `COMPLETE`
/// over measured gaps or unaccounted events is rejected typed.
#[derive(Clone, Debug)]
pub struct CoverageManifestPlan<'a> {
    /// Fingerprint the constructed manifest is retained under.
    pub fingerprint: &'a RunFingerprint,
    /// Revision-pinned allowed-manifest digest the denominator binds.
    pub allowed_manifest_digest: &'a str,
    /// Declared expected event sources and classes.
    pub expected_event_sources_and_event_classes: &'a [String],
    /// Actions host observation can see.
    pub observable_actions: &'a [String],
    /// Actions host observation cannot see. Unobservable host-access coverage
    /// forces the derived trace to `UNKNOWN` or `TAINTED`, never a
    /// self-reported `PASS`.
    pub unobservable_actions: &'a [String],
    /// Declared missing-source reasons.
    pub missing_source_reasons: &'a [String],
    /// Declared per-material-action and effect-route coverage.
    pub coverage_by_material_action_and_effect_route: &'a [MaterialActionCoverage],
    /// Declared denominator origin and sampling policy.
    pub denominator_origin_and_sampling_policy: &'a DenominatorOrigin,
    /// Claimed completeness, checked against the measured facts.
    pub completeness: CoverageCompleteness,
    /// Declared invalidation dependencies.
    pub invalidation_dependencies: &'a [String],
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
    /// Recorded #369 physical-route observation for this event's observation
    /// boundary. `None` exactly when no observation applies yet (a valid
    /// pre-observation event records the applicable absence with no actual
    /// digest); `Some` is fully validated against the binding and admission
    /// (`DurableHostEventJournal::check_route_digests`) and determines the
    /// actual column. Forbidden for session-only lineage.
    pub physical_observation: Option<&'a PhysicalRouteObservationReceipt>,
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
    /// Recorded #369 physical-route observation for this event's observation
    /// boundary, with the same required/forbidden shape as the allowed path
    /// above. The allowed and redacted paths enforce identical route rules.
    pub physical_observation: Option<&'a PhysicalRouteObservationReceipt>,
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

/// Owner-derived route digests for one execution-unit event (issue #2645
/// W1/W3).
///
/// This is the production execution-unit caller path into durable staging:
/// instead of accepting caller-supplied requested/actual hashes, the caller
/// supplies the exact owner material — the recorded #361 binding, the
/// governing #369 admission, and the applicable #369 physical observation
/// (or its explicit absence) — and this resolver derives the role-qualified
/// column digests with the existing [`route_fingerprint_digest_for`] recipe
/// and validates the observation with the existing
/// [`PhysicalRouteObservationReceipt::validate_against`] (which itself runs
/// the observation's [`PhysicalRouteObservationReceipt::validate`]). No new
/// hash recipe, no reinterpreted column, no test-only caller:
/// [`StageAllowed::execution_unit`] and [`StageRedacted::execution_unit`]
/// are the real constructors the execution-unit producer/normalizer calls,
/// and the staging guard recomputes the same digests from the same owners
/// before any mutation, so substituted caller bytes can never pass through
/// this path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionUnitRouteEvidence {
    /// Fingerprint digest recomputed from the admission's original requested
    /// route (logical-request identity, never the admission self-digest).
    pub requested_route_digest: LowercaseSha256,
    /// Fingerprint digest recomputed from the validated observation's
    /// observed route; `None` exactly when no observation applies yet (a
    /// valid pre-observation event) or the observation reports `Unobserved`.
    /// Never copied from requested/selected/admission bytes.
    pub actual_route_digest: Option<LowercaseSha256>,
}

impl ExecutionUnitRouteEvidence {
    /// Resolves role-qualified digests from validated owner material.
    ///
    /// The admission and binding validate through their existing owners;
    /// a supplied observation fully validates against them (exact
    /// attempt/binding/fence/generation/admission linkage plus the
    /// legitimate admission-selection boundary); the requested column binds
    /// the admission's original requested route and the actual column binds
    /// the observation's observed route, each recomputed here rather than
    /// trusted as a caller string. Typed contract failures travel as
    /// [`IngestError::Contract`]; digest-encoding failures as
    /// [`IngestError::DigestEncoding`].
    pub fn resolve(
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        physical_observation: Option<&PhysicalRouteObservationReceipt>,
    ) -> Result<Self, IngestError> {
        admission.validate()?;
        binding.validate_internal()?;
        let requested_route_digest = route_fingerprint_digest_for(&admission.requested_route)
            .map_err(|_| IngestError::DigestEncoding)?;
        let Some(observation) = physical_observation else {
            return Ok(Self {
                requested_route_digest,
                actual_route_digest: None,
            });
        };
        observation.validate_against(binding, admission)?;
        let actual_route_digest = observation
            .observed_route
            .as_ref()
            .map(route_fingerprint_digest_for)
            .transpose()
            .map_err(|_| IngestError::DigestEncoding)?;
        Ok(Self {
            requested_route_digest,
            actual_route_digest,
        })
    }
}

/// Binds a supplied observation's causal position to the envelope's
/// lineage-declared position before any owner digest is derived (issue #2645
/// W1/A1): a receipt minted for another cursor/sequence boundary — even with
/// the same attempt, binding, admission, fence, and generation — cannot
/// justify this event's actual-route column. Session lineage carries no
/// attempt authority, so an execution-unit construction over it rejects.
fn check_execution_unit_observation_applicability(
    envelope: &NormalizedHostEventEnvelope,
    physical_observation: Option<&PhysicalRouteObservationReceipt>,
) -> Result<(), IngestError> {
    match &envelope.lineage {
        ProviderObservationLineage::SessionObservation(_) => {
            Err(IngestError::InvalidInput("binding/lineage"))
        }
        ProviderObservationLineage::ExecutionUnitObservation(lineage) => {
            if let Some(observation) = physical_observation
                && (observation.event_cursor != lineage.cursor
                    || observation.event_sequence != lineage.sequence)
            {
                return Err(IngestError::Contract(ContractError::BindingMismatch));
            }
            Ok(())
        }
    }
}

impl<'a> StageAllowed<'a> {
    /// Builds an execution-unit staging request from validated owner
    /// material (issue #2645 W1/W3).
    ///
    /// The production execution-unit producer/normalizer calls this
    /// constructor — not the struct literal — with the exact binding,
    /// governing admission, and applicable physical observation (or its
    /// explicit absence for a valid pre-observation event). Requested/actual
    /// digests are derived from those owners here and re-verified by the
    /// staging guard before any mutation; no caller hash is trusted. The
    /// session-only producer path keeps its struct-literal `None` shape
    /// untouched.
    #[allow(clippy::too_many_arguments)]
    pub fn execution_unit(
        stream_id: &'a str,
        stream_sequence: u64,
        transport_bytes: &'a [u8],
        envelope: NormalizedHostEventEnvelope,
        binding: &'a ProviderExecutionBinding,
        admission: &'a AdmittedRouteReceipt,
        physical_observation: Option<&'a PhysicalRouteObservationReceipt>,
        predecessors: Vec<EventId>,
        warnings: Vec<String>,
        transformation_version: &'a str,
    ) -> Result<Self, IngestError> {
        check_execution_unit_observation_applicability(&envelope, physical_observation)?;
        let evidence =
            ExecutionUnitRouteEvidence::resolve(binding, admission, physical_observation)?;
        Ok(Self {
            stream_id,
            stream_sequence,
            transport_bytes,
            envelope,
            binding: Some(binding),
            admission: Some(admission),
            physical_observation,
            requested_route_digest: Some(evidence.requested_route_digest),
            actual_route_digest: evidence.actual_route_digest,
            predecessors,
            warnings,
            transformation_version,
        })
    }
}

impl<'a> StageRedacted<'a> {
    /// Builds an execution-unit redacted staging request from validated
    /// owner material (issue #2645 W1/W3).
    ///
    /// Identical owner rules to [`StageAllowed::execution_unit`]: the exact
    /// binding, governing admission, and applicable physical observation (or
    /// its explicit absence) supply the requested/actual digests through
    /// [`ExecutionUnitRouteEvidence::resolve`], and the allowed and redacted
    /// paths enforce identical route rules. The session-only producer path
    /// keeps its struct-literal `None` shape untouched.
    #[allow(clippy::too_many_arguments)]
    pub fn execution_unit(
        stream_id: &'a str,
        stream_sequence: u64,
        transport_bytes: &'a [u8],
        redacted_classes: Vec<String>,
        envelope: NormalizedHostEventEnvelope,
        binding: &'a ProviderExecutionBinding,
        admission: &'a AdmittedRouteReceipt,
        physical_observation: Option<&'a PhysicalRouteObservationReceipt>,
        predecessors: Vec<EventId>,
        warnings: Vec<String>,
        transformation_version: &'a str,
    ) -> Result<Self, IngestError> {
        check_execution_unit_observation_applicability(&envelope, physical_observation)?;
        let evidence =
            ExecutionUnitRouteEvidence::resolve(binding, admission, physical_observation)?;
        Ok(Self {
            stream_id,
            stream_sequence,
            transport_bytes,
            redacted_classes,
            envelope,
            binding: Some(binding),
            admission: Some(admission),
            physical_observation,
            requested_route_digest: Some(evidence.requested_route_digest),
            actual_route_digest: evidence.actual_route_digest,
            predecessors,
            warnings,
            transformation_version,
        })
    }
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
    /// Retained coverage denominators by product/session/attempt/route
    /// fingerprint (issue #1936 W1). One validated manifest per fingerprint;
    /// re-recording supersedes without deleting, and dependent traces
    /// revalidate through their ledger invalidation handles.
    coverage_manifests: BTreeMap<(String, String, String, String), ObservationCoverageManifest>,
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
    ///
    /// Route-relation contract (issues #2645 W5/W6): commit implies the
    /// record's requested/actual route columns already passed owner-qualified
    /// staging validation (admission fingerprint for requested, validated
    /// physical observation for actual, explicit absence otherwise), and this
    /// projection readback-validates the retained versioned
    /// [`CommittedRouteEvidenceRelation`] before converting: the relation's
    /// owner references must bind the envelope-carried admission reference
    /// and the relation's role-qualified columns must equal the retained
    /// record columns, or conversion fails closed. A pre-fix execution-unit
    /// row (relation absent or legacy-versioned) converts with the explicit
    /// unverified legacy disposition instead: its retained columns travel as
    /// forensic evidence, never as verified binding, and dependent use stays
    /// restricted. A consumer that uses route claims receives the validated
    /// relation in this view (same relation is also available through
    /// [`Self::committed_route_evidence`]) and requires its `Verified`
    /// disposition; the envelope's `admitted_route_digest` travels in this
    /// view as the exact owner-resolvable admission reference. No unused
    /// column is declared proof of coordinator validation here.
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
        Self::check_retained_route_evidence(record)?;
        CommittedHostEventIntake::from_envelope(
            &record.envelope,
            record.disposition.acked,
            record.route_evidence.clone(),
        )
        .map_err(IngestError::Contract)
    }

    /// Returns the retained versioned route-evidence relation for one
    /// committed record (issues #2645 W5/W6): `Some` exactly for
    /// execution-unit lineage carrying a current-version relation — the
    /// role-qualified requested/actual digests plus the exact
    /// owner-resolvable admission and observation references; `None` exactly
    /// for session-only lineage, which carries no route authority, and for
    /// pre-fix execution-unit rows, whose absent or legacy-versioned relation
    /// reads as the explicit unverified legacy disposition on the converted
    /// intake view instead. A route-claim consumer requires that view's
    /// `Verified` disposition: `None` here never authorizes route use.
    ///
    /// The retained relation is readback-validated before it is handed out
    /// (see [`Self::check_retained_route_evidence`]): a current-version
    /// relation that drifted from the envelope-carried admission reference
    /// or the retained record columns fails closed here instead of reaching
    /// a route-claim consumer.
    /// A staged-but-uncommitted record reports [`IngestError::NotCommitted`].
    pub fn committed_route_evidence(
        &self,
        key: &EventKey,
    ) -> Result<Option<CommittedRouteEvidenceRelation>, IngestError> {
        let record = self
            .records
            .get(&(key.stream_id.clone(), key.sequence))
            .ok_or(IngestError::UnknownRecord)?;
        if !record.disposition.committed {
            return Err(IngestError::NotCommitted);
        }
        Self::check_retained_route_evidence(record)?;
        Ok(record.route_evidence.clone())
    }

    /// Readback-validates the retained route-evidence relation of one record
    /// (issues #2645 W5/W6) without the owner receipts at hand: session-only
    /// lineage must retain no relation and no route columns (it carries no
    /// route authority); execution-unit lineage with a current-version
    /// relation must bind the envelope-carried admission reference with
    /// role-qualified columns equal to the retained record columns (see
    /// [`CommittedRouteEvidenceRelation::verify_retained`]); execution-unit
    /// lineage with an absent or legacy-versioned relation is a pre-fix row
    /// and is preserved as-is — its retained columns stay forensic evidence
    /// under the explicit unverified legacy disposition surfaced through the
    /// intake view, never upgraded by column agreement, never deleted, with
    /// no receipt mutated. Any other drift (smuggled session relation,
    /// re-pointed admission, column mismatch on a versioned row) fails
    /// closed with a typed error before the intake converts or the relation
    /// reaches a consumer.
    fn check_retained_route_evidence(record: &DurableHostEventRecord) -> Result<(), IngestError> {
        match &record.envelope.lineage {
            ProviderObservationLineage::SessionObservation(_) => {
                if record.route_evidence.is_some() {
                    return Err(IngestError::Contract(ContractError::BindingMismatch));
                }
                if record.requested_route_digest.is_some() || record.actual_route_digest.is_some() {
                    return Err(IngestError::EnvelopeMismatch("route_digest"));
                }
                Ok(())
            }
            ProviderObservationLineage::ExecutionUnitObservation(_) => {
                let Some(evidence) = record.route_evidence.as_ref() else {
                    return Ok(());
                };
                if evidence.schema_version != COMMITTED_ROUTE_EVIDENCE_SCHEMA_VERSION {
                    return Ok(());
                }
                evidence
                    .verify_retained(
                        record.envelope.admitted_route_digest.as_ref(),
                        record.requested_route_digest.as_ref(),
                        record.actual_route_digest.as_ref(),
                    )
                    .map_err(IngestError::Contract)
            }
        }
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

    /// Resolves host-observed compliance facts for one stream from retained
    /// immutable records only (issue #1936, I7.23).
    ///
    /// Every returned fact comes from a committed journal record: the
    /// retained event identity, the normalized envelope digest, the bound
    /// transformation version, and the exact stream cursor. Declared and
    /// forbidden tool facts resolve against the caller-supplied allowed
    /// Tool/Facet manifest revision (`allowed`); tool names are the retained
    /// normalized payload identities, never caller-supplied model JSON. A
    /// stream holding any staged-but-uncommitted record reports
    /// [`IngestError::NotCommitted`]: uncommitted facts might contain the
    /// prohibited action, so they are never silently treated as absent.
    /// Exact replays need no extra pass: storage is keyed by source-event
    /// identity `(stream_id, sequence)`, so one stored record yields exactly
    /// one resolved row.
    ///
    /// Retained envelopes carry no filesystem path, URL, or effect-route
    /// facts, so this resolution emits no access, write, or external-effect
    /// rows. That host-access coverage stays unobservable on the
    /// `ObservationCoverageManifest` (unobservable actions and material
    /// coverage), which forces the derived trace to `UNKNOWN` or `TAINTED`
    /// instead of a self-reported `PASS`.
    pub fn resolve_host_compliance_facts(
        &self,
        stream_id: &str,
        allowed: &AllowedHostManifestView<'_>,
    ) -> Result<ResolvedHostComplianceFacts, IngestError> {
        validate_stream_id(stream_id)?;
        if allowed.manifest_digest.trim().is_empty() {
            return Err(IngestError::InvalidInput("allowed.manifest_digest"));
        }
        if allowed.manifest_revision.trim().is_empty() {
            return Err(IngestError::InvalidInput("allowed.manifest_revision"));
        }
        for tool in allowed
            .declared_tool_names
            .iter()
            .chain(allowed.forbidden_tool_names.iter())
        {
            if tool.trim().is_empty() {
                return Err(IngestError::InvalidInput("allowed.tool_names"));
            }
        }
        let mut stored: Vec<&DurableHostEventRecord> = self
            .records
            .iter()
            .filter(|((record_stream, _), _)| record_stream == stream_id)
            .map(|(_, record)| record)
            .collect();
        stored.sort_by_key(|record| record.sequence);
        let mut records = Vec::with_capacity(stored.len());
        for record in stored {
            if !record.disposition.committed {
                return Err(IngestError::NotCommitted);
            }
            let (tool_name, non_tool_action) = match &record.envelope.payload {
                NormalizedHostEventPayload::ToolInvocation(observation) => {
                    (Some(observation.tool_name.clone()), None)
                }
                NormalizedHostEventPayload::ToolOutcome(observation) => {
                    (Some(observation.tool_name.clone()), None)
                }
                payload => (None, Some(payload.payload_type_tag().to_owned())),
            };
            let (declared, forbidden) = match &tool_name {
                Some(name) => (
                    allowed
                        .declared_tool_names
                        .iter()
                        .any(|entry| entry == name),
                    allowed
                        .forbidden_tool_names
                        .iter()
                        .any(|entry| entry == name),
                ),
                None => (false, false),
            };
            records.push(ResolvedHostRecord {
                sequence: record.sequence,
                event_id: record.envelope.event_id.as_str().to_owned(),
                envelope_digest: record.envelope_digest.as_str().to_owned(),
                transformation_version: record.transformation_version.clone(),
                tool_name,
                non_tool_action,
                declared,
                forbidden,
            });
        }
        Ok(ResolvedHostComplianceFacts {
            manifest_digest: allowed.manifest_digest.to_owned(),
            manifest_revision: allowed.manifest_revision.to_owned(),
            stream: self.cursor(stream_id),
            records,
        })
    }

    /// Fingerprint map key for one retained coverage manifest.
    fn coverage_manifest_key(fingerprint: &RunFingerprint) -> (String, String, String, String) {
        (
            fingerprint.product_id.clone(),
            fingerprint.session_id.clone(),
            fingerprint.attempt_id.clone(),
            fingerprint.route_fingerprint.clone(),
        )
    }

    /// Constructs and retains the coverage denominator for one
    /// product/session/attempt/route fingerprint (issue #1936 W1, I7.23).
    ///
    /// The caller declares the denominator halves the journal cannot observe
    /// ([`CoverageManifestPlan`]); the journal measures the halves it owns:
    /// per-stream expected cursor ranges from the durable cursors (commits
    /// are contiguous from one, and cursor facts are never evicted, so each
    /// committed stream binds `1..=last_durable`), received/applied/unknown
    /// counts from the committed records (rejections stay typed
    /// [`IngestError`] returns, never records), sequence gaps from the
    /// retained best-effort drop gaps with one localized blind interval per
    /// dropped sequence, and a fixed [`ProofCeiling::Observation`] ceiling
    /// host observation never exceeds. Exact replays need no extra pass:
    /// storage is keyed by source-event identity, so one stored record yields
    /// exactly one counted event.
    ///
    /// The joined manifest validates through
    /// [`ObservationCoverageManifest::validate`](eliot_evaluation_contracts::ObservationCoverageManifest::validate)
    /// before it is retained: a caller-declared `COMPLETE` over measured
    /// blind intervals or unaccounted events fails typed
    /// ([`IngestError::Manifest`]) and is retained nowhere. Retention is
    /// keyed by fingerprint and re-recording supersedes the retained
    /// manifest; dependent traces revalidate through their ledger
    /// invalidation handles, never by silently recovering.
    ///
    /// Any staged-but-uncommitted record reports
    /// [`IngestError::NotCommitted`]: uncommitted facts might contain the
    /// prohibited action, so they are never silently treated as absent from
    /// the denominator.
    pub fn record_coverage_manifest(
        &mut self,
        plan: &CoverageManifestPlan<'_>,
    ) -> Result<(), IngestError> {
        if plan.allowed_manifest_digest.trim().is_empty() {
            return Err(IngestError::InvalidInput("plan.allowed_manifest_digest"));
        }
        if self
            .records
            .values()
            .any(|record| !record.disposition.committed)
        {
            return Err(IngestError::NotCommitted);
        }
        let mut ranges = Vec::new();
        for (stream_id, progress) in &self.progress {
            if progress.last_durable_sequence == 0 {
                continue;
            }
            ranges.push(StreamCursorRange {
                stream: stream_id.clone(),
                first_expected_cursor: 1,
                last_expected_cursor: progress.last_durable_sequence,
            });
        }
        if ranges.is_empty() {
            return Err(IngestError::InvalidInput("coverage_manifest.streams"));
        }
        let mut received = 0u64;
        let mut applied = 0u64;
        for record in self.records.values() {
            received += 1;
            if record.disposition.applied_count > 0 {
                applied += 1;
            }
        }
        let mut blind_cursors: Vec<(String, u64, &'static str)> = self
            .dropped_gaps
            .iter()
            .map(|gap| {
                let reason = match gap.reason {
                    BestEffortDropReason::ConflictingDuplicate => {
                        "best-effort-drop:CONFLICTING_DUPLICATE"
                    }
                    BestEffortDropReason::StaleSequence => "best-effort-drop:STALE_SEQUENCE",
                };
                (gap.stream_id.clone(), gap.sequence, reason)
            })
            .collect();
        blind_cursors.sort();
        blind_cursors.dedup_by(|first, second| first.0 == second.0 && first.1 == second.1);
        let blind_intervals_and_missing_source_reasons = blind_cursors
            .into_iter()
            .map(|(stream, sequence, reason)| CoverageBlindInterval {
                stream,
                first_missing_cursor: sequence,
                last_missing_cursor: sequence,
                reason: reason.to_owned(),
            })
            .collect();
        let manifest = ObservationCoverageManifest {
            fingerprint: plan.fingerprint.clone(),
            allowed_manifest_digest: plan.allowed_manifest_digest.to_owned(),
            expected_event_sources_and_event_classes: plan
                .expected_event_sources_and_event_classes
                .to_vec(),
            observable_actions: plan.observable_actions.to_vec(),
            unobservable_actions: plan.unobservable_actions.to_vec(),
            first_and_last_expected_cursors_by_stream: ranges,
            counts: EventCounts {
                received,
                applied,
                rejected: 0,
                unknown: received - applied,
            },
            sequence_faults: SequenceFaults {
                gaps: self.dropped_gaps.len() as u64,
                duplicates: 0,
                reorders: 0,
                payload_mutations: 0,
            },
            blind_intervals_and_missing_source_reasons,
            missing_source_reasons: plan.missing_source_reasons.to_vec(),
            coverage_by_material_action_and_effect_route: plan
                .coverage_by_material_action_and_effect_route
                .to_vec(),
            denominator_origin_and_sampling_policy: plan
                .denominator_origin_and_sampling_policy
                .clone(),
            completeness: plan.completeness,
            proof_ceiling: ProofCeiling::Observation,
            invalidation_dependencies: plan.invalidation_dependencies.to_vec(),
        };
        manifest.validate()?;
        self.coverage_manifests
            .insert(Self::coverage_manifest_key(&manifest.fingerprint), manifest);
        Ok(())
    }

    /// Returns the retained coverage manifest for `fingerprint`, if one was
    /// recorded by [`Self::record_coverage_manifest`]. Lookup is by exact
    /// product/session/attempt/route match: a manifest recorded for another
    /// fingerprint never serves this one.
    #[must_use]
    pub fn coverage_manifest(
        &self,
        fingerprint: &RunFingerprint,
    ) -> Option<&ObservationCoverageManifest> {
        self.coverage_manifests
            .get(&Self::coverage_manifest_key(fingerprint))
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
            request.physical_observation,
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
            request.physical_observation,
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
            // projection, and the disposition together. The `normalized` memo
            // is set only when the linkage verifies live right here
            // (envelope digest recomputed against the stored bytes and the
            // declared output digest); [`DurableHostEventRecord::phase`] still
            // re-verifies live on every read and never trusts this memo.
            let linked = record
                .envelope
                .compute_digest()
                .is_ok_and(|digest| digest == record.envelope_digest)
                && record.envelope_digest == record.envelope.normalization.output_digest;
            record.disposition.normalized = linked;
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
        while let Ok(page) = self.pending_page_for_reconnect(&scope, after, MAX_PENDING_PAGE_ITEMS)
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
    /// The first application records the application count only: this journal
    /// never mints the canonical application receipt (a self-minted envelope
    /// digest would claim application without performing any), so the phase
    /// stays NORMALIZED-with-application-counted until the
    /// state-application owner binds its canonical receipt, and a lost
    /// acknowledgement after commit replays to the existing count/phase
    /// instead of duplicating the application.
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
        physical_observation: Option<&PhysicalRouteObservationReceipt>,
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
            physical_observation,
            requested_route_digest.as_ref(),
            actual_route_digest.as_ref(),
        )?;
        // Versioned route-evidence relation (issue #2645 W5): resolved from
        // the same validated owners by the same gate, before any mutation,
        // so the persisted record carries the exact owner-resolvable
        // references alongside the columns.
        let route_evidence =
            Self::retained_route_evidence(&envelope, binding, admission, physical_observation)?;
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
            if Self::staged_replay_identical(
                existing,
                &hash_hex,
                &envelope_digest,
                requested_route_digest.as_ref(),
                actual_route_digest.as_ref(),
                route_evidence.as_ref(),
            ) {
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
        self.insert_staged_record(
            stream_id,
            sequence,
            transport_hash,
            stored,
            envelope,
            envelope_digest,
            requested_route_digest,
            actual_route_digest,
            route_evidence,
            predecessors,
            warnings,
            transformation_version,
            key,
        )
    }

    /// Exact-replay identity for one stored record (issue #2645 W4): an
    /// identical redelivery under one cursor is idempotent, while changed
    /// route metadata under the same event identity is not — the retained
    /// versioned route-evidence relation compares alongside the existing
    /// transport/envelope/column commitment, so drift conflicts instead of
    /// restaging silently.
    fn staged_replay_identical(
        existing: &DurableHostEventRecord,
        hash_hex: &str,
        envelope_digest: &LowercaseSha256,
        requested_route_digest: Option<&LowercaseSha256>,
        actual_route_digest: Option<&LowercaseSha256>,
        route_evidence: Option<&CommittedRouteEvidenceRelation>,
    ) -> bool {
        existing.transport_hash.as_str() == hash_hex
            && existing.envelope_digest == *envelope_digest
            && existing.requested_route_digest.as_ref() == requested_route_digest
            && existing.actual_route_digest.as_ref() == actual_route_digest
            && existing.route_evidence.as_ref() == route_evidence
    }

    /// Fresh-record insertion for the shared staging core: stale-sequence,
    /// adapter-identity, and capacity gates, then the staged insert. Never
    /// advances a cursor. Idempotent replays never reach here (they return
    /// above without storing), so capacity failures here always mean
    /// genuinely new bytes.
    #[allow(clippy::too_many_arguments)]
    fn insert_staged_record(
        &mut self,
        stream_id: &str,
        sequence: u64,
        transport_hash: LowercaseSha256,
        stored: StoredPayload,
        envelope: NormalizedHostEventEnvelope,
        envelope_digest: LowercaseSha256,
        requested_route_digest: Option<LowercaseSha256>,
        actual_route_digest: Option<LowercaseSha256>,
        route_evidence: Option<CommittedRouteEvidenceRelation>,
        predecessors: Vec<EventId>,
        warnings: Vec<String>,
        transformation_version: &str,
        key: EventKey,
    ) -> Result<StageOutcome, IngestError> {
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
                route_evidence,
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
    /// each bind their own owner (see [`Self::check_route_digests`]).
    #[allow(clippy::too_many_arguments)]
    fn check_staging_context(
        envelope: &NormalizedHostEventEnvelope,
        binding: Option<&ProviderExecutionBinding>,
        admission: Option<&AdmittedRouteReceipt>,
        physical_observation: Option<&PhysicalRouteObservationReceipt>,
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
                if physical_observation.is_some() {
                    return Err(IngestError::InvalidInput("observation/lineage"));
                }
            }
            ProviderObservationLineage::ExecutionUnitObservation(lineage) => {
                let binding = binding.ok_or(IngestError::InvalidInput("binding/lineage"))?;
                let admission = admission.ok_or(IngestError::InvalidInput("admission/lineage"))?;
                envelope
                    .validate_for_lineage(binding, admission)
                    .map_err(IngestError::Contract)?;
                Self::check_route_digests(
                    binding,
                    admission,
                    physical_observation,
                    requested_route_digest,
                    actual_route_digest,
                    &lineage.cursor,
                    lineage.sequence,
                )?;
                return Ok(());
            }
        }
        Self::check_session_route_digests(requested_route_digest, actual_route_digest)
    }

    /// Checks that a session-only envelope carries no route digests: session
    /// lineage has no admission reference and therefore no route authority.
    fn check_session_route_digests(
        requested: Option<&LowercaseSha256>,
        actual: Option<&LowercaseSha256>,
    ) -> Result<(), IngestError> {
        if requested.is_some() || actual.is_some() {
            return Err(IngestError::EnvelopeMismatch("route_digest"));
        }
        Ok(())
    }

    /// Resolves the retained versioned route-evidence relation from the
    /// validated staging owners (issue #2645 W5). Session-only lineage
    /// carries no route authority and retains `None`; execution-unit lineage
    /// retains the relation resolved from the governing admission and the
    /// applicable physical observation (or its explicit absence) via
    /// [`CommittedRouteEvidenceRelation::resolve`], which re-runs the owner
    /// validation instead of trusting caller columns. Runs inside the shared
    /// staging core after [`Self::check_staging_context`] and before any
    /// mutation, so both the allowed and the redacted paths persist the same
    /// relation; exact replay compares it along with the existing
    /// source/envelope commitment, so changed route metadata under one event
    /// identity conflicts instead of restaging silently.
    fn retained_route_evidence(
        envelope: &NormalizedHostEventEnvelope,
        binding: Option<&ProviderExecutionBinding>,
        admission: Option<&AdmittedRouteReceipt>,
        physical_observation: Option<&PhysicalRouteObservationReceipt>,
    ) -> Result<Option<CommittedRouteEvidenceRelation>, IngestError> {
        match &envelope.lineage {
            ProviderObservationLineage::SessionObservation(_) => Ok(None),
            ProviderObservationLineage::ExecutionUnitObservation(_) => {
                let binding = binding.ok_or(IngestError::InvalidInput("binding/lineage"))?;
                let admission = admission.ok_or(IngestError::InvalidInput("admission/lineage"))?;
                CommittedRouteEvidenceRelation::resolve(binding, admission, physical_observation)
                    .map_err(IngestError::Contract)
                    .map(Some)
            }
        }
    }

    /// Checks that the carried execution-unit route-reference digests each
    /// bind their own owner, recomputed here rather than trusted as caller
    /// strings (issue #2645).
    ///
    /// The admission's self-digest is logical-decision identity, not route
    /// identity: an admission digest in either column rejects, since a
    /// matching column must never smuggle an unrelated valid-form hash
    /// through the other. Instead the requested column must equal the
    /// fingerprint digest recomputed from the accepted admission's original
    /// requested route, and the actual column must equal the fingerprint
    /// digest recomputed from the validated physical observation's observed
    /// route, or be absent exactly when no observation applies.
    ///
    /// The observation itself is fully validated with
    /// [`PhysicalRouteObservationReceipt::validate_against`] against this
    /// event's binding and admission: a receipt from another attempt, start
    /// request, generation, fence, or admission boundary rejects, and
    /// the legitimate admission-selection boundary is preserved (the
    /// observation's requested route agrees with the admission's selected
    /// route, while the staged requested column keeps the admission's
    /// original requested route). The observation's own cursor/sequence
    /// position is additionally bound to this event's lineage-declared
    /// cursor/sequence below: a receipt minted for another observation
    /// boundary of the same attempt is not automatically evidence for every
    /// event (`validate_against` cannot see the staged event, so the journal
    /// binds it here before any mutation). A valid divergent observation passes with
    /// its differences retained (it is evidence, never malformed), and an
    /// `Unobserved` observation carries no fabricated actual fingerprint: the
    /// actual column stays absent rather than copying requested bytes. A
    /// pre-observation event stages with no observation and no actual digest;
    /// later immutable observation evidence links as a new record, never as a
    /// silent rewrite.
    #[allow(clippy::too_many_arguments)]
    fn check_route_digests(
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        physical_observation: Option<&PhysicalRouteObservationReceipt>,
        requested: Option<&LowercaseSha256>,
        actual: Option<&LowercaseSha256>,
        event_cursor: &EventCursor,
        event_sequence: u64,
    ) -> Result<(), IngestError> {
        let expected_requested = route_fingerprint_digest_for(&admission.requested_route)
            .map_err(|_| IngestError::DigestEncoding)?;
        if requested != Some(&expected_requested) {
            return Err(IngestError::EnvelopeMismatch("route_digest"));
        }
        let Some(observation) = physical_observation else {
            if actual.is_some() {
                return Err(IngestError::EnvelopeMismatch("route_digest"));
            }
            return Ok(());
        };
        // Causal applicability (issue #2645 W1/A1): the observation's declared
        // position inside the bound execution unit must equal this event's
        // lineage-declared position. A receipt minted for another
        // cursor/sequence boundary — even with the same attempt, binding,
        // admission, fence, and generation — cannot justify this event's
        // actual-route column.
        if observation.event_cursor != *event_cursor || observation.event_sequence != event_sequence
        {
            return Err(IngestError::Contract(ContractError::BindingMismatch));
        }
        observation
            .validate_against(binding, admission)
            .map_err(IngestError::Contract)?;
        let expected_actual = observation
            .observed_route
            .as_ref()
            .map(route_fingerprint_digest_for)
            .transpose()
            .map_err(|_| IngestError::DigestEncoding)?;
        if actual != expected_actual.as_ref() {
            return Err(IngestError::EnvelopeMismatch("route_digest"));
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
