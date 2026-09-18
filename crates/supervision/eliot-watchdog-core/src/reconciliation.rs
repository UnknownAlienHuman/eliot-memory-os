//! Owner-neutral Watchdog spool reconciliation contract.
//!
//! Ownership: the Watchdog owns the spool records and the acknowledged-sequence
//! cursor. The sink owns only its per-entry dispositions. The sink never
//! deletes, mutates, or compacts source records; a retained record advances
//! past the Watchdog-owned cursor only after an exact authenticated sink
//! acknowledgement for the same immutable batch and per-entry disposition.
//! Applying an acknowledgement never writes through the sink.
//!
//! Fail-closed summary: every validator below rejects its input on any shape,
//! identity, range, digest, coverage, terminality, or freshness mismatch. No
//! path advances the cursor on partial, reordered, mutated, expired, or
//! unknown outcomes.
//!
//! Compatibility: entry identity mirrors the spool codec (`sequence`,
//! `schema_version`, `observed_at_ms`, and the three payload classes
//! Heartbeat, Gap, Recovery) without importing it, so this zero-dependency
//! core stays decoupled from the spool owner. Digests are opaque
//! caller-supplied 64-character hex strings; this module validates their shape
//! and equality but never computes them.
//!
//! Disposition terminal table (see
//! [`WatchdogSpoolSinkDisposition::advances_cursor`]):
//!
//! | disposition | heartbeat entry advances | gap/recovery entry advances |
//! |---|---|---|
//! | Received | no | no |
//! | Durable | no | no |
//! | AdmittedCandidate | no | no |
//! | Applied | yes | yes |
//! | Rejected (non-empty reason) | yes, terminal-as-decided | yes, terminal-as-decided |
//! | Unknown | no | no |
//! | GapRequiresRecovery | no (wrong phase) | yes |

use std::fmt::{Display, Formatter, Result as FmtResult};

/// Length of a lowercase or uppercase hex SHA-256 digest string.
const SHA256_HEX_LEN: usize = 64;

/// Ownership: Watchdog-owned cursor value; the sink never writes it.
/// Returns true for an opaque caller-supplied digest with exact SHA-256 hex
/// shape (non-empty, hex charset, length 64). Digests are never computed here.
fn is_sha256_hex_shape(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Ownership: the Watchdog owns the cursor; the sink never deletes source
/// records. A cursor names the Watchdog-owned acknowledged sequence plus the
/// owner identity the acknowledgement must echo back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolCursor {
    /// Contract revision. Must be nonzero.
    pub schema_version: u16,
    /// Highest consecutively acknowledged sequence. Zero means nothing
    /// acknowledged yet. Never stored with a high-water; callers pass the
    /// high-water to [`validate_cursor`] for the `<=` check.
    pub acknowledged_sequence: u64,
    /// Watchdog generation. Must be nonzero; zero means uninitialized.
    pub watchdog_generation: u64,
    /// Watchdog epoch. Zero denotes the explicit initial epoch and is
    /// allowed; a nonzero generation is still required.
    pub watchdog_epoch: u64,
    /// Owning installation. Must be non-empty.
    pub installation_id: String,
    /// Target sink this cursor reconciles with. Must be non-empty.
    pub sink_id: String,
}

/// Ownership: Watchdog-owned payload-class tag mirroring the spool codec
/// classes (Heartbeat, Gap, Recovery) without importing them.
/// Fail-closed: [`WatchdogSpoolSinkDisposition::advances_cursor`] treats
/// [`WatchdogSpoolPayloadKind::Gap`] and
/// [`WatchdogSpoolPayloadKind::Recovery`] entries as gap-like, so they cannot
/// be skipped by a later terminal disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogSpoolPayloadKind {
    /// Ordinary liveness/lease observation.
    Heartbeat,
    /// Pressure, wrap, or coverage-gap marker.
    Gap,
    /// Repair or recovery record.
    Recovery,
}

impl WatchdogSpoolPayloadKind {
    /// Ownership: pure classifier, no I/O. True for gap-like entries that
    /// require ordered gap resolution before the cursor may advance past them.
    fn is_gap_like(self) -> bool {
        matches!(self, Self::Gap | Self::Recovery)
    }
}

/// Ownership: one immutable spool record projection. Byte-stability identity
/// is (`sequence`, `record_digest`); a changed payload under the same sequence
/// is detectable via digest mismatch (see
/// [`WatchdogSpoolReconciliationError::PayloadMutated`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolExportEntry {
    /// Spool sequence number.
    pub sequence: u64,
    /// Contract revision; must equal the batch revision.
    pub schema_version: u16,
    /// Observation timestamp in milliseconds, mirroring the spool codec.
    pub observed_at_ms: u64,
    /// Payload class tag mirroring the spool codec classes.
    pub payload_kind: WatchdogSpoolPayloadKind,
    /// Opaque caller-supplied 64-hex digest of the payload bytes.
    pub payload_digest: String,
    /// Opaque caller-supplied 64-hex digest of the full record bytes.
    pub record_digest: String,
}

/// Ownership: immutable export view built by the Watchdog (spool owner) for
/// one sink. The sink never deletes source records; it only returns a
/// per-entry acknowledgement. The redundant owner identity
/// (`installation_id`, `watchdog_generation`, `watchdog_epoch`) must equal the
/// predecessor cursor fields; any divergence fails closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolExportBatch {
    /// Contract revision. Must be nonzero.
    pub schema_version: u16,
    /// Deterministic batch identity derived by the spool owner from
    /// (predecessor acknowledged sequence, first sequence, last sequence,
    /// batch digest). This core validates non-emptiness only and never
    /// computes it, preserving the zero-dependency core.
    pub batch_id: String,
    /// Owning installation. Must be non-empty and equal the predecessor.
    pub installation_id: String,
    /// Watchdog generation. Must be nonzero and equal the predecessor.
    pub watchdog_generation: u64,
    /// Watchdog epoch. Must equal the predecessor.
    pub watchdog_epoch: u64,
    /// Watchdog-owned cursor at export time; `acknowledged_sequence` is the
    /// predecessor every acknowledgement must echo.
    pub predecessor_cursor: WatchdogSpoolCursor,
    /// First covered sequence. Must equal predecessor acknowledged + 1.
    pub first_sequence: u64,
    /// Last covered sequence. Must not exceed the high-water.
    pub last_sequence: u64,
    /// Spool high-water at export time, for information only; the live
    /// high-water is always supplied by the caller.
    pub high_water_sequence: u64,
    /// Covered entries in strictly consecutive sequence order.
    pub entries: Vec<WatchdogSpoolExportEntry>,
    /// Must equal `entries.len()`.
    pub item_count: usize,
    /// Must be nonzero for a non-empty batch and zero for an empty batch.
    pub byte_size: u64,
    /// Opaque caller-supplied 64-hex digest of the canonical batch encoding.
    pub batch_digest: String,
    /// Explicit empty-batch flag for an empty spool. When true, `entries`
    /// must be empty and `first_sequence == last_sequence + 1 ==
    /// high_water_sequence + 1`.
    pub is_empty_batch: bool,
    /// Export timestamp in milliseconds. Must precede `expires_at_ms`.
    pub created_at_ms: u64,
    /// Acknowledgement deadline in milliseconds; see
    /// [`validate_batch_freshness`].
    pub expires_at_ms: u64,
}

/// Ownership: sink-owned per-entry outcome. The sink never deletes source
/// records; these values only advise the Watchdog-owned cursor decision.
/// Fail-closed: only [`WatchdogSpoolSinkDisposition::Applied`],
/// [`WatchdogSpoolSinkDisposition::Rejected`] (terminal-as-decided, advances
/// past a rejected entry exactly like an applied one), and
/// [`WatchdogSpoolSinkDisposition::GapRequiresRecovery`] on gap-like entries
/// advance the cursor. Received, Durable, `AdmittedCandidate`, and Unknown never
/// advance the cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogSpoolSinkDisposition {
    /// Sink received the entry; not durable, never advances the cursor.
    Received,
    /// Sink stored the entry without admitting it; never advances the cursor.
    Durable,
    /// Sink admitted the entry as a candidate; never advances the cursor.
    AdmittedCandidate,
    /// Sink applied the entry; advances the cursor for every payload kind.
    Applied,
    /// Sink refused the entry with a reason. Terminal-as-decided: advances
    /// past the entry exactly like an applied one. The reason must be
    /// non-empty.
    Rejected {
        /// Human- or machine-readable refusal reason. Must be non-empty.
        reason: String,
    },
    /// Sink outcome is unknown; never advances the cursor and fails
    /// acknowledgement validation (see
    /// [`WatchdogSpoolReconciliationError::UnknownOutcome`]).
    Unknown,
    /// Terminal gap-resolution phase for gap-like entries only; advances the
    /// cursor for Gap/Recovery entries and never for Heartbeat entries.
    GapRequiresRecovery,
}

impl WatchdogSpoolSinkDisposition {
    /// Ownership: pure sink-outcome classifier, no I/O. Returns true only for
    /// [`WatchdogSpoolSinkDisposition::Applied`] and
    /// [`WatchdogSpoolSinkDisposition::GapRequiresRecovery`] as the terminal
    /// gap-resolution phase. Received, Durable, `AdmittedCandidate`, and Unknown
    /// are never terminal for cursor advance; Rejected is terminal-as-decided
    /// (see [`WatchdogSpoolSinkDisposition::advances_cursor`]) rather than
    /// terminal for application.
    #[must_use]
    pub const fn terminal_for_application(&self) -> bool {
        matches!(self, Self::Applied | Self::GapRequiresRecovery)
    }

    /// Ownership: pure cursor-advance classifier, no I/O. Returns true for
    /// Applied (every kind), Rejected (every kind, terminal-as-decided), and
    /// `GapRequiresRecovery` on Gap/Recovery entries only. All other
    /// combinations return false; in particular `GapRequiresRecovery` on a
    /// Heartbeat entry is the wrong phase and never advances.
    #[must_use]
    pub fn advances_cursor(&self, kind: WatchdogSpoolPayloadKind) -> bool {
        match self {
            Self::Applied | Self::Rejected { .. } => true,
            Self::GapRequiresRecovery => kind.is_gap_like(),
            Self::Received | Self::Durable | Self::AdmittedCandidate | Self::Unknown => false,
        }
    }
}

/// Ownership: sink-owned per-entry acknowledgement line. Byte-stability
/// identity is (`sequence`, `record_digest`) and must match the batch entry
/// 1:1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolEntryDisposition {
    /// Acknowledged sequence; must match the batch entry exactly.
    pub sequence: u64,
    /// Sink outcome for this entry.
    pub disposition: WatchdogSpoolSinkDisposition,
    /// Echo of the batch entry `record_digest`; any mismatch fails closed.
    pub record_digest: String,
}

/// Ownership: sink-owned acknowledgement for exactly one batch. The Watchdog
/// (spool owner) decides cursor advance from this value; the sink never
/// deletes source records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolAcknowledgement {
    /// Contract revision. Must equal the batch revision.
    pub schema_version: u16,
    /// Echo of the batch identity.
    pub batch_id: String,
    /// Echo of the batch digest.
    pub batch_digest: String,
    /// Echo of the batch predecessor acknowledged sequence.
    pub predecessor_sequence: u64,
    /// Echo of the batch first sequence.
    pub first_sequence: u64,
    /// Echo of the batch last sequence.
    pub last_sequence: u64,
    /// Responding sink. Must equal the predecessor cursor sink.
    pub sink_id: String,
    /// Echo of the batch generation.
    pub watchdog_generation: u64,
    /// Echo of the batch epoch.
    pub watchdog_epoch: u64,
    /// Echo of the batch installation.
    pub installation_id: String,
    /// Exactly one line per batch entry, in order, covering
    /// `first_sequence..=last_sequence` consecutively.
    pub dispositions: Vec<WatchdogSpoolEntryDisposition>,
}

/// Ownership: fail-closed reconciliation failures. The Watchdog advances its
/// cursor only when no variant applies; the sink never deletes source records.
/// Variant meanings: `EmptyBatch` (empty flag inconsistent with entries, or
/// advance attempted over an empty batch); `NonConsecutiveSequences` (entries
/// not strictly +1 consecutive, including identical restatements);
/// `PredecessorMismatch` (sequence-level predecessor break, including schema
/// drift against the predecessor); `GenerationMismatch`, `EpochMismatch`,
/// `SinkMismatch`, `InstallationMismatch` (owner-identity divergence);
/// `BatchDigestMismatch` (batch id or digest echo differs);
/// `EntryDigestMismatch` (per-entry record digest differs);
/// `PayloadMutated` (same sequence restated with a different digest);
/// `UnknownOutcome` (sink reported Unknown);
/// `NonTerminalDisposition` (a disposition cannot advance its entry);
/// `GapSkipped` (a gap-like entry left non-terminal while a later entry
/// claims terminal); `AcknowledgementRangeMismatch` (range or coverage
/// differs); `ExpiredBatch` (owner clock reached the batch deadline);
/// `InvalidCursor` (cursor or caller high-water combination invalid);
/// `InvalidField` (field-shape violation naming the field).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogSpoolReconciliationError {
    /// Batch empty-flag inconsistent with entries, or advance over empty batch.
    EmptyBatch,
    /// Batch entries are not strictly consecutive.
    NonConsecutiveSequences,
    /// Batch or acknowledgement breaks the predecessor sequence chain.
    PredecessorMismatch,
    /// Watchdog generation diverges between compared values.
    GenerationMismatch,
    /// Watchdog epoch diverges between compared values.
    EpochMismatch,
    /// Sink identity diverges between compared values.
    SinkMismatch,
    /// Installation identity diverges between compared values.
    InstallationMismatch,
    /// Batch id or batch digest echo diverges from the batch.
    BatchDigestMismatch,
    /// Per-entry record digest diverges from the batch entry.
    EntryDigestMismatch,
    /// Same sequence restated with a different record digest.
    PayloadMutated,
    /// Sink reported an unknown outcome for an entry.
    UnknownOutcome,
    /// A disposition cannot advance its entry.
    NonTerminalDisposition,
    /// A gap-like entry was skipped by a later terminal disposition.
    GapSkipped,
    /// Acknowledgement range or coverage diverges from the batch.
    AcknowledgementRangeMismatch,
    /// Batch acknowledgement deadline reached on the owner clock.
    ExpiredBatch,
    /// Cursor or caller high-water combination is invalid.
    InvalidCursor,
    /// Field-shape violation; the payload names the offending field.
    InvalidField(&'static str),
}

impl Display for WatchdogSpoolReconciliationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::EmptyBatch => {
                formatter.write_str("watchdog spool batch is empty; no sequence advances")
            }
            Self::NonConsecutiveSequences => {
                formatter.write_str("watchdog spool batch entries are not strictly consecutive")
            }
            Self::PredecessorMismatch => formatter.write_str(
                "watchdog spool batch does not continue the predecessor cursor sequence",
            ),
            Self::GenerationMismatch => {
                formatter.write_str("watchdog generation does not match the expected value")
            }
            Self::EpochMismatch => {
                formatter.write_str("watchdog epoch does not match the expected value")
            }
            Self::SinkMismatch => {
                formatter.write_str("sink identity does not match the expected value")
            }
            Self::InstallationMismatch => {
                formatter.write_str("installation identity does not match the expected value")
            }
            Self::BatchDigestMismatch => {
                formatter.write_str("watchdog spool batch identity digest does not match")
            }
            Self::EntryDigestMismatch => {
                formatter.write_str("watchdog spool entry record digest does not match")
            }
            Self::PayloadMutated => formatter
                .write_str("watchdog spool sequence restated with a different record digest"),
            Self::UnknownOutcome => {
                formatter.write_str("sink reported an unknown outcome for an entry")
            }
            Self::NonTerminalDisposition => {
                formatter.write_str("sink disposition is not terminal for cursor advance")
            }
            Self::GapSkipped => formatter
                .write_str("gap entry left non-terminal while a later entry claims terminal"),
            Self::AcknowledgementRangeMismatch => {
                formatter.write_str("acknowledgement range does not match the batch range exactly")
            }
            Self::ExpiredBatch => {
                formatter.write_str("watchdog spool batch acknowledgement window expired")
            }
            Self::InvalidCursor => {
                formatter.write_str("watchdog spool cursor and high-water combination invalid")
            }
            Self::InvalidField(field) => {
                write!(
                    formatter,
                    "invalid watchdog spool reconciliation field: {field}"
                )
            }
        }
    }
}

impl std::error::Error for WatchdogSpoolReconciliationError {}

/// Ownership: validates Watchdog-owned cursor fields only; stores nothing.
/// Fail-closed: nonzero schema, nonzero generation, non-empty installation
/// and sink ids.
fn validate_cursor_fields(
    cursor: &WatchdogSpoolCursor,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::InvalidField;
    if cursor.schema_version == 0 {
        return Err(InvalidField("schema_version"));
    }
    if cursor.watchdog_generation == 0 {
        return Err(InvalidField("watchdog_generation"));
    }
    if cursor.installation_id.is_empty() {
        return Err(InvalidField("installation_id"));
    }
    if cursor.sink_id.is_empty() {
        return Err(InvalidField("sink_id"));
    }
    Ok(())
}

/// Ownership: the Watchdog owns the cursor; the sink never deletes source
/// records. Validates cursor shape plus `acknowledged_sequence <= high_water`
/// against the caller-provided high-water, which is never stored.
/// Fail-closed: any shape violation yields `InvalidField`; an acknowledged
/// sequence beyond the high-water yields `InvalidCursor`.
pub fn validate_cursor(
    cursor: &WatchdogSpoolCursor,
    high_water: u64,
) -> Result<(), WatchdogSpoolReconciliationError> {
    validate_cursor_fields(cursor)?;
    if cursor.acknowledged_sequence > high_water {
        return Err(WatchdogSpoolReconciliationError::InvalidCursor);
    }
    Ok(())
}

/// Ownership: validates the batch envelope (scalar shapes, predecessor owner
/// identity, high-water relations, creation ordering). The sink never deletes
/// source records.
/// Fail-closed: shape violations yield `InvalidField`; predecessor identity
/// divergence yields the specific mismatch variant; a caller high-water older
/// than the embedded or predecessor values yields `InvalidCursor`.
fn validate_batch_envelope(
    batch: &WatchdogSpoolExportBatch,
    high_water: u64,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::{
        EpochMismatch, GenerationMismatch, InstallationMismatch, InvalidCursor, InvalidField,
        PredecessorMismatch,
    };
    if batch.schema_version == 0 {
        return Err(InvalidField("schema_version"));
    }
    if batch.batch_id.is_empty() {
        return Err(InvalidField("batch_id"));
    }
    if batch.installation_id.is_empty() {
        return Err(InvalidField("installation_id"));
    }
    if batch.watchdog_generation == 0 {
        return Err(InvalidField("watchdog_generation"));
    }
    if !is_sha256_hex_shape(&batch.batch_digest) {
        return Err(InvalidField("batch_digest"));
    }
    if batch.created_at_ms >= batch.expires_at_ms {
        return Err(InvalidField("expires_at_ms"));
    }
    validate_cursor_fields(&batch.predecessor_cursor)?;
    if batch.predecessor_cursor.schema_version != batch.schema_version {
        return Err(PredecessorMismatch);
    }
    if batch.predecessor_cursor.installation_id != batch.installation_id {
        return Err(InstallationMismatch);
    }
    if batch.predecessor_cursor.watchdog_generation != batch.watchdog_generation {
        return Err(GenerationMismatch);
    }
    if batch.predecessor_cursor.watchdog_epoch != batch.watchdog_epoch {
        return Err(EpochMismatch);
    }
    if batch.high_water_sequence > high_water {
        return Err(InvalidCursor);
    }
    if batch.predecessor_cursor.acknowledged_sequence > high_water {
        return Err(InvalidCursor);
    }
    Ok(())
}

/// Ownership: validates the explicit empty-batch shape for an empty spool.
/// Fail-closed: any carried entry, count, size, or sequence deviation yields
/// `EmptyBatch`, `InvalidField`, or `PredecessorMismatch`; sequence exhaustion
/// (`u64::MAX` high-water) fails closed because `first == high_water + 1` is
/// inexpressible.
fn validate_empty_batch(
    batch: &WatchdogSpoolExportBatch,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::{EmptyBatch, InvalidField, PredecessorMismatch};
    if !batch.entries.is_empty() {
        return Err(EmptyBatch);
    }
    if batch.item_count != 0 {
        return Err(InvalidField("item_count"));
    }
    if batch.byte_size != 0 {
        return Err(InvalidField("byte_size"));
    }
    if batch.predecessor_cursor.acknowledged_sequence != batch.high_water_sequence {
        return Err(PredecessorMismatch);
    }
    let expected_first = batch
        .high_water_sequence
        .checked_add(1)
        .ok_or(PredecessorMismatch)?;
    if batch.first_sequence != expected_first {
        return Err(PredecessorMismatch);
    }
    if batch.last_sequence != batch.high_water_sequence {
        return Err(PredecessorMismatch);
    }
    Ok(())
}

/// Ownership: validates a non-empty batch body (counts, sizes, per-entry
/// shapes, declared range, strict consecutiveness, predecessor chain).
/// Fail-closed: empty entries yield `EmptyBatch`; count/size/endpoint breaks
/// yield `InvalidField`; chain breaks yield `PredecessorMismatch`; inter-entry
/// breaks yield `NonConsecutiveSequences`, except an adjacent restatement of
/// the same sequence with a different digest, which yields `PayloadMutated`.
fn validate_batch_entries(
    batch: &WatchdogSpoolExportBatch,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::{
        EmptyBatch, InvalidField, NonConsecutiveSequences, PayloadMutated, PredecessorMismatch,
    };
    if batch.entries.is_empty() {
        return Err(EmptyBatch);
    }
    if batch.item_count != batch.entries.len() {
        return Err(InvalidField("item_count"));
    }
    if batch.byte_size == 0 {
        return Err(InvalidField("byte_size"));
    }
    if batch.first_sequence > batch.last_sequence {
        return Err(InvalidField("first_sequence"));
    }
    let expected_first = batch
        .predecessor_cursor
        .acknowledged_sequence
        .checked_add(1)
        .ok_or(PredecessorMismatch)?;
    if batch.first_sequence != expected_first {
        return Err(PredecessorMismatch);
    }
    if batch.last_sequence > batch.high_water_sequence {
        return Err(InvalidField("last_sequence"));
    }
    let mut expected = batch.first_sequence;
    let mut previous_sequence: Option<u64> = None;
    let mut previous_digest: &str = "";
    for entry in &batch.entries {
        if entry.schema_version != batch.schema_version {
            return Err(InvalidField("schema_version"));
        }
        if !is_sha256_hex_shape(&entry.payload_digest) {
            return Err(InvalidField("payload_digest"));
        }
        if !is_sha256_hex_shape(&entry.record_digest) {
            return Err(InvalidField("record_digest"));
        }
        if entry.sequence != expected {
            if previous_sequence == Some(entry.sequence) && entry.record_digest != previous_digest {
                return Err(PayloadMutated);
            }
            return Err(NonConsecutiveSequences);
        }
        previous_sequence = Some(entry.sequence);
        previous_digest = entry.record_digest.as_str();
        expected = expected.checked_add(1).ok_or(NonConsecutiveSequences)?;
    }
    let after_last = batch
        .last_sequence
        .checked_add(1)
        .ok_or(InvalidField("last_sequence"))?;
    if expected != after_last {
        return Err(InvalidField("last_sequence"));
    }
    Ok(())
}

/// Ownership: the Watchdog owns the cursor and records; the sink never
/// deletes source records. Validates all structural, digest-shape, and range
/// rules for one immutable batch against the caller-provided live high-water.
/// Fail-closed: see [`validate_batch_envelope`], [`validate_empty_batch`],
/// and [`validate_batch_entries`]. Time-dependent expiry is not evaluated
/// here; the owner supplies its clock to [`validate_batch_freshness`].
pub fn validate_batch(
    batch: &WatchdogSpoolExportBatch,
    high_water: u64,
) -> Result<(), WatchdogSpoolReconciliationError> {
    validate_batch_envelope(batch, high_water)?;
    if batch.is_empty_batch {
        validate_empty_batch(batch)?;
    } else {
        validate_batch_entries(batch)?;
    }
    Ok(())
}

/// Ownership: pure freshness check; the owner supplies its clock and the sink
/// never deletes source records.
/// Fail-closed: returns [`WatchdogSpoolReconciliationError::ExpiredBatch`]
/// when `now_ms` has reached the batch deadline.
pub fn validate_batch_freshness(
    batch: &WatchdogSpoolExportBatch,
    now_ms: u64,
) -> Result<(), WatchdogSpoolReconciliationError> {
    if now_ms >= batch.expires_at_ms {
        return Err(WatchdogSpoolReconciliationError::ExpiredBatch);
    }
    Ok(())
}

/// Ownership: validates acknowledgement identity echoes against the batch.
/// Fail-closed: scalar echo breaks yield the specific mismatch variant
/// (`BatchDigestMismatch`, `PredecessorMismatch`,
/// `AcknowledgementRangeMismatch`, `SinkMismatch`, `GenerationMismatch`,
/// `EpochMismatch`, `InstallationMismatch`); schema drift yields
/// `InvalidField`.
fn validate_ack_identity(
    batch: &WatchdogSpoolExportBatch,
    ack: &WatchdogSpoolAcknowledgement,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::{
        AcknowledgementRangeMismatch, BatchDigestMismatch, EpochMismatch, GenerationMismatch,
        InstallationMismatch, InvalidField, PredecessorMismatch, SinkMismatch,
    };
    if ack.schema_version != batch.schema_version {
        return Err(InvalidField("schema_version"));
    }
    if ack.batch_id != batch.batch_id || ack.batch_digest != batch.batch_digest {
        return Err(BatchDigestMismatch);
    }
    if ack.predecessor_sequence != batch.predecessor_cursor.acknowledged_sequence {
        return Err(PredecessorMismatch);
    }
    if ack.first_sequence != batch.first_sequence || ack.last_sequence != batch.last_sequence {
        return Err(AcknowledgementRangeMismatch);
    }
    if ack.sink_id != batch.predecessor_cursor.sink_id {
        return Err(SinkMismatch);
    }
    if ack.watchdog_generation != batch.watchdog_generation {
        return Err(GenerationMismatch);
    }
    if ack.watchdog_epoch != batch.watchdog_epoch {
        return Err(EpochMismatch);
    }
    if ack.installation_id != batch.installation_id {
        return Err(InstallationMismatch);
    }
    Ok(())
}

/// Ownership: validates that dispositions cover exactly
/// `first_sequence..=last_sequence` consecutively with 1:1 sequence identity.
/// Fail-closed: any length or sequence deviation yields
/// `AcknowledgementRangeMismatch`, including a non-empty disposition list for
/// an empty batch.
fn validate_ack_coverage(
    batch: &WatchdogSpoolExportBatch,
    ack: &WatchdogSpoolAcknowledgement,
) -> Result<(), WatchdogSpoolReconciliationError> {
    if ack.dispositions.len() != batch.entries.len() {
        return Err(WatchdogSpoolReconciliationError::AcknowledgementRangeMismatch);
    }
    for (entry, line) in batch.entries.iter().zip(ack.dispositions.iter()) {
        if line.sequence != entry.sequence {
            return Err(WatchdogSpoolReconciliationError::AcknowledgementRangeMismatch);
        }
    }
    Ok(())
}

/// Ownership: validates per-entry digest equality and outcome usability after
/// identity and coverage hold. Tampering is reported before outcomes.
/// Fail-closed: digest divergence yields `EntryDigestMismatch`; an Unknown
/// disposition yields `UnknownOutcome`; a Rejected line without a reason
/// yields `InvalidField`.
fn validate_ack_outcomes(
    batch: &WatchdogSpoolExportBatch,
    ack: &WatchdogSpoolAcknowledgement,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::{EntryDigestMismatch, InvalidField, UnknownOutcome};
    for (entry, line) in batch.entries.iter().zip(ack.dispositions.iter()) {
        if line.record_digest != entry.record_digest {
            return Err(EntryDigestMismatch);
        }
        if line.disposition == WatchdogSpoolSinkDisposition::Unknown {
            return Err(UnknownOutcome);
        }
        if matches!(
            &line.disposition,
            WatchdogSpoolSinkDisposition::Rejected { reason } if reason.is_empty()
        ) {
            return Err(InvalidField("reason"));
        }
    }
    Ok(())
}

/// Ownership: the Watchdog owns the cursor; the sink never deletes source
/// records. Validates identity match plus per-entry coverage plus digest
/// equality for one acknowledgement against its batch.
/// Fail-closed: identity breaks yield the specific mismatch variants (see
/// [`validate_batch`]); coverage breaks yield `AcknowledgementRangeMismatch`;
/// digest breaks yield `EntryDigestMismatch`; an Unknown disposition yields
/// `UnknownOutcome` because an unknown outcome confirms nothing; a reasonless
/// Rejected line yields `InvalidField`.
pub fn validate_acknowledgement(
    batch: &WatchdogSpoolExportBatch,
    ack: &WatchdogSpoolAcknowledgement,
) -> Result<(), WatchdogSpoolReconciliationError> {
    validate_ack_identity(batch, ack)?;
    validate_ack_coverage(batch, ack)?;
    validate_ack_outcomes(batch, ack)?;
    Ok(())
}

/// Ownership: evaluates the disposition terminal table over 1:1 covered
/// entries; the sink never deletes source records. Callers must establish
/// coverage first (see [`validate_ack_coverage`]).
/// Fail-closed: returns `NonTerminalDisposition` when any entry cannot
/// advance (Received, Durable, `AdmittedCandidate`, Unknown, or
/// `GapRequiresRecovery` on a Heartbeat entry); returns `GapSkipped` when a
/// gap-like entry is left non-terminal while a later entry claims terminal,
/// because the cursor advances contiguously and gaps resolve in order.
fn check_advance_table(
    batch: &WatchdogSpoolExportBatch,
    ack: &WatchdogSpoolAcknowledgement,
) -> Result<(), WatchdogSpoolReconciliationError> {
    use WatchdogSpoolReconciliationError::{GapSkipped, NonTerminalDisposition};
    let mut blocked_gap = false;
    let mut blocked_any = false;
    for (entry, line) in batch.entries.iter().zip(ack.dispositions.iter()) {
        if line.disposition.advances_cursor(entry.payload_kind) {
            if blocked_gap {
                return Err(GapSkipped);
            }
        } else {
            blocked_any = true;
            if entry.payload_kind.is_gap_like() {
                blocked_gap = true;
            }
        }
    }
    if blocked_any {
        return Err(NonTerminalDisposition);
    }
    Ok(())
}

/// Ownership: pure Watchdog-side cursor decision; the sink never deletes
/// source records. Fails closed on any mismatch and returns the new
/// acknowledged sequence on success.
/// Fail-closed order: empty batches yield `EmptyBatch` (nothing advances);
/// the batch is revalidated against its embedded high-water (the owner must
/// separately run [`validate_batch`] with the live high-water and
/// [`validate_batch_freshness`] with its clock); identity and coverage are
/// revalidated; then the terminal table decides: any Received, Durable,
/// `AdmittedCandidate`, or Unknown disposition yields `NonTerminalDisposition`,
/// a skipped gap-like entry yields `GapSkipped`, and otherwise the
/// acknowledgement advances exactly once to `batch.last_sequence`.
/// Idempotency: re-applying the same acknowledgement is decided by the spool
/// owner comparing against its stored cursor (see [`is_duplicate_ack`]), not
/// by this function.
/// Terminal table: Applied advances every kind; Rejected advances every kind
/// as terminal-as-decided; `GapRequiresRecovery` advances Gap/Recovery entries
/// only; all other combinations never advance.
pub fn acknowledgement_advances_cursor(
    batch: &WatchdogSpoolExportBatch,
    ack: &WatchdogSpoolAcknowledgement,
) -> Result<u64, WatchdogSpoolReconciliationError> {
    if batch.is_empty_batch {
        return Err(WatchdogSpoolReconciliationError::EmptyBatch);
    }
    validate_batch(batch, batch.high_water_sequence)?;
    validate_ack_identity(batch, ack)?;
    validate_ack_coverage(batch, ack)?;
    check_advance_table(batch, ack)?;
    validate_ack_outcomes(batch, ack)?;
    Ok(batch.last_sequence)
}

/// Ownership: pure byte-stability comparator for export retries; neither side
/// mutates source records. Returns true only when batch id, batch digest, and
/// every entry digest (sequence, payload digest, record digest) match in
/// order. A false result means the retry restated the batch with different
/// bytes and must not be confused with the original.
#[must_use]
pub fn export_retry_identity_equal(
    first: &WatchdogSpoolExportBatch,
    second: &WatchdogSpoolExportBatch,
) -> bool {
    first.batch_id == second.batch_id
        && first.batch_digest == second.batch_digest
        && first.entries.len() == second.entries.len()
        && first
            .entries
            .iter()
            .zip(second.entries.iter())
            .all(|(left, right)| {
                left.sequence == right.sequence
                    && left.payload_digest == right.payload_digest
                    && left.record_digest == right.record_digest
            })
}

/// Ownership: duplicate detection belongs to the spool owner, which compares
/// the acknowledgement predecessor against its stored Watchdog-owned cursor.
/// Returns true when `ack.predecessor_sequence` is strictly below the stored
/// acknowledged sequence (a duplicate, not an error: the owner ignores it).
/// A predecessor equal to the stored value is the next acknowledgement to
/// apply; a greater predecessor is a future acknowledgement the owner must
/// hold until the missing range arrives.
#[must_use]
pub fn is_duplicate_ack(stored_acknowledged: u64, ack: &WatchdogSpoolAcknowledgement) -> bool {
    ack.predecessor_sequence < stored_acknowledged
}
