//! Bounded isolated backup snapshot and restore helpers for the watchdog spool.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-02.
//! Issue #955 lane: this child owns the immutable [`WatchdogSpoolFence`]
//! snapshot handle, bounded [`WatchdogSpoolSnapshotPage`] reads, and the
//! isolated-restore validation helpers. It performs no I/O, opens no database,
//! copies no live `watchdog.redb` file, holds no global state, mints no lease,
//! heartbeat, supervision authority, epoch, or cutover, and starts no process.
//! All functions operate on already-opened data so the owner methods in the
//! parent (`watchdog_spool.rs`) can call them inside one bounded coherent
//! read transaction.
//!
//! #954 contract correspondence (`eliot-protocol::backup`, accepted on main):
//!
//! This file deliberately takes no `eliot-protocol` dependency
//! (`eliot-protocol` is not in `bins/eliot-watchdog/Cargo.toml`; the spool and
//! composition writers wire the real contract once the manager adds it).
//! Every cross-boundary value is therefore carried as validated local fields
//! (non-blank bounded strings, lowercase SHA-256 digests, explicit bounds)
//! with the same shape rules as the #954 types, documented per item:
//!
//! - [`SpoolCoverageDenominator`] mirrors `Denominator`, including
//!   [`SpoolCoverageDenominator::validate_for_count`] mirroring
//!   `Denominator::validate_for_count` (zero requires complete; complete
//!   requires exact equality).
//! - [`WatchdogSpoolSnapshotPage`] mirrors `BackupSnapshotPageRead` paging:
//!   `member_count <= max_page_members`, continuation bound to one snapshot
//!   digest, cumulative counters.
//! - [`validate_isolated_destination`] mirrors
//!   `BackupIsolatedRestorePrepare` (`destination_installation` must equal the
//!   admitted destination and differ from the source).
//! - [`SpoolRestoreStep`] and [`validate_restore_chain`] mirror
//!   `BackupRestoreStep` (`step_digest` / `predecessor_digest` linkage, stable
//!   operation identity).
//! - [`reconcile_restore`] mirrors `BackupRestoreReconcile` (content-free
//!   retained-digest query; unknown stays visible).
//! - [`SpoolImportReplayLedger`] mirrors `BackupReplayLedger::observe`
//!   (byte-identical digest observes `Duplicate`; changed content under the
//!   same identity is a `ReplayConflict`).
//! - Owner attestations for `RestoreStepApplied` / `Reconciled` remain the
//!   composition writer's `BackupPhaseAttestation` with owner role
//!   `SpoolOwner`; this file only produces the evidenced digests and
//!   dispositions they bind.
//!
//! Error mapping: only [`SpoolError`] is used. [`SpoolError`] has no
//! `Incomplete` variant, so incomplete evidence (missing, expired, or
//! zero-on-incomplete members) maps to [`SpoolError::Corrupt`] with an exact
//! reason, never to a silent empty handle. No transport, SCM, restart,
//! cutover, or authority logic exists here by construction.
//!
//! Fence integrity: the evidence a fence carries — its ordered redacted
//! entries and its coverage denominator — is mutable only inside this module.
//! Both are handed out as shared slices/references, and
//! [`WatchdogSpoolFence::validate`] re-derives every counter, window, and
//! digest from the entries the fence actually holds. Both page-read paths call
//! it before serving, and each page's snapshot digest is derived from the
//! entries that read served. A holder can therefore neither fabricate page
//! members nor assert full coverage over a spool with gaps after capture, and a
//! changed member is corrupt — never known-empty and never complete.

use std::collections::BTreeMap;

use eliot_contracts::sha256_hex;

use crate::{GapRecoveryReason, SpoolError};

use super::codec::{
    WatchdogSpoolEntry, WatchdogSpoolHeader, WatchdogSpoolPayload, encode_entry, encode_high_water,
    validate_header, validate_high_water,
};
use super::intent::check_stored_intent_payload;
use super::{
    EXPORT_BATCH_TTL_MS, EXPORT_MAX_BYTES, EXPORT_MAX_ITEMS, SPOOL_MAX_BYTES,
    SPOOL_MAX_RECORD_BYTES, SPOOL_MAX_RECORDS, SPOOL_SCHEMA_VERSION,
};

/// Schema version of the fence shape itself.
///
/// Today this intentionally equals [`SPOOL_SCHEMA_VERSION`]: the fence only
/// ever covers spool schema 1 records, and a future spool revision refuses to
/// mix fence generations instead of reinterpreting them.
pub const SPOOL_FENCE_SCHEMA_VERSION: u16 = 1;

/// Maximum bytes for one installation, principal, or service identity text.
///
/// Mirrors the cursor identity frame (`1024`) so fence identities never exceed
/// the frames they reconcile against.
pub const BACKUP_IDENTITY_MAX_BYTES: usize = 1024;

/// Maximum bytes for one preserved recovery reason text.
///
/// Mirrors the #954 `MAX_BACKUP_TEXT_BYTES` bound (`8 KiB`).
pub const BACKUP_REASON_MAX_BYTES: usize = 8 * 1024;

/// Minimum page byte bound: one maximum-size spool record always fits.
///
/// Mirrors `SPOOL_MAX_RECORD_BYTES` (`64 KiB`) so the first covered record
/// always fits and paging always makes progress.
pub const BACKUP_MIN_PAGE_BYTES: u64 = 64 * 1024;

/// Ceiling for members carried by one snapshot page.
///
/// Mirrors `EXPORT_MAX_ITEMS` (`256`); a page is never wider than one export
/// batch.
pub const BACKUP_PAGE_MEMBERS_CEILING: u32 = 256;

/// Whole-snapshot handle lifetime ceiling, in milliseconds.
///
/// Mirrors the export freshness window (`EXPORT_BATCH_TTL_MS`): a fence older
/// than one window is no longer current and must be recaptured.
pub const BACKUP_SNAPSHOT_LIFETIME_MS: u64 = EXPORT_BATCH_TTL_MS;

/// Work ceiling in record units: at most one work unit per retained record.
///
/// Mirrors `SPOOL_MAX_RECORDS` so bounded work can never exceed the retention
/// ceiling.
pub const BACKUP_MAX_WORK_UNITS: u64 = SPOOL_MAX_RECORDS;

/// Length of one lowercase SHA-256 hex digest.
const SHA256_HEX_LEN: usize = 64;

/// Literal preserved by the spool owner when no corrupt sequence digest exists.
///
/// `WatchdogSpool::recover` writes `"missing"` when the corrupt row itself is
/// unreadable; the fence preserves that literal verbatim instead of inventing
/// a digest.
const MISSING_DIGEST_LITERAL: &str = "missing";

/// True for an opaque lowercase SHA-256 hex digest.
///
/// Mirrors the #954 `lowercase_sha256` shape rule: exactly 64 characters,
/// hex digits only, no uppercase.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Builds the corrupt disposition every fence integrity check returns.
fn fence_corrupt(message: &str) -> SpoolError {
    SpoolError::Corrupt(message.to_owned())
}

/// Rejects a blank, control-carrying, or oversized identity or reason text.
///
/// Mirrors the #954 `bounded_text` shape rule.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when `value` is blank, carries control
/// characters, or exceeds `max_bytes`.
fn check_text(value: &str, field: &str, max_bytes: usize) -> Result<(), SpoolError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup {field} is blank or carries control characters"
        )));
    }
    if value.len() > max_bytes {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup {field} exceeds the bounded frame"
        )));
    }
    Ok(())
}

/// Rejects a malformed lowercase SHA-256 digest.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when `value` is not exactly 64 lowercase
/// hex characters.
fn check_digest(value: &str, field: &str) -> Result<(), SpoolError> {
    if !is_lowercase_sha256(value) {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup {field} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

/// Redacted payload class of one fenced spool record.
///
/// Mirrors `WatchdogSpoolPayloadKind` (`Heartbeat`, `Gap`, `Recovery`; intents
/// project to the `Recovery` class at export) with the spool-local intent
/// variants kept distinct so the denominator can mark them incomplete. The
/// class carries no payload bytes by construction.
///
/// The derived encoding is the fence's own digest representation (see the
/// `derive_content_digest` docs), not a wire format: nothing decodes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub enum SpoolFenceEntryKind {
    /// Ordinary liveness or lease observation; payload bytes redacted.
    Heartbeat,
    /// Pressure, wrap, or coverage-gap marker; preserved verbatim below.
    Gap,
    /// Repair or recovery record; preserved verbatim below.
    Recovery,
    /// Spool-local problem intent awaiting Governor reconciliation.
    ProblemIntent,
    /// Spool-local incident intent awaiting Governor reconciliation.
    IncidentIntent,
}

impl SpoolFenceEntryKind {
    /// Returns the stable wire name of this entry kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Heartbeat => "heartbeat",
            Self::Gap => "gap",
            Self::Recovery => "recovery",
            Self::ProblemIntent => "problem_intent",
            Self::IncidentIntent => "incident_intent",
        }
    }

    /// Classifies one spool payload without copying any payload bytes.
    ///
    /// The match is exhaustive with no wildcard: a future payload variant
    /// fails the build here instead of silently misclassifying.
    fn classify(payload: &WatchdogSpoolPayload) -> Self {
        match payload {
            WatchdogSpoolPayload::Heartbeat { .. } => Self::Heartbeat,
            WatchdogSpoolPayload::Gap { .. } => Self::Gap,
            WatchdogSpoolPayload::Recovery { .. } => Self::Recovery,
            WatchdogSpoolPayload::ProblemIntent { .. } => Self::ProblemIntent,
            WatchdogSpoolPayload::IncidentIntent { .. } => Self::IncidentIntent,
        }
    }

    /// True for records that invalidate complete historical coverage.
    ///
    /// Any `Gap`, `Recovery`, or unreconciled intent in scope marks the fence
    /// denominator incomplete; such records are never dropped and no pre-gap
    /// entry is fabricated.
    #[must_use]
    pub const fn marks_incomplete(self) -> bool {
        match self {
            Self::Heartbeat => false,
            Self::Gap | Self::Recovery | Self::ProblemIntent | Self::IncidentIntent => true,
        }
    }
}

/// Verbatim marker detail preserved for coverage-invalidating records.
///
/// `Gap`, `Recovery`, and intent records stay visible in the fence with their
/// exact reason and digest material. Heartbeat payload bytes (lease ids,
/// scopes, signatures, digests) are never carried here: heartbeats keep only
/// their sequence, timestamp, kind, and entry digest. No service config,
/// credentials, commands, or user payloads exist in this enum by construction.
///
/// The derived encoding is the fence's own digest representation (see the
/// `derive_content_digest` docs), not a wire format: nothing decodes it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub enum SpoolMarkerDetail {
    /// Gap marker with its exact reason and coverage flag.
    Gap {
        /// Bounded gap reason carried by the retained record.
        reason: GapRecoveryReason,
        /// Coverage flag carried by the retained record, always false.
        coverage_claimed: bool,
    },
    /// Recovery record with its exact reason and corrupt-sequence evidence.
    Recovery {
        /// Bounded recovery reason carried by the retained record.
        reason: String,
        /// Retained corrupt sequence, when the recovery names one.
        corrupt_sequence: Option<u64>,
        /// Retained corrupt digest, or `"missing"` when unreadable.
        corrupt_digest: String,
    },
    /// Spool-local intent with its evidence digests, owner lineage, and the
    /// exact observed Governor-unavailability reason.
    ///
    /// Evidence refs are 64-hex digests and the lineage repeats only the
    /// owner identities the export cursor already binds; no authority,
    /// lease, or epoch material is carried. `governor_unavailable_reason` is
    /// the retained proof ceiling of the intent: the exact observed
    /// admission/lease failure that opened the episode. Dropping it would
    /// present an unreconciled intent as a bare escalation with no stated
    /// cause, so it travels verbatim with the marker.
    Intent {
        /// Bounded evidence digest refs carried by the retained record.
        evidence_refs: Vec<String>,
        /// Owner installation carried by the retained record.
        lineage_installation_id: String,
        /// Owner generation carried by the retained record.
        lineage_generation: u64,
        /// Owner epoch carried by the retained record.
        lineage_epoch: u64,
        /// Exact observed Governor-unavailability reason that opened the
        /// episode, preserved verbatim from the retained record.
        governor_unavailable_reason: GapRecoveryReason,
    },
}

/// Redacted view of one retained spool record.
///
/// Carries the entry identity (sequence, timestamp, kind, canonical entry
/// digest, encoded byte length) and, for coverage-invalidating markers, the
/// verbatim [`SpoolMarkerDetail`]. Raw service config, credentials, commands,
/// signatures, and user payload bytes are never stored here.
///
/// The derived encoding is the fence's own digest representation (see the
/// `derive_content_digest` docs), not a wire format: nothing decodes it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RedactedSpoolEntry {
    /// Spool sequence number.
    pub sequence: u64,
    /// Observation timestamp in milliseconds, mirroring the spool codec.
    pub observed_at_ms: u64,
    /// Redacted payload class.
    pub kind: SpoolFenceEntryKind,
    /// Lowercase SHA-256 over the canonical entry bytes.
    pub entry_digest: String,
    /// Canonical encoded byte length of the entry; a count, not content.
    pub entry_bytes: u64,
    /// Verbatim marker detail for coverage-invalidating records, else `None`.
    pub marker: Option<SpoolMarkerDetail>,
}

/// Explicit coverage denominator for one snapshot.
///
/// Mirrors the #954 `Denominator`: `retained_members` is the exact retained
/// member count, `gap_members` is the visible subset of `Gap`, `Recovery`,
/// and intent markers, and `complete` is false whenever any marker is in
/// scope. Absence of a closure record means unknown, never complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolCoverageDenominator {
    /// Exact retained member count.
    pub retained_members: u64,
    /// Visible marker subset invalidating complete coverage.
    pub gap_members: u64,
    /// True only when no marker is in scope.
    pub complete: bool,
}

impl SpoolCoverageDenominator {
    /// Returns the denominator total bounding observed counts.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.retained_members
    }

    /// Validates an observed count against this denominator.
    ///
    /// Mirrors `Denominator::validate_for_count` exactly: a zero observed
    /// count validates only when the denominator is complete; a complete
    /// denominator must equal the observed count exactly; the observed count
    /// can never exceed the denominator total. Unknown reconciliation
    /// therefore stays visible and blocks recovery acceptance instead of
    /// returning zero by default.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the observed count exceeds the
    /// total, is zero on an incomplete denominator, or differs from a
    /// complete denominator.
    pub fn validate_for_count(self, observed: u64) -> Result<(), SpoolError> {
        if observed > self.retained_members {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup denominator: observed count cannot exceed the denominator total"
                    .to_owned(),
            ));
        }
        if observed == 0 && !self.complete {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup denominator: a zero count requires a complete denominator"
                    .to_owned(),
            ));
        }
        if self.complete && observed != self.retained_members {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup denominator: a complete denominator must equal the observed count"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Immutable bounded snapshot handle for one coherent spool capture.
///
/// Binds the validated header, high-water sequence and digest, ordered
/// redacted entry views, exact coverage denominator, source installation,
/// watchdog generation, admitted requester, stable snapshot operation
/// identity, fence schema, optional canonical/ORS capture references, and the
/// content digest. A vector of records without header, high-water, and
/// coverage evidence is not a fence: [`capture_fence`] refuses to build one.
///
/// The handle carries digests and receipts only. Raw service config,
/// credentials, commands, signatures, and user payload bytes stay redacted:
/// heartbeats keep kind plus entry digest, and only `Gap`, `Recovery`, and
/// intent markers keep their verbatim reason and digest material.
///
/// The evidence it carries — the ordered entries and the coverage denominator
/// — is immutable outside this module: both are reachable only through
/// [`entries`](Self::entries) and [`denominator`](Self::denominator), which
/// hand out shared slices, so a holder cannot splice members into the page body
/// or flip `complete` after the fact. [`validate`](Self::validate) re-derives
/// every counter, digest, and window from the entries the fence actually holds
/// and runs at the top of both page-read paths.
#[derive(Clone, Debug)]
pub struct WatchdogSpoolFence {
    /// Validated spool header (schema and counters only, no payloads).
    pub(crate) header: WatchdogSpoolHeader,
    /// Durable high-water sequence bound by the capture.
    pub high_water: u64,
    /// Lowercase SHA-256 over the canonical high-water bytes.
    pub high_water_digest: String,
    /// Ordered redacted retained entries, sequence-consecutive.
    entries: Vec<RedactedSpoolEntry>,
    /// Exact retained member and marker denominator.
    denominator: SpoolCoverageDenominator,
    /// Source installation the capture was taken from.
    pub source_installation: String,
    /// Watchdog generation bound at sensor construction.
    pub watchdog_generation: u64,
    /// Admitted requester principal the snapshot was captured for.
    pub requester_principal: String,
    /// Stable snapshot operation identity (canonical request digest).
    pub snapshot_operation_id: String,
    /// Fence shape schema version ([`SPOOL_FENCE_SCHEMA_VERSION`]).
    pub schema_version: u16,
    /// Observation timestamp of the newest retained member the capture
    /// covers.
    ///
    /// This is the fence's capture anchor, taken from the owner's own retained
    /// record rather than from a caller-supplied or wall-clock instant, so it
    /// is never later than the newest evidence the fence actually carries.
    /// A page or whole-snapshot lifetime window is measured from here by the
    /// owner-bound port against its own clock, and the same window is applied
    /// at capture, so a capture that could never be paged is refused at
    /// capture instead of being handed out.
    pub captured_at_ms: u64,
    /// Compatible canonical capture reference, when fence-matched.
    pub canonical_ref: Option<String>,
    /// Compatible ORS capture reference, when fence-matched.
    pub ors_ref: Option<String>,
    /// Lowercase SHA-256 over the canonical encoding of the ordered redacted
    /// entries this fence carries.
    ///
    /// What it covers, exactly: each entry's identity (sequence, observation
    /// time, redacted kind, canonical encoded byte length), each entry's
    /// canonical entry digest — and therefore, transitively, the retained
    /// record bytes that digest commits to — and the verbatim marker detail of
    /// every coverage-invalidating record. What it does not cover: anything
    /// outside this fence, including the raw payload bytes themselves, which
    /// stay redacted and are never carried here.
    ///
    /// It is derived from the representation the fence actually stores, not
    /// from the raw records, so it is recomputable: [`validate`](Self::validate)
    /// re-derives it and every page read derives its own snapshot digest from
    /// the entries it serves. A fence whose entries changed after capture can
    /// therefore no longer present the original digest.
    pub content_digest: String,
}

impl WatchdogSpoolFence {
    /// Returns the ordered redacted retained entries this fence holds.
    ///
    /// A shared slice: callers observe the exact members the owner redacted and
    /// cannot add, remove, or reorder them. Any change is a corrupt fence, not a
    /// different view of the same evidence.
    #[must_use]
    pub fn entries(&self) -> &[RedactedSpoolEntry] {
        &self.entries
    }

    /// Returns the exact coverage denominator of this fence.
    ///
    /// A shared reference to an immutable `Copy` value, so `complete` cannot be
    /// flipped after capture; [`validate`](Self::validate) re-derives it from
    /// the entries the fence holds.
    #[must_use]
    pub const fn denominator(&self) -> &SpoolCoverageDenominator {
        &self.denominator
    }

    /// Re-validates this fence against the evidence it actually holds.
    ///
    /// Re-runs, over the entries in this fence rather than over any raw record:
    ///
    /// - the header shape and counters the codec validates — schema version,
    ///   nonzero sequence window, `record_count` equal to the entries actually
    ///   held, bounded record and byte ceilings, and a byte total equal to the
    ///   sum of the entries' recorded canonical lengths;
    /// - sequence consecutiveness — strictly increasing, first equal to
    ///   `header.first_sequence`, last below `header.next_sequence`;
    /// - the high-water binding — equal to `next_sequence - 1`, at or above the
    ///   last entry, with a matching `high_water_digest`;
    /// - the coverage denominator — retained count, marker count recomputed
    ///   from the entries' own kinds, and `complete` only when no marker is in
    ///   scope;
    /// - per-entry evidence — nonzero observation timestamp, bounded nonzero
    ///   canonical length, lowercase SHA-256 entry digest, and marker details
    ///   re-checked against the rules that redacted them;
    /// - the capture anchor (`captured_at_ms` is the newest observation held)
    ///   and the content digest (re-derived from these entries);
    /// - the bound identity shapes, and the fence schema version.
    ///
    /// What it deliberately cannot re-check: the exact cross-owner fence
    /// protocol behind `canonical_ref` / `ors_ref`. The fence stores no
    /// coherence flag, so this validates their digest shape only; coherence
    /// itself belongs to the coordinator that supplied them, and
    /// `WatchdogSpool::snapshot_backup` refuses any capture naming a
    /// cross-owner reference at all.
    ///
    /// A changed member, a changed denominator, or a swapped digest is therefore
    /// [`SpoolError::Corrupt`] — incomplete/corrupt, never a known-empty or
    /// full-coverage page.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when any re-derived counter, window,
    /// digest, or identity above disagrees with the fence, and
    /// [`SpoolError::Serialization`] when an entry cannot be canonically
    /// encoded.
    pub fn validate(&self) -> Result<(), SpoolError> {
        self.check_header_shape()?;
        self.validate_entries()?;
        self.validate_windows()?;
        self.validate_content()?;
        Ok(())
    }

    /// Re-checks the fence shape, its header counters, and the retained count.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the fence schema is unsupported, the
    /// fence holds no entries, the header counters or ceilings are
    /// inconsistent, or the header record count disagrees with the entries held.
    fn check_header_shape(&self) -> Result<(), SpoolError> {
        if self.schema_version != SPOOL_FENCE_SCHEMA_VERSION {
            return Err(fence_corrupt(
                "watchdog spool backup fence schema version is unsupported",
            ));
        }
        if self.entries.is_empty() {
            return Err(fence_corrupt(
                "watchdog spool backup fence holds no retained entries; a bare record vector is not a fence",
            ));
        }
        if self.header.schema_version != SPOOL_SCHEMA_VERSION
            || self.header.first_sequence == 0
            || self.header.next_sequence == 0
            || self.header.record_count > SPOOL_MAX_RECORDS
            || self.header.bytes > SPOOL_MAX_BYTES
        {
            return Err(fence_corrupt(
                "watchdog spool backup fence header counters or schema are inconsistent",
            ));
        }
        let retained_members = u64::try_from(self.entries.len()).map_err(|_| {
            fence_corrupt("watchdog spool backup fence retained count exceeds the bounded counter")
        })?;
        if self.header.record_count != retained_members {
            return Err(fence_corrupt(
                "watchdog spool backup fence header record count does not match the entries it holds",
            ));
        }
        Ok(())
    }

    /// Re-checks every entry the fence holds, their order, and their window.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when an entry carries an uninitialized
    /// timestamp, an out-of-frame length, a malformed digest, or a marker that
    /// fails its own checks; when entries are duplicated, out of order, or
    /// outside the header's sequence window; or when the summed canonical
    /// lengths disagree with the header byte total.
    fn validate_entries(&self) -> Result<(), SpoolError> {
        let max_record_bytes = u64::try_from(SPOOL_MAX_RECORD_BYTES).map_err(|_| {
            fence_corrupt("watchdog spool backup record frame exceeds the bounded counter")
        })?;
        let mut encoded_bytes = 0_u64;
        let mut previous_sequence: Option<u64> = None;
        for entry in &self.entries {
            if entry.observed_at_ms == 0 {
                return Err(fence_corrupt(
                    "watchdog spool backup fence entry carries an expired or uninitialized timestamp",
                ));
            }
            if entry.entry_bytes == 0 || entry.entry_bytes > max_record_bytes {
                return Err(fence_corrupt(
                    "watchdog spool backup fence entry length is outside the bounded record frame",
                ));
            }
            check_digest(&entry.entry_digest, "fence entry_digest")?;
            if let Some(marker) = &entry.marker {
                check_marker_detail(marker)?;
            }
            if previous_sequence.is_some_and(|previous| entry.sequence <= previous) {
                return Err(fence_corrupt(
                    "watchdog spool backup fence entries are duplicated or out of order",
                ));
            }
            previous_sequence = Some(entry.sequence);
            encoded_bytes = encoded_bytes
                .checked_add(entry.entry_bytes)
                .ok_or_else(|| {
                    fence_corrupt("watchdog spool backup fence byte counter overflow")
                })?;
        }
        if encoded_bytes != self.header.bytes {
            return Err(fence_corrupt(
                "watchdog spool backup fence byte total does not match the entries it holds",
            ));
        }
        let first_sequence = self.entries.first().map_or(0, |entry| entry.sequence);
        let last_sequence = self.newest_entry()?.sequence;
        if first_sequence != self.header.first_sequence
            || last_sequence >= self.header.next_sequence
        {
            return Err(fence_corrupt(
                "watchdog spool backup fence sequence window does not match its header",
            ));
        }
        Ok(())
    }

    /// Re-checks the high-water binding, the denominator, and the anchor.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the high-water does not bind the
    /// header window and the newest entry, when its digest disagrees, when the
    /// denominator disagrees with the entries' own kinds, or when the capture
    /// anchor is not the newest observation the fence holds.
    fn validate_windows(&self) -> Result<(), SpoolError> {
        let last_entry = self.newest_entry()?;
        let expected_high_water = self.header.next_sequence.checked_sub(1).ok_or_else(|| {
            fence_corrupt("watchdog spool backup fence header next sequence is invalid")
        })?;
        if self.high_water != expected_high_water || self.high_water < last_entry.sequence {
            return Err(fence_corrupt(
                "watchdog spool backup fence high-water does not bind the entries it holds",
            ));
        }
        if self.high_water_digest != sha256_hex(&encode_high_water(self.high_water)?) {
            return Err(fence_corrupt(
                "watchdog spool backup fence high-water digest does not match its high water",
            ));
        }
        let retained_members = self.retained_members()?;
        let gap_members = self.observed_gap_members();
        if self.denominator.retained_members != retained_members
            || self.denominator.gap_members != gap_members
            || self.denominator.complete != (gap_members == 0)
        {
            return Err(fence_corrupt(
                "watchdog spool backup fence denominator does not match the entries it holds",
            ));
        }
        if self.captured_at_ms != last_entry.observed_at_ms {
            return Err(fence_corrupt(
                "watchdog spool backup fence capture anchor is not the newest observation it holds",
            ));
        }
        Ok(())
    }

    /// Re-derives the content digest and re-checks the bound identities.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the content digest disagrees with
    /// the entries held, the generation is uninitialized, or an identity shape
    /// is unusable, and [`SpoolError::Serialization`] when an entry cannot be
    /// canonically encoded.
    fn validate_content(&self) -> Result<(), SpoolError> {
        if self.content_digest != self.derived_content_digest()? {
            return Err(fence_corrupt(
                "watchdog spool backup fence content digest does not match the entries it holds",
            ));
        }
        if self.watchdog_generation == 0 {
            return Err(fence_corrupt(
                "watchdog spool backup fence watchdog generation is uninitialized",
            ));
        }
        check_text(
            &self.source_installation,
            "fence source_installation",
            BACKUP_IDENTITY_MAX_BYTES,
        )?;
        check_text(
            &self.requester_principal,
            "fence requester_principal",
            BACKUP_IDENTITY_MAX_BYTES,
        )?;
        check_digest(&self.snapshot_operation_id, "fence snapshot_operation_id")?;
        if let Some(canonical_ref) = &self.canonical_ref {
            check_digest(canonical_ref, "fence canonical_ref")?;
        }
        if let Some(ors_ref) = &self.ors_ref {
            check_digest(ors_ref, "fence ors_ref")?;
        }
        Ok(())
    }

    /// Re-derives the content digest from exactly the entries this fence holds.
    ///
    /// The same derivation [`capture_fence`] used, so the digest is a function
    /// of the served evidence rather than a value copied beside it.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Serialization`] when an entry cannot be canonically
    /// encoded.
    fn derived_content_digest(&self) -> Result<String, SpoolError> {
        derive_content_digest(&self.entries)
    }

    /// Returns the newest entry this fence holds.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the fence holds no entry.
    fn newest_entry(&self) -> Result<&RedactedSpoolEntry, SpoolError> {
        self.entries
            .last()
            .ok_or_else(|| fence_corrupt("watchdog spool backup fence holds no entries"))
    }

    /// Returns the exact retained count re-derived from the entries held.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the count exceeds the bounded
    /// counter.
    fn retained_members(&self) -> Result<u64, SpoolError> {
        u64::try_from(self.entries.len()).map_err(|_| {
            fence_corrupt("watchdog spool backup fence retained count exceeds the bounded counter")
        })
    }

    /// Returns the marker count re-derived from the entries' own kinds.
    fn observed_gap_members(&self) -> u64 {
        self.entries
            .iter()
            .filter(|entry| entry.kind.marks_incomplete())
            .fold(0_u64, |count, _| count.saturating_add(1))
    }

    /// Returns the validated header schema version.
    #[must_use]
    pub const fn header_schema_version(&self) -> u16 {
        self.header.schema_version
    }

    /// Returns the validated header next sequence.
    #[must_use]
    pub const fn header_next_sequence(&self) -> u64 {
        self.header.next_sequence
    }

    /// Returns the validated header first sequence.
    #[must_use]
    pub const fn header_first_sequence(&self) -> u64 {
        self.header.first_sequence
    }

    /// Returns the validated header record count.
    #[must_use]
    pub const fn header_record_count(&self) -> u64 {
        self.header.record_count
    }

    /// Returns the validated header byte total.
    #[must_use]
    pub const fn header_bytes(&self) -> u64 {
        self.header.bytes
    }

    /// Returns the exact retained entry count.
    #[must_use]
    pub fn retained_count(&self) -> u64 {
        self.denominator.retained_members
    }

    /// Returns the summed canonical byte length of the retained entries.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.entry_bytes)
            .fold(0_u64, u64::saturating_add)
    }
}

/// Bounded window for one backup snapshot page read.
///
/// Mirrors [`WatchdogSpoolExportLimits`](super::WatchdogSpoolExportLimits)
/// with the admitted page-member bound plus the page freshness, bounded work,
/// and whole-snapshot lifetime bounds. All bounds apply together; a window
/// outside any ceiling is rejected instead of silently clamped so an exact
/// retry of the same window stays byte-equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolBackupLimits {
    /// Maximum members covered cumulatively; nonzero, at most
    /// `EXPORT_MAX_ITEMS`.
    pub max_items: usize,
    /// Maximum cumulative bytes; at least one maximum-size record, at most
    /// `EXPORT_MAX_BYTES`.
    pub max_bytes: u64,
    /// Maximum members carried by one page; nonzero, at most
    /// [`BACKUP_PAGE_MEMBERS_CEILING`]. Mirrors the #954
    /// `max_page_members` admitted page bound.
    pub max_page_members: u32,
    /// Page freshness window in milliseconds; nonzero, at most
    /// `EXPORT_BATCH_TTL_MS`.
    pub page_ttl_ms: u64,
    /// Maximum work units for the read; nonzero, at most
    /// [`BACKUP_MAX_WORK_UNITS`].
    pub max_work_units: u64,
    /// Whole-snapshot lifetime in milliseconds; nonzero, at most
    /// [`BACKUP_SNAPSHOT_LIFETIME_MS`].
    pub snapshot_lifetime_ms: u64,
}

impl Default for WatchdogSpoolBackupLimits {
    /// Returns the default bounded window: export ceilings throughout.
    fn default() -> Self {
        Self {
            max_items: EXPORT_MAX_ITEMS,
            max_bytes: EXPORT_MAX_BYTES,
            max_page_members: BACKUP_PAGE_MEMBERS_CEILING,
            page_ttl_ms: EXPORT_BATCH_TTL_MS,
            max_work_units: BACKUP_MAX_WORK_UNITS,
            snapshot_lifetime_ms: BACKUP_SNAPSHOT_LIFETIME_MS,
        }
    }
}

impl WatchdogSpoolBackupLimits {
    /// Rejects unbounded, unprogressable, or over-ceiling windows.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] carrying the exact bound failure when
    /// any bound is zero or above its hard ceiling.
    pub fn validate(&self) -> Result<(), SpoolError> {
        if self.max_items == 0 || self.max_items > EXPORT_MAX_ITEMS {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: max_items must be nonzero and within the export ceiling"
                    .to_owned(),
            ));
        }
        if self.max_bytes < BACKUP_MIN_PAGE_BYTES || self.max_bytes > EXPORT_MAX_BYTES {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: max_bytes must cover one record and stay within the export ceiling"
                    .to_owned(),
            ));
        }
        if self.max_page_members == 0 || self.max_page_members > BACKUP_PAGE_MEMBERS_CEILING {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: max_page_members must be nonzero and bounded"
                    .to_owned(),
            ));
        }
        if self.page_ttl_ms == 0 || self.page_ttl_ms > EXPORT_BATCH_TTL_MS {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: page_ttl_ms must be nonzero and within the freshness window"
                    .to_owned(),
            ));
        }
        if self.max_work_units == 0 || self.max_work_units > BACKUP_MAX_WORK_UNITS {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: max_work_units must be nonzero and within the retention ceiling"
                    .to_owned(),
            ));
        }
        if self.snapshot_lifetime_ms == 0 || self.snapshot_lifetime_ms > BACKUP_SNAPSHOT_LIFETIME_MS
        {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: snapshot_lifetime_ms must be nonzero and within the snapshot lifetime"
                    .to_owned(),
            ));
        }
        if self.max_bytes > SPOOL_MAX_BYTES
            || u64::try_from(self.max_items).is_ok_and(|count| count > SPOOL_MAX_RECORDS)
        {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup limits: window exceeds the spool retention ceiling"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Immutable bounded page of one snapshot.
///
/// Binds the snapshot digest, the zero-based page index, the page digest over
/// the member digests, the redacted entry subset, cumulative and total
/// counts/bytes, and the `complete` flag. Continuation binds exactly one
/// snapshot: [`check_page_continuation`] rejects any page whose snapshot
/// digest drifts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolSnapshotPage {
    /// Snapshot digest of the fence entries this page was read from.
    ///
    /// Derived from the entries the read actually served, never copied from a
    /// value stored beside them, so a mutated fence cannot present the
    /// original digest.
    pub snapshot_digest: String,
    /// Zero-based page index within the bounded snapshot.
    pub page_index: u64,
    /// Lowercase SHA-256 over the joined member digests of this page.
    pub page_digest: String,
    /// Redacted entry subset for this page, in snapshot order.
    pub entries: Vec<RedactedSpoolEntry>,
    /// Cumulative members covered through the end of this page.
    pub cumulative_members: u64,
    /// Cumulative canonical bytes covered through the end of this page.
    pub cumulative_bytes: u64,
    /// Total snapshot members.
    pub total_members: u64,
    /// Total snapshot canonical bytes.
    pub total_bytes: u64,
    /// True when this page ends exactly at the snapshot end.
    pub complete: bool,
}

/// Caller-supplied capture bindings for [`capture_fence`].
///
/// The owner method fills these from the retained binding (source
/// installation, watchdog generation) and the admitted backup request
/// (requester principal, stable operation identity, canonical/ORS refs).
/// Coherence with a canonical or ORS capture is established only by the
/// cross-owner coordinator's exact fence protocol, carried here as
/// `coherence_fence_equal`: equal timestamps alone claim nothing, and this
/// shape deliberately carries no timestamp input to compare.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureFenceParams {
    /// Source installation the capture is taken from.
    pub source_installation: String,
    /// Watchdog generation bound at sensor construction.
    pub watchdog_generation: u64,
    /// Admitted requester principal the snapshot is captured for.
    pub requester_principal: String,
    /// Stable snapshot operation identity (canonical request digest).
    pub snapshot_operation_id: String,
    /// Compatible canonical capture reference, when fence-matched.
    pub canonical_ref: Option<String>,
    /// Compatible ORS capture reference, when fence-matched.
    pub ors_ref: Option<String>,
    /// Exact fence-protocol equality observed by the coordinator.
    pub coherence_fence_equal: bool,
}

/// Returns the owner service identity carried by one spool payload.
///
/// The match is exhaustive with no wildcard: a future payload variant fails
/// the build here instead of entering a fence with an unknown owner.
fn entry_service(payload: &WatchdogSpoolPayload) -> &str {
    match payload {
        WatchdogSpoolPayload::Heartbeat { service, .. }
        | WatchdogSpoolPayload::Gap { service, .. }
        | WatchdogSpoolPayload::Recovery { service, .. }
        | WatchdogSpoolPayload::ProblemIntent { service, .. }
        | WatchdogSpoolPayload::IncidentIntent { service, .. } => service,
    }
}

/// Re-checks one already-redacted marker against the rules that redacted it.
///
/// The rules are exactly the ones [`marker_detail`] applied at capture, so a
/// marker that passes here carries the same shapes the retained record did.
/// `Gap` markers hold a closed reason enum and `Intent` markers hold
/// enum-scoped lineage, so the recovery arm is the only one with free-form text
/// and a digest field to re-check.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when a recovery reason is blank or
/// oversized, or a corrupt digest is neither lowercase SHA-256 nor the
/// preserved `"missing"` literal.
fn check_marker_detail(marker: &SpoolMarkerDetail) -> Result<(), SpoolError> {
    if let SpoolMarkerDetail::Recovery {
        reason,
        corrupt_digest,
        ..
    } = marker
    {
        check_text(reason, "recovery reason", BACKUP_REASON_MAX_BYTES)?;
        if corrupt_digest != MISSING_DIGEST_LITERAL {
            check_digest(corrupt_digest, "recovery corrupt_digest")?;
        }
    }
    Ok(())
}

/// Canonical digest representation of one redacted entry.
///
/// The same JSON encoder the spool codec uses for a retained record, applied to
/// the redacted view instead: it commits to the entry identity, the entry
/// digest, the recorded canonical length, and the verbatim marker detail, and
/// it carries no payload bytes. It exists so the fence content digest is
/// re-derivable from what the fence stores; it is not a wire codec and nothing
/// decodes it.
///
/// # Errors
///
/// Returns [`SpoolError::Serialization`] when the entry cannot be canonically
/// encoded.
fn encode_redacted_entry(entry: &RedactedSpoolEntry) -> Result<Vec<u8>, SpoolError> {
    serde_json::to_vec(entry).map_err(|error| SpoolError::Serialization(error.to_string()))
}

/// Re-derives the content digest of exactly the ordered entries a fence holds.
///
/// Derived from the representation the fence actually stores rather than from
/// the raw records, so the digest is recomputable on every read and a fence
/// whose entries changed after capture can no longer present the original
/// digest. Coverage of what the digest commits to is stated on
/// [`WatchdogSpoolFence::content_digest`].
///
/// # Errors
///
/// Returns [`SpoolError::Serialization`] when an entry cannot be canonically
/// encoded.
fn derive_content_digest(entries: &[RedactedSpoolEntry]) -> Result<String, SpoolError> {
    let mut material = Vec::new();
    for entry in entries {
        material.extend_from_slice(&encode_redacted_entry(entry)?);
    }
    Ok(sha256_hex(&material))
}

/// Builds the verbatim marker detail for coverage-invalidating records.
///
/// Heartbeats carry no marker (`None`): their payload bytes stay redacted.
/// `Gap` markers keep their exact reason and coverage flag; `Recovery`
/// records keep their exact reason and corrupt-sequence evidence; intents
/// keep their evidence digests and owner lineage. The built marker is then
/// re-checked through [`check_marker_detail`], the same check
/// [`WatchdogSpoolFence::validate`] applies to an already-redacted marker.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when a redacted marker detail fails the
/// checks above.
fn marker_detail(payload: &WatchdogSpoolPayload) -> Result<Option<SpoolMarkerDetail>, SpoolError> {
    let detail = match payload {
        WatchdogSpoolPayload::Heartbeat { .. } => None,
        WatchdogSpoolPayload::Gap {
            reason,
            coverage_claimed,
            ..
        } => Some(SpoolMarkerDetail::Gap {
            reason: *reason,
            coverage_claimed: *coverage_claimed,
        }),
        WatchdogSpoolPayload::Recovery {
            reason,
            corrupt_sequence,
            corrupt_digest,
            ..
        } => Some(SpoolMarkerDetail::Recovery {
            reason: reason.clone(),
            corrupt_sequence: *corrupt_sequence,
            corrupt_digest: corrupt_digest.clone(),
        }),
        WatchdogSpoolPayload::ProblemIntent {
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
            ..
        }
        | WatchdogSpoolPayload::IncidentIntent {
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
            ..
        } => Some(SpoolMarkerDetail::Intent {
            evidence_refs: evidence_refs.clone(),
            lineage_installation_id: lineage_installation_id.clone(),
            lineage_generation: *lineage_generation,
            lineage_epoch: *lineage_epoch,
            governor_unavailable_reason: *governor_unavailable_reason,
        }),
    };
    if let Some(detail) = detail.as_ref() {
        check_marker_detail(detail)?;
    }
    Ok(detail)
}

/// Validates one retained entry against its expected sequence and redacts it.
///
/// Rejects schema drift, out-of-order or duplicate sequences, sequence gaps,
/// uninitialized timestamps, blank owner service, non-canonical intent rows,
/// and malformed recovery evidence as [`SpoolError::Corrupt`] (explicit
/// incomplete/corrupt, never an empty view).
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] or [`SpoolError::Serialization`] when the
/// entry fails any bound above or cannot be canonically encoded.
fn redact_entry(
    entry: &WatchdogSpoolEntry,
    expected_sequence: u64,
) -> Result<RedactedSpoolEntry, SpoolError> {
    if entry.schema_version != SPOOL_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup entry {} has an unsupported schema version",
            entry.sequence
        )));
    }
    if entry.sequence < expected_sequence {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup entry {} is a duplicate or out of order",
            entry.sequence
        )));
    }
    if entry.sequence > expected_sequence {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup entry {expected_sequence} is missing before entry {}",
            entry.sequence
        )));
    }
    if entry.observed_at_ms == 0 {
        return Err(SpoolError::Corrupt(format!(
            "watchdog spool backup entry {} carries an expired or uninitialized timestamp",
            entry.sequence
        )));
    }
    check_stored_intent_payload(entry.observed_at_ms, &entry.payload)?;
    check_text(
        entry_service(&entry.payload),
        "spool entry service",
        BACKUP_IDENTITY_MAX_BYTES,
    )?;
    let raw = encode_entry(entry)?;
    let entry_bytes = u64::try_from(raw.len()).map_err(|_| {
        SpoolError::Corrupt(
            "watchdog spool backup entry exceeds the bounded byte counter".to_owned(),
        )
    })?;
    Ok(RedactedSpoolEntry {
        sequence: entry.sequence,
        observed_at_ms: entry.observed_at_ms,
        kind: SpoolFenceEntryKind::classify(&entry.payload),
        entry_digest: sha256_hex(&raw),
        entry_bytes,
        marker: marker_detail(&entry.payload)?,
    })
}

/// Validates the caller capture bindings for [`capture_fence`].
///
/// Requires non-blank bounded installation, principal, and operation
/// identities, lowercase SHA-256 shape for the stable operation identity and
/// any canonical/ORS reference, and exact fence-protocol equality whenever a
/// canonical or ORS reference claims coherence. A reference without fence
/// equality is a timestamp-only coherence claim and is refused: no timestamp
/// input exists to compare.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when any binding above fails.
fn check_capture_params(params: &CaptureFenceParams) -> Result<(), SpoolError> {
    check_text(
        &params.source_installation,
        "source_installation",
        BACKUP_IDENTITY_MAX_BYTES,
    )?;
    if params.watchdog_generation == 0 {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup watchdog_generation is uninitialized".to_owned(),
        ));
    }
    check_text(
        &params.requester_principal,
        "requester_principal",
        BACKUP_IDENTITY_MAX_BYTES,
    )?;
    check_digest(&params.snapshot_operation_id, "snapshot_operation_id")?;
    if let Some(canonical_ref) = &params.canonical_ref {
        check_digest(canonical_ref, "canonical_ref")?;
    }
    if let Some(ors_ref) = &params.ors_ref {
        check_digest(ors_ref, "ors_ref")?;
    }
    if (params.canonical_ref.is_some() || params.ors_ref.is_some()) && !params.coherence_fence_equal
    {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup canonical/ORS coherence requires exact fence equality, never timestamps alone"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Captures an immutable bounded fence over already-opened spool data.
///
/// The owner method opens one bounded coherent read transaction, validates
/// the header and high-water through the existing codec validators, and calls
/// this function with the decoded header, ordered entries, and durable
/// high-water. Every entry is rechecked (schema, consecutive sequence from
/// `first_sequence` through `next_sequence - 1`, initialized timestamp,
/// owner service, canonical intent shape, recovery evidence) and redacted
/// into ordered views; `Gap`, `Recovery`, and intent records are preserved
/// verbatim and mark the denominator incomplete. The result binds source
/// installation, watchdog generation, admitted requester, stable snapshot
/// operation identity, fence schema, fence-matched canonical/ORS references,
/// and the content digest.
///
/// The content digest is derived from the redacted entries this fence stores —
/// the same representation [`WatchdogSpoolFence::validate`] re-derives — so it
/// is recomputable and cannot outlive the evidence it describes. This builder
/// consults no clock and no caller-supplied instant: the capture anchor is the
/// newest retained observation, and the owner-bound port applies the clock
/// window to that anchor identically at capture and at every page read.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the header or high-water fails
/// validation, the entry set is empty, or any entry is expired, missing,
/// duplicated, conflicting, or malformed. Returns [`SpoolError::Corrupt`]
/// when a caller binding is unusable or claims canonical/ORS coherence
/// without exact fence equality. Returns [`SpoolError::Serialization`] when
/// canonical encoding fails.
pub fn capture_fence(
    header: &WatchdogSpoolHeader,
    entries: &[WatchdogSpoolEntry],
    high_water: u64,
    params: &CaptureFenceParams,
) -> Result<WatchdogSpoolFence, SpoolError> {
    validate_header(header, entries)?;
    validate_high_water(header, entries, high_water)?;
    check_capture_params(params)?;
    if entries.is_empty() {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup capture covers no retained entries; a bare record vector is not a fence"
                .to_owned(),
        ));
    }
    let last_sequence = header.next_sequence.checked_sub(1).ok_or_else(|| {
        SpoolError::Corrupt("watchdog spool backup header next sequence is invalid".to_owned())
    })?;
    let mut redacted = Vec::with_capacity(entries.len());
    let mut gap_members = 0_u64;
    for (index, entry) in entries.iter().enumerate() {
        let offset = u64::try_from(index).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog spool backup entry index exceeds the bounded counter".to_owned(),
            )
        })?;
        let expected = header.first_sequence.checked_add(offset).ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool backup sequence overflow".to_owned())
        })?;
        let view = redact_entry(entry, expected)?;
        if view.kind.marks_incomplete() {
            gap_members = gap_members.saturating_add(1);
        }
        redacted.push(view);
    }
    if redacted
        .last()
        .is_some_and(|last| last.sequence != last_sequence)
    {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup capture is missing trailing retained entries".to_owned(),
        ));
    }
    let retained_members = u64::try_from(redacted.len()).map_err(|_| {
        SpoolError::Corrupt(
            "watchdog spool backup retained count exceeds the bounded counter".to_owned(),
        )
    })?;
    // The capture anchor is the newest retained observation, so the lifetime
    // window can only ever understate freshness, never overstate it. The
    // content digest is derived from the redacted entries the fence stores, so
    // it is recomputable at every later read and a changed member can no longer
    // present the original digest.
    let captured_at_ms = entries
        .last()
        .map(|entry| entry.observed_at_ms)
        .ok_or_else(|| {
            SpoolError::Corrupt(
                "watchdog spool backup capture covers no retained entries; a bare record vector is not a fence"
                    .to_owned(),
            )
        })?;
    let content_digest = derive_content_digest(&redacted)?;
    Ok(WatchdogSpoolFence {
        header: header.clone(),
        high_water,
        high_water_digest: sha256_hex(&encode_high_water(high_water)?),
        entries: redacted,
        denominator: SpoolCoverageDenominator {
            retained_members,
            gap_members,
            complete: gap_members == 0,
        },
        source_installation: params.source_installation.clone(),
        watchdog_generation: params.watchdog_generation,
        requester_principal: params.requester_principal.clone(),
        snapshot_operation_id: params.snapshot_operation_id.clone(),
        schema_version: SPOOL_FENCE_SCHEMA_VERSION,
        captured_at_ms,
        canonical_ref: params.canonical_ref.clone(),
        ors_ref: params.ors_ref.clone(),
        content_digest,
    })
}

/// Reads one bounded page of a captured fence.
///
/// Page `page_index` covers at most `min(max_items, max_page_members)`
/// members starting at `page_index * per_page`, further truncated so the
/// cumulative bytes stay within `max_bytes` after always covering at least
/// one member. The cumulative members and bytes through the end of the page
/// must stay within `max_items`, `max_bytes`, and `max_work_units`; the work
/// ceiling is consulted here, not only shape-validated, so one page can never
/// examine more retained members than the admitted bounded window allows.
/// Continuation binds the one fence digest, so a page past the retained window
/// or past the cumulative bound fails instead of drifting.
///
/// The fence is re-validated first, through [`WatchdogSpoolFence::validate`],
/// and the page's snapshot digest is derived from the entries this read actually
/// serves rather than copied from a field beside them. A fence whose members,
/// denominator, or digests changed after capture is therefore
/// [`SpoolError::Corrupt`] here: no page can present the original digest over
/// evidence it no longer holds.
///
/// The clock-dependent `page_ttl_ms` and `snapshot_lifetime_ms` bounds are not
/// decidable from fence data alone; they are enforced by the owner-bound
/// [`crate::WatchdogBackupPort::read_page`], which holds the owner clock and
/// the fence's [`WatchdogSpoolFence::captured_at_ms`] anchor — and which applies
/// the identical window at [`crate::WatchdogBackupPort::snapshot`], so a capture
/// that could never be paged is refused at capture.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the fence fails re-validation, the
/// limits are unusable, the page index runs past the retained window or past a
/// cumulative bound, or a bounded counter overflows.
pub fn read_page(
    fence: &WatchdogSpoolFence,
    page_index: u64,
    limits: &WatchdogSpoolBackupLimits,
) -> Result<WatchdogSpoolSnapshotPage, SpoolError> {
    limits.validate()?;
    fence.validate()?;
    // Derived from the entries this read serves, so the page cannot present a
    // digest it did not derive from the evidence it is returning.
    let snapshot_digest = fence.derived_content_digest()?;
    let page_cap = u64::from(limits.max_page_members);
    let items_cap = u64::try_from(limits.max_items).map_err(|_| {
        fence_corrupt("watchdog spool backup item bound exceeds the bounded counter")
    })?;
    let per_page = items_cap.min(page_cap);
    let total_members = u64::try_from(fence.entries.len()).map_err(|_| {
        fence_corrupt("watchdog spool backup retained count exceeds the bounded counter")
    })?;
    let start = page_index.checked_mul(per_page).ok_or_else(|| {
        fence_corrupt("watchdog spool backup page index overflows the bounded window")
    })?;
    if start >= total_members {
        return Err(fence_corrupt(
            "watchdog spool backup page runs past the retained window; continuation drift",
        ));
    }
    if start >= items_cap {
        return Err(fence_corrupt(
            "watchdog spool backup page exceeds the cumulative member bound",
        ));
    }
    let start_idx = usize::try_from(start).map_err(|_| {
        fence_corrupt("watchdog spool backup page offset exceeds the bounded window")
    })?;
    let page_cap_idx = usize::try_from(per_page).map_err(|_| {
        fence_corrupt("watchdog spool backup page width exceeds the bounded window")
    })?;
    let mut end_idx = start_idx;
    let mut page_bytes = 0_u64;
    for entry in fence.entries.iter().skip(start_idx).take(page_cap_idx) {
        if end_idx > start_idx && page_bytes.saturating_add(entry.entry_bytes) > limits.max_bytes {
            break;
        }
        page_bytes = page_bytes
            .checked_add(entry.entry_bytes)
            .ok_or_else(|| fence_corrupt("watchdog spool backup page byte counter overflow"))?;
        end_idx += 1;
    }
    let taken = end_idx
        .checked_sub(start_idx)
        .ok_or_else(|| fence_corrupt("watchdog spool backup page window underflow"))?;
    let cumulative_members = start
        .checked_add(u64::try_from(taken).map_err(|_| {
            fence_corrupt("watchdog spool backup page count exceeds the bounded counter")
        })?)
        .ok_or_else(|| fence_corrupt("watchdog spool backup cumulative member counter overflow"))?;
    if cumulative_members > items_cap {
        return Err(fence_corrupt(
            "watchdog spool backup page exceeds the cumulative member bound",
        ));
    }
    let mut cumulative_bytes = 0_u64;
    for entry in fence.entries.iter().take(end_idx) {
        cumulative_bytes = cumulative_bytes
            .checked_add(entry.entry_bytes)
            .ok_or_else(|| {
                fence_corrupt("watchdog spool backup cumulative byte counter overflow")
            })?;
    }
    if cumulative_bytes > limits.max_bytes {
        return Err(fence_corrupt(
            "watchdog spool backup page exceeds the cumulative byte bound",
        ));
    }
    // The work ceiling is consulted, not only shape-validated: the members this
    // page examined must fit the admitted bounded work window.
    let examined = u64::try_from(end_idx).map_err(|_| {
        fence_corrupt("watchdog spool backup page width exceeds the bounded counter")
    })?;
    if examined > limits.max_work_units {
        return Err(fence_corrupt(
            "watchdog spool backup page exceeds the bounded work ceiling",
        ));
    }
    let mut digest_material = Vec::new();
    for entry in fence.entries.iter().skip(start_idx).take(taken) {
        digest_material.extend_from_slice(entry.entry_digest.as_bytes());
    }
    Ok(WatchdogSpoolSnapshotPage {
        snapshot_digest,
        page_index,
        page_digest: sha256_hex(&digest_material),
        entries: fence.entries[start_idx..end_idx].to_vec(),
        cumulative_members,
        cumulative_bytes,
        total_members,
        total_bytes: fence.total_bytes(),
        complete: end_idx
            == usize::try_from(total_members).map_err(|_| {
                fence_corrupt("watchdog spool backup retained count exceeds the bounded window")
            })?,
    })
}

/// Rejects page continuation drift across snapshots.
///
/// The continuation binds exactly one snapshot digest: a page whose digest
/// differs from the expected fence content digest fails closed.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the page snapshot digest drifts from
/// the expected snapshot digest.
pub fn check_page_continuation(
    expected_snapshot_digest: &str,
    page: &WatchdogSpoolSnapshotPage,
) -> Result<(), SpoolError> {
    if page.snapshot_digest != expected_snapshot_digest {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup page continuation drifts from the bound snapshot digest"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Recomputes and checks one page digest from its member digests.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the page digest does not match the
/// joined member digests.
pub fn verify_page_digest(page: &WatchdogSpoolSnapshotPage) -> Result<(), SpoolError> {
    let mut digest_material = Vec::new();
    for entry in &page.entries {
        digest_material.extend_from_slice(entry.entry_digest.as_bytes());
    }
    if page.page_digest != sha256_hex(&digest_material) {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup page digest does not match its member digests".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the isolated restore destination triple.
///
/// Mirrors `BackupIsolatedRestorePrepare`: the destination must be an
/// explicitly admitted installation that differs from the source (preserved
/// old observations stay under their exact source identity) and from the
/// currently active installation (an import never reuses the active lease,
/// heartbeat readiness, supervision authority, or kernel/watchdog epochs).
/// Imported evidence is forensic and historical only: this check carries no
/// lease, epoch, authority, or cutover field by construction.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when any installation identity is blank or
/// oversized, or the destination is not isolated from the source and active
/// installations.
pub fn validate_isolated_destination(
    source_installation: &str,
    dest_installation: &str,
    active_installation: &str,
) -> Result<(), SpoolError> {
    check_text(
        source_installation,
        "source_installation",
        BACKUP_IDENTITY_MAX_BYTES,
    )?;
    check_text(
        dest_installation,
        "dest_installation",
        BACKUP_IDENTITY_MAX_BYTES,
    )?;
    check_text(
        active_installation,
        "active_installation",
        BACKUP_IDENTITY_MAX_BYTES,
    )?;
    if dest_installation == source_installation {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup destination must be isolated from the source installation"
                .to_owned(),
        ));
    }
    if dest_installation == active_installation {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup destination must be isolated from the active installation"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Idempotent disposition returned by the import replay ledger.
///
/// Mirrors `BackupReplayDisposition`: a byte-identical digest observes
/// `Duplicate` (repeated import appends nothing), while changed content under
/// the same stable identity is a `ReplayConflict` reported as
/// [`SpoolError::Corrupt`], never a silent accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolImportReplayDisposition {
    /// First observation of this stable operation identity.
    Accepted,
    /// Byte-identical repeat; the import appends nothing.
    Duplicate,
}

/// Pure replay identity ledger for isolated restore operations.
///
/// Mirrors `BackupReplayLedger`: keyed by the stable operation identity (the
/// #954 `mutation.canonical_request_hash`, carried here as the step or
/// snapshot operation id); a byte-identical content digest observes
/// `Duplicate`, while changed content under the same identity returns a
/// replay conflict before any spool effect. The ledger is pure memory, not
/// durable storage: durability stays with the owner transaction.
#[derive(Clone, Debug, Default)]
pub struct SpoolImportReplayLedger {
    /// Stable operation identity to canonical content digest.
    seen: BTreeMap<String, String>,
}

impl SpoolImportReplayLedger {
    /// Creates an empty replay ledger. It is not durable storage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
        }
    }

    /// Records an operation identity and returns its idempotent disposition.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when either identity is malformed, or
    /// when changed content reuses an observed stable identity (replay
    /// conflict: exact import replays, changed input conflicts).
    pub fn observe(
        &mut self,
        operation_id: &str,
        content_digest: &str,
    ) -> Result<SpoolImportReplayDisposition, SpoolError> {
        check_text(operation_id, "operation_id", BACKUP_IDENTITY_MAX_BYTES)?;
        check_digest(content_digest, "content_digest")?;
        if let Some(previous) = self.seen.get(operation_id) {
            if previous == content_digest {
                return Ok(SpoolImportReplayDisposition::Duplicate);
            }
            return Err(SpoolError::Corrupt(
                "watchdog spool backup replay identity conflicts with changed content".to_owned(),
            ));
        }
        self.seen
            .insert(operation_id.to_owned(), content_digest.to_owned());
        Ok(SpoolImportReplayDisposition::Accepted)
    }
}

/// One operation-bound isolated restore step.
///
/// Mirrors `BackupRestoreStep`: the zero-based `step_index`, the canonical
/// `step_digest` of the step content retained by the owner, the
/// `predecessor_digest` chaining to the previous step (or the preparation
/// digest for step zero), and the stable `operation_id` binding the admitted
/// operation. Carries no content bytes and no authority material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolRestoreStep {
    /// Zero-based step index within the admitted restore.
    pub step_index: u64,
    /// Canonical digest of the step content retained by the owner.
    pub step_digest: String,
    /// Digest of the predecessor step, or the preparation digest for step zero.
    pub predecessor_digest: String,
    /// Stable operation identity binding the admitted operation.
    pub operation_id: String,
}

/// Validates one restore step chain against its preparation digest.
///
/// Requires a non-empty step list with consecutive zero-based indices,
/// well-formed digests and operation identities, and exact linkage: step zero
/// chains to `prepare_digest` and every later step chains to its
/// predecessor's `step_digest`. A lost import response reconciles by its
/// believed digest through [`reconcile_restore`] without appending a
/// duplicate; an empty chain fails explicitly instead of restoring nothing by
/// default.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the preparation digest or any step
/// field is malformed, the chain is empty, indices are not consecutive from
/// zero, or any linkage breaks.
pub fn validate_restore_chain(
    prepare_digest: &str,
    steps: &[SpoolRestoreStep],
) -> Result<(), SpoolError> {
    check_digest(prepare_digest, "prepare_digest")?;
    if steps.is_empty() {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup restore chain covers no steps; an empty chain restores nothing"
                .to_owned(),
        ));
    }
    let mut expected_predecessor = prepare_digest;
    for (index, step) in steps.iter().enumerate() {
        let expected_index = u64::try_from(index).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog spool backup restore step index exceeds the bounded counter".to_owned(),
            )
        })?;
        if step.step_index != expected_index {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup restore step index is not consecutive from zero".to_owned(),
            ));
        }
        check_digest(&step.step_digest, "restore step step_digest")?;
        check_digest(&step.predecessor_digest, "restore step predecessor_digest")?;
        check_text(
            &step.operation_id,
            "restore step operation_id",
            BACKUP_IDENTITY_MAX_BYTES,
        )?;
        if step.predecessor_digest != expected_predecessor {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup restore step linkage is broken".to_owned(),
            ));
        }
        expected_predecessor = &step.step_digest;
    }
    Ok(())
}

/// Per-item restore disposition, preserved separately, never a bool.
///
/// Mirrors the #954 `BackupDisposition` subset relevant to the spool owner.
/// `Unknown` keeps an unresolved critical signal visible: it blocks recovery
/// acceptance through [`acceptance_allowed`] instead of returning zero by
/// default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolRestoreDisposition {
    /// Step applied exactly once.
    Accepted,
    /// Byte-identical repeat; nothing appended.
    Duplicate,
    /// Lost response reconciled by believed digest; nothing appended.
    Reconciled,
    /// Unresolved reconciliation; visible and blocking.
    Unknown,
}

/// One retained digest with its observed restore disposition.
///
/// Content-free by construction: only the believed digest is compared, never
/// recomputed semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolObservedDigest {
    /// Retained canonical digest of the observed step content.
    pub digest: String,
    /// Observed disposition for that digest.
    pub disposition: SpoolRestoreDisposition,
}

/// Answers a restore reconcile query from retained digests only.
///
/// Mirrors `BackupRestoreReconcile`: carries no content, only the believed
/// digest. A believed digest matching retained evidence returns its recorded
/// disposition (so a lost import response reconciles without a duplicate
/// append); a believed digest with no retained evidence returns `Unknown`,
/// which stays visible and blocks recovery acceptance.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the believed digest or any retained
/// digest is malformed.
pub fn reconcile_restore(
    observed: &[SpoolObservedDigest],
    believed_digest: &str,
) -> Result<SpoolRestoreDisposition, SpoolError> {
    check_digest(believed_digest, "believed_digest")?;
    for entry in observed {
        check_digest(&entry.digest, "observed digest")?;
    }
    for entry in observed {
        if entry.digest == believed_digest {
            return Ok(entry.disposition);
        }
    }
    Ok(SpoolRestoreDisposition::Unknown)
}

/// Decides whether a restore disposition admits recovery acceptance.
///
/// `Accepted`, `Duplicate`, and `Reconciled` admit acceptance (duplicates and
/// reconciliations append nothing); `Unknown` fails closed so an unresolved
/// critical signal remains blocked, never known-zero.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the disposition is `Unknown`.
pub fn acceptance_allowed(disposition: SpoolRestoreDisposition) -> Result<(), SpoolError> {
    if disposition == SpoolRestoreDisposition::Unknown {
        return Err(SpoolError::Corrupt(
            "watchdog spool backup reconciliation is unknown; recovery acceptance is blocked"
                .to_owned(),
        ));
    }
    Ok(())
}
