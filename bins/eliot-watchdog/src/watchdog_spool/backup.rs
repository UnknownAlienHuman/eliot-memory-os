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

use std::collections::BTreeMap;

use eliot_contracts::sha256_hex;

use crate::{GapRecoveryReason, SpoolError};

use super::codec::{
    WatchdogSpoolEntry, WatchdogSpoolHeader, WatchdogSpoolPayload, encode_entry, encode_high_water,
    validate_header, validate_high_water,
};
use super::intent::check_stored_intent_payload;
use super::{
    EXPORT_BATCH_TTL_MS, EXPORT_MAX_BYTES, EXPORT_MAX_ITEMS, SPOOL_MAX_BYTES, SPOOL_MAX_RECORDS,
    SPOOL_SCHEMA_VERSION,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug)]
pub struct WatchdogSpoolFence {
    /// Validated spool header (schema and counters only, no payloads).
    pub(crate) header: WatchdogSpoolHeader,
    /// Durable high-water sequence bound by the capture.
    pub high_water: u64,
    /// Lowercase SHA-256 over the canonical high-water bytes.
    pub high_water_digest: String,
    /// Ordered redacted retained entries, sequence-consecutive.
    pub entries: Vec<RedactedSpoolEntry>,
    /// Exact retained member and marker denominator.
    pub denominator: SpoolCoverageDenominator,
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
    /// A page or whole-snapshot lifetime window is measured from here: a
    /// fence whose newest evidence is older than the admitted window is
    /// expired, not current.
    pub captured_at_ms: u64,
    /// Compatible canonical capture reference, when fence-matched.
    pub canonical_ref: Option<String>,
    /// Compatible ORS capture reference, when fence-matched.
    pub ors_ref: Option<String>,
    /// Lowercase SHA-256 over the ordered canonical entry bytes.
    pub content_digest: String,
}

impl WatchdogSpoolFence {
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
    /// Snapshot digest this page was read from (the fence content digest).
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

/// Builds the verbatim marker detail for coverage-invalidating records.
///
/// Heartbeats carry no marker (`None`): their payload bytes stay redacted.
/// `Gap` markers keep their exact reason and coverage flag; `Recovery`
/// records keep their exact reason and corrupt-sequence evidence; intents
/// keep their evidence digests and owner lineage.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when a recovery reason is blank or
/// oversized, or a corrupt digest is neither lowercase SHA-256 nor the
/// preserved `"missing"` literal.
fn marker_detail(payload: &WatchdogSpoolPayload) -> Result<Option<SpoolMarkerDetail>, SpoolError> {
    match payload {
        WatchdogSpoolPayload::Heartbeat { .. } => Ok(None),
        WatchdogSpoolPayload::Gap {
            reason,
            coverage_claimed,
            ..
        } => Ok(Some(SpoolMarkerDetail::Gap {
            reason: *reason,
            coverage_claimed: *coverage_claimed,
        })),
        WatchdogSpoolPayload::Recovery {
            reason,
            corrupt_sequence,
            corrupt_digest,
            ..
        } => {
            check_text(reason, "recovery reason", BACKUP_REASON_MAX_BYTES)?;
            if corrupt_digest != MISSING_DIGEST_LITERAL {
                check_digest(corrupt_digest, "recovery corrupt_digest")?;
            }
            Ok(Some(SpoolMarkerDetail::Recovery {
                reason: reason.clone(),
                corrupt_sequence: *corrupt_sequence,
                corrupt_digest: corrupt_digest.clone(),
            }))
        }
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
        } => Ok(Some(SpoolMarkerDetail::Intent {
            evidence_refs: evidence_refs.clone(),
            lineage_installation_id: lineage_installation_id.clone(),
            lineage_generation: *lineage_generation,
            lineage_epoch: *lineage_epoch,
            governor_unavailable_reason: *governor_unavailable_reason,
        })),
    }
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
    let mut content_bytes = Vec::new();
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
        content_bytes.extend_from_slice(&encode_entry(entry)?);
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
    // window can only ever understate freshness, never overstate it.
    let captured_at_ms = entries
        .last()
        .map(|entry| entry.observed_at_ms)
        .ok_or_else(|| {
            SpoolError::Corrupt(
                "watchdog spool backup capture covers no retained entries; a bare record vector is not a fence"
                    .to_owned(),
            )
        })?;
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
        content_digest: sha256_hex(&content_bytes),
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
/// The clock-dependent `page_ttl_ms` and `snapshot_lifetime_ms` bounds are not
/// decidable from fence data alone; they are enforced by the owner-bound
/// [`crate::WatchdogBackupPort::read_page`], which holds the owner clock and
/// the fence's [`WatchdogSpoolFence::captured_at_ms`] anchor.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the limits are unusable, the page
/// index runs past the retained window or past a cumulative bound, or a
/// bounded counter overflows.
pub fn read_page(
    fence: &WatchdogSpoolFence,
    page_index: u64,
    limits: &WatchdogSpoolBackupLimits,
) -> Result<WatchdogSpoolSnapshotPage, SpoolError> {
    fn corrupt(message: &str) -> SpoolError {
        SpoolError::Corrupt(message.to_owned())
    }
    limits.validate()?;
    let page_cap = u64::from(limits.max_page_members);
    let items_cap = u64::try_from(limits.max_items)
        .map_err(|_| corrupt("watchdog spool backup item bound exceeds the bounded counter"))?;
    let per_page = items_cap.min(page_cap);
    let total_members = u64::try_from(fence.entries.len())
        .map_err(|_| corrupt("watchdog spool backup retained count exceeds the bounded counter"))?;
    let start = page_index
        .checked_mul(per_page)
        .ok_or_else(|| corrupt("watchdog spool backup page index overflows the bounded window"))?;
    if start >= total_members {
        return Err(corrupt(
            "watchdog spool backup page runs past the retained window; continuation drift",
        ));
    }
    if start >= items_cap {
        return Err(corrupt(
            "watchdog spool backup page exceeds the cumulative member bound",
        ));
    }
    let start_idx = usize::try_from(start)
        .map_err(|_| corrupt("watchdog spool backup page offset exceeds the bounded window"))?;
    let page_cap_idx = usize::try_from(per_page)
        .map_err(|_| corrupt("watchdog spool backup page width exceeds the bounded window"))?;
    let mut end_idx = start_idx;
    let mut page_bytes = 0_u64;
    for entry in fence.entries.iter().skip(start_idx).take(page_cap_idx) {
        if end_idx > start_idx && page_bytes.saturating_add(entry.entry_bytes) > limits.max_bytes {
            break;
        }
        page_bytes = page_bytes
            .checked_add(entry.entry_bytes)
            .ok_or_else(|| corrupt("watchdog spool backup page byte counter overflow"))?;
        end_idx += 1;
    }
    let taken = end_idx
        .checked_sub(start_idx)
        .ok_or_else(|| corrupt("watchdog spool backup page window underflow"))?;
    let cumulative_members =
        start
            .checked_add(u64::try_from(taken).map_err(|_| {
                corrupt("watchdog spool backup page count exceeds the bounded counter")
            })?)
            .ok_or_else(|| corrupt("watchdog spool backup cumulative member counter overflow"))?;
    if cumulative_members > items_cap {
        return Err(corrupt(
            "watchdog spool backup page exceeds the cumulative member bound",
        ));
    }
    let mut cumulative_bytes = 0_u64;
    for entry in fence.entries.iter().take(end_idx) {
        cumulative_bytes = cumulative_bytes
            .checked_add(entry.entry_bytes)
            .ok_or_else(|| corrupt("watchdog spool backup cumulative byte counter overflow"))?;
    }
    if cumulative_bytes > limits.max_bytes {
        return Err(corrupt(
            "watchdog spool backup page exceeds the cumulative byte bound",
        ));
    }
    // The work ceiling is consulted, not only shape-validated: the members this
    // page examined must fit the admitted bounded work window.
    let examined = u64::try_from(end_idx)
        .map_err(|_| corrupt("watchdog spool backup page width exceeds the bounded counter"))?;
    if examined > limits.max_work_units {
        return Err(corrupt(
            "watchdog spool backup page exceeds the bounded work ceiling",
        ));
    }
    let mut digest_material = Vec::new();
    for entry in fence.entries.iter().skip(start_idx).take(taken) {
        digest_material.extend_from_slice(entry.entry_digest.as_bytes());
    }
    Ok(WatchdogSpoolSnapshotPage {
        snapshot_digest: fence.content_digest.clone(),
        page_index,
        page_digest: sha256_hex(&digest_material),
        entries: fence.entries[start_idx..end_idx].to_vec(),
        cumulative_members,
        cumulative_bytes,
        total_members,
        total_bytes: fence.total_bytes(),
        complete: end_idx
            == usize::try_from(total_members).map_err(|_| {
                corrupt("watchdog spool backup retained count exceeds the bounded window")
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
