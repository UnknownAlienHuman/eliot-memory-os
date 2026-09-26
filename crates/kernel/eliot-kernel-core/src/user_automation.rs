//! Kernel-owned UserAutomation contracts and deterministic admission.
//!
//! This module is the semantic owner of the first I11.12 automation boundary.
//! It describes immutable revision/configuration state and validates an
//! owner-issued preflight projection. It does not persist a revision, create a
//! scheduler, launch a process, call a provider, or issue a notification
//! receipt. Wake and execution values are typed projections of the existing
//! [`WakeIntent`] and Durable Job contracts; their owners remain responsible
//! for admission, persistence, execution and reconciliation.

use std::collections::BTreeSet;

use crate::user_automation_zones;

pub use eliot_config::ConfigPolicySnapshot;
use eliot_contracts::{
    ContractIdentity, ContractVersion, OperationId, PolicyRevision, RequestMetadata, StateFence,
    canonical_json_bytes, contract_identity, sha256_hex,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{JobOperationKind, JobState};
use eliot_receipts::ReceiptEnvelope;
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable contract name for the Kernel-owned UserAutomation domain.
pub const USER_AUTOMATION_CONTRACT_NAME: &str = "eliot.kernel.user-automation";
/// Current semantic contract revision.
pub const USER_AUTOMATION_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);
/// Selector used by authenticated Kernel/Host preflight reads.
pub const USER_AUTOMATION_PREFLIGHT_SELECTOR: &str = "eliot.config.user_automation.v1";
/// Operation marker used by the preflight read route.
pub const USER_AUTOMATION_PREFLIGHT_OPERATION: &str = "GetUserAutomationPreflightProjection";
/// Effect ceiling for the authenticated preflight route.
pub const USER_AUTOMATION_PREFLIGHT_EFFECT_CEILING: &str = "READ";
/// Fixed scope for the UserAutomation projection query.
pub const USER_AUTOMATION_SCOPE: &str = "user-automation";
/// Revision required by the deterministic preflight contract.
pub const USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION: &str = "eliot.user-automation.preflight.v1";
/// Canonical encoding of one owner-normalized calendar occurrence.
///
/// One occurrence key is the `|`-separated, fixed-arity record
///
/// ```text
/// <encoding>|<zone>|<zone database revision>|<local wall clock>|<offset>
///   |<resolved UTC instant>|<transition window>|<disposition>|<source digest>
/// ```
///
/// of exactly the owner evidence a replay needs. Every field has a closed
/// grammar, so a rejected value names a missing or malformed piece of evidence
/// instead of a string that merely resembles a timestamp. A local wall clock is
/// always accompanied by the instant the pinned zone revision resolved it to,
/// the offset that instant carries, the transition evidence that makes a fold or
/// gap reproducible, and the fold or gap disposition the owner applied. A
/// database revision therefore cannot silently re-resolve a stored occurrence:
/// it is part of the record, and of the occurrence identity derived from it.
///
/// The predecessor of this encoding was a local wall clock plus an offset with
/// none of that evidence. Such a record is a legacy, unverified input and is
/// refused with [`UserAutomationError::LegacyScheduleEncoding`], so it is never
/// silently certified under this stronger contract.
pub const NORMALIZED_OCCURRENCE_ENCODING: &str = "ELIOT/I11.12/OCCURRENCE/V2";
const OCCURRENCE_IDENTITY_DOMAIN: &str = "ELIOT/I11.12/USER-AUTOMATION-OCCURRENCE/V1";
const SCHEDULE_SOURCE_DIGEST_DOMAIN: &str = "ELIOT/I11.12/USER-AUTOMATION-SCHEDULE-SOURCE/V1";
const FAILURE_FINGERPRINT_DOMAIN: &str = "ELIOT/I11.12/USER-AUTOMATION-FAILURE/V1";
const WAKE_REASON_PREFIX: &str = "user-automation";
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_REFERENCES: usize = 256;

/// Errors returned by the pure UserAutomation contract boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationError {
    /// A required field has an invalid shape.
    #[error("invalid UserAutomation field: {0}")]
    Invalid(&'static str),
    /// A bounded list or text field exceeded its contract limit.
    #[error("UserAutomation field exceeds its bound: {0}")]
    LimitExceeded(&'static str),
    /// The canonical configuration snapshot is incomplete or invalid.
    #[error("canonical configuration snapshot is invalid: {0}")]
    Config(String),
    /// The owner-issued source receipt is invalid.
    #[error("owner-issued source receipt is invalid: {0}")]
    Receipt(String),
    /// The owner-issued receipt does not bind to the authenticated request.
    #[error("owner-issued source receipt is not bound to the authenticated request")]
    ReceiptBinding,
    /// The invocation and immutable revision disagree.
    #[error("UserAutomation invocation does not match its immutable revision")]
    RevisionMismatch,
    /// The invocation trigger does not identify the projected occurrence.
    #[error("UserAutomation occurrence identity mismatch")]
    OccurrenceMismatch,
    /// An owner projection omitted the failure data needed for a blocked result.
    #[error("blocked_config requires an owner-issued failure projection")]
    FailureProjectionMissing,
    /// An owner projection supplied a different failure fingerprint.
    #[error("owner-issued failure fingerprint is not the deterministic class fingerprint")]
    FailureFingerprintMismatch,
    /// A supersession does not form one immutable revision lineage.
    #[error("UserAutomation revision supersession is invalid")]
    InvalidSupersession,
    /// Canonical serialization failed while deriving an identity.
    #[error("UserAutomation canonical serialization failed: {0}")]
    Serialization(String),
    /// A normalized occurrence still carries the retired shape-only encoding.
    ///
    /// That encoding is a legacy, unverified input: it carries no zone
    /// identity, no pinned database revision, no resolved instant and no
    /// applied fold or gap disposition, so it is never certified under the
    /// versioned calendar contract. The owning calendar adapter must
    /// re-normalize it into a new revision.
    #[error("normalized occurrence is legacy shape-only and requires re-normalization: {0}")]
    LegacyScheduleEncoding(&'static str),
    /// The named zone is not a member of the pinned zone table.
    ///
    /// Zone admission is table membership, so a zone the pinned release does not
    /// define, a zone whose expansion could not be proven against an independent
    /// implementation, and a spelled pair that merely resembles a real one are
    /// all refused here. No zone is ever resolved from its spelling.
    ///
    /// A zone the pinned release does define, but whose pinned offsets cannot be
    /// stated exactly in this contract's canonical offset unit, is refused here as
    /// well rather than answered from a truncated offset. `Africa/Monrovia` is
    /// the one such zone in this release: it applied `-0:44:30` until 1972, and
    /// minutes cannot hold that value. The zone is reported here because from this
    /// boundary the two cases are the same answer: this contract has no
    /// minute-valued zone evidence to offer for it.
    #[error("normalized occurrence names a zone the pinned zone table does not carry: {0}")]
    UnknownZone(&'static str),
    /// The pinned zone database revision is not the one this build carries.
    ///
    /// A revision is refused rather than read from an ambient database, so a
    /// timezone database update cannot silently rewrite an existing revision.
    #[error("pinned zone database revision is not the revision this build carries: {0}")]
    ZoneDatabaseRevision(&'static str),
    /// The occurrence instant lies outside the pinned table's closed window.
    ///
    /// The window is never extrapolated: an occurrence beyond it is refused with
    /// the window in the payload rather than resolved from a guess.
    #[error("occurrence instant is outside the pinned zone table window {window}: {field}")]
    ZoneTableWindow {
        /// The field that carried the out-of-window instant.
        field: &'static str,
        /// The closed window this build admits, as an ISO-8601 interval.
        window: &'static str,
    },
    /// The embedded zone table failed its pinned digest or structure check.
    ///
    /// Every zone lookup fails closed rather than answer from bytes that are not
    /// the pinned release.
    #[error("the pinned zone table failed its integrity check and every zone lookup is refused")]
    ZoneTableIntegrity,
    /// The recorded zone evidence is not what the pinned table applies.
    ///
    /// The offset, the local wall clock, the transition evidence and the applied
    /// disposition of an occurrence must all be what the named zone actually
    /// applies at the recorded instant. This is what proves that a recorded
    /// offset is one the named zone applies at that local wall clock.
    #[error("occurrence evidence is not what the pinned zone table applies: {0}")]
    ZoneEvidence(&'static str),
}

/// Execution mode admitted by an immutable revision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationExecutionMode {
    /// Normal admitted task/model path; model access is still gated by the
    /// resulting preflight receipt and the existing route owners.
    Agent,
    /// Qualified process path with a capability profile that excludes model
    /// and provider access.
    DeterministicProcess,
}

/// Configuration state of an immutable UserAutomation revision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationConfigurationState {
    /// Future occurrences may be admitted after successful preflight.
    Active,
    /// Future occurrences are deferred while admitted execution is preserved.
    Paused,
    /// The revision is retained but its configuration cannot be admitted.
    BlockedConfig,
    /// The revision is tombstoned; history and reconciliation remain visible.
    Retired,
}

/// One-shot versus recurring normalized schedule.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScheduleKind {
    /// Exactly one owner-normalized calendar occurrence.
    OneShot,
    /// A recurring owner-normalized calendar expression.
    Recurring,
}

/// Policy for an ambiguous local-time fold during DST conversion.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DstFoldPolicy {
    /// Choose the first offset in the fold.
    First,
    /// Choose the second offset in the fold.
    Second,
    /// Reject the ambiguous occurrence and block admission.
    Reject,
}

/// Policy for a nonexistent local time during a DST gap.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DstGapPolicy {
    /// Shift to the next valid instant using the owner-normalized rule.
    ShiftForward,
    /// Reject the nonexistent occurrence and block admission.
    Reject,
}

/// Immutable normalized schedule and bounded next-occurrence projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedSchedule {
    /// One-shot or recurring schedule kind.
    pub kind: ScheduleKind,
    /// Owner-normalized expression, never a caller reparse hint.
    pub expression: String,
    /// Owner-normalized calendar identifier.
    pub calendar: String,
    /// IANA or platform owner-normalized timezone identifier.
    pub timezone: String,
    /// Fold handling for ambiguous local times.
    pub dst_fold: DstFoldPolicy,
    /// Gap handling for nonexistent local times.
    pub dst_gap: DstGapPolicy,
    /// Inclusive owner-normalized start instant.
    pub start_at: String,
    /// Optional inclusive owner-normalized end instant.
    pub end_at: Option<String>,
    /// Bounded, chronologically ordered owner-normalized occurrences in the
    /// [`NORMALIZED_OCCURRENCE_ENCODING`] encoding.
    pub next_occurrences: Vec<String>,
}

impl NormalizedSchedule {
    /// Validates the schedule shape without interpreting calendar semantics.
    ///
    /// Shape validation stays calendar-blind on purpose: the owner-normalized
    /// occurrence set is the trigger contract, and
    /// [`Self::validate_normalized_occurrences`] performs the deterministic
    /// calendar, timezone, DST, interval and chronological interpretation over
    /// exactly that set. No two instants are compared as text here, because `+`
    /// sorts before `Z` and a lexical order of mixed offsets is not a
    /// chronological one.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.expression, "schedule.expression")?;
        text(&self.calendar, "schedule.calendar")?;
        text(&self.timezone, "schedule.timezone")?;
        text(&self.start_at, "schedule.start_at")?;
        if let Some(end_at) = &self.end_at {
            text(end_at, "schedule.end_at")?;
        }
        if self.next_occurrences.is_empty() {
            return Err(UserAutomationError::Invalid("schedule.next_occurrences"));
        }
        list_text(&self.next_occurrences, "schedule.next_occurrences")?;
        if self.kind == ScheduleKind::OneShot && self.next_occurrences.len() != 1 {
            return Err(UserAutomationError::Invalid(
                "schedule.one_shot_occurrences",
            ));
        }
        Ok(())
    }

    /// Validates the declared timezone identifier without guessing one.
    ///
    /// Only identities that are members of the pinned zone table are admitted.
    /// A zone that release does not define, a zone whose expansion could not be
    /// proven against an independent implementation, and a spelled pair that
    /// merely resembles a real one are all refused identically, and none is
    /// resolved to a nearest match. The occurrence set must additionally pin the
    /// database revision the owner normalized against, so an ambiguous calendar
    /// phrase is never guessed and an ambient machine locale is never used.
    pub fn validate_timezone(&self) -> Result<(), UserAutomationError> {
        if self.timezone.trim() != self.timezone || !is_canonical_zone_identity(&self.timezone) {
            return Err(UserAutomationError::Invalid("schedule.timezone.canonical"));
        }
        Ok(())
    }

    /// Returns the immutable compiled digest binding this occurrence projection
    /// to its declared expression and calendar.
    ///
    /// The expression language is owned elsewhere, so Kernel never reparses it.
    /// The owner compiles the expression once and every occurrence of the
    /// projection carries this digest, so an occurrence that is not the next
    /// result of the declared expression and calendar fails closed instead of
    /// being presented as their projection.
    pub fn source_digest(&self) -> Result<String, UserAutomationError> {
        let bytes = canonical_json_bytes(&(
            SCHEDULE_SOURCE_DIGEST_DOMAIN,
            &self.expression,
            &self.calendar,
        ))
        .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns the decoded owner-issued occurrence set in validated
    /// chronological order.
    ///
    /// The set is the single normalized occurrence contract. Each member
    /// carries the canonical zone identity, the pinned zone database revision,
    /// the range-checked local civil datetime, the resolved UTC instant and
    /// applied offset, the applied fold or gap disposition, and the compiled
    /// source digest. Every member must resolve to exactly the instant its
    /// disposition and applied offset select, lie inside the declared start and
    /// end interval, and be strictly later than its predecessor: a duplicate
    /// instant cannot occupy two positions, and the two distinct instants of a
    /// fold remain two distinct occurrences instead of colliding.
    pub fn normalized_occurrences(&self) -> Result<Vec<NormalizedOccurrence>, UserAutomationError> {
        self.validate()?;
        self.validate_timezone()?;
        let source_digest = self.source_digest()?;
        let start = parse_civil_instant(&self.start_at, "schedule.start_at")?;
        let end = self
            .end_at
            .as_deref()
            .map(|end_at| parse_civil_instant(end_at, "schedule.end_at"))
            .transpose()?;
        if end.is_some_and(|end| end < start) {
            return Err(UserAutomationError::Invalid("schedule.end_at"));
        }
        let mut pinned_database_revision: Option<String> = None;
        let mut previous_instant: Option<i64> = None;
        let mut occurrences = Vec::with_capacity(self.next_occurrences.len());
        for occurrence_key in &self.next_occurrences {
            let occurrence = self.parse_occurrence(occurrence_key, &source_digest)?;
            match &pinned_database_revision {
                Some(revision) if *revision != occurrence.zone_database_revision => {
                    return Err(UserAutomationError::Invalid(
                        "schedule.next_occurrences.zone_database_revision",
                    ));
                }
                Some(_) => {}
                None => pinned_database_revision = Some(occurrence.zone_database_revision.clone()),
            }
            if occurrence.instant_seconds < start
                || end.is_some_and(|end| occurrence.instant_seconds > end)
            {
                return Err(UserAutomationError::Invalid(
                    "schedule.next_occurrences.interval",
                ));
            }
            match previous_instant {
                Some(previous) if occurrence.instant_seconds == previous => {
                    return Err(UserAutomationError::Invalid(
                        "schedule.next_occurrences.duplicate_instant",
                    ));
                }
                Some(previous) if occurrence.instant_seconds < previous => {
                    return Err(UserAutomationError::Invalid(
                        "schedule.next_occurrences.order",
                    ));
                }
                _ => {}
            }
            previous_instant = Some(occurrence.instant_seconds);
            occurrences.push(occurrence);
        }
        Ok(occurrences)
    }

    /// Interprets the owner-normalized occurrence set deterministically.
    ///
    /// This is the deterministic calendar interpretation of exactly that set:
    /// the declared zone identity, the pinned zone database revision, the civil
    /// local datetimes, the UTC offsets, the resolved instants, the applied
    /// fold and gap dispositions, the compiled source digest, the start and end
    /// interval, and the chronological order. It admits no occurrence it cannot
    /// derive from the owner-issued evidence and it never resolves a zone, reads
    /// a time zone database, or consults an ambient clock or locale.
    ///
    /// This is a schedule check only. Principal, `WorkScope`, State Fence,
    /// preflight, overlap and reconciliation remain separate admission checks
    /// over a valid occurrence, so a valid occurrence is still not a wake.
    pub fn validate_normalized_occurrences(&self) -> Result<(), UserAutomationError> {
        self.normalized_occurrences()?;
        Ok(())
    }

    /// Returns whether one calendar occurrence belongs to this revision's
    /// owner-normalized occurrence set.
    ///
    /// The supplied key is validated under the same versioned contract as the
    /// stored set, so an occurrence outside it is neither resolved, shifted, nor
    /// folded into a neighbour: the caller fails closed.
    pub fn contains_occurrence(&self, occurrence_key: &str) -> Result<bool, UserAutomationError> {
        self.validate_timezone()?;
        self.parse_occurrence(occurrence_key, &self.source_digest()?)?;
        Ok(self
            .next_occurrences
            .iter()
            .any(|key| key == occurrence_key))
    }

    /// Returns the deterministic successor of one normalized occurrence.
    ///
    /// The successor is the next member of the validated chronological
    /// projection, so re-spelling a member's text cannot move it in the chain.
    /// `None` means the occurrence is the last retained member of this
    /// revision's projection; a caller never invents a later occurrence.
    pub fn next_occurrence_after(
        &self,
        occurrence_key: &str,
    ) -> Result<Option<String>, UserAutomationError> {
        self.parse_occurrence(occurrence_key, &self.source_digest()?)?;
        self.validate_normalized_occurrences()?;
        Ok(self
            .next_occurrences
            .iter()
            .skip_while(|key| key.as_str() != occurrence_key)
            .nth(1)
            .cloned())
    }

    /// Parses and validates one occurrence key against this schedule's declared
    /// zone, fold and gap policies, and compiled source digest.
    fn parse_occurrence(
        &self,
        occurrence_key: &str,
        source_digest: &str,
    ) -> Result<NormalizedOccurrence, UserAutomationError> {
        if occurrence_key.len() > MAX_OCCURRENCE_KEY_BYTES {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.shape",
            ));
        }
        let fields: Vec<&str> = occurrence_key
            .split(NORMALIZED_OCCURRENCE_FIELD_SEPARATOR)
            .collect();
        if fields.len() != NORMALIZED_OCCURRENCE_FIELD_COUNT {
            return Err(if is_legacy_occurrence_key(occurrence_key) {
                UserAutomationError::LegacyScheduleEncoding("schedule.next_occurrences")
            } else {
                UserAutomationError::Invalid("schedule.occurrence_key.shape")
            });
        }
        if fields[0] != NORMALIZED_OCCURRENCE_ENCODING {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.encoding",
            ));
        }
        if fields[1] != self.timezone {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.timezone",
            ));
        }
        if !is_canonical_zone_database_revision(fields[2]) {
            return Err(UserAutomationError::ZoneDatabaseRevision(
                "schedule.occurrence_key.zone_database_revision",
            ));
        }
        if fields[8] != source_digest {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.source_digest",
            ));
        }
        let disposition =
            parse_occurrence_disposition(fields[7], "schedule.occurrence_key.disposition")?;
        require_declared_disposition(disposition, self.dst_fold, self.dst_gap)?;
        let local = parse_civil_wall_clock(fields[3], "schedule.occurrence_key.local")?;
        let offset_minutes = parse_utc_offset(fields[4], "schedule.occurrence_key.offset")?;
        let instant_seconds = parse_utc_instant(fields[5], "schedule.occurrence_key.instant")?;
        let transition =
            parse_transition_window(fields[6], disposition, "schedule.occurrence_key.transition")?;
        require_resolved_instant(
            local,
            offset_minutes,
            disposition,
            transition,
            instant_seconds,
        )?;
        require_pinned_zone_evidence(
            &self.timezone,
            local.unix_seconds(),
            offset_minutes,
            instant_seconds,
            disposition,
            transition,
        )?;
        Ok(NormalizedOccurrence {
            timezone: self.timezone.clone(),
            zone_database_revision: fields[2].to_owned(),
            local: fields[3].to_owned(),
            offset_minutes,
            instant_seconds,
            disposition,
            source_digest: fields[8].to_owned(),
        })
    }
}

/// Fold or gap disposition the calendar owner applied to one normalized
/// occurrence.
///
/// The disposition is owner-issued evidence recorded with the occurrence, not
/// a value Kernel re-derives: inspection and replay therefore never read a time
/// zone database again. A `DstFoldPolicy::Reject` or `DstGapPolicy::Reject`
/// schedule produces no disposition here, because the owner must refuse the
/// ambiguous or nonexistent local time instead of normalizing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccurrenceDisposition {
    /// The local wall clock exists exactly once in the pinned zone revision.
    Unique,
    /// The local wall clock occurs twice and the earlier instant was applied.
    FoldFirst,
    /// The local wall clock occurs twice and the later instant was applied.
    FoldSecond,
    /// The local wall clock does not exist and was shifted forward to the first
    /// existing instant.
    GapShiftForward,
}

/// One decoded owner-issued normalized calendar occurrence.
///
/// This is the whole normalized occurrence contract of one bounded projection
/// member: the canonical zone identity and the pinned zone database revision
/// the owner normalized against, the valid local civil datetime, the resolved
/// UTC instant and the applied offset, the applied fold or gap disposition, and
/// the immutable compiled digest of the source expression and calendar. Kernel
/// validates this evidence; it never resolves a zone, reads a time zone
/// database, or reads the ambient machine locale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedOccurrence {
    /// Canonical owner-normalized zone identity.
    pub timezone: String,
    /// Pinned versioned zone database or platform-owner revision token.
    pub zone_database_revision: String,
    /// Valid local civil wall clock in `timezone`.
    pub local: String,
    /// Applied UTC offset in signed minutes east of UTC.
    pub offset_minutes: i32,
    /// Resolved UTC instant in seconds since the Unix epoch.
    pub instant_seconds: i64,
    /// Applied fold or gap disposition.
    pub disposition: OccurrenceDisposition,
    /// Immutable compiled digest of the source expression and calendar.
    pub source_digest: String,
}

/// Separator between the fields of one normalized occurrence key. No field may
/// contain it, so the record is unambiguously position-addressable.
const NORMALIZED_OCCURRENCE_FIELD_SEPARATOR: char = '|';
/// Fixed number of fields in one normalized occurrence key.
const NORMALIZED_OCCURRENCE_FIELD_COUNT: usize = 9;
/// Longest accepted normalized occurrence key. The encoding is a fixed record
/// of short tokens, so a longer value is refused before it is split.
const MAX_OCCURRENCE_KEY_BYTES: usize = 1024;
/// Byte length of the canonical local wall clock `YYYY-MM-DDTHH:MM:SS`.
const CIVIL_WALL_CLOCK_BYTES: usize = 19;
/// Byte length of a canonical resolved UTC instant `YYYY-MM-DDTHH:MM:SSZ`.
const UTC_INSTANT_BYTES: usize = CIVIL_WALL_CLOCK_BYTES + 1;
/// Byte length of a canonical UTC offset `+HH:MM` or `-HH:MM`.
const UTC_OFFSET_BYTES: usize = 6;
/// Seconds in one civil day.
const SECONDS_PER_DAY: i64 = 86_400;
/// Seconds in one civil hour.
const SECONDS_PER_HOUR: i64 = 3_600;
/// Seconds in one civil minute.
const SECONDS_PER_MINUTE: i64 = 60;
/// Earliest civil year this contract normalizes. Year one keeps the absolute
/// instant arithmetic below exact, and no automation occurrence is normalized
/// before the Unix epoch.
const MIN_CIVIL_YEAR: u32 = 1;
/// Latest civil year this contract normalizes: the four digit range.
const MAX_CIVIL_YEAR: u32 = 9999;
/// Days from 0000-03-01 to 1970-01-01 in the proleptic Gregorian calendar.
const CIVIL_EPOCH_DAY_OFFSET: i64 = 719_468;
/// Days in one 400 year era of the proleptic Gregorian calendar.
const DAYS_PER_CIVIL_ERA: i64 = 146_097;
/// Largest civil UTC offset east of UTC in the time zone database, fourteen
/// hours, so a larger spelled offset names no instant.
const MAX_CIVIL_UTC_OFFSET_MINUTES: u32 = 14 * 60;
/// Largest civil offset step one zone transition may apply. The database
/// contains a whole skipped civil day, so the bound is one full day rather than
/// one hour.
const MAX_TRANSITION_STEP_MINUTES: u32 = 24 * 60;
/// Longest accepted zone identity.
const MAX_ZONE_IDENTITY_BYTES: usize = 64;
/// Longest accepted pinned zone database revision token.
const MAX_ZONE_DATABASE_REVISION_BYTES: usize = 64;
/// The closed window the pinned zone table admits, as an ISO-8601 interval.
///
/// An occurrence instant outside it is refused with this window in the payload
/// rather than resolved by extrapolating the table's stored timeline.
const ZONE_TABLE_WINDOW_ISO: &str = "[1970-01-01T00:00:00Z, 2100-01-01T00:00:00Z)";

/// One range-checked proleptic Gregorian civil date and time of day.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CivilDateTime {
    /// Proleptic Gregorian year.
    year: u32,
    /// Month of the year, `1..=12`.
    month: u32,
    /// Day of the month, nonzero and within the month.
    day: u32,
    /// Hour of the day, `0..=23`.
    hour: u32,
    /// Minute of the hour, `0..=59`.
    minute: u32,
    /// Second of the minute, `0..=59`.
    second: u32,
}

impl CivilDateTime {
    /// Absolute seconds since the Unix epoch for this civil wall clock read as
    /// UTC.
    ///
    /// A zone offset is applied by the caller, so the same civil value in two
    /// zones yields two instants by arithmetic alone and no ambient clock is
    /// ever read.
    fn unix_seconds(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * SECONDS_PER_DAY
            + i64::from(self.hour) * SECONDS_PER_HOUR
            + i64::from(self.minute) * SECONDS_PER_MINUTE
            + i64::from(self.second)
    }
}

/// Days from 1970-01-01 to one proleptic Gregorian civil date.
///
/// This is the closed domain `days_from_civil` decomposition of the civil
/// calendar. It reads no clock, locale, or calendar database, so two processes
/// always agree on the chronological order of a normalized occurrence. The
/// caller range-checks the date to [`MIN_CIVIL_YEAR`]..=[`MAX_CIVIL_YEAR`], the
/// domain in which the era decomposition below is exact.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let year = i64::from(year);
    let (shifted_year, shifted_month) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    let era = shifted_year / 400;
    let year_of_era = shifted_year - era * 400;
    let month_position = i64::from(shifted_month) - 3;
    let day_of_year = (153 * month_position + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_PER_CIVIL_ERA + day_of_era - CIVIL_EPOCH_DAY_OFFSET
}

/// Returns whether one proleptic Gregorian year is a leap year.
fn is_civil_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Returns the number of days in one proleptic Gregorian month, honouring the
/// leap day.
fn days_in_civil_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_civil_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Returns whether a canonical numeric field spells a decimal digit at `index`.
fn is_decimal_digit(value: &str, index: usize) -> bool {
    value.as_bytes()[index].is_ascii_digit()
}

/// Reads the two decimal digits at `start` of a validated canonical field.
fn decimal_pair(value: &str, start: usize) -> u32 {
    u32::from(value.as_bytes()[start] - b'0') * 10 + u32::from(value.as_bytes()[start + 1] - b'0')
}

/// Reads the four decimal digits at the start of a validated canonical field.
fn decimal_quad(value: &str) -> u32 {
    decimal_pair(value, 0) * 100 + decimal_pair(value, 2)
}

/// Parses one canonical local wall clock `YYYY-MM-DDTHH:MM:SS`.
///
/// The value is range-checked against the proleptic Gregorian calendar,
/// including leap days and the closed year range, instead of being accepted
/// because its bytes look like a date. Fractional seconds, a lower case `t`,
/// and a leap second are refused: only the canonical spelling of an exact civil
/// second is an owner-normalized value.
fn parse_civil_wall_clock(
    value: &str,
    field: &'static str,
) -> Result<CivilDateTime, UserAutomationError> {
    let bytes = value.as_bytes();
    let canonical = bytes.len() == CIVIL_WALL_CLOCK_BYTES
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            _ => byte.is_ascii_digit(),
        });
    if !canonical {
        return Err(UserAutomationError::Invalid(field));
    }
    let year = decimal_quad(value);
    let month = decimal_pair(value, 5);
    let day = decimal_pair(value, 8);
    let hour = decimal_pair(value, 11);
    let minute = decimal_pair(value, 14);
    let second = decimal_pair(value, 17);
    if !(MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_civil_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(UserAutomationError::Invalid(field));
    }
    Ok(CivilDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

/// Parses one canonical UTC offset `+HH:MM` or `-HH:MM` as signed minutes east
/// of UTC.
///
/// The offset is range-checked against the largest civil offset the time zone
/// database contains, so `+99`, a minute field above `59`, and a negative zero
/// offset are refused instead of being admitted as a spelled offset that names
/// no instant.
fn parse_utc_offset(value: &str, field: &'static str) -> Result<i32, UserAutomationError> {
    let bytes = value.as_bytes();
    let canonical = bytes.len() == UTC_OFFSET_BYTES
        && matches!(bytes[0], b'+' | b'-')
        && bytes[3] == b':'
        && is_decimal_digit(value, 1)
        && is_decimal_digit(value, 2)
        && is_decimal_digit(value, 4)
        && is_decimal_digit(value, 5);
    if !canonical {
        return Err(UserAutomationError::Invalid(field));
    }
    let hours = decimal_pair(value, 1);
    let minutes = decimal_pair(value, 4);
    if hours > 23 || minutes > 59 {
        return Err(UserAutomationError::Invalid(field));
    }
    let total_minutes = hours * 60 + minutes;
    if (total_minutes == 0 && bytes[0] == b'-') || total_minutes > MAX_CIVIL_UTC_OFFSET_MINUTES {
        return Err(UserAutomationError::Invalid(field));
    }
    let total_minutes =
        i32::try_from(total_minutes).map_err(|_| UserAutomationError::Invalid(field))?;
    Ok(if bytes[0] == b'+' {
        total_minutes
    } else {
        -total_minutes
    })
}

/// Parses the resolved UTC instant field of one occurrence record.
///
/// The canonical spelling is the civil UTC value with a `Z` suffix, so one
/// instant always has exactly one byte representation.
fn parse_utc_instant(value: &str, field: &'static str) -> Result<i64, UserAutomationError> {
    if value.len() != UTC_INSTANT_BYTES || !value.ends_with('Z') {
        return Err(UserAutomationError::Invalid(field));
    }
    Ok(parse_civil_wall_clock(&value[..CIVIL_WALL_CLOCK_BYTES], field)?.unix_seconds())
}

/// Parses one owner-normalized RFC 3339 instant as absolute seconds.
///
/// `start_at` and `end_at` are instants rather than wall clocks, so the offset
/// is applied here: `2026-01-01T00:00:00+14:00` is correctly later than
/// `2026-01-01T00:00:00Z` even though it sorts before it as text.
fn parse_civil_instant(value: &str, field: &'static str) -> Result<i64, UserAutomationError> {
    if value.len() < CIVIL_WALL_CLOCK_BYTES + 1 {
        return Err(UserAutomationError::Invalid(field));
    }
    let civil = parse_civil_wall_clock(&value[..CIVIL_WALL_CLOCK_BYTES], field)?;
    let offset = &value[CIVIL_WALL_CLOCK_BYTES..];
    let offset_minutes = if offset == "Z" {
        0
    } else {
        parse_utc_offset(offset, field)?
    };
    Ok(civil.unix_seconds() - i64::from(offset_minutes) * SECONDS_PER_MINUTE)
}

/// Parses the applied fold or gap disposition field of one occurrence record.
fn parse_occurrence_disposition(
    value: &str,
    field: &'static str,
) -> Result<OccurrenceDisposition, UserAutomationError> {
    match value {
        "UNIQUE" => Ok(OccurrenceDisposition::Unique),
        "FOLD_FIRST" => Ok(OccurrenceDisposition::FoldFirst),
        "FOLD_SECOND" => Ok(OccurrenceDisposition::FoldSecond),
        "GAP_SHIFT_FORWARD" => Ok(OccurrenceDisposition::GapShiftForward),
        _ => Err(UserAutomationError::Invalid(field)),
    }
}

/// Parses the owner-carried transition evidence of one fold or gap occurrence.
///
/// A unique occurrence carries `-`: its local wall clock exists once, so there
/// is no transition to reproduce. A fold or a gap carries the offsets the pinned
/// zone revision applies immediately before and after the transition, joined by
/// `~`. That pair is the exact evidence a replay needs to re-derive the applied
/// offset without reading a time zone database again, and
/// [`require_pinned_zone_evidence`] is what turns it into proof: it checks both
/// boundaries against the transitions the pinned table actually holds between
/// the two instants, so a recorded offset that the named zone does not apply at
/// that local wall clock is refused.
fn parse_transition_window(
    value: &str,
    disposition: OccurrenceDisposition,
    field: &'static str,
) -> Result<Option<(i32, i32)>, UserAutomationError> {
    if disposition == OccurrenceDisposition::Unique {
        return if value == "-" {
            Ok(None)
        } else {
            Err(UserAutomationError::Invalid(field))
        };
    }
    let Some((before, after)) = value.split_once('~') else {
        return Err(UserAutomationError::Invalid(field));
    };
    let pre = parse_utc_offset(before, field)?;
    let post = parse_utc_offset(after, field)?;
    let step = pre.abs_diff(post);
    if step == 0 || step > MAX_TRANSITION_STEP_MINUTES {
        return Err(UserAutomationError::Invalid(field));
    }
    Ok(Some((pre, post)))
}

/// Requires the recorded disposition to be the one the declared fold and gap
/// policies admit.
///
/// A `Reject` policy produces no normalized occurrence: the owner must refuse the
/// ambiguous or nonexistent local time instead of selecting a disposition for
/// it. A `Reject` schedule therefore never carries a fold or gap member, and a
/// `First` or `Second` schedule never silently carries the other side of a fold.
fn require_declared_disposition(
    disposition: OccurrenceDisposition,
    dst_fold: DstFoldPolicy,
    dst_gap: DstGapPolicy,
) -> Result<(), UserAutomationError> {
    let admitted = match disposition {
        OccurrenceDisposition::Unique => true,
        OccurrenceDisposition::FoldFirst => dst_fold == DstFoldPolicy::First,
        OccurrenceDisposition::FoldSecond => dst_fold == DstFoldPolicy::Second,
        OccurrenceDisposition::GapShiftForward => dst_gap == DstGapPolicy::ShiftForward,
    };
    if admitted {
        Ok(())
    } else {
        Err(UserAutomationError::Invalid(
            "schedule.occurrence_key.disposition",
        ))
    }
}

/// Requires the recorded instant to be exactly the one the applied disposition
/// selects for the recorded local wall clock and applied offset.
///
/// For a unique local wall clock the recorded offset is the only offset the
/// pinned zone revision applies, so the instant must be `local - offset`. For a
/// fold the zone applies the pre transition offset to the earlier instant and
/// the post transition offset to the later one, so `FIRST` must carry the pre
/// transition offset and resolve to `local - pre`, and `SECOND` must carry the
/// post transition offset and resolve to `local - post`. For a gap the local
/// wall clock does not exist, so the owner shifts it forward by the transition
/// step: the applied offset is the post transition offset and the instant is
/// `local + step - post`, which is the same value as `local - pre`.
///
/// An occurrence whose recorded offset is neither side of the recorded
/// transition, or whose instant does not round-trip through its own offset, is
/// refused. Kernel resolves nothing: it refuses evidence that is not
/// self-consistent.
fn require_resolved_instant(
    local: CivilDateTime,
    offset_minutes: i32,
    disposition: OccurrenceDisposition,
    transition: Option<(i32, i32)>,
    instant_seconds: i64,
) -> Result<(), UserAutomationError> {
    let applied = match (disposition, transition) {
        (OccurrenceDisposition::Unique, None) => offset_minutes,
        (OccurrenceDisposition::FoldFirst, Some((pre, post)))
            if pre > post && offset_minutes == pre =>
        {
            pre
        }
        (OccurrenceDisposition::FoldSecond, Some((pre, post)))
            if pre > post && offset_minutes == post =>
        {
            post
        }
        (OccurrenceDisposition::GapShiftForward, Some((pre, post)))
            if pre < post && offset_minutes == post =>
        {
            pre
        }
        _ => {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.transition",
            ));
        }
    };
    if local.unix_seconds() - i64::from(applied) * SECONDS_PER_MINUTE != instant_seconds {
        return Err(UserAutomationError::Invalid(
            "schedule.occurrence_key.instant",
        ));
    }
    Ok(())
}

/// Requires the recorded zone evidence to be what the pinned table applies.
///
/// The owner asserts a zone, a local wall clock, an offset, an instant, a
/// transition pair and a disposition. This is where Kernel decides whether that
/// assertion is true, by reading the offsets and transitions of the named zone
/// out of the pinned table. Nothing is taken on the owner's spelling and nothing
/// is read from an ambient database, so the recorded disposition stays
/// inspectable and replayable while the decision that admitted it is Kernel's.
///
/// Given the recorded `(zone, local, offset, instant, transition, disposition)`:
///
/// 1. the zone must be a member of the pinned table and the revision must be the
///    pinned one, which the caller has already established;
/// 2. the offset the zone applies at the recorded instant must equal the recorded
///    offset, which alone refuses an in-range offset that merely round-trips
///    through its own instant;
/// 3. the recorded local wall clock must equal the recorded instant rendered in
///    the offset the zone applies at that instant;
/// 4. what the local wall clock actually is decides the disposition: a unique
///    clock admits only `UNIQUE` and needs no transition, a fold admits only
///    `FOLD_FIRST` or `FOLD_SECOND` and must select the earlier or later of
///    exactly the two instants the table resolves it to, and a gap admits only
///    `GAP_SHIFT_FORWARD` and must land on the table's real post-transition
///    instant;
/// 5. when a transition pair is recorded, both of its boundaries must equal the
///    offsets the table actually applies on either side of the transition it
///    names.
fn require_pinned_zone_evidence(
    zone: &str,
    claimed_local_unix_seconds: i64,
    claimed_offset_minutes: i32,
    claimed_instant_seconds: i64,
    disposition: OccurrenceDisposition,
    transition: Option<(i32, i32)>,
) -> Result<(), UserAutomationError> {
    if !(user_automation_zones::ZONE_TABLE_WINDOW_START_SECONDS
        ..user_automation_zones::ZONE_TABLE_WINDOW_END_EXCLUSIVE_SECONDS)
        .contains(&claimed_instant_seconds)
    {
        return Err(UserAutomationError::ZoneTableWindow {
            field: "schedule.occurrence_key.instant",
            window: ZONE_TABLE_WINDOW_ISO,
        });
    }
    let applied = user_automation_zones::offset_minutes_at(zone, claimed_instant_seconds)
        .map_err(|error| map_zone_error(error, "schedule.occurrence_key.zone"))?;
    if applied != claimed_offset_minutes {
        return Err(UserAutomationError::ZoneEvidence(
            "schedule.occurrence_key.offset",
        ));
    }
    if claimed_local_unix_seconds
        != claimed_instant_seconds + i64::from(applied) * SECONDS_PER_MINUTE
    {
        return Err(UserAutomationError::ZoneEvidence(
            "schedule.occurrence_key.local",
        ));
    }
    let reality = user_automation_zones::classify_local_clock(zone, claimed_local_unix_seconds)
        .map_err(|error| map_zone_error(error, "schedule.occurrence_key.zone"))?;
    let disagree = || UserAutomationError::ZoneEvidence("schedule.occurrence_key.disposition");
    let real_transition = match (disposition, reality) {
        (
            OccurrenceDisposition::Unique,
            user_automation_zones::LocalClockReality::Unique {
                instant_seconds,
                offset_minutes,
            },
        ) => {
            if instant_seconds != claimed_instant_seconds || offset_minutes != applied {
                return Err(disagree());
            }
            return require_absent_transition(transition);
        }
        (
            OccurrenceDisposition::FoldFirst,
            user_automation_zones::LocalClockReality::Fold {
                first_instant_seconds,
                first_offset_minutes,
                transition: real,
                ..
            },
        ) => {
            if first_instant_seconds != claimed_instant_seconds || first_offset_minutes != applied {
                return Err(disagree());
            }
            real
        }
        (
            OccurrenceDisposition::FoldSecond,
            user_automation_zones::LocalClockReality::Fold {
                second_instant_seconds,
                second_offset_minutes,
                transition: real,
                ..
            },
        ) => {
            if second_instant_seconds != claimed_instant_seconds || second_offset_minutes != applied
            {
                return Err(disagree());
            }
            real
        }
        (
            OccurrenceDisposition::GapShiftForward,
            user_automation_zones::LocalClockReality::Gap {
                transition: real,
                resolved_instant_seconds,
                post_offset_minutes,
                ..
            },
        ) => {
            if resolved_instant_seconds != claimed_instant_seconds || post_offset_minutes != applied
            {
                return Err(disagree());
            }
            real
        }
        _ => return Err(disagree()),
    };
    let Some((pre, post)) = transition else {
        return Err(UserAutomationError::ZoneEvidence(
            "schedule.occurrence_key.transition",
        ));
    };
    if pre != real_transition.pre_offset_minutes || post != real_transition.post_offset_minutes {
        return Err(UserAutomationError::ZoneEvidence(
            "schedule.occurrence_key.transition",
        ));
    }
    Ok(())
}

/// Requires that a unique occurrence records no transition pair.
fn require_absent_transition(transition: Option<(i32, i32)>) -> Result<(), UserAutomationError> {
    if transition.is_some() {
        return Err(UserAutomationError::ZoneEvidence(
            "schedule.occurrence_key.transition",
        ));
    }
    Ok(())
}

/// Maps one zone-table failure onto its typed contract refusal.
fn map_zone_error(
    error: user_automation_zones::ZoneTableError,
    field: &'static str,
) -> UserAutomationError {
    match error {
        user_automation_zones::ZoneTableError::Integrity => UserAutomationError::ZoneTableIntegrity,
        user_automation_zones::ZoneTableError::UnknownZone
        | user_automation_zones::ZoneTableError::SubMinuteOffset(_) => {
            UserAutomationError::UnknownZone(field)
        }
        user_automation_zones::ZoneTableError::OutsideCoverage => {
            UserAutomationError::ZoneTableWindow {
                field: "schedule.occurrence_key.instant",
                window: ZONE_TABLE_WINDOW_ISO,
            }
        }
    }
}

/// Returns whether one zone identity is a member of the pinned zone table.
///
/// Zone admission is table membership and nothing else. The table is generated
/// from one pinned release of the IANA database and carries every name that
/// release defines, plus every backward-compatible alias, and it carries only
/// the names an independent implementation of the same data confirmed. So a
/// spelled pair that names no database zone is refused, and so is a name that
/// merely resembles one: `America/Nowhere_City` and `Foo/Bar` are absent for
/// exactly the same reason as each other. A zone the release does define, but
/// whose pinned offsets this contract's canonical offset unit cannot state
/// exactly, is absent too, and is refused rather than answered from a truncated
/// offset.
fn is_canonical_zone_identity(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= MAX_ZONE_IDENTITY_BYTES
        && user_automation_zones::is_pinned_zone(zone)
}

/// Returns whether one pinned zone database revision token names the revision
/// this build carries.
///
/// The token must be exactly the pinned release, compared case-sensitively. No
/// other revision is read, and none is resolved from an ambient database, so a
/// timezone database update cannot silently rewrite an existing revision.
fn is_canonical_zone_database_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ZONE_DATABASE_REVISION_BYTES
        && value == user_automation_zones::PINNED_ZONE_DATABASE_RELEASE
}

/// Returns whether one occurrence key still carries the retired shape-only
/// encoding.
///
/// The retired encoding was a local wall clock plus an offset, with no zone
/// identity, no pinned database revision, no resolved instant, and no applied
/// disposition. It is recognized only so the contract can name the required
/// re-normalization instead of silently certifying an unverified input under
/// the versioned calendar contract.
fn is_legacy_occurrence_key(occurrence_key: &str) -> bool {
    let bytes = occurrence_key.as_bytes();
    let retired_length = bytes.len() == UTC_INSTANT_BYTES
        || bytes.len() == CIVIL_WALL_CLOCK_BYTES + UTC_OFFSET_BYTES;
    retired_length
        && bytes[..CIVIL_WALL_CLOCK_BYTES]
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                4 | 7 => *byte == b'-',
                10 => *byte == b'T',
                13 | 16 => *byte == b':',
                _ => byte.is_ascii_digit(),
            })
}

/// The exact UserAutomation WorkScope projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationWorkScope {
    /// Canonical scope identity.
    pub scope_id: String,
    /// Product identity bound to the scope.
    pub product_id: String,
    /// Owner-qualified workdir reference.
    pub workdir_ref: String,
}

impl AutomationWorkScope {
    /// Validates the scope projection.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.scope_id, "work_scope.scope_id")?;
        text(&self.product_id, "work_scope.product_id")?;
        text(&self.workdir_ref, "work_scope.workdir_ref")
    }
}

/// Qualified task or script binding.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationTaskKind {
    /// Existing admitted task/model job path.
    AgentTask,
    /// Existing qualified deterministic process path.
    QualifiedScript,
}

/// Capability profile of the qualified task/script.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationCapabilityProfile {
    /// Whether the qualified executable may access a model provider.
    pub model_access: bool,
    /// Whether the qualified executable may access provider credentials/routes.
    pub provider_access: bool,
    /// Whether the qualified executable may create child automation operations.
    pub automation_scheduling: bool,
}

impl AutomationCapabilityProfile {
    /// Validates the capability profile as a shape-only value.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        Ok(())
    }
}

/// Owner-qualified task or script reference and capabilities.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationTaskBinding {
    /// Immutable qualified task/script identity.
    pub qualified_ref: String,
    /// Binding kind used for deterministic-mode checks.
    pub kind: AutomationTaskKind,
    /// Capability profile supplied by the qualified owner.
    pub capability_profile: AutomationCapabilityProfile,
}

impl AutomationTaskBinding {
    /// Validates the task binding.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.qualified_ref, "task.qualified_ref")?;
        self.capability_profile.validate()
    }
}

/// Provider/model/adapter identity observed or admitted by policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFingerprint {
    /// Provider identity.
    pub provider: String,
    /// Model identity.
    pub model: String,
    /// Adapter/runtime identity.
    pub adapter: String,
    /// Owner-issued immutable fingerprint.
    pub fingerprint: String,
}

impl ProviderFingerprint {
    /// Validates the fingerprint identity.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.provider, "provider.provider")?;
        text(&self.model, "provider.model")?;
        text(&self.adapter, "provider.adapter")?;
        text(&self.fingerprint, "provider.fingerprint")
    }
}

/// Provider policy for agent or deterministic execution.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderFingerprintPolicy {
    /// Exact admitted provider/model/adapter set.
    Allowed {
        /// Allowed provider/model/adapter identities.
        fingerprints: Vec<ProviderFingerprint>,
    },
    /// No model/provider access is admitted by this revision.
    DeterministicOnly,
}

impl ProviderFingerprintPolicy {
    /// Validates the policy and rejects duplicate fingerprint identities.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        match self {
            Self::Allowed { fingerprints } => {
                if fingerprints.is_empty() {
                    return Err(UserAutomationError::Invalid("provider_policy.fingerprints"));
                }
                for fingerprint in fingerprints {
                    fingerprint.validate()?;
                }
                if fingerprints.windows(2).any(|window| window[0] == window[1]) {
                    return Err(UserAutomationError::Invalid(
                        "provider_policy.fingerprints.unique",
                    ));
                }
            }
            Self::DeterministicOnly => {}
        }
        Ok(())
    }

    fn admits(&self, observed: Option<&ProviderFingerprint>) -> bool {
        match self {
            Self::Allowed { fingerprints } => {
                observed.is_some_and(|value| fingerprints.contains(value))
            }
            Self::DeterministicOnly => observed.is_none(),
        }
    }
}

/// Route and cost ceiling supplied by the canonical human policy owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCostPolicy {
    /// Named route policy reference.
    pub route_ref: String,
    /// Maximum admitted cost units.
    pub max_cost_units: u64,
    /// Maximum admitted duration in milliseconds.
    pub max_duration_ms: u64,
    /// Optional policy revision that approved the route ceiling.
    pub policy_revision: Option<PolicyRevision>,
}

impl RouteCostPolicy {
    /// Validates the route and finite resource ceilings.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.route_ref, "route_cost.route_ref")?;
        if self.max_cost_units == 0 {
            return Err(UserAutomationError::Invalid("route_cost.max_cost_units"));
        }
        if self.max_duration_ms == 0 {
            return Err(UserAutomationError::Invalid("route_cost.max_duration_ms"));
        }
        Ok(())
    }
}

/// Delivery target reference and allowed channels.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationDeliveryTarget {
    /// Canonical target identity.
    pub target_ref: String,
    /// Existing notification channels requested by the revision.
    pub channels: Vec<DeliveryChannel>,
    /// Owner-resolved recipient references.
    pub recipient_refs: Vec<String>,
}

impl AutomationDeliveryTarget {
    /// Validates the declared delivery target.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.target_ref, "delivery.target_ref")?;
        if self.channels.is_empty() {
            return Err(UserAutomationError::Invalid("delivery.channels"));
        }
        list_text(&self.recipient_refs, "delivery.recipient_refs")
    }
}

/// Bounded execution/resource policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationResourceCeiling {
    /// Maximum runtime in milliseconds.
    pub max_runtime_ms: u64,
    /// Maximum exact deterministic output bytes.
    pub max_output_bytes: u64,
    /// Maximum child depth admitted by this revision.
    pub max_child_count: u32,
}

impl AutomationResourceCeiling {
    /// Validates nonzero resource bounds.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        if self.max_runtime_ms == 0 {
            return Err(UserAutomationError::Invalid("resource.max_runtime_ms"));
        }
        if self.max_output_bytes == 0 {
            return Err(UserAutomationError::Invalid("resource.max_output_bytes"));
        }
        Ok(())
    }
}

/// Policy when one occurrence is already admitted or running.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OverlapPolicy {
    /// Reject the new occurrence before admission.
    ForbidOverlap,
    /// Keep one pending occurrence for the existing owner scheduler.
    QueueOne,
    /// Coalesce the latest wake into the existing owner projection.
    CoalesceLatest,
}

/// Policy controlling child automation scheduling.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursionPolicy {
    /// Whether an admitted execution may request another automation operation.
    pub allow_child_automation: bool,
    /// Inclusive maximum child depth.
    pub max_child_depth: u16,
}

impl RecursionPolicy {
    /// Validates the bounded child policy.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        if !self.allow_child_automation && self.max_child_depth != 0 {
            return Err(UserAutomationError::Invalid("recursion.max_child_depth"));
        }
        Ok(())
    }
}

/// I14.1 work class selected by the canonical automation owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationWorkClass {
    /// Kernel/control operations.
    Control,
    /// Human-interactive work.
    Interactive,
    /// Verification-only work.
    Verification,
    /// Canonical write work.
    CanonicalWrite,
    /// Ordinary background work.
    NormalBackground,
    /// Model-backed work.
    ModelJobs,
    /// Swarm coordination work.
    Swarm,
    /// Reporting work.
    Reporting,
    /// Maintenance work.
    Maintenance,
}

/// Immutable UserAutomation revision owned by Kernel semantics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRevision {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub revision: String,
    /// Immediately superseded revision, when this is an edit.
    pub supersedes: Option<String>,
    /// Owner principal reference.
    pub owner_principal: String,
    /// Exact UserAutomation WorkScope.
    pub work_scope: AutomationWorkScope,
    /// Original human request kept visible for inspection.
    pub natural_language_intent: String,
    /// Owner-normalized trigger contract.
    pub schedule: NormalizedSchedule,
    /// Agent or deterministic execution mode.
    pub mode: UserAutomationExecutionMode,
    /// Task/script binding and capability profile.
    pub task: AutomationTaskBinding,
    /// Exact trusted Skill package revision references.
    pub portable_skill_package_revision_refs: Vec<String>,
    /// Workdir binding repeated for explicit preflight inspection.
    pub workdir_ref: String,
    /// Route and cost ceiling.
    pub route_cost_policy: RouteCostPolicy,
    /// Provider/model/adapter admission policy.
    pub provider_policy: ProviderFingerprintPolicy,
    /// Delivery target.
    pub delivery_target: AutomationDeliveryTarget,
    /// Versioned deterministic preflight contract.
    pub preflight_contract_revision: String,
    /// Runtime/budget ceilings.
    pub resource_ceiling: AutomationResourceCeiling,
    /// Overlap behavior.
    pub overlap_policy: OverlapPolicy,
    /// Child scheduling behavior.
    pub recursion_policy: RecursionPolicy,
    /// Current configuration state.
    pub configuration_state: UserAutomationConfigurationState,
    /// I14.1 class for the existing Durable Job admission.
    pub work_class: AutomationWorkClass,
    /// Projection references into the existing Durable Job lifecycle.
    pub current_execution_refs: Vec<String>,
    /// Query reference into immutable execution/history records.
    pub execution_history_query_ref: String,
}

impl UserAutomationRevision {
    /// Validates the immutable revision and all nested owner projections.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.automation_id, "automation_id")?;
        text(&self.revision, "revision")?;
        if self.supersedes.as_deref() == Some(self.revision.as_str()) {
            return Err(UserAutomationError::InvalidSupersession);
        }
        text(&self.owner_principal, "owner_principal")?;
        self.work_scope.validate()?;
        text(&self.natural_language_intent, "natural_language_intent")?;
        self.schedule.validate_normalized_occurrences()?;
        self.task.validate()?;
        list_text(
            &self.portable_skill_package_revision_refs,
            "portable_skill_package_revision_refs",
        )?;
        text(&self.workdir_ref, "workdir_ref")?;
        if self.workdir_ref != self.work_scope.workdir_ref {
            return Err(UserAutomationError::Invalid("workdir_ref"));
        }
        self.route_cost_policy.validate()?;
        self.provider_policy.validate()?;
        self.delivery_target.validate()?;
        if self.preflight_contract_revision != USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION {
            return Err(UserAutomationError::Invalid("preflight_contract_revision"));
        }
        self.resource_ceiling.validate()?;
        self.recursion_policy.validate()?;
        list_text(&self.current_execution_refs, "current_execution_refs")?;
        if self
            .current_execution_refs
            .windows(2)
            .any(|window| window[0] == window[1])
        {
            return Err(UserAutomationError::Invalid(
                "current_execution_refs.unique",
            ));
        }
        text(
            &self.execution_history_query_ref,
            "execution_history_query_ref",
        )?;

        match self.mode {
            UserAutomationExecutionMode::Agent => {
                if self.task.kind != AutomationTaskKind::AgentTask
                    || !matches!(
                        self.provider_policy,
                        ProviderFingerprintPolicy::Allowed { .. }
                    )
                {
                    return Err(UserAutomationError::Invalid("agent_capability_profile"));
                }
            }
            UserAutomationExecutionMode::DeterministicProcess => {
                if self.task.kind != AutomationTaskKind::QualifiedScript
                    || self.task.capability_profile.model_access
                    || self.task.capability_profile.provider_access
                    || self.task.capability_profile.automation_scheduling
                    || !matches!(
                        self.provider_policy,
                        ProviderFingerprintPolicy::DeterministicOnly
                    )
                    || self.work_class == AutomationWorkClass::ModelJobs
                {
                    return Err(UserAutomationError::Invalid(
                        "deterministic_capability_profile",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Derives the immutable canonical digest used by query/read contracts.
    pub fn digest(&self) -> Result<String, UserAutomationError> {
        self.validate()?;
        canonical_digest(self)
    }

    /// Validates that `self` is a new revision immediately superseding `old`.
    pub fn validate_supersedes(
        &self,
        old: &UserAutomationRevision,
    ) -> Result<(), UserAutomationError> {
        self.validate()?;
        old.validate()?;
        if self.automation_id != old.automation_id
            || self.revision == old.revision
            || self.supersedes.as_deref() != Some(old.revision.as_str())
        {
            return Err(UserAutomationError::InvalidSupersession);
        }
        Ok(())
    }

    /// Compiles an inert existing-contract wake intent for one occurrence.
    pub fn compile_wake_intent(
        &self,
        occurrence_id: &str,
        state_fence: StateFence,
    ) -> Result<WakeIntent, UserAutomationError> {
        self.validate()?;
        text(occurrence_id, "occurrence_id")?;
        let wake = WakeIntent {
            wake_id: occurrence_id.to_owned(),
            reason: format!("{WAKE_REASON_PREFIX}:{occurrence_id}"),
            state_fence,
            state: WakeIntentState::Pending,
        };
        wake.validate()
            .map_err(|_| UserAutomationError::Invalid("wake_intent"))?;
        Ok(wake)
    }

    /// Returns the existing Durable Job operation used after admission.
    #[must_use]
    pub const fn durable_job_operation(&self) -> JobOperationKind {
        JobOperationKind::Submit
    }

    /// Compiles one owner-normalized calendar occurrence into the immutable
    /// scheduled trigger of this revision.
    ///
    /// The occurrence must be a member of this revision's normalized set. A
    /// calendar phrase the owner did not normalize is refused here rather than
    /// resolved, shifted, or folded into a neighbouring occurrence, so a
    /// duplicate wake or a restart of a different schedule revision can never
    /// invent a second identity for the same instant.
    pub fn scheduled_trigger(
        &self,
        occurrence_key: &str,
    ) -> Result<UserAutomationTrigger, UserAutomationError> {
        self.validate()?;
        if !self.schedule.contains_occurrence(occurrence_key)? {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.unnormalized",
            ));
        }
        let trigger = UserAutomationTrigger::Scheduled {
            occurrence_key: occurrence_key.to_owned(),
        };
        trigger.validate()?;
        Ok(trigger)
    }

    /// Builds the revision-bound invocation for one calendar occurrence.
    ///
    /// `ScheduledWake` is the origin for the existing scheduler wake and
    /// `AutomationChild` for an already admitted child. Neither path mints a
    /// principal: the caller supplies the authenticated principal reference and
    /// the owner route revalidates it before any effect.
    pub fn scheduled_invocation(
        &self,
        occurrence_key: &str,
        authenticated_principal: &str,
        trigger_origin: UserAutomationTriggerOrigin,
        child_depth: u16,
    ) -> Result<UserAutomationInvocation, UserAutomationError> {
        text(authenticated_principal, "principal_ref")?;
        let trigger = self.scheduled_trigger(occurrence_key)?;
        let invocation = UserAutomationInvocation {
            automation_id: self.automation_id.clone(),
            automation_revision: self.revision.clone(),
            trigger,
            mode: self.mode,
            principal_ref: authenticated_principal.to_owned(),
            work_scope_ref: self.work_scope.scope_id.clone(),
            workdir_ref: self.workdir_ref.clone(),
            trigger_origin,
            child_depth,
            provenance: None,
        };
        invocation.occurrence_identity_projection()?;
        Ok(invocation)
    }

    /// Builds the explicit manual run-now trigger for one Human-issued nonce.
    ///
    /// A manual nonce never mutates the normalized schedule: the manual
    /// occurrence is a distinct trigger kind, so it receives a distinct stable
    /// identity from any calendar occurrence of the same revision.
    pub fn manual_trigger(
        &self,
        nonce: &str,
    ) -> Result<UserAutomationTrigger, UserAutomationError> {
        self.validate()?;
        text(nonce, "operation.nonce")?;
        let trigger = UserAutomationTrigger::Manual {
            nonce: nonce.to_owned(),
        };
        trigger.validate()?;
        Ok(trigger)
    }

    /// Returns the stable revision-bound occurrence identity for one trigger.
    pub fn occurrence_identity_for(
        &self,
        trigger: &UserAutomationTrigger,
    ) -> Result<String, UserAutomationError> {
        self.validate()?;
        UserAutomationInvocation::occurrence_identity_for(
            &self.automation_id,
            &self.revision,
            trigger,
        )
    }

    /// Compiles the bounded next-occurrence projection of this revision into
    /// immutable revision-bound occurrence identities.
    ///
    /// This is the deterministic schedule compiler surface shown to the Human
    /// before activation and reused by every later admission: the same revision
    /// always produces the same ordered identities, and a duplicate wake or
    /// restart resolves to the identity already present in this list.
    pub fn compile_occurrence_identities(
        &self,
    ) -> Result<Vec<AutomationOccurrenceIdentity>, UserAutomationError> {
        self.validate()?;
        self.schedule.validate_normalized_occurrences()?;
        let mut identities = Vec::with_capacity(self.schedule.next_occurrences.len());
        for occurrence_key in &self.schedule.next_occurrences {
            let trigger = self.scheduled_trigger(occurrence_key)?;
            let occurrence_id = self.occurrence_identity_for(&trigger)?;
            identities.push(AutomationOccurrenceIdentity {
                automation_id: self.automation_id.clone(),
                revision: self.revision.clone(),
                trigger,
                occurrence_id,
            });
        }
        Ok(identities)
    }

    /// Returns the deterministic successor occurrence of this revision.
    pub fn next_occurrence_after(
        &self,
        occurrence_key: &str,
    ) -> Result<Option<String>, UserAutomationError> {
        self.validate()?;
        self.schedule.next_occurrence_after(occurrence_key)
    }
}

/// Scheduled calendar occurrence or explicit manual nonce.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationTrigger {
    /// Owner-normalized calendar occurrence key.
    Scheduled {
        /// Exact owner-normalized calendar occurrence.
        occurrence_key: String,
    },
    /// Explicit Human-issued run-now nonce.
    Manual {
        /// Nonce that distinguishes this manual occurrence from the schedule.
        nonce: String,
    },
}

impl UserAutomationTrigger {
    fn validate(&self) -> Result<(), UserAutomationError> {
        match self {
            Self::Scheduled { occurrence_key } => text(occurrence_key, "trigger.occurrence_key"),
            Self::Manual { nonce } => text(nonce, "trigger.nonce"),
        }
    }
}

/// Origin of a UserAutomation invocation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationTriggerOrigin {
    /// Explicit Human operation.
    Human,
    /// Existing scheduler wake revalidated by Host/Kernel.
    ScheduledWake,
    /// Child request from an already admitted automation.
    AutomationChild,
}

/// Persisted evidence for the request that first admitted this invocation.
///
/// The Store writes this alongside a `RunNow` invocation. It retains the exact
/// task/session metadata, closed operator payload, and canonical write
/// identity that produced the invocation; a later daemon selector cannot
/// replace or manufacture these fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationInvocationProvenance {
    /// Authenticated Kernel request context that admitted the operator action.
    pub request_metadata: RequestMetadata,
    /// Closed operation payload that produced this invocation.
    pub source_operation: UserAutomationOperation,
    /// Canonical Store operation identity for the source action.
    pub operation_id: OperationId,
    /// Idempotency identity for the source action.
    pub idempotency_key: String,
    /// Canonical request digest verified by the Store write path.
    pub canonical_request_hash: String,
}

impl UserAutomationInvocationProvenance {
    fn validate_for(
        &self,
        invocation: &UserAutomationInvocation,
        expected_state_fence: &StateFence,
    ) -> Result<(), UserAutomationError> {
        self.request_metadata
            .validate()
            .map_err(|_| UserAutomationError::Invalid("invocation.provenance.request_metadata"))?;
        self.source_operation.validate()?;
        text(
            &self.idempotency_key,
            "invocation.provenance.idempotency_key",
        )?;
        if self.canonical_request_hash.len() != 64
            || !self
                .canonical_request_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(UserAutomationError::Invalid(
                "invocation.provenance.canonical_request_hash",
            ));
        }
        if self.request_metadata.state_fence != *expected_state_fence
            || self.request_metadata.session_id.is_none()
            || self.request_metadata.task_id.is_none()
        {
            return Err(UserAutomationError::ReceiptBinding);
        }

        match (&self.source_operation, &invocation.trigger) {
            (
                UserAutomationOperation::RunNow {
                    automation_id,
                    automation_revision,
                    nonce,
                },
                UserAutomationTrigger::Manual {
                    nonce: invocation_nonce,
                },
            ) if automation_id == &invocation.automation_id
                && automation_revision == &invocation.automation_revision
                && nonce == invocation_nonce
                && invocation.trigger_origin == UserAutomationTriggerOrigin::Human
                && invocation.child_depth == 0 =>
            {
                Ok(())
            }
            _ => Err(UserAutomationError::ReceiptBinding),
        }
    }
}

/// Authenticated invocation selector accepted by the Kernel owner route.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationInvocation {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Scheduled occurrence or explicit manual nonce.
    pub trigger: UserAutomationTrigger,
    /// Mode supplied by the owner route and checked against the revision.
    pub mode: UserAutomationExecutionMode,
    /// Authenticated owner principal reference.
    pub principal_ref: String,
    /// Authenticated WorkScope reference.
    pub work_scope_ref: String,
    /// Authenticated workdir reference.
    pub workdir_ref: String,
    /// Origin of the invocation.
    pub trigger_origin: UserAutomationTriggerOrigin,
    /// Child depth carried by the admitted lineage.
    pub child_depth: u16,
    /// Original owner-admitted request and exact `RunNow` receipt identity.
    /// Older persisted invocations deserialize without provenance but are
    /// rejected by production admission until reconciled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<UserAutomationInvocationProvenance>,
}

impl UserAutomationInvocation {
    /// Validates the typed invocation without reading ambient identity.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.automation_id, "automation_id")?;
        text(&self.automation_revision, "automation_revision")?;
        self.trigger.validate()?;
        text(&self.principal_ref, "principal_ref")?;
        text(&self.work_scope_ref, "work_scope_ref")?;
        text(&self.workdir_ref, "workdir_ref")
    }

    /// Requires task/session and exact `RunNow` receipt provenance at the
    /// production owner-admission boundary.
    pub fn require_run_now_provenance(
        &self,
        expected_state_fence: &StateFence,
    ) -> Result<&UserAutomationInvocationProvenance, UserAutomationError> {
        let provenance = self
            .provenance
            .as_ref()
            .ok_or(UserAutomationError::ReceiptBinding)?;
        provenance.validate_for(self, expected_state_fence)?;
        Ok(provenance)
    }

    /// Returns the stable revision-bound occurrence identity.
    pub fn occurrence_identity(&self) -> Result<String, UserAutomationError> {
        self.validate()?;
        Self::occurrence_identity_for(
            &self.automation_id,
            &self.automation_revision,
            &self.trigger,
        )
    }

    /// Derives the stable occurrence identity from owner-selected immutable
    /// identity and trigger material without constructing an invocation.
    ///
    /// This is a selector operation only. It does not assign a principal,
    /// trigger origin, child depth, mode, or work scope; those fields must be
    /// recovered from the owner-issued persisted invocation before admission.
    pub fn occurrence_identity_for(
        automation_id: &str,
        automation_revision: &str,
        trigger: &UserAutomationTrigger,
    ) -> Result<String, UserAutomationError> {
        text(automation_id, "automation_id")?;
        text(automation_revision, "automation_revision")?;
        trigger.validate()?;
        let bytes = canonical_json_bytes(&(
            OCCURRENCE_IDENTITY_DOMAIN,
            automation_id,
            automation_revision,
            trigger,
        ))
        .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
        Ok(format!("user-automation-occurrence:{}", sha256_hex(&bytes)))
    }

    /// Returns a typed identity projection for callers that need the inputs.
    pub fn occurrence_identity_projection(
        &self,
    ) -> Result<AutomationOccurrenceIdentity, UserAutomationError> {
        Ok(AutomationOccurrenceIdentity {
            automation_id: self.automation_id.clone(),
            revision: self.automation_revision.clone(),
            trigger: self.trigger.clone(),
            occurrence_id: self.occurrence_identity()?,
        })
    }
}

/// Typed stable identity of one scheduled or manual occurrence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationOccurrenceIdentity {
    /// Automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub revision: String,
    /// Exact trigger material.
    pub trigger: UserAutomationTrigger,
    /// Derived stable identity.
    pub occurrence_id: String,
}

/// Execution projection backed by existing Durable Job history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationExecutionReference {
    /// Stable occurrence identity.
    pub occurrence_id: String,
    /// Existing Durable Job record reference.
    pub durable_job_ref: String,
    /// Current projected Durable Job state.
    pub state: JobState,
}

impl AutomationExecutionReference {
    /// Validates one execution reference.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.occurrence_id, "execution.occurrence_id")?;
        text(&self.durable_job_ref, "execution.durable_job_ref")
    }
}

/// Why one automation occurrence still carries an unresolved effect
/// obligation (I14.21, I5.16).
///
/// The disposition of a stored occurrence is never inferred from the absence
/// of a closure or coverage record: an occurrence whose owner-issued evidence
/// cannot be read, or one whose denominator could not be proven complete,
/// keeps an explicit typed obligation instead of silently reading as "no
/// effect".
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationReconciliationCause {
    /// The admitting canonical operation has no committed receipt, or its
    /// committed receipt still requires a reconciliation envelope.
    UnresolvedOperation,
    /// The stored invocation row carries no usable owner-issued invocation
    /// document (absent, legacy, or malformed). I5.16: absence of a coverage
    /// record is `unknown`, not unrestricted/complete.
    MissingInvocationEvidence,
    /// The stored invocation document carries no owner-issued provenance, so
    /// the admitting canonical operation cannot be resolved for this row.
    MissingInvocationProvenance,
    /// The canonical receipt lookup for the admitting operation could not be
    /// read; the effect disposition is unknown, not absent.
    ReceiptEvidenceUnavailable,
    /// The declared occurrence denominator was not owner-proven complete at
    /// the read revision, so later occurrences may still carry unresolved
    /// effects that are not represented inline.
    IncompleteDenominator,
}

/// Existing reconciliation obligation for an uncertain effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationReconciliationReference {
    /// Occurrence whose effect remains uncertain, or the exact automation
    /// denominator identity when the obligation is denominator coverage
    /// rather than one occurrence.
    pub occurrence_id: String,
    /// Existing ORS/reconciliation operation reference, or the actionable
    /// migration reference for a row whose owner evidence is unusable. It
    /// never claims a committed or failed outcome that was not observed.
    pub operation_ref: String,
    /// Typed reason this obligation exists.
    pub cause: AutomationReconciliationCause,
    /// Owner-issued read revision the occurrence denominator was read at.
    /// Every obligation in one projection carries the same value, so Status,
    /// History, preflight and Remove answer from one denominator revision.
    pub read_revision: String,
    /// Durable owner query handle that enumerates the rest of the declared
    /// denominator. Present exactly when coverage is not owner-proven.
    pub denominator_query_ref: Option<String>,
}

impl AutomationReconciliationReference {
    /// Validates one reconciliation reference.
    ///
    /// The durable denominator handle is required exactly for
    /// [`AutomationReconciliationCause::IncompleteDenominator`]: an
    /// unrepresented remainder of the denominator must remain addressable
    /// after retirement, and a per-occurrence obligation must not carry a
    /// collection handle that implies more rows.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.occurrence_id, "reconciliation.occurrence_id")?;
        text(&self.operation_ref, "reconciliation.operation_ref")?;
        text(&self.read_revision, "reconciliation.read_revision")?;
        let handle_is_expected = self.cause == AutomationReconciliationCause::IncompleteDenominator;
        if handle_is_expected != self.denominator_query_ref.is_some() {
            return Err(UserAutomationError::Invalid(
                "reconciliation.denominator_query_ref",
            ));
        }
        if let Some(handle) = &self.denominator_query_ref {
            text(handle, "reconciliation.denominator_query_ref")?;
        }
        Ok(())
    }
}

/// Separate execution/history projection for one immutable revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationExecutionProjection {
    /// Currently admitted/running Durable Job references.
    pub current_execution_refs: Vec<AutomationExecutionReference>,
    /// Unknown or otherwise unresolved effects requiring reconciliation.
    pub unresolved_reconciliation_refs: Vec<AutomationReconciliationReference>,
    /// Query reference for immutable history.
    pub history_query_ref: String,
}

impl UserAutomationExecutionProjection {
    /// Validates projection shape and retains unknown outcomes as obligations.
    ///
    /// Every retained obligation must also agree on one owner-issued
    /// denominator read revision. Two revisions in one projection mean the
    /// read raced a successor commit or retirement, so the set was assembled
    /// from two snapshots and fails closed instead of answering as one
    /// complete denominator.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        list_len(
            self.current_execution_refs.len(),
            "execution.current_execution_refs",
        )?;
        for execution in &self.current_execution_refs {
            execution.validate()?;
        }
        list_len(
            self.unresolved_reconciliation_refs.len(),
            "execution.unresolved_reconciliation_refs",
        )?;
        let mut read_revision: Option<&str> = None;
        for reconciliation in &self.unresolved_reconciliation_refs {
            reconciliation.validate()?;
            match read_revision {
                None => read_revision = Some(reconciliation.read_revision.as_str()),
                Some(observed) if observed == reconciliation.read_revision => {}
                Some(_) => {
                    return Err(UserAutomationError::Invalid(
                        "execution.unresolved_reconciliation_refs",
                    ));
                }
            }
        }
        text(&self.history_query_ref, "execution.history_query_ref")
    }

    /// Returns whether any admitted execution is still active.
    #[must_use]
    pub fn has_active_execution(&self) -> bool {
        self.current_execution_refs
            .iter()
            .any(|reference| !reference.state.is_terminal())
    }

    /// Returns whether an effect must be reconciled before a new admission.
    ///
    /// An unproven occurrence denominator is itself an obligation, so an
    /// incomplete or unreadable denominator reads as blocking rather than as
    /// "no reconciliation obligation" (I5.16).
    #[must_use]
    pub fn requires_reconciliation(&self) -> bool {
        !self.unresolved_reconciliation_refs.is_empty()
            || self
                .current_execution_refs
                .iter()
                .any(|reference| reference.state == JobState::UnknownOutcome)
    }
}

/// A notification recipient projection supplied by the canonical owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationRecipient {
    /// Authenticated recipient principal reference.
    pub principal: PlatformHandle,
    /// Admitted recipient role.
    pub role: AutomationRecipientRole,
}

/// Recipient role projection used by the existing notification adapter.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationRecipientRole {
    /// Requesting Human.
    Requester,
    /// Domain owner.
    DomainOwner,
    /// Architecture owner.
    ArchitectureOwner,
    /// System owner.
    SystemOwner,
    /// WorkScope owner.
    WorkScopeOwner,
    /// Approver.
    Approver,
    /// Recovery principal.
    RecoveryPrincipal,
    /// Explicitly authorized role.
    AuthorizedRole,
}

/// Notification content projected by the UserAutomation owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationFailureNotificationProjection {
    /// Canonical notification draft before revision/fingerprint identity bind.
    pub canonical: NotificationDraft,
    /// Human-facing subject.
    pub subject: String,
    /// Human-facing summary.
    pub summary: String,
    /// Owner-resolved recipients.
    pub recipients: Vec<AutomationRecipient>,
}

impl AutomationFailureNotificationProjection {
    /// Validates notification content without issuing delivery authority.
    pub fn validate(&self, state_fence: &StateFence) -> Result<(), UserAutomationError> {
        self.canonical
            .validate()
            .map_err(|_| UserAutomationError::Invalid("failure.notification.canonical"))?;
        text(&self.subject, "failure.notification.subject")?;
        text(&self.summary, "failure.notification.summary")?;
        if self.canonical.subject != self.subject || self.canonical.summary != self.summary {
            return Err(UserAutomationError::Invalid("failure.notification.summary"));
        }
        if self.canonical.state_fence != *state_fence || self.recipients.is_empty() {
            return Err(UserAutomationError::Invalid("failure.notification.binding"));
        }
        for recipient in &self.recipients {
            text(
                recipient.principal.as_str(),
                "failure.notification.recipient",
            )?;
        }
        Ok(())
    }
}

/// Canonical failure reason emitted by deterministic preflight.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationFailureReason {
    /// The canonical owner marked the revision blocked.
    CanonicalBlockedConfig {
        /// Owner-defined stable failure class.
        class: String,
    },
    /// Provider/model/adapter drift or absence failed closed.
    ProviderFingerprintMismatch,
    /// A deterministic capability attempted model/provider access.
    DeterministicModelAccess,
    /// Trusted Skill package revisions are not exact.
    SkillRevisionMismatch,
    /// Trusted Tool Definitions are not exact.
    ToolDefinitionMismatch,
    /// Delivery capability is unavailable.
    DeliveryUnavailable,
    /// Overlap policy forbids this occurrence.
    OverlapForbidden,
    /// Recursion policy rejects this child invocation.
    RecursionDenied,
    /// An admitted effect is unresolved.
    ReconciliationRequired,
}

impl UserAutomationFailureReason {
    fn validate(&self) -> Result<(), UserAutomationError> {
        if let Self::CanonicalBlockedConfig { class } = self {
            text(class, "failure.reason.class")?;
        }
        Ok(())
    }
}

/// Owner-issued failure fingerprint and notification content.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailureProjection {
    /// Deterministic failure-class fingerprint.
    pub failure_fingerprint: String,
    /// Typed reason used to derive the fingerprint.
    pub reason: UserAutomationFailureReason,
    /// Existing notification content passed to the surface adapter.
    pub notification: AutomationFailureNotificationProjection,
}

impl UserAutomationFailureProjection {
    /// Validates owner-issued failure identity and notification shape.
    pub fn validate(
        &self,
        revision: &UserAutomationRevision,
        state_fence: &StateFence,
    ) -> Result<(), UserAutomationError> {
        self.reason.validate()?;
        text(&self.failure_fingerprint, "failure.failure_fingerprint")?;
        let expected = revision.failure_fingerprint(&self.reason)?;
        if expected != self.failure_fingerprint {
            return Err(UserAutomationError::FailureFingerprintMismatch);
        }
        self.notification.validate(state_fence)
    }
}

impl UserAutomationRevision {
    /// Derives one stable class fingerprint from a typed preflight reason.
    pub fn failure_fingerprint(
        &self,
        reason: &UserAutomationFailureReason,
    ) -> Result<String, UserAutomationError> {
        self.validate()?;
        reason.validate()?;
        let bytes = canonical_json_bytes(&(FAILURE_FINGERPRINT_DOMAIN, reason))
            .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Deferred admission reason. No admitted execution is cancelled by this value.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationDeferReason {
    /// Configuration is paused.
    Paused,
    /// Revision is retired and history remains queryable.
    Retired,
    /// One occurrence is already active and queue-one owns the pending wake.
    QueueOne,
    /// The latest wake is coalesced by the existing scheduler projection.
    CoalescedLatest,
    /// The prior effect remains under I14.21 reconciliation.
    ReconciliationRequired,
}

/// Owner-issued preflight receipt bound to one occurrence and config snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightReceipt {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Stable scheduled/manual occurrence identity.
    pub occurrence_id: String,
    /// Canonical configuration snapshot identity.
    pub config_snapshot_id: String,
    /// Existing B-owned complete config snapshot observed by this preflight.
    /// The daemon admission gate compares this exact snapshot against the
    /// live policy owner; the id alone is not sufficient.
    pub config_snapshot: ConfigPolicySnapshot,
    /// Configuration state observed by this preflight.
    pub configuration_state: UserAutomationConfigurationState,
    /// I14.1 class for the existing Durable Job path.
    pub work_class: AutomationWorkClass,
    /// Whether a subsequent admitted execution may access a model provider.
    pub model_access_allowed_after_admission: bool,
    /// Existing owner-issued source receipt.
    pub source_receipt: ReceiptEnvelope,
}

/// Deterministic preflight decision. No branch invokes a model or scheduler.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationPreflightDecision {
    /// The occurrence may join the existing Durable Job admission path.
    Admitted {
        /// Receipt for this exact occurrence.
        receipt: UserAutomationPreflightReceipt,
    },
    /// The occurrence remains unadmitted and waits for an existing owner.
    Deferred {
        /// Receipt for this exact occurrence.
        receipt: UserAutomationPreflightReceipt,
        /// Why admission is deferred.
        reason: UserAutomationDeferReason,
    },
    /// Configuration/fingerprint failure is surfaced once by the notification
    /// adapter; no model or task effect has been admitted.
    BlockedConfig {
        /// Receipt for the failed preflight.
        receipt: UserAutomationPreflightReceipt,
        /// Owner-issued failure content and deterministic class identity.
        failure: UserAutomationFailureProjection,
    },
}

/// Authenticated request context used by the pure preflight evaluator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightContext {
    /// Full authenticated parent request metadata.
    pub request_metadata: RequestMetadata,
}

/// Owner-issued complete projection consumed by Kernel/Host and notify.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightProjection {
    /// Stable automation identity repeated for route binding.
    pub automation_id: String,
    /// Immutable revision identity repeated for route binding.
    pub automation_revision: String,
    /// Mode repeated for route binding.
    pub mode: UserAutomationExecutionMode,
    /// Stable occurrence identity.
    pub occurrence_id: String,
    /// Full immutable revision owned by this projection.
    pub revision: UserAutomationRevision,
    /// Live canonical configuration state from the current pointer.
    ///
    /// This may differ from the immutable revision's state after pause,
    /// resume, or retirement. Admission follows this owner readback; the
    /// revision retains the state captured when that immutable document was
    /// created.
    pub configuration_state: UserAutomationConfigurationState,
    /// Existing B-owned complete config snapshot.
    pub config_snapshot: ConfigPolicySnapshot,
    /// Existing owner-issued source verification receipt.
    pub source_receipt: ReceiptEnvelope,
    /// Existing Durable Job/history projection.
    pub execution: UserAutomationExecutionProjection,
    /// Provider identity observed by the owner route, if model access applies.
    pub observed_provider_fingerprint: Option<ProviderFingerprint>,
    /// Exact trusted Skill revisions observed by the owner route.
    pub trusted_skill_package_revision_refs: Vec<String>,
    /// Exact trusted Tool Definition revisions observed by the owner route.
    pub trusted_tool_definition_refs: Vec<String>,
    /// Whether the declared delivery target is currently capable.
    pub delivery_available: bool,
    /// Authenticated trigger origin.
    pub trigger_origin: UserAutomationTriggerOrigin,
    /// Authenticated child depth.
    pub child_depth: u16,
    /// Optional owner-issued blocked failure.
    pub failure: Option<UserAutomationFailureProjection>,
}

impl UserAutomationPreflightProjection {
    /// Runs deterministic preflight against the authenticated parent metadata.
    pub fn preflight(
        &self,
        invocation: &UserAutomationInvocation,
        context: &UserAutomationPreflightContext,
    ) -> Result<UserAutomationPreflightDecision, UserAutomationError> {
        invocation.validate()?;
        self.revision.validate()?;
        self.execution.validate()?;
        if self.execution.history_query_ref != self.revision.execution_history_query_ref {
            return Err(UserAutomationError::Invalid("execution.history_query_ref"));
        }
        let revision_refs = self
            .revision
            .current_execution_refs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let execution_refs = self
            .execution
            .current_execution_refs
            .iter()
            .map(|reference| reference.durable_job_ref.as_str())
            .collect::<BTreeSet<_>>();
        if revision_refs != execution_refs {
            return Err(UserAutomationError::Invalid(
                "execution.current_execution_refs",
            ));
        }
        if self.automation_id != invocation.automation_id
            || self.automation_revision != invocation.automation_revision
            || self.mode != invocation.mode
            || self.revision.automation_id != self.automation_id
            || self.revision.revision != self.automation_revision
            || self.revision.mode != self.mode
            || self.trigger_origin != invocation.trigger_origin
            || self.child_depth != invocation.child_depth
        {
            return Err(UserAutomationError::RevisionMismatch);
        }
        if invocation.principal_ref != self.revision.owner_principal
            || invocation.work_scope_ref != self.revision.work_scope.scope_id
            || invocation.workdir_ref != self.revision.workdir_ref
        {
            return Err(UserAutomationError::RevisionMismatch);
        }
        if self.occurrence_id != invocation.occurrence_identity()? {
            return Err(UserAutomationError::OccurrenceMismatch);
        }
        self.config_snapshot
            .validate()
            .map_err(|error| UserAutomationError::Config(error.to_string()))?;
        if self.config_snapshot.state_fence != context.request_metadata.state_fence
            || self.config_snapshot.state_fence.policy_revision
                != Some(self.config_snapshot.revision)
        {
            return Err(UserAutomationError::Invalid("config_snapshot.state_fence"));
        }
        self.source_receipt
            .validate()
            .map_err(|error| UserAutomationError::Receipt(error.to_string()))?;
        if self.source_receipt.core.request.metadata != context.request_metadata
            || self.source_receipt.core.request.state_fence != context.request_metadata.state_fence
            || self.source_receipt.core.work_scope.state_fence
                != context.request_metadata.state_fence
            || self.source_receipt.core.work_scope.product_id != context.request_metadata.product_id
        {
            return Err(UserAutomationError::ReceiptBinding);
        }
        list_text(
            &self.trusted_skill_package_revision_refs,
            "trusted_skill_package_revision_refs",
        )?;
        list_text(
            &self.trusted_tool_definition_refs,
            "trusted_tool_definition_refs",
        )?;

        let receipt = self.receipt();
        match self.configuration_state {
            UserAutomationConfigurationState::Paused => {
                self.require_no_failure()?;
                return Ok(UserAutomationPreflightDecision::Deferred {
                    receipt,
                    reason: UserAutomationDeferReason::Paused,
                });
            }
            UserAutomationConfigurationState::Retired => {
                self.require_no_failure()?;
                return Ok(UserAutomationPreflightDecision::Deferred {
                    receipt,
                    reason: UserAutomationDeferReason::Retired,
                });
            }
            UserAutomationConfigurationState::BlockedConfig => {
                let failure = self
                    .failure
                    .as_ref()
                    .ok_or(UserAutomationError::FailureProjectionMissing)?;
                failure.validate(&self.revision, &context.request_metadata.state_fence)?;
                return Ok(UserAutomationPreflightDecision::BlockedConfig {
                    receipt,
                    failure: failure.clone(),
                });
            }
            UserAutomationConfigurationState::Active => {}
        }

        if self.execution.requires_reconciliation() {
            self.require_failure(UserAutomationFailureReason::ReconciliationRequired, context)?;
            return Ok(UserAutomationPreflightDecision::Deferred {
                receipt,
                reason: UserAutomationDeferReason::ReconciliationRequired,
            });
        }
        if !self
            .revision
            .provider_policy
            .admits(self.observed_provider_fingerprint.as_ref())
        {
            return self.blocked(
                UserAutomationFailureReason::ProviderFingerprintMismatch,
                receipt,
                context,
            );
        }
        if self.revision.mode == UserAutomationExecutionMode::DeterministicProcess
            && (self.observed_provider_fingerprint.is_some()
                || self.revision.task.capability_profile.model_access
                || self.revision.task.capability_profile.provider_access)
        {
            return self.blocked(
                UserAutomationFailureReason::DeterministicModelAccess,
                receipt,
                context,
            );
        }
        if self.trusted_skill_package_revision_refs
            != self.revision.portable_skill_package_revision_refs
        {
            return self.blocked(
                UserAutomationFailureReason::SkillRevisionMismatch,
                receipt,
                context,
            );
        }
        if self.trusted_tool_definition_refs.is_empty() {
            return self.blocked(
                UserAutomationFailureReason::ToolDefinitionMismatch,
                receipt,
                context,
            );
        }
        if !self.delivery_available {
            return self.blocked(
                UserAutomationFailureReason::DeliveryUnavailable,
                receipt,
                context,
            );
        }
        if invocation.trigger_origin == UserAutomationTriggerOrigin::AutomationChild
            && (!self.revision.recursion_policy.allow_child_automation
                || invocation.child_depth > self.revision.recursion_policy.max_child_depth
                || !self.revision.task.capability_profile.automation_scheduling)
        {
            return self.blocked(
                UserAutomationFailureReason::RecursionDenied,
                receipt,
                context,
            );
        }
        if self.execution.has_active_execution() {
            match self.revision.overlap_policy {
                OverlapPolicy::ForbidOverlap => {
                    return self.blocked(
                        UserAutomationFailureReason::OverlapForbidden,
                        receipt,
                        context,
                    );
                }
                OverlapPolicy::QueueOne => {
                    self.require_no_failure()?;
                    return Ok(UserAutomationPreflightDecision::Deferred {
                        receipt,
                        reason: UserAutomationDeferReason::QueueOne,
                    });
                }
                OverlapPolicy::CoalesceLatest => {
                    self.require_no_failure()?;
                    return Ok(UserAutomationPreflightDecision::Deferred {
                        receipt,
                        reason: UserAutomationDeferReason::CoalescedLatest,
                    });
                }
            }
        }
        self.require_no_failure()?;
        Ok(UserAutomationPreflightDecision::Admitted { receipt })
    }

    fn receipt(&self) -> UserAutomationPreflightReceipt {
        UserAutomationPreflightReceipt {
            automation_id: self.automation_id.clone(),
            automation_revision: self.automation_revision.clone(),
            occurrence_id: self.occurrence_id.clone(),
            config_snapshot_id: self.config_snapshot.snapshot_id.clone(),
            config_snapshot: self.config_snapshot.clone(),
            configuration_state: self.configuration_state,
            work_class: self.revision.work_class,
            model_access_allowed_after_admission: self.mode == UserAutomationExecutionMode::Agent,
            source_receipt: self.source_receipt.clone(),
        }
    }

    fn require_no_failure(&self) -> Result<(), UserAutomationError> {
        if self.failure.is_some() {
            return Err(UserAutomationError::Invalid(
                "unexpected_failure_projection",
            ));
        }
        Ok(())
    }

    fn require_failure(
        &self,
        reason: UserAutomationFailureReason,
        context: &UserAutomationPreflightContext,
    ) -> Result<(), UserAutomationError> {
        let failure = self
            .failure
            .as_ref()
            .ok_or(UserAutomationError::FailureProjectionMissing)?;
        if failure.reason != reason {
            return Err(UserAutomationError::FailureFingerprintMismatch);
        }
        failure.validate(&self.revision, &context.request_metadata.state_fence)
    }

    fn blocked(
        &self,
        reason: UserAutomationFailureReason,
        receipt: UserAutomationPreflightReceipt,
        context: &UserAutomationPreflightContext,
    ) -> Result<UserAutomationPreflightDecision, UserAutomationError> {
        self.require_failure(reason, context)?;
        let Some(failure) = self.failure.clone() else {
            return Err(UserAutomationError::FailureProjectionMissing);
        };
        Ok(UserAutomationPreflightDecision::BlockedConfig { receipt, failure })
    }
}

/// Query kinds served by the authenticated Kernel/Host owner route.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationQueryKind {
    /// List current configuration revisions.
    List,
    /// Read current configuration/status projection.
    Status,
    /// Read immutable Durable Job history projection.
    History,
    /// Read the last owner-issued failure projection.
    InspectLastFailure,
    /// Read one deterministic preflight projection.
    Preflight,
}

/// Typed authenticated query contract for Kernel/Host dispatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationQuery {
    /// Exact query kind.
    pub kind: UserAutomationQueryKind,
    /// Stable automation identity.
    pub automation_id: String,
    /// Optional immutable revision selector.
    pub automation_revision: Option<String>,
    /// Exact StateFence bound by Kernel/Host authentication.
    pub state_fence: StateFence,
}

impl UserAutomationQuery {
    /// Validates the closed query shape.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.automation_id, "query.automation_id")?;
        if let Some(revision) = &self.automation_revision {
            text(revision, "query.automation_revision")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| UserAutomationError::Invalid("query.state_fence"))
    }
}

/// Closed Human/operator operation vocabulary for the UserAutomation surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationOperation {
    /// Create the first immutable revision.
    Create {
        /// Revision to persist through the existing canonical write path.
        revision: UserAutomationRevision,
    },
    /// List visible revisions.
    List {
        /// Whether retired tombstones are included in the read projection.
        include_retired: bool,
    },
    /// Read current status.
    Status {
        /// Stable automation identity.
        automation_id: String,
    },
    /// Read immutable execution/history records.
    History {
        /// Stable automation identity.
        automation_id: String,
    },
    /// Pause future admissions.
    Pause {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being paused.
        automation_revision: String,
    },
    /// Resume future admissions using the same immutable revision.
    Resume {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being resumed.
        automation_revision: String,
    },
    /// Edit by creating a new immutable superseding revision.
    Edit {
        /// Current revision that must be superseded.
        previous_revision: UserAutomationRevision,
        /// New immutable revision.
        revision: UserAutomationRevision,
    },
    /// Run once using an explicit nonce without mutating the schedule.
    RunNow {
        /// Stable automation identity.
        automation_id: String,
        /// Exact immutable revision to run.
        automation_revision: String,
        /// Explicit Human-issued manual nonce.
        nonce: String,
    },
    /// Retire/tombstone future work while preserving history.
    Remove {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being retired.
        automation_revision: String,
    },
    /// Inspect the last owner-issued failure.
    InspectLastFailure {
        /// Stable automation identity.
        automation_id: String,
    },
}

impl UserAutomationOperation {
    /// Validates the closed operator operation and revision lineage.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        match self {
            Self::Create { revision } => revision.validate(),
            Self::List { .. } => Ok(()),
            Self::Status { automation_id }
            | Self::History { automation_id }
            | Self::InspectLastFailure { automation_id } => {
                text(automation_id, "operation.automation_id")
            }
            Self::Pause {
                automation_id,
                automation_revision,
            }
            | Self::Resume {
                automation_id,
                automation_revision,
            }
            | Self::Remove {
                automation_id,
                automation_revision,
            } => {
                text(automation_id, "operation.automation_id")?;
                text(automation_revision, "operation.automation_revision")
            }
            Self::Edit {
                previous_revision,
                revision,
            } => revision.validate_supersedes(previous_revision),
            Self::RunNow {
                automation_id,
                automation_revision,
                nonce,
            } => {
                text(automation_id, "operation.automation_id")?;
                text(automation_revision, "operation.automation_revision")?;
                text(nonce, "operation.nonce")
            }
        }
    }
}

/// Authenticated Human operator intent; the owner service persists it through
/// the existing canonical write/ORS path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorIntent {
    /// Stable operation identity supplied by the authenticated surface.
    pub intent_id: String,
    /// Authenticated principal reference.
    pub principal_ref: String,
    /// Exact scope fence used for the operation.
    pub state_fence: StateFence,
    /// Closed operation payload.
    pub operation: UserAutomationOperation,
}

impl UserAutomationOperatorIntent {
    /// Validates the operation shape without issuing authority or writing.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.intent_id, "intent_id")?;
        text(&self.principal_ref, "principal_ref")?;
        self.state_fence
            .validate()
            .map_err(|_| UserAutomationError::Invalid("intent.state_fence"))?;
        self.operation.validate()
    }
}

/// Stable contract identity for the UserAutomation wire boundary.
pub fn user_automation_contract_identity() -> Result<ContractIdentity, UserAutomationError> {
    contract_identity(
        USER_AUTOMATION_CONTRACT_NAME,
        USER_AUTOMATION_CONTRACT_VERSION,
        &serde_json::json!({
            "preflight_selector": USER_AUTOMATION_PREFLIGHT_SELECTOR,
            "preflight_operation": USER_AUTOMATION_PREFLIGHT_OPERATION,
            "wake_contract": "eliot.runtime.wake-intent",
            "durable_job_contract": "eliot.foundation.protocol.durable-job",
            "immutable_revisions": true,
            "unknown_outcome_reconciliation": true,
        }),
    )
    .map_err(|error| UserAutomationError::Serialization(error.to_string()))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, UserAutomationError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn text(value: &str, field: &'static str) -> Result<(), UserAutomationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(UserAutomationError::Invalid(field));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(UserAutomationError::LimitExceeded(field));
    }
    Ok(())
}

fn list_text(values: &[String], field: &'static str) -> Result<(), UserAutomationError> {
    list_len(values.len(), field)?;
    for value in values {
        text(value, field)?;
    }
    Ok(())
}

fn list_len(length: usize, field: &'static str) -> Result<(), UserAutomationError> {
    if length > MAX_REFERENCES {
        Err(UserAutomationError::LimitExceeded(field))
    } else {
        Ok(())
    }
}

/// Existing Kernel notification state channel reused by UserAutomation.
pub use crate::module::notification_state::DeliveryChannel;
/// Existing canonical notification draft reused by the surface adapter.
pub use crate::module::notification_state::NotificationDraft;

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, SessionId, SourceId,
    };
    use eliot_security_contracts::PolicyFence;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let mut fence = StateFence::new(epoch, eliot_contracts::ResourceGeneration::genesis());
        fence.policy_revision = Some(PolicyRevision::genesis());
        fence
    }

    fn revision(state: UserAutomationConfigurationState) -> UserAutomationRevision {
        // The occurrence is the owner-issued versioned record of the normalized
        // result: the declared `America/New_York` wall clock, the offset the
        // pinned database revision applies to it, the instant that resolves to,
        // no transition, the unique disposition, and the compiled source digest
        // of the declared expression and calendar.
        let schedule = NormalizedSchedule {
            kind: ScheduleKind::Recurring,
            expression: "at 12:00".to_owned(),
            calendar: "gregorian".to_owned(),
            timezone: "America/New_York".to_owned(),
            dst_fold: DstFoldPolicy::First,
            dst_gap: DstGapPolicy::ShiftForward,
            start_at: "2026-09-21T00:00:00Z".to_owned(),
            end_at: None,
            next_occurrences: Vec::new(),
        };
        let source_digest = schedule.source_digest().expect("source digest");
        let mut schedule = schedule;
        schedule.next_occurrences = vec![format!(
            "{NORMALIZED_OCCURRENCE_ENCODING}|America/New_York|{}\
             |2026-09-21T12:00:00|-04:00|2026-09-21T16:00:00Z|-|UNIQUE|{source_digest}",
            user_automation_zones::PINNED_ZONE_DATABASE_RELEASE
        )];
        UserAutomationRevision {
            automation_id: "automation-1".to_owned(),
            revision: "revision-7".to_owned(),
            supersedes: None,
            owner_principal: "human-1".to_owned(),
            work_scope: AutomationWorkScope {
                scope_id: "scope-1".to_owned(),
                product_id: "eliot-test".to_owned(),
                workdir_ref: "workdir-1".to_owned(),
            },
            natural_language_intent: "run the qualified deterministic check".to_owned(),
            schedule,
            mode: UserAutomationExecutionMode::DeterministicProcess,
            task: AutomationTaskBinding {
                qualified_ref: "script:checks/v1".to_owned(),
                kind: AutomationTaskKind::QualifiedScript,
                capability_profile: AutomationCapabilityProfile {
                    model_access: false,
                    provider_access: false,
                    automation_scheduling: false,
                },
            },
            portable_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
            workdir_ref: "workdir-1".to_owned(),
            route_cost_policy: RouteCostPolicy {
                route_ref: "deterministic-local".to_owned(),
                max_cost_units: 1,
                max_duration_ms: 1_000,
                policy_revision: Some(PolicyRevision::genesis()),
            },
            provider_policy: ProviderFingerprintPolicy::DeterministicOnly,
            delivery_target: AutomationDeliveryTarget {
                target_ref: "human-1".to_owned(),
                channels: vec![DeliveryChannel::ControlBoard],
                recipient_refs: vec!["human-1".to_owned()],
            },
            preflight_contract_revision: USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION.to_owned(),
            resource_ceiling: AutomationResourceCeiling {
                max_runtime_ms: 1_000,
                max_output_bytes: 4_096,
                max_child_count: 0,
            },
            overlap_policy: OverlapPolicy::ForbidOverlap,
            recursion_policy: RecursionPolicy {
                allow_child_automation: false,
                max_child_depth: 0,
            },
            configuration_state: state,
            work_class: AutomationWorkClass::Maintenance,
            current_execution_refs: Vec::new(),
            execution_history_query_ref: "history:automation-1".to_owned(),
        }
    }

    fn request_metadata() -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("automation-request").expect("request id"),
            session_id: Some(SessionId::new("session-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("eliot-test").expect("product"),
            source_id: SourceId::new("eliot-user-automation").expect("source"),
            state_fence: fence(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        }
    }

    fn source_receipt(metadata: &RequestMetadata) -> ReceiptEnvelope {
        let core: eliot_receipts::ReceiptCore = serde_json::from_value(serde_json::json!({
            "contract": eliot_receipts::contract_identity().expect("contract"),
            "kind":"VERIFICATION",
            "work_scope": {"scope_id":"scope-1","product_id":"eliot-test","resource_generation":metadata.state_fence.resource_generation,"state_fence":metadata.state_fence},
            "task": null,
            "session": {"session_id":metadata.session_id,"authority_epoch":metadata.state_fence.authority_epoch,"state_fence":metadata.state_fence},
            "causal": {"state_fence":metadata.state_fence,"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]},
            "request": {"metadata":metadata,"state_fence":metadata.state_fence},
            "operation": {"operation_id":"operation-g08","request_id":metadata.request_id,"idempotency_key":"source-key","operation_kind":"g08_notification_projection","effect": "READ","state_fence":metadata.state_fence},
            "authority": {"authority_id":"authority-g08","authority_owner":"G-08","authority_epoch":metadata.state_fence.authority_epoch,"state_fence":metadata.state_fence,"allowed_effect":"READ","proof_ceiling":"SCOPED_VERIFICATION"},
            "artifacts": [], "verifier": null, "problem": null, "coordination": null,
            "disposition": {"kind":"SUCCESS","proof":"SCOPED_VERIFICATION"}
        }))
        .expect("receipt core fixture");
        ReceiptEnvelope::issue(core).expect("receipt fixture")
    }

    fn config_snapshot(metadata: &RequestMetadata) -> ConfigPolicySnapshot {
        let state_fence = metadata.state_fence.clone();
        ConfigPolicySnapshot {
            snapshot_id: "snapshot-1".to_owned(),
            machine_id: "machine-1".to_owned(),
            scope_id: USER_AUTOMATION_SCOPE.to_owned(),
            revision: PolicyRevision::genesis(),
            source_completeness: eliot_config::SourceCompleteness::Complete,
            settings: Vec::new(),
            policy_owner: eliot_config::HumanOwner {
                owner_ref: "human-1".to_owned(),
            },
            policy_fence: PolicyFence {
                policy_snapshot_id: "snapshot-1".to_owned(),
                state_fence: state_fence.clone(),
            },
            state_fence,
            parent_snapshot_id: None,
            rollback_of: None,
        }
    }

    fn notification(metadata: &RequestMetadata) -> AutomationFailureNotificationProjection {
        AutomationFailureNotificationProjection {
            canonical: NotificationDraft {
                notification_id: PlatformHandle::new("caller-id").expect("id"),
                severity: crate::NotificationSeverity::ActionRequired,
                subject: "Automation blocked".to_owned(),
                summary: "Configuration requires attention".to_owned(),
                evidence_handles: vec!["preflight-receipt".to_owned()],
                affected_scope: "automation-1".to_owned(),
                owner: "UserAutomation".to_owned(),
                required_action: "Review configuration".to_owned(),
                deadline_or_review: None,
                dedup_key: "caller-key".to_owned(),
                delivery_channels: vec![DeliveryChannel::ControlBoard],
                state_fence: metadata.state_fence.clone(),
            },
            subject: "Automation blocked".to_owned(),
            summary: "Configuration requires attention".to_owned(),
            recipients: vec![AutomationRecipient {
                principal: PlatformHandle::new("human-1").expect("principal"),
                role: AutomationRecipientRole::AuthorizedRole,
            }],
        }
    }

    #[test]
    fn canonical_automation_proof_covers_identity_revision_and_closed_preflight() {
        let metadata = request_metadata();
        let active = revision(UserAutomationConfigurationState::Active);
        active.validate().expect("valid revision");
        let mut edited = active.clone();
        edited.revision = "revision-8".to_owned();
        edited.supersedes = Some(active.revision.clone());
        edited
            .validate_supersedes(&active)
            .expect("valid supersession");

        let invocation = UserAutomationInvocation {
            automation_id: active.automation_id.clone(),
            automation_revision: active.revision.clone(),
            trigger: UserAutomationTrigger::Scheduled {
                occurrence_key: active.schedule.next_occurrences[0].clone(),
            },
            mode: active.mode,
            principal_ref: active.owner_principal.clone(),
            work_scope_ref: active.work_scope.scope_id.clone(),
            workdir_ref: active.workdir_ref.clone(),
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            child_depth: 0,
            provenance: None,
        };
        let projection = UserAutomationPreflightProjection {
            automation_id: active.automation_id.clone(),
            automation_revision: active.revision.clone(),
            mode: active.mode,
            occurrence_id: invocation.occurrence_identity().expect("occurrence"),
            revision: active,
            configuration_state: UserAutomationConfigurationState::Active,
            config_snapshot: config_snapshot(&metadata),
            source_receipt: source_receipt(&metadata),
            execution: UserAutomationExecutionProjection {
                current_execution_refs: Vec::new(),
                unresolved_reconciliation_refs: Vec::new(),
                history_query_ref: "history:automation-1".to_owned(),
            },
            observed_provider_fingerprint: None,
            trusted_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
            trusted_tool_definition_refs: vec!["tool-def@1".to_owned()],
            delivery_available: true,
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            child_depth: 0,
            failure: None,
        };
        let decision = projection
            .preflight(
                &invocation,
                &UserAutomationPreflightContext {
                    request_metadata: metadata.clone(),
                },
            )
            .expect("deterministic preflight");
        let UserAutomationPreflightDecision::Admitted { receipt } = decision else {
            panic!("valid deterministic occurrence must be admitted");
        };
        assert!(!receipt.model_access_allowed_after_admission);
        assert!(matches!(
            projection
                .revision
                .compile_wake_intent(&receipt.occurrence_id, metadata.state_fence.clone(),),
            Ok(WakeIntent {
                state: WakeIntentState::Pending,
                ..
            })
        ));

        let mut blocked = projection;
        blocked.configuration_state = UserAutomationConfigurationState::BlockedConfig;
        blocked.revision.configuration_state = UserAutomationConfigurationState::BlockedConfig;
        let reason = UserAutomationFailureReason::CanonicalBlockedConfig {
            class: "provider-fingerprint".to_owned(),
        };
        let failure = UserAutomationFailureProjection {
            failure_fingerprint: blocked
                .revision
                .failure_fingerprint(&reason)
                .expect("fingerprint"),
            reason,
            notification: notification(&metadata),
        };
        blocked.failure = Some(failure);
        assert!(matches!(
            blocked.preflight(
                &invocation,
                &UserAutomationPreflightContext {
                    request_metadata: metadata,
                }
            ),
            Ok(UserAutomationPreflightDecision::BlockedConfig { .. })
        ));
    }

    #[test]
    fn manual_nonce_and_schedule_replay_have_distinct_stable_identities() {
        let base = revision(UserAutomationConfigurationState::Active);
        let common = |trigger| UserAutomationInvocation {
            automation_id: base.automation_id.clone(),
            automation_revision: base.revision.clone(),
            trigger,
            mode: base.mode,
            principal_ref: base.owner_principal.clone(),
            work_scope_ref: base.work_scope.scope_id.clone(),
            workdir_ref: base.workdir_ref.clone(),
            trigger_origin: UserAutomationTriggerOrigin::Human,
            child_depth: 0,
            provenance: None,
        };
        let scheduled = common(UserAutomationTrigger::Scheduled {
            occurrence_key: base.schedule.next_occurrences[0].clone(),
        });
        let replay = scheduled.clone();
        let manual = common(UserAutomationTrigger::Manual {
            nonce: "manual-1".to_owned(),
        });
        assert_eq!(
            scheduled.occurrence_identity(),
            replay.occurrence_identity()
        );
        assert_ne!(
            scheduled.occurrence_identity(),
            manual.occurrence_identity()
        );
    }
}
