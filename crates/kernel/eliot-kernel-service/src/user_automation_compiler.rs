//! Deterministic service-owned compiler for the deliberately small normalized
//! schedule expression language.
//!
//! The core validates the owner-normalized timezone, local fields, pinned zone
//! evidence, DST disposition, interval, and ordering. This compiler separately
//! interprets only explicit Gregorian UTC expressions and compares their
//! independently derived instants to that validated projection. It never reads
//! a clock, locale, environment variable, or timezone database.

use eliot_kernel_core::user_automation::{
    NormalizedSchedule, PINNED_ZONE_DATABASE_REVISION, ScheduleKind, UserAutomationError,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const GREGORIAN_UTC_CALENDAR: &str = "gregorian-utc";
const ONE_SHOT_PREFIX: &str = "utc:";
const INTERVAL_PREFIX: &str = "utc-interval:";
const UNSUPPORTED_CALENDAR: &str = "schedule.calendar.unsupported_or_ambiguous";
const UNSUPPORTED_EXPRESSION: &str = "schedule.expression.unsupported_or_ambiguous";
const EXPRESSION_KIND_MISMATCH: &str = "schedule.expression.kind_mismatch";
const INVALID_EXPRESSION_TIMESTAMP: &str = "schedule.expression.utc_timestamp";
const INVALID_INTERVAL: &str = "schedule.expression.interval_seconds";
const EXPRESSION_ARITHMETIC: &str = "schedule.expression.interval_arithmetic";
const INCOMPLETE_PROJECTION: &str = "schedule.next_occurrences.incomplete";
const UNRELATED_PROJECTION: &str = "schedule.next_occurrences.unrelated_to_compiled_expression";

/// Opaque evidence that the service compiler independently matched a schedule
/// projection to its declared UTC expression.
///
/// The fields and constructor remain private so callers can consume the
/// verified identities but cannot manufacture a successful compiler result.
/// The content digests bind the exact source and ordered occurrence set;
/// `pinned_zone_database_revision` names the pinned release those core digests
/// include.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedScheduleCompilation {
    source_digest: String,
    compiled_occurrences_digest: String,
    pinned_zone_database_revision: &'static str,
}

impl VerifiedScheduleCompilation {
    pub(crate) fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub(crate) fn compiled_occurrences_digest(&self) -> &str {
        &self.compiled_occurrences_digest
    }

    pub(crate) fn pinned_zone_database_revision(&self) -> &'static str {
        self.pinned_zone_database_revision
    }
}

/// Independently compiles a strict Gregorian UTC expression and verifies the
/// complete ordered occurrence projection against the core's validated
/// occurrence contract.
///
/// The number of recurring instants requested comes only from the bounded
/// projection length. Its supplied members never participate in expression
/// parsing or expected-instant generation.
pub(crate) fn verify_compiled_schedule(
    schedule: &NormalizedSchedule,
) -> Result<VerifiedScheduleCompilation, UserAutomationError> {
    let normalized = schedule.validated_occurrences_without_receipt()?;
    if schedule.calendar != GREGORIAN_UTC_CALENDAR {
        return Err(UserAutomationError::Invalid(UNSUPPORTED_CALENDAR));
    }

    let start = parse_schedule_instant(&schedule.start_at, "schedule.start_at")?;
    let end = schedule
        .end_at
        .as_deref()
        .map(|value| parse_schedule_instant(value, "schedule.end_at"))
        .transpose()?;
    if end.is_some_and(|end| end < start) {
        return Err(UserAutomationError::Invalid("schedule.end_at"));
    }

    let expected = match schedule.kind {
        ScheduleKind::OneShot => {
            let Some(anchor) = schedule.expression.strip_prefix(ONE_SHOT_PREFIX) else {
                return Err(UserAutomationError::Invalid(EXPRESSION_KIND_MISMATCH));
            };
            let instant = parse_expression_anchor(anchor)?;
            if instant < start || end.is_some_and(|end| instant > end) {
                return Err(UserAutomationError::Invalid(INCOMPLETE_PROJECTION));
            }
            vec![instant]
        }
        ScheduleKind::Recurring => {
            let Some(expression) = schedule.expression.strip_prefix(INTERVAL_PREFIX) else {
                return Err(UserAutomationError::Invalid(EXPRESSION_KIND_MISMATCH));
            };
            let Some((anchor, interval)) = expression.split_once('/') else {
                return Err(UserAutomationError::Invalid(UNSUPPORTED_EXPRESSION));
            };
            let anchor = parse_expression_anchor(anchor)?;
            let interval_seconds = parse_positive_interval(interval)?;
            first_interval_instants(anchor, interval_seconds, start, end, normalized.len())?
        }
    };

    if normalized.len() != expected.len()
        || normalized
            .iter()
            .zip(expected.iter())
            .any(|(occurrence, expected_instant)| occurrence.instant_seconds != *expected_instant)
    {
        return Err(UserAutomationError::Invalid(UNRELATED_PROJECTION));
    }

    let source_digest = schedule.source_digest()?;
    let compiled_occurrences_digest = schedule.compiled_occurrences_digest()?;
    let pinned_zone_database_revision = PINNED_ZONE_DATABASE_REVISION;
    Ok(VerifiedScheduleCompilation {
        source_digest,
        compiled_occurrences_digest,
        pinned_zone_database_revision,
    })
}

/// Parses a canonical second-precision UTC timestamp from an expression.
fn parse_expression_anchor(value: &str) -> Result<i64, UserAutomationError> {
    if !has_canonical_timestamp_shape(value, true) {
        return Err(UserAutomationError::Invalid(INVALID_EXPRESSION_TIMESTAMP));
    }
    parse_time_timestamp(value).ok_or(UserAutomationError::Invalid(INVALID_EXPRESSION_TIMESTAMP))
}

/// Parses an already core-validated schedule bound as an instant.
fn parse_schedule_instant(value: &str, field: &'static str) -> Result<i64, UserAutomationError> {
    if !has_canonical_timestamp_shape(value, false) {
        return Err(UserAutomationError::Invalid(field));
    }
    parse_time_timestamp(value).ok_or(UserAutomationError::Invalid(field))
}

/// Checks the canonical lexical envelope before delegating Gregorian range and
/// leap-day validation to the pinned Rust time parser.
fn has_canonical_timestamp_shape(value: &str, utc_only: bool) -> bool {
    let bytes = value.as_bytes();
    let suffix_is_canonical = if utc_only {
        bytes.len() == 20 && bytes[19] == b'Z'
    } else {
        (bytes.len() == 20 && bytes[19] == b'Z')
            || (bytes.len() == 25
                && matches!(bytes[19], b'+' | b'-')
                && bytes[22] == b':'
                && all_ascii_digits(&bytes[20..22])
                && all_ascii_digits(&bytes[23..25]))
    };
    if !suffix_is_canonical
        || !all_ascii_digits(&bytes[0..4])
        || bytes[4] != b'-'
        || !all_ascii_digits(&bytes[5..7])
        || bytes[7] != b'-'
        || !all_ascii_digits(&bytes[8..10])
        || bytes[10] != b'T'
        || !all_ascii_digits(&bytes[11..13])
        || bytes[13] != b':'
        || !all_ascii_digits(&bytes[14..16])
        || bytes[16] != b':'
        || !all_ascii_digits(&bytes[17..19])
    {
        return false;
    }

    let year = decimal_quad(bytes[0], bytes[1], bytes[2], bytes[3]);
    let second = decimal_pair(bytes[17], bytes[18]);
    year != 0 && second <= 59
}

/// Parses the lexical form after shape checks have established its length and
/// separators. `time` applies the numeric UTC offset and validates Gregorian
/// month/day ranges without consulting ambient machine state.
fn parse_time_timestamp(value: &str) -> Option<i64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

fn all_ascii_digits(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_digit)
}

fn decimal_quad(first: u8, second: u8, third: u8, fourth: u8) -> u16 {
    u16::from(first - b'0') * 1_000
        + u16::from(second - b'0') * 100
        + u16::from(third - b'0') * 10
        + u16::from(fourth - b'0')
}

fn decimal_pair(first: u8, second: u8) -> u8 {
    (first - b'0') * 10 + (second - b'0')
}

fn parse_positive_interval(value: &str) -> Result<u64, UserAutomationError> {
    if value.is_empty()
        || !value.is_ascii()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.starts_with('0')
    {
        return Err(UserAutomationError::Invalid(INVALID_INTERVAL));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or(UserAutomationError::Invalid(INVALID_INTERVAL))
}

/// Returns the first `count` recurrence instants at or after `start`, refusing
/// if the inclusive end bound leaves too few representable occurrences.
fn first_interval_instants(
    anchor: i64,
    interval_seconds: u64,
    start: i64,
    end: Option<i64>,
    count: usize,
) -> Result<Vec<i64>, UserAutomationError> {
    if count == 0 {
        return Err(UserAutomationError::Invalid(INCOMPLETE_PROJECTION));
    }

    let interval = i128::from(interval_seconds);
    let anchor = i128::from(anchor);
    let start = i128::from(start);
    let first_index = if anchor >= start {
        0
    } else {
        let distance = start
            .checked_sub(anchor)
            .ok_or(UserAutomationError::Invalid(EXPRESSION_ARITHMETIC))?;
        let quotient = distance / interval;
        if distance % interval == 0 {
            quotient
        } else {
            quotient
                .checked_add(1)
                .ok_or(UserAutomationError::Invalid(EXPRESSION_ARITHMETIC))?
        }
    };
    let first = first_index
        .checked_mul(interval)
        .and_then(|offset| anchor.checked_add(offset))
        .ok_or(UserAutomationError::Invalid(EXPRESSION_ARITHMETIC))?;
    let end_wide = end.map(i128::from);
    if end_wide.is_some_and(|end| first > end) {
        return Err(UserAutomationError::Invalid(INCOMPLETE_PROJECTION));
    }

    let mut current =
        i64::try_from(first).map_err(|_| UserAutomationError::Invalid(EXPRESSION_ARITHMETIC))?;
    let mut expected = Vec::with_capacity(count);
    for index in 0..count {
        if end.is_some_and(|end| current > end) {
            return Err(UserAutomationError::Invalid(INCOMPLETE_PROJECTION));
        }
        expected.push(current);
        if index + 1 < count {
            let next = i128::from(current)
                .checked_add(interval)
                .ok_or(UserAutomationError::Invalid(EXPRESSION_ARITHMETIC))?;
            if end_wide.is_some_and(|end| next > end) {
                return Err(UserAutomationError::Invalid(INCOMPLETE_PROJECTION));
            }
            current = i64::try_from(next)
                .map_err(|_| UserAutomationError::Invalid(EXPRESSION_ARITHMETIC))?;
        }
    }
    Ok(expected)
}
