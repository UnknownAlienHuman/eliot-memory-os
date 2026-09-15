//! Bounded structured diagnostics for the independent Watchdog.
//!
//! Architecture: A8.1 Watchdog purpose; ARCH-WDG-01 independent supervision.
//! Implementation: I8.1 process and authority; I8.2 independent observation routes.
//!
//! This module owns only the process-global subscriber installation and the
//! small bounded field helpers used by diagnostic events. It owns no
//! supervision, admission, recovery, signature validation, restart-budget, or
//! process-effect authority; a log record is diagnostic evidence only and can
//! never reconcile an observation or authorize recovery.
//!
//! Observation vocabulary is preserved verbatim: unavailable, stale, unknown,
//! requested, admitted, attempted, and reconciled remain different
//! observations. Missing identity stays explicitly unavailable and is never
//! inferred from payload text. No signed payload body, secret, credential,
//! user content, or protected spool material is emitted; free-text fields are
//! truncated to the same bounds as the start-failure capsule.

use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

use crate::{HostObservationState, SpoolError};

/// Per-field ceiling for free-text diagnostic detail.
///
/// Mirrors `watchdog_service_status::START_FAILURE_DETAIL_MAX_CHARS` so the
/// typed class stays stable while the cause survives truncation secret-free.
pub(crate) const DIAGNOSTIC_DETAIL_MAX_CHARS: usize = 512;
/// Per-field ceiling for installation identity echoes.
pub(crate) const DIAGNOSTIC_IDENTITY_MAX_CHARS: usize = 128;

static SUBSCRIBER_INSTALLED: OnceLock<bool> = OnceLock::new();

/// Installs one bounded structured subscriber at binary startup.
///
/// The subscriber uses `tracing_subscriber::fmt` with an `env-filter` default
/// of `info` and the stderr writer. Installation is idempotent: repeat calls
/// cannot create a second global owner. Diagnostic initialization or output
/// failure uses the existing allowed fallback (stderr/capsule) and never
/// panics, takes a recovery action, or logs recursively.
pub fn install_subscriber() {
    let _ = SUBSCRIBER_INSTALLED.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
        true
    });
}

/// Truncates free-text diagnostic detail to [`DIAGNOSTIC_DETAIL_MAX_CHARS`]
/// characters.
///
/// The input is already secret-free (the registration nonce never enters
/// `SpoolError` or the start-failure detail); truncation only bounds bytes.
#[must_use]
pub(crate) fn truncate_diagnostic_detail(value: &str) -> String {
    truncate_chars(value, DIAGNOSTIC_DETAIL_MAX_CHARS)
}

/// Truncates an installation identity echo to
/// [`DIAGNOSTIC_IDENTITY_MAX_CHARS`] characters.
#[must_use]
pub(crate) fn truncate_diagnostic_identity(value: &str) -> String {
    truncate_chars(value, DIAGNOSTIC_IDENTITY_MAX_CHARS)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() > max_chars {
        value.chars().take(max_chars).collect()
    } else {
        value.to_owned()
    }
}

/// Stable diagnostic name for a [`HostObservationState`].
///
/// Every variant maps to a distinct string; `Unknown` never collapses into
/// `AbsentOrStopped` and a stale observation never becomes `unavailable`.
#[must_use]
pub(crate) const fn host_observation_diagnostic(state: &HostObservationState) -> &'static str {
    match state {
        HostObservationState::Running => "running",
        HostObservationState::AbsentOrStopped => "absent_or_stopped",
        HostObservationState::PidReused => "pid_reused",
        HostObservationState::ImageSubstituted => "image_substituted",
        HostObservationState::IdentityChanged => "identity_changed",
        HostObservationState::Unknown => "unknown",
    }
}

/// Stable diagnostic observation for a [`SpoolError`] without its free-text.
///
/// The inner string is never emitted (nested errors may contain protected
/// data); only the variant class is returned. `InvalidLease` (unavailable or
/// invalid) stays distinct from `LeaseStale` (stale) and `LeaseFenced`.
#[must_use]
pub(crate) const fn spool_error_observation(error: &SpoolError) -> &'static str {
    match error {
        SpoolError::Io(_) => "spool_io",
        SpoolError::InvalidProtectedRoot => "invalid_protected_root",
        SpoolError::Serialization(_) => "serialization",
        SpoolError::Database(_) => "database",
        SpoolError::Corrupt(_) => "corrupt",
        SpoolError::InvalidLease(_) => "unavailable_or_invalid",
        SpoolError::LeaseStale(_) => "stale",
        SpoolError::LeaseFenced(_) => "fenced",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_detail_truncation_is_bounded() {
        let long = "x".repeat(DIAGNOSTIC_DETAIL_MAX_CHARS + 16);
        assert_eq!(
            truncate_diagnostic_detail(&long).chars().count(),
            DIAGNOSTIC_DETAIL_MAX_CHARS
        );
        assert_eq!(truncate_diagnostic_detail("short"), "short");
    }

    #[test]
    fn diagnostic_identity_truncation_is_bounded() {
        let long = "y".repeat(DIAGNOSTIC_IDENTITY_MAX_CHARS + 8);
        assert_eq!(
            truncate_diagnostic_identity(&long).chars().count(),
            DIAGNOSTIC_IDENTITY_MAX_CHARS
        );
    }

    #[test]
    fn observation_names_preserve_unknown_and_stale() {
        assert_eq!(
            host_observation_diagnostic(&HostObservationState::Unknown),
            "unknown"
        );
        assert_ne!(
            host_observation_diagnostic(&HostObservationState::Unknown),
            host_observation_diagnostic(&HostObservationState::AbsentOrStopped)
        );
        let stale = SpoolError::LeaseStale("stale-cause".to_owned());
        let unavailable = SpoolError::InvalidLease("missing".to_owned());
        assert_eq!(spool_error_observation(&stale), "stale");
        assert_eq!(
            spool_error_observation(&unavailable),
            "unavailable_or_invalid"
        );
        assert_ne!(
            spool_error_observation(&stale),
            spool_error_observation(&unavailable)
        );
    }

    #[test]
    fn subscriber_installation_is_idempotent() {
        install_subscriber();
        install_subscriber();
        assert_eq!(SUBSCRIBER_INSTALLED.get(), Some(&true));
    }
}

/// Inline unit coverage for the bounded diagnostic helpers (738/2-inline).
///
/// Issue #738 explicitly authorizes private-path cases to use inline tests
/// beside an owned call site without exporting a production test API, so
/// this module exercises the `pub(crate)` helpers (and the private
/// `truncate_chars` they share) with minimal plain-value inputs. No
/// production signature, visibility, dependency, or lint configuration is
/// changed here.
#[cfg(test)]
mod diagnostics_unit_tests {
    use super::*;

    #[test]
    fn diagnostic_detail_bound_matches_documented_ceiling() {
        assert_eq!(DIAGNOSTIC_DETAIL_MAX_CHARS, 512);
        assert_eq!(truncate_diagnostic_detail("plain"), "plain");
        let long = "x".repeat(DIAGNOSTIC_DETAIL_MAX_CHARS + 4);
        let truncated = truncate_diagnostic_detail(&long);
        assert_eq!(truncated.chars().count(), DIAGNOSTIC_DETAIL_MAX_CHARS);
        assert_eq!(truncated, "x".repeat(DIAGNOSTIC_DETAIL_MAX_CHARS));
    }

    #[test]
    fn diagnostic_identity_bound_matches_documented_ceiling() {
        assert_eq!(DIAGNOSTIC_IDENTITY_MAX_CHARS, 128);
        assert_eq!(truncate_diagnostic_identity("plain"), "plain");
        let long = "y".repeat(DIAGNOSTIC_IDENTITY_MAX_CHARS + 4);
        let truncated = truncate_diagnostic_identity(&long);
        assert_eq!(truncated.chars().count(), DIAGNOSTIC_IDENTITY_MAX_CHARS);
        assert_eq!(
            truncate_chars("plain", DIAGNOSTIC_IDENTITY_MAX_CHARS),
            "plain"
        );
    }

    #[test]
    fn spool_error_observation_covers_documented_classes() {
        assert_eq!(
            spool_error_observation(&SpoolError::InvalidLease("missing".to_owned())),
            "unavailable_or_invalid"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::LeaseStale("stale".to_owned())),
            "stale"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::LeaseFenced("fenced".to_owned())),
            "fenced"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::InvalidProtectedRoot),
            "invalid_protected_root"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::Serialization("s".to_owned())),
            "serialization"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::Database("d".to_owned())),
            "database"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::Corrupt("c".to_owned())),
            "corrupt"
        );
        assert_eq!(
            spool_error_observation(&SpoolError::Io(std::io::Error::other("io"))),
            "spool_io"
        );
    }
}
