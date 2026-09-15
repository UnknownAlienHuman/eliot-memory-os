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

use crate::HostObservationState;

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

/// Stable diagnostic name for a [`HostObservationState`].
///
/// Every variant maps to a distinct string; `Unknown` never collapses into
/// `AbsentOrStopped` and a stale observation never becomes `unavailable`.
#[must_use]
pub(crate) const fn host_observation_diagnostic(state: HostObservationState) -> &'static str {
    match state {
        HostObservationState::Running => "running",
        HostObservationState::AbsentOrStopped => "absent_or_stopped",
        HostObservationState::PidReused => "pid_reused",
        HostObservationState::ImageSubstituted => "image_substituted",
        HostObservationState::IdentityChanged => "identity_changed",
        HostObservationState::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_names_preserve_unknown_and_stale() {
        assert_eq!(
            host_observation_diagnostic(HostObservationState::Unknown),
            "unknown"
        );
        assert_ne!(
            host_observation_diagnostic(HostObservationState::Unknown),
            host_observation_diagnostic(HostObservationState::AbsentOrStopped)
        );
    }

    #[test]
    fn subscriber_installation_is_idempotent() {
        install_subscriber();
        install_subscriber();
        assert_eq!(SUBSCRIBER_INSTALLED.get(), Some(&true));
    }
}
