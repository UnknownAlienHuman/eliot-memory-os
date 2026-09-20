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

use crate::{
    HostObservationState, SpoolError, WatchdogRuntimeReadback, WatchdogRuntimeState,
    WatchdogSelfAdmissionError,
};

/// Target for every event emitted by this facade.
///
/// Scoped so console-protocol stdout framing is never contaminated; delivery
/// is workspace `tracing` only to stderr via [`install_subscriber`]. The
/// Windows Event Log sink stays explicitly absent (see [`DiagnosticSink`]).
pub const WATCHDOG_DIAGNOSTICS_TARGET: &str = "eliot_watchdog::diagnostics";

/// Bound for short identity/code fields (observation names, terminal codes).
pub const MAX_DIAGNOSTIC_FIELD_BYTES: usize = 256;
/// Bound for free-text detail fields.
pub const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 1024;

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

/// Per-field ceiling for free-text diagnostic detail (port of #738).
///
/// Mirrors `watchdog_service_status::START_FAILURE_DETAIL_MAX_CHARS` so the
/// typed class stays stable while the cause survives truncation secret-free.
pub(crate) const DIAGNOSTIC_DETAIL_MAX_CHARS: usize = 512;
/// Per-field ceiling for installation identity echoes (port of #738).
pub(crate) const DIAGNOSTIC_IDENTITY_MAX_CHARS: usize = 128;

/// Truncates free-text diagnostic detail to [`DIAGNOSTIC_DETAIL_MAX_CHARS`]
/// characters (port of #738).
///
/// The input is already secret-free (the registration nonce never enters
/// `SpoolError` or the start-failure detail); truncation only bounds bytes.
#[must_use]
#[allow(dead_code, reason = "port of #738 truncation helper; wiring blocked on root-lock preparation")]
pub(crate) fn truncate_diagnostic_detail(value: &str) -> String {
    truncate_chars(value, DIAGNOSTIC_DETAIL_MAX_CHARS)
}

/// Truncates an installation identity echo to
/// [`DIAGNOSTIC_IDENTITY_MAX_CHARS`] characters (port of #738).
#[must_use]
#[allow(dead_code, reason = "port of #738 truncation helper; wiring blocked on root-lock preparation")]
pub(crate) fn truncate_diagnostic_identity(value: &str) -> String {
    truncate_chars(value, DIAGNOSTIC_IDENTITY_MAX_CHARS)
}

#[allow(dead_code, reason = "port of #738 truncation helper; wiring blocked on root-lock preparation")]
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

/// Stable diagnostic observation for a [`SpoolError`] without its free-text
/// (port of #738).
///
/// The inner string is never emitted (nested errors may contain protected
/// data); only the variant class is returned. `InvalidLease` (unavailable or
/// invalid) stays distinct from `LeaseStale` (stale) and `LeaseFenced`.
#[must_use]
#[allow(dead_code, reason = "port of #738 observation helper; wiring blocked on root-lock preparation")]
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

/// One truncated string plus its truncation honesty record.
fn truncate_to(value: &str, max_bytes: usize) -> (String, usize, bool) {
    let original_bytes = value.len();
    if original_bytes <= max_bytes {
        return (value.to_owned(), original_bytes, false);
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (value[..end].to_owned(), original_bytes, true)
}

/// Bounded short field (observation names, terminal codes).
///
/// Pure and total: never panics and never allocates beyond the bound.
/// Callers must pass only nonsecret material; bounding limits size, not
/// sensitivity (I15.4: no lease/nonce/credential/path/env/payload material).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedField {
    text: String,
    original_bytes: usize,
    truncated: bool,
}

impl BoundedField {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn original_bytes(&self) -> usize {
        self.original_bytes
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Bounds one short field to [`MAX_DIAGNOSTIC_FIELD_BYTES`].
#[must_use]
pub fn bound_field(value: &str) -> BoundedField {
    let (text, original_bytes, truncated) = truncate_to(value, MAX_DIAGNOSTIC_FIELD_BYTES);
    BoundedField {
        text,
        original_bytes,
        truncated,
    }
}

/// Bounded free-text detail with truncation honesty.
///
/// Pure and total: never panics and never allocates beyond the bound plus
/// the retained prefix. It never inspects content for secrets, so callers
/// must only pass nonsecret material: no credentials, tokens, nonces,
/// lease bodies, raw paths, config/env/source/user data, or arbitrary error
/// `Debug`/`Display` (I15.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDetail {
    text: String,
    original_bytes: usize,
    truncated: bool,
}

impl BoundedDetail {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn original_bytes(&self) -> usize {
        self.original_bytes
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Bounds one free-text detail to [`MAX_DIAGNOSTIC_DETAIL_BYTES`].
#[must_use]
pub fn bound_detail(detail: &str) -> BoundedDetail {
    let (text, original_bytes, truncated) = truncate_to(detail, MAX_DIAGNOSTIC_DETAIL_BYTES);
    BoundedDetail {
        text,
        original_bytes,
        truncated,
    }
}

/// Typed facade failures.
///
/// Diagnostics never change Watchdog results, so this answer is
/// informational for the caller only; no variant authorizes a retry,
/// a fallback effect, or a lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogDiagnosticsError {
    /// Windows Event Log delivery was requested but is unavailable: issue
    /// #984 (safe Windows Event Log port) is still open and unlanded, so
    /// this facade has no Event Log sink and must not fake one.
    EventLogUnavailable,
}

impl std::fmt::Display for WatchdogDiagnosticsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventLogUnavailable => {
                write!(f, "windows event log sink unavailable (see issue #984)")
            }
        }
    }
}

impl std::error::Error for WatchdogDiagnosticsError {}

/// Diagnostic delivery sinks visible to the Watchdog entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSink {
    /// Workspace `tracing` subscriber writing to stderr. Available.
    TracingStderr,
    /// Windows Event Log. Explicitly absent until #984 lands: requesting it
    /// is a typed error, never silent delivery elsewhere and never FFI
    /// acquired inside this facade.
    WindowsEventLog,
}

/// Reports whether a sink can carry Watchdog diagnostics.
///
/// The Event Log arm always answers
/// [`WatchdogDiagnosticsError::EventLogUnavailable`]; absence of evidence
/// remains missing, never a faked delivery.
pub const fn sink_status(sink: DiagnosticSink) -> Result<(), WatchdogDiagnosticsError> {
    match sink {
        DiagnosticSink::TracingStderr => Ok(()),
        DiagnosticSink::WindowsEventLog => Err(WatchdogDiagnosticsError::EventLogUnavailable),
    }
}

/// Publication readback observations.
///
/// A publication request, an owner-observed publication, an absent file, a
/// stale lease, and a conflicting/fenced binding are different facts.
/// Repeated observations retain replay/observation identity rather than
/// inventing another publication or success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationObservation {
    Requested,
    Observed,
    Absent,
    Stale,
    Conflicting,
}

impl PublicationObservation {
    /// Stable diagnostic name. Every variant maps to a distinct string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Observed => "observed",
            Self::Absent => "absent",
            Self::Stale => "stale",
            Self::Conflicting => "conflicting",
        }
    }
}

/// Service registration readback observations.
///
/// An SCM acknowledgement (service exists / start pending) is never
/// readiness evidence: only an exact matching readback is `Observed`.
/// `Unknown` is preserved verbatim and never promoted into observed,
/// absent, or mismatched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationObservation {
    Requested,
    Observed,
    Absent,
    Mismatched,
    Unknown,
}

impl ServiceRegistrationObservation {
    /// Stable diagnostic name. Every variant maps to a distinct string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Observed => "observed",
            Self::Absent => "absent",
            Self::Mismatched => "mismatched",
            Self::Unknown => "unknown",
        }
    }
}

/// Stable diagnostic name for a [`WatchdogRuntimeState`].
///
/// Every variant maps to a distinct string; `Unknown` never collapses into
/// a terminal absence and `Starting` never becomes `Running`.
#[must_use]
pub const fn watchdog_runtime_state_diagnostic(state: WatchdogRuntimeState) -> &'static str {
    match state {
        WatchdogRuntimeState::Absent => "absent",
        WatchdogRuntimeState::Stopped => "stopped",
        WatchdogRuntimeState::Starting => "starting",
        WatchdogRuntimeState::Running => "running",
        WatchdogRuntimeState::Stopping => "stopping",
        WatchdogRuntimeState::Unknown => "unknown",
    }
}

/// Stable diagnostic name for a [`WatchdogRuntimeReadback`].
///
/// The `Matching` arm preserves the exact lifecycle state; an SCM
/// acknowledgement without an exact match stays `mismatched` or `unknown`
/// and is never reported as an exact running observation.
#[must_use]
pub fn watchdog_readback_diagnostic(readback: &WatchdogRuntimeReadback) -> &'static str {
    match readback {
        WatchdogRuntimeReadback::Matching { state, .. } => {
            watchdog_runtime_state_diagnostic(*state)
        }
        WatchdogRuntimeReadback::Absent => "absent",
        WatchdogRuntimeReadback::Mismatched => "mismatched",
        WatchdogRuntimeReadback::Unknown => "unknown",
    }
}

/// Stable diagnostic name for a [`WatchdogSelfAdmissionError`].
///
/// Every fail-closed outcome maps to a distinct string; `Timeout` never
/// collapses into absence or mismatch.
#[must_use]
pub const fn self_admission_error_diagnostic(error: WatchdogSelfAdmissionError) -> &'static str {
    match error {
        WatchdogSelfAdmissionError::CurrentProcessUnavailable => "current_unavailable",
        WatchdogSelfAdmissionError::RegistrationAbsent => "registration_absent",
        WatchdogSelfAdmissionError::RegistrationMismatched => "registration_mismatched",
        WatchdogSelfAdmissionError::ServiceStopped => "service_stopped",
        WatchdogSelfAdmissionError::ServiceStopping => "service_stopping",
        WatchdogSelfAdmissionError::Timeout => "timeout",
    }
}

/// Records one publication boundary observation.
///
/// Observation only: the publication fact was already decided by its owner
/// before this call. `detail` must be nonsecret (I15.4); it is truncated
/// before formatting with its honesty record attached. Sink drop/failure
/// cannot affect the semantic return, state, or cursor.
pub fn observe_publication(observation: PublicationObservation, detail: &str) {
    let bounded = bound_detail(detail);
    tracing::debug!(
        target: WATCHDOG_DIAGNOSTICS_TARGET,
        event = "watchdog.publication_observed",
        observation = observation.as_str(),
        detail = bounded.text(),
        detail_bytes = bounded.original_bytes(),
        detail_truncated = bounded.truncated(),
        "watchdog publication observed"
    );
}

/// Records one service registration boundary observation.
///
/// Observation only: the registration fact was already decided by its owner.
/// `detail` must be nonsecret (I15.4); PID, start time, image bytes,
/// generation digests, fence nonces, and raw paths are never passed here —
/// identity is preserved as distinctions (`observed` vs `mismatched` vs
/// `unknown`), never as values.
pub fn observe_service_registration(observation: ServiceRegistrationObservation, detail: &str) {
    let bounded = bound_detail(detail);
    tracing::debug!(
        target: WATCHDOG_DIAGNOSTICS_TARGET,
        event = "watchdog.service_observed",
        observation = observation.as_str(),
        detail = bounded.text(),
        detail_bytes = bounded.original_bytes(),
        detail_truncated = bounded.truncated(),
        "watchdog service registration observed"
    );
}

/// Records one SCM launch inspection observation.
///
/// The inspected readback name (`absent`, `starting`, `running`, ...) is a
/// read-only projection; an SCM acknowledgement is never readiness evidence
/// and `unknown` is preserved verbatim.
pub fn observe_scm_inspection(readback: &WatchdogRuntimeReadback, detail: &str) {
    let bounded = bound_detail(detail);
    tracing::debug!(
        target: WATCHDOG_DIAGNOSTICS_TARGET,
        event = "watchdog.scm_inspection_observed",
        observation = watchdog_readback_diagnostic(readback),
        detail = bounded.text(),
        detail_bytes = bounded.original_bytes(),
        detail_truncated = bounded.truncated(),
        "watchdog SCM inspection observed"
    );
}

/// Records that self-admission reached one timing boundary.
///
/// Observation only: the timing decision was already made from the injected
/// [`crate::WatchdogSelfAdmissionProbe`] clock (`now_ms`) against the fixed
/// [`crate::WATCHDOG_SELF_ADMISSION_DEADLINE_MS`]; this call adds no clock,
/// sleep, retry, or deadline. `elapsed_ms` and `deadline_ms` are plain
/// numbers from the probe and never secret. Sink drop/failure cannot change
/// the admission return, sleeps, or deadline decision.
pub fn observe_self_admission_timing(outcome: &str, elapsed_ms: u64, deadline_ms: u64) {
    let bounded = bound_field(outcome);
    tracing::debug!(
        target: WATCHDOG_DIAGNOSTICS_TARGET,
        event = "watchdog.self_admission_timing",
        outcome = bounded.text(),
        outcome_bytes = bounded.original_bytes(),
        outcome_truncated = bounded.truncated(),
        elapsed_ms = elapsed_ms,
        deadline_ms = deadline_ms,
        "watchdog self-admission timing observed"
    );
}

/// Records one Host observation with identity-presence honesty.
///
/// `state` uses [`host_observation_diagnostic`] so `Unknown` never collapses;
/// `has_identity` records only whether a process identity accompanies the
/// observation, never its PID/start/image values (I15.4). An SCM
/// acknowledgement without an exact process identity stays `unknown`, never
/// `running`/readiness.
pub fn observe_host_observation(state: HostObservationState, has_identity: bool) {
    tracing::debug!(
        target: WATCHDOG_DIAGNOSTICS_TARGET,
        event = "watchdog.host_observation_diagnostic",
        observation = host_observation_diagnostic(state),
        has_identity = has_identity,
        "watchdog host observation diagnosed"
    );
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
            host_observation_diagnostic(HostObservationState::Unknown),
            "unknown"
        );
        assert_ne!(
            host_observation_diagnostic(HostObservationState::Unknown),
            host_observation_diagnostic(HostObservationState::AbsentOrStopped)
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
