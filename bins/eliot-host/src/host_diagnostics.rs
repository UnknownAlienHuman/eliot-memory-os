//! Host structured diagnostics facade (F-LOG-HOST-0, issue #889).
//!
//! Architecture: A13.2 Host Supervisor outside the Kernel/Watchdog/Doctor
//! process failure domain; I01.10 health/readiness (diagnostics never promote
//! liveness into readiness).
//! Implementation: I13.11 diagnostic brief (problem model, never raw dumps);
//!   I14.20 canonical lifecycle vocabulary (diagnostics project owner states,
//!   never a second lifecycle); I15.4 secrets (no secret material in logs);
//!   I07.20 agent-facing error contract (typed codes stay with their owners).
//!
//! This module owns exactly one process-global `tracing` subscriber
//! installation plus the bounded, nonsecret field helpers used by Host
//! process-entry observations. It owns no lifecycle, admission, transport,
//! supervision, Store, generation, provider, credential, or repair authority:
//! a diagnostic record is evidence only and can never reconcile an
//! observation, authorize an effect, or promote liveness into
//! readiness/completion.
//!
//! Delivery is workspace `tracing` only, written to stderr so the
//! newline-delimited console protocol on stdout
//! (`host_console_protocol::write_response`) is never contaminated. The
//! Windows Event Log sink is an explicitly absent seam (see
//! [`DiagnosticSink`]): issue #984 (safe Windows Event Log port) is still
//! open and unlanded, so this facade must neither acquire Event Log FFI nor
//! fake delivery through another sink. Real Windows delivery smoke stays an
//! honest residual until #984 lands.

use std::fmt;
use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

/// Target for every event emitted by this facade.
pub const HOST_DIAGNOSTICS_TARGET: &str = "eliot_host::diagnostics";

/// Bound for short identity/code fields (stage names, terminal codes).
pub const MAX_DIAGNOSTIC_FIELD_BYTES: usize = 256;
/// Bound for free-text detail fields.
pub const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 1024;

/// Terminal code projecting `HostStopCode::DispatcherFailed` (`main.rs`,
/// `dispatcher_failed`, specific 12). Observation vocabulary only; the stop
/// code enum in the binary remains the sole lifecycle owner.
pub const HOST_TERMINAL_CODE_DISPATCHER_FAILED: &str = "dispatcher_failed";
/// Terminal code projecting `HostStopCode::ConsoleFailed` (`main.rs`,
/// `console_failed`, specific 13). This is the single HOST-0 reference
/// failure; later leaves (#891) own the remaining sites.
pub const HOST_TERMINAL_CODE_CONSOLE_FAILED: &str = "console_failed";

/// Process ownership claim for the facade's one global subscriber install.
static SUBSCRIBER_INSTALLED: OnceLock<()> = OnceLock::new();

/// Typed facade failures.
///
/// Diagnostics never change Host results, so these answers are
/// informational for the caller only; no variant authorizes a retry,
/// a fallback effect, or a lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostDiagnosticsError {
    /// The facade already owns the process-global subscriber installation.
    /// Repeat installation is bounded and non-panicking: the first install
    /// stands and no second owner is created.
    AlreadyOwned,
    /// Windows Event Log delivery was requested but is unavailable: issue
    /// #984 (safe Windows Event Log port) is still open and unlanded, so
    /// this facade has no Event Log sink and must not fake one.
    EventLogUnavailable,
}

impl fmt::Display for HostDiagnosticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOwned => write!(f, "host diagnostics subscriber already owned"),
            Self::EventLogUnavailable => {
                write!(f, "windows event log sink unavailable (see issue #984)")
            }
        }
    }
}

impl std::error::Error for HostDiagnosticsError {}

/// Diagnostic delivery sinks visible to the Host entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSink {
    /// Workspace `tracing` subscriber writing to stderr. Available.
    TracingStderr,
    /// Windows Event Log. Explicitly absent until #984 lands: requesting it
    /// is a typed error, never silent delivery elsewhere and never FFI
    /// acquired inside this facade.
    WindowsEventLog,
}

/// Reports whether a sink can carry Host diagnostics.
///
/// The Event Log arm always answers [`HostDiagnosticsError::EventLogUnavailable`];
/// absence of evidence remains missing, never a faked delivery.
pub fn sink_status(sink: DiagnosticSink) -> Result<(), HostDiagnosticsError> {
    match sink {
        DiagnosticSink::TracingStderr => Ok(()),
        DiagnosticSink::WindowsEventLog => Err(HostDiagnosticsError::EventLogUnavailable),
    }
}

/// Installs the one process-global Host diagnostics subscriber.
///
/// The subscriber is `tracing_subscriber::fmt` with an `env-filter` default
/// of `info` and the stderr writer, so the console-protocol stdout framing is
/// preserved. The first caller becomes the single owner; every later caller
/// receives [`HostDiagnosticsError::AlreadyOwned`] without panic,
/// replacement, or a second global install. Delivery setup is best-effort: a
/// foreign pre-existing global install (or any init failure) is kept as-is
/// and the owner claim still stands, because diagnostics must never gate
/// startup, retry, recurse, or change Host results.
pub fn install_host_diagnostics() -> Result<(), HostDiagnosticsError> {
    if SUBSCRIBER_INSTALLED.set(()).is_err() {
        return Err(HostDiagnosticsError::AlreadyOwned);
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    Ok(())
}

/// One truncated string plus its truncation honesty record.
fn truncate_to(value: &str, max_bytes: usize) -> (String, usize, bool) {
    let original_bytes = value.len();
    if original_bytes <= max_bytes {
        return (value.to_owned(), original_bytes, false);
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), original_bytes, true)
}

/// Bounded short field (stage names, terminal codes).
///
/// Pure and total: never panics and never allocates beyond the bound.
/// Callers must pass only nonsecret material; bounding limits size, not
/// sensitivity (I15.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedField {
    /// Retained prefix: at most [`MAX_DIAGNOSTIC_FIELD_BYTES`] bytes.
    text: String,
    /// Byte length of the input before truncation.
    original_bytes: usize,
    /// Whether the retained prefix is shorter than the input.
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
/// must only pass nonsecret material: no credentials, tokens, connection
/// strings, environment values, command lines, source/user/model payloads,
/// or arbitrary error `Debug`/`Display` (I15.4, I07.20).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDetail {
    /// Retained prefix: at most [`MAX_DIAGNOSTIC_DETAIL_BYTES`] bytes.
    text: String,
    /// Byte length of the input before truncation.
    original_bytes: usize,
    /// Whether the retained prefix is shorter than the input.
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

/// Bounds one free-text detail to [`MAX_DIAGNOSTIC_DETAIL_BYTES`], recording
/// the original length and whether truncation occurred.
#[must_use]
pub fn bound_detail(detail: &str) -> BoundedDetail {
    let (text, original_bytes, truncated) = truncate_to(detail, MAX_DIAGNOSTIC_DETAIL_BYTES);
    BoundedDetail {
        text,
        original_bytes,
        truncated,
    }
}

/// Frozen Host process-entry boundaries observed by `main`.
///
/// One variant per actual startup funnel phase. Later leaves (#891 lifecycle
/// boundaries, #893 module paths) own their library paths and extend
/// observations through their own serialized turns; they never redefine these
/// entry names, and no diagnostic name replaces an owner lifecycle type
/// (I14.20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntrypointStage {
    /// Diagnostics installed; the launch funnel is entered.
    Startup,
    /// Launch/config parsing accepted (`HostLaunchOptions::parse`).
    LaunchConfig,
    /// SCM service dispatch contour entered (`run_as_scm_service`).
    ScmDispatch,
    /// Stdin/stdout console protocol entered (`run_console`).
    ConsoleLoop,
    /// Durable shutdown drained with no orphans.
    ShutdownDrain,
}

impl EntrypointStage {
    /// Stable diagnostic name. Every variant maps to a distinct string;
    /// names are observations only, never lifecycle states.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::LaunchConfig => "launch_config",
            Self::ScmDispatch => "scm_dispatch",
            Self::ConsoleLoop => "console_loop",
            Self::ShutdownDrain => "shutdown_drain",
        }
    }
}

/// Records that the entrypoint reached one frozen boundary stage.
///
/// Observation only: the stage was already decided by its owner before this
/// call. All macro arguments are precomputed pure values, so a disabled
/// event evaluates no extra effectful operation.
pub fn observe_entrypoint(stage: EntrypointStage) {
    tracing::info!(
        target: HOST_DIAGNOSTICS_TARGET,
        event = "host.entrypoint_stage",
        stage = stage.as_str(),
        "host entrypoint reached stage"
    );
}

/// Records that the entrypoint reached one frozen boundary stage with a
/// bounded nonsecret detail.
///
/// The detail is truncated before formatting with its honesty record
/// attached; see [`bound_detail`] for the nonsecret caller contract.
pub fn observe_entrypoint_with_detail(stage: EntrypointStage, detail: &str) {
    let bounded = bound_detail(detail);
    tracing::info!(
        target: HOST_DIAGNOSTICS_TARGET,
        event = "host.entrypoint_stage",
        stage = stage.as_str(),
        detail = bounded.text(),
        detail_bytes = bounded.original_bytes(),
        detail_truncated = bounded.truncated(),
        "host entrypoint reached stage"
    );
}

/// Records the single terminal error boundary with its exact typed code.
///
/// One underlying failed operation yields exactly one terminal record here;
/// lower-phase entrypoint observations correlate by stage order, not by a
/// dedup cache. The code is bounded defensively; the HOST-0 reference call
/// site passes [`HOST_TERMINAL_CODE_CONSOLE_FAILED`], which projects
/// `HostStopCode::ConsoleFailed` without duplicating its lifecycle ownership
/// (I07.20, I14.20). Terminal receipt framing (capsule, SCM status, console
/// exit code) is untouched and still owns the process exit.
pub fn observe_terminal_error(code: &str) {
    let bounded = bound_field(code);
    tracing::error!(
        target: HOST_DIAGNOSTICS_TARGET,
        event = "host.terminal_error",
        code = bounded.text(),
        code_bytes = bounded.original_bytes(),
        code_truncated = bounded.truncated(),
        "host terminal error"
    );
}
