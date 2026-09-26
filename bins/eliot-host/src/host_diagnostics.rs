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
//! (`host_console_protocol::write_response`) is never contaminated. Every
//! projected Host request additionally routes its admitted
//! service start/stop/failure record to the `windows_event_log` wrapper,
//! where real delivery through #984's landed safe port happens; that
//! wrapper, not this facade, owns the mapping and the OS call, and this
//! facade never acquires Event Log FFI and never fakes delivery through
//! another sink.

use std::fmt;
use std::sync::OnceLock;

use eliot_host_state::HostState;
use tracing_subscriber::EnvFilter;

use crate::windows_event_log::AdmittedEvent;
use crate::{HostComposition, HostError, HostLaunchOptions};

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
    /// Windows Event Log delivery was requested from the facade, which
    /// routes to `tracing` only: this arm has no Event Log sink and must
    /// not fake one (real delivery lives in the `windows_event_log`
    /// wrapper over #984's landed safe port).
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
    /// Windows Event Log. Explicitly unavailable from the facade, which
    /// routes to `tracing` only: requesting it is a typed error, never
    /// silent delivery elsewhere and never FFI acquired inside this
    /// facade. Real delivery lives in the `windows_event_log` wrapper.
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

/// Notes Event Log sink unavailability where the sink cannot carry a record.
///
/// Consumes the live [`crate::windows_event_log::event_log_sink_status`]
/// answer: where #984's landed safe port is live (Windows) there is nothing
/// to note and the call stays silent; elsewhere the unavailability is
/// recorded as one `INFO` subordinate record on the shared `tracing` sink so
/// the standing seam state stays observable. Observation only: the record is
/// never a terminal emission and never changes results, order, retry, or
/// receipts.
pub fn note_event_log_sink_status() {
    if crate::windows_event_log::event_log_sink_status().is_ok() {
        return;
    }
    tracing::info!(
        target: HOST_DIAGNOSTICS_TARGET,
        event = "host.event_log_sink_unavailable",
        "event log sink unavailable; record stays on tracing"
    );
}

/// Typed evidence basis for one projected Host request record.
///
/// This is a diagnostic evidence classification, never a lifecycle: each
/// variant names what the single record carrying it proves about the
/// request. No variant transitions into another, orders after another, or
/// grants authority (I14.20 machines stay with their owners; I01.10 forbids
/// merging process liveness with generation or capability state).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRequestEvidence {
    /// The request was sighted but nothing positive is asserted: identities
    /// it failed to carry (malformed wire input) stay explicitly missing.
    Observed,
    /// The request passed typed admission; the record's installation and
    /// generation come from the admitted [`HostLaunchOptions`].
    Admitted,
    /// The serving Host process started; the record carries the observed
    /// process id, the same identity the owner binds in
    /// `HostProcessBinding` from [`std::process::id`].
    ProcessStarted,
    /// The host is ready to serve in this record's phase and operation
    /// scope; the record carries the opened [`HostComposition`] running
    /// state. Console-serving readiness only, never durable or global
    /// readiness (I01.10).
    SemanticallyReady,
    /// The durable effect committed (Host stop drained). Positional backing:
    /// construct only where [`HostComposition::stop`] returned `Ok`.
    DurableCommitted,
    /// The request was admitted but effected nothing: the stop found an
    /// already-stopped host, i.e. cancellation with proven no-effect
    /// (I14.14 `cancel_proven_no_effect`). Positional backing: construct
    /// only in the `Err(HostError::Stopped)` arm.
    Cancelled,
    /// The request failed. The record carries the typed [`HostError`]
    /// reason kind, or no reason where the outcome collapsed it (see
    /// [`HostRequestProjection::failed_without_reason`]). A failed-evidence
    /// record is an `INFO` subordinate, never a second terminal emission:
    /// the single terminal per failed operation stays with
    /// [`observe_terminal_error`].
    Failed,
    /// The outcome is genuinely unknown (a prior failure with the reason
    /// not in hand); never a positive assertion of any kind.
    Unknown,
}

impl HostRequestEvidence {
    /// Stable evidence name. Every variant maps to a distinct string;
    /// names are observations only, never lifecycle states.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Admitted => "admitted",
            Self::ProcessStarted => "process_started",
            Self::SemanticallyReady => "semantically_ready",
            Self::DurableCommitted => "durable_committed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

/// Console request kind projected from the binary's typed wire `Request`.
///
/// Record vocabulary mirroring the existing `Status`/`Stop` wire request;
/// the binary maps exhaustively at the dispatch site, so a malformed line
/// yields no value here (explicitly missing) instead of a guessed kind.
/// Not a lifecycle: names only which request a record is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostConsoleRequest {
    /// Console `Status` query.
    Status,
    /// Console `Stop` request.
    Stop,
}

impl HostConsoleRequest {
    /// Stable request name. Distinct per variant; observation only.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Stop => "stop",
        }
    }
}

/// Secret-free kind name for a [`HostError`], recorded in projections.
///
/// Only the variant discriminant is recorded, never the payload, so paths,
/// digests, and evidence handles inside the error cannot leak through this
/// field (I15.4, I07.20). This mirrors the binary's capsule kind mapping
/// for the diagnostic record; both matches are exhaustive over
/// [`HostError`], so a new variant forces both projections to stay in sync.
const fn project_host_error_reason(error: &HostError) -> &'static str {
    match error {
        HostError::State(_) => "state",
        HostError::Journal(_) => "journal",
        HostError::Installation(_) => "installation",
        HostError::Platform(_) => "platform",
        HostError::Stopped => "stopped",
        HostError::MissingInstallation => "missing_installation",
        HostError::ProcessContour(_) => "process_contour",
        HostError::StoreNotLive { .. } => "store_not_live",
        HostError::RecoveryRequired(_) => "recovery_required",
        #[cfg(windows)]
        HostError::StoreRecoveryRequired(_) => "store_recovery_required",
        #[cfg(windows)]
        HostError::WatchdogCoverageUnavailable(_) => "watchdog_coverage_unavailable",
        HostError::OwnerLeaseHeld => "owner_lease_held",
        HostError::OwnerLeaseRecovery(_) => "owner_lease_recovery",
    }
}

/// One projected Host request identity bundle.
///
/// Every identity is extracted from an existing owner-typed value held at
/// the construction site: the console request kind, the admitted service
/// operation ([`AdmittedEvent`], shared with the Event Log sink contract),
/// the launch installation handle and plan generation
/// ([`HostLaunchOptions`]), the process id, the opened composition running
/// state, the typed failure reason ([`HostError`] kind only), and the two
/// console receipt identities (live journal sequence from [`HostState`],
/// computed terminal exit value). Service ([`crate::SERVICE_NAME`]) and
/// phase ([`EntrypointStage`]) are stamped on every record; nothing here
/// creates a lifecycle or authority (I14.20, I01.10).
///
/// Missing identities stay explicitly missing, never guessed: each slot
/// renders with a `<slot>_missing` flag, and placeholder values (empty
/// text, zero, false) in a slot field are meaningless unless that flag
/// reads false. Readers must check the flag first. Only actual owner
/// state held at the construction site may support a positive assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRequestProjection {
    evidence: HostRequestEvidence,
    phase: EntrypointStage,
    request: Option<HostConsoleRequest>,
    operation: Option<AdmittedEvent>,
    installation: Option<BoundedField>,
    generation: Option<u64>,
    process: Option<u32>,
    running: Option<bool>,
    reason: Option<&'static str>,
    receipt_sequence: Option<u64>,
    receipt_exit: Option<i32>,
}

impl HostRequestProjection {
    /// Sighting only: the request was observed, nothing positive asserted.
    #[must_use]
    pub const fn observed(phase: EntrypointStage) -> Self {
        Self::bare(phase, HostRequestEvidence::Observed)
    }

    /// Typed admission backed by the admitted launch options, which supply
    /// the record's installation and generation identities.
    #[must_use]
    pub fn admitted(phase: EntrypointStage, options: &HostLaunchOptions) -> Self {
        Self::bare(phase, HostRequestEvidence::Admitted).with_launch_options(options)
    }

    /// Serving process started, backed by the observed process id.
    #[must_use]
    pub const fn process_started(phase: EntrypointStage, process_id: u32) -> Self {
        let mut projection = Self::bare(phase, HostRequestEvidence::ProcessStarted);
        projection.process = Some(process_id);
        projection
    }

    /// Ready to serve in this record's scope, backed by the opened host;
    /// the record carries its actual running state. Construct only where
    /// the host was actually observed running; otherwise the record must
    /// be [`HostRequestEvidence::Unknown`], never a false ready claim.
    #[must_use]
    pub const fn semantically_ready(phase: EntrypointStage, host: &HostComposition) -> Self {
        let mut projection = Self::bare(phase, HostRequestEvidence::SemanticallyReady);
        projection.running = Some(host.running());
        projection
    }

    /// Durable effect committed. Positional backing: construct only where
    /// [`HostComposition::stop`] returned `Ok` (or the composition is
    /// already stopped with no recorded shutdown failure).
    #[must_use]
    pub const fn durable_committed(phase: EntrypointStage) -> Self {
        Self::bare(phase, HostRequestEvidence::DurableCommitted)
    }

    /// Admitted but vacuous: the stop found an already-stopped host
    /// (proven no-effect). Positional backing: construct only in the
    /// `Err(HostError::Stopped)` arm.
    #[must_use]
    pub const fn cancelled(phase: EntrypointStage) -> Self {
        Self::bare(phase, HostRequestEvidence::Cancelled)
    }

    /// Failure backed by the typed reason extracted from the error in hand.
    #[must_use]
    pub const fn failed(phase: EntrypointStage, error: &HostError) -> Self {
        let mut projection = Self::bare(phase, HostRequestEvidence::Failed);
        projection.reason = Some(project_host_error_reason(error));
        projection
    }

    /// Failure with the reason genuinely unattributed: no [`HostError`] is
    /// in hand because the outcome collapsed it (boolean result) or the
    /// error is not `Host`-typed. The reason stays explicitly missing;
    /// subordinate records own the specific attribution.
    #[must_use]
    pub const fn failed_without_reason(phase: EntrypointStage) -> Self {
        Self::bare(phase, HostRequestEvidence::Failed)
    }

    /// Genuinely unknown outcome (a prior failure with the reason not in
    /// hand); asserts nothing positive.
    #[must_use]
    pub const fn unknown(phase: EntrypointStage) -> Self {
        Self::bare(phase, HostRequestEvidence::Unknown)
    }

    const fn bare(phase: EntrypointStage, evidence: HostRequestEvidence) -> Self {
        Self {
            evidence,
            phase,
            request: None,
            operation: None,
            installation: None,
            generation: None,
            process: None,
            running: None,
            reason: None,
            receipt_sequence: None,
            receipt_exit: None,
        }
    }

    /// Attaches the console request kind served or sighted at this site.
    #[must_use]
    pub const fn with_request(mut self, request: HostConsoleRequest) -> Self {
        self.request = Some(request);
        self
    }

    /// Attaches the admitted service operation this record is about
    /// (`ServiceStart`/`ServiceStop`; failure travels via the evidence,
    /// so a status query, which is not a service operation, stays missing).
    #[must_use]
    pub const fn with_operation(mut self, operation: AdmittedEvent) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Attaches the installation and generation from launch options
    /// already held at this site (admitted values only, never argv text).
    /// The installation handle is bounded with truncation honesty.
    #[must_use]
    pub fn with_launch_options(mut self, options: &HostLaunchOptions) -> Self {
        self.installation = Some(bound_field(options.installation().as_str()));
        self.generation = Some(options.transaction_plan_generation());
        self
    }

    /// Attaches the live journal sequence from state already in hand for
    /// the wire response. The state is never read for diagnostics: pass
    /// only a snapshot the owner path already computed.
    #[must_use]
    pub const fn with_journal_state(mut self, state: &HostState) -> Self {
        self.receipt_sequence = Some(state.sequence);
        self
    }

    /// Attaches the computed terminal exit value this run will terminate
    /// with. The value is actual (pure function of the build config); the
    /// exit itself follows this record.
    #[must_use]
    pub const fn with_terminal_exit(mut self, code: i32) -> Self {
        self.receipt_exit = Some(code);
        self
    }
}

/// Records one projected Host request identity bundle.
///
/// Observation only: every identity was decided or produced by its owner
/// before this call. The record goes to stderr over the shared `tracing`
/// subscriber at `INFO`, so the console-protocol stdout framing is
/// preserved and no projection ever becomes a second terminal emission.
/// All macro arguments are precomputed pure values, so a disabled event
/// evaluates no extra effectful operation.
pub fn observe_host_request(projection: &HostRequestProjection) {
    publish_projected_event_log_record(projection);
    let installation = projection.installation.as_ref();
    tracing::info!(
        target: HOST_DIAGNOSTICS_TARGET,
        event = "host.request",
        service = crate::SERVICE_NAME,
        phase = projection.phase.as_str(),
        evidence = projection.evidence.as_str(),
        request = projection.request.map_or("", HostConsoleRequest::as_str),
        request_missing = projection.request.is_none(),
        operation = projection.operation.map_or("", AdmittedEvent::as_str),
        operation_missing = projection.operation.is_none(),
        installation = installation.map_or("", BoundedField::text),
        installation_bytes = installation.map_or(0, BoundedField::original_bytes),
        installation_truncated = installation.is_some_and(BoundedField::truncated),
        installation_missing = installation.is_none(),
        generation = projection.generation.unwrap_or(0),
        generation_missing = projection.generation.is_none(),
        process = projection.process.unwrap_or(0),
        process_missing = projection.process.is_none(),
        running = projection.running.unwrap_or(false),
        running_missing = projection.running.is_none(),
        reason = projection.reason.unwrap_or(""),
        reason_missing = projection.reason.is_none(),
        receipt_sequence = projection.receipt_sequence.unwrap_or(0),
        receipt_sequence_missing = projection.receipt_sequence.is_none(),
        receipt_exit = projection.receipt_exit.unwrap_or(0),
        receipt_exit_missing = projection.receipt_exit.is_none(),
        "host request projection"
    );
}

/// Reports the Event Log record a projected Host request carries, if any.
///
/// The Event Log admits service start, stop, and failure only
/// ([`AdmittedEvent`]), so a projection reaches the sink when it both names
/// one of those operations and carries the evidence that actually supports
/// it: [`HostRequestEvidence::ProcessStarted`] for a start,
/// [`HostRequestEvidence::DurableCommitted`] for a stop, and
/// [`HostRequestEvidence::Failed`] for a failure. Every other evidence class
/// (sighted, admitted, ready, cancelled, unknown) asserts no completed
/// operation, so it stays on the stderr `tracing` sink and the Event Log is
/// never asked to record an outcome the owner did not produce (I14.20: the
/// diagnostic projects owner state, it never asserts one).
///
/// The submission is the same synchronous OS port
/// [`crate::windows_event_log::report_event`] uses, reached through
/// [`crate::windows_event_log::report_admitted_event`]. The insertion string
/// is built here from the projection's own frozen vocabulary (service, phase,
/// evidence, operation, and the bounded terminal exit when the record
/// carries one) and is then bounded by the wrapper, so no secret, payload,
/// free-text, or unredacted error text can cross into the Event Log
/// (I15.4, I07.20).
///
/// Delivery is attempted before the `tracing` record so a blocking or refused
/// port cannot reorder the two sinks. The outcome is diagnostics only: it
/// never changes the Host operation, result, order, retry, state, or receipt,
/// and the typed disposition is recorded on the same stderr sink.
fn publish_projected_event_log_record(projection: &HostRequestProjection) {
    let Some(operation) = projection.operation else {
        return;
    };
    if !operation.is_admitted_by(projection.evidence) {
        return;
    }
    let receipt_exit = projection
        .receipt_exit
        .map_or_else(String::new, |exit| format!(" exit={exit}"));
    let correlation = format!(
        "service={} phase={} evidence={} operation={}{receipt_exit}",
        crate::SERVICE_NAME,
        projection.phase.as_str(),
        projection.evidence.as_str(),
        operation.as_str(),
    );
    let outcome = match crate::windows_event_log::report_admitted_event(operation, &correlation) {
        // OS acceptance only: not a registered source, not installed message
        // resources, not downstream delivery, and not a Host result.
        Ok(delivery) => delivery.as_str(),
        Err(error) => error.as_str(),
    };
    tracing::info!(
        target: HOST_DIAGNOSTICS_TARGET,
        event = "host.event_log_delivery",
        service = crate::SERVICE_NAME,
        phase = projection.phase.as_str(),
        evidence = projection.evidence.as_str(),
        operation = operation.as_str(),
        outcome = outcome,
        "host event log delivery outcome"
    );
}
