//! Kernel structured diagnostics facade (F-LOG-KERNEL-0, issue #895).
//!
//! Architecture: A13.2 Kernel and failure domains; A8.1 process/authority
//! split; I01.10 health/readiness (diagnostics never promote liveness into
//! readiness).
//! Implementation: I13.11 diagnostic brief (problem model, never raw dumps);
//!   I14.20 canonical lifecycle vocabulary (diagnostics project owner states,
//!   never a second lifecycle); I15.4 secrets (no secret material in logs);
//!   I15.2 principal/session binding (no identity inference from payload
//!   text); I07.20 agent-facing error contract (typed codes stay with their
//!   owners); I07.05 named pipes (no transport material in logs).
//!
//! This module owns exactly one process-global `tracing` subscriber
//! installation plus the bounded, nonsecret field helpers used by Kernel
//! process-entry observations. It owns no lifecycle, admission, transport,
//! supervision, Store, generation, provider, credential, or repair authority:
//! a diagnostic record is evidence only and can never reconcile an
//! observation, authorize an effect, or promote liveness into
//! readiness/completion.
//!
//! Delivery is workspace `tracing` only, written to stderr so protocol
//! stdout framing is never contaminated. The Windows Event Log sink is an
//! explicitly absent seam (see [`DiagnosticSink`]): issue #984 (safe Windows
//! Event Log port) is still open and unlanded, so this facade must neither
//! acquire Event Log FFI nor fake delivery through another sink.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use eliot_observability::field_policy::{
    self, RedactedHandle, TelemetryFieldFamily, requires_evidence_handle, scrub_labels_for_emit,
};
use tracing_subscriber::EnvFilter;

/// Target for every event emitted by this facade.
pub const KERNEL_DIAGNOSTICS_TARGET: &str = "eliot_kernel::diagnostics";

/// Bound for short identity/code fields (stage names, terminal codes).
pub const MAX_DIAGNOSTIC_FIELD_BYTES: usize = 256;
/// Bound for free-text detail fields.
pub const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 1024;

/// Telemetry family governing every record this facade emits.
///
/// Kernel records are operational-log records: they reach span fields and the
/// rolling-log sink through `tracing`, so the emission boundary is
/// [`scrub_labels_for_emit`] under this family (issue #1842, I16.3/I16.9).
const KERNEL_TELEMETRY_FAMILY: TelemetryFieldFamily = TelemetryFieldFamily::OperationalLog;

/// Label key for one bounded detail value on the emission path.
const DETAIL_LABEL_KEY: &str = "detail";
/// Label key for one bounded short identity/code value on the emission path.
const FIELD_LABEL_KEY: &str = "code";

/// Process ownership claim for the facade's one global subscriber install.
static SUBSCRIBER_INSTALLED: OnceLock<()> = OnceLock::new();

/// Typed facade failures.
///
/// Diagnostics never change Kernel results, so these answers are
/// informational for the caller only; no variant authorizes a retry,
/// a fallback effect, or a lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelDiagnosticsError {
    /// The facade already owns the process-global subscriber installation.
    /// Repeat installation is bounded and non-panicking: the first install
    /// stands and no second owner is created.
    AlreadyOwned,
    /// Windows Event Log delivery was requested but is unavailable: issue
    /// #984 (safe Windows Event Log port) is still open and unlanded, so
    /// this facade has no Event Log sink and must not fake one.
    EventLogUnavailable,
}

impl fmt::Display for KernelDiagnosticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOwned => write!(f, "kernel diagnostics subscriber already owned"),
            Self::EventLogUnavailable => {
                write!(f, "windows event log sink unavailable (see issue #984)")
            }
        }
    }
}

impl std::error::Error for KernelDiagnosticsError {}

/// Diagnostic delivery sinks visible to the Kernel entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSink {
    /// Workspace `tracing` subscriber writing to stderr. Available.
    TracingStderr,
    /// Windows Event Log. Explicitly absent until #984 lands: requesting it
    /// is a typed error, never silent delivery elsewhere and never FFI
    /// acquired inside this facade.
    WindowsEventLog,
}

/// Reports whether a sink can carry Kernel diagnostics.
///
/// The Event Log arm always answers [`KernelDiagnosticsError::EventLogUnavailable`];
/// absence of evidence remains missing, never a faked delivery.
pub fn sink_status(sink: DiagnosticSink) -> Result<(), KernelDiagnosticsError> {
    match sink {
        DiagnosticSink::TracingStderr => Ok(()),
        DiagnosticSink::WindowsEventLog => Err(KernelDiagnosticsError::EventLogUnavailable),
    }
}

/// Installs the one process-global Kernel diagnostics subscriber.
///
/// The subscriber is `tracing_subscriber::fmt` with an `env-filter` default
/// of `info` and the stderr writer, so protocol stdout framing is preserved.
/// The first caller becomes the single owner; every later caller receives
/// [`KernelDiagnosticsError::AlreadyOwned`] without panic, replacement, or
/// a second global install. Delivery setup is best-effort: a foreign
/// pre-existing global install (or any init failure) is kept as-is and the
/// owner claim still stands, because diagnostics must never gate startup,
/// retry, recurse, or change Kernel results.
pub fn install_kernel_diagnostics() -> Result<(), KernelDiagnosticsError> {
    if SUBSCRIBER_INSTALLED.set(()).is_err() {
        return Err(KernelDiagnosticsError::AlreadyOwned);
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
/// Bounding limits size, not sensitivity: the value is screened against the
/// shared telemetry field policy before it can reach a span field or a
/// rolling-log line, so a recognisable secret leaves the field and becomes an
/// immutable redacted evidence handle (issue #1842, I16.3/I15.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedField {
    /// Retained prefix: at most [`MAX_DIAGNOSTIC_FIELD_BYTES`] bytes, unless
    /// the value was redacted under the field policy.
    text: String,
    /// Byte length of the input before truncation.
    original_bytes: usize,
    /// Whether the retained prefix is shorter than the input.
    truncated: bool,
    /// Recorded handle when the value was redacted, `None` otherwise.
    redaction: Option<RedactedHandle>,
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

    /// Redaction status recorded for this value, or `None` when the value
    /// passed the policy gate unchanged.
    ///
    /// A handle is present exactly when the emitted text is not the input, so
    /// a reader can tell a redacted field from a genuinely short one.
    #[must_use]
    pub fn redaction_status(&self) -> Option<&str> {
        self.redaction
            .as_ref()
            .map(|handle| handle.redaction_status.as_str())
    }

    /// Immutable evidence handle standing in for the redacted value, or
    /// `None` when no redaction occurred.
    #[must_use]
    pub fn evidence_handle(&self) -> Option<&str> {
        self.redaction.as_ref().map(|handle| handle.handle.as_str())
    }
}

/// Bounds one short field to [`MAX_DIAGNOSTIC_FIELD_BYTES`], screening it
/// through the shared telemetry field policy first.
#[must_use]
pub fn bound_field(value: &str) -> BoundedField {
    bounded_value(value, MAX_DIAGNOSTIC_FIELD_BYTES, FIELD_LABEL_KEY).into()
}

/// Bounded free-text detail with truncation honesty and policy screening.
///
/// Pure and total: never panics and never allocates beyond the bound plus
/// the retained prefix. Callers must only pass nonsecret material: no
/// credentials, DB URLs, signed authority material, raw argv/environment,
/// unrestricted paths, or frame/request/model/user/evidence bodies
/// (I15.4, I07.20). A value that nevertheless carries a recognisable secret
/// never reaches the emitted record: it is replaced by an immutable redacted
/// evidence handle before bounding (issue #1842, I16.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDetail {
    /// Retained prefix: at most [`MAX_DIAGNOSTIC_DETAIL_BYTES`] bytes, unless
    /// the value was redacted under the field policy.
    text: String,
    /// Byte length of the input before truncation.
    original_bytes: usize,
    /// Whether the retained prefix is shorter than the input.
    truncated: bool,
    /// Recorded handle when the value was redacted, `None` otherwise.
    redaction: Option<RedactedHandle>,
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

    /// Redaction status recorded for this value, or `None` when the value
    /// passed the policy gate unchanged.
    #[must_use]
    pub fn redaction_status(&self) -> Option<&str> {
        self.redaction
            .as_ref()
            .map(|handle| handle.redaction_status.as_str())
    }

    /// Immutable evidence handle standing in for the redacted value, or
    /// `None` when no redaction occurred.
    #[must_use]
    pub fn evidence_handle(&self) -> Option<&str> {
        self.redaction.as_ref().map(|handle| handle.handle.as_str())
    }
}

/// Bounds one free-text detail to [`MAX_DIAGNOSTIC_DETAIL_BYTES`], screening
/// it through the shared telemetry field policy first.
#[must_use]
pub fn bound_detail(detail: &str) -> BoundedDetail {
    bounded_value(detail, MAX_DIAGNOSTIC_DETAIL_BYTES, DETAIL_LABEL_KEY).into()
}

/// One screened, bounded, already-policy-admitted field value.
///
/// Shared by [`bound_field`] and [`bound_detail`]: the two differ only in
/// their bound, so the emission boundary exists once.
struct BoundedScreenedValue {
    text: String,
    original_bytes: usize,
    truncated: bool,
    redaction: Option<RedactedHandle>,
}

impl From<BoundedScreenedValue> for BoundedField {
    fn from(value: BoundedScreenedValue) -> Self {
        Self {
            text: value.text,
            original_bytes: value.original_bytes,
            truncated: value.truncated,
            redaction: value.redaction,
        }
    }
}

impl From<BoundedScreenedValue> for BoundedDetail {
    fn from(value: BoundedScreenedValue) -> Self {
        Self {
            text: value.text,
            original_bytes: value.original_bytes,
            truncated: value.truncated,
            redaction: value.redaction,
        }
    }
}

/// Screens one value through the field policy and then bounds it.
///
/// Screening is first and is fail-closed: a value carrying a recognisable
/// secret, or one too long to be an opaque identifier, is replaced by the
/// immutable handle [`scrub_labels_for_emit`] mints, so no part of it reaches
/// the emitted record. Bounding then applies only to a value that already
/// passed the gate, which keeps the handle itself exact rather than truncated.
fn bounded_value(value: &str, max_bytes: usize, label_key: &str) -> BoundedScreenedValue {
    let original_bytes = value.len();
    if requires_evidence_handle(value) {
        let mut candidate = BTreeMap::new();
        candidate.insert(label_key.to_owned(), value.to_owned());
        let scrubbed = scrub_labels_for_emit(KERNEL_TELEMETRY_FAMILY, &candidate);
        // A Forbidden family emits nothing, so a redacted field would have no
        // emitted value. The Kernel family is Allowed, so the key survives
        // unless the field policy also renamed it as a forbidden key; either
        // way there is exactly one emitted value, and it is the handle.
        let Some(redacted) = scrubbed
            .labels
            .get(label_key)
            .or_else(|| scrubbed.labels.values().next())
        else {
            // Unreachable for the Allowed Kernel family; fail closed by
            // recording the value as denied rather than emitting it.
            return BoundedScreenedValue {
                text: field_policy::RedactionReason::Secret.as_str().to_owned(),
                original_bytes,
                truncated: false,
                redaction: None,
            };
        };
        let redaction = scrubbed
            .handles
            .iter()
            .find(|handle| &handle.handle == redacted)
            .cloned();
        debug_assert!(
            redaction.is_some(),
            "every emitted handle must be recorded on the scrubbed output"
        );
        return BoundedScreenedValue {
            text: redacted.clone(),
            original_bytes,
            truncated: false,
            redaction,
        };
    }
    let (text, original_bytes, truncated) = truncate_to(value, max_bytes);
    BoundedScreenedValue {
        text,
        original_bytes,
        truncated,
        redaction: None,
    }
}

/// Frozen Kernel process-entry boundaries observed by `main`.
///
/// One variant per actual startup funnel phase, plus the front-door loop
/// spans frozen by #895 W2. Later leaves (#897 front door/requests, #899
/// Store/composition, #901 process/supervision, #903 generation/control)
/// own their library paths and extend observations through their own
/// serialized turns; they never redefine these entry names, and no
/// diagnostic name replaces an owner lifecycle type (I14.20).
///
/// W2 freeze: every entrypoint span carries an event or an exact
/// propagation/no-event reason —
/// - permit admission: [`EntrypointStage::SessionPermitAdmission`] via
///   `observe_entrypoint_with_detail` from the front-door driver; permit
///   exhaustion emits `kernel.session.admission:deferred_capacity`,
///   visible without a success claim and without a terminal record (T14).
/// - session task outcome: [`EntrypointStage::SessionTaskOutcome`] via
///   `observe_entrypoint_with_detail` from the front-door driver; the
///   `JoinSet` evidence projects as `Ok(Ok) -> success`,
///   `Ok(Err) -> failure`, `Err -> join_failure`, `None -> drained`
///   (T15). Details carry no peer/session payload (I15.4).
/// - terminal output: NO event. `write_error` writes stderr, the terminal
///   sink itself, so a failed write is unobservable by design and must not
///   fail the process (W5); see the binary `write_error` no-event note.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntrypointStage {
    /// Diagnostics installed; the launch funnel is entered.
    Startup,
    /// Launch/config parsing accepted (`parse_launch_options`).
    LaunchConfig,
    /// Authenticated Host startup binding acquired (`from_environment`).
    HostStartupBinding,
    /// Store bootstrap requirement prepared.
    StoreBootstrap,
    /// Approved eliotd launch descriptor injected.
    EliotdLaunch,
    /// Kernel composition constructed with its authority descriptor.
    Composition,
    /// Production dispatch contour composed (doctor/testd/native-worker).
    DispatchComposition,
    /// External process authority handoff present.
    ProcessAuthority,
    /// Installer-provisioned supervision authority present.
    SupervisionAuthority,
    /// Authenticated front-door loop entered.
    FrontDoorLoop,
    /// Session permit admission decided inside the front-door loop.
    SessionPermitAdmission,
    /// One spawned session task joined (in-loop or final drain).
    SessionTaskOutcome,
    /// Shutdown drained with no orphans.
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
            Self::HostStartupBinding => "host_startup_binding",
            Self::StoreBootstrap => "store_bootstrap",
            Self::EliotdLaunch => "eliotd_launch",
            Self::Composition => "composition",
            Self::DispatchComposition => "dispatch_composition",
            Self::ProcessAuthority => "process_authority",
            Self::SupervisionAuthority => "supervision_authority",
            Self::FrontDoorLoop => "front_door_loop",
            Self::SessionPermitAdmission => "session_permit_admission",
            Self::SessionTaskOutcome => "session_task_outcome",
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
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.entrypoint_stage",
        stage = stage.as_str(),
        "kernel entrypoint reached stage"
    );
}

/// Records that the entrypoint reached one frozen boundary stage with a
/// bounded, policy-screened nonsecret detail.
///
/// The detail is screened against the shared telemetry field policy and then
/// truncated before formatting, with its honesty record attached; a
/// recognisable secret leaves the record as an immutable redacted evidence
/// handle carrying its redaction status, never as text. See [`bound_detail`].
pub fn observe_entrypoint_with_detail(stage: EntrypointStage, detail: &str) {
    let bounded = bound_detail(detail);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.entrypoint_stage",
        stage = stage.as_str(),
        detail = bounded.text(),
        detail_bytes = bounded.original_bytes(),
        detail_truncated = bounded.truncated(),
        detail_redaction = bounded.redaction_status().unwrap_or("none"),
        detail_evidence = bounded.evidence_handle().unwrap_or("none"),
        "kernel entrypoint reached stage"
    );
}

/// Records the single terminal error boundary (the `exit_error` funnel)
/// with its exact typed code.
///
/// One underlying failed operation yields exactly one terminal record here;
/// lower-phase entrypoint observations correlate by stage order, not by a
/// dedup cache. The code is screened against the shared telemetry field policy
/// and bounded defensively; every current call site passes a `&'static str`
/// typed code owned by its failure path (I07.20). Terminal receipt framing
/// (`write_error`) is untouched and still owns the process exit.
pub fn observe_terminal_error(code: &str) {
    let bounded = bound_field(code);
    tracing::error!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.terminal_error",
        code = bounded.text(),
        code_bytes = bounded.original_bytes(),
        code_truncated = bounded.truncated(),
        code_redaction = bounded.redaction_status().unwrap_or("none"),
        code_evidence = bounded.evidence_handle().unwrap_or("none"),
        "kernel terminal error"
    );
}
