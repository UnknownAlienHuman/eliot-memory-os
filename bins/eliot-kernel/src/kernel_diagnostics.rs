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
//! This module owns the bounded, nonsecret field helpers and the frozen
//! entrypoint observation vocabulary used by Kernel process entry. It installs
//! no process-global subscriber of its own: `eliot-observability-runtime` is
//! the one subscriber owner (issue #895 residual). The facade records the
//! install outcome that owner reported, and, when no such outcome was
//! reported, answers that its own stderr sink is unavailable. Whether the
//! owner's own global layer was accepted, or a foreign subscriber already held
//! the process, is not observable from this module.
//!
//! DELIVERY IS NOT UNIVERSAL, and this module does not pretend otherwise. The
//! accepted owner can only be installed once the launch funnel has the roots it
//! needs, so every record emitted BEFORE that point - the launch/config and
//! Host-binding stages, and any terminal record reached before it - is emitted
//! with no global subscriber installed and is therefore dropped, because
//! `tracing` with no dispatcher is a silent no-op. The same is true for the
//! whole funnel when the owner's install is refused, and on a target that
//! installs no owner at all. `main.rs` records those windows at its install
//! site. Closing them would need either an earlier owner install, which cannot
//! precede the roots it consumes, or a second `try_init` in this module, which
//! is precisely the two-owner defect this change removes.
//!
//! It owns no lifecycle, admission, transport, supervision, Store, generation,
//! provider, credential, or repair authority: a diagnostic record is evidence
//! only and can never reconcile an observation, authorize an effect, or
//! promote liveness into readiness/completion.
//!
//! General diagnostic delivery is workspace `tracing`, written to stderr so
//! protocol stdout framing is never contaminated. The separately admitted
//! Kernel Event Log profile uses one bounded queue and worker; this facade
//! owns only its capability status and never acquires Event Log FFI.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use eliot_observability::field_policy::{
    self, RedactedHandle, TelemetryFieldFamily, requires_evidence_handle, scrub_labels_for_emit,
};
use eliot_observability_runtime::ObservabilityInstallOutcome;

use crate::execution_metrics::KernelObservabilityError;

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

/// Stable owner-issued code for an observability configuration refusal.
///
/// A refused metrics/observability install is not a launch failure: startup
/// continues and only this non-terminal degraded observation is recorded
/// (issue #895 residual, Blocking defect 4). The code is the fixed
/// [`KernelObservabilityError::Config`] projection, never the failure's
/// `Display` prose, so the emitted code stays stable and comparable.
pub const OBSERVABILITY_INSTALL_CONFIG_REFUSED: &str = "OBSERVABILITY_INSTALL_CONFIG_REFUSED";
/// Stable owner-issued code for a non-loopback observability endpoint.
///
/// The fixed [`KernelObservabilityError::EndpointNotLoopback`] projection, with
/// the same stability and non-terminal meaning as
/// [`OBSERVABILITY_INSTALL_CONFIG_REFUSED`]: the admitted metrics surface is a
/// local surface, and a non-loopback address is refused rather than narrowed.
pub const OBSERVABILITY_INSTALL_ENDPOINT_NOT_LOOPBACK: &str =
    "OBSERVABILITY_INSTALL_ENDPOINT_NOT_LOOPBACK";

/// What the accepted observability owner reported for this process-global
/// subscriber. A projection of the owner's own outcome, not a second owner:
/// `ObservabilityInstallOutcome` in the observability runtime remains the
/// single source of truth for what was installed.
///
/// The runtime's outcome carries live handles that only its own `install` can
/// produce, so this copyable projection is what the facade records and
/// reports. It decides nothing about the install itself: diagnostics never
/// change Kernel results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSubscriberOwner {
    /// This process's configuration established the sole global subscriber owner.
    Installed,
    /// The accepted observability owner already stood; its owner is unchanged.
    AlreadyInstalled,
}

impl DiagnosticSubscriberOwner {
    /// Project the accepted owner's real install outcome.
    ///
    /// This is the only place the runtime's outcome type is matched in the
    /// Kernel facade, so the projection cannot drift into a second reading of
    /// what the accepted owner installed.
    #[must_use]
    pub fn observed(outcome: &ObservabilityInstallOutcome) -> Self {
        match outcome {
            ObservabilityInstallOutcome::Installed(_) => Self::Installed,
            ObservabilityInstallOutcome::AlreadyInstalled(_) => Self::AlreadyInstalled,
        }
    }
}

/// The accepted owner's reported install outcome, recorded once where the
/// outcome arrives.
///
/// Absent before any install, and never a pre-install ownership claim: it
/// exists so [`sink_status`] can report the outcome it observed rather than
/// assert a global dispatch nobody established.
static OBSERVED_SUBSCRIBER_OWNER: OnceLock<DiagnosticSubscriberOwner> = OnceLock::new();

/// Typed facade failures.
///
/// Diagnostics never change Kernel results, so these answers are
/// informational for the caller only; no variant authorizes a retry,
/// a fallback effect, or a lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelDiagnosticsError {
    /// The accepted observability owner already holds the process-global
    /// subscriber.
    ///
    /// Installation is bounded and non-panicking: the accepted
    /// `eliot-observability-runtime` owner stands and no second global
    /// install is attempted, so a repeat call creates no second owner and
    /// retries nothing. This answer means the accepted OWNER already stood,
    /// never that a private latch of this facade fired.
    AlreadyOwned,
    /// No accepted observability owner established this process's global
    /// subscriber, so the facade cannot prove its records reach any sink.
    ///
    /// This is deliberately a different answer from [`Self::AlreadyOwned`]:
    /// there is no owner at all here, which is the opposite fact, and an
    /// operator reading the rendered error must not be told a subscriber is
    /// owned when none is.
    SubscriberNotEstablished,
    /// The fixed Kernel Event Log queue has not been started or is unavailable.
    EventLogUnavailable,
}

impl fmt::Display for KernelDiagnosticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOwned => write!(f, "kernel diagnostics subscriber already owned"),
            Self::SubscriberNotEstablished => {
                write!(
                    f,
                    "no accepted observability owner established the global subscriber"
                )
            }
            Self::EventLogUnavailable => {
                write!(f, "kernel event log queue unavailable")
            }
        }
    }
}

impl std::error::Error for KernelDiagnosticsError {}

/// Diagnostic delivery sinks visible to the Kernel entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSink {
    /// Workspace `tracing` subscriber writing to stderr. Whether the accepted
    /// observability owner established it is reported by [`sink_status`], never
    /// assumed by this variant.
    TracingStderr,
    /// The admitted Kernel Event Log queue. This reports queue capability,
    /// never delivery; FFI remains on its single worker thread.
    WindowsEventLog,
}

/// Reports whether a sink can carry Kernel diagnostics.
///
/// The Event Log arm answers successfully only after the bounded Kernel queue
/// was initialized. That is not proof that the worker remains live or that
/// any event was accepted or delivered.
///
/// The `tracing` arm answers from the recorded owner outcome
/// (`OBSERVED_SUBSCRIBER_OWNER`). Either accepted owner answer means the one
/// process-global subscriber owner stands, whether this process's
/// configuration established it ([`DiagnosticSubscriberOwner::Installed`]) or
/// found it already standing ([`DiagnosticSubscriberOwner::AlreadyInstalled`]),
/// so both report `Ok(())`. With no such record this facade cannot prove its
/// records reach stderr, so the sink answers
/// [`KernelDiagnosticsError::SubscriberNotEstablished`] instead of relabelling
/// an unobserved dispatch as success. Whether a refused or failed install
/// inside the accepted owner left a foreign subscriber in place is not
/// distinguishable from this file, and no answer here claims that case is
/// resolved.
pub fn sink_status(sink: DiagnosticSink) -> Result<(), KernelDiagnosticsError> {
    match sink {
        DiagnosticSink::TracingStderr => {
            if OBSERVED_SUBSCRIBER_OWNER.get().is_some() {
                Ok(())
            } else {
                Err(KernelDiagnosticsError::SubscriberNotEstablished)
            }
        }
        DiagnosticSink::WindowsEventLog if crate::windows_event_log::queue_initialized() => Ok(()),
        DiagnosticSink::WindowsEventLog => Err(KernelDiagnosticsError::EventLogUnavailable),
    }
}

/// Records the accepted owner's real install outcome.
///
/// The process-global subscriber is installed by
/// `eliot_observability_runtime::install`, the one subscriber owner; this
/// facade emits through that owner and performs no global initialization of
/// its own. The answer therefore mirrors exactly what the accepted owner
/// reported: [`DiagnosticSubscriberOwner::Installed`] is that owner's own
/// report that this process's configuration established its subscriber, while
/// [`DiagnosticSubscriberOwner::AlreadyInstalled`] means the accepted owner
/// already stood, and this facade answers
/// [`KernelDiagnosticsError::AlreadyOwned`] instead of claiming it. Whether
/// the accepted owner's global layer was actually accepted, or a foreign
/// subscriber was already in place, is not observable from this module; that
/// residual is recorded as blocked in the issue checklist, not solved here.
///
/// Diagnostics never gate startup: the answer is informational for the caller,
/// never a panic, a retry, a replacement, or a second global install. It
/// reports the outcome the accepted owner handed over and nothing more; it
/// makes no claim about a global subscriber the accepted owner itself refused.
pub fn install_kernel_diagnostics(
    owner: DiagnosticSubscriberOwner,
) -> Result<(), KernelDiagnosticsError> {
    match owner {
        DiagnosticSubscriberOwner::Installed => {
            let _ = OBSERVED_SUBSCRIBER_OWNER.set(owner);
            Ok(())
        }
        DiagnosticSubscriberOwner::AlreadyInstalled => {
            let _ = OBSERVED_SUBSCRIBER_OWNER.set(owner);
            Err(KernelDiagnosticsError::AlreadyOwned)
        }
    }
}

/// Projects one refused observability install onto its stable owner code.
///
/// This is the only mapping from a [`KernelObservabilityError`] to an emitted
/// code, so the refusal vocabulary stays closed: the two constants above are
/// the codes, and no `Display` prose or other dynamic value can become one.
/// A refusal is non-terminal, so the code is emitted by
/// [`observe_observability_install_refused`] and never by
/// [`observe_terminal_error`].
#[must_use]
pub const fn observability_install_refused_code(error: KernelObservabilityError) -> &'static str {
    match error {
        KernelObservabilityError::Config => OBSERVABILITY_INSTALL_CONFIG_REFUSED,
        KernelObservabilityError::EndpointNotLoopback => {
            OBSERVABILITY_INSTALL_ENDPOINT_NOT_LOOPBACK
        }
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

/// Records that a refused observability/metrics install degrades diagnostics
/// without ending the launch.
///
/// Non-terminal by contract: a metrics install refusal never gates startup
/// (A13.10), so this observation carries the degraded disposition and no
/// `kernel.terminal_error`. On this entrypoint funnel `exit_error` is the sole
/// `kernel.terminal_error` emitter ([`observe_terminal_error`]); the library
/// modules keep their own per-operation terminal records. The code is a stable
/// owner-issued value from [`observability_install_refused_code`], screened
/// against the shared telemetry field policy and bounded like every other
/// short field here, so a recognised secret would leave the record as an
/// immutable redacted evidence handle rather than as text.
pub fn observe_observability_install_refused(code: &'static str) {
    let bounded = bound_field(code);
    tracing::warn!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.observability_install_refused",
        code = bounded.text(),
        code_bytes = bounded.original_bytes(),
        code_truncated = bounded.truncated(),
        code_redaction = bounded.redaction_status().unwrap_or("none"),
        code_evidence = bounded.evidence_handle().unwrap_or("none"),
        "kernel observability install refused"
    );
}

/// Builds an operation span from the safe identities already held by its owner.
///
/// Missing or not-yet-validated identities remain unavailable. This projection
/// never reads an owner, manufactures authority, or logs signed fence material.
/// Callers may record validated tree, lease and receipt references in the
/// declared fields after screening them through [`bound_field`].
#[must_use]
pub fn operation_context(
    operation: Option<&str>,
    generation: Option<&str>,
    state_fence: Option<&str>,
    authority_epoch: Option<&str>,
) -> tracing::Span {
    let operation = bound_field(operation.unwrap_or("unavailable"));
    let generation = bound_field(generation.unwrap_or("unavailable"));
    let state_fence = bound_field(state_fence.unwrap_or("unavailable"));
    let authority_epoch = bound_field(authority_epoch.unwrap_or("unavailable"));
    tracing::info_span!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        "kernel.operation",
        request_id = "unavailable",
        request_id_redaction = "none",
        operation = operation.text(),
        operation_redaction = operation.redaction_status().unwrap_or("none"),
        generation = generation.text(),
        generation_redaction = generation.redaction_status().unwrap_or("none"),
        state_fence = state_fence.text(),
        state_fence_redaction = state_fence.redaction_status().unwrap_or("none"),
        authority_epoch = authority_epoch.text(),
        authority_epoch_redaction = authority_epoch.redaction_status().unwrap_or("none"),
        process_tree = "unavailable",
        process_id = "unavailable",
        process_start_100ns = "unavailable",
        image_sha256 = "unavailable",
        lease = "unavailable",
        lease_operation = "unavailable",
        receipt = "unavailable",
    )
}

/// Records the single terminal error boundary (the `exit_error` funnel)
/// with its exact typed code.
///
/// One underlying failed operation yields exactly one terminal record here;
/// the current span is preserved for existing callers. Operation owners pass
/// their explicit span to [`observe_terminal_error_in_context`] so concurrent
/// operations never rely on stage order for correlation. No dedup cache is used.
/// The code is screened against the shared telemetry field policy
/// and bounded defensively; every current call site passes a `&'static str`
/// typed code owned by its failure path (I07.20). Terminal receipt framing
/// (`write_error`) is untouched and still owns the process exit.
pub fn observe_terminal_error(code: &str) {
    observe_terminal_error_in_context(code, &tracing::Span::current());
}

/// Emits the terminal assigned to this owner under its operation's exact span.
///
/// Subordinate owner reads must propagate their error without emitting another
/// terminal; choosing that boundary remains the caller's responsibility.
pub fn observe_terminal_error_in_context(code: &str, context: &tracing::Span) {
    let bounded = bound_field(code);
    tracing::error!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        parent: context,
        event = "kernel.terminal_error",
        code = bounded.text(),
        code_bytes = bounded.original_bytes(),
        code_truncated = bounded.truncated(),
        code_redaction = bounded.redaction_status().unwrap_or("none"),
        code_evidence = bounded.evidence_handle().unwrap_or("none"),
        "kernel terminal error"
    );
}
