//! Read-only validation of the canonical Host SCM launch registration.

use std::path::{Path, PathBuf};

use eliot_installation::InstallationProfile;
use eliot_platform::ServiceState;
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceBootstrapArguments, ServiceInspectionUnknownDetail, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, WindowsPlatform,
};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use uuid::Uuid;

#[cfg(windows)]
use super::host_durable_persistence::{sync_dir, write_durable_file};
use super::{HostError, HostLaunchOptions};

// F-LOG-HOST-3 (#978) SCM launch observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`,
// `observe_terminal_error`, `bound_field`); the Event Log seam stays
// typed-Unavailable (`super::windows_event_log::event_log_sink_status`), never
// implemented here (#984 still open).
//
// Identity binding (audit #5910159678 defect 5): this module observes a typed
// registration inspection and the platform's process/start information, but
// the shared-facade records used to omit all of it, which made the
// deterministic fields vacuous — two different SCM readbacks of the same
// service produced identical records. Every record emitted from a site whose
// owner already holds an identity now binds it: the canonical service name,
// the expected configuration digest the request compared against, the
// installation identity and transaction-plan generation when the caller
// supplied them, the observed SCM state, the SCM progress checkpoint, and —
// where the platform has already bound it — the observed process start
// identity as `pid/creation-time`. The `Matching` observation's own
// configuration digest is bound next to the requested one so a readback that
// matched and a readback that was never compared are distinguishable, and the
// `Unknown` payload's Win32 code, stage, raw state and PID are bound as the
// platform's own typed diagnostic fields. A slot the owner does not hold reads
// `unavailable`; nothing is invented.
//
// Never-logged (I15.4, I07.20): the registration nonce, image or bootstrap
// paths, host state roots, process image paths, and the platform's or this
// module's `Debug` renderings. `HostScmRegistrationCause::detail()` remains
// the one place the bounded cause text is built, and it feeds the typed error
// and the start-failure capsule, not a record.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Sink outcome never alters result/order/status/cleanup.
// There is no mutable global dedup cache: one terminal emission per failed SCM
// bootstrap is enforced by the single outermost guard in
// `validate_host_scm_bootstrap`; `classify_*` and `resolve_*` emit subordinate
// records and never a terminal. This mirrors the `HostTerminalGuard` model in
// `lib.rs` (F-LOG-HOST-1, #891) without touching it.
fn scm_launch_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

fn scm_launch_observe_bound(
    detail: &str,
    fields: &[(
        &'static str,
        super::host_job_launch::LaunchIdentityField<'_>,
    )],
) {
    scm_launch_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::ScmDispatch,
        &super::host_job_launch::render_launch_identity(detail, fields),
    );
}

fn scm_launch_observe_terminal(code: &str) {
    scm_launch_note_event_log_unavailable();
    super::host_diagnostics::observe_terminal_error(code);
}

/// Renders one already-observed SCM process identity as `pid/creation-time`.
///
/// The pair is the platform's own start identity, so a readback that observed
/// a specific process incarnation is distinguishable from one that only saw a
/// PID, and from a later process reusing that PID (case 978/5). The value is
/// read from the observation already in hand; this never opens, queries, or
/// re-observes a process.
fn scm_render_process_start_identity(process: &eliot_platform_windows::ProcessIdentity) -> String {
    format!("{}/{}", process.process_id, process.start_time_100ns)
}

/// Single-terminal guard for one SCM bootstrap validation.
///
/// Armed on entry; the single outermost boundary disarms on success. Any
/// `Err` return drops armed and emits exactly one terminal record with the
/// operation's frozen code. Emitting here never changes the `Result`.
/// No dedup cache, no lock, no second evaluation.
struct ScmLaunchTerminalGuard<'a> {
    code: &'a str,
    armed: bool,
}

impl<'a> ScmLaunchTerminalGuard<'a> {
    fn armed(code: &'a str) -> Self {
        Self { code, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ScmLaunchTerminalGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            scm_launch_observe_terminal(self.code);
        }
    }
}

/// Per-cause ceiling for the free-text SCM classification detail carried into
/// stderr and the start-failure capsule. This mirrors the Watchdog
/// `APPROVAL_DETAIL_MAX_CHARS` budget (the same 512-char width as the Host
/// capsule detail field) so the typed failure class stays stable while the
/// precise cause survives truncation secret-free. Host-owned; no cross-crate
/// sharing.
pub const HOST_SCM_CAUSE_MAX_CHARS: usize = 512;

fn truncate_host_scm_cause(value: &str) -> String {
    if value.chars().count() > HOST_SCM_CAUSE_MAX_CHARS {
        value.chars().take(HOST_SCM_CAUSE_MAX_CHARS).collect()
    } else {
        value.to_owned()
    }
}

/// Typed host-side cause for a non-matching Host SCM registration inspection.
///
/// The runtime [`ServiceRegistrationRuntimeInspection`] reports `Mismatched`
/// as a unit variant without field-level detail, so a binary-command/account
/// drift and a service-object security-descriptor (default-DACL, no
/// service-SID ACE) drift are indistinguishable at this layer; the
/// `Mismatched` detail text says so instead of guessing. This enum surfaces
/// exactly what IS observable — the variant plus its Debug text, with the
/// request-bound identity bindings for `Absent` — without redefining platform
/// types. Field-level mismatch detail remains a platform-owner gap (WRITER-A).
/// Every variant is fail-closed: [`validate_host_scm_bootstrap`] rejects
/// bootstrap on all of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostScmRegistrationCause {
    /// The canonical service name is not registered. Carries the request-bound
    /// identity (queried name plus admitted configuration digest, both
    /// non-secret) so the absence stays bound to the exact query. The runtime
    /// contour reports `Absent` as a unit variant without a live proof object,
    /// so the bindings are taken from the validated registration request.
    Absent {
        service_name: String,
        configuration_digest: String,
    },
    /// A service exists at the canonical name with different configuration.
    /// Carries the platform Debug text; the platform reports no
    /// SD-versus-config field breakdown.
    Mismatched { inspection_debug: String },
    /// SCM could not provide authoritative configuration and state readback
    /// (possible access-denied readback under the service account, or
    /// provider uncertainty). Still fail-closed.
    Unknown { inspection_debug: String },
}

impl HostScmRegistrationCause {
    /// Stable machine-readable cause name for stderr/capsule grepability.
    #[must_use]
    pub const fn cause(&self) -> &'static str {
        match self {
            Self::Absent { .. } => "absent",
            Self::Mismatched { .. } => "mismatched",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Bounded secret-free detail for stderr and the start-failure capsule.
    ///
    /// Carries only the canonical service name, the non-secret configuration
    /// digest (absent cause), and the platform variant/Debug text. Bootstrap
    /// paths, nonces, and digests beyond the SCM configuration digest never
    /// enter this string; output is truncated to
    /// [`HOST_SCM_CAUSE_MAX_CHARS`] characters.
    #[must_use]
    pub fn detail(&self) -> String {
        let text = match self {
            Self::Absent {
                service_name,
                configuration_digest,
            } => format!(
                "host-scm-registration-absent: service '{service_name}' is not registered (configuration {configuration_digest})"
            ),
            Self::Mismatched { inspection_debug } => format!(
                "host-scm-registration-mismatched: service '{ELIOT_HOST_SERVICE_NAME}' exists but its SCM configuration, service-SID type, or service-object security descriptor does not exactly match the canonical request (platform inspection reports Mismatched without field-level detail; inspection: {inspection_debug})",
            ),
            Self::Unknown { inspection_debug } => format!(
                "host-scm-registration-unknown: service '{ELIOT_HOST_SERVICE_NAME}' SCM configuration and state are not authoritatively observable via runtime contour inspect_service_registration_runtime (fail-closed; possible access-denied readback or provider uncertainty; SACL never requested, platform DACL-only readback; inspection: {inspection_debug})",
            ),
        };
        truncate_host_scm_cause(&text)
    }
}

/// Whether a runtime `Matching` observation state is admissible as a valid
/// Host bootstrap at `ServiceMain` time.
///
/// `Stopped`, `Starting`, and `Running` are accepted: `ServiceMain` runs while
/// SCM reports `START_PENDING` with a live PID, so requiring `Stopped` would
/// deterministically reject a healthy start. Every other state (`Stopping`,
/// `Unknown`, `Absent`, `Failed`) is inadmissible and maps to a fail-closed
/// `Unknown` cause in [`classify_host_scm_inspection`].
///
/// This predicate is the exact gate the `Matching { observation }` arm uses.
/// It takes the public [`ServiceState`] (not the platform-owned
/// `ServiceRuntimeObservation`, whose fields are `pub(super)` and cannot be
/// constructed outside `eliot-platform-windows`) so the Starting-acceptance
/// rule stays directly unit-testable without live SCM calls.
#[must_use]
pub const fn host_runtime_bootstrap_state_is_admissible(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::Stopped | ServiceState::Starting | ServiceState::Running
    )
}

/// Raw SCM `dwCurrentState` for `SERVICE_START_PENDING`.
///
/// The platform preserves the raw state in
/// [`ServiceInspectionUnknownDetail::current_state`] without mapping it to
/// [`ServiceState`], so the transient-pending predicate compares against this
/// documented constant instead of re-deriving the mapping.
pub const HOST_SCM_START_PENDING_STATE: u32 = 2;

/// Sleep between transient-pending re-reads.
///
/// This is the established host-side short poll (the same 250 ms used by the
/// post-bootstrap control loops), so one re-read can never breach the
/// `START_PENDING` checkpoint promise the reporter already publishes.
pub const HOST_SCM_TRANSIENT_RETRY_SLEEP_MS: u64 = 250;

/// Total runtime-contour inspections per bootstrap validation (1 initial + 4
/// retries). Worst-case added latency is therefore `4 × 250 ms = 1.0 s`, well
/// inside the SCM wait hint and one reporter tick.
pub const HOST_SCM_TRANSIENT_MAX_INSPECTIONS: usize = 5;

/// Whether a typed `Unknown` inspection is the transient `START_PENDING`/PID
/// race rather than a real failure.
///
/// Returns true only when `detail.win32_error() == 0` (the platform's own
/// marker for "logic contour violation, no Win32 error"), `detail.stage() ==
/// "query-status"`, and `detail.current_state() == Some(2)` (raw
/// `SERVICE_START_PENDING`, see [`HOST_SCM_START_PENDING_STATE`]). That triple
/// isolates the two-sample state/PID flap and process-identity race sites from
/// real failures: a failed second status query carries a real Win32 code, and
/// grant/config readback failures carry their own stage names. The process id
/// is deliberately ignored: PID `0` (pre-assignment) and an assigned PID
/// (mid-window) are both transient while the state is `START_PENDING`.
///
/// Only this triple retries, at most `4 × 250 ms`. Every other `Unknown`
/// (non-zero Win32 code, other stage, or other state) stays fail-closed with
/// zero retries, as do `Absent`, `Mismatched`, and inadmissible `Matching`.
#[must_use]
pub fn host_scm_unknown_is_transient_pending(detail: &ServiceInspectionUnknownDetail) -> bool {
    detail.win32_error() == 0
        && detail.stage() == "query-status"
        && detail.current_state() == Some(HOST_SCM_START_PENDING_STATE)
}

/// Identity slots one `Matching` runtime readback contributes to a record.
///
/// The observation already carries the configuration digest SCM actually
/// admitted, the observed SCM lifecycle state, the progress checkpoint, and —
/// when SCM reported a live process — that process's exact start identity.
/// Binding all of them is what makes a record prove a specific incarnation of
/// the service rather than a phase label, so both `Matching` classification
/// arms assemble them here and each arm adds only what is genuinely different
/// about it.
///
/// `checkpoint` is `Some` only where the arm binds the SCM progress
/// checkpoint; an arm that does not observe one passes `None` and the slot is
/// not rendered at all. `process` is the start identity already rendered by
/// [`scm_render_process_start_identity`], so the slot borrows the caller's
/// binding rather than a temporary; an observation SCM reported no live
/// process for reads `Unavailable`, exactly as before.
fn scm_matching_observed_fields<'a>(
    requested: &[(&'static str, super::host_job_launch::LaunchIdentityField<'a>)],
    observed_config_digest: &'a str,
    state: ServiceState,
    checkpoint: Option<u64>,
    process: Option<&'a str>,
) -> Vec<(&'static str, super::host_job_launch::LaunchIdentityField<'a>)> {
    let mut fields = requested.to_vec();
    fields.push((
        "observed_config_digest",
        super::host_job_launch::LaunchIdentityField::Text(observed_config_digest),
    ));
    fields.push((
        "scm_state",
        super::host_job_launch::LaunchIdentityField::Text(scm_state_name(state)),
    ));
    if let Some(checkpoint) = checkpoint {
        fields.push((
            "checkpoint",
            super::host_job_launch::LaunchIdentityField::Number(checkpoint),
        ));
    }
    fields.push((
        "process",
        match process {
            Some(process) => super::host_job_launch::LaunchIdentityField::Text(process),
            None => super::host_job_launch::LaunchIdentityField::Unavailable,
        },
    ));
    fields
}

/// Identity slots one typed `Unknown` runtime readback contributes to a
/// record.
///
/// The platform's own typed diagnostic fields for the failing stage are bound:
/// the preserved Win32 code, the failing stage, the raw `dwCurrentState`, the
/// observed PID, and whether that state is the transient `START_PENDING`
/// checkpoint. The PID is recorded as a PID, never as a start identity — this
/// readback carries no creation time, so the slot cannot claim one — and a
/// stage, state, or PID the platform could not observe reads `Unavailable`.
fn scm_unknown_diagnostic_fields<'a>(
    requested: &[(&'static str, super::host_job_launch::LaunchIdentityField<'a>)],
    detail: &ServiceInspectionUnknownDetail,
) -> Vec<(&'static str, super::host_job_launch::LaunchIdentityField<'a>)> {
    let mut fields = requested.to_vec();
    fields.push((
        "win32_error",
        super::host_job_launch::LaunchIdentityField::Number(u64::from(detail.win32_error())),
    ));
    fields.push((
        "stage",
        super::host_job_launch::LaunchIdentityField::Text(detail.stage()),
    ));
    fields.push((
        "current_state",
        match detail.current_state() {
            Some(state) => super::host_job_launch::LaunchIdentityField::Number(u64::from(state)),
            None => super::host_job_launch::LaunchIdentityField::Unavailable,
        },
    ));
    fields.push((
        "pid",
        match detail.process_id() {
            Some(pid) => super::host_job_launch::LaunchIdentityField::Number(u64::from(pid)),
            None => super::host_job_launch::LaunchIdentityField::Unavailable,
        },
    ));
    fields.push((
        "transient_pending",
        super::host_job_launch::LaunchIdentityField::Text(
            if detail
                .current_state()
                .is_some_and(|state| state == HOST_SCM_START_PENDING_STATE)
            {
                "pending"
            } else {
                "not_pending"
            },
        ),
    ));
    fields
}

/// Identity slots one installed-candidate readback request contributes to a
/// record.
///
/// The candidate spec is the identity this readback is about: the candidate
/// installation identity, its immutable transaction-plan generation, and its
/// approved config descriptor digest — all three borrowed from the spec the
/// caller holds, so both the requested record below and the observed record
/// after the platform read share one binding. The candidate image, descriptor,
/// state root and platform root are paths and never enter a record.
fn scm_candidate_identity(
    spec: &InstalledCandidateSpec,
) -> [(&'static str, super::host_job_launch::LaunchIdentityField<'_>); 3] {
    [
        (
            "installation",
            super::host_job_launch::LaunchIdentityField::Text(spec.installation_id.as_str()),
        ),
        (
            "plan_generation",
            super::host_job_launch::LaunchIdentityField::Number(spec.transaction_plan_generation),
        ),
        (
            "config_digest",
            super::host_job_launch::LaunchIdentityField::Text(
                spec.config_descriptor_digest.as_str(),
            ),
        ),
    ]
}

/// Identity slots one installed-candidate readback observation contributes to
/// a record.
///
/// Beside the candidate identity its owner already holds, the observed
/// registration identity and the desired-side manifest presence are bound: the
/// SCM configuration digest that was actually read back, the class of the
/// readback outcome, the process start identity when SCM reported one, and
/// whether an installed manifest was found. The manifest's own artifact
/// digests stay in the returned readback and never enter a record, and a
/// readback that reported no live process reads `Unavailable`.
fn scm_candidate_readback_observed_fields<'a>(
    identity: &[(&'static str, super::host_job_launch::LaunchIdentityField<'a>)],
    observed_config_digest: &'a str,
    inspection: &ServiceRegistrationRuntimeInspection,
    observed_process: Option<&'a str>,
    manifest_installed: bool,
) -> Vec<(&'static str, super::host_job_launch::LaunchIdentityField<'a>)> {
    let mut fields = identity.to_vec();
    fields.push((
        "observed_config_digest",
        super::host_job_launch::LaunchIdentityField::Text(observed_config_digest),
    ));
    fields.push((
        "inspection",
        super::host_job_launch::LaunchIdentityField::Text(scm_inspection_class(inspection)),
    ));
    fields.push((
        "process",
        match observed_process {
            Some(process) => super::host_job_launch::LaunchIdentityField::Text(process),
            None => super::host_job_launch::LaunchIdentityField::Unavailable,
        },
    ));
    fields.push((
        "manifest",
        super::host_job_launch::LaunchIdentityField::Text(if manifest_installed {
            "installed"
        } else {
            "absent"
        }),
    ));
    fields
}

/// Pure projection from a platform runtime registration inspection to the
/// typed host-side cause. Returns `None` only for an admissible `Matching`
/// observation; every other outcome maps to its fail-closed cause, so
/// `Mismatched` (including a default-DACL security-descriptor drift) can
/// never collapse into `Unknown`.
///
/// s40: Host `ServiceMain` runs while SCM reports `START_PENDING` with a live
/// PID. The non-runtime contour (`WindowsPlatform::inspect_service_registration`,
/// `crates/kernel/eliot-platform-windows/src/lib.rs:5427`) maps any PID != 0
/// readback through `inspect_service` (`lib.rs:5555`), which returns `Partial`
/// for every PID != 0 (`lib.rs:5624-5640`), to unit `Unknown` via
/// `service_registration_inspection_from_status` (`lib.rs:5532-5545`). A
/// healthy Starting host therefore deterministically failed closed with
/// 1066/3 (`bins/eliot-host/src/main.rs:588-600`,
/// `HostStopCode::InvalidRegistration` specific 3), while the installer
/// readback (`STOPPED`, PID 0) returned `Known` -> `Matching`. The runtime
/// contour (`WindowsPlatform::inspect_service_registration_runtime`,
/// `lib.rs:4938`) handles `Starting` + PID as `Matching` via
/// `classify_service_runtime_observation` (`lib.rs:4881-4921`) with two-sample
/// stability, matching the Watchdog path
/// (`bins/eliot-watchdog/src/scm_launch.rs:323-331`). SACL `S:(AU;FA;;;WD)`
/// is never requested: platform `GetSecurityInfo` reads are DACL-only
/// (`lib.rs:4019,4152`).
///
/// WRITER-A carry-over (s40 integration): platform `Unknown` is the typed
/// payload `Unknown { detail: ServiceInspectionUnknownDetail }` (Writer-A).
/// This is the sole inspection-to-cause mapping site; the `Unknown` arm
/// matches `Unknown { detail }` and preserves `detail.win32_error`,
/// `detail.stage`, `detail.current_state`, and `detail.process_id` via the
/// explicit typed rendering plus the platform Debug text verbatim (truncated
/// to [`HOST_SCM_CAUSE_MAX_CHARS`]). Fail-closed is unchanged: `Unknown`
/// never maps to `None`, never to `Matching`, and never collapses
/// `Mismatched`.
#[must_use]
pub fn classify_host_scm_inspection(
    request: &ServiceRegistrationRequest,
    inspection: &ServiceRegistrationRuntimeInspection,
) -> Option<HostScmRegistrationCause> {
    // The identity this classifier's owner already holds: the canonical
    // service name the request asked about and the expected configuration
    // digest it compared against. Both are non-secret approved request values.
    // The accessor returns an owned digest, so it is bound to a named local
    // here and the identity slots below borrow that binding for the whole
    // classification rather than a temporary that dies at the end of the
    // array expression.
    let expected_configuration_digest = request.expected_configuration_digest();
    let requested = [
        (
            "service",
            super::host_job_launch::LaunchIdentityField::Text(request.service_name()),
        ),
        (
            "expected_config_digest",
            super::host_job_launch::LaunchIdentityField::Text(
                expected_configuration_digest.as_str(),
            ),
        ),
    ];
    // WORK_UNIT_CASE: 978/5 — classification requested; request vs observed
    // process and start-identity vs PID stay distinct below.
    scm_launch_observe_bound("host.scm-launch classification requested", &requested);
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if host_runtime_bootstrap_state_is_admissible(observation.state()) =>
        {
            // The observation is the platform's own readback: it carries the
            // configuration digest SCM actually admitted, the SCM state, the
            // progress checkpoint, and — when SCM reported a live process —
            // that process's exact start identity. Binding all of them is what
            // makes this record prove a specific incarnation of the service
            // rather than a phase label.
            let process = observation.process().map(scm_render_process_start_identity);
            let fields = scm_matching_observed_fields(
                &requested,
                observation.configuration_digest(),
                observation.state(),
                Some(u64::from(observation.checkpoint())),
                process.as_deref(),
            );
            // WORK_UNIT_CASE: 978/5 — start-identity observed: the admissible
            // service identity + state accepts bootstrap; the ephemeral PID is
            // never identity.
            scm_launch_observe_bound("host.scm-launch start-identity observed", &fields);
            None
        }
        ServiceRegistrationRuntimeInspection::Matching { observation } => {
            // The same observed identity is bound here, so an inadmissible
            // state is distinguishable from the admissible readback of the very
            // same service and configuration instead of producing the same two
            // static strings. This arm observes no progress checkpoint, so it
            // renders no `checkpoint` slot at all.
            let process = observation.process().map(scm_render_process_start_identity);
            let fields = scm_matching_observed_fields(
                &requested,
                observation.configuration_digest(),
                observation.state(),
                None,
                process.as_deref(),
            );
            // WORK_UNIT_CASE: 978/5 — admissible start-identity absent; the
            // observed state cannot bootstrap.
            scm_launch_observe_bound("host.scm-launch start-identity unknown", &fields);
            Some(HostScmRegistrationCause::Unknown {
                inspection_debug: format!("{inspection:?}"),
            })
        }
        ServiceRegistrationRuntimeInspection::Absent => {
            // WORK_UNIT_CASE: 978/5 — SCM request observed: the canonical
            // registration request has no observed process. No process, state,
            // or observed digest exists for an absent registration, so those
            // slots stay explicitly unavailable rather than filled with the
            // request's own values.
            scm_launch_observe_bound("host.scm-launch request observed", &requested);
            Some(HostScmRegistrationCause::Absent {
                service_name: request.service_name().to_owned(),
                configuration_digest: request.expected_configuration_digest(),
            })
        }
        ServiceRegistrationRuntimeInspection::Mismatched => {
            // WORK_UNIT_CASE: 978/5 — observed process exists but is not the
            // requested registration. `Mismatched` is a unit variant, so the
            // platform reports no field-level detail: the observed process
            // identity is genuinely unavailable here and says so.
            scm_launch_observe_bound(
                "host.scm-launch process observed",
                &[
                    requested.as_slice(),
                    [(
                        "process",
                        super::host_job_launch::LaunchIdentityField::Unavailable,
                    )]
                    .as_slice(),
                ]
                .concat(),
            );
            Some(HostScmRegistrationCause::Mismatched {
                inspection_debug: format!("{inspection:?}"),
            })
        }
        ServiceRegistrationRuntimeInspection::Unknown { detail } => {
            // The platform's own typed diagnostic fields for the failing stage
            // are bound: the preserved Win32 code, the failing stage, the raw
            // `dwCurrentState`, and the observed PID. The PID is recorded as a
            // PID, never as a start identity — this readback carries no
            // creation time, so the slot cannot claim one.
            let fields = scm_unknown_diagnostic_fields(&requested, detail);
            // WORK_UNIT_CASE: 978/5 — ephemeral PID observation; never
            // promoted into start-identity.
            scm_launch_observe_bound("host.scm-launch pid observed", &fields);
            // Typed payload carry-over: preserve win32_error/stage/state/pid
            // explicitly via the typed rendering plus Debug verbatim. Both
            // stay bounded through truncate_host_scm_cause downstream and
            // reach only the typed error and the start-failure capsule, never a
            // record. SACL is never requested (platform DACL-only); Unknown
            // stays fail-closed 1066/3.
            Some(HostScmRegistrationCause::Unknown {
                inspection_debug: format!("{} | {inspection:?}", detail.detail()),
            })
        }
    }
}

/// Stable secret-free name for one observed SCM lifecycle state.
///
/// A projection of the owner's typed [`ServiceState`] discriminant only, so a
/// record names the observed state without rendering the provider's own
/// `Debug` output. The mapping is exhaustive, so a new state forces this to
/// stay in sync; it names a state and grants nothing (I14.20).
fn scm_state_name(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Unknown => "unknown",
        ServiceState::Absent => "absent",
        ServiceState::Stopped => "stopped",
        ServiceState::Starting => "starting",
        ServiceState::Running => "running",
        ServiceState::Stopping => "stopping",
        ServiceState::Failed => "failed",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostScmLaunch {
    bootstrap: ServiceBootstrapArguments,
    registration: ServiceRegistrationRequest,
    inspection: ServiceRegistrationRuntimeInspection,
}

impl ValidatedHostScmLaunch {
    #[must_use]
    pub fn bootstrap(&self) -> &ServiceBootstrapArguments {
        &self.bootstrap
    }

    #[must_use]
    pub fn registration(&self) -> &ServiceRegistrationRequest {
        &self.registration
    }

    #[must_use]
    pub fn inspection(&self) -> &ServiceRegistrationRuntimeInspection {
        &self.inspection
    }
}

/// Injectable read-only mechanics for the bounded transient-pending re-read
/// loop. Production supplies the live runtime-contour inspection plus
/// `std::thread::sleep`; tests supply a deterministic scripted sequence with a
/// recorded clock (no live SCM, no real sleeping). Mirrors
/// `WatchdogSelfAdmissionProbe::{inspect, sleep_ms}`.
trait HostScmBootstrapProbe {
    fn inspect(&mut self) -> ServiceRegistrationRuntimeInspection;
    fn sleep_ms(&mut self, milliseconds: u64);
}

/// Drives the bounded transient-pending re-read loop to a settled inspection.
///
/// Issues the initial inspection, then — only while the outcome is an
/// `Unknown` for which [`host_scm_unknown_is_transient_pending`] holds —
/// sleeps [`HOST_SCM_TRANSIENT_RETRY_SLEEP_MS`] and re-inspects, up to
/// [`HOST_SCM_TRANSIENT_MAX_INSPECTIONS`] total inspections. Exits on the
/// first non-transient outcome; a still-transient outcome after exhaustion is
/// returned as-is so the caller maps it through the existing fail-closed
/// `Unknown` cause (1066/3). Classification itself stays in
/// [`classify_host_scm_inspection`], the sole inspection-to-cause mapping site.
fn resolve_host_scm_inspection_with_probe<P: HostScmBootstrapProbe>(
    probe: &mut P,
) -> ServiceRegistrationRuntimeInspection {
    // The bounded re-read budget is the identity this site holds before the
    // loop runs: the total inspections it may issue and the fixed sleep
    // between them. Binding them distinguishes this re-read loop from any
    // other, and makes the record state the exact budget that was granted.
    let budget = [
        (
            "max_inspections",
            super::host_job_launch::LaunchIdentityField::Number(
                HOST_SCM_TRANSIENT_MAX_INSPECTIONS as u64,
            ),
        ),
        (
            "retry_sleep_ms",
            super::host_job_launch::LaunchIdentityField::Number(HOST_SCM_TRANSIENT_RETRY_SLEEP_MS),
        ),
    ];
    // WORK_UNIT_CASE: 978/13 — deterministic probe schedule requested; the
    // injected inspection script drives the bounded re-read loop.
    scm_launch_observe_bound("host.scm-launch probe requested", &budget);
    let mut current = probe.inspect();
    // Number of inspections actually issued, counted from the loop's own
    // index; it is a property of the schedule that ran, not a new probe.
    let mut issued: u64 = 1;
    for _ in 1..HOST_SCM_TRANSIENT_MAX_INSPECTIONS {
        let transient = matches!(
            &current,
            ServiceRegistrationRuntimeInspection::Unknown { detail }
                if host_scm_unknown_is_transient_pending(detail)
        );
        if !transient {
            break;
        }
        probe.sleep_ms(HOST_SCM_TRANSIENT_RETRY_SLEEP_MS);
        current = probe.inspect();
        issued += 1;
    }
    // WORK_UNIT_CASE: 978/5 — settled PID observation; start-identity
    // admission stays with the classifier, never invented here. The record
    // binds the settled observation's own identity — the configuration digest
    // SCM admitted and the process start identity when it reported one — plus
    // how many inspections the schedule actually consumed, so two runs of the
    // same budget that settled differently stay distinguishable.
    let mut fields = budget.to_vec();
    fields.push((
        "inspections_issued",
        super::host_job_launch::LaunchIdentityField::Number(issued),
    ));
    // The settled inspection's process start identity is rendered once, into a
    // named local that outlives the branch below, so the identity slot can
    // borrow it for the whole record instead of a temporary scoped to the
    // `Matching` arm. It reads the settled readback already in hand and never
    // queries a process.
    let settled_process = scm_inspection_process(&current).map(scm_render_process_start_identity);
    if let ServiceRegistrationRuntimeInspection::Matching { observation } = &current {
        fields.push((
            "observed_config_digest",
            super::host_job_launch::LaunchIdentityField::Text(observation.configuration_digest()),
        ));
        fields.push((
            "scm_state",
            super::host_job_launch::LaunchIdentityField::Text(scm_state_name(observation.state())),
        ));
        fields.push((
            "process",
            match settled_process.as_deref() {
                Some(process) => super::host_job_launch::LaunchIdentityField::Text(process),
                None => super::host_job_launch::LaunchIdentityField::Unavailable,
            },
        ));
    } else {
        fields.push((
            "observed_config_digest",
            super::host_job_launch::LaunchIdentityField::Unavailable,
        ));
        fields.push((
            "scm_state",
            super::host_job_launch::LaunchIdentityField::Text(scm_inspection_class(&current)),
        ));
        fields.push((
            "process",
            super::host_job_launch::LaunchIdentityField::Unavailable,
        ));
    }
    scm_launch_observe_bound("host.scm-launch pid observed", &fields);
    current
}

/// Stable secret-free class name for a non-`Matching` inspection outcome.
///
/// Names which outcome the readback produced — never the provider's `Debug`
/// text, which may embed a path. It names an outcome and grants nothing.
fn scm_inspection_class(inspection: &ServiceRegistrationRuntimeInspection) -> &'static str {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { .. } => "matching",
        ServiceRegistrationRuntimeInspection::Absent => "absent",
        ServiceRegistrationRuntimeInspection::Mismatched => "mismatched",
        ServiceRegistrationRuntimeInspection::Unknown { .. } => "unknown",
    }
}

/// The platform-observed process identity carried by one inspection, if any.
///
/// Only a `Matching` observation carries the handle-observed process identity;
/// every other outcome leaves it genuinely absent, and the caller renders that
/// absence explicitly. This is a pure read of a value already in hand and
/// never queries SCM or a process.
fn scm_inspection_process(
    inspection: &ServiceRegistrationRuntimeInspection,
) -> Option<&eliot_platform_windows::ProcessIdentity> {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation } => observation.process(),
        ServiceRegistrationRuntimeInspection::Absent
        | ServiceRegistrationRuntimeInspection::Mismatched
        | ServiceRegistrationRuntimeInspection::Unknown { .. } => None,
    }
}

/// Production probe: live runtime-contour inspection plus real thread sleep.
struct WindowsScmBootstrapProbe<'a> {
    platform: &'a WindowsPlatform,
    registration: &'a ServiceRegistrationRequest,
}

impl HostScmBootstrapProbe for WindowsScmBootstrapProbe<'_> {
    fn inspect(&mut self) -> ServiceRegistrationRuntimeInspection {
        self.platform
            .inspect_service_registration_runtime(self.registration)
    }

    fn sleep_ms(&mut self, milliseconds: u64) {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds));
    }
}

/// Rebuilds and read-only-inspects the canonical Host SCM registration from
/// the validated launch options. Host never registers or starts its own SCM
/// service; the installer is the sole registration owner.
///
/// The readback uses the runtime contour
/// (`WindowsPlatform::inspect_service_registration_runtime`), which accepts
/// `Stopped`, `Starting`, and `Running` observations with valid
/// configuration plus grant at `ServiceMain` time. `Starting` is valid: the
/// host process is already running while SCM still reports `START_PENDING`.
///
/// A typed transient `Unknown` (zero Win32 error, `"query-status"` stage, raw
/// `START_PENDING` state — see [`host_scm_unknown_is_transient_pending`]) is
/// re-read at most four times at 250 ms intervals (5 inspections, ≤1.0 s
/// added latency) so the `START_PENDING`/PID-assignment race can converge to
/// a stable outcome. Exhaustion maps to the existing fail-closed `Unknown`
/// cause; every other outcome settles with zero retries.
///
/// # Errors
///
/// Returns an error when the current executable, canonical registration
/// request, or read-only SCM registration inspection is invalid or unknown.
/// A non-matching inspection yields the typed [`HostScmRegistrationCause`]
/// detail (`absent`, `mismatched`, or `unknown`); all three reject bootstrap
/// fail-closed under the existing `invalid_scm_registration` stop class.
pub fn validate_host_scm_bootstrap(
    launch_options: &HostLaunchOptions,
) -> Result<ValidatedHostScmLaunch, HostError> {
    // The launch options are the identity this site holds on entry: the
    // installation identity, the immutable transaction-plan generation, and
    // the approved config descriptor digest. The registration nonce and every
    // path in these options are never recorded.
    let identity = [
        (
            "installation",
            super::host_job_launch::LaunchIdentityField::Text(
                launch_options.installation().as_str(),
            ),
        ),
        (
            "plan_generation",
            super::host_job_launch::LaunchIdentityField::Number(
                launch_options.transaction_plan_generation(),
            ),
        ),
        (
            "config_digest",
            super::host_job_launch::LaunchIdentityField::Text(
                launch_options.config_descriptor_digest().as_str(),
            ),
        ),
    ];
    // WORK_UNIT_CASE: 978/5 — SCM bootstrap requested; the single outermost
    // contour owns the one terminal below (#891 owns nothing here; main.rs
    // ServiceMain projects the stop receipt without its own diagnostics
    // terminal).
    scm_launch_observe_bound("host.scm-launch requested", &identity);
    // WORK_UNIT_CASE: 978/10 — one terminal across the SCM nesting:
    // classification and probe correlate by stage order only; only this guard
    // may emit the SCM unknown code.
    let mut scm_terminal = ScmLaunchTerminalGuard::armed("host-scm-launch-unknown");
    let registration_nonce = launch_options.registration_nonce().ok_or_else(|| {
        HostError::Platform("SystemService requires the registration nonce pair".to_owned())
    })?;
    let bootstrap = ServiceBootstrapArguments::new(
        launch_options.config_descriptor_path().to_path_buf(),
        launch_options
            .config_descriptor_digest()
            .as_str()
            .to_owned(),
        launch_options.installation().as_str().to_owned(),
        launch_options.transaction_plan_generation(),
        std::iter::empty::<String>(),
    )
    .map_err(|error| HostError::Platform(error.to_string()))?
    .with_host_state_root(launch_options.host_state_root().to_path_buf())
    .map_err(|error| HostError::Platform(error.to_string()))?
    .with_registration_nonce(registration_nonce.as_str().to_owned())
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let executable =
        std::env::current_exe().map_err(|error| HostError::Platform(error.to_string()))?;
    let registration = ServiceRegistrationRequest::with_bootstrap(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        executable.clone(),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap.clone(),
    )
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let root = executable
        .parent()
        .ok_or_else(|| HostError::Platform("current executable has no parent".to_owned()))?;
    let platform = WindowsPlatform::new(root.to_path_buf())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let inspection = {
        let mut probe = WindowsScmBootstrapProbe {
            platform: &platform,
            registration: &registration,
        };
        resolve_host_scm_inspection_with_probe(&mut probe)
    };
    if let Some(cause) = classify_host_scm_inspection(&registration, &inspection) {
        // The typed cause class is the reason this bootstrap failed, and it is
        // an owner-defined closed vocabulary (`absent` / `mismatched` /
        // `unknown`) rather than free text, so it is bound alongside the
        // installation identity. The cause's own detail string stays with the
        // typed error and the start-failure capsule.
        let mut fields = identity.to_vec();
        fields.push((
            "reason",
            super::host_job_launch::LaunchIdentityField::Text(cause.cause()),
        ));
        scm_launch_observe_bound("host.scm-launch rejected", &fields);
        return Err(HostError::Platform(cause.detail()));
    }
    scm_terminal.disarm();
    // The settled inspection is in hand here, so the admitted record binds the
    // configuration digest SCM actually admitted and the exact process start
    // identity it reported. The service name and configuration digest of the
    // validated request are the ones compared against it.
    let mut fields = identity.to_vec();
    fields.push((
        "observed_config_digest",
        match &inspection {
            ServiceRegistrationRuntimeInspection::Matching { observation } => {
                super::host_job_launch::LaunchIdentityField::Text(
                    observation.configuration_digest(),
                )
            }
            _ => super::host_job_launch::LaunchIdentityField::Unavailable,
        },
    ));
    // The admitted inspection's exact process start identity is rendered into a
    // named local that outlives the record below, so the identity slot borrows
    // the binding rather than a temporary that would be dropped at the end of
    // the push expression.
    let admitted_process =
        scm_inspection_process(&inspection).map(scm_render_process_start_identity);
    fields.push((
        "process",
        match admitted_process.as_deref() {
            Some(process) => super::host_job_launch::LaunchIdentityField::Text(process),
            None => super::host_job_launch::LaunchIdentityField::Unavailable,
        },
    ));
    // WORK_UNIT_CASE: 978/5 — SCM request admitted against the observed
    // start-identity; exact error propagation above is unchanged.
    scm_launch_observe_bound("host.scm-launch admitted", &fields);
    Ok(ValidatedHostScmLaunch {
        bootstrap,
        registration,
        inspection,
    })
}

/// Wire version of the per-component supervision record (#1801 W1).
pub const SUPERVISION_RECORD_WIRE: &str = "eliot.host.supervision-record.v1";

/// Retained file name of the supervision record below the Host state root.
pub const SUPERVISION_RECORD_FILE_NAME: &str = "supervision-record.json";

/// Bounded size of the retained supervision record (five rows of approved
/// digests, paths, identities, and restart-policy references).
const MAX_SUPERVISION_RECORD_BYTES: u64 = 16 * 1024;

/// Canonical supervision-table components in row order (#1801 Work item 1).
pub const SUPERVISION_RECORD_COMPONENTS: [&str; 5] =
    ["host", "watchdog", "kernel", "surreal", "doctor"];

/// One per-component record of the supervision table (#1801 W1): artifact,
/// registration or launch descriptor, admitted profile, OS/service identity
/// where applicable, supervising owner, Job membership, journal/root,
/// current generation, and restart-policy reference.
///
/// Every cell carries either an owner-observed value or an explicit
/// not-owned marker naming the owning reader (for example the Kernel-managed
/// Doctor budget, which Host never observes directly). Intended
/// (manifest-approved) and observed (live readback or pre-admission) facts
/// stay in distinct cells so a later readback can compare desired manifests
/// to actual registration/process state instead of asserting them equal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionComponentRecord {
    /// One of [`SUPERVISION_RECORD_COMPONENTS`].
    pub component: String,
    /// Approved artifact digest plus the live image digest where observed.
    pub artifact: String,
    /// Registration or launch descriptor binding the artifact.
    pub descriptor: String,
    /// Admitted installation profile (`system_service`, `user_mode`, or
    /// `portable_dev`).
    pub profile: String,
    /// OS/service identity (SCM name, Job-qualified process lineage, or the
    /// explicit marker where Host holds no handle).
    pub identity: String,
    /// Supervising owner of the component lifetime.
    pub owner: String,
    /// Job membership of the component.
    pub job: String,
    /// Journal or state root proving the component contour.
    pub journal_or_root: String,
    /// Approved generation plus the live observed generation where known.
    pub generation: String,
    /// Restart-policy reference: the owning budget and its durable evidence.
    pub restart_policy: String,
}

/// Diagnostic projection of the full supervision table: one row per
/// component of the #1801 topology, bound to the installation and Host
/// epoch that published it. This is the inspectable artifact Work item 1
/// requires: Host publishes it at open beside the journal, and the
/// installed-candidate RUN under #11 reads it back next to live SCM and Job
/// observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionRecordTable {
    /// Must equal [`SUPERVISION_RECORD_WIRE`].
    pub wire: String,
    /// Installation identity that published the table.
    pub installation: String,
    /// Host epoch sequence that published the table.
    pub host_epoch_sequence: u64,
    /// Host epoch lineage that published the table.
    pub host_lineage: String,
    /// Exactly one row per [`SUPERVISION_RECORD_COMPONENTS`], in order.
    pub rows: Vec<SupervisionComponentRecord>,
}

impl SupervisionRecordTable {
    /// Validates the table shape with the existing typed failures: a wrong
    /// wire, an unbound installation/lineage, a missing or reordered row, or
    /// an empty cell fails closed instead of publishing a partial record.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::RecoveryRequired`] when the table is not the
    /// complete five-row supervision record it claims to be.
    pub fn validate(&self) -> Result<(), HostError> {
        if self.wire != SUPERVISION_RECORD_WIRE {
            return Err(HostError::RecoveryRequired(
                "supervision record wire is not the canonical record version".to_owned(),
            ));
        }
        for bound in [&self.installation, &self.host_lineage] {
            if bound.trim().is_empty() || bound.chars().any(char::is_control) {
                return Err(HostError::RecoveryRequired(
                    "supervision record publisher binding is malformed".to_owned(),
                ));
            }
        }
        if self.rows.len() != SUPERVISION_RECORD_COMPONENTS.len() {
            return Err(HostError::RecoveryRequired(
                "supervision record does not carry every topology component".to_owned(),
            ));
        }
        for (row, expected) in self.rows.iter().zip(SUPERVISION_RECORD_COMPONENTS) {
            if row.component != expected {
                return Err(HostError::RecoveryRequired(
                    "supervision record rows are not the canonical topology order".to_owned(),
                ));
            }
            for cell in [
                &row.artifact,
                &row.descriptor,
                &row.profile,
                &row.identity,
                &row.owner,
                &row.job,
                &row.journal_or_root,
                &row.generation,
                &row.restart_policy,
            ] {
                if cell.trim().is_empty() {
                    return Err(HostError::RecoveryRequired(format!(
                        "supervision record row '{}' has an empty cell",
                        row.component
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Retained path of the supervision record below a Host state root.
#[must_use]
pub fn supervision_record_path(host_state_root: &Path) -> PathBuf {
    host_state_root.join(SUPERVISION_RECORD_FILE_NAME)
}

/// Publishes the supervision record durably beside the Host journal: the
/// staged bytes are synced, atomically moved over the retained record on the
/// same volume, committed with a directory sync, and proven back by an exact
/// validated reload. Called from `HostComposition::open` (the production
/// write path); read back with [`read_supervision_record_table`].
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the table is not publishable or the
/// atomic publication fails, and [`HostError::RecoveryRequired`] when the
/// readback differs from the published table or its cleanup fails.
#[cfg(windows)]
pub fn publish_supervision_record_table(
    host_state_root: &Path,
    table: &SupervisionRecordTable,
) -> Result<(), HostError> {
    // The table is the identity this publication is about: the installation
    // identity that published it, the Host epoch sequence and lineage it was
    // published under, and the number of canonical component rows it carries.
    // The per-row cells (artifact digests, descriptors, roots) stay in the
    // retained record and are never copied into a diagnostic record.
    let published = [
        (
            "installation",
            super::host_job_launch::LaunchIdentityField::Text(table.installation.as_str()),
        ),
        (
            "host_epoch_sequence",
            super::host_job_launch::LaunchIdentityField::Number(table.host_epoch_sequence),
        ),
        (
            "host_lineage",
            super::host_job_launch::LaunchIdentityField::Text(table.host_lineage.as_str()),
        ),
        (
            "rows",
            super::host_job_launch::LaunchIdentityField::Number(table.rows.len() as u64),
        ),
    ];
    scm_launch_observe_bound(
        "host.scm-launch supervision record publish requested",
        &published,
    );
    table.validate().map_err(|error| {
        HostError::Platform(format!("supervision record is not publishable: {error}"))
    })?;
    let bytes =
        serde_json::to_vec(table).map_err(|error| HostError::Platform(error.to_string()))?;
    if bytes.len() as u64 > MAX_SUPERVISION_RECORD_BYTES {
        return Err(HostError::Platform(
            "supervision record exceeds its bounded size".to_owned(),
        ));
    }
    let path = supervision_record_path(host_state_root);
    let tmp = host_state_root.join(format!(
        ".supervision-record.{}.tmp",
        Uuid::new_v4().simple()
    ));
    let publication = (|| {
        write_durable_file(&tmp, &bytes)?;
        eliot_windows_ipc::atomic_replace_file(&tmp, &path).map_err(|error| {
            HostError::Platform(format!("supervision record atomic replace failed: {error}"))
        })?;
        sync_dir(host_state_root)?;
        Ok(())
    })();
    // The atomic move consumes the staging file on success; on failure the
    // staging file is removed. Publication failure stays primary across
    // cleanup and its commit.
    let cleanup = std::fs::remove_file(&tmp);
    let sync_after_cleanup = sync_dir(host_state_root);
    if let Err(publication_error) = publication {
        scm_launch_observe_bound(
            "host.scm-launch supervision record publication failed",
            &published,
        );
        return Err(publication_error);
    }
    match cleanup {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "supervision record temporary cleanup failed: {error}"
            )));
        }
    }
    sync_after_cleanup?;
    let reloaded = read_supervision_record_table(host_state_root)?;
    if reloaded != *table {
        return Err(HostError::RecoveryRequired(
            "supervision record readback differs from the published table".to_owned(),
        ));
    }
    // The readback matched the published table exactly (`reloaded != *table`
    // returned above), so the published identity is the confirmed one; the
    // confirmed row count is bound so two publications of different topologies
    // stay distinguishable.
    let mut verified = published.to_vec();
    verified.push((
        "verified_rows",
        super::host_job_launch::LaunchIdentityField::Number(reloaded.rows.len() as u64),
    ));
    scm_launch_observe_bound("host.scm-launch supervision record published", &verified);
    Ok(())
}

/// Reads back the retained supervision record: the production read path for
/// the #1801 record table, used by the verified-reload step of publication
/// and by the installed-candidate RUN under #11 next to live SCM and Job
/// observations.
///
/// # Errors
///
/// Returns [`HostError::RecoveryRequired`] when the record is absent,
/// oversized, malformed, or invalid. The original record is validated with
/// the existing [`SupervisionRecordTable::validate`]; validation failures
/// stay typed.
pub fn read_supervision_record_table(
    host_state_root: &Path,
) -> Result<SupervisionRecordTable, HostError> {
    const LABEL: &str = "supervision record";
    let path = supervision_record_path(host_state_root);
    let metadata = std::fs::metadata(&path).map_err(|error| {
        HostError::RecoveryRequired(format!("{LABEL} cannot be inspected: {error}"))
    })?;
    if !metadata.is_file() || metadata.len() > MAX_SUPERVISION_RECORD_BYTES {
        return Err(HostError::RecoveryRequired(format!(
            "{LABEL} is malformed or too large"
        )));
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| HostError::RecoveryRequired(format!("{LABEL} cannot be read: {error}")))?;
    if bytes.len() as u64 > MAX_SUPERVISION_RECORD_BYTES {
        return Err(HostError::RecoveryRequired(format!(
            "{LABEL} is malformed or too large"
        )));
    }
    let table = serde_json::from_slice::<SupervisionRecordTable>(&bytes)
        .map_err(|error| HostError::RecoveryRequired(format!("{LABEL} is malformed: {error}")))?;
    table.validate()?;
    Ok(table)
}

/// Caller-supplied identity of one disposable first-install candidate
/// contour (#1801 A1).
///
/// Only the canonical `EliotHost` service identity can be inspected: the
/// platform admits no other service name, so a disposable candidate is
/// isolated by its disposable root and installation — never by a guessed
/// service name. Every path below names the candidate's own files; the
/// candidate image must already exist on disk (the registration constructor
/// proves that, it is never assumed here).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledCandidateSpec {
    /// Candidate Host image path (must exist; proven by the constructor).
    pub image_path: PathBuf,
    /// Candidate bootstrap config descriptor path.
    pub config_descriptor_path: PathBuf,
    /// Candidate bootstrap config descriptor digest (lowercase SHA-256).
    pub config_descriptor_digest: String,
    /// Candidate installation identity.
    pub installation_id: String,
    /// Candidate immutable transaction-plan generation (non-zero).
    pub transaction_plan_generation: u64,
    /// Candidate Host state root carrying the candidate registry.
    pub host_state_root: PathBuf,
    /// Filesystem root the platform adapter observes from.
    pub platform_root: PathBuf,
    /// Installation profile the candidate registry is opened under.
    pub profile: InstallationProfile,
}

/// Approved-manifest summary read back from a candidate registry: the
/// desired side of the installed-candidate readback, sourced from the
/// existing installation registry owner (never synthesized).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledCandidateManifestSummary {
    /// Approved candidate generation.
    pub generation: String,
    /// Admitted installation profile.
    pub profile: String,
    /// Approved Kernel image digest.
    pub kernel_artifact: String,
    /// Approved Store bridge image digest.
    pub store_bridge_artifact: String,
    /// Approved canonical Store engine image digest.
    pub canonical_store_artifact: String,
    /// Approved Host image digest.
    pub host_artifact: String,
    /// Approved Doctor image digest.
    pub doctor_artifact: String,
    /// Approved generation configuration digest.
    pub config_digest: String,
}

/// Exact registration plus manifest readback taken on a disposable
/// first-install candidate (#1801 A1).
///
/// `inspection` is the live platform readback for the canonical Host
/// registration (matching/absent/mismatched/unknown, with the observed
/// process identity where SCM reports one); `manifest` is the desired side
/// read from the candidate's own installation registry (`None` when the
/// candidate installed no registry yet). Branch Job/process rows for the
/// candidate's live branches are produced inside the running candidate by
/// `HostComposition::supervision_record_table` and published beside its
/// journal; the installed RUN under #11 joins both halves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledCandidateReadback {
    /// Canonical service name that was inspected (`EliotHost`).
    pub service_name: String,
    /// Expected SCM configuration digest the inspection compared against.
    pub configuration_digest: String,
    /// Live platform registration readback (data, not an error: the #11
    /// harness asserts the expected outcome from this value).
    pub inspection: ServiceRegistrationRuntimeInspection,
    /// Desired side from the candidate registry, when one is installed.
    pub manifest: Option<InstalledCandidateManifestSummary>,
}

/// Performs exact registration plus manifest readback on a disposable
/// first-install candidate contour.
///
/// TEST-PHASE (#11): this is the product code path for the
/// first-install candidate contour; the installed-candidate RUN itself
/// (install a disposable `SystemService` candidate, start it, assert exact
/// registration and process/Job readback demonstrate the supervision table)
/// follows product assembly under #11 per the issue body sequencing. This
/// function is therefore not invoked by `service_main` or `open`, and it
/// must never be pointed at the live service: it performs read-only
/// inspection only (one SCM registration readback plus one short-lived
/// registry load) and owns no register/start/stop/remove capability — the
/// only platform calls below are `inspect_service_registration_runtime`
/// and the registry read; no SCM mutation exists on this path by
/// construction.
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the candidate identity is not
/// canonical or the platform cannot be observed, [`HostError::Installation`]
/// when the candidate registry cannot be loaded, and
/// [`HostError::RecoveryRequired`] when a live observation cannot be read.
pub fn read_installed_candidate_contour(
    spec: &InstalledCandidateSpec,
) -> Result<InstalledCandidateReadback, HostError> {
    // The candidate spec is the identity this readback is about.
    let identity = scm_candidate_identity(spec);
    scm_launch_observe_bound(
        "host.scm-launch installed candidate readback requested",
        &identity,
    );
    let bootstrap = ServiceBootstrapArguments::new(
        spec.config_descriptor_path.clone(),
        spec.config_descriptor_digest.clone(),
        spec.installation_id.clone(),
        spec.transaction_plan_generation,
        std::iter::empty::<String>(),
    )
    .map_err(|error| HostError::Platform(error.to_string()))?
    .with_host_state_root(spec.host_state_root.clone())
    .map_err(|error| HostError::Platform(error.to_string()))?;
    // The candidate carries the canonical Host identity: the platform
    // admits no other service name, and `with_bootstrap` proves the
    // canonical name/display/mode/account plus the on-disk image instead
    // of trusting the spec.
    let request = ServiceRegistrationRequest::with_bootstrap(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        spec.image_path.clone(),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap,
    )
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let platform = WindowsPlatform::new(spec.platform_root.clone())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let inspection = platform.inspect_service_registration_runtime(&request);
    let configuration_digest = request.expected_configuration_digest();
    let service_name = request.service_name().to_owned();
    let store = super::open_installation_registry_with_transient_retry_for_profile(
        &spec.host_state_root,
        spec.profile,
    )?;
    let manifest = match store.as_ref() {
        None => None,
        Some(store) => {
            let registry = store.load().map_err(HostError::Installation)?;
            registry
                .active()
                .map(|active| &active.manifest)
                .or_else(|| {
                    registry
                        .pending_activation()
                        .map(|pending| &pending.manifest)
                })
                .map(|manifest| InstalledCandidateManifestSummary {
                    generation: manifest.generation.as_str().to_owned(),
                    profile: format!("{:?}", manifest.runtime_launch.profile),
                    kernel_artifact: manifest.kernel_artifact_digest.as_str().to_owned(),
                    store_bridge_artifact: manifest
                        .store_bridge_artifact_digest
                        .as_str()
                        .to_owned(),
                    canonical_store_artifact: manifest
                        .canonical_store_artifact_digest
                        .as_str()
                        .to_owned(),
                    host_artifact: manifest.host_artifact_digest.as_str().to_owned(),
                    doctor_artifact: manifest.doctor_artifact_digest.as_str().to_owned(),
                    config_digest: manifest.config_digest.as_str().to_owned(),
                })
        }
    };
    // The observed registration identity and the desired-side manifest
    // presence are in hand here, so the record binds the SCM configuration
    // digest that was actually read back, the class of the readback outcome,
    // the process start identity when SCM reported one, and whether an
    // installed manifest was found. The manifest's own artifact digests stay in
    // the returned readback and never enter a record.
    // The observed process start identity is rendered into a named local that
    // outlives the record below, so the identity slot borrows the binding rather
    // than a temporary that would be dropped at the end of the push expression.
    let observed_process =
        scm_inspection_process(&inspection).map(scm_render_process_start_identity);
    let fields = scm_candidate_readback_observed_fields(
        &identity,
        &configuration_digest,
        &inspection,
        observed_process.as_deref(),
        manifest.is_some(),
    );
    scm_launch_observe_bound(
        "host.scm-launch installed candidate readback observed",
        &fields,
    );
    Ok(InstalledCandidateReadback {
        service_name,
        configuration_digest,
        inspection,
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registration_request() -> ServiceRegistrationRequest {
        let image = std::env::current_exe().unwrap_or_else(|_| panic!("test image unavailable"));
        ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|_| panic!("test registration request must build"))
    }

    #[test]
    fn default_dacl_mismatched_sd_classifies_as_mismatched_not_unknown() {
        // A default-DACL service (Windows default service DACL, not
        // protected, no service-SID ACE) reaches the platform readback as a
        // unit `Mismatched`: configuration/SID-type/service-DACL comparison
        // differs. The host projection must preserve that cause instead of
        // collapsing Absent/Mismatched/Unknown into one string.
        let request = test_registration_request();
        let mismatched = classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Mismatched,
        )
        .unwrap_or_else(|| panic!("mismatched inspection must classify"));
        assert_eq!(
            mismatched,
            HostScmRegistrationCause::Mismatched {
                inspection_debug: "Mismatched".to_owned(),
            }
        );
        assert_eq!(mismatched.cause(), "mismatched");
        // Writer-A payload carry-over: Unknown is now typed Unknown{detail}.
        // The host projection preserves win32_error/stage/state/pid via the
        // explicit typed rendering plus Debug verbatim, still fail-closed.
        let unknown_inspection =
            ServiceRegistrationRuntimeInspection::unknown_with_status(5, "open-service", 3, 1234);
        let unknown_detail_typed = unknown_inspection
            .unknown_detail()
            .unwrap_or_else(|| panic!("unknown inspection must carry diagnostics"));
        assert_eq!(unknown_detail_typed.win32_error(), 5);
        assert_eq!(unknown_detail_typed.stage(), "open-service");
        assert_eq!(unknown_detail_typed.current_state(), Some(3));
        assert_eq!(unknown_detail_typed.process_id(), Some(1234));
        let unknown = classify_host_scm_inspection(&request, &unknown_inspection)
            .unwrap_or_else(|| panic!("unknown inspection must classify"));
        assert_eq!(unknown.cause(), "unknown");
        assert_ne!(mismatched, unknown);
        let mismatched_detail = mismatched.detail();
        let unknown_detail = unknown.detail();
        assert_eq!(
            mismatched_detail,
            "host-scm-registration-mismatched: service 'EliotHost' exists but its SCM configuration, service-SID type, or service-object security descriptor does not exactly match the canonical request (platform inspection reports Mismatched without field-level detail; inspection: Mismatched)"
        );
        assert_ne!(mismatched_detail, unknown_detail);
        assert!(mismatched_detail.contains("host-scm-registration-mismatched"));
        assert!(unknown_detail.contains("host-scm-registration-unknown"));
        // Typed preservation: the bounded cause carries win32_error/stage/
        // state/pid plus Debug verbatim.
        assert!(
            unknown_detail.contains("open-service"),
            "unknown cause must preserve stage: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains('5'),
            "unknown cause must preserve win32_error: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("Unknown"),
            "unknown cause must carry Debug verbatim: {unknown_detail}"
        );
        for detail in [&mismatched_detail, &unknown_detail] {
            assert!(
                !detail.contains("is not an exact read-only match"),
                "the old collapsed string must be gone: {detail}"
            );
            assert!(
                detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
                "cause detail must stay bounded"
            );
        }
        // The bound itself is defense-in-depth for a future platform Debug
        // payload, not just today's unit-variant text.
        assert_eq!(
            truncate_host_scm_cause(&"d".repeat(4000)).chars().count(),
            HOST_SCM_CAUSE_MAX_CHARS
        );
        // The transient-pending predicate can never fire on Mismatched/Absent
        // projections: they carry no Unknown detail at all, so genuine
        // configuration/identity drift (including a default-DACL drift) is
        // never retried and stays fail-closed on the first inspection.
        assert!(
            ServiceRegistrationRuntimeInspection::Mismatched
                .unknown_detail()
                .is_none(),
            "Mismatched must carry no Unknown detail for the pending predicate"
        );
        assert!(
            ServiceRegistrationRuntimeInspection::Absent
                .unknown_detail()
                .is_none(),
            "Absent must carry no Unknown detail for the pending predicate"
        );
    }

    #[test]
    fn runtime_starting_is_admissible_while_mismatch_and_unknown_stay_typed() {
        // s40: `ServiceMain` runs while SCM reports `START_PENDING` with a
        // live PID. The `Matching` arm of `classify_host_scm_inspection`
        // accepts `Starting` via `host_runtime_bootstrap_state_is_admissible`.
        // `ServiceRuntimeObservation` fields are `pub(super)` to the platform
        // crate, so no `Matching { observation }` value can be constructed
        // here; the admissibility predicate IS the exact gate the `Matching`
        // arm uses, and the fail-closed arms are proven below with directly
        // constructible inspection variants (Mismatched unit, typed Unknown
        // payload). No SCM calls, no mocks.
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Starting
        ));
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Stopped
        ));
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Running
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Stopping
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Unknown
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Absent
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Failed
        ));

        let request = test_registration_request();
        let mismatched = classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Mismatched,
        )
        .unwrap_or_else(|| panic!("mismatched inspection must classify"));
        // Writer-A payload: Unknown carries typed win32_error/stage/state/pid.
        let unknown_inspection = ServiceRegistrationRuntimeInspection::unknown_with_status(
            1066,
            "query-status",
            3,
            4242,
        );
        let unknown_typed = unknown_inspection
            .unknown_detail()
            .unwrap_or_else(|| panic!("unknown inspection must carry diagnostics"));
        assert_eq!(unknown_typed.win32_error(), 1066);
        assert_eq!(unknown_typed.stage(), "query-status");
        assert_eq!(unknown_typed.current_state(), Some(3));
        assert_eq!(unknown_typed.process_id(), Some(4242));
        let unknown = classify_host_scm_inspection(&request, &unknown_inspection)
            .unwrap_or_else(|| panic!("unknown inspection must classify"));
        assert_eq!(mismatched.cause(), "mismatched");
        assert_eq!(unknown.cause(), "unknown");
        assert_ne!(mismatched, unknown);
        let mismatched_detail = mismatched.detail();
        let unknown_detail = unknown.detail();
        assert_ne!(mismatched_detail, unknown_detail);
        assert!(mismatched_detail.contains("host-scm-registration-mismatched"));
        assert!(mismatched_detail.contains("inspection:"));
        assert!(mismatched_detail.contains("Mismatched"));
        assert!(unknown_detail.contains("host-scm-registration-unknown"));
        assert!(unknown_detail.contains("inspection:"));
        assert!(unknown_detail.contains("Unknown"));
        // Typed s40-1 diagnostics: the Unknown detail names the runtime
        // contour used and records that SACL was never requested, while
        // carrying the platform Debug text verbatim plus the explicit typed
        // win32_error/stage/state/pid rendering.
        assert!(
            unknown_detail.contains("inspect_service_registration_runtime"),
            "unknown detail must name the runtime contour: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("SACL"),
            "unknown detail must record that SACL was never requested: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("query-status"),
            "unknown detail must preserve stage: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("1066"),
            "unknown detail must preserve win32_error: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("4242"),
            "unknown detail must preserve pid: {unknown_detail}"
        );
        for detail in [&mismatched_detail, &unknown_detail] {
            assert!(
                detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
                "cause detail must stay bounded"
            );
        }

        // The runtime `Absent` unit variant binds the request identity
        // (service name plus configuration digest) into the cause.
        let absent =
            classify_host_scm_inspection(&request, &ServiceRegistrationRuntimeInspection::Absent)
                .unwrap_or_else(|| panic!("absent inspection must classify"));
        assert_eq!(absent.cause(), "absent");
        let absent_detail = absent.detail();
        assert!(absent_detail.contains("host-scm-registration-absent"));
        assert!(absent_detail.contains(request.service_name()));
        assert!(absent_detail.contains(&request.expected_configuration_digest()));
        assert!(
            absent_detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
            "absent detail must stay bounded"
        );
        assert_ne!(absent_detail, mismatched_detail);
        assert_ne!(absent_detail, unknown_detail);

        assert_transient_pending_predicate_cases();
    }

    /// Case table for [`host_scm_unknown_is_transient_pending`]: TRUE only
    /// for the (0, "query-status", `START_PENDING`) race triple, regardless of
    /// PID; FALSE for a real Win32 code, a non-status stage, or a
    /// non-pending state. Split from
    /// `runtime_starting_is_admissible_while_mismatch_and_unknown_stay_typed`
    /// so each test function stays within the pedantic line budget without
    /// weakening any assertion.
    fn assert_transient_pending_predicate_cases() {
        for (win32_error, stage, state, pid) in [
            (0_u32, "query-status", 2_u32, 0_u32),
            (0_u32, "query-status", 2_u32, 4242_u32),
        ] {
            let inspection = ServiceRegistrationRuntimeInspection::unknown_with_status(
                win32_error,
                stage,
                state,
                pid,
            );
            let detail = inspection
                .unknown_detail()
                .unwrap_or_else(|| panic!("unknown inspection must carry diagnostics"));
            assert!(
                host_scm_unknown_is_transient_pending(&detail),
                "({win32_error}, {stage}, {state}, {pid}) must read as transient pending"
            );
        }
        for (win32_error, stage, state, pid) in [
            (1066_u32, "query-status", 2_u32, 4242_u32),
            (0_u32, "query-config", 2_u32, 0_u32),
            (0_u32, "open-service", 0_u32, 0_u32),
        ] {
            let inspection = ServiceRegistrationRuntimeInspection::unknown_with_status(
                win32_error,
                stage,
                state,
                pid,
            );
            let detail = inspection
                .unknown_detail()
                .unwrap_or_else(|| panic!("unknown inspection must carry diagnostics"));
            assert!(
                !host_scm_unknown_is_transient_pending(&detail),
                "({win32_error}, {stage}, {state}, {pid}) must stay fail-closed without retry"
            );
        }
    }

    /// Scripted probe for the bounded re-read loop: replays platform
    /// observations without live SCM and records inspections/sleeps with a
    /// recorded clock (no real sleeping). It never classifies: every returned
    /// observation flows through the production
    /// [`resolve_host_scm_inspection_with_probe`] + [`classify_host_scm_inspection`]
    /// path, so the loop mechanics — not faked outcomes — are under test.
    struct RecordingProbe {
        script: std::collections::VecDeque<ServiceRegistrationRuntimeInspection>,
        inspections: usize,
        sleeps_ms: Vec<u64>,
    }

    impl RecordingProbe {
        fn with_script(
            script: impl IntoIterator<Item = ServiceRegistrationRuntimeInspection>,
        ) -> Self {
            Self {
                script: script.into_iter().collect(),
                inspections: 0,
                sleeps_ms: Vec::new(),
            }
        }
    }

    impl HostScmBootstrapProbe for RecordingProbe {
        fn inspect(&mut self) -> ServiceRegistrationRuntimeInspection {
            self.inspections += 1;
            self.script
                .pop_front()
                .unwrap_or_else(|| panic!("probe script exhausted"))
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            self.sleeps_ms.push(milliseconds);
        }
    }

    #[test]
    fn transient_pending_unknown_retries_then_admits_stable_match() {
        // Two transient START_PENDING/PID-race Unknowns settle to a stable
        // outcome: the loop must re-read with 250 ms sleeps and converge well
        // within 5 inspections. `ServiceRuntimeObservation` fields are
        // `pub(super)` to the platform crate, so no `Matching { observation }`
        // value can be constructed here; the scripted terminal is therefore
        // the first stable non-transient outcome (`Absent`), which proves the
        // loop exits on stability, while admission itself is proven through
        // the exact gate the `Matching` arm uses —
        // `host_runtime_bootstrap_state_is_admissible(Starting)` — the same
        // predicate-as-gate pattern as
        // `runtime_starting_is_admissible_while_mismatch_and_unknown_stay_typed`.
        let request = test_registration_request();
        let mut probe = RecordingProbe::with_script([
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 0),
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 4242),
            ServiceRegistrationRuntimeInspection::Absent,
        ]);
        let settled = resolve_host_scm_inspection_with_probe(&mut probe);
        assert_eq!(settled, ServiceRegistrationRuntimeInspection::Absent);
        assert!(
            probe.inspections <= HOST_SCM_TRANSIENT_MAX_INSPECTIONS,
            "must converge within the bounded inspections: {}",
            probe.inspections
        );
        assert_eq!(probe.inspections, 3);
        assert_eq!(
            probe.sleeps_ms,
            vec![
                HOST_SCM_TRANSIENT_RETRY_SLEEP_MS,
                HOST_SCM_TRANSIENT_RETRY_SLEEP_MS
            ]
        );
        assert_eq!(probe.sleeps_ms, vec![250, 250]);
        // The settled terminal flows through the real classifier unchanged.
        let cause = classify_host_scm_inspection(&request, &settled)
            .unwrap_or_else(|| panic!("settled absent inspection must classify"));
        assert_eq!(cause.cause(), "absent");
        // And the production terminal gate admits a stable Starting match, so
        // a converged `Matching { Starting }` readback proceeds to bootstrap.
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Starting
        ));
    }

    #[test]
    fn exhausted_pending_and_real_unknown_stay_fail_closed_1066_3() {
        // A transient that never converges exhausts the bound (5 inspections,
        // 4 × 250 ms sleeps) and stays fail-closed under the EXISTING Unknown
        // cause: no new stop code, no capsule change. The 1066/3 mapping
        // itself lives in `bins/eliot-host/src/main.rs` (`service_main` maps
        // any `validate_host_scm_bootstrap` error to
        // `HostStopCode::InvalidRegistration`, specific 3, win32 1066,
        // `invalid_scm_registration`), which this change does not touch; here
        // the unchanged `cause()` strings plus the stable
        // `host-scm-registration-*` detail prefixes and the
        // `HOST_SCM_CAUSE_MAX_CHARS` bound prove the mapping inputs are
        // identical, so the call-site projection cannot have moved.
        let request = test_registration_request();
        let mut exhaust = RecordingProbe::with_script([
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 0),
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 100),
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 200),
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 300),
            ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 4242),
        ]);
        let settled = resolve_host_scm_inspection_with_probe(&mut exhaust);
        assert_eq!(exhaust.inspections, HOST_SCM_TRANSIENT_MAX_INSPECTIONS);
        assert_eq!(exhaust.inspections, 5);
        assert_eq!(
            exhaust.sleeps_ms,
            vec![250, 250, 250, 250],
            "exhaustion must sleep 250 ms between attempts only"
        );
        let exhausted_cause = classify_host_scm_inspection(&request, &settled)
            .unwrap_or_else(|| panic!("exhausted transient must stay fail-closed"));
        assert_eq!(exhausted_cause.cause(), "unknown");
        let exhausted_detail = exhausted_cause.detail();
        assert!(exhausted_detail.contains("host-scm-registration-unknown"));
        assert!(
            exhausted_detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
            "cause detail must stay bounded"
        );

        // Fail-closed preservation: a real Win32 code, a drifted
        // registration, and an absent registration all settle with zero
        // retries and unchanged cause inputs.
        for (inspection, expected_cause, expected_prefix) in [
            (
                ServiceRegistrationRuntimeInspection::unknown_with_status(
                    1066,
                    "query-status",
                    2,
                    4242,
                ),
                "unknown",
                "host-scm-registration-unknown",
            ),
            (
                ServiceRegistrationRuntimeInspection::Mismatched,
                "mismatched",
                "host-scm-registration-mismatched",
            ),
            (
                ServiceRegistrationRuntimeInspection::Absent,
                "absent",
                "host-scm-registration-absent",
            ),
        ] {
            let mut probe = RecordingProbe::with_script([inspection]);
            let settled = resolve_host_scm_inspection_with_probe(&mut probe);
            assert_eq!(
                probe.inspections, 1,
                "{expected_cause} must settle with zero retries"
            );
            assert!(
                probe.sleeps_ms.is_empty(),
                "{expected_cause} must sleep zero times"
            );
            let cause = classify_host_scm_inspection(&request, &settled)
                .unwrap_or_else(|| panic!("{expected_cause} inspection must classify"));
            assert_eq!(cause.cause(), expected_cause);
            let detail = cause.detail();
            assert!(
                detail.contains(expected_prefix),
                "{expected_cause} detail must keep its prefix: {detail}"
            );
            assert!(
                detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
                "{expected_cause} detail must stay bounded"
            );
        }
    }
}
