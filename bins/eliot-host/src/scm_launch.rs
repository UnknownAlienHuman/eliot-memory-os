//! Read-only validation of the canonical Host SCM launch registration.

use std::path::{Path, PathBuf};

use eliot_installation::InstallationProfile;
use eliot_platform::ServiceState;
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ProcessIdentity, ServiceAccount,
    ServiceBootstrapArguments, ServiceInspectionUnknownDetail, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, WindowsPlatform,
};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use uuid::Uuid;

#[cfg(windows)]
use super::host_durable_persistence::{sync_dir, write_durable_file};
use super::{HostError, HostLaunchOptions};
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) SCM launch observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`,
// `observe_terminal_error`); the Event Log seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Structured correlation (audit 5910159678, defects 3 and 5): every
// observation carries a phase token plus the bounded identities its call site
// already holds, rendered by `crate::host_job_launch::LaunchPhaseCorrelation`
// through `host_diagnostics::bound_field`. A static label can classify a
// phase; only a bound installation, plan or host-epoch generation, approved
// configuration digest, path-free process-start identity, and typed cause kind
// say which installation generation or process incarnation produced the
// record. `operation` names exactly one identity across the whole correlation
// corpus - the canonical KernelRecord operation identity - and this file is
// never handed one, so no call site below binds it. Each slot is an
// already-held non-secret handle, counter, or typed variant name: no path,
// image name, argv, environment value, credential, nonce, connection string,
// descriptor payload, or arbitrary `Debug`/`Display` text ever enters a slot,
// and no probe, lookup, second inspection, or duplicate evaluation of an
// expression runs to obtain one. A call site that holds none of them binds
// `LaunchPhaseCorrelation::NONE`, so a missing identity stays explicitly
// missing instead of being invented. Bounding limits size, not sensitivity
// (I15.4).
//
// Recorded loss of rendered detail (issue #978; I14.20 line 296, "Identical
// labels in different typed machines are not interchangeable"): the Windows
// SCM service name (`ServiceRegistrationRequest::service_name`) is a real,
// non-secret, owner-held identity that this file always held in hand, and it
// is no longer bound into any correlation slot. The eight-key correlation
// vocabulary is frozen and has no service-name key, and `operation` names the
// canonical KernelRecord operation identity corpus-wide, so binding the SCM
// service name there gave one rendered key two unrelated identities. Every
// record that used to carry it now renders the renderer's explicit
// `operation=missing` marker, exactly like every other site that does not hold
// that identity. This is a recorded loss of rendered detail, not a claim that
// the name is unavailable, unobservable, or unimportant: the name is still
// present in the typed `HostScmRegistrationCause::Absent` detail and in
// `InstalledCandidateReadback::service_name`, both of which are unchanged.
//
// Readiness rule: an SCM request, a launched process, a PID, a start mode, and
// a `START_PENDING` state are request/liveness observations, never readiness.
// No record in this file claims readiness; semantic readiness stays with the
// owner that validates the activation receipt.
//
// Single terminal: `ScmLaunchTerminalGuard` below keeps owning the one
// terminal record of one SCM bootstrap validation, because this validation has
// no outer terminal owner of its own — `main.rs` projects the stop receipt
// without its own diagnostics terminal, unlike `lib.rs`, which already owns
// the launch contour's terminal in `lib.rs`. It therefore stays
// code-bearing rather than phase-only. `classify_*` and `resolve_*` correlate
// by order plus the bound identities and never emit a terminal. There is no
// mutable global dedup cache, and sink outcome never alters
// result/order/status/cleanup.
fn scm_launch_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

fn scm_launch_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    scm_launch_note_event_log_unavailable();
    let detail = correlation.render(phase);
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::ScmDispatch,
        &detail,
    );
}

fn scm_launch_observe_terminal(code: &str) {
    scm_launch_note_event_log_unavailable();
    super::host_diagnostics::observe_terminal_error(code);
}

/// Path-free process-start identity of one already-held [`ProcessIdentity`].
///
/// A bare PID is reusable, so the process-start identity carries the
/// handle-observed creation time with it and stays distinguishable across two
/// incarnations of the same PID. The process `image_path` is deliberately
/// excluded: a path is never a diagnostic identity (I15.4). Pure projection of
/// fields the caller already holds — no probe, handle open, or second process
/// observation runs here.
fn scm_process_start_identity(process: &ProcessIdentity) -> String {
    format!(
        "windows-pid:{pid}:start:{start}",
        pid = process.process_id,
        start = process.start_time_100ns
    )
}

/// Bounded correlation of one already-held runtime inspection.
///
/// `artifact` is the observed registration configuration digest a `Matching`
/// readback already holds (never an image name or path); `reason` is the typed
/// cause kind this observation is about, or `None` when the observation admits
/// bootstrap and therefore fails no cause. `operation` is deliberately left
/// unbound and renders `operation=missing`: this file holds no `KernelRecord`
/// operation identity on any path, and the SCM service name is not one (see the
/// recorded loss of rendered detail in the F-LOG-HOST-3 header above). A bare
/// `Unknown` PID is never bound: `process_start` stays absent unless the caller
/// already holds a real process-start identity and passes it. No probe,
/// lookup, or re-inspection happens inside.
fn scm_observed_correlation<'a>(
    inspection: &'a ServiceRegistrationRuntimeInspection,
    reason: Option<&'a str>,
    process_start: Option<&'a str>,
) -> LaunchPhaseCorrelation<'a> {
    let mut correlation = LaunchPhaseCorrelation::NONE;
    if let Some(reason) = reason {
        correlation = correlation.with_reason(reason);
    }
    if let ServiceRegistrationRuntimeInspection::Matching { observation } = inspection {
        correlation = correlation.with_artifact(observation.configuration_digest());
    }
    if let Some(process_start) = process_start {
        correlation = correlation.with_process_start(process_start);
    }
    correlation
}

/// Bounded correlation of the admitted launch identities the caller already
/// holds: the installation handle, its immutable transaction-plan generation,
/// and the approved bootstrap config descriptor digest. `operation` is
/// deliberately left unbound and renders `operation=missing` for the recorded
/// loss of rendered detail stated in the F-LOG-HOST-3 header above: the SCM
/// service name this file holds is not the corpus-wide `KernelRecord` operation
/// identity, and the frozen vocabulary has no service-name key for it. Never
/// the config descriptor path, the registration nonce, extra argv, or the
/// service image.
fn scm_bootstrap_correlation(launch_options: &HostLaunchOptions) -> LaunchPhaseCorrelation<'_> {
    LaunchPhaseCorrelation::NONE
        .with_installation(launch_options.installation().as_str())
        .with_generation(launch_options.transaction_plan_generation())
        .with_artifact(launch_options.config_descriptor_digest().as_str())
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

/// Stable secret-free name of the `absent` cause kind, shared by
/// [`HostScmRegistrationCause::cause`] and the bounded diagnostic correlation
/// so a record can never spell a cause the error detail does not.
const HOST_SCM_CAUSE_ABSENT: &str = "absent";
/// Stable secret-free name of the `mismatched` cause kind; see
/// [`HOST_SCM_CAUSE_ABSENT`].
const HOST_SCM_CAUSE_MISMATCHED: &str = "mismatched";
/// Stable secret-free name of the `unknown` cause kind; see
/// [`HOST_SCM_CAUSE_ABSENT`].
const HOST_SCM_CAUSE_UNKNOWN: &str = "unknown";

impl HostScmRegistrationCause {
    /// Stable machine-readable cause name for stderr/capsule grepability.
    #[must_use]
    pub const fn cause(&self) -> &'static str {
        match self {
            Self::Absent { .. } => HOST_SCM_CAUSE_ABSENT,
            Self::Mismatched { .. } => HOST_SCM_CAUSE_MISMATCHED,
            Self::Unknown { .. } => HOST_SCM_CAUSE_UNKNOWN,
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
    // WORK_UNIT_CASE: 978/5 — classification requested; request vs observed
    // process and start-identity vs PID stay distinct below.
    scm_launch_observe(
        "host.scm-launch classification requested",
        &scm_observed_correlation(inspection, None, None),
    );
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if host_runtime_bootstrap_state_is_admissible(observation.state()) =>
        {
            // WORK_UNIT_CASE: 978/5 — start-identity observed: the admissible
            // service identity + state accepts bootstrap; the ephemeral PID is
            // never identity. The observed configuration digest and, where a
            // live process identity is present, its path-free process-start
            // identity are already held by this readback, so both are bound;
            // no cause exists, so `reason` stays missing.
            let process_start = observation.process().map(scm_process_start_identity);
            scm_launch_observe(
                "host.scm-launch start-identity observed",
                &scm_observed_correlation(inspection, None, process_start.as_deref()),
            );
            None
        }
        ServiceRegistrationRuntimeInspection::Matching { observation } => {
            // WORK_UNIT_CASE: 978/5 — admissible start-identity absent; the
            // observed state cannot bootstrap, so this is a fail-closed
            // liveness observation and never a readiness claim. The same
            // observed identities plus the typed `unknown` cause kind are
            // bound from what this readback already holds.
            let process_start = observation.process().map(scm_process_start_identity);
            scm_launch_observe(
                "host.scm-launch start-identity unknown",
                &scm_observed_correlation(
                    inspection,
                    Some(HOST_SCM_CAUSE_UNKNOWN),
                    process_start.as_deref(),
                ),
            );
            Some(HostScmRegistrationCause::Unknown {
                inspection_debug: format!("{inspection:?}"),
            })
        }
        ServiceRegistrationRuntimeInspection::Absent => {
            // WORK_UNIT_CASE: 978/5 — SCM request observed: the canonical
            // registration request has no observed process. The correlation
            // binds the admitted configuration digest the cause retains, read
            // once. The queried registration name is retained by the returned
            // cause but is no longer bound into any correlation slot — the
            // recorded loss of rendered detail stated in the F-LOG-HOST-3
            // header above — so `operation` renders `operation=missing`. No
            // process identity is bound because an absent registration has
            // none.
            let configuration_digest = request.expected_configuration_digest();
            scm_launch_observe(
                "host.scm-launch request observed",
                &scm_observed_correlation(inspection, Some(HOST_SCM_CAUSE_ABSENT), None)
                    .with_artifact(&configuration_digest),
            );
            Some(HostScmRegistrationCause::Absent {
                service_name: request.service_name().to_owned(),
                configuration_digest,
            })
        }
        ServiceRegistrationRuntimeInspection::Mismatched => {
            // WORK_UNIT_CASE: 978/5 — observed process exists but is not the
            // requested registration. The unit variant carries no observed
            // digest or process identity, so the typed cause kind is the only
            // identity this record binds; `operation` and `process_start`
            // render as `missing`.
            scm_launch_observe(
                "host.scm-launch process observed",
                &scm_observed_correlation(inspection, Some(HOST_SCM_CAUSE_MISMATCHED), None),
            );
            Some(HostScmRegistrationCause::Mismatched {
                inspection_debug: format!("{inspection:?}"),
            })
        }
        ServiceRegistrationRuntimeInspection::Unknown { detail } => {
            // WORK_UNIT_CASE: 978/5 — ephemeral PID observation; never
            // promoted into start-identity. A bare PID is never bound as a
            // process-start identity, so `process_start` stays missing and only
            // the typed cause kind carries this record; the request-bound
            // operation identity is deliberately no longer bound (recorded loss
            // of rendered detail, F-LOG-HOST-3 header above), and re-deriving
            // the admitted configuration digest here would be a second
            // evaluation, so that stays missing too.
            scm_launch_observe(
                "host.scm-launch pid observed",
                &scm_observed_correlation(inspection, Some(HOST_SCM_CAUSE_UNKNOWN), None),
            );
            // Typed payload carry-over: preserve win32_error/stage/state/pid
            // explicitly via the typed rendering plus Debug verbatim. Both
            // stay bounded through truncate_host_scm_cause downstream.
            // SACL is never requested (platform DACL-only); Unknown stays
            // fail-closed 1066/3.
            Some(HostScmRegistrationCause::Unknown {
                inspection_debug: format!("{} | {inspection:?}", detail.detail()),
            })
        }
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
///
/// `correlation` carries only identities the caller already holds; the loop
/// borrows it for its two observations and neither inspects extra nor changes
/// the bounded inspection count.
fn resolve_host_scm_inspection_with_probe<P: HostScmBootstrapProbe>(
    probe: &mut P,
    correlation: &LaunchPhaseCorrelation<'_>,
) -> ServiceRegistrationRuntimeInspection {
    // WORK_UNIT_CASE: 978/13 — deterministic probe schedule requested; the
    // injected inspection script drives the bounded re-read loop. The caller
    // passes the admitted launch identities it already holds, so both loop
    // records correlate to the exact installation generation and approved
    // configuration digest instead of to a static label alone; the loop itself
    // never inspects extra.
    scm_launch_observe("host.scm-launch probe requested", correlation);
    let mut current = probe.inspect();
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
    }
    // WORK_UNIT_CASE: 978/5 — settled status observation; the observed
    // configuration digest and process-start identity of this settled
    // readback, and its typed cause kind, are bound by the classifier, which
    // is the sole inspection-to-cause mapping site. A bare PID is never bound
    // here, so a reusable PID cannot masquerade as a start identity.
    scm_launch_observe("host.scm-launch pid observed", correlation);
    current
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
    // WORK_UNIT_CASE: 978/5 — SCM bootstrap requested; the single outermost
    // contour owns the one terminal below (#891 owns nothing here; main.rs
    // ServiceMain projects the stop receipt without its own diagnostics
    // terminal, so this guard keeps owning it).
    //
    // The admitted installation handle, its transaction-plan generation, and
    // the approved bootstrap config descriptor digest are already in
    // `launch_options`. The canonical registration request does not exist yet at
    // this point, and even once it does this file binds no `operation` identity
    // (recorded loss of rendered detail, F-LOG-HOST-3 header above), so every
    // record below renders `operation=missing` rather than guessing an identity
    // from a constant.
    scm_launch_observe(
        "host.scm-launch requested",
        &scm_bootstrap_correlation(launch_options),
    );
    // WORK_UNIT_CASE: 978/10 — one terminal across the SCM nesting:
    // classification and probe correlate by stage order plus their bound
    // identities; only this guard may emit the SCM unknown code.
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
    let registration_correlation = scm_bootstrap_correlation(launch_options);
    let inspection = {
        let mut probe = WindowsScmBootstrapProbe {
            platform: &platform,
            registration: &registration,
        };
        resolve_host_scm_inspection_with_probe(&mut probe, &registration_correlation)
    };
    if let Some(cause) = classify_host_scm_inspection(&registration, &inspection) {
        return Err(HostError::Platform(cause.detail()));
    }
    scm_terminal.disarm();
    // WORK_UNIT_CASE: 978/5 — SCM request admitted against the observed
    // start-identity; exact error propagation above is unchanged. Admission is
    // a registration/liveness fact, never readiness: the observed process
    // identity and configuration digest of this inspection were already bound
    // by the classifier record for the same readback.
    scm_launch_observe("host.scm-launch admitted", &registration_correlation);
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
    // The publishing installation identity and the Host epoch sequence are
    // already held in the table; the state root below is a path and stays
    // unbound, and the five per-component approved digests are the table's own
    // content rather than one artifact identity of this operation.
    let record_correlation = LaunchPhaseCorrelation::NONE
        .with_installation(table.installation.as_str())
        .with_generation(table.host_epoch_sequence);
    scm_launch_observe(
        "host.scm-launch supervision record publish requested",
        &record_correlation,
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
        scm_launch_observe(
            "host.scm-launch supervision record publication failed",
            &record_correlation,
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
    scm_launch_observe(
        "host.scm-launch supervision record published",
        &record_correlation,
    );
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
    // The candidate installation identity, its immutable transaction-plan
    // generation, and the approved candidate config descriptor digest are
    // already held in `spec`; the candidate image path, config descriptor
    // path, and state root stay unbound.
    //
    // The `artifact` slot of THIS record carries the approved candidate config
    // DESCRIPTOR digest, and only that: at this point the canonical
    // registration request does not exist yet, so no SCM configuration digest
    // has been computed and none is guessed. The later
    // "…readback observed" record binds the SCM configuration digest of the
    // request it just inspected instead, so the two phases of this one
    // candidate readback carry two different approved facts under the same
    // frozen key rather than one silently replacing the other; see the comment
    // at that second site.
    let candidate_correlation = LaunchPhaseCorrelation::NONE
        .with_installation(&spec.installation_id)
        .with_generation(spec.transaction_plan_generation)
        .with_artifact(&spec.config_descriptor_digest);
    scm_launch_observe(
        "host.scm-launch installed candidate readback requested",
        &candidate_correlation,
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
    // The readback is bound to the admitted candidate identities and to the
    // exact query it made: the approved configuration digest it compared
    // against, already computed above. This stays a read-only registration
    // observation — it proves the registration contour, never any service
    // readiness.
    //
    // `operation` is deliberately left unbound here, for the recorded loss of
    // rendered detail stated in the F-LOG-HOST-3 header above: the candidate SCM
    // service name read at this point is a real, non-secret, owner-held identity,
    // but it is not the corpus-wide `KernelRecord` operation identity and the
    // frozen eight-key vocabulary has no service-name key for it. The record
    // therefore renders `operation=missing`. The name itself is not discarded —
    // it is returned unchanged in `InstalledCandidateReadback::service_name`
    // below.
    //
    // The `artifact` slot of THIS record therefore carries the SCM
    // configuration digest of the canonical request just built
    // (`ServiceRegistrationRequest::expected_configuration_digest`, the digest
    // the runtime readback compared against), not the approved candidate config
    // descriptor digest the "…readback requested" record above carries. Those
    // are two different approved facts of the same candidate — one hashes the
    // descriptor, the other the whole canonical SCM registration — so the
    // second `with_artifact` deliberately rebinds this slot instead of letting
    // the descriptor digest stand in for a digest that was never observed here.
    // The correlation carries one artifact slot, so the two facts stay in two
    // records rather than in a second invented slot.
    scm_launch_observe(
        "host.scm-launch installed candidate readback observed",
        &candidate_correlation.with_artifact(&configuration_digest),
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
    use std::sync::{Arc, Mutex};

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

    /// In-memory sink that captures facade output without contending for the
    /// process-global subscriber.
    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `emit` under a scoped `tracing` subscriber and returns the captured
    /// facade output.
    ///
    /// Timestamps are suppressed so two identical production calls produce
    /// byte-identical captures and a determinism assertion below compares the
    /// records themselves rather than wall-clock noise.
    fn capture(emit: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = sink
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Runs the real production classifier [`classify_host_scm_inspection`] for
    /// one inspection under a scoped subscriber and returns the records the
    /// facade emitted for it.
    ///
    /// Every assertion in the case-5 and case-4/13 tests below reads this text.
    /// No expected log record is composed by the test, no visibility is
    /// widened, and no production algorithm is restated: the classifier, its
    /// correlations and the facade call are the only producers of these bytes.
    fn capture_classified(
        request: &ServiceRegistrationRequest,
        inspection: &ServiceRegistrationRuntimeInspection,
    ) -> String {
        capture(|| {
            let _classified = classify_host_scm_inspection(request, inspection);
        })
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
        let settled =
            resolve_host_scm_inspection_with_probe(&mut probe, &LaunchPhaseCorrelation::NONE);
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
        let settled =
            resolve_host_scm_inspection_with_probe(&mut exhaust, &LaunchPhaseCorrelation::NONE);
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
            let settled =
                resolve_host_scm_inspection_with_probe(&mut probe, &LaunchPhaseCorrelation::NONE);
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

    /// Honest unit proof of the private [`scm_process_start_identity`]
    /// projection and nothing else.
    ///
    /// This test deliberately carries no work-unit case marker. The
    /// `Matching { observation }` arm of [`classify_host_scm_inspection`] — the
    /// only production site that binds a process-start identity — needs a
    /// `ServiceRuntimeObservation` whose fields are `pub(super)` inside
    /// `eliot-platform-windows`, so that arm cannot be reached, let alone
    /// observed, from any eliot-host seam. The positive two-incarnation record
    /// therefore belongs to `eliot-platform-windows`' own owner tests; what is
    /// Host-proved here is captured in
    /// `classify_records_bind_typed_cause_leave_operation_missing_and_never_a_bare_pid`.
    #[test]
    fn process_start_identity_separates_two_incarnations_of_one_pid_and_hides_the_path() {
        const CANARY_IMAGE: &str = r"C:\canary\service-image.exe";
        let first = ProcessIdentity {
            process_id: 4242,
            start_time_100ns: 133_000_000_000_000_001,
            image_path: CANARY_IMAGE.to_owned(),
        };
        let second = ProcessIdentity {
            start_time_100ns: 133_000_000_000_000_002,
            ..first.clone()
        };
        let first_identity = scm_process_start_identity(&first);
        let second_identity = scm_process_start_identity(&second);
        assert_ne!(
            first_identity, second_identity,
            "one reused PID must never yield one process-start identity"
        );
        assert!(first_identity.contains("4242"));
        assert!(first_identity.contains("133000000000000001"));
        assert!(
            !first_identity.contains(CANARY_IMAGE),
            "an image path is never a diagnostic identity: {first_identity}"
        );
        assert!(!first_identity.contains("canary"));
    }

    /// `WORK_UNIT_CASE`: 978/5 — the real, reachable production path
    /// [`classify_host_scm_inspection`] binds the typed cause kind into the
    /// record the facade emits, renders `operation` as the explicit `missing`
    /// marker because this file holds no `KernelRecord` operation identity, and
    /// never promotes a bare observed PID into a process-start identity;
    /// `WORK_UNIT_CASE`: 978/12 — those emitted records carry no image path.
    ///
    /// Every assertion below reads bytes captured out of a scoped `tracing`
    /// subscriber while the production classifier ran: no expected log record
    /// is hand-constructed here, no private visibility is widened, and no
    /// production algorithm is restated. `Absent`, `Mismatched` and the typed
    /// `Unknown { detail }` payload are the inspection values constructible from
    /// outside `eliot-platform-windows`; the positive `Matching` arm requires a
    /// `ServiceRuntimeObservation` whose fields are `pub(super)` to that crate
    /// and is its owner tests' proof, as recorded in the sibling helper test.
    #[test]
    fn classify_records_bind_typed_cause_leave_operation_missing_and_never_a_bare_pid() {
        let request = test_registration_request();
        let service_name = request.service_name().to_owned();
        let image_path = request.binary_path().display().to_string();

        // `Absent`: the typed `absent` cause kind reaches the emitted record, and
        // `operation` renders the renderer's own `missing` marker — that key
        // names the canonical KernelRecord operation identity corpus-wide, so
        // the SCM service name this call site holds may not fill it (recorded
        // loss of rendered detail, F-LOG-HOST-3 header).
        let absent_records =
            capture_classified(&request, &ServiceRegistrationRuntimeInspection::Absent);
        assert!(
            absent_records.contains("operation=missing"),
            "the unbound operation identity must render explicitly missing: {absent_records}"
        );
        assert!(
            !absent_records.contains(&service_name),
            "the SCM service name must reach no correlation slot: {absent_records}"
        );
        assert!(
            absent_records.contains(&format!("reason={HOST_SCM_CAUSE_ABSENT}")),
            "the typed absent cause kind must reach the emitted record: {absent_records}"
        );
        assert!(
            absent_records.contains("process_start=missing"),
            "an absent registration observed no process: {absent_records}"
        );

        // `Mismatched`: a different typed cause kind on the same request.
        let mismatched_records =
            capture_classified(&request, &ServiceRegistrationRuntimeInspection::Mismatched);
        assert!(
            mismatched_records.contains("operation=missing"),
            "the unbound operation identity must render explicitly missing: {mismatched_records}"
        );
        assert!(
            !mismatched_records.contains(&service_name),
            "the SCM service name must reach no correlation slot: {mismatched_records}"
        );
        assert!(
            mismatched_records.contains(&format!("reason={HOST_SCM_CAUSE_MISMATCHED}")),
            "the typed mismatched cause kind must reach the emitted record: {mismatched_records}"
        );
        assert!(
            mismatched_records.contains("process_start=missing"),
            "the unit Mismatched variant carries no observed process: {mismatched_records}"
        );
        assert!(
            !mismatched_records.contains(&format!("reason={HOST_SCM_CAUSE_UNKNOWN}")),
            "a registration drift must never collapse into the unknown cause: {mismatched_records}"
        );

        // A transient `START_PENDING` readback carries a bare PID in the
        // platform payload. The emitted record must name the typed `unknown`
        // cause kind and must leave the process-start slot explicitly missing:
        // a reusable PID is never a process-start identity.
        let pending = ServiceRegistrationRuntimeInspection::unknown_with_status(
            0,
            "query-status",
            HOST_SCM_START_PENDING_STATE,
            987_654,
        );
        let pending_records = capture_classified(&request, &pending);
        assert!(
            pending_records.contains(&format!("reason={HOST_SCM_CAUSE_UNKNOWN}")),
            "the typed unknown cause kind must reach the emitted record: {pending_records}"
        );
        assert!(
            pending_records.contains("process_start=missing"),
            "a bare PID must never be promoted into a process-start identity: {pending_records}"
        );
        assert!(
            !pending_records.contains("987654"),
            "a bare PID must never reach the emitted record: {pending_records}"
        );

        // Case 12: the captured production records carry no path canary, and
        // they are real records rather than empty captures.
        for records in [&absent_records, &mismatched_records, &pending_records] {
            assert!(
                records.contains("host.entrypoint_stage"),
                "each production classification must emit facade records: {records}"
            );
            assert!(
                !records.contains(&image_path),
                "no image path may reach an emitted record: {records}"
            );
        }
    }

    /// `WORK_UNIT_CASE`: 978/4 — an SCM request and an observed status sample
    /// are request/liveness observations, never readiness and never a
    /// process-start identity; `WORK_UNIT_CASE`: 978/13 — those emitted records
    /// are deterministic per held identity and differ per typed inspection;
    /// and `WORK_UNIT_CASE`: 978/12 — no path value appears in them.
    ///
    /// Every assertion below reads records captured out of a scoped `tracing`
    /// subscriber while the real [`classify_host_scm_inspection`] production
    /// function ran. Nothing here renders or formats a detail string, so no
    /// assertion can pass on a record this test composed itself.
    #[test]
    fn observed_correlation_binds_held_identity_without_path_nonce_or_bare_pid() {
        let request = test_registration_request();
        let image_path = request.binary_path().display().to_string();
        let configuration_digest = request.expected_configuration_digest();
        let absent_inspection = ServiceRegistrationRuntimeInspection::Absent;

        // One real `Absent` classification emits the classifier's own request
        // record plus its typed request observation, the latter carrying the
        // admitted configuration digest the cause retains and no observed
        // process. Only the latter carries that digest: `scm_observed_correlation`
        // binds `artifact` only for a `Matching` readback, so the classifier's
        // own request record holds no observed configuration digest and renders
        // `artifact=missing`, which is why the digest assertion below reads the
        // two-record window rather than one named record. The SCM service name
        // the cause also retains is bound nowhere in the correlation (recorded
        // loss of rendered detail, F-LOG-HOST-3 header), so `operation` renders
        // `operation=missing` on both records.
        let absent_records = capture_classified(&request, &absent_inspection);
        assert!(
            absent_records.contains("phase=host.scm-launch classification requested"),
            "the classifier must emit its own request record: {absent_records}"
        );
        assert!(
            absent_records.contains("phase=host.scm-launch request observed"),
            "the absent arm must emit its typed request record: {absent_records}"
        );
        assert!(
            absent_records.contains(&format!("artifact={configuration_digest}")),
            "the absent record must carry the request-bound configuration digest: {absent_records}"
        );
        assert!(
            absent_records.contains("process_start=missing"),
            "an absent registration observed no process: {absent_records}"
        );
        // Case 4: an SCM registration request is not readiness, so no emitted
        // record in this path may claim it.
        assert!(
            !absent_records.contains("ready"),
            "an SCM registration request is never a readiness record: {absent_records}"
        );

        // Case 13: identical held identities and an identical typed inspection
        // produce byte-identical production records — determinism, not a count.
        let repeated = capture_classified(&request, &absent_inspection);
        assert_eq!(
            absent_records, repeated,
            "identical held identities must produce identical production records"
        );
        // ... and a different typed inspection produces a different record set
        // instead of one vacuous field set.
        let mismatched_records =
            capture_classified(&request, &ServiceRegistrationRuntimeInspection::Mismatched);
        assert_ne!(
            absent_records, mismatched_records,
            "typed inspections must not collapse into one record set"
        );
        assert!(
            mismatched_records.contains("phase=host.scm-launch process observed"),
            "the mismatched arm must emit its own phase record: {mismatched_records}"
        );
        assert!(
            mismatched_records.contains(&format!("reason={HOST_SCM_CAUSE_MISMATCHED}")),
            "the mismatched record must name its typed cause kind: {mismatched_records}"
        );
        assert!(
            mismatched_records.contains("process_start=missing"),
            "the unit Mismatched variant carries no observed process: {mismatched_records}"
        );

        // Case 12: the captured production records carry no path canary.
        for records in [&absent_records, &mismatched_records] {
            assert!(
                records.contains("host.entrypoint_stage"),
                "each production classification must emit facade records: {records}"
            );
            assert!(
                !records.contains(&image_path),
                "no image path may reach an emitted record: {records}"
            );
        }
    }
}
