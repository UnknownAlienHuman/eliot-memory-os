//! Read-only installed Watchdog registration selection and runtime inspection.
//!
//! Architecture anchors: `A8` (Watchdog) and `ARCH-WDG-01` (independent
//! supervision). Implementation anchors: `I1.2` (Host SCM lifecycle), `I1.4`
//! (SCM supervision tree), and `I8.2` (independent observation routes).
//!
//! This child owns only approved request selection and read-only registration
//! inspection; it has no authority to register, start, stop, or replace the
//! Watchdog service.

use std::path::Path;

use eliot_platform_windows::ServiceBootstrapArguments;

use super::super::{
    ApprovedGenerationRegistry, CandidateManifest, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, HostError, InstallationProfile,
    InstallerServiceRegistrationApproval, InstallerServiceRole, PlatformHandle, ProcessIdentity,
    RuntimeLaunchDescriptor, ServiceAccount, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, ServiceState, WindowsPlatform,
    phase_b_scm_selector, windows_paths_equal,
};

// F-LOG-HOST-4 (#979) inspection helpers.
//
// Through the #889 facade only
// (`super::super::host_diagnostics::observe_entrypoint_with_detail`); the
// Event Log seam stays typed-Unavailable
// (`super::super::windows_event_log::event_log_sink_status`), never
// implemented here (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner through ONE closed typed observation
// (`WatchdogInspectionObservation` + `watchdog_inspection_observe`, the same
// facade and the same bounding helper its parent uses). Each record carries
// the canonical service registration identity, the approved bootstrap
// installation, immutable transaction-plan generation and approved config
// descriptor digest, the approved manifest generation, the observed SCM state
// and wait hint, and the process PID/start pair the owner validated — so a
// stale observation can never be told from a current one by adjacency alone
// (I7.20). An identity this owner does not hold stays an explicit unavailable
// field rather than a static sentence pretending to be an identity. Never a
// raw image path, argv, environment value, bootstrap nonce, credential or key
// material, or arbitrary `Debug`/serde error text, so bounding limits size,
// not sensitivity (I15.4). `Running` here is SCM liveness only: no record may
// imply heartbeat or independent supervision. Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision;
// these phase observations never emit a terminal. A bare `?` on an
// already-observed inner boundary propagates without a second record.
#[cfg(windows)]
fn watchdog_inspection_note_event_log_unavailable() {
    let _ = super::super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn watchdog_inspection_observe(observation: &super::WatchdogInspectionObservation<'_>) {
    watchdog_inspection_note_event_log_unavailable();
    let mut detail = String::from(observation.label);
    for (key, value) in [
        ("service", observation.service),
        ("install", observation.installation),
        ("plan", observation.approved_plan_generation),
        ("config", observation.config_descriptor_digest),
        ("gen", observation.approved_generation),
        ("state", observation.state),
        ("wait", observation.wait_hint_ms),
        ("pid", observation.process_id),
        ("start", observation.process_start),
    ] {
        detail.push(' ');
        detail.push_str(key);
        detail.push('=');
        detail.push_str(value.unwrap_or(WATCHDOG_INSPECTION_IDENTITY_UNAVAILABLE));
    }
    super::super::host_diagnostics::observe_entrypoint_with_detail(
        super::super::host_diagnostics::EntrypointStage::ScmDispatch,
        &detail,
    );
}

/// The explicit disposition of one Watchdog inspection identity this boundary
/// does not hold (F-LOG-HOST-4, #979). It stays a real slot value: never a
/// fabricated, defaulted, recomputed, or statically-worded stand-in for an
/// identity this owner never produced.
#[cfg(windows)]
const WATCHDOG_INSPECTION_IDENTITY_UNAVAILABLE: &str = "unavailable";

/// The closed set of nonsecret Watchdog inspection identities this owner may
/// bind to one read-only inspection observation (F-LOG-HOST-4, #979).
///
/// Every slot is either the exact value the owner already validated or
/// observed — the canonical service registration name, its bootstrap
/// installation, immutable transaction-plan generation and approved config
/// descriptor digest, the approved manifest generation, the observed SCM state
/// and wait hint, and the process PID/start pair — or the explicit
/// [`WATCHDOG_INSPECTION_IDENTITY_UNAVAILABLE`] disposition. The image path,
/// argv, environment, bootstrap nonce, credential, and any
/// `Debug`/serde error text never cross; the process slots carry only the two
/// owner-issued numbers the issue permits. `Running` here is SCM liveness only:
/// no record may imply heartbeat or independent supervision.
#[cfg(windows)]
struct WatchdogInspectionObservation<'a> {
    label: &'static str,
    service: Option<&'a str>,
    installation: Option<&'a str>,
    approved_plan_generation: Option<String>,
    config_descriptor_digest: Option<&'a str>,
    approved_generation: Option<&'a str>,
    state: Option<&'static str>,
    wait_hint_ms: Option<String>,
    process_id: Option<String>,
    process_start: Option<String>,
}

#[cfg(windows)]
impl<'a> WatchdogInspectionObservation<'a> {
    /// The observation of a boundary reached before this owner holds any
    /// registration identity.
    fn unavailable(label: &'static str) -> Self {
        Self {
            label,
            service: None,
            installation: None,
            approved_plan_generation: None,
            config_descriptor_digest: None,
            approved_generation: None,
            state: None,
            wait_hint_ms: None,
            process_id: None,
            process_start: None,
        }
    }

    /// Binds the canonical service registration identities of the approved
    /// request this contour inspects. All values are copied from the
    /// owner-validated request; none is re-derived.
    fn for_registration(label: &'static str, registration: &'a ServiceRegistrationRequest) -> Self {
        let mut observation = Self::unavailable(label);
        observation.service = Some(registration.service_name());
        let Some(bootstrap) = registration.bootstrap() else {
            return observation;
        };
        observation.installation = Some(bootstrap.installation_id());
        observation.approved_plan_generation =
            Some(bootstrap.transaction_plan_generation().to_string());
        observation.config_descriptor_digest = Some(bootstrap.config_descriptor_digest());
        observation
    }

    /// Binds the approved manifest generation this registration was approved
    /// against, so two generations of the same service never share a record.
    fn with_approved_generation(mut self, generation: &'a str) -> Self {
        self.approved_generation = Some(generation);
        self
    }

    /// Binds the approved launch's installation identity, which the caller
    /// already holds before the registration request is reconstructed.
    fn with_approved_launch_installation(mut self, launch: &'a RuntimeLaunchDescriptor) -> Self {
        self.installation = Some(launch.installation_epoch.installation.as_str());
        self
    }

    /// Binds the observed SCM state through its frozen 1:1 label, never its
    /// `Debug` text.
    fn with_state(mut self, state: ServiceState) -> Self {
        self.state = Some(super::watchdog_service_state_label(state));
        self
    }

    /// Binds the owner-reported responsiveness wait hint. Only a `Matching`
    /// readback carries one; every other outcome leaves it explicitly
    /// unavailable rather than substituting a number.
    fn with_wait_hint(mut self, wait_hint_ms: u32) -> Self {
        self.wait_hint_ms = Some(wait_hint_ms.to_string());
        self
    }

    /// Binds the observed process PID/start pair. The image path this owner
    /// validated never crosses.
    fn with_process(mut self, process: Option<&'a ProcessIdentity>) -> Self {
        if let Some(process) = process {
            self.process_id = Some(process.process_id.to_string());
            self.process_start = Some(process.start_time_100ns.to_string());
        }
        self
    }

    /// Binds the exact process PID/start pair and approved plan generation the
    /// owner has already proved, copied from its own
    /// `VerifiedWatchdogScmRunning` record. `None` for the approved plan
    /// generation of a bootstrap-less registration stays explicitly
    /// unavailable rather than becoming a substitute number.
    fn with_verified(mut self, verified: &'a VerifiedWatchdogScmRunning) -> Self {
        self.process_id = Some(verified.process.process_id.to_string());
        self.process_start = Some(verified.process.start_time_100ns.to_string());
        self.approved_plan_generation = verified
            .approved_plan_generation
            .map(|generation| generation.to_string());
        self
    }
}

#[cfg(windows)]
pub fn approved_service_registration_request(
    launch: &RuntimeLaunchDescriptor,
    approval: &InstallerServiceRegistrationApproval,
    role: InstallerServiceRole,
    expected_image: &PlatformHandle,
) -> Result<ServiceRegistrationRequest, HostError> {
    if approval.role() != role || approval.generation() != &launch.generation {
        // WORK_UNIT_CASE: 979/4 — approval bound to another role/generation, never used.
        // The approved launch identities are already in hand and are bound;
        // no request identity exists yet, so those slots stay unavailable.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::unavailable(
                "watchdog.inspection approval role rejected",
            )
            .with_approved_generation(launch.generation.as_str())
            .with_approved_launch_installation(launch),
        );
        return Err(HostError::ProcessContour(
            "SCM registration approval does not match the approved runtime launch".to_owned(),
        ));
    }
    let request = approval.service_registration_request().map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — approval not reconstructible, never used.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::unavailable("watchdog.inspection approval unreadable")
                .with_approved_generation(launch.generation.as_str())
                .with_approved_launch_installation(launch),
        );
        HostError::Installation(error)
    })?;
    let expected_name = match role {
        InstallerServiceRole::Host => ELIOT_HOST_SERVICE_NAME,
        InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_NAME,
    };
    // The reconstructed request is now in hand; the approved launch generation
    // and installation stay bound beside it so a refusal names the exact
    // generation the request was reconstructed against.
    let admitted = WatchdogInspectionObservation::for_registration(
        "watchdog.inspection approval non-canonical",
        &request,
    )
    .with_approved_generation(launch.generation.as_str());
    if request.service_name() != expected_name
        || request.binary_path() != Path::new(expected_image.as_str())
        || request.start_mode() != ServiceStartMode::Automatic
        || request.account() != ServiceAccount::LocalService
    {
        // WORK_UNIT_CASE: 979/4 — non-canonical reconstruction, never used.
        watchdog_inspection_observe(&admitted);
        return Err(HostError::ProcessContour(
            "SCM registration approval reconstructed a non-canonical service request".to_owned(),
        ));
    }
    let bootstrap = request.bootstrap().ok_or_else(|| {
        // WORK_UNIT_CASE: 979/4 — bootstrap absent, never used.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::for_registration(
                "watchdog.inspection approval bootstrap absent",
                &request,
            )
            .with_approved_generation(launch.generation.as_str()),
        );
        HostError::ProcessContour(
            "SCM registration approval did not reconstruct a typed bootstrap".to_owned(),
        )
    })?;
    let expected_descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — Phase-B SCM selector boundary.
            watchdog_inspection_observe(&admitted);
            HostError::Installation(error)
        })?;
    if bootstrap.config_descriptor_path() != Path::new(launch.authority_descriptor_path.as_str())
        || bootstrap.config_descriptor_digest() != expected_descriptor_digest.as_str()
        || bootstrap.installation_id() != launch.installation_epoch.installation.as_str()
        || bootstrap.host_state_root()
            != Some(Path::new(
                launch.runtime_state_roots.host_state_root.as_str(),
            ))
        || bootstrap.registration_nonce().is_none()
    {
        // WORK_UNIT_CASE: 979/4 — inexact bootstrap binding, never used.
        watchdog_inspection_observe(&admitted);
        return Err(HostError::ProcessContour(
            "SCM registration approval bootstrap is not exact".to_owned(),
        ));
    }
    // `transaction_plan_generation` is the immutable SCM selector minted in
    // Phase A. The live ORS authority generation may advance in Phase B, so
    // callers must bind that value through the Host receipt before admission.
    // WORK_UNIT_CASE: 979/4 — approval admitted with exact registration identity.
    watchdog_inspection_observe(
        &WatchdogInspectionObservation::for_registration(
            "watchdog.inspection approval admitted",
            &request,
        )
        .with_approved_generation(launch.generation.as_str()),
    );
    Ok(request)
}

#[cfg(windows)]
pub fn select_watchdog_approval_for_inspection(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
) -> Result<Option<InstallerServiceRegistrationApproval>, HostError> {
    if manifest.runtime_launch.profile != InstallationProfile::SystemService {
        // WORK_UNIT_CASE: 979/4 — non-service profile needs no Watchdog approval.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::unavailable(
                "watchdog.inspection non-service profile",
            )
            .with_approved_generation(manifest.generation.as_str())
            .with_approved_launch_installation(&manifest.runtime_launch),
        );
        return Ok(None);
    }
    let approval = registry
        .service_registration_approval(
            &manifest.runtime_launch.generation,
            InstallerServiceRole::Watchdog,
        )
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/4 — Watchdog SCM approval absent, never selected.
            watchdog_inspection_observe(
                &WatchdogInspectionObservation::unavailable("watchdog.inspection approval absent")
                    .with_approved_generation(manifest.generation.as_str())
                    .with_approved_launch_installation(&manifest.runtime_launch),
            );
            HostError::ProcessContour(
                "approved generation is missing the installer-owned Watchdog SCM approval"
                    .to_owned(),
            )
        })?;
    // `?` propagates the already-observed inner approval boundary; no second record.
    let request = approved_service_registration_request(
        &manifest.runtime_launch,
        approval,
        InstallerServiceRole::Watchdog,
        &manifest.runtime_launch.watchdog_executable_path,
    )?;
    // WORK_UNIT_CASE: 979/4 — Watchdog approval selected with exact identity.
    watchdog_inspection_observe(
        &WatchdogInspectionObservation::for_registration(
            "watchdog.inspection approval selected",
            &request,
        )
        .with_approved_generation(manifest.generation.as_str()),
    );
    Ok(Some(approval.clone()))
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstalledWatchdogRuntimeInspection {
    Matching {
        state: ServiceState,
        wait_hint_ms: u32,
        process: Option<ProcessIdentity>,
    },
    Absent,
    Mismatched,
    Unknown,
}

#[cfg(windows)]
pub trait InstalledWatchdogControl {
    /// Host startup has only this read-only capability.
    fn inspect_registration_runtime(
        &mut self,
        request: &ServiceRegistrationRequest,
    ) -> InstalledWatchdogRuntimeInspection;
}

#[cfg(windows)]
impl InstalledWatchdogControl for WindowsPlatform {
    fn inspect_registration_runtime(
        &mut self,
        request: &ServiceRegistrationRequest,
    ) -> InstalledWatchdogRuntimeInspection {
        match self.inspect_service_registration_runtime(request) {
            ServiceRegistrationRuntimeInspection::Matching { observation } => {
                InstalledWatchdogRuntimeInspection::Matching {
                    state: observation.state(),
                    wait_hint_ms: observation.wait_hint_ms(),
                    process: observation.process().cloned(),
                }
            }
            ServiceRegistrationRuntimeInspection::Absent => {
                InstalledWatchdogRuntimeInspection::Absent
            }
            ServiceRegistrationRuntimeInspection::Mismatched => {
                InstalledWatchdogRuntimeInspection::Mismatched
            }
            ServiceRegistrationRuntimeInspection::Unknown { .. } => {
                InstalledWatchdogRuntimeInspection::Unknown
            }
        }
    }
}

#[cfg(windows)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "read-only Watchdog inspection remains covered by the production-bound service tests"
    )
)]
pub fn require_running_watchdog<C>(
    control: &mut C,
    registration: &ServiceRegistrationRequest,
) -> Result<(), HostError>
where
    C: InstalledWatchdogControl,
{
    match control.inspect_registration_runtime(registration) {
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Running,
            wait_hint_ms,
            process,
        } => {
            // WORK_UNIT_CASE: 979/5 — SCM Running readback observed, never readiness.
            watchdog_inspection_observe(
                &WatchdogInspectionObservation::for_registration(
                    "watchdog.inspection running observed",
                    registration,
                )
                .with_state(ServiceState::Running)
                .with_wait_hint(wait_hint_ms)
                .with_process(process.as_ref()),
            );
            Ok(())
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state,
            wait_hint_ms,
            process,
        } => {
            // WORK_UNIT_CASE: 979/5 — SCM readback is not Running, never readiness.
            watchdog_inspection_observe(
                &WatchdogInspectionObservation::for_registration(
                    "watchdog.inspection not running",
                    registration,
                )
                .with_state(state)
                .with_wait_hint(wait_hint_ms)
                .with_process(process.as_ref()),
            );
            Err(HostError::RecoveryRequired(format!(
                "canonical EliotWatchdog service is not Running (observed {state:?})"
            )))
        }
        InstalledWatchdogRuntimeInspection::Absent => {
            // WORK_UNIT_CASE: 979/5 — registration absent, never Running.
            watchdog_inspection_observe(
                &WatchdogInspectionObservation::for_registration(
                    "watchdog.inspection registration absent",
                    registration,
                )
                .with_state(ServiceState::Absent),
            );
            Err(HostError::Platform(
                "canonical EliotWatchdog service is not registered; installer/SCM must register both LocalService siblings before starting Host"
                    .to_owned(),
            ))
        }
        InstalledWatchdogRuntimeInspection::Mismatched => {
            // WORK_UNIT_CASE: 979/5 — registration mismatched, never Running.
            watchdog_inspection_observe(
                &WatchdogInspectionObservation::for_registration(
                    "watchdog.inspection registration mismatched",
                    registration,
                ),
            );
            Err(HostError::Platform(
                "canonical EliotWatchdog service registration does not match the approved configuration"
                    .to_owned(),
            ))
        }
        InstalledWatchdogRuntimeInspection::Unknown => {
            // WORK_UNIT_CASE: 979/7 — registration unknown, preserved verbatim.
            watchdog_inspection_observe(
                &WatchdogInspectionObservation::for_registration(
                    "watchdog.inspection registration unknown",
                    registration,
                )
                .with_state(ServiceState::Unknown),
            );
            Err(HostError::Platform(
                "canonical EliotWatchdog service registration is not authoritatively observable"
                    .to_owned(),
            ))
        }
    }
}

#[cfg(windows)]
/// SCM-liveness incarnation of the independently SCM-managed Watchdog
/// sibling: the approval path bound the registration to the approved
/// generation/image/bootstrap, and the readback path observed that same
/// registration `Running` with a handle-bound, image-matched process.
///
/// This is SCM liveness only. It is NOT independent-supervision evidence:
/// this layer never reads the Watchdog-owned heartbeat projection
/// (authority state, coverage flag, admitted epoch pair) and never validates
/// any admitted supervision epoch, because no Host-to-Watchdog heartbeat
/// transport exists at SCM-start time and the watchdog may not have admitted
/// any lease yet (pre-activation). Callers must never treat this value as
/// supervised coverage; supervision is proven only by the Kernel `ProbeReady`
/// watchdog-branch gate (exact admitted-epoch equality on the renewed ORS
/// head) plus the exact-lease evidence ref, with governance held degraded
/// until a proven-ready transition. No Host-side heartbeat validator exists:
/// the admitted ORS snapshot carries lease currency (epoch pair, validity
/// window) but no heartbeat recency (no authority state, coverage flag,
/// tick interval, or last-beat timestamp). Heartbeat recency arrives only
/// through the Host-to-Watchdog pipe transport: the Watchdog-owned
/// `WatchdogReadiness` projection plus the Host-recorded receive time,
/// consumed exclusively as the derived `HostObservedWatchdogHeartbeat`
/// (see `watchdog_heartbeat`), with the admission failing closed without
/// a fresh admitted beat. SCM `Running` therefore never implies a fresh
/// heartbeat. `approved_plan_generation` is the
/// approval binding only (the immutable transaction-plan generation that
/// authorized this exact registration), never a supervision epoch. `None`
/// only for bootstrap-less registrations, which the production approval path
/// never produces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWatchdogScmRunning {
    pub process: ProcessIdentity,
    pub wait_hint_ms: u32,
    pub approved_plan_generation: Option<u64>,
}

#[cfg(windows)]
/// Verifies one already-observed SCM readback as a live, approved Watchdog
/// SCM incarnation, returning the approval binding plus `Running`
/// responsiveness evidence.
///
/// Read-only: performs no SCM inspection itself and owns no start/stop,
/// registration, Job, or kill-handle capability — it only classifies the
/// approval/readback pair the caller already holds. Any unverifiable branch
/// (non-`Running` state, absent process identity, unusable PID/start handle,
/// or substituted image) fails closed with the same typed vocabulary as
/// [`require_running_watchdog`]. A successful return proves SCM liveness of
/// the approved image only; it never proves independent supervision (no
/// heartbeat is read, no admitted epoch is validated).
pub fn verify_watchdog_scm_running(
    registration: &ServiceRegistrationRequest,
    state: ServiceState,
    wait_hint_ms: u32,
    process: Option<&ProcessIdentity>,
) -> Result<VerifiedWatchdogScmRunning, HostError> {
    if state != ServiceState::Running {
        // WORK_UNIT_CASE: 979/5 — SCM readback is not Running, never liveness.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::for_registration(
                "watchdog.inspection SCM not running",
                registration,
            )
            .with_state(state)
            .with_wait_hint(wait_hint_ms)
            .with_process(process),
        );
        return Err(HostError::RecoveryRequired(format!(
            "canonical EliotWatchdog service is not Running (observed {state:?})"
        )));
    }
    let Some(observed) = process else {
        // WORK_UNIT_CASE: 979/5 — Running without process identity, never liveness.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::for_registration(
                "watchdog.inspection process identity absent",
                registration,
            )
            .with_state(state)
            .with_wait_hint(wait_hint_ms),
        );
        return Err(HostError::RecoveryRequired(
            "Watchdog reached Running without a handle-bound process identity".to_owned(),
        ));
    };
    if observed.process_id == 0
        || observed.start_time_100ns == 0
        || !windows_paths_equal(Path::new(&observed.image_path), registration.binary_path())
    {
        // WORK_UNIT_CASE: 979/4 — unusable or substituted process identity, never liveness.
        watchdog_inspection_observe(
            &WatchdogInspectionObservation::for_registration(
                "watchdog.inspection process identity rejected",
                registration,
            )
            .with_state(state)
            .with_wait_hint(wait_hint_ms)
            .with_process(Some(observed)),
        );
        return Err(HostError::RecoveryRequired(
            "Watchdog process identity is unusable or its image is not the approved image"
                .to_owned(),
        ));
    }
    let verified = VerifiedWatchdogScmRunning {
        process: observed.clone(),
        wait_hint_ms,
        approved_plan_generation: registration
            .bootstrap()
            .map(ServiceBootstrapArguments::transaction_plan_generation),
    };
    // WORK_UNIT_CASE: 979/5 — SCM liveness verified; never supervision evidence.
    // The owner's own verified record supplies the exact process PID/start pair
    // and approved plan generation instead of a static sentence; the image path
    // it also holds never crosses.
    watchdog_inspection_observe(
        &WatchdogInspectionObservation::for_registration(
            "watchdog.inspection SCM running verified",
            registration,
        )
        .with_state(state)
        .with_verified(&verified),
    );
    Ok(verified)
}
