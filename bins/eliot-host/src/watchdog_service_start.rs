use std::{
    path::Path,
    time::{Duration, Instant},
};

use super::{
    ApprovedGenerationRegistry, CandidateManifest, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, HostError, InstallationProfile,
    InstallerServiceRegistrationApproval, InstallerServiceRole, PlatformHandle, ProcessIdentity,
    RequestMetadata, RuntimeLaunchDescriptor, ServiceAccount, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, ServiceState, WindowsPlatform,
    phase_b_scm_selector, windows_paths_equal,
};

#[cfg(windows)]
pub(super) fn approved_service_registration_request(
    launch: &RuntimeLaunchDescriptor,
    approval: &InstallerServiceRegistrationApproval,
    role: InstallerServiceRole,
    expected_image: &PlatformHandle,
) -> Result<ServiceRegistrationRequest, HostError> {
    if approval.role() != role || approval.generation() != &launch.generation {
        return Err(HostError::ProcessContour(
            "SCM registration approval does not match the approved runtime launch".to_owned(),
        ));
    }
    let request = approval
        .service_registration_request()
        .map_err(HostError::Installation)?;
    let expected_name = match role {
        InstallerServiceRole::Host => ELIOT_HOST_SERVICE_NAME,
        InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_NAME,
    };
    if request.service_name() != expected_name
        || request.binary_path() != Path::new(expected_image.as_str())
        || request.start_mode() != ServiceStartMode::Automatic
        || request.account() != ServiceAccount::LocalService
    {
        return Err(HostError::ProcessContour(
            "SCM registration approval reconstructed a non-canonical service request".to_owned(),
        ));
    }
    let bootstrap = request.bootstrap().ok_or_else(|| {
        HostError::ProcessContour(
            "SCM registration approval did not reconstruct a typed bootstrap".to_owned(),
        )
    })?;
    let expected_descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest)
        .map_err(HostError::Installation)?;
    if bootstrap.config_descriptor_path() != Path::new(launch.authority_descriptor_path.as_str())
        || bootstrap.config_descriptor_digest() != expected_descriptor_digest.as_str()
        || bootstrap.installation_id() != launch.installation_epoch.installation.as_str()
        || bootstrap.host_state_root()
            != Some(Path::new(
                launch.runtime_state_roots.host_state_root.as_str(),
            ))
        || bootstrap.registration_nonce().is_none()
    {
        return Err(HostError::ProcessContour(
            "SCM registration approval bootstrap is not exact".to_owned(),
        ));
    }
    // `transaction_plan_generation` is the immutable SCM selector minted in
    // Phase A. The live ORS authority generation may advance in Phase B, so
    // callers must bind that value through the Host receipt before admission.
    Ok(request)
}

#[cfg(windows)]
pub(super) fn select_watchdog_approval_for_inspection(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
) -> Result<Option<InstallerServiceRegistrationApproval>, HostError> {
    if manifest.runtime_launch.profile != InstallationProfile::SystemService {
        return Ok(None);
    }
    let approval = registry
        .service_registration_approval(
            &manifest.runtime_launch.generation,
            InstallerServiceRole::Watchdog,
        )
        .ok_or_else(|| {
            HostError::ProcessContour(
                "approved generation is missing the installer-owned Watchdog SCM approval"
                    .to_owned(),
            )
        })?;
    approved_service_registration_request(
        &manifest.runtime_launch,
        approval,
        InstallerServiceRole::Watchdog,
        &manifest.runtime_launch.watchdog_executable_path,
    )?;
    Ok(Some(approval.clone()))
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum InstalledWatchdogRuntimeInspection {
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
pub(super) trait InstalledWatchdogControl {
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
            ServiceRegistrationRuntimeInspection::Unknown => {
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
pub(super) fn require_running_watchdog<C>(
    control: &mut C,
    registration: &ServiceRegistrationRequest,
) -> Result<(), HostError>
where
    C: InstalledWatchdogControl,
{
    match control.inspect_registration_runtime(registration) {
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Running,
            ..
        } => Ok(()),
        InstalledWatchdogRuntimeInspection::Matching { state, .. } => Err(
            HostError::RecoveryRequired(format!(
                "canonical EliotWatchdog service is not Running (observed {state:?})"
            )),
        ),
        InstalledWatchdogRuntimeInspection::Absent => Err(HostError::Platform(
            "canonical EliotWatchdog service is not registered; installer/SCM must register both LocalService siblings before starting Host"
                .to_owned(),
        )),
        InstalledWatchdogRuntimeInspection::Mismatched => Err(HostError::Platform(
            "canonical EliotWatchdog service registration does not match the approved configuration"
                .to_owned(),
        )),
        InstalledWatchdogRuntimeInspection::Unknown => Err(HostError::Platform(
            "canonical EliotWatchdog service registration is not authoritatively observable"
                .to_owned(),
        )),
    }
}

#[cfg(windows)]
pub(super) trait InstalledWatchdogStartControl: InstalledWatchdogControl {
    fn start(
        &mut self,
        request: &eliot_platform::ServiceRequest,
    ) -> eliot_platform::PortOutcome<eliot_platform::ServiceObservation>;
}

#[cfg(windows)]
impl InstalledWatchdogStartControl for WindowsPlatform {
    fn start(
        &mut self,
        request: &eliot_platform::ServiceRequest,
    ) -> eliot_platform::PortOutcome<eliot_platform::ServiceObservation> {
        eliot_platform::ServicePort::execute(self, request)
    }
}

#[cfg(windows)]
pub(super) trait WatchdogStartClock {
    fn now_ms(&mut self) -> u64;

    fn sleep(&mut self, duration: Duration);
}

#[cfg(windows)]
struct SystemWatchdogStartClock {
    origin: Instant,
}

#[cfg(windows)]
impl SystemWatchdogStartClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

#[cfg(windows)]
impl WatchdogStartClock for SystemWatchdogStartClock {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(windows)]
pub(super) const WATCHDOG_START_TIMEOUT_MS: u64 = 30_000;

#[cfg(windows)]
const WATCHDOG_START_MIN_WAIT_MS: u64 = 25;

#[cfg(windows)]
const WATCHDOG_START_MAX_WAIT_MS: u64 = 250;

#[cfg(windows)]
const WATCHDOG_START_UNKNOWN_WAIT_MS: u64 = 50;

#[cfg(windows)]
pub(super) fn watchdog_start_wait(wait_hint_ms: u32) -> Duration {
    let wait_ms =
        u64::from(wait_hint_ms).clamp(WATCHDOG_START_MIN_WAIT_MS, WATCHDOG_START_MAX_WAIT_MS);
    Duration::from_millis(wait_ms)
}

#[cfg(windows)]
fn watchdog_unknown_wait() -> Duration {
    Duration::from_millis(WATCHDOG_START_UNKNOWN_WAIT_MS)
}

#[cfg(windows)]
fn bind_watchdog_process(
    registration: &ServiceRegistrationRequest,
    bound: &mut Option<ProcessIdentity>,
    observed: Option<&ProcessIdentity>,
    state: ServiceState,
) -> Result<(), HostError> {
    let Some(observed) = observed else {
        if state == ServiceState::Running {
            return Err(HostError::RecoveryRequired(
                "Watchdog reached Running without a handle-bound process identity".to_owned(),
            ));
        }
        return Ok(());
    };
    if observed.process_id == 0
        || observed.start_time_100ns == 0
        || !windows_paths_equal(Path::new(&observed.image_path), registration.binary_path())
    {
        return Err(HostError::RecoveryRequired(
            "Watchdog process identity is unusable or its image is not the approved image"
                .to_owned(),
        ));
    }
    if let Some(expected) = bound {
        if expected.process_id != observed.process_id
            || expected.start_time_100ns != observed.start_time_100ns
            || !windows_paths_equal(
                Path::new(&expected.image_path),
                Path::new(&observed.image_path),
            )
        {
            return Err(HostError::RecoveryRequired(
                "Watchdog process identity changed during SCM start convergence".to_owned(),
            ));
        }
    } else {
        *bound = Some(observed.clone());
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn start_installed_watchdog<C>(
    control: &mut C,
    registration: &ServiceRegistrationRequest,
    context: RequestMetadata,
) -> Result<(), HostError>
where
    C: InstalledWatchdogStartControl,
{
    let mut clock = SystemWatchdogStartClock::new();
    start_installed_watchdog_with_clock(control, registration, context, &mut clock)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the bounded SCM reconcile state machine keeps the one-start invariant and every terminal state in one reviewable contour"
)]
pub(super) fn start_installed_watchdog_with_clock<C, W>(
    control: &mut C,
    registration: &ServiceRegistrationRequest,
    context: RequestMetadata,
    clock: &mut W,
) -> Result<(), HostError>
where
    C: InstalledWatchdogStartControl,
    W: WatchdogStartClock,
{
    let deadline = clock.now_ms().saturating_add(WATCHDOG_START_TIMEOUT_MS);
    let mut bound_process = None;
    let mut initial_wait = None;
    match control.inspect_registration_runtime(registration) {
        InstalledWatchdogRuntimeInspection::Matching { state, process, .. }
            if state == ServiceState::Running =>
        {
            bind_watchdog_process(registration, &mut bound_process, process.as_ref(), state)?;
            return Ok(());
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Stopped,
            ..
        } => {
            if clock.now_ms() >= deadline {
                return Err(HostError::RecoveryRequired(
                    "Watchdog SCM start deadline expired before StartService could be issued"
                        .to_owned(),
                ));
            }
            let service = PlatformHandle::new(registration.service_name())
                .map_err(|error| HostError::Platform(error.to_string()))?;
            // A StartService result can be Known, Partial, Unknown, or Error
            // while the external SCM effect remains live. Reconciliation below
            // is the only authority, and this branch is the sole Start call.
            let _ = control.start(&eliot_platform::ServiceRequest {
                context,
                service,
                operation: eliot_platform::ServiceOperation::Start,
            });
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Starting,
            wait_hint_ms,
            process,
            ..
        } => {
            bind_watchdog_process(
                registration,
                &mut bound_process,
                process.as_ref(),
                ServiceState::Starting,
            )?;
            if clock.now_ms() >= deadline {
                return Err(HostError::RecoveryRequired(
                    "Watchdog SCM start did not converge before the bounded deadline".to_owned(),
                ));
            }
            initial_wait = Some(watchdog_start_wait(wait_hint_ms));
        }
        InstalledWatchdogRuntimeInspection::Matching { state, .. } => {
            return Err(HostError::RecoveryRequired(format!(
                "canonical Watchdog service is not startable from observed state {state:?}"
            )));
        }
        InstalledWatchdogRuntimeInspection::Absent => {
            return Err(HostError::Platform(
                "canonical Watchdog service is not installed".to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Mismatched => {
            return Err(HostError::Platform(
                "canonical Watchdog service registration does not match the approved plan"
                    .to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Unknown => {
            return Err(HostError::Platform(
                "canonical Watchdog service registration is not authoritatively observable"
                    .to_owned(),
            ));
        }
    }

    if let Some(wait) = initial_wait {
        let remaining_ms = deadline.saturating_sub(clock.now_ms());
        if remaining_ms > 0 {
            clock.sleep(wait.min(Duration::from_millis(remaining_ms)));
        }
    }

    loop {
        let wait = match control.inspect_registration_runtime(registration) {
            InstalledWatchdogRuntimeInspection::Matching {
                state,
                wait_hint_ms,
                process,
            } => match state {
                ServiceState::Running => {
                    if clock.now_ms() >= deadline {
                        return Err(HostError::RecoveryRequired(
                            "Watchdog reached Running after the bounded SCM start deadline"
                                .to_owned(),
                        ));
                    }
                    bind_watchdog_process(
                        registration,
                        &mut bound_process,
                        process.as_ref(),
                        state,
                    )?;
                    return Ok(());
                }
                ServiceState::Starting => {
                    bind_watchdog_process(
                        registration,
                        &mut bound_process,
                        process.as_ref(),
                        state,
                    )?;
                    watchdog_start_wait(wait_hint_ms)
                }
                ServiceState::Stopped
                | ServiceState::Stopping
                | ServiceState::Absent
                | ServiceState::Failed
                | ServiceState::Unknown => {
                    return Err(HostError::RecoveryRequired(format!(
                        "Watchdog SCM start converged to terminal state {state:?}"
                    )));
                }
            },
            // Readback uncertainty is transient only after the one permitted
            // StartService call (or when SCM was already Starting). It can never
            // authorize another start and expires at the fixed deadline above.
            InstalledWatchdogRuntimeInspection::Unknown => watchdog_unknown_wait(),
            InstalledWatchdogRuntimeInspection::Absent => {
                return Err(HostError::RecoveryRequired(
                    "Watchdog service disappeared during SCM start convergence".to_owned(),
                ));
            }
            InstalledWatchdogRuntimeInspection::Mismatched => {
                return Err(HostError::RecoveryRequired(
                    "Watchdog service registration changed during SCM start convergence".to_owned(),
                ));
            }
        };
        let remaining_ms = deadline.saturating_sub(clock.now_ms());
        if remaining_ms == 0 {
            return Err(HostError::RecoveryRequired(
                "Watchdog SCM start did not converge to Running before the bounded deadline"
                    .to_owned(),
            ));
        }
        clock.sleep(wait.min(Duration::from_millis(remaining_ms)));
    }
}
