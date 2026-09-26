use std::{path::Path, time::Duration};

use super::{
    HostError, PlatformHandle, ProcessIdentity, RequestMetadata, ServiceRegistrationRequest,
    ServiceState, WindowsPlatform, windows_paths_equal,
};

#[cfg(windows)]
#[path = "watchdog_start_timing.rs"]
mod watchdog_start_timing;

#[cfg(windows)]
use watchdog_start_timing::{SystemWatchdogStartClock, watchdog_unknown_wait};
#[cfg(windows)]
pub(super) use watchdog_start_timing::{
    WATCHDOG_START_TIMEOUT_MS, WatchdogStartClock, watchdog_start_wait,
};

#[cfg(windows)]
mod inspection;
#[cfg(windows)]
#[allow(unused_imports)]
pub(super) use inspection::{
    InstalledWatchdogControl, InstalledWatchdogRuntimeInspection, VerifiedWatchdogScmRunning,
    approved_service_registration_request, require_running_watchdog,
    select_watchdog_approval_for_inspection, verify_watchdog_scm_running,
};

// F-LOG-HOST-4 (#979) service-start observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never service
// names, digests, paths, PIDs, start-times, nonces, or arbitrary error text —
// so bounding limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision
// (SCM start failure degrades rather than fails the outer activation); these
// phase observations correlate by stage order only and never emit a terminal.
// A bare `?` on an already-observed inner boundary propagates without a
// second record. Timing observations below record the injected-clock deadline
// decisions already made by the loop; they add no clock, sleep, retry, or
// deadline.
#[cfg(windows)]
fn watchdog_start_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn watchdog_start_observe(detail: &str) {
    watchdog_start_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
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
fn bind_watchdog_process(
    registration: &ServiceRegistrationRequest,
    bound: &mut Option<ProcessIdentity>,
    observed: Option<&ProcessIdentity>,
    state: ServiceState,
) -> Result<(), HostError> {
    let Some(observed) = observed else {
        if state == ServiceState::Running {
            // WORK_UNIT_CASE: 979/5 — Running without process identity, never bound.
            watchdog_start_observe("watchdog.start process identity absent");
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
        // WORK_UNIT_CASE: 979/4 — unusable or substituted process identity, never bound.
        watchdog_start_observe("watchdog.start process identity rejected");
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
            // WORK_UNIT_CASE: 979/4 — process identity changed, never rebound.
            watchdog_start_observe("watchdog.start process identity changed");
            return Err(HostError::RecoveryRequired(
                "Watchdog process identity changed during SCM start convergence".to_owned(),
            ));
        }
    } else {
        *bound = Some(observed.clone());
    }
    // WORK_UNIT_CASE: 979/4 — exact process identity bound (pid/start/image match).
    watchdog_start_observe("watchdog.start process identity bound");
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
    // F-LOG-HOST-4 (#979): non-boundary delegation — the single call below
    // owns every start/observation/timing diagnostic; see
    // `start_installed_watchdog_with_clock`.
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
    // WORK_UNIT_CASE: 979/5 — start requested, distinct from SCM ack below.
    watchdog_start_observe("watchdog.start requested");
    let deadline = clock.now_ms().saturating_add(WATCHDOG_START_TIMEOUT_MS);
    let mut bound_process = None;
    let mut initial_wait = None;
    match control.inspect_registration_runtime(registration) {
        InstalledWatchdogRuntimeInspection::Matching {
            state,
            wait_hint_ms,
            process,
            ..
        } if state == ServiceState::Running => {
            // `?` propagates the already-observed inner bind/verify boundaries.
            bind_watchdog_process(registration, &mut bound_process, process.as_ref(), state)?;
            // I1.5 (#1750): a Running sibling proceeds only after the
            // approved-identity binding and live-process responsiveness verify.
            // SCM liveness only: this proves the approved image is Running,
            // never independent supervision (no heartbeat is read, no admitted
            // epoch is validated here; the Host-to-Watchdog heartbeat
            // transport delivers the admitted projection to the readiness
            // admission path separately. Until a fresh admitted heartbeat is
            // observed, no supervised claim may treat this gate as coverage.
            // This gate is read-only and introduces no
            // Job, kill-handle, or SCM stop capability.
            verify_watchdog_scm_running(registration, state, wait_hint_ms, process.as_ref())?;
            // WORK_UNIT_CASE: 979/5 — already Running with bound identity; SCM liveness only.
            watchdog_start_observe("watchdog.start already running observed");
            return Ok(());
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Stopped,
            ..
        } => {
            if clock.now_ms() >= deadline {
                // WORK_UNIT_CASE: 979/6 — exact deadline expired before StartService.
                watchdog_start_observe("watchdog.start deadline expired before start");
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
            // WORK_UNIT_CASE: 979/5 — SCM start issued; the ack is never
            // process/readiness evidence, only reconciliation below decides.
            watchdog_start_observe("watchdog.start SCM start issued");
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Starting,
            wait_hint_ms,
            process,
            ..
        } => {
            // `?` propagates the already-observed inner bind boundary; no second record.
            bind_watchdog_process(
                registration,
                &mut bound_process,
                process.as_ref(),
                ServiceState::Starting,
            )?;
            if clock.now_ms() >= deadline {
                // WORK_UNIT_CASE: 979/6 — exact deadline expired while Starting.
                watchdog_start_observe("watchdog.start deadline expired");
                return Err(HostError::RecoveryRequired(
                    "Watchdog SCM start did not converge before the bounded deadline".to_owned(),
                ));
            }
            // WORK_UNIT_CASE: 979/5 — SCM Starting readback observed, converging.
            watchdog_start_observe("watchdog.start starting observed");
            initial_wait = Some(watchdog_start_wait(wait_hint_ms));
        }
        InstalledWatchdogRuntimeInspection::Matching { state, .. } => {
            // WORK_UNIT_CASE: 979/5 — observed state is not startable, never Starting.
            watchdog_start_observe("watchdog.start state not startable");
            return Err(HostError::RecoveryRequired(format!(
                "canonical Watchdog service is not startable from observed state {state:?}"
            )));
        }
        InstalledWatchdogRuntimeInspection::Absent => {
            // WORK_UNIT_CASE: 979/5 — registration absent, never startable.
            watchdog_start_observe("watchdog.start registration absent");
            return Err(HostError::Platform(
                "canonical Watchdog service is not installed".to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Mismatched => {
            // WORK_UNIT_CASE: 979/5 — registration mismatched, never startable.
            watchdog_start_observe("watchdog.start registration mismatched");
            return Err(HostError::Platform(
                "canonical Watchdog service registration does not match the approved plan"
                    .to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Unknown => {
            // WORK_UNIT_CASE: 979/7 — registration unknown, preserved verbatim.
            watchdog_start_observe("watchdog.start registration unknown");
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
                        // WORK_UNIT_CASE: 979/6 — Running observed after the exact deadline.
                        watchdog_start_observe("watchdog.start running after deadline");
                        return Err(HostError::RecoveryRequired(
                            "Watchdog reached Running after the bounded SCM start deadline"
                                .to_owned(),
                        ));
                    }
                    // `?` propagates the already-observed inner bind/verify boundaries.
                    bind_watchdog_process(
                        registration,
                        &mut bound_process,
                        process.as_ref(),
                        state,
                    )?;
                    // I1.5 (#1750): converged Running proceeds only with the
                    // approval binding and live-process responsiveness verified;
                    // an unverifiable branch fails closed here. SCM liveness
                    // only, never a supervision proof. Read-only: no Job,
                    // kill-handle, or SCM stop is introduced.
                    verify_watchdog_scm_running(
                        registration,
                        state,
                        wait_hint_ms,
                        process.as_ref(),
                    )?;
                    // WORK_UNIT_CASE: 979/5 — converged Running with bound identity.
                    watchdog_start_observe("watchdog.start running observed");
                    return Ok(());
                }
                ServiceState::Starting => {
                    // `?` propagates the already-observed inner bind boundary.
                    bind_watchdog_process(
                        registration,
                        &mut bound_process,
                        process.as_ref(),
                        state,
                    )?;
                    // WORK_UNIT_CASE: 979/5 — SCM Starting readback observed, converging.
                    watchdog_start_observe("watchdog.start starting observed");
                    watchdog_start_wait(wait_hint_ms)
                }
                ServiceState::Stopped
                | ServiceState::Stopping
                | ServiceState::Absent
                | ServiceState::Failed
                | ServiceState::Unknown => {
                    // WORK_UNIT_CASE: 979/5 — converged to a terminal state, never Running.
                    watchdog_start_observe("watchdog.start converged terminal");
                    return Err(HostError::RecoveryRequired(format!(
                        "Watchdog SCM start converged to terminal state {state:?}"
                    )));
                }
            },
            // Readback uncertainty is transient only after the one permitted
            // StartService call (or when SCM was already Starting). It can never
            // authorize another start and expires at the fixed deadline above.
            InstalledWatchdogRuntimeInspection::Unknown => {
                // WORK_UNIT_CASE: 979/7 — transient readback unknown; never another start.
                watchdog_start_observe("watchdog.start readback unknown");
                watchdog_unknown_wait()
            }
            InstalledWatchdogRuntimeInspection::Absent => {
                // WORK_UNIT_CASE: 979/5 — service disappeared, never Running.
                watchdog_start_observe("watchdog.start service disappeared");
                return Err(HostError::RecoveryRequired(
                    "Watchdog service disappeared during SCM start convergence".to_owned(),
                ));
            }
            InstalledWatchdogRuntimeInspection::Mismatched => {
                // WORK_UNIT_CASE: 979/5 — registration changed, never Running.
                watchdog_start_observe("watchdog.start registration changed");
                return Err(HostError::RecoveryRequired(
                    "Watchdog service registration changed during SCM start convergence".to_owned(),
                ));
            }
        };
        let remaining_ms = deadline.saturating_sub(clock.now_ms());
        if remaining_ms == 0 {
            // WORK_UNIT_CASE: 979/6 — exact deadline expired without convergence.
            watchdog_start_observe("watchdog.start deadline expired");
            return Err(HostError::RecoveryRequired(
                "Watchdog SCM start did not converge to Running before the bounded deadline"
                    .to_owned(),
            ));
        }
        clock.sleep(wait.min(Duration::from_millis(remaining_ms)));
    }
}
