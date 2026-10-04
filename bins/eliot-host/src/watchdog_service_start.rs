use std::{path::Path, time::Duration};

use super::{
    HostError, PlatformHandle, ProcessIdentity, RequestMetadata, ServiceRegistrationRequest,
    ServiceState, WindowsPlatform, windows_paths_equal,
};

#[cfg(windows)]
use crate::watchdog_publication::HostWatchdogObservation;

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
// Through the #889 facade only: one closed typed observation record
// (`crate::watchdog_publication::HostWatchdogObservation`, declared once in
// that module). Its single `emit` writes the one `info!` record at
// `HOST_DIAGNOSTICS_TARGET` and notes the live Event Log disposition through
// the shared bounded observer (`host_diagnostics::note_event_log_sink_status`,
// over #984's landed safe port). Every record built here is emitted exactly
// once, under its own phase token and its own slot content: no boundary emits
// the same record twice, and no complete record is built and then dropped
// without an `emit`.
//
// A record's identity is the (event, phase) pair, so each distinct boundary
// keeps its own token even where the record body would otherwise be identical
// — the first SCM Starting readback and a later convergence-loop readback are
// two boundaries, and issuance of the one StartService call is a third fact
// distinct from the disposition that call returned: `start_attempt` rides only
// on the `attempt_*` records, never on `scm_start_issued`.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Only the short static `phase` token is a literal; every
// identity travels in its own bounded slot — the canonical SCM service name,
// the bootstrap installation id and transaction-plan generation, the observed
// PID/start-time pair, the observed SCM state, the injected-clock deadline and
// the typed StartService disposition — so bounding limits size, not
// sensitivity: `host_diagnostics::bound_field` bounds bytes only, so this
// caller must pass nonsecret material. `deadline_basis` means one thing here:
// the absolute injected-clock deadline every timing decision is judged against.
// The relative SCM wait hint this contour also holds is never projected into
// it; a relative duration belongs in the sibling inspect/verify contour's own
// slot, so one operation never emits two incomparable values under this one
// identity. An identity this boundary does not hold stays an explicit missing
// slot: never prose, never a default, never
// the order in which records were emitted. The image path, the
// config-descriptor path/digest, the
// registration nonce and provider error text are never projected, and no slot is
// filled by re-reading, re-hashing or re-probing anything — this contour holds
// no owner-issued image digest, and hashing the approved image path here would
// mint a digest scheme this boundary does not own. Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision
// (SCM start failure degrades rather than fails the outer activation); these
// phase records correlate by the identities they carry, not by stage order
// alone, and they never emit a terminal. A bare `?` on an already-observed
// inner boundary propagates without a second record. Timing observations below
// record the injected-clock deadline decisions already made by the loop; they
// add no clock, sleep, retry, or deadline.
//
// One local emission seam keeps all twenty-six boundaries uniform. The record's
// slot setters take the plain nonsecret text and apply the shared bound
// themselves, so no caller in this file constructs a bounded field directly.
#[cfg(windows)]
fn watchdog_start_observe(observation: &HostWatchdogObservation, phase: &'static str) {
    observation.emit(phase);
}

// Projects the registration identities this boundary already holds.
//
// `service_identity` is the canonical SCM service name of the approved
// registration. `installation` and `approved_generation` come from the
// immutable bootstrap authority bound to that same registration: the
// installation id the approved launch was minted for, and the transaction-plan
// generation that authorized this exact registration (the approval binding
// only, never a supervision epoch). Both stay explicitly missing for a
// bootstrap-less registration, which the production approval path never
// produces.
#[cfg(windows)]
fn watchdog_start_observation(
    registration: &ServiceRegistrationRequest,
) -> HostWatchdogObservation {
    let mut observation = HostWatchdogObservation::default();
    observation.set_service_identity(registration.service_name());
    if let Some(bootstrap) = registration.bootstrap() {
        observation.set_installation(bootstrap.installation_id());
        observation.set_approved_generation(&bootstrap.transaction_plan_generation().to_string());
    }
    observation
}

// Stable diagnostic token of the owner's own SCM state value. This renames a
// `ServiceState` the caller already matched on; it is not a
// `ServiceProcessState` lifecycle and adds no state machine (I14.20, I1.10).
#[cfg(windows)]
const fn watchdog_start_scm_state_token(state: ServiceState) -> &'static str {
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

#[cfg(windows)]
fn watchdog_start_bind_scm_state(observation: &mut HostWatchdogObservation, state: ServiceState) {
    observation.set_scm_state(watchdog_start_scm_state_token(state));
}

// Projects the PID/start-time pair the caller already holds, so two
// incarnations of one PID stay distinguishable records.
//
// The image path is deliberately excluded: `ProcessIdentity::stable_key()` is a
// raw string that embeds it, and a path is not an approved-image identity. The
// pair is rendered exactly as held and is not hashed here; an absent identity
// stays an explicit missing slot.
#[cfg(windows)]
fn watchdog_start_bind_process(
    observation: &mut HostWatchdogObservation,
    process: Option<&ProcessIdentity>,
) {
    let Some(process) = process else {
        return;
    };
    let process_id = process.process_id;
    let start_time_100ns = process.start_time_100ns;
    observation.set_process_start(&format!(
        "windows-pid:{process_id}:start:{start_time_100ns}"
    ));
}

// Projects the injected-clock deadline every timing decision below is judged
// against. The decision itself is the phase token; this slot is only its basis,
// and it adds no clock, sleep, retry or deadline. The value is always the
// absolute deadline computed once at the top of the start path — never a
// relative duration, a remaining-milliseconds figure or an SCM wait hint, so
// this slot keeps one meaning for every boundary that fills it.
#[cfg(windows)]
fn watchdog_start_bind_deadline(observation: &mut HostWatchdogObservation, deadline_ms: u64) {
    observation.set_deadline_basis(&deadline_ms.to_string());
}

// Projects the typed StartService provider outcome as attempt evidence.
//
// It is attempt evidence only: never process evidence, never readiness
// evidence. The read-only reconciliation below remains the sole Running
// authority, and this branch remains the single Start call. The provider's own
// reason text is not projected; only the closed disposition it returned is.
#[cfg(windows)]
fn watchdog_start_attempt_disposition(
    attempt: &eliot_platform::PortOutcome<eliot_platform::ServiceObservation>,
) -> &'static str {
    match attempt {
        eliot_platform::PortOutcome::Known(_) => "acknowledged",
        eliot_platform::PortOutcome::Partial { .. } => "partially_observed",
        eliot_platform::PortOutcome::Unknown(_) => "unknown_effect",
        eliot_platform::PortOutcome::Error(_) => "failed",
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
fn bind_watchdog_process(
    registration: &ServiceRegistrationRequest,
    bound: &mut Option<ProcessIdentity>,
    observed: Option<&ProcessIdentity>,
    state: ServiceState,
) -> Result<(), HostError> {
    let Some(observed) = observed else {
        if state == ServiceState::Running {
            // Built here because this is the only branch that observes; the
            // sibling `Ok(())` path below observes nothing, so no complete
            // record is constructed and then dropped without an `emit`.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_scm_state(&mut observation, state);
            // WORK_UNIT_CASE: 979/5 — Running without process identity, never bound.
            watchdog_start_observe(&observation, "process_identity_absent");
            return Err(HostError::RecoveryRequired(
                "Watchdog reached Running without a handle-bound process identity".to_owned(),
            ));
        }
        return Ok(());
    };
    let mut observation = watchdog_start_observation(registration);
    watchdog_start_bind_scm_state(&mut observation, state);
    watchdog_start_bind_process(&mut observation, Some(observed));
    if observed.process_id == 0
        || observed.start_time_100ns == 0
        || !windows_paths_equal(Path::new(&observed.image_path), registration.binary_path())
    {
        // WORK_UNIT_CASE: 979/4 — unusable or substituted process identity, never bound.
        watchdog_start_observe(&observation, "process_identity_rejected");
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
            watchdog_start_observe(&observation, "process_identity_changed");
            return Err(HostError::RecoveryRequired(
                "Watchdog process identity changed during SCM start convergence".to_owned(),
            ));
        }
    } else {
        *bound = Some(observed.clone());
    }
    // WORK_UNIT_CASE: 979/4 — exact process identity bound (pid/start/image match).
    watchdog_start_observe(&observation, "process_identity_bound");
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
    // The deadline is computed immediately below, so this first boundary holds
    // no deadline basis, no observed SCM state and no process identity yet: all
    // three stay explicitly missing rather than being guessed here.
    // WORK_UNIT_CASE: 979/5 — start requested, distinct from SCM ack below.
    let observation = watchdog_start_observation(registration);
    watchdog_start_observe(&observation, "start_requested");
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
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_scm_state(&mut observation, state);
            watchdog_start_bind_process(&mut observation, process.as_ref());
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "already_running_observed");
            return Ok(());
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Stopped,
            ..
        } => {
            if clock.now_ms() >= deadline {
                // WORK_UNIT_CASE: 979/6 — exact deadline expired before StartService.
                let mut observation = watchdog_start_observation(registration);
                watchdog_start_bind_scm_state(&mut observation, ServiceState::Stopped);
                watchdog_start_bind_deadline(&mut observation, deadline);
                watchdog_start_observe(&observation, "deadline_expired_before_start");
                return Err(HostError::RecoveryRequired(
                    "Watchdog SCM start deadline expired before StartService could be issued"
                        .to_owned(),
                ));
            }
            let service = PlatformHandle::new(registration.service_name())
                .map_err(|error| HostError::Platform(error.to_string()))?;
            // Audit 5909923856 defect 4: the typed owner outcome is attempt
            // evidence only. Read-only reconciliation below stays the sole
            // authority for Running/readiness, and this branch remains the
            // single Start call.
            let start_attempt = control.start(&eliot_platform::ServiceRequest {
                context,
                service,
                operation: eliot_platform::ServiceOperation::Start,
            });
            let attempt_disposition = watchdog_start_attempt_disposition(&start_attempt);
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_scm_state(&mut observation, ServiceState::Stopped);
            watchdog_start_bind_deadline(&mut observation, deadline);
            // `start_attempt` is attached only AFTER the issuance record below,
            // never on it: issuance and the disposition the provider returned
            // are two different facts, so the four `attempt_*` records keep the
            // typed outcome as attempt evidence while this one stays the record
            // of the issuance. The two are therefore never slot-identical for
            // one attempt.
            // WORK_UNIT_CASE: 979/5 — SCM start issued; the ack is never
            // process/readiness evidence, only reconciliation below decides.
            watchdog_start_observe(&observation, "scm_start_issued");
            observation.set_start_attempt(attempt_disposition);
            match start_attempt {
                eliot_platform::PortOutcome::Known(_) => {
                    // WORK_UNIT_CASE: 979/5 — provider acknowledged the start attempt.
                    watchdog_start_observe(&observation, "attempt_acknowledged");
                }
                eliot_platform::PortOutcome::Partial { .. } => {
                    // WORK_UNIT_CASE: 979/5 — provider partially observed the start attempt.
                    watchdog_start_observe(&observation, "attempt_partially_observed");
                }
                eliot_platform::PortOutcome::Unknown(_) => {
                    // WORK_UNIT_CASE: 979/5 — start attempt of unknown possible effect.
                    watchdog_start_observe(&observation, "attempt_unknown_effect");
                }
                eliot_platform::PortOutcome::Error(_) => {
                    // WORK_UNIT_CASE: 979/5 — provider failed the start attempt.
                    watchdog_start_observe(&observation, "attempt_failed");
                }
            }
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
                let mut observation = watchdog_start_observation(registration);
                watchdog_start_bind_scm_state(&mut observation, ServiceState::Starting);
                watchdog_start_bind_process(&mut observation, process.as_ref());
                watchdog_start_bind_deadline(&mut observation, deadline);
                watchdog_start_observe(&observation, "deadline_expired_starting");
                return Err(HostError::RecoveryRequired(
                    "Watchdog SCM start did not converge before the bounded deadline".to_owned(),
                ));
            }
            // The first SCM Starting readback of this operation. Its phase
            // token is distinct from the convergence-loop readback below:
            // the record's identity is the (event, phase) pair, so one reused
            // token would make the first observation indistinguishable from
            // any later iteration of the loop.
            // WORK_UNIT_CASE: 979/5 — SCM Starting readback observed, converging.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_scm_state(&mut observation, ServiceState::Starting);
            watchdog_start_bind_process(&mut observation, process.as_ref());
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "starting_observed_initial_inspection");
            initial_wait = Some(watchdog_start_wait(wait_hint_ms));
        }
        InstalledWatchdogRuntimeInspection::Matching { state, .. } => {
            // WORK_UNIT_CASE: 979/5 — observed state is not startable, never Starting.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_scm_state(&mut observation, state);
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "state_not_startable");
            return Err(HostError::RecoveryRequired(format!(
                "canonical Watchdog service is not startable from observed state {state:?}"
            )));
        }
        InstalledWatchdogRuntimeInspection::Absent => {
            // WORK_UNIT_CASE: 979/5 — registration absent, never startable.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "registration_absent");
            return Err(HostError::Platform(
                "canonical Watchdog service is not installed".to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Mismatched => {
            // WORK_UNIT_CASE: 979/5 — registration mismatched, never startable.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "registration_mismatched");
            return Err(HostError::Platform(
                "canonical Watchdog service registration does not match the approved plan"
                    .to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Unknown => {
            // WORK_UNIT_CASE: 979/7 — registration unknown, preserved verbatim.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "registration_unknown");
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
                        let mut observation = watchdog_start_observation(registration);
                        watchdog_start_bind_scm_state(&mut observation, state);
                        watchdog_start_bind_process(&mut observation, process.as_ref());
                        watchdog_start_bind_deadline(&mut observation, deadline);
                        watchdog_start_observe(&observation, "running_after_deadline");
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
                    let mut observation = watchdog_start_observation(registration);
                    watchdog_start_bind_scm_state(&mut observation, state);
                    watchdog_start_bind_process(&mut observation, process.as_ref());
                    watchdog_start_bind_deadline(&mut observation, deadline);
                    watchdog_start_observe(&observation, "running_observed");
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
                    // A convergence-loop Starting readback, distinct from the
                    // first readback above: the loop may repeat this boundary
                    // many times per attempt, so it has its own phase token.
                    // WORK_UNIT_CASE: 979/5 — SCM Starting readback observed, converging.
                    let mut observation = watchdog_start_observation(registration);
                    watchdog_start_bind_scm_state(&mut observation, state);
                    watchdog_start_bind_process(&mut observation, process.as_ref());
                    watchdog_start_bind_deadline(&mut observation, deadline);
                    watchdog_start_observe(&observation, "starting_observed_convergence_readback");
                    watchdog_start_wait(wait_hint_ms)
                }
                ServiceState::Stopped
                | ServiceState::Stopping
                | ServiceState::Absent
                | ServiceState::Failed
                | ServiceState::Unknown => {
                    // WORK_UNIT_CASE: 979/5 — converged to a terminal state, never Running.
                    let mut observation = watchdog_start_observation(registration);
                    watchdog_start_bind_scm_state(&mut observation, state);
                    watchdog_start_bind_process(&mut observation, process.as_ref());
                    watchdog_start_bind_deadline(&mut observation, deadline);
                    watchdog_start_observe(&observation, "converged_terminal");
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
                let mut observation = watchdog_start_observation(registration);
                watchdog_start_bind_deadline(&mut observation, deadline);
                watchdog_start_observe(&observation, "readback_unknown");
                watchdog_unknown_wait()
            }
            InstalledWatchdogRuntimeInspection::Absent => {
                // WORK_UNIT_CASE: 979/5 — service disappeared, never Running.
                let mut observation = watchdog_start_observation(registration);
                watchdog_start_bind_deadline(&mut observation, deadline);
                watchdog_start_observe(&observation, "service_disappeared");
                return Err(HostError::RecoveryRequired(
                    "Watchdog service disappeared during SCM start convergence".to_owned(),
                ));
            }
            InstalledWatchdogRuntimeInspection::Mismatched => {
                // WORK_UNIT_CASE: 979/5 — registration changed, never Running.
                let mut observation = watchdog_start_observation(registration);
                watchdog_start_bind_deadline(&mut observation, deadline);
                watchdog_start_observe(&observation, "registration_changed");
                return Err(HostError::RecoveryRequired(
                    "Watchdog service registration changed during SCM start convergence".to_owned(),
                ));
            }
        };
        let remaining_ms = deadline.saturating_sub(clock.now_ms());
        if remaining_ms == 0 {
            // WORK_UNIT_CASE: 979/6 — exact deadline expired without convergence.
            let mut observation = watchdog_start_observation(registration);
            watchdog_start_bind_deadline(&mut observation, deadline);
            watchdog_start_observe(&observation, "deadline_expired_unconverged");
            return Err(HostError::RecoveryRequired(
                "Watchdog SCM start did not converge to Running before the bounded deadline"
                    .to_owned(),
            ));
        }
        clock.sleep(wait.min(Duration::from_millis(remaining_ms)));
    }
}
