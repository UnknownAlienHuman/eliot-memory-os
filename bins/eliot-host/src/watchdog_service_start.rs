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
// the semantic owner through ONE closed typed observation
// (`WatchdogStartObservation` + `watchdog_start_observe`; the read-only
// inspection child uses its own `WatchdogInspectionObservation` over the same
// facade, so neither introduces a second emitter, sink, or bounding scheme).
// Each record carries the canonical service registration identity, the
// approved bootstrap installation and transaction-plan generation, the
// approved config descriptor digest, the request identity and State Fence the
// caller's metadata already holds, the injected-clock deadline, the observed
// SCM state, the process PID/start pair, and the returned StartService
// `PortOutcome` disposition, so two SCM start attempts and a stale observation
// from a current one can never share one record (I7.20). An identity this owner
// does not hold stays an explicit unavailable field rather than a static
// sentence pretending to be an identity. Never a raw image path, argv,
// environment value, bootstrap nonce, credential or key material, or arbitrary
// `Debug`/serde error text, so bounding limits size, not sensitivity (I15.4).
// The returned StartService disposition is attempt evidence only and is never
// promoted to process or readiness evidence: readback stays the sole Running
// authority, and SCM `Running` here is liveness only, never heartbeat or
// independent supervision. Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision
// (SCM start failure degrades rather than fails the outer activation); these
// phase observations never emit a terminal. A bare `?` on an already-observed
// inner boundary propagates without a second record. Timing observations
// record the injected-clock deadline decisions already made by the loop; they
// add no clock, sleep, retry, or deadline.
#[cfg(windows)]
fn watchdog_start_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn watchdog_start_observe(observation: &WatchdogStartObservation<'_>) {
    watchdog_start_note_event_log_unavailable();
    let mut detail = String::from(observation.label);
    for (key, value) in [
        ("service", observation.service),
        ("install", observation.installation),
        ("plan", observation.approved_plan_generation),
        ("config", observation.config_descriptor_digest),
        ("request", observation.request),
        ("fence", observation.state_fence),
        ("generation", observation.resource_generation),
        ("deadline", observation.deadline_ms),
        ("state", observation.state),
        ("pid", observation.process_id),
        ("start", observation.process_start),
        ("port", observation.port_outcome),
    ] {
        detail.push(' ');
        detail.push_str(key);
        detail.push('=');
        detail.push_str(value.unwrap_or(WATCHDOG_START_IDENTITY_UNAVAILABLE));
    }
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::ScmDispatch,
        &detail,
    );
}

/// The explicit disposition of one Watchdog start identity this boundary does
/// not hold (F-LOG-HOST-4, #979). It stays a real slot value: never a
/// fabricated, defaulted, recomputed, or statically-worded stand-in for an
/// identity this owner never produced.
#[cfg(windows)]
const WATCHDOG_START_IDENTITY_UNAVAILABLE: &str = "unavailable";

/// The request identity and State Fence this contour binds to its records,
/// snapshotted once from the caller's `RequestMetadata` (F-LOG-HOST-4, #979).
///
/// Taken before the single StartService call consumes the metadata, so the
/// request identity of a start attempt survives into the later convergence
/// records. Pure string formatting over already-validated owner values: no
/// reread, no revalidation, no mutation, and no session, task, product, source,
/// clock or payload value crosses.
#[cfg(windows)]
struct WatchdogStartRequest {
    request_id: String,
    state_fence: String,
    resource_generation: String,
}

#[cfg(windows)]
impl WatchdogStartRequest {
    fn of(context: &RequestMetadata) -> Self {
        Self {
            request_id: context.request_id.as_str().to_owned(),
            state_fence: format!(
                "{}:{}",
                context.state_fence.authority_epoch.lineage_id.as_str(),
                context.state_fence.authority_epoch.sequence.get(),
            ),
            resource_generation: context.state_fence.resource_generation.value().to_string(),
        }
    }
}

/// The closed set of nonsecret Watchdog start identities this owner may bind
/// to one SCM start observation (F-LOG-HOST-4, #979).
///
/// Every slot is either the exact value the owner already holds — the
/// canonical service registration name and its approved bootstrap binding, the
/// snapshotted request identity and State Fence, the injected-clock deadline,
/// the observed SCM state, the process PID/start pair, or the returned
/// `PortOutcome` disposition — or the explicit
/// [`WATCHDOG_START_IDENTITY_UNAVAILABLE`] disposition. Each numeric slot is
/// rendered from an owner-issued number in plain decimal form; no slot ever
/// carries the image path, argv, environment, nonce, credential, or arbitrary
/// `Debug`/error text. SCM `Running` here is liveness only and no record may
/// imply heartbeat or independent supervision.
#[cfg(windows)]
struct WatchdogStartObservation<'a> {
    label: &'static str,
    service: Option<&'a str>,
    installation: Option<&'a str>,
    approved_plan_generation: Option<String>,
    config_descriptor_digest: Option<&'a str>,
    request: Option<&'a str>,
    state_fence: Option<String>,
    resource_generation: Option<String>,
    deadline_ms: Option<String>,
    state: Option<&'static str>,
    process_id: Option<String>,
    process_start: Option<String>,
    port_outcome: Option<&'static str>,
}

#[cfg(windows)]
impl<'a> WatchdogStartObservation<'a> {
    /// The observation of a boundary reached before this owner holds any start
    /// identity.
    fn unavailable(label: &'static str) -> Self {
        Self {
            label,
            service: None,
            installation: None,
            approved_plan_generation: None,
            config_descriptor_digest: None,
            request: None,
            state_fence: None,
            resource_generation: None,
            deadline_ms: None,
            state: None,
            process_id: None,
            process_start: None,
            port_outcome: None,
        }
    }

    /// Binds the approved registration identities of the one canonical
    /// Watchdog service this contour starts: its name, the bootstrap
    /// installation, immutable transaction-plan generation, and approved config
    /// descriptor digest. All are copied from the owner-validated request; none
    /// is re-derived.
    fn for_registration(
        label: &'static str,
        registration: &'a ServiceRegistrationRequest,
    ) -> Self {
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

    /// Binds the request identity and State Fence this contour snapshotted
    /// from the caller's request metadata. No session, task, product, source,
    /// clock or payload value crosses.
    fn with_request(mut self, request: &WatchdogStartRequest) -> Self {
        self.request = Some(request.request_id.as_str());
        self.state_fence = Some(request.state_fence.as_str());
        self.resource_generation = Some(request.resource_generation.as_str());
        self
    }

    /// Binds the injected-clock deadline this contour already decided.
    fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms.to_string());
        self
    }

    /// Binds the observed SCM state through its frozen 1:1 label, never its
    /// `Debug` text.
    fn with_state(mut self, state: ServiceState) -> Self {
        self.state = Some(watchdog_service_state_label(state));
        self
    }

    /// Binds the observed process PID/start pair. The image path this owner
    /// validated never crosses: only the two owner-issued numbers the issue
    /// permits do. The same slot set serves a fresh readback and the pair this
    /// contour has already bound, so a reader compares the two records.
    fn with_process(mut self, process: Option<&'a ProcessIdentity>) -> Self {
        if let Some(process) = process {
            self.process_id = Some(process.process_id.to_string());
            self.process_start = Some(process.start_time_100ns.to_string());
        }
        self
    }

    /// Binds the returned StartService attempt disposition as attempt evidence
    /// only. It is never process or readiness evidence: the readback below
    /// remains the sole Running authority.
    fn with_port_outcome(
        mut self,
        outcome: &'a eliot_platform::PortOutcome<eliot_platform::ServiceObservation>,
    ) -> Self {
        self.port_outcome = Some(watchdog_port_outcome_label(outcome));
        self
    }
}

/// Stable diagnostic label for one observed SCM state (F-LOG-HOST-4, #979).
/// A 1:1 map, never `Debug`.
#[cfg(windows)]
fn watchdog_service_state_label(state: ServiceState) -> &'static str {
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

/// Stable diagnostic label for one returned StartService attempt disposition
/// (F-LOG-HOST-4, #979). A 1:1 map over the platform owner's own typed
/// `PortOutcome`, so acknowledgement, partial observation, unestablished
/// effect and a typed request failure stay distinct without carrying any
/// payload, reason text or `Debug`.
#[cfg(windows)]
fn watchdog_port_outcome_label(
    outcome: &eliot_platform::PortOutcome<eliot_platform::ServiceObservation>,
) -> &'static str {
    match outcome {
        eliot_platform::PortOutcome::Known(_) => "known",
        eliot_platform::PortOutcome::Partial { .. } => "partial",
        eliot_platform::PortOutcome::Unknown(_) => "unknown",
        eliot_platform::PortOutcome::Error(_) => "error",
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
            // WORK_UNIT_CASE: 979/5 — Running without process identity, never bound.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start process identity absent",
                    registration,
                )
                .with_state(state)
                .with_process(bound.as_ref()),
            );
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
        watchdog_start_observe(
            &WatchdogStartObservation::for_registration(
                "watchdog.start process identity rejected",
                registration,
            )
            .with_state(state)
            .with_process(Some(observed))
            .with_process(bound.as_ref()),
        );
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
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start process identity changed",
                    registration,
                )
                .with_state(state)
                .with_process(Some(observed))
                .with_process(bound.as_ref()),
            );
            return Err(HostError::RecoveryRequired(
                "Watchdog process identity changed during SCM start convergence".to_owned(),
            ));
        }
    } else {
        *bound = Some(observed.clone());
    }
    // WORK_UNIT_CASE: 979/4 — exact process identity bound (pid/start/image match).
    watchdog_start_observe(
        &WatchdogStartObservation::for_registration(
            "watchdog.start process identity bound",
            registration,
        )
        .with_state(state)
        .with_process(Some(observed)),
    );
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
    // The request identity is snapshotted here, before the single StartService
    // call below consumes the caller's metadata, so every later boundary of
    // this contour can still name the exact request it belongs to.
    let request = WatchdogStartRequest::of(&context);
    watchdog_start_observe(
        &WatchdogStartObservation::for_registration("watchdog.start requested", registration)
            .with_request(&request),
    );
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
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start already running observed",
                    registration,
                )
                .with_request(&request)
                .with_deadline(deadline)
                .with_state(state)
                .with_process(process.as_ref()),
            );
            return Ok(());
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Stopped,
            ..
        } => {
            if clock.now_ms() >= deadline {
                // WORK_UNIT_CASE: 979/6 — exact deadline expired before StartService.
                watchdog_start_observe(
                    &WatchdogStartObservation::for_registration(
                        "watchdog.start deadline expired before start",
                        registration,
                    )
                    .with_request(&request)
                    .with_deadline(deadline)
                    .with_state(ServiceState::Stopped),
                );
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
            let start_outcome = control.start(&eliot_platform::ServiceRequest {
                context,
                service,
                operation: eliot_platform::ServiceOperation::Start,
            });
            // WORK_UNIT_CASE: 979/5 — SCM start issued; the returned typed
            // disposition is attempt evidence only and is never process or
            // readiness evidence, only reconciliation below decides.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start SCM start issued",
                    registration,
                )
                .with_deadline(deadline)
                .with_state(ServiceState::Stopped)
                .with_port_outcome(&start_outcome),
            );
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
                watchdog_start_observe(
                    &WatchdogStartObservation::for_registration(
                        "watchdog.start deadline expired",
                        registration,
                    )
                    .with_deadline(deadline)
                    .with_state(ServiceState::Starting)
                    .with_process(process.as_ref()),
                );
                return Err(HostError::RecoveryRequired(
                    "Watchdog SCM start did not converge before the bounded deadline".to_owned(),
                ));
            }
            // WORK_UNIT_CASE: 979/5 — SCM Starting readback observed, converging.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start starting observed",
                    registration,
                )
                .with_deadline(deadline)
                .with_state(ServiceState::Starting)
                .with_process(process.as_ref()),
            );
            initial_wait = Some(watchdog_start_wait(wait_hint_ms));
        }
        InstalledWatchdogRuntimeInspection::Matching { state, .. } => {
            // WORK_UNIT_CASE: 979/5 — observed state is not startable, never Starting.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start state not startable",
                    registration,
                )
                .with_deadline(deadline)
                .with_state(state),
            );
            return Err(HostError::RecoveryRequired(format!(
                "canonical Watchdog service is not startable from observed state {state:?}"
            )));
        }
        InstalledWatchdogRuntimeInspection::Absent => {
            // WORK_UNIT_CASE: 979/5 — registration absent, never startable.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start registration absent",
                    registration,
                )
                .with_request(&request)
                .with_deadline(deadline)
                .with_state(ServiceState::Absent),
            );
            return Err(HostError::Platform(
                "canonical Watchdog service is not installed".to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Mismatched => {
            // WORK_UNIT_CASE: 979/5 — registration mismatched, never startable.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start registration mismatched",
                    registration,
                )
                .with_request(&request)
                .with_deadline(deadline),
            );
            return Err(HostError::Platform(
                "canonical Watchdog service registration does not match the approved plan"
                    .to_owned(),
            ));
        }
        InstalledWatchdogRuntimeInspection::Unknown => {
            // WORK_UNIT_CASE: 979/7 — registration unknown, preserved verbatim.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start registration unknown",
                    registration,
                )
                .with_request(&request)
                .with_deadline(deadline)
                .with_state(ServiceState::Unknown),
            );
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
                        watchdog_start_observe(
                            &WatchdogStartObservation::for_registration(
                                "watchdog.start running after deadline",
                                registration,
                            )
                            .with_deadline(deadline)
                            .with_state(state)
                            .with_process(process.as_ref()),
                        );
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
                    watchdog_start_observe(
                        &WatchdogStartObservation::for_registration(
                            "watchdog.start running observed",
                            registration,
                        )
                        .with_deadline(deadline)
                        .with_state(state)
                        .with_process(process.as_ref())
                        .with_process(bound_process.as_ref()),
                    );
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
                    watchdog_start_observe(
                        &WatchdogStartObservation::for_registration(
                            "watchdog.start starting observed",
                            registration,
                        )
                        .with_deadline(deadline)
                        .with_state(state)
                        .with_process(process.as_ref())
                        .with_process(bound_process.as_ref()),
                    );
                    watchdog_start_wait(wait_hint_ms)
                }
                ServiceState::Stopped
                | ServiceState::Stopping
                | ServiceState::Absent
                | ServiceState::Failed
                | ServiceState::Unknown => {
                    // WORK_UNIT_CASE: 979/5 — converged to a terminal state, never Running.
                    watchdog_start_observe(
                        &WatchdogStartObservation::for_registration(
                            "watchdog.start converged terminal",
                            registration,
                        )
                        .with_deadline(deadline)
                        .with_state(state)
                        .with_process(process.as_ref())
                        .with_process(bound_process.as_ref()),
                    );
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
                watchdog_start_observe(
                    &WatchdogStartObservation::for_registration(
                        "watchdog.start readback unknown",
                        registration,
                    )
                    .with_deadline(deadline)
                    .with_state(ServiceState::Unknown)
                    .with_process(bound_process.as_ref()),
                );
                watchdog_unknown_wait()
            }
            InstalledWatchdogRuntimeInspection::Absent => {
                // WORK_UNIT_CASE: 979/5 — service disappeared, never Running.
                watchdog_start_observe(
                    &WatchdogStartObservation::for_registration(
                        "watchdog.start service disappeared",
                        registration,
                    )
                    .with_deadline(deadline)
                    .with_state(ServiceState::Absent)
                    .with_process(bound_process.as_ref()),
                );
                return Err(HostError::RecoveryRequired(
                    "Watchdog service disappeared during SCM start convergence".to_owned(),
                ));
            }
            InstalledWatchdogRuntimeInspection::Mismatched => {
                // WORK_UNIT_CASE: 979/5 — registration changed, never Running.
                watchdog_start_observe(
                    &WatchdogStartObservation::for_registration(
                        "watchdog.start registration changed",
                        registration,
                    )
                    .with_deadline(deadline)
                    .with_process(bound_process.as_ref()),
                );
                return Err(HostError::RecoveryRequired(
                    "Watchdog service registration changed during SCM start convergence".to_owned(),
                ));
            }
        };
        let remaining_ms = deadline.saturating_sub(clock.now_ms());
        if remaining_ms == 0 {
            // WORK_UNIT_CASE: 979/6 — exact deadline expired without convergence.
            watchdog_start_observe(
                &WatchdogStartObservation::for_registration(
                    "watchdog.start deadline expired",
                    registration,
                )
                .with_deadline(deadline)
                .with_process(bound_process.as_ref()),
            );
            return Err(HostError::RecoveryRequired(
                "Watchdog SCM start did not converge to Running before the bounded deadline"
                    .to_owned(),
            ));
        }
        clock.sleep(wait.min(Duration::from_millis(remaining_ms)));
    }
}
