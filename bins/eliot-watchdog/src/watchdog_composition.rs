//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04.
//! Implementation: I2.23, I8.1, I8.3, I8.4, I14.10, I14.15.
//! Responsibility/Forbidden ownership: bounded Watchdog runtime composition and admitted heartbeat only; no Kernel effect, Host identity, Store canonical state, unbounded restart, default, retry, or mint authority.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use eliot_runtime::{ChildClass, Runtime, ShutdownOutcome, SupervisionStrategy, TaskFailure};

use crate::CompositionError;
use crate::HostObservationSource;
use crate::HostObservationState;
use crate::KernelWatchdogPort;
use crate::LiveHostObservationSource;
use crate::PROTOCOL_VERSION;
use crate::SERVICE_NAME;
use crate::SpoolError;
use crate::WatchdogAdmissionSource;
use crate::WatchdogConfig;
use crate::admission_gap_reason;
use crate::heartbeat_transport::HeartbeatTransport;
use crate::kernel_gap_reason;
use crate::report_gap_nonfatal;
use crate::watchdog_spool::WatchdogSpool;
use crate::watchdog_spool::backup::{
    CaptureFenceParams, SpoolRestoreDisposition, SpoolRestoreStep, WatchdogSpoolBackupLimits,
    WatchdogSpoolFence, WatchdogSpoolSnapshotPage,
};

mod authority_state;

use authority_state::WatchdogAuthorityStateCell;
pub use authority_state::{WatchdogAuthorityState, WatchdogReadiness};

/// Runtime-owned watchdog composition.
pub struct WatchdogComposition {
    runtime: Runtime,
    admission: Arc<dyn WatchdogAdmissionSource>,
    authority_state: WatchdogAuthorityStateCell,
    config: WatchdogConfig,
    task: eliot_runtime::SupervisedHandle,
    shutdown_requested: Arc<AtomicBool>,
    heartbeat: Option<Arc<HeartbeatTransport>>,
}

impl WatchdogComposition {
    /// Builds and admits the watchdog loop against an injected kernel port.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration or initial supervision
    /// authority is invalid, or if the runtime is already shutting down.
    pub fn start(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown(config, admission, kernel, Arc::new(AtomicBool::new(false)))
    }

    /// Starts the composition with a caller-owned stop flag.  SCM control
    /// handlers use this flag because they execute outside the Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration is invalid or if the runtime
    /// denies task admission. An unavailable initial lease remains a nonfatal
    /// observation gap and publishes no current coverage epochs.
    pub fn start_with_shutdown(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        let expected_host_image = admission.approved_host_image().ok_or_else(|| {
            CompositionError::InvalidConfiguration(
                "approved Host image is required for the production observer".to_owned(),
            )
        })?;
        let expected_host_registration =
            admission.approved_host_registration().ok_or_else(|| {
                CompositionError::InvalidConfiguration(
                    "installer-approved Host registration is required for the production observer"
                        .to_owned(),
                )
            })?;
        let host = Arc::new(LiveHostObservationSource::try_new(
            expected_host_image,
            expected_host_registration,
        ));
        Self::start_with_shutdown_and_host(config, admission, kernel, host, shutdown_requested)
    }

    /// Starts the composition with an injected read-only Host observation
    /// source. The source can classify Host loss but cannot perform lifecycle
    /// effects or supply supervision authority.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration is invalid or if the runtime
    /// denies task admission. An unavailable initial lease remains a nonfatal
    /// observation gap and publishes no current coverage epochs.
    pub fn start_with_shutdown_and_host(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        host: Arc<dyn HostObservationSource>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown_and_host_and_heartbeat(
            config,
            admission,
            kernel,
            host,
            shutdown_requested,
            None,
        )
    }

    /// Starts the composition with an optional Host heartbeat sink. The
    /// sink receives one admitted emission per Kernel-accepted heartbeat;
    /// emission failures are traced inside the tick and never fail
    /// supervision. `None` preserves the stdout-only contour.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as
    /// [`Self::start_with_shutdown_and_host`].
    #[allow(
        clippy::too_many_lines,
        reason = "the bounded supervision task keeps admission, observation, heartbeat emission, and gap reporting in one reviewable contour"
    )]
    pub fn start_with_shutdown_and_host_and_heartbeat(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        host: Arc<dyn HostObservationSource>,
        shutdown_requested: Arc<AtomicBool>,
        heartbeat: Option<Arc<HeartbeatTransport>>,
    ) -> Result<Self, CompositionError> {
        let _span = tracing::debug_span!("watchdog.composition_start").entered();
        tracing::debug!(
            event = "watchdog.composition_requested",
            observation = "requested",
            "watchdog composition requested"
        );
        config.validate()?;
        let runtime = config.runtime()?;
        let task_admission = admission.clone();
        let task_host = host;
        let authority_state = WatchdogAuthorityStateCell::new();
        let task_authority_state = authority_state.clone();
        let task_heartbeat = heartbeat.clone();
        let interval = config.tick_interval;
        let task = match runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            SERVICE_NAME,
            ChildClass::Worker,
            move |token| {
                let kernel = kernel.clone();
                let admission = task_admission.clone();
                let host = task_host.clone();
                let authority_state = task_authority_state.clone();
                let heartbeat = task_heartbeat.clone();
                async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => return Ok(()),
                            () = tokio::time::sleep(interval) => {}
                        }
                        // Host liveness is an independent sibling observation.
                        // It must run even when a lease is missing, stale, or
                        // otherwise unavailable during first install/recovery.
                        let host_observation = host.observe();
                        let host_gap = host_observation.gap_reason();
                        let admission = match admission.reload() {
                            Ok(admission) => admission,
                            Err(error) => {
                                authority_state.publish_no_authority();
                                // I14.23: intentional and incomplete shutdown
                                // are distinct observed states, not generic
                                // gaps. The lease stays fenced either way;
                                // only the observation vocabulary differs so
                                // recovery can tell a clean stop from retained
                                // pending work.
                                if crate::supervision_lease_load::is_intentional_shutdown_fence(
                                    &error,
                                ) {
                                    tracing::info!(
                                        event = "watchdog.shutdown.intentional_observed",
                                        observation = "intentional",
                                        "watchdog observed intentional shutdown; pre-drain leases fenced"
                                    );
                                } else if crate::supervision_lease_load::is_incomplete_shutdown_fence(
                                    &error,
                                ) {
                                    tracing::info!(
                                        event = "watchdog.shutdown.incomplete_observed",
                                        observation = "incomplete",
                                        "watchdog observed incomplete shutdown; pending work retained"
                                    );
                                }
                                if let Some(reason) = host_gap {
                                    report_gap_nonfatal(kernel.as_ref(), reason).await;
                                }
                                report_gap_nonfatal(kernel.as_ref(), admission_gap_reason(&error))
                                    .await;
                                continue;
                            }
                        };
                        if let Some(reason) = host_gap {
                            authority_state.publish_no_authority();
                            // Observation/spool failure is nonfatal. The
                            // Watchdog remains alive and will retry on the
                            // next bounded tick; no restart-budget path is
                            // entered for a lost Host or stale lease.
                            report_gap_nonfatal(kernel.as_ref(), reason).await;
                            if matches!(
                                host_observation.state,
                                HostObservationState::PidReused
                                    | HostObservationState::ImageSubstituted
                                    | HostObservationState::IdentityChanged
                            ) {
                                // A changed process identity is eligible for
                                // one fresh baseline only after this tick's
                                // signed lease was verified. Absent/unknown
                                // observations never get a free baseline.
                                host.rebaseline_after_verified_lease(admission.lease());
                            }
                            continue;
                        }
                        match kernel.supervise(admission.lease()).await {
                            Ok(()) => {
                                let kernel_epoch =
                                    admission.lease().lease().kernel_epoch.sequence.get();
                                let watchdog_epoch = admission.watchdog_epoch().value();
                                authority_state.publish_admitted(kernel_epoch, watchdog_epoch);
                                emit_admitted_heartbeat_best_effort(
                                    heartbeat.as_ref(),
                                    kernel_epoch,
                                    watchdog_epoch,
                                    interval.as_millis(),
                                )
                                .await;
                            }
                            Err(error) => {
                                authority_state.publish_no_authority();
                                report_gap_nonfatal(kernel.as_ref(), kernel_gap_reason(&error))
                                    .await;
                            }
                        }
                    }
                }
            },
        ) {
            eliot_runtime::SpawnDisposition::Admitted(task) => task,
            eliot_runtime::SpawnDisposition::DeniedShuttingDown => {
                return Err(CompositionError::AdmissionClosed);
            }
        };
        Ok(Self {
            runtime,
            admission,
            authority_state,
            config,
            task,
            shutdown_requested,
            heartbeat,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> WatchdogReadiness {
        let snapshot = self.authority_state.load();
        let (service_instance_guid, host_challenge_nonce, watchdog_readiness_sequence) =
            self.heartbeat.as_ref().map_or_else(
                || {
                    (
                        String::new(),
                        String::new(),
                        crate::heartbeat_transport::FENCE_SEQUENCE,
                    )
                },
                |transport| {
                    let (service_instance_guid, host_challenge_nonce) = transport.echo_identity();
                    (
                        service_instance_guid,
                        host_challenge_nonce,
                        transport.last_sequence(),
                    )
                },
            );
        WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: snapshot.state,
            coverage_claimed: snapshot.state.coverage_claimed(),
            kernel_epoch: snapshot.kernel_epoch,
            watchdog_epoch: snapshot.watchdog_epoch,
            tick_interval_ms: self.config.tick_interval.as_millis(),
            service_instance_guid,
            host_challenge_nonce,
            watchdog_readiness_sequence,
        }
    }

    /// Waits for process termination and performs ordered runtime shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the supervised watchdog task, shutdown signal, or
    /// externally requested shutdown path fails.
    pub async fn run_until_shutdown(self) -> Result<ShutdownOutcome, TaskFailure> {
        let _span = tracing::info_span!("watchdog.run_until_shutdown").entered();
        tracing::info!(
            event = "watchdog.supervision_running",
            observation = "admitted",
            "watchdog supervision running until shutdown"
        );
        let WatchdogComposition {
            runtime,
            admission,
            task,
            shutdown_requested,
            ..
        } = self;
        let _admission_source = admission;
        let mut task_result = Box::pin(task.join());
        tokio::select! {
            result = &mut task_result => {
                let shutdown = runtime.shutdown().await;
                result.map(|_| shutdown)
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    return Err(TaskFailure::Failed("failed to receive shutdown signal".to_owned()));
                }
                runtime.shutdown_handle().request();
                let result = task_result.await;
                let shutdown = runtime.shutdown().await;
                complete_requested_shutdown(result, shutdown)
            }
            result = wait_for_shutdown(shutdown_requested) => {
                if result {
                    runtime.shutdown_handle().request();
                    let result = task_result.await;
                    let shutdown = runtime.shutdown().await;
                    complete_requested_shutdown(result, shutdown)
                } else {
                    Err(TaskFailure::Failed("watchdog shutdown signal failed".to_owned()))
                }
            }
        }
    }

    /// Requests bounded shutdown from an SCM control path.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
    }
}

fn complete_requested_shutdown<T>(
    result: Result<T, TaskFailure>,
    shutdown: ShutdownOutcome,
) -> Result<ShutdownOutcome, TaskFailure> {
    match result {
        Ok(_) | Err(TaskFailure::Cancelled) => Ok(shutdown),
        Err(error) => Err(error),
    }
}

/// Emits one admitted heartbeat best-effort: emission failures are traced
/// and never fail the supervision tick.
async fn emit_admitted_heartbeat_best_effort(
    heartbeat: Option<&Arc<HeartbeatTransport>>,
    kernel_epoch: u64,
    watchdog_epoch: u64,
    tick_interval_ms: u128,
) {
    let Some(transport) = heartbeat else {
        return;
    };
    if let Err(error) = transport
        .emit_admitted(kernel_epoch, watchdog_epoch, tick_interval_ms)
        .await
    {
        tracing::debug!(
            event = "watchdog.heartbeat.emit_skipped",
            observation = "attempted",
            error = error.to_string().as_str(),
            "heartbeat emission skipped; supervision continues"
        );
    }
}

async fn wait_for_shutdown(shutdown_requested: Arc<AtomicBool>) -> bool {
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Narrow admitted backup control port over the owner-held spool.
///
/// The caller must be the admitted backup role (`BackupRole::SpoolOwner` per
/// #954). Role authentication happens above this port: this crate carries no
/// `eliot-protocol` dependency, so this type takes no role argument and mints
/// no authority.
///
/// Every method runs OUTSIDE the heartbeat tick with finite limits, so backup
/// work can never block Control Reserve through unbounded work. Captures are
/// read-only owner transactions; isolated imports target only the externally
/// admitted isolated installation and never reuse the active lease, heartbeat
/// readiness, supervision authority, or kernel/watchdog epochs. This port
/// performs no SCM, restart, cutover, authority, lease, epoch, or transport
/// work, and changes nothing on the start/readiness/heartbeat paths.
pub struct WatchdogBackupPort {
    spool: Arc<WatchdogSpool>,
    limits: WatchdogSpoolBackupLimits,
}

impl WatchdogBackupPort {
    /// Binds the admitted port to the composition's spool owner handle with
    /// finite page limits.
    ///
    /// The spool handle is the same owner the supervision path appends
    /// through; no second database handle is opened and no global state is
    /// introduced. `limits` bounds every later [`Self::read_page`] call.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when `limits` is unbounded, unprogressable, or
    /// above its hard ceilings.
    ///
    /// The final backup composition (#945 follow-up) is the designated
    /// production caller that binds the owner spool handle; until that wiring
    /// lands this constructor is crate-reachable staging, not dead logic.
    #[allow(
        dead_code,
        reason = "constructed by the #945 final backup composition wiring"
    )]
    pub(crate) fn new(
        spool: Arc<WatchdogSpool>,
        limits: WatchdogSpoolBackupLimits,
    ) -> Result<Self, SpoolError> {
        limits.validate()?;
        Ok(Self { spool, limits })
    }

    /// Captures one bounded coherent fence through the spool owner.
    ///
    /// Thin delegation to `WatchdogSpool::snapshot_backup`: one bounded read
    /// transaction over header, high-water, and retained entries. The
    /// requester bound in `params` must be the admitted backup role.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the admitted bindings, limits, or retained
    /// evidence fail validation.
    pub fn snapshot(
        &self,
        params: CaptureFenceParams,
        limits: WatchdogSpoolBackupLimits,
    ) -> Result<WatchdogSpoolFence, SpoolError> {
        self.spool.snapshot_backup(params, limits)
    }

    /// Reads one finite page of a captured fence.
    ///
    /// Thin delegation to `backup::read_page`, bounded by the limits fixed at
    /// [`Self::new`]. Continuation binds the one fence digest; drift fails
    /// closed instead of returning partial coverage.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the page runs past the retained window or
    /// the cumulative bound.
    pub fn read_page(
        &self,
        fence: &WatchdogSpoolFence,
        page_index: u64,
    ) -> Result<WatchdogSpoolSnapshotPage, SpoolError> {
        crate::watchdog_spool::backup::read_page(fence, page_index, &self.limits)
    }

    /// Imports bounded restore steps into the isolated destination only.
    ///
    /// Thin delegation to `WatchdogSpool::import_backup_isolated`. `dest`
    /// must differ from both `source` and the active installation; old signed
    /// observations stay historical evidence under their exact source
    /// identity and grant no active supervision, heartbeat, lease, or epoch
    /// authority. A repeated byte-identical import appends nothing; unknown
    /// reconciliation stays visible and blocks acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the destination is not isolated, the step
    /// chain breaks, content conflicts, or reconciliation is unknown.
    pub fn import_isolated(
        &self,
        source: &str,
        dest: &str,
        active: &str,
        steps: &[SpoolRestoreStep],
    ) -> Result<SpoolRestoreDisposition, SpoolError> {
        self.spool
            .import_backup_isolated(source, dest, active, steps)
    }
}
