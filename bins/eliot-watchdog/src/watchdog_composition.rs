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
use crate::backup_control::BackupControlRegistration;
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
    /// The injected Kernel port, retained so the admitted backup control port
    /// can reach the owner-held spool through the same owner the supervision
    /// task supervises through.
    ///
    /// The supervision task holds its own clone for the whole process lifetime,
    /// so retaining one here adds no second owner, no second spool handle, and
    /// no effect: the admitted backup port is the only reader this exposes.
    kernel: Arc<dyn KernelWatchdogPort>,
    authority_state: WatchdogAuthorityStateCell,
    config: WatchdogConfig,
    task: eliot_runtime::SupervisedHandle,
    shutdown_requested: Arc<AtomicBool>,
    heartbeat: Option<Arc<HeartbeatTransport>>,
    /// This composition's own bounded backup-control registration table.
    ///
    /// Opened once at composition start, so backup control is registrable for
    /// this composition's whole supervised lifetime and only this
    /// composition's own shutdown closes it. It is not a process global: a
    /// second composition in the same process opens its own table, and
    /// starting supervision never touches either one.
    backup_control_registration: BackupControlRegistration,
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
        let task_kernel = Arc::clone(&kernel);
        let interval = config.tick_interval;
        let task = match runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            SERVICE_NAME,
            ChildClass::Worker,
            move |token| {
                let kernel = task_kernel.clone();
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
            kernel,
            authority_state,
            config,
            task,
            shutdown_requested,
            heartbeat,
            backup_control_registration: BackupControlRegistration::open(),
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
    /// Supervision STARTING is not a lifecycle end for backup control: this
    /// method only begins waiting, so it does not close, release, or otherwise
    /// touch the composition's backup-control registration table. Registration
    /// stays open for the whole supervised lifetime and is closed only by the
    /// genuine shutdown path, [`request_shutdown`](Self::request_shutdown).
    /// Backup control holds no supervised task, so bounded cleanup needs no
    /// join here and supervision priority is preserved.
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

    /// Registers the admitted backup control port against this composition.
    ///
    /// Delegates to [`crate::backup_control::register_backup_control`], which
    /// binds the port to the owner-held spool reachable through
    /// [`Self::owner_backup_port`] and reserves a slot in THIS composition's own
    /// bounded registration table. Backup control holds no supervision task:
    /// it cannot stall supervision or exhaust the Control Reserve.
    ///
    /// Registration is refused only by this composition's own bounded table
    /// (exhausted, or closed by this composition's own shutdown). Starting
    /// supervision does not close it, and another composition's shutdown does
    /// not affect it, so the port stays registrable for the whole supervised
    /// lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when the composition identity is unexpected or when
    /// the injected kernel port owns no spool, so no owner-bound backup port
    /// exists to admit.
    pub fn register_backup_control(
        &self,
    ) -> Result<crate::backup_control::BackupControlHandle, CompositionError> {
        crate::backup_control::register_backup_control(self)
    }

    /// Returns this composition's own bounded backup-control registration
    /// table, so registration is scoped to this lifecycle.
    ///
    /// Cloned into each registered handle, never into process-global state: a
    /// fresh composition opens its own open table, and only
    /// [`Self::request_shutdown`] closes this one.
    pub(crate) fn backup_control_registration(&self) -> BackupControlRegistration {
        self.backup_control_registration.clone()
    }

    /// Returns the owner-bound backup port exposed by this composition's
    /// kernel port, or `None` when the injected port owns no spool.
    ///
    /// This is the only route from the composition to the Watchdog spool: the
    /// composition holds no `WatchdogSpool` of its own, so the single owner
    /// handle lives inside the sensor that also appends every heartbeat and
    /// gap record. No second database handle is opened anywhere on this path.
    pub(crate) fn owner_backup_port(&self) -> Option<Arc<WatchdogBackupPort>> {
        self.kernel.spool_backup_port()
    }

    /// Requests bounded shutdown from an SCM control path.
    pub fn request_shutdown(&self) {
        // Genuine lifecycle end: this composition closes its OWN backup-control
        // table, releasing exactly its registrations. Backup control holds no
        // task to join: shutdown stays bounded and supervision teardown never
        // waits on backup wiring.
        self.backup_control_registration.close();
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

/// Owner-bound admitted backup control port over the Watchdog spool.
///
/// The port is bound to the exact owner that holds the spool: the construction
/// seam is the same
/// [`IndependentKernelSensor`](crate::IndependentKernelSensor) that appends
/// through `KernelWatchdogPort::supervise`, so the composition's kernel port
/// hands out this one object and no second database handle is ever opened. The
/// port also carries that owner's retained installation identity and watchdog
/// generation, and binds every request and every fence against those
/// owner-held values, failing closed on any mismatch.
///
/// The caller must be the admitted backup role (`BackupRole::SpoolOwner` per
/// #954). Role authentication happens above this port: this crate carries no
/// `eliot-protocol` dependency, so this type takes no role argument and mints
/// no authority. The port therefore validates no peer identity and no
/// generation fence of its own; those need the role-bound control contract.
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
    source_installation: String,
    watchdog_generation: u64,
    limits: WatchdogSpoolBackupLimits,
}

impl WatchdogBackupPort {
    /// Binds the admitted port to the composition's spool owner handle, that
    /// owner's retained identities, and finite page limits.
    ///
    /// The spool handle is the same owner the supervision path appends
    /// through; no second database handle is opened and no global state is
    /// introduced. `source_installation` and `watchdog_generation` are the
    /// owner's own retained binding values, not caller input: every later
    /// capture and page read is bound against them. `limits` bounds every
    /// later [`Self::read_page`] call.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when `limits` is unbounded, unprogressable, or
    /// above its hard ceilings, when the owner installation identity is
    /// unusable, or when the owner generation is zero.
    pub(crate) fn new(
        spool: Arc<WatchdogSpool>,
        source_installation: String,
        watchdog_generation: u64,
        limits: WatchdogSpoolBackupLimits,
    ) -> Result<Self, SpoolError> {
        limits.validate()?;
        if source_installation.trim().is_empty()
            || source_installation.chars().any(char::is_control)
        {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an unusable owner installation identity".to_owned(),
            ));
        }
        if watchdog_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an uninitialized owner generation".to_owned(),
            ));
        }
        Ok(Self {
            spool,
            source_installation,
            watchdog_generation,
            limits,
        })
    }

    /// Returns the owner-held installation identity this port is bound to.
    #[must_use]
    pub fn source_installation(&self) -> &str {
        &self.source_installation
    }

    /// Returns the owner-held watchdog generation this port is bound to.
    #[must_use]
    pub const fn watchdog_generation(&self) -> u64 {
        self.watchdog_generation
    }

    /// Binds one capture request against the owner's retained identity.
    ///
    /// The requested source installation and watchdog generation are compared
    /// with the values the owner itself holds, so a request naming another
    /// installation or another generation fails closed instead of producing a
    /// fence that claims the wrong provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when either binding differs from the owner's.
    fn check_owner_bindings(&self, params: &CaptureFenceParams) -> Result<(), SpoolError> {
        if params.source_installation != self.source_installation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a capture for a foreign source installation"
                    .to_owned(),
            ));
        }
        if params.watchdog_generation != self.watchdog_generation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a capture for a foreign watchdog generation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Captures one bounded coherent fence through the spool owner.
    ///
    /// Thin delegation to `WatchdogSpool::snapshot_backup`: one bounded read
    /// transaction over header, high-water, and retained entries, after the
    /// request is bound against the owner-held installation identity and
    /// generation.
    ///
    /// The captured fence is then put through the SAME age window
    /// [`Self::read_page`] applies, by the same [`Self::check_capture_age`]
    /// check against the same owner clock. That is what keeps the two halves
    /// of this port from disagreeing: the freshness anchor is the fence's
    /// capture anchor, which is the newest retained observation rather than a
    /// wall-clock instant (this fence builder is clock-free and mints no
    /// instant of its own), so a spool whose newest retained observation is
    /// already older than the admitted window yields a fence that could never
    /// be paged. Refusing it here, with the identical reason and verdict a
    /// page read would give, is the honest outcome — the alternative is handing
    /// out a capture that is born expired. Nothing is invented to avoid that
    /// refusal: no second clock is read and no timestamp is stamped, so a
    /// capture is still admitted exactly when the same fence would still pass
    /// its own page read.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the admitted bindings or limits fail
    /// validation, the retained evidence fails capture validation, or the
    /// captured fence is outside the admitted page-freshness and
    /// whole-snapshot lifetime windows.
    pub fn snapshot(
        &self,
        params: CaptureFenceParams,
        limits: WatchdogSpoolBackupLimits,
    ) -> Result<WatchdogSpoolFence, SpoolError> {
        self.check_owner_bindings(&params)?;
        let fence = self.spool.snapshot_backup(params, limits)?;
        self.check_capture_age(&fence)?;
        Ok(fence)
    }

    /// Applies the owner clock's capture-age window to one fence.
    ///
    /// The anchor is [`WatchdogSpoolFence::captured_at_ms`] — the newest
    /// retained observation the fence carries, which is never later than its own
    /// evidence — measured against this owner's own clock with the bounds fixed
    /// at [`Self::new`]. A future-dated anchor, or one older than either the
    /// page-freshness window or the whole-snapshot lifetime window, is refused.
    ///
    /// Both [`Self::snapshot`] and [`Self::read_page`] call this one function, so
    /// for the same fence and the same instant the two halves of this port give
    /// the same verdict: capture admits exactly the fences a later page read
    /// would still accept, and refuses a born-expired fence instead of issuing
    /// one that can never be paged. The reasons below name both callers because
    /// the check is one check.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the owner clock is unavailable, the fence is
    /// future-dated, or the fence is older than the admitted freshness or
    /// lifetime window.
    fn check_capture_age(&self, fence: &WatchdogSpoolFence) -> Result<(), SpoolError> {
        let now_ms = crate::current_unix_ms()?;
        if now_ms < fence.captured_at_ms {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a future-dated capture; a page read of it would be refused"
                    .to_owned(),
            ));
        }
        let age_ms = now_ms - fence.captured_at_ms;
        if age_ms > self.limits.page_ttl_ms || age_ms > self.limits.snapshot_lifetime_ms {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an expired capture; a page read of it would be refused"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Reads one finite, unexpired page of a captured fence.
    ///
    /// The fence is re-validated against the evidence it holds, bound against
    /// the owner-held installation identity and generation, and bounded by the
    /// limits fixed at [`Self::new`]. The clock-dependent page-freshness and
    /// whole-snapshot lifetime windows are consulted here against the owner's
    /// own clock, through the same [`Self::check_capture_age`] that
    /// [`Self::snapshot`] applies: an expired fence is incomplete, never a
    /// current empty page. Continuation binds the one fence digest, so drift
    /// fails closed instead of returning partial coverage.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the fence fails re-validation, is not this
    /// owner's, the page is older than the admitted freshness or lifetime
    /// window, the page runs past the retained window, or the cumulative bound
    /// is exceeded.
    pub fn read_page(
        &self,
        fence: &WatchdogSpoolFence,
        page_index: u64,
    ) -> Result<WatchdogSpoolSnapshotPage, SpoolError> {
        fence.validate()?;
        if fence.source_installation != self.source_installation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a page read for a foreign source installation"
                    .to_owned(),
            ));
        }
        if fence.watchdog_generation != self.watchdog_generation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a page read for a foreign watchdog generation"
                    .to_owned(),
            ));
        }
        self.check_capture_age(fence)?;
        crate::watchdog_spool::backup::read_page(fence, page_index, &self.limits)
    }

    /// Imports bounded restore steps and reports whether recovery is accepted.
    ///
    /// Thin delegation to `WatchdogSpool::import_backup_isolated`, with the
    /// request's `active` installation bound against the owner-held identity
    /// so an import can never be presented as isolated from the wrong live
    /// installation. `dest` must differ from both `source` and that active
    /// identity; old signed observations stay historical evidence under their
    /// exact source identity and grant no active supervision, heartbeat,
    /// lease, or epoch authority. A repeated byte-identical import appends
    /// nothing; the observed disposition is then passed through
    /// `acceptance_allowed`, so an unresolved reconciliation blocks recovery
    /// acceptance instead of returning zero by default.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the active identity is not the owner's, the
    /// destination is not isolated, the step chain breaks, content conflicts,
    /// or reconciliation is unknown.
    pub fn import_isolated(
        &self,
        source: &str,
        dest: &str,
        active: &str,
        steps: &[SpoolRestoreStep],
    ) -> Result<SpoolRestoreDisposition, SpoolError> {
        if active != self.source_installation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an import that does not name this owner as the active installation"
                    .to_owned(),
            ));
        }
        let disposition = self
            .spool
            .import_backup_isolated(source, dest, active, steps)?;
        crate::watchdog_spool::backup::acceptance_allowed(disposition)?;
        Ok(disposition)
    }
}
