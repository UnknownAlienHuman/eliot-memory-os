//! Private runtime-loop wiring for the independent Watchdog process.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose),
//! A13.2 (docs/architecture/A13-02-kernel-and-failure-domains.md#a132-kernel-and-failure-domains),
//! ARCH-WDG-01, ARCH-WDG-02.
//! Implementation: I1.2 (docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md#i12-required-processes-of-the-first-complete-runtime),
//! I8.1 (docs/architecture/I08-01-process-and-authority.md#i81-process-and-authority),
//! I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes).
//!
//! This private child owns only the extracted bounded Watchdog composition
//! mechanism. It owns no lifecycle, SCM, canonical, semantic, or write
//! authority; the parent retains process entry, SCM dispatch/validation,
//! self-admission probes, and status publication.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(windows)]
use std::time::Instant;

use eliot_platform_windows::ServiceBootstrapArguments;
#[cfg(windows)]
use eliot_platform_windows::WindowsPlatform;
use eliot_runtime::ShutdownDisposition;
use eliot_watchdog::{
    FileWatchdogAdmission, GovernorIntentAdmissionSource, HeartbeatTransport,
    INSTALLATION_REGISTRY_FILE_NAME, IndependentKernelSensor, LiveHostObservationSource,
    SERVICE_NAME, SpoolError, WatchdogAdmissionSource, WatchdogComposition, WatchdogConfig,
    WatchdogReadiness, inspect_approved_host_registration,
};

#[cfg(windows)]
use super::{
    ScmWatchdogSelfAdmissionStatus, WindowsWatchdogSelfAdmissionProbe, set_service_status_running,
    set_service_status_stopped,
};

pub(super) fn run_watchdog(
    stop_signal: Arc<AtomicBool>,
    scm_launch: Option<&eliot_watchdog::ValidatedWatchdogScmLaunch>,
) -> Result<(), String> {
    let _runtime_span = tracing::info_span!("watchdog.runtime").entered();
    tracing::info!(
        event = "watchdog.startup_requested",
        observation = "requested",
        "watchdog runtime requested"
    );
    let bootstrap = scm_launch
        .map(|launch| launch.bootstrap().clone())
        .ok_or_else(|| "SCM bootstrap is required for Runtime contour selection".to_owned())?;
    let host_state_root = bootstrap
        .host_state_root()
        .ok_or_else(|| "SCM bootstrap omitted the installer-approved Host state root".to_owned())?;
    let registry_path = host_state_root.join(INSTALLATION_REGISTRY_FILE_NAME);
    // The heartbeat transport binds this exact bootstrap contour and arms
    // lazily from the Host-issued descriptor file, so a descriptor issued
    // after Watchdog start (pre-Phase-B fence, then Host start) is picked
    // up without a restart. Absent or invalid files degrade to
    // stdout-only; supervision never fails for transport state.
    let heartbeat = Arc::new(HeartbeatTransport::for_bootstrap(
        &host_state_root,
        bootstrap.installation_id(),
        bootstrap.transaction_plan_generation(),
        WatchdogConfig::default().tick_interval,
    ));
    // The lease is issued by the Host/Kernel contour.  There is deliberately
    // no genesis/default lease in this process.  A stale or missing lease
    // starts a gap-only sensor so the Watchdog can remain alive and record a
    // bounded observation; the sensor gains heartbeat authority only after a
    // later, freshly verified lease.  The source is retained by the
    // composition and reloaded before every observation.
    let admission_source = match wait_for_durable_admission(
        registry_path,
        bootstrap,
        &stop_signal,
        heartbeat.clone(),
    )? {
        Some(admission) => {
            tracing::info!(
                event = "watchdog.admission_reconciled",
                observation = "reconciled",
                "durable admission reconciled"
            );
            Arc::new(admission)
        }
        None => {
            tracing::info!(
                event = "watchdog.shutdown",
                disposition = "stop_requested",
                "shutdown requested before durable admission"
            );
            return Ok(());
        }
    };
    let binding = admission_source.runtime_binding();
    inspect_approved_host_registration(&binding).map_err(|error| error.to_string())?;
    let initial_admission = match admission_source.reload() {
        Ok(admission) => Some(admission),
        Err(error) => {
            // A real admission-path failure observed before the sensor exists
            // is still evidence: a gap-only sensor opens below and starts
            // counting the deterministic rule on its first supervision tick.
            let reason = match &error {
                SpoolError::Io(_) => "spool_io",
                SpoolError::InvalidProtectedRoot => "invalid_protected_root",
                SpoolError::Serialization(_) => "serialization",
                SpoolError::Database(_) => "database",
                SpoolError::Corrupt(_) => "corrupt",
                SpoolError::InvalidLease(_) => "unavailable_or_invalid",
                SpoolError::LeaseStale(_) => "stale",
                SpoolError::LeaseFenced(_) => "fenced",
            };
            // I1.10: freshness is its own health dimension, so a stale lease
            // owns the exact stale diagnostic here — never the unavailable
            // record and never a failure. The gap-only sensor below still
            // opens either way; only the observation vocabulary differs.
            if matches!(&error, SpoolError::LeaseStale(_)) {
                tracing::info!(
                    event = "watchdog.initial_admission_stale",
                    observation = "stale",
                    reason = reason,
                    "initial durable admission is stale; starting a gap-only sensor"
                );
            } else {
                tracing::info!(
                    event = "watchdog.initial_admission_unavailable",
                    observation = "unavailable",
                    reason = reason,
                    "initial durable admission is unavailable; starting a gap-only sensor"
                );
            }
            None
        }
    };
    let sensor = Arc::new(
        match initial_admission {
            Some(admission) => IndependentKernelSensor::open_runtime_binding(
                binding.clone(),
                admission.watchdog_epoch().value(),
            ),
            None => IndependentKernelSensor::open_runtime_binding_without_epoch(binding.clone()),
        }
        .map_err(|error| error.to_string())?,
    );
    // I8.1: the deterministic intent rule is driven by the real admission
    // path, not by a private Watchdog policy loop. The decorator delegates
    // every admission decision unchanged and returns its result verbatim; it
    // only counts genuine Governor-unavailability proofs and closes an open
    // escalation episode on a live admission. Its sole write is a
    // `watchdog.redb` append: no ORS, canonical, or HostStateJournal write is
    // reachable from this seam.
    let admission_source = Arc::new(GovernorIntentAdmissionSource::new(
        admission_source,
        sensor.clone(),
    ));
    let composition = WatchdogComposition::start_with_shutdown_and_host_and_heartbeat(
        WatchdogConfig::default(),
        admission_source,
        sensor,
        Arc::new(LiveHostObservationSource::from_binding(&binding)),
        stop_signal,
        Some(heartbeat),
    )
    .map_err(|error| error.to_string())?;
    #[cfg(windows)]
    if let Some(launch) = scm_launch {
        let root = launch
            .registration()
            .binary_path()
            .parent()
            .ok_or_else(|| "approved Watchdog image has no package root".to_owned())?;
        let platform = WindowsPlatform::new(root.to_path_buf())
            .map_err(|error| format!("Watchdog self-admission platform root: {error}"))?;
        let mut probe = WindowsWatchdogSelfAdmissionProbe {
            platform,
            request: launch.registration(),
            started_at: Instant::now(),
        };
        let mut status = ScmWatchdogSelfAdmissionStatus;
        eliot_watchdog::admit_watchdog_self_start(&mut probe, &mut status)
            .map_err(|error| error.to_string())?;
    }
    let readiness = composition.readiness();
    tracing::info!(
        event = "watchdog.readiness",
        observation = "admitted",
        "watchdog readiness published; startup is not readiness"
    );
    serde_json::to_writer(&mut io::stdout().lock(), &readiness)
        .map_err(|error| format!("{error:?}"))?;
    writeln!(io::stdout().lock()).map_err(|error| error.to_string())?;
    #[cfg(windows)]
    set_service_status_running();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    // #962 W1/W2: the live production startup path of this process now owns the
    // backup-control lifecycle. It registers and starts against the real
    // `WatchdogComposition` started above, and stops on the single release
    // point below, so no registration outlives the supervised lifetime and no
    // exit path skips the release.
    //
    // Placement is deliberate: readiness is already published and SCM is already
    // `RUNNING` above, so a refusal here can never block readiness, delay
    // start, or keep the service from reaching its supervised lifetime. The
    // blast radius of a refusal is exactly one capability — supervision
    // continues unchanged, and no listener, task, registration slot, or
    // authority is created on either side of it.
    let backup_control = start_supervision_backup_control(&composition);
    let shutdown = runtime.block_on(composition.run_until_shutdown());
    // Unconditional and before the only fallible step below, so the normal
    // return, the task-failure return, and the externally requested stop all
    // release the registration exactly once.
    release_supervision_backup_control(backup_control);
    let shutdown = shutdown.map_err(|error| format!("{error:?}"))?;
    #[cfg(windows)]
    set_service_status_stopped();
    let disposition = match shutdown.disposition {
        ShutdownDisposition::Graceful => "graceful",
        ShutdownDisposition::Forced => "forced",
        ShutdownDisposition::Incomplete => "incomplete",
    };
    tracing::info!(
        event = "watchdog.shutdown",
        disposition = disposition,
        forced_tasks = shutdown.forced_tasks,
        no_orphans = shutdown.no_orphans,
        "watchdog supervision shutdown reported"
    );
    Ok(())
}

/// Registers and starts Watchdog backup control on the live composition.
///
/// This is a real production caller, not a probe: it calls the composition's
/// own registration method and the bounded start on the composition this
/// process actually started, and it observes the live owner resource both steps
/// read. It returns `None` — never a substitute handle, never a no-op stand-in
/// — when this process cannot admit backup control.
///
/// A refusal is bounded and nonfatal by placement, not by suppression: the
/// caller runs this after readiness is published and after SCM reports
/// `RUNNING`, so declining backup control cannot delay or block startup. The
/// typed reason is traced in full, and supervision continues with exactly the
/// behaviour it had before, because this function creates no listener, task,
/// slot, or authority on either the admitted or the refused path.
fn start_supervision_backup_control(
    composition: &WatchdogComposition,
) -> Option<eliot_watchdog::BackupControlHandle> {
    let mut handle = match composition.register_backup_control() {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                event = "watchdog.backup_control_registration_refused",
                observation = "unavailable",
                reason_code = "REGISTRATION_REFUSED",
                detail = truncate_failure_detail(&error.to_string()).as_str(),
                "watchdog continues without backup control; supervision is unchanged"
            );
            return None;
        }
    };
    if let Err(error) = eliot_watchdog::start_backup_control(&mut handle) {
        // The bounded slot this handle already reserved is released on this
        // refusal path too: a handle that failed to start never admitted
        // dispatch, so it must not keep occupying one of the bounded slots.
        let released = eliot_watchdog::stop_backup_control(handle);
        tracing::warn!(
            event = "watchdog.backup_control_start_refused",
            observation = "unavailable",
            reason_code = "START_REFUSED",
            registration_slot = released.registration_slot(),
            detail = truncate_failure_detail(&error.to_string()).as_str(),
            "watchdog continues without backup control; supervision is unchanged"
        );
        return None;
    }
    tracing::info!(
        event = "watchdog.backup_control_admitted",
        observation = "admitted",
        registration_slot = handle.registration_slot(),
        owner_spool_high_water = handle.owner_spool_high_water(),
        owner_generation = handle.owner_generation(),
        "watchdog backup control registered and started against the live owner spool"
    );
    Some(handle)
}

/// Releases one started backup-control registration on the shutdown path.
///
/// Idempotent for a `None` input: the caller may hold no registration at all
/// when registration was refused. The released slot and the owner sequences
/// observed while it was live are both reported, so a reader can see that the
/// registration was released rather than merely dropped.
fn release_supervision_backup_control(handle: Option<eliot_watchdog::BackupControlHandle>) {
    let Some(handle) = handle else {
        return;
    };
    let slot = handle.registration_slot();
    let owner_spool_high_water = handle.owner_spool_high_water();
    let _released = eliot_watchdog::stop_backup_control(handle);
    tracing::info!(
        event = "watchdog.backup_control_released",
        observation = "released",
        registration_slot = slot,
        owner_spool_high_water = owner_spool_high_water,
        "watchdog backup control registration released on the shutdown path"
    );
}

/// Delay between durable-admission probes while fenced pre-Phase-B.
const PENDING_PHASE_B_FENCE_POLL: Duration = Duration::from_millis(250);

/// Base delay between transient-registry-lock retries while awaiting durable
/// admission. The sleep doubles per consecutive transient observation and is
/// capped by [`TRANSIENT_REGISTRY_LOCK_POLL_MAX`].
const TRANSIENT_REGISTRY_LOCK_POLL_BASE: Duration = Duration::from_millis(250);
/// Ceiling for one transient-registry-lock sleep. The wait itself stays
/// SCM-stop-bounded (A13.2): an SCM stop exits cleanly instead of polling.
const TRANSIENT_REGISTRY_LOCK_POLL_MAX: Duration = Duration::from_millis(2_000);

/// Per-field ceiling for the admission/fence failure detail carried in the
/// `run_watchdog` error string. Mirrors the capsule detail bound
/// (`watchdog_service_status.rs`) so the typed class stays stable while the
/// fence cause survives truncation secret-free.
const ADMISSION_FAILURE_DETAIL_MAX_CHARS: usize = 512;

/// One fence-poll iteration disposition for a failed registry read.
///
/// s37/#1339: a redb `DatabaseAlreadyOpen` lock is transient contention from
/// a live writer (Host `registry_store`, installer staging), not a verdict
/// on registry bytes, so the waiter sleeps and polls again instead of
/// exiting (A0.3 defaults to retry with new evidence outside Hard
/// Boundaries). Any other registry state keeps failing closed with `STOPPED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FencePollDisposition {
    /// A lock-contention read: sleep with bounded backoff and poll again.
    RetryTransient,
    /// A proved non-transient state: exit with the bounded failure detail.
    FailClosed,
}

/// Classifies one failed fence-poll iteration from the exact production
/// error strings.
///
/// Either read may observe the transient lock while the other fails
/// differently (release race between the two opens), so contention on either
/// side retries: the waiter cannot prove a fail-closed state while a read is
/// lock-blocked, and the next iteration re-evaluates both reads.
#[must_use]
pub(crate) fn fence_poll_disposition(
    admission_error: &str,
    fence_error: &str,
) -> FencePollDisposition {
    if FileWatchdogAdmission::is_transient_registry_lock(admission_error)
        || FileWatchdogAdmission::is_transient_registry_lock(fence_error)
    {
        FencePollDisposition::RetryTransient
    } else {
        FencePollDisposition::FailClosed
    }
}

/// Bounded backoff for consecutive transient-lock observations.
#[must_use]
pub(crate) fn transient_lock_backoff(transient_streak: u32) -> Duration {
    let shift = transient_streak.min(3);
    TRANSIENT_REGISTRY_LOCK_POLL_BASE
        .checked_mul(1_u32 << shift)
        .unwrap_or(TRANSIENT_REGISTRY_LOCK_POLL_MAX)
        .min(TRANSIENT_REGISTRY_LOCK_POLL_MAX)
}

fn truncate_failure_detail(value: &str) -> String {
    if value.chars().count() > ADMISSION_FAILURE_DETAIL_MAX_CHARS {
        value
            .chars()
            .take(ADMISSION_FAILURE_DETAIL_MAX_CHARS)
            .collect()
    } else {
        value.to_owned()
    }
}

/// Best-effort bounded notice that one fence-poll iteration observed lock
/// contention and will retry. The detail is already truncated and carries no
/// bootstrap secret (the registration nonce never enters `SpoolError`).
fn report_transient_registry_lock(detail: &str) {
    tracing::debug!(
        event = "watchdog.transient_registry_lock",
        observation = "attempted",
        detail = truncate_failure_detail(detail).as_str(),
        "transient installation-registry lock, retrying"
    );
    let _ = writeln!(
        io::stderr().lock(),
        "{SERVICE_NAME}: transient installation-registry lock, retrying: {detail}"
    );
}

/// Publishes one proven pre-Phase-B fence readiness: `RunningNoAuthority`
/// with no coverage claimed. Only a successful
/// `pending_phase_b_fence_readiness` probe reaches this; a transient lock is
/// never announced as fenced.
fn announce_fence_readiness(
    fence: &WatchdogReadiness,
    heartbeat: &HeartbeatTransport,
) -> Result<(), String> {
    tracing::info!(
        event = "watchdog.fence_readiness",
        observation = "admitted",
        "pre-Phase-B fence readiness announced"
    );
    serde_json::to_writer(&mut io::stdout().lock(), fence).map_err(|error| format!("{error:?}"))?;
    writeln!(io::stdout().lock()).map_err(|error| error.to_string())?;
    // Transport1750: the same fence projection rides the Host-owned pipe at
    // sequence zero when the Host already issued this contour a descriptor.
    // Best-effort on a throwaway runtime: a missing listener only costs one
    // failed open, and stdout above remains the durable announce.
    if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        runtime.block_on(heartbeat.emit_fence(fence));
    }
    #[cfg(windows)]
    set_service_status_running();
    Ok(())
}

/// Resolves the durable installer-bound admission, awaiting the Phase-B
/// receipt when the selected generation is fenced pre-Phase-B.
///
/// s33.2: first install starts Watchdog before credential provisioning and
/// Phase-B materialization by design, so `from_registry` fails on the durable
/// authority gate while every other contour check passes. That state returns
/// the observable fenced readiness (`RunningNoAuthority`, no coverage claimed)
/// and reports SCM running so the installation drive can advance to Host
/// start, credential provisioning, and Phase-B materialization; the existing
/// reconcile path (`from_registry` re-read per probe) then admits the durable
/// authority without a new stage. Any registry state that is not a provable
/// pre-Phase-B pending fence keeps the original error so the process still
/// fails closed with `STOPPED`, and an SCM stop during the wait exits cleanly.
fn wait_for_durable_admission(
    registry_path: PathBuf,
    bootstrap: ServiceBootstrapArguments,
    stop_signal: &AtomicBool,
    heartbeat: Arc<HeartbeatTransport>,
) -> Result<Option<FileWatchdogAdmission>, String> {
    let _admission_span = tracing::info_span!("watchdog.durable_admission").entered();
    match FileWatchdogAdmission::from_registry(registry_path.clone(), bootstrap.clone()) {
        Ok(admission) => Ok(Some(admission)),
        Err(error) => {
            let error_detail = truncate_failure_detail(&error.to_string());
            // A transient lock on the first read is not a verdict: enter the
            // poll below without emitting an unproven fence. Any other first
            // failure still needs the fence probe to distinguish awaitable
            // pre-Phase-B pending from fail-closed corruption.
            let mut fence_announced = false;
            match FileWatchdogAdmission::pending_phase_b_fence_readiness(
                registry_path.clone(),
                &bootstrap,
            ) {
                Ok(fence) => {
                    announce_fence_readiness(&fence, &heartbeat)?;
                    fence_announced = true;
                }
                Err(fence_error) => {
                    let fence_detail = truncate_failure_detail(&fence_error.to_string());
                    if fence_poll_disposition(&error_detail, &fence_detail)
                        == FencePollDisposition::FailClosed
                    {
                        return Err(format!(
                            "{error_detail}; pre-Phase-B fence readiness: {fence_detail}"
                        ));
                    }
                    report_transient_registry_lock(&error_detail);
                }
            }
            let mut transient_streak = 0_u32;
            loop {
                if stop_signal.load(Ordering::Acquire) {
                    #[cfg(windows)]
                    set_service_status_stopped();
                    return Ok(None);
                }
                match FileWatchdogAdmission::from_registry(registry_path.clone(), bootstrap.clone())
                {
                    Ok(admission) => return Ok(Some(admission)),
                    Err(retry) => {
                        let retry_detail = truncate_failure_detail(&retry.to_string());
                        match FileWatchdogAdmission::pending_phase_b_fence_readiness(
                            registry_path.clone(),
                            &bootstrap,
                        ) {
                            Ok(fence) => {
                                transient_streak = 0;
                                if !fence_announced {
                                    announce_fence_readiness(&fence, &heartbeat)?;
                                    fence_announced = true;
                                }
                                std::thread::sleep(PENDING_PHASE_B_FENCE_POLL);
                            }
                            Err(fence_retry) => {
                                let fence_retry_detail =
                                    truncate_failure_detail(&fence_retry.to_string());
                                if fence_poll_disposition(&retry_detail, &fence_retry_detail)
                                    == FencePollDisposition::FailClosed
                                {
                                    return Err(retry_detail);
                                }
                                transient_streak = transient_streak.saturating_add(1);
                                report_transient_registry_lock(&retry_detail);
                                std::thread::sleep(transient_lock_backoff(transient_streak));
                            }
                        }
                    }
                }
            }
        }
    }
}
