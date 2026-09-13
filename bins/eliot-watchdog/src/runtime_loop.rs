//! Private runtime-loop wiring for the independent Watchdog process.
//!
//! Architecture (`ELIOT_ARCHITECTURE.md`, `4.5-draft`): A8.1 Watchdog
//! purpose, A8.2 deterministic supervision, A13.2 failure domains,
//! `ARCH-WDG-01`, and `ARCH-WDG-02`.
//! Implementation (`ELIOT_IMPLEMENTATION.md`, `0.29-draft`): I1.2 mandatory
//! runtime processes, I8.1 process and authority, I8.2 independent observation
//! routes, I8.3 deterministic supervision loop, and I14.10 supervision
//! strategies and restart intensity.
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
use eliot_watchdog::{
    FileWatchdogAdmission, INSTALLATION_REGISTRY_FILE_NAME, IndependentKernelSensor,
    LiveHostObservationSource, SERVICE_NAME, WatchdogAdmissionSource, WatchdogComposition,
    WatchdogConfig, WatchdogReadiness, inspect_approved_host_registration,
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
    let bootstrap = scm_launch
        .map(|launch| launch.bootstrap().clone())
        .ok_or_else(|| "SCM bootstrap is required for Runtime contour selection".to_owned())?;
    let host_state_root = bootstrap
        .host_state_root()
        .ok_or_else(|| "SCM bootstrap omitted the installer-approved Host state root".to_owned())?;
    let registry_path = host_state_root.join(INSTALLATION_REGISTRY_FILE_NAME);
    // The lease is issued by the Host/Kernel contour.  There is deliberately
    // no genesis/default lease in this process.  A stale or missing lease
    // starts a gap-only sensor so the Watchdog can remain alive and record a
    // bounded observation; the sensor gains heartbeat authority only after a
    // later, freshly verified lease.  The source is retained by the
    // composition and reloaded before every observation.
    let admission_source = match wait_for_durable_admission(registry_path, bootstrap, &stop_signal)?
    {
        Some(admission) => Arc::new(admission),
        None => return Ok(()),
    };
    let binding = admission_source.runtime_binding();
    inspect_approved_host_registration(&binding).map_err(|error| error.to_string())?;
    let initial_admission = admission_source.reload().ok();
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
    let composition = WatchdogComposition::start_with_shutdown_and_host(
        WatchdogConfig::default(),
        admission_source,
        sensor,
        Arc::new(LiveHostObservationSource::from_binding(&binding)),
        stop_signal,
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
    serde_json::to_writer(&mut io::stdout().lock(), &readiness)
        .map_err(|error| format!("{error:?}"))?;
    writeln!(io::stdout().lock()).map_err(|error| error.to_string())?;
    #[cfg(windows)]
    set_service_status_running();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime
        .block_on(composition.run_until_shutdown())
        .map_err(|error| format!("{error:?}"))?;
    #[cfg(windows)]
    set_service_status_stopped();
    Ok(())
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
    let _ = writeln!(
        io::stderr().lock(),
        "{SERVICE_NAME}: transient installation-registry lock, retrying: {detail}"
    );
}

/// Publishes one proven pre-Phase-B fence readiness: `RunningNoAuthority`
/// with no coverage claimed. Only a successful
/// `pending_phase_b_fence_readiness` probe reaches this; a transient lock is
/// never announced as fenced.
fn announce_fence_readiness(fence: &WatchdogReadiness) -> Result<(), String> {
    serde_json::to_writer(&mut io::stdout().lock(), fence).map_err(|error| format!("{error:?}"))?;
    writeln!(io::stdout().lock()).map_err(|error| error.to_string())?;
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
) -> Result<Option<FileWatchdogAdmission>, String> {
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
                bootstrap.clone(),
            ) {
                Ok(fence) => {
                    announce_fence_readiness(&fence)?;
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
                            bootstrap.clone(),
                        ) {
                            Ok(fence) => {
                                transient_streak = 0;
                                if !fence_announced {
                                    announce_fence_readiness(&fence)?;
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
