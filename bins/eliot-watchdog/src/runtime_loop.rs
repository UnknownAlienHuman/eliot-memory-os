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
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[cfg(windows)]
use std::time::Instant;

#[cfg(windows)]
use eliot_platform_windows::WindowsPlatform;
use eliot_watchdog::{
    FileWatchdogAdmission, INSTALLATION_REGISTRY_FILE_NAME, IndependentKernelSensor,
    LiveHostObservationSource, WatchdogAdmissionSource, WatchdogComposition, WatchdogConfig,
    inspect_approved_host_registration,
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
    let admission_source = Arc::new(
        FileWatchdogAdmission::from_registry(registry_path, bootstrap)
            .map_err(|error| error.to_string())?,
    );
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
