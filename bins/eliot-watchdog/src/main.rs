use std::io::{self, Write};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use eliot_platform_windows::ServiceBootstrapArguments;
use eliot_watchdog::{
    FileWatchdogAdmission, INSTALLATION_REGISTRY_FILE_NAME, IndependentKernelSensor,
    LiveHostObservationSource, SERVICE_NAME, SUPERVISION_LEASE_FILE_NAME,
    WATCHDOG_ADMISSION_FILE_NAME, WatchdogAdmissionSource, WatchdogComposition, WatchdogConfig,
    inspect_approved_host_registration,
};

static PROCESS_BOOTSTRAP: OnceLock<Result<Option<ServiceBootstrapArguments>, String>> =
    OnceLock::new();

fn main() {
    let _ = PROCESS_BOOTSTRAP.set(parse_process_bootstrap());
    #[cfg(windows)]
    match run_as_scm_service() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{SERVICE_NAME}: StartServiceCtrlDispatcherW failed with Win32 error {error} (0x{error:08X})"
            );
            std::process::exit(1);
        }
    }
    if let Err(error) = run_watchdog(Arc::new(AtomicBool::new(false)), None) {
        let _ = writeln!(io::stderr().lock(), "{SERVICE_NAME}: {error}");
        std::process::exit(1);
    }
}

fn run_watchdog(
    stop_signal: Arc<AtomicBool>,
    scm_launch: Option<&eliot_watchdog::ValidatedWatchdogScmLaunch>,
) -> Result<(), String> {
    let bootstrap = scm_launch
        .map(|launch| launch.bootstrap().clone())
        .ok_or_else(|| "SCM bootstrap is required for Runtime contour selection".to_owned())?;
    let host_state_root = bootstrap
        .host_state_root()
        .ok_or_else(|| "SCM bootstrap omitted the installer-approved Host state root".to_owned())?;
    let lease_path = host_state_root.join(SUPERVISION_LEASE_FILE_NAME);
    let admission_config_path = host_state_root.join(WATCHDOG_ADMISSION_FILE_NAME);
    let registry_path = host_state_root.join(INSTALLATION_REGISTRY_FILE_NAME);
    // The lease is issued by the Host/Kernel contour.  There is deliberately
    // no genesis/default lease in this process.  A stale or missing lease
    // starts a gap-only sensor so the Watchdog can remain alive and record a
    // bounded observation; the sensor gains heartbeat authority only after a
    // later, freshly verified lease.  The source is retained by the
    // composition and reloaded before every observation.
    let admission_source = Arc::new(
        FileWatchdogAdmission::from_registry(
            lease_path,
            admission_config_path,
            registry_path,
            bootstrap,
        )
        .map_err(|error| error.to_string())?,
    );
    let binding = admission_source.runtime_binding();
    inspect_approved_host_registration(binding.approved_host_image())
        .map_err(|error| error.to_string())?;
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
        Arc::new(LiveHostObservationSource::try_new(
            binding.approved_host_image().to_owned(),
        )),
        stop_signal,
    )
    .map_err(|error| error.to_string())?;
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

#[cfg(windows)]
static SERVICE_STOP_REQUESTED: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

#[cfg(windows)]
static SERVICE_STATUS_HANDLE: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

#[cfg(windows)]
fn run_as_scm_service() -> Result<bool, u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, GetLastError};
    use windows_sys::Win32::System::Services::{SERVICE_TABLE_ENTRYW, StartServiceCtrlDispatcherW};
    let name = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr().cast_mut(),
            lpServiceProc: Some(watchdog_service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: SCM borrows the table only until the dispatcher returns.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
        Ok(true)
    } else {
        let error = unsafe { GetLastError() };
        if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn watchdog_service_main(
    service_arg_count: u32,
    service_arg_vector: *mut *mut u16,
) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_START_PENDING, SERVICE_STOPPED,
    };
    let name = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: the callback and name remain valid for the service lifetime.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(service_control), std::ptr::null_mut())
    };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        publish_service_status(handle, SERVICE_STOPPED, 0, error, 0, 0);
        return;
    }
    SERVICE_STATUS_HANDLE.store(handle as isize, Ordering::Release);
    publish_service_status(handle, SERVICE_START_PENDING, 0, 0, 1, 10_000);
    let validated_launch =
        match unsafe { service_launch_options(service_arg_count, service_arg_vector) }
            .and_then(|()| validate_registered_process_bootstrap())
        {
            Ok(launch) => launch,
            Err(error) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "{SERVICE_NAME}: invalid SCM launch argv or registration: {error}"
                );
                publish_service_status(handle, SERVICE_STOPPED, 0, 1, 0, 0);
                return;
            }
        };
    let stop_signal = Arc::new(AtomicBool::new(false));
    let _ = SERVICE_STOP_REQUESTED.set(stop_signal.clone());
    if let Err(error) = run_watchdog(stop_signal, Some(&validated_launch)) {
        let _ = writeln!(io::stderr().lock(), "{SERVICE_NAME}: {error}");
        publish_service_status(handle, SERVICE_STOPPED, 0, 1, 0, 0);
    }
}

fn parse_process_bootstrap() -> Result<Option<ServiceBootstrapArguments>, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Ok(None);
    }
    eliot_watchdog::parse_watchdog_process_argv(args)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn validate_registered_process_bootstrap()
-> Result<eliot_watchdog::ValidatedWatchdogScmLaunch, eliot_watchdog::WatchdogScmLaunchError> {
    match PROCESS_BOOTSTRAP.get() {
        Some(Ok(Some(bootstrap))) => eliot_watchdog::validate_watchdog_scm_bootstrap(bootstrap),
        Some(Ok(None)) => Err(eliot_watchdog::WatchdogScmLaunchError::InvalidArgv(
            "SCM process command line omitted the canonical bootstrap".to_owned(),
        )),
        Some(Err(error)) => Err(eliot_watchdog::WatchdogScmLaunchError::InvalidArgv(
            error.clone(),
        )),
        None => Err(eliot_watchdog::WatchdogScmLaunchError::InvalidArgv(
            "SCM process bootstrap was not captured before dispatch".to_owned(),
        )),
    }
}

#[cfg(windows)]
unsafe fn service_launch_options(
    service_arg_count: u32,
    service_arg_vector: *mut *mut u16,
) -> Result<(), eliot_watchdog::WatchdogScmLaunchError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    const MAX_SERVICE_ARG_UNITS: usize = 64 * 1024;

    if service_arg_vector.is_null() || service_arg_count != 1 {
        return Err(eliot_watchdog::WatchdogScmLaunchError::InvalidArgv(
            "ServiceMain argv must contain only the canonical service name".to_owned(),
        ));
    }
    let raw = unsafe {
        std::slice::from_raw_parts(service_arg_vector.cast_const(), service_arg_count as usize)
    };
    let pointer = raw[0];
    if pointer.is_null() {
        return Err(eliot_watchdog::WatchdogScmLaunchError::InvalidArgv(
            "SCM provided a null service argv value".to_owned(),
        ));
    }
    let mut length = 0usize;
    while length < MAX_SERVICE_ARG_UNITS && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == MAX_SERVICE_ARG_UNITS {
        return Err(eliot_watchdog::WatchdogScmLaunchError::InvalidArgv(
            "SCM argv value is too long".to_owned(),
        ));
    }
    let value = unsafe { std::slice::from_raw_parts(pointer.cast_const(), length) };
    eliot_watchdog::validate_watchdog_service_main_argv([OsString::from_wide(value)])
}

#[cfg(windows)]
fn set_service_status_running() {
    let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
    if raw != 0 {
        publish_service_status(
            raw as _,
            windows_sys::Win32::System::Services::SERVICE_RUNNING,
            windows_sys::Win32::System::Services::SERVICE_ACCEPT_STOP
                | windows_sys::Win32::System::Services::SERVICE_ACCEPT_SHUTDOWN
                | windows_sys::Win32::System::Services::SERVICE_ACCEPT_PRESHUTDOWN,
            0,
            0,
            0,
        );
    }
}

#[cfg(windows)]
fn set_service_status_stopped() {
    let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
    if raw != 0 {
        publish_service_status(
            raw as _,
            windows_sys::Win32::System::Services::SERVICE_STOPPED,
            0,
            0,
            0,
            0,
        );
    }
}

#[cfg(windows)]
fn publish_service_status(
    handle: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
    state: u32,
    controls: u32,
    error: u32,
    checkpoint: u32,
    wait_hint: u32,
) {
    use windows_sys::Win32::System::Services::{SERVICE_STATUS, SetServiceStatus};
    let status = SERVICE_STATUS {
        dwServiceType: 0x0000_0010,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    // SAFETY: the handle is either SCM-provided or zero-checked by callers.
    unsafe { SetServiceStatus(handle, &raw const status) };
}

#[cfg(windows)]
unsafe extern "system" fn service_control(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    use windows_sys::Win32::System::Services::{
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_STOP_PENDING,
    };
    if matches!(
        control,
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN
    ) {
        if let Some(stop_signal) = SERVICE_STOP_REQUESTED.get() {
            stop_signal.store(true, Ordering::Release);
        }
        let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
        if raw != 0 {
            publish_service_status(raw as _, SERVICE_STOP_PENDING, 0, 0, 1, 10_000);
        }
    }
    if control == SERVICE_CONTROL_INTERROGATE {
        return 0;
    }
    0
}
