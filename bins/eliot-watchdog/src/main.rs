use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use eliot_watchdog::{
    IndependentKernelSensor, SERVICE_NAME, WatchdogComposition, WatchdogConfig,
    load_supervision_lease,
};

fn main() {
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
    if let Err(error) = run_watchdog(Arc::new(AtomicBool::new(false))) {
        let _ = writeln!(io::stderr().lock(), "{SERVICE_NAME}: {error}");
        std::process::exit(1);
    }
}

fn run_watchdog(stop_signal: Arc<AtomicBool>) -> Result<(), String> {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .ok_or_else(|| "ProgramData is not configured".to_owned())?;
    if !program_data.is_absolute() {
        return Err("ProgramData must be an absolute path".to_owned());
    }
    let lease_path = program_data
        .join("Eliot")
        .join("host")
        .join("supervision-lease.json");
    let admission_config_path = program_data
        .join("Eliot")
        .join("host")
        .join("watchdog-admission.json");
    let registry_path = program_data
        .join("Eliot")
        .join("host")
        .join("installation-registry.redb");
    // The lease is issued by the Host/Kernel contour.  There is deliberately
    // no genesis/default lease in this process: stale or missing durable bytes
    // fail closed before the watchdog can advertise readiness.
    let admission = load_supervision_lease(&lease_path, &admission_config_path, &registry_path)
        .map_err(|error| error.to_string())?;
    let sensor = Arc::new(
        IndependentKernelSensor::open_program_data(
            PathBuf::from("Eliot")
                .join("watchdog")
                .join("protected-spool.jsonl"),
            admission.watchdog_epoch().value(),
        )
        .map_err(|error| error.to_string())?,
    );
    let composition = WatchdogComposition::start_with_shutdown(
        WatchdogConfig::default(),
        admission.lease().clone(),
        sensor,
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
unsafe extern "system" fn watchdog_service_main(_argc: u32, _argv: *mut *mut u16) {
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
    let stop_signal = Arc::new(AtomicBool::new(false));
    let _ = SERVICE_STOP_REQUESTED.set(stop_signal.clone());
    if let Err(error) = run_watchdog(stop_signal) {
        let _ = writeln!(io::stderr().lock(), "{SERVICE_NAME}: {error}");
        publish_service_status(handle, SERVICE_STOPPED, 0, 1, 0, 0);
    }
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
