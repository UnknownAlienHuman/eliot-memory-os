use std::io::{self, Write};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(windows)]
use std::time::{Duration, Instant};

mod runtime_loop;

#[cfg(windows)]
mod watchdog_service_status;

use runtime_loop::run_watchdog;

use eliot_platform_windows::ServiceBootstrapArguments;
#[cfg(windows)]
use eliot_platform_windows::{ServiceRegistrationRequest, WindowsPlatform};
use eliot_watchdog::{
    SERVICE_NAME, WatchdogRuntimeReadback, WatchdogSelfAdmissionProbe, WatchdogSelfAdmissionStatus,
    project_service_runtime_inspection,
};
#[cfg(windows)]
use watchdog_service_status::{
    SERVICE_STATUS_HANDLE, publish_service_status, set_service_status_running,
    set_service_status_stopped,
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

#[cfg(windows)]
struct WindowsWatchdogSelfAdmissionProbe<'a> {
    platform: WindowsPlatform,
    request: &'a ServiceRegistrationRequest,
    started_at: Instant,
}

#[cfg(windows)]
impl WatchdogSelfAdmissionProbe for WindowsWatchdogSelfAdmissionProbe<'_> {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn current_process_identity(&mut self) -> Option<eliot_platform_windows::ProcessIdentity> {
        self.platform.process_identity(std::process::id()).ok()
    }

    fn inspect(&mut self) -> WatchdogRuntimeReadback {
        project_service_runtime_inspection(
            self.platform
                .inspect_service_registration_runtime(self.request),
        )
    }

    fn sleep_ms(&mut self, milliseconds: u32) {
        std::thread::sleep(Duration::from_millis(u64::from(milliseconds)));
    }
}

#[cfg(windows)]
struct ScmWatchdogSelfAdmissionStatus;

#[cfg(windows)]
impl WatchdogSelfAdmissionStatus for ScmWatchdogSelfAdmissionStatus {
    fn report_start_pending(&mut self, checkpoint: u32, wait_hint_ms: u32) {
        let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
        if raw != 0 {
            publish_service_status(
                raw as _,
                windows_sys::Win32::System::Services::SERVICE_START_PENDING,
                0,
                0,
                checkpoint,
                wait_hint_ms,
            );
        }
    }
}

#[cfg(windows)]
static SERVICE_STOP_REQUESTED: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_has_no_non_scm_root_fallback() {
        assert_eq!(
            run_watchdog(Arc::new(AtomicBool::new(true)), None),
            Err("SCM bootstrap is required for Runtime contour selection".to_owned())
        );
    }
}
