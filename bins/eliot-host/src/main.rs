use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[cfg(windows)]
use eliot_host::HostBranchDisposition;
use eliot_host::{HostComposition, HostError, PROTOCOL_VERSION, SERVICE_NAME};
use eliot_platform::PlatformHandle;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Stop,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
    },
    State {
        running: bool,
        active_process: bool,
        managed_dependencies: usize,
    },
    Stopped,
    Error {
        error: String,
    },
}

fn main() {
    #[cfg(windows)]
    match run_as_scm_service() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "eliot-host: StartServiceCtrlDispatcherW failed with Win32 error {error} (0x{error:08X})"
            );
            std::process::exit(1);
        }
    }
    if !run_console() {
        std::process::exit(1);
    }
}

fn run_console() -> bool {
    let mut host = match open_host() {
        Ok(host) => host,
        Err(error) => {
            write_response(Response::Error {
                error: error.to_string(),
            });
            return false;
        }
    };
    if !write_response(Response::Ready {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
    }) {
        return finish_console_shutdown(&mut host, "ready response failed");
    }
    for line in io::stdin().lock().lines() {
        let (response, terminate) = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut host, &line),
            Err(error) => (
                Response::Error {
                    error: error.to_string(),
                },
                true,
            ),
        };
        if !write_response(response) || terminate || !host.running() {
            break;
        }
    }
    finish_console_shutdown(&mut host, "console input ended")
}

fn open_host() -> Result<HostComposition, HostError> {
    let installation_value =
        std::env::var("ELIOT_INSTALLATION_ID").map_err(|_| HostError::MissingInstallation)?;
    let installation = PlatformHandle::new(installation_value)
        .map_err(|error| HostError::Platform(format!("invalid ELIOT_INSTALLATION_ID: {error}")))?;
    let path = state_path()?;
    HostComposition::open(path, installation)
}

fn state_path() -> Result<PathBuf, HostError> {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .ok_or_else(|| HostError::Platform("ProgramData is not configured".to_owned()))?;
    if !program_data.is_absolute() {
        return Err(HostError::Platform(
            "ProgramData must be an absolute path".to_owned(),
        ));
    }
    Ok(program_data
        .join("Eliot")
        .join("host")
        .join("host-state.redb"))
}

fn dispatch(host: &mut HostComposition, line: &str) -> (Response, bool) {
    match serde_json::from_str::<Request>(line) {
        Ok(Request::Status) => (
            match host.snapshot() {
                Ok(state) => Response::State {
                    running: host.running(),
                    active_process: state.active_process.is_some(),
                    managed_dependencies: state.managed_dependencies.len(),
                },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            false,
        ),
        Ok(Request::Stop) => (
            match host.stop() {
                Ok(()) => Response::Stopped,
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            true,
        ),
        Err(error) => (
            Response::Error {
                error: error.to_string(),
            },
            false,
        ),
    }
}

fn finish_console_shutdown(host: &mut HostComposition, cause: &str) -> bool {
    if !host.running() {
        return !host.shutdown_failed();
    }
    match host.stop() {
        Ok(()) | Err(HostError::Stopped) => true,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "eliot-host: durable shutdown failed after {cause}: {error}"
            );
            false
        }
    }
}

fn write_response(response: Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

#[cfg(windows)]
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table and UTF-16 name remain live until SCM returns.
    let connected = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0;
    if connected {
        Ok(true)
    } else {
        let error = unsafe { GetLastError() };
        if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            // The documented interactive-console case is the only condition
            // under which the process may enter its stdin/stdout fallback.
            Ok(false)
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING,
        SERVICE_STOPPED, SetServiceStatus,
    };

    let name = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: callback and name are valid for the service lifetime.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(service_control), std::ptr::null_mut())
    };
    if handle.is_null() {
        return;
    }
    let mut status = SERVICE_STATUS {
        dwServiceType: 0x00000010,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 10_000,
    };
    // SAFETY: handle is registered and status is initialized.
    unsafe { SetServiceStatus(handle, &raw const status) };
    let mut host = match open_host() {
        Ok(host) => host,
        Err(_) => {
            status.dwCurrentState = SERVICE_STOPPED;
            status.dwWin32ExitCode = 1;
            // SAFETY: handle is registered and status is initialized.
            unsafe { SetServiceStatus(handle, &raw const status) };
            return;
        }
    };
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwCheckPoint = 0;
    // SAFETY: handle is registered and status is initialized.
    unsafe { SetServiceStatus(handle, &raw const status) };
    while !STOP_REQUESTED.load(Ordering::Acquire) && host.running() {
        if host.has_process_contour() {
            match host.reconcile_approved_contour() {
                Ok(HostBranchDisposition::Healthy) => {}
                Ok(disposition) => {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "eliot-host: independent contour disposition: {disposition:?}"
                    );
                }
                Err(error) => {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "eliot-host: shared contour admission failed: {error}"
                    );
                    STOP_REQUESTED.store(true, Ordering::Release);
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    status.dwCurrentState = SERVICE_STOP_PENDING;
    status.dwControlsAccepted = 0;
    status.dwCheckPoint = 1;
    status.dwWaitHint = 10_000;
    // SAFETY: handle is registered and status is initialized.
    unsafe { SetServiceStatus(handle, &raw const status) };
    let stop_result = host.stop();
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    if let Err(error) = stop_result {
        let _ = writeln!(
            io::stderr().lock(),
            "eliot-host: durable SCM shutdown failed; recovery required: {error}"
        );
        // SCM receives a stopped state with a non-zero service-specific code,
        // which is a failed/recovery outcome rather than a clean stop.
        status.dwWin32ExitCode = 1;
        status.dwServiceSpecificExitCode = 1;
    }
    // SAFETY: handle is registered and status is initialized.
    unsafe { SetServiceStatus(handle, &raw const status) };
}

#[cfg(windows)]
unsafe extern "system" fn service_control(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Services::{
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP,
    };
    if matches!(
        control,
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN
    ) {
        // The callback and service main share SCM-owned process lifetime; the
        // stop flag only closes admission and lets the main loop reap branches.
        STOP_REQUESTED.store(true, Ordering::Release);
    }
    if control == SERVICE_CONTROL_INTERROGATE {
        return 0;
    }
    0
}
