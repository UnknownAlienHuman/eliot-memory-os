use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_host::{HostComposition, HostError, PROTOCOL_VERSION, SERVICE_NAME, initial_epoch};
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
    if run_as_scm_service() {
        return;
    }
    run_console();
}

fn run_console() {
    let mut host = match open_host() {
        Ok(host) => host,
        Err(error) => {
            write_response(Response::Error {
                error: error.to_string(),
            });
            return;
        }
    };
    if !write_response(Response::Ready {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
    }) {
        return;
    }
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut host, &line),
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        };
        if !write_response(response) || !host.running() {
            break;
        }
    }
}

fn open_host() -> Result<HostComposition, HostError> {
    let installation = std::env::var("ELIOT_INSTALLATION_ID")
        .ok()
        .and_then(|value| PlatformHandle::new(value).ok())
        .unwrap_or_else(|| handle("system"));
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    HostComposition::open(path, initial_epoch(installation))
}

fn state_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Eliot")
        .join("host")
        .join("host-state.redb")
}

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn dispatch(host: &mut HostComposition, line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(Request::Status) => match host.snapshot() {
            Ok(state) => Response::State {
                running: host.running(),
                active_process: state.active_process.is_some(),
                managed_dependencies: state.managed_dependencies.len(),
            },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Ok(Request::Stop) => match host.stop() {
            Ok(()) => Response::Stopped,
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Err(error) => Response::Error {
            error: error.to_string(),
        },
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
fn run_as_scm_service() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
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
        true
    } else {
        // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT means an interactive launch;
        // every other error is still reported through the normal console path.
        let _ = unsafe { GetLastError() };
        false
    }
}

#[cfg(windows)]
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED, SetServiceStatus,
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
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let _ = host.stop();
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
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
