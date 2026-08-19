use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_host::{
    HOST_JOURNAL_RELATIVE_PATH, HostComposition, HostError, HostLaunchOptions, PROTOCOL_VERSION,
    SERVICE_NAME,
};
#[cfg(windows)]
use eliot_host::{HostBranchDisposition, HostLivenessTick};
use eliot_platform_windows::protected_program_data_path;
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
    let launch_options = match HostLaunchOptions::parse(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            write_response(&Response::Error {
                error: error.to_string(),
            });
            return false;
        }
    };
    let mut host = match open_host(launch_options) {
        Ok(host) => host,
        Err(error) => {
            write_response(&Response::Error {
                error: error.to_string(),
            });
            return false;
        }
    };
    if !write_response(&Response::Ready {
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
        if !write_response(&response) || terminate || !host.running() {
            break;
        }
    }
    finish_console_shutdown(&mut host, "console input ended")
}

fn open_host(launch_options: HostLaunchOptions) -> Result<HostComposition, HostError> {
    let path = state_path()?;
    HostComposition::open(path, launch_options)
}

fn state_path() -> Result<PathBuf, HostError> {
    protected_program_data_path(HOST_JOURNAL_RELATIVE_PATH)
        .map_err(|error| HostError::Platform(error.to_string()))
}

fn dispatch(host: &mut HostComposition, line: &str) -> (Response, bool) {
    match serde_json::from_str::<Request>(line) {
        Ok(Request::Status) => (
            match host.snapshot() {
                Ok(state) => Response::State {
                    running: host.running(),
                    active_process: state
                        .kernel
                        .as_ref()
                        .and_then(|record| record.process.as_ref())
                        .is_some(),
                    managed_dependencies: state.dependencies.len(),
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

fn write_response(response: &Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, response).is_ok()
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
#[allow(
    clippy::too_many_lines,
    reason = "the SCM callback owns the complete fail-closed service lifecycle"
)]
unsafe extern "system" fn service_main(service_arg_count: u32, service_arg_vector: *mut *mut u16) {
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
        dwServiceType: 0x0000_0010,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 10_000,
    };
    // SAFETY: handle is registered and status is initialized.
    unsafe { SetServiceStatus(handle, &raw const status) };
    let launch_options =
        match unsafe { service_launch_options(service_arg_count, service_arg_vector) } {
            Ok(options) => options,
            Err(error) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "eliot-host: invalid SCM launch argv: {error}"
                );
                status.dwCurrentState = SERVICE_STOPPED;
                status.dwWin32ExitCode = 1;
                // SAFETY: handle is registered and status is initialized.
                unsafe { SetServiceStatus(handle, &raw const status) };
                return;
            }
        };
    let Ok(mut host) = open_host(launch_options) else {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        // SAFETY: handle is registered and status is initialized.
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    };
    let Ok(credential_thread) = spawn_credential_control(&host) else {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        let _ = host.stop();
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    };
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwCheckPoint = 0;
    // SAFETY: handle is registered and status is initialized.
    unsafe { SetServiceStatus(handle, &raw const status) };
    while !STOP_REQUESTED.load(Ordering::Acquire) && host.running() {
        match host.has_durable_branch_fence() {
            Ok(true) => {
                // A degraded branch has fenced the shared authority in the
                // durable state store. Keep the healthy sibling alive, but do
                // not continue claiming or reconciling stale authority.
                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            }
            Ok(false) => {}
            Err(error) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "eliot-host: durable authority-fence inspection failed: {error}"
                );
                STOP_REQUESTED.store(true, Ordering::Release);
                break;
            }
        }
        if host.has_process_contour() {
            match run_scm_contour_tick(&mut host) {
                Ok(outcome) => report_scm_tick(outcome),
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
    STOP_REQUESTED.store(true, Ordering::Release);
    let _ = credential_thread.join();
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
unsafe fn service_launch_options(
    service_arg_count: u32,
    service_arg_vector: *mut *mut u16,
) -> Result<HostLaunchOptions, HostError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    const MAX_SERVICE_ARG_UNITS: usize = 64 * 1024;

    if service_arg_vector.is_null() || service_arg_count != 11 {
        return Err(HostError::Platform(
            "SCM did not provide the canonical nonce-bound service argv".to_owned(),
        ));
    }
    let raw = unsafe {
        std::slice::from_raw_parts(service_arg_vector.cast_const(), service_arg_count as usize)
    };
    let mut launch_args = Vec::with_capacity(raw.len().saturating_sub(1));
    for pointer in raw.iter().skip(1) {
        if pointer.is_null() {
            return Err(HostError::Platform(
                "SCM provided a null service argv value".to_owned(),
            ));
        }
        let mut length = 0usize;
        while length < MAX_SERVICE_ARG_UNITS && unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        if length == MAX_SERVICE_ARG_UNITS {
            return Err(HostError::Platform("SCM argv value is too long".to_owned()));
        }
        let value = unsafe { std::slice::from_raw_parts(*pointer, length) };
        launch_args.push(OsString::from_wide(value));
    }
    HostLaunchOptions::parse_system_service(launch_args)
}

#[cfg(windows)]
fn spawn_credential_control(
    host: &HostComposition,
) -> Result<std::thread::JoinHandle<()>, HostError> {
    let journal = state_path()?;
    let host_state_root = journal
        .parent()
        .ok_or_else(|| HostError::Platform("Host journal has no state root".to_owned()))?
        .to_path_buf();
    let control = host.credential_control(host_state_root)?;
    std::thread::Builder::new()
        .name("eliot-host-credential-control".to_owned())
        .spawn(move || {
            use std::sync::atomic::Ordering;
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            else {
                STOP_REQUESTED.store(true, Ordering::Release);
                return;
            };
            while !STOP_REQUESTED.load(Ordering::Acquire) {
                if runtime
                    .block_on(control.serve_one(std::time::Duration::from_millis(500)))
                    .is_err()
                {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        })
        .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
trait ScmContourHost {
    fn liveness_tick(&mut self) -> Result<HostLivenessTick, HostError>;
    fn full_reconcile(&mut self) -> Result<HostBranchDisposition, HostError>;
}

#[cfg(windows)]
impl ScmContourHost for HostComposition {
    fn liveness_tick(&mut self) -> Result<HostLivenessTick, HostError> {
        HostComposition::liveness_tick(self)
    }

    fn full_reconcile(&mut self) -> Result<HostBranchDisposition, HostError> {
        self.reconcile_approved_contour()
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScmContourTickOutcome {
    LeasePreserved,
    ReadinessRetryPending,
    Reconciled(HostBranchDisposition),
}

#[cfg(windows)]
fn run_scm_contour_tick(
    host: &mut impl ScmContourHost,
) -> Result<ScmContourTickOutcome, HostError> {
    match host.liveness_tick()? {
        HostLivenessTick::HealthyLeasePreserved => Ok(ScmContourTickOutcome::LeasePreserved),
        HostLivenessTick::ReadinessRetryPending => Ok(ScmContourTickOutcome::ReadinessRetryPending),
        HostLivenessTick::FullReconcileDue => {
            host.full_reconcile().map(ScmContourTickOutcome::Reconciled)
        }
    }
}

#[cfg(windows)]
fn report_scm_tick(outcome: ScmContourTickOutcome) {
    let disposition = match outcome {
        ScmContourTickOutcome::LeasePreserved
        | ScmContourTickOutcome::Reconciled(HostBranchDisposition::Healthy) => return,
        ScmContourTickOutcome::ReadinessRetryPending => HostBranchDisposition::ReadinessDegraded,
        ScmContourTickOutcome::Reconciled(disposition) => disposition,
    };
    let _ = writeln!(
        io::stderr().lock(),
        "eliot-host: independent contour disposition: {disposition:?}"
    );
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    struct ScmCallGraphSpy {
        next_tick: HostLivenessTick,
        liveness_ticks: usize,
        full_reconciles: usize,
        file_digest_verifications: usize,
        pipe_exchanges: usize,
        durable_journal_operations: usize,
    }

    impl ScmContourHost for ScmCallGraphSpy {
        fn liveness_tick(&mut self) -> Result<HostLivenessTick, HostError> {
            self.liveness_ticks += 1;
            Ok(self.next_tick)
        }

        fn full_reconcile(&mut self) -> Result<HostBranchDisposition, HostError> {
            self.full_reconciles += 1;
            self.file_digest_verifications += 1;
            self.pipe_exchanges += 1;
            self.durable_journal_operations += 1;
            Ok(HostBranchDisposition::Healthy)
        }
    }

    #[test]
    fn scm_tick_skips_full_operations_until_exact_lease_is_due() {
        let mut spy = ScmCallGraphSpy {
            next_tick: HostLivenessTick::HealthyLeasePreserved,
            liveness_ticks: 0,
            full_reconciles: 0,
            file_digest_verifications: 0,
            pipe_exchanges: 0,
            durable_journal_operations: 0,
        };

        assert_eq!(
            run_scm_contour_tick(&mut spy).unwrap(),
            ScmContourTickOutcome::LeasePreserved
        );
        assert_eq!(spy.liveness_ticks, 1);
        assert_eq!(spy.full_reconciles, 0);
        assert_eq!(spy.file_digest_verifications, 0);
        assert_eq!(spy.pipe_exchanges, 0);
        assert_eq!(spy.durable_journal_operations, 0);

        spy.next_tick = HostLivenessTick::FullReconcileDue;
        assert_eq!(
            run_scm_contour_tick(&mut spy).unwrap(),
            ScmContourTickOutcome::Reconciled(HostBranchDisposition::Healthy)
        );
        assert_eq!(spy.liveness_ticks, 2);
        assert_eq!(spy.full_reconciles, 1);
        assert_eq!(spy.file_digest_verifications, 1);
        assert_eq!(spy.pipe_exchanges, 1);
        assert_eq!(spy.durable_journal_operations, 1);
    }
}
