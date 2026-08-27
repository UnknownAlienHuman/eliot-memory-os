use std::io::{self, BufRead, Write};
use std::sync::OnceLock;

#[cfg(windows)]
use eliot_host::{HostBranchDisposition, HostLivenessTick, HostRuntimeControlOperation};
use eliot_host::{
    HostComposition, HostError, HostLaunchOptions, HostPhaseBRequestQueue, PROTOCOL_VERSION,
    SERVICE_NAME,
};
use serde::{Deserialize, Serialize};

static PROCESS_BOOTSTRAP: OnceLock<Result<HostLaunchOptions, String>> = OnceLock::new();

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
    let _ = PROCESS_BOOTSTRAP.set(parse_process_bootstrap(std::env::args_os().skip(1)));
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

fn parse_process_bootstrap<I, S>(args: I) -> Result<HostLaunchOptions, String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    HostLaunchOptions::parse_system_service(args).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn captured_process_bootstrap() -> Result<HostLaunchOptions, HostError> {
    match PROCESS_BOOTSTRAP.get() {
        Some(Ok(options)) => Ok(options.clone()),
        Some(Err(error)) => Err(HostError::Platform(error.clone())),
        None => Err(HostError::Platform(
            "SCM process bootstrap was not captured before dispatch".to_owned(),
        )),
    }
}

fn open_host(launch_options: HostLaunchOptions) -> Result<HostComposition, HostError> {
    HostComposition::open(launch_options)
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
struct HostStartPendingReporter {
    stop: Option<std::sync::mpsc::Sender<()>>,
    task: Option<std::thread::JoinHandle<()>>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(windows)]
impl HostStartPendingReporter {
    fn start(
        handle: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
    ) -> io::Result<Self> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows_sys::Win32::System::Services::{
            SERVICE_START_PENDING, SERVICE_STATUS, SetServiceStatus,
        };

        let (stop, stopped) = std::sync::mpsc::channel();
        let failed = std::sync::Arc::new(AtomicBool::new(false));
        let task_failed = failed.clone();
        let raw_handle = handle as isize;
        let task = std::thread::Builder::new()
            .name("eliot-host-scm-start-pending".to_owned())
            .spawn(move || {
                let mut checkpoint = 2u32;
                loop {
                    match stopped.recv_timeout(std::time::Duration::from_secs(2)) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let status = SERVICE_STATUS {
                        dwServiceType: 0x0000_0010,
                        dwCurrentState: SERVICE_START_PENDING,
                        dwControlsAccepted: 0,
                        dwWin32ExitCode: 0,
                        dwServiceSpecificExitCode: 0,
                        dwCheckPoint: checkpoint,
                        dwWaitHint: 10_000,
                    };
                    // SAFETY: the service-main thread retains the registered
                    // status handle until this reporter is stopped and joined.
                    if unsafe { SetServiceStatus(raw_handle as _, &raw const status) } == 0 {
                        task_failed.store(true, Ordering::Release);
                        break;
                    }
                    checkpoint = checkpoint.saturating_add(1);
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            task: Some(task),
            failed,
        })
    }

    fn finish(mut self) -> bool {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> bool {
        use std::sync::atomic::Ordering;

        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let joined = self.task.take().is_none_or(|task| task.join().is_ok());
        joined && !self.failed.load(Ordering::Acquire)
    }
}

#[cfg(windows)]
impl Drop for HostStartPendingReporter {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
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
        match unsafe { service_launch_options(service_arg_count, service_arg_vector) }
            .and_then(|()| captured_process_bootstrap())
        {
            Ok(options) => options,
            Err(error) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "eliot-host: invalid SCM launch argv or process bootstrap: {error}"
                );
                status.dwCurrentState = SERVICE_STOPPED;
                status.dwWin32ExitCode = 1;
                // SAFETY: handle is registered and status is initialized.
                unsafe { SetServiceStatus(handle, &raw const status) };
                return;
            }
        };
    if let Err(error) = eliot_host::validate_host_scm_bootstrap(&launch_options) {
        let _ = writeln!(
            io::stderr().lock(),
            "eliot-host: invalid SCM registration: {error}"
        );
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    }
    let reporter = match HostStartPendingReporter::start(handle) {
        Ok(reporter) => reporter,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "eliot-host: SCM start-pending reporter could not start: {error}"
            );
            status.dwCurrentState = SERVICE_STOPPED;
            status.dwWin32ExitCode = 1;
            unsafe { SetServiceStatus(handle, &raw const status) };
            return;
        }
    };
    let host_result = open_host(launch_options);
    let reporter_succeeded = reporter.finish();
    let Ok(mut host) = host_result else {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        // SAFETY: handle is registered and status is initialized.
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    };
    if !reporter_succeeded {
        let _ = writeln!(
            io::stderr().lock(),
            "eliot-host: SCM start-pending progress could not be published"
        );
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        let _ = host.stop();
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    }
    let Ok(credential_control) = host.credential_control() else {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        let _ = host.stop();
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    };
    let phase_b_queue = credential_control.phase_b_queue();
    let Ok(credential_thread) = spawn_credential_control(credential_control) else {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        let _ = host.stop();
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    };
    let Ok(runtime_control) = host.runtime_control() else {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = 1;
        let _ = host.stop();
        unsafe { SetServiceStatus(handle, &raw const status) };
        return;
    };
    let runtime_queue = runtime_control.queue();
    let Ok(runtime_thread) = spawn_runtime_control(runtime_control) else {
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
        process_phase_b_requests(&mut host, &phase_b_queue);
        process_runtime_control_requests(&mut host, &runtime_queue);
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
    let _ = runtime_thread.join();
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
) -> Result<(), HostError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    const MAX_SERVICE_ARG_UNITS: usize = 64 * 1024;

    if service_arg_vector.is_null() || service_arg_count != 1 {
        return Err(HostError::Platform(
            "SCM did not provide the canonical EliotHost ServiceMain argv".to_owned(),
        ));
    }
    let raw = unsafe {
        std::slice::from_raw_parts(service_arg_vector.cast_const(), service_arg_count as usize)
    };
    let pointer = raw[0];
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
    let value = unsafe { std::slice::from_raw_parts(pointer.cast_const(), length) };
    HostLaunchOptions::validate_service_main_argv([OsString::from_wide(value)])
}

#[cfg(windows)]
fn spawn_credential_control(
    control: eliot_host::HostCredentialControl,
) -> Result<std::thread::JoinHandle<()>, HostError> {
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
fn spawn_runtime_control(
    control: eliot_host::HostRuntimeControl,
) -> Result<std::thread::JoinHandle<()>, HostError> {
    std::thread::Builder::new()
        .name("eliot-host-runtime-control".to_owned())
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeControlDispatch {
    Kernel,
    Store,
}

#[cfg(windows)]
fn runtime_control_dispatch(operation: &HostRuntimeControlOperation) -> RuntimeControlDispatch {
    match operation {
        HostRuntimeControlOperation::RestartKernel
        | HostRuntimeControlOperation::ReconcileKernelRestart => RuntimeControlDispatch::Kernel,
        HostRuntimeControlOperation::RecoverStore
        | HostRuntimeControlOperation::ReconcileStoreRecovery => RuntimeControlDispatch::Store,
    }
}

#[cfg(windows)]
fn process_runtime_control_requests(
    host: &mut HostComposition,
    queue: &eliot_host::HostRuntimeControlQueue,
) {
    loop {
        let request = match queue.lock() {
            Ok(mut q) => q.pop_front(),
            Err(_) => None,
        };
        let Some(envelope) = request else { break };
        let response = match runtime_control_dispatch(&envelope.request().operation) {
            RuntimeControlDispatch::Kernel => {
                host.handle_kernel_restart_request(envelope.request())
            }
            RuntimeControlDispatch::Store => host.handle_store_recovery_request(envelope.request()),
        };
        let _ = envelope.respond(response);
    }
}

#[cfg(windows)]
fn process_phase_b_requests(host: &mut HostComposition, queue: &HostPhaseBRequestQueue) {
    loop {
        let request = match queue.lock() {
            Ok(mut queue) => queue.pop_front(),
            Err(_) => None,
        };
        let Some(request) = request else { break };
        let eliot_host::HostPhaseBRequest {
            operation,
            intent,
            credential_receipt,
            final_receipt,
            reply,
        } = request;
        let response = match operation {
            eliot_installation::HostCredentialControlOperation::MaterializePhaseB => {
                host.handle_phase_b_request(&intent, &credential_receipt)
            }
            eliot_installation::HostCredentialControlOperation::ReconcilePhaseB => {
                host.reconcile_phase_b_request(&intent, &credential_receipt)
            }
            eliot_installation::HostCredentialControlOperation::FinalizePhaseB => {
                match final_receipt {
                    Some(receipt) => {
                        host.finalize_phase_b_request(&intent, &credential_receipt, &receipt)
                    }
                    None => eliot_installation::HostCredentialControlResponse::Unknown {
                        pending_ref: eliot_platform::PlatformHandle::new(
                            "phase-b-finalize-missing-receipt",
                        )
                        .unwrap_or_else(|_| unreachable!()),
                    },
                }
            }
            _ => unreachable!("credential control queue admits only Phase-B operations"),
        };
        // The sender is one-shot and belongs to the authenticated worker;
        // dropping it after a failed reply preserves the unknown outcome.
        let _ = reply.send(response);
    }
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
    fn scm_tick_skips_full_operations_until_exact_lease_is_due() -> Result<(), HostError> {
        let mut spy = ScmCallGraphSpy {
            next_tick: HostLivenessTick::HealthyLeasePreserved,
            liveness_ticks: 0,
            full_reconciles: 0,
            file_digest_verifications: 0,
            pipe_exchanges: 0,
            durable_journal_operations: 0,
        };

        assert_eq!(
            run_scm_contour_tick(&mut spy)?,
            ScmContourTickOutcome::LeasePreserved
        );
        assert_eq!(spy.liveness_ticks, 1);
        assert_eq!(spy.full_reconciles, 0);
        assert_eq!(spy.file_digest_verifications, 0);
        assert_eq!(spy.pipe_exchanges, 0);
        assert_eq!(spy.durable_journal_operations, 0);

        spy.next_tick = HostLivenessTick::FullReconcileDue;
        assert_eq!(
            run_scm_contour_tick(&mut spy)?,
            ScmContourTickOutcome::Reconciled(HostBranchDisposition::Healthy)
        );
        assert_eq!(spy.liveness_ticks, 2);
        assert_eq!(spy.full_reconciles, 1);
        assert_eq!(spy.file_digest_verifications, 1);
        assert_eq!(spy.pipe_exchanges, 1);
        assert_eq!(spy.durable_journal_operations, 1);
        Ok(())
    }

    #[test]
    fn production_runtime_control_dispatch_is_operation_exact() {
        assert_eq!(
            runtime_control_dispatch(&HostRuntimeControlOperation::RestartKernel),
            RuntimeControlDispatch::Kernel
        );
        assert_eq!(
            runtime_control_dispatch(&HostRuntimeControlOperation::ReconcileKernelRestart),
            RuntimeControlDispatch::Kernel
        );
        assert_eq!(
            runtime_control_dispatch(&HostRuntimeControlOperation::RecoverStore),
            RuntimeControlDispatch::Store
        );
        assert_eq!(
            runtime_control_dispatch(&HostRuntimeControlOperation::ReconcileStoreRecovery),
            RuntimeControlDispatch::Store
        );
    }
}

#[cfg(test)]
mod process_bootstrap_tests {
    use super::*;
    use std::ffi::OsString;

    fn valid_process_args() -> Vec<OsString> {
        vec![
            OsString::from("--config-descriptor"),
            OsString::from(
                std::env::temp_dir()
                    .join("eliot-authority.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
            OsString::from("--config-descriptor-sha256"),
            OsString::from("a".repeat(64)),
            OsString::from("--installation-id"),
            OsString::from("installation-host-test"),
            OsString::from("--tx-plan-generation"),
            OsString::from("7"),
            OsString::from("--host-state-root"),
            OsString::from(
                std::env::temp_dir()
                    .join("eliot-host-state")
                    .to_string_lossy()
                    .into_owned(),
            ),
            OsString::from("--registration-nonce"),
            OsString::from("b".repeat(64)),
        ]
    }

    #[test]
    fn process_bootstrap_and_start_service_zero_arg_callback_are_distinct() -> Result<(), String> {
        let process_args = valid_process_args();
        let process = parse_process_bootstrap(process_args.clone())?;
        assert!(
            process
                .registration_nonce()
                .is_some_and(|value| value.as_str() == "b".repeat(64))
        );

        // StartServiceW is called with argc=0/argv=NULL, so ServiceMain sees
        // only argv[0], the canonical service name.
        assert!(
            HostLaunchOptions::validate_service_main_argv([OsString::from(SERVICE_NAME)]).is_ok()
        );
        let callback_with_process_args =
            std::iter::once(OsString::from(SERVICE_NAME)).chain(process_args);
        assert!(HostLaunchOptions::validate_service_main_argv(callback_with_process_args).is_err());
        Ok(())
    }
}
