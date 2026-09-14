#![forbid(unsafe_code)]

mod host_console_protocol;

use std::io::{self, BufRead, Write};
use std::sync::OnceLock;

#[cfg(windows)]
use eliot_host::{HostBranchDisposition, HostLivenessTick, HostRuntimeControlOperation};
use eliot_host::{
    HostComposition, HostError, HostLaunchOptions, HostPhaseBRequestQueue, PROTOCOL_VERSION,
    SERVICE_NAME,
};
use host_console_protocol::{Request, Response, write_response};

static PROCESS_BOOTSTRAP: OnceLock<Result<HostLaunchOptions, String>> = OnceLock::new();

/// Win32 `ERROR_SERVICE_SPECIFIC_ERROR`: the `dwWin32ExitCode` reported for
/// every typed Host start failure. The per-class detail travels in
/// `dwServiceSpecificExitCode` ([`HostStopCode::specific`]), so `sc queryex`
/// names the failure class instead of collapsing every start failure to
/// `exit 1 / specific 0`.
const HOST_WIN32_SERVICE_SPECIFIC_ERROR: u32 = 1066;

/// Process exit code for console start failures. A console run has no
/// `SERVICE_STATUS_HANDLE`, so the 1066 marker is carried as the process exit
/// code on Windows while the typed class is carried in stderr and the capsule.
const HOST_CONSOLE_PROCESS_EXIT_CODE: i32 = 1066;

/// Single bounded start-failure capsule file inside the Host state root.
const HOST_START_FAILURE_CAPSULE_FILE_NAME: &str = "eliot-host-start-failure.json";
/// Hard ceiling for the serialized capsule; the builder truncates fields first
/// and then trims at a character boundary so output never exceeds this.
const HOST_START_FAILURE_CAPSULE_MAX_BYTES: usize = 4096;
/// Per-field ceiling for the free-text failure detail.
const HOST_START_FAILURE_DETAIL_MAX_CHARS: usize = 512;
/// Per-field ceiling for the installation identity echo.
const HOST_START_FAILURE_IDENTITY_MAX_CHARS: usize = 128;

/// Typed Host service-start failure classes.
///
/// Each variant documents the exact `service_main` site it classifies and owns
/// one stable `dwServiceSpecificExitCode` (the discriminant). Discriminants
/// are never reused or reordered: operators and installers key runbooks off
/// them. Only the numeric projection changes; every site keeps its historical
/// control flow, stderr text, and shutdown behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostStopCode {
    /// `RegisterServiceCtrlHandlerExW` returned NULL. Previously a silent
    /// return; now also leaves stderr and a capsule.
    ScmRegisterNull = 1,
    /// `ServiceMain` argv shape or the captured process bootstrap is invalid.
    InvalidScmArgvOrBootstrap = 2,
    /// The read-only SCM registration inspection is not an exact match.
    InvalidRegistration = 3,
    /// The `START_PENDING` progress reporter thread could not start.
    ReporterStartFailed = 4,
    /// `HostComposition::open` failed.
    OpenHostFailed = 5,
    /// The `START_PENDING` reporter did not sustain progress publication.
    ReporterProgressFailed = 6,
    /// `HostComposition::credential_control` failed.
    CredentialControlFailed = 7,
    /// The credential-control thread could not be spawned.
    SpawnCredentialFailed = 8,
    /// `HostComposition::runtime_control` failed.
    RuntimeControlFailed = 9,
    /// The runtime-control thread could not be spawned.
    SpawnRuntimeFailed = 10,
    /// Durable SCM shutdown (`host.stop()`) failed; recovery is required.
    DurableShutdownFailed = 11,
    /// `StartServiceCtrlDispatcherW` failed in the console entry path.
    DispatcherFailed = 12,
    /// The stdin/stdout console protocol failed before durable shutdown.
    ConsoleFailed = 13,
}

impl HostStopCode {
    /// Stable per-class `dwServiceSpecificExitCode` (`sc queryex` names this).
    #[must_use]
    const fn specific(self) -> u32 {
        self as u32
    }

    /// Stable machine-readable class name recorded in the capsule.
    #[must_use]
    const fn failure_class(self) -> &'static str {
        match self {
            Self::ScmRegisterNull => "scm_register_null",
            Self::InvalidScmArgvOrBootstrap => "invalid_scm_argv_or_bootstrap",
            Self::InvalidRegistration => "invalid_scm_registration",
            Self::ReporterStartFailed => "reporter_start_failed",
            Self::OpenHostFailed => "open_host_failed",
            Self::ReporterProgressFailed => "reporter_progress_failed",
            Self::CredentialControlFailed => "credential_control_failed",
            Self::SpawnCredentialFailed => "spawn_credential_failed",
            Self::RuntimeControlFailed => "runtime_control_failed",
            Self::SpawnRuntimeFailed => "spawn_runtime_failed",
            Self::DurableShutdownFailed => "durable_shutdown_failed",
            Self::DispatcherFailed => "dispatcher_failed",
            Self::ConsoleFailed => "console_failed",
        }
    }
}

/// Secret-free kind name for a [`HostError`], recorded in the capsule.
///
/// Only the variant discriminant is recorded, never the payload, so paths,
/// digests, and evidence handles inside the error cannot leak through this
/// field; the truncated `detail` still carries the same text stderr already
/// prints.
fn host_error_variant(error: &HostError) -> &'static str {
    match error {
        HostError::State(_) => "state",
        HostError::Journal(_) => "journal",
        HostError::Installation(_) => "installation",
        HostError::Platform(_) => "platform",
        HostError::Stopped => "stopped",
        HostError::MissingInstallation => "missing_installation",
        HostError::ProcessContour(_) => "process_contour",
        HostError::StoreNotLive { .. } => "store_not_live",
        HostError::RecoveryRequired(_) => "recovery_required",
        #[cfg(windows)]
        HostError::StoreRecoveryRequired(_) => "store_recovery_required",
        HostError::OwnerLeaseHeld => "owner_lease_held",
        HostError::OwnerLeaseRecovery(_) => "owner_lease_recovery",
    }
}

/// Builds the bounded secret-free start-failure capsule JSON.
///
/// The record carries the failure class, the error kind, both exit codes, and
/// the non-secret launch identities (installation id, plan generation) when
/// known. The registration nonce is never read and therefore can never be
/// persisted; the free-text detail is truncated to
/// [`HOST_START_FAILURE_DETAIL_MAX_CHARS`] characters and the whole record is
/// capped at [`HOST_START_FAILURE_CAPSULE_MAX_BYTES`] bytes.
#[must_use]
fn build_host_start_failure_capsule(
    code: HostStopCode,
    error_variant: &str,
    detail: &str,
    installation_id: Option<&str>,
    plan_generation: Option<u64>,
) -> String {
    let detail = truncate_host_chars(detail, HOST_START_FAILURE_DETAIL_MAX_CHARS);
    let installation = installation_id
        .map(|value| truncate_host_chars(value, HOST_START_FAILURE_IDENTITY_MAX_CHARS));
    let value = serde_json::json!({
        "record_type": "host_start_failure",
        "service": SERVICE_NAME,
        "failure_class": code.failure_class(),
        "error_variant": error_variant,
        "win32_exit_code": HOST_WIN32_SERVICE_SPECIFIC_ERROR,
        "service_specific_exit_code": code.specific(),
        "installation_id": installation.as_deref(),
        "tx_plan_generation": plan_generation,
        "detail": detail,
    });
    let mut text = serde_json::to_string(&value)
        .unwrap_or_else(|_| String::from("{\"record_type\":\"host_start_failure\"}"));
    while text.len() > HOST_START_FAILURE_CAPSULE_MAX_BYTES {
        text.pop();
    }
    text
}

/// Persists one bounded secret-free start-failure capsule inside the Host
/// state root (the existing Host-owned root from the launch options), or the
/// process temp directory when no valid launch options exist.
///
/// The write is best-effort and never fails the service path: SCM status plus
/// stderr remain the primary signals. This is a terminal receipt projection,
/// not a logging subsystem: one file, one record, bounded bytes.
fn persist_host_start_failure(
    code: HostStopCode,
    error_variant: &str,
    detail: &str,
    launch_options: Option<&HostLaunchOptions>,
) {
    let (installation_id, plan_generation, root) = match launch_options {
        Some(options) => (
            Some(options.installation().as_str()),
            Some(options.transaction_plan_generation()),
            options.host_state_root().to_path_buf(),
        ),
        None => (None, None, std::env::temp_dir()),
    };
    let capsule = build_host_start_failure_capsule(
        code,
        error_variant,
        detail,
        installation_id,
        plan_generation,
    );
    let _ = std::fs::write(root.join(HOST_START_FAILURE_CAPSULE_FILE_NAME), capsule);
}

fn truncate_host_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() > max_chars {
        value.chars().take(max_chars).collect()
    } else {
        value.to_owned()
    }
}

/// Cloned process bootstrap for capsule identities, when it parsed.
///
/// Only installation id, plan generation, and Host state root are ever read
/// from it; the registration nonce is never accessed.
fn captured_bootstrap_snapshot() -> Option<HostLaunchOptions> {
    PROCESS_BOOTSTRAP
        .get()
        .and_then(|result| result.as_ref().ok())
        .cloned()
}

/// Console process exit for a failed run: the 1066 marker on Windows, where
/// SCM status projection exists, and the historical `1` elsewhere.
fn console_process_exit_code() -> i32 {
    #[cfg(windows)]
    {
        HOST_CONSOLE_PROCESS_EXIT_CODE
    }
    #[cfg(not(windows))]
    {
        1
    }
}

fn main() {
    let _ = PROCESS_BOOTSTRAP.set(parse_process_bootstrap(std::env::args_os().skip(1)));
    #[cfg(windows)]
    match run_as_scm_service() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            let detail = format!(
                "StartServiceCtrlDispatcherW failed with Win32 error {error} (0x{error:08X})"
            );
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let cached = captured_bootstrap_snapshot();
            persist_host_start_failure(
                HostStopCode::DispatcherFailed,
                "dispatcher",
                &detail,
                cached.as_ref(),
            );
            std::process::exit(HOST_CONSOLE_PROCESS_EXIT_CODE);
        }
    }
    if !run_console() {
        let cached = captured_bootstrap_snapshot();
        persist_host_start_failure(
            HostStopCode::ConsoleFailed,
            "console",
            "console protocol failed before durable shutdown",
            cached.as_ref(),
        );
        std::process::exit(console_process_exit_code());
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

#[cfg(windows)]
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(windows)]
fn run_as_scm_service() -> Result<bool, u32> {
    use eliot_platform_windows::scm_entry::{DispatcherOutcome, run_service_dispatcher};

    match run_service_dispatcher(SERVICE_NAME, service_main) {
        Ok(DispatcherOutcome::Dispatched) => Ok(true),
        Ok(DispatcherOutcome::Console) => {
            // The documented interactive-console case is the only condition
            // under which the process may enter its stdin/stdout fallback.
            Ok(false)
        }
        Err(error) => Err(error.code()),
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
    fn start(handle: eliot_platform_windows::scm_entry::ServiceStatusHandle) -> io::Result<Self> {
        use eliot_platform_windows::scm_entry::{ServiceStatusReport, report_service_status};
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows_sys::Win32::System::Services::SERVICE_START_PENDING;

        let (stop, stopped) = std::sync::mpsc::channel();
        let failed = std::sync::Arc::new(AtomicBool::new(false));
        let task_failed = failed.clone();
        let task = std::thread::Builder::new()
            .name("eliot-host-scm-start-pending".to_owned())
            .spawn(move || {
                let mut checkpoint = 2u32;
                loop {
                    match stopped.recv_timeout(std::time::Duration::from_secs(2)) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let report = ServiceStatusReport::new(
                        SERVICE_START_PENDING,
                        0,
                        0,
                        0,
                        checkpoint,
                        10_000,
                    );
                    // The service-main thread retains the registered
                    // status handle until this reporter is stopped and joined.
                    if report_service_status(&handle, &report).is_err() {
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
    clippy::too_many_arguments,
    reason = "one terminal failure projection carries class, kind, detail, and identities together"
)]
fn fail_host_service(
    handle: &eliot_platform_windows::scm_entry::ServiceStatusHandle,
    report: &mut eliot_platform_windows::scm_entry::ServiceStatusReport,
    code: HostStopCode,
    error_variant: &str,
    detail: &str,
    launch_options: Option<&HostLaunchOptions>,
) {
    use eliot_platform_windows::scm_entry::report_service_status;
    use windows_sys::Win32::System::Services::SERVICE_STOPPED;
    persist_host_start_failure(code, error_variant, detail, launch_options);
    report.current_state = SERVICE_STOPPED;
    report.win32_exit_code = HOST_WIN32_SERVICE_SPECIFIC_ERROR;
    report.service_specific_exit_code = code.specific();
    let _ = report_service_status(handle, report);
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the SCM callback owns the complete fail-closed service lifecycle"
)]
extern "system" fn service_main(service_arg_count: u32, service_arg_vector: *mut *mut u16) {
    use eliot_platform_windows::scm_entry::{
        ServiceArgvError, ServiceStatusReport, parse_service_main_argv,
        register_service_control_handler, report_service_status,
    };
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Services::{
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };

    let handle = match register_service_control_handler(SERVICE_NAME, service_control) {
        Ok(handle) => handle,
        Err(error) => {
            let code = error.code();
            let detail = format!(
                "RegisterServiceCtrlHandlerExW returned a null handle (Win32 error {code} (0x{code:08X}))"
            );
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let cached = captured_bootstrap_snapshot();
            persist_host_start_failure(
                HostStopCode::ScmRegisterNull,
                "none",
                &detail,
                cached.as_ref(),
            );
            return;
        }
    };
    let mut report = ServiceStatusReport::new(SERVICE_START_PENDING, 0, 0, 0, 1, 10_000);
    let _ = report_service_status(&handle, &report);
    let launch_options = match parse_service_main_argv(service_arg_count, service_arg_vector)
        .map_err(|argv_error| match argv_error {
            ServiceArgvError::BadCount | ServiceArgvError::NullVector => HostError::Platform(
                "SCM did not provide the canonical EliotHost ServiceMain argv".to_owned(),
            ),
            ServiceArgvError::NullValue => {
                HostError::Platform("SCM provided a null service argv value".to_owned())
            }
            ServiceArgvError::TooLong => {
                HostError::Platform("SCM argv value is too long".to_owned())
            }
            ServiceArgvError::InvalidUtf16 => HostError::Platform(argv_error.to_string()),
        })
        .and_then(|argv| HostLaunchOptions::validate_service_main_argv([argv]))
        .and_then(|()| captured_process_bootstrap())
    {
        Ok(options) => options,
        Err(error) => {
            let detail = format!("invalid SCM launch argv or process bootstrap: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let cached = captured_bootstrap_snapshot();
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::InvalidScmArgvOrBootstrap,
                host_error_variant(&error),
                &detail,
                cached.as_ref(),
            );
            return;
        }
    };
    if let Err(error) = eliot_host::validate_host_scm_bootstrap(&launch_options) {
        let detail = format!("invalid SCM registration: {error}");
        let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
        fail_host_service(
            &handle,
            &mut report,
            HostStopCode::InvalidRegistration,
            host_error_variant(&error),
            &detail,
            Some(&launch_options),
        );
        return;
    }
    let reporter = match HostStartPendingReporter::start(handle) {
        Ok(reporter) => reporter,
        Err(error) => {
            let detail = format!("SCM start-pending reporter could not start: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::ReporterStartFailed,
                "io",
                &detail,
                Some(&launch_options),
            );
            return;
        }
    };
    let capsule_bootstrap = launch_options.clone();
    let host_result = open_host(launch_options);
    let reporter_succeeded = reporter.finish();
    let mut host = match host_result {
        Ok(host) => host,
        Err(error) => {
            let detail = format!("SCM host open failed: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::OpenHostFailed,
                host_error_variant(&error),
                &detail,
                Some(&capsule_bootstrap),
            );
            return;
        }
    };
    if !reporter_succeeded {
        let detail = "SCM start-pending progress could not be published";
        let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
        let _ = host.stop();
        fail_host_service(
            &handle,
            &mut report,
            HostStopCode::ReporterProgressFailed,
            "reporter",
            detail,
            Some(&capsule_bootstrap),
        );
        return;
    }
    let credential_control = match host.credential_control() {
        Ok(control) => control,
        Err(error) => {
            let detail = format!("SCM credential control is unavailable: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let _ = host.stop();
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::CredentialControlFailed,
                host_error_variant(&error),
                &detail,
                Some(&capsule_bootstrap),
            );
            return;
        }
    };
    let phase_b_queue = credential_control.phase_b_queue();
    let credential_thread = match spawn_credential_control(credential_control) {
        Ok(thread) => thread,
        Err(error) => {
            let detail = format!("SCM credential-control thread could not start: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let _ = host.stop();
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::SpawnCredentialFailed,
                host_error_variant(&error),
                &detail,
                Some(&capsule_bootstrap),
            );
            return;
        }
    };
    let runtime_control = match host.runtime_control() {
        Ok(control) => control,
        Err(error) => {
            let detail = format!("SCM runtime control is unavailable: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let _ = host.stop();
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::RuntimeControlFailed,
                host_error_variant(&error),
                &detail,
                Some(&capsule_bootstrap),
            );
            return;
        }
    };
    let runtime_queue = runtime_control.queue();
    let runtime_thread = match spawn_runtime_control(runtime_control) {
        Ok(thread) => thread,
        Err(error) => {
            let detail = format!("SCM runtime-control thread could not start: {error}");
            let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
            let _ = host.stop();
            fail_host_service(
                &handle,
                &mut report,
                HostStopCode::SpawnRuntimeFailed,
                host_error_variant(&error),
                &detail,
                Some(&capsule_bootstrap),
            );
            return;
        }
    };
    report.current_state = SERVICE_RUNNING;
    report.controls_accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    report.check_point = 0;
    let _ = report_service_status(&handle, &report);
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
    report.current_state = SERVICE_STOP_PENDING;
    report.controls_accepted = 0;
    report.check_point = 1;
    report.wait_hint = 10_000;
    let _ = report_service_status(&handle, &report);
    let stop_result = host.stop();
    report.current_state = SERVICE_STOPPED;
    report.controls_accepted = 0;
    if let Err(error) = stop_result {
        let detail = format!("durable SCM shutdown failed; recovery required: {error}");
        let _ = writeln!(io::stderr().lock(), "eliot-host: {detail}");
        persist_host_start_failure(
            HostStopCode::DurableShutdownFailed,
            host_error_variant(&error),
            &detail,
            Some(&capsule_bootstrap),
        );
        // SCM receives a stopped state with 1066 plus a typed service-specific
        // code, which is a failed/recovery outcome rather than a clean stop.
        report.win32_exit_code = HOST_WIN32_SERVICE_SPECIFIC_ERROR;
        report.service_specific_exit_code = HostStopCode::DurableShutdownFailed.specific();
    }
    let _ = report_service_status(&handle, &report);
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
extern "system" fn service_control(
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

    fn all_stop_codes() -> [HostStopCode; 13] {
        use HostStopCode::{
            ConsoleFailed, CredentialControlFailed, DispatcherFailed, DurableShutdownFailed,
            InvalidRegistration, InvalidScmArgvOrBootstrap, OpenHostFailed, ReporterProgressFailed,
            ReporterStartFailed, RuntimeControlFailed, ScmRegisterNull, SpawnCredentialFailed,
            SpawnRuntimeFailed,
        };
        [
            ScmRegisterNull,
            InvalidScmArgvOrBootstrap,
            InvalidRegistration,
            ReporterStartFailed,
            OpenHostFailed,
            ReporterProgressFailed,
            CredentialControlFailed,
            SpawnCredentialFailed,
            RuntimeControlFailed,
            SpawnRuntimeFailed,
            DurableShutdownFailed,
            DispatcherFailed,
            ConsoleFailed,
        ]
    }

    #[test]
    fn host_stop_codes_are_stable_unique_and_typed() {
        let codes = all_stop_codes();
        let mut specifics = codes.map(HostStopCode::specific);
        specifics.sort_unstable();
        assert_eq!(
            specifics,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            "discriminants are the stable documented specific codes"
        );
        for code in codes {
            assert!(!code.failure_class().is_empty());
        }
        assert_eq!(
            HOST_WIN32_SERVICE_SPECIFIC_ERROR, 1066,
            "Win32 marker must be ERROR_SERVICE_SPECIFIC_ERROR"
        );
        let mut classes: Vec<&'static str> =
            codes.iter().map(|code| code.failure_class()).collect();
        classes.sort_unstable();
        classes.dedup();
        assert_eq!(classes.len(), codes.len(), "failure classes must be unique");
    }

    #[test]
    fn host_error_variants_name_kinds_without_data() {
        let secret = "registration-nonce-should-never-appear";
        assert_eq!(
            host_error_variant(&HostError::Platform(secret.to_owned())),
            "platform"
        );
        assert_eq!(
            host_error_variant(&HostError::RecoveryRequired(secret.to_owned())),
            "recovery_required"
        );
        assert_eq!(host_error_variant(&HostError::Stopped), "stopped");
        assert_eq!(
            host_error_variant(&HostError::MissingInstallation),
            "missing_installation"
        );
        assert_eq!(
            host_error_variant(&HostError::OwnerLeaseHeld),
            "owner_lease_held"
        );
        for variant in [
            host_error_variant(&HostError::Platform(secret.to_owned())),
            host_error_variant(&HostError::RecoveryRequired(secret.to_owned())),
        ] {
            assert!(
                !variant.contains(secret),
                "variant names must never carry error payloads"
            );
        }
    }

    fn windows_test_options(state_root: &std::path::Path) -> HostLaunchOptions {
        use std::ffi::OsString;
        let args = vec![
            OsString::from("--config-descriptor"),
            OsString::from(
                state_root
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
            OsString::from(state_root.to_string_lossy().into_owned()),
            OsString::from("--registration-nonce"),
            OsString::from("b".repeat(64)),
        ];
        HostLaunchOptions::parse_system_service(args)
            .unwrap_or_else(|error| panic!("test launch options: {error}"))
    }

    #[test]
    fn host_capsule_is_bounded_and_secret_free() {
        let root =
            std::env::temp_dir().join(format!("eliot-host-stop-code-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("fixture root: {error}"));
        let options = windows_test_options(&root);
        let nonce = options
            .registration_nonce()
            .unwrap_or_else(|| panic!("fixture nonce"))
            .as_str()
            .to_owned();
        let capsule = build_host_start_failure_capsule(
            HostStopCode::OpenHostFailed,
            host_error_variant(&HostError::RecoveryRequired(
                "durable state diverged".to_owned(),
            )),
            &"d".repeat(4000),
            Some(options.installation().as_str()),
            Some(options.transaction_plan_generation()),
        );
        assert!(
            capsule.len() <= HOST_START_FAILURE_CAPSULE_MAX_BYTES,
            "capsule must stay bounded"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&capsule).unwrap_or_else(|error| panic!("capsule JSON: {error}"));
        assert_eq!(parsed["record_type"], "host_start_failure");
        assert_eq!(parsed["service"], SERVICE_NAME);
        assert_eq!(parsed["failure_class"], "open_host_failed");
        assert_eq!(parsed["error_variant"], "recovery_required");
        assert_eq!(parsed["win32_exit_code"], 1066);
        assert_eq!(parsed["service_specific_exit_code"], 5);
        assert_eq!(parsed["installation_id"], "installation-host-test");
        assert_eq!(parsed["tx_plan_generation"], 7);
        assert!(
            parsed["detail"]
                .as_str()
                .is_some_and(|detail| detail.chars().count() <= HOST_START_FAILURE_DETAIL_MAX_CHARS),
            "detail must be truncated"
        );
        assert!(
            !capsule.contains(&nonce),
            "the registration nonce must never be persisted"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn host_capsule_persist_roundtrip_never_carries_the_nonce() {
        let root = std::env::temp_dir().join(format!(
            "eliot-host-stop-code-persist-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("fixture root: {error}"));
        let options = windows_test_options(&root);
        let nonce = options
            .registration_nonce()
            .unwrap_or_else(|| panic!("fixture nonce"))
            .as_str()
            .to_owned();
        // Typed self-check contract (s38 item 2, s40 runtime contour): a
        // default-DACL (Mismatched SD) observation projects through the same
        // pure host projection the bootstrap path uses, and the capsule
        // carries that exact typed detail — never the old collapsed string.
        // The runtime contour reports Mismatched as a unit variant; the Absent
        // bindings come from the validated request.
        let image = std::env::current_exe().unwrap_or_else(|_| panic!("test image unavailable"));
        let request = eliot_platform_windows::ServiceRegistrationRequest::new(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            eliot_platform_windows::ELIOT_HOST_SERVICE_DISPLAY_NAME,
            &image,
            eliot_platform_windows::ServiceStartMode::Automatic,
            eliot_platform_windows::ServiceAccount::LocalService,
        )
        .unwrap_or_else(|_| panic!("test registration request must build"));
        let cause = eliot_host::classify_host_scm_inspection(
            &request,
            &eliot_platform_windows::ServiceRegistrationRuntimeInspection::Mismatched,
        )
        .unwrap_or_else(|| panic!("mismatched inspection must classify"));
        assert_eq!(
            cause,
            eliot_host::HostScmRegistrationCause::Mismatched {
                inspection_debug: "Mismatched".to_owned(),
            }
        );
        let detail = cause.detail();
        assert_eq!(
            detail,
            "host-scm-registration-mismatched: service 'EliotHost' exists but its SCM configuration, service-SID type, or service-object security descriptor does not exactly match the canonical request (platform inspection reports Mismatched without field-level detail; inspection: Mismatched)"
        );
        assert!(
            !detail.contains("is not an exact read-only match"),
            "the old collapsed string must be gone"
        );
        persist_host_start_failure(
            HostStopCode::InvalidRegistration,
            "platform",
            &detail,
            Some(&options),
        );
        let stored = std::fs::read_to_string(root.join(HOST_START_FAILURE_CAPSULE_FILE_NAME))
            .unwrap_or_else(|error| panic!("capsule readback: {error}"));
        assert!(
            !stored.contains(&nonce),
            "the nonce must never be persisted"
        );
        assert!(stored.contains("invalid_scm_registration"));
        assert!(stored.contains("host-scm-registration-mismatched"));
        assert!(stored.contains("installation-host-test"));
        assert_eq!(
            HostStopCode::InvalidRegistration.specific(),
            3,
            "the typed cause must not renumber the stop class"
        );
        assert!(stored.len() <= HOST_START_FAILURE_CAPSULE_MAX_BYTES);
        let _ = std::fs::remove_file(root.join(HOST_START_FAILURE_CAPSULE_FILE_NAME));
        let _ = std::fs::remove_dir(&root);
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
