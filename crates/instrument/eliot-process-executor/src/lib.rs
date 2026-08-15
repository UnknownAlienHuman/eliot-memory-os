//! P-04: the sole physical implementation of the provider-neutral process
//! contract.
//!
//! P-04 owns launch mechanics, stream draining, deadlines and Job-tree
//! observations.  It does not mint dispatch authority.  Authority is injected
//! through [`DispatchValidationPort`], whose production implementation is the
//! P-07 controller composition.  The port is intentionally narrower than a
//! P-03 issuer: it can only consume a caller-owned request against fresh
//! suspended-child evidence.

#![forbid(unsafe_code)]

use eliot_instrument_api::EvidenceAxes;
use eliot_process::{
    CancellationReceipt, CancellationRequest, ContractError, DescendantEvidence, ExitDisposition,
    ExitStatus, OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessHealth, ProcessHealthStatus, ProcessId,
    ProcessLifecycle, ProcessRequest, ProcessStartReceipt, ProcessState, SuspendedProcessIdentity,
    ValidatedDispatch,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, JobObjectLimits, RunningJobChild, RunningJobObservation, SuspendedJobChild,
    SuspendedLaunchSpec, SuspendedProcessEvidence, SuspendedValidationError, TerminatedJobChild,
};

const DEFAULT_CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
const JOB_TERMINATION_CODE: u32 = 0xE1_04;
const WATCH_INTERVAL: Duration = Duration::from_millis(25);
const STREAM_CHUNK_BYTES: usize = 8192;
static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// P-07's injected process-authority seam.
///
/// Implementations must route this operation to the one active
/// `ProcessDispatchAuthorityController`.  P-04 never receives a key, replay
/// snapshot, or issuer capability and therefore cannot become a second
/// authority owner.
pub trait DispatchValidationPort: Send + Sync {
    /// Consumes exactly one P-03 permit after fresh P-02 evidence has been
    /// bound to the request.
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError>;
}

/// Bounded stream projection retained by P-04 for diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedStream {
    /// Retained prefix, bounded by the request and executor ceilings.
    pub bytes: Vec<u8>,
    /// Number of bytes drained, including bytes not retained.
    pub total_bytes: u64,
    /// Whether bytes beyond the retained prefix were observed.
    pub truncated: bool,
    /// Whether EOF was observed.
    pub complete: bool,
    /// Whether P-02 supplied a stream handle.
    pub captured: bool,
}

#[derive(Debug)]
struct StreamCapture {
    bytes: Vec<u8>,
    limit: usize,
    total_bytes: u64,
    truncated: bool,
    complete: bool,
    captured: bool,
}

impl StreamCapture {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit: limit.max(1),
            total_bytes: 0,
            truncated: false,
            complete: false,
            captured: false,
        }
    }

    fn snapshot(&self) -> CapturedStream {
        CapturedStream {
            bytes: self.bytes.clone(),
            total_bytes: self.total_bytes,
            truncated: self.truncated,
            complete: self.complete,
            captured: self.captured,
        }
    }
}

#[cfg(windows)]
struct Operation {
    state: ProcessState,
    sink: Arc<dyn ProcessEvidenceSink>,
    child: Option<RunningJobChild<ValidatedDispatch>>,
    stdout: Arc<Mutex<StreamCapture>>,
    stderr: Arc<Mutex<StreamCapture>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    deadline: Instant,
    timed_out: bool,
}

#[cfg(not(windows))]
struct Operation;

/// The single governed process executor.  It is deliberately constructed
/// with an injected authority port so no alternate issuer can be hidden in
/// the physical implementation.
pub struct WindowsProcessExecutor {
    authority: Arc<dyn DispatchValidationPort>,
    operations: Mutex<BTreeMap<OperationId, Arc<Mutex<Operation>>>>,
    reservations: Mutex<std::collections::BTreeSet<OperationId>>,
    capture_limit: usize,
}

struct OperationReservation<'a> {
    executor: &'a WindowsProcessExecutor,
    operation_id: OperationId,
}

impl Drop for OperationReservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut reservations) = self.executor.reservations.lock() {
            reservations.remove(&self.operation_id);
        }
    }
}

impl WindowsProcessExecutor {
    /// Creates one executor around the P-07 authority composition.
    #[must_use]
    pub fn new(authority: Arc<dyn DispatchValidationPort>) -> Self {
        Self {
            authority,
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
        }
    }

    /// Creates one executor with a bounded retained-stream ceiling.
    #[must_use]
    pub fn with_capture_limit(
        authority: Arc<dyn DispatchValidationPort>,
        capture_limit: usize,
    ) -> Self {
        Self {
            authority,
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: capture_limit.max(1),
        }
    }

    fn operation(&self, id: &OperationId) -> Result<Arc<Mutex<Operation>>, ProcessExecutionError> {
        self.operations
            .lock()
            .map_err(|_| unavailable("operation registry lock poisoned"))?
            .get(id)
            .cloned()
            .ok_or(ProcessExecutionError::NotFound)
    }

    fn reserve_operation(
        &self,
        id: OperationId,
    ) -> Result<OperationReservation<'_>, ProcessExecutionError> {
        let operations = self
            .operations
            .lock()
            .map_err(|_| unavailable("operation registry lock poisoned"))?;
        if operations.contains_key(&id) {
            return Err(unavailable("operation identity already exists"));
        }
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| unavailable("operation reservation lock poisoned"))?;
        if !reservations.insert(id.clone()) {
            return Err(unavailable("operation identity already exists"));
        }
        Ok(OperationReservation {
            executor: self,
            operation_id: id,
        })
    }

    /// Returns the retained non-authoritative stream projections.
    pub fn captured_output(
        &self,
        id: &OperationId,
    ) -> Result<(CapturedStream, CapturedStream), ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(id)?;
            let guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            return Ok((
                guard
                    .stdout
                    .lock()
                    .map_err(|_| unavailable("stdout lock poisoned"))?
                    .snapshot(),
                guard
                    .stderr
                    .lock()
                    .map_err(|_| unavailable("stderr lock poisoned"))?
                    .snapshot(),
            ));
        }
        #[cfg(not(windows))]
        {
            let _ = id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    /// Removes terminal operations after their descendants and streams have
    /// been observed.  The executor remains the sole owner of this cleanup;
    /// callers never receive a raw child or Job handle.
    pub fn cleanup_finished(&self) -> Result<usize, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| unavailable("operation registry lock poisoned"))?;
            let ids = operations
                .iter()
                .filter_map(|(id, operation)| {
                    let mut guard = operation.lock().ok()?;
                    if !guard.state.view().lifecycle().is_terminal() {
                        return None;
                    }
                    join_streams(&mut guard);
                    Some(id.clone())
                })
                .collect::<Vec<_>>();
            let count = ids.len();
            for id in ids {
                operations.remove(&id);
            }
            Ok(count)
        }
        #[cfg(not(windows))]
        {
            Ok(0)
        }
    }

    /// Terminates every still-owned child and clears the operation registry.
    ///
    /// This is the final physical cleanup contour used during Kernel
    /// shutdown and Drop; it does not claim a successful process outcome.
    pub fn shutdown(&self) -> Result<(), ProcessExecutionError> {
        #[cfg(windows)]
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| unavailable("operation registry lock poisoned"))?;
            for operation in operations.values() {
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                if guard.child.is_some() {
                    let _ = finalize_operation(&mut guard, ExitDisposition::Unknown, false);
                }
                join_streams(&mut guard);
            }
            operations.clear();
            self.reservations
                .lock()
                .map_err(|_| unavailable("operation reservation lock poisoned"))?
                .clear();
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

impl Drop for WindowsProcessExecutor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl ProcessExecutor for WindowsProcessExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        request.validate()?;
        let operation_id = request.operation_id().clone();
        let _reservation = self.reserve_operation(operation_id.clone())?;

        #[cfg(not(windows))]
        {
            let _ = (request, sink);
            return Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ));
        }

        #[cfg(windows)]
        {
            if !request.environment().secret_refs().is_empty() {
                return Err(unavailable(
                    "secret environment references require an admitted secret projection",
                ));
            }
            let executable = Path::new(request.executable());
            let digest = sha256_file(executable).map_err(unavailable)?;
            if !digest.eq_ignore_ascii_case(request.executable_sha256()) {
                return Err(unavailable(
                    "executable digest does not match ProcessRequest",
                ));
            }
            let environment = request
                .environment()
                .non_secret()
                .iter()
                .map(|(name, value)| (name.clone().into(), value.clone().into()))
                .collect::<Vec<_>>();
            let spec = SuspendedLaunchSpec::new(
                executable,
                request.argv().iter().cloned().map(Into::into).collect(),
                request.working_directory(),
                environment,
            )
            .map_err(|error| unavailable(error))?;
            let active_limit = request
                .resource_limits()
                .max_descendants()
                .checked_add(1)
                .ok_or_else(|| unavailable("descendant limit overflows Job limit"))?;
            let limits = JobObjectLimits::new(
                request.resource_limits().cpu_time_ms(),
                request.resource_limits().memory_bytes(),
                Some(active_limit),
            )
            .map_err(|error| unavailable(error))?;
            let stdout_limit = request.resource_limits().stdout_bytes();
            let stderr_limit = request.resource_limits().stderr_bytes();
            let wall_timeout_ms = request.resource_limits().wall_timeout_ms();
            let sequence = JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let job_name = JobObjectIdentity::new(format!(
                "Local\\Eliot-P04-{}-{}",
                std::process::id(),
                sequence
            ))
            .map_err(|error| unavailable(error))?;
            let child = SuspendedJobChild::spawn_named_with_limits(spec, job_name, limits)
                .map_err(|error| unavailable(error))?;

            let authority = Arc::clone(&self.authority);
            let validated = child
                .validate(|evidence| {
                    let observed = suspended_identity(&request, evidence)?;
                    authority.validate_and_consume(request, observed)
                })
                .map_err(validation_error)?;
            let mut state = ProcessState::from_validated(validated.validation());
            let mut running = validated.resume().map_err(|error| unavailable(error))?;
            let now = now_ms();
            state.mark_resumed(
                now,
                ProcessHealth::new(
                    ProcessHealthStatus::Healthy,
                    true,
                    now,
                    Some("P-02 suspended launch and resume observed".to_owned()),
                )?,
            )?;
            let receipt = ProcessStartReceipt::new(&state)?;
            let stdout = Arc::new(Mutex::new(StreamCapture::new(retention(
                stdout_limit,
                self.capture_limit,
            ))));
            let stderr = Arc::new(Mutex::new(StreamCapture::new(retention(
                stderr_limit,
                self.capture_limit,
            ))));
            let stdout_thread = spawn_capture(running.take_stdout(), Arc::clone(&stdout));
            let stderr_thread = spawn_capture(running.take_stderr(), Arc::clone(&stderr));
            let operation = Arc::new(Mutex::new(Operation {
                state,
                sink,
                child: Some(running),
                stdout,
                stderr,
                stdout_thread,
                stderr_thread,
                deadline: Instant::now()
                    .checked_add(Duration::from_millis(wall_timeout_ms))
                    .ok_or_else(|| unavailable("wall timeout overflows monotonic clock"))?,
                timed_out: false,
            }));
            self.operations
                .lock()
                .map_err(|_| unavailable("operation registry lock poisoned"))?
                .insert(operation_id, Arc::clone(&operation));
            spawn_deadline_watcher(operation);
            Ok(receipt)
        }
    }

    async fn inspect(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(&operation_id)?;
            let mut guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            refresh_operation(&mut guard)?;
            return Ok(guard.state.view());
        }
        #[cfg(not(windows))]
        {
            let _ = operation_id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    async fn cancel(
        &self,
        operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(&operation_id)?;
            let mut guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            let binding = guard.state.view().binding().clone();
            let receipt = guard.state.cancel(&CancellationRequest::new(binding))?;
            if guard.state.view().lifecycle() == ProcessLifecycle::Cancelling {
                finalize_operation(&mut guard, ExitDisposition::Cancelled, true)?;
            }
            return Ok(receipt);
        }
        #[cfg(not(windows))]
        {
            let _ = operation_id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(&operation_id)?;
            let mut guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            refresh_operation(&mut guard)?;
            if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                let Some(descendants) = guard.state.view().descendants().cloned() else {
                    return Err(ProcessExecutionError::UnknownOutcome);
                };
                if !descendants.complete() || !descendants.tree_terminated() {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                guard.state.reconcile(descendants)?;
            }
            join_streams(&mut guard);
            let view = guard.state.view();
            let evidence = ProcessEvidence::new(
                view,
                capture_ref(&guard.stdout),
                capture_ref(&guard.stderr),
                EvidenceAxes::observed(),
            )?;
            guard.sink.record(evidence.clone())?;
            return Ok(evidence);
        }
        #[cfg(not(windows))]
        {
            let _ = operation_id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }
}

#[cfg(windows)]
fn suspended_identity(
    request: &ProcessRequest,
    evidence: &SuspendedProcessEvidence,
) -> Result<SuspendedProcessIdentity, ContractError> {
    let process_id = ProcessId::new(format!(
        "windows-process:{}",
        short_digest(evidence.process().stable_key().as_bytes())
    ))?;
    SuspendedProcessIdentity::new(
        process_id,
        request.process_tree_id().clone(),
        request.job_id().clone(),
        request.image_id().clone(),
        request.session_id().clone(),
        request.generation(),
        evidence.process().process_id,
        now_ms(),
        request.executable_sha256(),
    )
}

#[cfg(windows)]
fn validation_error<E: std::fmt::Display>(
    error: SuspendedValidationError<E>,
) -> ProcessExecutionError {
    match error {
        SuspendedValidationError::Mechanics(error) => unavailable(error),
        SuspendedValidationError::Rejected(error) => unavailable(error),
    }
}

#[cfg(windows)]
fn refresh_operation(operation: &mut Operation) -> Result<(), ProcessExecutionError> {
    if operation.state.view().lifecycle().is_terminal() {
        return Ok(());
    }
    if !operation.timed_out && Instant::now() >= operation.deadline {
        operation.timed_out = true;
        return finalize_operation(operation, ExitDisposition::ResourceLimit, false);
    }
    let Some(child) = operation.child.as_ref() else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    match child.observe().map_err(unavailable)? {
        RunningJobObservation::Running { .. } => Ok(()),
        RunningJobObservation::RootExited { .. } | RunningJobObservation::Exited { .. } => {
            finalize_operation(operation, ExitDisposition::Completed, false)
        }
    }
}

#[cfg(windows)]
fn finalize_operation(
    operation: &mut Operation,
    disposition: ExitDisposition,
    cancelled: bool,
) -> Result<(), ProcessExecutionError> {
    let Some(child) = operation.child.take() else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    let observed_root_exit = child
        .observe()
        .ok()
        .and_then(|observation| match observation {
            RunningJobObservation::RootExited { exit_code, .. }
            | RunningJobObservation::Exited { exit_code } => Some(exit_code),
            RunningJobObservation::Running { .. } => None,
        });
    let termination = child.terminate(JOB_TERMINATION_CODE);
    let observed_exit_code = termination
        .as_ref()
        .ok()
        .map(TerminatedJobChild::observed_exit_code);
    let history = termination.ok().map(|receipt| receipt.history().clone());
    let (process_ids, complete, tree_terminated, evidence_ref) = history
        .as_ref()
        .map(|history| {
            let ids = history
                .processes()
                .iter()
                .filter_map(|observation| {
                    ProcessId::new(format!(
                        "windows-process:{}",
                        short_digest(observation.process().stable_key().as_bytes())
                    ))
                    .ok()
                })
                .collect::<Vec<_>>();
            let evidence_ref = format!(
                "raw:p04-job-history:{}:{}:{}",
                ids.len(),
                history.complete(),
                history.job_empty()
            );
            (
                ids,
                history.complete(),
                history.job_empty(),
                Some(evidence_ref),
            )
        })
        .unwrap_or_else(|| (Vec::new(), false, false, None));
    let view = operation.state.view();
    let Some(identity) = view.identity() else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    let descendants = DescendantEvidence::new(
        view.binding().clone(),
        identity.process_id().clone(),
        process_ids,
        complete,
        tree_terminated,
        evidence_ref,
    )?;
    let actual_disposition = if !complete || !tree_terminated {
        ExitDisposition::Unknown
    } else if observed_root_exit.is_some() {
        ExitDisposition::Completed
    } else if cancelled {
        ExitDisposition::Cancelled
    } else if disposition == ExitDisposition::Completed {
        // A completion request without a root-exit observation cannot be
        // projected as a successful completion, even when Job termination
        // itself succeeded.  The adapter's forced-termination code is not a
        // substitute for the child outcome.
        ExitDisposition::Unknown
    } else {
        disposition
    };
    let code = if actual_disposition == ExitDisposition::Unknown {
        None
    } else {
        observed_root_exit.or(observed_exit_code)
    };
    let exit = ExitStatus::new(actual_disposition, code, None, now_ms())?;
    operation.state.exit(exit, descendants)?;
    Ok(())
}

#[cfg(windows)]
fn spawn_deadline_watcher(operation: Arc<Mutex<Operation>>) {
    let _ = thread::Builder::new()
        .name("eliot-p04-deadline".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(WATCH_INTERVAL);
                let Ok(mut guard) = operation.lock() else {
                    return;
                };
                if guard.state.view().lifecycle().is_terminal() {
                    return;
                }
                if refresh_operation(&mut guard).is_err() {
                    // A failed observation is an external-state gap, not a
                    // reason to detach the Job.  Fence the operation as
                    // unknown and retain it for explicit reconciliation or
                    // final shutdown cleanup.
                    let _ = finalize_operation(&mut guard, ExitDisposition::Unknown, false);
                    return;
                }
            }
        });
}

#[cfg(windows)]
fn join_streams(operation: &mut Operation) {
    if let Some(thread) = operation.stdout_thread.take() {
        let _ = thread.join();
    }
    if let Some(thread) = operation.stderr_thread.take() {
        let _ = thread.join();
    }
}

#[cfg(windows)]
fn spawn_capture(
    file: Option<std::fs::File>,
    capture: Arc<Mutex<StreamCapture>>,
) -> Option<JoinHandle<()>> {
    let mut file = file?;
    if let Ok(mut guard) = capture.lock() {
        guard.captured = true;
    }
    thread::Builder::new()
        .name("eliot-p04-stream".to_owned())
        .spawn(move || {
            let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
            loop {
                match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        let Some(mut guard) = capture.lock().ok() else {
                            return;
                        };
                        guard.total_bytes = guard.total_bytes.saturating_add(read as u64);
                        let remaining = guard.limit.saturating_sub(guard.bytes.len());
                        let retained = read.min(remaining);
                        guard.bytes.extend_from_slice(&buffer[..retained]);
                        if retained < read {
                            guard.truncated = true;
                        }
                    }
                    Err(_) => break,
                }
            }
            if let Ok(mut guard) = capture.lock() {
                guard.complete = true;
            }
        })
        .ok()
}

#[cfg(windows)]
fn capture_ref(capture: &Arc<Mutex<StreamCapture>>) -> Option<String> {
    let guard = capture.lock().ok()?;
    if !guard.captured {
        return None;
    }
    Some(format!(
        "raw:p04-stream:sha256:{}:bytes:{}:complete:{}",
        short_digest(&guard.bytes),
        guard.total_bytes,
        guard.complete
    ))
}

fn retention(limit: u64, ceiling: usize) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX).min(ceiling)
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn short_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}

fn unavailable(error: impl std::fmt::Display) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(error.to_string())
}
