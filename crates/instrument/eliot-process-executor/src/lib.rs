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
    ExitStatus, OperationId, PhysicalProcessBinding, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionBinding, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessHealth, ProcessHealthStatus, ProcessId, ProcessLaunchAdmission, ProcessLifecycle,
    ProcessRequest, ProcessStartReceipt, ProcessState, ProcessStreamEvidence, ProcessStreamKind,
    ProcessStreamPolicyBinding, ProcessStreamPrefixPreview, StreamEvidenceGap,
    StreamPersistenceStatus, StreamTransportStatus, SuspendedLaunchEvidence,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, JobObjectLimits, RunningJobChild, RunningJobObservation, SuspendedJobChild,
    SuspendedLaunchSpec, SuspendedProcessEvidence, SuspendedValidationError, TerminatedJobChild,
    cancel_capture_thread_io,
};

const DEFAULT_CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
const EVIDENCE_PREVIEW_CEILING: usize = 16 * 1024 * 1024;
const JOB_TERMINATION_CODE: u32 = 0xE1_04;
const WATCH_INTERVAL: Duration = Duration::from_millis(25);
const STREAM_CHUNK_BYTES: usize = 8192;
const STREAM_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_JOIN_POLL: Duration = Duration::from_millis(5);
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
    ///
    /// # Errors
    /// Returns an error when the request or suspended identity is invalid, or
    /// when the active authority cannot consume the one-shot permit.
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

#[allow(
    clippy::struct_excessive_bools,
    reason = "requested, captured, truncated, complete, and read_error are independent stream observations"
)]
struct StreamCapture {
    requested: bool,
    bytes: Vec<u8>,
    limit: usize,
    total_bytes: u64,
    truncated: bool,
    complete: bool,
    read_error: bool,
    captured: bool,
    digest: Sha256,
}

impl std::fmt::Debug for StreamCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamCapture")
            .field("requested", &self.requested)
            .field("bytes", &self.bytes)
            .field("limit", &self.limit)
            .field("total_bytes", &self.total_bytes)
            .field("truncated", &self.truncated)
            .field("complete", &self.complete)
            .field("read_error", &self.read_error)
            .field("captured", &self.captured)
            .finish_non_exhaustive()
    }
}

impl StreamCapture {
    fn new(limit: usize, requested: bool) -> Self {
        Self {
            requested,
            bytes: Vec::new(),
            limit: limit.max(1),
            total_bytes: 0,
            truncated: false,
            complete: false,
            read_error: false,
            captured: false,
            digest: Sha256::new(),
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
#[derive(Clone, Debug, Eq, PartialEq)]
struct CaptureFailure {
    stream: &'static str,
    thread_id: Option<String>,
    disposition: CaptureFailureDisposition,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureFailureDisposition {
    SpawnFailed,
    Timeout,
    Panicked,
    Incomplete,
    ReadFailed,
}

#[cfg(windows)]
struct DeadlineWatcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(windows)]
impl DeadlineWatcher {
    fn stop_and_join(mut self) -> Result<(), ProcessExecutionError> {
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return Err(unavailable("deadline watcher owner is missing its thread"));
        };
        handle
            .join()
            .map_err(|_| unavailable("deadline watcher thread panicked"))
    }
}

#[cfg(windows)]
impl Drop for DeadlineWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
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
    deadline_watcher: Option<DeadlineWatcher>,
    timed_out: bool,
    cleanup_required: bool,
    termination: Option<TerminatedJobChild>,
    capture_failures: Vec<CaptureFailure>,
}

#[cfg(not(windows))]
struct Operation;

/// The single governed process executor.  It is deliberately constructed
/// with an injected authority port so no alternate issuer can be hidden in
/// the physical implementation.
pub struct WindowsProcessExecutor {
    authority: Arc<dyn DispatchValidationPort>,
    launch_admission: Option<Arc<dyn ProcessLaunchAdmission>>,
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
            launch_admission: None,
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
        }
    }

    /// Creates one executor with a Kernel-owned retained launch-proof seam.
    #[must_use]
    pub fn new_with_launch_admission(
        authority: Arc<dyn DispatchValidationPort>,
        launch_admission: Arc<dyn ProcessLaunchAdmission>,
    ) -> Self {
        Self {
            authority,
            launch_admission: Some(launch_admission),
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
            launch_admission: None,
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
    ///
    /// # Errors
    /// Returns an error when the operation is absent, a capture lock is
    /// poisoned, or the Windows executor is unavailable.
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
    ///
    /// # Errors
    /// Returns an error when registry access fails or stream cleanup cannot be
    /// proven complete. Incomplete cleanup is retained as an unknown outcome.
    pub fn cleanup_finished(&self) -> Result<usize, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| unavailable("operation registry lock poisoned"))?;
            let mut ids = Vec::new();
            let mut cleanup_unknown = false;
            for (id, operation) in operations.iter() {
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                if !guard.state.view().lifecycle().is_terminal() || guard.cleanup_required {
                    continue;
                }
                let watcher = guard.deadline_watcher.take();
                drop(guard);
                if let Some(watcher) = watcher
                    && join_deadline_watcher(watcher).is_err()
                {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| unavailable("operation lock poisoned"))?;
                    quarantine_operation(&mut guard);
                    cleanup_unknown = true;
                    continue;
                }
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                if !join_streams(&mut guard) {
                    quarantine_operation(&mut guard);
                    cleanup_unknown = true;
                    continue;
                }
                ids.push(id.clone());
            }
            if cleanup_unknown {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
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

    /// Terminates every still-owned child and clears the operation registry
    /// only when every cleanup owner reaches a terminal projection.
    ///
    /// This is the final physical cleanup contour used during Kernel
    /// shutdown and Drop; it does not claim a successful process outcome.
    ///
    /// # Errors
    /// Returns [`ProcessExecutionError::UnknownOutcome`] and retains the
    /// operation registry when any child or cleanup marker remains owned.
    pub fn shutdown(&self) -> Result<(), ProcessExecutionError> {
        #[cfg(windows)]
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| unavailable("operation registry lock poisoned"))?;
            let mut retain_cleanup_owners = false;
            let mut watcher_owners = Vec::new();
            for operation in operations.values() {
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                retain_cleanup_owners |= guard.cleanup_required
                    || guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome;
                if guard.child.is_some()
                    && guard.termination.is_none()
                    && finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err()
                {
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                }
                if !join_streams(&mut guard) {
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                }
                if let Some(watcher) = guard.deadline_watcher.take() {
                    watcher_owners.push((Arc::clone(operation), watcher));
                }
            }
            for (operation, watcher) in watcher_owners {
                if join_deadline_watcher(watcher).is_err() {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| unavailable("operation lock poisoned"))?;
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                }
            }
            if !retain_cleanup_owners {
                operations.clear();
                self.reservations
                    .lock()
                    .map_err(|_| unavailable("operation reservation lock poisoned"))?
                    .clear();
                return Ok(());
            }
            Err(ProcessExecutionError::UnknownOutcome)
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
    #[allow(
        clippy::too_many_lines,
        reason = "the suspend, validate-and-consume, resume, capture, and registration order is security-critical"
    )]
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
            .map_err(unavailable)?;
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
            .map_err(unavailable)?;
            let stdout_limit = request.resource_limits().stdout_bytes();
            let stderr_limit = request.resource_limits().stderr_bytes();
            let stdout_requested = stdout_limit > 0;
            let stderr_requested = stderr_limit > 0;
            let wall_timeout_ms = request.resource_limits().wall_timeout_ms();
            let sequence = JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let job_name = JobObjectIdentity::new(format!(
                "Local\\Eliot-P04-{}-{}",
                std::process::id(),
                sequence
            ))
            .map_err(unavailable)?;
            let child = SuspendedJobChild::spawn_named_with_limits(spec, job_name, limits)
                .map_err(unavailable)?;

            let authority = Arc::clone(&self.authority);
            let launch_admission = self.launch_admission.as_ref().map(Arc::clone);
            let validated = child
                .validate(|evidence| {
                    let observed = suspended_identity(&request, evidence)?;
                    let executable = evidence.executable_file_identity();
                    let launch = SuspendedLaunchEvidence::new(
                        evidence.requested_executable().to_string_lossy(),
                        executable.volume_serial_number,
                        executable.file_index,
                    )?;
                    if let Some(admission) = &launch_admission {
                        admission.validate_launch(&request, &observed, &launch)?;
                    }
                    authority.validate_and_consume(request, observed)
                })
                .map_err(validation_error)?;
            let mut state = ProcessState::from_validated(validated.validation());
            let mut running = validated.resume().map_err(unavailable)?;
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
            let stdout = Arc::new(Mutex::new(StreamCapture::new(
                retention(stdout_limit, self.capture_limit),
                stdout_requested,
            )));
            let stderr = Arc::new(Mutex::new(StreamCapture::new(
                retention(stderr_limit, self.capture_limit),
                stderr_requested,
            )));
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(wall_timeout_ms))
                .ok_or_else(|| unavailable("wall timeout overflows monotonic clock"))?;
            let mut capture_spawn_error = None;
            let mut capture_failure = None;
            let stdout_thread =
                match spawn_capture("stdout", running.take_stdout(), Arc::clone(&stdout)) {
                    Ok(thread) => thread,
                    Err(error) => {
                        capture_spawn_error = Some(error);
                        capture_failure = Some(CaptureFailure {
                            stream: "stdout",
                            thread_id: None,
                            disposition: CaptureFailureDisposition::SpawnFailed,
                        });
                        None
                    }
                };
            let stderr_thread = if capture_spawn_error.is_none() {
                match spawn_capture("stderr", running.take_stderr(), Arc::clone(&stderr)) {
                    Ok(thread) => thread,
                    Err(error) => {
                        capture_spawn_error = Some(error);
                        capture_failure = Some(CaptureFailure {
                            stream: "stderr",
                            thread_id: None,
                            disposition: CaptureFailureDisposition::SpawnFailed,
                        });
                        None
                    }
                }
            } else {
                None
            };
            let operation = Arc::new(Mutex::new(Operation {
                state,
                sink,
                child: Some(running),
                stdout,
                stderr,
                stdout_thread,
                stderr_thread,
                deadline,
                deadline_watcher: None,
                timed_out: false,
                cleanup_required: false,
                termination: None,
                capture_failures: capture_failure.into_iter().collect(),
            }));
            if let Some(error) = capture_spawn_error {
                self.operations
                    .lock()
                    .map_err(|_| unavailable("operation registry lock poisoned"))?
                    .insert(operation_id.clone(), Arc::clone(&operation));
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                quarantine_operation(&mut guard);
                return Err(error);
            }
            let Ok(deadline_watcher) = spawn_deadline_watcher(&operation) else {
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                if finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err() {
                    quarantine_operation(&mut guard);
                }
                drop(guard);
                self.operations
                    .lock()
                    .map_err(|_| unavailable("operation registry lock poisoned"))?
                    .insert(operation_id.clone(), Arc::clone(&operation));
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            let Ok(mut guard) = operation.lock() else {
                let _ = join_deadline_watcher(deadline_watcher);
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            guard.deadline_watcher = Some(deadline_watcher);
            let view = guard.state.view();
            let sink = Arc::clone(&guard.sink);
            drop(guard);
            let evidence = ProcessEvidence::new_typed(view, None, None, EvidenceAxes::observed());
            let published = match evidence {
                Ok(evidence) => sink.record(evidence).is_ok(),
                Err(_) => false,
            };
            let Ok(mut guard) = operation.lock() else {
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            if !published {
                quarantine_operation(&mut guard);
                drop(guard);
                if let Ok(mut registry) = self.operations.lock() {
                    registry
                        .entry(operation_id.clone())
                        .or_insert_with(|| Arc::clone(&operation));
                }
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            self.operations
                .lock()
                .map_err(|_| ProcessExecutionError::UnknownOutcome)?
                .insert(operation_id, Arc::clone(&operation));
            let Ok(receipt) = ProcessStartReceipt::new(&guard.state) else {
                quarantine_operation(&mut guard);
                return Err(ProcessExecutionError::UnknownOutcome);
            };
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
            if let Err(error) = refresh_operation(&mut guard) {
                quarantine_operation(&mut guard);
                return Err(error);
            }
            Ok(guard.state.view())
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
            if let Err(error) = guard
                .state
                .cancel(&CancellationRequest::new(binding.clone()))
            {
                quarantine_operation(&mut guard);
                return Err(error.into());
            }
            if guard.state.view().lifecycle() == ProcessLifecycle::Cancelling
                && let Err(error) = finalize_operation(&mut guard, ExitDisposition::Cancelled, true)
            {
                quarantine_operation(&mut guard);
                return Err(error);
            }
            // Re-read the receipt after the finalize path so the returned
            // descendants prove the post-finalize tree state instead of the
            // pre-finalize gap. Terminal states re-report the stored closure
            // evidence through the existing cancel projection; an
            // UnknownOutcome landing surfaces the typed unknown outcome while
            // the operation stays retained for reconcile/shutdown.
            // `CancellationReceipt` carries no cleanup-required field, so the
            // typed error is the only honest carrier for unproven closure.
            match guard.state.cancel(&CancellationRequest::new(binding)) {
                Ok(receipt) => Ok(receipt),
                Err(error) => {
                    quarantine_operation(&mut guard);
                    if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                        return Err(ProcessExecutionError::UnknownOutcome);
                    }
                    Err(error.into())
                }
            }
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
            if let Err(error) = refresh_operation(&mut guard) {
                quarantine_operation(&mut guard);
                return Err(error);
            }
            if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                let Some(descendants) = guard.state.view().descendants().cloned() else {
                    return Err(ProcessExecutionError::UnknownOutcome);
                };
                if !descendants.complete() || !descendants.tree_terminated() {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                guard.state.reconcile(descendants)?;
            }
            if !join_streams(&mut guard) {
                quarantine_operation(&mut guard);
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            let view = guard.state.view();
            let binding = view.binding().clone();
            let stdout_typed =
                match typed_stream_evidence(&guard.stdout, ProcessStreamKind::Stdout, &binding) {
                    Ok(stream) => stream,
                    Err(error) => {
                        quarantine_operation(&mut guard);
                        return Err(error);
                    }
                };
            let stderr_typed =
                match typed_stream_evidence(&guard.stderr, ProcessStreamKind::Stderr, &binding) {
                    Ok(stream) => stream,
                    Err(error) => {
                        quarantine_operation(&mut guard);
                        return Err(error);
                    }
                };
            let Ok(evidence) = ProcessEvidence::new_typed(
                view,
                stdout_typed,
                stderr_typed,
                EvidenceAxes::observed(),
            ) else {
                quarantine_operation(&mut guard);
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            guard.sink.record(evidence.clone())?;
            Ok(evidence)
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
        PhysicalProcessBinding::new(
            evidence.process().process_id,
            evidence.process().start_time_100ns,
            evidence.process().image_path.clone(),
            evidence.job_identity().name(),
        )?,
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
    let Some(child) = operation.child.as_mut() else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    let observed_root_exit = match child.observe().map_err(unavailable)? {
        RunningJobObservation::RootExited { exit_code, .. }
        | RunningJobObservation::Exited { exit_code } => Some(exit_code),
        RunningJobObservation::Running { .. } => None,
    };
    let termination = child
        .terminate_in_place(JOB_TERMINATION_CODE)
        .map_err(unavailable)?;
    let observed_exit_code = termination.observed_exit_code();
    let history = termination.history().clone();
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
    let (process_ids, complete, tree_terminated, evidence_ref) = (
        ids,
        history.complete(),
        history.job_empty(),
        Some(evidence_ref),
    );
    let view = operation.state.view();
    let Some(identity) = view.identity() else {
        operation.termination = Some(termination);
        operation.cleanup_required = true;
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    let descendants = match DescendantEvidence::new(
        view.binding().clone(),
        identity.process_id().clone(),
        process_ids,
        complete,
        tree_terminated,
        evidence_ref,
    ) {
        Ok(descendants) => descendants,
        Err(error) => {
            operation.termination = Some(termination);
            operation.cleanup_required = true;
            return Err(error.into());
        }
    };
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
        observed_root_exit.or(Some(observed_exit_code))
    };
    let exit = match ExitStatus::new(actual_disposition, code, None, now_ms()) {
        Ok(exit) => exit,
        Err(error) => {
            operation.termination = Some(termination);
            operation.cleanup_required = true;
            return Err(error.into());
        }
    };
    if !join_streams(operation) {
        operation.termination = Some(termination);
        operation.cleanup_required = true;
        return Err(ProcessExecutionError::UnknownOutcome);
    }
    if let Err(error) = operation.state.exit(exit, descendants) {
        operation.termination = Some(termination);
        operation.cleanup_required = true;
        return Err(error.into());
    }
    let _ = operation.child.take();
    Ok(())
}

#[cfg(windows)]
fn fence_unknown(operation: &mut Operation) -> Result<(), ProcessExecutionError> {
    if operation.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
        return Ok(());
    }
    let view = operation.state.view();
    let identity = view
        .identity()
        .ok_or(ProcessExecutionError::UnknownOutcome)?;
    let descendants = DescendantEvidence::new(
        view.binding().clone(),
        identity.process_id().clone(),
        Vec::new(),
        false,
        false,
        None,
    )?;
    let exit = ExitStatus::new(ExitDisposition::Unknown, None, None, now_ms())?;
    operation.state.exit(exit, descendants)?;
    Ok(())
}

#[cfg(windows)]
fn quarantine_operation(operation: &mut Operation) {
    operation.cleanup_required = true;
    let _ = fence_unknown(operation);
}

#[cfg(windows)]
fn spawn_deadline_watcher(
    operation: &Arc<Mutex<Operation>>,
) -> Result<DeadlineWatcher, ProcessExecutionError> {
    #[cfg(test)]
    if FAIL_NEXT_DEADLINE_WATCHER_SPAWN.swap(false, Ordering::AcqRel) {
        return Err(unavailable("injected deadline watcher spawn failure"));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let operation = Arc::downgrade(operation);
    let handle = thread::Builder::new()
        .name("eliot-p04-deadline".to_owned())
        .spawn(move || {
            loop {
                if thread_stop.load(Ordering::Acquire) {
                    return;
                }
                thread::sleep(WATCH_INTERVAL);
                if thread_stop.load(Ordering::Acquire) {
                    return;
                }
                let Some(operation) = operation.upgrade() else {
                    return;
                };
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
                    quarantine_operation(&mut guard);
                    return;
                }
            }
        })
        .map_err(|error| unavailable(format!("deadline watcher spawn failed: {error}")))?;
    Ok(DeadlineWatcher {
        stop,
        handle: Some(handle),
    })
}

#[cfg(windows)]
fn join_deadline_watcher(watcher: DeadlineWatcher) -> Result<(), ProcessExecutionError> {
    watcher.stop_and_join()
}

#[cfg(all(test, windows))]
static FAIL_NEXT_DEADLINE_WATCHER_SPAWN: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn join_streams(operation: &mut Operation) -> bool {
    let stdout_result = join_capture_thread(&mut operation.stdout_thread, "stdout");
    let stderr_result = join_capture_thread(&mut operation.stderr_thread, "stderr");
    let mut failures = Vec::new();
    if let Err(failure) = &stdout_result {
        failures.push(failure.clone());
    }
    if let Err(failure) = &stderr_result {
        failures.push(failure.clone());
    }
    if let Ok(thread_id) = &stdout_result {
        let (complete, read_error) = capture_status(&operation.stdout);
        if read_error {
            failures.push(CaptureFailure {
                stream: "stdout",
                thread_id: thread_id.clone(),
                disposition: CaptureFailureDisposition::ReadFailed,
            });
        } else if !complete {
            failures.push(CaptureFailure {
                stream: "stdout",
                thread_id: thread_id.clone(),
                disposition: if thread_id.is_some() {
                    CaptureFailureDisposition::Incomplete
                } else {
                    CaptureFailureDisposition::SpawnFailed
                },
            });
        }
    }
    if let Ok(thread_id) = &stderr_result {
        let (complete, read_error) = capture_status(&operation.stderr);
        if read_error {
            failures.push(CaptureFailure {
                stream: "stderr",
                thread_id: thread_id.clone(),
                disposition: CaptureFailureDisposition::ReadFailed,
            });
        } else if !complete {
            failures.push(CaptureFailure {
                stream: "stderr",
                thread_id: thread_id.clone(),
                disposition: if thread_id.is_some() {
                    CaptureFailureDisposition::Incomplete
                } else {
                    CaptureFailureDisposition::SpawnFailed
                },
            });
        }
    }
    for failure in &failures {
        if !operation.capture_failures.contains(failure) {
            operation.capture_failures.push(failure.clone());
        }
    }
    failures.is_empty()
}

#[cfg(windows)]
fn join_capture_thread(
    thread_slot: &mut Option<JoinHandle<()>>,
    stream: &'static str,
) -> Result<Option<String>, CaptureFailure> {
    let Some(thread) = thread_slot.as_ref() else {
        return Ok(None);
    };
    let thread_id = Some(format!("{:?}", thread.thread().id()));
    if !thread.is_finished() {
        let _ = cancel_capture_thread_io(thread);
        let deadline = Instant::now()
            .checked_add(STREAM_JOIN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        while !thread.is_finished() && Instant::now() < deadline {
            thread::sleep(STREAM_JOIN_POLL);
        }
    }
    if !thread.is_finished() {
        return Err(CaptureFailure {
            stream,
            thread_id,
            disposition: CaptureFailureDisposition::Timeout,
        });
    }
    let Some(thread) = thread_slot.take() else {
        return Err(CaptureFailure {
            stream,
            thread_id,
            disposition: CaptureFailureDisposition::Panicked,
        });
    };
    if thread.join().is_err() {
        return Err(CaptureFailure {
            stream,
            thread_id,
            disposition: CaptureFailureDisposition::Panicked,
        });
    }
    Ok(thread_id)
}

#[cfg(windows)]
fn capture_status(capture: &Arc<Mutex<StreamCapture>>) -> (bool, bool) {
    capture.lock().map_or((false, true), |guard| {
        (!guard.requested || guard.complete, guard.read_error)
    })
}

#[cfg(windows)]
fn spawn_capture(
    stream: &'static str,
    file: Option<std::fs::File>,
    capture: Arc<Mutex<StreamCapture>>,
) -> Result<Option<JoinHandle<()>>, ProcessExecutionError> {
    let requested = capture
        .lock()
        .map_err(|_| unavailable(format!("{stream} capture lock poisoned")))?
        .requested;
    if !requested {
        return Ok(None);
    }
    let Some(mut file) = file else {
        return Err(unavailable(format!(
            "requested {stream} capture reader handle is missing"
        )));
    };
    let thread = thread::Builder::new()
        .name("eliot-p04-stream".to_owned())
        .spawn(move || {
            if let Ok(mut guard) = capture.lock() {
                guard.captured = true;
            } else {
                return;
            }
            let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
            let mut reached_eof = false;
            loop {
                match file.read(&mut buffer) {
                    Ok(0) => {
                        reached_eof = true;
                        break;
                    }
                    Ok(read) => {
                        let Some(mut guard) = capture.lock().ok() else {
                            return;
                        };
                        guard.digest.update(&buffer[..read]);
                        guard.total_bytes = guard.total_bytes.saturating_add(read as u64);
                        let remaining = guard.limit.saturating_sub(guard.bytes.len());
                        let retained = read.min(remaining);
                        guard.bytes.extend_from_slice(&buffer[..retained]);
                        if retained < read {
                            guard.truncated = true;
                        }
                    }
                    Err(_) => {
                        if let Ok(mut guard) = capture.lock() {
                            guard.read_error = true;
                        }
                        break;
                    }
                }
            }
            if reached_eof && let Ok(mut guard) = capture.lock() {
                guard.complete = true;
            }
        })
        .map_err(|error| unavailable(format!("{stream} capture reader spawn failed: {error}")))?;
    Ok(Some(thread))
}

#[cfg(windows)]
fn p04_stream_policy() -> Result<ProcessStreamPolicyBinding, ProcessExecutionError> {
    // P-04 raw-transport preview-only policy binding. No durable provider is
    // wired in P-04 and no redaction is applied; parsing stays Raw and
    // evaluation stays Unassessed via `new_raw_inner`.
    // - policy_ref `p04:stream-policy:transport-preview-v1`: P-04 offers only a
    //   bounded raw-transport prefix preview, never a durable complete source.
    // - privacy_ref `p04:privacy:raw-transport-preview`: raw child bytes are
    //   shown unredacted in the preview; no privacy transformation is applied.
    // - visibility_ref `p04:visibility:operation-diagnostic`: the preview is
    //   visible to the operation owner for diagnostics, not a canonical
    //   disclosure.
    // - retention_ref `p04:retention:bounded-prefix-only`: only a bounded
    //   in-memory prefix is retained; no durable retention is claimed.
    // - redaction_ref `p04:redaction:none-raw-preview`: no redaction or
    //   transformation is applied to the preview bytes.
    ProcessStreamPolicyBinding::new(
        "p04:stream-policy:transport-preview-v1",
        "p04:privacy:raw-transport-preview",
        "p04:visibility:operation-diagnostic",
        "p04:retention:bounded-prefix-only",
        "p04:redaction:none-raw-preview",
    )
    .map_err(|_| ProcessExecutionError::UnknownOutcome)
}

#[cfg(windows)]
fn typed_stream_evidence(
    capture: &Arc<Mutex<StreamCapture>>,
    kind: ProcessStreamKind,
    binding: &ProcessExecutionBinding,
) -> Result<Option<ProcessStreamEvidence>, ProcessExecutionError> {
    let (retained, total_bytes, observed_sha256) = {
        let guard = capture
            .lock()
            .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
        if !guard.requested || !guard.captured {
            return Ok(None);
        }
        if guard.read_error || !guard.complete {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let observed_sha256 = format!("{:x}", guard.digest.clone().finalize());
        (guard.bytes.clone(), guard.total_bytes, observed_sha256)
    };
    let mut prefix = retained;
    if prefix.len() > EVIDENCE_PREVIEW_CEILING {
        prefix.truncate(EVIDENCE_PREVIEW_CEILING);
    }
    let policy = p04_stream_policy()?;
    let preview = ProcessStreamPrefixPreview::from_transport_prefix(prefix, total_bytes)
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    // No durable provider is wired in P-04; the store backend is T3-owned, so
    // persistence is always `SourceUnavailable` with exactly the
    // `PersistenceUnavailable` gap and no source locator.
    let evidence = ProcessStreamEvidence::new_raw(
        binding.clone(),
        kind,
        policy,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::SourceUnavailable,
        observed_sha256,
        total_bytes,
        preview,
        None,
        vec![StreamEvidenceGap::PersistenceUnavailable],
    )
    .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    Ok(Some(evidence))
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

#[cfg(test)]
mod tests {
    use super::{DispatchValidationPort, WindowsProcessExecutor};
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
        EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
        ProcessExecutionError, ProcessExecutor, ProcessIntent, ProcessRequest, ProcessTreeId,
        ResourceLimits, SecretRef, SessionId, SuspendedProcessIdentity, ValidatedDispatch,
    };
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    #[cfg(windows)]
    use eliot_instrument_api::EvidenceAxes;
    #[cfg(windows)]
    use eliot_platform::ClockObservation;
    #[cfg(windows)]
    use eliot_process::{
        CancellationStatus, DispatchValidationContext, ExitDisposition, ProcessLifecycle,
    };

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        use eliot_contracts::{EpochId, EpochLineageId};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    #[derive(Default)]
    struct RecordingSink {
        evidence: Mutex<Vec<ProcessEvidence>>,
    }

    impl ProcessEvidenceSink for RecordingSink {
        fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            match self.evidence.lock() {
                Ok(mut guard) => {
                    guard.push(evidence);
                    Ok(())
                }
                Err(_) => Err(EvidenceSinkError {
                    message: "recording sink lock poisoned".to_owned(),
                }),
            }
        }
    }

    impl RecordingSink {
        fn recorded_len(&self) -> usize {
            match self.evidence.lock() {
                Ok(guard) => guard.len(),
                Err(_) => usize::MAX,
            }
        }

        fn recorded_one(&self) -> Option<ProcessEvidence> {
            match self.evidence.lock() {
                Ok(guard) => guard.first().cloned(),
                Err(_) => None,
            }
        }
    }

    struct DummyPort;

    impl DispatchValidationPort for DummyPort {
        fn validate_and_consume(
            &self,
            _request: ProcessRequest,
            _observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "dummy port must not be called pre-spawn".to_owned(),
            ))
        }
    }

    #[cfg(windows)]
    struct FakePort {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
    }

    #[cfg(windows)]
    impl DispatchValidationPort for FakePort {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            let mut authority = self.authority.lock().map_err(|_| {
                ProcessExecutionError::Unavailable("dispatch authority lock poisoned".to_owned())
            })?;
            authority
                .validate_and_consume(request, observed, &self.context)
                .map_err(Into::into)
        }
    }

    #[cfg(windows)]
    struct FailingSink;

    #[cfg(windows)]
    impl ProcessEvidenceSink for FailingSink {
        fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            Err(EvidenceSinkError {
                message: "injected sink failure".to_owned(),
            })
        }
    }

    // Large matrix deferred per START.md s1 — focused recipe only
    // (3 baseline start tests plus 2 T2-S03 reconcile stream tests).
    #[test]
    #[cfg(windows)]
    fn start_publishes_initial_observed_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-t2-s01-ok")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-t2-s01-ok")?,
            JobId::new("job-t2-s01-ok")?,
            ImageId::new("image-t2-s01-ok")?,
            SessionId::new("session-t2-s01-ok")?,
            generation,
            executable,
            digest,
            vec![
                "/c".to_owned(),
                "ping".to_owned(),
                "-n".to_owned(),
                "5".to_owned(),
                "127.0.0.1".to_owned(),
            ],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s01-ok")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s01")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-ok")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-ok",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        let _receipt = block_on(executor.start(request, sink_dyn))?;
        assert_eq!(sink.recorded_len(), 1);
        let Some(evidence) = sink.recorded_one() else {
            panic!("expected exactly one recorded evidence")
        };
        assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Running);
        assert_eq!(evidence.operation_id(), &operation_id);
        assert_eq!(evidence.axes(), EvidenceAxes::observed());
        let inspected = block_on(executor.inspect(operation_id))?;
        assert_eq!(inspected.lifecycle(), ProcessLifecycle::Running);
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn start_sink_failure_retains_unknown_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-t2-s01-sink-fail")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-t2-s01-sink-fail")?,
            JobId::new("job-t2-s01-sink-fail")?,
            ImageId::new("image-t2-s01-sink-fail")?,
            SessionId::new("session-t2-s01-sink-fail")?,
            generation,
            executable,
            digest,
            vec![
                "/c".to_owned(),
                "ping".to_owned(),
                "-n".to_owned(),
                "5".to_owned(),
                "127.0.0.1".to_owned(),
            ],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s01-sink-fail")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s01")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-sink-fail")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-sink-fail",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = Arc::new(FailingSink);
        let result = block_on(executor.start(request, sink_dyn));
        assert!(matches!(result, Err(ProcessExecutionError::UnknownOutcome)));
        let inspected = block_on(executor.inspect(operation_id))?;
        assert_eq!(inspected.lifecycle(), ProcessLifecycle::UnknownOutcome);
        Ok(())
    }

    #[test]
    fn start_rejects_bad_binding_pre_spawn() -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let generation = Generation::new(1)?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s01-bad")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s01")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let executor = WindowsProcessExecutor::new(Arc::new(DummyPort));
        let tampered_id = OperationId::new("op-t2-s01-bad-sha")?;
        let tampered_intent = ProcessIntent::new(
            tampered_id.clone(),
            ProcessTreeId::new("tree-t2-s01-bad-sha")?,
            JobId::new("job-t2-s01-bad-sha")?,
            ImageId::new("image-t2-s01-bad-sha")?,
            SessionId::new("session-t2-s01-bad-sha")?,
            generation,
            executable,
            "0".repeat(64),
            vec!["/c".to_owned(), "echo".to_owned(), "hi".to_owned()],
            working_directory.clone(),
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let tampered_permit = authority.issue(
            &tampered_intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-bad-sha")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-bad-sha",
            )?,
        )?;
        let tampered_request = ProcessRequest::new(tampered_intent, tampered_permit)?;
        let tampered_sink = Arc::new(RecordingSink::default());
        let tampered_sink_dyn: Arc<dyn ProcessEvidenceSink> = tampered_sink.clone();
        let tampered_result = block_on(executor.start(tampered_request, tampered_sink_dyn));
        assert!(matches!(
            tampered_result,
            Err(ProcessExecutionError::Unavailable(_))
        ));
        assert!(matches!(
            block_on(executor.inspect(tampered_id)),
            Err(ProcessExecutionError::NotFound)
        ));
        assert_eq!(tampered_sink.recorded_len(), 0);
        let secret_id = OperationId::new("op-t2-s01-bad-secret")?;
        let secret_env = EnvironmentProjection::new(
            BTreeMap::new(),
            vec![SecretRef::new("prov-t2-s01", "key-t2-s01")?],
            EnvironmentInheritance::None,
        )?;
        let secret_intent = ProcessIntent::new(
            secret_id.clone(),
            ProcessTreeId::new("tree-t2-s01-bad-secret")?,
            JobId::new("job-t2-s01-bad-secret")?,
            ImageId::new("image-t2-s01-bad-secret")?,
            SessionId::new("session-t2-s01-bad-secret")?,
            generation,
            executable,
            "a".repeat(64),
            vec!["/c".to_owned(), "echo".to_owned(), "hi".to_owned()],
            working_directory,
            secret_env,
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let secret_permit = authority.issue(
            &secret_intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-bad-secret")?,
                fence,
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-bad-secret",
            )?,
        )?;
        let secret_request = ProcessRequest::new(secret_intent, secret_permit)?;
        let secret_sink = Arc::new(RecordingSink::default());
        let secret_sink_dyn: Arc<dyn ProcessEvidenceSink> = secret_sink.clone();
        let secret_result = block_on(executor.start(secret_request, secret_sink_dyn));
        assert!(matches!(
            secret_result,
            Err(ProcessExecutionError::Unavailable(_))
        ));
        assert!(matches!(
            block_on(executor.inspect(secret_id)),
            Err(ProcessExecutionError::NotFound)
        ));
        assert_eq!(secret_sink.recorded_len(), 0);
        Ok(())
    }

    #[cfg(windows)]
    struct CountingFailSink {
        records: Mutex<usize>,
    }

    #[cfg(windows)]
    impl ProcessEvidenceSink for CountingFailSink {
        fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            let mut guard = self.records.lock().map_err(|_| EvidenceSinkError {
                message: "counting sink lock poisoned".to_owned(),
            })?;
            *guard = guard.saturating_add(1);
            if *guard == 1 {
                Ok(())
            } else {
                Err(EvidenceSinkError {
                    message: "injected post-start sink failure".to_owned(),
                })
            }
        }
    }

    #[cfg(windows)]
    fn start_and_reconcile(
        op_tag: &str,
        argv: Vec<String>,
        stdout_limit: u64,
        stderr_limit: u64,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessEvidence, Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new(format!("op-t2-s03-{op_tag}"))?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new(format!("tree-t2-s03-{op_tag}"))?,
            JobId::new(format!("job-t2-s03-{op_tag}"))?,
            ImageId::new(format!("image-t2-s03-{op_tag}"))?,
            SessionId::new(format!("session-t2-s03-{op_tag}"))?,
            generation,
            executable,
            digest,
            argv,
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(
                30_000,
                Some(10_000),
                Some(512_000_000),
                stdout_limit,
                stderr_limit,
                4,
            )?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-t2-s03-{op_tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-t2-s03-{op_tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-t2-s03-{op_tag}"))?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                format!("nonce-t2-s03-{op_tag}"),
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let _receipt = block_on(executor.start(request, sink))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view = block_on(executor.inspect(operation_id.clone()))?;
            if view.lifecycle().is_terminal() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for terminal lifecycle",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Ok(block_on(executor.reconcile(operation_id.clone()))?)
    }

    #[cfg(windows)]
    fn assert_truncated_stream(
        stream: &eliot_process::ProcessStreamEvidence,
        expected_retained: u64,
    ) {
        use eliot_process::{
            StreamEvaluationStatus, StreamEvidenceGap, StreamParsingStatus,
            StreamPersistenceStatus, StreamTransportStatus,
        };
        assert_eq!(stream.transport(), StreamTransportStatus::Complete);
        assert_eq!(
            stream.persistence(),
            StreamPersistenceStatus::SourceUnavailable
        );
        assert_eq!(stream.gaps().len(), 1);
        assert_eq!(stream.gaps()[0], StreamEvidenceGap::PersistenceUnavailable);
        assert!(stream.observed_bytes() > expected_retained);
        assert!(stream.preview().is_truncated());
        assert_eq!(stream.preview().retained_bytes(), expected_retained);
        assert_eq!(
            stream.preview().retained_bytes(),
            u64::try_from(stream.preview().bytes().len()).unwrap_or(u64::MAX)
        );
        assert_eq!(
            stream.preview().sha256(),
            super::short_digest(stream.preview().bytes()).as_str()
        );
        assert_eq!(stream.preview().omitted_ranges().len(), 1);
        assert_eq!(
            stream.preview().omitted_ranges()[0].start(),
            expected_retained
        );
        assert_eq!(
            stream.preview().omitted_ranges()[0].end_exclusive(),
            stream.observed_bytes()
        );
        assert_eq!(
            stream.preview().represented_bytes(),
            stream.observed_bytes()
        );
        assert!(stream.source().is_none());
        assert_eq!(stream.parsing(), StreamParsingStatus::Raw);
        assert_eq!(stream.evaluation(), StreamEvaluationStatus::Unassessed);
    }

    #[test]
    #[cfg(windows)]
    fn reconcile_reports_typed_bounded_streams_beyond_preview_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let bat_path = std::env::temp_dir().join("eliot-t2-s03-pressure.bat");
        std::fs::write(
            &bat_path,
            "@echo off\r\nfor /L %%i in (1,1,300) do (\r\necho STDOUT-PRESSURE-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\necho STDERR-PRESSURE-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ 1>&2\r\n)\r\n",
        )?;
        let pressure_argv = vec!["/c".to_owned(), bat_path.to_string_lossy().into_owned()];
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        let evidence = start_and_reconcile("pressure", pressure_argv, 4_096, 4_096, sink)?;
        let Some(stdout) = evidence.stdout() else {
            panic!("expected typed stdout evidence")
        };
        let Some(stderr) = evidence.stderr() else {
            panic!("expected typed stderr evidence")
        };
        assert_truncated_stream(stdout, 4_096);
        assert_truncated_stream(stderr, 4_096);
        let small_argv = vec![
            "/c".to_owned(),
            "echo".to_owned(),
            "small-stdout".to_owned(),
        ];
        let small_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        let small = start_and_reconcile("pressure-small", small_argv, 4_096, 4_096, small_sink)?;
        let Some(small_stdout) = small.stdout() else {
            panic!("expected small typed stdout evidence")
        };
        assert!(!small_stdout.preview().is_truncated());
        assert!(small_stdout.preview().omitted_ranges().is_empty());
        assert_eq!(
            small_stdout.preview().sha256(),
            small_stdout.observed_sha256()
        );
        let _ = std::fs::remove_file(&bat_path);
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn reconcile_with_failing_sink_reports_no_complete_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-t2-s03-sink-fail")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-t2-s03-sink-fail")?,
            JobId::new("job-t2-s03-sink-fail")?,
            ImageId::new("image-t2-s03-sink-fail")?,
            SessionId::new("session-t2-s03-sink-fail")?,
            generation,
            executable,
            digest,
            vec!["/c".to_owned(), "echo".to_owned(), "small-ok".to_owned()],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s03-sink-fail")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s03-sink-fail")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s03-sink-fail")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s03-sink-fail",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(CountingFailSink {
            records: Mutex::new(0),
        });
        let _receipt = block_on(executor.start(request, Arc::clone(&sink)))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view = block_on(executor.inspect(operation_id.clone()))?;
            if view.lifecycle().is_terminal() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for terminal lifecycle",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let result = block_on(executor.reconcile(operation_id));
        assert!(result.is_err());
        Ok(())
    }

    #[cfg(windows)]
    fn s04_authorized_request(
        op_tag: &str,
        argv: Vec<String>,
        stdout_limit: u64,
        stderr_limit: u64,
        max_descendants: u32,
    ) -> Result<(ProcessRequest, DispatchPermitAuthority, FencingToken), Box<dyn std::error::Error>>
    {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new(format!("op-t2-s04-{op_tag}"))?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id,
            ProcessTreeId::new(format!("tree-t2-s04-{op_tag}"))?,
            JobId::new(format!("job-t2-s04-{op_tag}"))?,
            ImageId::new(format!("image-t2-s04-{op_tag}"))?,
            SessionId::new(format!("session-t2-s04-{op_tag}"))?,
            generation,
            executable,
            digest,
            argv,
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(
                30_000,
                Some(10_000),
                Some(512_000_000),
                stdout_limit,
                stderr_limit,
                max_descendants,
            )?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-t2-s04-{op_tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-t2-s04-{op_tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-t2-s04-{op_tag}"))?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                format!("nonce-t2-s04-{op_tag}"),
            )?,
        )?;
        Ok((ProcessRequest::new(intent, permit)?, authority, fence))
    }

    #[cfg(windows)]
    fn s04_start(
        op_tag: &str,
        argv: Vec<String>,
        stdout_limit: u64,
        stderr_limit: u64,
        max_descendants: u32,
    ) -> Result<(WindowsProcessExecutor, OperationId, Arc<RecordingSink>), Box<dyn std::error::Error>>
    {
        let (request, authority, fence) =
            s04_authorized_request(op_tag, argv, stdout_limit, stderr_limit, max_descendants)?;
        let operation_id = request.operation_id().clone();
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        // The start receipt is intentionally dropped here: the executor is the
        // sole owner afterwards, which is exactly the disconnect shape the
        // reconcile test needs.
        let _receipt = block_on(executor.start(request, sink_dyn))?;
        Ok((executor, operation_id, sink))
    }

    #[cfg(windows)]
    fn s04_wait_terminal(
        executor: &WindowsProcessExecutor,
        operation_id: &OperationId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view = block_on(executor.inspect(operation_id.clone()))?;
            if view.lifecycle().is_terminal() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for terminal lifecycle",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[test]
    #[cfg(windows)]
    fn cancel_under_pressure_proves_tree_closure_or_typed_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let bat_path = std::env::temp_dir().join("eliot-t2-s04-cancel-tree.bat");
        let child_path = std::env::temp_dir().join("eliot-t2-s04-cancel-child.bat");
        // Separate files: no nested quoting, so `start` cannot re-split the
        // child command. Keep-alive uses only cmd internals (`for`/`rem`):
        // the spawn environment offers no PATH, so external waits like ping
        // fail instantly and cannot hold the tree open.
        std::fs::write(
            &child_path,
            "@echo off\r\nfor /L %%i in (1,1,400) do (\r\necho CHILD-OUT-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\necho CHILD-ERR-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ 1>&2\r\n)\r\nfor /L %%i in (1,0,2) do rem\r\n",
        )?;
        std::fs::write(
            &bat_path,
            format!(
                "@echo off\r\nstart \"\" /b \"{}\"\r\nfor /L %%i in (1,1,300) do (\r\necho ROOT-OUT-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\necho ROOT-ERR-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ 1>&2\r\n)\r\nfor /L %%i in (1,0,2) do rem\r\n",
                child_path.to_string_lossy()
            ),
        )?;
        let argv = vec!["/c".to_owned(), bat_path.to_string_lossy().into_owned()];
        let (executor, operation_id, _sink) = s04_start("cancel-tree", argv, 4_096, 4_096, 4)?;
        // Prove stdout/stderr pressure accumulated before cancelling: both
        // captured totals must exceed the 4096-byte preview bound.
        let pressure_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let (stdout, stderr) = executor.captured_output(&operation_id)?;
            if stdout.total_bytes > 4_096 && stderr.total_bytes > 4_096 {
                break;
            }
            if std::time::Instant::now() >= pressure_deadline {
                let _ = std::fs::remove_file(&bat_path);
                let _ = std::fs::remove_file(&child_path);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for stream pressure",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        // Give the Job observer a chance to notice the real child before the
        // tree is torn down. Both root and child spin in internal keep-alive
        // loops afterwards, so the tree is still owned at cancel time.
        std::thread::sleep(std::time::Duration::from_secs(1));
        let cancel_result = block_on(executor.cancel(operation_id.clone()));
        let _ = std::fs::remove_file(&bat_path);
        let _ = std::fs::remove_file(&child_path);
        match cancel_result {
            Ok(receipt) => {
                // Post-finalize receipt: tree closure is proven at the cancel
                // boundary. There is no `Cancelled` lifecycle variant, so the
                // proven terminal state is `Exited` with the `Cancelled` exit
                // disposition plus complete descendant evidence.
                assert_eq!(receipt.status(), CancellationStatus::Completed);
                assert_eq!(receipt.lifecycle(), ProcessLifecycle::Exited);
                let Some(descendants) = receipt.descendants() else {
                    panic!("cancel receipt must carry post-finalize descendant evidence")
                };
                assert!(descendants.complete());
                assert!(descendants.tree_terminated());
                assert!(
                    descendants.process_ids().len() >= 2,
                    "expected root plus at least one real child, observed {}",
                    descendants.process_ids().len()
                );
                let view = block_on(executor.inspect(operation_id.clone()))?;
                assert_eq!(view.lifecycle(), ProcessLifecycle::Exited);
                assert_eq!(view.cancellation(), CancellationStatus::Completed);
                let Some(exit) = view.exit() else {
                    panic!("expected an exit observation after cancel")
                };
                assert_eq!(exit.disposition(), ExitDisposition::Cancelled);
                let Some(view_descendants) = view.descendants() else {
                    panic!("expected descendant evidence after cancel")
                };
                assert!(view_descendants.complete() && view_descendants.tree_terminated());
                let evidence = block_on(executor.reconcile(operation_id.clone()))?;
                assert_eq!(evidence.operation_id(), &operation_id);
                assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Exited);
                let (stdout, stderr) = executor.captured_output(&operation_id)?;
                assert!(stdout.total_bytes > 4_096);
                assert!(stderr.total_bytes > 4_096);
                Ok(())
            }
            Err(ProcessExecutionError::UnknownOutcome) => {
                // Tree closure could not be proven within the existing waits:
                // the operation stays retained as unknown, never promoted to
                // a fabricated success.
                let view = block_on(executor.inspect(operation_id.clone()))?;
                assert_eq!(view.lifecycle(), ProcessLifecycle::UnknownOutcome);
                assert!(matches!(
                    block_on(executor.reconcile(operation_id)),
                    Err(ProcessExecutionError::UnknownOutcome)
                ));
                Ok(())
            }
            Err(other) => {
                Err(format!("cancel must prove closure or stay unknown, got {other:?}").into())
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn disconnect_reconciles_retained_operation_without_second_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let argv = vec![
            "/c".to_owned(),
            "echo".to_owned(),
            "disconnect-probe".to_owned(),
        ];
        let (executor, operation_id, sink) = s04_start("disconnect", argv, 4_096, 4_096, 4)?;
        // No cancel and no second start: reconcile the same retained
        // operation on the same executor after all client handles were
        // dropped inside `s04_start`.
        s04_wait_terminal(&executor, &operation_id)?;
        let initial = sink
            .recorded_one()
            .expect("start must record initial evidence");
        let evidence = block_on(executor.reconcile(operation_id.clone()))?;
        assert_eq!(evidence.operation_id(), &operation_id);
        assert!(evidence.view().lifecycle().is_terminal());
        assert_eq!(evidence.binding(), initial.binding());
        assert_eq!(evidence.operation_id(), initial.operation_id());
        // One record for the start plus one for the reconcile: no second
        // child was spawned.
        assert_eq!(sink.recorded_len(), 2);
        // A second start with the same operation identity must hit the
        // reservation instead of spawning another child. The argv
        // deliberately differs so only the operation identity can match.
        let (retry_request, _, _) = s04_authorized_request(
            "disconnect",
            vec!["/c".to_owned(), "echo".to_owned(), "retry-probe".to_owned()],
            4_096,
            4_096,
            4,
        )?;
        let retry_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        match block_on(executor.start(retry_request, retry_sink)) {
            Err(ProcessExecutionError::Unavailable(_)) => {}
            other => panic!("duplicate operation identity must hit the reservation, got {other:?}"),
        }
        assert_eq!(sink.recorded_len(), 2);
        let retained = block_on(executor.inspect(operation_id))?;
        assert_eq!(retained.operation_id(), evidence.operation_id());
        assert_eq!(retained.binding(), evidence.binding());
        Ok(())
    }
}
