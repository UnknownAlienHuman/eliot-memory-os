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
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessHealth,
    ProcessHealthStatus, ProcessId, ProcessLaunchAdmission, ProcessLifecycle, ProcessRequest,
    ProcessStartReceipt, ProcessState, SuspendedLaunchEvidence, SuspendedProcessIdentity,
    ValidatedDispatch,
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

/// Availability of one independent executor capability dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorCapabilityHealth {
    /// The capability is available for every currently known operation.
    Available,
    /// The capability remains available, but one or more operations are
    /// locally quarantined or have incomplete evidence.
    Degraded,
    /// The capability cannot currently be offered by this executor generation.
    Unavailable,
}

/// Stable class of an operation-local quarantine cause.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationQuarantineReason {
    /// A requested stdout/stderr capture owner could not be established or
    /// completed exactly.
    Capture,
    /// The physical child or Job could not be observed exactly.
    Observation,
    /// Cancellation or physical containment could not be completed exactly.
    Cancellation,
    /// Evidence construction or persistence failed for this operation.
    Evidence,
    /// Final stream/Job cleanup could not be proven complete.
    Cleanup,
}

/// Executor-generation health split by independent control/evidence dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorHealthSnapshot {
    new_starts: ExecutorCapabilityHealth,
    inspection: ExecutorCapabilityHealth,
    cancellation: ExecutorCapabilityHealth,
    evidence: ExecutorCapabilityHealth,
    cleanup: ExecutorCapabilityHealth,
    operation_count: usize,
    quarantined_operations: usize,
}

impl ExecutorHealthSnapshot {
    /// Returns whether this generation may admit a new start.
    pub const fn new_starts(&self) -> ExecutorCapabilityHealth {
        self.new_starts
    }

    /// Returns the aggregate existing-operation inspection capability.
    pub const fn inspection(&self) -> ExecutorCapabilityHealth {
        self.inspection
    }

    /// Returns the aggregate cancellation/containment capability.
    pub const fn cancellation(&self) -> ExecutorCapabilityHealth {
        self.cancellation
    }

    /// Returns the aggregate capture/evidence completeness capability.
    pub const fn evidence(&self) -> ExecutorCapabilityHealth {
        self.evidence
    }

    /// Returns the aggregate cleanup/reconciliation capability.
    pub const fn cleanup(&self) -> ExecutorCapabilityHealth {
        self.cleanup
    }

    /// Returns the number of retained operation owners.
    pub const fn operation_count(&self) -> usize {
        self.operation_count
    }

    /// Returns the number of operations requiring local reconciliation or cleanup.
    pub const fn quarantined_operations(&self) -> usize {
        self.quarantined_operations
    }
}

/// Operation-local health without exposing a raw child or Job handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationHealthSnapshot {
    operation_id: OperationId,
    lifecycle: ProcessLifecycle,
    quarantined: bool,
    cleanup_required: bool,
    evidence: ExecutorCapabilityHealth,
    identity_observed: bool,
    descendant_evidence_complete: bool,
    quarantine_reasons: Vec<OperationQuarantineReason>,
}

impl OperationHealthSnapshot {
    /// Returns the exact operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the provider-neutral process lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns whether this operation is locally fenced for reconciliation.
    pub const fn quarantined(&self) -> bool {
        self.quarantined
    }

    /// Returns whether P-04 must retain the physical cleanup owner.
    pub const fn cleanup_required(&self) -> bool {
        self.cleanup_required
    }

    /// Returns the operation-local capture/evidence dimension.
    pub const fn evidence(&self) -> ExecutorCapabilityHealth {
        self.evidence
    }

    /// Returns whether the exact resumed physical identity was observed.
    pub const fn identity_observed(&self) -> bool {
        self.identity_observed
    }

    /// Returns whether complete terminated-tree evidence is currently present.
    pub const fn descendant_evidence_complete(&self) -> bool {
        self.descendant_evidence_complete
    }

    /// Returns the stable local quarantine reason set.
    pub fn quarantine_reasons(&self) -> &[OperationQuarantineReason] {
        &self.quarantine_reasons
    }
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
#[derive(Debug)]
struct StreamCapture {
    requested: bool,
    bytes: Vec<u8>,
    limit: usize,
    total_bytes: u64,
    truncated: bool,
    complete: bool,
    read_error: bool,
    captured: bool,
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
    cleanup_required: bool,
    termination: Option<TerminatedJobChild>,
    capture_failures: Vec<CaptureFailure>,
    quarantine_reasons: Vec<OperationQuarantineReason>,
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
    start_gate_closed: AtomicBool,
}

struct OperationReservation<'a> {
    executor: &'a WindowsProcessExecutor,
    operation_id: OperationId,
}

impl Drop for OperationReservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut reservations) = self.executor.reservations.lock() {
            reservations.remove(&self.operation_id);
        } else {
            self.executor.close_new_starts_for_shared_fault();
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
            start_gate_closed: AtomicBool::new(false),
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
            start_gate_closed: AtomicBool::new(false),
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
            start_gate_closed: AtomicBool::new(false),
        }
    }

    /// Closes only new-start admission after evidence of a shared executor-
    /// generation fault. Existing operation inspection, cancellation and
    /// cleanup remain reachable and the generation cannot silently reopen.
    pub fn close_new_starts_for_shared_fault(&self) {
        self.start_gate_closed.store(true, Ordering::Release);
    }

    /// Returns the current executor-generation health vector.
    #[must_use]
    pub fn health(&self) -> ExecutorHealthSnapshot {
        #[cfg(windows)]
        {
            let new_starts = if self.start_gate_closed.load(Ordering::Acquire) {
                ExecutorCapabilityHealth::Unavailable
            } else {
                ExecutorCapabilityHealth::Available
            };
            let operations = match self.operations.lock() {
                Ok(operations) => operations,
                Err(_) => {
                    self.close_new_starts_for_shared_fault();
                    return ExecutorHealthSnapshot {
                        new_starts: ExecutorCapabilityHealth::Unavailable,
                        inspection: ExecutorCapabilityHealth::Unavailable,
                        cancellation: ExecutorCapabilityHealth::Unavailable,
                        evidence: ExecutorCapabilityHealth::Unavailable,
                        cleanup: ExecutorCapabilityHealth::Unavailable,
                        operation_count: 0,
                        quarantined_operations: 0,
                    };
                }
            };
            let operation_count = operations.len();
            let mut quarantined_operations = 0;
            let mut inspection_degraded = false;
            let mut cancellation_degraded = false;
            let mut evidence_degraded = false;
            let mut cleanup_degraded = false;
            for operation in operations.values() {
                let Ok(guard) = operation.lock() else {
                    quarantined_operations += 1;
                    inspection_degraded = true;
                    cancellation_degraded = true;
                    evidence_degraded = true;
                    cleanup_degraded = true;
                    continue;
                };
                if operation_is_quarantined(&guard) {
                    quarantined_operations += 1;
                    inspection_degraded = true;
                    cancellation_degraded = true;
                }
                if !guard.capture_failures.is_empty()
                    || guard.quarantine_reasons.iter().any(|reason| {
                        matches!(
                            reason,
                            OperationQuarantineReason::Capture
                                | OperationQuarantineReason::Evidence
                        )
                    })
                {
                    evidence_degraded = true;
                }
                if guard.cleanup_required {
                    cleanup_degraded = true;
                }
            }
            ExecutorHealthSnapshot {
                new_starts,
                inspection: health_from_degraded(inspection_degraded),
                cancellation: health_from_degraded(cancellation_degraded),
                evidence: health_from_degraded(evidence_degraded),
                cleanup: health_from_degraded(cleanup_degraded),
                operation_count,
                quarantined_operations,
            }
        }
        #[cfg(not(windows))]
        {
            ExecutorHealthSnapshot {
                new_starts: ExecutorCapabilityHealth::Unavailable,
                inspection: ExecutorCapabilityHealth::Unavailable,
                cancellation: ExecutorCapabilityHealth::Unavailable,
                evidence: ExecutorCapabilityHealth::Unavailable,
                cleanup: ExecutorCapabilityHealth::Unavailable,
                operation_count: 0,
                quarantined_operations: 0,
            }
        }
    }

    /// Returns one retained operation's local health and recovery disposition.
    ///
    /// # Errors
    /// Returns an error when the operation is absent, its local lock is
    /// unavailable, or this is not a Windows target.
    pub fn operation_health(
        &self,
        id: &OperationId,
    ) -> Result<OperationHealthSnapshot, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(id)?;
            let guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            let view = guard.state.view();
            let descendant_evidence_complete = view
                .descendants()
                .is_some_and(|evidence| evidence.complete() && evidence.tree_terminated());
            let evidence_degraded = !guard.capture_failures.is_empty()
                || guard.quarantine_reasons.iter().any(|reason| {
                    matches!(
                        reason,
                        OperationQuarantineReason::Capture | OperationQuarantineReason::Evidence
                    )
                });
            return Ok(OperationHealthSnapshot {
                operation_id: id.clone(),
                lifecycle: view.lifecycle(),
                quarantined: operation_is_quarantined(&guard),
                cleanup_required: guard.cleanup_required,
                evidence: health_from_degraded(evidence_degraded),
                identity_observed: view.identity().is_some(),
                descendant_evidence_complete,
                quarantine_reasons: guard.quarantine_reasons.clone(),
            });
        }
        #[cfg(not(windows))]
        {
            let _ = id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    fn shared_unavailable(&self, error: impl std::fmt::Display) -> ProcessExecutionError {
        self.close_new_starts_for_shared_fault();
        unavailable(error)
    }

    fn operation(&self, id: &OperationId) -> Result<Arc<Mutex<Operation>>, ProcessExecutionError> {
        self.operations
            .lock()
            .map_err(|_| self.shared_unavailable("operation registry lock poisoned"))?
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
            .map_err(|_| self.shared_unavailable("operation registry lock poisoned"))?;
        if operations.contains_key(&id) {
            return Err(unavailable("operation identity already exists"));
        }
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| self.shared_unavailable("operation reservation lock poisoned"))?;
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
                .map_err(|_| self.shared_unavailable("operation registry lock poisoned"))?;
            let mut ids = Vec::new();
            let mut cleanup_unknown = false;
            for (id, operation) in operations.iter() {
                let Ok(mut guard) = operation.lock() else {
                    cleanup_unknown = true;
                    continue;
                };
                if !guard.state.view().lifecycle().is_terminal() || guard.cleanup_required {
                    continue;
                }
                if !join_streams(&mut guard) {
                    quarantine_operation(&mut guard, OperationQuarantineReason::Cleanup);
                    cleanup_unknown = true;
                    continue;
                }
                ids.push(id.clone());
            }
            let count = ids.len();
            for id in ids {
                operations.remove(&id);
            }
            if cleanup_unknown {
                Err(ProcessExecutionError::UnknownOutcome)
            } else {
                Ok(count)
            }
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
                .map_err(|_| self.shared_unavailable("operation registry lock poisoned"))?;
            let mut retain_cleanup_owners = false;
            for operation in operations.values() {
                let Ok(mut guard) = operation.lock() else {
                    retain_cleanup_owners = true;
                    continue;
                };
                retain_cleanup_owners |= guard.cleanup_required
                    || guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome;
                if guard.child.is_some()
                    && guard.termination.is_none()
                    && finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err()
                {
                    quarantine_operation(&mut guard, OperationQuarantineReason::Cleanup);
                    retain_cleanup_owners = true;
                }
                if !join_streams(&mut guard) {
                    quarantine_operation(&mut guard, OperationQuarantineReason::Cleanup);
                    retain_cleanup_owners = true;
                }
            }
            if !retain_cleanup_owners {
                operations.clear();
                self.reservations
                    .lock()
                    .map_err(|_| self.shared_unavailable("operation reservation lock poisoned"))?
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
        if self.start_gate_closed.load(Ordering::Acquire) {
            return Err(unavailable(
                "shared executor-generation fault closed new process starts",
            ));
        }
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
            let receipt = ProcessStartReceipt::new(&state)?;
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
                timed_out: false,
                cleanup_required: false,
                termination: None,
                capture_failures: capture_failure.into_iter().collect(),
                quarantine_reasons: Vec::new(),
            }));
            self.operations
                .lock()
                .map_err(|_| self.shared_unavailable("operation registry lock poisoned"))?
                .insert(operation_id, Arc::clone(&operation));
            if let Some(error) = capture_spawn_error {
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                quarantine_operation(&mut guard, OperationQuarantineReason::Capture);
                return Err(error);
            }
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
            if let Err(error) = refresh_operation(&mut guard) {
                quarantine_operation(&mut guard, OperationQuarantineReason::Observation);
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
            let receipt = match guard.state.cancel(&CancellationRequest::new(binding)) {
                Ok(receipt) => receipt,
                Err(error) => {
                    quarantine_operation(&mut guard, OperationQuarantineReason::Cancellation);
                    return Err(error.into());
                }
            };
            if guard.state.view().lifecycle() == ProcessLifecycle::Cancelling
                && let Err(error) = finalize_operation(&mut guard, ExitDisposition::Cancelled, true)
            {
                quarantine_operation(&mut guard, OperationQuarantineReason::Cancellation);
                return Err(error);
            }
            Ok(receipt)
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
                quarantine_operation(&mut guard, OperationQuarantineReason::Observation);
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
                quarantine_operation(&mut guard, OperationQuarantineReason::Evidence);
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            let view = guard.state.view();
            let evidence = ProcessEvidence::new(
                view,
                capture_ref(&guard.stdout),
                capture_ref(&guard.stderr),
                EvidenceAxes::observed(),
            )?;
            if let Err(error) = guard.sink.record(evidence.clone()) {
                quarantine_operation(&mut guard, OperationQuarantineReason::Evidence);
                return Err(error.into());
            }
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
    let lifecycle = operation.state.view().lifecycle();
    if lifecycle == ProcessLifecycle::UnknownOutcome || lifecycle.is_terminal() {
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
fn quarantine_operation(operation: &mut Operation, reason: OperationQuarantineReason) {
    operation.cleanup_required = true;
    record_quarantine_reason(&mut operation.quarantine_reasons, reason);
    let _ = fence_unknown(operation);
}

fn record_quarantine_reason(
    reasons: &mut Vec<OperationQuarantineReason>,
    reason: OperationQuarantineReason,
) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
        reasons.sort_unstable();
    }
}

#[cfg(windows)]
fn operation_is_quarantined(operation: &Operation) -> bool {
    operation.cleanup_required
        || !operation.quarantine_reasons.is_empty()
        || matches!(
            operation.state.view().lifecycle(),
            ProcessLifecycle::UnknownOutcome | ProcessLifecycle::Quarantined
        )
}

const fn health_from_degraded(degraded: bool) -> ExecutorCapabilityHealth {
    if degraded {
        ExecutorCapabilityHealth::Degraded
    } else {
        ExecutorCapabilityHealth::Available
    }
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
                    // reason to detach the Job or close independent control.
                    // Fence only this operation and retain its cleanup owner.
                    quarantine_operation(&mut guard, OperationQuarantineReason::Observation);
                    return;
                }
            }
        });
}

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

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectingAuthority;

    impl DispatchValidationPort for RejectingAuthority {
        fn validate_and_consume(
            &self,
            _request: ProcessRequest,
            _observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            Err(unavailable("test authority rejects execution"))
        }
    }

    fn executor() -> WindowsProcessExecutor {
        WindowsProcessExecutor::new(Arc::new(RejectingAuthority))
    }

    #[test]
    fn shared_fault_closes_only_new_start_admission() {
        let executor = executor();
        executor.close_new_starts_for_shared_fault();
        assert!(executor.start_gate_closed.load(Ordering::Acquire));

        let source = include_str!("lib.rs");
        assert_eq!(
            source
                .matches("start_gate_closed.load(Ordering::Acquire)")
                .count(),
            2,
            "the start gate may be read only by start and the health projection"
        );
        assert!(!source.contains("poison_operation"));
        assert!(!source.contains("poisoned: Arc<AtomicBool>"));
    }

    #[test]
    fn local_quarantine_reason_set_is_stable_and_unique() {
        let mut reasons = Vec::new();
        record_quarantine_reason(&mut reasons, OperationQuarantineReason::Cleanup);
        record_quarantine_reason(&mut reasons, OperationQuarantineReason::Capture);
        record_quarantine_reason(&mut reasons, OperationQuarantineReason::Cleanup);
        assert_eq!(
            reasons,
            vec![
                OperationQuarantineReason::Capture,
                OperationQuarantineReason::Cleanup
            ]
        );
    }

    #[test]
    fn aggregate_health_does_not_conflate_degraded_with_unavailable() {
        assert_eq!(
            health_from_degraded(false),
            ExecutorCapabilityHealth::Available
        );
        assert_eq!(
            health_from_degraded(true),
            ExecutorCapabilityHealth::Degraded
        );
        assert_ne!(
            health_from_degraded(true),
            ExecutorCapabilityHealth::Unavailable
        );
    }
}
