use anyhow::{Context, Result, anyhow, bail};
use eliot_engine::{
    BoxProviderProcessFuture, ProviderProcessOutcome, ProviderProcessRunner, ProviderProcessSpec,
    runtime_supervision::{AdapterExecutionContext, CancellationToken},
};
use eliot_types::{
    DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION, DescendantFileIdentity, DescendantProcessSnapshot,
    DescendantsAtRootExit, DescendantsAtRootExitFailed, DescendantsCaptureErrorKind,
    OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION, OperationCancellationState, OperationPhase,
    OperationReconciliationState, OperationRuntimeCheckpoint, ProcessReapReceipt,
    ProviderDispatchState, ProviderTimeoutClass,
};
use eliot_windows_ipc::{RecoverableJobObject, SuspendedJobChild};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::mpsc;

const SUPERVISED_TERMINATION_CODE: u32 = 0xE110_7001;
// `connect_global_client` can spend one 10s window waiting for publication and
// a second 10s window opening a busy pipe.  Preserve those healthy transport
// budgets, the 2s handshake, and a bounded local response margin while still
// rejecting a peer that accepts the request and never replies.
const DAEMON_OPERATION_RUNTIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[path = "supervised_process_contract.rs"]
mod supervised_process_contract;

pub use supervised_process_contract::{
    ChildCriticality, ProcessRestartPolicy, RestartStrategy, SupervisedChildKind,
    SupervisedProcessOutput, SupervisedProcessSpec,
};

#[derive(Clone, Debug)]
enum ProcessProgress {
    Spawned {
        pid: u32,
        process_count: u32,
        job_name: String,
        process_start_ticks: Option<u64>,
        executable_sha256: Option<String>,
    },
    DispatchProven,
    Stdin(u64),
    Stdout(u64),
    Stderr(u64),
    ProcessCount(u32),
    Exited,
    Reaping,
}

struct PipeCapture {
    bytes: Vec<u8>,
    total_bytes: u64,
    terminal: bool,
    error_code: Option<u32>,
}

struct WorkerOutput {
    output: SupervisedProcessOutput,
}

struct WorkerThread<T> {
    result_rx: std_mpsc::Receiver<T>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
struct OutputActivity {
    first_at: Option<Instant>,
    last_at: Option<Instant>,
}

struct DaemonOperationRuntimeProxy {
    instance: crate::runtime_instance::RuntimeInstance,
}

impl eliot_engine::OperationRuntimeProxy for DaemonOperationRuntimeProxy {
    fn request(
        &self,
        request: eliot_engine::OperationRuntimeRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<
                        eliot_engine::OperationRuntimeResponse,
                        eliot_engine::EngineError,
                    >,
                > + Send
                + '_,
        >,
    > {
        let instance = self.instance.clone();
        Box::pin(async move {
            let params = serde_json::to_value(request).map_err(|error| {
                eliot_engine::EngineError::RuntimeSupervision(format!(
                    "encode daemon operation-runtime request: {error}"
                ))
            })?;
            let response = bounded_operation_runtime_request(
                DAEMON_OPERATION_RUNTIME_REQUEST_TIMEOUT,
                crate::named_pipe_ipc::host_governor_request(
                    &instance,
                    "runtime/operation",
                    params,
                ),
            )
            .await
            .map_err(|error| {
                eliot_engine::EngineError::RuntimeSupervision(format!(
                    "daemon operation-runtime request failed: {error:#}"
                ))
            })?;
            serde_json::from_value(response).map_err(|error| {
                eliot_engine::EngineError::RuntimeSupervision(format!(
                    "decode daemon operation-runtime response: {error}"
                ))
            })
        })
    }
}

async fn bounded_operation_runtime_request<F, T>(timeout: Duration, request: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    tokio::time::timeout(timeout, request)
        .await
        .context("daemon operation-runtime request timed out")?
}

pub fn daemon_operation_runtime_handle(
    config_path: &Path,
) -> Result<eliot_engine::OperationRuntimeHandle> {
    Ok(daemon_operation_runtime_handle_for_runtime_instance(
        default_daemon_runtime_instance(config_path)?,
    ))
}

pub fn daemon_operation_runtime_handle_for_instance(
    config_path: &Path,
    instance: Option<&str>,
) -> Result<eliot_engine::OperationRuntimeHandle> {
    let instance = crate::runtime_instance::RuntimeInstance::select(config_path, instance)?;
    Ok(daemon_operation_runtime_handle_for_runtime_instance(
        instance,
    ))
}

fn default_daemon_runtime_instance(
    config_path: &Path,
) -> Result<crate::runtime_instance::RuntimeInstance> {
    super::host_governor_instance(config_path)
}

fn daemon_operation_runtime_handle_for_runtime_instance(
    instance: crate::runtime_instance::RuntimeInstance,
) -> eliot_engine::OperationRuntimeHandle {
    eliot_engine::OperationRuntimeHandle::from_proxy(Arc::new(DaemonOperationRuntimeProxy {
        instance,
    }))
}

pub struct SupervisedWindowsProcessRunner {
    runtime_store: eliot_engine::OperationRuntimeHandle,
}

impl SupervisedWindowsProcessRunner {
    pub(super) fn from_runtime_store(runtime_store: eliot_engine::OperationRuntimeHandle) -> Self {
        Self { runtime_store }
    }
}

impl ProviderProcessRunner for SupervisedWindowsProcessRunner {
    fn run<'a>(
        &'a self,
        spec: ProviderProcessSpec,
        on_spawned: &'a mut (dyn FnMut(u32) -> Result<(), eliot_engine::EngineError> + Send),
    ) -> BoxProviderProcessFuture<'a> {
        Box::pin(async move {
            let operation_id = spec.operation_id.clone();
            let route_policy = spec.route_policy;
            let process_spec = SupervisedProcessSpec {
                operation_id: spec.operation_id,
                invocation_id: spec.invocation_id,
                generation: 1,
                child_kind: SupervisedChildKind::Provider,
                criticality: ChildCriticality::InvocationDependency,
                restart_policy: ProcessRestartPolicy {
                    strategy: RestartStrategy::Never,
                    max_restarts: 0,
                    restart_window_seconds: 60,
                    base_backoff_ms: 0,
                    pre_dispatch_only: false,
                },
                executable: spec.executable,
                args: spec.args,
                cwd: spec.cwd,
                environment: spec.environment.into_iter().collect(),
                stdin_payload: spec.stdin_payload,
                stdout_limit_bytes: route_policy.output_limit_bytes(),
                stderr_limit_bytes: route_policy.output_limit_bytes(),
                timeout_profile: route_policy.timeout_profile().clone(),
                runtime_contract_sha256: spec.runtime_contract_sha256.clone(),
                role_lease_id: spec.role_lease_id.clone(),
                role_lease_epoch: spec.role_lease_epoch,
            };
            let context = AdapterExecutionContext {
                operation_id,
                generation: 1,
                cancellation: spec.cancellation,
                deadline: spec.deadline,
                runtime_store: self.runtime_store.clone(),
                role_lease_id: spec.role_lease_id,
                role_lease_epoch: spec.role_lease_epoch,
                runtime_contract_sha256: spec.runtime_contract_sha256,
            };
            let result = run_supervised_process_with_spawn_hook(process_spec, context, |pid| {
                on_spawned(pid).map_err(|error| anyhow!(error.to_string()))
            })
            .await
            .map_err(|error| {
                eliot_engine::EngineError::RuntimeSupervision(format!(
                    "supervised provider execution failed: {error:#}"
                ))
            })?;
            Ok(ProviderProcessOutcome {
                exit_code: result.exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                stdout_total_bytes: result.stdout_total_bytes,
                stderr_total_bytes: result.stderr_total_bytes,
                stdout_truncated: result.stdout_truncated,
                stderr_truncated: result.stderr_truncated,
                timed_out: result.timed_out,
                timeout_class: result.timeout_class,
                cancelled: result.cancelled,
                worker_error: result.worker_error,
                observed_processes: result.observed_processes,
                process_started_at: result.process_started_at,
                first_output_at: result.first_output_at,
                last_output_at: result.last_output_at,
                process_exit_at: result.process_exit_at,
                cleanup_completed_at: result.cleanup_completed_at,
                reap_receipt: result.reap_receipt,
            })
        })
    }
}

#[cfg(test)]
pub struct ScriptedProviderProcessRunner {
    outcomes: Mutex<std::collections::VecDeque<ProviderProcessOutcome>>,
    specs: Mutex<Vec<ProviderProcessSpec>>,
    completion_delay: Duration,
    calls: AtomicUsize,
}

#[cfg(test)]
impl ScriptedProviderProcessRunner {
    pub fn new(outcomes: impl IntoIterator<Item = ProviderProcessOutcome>) -> Self {
        Self::with_delay(outcomes, Duration::ZERO)
    }

    pub fn with_delay(
        outcomes: impl IntoIterator<Item = ProviderProcessOutcome>,
        completion_delay: Duration,
    ) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            specs: Mutex::new(Vec::new()),
            completion_delay,
            calls: AtomicUsize::new(0),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn specs(&self) -> Result<Vec<ProviderProcessSpec>, eliot_engine::EngineError> {
        self.specs.lock().map(|specs| specs.clone()).map_err(|_| {
            eliot_engine::EngineError::RuntimeSupervision(
                "scripted provider process spec lock is poisoned".to_owned(),
            )
        })
    }
}

#[cfg(test)]
impl ProviderProcessRunner for ScriptedProviderProcessRunner {
    fn run<'a>(
        &'a self,
        spec: ProviderProcessSpec,
        on_spawned: &'a mut (dyn FnMut(u32) -> Result<(), eliot_engine::EngineError> + Send),
    ) -> BoxProviderProcessFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.specs
                .lock()
                .map_err(|_| {
                    eliot_engine::EngineError::RuntimeSupervision(
                        "scripted provider process spec lock is poisoned".to_owned(),
                    )
                })?
                .push(spec);
            let outcome = self
                .outcomes
                .lock()
                .map_err(|_| {
                    eliot_engine::EngineError::RuntimeSupervision(
                        "scripted provider process outcome lock is poisoned".to_owned(),
                    )
                })?
                .pop_front()
                .ok_or_else(|| {
                    eliot_engine::EngineError::RuntimeSupervision(
                        "scripted provider process outcome is exhausted before spawn".to_owned(),
                    )
                })?;
            let pid = outcome.reap_receipt.root_pid.ok_or_else(|| {
                eliot_engine::EngineError::RuntimeSupervision(
                    "scripted provider process outcome has no process identity".to_owned(),
                )
            })?;
            if let Err(error) = on_spawned(pid) {
                let mut outcome = outcome;
                record_worker_error(
                    &mut outcome.worker_error,
                    format!("post-spawn scripted callback failed: {error}"),
                );
                return Ok(outcome);
            }
            tokio::time::sleep(self.completion_delay).await;
            Ok(outcome)
        })
    }
}

pub async fn run_supervised_process(
    spec: SupervisedProcessSpec,
    context: AdapterExecutionContext,
) -> Result<SupervisedProcessOutput> {
    run_supervised_process_with_spawn_hook(spec, context, |_| Ok(())).await
}

#[allow(
    clippy::too_many_lines,
    reason = "the supervision state machine keeps spawn admission, persistence, cancellation, and reap ordering explicit"
)]
pub async fn run_supervised_process_with_spawn_hook<F>(
    spec: SupervisedProcessSpec,
    context: AdapterExecutionContext,
    on_spawned: F,
) -> Result<SupervisedProcessOutput>
where
    F: FnOnce(u32) -> Result<()>,
{
    validate_spec(&spec)?;
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel();
    let (admission_tx, admission_rx) = std_mpsc::sync_channel(1);
    let progress_operation_id = spec.operation_id.clone();
    let runtime_store = context.runtime_store.clone();
    let mut initial_checkpoint = operation_checkpoint(&spec);
    if let Some(existing) = runtime_store
        .get_checkpoint(spec.operation_id.clone())
        .await?
        && existing.generation == spec.generation
    {
        if initial_checkpoint.invocation_id.is_none() {
            initial_checkpoint.invocation_id = existing.invocation_id;
        }
        initial_checkpoint.adapter_id = existing.adapter_id;
        initial_checkpoint.restart_count = existing.restart_count;
        initial_checkpoint.restart_window_started_at = existing.restart_window_started_at;
        if initial_checkpoint.role_lease_id.is_none() {
            initial_checkpoint.role_lease_id = existing.role_lease_id;
        }
        if initial_checkpoint.role_lease_epoch.is_none() {
            initial_checkpoint.role_lease_epoch = existing.role_lease_epoch;
        }
        if initial_checkpoint.runtime_contract_sha256.is_none() {
            initial_checkpoint.runtime_contract_sha256 = existing.runtime_contract_sha256;
        }
        initial_checkpoint.last_evidence_refs = existing.last_evidence_refs;
    }
    runtime_store
        .put_checkpoint(initial_checkpoint)
        .await
        .context("persist supervised operation before spawn")?;
    let cancellation = context.cancellation.clone();
    let worker_context = context.clone();
    let worker_progress_tx = progress_tx.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        run_worker(
            spec,
            &worker_context.cancellation,
            Some(worker_context.deadline.into_std()),
            &worker_progress_tx,
            spawned_tx,
            &admission_rx,
        )
    });
    let spawn_callback = match spawned_rx.await {
        Ok(Ok(pid)) => on_spawned(pid),
        Ok(Err(error)) => Err(anyhow!(error)),
        Err(_) => Err(anyhow!(
            "supervised process worker ended before reporting spawn state"
        )),
    };
    let spawn_callback_succeeded = spawn_callback.is_ok();
    if spawn_callback_succeeded {
        let _ = progress_tx.send(ProcessProgress::DispatchProven);
    }
    let _ = admission_tx.send(spawn_callback_succeeded);
    let spawn_callback_error = spawn_callback.err().map(|error| error.to_string());
    let mut persistence_error = None;
    let mut cancellation_poll = tokio::time::interval(Duration::from_millis(250));
    cancellation_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            outcome = &mut worker => {
                let mut outcome = outcome.context("supervised process worker panicked")??;
                while let Ok(progress) = progress_rx.try_recv() {
                    if persistence_error.is_none()
                        && let Err(error) =
                            persist_progress(&runtime_store, &progress_operation_id, progress).await
                    {
                        cancellation.cancel();
                        persistence_error = Some(error);
                    }
                }
                if let Some(error) = spawn_callback_error {
                    record_worker_error(
                        &mut outcome.output.worker_error,
                        format!("post-spawn admission callback failed: {error}"),
                    );
                }
                if let Some(error) = persistence_error {
                    record_worker_error(
                        &mut outcome.output.worker_error,
                        format!(
                            "runtime checkpoint persistence failed after spawn; child was cancelled and reaped: {error:#}"
                        ),
                    );
                }
                if let Err(error) =
                    persist_terminal(&runtime_store, &progress_operation_id, &outcome.output).await
                {
                    record_worker_error(
                        &mut outcome.output.worker_error,
                        format!("persist terminal supervised process checkpoint: {error:#}"),
                    );
                }
                return Ok(outcome.output);
            }
            progress = progress_rx.recv() => {
                if persistence_error.is_none()
                    && let Some(progress) = progress
                    && let Err(error) =
                        persist_progress(&runtime_store, &progress_operation_id, progress).await
                {
                    cancellation.cancel();
                    persistence_error = Some(error);
                }
            }
            _ = cancellation_poll.tick(), if runtime_store.is_enabled() && !cancellation.is_cancelled() => {
                match runtime_store.get_checkpoint(progress_operation_id.clone()).await {
                    Ok(Some(checkpoint)) if checkpoint_requests_process_cancellation(&checkpoint) => {
                        cancellation.cancel();
                    }
                    Err(error) => {
                        if persistence_error.is_none() {
                            cancellation.cancel();
                            persistence_error = Some(anyhow!(error).context(
                                "poll daemon-owned operation cancellation",
                            ));
                        }
                    }
                    Ok(_) => {}
                }
            }
        }
    }
}

pub fn run_supervised_process_blocking(
    spec: SupervisedProcessSpec,
    context: AdapterExecutionContext,
) -> Result<SupervisedProcessOutput> {
    std::thread::Builder::new()
        .name("eliot-supervised-blocking-runtime".to_owned())
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build supervised blocking Tokio runtime")?
                .block_on(run_supervised_process(spec, context))
        })
        .context("spawn supervised blocking runtime thread")?
        .join()
        .map_err(|_| anyhow!("supervised blocking runtime thread panicked"))?
}

#[allow(
    clippy::too_many_lines,
    reason = "startup recovery keeps every durable checkpoint transition adjacent to its reap outcome"
)]
pub async fn recover_stale_job_objects(
    runtime_store: &eliot_engine::OperationRuntimeHandle,
    now: OffsetDateTime,
    include_unexpired_startup_orphans: bool,
) -> Result<Vec<ProcessReapReceipt>> {
    let mut receipts = Vec::new();
    for mut checkpoint in runtime_store.list_nonterminal_checkpoints().await? {
        if !checkpoint_requires_process_recovery(
            &checkpoint,
            now,
            include_unexpired_startup_orphans,
        ) {
            continue;
        }
        let started = Instant::now();
        let recovery_checkpoint = checkpoint.clone();
        let recovery = tokio::task::spawn_blocking(move || {
            recover_checkpoint_process_tree(&recovery_checkpoint, Duration::from_secs(5))
        })
        .await
        .context("startup process recovery worker panicked")?;
        let recovery = recovery_or_identity_unproven(recovery);
        match recovery {
            StartupProcessRecovery::JobReaped {
                job_name,
                process_count_before,
                process_count_after,
                forced_termination,
                empty,
            } => {
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let descendants_at_root_exit = DescendantsAtRootExit::failed(
                    checkpoint.root_pid,
                    None,
                    elapsed_ms,
                    DescendantsCaptureErrorKind::EnumerationFailed,
                    "startup recovery: no live root-exit descendant capture",
                )
                .unwrap_or(DescendantsAtRootExit::Failed(DescendantsAtRootExitFailed {
                    schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
                    root_pid: checkpoint.root_pid,
                    root_exit_code: None,
                    capture_elapsed_ms: elapsed_ms,
                    error_kind: DescendantsCaptureErrorKind::EnumerationFailed,
                    detail: "startup recovery".to_owned(),
                }));
                let receipt = ProcessReapReceipt {
                    operation_id: checkpoint.operation_id.clone(),
                    generation: checkpoint.generation,
                    job_object_name: job_name,
                    root_pid: checkpoint.root_pid,
                    process_count_before,
                    process_count_after,
                    graceful_attempted: false,
                    forced_termination,
                    stdout_closed: empty,
                    stderr_closed: empty,
                    all_tasks_joined: empty,
                    elapsed_ms,
                    terminal_error_codes: Vec::new(),
                    descendants_at_root_exit,
                };
                checkpoint.active_process_count = process_count_after;
                checkpoint.cancellation_state = if receipt.proves_complete_reap() {
                    eliot_types::OperationCancellationState::Reaped
                } else {
                    eliot_types::OperationCancellationState::Forced
                };
                let reconciliation_required =
                    checkpoint.dispatch_state != ProviderDispatchState::NotStarted;
                checkpoint.phase = if reconciliation_required || !receipt.proves_complete_reap() {
                    OperationPhase::Reconciling
                } else {
                    OperationPhase::Failed
                };
                checkpoint.reconciliation_state = if reconciliation_required {
                    OperationReconciliationState::Pending
                } else if receipt.proves_complete_reap() {
                    OperationReconciliationState::NotRequired
                } else {
                    OperationReconciliationState::Failed
                };
                checkpoint.last_error_class = Some(if receipt.proves_complete_reap() {
                    "startup_reaped_stale_job".to_owned()
                } else {
                    "startup_job_reap_incomplete".to_owned()
                });
                checkpoint.last_progress_at = now;
                runtime_store.put_checkpoint(checkpoint).await?;
                receipts.push(receipt);
            }
            StartupProcessRecovery::VerifiedRootReaped { job_name, root_pid } => {
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let descendants_at_root_exit = DescendantsAtRootExit::failed(
                    Some(root_pid),
                    None,
                    elapsed_ms,
                    DescendantsCaptureErrorKind::EnumerationFailed,
                    "startup recovery: verified root without live descendant capture",
                )
                .unwrap_or(DescendantsAtRootExit::Failed(DescendantsAtRootExitFailed {
                    schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
                    root_pid: Some(root_pid),
                    root_exit_code: None,
                    capture_elapsed_ms: elapsed_ms,
                    error_kind: DescendantsCaptureErrorKind::EnumerationFailed,
                    detail: "startup recovery".to_owned(),
                }));
                let receipt = ProcessReapReceipt {
                    operation_id: checkpoint.operation_id.clone(),
                    generation: checkpoint.generation,
                    job_object_name: job_name,
                    root_pid: Some(root_pid),
                    process_count_before: 1,
                    process_count_after: 0,
                    graceful_attempted: false,
                    forced_termination: true,
                    stdout_closed: true,
                    stderr_closed: true,
                    all_tasks_joined: true,
                    elapsed_ms,
                    terminal_error_codes: Vec::new(),
                    descendants_at_root_exit,
                };
                checkpoint.active_process_count = 0;
                checkpoint.cancellation_state = eliot_types::OperationCancellationState::Reaped;
                if checkpoint.dispatch_state == ProviderDispatchState::NotStarted {
                    checkpoint.phase = OperationPhase::Failed;
                    checkpoint.reconciliation_state = OperationReconciliationState::NotRequired;
                } else {
                    checkpoint.phase = OperationPhase::Reconciling;
                    checkpoint.reconciliation_state = OperationReconciliationState::Pending;
                }
                checkpoint.last_progress_at = now;
                checkpoint.last_error_class =
                    Some("startup_verified_pre_job_root_reaped".to_owned());
                runtime_store.put_checkpoint(checkpoint).await?;
                receipts.push(receipt);
            }
            StartupProcessRecovery::IdentityUnproven(reason) => {
                checkpoint.phase = OperationPhase::Reconciling;
                checkpoint.reconciliation_state = OperationReconciliationState::Pending;
                checkpoint.last_error_class =
                    Some(format!("startup_process_identity_unproven:{reason}"));
                checkpoint.last_evidence_refs.push(format!(
                    "runtime-integrity:identity-unproven:{}",
                    checkpoint.operation_id
                ));
                runtime_store.put_checkpoint(checkpoint).await?;
            }
        }
    }
    runtime_store
        .put_recovery_cursor(now.format(&time::format_description::well_known::Rfc3339)?)
        .await?;
    Ok(receipts)
}

fn checkpoint_requires_process_recovery(
    checkpoint: &OperationRuntimeCheckpoint,
    now: OffsetDateTime,
    include_unexpired_startup_orphans: bool,
) -> bool {
    include_unexpired_startup_orphans
        || checkpoint.cancellation_state != OperationCancellationState::NotRequested
        || now > checkpoint.phase_deadline_at
        || now > checkpoint.absolute_deadline_at
}

fn checkpoint_requests_process_cancellation(checkpoint: &OperationRuntimeCheckpoint) -> bool {
    checkpoint.cancellation_state != OperationCancellationState::NotRequested
        || matches!(
            checkpoint.phase,
            OperationPhase::Cancelling
                | OperationPhase::Reaping
                | OperationPhase::Failed
                | OperationPhase::Abandoned
        )
}

enum StartupProcessRecovery {
    JobReaped {
        job_name: String,
        process_count_before: u32,
        process_count_after: u32,
        forced_termination: bool,
        empty: bool,
    },
    VerifiedRootReaped {
        job_name: String,
        root_pid: u32,
    },
    IdentityUnproven(String),
}

fn recovery_or_identity_unproven(
    recovery: Result<StartupProcessRecovery>,
) -> StartupProcessRecovery {
    recovery.unwrap_or_else(|error| {
        StartupProcessRecovery::IdentityUnproven(format!("process_recovery_failed:{error:#}"))
    })
}

fn recover_checkpoint_process_tree(
    checkpoint: &OperationRuntimeCheckpoint,
    cleanup_grace: Duration,
) -> Result<StartupProcessRecovery> {
    let Some(job_name) = checkpoint.job_object_name.clone() else {
        return Ok(StartupProcessRecovery::IdentityUnproven(
            "missing_job_object_name".to_owned(),
        ));
    };
    match eliot_windows_ipc::RecoverableJobObject::open(&job_name) {
        Ok(job) => {
            let process_count_before = job
                .active_process_count()
                .context("query reopened Job Object before recovery")?;
            let forced_termination = process_count_before > 0;
            if forced_termination {
                job.terminate(SUPERVISED_TERMINATION_CODE)
                    .context("terminate reopened Job Object during recovery")?;
            }
            let empty = job
                .wait_for_empty(cleanup_grace)
                .context("wait for reopened Job Object recovery")?;
            let process_count_after = job
                .active_process_count()
                .context("query reopened Job Object after recovery")?;
            Ok(StartupProcessRecovery::JobReaped {
                job_name,
                process_count_before,
                process_count_after,
                forced_termination,
                empty,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (Some(root_pid), Some(expected_start_ticks), Some(expected_sha256)) = (
                checkpoint.root_pid,
                checkpoint.root_process_start_ticks,
                checkpoint.root_executable_sha256.as_deref(),
            ) else {
                return Ok(StartupProcessRecovery::IdentityUnproven(
                    "job_absent_and_root_identity_incomplete".to_owned(),
                ));
            };
            let process = match eliot_windows_ipc::RecoverableProcess::open(root_pid) {
                Ok(process) => process,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(StartupProcessRecovery::IdentityUnproven(
                        "job_and_root_pid_absent_without_reap_receipt".to_owned(),
                    ));
                }
                Err(error) => return Err(error.into()),
            };
            let actual_start_ticks = process.start_ticks()?;
            if actual_start_ticks != expected_start_ticks {
                return Ok(StartupProcessRecovery::IdentityUnproven(format!(
                    "root_start_ticks_mismatch:expected={expected_start_ticks}:actual={actual_start_ticks}"
                )));
            }
            let actual_sha256 = sha256_file(&process.identity().image)?;
            if actual_sha256 != expected_sha256 {
                return Ok(StartupProcessRecovery::IdentityUnproven(format!(
                    "root_executable_sha256_mismatch:expected={expected_sha256}:actual={actual_sha256}"
                )));
            }
            process.terminate(SUPERVISED_TERMINATION_CODE)?;
            if !process.wait_timeout(cleanup_grace)? {
                return Ok(StartupProcessRecovery::IdentityUnproven(
                    "verified_root_termination_wait_timed_out".to_owned(),
                ));
            }
            Ok(StartupProcessRecovery::VerifiedRootReaped { job_name, root_pid })
        }
        Err(error) => Ok(StartupProcessRecovery::IdentityUnproven(format!(
            "job_open_failed:{error}"
        ))),
    }
}

fn validate_spec(spec: &SupervisedProcessSpec) -> Result<()> {
    if spec.operation_id.trim().is_empty() {
        bail!("supervised process operation_id is empty");
    }
    if spec.invocation_id.as_deref().is_some_and(str::is_empty) {
        bail!("supervised process invocation_id cannot be empty");
    }
    if !spec.executable.is_file() {
        bail!(
            "supervised process executable is not a file: {}",
            spec.executable.display()
        );
    }
    if !spec.cwd.is_dir() {
        bail!(
            "supervised process cwd is not a directory: {}",
            spec.cwd.display()
        );
    }
    if spec.timeout_profile.absolute_runtime_deadline_ms() == 0 {
        bail!("absolute runtime deadline must be non-zero");
    }
    if spec.timeout_profile.cleanup_grace_ms() == 0 {
        bail!("cleanup grace must be non-zero");
    }
    if spec.restart_policy.max_restarts > 0 && spec.restart_policy.restart_window_seconds == 0 {
        bail!("restart window must be non-zero when restarts are enabled");
    }
    if spec.restart_policy.max_restarts > 0
        && spec.restart_policy.pre_dispatch_only
        && !matches!(spec.restart_policy.strategy, RestartStrategy::OneForOne)
    {
        bail!("pre-dispatch-only restart requires a restart strategy");
    }
    if spec
        .runtime_contract_sha256
        .as_deref()
        .is_some_and(str::is_empty)
        || spec.role_lease_id.as_deref().is_some_and(str::is_empty)
    {
        bail!("runtime contract and role lease identifiers cannot be empty");
    }
    Ok(())
}

fn operation_checkpoint(spec: &SupervisedProcessSpec) -> OperationRuntimeCheckpoint {
    let now = OffsetDateTime::now_utc();
    let absolute_deadline_at = now
        + time::Duration::milliseconds(
            i64::try_from(spec.timeout_profile.absolute_runtime_deadline_ms()).unwrap_or(i64::MAX),
        );
    // The checkpoint is persisted through the daemon before the worker owns a
    // PID and named Job Object.  That IPC latency must not consume the local
    // spawn-admission budget: a daemon watchdog cannot safely recover a
    // pre-spawn checkpoint which has no process identity.  The worker enforces
    // `spawn_deadline_ms` after the process is created; durable progress moves
    // this checkpoint to `Running` and keeps the absolute deadline.
    let phase_deadline_at = absolute_deadline_at;
    OperationRuntimeCheckpoint {
        schema_version: OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION.to_owned(),
        operation_id: spec.operation_id.clone(),
        invocation_id: spec.invocation_id.clone(),
        adapter_id: None,
        generation: spec.generation,
        phase: OperationPhase::Prepared,
        dispatch_state: ProviderDispatchState::NotStarted,
        cancellation_state: OperationCancellationState::NotRequested,
        reconciliation_state: OperationReconciliationState::NotRequired,
        root_pid: None,
        root_process_start_ticks: None,
        root_executable_sha256: None,
        job_object_name: None,
        active_process_count: 0,
        stdin_bytes: 0,
        stdout_bytes: 0,
        stderr_bytes: 0,
        phase_started_at: now,
        last_progress_at: now,
        phase_deadline_at,
        absolute_deadline_at,
        restart_count: 0,
        restart_window_started_at: (spec.restart_policy.max_restarts > 0)
            .then(|| now.unix_timestamp().to_string()),
        role_lease_id: spec.role_lease_id.clone(),
        role_lease_epoch: spec.role_lease_epoch,
        runtime_contract_sha256: spec.runtime_contract_sha256.clone(),
        last_error_class: None,
        last_evidence_refs: vec![
            format!("child_kind:{:?}", spec.child_kind).to_ascii_lowercase(),
            format!("criticality:{:?}", spec.criticality).to_ascii_lowercase(),
        ],
    }
}

async fn persist_progress(
    runtime_store: &eliot_engine::OperationRuntimeHandle,
    operation_id: &str,
    progress: ProcessProgress,
) -> Result<()> {
    let Some(mut checkpoint) = runtime_store.get_checkpoint(operation_id).await? else {
        return Ok(());
    };
    checkpoint.last_progress_at = OffsetDateTime::now_utc();
    match progress {
        ProcessProgress::Spawned {
            pid,
            process_count,
            job_name,
            process_start_ticks,
            executable_sha256,
        } => {
            checkpoint.phase = OperationPhase::Running;
            checkpoint.dispatch_state = ProviderDispatchState::Starting;
            checkpoint.root_pid = Some(pid);
            checkpoint.root_process_start_ticks = process_start_ticks;
            checkpoint.root_executable_sha256 = executable_sha256;
            checkpoint.active_process_count = process_count;
            checkpoint.job_object_name = Some(job_name);
            checkpoint.phase_started_at = checkpoint.last_progress_at;
            checkpoint.phase_deadline_at = checkpoint.absolute_deadline_at;
        }
        ProcessProgress::DispatchProven => {
            checkpoint.dispatch_state = ProviderDispatchState::Proven;
        }
        ProcessProgress::Stdin(bytes) => checkpoint.stdin_bytes = bytes,
        ProcessProgress::Stdout(bytes) => checkpoint.stdout_bytes = bytes,
        ProcessProgress::Stderr(bytes) => checkpoint.stderr_bytes = bytes,
        ProcessProgress::ProcessCount(count) => checkpoint.active_process_count = count,
        ProcessProgress::Exited => checkpoint.phase = OperationPhase::OutputDraining,
        ProcessProgress::Reaping => checkpoint.phase = OperationPhase::Reaping,
    }
    runtime_store.put_checkpoint(checkpoint).await?;
    Ok(())
}

async fn persist_terminal(
    runtime_store: &eliot_engine::OperationRuntimeHandle,
    operation_id: &str,
    output: &SupervisedProcessOutput,
) -> Result<()> {
    let Some(mut checkpoint) = runtime_store.get_checkpoint(operation_id).await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    checkpoint.phase = if output.exit_code == Some(0)
        && !output.timed_out
        && output.worker_error.is_none()
        && output.reap_receipt.proves_complete_reap()
    {
        OperationPhase::Completed
    } else {
        OperationPhase::Failed
    };
    checkpoint.cancellation_state = if output.reap_receipt.proves_complete_reap() {
        OperationCancellationState::Reaped
    } else if output.reap_receipt.forced_termination {
        OperationCancellationState::Forced
    } else {
        checkpoint.cancellation_state
    };
    checkpoint.active_process_count = output.reap_receipt.process_count_after;
    checkpoint.stdout_bytes = output.stdout_total_bytes;
    checkpoint.stderr_bytes = output.stderr_total_bytes;
    checkpoint.last_progress_at = now;
    checkpoint.last_error_class = output.worker_error.clone().or_else(|| {
        output
            .timed_out
            .then(|| "supervised_process_timeout".to_owned())
    });
    checkpoint.last_evidence_refs.push(format!(
        "reap:{}:{}",
        output.reap_receipt.job_object_name, output.reap_receipt.process_count_after
    ));
    runtime_store.put_checkpoint(checkpoint).await?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the worker state machine keeps process ownership, deadline handling, and bounded reap in one auditable scope"
)]
fn run_worker(
    spec: SupervisedProcessSpec,
    cancellation: &CancellationToken,
    context_deadline: Option<Instant>,
    progress_tx: &mpsc::UnboundedSender<ProcessProgress>,
    spawned_tx: tokio::sync::oneshot::Sender<Result<u32, String>>,
    admission_rx: &std_mpsc::Receiver<bool>,
) -> Result<WorkerOutput> {
    let started = Instant::now();
    let wall_started_at = OffsetDateTime::now_utc();
    let job_name = job_object_name(&spec.operation_id, spec.generation);
    let mut command = Command::new(&spec.executable);
    command.args(&spec.args).current_dir(&spec.cwd).env_clear();
    command.envs(&spec.environment);
    let mut child = match SuspendedJobChild::spawn_named(&command, &job_name) {
        Ok(child) => child,
        Err(error) => {
            let detail = format!("spawn supervised process in {job_name}: {error}");
            let _ = spawned_tx.send(Err(detail.clone()));
            bail!(detail);
        }
    };
    let process_started_at = OffsetDateTime::now_utc();
    cancellation.register_reap_required();

    let mut worker_error = None;
    let root_pid = child.id();
    let initial_count = child.active_process_count().unwrap_or(1);
    let process_start_ticks = match child.root_process_start_ticks() {
        Ok(ticks) => Some(ticks),
        Err(error) => {
            record_worker_error(
                &mut worker_error,
                format!("query supervised root process creation time: {error}"),
            );
            cancellation.cancel();
            None
        }
    };
    let executable_sha256 = match child
        .root_process_identity()
        .and_then(|identity| sha256_file(&identity.image))
    {
        Ok(hash) => Some(hash),
        Err(error) => {
            record_worker_error(
                &mut worker_error,
                format!("hash supervised root executable: {error}"),
            );
            cancellation.cancel();
            None
        }
    };
    send_progress(
        progress_tx,
        ProcessProgress::Spawned {
            pid: root_pid,
            process_count: initial_count,
            job_name: job_name.clone(),
            process_start_ticks,
            executable_sha256,
        },
    );
    let _ = spawned_tx.send(Ok(root_pid));
    let spawn_admission_timeout =
        Duration::from_millis(spec.timeout_profile.spawn_deadline_ms().unwrap_or(5_000));
    if !admission_rx
        .recv_timeout(spawn_admission_timeout)
        .unwrap_or(false)
    {
        cancellation.cancel();
    }
    let stdin_task = child.take_stdin().map_or_else(
        || {
            record_worker_error(
                &mut worker_error,
                "supervised child stdin handle is missing",
            );
            cancellation.cancel();
            None
        },
        |stdin| {
            Some(spawn_stdin_writer(
                stdin,
                spec.stdin_payload.unwrap_or_default(),
                progress_tx.clone(),
            ))
        },
    );
    let output_activity = Arc::new(Mutex::new(OutputActivity::default()));
    let stdout_task = child.take_stdout().map_or_else(
        || {
            record_worker_error(
                &mut worker_error,
                "supervised child stdout handle is missing",
            );
            cancellation.cancel();
            None
        },
        |stdout| {
            Some(spawn_pipe_reader(
                stdout,
                spec.stdout_limit_bytes,
                true,
                progress_tx.clone(),
                Arc::clone(&output_activity),
            ))
        },
    );
    let stderr_task = child.take_stderr().map_or_else(
        || {
            record_worker_error(
                &mut worker_error,
                "supervised child stderr handle is missing",
            );
            cancellation.cancel();
            None
        },
        |stderr| {
            Some(spawn_pipe_reader(
                stderr,
                spec.stderr_limit_bytes,
                false,
                progress_tx.clone(),
                Arc::clone(&output_activity),
            ))
        },
    );

    let profile_absolute_deadline = started
        .checked_add(Duration::from_millis(
            spec.timeout_profile.absolute_runtime_deadline_ms(),
        ))
        .unwrap_or(started);
    let absolute_deadline = context_deadline.map_or(profile_absolute_deadline, |deadline| {
        profile_absolute_deadline.min(deadline)
    });
    let first_output_deadline = [
        spec.timeout_profile.dispatch_ack_deadline_ms(),
        spec.timeout_profile.first_output_deadline_ms(),
    ]
    .into_iter()
    .flatten()
    .min()
    .map(Duration::from_millis);
    let idle_output_deadline = spec
        .timeout_profile
        .idle_output_deadline_ms()
        .map(Duration::from_millis);
    let cancellation_grace = Duration::from_millis(spec.timeout_profile.cancellation_grace_ms());
    let cleanup_grace = Duration::from_millis(spec.timeout_profile.cleanup_grace_ms());
    let mut max_process_count = initial_count;
    let mut last_process_count = initial_count;
    let mut timed_out = false;
    let mut timeout_class = None;
    let mut forced_termination = false;
    let mut cancellation_seen_at = None;
    let mut exit_code = None;
    let mut process_exit_at = None;
    let mut root_exit_seen_at = None;
    let mut root_descendant_grace_deadline = None;
    let mut root_wait_failure_detail = None;
    let mut descendants_at_root_exit: Option<DescendantsAtRootExit> = None;
    let mut descendant_capture_task: Option<WorkerThread<DescendantsAtRootExit>> = None;

    loop {
        if root_exit_seen_at.is_none() {
            match child.try_wait() {
                Ok(Some(code)) => {
                    let elapsed_ms =
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let root_exit_at = Instant::now();
                    root_exit_seen_at = Some(root_exit_at);
                    root_descendant_grace_deadline = Some(
                        root_exit_at
                            .checked_add(cleanup_grace)
                            .unwrap_or(root_exit_at),
                    );
                    send_progress(progress_tx, ProcessProgress::Exited);
                    descendant_capture_task = Some(spawn_descendant_capture(
                        child.job_name().to_owned(),
                        root_pid,
                        Some(code),
                        elapsed_ms,
                        descendant_capture_delay(&spec.operation_id),
                    ));
                    if process_exit_at.is_none() {
                        process_exit_at = Some(OffsetDateTime::now_utc());
                    }
                    if exit_code.is_none() {
                        exit_code = Some(code);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    record_root_wait_failure(
                        cancellation,
                        &mut worker_error,
                        &mut root_wait_failure_detail,
                        &error,
                    );
                }
            }
        }
        match child.active_process_count() {
            Ok(count) => {
                max_process_count = max_process_count.max(count);
                if count != last_process_count {
                    last_process_count = count;
                    send_progress(progress_tx, ProcessProgress::ProcessCount(count));
                }
                if count == 0 {
                    match child.try_wait() {
                        Ok(code) => exit_code = code,
                        Err(error) => record_root_wait_failure(
                            cancellation,
                            &mut worker_error,
                            &mut root_wait_failure_detail,
                            &error,
                        ),
                    }
                    process_exit_at = Some(OffsetDateTime::now_utc());
                    send_progress(progress_tx, ProcessProgress::Exited);
                    break;
                }
            }
            Err(error) => {
                record_worker_error(
                    &mut worker_error,
                    format!("query Job Object process count: {error}"),
                );
                cancellation.cancel();
            }
        }

        if root_descendant_grace_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            send_progress(progress_tx, ProcessProgress::Reaping);
            if let Err(error) = child.terminate(SUPERVISED_TERMINATION_CODE) {
                record_worker_error(
                    &mut worker_error,
                    format!("terminate descendants after supervised root exit: {error}"),
                );
            }
            forced_termination = true;
            break;
        }

        let now = Instant::now();
        if now >= absolute_deadline {
            timed_out = true;
            timeout_class.get_or_insert(ProviderTimeoutClass::AbsoluteRuntimeTimeout);
            record_worker_error(&mut worker_error, "absolute runtime deadline exceeded");
            cancellation.cancel();
        }
        let activity = output_activity.lock().ok();
        if let Some(first_output_deadline) = first_output_deadline
            && activity
                .as_ref()
                .is_none_or(|activity| activity.first_at.is_none())
            && started.elapsed() >= first_output_deadline
        {
            timed_out = true;
            timeout_class.get_or_insert(ProviderTimeoutClass::FirstOutputTimeout);
            record_worker_error(&mut worker_error, "first output deadline exceeded");
            cancellation.cancel();
        }
        if let Some(idle_output_deadline) = idle_output_deadline
            && let Some(last_at) = activity.as_ref().and_then(|activity| activity.last_at)
            && last_at.elapsed() >= idle_output_deadline
        {
            timed_out = true;
            timeout_class.get_or_insert(ProviderTimeoutClass::IdleOutputTimeout);
            record_worker_error(&mut worker_error, "idle output deadline exceeded");
            cancellation.cancel();
        }
        drop(activity);
        if cancellation.is_cancelled() {
            let cancellation_started = *cancellation_seen_at.get_or_insert_with(Instant::now);
            if cancellation_started.elapsed() >= cancellation_grace {
                send_progress(progress_tx, ProcessProgress::Reaping);
                if let Err(error) = child.terminate(SUPERVISED_TERMINATION_CODE) {
                    record_worker_error(
                        &mut worker_error,
                        format!("terminate supervised Job Object: {error}"),
                    );
                }
                forced_termination = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let cleanup_deadline = Instant::now()
        .checked_add(cleanup_grace)
        .unwrap_or_else(Instant::now);
    match child.wait_for_empty(remaining(cleanup_deadline)) {
        Ok(true) => {}
        Ok(false) => record_worker_error(
            &mut worker_error,
            "Job Object did not become empty before cleanup deadline",
        ),
        Err(error) => record_worker_error(
            &mut worker_error,
            format!("wait for supervised Job Object to become empty: {error}"),
        ),
    }
    let process_count_after = child.active_process_count().unwrap_or(u32::MAX);
    if exit_code.is_none() {
        match child.wait_timeout(remaining(cleanup_deadline)) {
            Ok(code) => {
                exit_code = code;
                process_exit_at = code.map(|_| OffsetDateTime::now_utc());
            }
            Err(error) => record_worker_error(
                &mut worker_error,
                format!("wait for supervised root process exit: {error}"),
            ),
        }
    }
    let exit_waiter_terminal = exit_code.is_some();
    if descendants_at_root_exit.is_none() {
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let fallback = root_wait_failure_detail.as_deref().map_or_else(
            || {
                failed_descendant_capture(
                    Some(root_pid),
                    exit_code,
                    elapsed_ms,
                    DescendantsCaptureErrorKind::Ambiguous,
                    if descendant_capture_task.is_some() {
                        "descendant capture did not complete before bounded cleanup"
                    } else {
                        "root exit was not observed before bounded cleanup"
                    },
                )
            },
            |detail| {
                failed_descendant_capture(
                    Some(root_pid),
                    exit_code,
                    elapsed_ms,
                    DescendantsCaptureErrorKind::EnumerationFailed,
                    detail,
                )
            },
        );
        let snapshot = if descendant_capture_task.is_some() {
            receive_worker_thread(descendant_capture_task.take(), cleanup_deadline, fallback).0
        } else {
            fallback
        };
        descendants_at_root_exit = Some(snapshot);
    }
    let descendants_at_root_exit = descendants_at_root_exit.unwrap_or_else(|| {
        DescendantsAtRootExit::failed(
            Some(root_pid),
            exit_code,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            DescendantsCaptureErrorKind::EnumerationFailed,
            "descendant capture unavailable",
        )
        .unwrap_or(DescendantsAtRootExit::Failed(DescendantsAtRootExitFailed {
            schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
            root_pid: Some(root_pid),
            root_exit_code: exit_code,
            capture_elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            error_kind: DescendantsCaptureErrorKind::EnumerationFailed,
            detail: "descendant capture unavailable".to_owned(),
        }))
    });
    let observed_processes = child.observed_processes();
    max_process_count =
        max_process_count.max(u32::try_from(observed_processes.len()).unwrap_or(u32::MAX));

    let ((stdin_terminal, stdin_error), stdin_joined) =
        join_stdin_bounded(stdin_task, cleanup_deadline);
    let (stdout_capture, stdout_joined) = join_pipe_bounded(stdout_task, cleanup_deadline);
    let (stderr_capture, stderr_joined) = join_pipe_bounded(stderr_task, cleanup_deadline);
    let mut terminal_error_codes = [
        stdin_error,
        stdout_capture.error_code,
        stderr_capture.error_code,
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    terminal_error_codes.sort_unstable();
    terminal_error_codes.dedup();
    let receipt = ProcessReapReceipt {
        operation_id: spec.operation_id,
        generation: spec.generation,
        job_object_name: job_name,
        root_pid: Some(root_pid),
        process_count_before: max_process_count,
        process_count_after,
        graceful_attempted: false,
        forced_termination,
        stdout_closed: stdout_capture.terminal,
        stderr_closed: stderr_capture.terminal,
        all_tasks_joined: stdin_terminal
            && stdin_joined
            && stdout_joined
            && stderr_joined
            && exit_waiter_terminal,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        terminal_error_codes,
        descendants_at_root_exit,
    };
    if receipt.proves_complete_reap() {
        cancellation.mark_reaped();
    } else if worker_error.is_none() {
        worker_error = Some("process reap receipt is incomplete".to_owned());
    }
    let (first_output_at, last_output_at) =
        output_activity.lock().map_or((None, None), |activity| {
            (
                activity
                    .first_at
                    .map(|observed| elapsed_timestamp(wall_started_at, started, observed)),
                activity
                    .last_at
                    .map(|observed| elapsed_timestamp(wall_started_at, started, observed)),
            )
        });
    let cleanup_completed_at = OffsetDateTime::now_utc();

    Ok(WorkerOutput {
        output: SupervisedProcessOutput {
            exit_code,
            stdout_total_bytes: stdout_capture.total_bytes,
            stderr_total_bytes: stderr_capture.total_bytes,
            stdout_truncated: stdout_capture.total_bytes
                > u64::try_from(stdout_capture.bytes.len()).unwrap_or(u64::MAX),
            stderr_truncated: stderr_capture.total_bytes
                > u64::try_from(stderr_capture.bytes.len()).unwrap_or(u64::MAX),
            stdout: stdout_capture.bytes,
            stderr: stderr_capture.bytes,
            timed_out,
            timeout_class,
            cancelled: cancellation.is_cancelled(),
            worker_error,
            observed_processes,
            process_started_at,
            first_output_at,
            last_output_at,
            process_exit_at,
            cleanup_completed_at,
            reap_receipt: receipt,
        },
    })
}

fn elapsed_timestamp(
    wall_started_at: OffsetDateTime,
    started: Instant,
    observed: Instant,
) -> OffsetDateTime {
    wall_started_at
        + time::Duration::milliseconds(
            i64::try_from(observed.duration_since(started).as_millis()).unwrap_or(i64::MAX),
        )
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn spawn_descendant_capture(
    job_name: String,
    root_pid: u32,
    root_exit_code: Option<i32>,
    capture_elapsed_ms: u64,
    delay: Duration,
) -> WorkerThread<DescendantsAtRootExit> {
    let (result_tx, result_rx) = std_mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let snapshot = RecoverableJobObject::open(&job_name).map_or_else(
            |error| {
                failed_descendant_capture(
                    Some(root_pid),
                    root_exit_code,
                    capture_elapsed_ms,
                    DescendantsCaptureErrorKind::EnumerationFailed,
                    format!("open Job Object for descendant capture: {error}"),
                )
            },
            |job| {
                capture_descendants_at_root_exit(&job, root_pid, root_exit_code, capture_elapsed_ms)
            },
        );
        let _ = result_tx.send(snapshot);
    });
    WorkerThread {
        result_rx,
        thread: Some(thread),
    }
}

fn descendant_capture_delay(operation_id: &str) -> Duration {
    #[cfg(test)]
    if operation_id.contains("delayed-descendant-capture") {
        return Duration::from_secs(5);
    }
    let _ = operation_id;
    Duration::ZERO
}

fn failed_descendant_capture(
    root_pid: Option<u32>,
    root_exit_code: Option<i32>,
    capture_elapsed_ms: u64,
    error_kind: DescendantsCaptureErrorKind,
    detail: impl Into<String>,
) -> DescendantsAtRootExit {
    let detail = detail.into();
    DescendantsAtRootExit::failed(
        root_pid,
        root_exit_code,
        capture_elapsed_ms,
        error_kind,
        detail.clone(),
    )
    .unwrap_or(DescendantsAtRootExit::Failed(DescendantsAtRootExitFailed {
        schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
        root_pid,
        root_exit_code,
        capture_elapsed_ms,
        error_kind: DescendantsCaptureErrorKind::EnumerationFailed,
        detail,
    }))
}

#[allow(clippy::too_many_lines)]
fn capture_descendants_at_root_exit(
    job: &RecoverableJobObject,
    root_pid: u32,
    root_exit_code: Option<i32>,
    capture_elapsed_ms: u64,
) -> DescendantsAtRootExit {
    match job.current_job_processes() {
        Ok(snapshots) => {
            let mut descendants = Vec::new();
            for snapshot in snapshots {
                if snapshot.pid == root_pid {
                    continue;
                }
                let image_path = snapshot.image.to_string_lossy().to_string();
                let image_sha256 = sha256_file(&snapshot.image)
                    .ok()
                    .filter(|hash| hash.chars().count() <= 128 && !hash.is_empty());
                descendants.push(DescendantProcessSnapshot {
                    pid: snapshot.pid,
                    start_ticks: snapshot.start_ticks,
                    image_path,
                    file_identity: DescendantFileIdentity {
                        volume_serial_number: snapshot.file_identity.volume_serial_number,
                        file_index: snapshot.file_identity.file_index,
                    },
                    image_sha256,
                });
            }
            match DescendantsAtRootExit::captured(
                root_pid,
                root_exit_code,
                capture_elapsed_ms,
                descendants,
            ) {
                Ok(captured) => captured,
                Err(detail) => {
                    let kind = if detail.contains("overflow") {
                        DescendantsCaptureErrorKind::Overflow
                    } else if detail.contains("duplicate") {
                        DescendantsCaptureErrorKind::Duplicate
                    } else if detail.contains("pid must be non-zero") || detail.contains("PID 0") {
                        DescendantsCaptureErrorKind::InvalidPid
                    } else if detail.contains("equals root") {
                        DescendantsCaptureErrorKind::Duplicate
                    } else {
                        DescendantsCaptureErrorKind::EnumerationFailed
                    };
                    let truncated = if detail.chars().count() > 512 {
                        detail.chars().take(512).collect::<String>()
                    } else {
                        detail
                    };
                    DescendantsAtRootExit::failed(
                        Some(root_pid),
                        root_exit_code,
                        capture_elapsed_ms,
                        kind,
                        truncated.clone(),
                    )
                    .unwrap_or(DescendantsAtRootExit::Failed(
                        DescendantsAtRootExitFailed {
                            schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
                            root_pid: Some(root_pid),
                            root_exit_code,
                            capture_elapsed_ms,
                            error_kind: DescendantsCaptureErrorKind::EnumerationFailed,
                            detail: truncated,
                        },
                    ))
                }
            }
        }
        Err(error) => {
            let kind = match error.kind() {
                std::io::ErrorKind::PermissionDenied => DescendantsCaptureErrorKind::AccessDenied,
                std::io::ErrorKind::WouldBlock => DescendantsCaptureErrorKind::Ambiguous,
                std::io::ErrorKind::InvalidData if error.to_string().contains("duplicate") => {
                    DescendantsCaptureErrorKind::Duplicate
                }
                std::io::ErrorKind::InvalidData if error.to_string().contains("PID 0") => {
                    DescendantsCaptureErrorKind::InvalidPid
                }
                _ => DescendantsCaptureErrorKind::EnumerationFailed,
            };
            let detail = error.to_string();
            let detail = if detail.chars().count() > 512 {
                detail.chars().take(512).collect::<String>()
            } else {
                detail
            };
            DescendantsAtRootExit::failed(
                Some(root_pid),
                root_exit_code,
                capture_elapsed_ms,
                kind,
                detail.clone(),
            )
            .unwrap_or(DescendantsAtRootExit::Failed(DescendantsAtRootExitFailed {
                schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
                root_pid: Some(root_pid),
                root_exit_code,
                capture_elapsed_ms,
                error_kind: DescendantsCaptureErrorKind::EnumerationFailed,
                detail,
            }))
        }
    }
}

fn job_object_name(operation_id: &str, generation: u64) -> String {
    let mut sanitized = operation_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.truncate(200);
    format!("Eliot-{sanitized}-g{generation}")
}

fn spawn_stdin_writer(
    mut stdin: File,
    payload: Vec<u8>,
    progress_tx: mpsc::UnboundedSender<ProcessProgress>,
) -> WorkerThread<(bool, Option<u32>)> {
    let (result_tx, result_rx) = std_mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let result = stdin.write_all(&payload).and_then(|()| stdin.flush());
        if result.is_ok() {
            send_progress(
                &progress_tx,
                ProcessProgress::Stdin(u64::try_from(payload.len()).unwrap_or(u64::MAX)),
            );
        }
        let result = match result {
            Ok(()) => (true, None),
            Err(error) if pipe_is_terminal(&error) => {
                (true, error.raw_os_error().map(i32::cast_unsigned))
            }
            Err(error) => (false, error.raw_os_error().map(i32::cast_unsigned)),
        };
        drop(stdin);
        let _ = result_tx.send(result);
    });
    WorkerThread {
        result_rx,
        thread: Some(thread),
    }
}

fn spawn_pipe_reader(
    mut pipe: File,
    limit: u64,
    stdout: bool,
    progress_tx: mpsc::UnboundedSender<ProcessProgress>,
    output_activity: Arc<Mutex<OutputActivity>>,
) -> WorkerThread<PipeCapture> {
    let (result_tx, result_rx) = std_mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let capture_limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut captured = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut total = 0_u64;
        let mut reported_total = 0_u64;
        let mut last_reported_at = Instant::now();
        let capture = loop {
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    if total != reported_total {
                        send_progress(
                            &progress_tx,
                            if stdout {
                                ProcessProgress::Stdout(total)
                            } else {
                                ProcessProgress::Stderr(total)
                            },
                        );
                    }
                    break PipeCapture {
                        bytes: captured,
                        total_bytes: total,
                        terminal: true,
                        error_code: None,
                    };
                }
                Ok(read) => {
                    total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                    let remaining = capture_limit.saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..read.min(remaining)]);
                    let now = Instant::now();
                    if let Ok(mut activity) = output_activity.lock() {
                        activity.first_at.get_or_insert(now);
                        activity.last_at = Some(now);
                    }
                    if total.saturating_sub(reported_total) >= 64 * 1024
                        || last_reported_at.elapsed() >= Duration::from_secs(1)
                    {
                        send_progress(
                            &progress_tx,
                            if stdout {
                                ProcessProgress::Stdout(total)
                            } else {
                                ProcessProgress::Stderr(total)
                            },
                        );
                        reported_total = total;
                        last_reported_at = now;
                    }
                }
                Err(error) if pipe_is_terminal(&error) => {
                    break PipeCapture {
                        bytes: captured,
                        total_bytes: total,
                        terminal: true,
                        error_code: error.raw_os_error().map(i32::cast_unsigned),
                    };
                }
                Err(error) => {
                    break PipeCapture {
                        bytes: captured,
                        total_bytes: total,
                        terminal: false,
                        error_code: error.raw_os_error().map(i32::cast_unsigned),
                    };
                }
            }
        };
        drop(pipe);
        let _ = result_tx.send(capture);
    });
    WorkerThread {
        result_rx,
        thread: Some(thread),
    }
}

fn join_stdin_bounded(
    task: Option<WorkerThread<(bool, Option<u32>)>>,
    deadline: Instant,
) -> ((bool, Option<u32>), bool) {
    receive_worker_thread(task, deadline, (false, None))
}

fn join_pipe_bounded(
    task: Option<WorkerThread<PipeCapture>>,
    deadline: Instant,
) -> (PipeCapture, bool) {
    receive_worker_thread(
        task,
        deadline,
        PipeCapture {
            bytes: Vec::new(),
            total_bytes: 0,
            terminal: false,
            error_code: None,
        },
    )
}

fn receive_worker_thread<T>(
    task: Option<WorkerThread<T>>,
    deadline: Instant,
    fallback: T,
) -> (T, bool) {
    let Some(mut task) = task else {
        return (fallback, false);
    };
    let Ok(result) = task.result_rx.recv_timeout(remaining(deadline)) else {
        return (fallback, false);
    };
    let joined = task
        .thread
        .take()
        .is_some_and(|thread| thread.join().is_ok());
    (result, joined)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn record_root_wait_failure(
    cancellation: &CancellationToken,
    worker_error: &mut Option<String>,
    root_wait_failure_detail: &mut Option<String>,
    error: &std::io::Error,
) {
    let detail = format!("root wait failed: {error}");
    let detail = if detail.chars().count() > 512 {
        detail.chars().take(512).collect::<String>()
    } else {
        detail
    };
    root_wait_failure_detail.get_or_insert_with(|| detail.clone());
    record_worker_error(
        worker_error,
        format!("query supervised root process exit: {error}"),
    );
    cancellation.cancel();
}

fn record_worker_error(error: &mut Option<String>, detail: impl Into<String>) {
    let detail = detail.into();
    if let Some(error) = error {
        if !error.contains(&detail) {
            error.push_str("; ");
            error.push_str(&detail);
        }
    } else {
        *error = Some(detail);
    }
}

fn pipe_is_terminal(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(109 | 232 | 233))
}

fn send_progress(sender: &mpsc::UnboundedSender<ProcessProgress>, progress: ProcessProgress) {
    let _ = sender.send(progress);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{
        ChildCriticality, ProcessRestartPolicy, RestartStrategy, ScriptedProviderProcessRunner,
        StartupProcessRecovery, SupervisedChildKind, SupervisedProcessSpec,
        SupervisedWindowsProcessRunner, bounded_operation_runtime_request,
        checkpoint_requests_process_cancellation, checkpoint_requires_process_recovery,
        default_daemon_runtime_instance, job_object_name, operation_checkpoint,
        record_root_wait_failure, recovery_or_identity_unproven, run_supervised_process,
    };
    use anyhow::{Result, anyhow, bail};
    use eliot_engine::{
        EngineError, OperationRuntimeHandle, OperationRuntimeProxy, OperationRuntimeRequest,
        OperationRuntimeResponse, ProviderProcessRunner, ProviderProcessSpec,
        runtime_supervision::{AdapterExecutionContext, CancellationToken},
    };
    use eliot_types::{
        DescendantsAtRootExit, DescendantsCaptureErrorKind, OperationCancellationState,
        ProcessReapReceipt,
    };
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::time::Instant;

    const FIXTURE_ENV: &str = "ELIOT_SUPERVISED_PROCESS_FIXTURE";
    const TEST_SUCCESS_RUNTIME_MS: u64 = 60_000;
    const TEST_SUCCESS_CONTEXT_TIMEOUT_MS: u64 = 60_000;
    const TEST_IDLE_RUNTIME_MS: u64 = 30_000;
    const TEST_IDLE_CONTEXT_TIMEOUT_MS: u64 = 60_000;
    static FIXTURE_OPERATION_NONCE: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn production_operation_runtime_falls_back_to_config_bound_daemon_instance() -> Result<()> {
        let config_path = Path::new("ignored/supervised-process-isolated-governor.toml");
        let instance = default_daemon_runtime_instance(config_path)?;
        let expected = crate::runtime_instance::RuntimeInstance::select(config_path, None)?;

        assert_eq!(instance.name(), expected.name());
        assert_eq!(instance.publication_path(), expected.publication_path());
        assert_ne!(
            instance.name(),
            crate::runtime_instance::DEFAULT_INSTANCE_NAME
        );
        Ok(())
    }

    #[test]
    fn recovery_query_error_is_fail_closed_not_fatal() {
        let recovery = recovery_or_identity_unproven(Err(anyhow!(
            "The parameter is incorrect. (os error 87)"
        )));

        let StartupProcessRecovery::IdentityUnproven(reason) = recovery else {
            panic!("recovery error must remain identity-unproven");
        };
        assert_eq!(
            reason,
            "process_recovery_failed:The parameter is incorrect. (os error 87)"
        );
    }

    #[test]
    fn root_wait_error_retries_observation_and_cancels_fail_closed() {
        let cancellation = CancellationToken::new();
        let mut worker_error = None;
        let mut root_wait_failure_detail = None;

        record_root_wait_failure(
            &cancellation,
            &mut worker_error,
            &mut root_wait_failure_detail,
            &std::io::Error::from_raw_os_error(6),
        );

        assert!(cancellation.is_cancelled());
        assert!(
            worker_error
                .as_deref()
                .is_some_and(|detail| detail.contains("query supervised root process exit"))
        );
        assert!(
            root_wait_failure_detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("root wait failed:"))
        );
    }

    #[tokio::test]
    async fn daemon_operation_runtime_timeout_unblocks_never_replying_proxy_request() {
        let started = Instant::now();
        let result = bounded_operation_runtime_request(
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await;

        let error = result.expect_err("never-replying runtime request must time out");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[derive(Default)]
    struct NeverReplyingAfterPrepareProxy {
        calls: AtomicUsize,
    }

    impl OperationRuntimeProxy for NeverReplyingAfterPrepareProxy {
        fn request(
            &self,
            request: OperationRuntimeRequest,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<OperationRuntimeResponse, EngineError>>
                    + Send
                    + '_,
            >,
        > {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                match (call, request) {
                    (0, OperationRuntimeRequest::GetCheckpoint(_)) => {
                        Ok(OperationRuntimeResponse::Checkpoint(None))
                    }
                    (1, OperationRuntimeRequest::PutCheckpoint(_)) => {
                        Ok(OperationRuntimeResponse::Unit)
                    }
                    _ => bounded_operation_runtime_request(
                        Duration::from_millis(25),
                        std::future::pending::<Result<OperationRuntimeResponse>>(),
                    )
                    .await
                    .map_err(|error| {
                        EngineError::RuntimeSupervision(format!(
                            "never-replying operation-runtime proxy: {error:#}"
                        ))
                    }),
                }
            })
        }
    }

    #[tokio::test]
    async fn never_replying_operation_runtime_cancels_and_reaps_ready_worker() -> Result<()> {
        let proxy = Arc::new(NeverReplyingAfterPrepareProxy::default());
        let mut run_context = context(3_000);
        run_context.runtime_store = OperationRuntimeHandle::from_proxy(proxy.clone());
        let mut spec = fixture_spec("ignore-shutdown", 5_000)?;
        spec.stdin_payload = Some(Vec::new());
        spec.timeout_profile = eliot_types::ProviderRoutePolicy::for_route(
            eliot_types::AgentHostId::Codex,
            "never-replying-operation-runtime-fixture",
            eliot_types::ProviderDeclaredBudget::new(5_000, 32 * 1024)
                .with_spawn_deadline_ms(Some(1_000))
                .with_first_output_deadline_ms(None)
                .with_cancellation_grace_ms(20)
                .with_cleanup_grace_ms(250)
                .with_reconciliation_window_ms(0),
        )
        .timeout_profile()
        .clone();

        let output = tokio::time::timeout(
            Duration::from_secs(3),
            run_supervised_process(spec, run_context),
        )
        .await
        .expect("bounded operation-runtime failure must not strand the runner")?;

        assert!(proxy.calls.load(Ordering::SeqCst) >= 3);
        assert!(output.reap_receipt.proves_complete_reap());
        assert!(
            output
                .worker_error
                .as_deref()
                .is_some_and(|detail| detail.contains("runtime checkpoint persistence failed"))
        );
        Ok(())
    }

    #[test]
    fn provider_route_policy_does_not_invent_dispatch_ack() {
        let policy = eliot_types::ProviderRoutePolicy::for_route(
            eliot_types::AgentHostId::Antigravity,
            "provider-runner-fixture",
            eliot_types::ProviderDeclaredBudget::new(120_000, 32 * 1024),
        );
        let profile = policy.timeout_profile();

        assert_eq!(profile.dispatch_ack_deadline_ms(), None);
        assert_eq!(profile.first_output_deadline_ms(), Some(120_000));
        assert_eq!(profile.absolute_runtime_deadline_ms(), 120_000);
    }

    #[test]
    fn supervised_process_native_fixture() -> Result<()> {
        let Ok(mode) = std::env::var(FIXTURE_ENV) else {
            return Ok(());
        };
        match mode.as_str() {
            "pipe-pressure" => {
                let out = vec![b'o'; 96 * 1024];
                let err = vec![b'e'; 96 * 1024];
                let stdout_task =
                    std::thread::spawn(move || std::io::stdout().lock().write_all(&out));
                let stderr_task =
                    std::thread::spawn(move || std::io::stderr().lock().write_all(&err));
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input)?;
                stdout_task
                    .join()
                    .map_err(|_| anyhow!("stdout fixture writer panicked"))??;
                stderr_task
                    .join()
                    .map_err(|_| anyhow!("stderr fixture writer panicked"))??;
                assert_eq!(input.len(), 96 * 1024);
            }
            "ignore-shutdown" | "descendant-sleep" => {
                std::thread::sleep(Duration::from_secs(30));
            }
            "idle-output" => {
                std::io::stdout().write_all(b"ready\n")?;
                std::io::stdout().flush()?;
                std::thread::sleep(Duration::from_secs(30));
            }
            "terminal-no-exit" => {
                std::io::stdout().write_all(b"{\"status\":\"complete\"}\n")?;
                std::io::stdout().flush()?;
                std::thread::sleep(Duration::from_secs(30));
            }
            "antigravity-executor" => {
                let output = vec![b'o'; 96 * 1024];
                let error = vec![b'e'; 96 * 1024];
                std::io::stdout().write_all(&output)?;
                std::io::stderr().write_all(&error)?;
            }
            "descendant-handles" => {
                let mut descendant = std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "host_runtime::supervised_process::tests::supervised_process_native_fixture",
                        "--nocapture",
                    ])
                    .env(FIXTURE_ENV, "descendant-sleep")
                    .spawn()?;
                let _descendant_waiter = std::thread::spawn(move || descendant.wait());
                std::io::stdout().write_all(b"root-exited\n")?;
                std::io::stderr().write_all(b"descendant-retains-handles\n")?;
            }
            other => bail!("unknown supervised fixture mode: {other}"),
        }
        Ok(())
    }

    fn fixture_spec(mode: &str, runtime_ms: u64) -> Result<SupervisedProcessSpec> {
        let executable = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        let mut environment = BTreeMap::new();
        environment.insert(OsString::from(FIXTURE_ENV), OsString::from(mode));
        let operation_nonce = FIXTURE_OPERATION_NONCE.fetch_add(1, Ordering::SeqCst);
        Ok(SupervisedProcessSpec {
            operation_id: format!(
                "supervised-process-{mode}-{}-{operation_nonce}",
                std::process::id()
            ),
            invocation_id: None,
            generation: 1,
            child_kind: SupervisedChildKind::Verifier,
            criticality: ChildCriticality::Optional,
            restart_policy: ProcessRestartPolicy {
                strategy: RestartStrategy::Never,
                max_restarts: 0,
                restart_window_seconds: 60,
                base_backoff_ms: 0,
                pre_dispatch_only: true,
            },
            executable,
            args: vec![
                OsString::from("--exact"),
                OsString::from(
                    "host_runtime::supervised_process::tests::supervised_process_native_fixture",
                ),
                OsString::from("--nocapture"),
            ],
            cwd,
            environment,
            stdin_payload: Some(vec![b'i'; 96 * 1024]),
            stdout_limit_bytes: 32 * 1024,
            stderr_limit_bytes: 32 * 1024,
            timeout_profile: eliot_types::ProviderRoutePolicy::for_route(
                eliot_types::AgentHostId::Codex,
                "supervised-process-fixture",
                eliot_types::ProviderDeclaredBudget::new(runtime_ms, 32 * 1024)
                    .with_spawn_deadline_ms(Some(1_000))
                    .with_first_output_deadline_ms(None)
                    .with_cancellation_grace_ms(20)
                    .with_cleanup_grace_ms(2_000)
                    .with_reconciliation_window_ms(0),
            )
            .timeout_profile()
            .clone(),
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        })
    }

    #[test]
    fn supervised_process_fixtures_never_share_a_named_job() -> Result<()> {
        let first = fixture_spec("ignore-shutdown", 100)?;
        let second = fixture_spec("ignore-shutdown", 100)?;

        assert_ne!(first.operation_id, second.operation_id);
        assert_ne!(
            job_object_name(&first.operation_id, first.generation),
            job_object_name(&second.operation_id, second.generation)
        );
        Ok(())
    }

    fn context(timeout_ms: u64) -> AdapterExecutionContext {
        AdapterExecutionContext {
            operation_id: "fixture".to_owned(),
            generation: 1,
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_millis(timeout_ms),
            runtime_store: OperationRuntimeHandle::disabled(),
            role_lease_id: None,
            role_lease_epoch: None,
            runtime_contract_sha256: None,
        }
    }

    #[test]
    fn continuous_recovery_does_not_reap_a_healthy_unexpired_operation() -> Result<()> {
        let now = time::OffsetDateTime::now_utc();
        let mut checkpoint = operation_checkpoint(&fixture_spec("pipe-pressure", 5_000)?);

        assert!(!checkpoint_requires_process_recovery(
            &checkpoint,
            now,
            false
        ));
        assert!(checkpoint_requires_process_recovery(&checkpoint, now, true));

        checkpoint.phase_deadline_at = now - time::Duration::milliseconds(1);
        assert!(checkpoint_requires_process_recovery(
            &checkpoint,
            now,
            false
        ));

        checkpoint.phase_deadline_at = now + time::Duration::seconds(1);
        checkpoint.cancellation_state = OperationCancellationState::Requested;
        assert!(checkpoint_requires_process_recovery(
            &checkpoint,
            now,
            false
        ));
        assert!(checkpoint_requests_process_cancellation(&checkpoint));
        Ok(())
    }

    #[test]
    fn prepared_checkpoint_does_not_spend_spawn_budget_on_daemon_persistence() -> Result<()> {
        let spec = fixture_spec("pipe-pressure", 60_000)?;
        let checkpoint = operation_checkpoint(&spec);

        assert_eq!(checkpoint.phase, eliot_types::OperationPhase::Prepared);
        assert_eq!(
            checkpoint.phase_deadline_at,
            checkpoint.absolute_deadline_at
        );
        assert!(
            checkpoint.phase_deadline_at - checkpoint.phase_started_at
                >= time::Duration::seconds(59)
        );
        Ok(())
    }

    #[tokio::test]
    async fn provider_runner_uses_shared_job_primitive_and_reports_spawn() -> Result<()> {
        let executable = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        let runner = SupervisedWindowsProcessRunner {
            runtime_store: OperationRuntimeHandle::disabled(),
        };
        let mut spawned_pid = None;
        let mut on_spawned = |pid| {
            spawned_pid = Some(pid);
            Ok(())
        };
        let output = runner
            .run(
                ProviderProcessSpec {
                    operation_id: format!("antigravity-shared-supervisor-{}", std::process::id()),
                    invocation_id: None,
                    executable,
                    args: vec![
                        OsString::from("--exact"),
                        OsString::from(
                            "host_runtime::supervised_process::tests::supervised_process_native_fixture",
                        ),
                        OsString::from("--nocapture"),
                    ],
                    cwd,
                    environment: vec![(
                        OsString::from(FIXTURE_ENV),
                        OsString::from("antigravity-executor"),
                    )],
                    stdin_payload: None,
                    route_policy: eliot_types::ProviderRoutePolicy::for_route(
                        eliot_types::AgentHostId::Antigravity,
                        "provider-runner-fixture",
                        eliot_types::ProviderDeclaredBudget::new(
                            TEST_SUCCESS_RUNTIME_MS,
                            32 * 1024,
                        ),
                    ),
                    cancellation: CancellationToken::new(),
                    deadline: Instant::now()
                        + Duration::from_millis(TEST_SUCCESS_CONTEXT_TIMEOUT_MS),
                    runtime_contract_sha256: None,
                    role_lease_id: None,
                    role_lease_epoch: None,
                },
                &mut on_spawned,
            )
            .await?;
        assert_eq!(spawned_pid, output.reap_receipt.root_pid);
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.timed_out);
        assert!(!output.reap_receipt.forced_termination);
        assert!(output.worker_error.is_none(), "{:?}", output.worker_error);
        assert!(output.stdout_truncated);
        assert!(output.stderr_truncated);
        assert!(output.reap_receipt.proves_complete_reap());
        assert!(!output.reap_receipt.job_object_name.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn scripted_provider_runner_returns_post_spawn_callback_failure_as_outcome() -> Result<()>
    {
        let now = time::OffsetDateTime::now_utc();
        let scripted = ScriptedProviderProcessRunner::new([eliot_engine::ProviderProcessOutcome {
            exit_code: Some(0),
            stdout: b"complete".to_vec(),
            stderr: Vec::new(),
            stdout_total_bytes: 8,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            timeout_class: None,
            cancelled: true,
            worker_error: None,
            observed_processes: Vec::new(),
            process_started_at: now,
            first_output_at: Some(now),
            last_output_at: Some(now),
            process_exit_at: Some(now),
            cleanup_completed_at: now,
            reap_receipt: ProcessReapReceipt {
                operation_id: "scripted-provider".to_owned(),
                generation: 1,
                job_object_name: "scripted-job".to_owned(),
                root_pid: Some(41),
                process_count_before: 1,
                process_count_after: 0,
                graceful_attempted: false,
                forced_termination: true,
                stdout_closed: true,
                stderr_closed: true,
                all_tasks_joined: true,
                elapsed_ms: 1,
                terminal_error_codes: Vec::new(),
                descendants_at_root_exit: eliot_types::DescendantsAtRootExit::captured(
                    41,
                    Some(0),
                    1,
                    Vec::new(),
                )
                .unwrap(),
            },
        }]);
        let spec = ProviderProcessSpec {
            operation_id: "scripted-provider".to_owned(),
            invocation_id: None,
            executable: std::env::current_exe()?,
            args: Vec::new(),
            cwd: std::env::current_dir()?,
            environment: Vec::new(),
            stdin_payload: None,
            route_policy: eliot_types::ProviderRoutePolicy::for_route(
                eliot_types::AgentHostId::Claude,
                "scripted-provider",
                eliot_types::ProviderDeclaredBudget::new(100, 1_024),
            ),
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_millis(100),
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        };
        let mut callback = |_| {
            Err(eliot_engine::EngineError::RuntimeSupervision(
                "journal unavailable".to_owned(),
            ))
        };

        let outcome = scripted.run(spec, &mut callback).await?;

        assert!(outcome.reap_receipt.proves_complete_reap());
        assert!(
            outcome
                .worker_error
                .as_deref()
                .is_some_and(|error| error.contains("journal unavailable"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn supervised_process_drains_bidirectional_pressure_and_caps_output() -> Result<()> {
        let output = run_supervised_process(
            fixture_spec("pipe-pressure", TEST_SUCCESS_RUNTIME_MS)?,
            context(TEST_SUCCESS_CONTEXT_TIMEOUT_MS),
        )
        .await?;
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.timed_out);
        assert!(!output.reap_receipt.forced_termination);
        assert!(output.worker_error.is_none(), "{:?}", output.worker_error);
        assert!(output.stdout_total_bytes >= 96 * 1024);
        assert!(output.stderr_total_bytes >= 96 * 1024);
        assert_eq!(output.stdout.len(), 32 * 1024);
        assert_eq!(output.stderr.len(), 32 * 1024);
        assert!(output.stdout_truncated);
        assert!(output.stderr_truncated);
        assert!(
            output.reap_receipt.proves_complete_reap(),
            "{:?}",
            output.reap_receipt
        );
        Ok(())
    }

    #[tokio::test]
    async fn supervised_process_timeout_forces_job_and_proves_zero_orphan() -> Result<()> {
        let output =
            run_supervised_process(fixture_spec("ignore-shutdown", 100)?, context(100)).await?;
        assert!(output.timed_out);
        assert!(output.reap_receipt.forced_termination);
        assert_eq!(output.reap_receipt.process_count_after, 0);
        assert!(
            output.reap_receipt.proves_complete_reap(),
            "{:?}",
            output.reap_receipt
        );
        Ok(())
    }

    #[tokio::test]
    async fn supervised_process_idle_output_deadline_cancels_and_reaps() -> Result<()> {
        let mut spec = fixture_spec("idle-output", TEST_IDLE_RUNTIME_MS)?;
        spec.stdin_payload = Some(Vec::new());
        spec.timeout_profile = eliot_types::ProviderRoutePolicy::for_route(
            eliot_types::AgentHostId::Codex,
            "supervised-process-idle-output-fixture",
            eliot_types::ProviderDeclaredBudget::new(TEST_IDLE_RUNTIME_MS, 32 * 1024)
                .with_spawn_deadline_ms(Some(1_000))
                .with_first_output_deadline_ms(None)
                .with_idle_output_deadline_ms(Some(100))
                .with_cancellation_grace_ms(20)
                .with_cleanup_grace_ms(2_000)
                .with_reconciliation_window_ms(0),
        )
        .timeout_profile()
        .clone();
        // This test asserts the provider profile's idle-output cause.  Keep the
        // caller-owned wall clock outside the assertion window so scheduler
        // delay before `spawn_blocking` cannot legitimately win first.
        let output = run_supervised_process(spec, context(TEST_IDLE_CONTEXT_TIMEOUT_MS)).await?;
        assert!(output.timed_out);
        assert_eq!(
            output.timeout_class,
            Some(eliot_types::ProviderTimeoutClass::IdleOutputTimeout)
        );
        assert!(
            output
                .worker_error
                .as_deref()
                .is_some_and(|error| error.contains("idle output deadline exceeded"))
        );
        assert!(
            !output
                .worker_error
                .as_deref()
                .is_some_and(|error| error.contains("first output deadline exceeded"))
        );
        assert!(
            !output
                .worker_error
                .as_deref()
                .is_some_and(|error| error.contains("absolute runtime deadline exceeded"))
        );
        assert!(
            output
                .stdout
                .windows(b"ready".len())
                .any(|window| window == b"ready")
        );
        assert!(output.reap_receipt.forced_termination);
        assert!(output.reap_receipt.proves_complete_reap());
        Ok(())
    }

    #[tokio::test]
    async fn supervised_process_descendant_handles_wait_for_job_termination() -> Result<()> {
        let mut spec = fixture_spec("descendant-handles", 200)?;
        spec.stdin_payload = Some(Vec::new());
        let output = run_supervised_process(spec, context(1_000)).await?;
        assert!(output.timed_out);
        assert!(output.reap_receipt.forced_termination);
        assert!(output.reap_receipt.process_count_before >= 2);
        assert_eq!(output.reap_receipt.process_count_after, 0);
        assert!(
            output
                .stdout
                .windows(b"root-exited".len())
                .any(|window| window == b"root-exited")
        );
        assert!(output.reap_receipt.proves_complete_reap());
        Ok(())
    }

    #[tokio::test]
    async fn supervised_process_terminal_output_without_exit_is_reaped_once() -> Result<()> {
        let mut spec = fixture_spec("terminal-no-exit", 200)?;
        spec.stdin_payload = Some(Vec::new());
        let output = run_supervised_process(spec, context(1_000)).await?;
        assert!(output.timed_out);
        assert!(output.reap_receipt.forced_termination);
        assert!(
            output
                .stdout
                .windows(b"{\"status\":\"complete\"}".len())
                .any(|window| window == b"{\"status\":\"complete\"}")
        );
        assert!(output.reap_receipt.proves_complete_reap());
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn delayed_descendant_capture_cannot_block_bounded_reaping() -> Result<()> {
        let mut spec = fixture_spec("descendant-handles", 5_000)?;
        spec.operation_id = format!(
            "delayed-descendant-capture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        spec.stdin_payload = Some(Vec::new());
        spec.timeout_profile = eliot_types::ProviderRoutePolicy::for_route(
            eliot_types::AgentHostId::Codex,
            "delayed-descendant-capture-fixture",
            eliot_types::ProviderDeclaredBudget::new(5_000, 32 * 1024)
                .with_spawn_deadline_ms(Some(1_000))
                .with_first_output_deadline_ms(None)
                .with_cancellation_grace_ms(20)
                .with_cleanup_grace_ms(150)
                .with_reconciliation_window_ms(0),
        )
        .timeout_profile()
        .clone();
        let started = Instant::now();
        let output = run_supervised_process(spec, context(3_000)).await?;
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(output.reap_receipt.forced_termination);
        assert_eq!(output.reap_receipt.process_count_after, 0);
        assert!(output.reap_receipt.proves_complete_reap());
        match &output.reap_receipt.descendants_at_root_exit {
            DescendantsAtRootExit::Failed(failed) => {
                assert_eq!(failed.error_kind, DescendantsCaptureErrorKind::Ambiguous);
                assert!(failed.detail.contains("bounded cleanup"));
            }
            DescendantsAtRootExit::Captured(captured) => {
                panic!("delayed capture became authoritative: {captured:?}");
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    async fn descendant_snapshot_at_root_exit_is_authoritative() -> Result<()> {
        let mut spec = fixture_spec("descendant-handles", 5_000)?;
        spec.operation_id = format!(
            "{}-snap-{}-{:?}",
            spec.operation_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::thread::current().id()
        );
        spec.stdin_payload = Some(Vec::new());
        spec.timeout_profile = eliot_types::ProviderRoutePolicy::for_route(
            eliot_types::AgentHostId::Codex,
            "descendant-snapshot-fixture",
            eliot_types::ProviderDeclaredBudget::new(5_000, 32 * 1024)
                .with_spawn_deadline_ms(Some(1_000))
                .with_first_output_deadline_ms(None)
                .with_cancellation_grace_ms(20)
                .with_cleanup_grace_ms(2_000)
                .with_reconciliation_window_ms(0),
        )
        .timeout_profile()
        .clone();
        let output = run_supervised_process(spec, context(5_000)).await?;
        assert!(output.reap_receipt.proves_complete_reap());
        assert_eq!(output.reap_receipt.process_count_after, 0);
        match &output.reap_receipt.descendants_at_root_exit {
            eliot_types::DescendantsAtRootExit::Captured(captured) => {
                let root_pid = output.reap_receipt.root_pid.expect("root pid");
                assert_eq!(captured.root_pid, root_pid);
                assert!(!captured.descendants.is_empty());
                assert!(
                    captured
                        .descendants
                        .iter()
                        .all(|entry| entry.pid != root_pid)
                );
                assert!(captured.descendants.iter().all(|entry| entry.pid != 0));
                for entry in &captured.descendants {
                    assert!(!entry.image_path.is_empty());
                    assert!(entry.start_ticks != 0);
                    assert!(
                        entry.file_identity.file_index != 0
                            || entry.file_identity.volume_serial_number != 0
                    );
                    if let Some(sha) = &entry.image_sha256 {
                        assert_eq!(sha.len(), 64);
                    }
                }
                let mut sorted = captured.descendants.clone();
                sorted.sort_by_key(|entry| entry.pid);
                assert_eq!(sorted, captured.descendants);
            }
            eliot_types::DescendantsAtRootExit::Failed(failed) => {
                panic!("expected captured descendants, got failed {failed:?}");
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    async fn no_descendant_snapshot_is_authoritative_empty() -> Result<()> {
        let mut spec = fixture_spec("antigravity-executor", 5_000)?;
        spec.operation_id = format!(
            "{}-empty-{}-{:?}",
            spec.operation_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::thread::current().id()
        );
        spec.stdin_payload = Some(Vec::new());
        let output = run_supervised_process(spec, context(5_000)).await?;
        assert!(output.reap_receipt.proves_complete_reap());
        assert_eq!(output.reap_receipt.process_count_after, 0);
        match &output.reap_receipt.descendants_at_root_exit {
            eliot_types::DescendantsAtRootExit::Captured(captured) => {
                assert!(captured.descendants.is_empty());
                assert_eq!(
                    captured.root_pid,
                    output.reap_receipt.root_pid.expect("root pid")
                );
            }
            eliot_types::DescendantsAtRootExit::Failed(failed) => {
                panic!("expected empty captured, got failed {failed:?}");
            }
        }
        Ok(())
    }
}
