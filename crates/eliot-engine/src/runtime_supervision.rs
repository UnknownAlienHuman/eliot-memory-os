use crate::{EngineError, OperationRuntimeHandle};
use eliot_types::{
    OperationCancellationState, OperationPhase, OperationRuntimeCheckpoint, ProviderDispatchState,
    ProviderInvocationAttempt, ProviderInvocationState,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify};
use tokio::time::{Duration, Instant};

#[derive(Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    reap_required: AtomicBool,
    reaped: AtomicBool,
    notify: Notify,
    reap_notify: Notify,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        while !self.is_cancelled() {
            self.inner.notify.notified().await;
        }
    }

    pub fn register_reap_required(&self) {
        self.inner.reap_required.store(true, Ordering::Release);
    }

    pub fn mark_reaped(&self) {
        self.inner.reaped.store(true, Ordering::Release);
        self.inner.reap_notify.notify_waiters();
    }

    #[must_use]
    pub fn reap_required(&self) -> bool {
        self.inner.reap_required.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn reap_completed(&self) -> bool {
        !self.reap_required() || self.inner.reaped.load(Ordering::Acquire)
    }

    pub async fn reaped(&self) {
        while !self.reap_completed() {
            self.inner.reap_notify.notified().await;
        }
    }
}

#[derive(Clone)]
pub struct AdapterExecutionContext {
    pub operation_id: String,
    pub generation: u64,
    pub cancellation: CancellationToken,
    pub deadline: Instant,
    pub runtime_store: OperationRuntimeHandle,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
    pub runtime_contract_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    RestartFreshGeneration,
    ReconcileBeforeAnyRetry,
    AcceptCapturedTerminalThenReap,
    OpenCircuit,
    TerminalFailure,
}

#[must_use]
pub fn classify_restart(
    checkpoint: &OperationRuntimeCheckpoint,
    provider_attempt: Option<&ProviderInvocationAttempt>,
    canonical_result_exists: bool,
) -> RestartDecision {
    if canonical_result_exists {
        return RestartDecision::AcceptCapturedTerminalThenReap;
    }
    if checkpoint.restart_count > 0
        && matches!(
            checkpoint.phase,
            OperationPhase::Prepared
                | OperationPhase::Validating
                | OperationPhase::Staging
                | OperationPhase::DispatchStarting
        )
    {
        return RestartDecision::OpenCircuit;
    }
    if checkpoint.dispatch_state == ProviderDispatchState::NotStarted
        && provider_attempt.is_none_or(|attempt| {
            !attempt.state_transitions.iter().any(|transition| {
                matches!(
                    transition.to,
                    ProviderInvocationState::Dispatched
                        | ProviderInvocationState::Running
                        | ProviderInvocationState::OutputObserved
                        | ProviderInvocationState::CompletedCaptured
                )
            })
        })
    {
        return RestartDecision::RestartFreshGeneration;
    }
    if matches!(
        checkpoint.dispatch_state,
        ProviderDispatchState::Starting
            | ProviderDispatchState::AckUnknown
            | ProviderDispatchState::Proven
    ) {
        return RestartDecision::ReconcileBeforeAnyRetry;
    }
    RestartDecision::TerminalFailure
}

struct RegisteredOperation {
    checkpoint: OperationRuntimeCheckpoint,
    cancellation: CancellationToken,
}

#[derive(Clone)]
pub struct OperationSupervisor {
    runtime_store: OperationRuntimeHandle,
    operations: Arc<Mutex<BTreeMap<String, RegisteredOperation>>>,
}

impl OperationSupervisor {
    #[must_use]
    pub fn new(runtime_store: OperationRuntimeHandle) -> Self {
        Self {
            runtime_store,
            operations: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn register(
        &self,
        checkpoint: OperationRuntimeCheckpoint,
    ) -> Result<CancellationToken, EngineError> {
        let token = CancellationToken::new();
        self.runtime_store
            .put_checkpoint(checkpoint.clone())
            .await?;
        self.operations.lock().await.insert(
            checkpoint.operation_id.clone(),
            RegisteredOperation {
                checkpoint,
                cancellation: token.clone(),
            },
        );
        Ok(token)
    }

    pub async fn update(&self, checkpoint: OperationRuntimeCheckpoint) -> Result<(), EngineError> {
        self.runtime_store
            .put_checkpoint(checkpoint.clone())
            .await?;
        if let Some(operation) = self
            .operations
            .lock()
            .await
            .get_mut(&checkpoint.operation_id)
        {
            operation.checkpoint = checkpoint;
        }
        Ok(())
    }

    pub async fn cancel(&self, operation_id: &str) -> Result<bool, EngineError> {
        let mut operations = self.operations.lock().await;
        let Some(operation) = operations.get_mut(operation_id) else {
            return Ok(false);
        };
        operation.cancellation.cancel();
        operation.checkpoint.cancellation_state = OperationCancellationState::Requested;
        operation.checkpoint.phase = OperationPhase::Cancelling;
        operation.checkpoint.last_progress_at = OffsetDateTime::now_utc();
        let checkpoint = operation.checkpoint.clone();
        drop(operations);
        self.runtime_store.put_checkpoint(checkpoint).await?;
        Ok(true)
    }

    pub async fn complete(
        &self,
        checkpoint: OperationRuntimeCheckpoint,
    ) -> Result<(), EngineError> {
        self.runtime_store
            .put_checkpoint(checkpoint.clone())
            .await?;
        self.operations
            .lock()
            .await
            .remove(&checkpoint.operation_id);
        Ok(())
    }

    pub async fn watchdog_once(&self, now: OffsetDateTime) -> Result<Vec<String>, EngineError> {
        let mut cancelled = Vec::new();
        let mut updates = Vec::new();
        {
            let mut operations = self.operations.lock().await;
            for operation in operations.values_mut() {
                if operation.checkpoint.is_terminal() {
                    continue;
                }
                if now > operation.checkpoint.phase_deadline_at
                    || now > operation.checkpoint.absolute_deadline_at
                {
                    operation.cancellation.cancel();
                    operation.checkpoint.cancellation_state = OperationCancellationState::Requested;
                    operation.checkpoint.phase = OperationPhase::Cancelling;
                    operation.checkpoint.last_progress_at = now;
                    operation.checkpoint.last_error_class =
                        Some("watchdog_deadline_exceeded".to_owned());
                    cancelled.push(operation.checkpoint.operation_id.clone());
                    updates.push(operation.checkpoint.clone());
                }
            }
        }
        for checkpoint in updates {
            self.runtime_store.put_checkpoint(checkpoint).await?;
        }
        for mut checkpoint in self.runtime_store.list_nonterminal_checkpoints().await? {
            if cancelled.contains(&checkpoint.operation_id)
                || (now <= checkpoint.phase_deadline_at && now <= checkpoint.absolute_deadline_at)
            {
                continue;
            }
            checkpoint.cancellation_state = OperationCancellationState::Requested;
            checkpoint.phase = OperationPhase::Cancelling;
            checkpoint.last_progress_at = now;
            checkpoint.last_error_class = Some("watchdog_deadline_exceeded".to_owned());
            cancelled.push(checkpoint.operation_id.clone());
            self.runtime_store.put_checkpoint(checkpoint).await?;
        }
        Ok(cancelled)
    }

    pub async fn run_watchdog(
        self: Arc<Self>,
        shutdown: CancellationToken,
        interval: Duration,
    ) -> Result<(), EngineError> {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(interval) => {
                    self.watchdog_once(OffsetDateTime::now_utc()).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OperationSupervisor, RestartDecision, classify_restart};
    use crate::OperationRuntimeHandle;
    use eliot_types::{
        OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION, OperationCancellationState, OperationPhase,
        OperationReconciliationState, OperationRuntimeCheckpoint, ProviderDispatchState,
    };
    use time::OffsetDateTime;

    fn checkpoint() -> OperationRuntimeCheckpoint {
        let now = OffsetDateTime::now_utc();
        OperationRuntimeCheckpoint {
            schema_version: OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION.to_owned(),
            operation_id: "runtime-supervision-fixture".to_owned(),
            invocation_id: None,
            adapter_id: Some("fixture".to_owned()),
            generation: 1,
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
            phase_deadline_at: now + time::Duration::seconds(1),
            absolute_deadline_at: now + time::Duration::seconds(2),
            restart_count: 0,
            restart_window_started_at: None,
            role_lease_id: None,
            role_lease_epoch: None,
            runtime_contract_sha256: None,
            last_error_class: None,
            last_evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn runtime_supervision_restart_classification_never_blindly_retries_dispatch() {
        let mut checkpoint = checkpoint();
        assert_eq!(
            classify_restart(&checkpoint, None, false),
            RestartDecision::RestartFreshGeneration
        );
        checkpoint.dispatch_state = ProviderDispatchState::Starting;
        assert_eq!(
            classify_restart(&checkpoint, None, false),
            RestartDecision::ReconcileBeforeAnyRetry
        );
        checkpoint.dispatch_state = ProviderDispatchState::NotStarted;
        checkpoint.restart_count = 1;
        assert_eq!(
            classify_restart(&checkpoint, None, false),
            RestartDecision::OpenCircuit
        );
        assert_eq!(
            classify_restart(&checkpoint, None, true),
            RestartDecision::AcceptCapturedTerminalThenReap
        );
    }

    #[tokio::test]
    async fn runtime_supervision_watchdog_cancels_stale_operation() -> Result<(), crate::EngineError>
    {
        let supervisor = OperationSupervisor::new(OperationRuntimeHandle::disabled());
        let mut checkpoint = checkpoint();
        let now = OffsetDateTime::now_utc();
        checkpoint.phase_deadline_at = now - time::Duration::seconds(1);
        let cancellation = supervisor.register(checkpoint).await?;
        let cancelled = supervisor.watchdog_once(now).await?;
        assert_eq!(cancelled, vec!["runtime-supervision-fixture"]);
        assert!(cancellation.is_cancelled());
        Ok(())
    }
}
