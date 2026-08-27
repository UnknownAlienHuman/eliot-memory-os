//! Process execution tests — test-oracle only.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md` :: A2.3 and `ARCH-MOD-01` — modular architecture, ordinary module boundary.
//! - `ELIOT_IMPLEMENTATION.md` :: I2.2, `I2.16`, `I2.20`, `I2.23` — kernel process execution orchestration.
//!
//! This module is test-oracle only with no process, authority, Store or daemon ownership and exercises only the Kernel composition boundary via `super::*`.

use super::*;

#[derive(Clone)]
struct GatewayTestPorts {
    state: Arc<Mutex<GatewayTestState>>,
}

struct GatewayTestState {
    snapshot: Result<CanonicalValidationSnapshot, String>,
    snapshot_calls: usize,
    issue_calls: usize,
    executor_starts: usize,
    validations: usize,
    resumes: usize,
    retained_contexts: BTreeMap<OperationId, (FencingToken, BTreeMap<String, String>, u64)>,
    retained_paths: std::collections::BTreeSet<OperationId>,
    context_count_tx: tokio::sync::watch::Sender<usize>,
    replay: BTreeMap<OperationId, ProcessExecutionReplayRecord>,
    completed_persisted: usize,
    fail_context: bool,
    abort_not_released: bool,
    abort_calls: usize,
    pause_executor: Option<Arc<tokio::sync::Notify>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayTestRequest {
    operation_id: OperationId,
    fence: FencingToken,
    heads: BTreeMap<String, String>,
    validation_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayTestReceipt {
    operation_id: OperationId,
}

struct GatewayTestGuard {
    state: Arc<Mutex<GatewayTestState>>,
    operation_id: OperationId,
    context: bool,
}

impl Drop for GatewayTestGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if self.context {
                state.retained_contexts.remove(&self.operation_id);
            } else {
                state.retained_paths.remove(&self.operation_id);
            }
            let _ = state.context_count_tx.send(state.retained_contexts.len());
        }
    }
}

fn gateway_test_snapshot() -> CanonicalValidationSnapshot {
    let fence = StoreStateFence::new(
        eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
        eliot_contracts::ResourceGeneration::new(1).expect("generation"),
    );
    CanonicalValidationSnapshot {
        state_fence: fence.clone(),
        revision_heads: vec![RevisionHead {
            key: RevisionKey::new("scope:test").expect("key"),
            revision: 7,
            state_fence: fence,
        }],
        validation_revision: 9,
        observed_at_unix_ms: 1_000,
    }
}

impl GatewayTestPorts {
    fn new(snapshot: Result<CanonicalValidationSnapshot, String>) -> Self {
        let (context_count_tx, _context_count_rx) = tokio::sync::watch::channel(0_usize);
        Self {
            state: Arc::new(Mutex::new(GatewayTestState {
                snapshot,
                snapshot_calls: 0,
                issue_calls: 0,
                executor_starts: 0,
                validations: 0,
                resumes: 0,
                retained_contexts: BTreeMap::new(),
                retained_paths: std::collections::BTreeSet::new(),
                context_count_tx,
                replay: BTreeMap::new(),
                completed_persisted: 0,
                fail_context: false,
                abort_not_released: false,
                abort_calls: 0,
                pause_executor: None,
            })),
        }
    }

    async fn wait_contexts(&self, target: usize) {
        let mut receiver = self
            .state
            .lock()
            .expect("test state")
            .context_count_tx
            .subscribe();
        while *receiver.borrow() < target {
            receiver.changed().await.expect("context count channel");
        }
    }

    fn pause_executor(&self, pause: Arc<tokio::sync::Notify>) {
        self.state.lock().expect("test state").pause_executor = Some(pause);
    }

    fn fail_context(&self) {
        self.state.lock().expect("test state").fail_context = true;
    }

    fn allow_context(&self) {
        self.state.lock().expect("test state").fail_context = false;
    }

    fn fail_abort(&self) {
        self.state.lock().expect("test state").abort_not_released = true;
    }

    fn allow_abort(&self) {
        self.state.lock().expect("test state").abort_not_released = false;
    }

    fn counts(&self) -> (usize, usize, usize, usize, usize) {
        let state = self.state.lock().expect("test state");
        (
            state.snapshot_calls,
            state.issue_calls,
            state.executor_starts,
            state.validations,
            state.resumes,
        )
    }

    fn retained(&self) -> (usize, usize) {
        let state = self.state.lock().expect("test state");
        (state.retained_contexts.len(), state.retained_paths.len())
    }

    fn abort_calls(&self) -> usize {
        self.state.lock().expect("test state").abort_calls
    }
}

impl ProcessStartPorts for GatewayTestPorts {
    type PathProof = ();
    type Request = GatewayTestRequest;
    type Receipt = GatewayTestReceipt;

    fn validate_admission(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        owner: &ProcessOwnerBinding,
    ) -> Result<(), ProcessExecutionError> {
        if admission.recipient_module_id() != owner.module_id()
            || admission.state_fence().authority_epoch() != owner.authority_epoch()
            || admission.state_fence().generation() != owner.generation()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        Ok(())
    }

    fn now(&self) -> u64 {
        unix_ms()
    }

    fn validate_path(
        &self,
        _admission: &ProcessExecutionAdmissionRequest,
        _path_proof: &Self::PathProof,
    ) -> Result<(), ProcessExecutionError> {
        Ok(())
    }

    fn begin(
        &self,
        operation_id: &OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, ProcessExecutionError> {
        let mut state = self.state.lock().expect("test state");
        if let Some(existing) = state.replay.get(operation_id) {
            return Ok(ProcessExecutionReplayBegin::Existing(existing.clone()));
        }
        let record = ProcessExecutionReplayRecord {
            admission_digest: digest.to_owned(),
            owner: owner.clone(),
            state: ProcessExecutionReplayState::Reserved,
            receipt: None,
        };
        state.replay.insert(operation_id.clone(), record);
        Ok(ProcessExecutionReplayBegin::Acquired)
    }

    async fn completed_receipt(
        &self,
        _record: ProcessExecutionReplayRecord,
    ) -> Result<Option<Self::Receipt>, ProcessExecutionError> {
        Err(ProcessExecutionError::UnknownOutcome)
    }

    async fn snapshot(&self) -> Result<CanonicalValidationSnapshot, ProcessExecutionError> {
        let snapshot = {
            let mut state = self.state.lock().expect("test state");
            state.snapshot_calls += 1;
            state.snapshot.clone()
        };
        snapshot.map_err(ProcessExecutionError::Unavailable)
    }

    fn build_context(
        &self,
        clock: ClockObservation,
        store_fence: FencingToken,
        authority_epoch: u64,
        revision_heads: BTreeMap<String, String>,
        validation_revision: u64,
    ) -> Result<DispatchValidationContext, ProcessExecutionError> {
        if self.state.lock().expect("test state").fail_context {
            return Err(ProcessExecutionError::Unavailable(
                "injected validation context failure".to_owned(),
            ));
        }
        DispatchValidationContext::new(
            clock,
            store_fence,
            authority_epoch,
            revision_heads,
            validation_revision,
        )
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn insert_context(
        &self,
        operation_id: OperationId,
        context: DispatchValidationContext,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        {
            let mut state = self.state.lock().expect("test state");
            if state.retained_contexts.contains_key(&operation_id) {
                return Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ));
            }
            let _ = context;
            state.retained_contexts.insert(
                operation_id.clone(),
                (
                    FencingToken::new(1, Generation::new(1).expect("generation"), "pending")
                        .expect("pending fence"),
                    BTreeMap::new(),
                    0,
                ),
            );
            let _ = state.context_count_tx.send(state.retained_contexts.len());
        }
        Ok(Box::new(GatewayTestGuard {
            state: Arc::clone(&self.state),
            operation_id,
            context: true,
        }))
    }

    fn issue(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        store_fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        _now: u64,
        validation_revision: u64,
    ) -> Result<Self::Request, ProcessExecutionError> {
        let mut state = self.state.lock().expect("test state");
        state.issue_calls += 1;
        if let Some(context) = state
            .retained_contexts
            .get_mut(admission.intent().operation_id())
        {
            *context = (
                store_fence.clone(),
                revision_heads.clone(),
                validation_revision,
            );
        }
        Ok(GatewayTestRequest {
            operation_id: admission.intent().operation_id().clone(),
            fence: store_fence,
            heads: revision_heads,
            validation_revision,
        })
    }

    fn insert_path(
        &self,
        operation_id: OperationId,
        _path_proof: Self::PathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        let mut state = self.state.lock().expect("test state");
        if !state.retained_paths.insert(operation_id.clone()) {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        Ok(Box::new(GatewayTestGuard {
            state: Arc::clone(&self.state),
            operation_id,
            context: false,
        }))
    }

    async fn execute(
        &self,
        _owner: &ProcessOwnerBinding,
        request: Self::Request,
    ) -> Result<Self::Receipt, ProcessExecutionError> {
        let pause = {
            let mut state = self.state.lock().expect("test state");
            state.executor_starts += 1;
            let context = state.retained_contexts.get(&request.operation_id).ok_or(
                ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ),
            )?;
            if context.0 != request.fence
                || context.1 != request.heads
                || context.2 != request.validation_revision
            {
                return Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ));
            }
            state.validations += 1;
            state.pause_executor.clone()
        };
        if let Some(pause) = pause {
            pause.notified().await;
        }
        self.state.lock().expect("test state").resumes += 1;
        Ok(GatewayTestReceipt {
            operation_id: request.operation_id,
        })
    }

    fn persist_completed(
        &self,
        operation_id: &OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
        receipt: Self::Receipt,
    ) -> Result<(), ProcessExecutionError> {
        let mut state = self.state.lock().expect("test state");
        state.completed_persisted += 1;
        state.replay.insert(
            operation_id.clone(),
            ProcessExecutionReplayRecord {
                admission_digest: digest.to_owned(),
                owner: owner.clone(),
                state: ProcessExecutionReplayState::Completed,
                receipt: None,
            },
        );
        assert_eq!(receipt.operation_id, *operation_id);
        Ok(())
    }

    fn mark_unknown(&self, operation_id: &OperationId, digest: &str, owner: &ProcessOwnerBinding) {
        if let Ok(mut state) = self.state.lock() {
            state.replay.insert(
                operation_id.clone(),
                ProcessExecutionReplayRecord {
                    admission_digest: digest.to_owned(),
                    owner: owner.clone(),
                    state: ProcessExecutionReplayState::Unknown,
                    receipt: None,
                },
            );
        }
    }

    fn abort(
        &self,
        operation_id: &OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, ProcessExecutionError> {
        let mut state = self.state.lock().expect("test state");
        state.abort_calls += 1;
        if state.abort_not_released {
            return Ok(ProcessExecutionReplayAbort::NotReleased);
        }
        let Some(record) = state.replay.get(operation_id) else {
            return Err(ProcessExecutionError::Unavailable(
                "missing replay".to_owned(),
            ));
        };
        if record.state == ProcessExecutionReplayState::Reserved
            && record.admission_digest == digest
            && record.owner == *owner
        {
            state.replay.remove(operation_id);
            return Ok(ProcessExecutionReplayAbort::Released);
        }
        Ok(ProcessExecutionReplayAbort::NotReleased)
    }
}

#[tokio::test]
async fn actual_process_start_orchestration_proves_canonical_ordering() {
    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let owner = gateway_test_owner();
    let admission = gateway_test_admission("gateway-positive");
    let receipt = run_process_start(&ports, &owner, admission, ())
        .await
        .expect("start");
    assert_eq!(receipt.operation_id.as_str(), "gateway-positive");
    assert_eq!(ports.counts(), (1, 1, 1, 1, 1));
    assert_eq!(ports.retained(), (0, 0));
    let state = ports.state.lock().expect("test state");
    assert_eq!(state.completed_persisted, 1);
    assert_eq!(
        state
            .replay
            .get(&OperationId::new("gateway-positive").expect("operation"))
            .expect("completed replay")
            .state,
        ProcessExecutionReplayState::Completed
    );
}

#[cfg(windows)]
#[tokio::test]
async fn stale_completed_restart_never_replays_and_new_attempt_starts_fresh() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-stale-completed-attempt-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let launch = test_daemon_launch(&root);
    let generation = Generation::new(launch.generation.value()).expect("generation");
    let old_attempt = eliotd_launch_attempt_identity(
        &launch,
        42_001,
        7_001,
        r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
    )
    .expect("old attempt");
    let restarted_attempt = eliotd_launch_attempt_identity(
        &launch,
        42_001,
        7_002,
        r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
    )
    .expect("restarted attempt");
    let old_operation =
        eliotd_operation_id(generation, &old_attempt).expect("old operation identity");
    let restarted_operation =
        eliotd_operation_id(generation, &restarted_attempt).expect("restarted operation identity");
    assert_ne!(old_operation, restarted_operation);

    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let owner = gateway_test_owner();
    run_process_start(
        &ports,
        &owner,
        gateway_test_admission(old_operation.as_str()),
        (),
    )
    .await
    .expect("old attempt start");
    assert!(
        run_process_start(
            &ports,
            &owner,
            gateway_test_admission(old_operation.as_str()),
            (),
        )
        .await
        .is_err(),
        "a Completed record without fresh live executor evidence must not replay"
    );
    assert_eq!(ports.counts().2, 1);
    run_process_start(
        &ports,
        &owner,
        gateway_test_admission(restarted_operation.as_str()),
        (),
    )
    .await
    .expect("restarted Kernel gets a fresh exact attempt");
    assert_eq!(ports.counts().2, 2);
}

#[tokio::test]
async fn actual_process_start_orchestration_fails_closed_and_releases_reserved() {
    let mut malformed = gateway_test_snapshot();
    malformed.validation_revision = 0;
    let mut stale = gateway_test_snapshot();
    stale.state_fence = StoreStateFence::new(
        eliot_contracts::AuthorityEpoch::new(2).expect("epoch"),
        eliot_contracts::ResourceGeneration::new(1).expect("generation"),
    );
    for head in &mut stale.revision_heads {
        head.state_fence = stale.state_fence.clone();
    }
    let mut substituted = gateway_test_snapshot();
    substituted.revision_heads[0].state_fence = StoreStateFence::new(
        eliot_contracts::AuthorityEpoch::new(8).expect("epoch"),
        eliot_contracts::ResourceGeneration::new(1).expect("generation"),
    );
    for (name, snapshot) in [
        ("unavailable", Err("store unavailable".to_owned())),
        ("malformed", Ok(malformed)),
        ("stale", Ok(stale)),
        ("substituted", Ok(substituted)),
    ] {
        let ports = GatewayTestPorts::new(snapshot);
        let owner = gateway_test_owner();
        let admission = gateway_test_admission(&format!("gateway-{name}"));
        assert!(
            run_process_start(&ports, &owner, admission.clone(), ())
                .await
                .is_err()
        );
        assert_eq!(ports.counts(), (1, 0, 0, 0, 0));
        assert_eq!(ports.retained(), (0, 0));
        assert!(ports.state.lock().expect("test state").replay.is_empty());
        let digest = process_admission_digest(&admission).expect("digest");
        assert!(matches!(
            ports.begin(admission.intent().operation_id(), &digest, &owner),
            Ok(ProcessExecutionReplayBegin::Acquired)
        ));
        assert!(matches!(
            ports.abort(admission.intent().operation_id(), &digest, &owner),
            Ok(ProcessExecutionReplayAbort::Released)
        ));
    }
}

#[tokio::test]
async fn actual_process_start_context_failure_explicitly_aborts_and_maps_abort_failure() {
    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    ports.fail_context();
    ports.fail_abort();
    let owner = gateway_test_owner();
    let admission = gateway_test_admission("gateway-context-failure");
    assert!(matches!(
        run_process_start(&ports, &owner, admission.clone(), ()).await,
        Err(ProcessExecutionError::UnknownOutcome)
    ));
    assert_eq!(ports.counts(), (1, 0, 0, 0, 0));
    assert_eq!(ports.abort_calls(), 1);
    assert_eq!(ports.retained(), (0, 0));
    assert_eq!(
        ports
            .state
            .lock()
            .expect("test state")
            .replay
            .get(admission.intent().operation_id())
            .expect("reserved replay")
            .state,
        ProcessExecutionReplayState::Reserved
    );

    ports.allow_abort();
    let digest = process_admission_digest(&admission).expect("digest");
    assert!(matches!(
        ports.abort(admission.intent().operation_id(), &digest, &owner),
        Ok(ProcessExecutionReplayAbort::Released)
    ));
    ports.allow_context();
    assert!(
        run_process_start(&ports, &owner, admission, ())
            .await
            .is_ok(),
        "exact retry after explicit release"
    );
    assert_eq!(ports.abort_calls(), 2);
    assert_eq!(ports.retained(), (0, 0));
}

#[tokio::test]
async fn actual_process_start_orchestration_isolated_for_concurrent_and_duplicate_ops() {
    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let owner = gateway_test_owner();
    let first_ports = ports.clone();
    let first_owner = owner.clone();
    let first = tokio::spawn(async move {
        run_process_start(
            &first_ports,
            &first_owner,
            gateway_test_admission("gateway-concurrent-a"),
            (),
        )
        .await
    });
    let second_ports = ports.clone();
    let second_owner = owner.clone();
    let second = tokio::spawn(async move {
        run_process_start(
            &second_ports,
            &second_owner,
            gateway_test_admission("gateway-concurrent-b"),
            (),
        )
        .await
    });
    assert!(first.await.expect("first task").is_ok());
    assert!(second.await.expect("second task").is_ok());
    assert_eq!(ports.counts(), (2, 2, 2, 2, 2));
    assert_eq!(ports.retained(), (0, 0));

    let paused = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let pause = Arc::new(tokio::sync::Notify::new());
    paused.pause_executor(Arc::clone(&pause));
    let duplicate_admission = gateway_test_admission("gateway-duplicate");
    let first_admission = duplicate_admission.clone();
    let duplicate_ports = paused.clone();
    let duplicate_owner = owner.clone();
    let first = tokio::spawn(async move {
        run_process_start(&duplicate_ports, &duplicate_owner, first_admission, ()).await
    });
    paused.wait_contexts(1).await;
    let duplicate = run_process_start(&paused, &owner, duplicate_admission, ()).await;
    assert!(matches!(
        duplicate,
        Err(ProcessExecutionError::UnknownOutcome)
    ));
    assert_eq!(paused.retained(), (1, 1));
    pause.notify_waiters();
    assert!(first.await.expect("duplicate task").is_ok());
    assert_eq!(paused.retained(), (0, 0));
}

#[tokio::test]
async fn actual_process_start_orchestration_abort_cleans_exact_context_path_and_replay() {
    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let pause = Arc::new(tokio::sync::Notify::new());
    ports.pause_executor(Arc::clone(&pause));
    let task_ports = ports.clone();
    let owner = gateway_test_owner();
    let task_owner = owner.clone();
    let task = tokio::spawn(async move {
        run_process_start(
            &task_ports,
            &task_owner,
            gateway_test_admission("gateway-cancelled"),
            (),
        )
        .await
    });
    ports.wait_contexts(1).await;
    assert_eq!(ports.retained(), (1, 1));
    task.abort();
    assert!(task.await.expect_err("cancelled task").is_cancelled());
    assert_eq!(ports.retained(), (0, 0));
    assert!(ports.state.lock().expect("test state").replay.is_empty());

    let retry = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    assert!(
        run_process_start(
            &retry,
            &owner,
            gateway_test_admission("gateway-cancelled"),
            (),
        )
        .await
        .is_ok()
    );
    assert_eq!(retry.counts(), (1, 1, 1, 1, 1));
}
