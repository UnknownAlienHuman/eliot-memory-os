//! Process execution tests — test-oracle only.
//!
//! Architecture traceability:
//! - `A2.3` (`docs/architecture/A02-03-modular-architecture.md`) and
//!   `ARCH-MOD-01` — modular architecture, ordinary module boundary.
//! - `I2.16`
//!   (`docs/architecture/I02-16-crate-size-and-agent-context-envelope.md`),
//!   `I2.20`
//!   (`docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md`)
//!   is the Module Contract Kit, Crate Context Capsule, and Module Test
//!   Capsule; and
//!   `I2.23`
//!   (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`)
//!   — kernel process execution orchestration.
//!
//! This module is test-oracle only with no process, authority, Store or daemon ownership and exercises only the Kernel composition boundary via `super::*`.

use super::*;
use eliot_contracts::{EpochId, EpochLineageId};

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

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
    /// #1884 AUD4: the new-operation authority this fixture's own data states.
    /// Empty by default, because this fixture has no recorded
    /// `KernelExecutionManifest` and no ORS effect operation lease.
    new_effect_authority: BTreeSet<GatewayTestEffectAuthority>,
    /// #1885 (I1.9, W2): the effect-replay authority this fixture's own data
    /// states. Empty by default, for the same reason: the effect operation
    /// lease an effect-capable replay needs is an ORS-owned durable record this
    /// fixture does not have.
    effect_replay_authority: BTreeSet<GatewayTestEffectAuthority>,
    pause_executor: Option<Arc<tokio::sync::Notify>>,
}

/// One admitted operation authority, stated exactly as a test records it.
///
/// These are the coordinates the production seam compares: the authenticated
/// owner identity (module id and generation) plus this operation's own
/// identity, and the effect receipt the production lease records — the
/// admission digest `run_process_start` computes over the admitted request.
/// A grant is a recorded row and never a flag, so a foreign, substituted or
/// empty input cannot be admitted by a row some other test case recorded.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GatewayTestEffectAuthority {
    module_id: String,
    generation: u64,
    operation_id: OperationId,
    admission_digest: String,
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

/// The one admitted operation authority a test records for its own scenario.
///
/// The coordinates are exactly the ones the production seam binds: the
/// authenticated owner identity, this operation's identity, and the admission
/// digest the production lease records as its effect receipt.
fn gateway_test_authority(
    owner: &ProcessOwnerBinding,
    admission: &ProcessExecutionAdmissionRequest,
) -> GatewayTestEffectAuthority {
    GatewayTestEffectAuthority {
        module_id: owner.module_id().to_owned(),
        generation: owner.generation().get(),
        operation_id: admission.intent().operation_id().clone(),
        admission_digest: process_admission_digest(admission).expect("admission digest"),
    }
}

fn gateway_test_snapshot() -> CanonicalValidationSnapshot {
    let fence = StoreStateFence::new(
        test_epoch(1),
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
                new_effect_authority: BTreeSet::new(),
                effect_replay_authority: BTreeSet::new(),
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

    /// Records the admitted authority for exactly this one new operation
    /// (#1884 AUD4).
    ///
    /// The gate refuses by default, so a scenario that needs the granted path
    /// states here the owner identity and the admitted request whose digest
    /// the production lease would record as its effect receipt. Nothing else
    /// admits a new operation: a different operation, a different owner
    /// identity, or a substituted digest is refused by the comparison in
    /// `require_new_effect_operation_authority`.
    fn admit_new_effect_authority(
        &self,
        owner: &ProcessOwnerBinding,
        admission: &ProcessExecutionAdmissionRequest,
    ) {
        self.state
            .lock()
            .expect("test state")
            .new_effect_authority
            .insert(gateway_test_authority(owner, admission));
    }

    /// Records the admitted authority for exactly this one replayed operation
    /// (#1885; I1.9, W2).
    ///
    /// The `Existing(record)` arm reaches `require_effect_replay_authority`,
    /// which refuses by default for the same reason. A scenario that needs the
    /// granted resume states the exact owner identity and operation it is
    /// resuming; a different operation identity is refused.
    fn admit_effect_replay_authority(
        &self,
        owner: &ProcessOwnerBinding,
        admission: &ProcessExecutionAdmissionRequest,
    ) {
        self.state
            .lock()
            .expect("test state")
            .effect_replay_authority
            .insert(gateway_test_authority(owner, admission));
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

    /// #1885 (I1.9, W2): the effect operation lease an effect-capable replay
    /// needs is an ORS-owned durable record, and this fixture has none, so the
    /// recorded default is a TYPED REFUSAL: nothing in this double can resume
    /// an operation no test stated. Only
    /// [`GatewayTestPorts::admit_effect_replay_authority`] records one, and it
    /// records the exact owner identity, operation identity and admission
    /// digest the production store resolves the lease by — so a foreign,
    /// substituted or empty input is still refused.
    fn require_effect_replay_authority(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &OperationId,
        _context: &tracing::Span,
    ) -> Result<(), ProcessExecutionError> {
        let admitted = self
            .state
            .lock()
            .map_err(|_| ProcessExecutionError::Unavailable("test state".to_owned()))?
            .effect_replay_authority
            .iter()
            .any(|recorded| {
                recorded.module_id == owner.module_id()
                    && recorded.generation == owner.generation().get()
                    && recorded.operation_id == *operation_id
            });
        if admitted {
            return Ok(());
        }
        // The refusal is typed and it says why: this test recorded no admitted
        // replay authority for the operation it asked about. No lease, no
        // receipt and no permit is invented here, and the denied replay is
        // never reported as an admitted or shadow one.
        Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::InvalidValue {
                field: "test_scripted_effect_replay_authority",
                reason: "this test recorded no admitted replay authority for this operation",
            },
        ))
    }

    /// #1884 AUD4: the recorded `KernelExecutionManifest` and the effect
    /// operation lease an effect-capable generation needs are ORS-owned durable
    /// records, and this fixture has neither, so the recorded default is a
    /// TYPED REFUSAL. Only
    /// [`GatewayTestPorts::admit_new_effect_authority`] admits one, and it
    /// admits exactly the owner identity, operation identity and admission
    /// digest the test recorded — the same coordinates the production lease
    /// binds — so a foreign, substituted or empty input is refused here too
    /// rather than admitted by a flag.
    fn require_new_effect_operation_authority(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &OperationId,
        admission_digest: &str,
        _deadline_unix_ms: u64,
        _context: &tracing::Span,
    ) -> Result<(), ProcessExecutionError> {
        let admitted = self
            .state
            .lock()
            .map_err(|_| ProcessExecutionError::Unavailable("test state".to_owned()))?
            .new_effect_authority
            .iter()
            .any(|recorded| {
                recorded.module_id == owner.module_id()
                    && recorded.generation == owner.generation().get()
                    && recorded.operation_id == *operation_id
                    && recorded.admission_digest == admission_digest
            });
        if admitted {
            return Ok(());
        }
        // The refusal is typed and it says why: this test recorded no admitted
        // new-operation authority for the operation, owner identity and effect
        // receipt it asked about. No permit, lease or generation is invented
        // here, and no admission is reported as an unavailable or shadow one.
        Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::InvalidValue {
                field: "test_scripted_new_effect_operation_authority",
                reason: "this test recorded no admitted new-effect authority for this operation",
            },
        ))
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
        authority_epoch: eliot_contracts::EpochId,
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
                    FencingToken::new(
                        test_epoch(1),
                        Generation::new(1).expect("generation"),
                        "pending",
                    )
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
        _outer_binding: Option<&eliot_kernel_service::HostKernelCandidateBinding>,
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
    ports.admit_new_effect_authority(&owner, &admission);
    let receipt = run_process_start(
        &ports,
        &owner,
        admission,
        (),
        None,
        &tracing::Span::none(),
        &mut false,
    )
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
    // The scenario states both authorities it exercises: the new-operation
    // authority for each first start, and the exact replay authority for the
    // one same-identity resume the `Existing(record)` arm takes. The resumed
    // attempt still fails below because the recorded `Completed` state has no
    // fresh live executor evidence, which is the property this test is about.
    let old_admission = gateway_test_admission(old_operation.as_str());
    let restarted_admission = gateway_test_admission(restarted_operation.as_str());
    ports.admit_new_effect_authority(&owner, &old_admission);
    ports.admit_new_effect_authority(&owner, &restarted_admission);
    ports.admit_effect_replay_authority(&owner, &old_admission);
    run_process_start(
        &ports,
        &owner,
        old_admission.clone(),
        (),
        None,
        &tracing::Span::none(),
        &mut false,
    )
    .await
    .expect("old attempt start");
    assert!(
        run_process_start(
            &ports,
            &owner,
            old_admission,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
        .await
        .is_err(),
        "a Completed record without fresh live executor evidence must not replay"
    );
    assert_eq!(ports.counts().2, 1);
    run_process_start(
        &ports,
        &owner,
        restarted_admission,
        (),
        None,
        &tracing::Span::none(),
        &mut false,
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
        test_epoch(2),
        eliot_contracts::ResourceGeneration::new(1).expect("generation"),
    );
    for head in &mut stale.revision_heads {
        head.state_fence = stale.state_fence.clone();
    }
    let mut substituted = gateway_test_snapshot();
    substituted.revision_heads[0].state_fence = StoreStateFence::new(
        test_epoch(8),
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
        // This scenario is about the fail-closed snapshot, not the new-operation
        // gate, so it states the one authority the `Acquired` arm needs.
        ports.admit_new_effect_authority(&owner, &admission);
        assert!(
            run_process_start(
                &ports,
                &owner,
                admission.clone(),
                (),
                None,
                &tracing::Span::none(),
                &mut false,
            )
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
    // Both starts in this scenario are first starts of the same operation, so
    // the one recorded authority covers the `Acquired` arm each time.
    ports.admit_new_effect_authority(&owner, &admission);
    assert!(matches!(
        run_process_start(
            &ports,
            &owner,
            admission.clone(),
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
        .await,
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
        run_process_start(
            &ports,
            &owner,
            admission,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
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
    // Two distinct first starts, so two distinct recorded authorities: the
    // concurrent second one is not covered by the first one's row.
    let concurrent_a = gateway_test_admission("gateway-concurrent-a");
    let concurrent_b = gateway_test_admission("gateway-concurrent-b");
    ports.admit_new_effect_authority(&owner, &concurrent_a);
    ports.admit_new_effect_authority(&owner, &concurrent_b);
    let first_ports = ports.clone();
    let first_owner = owner.clone();
    let first = tokio::spawn(async move {
        run_process_start(
            &first_ports,
            &first_owner,
            concurrent_a,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
        .await
    });
    let second_ports = ports.clone();
    let second_owner = owner.clone();
    let second = tokio::spawn(async move {
        run_process_start(
            &second_ports,
            &second_owner,
            concurrent_b,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
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
    // The duplicate below is a same-identity RESUME, so the `Existing(record)`
    // arm is the one it reaches; this scenario states that exact replay
    // authority as well as the first start's own. The duplicate still fails,
    // because the reserved record carries no outcome yet.
    paused.admit_new_effect_authority(&owner, &duplicate_admission);
    paused.admit_effect_replay_authority(&owner, &duplicate_admission);
    let first_admission = duplicate_admission.clone();
    let duplicate_ports = paused.clone();
    let duplicate_owner = owner.clone();
    let first = tokio::spawn(async move {
        run_process_start(
            &duplicate_ports,
            &duplicate_owner,
            first_admission,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
        .await
    });
    paused.wait_contexts(1).await;
    let duplicate = run_process_start(
        &paused,
        &owner,
        duplicate_admission,
        (),
        None,
        &tracing::Span::none(),
        &mut false,
    )
    .await;
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
    let cancelled_admission = gateway_test_admission("gateway-cancelled");
    ports.admit_new_effect_authority(&owner, &cancelled_admission);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move {
        run_process_start(
            &task_ports,
            &task_owner,
            cancelled_admission,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
        .await
    });
    ports.wait_contexts(1).await;
    assert_eq!(ports.retained(), (1, 1));
    task.abort();
    assert!(task.await.expect_err("cancelled task").is_cancelled());
    assert_eq!(ports.retained(), (0, 0));
    assert!(ports.state.lock().expect("test state").replay.is_empty());

    // A fresh double has no recorded authority of its own, so this retry states
    // the one it is about to exercise rather than inheriting a grant.
    let retry = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let retry_admission = gateway_test_admission("gateway-cancelled");
    retry.admit_new_effect_authority(&owner, &retry_admission);
    assert!(
        run_process_start(
            &retry,
            &owner,
            retry_admission,
            (),
            None,
            &tracing::Span::none(),
            &mut false,
        )
        .await
        .is_ok()
    );
    assert_eq!(retry.counts(), (1, 1, 1, 1, 1));
}

/// The recorded default of both #1884 AUD4 gates is a TYPED REFUSAL, not a
/// grant: a test that exercises the double without scripting the admitted
/// authority is refused before the snapshot, the context, the issued request
/// and the executor handoff that follow the `Acquired` arm's gate, and it is
/// refused with the recorded reason rather than an invented permit.
#[tokio::test]
async fn an_unscripted_new_effect_operation_is_refused_and_releases_its_reservation() {
    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let owner = gateway_test_owner();
    let admission = gateway_test_admission("gateway-unscripted-authority");
    // No `admit_new_effect_authority` call: this scenario exists to show the
    // default is a refusal.
    let error = run_process_start(
        &ports,
        &owner,
        admission,
        (),
        None,
        &tracing::Span::none(),
        &mut false,
    )
    .await
    .expect_err("an unscripted new operation must not be admitted");
    assert!(matches!(
        error,
        ProcessExecutionError::Contract(eliot_process::ContractError::InvalidValue {
            field: "test_scripted_new_effect_operation_authority",
            reason: "this test recorded no admitted new-effect authority for this operation",
        })
    ));
    // The gate refused before the rest of the `Acquired` arm ran, and the
    // reservation it had taken was released, so nothing is left reserved.
    assert_eq!(ports.counts(), (0, 0, 0, 0, 0));
    assert_eq!(ports.retained(), (0, 0));
    assert_eq!(ports.abort_calls(), 1);
    assert!(ports.state.lock().expect("test state").replay.is_empty());
}

/// The granted path is bound to the exact identity the production seam
/// compares, so an authority recorded for one operation does not admit a
/// foreign operation, a substituted owner identity or a substituted digest.
#[tokio::test]
async fn a_recorded_authority_admits_only_its_own_exact_operation_owner_and_digest() {
    let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
    let owner = gateway_test_owner();
    let recorded = gateway_test_admission("gateway-recorded-authority");
    let foreign = gateway_test_admission("gateway-foreign-authority");
    ports.admit_new_effect_authority(&owner, &recorded);
    let recorded_digest = process_admission_digest(&recorded).expect("recorded digest");
    let foreign_digest = process_admission_digest(&foreign).expect("foreign digest");
    let substituted_owner = ProcessOwnerBinding::new(
        "eliotd",
        "a".repeat(64),
        test_epoch(1),
        Generation::new(2).expect("generation"),
    )
    .expect("substituted owner");

    for (name, owner, operation, digest) in [
        (
            "foreign operation",
            &owner,
            foreign.intent().operation_id(),
            foreign_digest.as_str(),
        ),
        (
            "substituted owner generation",
            &substituted_owner,
            recorded.intent().operation_id(),
            recorded_digest.as_str(),
        ),
        (
            "substituted admission digest",
            &owner,
            recorded.intent().operation_id(),
            foreign_digest.as_str(),
        ),
    ] {
        assert!(
            ports
                .require_new_effect_operation_authority(
                    owner,
                    operation,
                    digest,
                    foreign.deadline_unix_ms(),
                    &tracing::Span::none(),
                )
                .is_err(),
            "{name} must not be admitted by another operation's recorded authority"
        );
    }
    // The recorded row still admits exactly the identity it names.
    ports
        .require_new_effect_operation_authority(
            &owner,
            recorded.intent().operation_id(),
            &recorded_digest,
            recorded.deadline_unix_ms(),
            &tracing::Span::none(),
        )
        .expect("the recorded exact identity is admitted");
    // The replay gate is bound the same way and has no grant of its own.
    assert!(
        ports
            .require_effect_replay_authority(
                &owner,
                recorded.intent().operation_id(),
                &tracing::Span::none(),
            )
            .is_err(),
        "a new-operation authority must not admit a replay"
    );
}
