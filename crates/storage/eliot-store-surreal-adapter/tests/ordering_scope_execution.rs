//! Bounded reserved-scope write execution (S-CONC-EXECUTE, issue #993).
//!
//! Drives the real runtime orchestration
//! ([`WriteExecution`](eliot_store_surreal_adapter::WriteExecution)) over
//! the accepted #988 scheduler core, #987 permit bounds, #990/#991 sealed
//! admission, and the #989 outcome taxonomy through a deterministic
//! scripted transport. No provider is touched: the fake gates race
//! ordering, exactly as the slice requires, while the separate #67
//! acceptance owner exercises the full real path.
//!
//! Declared denominator, exactly one substantive test per case:
//!
//! 1. complete normal/reserved/migration/genesis/recovery entrypoint denominator;
//! 2. concurrent profile requires all accepted current capability/evidence inputs;
//! 3. serial/concurrent profiles cannot write concurrently under incompatible ownership;
//! 4. unreserved Apply cannot bypass the concurrent scheduler;
//! 5. disjoint ready operations enter separate provider execution paths within capacity;
//! 6. overlapping/multi-scope operations obey exact atomic precedence;
//! 7. waiting work holds no provider/protected permit or await-held scheduler lock;
//! 8. current generation/fence/expiry/cancel rechecked before send;
//! 9. exact immutable transition reaches #989 with no dropped optimistic guard;
//! 10. pre-submit cancellation/capacity failure causes no provider call;
//! 11. post-submit cancellation/drop/panic retains operation and reconciliation ownership;
//! 12. uncertain response cannot release successors or trigger blind retry;
//! 13. exact canonical reconciliation resumes only permitted scopes;
//! 14. delayed/unknown scope does not block independent ready work through an application-global gate;
//! 15. bounded normal saturation preserves the declared protected path;
//! 16. no oversubscribed sessions/tasks/queue/history or forgotten unresolved operation;
//! 17. migration closes admission and drains every possible effect;
//! 18. incomplete/unknown drain cannot grant exclusivity;
//! 19. migration failure/unknown stays fenced; accepted generation/schema required to reopen;
//! 20. restart from complete versus incomplete durable recovery denominator;
//! 21. deterministic fault/metrics/redaction fixtures preserve exact result and ownership;
//! 22. source/API/actual-path guard proves no normal global write mutex, hidden semaphore-of-one, duplicate core/SQL, new durable authority or unowned change.
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
};
use eliot_store_api::{
    CAPABILITY_RESERVED_WRITE, CommitId, EffectClass, EventProjectionRelationIntents,
    NamedMutationOperation, NamedMutationRequest, OperationId, OperationIdentity,
    OperationManifestDigest, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, ReservedScopeBinding, ReservedWriteRequest, Resubmission,
    RevisionHeadExpectation, RevisionKey, ScopeId, SecurityContext, StateFence, StoreError,
    TransitionClass, WriteAdmissionParams, WriteAdmissionProjection, WriteReceipt,
    WriteReceiptStatus, WriterEpochBinding, issue_store_receipt_envelope,
};
use eliot_store_surreal_adapter::{
    AdapterError, AttemptOutcome, ClientSetLimits, ConcurrentEvidence, DurableOpOutcome,
    DurableRecoverySet, ExclusiveOpKind, ExecutableAttempt, ExecutionProfile, OpExecution,
    ProviderGate, ReconcileOutcome, ReservationProjection, ReservedAttemptTransport,
    ReservedScopeProjection, SchemaGeneration, SubmitDisposition, WriteExecution,
};
use serde_json::Value;

const LINEAGE_993: &str = "550e8400-e29b-41d4-a716-446655440000";
const BASE_MS: i64 = 1_700_000_000_000;
const NOW: u64 = 1_700_000_010_000;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_993).unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).unwrap()).unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn ctx(op: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-{op}")).unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-993").unwrap(),
        source_id: SourceId::new("source-993").unwrap(),
        state_fence: fence(),
        clock: ClockReading {
            valid_time_ms: Some(1000),
            known_time_ms: Some(1001),
            ..ClockReading::default()
        },
    }
}

fn transition(op: &str, scopes: &[&str]) -> PreparedTransition {
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(op).unwrap(),
            idempotency_key: format!("idem-{op}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(scopes[0]).unwrap(),
        task_id: None,
        ordering_scopes: scopes
            .iter()
            .map(|scope| OrderingScopeId::new(*scope).unwrap())
            .collect(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new("manifest-993").unwrap(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: std::collections::BTreeMap::from([(
                "subject".to_owned(),
                serde_json::json!(format!("observation-{op}")),
            )]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    }
}

fn binding(scope: &str, reserved: u64, expected: u64) -> ReservedScopeBinding {
    ReservedScopeBinding {
        scope: OrderingScopeId::new(scope).unwrap(),
        reserved_sequence: reserved,
        expected_sequence: expected,
        expected_head_digest: "c".repeat(64),
    }
}

fn epoch_binding() -> WriterEpochBinding {
    WriterEpochBinding {
        lineage_id: "epoch-lineage-993".to_owned(),
        epoch: 5,
        predecessor_lineage_id: None,
        predecessor_epoch: None,
    }
}

fn admission_for(
    transition: &PreparedTransition,
    order: u64,
    scopes: Vec<ReservedScopeBinding>,
) -> WriteAdmissionProjection {
    let params = WriteAdmissionParams {
        reservation_id: format!("reservation-{}", transition.identity.operation_id.as_str()),
        reservation_order: order,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes,
        writer_epoch: epoch_binding(),
        state_fence: fence(),
        source_id: "source-993".to_owned(),
        created_at_ms: BASE_MS,
        expires_at_ms: BASE_MS + 60_000,
        recovery_owner: "recovery-owner-993".to_owned(),
    };
    WriteAdmissionProjection::bind(transition, params).unwrap()
}

/// Builds a sealed reserved request over `scopes` as `(scope, reserved,
/// expected)` triples. Scopes must arrive sorted: the admission shape
/// requires sorted-unique, and the scheduler validates rather than
/// repairing.
fn request_scopes(op: &str, scopes: &[(&str, u64, u64)], order: u64) -> ReservedWriteRequest {
    let scope_names: Vec<&str> = scopes.iter().map(|(scope, _, _)| *scope).collect();
    let transition = transition(op, &scope_names);
    let bindings: Vec<ReservedScopeBinding> = scopes
        .iter()
        .map(|(scope, reserved, expected)| binding(*scope, *reserved, *expected))
        .collect();
    let admission = admission_for(&transition, order, bindings);
    let expected_ordering_heads: Vec<OrderingHeadExpectation> = scopes
        .iter()
        .map(|(scope, _, expected)| OrderingHeadExpectation {
            scope: OrderingScopeId::new(*scope).unwrap(),
            expected_sequence: *expected,
            state_fence: fence(),
        })
        .collect();
    ReservedWriteRequest {
        context: ctx(op),
        transition,
        admission,
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new(format!("rev-993-{op}")).unwrap(),
            expected_revision: 3,
            state_fence: fence(),
        }],
        expected_ordering_heads,
    }
}

fn request(
    op: &str,
    scope: &str,
    order: u64,
    reserved: u64,
    expected: u64,
) -> ReservedWriteRequest {
    request_scopes(op, &[(scope, reserved, expected)], order)
}

fn evidence() -> ConcurrentEvidence {
    ConcurrentEvidence {
        capability: CAPABILITY_RESERVED_WRITE,
        observed_generation: SchemaGeneration::v2(),
        expected_generation: SchemaGeneration::v2(),
        state_fence: fence(),
        kernel_generation: "kernel-993".to_owned(),
    }
}

fn install_concurrent_ws(write_sessions: u8, lanes: u8, queue: usize) -> WriteExecution {
    let limits = ClientSetLimits::new(1, write_sessions, 1).unwrap();
    WriteExecution::install_concurrent(
        limits,
        NonZeroUsize::new(usize::from(lanes)).unwrap(),
        NonZeroUsize::new(queue).unwrap(),
        &evidence(),
        NOW,
    )
    .unwrap()
}

/// Committed receipt bound to one executable attempt, mirroring the #991
/// receipt helper: envelope issued over the exact attempt material, then
/// validated.
fn commit_receipt(attempt: &ExecutableAttempt) -> WriteReceipt {
    let transition = &attempt.transition;
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(
            CommitId::new(format!(
                "commit-{}",
                transition.identity.operation_id.as_str()
            ))
            .unwrap(),
        ),
        state_fence: attempt.context.state_fence.clone(),
        ordering_sequences: attempt
            .expected_ordering_heads
            .iter()
            .map(|head| OrderingHead {
                scope: head.scope.clone(),
                sequence: head.expected_sequence,
                state_fence: head.state_fence.clone(),
            })
            .collect(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["capture-observation".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    };
    receipt.envelope =
        Some(issue_store_receipt_envelope(&attempt.context, transition, &receipt, 1).unwrap());
    receipt.validate().unwrap();
    receipt
}

/// Receipt for reconciliation answers, built from the sealed request.
fn receipt_for_request(request: &ReservedWriteRequest) -> WriteReceipt {
    let attempt = ExecutableAttempt {
        operation_id: request.transition.identity.operation_id.clone(),
        context: request.context.clone(),
        transition: request.transition.clone(),
        expected_revision_heads: request.expected_revision_heads.clone(),
        expected_ordering_heads: request.expected_ordering_heads.clone(),
        reservation_order: request.admission.reservation_order,
        expires_at_ms: request.admission.expires_at_ms,
    };
    commit_receipt(&attempt)
}

type ExecuteFn = Arc<
    dyn for<'a> Fn(
            &'a WriteExecution,
            &'a ExecutableAttempt,
        ) -> Pin<Box<dyn Future<Output = AttemptOutcome> + Send + 'a>>
        + Send
        + Sync,
>;

#[derive(Clone)]
enum ExecuteScript {
    Commit,
    Reject(StoreError),
    DeadLetter,
    Cancel,
    Unknown,
    Custom(ExecuteFn),
}

#[derive(Clone, Debug, PartialEq)]
enum Call {
    Gate(String),
    Execute(String),
    Reconcile(String),
}

/// Deterministic scripted transport: scripted gate/execute/reconcile
/// answers per operation (or generation-wide defaults) with a complete
/// call record and live-execution tracking. No provider, no clock.
struct ScriptedTransport {
    calls: Mutex<Vec<Call>>,
    gate: Mutex<ProviderGate>,
    per_op_gate: Mutex<BTreeMap<String, ProviderGate>>,
    execute: Mutex<ExecuteScript>,
    per_op_execute: Mutex<BTreeMap<String, ExecuteScript>>,
    reconcile: Mutex<ReconcileOutcome>,
    per_op_reconcile: Mutex<BTreeMap<String, ReconcileOutcome>>,
    live: Mutex<usize>,
    max_live: Mutex<usize>,
}

impl ScriptedTransport {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            gate: Mutex::new(ProviderGate::open()),
            per_op_gate: Mutex::new(BTreeMap::new()),
            execute: Mutex::new(ExecuteScript::Commit),
            per_op_execute: Mutex::new(BTreeMap::new()),
            reconcile: Mutex::new(ReconcileOutcome::StillUnknown),
            per_op_reconcile: Mutex::new(BTreeMap::new()),
            live: Mutex::new(0),
            max_live: Mutex::new(0),
        }
    }

    fn set_gate(&self, op: &str, gate: ProviderGate) {
        self.per_op_gate.lock().unwrap().insert(op.to_owned(), gate);
    }

    fn set_execute_all(&self, script: ExecuteScript) {
        *self.execute.lock().unwrap() = script;
    }

    fn set_execute(&self, op: &str, script: ExecuteScript) {
        self.per_op_execute
            .lock()
            .unwrap()
            .insert(op.to_owned(), script);
    }

    fn set_reconcile_all(&self, outcome: ReconcileOutcome) {
        *self.reconcile.lock().unwrap() = outcome;
    }

    fn set_reconcile(&self, op: &str, outcome: ReconcileOutcome) {
        self.per_op_reconcile
            .lock()
            .unwrap()
            .insert(op.to_owned(), outcome);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn execute_calls(&self, op: &str) -> usize {
        self.calls()
            .iter()
            .filter(|call| matches!(call, Call::Execute(id) if id == op))
            .count()
    }

    fn max_live(&self) -> usize {
        *self.max_live.lock().unwrap()
    }

    fn record(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
    }

    fn gate_for(&self, op: &str) -> ProviderGate {
        self.per_op_gate
            .lock()
            .unwrap()
            .get(op)
            .copied()
            .unwrap_or_else(|| *self.gate.lock().unwrap())
    }

    fn execute_for(&self, op: &str) -> ExecuteScript {
        self.per_op_execute
            .lock()
            .unwrap()
            .get(op)
            .cloned()
            .unwrap_or_else(|| self.execute.lock().unwrap().clone())
    }

    fn reconcile_for(&self, op: &str) -> ReconcileOutcome {
        self.per_op_reconcile
            .lock()
            .unwrap()
            .get(op)
            .cloned()
            .unwrap_or_else(|| self.reconcile.lock().unwrap().clone())
    }
}

fn script_future<'a>(
    script: &ExecuteScript,
    execution: &'a WriteExecution,
    attempt: &'a ExecutableAttempt,
) -> Pin<Box<dyn Future<Output = AttemptOutcome> + Send + 'a>> {
    match script.clone() {
        ExecuteScript::Commit => {
            Box::pin(async move { AttemptOutcome::Committed(Box::new(commit_receipt(attempt))) })
        }
        ExecuteScript::Reject(error) => Box::pin(async move { AttemptOutcome::Rejected(error) }),
        ExecuteScript::DeadLetter => Box::pin(async move { AttemptOutcome::DeadLetter }),
        ExecuteScript::Cancel => Box::pin(async move { AttemptOutcome::Cancelled }),
        ExecuteScript::Unknown => {
            Box::pin(async move { AttemptOutcome::Unknown { retry_after_ms: 0 } })
        }
        ExecuteScript::Custom(execute) => execute(execution, attempt),
    }
}

impl ReservedAttemptTransport for ScriptedTransport {
    async fn read_submission_gate(
        &self,
        _execution: &WriteExecution,
        attempt: &ExecutableAttempt,
        _now_ms: u64,
    ) -> ProviderGate {
        let op = attempt.operation_id.as_str().to_owned();
        self.record(Call::Gate(op.clone()));
        self.gate_for(&op)
    }

    async fn execute_attempt(
        &self,
        execution: &WriteExecution,
        attempt: &ExecutableAttempt,
    ) -> AttemptOutcome {
        let op = attempt.operation_id.as_str().to_owned();
        self.record(Call::Execute(op.clone()));
        {
            let mut live = self.live.lock().unwrap();
            *live += 1;
            let mut max_live = self.max_live.lock().unwrap();
            *max_live = (*max_live).max(*live);
        }
        let script = self.execute_for(&op);
        let outcome = script_future(&script, execution, attempt).await;
        {
            let mut live = self.live.lock().unwrap();
            *live -= 1;
        }
        outcome
    }

    async fn reconcile_unknown(
        &self,
        _execution: &WriteExecution,
        operation_id: &OperationId,
    ) -> ReconcileOutcome {
        let op = operation_id.as_str().to_owned();
        self.record(Call::Reconcile(op.clone()));
        self.reconcile_for(&op)
    }
}

/// Runs one ready batch with a hang guard: a wedged orchestration fails
/// the test instead of hanging the suite.

/// Runs one ready batch with a hang guard: a wedged orchestration fails
/// the test instead of hanging the suite.
async fn run_batch(
    execution: &WriteExecution,
    now_ms: u64,
    transport: &ScriptedTransport,
) -> Vec<OpExecution> {
    tokio::time::timeout(
        Duration::from_secs(10),
        execution.run_ready_batch(now_ms, transport),
    )
    .await
    .expect("batch completes without hanging")
    .expect("batch succeeds")
}

fn source(path: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("current source")
}

fn committed_id(outcome: &OpExecution) -> &str {
    if let OpExecution::Committed { operation_id, .. } = outcome {
        operation_id.as_str()
    } else {
        assert_eq!(
            format!("{outcome:?}"),
            "committed",
            "expected a commit outcome"
        );
        "unreachable-commit"
    }
}

// WORK_UNIT_CASE: 993/1
#[tokio::test]
async fn complete_entrypoint_denominator_routes_reserved_and_refuses_serial() {
    // The concurrent generation accepts a sealed reserved write and
    // returns its commit through the real orchestration; the serial
    // profile refuses the reserved shape; the client/migration/genesis
    // delegation lives on the adapter surface (source-bound below, since
    // adapter construction needs a provider lease).
    let execution = install_concurrent_ws(2, 2, 8);
    let transport = ScriptedTransport::new();
    let submitted = execution
        .submit_reserved(request("op-993-01", "scope-993-01", 1, 5, 4), NOW)
        .expect("reserved submit accepted");
    assert_eq!(submitted, SubmitDisposition::Accepted);
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert_eq!(outcomes.len(), 1, "one ready operation executes");
    assert!(
        matches!(
            &outcomes[0],
            OpExecution::Committed {
                reconciled: false,
                ..
            }
        ),
        "direct commit, not a reconciliation: {:?}",
        outcomes[0]
    );
    assert_eq!(committed_id(&outcomes[0]), "op-993-01");
    if let OpExecution::Committed { receipt, .. } = &outcomes[0] {
        assert_eq!(receipt.operation_id.as_str(), "op-993-01");
        receipt.validate().expect("receipt validates");
    }
    assert_eq!(execution.pending_count(), 0);

    let serial = WriteExecution::install_serial(
        ClientSetLimits::compatibility(),
        NonZeroUsize::new(8).unwrap(),
    )
    .unwrap();
    let refused = serial
        .submit_reserved(request("op-993-01s", "scope-993-01s", 1, 5, 4), NOW)
        .expect_err("serial refuses the reserved shape");
    assert_eq!(
        refused,
        AdapterError::Store(StoreError::InvalidField {
            field: "store.write_path",
            reason: "reserved writes require the concurrent execution profile",
        })
    );

    let lib = source("src/lib.rs");
    assert!(
        lib.contains("async fn apply_reserved_write"),
        "client delegation exists"
    );
    assert!(
        lib.contains("reserved_write_capability"),
        "capability evidence exists"
    );
    let apply = source("src/apply.rs");
    assert!(
        apply.contains("pub(crate) async fn apply_reserved_write"),
        "reserved delegation exists"
    );
    assert!(
        apply.contains("drain_for_migration"),
        "exclusive drain wiring exists"
    );
}

// WORK_UNIT_CASE: 993/2
#[test]
fn concurrent_profile_requires_all_accepted_capability_evidence_inputs() {
    // Every concurrent evidence input is load-bearing: each invalid input
    // below fails installation, and only the complete accepted set admits.
    let limits = ClientSetLimits::new(1, 2, 1).unwrap();
    let lanes = NonZeroUsize::new(2).unwrap();
    let queue = NonZeroUsize::new(8).unwrap();
    assert!(WriteExecution::install_concurrent(limits, lanes, queue, &evidence(), NOW).is_ok());

    let mut wrong_capability = evidence();
    wrong_capability.capability = "store.write";
    let refused = WriteExecution::install_concurrent(limits, lanes, queue, &wrong_capability, NOW)
        .expect_err("lookalike capability refused");
    assert_eq!(
        refused,
        AdapterError::Store(StoreError::InvalidField {
            field: "execution.capability",
            reason: "concurrent execution requires the accepted reserved-write capability",
        })
    );

    let mut wrong_generation = evidence();
    wrong_generation.expected_generation = SchemaGeneration::new("1.0.0").unwrap();
    assert!(
        WriteExecution::install_concurrent(limits, lanes, queue, &wrong_generation, NOW).is_err(),
        "generation drift refused"
    );

    let mut blank_kernel = evidence();
    blank_kernel.kernel_generation = "   ".to_owned();
    assert!(
        WriteExecution::install_concurrent(limits, lanes, queue, &blank_kernel, NOW).is_err(),
        "missing Kernel binding refused"
    );

    let mut control_kernel = evidence();
    control_kernel.kernel_generation = "kernel-\n993".to_owned();
    assert!(
        WriteExecution::install_concurrent(limits, lanes, queue, &control_kernel, NOW).is_err(),
        "control characters refused"
    );

    let oversubscribed = NonZeroUsize::new(3).unwrap();
    assert!(
        WriteExecution::install_concurrent(limits, oversubscribed, queue, &evidence(), NOW)
            .is_err(),
        "lanes beyond write sessions refused"
    );
}

// WORK_UNIT_CASE: 993/3
#[test]
fn serial_and_concurrent_profiles_are_mutually_exclusive_per_generation() {
    // Reserved submits route only under the concurrent generation; the
    // legacy lane admits only under serial; generation identities never
    // repeat, so a profile change cannot alias a live generation.
    let concurrent = install_concurrent_ws(2, 2, 8);
    let serial = WriteExecution::install_serial(
        ClientSetLimits::compatibility(),
        NonZeroUsize::new(8).unwrap(),
    )
    .unwrap();
    assert_eq!(concurrent.profile(), ExecutionProfile::Concurrent);
    assert_eq!(serial.profile(), ExecutionProfile::Serial);
    assert!(!concurrent.unreserved_apply_admission().allowed());
    assert!(serial.unreserved_apply_admission().allowed());
    assert!(
        concurrent
            .submit_reserved(request("op-993-03c", "scope-993-03c", 1, 5, 4), NOW)
            .is_ok()
    );
    assert!(
        serial
            .submit_reserved(request("op-993-03s", "scope-993-03s", 1, 5, 4), NOW)
            .is_err()
    );
    assert_ne!(
        concurrent.generation_id(),
        WriteExecution::install_serial(
            ClientSetLimits::compatibility(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap()
        .generation_id(),
        "generation identities are unique per install"
    );
    assert!(
        concurrent.uninstall_readiness().is_err(),
        "live work blocks uninstall"
    );
}

// WORK_UNIT_CASE: 993/4
#[test]
fn unreserved_apply_cannot_bypass_the_concurrent_scheduler() {
    // The admission matrix lives on the execution; the exact refusal the
    // legacy path returns is wired in `apply_prepared_with_authority`
    // (source-bound: this target cannot construct the provider-bound
    // adapter, so it proves the live call site textually).
    let concurrent = install_concurrent_ws(2, 2, 8);
    let serial = WriteExecution::install_serial(
        ClientSetLimits::compatibility(),
        NonZeroUsize::new(8).unwrap(),
    )
    .unwrap();
    assert!(!concurrent.unreserved_apply_admission().allowed());
    assert!(serial.unreserved_apply_admission().allowed());
    let apply = source("src/apply.rs");
    assert!(
        apply.contains("execution.unreserved_apply_admission().allowed()"),
        "legacy path consults the execution gate"
    );
    assert!(
        apply
            .contains("unreserved apply is not admitted under the concurrent execution generation"),
        "bypass refusal carries the exact closed reason"
    );
}

// WORK_UNIT_CASE: 993/5
#[tokio::test]
async fn disjoint_ready_operations_enter_separate_provider_paths_within_capacity() {
    // Both disjoint operations must ENTER their provider paths together:
    // each execute blocks until both arrived (barrier), so a serialized
    // lane would hang and the batch timeout would fail the test.
    let execution = install_concurrent_ws(2, 2, 8);
    let transport = ScriptedTransport::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    for op in ["op-993-05a", "op-993-05b"] {
        let barrier = barrier.clone();
        transport.set_execute(
            op,
            ExecuteScript::Custom(Arc::new(move |_execution, attempt| {
                let barrier = barrier.clone();
                Box::pin(async move {
                    barrier.wait().await;
                    AttemptOutcome::Committed(Box::new(commit_receipt(attempt)))
                })
            })),
        );
    }
    execution
        .submit_reserved(request("op-993-05a", "scope-993-a", 1, 5, 4), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-05b", "scope-993-b", 2, 5, 4), NOW)
        .unwrap();
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert_eq!(outcomes.len(), 2);
    assert_eq!(committed_id(&outcomes[0]), "op-993-05a");
    assert_eq!(committed_id(&outcomes[1]), "op-993-05b");
    assert_eq!(transport.max_live(), 2, "both provider paths overlapped");
    assert_eq!(execution.pending_count(), 0);
}

// WORK_UNIT_CASE: 993/6
#[tokio::test]
async fn overlapping_operations_obey_exact_atomic_precedence() {
    // Submission order is irrelevant: the later-submitted lower order
    // still executes first, and the successor waits exactly one batch.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    execution
        .submit_reserved(request("op-993-06hi", "scope-993-06", 2, 6, 5), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-06lo", "scope-993-06", 1, 5, 4), NOW)
        .unwrap();
    let first = run_batch(&execution, NOW, &transport).await;
    assert_eq!(first.len(), 1, "one lane admits exactly the head");
    assert_eq!(committed_id(&first[0]), "op-993-06lo");
    let second = run_batch(&execution, NOW, &transport).await;
    assert_eq!(second.len(), 1);
    assert_eq!(committed_id(&second[0]), "op-993-06hi");
    assert_eq!(execution.pending_count(), 0);
    let order: Vec<String> = transport
        .calls()
        .iter()
        .filter_map(|call| match call {
            Call::Execute(op) => Some(op.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        order,
        vec!["op-993-06lo".to_owned(), "op-993-06hi".to_owned()]
    );
}

// WORK_UNIT_CASE: 993/7
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_work_holds_no_permit_or_await_held_scheduler_lock() {
    // op-993-07a executes (blocked on release), op-993-07b waits on the
    // same scope, op-993-07c proceeds on a disjoint scope. While -07a is
    // parked inside its provider path, -07c still acquires a permit and
    // completes (no await-held scheduler lock), -07b never executes (no
    // permit), and exactly the executing operation holds a permit.
    let execution = Arc::new(install_concurrent_ws(2, 2, 8));
    let transport = Arc::new(ScriptedTransport::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    for blocker in ["op-993-07a", "op-993-07c"] {
        let entered_tx = entered_tx.clone();
        let release_in_execute = release.clone();
        let blocker = blocker.to_owned();
        transport.set_execute(
            &blocker,
            ExecuteScript::Custom(Arc::new(move |_execution, attempt| {
                let entered_tx = entered_tx.clone();
                let release = release_in_execute.clone();
                Box::pin(async move {
                    entered_tx
                        .send(attempt.operation_id.as_str().to_owned())
                        .unwrap();
                    release.notified().await;
                    AttemptOutcome::Committed(Box::new(commit_receipt(attempt)))
                })
            })),
        );
    }
    execution
        .submit_reserved(request("op-993-07a", "scope-993-a", 1, 5, 4), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-07b", "scope-993-a", 2, 6, 5), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-07c", "scope-993-b", 3, 5, 4), NOW)
        .unwrap();
    let batch_execution = execution.clone();
    let batch_transport = transport.clone();
    let batch = tokio::spawn(async move {
        batch_execution
            .run_ready_batch(NOW, &*batch_transport)
            .await
    });
    let mut entered = vec![
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("first path enters"),
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("second path enters"),
    ];
    entered.sort();
    assert_eq!(
        entered,
        vec!["op-993-07a".to_owned(), "op-993-07c".to_owned()]
    );
    assert_eq!(
        transport.execute_calls("op-993-07b"),
        0,
        "waiting work never executes"
    );
    assert_eq!(
        execution.available_normal_permits(),
        0,
        "exactly the two executing operations hold the two permits; the waiter holds none"
    );
    assert_eq!(execution.in_flight_count(), 2);
    release.notify_waiters();
    let outcomes = tokio::time::timeout(Duration::from_secs(10), batch)
        .await
        .expect("batch joins")
        .expect("spawn succeeds")
        .expect("batch succeeds");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(committed_id(&outcomes[0]), "op-993-07a");
    assert_eq!(committed_id(&outcomes[1]), "op-993-07c");
    assert_eq!(execution.pending_count(), 1, "the waiter stays queued");
    assert_eq!(
        execution.available_normal_permits(),
        2,
        "every permit released"
    );
    let metrics = execution.metrics_snapshot();
    assert_eq!(metrics.committed, 2);
}

// WORK_UNIT_CASE: 993/8
#[tokio::test]
async fn current_generation_fence_expiry_cancel_rechecked_before_send() {
    // Each closed dimension dispositions without submission: the fake
    // records zero execute calls while the scheduler advances exactly.
    for (name, gate) in [
        (
            "stale owner",
            ProviderGate {
                owner_current: false,
                fence_matches: true,
                not_expired: true,
            },
        ),
        (
            "fence mismatch",
            ProviderGate {
                owner_current: true,
                fence_matches: false,
                not_expired: true,
            },
        ),
        (
            "expired",
            ProviderGate {
                owner_current: true,
                fence_matches: true,
                not_expired: false,
            },
        ),
    ] {
        let execution = install_concurrent_ws(1, 1, 8);
        let transport = ScriptedTransport::new();
        let op = format!("op-993-08-{name}").replace(' ', "-");
        transport.set_gate(&op, gate);
        execution
            .submit_reserved(request(&op, "scope-993-08", 1, 5, 4), NOW)
            .unwrap();
        let outcomes = run_batch(&execution, NOW, &transport).await;
        assert_eq!(outcomes.len(), 1, "{name} dispositions exactly once");
        if name == "fence mismatch" {
            assert!(
                matches!(
                    &outcomes[0],
                    OpExecution::Rejected {
                        error: StoreError::FenceMismatch,
                        ..
                    }
                ),
                "{name} rejects deterministically: {:?}",
                outcomes[0]
            );
        } else {
            assert!(
                matches!(&outcomes[0], OpExecution::CancelledBeforeEffect { .. }),
                "{name} sheds without effects: {:?}",
                outcomes[0]
            );
        }
        assert_eq!(transport.execute_calls(&op), 0, "{name} never submits");
        assert_eq!(execution.pending_count(), 0);
    }

    // Caller cancellation is honored at the same recheck with zero
    // transport contact of any kind.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    execution
        .submit_reserved(request("op-993-08-cancel", "scope-993-08", 1, 5, 4), NOW)
        .unwrap();
    assert!(execution.cancel_operation(&OperationId::new("op-993-08-cancel").unwrap()));
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert!(matches!(
        outcomes[0],
        OpExecution::CancelledBeforeEffect { .. }
    ));
    assert!(
        transport.calls().is_empty(),
        "no gate read, no attempt, no reconcile"
    );
}

// WORK_UNIT_CASE: 993/9
#[tokio::test]
async fn exact_immutable_transition_reaches_the_attempt_with_all_guards() {
    // The fake captures the executable attempt: identity, fences, heads,
    // order, and expiry must equal the sealed submission byte-for-byte in
    // every load-bearing field.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    let captured: Arc<Mutex<Option<ExecutableAttempt>>> = Arc::new(Mutex::new(None));
    let captured_in_execute = captured.clone();
    transport.set_execute(
        "op-993-09",
        ExecuteScript::Custom(Arc::new(move |_execution, attempt| {
            let captured = captured_in_execute.clone();
            Box::pin(async move {
                *captured.lock().unwrap() = Some(attempt.clone());
                AttemptOutcome::Committed(Box::new(commit_receipt(attempt)))
            })
        })),
    );
    let submitted = request("op-993-09", "scope-993-09", 7, 9, 8);
    execution.submit_reserved(submitted.clone(), NOW).unwrap();
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert!(matches!(outcomes[0], OpExecution::Committed { .. }));
    let attempt = captured.lock().unwrap().clone().expect("attempt captured");
    assert_eq!(
        attempt.operation_id,
        submitted.transition.identity.operation_id
    );
    assert_eq!(
        attempt.context.state_fence, submitted.transition.state_fence,
        "context and transition share the admitted fence"
    );
    assert_eq!(
        attempt.expected_revision_heads,
        submitted.expected_revision_heads
    );
    assert_eq!(
        attempt.expected_ordering_heads,
        submitted.expected_ordering_heads
    );
    assert_eq!(
        attempt.reservation_order,
        submitted.admission.reservation_order
    );
    assert_eq!(attempt.expires_at_ms, submitted.admission.expires_at_ms);
    assert_eq!(
        attempt.transition.identity.canonical_request_hash,
        submitted.transition.identity.canonical_request_hash,
        "no dropped optimistic guard: the sealed digest travels intact"
    );

    // The production path sends through the pooled write lane with no
    // duplicated transaction assembly.
    let apply = source("src/apply.rs");
    assert!(
        apply.contains("TxLane::PooledWrite"),
        "reserved attempts use the pooled lane"
    );
    assert!(
        apply.contains("pub(crate) async fn apply_reserved_attempt"),
        "single attempt entry"
    );
    let writer = source("src/apply/atomic_write.rs");
    assert!(
        writer.contains("TxLane::PooledWrite => db.query_write"),
        "one pooled send site, no duplicated SQL"
    );
}

// WORK_UNIT_CASE: 993/10
#[tokio::test]
async fn pre_submit_cancellation_and_capacity_failure_cause_no_provider_call() {
    // Cancellation before the batch dispositions with zero transport
    // contact; queue-full sheds the excess submit with exact accounting.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    execution
        .submit_reserved(request("op-993-10a", "scope-993-10a", 1, 5, 4), NOW)
        .unwrap();
    assert!(execution.cancel_operation(&OperationId::new("op-993-10a").unwrap()));
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert!(matches!(
        outcomes[0],
        OpExecution::CancelledBeforeEffect { .. }
    ));
    assert!(
        transport.calls().is_empty(),
        "cancelled work touches nothing"
    );
    assert_eq!(execution.metrics_snapshot().cancelled_before_effect, 1);

    let bounded = install_concurrent_ws(1, 1, 1);
    let bounded_transport = ScriptedTransport::new();
    bounded
        .submit_reserved(request("op-993-10b", "scope-993-10b", 1, 5, 4), NOW)
        .unwrap();
    let shed = bounded
        .submit_reserved(request("op-993-10c", "scope-993-10c", 2, 5, 4), NOW)
        .expect_err("bounded queue sheds");
    assert_eq!(shed, AdapterError::Store(StoreError::Unavailable));
    assert_eq!(bounded.metrics_snapshot().queue_full_shed, 1);
    let outcomes = run_batch(&bounded, NOW, &bounded_transport).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(committed_id(&outcomes[0]), "op-993-10b");
    assert_eq!(
        bounded_transport.execute_calls("op-993-10c"),
        0,
        "shed work never executes"
    );
}

// WORK_UNIT_CASE: 993/11
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_submit_cancellation_and_dropped_caller_retain_reconciliation_ownership() {
    // A mid-flight cancellation with a lost response keeps operation and
    // reservation identity in explicit reconciliation: the reconcile call
    // carries the exact identity and the commit surfaces as reconciled.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    transport.set_execute(
        "op-993-11a",
        ExecuteScript::Custom(Arc::new(|execution, attempt| {
            execution.cancel_operation(&attempt.operation_id);
            Box::pin(async { AttemptOutcome::Unknown { retry_after_ms: 0 } })
        })),
    );
    let awaited = request("op-993-11a", "scope-993-11a", 1, 5, 4);
    let reconciled_receipt = receipt_for_request(&awaited);
    transport.set_reconcile(
        "op-993-11a",
        ReconcileOutcome::Committed(Box::new(reconciled_receipt)),
    );
    execution.submit_reserved(awaited, NOW).unwrap();
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert_eq!(outcomes.len(), 1);
    assert!(
        matches!(
            &outcomes[0],
            OpExecution::Committed {
                reconciled: true,
                ..
            }
        ),
        "lost response reconciles to its commit: {:?}",
        outcomes[0]
    );
    assert_eq!(
        transport
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Reconcile(op) if op == "op-993-11a"))
            .count(),
        1,
        "exactly one owned reconciliation"
    );
    assert_eq!(execution.metrics_snapshot().committed_via_reconcile, 1);

    // A dropped caller abandons neither identity nor evidence: aborting
    // the batch mid-attempt keeps the scheduler entry (in flight,
    // uncompleted) while the RAII permit releases. Permit release never
    // implies semantic completion.
    let dropped = Arc::new(install_concurrent_ws(1, 1, 8));
    let dropped_transport = Arc::new(ScriptedTransport::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let release_in_execute = release.clone();
    dropped_transport.set_execute(
        "op-993-11b",
        ExecuteScript::Custom(Arc::new(move |_execution, _attempt| {
            let entered_tx = entered_tx.clone();
            let release = release_in_execute.clone();
            Box::pin(async move {
                entered_tx.send(()).unwrap();
                release.notified().await;
                AttemptOutcome::Committed(Box::new(commit_receipt(_attempt)))
            })
        })),
    );
    dropped
        .submit_reserved(request("op-993-11b", "scope-993-11b", 1, 5, 4), NOW)
        .unwrap();
    let batch_dropped = dropped.clone();
    let batch_transport = dropped_transport.clone();
    let batch =
        tokio::spawn(async move { batch_dropped.run_ready_batch(NOW, &*batch_transport).await });
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("attempt starts");
    batch.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(dropped.pending_count(), 1, "operation identity retained");
    assert_eq!(dropped.in_flight_count(), 1, "in-flight evidence retained");
    assert_eq!(
        dropped.available_normal_permits(),
        1,
        "permit released without implying completion"
    );
    release.notify_one();
}
// WORK_UNIT_CASE: 993/12
#[tokio::test]
async fn uncertain_response_cannot_release_successors_or_trigger_blind_retry() {
    // An unknown outcome pauses only its own scopes, and later batches
    // re-reconcile without re-executing: the execute count stays one
    // across both runs while the successor never runs.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    transport.set_execute_all(ExecuteScript::Unknown);
    transport.set_reconcile_all(ReconcileOutcome::StillUnknown);
    execution
        .submit_reserved(request("op-993-12a", "scope-993-12", 1, 5, 4), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-12b", "scope-993-12", 2, 6, 5), NOW)
        .unwrap();
    let first = run_batch(&execution, NOW, &transport).await;
    assert_eq!(first.len(), 1);
    assert!(matches!(first[0], OpExecution::UnknownRetained { .. }));
    let second = run_batch(&execution, NOW, &transport).await;
    assert_eq!(
        second.len(),
        1,
        "re-reconciliation reports the retained uncertainty"
    );
    assert!(matches!(second[0], OpExecution::UnknownRetained { .. }));
    assert_eq!(transport.execute_calls("op-993-12a"), 1, "no blind retry");
    assert_eq!(
        transport.execute_calls("op-993-12b"),
        0,
        "successor never released"
    );
    assert_eq!(execution.pending_count(), 2);
    assert_eq!(execution.uncertain_operations().len(), 1);
}

// WORK_UNIT_CASE: 993/13
#[tokio::test]
async fn exact_canonical_reconciliation_resumes_only_permitted_scopes() {
    // op-993-13c on a disjoint scope commits in the first batch while
    // op-993-13a goes unknown; resolving -13a by receipt lets the paused
    // same-scope successor -13b run, and only then.
    let execution = install_concurrent_ws(2, 2, 8);
    let transport = ScriptedTransport::new();
    transport.set_execute("op-993-13a", ExecuteScript::Unknown);
    execution
        .submit_reserved(request("op-993-13a", "scope-993-13a", 1, 5, 4), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-13b", "scope-993-13a", 2, 6, 5), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-13c", "scope-993-13c", 3, 5, 4), NOW)
        .unwrap();
    let first = run_batch(&execution, NOW, &transport).await;
    assert_eq!(first.len(), 2, "disjoint commit plus retained uncertainty");
    assert_eq!(committed_id(&first[0]), "op-993-13c");
    assert!(matches!(first[1], OpExecution::UnknownRetained { .. }));
    assert_eq!(transport.execute_calls("op-993-13b"), 0);

    let awaited = request("op-993-13a", "scope-993-13a", 1, 5, 4);
    transport.set_reconcile(
        "op-993-13a",
        ReconcileOutcome::Committed(Box::new(receipt_for_request(&awaited))),
    );
    let second = run_batch(&execution, NOW, &transport).await;
    assert_eq!(second.len(), 1);
    assert!(
        matches!(
            &second[0],
            OpExecution::Committed {
                reconciled: true,
                ..
            }
        ),
        "reconciliation proves the paused commit: {:?}",
        second[0]
    );
    assert_eq!(committed_id(&second[0]), "op-993-13a");
    let third = run_batch(&execution, NOW, &transport).await;
    assert_eq!(third.len(), 1);
    assert_eq!(committed_id(&third[0]), "op-993-13b");
    assert_eq!(execution.pending_count(), 0);
}

// WORK_UNIT_CASE: 993/14
#[tokio::test]
async fn delayed_unknown_scope_does_not_block_independent_ready_work() {
    // No application-global gate: the disjoint operation commits in the
    // same batch that retains the unknown one.
    let execution = install_concurrent_ws(2, 2, 8);
    let transport = ScriptedTransport::new();
    transport.set_execute("op-993-14a", ExecuteScript::Unknown);
    execution
        .submit_reserved(request("op-993-14a", "scope-993-14a", 1, 5, 4), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-14b", "scope-993-14b", 2, 5, 4), NOW)
        .unwrap();
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert_eq!(outcomes.len(), 2);
    let mut committed = false;
    let mut retained = false;
    for outcome in &outcomes {
        match outcome {
            OpExecution::Committed { operation_id, .. } => {
                assert_eq!(operation_id.as_str(), "op-993-14b");
                committed = true;
            }
            OpExecution::UnknownRetained { operation_id } => {
                assert_eq!(operation_id.as_str(), "op-993-14a");
                retained = true;
            }
            other => assert_eq!(format!("{other:?}"), "committed-or-retained"),
        }
    }
    assert!(
        committed && retained,
        "independent work proceeds under uncertainty"
    );
    assert_eq!(execution.uncertain_operations().len(), 1);
}

// WORK_UNIT_CASE: 993/15
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_normal_saturation_preserves_the_declared_protected_path() {
    // One normal session held by a parked attempt saturates the normal
    // lane; the separately admitted protected permit still acquires and
    // releases without touching normal capacity.
    let execution = Arc::new(install_concurrent_ws(1, 1, 8));
    let transport = Arc::new(ScriptedTransport::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let release_in_execute = release.clone();
    transport.set_execute(
        "op-993-15",
        ExecuteScript::Custom(Arc::new(move |_execution, attempt| {
            let entered_tx = entered_tx.clone();
            let release = release_in_execute.clone();
            Box::pin(async move {
                entered_tx.send(()).unwrap();
                release.notified().await;
                AttemptOutcome::Committed(Box::new(commit_receipt(attempt)))
            })
        })),
    );
    execution
        .submit_reserved(request("op-993-15", "scope-993-15", 1, 5, 4), NOW)
        .unwrap();
    let batch_execution = execution.clone();
    let batch_transport = transport.clone();
    let batch = tokio::spawn(async move {
        batch_execution
            .run_ready_batch(NOW, &*batch_transport)
            .await
    });
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("normal lane saturates");
    assert_eq!(execution.available_normal_permits(), 0);
    let protected = execution
        .try_acquire_protected_permit()
        .expect("protected path survives saturation");
    assert_eq!(execution.available_protected_permits(), 0);
    drop(protected);
    assert_eq!(
        execution.available_protected_permits(),
        1,
        "protected permit releases cleanly"
    );
    assert_eq!(
        execution.available_normal_permits(),
        0,
        "normal lane still held"
    );
    release.notify_one();
    let outcomes = tokio::time::timeout(Duration::from_secs(10), batch)
        .await
        .expect("batch joins")
        .expect("spawn succeeds")
        .expect("batch succeeds");
    assert_eq!(committed_id(&outcomes[0]), "op-993-15");
}

// WORK_UNIT_CASE: 993/16
#[tokio::test]
async fn no_oversubscribed_sessions_tasks_queue_history_or_forgotten_operation() {
    // Four disjoint operations over two lanes and two sessions: at most
    // two provider paths ever overlap, every submitted operation accounts
    // exactly once, and the queue bound plus identity rules hold.
    let execution = install_concurrent_ws(2, 2, 8);
    let transport = ScriptedTransport::new();
    for (index, scope) in [
        "scope-993-16a",
        "scope-993-16b",
        "scope-993-16c",
        "scope-993-16d",
    ]
    .iter()
    .enumerate()
    {
        let order = u64::try_from(index + 1).unwrap();
        execution
            .submit_reserved(
                request(&format!("op-993-16-{index}"), scope, order, 5, 4),
                NOW,
            )
            .unwrap();
    }
    let mut committed = 0u64;
    for _ in 0..4 {
        let outcomes = run_batch(&execution, NOW, &transport).await;
        if outcomes.is_empty() {
            break;
        }
        committed += u64::try_from(outcomes.len()).unwrap();
    }
    assert_eq!(
        committed, 4,
        "every admitted operation accounts exactly once"
    );
    assert_eq!(
        execution.pending_count(),
        0,
        "no forgotten unresolved operation"
    );
    assert!(transport.max_live() <= 2, "never beyond the session bound");
    let metrics = execution.metrics_snapshot();
    assert_eq!(metrics.submitted, 4);
    assert_eq!(metrics.committed, 4);

    // Identity rules: same digest resubmits idempotently, changed content
    // under the same identity conflicts.
    let bounded = install_concurrent_ws(1, 1, 8);
    bounded
        .submit_reserved(request("op-993-16dup", "scope-993-16dup", 1, 5, 4), NOW)
        .unwrap();
    let duplicate = bounded
        .submit_reserved(request("op-993-16dup", "scope-993-16dup", 1, 5, 4), NOW)
        .expect("idempotent resubmit");
    assert_eq!(duplicate, SubmitDisposition::AlreadyQueued);
    assert_eq!(bounded.metrics_snapshot().duplicates_suppressed, 1);
    let conflicted = bounded
        .submit_reserved(
            request_scopes("op-993-16dup", &[("scope-993-16other", 5, 4)], 1),
            NOW,
        )
        .expect_err("changed content conflicts");
    assert_eq!(
        conflicted,
        AdapterError::Store(StoreError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 993/17
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_closes_admission_and_drains_every_possible_effect() {
    // op-993-17a commits first; -17b/-17c queue behind the single lane.
    // The drain dispositions both queued operations without provider
    // effects, refuses a concurrent submit, then runs the exclusive
    // operation exactly once before reopening.
    let execution = Arc::new(install_concurrent_ws(1, 1, 8));
    let transport = Arc::new(ScriptedTransport::new());
    execution
        .submit_reserved(request("op-993-17a", "scope-993-17", 1, 5, 4), NOW)
        .unwrap();
    let first = run_batch(&execution, NOW, &transport).await;
    assert_eq!(committed_id(&first[0]), "op-993-17a");
    execution
        .submit_reserved(request("op-993-17b", "scope-993-17", 2, 6, 5), NOW)
        .unwrap();
    execution
        .submit_reserved(request("op-993-17c", "scope-993-17", 3, 7, 6), NOW)
        .unwrap();

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_in_exclusive = events.clone();
    let gate = Arc::new(tokio::sync::Notify::new());
    let gate_in_exclusive = gate.clone();
    let drain_execution = execution.clone();
    let drain_transport = transport.clone();
    let drain = tokio::spawn(async move {
        drain_execution
            .drain_for_migration(ExclusiveOpKind::Migration, NOW, &*drain_transport, || {
                let events = events_in_exclusive.clone();
                let gate = gate_in_exclusive.clone();
                async move {
                    gate.notified().await;
                    events.lock().unwrap().push("exclusive".to_owned());
                    Ok::<u32, AdapterError>(42)
                }
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while !execution.is_draining() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("drain closes admission");
    let refused = execution
        .submit_reserved(request("op-993-17d", "scope-993-17d", 4, 5, 4), NOW)
        .expect_err("admission closed during drain");
    assert_eq!(refused, AdapterError::Store(StoreError::Unavailable));
    gate.notify_one();
    let (report, value) = tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .expect("drain joins")
        .expect("spawn succeeds")
        .expect("drain succeeds");
    assert_eq!(value, 42);
    assert_eq!(report.kind, ExclusiveOpKind::Migration);
    assert_eq!(
        report.cancelled_queued, 2,
        "queued work dispositioned without effects"
    );
    assert_eq!(transport.execute_calls("op-993-17b"), 0);
    assert_eq!(transport.execute_calls("op-993-17c"), 0);
    assert_eq!(events.lock().unwrap().as_slice(), ["exclusive"]);
    assert!(!execution.is_draining(), "authorized completion reopens");
    assert_eq!(execution.pending_count(), 0);
    execution
        .submit_reserved(request("op-993-17e", "scope-993-17e", 5, 5, 4), NOW)
        .expect("reopened generation accepts");
    let metrics = execution.metrics_snapshot();
    assert_eq!(metrics.drains_completed, 1);
    assert_eq!(metrics.cancelled_before_effect, 2);
}

// WORK_UNIT_CASE: 993/18
#[tokio::test]
async fn incomplete_unknown_drain_cannot_grant_exclusivity() {
    // An unresolvable uncertainty fails the drain fast (no quiescence
    // wait: uncertain work reconciles, never completes alone), the
    // exclusive operation never runs, and the execution stays fenced with
    // its uncertainty intact.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    transport.set_execute_all(ExecuteScript::Unknown);
    execution
        .submit_reserved(request("op-993-18", "scope-993-18", 1, 5, 4), NOW)
        .unwrap();
    let first = run_batch(&execution, NOW, &transport).await;
    assert!(matches!(first[0], OpExecution::UnknownRetained { .. }));
    let exclusive_ran = Arc::new(Mutex::new(false));
    let exclusive_ran_in_closure = exclusive_ran.clone();
    let drained = tokio::time::timeout(
        Duration::from_secs(10),
        execution.drain_for_migration(ExclusiveOpKind::Migration, NOW, &transport, || async {
            *exclusive_ran_in_closure.lock().unwrap() = true;
            Ok::<(), AdapterError>(())
        }),
    )
    .await
    .expect("drain returns without hanging");
    assert_eq!(drained, Err(AdapterError::Store(StoreError::Unavailable)));
    assert!(!*exclusive_ran.lock().unwrap(), "exclusivity never granted");
    assert!(execution.is_fenced(), "unknown outcome stays fenced");
    assert_eq!(execution.uncertain_operations().len(), 1);
    assert!(
        execution
            .submit_reserved(request("op-993-18b", "scope-993-18b", 2, 5, 4), NOW)
            .is_err(),
        "fenced execution refuses admission"
    );
}

// WORK_UNIT_CASE: 993/19
#[tokio::test]
async fn migration_failure_stays_fenced_until_accepted_generation_reopens() {
    // A failed exclusive operation preserves its exact error and fences
    // the execution; reopening demands accepted evidence, and only that
    // reopens.
    let execution = install_concurrent_ws(1, 1, 8);
    let transport = ScriptedTransport::new();
    let failed = tokio::time::timeout(
        Duration::from_secs(10),
        execution.drain_for_migration(
            ExclusiveOpKind::SchemaReplacement,
            NOW,
            &transport,
            || async {
                Err::<(), AdapterError>(AdapterError::Config("migration-993-boom".to_owned()))
            },
        ),
    )
    .await
    .expect("drain returns");
    assert_eq!(
        failed,
        Err(AdapterError::Config("migration-993-boom".to_owned())),
        "the exclusive error is preserved, not replaced"
    );
    assert!(execution.is_fenced());
    assert!(
        execution.uninstall_readiness().is_err(),
        "fenced generation cannot move profile"
    );
    assert!(
        execution
            .submit_reserved(request("op-993-19", "scope-993-19", 1, 5, 4), NOW)
            .is_err(),
        "fenced execution refuses admission"
    );

    let mut bad_evidence = evidence();
    bad_evidence.capability = "store.write";
    assert!(execution.reopen_generation(&bad_evidence).is_err());
    execution
        .reopen_generation(&evidence())
        .expect("accepted generation reopens");
    assert!(!execution.is_fenced(), "accepted generation reopens");
    assert!(!execution.is_draining());
    execution
        .submit_reserved(request("op-993-19b", "scope-993-19b", 1, 5, 4), NOW)
        .expect("reopened generation accepts");
    let outcomes = run_batch(&execution, NOW, &transport).await;
    assert_eq!(committed_id(&outcomes[0]), "op-993-19b");
}

// WORK_UNIT_CASE: 993/20
#[tokio::test]
async fn restart_from_complete_versus_incomplete_durable_recovery_denominator() {
    // Only the supplied denominator shapes the reconstruction: terminal
    // outcomes need no entry, unknown or missing outcomes schedule as
    // uncertainties that block readiness until each resolves.
    let limits = ClientSetLimits::new(1, 2, 1).unwrap();
    let lanes = NonZeroUsize::new(2).unwrap();
    let queue = NonZeroUsize::new(8).unwrap();
    let projection = |op: &str, order: u64, scope: &str, sequence: u64| ReservationProjection {
        operation_id: OperationId::new(op).unwrap(),
        reservation_order: order,
        scopes: vec![ReservedScopeProjection {
            scope: OrderingScopeId::new(scope).unwrap(),
            reserved_sequence: sequence,
        }],
    };
    let complete = DurableRecoverySet {
        reservations: vec![projection("op-993-20a", 1, "scope-993-20a", 5)],
        outcomes: vec![("op-993-20a".to_owned(), DurableOpOutcome::Committed)]
            .into_iter()
            .map(|(id, outcome)| (OperationId::new(id).unwrap(), outcome))
            .collect(),
    };
    let recovered =
        WriteExecution::recover_concurrent(limits, lanes, queue, &evidence(), &complete, NOW)
            .expect("complete denominator recovers");
    assert!(
        !recovered.recovery_blocked(),
        "terminal denominator needs no block"
    );
    assert!(recovered.uncertain_operations().is_empty());

    let incomplete = DurableRecoverySet {
        reservations: vec![
            projection("op-993-20b", 1, "scope-993-20b", 5),
            projection("op-993-20c", 2, "scope-993-20c", 5),
            projection("op-993-20d", 3, "scope-993-20d", 5),
        ],
        outcomes: vec![
            (
                OperationId::new("op-993-20b").unwrap(),
                DurableOpOutcome::Committed,
            ),
            (
                OperationId::new("op-993-20c").unwrap(),
                DurableOpOutcome::Unknown,
            ),
        ],
    };
    let blocked =
        WriteExecution::recover_concurrent(limits, lanes, queue, &evidence(), &incomplete, NOW)
            .expect("incomplete denominator recovers");
    assert!(
        blocked.recovery_blocked(),
        "unknown recovery blocks readiness"
    );
    let uncertain: Vec<String> = blocked
        .uncertain_operations()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    assert_eq!(
        uncertain,
        vec!["op-993-20c".to_owned(), "op-993-20d".to_owned()]
    );
    assert!(
        blocked
            .submit_reserved(request("op-993-20e", "scope-993-20e", 4, 5, 4), NOW)
            .is_err(),
        "blocked execution refuses normal work"
    );
    let blocked_transport = ScriptedTransport::new();
    let blocked_drain = blocked
        .drain_for_migration(
            ExclusiveOpKind::Migration,
            NOW,
            &blocked_transport,
            || async { Ok::<(), AdapterError>(()) },
        )
        .await;
    assert_eq!(
        blocked_drain,
        Err(AdapterError::Store(StoreError::Unavailable)),
        "blocked execution refuses the drain without fencing"
    );
    assert!(!blocked.is_fenced() && !blocked.is_draining());
    assert!(
        blocked
            .resolve_recovered(
                &OperationId::new("op-993-20x").unwrap(),
                DurableOpOutcome::Committed,
                NOW
            )
            .is_err(),
        "local memory invents nothing: unknown identities stay rejected"
    );
    blocked
        .resolve_recovered(
            &OperationId::new("op-993-20c").unwrap(),
            DurableOpOutcome::Committed,
            NOW,
        )
        .unwrap();
    assert!(
        blocked.recovery_blocked(),
        "one residual unknown still blocks"
    );
    blocked
        .resolve_recovered(
            &OperationId::new("op-993-20d").unwrap(),
            DurableOpOutcome::DeadLetter,
            NOW,
        )
        .unwrap();
    assert!(!blocked.recovery_blocked(), "resolved denominator reopens");
    assert!(blocked.uncertain_operations().is_empty());
}

// WORK_UNIT_CASE: 993/21
#[tokio::test]
async fn deterministic_fixture_preserves_exact_result_ownership_and_metrics() {
    // The frozen scenario descriptor drives the real orchestration; every
    // frozen metric must match exactly, receipts must validate, and no
    // redacted identity may leak into diagnostics.
    let fixture: Value =
        serde_json::from_str(include_str!("data/ordering_scope_execution.json")).unwrap();
    assert_eq!(fixture["contract_version"], 1);
    let submit_at = NOW + fixture["submit_at_ms_offset"].as_u64().unwrap();
    let run_at = NOW + fixture["run_at_ms_offset"].as_u64().unwrap();
    let execution = install_concurrent_ws(2, 2, 8);
    let transport = ScriptedTransport::new();
    for operation in fixture["operations"].as_array().unwrap() {
        let op = operation["op"].as_str().unwrap();
        match operation["outcome"].as_str().unwrap() {
            "commit" => transport.set_execute(op, ExecuteScript::Commit),
            "reject" => {
                transport.set_execute(op, ExecuteScript::Reject(StoreError::RevisionConflict))
            }
            "cancel" => transport.set_execute(op, ExecuteScript::Cancel),
            "deadletter" => transport.set_execute(op, ExecuteScript::DeadLetter),
            other => assert_eq!(other, "commit-reject-cancel-or-deadletter"),
        }
        execution
            .submit_reserved(
                request(
                    op,
                    operation["scope"].as_str().unwrap(),
                    operation["order"].as_u64().unwrap(),
                    operation["reserved_sequence"].as_u64().unwrap(),
                    operation["expected_sequence"].as_u64().unwrap(),
                ),
                submit_at,
            )
            .expect("fixture submits");
    }
    for _ in 0..4 {
        if run_batch(&execution, run_at, &transport).await.is_empty() {
            break;
        }
    }
    assert_eq!(execution.pending_count(), 0);
    let metrics = execution.metrics_snapshot();
    let expected = &fixture["expected_metrics"];
    for (field, value) in [
        ("submitted", metrics.submitted),
        ("duplicates_suppressed", metrics.duplicates_suppressed),
        ("committed", metrics.committed),
        ("committed_via_reconcile", metrics.committed_via_reconcile),
        ("rejected", metrics.rejected),
        ("dead_lettered", metrics.dead_lettered),
        ("cancelled_before_effect", metrics.cancelled_before_effect),
        ("unknown_observed", metrics.unknown_observed),
        ("reconciled_absent", metrics.reconciled_absent),
        ("still_unknown_retained", metrics.still_unknown_retained),
        ("queue_full_shed", metrics.queue_full_shed),
        ("submit_refused_not_ready", metrics.submit_refused_not_ready),
        ("oldest_ready_wait_max_ms", metrics.oldest_ready_wait_max_ms),
        ("permit_waited_events", metrics.permit_waited_events),
    ] {
        assert_eq!(
            value,
            expected[field].as_u64().unwrap(),
            "metric {field} matches the frozen fixture"
        );
    }
    let rendered_metrics = format!("{metrics:?}");
    let rendered_execution = format!("{execution:?}");
    for leaked in [
        "op-993-m1",
        "op-993-m2",
        "op-993-m3",
        "op-993-m4",
        "op-993-m5",
        "scope-993-a",
        "reservation-",
    ] {
        assert!(
            !rendered_metrics.contains(leaked),
            "metrics redact {leaked}"
        );
        assert!(
            !rendered_execution.contains(leaked),
            "diagnostics redact {leaked}"
        );
    }
}

// WORK_UNIT_CASE: 993/22
#[test]
fn source_api_and_actual_path_guard_forbids_bypass_duplication_and_hidden_gates() {
    // Structural proof over current source: the reserved path owns
    // bounded permits from the #987 session bound, never the historical
    // global mutex, never a semaphore-of-one, never duplicated
    // transaction SQL or schema, and no new durable authority; the
    // adapter surface delegates through the accepted seams.
    let runtime = source("src/write_execution.rs");
    assert!(
        runtime.contains("Semaphore::new(usize::from(limits.write_sessions()))"),
        "permits derive from the bounded session set"
    );
    assert!(
        !runtime.contains("write_lock"),
        "normal path never touches the global mutex"
    );
    assert!(
        !runtime.contains("Mutex<()>"),
        "no unit gate stands in for the old lock"
    );
    assert!(
        !runtime.contains("Semaphore::new(1)"),
        "no hidden semaphore-of-one"
    );
    assert!(!runtime.contains("BEGIN"), "no duplicated transaction SQL");
    assert!(!runtime.contains("DEFINE TABLE"), "no schema authority");
    assert!(!runtime.contains("CREATE TABLE"), "no schema authority");
    assert!(
        runtime.contains("request.validate()"),
        "the admitted receiving boundary gates submits"
    );

    let lib = source("src/lib.rs");
    assert!(
        lib.contains("async fn apply_reserved_write"),
        "client method delegates"
    );
    assert!(
        lib.contains("CAPABILITY_RESERVED_WRITE"),
        "capability evidence binds the accepted declaration"
    );

    let apply = source("src/apply.rs");
    assert!(
        apply.contains("TxLane::PooledWrite"),
        "reserved attempts ride the pooled lane"
    );
    assert!(
        apply.contains("drain_for_migration"),
        "migration and genesis drain exclusively"
    );
    assert!(
        apply.contains("execution.unreserved_apply_admission().allowed()"),
        "unreserved path cannot bypass"
    );

    let config = source("src/config.rs");
    assert!(
        config.contains("pub fn validate_execution_profile"),
        "additive profile validation only"
    );
}
