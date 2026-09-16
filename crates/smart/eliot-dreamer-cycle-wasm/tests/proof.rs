//! Issue #644 proof matrix: exactly cases 1..27, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, ErrorCode, OperationId,
    PolicyRevision, ProductId, ReceiptId, RequestId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision, TransactionSequence, canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, DreamJobInput, JobClass, Requester, RequesterOrigin, ScreenBinding,
    ScreenState,
};
use eliot_dreamer_cycle::{
    CYCLE_SCHEMA_VERSION, CycleError, CyclePhase, CyclePolicy, DreamerCycleState, ExpectedArtifact,
    ObservedOutcome, OutcomeDisposition, PendingRequest, PhasePolicyRule, RequestKind,
    StepDisposition, contract::MAX_RECORDS, step_dreamer_cycle, step_dreamer_cycle_at,
};
use eliot_dreamer_cycle_wasm::{
    CallLedger, GUEST_ABI_VERSION, GUEST_TARGET, GuestError, GuestRequest, HANDLER_SUBTYPE,
    TOOLCHAIN_CHANNEL, WORLD_NAME, WORLD_PACKAGE, check_wasm_imports, decode_request,
    decode_response, descriptor, descriptor_digest, disposition_as_str, encode_request,
    encode_response, handle_request_typed, handle_with_ledger, is_forbidden_import,
    list_wasm_imports, parse_disposition, qualified_export_name, request_digest, run,
    wit_export_name,
};
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, TaskBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};

use std::num::NonZeroU64;

const PAYLOAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const TEST_LINEAGE_B: &str = "660e8400-e29b-41d4-a716-446655440001";

const INERT_AWAITING: &str = "awaiting an externally supplied owner observation";
const INERT_RECONCILE: &str = "reconcile the same operation; do not issue a replacement retry";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn fence() -> StateFence {
    StateFence {
        authority_epoch: test_epoch(1),
        resource_generation: ResourceGeneration::genesis(),
        task_revision: Some(TaskRevision::genesis()),
        policy_revision: Some(PolicyRevision::genesis()),
        integration_revision: None,
    }
}

fn job(fence: &StateFence) -> DreamJobInput {
    job_with_deadline(fence, None)
}

fn job_with_deadline(fence: &StateFence, deadline_ms: Option<u64>) -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "tester".to_owned(),
            session: None,
        },
        operation_id: "operation-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence.clone(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1_000_000),
            output_bytes: Some(1_000_000),
            source_width: Some(512),
            reference_width: Some(512),
            model_calls: Some(10),
            attempts: Some(10),
            candidates: Some(10),
            wall_ms: Some(600_000),
            work_fan_out: Some(10),
            report_bytes: Some(1_000_000),
            max_stu: Some(1_000),
        },
        deadline_ms,
        frozen_manifest_digest: PAYLOAD.to_owned(),
    }
}

fn policy(fence: &StateFence, operation_kind: &str) -> CyclePolicy {
    policy_for_phase(fence, CyclePhase::BundleValidated, operation_kind)
}

fn policy_for_phase(fence: &StateFence, phase: CyclePhase, operation_kind: &str) -> CyclePolicy {
    let mut policy = CyclePolicy {
        schema_version: 1,
        policy_id: ArtifactId::new("policy-1").unwrap(),
        policy_revision: PolicyRevision::genesis(),
        state_fence: fence.clone(),
        max_pending: 8,
        max_outcomes: 32,
        max_requests: 8,
        max_transitions: 32,
        max_bytes: 1_000_000,
        deadline_ms: None,
        cancellation_requested: false,
        canonical_digest: String::new(),
        phase_rules: vec![PhasePolicyRule {
            phase,
            owner: "owner-1".to_owned(),
            product_id: ProductId::new("product-1").unwrap(),
            source_id: SourceId::new("source-1").unwrap(),
            operation_kind: operation_kind.to_owned(),
            effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        }],
    };
    policy.seal().unwrap();
    policy
}

fn pending(policy: &CyclePolicy, job: &DreamJobInput) -> PendingRequest {
    PendingRequest {
        request_id: RequestId::new("request-1").unwrap(),
        operation_id: OperationId::new("operation-1").unwrap(),
        idempotency_key: "idem-1".to_owned(),
        product_id: ProductId::new("product-1").unwrap(),
        source_id: SourceId::new("source-1").unwrap(),
        operation_kind: policy.phase_rules[0].operation_kind.clone(),
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::Observation,
        owner: "owner-1".to_owned(),
        kind: RequestKind::BundleValidation,
        phase: CyclePhase::BundleValidated,
        attempt_id: AgentAttemptId::new("attempt-1").unwrap(),
        payload_digest: PAYLOAD.to_owned(),
        bundle_digest: PAYLOAD.to_owned(),
        job_digest: sha256_hex(&canonical_json_bytes(job).unwrap()),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: policy.state_fence.clone(),
        predecessor_receipt_id: None,
        handler_request: None,
        expected_artifacts: vec![ExpectedArtifact {
            artifact_id: ArtifactId::new("payload-1").unwrap(),
            sha256: PAYLOAD.to_owned(),
            role: ReceiptKind::Artifact,
            source_revision: None,
        }],
    }
}

fn state(policy: &CyclePolicy, job: &DreamJobInput, request: PendingRequest) -> DreamerCycleState {
    let mut state = DreamerCycleState {
        schema_version: 1,
        cycle_id: ArtifactId::new("cycle-1").unwrap(),
        job: job.clone(),
        bundle_digest: PAYLOAD.to_owned(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        policy_digest: policy.canonical_digest.clone(),
        phase: CyclePhase::Validated,
        controller_revision: 0,
        predecessor_digest: None,
        pending: vec![request],
        proposed_requests: Vec::new(),
        outcomes: Vec::new(),
        frontier: Vec::new(),
        budget_usage: BudgetUsage::default(),
        cancellation_requested: false,
        canonical_digest: String::new(),
    };
    state.seal().unwrap();
    state
}

fn receipt(
    request: &PendingRequest,
    disposition: ReceiptDisposition,
    parent: Option<eliot_contracts::ReceiptId>,
) -> ReceiptEnvelope {
    receipt_with_artifacts(request, disposition, parent, &[])
}

fn receipt_with_artifacts(
    request: &PendingRequest,
    disposition: ReceiptDisposition,
    parent: Option<eliot_contracts::ReceiptId>,
    extras: &[(&str, &str)],
) -> ReceiptEnvelope {
    let fence = request.state_fence.clone();
    let request_id = request.request_id.clone();
    let operation_id = request.operation_id.clone();
    let product_id = request.product_id.clone();
    let source_id = request.source_id.clone();
    let task_id = TaskId::new(request.task_id.clone()).unwrap();
    let scope_id = WorkScopeId::new(request.scope_id.clone()).unwrap();
    let request_digest_value = sha256_hex(&canonical_json_bytes(request).unwrap());
    let core = ReceiptCore {
        contract: contract_identity().unwrap(),
        kind: ReceiptKind::Operation,
        work_scope: WorkScopeBinding {
            scope_id,
            product_id: product_id.clone(),
            resource_generation: fence.resource_generation,
            state_fence: fence.clone(),
        },
        task: Some(TaskBinding {
            task_id,
            task_revision: TaskRevision::genesis(),
            state_fence: fence.clone(),
        }),
        session: None,
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: parent
                .as_ref()
                .map_or_else(TransactionSequence::genesis, |_| {
                    TransactionSequence::new(2).unwrap()
                }),
            parent_receipt_id: parent.clone(),
            predecessor_receipt_ids: parent.into_iter().collect(),
        },
        request: RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id: request_id.clone(),
                session_id: None,
                task_id: Some(TaskId::new(request.task_id.clone()).unwrap()),
                product_id,
                source_id,
                state_fence: fence.clone(),
                clock: ClockReading {
                    valid_time_ms: Some(1),
                    known_time_ms: Some(1),
                    transaction_sequence: Some(TransactionSequence::genesis()),
                    monotonic_ns: None,
                },
            },
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id,
            request_id,
            idempotency_key: request.idempotency_key.clone(),
            operation_kind: request.operation_kind.clone(),
            effect: request.effect,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-1").unwrap(),
            authority_owner: request.owner.clone(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: request.effect,
            proof_ceiling: request.proof_ceiling,
        },
        artifacts: std::iter::once(eliot_receipts::ArtifactBinding {
            artifact_id: ArtifactId::new("request-artifact").unwrap(),
            sha256: request_digest_value,
            role: ReceiptKind::Request,
            source_revision: None,
        })
        .chain(std::iter::once(eliot_receipts::ArtifactBinding {
            artifact_id: ArtifactId::new("payload-1").unwrap(),
            sha256: request.payload_digest.clone(),
            role: ReceiptKind::Artifact,
            source_revision: None,
        }))
        .chain(
            extras
                .iter()
                .map(|(id, digest)| eliot_receipts::ArtifactBinding {
                    artifact_id: ArtifactId::new(*id).unwrap(),
                    sha256: (*digest).to_owned(),
                    role: ReceiptKind::Artifact,
                    source_revision: None,
                }),
        )
        .collect(),
        verifier: None,
        problem: None,
        coordination: None,
        disposition,
    };
    ReceiptEnvelope::issue(core).unwrap()
}

fn outcome(
    request: &PendingRequest,
    receipt: ReceiptEnvelope,
    disposition: OutcomeDisposition,
    possible_effect: bool,
) -> ObservedOutcome {
    outcome_at(
        request,
        receipt,
        CyclePhase::BundleValidated,
        disposition,
        possible_effect,
        Vec::new(),
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn outcome_at(
    request: &PendingRequest,
    receipt: ReceiptEnvelope,
    phase: CyclePhase,
    disposition: OutcomeDisposition,
    possible_effect: bool,
    evidence_refs: Vec<ArtifactId>,
    handler_result: Option<eliot_dreamer_contracts::TypedCurationHandlerResult>,
    validation_receipt: Option<eliot_dreamer_contracts::ValidationReceipt>,
    screen_binding: Option<ScreenBinding>,
) -> ObservedOutcome {
    ObservedOutcome {
        receipt,
        phase,
        disposition,
        payload_digest: request.payload_digest.clone(),
        possible_effect,
        evidence_refs,
        handler_result,
        validation_receipt,
        screen_binding,
    }
}

fn screen_for(request: &PendingRequest) -> ScreenBinding {
    ScreenBinding {
        request_id: request.request_id.clone(),
        receipt_id: eliot_contracts::ReceiptId::new("screen-receipt-1").unwrap(),
        screened_targets: vec!["target".to_owned()],
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        task_id: request.task_id.clone(),
        scope_id: request.scope_id.clone(),
        state_fence: request.state_fence.clone(),
        state: ScreenState::Eligible,
        result_digest: "d".repeat(64),
        item_digest: request.payload_digest.clone(),
    }
}

fn rebind(state: &mut DreamerCycleState, policy: &CyclePolicy) {
    state.policy_id = policy.policy_id.clone();
    state.policy_revision = policy.policy_revision;
    state.policy_digest.clone_from(&policy.canonical_digest);
    state.seal().unwrap();
}

fn retune(
    state: &DreamerCycleState,
    policy: &CyclePolicy,
    tune: impl FnOnce(&mut CyclePolicy),
) -> (DreamerCycleState, CyclePolicy) {
    let mut policy = policy.clone();
    tune(&mut policy);
    policy.seal().unwrap();
    let mut state = state.clone();
    rebind(&mut state, &policy);
    (state, policy)
}

/// Moves one caller-supplied proposal for `phase` into `proposed_requests`,
/// mirroring the native test harness (no controller logic in the guest).
fn propose(
    state: &mut DreamerCycleState,
    policy: &CyclePolicy,
    phase: CyclePhase,
    kind: RequestKind,
) -> PendingRequest {
    rebind(state, policy);
    let mut request = pending(policy, &state.job.clone());
    let phase_tag = format!("{phase:?}").to_lowercase();
    request.request_id = RequestId::new(format!("request-{phase_tag}")).unwrap();
    request.operation_id = OperationId::new(format!("operation-{phase_tag}")).unwrap();
    request.idempotency_key = format!("idem-{phase_tag}");
    request.attempt_id = AgentAttemptId::new(format!("attempt-{phase_tag}")).unwrap();
    request.phase = phase;
    request.kind = kind;
    let rule = &policy.phase_rules[0];
    request.owner.clone_from(&rule.owner);
    request.product_id = rule.product_id.clone();
    request.source_id = rule.source_id.clone();
    request.operation_kind.clone_from(&rule.operation_kind);
    request.effect = rule.effect;
    request.proof_ceiling = rule.proof_ceiling;
    request.predecessor_receipt_id = state
        .outcomes
        .last()
        .map(|outcome| outcome.receipt.identity.receipt_id.clone());
    state.proposed_requests = vec![request.clone()];
    state.seal().unwrap();
    request
}

fn guest_envelope(
    state: DreamerCycleState,
    observed: Vec<ObservedOutcome>,
    policy: CyclePolicy,
) -> GuestRequest {
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        state,
        observed,
        policy,
        observation_time_ms: None,
    }
}

/// Minimal valid scenario: one completed bundle-validation observation.
fn completed_bundle() -> (
    GuestRequest,
    DreamerCycleState,
    CyclePolicy,
    ObservedOutcome,
) {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let bundle_receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let observed = outcome(
        &request,
        bundle_receipt,
        OutcomeDisposition::Completed,
        false,
    );
    let envelope = guest_envelope(
        current.clone(),
        vec![observed.clone()],
        current_policy.clone(),
    );
    (envelope, current, current_policy, observed)
}

/// Activation scenario: empty pending plus one proposed next-phase request.
fn activation() -> (GuestRequest, DreamerCycleState, CyclePolicy, PendingRequest) {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let mut current = state(&current_policy, &current_job, request);
    current.pending.clear();
    current.seal().unwrap();
    let proposed = propose(
        &mut current,
        &current_policy,
        CyclePhase::BundleValidated,
        RequestKind::BundleValidation,
    );
    let envelope = guest_envelope(current.clone(), Vec::new(), current_policy.clone());
    (envelope, current, current_policy, proposed)
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn own_manifest() -> &'static str {
    include_str!("../Cargo.toml")
}

fn own_module() -> &'static str {
    include_str!("../module.toml")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

fn candidate_artifact_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(dir) = option_env!("CARGO_TARGET_DIR") {
        paths.push(
            std::path::PathBuf::from(dir)
                .join("wasm32-wasip2/release/eliot_dreamer_cycle_wasm.wasm"),
        );
    }
    paths.push(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/wasm32-wasip2/release/eliot_dreamer_cycle_wasm.wasm"),
    );
    paths
}

// WORK_UNIT_CASE: 644/1
#[test]
fn minimal_valid_native_transition() {
    let (envelope, current, current_policy, observed) = completed_bundle();
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&observed), &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Advanced);
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&envelope, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.error.is_none());
    let step = response.step.expect("step");
    assert_eq!(step, native);
    assert_eq!(step.disposition, StepDisposition::Advanced);
    assert_eq!(step.next_state.phase, CyclePhase::BundleValidated);
    assert!(step.next_state.pending.is_empty());
    assert_eq!(step.predecessor_digest, current.canonical_digest);
    assert_eq!(step.transition_digest.len(), 64);
    assert!(step.requests.is_empty());
    // The same semantics hold through the `run` byte boundary.
    let bytes = run(&encode_request(&envelope).expect("encode")).expect("run");
    let through_bytes = decode_response(&bytes).expect("decode");
    assert_eq!(through_bytes.step.expect("step"), native);
    assert_eq!(through_bytes.native_calls, 1);
    // Request digest binds the envelope for capsule correlation.
    assert_eq!(request_digest(&envelope).len(), 64);
    assert_eq!(wit_export_name(), "run");
}

// WORK_UNIT_CASE: 644/2
#[test]
fn no_work_idle_replays_without_mutation() {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let mut idle = state(&current_policy, &current_job, request);
    idle.pending.clear();
    idle.seal().unwrap();
    let envelope = guest_envelope(idle.clone(), Vec::new(), current_policy.clone());
    let native = step_dreamer_cycle(&idle, &[], &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Replayed);
    assert!(native.requests.is_empty());
    let response = handle_request_typed(&envelope);
    assert_eq!(response.native_calls, 1);
    assert!(response.error.is_none());
    let step = response.step.expect("step");
    assert_eq!(step, native);
    assert_eq!(step.next_state, idle);
    // Exact replay of an already-recorded observation also replays.
    let (first_envelope, _, first_policy, observed) = completed_bundle();
    let first = handle_request_typed(&first_envelope)
        .step
        .expect("first step");
    let replay_envelope = guest_envelope(first.next_state.clone(), vec![observed], first_policy);
    let replay = handle_request_typed(&replay_envelope);
    let replay_step = replay.step.expect("replay step");
    assert_eq!(replay_step.disposition, StepDisposition::Replayed);
    assert_eq!(replay_step.next_state, first.next_state);
}

// WORK_UNIT_CASE: 644/3
#[test]
fn bounded_inert_next_work_request() {
    let (envelope, current, current_policy, proposed) = activation();
    let native = step_dreamer_cycle(&current, &[], &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Advanced);
    assert_eq!(native.requests.len(), 1);
    let response = handle_request_typed(&envelope);
    assert_eq!(response.native_calls, 1);
    let step = response.step.expect("step");
    assert_eq!(step, native);
    assert_eq!(step.requests.len(), 1);
    let inert = &step.requests[0];
    assert_eq!(inert.request_id, proposed.request_id);
    assert_eq!(inert.operation_id, proposed.operation_id);
    assert_eq!(inert.kind, RequestKind::BundleValidation);
    assert_eq!(inert.phase, CyclePhase::BundleValidated);
    assert_eq!(inert.reason, INERT_AWAITING);
    assert_eq!(step.next_state.pending.len(), 1);
    assert_eq!(step.next_state.pending[0].request_id, proposed.request_id);
}

// WORK_UNIT_CASE: 644/4
#[test]
fn blocked_prerequisite_preserves_pending() {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let rejected = outcome_at(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Failure {
                code: ErrorCode::InvalidRequest,
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        CyclePhase::BundleValidated,
        OutcomeDisposition::Rejected,
        false,
        Vec::new(),
        None,
        None,
        None,
    );
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&rejected), &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Blocked);
    assert_eq!(
        native.next_state.frontier,
        ["owner outcome did not advance"]
    );
    let envelope = guest_envelope(current, vec![rejected], current_policy);
    let response = handle_request_typed(&envelope);
    let step = response.step.expect("step");
    assert_eq!(step, native);
    assert_eq!(step.disposition, StepDisposition::Blocked);
    // The blocked prerequisite stays pending; nothing was discharged.
    assert_eq!(step.next_state.pending.len(), 1);
    assert!(step.requests.is_empty());
}

// WORK_UNIT_CASE: 644/5
#[test]
fn partial_outcome_records_frontier() {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let partial = outcome_at(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Partial {
                proof: ProofCeiling::Observation,
                unresolved: vec!["gap-1".to_owned()],
            },
            None,
        ),
        CyclePhase::BundleValidated,
        OutcomeDisposition::Partial,
        false,
        Vec::new(),
        None,
        None,
        None,
    );
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&partial), &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Blocked);
    assert_eq!(native.next_state.frontier, ["partial owner outcome"]);
    let envelope = guest_envelope(current, vec![partial], current_policy);
    let response = handle_request_typed(&envelope);
    let step = response.step.expect("step");
    assert_eq!(step, native);
    assert_eq!(step.next_state.frontier, ["partial owner outcome"]);
    assert!(step.requests.is_empty());
}

// WORK_UNIT_CASE: 644/6
#[test]
fn exact_and_one_over_every_independent_budget() {
    // max_requests on the one-request activation scenario.
    let (_envelope, current, current_policy, _) = activation();
    let (exact, exact_policy) = retune(&current, &current_policy, |policy| {
        policy.max_requests = 1;
    });
    assert_eq!(
        handle_request_typed(&guest_envelope(exact, Vec::new(), exact_policy))
            .step
            .expect("exact max_requests")
            .disposition,
        StepDisposition::Advanced
    );
    let (over, over_policy) = retune(&current, &current_policy, |policy| {
        policy.max_requests = 0;
    });
    let over_response = handle_request_typed(&guest_envelope(over, Vec::new(), over_policy));
    assert_eq!(over_response.native_calls, 1);
    assert_eq!(over_response.error, Some(GuestError::BudgetBlocked));

    // max_outcomes on the one-observation completed scenario.
    let (_bundle_envelope, bundle_state, bundle_policy, observed) = completed_bundle();
    let (exact, exact_policy) = retune(&bundle_state, &bundle_policy, |policy| {
        policy.max_outcomes = 1;
    });
    assert!(
        handle_request_typed(&guest_envelope(exact, vec![observed.clone()], exact_policy))
            .step
            .is_some()
    );
    let (over, over_policy) = retune(&bundle_state, &bundle_policy, |policy| {
        policy.max_outcomes = 0;
    });
    assert_eq!(
        handle_request_typed(&guest_envelope(over, vec![observed.clone()], over_policy)).error,
        Some(GuestError::BudgetBlocked)
    );

    // max_bytes exact length passes, one byte less blocks.
    let native = step_dreamer_cycle(
        &bundle_state,
        std::slice::from_ref(&observed),
        &bundle_policy,
    )
    .unwrap();
    let mut candidate = native.clone();
    candidate.transition_digest.clear();
    let exact_len = u32::try_from(canonical_json_bytes(&candidate).unwrap().len()).unwrap();
    let (exact, exact_policy) = retune(&bundle_state, &bundle_policy, |policy| {
        policy.max_bytes = exact_len;
    });
    assert!(
        handle_request_typed(&guest_envelope(exact, vec![observed.clone()], exact_policy))
            .step
            .is_some()
    );
    let (over, over_policy) = retune(&bundle_state, &bundle_policy, |policy| {
        policy.max_bytes = exact_len - 1;
    });
    assert_eq!(
        handle_request_typed(&guest_envelope(over, vec![observed.clone()], over_policy)).error,
        Some(GuestError::BudgetBlocked)
    );

    // max_transitions on the activation scenario (revision 0).
    let (exact, exact_policy) = retune(&current, &current_policy, |policy| {
        policy.max_transitions = 1;
    });
    assert_eq!(
        handle_request_typed(&guest_envelope(exact, Vec::new(), exact_policy))
            .step
            .expect("exact max_transitions")
            .disposition,
        StepDisposition::Advanced
    );
    let (over, over_policy) = retune(&current, &current_policy, |policy| {
        policy.max_transitions = 0;
    });
    // Dispatch-budget exhaustion does not error: the transition replays empty.
    // This is the native distinction between dispatch budgets (replay) and
    // request/outcome/byte budgets (BudgetBlocked above).
    let over_native = step_dreamer_cycle(&over, &[], &over_policy).unwrap();
    assert_eq!(over_native.disposition, StepDisposition::Replayed);
    assert!(over_native.requests.is_empty());
    let over_response = handle_request_typed(&guest_envelope(over, Vec::new(), over_policy));
    assert_eq!(over_response.error, None);
    assert_eq!(over_response.step.expect("replayed step"), over_native);

    // MAX_RECORDS observations: guest preflights with zero calls, native reports Bound.
    let many = vec![observed.clone(); MAX_RECORDS + 1];
    assert_eq!(many.len(), MAX_RECORDS + 1);
    let ledger = CallLedger::new();
    let rejected = handle_with_ledger(
        &guest_envelope(bundle_state.clone(), many, bundle_policy.clone()),
        &ledger,
    );
    assert_eq!(ledger.calls(), 0);
    assert_eq!(
        rejected.error,
        Some(GuestError::RejectedEnvelope(
            "observed_external_outcomes".to_owned()
        ))
    );
}

// WORK_UNIT_CASE: 644/7
#[test]
fn cancellation_before_evaluation_replays() {
    let (envelope, current, current_policy, _) = activation();
    let baseline = handle_request_typed(&envelope).step.expect("baseline");
    assert_eq!(baseline.disposition, StepDisposition::Advanced);
    // Policy-level cancellation: no error is invented, activation replays empty.
    let (cancelled, cancelled_policy) = retune(&current, &current_policy, |policy| {
        policy.cancellation_requested = true;
    });
    let native = step_dreamer_cycle(&cancelled, &[], &cancelled_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Replayed);
    assert!(native.requests.is_empty());
    let response = handle_request_typed(&guest_envelope(cancelled, Vec::new(), cancelled_policy));
    assert_eq!(response.error, None);
    assert_eq!(response.step.expect("cancelled step"), native);
    // State-level cancellation behaves identically.
    let mut state_cancelled = current.clone();
    state_cancelled.cancellation_requested = true;
    state_cancelled.seal().unwrap();
    let native = step_dreamer_cycle(&state_cancelled, &[], &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::Replayed);
    let response =
        handle_request_typed(&guest_envelope(state_cancelled, Vec::new(), current_policy));
    assert_eq!(response.step.expect("state-cancelled step"), native);
}

// WORK_UNIT_CASE: 644/8
#[test]
fn exhausted_deadline_replays_until_observed() {
    let fence = fence();
    let deadline_job = job_with_deadline(&fence, Some(0));
    let mut deadline_policy = policy(&fence, "bundle_validation");
    deadline_policy.deadline_ms = Some(0);
    deadline_policy.seal().unwrap();
    let request = pending(&deadline_policy, &deadline_job);
    let mut current = state(&deadline_policy, &deadline_job, request);
    current.pending.clear();
    current.seal().unwrap();
    propose(
        &mut current,
        &deadline_policy,
        CyclePhase::BundleValidated,
        RequestKind::BundleValidation,
    );
    // No observation time against an exhausted deadline: budget blocks dispatch.
    let blocked = step_dreamer_cycle_at(&current, &[], &deadline_policy, None).unwrap();
    assert_eq!(blocked.disposition, StepDisposition::Replayed);
    assert!(blocked.requests.is_empty());
    let mut envelope = guest_envelope(current.clone(), Vec::new(), deadline_policy.clone());
    let response = handle_request_typed(&envelope);
    assert_eq!(response.step.expect("deadline step"), blocked);
    // An observation time within the deadline still advances.
    envelope.observation_time_ms = Some(0);
    let advanced = handle_request_typed(&envelope).step.expect("advanced");
    assert_eq!(advanced.disposition, StepDisposition::Advanced);
    assert_eq!(advanced.requests.len(), 1);
    assert_eq!(
        step_dreamer_cycle_at(&current, &[], &deadline_policy, Some(0)).unwrap(),
        advanced
    );
    // An observation time past the deadline blocks again.
    envelope.observation_time_ms = Some(1);
    let past = handle_request_typed(&envelope).step.expect("past");
    assert_eq!(past.disposition, StepDisposition::Replayed);
}

// WORK_UNIT_CASE: 644/9
#[test]
fn stale_identity_fence_scope_task_attempt() {
    let base_fence = fence();
    let current_job = job(&base_fence);
    let current_policy = policy(&base_fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let bundle_receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let observed = outcome(
        &request,
        bundle_receipt,
        OutcomeDisposition::Completed,
        false,
    );

    // Stale fence: policy epoch lineage differs from the frozen job fence.
    let stale_epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_B).unwrap(),
        NonZeroU64::new(1).unwrap(),
    )
    .unwrap();
    let mut stale_fence = fence();
    stale_fence.authority_epoch = stale_epoch;
    let stale_policy = policy(&stale_fence, "bundle_validation");
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&observed), &stale_policy).unwrap_err();
    assert!(matches!(
        native,
        CycleError::BindingMismatch {
            field: "cycle_policy.state_fence",
            ..
        }
    ));
    let response = handle_request_typed(&guest_envelope(
        current.clone(),
        vec![observed.clone()],
        stale_policy,
    ));
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::from(&native)));

    // Changed scope binding in the pending request.
    let mut scoped = request.clone();
    scoped.scope_id = "scope-2".to_owned();
    let scoped_state = state(&current_policy, &current_job, scoped);
    let native = step_dreamer_cycle(
        &scoped_state,
        std::slice::from_ref(&observed),
        &current_policy,
    )
    .unwrap_err();
    assert!(matches!(
        native,
        CycleError::BindingMismatch {
            field: "pending.job_binding",
            ..
        }
    ));
    assert_eq!(
        handle_request_typed(&guest_envelope(
            scoped_state,
            vec![observed.clone()],
            current_policy.clone()
        ))
        .error,
        Some(GuestError::from(&native))
    );

    // Changed task binding in the pending request.
    let mut tasked = request.clone();
    tasked.task_id = "task-2".to_owned();
    let tasked_state = state(&current_policy, &current_job, tasked);
    let native = step_dreamer_cycle(
        &tasked_state,
        std::slice::from_ref(&observed),
        &current_policy,
    )
    .unwrap_err();
    assert!(matches!(
        native,
        CycleError::BindingMismatch {
            field: "pending.job_binding",
            ..
        }
    ));
    assert_eq!(
        handle_request_typed(&guest_envelope(
            tasked_state,
            vec![observed.clone()],
            current_policy.clone()
        ))
        .error,
        Some(GuestError::from(&native))
    );

    // Changed attempt identity breaks the receipt request-artifact binding.
    let mut attempted = request.clone();
    attempted.attempt_id = AgentAttemptId::new("attempt-9").unwrap();
    let attempted_state = state(&current_policy, &current_job, attempted);
    let native = step_dreamer_cycle(
        &attempted_state,
        std::slice::from_ref(&observed),
        &current_policy,
    )
    .unwrap_err();
    let response = handle_request_typed(&guest_envelope(
        attempted_state,
        vec![observed],
        current_policy,
    ));
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::from(&native)));
}

// WORK_UNIT_CASE: 644/10
#[test]
fn state_policy_native_wit_revision_mismatch() {
    let (envelope, current, current_policy, observed) = completed_bundle();
    // Native schema revisions preflight in the guest with zero native calls.
    let mut bad_state = current.clone();
    bad_state.schema_version = CYCLE_SCHEMA_VERSION + 98;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(
        &guest_envelope(bad_state, vec![observed.clone()], current_policy.clone()),
        &ledger,
    );
    assert_eq!(ledger.calls(), 0);
    assert_eq!(
        response.error,
        Some(GuestError::RejectedEnvelope(
            "state.schema_version".to_owned()
        ))
    );
    let mut bad_policy = current_policy.clone();
    bad_policy.schema_version = CYCLE_SCHEMA_VERSION + 98;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(
        &guest_envelope(current.clone(), vec![observed.clone()], bad_policy),
        &ledger,
    );
    assert_eq!(ledger.calls(), 0);
    assert_eq!(
        response.error,
        Some(GuestError::RejectedEnvelope(
            "policy.schema_version".to_owned()
        ))
    );
    // Frozen policy identity drift reaches native and keeps its typed error.
    let (drifted, drifted_policy) = retune(&current, &current_policy, |policy| {
        policy.policy_id = ArtifactId::new("policy-2").unwrap();
    });
    let native =
        step_dreamer_cycle(&drifted, std::slice::from_ref(&observed), &drifted_policy).unwrap_err();
    assert!(matches!(
        native,
        CycleError::BindingMismatch {
            field: "cycle_policy.identity",
            ..
        }
    ));
    let response = handle_request_typed(&guest_envelope(
        drifted,
        vec![observed.clone()],
        drifted_policy,
    ));
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::from(&native)));
    // WIT world and ABI drift never reach native.
    for mutate in [
        |envelope: &mut GuestRequest| envelope.world = "dreamer-cycle-step".to_owned(),
        |envelope: &mut GuestRequest| envelope.abi_version = 999,
        |envelope: &mut GuestRequest| envelope.handler_subtype = "orientation".to_owned(),
    ] {
        let mut bad = envelope.clone();
        mutate(&mut bad);
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&bad, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert!(matches!(
            response.error,
            Some(GuestError::RejectedEnvelope(_))
        ));
    }
}

// WORK_UNIT_CASE: 644/11
#[test]
fn duplicate_and_changed_same_id_content() {
    let (envelope, current, current_policy, observed) = completed_bundle();
    // The same new observation twice in one call conflicts.
    let native = step_dreamer_cycle(
        &current,
        &[observed.clone(), observed.clone()],
        &current_policy,
    )
    .unwrap_err();
    assert!(matches!(native, CycleError::IdentityConflict { .. }));
    let response = handle_request_typed(&guest_envelope(
        current.clone(),
        vec![observed.clone(), observed.clone()],
        current_policy.clone(),
    ));
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::from(&native)));
    // Changed content under the recorded receipt id is rejected on replay.
    let first = handle_request_typed(&envelope).step.expect("first");
    let mut changed = observed.clone();
    changed.disposition = OutcomeDisposition::Accepted;
    let native = step_dreamer_cycle(
        &first.next_state,
        std::slice::from_ref(&changed),
        &current_policy,
    )
    .unwrap_err();
    assert!(matches!(native, CycleError::IdentityConflict { .. }));
    assert_eq!(
        handle_request_typed(&guest_envelope(
            first.next_state,
            vec![changed],
            current_policy.clone()
        ))
        .error,
        Some(GuestError::from(&native))
    );
    // Duplicate pending identities fail state validation through the guest.
    let fence = fence();
    let current_job = job(&fence);
    let dup_request = pending(&current_policy, &current_job);
    let mut dup_state = state(&current_policy, &current_job, dup_request.clone());
    dup_state.pending = vec![dup_request.clone(), dup_request];
    dup_state.seal().unwrap();
    let native = step_dreamer_cycle(&dup_state, &[], &current_policy).unwrap_err();
    assert!(matches!(native, CycleError::IdentityConflict { .. }));
    assert_eq!(
        handle_request_typed(&guest_envelope(dup_state, Vec::new(), current_policy)).error,
        Some(GuestError::from(&native))
    );
}

// WORK_UNIT_CASE: 644/12
#[test]
fn unknown_schema_field_variant_rejected() {
    let (envelope, _, _, _) = completed_bundle();
    let bytes = encode_request(&envelope).expect("encode");
    // Unknown top-level field.
    let json = String::from_utf8(bytes.clone()).expect("UTF-8");
    let injected = json.replacen('{', "{\"guest_unknown_field\":1,", 1);
    assert!(decode_request(injected.as_bytes()).is_err());
    assert!(run(injected.as_bytes()).is_err());
    // Unknown outcome disposition variant.
    let unknown_disposition = json.replacen("\"COMPLETED\"", "\"FROBNICATED\"", 1);
    assert_ne!(unknown_disposition, json);
    assert!(decode_request(unknown_disposition.as_bytes()).is_err());
    // Unknown phase variant.
    let unknown_phase = json.replacen("\"BUNDLE_VALIDATED\"", "\"SLEEPING\"", 1);
    assert_ne!(unknown_phase, json);
    assert!(decode_request(unknown_phase.as_bytes()).is_err());
    // Unknown step disposition never parses.
    assert_eq!(parse_disposition("frobnicated"), None);
    assert_eq!(parse_disposition("other"), None);
    // A decodable-but-unsupported schema revision is a typed zero-call rejection.
    let mut decoded = decode_request(&bytes).expect("decode");
    decoded.state.schema_version = CYCLE_SCHEMA_VERSION + 98;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&decoded, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::RejectedEnvelope(_))
    ));
}

// WORK_UNIT_CASE: 644/13
#[test]
fn malformed_state_input_mapped_not_trapped() {
    // Truncated and empty envelopes stay at the transport boundary.
    let (envelope, _, _, _) = completed_bundle();
    let bytes = encode_request(&envelope).expect("encode");
    assert!(run(&[]).is_err());
    assert!(run(&[0xFF, 0xFE, 0x00]).is_err());
    assert!(run(&bytes[..bytes.len() / 2]).is_err());
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"trailing");
    assert!(run(&trailing).is_err());
    assert!(decode_request(&vec![0u8; 2_097_152]).is_err());
    // Malformed frozen state reaches native once and keeps its typed error:
    // a non-digest bundle binding passes the byte preflight but not validation.
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let mut malformed = state(&current_policy, &current_job, request);
    malformed.bundle_digest = "not-a-digest-644".to_owned();
    malformed.seal().unwrap();
    let native = step_dreamer_cycle(&malformed, &[], &current_policy).unwrap_err();
    assert!(matches!(native, CycleError::IncompleteOutcome(_)));
    let response = handle_request_typed(&guest_envelope(malformed, Vec::new(), current_policy));
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::from(&native)));
    // Tampered policy digest keeps the native identity-conflict error.
    let (fresh_envelope, fresh_state, fresh_policy, _) = completed_bundle();
    let _ = fresh_envelope;
    let mut tampered_policy = fresh_policy.clone();
    tampered_policy.canonical_digest = "0".repeat(64);
    let native = step_dreamer_cycle(&fresh_state, &[], &tampered_policy).unwrap_err();
    assert!(matches!(native, CycleError::IdentityConflict { .. }));
    assert_eq!(
        handle_request_typed(&guest_envelope(fresh_state, Vec::new(), tampered_policy)).error,
        Some(GuestError::from(&native))
    );
}

// WORK_UNIT_CASE: 644/14
#[test]
fn every_native_error_maps_exhaustively() {
    let base_fence = fence();
    let current_job = job(&base_fence);
    let current_policy = policy(&base_fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let success = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let completed = outcome(&request, success, OutcomeDisposition::Completed, false);
    let mut natives: Vec<CycleError> = Vec::new();
    // BindingMismatch: stale policy fence.
    let mut stale_fence = fence();
    stale_fence.authority_epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_B).unwrap(),
        NonZeroU64::new(1).unwrap(),
    )
    .unwrap();
    natives.push(
        step_dreamer_cycle(
            &current,
            std::slice::from_ref(&completed),
            &policy(&stale_fence, "bundle_validation"),
        )
        .unwrap_err(),
    );
    // IdentityConflict: duplicated new observation.
    natives.push(
        step_dreamer_cycle(
            &current,
            &[completed.clone(), completed.clone()],
            &current_policy,
        )
        .unwrap_err(),
    );
    // PhaseViolation: two distinct new observations in one call. A receipt
    // issued under a different causal parent carries a different identity,
    // so both observations are new and the single-observation rule fires.
    let second_receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        Some(ReceiptId::new("receipt-parent-644").unwrap()),
    );
    let second = outcome(
        &request,
        second_receipt,
        OutcomeDisposition::Completed,
        false,
    );
    // Same receipt shape under a fresh id still counts as two new observations.
    let two_new =
        step_dreamer_cycle(&current, &[completed.clone(), second], &current_policy).unwrap_err();
    assert!(matches!(two_new, CycleError::PhaseViolation(_)));
    natives.push(two_new);
    // IncompleteOutcome: a non-digest bundle binding fails state validation.
    let mut bad_digest = current.clone();
    bad_digest.bundle_digest = "not-a-digest-644".to_owned();
    bad_digest.seal().unwrap();
    natives.push(
        step_dreamer_cycle(
            &bad_digest,
            std::slice::from_ref(&completed),
            &current_policy,
        )
        .unwrap_err(),
    );
    // Bound: native direct call with one-over observations.
    let mut many = Vec::new();
    for _ in 0..=MAX_RECORDS {
        many.push(completed.clone());
    }
    natives.push(step_dreamer_cycle(&current, &many, &current_policy).unwrap_err());
    // BudgetBlocked: zero request allowance on the activation scenario.
    let (activation_envelope, activation_state, activation_policy, _) = activation();
    let _ = activation_envelope;
    let (blocked_state, blocked_policy) = retune(&activation_state, &activation_policy, |policy| {
        policy.max_requests = 0;
    });
    natives.push(step_dreamer_cycle(&blocked_state, &[], &blocked_policy).unwrap_err());
    // Contract: screen binding with a non-hex digest fails inner validation.
    let mut bad_screen = screen_for(&request);
    bad_screen.result_digest = "z".repeat(64);
    let screened = outcome_at(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        CyclePhase::BundleValidated,
        OutcomeDisposition::Completed,
        false,
        Vec::new(),
        None,
        None,
        Some(bad_screen),
    );
    natives.push(
        step_dreamer_cycle(&current, std::slice::from_ref(&screened), &current_policy).unwrap_err(),
    );
    // Receipt: tampered receipt identity digest fails envelope validation.
    let mut tampered = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    tampered.identity.canonical_sha256 = "0".repeat(64);
    let tampered_outcome = outcome(&request, tampered, OutcomeDisposition::Completed, false);
    natives.push(
        step_dreamer_cycle(
            &current,
            std::slice::from_ref(&tampered_outcome),
            &current_policy,
        )
        .unwrap_err(),
    );
    // Encoding: canonical encoding over these shapes is infallible in practice;
    // the mapping arm itself is still proven closed and distinct.
    natives.push(CycleError::Encoding("probe-644".to_owned()));
    assert_eq!(natives.len(), 9);
    assert!(matches!(natives[0], CycleError::BindingMismatch { .. }));
    assert!(matches!(natives[1], CycleError::IdentityConflict { .. }));
    assert!(matches!(natives[2], CycleError::PhaseViolation(_)));
    assert!(matches!(natives[3], CycleError::IncompleteOutcome(_)));
    assert!(matches!(natives[4], CycleError::Bound { .. }));
    assert!(matches!(natives[5], CycleError::BudgetBlocked));
    assert!(matches!(natives[6], CycleError::Contract(_)));
    assert!(matches!(natives[7], CycleError::Receipt(_)));
    assert!(matches!(natives[8], CycleError::Encoding(_)));
    let mut seen = BTreeSet::new();
    for native in &natives {
        let guest = GuestError::from(native);
        let json = canonical_json_bytes(&guest).expect("guest error json");
        assert!(seen.insert(json), "every native error maps distinctly");
    }
    assert_eq!(seen.len(), 9);
    // Each mapped shape carries its native payload through the boundary.
    assert!(matches!(
        GuestError::from(&natives[0]),
        GuestError::BindingMismatch { .. }
    ));
    assert!(matches!(
        GuestError::from(&natives[1]),
        GuestError::IdentityConflict { .. }
    ));
    assert!(matches!(
        GuestError::from(&natives[2]),
        GuestError::PhaseViolation(_)
    ));
    assert!(matches!(
        GuestError::from(&natives[3]),
        GuestError::IncompleteOutcome(_)
    ));
    assert!(matches!(
        GuestError::from(&natives[4]),
        GuestError::BoundExceeded { .. }
    ));
    assert_eq!(GuestError::from(&natives[5]), GuestError::BudgetBlocked);
    assert!(matches!(
        GuestError::from(&natives[6]),
        GuestError::ContractViolation(_)
    ));
    assert!(matches!(
        GuestError::from(&natives[7]),
        GuestError::ReceiptViolation(_)
    ));
    assert!(matches!(
        GuestError::from(&natives[8]),
        GuestError::EncodingFailure(_)
    ));
}

// WORK_UNIT_CASE: 644/15
#[test]
fn possible_external_outcome_stays_unknown_no_retry() {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let unknown_receipt = receipt(
        &request,
        ReceiptDisposition::Unknown {
            reason: "no observation yet".to_owned(),
        },
        None,
    );
    let unknown_id = unknown_receipt.identity.receipt_id.clone();
    let unknown = outcome(&request, unknown_receipt, OutcomeDisposition::Unknown, true);
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&unknown), &current_policy).unwrap();
    assert_eq!(native.disposition, StepDisposition::ReconciliationRequired);
    assert_eq!(native.next_state.frontier, ["unknown external outcome"]);
    let envelope = guest_envelope(current, vec![unknown], current_policy);
    let response = handle_request_typed(&envelope);
    let step = response.step.expect("step");
    assert_eq!(step, native);
    // No retry is issued: exactly one reconciliation request names the same operation.
    assert_eq!(step.requests.len(), 1);
    let reconcile = &step.requests[0];
    assert_eq!(reconcile.kind, RequestKind::EffectReconciliation);
    assert_eq!(reconcile.request_id, request.request_id);
    assert_eq!(reconcile.operation_id, request.operation_id);
    assert_eq!(reconcile.predecessor_receipt_id, Some(unknown_id));
    assert_eq!(reconcile.reason, INERT_RECONCILE);
}

// WORK_UNIT_CASE: 644/16
#[test]
fn irrelevant_set_order_invariance() {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let refs = |first: &str, second: &str| {
        vec![
            ArtifactId::new(first).unwrap(),
            ArtifactId::new(second).unwrap(),
        ]
    };
    let build = |order: Vec<ArtifactId>| {
        let accepted = receipt_with_artifacts(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
            &[("extra-a", PAYLOAD), ("extra-b", PAYLOAD)],
        );
        outcome_at(
            &request,
            accepted,
            CyclePhase::BundleValidated,
            OutcomeDisposition::Accepted,
            false,
            order,
            None,
            None,
            None,
        )
    };
    let first = build(refs("extra-a", "extra-b"));
    let second = build(refs("extra-b", "extra-a"));
    let one = handle_request_typed(&guest_envelope(
        current.clone(),
        vec![first],
        current_policy.clone(),
    ))
    .step
    .expect("first order");
    let two = handle_request_typed(&guest_envelope(current, vec![second], current_policy))
        .step
        .expect("second order");
    // Evidence membership is order-insensitive: same disposition, same requests.
    assert_eq!(one.disposition, StepDisposition::ReconciliationRequired);
    assert_eq!(two.disposition, StepDisposition::ReconciliationRequired);
    assert_eq!(one.requests, two.requests);
}

// WORK_UNIT_CASE: 644/17
#[test]
fn exact_native_semantic_digest_equality() {
    let (envelope, current, current_policy, observed) = completed_bundle();
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&observed), &current_policy).unwrap();
    let response = handle_request_typed(&envelope);
    let step = response.step.expect("step");
    assert_eq!(step.transition_digest, native.transition_digest);
    assert_eq!(step.predecessor_digest, current.canonical_digest);
    assert_eq!(
        step.next_state.canonical_digest,
        native.next_state.canonical_digest
    );
    assert_eq!(step.next_state.controller_revision, 1);
    assert_eq!(
        step.next_state.predecessor_digest,
        Some(current.canonical_digest.clone())
    );
    for digest in [
        &step.transition_digest,
        &step.predecessor_digest,
        &step.next_state.canonical_digest,
    ] {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    // Disposition wire spellings round-trip over the closed set.
    for (disposition, code) in [
        (StepDisposition::Advanced, "advanced"),
        (StepDisposition::Replayed, "replayed"),
        (
            StepDisposition::ReconciliationRequired,
            "reconciliation_required",
        ),
        (StepDisposition::Blocked, "blocked"),
        (StepDisposition::Terminal, "terminal"),
    ] {
        assert_eq!(disposition_as_str(disposition), code);
        assert_eq!(parse_disposition(code), Some(disposition));
    }
}

// WORK_UNIT_CASE: 644/18
#[test]
fn output_bound_retains_frontier() {
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let partial = outcome_at(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Partial {
                proof: ProofCeiling::Observation,
                unresolved: vec!["gap-1".to_owned()],
            },
            None,
        ),
        CyclePhase::BundleValidated,
        OutcomeDisposition::Partial,
        false,
        Vec::new(),
        None,
        None,
        None,
    );
    let native =
        step_dreamer_cycle(&current, std::slice::from_ref(&partial), &current_policy).unwrap();
    let mut candidate = native.clone();
    candidate.transition_digest.clear();
    let exact_len = u32::try_from(canonical_json_bytes(&candidate).unwrap().len()).unwrap();
    let (exact, exact_policy) = retune(&current, &current_policy, |policy| {
        policy.max_bytes = exact_len;
    });
    let response =
        handle_request_typed(&guest_envelope(exact, vec![partial.clone()], exact_policy));
    let step = response.step.expect("exact bound keeps output");
    assert_eq!(step.next_state.frontier, ["partial owner outcome"]);
    // The retuned policy carries a new digest, so full-step parity is against
    // native under the same exact policy rather than the original-budget run.
    let (parity_state, parity_policy) = retune(&current, &current_policy, |policy| {
        policy.max_bytes = exact_len;
    });
    let parity_native = step_dreamer_cycle(
        &parity_state,
        std::slice::from_ref(&partial),
        &parity_policy,
    )
    .unwrap();
    assert_eq!(step, parity_native);
    // One byte less fails closed instead of truncating the frontier.
    let (over, over_policy) = retune(&current, &current_policy, |policy| {
        policy.max_bytes = exact_len - 1;
    });
    assert_eq!(
        handle_request_typed(&guest_envelope(over, vec![partial], over_policy)).error,
        Some(GuestError::BudgetBlocked)
    );
}

// WORK_UNIT_CASE: 644/19
#[test]
fn actual_built_import_inspection() {
    // The pinned gate itself is proven over fixtures in both encodings first:
    // core modules and components share one forbidden-namespace rule.
    for forbidden in eliot_dreamer_cycle_wasm::FORBIDDEN_IMPORT_SUBSTRINGS {
        assert!(
            is_forbidden_import(&format!("cap:{forbidden}"), "f"),
            "gate covers {forbidden}"
        );
    }
    for (module, name) in [
        ("wasi:filesystem/types@0.2.10", "stat"),
        ("wasi:sockets/tcp@0.2.10", "connect"),
        ("wasi:http/outgoing-handler@0.2.10", "handle"),
        ("wasi:cli/stdin@0.2.10", "get-stdin"),
        ("wasi:clocks/wall-clock@0.2.10", "now"),
        ("wasi:random/random@0.2.10", "get-random-bytes"),
    ] {
        let wasm = wat::parse_str(format!("(module (import \"{module}\" \"{name}\" (func)))"))
            .expect("wasi fixture");
        let error = check_wasm_imports(&wasm).expect_err("forbidden import must fail");
        assert_eq!(
            error,
            eliot_dreamer_cycle_wasm::DescriptorError::ForbiddenImport {
                module: module.into(),
                name: name.into(),
            }
        );
    }
    let component_forbidden = wat::parse_str(
        "(component (import \"wasi:clocks/wall-clock@0.2.10\" (instance (export \"now\" (func)))))",
    )
    .expect("component wasi fixture");
    let error = check_wasm_imports(&component_forbidden).expect_err("component import must fail");
    assert_eq!(
        error,
        eliot_dreamer_cycle_wasm::DescriptorError::ForbiddenImport {
            module: "wasi:clocks/wall-clock@0.2.10".into(),
            name: "instance".into(),
        }
    );
    let benign =
        wat::parse_str("(module (func (export \"run\") (param i32) (result i32) local.get 0))")
            .expect("benign fixture");
    assert_eq!(list_wasm_imports(&benign).expect("imports"), vec![]);
    assert!(
        check_wasm_imports(&benign)
            .expect("benign passes")
            .is_empty()
    );
    let benign_component = wat::parse_str("(component)").expect("benign component fixture");
    assert_eq!(
        list_wasm_imports(&benign_component).expect("component imports"),
        vec![]
    );
    assert_eq!(
        list_wasm_imports(b"not a module").expect_err("not wasm"),
        eliot_dreamer_cycle_wasm::DescriptorError::NotWasm
    );
    assert!(check_wasm_imports(b"not a module").is_err());
    // Then the actual built component is inspected when the wasip2 release
    // artifact exists on the proving machine.
    let found = candidate_artifact_paths()
        .into_iter()
        .find(|path| path.is_file());
    if let Some(path) = found {
        let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("read {}", path.display()));
        let imports = check_wasm_imports(&bytes).expect("built artifact passes the gate");
        for import in &imports {
            assert!(
                !is_forbidden_import(&import.module, &import.name),
                "built import {}::{} is not forbidden",
                import.module,
                import.name
            );
        }
        eprintln!(
            "inspected built artifact {}: {} imports",
            path.display(),
            imports.len()
        );
    } else {
        eprintln!("no built wasip2 artifact present; gate proven over fixtures");
    }
}

// WORK_UNIT_CASE: 644/20
#[test]
fn one_native_call_no_local_controller_algorithm() {
    let (envelope, _, _, _) = completed_bundle();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&envelope, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.step.is_some());
    // Structural proof: exactly one native call site outside tests.
    let mut at_sites = 0;
    let mut plain_sites = 0;
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        at_sites += read_src(name).matches("step_dreamer_cycle_at(").count();
        plain_sites += read_src(name).matches("step_dreamer_cycle(").count();
    }
    assert_eq!(at_sites, 1);
    assert_eq!(plain_sites, 0);
}

// WORK_UNIT_CASE: 644/21
#[test]
fn no_scheduler_store_provider_process_path() {
    // Capability-deny names live only in the import gate itself: the deny
    // list must name every issue-namespace capability, while no other source
    // file may touch scheduler, store, provider, process or effect paths.
    for namespace in [
        "filesystem",
        "network",
        "stdio",
        "env",
        "args",
        "clock",
        "random",
        "process",
        "thread",
        "credential",
        "store",
        "kernel",
        "provider",
    ] {
        assert!(
            eliot_dreamer_cycle_wasm::FORBIDDEN_IMPORT_SUBSTRINGS.contains(&namespace),
            "gate must deny {namespace}"
        );
    }
    for name in ["lib.rs", "conversion.rs", "export.rs"] {
        let source = read_src(name);
        for forbidden in [
            "Scheduler",
            "scheduler",
            "DurableJob",
            "durable_job",
            "Store",
            "provider",
            "Provider",
            "tokio",
            "reqwest",
            "surrealdb",
            "std::process",
            "std::fs",
            "WasmRuntime",
            "execute(",
            "Finish",
            "plan_cycle",
            "sample_cycle",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
    // No generic-serialization or stub escape in any source file.
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source = read_src(name);
        for forbidden in ["serde_json::Value", "unimplemented!", "todo!", "todo!()"] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
    // Executed-effect vocabulary never appears in a guest response.
    let (envelope, _, _, _) = completed_bundle();
    let response = handle_request_typed(&envelope);
    let json =
        String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
    for absent in [
        "DurableJob",
        "Finish",
        "scheduled",
        "executed",
        "task_completion",
        "OperationContinuationPermit",
        "new_authority_epoch",
        "cutover",
    ] {
        assert!(!json.contains(absent), "response must not raise {absent}");
    }
}

// WORK_UNIT_CASE: 644/22
#[test]
fn clean_warm_independent_build_after_toolchain_no_qualification_cycle() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-dreamer-cycle-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // #870 readiness: pinned target and channel from the owning toolchain file.
    let toolchain = String::from_utf8(eliot_dreamer_cycle_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("rust-toolchain.toml is UTF-8");
    assert!(toolchain.contains("wasm32-wasip2"));
    assert!(toolchain.contains(TOOLCHAIN_CHANNEL));
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert_eq!(GUEST_TARGET, eliot_wasm_runtime::DEFAULT_GUEST_TARGET);
    // I2.11 standalone mode: own manifest carries its own workspace table and
    // every ELIOT dependency resolves through a relative path input.
    assert!(own_manifest().contains("[workspace]"));
    for line in own_manifest().lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("eliot-") && trimmed.contains('=') {
            assert!(
                trimmed.contains("path = "),
                "standalone dep must be path-pinned: {trimmed}"
            );
        }
    }
    assert!(!own_manifest().contains("764"));
    assert!(own_module().contains("644/1..27"));
    // Controller-owned handoff (issue #644): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-dreamer-cycle-wasm"));
}

// WORK_UNIT_CASE: 644/23
#[test]
fn actual_kit_capsule_identity_execution_and_serialized_admission() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let descriptor = descriptor();
    assert_eq!(descriptor.world_package, WORLD_PACKAGE);
    assert_eq!(descriptor.world, WORLD_NAME);
    assert_eq!(descriptor.export_name, "run");
    assert_eq!(descriptor.handler_subtype, HANDLER_SUBTYPE);
    assert_eq!(descriptor.abi_version, GUEST_ABI_VERSION);
    assert!(descriptor.capability_envelope.is_empty());
    assert_eq!(qualified_export_name(), format!("{WORLD_NAME}#run"));
    let (envelope, _, _, _) = completed_bundle();
    let input = encode_request(&envelope).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-644-capsule").expect("invocation"),
        CapabilityId::new("fixture-cycle-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-644").expect("work unit"),
        WorkScopeRef::new("fixture-scope-644").expect("scope"),
        ExecutionContour::Shadow,
        input,
        644,
        false,
    )
    .expect("capsule request");
    invocation.validate().expect("capsule digest");
    // #758/#760 are OPEN: no engine/port surface is injected, so the real
    // facade must return the typed PLAN_GAP instead of executing.
    let mut runtime = WasmRuntime::new(None);
    let result = runtime.execute(invocation);
    assert_eq!(
        result.receipt.disposition,
        InvocationDisposition::Unavailable
    );
    assert_eq!(result.receipt.error, Some(RuntimeError::PlanGap));
    assert!(result.output.is_none());
    assert!(result.proposed_effects.is_empty());
    assert!(result.observed_state_delta.is_none());
    assert!(!result.receipt.reconciliation_required);
    // Cancellation preserves the real host's typed rejection path.
    let cancelled = InvocationRequest::new(
        InvocationId::new("fixture-644-cancelled").expect("invocation"),
        CapabilityId::new("fixture-cycle-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-644").expect("work unit"),
        WorkScopeRef::new("fixture-scope-644").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        644,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 644/24
#[test]
fn bounded_malformed_lifted_input_fixtures_cannot_panic() {
    let (envelope, _, _, _) = completed_bundle();
    let valid = encode_request(&envelope).expect("encode");
    let valid_json = String::from_utf8(valid.clone()).expect("UTF-8");
    let mut battery: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0xFF, 0xFE, 0x00],
        b"not a module".to_vec(),
        valid[..valid.len() / 2].to_vec(),
        vec![0u8; 2_097_152],
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{}".to_vec(),
        b"\"just a string\"".to_vec(),
        format!("{{\"guest_unknown_field\":1,{}", &valid_json[1..]).into_bytes(),
        valid_json
            .replacen("\"abi_version\":1", "\"abi_version\":\"one\"", 1)
            .into_bytes(),
        format!("{{\"a\":{}}}", "{\"a\":".repeat(200)).into_bytes(),
    ];
    // A control-bearing owner still decodes; native rejects it without panic.
    let mut control = valid_json.clone();
    control = control.replacen("\"owner\":\"owner-1\"", "\"owner\":\"bad\\u0000owner\"", 1);
    battery.push(control.into_bytes());
    let mut transport_errors = 0;
    let mut typed_rejections = 0;
    for input in &battery {
        let result = run(input);
        match result {
            Err(_) => transport_errors += 1,
            Ok(bytes) => {
                // Decodable envelopes surface a typed error (zero-call
                // preflight rejections, or the single native mapping for the
                // control-bearing owner); none may trap or fake success.
                let response = decode_response(&bytes).expect("response decodes");
                assert!(response.step.is_none());
                assert!(response.error.is_some());
                typed_rejections += 1;
            }
        }
    }
    assert_eq!(transport_errors + typed_rejections, battery.len());
    assert!(transport_errors >= 12);
}

// WORK_UNIT_CASE: 644/25
#[test]
fn no_semantic_output_unavailable_from_native_input() {
    // Four success dispositions: guest carries exactly the native step.
    let (bundle_envelope, bundle_state, bundle_policy, observed) = completed_bundle();
    let native = step_dreamer_cycle(
        &bundle_state,
        std::slice::from_ref(&observed),
        &bundle_policy,
    )
    .unwrap();
    assert_eq!(
        handle_request_typed(&bundle_envelope).step.expect("step"),
        native
    );
    let idle = {
        let mut idle = bundle_state.clone();
        idle.pending.clear();
        idle.proposed_requests.clear();
        idle.seal().unwrap();
        idle
    };
    let idle_native = step_dreamer_cycle(&idle, &[], &bundle_policy).unwrap();
    assert_eq!(
        handle_request_typed(&guest_envelope(idle, Vec::new(), bundle_policy.clone()))
            .step
            .expect("idle"),
        idle_native
    );
    // Three error shapes: guest carries exactly the mapped native error.
    let stale_fence = {
        let mut stale = fence();
        stale.authority_epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_B).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
        stale
    };
    let stale_policy = policy(&stale_fence, "bundle_validation");
    let native_err = step_dreamer_cycle(
        &bundle_state,
        std::slice::from_ref(&observed),
        &stale_policy,
    )
    .unwrap_err();
    let response = handle_request_typed(&guest_envelope(
        bundle_state.clone(),
        vec![observed.clone()],
        stale_policy,
    ));
    assert!(response.step.is_none());
    assert_eq!(response.error, Some(GuestError::from(&native_err)));
    // Every emitted request reason is one of the two native inert strings.
    for scenario in [
        handle_request_typed(&bundle_envelope).step.expect("step"),
        idle_native,
    ] {
        for request in &scenario.requests {
            assert!(
                request.reason == INERT_AWAITING || request.reason == INERT_RECONCILE,
                "unexpected request reason {}",
                request.reason
            );
        }
    }
    let _ = native;
}

// WORK_UNIT_CASE: 644/26
#[test]
fn changed_inputs_invalidate_old_output() {
    let (envelope, current, current_policy, observed) = completed_bundle();
    let old_digest = handle_request_typed(&envelope)
        .step
        .expect("step")
        .transition_digest;
    // Bumped controller revision: same call shape, different output digest.
    let mut advanced_state = current.clone();
    advanced_state.controller_revision = 7;
    advanced_state.seal().unwrap();
    let new_digest = handle_request_typed(&guest_envelope(
        advanced_state,
        vec![observed.clone()],
        current_policy.clone(),
    ))
    .step
    .expect("advanced step")
    .transition_digest;
    assert_ne!(old_digest, new_digest);
    // Changed policy binding: the old output is unusable, an error results.
    let (drifted, drifted_policy) = retune(&current, &current_policy, |policy| {
        policy.phase_rules[0].owner = "owner-2".to_owned();
    });
    assert!(
        handle_request_typed(&guest_envelope(
            drifted,
            vec![observed.clone()],
            drifted_policy
        ))
        .step
        .is_none()
    );
    // Changed fence: the old output is unusable.
    let mut fenced = current.clone();
    fenced.job.state_fence.authority_epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_B).unwrap(),
        NonZeroU64::new(1).unwrap(),
    )
    .unwrap();
    fenced.seal().unwrap();
    assert!(
        handle_request_typed(&guest_envelope(
            fenced,
            vec![observed.clone()],
            current_policy
        ))
        .step
        .is_none()
    );
    // Changed envelope world: rejected before native, old digest never reissued.
    let mut foreign = envelope.clone();
    foreign.world = "dreamer-cycle-step".to_owned();
    let response = handle_request_typed(&foreign);
    assert_eq!(response.native_calls, 0);
    assert!(response.step.is_none());
}

// WORK_UNIT_CASE: 644/27
#[test]
fn no_durable_schedule_executed_effect_task_completion() {
    // Across all four success dispositions the guest represents only the pure
    // candidate: frozen bindings plus inert owner requests.
    let fence = fence();
    let current_job = job(&fence);
    let current_policy = policy(&fence, "bundle_validation");
    let request = pending(&current_policy, &current_job);
    let current = state(&current_policy, &current_job, request.clone());
    let success = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let completed = outcome(&request, success, OutcomeDisposition::Completed, false);
    let unknown = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Unknown {
                reason: "no observation yet".to_owned(),
            },
            None,
        ),
        OutcomeDisposition::Unknown,
        true,
    );
    let rejected = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Failure {
                code: ErrorCode::InvalidRequest,
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Rejected,
        false,
    );
    let mut idle = current.clone();
    idle.pending.clear();
    idle.seal().unwrap();
    let scenarios = [
        (current.clone(), vec![completed]),
        (idle, Vec::new()),
        (current.clone(), vec![rejected]),
        (current.clone(), vec![unknown]),
    ];
    let mut dispositions = BTreeSet::new();
    for (scenario_state, scenario_observed) in scenarios {
        let response = handle_request_typed(&guest_envelope(
            scenario_state.clone(),
            scenario_observed.clone(),
            current_policy.clone(),
        ));
        let step = response.step.clone().expect("scenario step");
        dispositions.insert(disposition_as_str(step.disposition));
        // Outcomes recorded are exactly the supplied observations, nothing more.
        assert_eq!(
            step.next_state.outcomes.len(),
            scenario_state.outcomes.len() + scenario_observed.len()
        );
        for observation in &scenario_observed {
            assert!(step.next_state.outcomes.contains(observation));
        }
        // Requests are inert and non-empty only while an owner owes observation.
        for inert in &step.requests {
            assert!(
                inert.reason == INERT_AWAITING || inert.reason == INERT_RECONCILE,
                "unexpected request reason {}",
                inert.reason
            );
            assert!(!inert.request_id.as_str().is_empty());
        }
        let json =
            String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
        for absent in [
            "DurableJob",
            "Finish",
            "scheduled",
            "task_completion",
            "OperationContinuationPermit",
            "new_authority_epoch",
            "cutover",
            "promotion",
        ] {
            assert!(!json.contains(absent), "response must not raise {absent}");
        }
    }
    assert_eq!(dispositions.len(), 4);
}
