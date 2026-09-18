#![allow(clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, ErrorCode, OperationId,
    PolicyRevision, ProductId, RequestId, ResourceGeneration, SourceId, StateFence, TaskId,
    TaskRevision, TransactionSequence, canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::curation::{ClassificationPayload, TargetEvidence};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetLimits, BudgetUsage, CurationFamily, CurationKind, CurationPayload,
    DreamJobAdmission, DreamJobInput, JobClass, Requester, RequesterOrigin, ScreenBinding,
    ScreenState, TargetDenominator, TypedCurationHandlerRequest, TypedCurationHandlerResult,
    ValidationReceipt,
};
use eliot_dreamer_cycle::{
    AckEvidence, CycleError, CyclePhase, CyclePolicy, DeliveryEvidence, DreamerCycleState,
    DurableCommand, DurableDisposition, DurableEvent, DurableJobState, DurablePhase, DurableStage,
    ExpectedArtifact, ExperimentKind, ObservedOutcome, OutcomeDisposition, PendingRequest,
    PhasePolicyRule, PlanHorizon, RequestKind, SampleLimits, StageEvidence, StageReconciled,
    StageRequest, StageResolution, StepDisposition, plan_cycle, sample_cycle, step_dreamer_cycle,
    step_dreamer_cycle_at, step_durable_job,
};
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, TaskBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};

use std::num::NonZeroU64;

const PAYLOAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DIGEST_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

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

fn job(fence: &StateFence) -> DreamJobAdmission {
    DreamJobAdmission {
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
        deadline_ms: None,
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

fn pending(policy: &CyclePolicy) -> PendingRequest {
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
        job_digest: sha256_hex(&canonical_json_bytes(&job(&policy.state_fence)).unwrap()),
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

fn set_phase(request: &mut PendingRequest, phase: CyclePhase, kind: RequestKind) {
    request.phase = phase;
    request.kind = kind;
}

fn set_phase_identity(request: &mut PendingRequest, tag: &str) {
    request.request_id = RequestId::new(format!("request-{tag}")).unwrap();
    request.operation_id = OperationId::new(format!("operation-{tag}")).unwrap();
    request.idempotency_key = format!("idem-{tag}");
    request.attempt_id = AgentAttemptId::new(format!("attempt-{tag}")).unwrap();
}

fn state(policy: &CyclePolicy, request: PendingRequest) -> DreamerCycleState {
    let mut state = DreamerCycleState {
        schema_version: 1,
        cycle_id: ArtifactId::new("cycle-1").unwrap(),
        job: job(&policy.state_fence),
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
    let request_digest = sha256_hex(&canonical_json_bytes(request).unwrap());
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
            sha256: request_digest,
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
    handler_result: Option<TypedCurationHandlerResult>,
    validation_receipt: Option<ValidationReceipt>,
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

fn propose_phase(
    state: &mut DreamerCycleState,
    policy: &CyclePolicy,
    phase: CyclePhase,
    kind: RequestKind,
) -> PendingRequest {
    state.policy_id = policy.policy_id.clone();
    state.policy_revision = policy.policy_revision;
    state.policy_digest.clone_from(&policy.canonical_digest);
    let mut request = pending(policy);
    let phase_tag = format!("{phase:?}").to_lowercase();
    set_phase_identity(&mut request, &phase_tag);
    set_phase(&mut request, phase, kind);
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

fn activate_phase(state: &DreamerCycleState, policy: &CyclePolicy) -> DreamerCycleState {
    let expected = state.proposed_requests.first().unwrap();
    let step = step_dreamer_cycle(state, &[], policy).unwrap();
    assert_eq!(step.disposition, StepDisposition::Advanced);
    assert_eq!(step.requests.len(), 1);
    assert_eq!(step.requests[0].request_id, expected.request_id);
    assert_eq!(step.requests[0].operation_id, expected.operation_id);
    assert_eq!(step.requests[0].kind, expected.kind);
    step.next_state
}

fn complete_plain_phase(
    mut state: DreamerCycleState,
    fence: &StateFence,
    phase: CyclePhase,
    kind: RequestKind,
    operation_kind: &str,
    proof: ProofCeiling,
) -> DreamerCycleState {
    let mut policy = policy_for_phase(fence, phase, operation_kind);
    policy.phase_rules[0].proof_ceiling = proof;
    policy.seal().unwrap();
    let request = propose_phase(&mut state, &policy, phase, kind);
    state = activate_phase(&state, &policy);
    let mut observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success { proof },
            request.predecessor_receipt_id.clone(),
        ),
        OutcomeDisposition::Completed,
        false,
    );
    observed.phase = phase;
    step_dreamer_cycle(&state, &[observed], &policy)
        .unwrap()
        .next_state
}

fn screen_binding(request: &PendingRequest) -> ScreenBinding {
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
        result_digest: DIGEST_D.to_owned(),
        item_digest: request.payload_digest.clone(),
    }
}

fn handler_request(
    state: &DreamerCycleState,
    screen: ScreenBinding,
) -> TypedCurationHandlerRequest {
    TypedCurationHandlerRequest {
        request_id: screen.request_id.to_string(),
        receipt_id: screen.receipt_id.to_string(),
        source_snapshot: screen.source_snapshot.clone(),
        source_revision: screen.source_revision.clone(),
        profile: screen.profile.clone(),
        kind: CurationKind::Classification,
        family: CurationFamily::Classification,
        job_id: state.job.canonical_id(),
        scope_id: state.job.scope_id.clone(),
        task_id: state.job.task_id.clone(),
        state_fence: state.job.state_fence.clone(),
        payload: CurationPayload::Classification(ClassificationPayload {
            label: "label".to_owned(),
            confidence_bps: 9000,
            target_evidence: TargetEvidence {
                targets: vec!["target".to_owned()],
                evidence_refs: vec!["evidence".to_owned()],
            },
        }),
        denominator: TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["target".to_owned()],
            expected_total: 1,
        },
        screen_binding: Some(screen),
    }
}

fn validation_receipt(state: &DreamerCycleState, request: &PendingRequest) -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_owned(),
        validator_policy: "a05-policy".to_owned(),
        job_id: state.job.canonical_id(),
        draft_digest: PAYLOAD.to_owned(),
        bundle_digest: request.bundle_digest.clone(),
        manifest_digest: state.job.frozen_manifest_digest.clone(),
        task_id: request.task_id.clone(),
        scope_id: request.scope_id.clone(),
        input_digest: DIGEST_B.to_owned(),
        output_digest: DIGEST_C.to_owned(),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: request.state_fence.clone(),
        preservation_digest: DIGEST_D.to_owned(),
        budget_digest: DIGEST_E.to_owned(),
    }
}

fn durable_input(fence: &StateFence, class: JobClass, deadline_ms: i64) -> DreamJobInput {
    DreamJobInput {
        job_id: "job-1".to_owned(),
        job_class: class,
        exact_question: "question".to_owned(),
        requester: "tester".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: Some("task-1".to_owned()),
        state_fence: fence.clone(),
        evidence_handles: Vec::new(),
        memory_handles: Vec::new(),
        architecture_handles: Vec::new(),
        implementation_handles: Vec::new(),
        conformance_handles: Vec::new(),
        conflicts_and_unknowns: Vec::new(),
        privacy_profile: "local_only".to_owned(),
        allowed_tools: vec!["tool-1".to_owned()],
        allowed_model_routes: vec!["route-1".to_owned()],
        budget_units: 1000,
        deadline_ms,
        output_schema: "schema".to_owned(),
        forbidden_effects: Vec::new(),
    }
}

fn durable_admit_orientation() -> (DurableJobState, StateFence) {
    let fence = fence();
    let input = durable_input(&fence, JobClass::Orientation, 600_000);
    let state = DurableJobState::admit(&input, PAYLOAD, None).unwrap();
    (state, fence)
}

fn durable_op(tag: &str) -> OperationId {
    OperationId::new(format!("durable-op-{tag}")).unwrap()
}

fn durable_stage_request(stage: DurableStage, tag: &str) -> StageRequest {
    StageRequest {
        stage,
        operation_id: durable_op(tag),
        idempotency_key: format!("durable-idem-{tag}"),
    }
}

fn durable_evidence(stage: DurableStage, tag: &str) -> StageEvidence {
    StageEvidence {
        stage,
        operation_id: durable_op(tag),
        cycle_receipt_digest: PAYLOAD.to_owned(),
    }
}

#[allow(clippy::similar_names, clippy::needless_pass_by_value)]
fn durable_request_and_ready(
    current_state: DurableJobState,
    stage: DurableStage,
    tag: &str,
) -> DurableJobState {
    let request = durable_stage_request(stage, tag);
    let step = step_durable_job(&current_state, &DurableEvent::RequestStage(request)).unwrap();
    assert_eq!(step.disposition, DurableDisposition::Advanced);
    let evidence = durable_evidence(stage, tag);
    let done = step_durable_job(&step.next_state, &DurableEvent::StageReady(evidence)).unwrap();
    assert_eq!(done.disposition, DurableDisposition::Advanced);
    done.next_state
}

fn durable_drive_to_committed() -> DurableJobState {
    let (mut current, _) = durable_admit_orientation();
    current = durable_request_and_ready(current, DurableStage::Bundle, "bundle");
    let screen_request = durable_stage_request(DurableStage::Screen, "screen");
    let screen_step =
        step_durable_job(&current, &DurableEvent::RequestStage(screen_request)).unwrap();
    assert_eq!(screen_step.disposition, DurableDisposition::Advanced);
    assert_eq!(
        screen_step.next_state.phase,
        DurablePhase::ScreenNotApplicable
    );
    current = screen_step.next_state;
    current = durable_request_and_ready(current, DurableStage::Model, "model");
    current = durable_request_and_ready(current, DurableStage::Grounding, "grounding");
    current = durable_request_and_ready(current, DurableStage::Validation, "validation");
    current = durable_request_and_ready(current, DurableStage::Dispatch, "dispatch");
    current = durable_request_and_ready(current, DurableStage::Submission, "submission");
    assert_eq!(current.phase, DurablePhase::SubmissionCommitted);
    current
}

fn generic_for(_request: &PendingRequest, disposition: OutcomeDisposition) -> ReceiptDisposition {
    match disposition {
        OutcomeDisposition::Accepted
        | OutcomeDisposition::Completed
        | OutcomeDisposition::NotAttempted
        | OutcomeDisposition::FailedBeforeEffect => ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        OutcomeDisposition::Partial => ReceiptDisposition::Partial {
            proof: ProofCeiling::Observation,
            unresolved: vec!["gap".to_owned()],
        },
        OutcomeDisposition::Rejected
        | OutcomeDisposition::Unavailable
        | OutcomeDisposition::Stale
        | OutcomeDisposition::Expired
        | OutcomeDisposition::Superseded => ReceiptDisposition::Failure {
            code: ErrorCode::Unavailable,
            proof: ProofCeiling::Observation,
        },
        OutcomeDisposition::Unknown => ReceiptDisposition::Unknown {
            reason: "no observation".to_owned(),
        },
        OutcomeDisposition::Cancelled => ReceiptDisposition::Cancelled {
            reason: "cancelled".to_owned(),
        },
    }
}

// WORK_UNIT_CASE: 806/1
#[test]
fn controller_vocabulary_is_closed_without_duplicate_durable_lifecycle() {
    let phases = [
        CyclePhase::Validated,
        CyclePhase::BundleValidated,
        CyclePhase::Screened,
        CyclePhase::ModelObserved,
        CyclePhase::GroundingValidated,
        CyclePhase::CommonValidated,
        CyclePhase::HandlerObserved,
        CyclePhase::IntrinsicOutputChecked,
        CyclePhase::ExternalAdmission,
        CyclePhase::ClosureObserved,
    ];
    for window in phases.windows(2) {
        assert_eq!(window[0].next(), Some(window[1]));
    }
    assert_eq!(CyclePhase::ClosureObserved.next(), None);
    let dispositions = [
        OutcomeDisposition::Accepted,
        OutcomeDisposition::Rejected,
        OutcomeDisposition::NotAttempted,
        OutcomeDisposition::Completed,
        OutcomeDisposition::Partial,
        OutcomeDisposition::FailedBeforeEffect,
        OutcomeDisposition::Unknown,
        OutcomeDisposition::Cancelled,
        OutcomeDisposition::Expired,
        OutcomeDisposition::Superseded,
        OutcomeDisposition::Unavailable,
        OutcomeDisposition::Stale,
    ];
    assert_eq!(dispositions.len(), 12);
    let kinds = [
        RequestKind::BundleValidation,
        RequestKind::CurationScreen,
        RequestKind::ModelInvocation,
        RequestKind::Grounding,
        RequestKind::CommonValidation,
        RequestKind::SemanticHandler,
        RequestKind::IntrinsicOutput,
        RequestKind::ExternalAdmission,
        RequestKind::Closure,
        RequestKind::EffectReconciliation,
        RequestKind::Clarification,
    ];
    assert_eq!(kinds.len(), 11);
    let steps = [
        StepDisposition::Advanced,
        StepDisposition::Replayed,
        StepDisposition::ReconciliationRequired,
        StepDisposition::Blocked,
        StepDisposition::Terminal,
    ];
    assert_eq!(steps.len(), 5);
    assert!(DurableStage::screen_applies(JobClass::Curation));
    assert!(!DurableStage::screen_applies(JobClass::Orientation));
    let fence = fence();
    let policy = policy(&fence, "op-kind");
    let request = pending(&policy);
    let current = state(&policy, request);
    let sample = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 8 }).unwrap();
    let plan = plan_cycle(&sample, &current, &policy, None).unwrap();
    let encoded = String::from_utf8(canonical_json_bytes(&plan).unwrap()).unwrap();
    for forbidden in [
        "DurableJob",
        "WakeIntent",
        "RuntimeLease",
        "route_reservation",
        "self-enqueue",
    ] {
        assert!(!encoded.contains(forbidden), "forbidden {forbidden}");
    }
    let state_bytes = String::from_utf8(canonical_json_bytes(&current).unwrap()).unwrap();
    assert!(!state_bytes.contains("DurableJob"));
}

// WORK_UNIT_CASE: 806/2
#[test]
fn legal_adjacent_phases_follow_mandated_order() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let mut current = state(&policy, request.clone());
    let bundle_receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let step = step_dreamer_cycle(
        &current,
        &[outcome(
            &request,
            bundle_receipt,
            OutcomeDisposition::Completed,
            false,
        )],
        &policy,
    )
    .unwrap();
    assert_eq!(step.disposition, StepDisposition::Advanced);
    assert_eq!(step.next_state.phase, CyclePhase::BundleValidated);
    assert!(step.next_state.pending.is_empty());
    current = step.next_state;
    let screen_policy = policy_for_phase(&fence, CyclePhase::Screened, "curation_screen");
    let screen_request = propose_phase(
        &mut current,
        &screen_policy,
        CyclePhase::Screened,
        RequestKind::CurationScreen,
    );
    current = activate_phase(&current, &screen_policy);
    let screen = screen_binding(&screen_request);
    let screen_digest = sha256_hex(&canonical_json_bytes(&screen).unwrap());
    let screen_receipt = receipt_with_artifacts(
        &screen_request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        screen_request.predecessor_receipt_id.clone(),
        &[
            ("screen-result", &screen.result_digest),
            ("screen-evidence", &screen_digest),
        ],
    );
    let screen_outcome = outcome_at(
        &screen_request,
        screen_receipt,
        CyclePhase::Screened,
        OutcomeDisposition::Completed,
        false,
        vec![
            ArtifactId::new("payload-1").unwrap(),
            ArtifactId::new("screen-result").unwrap(),
            ArtifactId::new("screen-evidence").unwrap(),
        ],
        None,
        None,
        Some(screen.clone()),
    );
    current = step_dreamer_cycle(&current, &[screen_outcome], &screen_policy)
        .unwrap()
        .next_state;
    current = complete_plain_phase(
        current,
        &fence,
        CyclePhase::ModelObserved,
        RequestKind::ModelInvocation,
        "model_invocation",
        ProofCeiling::Observation,
    );
    current = complete_plain_phase(
        current,
        &fence,
        CyclePhase::GroundingValidated,
        RequestKind::Grounding,
        "grounding",
        ProofCeiling::Observation,
    );
    let common_policy = policy_for_phase(&fence, CyclePhase::CommonValidated, "common_validation");
    let common_request = propose_phase(
        &mut current,
        &common_policy,
        CyclePhase::CommonValidated,
        RequestKind::CommonValidation,
    );
    current = activate_phase(&current, &common_policy);
    let validation = validation_receipt(&current, &common_request);
    let validation_input = validation.input_digest.clone();
    let validation_output = validation.output_digest.clone();
    let validation_digest = sha256_hex(&canonical_json_bytes(&validation).unwrap());
    let common_receipt = receipt_with_artifacts(
        &common_request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        common_request.predecessor_receipt_id.clone(),
        &[
            ("validation-input", &validation_input),
            ("validation-output", &validation_output),
            ("validation-evidence", &validation_digest),
        ],
    );
    let common_outcome = outcome_at(
        &common_request,
        common_receipt,
        CyclePhase::CommonValidated,
        OutcomeDisposition::Completed,
        false,
        vec![
            ArtifactId::new("payload-1").unwrap(),
            ArtifactId::new("validation-input").unwrap(),
            ArtifactId::new("validation-output").unwrap(),
            ArtifactId::new("validation-evidence").unwrap(),
        ],
        None,
        Some(validation),
        None,
    );
    current = step_dreamer_cycle(&current, &[common_outcome], &common_policy)
        .unwrap()
        .next_state;
    let mut handler_policy =
        policy_for_phase(&fence, CyclePhase::HandlerObserved, "semantic_handler");
    handler_policy.phase_rules[0].proof_ceiling = ProofCeiling::CandidateArtifact;
    handler_policy.seal().unwrap();
    let mut handler_pending = propose_phase(
        &mut current,
        &handler_policy,
        CyclePhase::HandlerObserved,
        RequestKind::SemanticHandler,
    );
    let typed_request = handler_request(&current, screen);
    handler_pending.handler_request = Some(typed_request.clone());
    current.proposed_requests = vec![handler_pending.clone()];
    current.seal().unwrap();
    current = activate_phase(&current, &handler_policy);
    let typed_request_digest = sha256_hex(&canonical_json_bytes(&typed_request).unwrap());
    let typed_result = TypedCurationHandlerResult {
        request_id: typed_request.request_id.clone(),
        kind: typed_request.kind,
        family: typed_request.family,
        disposition: eliot_dreamer_contracts::CandidateDisposition::Candidate,
        handler_id: handler_pending.owner.clone(),
        request_digest: typed_request_digest,
        result_digest: DIGEST_E.to_owned(),
    };
    let typed_result_digest = sha256_hex(&canonical_json_bytes(&typed_result).unwrap());
    let handler_receipt = receipt_with_artifacts(
        &handler_pending,
        ReceiptDisposition::Success {
            proof: ProofCeiling::CandidateArtifact,
        },
        handler_pending.predecessor_receipt_id.clone(),
        &[
            ("handler-result", &typed_result.result_digest),
            ("handler-evidence", &typed_result_digest),
        ],
    );
    let handler_outcome = outcome_at(
        &handler_pending,
        handler_receipt,
        CyclePhase::HandlerObserved,
        OutcomeDisposition::Completed,
        false,
        vec![
            ArtifactId::new("payload-1").unwrap(),
            ArtifactId::new("handler-result").unwrap(),
            ArtifactId::new("handler-evidence").unwrap(),
        ],
        Some(typed_result),
        None,
        None,
    );
    current = step_dreamer_cycle(&current, &[handler_outcome], &handler_policy)
        .unwrap()
        .next_state;
    current = complete_plain_phase(
        current,
        &fence,
        CyclePhase::IntrinsicOutputChecked,
        RequestKind::IntrinsicOutput,
        "intrinsic_output",
        ProofCeiling::Observation,
    );
    current = complete_plain_phase(
        current,
        &fence,
        CyclePhase::ExternalAdmission,
        RequestKind::ExternalAdmission,
        "external_admission",
        ProofCeiling::CandidateArtifact,
    );
    let mut closure_policy = policy_for_phase(&fence, CyclePhase::ClosureObserved, "closure");
    closure_policy.phase_rules[0].effect = EffectClass::ExternalEffect;
    closure_policy.phase_rules[0].proof_ceiling = ProofCeiling::ObservedExternalEffect;
    closure_policy.seal().unwrap();
    let mut closure_request = propose_phase(
        &mut current,
        &closure_policy,
        CyclePhase::ClosureObserved,
        RequestKind::Closure,
    );
    closure_request.effect = EffectClass::ExternalEffect;
    closure_request.proof_ceiling = ProofCeiling::ObservedExternalEffect;
    closure_request.predecessor_receipt_id = current
        .outcomes
        .last()
        .map(|outcome| outcome.receipt.identity.receipt_id.clone());
    current.proposed_requests = vec![closure_request.clone()];
    current.seal().unwrap();
    current = activate_phase(&current, &closure_policy);
    let mut closure_outcome = outcome(
        &closure_request,
        receipt(
            &closure_request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::ObservedExternalEffect,
            },
            closure_request.predecessor_receipt_id.clone(),
        ),
        OutcomeDisposition::Completed,
        false,
    );
    closure_outcome.phase = CyclePhase::ClosureObserved;
    let closure_step = step_dreamer_cycle(&current, &[closure_outcome], &closure_policy).unwrap();
    assert_eq!(closure_step.disposition, StepDisposition::Terminal);
    assert_eq!(closure_step.next_state.phase, CyclePhase::ClosureObserved);
}

// WORK_UNIT_CASE: 806/3
#[test]
fn illegal_skip_regression_cross_job_and_post_handler_are_rejected() {
    let fence = fence();
    let bundle_policy = policy(&fence, "bundle_validation");
    let mut skipped = pending(&bundle_policy);
    set_phase(
        &mut skipped,
        CyclePhase::Screened,
        RequestKind::CurationScreen,
    );
    let mut skipped_state = state(&bundle_policy, skipped.clone());
    skipped_state.phase = CyclePhase::Validated;
    skipped_state.seal().unwrap();
    let mut skipped_outcome = outcome(
        &skipped,
        receipt(
            &skipped,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    skipped_outcome.phase = CyclePhase::Screened;
    assert!(step_dreamer_cycle(&skipped_state, &[skipped_outcome], &bundle_policy).is_err());
    let mut regressed = pending(&bundle_policy);
    let mut regressed_state = state(&bundle_policy, regressed.clone());
    regressed_state.phase = CyclePhase::GroundingValidated;
    regressed_state.seal().unwrap();
    regressed.phase = CyclePhase::BundleValidated;
    let regressed_outcome = outcome(
        &regressed,
        receipt(
            &regressed,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    assert!(step_dreamer_cycle(&regressed_state, &[regressed_outcome], &bundle_policy).is_err());
    let common_policy = policy_for_phase(&fence, CyclePhase::CommonValidated, "common_validation");
    let mut late = pending(&common_policy);
    set_phase(
        &mut late,
        CyclePhase::CommonValidated,
        RequestKind::CommonValidation,
    );
    let mut late_state = state(&common_policy, late.clone());
    late_state.phase = CyclePhase::HandlerObserved;
    late_state.seal().unwrap();
    let mut late_outcome = outcome(
        &late,
        receipt(
            &late,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    late_outcome.phase = CyclePhase::CommonValidated;
    assert!(step_dreamer_cycle(&late_state, &[late_outcome], &common_policy).is_err());
    let handler_policy = policy_for_phase(&fence, CyclePhase::HandlerObserved, "semantic_handler");
    let mut foreign = pending(&handler_policy);
    set_phase(
        &mut foreign,
        CyclePhase::HandlerObserved,
        RequestKind::SemanticHandler,
    );
    foreign.task_id = "foreign-task".to_owned();
    let foreign_state = state(&handler_policy, foreign);
    assert!(step_dreamer_cycle(&foreign_state, &[], &handler_policy).is_err());
}

// WORK_UNIT_CASE: 806/4
#[test]
fn exact_replay_is_idempotent_while_changed_same_id_conflicts() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let first = step_dreamer_cycle(&current, std::slice::from_ref(&observed), &policy).unwrap();
    let mut replay_state = first.next_state.clone();
    replay_state.proposed_requests.push(request.clone());
    replay_state.seal().unwrap();
    let replay =
        step_dreamer_cycle(&replay_state, std::slice::from_ref(&observed), &policy).unwrap();
    assert_eq!(replay.disposition, StepDisposition::Replayed);
    assert_eq!(replay.next_state, replay_state);
    let timeless = replay.transition_digest.clone();
    let injected = step_dreamer_cycle_at(
        &replay_state,
        std::slice::from_ref(&observed),
        &policy,
        Some(1),
    )
    .unwrap();
    assert_eq!(injected.disposition, StepDisposition::Replayed);
    assert_eq!(injected.transition_digest, timeless);
    let mut changed = observed.clone();
    changed.payload_digest = DIGEST_B.to_owned();
    assert!(step_dreamer_cycle(&first.next_state, &[changed], &policy).is_err());
}

// WORK_UNIT_CASE: 806/5
#[test]
fn outcome_without_exact_pending_request_cannot_advance() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let mut other = request.clone();
    other.request_id = RequestId::new("request-2").unwrap();
    let result = step_dreamer_cycle(
        &current,
        &[outcome(
            &other,
            receipt(
                &other,
                ReceiptDisposition::Success {
                    proof: ProofCeiling::Observation,
                },
                None,
            ),
            OutcomeDisposition::Completed,
            false,
        )],
        &policy,
    );
    assert!(matches!(
        result,
        Err(CycleError::IncompleteOutcome("outcome.pending_request"))
    ));
    assert_eq!(current.phase, CyclePhase::Validated);
}

// WORK_UNIT_CASE: 806/6
#[test]
fn wrong_owner_task_attempt_scope_or_fence_is_rejected() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let mut bad_owner = pending(&policy);
    bad_owner.owner = "foreign-owner".to_owned();
    assert!(step_dreamer_cycle(&state(&policy, bad_owner), &[], &policy).is_err());
    let mut bad_task = pending(&policy);
    bad_task.task_id = "foreign-task".to_owned();
    assert!(step_dreamer_cycle(&state(&policy, bad_task), &[], &policy).is_err());
    let mut bad_scope = pending(&policy);
    bad_scope.scope_id = "foreign-scope".to_owned();
    assert!(step_dreamer_cycle(&state(&policy, bad_scope), &[], &policy).is_err());
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let accepted = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Accepted,
        false,
    );
    let waiting = step_dreamer_cycle(&current, &[accepted], &policy).unwrap();
    let mut tampered = waiting.next_state.clone();
    tampered.pending[0].attempt_id = AgentAttemptId::new("attempt-foreign").unwrap();
    tampered.seal().unwrap();
    assert!(step_dreamer_cycle(&tampered, &[], &policy).is_err());
    let mut bad_fence = pending(&policy);
    let mut foreign_fence = fence.clone();
    foreign_fence.resource_generation = ResourceGeneration::new(99).unwrap();
    bad_fence.state_fence = foreign_fence;
    assert!(step_dreamer_cycle(&state(&policy, bad_fence), &[], &policy).is_err());
}

// WORK_UNIT_CASE: 806/7
#[test]
fn every_outcome_disposition_has_exact_controller_meaning() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let cases: &[(OutcomeDisposition, StepDisposition, bool)] = &[
        (
            OutcomeDisposition::Completed,
            StepDisposition::Advanced,
            true,
        ),
        (
            OutcomeDisposition::Accepted,
            StepDisposition::ReconciliationRequired,
            true,
        ),
        (
            OutcomeDisposition::Unknown,
            StepDisposition::ReconciliationRequired,
            true,
        ),
        (OutcomeDisposition::Partial, StepDisposition::Blocked, true),
        (OutcomeDisposition::Rejected, StepDisposition::Blocked, true),
        (
            OutcomeDisposition::Unavailable,
            StepDisposition::Blocked,
            true,
        ),
        (OutcomeDisposition::Stale, StepDisposition::Blocked, true),
        (OutcomeDisposition::Expired, StepDisposition::Blocked, true),
        (
            OutcomeDisposition::Superseded,
            StepDisposition::Blocked,
            true,
        ),
        (
            OutcomeDisposition::Cancelled,
            StepDisposition::Blocked,
            true,
        ),
    ];
    for (disposition, expected, _) in cases {
        let request = pending(&policy);
        let current = state(&policy, request.clone());
        let observed = outcome(
            &request,
            receipt(&request, generic_for(&request, *disposition), None),
            *disposition,
            *disposition == OutcomeDisposition::Unknown,
        );
        let step = step_dreamer_cycle(&current, &[observed], &policy).unwrap();
        assert_eq!(step.disposition, *expected, "for {disposition:?}");
    }
    for disposition in [
        OutcomeDisposition::NotAttempted,
        OutcomeDisposition::FailedBeforeEffect,
    ] {
        let request = pending(&policy);
        let current = state(&policy, request.clone());
        let observed = outcome(
            &request,
            receipt(&request, generic_for(&request, disposition), None),
            disposition,
            false,
        );
        assert!(
            step_dreamer_cycle(&current, &[observed], &policy).is_err(),
            "for {disposition:?}"
        );
    }
}

// WORK_UNIT_CASE: 806/8
#[test]
fn possible_effect_stays_same_operation_reconciliation() {
    let fence = fence();
    let screen_policy = policy_for_phase(&fence, CyclePhase::Screened, "curation_screen");
    let mut screen_request = pending(&screen_policy);
    set_phase_identity(&mut screen_request, "screened");
    let screen = screen_binding(&screen_request);
    let screen_receipt = receipt(
        &screen_request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let screen_outcome = outcome_at(
        &screen_request,
        screen_receipt.clone(),
        CyclePhase::Screened,
        OutcomeDisposition::Completed,
        false,
        Vec::new(),
        None,
        None,
        Some(screen.clone()),
    );
    let policy = policy_for_phase(&fence, CyclePhase::HandlerObserved, "semantic_handler");
    let mut request = pending(&policy);
    set_phase(
        &mut request,
        CyclePhase::HandlerObserved,
        RequestKind::SemanticHandler,
    );
    request.predecessor_receipt_id = Some(screen_receipt.identity.receipt_id.clone());
    request.handler_request = Some(handler_request(&state(&policy, request.clone()), screen));
    let mut current = state(&policy, request.clone());
    current.phase = CyclePhase::CommonValidated;
    current.outcomes = vec![screen_outcome];
    current.seal().unwrap();
    let unknown_receipt = receipt(
        &request,
        ReceiptDisposition::Unknown {
            reason: "no observation".to_owned(),
        },
        request.predecessor_receipt_id.clone(),
    );
    let mut unknown = outcome(
        &request,
        unknown_receipt.clone(),
        OutcomeDisposition::Unknown,
        true,
    );
    unknown.phase = CyclePhase::HandlerObserved;
    let waiting = step_dreamer_cycle(&current, &[unknown], &policy).unwrap();
    assert_eq!(waiting.disposition, StepDisposition::ReconciliationRequired);
    assert_eq!(
        waiting.next_state.pending[0].operation_id,
        request.operation_id
    );
    assert_eq!(waiting.requests[0].kind, RequestKind::EffectReconciliation);
    assert_eq!(
        waiting.requests[0].predecessor_receipt_id,
        Some(unknown_receipt.identity.receipt_id.clone())
    );
    let typed_request = request.handler_request.as_ref().unwrap();
    let typed_result = TypedCurationHandlerResult {
        request_id: typed_request.request_id.clone(),
        kind: typed_request.kind,
        family: typed_request.family,
        disposition: eliot_dreamer_contracts::CandidateDisposition::Candidate,
        handler_id: request.owner.clone(),
        request_digest: sha256_hex(&canonical_json_bytes(typed_request).unwrap()),
        result_digest: DIGEST_E.to_owned(),
    };
    let result_digest = typed_result.result_digest.clone();
    let full_result_digest = sha256_hex(&canonical_json_bytes(&typed_result).unwrap());
    let resolved = outcome_at(
        &request,
        receipt_with_artifacts(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            Some(unknown_receipt.identity.receipt_id.clone()),
            &[
                ("handler-result", &result_digest),
                ("handler-evidence", &full_result_digest),
            ],
        ),
        CyclePhase::HandlerObserved,
        OutcomeDisposition::Completed,
        false,
        vec![
            ArtifactId::new("payload-1").unwrap(),
            ArtifactId::new("handler-result").unwrap(),
            ArtifactId::new("handler-evidence").unwrap(),
        ],
        Some(typed_result),
        None,
        None,
    );
    let done = step_dreamer_cycle(&waiting.next_state, &[resolved], &policy).unwrap();
    assert_eq!(done.disposition, StepDisposition::Advanced);
    assert!(done.next_state.pending.is_empty());
}

// WORK_UNIT_CASE: 806/9
#[test]
fn missing_observation_remains_unknown_without_progress() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request);
    let idle = step_dreamer_cycle(&current, &[], &policy).unwrap();
    assert_eq!(idle.disposition, StepDisposition::Replayed);
    assert_eq!(idle.next_state.phase, CyclePhase::Validated);
    assert_eq!(idle.next_state.pending.len(), 1);
    assert_eq!(idle.requests.len(), 1);
    assert_eq!(idle.next_state.outcomes.len(), 0);
    let (durable, _) = durable_admit_orientation();
    let restart = step_durable_job(
        &durable,
        &DurableEvent::RestartObserved(eliot_dreamer_cycle::RestartEvidence {
            fence: durable.fence.clone(),
            revision: durable.revision,
        }),
    )
    .unwrap();
    assert_eq!(restart.disposition, DurableDisposition::Advanced);
    assert_eq!(restart.next_state.phase, DurablePhase::Admitted);
}

// WORK_UNIT_CASE: 806/10
#[test]
fn at_most_one_transition_per_call() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let first = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let second = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Unknown {
                reason: "second".to_owned(),
            },
            None,
        ),
        OutcomeDisposition::Unknown,
        true,
    );
    assert!(step_dreamer_cycle(&current, &[first, second], &policy).is_err());
    let (durable, _) = durable_admit_orientation();
    let transition = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap();
    assert!(transition.commands.len() <= 1);
    assert_eq!(transition.disposition, DurableDisposition::Advanced);
}

// WORK_UNIT_CASE: 806/11
#[test]
fn no_recursion_or_self_scheduling() {
    let fence = fence();
    let policy = policy(&fence, "op-kind");
    let request = pending(&policy);
    let current = state(&policy, request);
    let sample = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 8 }).unwrap();
    let plan = plan_cycle(&sample, &current, &policy, None).unwrap();
    assert_eq!(plan.horizon, PlanHorizon::OneCycle);
    assert_eq!(plan.to_phase, plan.from_phase.next().unwrap());
    assert!(plan.experiments.len() <= 1);
    for experiment in &plan.experiments {
        assert!(matches!(
            experiment.kind,
            ExperimentKind::ClarificationProbe | ExperimentKind::ReconciliationProbe
        ));
    }
    let encoded = String::from_utf8(canonical_json_bytes(&plan).unwrap()).unwrap();
    for forbidden in ["schedule", "WakeIntent", "RuntimeLease", "self-enqueue"] {
        assert!(!encoded.contains(forbidden));
    }
    let (durable, _) = durable_admit_orientation();
    let requested = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap()
    .next_state;
    let restart = step_durable_job(
        &requested,
        &DurableEvent::RestartObserved(eliot_dreamer_cycle::RestartEvidence {
            fence: requested.fence.clone(),
            revision: requested.revision,
        }),
    )
    .unwrap();
    assert_eq!(
        restart.disposition,
        DurableDisposition::ReconciliationRequired
    );
    assert!(matches!(
        restart.commands[0],
        DurableCommand::ReconcileOperation(_)
    ));
    assert!(
        step_durable_job(
            &restart.next_state,
            &DurableEvent::RequestStage(durable_stage_request(DurableStage::Grounding, "other")),
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 806/12
#[test]
fn inert_requests_grant_no_execution_lease_or_authority() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request);
    let idle = step_dreamer_cycle(&current, &[], &policy).unwrap();
    assert_eq!(idle.requests.len(), 1);
    let inert = &idle.requests[0];
    assert_eq!(
        inert.reason,
        "awaiting an externally supplied owner observation"
    );
    let encoded = String::from_utf8(canonical_json_bytes(inert).unwrap()).unwrap();
    for forbidden in ["lease", "authority_grant", "execute", "schedule", "Finish"] {
        assert!(!encoded.contains(forbidden), "forbidden {forbidden}");
    }
    let (durable, _) = durable_admit_orientation();
    let transition = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap();
    assert_eq!(transition.commands.len(), 1);
    match &transition.commands[0] {
        DurableCommand::AdvanceStage(command) => {
            assert_eq!(command.stage, DurableStage::Bundle);
            assert_eq!(command.job_digest, durable.job_digest);
        }
        other => panic!("unexpected durable command {other:?}"),
    }
    let encoded = String::from_utf8(canonical_json_bytes(&transition.commands).unwrap()).unwrap();
    assert!(!encoded.contains("lease"));
}

// WORK_UNIT_CASE: 806/13
#[test]
fn terminal_requires_exact_external_evidence() {
    let fence = fence();
    let mut closure_policy = policy_for_phase(&fence, CyclePhase::ClosureObserved, "closure");
    closure_policy.phase_rules[0].effect = EffectClass::ExternalEffect;
    closure_policy.phase_rules[0].proof_ceiling = ProofCeiling::ObservedExternalEffect;
    closure_policy.seal().unwrap();
    let mut bad_state = DreamerCycleState {
        schema_version: 1,
        cycle_id: ArtifactId::new("cycle-1").unwrap(),
        job: job(&fence),
        bundle_digest: PAYLOAD.to_owned(),
        policy_id: closure_policy.policy_id.clone(),
        policy_revision: closure_policy.policy_revision,
        policy_digest: closure_policy.canonical_digest.clone(),
        phase: CyclePhase::ExternalAdmission,
        controller_revision: 0,
        predecessor_digest: None,
        pending: Vec::new(),
        proposed_requests: Vec::new(),
        outcomes: Vec::new(),
        frontier: Vec::new(),
        budget_usage: BudgetUsage::default(),
        cancellation_requested: false,
        canonical_digest: String::new(),
    };
    let mut bad_request = pending(&closure_policy);
    set_phase(
        &mut bad_request,
        CyclePhase::ClosureObserved,
        RequestKind::Closure,
    );
    bad_request.effect = EffectClass::Read;
    bad_request.proof_ceiling = ProofCeiling::Observation;
    bad_state.pending = vec![bad_request.clone()];
    bad_state.seal().unwrap();
    let bad_outcome = outcome_at(
        &bad_request,
        receipt(
            &bad_request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        CyclePhase::ClosureObserved,
        OutcomeDisposition::Completed,
        false,
        Vec::new(),
        None,
        None,
        None,
    );
    assert!(step_dreamer_cycle(&bad_state, &[bad_outcome], &closure_policy).is_err());
    let committed = durable_drive_to_committed();
    let delivered = step_durable_job(
        &committed,
        &DurableEvent::Delivered(DeliveryEvidence {
            delivery_digest: PAYLOAD.to_owned(),
        }),
    )
    .unwrap();
    assert_eq!(delivered.next_state.phase, DurablePhase::Delivery);
    let acknowledged = step_durable_job(
        &delivered.next_state,
        &DurableEvent::Acknowledged(AckEvidence {
            ack_digest: PAYLOAD.to_owned(),
        }),
    )
    .unwrap();
    assert_eq!(acknowledged.disposition, DurableDisposition::Terminal);
    assert_eq!(acknowledged.next_state.phase, DurablePhase::Acknowledged);
    let replay = step_durable_job(
        &acknowledged.next_state,
        &DurableEvent::Acknowledged(AckEvidence {
            ack_digest: PAYLOAD.to_owned(),
        }),
    )
    .unwrap();
    assert_eq!(replay.disposition, DurableDisposition::Replayed);
}

// WORK_UNIT_CASE: 806/14
#[test]
fn candidate_packet_or_provider_response_cannot_self_finish() {
    let fence = fence();
    let common_policy = policy_for_phase(&fence, CyclePhase::CommonValidated, "common_validation");
    let mut request = pending(&common_policy);
    set_phase(
        &mut request,
        CyclePhase::CommonValidated,
        RequestKind::CommonValidation,
    );
    let mut current = state(&common_policy, request.clone());
    current.phase = CyclePhase::GroundingValidated;
    current.seal().unwrap();
    let mut validation = validation_receipt(&current, &request);
    validation.terminal_disposition = "rejected".to_owned();
    let validation_input = validation.input_digest.clone();
    let validation_output = validation.output_digest.clone();
    let validation_digest = sha256_hex(&canonical_json_bytes(&validation).unwrap());
    let common_receipt = receipt_with_artifacts(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        request.predecessor_receipt_id.clone(),
        &[
            ("validation-input", &validation_input),
            ("validation-output", &validation_output),
            ("validation-evidence", &validation_digest),
        ],
    );
    let common_outcome = outcome_at(
        &request,
        common_receipt,
        CyclePhase::CommonValidated,
        OutcomeDisposition::Completed,
        false,
        vec![
            ArtifactId::new("payload-1").unwrap(),
            ArtifactId::new("validation-input").unwrap(),
            ArtifactId::new("validation-output").unwrap(),
            ArtifactId::new("validation-evidence").unwrap(),
        ],
        None,
        Some(validation),
        None,
    );
    let step = step_dreamer_cycle(&current, &[common_outcome], &common_policy).unwrap();
    assert_eq!(step.disposition, StepDisposition::Blocked);
    assert_eq!(step.next_state.phase, CyclePhase::GroundingValidated);
    let (durable, _) = durable_admit_orientation();
    let requested = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap()
    .next_state;
    let mut foreign = durable_evidence(DurableStage::Bundle, "bundle");
    foreign.operation_id = durable_op("foreign");
    assert!(step_durable_job(&requested, &DurableEvent::StageReady(foreign),).is_err());
    assert!(
        step_durable_job(
            &requested,
            &DurableEvent::StageUnknown(durable_evidence(DurableStage::Bundle, "bundle")),
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 806/15
#[test]
fn complete_and_partial_denominators_are_explicit() {
    let fence = fence();
    let policy = policy(&fence, "op-kind");
    let first = pending(&policy);
    let mut current = state(&policy, first);
    for tag in ["b", "c"] {
        let mut extra = pending(&policy);
        set_phase_identity(&mut extra, tag);
        current.pending.push(extra);
    }
    current.seal().unwrap();
    let partial = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 2 }).unwrap();
    assert_eq!(partial.denominator.pending_total, 3);
    assert_eq!(partial.sampled_pending.len(), 2);
    assert_eq!(partial.omitted_pending.len(), 1);
    assert!(!partial.complete);
    assert!(partial.validate(&current, &policy).is_ok());
    let full = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 8 }).unwrap();
    assert!(full.complete);
    assert!(full.omitted_pending.is_empty());
    assert!(full.validate(&current, &policy).is_ok());
    let mut tampered = full;
    tampered.complete = false;
    assert!(tampered.validate(&current, &policy).is_err());
}

// WORK_UNIT_CASE: 806/16
#[test]
fn independent_limits_deadline_and_cancel_are_exact_with_one_over() {
    let test_fence = fence();
    let policy = policy(&test_fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let mut full_policy = policy.clone();
    full_policy.max_outcomes = 0;
    full_policy.seal().unwrap();
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let mut aligned = current.clone();
    aligned.policy_id = full_policy.policy_id.clone();
    aligned.policy_revision = full_policy.policy_revision;
    aligned
        .policy_digest
        .clone_from(&full_policy.canonical_digest);
    aligned.seal().unwrap();
    assert!(step_dreamer_cycle(&aligned, &[observed], &full_policy).is_err());
    let fence_deadline = test_fence;
    let mut deadline_input = durable_input(&fence_deadline, JobClass::Orientation, 1000);
    deadline_input.job_id = "deadline-job".to_owned();
    let deadline_state = DurableJobState::admit(&deadline_input, PAYLOAD, Some(1000)).unwrap();
    assert!(
        step_durable_job(
            &deadline_state,
            &DurableEvent::DeadlineExceeded(eliot_dreamer_cycle::DeadlineEvidence {
                observed_time_ms: 1000,
            }),
        )
        .is_err()
    );
    let expired = step_durable_job(
        &deadline_state,
        &DurableEvent::DeadlineExceeded(eliot_dreamer_cycle::DeadlineEvidence {
            observed_time_ms: 1001,
        }),
    )
    .unwrap();
    assert_eq!(expired.disposition, DurableDisposition::Terminal);
    assert_eq!(expired.next_state.phase, DurablePhase::Cancelled);
    let (idle, _) = durable_admit_orientation();
    let cancelled = step_durable_job(&idle, &DurableEvent::CancelRequested).unwrap();
    assert_eq!(cancelled.disposition, DurableDisposition::Terminal);
    assert_eq!(cancelled.next_state.phase, DurablePhase::Cancelled);
    let divergent = step_durable_job(
        &cancelled.next_state,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "late")),
    );
    assert!(matches!(divergent, Err(CycleError::PhaseViolation(_))));
    let replayed = step_durable_job(&cancelled.next_state, &DurableEvent::CancelRequested).unwrap();
    assert_eq!(replayed.disposition, DurableDisposition::Replayed);
    let (busy_base, _) = durable_admit_orientation();
    let busy = step_durable_job(
        &busy_base,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap()
    .next_state;
    let parked = step_durable_job(&busy, &DurableEvent::CancelRequested).unwrap();
    assert_eq!(
        parked.disposition,
        DurableDisposition::ReconciliationRequired
    );
    assert_eq!(parked.next_state.phase, DurablePhase::Reconciling);
    assert!(
        step_durable_job(
            &parked.next_state,
            &DurableEvent::RequestStage(durable_stage_request(DurableStage::Grounding, "late")),
        )
        .is_err()
    );
    let again = step_durable_job(&parked.next_state, &DurableEvent::CancelRequested).unwrap();
    assert_eq!(again.disposition, DurableDisposition::Replayed);
}

// WORK_UNIT_CASE: 806/17
#[test]
fn irrelevant_input_order_preserves_result_and_digest() {
    let fence = fence();
    let bundle_policy = policy(&fence, "bundle_validation");
    let request = pending(&bundle_policy);
    let start = state(&bundle_policy, request.clone());
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let after_bundle = step_dreamer_cycle(&start, &[observed], &bundle_policy)
        .unwrap()
        .next_state;
    assert_eq!(after_bundle.outcomes.len(), 1);
    let replayed = after_bundle.outcomes[0].clone();
    let once = step_dreamer_cycle(
        &after_bundle,
        std::slice::from_ref(&replayed),
        &bundle_policy,
    )
    .unwrap();
    let twice = step_dreamer_cycle(&after_bundle, &[replayed], &bundle_policy).unwrap();
    assert_eq!(once.disposition, StepDisposition::Replayed);
    assert_eq!(twice.disposition, StepDisposition::Replayed);
    assert_eq!(once.transition_digest, twice.transition_digest);
    assert_eq!(once.next_state, twice.next_state);
    let bytes_one = canonical_json_bytes(&after_bundle).unwrap();
    let bytes_two = canonical_json_bytes(&after_bundle).unwrap();
    assert_eq!(sha256_hex(&bytes_one), sha256_hex(&bytes_two));
}

// WORK_UNIT_CASE: 806/18
#[test]
fn bounded_malformed_inputs_are_panic_free() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let duplicate = vec![observed.clone(), observed.clone()];
    assert!(step_dreamer_cycle(&current, &duplicate, &policy).is_err());
    let mut oversized = current.clone();
    oversized.frontier = vec!["x".to_owned(); 257];
    assert!(oversized.seal().is_err() || step_dreamer_cycle(&oversized, &[], &policy).is_err());
    let mut control = current.clone();
    control.frontier = vec!["bad\u{0}frontier".to_owned()];
    assert!(control.seal().is_err() || step_dreamer_cycle(&control, &[], &policy).is_err());
    let mut long_pending = current.clone();
    long_pending.pending[0].owner = "o".repeat(16_385);
    assert!(
        long_pending.seal().is_err() || step_dreamer_cycle(&long_pending, &[], &policy).is_err()
    );
    let oversized_limits = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 65 });
    assert!(oversized_limits.is_err());
    let zero_limits = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 0 });
    assert!(zero_limits.is_err());
    let (durable, _) = durable_admit_orientation();
    let mut bad_event = durable_evidence(DurableStage::Bundle, "bundle");
    bad_event.cycle_receipt_digest = "not-a-digest".to_owned();
    let requested = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap()
    .next_state;
    assert!(step_durable_job(&requested, &DurableEvent::StageReady(bad_event)).is_err());
}

// WORK_UNIT_CASE: 806/19
#[test]
fn every_accepted_outcome_names_its_exact_predecessor_request() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let accepted = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Accepted,
        false,
    );
    let waiting = step_dreamer_cycle(&current, &[accepted], &policy).unwrap();
    assert_eq!(waiting.disposition, StepDisposition::ReconciliationRequired);
    let mut wrong_parent = request.clone();
    wrong_parent.predecessor_receipt_id =
        Some(eliot_contracts::ReceiptId::new("receipt-foreign").unwrap());
    let wrong_state = state(&policy, wrong_parent.clone());
    let wrong_outcome = outcome(
        &wrong_parent,
        receipt(
            &wrong_parent,
            generic_for(&wrong_parent, OutcomeDisposition::Accepted),
            None,
        ),
        OutcomeDisposition::Accepted,
        false,
    );
    assert!(step_dreamer_cycle(&wrong_state, &[wrong_outcome], &policy).is_err());
    let mut wrong_payload = request.clone();
    wrong_payload.payload_digest = DIGEST_B.to_owned();
    let wrong_payload_state = state(&policy, wrong_payload.clone());
    let wrong_payload_outcome = outcome(
        &wrong_payload,
        receipt(
            &wrong_payload,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Accepted,
        false,
    );
    assert!(step_dreamer_cycle(&wrong_payload_state, &[wrong_payload_outcome], &policy).is_err());
}

// WORK_UNIT_CASE: 806/20
#[test]
fn output_predecessor_is_exactly_the_input_state() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let advanced = step_dreamer_cycle(&current, &[observed], &policy).unwrap();
    assert_eq!(advanced.predecessor_digest, current.canonical_digest);
    assert_eq!(
        advanced.next_state.predecessor_digest,
        Some(current.canonical_digest.clone())
    );
    assert_eq!(advanced.next_state.controller_revision, 1);
    let expected_transition = sha256_hex(
        &canonical_json_bytes(&eliot_dreamer_cycle::CycleStep {
            predecessor_digest: advanced.predecessor_digest.clone(),
            next_state: advanced.next_state.clone(),
            requests: advanced.requests.clone(),
            disposition: advanced.disposition,
            transition_digest: String::new(),
        })
        .unwrap(),
    );
    assert_eq!(advanced.transition_digest, expected_transition);
    let (durable, _) = durable_admit_orientation();
    let durable_step = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap();
    assert_eq!(durable_step.predecessor_digest, durable.canonical_digest);
    assert_eq!(
        durable_step.next_state.predecessor_digest,
        Some(durable.canonical_digest.clone())
    );
    assert_eq!(durable_step.next_state.revision, 1);
}

// WORK_UNIT_CASE: 806/21
#[test]
fn unknown_effect_never_loses_reconciliation() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let unknown = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Unknown {
                reason: "no observation".to_owned(),
            },
            None,
        ),
        OutcomeDisposition::Unknown,
        true,
    );
    let parked = step_dreamer_cycle(&current, &[unknown], &policy).unwrap();
    assert_eq!(parked.disposition, StepDisposition::ReconciliationRequired);
    assert_eq!(parked.requests.len(), 1);
    assert_eq!(parked.requests[0].kind, RequestKind::EffectReconciliation);
    assert_eq!(parked.next_state.pending.len(), 1);
    let replayed = step_dreamer_cycle(&parked.next_state, &[], &policy).unwrap();
    assert_eq!(replayed.requests.len(), 1);
    assert_eq!(replayed.requests[0].kind, RequestKind::EffectReconciliation);
    let (durable, _) = durable_admit_orientation();
    let requested = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Model, "model-skip")),
    );
    assert!(requested.is_err());
    let bundle_requested = step_durable_job(
        &durable,
        &DurableEvent::RequestStage(durable_stage_request(DurableStage::Bundle, "bundle")),
    )
    .unwrap()
    .next_state;
    let mut reconciled = StageReconciled {
        operation_id: durable_op("bundle"),
        resolution: StageResolution::Failed,
        readback_digest: PAYLOAD.to_owned(),
    };
    reconciled.operation_id = durable_op("foreign");
    assert!(step_durable_job(&bundle_requested, &DurableEvent::Reconciled(reconciled),).is_err());
}

// WORK_UNIT_CASE: 806/22
#[test]
fn no_provider_tool_store_scheduler_or_finish_code_path_exists() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let step = step_dreamer_cycle(&current, &[observed], &policy).unwrap();
    assert!(step.next_state.pending.is_empty());
    assert!(step.requests.is_empty());
    let sample = sample_cycle(&step.next_state, &policy, &SampleLimits { max_sampled: 8 });
    if let Ok(sample) = sample {
        let plan = plan_cycle(&sample, &step.next_state, &policy, None).unwrap();
        let encoded = String::from_utf8(canonical_json_bytes(&plan).unwrap()).unwrap();
        for forbidden in [
            "provider",
            "Store",
            "scheduler",
            "process",
            "authority_grant",
            "Finish",
            "tool_call",
            "model_call",
        ] {
            assert!(!encoded.contains(forbidden), "forbidden {forbidden}");
        }
    }
    let committed = durable_drive_to_committed();
    let encoded = String::from_utf8(canonical_json_bytes(&committed.settled).unwrap()).unwrap();
    for forbidden in ["provider", "Store", "scheduler", "Finish"] {
        assert!(!encoded.contains(forbidden));
    }
}

// WORK_UNIT_CASE: 806/23
#[test]
fn pinned_wasm_portable_operation_uses_only_injected_evidence() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let observed = outcome(
        &request,
        receipt(
            &request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            None,
        ),
        OutcomeDisposition::Completed,
        false,
    );
    let first = step_dreamer_cycle(&current, std::slice::from_ref(&observed), &policy).unwrap();
    let second = step_dreamer_cycle(&current, &[observed], &policy).unwrap();
    assert_eq!(first.transition_digest, second.transition_digest);
    assert_eq!(
        first.next_state.canonical_digest,
        second.next_state.canonical_digest
    );
    let at_none = step_dreamer_cycle_at(&current, &[], &policy, None).unwrap();
    let at_some = step_dreamer_cycle_at(&current, &[], &policy, Some(1_700_000_000_000)).unwrap();
    assert_eq!(at_none.disposition, at_some.disposition);
    let sample = sample_cycle(&current, &policy, &SampleLimits { max_sampled: 8 }).unwrap();
    assert_eq!(sample.coverage_digest, sample.computed_digest().unwrap());
    let plan = plan_cycle(&sample, &current, &policy, None).unwrap();
    assert_eq!(plan.plan_digest, plan.computed_digest().unwrap());
    let (durable, _) = durable_admit_orientation();
    let before = step_durable_job(
        &durable,
        &DurableEvent::DeadlineExceeded(eliot_dreamer_cycle::DeadlineEvidence {
            observed_time_ms: 1,
        }),
    );
    assert!(before.is_err());
}
