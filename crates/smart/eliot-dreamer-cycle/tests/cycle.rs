use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, TransactionSequence,
    canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, DreamJobInput, JobClass, Requester, RequesterOrigin,
};
use eliot_dreamer_cycle::{
    CyclePhase, CyclePolicy, DreamerCycleState, ExpectedArtifact, ObservedOutcome,
    OutcomeDisposition, PendingRequest, PhasePolicyRule, RequestKind, StepDisposition,
    step_dreamer_cycle,
};
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, TaskBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};

const PAYLOAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fence() -> StateFence {
    StateFence {
        authority_epoch: AuthorityEpoch::genesis(),
        resource_generation: ResourceGeneration::genesis(),
        task_revision: Some(TaskRevision::genesis()),
        policy_revision: Some(PolicyRevision::genesis()),
        integration_revision: None,
    }
}

fn job(fence: &StateFence) -> DreamJobInput {
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
            source_width: Some(1_000),
            reference_width: Some(1_000),
            model_calls: Some(10),
            attempts: Some(10),
            candidates: Some(10),
            wall_ms: Some(1_000_000),
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
        max_outcomes: 8,
        max_requests: 8,
        max_transitions: 8,
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

fn state(policy: &CyclePolicy, request: PendingRequest) -> DreamerCycleState {
    let mut state = DreamerCycleState {
        schema_version: 1,
        cycle_id: ArtifactId::new("cycle-1").unwrap(),
        job: job(&policy.state_fence),
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
            authority_epoch: fence.authority_epoch,
            state_fence: fence.clone(),
            allowed_effect: request.effect,
            proof_ceiling: request.proof_ceiling,
        },
        artifacts: vec![
            eliot_receipts::ArtifactBinding {
                artifact_id: ArtifactId::new("request-artifact").unwrap(),
                sha256: request_digest,
                role: ReceiptKind::Request,
                source_revision: None,
            },
            eliot_receipts::ArtifactBinding {
                artifact_id: ArtifactId::new("payload-1").unwrap(),
                sha256: request.payload_digest.clone(),
                role: ReceiptKind::Artifact,
                source_revision: None,
            },
        ],
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
    ObservedOutcome {
        receipt,
        phase: CyclePhase::BundleValidated,
        disposition,
        payload_digest: request.payload_digest.clone(),
        possible_effect,
        evidence_refs: Vec::new(),
        handler_result: None,
        validation_receipt: None,
        screen_binding: None,
    }
}

#[test]
fn completed_receipt_advances_one_adjacent_phase() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let receipt = receipt(
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
            receipt,
            OutcomeDisposition::Completed,
            false,
        )],
        &policy,
    )
    .unwrap();
    assert_eq!(step.disposition, StepDisposition::Advanced);
    assert_eq!(step.next_state.phase, CyclePhase::BundleValidated);
    assert!(step.next_state.pending.is_empty());
}

#[test]
fn exact_receipt_replays_without_mutation() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let observed = outcome(&request, receipt, OutcomeDisposition::Completed, false);
    let first = step_dreamer_cycle(&current, std::slice::from_ref(&observed), &policy).unwrap();
    let replay =
        step_dreamer_cycle(&first.next_state, std::slice::from_ref(&observed), &policy).unwrap();
    assert_eq!(replay.disposition, StepDisposition::Replayed);
    assert_eq!(replay.next_state, first.next_state);
}

#[test]
fn changed_payload_under_same_receipt_id_is_rejected() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let observed = outcome(&request, receipt, OutcomeDisposition::Completed, false);
    let first = step_dreamer_cycle(&current, std::slice::from_ref(&observed), &policy).unwrap();
    let mut changed = observed.clone();
    changed.payload_digest =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    assert!(step_dreamer_cycle(&first.next_state, &[changed], &policy).is_err());
}

#[test]
fn unknown_then_predecessor_linked_completion_reconciles_same_operation() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let unknown_receipt = receipt(
        &request,
        ReceiptDisposition::Unknown {
            reason: "no observation".to_owned(),
        },
        None,
    );
    let unknown = outcome(
        &request,
        unknown_receipt.clone(),
        OutcomeDisposition::Unknown,
        true,
    );
    let waiting = step_dreamer_cycle(&current, &[unknown], &policy).unwrap();
    assert_eq!(waiting.disposition, StepDisposition::ReconciliationRequired);
    assert_eq!(
        waiting.next_state.pending[0].operation_id,
        request.operation_id
    );
    let resolved_receipt = receipt(
        &request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        Some(unknown_receipt.identity.receipt_id),
    );
    let resolved = outcome(
        &request,
        resolved_receipt,
        OutcomeDisposition::Completed,
        false,
    );
    let done = step_dreamer_cycle(&waiting.next_state, &[resolved], &policy).unwrap();
    assert_eq!(done.disposition, StepDisposition::Advanced);
    assert!(done.next_state.pending.is_empty());
}

#[test]
fn unrelated_valid_receipt_cannot_advance_pending_request() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let request = pending(&policy);
    let current = state(&policy, request.clone());
    let mut other = request.clone();
    other.request_id = RequestId::new("request-2").unwrap();
    let receipt = receipt(
        &other,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let result = step_dreamer_cycle(
        &current,
        &[outcome(
            &other,
            receipt,
            OutcomeDisposition::Completed,
            false,
        )],
        &policy,
    );
    assert!(result.is_err());
    assert_eq!(current.phase, CyclePhase::Validated);
}

#[test]
fn pending_operation_must_match_frozen_phase_rule() {
    let fence = fence();
    let policy = policy(&fence, "bundle_validation");
    let mut request = pending(&policy);
    request.operation_kind = "wrong-operation".to_owned();
    let current = state(&policy, request);
    assert!(step_dreamer_cycle(&current, &[], &policy).is_err());

    let screen_policy = policy_for_phase(&fence, CyclePhase::Screened, "curation_screen");
    let mut screen_request = pending(&screen_policy);
    set_phase(
        &mut screen_request,
        CyclePhase::Screened,
        RequestKind::CurationScreen,
    );
    let mut screen_state = state(&screen_policy, screen_request.clone());
    screen_state.phase = CyclePhase::BundleValidated;
    screen_state.seal().unwrap();
    let screen_receipt = receipt(
        &screen_request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let mut screen_outcome = outcome(
        &screen_request,
        screen_receipt,
        OutcomeDisposition::Completed,
        false,
    );
    screen_outcome.phase = CyclePhase::Screened;
    assert!(step_dreamer_cycle(&screen_state, &[screen_outcome], &screen_policy).is_err());

    let common_policy = policy_for_phase(&fence, CyclePhase::CommonValidated, "common_validation");
    let mut common_request = pending(&common_policy);
    set_phase(
        &mut common_request,
        CyclePhase::CommonValidated,
        RequestKind::CommonValidation,
    );
    let mut common_state = state(&common_policy, common_request.clone());
    common_state.phase = CyclePhase::GroundingValidated;
    common_state.seal().unwrap();
    let common_receipt = receipt(
        &common_request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let mut common_outcome = outcome(
        &common_request,
        common_receipt,
        OutcomeDisposition::Completed,
        false,
    );
    common_outcome.phase = CyclePhase::CommonValidated;
    assert!(step_dreamer_cycle(&common_state, &[common_outcome], &common_policy).is_err());

    let handler_policy = policy_for_phase(&fence, CyclePhase::HandlerObserved, "semantic_handler");
    let mut handler_request = pending(&handler_policy);
    set_phase(
        &mut handler_request,
        CyclePhase::HandlerObserved,
        RequestKind::SemanticHandler,
    );
    let mut handler_state = state(&handler_policy, handler_request.clone());
    handler_state.phase = CyclePhase::CommonValidated;
    handler_state.seal().unwrap();
    let handler_receipt = receipt(
        &handler_request,
        ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        None,
    );
    let mut handler_outcome = outcome(
        &handler_request,
        handler_receipt,
        OutcomeDisposition::Completed,
        false,
    );
    handler_outcome.phase = CyclePhase::HandlerObserved;
    assert!(step_dreamer_cycle(&handler_state, &[handler_outcome], &handler_policy).is_err());
}
