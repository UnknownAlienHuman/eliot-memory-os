use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, TransactionSequence,
    canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::curation::{ClassificationPayload, TargetEvidence};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetLimits, BudgetUsage, CurationFamily, CurationKind, CurationPayload,
    DreamJobInput, JobClass, Requester, RequesterOrigin, ScreenBinding, ScreenState,
    TargetDenominator, TypedCurationHandlerRequest, TypedCurationHandlerResult, ValidationReceipt,
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
            authority_epoch: fence.authority_epoch,
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
    state.policy_digest = policy.canonical_digest.clone();
    let mut request = pending(policy);
    let phase_tag = format!("{:?}", phase).to_lowercase();
    set_phase_identity(&mut request, &phase_tag);
    set_phase(&mut request, phase, kind);
    let rule = &policy.phase_rules[0];
    request.owner = rule.owner.clone();
    request.product_id = rule.product_id.clone();
    request.source_id = rule.source_id.clone();
    request.operation_kind = rule.operation_kind.clone();
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
        result_digest: "d".repeat(64),
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
        draft_digest: "a".repeat(64),
        bundle_digest: request.bundle_digest.clone(),
        manifest_digest: state.job.frozen_manifest_digest.clone(),
        task_id: request.task_id.clone(),
        scope_id: request.scope_id.clone(),
        input_digest: "b".repeat(64),
        output_digest: "c".repeat(64),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: request.state_fence.clone(),
        preservation_digest: "d".repeat(64),
        budget_digest: "e".repeat(64),
    }
}

#[test]
fn completed_receipt_advances_one_adjacent_phase() {
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
        result_digest: "e".repeat(64),
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
    let mut replay_state = first.next_state.clone();
    replay_state.proposed_requests.push(request);
    replay_state.seal().unwrap();
    let replay =
        step_dreamer_cycle(&replay_state, std::slice::from_ref(&observed), &policy).unwrap();
    assert_eq!(replay.disposition, StepDisposition::Replayed);
    assert_eq!(replay.next_state, replay_state);
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
    let unknown = outcome(
        &request,
        unknown_receipt.clone(),
        OutcomeDisposition::Unknown,
        true,
    );
    let mut unknown = unknown;
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
        result_digest: "e".repeat(64),
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
