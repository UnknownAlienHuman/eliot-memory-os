#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance, VerificationBinding,
};
use eliot_instrument_api::{
    EvidenceCoverage as InstrumentCoverage, EvidenceFreshness as InstrumentFreshness,
    ExecutionStatus, RawEvidence, RawEvidenceSource, VerificationOutcome, VerificationRun,
};
use eliot_learning_contracts::{
    AgentAttemptId, CampaignId, ChangeOperation, ChangeSurface, Completeness, ContractBinding,
    InverseChange, LearningStateViewRecipe, MemberId, OmissionPolicy, OwnerId, ProofCeiling,
    SlotDisposition, SlotProjection, SlotRequirement, SlotSpec, SourceDenominator, ValueState,
};
use eliot_learning_delta::{
    AttemptEvidence, AttemptInvocationBinding, AttemptLearningOutcome, AttemptStatus,
    BeforeSelector, ChangeRequest, DependencyEvidence, DependencyRole, DependencyStatus,
    DerivationContext, DerivationPolicy, EvaluationContext, EvaluatorBinding, EvidenceKind,
    EvidenceReceipt, FrozenPropertyBinding, LearningDeltaError, NoChangeProof, NoChangeRequest,
    NoChangeWitness, RetryContext, RetryReason, SemanticOutcome, SurfacePermission,
    canonical_retry_fingerprint, derive_attempt_learning_outcome,
};

fn digest(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

fn policy(pass_outcome: SemanticOutcome) -> DerivationPolicy {
    let evaluator = ContractId::new("eval-contract").expect("fixture contract");
    let mut no_change_witnesses = BTreeMap::new();
    no_change_witnesses.insert(
        "proven_non_applicability".to_owned(),
        NoChangeWitness {
            verifier: evaluator.clone(),
            property: "learning-outcome".to_owned(),
            revision: "1".to_owned(),
            outcome: SemanticOutcome::NoEvent,
        },
    );
    no_change_witnesses.insert(
        "controlled_replication_needed".to_owned(),
        NoChangeWitness {
            verifier: evaluator.clone(),
            property: "learning-outcome".to_owned(),
            revision: "1".to_owned(),
            outcome: SemanticOutcome::MeasuredUnchanged,
        },
    );
    DerivationPolicy {
        evaluator_contract: Some(evaluator.clone()),
        evaluator_verifier: Some(evaluator),
        evaluator_pass_outcome: pass_outcome,
        no_change_witnesses,
        allowed_surfaces: vec![ChangeSurface::Strategy],
        surface_permissions: vec![SurfacePermission {
            slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
            target: eliot_learning_contracts::TargetId::new("target-a").expect("target"),
            owner: OwnerId::from_artifact(aid("owner-a")),
            member_id: Some(MemberId::from_artifact(aid("member-a"))),
            surface: ChangeSurface::Strategy,
            accepted_type: "strategy/v1".to_owned(),
            schema_digest: digest("strategy-schema"),
        }],
        ..DerivationPolicy::default()
    }
}

fn aid(text: &str) -> ArtifactId {
    ArtifactId::new(text).expect("fixture identity")
}

fn binding(tag: &str) -> ContractBinding {
    ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new(format!("request-{tag}")).expect("request"),
        operation_id: OperationId::new(format!("operation-{tag}")).expect("operation"),
        product_id: ProductId::new("eliot").expect("product"),
        task_id: TaskId::new(format!("task-{tag}")).expect("task"),
        scope: eliot_learning_contracts::WorkScopeId::new(format!("scope-{tag}")).expect("scope"),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new(format!("source-{tag}")).expect("source"),
            snapshot: aid(&format!("snapshot-{tag}")),
            revision: TaskRevision::genesis(),
            digest: digest("source"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

fn recipe_and_view(
    tag: &str,
) -> (
    LearningStateViewRecipe,
    eliot_learning_contracts::CampaignLearningStateView,
) {
    let binding = binding(tag);
    let target = eliot_learning_contracts::TargetId::new("target-a").expect("target");
    let slot_id = eliot_learning_contracts::SlotId::from_artifact(aid("slot-a"));
    let owner = OwnerId::from_artifact(aid("owner-a"));
    let member_id = MemberId::from_artifact(aid("member-a"));
    let spec = SlotSpec {
        slot_id: slot_id.clone(),
        owner: owner.clone(),
        target: target.clone(),
        requirement: SlotRequirement::Required,
        declared_members: vec![member_id.clone()],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    };
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-a"),
        campaign_id: CampaignId::from_artifact(aid("campaign-a")),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![spec],
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    recipe.seal().expect("recipe seal");
    let member = eliot_learning_contracts::MemberProjection {
        member_id,
        owner,
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("before-value")),
        evidence: vec![aid("view-member-evidence")],
    };
    let mut view = eliot_learning_contracts::CampaignLearningStateView {
        view_id: aid("view-a"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target,
        binding: binding.clone(),
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id,
            disposition: SlotDisposition::Current,
            members: vec![member],
            evidence: vec![aid("view-slot-evidence")],
        }],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("objective-ref")],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.seal().expect("view seal");
    (recipe, view)
}

fn receipt(
    input_binding: &ContractBinding,
    attempt: &AgentAttemptId,
    target: &eliot_learning_contracts::TargetId,
    id: &str,
    kind: EvidenceKind,
    outcome: SemanticOutcome,
    route: &str,
) -> EvidenceReceipt {
    let verification = (kind == EvidenceKind::Evaluator).then(|| VerificationBinding {
        contract_id: ContractId::new("eval-contract").expect("contract"),
        run_id: aid("eval-run"),
        revision: "1".to_owned(),
    });
    EvidenceReceipt {
        id: aid(id),
        binding: input_binding.clone(),
        attempt_id: attempt.clone(),
        target: target.clone(),
        state_fence: input_binding.state_fence.clone(),
        metric: "outcome".to_owned(),
        unit: "categorical".to_owned(),
        population: "declared-attempt".to_owned(),
        window: "attempt".to_owned(),
        source_revision: "1".to_owned(),
        source_digest: digest(id),
        source_units: 1,
        kind,
        outcome,
        envelope: EvidenceEnvelope {
            authority: EvidenceAuthority::DeterministicRuntimeTest,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: if kind == EvidenceKind::Evaluator {
                EpistemicStatus::Verified
            } else {
                EpistemicStatus::Observed
            },
            assertability: if kind == EvidenceKind::Evaluator {
                Assertability::Assertable
            } else {
                Assertability::NonAssertableUnverified
            },
            provenance: Provenance {
                source_id: input_binding.source.owner.clone(),
                capture_route: route.to_owned(),
                scope: input_binding.scope.as_str().to_owned(),
                raw_handle: Some(id.to_owned()),
                revision: Some("1".to_owned()),
            },
            verification,
            state_fence: input_binding.state_fence.clone(),
        },
    }
}

fn raw(binding: &ContractBinding, id: &str) -> RawEvidence {
    raw_with_invocation(binding, id, input_binding_operation(binding))
}

fn raw_pre(binding: &ContractBinding, id: &str) -> RawEvidence {
    raw_with_invocation(
        binding,
        id,
        RequestId::new(format!("pre-{}", binding.operation_id.as_str())).expect("pre invocation"),
    )
}

fn raw_with_invocation(
    _binding: &ContractBinding,
    id: &str,
    invocation_id: RequestId,
) -> RawEvidence {
    let bytes = id.as_bytes().to_vec();
    RawEvidence {
        artifact_id: aid(id),
        invocation_id,
        source: RawEvidenceSource::Inline,
        content_type: "text/plain".to_owned(),
        sha256: sha256_hex(&bytes),
        bytes,
        captured_at: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
        truncated: false,
    }
}

fn base_input(
    tag: &str,
) -> (
    LearningStateViewRecipe,
    eliot_learning_contracts::CampaignLearningStateView,
    AttemptEvidence,
    &'static DerivationContext<'static>,
) {
    base_input_with_outcome(tag, SemanticOutcome::Benefit)
}

fn base_input_with_outcome(
    tag: &str,
    evaluator_outcome: SemanticOutcome,
) -> (
    LearningStateViewRecipe,
    eliot_learning_contracts::CampaignLearningStateView,
    AttemptEvidence,
    &'static DerivationContext<'static>,
) {
    let (recipe, view) = recipe_and_view(tag);
    let binding = view.binding.clone();
    let attempt_id = AgentAttemptId::new(format!("attempt-{tag}")).expect("attempt");
    let target = view.target.clone();
    let before = BeforeSelector::CurrentMember {
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        member_id: MemberId::from_artifact(aid("member-a")),
        owner: OwnerId::from_artifact(aid("owner-a")),
        source_owner: binding.source.owner.clone(),
        source_revision: TaskRevision::genesis(),
        source_snapshot: binding.source.snapshot.clone(),
        source_digest: binding.source.digest.clone(),
        projection_revision: TaskRevision::genesis(),
    };
    let observation = receipt(
        &binding,
        &attempt_id,
        &target,
        "observation",
        EvidenceKind::Observation,
        SemanticOutcome::Benefit,
        "observation-route",
    );
    let evaluator = receipt(
        &binding,
        &attempt_id,
        &target,
        "evaluator",
        EvidenceKind::Evaluator,
        evaluator_outcome,
        "evaluator-route",
    );
    let change = ChangeRequest {
        target: target.clone(),
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        member_id: Some(MemberId::from_artifact(aid("member-a"))),
        owner: OwnerId::from_artifact(aid("owner-a")),
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
        surface: ChangeSurface::Strategy,
        before: before.clone(),
        after: ValueState {
            present: true,
            digest: Some(digest("after-value")),
        },
        rollback: InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Replace {
                target: target.clone(),
                surface: ChangeSurface::Strategy,
                before: ValueState {
                    present: true,
                    digest: Some(digest("after-value")),
                },
                after: ValueState {
                    present: true,
                    digest: Some(digest("before-value")),
                },
            },
        },
        invalidation: aid("invalidation-ref"),
        dependencies: vec![aid("dependency")],
    };
    let input = build_attempt_evidence(AttemptFixture {
        recipe: &recipe,
        binding: &binding,
        attempt_id,
        target,
        before,
        change,
        observation,
        evaluator,
        evaluator_outcome,
        view: &view,
    });
    let context = build_evaluation_context(&input, &binding, evaluator_outcome);
    (recipe, view, input, context)
}

fn build_evaluation_context(
    input: &AttemptEvidence,
    binding: &ContractBinding,
    evaluator_outcome: SemanticOutcome,
) -> &'static DerivationContext<'static> {
    let run = Box::leak(Box::new(VerificationRun {
        run_id: RequestId::new("eval-run").expect("run"),
        verifier: ContractId::new("eval-contract").expect("verifier"),
        invocation_id: RequestId::new(input.binding.operation_id.as_str()).expect("invocation"),
        property: "learning-outcome".to_owned(),
        scope: input.binding.scope.as_str().to_owned(),
        execution: ExecutionStatus::Succeeded,
        outcome: VerificationOutcome::Pass,
        freshness: InstrumentFreshness::ExactCandidate,
        coverage: InstrumentCoverage::CompleteForScope,
        evidence: vec![],
        raw_evidence: vec![
            aid("observation"),
            aid("evaluator"),
            aid("baseline"),
            aid("control"),
            aid("discriminator-a"),
            aid("intended-content"),
            aid("attempted-content"),
            aid("mechanism"),
            aid("probe"),
            aid("action-plan"),
        ],
        state_fence: input.binding.state_fence.clone(),
        started_at: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
        finished_at: Some(ClockReading {
            valid_time_ms: Some(2),
            known_time_ms: Some(2),
            transaction_sequence: None,
            monotonic_ns: Some(2),
        }),
    }));
    let raw_records = Box::leak(
        vec![
            raw(binding, "observation"),
            raw(binding, "evaluator"),
            raw(binding, "baseline"),
            raw(binding, "control"),
            raw_pre(binding, "intended-content"),
            raw_pre(binding, "attempted-content"),
            raw_pre(binding, "mechanism"),
            raw_pre(binding, "probe"),
            raw_pre(binding, "action-plan"),
            raw_pre(binding, "discriminator-a"),
        ]
        .into_boxed_slice(),
    );
    let frozen = Box::leak(Box::new(FrozenPropertyBinding {
        run_id: RequestId::new("eval-run").expect("run"),
        invocation_id: input_binding_operation(binding),
        verifier: ContractId::new("eval-contract").expect("verifier"),
        property: "learning-outcome".to_owned(),
        scope: binding.scope.as_str().to_owned(),
        revision: "1".to_owned(),
        pass_outcome: evaluator_outcome,
        fail_outcome: SemanticOutcome::Harm,
    }));
    Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: raw_records,
            binding: frozen,
            invocation: Box::leak(Box::new(AttemptInvocationBinding {
                attempt_id: input.attempt_id.clone(),
                target: input.target.clone(),
                task_id: input.binding.task_id.clone(),
                scope: input.binding.scope.clone(),
                state_fence: input.binding.state_fence.clone(),
                environment_fingerprint: "env-a".to_owned(),
                invocation_id: input_binding_operation(&input.binding),
                relation_receipt: aid("evaluator"),
                pre_observation_invocation_id: input.pre_observation_invocation_id.clone(),
            })),
        },
        prior: None,
    }))
}

struct AttemptFixture<'a> {
    recipe: &'a LearningStateViewRecipe,
    binding: &'a ContractBinding,
    attempt_id: AgentAttemptId,
    target: eliot_learning_contracts::TargetId,
    before: BeforeSelector,
    change: ChangeRequest,
    observation: EvidenceReceipt,
    evaluator: EvidenceReceipt,
    evaluator_outcome: SemanticOutcome,
    view: &'a eliot_learning_contracts::CampaignLearningStateView,
}

fn build_attempt_evidence(fixture: AttemptFixture<'_>) -> AttemptEvidence {
    let AttemptFixture {
        recipe,
        binding,
        attempt_id,
        target,
        before,
        change,
        observation,
        evaluator,
        evaluator_outcome,
        view,
    } = fixture;
    AttemptEvidence {
        binding: binding.clone(),
        attempt_id,
        delta_id: aid("delta-a"),
        target,
        recipe: recipe.clone(),
        status: AttemptStatus::Consequential,
        pre_observation_discriminator: aid("discriminator-a"),
        before,
        owner_empty_declarations: vec![],
        predicted_outcome: evaluator_outcome,
        intended_strategy: aid("intended-content"),
        attempted_strategy: aid("attempted-content"),
        changes: vec![change],
        dependency_evidence: vec![
            DependencyEvidence {
                id: aid("dependency"),
                binding: binding.clone(),
                source_digest: binding.source.digest.clone(),
                status: DependencyStatus::Current,
                role: DependencyRole::Supporting,
                depends_on: vec![],
            },
            DependencyEvidence {
                id: aid("invalidation-ref"),
                binding: binding.clone(),
                source_digest: binding.source.digest.clone(),
                status: DependencyStatus::Current,
                role: DependencyRole::Invalidation {
                    target: view.target.clone(),
                    surface: ChangeSurface::Strategy,
                    owner: OwnerId::from_artifact(aid("owner-a")),
                    member_id: Some(MemberId::from_artifact(aid("member-a"))),
                },
                depends_on: vec![],
            },
        ],
        observations: vec![observation],
        evaluator: Some(evaluator),
        evaluator_binding: Some(EvaluatorBinding {
            contract_id: ContractId::new("eval-contract").expect("contract"),
            run_id: RequestId::new("eval-run").expect("run"),
            invocation_id: input_binding_operation(binding),
            property: "learning-outcome".to_owned(),
            scope: binding.scope.as_str().to_owned(),
            verifier: ContractId::new("eval-contract").expect("verifier"),
            revision: "1".to_owned(),
            pass_outcome: evaluator_outcome,
            fail_outcome: SemanticOutcome::Harm,
        }),
        no_change: None,
        retry: RetryContext {
            environment_fingerprint: "env-a".to_owned(),
            ..RetryContext::default()
        },
        refiner: None,
        baseline: vec![aid("baseline")],
        control: vec![aid("control")],
        confounders: vec![],
        stu: Some(1),
        cost_units: 1,
        output_units: 1,
        work_units: 1,
        intended_strategy_digest: digest("intended-content"),
        attempted_strategy_digest: digest("attempted-content"),
        mechanism_fingerprint: digest("mechanism"),
        probe_fingerprint: digest("probe"),
        action_plan_fingerprint: digest("action-plan"),
        intended_strategy_evidence: aid("intended-content"),
        attempted_strategy_evidence: aid("attempted-content"),
        mechanism_evidence: aid("mechanism"),
        probe_evidence: aid("probe"),
        action_plan_evidence: aid("action-plan"),
        discriminator_evidence: aid("discriminator-a"),
        discriminator_digest: digest("discriminator-a"),
        pre_observation_invocation_id: RequestId::new(format!(
            "pre-{}",
            binding.operation_id.as_str()
        ))
        .expect("pre invocation"),
    }
}

fn input_binding_operation(binding: &ContractBinding) -> RequestId {
    RequestId::new(binding.operation_id.as_str()).expect("invocation")
}

fn prior_context(context: &DerivationContext<'static>) -> &'static DerivationContext<'static> {
    let prior_invocation = RequestId::new("prior-invocation").expect("prior invocation");
    let prior_pre_observation = RequestId::new("prior-pre-invocation").expect("prior pre");
    let rename = |id: &ArtifactId| match id.as_str() {
        "observation" => aid("prior-observation"),
        "evaluator" => aid("prior-evaluator"),
        "baseline" => aid("prior-baseline"),
        "control" => aid("prior-control"),
        "discriminator-a" => aid("prior-discriminator"),
        "intended-content" => aid("prior-intended"),
        "attempted-content" => aid("prior-attempted"),
        "mechanism" => aid("prior-mechanism"),
        "probe" => aid("prior-probe"),
        "action-plan" => aid("prior-action-plan"),
        _ => id.clone(),
    };
    let mut raw_records = context.current.raw_evidence.to_vec();
    for raw in &mut raw_records {
        let material = matches!(
            raw.artifact_id.as_str(),
            "discriminator-a"
                | "intended-content"
                | "attempted-content"
                | "mechanism"
                | "probe"
                | "action-plan"
        );
        raw.artifact_id = rename(&raw.artifact_id);
        raw.invocation_id = if material {
            prior_pre_observation.clone()
        } else {
            prior_invocation.clone()
        };
    }
    let raw_records = Box::leak(raw_records.into_boxed_slice());
    let mut run = (*context.current.run).clone();
    run.run_id = RequestId::new("prior-run").expect("prior run");
    run.invocation_id = prior_invocation.clone();
    run.raw_evidence = run.raw_evidence.iter().map(rename).collect();
    let run = Box::leak(Box::new(run));
    let mut frozen = (*context.current.binding).clone();
    frozen.run_id = run.run_id.clone();
    frozen.invocation_id = prior_invocation.clone();
    let frozen = Box::leak(Box::new(frozen));
    let mut invocation = (*context.current.invocation).clone();
    invocation.attempt_id = AgentAttemptId::new("prior-attempt").expect("prior attempt");
    invocation.invocation_id = prior_invocation;
    invocation.pre_observation_invocation_id = prior_pre_observation;
    invocation.relation_receipt = aid("prior-relation");
    let invocation = Box::leak(Box::new(invocation));
    Box::leak(Box::new(DerivationContext {
        current: context.current,
        prior: Some(EvaluationContext {
            run,
            raw_evidence: raw_records,
            binding: frozen,
            invocation,
        }),
    }))
}

fn renamed_material_context(
    context: &DerivationContext<'static>,
) -> &'static DerivationContext<'static> {
    let replacements = [
        (aid("discriminator-a"), aid("discriminator-b")),
        (aid("intended-content"), aid("intended-b")),
        (aid("attempted-content"), aid("attempted-b")),
        (aid("mechanism"), aid("mechanism-b")),
        (aid("probe"), aid("probe-b")),
        (aid("action-plan"), aid("action-plan-b")),
    ];
    let rename = |id: &ArtifactId| {
        replacements
            .iter()
            .find_map(|(old, new)| (id == old).then(|| new.clone()))
            .unwrap_or_else(|| id.clone())
    };
    let mut raw_records = context.current.raw_evidence.to_vec();
    for raw in &mut raw_records {
        raw.artifact_id = rename(&raw.artifact_id);
    }
    let raw_records = Box::leak(raw_records.into_boxed_slice());
    let mut run = (*context.current.run).clone();
    run.raw_evidence = run.raw_evidence.iter().map(rename).collect();
    let run = Box::leak(Box::new(run));
    Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: raw_records,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }))
}

#[test]
fn derives_delta_with_exact_before_and_inverse() {
    let (_, view, mut input, context) = base_input("delta");
    input.dependency_evidence[0].depends_on = vec![aid("dependency-child")];
    input.dependency_evidence.push(DependencyEvidence {
        id: aid("dependency-child"),
        binding: input.binding.clone(),
        source_digest: input.binding.source.digest.clone(),
        status: DependencyStatus::Current,
        role: DependencyRole::Supporting,
        depends_on: vec![],
    });
    let mut second = input.changes[0].clone();
    second.surface = ChangeSurface::Route;
    second.invalidation = aid("invalidation-route");
    second.rollback.inverse = ChangeOperation::Replace {
        target: second.target.clone(),
        surface: ChangeSurface::Route,
        before: second.after.clone(),
        after: ValueState {
            present: true,
            digest: Some(digest("before-value")),
        },
    };
    input.changes.push(second);
    input.dependency_evidence.push(DependencyEvidence {
        id: aid("invalidation-route"),
        binding: input.binding.clone(),
        source_digest: input.binding.source.digest.clone(),
        status: DependencyStatus::Current,
        role: DependencyRole::Invalidation {
            target: input.target.clone(),
            surface: ChangeSurface::Route,
            owner: OwnerId::from_artifact(aid("owner-a")),
            member_id: Some(MemberId::from_artifact(aid("member-a"))),
        },
        depends_on: vec![],
    });
    let mut delta_policy = policy(SemanticOutcome::Benefit);
    delta_policy.allowed_surfaces.push(ChangeSurface::Route);
    delta_policy.surface_permissions.push(SurfacePermission {
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        target: input.target.clone(),
        owner: OwnerId::from_artifact(aid("owner-a")),
        member_id: Some(MemberId::from_artifact(aid("member-a"))),
        surface: ChangeSurface::Route,
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    });
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &delta_policy)
        .expect("delta derivation");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(delta.changes.len(), 2);
    assert_eq!(delta.dependencies.len(), 4);
    assert_eq!(delta.changes[0].target(), &view.target);
    assert!(delta.validate_against_view(&view).is_ok());
}

#[test]
fn derives_affirmative_non_applicability_no_change() {
    let (_, view, mut input, context) = base_input_with_outcome("fixed", SemanticOutcome::NoEvent);
    input.changes.clear();
    let evaluator_id = input.evaluator.as_ref().expect("evaluator").id.clone();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ProvenNonApplicability {
            applicability: evaluator_id.clone(),
        },
        affirmative_evidence: vec![evaluator_id],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    });
    let mut no_change_policy = policy(SemanticOutcome::NoEvent);
    no_change_policy.allowed_surfaces.clear();
    no_change_policy.surface_permissions.clear();
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &no_change_policy)
        .expect("no change derivation");
    assert!(matches!(outcome, AttemptLearningOutcome::NoChange(_)));
}

#[test]
fn rejects_missing_or_nonsemantic_evaluator_evidence() {
    let (_, view, mut input, context) = base_input("invalid");
    input.evaluator = None;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::MissingEvaluator)
    );
    let (_, view, mut input, context) = base_input("self-report");
    input.evaluator.as_mut().expect("evaluator").kind = EvidenceKind::SelfReport;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::NonSemanticEvidence)
    );
    let (_, view, mut input, context) = base_input("cancelled");
    input.status = AttemptStatus::Cancelled;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::Cancelled)
    );
    let (_, view, input, context) = base_input("bounded");
    let mut bounded_policy = policy(SemanticOutcome::Benefit);
    bounded_policy.max_work_units = 1;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &bounded_policy),
        Err(LearningDeltaError::Bound { field: "work" })
    );
}

#[test]
fn equivalent_retry_requires_exact_allowed_reason() {
    let (_, view, mut input, current) =
        base_input_with_outcome("retry", SemanticOutcome::MeasuredUnchanged);
    input.changes.clear();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ControlledReplicationNeeded {
            prior_evidence: aid("prior-evaluator"),
            reason: RetryReason::Replication,
        },
        affirmative_evidence: vec![aid("prior-evaluator")],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    });
    let context = prior_context(current);
    let fingerprint = canonical_retry_fingerprint(&input, context).expect("fingerprint");
    input.retry.prior_attempt = Some(AgentAttemptId::new("prior-attempt").expect("prior"));
    input.retry.prior_fingerprint = Some(fingerprint);
    let mut prior_binding = input.binding.clone();
    prior_binding.request_id = RequestId::new("prior-request").expect("prior request");
    prior_binding.operation_id = OperationId::new("prior-operation").expect("prior operation");
    input.retry.prior_binding = Some(prior_binding);
    input.retry.prior_target = Some(input.target.clone());
    input.retry.prior_outcome = Some(SemanticOutcome::MeasuredUnchanged);
    input.retry.prior_evidence = vec![
        aid("prior-observation"),
        aid("prior-evaluator"),
        aid("prior-baseline"),
        aid("prior-control"),
        aid("prior-discriminator"),
        aid("prior-intended"),
        aid("prior-attempted"),
        aid("prior-mechanism"),
        aid("prior-probe"),
        aid("prior-action-plan"),
    ];
    input.retry.prior_material_evidence = vec![
        aid("prior-discriminator"),
        aid("prior-intended"),
        aid("prior-attempted"),
        aid("prior-mechanism"),
        aid("prior-probe"),
        aid("prior-action-plan"),
    ];
    input.retry.reason = Some(RetryReason::Replication);
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::MeasuredUnchanged),
    )
    .expect("controlled retry");
    assert!(matches!(outcome, AttemptLearningOutcome::NoChange(_)));
    input.retry.prior_fingerprint = Some("0".repeat(64));
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::MeasuredUnchanged),
        ),
        Err(LearningDeltaError::UnknownPriorEffect)
    );
}

#[test]
fn retry_fingerprint_includes_strategy_content_and_is_deterministic() {
    let (_, _, mut input, context) = base_input("fingerprint");
    let first = canonical_retry_fingerprint(&input, context).expect("fingerprint");
    let second = canonical_retry_fingerprint(&input, context).expect("fingerprint");
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    input.retry.environment_fingerprint = "env-b".to_owned();
    let changed_environment = canonical_retry_fingerprint(&input, context).expect("environment");
    assert_ne!(first, changed_environment);
    input.retry.environment_fingerprint = "env-a".to_owned();
    let renamed = renamed_material_context(context);
    input.pre_observation_discriminator = aid("discriminator-b");
    input.discriminator_evidence = aid("discriminator-b");
    input.intended_strategy = aid("intended-b");
    input.intended_strategy_evidence = aid("intended-b");
    input.attempted_strategy = aid("attempted-b");
    input.attempted_strategy_evidence = aid("attempted-b");
    input.mechanism_evidence = aid("mechanism-b");
    input.probe_evidence = aid("probe-b");
    input.action_plan_evidence = aid("action-plan-b");
    let renamed_fingerprint = canonical_retry_fingerprint(&input, renamed).expect("renamed");
    assert_eq!(first, renamed_fingerprint);
}
