#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, OperationId, PolicyRevision,
    ProductId, RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision,
    sha256_hex,
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
    InverseChange, LearningStateViewRecipe, MemberId, NoChangeReason, OmissionPolicy,
    OwnerDisagreement, OwnerId, ProofCeiling, SlotDisposition, SlotProjection, SlotRequirement,
    SlotSpec, SourceDenominator, ValueState,
};
use eliot_learning_delta::{
    AttemptEvidence, AttemptInvocationBinding, AttemptLearningOutcome, AttemptStatus,
    BeforeSelector, ChangeRequest, DependencyEvidence, DependencyRole, DependencyStatus,
    DerivationContext, DerivationPolicy, EvaluationContext, EvaluatorBinding, EvidenceKind,
    EvidenceReceipt, FrozenPropertyBinding, LearningDeltaError, NoChangeProof, NoChangeRequest,
    NoChangeWitness, OwnerEmptyDeclaration, RefinerDraft, RetryContext, RetryReason,
    SemanticOutcome, SurfacePermission, canonical_retry_fingerprint,
    derive_attempt_learning_outcome,
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
        state_fence: StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("valid test lineage"),
                std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
            )
            .expect("valid test epoch"),
            ResourceGeneration::genesis(),
        ),
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

fn isolated_evaluation_context(
    evaluation: EvaluationContext<'static>,
) -> &'static DerivationContext<'static> {
    Box::leak(Box::new(DerivationContext {
        current: evaluation,
        prior: None,
    }))
}

fn prior_context_with_environment(
    context: &DerivationContext<'static>,
    environment: &str,
) -> &'static DerivationContext<'static> {
    let prior = context.prior.expect("prior context");
    let mut invocation = (*prior.invocation).clone();
    environment.clone_into(&mut invocation.environment_fingerprint);
    let invocation = Box::leak(Box::new(invocation));
    Box::leak(Box::new(DerivationContext {
        current: context.current,
        prior: Some(EvaluationContext {
            invocation,
            ..prior
        }),
    }))
}

fn prior_context_with_mechanism(
    context: &DerivationContext<'static>,
) -> &'static DerivationContext<'static> {
    let prior = context.prior.expect("prior context");
    let mut raw_records = prior.raw_evidence.to_vec();
    let mechanism = raw_records
        .iter_mut()
        .find(|raw| raw.artifact_id == aid("prior-mechanism"))
        .expect("prior mechanism");
    mechanism.bytes = b"changed-prior-mechanism".to_vec();
    mechanism.sha256 = sha256_hex(&mechanism.bytes);
    let raw_records = Box::leak(raw_records.into_boxed_slice());
    Box::leak(Box::new(DerivationContext {
        current: context.current,
        prior: Some(EvaluationContext {
            raw_evidence: raw_records,
            ..prior
        }),
    }))
}

fn prior_fingerprint_input(
    input: &AttemptEvidence,
    prior: EvaluationContext<'static>,
) -> AttemptEvidence {
    let mut prior_input = input.clone();
    prior_input.pre_observation_discriminator = aid("prior-discriminator");
    prior_input.discriminator_evidence = aid("prior-discriminator");
    prior_input.intended_strategy = aid("prior-intended");
    prior_input.intended_strategy_evidence = aid("prior-intended");
    prior_input.attempted_strategy = aid("prior-attempted");
    prior_input.attempted_strategy_evidence = aid("prior-attempted");
    prior_input.mechanism_evidence = aid("prior-mechanism");
    prior_input.probe_evidence = aid("prior-probe");
    prior_input.action_plan_evidence = aid("prior-action-plan");
    prior_input.pre_observation_invocation_id =
        prior.invocation.pre_observation_invocation_id.clone();
    prior_input
        .retry
        .environment_fingerprint
        .clone_from(&prior.invocation.environment_fingerprint);
    prior_input
}

fn configure_distinct_retry(
    input: &mut AttemptEvidence,
    prior: EvaluationContext<'static>,
    fingerprint: String,
) {
    input.retry.prior_attempt = Some(prior.invocation.attempt_id.clone());
    input.retry.prior_fingerprint = Some(fingerprint);
    let mut prior_binding = input.binding.clone();
    prior_binding.request_id = RequestId::new("prior-request").expect("prior request");
    prior_binding.operation_id = OperationId::new("prior-operation").expect("prior operation");
    input.retry.prior_binding = Some(prior_binding);
    input.retry.prior_target = Some(prior.invocation.target.clone());
    input.retry.prior_outcome = Some(prior.binding.pass_outcome);
    input
        .retry
        .prior_evidence
        .clone_from(&prior.run.raw_evidence);
    input.retry.prior_material_evidence = vec![
        aid("prior-discriminator"),
        aid("prior-intended"),
        aid("prior-attempted"),
        aid("prior-mechanism"),
        aid("prior-probe"),
        aid("prior-action-plan"),
    ];
    input.retry.reason = None;
    input.no_change = None;
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
    let (_, view, mut input, context) = base_input("fingerprint");
    let first = canonical_retry_fingerprint(&input, context).expect("fingerprint");
    let second = canonical_retry_fingerprint(&input, context).expect("fingerprint");
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    input.retry.environment_fingerprint = "env-b".to_owned();
    let changed_environment = canonical_retry_fingerprint(&input, context).expect("environment");
    assert_ne!(first, changed_environment);
    input.retry.environment_fingerprint = "env-a".to_owned();

    let prior_environment_context = prior_context(context);
    let prior_environment = prior_environment_context.prior.expect("prior evaluation");
    let changed_environment_context =
        prior_context_with_environment(prior_environment_context, "env-b");
    let changed_environment_prior = changed_environment_context
        .prior
        .expect("prior environment");
    let environment_input = prior_fingerprint_input(&input, changed_environment_prior);
    let environment_claim = canonical_retry_fingerprint(
        &environment_input,
        isolated_evaluation_context(changed_environment_prior),
    )
    .expect("prior environment fingerprint");
    let mut environment_retry = input.clone();
    configure_distinct_retry(&mut environment_retry, prior_environment, environment_claim);
    assert!(matches!(
        derive_attempt_learning_outcome(
            &view,
            &environment_retry,
            changed_environment_context,
            None,
            &policy(SemanticOutcome::Benefit),
        ),
        Ok(AttemptLearningOutcome::Delta(_))
    ));

    let changed_mechanism_context = prior_context_with_mechanism(prior_environment_context);
    let changed_mechanism_prior = changed_mechanism_context.prior.expect("prior mechanism");
    let mut mechanism_input = prior_fingerprint_input(&input, changed_mechanism_prior);
    mechanism_input.mechanism_fingerprint = changed_mechanism_prior
        .raw_evidence
        .iter()
        .find(|raw| raw.artifact_id == aid("prior-mechanism"))
        .expect("changed mechanism")
        .sha256
        .clone();
    let mechanism_claim = canonical_retry_fingerprint(
        &mechanism_input,
        isolated_evaluation_context(changed_mechanism_prior),
    )
    .expect("prior mechanism fingerprint");
    let mut mechanism_retry = input.clone();
    configure_distinct_retry(
        &mut mechanism_retry,
        changed_mechanism_prior,
        mechanism_claim,
    );
    assert!(matches!(
        derive_attempt_learning_outcome(
            &view,
            &mechanism_retry,
            changed_mechanism_context,
            None,
            &policy(SemanticOutcome::Benefit),
        ),
        Ok(AttemptLearningOutcome::Delta(_))
    ));

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

fn controlled_replication_fixture(
    tag: &str,
    reason: RetryReason,
) -> (
    eliot_learning_contracts::CampaignLearningStateView,
    AttemptEvidence,
    &'static DerivationContext<'static>,
    &'static DerivationContext<'static>,
    DerivationPolicy,
) {
    let (_, view, mut input, bare) =
        base_input_with_outcome(tag, SemanticOutcome::MeasuredUnchanged);
    input.changes.clear();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ControlledReplicationNeeded {
            prior_evidence: aid("prior-evaluator"),
            reason,
        },
        affirmative_evidence: vec![aid("prior-evaluator")],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    });
    let context = prior_context(bare);
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
    input.retry.reason = Some(reason);
    (
        view,
        input,
        bare,
        context,
        policy(SemanticOutcome::MeasuredUnchanged),
    )
}

fn empty_slot_view(
    tag: &str,
) -> (
    ContractBinding,
    LearningStateViewRecipe,
    eliot_learning_contracts::CampaignLearningStateView,
    OwnerEmptyDeclaration,
) {
    let binding = binding(tag);
    let target = eliot_learning_contracts::TargetId::new("target-a").expect("target");
    let slot_id = eliot_learning_contracts::SlotId::from_artifact(aid("slot-a"));
    let owner = OwnerId::from_artifact(aid("owner-a"));
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-a"),
        campaign_id: CampaignId::from_artifact(aid("campaign-a")),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![SlotSpec {
            slot_id: slot_id.clone(),
            owner: owner.clone(),
            target: target.clone(),
            requirement: SlotRequirement::Required,
            declared_members: vec![],
            accepted_type: "strategy/v1".to_owned(),
            schema_digest: digest("strategy-schema"),
        }],
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    recipe.seal().expect("recipe seal");
    let source = eliot_learning_contracts::identity::SourceLineage {
        owner: SourceId::new("source-empty").expect("source"),
        snapshot: aid("snapshot-empty"),
        revision: TaskRevision::genesis(),
        digest: digest("source-empty"),
    };
    let mut declaration_binding = binding.clone();
    declaration_binding.source = source.clone();
    let declaration_id = aid("empty-declaration");
    let declaration = OwnerEmptyDeclaration {
        receipt_id: declaration_id.clone(),
        slot_id: slot_id.clone(),
        target: target.clone(),
        owner: owner.clone(),
        source: source.clone(),
        binding: declaration_binding,
    };
    let mut view = eliot_learning_contracts::CampaignLearningStateView {
        view_id: aid("view-a"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target: target.clone(),
        binding: binding.clone(),
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id: slot_id.clone(),
            disposition: SlotDisposition::KnownEmpty,
            members: vec![],
            evidence: vec![declaration_id.clone()],
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
    (binding, recipe, view, declaration)
}

fn empty_slot_fixture(
    tag: &str,
) -> (
    eliot_learning_contracts::CampaignLearningStateView,
    AttemptEvidence,
    &'static DerivationContext<'static>,
    DerivationPolicy,
) {
    let (binding, recipe, view, declaration) = empty_slot_view(tag);
    let target = declaration.target.clone();
    let slot_id = declaration.slot_id.clone();
    let owner = declaration.owner.clone();
    let source = declaration.source.clone();
    let declaration_id = declaration.receipt_id.clone();
    let attempt_id = AgentAttemptId::new(format!("attempt-{tag}")).expect("attempt");
    let before = BeforeSelector::KnownEmpty {
        slot_id: slot_id.clone(),
        owner: owner.clone(),
        source_owner: source.owner.clone(),
        source_snapshot: source.snapshot.clone(),
        source_revision: source.revision,
        source_digest: source.digest.clone(),
        evidence: declaration_id,
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
        SemanticOutcome::Benefit,
        "evaluator-route",
    );
    let change = ChangeRequest {
        target: target.clone(),
        slot_id: slot_id.clone(),
        member_id: None,
        owner: owner.clone(),
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
            inverse: ChangeOperation::Remove {
                target: target.clone(),
                surface: ChangeSurface::Strategy,
                before: ValueState {
                    present: true,
                    digest: Some(digest("after-value")),
                },
            },
        },
        invalidation: aid("invalidation-ref"),
        dependencies: vec![aid("dependency")],
    };
    let mut input = build_attempt_evidence(AttemptFixture {
        recipe: &recipe,
        binding: &binding,
        attempt_id,
        target: target.clone(),
        before,
        change,
        observation,
        evaluator,
        evaluator_outcome: SemanticOutcome::Benefit,
        view: &view,
    });
    input.owner_empty_declarations = vec![declaration];
    for dependency in &mut input.dependency_evidence {
        if dependency.id == aid("invalidation-ref") {
            dependency.role = DependencyRole::Invalidation {
                target: input.target.clone(),
                surface: ChangeSurface::Strategy,
                owner: OwnerId::from_artifact(aid("owner-a")),
                member_id: None,
            };
        }
    }
    let context = build_evaluation_context(&input, &binding, SemanticOutcome::Benefit);
    let mut empty_policy = policy(SemanticOutcome::Benefit);
    empty_policy.surface_permissions.push(SurfacePermission {
        slot_id,
        target,
        owner,
        member_id: None,
        surface: ChangeSurface::Strategy,
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    });
    (view, input, context, empty_policy)
}

fn omission_fixture(
    tag: &str,
    use_frontier: bool,
) -> (
    eliot_learning_contracts::CampaignLearningStateView,
    AttemptEvidence,
    &'static DerivationContext<'static>,
    DerivationPolicy,
) {
    let (_, mut view, mut input, context) = base_input(tag);
    let slot_b = eliot_learning_contracts::SlotId::from_artifact(aid("slot-b"));
    input.recipe.slots.push(SlotSpec {
        slot_id: slot_b.clone(),
        owner: OwnerId::from_artifact(aid("owner-a")),
        target: input.target.clone(),
        requirement: SlotRequirement::Optional,
        declared_members: vec![],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    });
    input.recipe.seal().expect("recipe seal");
    view.recipe_digest
        .clone_from(&input.recipe.canonical_digest);
    view.denominator.declared = 2;
    if use_frontier {
        view.frontier = vec![slot_b];
    } else {
        view.omissions = vec![slot_b];
    }
    view.seal().expect("view seal");
    (view, input, context, policy(SemanticOutcome::Benefit))
}

fn two_change_input(
    tag: &str,
) -> (
    eliot_learning_contracts::CampaignLearningStateView,
    AttemptEvidence,
    &'static DerivationContext<'static>,
    DerivationPolicy,
) {
    let (_, view, mut input, context) = base_input(tag);
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
    let mut two_policy = policy(SemanticOutcome::Benefit);
    two_policy.allowed_surfaces.push(ChangeSurface::Route);
    two_policy.surface_permissions.push(SurfacePermission {
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        target: input.target.clone(),
        owner: OwnerId::from_artifact(aid("owner-a")),
        member_id: Some(MemberId::from_artifact(aid("member-a"))),
        surface: ChangeSurface::Route,
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    });
    (view, input, context, two_policy)
}

fn retarget_surface(
    input: &mut AttemptEvidence,
    surface_policy: &mut DerivationPolicy,
    surface: ChangeSurface,
) {
    let invalidation = input.changes[0].invalidation.clone();
    let change = &mut input.changes[0];
    change.surface = surface;
    if let ChangeOperation::Replace {
        surface: current, ..
    } = &mut change.rollback.inverse
    {
        *current = surface;
    }
    for dependency in &mut input.dependency_evidence {
        if dependency.id == invalidation
            && let DependencyRole::Invalidation {
                surface: current, ..
            } = &mut dependency.role
        {
            *current = surface;
        }
    }
    if !surface_policy.allowed_surfaces.contains(&surface) {
        surface_policy.allowed_surfaces.push(surface);
    }
    surface_policy.surface_permissions.push(SurfacePermission {
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        target: input.target.clone(),
        owner: OwnerId::from_artifact(aid("owner-a")),
        member_id: Some(MemberId::from_artifact(aid("member-a"))),
        surface,
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    });
}

fn prior_with_changed_material(
    context: &'static DerivationContext<'static>,
    material: &str,
    bytes: &[u8],
) -> &'static DerivationContext<'static> {
    let prior = context.prior.expect("prior evaluation");
    let mut raw_records = prior.raw_evidence.to_vec();
    let record = raw_records
        .iter_mut()
        .find(|raw| raw.artifact_id == aid(material))
        .expect("prior material");
    record.bytes = bytes.to_vec();
    record.sha256 = sha256_hex(bytes);
    let raw_records = Box::leak(raw_records.into_boxed_slice());
    Box::leak(Box::new(DerivationContext {
        current: context.current,
        prior: Some(EvaluationContext {
            raw_evidence: raw_records,
            ..prior
        }),
    }))
}

fn no_change_proof_for(reason: NoChangeReason, evaluator: &ArtifactId) -> NoChangeProof {
    match reason {
        NoChangeReason::ConfirmedFixedPrediction => NoChangeProof::ConfirmedFixedPrediction {
            evaluator: evaluator.clone(),
        },
        NoChangeReason::ProtectedConstraint => NoChangeProof::ProtectedConstraint {
            constraint: evaluator.clone(),
        },
        NoChangeReason::ProvenNonApplicability => NoChangeProof::ProvenNonApplicability {
            applicability: evaluator.clone(),
        },
        NoChangeReason::Contradicted => NoChangeProof::Contradicted {
            counterevidence: evaluator.clone(),
        },
        NoChangeReason::UnsafeCandidate => NoChangeProof::UnsafeCandidate {
            policy_evidence: evaluator.clone(),
        },
        NoChangeReason::OwnerBlocked => NoChangeProof::OwnerBlocked {
            owner_receipt: evaluator.clone(),
        },
        NoChangeReason::ExternalReviewRequired => NoChangeProof::ExternalReviewRequired {
            review_requirement: evaluator.clone(),
        },
        NoChangeReason::ControlledReplicationNeeded => NoChangeProof::ControlledReplicationNeeded {
            prior_evidence: evaluator.clone(),
            reason: RetryReason::Replication,
        },
    }
}

fn assert_invalid_no_change_predicate(
    tag: &str,
    evidence: ArtifactId,
    affirmative: Vec<ArtifactId>,
    denominator: SourceDenominator,
    strip_witnesses: bool,
) {
    let (_, view, mut input, context) = base_input_with_outcome(tag, SemanticOutcome::NoEvent);
    input.changes.clear();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ProvenNonApplicability {
            applicability: evidence,
        },
        affirmative_evidence: affirmative,
        denominator,
    });
    let mut no_change_policy = policy(SemanticOutcome::NoEvent);
    if strip_witnesses {
        no_change_policy.no_change_witnesses.clear();
    }
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &no_change_policy),
        Err(LearningDeltaError::InvalidNoChangePredicate)
    );
}

fn no_change_witness_key(reason: NoChangeReason) -> String {
    match reason {
        NoChangeReason::ConfirmedFixedPrediction => "confirmed_fixed_prediction",
        NoChangeReason::ControlledReplicationNeeded => "controlled_replication_needed",
        NoChangeReason::ProtectedConstraint => "protected_constraint",
        NoChangeReason::ProvenNonApplicability => "proven_non_applicability",
        NoChangeReason::Contradicted => "contradicted",
        NoChangeReason::UnsafeCandidate => "unsafe_candidate",
        NoChangeReason::OwnerBlocked => "owner_blocked",
        NoChangeReason::ExternalReviewRequired => "external_review_required",
    }
    .to_owned()
}

// WORK_UNIT_CASE: 616/1
#[test]
fn valid_consequential_attempt_yields_delta() {
    let (_, view, input, context) = base_input("c01-delta");
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("delta");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(delta.base_view_digest, view.canonical_digest);
    assert_eq!(delta.binding, input.binding);
    assert_eq!(delta.attempt_id, input.attempt_id);
    assert_eq!(delta.changes.len(), 1);
    assert_eq!(delta.inverses.len(), 1);
    assert!(delta.inverses[0].is_exact_inverse_of(&delta.changes[0]));
    assert_eq!(delta.evidence, vec![aid("evaluator"), aid("observation")]);
    assert_eq!(delta.evaluator_receipts, vec![aid("evaluator")]);
    assert_eq!(delta.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(delta.canonical_digest.len(), 64);
    assert!(delta.validate_against_view(&view).is_ok());
}

// WORK_UNIT_CASE: 616/2
#[test]
fn valid_consequential_attempt_yields_evidence_backed_no_change() {
    let (_, view, mut input, context) =
        base_input_with_outcome("c02-nochange", SemanticOutcome::Benefit);
    input.changes.clear();
    let evaluator_id = input.evaluator.as_ref().expect("evaluator").id.clone();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ConfirmedFixedPrediction {
            evaluator: evaluator_id.clone(),
        },
        affirmative_evidence: vec![evaluator_id.clone()],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    });
    let mut witness_policy = policy(SemanticOutcome::Benefit);
    witness_policy.no_change_witnesses.insert(
        "confirmed_fixed_prediction".to_owned(),
        NoChangeWitness {
            verifier: ContractId::new("eval-contract").expect("contract"),
            property: "learning-outcome".to_owned(),
            revision: "1".to_owned(),
            outcome: SemanticOutcome::Benefit,
        },
    );
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &witness_policy)
        .expect("no-change");
    let AttemptLearningOutcome::NoChange(disposition) = outcome else {
        panic!("expected no-change")
    };
    assert_eq!(disposition.reason, NoChangeReason::ConfirmedFixedPrediction);
    assert_eq!(disposition.affirmative_evidence, vec![evaluator_id]);
    assert_eq!(
        disposition.denominator,
        SourceDenominator {
            declared: 1,
            observed: 1,
        }
    );
    assert_eq!(disposition.binding, input.binding);
    assert_eq!(disposition.canonical_digest.len(), 64);
    assert!(disposition.validate().is_ok());
}

// WORK_UNIT_CASE: 616/3
#[test]
fn closed_outcome_operation_no_change_and_retry_vocabularies() {
    for surface in [
        ChangeSurface::TaskLocalContext,
        ChangeSurface::Memory,
        ChangeSurface::Skill,
        ChangeSurface::Tool,
        ChangeSurface::Route,
        ChangeSurface::Hypothesis,
        ChangeSurface::Strategy,
        ChangeSurface::Abstraction,
        ChangeSurface::CandidateParent,
        ChangeSurface::VerificationOrder,
        ChangeSurface::SearchProbeStopping,
    ] {
        let (_, view, mut input, context) = base_input("c03-surface");
        let mut surface_policy = policy(SemanticOutcome::Benefit);
        retarget_surface(&mut input, &mut surface_policy, surface);
        let outcome =
            derive_attempt_learning_outcome(&view, &input, context, None, &surface_policy)
                .expect("surface delta");
        assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    }
    let (_, view, input, context) = base_input("c03-replace");
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("replace");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Replace { .. }));
    let (_, view, mut input, context) = base_input("c03-remove");
    input.changes[0].after = ValueState {
        present: false,
        digest: None,
    };
    input.changes[0].rollback.inverse = ChangeOperation::Add {
        target: input.target.clone(),
        surface: ChangeSurface::Strategy,
        after: ValueState {
            present: true,
            digest: Some(digest("before-value")),
        },
    };
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("remove");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Remove { .. }));
    let (view, input, context, add_policy) = empty_slot_fixture("c03-add");
    let outcome =
        derive_attempt_learning_outcome(&view, &input, context, None, &add_policy).expect("add");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Add { .. }));
}

// WORK_UNIT_CASE: 616/4
#[test]
fn no_third_or_empty_success_outcome_with_typed_failures() {
    let (_, view, mut input, context) = base_input("c04-empty");
    input.changes.clear();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "result" })
    );
    let (_, view, mut input, context) = base_input("c04-both");
    let evaluator_id = input.evaluator.as_ref().expect("evaluator").id.clone();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ConfirmedFixedPrediction {
            evaluator: evaluator_id.clone(),
        },
        affirmative_evidence: vec![evaluator_id],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    });
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "result.arms"
        })
    );
    for (status, expected) in [
        (
            AttemptStatus::NonConsequential,
            LearningDeltaError::NonConsequential,
        ),
        (AttemptStatus::Cancelled, LearningDeltaError::Cancelled),
        (AttemptStatus::BoundedOut, LearningDeltaError::BoundedOut),
    ] {
        let (_, view, mut input, context) = base_input("c04-status");
        input.status = status;
        assert_eq!(
            derive_attempt_learning_outcome(
                &view,
                &input,
                context,
                None,
                &policy(SemanticOutcome::Benefit)
            ),
            Err(expected)
        );
    }
    let (_, view, input, context) = base_input("c04-arms");
    match derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("outcome")
    {
        AttemptLearningOutcome::Delta(_) | AttemptLearningOutcome::NoChange(_) => {}
    }
}

// WORK_UNIT_CASE: 616/5
#[test]
fn task_target_scope_fence_and_base_view_mismatch_rejected() {
    let (_, view, mut input, context) = base_input("c05-target");
    input.target = eliot_learning_contracts::TargetId::new("target-other").expect("target");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "view" })
    );
    let (_, view, mut input, context) = base_input("c05-task");
    input.binding.task_id = TaskId::new("task-other").expect("task");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "view" })
    );
    let (_, view, mut input, context) = base_input("c05-scope");
    input.binding.scope = eliot_learning_contracts::WorkScopeId::new("scope-other").expect("scope");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "view" })
    );
    let (_, view, mut input, context) = base_input("c05-fence");
    input.binding.state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(2).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    );
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "view" })
    );
    let (_, view, mut input, context) = base_input("c05-recipe");
    input.recipe.privacy_class = "other-class".to_owned();
    input.recipe.seal().expect("recipe seal");
    assert!(matches!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::Contract(_))
    ));
}

// WORK_UNIT_CASE: 616/6
#[test]
fn before_prediction_and_strategy_frozen_before_observation() {
    let (_, view, mut input, context) = base_input("c06-discriminator");
    input.discriminator_digest = digest("other-discriminator");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "pre_observation.digest"
        })
    );
    let (_, view, mut input, context) = base_input("c06-strategy");
    input.intended_strategy_digest = digest("other-strategy");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "pre_observation.digest"
        })
    );
    let (_, view, input, context) = base_input("c06-raw");
    let mut raws = context.current.raw_evidence.to_vec();
    let record = raws
        .iter_mut()
        .find(|raw| raw.artifact_id == aid("mechanism"))
        .expect("mechanism raw");
    record.bytes = b"tampered-mechanism".to_vec();
    let raws = Box::leak(raws.into_boxed_slice());
    let tampered = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run: context.current.run,
            raw_evidence: raws,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            tampered,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "raw_evidence"
        })
    );
    let (_, view, mut input, context) = base_input("c06-pre");
    input.pre_observation_invocation_id = input_binding_operation(&input.binding);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "attempt_invocation"
        })
    );
    let (_, view, mut input, context) = base_input("c06-env");
    input.retry.environment_fingerprint = "env-b".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "attempt_invocation"
        })
    );
}

// WORK_UNIT_CASE: 616/7
#[test]
fn post_hoc_before_narrative_rejected() {
    let (_, view, mut input, context) = base_input("c07-discriminator");
    input.discriminator_evidence = aid("post-hoc-discriminator");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "attempt.identity"
        })
    );
    let (_, view, mut input, context) = base_input("c07-strategy");
    input.intended_strategy = aid("post-hoc-strategy");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "attempt.identity"
        })
    );
    let (_, view, input, context) = base_input("c07-material");
    let mut raws = context.current.raw_evidence.to_vec();
    let record = raws
        .iter_mut()
        .find(|raw| raw.artifact_id == aid("discriminator-a"))
        .expect("discriminator raw");
    record.invocation_id = input_binding_operation(&input.binding);
    let raws = Box::leak(raws.into_boxed_slice());
    let moved = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run: context.current.run,
            raw_evidence: raws,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            moved,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "pre_observation.digest"
        })
    );
}

// WORK_UNIT_CASE: 616/8
#[test]
fn exact_before_value_with_stale_missing_and_conflicted_base() {
    let (_, view, mut input, context) = base_input("c08-lineage");
    if let BeforeSelector::CurrentMember { source_digest, .. } = &mut input.changes[0].before {
        *source_digest = digest("other-source");
    }
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::BeforeValueUnavailable {
            field: "member.lineage"
        })
    );
    let (_, view, mut input, context) = base_input("c08-member");
    if let BeforeSelector::CurrentMember { member_id, .. } = &mut input.changes[0].before {
        *member_id = MemberId::from_artifact(aid("ghost-member"));
    }
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::BeforeValueUnavailable { field: "selector" })
    );
    for disposition in [SlotDisposition::Stale, SlotDisposition::Conflicted] {
        let (_, mut view, input, context) = base_input("c08-disposition");
        view.slots[0].disposition = disposition;
        view.completeness = Completeness::Partial;
        view.seal().expect("view seal");
        assert_eq!(
            derive_attempt_learning_outcome(
                &view,
                &input,
                context,
                None,
                &policy(SemanticOutcome::Benefit)
            ),
            Err(LearningDeltaError::BeforeValueUnavailable {
                field: "slot.disposition"
            })
        );
    }
    let (_, mut view, input, context) = base_input("c08-invalidated");
    view.invalidated = true;
    view.invalidation_reason = Some("retired".to_owned());
    view.completeness = Completeness::Partial;
    view.seal().expect("view seal");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::BeforeValueUnavailable {
            field: "view.invalidated"
        })
    );
    let (_, mut view, input, context) = base_input("c08-disagreement");
    view.owner_disagreements.push(OwnerDisagreement {
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        owners: vec![
            OwnerId::from_artifact(aid("owner-a")),
            OwnerId::from_artifact(aid("owner-b")),
        ],
        evidence: vec![aid("disagreement-ev")],
    });
    view.seal().expect("view seal");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "view.owner_disagreements"
        })
    );
}

// WORK_UNIT_CASE: 616/9
#[test]
fn every_observation_disposition_is_accounted() {
    for outcome in [
        SemanticOutcome::Benefit,
        SemanticOutcome::Harm,
        SemanticOutcome::NoEvent,
        SemanticOutcome::MeasuredUnchanged,
    ] {
        let (_, view, mut input, context) = base_input("c09-valid");
        input.observations[0].outcome = outcome;
        let result = derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit),
        );
        assert!(
            matches!(result, Ok(AttemptLearningOutcome::Delta(_))),
            "observation {outcome:?} must stay derivable"
        );
    }
    for outcome in [
        SemanticOutcome::Inconclusive,
        SemanticOutcome::Unknown,
        SemanticOutcome::Mixed,
        SemanticOutcome::Missing,
    ] {
        let (_, view, mut input, context) = base_input("c09-unknown");
        input.observations[0].outcome = outcome;
        assert_eq!(
            derive_attempt_learning_outcome(
                &view,
                &input,
                context,
                None,
                &policy(SemanticOutcome::Benefit)
            ),
            Err(LearningDeltaError::InsufficientEvidence { field: "outcome" })
        );
    }
}

// WORK_UNIT_CASE: 616/10
#[test]
fn missing_instrumentation_remains_unknown() {
    let (_, view, mut input, context) = base_input("c10-empty");
    input.observations.clear();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "observations"
        })
    );
    let (_, view, mut input, context) = base_input("c10-evaluator");
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
    let (_, view, mut input, context) = base_input("c10-stu");
    input.stu = None;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "stu" })
    );
    for run_outcome in [
        VerificationOutcome::Partial,
        VerificationOutcome::Unknown,
        VerificationOutcome::Blocked,
        VerificationOutcome::Cancelled,
    ] {
        let (_, view, input, context) = base_input("c10-run");
        let mut run = (*context.current.run).clone();
        run.outcome = run_outcome;
        let run = Box::leak(Box::new(run));
        let partial = Box::leak(Box::new(DerivationContext {
            current: EvaluationContext {
                run,
                raw_evidence: context.current.raw_evidence,
                binding: context.current.binding,
                invocation: context.current.invocation,
            },
            prior: None,
        }));
        assert_eq!(
            derive_attempt_learning_outcome(
                &view,
                &input,
                partial,
                None,
                &policy(SemanticOutcome::Benefit)
            ),
            Err(LearningDeltaError::InsufficientEvidence {
                field: "verification_run.outcome"
            })
        );
    }
    let (_, view, input, context) = base_input("c10-coverage");
    let mut run = (*context.current.run).clone();
    run.coverage = InstrumentCoverage::PartialForScope;
    let run = Box::leak(Box::new(run));
    let partial = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: context.current.raw_evidence,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            partial,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "verification_run"
        })
    );
}

// WORK_UNIT_CASE: 616/11
#[test]
fn non_semantic_reports_cannot_establish_evidence() {
    for kind in [
        EvidenceKind::SelfReport,
        EvidenceKind::ToolResponse,
        EvidenceKind::DeliveryAcknowledgement,
    ] {
        let (_, view, mut input, context) = base_input("c11-report");
        input.observations[0].kind = kind;
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
    }
    let (_, view, mut input, context) = base_input("c11-evaluator");
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
    let (_, view, mut input, context) = base_input("c11-authority");
    input.observations[0].envelope.authority = EvidenceAuthority::ModelInterpretation;
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
}

// WORK_UNIT_CASE: 616/12
#[test]
fn exact_semantic_outcome_and_evaluator_receipt() {
    let (_, view, mut input, context) = base_input("c12-kind");
    input.evaluator.as_mut().expect("evaluator").kind = EvidenceKind::Observation;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "observation.status"
        })
    );
    let (_, view, mut input, context) = base_input("c12-status");
    input.evaluator.as_mut().expect("evaluator").envelope.status = EpistemicStatus::Observed;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "envelope" })
    );
    let (_, view, mut input, context) = base_input("c12-binding");
    input.evaluator_binding = None;
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
    let (_, view, mut input, context) = base_input("c12-fail");
    let mut run = (*context.current.run).clone();
    run.outcome = VerificationOutcome::Fail;
    let run = Box::leak(Box::new(run));
    let failed = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: context.current.raw_evidence,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    input.evaluator.as_mut().expect("evaluator").outcome = SemanticOutcome::Harm;
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        failed,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("fail maps to harm");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    let (_, view, mut input, context) = base_input("c12-observed");
    input.observations[0].envelope.status = EpistemicStatus::Verified;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "envelope" })
    );
}

// WORK_UNIT_CASE: 616/13
#[test]
fn metric_unit_population_and_window_mismatch_rejected() {
    let (_, view, mut input, context) = base_input("c13-metric");
    input.observations[0].metric = "other-metric".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "metric" })
    );
    let (_, view, mut input, context) = base_input("c13-unit");
    input.observations[0].unit = "other-unit".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "metric" })
    );
    let (_, view, mut input, context) = base_input("c13-population");
    input.observations[0].population = "other-population".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "metric" })
    );
    let (_, view, mut input, context) = base_input("c13-window");
    input.observations[0].window = "other-window".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "metric" })
    );
    let (_, view, mut input, context) = base_input("c13-evaluator");
    input.evaluator.as_mut().expect("evaluator").unit = "other-unit".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "metric" })
    );
}

// WORK_UNIT_CASE: 616/14
#[test]
fn benefit_harm_no_event_measured_unchanged_and_unknown_distinct() {
    let (_, view, input, context) =
        base_input_with_outcome("c14-benefit", SemanticOutcome::Benefit);
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("benefit delta");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    let (_, view, input, context) = base_input_with_outcome("c14-harm", SemanticOutcome::Harm);
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Harm),
    )
    .expect("harm delta");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    let (_, view, input, context) =
        base_input_with_outcome("c14-noevent", SemanticOutcome::NoEvent);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::NoEvent)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "delta.evaluator"
        })
    );
    let (_, view, input, context) =
        base_input_with_outcome("c14-unchanged", SemanticOutcome::MeasuredUnchanged);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::MeasuredUnchanged)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "delta.evaluator"
        })
    );
    let (_, view, mut input, context) = base_input("c14-unknown");
    input.evaluator.as_mut().expect("evaluator").outcome = SemanticOutcome::Unknown;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "outcome" })
    );
    let (_, view, mut input, context) = base_input("c14-alone");
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
}

// WORK_UNIT_CASE: 616/15
#[test]
fn baseline_control_confounder_and_independence_enforced() {
    let (_, view, mut input, context) = base_input("c15-mix");
    input.control = vec![aid("baseline")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "control" })
    );
    let (_, view, mut input, context) = base_input("c15-ghost");
    input.baseline = vec![aid("ghost-baseline")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "baseline" })
    );
    let (_, view, mut input, context) = base_input("c15-dup");
    input.baseline = vec![aid("baseline"), aid("baseline")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput { field: "baseline" })
    );
    let (_, view, mut input, context) = base_input("c15-retain");
    let mut run = (*context.current.run).clone();
    run.raw_evidence.push(aid("conf-x"));
    let run = Box::leak(Box::new(run));
    let mut raws = context.current.raw_evidence.to_vec();
    raws.push(raw(&input.binding, "conf-x"));
    let raws = Box::leak(raws.into_boxed_slice());
    let extended = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: raws,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    input.confounders = vec![aid("conf-x")];
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        extended,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("retained references");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(delta.baseline, vec![aid("baseline")]);
    assert_eq!(delta.control, vec![aid("control")]);
    assert_eq!(delta.confounders, vec![aid("conf-x")]);
}

// WORK_UNIT_CASE: 616/16
#[test]
fn correlation_and_before_after_cannot_prove_causal_benefit() {
    let (_, view, mut input, context) = base_input("c16-alone");
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
    let (_, view, input, context) =
        base_input_with_outcome("c16-noevent", SemanticOutcome::NoEvent);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::NoEvent)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "delta.evaluator"
        })
    );
    let (_, view, mut input, context) = base_input("c16-inconclusive");
    input.evaluator.as_mut().expect("evaluator").outcome = SemanticOutcome::Inconclusive;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "outcome" })
    );
    let (_, view, mut input, context) = base_input("c16-harm");
    input.evaluator.as_mut().expect("evaluator").outcome = SemanticOutcome::Harm;
    input.predicted_outcome = SemanticOutcome::Benefit;
    let mut run = (*context.current.run).clone();
    run.outcome = VerificationOutcome::Fail;
    let run = Box::leak(Box::new(run));
    let failed = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: context.current.raw_evidence,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        failed,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("harm stays harm");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
}

// WORK_UNIT_CASE: 616/17
#[test]
fn every_closed_operation_with_invalid_before_after_combinations() {
    let (_, view, input, context) = base_input("c17-replace");
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("replace");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Replace { .. }));
    let (_, view, mut input, context) = base_input("c17-remove");
    input.changes[0].after = ValueState {
        present: false,
        digest: None,
    };
    input.changes[0].rollback.inverse = ChangeOperation::Add {
        target: input.target.clone(),
        surface: ChangeSurface::Strategy,
        after: ValueState {
            present: true,
            digest: Some(digest("before-value")),
        },
    };
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("remove");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Remove { .. }));
    let (view, input, context, add_policy) = empty_slot_fixture("c17-add");
    let outcome =
        derive_attempt_learning_outcome(&view, &input, context, None, &add_policy).expect("add");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Add { .. }));
    let (_, view, mut input, context) = base_input("c17-noop");
    input.changes[0].after = ValueState {
        present: true,
        digest: Some(digest("before-value")),
    };
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "change.noop"
        })
    );
    let (view, mut input, context, add_policy) = empty_slot_fixture("c17-empty");
    input.changes[0].after = ValueState {
        present: false,
        digest: None,
    };
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &add_policy),
        Err(LearningDeltaError::InvalidInput {
            field: "change.empty"
        })
    );
}

// WORK_UNIT_CASE: 616/18
#[test]
fn absence_of_observation_cannot_imply_removal() {
    let (_, view, mut input, context) = base_input("c18-absent");
    input.observations.clear();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "observations"
        })
    );
    let (view, mut input, context, add_policy) = empty_slot_fixture("c18-tombstone");
    input.changes[0].after = ValueState {
        present: false,
        digest: None,
    };
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &add_policy),
        Err(LearningDeltaError::InvalidInput {
            field: "change.empty"
        })
    );
    let (_, view, mut input, context) = base_input("c18-remove");
    input.changes[0].after = ValueState {
        present: false,
        digest: None,
    };
    input.changes[0].rollback.inverse = ChangeOperation::Add {
        target: input.target.clone(),
        surface: ChangeSurface::Strategy,
        after: ValueState {
            present: true,
            digest: Some(digest("before-value")),
        },
    };
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("evidence-backed remove");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert!(matches!(delta.changes[0], ChangeOperation::Remove { .. }));
}

// WORK_UNIT_CASE: 616/19
#[test]
fn change_without_evidence_verifier_rollback_or_invalidation_rejected() {
    let (_, view, mut input, context) = base_input("c19-rollback");
    input.changes[0].rollback.inverse = ChangeOperation::Replace {
        target: input.target.clone(),
        surface: ChangeSurface::Strategy,
        before: ValueState {
            present: true,
            digest: Some(digest("before-value")),
        },
        after: ValueState {
            present: true,
            digest: Some(digest("after-value")),
        },
    };
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "change.rollback"
        })
    );
    let (_, view, mut input, context) = base_input("c19-invalidation");
    input.changes[0].invalidation = aid("ghost-invalidation");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "dependencies.missing"
        })
    );
    let (_, view, mut input, context) = base_input("c19-role");
    input.dependency_evidence[1].role = DependencyRole::Supporting;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "invalidation.role"
        })
    );
    let (_, view, mut input, context) = base_input("c19-evaluator");
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
    let (_, view, mut input, context) = base_input("c19-support");
    input.dependency_evidence[0].role = DependencyRole::Invalidation {
        target: input.target.clone(),
        surface: ChangeSurface::Strategy,
        owner: OwnerId::from_artifact(aid("owner-a")),
        member_id: Some(MemberId::from_artifact(aid("member-a"))),
    };
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "dependency.role"
        })
    );
}

// WORK_UNIT_CASE: 616/20
#[test]
fn protected_objective_acceptance_and_authority_surfaces_rejected() {
    let (_, view, mut input, context) = base_input("c20-memory");
    let mut closed_policy = policy(SemanticOutcome::Benefit);
    retarget_surface(&mut input, &mut closed_policy, ChangeSurface::Memory);
    closed_policy
        .allowed_surfaces
        .retain(|surface| *surface != ChangeSurface::Memory);
    closed_policy
        .surface_permissions
        .retain(|permission| permission.surface != ChangeSurface::Memory);
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &closed_policy),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c20-type");
    input.changes[0].accepted_type = "evil/v9".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, mut view, input, context) = base_input("c20-required");
    view.required_references.push(aid("invalidation-ref"));
    view.seal().expect("view seal");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c20-hypothesis");
    let mut closed_policy = policy(SemanticOutcome::Benefit);
    retarget_surface(&mut input, &mut closed_policy, ChangeSurface::Hypothesis);
    closed_policy
        .allowed_surfaces
        .retain(|surface| *surface != ChangeSurface::Hypothesis);
    closed_policy
        .surface_permissions
        .retain(|permission| permission.surface != ChangeSurface::Hypothesis);
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &closed_policy),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c20-member");
    input.changes[0].member_id = None;
    for dependency in &mut input.dependency_evidence {
        if dependency.id == input.changes[0].invalidation.clone()
            && let DependencyRole::Invalidation { member_id, .. } = &mut dependency.role
        {
            *member_id = None;
        }
    }
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
}

// WORK_UNIT_CASE: 616/21
#[test]
fn generic_json_and_field_path_patches_rejected() {
    let (_, view, mut input, context) = base_input("c21-patch");
    input.changes[0].accepted_type = "json-patch/v1".to_owned();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c21-schema");
    input.changes[0].schema_digest = digest("other-schema");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c21-empty");
    input.changes[0].accepted_type = String::new();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c21-member");
    input.changes[0].member_id = Some(MemberId::from_artifact(aid("other-member")));
    for dependency in &mut input.dependency_evidence {
        if dependency.id == input.changes[0].invalidation.clone()
            && let DependencyRole::Invalidation { member_id, .. } = &mut dependency.role
        {
            *member_id = Some(MemberId::from_artifact(aid("other-member")));
        }
    }
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::ProtectedSurface)
    );
    let (_, view, mut input, context) = base_input("c21-untyped");
    input.changes[0].after = ValueState {
        present: true,
        digest: Some("not-a-hex-digest".to_owned()),
    };
    assert!(matches!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::Contract(_))
    ));
}

// WORK_UNIT_CASE: 616/22
#[test]
fn materially_equivalent_retry_is_detected_exactly() {
    let (view, input, _, context, retry_policy) =
        controlled_replication_fixture("c22-equiv", RetryReason::Replication);
    let current = canonical_retry_fingerprint(&input, context).expect("current");
    assert_eq!(
        input.retry.prior_fingerprint.as_deref(),
        Some(current.as_str())
    );
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &retry_policy)
        .expect("equivalent");
    let AttemptLearningOutcome::NoChange(disposition) = outcome else {
        panic!("expected no-change")
    };
    assert_eq!(
        disposition.reason,
        NoChangeReason::ControlledReplicationNeeded
    );
}

// WORK_UNIT_CASE: 616/23
#[test]
fn superficial_wording_and_order_edits_remain_equivalent() {
    let (_, _, input, context) = base_input("c23-wording");
    let first = canonical_retry_fingerprint(&input, context).expect("fingerprint");
    let renamed = renamed_material_context(context);
    let mut renamed_input = input.clone();
    renamed_input.pre_observation_discriminator = aid("discriminator-b");
    renamed_input.discriminator_evidence = aid("discriminator-b");
    renamed_input.intended_strategy = aid("intended-b");
    renamed_input.intended_strategy_evidence = aid("intended-b");
    renamed_input.attempted_strategy = aid("attempted-b");
    renamed_input.attempted_strategy_evidence = aid("attempted-b");
    renamed_input.mechanism_evidence = aid("mechanism-b");
    renamed_input.probe_evidence = aid("probe-b");
    renamed_input.action_plan_evidence = aid("action-plan-b");
    let renamed_fingerprint =
        canonical_retry_fingerprint(&renamed_input, renamed).expect("renamed");
    assert_eq!(first, renamed_fingerprint);
    let (_, view, mut input, context) = base_input("c23-derive");
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
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        renamed,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("renamed delta");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
}

// WORK_UNIT_CASE: 616/24
#[test]
fn material_mechanism_probe_and_environment_change_is_distinct() {
    let (_, view, input, context) = base_input("c24-base");
    let bare_policy = policy(SemanticOutcome::Benefit);
    for (material, bytes) in [
        ("prior-mechanism", b"changed-prior-mechanism".as_slice()),
        ("prior-probe", b"changed-prior-probe".as_slice()),
        ("prior-action-plan", b"changed-prior-action-plan".as_slice()),
    ] {
        let seeded = prior_context(context);
        let changed = prior_with_changed_material(seeded, material, bytes);
        let prior_eval = changed.prior.expect("prior evaluation");
        let mut claim_input = prior_fingerprint_input(&input, prior_eval);
        let changed_sha = prior_eval
            .raw_evidence
            .iter()
            .find(|raw| raw.artifact_id == aid(material))
            .expect("changed material")
            .sha256
            .clone();
        if material == "prior-mechanism" {
            claim_input.mechanism_fingerprint = changed_sha;
        } else if material == "prior-probe" {
            claim_input.probe_fingerprint = changed_sha;
        } else {
            claim_input.action_plan_fingerprint = changed_sha;
        }
        let claim =
            canonical_retry_fingerprint(&claim_input, isolated_evaluation_context(prior_eval))
                .expect("prior claim");
        let current = canonical_retry_fingerprint(&input, changed).expect("current");
        assert_ne!(claim, current);
        let mut distinct = input.clone();
        configure_distinct_retry(&mut distinct, prior_eval, claim);
        let outcome =
            derive_attempt_learning_outcome(&view, &distinct, changed, None, &bare_policy)
                .expect("distinct delta");
        assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    }
}

// WORK_UNIT_CASE: 616/25
#[test]
fn controlled_replication_needs_an_allowed_reason() {
    for reason in [
        RetryReason::Replication,
        RetryReason::NoiseEstimation,
        RetryReason::ControlledComparison,
        RetryReason::ExactReproduction,
        RetryReason::RecoveryProof,
        RetryReason::VerifierCalibration,
    ] {
        let (view, input, _, context, retry_policy) =
            controlled_replication_fixture("c25-allowed", reason);
        let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &retry_policy)
            .expect("allowed");
        assert!(matches!(outcome, AttemptLearningOutcome::NoChange(_)));
    }
    let (view, mut denied, _, context, retry_policy) =
        controlled_replication_fixture("c25-denied", RetryReason::NoiseEstimation);
    denied.retry.reason = None;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &denied, context, None, &retry_policy),
        Err(LearningDeltaError::EquivalentRetryRequiresReason)
    );
}

// WORK_UNIT_CASE: 616/26
#[test]
fn unknown_prior_effect_blocks_blind_retry() {
    let (view, input, bare, full, retry_policy) =
        controlled_replication_fixture("c26-base", RetryReason::Replication);
    let mut wrong = input.clone();
    wrong.retry.prior_fingerprint = Some("0".repeat(64));
    assert_eq!(
        derive_attempt_learning_outcome(&view, &wrong, full, None, &retry_policy),
        Err(LearningDeltaError::UnknownPriorEffect)
    );
    let mut mismatched = input.clone();
    mismatched.retry.prior_outcome = Some(SemanticOutcome::Benefit);
    assert_eq!(
        derive_attempt_learning_outcome(&view, &mismatched, full, None, &retry_policy),
        Err(LearningDeltaError::UnknownPriorEffect)
    );
    let mut unbound = input.clone();
    unbound.retry.prior_binding = None;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &unbound, full, None, &retry_policy),
        Err(LearningDeltaError::UnknownPriorEffect)
    );
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, bare, None, &retry_policy),
        Err(LearningDeltaError::UnknownPriorEffect)
    );
    let mut short = input.clone();
    short.retry.prior_material_evidence.pop();
    assert_eq!(
        derive_attempt_learning_outcome(&view, &short, full, None, &retry_policy),
        Err(LearningDeltaError::UnknownPriorEffect)
    );
}

// WORK_UNIT_CASE: 616/27
#[test]
fn dependency_dag_valid_missing_cyclic_and_partial() {
    let (_, view, mut input, context) = base_input("c27-valid");
    input.dependency_evidence[0].depends_on = vec![aid("dependency-child")];
    input.dependency_evidence.push(DependencyEvidence {
        id: aid("dependency-child"),
        binding: input.binding.clone(),
        source_digest: input.binding.source.digest.clone(),
        status: DependencyStatus::Current,
        role: DependencyRole::Supporting,
        depends_on: vec![],
    });
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("chained dependencies");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    let (_, view, mut input, context) = base_input("c27-missing");
    input.changes[0].dependencies = vec![aid("ghost-dependency")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "dependencies.missing"
        })
    );
    let (_, view, mut input, context) = base_input("c27-self");
    input.dependency_evidence[0].depends_on = vec![aid("dependency")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "dependencies.cycle"
        })
    );
    let (_, view, mut input, context) = base_input("c27-cycle");
    input.dependency_evidence.push(DependencyEvidence {
        id: aid("dependency-b"),
        binding: input.binding.clone(),
        source_digest: input.binding.source.digest.clone(),
        status: DependencyStatus::Current,
        role: DependencyRole::Supporting,
        depends_on: vec![aid("dependency")],
    });
    input.dependency_evidence[0].depends_on = vec![aid("dependency-b")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "dependencies.cycle"
        })
    );
    let (_, view, mut input, context) = base_input("c27-partial");
    input.dependency_evidence[0].depends_on = vec![aid("ghost-transitive")];
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "dependencies"
        })
    );
    let (_, view, mut input, context) = base_input("c27-stale");
    input.dependency_evidence[0].status = DependencyStatus::Stale;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "dependencies"
        })
    );
}

// WORK_UNIT_CASE: 616/28
#[test]
fn competing_values_preserved_without_last_write_wins() {
    let (_, view, mut input, context) = base_input("c28-conflict");
    let duplicate = input.changes[0].clone();
    input.changes.push(duplicate);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "changes.target_conflict"
        })
    );
    let (view, input, context, two_policy) = two_change_input("c28-coexist");
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &two_policy)
        .expect("compatible units coexist");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(delta.changes.len(), 2);
    assert!(matches!(
        delta.changes[0],
        ChangeOperation::Replace {
            surface: ChangeSurface::Route,
            ..
        }
    ));
    assert!(matches!(
        delta.changes[1],
        ChangeOperation::Replace {
            surface: ChangeSurface::Strategy,
            ..
        }
    ));
    for (operation, inverse) in delta.changes.iter().zip(delta.inverses.iter()) {
        assert!(inverse.is_exact_inverse_of(operation));
    }
    let (_, mut view, input, context) = base_input("c28-disagreement");
    view.owner_disagreements.push(OwnerDisagreement {
        slot_id: eliot_learning_contracts::SlotId::from_artifact(aid("slot-a")),
        owners: vec![
            OwnerId::from_artifact(aid("owner-a")),
            OwnerId::from_artifact(aid("owner-b")),
        ],
        evidence: vec![aid("disagreement-ev")],
    });
    view.seal().expect("view seal");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "view.owner_disagreements"
        })
    );
}

// WORK_UNIT_CASE: 616/29
#[test]
fn valid_no_change_reasons_and_insufficient_evidence_not_converted() {
    for reason in [
        NoChangeReason::ConfirmedFixedPrediction,
        NoChangeReason::ProtectedConstraint,
        NoChangeReason::ProvenNonApplicability,
        NoChangeReason::Contradicted,
        NoChangeReason::UnsafeCandidate,
        NoChangeReason::OwnerBlocked,
        NoChangeReason::ExternalReviewRequired,
    ] {
        let (_, view, mut input, context) =
            base_input_with_outcome("c29-valid", SemanticOutcome::Harm);
        input.changes.clear();
        let evaluator_id = input.evaluator.as_ref().expect("evaluator").id.clone();
        input.no_change = Some(NoChangeRequest {
            proof: no_change_proof_for(reason, &evaluator_id),
            affirmative_evidence: vec![evaluator_id],
            denominator: SourceDenominator {
                declared: 1,
                observed: 1,
            },
        });
        let mut reason_policy = policy(SemanticOutcome::Harm);
        reason_policy.no_change_witnesses.insert(
            no_change_witness_key(reason),
            NoChangeWitness {
                verifier: ContractId::new("eval-contract").expect("contract"),
                property: "learning-outcome".to_owned(),
                revision: "1".to_owned(),
                outcome: SemanticOutcome::Harm,
            },
        );
        let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &reason_policy)
            .expect("valid reason");
        let AttemptLearningOutcome::NoChange(disposition) = outcome else {
            panic!("expected no-change")
        };
        assert_eq!(disposition.reason, reason);
    }
    let (view, input, _, context, retry_policy) =
        controlled_replication_fixture("c29-controlled", RetryReason::Replication);
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &retry_policy)
        .expect("controlled");
    let AttemptLearningOutcome::NoChange(disposition) = outcome else {
        panic!("expected no-change")
    };
    assert_eq!(
        disposition.reason,
        NoChangeReason::ControlledReplicationNeeded
    );
    assert_invalid_no_change_predicate(
        "c29-denominator",
        aid("evaluator"),
        vec![aid("evaluator")],
        SourceDenominator {
            declared: 2,
            observed: 1,
        },
        false,
    );
    assert_invalid_no_change_predicate(
        "c29-affirmative",
        aid("ghost-evidence"),
        vec![aid("ghost-evidence")],
        SourceDenominator {
            declared: 1,
            observed: 1,
        },
        false,
    );
    assert_invalid_no_change_predicate(
        "c29-witness",
        aid("evaluator"),
        vec![aid("evaluator")],
        SourceDenominator {
            declared: 1,
            observed: 1,
        },
        true,
    );
}

// WORK_UNIT_CASE: 616/30
#[test]
fn complete_and_partial_observation_and_change_denominators() {
    let (_, view, mut input, context) =
        base_input_with_outcome("c30-declared", SemanticOutcome::NoEvent);
    input.changes.clear();
    let evaluator_id = input.evaluator.as_ref().expect("evaluator").id.clone();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ProvenNonApplicability {
            applicability: evaluator_id.clone(),
        },
        affirmative_evidence: vec![evaluator_id],
        denominator: SourceDenominator {
            declared: 2,
            observed: 2,
        },
    });
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::NoEvent)
        ),
        Err(LearningDeltaError::InvalidNoChangePredicate)
    );
    let (_, view, mut input, context) =
        base_input_with_outcome("c30-zero", SemanticOutcome::NoEvent);
    input.changes.clear();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ProvenNonApplicability {
            applicability: aid("unused"),
        },
        affirmative_evidence: vec![],
        denominator: SourceDenominator {
            declared: 0,
            observed: 0,
        },
    });
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::NoEvent)
        ),
        Err(LearningDeltaError::InvalidNoChangePredicate)
    );
    let (_, mut view, input, context) = base_input("c30-view");
    view.denominator.declared = 99;
    view.seal().expect("view seal");
    assert!(matches!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::Contract(_))
    ));
    let (_, view, input, context) = base_input("c30-run");
    let mut run = (*context.current.run).clone();
    run.coverage = InstrumentCoverage::PartialForScope;
    let run = Box::leak(Box::new(run));
    let partial = Box::leak(Box::new(DerivationContext {
        current: EvaluationContext {
            run,
            raw_evidence: context.current.raw_evidence,
            binding: context.current.binding,
            invocation: context.current.invocation,
        },
        prior: None,
    }));
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            partial,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "verification_run"
        })
    );
    let (_, view, mut input, context) = base_input("c30-envelope");
    input.observations[0].envelope.coverage = EvidenceCoverage::PartialForScope;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "coverage" })
    );
}

// WORK_UNIT_CASE: 616/31
#[test]
fn every_independent_bound_with_exact_omitted_frontier() {
    let (_, view, input, context) = base_input("c31-evidence");
    let mut tight_policy = policy(SemanticOutcome::Benefit);
    tight_policy.max_evidence = 1;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &tight_policy),
        Err(LearningDeltaError::Bound { field: "evidence" })
    );
    let (_, view, mut input, context) = base_input("c31-references");
    input.retry.prior_evidence = vec![
        aid("retry-a"),
        aid("retry-b"),
        aid("retry-c"),
        aid("retry-d"),
        aid("retry-e"),
        aid("retry-f"),
        aid("retry-g"),
        aid("retry-h"),
        aid("retry-i"),
        aid("retry-j"),
        aid("retry-k"),
    ];
    let mut tight_policy = policy(SemanticOutcome::Benefit);
    tight_policy.max_references = 10;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &tight_policy),
        Err(LearningDeltaError::Bound {
            field: "retry.evidence"
        })
    );
    let (_, view, input, context) = base_input("c31-source");
    let mut tight_policy = policy(SemanticOutcome::Benefit);
    tight_policy.max_source_units = 1;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &tight_policy),
        Err(LearningDeltaError::Bound { field: "input" })
    );
    let (_, view, mut input, context) = base_input("c31-stu");
    input.stu = Some(2);
    let mut tight_policy = policy(SemanticOutcome::Benefit);
    tight_policy.max_stu = 1;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &tight_policy),
        Err(LearningDeltaError::Bound {
            field: "measured_limits"
        })
    );
    let (_, view, input, context) = base_input("c31-output");
    let mut tight_policy = policy(SemanticOutcome::Benefit);
    tight_policy.max_output_bytes = 10;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &tight_policy),
        Err(LearningDeltaError::Bound { field: "output" })
    );
    let (_, view, input, context) = base_input("c31-input");
    let mut tight_policy = policy(SemanticOutcome::Benefit);
    tight_policy.max_input_bytes = 64;
    assert!(matches!(
        derive_attempt_learning_outcome(&view, &input, context, None, &tight_policy),
        Err(LearningDeltaError::Bound { .. })
    ));
    let (view, input, context, omission_policy) = omission_fixture("c31-omitted", false);
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &omission_policy)
        .expect("omitted slot derives");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(delta.base_view_digest, view.canonical_digest);
    let (view, input, context, frontier_policy) = omission_fixture("c31-frontier", true);
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &frontier_policy)
        .expect("frontier slot derives");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
}

// WORK_UNIT_CASE: 616/32
#[test]
fn replay_and_changed_same_id_request_evidence_or_policy_conflict() {
    let (_, view, input, context) = base_input("c32-replay");
    let first = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("first replay");
    let second = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("second replay");
    assert_eq!(first, second);
    let (_, view, mut input, context) = base_input("c32-duplicate");
    let duplicate = input.observations[0].clone();
    input.observations.push(duplicate);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "evidence.receipts"
        })
    );
    let (_, view, input, context) = base_input("c32-policy");
    let mut revised_policy = policy(SemanticOutcome::Benefit);
    revised_policy.revision = revised_policy.revision.next().expect("policy revision");
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &revised_policy),
        Err(LearningDeltaError::EvidenceBinding {
            field: "policy_revision"
        })
    );
    let (_, view, mut input, context) = base_input("c32-digest");
    input.observations[0].source_digest = digest("changed-source");
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "raw_evidence.digest"
        })
    );
}

// WORK_UNIT_CASE: 616/33
#[test]
fn randomized_set_like_input_order_yields_identical_output() {
    let (view, input, context, two_policy) = two_change_input("c33-order");
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &two_policy)
        .expect("ordered");
    let AttemptLearningOutcome::Delta(ordered) = outcome else {
        panic!("expected delta")
    };
    let (view, mut swapped, context, two_policy) = two_change_input("c33-order");
    swapped.changes.reverse();
    let outcome = derive_attempt_learning_outcome(&view, &swapped, context, None, &two_policy)
        .expect("swapped");
    let AttemptLearningOutcome::Delta(reordered) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(ordered.canonical_digest, reordered.canonical_digest);
    let (_, view, mut input, context) =
        base_input_with_outcome("c33-affirmative", SemanticOutcome::NoEvent);
    input.changes.clear();
    let evaluator_id = input.evaluator.as_ref().expect("evaluator").id.clone();
    let observation_id = input.observations[0].id.clone();
    input.no_change = Some(NoChangeRequest {
        proof: NoChangeProof::ProvenNonApplicability {
            applicability: evaluator_id.clone(),
        },
        affirmative_evidence: vec![evaluator_id.clone(), observation_id.clone()],
        denominator: SourceDenominator {
            declared: 2,
            observed: 2,
        },
    });
    let mut wide_policy = policy(SemanticOutcome::NoEvent);
    wide_policy.no_change_witnesses.insert(
        "proven_non_applicability".to_owned(),
        NoChangeWitness {
            verifier: ContractId::new("eval-contract").expect("contract"),
            property: "learning-outcome".to_owned(),
            revision: "1".to_owned(),
            outcome: SemanticOutcome::NoEvent,
        },
    );
    wide_policy.no_change_witnesses.insert(
        "other_witness".to_owned(),
        NoChangeWitness {
            verifier: ContractId::new("eval-contract").expect("contract"),
            property: "learning-outcome".to_owned(),
            revision: "1".to_owned(),
            outcome: SemanticOutcome::NoEvent,
        },
    );
    let first = derive_attempt_learning_outcome(&view, &input, context, None, &wide_policy)
        .expect("affirmative order");
    input
        .no_change
        .as_mut()
        .expect("no-change")
        .affirmative_evidence
        .reverse();
    let second = derive_attempt_learning_outcome(&view, &input, context, None, &wide_policy)
        .expect("reversed affirmative");
    assert_eq!(first, second);
    let (_, view, mut input, context) = base_input("c33-dependencies");
    input.dependency_evidence.reverse();
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("reversed dependencies");
    let AttemptLearningOutcome::Delta(reordered) = outcome else {
        panic!("expected delta")
    };
    let (_, view, input, context) = base_input("c33-dependencies");
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("ordered dependencies");
    let AttemptLearningOutcome::Delta(ordered) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(ordered.canonical_digest, reordered.canonical_digest);
}

// WORK_UNIT_CASE: 616/34
#[test]
fn bounded_malformed_input_never_panics() {
    let (_, view, mut input, context) = base_input("c34-digest");
    input.intended_strategy_digest = "z".repeat(64);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "intended_strategy_digest"
        })
    );
    let (_, view, mut input, context) = base_input("c34-duplicate");
    let duplicate = input.observations[0].clone();
    input.observations.push(duplicate);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "evidence.receipts"
        })
    );
    let (_, view, mut input, context) = base_input("c34-empty");
    input.changes.clear();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "result" })
    );
    let (_, view, input, context) = base_input("c34-policy");
    let mut empty_policy = policy(SemanticOutcome::Benefit);
    empty_policy.max_evidence = 0;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &empty_policy),
        Err(LearningDeltaError::Bound { field: "policy" })
    );
    let (_, view, input, context) = base_input("c34-metric");
    let mut metric_policy = policy(SemanticOutcome::Benefit);
    metric_policy.metric = String::new();
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &metric_policy),
        Err(LearningDeltaError::InvalidInput {
            field: "policy.metric"
        })
    );
    let (_, view, mut input, context) = base_input("c34-stu");
    input.stu = None;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence { field: "stu" })
    );
    let (_, view, mut input, context) = base_input("c34-cost");
    input.cost_units = 9_000;
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::Bound {
            field: "measured_limits"
        })
    );
    let (_, view, mut input, context) = base_input("c34-invocation");
    input.pre_observation_invocation_id = input_binding_operation(&input.binding);
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding {
            field: "attempt_invocation"
        })
    );
}

// WORK_UNIT_CASE: 616/35
#[test]
fn every_delta_unit_has_before_evidence_verifier_and_rollback() {
    let (view, mut input, context, two_policy) = two_change_input("c35-rollback");
    input.changes[1].rollback.inverse = ChangeOperation::Replace {
        target: input.target.clone(),
        surface: ChangeSurface::Route,
        before: ValueState {
            present: true,
            digest: Some(digest("before-value")),
        },
        after: ValueState {
            present: true,
            digest: Some(digest("after-value")),
        },
    };
    assert_eq!(
        derive_attempt_learning_outcome(&view, &input, context, None, &two_policy),
        Err(LearningDeltaError::InvalidInput {
            field: "change.rollback"
        })
    );
    let (_, view, mut input, context) = base_input("c35-verifier");
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
    let (_, view, mut input, context) = base_input("c35-before");
    if let BeforeSelector::CurrentMember { source_digest, .. } = &mut input.changes[0].before {
        *source_digest = digest("other-source");
    }
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::BeforeValueUnavailable {
            field: "member.lineage"
        })
    );
    let (view, input, context, two_policy) = two_change_input("c35-complete");
    let outcome = derive_attempt_learning_outcome(&view, &input, context, None, &two_policy)
        .expect("complete units");
    let AttemptLearningOutcome::Delta(delta) = outcome else {
        panic!("expected delta")
    };
    assert_eq!(delta.changes.len(), 2);
    assert!(!delta.evidence.is_empty());
    assert!(!delta.evaluator_receipts.is_empty());
    for (operation, inverse) in delta.changes.iter().zip(delta.inverses.iter()) {
        assert!(inverse.is_exact_inverse_of(operation));
    }
}

// WORK_UNIT_CASE: 616/36
#[test]
fn every_valid_input_yields_exactly_one_top_level_outcome() {
    let (_, view, input, context) = base_input("c36-delta");
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("delta");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    assert!(!matches!(outcome, AttemptLearningOutcome::NoChange(_)));
    let (_, view, mut input, context) =
        base_input_with_outcome("c36-nochange", SemanticOutcome::NoEvent);
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
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::NoEvent),
    )
    .expect("no-change");
    assert!(matches!(outcome, AttemptLearningOutcome::NoChange(_)));
    assert!(!matches!(outcome, AttemptLearningOutcome::Delta(_)));
    let (_, view, input, context) = base_input_with_outcome("c36-harm", SemanticOutcome::Harm);
    let outcome = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Harm),
    )
    .expect("harm delta");
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    let (_, view, input, context) = base_input("c36-replay");
    let first = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("first");
    let second = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("second");
    assert_eq!(first, second);
}

// WORK_UNIT_CASE: 616/37
#[test]
fn removing_load_bearing_receipt_or_changing_base_invalidates_digest() {
    let (_, view, input, context) = base_input("c37-stable");
    let first = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("stable");
    let AttemptLearningOutcome::Delta(stable) = &first else {
        panic!("expected delta")
    };
    assert!(!stable.canonical_digest.is_empty());
    let second = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("replay");
    let AttemptLearningOutcome::Delta(replayed) = &second else {
        panic!("expected delta")
    };
    assert_eq!(stable.canonical_digest, replayed.canonical_digest);
    let (_, view, mut input, context) = base_input("c37-remove");
    input.observations.clear();
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InsufficientEvidence {
            field: "observations"
        })
    );
    let (_, view, mut input, context) = base_input("c37-fence");
    input.binding.state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(2).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    );
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::EvidenceBinding { field: "view" })
    );
    let (_, mut view, input, context) = base_input("c37-digest");
    view.canonical_digest = "0".repeat(64);
    assert!(matches!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            None,
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::Contract(_))
    ));
}

// WORK_UNIT_CASE: 616/38
#[test]
fn equivalent_retry_cannot_become_an_ordinary_delta() {
    let (view, input, _, context, retry_policy) =
        controlled_replication_fixture("c38-base", RetryReason::Replication);
    let (_, _, transplant, _) =
        base_input_with_outcome("c38-base", SemanticOutcome::MeasuredUnchanged);
    let mut with_changes = input.clone();
    with_changes.changes = transplant.changes.clone();
    with_changes.no_change = None;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &with_changes, context, None, &retry_policy),
        Err(LearningDeltaError::InvalidInput {
            field: "retry.delta"
        })
    );
    let mut without_arm = input.clone();
    without_arm.no_change = None;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &without_arm, context, None, &retry_policy),
        Err(LearningDeltaError::InsufficientEvidence { field: "result" })
    );
    let mut without_reason = input.clone();
    without_reason.retry.reason = None;
    without_reason.changes = transplant.changes.clone();
    without_reason.no_change = None;
    assert_eq!(
        derive_attempt_learning_outcome(&view, &without_reason, context, None, &retry_policy),
        Err(LearningDeltaError::EquivalentRetryRequiresReason)
    );
}

// WORK_UNIT_CASE: 616/39
#[test]
fn no_state_view_producer_refiner_or_promotion_path() {
    let (_, view, input, context) = base_input("c39-pure");
    let reference = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        None,
        &policy(SemanticOutcome::Benefit),
    )
    .expect("reference");
    let draft = RefinerDraft {
        artifact: aid("refiner-draft"),
        route: "refiner-route".to_owned(),
        receipt: aid("evaluator"),
    };
    let with_draft = derive_attempt_learning_outcome(
        &view,
        &input,
        context,
        Some(&draft),
        &policy(SemanticOutcome::Benefit),
    )
    .expect("draft is references only");
    assert_eq!(reference, with_draft);
    let bad = RefinerDraft {
        artifact: aid("refiner-draft"),
        route: String::new(),
        receipt: aid("evaluator"),
    };
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &input,
            context,
            Some(&bad),
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput { field: "refiner" })
    );
    let mut conflicted = input.clone();
    conflicted.refiner = Some(RefinerDraft {
        artifact: aid("other-draft"),
        route: "refiner-route".to_owned(),
        receipt: aid("evaluator"),
    });
    assert_eq!(
        derive_attempt_learning_outcome(
            &view,
            &conflicted,
            context,
            Some(&draft),
            &policy(SemanticOutcome::Benefit)
        ),
        Err(LearningDeltaError::InvalidInput {
            field: "refiner.binding"
        })
    );
    let AttemptLearningOutcome::Delta(candidate) = reference else {
        panic!("expected delta")
    };
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert!(candidate.equivalent_retry.is_none());
    assert_eq!(input.binding.proof_ceiling, ProofCeiling::CandidateArtifact);
}
