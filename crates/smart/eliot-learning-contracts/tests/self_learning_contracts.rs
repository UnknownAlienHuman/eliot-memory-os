use eliot_agent_contracts::{AgentAttemptId, TargetId};
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_learning_contracts::{
    AssessmentDimension, AssignmentKind, AttributedSubject, CausalCeiling, ClosureHandoff,
    ContractBinding, DimensionAssessment, DimensionStatus, ExternalDecisionClass, HistoryRetention,
    ImprovementExperimentCandidate, LearningContractError, NonUseDeclaration, OwnerId, OwnerProof,
    PromotionBoundaryCandidate, PromotionMutationTarget, RolloutBoundary, SourceDenominator,
    SubjectKind, UseAttributionCandidate, UseBasis, UseDisposition,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn aid(value: &str) -> Result<ArtifactId, Box<dyn std::error::Error>> {
    Ok(ArtifactId::new(value)?)
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn target(value: &str) -> Result<TargetId, Box<dyn std::error::Error>> {
    Ok(TargetId::new(value)?)
}

fn binding(tag: &str) -> Result<ContractBinding, Box<dyn std::error::Error>> {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
    let sequence = std::num::NonZeroU64::new(1).ok_or("nonzero test sequence")?;
    Ok(ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new(format!("request-self-{tag}"))?,
        operation_id: OperationId::new(format!("operation-self-{tag}"))?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new(format!("task-self-{tag}"))?,
        scope: WorkScopeId::new(format!("scope-self-{tag}"))?,
        state_fence: StateFence::new(
            EpochId::new(lineage, sequence).map_err(|_| "valid test epoch")?,
            ResourceGeneration::genesis(),
        ),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new(format!("source-self-{tag}"))?,
            snapshot: aid(&format!("snapshot-self-{tag}"))?,
            revision: TaskRevision::genesis(),
            digest: digest("source"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn dimension(
    dimension: AssessmentDimension,
    status: DimensionStatus,
    tag: &str,
) -> Result<DimensionAssessment, Box<dyn std::error::Error>> {
    let established = matches!(
        status,
        DimensionStatus::Pass
            | DimensionStatus::Fail
            | DimensionStatus::Harm
            | DimensionStatus::NoEffect
    );
    let (evidence, owner_receipt) = if established {
        (
            vec![aid(&format!("evidence-{tag}"))?],
            Some(aid(&format!("receipt-{tag}"))?),
        )
    } else {
        (vec![], None)
    };
    Ok(DimensionAssessment {
        dimension,
        status,
        evidence,
        owner_receipt,
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: vec![aid(&format!("metric-{tag}"))?],
        causal_ceiling: CausalCeiling::Observational,
    })
}

fn attribution_dimensions() -> Result<Vec<DimensionAssessment>, Box<dyn std::error::Error>> {
    Ok(vec![
        dimension(
            AssessmentDimension::ActionLinkedUse,
            DimensionStatus::Pass,
            "attr-action",
        )?,
        dimension(
            AssessmentDimension::Harm,
            DimensionStatus::NoEffect,
            "attr-harm",
        )?,
        dimension(
            AssessmentDimension::SourceEvaluatorIndependence,
            DimensionStatus::Pass,
            "attr-independence",
        )?,
    ])
}

fn experiment_dimensions() -> Result<Vec<DimensionAssessment>, Box<dyn std::error::Error>> {
    Ok(vec![
        dimension(
            AssessmentDimension::BaselineControlQuality,
            DimensionStatus::Pass,
            "exp-control",
        )?,
        dimension(
            AssessmentDimension::Harm,
            DimensionStatus::NoEffect,
            "exp-harm",
        )?,
        dimension(
            AssessmentDimension::Confounders,
            DimensionStatus::Pass,
            "exp-confounders",
        )?,
    ])
}

fn promotion_dimensions() -> Result<Vec<DimensionAssessment>, Box<dyn std::error::Error>> {
    Ok(vec![
        dimension(
            AssessmentDimension::Harm,
            DimensionStatus::Harm,
            "promo-harm",
        )?,
        dimension(
            AssessmentDimension::OutcomeValidity,
            DimensionStatus::Pass,
            "promo-outcome",
        )?,
    ])
}

#[allow(clippy::too_many_lines)]
fn valid_attribution(
    tag: &str,
    binding: &ContractBinding,
    delta_id: &ArtifactId,
    delta_digest: &str,
) -> Result<UseAttributionCandidate, Box<dyn std::error::Error>> {
    let subject_id = aid(&format!("subject-{tag}"))?;
    let mut candidate = UseAttributionCandidate {
        binding: binding.clone(),
        attribution_id: aid(&format!("attribution-{tag}"))?,
        target: target(&format!("target-self-{tag}"))?,
        subject: AttributedSubject {
            kind: SubjectKind::Candidate,
            id: subject_id.clone(),
            version: format!("v1.0.0-{tag}"),
            digest: digest(&format!("subject-record-{tag}")),
        },
        decision_action_id: aid(&format!("decision-{tag}"))?,
        source_delta_id: delta_id.clone(),
        source_delta_digest: delta_digest.to_owned(),
        disposition: UseDisposition::Used,
        use_basis: UseBasis::DirectObservation,
        denominator: SourceDenominator {
            declared: 3,
            observed: 3,
        },
        eligible_refs: vec![subject_id, aid(&format!("eligible-rival-{tag}"))?],
        non_use: vec![NonUseDeclaration {
            subject: aid(&format!("non-use-{tag}"))?,
            reason: "out of scope for this decision".to_owned(),
        }],
        competing_contributors: vec![aid(&format!("competitor-{tag}"))?],
        evaluator_receipt: aid(&format!("evaluator-{tag}"))?,
        evidence_refs: vec![aid(&format!("attr-evidence-{tag}"))?],
        dimensions: attribution_dimensions()?,
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

#[allow(clippy::too_many_lines)]
fn valid_experiment(
    tag: &str,
    binding: &ContractBinding,
    target: &TargetId,
    attribution: &UseAttributionCandidate,
) -> Result<ImprovementExperimentCandidate, Box<dyn std::error::Error>> {
    let mut candidate = ImprovementExperimentCandidate {
        binding: binding.clone(),
        experiment_id: aid(&format!("experiment-{tag}"))?,
        target: target.clone(),
        attribution_id: attribution.attribution_id.clone(),
        attribution_digest: attribution.canonical_digest.clone(),
        hypothesis: format!("candidate {tag} improves adherence without new harm"),
        eligibility: format!("eligible when fence and scope match {tag}"),
        assignment: AssignmentKind::Randomized,
        assignment_seed_digest: digest(&format!("seed-{tag}")),
        intervention_id: aid(&format!("intervention-{tag}"))?,
        control_id: aid(&format!("control-{tag}"))?,
        pre_observation_discriminator: aid(&format!("discriminator-{tag}"))?,
        safeguards: vec![aid(&format!("safeguard-{tag}"))?],
        stop_conditions: vec![format!("stop on harm signal {tag}")],
        rollback_refs: vec![aid(&format!("exp-rollback-{tag}"))?],
        contamination_policy: format!("exclude prior exposure {tag}"),
        prior_exposure_refs: vec![aid(&format!("prior-{tag}"))?],
        evidence_freeze_digest: digest(&format!("freeze-{tag}")),
        evidence_freeze_refs: vec![aid(&format!("frozen-{tag}"))?],
        outcome_dimensions: experiment_dimensions()?,
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

#[allow(clippy::too_many_lines)]
fn valid_promotion(
    tag: &str,
    binding: &ContractBinding,
    target: &TargetId,
    attribution: &UseAttributionCandidate,
    experiment: &ImprovementExperimentCandidate,
) -> Result<PromotionBoundaryCandidate, Box<dyn std::error::Error>> {
    let mut candidate = PromotionBoundaryCandidate {
        binding: binding.clone(),
        promotion_id: aid(&format!("promotion-{tag}"))?,
        target: target.clone(),
        attribution_id: attribution.attribution_id.clone(),
        attribution_digest: attribution.canonical_digest.clone(),
        experiment_id: experiment.experiment_id.clone(),
        experiment_digest: experiment.canonical_digest.clone(),
        governor_receipt_ref: Some(aid(&format!("governor-receipt-{tag}"))?),
        rollout: RolloutBoundary {
            reversible: true,
            canary_required: true,
            invalidation_conditions: vec![format!("harm signal {tag}")],
        },
        mutation_target: PromotionMutationTarget::CandidateOnly,
        supersedes: vec![],
        invalidates: vec![],
        history_retention: HistoryRetention::RetainAlways,
        evaluation_dimensions: promotion_dimensions()?,
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

fn delta_fixture(
    tag: &str,
    binding: &ContractBinding,
    target: &TargetId,
) -> Result<eliot_learning_contracts::AttemptLearningDeltaCandidate, Box<dyn std::error::Error>> {
    use eliot_learning_contracts::{
        AttemptLearningDeltaCandidate, ChangeOperation, ChangeSurface, InverseChange, ValueState,
    };
    let proposed = ValueState {
        present: true,
        digest: Some(digest(&format!("proposed-{tag}"))),
    };
    let mut delta = AttemptLearningDeltaCandidate {
        binding: binding.clone(),
        attempt_id: AgentAttemptId::new(format!("attempt-self-{tag}"))?,
        delta_id: aid(&format!("delta-self-{tag}"))?,
        target: target.clone(),
        base_view_digest: digest(&format!("base-view-{tag}")),
        pre_observation_discriminator: aid(&format!("delta-discriminator-{tag}"))?,
        intended_strategy: aid(&format!("intended-{tag}"))?,
        attempted_strategy: aid(&format!("attempted-{tag}"))?,
        changes: vec![ChangeOperation::Add {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            after: proposed.clone(),
        }],
        inverses: vec![InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Remove {
                target: target.clone(),
                surface: ChangeSurface::Strategy,
                before: proposed,
            },
        }],
        evidence: vec![aid(&format!("delta-evidence-{tag}"))?],
        evaluator_receipts: vec![aid(&format!("delta-evaluator-{tag}"))?],
        baseline: vec![aid(&format!("delta-baseline-{tag}"))?],
        control: vec![aid(&format!("delta-control-{tag}"))?],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    delta.seal()?;
    Ok(delta)
}

#[test]
fn attribution_validates_complete_denominator_and_rejects_weak_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("attr")?;
    let target = target("target-self-attr")?;
    let delta = delta_fixture("attr", &binding, &target)?;
    let attribution =
        valid_attribution("attr", &binding, &delta.delta_id, &delta.canonical_digest)?;
    attribution.validate_against_delta(&delta)?;
    let json = serde_json::to_string(&attribution)?;
    let restored: UseAttributionCandidate = serde_json::from_str(&json)?;
    assert_eq!(attribution, restored);

    let mut missing_denominator = attribution.clone();
    missing_denominator.denominator = SourceDenominator {
        declared: 0,
        observed: 0,
    };
    missing_denominator.seal()?;
    assert!(matches!(
        missing_denominator.validate(),
        Err(LearningContractError::Missing { .. } | LearningContractError::IncompleteCoverage)
    ));

    let mut single_score = attribution.clone();
    single_score.dimensions.truncate(1);
    single_score.seal()?;
    assert!(matches!(
        single_score.validate(),
        Err(LearningContractError::IncompleteCoverage)
    ));

    let mut retrieval_as_use = attribution.clone();
    retrieval_as_use.use_basis = UseBasis::RetrievalCount;
    retrieval_as_use.seal()?;
    assert!(matches!(
        retrieval_as_use.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

#[test]
fn attribution_rejects_self_rating_and_fence_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let base_binding = binding("selfrate")?;
    let target = target("target-self-selfrate")?;
    let delta = delta_fixture("selfrate", &base_binding, &target)?;
    let attribution = valid_attribution(
        "selfrate",
        &base_binding,
        &delta.delta_id,
        &delta.canonical_digest,
    )?;

    let mut self_rated = attribution.clone();
    self_rated.evaluator_receipt = self_rated.subject.id.clone();
    self_rated.seal()?;
    assert!(matches!(
        self_rated.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));

    let mut model_judgment = attribution.clone();
    model_judgment.use_basis = UseBasis::ModelJudgment;
    model_judgment.seal()?;
    assert!(matches!(
        model_judgment.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));

    let other_binding = binding("other")?;
    let mut fenced = attribution.clone();
    fenced.binding = other_binding;
    fenced.seal()?;
    assert!(matches!(
        fenced.validate_against_delta(&delta),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

#[test]
fn experiment_validates_control_and_freeze_with_unfenced_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let base_binding = binding("exp")?;
    let target = target("target-self-exp")?;
    let delta = delta_fixture("exp", &base_binding, &target)?;
    let attribution = valid_attribution(
        "exp",
        &base_binding,
        &delta.delta_id,
        &delta.canonical_digest,
    )?;
    let experiment = valid_experiment("exp", &base_binding, &target, &attribution)?;
    experiment.validate_against_attribution(&attribution)?;

    let mut missing_control = experiment.clone();
    missing_control.control_id = aid("missing-control")?;
    // Blank the control by replacing with an empty identity is not representable,
    // so simulate the missing-control shape through identical intervention/control.
    missing_control.control_id = missing_control.intervention_id.clone();
    missing_control.seal()?;
    assert!(matches!(
        missing_control.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));

    let mut absent_freeze = experiment.clone();
    absent_freeze.evidence_freeze_refs.clear();
    absent_freeze.seal()?;
    assert!(matches!(
        absent_freeze.validate(),
        Err(LearningContractError::Missing { .. })
    ));

    let mut tampered = experiment.clone();
    tampered.intervention_id = aid("tampered-intervention")?;
    assert!(matches!(
        tampered.validate(),
        Err(LearningContractError::DigestMismatch { .. })
    ));

    let other_binding = binding("exp-other")?;
    let mut unfenced = experiment.clone();
    unfenced.binding = other_binding;
    unfenced.seal()?;
    assert!(matches!(
        unfenced.validate_against_attribution(&attribution),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

#[test]
fn experiment_rejects_silent_contamination_and_keeps_dimensioned_confounders()
-> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("conf")?;
    let target = target("target-self-conf")?;
    let delta = delta_fixture("conf", &binding, &target)?;
    let attribution =
        valid_attribution("conf", &binding, &delta.delta_id, &delta.canonical_digest)?;
    let experiment = valid_experiment("conf", &binding, &target, &attribution)?;
    experiment.validate_against_attribution(&attribution)?;
    assert!(
        experiment
            .outcome_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::Confounders)
    );

    let mut silent = experiment.clone();
    silent.contamination_policy = String::new();
    silent.seal()?;
    assert!(matches!(
        silent.validate(),
        Err(LearningContractError::Missing { .. })
    ));

    let mut scalar = experiment.clone();
    scalar.outcome_dimensions.truncate(1);
    scalar.seal()?;
    assert!(matches!(
        scalar.validate(),
        Err(LearningContractError::IncompleteCoverage)
    ));
    Ok(())
}

#[test]
fn promotion_validates_candidate_only_and_rollback_preserves_history()
-> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("promo")?;
    let target = target("target-self-promo")?;
    let delta = delta_fixture("promo", &binding, &target)?;
    let attribution =
        valid_attribution("promo", &binding, &delta.delta_id, &delta.canonical_digest)?;
    let experiment = valid_experiment("promo", &binding, &target, &attribution)?;
    let mut promotion = valid_promotion("promo", &binding, &target, &attribution, &experiment)?;
    promotion.validate_against_attribution_and_experiment(&attribution, &experiment)?;

    let history_digest = promotion.canonical_digest.clone();
    let history_dimensions = promotion.evaluation_dimensions.clone();
    let invalidation = aid("invalidation-promo")?;
    promotion.invalidate(&invalidation)?;
    promotion.validate()?;
    assert_eq!(promotion.evaluation_dimensions, history_dimensions);
    assert_ne!(promotion.canonical_digest, history_digest);
    assert!(promotion.invalidates.contains(&invalidation));

    let mut active = promotion.clone();
    active.mutation_target = PromotionMutationTarget::ActiveGeneration;
    active.seal()?;
    assert!(matches!(
        active.validate(),
        Err(LearningContractError::CandidateCeiling)
    ));

    let mut self_issued = promotion.clone();
    self_issued.governor_receipt_ref = Some(self_issued.promotion_id.clone());
    self_issued.seal()?;
    assert!(matches!(
        self_issued.validate(),
        Err(LearningContractError::CandidateCeiling)
    ));

    let mut irreversible = promotion.clone();
    irreversible.rollout.reversible = false;
    irreversible.seal()?;
    assert!(matches!(
        irreversible.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));

    let mut deleting = promotion.clone();
    deleting.history_retention = HistoryRetention::DeleteOnRollback;
    deleting.seal()?;
    assert!(matches!(
        deleting.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

#[test]
fn promotion_validates_delayed_harm_dimensioned_and_rejects_scalar()
-> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("harm")?;
    let target = target("target-self-harm")?;
    let delta = delta_fixture("harm", &binding, &target)?;
    let attribution =
        valid_attribution("harm", &binding, &delta.delta_id, &delta.canonical_digest)?;
    let experiment = valid_experiment("harm", &binding, &target, &attribution)?;
    let promotion = valid_promotion("harm", &binding, &target, &attribution, &experiment)?;
    promotion.validate_against_attribution_and_experiment(&attribution, &experiment)?;
    assert!(
        promotion
            .evaluation_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::Harm
                && matches!(item.status, DimensionStatus::Harm))
    );

    let mut scalar = promotion.clone();
    scalar.evaluation_dimensions = vec![dimension(
        AssessmentDimension::OutcomeValidity,
        DimensionStatus::Pass,
        "scalar-only",
    )?];
    scalar.seal()?;
    assert!(matches!(
        scalar.validate(),
        Err(LearningContractError::IncompleteCoverage)
    ));
    Ok(())
}

#[test]
fn self_learning_working_path_links_delta_to_closure() -> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("path")?;
    let target = target("target-self-path")?;
    let delta = delta_fixture("path", &binding, &target)?;
    let attribution =
        valid_attribution("path", &binding, &delta.delta_id, &delta.canonical_digest)?;
    attribution.validate_against_delta(&delta)?;
    let experiment = valid_experiment("path", &binding, &target, &attribution)?;
    experiment.validate_against_attribution(&attribution)?;
    let promotion = valid_promotion("path", &binding, &target, &attribution, &experiment)?;
    promotion.validate_against_attribution_and_experiment(&attribution, &experiment)?;

    let mut handoff = ClosureHandoff {
        binding: binding.clone(),
        target: target.clone(),
        delta_id: delta.delta_id.clone(),
        overlay_id: eliot_learning_contracts::OverlayId::from_artifact(aid("overlay-path")?),
        assessment_id: aid("assessment-path")?,
        assessment_digest: digest("assessment-shape-path"),
        required_owner_proofs: vec![OwnerProof {
            owner: OwnerId::from_artifact(aid("owner-path")?),
            receipt: aid("owner-receipt-path")?,
            scope: binding.scope.clone(),
            state_fence: binding.state_fence.clone(),
            evidence: vec![aid("owner-evidence-path")?],
            proof_ceiling: ProofCeiling::CandidateArtifact,
        }],
        debts: vec![AssessmentDimension::Harm],
        rollback_refs: vec![aid("rollback-path")?],
        external_promotion_refs: vec![promotion.promotion_id.clone()],
        requested_decision: ExternalDecisionClass::PromotionReview,
        canonical_digest: String::new(),
    };
    handoff.seal()?;
    handoff.validate()?;
    assert!(
        handoff
            .external_promotion_refs
            .contains(&promotion.promotion_id)
    );
    Ok(())
}
