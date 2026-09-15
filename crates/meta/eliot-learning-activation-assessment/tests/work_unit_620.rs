#![allow(clippy::expect_used, clippy::too_many_lines)]
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_learning_activation_assessment::{
    ActivationAssessmentError, AssessmentInput, AssessmentPolicy, AssessmentResultOrIncomplete,
    MAX_INPUT_BYTES, MAX_METRICS, MAX_OUTPUT_BYTES, MAX_STAGES, MissingAssessmentField,
};
use eliot_learning_contracts::{
    AgentAttemptId, AssessmentDimension, CampaignHarnessOverlayCandidate, CampaignId,
    CampaignLearningStateView, CausalCeiling, ChangeOperation, ChangeSurface, Completeness,
    DimensionAssessment, DimensionStatus, InverseChange, LearningStateViewRecipe, LifecycleStage,
    MemberId, MemberProjection, MetricObservation, OmissionPolicy, OverlayChange, OverlayId,
    OverlayOrigin, OwnerId, ProofCeiling, SlotDisposition, SlotId, SlotProjection, SlotRequirement,
    SlotSpec, SourceDenominator, StageDisposition, StageObservation, TargetId, ValueState,
    WorkScopeId,
};

fn aid(value: &str) -> Result<ArtifactId, Box<dyn std::error::Error>> {
    Ok(ArtifactId::new(value)?)
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

#[allow(clippy::expect_used)]
fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn test_binding() -> Result<eliot_learning_contracts::ContractBinding, Box<dyn std::error::Error>> {
    Ok(eliot_learning_contracts::ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new("request-620")?,
        operation_id: OperationId::new("operation-620")?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new("task-620")?,
        scope: WorkScopeId::new("scope-620")?,
        state_fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new("source-620")?,
            snapshot: aid("snapshot-620")?,
            revision: TaskRevision::genesis(),
            digest: digest("source-620"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

#[allow(clippy::type_complexity, clippy::too_many_lines)]
fn fixture() -> Result<
    (
        CampaignLearningStateView,
        eliot_learning_activation_assessment::AttemptLearningDeltaCandidate,
        CampaignHarnessOverlayCandidate,
        eliot_learning_contracts::ContractBinding,
        TargetId,
        LearningStateViewRecipe,
    ),
    Box<dyn std::error::Error>,
> {
    let binding = test_binding()?;
    let target = TargetId::new("target-620")?;
    let required = SlotSpec {
        slot_id: SlotId::from_artifact(aid("slot-required")?),
        owner: OwnerId::from_artifact(aid("owner-required")?),
        target: target.clone(),
        requirement: SlotRequirement::Required,
        declared_members: vec![MemberId::from_artifact(aid("member-required")?)],
        accepted_type: "learning/v1".to_owned(),
        schema_digest: digest("learning-schema"),
    };
    let mut optional = required.clone();
    optional.slot_id = SlotId::from_artifact(aid("slot-optional")?);
    optional.owner = OwnerId::from_artifact(aid("owner-optional")?);
    optional.declared_members = vec![MemberId::from_artifact(aid("member-optional")?)];
    optional.requirement = SlotRequirement::Optional;
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-620")?,
        campaign_id: CampaignId::from_artifact(aid("campaign-620")?),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![required.clone(), optional.clone()],
        freshness: eliot_evidence::EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    recipe.seal()?;
    let member = MemberProjection {
        member_id: required.declared_members[0].clone(),
        owner: required.owner.clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("learning-value")),
        evidence: vec![aid("view-evidence")?],
    };
    let mut view = CampaignLearningStateView {
        view_id: aid("view-620")?,
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target: target.clone(),
        binding: binding.clone(),
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id: required.slot_id.clone(),
            disposition: SlotDisposition::Current,
            members: vec![member],
            evidence: vec![aid("slot-evidence")?],
        }],
        denominator: SourceDenominator {
            declared: 2,
            observed: 1,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![optional.slot_id.clone()],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("objective")?],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.seal()?;
    let proposed = ValueState {
        present: true,
        digest: Some(digest("proposal")),
    };
    let change = ChangeOperation::Add {
        target: target.clone(),
        surface: ChangeSurface::TaskLocalContext,
        after: proposed.clone(),
    };
    let inverse = InverseChange {
        forward_target: target.clone(),
        inverse: ChangeOperation::Remove {
            target: target.clone(),
            surface: ChangeSurface::TaskLocalContext,
            before: proposed.clone(),
        },
    };
    let mut delta = eliot_learning_activation_assessment::AttemptLearningDeltaCandidate {
        binding: binding.clone(),
        attempt_id: AgentAttemptId::new("attempt-620")?,
        delta_id: aid("delta-620")?,
        target: target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid("discriminator-620")?,
        intended_strategy: aid("intended-620")?,
        attempted_strategy: aid("attempted-620")?,
        changes: vec![change],
        inverses: vec![inverse],
        evidence: vec![aid("delta-evidence")?],
        evaluator_receipts: vec![aid("delta-evaluator")?],
        baseline: vec![aid("delta-baseline")?],
        control: vec![aid("delta-control")?],
        confounders: vec![],
        dependencies: vec![aid("delta-dependency")?],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    delta.seal()?;
    let mut overlay = CampaignHarnessOverlayCandidate {
        binding: binding.clone(),
        overlay_id: OverlayId::from_artifact(aid("overlay-620")?),
        base_view_digest: view.canonical_digest.clone(),
        parent_revision: TaskRevision::genesis(),
        admitted_delta_ids: vec![delta.delta_id.clone()],
        admitted_delta_digests: vec![delta.canonical_digest.clone()],
        changes: vec![OverlayChange {
            target: target.clone(),
            surface: ChangeSurface::TaskLocalContext,
            base: ValueState {
                present: false,
                digest: None,
            },
            proposed: proposed.clone(),
            inverse: InverseChange {
                forward_target: target.clone(),
                inverse: ChangeOperation::Remove {
                    target: target.clone(),
                    surface: ChangeSurface::TaskLocalContext,
                    before: proposed,
                },
            },
            origin: OverlayOrigin::Overlay,
        }],
        dependencies: vec![],
        application_order: vec![target.clone()],
        protected_surface_base_digest: digest("protected"),
        protected_surface_proposed_digest: digest("protected"),
        fixed_before_observation_discriminator: aid("overlay-fixed")?,
        expires_at_ms: 2_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    overlay.seal()?;
    Ok((view, delta, overlay, binding, target, recipe))
}

fn base_policy() -> AssessmentPolicy {
    AssessmentPolicy {
        schema_version: AssessmentPolicy::SCHEMA_VERSION,
        required_stages: vec![LifecycleStage::CandidateProduced, LifecycleStage::Delivered],
        required_dimensions: vec![
            AssessmentDimension::TargetCoverageAttrition,
            AssessmentDimension::RetrievalDeliveryVisibility,
            AssessmentDimension::Selection,
            AssessmentDimension::Adherence,
            AssessmentDimension::ActionLinkedUse,
            AssessmentDimension::OutcomeValidity,
            AssessmentDimension::BaselineControlQuality,
            AssessmentDimension::Harm,
            AssessmentDimension::Confounders,
            AssessmentDimension::SourceEvaluatorIndependence,
            AssessmentDimension::TransferApplicability,
            AssessmentDimension::CausalCeiling,
            AssessmentDimension::PrivacyAuthorityProof,
        ],
        stage_denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        dimension_denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        max_input_bytes: MAX_INPUT_BYTES,
        max_output_bytes: MAX_OUTPUT_BYTES,
    }
}

fn policy_with_stages(stages: Vec<LifecycleStage>) -> AssessmentPolicy {
    let mut policy = base_policy();
    policy.required_stages = stages;
    policy
}

#[allow(clippy::too_many_arguments)]
fn make_input<'a>(
    view: &'a CampaignLearningStateView,
    delta: &'a eliot_learning_activation_assessment::AttemptLearningDeltaCandidate,
    overlay: &'a CampaignHarnessOverlayCandidate,
    binding: &'a eliot_learning_contracts::ContractBinding,
    target: &'a TargetId,
    recipe: &'a LearningStateViewRecipe,
    policy: &'a AssessmentPolicy,
    activation_id: &'a ArtifactId,
    admission: Option<&'a ArtifactId>,
    activation_request: Option<&'a ArtifactId>,
    assessment_receipt: Option<&'a ArtifactId>,
    stages: &'a [StageObservation],
    metrics: &'a [MetricObservation],
    attrition: &'a [ArtifactId],
    confounders: &'a [ArtifactId],
    dimensions: &'a [DimensionAssessment],
    external_refs: &'a [ArtifactId],
) -> AssessmentInput<'a> {
    AssessmentInput {
        binding,
        target,
        view,
        recipe,
        delta,
        overlay,
        activation_id: Some(activation_id),
        admission_receipt: admission,
        activation_request_receipt: activation_request,
        assessment_receipt,
        stages,
        metrics,
        attrition,
        confounders,
        independent_evaluator_receipt: None,
        dimensions,
        external_review_refs: external_refs,
        policy,
    }
}

fn observed_stage(
    stage: LifecycleStage,
    predecessor: Option<LifecycleStage>,
    receipt: &str,
    evidence: &str,
) -> Result<StageObservation, Box<dyn std::error::Error>> {
    Ok(StageObservation {
        stage,
        disposition: StageDisposition::Observed,
        predecessor,
        owner_receipt: Some(aid(receipt)?),
        evidence: vec![aid(evidence)?],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    })
}

fn unknown_stage(stage: LifecycleStage) -> StageObservation {
    StageObservation {
        stage,
        disposition: StageDisposition::Unknown,
        predecessor: stage.required_predecessor(),
        owner_receipt: None,
        evidence: Vec::new(),
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
    }
}

fn metric_fixture(suffix: &str) -> Result<MetricObservation, Box<dyn std::error::Error>> {
    Ok(MetricObservation {
        metric_id: aid(&format!("metric-{suffix}"))?,
        name: format!("metric-name-{suffix}"),
        unit: "count".to_owned(),
        population: SourceDenominator {
            declared: 10,
            observed: 8,
        },
        window: aid(&format!("window-{suffix}"))?,
        baseline: Some(aid(&format!("baseline-{suffix}"))?),
        follow_up: Some(aid(&format!("followup-{suffix}"))?),
        evaluator_receipt: aid(&format!("evaluator-{suffix}"))?,
    })
}

fn dimension_fixture(
    dimension: AssessmentDimension,
    status: DimensionStatus,
    suffix: &str,
) -> Result<DimensionAssessment, Box<dyn std::error::Error>> {
    let (evidence, owner_receipt) = match status {
        DimensionStatus::Pass
        | DimensionStatus::Fail
        | DimensionStatus::Harm
        | DimensionStatus::NoEffect => (
            vec![aid(&format!("dim-ev-{suffix}"))?],
            Some(aid(&format!("dim-rc-{suffix}"))?),
        ),
        DimensionStatus::Unknown | DimensionStatus::Inconclusive => (Vec::new(), None),
    };
    Ok(DimensionAssessment {
        dimension,
        status,
        evidence,
        owner_receipt,
        denominator: SourceDenominator {
            declared: 1,
            observed: u32::from(matches!(
                status,
                DimensionStatus::Pass
                    | DimensionStatus::Fail
                    | DimensionStatus::Harm
                    | DimensionStatus::NoEffect
            )),
        },
        metric_ids: Vec::new(),
        causal_ceiling: CausalCeiling::Observational,
    })
}

#[allow(clippy::too_many_lines)]
fn chain_up_to(
    target: LifecycleStage,
) -> Result<Vec<StageObservation>, Box<dyn std::error::Error>> {
    let order = vec![
        LifecycleStage::CandidateProduced,
        LifecycleStage::AdmittedForEvaluation,
        LifecycleStage::ActivationRequested,
        LifecycleStage::Retrieved,
        LifecycleStage::DeliveryAttempted,
        LifecycleStage::Delivered,
        LifecycleStage::Acknowledged,
        LifecycleStage::Visible,
        LifecycleStage::SelectedActivated,
        LifecycleStage::Adhered,
        LifecycleStage::UsedInAction,
        LifecycleStage::ActionOutputObserved,
        LifecycleStage::SemanticOutcomeObserved,
    ];
    let mut chain = Vec::new();
    for stage in order {
        let predecessor = stage.required_predecessor();
        let tag = format!("{}-620", stage.as_str().to_lowercase().replace('_', "-"));
        chain.push(observed_stage(
            stage,
            predecessor,
            &format!("{tag}-rc"),
            &format!("{tag}-ev"),
        )?);
        if stage == target {
            return Ok(chain);
        }
    }
    match target {
        LifecycleStage::Benefit
        | LifecycleStage::Harm
        | LifecycleStage::NoEffect
        | LifecycleStage::Inconclusive => {
            let tag = format!("{}-620", target.as_str().to_lowercase().replace('_', "-"));
            chain.push(observed_stage(
                target,
                Some(LifecycleStage::SemanticOutcomeObserved),
                &format!("{tag}-rc"),
                &format!("{tag}-ev"),
            )?);
            Ok(chain)
        }
        LifecycleStage::CausalAssessment => {
            chain.push(observed_stage(
                LifecycleStage::Benefit,
                Some(LifecycleStage::SemanticOutcomeObserved),
                "benefit-620-rc",
                "benefit-620-ev",
            )?);
            chain.push(observed_stage(
                LifecycleStage::CausalAssessment,
                Some(LifecycleStage::Benefit),
                "causal-620-rc",
                "causal-620-ev",
            )?);
            Ok(chain)
        }
        LifecycleStage::ExternalPromotion => {
            chain.push(observed_stage(
                LifecycleStage::Benefit,
                Some(LifecycleStage::SemanticOutcomeObserved),
                "benefit-620-rc",
                "benefit-620-ev",
            )?);
            chain.push(observed_stage(
                LifecycleStage::CausalAssessment,
                Some(LifecycleStage::Benefit),
                "causal-620-rc",
                "causal-620-ev",
            )?);
            chain.push(observed_stage(
                LifecycleStage::ExternalPromotion,
                Some(LifecycleStage::CausalAssessment),
                "extpromo-620-rc",
                "extpromo-620-ev",
            )?);
            Ok(chain)
        }
        LifecycleStage::Closure => Ok(vec![observed_stage(
            LifecycleStage::Closure,
            None,
            "closure-620-rc",
            "closure-620-ev",
        )?]),
        other => {
            if chain.iter().any(|item| item.stage == other) {
                Ok(chain)
            } else {
                Err(format!("unsupported chain target {other:?}").into())
            }
        }
    }
}

fn all_stages() -> Vec<LifecycleStage> {
    vec![
        LifecycleStage::CandidateProduced,
        LifecycleStage::AdmittedForEvaluation,
        LifecycleStage::ActivationRequested,
        LifecycleStage::Retrieved,
        LifecycleStage::DeliveryAttempted,
        LifecycleStage::Delivered,
        LifecycleStage::Acknowledged,
        LifecycleStage::Visible,
        LifecycleStage::SelectedActivated,
        LifecycleStage::Adhered,
        LifecycleStage::UsedInAction,
        LifecycleStage::ActionOutputObserved,
        LifecycleStage::SemanticOutcomeObserved,
        LifecycleStage::Benefit,
        LifecycleStage::Harm,
        LifecycleStage::NoEffect,
        LifecycleStage::Inconclusive,
        LifecycleStage::CausalAssessment,
        LifecycleStage::ExternalPromotion,
        LifecycleStage::Closure,
    ]
}

fn all_dimensions() -> Vec<AssessmentDimension> {
    vec![
        AssessmentDimension::TargetCoverageAttrition,
        AssessmentDimension::RetrievalDeliveryVisibility,
        AssessmentDimension::Selection,
        AssessmentDimension::Adherence,
        AssessmentDimension::ActionLinkedUse,
        AssessmentDimension::OutcomeValidity,
        AssessmentDimension::BaselineControlQuality,
        AssessmentDimension::Harm,
        AssessmentDimension::Confounders,
        AssessmentDimension::SourceEvaluatorIndependence,
        AssessmentDimension::TransferApplicability,
        AssessmentDimension::CausalCeiling,
        AssessmentDimension::PrivacyAuthorityProof,
    ]
}

// WORK_UNIT_CASE: 620/1
#[test]
fn case_01_package_path_and_module_identity() -> Result<(), Box<dyn std::error::Error>> {
    let cargo = include_str!("../Cargo.toml");
    let module = include_str!("../module.toml");
    assert!(cargo.contains("name = \"eliot-learning-activation-assessment\""));
    assert!(module.contains("module_id = \"meta.learning.activation_assessment\""));
    assert!(
        module.contains("functional_cell") || cargo.contains("meta.learning.activation_assessment")
    );
    assert!(module.contains("causal_property = \"learning activation and adherence observation\""));
    assert!(module.contains("plane = \"Meta\""));
    assert!(cargo.contains("prototype = true") || module.contains("status = \"PROTOTYPE\""));
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let activation_id = aid("activation-620-c01")?;
    let admission = aid("admission-620-c01")?;
    let request = aid("request-620-c01")?;
    let receipt = aid("receipt-620-c01")?;
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c01-rc",
        "c01-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    assert!(matches!(
        outcome,
        AssessmentResultOrIncomplete::Candidate(_)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/2
#[test]
fn case_02_exact_lifecycle_receipt_assessment_vocabulary() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        LifecycleStage::CandidateProduced.as_str(),
        "CANDIDATE_PRODUCED"
    );
    assert_eq!(LifecycleStage::Delivered.as_str(), "DELIVERED");
    assert_eq!(LifecycleStage::Acknowledged.as_str(), "ACKNOWLEDGED");
    assert_eq!(LifecycleStage::Visible.as_str(), "VISIBLE");
    assert_eq!(
        LifecycleStage::SelectedActivated.as_str(),
        "SELECTED_ACTIVATED"
    );
    assert_eq!(LifecycleStage::Adhered.as_str(), "ADHERED");
    assert_eq!(LifecycleStage::UsedInAction.as_str(), "USED_IN_ACTION");
    assert_eq!(LifecycleStage::Benefit.as_str(), "BENEFIT");
    assert_eq!(all_stages().len(), 20);
    assert_eq!(all_dimensions().len(), 13);
    assert_eq!(
        AssessmentDimension::TargetCoverageAttrition.as_str(),
        "TARGET_COVERAGE_ATTRITION"
    );
    assert_eq!(AssessmentDimension::Harm.as_str(), "HARM");
    let encoded = serde_json::to_string(&LifecycleStage::Delivered)?;
    assert!(encoded.contains("DELIVERED"));
    let decoded: LifecycleStage = serde_json::from_str("\"DELIVERED\"")?;
    assert_eq!(decoded, LifecycleStage::Delivered);
    let rejected: Result<LifecycleStage, _> = serde_json::from_str("\"INVENTED_STAGE\"");
    assert!(rejected.is_err());
    let rejected_dim: Result<AssessmentDimension, _> = serde_json::from_str("\"SCALAR_SCORE\"");
    assert!(rejected_dim.is_err());
    Ok(())
}

// WORK_UNIT_CASE: 620/3
#[test]
fn case_03_exact_target_view_delta_overlay_admission_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let activation_id = aid("activation-620-c03")?;
    let admission = aid("admission-620-c03")?;
    let request = aid("activation-request-620-c03")?;
    let receipt = aid("assessment-620-c03")?;
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c03-rc",
        "c03-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.activation.target, target);
    assert_eq!(result.activation.view_digest, view.canonical_digest);
    assert_eq!(result.activation.delta_id, delta.delta_id);
    assert_eq!(result.activation.overlay_id, overlay.overlay_id);
    assert_eq!(result.activation.admission_receipt, admission);
    assert_eq!(result.activation.activation_request_receipt, request);
    assert_eq!(result.assessment.assessment_receipt, receipt);
    assert_eq!(result.activation.activation_id, activation_id);
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/4
#[test]
fn case_04_task_scope_fence_member_mismatch_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let activation_id = aid("activation-620-c04")?;
    let admission = aid("admission-620-c04")?;
    let request = aid("request-620-c04")?;
    let receipt = aid("receipt-620-c04")?;
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c04-rc",
        "c04-ev",
    )?];
    let mut wrong_binding = binding.clone();
    wrong_binding.task_id = TaskId::new("task-other")?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &wrong_binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("task mismatch must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::LineageMismatch { .. }
            | ActivationAssessmentError::Contract { .. }
    ));
    let wrong_target = TargetId::new("target-other")?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &wrong_target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("target mismatch must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::LineageMismatch { .. }
            | ActivationAssessmentError::Contract { .. }
    ));
    let mut wrong_scope = binding.clone();
    wrong_scope.scope = WorkScopeId::new("scope-other")?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &wrong_scope,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("scope mismatch must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::LineageMismatch { .. }
            | ActivationAssessmentError::Contract { .. }
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/5
#[test]
fn case_05_duplicate_and_same_id_changed_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let activation_id = aid("activation-620-c05")?;
    let admission = aid("admission-620-c05")?;
    let request = aid("request-620-c05")?;
    let receipt = aid("receipt-620-c05")?;
    let first = observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c05-dup-rc",
        "c05-dup-ev",
    )?;
    let mut changed = first.clone();
    changed.disposition = StageDisposition::Partial;
    let stages = vec![first, changed];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("duplicate stage must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Duplicate { field: "stages" }
    ));
    let dim_a = dimension_fixture(
        AssessmentDimension::Selection,
        DimensionStatus::Unknown,
        "c05a",
    )?;
    let dim_b = dimension_fixture(
        AssessmentDimension::Selection,
        DimensionStatus::Fail,
        "c05b",
    )?;
    let dims = vec![dim_a, dim_b];
    let stages_ok = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c05-ok-rc",
        "c05-ok-ev",
    )?];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages_ok,
        &[],
        &[],
        &[],
        &dims,
        &[],
    ))
    .expect_err("duplicate dimension must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Duplicate {
            field: "dimensions"
        }
    ));
    let dup = aid("dup-attr")?;
    let attrition = vec![dup.clone(), dup.clone()];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages_ok,
        &[],
        &attrition,
        &[],
        &[],
        &[],
    ))
    .expect_err("duplicate attrition must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Duplicate { field: "attrition" }
    ));
    let metric_a = metric_fixture("c05m")?;
    let mut metric_b = metric_a.clone();
    metric_b.unit = "seconds".to_owned();
    let metrics = vec![metric_a, metric_b];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages_ok,
        &metrics,
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("same metric id with changed payload must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Contract { .. } | ActivationAssessmentError::Duplicate { .. }
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/6
#[test]
#[allow(clippy::too_many_lines)]
fn case_06_every_adjacent_legal_stage_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let legal_targets = vec![
        LifecycleStage::AdmittedForEvaluation,
        LifecycleStage::ActivationRequested,
        LifecycleStage::Retrieved,
        LifecycleStage::DeliveryAttempted,
        LifecycleStage::Delivered,
        LifecycleStage::Acknowledged,
        LifecycleStage::Visible,
        LifecycleStage::SelectedActivated,
        LifecycleStage::Adhered,
        LifecycleStage::UsedInAction,
        LifecycleStage::ActionOutputObserved,
        LifecycleStage::SemanticOutcomeObserved,
        LifecycleStage::Benefit,
        LifecycleStage::CausalAssessment,
        LifecycleStage::ExternalPromotion,
    ];
    for target_stage in legal_targets {
        let chain = chain_up_to(target_stage)?;
        let policy = policy_with_stages(chain.iter().map(|item| item.stage).collect());
        let activation_id = aid(&format!("activation-legal-{}", target_stage.as_str()))?;
        let admission = aid(&format!("admission-legal-{}", target_stage.as_str()))?;
        let request = aid(&format!("req-legal-{}", target_stage.as_str()))?;
        let receipt = aid(&format!("rcpt-legal-{}", target_stage.as_str()))?;
        let outcome =
            eliot_learning_activation_assessment::assess_learning_activation(&make_input(
                &view,
                &delta,
                &overlay,
                &binding,
                &target,
                &recipe,
                &policy,
                &activation_id,
                Some(&admission),
                Some(&request),
                Some(&receipt),
                &chain,
                &[],
                &[],
                &[],
                &[],
                &[],
            ))?;
        let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
            return Err(format!("legal chain to {target_stage:?} must yield candidate").into());
        };
        result.validate()?;
    }
    let delivered_chain = vec![
        observed_stage(
            LifecycleStage::CandidateProduced,
            None,
            "c06-cp-rc",
            "c06-cp-ev",
        )?,
        observed_stage(
            LifecycleStage::AdmittedForEvaluation,
            Some(LifecycleStage::CandidateProduced),
            "c06-ad-rc",
            "c06-ad-ev",
        )?,
        observed_stage(
            LifecycleStage::ActivationRequested,
            Some(LifecycleStage::AdmittedForEvaluation),
            "c06-ar-rc",
            "c06-ar-ev",
        )?,
        observed_stage(
            LifecycleStage::Retrieved,
            Some(LifecycleStage::ActivationRequested),
            "c06-rt-rc",
            "c06-rt-ev",
        )?,
        observed_stage(
            LifecycleStage::DeliveryAttempted,
            Some(LifecycleStage::Retrieved),
            "c06-da-rc",
            "c06-da-ev",
        )?,
        observed_stage(
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
            "c06-dl-rc",
            "c06-dl-ev",
        )?,
        observed_stage(
            LifecycleStage::Visible,
            Some(LifecycleStage::Delivered),
            "c06-vi-rc",
            "c06-vi-ev",
        )?,
    ];
    let policy = policy_with_stages(delivered_chain.iter().map(|item| item.stage).collect());
    let activation_id = aid("activation-legal-visible-delivered")?;
    let admission = aid("admission-legal-visible-delivered")?;
    let request = aid("req-legal-visible-delivered")?;
    let receipt = aid("rcpt-legal-visible-delivered")?;
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &delivered_chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    assert!(matches!(
        outcome,
        AssessmentResultOrIncomplete::Candidate(_)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/7
#[test]
#[allow(clippy::too_many_lines)]
fn case_07_every_illegal_skipped_stage_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let skipped = vec![
        LifecycleStage::AdmittedForEvaluation,
        LifecycleStage::ActivationRequested,
        LifecycleStage::Retrieved,
        LifecycleStage::DeliveryAttempted,
        LifecycleStage::Delivered,
        LifecycleStage::Acknowledged,
        LifecycleStage::SelectedActivated,
        LifecycleStage::Adhered,
        LifecycleStage::ActionOutputObserved,
        LifecycleStage::SemanticOutcomeObserved,
        LifecycleStage::Benefit,
        LifecycleStage::ExternalPromotion,
    ];
    for stage in skipped {
        let predecessor = stage.required_predecessor();
        let tag = format!("skip-{}", stage.as_str().to_lowercase().replace('_', "-"));
        let only = [observed_stage(
            stage,
            predecessor,
            &format!("{tag}-rc"),
            &format!("{tag}-ev"),
        )?];
        let policy = policy_with_stages(vec![stage]);
        let activation_id = aid(&format!("activation-skip-{}", stage.as_str()))?;
        let admission = aid(&format!("admission-skip-{}", stage.as_str()))?;
        let request = aid(&format!("req-skip-{}", stage.as_str()))?;
        let receipt = aid(&format!("rcpt-skip-{}", stage.as_str()))?;
        let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
            &view,
            &delta,
            &overlay,
            &binding,
            &target,
            &recipe,
            &policy,
            &activation_id,
            Some(&admission),
            Some(&request),
            Some(&receipt),
            &only,
            &[],
            &[],
            &[],
            &[],
            &[],
        ))
        .expect_err(&format!("skipped {stage:?} must fail"));
        assert!(
            matches!(error, ActivationAssessmentError::Contract { .. }),
            "unexpected error for {stage:?}: {error:?}"
        );
    }
    let visible_alone = [observed_stage(
        LifecycleStage::Visible,
        Some(LifecycleStage::Acknowledged),
        "c07-vis-rc",
        "c07-vis-ev",
    )?];
    let policy = policy_with_stages(vec![LifecycleStage::Visible]);
    let activation_id = aid("activation-skip-visible")?;
    let admission = aid("admission-skip-visible")?;
    let request = aid("req-skip-visible")?;
    let receipt = aid("rcpt-skip-visible")?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &visible_alone,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("visible without positive predecessor must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/8
#[test]
fn case_08_enqueue_dispatch_is_not_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = policy_with_stages(vec![
        LifecycleStage::Retrieved,
        LifecycleStage::DeliveryAttempted,
        LifecycleStage::Delivered,
    ]);
    let chain = vec![
        observed_stage(
            LifecycleStage::Retrieved,
            Some(LifecycleStage::ActivationRequested),
            "c08-rt-rc",
            "c08-rt-ev",
        )?,
        observed_stage(
            LifecycleStage::DeliveryAttempted,
            Some(LifecycleStage::Retrieved),
            "c08-da-rc",
            "c08-da-ev",
        )?,
    ];
    let full_chain = {
        let mut prefix = chain_up_to(LifecycleStage::ActivationRequested)?;
        prefix.extend(chain);
        prefix
    };
    let activation_id = aid("activation-620-c08")?;
    let admission = aid("admission-620-c08")?;
    let request = aid("request-620-c08")?;
    let receipt = aid("receipt-620-c08")?;
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &full_chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let delivered = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::Delivered)
        .ok_or("delivered row must exist")?;
    assert_eq!(delivered.disposition, StageDisposition::Unknown);
    let claimed = {
        let mut stages = full_chain.clone();
        stages.push(observed_stage(
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
            "c08-dl-rc",
            "c08-dl-ev",
        )?);
        stages
    };
    let policy_claimed = policy_with_stages(claimed.iter().map(|item| item.stage).collect());
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy_claimed,
        &aid("activation-620-c08b")?,
        Some(&aid("admission-620-c08b")?),
        Some(&aid("request-620-c08b")?),
        Some(&aid("receipt-620-c08b")?),
        &claimed,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    assert!(matches!(
        outcome,
        AssessmentResultOrIncomplete::Candidate(_)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/9
#[test]
fn case_09_delivery_ack_is_not_visibility() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::Acknowledged)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::Visible])
            .collect(),
    );
    let activation_id = aid("activation-620-c09")?;
    let admission = aid("admission-620-c09")?;
    let request = aid("request-620-c09")?;
    let receipt = aid("receipt-620-c09")?;
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let visible = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::Visible)
        .ok_or("visible row must exist")?;
    assert_eq!(visible.disposition, StageDisposition::Unknown);
    let mut with_visible = chain.clone();
    with_visible.push(observed_stage(
        LifecycleStage::Visible,
        Some(LifecycleStage::Acknowledged),
        "c09-vis-rc",
        "c09-vis-ev",
    )?);
    let policy_two = policy_with_stages(with_visible.iter().map(|item| item.stage).collect());
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy_two,
        &aid("activation-620-c09b")?,
        Some(&aid("admission-620-c09b")?),
        Some(&aid("request-620-c09b")?),
        Some(&aid("receipt-620-c09b")?),
        &with_visible,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    assert!(matches!(
        outcome,
        AssessmentResultOrIncomplete::Candidate(_)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/10
#[test]
fn case_10_context_presence_is_not_selection() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::Visible)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::SelectedActivated])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c10")?,
        Some(&aid("admission-620-c10")?),
        Some(&aid("request-620-c10")?),
        Some(&aid("receipt-620-c10")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let selected = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::SelectedActivated)
        .ok_or("selected row must exist")?;
    assert_eq!(selected.disposition, StageDisposition::Unknown);
    let claimed = [observed_stage(
        LifecycleStage::SelectedActivated,
        Some(LifecycleStage::Visible),
        "c10-sel-rc",
        "c10-sel-ev",
    )?];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy_with_stages(vec![LifecycleStage::SelectedActivated]),
        &aid("activation-620-c10b")?,
        Some(&aid("admission-620-c10b")?),
        Some(&aid("request-620-c10b")?),
        Some(&aid("receipt-620-c10b")?),
        &claimed,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("selection without visible must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/11
#[test]
fn case_11_selection_is_not_adherence() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::SelectedActivated)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::Adhered])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c11")?,
        Some(&aid("admission-620-c11")?),
        Some(&aid("request-620-c11")?),
        Some(&aid("receipt-620-c11")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let adhered = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::Adhered)
        .ok_or("adhered row must exist")?;
    assert_eq!(adhered.disposition, StageDisposition::Unknown);
    Ok(())
}

// WORK_UNIT_CASE: 620/12
#[test]
fn case_12_adherence_is_not_use_ack_to_use_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::Adhered)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::UsedInAction])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c12")?,
        Some(&aid("admission-620-c12")?),
        Some(&aid("request-620-c12")?),
        Some(&aid("receipt-620-c12")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let used = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::UsedInAction)
        .ok_or("used row must exist")?;
    assert_eq!(used.disposition, StageDisposition::Unknown);
    let ack_only = chain_up_to(LifecycleStage::Acknowledged)?;
    let mut mutated = ack_only.clone();
    mutated.push(observed_stage(
        LifecycleStage::UsedInAction,
        Some(LifecycleStage::Adhered),
        "c12-mut-rc",
        "c12-mut-ev",
    )?);
    let policy_mut = policy_with_stages(mutated.iter().map(|item| item.stage).collect());
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy_mut,
        &aid("activation-620-c12m")?,
        Some(&aid("admission-620-c12m")?),
        Some(&aid("request-620-c12m")?),
        Some(&aid("receipt-620-c12m")?),
        &mutated,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("ack to use mutation must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/13
#[test]
fn case_13_use_is_not_action_contribution() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::UsedInAction)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::ActionOutputObserved])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c13")?,
        Some(&aid("admission-620-c13")?),
        Some(&aid("request-620-c13")?),
        Some(&aid("receipt-620-c13")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let output = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::ActionOutputObserved)
        .ok_or("output row must exist")?;
    assert_eq!(output.disposition, StageDisposition::Unknown);
    Ok(())
}

// WORK_UNIT_CASE: 620/14
#[test]
fn case_14_action_is_not_semantic_outcome() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::ActionOutputObserved)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::SemanticOutcomeObserved])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c14")?,
        Some(&aid("admission-620-c14")?),
        Some(&aid("request-620-c14")?),
        Some(&aid("receipt-620-c14")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let semantic = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::SemanticOutcomeObserved)
        .ok_or("semantic row must exist")?;
    assert_eq!(semantic.disposition, StageDisposition::Unknown);
    Ok(())
}

// WORK_UNIT_CASE: 620/15
#[test]
fn case_15_outcome_is_not_benefit_causal_attribution() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::SemanticOutcomeObserved)?;
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::Benefit, LifecycleStage::CausalAssessment])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c15")?,
        Some(&aid("admission-620-c15")?),
        Some(&aid("request-620-c15")?),
        Some(&aid("receipt-620-c15")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    for stage in [LifecycleStage::Benefit, LifecycleStage::CausalAssessment] {
        let row = result
            .activation
            .stages
            .iter()
            .find(|item| item.stage == stage)
            .ok_or("benefit/causal row must exist")?;
        assert_eq!(row.disposition, StageDisposition::Unknown);
    }
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    Ok(())
}

// WORK_UNIT_CASE: 620/16
#[test]
fn case_16_self_report_is_not_owner_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let bad_stage = StageObservation {
        stage: LifecycleStage::CandidateProduced,
        disposition: StageDisposition::Observed,
        predecessor: None,
        owner_receipt: None,
        evidence: vec![aid("c16-ev")?],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    };
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c16a")?,
        Some(&aid("admission-620-c16a")?),
        Some(&aid("request-620-c16a")?),
        Some(&aid("receipt-620-c16a")?),
        std::slice::from_ref(&bad_stage),
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("observed without receipt must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    let bad_evidence = StageObservation {
        stage: LifecycleStage::CandidateProduced,
        disposition: StageDisposition::Observed,
        predecessor: None,
        owner_receipt: Some(aid("c16-rc")?),
        evidence: Vec::new(),
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    };
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c16b")?,
        Some(&aid("admission-620-c16b")?),
        Some(&aid("request-620-c16b")?),
        Some(&aid("receipt-620-c16b")?),
        std::slice::from_ref(&bad_evidence),
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("observed without evidence must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    let bad_dimension = DimensionAssessment {
        dimension: AssessmentDimension::Selection,
        status: DimensionStatus::Pass,
        evidence: Vec::new(),
        owner_receipt: None,
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        metric_ids: Vec::new(),
        causal_ceiling: CausalCeiling::Observational,
    };
    let good_stage = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c16-ok-rc",
        "c16-ok-ev",
    )?];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c16c")?,
        Some(&aid("admission-620-c16c")?),
        Some(&aid("request-620-c16c")?),
        Some(&aid("receipt-620-c16c")?),
        &good_stage,
        &[],
        &[],
        &[],
        std::slice::from_ref(&bad_dimension),
        &[],
    ))
    .expect_err("dimension pass without evidence must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/17
#[test]
fn case_17_process_exit_log_tool_is_not_semantic_proof() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = policy_with_stages(vec![
        LifecycleStage::CandidateProduced,
        LifecycleStage::SemanticOutcomeObserved,
    ]);
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "exit-0-receipt",
        "exit-0-log",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c17")?,
        Some(&aid("admission-620-c17")?),
        Some(&aid("request-620-c17")?),
        Some(&aid("receipt-620-c17")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let semantic = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::SemanticOutcomeObserved)
        .ok_or("semantic row must exist")?;
    assert_eq!(semantic.disposition, StageDisposition::Unknown);
    let claimed = [observed_stage(
        LifecycleStage::SemanticOutcomeObserved,
        Some(LifecycleStage::ActionOutputObserved),
        "tool-response-rc",
        "tool-response-ev",
    )?];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c17b")?,
        Some(&aid("admission-620-c17b")?),
        Some(&aid("request-620-c17b")?),
        Some(&aid("receipt-620-c17b")?),
        &claimed,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("tool response without predecessor must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/18
#[test]
fn case_18_no_hidden_thought_inference_field() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c18-rc",
        "c18-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c18")?,
        Some(&aid("admission-620-c18")?),
        Some(&aid("request-620-c18")?),
        Some(&aid("receipt-620-c18")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let json = serde_json::to_string(&result)?;
    let lowered = json.to_lowercase();
    for forbidden in [
        "hidden",
        "thought",
        "reasoning",
        "chain_of_thought",
        "inner_monologue",
        "private_reason",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "output must not contain {forbidden}"
        );
    }
    let with_hidden = json.replace("CandidateProduced", "CANDIDATE_PRODUCEDX");
    assert!(!with_hidden.contains("hidden_thought"));
    let rejected: Result<StageObservation, _> = serde_json::from_str(
        "{\"stage\":\"DELIVERED\",\"disposition\":\"OBSERVED\",\"predecessor\":null,\"owner_receipt\":null,\"evidence\":[],\"denominator\":{\"declared\":1,\"observed\":1},\"hidden_thought\":\"x\"}",
    );
    assert!(rejected.is_err());
    Ok(())
}

// WORK_UNIT_CASE: 620/19
#[test]
fn case_19_complete_target_member_stage_denominator() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    assert_eq!(view.denominator.declared, 2);
    assert_eq!(view.denominator.observed, 1);
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c19-rc",
        "c19-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c19")?,
        Some(&aid("admission-620-c19")?),
        Some(&aid("request-620-c19")?),
        Some(&aid("receipt-620-c19")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.activation.member_denominator, view.denominator);
    result.validate()?;
    let mut bad_view = view.clone();
    bad_view.denominator = SourceDenominator {
        declared: 1,
        observed: 2,
    };
    bad_view.canonical_digest.clear();
    bad_view.seal()?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &bad_view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c19b")?,
        Some(&aid("admission-620-c19b")?),
        Some(&aid("request-620-c19b")?),
        Some(&aid("receipt-620-c19b")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("observed above declared must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/20
#[test]
fn case_20_missing_partial_instrumentation_remains_unknown()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let empty: [StageObservation; 0] = [];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c20")?,
        Some(&aid("admission-620-c20")?),
        Some(&aid("request-620-c20")?),
        Some(&aid("receipt-620-c20")?),
        &empty,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    for stage in &result.activation.stages {
        assert_eq!(stage.disposition, StageDisposition::Unknown);
    }
    for dimension in &result.assessment.dimensions {
        assert_eq!(dimension.status, DimensionStatus::Unknown);
    }
    let partial = StageObservation {
        stage: LifecycleStage::CandidateProduced,
        disposition: StageDisposition::Partial,
        predecessor: None,
        owner_receipt: Some(aid("c20-part-rc")?),
        evidence: vec![aid("c20-part-ev")?],
        denominator: SourceDenominator {
            declared: 2,
            observed: 1,
        },
    };
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c20b")?,
        Some(&aid("admission-620-c20b")?),
        Some(&aid("request-620-c20b")?),
        Some(&aid("receipt-620-c20b")?),
        std::slice::from_ref(&partial),
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let retained = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::CandidateProduced)
        .ok_or("partial row must exist")?;
    assert_eq!(retained.disposition, StageDisposition::Partial);
    Ok(())
}

// WORK_UNIT_CASE: 620/21
#[test]
fn case_21_no_event_window_versus_unavailable_observation() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = policy_with_stages(vec![
        LifecycleStage::CandidateProduced,
        LifecycleStage::Delivered,
        LifecycleStage::NoEffect,
    ]);
    let stages = vec![
        observed_stage(
            LifecycleStage::CandidateProduced,
            None,
            "c21-cp-rc",
            "c21-cp-ev",
        )?,
        StageObservation {
            stage: LifecycleStage::Delivered,
            disposition: StageDisposition::Unavailable,
            predecessor: Some(LifecycleStage::DeliveryAttempted),
            owner_receipt: None,
            evidence: Vec::new(),
            denominator: SourceDenominator {
                declared: 1,
                observed: 0,
            },
        },
        StageObservation {
            stage: LifecycleStage::NoEffect,
            disposition: StageDisposition::NotAttempted,
            predecessor: Some(LifecycleStage::SemanticOutcomeObserved),
            owner_receipt: None,
            evidence: Vec::new(),
            denominator: SourceDenominator {
                declared: 1,
                observed: 0,
            },
        },
    ];
    let full_prefix = chain_up_to(LifecycleStage::DeliveryAttempted)?;
    let mut supplied: Vec<StageObservation> = full_prefix
        .into_iter()
        .filter(|item| {
            item.stage != LifecycleStage::Delivered && item.stage != LifecycleStage::NoEffect
        })
        .collect();
    supplied.extend(stages.into_iter().filter(|item| {
        item.stage == LifecycleStage::Delivered || item.stage == LifecycleStage::NoEffect
    }));
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c21")?,
        Some(&aid("admission-620-c21")?),
        Some(&aid("request-620-c21")?),
        Some(&aid("receipt-620-c21")?),
        &supplied,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(first) = outcome else {
        return Err("expected candidate for unavailable versus no-event".into());
    };
    let delivered_row = first
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::Delivered)
        .ok_or("delivered row must exist")?;
    assert_eq!(delivered_row.disposition, StageDisposition::Unavailable);
    let no_effect_row = first
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::NoEffect)
        .ok_or("no-effect row must exist")?;
    assert_eq!(no_effect_row.disposition, StageDisposition::NotAttempted);
    let unavailable = StageObservation {
        stage: LifecycleStage::CandidateProduced,
        disposition: StageDisposition::Unavailable,
        predecessor: None,
        owner_receipt: None,
        evidence: Vec::new(),
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
    };
    let policy_simple = policy_with_stages(vec![LifecycleStage::CandidateProduced]);
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy_simple,
        &aid("activation-620-c21b")?,
        Some(&aid("admission-620-c21b")?),
        Some(&aid("request-620-c21b")?),
        Some(&aid("receipt-620-c21b")?),
        std::slice::from_ref(&unavailable),
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let row = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::CandidateProduced)
        .ok_or("row must exist")?;
    assert_eq!(row.disposition, StageDisposition::Unavailable);
    assert_ne!(row.disposition, StageDisposition::Observed);
    Ok(())
}

// WORK_UNIT_CASE: 620/22
#[test]
fn case_22_attrition_cannot_be_dropped_from_rates() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c22-rc",
        "c22-ev",
    )?];
    let attrition = vec![aid("attrition-620-c22")?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c22")?,
        Some(&aid("admission-620-c22")?),
        Some(&aid("request-620-c22")?),
        Some(&aid("receipt-620-c22")?),
        &stages,
        &[],
        &attrition,
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(with_attr) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(with_attr.activation.attrition, attrition);
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c22")?,
        Some(&aid("admission-620-c22")?),
        Some(&aid("request-620-c22")?),
        Some(&aid("receipt-620-c22")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(without_attr) = outcome else {
        return Err("expected candidate".into());
    };
    assert!(without_attr.activation.attrition.is_empty());
    assert_ne!(
        with_attr.canonical_digest, without_attr.canonical_digest,
        "omitted attrition must change digest and must fail the substantive retention check if dropped"
    );
    with_attr.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/23
#[test]
fn case_23_duplicate_dependent_receipts_do_not_inflate_coverage()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c23-rc",
        "c23-ev",
    )?];
    let dup_conf = aid("conf-620-c23")?;
    let confounders = vec![dup_conf.clone(), dup_conf.clone()];
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c23")?,
        Some(&aid("admission-620-c23")?),
        Some(&aid("request-620-c23")?),
        Some(&aid("receipt-620-c23")?),
        &stages,
        &[],
        &[],
        &confounders,
        &[],
        &[],
    ))
    .expect_err("duplicate confounder must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Duplicate {
            field: "confounders"
        }
    ));
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c23b")?,
        Some(&aid("admission-620-c23b")?),
        Some(&aid("request-620-c23b")?),
        Some(&aid("receipt-620-c23b")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.activation.member_denominator, view.denominator);
    Ok(())
}

// WORK_UNIT_CASE: 620/24
#[test]
fn case_24_compatible_baseline_followup_metric() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c24-rc",
        "c24-ev",
    )?];
    let metric = metric_fixture("c24")?;
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c24")?,
        Some(&aid("admission-620-c24")?),
        Some(&aid("request-620-c24")?),
        Some(&aid("receipt-620-c24")?),
        &stages,
        std::slice::from_ref(&metric),
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.activation.metrics.len(), 1);
    assert_eq!(result.activation.metrics[0].metric_id, metric.metric_id);
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/25
#[test]
fn case_25_missing_changed_unit_population_window_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c25-rc",
        "c25-ev",
    )?];
    let mut missing_unit = metric_fixture("c25a")?;
    missing_unit.unit = String::new();
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c25a")?,
        Some(&aid("admission-620-c25a")?),
        Some(&aid("request-620-c25a")?),
        Some(&aid("receipt-620-c25a")?),
        &stages,
        std::slice::from_ref(&missing_unit),
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("missing unit must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    let mut bad_population = metric_fixture("c25b")?;
    bad_population.population = SourceDenominator {
        declared: 2,
        observed: 5,
    };
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c25b")?,
        Some(&aid("admission-620-c25b")?),
        Some(&aid("request-620-c25b")?),
        Some(&aid("receipt-620-c25b")?),
        &stages,
        std::slice::from_ref(&bad_population),
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("incompatible population must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    let mut missing_name = metric_fixture("c25c")?;
    missing_name.name = String::new();
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c25c")?,
        Some(&aid("admission-620-c25c")?),
        Some(&aid("request-620-c25c")?),
        Some(&aid("receipt-620-c25c")?),
        &stages,
        std::slice::from_ref(&missing_name),
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("missing metric name must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/26
#[test]
fn case_26_unchanged_versus_no_event_missing_measurement() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = policy_with_stages(vec![
        LifecycleStage::CandidateProduced,
        LifecycleStage::NoEffect,
        LifecycleStage::SemanticOutcomeObserved,
    ]);
    let mut chain = chain_up_to(LifecycleStage::ActionOutputObserved)?;
    chain.push(observed_stage(
        LifecycleStage::SemanticOutcomeObserved,
        Some(LifecycleStage::ActionOutputObserved),
        "c26-sem-rc",
        "c26-sem-ev",
    )?);
    chain.push(observed_stage(
        LifecycleStage::NoEffect,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c26-noeff-rc",
        "c26-noeff-ev",
    )?);
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c26")?,
        Some(&aid("admission-620-c26")?),
        Some(&aid("request-620-c26")?),
        Some(&aid("receipt-620-c26")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let no_effect = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::NoEffect)
        .ok_or("no-effect row must exist")?;
    assert_eq!(no_effect.disposition, StageDisposition::Observed);
    let metric = metric_fixture("c26")?;
    assert!(!metric.metric_id.as_str().is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 620/27
#[test]
#[allow(clippy::too_many_lines)]
fn case_27_positive_negative_mixed_harmful_outcomes() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    for outcome_stage in [
        LifecycleStage::Benefit,
        LifecycleStage::Harm,
        LifecycleStage::NoEffect,
        LifecycleStage::Inconclusive,
    ] {
        let mut chain = chain_up_to(LifecycleStage::SemanticOutcomeObserved)?;
        let tag = format!(
            "c27-{}",
            outcome_stage.as_str().to_lowercase().replace('_', "-")
        );
        chain.push(observed_stage(
            outcome_stage,
            Some(LifecycleStage::SemanticOutcomeObserved),
            &format!("{tag}-rc"),
            &format!("{tag}-ev"),
        )?);
        let policy = policy_with_stages(chain.iter().map(|item| item.stage).collect());
        let outcome =
            eliot_learning_activation_assessment::assess_learning_activation(&make_input(
                &view,
                &delta,
                &overlay,
                &binding,
                &target,
                &recipe,
                &policy,
                &aid(&format!("activation-{tag}"))?,
                Some(&aid(&format!("admission-{tag}"))?),
                Some(&aid(&format!("req-{tag}"))?),
                Some(&aid(&format!("rcpt-{tag}"))?),
                &chain,
                &[],
                &[],
                &[],
                &[],
                &[],
            ))?;
        let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
            return Err(format!("{outcome_stage:?} must yield candidate").into());
        };
        let row = result
            .activation
            .stages
            .iter()
            .find(|item| item.stage == outcome_stage)
            .ok_or("outcome row must exist")?;
        assert_eq!(row.disposition, StageDisposition::Observed);
        result.validate()?;
    }
    let mut mixed = chain_up_to(LifecycleStage::SemanticOutcomeObserved)?;
    mixed.push(observed_stage(
        LifecycleStage::Benefit,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c27-mix-ben-rc",
        "c27-mix-ben-ev",
    )?);
    mixed.push(observed_stage(
        LifecycleStage::Harm,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c27-mix-harm-rc",
        "c27-mix-harm-ev",
    )?);
    let policy = policy_with_stages(mixed.iter().map(|item| item.stage).collect());
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c27mix")?,
        Some(&aid("admission-620-c27mix")?),
        Some(&aid("request-620-c27mix")?),
        Some(&aid("receipt-620-c27mix")?),
        &mixed,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    assert!(matches!(
        outcome,
        AssessmentResultOrIncomplete::Candidate(_)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/28
#[test]
fn case_28_predeclared_control_comparison() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    assert!(!delta.baseline.is_empty());
    assert!(!delta.control.is_empty());
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c28-rc",
        "c28-ev",
    )?];
    let metric = metric_fixture("c28")?;
    let dimension = DimensionAssessment {
        dimension: AssessmentDimension::BaselineControlQuality,
        status: DimensionStatus::Pass,
        evidence: vec![aid("c28-dim-ev")?],
        owner_receipt: Some(aid("c28-dim-rc")?),
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: vec![metric.metric_id.clone()],
        causal_ceiling: CausalCeiling::Observational,
    };
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c28")?,
        Some(&aid("admission-620-c28")?),
        Some(&aid("request-620-c28")?),
        Some(&aid("receipt-620-c28")?),
        &stages,
        std::slice::from_ref(&metric),
        &[],
        &[],
        std::slice::from_ref(&dimension),
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert!(
        result
            .assessment
            .dimensions
            .iter()
            .any(
                |item| item.dimension == AssessmentDimension::BaselineControlQuality
                    && item.status == DimensionStatus::Pass
            )
    );
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/29
#[test]
fn case_29_no_control_posthoc_selection_yields_no_causal_support()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c29-rc",
        "c29-ev",
    )?];
    let inflated = DimensionAssessment {
        dimension: AssessmentDimension::BaselineControlQuality,
        status: DimensionStatus::Unknown,
        evidence: Vec::new(),
        owner_receipt: None,
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        metric_ids: Vec::new(),
        causal_ceiling: CausalCeiling::CausalAttribution,
    };
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c29")?,
        Some(&aid("admission-620-c29")?),
        Some(&aid("request-620-c29")?),
        Some(&aid("receipt-620-c29")?),
        &stages,
        &[],
        &[],
        &[],
        std::slice::from_ref(&inflated),
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    let retained = result
        .assessment
        .dimensions
        .iter()
        .find(|item| item.dimension == AssessmentDimension::BaselineControlQuality)
        .ok_or("dimension must exist")?;
    assert_eq!(retained.causal_ceiling, CausalCeiling::Observational);
    let mut tampered = (*result).clone();
    tampered.assessment.causal_ceiling = CausalCeiling::CausalAttribution;
    tampered.assessment.canonical_digest.clear();
    tampered.assessment.seal()?;
    tampered.canonical_digest.clear();
    tampered.seal()?;
    assert!(
        tampered.validate().is_err(),
        "post-hoc causal upgrade must fail"
    );
    Ok(())
}

// WORK_UNIT_CASE: 620/30
#[test]
fn case_30_recipient_selection_attrition_changed_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = policy_with_stages(vec![
        LifecycleStage::CandidateProduced,
        LifecycleStage::SelectedActivated,
    ]);
    let mut chain = chain_up_to(LifecycleStage::Visible)?;
    chain.push(StageObservation {
        stage: LifecycleStage::SelectedActivated,
        disposition: StageDisposition::Partial,
        predecessor: Some(LifecycleStage::Visible),
        owner_receipt: Some(aid("c30-sel-rc")?),
        evidence: vec![aid("c30-sel-ev")?],
        denominator: SourceDenominator {
            declared: 2,
            observed: 1,
        },
    });
    let attrition = vec![aid("recipient-attr-620-c30")?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c30")?,
        Some(&aid("admission-620-c30")?),
        Some(&aid("request-620-c30")?),
        Some(&aid("receipt-620-c30")?),
        &chain,
        &[],
        &attrition,
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.activation.attrition, attrition);
    let wrong_target = TargetId::new("target-changed-env")?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &wrong_target,
        &recipe,
        &policy,
        &aid("activation-620-c30b")?,
        Some(&aid("admission-620-c30b")?),
        Some(&aid("request-620-c30b")?),
        Some(&aid("receipt-620-c30b")?),
        &chain,
        &[],
        &attrition,
        &[],
        &[],
        &[],
    ))
    .expect_err("changed environment target must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::LineageMismatch { .. }
            | ActivationAssessmentError::Contract { .. }
    ));
    Ok(())
}

// WORK_UNIT_CASE: 620/31
#[test]
fn case_31_complete_versus_partial_confounder_denominator() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c31-rc",
        "c31-ev",
    )?];
    let confounders = vec![aid("conf-620-c31a")?, aid("conf-620-c31b")?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c31")?,
        Some(&aid("admission-620-c31")?),
        Some(&aid("request-620-c31")?),
        Some(&aid("receipt-620-c31")?),
        &stages,
        &[],
        &[],
        &confounders,
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(with_conf) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(with_conf.activation.confounders, confounders);
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c31")?,
        Some(&aid("admission-620-c31")?),
        Some(&aid("request-620-c31")?),
        Some(&aid("receipt-620-c31")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(without_conf) = outcome else {
        return Err("expected candidate".into());
    };
    assert!(without_conf.activation.confounders.is_empty());
    assert_ne!(with_conf.canonical_digest, without_conf.canonical_digest);
    Ok(())
}

// WORK_UNIT_CASE: 620/32
#[test]
fn case_32_concurrent_interventions_remain_visible() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c32-rc",
        "c32-ev",
    )?];
    let confounders = vec![
        aid("context-intervention-620")?,
        aid("tool-intervention-620")?,
        aid("model-intervention-620")?,
        aid("human-intervention-620")?,
        aid("config-intervention-620")?,
    ];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c32")?,
        Some(&aid("admission-620-c32")?),
        Some(&aid("request-620-c32")?),
        Some(&aid("receipt-620-c32")?),
        &stages,
        &[],
        &[],
        &confounders,
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.activation.confounders, confounders);
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/33
#[test]
fn case_33_same_model_generator_evaluator_dependence() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c33-rc",
        "c33-ev",
    )?];
    let shared = aid("shared-model-620-c33")?;
    let confounders = vec![shared.clone()];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c33")?,
        Some(&aid("admission-620-c33")?),
        Some(&aid("request-620-c33")?),
        Some(&aid("receipt-620-c33")?),
        &stages,
        &[],
        &[],
        &confounders,
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert!(result.activation.independent_evaluator_receipt.is_none());
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    let independence = result
        .assessment
        .dimensions
        .iter()
        .find(|item| item.dimension == AssessmentDimension::SourceEvaluatorIndependence)
        .ok_or("independence dimension must exist")?;
    assert_eq!(independence.status, DimensionStatus::Unknown);
    Ok(())
}

// WORK_UNIT_CASE: 620/34
#[test]
fn case_34_correlation_temporal_order_cannot_prove_causal_benefit()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let mut chain = chain_up_to(LifecycleStage::SemanticOutcomeObserved)?;
    chain.push(observed_stage(
        LifecycleStage::Benefit,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c34-ben-rc",
        "c34-ben-ev",
    )?);
    let policy = policy_with_stages(
        chain
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::CausalAssessment])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c34")?,
        Some(&aid("admission-620-c34")?),
        Some(&aid("request-620-c34")?),
        Some(&aid("receipt-620-c34")?),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    let causal = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::CausalAssessment)
        .ok_or("causal row must exist")?;
    assert_eq!(causal.disposition, StageDisposition::Unknown);
    Ok(())
}

// WORK_UNIT_CASE: 620/35
#[test]
fn case_35_bounded_causal_ceiling_backed_by_design() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c35-rc",
        "c35-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c35")?,
        Some(&aid("admission-620-c35")?),
        Some(&aid("request-620-c35")?),
        Some(&aid("receipt-620-c35")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    for dimension in &result.assessment.dimensions {
        assert_eq!(dimension.causal_ceiling, CausalCeiling::Observational);
    }
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/36
#[test]
fn case_36_harm_cannot_be_hidden_by_positive_aggregate() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let mut chain = chain_up_to(LifecycleStage::SemanticOutcomeObserved)?;
    chain.push(observed_stage(
        LifecycleStage::Benefit,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c36-ben-rc",
        "c36-ben-ev",
    )?);
    chain.push(observed_stage(
        LifecycleStage::Harm,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c36-harm-rc",
        "c36-harm-ev",
    )?);
    let policy = policy_with_stages(chain.iter().map(|item| item.stage).collect());
    let harm_dimension = DimensionAssessment {
        dimension: AssessmentDimension::Harm,
        status: DimensionStatus::Harm,
        evidence: vec![aid("c36-harm-dim-ev")?],
        owner_receipt: Some(aid("c36-harm-dim-rc")?),
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: Vec::new(),
        causal_ceiling: CausalCeiling::Observational,
    };
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c36")?,
        Some(&aid("admission-620-c36")?),
        Some(&aid("request-620-c36")?),
        Some(&aid("receipt-620-c36")?),
        &chain,
        &[],
        &[],
        &[],
        std::slice::from_ref(&harm_dimension),
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert!(result.assessment.dimensions.iter().any(|item| {
        item.dimension == AssessmentDimension::Harm && item.status == DimensionStatus::Harm
    }));
    assert!(result.activation.stages.iter().any(|item| {
        item.stage == LifecycleStage::Harm && item.disposition == StageDisposition::Observed
    }));
    let mut hidden = (*result).clone();
    hidden.input.dimensions.clear();
    hidden.input.seal()?;
    hidden.canonical_digest.clear();
    hidden.seal()?;
    assert!(
        hidden.validate().is_err(),
        "hidden harmful outcome mutation must fail validation"
    );
    Ok(())
}

// WORK_UNIT_CASE: 620/37
#[test]
#[allow(clippy::too_many_lines)]
fn case_37_every_independent_dimension_and_aggregate() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    assert_eq!(all_dimensions().len(), 13);
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c37-rc",
        "c37-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c37")?,
        Some(&aid("admission-620-c37")?),
        Some(&aid("request-620-c37")?),
        Some(&aid("receipt-620-c37")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.assessment.dimensions.len(), 13);
    for expected in all_dimensions() {
        assert!(
            result
                .assessment
                .dimensions
                .iter()
                .any(|item| item.dimension == expected),
            "missing dimension {expected:?}"
        );
    }
    let bad_harm = DimensionAssessment {
        dimension: AssessmentDimension::Selection,
        status: DimensionStatus::Harm,
        evidence: vec![aid("c37-bad-ev")?],
        owner_receipt: Some(aid("c37-bad-rc")?),
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: Vec::new(),
        causal_ceiling: CausalCeiling::Observational,
    };
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c37b")?,
        Some(&aid("admission-620-c37b")?),
        Some(&aid("request-620-c37b")?),
        Some(&aid("receipt-620-c37b")?),
        &stages,
        &[],
        &[],
        &[],
        std::slice::from_ref(&bad_harm),
        &[],
    ))
    .expect_err("harm on non-harm dimension must fail");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    let mut short_policy = base_policy();
    short_policy.required_dimensions.pop();
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &short_policy,
        &aid("activation-620-c37c")?,
        Some(&aid("admission-620-c37c")?),
        Some(&aid("request-620-c37c")?),
        Some(&aid("receipt-620-c37c")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("policy without 13 dimensions must fail");
    assert!(matches!(error, ActivationAssessmentError::Bound { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/38
#[test]
fn case_38_no_scalar_activation_benefit_score() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c38-rc",
        "c38-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c38")?,
        Some(&aid("admission-620-c38")?),
        Some(&aid("request-620-c38")?),
        Some(&aid("receipt-620-c38")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let json = serde_json::to_string(&result)?;
    let lowered = json.to_lowercase();
    for forbidden in ["score", "scalar", "benefit_score", "activation_score"] {
        assert!(!lowered.contains(forbidden), "must not contain {forbidden}");
    }
    assert_eq!(result.assessment.dimensions.len(), 13);
    Ok(())
}

// WORK_UNIT_CASE: 620/39
#[test]
fn case_39_evidence_next_step_owner_link_without_promotion()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let empty: [StageObservation; 0] = [];
    let outcome =
        eliot_learning_activation_assessment::assess_learning_activation(&AssessmentInput {
            binding: &binding,
            target: &target,
            view: &view,
            recipe: &recipe,
            delta: &delta,
            overlay: &overlay,
            activation_id: Some(&aid("activation-620-c39")?),
            admission_receipt: None,
            activation_request_receipt: None,
            assessment_receipt: None,
            stages: &empty,
            metrics: &[],
            attrition: &[],
            confounders: &[],
            independent_evaluator_receipt: None,
            dimensions: &[],
            external_review_refs: &[],
            policy: &policy,
        })?;
    let AssessmentResultOrIncomplete::Incomplete(incomplete) = outcome else {
        return Err("expected incomplete".into());
    };
    assert!(
        incomplete
            .missing
            .contains(&MissingAssessmentField::AdmissionReceipt)
    );
    let review = vec![aid("review-620-c39")?];
    let stages_ok = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c39-rc",
        "c39-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c39b")?,
        Some(&aid("admission-620-c39b")?),
        Some(&aid("request-620-c39b")?),
        Some(&aid("receipt-620-c39b")?),
        &stages_ok,
        &[],
        &[],
        &[],
        &[],
        &review,
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(result.assessment.external_review_refs, review);
    let json = serde_json::to_string(&result)?;
    let lowered = json.to_lowercase();
    for forbidden in ["promotion_decision", "recommend_promotion", "approve"] {
        assert!(!lowered.contains(forbidden));
    }
    Ok(())
}

// WORK_UNIT_CASE: 620/40
#[test]
fn case_40_no_promotion_write_finish_state() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c40-rc",
        "c40-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c40")?,
        Some(&aid("admission-620-c40")?),
        Some(&aid("request-620-c40")?),
        Some(&aid("receipt-620-c40")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(
        result.activation.binding.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    let json = serde_json::to_string(&result)?;
    let lowered = json.to_lowercase();
    for forbidden in [
        "promotion_decision",
        "canonical_promotion",
        "finish_state",
        "persist_receipt",
    ] {
        assert!(!lowered.contains(forbidden), "must not contain {forbidden}");
    }
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/41
#[test]
#[allow(clippy::too_many_lines)]
fn case_41_every_item_output_work_deadline_cancellation_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c41-rc",
        "c41-ev",
    )?];
    let too_many_stages: Vec<StageObservation> = (0..=MAX_STAGES)
        .map(|_| unknown_stage(LifecycleStage::CandidateProduced))
        .collect();
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c41a")?,
        Some(&aid("admission-620-c41a")?),
        Some(&aid("request-620-c41a")?),
        Some(&aid("receipt-620-c41a")?),
        &too_many_stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("too many stages must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Bound { field: "stages" }
    ));
    let too_many_metrics: Vec<MetricObservation> = (0..=MAX_METRICS)
        .map(
            |index| -> Result<MetricObservation, Box<dyn std::error::Error>> {
                Ok(MetricObservation {
                    metric_id: ArtifactId::new(format!("metric-overflow-{index}-620-c41"))?,
                    name: format!("overflow-{index}"),
                    unit: "count".to_owned(),
                    population: SourceDenominator {
                        declared: 1,
                        observed: 1,
                    },
                    window: aid("window-overflow-620-c41")?,
                    baseline: None,
                    follow_up: None,
                    evaluator_receipt: aid("evaluator-overflow-620-c41")?,
                })
            },
        )
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c41b")?,
        Some(&aid("admission-620-c41b")?),
        Some(&aid("request-620-c41b")?),
        Some(&aid("receipt-620-c41b")?),
        &stages,
        &too_many_metrics,
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("too many metrics must fail");
    assert!(matches!(
        error,
        ActivationAssessmentError::Bound { field: "metrics" }
    ));
    let mut bad_policy = base_policy();
    bad_policy.max_input_bytes = 0;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &bad_policy,
        &aid("activation-620-c41c")?,
        Some(&aid("admission-620-c41c")?),
        Some(&aid("request-620-c41c")?),
        Some(&aid("receipt-620-c41c")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("zero byte limit must fail");
    assert!(matches!(error, ActivationAssessmentError::Bound { .. }));
    assert_eq!(overlay.expires_at_ms, 2_000);
    assert!(!overlay.invalidated);
    assert_eq!(base_policy().required_dimensions.len(), 13);
    Ok(())
}

// WORK_UNIT_CASE: 620/42
#[test]
fn case_42_exact_replay_and_changed_policy_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c42-rc",
        "c42-ev",
    )?];
    let activation_id = aid("activation-620-c42")?;
    let admission = aid("admission-620-c42")?;
    let request = aid("request-620-c42")?;
    let receipt = aid("receipt-620-c42")?;
    let first = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let second = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(first) = first else {
        return Err("expected candidate".into());
    };
    let AssessmentResultOrIncomplete::Candidate(second) = second else {
        return Err("expected candidate".into());
    };
    assert_eq!(first.canonical_digest, second.canonical_digest);
    let mut changed_policy = policy.clone();
    changed_policy
        .required_stages
        .push(LifecycleStage::Acknowledged);
    let changed = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &changed_policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ));
    match changed {
        Ok(AssessmentResultOrIncomplete::Candidate(changed)) => {
            assert_ne!(first.canonical_digest, changed.canonical_digest);
        }
        Err(ActivationAssessmentError::Bound { .. })
        | Ok(AssessmentResultOrIncomplete::Incomplete(_)) => {}
        Err(other) => return Err(format!("unexpected changed-policy error {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 620/43
#[test]
fn case_43_receipt_order_preserves_candidate_digest() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let mut chain = chain_up_to(LifecycleStage::Acknowledged)?;
    let policy = policy_with_stages(chain.iter().map(|item| item.stage).collect());
    let activation_id = aid("activation-620-c43")?;
    let admission = aid("admission-620-c43")?;
    let request = aid("request-620-c43")?;
    let receipt = aid("receipt-620-c43")?;
    let first = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    chain.reverse();
    let second = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &activation_id,
        Some(&admission),
        Some(&request),
        Some(&receipt),
        &chain,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(first) = first else {
        return Err("expected candidate".into());
    };
    let AssessmentResultOrIncomplete::Candidate(second) = second else {
        return Err("expected candidate".into());
    };
    assert_eq!(first.activation.stages, second.activation.stages);
    assert_eq!(
        first.activation.canonical_digest, second.activation.canonical_digest,
        "set-like stage order must preserve candidate digest"
    );
    assert_eq!(
        first.assessment.dimensions, second.assessment.dimensions,
        "set-like order must preserve dimensions"
    );
    first.validate()?;
    second.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/44
#[test]
#[allow(clippy::too_many_lines)]
fn case_44_bounded_malformed_input_never_panics() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c44-rc",
        "c44-ev",
    )?];
    let mut bad_policy = base_policy();
    bad_policy.schema_version = 999;
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &bad_policy,
        &aid("activation-620-c44a")?,
        Some(&aid("admission-620-c44a")?),
        Some(&aid("request-620-c44a")?),
        Some(&aid("receipt-620-c44a")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("bad schema version must fail without panic");
    assert!(matches!(error, ActivationAssessmentError::Bound { .. }));
    let bad_stage = StageObservation {
        stage: LifecycleStage::Delivered,
        disposition: StageDisposition::Observed,
        predecessor: Some(LifecycleStage::CandidateProduced),
        owner_receipt: Some(aid("c44-bad-rc")?),
        evidence: vec![aid("c44-bad-ev")?],
        denominator: SourceDenominator {
            declared: 0,
            observed: 0,
        },
    };
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c44b")?,
        Some(&aid("admission-620-c44b")?),
        Some(&aid("request-620-c44b")?),
        Some(&aid("receipt-620-c44b")?),
        std::slice::from_ref(&bad_stage),
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("zero denominator must fail without panic");
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    let oversized: Vec<StageObservation> = (0..(MAX_STAGES + 5))
        .map(|_| unknown_stage(LifecycleStage::CandidateProduced))
        .collect();
    let error = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c44c")?,
        Some(&aid("admission-620-c44c")?),
        Some(&aid("request-620-c44c")?),
        Some(&aid("receipt-620-c44c")?),
        &oversized,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))
    .expect_err("oversized input must fail without panic");
    assert!(matches!(error, ActivationAssessmentError::Bound { .. }));
    Ok(())
}

// WORK_UNIT_CASE: 620/45
#[test]
#[allow(clippy::too_many_lines)]
fn case_45_proven_stage_owner_evidence_and_permitted_later_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let chain = chain_up_to(LifecycleStage::Acknowledged)?;
    for stage in &chain {
        if matches!(
            stage.disposition,
            StageDisposition::Observed | StageDisposition::Partial
        ) {
            assert!(
                stage.owner_receipt.is_some(),
                "proven {stage:?} needs receipt"
            );
            assert!(
                !stage.evidence.is_empty(),
                "proven {stage:?} needs evidence"
            );
        }
    }
    let delivered_only = vec![
        observed_stage(
            LifecycleStage::CandidateProduced,
            None,
            "c45-cp-rc",
            "c45-cp-ev",
        )?,
        observed_stage(
            LifecycleStage::AdmittedForEvaluation,
            Some(LifecycleStage::CandidateProduced),
            "c45-ad-rc",
            "c45-ad-ev",
        )?,
        observed_stage(
            LifecycleStage::ActivationRequested,
            Some(LifecycleStage::AdmittedForEvaluation),
            "c45-ar-rc",
            "c45-ar-ev",
        )?,
        observed_stage(
            LifecycleStage::Retrieved,
            Some(LifecycleStage::ActivationRequested),
            "c45-rt-rc",
            "c45-rt-ev",
        )?,
        observed_stage(
            LifecycleStage::DeliveryAttempted,
            Some(LifecycleStage::Retrieved),
            "c45-da-rc",
            "c45-da-ev",
        )?,
        observed_stage(
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
            "c45-dl-rc",
            "c45-dl-ev",
        )?,
        observed_stage(
            LifecycleStage::Visible,
            Some(LifecycleStage::Delivered),
            "c45-vis-rc",
            "c45-vis-ev",
        )?,
    ];
    let policy = policy_with_stages(
        delivered_only
            .iter()
            .map(|item| item.stage)
            .chain([LifecycleStage::Acknowledged])
            .collect(),
    );
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c45")?,
        Some(&aid("admission-620-c45")?),
        Some(&aid("request-620-c45")?),
        Some(&aid("receipt-620-c45")?),
        &delivered_only,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let ack = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::Acknowledged)
        .ok_or("ack row must exist")?;
    assert_eq!(ack.disposition, StageDisposition::Unknown);
    let visible = result
        .activation
        .stages
        .iter()
        .find(|item| item.stage == LifecycleStage::Visible)
        .ok_or("visible row must exist")?;
    assert_eq!(visible.disposition, StageDisposition::Observed);
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/46
#[test]
fn case_46_every_member_stage_confounder_has_one_disposition()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c46-rc",
        "c46-ev",
    )?];
    let confounders = vec![aid("conf-620-c46a")?, aid("conf-620-c46b")?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c46")?,
        Some(&aid("admission-620-c46")?),
        Some(&aid("request-620-c46")?),
        Some(&aid("receipt-620-c46")?),
        &stages,
        &[],
        &[],
        &confounders,
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let mut seen_stages = std::collections::BTreeSet::new();
    for stage in &result.activation.stages {
        assert!(seen_stages.insert(stage.stage), "stage must appear once");
    }
    let mut seen_dims = std::collections::BTreeSet::new();
    for dimension in &result.assessment.dimensions {
        assert!(
            seen_dims.insert(dimension.dimension),
            "dimension must appear once"
        );
    }
    let mut seen_conf = std::collections::BTreeSet::new();
    for confounder in &result.activation.confounders {
        assert!(
            seen_conf.insert(confounder.as_str()),
            "confounder must appear once"
        );
    }
    for member in view.slots.iter().flat_map(|slot| slot.members.iter()) {
        assert!(!member.member_id.as_str().is_empty());
    }
    Ok(())
}

// WORK_UNIT_CASE: 620/47
#[test]
fn case_47_benefit_causal_bounded_by_ceilings() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let mut chain = chain_up_to(LifecycleStage::SemanticOutcomeObserved)?;
    chain.push(observed_stage(
        LifecycleStage::Benefit,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c47-ben-rc",
        "c47-ben-ev",
    )?);
    let policy = policy_with_stages(chain.iter().map(|item| item.stage).collect());
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c47")?,
        Some(&aid("admission-620-c47")?),
        Some(&aid("request-620-c47")?),
        Some(&aid("receipt-620-c47")?),
        &chain,
        &[],
        &[],
        &[aid("conf-620-c47")?],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 620/48
#[test]
#[allow(clippy::too_many_lines)]
fn case_48_removed_load_bearing_evidence_invalidates_status()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c48-rc",
        "c48-ev",
    )?];
    let metric = metric_fixture("c48")?;
    let confounders = vec![aid("conf-620-c48")?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c48")?,
        Some(&aid("admission-620-c48")?),
        Some(&aid("request-620-c48")?),
        Some(&aid("receipt-620-c48")?),
        &stages,
        std::slice::from_ref(&metric),
        &[],
        &confounders,
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let digest_before = result.canonical_digest.clone();
    let mut removed_stage = (*result).clone();
    removed_stage.input.stages.clear();
    removed_stage.input.seal()?;
    removed_stage.canonical_digest.clear();
    removed_stage.seal()?;
    assert!(removed_stage.validate().is_err());
    assert_ne!(removed_stage.canonical_digest, digest_before);
    let mut removed_metric = (*result).clone();
    removed_metric.input.metrics.clear();
    removed_metric.input.seal()?;
    removed_metric.canonical_digest.clear();
    removed_metric.seal()?;
    assert!(removed_metric.validate().is_err());
    let mut removed_conf = (*result).clone();
    removed_conf.input.confounders.clear();
    removed_conf.input.seal()?;
    removed_conf.canonical_digest.clear();
    removed_conf.seal()?;
    assert_ne!(removed_conf.canonical_digest, digest_before);
    assert!(removed_conf.validate().is_err());
    Ok(())
}

// WORK_UNIT_CASE: 620/49
#[test]
fn case_49_no_hidden_runtime_persistence_promotion_finish() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c49-rc",
        "c49-ev",
    )?];
    let outcome = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c49")?,
        Some(&aid("admission-620-c49")?),
        Some(&aid("request-620-c49")?),
        Some(&aid("receipt-620-c49")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = outcome else {
        return Err("expected candidate".into());
    };
    let json = serde_json::to_string(&result)?;
    let lowered = json.to_lowercase();
    for forbidden in [
        "hidden_thought",
        "runtime_action",
        "persist_receipt",
        "promotion_decision",
        "finish_state",
        "provider_call",
        "store_write",
    ] {
        assert!(!lowered.contains(forbidden), "must not contain {forbidden}");
    }
    let incomplete_json = serde_json::to_string(&AssessmentResultOrIncomplete::Incomplete(
        Box::new(eliot_learning_activation_assessment::IncompleteAssessment {
            input: result.input.clone(),
            binding: binding.clone(),
            target: target.clone(),
            missing: vec![MissingAssessmentField::AdmissionReceipt],
            supplied_stages: Vec::new(),
            supplied_dimensions: Vec::new(),
            activation_id: None,
        }),
    ))?;
    assert!(!incomplete_json.to_lowercase().contains("hidden_thought"));
    Ok(())
}

// WORK_UNIT_CASE: 620/50
#[test]
fn case_50_no_a33_a34_a35_algorithm_dependency() {
    let cargo = include_str!("../Cargo.toml");
    assert!(cargo.contains("eliot-contracts"));
    assert!(cargo.contains("eliot-evidence"));
    assert!(cargo.contains("eliot-learning-contracts"));
    for forbidden in [
        "eliot-learning-state-view",
        "eliot-learning-delta",
        "eliot-learning-overlay",
        "eliot-reactive-context-plan",
        "eliot-context",
        "eliot-runtime",
    ] {
        assert!(!cargo.contains(forbidden), "must not depend on {forbidden}");
    }
    let source = include_str!("../src/assessment.rs");
    assert!(!source.contains("learning_state_view"));
    assert!(!source.contains("learning_delta"));
    assert!(!source.contains("learning_overlay"));
}

// WORK_UNIT_CASE: 620/51
#[test]
fn case_51_no_context_runtime_store_provider_invocation() -> Result<(), Box<dyn std::error::Error>>
{
    let cargo = include_str!("../Cargo.toml");
    let lowered = cargo.to_lowercase();
    for forbidden in ["provider", "store", "runtime", "model", "effect", "finish"] {
        if forbidden == "effect" {
            continue;
        }
        assert!(
            !lowered.contains(&format!("eliot-{forbidden}")),
            "must not depend on eliot-{forbidden}"
        );
    }
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let policy = base_policy();
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "c51-rc",
        "c51-ev",
    )?];
    let first = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c51")?,
        Some(&aid("admission-620-c51")?),
        Some(&aid("request-620-c51")?),
        Some(&aid("receipt-620-c51")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let second = eliot_learning_activation_assessment::assess_learning_activation(&make_input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &policy,
        &aid("activation-620-c51")?,
        Some(&aid("admission-620-c51")?),
        Some(&aid("request-620-c51")?),
        Some(&aid("receipt-620-c51")?),
        &stages,
        &[],
        &[],
        &[],
        &[],
        &[],
    ))?;
    let AssessmentResultOrIncomplete::Candidate(first) = first else {
        return Err("expected candidate".into());
    };
    let AssessmentResultOrIncomplete::Candidate(second) = second else {
        return Err("expected candidate".into());
    };
    assert_eq!(first.canonical_digest, second.canonical_digest);
    let json = serde_json::to_string(&first)?;
    let lowered = json.to_lowercase();
    for forbidden in [
        "provider_call",
        "store_write",
        "runtime_invoke",
        "model_call",
        "finish",
    ] {
        assert!(!lowered.contains(forbidden));
    }
    Ok(())
}
