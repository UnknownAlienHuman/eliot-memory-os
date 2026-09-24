use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_learning_activation_assessment::*;
use eliot_learning_contracts::{
    ActivationSection, ActivationStatus, AdherenceSection, AdherenceStatus, AgentAttemptId,
    CampaignId, CampaignLearningStateView, ChangeOperation, ChangeSurface, Completeness,
    DeliverySection, DeliveryStatus, InverseChange, LearningStateViewRecipe, MemberId,
    MemberProjection, OmissionPolicy, OverlayChange, OverlayId, OverlayOrigin, OwnerId,
    ProofCeiling, RetrievalSection, RetrievalStatus, SlotDisposition, SlotId, SlotProjection,
    SlotRequirement, SlotSpec, TargetId, ValueState, WorkScopeId,
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

fn binding() -> Result<ContractBinding, Box<dyn std::error::Error>> {
    Ok(ContractBinding {
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
        AttemptLearningDeltaCandidate,
        CampaignHarnessOverlayCandidate,
        ContractBinding,
        TargetId,
        LearningStateViewRecipe,
    ),
    Box<dyn std::error::Error>,
> {
    let binding = binding()?;
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
    let mut delta = AttemptLearningDeltaCandidate {
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
        campaign_id: view.campaign_id.clone(),
        admission_receipt: None,
        revision: 1,
        supersedes: None,
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
        intended_mechanism: "activation-mechanism".to_owned(),
        prediction: "activation-prediction".to_owned(),
        expected_observable: "activation-observable".to_owned(),
        possible_regressions: "activation-regressions".to_owned(),
        confounders: "activation-confounders".to_owned(),
        preserved_success_constraint: "activation-preserved".to_owned(),
        next_discriminator_text: "activation-next".to_owned(),
        rollback_condition: "activation-rollback".to_owned(),
        expires_at_ms: 2_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    overlay.seal()?;
    Ok((view, delta, overlay, binding, target, recipe))
}

fn policy() -> AssessmentPolicy {
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

#[allow(clippy::too_many_arguments)]
fn input<'a>(
    view: &'a CampaignLearningStateView,
    delta: &'a AttemptLearningDeltaCandidate,
    overlay: &'a CampaignHarnessOverlayCandidate,
    binding: &'a ContractBinding,
    target: &'a TargetId,
    recipe: &'a LearningStateViewRecipe,
    policy: &'a AssessmentPolicy,
    activation_id: &'a ArtifactId,
    admission: Option<&'a ArtifactId>,
    activation_request: Option<&'a ArtifactId>,
    assessment_receipt: Option<&'a ArtifactId>,
    stages: &'a [StageObservation],
    extra: &'a ExtraEvidence,
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
        metrics: &[],
        attrition: &[],
        confounders: &[],
        independent_evaluator_receipt: None,
        dimensions: &[],
        external_review_refs: &[],
        policy,
        compiled_view_ref: &extra.compiled_view_ref,
        context_compiler_revision: &extra.context_compiler_revision,
        render_profile_revision: &extra.render_profile_revision,
        stable_harness_refs: &extra.stable_harness_refs,
        task_family_harness_refs: &extra.task_family_harness_refs,
        skill_refs: &extra.skill_refs,
        memory_refs: &extra.memory_refs,
        procedure_refs: &extra.procedure_refs,
        preserved_success_ref: extra.preserved_success_ref.as_ref(),
        eligibility_and_retrieval_reason: extra.eligibility_and_retrieval_reason.as_deref(),
        retrieval: &extra.retrieval,
        delivery: &extra.delivery,
        activation: &extra.activation,
        adherence: &extra.adherence,
        conflicts_suppression_or_compaction_loss: &extra.conflicts_suppression_or_compaction_loss,
        downstream_refs: &extra.downstream_refs,
        receipt_completeness_and_missing_fields: &extra.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: &extra.invalidation_expiry_and_missingness,
    }
}

/// Owned harness-activation evidence backing one `AssessmentInput`.
struct ExtraEvidence {
    compiled_view_ref: ArtifactId,
    context_compiler_revision: String,
    render_profile_revision: String,
    stable_harness_refs: Vec<ArtifactId>,
    task_family_harness_refs: Vec<ArtifactId>,
    skill_refs: Vec<ArtifactId>,
    memory_refs: Vec<ArtifactId>,
    procedure_refs: Vec<ArtifactId>,
    preserved_success_ref: Option<ArtifactId>,
    eligibility_and_retrieval_reason: Option<String>,
    retrieval: RetrievalSection,
    delivery: DeliverySection,
    activation: ActivationSection,
    adherence: AdherenceSection,
    conflicts_suppression_or_compaction_loss: Vec<ArtifactId>,
    downstream_refs: Vec<ArtifactId>,
    receipt_completeness_and_missing_fields: Vec<String>,
    invalidation_expiry_and_missingness: Vec<String>,
}

#[allow(clippy::expect_used)]
fn extra_evidence(suffix: &str) -> Result<ExtraEvidence, Box<dyn std::error::Error>> {
    Ok(ExtraEvidence {
        compiled_view_ref: aid(&format!("compiled-view-{suffix}"))?,
        context_compiler_revision: format!("compiler-rev-{suffix}"),
        render_profile_revision: format!("render-rev-{suffix}"),
        stable_harness_refs: vec![],
        task_family_harness_refs: vec![],
        skill_refs: vec![],
        memory_refs: vec![],
        procedure_refs: vec![],
        preserved_success_ref: None,
        eligibility_and_retrieval_reason: None,
        retrieval: RetrievalSection {
            status: RetrievalStatus::Unknown,
            expansion_or_tool_query_refs: vec![],
        },
        delivery: DeliverySection {
            status: DeliveryStatus::Missing,
            packet_position: None,
            serialized_digest: None,
            bytes: None,
            actual_tokens: None,
        },
        activation: ActivationSection {
            status: ActivationStatus::Unknown,
            acknowledgement_ref: None,
            observation_limit_reason: None,
            first_qualifying_observable_use_ref: None,
        },
        adherence: AdherenceSection {
            status: AdherenceStatus::Unknown,
            early_mid_final_checkpoint_refs: vec![],
            prescribed_or_avoided_action_and_required_verifier_refs: vec![],
        },
        conflicts_suppression_or_compaction_loss: vec![],
        downstream_refs: vec![],
        receipt_completeness_and_missing_fields: vec![],
        invalidation_expiry_and_missingness: vec![],
    })
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

#[test]
fn constructs_candidate_and_retains_unknowns() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let admission = aid("admission-620")?;
    let activation_request = aid("activation-request-620")?;
    let assessment_receipt = aid("assessment-receipt-620")?;
    let activation_id = aid("activation-620")?;
    let stage_evidence = aid("candidate-evidence")?;
    let stage_receipt = aid("candidate-receipt")?;
    let stages = [StageObservation {
        stage: LifecycleStage::CandidateProduced,
        disposition: StageDisposition::Observed,
        predecessor: None,
        owner_receipt: Some(stage_receipt),
        evidence: vec![stage_evidence],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    }];
    let p = policy();
    let extra = extra_evidence("620")?;
    let result = assess_learning_activation(&input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &p,
        &activation_id,
        Some(&admission),
        Some(&activation_request),
        Some(&assessment_receipt),
        &stages,
        &extra,
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = result else {
        return Err("unexpected incomplete result".into());
    };
    result.validate()?;
    assert_eq!(result.activation.stages.len(), 2);
    assert_eq!(result.activation.member_denominator, view.denominator);
    assert!(result.activation.stages.iter().any(|stage| {
        stage.stage == LifecycleStage::Delivered && stage.disposition == StageDisposition::Unknown
    }));
    assert_eq!(result.assessment.dimensions.len(), 13);
    assert_eq!(
        result.assessment.causal_ceiling,
        CausalCeiling::Observational
    );
    let mut tampered = (*result).clone();
    tampered.input.dimensions.push(DimensionAssessment {
        dimension: AssessmentDimension::Selection,
        status: DimensionStatus::Unknown,
        evidence: Vec::new(),
        owner_receipt: None,
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        metric_ids: vec![aid("unretained-metric")?],
        causal_ceiling: CausalCeiling::Observational,
    });
    tampered.input.seal()?;
    tampered.canonical_digest.clear();
    tampered.seal()?;
    let Err(error) = tampered.validate() else {
        return Err("public result validation unexpectedly accepted metric join".into());
    };
    assert!(matches!(
        error,
        ActivationAssessmentError::LineageMismatch {
            field: "dimension.metric_ids"
        }
    ));
    Ok(())
}

#[test]
fn missing_receipts_are_explicit_incomplete_without_fabrication()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let p = policy();
    let stages: [StageObservation; 0] = [];
    let activation_id = aid("activation-missing")?;
    let extra = extra_evidence("missing")?;
    let result = assess_learning_activation(&AssessmentInput {
        binding: &binding,
        target: &target,
        view: &view,
        recipe: &recipe,
        delta: &delta,
        overlay: &overlay,
        activation_id: Some(&activation_id),
        admission_receipt: None,
        activation_request_receipt: None,
        assessment_receipt: None,
        stages: &stages,
        metrics: &[],
        attrition: &[],
        confounders: &[],
        independent_evaluator_receipt: None,
        dimensions: &[],
        external_review_refs: &[],
        policy: &p,
        compiled_view_ref: &extra.compiled_view_ref,
        context_compiler_revision: &extra.context_compiler_revision,
        render_profile_revision: &extra.render_profile_revision,
        stable_harness_refs: &extra.stable_harness_refs,
        task_family_harness_refs: &extra.task_family_harness_refs,
        skill_refs: &extra.skill_refs,
        memory_refs: &extra.memory_refs,
        procedure_refs: &extra.procedure_refs,
        preserved_success_ref: extra.preserved_success_ref.as_ref(),
        eligibility_and_retrieval_reason: extra.eligibility_and_retrieval_reason.as_deref(),
        retrieval: &extra.retrieval,
        delivery: &extra.delivery,
        activation: &extra.activation,
        adherence: &extra.adherence,
        conflicts_suppression_or_compaction_loss: &extra.conflicts_suppression_or_compaction_loss,
        downstream_refs: &extra.downstream_refs,
        receipt_completeness_and_missing_fields: &extra.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: &extra.invalidation_expiry_and_missingness,
    })?;
    let AssessmentResultOrIncomplete::Incomplete(incomplete) = result else {
        return Err("missing receipts unexpectedly constructed a candidate".into());
    };
    assert!(
        incomplete
            .missing
            .contains(&MissingAssessmentField::AdmissionReceipt)
    );
    assert!(
        incomplete
            .missing
            .contains(&MissingAssessmentField::ActivationRequestReceipt)
    );
    assert!(
        incomplete
            .missing
            .contains(&MissingAssessmentField::AssessmentReceipt)
    );
    Ok(())
}

#[test]
fn skipped_positive_stage_is_rejected_by_canonical_predecessor_rule()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let admission = aid("admission-invalid")?;
    let activation_request = aid("activation-request-invalid")?;
    let assessment_receipt = aid("assessment-receipt-invalid")?;
    let activation_id = aid("activation-invalid")?;
    let stages = [StageObservation {
        stage: LifecycleStage::Visible,
        disposition: StageDisposition::Observed,
        // Acknowledged is an allowed predecessor for Visible, but its
        // observation is intentionally absent. The owner validator must
        // reject the missing positive predecessor record.
        predecessor: Some(LifecycleStage::Acknowledged),
        owner_receipt: Some(aid("visible-receipt")?),
        evidence: vec![aid("visible-evidence")?],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    }];
    let p = policy();
    let extra = extra_evidence("invalid")?;
    let Err(error) = assess_learning_activation(&AssessmentInput {
        binding: &binding,
        target: &target,
        view: &view,
        recipe: &recipe,
        delta: &delta,
        overlay: &overlay,
        activation_id: Some(&activation_id),
        admission_receipt: Some(&admission),
        activation_request_receipt: Some(&activation_request),
        assessment_receipt: Some(&assessment_receipt),
        stages: &stages,
        metrics: &[],
        attrition: &[],
        confounders: &[],
        independent_evaluator_receipt: None,
        dimensions: &[],
        external_review_refs: &[],
        policy: &p,
        compiled_view_ref: &extra.compiled_view_ref,
        context_compiler_revision: &extra.context_compiler_revision,
        render_profile_revision: &extra.render_profile_revision,
        stable_harness_refs: &extra.stable_harness_refs,
        task_family_harness_refs: &extra.task_family_harness_refs,
        skill_refs: &extra.skill_refs,
        memory_refs: &extra.memory_refs,
        procedure_refs: &extra.procedure_refs,
        preserved_success_ref: extra.preserved_success_ref.as_ref(),
        eligibility_and_retrieval_reason: extra.eligibility_and_retrieval_reason.as_deref(),
        retrieval: &extra.retrieval,
        delivery: &extra.delivery,
        activation: &extra.activation,
        adherence: &extra.adherence,
        conflicts_suppression_or_compaction_loss: &extra.conflicts_suppression_or_compaction_loss,
        downstream_refs: &extra.downstream_refs,
        receipt_completeness_and_missing_fields: &extra.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: &extra.invalidation_expiry_and_missingness,
    }) else {
        return Err("skipped positive stage unexpectedly succeeded".into());
    };
    assert!(matches!(error, ActivationAssessmentError::Contract { .. }));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn acknowledged_chain_retains_harm_and_attrition_evidence() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let activation_id = aid("activation-chain")?;
    let admission = aid("admission-chain")?;
    let activation_request = aid("activation-request-chain")?;
    let assessment_receipt = aid("assessment-receipt-chain")?;
    let stages = [
        observed_stage(
            LifecycleStage::CandidateProduced,
            None,
            "candidate-chain-receipt",
            "candidate-chain-evidence",
        )?,
        observed_stage(
            LifecycleStage::AdmittedForEvaluation,
            Some(LifecycleStage::CandidateProduced),
            "admitted-chain-receipt",
            "admitted-chain-evidence",
        )?,
        observed_stage(
            LifecycleStage::ActivationRequested,
            Some(LifecycleStage::AdmittedForEvaluation),
            "requested-chain-receipt",
            "requested-chain-evidence",
        )?,
        observed_stage(
            LifecycleStage::Retrieved,
            Some(LifecycleStage::ActivationRequested),
            "retrieved-chain-receipt",
            "retrieved-chain-evidence",
        )?,
        observed_stage(
            LifecycleStage::DeliveryAttempted,
            Some(LifecycleStage::Retrieved),
            "attempt-chain-receipt",
            "attempt-chain-evidence",
        )?,
        observed_stage(
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
            "delivery-chain-receipt",
            "delivery-chain-evidence",
        )?,
        observed_stage(
            LifecycleStage::Acknowledged,
            Some(LifecycleStage::Delivered),
            "ack-chain-receipt",
            "ack-chain-evidence",
        )?,
        StageObservation {
            stage: LifecycleStage::UsedInAction,
            disposition: StageDisposition::Unknown,
            predecessor: Some(LifecycleStage::Adhered),
            owner_receipt: None,
            evidence: Vec::new(),
            denominator: SourceDenominator {
                declared: 1,
                observed: 0,
            },
        },
    ];
    let dimensions = [DimensionAssessment {
        dimension: AssessmentDimension::Harm,
        status: DimensionStatus::Harm,
        evidence: vec![aid("harm-evidence")?],
        owner_receipt: Some(aid("harm-receipt")?),
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: Vec::new(),
        causal_ceiling: CausalCeiling::CausalAttribution,
    }];
    let attrition = [aid("attrition-evidence")?];
    let p = policy();
    let extra = extra_evidence("chain")?;
    let result = assess_learning_activation(&AssessmentInput {
        binding: &binding,
        target: &target,
        view: &view,
        recipe: &recipe,
        delta: &delta,
        overlay: &overlay,
        activation_id: Some(&activation_id),
        admission_receipt: Some(&admission),
        activation_request_receipt: Some(&activation_request),
        assessment_receipt: Some(&assessment_receipt),
        stages: &stages,
        metrics: &[],
        attrition: &attrition,
        confounders: &[],
        independent_evaluator_receipt: None,
        dimensions: &dimensions,
        external_review_refs: &[],
        policy: &p,
        compiled_view_ref: &extra.compiled_view_ref,
        context_compiler_revision: &extra.context_compiler_revision,
        render_profile_revision: &extra.render_profile_revision,
        stable_harness_refs: &extra.stable_harness_refs,
        task_family_harness_refs: &extra.task_family_harness_refs,
        skill_refs: &extra.skill_refs,
        memory_refs: &extra.memory_refs,
        procedure_refs: &extra.procedure_refs,
        preserved_success_ref: extra.preserved_success_ref.as_ref(),
        eligibility_and_retrieval_reason: extra.eligibility_and_retrieval_reason.as_deref(),
        retrieval: &extra.retrieval,
        delivery: &extra.delivery,
        activation: &extra.activation,
        adherence: &extra.adherence,
        conflicts_suppression_or_compaction_loss: &extra.conflicts_suppression_or_compaction_loss,
        downstream_refs: &extra.downstream_refs,
        receipt_completeness_and_missing_fields: &extra.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: &extra.invalidation_expiry_and_missingness,
    })?;
    let AssessmentResultOrIncomplete::Candidate(result) = result else {
        return Err("complete evidence unexpectedly returned incomplete".into());
    };
    assert_eq!(result.activation.stages.len(), 8);
    assert!(result.activation.stages.iter().any(|stage| {
        stage.stage == LifecycleStage::Acknowledged
            && stage.disposition == StageDisposition::Observed
    }));
    assert!(result.activation.stages.iter().any(|stage| {
        stage.stage == LifecycleStage::UsedInAction
            && stage.disposition == StageDisposition::Unknown
    }));
    assert_eq!(result.activation.attrition, attrition.to_vec());
    assert!(result.assessment.dimensions.iter().any(|dimension| {
        dimension.dimension == AssessmentDimension::Harm
            && dimension.status == DimensionStatus::Harm
            && dimension.causal_ceiling == CausalCeiling::Observational
    }));
    result.validate()?;
    Ok(())
}

#[test]
fn duplicate_required_stage_policy_is_rejected_before_owner_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let activation_id = aid("activation-duplicate-policy")?;
    let admission = aid("admission-duplicate-policy")?;
    let activation_request = aid("activation-request-duplicate-policy")?;
    let assessment_receipt = aid("assessment-receipt-duplicate-policy")?;
    let mut p = policy();
    p.required_stages.push(LifecycleStage::Delivered);
    let extra = extra_evidence("duplicate-policy")?;
    let Err(error) = assess_learning_activation(&input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &p,
        &activation_id,
        Some(&admission),
        Some(&activation_request),
        Some(&assessment_receipt),
        &[],
        &extra,
    )) else {
        return Err("duplicate required stage unexpectedly succeeded".into());
    };
    assert!(matches!(
        error,
        ActivationAssessmentError::Bound {
            field: "policy.required_stages"
        }
    ));
    Ok(())
}

#[test]
fn dimension_metric_reference_must_be_supplied() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let activation_id = aid("activation-metric-reference")?;
    let admission = aid("admission-metric-reference")?;
    let activation_request = aid("activation-request-metric-reference")?;
    let assessment_receipt = aid("assessment-receipt-metric-reference")?;
    let dimensions = [DimensionAssessment {
        dimension: AssessmentDimension::Selection,
        status: DimensionStatus::Unknown,
        evidence: Vec::new(),
        owner_receipt: None,
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        metric_ids: vec![aid("metric-not-supplied")?],
        causal_ceiling: CausalCeiling::Observational,
    }];
    let p = policy();
    let extra = extra_evidence("metric-reference")?;
    let Err(error) = assess_learning_activation(&AssessmentInput {
        binding: &binding,
        target: &target,
        view: &view,
        recipe: &recipe,
        delta: &delta,
        overlay: &overlay,
        activation_id: Some(&activation_id),
        admission_receipt: Some(&admission),
        activation_request_receipt: Some(&activation_request),
        assessment_receipt: Some(&assessment_receipt),
        stages: &[],
        metrics: &[],
        attrition: &[],
        confounders: &[],
        independent_evaluator_receipt: None,
        dimensions: &dimensions,
        external_review_refs: &[],
        policy: &p,
        compiled_view_ref: &extra.compiled_view_ref,
        context_compiler_revision: &extra.context_compiler_revision,
        render_profile_revision: &extra.render_profile_revision,
        stable_harness_refs: &extra.stable_harness_refs,
        task_family_harness_refs: &extra.task_family_harness_refs,
        skill_refs: &extra.skill_refs,
        memory_refs: &extra.memory_refs,
        procedure_refs: &extra.procedure_refs,
        preserved_success_ref: extra.preserved_success_ref.as_ref(),
        eligibility_and_retrieval_reason: extra.eligibility_and_retrieval_reason.as_deref(),
        retrieval: &extra.retrieval,
        delivery: &extra.delivery,
        activation: &extra.activation,
        adherence: &extra.adherence,
        conflicts_suppression_or_compaction_loss: &extra.conflicts_suppression_or_compaction_loss,
        downstream_refs: &extra.downstream_refs,
        receipt_completeness_and_missing_fields: &extra.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: &extra.invalidation_expiry_and_missingness,
    }) else {
        return Err("missing metric reference unexpectedly succeeded".into());
    };
    assert!(matches!(
        error,
        ActivationAssessmentError::LineageMismatch {
            field: "dimension.metric_ids"
        }
    ));
    Ok(())
}

#[test]
fn eligible_overlay_without_delivery_stays_not_observed() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let activation_id = aid("activation-a1")?;
    let admission = aid("admission-a1")?;
    let activation_request = aid("activation-request-a1")?;
    let assessment_receipt = aid("assessment-receipt-a1")?;
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "candidate-a1-receipt",
        "candidate-a1-evidence",
    )?];
    let mut extra = extra_evidence("a1")?;
    extra.retrieval.status = RetrievalStatus::EligibleNotRetrieved;
    extra.eligibility_and_retrieval_reason = Some("eligible; not retrieved".to_owned());
    extra.delivery.status = DeliveryStatus::NotDelivered;
    extra.activation.status = ActivationStatus::NotObserved;
    let p = policy();
    let result = assess_learning_activation(&input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &p,
        &activation_id,
        Some(&admission),
        Some(&activation_request),
        Some(&assessment_receipt),
        &stages,
        &extra,
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = result else {
        return Err("eligible overlay unexpectedly returned incomplete".into());
    };
    result.validate()?;
    assert_eq!(
        result.activation.retrieval.status,
        RetrievalStatus::EligibleNotRetrieved
    );
    assert_eq!(
        result.activation.delivery.status,
        DeliveryStatus::NotDelivered
    );
    assert_eq!(
        result.activation.activation.status,
        ActivationStatus::NotObserved
    );
    assert!(
        result
            .activation
            .activation
            .first_qualifying_observable_use_ref
            .is_none()
    );
    Ok(())
}

#[test]
fn acknowledgement_without_use_stays_not_observed() -> Result<(), Box<dyn std::error::Error>> {
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let activation_id = aid("activation-a2")?;
    let admission = aid("admission-a2")?;
    let activation_request = aid("activation-request-a2")?;
    let assessment_receipt = aid("assessment-receipt-a2")?;
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "candidate-a2-receipt",
        "candidate-a2-evidence",
    )?];
    let mut extra = extra_evidence("a2")?;
    let ack = aid("ack-a2")?;
    extra.activation.status = ActivationStatus::NotObserved;
    extra.activation.acknowledgement_ref = Some(ack.clone());
    let p = policy();
    let result = assess_learning_activation(&input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &p,
        &activation_id,
        Some(&admission),
        Some(&activation_request),
        Some(&assessment_receipt),
        &stages,
        &extra,
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = result else {
        return Err("acknowledged attempt unexpectedly returned incomplete".into());
    };
    result.validate()?;
    assert_eq!(result.activation.activation.acknowledgement_ref, Some(ack));
    assert_eq!(
        result.activation.activation.status,
        ActivationStatus::NotObserved
    );
    assert!(
        result
            .activation
            .activation
            .first_qualifying_observable_use_ref
            .is_none()
    );
    Ok(())
}

#[test]
fn observed_violation_retains_checkpoint_and_action_refs() -> Result<(), Box<dyn std::error::Error>>
{
    let (view, delta, overlay, binding, target, recipe) = fixture()?;
    let activation_id = aid("activation-a3")?;
    let admission = aid("admission-a3")?;
    let activation_request = aid("activation-request-a3")?;
    let assessment_receipt = aid("assessment-receipt-a3")?;
    let stages = [observed_stage(
        LifecycleStage::CandidateProduced,
        None,
        "candidate-a3-receipt",
        "candidate-a3-evidence",
    )?];
    let mut extra = extra_evidence("a3")?;
    let checkpoints = vec![aid("checkpoint-a3")?];
    let actions = vec![aid("violated-action-a3")?, aid("verifier-a3")?];
    extra.adherence.status = AdherenceStatus::ObservedViolated;
    extra.adherence.early_mid_final_checkpoint_refs = checkpoints.clone();
    extra
        .adherence
        .prescribed_or_avoided_action_and_required_verifier_refs = actions.clone();
    let p = policy();
    let result = assess_learning_activation(&input(
        &view,
        &delta,
        &overlay,
        &binding,
        &target,
        &recipe,
        &p,
        &activation_id,
        Some(&admission),
        Some(&activation_request),
        Some(&assessment_receipt),
        &stages,
        &extra,
    ))?;
    let AssessmentResultOrIncomplete::Candidate(result) = result else {
        return Err("observed violation unexpectedly returned incomplete".into());
    };
    result.validate()?;
    assert_eq!(
        result.activation.adherence.status,
        AdherenceStatus::ObservedViolated
    );
    assert_eq!(
        result.activation.adherence.early_mid_final_checkpoint_refs,
        checkpoints
    );
    assert_eq!(
        result
            .activation
            .adherence
            .prescribed_or_avoided_action_and_required_verifier_refs,
        actions
    );
    Ok(())
}
