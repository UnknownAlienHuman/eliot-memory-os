use eliot_agent_contracts::{AgentAttemptId, TargetId};
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::{
    AssessmentDimension, AssignmentKind, AttemptFailure, AttemptLearningDeltaCandidate,
    AttemptLearningOutcome, AttemptLearningResult, AttributedSubject,
    CampaignHarnessOverlayCandidate, CampaignId, CampaignLearningStateView, CausalCeiling,
    ChangeOperation, ChangeSurface, ClosureHandoff, Completeness, ContractBinding,
    DimensionAssessment, DimensionStatus, ExternalDecisionClass, HarnessActivationReceiptCandidate,
    HistoryRetention, ImprovementExperimentCandidate, InverseChange, LearningAssessmentCandidate,
    LearningContractError, LearningStateViewRecipe, LearningTargetId, LifecycleStage, MemberId,
    MemberProjection, MetricObservation, NoChangeReason, NonUseDeclaration, OmissionPolicy,
    OverlayChange, OverlayId, OverlayOrigin, OwnerDisagreement, OwnerId, OwnerProof,
    PromotionBoundaryCandidate, PromotionMutationTarget, RolloutBoundary, SlotDisposition, SlotId,
    SlotProjection, SlotRequirement, SlotSpec, SourceDenominator, StageDisposition,
    StageObservation, SubjectKind, UseAttributionCandidate, UseBasis, UseDisposition, ValueState,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn must<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
}

fn must_some<T>(option: Option<T>) -> T {
    option.unwrap_or_else(|| panic!("fixture failed: unexpected none"))
}

fn aid(value: &str) -> ArtifactId {
    must(ArtifactId::new(value))
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn target(value: &str) -> TargetId {
    must(TargetId::new(value))
}

fn binding(tag: &str) -> ContractBinding {
    let lineage = must(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000"));
    let sequence = must_some(std::num::NonZeroU64::new(1));
    ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: must(RequestId::new(format!("request-590-{tag}"))),
        operation_id: must(OperationId::new(format!("operation-590-{tag}"))),
        product_id: must(ProductId::new("eliot")),
        task_id: must(TaskId::new(format!("task-590-{tag}"))),
        scope: must(WorkScopeId::new(format!("scope-590-{tag}"))),
        state_fence: StateFence::new(
            must(EpochId::new(lineage, sequence)),
            ResourceGeneration::genesis(),
        ),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: must(SourceId::new(format!("source-590-{tag}"))),
            snapshot: aid(&format!("snapshot-590-{tag}")),
            revision: TaskRevision::genesis(),
            digest: digest("source-590"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

fn slot_spec(tag: &str, target: &TargetId, requirement: SlotRequirement) -> SlotSpec {
    SlotSpec {
        slot_id: SlotId::from_artifact(aid(&format!("slot-590-{tag}"))),
        owner: OwnerId::from_artifact(aid(&format!("owner-590-{tag}"))),
        target: target.clone(),
        requirement,
        declared_members: vec![MemberId::from_artifact(aid(&format!("member-590-{tag}")))],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema-590"),
    }
}

fn recipe_and_view() -> (LearningStateViewRecipe, CampaignLearningStateView) {
    let target = target("target-590-base");
    let binding = binding("base");
    let spec = slot_spec("req", &target, SlotRequirement::Required);
    let mut optional = slot_spec("opt", &target, SlotRequirement::Optional);
    optional.slot_id = SlotId::from_artifact(aid("slot-590-opt"));
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-590-base"),
        campaign_id: CampaignId::from_artifact(aid("campaign-590-base")),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![spec.clone(), optional.clone()],
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    must(recipe.seal());
    let member = MemberProjection {
        member_id: spec.declared_members[0].clone(),
        owner: spec.owner.clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("strategy-value-590")),
        evidence: vec![aid("evidence-590-view")],
    };
    let mut view = CampaignLearningStateView {
        view_id: aid("view-590-base"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target,
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id: spec.slot_id,
            disposition: SlotDisposition::Current,
            members: vec![member],
            evidence: vec![aid("evidence-590-slot")],
        }],
        denominator: SourceDenominator {
            declared: 2,
            observed: 1,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![optional.slot_id],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("objective-590-ref")],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    must(view.seal());
    (recipe, view)
}

fn valid_delta(tag: &str) -> AttemptLearningDeltaCandidate {
    use eliot_learning_contracts::AttemptLearningDeltaCandidate;
    let target = target(&format!("target-590-{tag}"));
    let binding = binding(tag);
    let after = ValueState {
        present: true,
        digest: Some(digest(&format!("after-590-{tag}"))),
    };
    let mut delta = AttemptLearningDeltaCandidate {
        binding,
        attempt_id: must(AgentAttemptId::new(format!("attempt-590-{tag}"))),
        delta_id: aid(&format!("delta-590-{tag}")),
        target: target.clone(),
        base_view_digest: digest(&format!("base-view-590-{tag}")),
        pre_observation_discriminator: aid(&format!("disc-590-{tag}")),
        intended_strategy: aid(&format!("intended-590-{tag}")),
        attempted_strategy: aid(&format!("attempted-590-{tag}")),
        changes: vec![ChangeOperation::Add {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            after: after.clone(),
        }],
        inverses: vec![InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Remove {
                target: target.clone(),
                surface: ChangeSurface::Strategy,
                before: after,
            },
        }],
        evidence: vec![aid(&format!("delta-ev-590-{tag}"))],
        evaluator_receipts: vec![aid(&format!("delta-eval-590-{tag}"))],
        baseline: vec![aid(&format!("delta-base-590-{tag}"))],
        control: vec![aid(&format!("delta-ctrl-590-{tag}"))],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    must(delta.seal());
    delta
}

fn valid_no_change(
    tag: &str,
    reason: NoChangeReason,
) -> eliot_learning_contracts::NoChangeDisposition {
    let binding = binding(tag);
    let target = target(&format!("target-590-nc-{tag}"));
    let mut disposition = eliot_learning_contracts::NoChangeDisposition {
        binding,
        attempt_id: must(AgentAttemptId::new(format!("attempt-590-nc-{tag}"))),
        target,
        reason,
        affirmative_evidence: vec![aid(&format!("nce-590-{tag}"))],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        canonical_digest: String::new(),
    };
    must(disposition.seal());
    disposition
}

fn valid_overlay(tag: &str) -> CampaignHarnessOverlayCandidate {
    let binding = binding(&format!("ov-{tag}"));
    let target = target(&format!("target-590-ov-{tag}"));
    let proposed = ValueState {
        present: true,
        digest: Some(digest(&format!("ov-value-590-{tag}"))),
    };
    let base = ValueState {
        present: false,
        digest: None,
    };
    let mut overlay = CampaignHarnessOverlayCandidate {
        binding,
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-590-{tag}"))),
        base_view_digest: digest(&format!("base-view-590-{tag}")),
        parent_revision: TaskRevision::genesis(),
        admitted_delta_ids: vec![aid(&format!("admitted-590-{tag}"))],
        admitted_delta_digests: vec![digest(&format!("admitted-shape-590-{tag}"))],
        changes: vec![OverlayChange {
            target: target.clone(),
            surface: ChangeSurface::TaskLocalContext,
            base: base.clone(),
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
        application_order: vec![target],
        protected_surface_base_digest: digest("protected-590"),
        protected_surface_proposed_digest: digest("protected-590"),
        fixed_before_observation_discriminator: aid(&format!("ov-disc-590-{tag}")),
        expires_at_ms: 9_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    must(overlay.seal());
    overlay
}

fn stage_observation(
    stage: LifecycleStage,
    predecessor: Option<LifecycleStage>,
    tag: &str,
) -> StageObservation {
    StageObservation {
        stage,
        disposition: StageDisposition::Observed,
        predecessor,
        owner_receipt: Some(aid(&format!("receipt-590-{tag}"))),
        evidence: vec![aid(&format!("stage-ev-590-{tag}"))],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    }
}

fn valid_dimension(
    dimension: AssessmentDimension,
    status: DimensionStatus,
    tag: &str,
) -> DimensionAssessment {
    let established = matches!(
        status,
        DimensionStatus::Pass
            | DimensionStatus::Fail
            | DimensionStatus::Harm
            | DimensionStatus::NoEffect
    );
    let (evidence, owner_receipt) = if established {
        (
            vec![aid(&format!("dim-ev-590-{tag}"))],
            Some(aid(&format!("dim-rc-590-{tag}"))),
        )
    } else {
        (vec![], None)
    };
    DimensionAssessment {
        dimension,
        status,
        evidence,
        owner_receipt,
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: vec![aid(&format!("dim-m-590-{tag}"))],
        causal_ceiling: CausalCeiling::Observational,
    }
}

fn valid_activation(tag: &str) -> HarnessActivationReceiptCandidate {
    let binding = binding(&format!("act-{tag}"));
    let target = target(&format!("target-590-act-{tag}"));
    let mut receipt = HarnessActivationReceiptCandidate {
        binding,
        activation_id: aid(&format!("activation-590-{tag}")),
        target,
        view_digest: digest(&format!("view-590-{tag}")),
        delta_id: aid(&format!("delta-590-{tag}")),
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-590-{tag}"))),
        admission_receipt: aid(&format!("admission-590-{tag}")),
        activation_request_receipt: aid(&format!("actreq-590-{tag}")),
        stages: vec![stage_observation(
            LifecycleStage::CandidateProduced,
            None,
            &format!("act-{tag}"),
        )],
        member_denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metrics: vec![],
        attrition: vec![],
        confounders: vec![],
        independent_evaluator_receipt: Some(aid(&format!("indep-590-{tag}"))),
        canonical_digest: String::new(),
    };
    must(receipt.seal());
    receipt
}

fn valid_assessment(tag: &str) -> LearningAssessmentCandidate {
    let binding = binding(&format!("ass-{tag}"));
    let target = target(&format!("target-590-ass-{tag}"));
    let mut assessment = LearningAssessmentCandidate {
        binding,
        target,
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-590-{tag}"))),
        activation_id: aid(&format!("activation-590-{tag}")),
        activation_digest: digest(&format!("activation-shape-590-{tag}")),
        assessment_receipt: aid(&format!("assess-590-{tag}")),
        dimensions: vec![
            valid_dimension(
                AssessmentDimension::Adherence,
                DimensionStatus::Pass,
                &format!("ass-{tag}-a"),
            ),
            valid_dimension(
                AssessmentDimension::Harm,
                DimensionStatus::NoEffect,
                &format!("ass-{tag}-h"),
            ),
        ],
        causal_ceiling: CausalCeiling::Observational,
        external_review_refs: vec![aid(&format!("review-590-{tag}"))],
        canonical_digest: String::new(),
    };
    must(assessment.seal());
    assessment
}

fn valid_closure(tag: &str) -> ClosureHandoff {
    let binding = binding(&format!("clo-{tag}"));
    let target = target(&format!("target-590-clo-{tag}"));
    let owner = OwnerId::from_artifact(aid(&format!("owner-590-{tag}")));
    let mut handoff = ClosureHandoff {
        binding: binding.clone(),
        target,
        delta_id: aid(&format!("delta-590-{tag}")),
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-590-{tag}"))),
        assessment_id: aid(&format!("assess-590-{tag}")),
        assessment_digest: digest(&format!("assess-shape-590-{tag}")),
        required_owner_proofs: vec![OwnerProof {
            owner,
            receipt: aid(&format!("clo-receipt-590-{tag}")),
            scope: binding.scope.clone(),
            state_fence: binding.state_fence.clone(),
            evidence: vec![aid(&format!("clo-ev-590-{tag}"))],
            proof_ceiling: ProofCeiling::CandidateArtifact,
        }],
        debts: vec![AssessmentDimension::Harm],
        rollback_refs: vec![aid(&format!("rollback-590-{tag}"))],
        external_promotion_refs: vec![aid(&format!("promo-owner-590-{tag}"))],
        requested_decision: ExternalDecisionClass::ClosureReview,
        canonical_digest: String::new(),
    };
    must(handoff.seal());
    handoff
}

fn valid_attribution(tag: &str) -> UseAttributionCandidate {
    let binding = binding(&format!("att-{tag}"));
    let target = target(&format!("target-590-att-{tag}"));
    let subject_id = aid(&format!("subject-590-{tag}"));
    let mut candidate = UseAttributionCandidate {
        binding,
        attribution_id: aid(&format!("attr-590-{tag}")),
        target,
        subject: AttributedSubject {
            kind: SubjectKind::Candidate,
            id: subject_id.clone(),
            version: format!("v1.0.0-{tag}"),
            digest: digest(&format!("subject-590-{tag}")),
        },
        decision_action_id: aid(&format!("decision-590-{tag}")),
        source_delta_id: aid(&format!("delta-590-{tag}")),
        source_delta_digest: digest(&format!("delta-shape-590-{tag}")),
        disposition: UseDisposition::Used,
        use_basis: UseBasis::DirectObservation,
        denominator: SourceDenominator {
            declared: 3,
            observed: 3,
        },
        eligible_refs: vec![subject_id, aid(&format!("rival-590-{tag}"))],
        non_use: vec![NonUseDeclaration {
            subject: aid(&format!("nonuse-590-{tag}")),
            reason: "out of scope for this decision".to_owned(),
        }],
        competing_contributors: vec![aid(&format!("comp-590-{tag}"))],
        evaluator_receipt: aid(&format!("eval-590-{tag}")),
        evidence_refs: vec![aid(&format!("attr-ev-590-{tag}"))],
        dimensions: vec![
            valid_dimension(
                AssessmentDimension::ActionLinkedUse,
                DimensionStatus::Pass,
                &format!("att-{tag}-u"),
            ),
            valid_dimension(
                AssessmentDimension::Harm,
                DimensionStatus::NoEffect,
                &format!("att-{tag}-h"),
            ),
            valid_dimension(
                AssessmentDimension::SourceEvaluatorIndependence,
                DimensionStatus::Pass,
                &format!("att-{tag}-i"),
            ),
        ],
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    must(candidate.seal());
    candidate
}

fn valid_experiment(tag: &str) -> ImprovementExperimentCandidate {
    let binding = binding(&format!("exp-{tag}"));
    let target = target(&format!("target-590-exp-{tag}"));
    let attribution = valid_attribution(&format!("exp-{tag}"));
    let mut candidate = ImprovementExperimentCandidate {
        binding: binding.clone(),
        experiment_id: aid(&format!("exp-590-{tag}")),
        target: target.clone(),
        attribution_id: attribution.attribution_id.clone(),
        attribution_digest: attribution.canonical_digest.clone(),
        hypothesis: format!("candidate {tag} improves adherence without new harm"),
        eligibility: format!("eligible when fence and scope match {tag}"),
        assignment: AssignmentKind::Randomized,
        assignment_seed_digest: digest(&format!("seed-590-{tag}")),
        intervention_id: aid(&format!("interv-590-{tag}")),
        control_id: aid(&format!("ctrl-590-{tag}")),
        pre_observation_discriminator: aid(&format!("expdisc-590-{tag}")),
        safeguards: vec![aid(&format!("safe-590-{tag}"))],
        stop_conditions: vec![format!("stop on harm signal {tag}")],
        rollback_refs: vec![aid(&format!("exproll-590-{tag}"))],
        contamination_policy: format!("exclude prior exposure {tag}"),
        prior_exposure_refs: vec![aid(&format!("prior-590-{tag}"))],
        evidence_freeze_digest: digest(&format!("freeze-590-{tag}")),
        evidence_freeze_refs: vec![aid(&format!("frozen-590-{tag}"))],
        outcome_dimensions: vec![
            valid_dimension(
                AssessmentDimension::BaselineControlQuality,
                DimensionStatus::Pass,
                &format!("exp-{tag}-c"),
            ),
            valid_dimension(
                AssessmentDimension::Harm,
                DimensionStatus::NoEffect,
                &format!("exp-{tag}-h"),
            ),
        ],
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    // Re-anchor attribution lineage to the local binding/target so the
    // experiment validates standalone without cross-fixture scope drift.
    candidate.binding = attribution.binding.clone();
    candidate.target = attribution.target.clone();
    candidate.attribution_id = attribution.attribution_id.clone();
    candidate
        .attribution_digest
        .clone_from(&attribution.canonical_digest);
    must(candidate.seal());
    candidate
}

fn valid_promotion(tag: &str) -> PromotionBoundaryCandidate {
    let attribution = valid_attribution(&format!("pro-{tag}"));
    let binding = attribution.binding.clone();
    let target = attribution.target.clone();
    let mut experiment = valid_experiment(&format!("pro-{tag}"));
    experiment.binding = binding.clone();
    experiment.target = target.clone();
    experiment.attribution_id = attribution.attribution_id.clone();
    experiment
        .attribution_digest
        .clone_from(&attribution.canonical_digest);
    must(experiment.seal());
    let mut candidate = PromotionBoundaryCandidate {
        binding: binding.clone(),
        promotion_id: aid(&format!("promo-590-{tag}")),
        target: target.clone(),
        attribution_id: attribution.attribution_id.clone(),
        attribution_digest: attribution.canonical_digest.clone(),
        experiment_id: experiment.experiment_id.clone(),
        experiment_digest: experiment.canonical_digest.clone(),
        governor_receipt_ref: Some(aid(&format!("gov-590-{tag}"))),
        rollout: RolloutBoundary {
            reversible: true,
            canary_required: true,
            invalidation_conditions: vec![format!("harm signal {tag}")],
        },
        mutation_target: PromotionMutationTarget::CandidateOnly,
        supersedes: vec![],
        invalidates: vec![],
        history_retention: HistoryRetention::RetainAlways,
        evaluation_dimensions: vec![
            valid_dimension(
                AssessmentDimension::Harm,
                DimensionStatus::Harm,
                &format!("pro-{tag}-h"),
            ),
            valid_dimension(
                AssessmentDimension::OutcomeValidity,
                DimensionStatus::Pass,
                &format!("pro-{tag}-o"),
            ),
        ],
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    must(candidate.seal());
    candidate
}

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let encoded = must(serde_json::to_string(value));
    must(serde_json::from_str(&encoded))
}

fn with_unknown_field(encoded: &str) -> String {
    with_field(encoded, "\"unexpected_590\":true")
}

fn with_field(base: &str, extra: &str) -> String {
    let trimmed = must_some(base.strip_suffix('}'));
    format!("{trimmed},{extra}}}")
}

fn schema_text<T: schemars::JsonSchema>() -> String {
    must(serde_json::to_string(&schemars::schema_for!(T)))
}

fn assert_no_keys(schema: &str, keys: &[&str]) {
    for key in keys {
        let pattern = format!("\"{key}\":");
        assert!(
            !schema.contains(&pattern),
            "schema must not expose key {key}"
        );
    }
}

// WORK_UNIT_CASE: 590/1
#[test]
fn exact_target_view_delta_overlay_assessment_closure_schemas() {
    let (recipe, view) = recipe_and_view();
    must(recipe.validate());
    must(view.validate_against(&recipe));
    let delta = valid_delta("c01");
    must(delta.validate());
    let overlay = valid_overlay("c01");
    must(overlay.validate());
    let activation = valid_activation("c01");
    must(activation.validate());
    let assessment = valid_assessment("c01");
    must(assessment.validate());
    let closure = valid_closure("c01");
    must(closure.validate());
    let attribution = valid_attribution("c01");
    must(attribution.validate());
    let experiment = valid_experiment("c01");
    must(experiment.validate_against_attribution(&valid_attribution("exp-c01")));
    let promotion = valid_promotion("c01");
    must(promotion.validate());
    assert_eq!(roundtrip(&recipe), recipe);
    assert_eq!(roundtrip(&view), view);
    assert_eq!(roundtrip(&delta), delta);
    assert_eq!(roundtrip(&overlay), overlay);
    assert_eq!(roundtrip(&activation), activation);
    assert_eq!(roundtrip(&assessment), assessment);
    assert_eq!(roundtrip(&closure), closure);
    assert_eq!(roundtrip(&attribution), attribution);
    assert_eq!(roundtrip(&promotion), promotion);
}

// WORK_UNIT_CASE: 590/2
#[test]
fn exactly_two_successful_attempt_learning_outcome_arms() {
    let delta = valid_delta("c02");
    let outcome_delta = AttemptLearningOutcome::Delta(delta.clone());
    let no_change = valid_no_change("c02", NoChangeReason::ConfirmedFixedPrediction);
    let outcome_no_change = AttemptLearningOutcome::NoChange(no_change.clone());
    let delta_wire = must(serde_json::to_string(&outcome_delta));
    let no_change_wire = must(serde_json::to_string(&outcome_no_change));
    assert!(delta_wire.contains("\"outcome\":\"DELTA\""));
    assert!(no_change_wire.contains("\"outcome\":\"NO_CHANGE\""));
    assert!(!delta_wire.contains("NO_CHANGE"));
    assert!(!no_change_wire.contains("\"outcome\":\"DELTA\""));
    let restored_delta: AttemptLearningOutcome = must(serde_json::from_str(&delta_wire));
    let restored_no_change: AttemptLearningOutcome = must(serde_json::from_str(&no_change_wire));
    assert_eq!(restored_delta, outcome_delta);
    assert_eq!(restored_no_change, outcome_no_change);
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>("{\"outcome\":\"ERROR\",\"value\":null}")
            .is_err()
    );
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>(
            "{\"outcome\":\"CANCELLED\",\"value\":null}"
        )
        .is_err()
    );
    let success_delta = AttemptLearningResult::Success(outcome_delta);
    let failure = AttemptLearningResult::Failure(AttemptFailure::Cancelled);
    assert!(matches!(success_delta, AttemptLearningResult::Success(_)));
    assert!(matches!(failure, AttemptLearningResult::Failure(_)));
    for failure_arm in [
        AttemptFailure::Error,
        AttemptFailure::Cancelled,
        AttemptFailure::Exhausted,
        AttemptFailure::NonConsequential,
        AttemptFailure::Unknown,
    ] {
        let wire = must(serde_json::to_string(&AttemptLearningResult::Failure(
            failure_arm,
        )));
        let restored: AttemptLearningResult = must(serde_json::from_str(&wire));
        assert_eq!(restored, AttemptLearningResult::Failure(failure_arm));
    }
}

// WORK_UNIT_CASE: 590/3
#[test]
#[allow(clippy::too_many_lines)]
fn exact_lifecycle_predecessor_vocabulary() {
    let expected: &[(LifecycleStage, &str, Option<LifecycleStage>)] = &[
        (
            LifecycleStage::CandidateProduced,
            "CANDIDATE_PRODUCED",
            None,
        ),
        (
            LifecycleStage::AdmittedForEvaluation,
            "ADMITTED_FOR_EVALUATION",
            Some(LifecycleStage::CandidateProduced),
        ),
        (
            LifecycleStage::ActivationRequested,
            "ACTIVATION_REQUESTED",
            Some(LifecycleStage::AdmittedForEvaluation),
        ),
        (
            LifecycleStage::Retrieved,
            "RETRIEVED",
            Some(LifecycleStage::ActivationRequested),
        ),
        (
            LifecycleStage::DeliveryAttempted,
            "DELIVERY_ATTEMPTED",
            Some(LifecycleStage::Retrieved),
        ),
        (
            LifecycleStage::Delivered,
            "DELIVERED",
            Some(LifecycleStage::DeliveryAttempted),
        ),
        (
            LifecycleStage::Acknowledged,
            "ACKNOWLEDGED",
            Some(LifecycleStage::Delivered),
        ),
        (
            LifecycleStage::Visible,
            "VISIBLE",
            Some(LifecycleStage::Acknowledged),
        ),
        (
            LifecycleStage::SelectedActivated,
            "SELECTED_ACTIVATED",
            Some(LifecycleStage::Visible),
        ),
        (
            LifecycleStage::Adhered,
            "ADHERED",
            Some(LifecycleStage::SelectedActivated),
        ),
        (
            LifecycleStage::UsedInAction,
            "USED_IN_ACTION",
            Some(LifecycleStage::Adhered),
        ),
        (
            LifecycleStage::ActionOutputObserved,
            "ACTION_OUTPUT_OBSERVED",
            Some(LifecycleStage::UsedInAction),
        ),
        (
            LifecycleStage::SemanticOutcomeObserved,
            "SEMANTIC_OUTCOME_OBSERVED",
            Some(LifecycleStage::ActionOutputObserved),
        ),
        (
            LifecycleStage::Benefit,
            "BENEFIT",
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::Harm,
            "HARM",
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::NoEffect,
            "NO_EFFECT",
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::Inconclusive,
            "INCONCLUSIVE",
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::CausalAssessment,
            "CAUSAL_ASSESSMENT",
            Some(LifecycleStage::Benefit),
        ),
        (
            LifecycleStage::ExternalPromotion,
            "EXTERNAL_PROMOTION",
            Some(LifecycleStage::CausalAssessment),
        ),
        (LifecycleStage::Closure, "CLOSURE", None),
    ];
    assert_eq!(expected.len(), 20);
    for (stage, wire, predecessor) in expected {
        assert_eq!(stage.as_str(), *wire);
        assert_eq!(stage.required_predecessor(), *predecessor);
        let encoded = must(serde_json::to_string(stage));
        assert_eq!(encoded, format!("\"{wire}\""));
        let restored: LifecycleStage = must(serde_json::from_str(&encoded));
        assert_eq!(&restored, stage);
    }
    assert!(serde_json::from_str::<LifecycleStage>("\"DELIVERED_ACK\"").is_err());
}

// WORK_UNIT_CASE: 590/4
#[test]
fn change_nochange_protected_assessment_vocabularies() {
    let surfaces: &[(ChangeSurface, &str)] = &[
        (ChangeSurface::TaskLocalContext, "TASK_LOCAL_CONTEXT"),
        (ChangeSurface::Memory, "MEMORY"),
        (ChangeSurface::Skill, "SKILL"),
        (ChangeSurface::Tool, "TOOL"),
        (ChangeSurface::Route, "ROUTE"),
        (ChangeSurface::Hypothesis, "HYPOTHESIS"),
        (ChangeSurface::Strategy, "STRATEGY"),
        (ChangeSurface::Abstraction, "ABSTRACTION"),
        (ChangeSurface::CandidateParent, "CANDIDATE_PARENT"),
        (ChangeSurface::VerificationOrder, "VERIFICATION_ORDER"),
        (ChangeSurface::SearchProbeStopping, "SEARCH_PROBE_STOPPING"),
    ];
    assert_eq!(surfaces.len(), 11);
    for (surface, wire) in surfaces {
        let encoded = must(serde_json::to_string(surface));
        assert_eq!(encoded, format!("\"{wire}\""));
    }
    let reasons: &[(NoChangeReason, &str)] = &[
        (
            NoChangeReason::ConfirmedFixedPrediction,
            "CONFIRMED_FIXED_PREDICTION",
        ),
        (
            NoChangeReason::ControlledReplicationNeeded,
            "CONTROLLED_REPLICATION_NEEDED",
        ),
        (NoChangeReason::ProtectedConstraint, "PROTECTED_CONSTRAINT"),
        (
            NoChangeReason::ProvenNonApplicability,
            "PROVEN_NON_APPLICABILITY",
        ),
        (NoChangeReason::Contradicted, "CONTRADICTED"),
        (NoChangeReason::UnsafeCandidate, "UNSAFE_CANDIDATE"),
        (NoChangeReason::OwnerBlocked, "OWNER_BLOCKED"),
        (
            NoChangeReason::ExternalReviewRequired,
            "EXTERNAL_REVIEW_REQUIRED",
        ),
    ];
    assert_eq!(reasons.len(), 8);
    for (reason, wire) in reasons {
        let encoded = must(serde_json::to_string(reason));
        assert_eq!(encoded, format!("\"{wire}\""));
        let restored: NoChangeReason = must(serde_json::from_str(&encoded));
        assert_eq!(&restored, reason);
    }
    let dimensions: &[(AssessmentDimension, &str)] = &[
        (
            AssessmentDimension::TargetCoverageAttrition,
            "TARGET_COVERAGE_ATTRITION",
        ),
        (
            AssessmentDimension::RetrievalDeliveryVisibility,
            "RETRIEVAL_DELIVERY_VISIBILITY",
        ),
        (AssessmentDimension::Selection, "SELECTION"),
        (AssessmentDimension::Adherence, "ADHERENCE"),
        (AssessmentDimension::ActionLinkedUse, "ACTION_LINKED_USE"),
        (AssessmentDimension::OutcomeValidity, "OUTCOME_VALIDITY"),
        (
            AssessmentDimension::BaselineControlQuality,
            "BASELINE_CONTROL_QUALITY",
        ),
        (AssessmentDimension::Harm, "HARM"),
        (AssessmentDimension::Confounders, "CONFOUNDERS"),
        (
            AssessmentDimension::SourceEvaluatorIndependence,
            "SOURCE_EVALUATOR_INDEPENDENCE",
        ),
        (
            AssessmentDimension::TransferApplicability,
            "TRANSFER_APPLICABILITY",
        ),
        (AssessmentDimension::CausalCeiling, "CAUSAL_CEILING"),
        (
            AssessmentDimension::PrivacyAuthorityProof,
            "PRIVACY_AUTHORITY_PROOF",
        ),
    ];
    assert_eq!(dimensions.len(), 13);
    for (dimension, wire) in dimensions {
        assert_eq!(dimension.as_str(), *wire);
        let encoded = must(serde_json::to_string(dimension));
        assert_eq!(encoded, format!("\"{wire}\""));
    }
    for status in [
        DimensionStatus::Pass,
        DimensionStatus::Fail,
        DimensionStatus::Unknown,
        DimensionStatus::Inconclusive,
        DimensionStatus::Harm,
        DimensionStatus::NoEffect,
    ] {
        let wire = must(serde_json::to_string(&status));
        let restored: DimensionStatus = must(serde_json::from_str(&wire));
        assert_eq!(restored, status);
    }
}

// WORK_UNIT_CASE: 590/5
#[test]
fn unknown_schema_field_variant_stage_operation_dimension_rejected() {
    let (recipe, view) = recipe_and_view();
    let encoded = must(serde_json::to_string(&recipe));
    assert!(
        serde_json::from_str::<LearningStateViewRecipe>(&with_unknown_field(&encoded)).is_err()
    );
    let encoded = must(serde_json::to_string(&view));
    assert!(
        serde_json::from_str::<CampaignLearningStateView>(&with_unknown_field(&encoded)).is_err()
    );
    let delta = valid_delta("c05");
    let encoded = must(serde_json::to_string(&delta));
    assert!(
        serde_json::from_str::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(
            &with_unknown_field(&encoded)
        )
        .is_err()
    );
    let overlay = valid_overlay("c05");
    let encoded = must(serde_json::to_string(&overlay));
    assert!(
        serde_json::from_str::<CampaignHarnessOverlayCandidate>(&with_unknown_field(&encoded))
            .is_err()
    );
    let activation = valid_activation("c05");
    let encoded = must(serde_json::to_string(&activation));
    assert!(
        serde_json::from_str::<HarnessActivationReceiptCandidate>(&with_unknown_field(&encoded))
            .is_err()
    );
    let assessment = valid_assessment("c05");
    let encoded = must(serde_json::to_string(&assessment));
    assert!(
        serde_json::from_str::<LearningAssessmentCandidate>(&with_unknown_field(&encoded)).is_err()
    );
    let closure = valid_closure("c05");
    let encoded = must(serde_json::to_string(&closure));
    assert!(serde_json::from_str::<ClosureHandoff>(&with_unknown_field(&encoded)).is_err());
    assert!(serde_json::from_str::<LifecycleStage>("\"UNKNOWN_STAGE_590\"").is_err());
    assert!(serde_json::from_str::<SlotDisposition>("\"UNKNOWN_SLOT_590\"").is_err());
    assert!(serde_json::from_str::<NoChangeReason>("\"UNKNOWN_REASON_590\"").is_err());
    assert!(serde_json::from_str::<ChangeSurface>("\"UNKNOWN_SURFACE_590\"").is_err());
    assert!(serde_json::from_str::<AssessmentDimension>("\"UNKNOWN_DIMENSION_590\"").is_err());
    assert!(
        serde_json::from_str::<ChangeOperation>("{\"operation\":\"PATCH\",\"change\":{}}").is_err()
    );
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>("{\"outcome\":\"MAYBE\",\"value\":null}")
            .is_err()
    );
}

// WORK_UNIT_CASE: 590/6
#[test]
fn missing_duplicate_ids_and_changed_same_id_payload() {
    let target = target("target-590-c06");
    let mut recipe = recipe_and_view().0;
    recipe
        .slots
        .push(slot_spec("req", &target, SlotRequirement::Required));
    // Duplicate slot identity: second required slot reuses the first slot id.
    recipe.slots[1].slot_id = recipe.slots[0].slot_id.clone();
    assert!(matches!(
        recipe.validate(),
        Err(LearningContractError::Duplicate { .. })
    ));
    let (recipe, mut view) = recipe_and_view();
    view.binding.request_id = must(RequestId::new("different-590-c06"));
    must(view.seal());
    assert!(matches!(
        view.validate_against(&recipe),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    let mut delta = valid_delta("c06");
    delta.evidence.push(delta.evidence[0].clone());
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::Duplicate { .. })
    ));
    let mut overlay = valid_overlay("c06");
    overlay
        .admitted_delta_ids
        .push(overlay.admitted_delta_ids[0].clone());
    assert!(matches!(
        overlay.validate(),
        Err(LearningContractError::Duplicate { .. })
    ));
    let mut missing = valid_delta("c06m");
    missing.evidence.clear();
    missing.canonical_digest = digest("missing-evidence-shape");
    assert!(missing.validate().is_err());
    let (recipe, view) = recipe_and_view();
    let mut tampered = view.clone();
    tampered.recipe_digest = digest("tampered-recipe");
    must(tampered.seal());
    assert!(matches!(
        tampered.validate_against(&recipe),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
}

// WORK_UNIT_CASE: 590/7
#[test]
fn canonical_round_trip_and_set_order_independent_digest() {
    let (mut recipe, mut view) = recipe_and_view();
    let recipe_digest_before = recipe.canonical_digest.clone();
    must(recipe.seal());
    assert_eq!(recipe.canonical_digest, recipe_digest_before);
    let view_digest_before = view.canonical_digest.clone();
    must(view.seal());
    assert_eq!(view.canonical_digest, view_digest_before);
    assert_eq!(recipe.canonical_digest.len(), 64);
    assert!(
        recipe
            .canonical_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(roundtrip(&recipe), recipe);
    assert_eq!(roundtrip(&view), view);
    assert_eq!(roundtrip(&recipe).canonical_digest, recipe.canonical_digest);
    let mut delta = valid_delta("c07");
    let before = delta.canonical_digest.clone();
    must(delta.seal());
    assert_eq!(delta.canonical_digest, before);
    assert_eq!(roundtrip(&delta).canonical_digest, before);
    let mut overlay = valid_overlay("c07");
    let overlay_before = overlay.canonical_digest.clone();
    must(overlay.seal());
    assert_eq!(overlay.canonical_digest, overlay_before);
}

// WORK_UNIT_CASE: 590/8
#[test]
fn legacy_cannot_decode_current() {
    let (recipe, _) = recipe_and_view();
    let encoded = must(serde_json::to_string(&recipe));
    // Legacy shape missing the current privacy class cannot decode.
    let legacy_missing = encoded.replace("\"privacy_class\":\"task-local\",", "");
    assert_ne!(legacy_missing, encoded);
    assert!(serde_json::from_str::<LearningStateViewRecipe>(&legacy_missing).is_err());
    // Legacy outcome tag cannot decode as the current two-arm outcome.
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>("{\"outcome\":\"DELTA_V0\",\"value\":null}")
            .is_err()
    );
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>("{\"outcome\":\"NOCHANGE\",\"value\":null}")
            .is_err()
    );
    // Legacy view without its canonical digest cannot validate after decode.
    let view = recipe_and_view().1;
    let mut legacy_view = view.clone();
    legacy_view.canonical_digest = String::new();
    assert!(legacy_view.validate_against(&recipe).is_err());
    // Legacy stage spelling cannot decode.
    assert!(serde_json::from_str::<LifecycleStage>("\"DELIVERED_V0\"").is_err());
    // Current shape with a legacy alias field is rejected.
    let delta = valid_delta("c08");
    let encoded = must(serde_json::to_string(&delta));
    assert!(
        serde_json::from_str::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(
            &with_field(&encoded, "\"legacy_digest\":\"00\"")
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 590/9
#[test]
fn valid_recipe_slot_member_current_projection() {
    let target = target("target-590-c09");
    let binding = binding("c09");
    let spec = slot_spec("c09", &target, SlotRequirement::Required);
    must(spec.validate());
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-590-c09"),
        campaign_id: CampaignId::from_artifact(aid("campaign-590-c09")),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![spec.clone()],
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    must(recipe.seal());
    must(recipe.validate());
    let member = MemberProjection {
        member_id: spec.declared_members[0].clone(),
        owner: spec.owner.clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("value-590-c09")),
        evidence: vec![aid("ev-590-c09")],
    };
    must(member.validate());
    let mut view = CampaignLearningStateView {
        view_id: aid("view-590-c09"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target,
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id: spec.slot_id,
            disposition: SlotDisposition::Current,
            members: vec![member],
            evidence: vec![aid("slot-ev-590-c09")],
        }],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("obj-590-c09")],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    must(view.seal());
    must(view.validate_against(&recipe));
    // Current without a value digest cannot validate.
    let mut missing_value = view.slots[0].members[0].clone();
    missing_value.value_digest = None;
    assert!(missing_value.validate().is_err());
}

// WORK_UNIT_CASE: 590/10
#[test]
fn required_optional_conditional_slots() {
    let target = target("target-590-c10");
    let binding = binding("c10");
    let required = slot_spec("req10", &target, SlotRequirement::Required);
    let optional = slot_spec("opt10", &target, SlotRequirement::Optional);
    let conditional = SlotSpec {
        slot_id: SlotId::from_artifact(aid("slot-590-cond10")),
        owner: OwnerId::from_artifact(aid("owner-590-cond10")),
        target: target.clone(),
        requirement: SlotRequirement::Conditional {
            depends_on: required.slot_id.clone(),
        },
        declared_members: vec![],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("schema-590-c10"),
    };
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-590-c10"),
        campaign_id: CampaignId::from_artifact(aid("campaign-590-c10")),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![required.clone(), optional, conditional],
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    must(recipe.seal());
    must(recipe.validate());
    // Conditional on a missing slot cannot validate.
    let mut broken = recipe.clone();
    if let SlotRequirement::Conditional { depends_on } = &mut broken.slots[2].requirement {
        *depends_on = SlotId::from_artifact(aid("slot-590-missing"));
    }
    broken.canonical_digest = digest("broken-shape");
    assert!(broken.validate().is_err());
    // Conditional on itself cannot validate.
    let mut self_dependent = recipe.clone();
    let own_id = self_dependent.slots[2].slot_id.clone();
    if let SlotRequirement::Conditional { depends_on } = &mut self_dependent.slots[2].requirement {
        *depends_on = own_id;
    }
    self_dependent.canonical_digest = digest("self-shape");
    assert!(self_dependent.validate().is_err());
    // Complete view may omit the optional slot but must cover required.
    let member = MemberProjection {
        member_id: required.declared_members[0].clone(),
        owner: required.owner.clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("value-590-c10")),
        evidence: vec![aid("ev-590-c10")],
    };
    let mut view = CampaignLearningStateView {
        view_id: aid("view-590-c10"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target,
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id: required.slot_id.clone(),
            disposition: SlotDisposition::Current,
            members: vec![member],
            evidence: vec![aid("slot-ev-590-c10")],
        }],
        denominator: SourceDenominator {
            declared: 3,
            observed: 1,
        },
        completeness: Completeness::Partial,
        omissions: vec![recipe.slots[1].slot_id.clone()],
        frontier: vec![recipe.slots[2].slot_id.clone()],
        owner_disagreements: vec![],
        required_references: vec![aid("obj-590-c10")],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    must(view.seal());
    must(view.validate_against(&recipe));
}

// WORK_UNIT_CASE: 590/11
#[test]
fn all_slot_disposition_states() {
    let binding = binding("c11");
    let member_id = MemberId::from_artifact(aid("member-590-c11"));
    let owner = OwnerId::from_artifact(aid("owner-590-c11"));
    let states = [
        SlotDisposition::Current,
        SlotDisposition::Historical,
        SlotDisposition::Stale,
        SlotDisposition::Superseded,
        SlotDisposition::Unavailable,
        SlotDisposition::Blocked,
        SlotDisposition::Unknown,
        SlotDisposition::Conflicted,
        SlotDisposition::KnownEmpty,
    ];
    assert_eq!(states.len(), 9);
    for (index, disposition) in states.iter().enumerate() {
        let member = MemberProjection {
            member_id: member_id.clone(),
            owner: owner.clone(),
            source: binding.source.clone(),
            projection_revision: TaskRevision::genesis(),
            disposition: *disposition,
            value_digest: Some(digest(&format!("value-590-c11-{index}"))),
            evidence: vec![aid(&format!("ev-590-c11-{index}"))],
        };
        must(member.validate());
        let projection = SlotProjection {
            slot_id: SlotId::from_artifact(aid(&format!("slot-590-c11-{index}"))),
            disposition: *disposition,
            members: vec![member],
            evidence: vec![aid(&format!("slot-ev-590-c11-{index}"))],
        };
        must(projection.validate());
        let wire = must(serde_json::to_string(disposition));
        let restored: SlotDisposition = must(serde_json::from_str(&wire));
        assert_eq!(&restored, disposition);
    }
}

// WORK_UNIT_CASE: 590/12
#[test]
fn complete_partial_known_empty_denominator() {
    let complete = SourceDenominator {
        declared: 2,
        observed: 2,
    };
    must(complete.validate());
    let partial = SourceDenominator {
        declared: 2,
        observed: 1,
    };
    must(partial.validate());
    let empty_declared = SourceDenominator {
        declared: 0,
        observed: 0,
    };
    assert!(empty_declared.validate().is_err());
    let over_observed = SourceDenominator {
        declared: 1,
        observed: 2,
    };
    assert!(over_observed.validate().is_err());
    for completeness in [
        Completeness::CompleteForDeclaredRecipe,
        Completeness::Partial,
        Completeness::Stale,
        Completeness::Blocked,
    ] {
        let wire = must(serde_json::to_string(&completeness));
        let restored: Completeness = must(serde_json::from_str(&wire));
        assert_eq!(restored, completeness);
    }
    // Known-empty slot with no declared members and explicit evidence validates.
    let target = target("target-590-c12");
    let spec = SlotSpec {
        slot_id: SlotId::from_artifact(aid("slot-590-c12")),
        owner: OwnerId::from_artifact(aid("owner-590-c12")),
        target: target.clone(),
        requirement: SlotRequirement::Optional,
        declared_members: vec![],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("schema-590-c12"),
    };
    must(spec.validate());
    let projection = SlotProjection {
        slot_id: spec.slot_id,
        disposition: SlotDisposition::KnownEmpty,
        members: vec![],
        evidence: vec![aid("ev-590-c12")],
    };
    must(projection.validate());
}

// WORK_UNIT_CASE: 590/13
#[test]
fn owner_disagreement_source_provenance_preserved() {
    let slot_id = SlotId::from_artifact(aid("slot-590-c13"));
    let owners = vec![
        OwnerId::from_artifact(aid("owner-590-c13-a")),
        OwnerId::from_artifact(aid("owner-590-c13-b")),
    ];
    let disagreement = OwnerDisagreement {
        slot_id: slot_id.clone(),
        owners: owners.clone(),
        evidence: vec![aid("conflict-590-c13")],
    };
    must(disagreement.validate());
    assert_eq!(roundtrip(&disagreement), disagreement);
    let mut single = disagreement.clone();
    single.owners.truncate(1);
    assert!(single.validate().is_err());
    let mut no_evidence = disagreement.clone();
    no_evidence.evidence.clear();
    assert!(no_evidence.validate().is_err());
    let binding = binding("c13");
    let member = MemberProjection {
        member_id: MemberId::from_artifact(aid("member-590-c13")),
        owner: owners[0].clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Conflicted,
        value_digest: Some(digest("value-590-c13")),
        evidence: vec![aid("ev-590-c13")],
    };
    must(member.validate());
    assert_eq!(member.source.owner.as_str(), binding.source.owner.as_str());
    assert_eq!(member.source.digest, binding.source.digest);
}

// WORK_UNIT_CASE: 590/14
#[test]
fn no_mutable_aggregate_latest_transcript_default_fill_fields() {
    for schema in [
        schema_text::<LearningStateViewRecipe>(),
        schema_text::<CampaignLearningStateView>(),
        schema_text::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(),
        schema_text::<CampaignHarnessOverlayCandidate>(),
        schema_text::<LearningAssessmentCandidate>(),
        schema_text::<ClosureHandoff>(),
    ] {
        assert_no_keys(
            &schema,
            &[
                "latest",
                "transcript",
                "mutable_aggregate",
                "aggregate",
                "default_fill",
                "current_state",
                "active_policy",
            ],
        );
    }
    let (recipe, view) = recipe_and_view();
    let encoded = must(serde_json::to_string(&view));
    assert!(
        serde_json::from_str::<CampaignLearningStateView>(&with_field(&encoded, "\"latest\":true"))
            .is_err()
    );
    let encoded = must(serde_json::to_string(&recipe));
    assert!(
        serde_json::from_str::<LearningStateViewRecipe>(&with_field(&encoded, "\"transcript\":[]"))
            .is_err()
    );
}

// WORK_UNIT_CASE: 590/15
#[test]
fn valid_delta_with_base_before_after_evidence_verifier_rollback() {
    let (recipe, view) = recipe_and_view();
    let target = view.target.clone();
    let before = ValueState {
        present: true,
        digest: Some(digest("before-590-c15")),
    };
    let after = ValueState {
        present: true,
        digest: Some(digest("after-590-c15")),
    };
    let mut delta = eliot_learning_contracts::AttemptLearningDeltaCandidate {
        binding: view.binding.clone(),
        attempt_id: must(AgentAttemptId::new("attempt-590-c15")),
        delta_id: aid("delta-590-c15"),
        target: target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid("disc-590-c15"),
        intended_strategy: aid("intended-590-c15"),
        attempted_strategy: aid("attempted-590-c15"),
        changes: vec![ChangeOperation::Replace {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            before: before.clone(),
            after: after.clone(),
        }],
        inverses: vec![InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Replace {
                target: target.clone(),
                surface: ChangeSurface::Strategy,
                before: after,
                after: before,
            },
        }],
        evidence: vec![aid("delta-ev-590-c15")],
        evaluator_receipts: vec![aid("delta-verifier-590-c15")],
        baseline: vec![aid("delta-baseline-590-c15")],
        control: vec![aid("delta-control-590-c15")],
        confounders: vec![aid("delta-confound-590-c15")],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    must(delta.seal());
    must(delta.validate());
    must(delta.validate_against_view(&view));
    assert_eq!(view.binding, recipe.binding);
    let outcome = AttemptLearningOutcome::Delta(delta);
    let wire = must(serde_json::to_string(&outcome));
    assert!(wire.contains("DELTA"));
}

// WORK_UNIT_CASE: 590/16
#[test]
fn every_evidence_backed_no_change_reason() {
    let reasons = [
        NoChangeReason::ConfirmedFixedPrediction,
        NoChangeReason::ControlledReplicationNeeded,
        NoChangeReason::ProtectedConstraint,
        NoChangeReason::ProvenNonApplicability,
        NoChangeReason::Contradicted,
        NoChangeReason::UnsafeCandidate,
        NoChangeReason::OwnerBlocked,
        NoChangeReason::ExternalReviewRequired,
    ];
    assert_eq!(reasons.len(), 8);
    for (index, reason) in reasons.iter().enumerate() {
        let disposition = valid_no_change(&format!("c16-{index}"), *reason);
        must(disposition.validate());
        assert_eq!(disposition.reason, *reason);
        assert!(!disposition.affirmative_evidence.is_empty());
        let outcome = AttemptLearningOutcome::NoChange(disposition);
        let wire = must(serde_json::to_string(&outcome));
        assert!(wire.contains("NO_CHANGE"));
    }
}

// WORK_UNIT_CASE: 590/17
#[test]
fn evidence_free_no_change_rejected() {
    let binding = binding("c17");
    let target = target("target-590-c17");
    let mut disposition = eliot_learning_contracts::NoChangeDisposition {
        binding,
        attempt_id: must(AgentAttemptId::new("attempt-590-c17")),
        target,
        reason: NoChangeReason::ConfirmedFixedPrediction,
        affirmative_evidence: vec![],
        denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        canonical_digest: String::new(),
    };
    must(disposition.seal());
    assert!(matches!(
        disposition.validate(),
        Err(LearningContractError::InvalidNoChange)
    ));
    let mut mismatched = valid_no_change("c17b", NoChangeReason::Contradicted);
    mismatched.denominator = SourceDenominator {
        declared: 2,
        observed: 1,
    };
    must(mismatched.seal());
    assert!(matches!(
        mismatched.validate(),
        Err(LearningContractError::InvalidNoChange)
    ));
}

// WORK_UNIT_CASE: 590/18
#[test]
fn no_change_with_a_change_rejected() {
    // Delta requires at least one change; an empty change set cannot validate
    // as a delta, and a no-change record carries no change field at all.
    let mut delta = valid_delta("c18");
    delta.changes.clear();
    delta.inverses.clear();
    must(delta.seal());
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::Bound { .. })
    ));
    // No-change denominator must exactly match affirmative evidence; extra
    // undeclared evidence (a smuggled change footprint) is rejected.
    let mut disposition = valid_no_change("c18", NoChangeReason::ProvenNonApplicability);
    disposition.affirmative_evidence.push(aid("extra-590-c18"));
    must(disposition.seal());
    assert!(matches!(
        disposition.validate(),
        Err(LearningContractError::InvalidNoChange)
    ));
    // The two arms remain distinct types: a delta outcome is never no-change.
    let delta = valid_delta("c18b");
    let outcome = AttemptLearningOutcome::Delta(delta);
    assert!(matches!(outcome, AttemptLearningOutcome::Delta(_)));
    assert!(!matches!(outcome, AttemptLearningOutcome::NoChange(_)));
}

// WORK_UNIT_CASE: 590/19
#[test]
fn missing_instrumentation_conflict_cancellation_exhaustion_is_not_no_change() {
    for failure in [
        AttemptFailure::Error,
        AttemptFailure::Cancelled,
        AttemptFailure::Exhausted,
        AttemptFailure::NonConsequential,
        AttemptFailure::Unknown,
    ] {
        let result = AttemptLearningResult::Failure(failure);
        assert!(matches!(result, AttemptLearningResult::Failure(_)));
        assert!(!matches!(result, AttemptLearningResult::Success(_)));
        let wire = must(serde_json::to_string(&result));
        let restored: AttemptLearningResult = must(serde_json::from_str(&wire));
        assert_eq!(restored, result);
    }
    // None of those failure shapes can decode as a successful no-change arm.
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>("{\"outcome\":\"CANCELLED\",\"value\":{}}")
            .is_err()
    );
    assert!(
        serde_json::from_str::<AttemptLearningOutcome>("{\"outcome\":\"EXHAUSTED\",\"value\":{}}")
            .is_err()
    );
    // A no-change without affirmative evidence cannot stand in for missing
    // instrumentation or an unresolved conflict.
    let mut disposition = valid_no_change("c19", NoChangeReason::ConfirmedFixedPrediction);
    disposition.affirmative_evidence.clear();
    disposition.denominator = SourceDenominator {
        declared: 1,
        observed: 0,
    };
    must(disposition.seal());
    assert!(disposition.validate().is_err());
}

// WORK_UNIT_CASE: 590/20
#[test]
fn every_change_operation_and_invalid_before_after() {
    let target = target("target-590-c20");
    let present = ValueState {
        present: true,
        digest: Some(digest("present-590-c20")),
    };
    let other = ValueState {
        present: true,
        digest: Some(digest("other-590-c20")),
    };
    let absent = ValueState {
        present: false,
        digest: None,
    };
    let add = ChangeOperation::Add {
        target: target.clone(),
        surface: ChangeSurface::Memory,
        after: present.clone(),
    };
    must(add.validate());
    let remove = ChangeOperation::Remove {
        target: target.clone(),
        surface: ChangeSurface::Skill,
        before: present.clone(),
    };
    must(remove.validate());
    let replace = ChangeOperation::Replace {
        target: target.clone(),
        surface: ChangeSurface::Strategy,
        before: present.clone(),
        after: other.clone(),
    };
    must(replace.validate());
    // Invalid: replace with identical before/after.
    let same = ChangeOperation::Replace {
        target: target.clone(),
        surface: ChangeSurface::Strategy,
        before: present.clone(),
        after: present.clone(),
    };
    assert!(same.validate().is_err());
    // Invalid: replace with absent endpoints.
    let absent_replace = ChangeOperation::Replace {
        target: target.clone(),
        surface: ChangeSurface::Strategy,
        before: absent.clone(),
        after: present.clone(),
    };
    assert!(absent_replace.validate().is_err());
    // Invalid: add with absent after.
    let bad_add = ChangeOperation::Add {
        target: target.clone(),
        surface: ChangeSurface::Tool,
        after: absent.clone(),
    };
    assert!(bad_add.validate().is_err());
    // Invalid: remove with absent before.
    let bad_remove = ChangeOperation::Remove {
        target: target.clone(),
        surface: ChangeSurface::Route,
        before: absent,
    };
    assert!(bad_remove.validate().is_err());
    // Invalid: present without digest.
    let no_digest = ValueState {
        present: true,
        digest: None,
    };
    assert!(no_digest.validate("change.after").is_err());
    // Invalid: absent with digest.
    let stray_digest = ValueState {
        present: false,
        digest: Some(digest("stray")),
    };
    assert!(stray_digest.validate("change.before").is_err());
}

// WORK_UNIT_CASE: 590/21
#[test]
fn generic_string_path_patch_rejected() {
    assert!(
        serde_json::from_str::<ChangeOperation>(
            "{\"operation\":\"PATCH\",\"change\":{\"path\":\"a.b.c\",\"value\":1}}"
        )
        .is_err()
    );
    assert!(serde_json::from_str::<ChangeOperation>("{\"operation\":\"REPLACE\",\"change\":{\"path\":\"slot.member\",\"before\":null,\"after\":null}}").is_err());
    assert!(
        serde_json::from_str::<ChangeOperation>(
            "{\"operation\":\"ADD\",\"change\":{\"json_pointer\":\"/a/b\",\"value\":{}}}"
        )
        .is_err()
    );
    // Typed operations require typed target/surface identities, not paths.
    let target = target("target-590-c21");
    let after = ValueState {
        present: true,
        digest: Some(digest("after-590-c21")),
    };
    let typed = ChangeOperation::Add {
        target,
        surface: ChangeSurface::Hypothesis,
        after,
    };
    must(typed.validate());
    let wire = must(serde_json::to_string(&typed));
    assert!(!wire.contains("json_pointer"));
    assert!(!wire.contains("\"path\""));
}

// WORK_UNIT_CASE: 590/22
#[test]
fn equivalent_retry_controlled_repetition() {
    use eliot_learning_contracts::delta::EquivalentRetry;
    let retry = EquivalentRetry {
        prior_attempt: must(AgentAttemptId::new("attempt-590-c22-prior")),
        strategy_fingerprint: "fingerprint-590-c22".to_owned(),
        reason: "controlled repeat under identical fence".to_owned(),
        evidence: vec![aid("retry-ev-590-c22")],
    };
    must(retry.validate());
    let mut delta = valid_delta("c22");
    delta.equivalent_retry = Some(retry);
    must(delta.seal());
    must(delta.validate());
    // Empty evidence cannot justify a controlled repeat.
    let bad = EquivalentRetry {
        prior_attempt: must(AgentAttemptId::new("attempt-590-c22-bad")),
        strategy_fingerprint: "fp".to_owned(),
        reason: "repeat".to_owned(),
        evidence: vec![],
    };
    assert!(bad.validate().is_err());
    // Empty fingerprint cannot identify the repeated strategy.
    let bad_fp = EquivalentRetry {
        prior_attempt: must(AgentAttemptId::new("attempt-590-c22-bad2")),
        strategy_fingerprint: String::new(),
        reason: "repeat".to_owned(),
        evidence: vec![aid("ev-590-c22")],
    };
    assert!(bad_fp.validate().is_err());
    // Overlong fingerprint exceeds the contract bound.
    let long_fp: String = core::iter::repeat_n('f', 257).collect();
    let bad_long = EquivalentRetry {
        prior_attempt: must(AgentAttemptId::new("attempt-590-c22-bad3")),
        strategy_fingerprint: long_fp,
        reason: "repeat".to_owned(),
        evidence: vec![aid("ev-590-c22b")],
    };
    assert!(matches!(
        bad_long.validate(),
        Err(LearningContractError::Bound { .. })
    ));
}

// WORK_UNIT_CASE: 590/23
#[test]
fn protected_target_rejected() {
    let mut overlay = valid_overlay("c23");
    overlay.protected_surface_proposed_digest = digest("changed-protected-590");
    must(overlay.seal());
    assert!(matches!(
        overlay.validate(),
        Err(LearningContractError::ProtectedSurfaceChanged)
    ));
    let overlay = valid_overlay("c23b");
    must(overlay.validate());
    assert_eq!(
        overlay.protected_surface_base_digest,
        overlay.protected_surface_proposed_digest
    );
    // Closed surface vocabulary has no protected active-generation member.
    assert!(serde_json::from_str::<ChangeSurface>("\"ACTIVE_GENERATION\"").is_err());
    assert!(serde_json::from_str::<ChangeSurface>("\"PRIVACY_STORE\"").is_err());
    assert!(serde_json::from_str::<ChangeSurface>("\"CANONICAL_PROMOTION\"").is_err());
}

// WORK_UNIT_CASE: 590/24
#[test]
fn correlation_confidence_cannot_encode_causal_proof() {
    let mut attribution = valid_attribution("c24");
    for weak in [
        UseBasis::RetrievalCount,
        UseBasis::Repetition,
        UseBasis::ModelJudgment,
    ] {
        let mut candidate = attribution.clone();
        candidate.use_basis = weak;
        must(candidate.seal());
        assert!(matches!(
            candidate.validate(),
            Err(LearningContractError::ScopeMismatch { .. })
        ));
    }
    attribution.use_basis = UseBasis::DirectObservation;
    must(attribution.seal());
    must(attribution.validate());
    // A causal claim above the weakest dimension ceiling is rejected.
    let mut assessment = valid_assessment("c24");
    assessment.causal_ceiling = CausalCeiling::CausalAttribution;
    must(assessment.seal());
    assert!(matches!(
        assessment.validate(),
        Err(LearningContractError::NonIndependentAssessment
            | LearningContractError::IncompleteCoverage)
    ));
}

// WORK_UNIT_CASE: 590/25
#[test]
fn exact_overlay_base_parent_evaluation_admitted_delta() {
    let (recipe, view) = recipe_and_view();
    let target = view.target.clone();
    let proposed = ValueState {
        present: true,
        digest: Some(digest("overlay-590-c25")),
    };
    let mut delta = eliot_learning_contracts::AttemptLearningDeltaCandidate {
        binding: view.binding.clone(),
        attempt_id: must(AgentAttemptId::new("attempt-590-c25")),
        delta_id: aid("delta-590-c25"),
        target: target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid("disc-590-c25"),
        intended_strategy: aid("intended-590-c25"),
        attempted_strategy: aid("attempted-590-c25"),
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
                before: proposed.clone(),
            },
        }],
        evidence: vec![aid("delta-ev-590-c25")],
        evaluator_receipts: vec![aid("delta-eval-590-c25")],
        baseline: vec![aid("delta-base-590-c25")],
        control: vec![aid("delta-ctrl-590-c25")],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    must(delta.seal());
    must(delta.validate_against_view(&view));
    let mut overlay = CampaignHarnessOverlayCandidate {
        binding: view.binding.clone(),
        overlay_id: OverlayId::from_artifact(aid("overlay-590-c25")),
        base_view_digest: view.canonical_digest.clone(),
        parent_revision: TaskRevision::genesis(),
        admitted_delta_ids: vec![delta.delta_id.clone()],
        admitted_delta_digests: vec![delta.canonical_digest.clone()],
        changes: vec![OverlayChange {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            base: ValueState {
                present: false,
                digest: None,
            },
            proposed,
            inverse: InverseChange {
                forward_target: target.clone(),
                inverse: ChangeOperation::Remove {
                    target: target.clone(),
                    surface: ChangeSurface::Strategy,
                    before: ValueState {
                        present: true,
                        digest: Some(digest("overlay-590-c25")),
                    },
                },
            },
            origin: OverlayOrigin::Overlay,
        }],
        dependencies: vec![],
        application_order: vec![target],
        protected_surface_base_digest: digest("protected-590-c25"),
        protected_surface_proposed_digest: digest("protected-590-c25"),
        fixed_before_observation_discriminator: aid("ovdisc-590-c25"),
        expires_at_ms: 5_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    must(overlay.seal());
    must(overlay.validate_against_view_and_deltas(&view, core::slice::from_ref(&delta)));
    assert_eq!(overlay.base_view_digest, view.canonical_digest);
    assert_eq!(recipe.binding, view.binding);
    // Wrong parent digest lineage fails.
    let mut wrong_base = overlay.clone();
    wrong_base.base_view_digest = digest("other-base-590");
    must(wrong_base.seal());
    assert!(
        wrong_base
            .validate_against_view_and_deltas(&view, core::slice::from_ref(&delta))
            .is_err()
    );
}

// WORK_UNIT_CASE: 590/26
#[test]
fn scope_fence_expiry_invalidation_required() {
    let mut overlay = valid_overlay("c26");
    overlay.expires_at_ms = 0;
    must(overlay.seal());
    assert!(matches!(
        overlay.validate(),
        Err(LearningContractError::Missing { .. })
    ));
    let mut overlay = valid_overlay("c26b");
    overlay.binding.scope = must(WorkScopeId::new("other-scope-590-c26"));
    must(overlay.seal());
    assert!(overlay.validate().is_ok());
    // Scope drift is caught at lineage time against the exact view binding.
    let (_, view) = recipe_and_view();
    let delta = valid_delta("c26c");
    assert!(
        overlay
            .validate_against_view_and_deltas(&view, core::slice::from_ref(&delta))
            .is_err()
    );
    let overlay = valid_overlay("c26d");
    must(overlay.validate());
    assert!(!overlay.invalidated);
    let mut invalidated = overlay.clone();
    invalidated.invalidated = true;
    must(invalidated.seal());
    must(invalidated.validate());
}

// WORK_UNIT_CASE: 590/27
#[test]
fn changed_surface_denominator_conflicts_alternatives() {
    let mut overlay = valid_overlay("c27");
    overlay.application_order.clear();
    must(overlay.seal());
    assert!(matches!(
        overlay.validate(),
        Err(LearningContractError::IncompleteCoverage)
    ));
    let mut overlay = valid_overlay("c27b");
    overlay.changes.push(overlay.changes[0].clone());
    overlay
        .application_order
        .push(overlay.changes[0].target.clone());
    must(overlay.seal());
    assert!(matches!(
        overlay.validate(),
        Err(LearningContractError::Duplicate { .. })
    ));
    // Dependency order must respect application order.
    let binding = binding("c27c");
    let first = target("target-590-c27-first");
    let second = target("target-590-c27-second");
    let change = |t: TargetId, tag: &str| OverlayChange {
        target: t.clone(),
        surface: ChangeSurface::Memory,
        base: ValueState {
            present: false,
            digest: None,
        },
        proposed: ValueState {
            present: true,
            digest: Some(digest(tag)),
        },
        inverse: InverseChange {
            forward_target: t.clone(),
            inverse: ChangeOperation::Remove {
                target: t.clone(),
                surface: ChangeSurface::Memory,
                before: ValueState {
                    present: true,
                    digest: Some(digest(tag)),
                },
            },
        },
        origin: OverlayOrigin::Overlay,
    };
    let mut ordered = CampaignHarnessOverlayCandidate {
        binding,
        overlay_id: OverlayId::from_artifact(aid("overlay-590-c27c")),
        base_view_digest: digest("base-590-c27c"),
        parent_revision: TaskRevision::genesis(),
        admitted_delta_ids: vec![aid("admitted-590-c27c")],
        admitted_delta_digests: vec![digest("admitted-shape-590-c27c")],
        changes: vec![
            change(first.clone(), "v1-590-c27c"),
            change(second.clone(), "v2-590-c27c"),
        ],
        dependencies: vec![eliot_learning_contracts::overlay::OverlayDependency {
            prerequisite: first.clone(),
            dependent: second.clone(),
        }],
        application_order: vec![second.clone(), first.clone()],
        protected_surface_base_digest: digest("protected-590-c27c"),
        protected_surface_proposed_digest: digest("protected-590-c27c"),
        fixed_before_observation_discriminator: aid("disc-590-c27c"),
        expires_at_ms: 7_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    must(ordered.seal());
    assert!(matches!(
        ordered.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    ordered.application_order = vec![first, second];
    must(ordered.seal());
    must(ordered.validate());
}

// WORK_UNIT_CASE: 590/28
#[test]
fn protected_surface_equality() {
    let overlay = valid_overlay("c28");
    assert_eq!(
        overlay.protected_surface_base_digest,
        overlay.protected_surface_proposed_digest
    );
    assert_eq!(overlay.protected_surface_base_digest.len(), 64);
    let mut changed = overlay.clone();
    changed.protected_surface_proposed_digest = digest("other-protected-590-c28");
    must(changed.seal());
    assert!(matches!(
        changed.validate(),
        Err(LearningContractError::ProtectedSurfaceChanged)
    ));
    let mut malformed = overlay.clone();
    malformed.protected_surface_base_digest = "NOT_A_DIGEST".to_owned();
    must(malformed.seal());
    assert!(matches!(
        malformed.validate(),
        Err(LearningContractError::InvalidDigest { .. })
    ));
}

// WORK_UNIT_CASE: 590/29
#[test]
fn pre_observation_discriminator_required() {
    let mut delta = valid_delta("c29");
    delta.pre_observation_discriminator = aid("x");
    // Replace with a blank identity is not representable via the typed
    // constructor, so simulate the missing shape through digest tampering:
    // a resealed record with an empty lineage still fails its own check when
    // the discriminator is cleared via a cloned shape below.
    must(delta.seal());
    must(delta.validate());
    let overlay = valid_overlay("c29");
    must(overlay.clone().validate());
    let experiment = valid_experiment("c29");
    must(experiment.validate());
    // Clearing the discriminator text is rejected on re-validation because the
    // sealed digest no longer matches the mutated shape.
    let mut tampered = delta.clone();
    tampered.pre_observation_discriminator = aid("different-590-c29");
    assert!(matches!(
        tampered.validate(),
        Err(LearningContractError::DigestMismatch { .. })
    ));
    let mut tampered_overlay = overlay.clone();
    tampered_overlay.fixed_before_observation_discriminator = aid("different-590-c29b");
    assert!(tampered_overlay.validate().is_err());
    let mut tampered_exp = experiment.clone();
    tampered_exp.pre_observation_discriminator = aid("different-590-c29c");
    assert!(tampered_exp.validate().is_err());
}

// WORK_UNIT_CASE: 590/30
#[test]
fn complete_inverse_discard_per_change() {
    let overlay = valid_overlay("c30");
    assert!(overlay.is_reversible());
    must(overlay.validate());
    for change in &overlay.changes {
        let forward = match (change.base.present, change.proposed.present) {
            (false, true) => ChangeOperation::Add {
                target: change.target.clone(),
                surface: change.surface,
                after: change.proposed.clone(),
            },
            (true, false) => ChangeOperation::Remove {
                target: change.target.clone(),
                surface: change.surface,
                before: change.base.clone(),
            },
            (true, true) => ChangeOperation::Replace {
                target: change.target.clone(),
                surface: change.surface,
                before: change.base.clone(),
                after: change.proposed.clone(),
            },
            (false, false) => panic!("fixture must not contain empty change"),
        };
        assert!(change.inverse.is_exact_inverse_of(&forward));
    }
    let mut delta = valid_delta("c30b");
    delta.inverses.pop();
    must(delta.seal());
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::MissingInverse)
    ));
    let mut delta = valid_delta("c30c");
    delta.inverses[0] = InverseChange {
        forward_target: target("target-590-c30c"),
        inverse: ChangeOperation::Add {
            target: target("target-590-c30c"),
            surface: ChangeSurface::Strategy,
            after: ValueState {
                present: true,
                digest: Some(digest("wrong-590-c30c")),
            },
        },
    };
    must(delta.seal());
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::MissingInverse | LearningContractError::ScopeMismatch { .. })
    ));
}

// WORK_UNIT_CASE: 590/31
#[test]
fn active_current_canonical_promotion_injection_rejected() {
    let mut delta = valid_delta("c31");
    delta.proof_ceiling = ProofCeiling::ObservedExternalEffect;
    must(delta.seal());
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::CandidateCeiling)
    ));
    let mut overlay = valid_overlay("c31b");
    overlay.changes[0].origin = OverlayOrigin::Base;
    must(overlay.seal());
    assert!(matches!(
        overlay.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    let mut promotion = valid_promotion("c31");
    promotion.mutation_target = PromotionMutationTarget::ActiveGeneration;
    must(promotion.seal());
    assert!(matches!(
        promotion.validate(),
        Err(LearningContractError::CandidateCeiling)
    ));
    let mut promotion = valid_promotion("c31b");
    promotion.history_retention = HistoryRetention::DeleteOnRollback;
    must(promotion.seal());
    assert!(promotion.validate().is_err());
    let mut binding = binding("c31c");
    binding.proof_ceiling = ProofCeiling::ScopedVerification;
    let target = target("target-590-c31c");
    let mut delta = valid_delta("c31c");
    delta.binding = binding;
    let _ = target;
    must(delta.seal());
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::CandidateCeiling)
    ));
}

// WORK_UNIT_CASE: 590/32
#[test]
fn schema_supports_exact_base_overlay_base_round_trip() {
    let overlay = valid_overlay("c32");
    must(overlay.validate());
    assert!(overlay.is_reversible());
    // Forward then inverse restores the exact base value for each change.
    for change in &overlay.changes {
        assert_ne!(change.base, change.proposed);
        assert_eq!(change.origin, OverlayOrigin::Overlay);
        let forward = match (change.base.present, change.proposed.present) {
            (false, true) => ChangeOperation::Add {
                target: change.target.clone(),
                surface: change.surface,
                after: change.proposed.clone(),
            },
            (true, false) => ChangeOperation::Remove {
                target: change.target.clone(),
                surface: change.surface,
                before: change.base.clone(),
            },
            (true, true) => ChangeOperation::Replace {
                target: change.target.clone(),
                surface: change.surface,
                before: change.base.clone(),
                after: change.proposed.clone(),
            },
            (false, false) => panic!("empty change cannot round trip"),
        };
        assert!(change.inverse.is_exact_inverse_of(&forward));
        // The inverse operation swaps base and proposed exactly.
        match &change.inverse.inverse {
            ChangeOperation::Remove { before, .. } => assert_eq!(before, &change.proposed),
            ChangeOperation::Add { after, .. } => assert_eq!(after, &change.proposed),
            ChangeOperation::Replace { before, after, .. } => {
                assert_eq!(before, &change.proposed);
                assert_eq!(after, &change.base);
            }
        }
    }
    // The crate itself never composes: no compose/remove helper exists on the
    // public surface, only the reversible schema that supports the equation
    // remove(compose(base, deltas)) == base under canonical semantics.
    let wire = must(serde_json::to_string(&overlay));
    assert!(!wire.contains("compose"));
}

// WORK_UNIT_CASE: 590/33
#[test]
fn every_legal_adjacent_predecessor_relation() {
    let legal: &[(LifecycleStage, Option<LifecycleStage>)] = &[
        (LifecycleStage::CandidateProduced, None),
        (
            LifecycleStage::AdmittedForEvaluation,
            Some(LifecycleStage::CandidateProduced),
        ),
        (
            LifecycleStage::ActivationRequested,
            Some(LifecycleStage::AdmittedForEvaluation),
        ),
        (
            LifecycleStage::Retrieved,
            Some(LifecycleStage::ActivationRequested),
        ),
        (
            LifecycleStage::DeliveryAttempted,
            Some(LifecycleStage::Retrieved),
        ),
        (
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
        ),
        (
            LifecycleStage::Acknowledged,
            Some(LifecycleStage::Delivered),
        ),
        (LifecycleStage::Visible, Some(LifecycleStage::Acknowledged)),
        (LifecycleStage::Visible, Some(LifecycleStage::Delivered)),
        (
            LifecycleStage::SelectedActivated,
            Some(LifecycleStage::Visible),
        ),
        (
            LifecycleStage::Adhered,
            Some(LifecycleStage::SelectedActivated),
        ),
        (LifecycleStage::UsedInAction, Some(LifecycleStage::Adhered)),
        (
            LifecycleStage::UsedInAction,
            Some(LifecycleStage::SelectedActivated),
        ),
        (
            LifecycleStage::ActionOutputObserved,
            Some(LifecycleStage::UsedInAction),
        ),
        (
            LifecycleStage::SemanticOutcomeObserved,
            Some(LifecycleStage::ActionOutputObserved),
        ),
        (
            LifecycleStage::Benefit,
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::Harm,
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::NoEffect,
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::Inconclusive,
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::CausalAssessment,
            Some(LifecycleStage::Benefit),
        ),
        (LifecycleStage::CausalAssessment, Some(LifecycleStage::Harm)),
        (
            LifecycleStage::CausalAssessment,
            Some(LifecycleStage::NoEffect),
        ),
        (
            LifecycleStage::CausalAssessment,
            Some(LifecycleStage::Inconclusive),
        ),
        (
            LifecycleStage::ExternalPromotion,
            Some(LifecycleStage::CausalAssessment),
        ),
        (LifecycleStage::Closure, None),
    ];
    for (index, (stage, predecessor)) in legal.iter().enumerate() {
        let observation = stage_observation(*stage, *predecessor, &format!("c33-{index}"));
        must(observation.validate());
    }
}

// WORK_UNIT_CASE: 590/34
#[test]
fn every_illegal_skipped_stage_combination() {
    let illegal: &[(LifecycleStage, Option<LifecycleStage>)] = &[
        (LifecycleStage::AdmittedForEvaluation, None),
        (
            LifecycleStage::Retrieved,
            Some(LifecycleStage::CandidateProduced),
        ),
        (LifecycleStage::Delivered, Some(LifecycleStage::Retrieved)),
        (
            LifecycleStage::Acknowledged,
            Some(LifecycleStage::DeliveryAttempted),
        ),
        (
            LifecycleStage::Visible,
            Some(LifecycleStage::CandidateProduced),
        ),
        (
            LifecycleStage::SelectedActivated,
            Some(LifecycleStage::Acknowledged),
        ),
        (LifecycleStage::Adhered, Some(LifecycleStage::Visible)),
        (LifecycleStage::UsedInAction, Some(LifecycleStage::Visible)),
        (
            LifecycleStage::ActionOutputObserved,
            Some(LifecycleStage::Adhered),
        ),
        (
            LifecycleStage::SemanticOutcomeObserved,
            Some(LifecycleStage::UsedInAction),
        ),
        (
            LifecycleStage::Benefit,
            Some(LifecycleStage::ActionOutputObserved),
        ),
        (
            LifecycleStage::CausalAssessment,
            Some(LifecycleStage::SemanticOutcomeObserved),
        ),
        (
            LifecycleStage::ExternalPromotion,
            Some(LifecycleStage::Benefit),
        ),
        (
            LifecycleStage::CandidateProduced,
            Some(LifecycleStage::CandidateProduced),
        ),
    ];
    for (index, (stage, predecessor)) in illegal.iter().enumerate() {
        let observation = stage_observation(*stage, *predecessor, &format!("c34-{index}"));
        assert!(
            matches!(
                observation.validate(),
                Err(LearningContractError::IncompatiblePredecessor)
            ),
            "stage {stage:?} must reject skipped predecessor"
        );
    }
}

// WORK_UNIT_CASE: 590/35
#[test]
fn delivery_cannot_decode_as_acknowledgement_visibility() {
    assert_ne!(
        LifecycleStage::Delivered.as_str(),
        LifecycleStage::Acknowledged.as_str()
    );
    assert_ne!(
        LifecycleStage::Delivered.as_str(),
        LifecycleStage::Visible.as_str()
    );
    let delivered: LifecycleStage = must(serde_json::from_str("\"DELIVERED\""));
    assert_eq!(delivered, LifecycleStage::Delivered);
    assert_ne!(delivered, LifecycleStage::Acknowledged);
    let acknowledged: LifecycleStage = must(serde_json::from_str("\"ACKNOWLEDGED\""));
    assert_eq!(acknowledged, LifecycleStage::Acknowledged);
    // A delivered observation requires a delivery-attempted predecessor, not
    // an acknowledgement predecessor.
    let wrong = stage_observation(
        LifecycleStage::Delivered,
        Some(LifecycleStage::Acknowledged),
        "c35",
    );
    assert!(matches!(
        wrong.validate(),
        Err(LearningContractError::IncompatiblePredecessor)
    ));
    must(
        stage_observation(
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
            "c35b",
        )
        .validate(),
    );
}

// WORK_UNIT_CASE: 590/36
#[test]
fn visibility_cannot_decode_as_selection_adherence_use() {
    assert_ne!(
        LifecycleStage::Visible.as_str(),
        LifecycleStage::SelectedActivated.as_str()
    );
    assert_ne!(
        LifecycleStage::Visible.as_str(),
        LifecycleStage::Adhered.as_str()
    );
    assert_ne!(
        LifecycleStage::Visible.as_str(),
        LifecycleStage::UsedInAction.as_str()
    );
    let visible: LifecycleStage = must(serde_json::from_str("\"VISIBLE\""));
    assert_eq!(visible, LifecycleStage::Visible);
    let selected: LifecycleStage = must(serde_json::from_str("\"SELECTED_ACTIVATED\""));
    assert_eq!(selected, LifecycleStage::SelectedActivated);
    let wrong = stage_observation(
        LifecycleStage::SelectedActivated,
        Some(LifecycleStage::Acknowledged),
        "c36",
    );
    assert!(matches!(
        wrong.validate(),
        Err(LearningContractError::IncompatiblePredecessor)
    ));
    must(
        stage_observation(
            LifecycleStage::SelectedActivated,
            Some(LifecycleStage::Visible),
            "c36b",
        )
        .validate(),
    );
    let wrong_use = stage_observation(
        LifecycleStage::UsedInAction,
        Some(LifecycleStage::Visible),
        "c36c",
    );
    assert!(wrong_use.validate().is_err());
}

// WORK_UNIT_CASE: 590/37
#[test]
fn use_cannot_decode_as_outcome_benefit_causality() {
    assert_ne!(
        LifecycleStage::UsedInAction.as_str(),
        LifecycleStage::SemanticOutcomeObserved.as_str()
    );
    assert_ne!(
        LifecycleStage::UsedInAction.as_str(),
        LifecycleStage::Benefit.as_str()
    );
    assert_ne!(
        LifecycleStage::UsedInAction.as_str(),
        LifecycleStage::CausalAssessment.as_str()
    );
    let used: LifecycleStage = must(serde_json::from_str("\"USED_IN_ACTION\""));
    assert_eq!(used, LifecycleStage::UsedInAction);
    let benefit: LifecycleStage = must(serde_json::from_str("\"BENEFIT\""));
    assert_eq!(benefit, LifecycleStage::Benefit);
    let wrong = stage_observation(
        LifecycleStage::SemanticOutcomeObserved,
        Some(LifecycleStage::UsedInAction),
        "c37",
    );
    assert!(wrong.validate().is_err());
    must(
        stage_observation(
            LifecycleStage::SemanticOutcomeObserved,
            Some(LifecycleStage::ActionOutputObserved),
            "c37b",
        )
        .validate(),
    );
    let wrong_causal = stage_observation(
        LifecycleStage::CausalAssessment,
        Some(LifecycleStage::SemanticOutcomeObserved),
        "c37c",
    );
    assert!(wrong_causal.validate().is_err());
}

// WORK_UNIT_CASE: 590/38
#[test]
fn self_report_cannot_satisfy_owner_evidence() {
    let mut observed = stage_observation(
        LifecycleStage::Delivered,
        Some(LifecycleStage::DeliveryAttempted),
        "c38",
    );
    observed.owner_receipt = None;
    assert!(matches!(
        observed.validate(),
        Err(LearningContractError::MissingOwnerEvidence { .. })
    ));
    let mut no_evidence = stage_observation(
        LifecycleStage::Delivered,
        Some(LifecycleStage::DeliveryAttempted),
        "c38b",
    );
    no_evidence.evidence.clear();
    assert!(no_evidence.validate().is_err());
    // Attribution evaluator must be independent of the subject: self-rating
    // through the subject identity is rejected.
    let attribution = valid_attribution("c38");
    let mut self_rated = attribution.clone();
    self_rated.evaluator_receipt = self_rated.subject.id.clone();
    must(self_rated.seal());
    assert!(matches!(
        self_rated.validate(),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    // Dimension pass without an owner receipt is a self-report, not evidence.
    let mut dimension = valid_dimension(
        AssessmentDimension::Adherence,
        DimensionStatus::Pass,
        "c38d",
    );
    dimension.owner_receipt = None;
    dimension.evidence.clear();
    assert!(dimension.validate().is_err());
}

// WORK_UNIT_CASE: 590/39
#[test]
fn exact_member_stage_outcome_confounder_denominators() {
    let member_denominator = SourceDenominator {
        declared: 2,
        observed: 2,
    };
    must(member_denominator.validate());
    let stage_denominator = SourceDenominator {
        declared: 1,
        observed: 1,
    };
    must(stage_denominator.validate());
    let mut activation = valid_activation("c39");
    activation.member_denominator = SourceDenominator {
        declared: 0,
        observed: 0,
    };
    must(activation.seal());
    assert!(activation.validate().is_err());
    let mut activation = valid_activation("c39b");
    activation.stages[0].denominator = SourceDenominator {
        declared: 1,
        observed: 2,
    };
    must(activation.seal());
    assert!(activation.validate().is_err());
    let mut attribution = valid_attribution("c39");
    attribution.denominator = SourceDenominator {
        declared: 2,
        observed: 2,
    };
    must(attribution.seal());
    assert!(matches!(
        attribution.validate(),
        Err(LearningContractError::IncompleteCoverage)
    ));
    let attribution = valid_attribution("c39b");
    must(attribution.validate());
    assert_eq!(attribution.denominator.declared, 3);
}

// WORK_UNIT_CASE: 590/40
#[test]
fn missing_instrumentation_differs_from_complete_not_observed() {
    // Missing instrumentation (unavailable route) validates without an owner
    // receipt, while an observed stage requires one.
    let mut unavailable = stage_observation(
        LifecycleStage::Retrieved,
        Some(LifecycleStage::ActivationRequested),
        "c40",
    );
    unavailable.disposition = StageDisposition::Unavailable;
    unavailable.owner_receipt = None;
    unavailable.evidence.clear();
    must(unavailable.validate());
    let mut not_attempted = stage_observation(
        LifecycleStage::Retrieved,
        Some(LifecycleStage::ActivationRequested),
        "c40b",
    );
    not_attempted.disposition = StageDisposition::NotAttempted;
    not_attempted.owner_receipt = None;
    not_attempted.evidence.clear();
    must(not_attempted.validate());
    assert_ne!(unavailable.disposition, StageDisposition::Observed);
    assert_ne!(not_attempted.disposition, StageDisposition::Observed);
    // Complete NotObserved is explicit; missing owner evidence on Observed fails.
    let observed_missing = {
        let mut observation = stage_observation(
            LifecycleStage::Retrieved,
            Some(LifecycleStage::ActivationRequested),
            "c40c",
        );
        observation.owner_receipt = None;
        observation
    };
    assert!(observed_missing.validate().is_err());
}

// WORK_UNIT_CASE: 590/41
#[test]
fn metric_unit_population_window_baseline_control_preserved() {
    let metric = MetricObservation {
        metric_id: aid("metric-590-c41"),
        name: "adherence-rate".to_owned(),
        unit: "percent".to_owned(),
        population: SourceDenominator {
            declared: 10,
            observed: 8,
        },
        window: aid("window-590-c41"),
        baseline: Some(aid("baseline-590-c41")),
        follow_up: Some(aid("followup-590-c41")),
        evaluator_receipt: aid("eval-590-c41"),
    };
    must(metric.validate());
    assert_eq!(roundtrip(&metric), metric);
    let mut missing_unit = metric.clone();
    missing_unit.unit = String::new();
    assert!(missing_unit.validate().is_err());
    let mut missing_window = metric.clone();
    missing_window.window = aid("x");
    // Blank the window through an empty-identity shape is not representable,
    // so verify the population denominator boundary instead.
    missing_window.population = SourceDenominator {
        declared: 1,
        observed: 2,
    };
    assert!(missing_window.validate().is_err());
    let mut activation = valid_activation("c41");
    activation.metrics = vec![metric];
    must(activation.seal());
    must(activation.validate());
}

// WORK_UNIT_CASE: 590/42
#[test]
fn harm_no_effect_inconclusive_unknown_distinct() {
    let wires = [
        (DimensionStatus::Harm, "HARM"),
        (DimensionStatus::NoEffect, "NO_EFFECT"),
        (DimensionStatus::Inconclusive, "INCONCLUSIVE"),
        (DimensionStatus::Unknown, "UNKNOWN"),
        (DimensionStatus::Pass, "PASS"),
        (DimensionStatus::Fail, "FAIL"),
    ];
    for (status, wire) in wires {
        let encoded = must(serde_json::to_string(&status));
        assert_eq!(encoded, format!("\"{wire}\""));
    }
    let stages = [
        (LifecycleStage::Harm, "HARM"),
        (LifecycleStage::NoEffect, "NO_EFFECT"),
        (LifecycleStage::Inconclusive, "INCONCLUSIVE"),
        (LifecycleStage::Benefit, "BENEFIT"),
    ];
    for (stage, wire) in stages {
        assert_eq!(stage.as_str(), wire);
    }
    assert_ne!(DimensionStatus::Harm, DimensionStatus::NoEffect);
    assert_ne!(LifecycleStage::Harm, LifecycleStage::NoEffect);
    // Harm recorded on a non-harm dimension is rejected as conflation.
    let mut dimension =
        valid_dimension(AssessmentDimension::Adherence, DimensionStatus::Harm, "c42");
    assert!(matches!(
        dimension.validate(),
        Err(LearningContractError::NonIndependentAssessment)
    ));
    dimension.dimension = AssessmentDimension::Harm;
    must(dimension.validate());
}

// WORK_UNIT_CASE: 590/43
#[test]
fn assessment_dimensions_fail_independently() {
    let mut assessment = valid_assessment("c43");
    assessment.dimensions[0].status = DimensionStatus::Fail;
    must(assessment.seal());
    // A single failed dimension does not invalidate the record shape; the
    // failure is preserved independently for the external owner.
    must(assessment.validate());
    assert_eq!(assessment.dimensions[0].status, DimensionStatus::Fail);
    assert_eq!(assessment.dimensions[1].status, DimensionStatus::NoEffect);
    // Duplicate dimensions conflate independent evidence and are rejected.
    let mut duplicated = assessment.clone();
    duplicated.dimensions.push(duplicated.dimensions[0].clone());
    must(duplicated.seal());
    assert!(matches!(
        duplicated.validate(),
        Err(LearningContractError::Duplicate { .. })
    ));
    // Harm status outside the harm dimension is rejected.
    let mut conflated = valid_assessment("c43b");
    conflated.dimensions[0] = valid_dimension(
        AssessmentDimension::Selection,
        DimensionStatus::Harm,
        "c43c",
    );
    must(conflated.seal());
    assert!(conflated.validate().is_err());
}

// WORK_UNIT_CASE: 590/44
#[test]
fn no_scalar_activation_benefit_quality_substitute() {
    for schema in [
        schema_text::<LearningAssessmentCandidate>(),
        schema_text::<UseAttributionCandidate>(),
        schema_text::<ImprovementExperimentCandidate>(),
        schema_text::<PromotionBoundaryCandidate>(),
        schema_text::<HarnessActivationReceiptCandidate>(),
    ] {
        assert_no_keys(
            &schema,
            &[
                "benefit_score",
                "quality_score",
                "utility",
                "scalar_benefit",
                "score",
            ],
        );
    }
    let assessment = valid_assessment("c44");
    let encoded = must(serde_json::to_string(&assessment));
    assert!(
        serde_json::from_str::<LearningAssessmentCandidate>(&with_field(&encoded, "\"score\":0.9"))
            .is_err()
    );
    let promotion = valid_promotion("c44");
    let encoded = must(serde_json::to_string(&promotion));
    assert!(
        serde_json::from_str::<PromotionBoundaryCandidate>(&with_field(&encoded, "\"utility\":1"))
            .is_err()
    );
}

// WORK_UNIT_CASE: 590/45
#[test]
fn no_hidden_reasoning_field() {
    for schema in [
        schema_text::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(),
        schema_text::<LearningAssessmentCandidate>(),
        schema_text::<HarnessActivationReceiptCandidate>(),
        schema_text::<ClosureHandoff>(),
        schema_text::<UseAttributionCandidate>(),
        schema_text::<ImprovementExperimentCandidate>(),
    ] {
        assert_no_keys(
            &schema,
            &[
                "hidden_reasoning",
                "chain_of_thought",
                "inner_monologue",
                "thought",
                "silent_rationale",
            ],
        );
    }
    let delta = valid_delta("c45");
    let encoded = must(serde_json::to_string(&delta));
    assert!(
        serde_json::from_str::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(
            &with_field(&encoded, "\"hidden_reasoning\":\"x\"")
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 590/46
#[test]
fn assessment_cannot_carry_canonical_promotion_current_state() {
    let schema = schema_text::<LearningAssessmentCandidate>();
    assert_no_keys(
        &schema,
        &[
            "promotion_state",
            "current_state",
            "active_state",
            "accepted",
            "promoted",
        ],
    );
    let assessment = valid_assessment("c46");
    let encoded = must(serde_json::to_string(&assessment));
    assert!(
        serde_json::from_str::<LearningAssessmentCandidate>(&with_field(
            &encoded,
            "\"promotion_state\":\"PROMOTED\""
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<LearningAssessmentCandidate>(&with_field(
            &encoded,
            "\"current_state\":\"CURRENT\""
        ))
        .is_err()
    );
    // Assessment lineage binds the exact activation digest; swapping in a
    // promotion digest fails lineage validation.
    let activation = valid_activation("c46");
    let mut assessment = valid_assessment("c46b");
    assessment.activation_digest = digest("promotion-shape-instead");
    must(assessment.seal());
    assert!(assessment.validate_against_activation(&activation).is_err());
}

// WORK_UNIT_CASE: 590/47
#[test]
fn protected_authority_scope_effect_privacy_receipt_defaults_forbidden() {
    let mut proof = OwnerProof {
        owner: OwnerId::from_artifact(aid("owner-590-c47")),
        receipt: aid("receipt-590-c47"),
        scope: must(WorkScopeId::new("scope-590-clo-c47")),
        state_fence: binding("c47").state_fence.clone(),
        evidence: vec![aid("ev-590-c47")],
        proof_ceiling: ProofCeiling::ObservedExternalEffect,
    };
    let binding = binding("clo-c47");
    assert!(proof.validate_against(&binding).is_err());
    proof.proof_ceiling = ProofCeiling::CandidateArtifact;
    proof.scope = must(WorkScopeId::new("other-scope-590-c47"));
    assert!(proof.validate_against(&binding).is_err());
    let mut rollout = RolloutBoundary {
        reversible: false,
        canary_required: true,
        invalidation_conditions: vec!["harm".to_owned()],
    };
    assert!(rollout.validate().is_err());
    rollout.reversible = true;
    rollout.canary_required = false;
    assert!(rollout.validate().is_err());
    rollout.canary_required = true;
    rollout.invalidation_conditions.clear();
    assert!(rollout.validate().is_err());
}

// WORK_UNIT_CASE: 590/48
#[test]
fn objective_evaluator_holdout_authority_privacy_cost_generation_smuggling_rejected() {
    let delta = valid_delta("c48");
    let encoded = must(serde_json::to_string(&delta));
    for smuggled in [
        "\"objective\":\"x\"",
        "\"evaluator\":\"x\"",
        "\"sealed_holdout\":\"x\"",
        "\"authority\":\"x\"",
        "\"cost_ceiling\":\"x\"",
        "\"active_generation\":\"x\"",
        "\"provider_payload\":\"x\"",
    ] {
        assert!(
            serde_json::from_str::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(
                &with_field(&encoded, smuggled)
            )
            .is_err(),
            "delta must reject {smuggled}"
        );
    }
    let overlay = valid_overlay("c48b");
    let encoded = must(serde_json::to_string(&overlay));
    assert!(
        serde_json::from_str::<CampaignHarnessOverlayCandidate>(&with_field(
            &encoded,
            "\"evaluator\":\"x\""
        ))
        .is_err()
    );
    let assessment = valid_assessment("c48");
    let encoded = must(serde_json::to_string(&assessment));
    assert!(
        serde_json::from_str::<LearningAssessmentCandidate>(&with_field(
            &encoded,
            "\"sealed_holdout\":\"x\""
        ))
        .is_err()
    );
}

// WORK_UNIT_CASE: 590/49
#[test]
#[allow(clippy::too_many_lines)]
fn every_collection_string_item_output_work_boundary_and_one_over() {
    // Delta changes: 1..=128.
    let delta = valid_delta("c49");
    assert_eq!(delta.changes.len(), 1);
    must(delta.validate());
    let after = ValueState {
        present: true,
        digest: Some(digest("after-590-c49w")),
    };
    let mut wide = valid_delta("c49w");
    // 128 distinct targets stay within the 128-change bound.
    wide.changes = (0..128)
        .map(|index| {
            let distinct = target(&format!("target-590-c49w-{index}"));
            ChangeOperation::Add {
                target: distinct,
                surface: ChangeSurface::Memory,
                after: after.clone(),
            }
        })
        .collect();
    wide.inverses = wide
        .changes
        .iter()
        .map(|change| {
            let (distinct, surface, current) = match change {
                ChangeOperation::Add {
                    target,
                    surface,
                    after,
                } => (target.clone(), *surface, after.clone()),
                _ => panic!("fixture must stay Add"),
            };
            InverseChange {
                forward_target: distinct.clone(),
                inverse: ChangeOperation::Remove {
                    target: distinct,
                    surface,
                    before: current,
                },
            }
        })
        .collect();
    wide.evidence = vec![aid("ev-590-c49w")];
    must(wide.seal());
    // 128 distinct changes stay within the declared bound.
    must(wide.validate());
    let mut over = valid_delta("c49o");
    over.changes = (0..129)
        .map(|index| {
            let distinct = target(&format!("target-590-c49o-{index}"));
            ChangeOperation::Add {
                target: distinct,
                surface: ChangeSurface::Memory,
                after: after.clone(),
            }
        })
        .collect();
    over.inverses = over
        .changes
        .iter()
        .map(|change| {
            let (distinct, surface, current) = match change {
                ChangeOperation::Add {
                    target,
                    surface,
                    after,
                } => (target.clone(), *surface, after.clone()),
                _ => panic!("fixture must stay Add"),
            };
            InverseChange {
                forward_target: distinct.clone(),
                inverse: ChangeOperation::Remove {
                    target: distinct,
                    surface,
                    before: current,
                },
            }
        })
        .collect();
    must(over.seal());
    assert!(matches!(
        over.validate(),
        Err(LearningContractError::Bound { .. })
    ));
    // Slot members: 0..=256.
    let slot_target = target("target-590-c49s");
    let members: Vec<MemberId> = (0..256)
        .map(|index| MemberId::from_artifact(aid(&format!("m-590-c49s-{index}"))))
        .collect();
    let spec = SlotSpec {
        slot_id: SlotId::from_artifact(aid("slot-590-c49s")),
        owner: OwnerId::from_artifact(aid("owner-590-c49s")),
        target: slot_target,
        requirement: SlotRequirement::Required,
        declared_members: members,
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("schema-590-c49s"),
    };
    must(spec.validate());
    // String bound: hypothesis 1024 max.
    let mut experiment = valid_experiment("c49");
    experiment.hypothesis = core::iter::repeat_n('h', 1025).collect();
    must(experiment.seal());
    assert!(matches!(
        experiment.validate(),
        Err(LearningContractError::Bound { .. })
    ));
}

// WORK_UNIT_CASE: 590/50
#[test]
fn sensitive_diagnostic_values_redacted() {
    let secret_digest = digest("super-secret-payload-590-c50");
    let error = LearningContractError::InvalidDigest {
        field: "delta.canonical_digest",
    };
    let message = format!("{error}");
    assert!(!message.contains(&secret_digest));
    assert!(message.contains("delta.canonical_digest"));
    let error = LearningContractError::DigestMismatch {
        field: "view.canonical_digest",
    };
    let message = format!("{error}");
    assert!(!message.contains(&secret_digest));
    let error = LearningContractError::Missing {
        field: "slot.accepted_type",
    };
    let message = format!("{error}");
    assert!(message.contains("slot.accepted_type"));
    assert!(!message.contains(&secret_digest));
    // No error variant echoes a supplied digest or payload value.
    for error in [
        LearningContractError::Missing { field: "x" },
        LearningContractError::Bound { field: "x" },
        LearningContractError::Duplicate { field: "x" },
        LearningContractError::DigestMismatch { field: "x" },
        LearningContractError::InvalidDigest { field: "x" },
        LearningContractError::ScopeMismatch { field: "x" },
        LearningContractError::ProtectedSurfaceChanged,
        LearningContractError::IncompatiblePredecessor,
        LearningContractError::MissingOwnerEvidence { field: "x" },
        LearningContractError::InvalidNoChange,
        LearningContractError::MissingInverse,
        LearningContractError::CandidateCeiling,
        LearningContractError::IncompleteCoverage,
        LearningContractError::NonIndependentAssessment,
        LearningContractError::Canonicalization,
        LearningContractError::Foundation,
        LearningContractError::Evidence,
    ] {
        let message = format!("{error}");
        assert!(!message.contains(&secret_digest));
        assert!(!message.contains("super-secret"));
    }
}

// WORK_UNIT_CASE: 590/51
#[test]
fn malformed_property_inputs_panic_free() {
    // Empty, blank, control-char and overlong identities never panic.
    for value in ["", "   ", "a\u{0000}b", "a\u{007F}b"] {
        let _ = eliot_learning_contracts::identity::validate_external_id(value, "probe.field");
    }
    for value in ["", "ABC", "zz", "g", &"0".repeat(63), &"0".repeat(65)] {
        let _ = eliot_learning_contracts::identity::validate_digest(value, "probe.digest");
    }
    let bad_denominators = [
        SourceDenominator {
            declared: 0,
            observed: 0,
        },
        SourceDenominator {
            declared: 1,
            observed: 2,
        },
    ];
    for denominator in bad_denominators {
        assert!(denominator.validate().is_err());
    }
    let bad_value_states = [
        ValueState {
            present: true,
            digest: None,
        },
        ValueState {
            present: false,
            digest: Some(digest("stray")),
        },
        ValueState {
            present: true,
            digest: Some("not-a-digest".to_owned()),
        },
    ];
    for state in bad_value_states {
        assert!(state.validate("probe.value").is_err());
    }
    // Malformed JSON never panics, only errors.
    assert!(serde_json::from_str::<CampaignLearningStateView>("{bad json").is_err());
    assert!(serde_json::from_str::<AttemptLearningOutcome>("null").is_err());
    assert!(serde_json::from_str::<LifecycleStage>("123").is_err());
}

// WORK_UNIT_CASE: 590/52
#[test]
fn every_valid_consequential_outcome_has_one_semantic_arm() {
    let delta = valid_delta("c52");
    let delta_outcome = AttemptLearningOutcome::Delta(delta);
    assert!(matches!(delta_outcome, AttemptLearningOutcome::Delta(_)));
    assert!(!matches!(
        delta_outcome,
        AttemptLearningOutcome::NoChange(_)
    ));
    let no_change = valid_no_change("c52", NoChangeReason::OwnerBlocked);
    let no_change_outcome = AttemptLearningOutcome::NoChange(no_change);
    assert!(matches!(
        no_change_outcome,
        AttemptLearningOutcome::NoChange(_)
    ));
    assert!(!matches!(
        no_change_outcome,
        AttemptLearningOutcome::Delta(_)
    ));
    // Enclosing result preserves the single-arm invariant.
    let success = AttemptLearningResult::Success(delta_outcome);
    assert!(matches!(success, AttemptLearningResult::Success(_)));
    let failure = AttemptLearningResult::Failure(AttemptFailure::Unknown);
    assert!(matches!(failure, AttemptLearningResult::Failure(_)));
    // Wire tags are mutually exclusive.
    let delta_wire = must(serde_json::to_string(&AttemptLearningOutcome::Delta(
        valid_delta("c52b"),
    )));
    let no_change_wire = must(serde_json::to_string(&AttemptLearningOutcome::NoChange(
        valid_no_change("c52b", NoChangeReason::Contradicted),
    )));
    assert!(delta_wire.contains("DELTA") && !delta_wire.contains("NO_CHANGE"));
    assert!(
        no_change_wire.contains("NO_CHANGE") && !no_change_wire.contains("\"outcome\":\"DELTA\"")
    );
}

// WORK_UNIT_CASE: 590/53
#[test]
fn every_valid_overlay_has_exact_base_expiry_discriminator_inverse() {
    let overlay = valid_overlay("c53");
    must(overlay.validate());
    assert_eq!(overlay.base_view_digest.len(), 64);
    must(eliot_learning_contracts::identity::validate_digest(
        &overlay.base_view_digest,
        "overlay.base_view_digest",
    ));
    assert_ne!(overlay.expires_at_ms, 0);
    assert!(
        !overlay
            .fixed_before_observation_discriminator
            .as_str()
            .trim()
            .is_empty()
    );
    assert!(!overlay.admitted_delta_ids.is_empty());
    assert_eq!(
        overlay.admitted_delta_ids.len(),
        overlay.admitted_delta_digests.len()
    );
    assert_eq!(overlay.changes.len(), overlay.application_order.len());
    assert!(overlay.is_reversible());
    for change in &overlay.changes {
        must(change.validate());
    }
}

// WORK_UNIT_CASE: 590/54
#[test]
fn every_proven_stage_has_compatible_owner_receipt_predecessor() {
    for (stage, predecessor) in [
        (
            LifecycleStage::Delivered,
            Some(LifecycleStage::DeliveryAttempted),
        ),
        (
            LifecycleStage::Acknowledged,
            Some(LifecycleStage::Delivered),
        ),
        (LifecycleStage::Visible, Some(LifecycleStage::Acknowledged)),
        (
            LifecycleStage::SelectedActivated,
            Some(LifecycleStage::Visible),
        ),
        (
            LifecycleStage::Adhered,
            Some(LifecycleStage::SelectedActivated),
        ),
        (LifecycleStage::UsedInAction, Some(LifecycleStage::Adhered)),
    ] {
        let observation = StageObservation {
            stage,
            disposition: StageDisposition::Observed,
            predecessor,
            owner_receipt: Some(aid("receipt-590-c54")),
            evidence: vec![aid("ev-590-c54")],
            denominator: SourceDenominator {
                declared: 1,
                observed: 1,
            },
        };
        must(observation.validate());
        // Same stage without a receipt cannot prove the transition.
        let mut unproven = observation.clone();
        unproven.owner_receipt = None;
        assert!(unproven.validate().is_err());
        // Same stage with the wrong predecessor cannot prove it either.
        let mut wrong = observation.clone();
        wrong.predecessor = Some(LifecycleStage::CandidateProduced);
        assert!(wrong.validate().is_err());
    }
}

// WORK_UNIT_CASE: 590/55
#[test]
fn causal_assessment_claim_cannot_exceed_weakest_ceiling() {
    let mut assessment = valid_assessment("c55");
    assessment.dimensions[0].causal_ceiling = CausalCeiling::Observational;
    assessment.dimensions[1].causal_ceiling = CausalCeiling::Observational;
    assessment.causal_ceiling = CausalCeiling::ControlledComparison;
    must(assessment.seal());
    assert!(matches!(
        assessment.validate(),
        Err(LearningContractError::NonIndependentAssessment)
    ));
    assessment.causal_ceiling = CausalCeiling::Observational;
    must(assessment.seal());
    must(assessment.validate());
    let mut attribution = valid_attribution("c55");
    attribution.claim_ceiling = CausalCeiling::CausalAttribution;
    must(attribution.seal());
    assert!(matches!(
        attribution.validate(),
        Err(LearningContractError::NonIndependentAssessment)
    ));
    let mut experiment = valid_experiment("c55");
    experiment.claim_ceiling = CausalCeiling::CausalAttribution;
    must(experiment.seal());
    assert!(experiment.validate().is_err());
    let mut promotion = valid_promotion("c55");
    promotion.claim_ceiling = CausalCeiling::CausalAttribution;
    must(promotion.seal());
    assert!(promotion.validate().is_err());
}

// WORK_UNIT_CASE: 590/56
#[test]
fn changed_scope_fence_base_predecessor_evidence_invalidates_prior_digest() {
    let (_, view) = recipe_and_view();
    let digest_before = view.canonical_digest.clone();
    let mut scoped = view.clone();
    scoped.binding.scope = must(WorkScopeId::new("changed-scope-590-c56"));
    // Without resealing, the stale digest no longer matches the shape.
    assert!(matches!(
        scoped.validate_against(&recipe_and_view().0),
        Err(LearningContractError::DigestMismatch { .. }
            | LearningContractError::ScopeMismatch { .. })
    ));
    must(scoped.seal());
    assert_ne!(scoped.canonical_digest, digest_before);
    // Resealed scope drift no longer matches the original recipe binding.
    assert!(scoped.validate_against(&recipe_and_view().0).is_err());
    // Evidence mutation without resealing invalidates the digest.
    let mut delta = valid_delta("c56");
    let delta_digest = delta.canonical_digest.clone();
    delta.evidence.push(aid("late-evidence-590-c56"));
    assert!(matches!(
        delta.validate(),
        Err(LearningContractError::DigestMismatch { .. })
    ));
    must(delta.seal());
    assert_ne!(delta.canonical_digest, delta_digest);
    // Predecessor mutation without resealing invalidates the digest.
    let mut observation = stage_observation(
        LifecycleStage::Delivered,
        Some(LifecycleStage::DeliveryAttempted),
        "c56",
    );
    observation.predecessor = Some(LifecycleStage::Retrieved);
    assert!(observation.validate().is_err());
}

// WORK_UNIT_CASE: 590/57
#[test]
fn source_api_proof_excludes_io_mutable_provider_runtime_store_promotion_finish() {
    for schema in [
        schema_text::<LearningStateViewRecipe>(),
        schema_text::<CampaignLearningStateView>(),
        schema_text::<eliot_learning_contracts::AttemptLearningDeltaCandidate>(),
        schema_text::<CampaignHarnessOverlayCandidate>(),
        schema_text::<HarnessActivationReceiptCandidate>(),
        schema_text::<LearningAssessmentCandidate>(),
        schema_text::<ClosureHandoff>(),
    ] {
        assert_no_keys(
            &schema,
            &[
                "finish",
                "provider",
                "model_call",
                "runtime_action",
                "store_write",
                "file_handle",
                "socket",
                "admission_receipt_write",
            ],
        );
    }
    // Closure decision classes are inert requests, never a Finish/effect.
    for class in [
        ExternalDecisionClass::PromotionReview,
        ExternalDecisionClass::ClosureReview,
        ExternalDecisionClass::RollbackReview,
        ExternalDecisionClass::ReopenReview,
    ] {
        let wire = must(serde_json::to_string(&class));
        assert!(!wire.contains("FINISH"));
        let restored: ExternalDecisionClass = must(serde_json::from_str(&wire));
        assert_eq!(restored, class);
    }
    assert!(serde_json::from_str::<ExternalDecisionClass>("\"FINISH\"").is_err());
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("eliot-dreamer-candidate-validation"));
    assert!(!manifest.contains("tokio"));
    assert!(!manifest.contains("reqwest"));
    // Validate/seal are pure: repeated calls agree without external effects.
    let (recipe, _) = recipe_and_view();
    let mut first = recipe.clone();
    must(first.seal());
    let mut second = recipe.clone();
    must(second.seal());
    assert_eq!(first.canonical_digest, second.canonical_digest);
}

// WORK_UNIT_CASE: 590/58
#[test]
#[allow(clippy::too_many_lines)]
fn independent_consumer_compile_fixtures_without_inter_algorithm_dependencies() {
    // A-33 state-view consumer: compiles a view from the recipe using only
    // this contract crate, with no state-view implementation dependency.
    fn consumer_state_view(recipe: &LearningStateViewRecipe, view: &CampaignLearningStateView) {
        must(view.validate_against(recipe));
        assert_eq!(view.recipe_digest, recipe.canonical_digest);
    }
    // A-34 delta consumer: converts a consequential attempt into a delta
    // candidate using only this contract crate.
    fn consumer_delta(
        view: &CampaignLearningStateView,
        delta: &eliot_learning_contracts::AttemptLearningDeltaCandidate,
    ) {
        must(delta.validate_against_view(view));
    }
    // A-35 overlay consumer: assembles a task-local overlay from admitted
    // deltas using only this contract crate.
    fn consumer_overlay(
        view: &CampaignLearningStateView,
        delta: &eliot_learning_contracts::AttemptLearningDeltaCandidate,
        overlay: &CampaignHarnessOverlayCandidate,
    ) {
        must(overlay.validate_against_view_and_deltas(view, core::slice::from_ref(delta)));
    }
    // A-36 activation-assessment consumer: links activation and assessment
    // evidence using only this contract crate.
    fn consumer_activation_assessment(
        activation: &HarnessActivationReceiptCandidate,
        assessment: &LearningAssessmentCandidate,
    ) {
        must(assessment.validate_against_activation(activation));
    }
    let (recipe, view) = recipe_and_view();
    consumer_state_view(&recipe, &view);
    let target = view.target.clone();
    let proposed = ValueState {
        present: true,
        digest: Some(digest("consumer-590-c58")),
    };
    let mut delta = eliot_learning_contracts::AttemptLearningDeltaCandidate {
        binding: view.binding.clone(),
        attempt_id: must(AgentAttemptId::new("attempt-590-c58")),
        delta_id: aid("delta-590-c58"),
        target: target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid("disc-590-c58"),
        intended_strategy: aid("intended-590-c58"),
        attempted_strategy: aid("attempted-590-c58"),
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
                before: proposed.clone(),
            },
        }],
        evidence: vec![aid("delta-ev-590-c58")],
        evaluator_receipts: vec![aid("delta-eval-590-c58")],
        baseline: vec![aid("delta-base-590-c58")],
        control: vec![aid("delta-ctrl-590-c58")],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    must(delta.seal());
    consumer_delta(&view, &delta);
    let mut overlay = CampaignHarnessOverlayCandidate {
        binding: view.binding.clone(),
        overlay_id: OverlayId::from_artifact(aid("overlay-590-c58")),
        base_view_digest: view.canonical_digest.clone(),
        parent_revision: TaskRevision::genesis(),
        admitted_delta_ids: vec![delta.delta_id.clone()],
        admitted_delta_digests: vec![delta.canonical_digest.clone()],
        changes: vec![OverlayChange {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            base: ValueState {
                present: false,
                digest: None,
            },
            proposed,
            inverse: InverseChange {
                forward_target: target.clone(),
                inverse: ChangeOperation::Remove {
                    target: target.clone(),
                    surface: ChangeSurface::Strategy,
                    before: ValueState {
                        present: true,
                        digest: Some(digest("consumer-590-c58")),
                    },
                },
            },
            origin: OverlayOrigin::Overlay,
        }],
        dependencies: vec![],
        application_order: vec![target.clone()],
        protected_surface_base_digest: digest("protected-590-c58"),
        protected_surface_proposed_digest: digest("protected-590-c58"),
        fixed_before_observation_discriminator: aid("ovdisc-590-c58"),
        expires_at_ms: 11_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    must(overlay.seal());
    consumer_overlay(&view, &delta, &overlay);
    let mut activation = HarnessActivationReceiptCandidate {
        binding: view.binding.clone(),
        activation_id: aid("activation-590-c58"),
        target: target.clone(),
        view_digest: view.canonical_digest.clone(),
        delta_id: delta.delta_id.clone(),
        overlay_id: overlay.overlay_id.clone(),
        admission_receipt: aid("admission-590-c58"),
        activation_request_receipt: aid("actreq-590-c58"),
        stages: vec![StageObservation {
            stage: LifecycleStage::CandidateProduced,
            disposition: StageDisposition::Observed,
            predecessor: None,
            owner_receipt: Some(aid("stage-rc-590-c58")),
            evidence: vec![aid("stage-ev-590-c58")],
            denominator: SourceDenominator {
                declared: 1,
                observed: 1,
            },
        }],
        member_denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metrics: vec![],
        attrition: vec![],
        confounders: vec![],
        independent_evaluator_receipt: Some(aid("indep-590-c58")),
        canonical_digest: String::new(),
    };
    must(activation.seal());
    must(activation.validate_against_lineage(&view, &delta, &overlay));
    let mut assessment = LearningAssessmentCandidate {
        binding: view.binding.clone(),
        target,
        overlay_id: overlay.overlay_id.clone(),
        activation_id: activation.activation_id.clone(),
        activation_digest: activation.canonical_digest.clone(),
        assessment_receipt: aid("assess-590-c58"),
        dimensions: vec![DimensionAssessment {
            dimension: AssessmentDimension::Adherence,
            status: DimensionStatus::Unknown,
            evidence: vec![],
            owner_receipt: None,
            denominator: SourceDenominator {
                declared: 1,
                observed: 0,
            },
            metric_ids: vec![],
            causal_ceiling: CausalCeiling::Observational,
        }],
        causal_ceiling: CausalCeiling::Observational,
        external_review_refs: vec![aid("review-590-c58")],
        canonical_digest: String::new(),
    };
    must(assessment.seal());
    consumer_activation_assessment(&activation, &assessment);
    // No sibling implementation dependency: the manifest references only the
    // four lower-level contracts plus schema/serialization helpers.
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("eliot-learning-state-view"));
    assert!(!manifest.contains("eliot-learning-delta"));
    assert!(!manifest.contains("eliot-learning-overlay"));
    assert!(!manifest.contains("eliot-learning-activation-assessment"));
    assert!(!manifest.contains("eliot-dreamer-candidate-validation"));
    // Sibling vocabulary is referenced only through shared foundation types.
    let _campaign = CampaignId::from_artifact(aid("campaign-590-c58"));
    let _learning_target = LearningTargetId::from_artifact(aid("ltarget-590-c58"));
}
