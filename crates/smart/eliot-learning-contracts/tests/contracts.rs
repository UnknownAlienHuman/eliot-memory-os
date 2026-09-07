use eliot_agent_contracts::{AgentAttemptId, TargetId};
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::*;
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
    Ok(ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new(format!("request-{tag}"))?,
        operation_id: OperationId::new(format!("operation-{tag}"))?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new(format!("task-{tag}"))?,
        scope: WorkScopeId::new(format!("scope-{tag}"))?,
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        source: identity::SourceLineage {
            owner: SourceId::new(format!("source-{tag}"))?,
            snapshot: aid(&format!("snapshot-{tag}"))?,
            revision: TaskRevision::genesis(),
            digest: digest("source"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn slot(tag: &str, target: &TargetId) -> Result<state_view::SlotSpec, Box<dyn std::error::Error>> {
    Ok(state_view::SlotSpec {
        slot_id: SlotId::from_artifact(aid(&format!("slot-{tag}"))?),
        owner: OwnerId::from_artifact(aid(&format!("owner-{tag}"))?),
        target: target.clone(),
        requirement: SlotRequirement::Required,
        declared_members: vec![MemberId::from_artifact(aid(&format!("member-{tag}"))?)],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    })
}

fn recipe_and_view()
-> Result<(LearningStateViewRecipe, CampaignLearningStateView), Box<dyn std::error::Error>> {
    let target = target("target-a")?;
    let binding = binding("a")?;
    let spec = slot("a", &target)?;
    let mut optional = slot("optional", &target)?;
    optional.requirement = SlotRequirement::Optional;
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-a")?,
        campaign_id: CampaignId::from_artifact(aid("campaign-a")?),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![spec.clone(), optional.clone()],
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    recipe.seal()?;
    let member = MemberProjection {
        member_id: spec.declared_members[0].clone(),
        owner: spec.owner.clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("strategy-value")),
        evidence: vec![aid("evidence-view")?],
    };
    let mut view = CampaignLearningStateView {
        view_id: aid("view-a")?,
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target,
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        slots: vec![SlotProjection {
            slot_id: spec.slot_id,
            disposition: SlotDisposition::Current,
            members: vec![member],
            evidence: vec![aid("evidence-slot")?],
        }],
        denominator: SourceDenominator {
            declared: 2,
            observed: 1,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![optional.slot_id],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("objective-ref")?],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.seal()?;
    Ok((recipe, view))
}

#[test]
fn recipe_view_roundtrip_requires_exact_members_and_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let (recipe, view) = recipe_and_view()?;
    recipe.validate()?;
    view.validate_against(&recipe)?;
    let json = serde_json::to_string(&view)?;
    let restored: CampaignLearningStateView = serde_json::from_str(&json)?;
    assert_eq!(view, restored);
    let mut changed = restored;
    changed.binding.request_id = RequestId::new("different-request")?;
    changed.seal()?;
    assert!(matches!(
        changed.validate_against(&recipe),
        Err(LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

#[test]
fn consequential_success_has_delta_or_evidence_backed_no_change()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, view) = recipe_and_view()?;
    let target = target("target-a")?;
    let binding = binding("b")?;
    let change = ChangeOperation::Add {
        target: target.clone(),
        surface: ChangeSurface::Strategy,
        after: ValueState {
            present: true,
            digest: Some(digest("new-strategy")),
        },
    };
    let inverse = InverseChange {
        forward_target: target.clone(),
        inverse: ChangeOperation::Remove {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            before: ValueState {
                present: true,
                digest: Some(digest("new-strategy")),
            },
        },
    };
    let mut delta = AttemptLearningDeltaCandidate {
        binding: binding.clone(),
        attempt_id: AgentAttemptId::new("attempt-b")?,
        delta_id: aid("delta-b")?,
        target: target.clone(),
        base_view_digest: view.canonical_digest,
        pre_observation_discriminator: aid("discriminator-b")?,
        intended_strategy: aid("intended-b")?,
        attempted_strategy: aid("attempted-b")?,
        changes: vec![change],
        inverses: vec![inverse],
        evidence: vec![aid("delta-evidence")?],
        evaluator_receipts: vec![aid("evaluator-b")?],
        baseline: vec![aid("baseline-b")?],
        control: vec![aid("control-b")?],
        confounders: vec![],
        dependencies: vec![aid("dependency-b")?],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    delta.seal()?;
    delta.validate()?;
    let delta_json = serde_json::to_string(&AttemptLearningOutcome::Delta(delta))?;
    assert!(delta_json.contains("\"outcome\":\"DELTA\""));
    let mut no_change = NoChangeDisposition {
        binding,
        attempt_id: AgentAttemptId::new("attempt-c")?,
        target,
        reason: NoChangeReason::ConfirmedFixedPrediction,
        affirmative_evidence: vec![aid("fixed-prediction")?],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        canonical_digest: String::new(),
    };
    no_change.seal()?;
    no_change.validate()?;
    assert!(
        serde_json::to_string(&AttemptLearningOutcome::NoChange(no_change))?
            .contains("\"outcome\":\"NO_CHANGE\"")
    );
    Ok(())
}

#[test]
fn overlay_is_expiring_reversible_and_protects_base_surface()
-> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("overlay")?;
    let target = target("overlay-target")?;
    let base = ValueState {
        present: false,
        digest: None,
    };
    let proposed = ValueState {
        present: true,
        digest: Some(digest("overlay-value")),
    };
    let mut overlay = CampaignHarnessOverlayCandidate {
        binding,
        overlay_id: OverlayId::from_artifact(aid("overlay-1")?),
        base_view_digest: digest("base-view"),
        parent_revision: TaskRevision::genesis(),
        admitted_delta_ids: vec![aid("admitted-delta")?],
        admitted_delta_digests: vec![digest("admitted-delta-shape")],
        changes: vec![OverlayChange {
            target: target.clone(),
            surface: ChangeSurface::TaskLocalContext,
            base,
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
        protected_surface_base_digest: digest("protected"),
        protected_surface_proposed_digest: digest("protected"),
        fixed_before_observation_discriminator: aid("fixed-overlay-discriminator")?,
        expires_at_ms: 2_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    overlay.seal()?;
    overlay.validate()?;
    assert!(overlay.is_reversible());
    Ok(())
}

#[test]
fn lifecycle_stages_require_owner_receipts_and_predecessors()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = aid("stage-evidence")?;
    let receipt = aid("stage-receipt")?;
    let denominator = SourceDenominator {
        declared: 1,
        observed: 1,
    };
    let candidate = StageObservation {
        stage: LifecycleStage::CandidateProduced,
        disposition: StageDisposition::Observed,
        predecessor: None,
        owner_receipt: Some(receipt.clone()),
        evidence: vec![evidence.clone()],
        denominator,
    };
    candidate.validate()?;
    let skipped = StageObservation {
        stage: LifecycleStage::Visible,
        disposition: StageDisposition::Observed,
        predecessor: Some(LifecycleStage::CandidateProduced),
        owner_receipt: Some(receipt),
        evidence: vec![evidence],
        denominator,
    };
    assert!(matches!(
        skipped.validate(),
        Err(LearningContractError::IncompatiblePredecessor)
    ));
    Ok(())
}

#[test]
fn assessment_dimensions_and_closure_handoff_remain_independent_and_inert()
-> Result<(), Box<dyn std::error::Error>> {
    let binding = binding("assessment")?;
    let target = target("assessment-target")?;
    let owner = OwnerId::from_artifact(aid("assessment-owner")?);
    let mut assessment = LearningAssessmentCandidate {
        binding: binding.clone(),
        target: target.clone(),
        overlay_id: OverlayId::from_artifact(aid("assessment-overlay")?),
        activation_id: aid("assessment-activation")?,
        activation_digest: digest("assessment-activation-shape"),
        assessment_receipt: aid("assessment-receipt")?,
        dimensions: vec![
            DimensionAssessment {
                dimension: AssessmentDimension::Adherence,
                status: DimensionStatus::Pass,
                evidence: vec![aid("adherence-evidence")?],
                owner_receipt: Some(aid("adherence-receipt")?),
                denominator: SourceDenominator {
                    declared: 1,
                    observed: 1,
                },
                metric_ids: vec![aid("adherence-metric")?],
                causal_ceiling: CausalCeiling::Observational,
            },
            DimensionAssessment {
                dimension: AssessmentDimension::Harm,
                status: DimensionStatus::Harm,
                evidence: vec![aid("harm-evidence")?],
                owner_receipt: Some(aid("harm-receipt")?),
                denominator: SourceDenominator {
                    declared: 1,
                    observed: 1,
                },
                metric_ids: vec![aid("harm-metric")?],
                causal_ceiling: CausalCeiling::Observational,
            },
        ],
        causal_ceiling: CausalCeiling::Observational,
        external_review_refs: vec![aid("external-review")?],
        canonical_digest: String::new(),
    };
    assessment.seal()?;
    assessment.validate()?;
    let mut handoff = ClosureHandoff {
        binding: binding.clone(),
        target,
        delta_id: aid("closure-delta")?,
        overlay_id: assessment.overlay_id.clone(),
        assessment_id: assessment.assessment_receipt.clone(),
        assessment_digest: assessment.canonical_digest,
        required_owner_proofs: vec![OwnerProof {
            owner,
            receipt: aid("closure-owner-receipt")?,
            scope: binding.scope.clone(),
            state_fence: binding.state_fence.clone(),
            evidence: vec![aid("closure-owner-evidence")?],
            proof_ceiling: ProofCeiling::CandidateArtifact,
        }],
        debts: vec![AssessmentDimension::Harm],
        rollback_refs: vec![aid("rollback")?],
        external_promotion_refs: vec![aid("promotion-owner")?],
        requested_decision: ExternalDecisionClass::ClosureReview,
        canonical_digest: String::new(),
    };
    handoff.seal()?;
    handoff.validate()?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn linked_candidate_flow_preserves_lineage() -> Result<(), Box<dyn std::error::Error>> {
    let (recipe, view) = recipe_and_view()?;
    let target = view.target.clone();
    let proposed = ValueState {
        present: true,
        digest: Some(digest("linked-proposed")),
    };
    let mut delta = AttemptLearningDeltaCandidate {
        binding: view.binding.clone(),
        attempt_id: AgentAttemptId::new("linked-attempt")?,
        delta_id: aid("linked-delta")?,
        target: target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid("linked-discriminator")?,
        intended_strategy: aid("linked-intended")?,
        attempted_strategy: aid("linked-attempted")?,
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
        evidence: vec![aid("linked-evidence")?],
        evaluator_receipts: vec![aid("linked-evaluator")?],
        baseline: vec![aid("linked-baseline")?],
        control: vec![aid("linked-control")?],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    delta.seal()?;
    delta.validate_against_view(&view)?;
    let mut overlay = CampaignHarnessOverlayCandidate {
        binding: view.binding.clone(),
        overlay_id: OverlayId::from_artifact(aid("linked-overlay")?),
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
                        digest: Some(digest("linked-proposed")),
                    },
                },
            },
            origin: OverlayOrigin::Overlay,
        }],
        dependencies: vec![],
        application_order: vec![target.clone()],
        protected_surface_base_digest: digest("linked-protected"),
        protected_surface_proposed_digest: digest("linked-protected"),
        fixed_before_observation_discriminator: aid("linked-fixed")?,
        expires_at_ms: 3_000,
        invalidated: false,
        canonical_digest: String::new(),
    };
    overlay.seal()?;
    overlay.validate_against_view_and_deltas(&view, std::slice::from_ref(&delta))?;
    let mut receipt = HarnessActivationReceiptCandidate {
        binding: view.binding.clone(),
        activation_id: aid("linked-activation-receipt")?,
        target: target.clone(),
        view_digest: view.canonical_digest.clone(),
        delta_id: delta.delta_id.clone(),
        overlay_id: overlay.overlay_id.clone(),
        admission_receipt: aid("linked-admission")?,
        activation_request_receipt: aid("linked-activation")?,
        stages: vec![StageObservation {
            stage: LifecycleStage::CandidateProduced,
            disposition: StageDisposition::Observed,
            predecessor: None,
            owner_receipt: Some(aid("linked-stage-receipt")?),
            evidence: vec![aid("linked-stage-evidence")?],
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
        independent_evaluator_receipt: Some(aid("linked-independent")?),
        canonical_digest: String::new(),
    };
    receipt.seal()?;
    receipt.validate_against_lineage(&view, &delta, &overlay)?;
    let mut assessment = LearningAssessmentCandidate {
        binding: view.binding.clone(),
        target,
        overlay_id: overlay.overlay_id.clone(),
        activation_id: receipt.activation_id.clone(),
        activation_digest: receipt.canonical_digest.clone(),
        assessment_receipt: aid("linked-assessment")?,
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
        external_review_refs: vec![aid("linked-review")?],
        canonical_digest: String::new(),
    };
    assessment.seal()?;
    assessment.validate_against_activation(&receipt)?;
    let mut handoff = ClosureHandoff {
        binding: view.binding,
        target: view.target,
        delta_id: delta.delta_id.clone(),
        overlay_id: overlay.overlay_id,
        assessment_id: assessment.assessment_receipt.clone(),
        assessment_digest: assessment.canonical_digest.clone(),
        required_owner_proofs: vec![OwnerProof {
            owner: OwnerId::from_artifact(aid("linked-owner")?),
            receipt: aid("linked-owner-receipt")?,
            scope: recipe.binding.scope,
            state_fence: recipe.binding.state_fence,
            evidence: vec![aid("linked-owner-evidence")?],
            proof_ceiling: ProofCeiling::CandidateArtifact,
        }],
        debts: vec![AssessmentDimension::Adherence],
        rollback_refs: vec![aid("linked-rollback")?],
        external_promotion_refs: vec![],
        requested_decision: ExternalDecisionClass::ClosureReview,
        canonical_digest: String::new(),
    };
    handoff.seal()?;
    handoff.validate_against_assessment_and_delta(&assessment, &delta)?;
    Ok(())
}
