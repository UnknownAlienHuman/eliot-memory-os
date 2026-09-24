use eliot_agent_contracts::{AgentAttemptId, TargetId};
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
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
    let mut state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    );
    state_fence.task_revision = Some(TaskRevision::genesis());
    Ok(ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new(format!("request-{tag}"))?,
        operation_id: OperationId::new(format!("operation-{tag}"))?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new(format!("task-{tag}"))?,
        scope: WorkScopeId::new(format!("scope-{tag}"))?,
        state_fence,
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
        source_role: CampaignSourceRole::ArtifactProjection,
        target: target.clone(),
        requirement: SlotRequirement::Required,
        declared_members: vec![MemberId::from_artifact(aid(&format!("member-{tag}"))?)],
        accepted_type: "strategy/v1".to_owned(),
        schema_digest: digest("strategy-schema"),
    })
}

fn source_revision(
    role: CampaignSourceRole,
    content_digest: &str,
    binding: &ContractBinding,
) -> CampaignOwnerRevision {
    match role {
        CampaignSourceRole::TaskObjective
        | CampaignSourceRole::TaskAcceptance
        | CampaignSourceRole::TaskPlan
        | CampaignSourceRole::TaskOpenItems
        | CampaignSourceRole::ContextRecipe
        | CampaignSourceRole::ContextDelivery
        | CampaignSourceRole::CurrentPosition => {
            CampaignOwnerRevision::Task(TaskRevision::genesis())
        }
        CampaignSourceRole::GovernorEpoch => {
            CampaignOwnerRevision::AuthorityEpoch(AuthorityEpoch::genesis())
        }
        CampaignSourceRole::GovernorPolicy | CampaignSourceRole::ContextToolPolicy => {
            CampaignOwnerRevision::Policy(binding.policy_revision)
        }
        CampaignSourceRole::MemoryProjection
        | CampaignSourceRole::StableHarness
        | CampaignSourceRole::TaskFamilyHarness => CampaignOwnerRevision::ResourceGeneration(
            binding.state_fence.resource_generation,
        ),
        CampaignSourceRole::FrozenAnchor | CampaignSourceRole::ArtifactProjection => {
            CampaignOwnerRevision::ResourceSnapshot(content_digest.to_owned())
        }
        _ => CampaignOwnerRevision::Counter(1),
    }
}

fn campaign_source_contract(
    binding: &ContractBinding,
) -> Result<(Vec<CampaignSourceRequirement>, CampaignLearningStateProvenance), Box<dyn std::error::Error>> {
    let mut requirements = Vec::with_capacity(CampaignSourceRole::all().len());
    let mut resolutions = Vec::with_capacity(CampaignSourceRole::all().len());
    for (index, role) in CampaignSourceRole::all().into_iter().enumerate() {
        let task_anchor = role == CampaignSourceRole::TaskPlan;
        let owner = if task_anchor {
            OwnerId::from_artifact(aid(TASK_CONTROLLER_CAMPAIGN_OWNER_ID)?)
        } else {
            OwnerId::from_artifact(aid(&format!("source-owner-a-{index}"))?)
        };
        let expected_reference = if role == CampaignSourceRole::ActiveOverlay || task_anchor {
            None
        } else {
            let content_digest = digest(&format!("source-content-a-{index}"));
            let record_id = match role {
                CampaignSourceRole::TaskObjective
                | CampaignSourceRole::TaskAcceptance
                | CampaignSourceRole::TaskOpenItems => {
                    CampaignOwnerRecordId::Task(binding.task_id.clone())
                }
                _ => CampaignOwnerRecordId::Artifact(aid(&format!("source-record-a-{index}"))?),
            };
            Some(CampaignSourceRevisionRef {
                role,
                owner: owner.clone(),
                record_id,
                revision: source_revision(role, &content_digest, binding),
                content_digest,
                slot_projection_digests: vec![],
                recorded_state_fence: binding.state_fence.clone(),
            })
        };
        let absent = role == CampaignSourceRole::ActiveOverlay;
        let reference = if task_anchor {
            Some(CampaignSourceRevisionRef {
                role,
                owner: owner.clone(),
                record_id: CampaignOwnerRecordId::Task(binding.task_id.clone()),
                revision: CampaignOwnerRevision::Task(
                    binding
                        .state_fence
                        .task_revision
                        .clone()
                        .expect("task anchor revision"),
                ),
                content_digest: digest("task-anchor-a"),
                slot_projection_digests: vec![],
                recorded_state_fence: binding.state_fence.clone(),
            })
        } else {
            expected_reference.clone()
        };
        requirements.push(CampaignSourceRequirement {
            role,
            source_binding: if absent {
                CampaignSourceBinding::ExplicitlyAbsent
            } else if task_anchor {
                CampaignSourceBinding::AuthenticatedTaskAnchor
            } else {
                CampaignSourceBinding::ExactReference
            },
            owner,
            expected_reference: expected_reference.clone(),
            load_bearing: !absent,
        });
        resolutions.push(CampaignSourceResolution {
            role,
            status: if reference.is_some() {
                CampaignSourceResolutionStatus::Current
            } else {
                CampaignSourceResolutionStatus::Missing
            },
            reference,
            read_state_fence: binding.state_fence.clone(),
        });
    }
    let position_specs = [
        (CampaignPositionKind::Current, CampaignSourceRole::CurrentPosition),
        (CampaignPositionKind::Experience, CampaignSourceRole::ExperiencePosition),
        (CampaignPositionKind::Adaptation, CampaignSourceRole::AdaptationPosition),
        (CampaignPositionKind::Evaluation, CampaignSourceRole::EvaluationPosition),
        (CampaignPositionKind::EconomicsProgress, CampaignSourceRole::EconomicsProgress),
    ];
    let positions = position_specs
        .into_iter()
        .map(|(kind, source_role)| {
            let source = resolutions
                .iter()
                .find(|resolution| resolution.role == source_role)
                .and_then(|resolution| resolution.reference.as_ref())
                .expect("position role has an exact source reference");
            CampaignPositionRef {
                kind,
                source_role,
                record_id: source.record_id.clone(),
                revision: source.revision.clone(),
                source_content_digest: source.content_digest.clone(),
                position_digest: source.content_digest.clone(),
            }
        })
        .collect();
    let frozen_anchor_digest = resolutions
        .iter()
        .find(|resolution| resolution.role == CampaignSourceRole::FrozenAnchor)
        .and_then(|resolution| resolution.reference.as_ref())
        .map(|reference| reference.content_digest.clone())
        .expect("frozen anchor has an exact source reference");
    Ok((
        requirements,
        CampaignLearningStateProvenance {
            source_resolutions: resolutions,
            frozen_anchor_digest,
            positions,
            history_plans: vec![CampaignHistoryPlanReference {
                retrieval_plan_digest: digest("retrieval-plan-a"),
                selected_handles: vec![aid("history-handle-a")?],
                summary_digest: Some(digest("history-summary-a")),
                diff_digests: vec![digest("history-diff-a")],
                policy_slice_handles: vec![],
            }],
            generated_at_ms: 1_790_208_000_000,
            expires_at_ms: None,
            rebuild_reason: None,
        },
    ))
}

fn bind_slot_source_contract(
    recipe: &mut LearningStateViewRecipe,
    provenance: &mut CampaignLearningStateProvenance,
    projections: &[SlotProjection],
) -> Result<(), Box<dyn std::error::Error>> {
    for spec in &recipe.slots {
        let requirement = recipe
            .source_requirements
            .iter_mut()
            .find(|requirement| requirement.role == spec.source_role)
            .expect("slot source role is declared");
        requirement.owner = spec.owner.clone();
        requirement.expected_reference.as_mut().expect("slot source is declared").owner = spec.owner.clone();
        let resolution = provenance
            .source_resolutions
            .iter_mut()
            .find(|resolution| resolution.role == spec.source_role)
            .expect("slot source role is resolved");
        resolution.reference.as_mut().expect("slot source is current").owner = spec.owner.clone();
    }
    for projection in projections {
        let spec = recipe
            .slots
            .iter()
            .find(|spec| spec.slot_id == projection.slot_id)
            .expect("projection is declared by recipe");
        let projection_digest = projection.canonical_digest()?;
        recipe
            .source_requirements
            .iter_mut()
            .find(|requirement| requirement.role == spec.source_role)
            .expect("slot source role is declared")
            .expected_reference
            .as_mut()
            .expect("slot source is declared")
            .slot_projection_digests
            .push(CampaignSlotProjectionDigest { slot_id: projection.slot_id.clone(), digest: projection_digest.clone() });
        provenance
            .source_resolutions
            .iter_mut()
            .find(|resolution| resolution.role == spec.source_role)
            .expect("slot source role is resolved")
            .reference
            .as_mut()
            .expect("slot source is current")
            .slot_projection_digests
            .push(CampaignSlotProjectionDigest { slot_id: projection.slot_id.clone(), digest: projection_digest });
    }
    recipe.seal()?;
    Ok(())
}

fn recipe_and_view()
-> Result<(LearningStateViewRecipe, CampaignLearningStateView), Box<dyn std::error::Error>> {
    let target = target("target-a")?;
    let binding = binding("a")?;
    let spec = slot("a", &target)?;
    let mut optional = slot("optional", &target)?;
    optional.requirement = SlotRequirement::Optional;
    optional.source_role = CampaignSourceRole::MemoryProjection;
    let (source_requirements, mut provenance) = campaign_source_contract(&binding)?;
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-a")?,
        campaign_id: CampaignId::from_artifact(aid("campaign-a")?),
        target: target.clone(),
        binding: binding.clone(),
        slots: vec![spec.clone(), optional.clone()],
        source_requirements,
        active_overlay_policy: CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed,
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    let member = MemberProjection {
        member_id: spec.declared_members[0].clone(),
        owner: spec.owner.clone(),
        source: binding.source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest("strategy-value")),
        evidence: vec![aid("evidence-view")?],
    };
    let slots = vec![SlotProjection {
        slot_id: spec.slot_id.clone(),
        disposition: SlotDisposition::Current,
        members: vec![member],
        evidence: vec![aid("evidence-slot")?],
    }];
    bind_slot_source_contract(&mut recipe, &mut provenance, &slots)?;
    let mut view = CampaignLearningStateView {
        view_id: aid("view-a")?,
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target,
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        provenance,
        slots,
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
    view.seal_content_addressed()?;
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
        campaign_id: CampaignId::from_artifact(aid("campaign-contracts")?),
        admission_receipt: None,
        revision: 1,
        supersedes: None,
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
        intended_mechanism: "contracts-mechanism".to_owned(),
        prediction: "contracts-prediction".to_owned(),
        expected_observable: "contracts-observable".to_owned(),
        possible_regressions: "contracts-regressions".to_owned(),
        confounders: "contracts-confounders".to_owned(),
        preserved_success_constraint: "contracts-preserved".to_owned(),
        next_discriminator_text: "contracts-next".to_owned(),
        rollback_condition: "contracts-rollback".to_owned(),
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
    let closure = StageObservation {
        stage: LifecycleStage::Closure,
        disposition: StageDisposition::Observed,
        predecessor: None,
        owner_receipt: Some(aid("closure-stage-receipt")?),
        evidence: vec![aid("closure-stage-evidence")?],
        denominator,
    };
    closure.validate()?;
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
        intended_mechanism: "linked-mechanism".to_owned(),
        prediction: "linked-prediction".to_owned(),
        expected_observable: "linked-observable".to_owned(),
        possible_regressions: "linked-regressions".to_owned(),
        confounders: "linked-confounders".to_owned(),
        preserved_success_constraint: "linked-preserved".to_owned(),
        next_discriminator_text: "linked-next".to_owned(),
        rollback_condition: "linked-rollback".to_owned(),
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
        compiled_view_ref: aid("linked-compiled-view")?,
        context_compiler_revision: "compiler-rev-1".to_owned(),
        render_profile_revision: "render-profile-rev-1".to_owned(),
        stable_harness_refs: vec![aid("linked-stable-harness")?],
        task_family_harness_refs: vec![aid("linked-task-family-harness")?],
        skill_refs: vec![aid("linked-skill")?],
        memory_refs: vec![aid("linked-memory")?],
        procedure_refs: vec![aid("linked-procedure")?],
        preserved_success_ref: Some(aid("linked-preserved-success")?),
        eligibility_and_retrieval_reason: Some("eligible and retrieved".to_owned()),
        retrieval: eliot_learning_contracts::activation::RetrievalSection {
            status: eliot_learning_contracts::activation::RetrievalStatus::Retrieved,
            expansion_or_tool_query_refs: vec![],
        },
        delivery: eliot_learning_contracts::activation::DeliverySection {
            status: eliot_learning_contracts::activation::DeliveryStatus::Full,
            packet_position: Some(0),
            serialized_digest: Some(digest("linked-packet")),
            bytes: Some(128),
            actual_tokens: Some(32),
        },
        activation: eliot_learning_contracts::activation::ActivationSection {
            status: eliot_learning_contracts::activation::ActivationStatus::NotObserved,
            acknowledgement_ref: Some(aid("linked-ack")?),
            observation_limit_reason: None,
            first_qualifying_observable_use_ref: None,
        },
        adherence: eliot_learning_contracts::activation::AdherenceSection {
            status: eliot_learning_contracts::activation::AdherenceStatus::NotAssessed,
            early_mid_final_checkpoint_refs: vec![],
            prescribed_or_avoided_action_and_required_verifier_refs: vec![],
        },
        conflicts_suppression_or_compaction_loss: vec![],
        downstream_decision_action_artifact_and_verifier_refs: vec![],
        receipt_completeness_and_missing_fields: vec![],
        invalidation_expiry_and_missingness: vec![],
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
