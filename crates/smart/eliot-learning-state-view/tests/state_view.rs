#![allow(clippy::expect_used)]

use std::error::Error;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::{
    CampaignActiveOverlayPolicy, CampaignLearningStateView, CampaignOwnerRecordId,
    CampaignOwnerRevision, CampaignPositionKind, CampaignPositionRef, CampaignSlotProjectionDigest,
    CampaignSourceBinding, CampaignSourceRequirement, CampaignSourceResolution,
    CampaignSourceResolutionStatus, CampaignSourceRevisionRef, CampaignSourceRole, Completeness,
    ContractBinding, LearningStateViewRecipe, MemberProjection, OmissionPolicy, OwnerDisagreement,
    OwnerId, SlotDisposition, SlotId, SlotProjection, SlotRequirement, SlotSpec, TargetId,
    TASK_CONTROLLER_CAMPAIGN_OWNER_ID,
};
use eliot_learning_contracts::{ProofCeiling, WorkScopeId};
use eliot_learning_state_view::{
    CampaignHistoryPlanInput, CampaignLearningStateCompilationInput, MAX_EVIDENCE,
    MAX_LABEL_BYTES, MAX_RECORD_EVIDENCE, compile_campaign_learning_state_view,
};
use eliot_reactive_context_plan::{
    CampaignBudgets, CampaignExperienceQuery, CampaignIntent, CampaignOutputMode, RetrievalPlan,
    RouteExecution, RouteExecutionOrder, SourceProjectionFence,
};

type TestResult = Result<(), Box<dyn Error>>;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn artifact(value: &str) -> Result<ArtifactId, Box<dyn Error>> {
    Ok(ArtifactId::new(value)?)
}

fn source(
    tag: &str,
    revision: u64,
) -> Result<eliot_learning_contracts::identity::SourceLineage, Box<dyn Error>> {
    Ok(eliot_learning_contracts::identity::SourceLineage {
        owner: SourceId::new(format!("source-{tag}"))?,
        snapshot: artifact(&format!("snapshot-{tag}"))?,
        revision: TaskRevision::new(revision)?,
        digest: digest(&format!("source-{tag}-{revision}")),
    })
}

fn binding() -> Result<ContractBinding, Box<dyn Error>> {
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
        request_id: RequestId::new("request-614")?,
        operation_id: OperationId::new("operation-614")?,
        product_id: ProductId::new("product-614")?,
        task_id: TaskId::new("task-614")?,
        scope: WorkScopeId::new("scope-614")?,
        state_fence,
        source: source("binding", 1)?,
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

const SLOT_SOURCE_ROLES: [CampaignSourceRole; 19] = [
    CampaignSourceRole::TaskObjective,
    CampaignSourceRole::TaskAcceptance,
    CampaignSourceRole::TaskOpenItems,
    CampaignSourceRole::AttemptLineageLatestOutcomes,
    CampaignSourceRole::GovernorAdmission,
    CampaignSourceRole::GovernorEpoch,
    CampaignSourceRole::GovernorPolicy,
    CampaignSourceRole::ContextRecipe,
    CampaignSourceRole::ContextToolPolicy,
    CampaignSourceRole::ContextDelivery,
    CampaignSourceRole::EvaluatorContract,
    CampaignSourceRole::EvaluatorHoldout,
    CampaignSourceRole::EvaluationResults,
    CampaignSourceRole::MemoryProjection,
    CampaignSourceRole::ExperienceProjection,
    CampaignSourceRole::ArtifactProjection,
    CampaignSourceRole::FrozenAnchor,
    CampaignSourceRole::StableHarness,
    CampaignSourceRole::TaskFamilyHarness,
];

fn source_requirements(
    binding: &ContractBinding,
    slots: &[SlotSpec],
) -> Result<Vec<CampaignSourceRequirement>, Box<dyn Error>> {
    CampaignSourceRole::all()
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            let task_anchor = role == CampaignSourceRole::TaskPlan;
            let owner = if task_anchor {
                OwnerId::from_artifact(artifact(TASK_CONTROLLER_CAMPAIGN_OWNER_ID)?)
            } else {
                slots
                    .iter()
                    .find(|slot| slot.source_role == role)
                    .map(|slot| slot.owner.clone())
                    .unwrap_or(OwnerId::from_artifact(artifact(&format!("source-owner-{index}"))?))
            };
            let absent = role == CampaignSourceRole::ActiveOverlay;
            let expected_reference = if absent || task_anchor {
                None
            } else {
                let task_record = matches!(
                    role,
                    CampaignSourceRole::TaskObjective
                        | CampaignSourceRole::TaskAcceptance
                        | CampaignSourceRole::TaskOpenItems
                );
                Some(CampaignSourceRevisionRef {
                    role,
                    owner: owner.clone(),
                    record_id: if task_record {
                        CampaignOwnerRecordId::Task(binding.task_id.clone())
                    } else {
                        CampaignOwnerRecordId::Artifact(artifact(&format!("source-record-{index}"))?)
                    },
                    revision: if task_record {
                        CampaignOwnerRevision::Task(TaskRevision::genesis())
                    } else {
                        CampaignOwnerRevision::Counter(index as u64 + 1)
                    },
                    content_digest: digest(&format!("source-content-{index}")),
                    slot_projection_digests: vec![],
                    recorded_state_fence: binding.state_fence.clone(),
                })
            };
            Ok(CampaignSourceRequirement {
                role,
                source_binding: if absent {
                    CampaignSourceBinding::ExplicitlyAbsent
                } else if task_anchor {
                    CampaignSourceBinding::AuthenticatedTaskAnchor
                } else {
                    CampaignSourceBinding::ExactReference
                },
                owner,
                expected_reference,
                load_bearing: !absent,
            })
        })
        .collect()
}

fn recipe(
    requirements: Vec<SlotRequirement>,
    member_counts: Vec<usize>,
    omission_policy: OmissionPolicy,
) -> Result<LearningStateViewRecipe, Box<dyn Error>> {
    let target = TargetId::new("target-614")?;
    let binding = binding()?;
    let mut slots = Vec::new();
    for (index, (requirement, member_count)) in
        requirements.into_iter().zip(member_counts).enumerate()
    {
        let slot_id = SlotId::from_artifact(artifact(&format!("slot-{index}"))?);
        let owner = OwnerId::from_artifact(artifact(&format!("owner-{index}"))?);
        let source_role = *SLOT_SOURCE_ROLES
            .get(index)
            .expect("test recipes use unique slot source roles");
        let members = (0..member_count)
            .map(|member| {
                artifact(&format!("member-{index}-{member}"))
                    .map(eliot_learning_contracts::MemberId::from_artifact)
            })
            .collect::<Result<Vec<_>, _>>()?;
        slots.push(SlotSpec {
            slot_id,
            owner,
            source_role,
            target: target.clone(),
            requirement,
            declared_members: members,
            accepted_type: "projection/v1".to_owned(),
            schema_digest: digest("projection-schema"),
        });
    }
    let source_requirements = source_requirements(&binding, &slots)?;
    let mut value = LearningStateViewRecipe {
        recipe_id: artifact("recipe-614")?,
        campaign_id: eliot_learning_contracts::CampaignId::from_artifact(artifact("campaign-614")?),
        target,
        binding,
        slots,
        source_requirements,
        active_overlay_policy: CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed,
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy,
        canonical_digest: String::new(),
    };
    value.seal()?;
    Ok(value)
}

fn projection(
    recipe: &LearningStateViewRecipe,
    slot_index: usize,
    disposition: SlotDisposition,
) -> Result<SlotProjection, Box<dyn Error>> {
    let lineage = source(&format!("slot-{slot_index}"), 1)?;
    projection_with_lineage(recipe, slot_index, disposition, &lineage)
}

fn projection_with_lineage(
    recipe: &LearningStateViewRecipe,
    slot_index: usize,
    disposition: SlotDisposition,
    lineage: &eliot_learning_contracts::identity::SourceLineage,
) -> Result<SlotProjection, Box<dyn Error>> {
    let spec = &recipe.slots[slot_index];
    let members = spec
        .declared_members
        .iter()
        .enumerate()
        .map(|(index, member_id)| {
            Ok(MemberProjection {
                member_id: member_id.clone(),
                owner: spec.owner.clone(),
                source: lineage.clone(),
                projection_revision: TaskRevision::new(1)?,
                disposition: if disposition == SlotDisposition::Current {
                    SlotDisposition::Current
                } else {
                    disposition
                },
                value_digest: Some(digest(&format!("value-{slot_index}-{index}"))),
                evidence: vec![
                    artifact(&format!("evidence-{slot_index}-{index}-a"))?,
                    artifact(&format!("evidence-{slot_index}-{index}-b"))?,
                ],
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(SlotProjection {
        slot_id: spec.slot_id.clone(),
        disposition,
        members,
        evidence: vec![
            artifact(&format!("slot-evidence-{slot_index}-a"))?,
            artifact(&format!("slot-evidence-{slot_index}-b"))?,
        ],
    })
}

fn compile(
    recipe: &mut LearningStateViewRecipe,
    projections: &[SlotProjection],
    refs: &[ArtifactId],
) -> Result<CampaignLearningStateView, eliot_learning_contracts::LearningContractError> {
    compile_with(recipe, projections, refs, &[], None)
}

fn compile_with(
    recipe: &mut LearningStateViewRecipe,
    projections: &[SlotProjection],
    refs: &[ArtifactId],
    disagreements: &[OwnerDisagreement],
    current_state_fence: Option<&StateFence>,
) -> Result<CampaignLearningStateView, eliot_learning_contracts::LearningContractError> {
    let mut bound_recipe = recipe.clone();
    bound_recipe.validate()?;
    for requirement in &mut bound_recipe.source_requirements {
        if let Some(reference) = requirement.expected_reference.as_mut() {
            reference.slot_projection_digests.clear();
        }
    }
    for projection in projections {
        let spec = bound_recipe
            .slots
            .iter()
            .find(|spec| spec.slot_id == projection.slot_id)
            .ok_or(eliot_learning_contracts::LearningContractError::ScopeMismatch {
                field: "projection.slot_id",
            })?;
        bound_recipe
            .source_requirements
            .iter_mut()
            .find(|requirement| requirement.role == spec.source_role)
            .expect("slot source role is declared")
            .expected_reference
            .as_mut()
            .expect("slot source has an exact reference")
            .slot_projection_digests
            .push(CampaignSlotProjectionDigest {
                slot_id: projection.slot_id.clone(),
                digest: projection.canonical_digest()?,
            });
    }
    bound_recipe.seal()?;
    *recipe = bound_recipe;

    let source_resolutions: Vec<_> = recipe
        .source_requirements
        .iter()
        .map(|requirement| {
            let authenticated_task_anchor =
                requirement.source_binding == CampaignSourceBinding::AuthenticatedTaskAnchor;
            let reference = if authenticated_task_anchor {
                Some(CampaignSourceRevisionRef {
                    role: requirement.role,
                    owner: requirement.owner.clone(),
                    record_id: CampaignOwnerRecordId::Task(recipe.binding.task_id.clone()),
                    revision: CampaignOwnerRevision::Task(
                        recipe
                            .binding
                            .state_fence
                            .task_revision
                            .clone()
                            .expect("fixture fence carries its authenticated task revision"),
                    ),
                    content_digest: digest("authenticated-task-anchor-614"),
                    slot_projection_digests: vec![],
                    recorded_state_fence: recipe.binding.state_fence.clone(),
                })
            } else {
                requirement.expected_reference.clone()
            };
            CampaignSourceResolution {
                role: requirement.role,
                status: if reference.is_some() {
                    CampaignSourceResolutionStatus::Current
                } else {
                    CampaignSourceResolutionStatus::Missing
                },
                reference,
                read_state_fence: recipe.binding.state_fence.clone(),
            }
        })
        .collect();
    let positions: Vec<_> = [
        (CampaignPositionKind::Current, CampaignSourceRole::CurrentPosition),
        (CampaignPositionKind::Experience, CampaignSourceRole::ExperiencePosition),
        (CampaignPositionKind::Adaptation, CampaignSourceRole::AdaptationPosition),
        (CampaignPositionKind::Evaluation, CampaignSourceRole::EvaluationPosition),
        (CampaignPositionKind::EconomicsProgress, CampaignSourceRole::EconomicsProgress),
    ]
    .into_iter()
    .map(|(kind, role)| {
        let source = source_resolutions
            .iter()
            .find(|resolution| resolution.role == role)
            .and_then(|resolution| resolution.reference.as_ref())
            .expect("position source has a current reference");
        CampaignPositionRef {
            kind,
            source_role: role,
            record_id: source.record_id.clone(),
            revision: source.revision.clone(),
            source_content_digest: source.content_digest.clone(),
            position_digest: source.content_digest.clone(),
        }
    })
    .collect();
    let frozen_anchor_digest = source_resolutions
        .iter()
        .find(|resolution| resolution.role == CampaignSourceRole::FrozenAnchor)
        .and_then(|resolution| resolution.reference.as_ref())
        .map(|reference| reference.content_digest.clone())
        .expect("frozen anchor has a current reference");

    let fence = recipe.binding.state_fence.clone();
    let history_handle = artifact("history-plan-handle-614").expect("history handle");
    let plan = RetrievalPlan {
        required_exact_routes: vec![history_handle.clone()],
        optional_routes: vec![],
        execution: RouteExecution {
            order: RouteExecutionOrder::Sequential,
            reason: "bounded fixture route order".to_owned(),
        },
        source_projection_fences: vec![SourceProjectionFence {
            source: recipe.binding.source.owner.clone(),
            fence: fence.clone(),
            expected_revision: None,
        }],
        campaign_experience_query: Some(CampaignExperienceQuery {
            scope: recipe.campaign_id.as_str().to_owned(),
            intent: CampaignIntent::FindPriorSuccess,
            handles: vec![history_handle.clone()],
            filters: "fixture exact handles".to_owned(),
            predicates: "fixture bounded history".to_owned(),
            temporal_and_lineage_range: "fixture task lineage".to_owned(),
            output_mode: CampaignOutputMode::Index,
            budgets: CampaignBudgets {
                max_tokens: 256,
                max_bytes: 4096,
                max_time_ms: 1000,
            },
            fence: fence.clone(),
        }),
        coverage_and_negative_claims: "fixture bounded coverage".to_owned(),
        budget_and_stop_conditions: "fixture bounded stop condition".to_owned(),
        fallback_or_abstention: "fixture abstain when no handle is available".to_owned(),
    };
    let history_plans = [CampaignHistoryPlanInput {
        plan: &plan,
        selected_handles: vec![history_handle.clone()],
        summary_digest: Some(digest("history-summary-614")),
        diff_digests: vec![digest("history-diff-614")],
        policy_slice_handles: vec![history_handle],
    }];
    let current_state_fence = current_state_fence.cloned().unwrap_or(fence);
    compile_campaign_learning_state_view(CampaignLearningStateCompilationInput {
        recipe,
        projections,
        current_state_fence: &current_state_fence,
        source_resolutions: &source_resolutions,
        required_references: refs,
        disagreements,
        positions: &positions,
        frozen_anchor_digest: &frozen_anchor_digest,
        history_plans: &history_plans,
        generated_at_ms: 1_790_208_000_000,
        expires_at_ms: None,
        rebuild_reason: None,
    })
}

#[test]
fn complete_reconstruction_preserves_recipe_member_order_and_canonical_digest() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&recipe, 0, SlotDisposition::Current)?;
    let refs = vec![artifact("ref-z")?, artifact("ref-a")?];
    let view_id = artifact("view-explicit")?;
    let view = compile(
        &mut recipe,
        std::slice::from_ref(&first),
        &refs,
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_ne!(view.view_id, view_id);
    assert!(view
        .view_id
        .as_str()
        .starts_with("campaign-learning-state-view:sha256:"));
    assert_eq!(view.binding.state_fence, recipe.binding.state_fence);
    assert_eq!(
        view.required_references,
        vec![artifact("ref-a")?, artifact("ref-z")?]
    );
    assert_eq!(
        view.slots[0].members[0].member_id,
        recipe.slots[0].declared_members[0]
    );
    assert_eq!(view.required_references[0], artifact("ref-a")?);
    assert!(!view.canonical_digest.is_empty());
    view.validate_against(&recipe)?;
    assert_eq!(view.slots[0], first);
    Ok(())
}

#[test]
fn shared_lineage_and_input_order_are_bound_before_compilation() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![2, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let shared = source("shared", 1)?;
    let second = projection_with_lineage(&recipe, 1, SlotDisposition::Current, &shared)?;
    let first = projection_with_lineage(&recipe, 0, SlotDisposition::Current, &shared)?;
    let before = recipe.canonical_digest.clone();
    let view = compile(&mut recipe,
        &[first.clone(), second.clone()],
        &[artifact("ref-a")?],
    )?;
    let mut expected_first = first.clone();
    let mut expected_second = second.clone();
    for expected in [&mut expected_first, &mut expected_second] {
        expected
            .evidence
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        for member in &mut expected.members {
            member
                .evidence
                .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        }
    }
    assert_eq!(view.slots[0], expected_first);
    assert_eq!(view.slots[1], expected_second);
    let mut reverse_first = first;
    reverse_first.members.reverse();
    reverse_first.evidence.reverse();
    for member in &mut reverse_first.members {
        member.evidence.reverse();
    }
    let mut reverse_second = second;
    reverse_second.members.reverse();
    reverse_second.evidence.reverse();
    for member in &mut reverse_second.members {
        member.evidence.reverse();
    }
    let reversed = compile(&mut recipe,
        &[reverse_second, reverse_first],
        &[artifact("ref-a")?],
    )?;
    let bound_recipe_digest = recipe.canonical_digest.clone();
    assert_ne!(bound_recipe_digest, before);
    assert_eq!(view, reversed);
    assert_eq!(recipe.canonical_digest, bound_recipe_digest);
    assert_eq!(view.slots[0].slot_id, recipe.slots[0].slot_id);
    assert_eq!(view.slots[1].slot_id, recipe.slots[1].slot_id);
    Ok(())
}

#[test]
fn duplicate_slot_and_changed_shared_lineage_fail_closed() -> TestResult {
    let mut base_recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&base_recipe, 0, SlotDisposition::Current)?;
    let duplicate = first.clone();
    assert!(matches!(
        compile(&mut base_recipe, &[first, duplicate], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    let first = projection(&base_recipe, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(&mut base_recipe,
            std::slice::from_ref(&first),
            &[artifact("ref")?, artifact("ref")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    let mut changed = projection(&base_recipe, 0, SlotDisposition::Current)?;
    changed.members[1].source.revision = TaskRevision::new(2)?;
    assert!(matches!(
        compile(&mut base_recipe, &[changed], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    let mut duplicate_member = projection(&base_recipe, 0, SlotDisposition::Current)?;
    let repeated_member = duplicate_member.members[0].clone();
    duplicate_member.members.push(repeated_member);
    assert!(matches!(
        compile(&mut base_recipe, &[duplicate_member], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));

    let mut oversized_dependency = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    oversized_dependency.slots[0].requirement = SlotRequirement::Conditional {
        depends_on: SlotId::from_artifact(artifact(&"d".repeat(MAX_LABEL_BYTES + 1))?),
    };
    oversized_dependency.seal()?;
    let oversized_projection = projection(&oversized_dependency, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(&mut oversized_dependency,
            &[oversized_projection],
            &[artifact("ref")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Bound {
            field: "slot.depends_on"
        })
    ));

    let mut oversized_disagreements = Vec::new();
    for record in 0..=(MAX_EVIDENCE / MAX_RECORD_EVIDENCE) {
        let mut evidence = Vec::new();
        for item in 0..MAX_RECORD_EVIDENCE {
            evidence.push(artifact(&format!("disagreement-{record}-{item}"))?);
        }
        oversized_disagreements.push(OwnerDisagreement {
            slot_id: base_recipe.slots[0].slot_id.clone(),
            owners: vec![base_recipe.slots[0].owner.clone()],
            evidence,
        });
    }
    let base_fence = base_recipe.binding.state_fence.clone();
    assert!(matches!(
        compile_with(
            &mut base_recipe,
            &[],
            &[artifact("ref")?],
            &oversized_disagreements,
            Some(&base_fence),
        ),
        Err(eliot_learning_contracts::LearningContractError::Bound {
            field: "owner_disagreement.evidence"
        })
    ));
    let mut inconsistent = projection(&base_recipe, 0, SlotDisposition::Current)?;
    inconsistent.members[0].disposition = SlotDisposition::Stale;
    assert!(matches!(
        compile(&mut base_recipe, &[inconsistent], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    Ok(())
}

#[test]
fn omission_policy_and_conditional_unknown_remain_explicit() -> TestResult {
    let mut required = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Optional],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    assert!(matches!(
        compile(&mut required, &[], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    let mut frontier = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Optional,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-1")?),
            },
        ],
        vec![1, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let view = compile(&mut frontier, &[], &[artifact("ref")?])?;
    assert_eq!(
        view.frontier,
        frontier
            .slots
            .iter()
            .map(|slot| slot.slot_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(view.completeness, Completeness::Partial);
    view.validate_against(&frontier)?;
    Ok(())
}

#[test]
fn optional_stale_and_explicit_disagreement_are_preserved() -> TestResult {
    let mut base_recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Optional],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let required = projection(&base_recipe, 0, SlotDisposition::Current)?;
    let optional = projection(&base_recipe, 1, SlotDisposition::Stale)?;
    let disagreement = OwnerDisagreement {
        slot_id: base_recipe.slots[1].slot_id.clone(),
        owners: vec![
            OwnerId::from_artifact(artifact("owner-b")?),
            OwnerId::from_artifact(artifact("owner-a")?),
        ],
        evidence: vec![artifact("disagreement-z")?, artifact("disagreement-a")?],
    };
    let view = compile_with(
        &mut base_recipe,
        &[optional.clone(), required],
        &[artifact("ref")?],
        std::slice::from_ref(&disagreement),
        None,
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.slots[1], optional);
    let mut expected_disagreement = disagreement;
    expected_disagreement
        .owners
        .sort_by(|left, right| left.as_str().cmp(right.as_str()));
    expected_disagreement
        .evidence
        .sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(view.owner_disagreements, vec![expected_disagreement]);

    let mut conditional = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Optional,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-1")?),
            },
        ],
        vec![1, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let required = projection(&conditional, 0, SlotDisposition::Current)?;
    let blocked_optional = projection(&conditional, 1, SlotDisposition::Blocked)?;
    let dependent = compile(&mut conditional,
        &[required, blocked_optional.clone()],
        &[artifact("ref")?],
    )?;
    assert_eq!(dependent.completeness, Completeness::Blocked);
    assert_eq!(dependent.slots[1], blocked_optional);
    assert_eq!(
        dependent.frontier,
        vec![conditional.slots[2].slot_id.clone()]
    );
    dependent.validate_against(&conditional)?;
    Ok(())
}

#[test]
fn required_status_precedence_survives_missing_frontier() -> TestResult {
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Required,
            SlotRequirement::Required,
        ],
        vec![1, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let blocked = projection(&recipe, 0, SlotDisposition::Blocked)?;
    let stale = projection(&recipe, 1, SlotDisposition::Stale)?;
    let view = compile(&mut recipe, &[blocked, stale], &[artifact("ref")?])?;
    assert_eq!(view.completeness, Completeness::Blocked);
    assert_eq!(view.frontier, vec![recipe.slots[2].slot_id.clone()]);
    assert_eq!(view.slots[0].disposition, SlotDisposition::Blocked);
    assert_eq!(view.slots[1].disposition, SlotDisposition::Stale);
    Ok(())
}

fn fence_with_sequence(sequence: u64) -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    )
}

// WORK_UNIT_CASE: 614/1
#[test]
fn minimal_complete_recipe_complete_view() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.slots.len(), 1);
    assert!(view.omissions.is_empty());
    assert!(view.frontier.is_empty());
    assert_eq!(view.denominator.declared, 1);
    assert_eq!(view.denominator.observed, 1);
    assert_eq!(view.recipe_digest, recipe.canonical_digest);
    assert!(!view.canonical_digest.is_empty());
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/2
#[test]
fn multi_owner_multi_slot_complete_view() -> TestResult {
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Required,
            SlotRequirement::Required,
        ],
        vec![2, 1, 3],
        OmissionPolicy::RequiredSlots,
    )?;
    let projections = vec![
        projection(&recipe, 0, SlotDisposition::Current)?,
        projection(&recipe, 1, SlotDisposition::Current)?,
        projection(&recipe, 2, SlotDisposition::Current)?,
    ];
    let view = compile(&mut recipe, &projections, &[artifact("ref-1")?])?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.slots.len(), 3);
    assert_eq!(view.denominator.declared, 3);
    assert_eq!(view.denominator.observed, 3);
    for (index, slot) in view.slots.iter().enumerate() {
        assert_eq!(slot.slot_id, recipe.slots[index].slot_id);
        assert_eq!(
            slot.members.len(),
            recipe.slots[index].declared_members.len()
        );
    }
    assert_ne!(recipe.slots[0].owner, recipe.slots[1].owner);
    assert_ne!(recipe.slots[1].owner, recipe.slots[2].owner);
    let replay = compile(&mut recipe, &projections, &[artifact("ref-1")?])?;
    assert_eq!(view, replay);
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/3
#[test]
fn exact_recipe_slot_status_disposition_vocabularies() -> TestResult {
    // Every non-empty disposition spelling round-trips through compilation.
    for disposition in [
        SlotDisposition::Current,
        SlotDisposition::Historical,
        SlotDisposition::Stale,
        SlotDisposition::Superseded,
        SlotDisposition::Unavailable,
        SlotDisposition::Blocked,
        SlotDisposition::Unknown,
        SlotDisposition::Conflicted,
    ] {
        let mut recipe = recipe(
            vec![SlotRequirement::Optional],
            vec![1],
            OmissionPolicy::RequiredSlots,
        )?;
        let supplied = projection(&recipe, 0, disposition)?;
        let view = compile(&mut recipe,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?],
        )?;
        assert_eq!(view.slots[0].disposition, disposition);
        view.validate_against(&recipe)?;
    }
    // KnownEmpty is only expressible against an explicitly empty declared set.
    let mut empty = recipe(
        vec![SlotRequirement::Optional],
        vec![0],
        OmissionPolicy::RequiredSlots,
    )?;
    let known_empty = projection(&empty, 0, SlotDisposition::KnownEmpty)?;
    assert!(known_empty.members.is_empty());
    let view = compile(&mut empty,
        std::slice::from_ref(&known_empty),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.slots[0].disposition, SlotDisposition::KnownEmpty);
    // Requirement and policy spellings stay distinct and usable in one recipe.
    let mixed = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Optional,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-0")?),
            },
        ],
        vec![1, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    assert!(matches!(
        mixed.slots[0].requirement,
        SlotRequirement::Required
    ));
    assert!(matches!(
        mixed.slots[1].requirement,
        SlotRequirement::Optional
    ));
    assert!(matches!(
        mixed.slots[2].requirement,
        SlotRequirement::Conditional { .. }
    ));
    assert_eq!(mixed.omission_policy, OmissionPolicy::ExplicitFrontier);
    let required_only = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    assert_eq!(required_only.omission_policy, OmissionPolicy::RequiredSlots);
    Ok(())
}

// WORK_UNIT_CASE: 614/4
#[test]
fn task_target_scope_fence_recipe_mismatch() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    // A fence from another epoch sequence cannot authorize this recipe binding.
    let other_fence = fence_with_sequence(2);
    assert!(matches!(
        compile_with(
            &mut recipe,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?],
            &[],
            Some(&other_fence),
        ),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // A recipe mutated after sealing no longer validates its own digest.
    let mut tampered = recipe.clone();
    tampered.target = TargetId::new("target-other")?;
    assert!(matches!(
        compile(&mut tampered,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::DigestMismatch { .. })
    ));
    // A view stays bound to its exact recipe: resealing under another privacy
    // class breaks recipe binding even though the slot set is unchanged.
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    let mut other = recipe.clone();
    other.privacy_class = "campaign-wide".to_owned();
    other.seal()?;
    assert!(matches!(
        view.validate_against(&other),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/5
#[test]
fn duplicate_and_same_id_changed_payload_rejected() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&recipe, 0, SlotDisposition::Current)?;
    // Same slot identity twice is a duplicate even when the payload changed.
    let mut changed = first.clone();
    changed.members[0].value_digest = Some(digest("changed-value"));
    changed.evidence.reverse();
    assert!(matches!(
        compile(&mut recipe, &[first.clone(), changed], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    // Same member identity twice inside one projection is a duplicate.
    let mut repeated = first.clone();
    let extra = repeated.members[0].clone();
    repeated.members.push(extra);
    assert!(matches!(
        compile(&mut recipe, &[repeated], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    // Same required reference twice is a duplicate.
    assert!(matches!(
        compile(&mut recipe,
            std::slice::from_ref(&first),
            &[artifact("ref-1")?, artifact("ref-1")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    // Same disagreement slot twice is a duplicate.
    let disagreement = OwnerDisagreement {
        slot_id: recipe.slots[0].slot_id.clone(),
        owners: vec![
            OwnerId::from_artifact(artifact("owner-a")?),
            OwnerId::from_artifact(artifact("owner-b")?),
        ],
        evidence: vec![artifact("disagreement-a")?],
    };
    assert!(matches!(
        compile_with(
            &mut recipe,
            std::slice::from_ref(&first),
            &[artifact("ref-1")?],
            &[disagreement.clone(), disagreement],
            None,
        ),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/6
#[test]
fn exact_current_owner_projection_preserved() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let mut supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    for member in &mut supplied.members {
        member.evidence.reverse();
    }
    supplied.evidence.reverse();
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    let slot = &view.slots[0];
    assert_eq!(slot.disposition, SlotDisposition::Current);
    assert_eq!(slot.members.len(), 2);
    for (index, member) in slot.members.iter().enumerate() {
        assert_eq!(member.member_id, recipe.slots[0].declared_members[index]);
        assert_eq!(member.owner, recipe.slots[0].owner);
        assert_eq!(member.disposition, SlotDisposition::Current);
        assert_eq!(member.value_digest, supplied.members[index].value_digest);
        assert_eq!(member.source, supplied.members[index].source);
        assert_eq!(
            member.projection_revision,
            supplied.members[index].projection_revision
        );
        let mut expected_evidence = supplied.members[index].evidence.clone();
        expected_evidence.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        assert_eq!(member.evidence, expected_evidence);
    }
    Ok(())
}

// WORK_UNIT_CASE: 614/7
#[test]
fn historical_stale_superseded_invalidated_projections() -> TestResult {
    for (disposition, expected) in [
        (SlotDisposition::Historical, Completeness::Partial),
        (SlotDisposition::Stale, Completeness::Stale),
        (SlotDisposition::Superseded, Completeness::Partial),
    ] {
        let mut recipe = recipe(
            vec![SlotRequirement::Required],
            vec![1],
            OmissionPolicy::RequiredSlots,
        )?;
        let supplied = projection(&recipe, 0, disposition)?;
        let view = compile(&mut recipe,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?],
        )?;
        assert_eq!(view.slots[0].disposition, disposition);
        assert_eq!(view.completeness, expected);
        view.validate_against(&recipe)?;
    }
    // Fresh compilations never arrive invalidated; flipping the marker on a
    // complete view breaks recipe coverage instead of sticking.
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let mut view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert!(!view.invalidated);
    assert_eq!(view.invalidation_reason, None);
    view.invalidated = true;
    assert!(matches!(
        view.validate_against(&recipe),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/8
#[test]
fn required_missing_versus_optional_absent() -> TestResult {
    // A missing required slot fails closed; nothing is default-filled.
    let mut required = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    assert!(matches!(
        compile(&mut required, &[], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    // An empty member list cannot stand in for declared owner members either.
    let mut default_filled = projection(&required, 0, SlotDisposition::Current)?;
    default_filled.members.clear();
    assert!(matches!(
        compile(&mut required, &[default_filled], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    // An absent optional slot is recorded as an omission and stays complete.
    let mut mixed = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Optional],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&mixed, 0, SlotDisposition::Current)?;
    let view = compile(&mut mixed,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.omissions, vec![mixed.slots[1].slot_id.clone()]);
    assert!(view.frontier.is_empty());
    view.validate_against(&mixed)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/9
#[test]
fn conditional_required_true_false_unknown() -> TestResult {
    // Predicate true: dependency present, conditional slot required and current.
    let mut satisfied = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-0")?),
            },
        ],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let satisfied_projections = [
        projection(&satisfied, 0, SlotDisposition::Current)?,
        projection(&satisfied, 1, SlotDisposition::Current)?,
    ];
    let view = compile(&mut satisfied, &satisfied_projections, &[artifact("ref-1")?])?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    // Predicate false: dependency present alone, conditional slot waits on the
    // frontier without failing the compilation.
    let mut frontier_recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-0")?),
            },
        ],
        vec![1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let only_dependency = projection(&frontier_recipe, 0, SlotDisposition::Current)?;
    let view = compile(&mut frontier_recipe,
        std::slice::from_ref(&only_dependency),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(
        view.frontier,
        vec![frontier_recipe.slots[1].slot_id.clone()]
    );
    assert_eq!(view.completeness, Completeness::Partial);
    // Predicate unknown: an Unknown conditional slot is partial, never
    // complete-as-empty.
    let mut unknown_recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-0")?),
            },
        ],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let unknown_projections = [
        projection(&unknown_recipe, 0, SlotDisposition::Current)?,
        projection(&unknown_recipe, 1, SlotDisposition::Unknown)?,
    ];
    let view = compile(
        &mut unknown_recipe,
        &unknown_projections,
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.slots[1].disposition, SlotDisposition::Unknown);
    assert_eq!(view.completeness, Completeness::Partial);
    assert_ne!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    view.validate_against(&unknown_recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/10
#[test]
fn unavailable_and_blocked_owner_preserved() -> TestResult {
    for disposition in [SlotDisposition::Unavailable, SlotDisposition::Blocked] {
        let mut recipe = recipe(
            vec![SlotRequirement::Required],
            vec![1],
            OmissionPolicy::RequiredSlots,
        )?;
        let supplied = projection(&recipe, 0, disposition)?;
        let view = compile(&mut recipe,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?],
        )?;
        assert_eq!(view.completeness, Completeness::Blocked);
        assert_eq!(view.slots[0].disposition, disposition);
        assert_eq!(view.slots[0].evidence, supplied.evidence);
        assert_eq!(view.slots[0].members.len(), 1);
        view.validate_against(&recipe)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 614/11
#[test]
fn owner_disagreement_conflict_set_preserved() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&recipe, 0, SlotDisposition::Conflicted)?;
    let second = projection(&recipe, 1, SlotDisposition::Current)?;
    let later = OwnerDisagreement {
        slot_id: recipe.slots[1].slot_id.clone(),
        owners: vec![
            OwnerId::from_artifact(artifact("owner-z")?),
            OwnerId::from_artifact(artifact("owner-a")?),
        ],
        evidence: vec![artifact("conflict-z")?, artifact("conflict-a")?],
    };
    let earlier = OwnerDisagreement {
        slot_id: recipe.slots[0].slot_id.clone(),
        owners: vec![
            OwnerId::from_artifact(artifact("owner-b")?),
            OwnerId::from_artifact(artifact("owner-a")?),
        ],
        evidence: vec![artifact("disagreement-1")?],
    };
    let view = compile_with(
        &mut recipe,
        &[second, first],
        &[artifact("ref-1")?],
        &[later, earlier],
        None,
    )?;
    assert_eq!(view.owner_disagreements.len(), 2);
    assert_eq!(view.owner_disagreements[0].slot_id, recipe.slots[0].slot_id);
    assert_eq!(view.owner_disagreements[1].slot_id, recipe.slots[1].slot_id);
    let owners: Vec<&str> = view.owner_disagreements[0]
        .owners
        .iter()
        .map(OwnerId::as_str)
        .collect();
    assert_eq!(owners, vec!["owner-a", "owner-b"]);
    // Conflict is preserved, never resolved: the view stays partial.
    assert_eq!(view.slots[0].disposition, SlotDisposition::Conflicted);
    assert_eq!(view.completeness, Completeness::Partial);
    // Erasing a disagreement changes the projection: disagreement is material.
    let without_projections = [
        projection(&recipe, 0, SlotDisposition::Conflicted)?,
        projection(&recipe, 1, SlotDisposition::Current)?,
    ];
    let without = compile(&mut recipe,
        &without_projections,
        &[artifact("ref-1")?],
    )?;
    assert_ne!(view.canonical_digest, without.canonical_digest);
    assert!(without.owner_disagreements.is_empty());
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/12
#[test]
fn no_latest_confidence_majority_selection() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![3],
        OmissionPolicy::RequiredSlots,
    )?;
    let mut first = projection(&recipe, 0, SlotDisposition::Conflicted)?;
    // Distinct rival values stay side by side; the duplicated value does not win.
    first.members[0].value_digest = Some(digest("rival-alpha"));
    first.members[1].value_digest = Some(digest("rival-beta"));
    first.members[2].value_digest = Some(digest("rival-beta"));
    let mut second = first.clone();
    second.members.reverse();
    second.evidence.reverse();
    let view = compile(&mut recipe, std::slice::from_ref(&first), &[artifact("ref-1")?])?;
    let reordered = compile(&mut recipe,
        std::slice::from_ref(&second),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view, reordered);
    assert_eq!(view.slots[0].members.len(), 3);
    let digests: Vec<String> = view.slots[0]
        .members
        .iter()
        .filter_map(|member| member.value_digest.clone())
        .collect();
    assert!(digests.contains(&digest("rival-alpha")));
    assert!(digests.contains(&digest("rival-beta")));
    assert_eq!(view.slots[0].disposition, SlotDisposition::Conflicted);
    assert_eq!(view.completeness, Completeness::Partial);
    Ok(())
}

// WORK_UNIT_CASE: 614/13
#[test]
fn transcript_substitution_rejected() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    // A conversational fragment with an undeclared slot identity cannot join.
    let mut fragment = supplied.clone();
    fragment.slot_id = SlotId::from_artifact(artifact("transcript-fragment")?);
    assert!(matches!(
        compile(&mut recipe,
            &[supplied.clone(), fragment],
            &[artifact("ref-1")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // Another owner's identity cannot stand in for the declared slot owner.
    let mut substituted = supplied.clone();
    substituted.members[0].owner = OwnerId::from_artifact(artifact("owner-impostor")?);
    assert!(matches!(
        compile(&mut recipe, &[substituted], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // An absent owner value stays missing; nothing substitutes for it.
    assert!(matches!(
        compile(&mut recipe, &[], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/14
#[test]
fn source_revision_digest_provenance_mismatch() -> TestResult {
    let mut pair = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    // Malformed digests never enter the view.
    let mut single = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let mut malformed = projection(&single, 0, SlotDisposition::Current)?;
    malformed.members[0].source.digest = "not-a-digest".to_owned();
    assert!(matches!(
        compile(&mut single, &[malformed], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::InvalidDigest { .. })
    ));
    // Same owner/snapshot key with divergent lineage is a provenance conflict.
    let mut forked = projection(&pair, 0, SlotDisposition::Current)?;
    forked.members[1].source.digest = digest("forked-source");
    assert!(matches!(
        compile(&mut pair, &[forked], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // Same key with a bumped revision clock is the same conflict.
    let mut revised = projection(&pair, 0, SlotDisposition::Current)?;
    revised.members[1].source.revision = TaskRevision::new(2)?;
    assert!(matches!(
        compile(&mut pair, &[revised], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/15
#[test]
fn privacy_authority_effect_proof_exclusion_visible() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let blocked = projection(&recipe, 0, SlotDisposition::Blocked)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&blocked),
        &[artifact("ref-1")?],
    )?;
    // Excluded material stays in the view with its reason and evidence.
    assert_eq!(view.slots.len(), 1);
    assert_eq!(view.slots[0].disposition, SlotDisposition::Blocked);
    assert_eq!(view.slots[0].evidence, blocked.evidence);
    assert_eq!(view.completeness, Completeness::Blocked);
    // Caller privacy boundary and candidate-only ceiling travel with the view.
    assert_eq!(recipe.privacy_class, "task-local");
    assert_eq!(view.binding, recipe.binding);
    assert_eq!(
        view.binding.proof_ceiling,
        eliot_learning_contracts::ProofCeiling::CandidateArtifact
    );
    // An empty privacy class is rejected instead of defaulted.
    let mut exposed = recipe.clone();
    exposed.privacy_class = String::new();
    assert!(matches!(
        compile(&mut exposed, &[blocked], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Missing { .. })
    ));
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/16
#[test]
fn required_interpretation_dependency_present_or_missing() -> TestResult {
    // Present dependency chain compiles complete.
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-0")?),
            },
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-1")?),
            },
        ],
        vec![1, 1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let complete_projections = [
        projection(&recipe, 0, SlotDisposition::Current)?,
        projection(&recipe, 1, SlotDisposition::Current)?,
        projection(&recipe, 2, SlotDisposition::Current)?,
    ];
    let view = compile(&mut recipe, &complete_projections, &[artifact("ref-1")?])?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    // Depending on an undeclared slot is a scope error, not an optional edge.
    let mut missing = recipe.clone();
    missing.slots[2].requirement = SlotRequirement::Conditional {
        depends_on: SlotId::from_artifact(artifact("slot-9")?),
    };
    missing.seal()?;
    let projections = vec![
        projection(&missing, 0, SlotDisposition::Current)?,
        projection(&missing, 1, SlotDisposition::Current)?,
        projection(&missing, 2, SlotDisposition::Current)?,
    ];
    assert!(matches!(
        compile(&mut missing, &projections, &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // A dependency cycle fails closed as well.
    let mut cyclic = recipe.clone();
    cyclic.slots[0].requirement = SlotRequirement::Conditional {
        depends_on: SlotId::from_artifact(artifact("slot-2")?),
    };
    cyclic.seal()?;
    assert!(matches!(
        compile(&mut cyclic, &projections, &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/17
#[test]
fn complete_source_and_recipe_denominators() -> TestResult {
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Required,
            SlotRequirement::Optional,
        ],
        vec![2, 1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let current_projections = [
        projection(&recipe, 0, SlotDisposition::Current)?,
        projection(&recipe, 1, SlotDisposition::Current)?,
    ];
    let view = compile(&mut recipe, &current_projections, &[artifact("ref-1")?])?;
    // Declared counts every recipe slot; observed counts represented slots only.
    assert_eq!(view.denominator.declared, 3);
    assert_eq!(view.denominator.observed, 2);
    assert_eq!(view.omissions.len(), 1);
    view.denominator.validate()?;
    // Denominators are never inferred: over-observation and empty declaration fail.
    let over = eliot_learning_contracts::SourceDenominator {
        declared: 2,
        observed: 3,
    };
    assert!(matches!(
        over.validate(),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    let empty = eliot_learning_contracts::SourceDenominator {
        declared: 0,
        observed: 0,
    };
    assert!(matches!(
        empty.validate(),
        Err(eliot_learning_contracts::LearningContractError::Missing { .. })
    ));
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/18
#[test]
fn known_empty_against_unavailable_partial_unknown() -> TestResult {
    // Affirmative empty over an explicitly empty declared set is complete.
    let mut declared = recipe(
        vec![SlotRequirement::Required],
        vec![0],
        OmissionPolicy::RequiredSlots,
    )?;
    let empty = projection(&declared, 0, SlotDisposition::KnownEmpty)?;
    let view = compile(&mut declared,
        std::slice::from_ref(&empty),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    // Unknown is partial evidence, never an empty declaration.
    let mut unknown = empty.clone();
    unknown.disposition = SlotDisposition::Unknown;
    let view = compile(&mut declared,
        std::slice::from_ref(&unknown),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.completeness, Completeness::Partial);
    // Unevidenced emptiness and emptiness over declared members both fail.
    let mut bare = empty.clone();
    bare.evidence.clear();
    assert!(matches!(
        compile(&mut declared, &[bare], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::MissingOwnerEvidence { .. })
    ));
    let mut full = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let mut nonempty = projection(&full, 0, SlotDisposition::Current)?;
    nonempty.disposition = SlotDisposition::KnownEmpty;
    assert!(matches!(
        compile(&mut full, &[nonempty], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    // Unavailable stays blocked, distinct from empty and partial.
    let mut unavailable = projection(&full, 0, SlotDisposition::Current)?;
    unavailable.disposition = SlotDisposition::Unavailable;
    for member in &mut unavailable.members {
        member.disposition = SlotDisposition::Unavailable;
    }
    let view = compile(&mut full,
        std::slice::from_ref(&unavailable),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.completeness, Completeness::Blocked);
    Ok(())
}

// WORK_UNIT_CASE: 614/19
#[test]
fn unexpected_and_duplicate_projection_disposition() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    // A projection outside the declared denominator is rejected outright.
    let mut stranger = supplied.clone();
    stranger.slot_id = SlotId::from_artifact(artifact("slot-9")?);
    assert!(matches!(
        compile(&mut recipe, &[stranger.clone()], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // The frontier excuses declared slots only; strangers stay rejected.
    assert!(matches!(
        compile(&mut recipe,
            &[supplied.clone(), stranger],
            &[artifact("ref-1")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // A duplicate delivery of the same declared slot is rejected.
    assert!(matches!(
        compile(&mut recipe,
            &[supplied.clone(), supplied],
            &[artifact("ref-1")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    // A declared-but-absent required slot lands on the frontier instead.
    let view = compile(&mut recipe, &[], &[artifact("ref-1")?])?;
    assert_eq!(view.frontier, vec![recipe.slots[0].slot_id.clone()]);
    assert_eq!(view.completeness, Completeness::Partial);
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/20
#[test]
fn exact_structural_filter_and_visible_exclusion() -> TestResult {
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Optional,
            SlotRequirement::Optional,
        ],
        vec![1, 1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    // Omitted optionals are named in omissions; supplied ones stay visible.
    let required = projection(&recipe, 0, SlotDisposition::Current)?;
    let excluded = projection(&recipe, 2, SlotDisposition::Blocked)?;
    let view = compile(&mut recipe, &[required, excluded], &[artifact("ref-1")?])?;
    assert_eq!(view.omissions, vec![recipe.slots[1].slot_id.clone()]);
    assert!(view.frontier.is_empty());
    assert_eq!(view.slots.len(), 2);
    assert_eq!(view.slots[0].slot_id, recipe.slots[0].slot_id);
    assert_eq!(view.slots[1].slot_id, recipe.slots[2].slot_id);
    assert_eq!(view.slots[1].disposition, SlotDisposition::Blocked);
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    // Nothing is silently dropped: every declared slot is represented exactly once.
    assert_eq!(
        view.slots.len() + view.omissions.len() + view.frontier.len(),
        3
    );
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/21
#[test]
fn item_byte_exact_fit_and_one_over() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    // Byte ceiling: the maximum label fits, one byte more does not.
    let mut fitting = recipe.clone();
    fitting.slots[0].accepted_type = "a".repeat(eliot_learning_state_view::MAX_LABEL_BYTES);
    fitting.seal()?;
    let supplied = projection(&fitting, 0, SlotDisposition::Current)?;
    compile(&mut fitting,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    let mut overflowing = recipe.clone();
    overflowing.slots[0].accepted_type = "a".repeat(eliot_learning_state_view::MAX_LABEL_BYTES + 1);
    overflowing.seal()?;
    let supplied = projection(&overflowing, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(&mut overflowing, &[supplied], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Bound { .. })
    ));
    // Item ceiling: maximum slot evidence fits, one handle more does not.
    let mut exact = projection(&recipe, 0, SlotDisposition::Current)?;
    exact.evidence.clear();
    for index in 0..eliot_learning_state_view::MAX_RECORD_EVIDENCE {
        exact
            .evidence
            .push(artifact(&format!("slot-evidence-{index:04}"))?);
    }
    compile(&mut recipe, std::slice::from_ref(&exact), &[artifact("ref-1")?])?;
    let mut over = exact.clone();
    over.evidence.push(artifact("slot-evidence-over")?);
    assert!(matches!(
        compile(&mut recipe, &[over], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Bound { .. })
    ));
    // Reference ceiling: maximum references fit, one more does not.
    let mut refs = Vec::new();
    for index in 0..eliot_learning_state_view::MAX_REFERENCES {
        refs.push(artifact(&format!("ref-{index:04}"))?);
    }
    let fitting_projection = projection(&recipe, 0, SlotDisposition::Current)?;
    compile(
        &mut recipe,
        std::slice::from_ref(&fitting_projection),
        &refs,
    )?;
    refs.push(artifact("ref-over")?);
    let over_projection = projection(&recipe, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(&mut recipe,
            std::slice::from_ref(&over_projection),
            &refs
        ),
        Err(eliot_learning_contracts::LearningContractError::Bound { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/22
#[test]
fn cursor_binds_snapshot_recipe_query_rejects_stale() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    // The view cursor pins the exact recipe digest and fence it was built from.
    assert_eq!(view.recipe_digest, recipe.canonical_digest);
    assert_eq!(view.binding.state_fence, recipe.binding.state_fence);
    // A stale recipe cursor (resealed denominator) no longer admits the view.
    let mut stale = recipe.clone();
    stale.privacy_class = "campaign-wide".to_owned();
    stale.seal()?;
    assert_ne!(stale.canonical_digest, recipe.canonical_digest);
    assert!(matches!(
        view.validate_against(&stale),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // A stale view cursor (rewritten digest) fails digest validation.
    let mut rewritten = view.clone();
    rewritten.canonical_digest = digest("rewritten-cursor");
    assert!(matches!(
        rewritten.validate_against(&recipe),
        Err(eliot_learning_contracts::LearningContractError::DigestMismatch { .. })
    ));
    // A wrong fence cursor cannot compile the same recipe payload.
    let other_fence = fence_with_sequence(7);
    assert!(matches!(
        compile_with(
            &mut recipe,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?],
            &[],
            Some(&other_fence),
        ),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/23
#[test]
fn bound_cutting_required_slot_yields_partial() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.completeness, Completeness::Partial);
    assert_ne!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.frontier, vec![recipe.slots[1].slot_id.clone()]);
    assert_eq!(view.denominator.declared, 2);
    assert_eq!(view.denominator.observed, 1);
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/24
#[test]
fn deterministic_ordering_under_randomized_input_order() -> TestResult {
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Required,
            SlotRequirement::Required,
        ],
        vec![2, 1, 2],
        OmissionPolicy::RequiredSlots,
    )?;
    let projections = vec![
        projection(&recipe, 0, SlotDisposition::Current)?,
        projection(&recipe, 1, SlotDisposition::Current)?,
        projection(&recipe, 2, SlotDisposition::Current)?,
    ];
    let baseline = compile(&mut recipe, &projections, &[artifact("ref-1")?])?;
    for order in [[2, 1, 0], [1, 2, 0], [2, 0, 1], [1, 0, 2]] {
        let shuffled = vec![
            projections[order[0]].clone(),
            projections[order[1]].clone(),
            projections[order[2]].clone(),
        ];
        let view = compile(&mut recipe, &shuffled, &[artifact("ref-1")?])?;
        assert_eq!(view, baseline);
    }
    // Recipe declaration order, not arrival order, fixes view order.
    assert_eq!(baseline.slots[0].slot_id, recipe.slots[0].slot_id);
    assert_eq!(baseline.slots[1].slot_id, recipe.slots[1].slot_id);
    assert_eq!(baseline.slots[2].slot_id, recipe.slots[2].slot_id);
    Ok(())
}

// WORK_UNIT_CASE: 614/25
#[test]
fn source_to_view_exact_value_digest_equality() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(view.recipe_id, recipe.recipe_id);
    assert_eq!(view.campaign_id, recipe.campaign_id);
    assert_eq!(view.target, recipe.target);
    assert_eq!(view.binding, recipe.binding);
    assert_eq!(view.recipe_digest, recipe.canonical_digest);
    assert_eq!(view.slots.len(), 1);
    for (index, member) in view.slots[0].members.iter().enumerate() {
        let origin = &supplied.members[index];
        assert_eq!(member.member_id, origin.member_id);
        assert_eq!(member.owner, origin.owner);
        assert_eq!(member.source.owner, origin.source.owner);
        assert_eq!(member.source.snapshot, origin.source.snapshot);
        assert_eq!(member.source.revision, origin.source.revision);
        assert_eq!(member.source.digest, origin.source.digest);
        assert_eq!(member.value_digest, origin.value_digest);
        assert_eq!(member.projection_revision, origin.projection_revision);
    }
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/26
#[test]
fn manufactured_unowned_view_entry_rejected() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    // A member minted by an undeclared owner cannot join the declared slot.
    let mut impostor = projection(&recipe, 0, SlotDisposition::Current)?;
    impostor.members[0].owner = OwnerId::from_artifact(artifact("owner-impostor")?);
    assert!(matches!(
        compile(&mut recipe, &[impostor], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // Members match the declared set exactly: duplicates are not members.
    let mut extra = projection(&recipe, 0, SlotDisposition::Current)?;
    let repeated = extra.members[0].clone();
    extra.members.push(repeated);
    assert!(matches!(
        compile(&mut recipe, &[extra], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    // Dropped members leave the coverage incomplete.
    let mut dropped = projection(&recipe, 0, SlotDisposition::Current)?;
    dropped.members.remove(0);
    assert!(matches!(
        compile(&mut recipe, &[dropped], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    // A current member without a value identity is not admissible.
    let mut valueless = projection(&recipe, 0, SlotDisposition::Current)?;
    valueless.members[0].value_digest = None;
    assert!(matches!(
        compile(&mut recipe, &[valueless], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Missing { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/27
#[test]
fn exact_replay_and_changed_same_id_conflict() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let first = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    let second = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(first, second);
    assert_eq!(first.canonical_digest, second.canonical_digest);
    // Same view identity with changed owner values produces a different view,
    // never an alias of the earlier compilation.
    let mut changed = supplied.clone();
    changed.members[0].value_digest = Some(digest("changed-same-id"));
    let replay = compile(&mut recipe,
        std::slice::from_ref(&changed),
        &[artifact("ref-1")?],
    )?;
    assert_ne!(replay.canonical_digest, first.canonical_digest);
    // The earlier view no longer validates once the recipe itself changed.
    let mut evolved = recipe.clone();
    evolved.slots[0].owner = OwnerId::from_artifact(artifact("owner-next")?);
    evolved.seal()?;
    assert!(matches!(
        first.validate_against(&evolved),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/28
#[test]
fn no_newly_issued_transition_or_outcome_fields() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    // Exhaustive field accounting: adding an issued-transition field breaks this.
    let CampaignLearningStateView {
        view_id,
        recipe_id,
        campaign_id,
        target,
        binding,
        recipe_digest,
        provenance,
        slots,
        denominator,
        completeness,
        omissions,
        frontier,
        owner_disagreements,
        required_references,
        invalidated,
        invalidation_reason,
        canonical_digest,
    } = view.clone();
    assert!(view_id
        .as_str()
        .starts_with("campaign-learning-state-view:sha256:"));
    assert_eq!(recipe_id, recipe.recipe_id);
    assert_eq!(campaign_id, recipe.campaign_id);
    assert_eq!(target, recipe.target);
    assert_eq!(binding, recipe.binding);
    assert_eq!(recipe_digest, recipe.canonical_digest);
    assert_eq!(provenance.source_resolutions.len(), CampaignSourceRole::all().len());
    assert_eq!(provenance.positions.len(), 5);
    assert_eq!(slots.len(), 1);
    assert_eq!(denominator, view.denominator);
    assert_eq!(completeness, Completeness::CompleteForDeclaredRecipe);
    assert!(omissions.is_empty());
    assert!(frontier.is_empty());
    assert!(owner_disagreements.is_empty());
    assert_eq!(required_references, vec![artifact("ref-1")?]);
    assert!(!invalidated);
    assert_eq!(invalidation_reason, None);
    assert!(!canonical_digest.is_empty());
    // Provenance names a few owner record families (such as outcomes and
    // delivery), but the view still carries no issued transition fields.
    let rendered = format!("{view:?}").to_lowercase();
    for forbidden in [
        "delta",
        "activation",
        "promotion",
        "finish",
        "transcript",
    ] {
        assert!(!rendered.contains(forbidden), "view leaks {forbidden}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 614/29
#[test]
fn bounded_malformed_property_input_never_panics() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    // Blank view identity is rejected at the foundation boundary itself.
    assert!(artifact("   ").is_err());
    // An empty reference set cannot back a view.
    assert!(matches!(
        compile(&mut recipe, std::slice::from_ref(&supplied), &[]),
        Err(eliot_learning_contracts::LearningContractError::Missing { .. })
    ));
    // A malformed schema digest fails before any projection is read.
    let mut tampered = recipe.clone();
    tampered.slots[0].schema_digest = "zz".to_owned();
    assert!(matches!(
        compile(&mut tampered,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::InvalidDigest { .. })
    ));
    // An oversized label fails on its bound.
    let mut oversized = recipe.clone();
    oversized.slots[0].accepted_type = "b".repeat(eliot_learning_state_view::MAX_LABEL_BYTES + 1);
    oversized.seal()?;
    let over_projection = projection(&oversized, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(&mut oversized, &[over_projection], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Bound { .. })
    ));
    // Unknown slot identities and empty recipes fail closed.
    let mut stranger = supplied.clone();
    stranger.slot_id = SlotId::from_artifact(artifact("slot-9")?);
    assert!(matches!(
        compile(&mut recipe, &[stranger], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    let mut empty_recipe = recipe.clone();
    empty_recipe.slots.clear();
    empty_recipe.seal()?;
    assert!(matches!(
        compile(&mut empty_recipe, &[], &[artifact("ref-1")?]),
        Err(eliot_learning_contracts::LearningContractError::Missing { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 614/30
#[test]
fn every_member_has_exactly_one_disposition() -> TestResult {
    let mut recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Optional,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-0")?),
            },
        ],
        vec![2, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let required = projection(&recipe, 0, SlotDisposition::Current)?;
    let optional = projection(&recipe, 1, SlotDisposition::Stale)?;
    let view = compile(&mut recipe, &[required, optional], &[artifact("ref-1")?])?;
    // Partition: each declared slot appears exactly once across the three sets.
    let mut accounted = std::collections::BTreeSet::new();
    for slot in view
        .slots
        .iter()
        .map(|slot| slot.slot_id.as_str())
        .chain(view.omissions.iter().map(SlotId::as_str))
        .chain(view.frontier.iter().map(SlotId::as_str))
    {
        assert!(accounted.insert(slot), "slot accounted twice");
    }
    assert_eq!(accounted.len(), recipe.slots.len());
    assert_eq!(view.frontier, vec![recipe.slots[2].slot_id.clone()]);
    // Every represented slot and member carries one explicit disposition.
    for slot in &view.slots {
        assert!(matches!(
            slot.disposition,
            SlotDisposition::Current
                | SlotDisposition::Historical
                | SlotDisposition::Stale
                | SlotDisposition::Superseded
                | SlotDisposition::Unavailable
                | SlotDisposition::Blocked
                | SlotDisposition::Unknown
                | SlotDisposition::Conflicted
                | SlotDisposition::KnownEmpty
        ));
        for member in &slot.members {
            assert!(matches!(
                member.disposition,
                SlotDisposition::Current
                    | SlotDisposition::Historical
                    | SlotDisposition::Stale
                    | SlotDisposition::Superseded
                    | SlotDisposition::Unavailable
                    | SlotDisposition::Blocked
                    | SlotDisposition::Unknown
                    | SlotDisposition::Conflicted
                    | SlotDisposition::KnownEmpty
            ));
        }
    }
    assert_eq!(
        view.slots
            .iter()
            .map(|slot| slot.members.len())
            .sum::<usize>(),
        3
    );
    view.validate_against(&recipe)?;
    Ok(())
}

// WORK_UNIT_CASE: 614/31
#[test]
fn complete_implies_current_allowed_required_slots() -> TestResult {
    let mut pair = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let pair_projections = pair
        .slots
        .iter()
        .enumerate()
        .map(|(index, _)| projection(&pair, index, SlotDisposition::Current))
        .collect::<Result<Vec<_>, _>>()?;
    let view = compile(&mut pair, &pair_projections, &[artifact("ref-1")?])?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    for slot in &view.slots {
        assert_eq!(slot.disposition, SlotDisposition::Current);
        for member in &slot.members {
            assert_eq!(member.disposition, SlotDisposition::Current);
        }
    }
    // Any non-current required disposition withholds completeness.
    for disposition in [
        SlotDisposition::Historical,
        SlotDisposition::Stale,
        SlotDisposition::Superseded,
        SlotDisposition::Unavailable,
        SlotDisposition::Blocked,
        SlotDisposition::Unknown,
        SlotDisposition::Conflicted,
    ] {
        let mut single = recipe(
            vec![SlotRequirement::Required],
            vec![1],
            OmissionPolicy::RequiredSlots,
        )?;
        let supplied = projection(&single, 0, disposition)?;
        let view = compile(&mut single,
            std::slice::from_ref(&supplied),
            &[artifact("ref-1")?],
        )?;
        assert_ne!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    }
    Ok(())
}

// WORK_UNIT_CASE: 614/32
#[test]
fn changing_owner_source_fence_recipe_invalidates_digest() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let baseline = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    // Changed slot owner reseals to a new recipe and a new view digest.
    let mut next_owner = recipe.clone();
    let next_owner_id = OwnerId::from_artifact(artifact("owner-next")?);
    let changed_role = next_owner.slots[0].source_role;
    next_owner.slots[0].owner = next_owner_id.clone();
    let changed_requirement = next_owner
        .source_requirements
        .iter_mut()
        .find(|requirement| requirement.role == changed_role)
        .expect("changed slot source is declared");
    changed_requirement.owner = next_owner_id.clone();
    changed_requirement
        .expected_reference
        .as_mut()
        .expect("changed slot source has an exact reference")
        .owner = next_owner_id;
    next_owner.seal()?;
    let owner_projection = projection(&next_owner, 0, SlotDisposition::Current)?;
    let view = compile(&mut next_owner,
        std::slice::from_ref(&owner_projection),
        &[artifact("ref-1")?],
    )?;
    assert_ne!(view.canonical_digest, baseline.canonical_digest);
    assert!(matches!(
        baseline.validate_against(&next_owner),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    // Changed source revision reseals the lineage and the view digest.
    let lineage = source("slot-0", 2)?;
    let revised = projection_with_lineage(&recipe, 0, SlotDisposition::Current, &lineage)?;
    let view = compile(&mut recipe,
        std::slice::from_ref(&revised),
        &[artifact("ref-1")?],
    )?;
    assert_ne!(view.canonical_digest, baseline.canonical_digest);
    // Changed fence and reference set each move the content-derived digest.
    let mut next_fence = recipe.clone();
    next_fence.binding.state_fence = fence_with_sequence(3);
    next_fence.binding.state_fence.task_revision =
        recipe.binding.state_fence.task_revision.clone();
    next_fence.seal()?;
    let fence_projection = projection(&next_fence, 0, SlotDisposition::Current)?;
    let view = compile(
        &mut next_fence,
        std::slice::from_ref(&fence_projection),
        &[artifact("ref-1")?],
    )?;
    assert_ne!(view.canonical_digest, baseline.canonical_digest);
    let same_content = compile(
        &mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(same_content.canonical_digest, baseline.canonical_digest);
    assert_eq!(same_content.view_id, baseline.view_id);
    let relabeled = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?, artifact("ref-2")?],
    )?;
    assert_ne!(relabeled.canonical_digest, baseline.canonical_digest);
    Ok(())
}

// WORK_UNIT_CASE: 614/33
#[test]
fn every_projected_value_equals_supplied_owner_value() -> TestResult {
    let mut recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![2, 2],
        OmissionPolicy::RequiredSlots,
    )?;
    let projections = vec![
        projection(&recipe, 0, SlotDisposition::Current)?,
        projection(&recipe, 1, SlotDisposition::Current)?,
    ];
    let view = compile(&mut recipe, &projections, &[artifact("ref-1")?])?;
    let mut supplied_values = std::collections::BTreeSet::new();
    for projection in &projections {
        for member in &projection.members {
            supplied_values.insert((
                member.member_id.as_str(),
                member.owner.as_str(),
                member.source.digest.as_str(),
                member.value_digest.clone(),
            ));
        }
    }
    let mut observed = 0;
    for slot in &view.slots {
        for member in &slot.members {
            observed += 1;
            assert!(supplied_values.contains(&(
                member.member_id.as_str(),
                member.owner.as_str(),
                member.source.digest.as_str(),
                member.value_digest.clone(),
            )));
        }
    }
    assert_eq!(observed, 4);
    assert_eq!(observed, supplied_values.len());
    Ok(())
}

// WORK_UNIT_CASE: 614/34
#[test]
fn no_store_clock_transcript_provider_mutation_path() -> TestResult {
    // The compiler source admits no I/O, clock, store, transcript, model or
    // provider vocabulary and no interior mutability.
    const SOURCE: &str = include_str!("../src/lib.rs");
    for forbidden in [
        "std::fs",
        "std::net",
        "std::io",
        "std::process",
        "SystemTime",
        "Instant",
        "tokio",
        "reqwest",
        "hyper",
        "provider",
        "Provider",
        "transcript",
        "Transcript",
        "socket",
        "http",
        "Mutex",
        "RwLock",
        "Atomic",
        "env::",
        "Store",
        "Model",
        "clock",
        "Clock",
        "Cell<",
        "RefCell",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "compiler references {forbidden}"
        );
    }
    // Pure shared borrows only: identical inputs compile identically with
    // inputs intact, which a clock, store read or mutation would break.
    let mut recipe = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    let supplied = projection(&recipe, 0, SlotDisposition::Current)?;
    let digest_before = recipe.canonical_digest.clone();
    let first = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    let second = compile(&mut recipe,
        std::slice::from_ref(&supplied),
        &[artifact("ref-1")?],
    )?;
    assert_eq!(first, second);
    assert_eq!(recipe.canonical_digest, digest_before);
    assert_eq!(supplied.members.len(), 1);
    Ok(())
}
