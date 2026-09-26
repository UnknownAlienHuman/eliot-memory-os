//! Governed local overlay admission proof for issue #1864, item A2.
//!
//! A proposed overlay that attempts to alter a sealed holdout,
//! authority/privacy ceiling, task finish condition, or task budget is
//! rejected before activation (partial, surfaces-only proof; see S218/S218b/S220).
//!
//! Rejection is proven at the admit stage (or earlier, at compose for shapes
//! the composer cannot represent). No test in this file activates an overlay:
//! this crate owns no activation path, so the tests call only
//! `compose_campaign_harness_overlay`, `admit_local`, and
//! `admit_local_with_refs`.

#![allow(clippy::expect_used)]

use eliot_agent_contracts::TargetId;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignActiveOverlayPolicy, CampaignHistoryPlanReference,
    CampaignId, CampaignLearningStateProvenance, CampaignLearningStateView, CampaignOwnerRecordId,
    CampaignOwnerRevision, CampaignPositionKind, CampaignPositionRef, CampaignSlotProjectionDigest,
    CampaignSourceBinding, CampaignSourceRequirement, CampaignSourceResolution,
    CampaignSourceResolutionStatus, CampaignSourceRevisionRef, CampaignSourceRole, ChangeOperation,
    ChangeSurface, Completeness, ContractBinding, InverseChange, LearningContractError,
    LearningStateViewRecipe, OmissionPolicy, OwnerId, ProofCeiling, SlotDisposition, SlotId,
    SlotProjection, SlotRequirement, SlotSpec, SourceDenominator,
    TASK_CONTROLLER_CAMPAIGN_OWNER_ID, ValueState,
};
use eliot_learning_overlay::OverlayError;
use eliot_learning_overlay::{
    AdmittedDeltaPair, FrozenPreEvaluation, OverlayComposeInput,
    admission::{AuthoritativeRefs, admit_local, admit_local_with_refs},
    compose_campaign_harness_overlay,
};

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn binding() -> ContractBinding {
    let mut fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    );
    fence.task_revision = Some(TaskRevision::genesis());
    fence.policy_revision = Some(PolicyRevision::genesis());
    ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new("request-1864").expect("request"),
        operation_id: OperationId::new("operation-1864").expect("operation"),
        product_id: ProductId::new("eliot").expect("product"),
        task_id: TaskId::new("task-1864").expect("task"),
        scope: eliot_learning_contracts::WorkScopeId::new("scope-1864").expect("scope"),
        state_fence: fence,
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new("source-1864").expect("source"),
            snapshot: aid("snapshot-1864"),
            revision: TaskRevision::genesis(),
            digest: digest("source"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

struct Fixture {
    recipe: LearningStateViewRecipe,
    view: CampaignLearningStateView,
    target: TargetId,
    discriminator: ArtifactId,
    frozen: FrozenPreEvaluation,
}

fn owner_revision(
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
        | CampaignSourceRole::TaskFamilyHarness => {
            CampaignOwnerRevision::ResourceGeneration(binding.state_fence.resource_generation)
        }
        CampaignSourceRole::FrozenAnchor | CampaignSourceRole::ArtifactProjection => {
            CampaignOwnerRevision::ResourceSnapshot(content_digest.to_owned())
        }
        _ => CampaignOwnerRevision::Counter(1),
    }
}

/// One exact current resolution for every recipe source role. The recipe
/// manifest and the view provenance must agree role-for-role, so both are built
/// from this single closed role list.
fn campaign_source_contract(
    tag: &str,
    binding: &ContractBinding,
) -> (
    Vec<CampaignSourceRequirement>,
    CampaignLearningStateProvenance,
) {
    let roles = [
        (CampaignSourceRole::TaskObjective, "task-objective"),
        (CampaignSourceRole::TaskAcceptance, "task-acceptance"),
        (CampaignSourceRole::TaskPlan, "task-plan"),
        (CampaignSourceRole::TaskOpenItems, "task-open-items"),
        (
            CampaignSourceRole::AttemptLineageLatestOutcomes,
            "attempt-lineage-outcomes",
        ),
        (CampaignSourceRole::GovernorAdmission, "governor-admission"),
        (CampaignSourceRole::GovernorEpoch, "governor-epoch"),
        (CampaignSourceRole::GovernorPolicy, "governor-policy"),
        (CampaignSourceRole::ContextRecipe, "context-recipe"),
        (CampaignSourceRole::ContextToolPolicy, "context-tool-policy"),
        (CampaignSourceRole::ContextDelivery, "context-delivery"),
        (CampaignSourceRole::EvaluatorContract, "evaluator-contract"),
        (CampaignSourceRole::EvaluatorHoldout, "evaluator-holdout"),
        (CampaignSourceRole::EvaluationResults, "evaluation-results"),
        (CampaignSourceRole::MemoryProjection, "memory-projection"),
        (
            CampaignSourceRole::ExperienceProjection,
            "experience-projection",
        ),
        (
            CampaignSourceRole::ArtifactProjection,
            "artifact-projection",
        ),
        (CampaignSourceRole::FrozenAnchor, "frozen-anchor"),
        (CampaignSourceRole::StableHarness, "stable-harness"),
        (CampaignSourceRole::TaskFamilyHarness, "task-family-harness"),
        (CampaignSourceRole::ActiveOverlay, "active-overlay"),
        (CampaignSourceRole::CurrentPosition, "current-position"),
        (
            CampaignSourceRole::ExperiencePosition,
            "experience-position",
        ),
        (
            CampaignSourceRole::AdaptationPosition,
            "adaptation-position",
        ),
        (
            CampaignSourceRole::EvaluationPosition,
            "evaluation-position",
        ),
        (CampaignSourceRole::EconomicsProgress, "economics-progress"),
    ];
    let mut source_requirements = Vec::with_capacity(roles.len());
    let mut source_resolutions = Vec::with_capacity(roles.len());
    for (role, label) in roles {
        let task_anchor = role == CampaignSourceRole::TaskPlan;
        let owner = if task_anchor {
            OwnerId::from_artifact(aid(TASK_CONTROLLER_CAMPAIGN_OWNER_ID))
        } else {
            OwnerId::from_artifact(aid(&format!("source-owner-{tag}-{label}")))
        };
        let expected_reference = if role == CampaignSourceRole::ActiveOverlay || task_anchor {
            None
        } else {
            let record_id = match role {
                CampaignSourceRole::TaskObjective
                | CampaignSourceRole::TaskAcceptance
                | CampaignSourceRole::TaskOpenItems => {
                    CampaignOwnerRecordId::Task(binding.task_id.clone())
                }
                _ => CampaignOwnerRecordId::Artifact(aid(&format!("source-record-{tag}-{label}"))),
            };
            let content_digest = digest(&format!("source-content-{tag}-{label}"));
            Some(CampaignSourceRevisionRef {
                role,
                owner: owner.clone(),
                record_id,
                revision: owner_revision(role, &content_digest, binding),
                content_digest,
                slot_projection_digests: vec![],
                recorded_state_fence: binding.state_fence.clone(),
            })
        };
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
                        .expect("fixture fence carries a task revision"),
                ),
                content_digest: digest(&format!("task-anchor-{tag}")),
                slot_projection_digests: vec![],
                recorded_state_fence: binding.state_fence.clone(),
            })
        } else {
            expected_reference.clone()
        };
        let status = if reference.is_some() {
            CampaignSourceResolutionStatus::Current
        } else {
            CampaignSourceResolutionStatus::Missing
        };
        source_requirements.push(CampaignSourceRequirement {
            role,
            source_binding: if role == CampaignSourceRole::ActiveOverlay {
                CampaignSourceBinding::ExplicitlyAbsent
            } else if task_anchor {
                CampaignSourceBinding::AuthenticatedTaskAnchor
            } else {
                CampaignSourceBinding::ExactReference
            },
            owner,
            expected_reference: expected_reference.clone(),
            load_bearing: expected_reference.is_some() || task_anchor,
        });
        source_resolutions.push(CampaignSourceResolution {
            role,
            status,
            reference,
            read_state_fence: binding.state_fence.clone(),
        });
    }

    let positions = [
        (
            CampaignPositionKind::Current,
            CampaignSourceRole::CurrentPosition,
        ),
        (
            CampaignPositionKind::Experience,
            CampaignSourceRole::ExperiencePosition,
        ),
        (
            CampaignPositionKind::Adaptation,
            CampaignSourceRole::AdaptationPosition,
        ),
        (
            CampaignPositionKind::Evaluation,
            CampaignSourceRole::EvaluationPosition,
        ),
        (
            CampaignPositionKind::EconomicsProgress,
            CampaignSourceRole::EconomicsProgress,
        ),
    ]
    .into_iter()
    .map(|(kind, source_role)| {
        let source = source_resolutions
            .iter()
            .find(|resolution| resolution.role == source_role)
            .and_then(|resolution| resolution.reference.as_ref())
            .expect("position role has an exact current source");
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
    let frozen_anchor_digest = source_resolutions
        .iter()
        .find(|resolution| resolution.role == CampaignSourceRole::FrozenAnchor)
        .and_then(|resolution| resolution.reference.as_ref())
        .map(|reference| reference.content_digest.clone())
        .expect("frozen anchor has an exact current source");

    (
        source_requirements,
        CampaignLearningStateProvenance {
            source_resolutions,
            frozen_anchor_digest,
            positions,
            history_plans: vec![CampaignHistoryPlanReference {
                retrieval_plan_digest: digest(&format!("retrieval-plan-{tag}")),
                selected_handles: vec![aid(&format!("history-handle-{tag}"))],
                summary_digest: Some(digest(&format!("history-summary-{tag}"))),
                diff_digests: vec![digest(&format!("history-diff-{tag}"))],
                policy_slice_handles: vec![],
            }],
            generated_at_ms: 1_790_208_000_000,
            expires_at_ms: None,
            rebuild_reason: None,
        },
    )
}

/// Point each slot's declared source role at that slot's own owner and bind the
/// exact projected slot payload into its source record, then reseal the recipe.
fn bind_slot_source_contract(
    recipe: &mut LearningStateViewRecipe,
    provenance: &mut CampaignLearningStateProvenance,
    projections: &[SlotProjection],
) {
    for spec in &recipe.slots {
        let requirement = recipe
            .source_requirements
            .iter_mut()
            .find(|requirement| requirement.role == spec.source_role)
            .expect("slot source role is declared");
        requirement.owner = spec.owner.clone();
        if let Some(reference) = requirement.expected_reference.as_mut() {
            reference.owner = spec.owner.clone();
        }
        let resolution = provenance
            .source_resolutions
            .iter_mut()
            .find(|resolution| resolution.role == spec.source_role)
            .expect("slot source role is resolved");
        if let Some(reference) = resolution.reference.as_mut() {
            reference.owner = spec.owner.clone();
        }
    }
    for projection in projections {
        let spec = recipe
            .slots
            .iter()
            .find(|spec| spec.slot_id == projection.slot_id)
            .expect("projection is declared by recipe");
        let digest = projection.canonical_digest().expect("projection digest");
        recipe
            .source_requirements
            .iter_mut()
            .find(|requirement| requirement.role == spec.source_role)
            .expect("slot source role is declared")
            .expected_reference
            .as_mut()
            .expect("slot source has an exact expected reference")
            .slot_projection_digests
            .push(CampaignSlotProjectionDigest {
                slot_id: projection.slot_id.clone(),
                digest,
            });
    }
    recipe.seal().expect("recipe seal");
}

fn fixture() -> Fixture {
    let binding = binding();
    let target = TargetId::new("target-1864").expect("target");
    let spec = SlotSpec {
        slot_id: SlotId::from_artifact(aid("slot-1864")),
        owner: OwnerId::from_artifact(aid("owner-1864")),
        source_role: CampaignSourceRole::ArtifactProjection,
        target: target.clone(),
        requirement: SlotRequirement::Optional,
        declared_members: vec![],
        accepted_type: "verification/v1".to_owned(),
        schema_digest: digest("schema-1864"),
    };
    let (source_requirements, mut provenance) = campaign_source_contract("1864", &binding);
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-1864"),
        campaign_id: CampaignId::from_artifact(aid("campaign-1864")),
        target: TargetId::new("task-target-1864").expect("target"),
        binding: binding.clone(),
        slots: vec![spec.clone()],
        source_requirements,
        active_overlay_policy: CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed,
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    let slots = vec![SlotProjection {
        slot_id: spec.slot_id.clone(),
        disposition: SlotDisposition::KnownEmpty,
        members: vec![],
        evidence: vec![aid("empty-owner-evidence-1864")],
    }];
    bind_slot_source_contract(&mut recipe, &mut provenance, &slots);
    let mut view = CampaignLearningStateView {
        view_id: aid("view-1864"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target: recipe.target.clone(),
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        provenance,
        slots,
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("objective-reference-1864")],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.seal_content_addressed().expect("view seal");
    Fixture {
        recipe,
        view,
        target,
        discriminator: aid("next-discriminator-1864"),
        frozen: FrozenPreEvaluation {
            intended_mechanism: "admission-1864-mechanism".to_owned(),
            prediction: "admission-1864-prediction".to_owned(),
            expected_observable: "admission-1864-observable".to_owned(),
            possible_regressions: "admission-1864-regressions".to_owned(),
            confounders: "admission-1864-confounders".to_owned(),
            preserved_success_constraint: "admission-1864-preserved".to_owned(),
            next_discriminator_text: "admission-1864-next".to_owned(),
            rollback_condition: "admission-1864-rollback".to_owned(),
        },
    }
}

fn operation_add(
    target: &TargetId,
    surface: ChangeSurface,
    value: &str,
) -> (ChangeOperation, InverseChange) {
    let after = ValueState {
        present: true,
        digest: Some(digest(value)),
    };
    (
        ChangeOperation::Add {
            target: target.clone(),
            surface,
            after: after.clone(),
        },
        InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Remove {
                target: target.clone(),
                surface,
                before: after,
            },
        },
    )
}

fn delta(
    view: &CampaignLearningStateView,
    id: &str,
    operation: ChangeOperation,
    inverse: InverseChange,
) -> AttemptLearningDeltaCandidate {
    let mut delta = AttemptLearningDeltaCandidate {
        binding: view.binding.clone(),
        attempt_id: eliot_learning_contracts::AgentAttemptId::new(format!("attempt-1864-{id}"))
            .expect("attempt"),
        delta_id: aid(&format!("delta-1864-{id}")),
        target: view.target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid(&format!("prior-discriminator-1864-{id}")),
        intended_strategy: aid(&format!("intended-1864-{id}")),
        attempted_strategy: aid(&format!("attempted-1864-{id}")),
        changes: vec![operation],
        inverses: vec![inverse],
        evidence: vec![aid(&format!("evidence-1864-{id}"))],
        evaluator_receipts: vec![aid(&format!("evaluator-1864-{id}"))],
        baseline: vec![],
        control: vec![],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    delta.seal().expect("delta seal");
    delta
}

fn mutated_delta(
    view: &CampaignLearningStateView,
    id: &str,
    operation: ChangeOperation,
    inverse: InverseChange,
    mutate: impl FnOnce(&mut AttemptLearningDeltaCandidate),
) -> AttemptLearningDeltaCandidate {
    let mut next = delta(view, id, operation, inverse);
    mutate(&mut next);
    next.seal().expect("delta reseal");
    next
}

fn input<'a>(
    fixture: &'a Fixture,
    deltas: &'a [AttemptLearningDeltaCandidate],
    admitted: &'a [AdmittedDeltaPair],
) -> OverlayComposeInput<'a> {
    OverlayComposeInput {
        recipe: &fixture.recipe,
        view: &fixture.view,
        deltas,
        admitted,
        overlay_id: eliot_learning_contracts::OverlayId::from_artifact(aid("overlay-1864")),
        parent_revision: TaskRevision::genesis(),
        protected_surface_base_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        protected_surface_proposed_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        fixed_before_observation_discriminator: &fixture.discriminator,
        frozen: &fixture.frozen,
        expires_at_ms: 2_000,
        observed_at_ms: 1_000,
    }
}

fn admitted(deltas: &[AttemptLearningDeltaCandidate]) -> Vec<AdmittedDeltaPair> {
    deltas
        .iter()
        .map(|delta| AdmittedDeltaPair {
            delta_id: delta.delta_id.clone(),
            canonical_digest: delta.canonical_digest.clone(),
        })
        .collect()
}

/// Caller-supplied owner records; widening is `candidate != ceiling` by exact
/// string equality, so the matching case repeats the ceiling labels verbatim.
struct RefData {
    objective: String,
    acceptance: String,
    authority_ceiling: String,
    candidate_authority: String,
    privacy_ceiling: String,
    candidate_privacy: String,
    sealed_holdout_refs: Vec<String>,
    evaluator_refs: Vec<String>,
}

impl RefData {
    fn matching() -> Self {
        Self {
            objective: "objective-rev-1".to_owned(),
            acceptance: "acceptance-rev-1".to_owned(),
            authority_ceiling: "task-local".to_owned(),
            candidate_authority: "task-local".to_owned(),
            privacy_ceiling: "task-local".to_owned(),
            candidate_privacy: "task-local".to_owned(),
            sealed_holdout_refs: vec![],
            evaluator_refs: vec![],
        }
    }

    fn refs<'a>(&'a self, view: &'a CampaignLearningStateView) -> AuthoritativeRefs<'a> {
        AuthoritativeRefs {
            objective_revision: self.objective.as_str(),
            acceptance_revision: self.acceptance.as_str(),
            expected_objective_revision: self.objective.as_str(),
            expected_acceptance_revision: self.acceptance.as_str(),
            authority_ceiling: self.authority_ceiling.as_str(),
            candidate_authority: self.candidate_authority.as_str(),
            privacy_ceiling: self.privacy_ceiling.as_str(),
            candidate_privacy: self.candidate_privacy.as_str(),
            sealed_holdout_refs: self.sealed_holdout_refs.as_slice(),
            evaluator_refs: self.evaluator_refs.as_slice(),
            state_fence: &view.binding.state_fence,
        }
    }
}

fn valid_candidate(
    fixture: &Fixture,
) -> (
    Vec<AttemptLearningDeltaCandidate>,
    eliot_learning_contracts::CampaignHarnessOverlayCandidate,
) {
    let (operation, inverse) = operation_add(
        &fixture.target,
        ChangeSurface::VerificationOrder,
        "value-1864",
    );
    let deltas = vec![delta(&fixture.view, "valid", operation, inverse)];
    let pairs = admitted(&deltas);
    let candidate =
        compose_campaign_harness_overlay(&input(fixture, &deltas, &pairs)).expect("candidate");
    (deltas, candidate)
}

// A2/1: a change whose target names a sealed-holdout reference is rejected at
// the admit stage with `ProtectedSurfaceChanged`; no activation call exists.
#[test]
fn sealed_holdout_overlap_rejected_before_activation() {
    let fixture = fixture();
    let (deltas, candidate) = valid_candidate(&fixture);
    let mut refs_data = RefData::matching();
    refs_data.sealed_holdout_refs = vec![fixture.target.as_str().to_owned()];
    assert!(matches!(
        admit_local_with_refs(
            &candidate,
            &fixture.view,
            &deltas,
            &refs_data.refs(&fixture.view),
            1_000
        ),
        Err(OverlayError::ProtectedSurfaceChanged)
    ));
}

// A2/2: any candidate authority label that is not exactly the Governor ceiling
// label rejects at the admit stage, whether it names more authority or merely
// different authority.
#[test]
fn authority_widening_rejected_before_activation() {
    let fixture = fixture();
    let (deltas, candidate) = valid_candidate(&fixture);
    let mut refs_data = RefData::matching();
    refs_data.candidate_authority = "task-elevated".to_owned();
    assert!(matches!(
        admit_local_with_refs(
            &candidate,
            &fixture.view,
            &deltas,
            &refs_data.refs(&fixture.view),
            1_000
        ),
        Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "admission.authority"
            }
        ))
    ));
}

// A2/3: a finish-condition attempt names a surface outside the two supported
// task-local surfaces, so composition itself rejects it as `Unsupported` —
// before admission and therefore before any activation.
#[test]
fn finish_condition_surface_rejected_at_compose_before_admission() {
    let fixture = fixture();
    let (operation, inverse) =
        operation_add(&fixture.target, ChangeSurface::Strategy, "finish-1864");
    let deltas = vec![delta(&fixture.view, "finish", operation, inverse)];
    let pairs = admitted(&deltas);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)),
        Err(OverlayError::Unsupported {
            field: "change.surface"
        })
    ));
}

// A2/4: a budget attempt that escalates the proof ceiling above the binding
// ceiling is rejected at compose with a contract error — before admission and
// therefore before any activation. (A-32 carries no budget payload, so the
// proof ceiling is the local budget-ceiling analogue enforced here.)
#[test]
fn budget_ceiling_escalation_rejected_at_compose_before_activation() {
    let fixture = fixture();
    let (operation, inverse) = operation_add(
        &fixture.target,
        ChangeSurface::VerificationOrder,
        "budget-1864",
    );
    let escalated = mutated_delta(&fixture.view, "budget", operation, inverse, |next| {
        next.proof_ceiling = ProofCeiling::ScopedVerification;
    });
    let pairs = admitted(std::slice::from_ref(&escalated));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[escalated], &pairs)),
        Err(OverlayError::Contract(
            LearningContractError::CandidateCeiling
        ))
    ));
}

// A2/5 (must-accept): a bounded local `VerificationOrder` change with matching
// owner records admits and yields a receipt bound to the observation time.
#[test]
fn bounded_local_change_with_matching_refs_admits_with_receipt() {
    let fixture = fixture();
    let (deltas, candidate) = valid_candidate(&fixture);
    let refs_data = RefData::matching();
    let receipt = admit_local_with_refs(
        &candidate,
        &fixture.view,
        &deltas,
        &refs_data.refs(&fixture.view),
        1_000,
    )
    .expect("matching refs admit");
    assert_eq!(receipt.overlay_id, candidate.overlay_id.as_str());
    assert_eq!(receipt.admitted_at_ms, 1_000);
    assert!(admit_local(&candidate, &fixture.view, &deltas, 1_000).is_ok());
}
