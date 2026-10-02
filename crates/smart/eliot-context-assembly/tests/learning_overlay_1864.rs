//! Governed local overlay admission proof for issue #1864, item A3.
//!
//! After expiry, the same overlay revision is not retrievable or deliverable
//! to a later attempt absent a new governed admission. These tests pin the
//! delivery side through the governed assembly entrypoint
//! [`assemble_active_view_with_learning`], which runs the shared owner-bound
//! carriage gate exactly as at retrieval:
//!
//! - the expired revision (same `overlay_id`, live mark, past `expires_at`)
//!   refuses before anything renders, and the plain base-view projection
//!   survives untouched;
//! - the same revision under a new governed admission (fresh expiry and
//!   admission handle) delivers again to its own campaign, and no longer
//!   reaches another campaign under a revalidation that only re-spelled the
//!   local admission (#1869: a carryover needs a distinct, owner-issued
//!   admission, and a request from the admitted task under a foreign campaign
//!   label is refused as cross-campaign leakage);
//! - the invalidated revision refuses even with live expiry.
//!
//! Note: `eliot-learning-contracts::overlay_eligibility` and
//! `eliot-learning-overlay::check_retrievable` express the same causal
//! property, but neither crate is a dependency of `eliot-context-assembly`
//! (see `Cargo.toml`), so these tests exercise the identical refusal reasons
//! through the available governed screen: `ExpiredOverlay` maps to
//! `InvalidField("learning.expires_at")` (the `overlay_expired` analog) and
//! `OverlayNotAdmitted` maps to `InvalidField("learning.overlay")` (the
//! `overlay_invalidated` analog).

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AdmittedContextSet, AssemblyError, AssemblyPolicy,
    QualityScorecard, SerializedContextMeasurement, assemble_active_view,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, ContractVersion, DecisionId, EpochId, EpochLineageId, PolicyRevision,
    ResourceGeneration, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, VerifiedLearningAdmission, issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{
    BoundedBacklog, CrossTaskCarryover, GovernedOverlay, OverlayState,
};
use eliot_improvement::{PresentedLearning, datetime_from_unix};
use eliot_receipts::{ProofCeiling, ProtectedReserves, WorkScopeId};

const LINEAGE_1864: &str = "550e8400-e29b-41d4-a716-446655440001";
const CAMPAIGN_1864: &str = "campaign-1864-a";
const OTHER_CAMPAIGN_1864: &str = "campaign-1864-b";
const TASK_1864: &str = "task-1864-a";
const OVERLAY_1864: &str = "overlay-1864-rev7";
const NOW_1864: u64 = 1_800_000_000;
const LATER_1864: u64 = NOW_1864 + 7200;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "b".repeat(64)
}

fn epoch_1864() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1864).expect("lineage"),
        NonZeroU64::new(3).expect("sequence"),
    )
    .expect("epoch")
}

fn fence_1864() -> StateFence {
    StateFence::new(
        epoch_1864(),
        ResourceGeneration::new(7).expect("generation"),
    )
}

fn governor_1864() -> Governor {
    let config = GovernorConfig {
        authority_epoch: epoch_1864(),
        resource_generation: ResourceGeneration::new(7).expect("generation"),
        queues: QueueLimits::default(),
        background_pause_interactive_depth: 1,
    };
    let mut governor = Governor::new(config).expect("governor config");
    governor.begin_startup().expect("startup begins");
    governor
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new(TASK_1864).expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt-1864").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope-1864").expect("fixture scope"),
        state_fence: fence_1864(),
        decision_id: DecisionId::new("decision-1864").expect("fixture decision"),
        operation_id: None,
    }
}

fn role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("fixture-provider").expect("fixture provider"),
        role: SemanticRole::Goal,
    }
}

fn candidate(context: &ContextBinding, atom: &str) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom),
        provider_role: role(),
        // This fixture asserts about learning overlay routing, not about a
        // measured position inside the snapshot, so the range stays a typed
        // unknown.
        source_range: None,
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new(format!("source-{atom}"))
                .expect("fixture source"),
            owner: ProviderId::new("fixture-provider").expect("fixture owner"),
            snapshot_id: id(&format!("snapshot-{atom}")),
            revision: "revision-1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: format!("whole {atom}"),
        },
        learning: None,
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(),
            serializer: "fixture-serde-v1".to_owned(),
        },
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id(&format!("evidence-{atom}")),
            ceiling: ProofCeiling::Observation,
        },
    }
}

/// Admitted set with one ordinary atom plus one intrinsically marked
/// learning atom citing `permit_digest`. The mark expiry is caller-chosen so
/// refusal can be attributed to the overlay revision alone.
fn admitted_with_learning(permit_digest: &str, mark_expires: Option<u64>) -> AdmittedContextSet {
    let context = binding();
    let first = candidate(&context, "atom-1864");
    let mut second = candidate(&context, "learning-1864");
    second.learning = Some(LearningProvenance {
        campaign_id: CAMPAIGN_1864.to_string(),
        overlay_id: Some(OVERLAY_1864.to_string()),
        candidate_id: None,
        closure_ref: None,
        owner: None,
        draft: false,
        expires_at_unix_secs: mark_expires,
        permit_digest: permit_digest.to_string(),
    });
    let atom_id = first.atom_id.clone();
    let provider = first.provider_role.clone();
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![provider.clone()],
            dispositions: vec![ProviderDisposition {
                slot: provider.clone(),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        members: vec![SafetyFloorMember {
            atom_id: atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(first.measurement.clone()),
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
    };
    let mut value = AdmittedContextSet {
        binding: context.clone(),
        records: vec![
            AdmittedAtom {
                candidate: first,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmittedAtom {
                candidate: second.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
        ],
        admissions: vec![
            AdmissionRecord {
                atom_id: atom_id.clone(),
                provider_role: provider,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmissionRecord {
                atom_id: second.atom_id.clone(),
                provider_role: second.provider_role.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
        ],
        floor,
        economy: ContextEconomyReceipt {
            binding: context.clone(),
            decision_id: context.decision_id.clone(),
            measurement: MeasurementRef {
                digest: digest(),
                serializer: "fixture-serde-v1".to_owned(),
            },
            requested: vec![atom_id.clone(), second.atom_id.clone()],
            admitted: vec![atom_id, second.atom_id.clone()],
            displaced: Vec::new(),
            omissions: Vec::new(),
            applied_rule: id("economy-rule"),
            allocations: EconomyAllocations {
                fixed_overhead: 2,
                output_reserve: 3,
                review_reserve: 4,
                admitted_required: 1,
                admitted_optional: 0,
                remaining_headroom: 99_990,
                route_capacity: 100_000,
            },
            recipe_digest: recipe(&context).recipe_sha256.clone(),
            policy_sha256: recipe(&context).decision.policy_sha256.clone(),
            receipt_digest: digest(),
        },
    };
    refresh_economy_receipt(&mut value);
    let payload_bytes = value
        .canonical_payload_utf8_bytes()
        .expect("admitted payload");
    value.economy.allocations.admitted_required = payload_bytes;
    value.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    refresh_economy_receipt(&mut value);
    value.economy.measurement.digest = value.canonical_payload_digest().expect("admitted digest");
    refresh_economy_receipt(&mut value);
    value
}

fn refresh_economy_receipt(value: &mut AdmittedContextSet) {
    let mut unsigned = value.economy.clone();
    unsigned.receipt_digest = "0".repeat(64);
    value.economy.receipt_digest =
        eliot_context_contracts::canonical_digest(&unsigned).expect("economy receipt");
}

fn resolved_applicability() -> QualityApplicability {
    QualityApplicability {
        resolved: QUALITY_APPLICABILITY_INPUTS.to_vec(),
        unknown: Vec::new(),
    }
}

/// Intrinsically well-formed output binding for a card that is only checked for
/// structural integrity, or for a packet assembly refuses before the grade is
/// read. The serializer and route identities are the ones
/// [`policy_for`] applies, because a card naming a different serializer or
/// route is not the grade of the bytes produced under this policy and
/// `require_graded_output` refuses it. The digests are placeholders: a card
/// naming one packet's exact digests is built by that packet's owner.
fn fixture_output_binding() -> QualityOutputBinding {
    QualityOutputBinding {
        recipe_digest: digest(),
        fence_digest: digest(),
        admitted_digest: digest(),
        rendered_digest: digest(),
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        evidence_revisions: Vec::new(),
        omission_handles: Vec::new(),
    }
}

fn quality(context: &ContextBinding) -> QualityScorecard {
    let dimensions = [
        QualityDimension::AcceptanceDecisionCoverage,
        QualityDimension::CausalOperationalSufficiency,
        QualityDimension::ExactAnchorProvenanceCoverage,
        QualityDimension::FreshnessStateFenceCoherence,
        QualityDimension::RivalsConflictsUnknownsVisibility,
        QualityDimension::NegativeMemoryInvariantCoverage,
        QualityDimension::VerifierActionReadiness,
        QualityDimension::RouteAccessibilityLayoutRisk,
        QualityDimension::InstructionSufficiency,
        QualityDimension::PayloadHandleReconstructionCost,
        QualityDimension::KnownOmissionsExpansionPaths,
        QualityDimension::TelemetryMeasurementCostCoverage,
    ];
    QualityScorecard {
        schema_version: QUALITY_SCORECARD_SCHEMA_VERSION,
        binding: context.clone(),
        output: fixture_output_binding(),
        applicability: resolved_applicability(),
        results: dimensions
            .into_iter()
            .map(|dimension| QualityDimensionResult {
                schema_version: QUALITY_RESULT_SCHEMA_VERSION,
                dimension,
                state: QualityDimensionState::Passed,
                rule_revision: id("rule-revision"),
                required_evidence: vec![id("quality-evidence")],
                evidence: vec![id("quality-evidence")],
                measurements: Vec::new(),
                failed_invariant: None,
                unknown_evidence: Vec::new(),
                proof_ceiling: ProofCeiling::Observation,
                invalidation: None,
                binding: context.clone(),
            })
            .collect(),
    }
}

/// The card a real packet accepts: it records the exact output it graded, so
/// the recipe revision, the fence, the admitted set's own canonical payload
/// digest, the ordered rendered payload digest, the serializer/route identity
/// the bytes are produced under and the source revisions they are read from are
/// this packet's values. A card that omits or forges any of them is refused by
/// `require_graded_output` rather than accepted on the strength of its twelve
/// passing dimensions, which is why [`fixture_output_binding`] is a card for a
/// packet this path refuses before the grade is read and not the card behind a
/// delivered view.
fn quality_for(admitted: &AdmittedContextSet, recipe: &ContextRecipe) -> QualityScorecard {
    let mut card = quality(&admitted.binding);
    let fence_digest =
        eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)
            .expect("fixture fence digest");
    let rendered = rendered_for(admitted);
    card.output.recipe_digest = recipe.recipe_sha256.clone();
    card.output.fence_digest = fence_digest.clone();
    card.output.admitted_digest = admitted
        .canonical_payload_digest()
        .expect("fixture admitted digest");
    card.output.rendered_digest = ActiveUnderstandingView::canonical_output_digest(
        &admitted.binding,
        &recipe.recipe_sha256,
        &fence_digest,
        &rendered,
    )
    .expect("fixture rendered digest");
    card.output.omission_handles = admitted.economy.displaced.clone();
    // The source revisions this packet was actually read from, deduplicated in
    // canonical order exactly as the owner derives them from the admitted
    // records. These are real observations, so the binding is satisfied by the
    // packet and not by a self-referential list.
    card.output.evidence_revisions = admitted
        .records
        .iter()
        .map(|record| record.candidate.source.snapshot_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    card
}

/// The ordered rendered payload the approved revision produces for `admitted`.
///
/// #1724 W4: the order the renderer applies is the approved revision's own
/// declared `layout.role_positions`, then provider, then atom identity. This
/// fixture's revision declares one configured role, so every rendered atom
/// shares that single declared position and the order below is exactly the
/// role/provider/atom order the renderer produces — the same sequence
/// `tests/assembly.rs` derives, kept identical so the copies of this fixture
/// assert one thing under one name.
fn rendered_for(admitted: &AdmittedContextSet) -> Vec<RenderedAtom> {
    let mut rendered: Vec<RenderedAtom> = admitted
        .records
        .iter()
        .map(RenderedAtom::from_admitted)
        .collect();
    rendered.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.atom_id.cmp(&right.atom_id))
    });
    rendered
}

fn measurement(context: &ContextBinding, bytes: &[u8]) -> SerializedContextMeasurement {
    SerializedContextMeasurement {
        measurement_id: id("measurement"),
        context: context.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest: sha256_hex(bytes),
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        rendered_utf8_bytes: u64::try_from(bytes.len()).expect("fixture byte count"),
        stu_estimate: None,
        tokenizer: None,
        status: MeasurementStatus::ExactUtf8,
        fixed_overhead: 2,
        output_reserve: 3,
        review_reserve: 4,
        false_safe_overflow: None,
        false_rejection_or_decomposition: None,
        valid_until: None,
    }
}

fn policy_for(context: &ContextBinding, max_serialized_bytes: u64) -> AssemblyPolicy {
    AssemblyPolicy {
        fence_digest: eliot_context_contracts::canonical_fence_digest(&context.state_fence)
            .expect("fence digest"),
        max_serialized_bytes,
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        measurement_status: MeasurementStatus::ExactUtf8,
    }
}

/// The approved reusable `ContextRecipePolicy` revision this fixture compiles
/// under.
///
/// `assemble_active_view_with_learning` delegates to `assemble_active_view`,
/// which reads the EXECUTED layout order from the approved revision rather than
/// from the `SemanticRole` ordinal, so a fixture that hands the entrypoint an
/// approved revision has to declare one. Nothing here is invented content: every
/// declaration is the one this execution path actually applies, and both digests
/// are derived by the owners' own `canonical_*_digest` functions.
///
/// The three checks `require_approved_recipe_binding` runs are each satisfied by
/// construction: `approved.validate()` re-derives `policy_sha256`; and
/// `binds_recipe` compares the instance's recorded
/// `DecisionRevision::policy_sha256` with this revision's own digest while
/// requiring every mandatory role and role policy of the instance to be a
/// configured feature — [`recipe`] records this digest, and the single configured
/// feature is `SemanticRole::Goal` with the instance's own
/// `LossPolicy::NonDroppable`, which is also the one representation contract the
/// section budget declares. `require_executable` is satisfied by declaring the
/// one `EXECUTED_CONTEXT_STAGE` with no predecessor edge,
/// `EXECUTED_REPETITION_POLICY`, a `BoundaryUnitKind::Unit` section whose
/// degradation is `EXECUTED_SECTION_DEGRADATION`, and no feature disable (this
/// path has no such capability, so a budget relying on one is refused by name).
/// The `ordering_revision` half needs nothing from this fixture: the entrypoint
/// builds its support record from its own ordering-scheme constant.
///
/// The single declared `role_positions` entry covers every role this fixture's
/// admitted set carries, so `render::render` positions all of them.
fn approved_policy() -> ContextRecipePolicy {
    let route = "route";
    let mut policy = ContextRecipePolicy {
        policy_schema_version: CONTEXT_RECIPE_POLICY_SCHEMA_VERSION,
        policy_id: id("recipe-policy-1864"),
        policy_revision: PolicyRevision::new(1).expect("policy revision"),
        // Placeholder, replaced by the canonical digest of the finished content
        // below exactly as `canonical_policy_digest` expects.
        policy_sha256: "0".repeat(64),
        applicability: RecipeApplicability {
            task_profiles: vec![TASK_1864.to_owned()],
            route_profiles: vec![route.to_owned()],
            impact_profiles: vec!["decision".to_owned()],
            governance_profiles: vec!["default".to_owned()],
        },
        stages: vec![RecipeStage {
            stage_id: ArtifactId::new(EXECUTED_CONTEXT_STAGE).expect("executed stage"),
            semantic_role: SemanticRole::Goal,
            predecessors: Vec::new(),
        }],
        candidate_features: vec![SemanticRole::Goal],
        admission: RecipeAdmissionPolicy {
            admission_rule: id("admission-rule"),
            safety_floor: id("floor-rule"),
            suppressible_roles: Vec::new(),
        },
        section_budgets: vec![ContextSectionBudget {
            semantic_role: SemanticRole::Goal,
            unit_boundary_kind: BoundaryUnitKind::Unit,
            minimum_required_whole_units: 1,
            required_exact_references: vec![id("atom-1864")],
            protected_floor_refs: Vec::new(),
            planning_maximum_whole_units: 8,
            planning_route_profile: route.to_owned(),
            omission_or_handle_policy: LossPolicy::NonDroppable,
            degradation_behavior: EXECUTED_SECTION_DEGRADATION,
            disable_feature_when_floor_cannot_be_preserved: false,
        }],
        protected_reserve: ProtectedReservePolicy {
            reserves: ProtectedReserves {
                reasoning_reserve: 1,
                review_reserve: 4,
                evidence_reserve: 1,
                owner_ref: "context-budget-owner".to_owned(),
            },
            margin_reserve: 1,
        },
        layout: RecipeLayoutPolicy {
            role_positions: vec![RecipeRolePosition {
                semantic_role: SemanticRole::Goal,
                position: 0,
            }],
            repetition: EXECUTED_REPETITION_POLICY,
        },
        omission: RecipeOmissionPolicy {
            permitted_reasons: vec![OmissionReason::Capacity],
            non_recoverable_reasons: Vec::new(),
        },
        blocking_dimensions: vec![QualityDimension::AcceptanceDecisionCoverage],
        execution: RecipeExecutionContour {
            contour: id("execution-contour"),
            generation: 1,
            transform: BoundaryTransformerRevision {
                transformer_id: "identity".to_owned(),
                revision: ContractVersion::new(1, 0, 0),
                configuration_sha256: digest(),
            },
        },
        qualification: RecipeQualification {
            qualification: id("qualification"),
            state: RecipeQualificationState::Qualified,
            counter_metrics: Vec::new(),
        },
        supersession: RecipeSupersession {
            activation: id("activation"),
        },
    };
    policy.policy_sha256 = policy.canonical_policy_digest().expect("policy digest");
    policy
}

/// The owner-resolved `ResolvedContextRecipe` the assembly entrypoints require.
///
/// Every recorded member is re-derived from the approved content rather than
/// written: the identity is the policy's own three values, the approval IS the
/// policy's activation decision, the execution contour IS the policy's, the
/// applicability is the policy's own declaration (so it covers itself), and
/// `resolution_sha256` is the canonical resolution digest. That is what makes
/// `ResolvedContextRecipe::validate` — the first of the three checks
/// `require_approved_recipe_binding` runs — pass.
fn approved() -> ResolvedContextRecipe {
    let policy = approved_policy();
    let mut resolution = ResolvedContextRecipe {
        identity: RecipePolicyIdentity {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.policy_revision,
            policy_sha256: policy.policy_sha256.clone(),
        },
        approval: policy.supersession.activation.clone(),
        applicability: policy.applicability.clone(),
        execution: policy.execution.clone(),
        policy,
        resolution_sha256: "0".repeat(64),
    };
    resolution.resolution_sha256 = resolution
        .canonical_resolution_digest()
        .expect("resolution digest");
    resolution
}

fn recipe(context: &ContextBinding) -> ContextRecipe {
    let provider = role();
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: DecisionRevision {
            decision_id: context.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("recipe revision"),
            // The approved revision this instance was issued under.
            // `binds_recipe` compares this recorded value with the approved
            // revision's own `policy_sha256`, so the two halves of one
            // compilation name one revision.
            policy_sha256: approved_policy().policy_sha256,
        },
        recipe_sha256: digest(),
        denominator: ProviderRoleDenominator {
            requested: vec![provider.clone()],
            dispositions: vec![ProviderDisposition {
                slot: provider,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        mandatory_roles: vec![SemanticRole::Goal],
        role_policies: vec![RoleLossRule {
            role: SemanticRole::Goal,
            loss_policy: LossPolicy::NonDroppable,
            required: true,
            allowed_representations: vec![RepresentationKind::Whole],
        }],
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
        predecessor: None,
        invalidation: None,
    };
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
    recipe
}

fn owner_permit(
    governor: &Governor,
    fence: &StateFence,
) -> eliot_governor::LearningAdmissionPermit {
    issue_learning_admission(
        governor,
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1864.to_string(),
            target_task_id: TASK_1864.to_string(),
            fence: fence.clone(),
            overlay_id: Some(OVERLAY_1864.to_string()),
            candidate_id: None,
            scope_ref: "scope-1864".to_string(),
            authority_ref: "governor-1864".to_string(),
            retention_ref: "retention-1864".to_string(),
            evaluator_ref: "evaluator-1864-a".to_string(),
            rollback_ref: "rollback-1864".to_string(),
        },
    )
    .expect("live owner issues")
}

/// The same overlay revision under test: identical identity bytes
/// (`overlay_id`, campaign, fence); only the governed admission liveness
/// (`state`, `admission_ref`, `expires_at`) varies per case.
fn overlay_revision_1864(
    fence: &StateFence,
    state: OverlayState,
    admission_ref: &str,
    expires_at_unix_secs: u64,
) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: OVERLAY_1864.to_string(),
        campaign_id: CAMPAIGN_1864.to_string(),
        task_id: TASK_1864.to_string(),
        fence: fence.clone(),
        compatible_recipe_ref: "recipe-1864".to_string(),
        state,
        admission_ref: Some(admission_ref.to_string()),
        expires_at: Some(datetime_from_unix(expires_at_unix_secs).expect("overlay expiry")),
    }
}

#[allow(clippy::too_many_arguments)]
fn presented_1864<'a>(
    governor: &'a Governor,
    verified: &'a VerifiedLearningAdmission<'a>,
    overlay: &'a GovernedOverlay,
    backlog: &'a BoundedBacklog,
    cross_task: Option<&'a CrossTaskCarryover<'a>>,
    requesting_campaign_id: &'a str,
    now: u64,
) -> PresentedLearning<'a> {
    PresentedLearning {
        governor,
        verified,
        ticket: verified.permit().ticket(),
        overlay: Some(overlay),
        backlog,
        cross_task,
        requesting_campaign_id,
        requesting_task_id: TASK_1864,
        now_unix_secs: now,
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_marked_1864(
    value: &AdmittedContextSet,
    governor: &Governor,
    verified: &VerifiedLearningAdmission<'_>,
    overlay: &GovernedOverlay,
    backlog: &BoundedBacklog,
    cross_task: Option<&CrossTaskCarryover<'_>>,
    requesting_campaign_id: &str,
    now: u64,
) -> Result<ActiveUnderstandingViewResult, AssemblyError> {
    let context = value.binding.clone();
    let instance = recipe(&context);
    let approved = approved();
    assemble_active_view_with_learning(
        value,
        &instance,
        &approved,
        quality_for(value, &instance),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        presented_1864(
            governor,
            verified,
            overlay,
            backlog,
            cross_task,
            requesting_campaign_id,
            now,
        ),
    )
}

/// A3, expired revision: the same overlay revision presented to a later
/// attempt refuses delivery. The mark itself is live, so the refusal is
/// attributable to the expired revision, not to mark expiry.
#[test]
fn expired_overlay_revision_refuses_later_delivery_and_plain_projection_survives() {
    let governor = governor_1864();
    let fence = fence_1864();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(LATER_1864 + 3600));
    let overlay = overlay_revision_1864(
        &fence,
        OverlayState::LocalAdmitted,
        "admission-1864-rev7",
        NOW_1864 + 3600,
    );
    let backlog = BoundedBacklog::default();
    let result = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        CAMPAIGN_1864,
        LATER_1864,
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "learning.expires_at"
        )))
    );
    // Historical behavior is untouched: unmarked atoms project as before.
    let mut plain = value;
    for record in &mut plain.records {
        record.candidate.learning = None;
    }
    refresh_economy_receipt(&mut plain);
    let payload_bytes = plain
        .canonical_payload_utf8_bytes()
        .expect("admitted payload");
    plain.economy.allocations.admitted_required = payload_bytes;
    plain.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    refresh_economy_receipt(&mut plain);
    plain.economy.measurement.digest = plain.canonical_payload_digest().expect("admitted digest");
    refresh_economy_receipt(&mut plain);
    let context = plain.binding.clone();
    let instance = recipe(&context);
    let approved = approved();
    let view = assemble_active_view(
        &plain,
        &instance,
        &approved,
        quality_for(&plain, &instance),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("plain projection survives");
    assert_eq!(view.view.rendered.len(), 2);
}

/// A3, re-admission: the same revision (identical identity bytes) under a new
/// governed admission delivers again. No new admission, no delivery
/// (see the expired test above).
///
/// The old fixture asked for that delivery to ANOTHER campaign on the strength
/// of a "cross-task admission" that re-spelled this very permit's own bound
/// values and named this very task, so no other task was involved at all —
/// the defect #1869 removes. A carryover is now a distinct, owner-issued
/// admission, and a request from the admitted task under a foreign campaign
/// label is refused as cross-campaign leakage, so that leg is pinned as the
/// refusal it now is and the re-admitted revision is proved on the campaign
/// its learning belongs to.
#[test]
fn readmitted_overlay_revision_delivers_to_other_campaign_with_new_admission() {
    let governor = governor_1864();
    let fence = fence_1864();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(LATER_1864 + 3600));
    let overlay = overlay_revision_1864(
        &fence,
        OverlayState::LocalAdmitted,
        "admission-1864-rev7-readmit",
        LATER_1864 + 3600,
    );
    let backlog = BoundedBacklog::default();
    let refusal = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        OTHER_CAMPAIGN_1864,
        LATER_1864,
    );
    assert_eq!(
        refusal,
        Err(AssemblyError::Contract(ContextError::IdentityConflict)),
        "another campaign is not a carryover a re-spelled local admission buys"
    );

    let view = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        CAMPAIGN_1864,
        LATER_1864,
    )
    .expect("readmitted revision delivers with new governed admission");
    assert_eq!(view.view.rendered.len(), 2);
    assert!(view.view.admitted_ids.contains(&id("learning-1864")));
}

/// A3, invalidation: the same revision with live expiry but an invalidated
/// state refuses delivery; expiry is not the only way a revision dies.
#[test]
fn invalidated_overlay_revision_refuses_delivery() {
    let governor = governor_1864();
    let fence = fence_1864();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(NOW_1864 + 3600));
    let overlay = overlay_revision_1864(
        &fence,
        OverlayState::Invalidated,
        "admission-1864-rev7",
        NOW_1864 + 3600,
    );
    let backlog = BoundedBacklog::default();
    let result = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        CAMPAIGN_1864,
        NOW_1864,
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "learning.overlay"
        )))
    );
}
