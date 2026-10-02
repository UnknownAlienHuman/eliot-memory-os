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
    ActiveUnderstandingView, ActiveUnderstandingViewResult, AdmittedContextSet, AssemblyError,
    AssemblyPolicy, QualityScorecard, SerializedContextMeasurement, assemble_active_view,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, PolicyRevision, ResourceGeneration,
    StateFence, TaskId, TaskRevision, sha256_hex,
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
/// The learning provenance this file's overlay revision admits: an owner-issued
/// campaign/overlay pair with no draft, closure or owner claim, and the caller's
/// chosen expiry and permit digest. Extracted so the admitted-set fixture stays
/// readable; every field is the same literal the fixture always carried.
fn learning_provenance_1864(mark_expires: Option<u64>, permit_digest: &str) -> LearningProvenance {
    LearningProvenance {
        campaign_id: CAMPAIGN_1864.to_string(),
        overlay_id: Some(OVERLAY_1864.to_string()),
        candidate_id: None,
        closure_ref: None,
        owner: None,
        draft: false,
        expires_at_unix_secs: mark_expires,
        permit_digest: permit_digest.to_string(),
    }
}

fn admitted_with_learning(permit_digest: &str, mark_expires: Option<u64>) -> AdmittedContextSet {
    let context = binding();
    let first = candidate(&context, "atom-1864");
    let mut second = candidate(&context, "learning-1864");
    second.learning = Some(learning_provenance_1864(mark_expires, permit_digest));
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

/// The card a delivered packet accepts: it records the exact output it graded
/// (the instance digest, the fence, the admitted set's own canonical payload
/// digest, the ordered rendered payload digest and the source revisions the
/// bytes were read from), so `require_graded_output` compares a real grade
/// against a real packet. The intrinsic [`quality`] card above is for the
/// packets the carriage gate refuses BEFORE the grade is read; a packet that is
/// delivered is graded, and a placeholder card is not the grade of anything.
fn quality_for(admitted: &AdmittedContextSet, recipe: &ContextRecipe) -> QualityScorecard {
    let mut card = quality(&admitted.binding);
    let fence_digest =
        eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)
            .expect("fixture fence digest");
    card.output.recipe_digest.clone_from(&recipe.recipe_sha256);
    card.output.fence_digest.clone_from(&fence_digest);
    card.output.admitted_digest = admitted
        .canonical_payload_digest()
        .expect("fixture admitted digest");
    card.output.rendered_digest = ActiveUnderstandingView::canonical_output_digest(
        &admitted.binding,
        &recipe.recipe_sha256,
        &fence_digest,
        &rendered_for(admitted),
    )
    .expect("fixture rendered digest");
    card.output
        .omission_handles
        .clone_from(&admitted.economy.displaced);
    card.output.evidence_revisions = admitted
        .records
        .iter()
        .map(|record| record.candidate.source.snapshot_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    card
}

/// The rendered order this fixture's approved revision declares: declared role
/// position, then provider, then atom identity. The positions
/// [`approved_policy`] assigns are `SemanticRole` ordinals, so this projection
/// and the approved revision's `layout.role_positions` state one order.
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

fn recipe(context: &ContextBinding) -> ContextRecipe {
    let provider = role();
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: DecisionRevision {
            decision_id: context.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("recipe revision"),
            // Sealed by `seal_recipe`: the approved revision this instance is
            // issued under, not a placeholder. See that function.
            policy_sha256: String::new(),
        },
        recipe_sha256: String::new(),
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
    seal_recipe(&mut recipe);
    recipe
}

/// Re-seal one instance against the approved revision it is now issued under.
///
/// #1724 made the approved revision part of the instance's own identity: the
/// assembly joins the instance's recorded `decision.policy_sha256`, the approved
/// revision's own digest and the admitted receipt's on one value
/// (`ContextRecipePolicy::binds_recipe`, `require_recipe_policy_binding`, and
/// `ActiveUnderstandingView::validate_against` on the way out). A placeholder
/// digest cannot satisfy that join, so the instance records the digest of the
/// revision [`approved_recipe`] actually builds for it.
fn seal_recipe(recipe: &mut ContextRecipe) {
    recipe.decision.policy_sha256 =
        approved_policy(&recipe.mandatory_roles, &recipe.role_policies).policy_sha256;
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
}

/// The approved recipe revision this fixture's compilation is issued under.
///
/// #1724 W4/W5. The delivery entrypoint renders under an APPROVED revision and
/// joins it to the instance and to the admitted receipt by digest, so a
/// placeholder cannot stand in for one: this builds a real
/// `ContextRecipePolicy` and seals its own `canonical_policy_digest`, and
/// [`seal_recipe`] records that digest on the instance.
///
/// It is derived FROM the instance's own role declarations instead of being one
/// shared fixture, because the approved content must declare what this instance
/// declares: `ContextRecipePolicy::binds_recipe` refuses a budgeted role the
/// instance governs no `RoleLossRule` for, and `render::render` refuses a
/// rendered role the revision does not position. Layout positions are assigned
/// in `SemanticRole` ordinal order, which is the order [`rendered_for`] above
/// projects.
fn approved_policy(
    mandatory_roles: &[SemanticRole],
    role_policies: &[RoleLossRule],
) -> ContextRecipePolicy {
    let features: Vec<SemanticRole> = mandatory_roles
        .iter()
        .chain(role_policies.iter().map(|rule| &rule.role))
        .copied()
        .collect::<std::collections::BTreeSet<SemanticRole>>()
        .into_iter()
        .collect();
    let mut policy = ContextRecipePolicy {
        policy_schema_version: CONTEXT_RECIPE_POLICY_SCHEMA_VERSION,
        policy_id: id("fixture-recipe-policy"),
        policy_revision: PolicyRevision::new(1).expect("fixture policy revision"),
        policy_sha256: String::new(),
        applicability: RecipeApplicability {
            task_profiles: vec!["fixture-task-profile".to_owned()],
            route_profiles: vec!["fixture-route-profile".to_owned()],
            impact_profiles: vec!["fixture-impact-profile".to_owned()],
            governance_profiles: vec!["fixture-governance-profile".to_owned()],
        },
        stages: vec![RecipeStage {
            stage_id: id(EXECUTED_CONTEXT_STAGE),
            semantic_role: *features
                .first()
                .expect("fixture instance configures at least one role"),
            predecessors: Vec::new(),
        }],
        candidate_features: features.clone(),
        admission: RecipeAdmissionPolicy {
            admission_rule: id("admission-rule"),
            safety_floor: id("safety-floor"),
            // A mandatory role may never also be suppressible, and this
            // revision suppresses nothing.
            suppressible_roles: Vec::new(),
        },
        section_budgets: role_policies
            .iter()
            .map(|rule| ContextSectionBudget {
                semantic_role: rule.role,
                unit_boundary_kind: BoundaryUnitKind::Unit,
                minimum_required_whole_units: 1,
                required_exact_references: vec![id("fixture-section-unit")],
                protected_floor_refs: Vec::new(),
                planning_maximum_whole_units: 64,
                planning_route_profile: "fixture-route-profile".to_owned(),
                // The instance's OWN per-role loss rule, which is what
                // `binds_recipe` compares against this member.
                omission_or_handle_policy: rule.loss_policy,
                degradation_behavior: EXECUTED_SECTION_DEGRADATION,
                disable_feature_when_floor_cannot_be_preserved: false,
            })
            .collect(),
        protected_reserve: ProtectedReservePolicy {
            reserves: ProtectedReserves {
                reasoning_reserve: 1,
                review_reserve: 1,
                evidence_reserve: 1,
                owner_ref: "fixture-protected-reserve".to_owned(),
            },
            margin_reserve: 1,
        },
        layout: RecipeLayoutPolicy {
            role_positions: features
                .iter()
                .enumerate()
                .map(|(position, semantic_role)| RecipeRolePosition {
                    semantic_role: *semantic_role,
                    position: u32::try_from(position).expect("fixture layout position"),
                })
                .collect(),
            repetition: EXECUTED_REPETITION_POLICY,
        },
        omission: RecipeOmissionPolicy {
            permitted_reasons: vec![OmissionReason::Capacity],
            non_recoverable_reasons: Vec::new(),
        },
        blocking_dimensions: vec![QualityDimension::FreshnessStateFenceCoherence],
        execution: RecipeExecutionContour {
            contour: id("fixture-compiler-contour"),
            generation: 1,
            transform: BoundaryTransformerRevision {
                transformer_id: "fixture-transform".to_owned(),
                revision: eliot_contracts::ContractVersion::new(1, 0, 0),
                configuration_sha256: digest(),
            },
        },
        qualification: RecipeQualification {
            qualification: id("fixture-qualification"),
            state: RecipeQualificationState::Qualified,
            counter_metrics: Vec::new(),
        },
        supersession: RecipeSupersession {
            activation: id("fixture-recipe-activation"),
        },
    };
    policy.policy_sha256 = policy
        .canonical_policy_digest()
        .expect("approved recipe policy digest");
    policy
}

/// The approved revision pinned for one exact instance, taken BY VALUE.
///
/// Every call site owns the exact instance value it passes as the delivery
/// entrypoint's `recipe` argument, so the approved revision is derived from that
/// owned value rather than from a re-borrow of a name that could mean something
/// else by the time it is read. What IS validated here is the approved revision
/// this helper built, so a fixture that cannot construct one fails loudly
/// instead of passing a revision the assembly would refuse.
fn approved_recipe(recipe: ContextRecipe) -> ResolvedContextRecipe {
    let ContextRecipe {
        mandatory_roles,
        role_policies,
        ..
    } = recipe;
    let policy = approved_policy(&mandatory_roles, &role_policies);
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
        .expect("fixture approved recipe revision digest");
    resolution
        .validate()
        .expect("fixture approved recipe revision resolves");
    resolution
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
    assemble_active_view_with_learning(
        value,
        &recipe(&context),
        &approved_recipe(recipe(&context)),
        quality_for(value, &recipe(&context)),
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
    let view = assemble_active_view(
        &plain,
        &recipe(&context),
        &approved_recipe(recipe(&context)),
        quality_for(&plain, &recipe(&context)),
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
