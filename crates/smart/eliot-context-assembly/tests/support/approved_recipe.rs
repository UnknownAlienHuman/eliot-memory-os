//! Shared approved-recipe fixture for the A-18 assembly tests.
//!
//! `assemble_active_view`, `assemble_active_view_with_measurement` and
//! `assemble_active_view_with_learning` all take the approved
//! [`ResolvedContextRecipe`] whose declared layout order the projection applies.
//! The three test binaries that call them each need one, and each already
//! builds its own `ContextRecipe`, so the approved revision here is derived
//! from that instance rather than hardcoded: `policy_sha256` must equal the
//! recipe's own recorded `DecisionRevision::policy_sha256`, and the policy's
//! section budgets must cover the instance's mandatory roles and agree with its
//! per-role loss rules, or `ContextRecipePolicy::binds_recipe` refuses.
//!
//! Every setting this owner actually executes is read from the contract's own
//! `EXECUTED_*` constants, so the fixture cannot disagree with the execution
//! path it is proving.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_context_contracts::{
    CONTEXT_RECIPE_POLICY_SCHEMA_VERSION, ContextRecipe, ContextRecipePolicy, ContextSectionBudget,
    CounterMetricMovement, EXECUTED_CONTEXT_STAGE, EXECUTED_REPETITION_POLICY,
    EXECUTED_SECTION_DEGRADATION, LossPolicy, OmissionReason, ProtectedReservePolicy,
    QualityDimension, RecipeAdmissionPolicy, RecipeApplicability, RecipeCounterMetric,
    RecipeExecutionContour, RecipeLayoutPolicy, RecipeOmissionPolicy, RecipeQualification,
    RecipeQualificationState, RecipeRolePosition, RecipeStage, RecipeSupersession,
    ResolvedContextRecipe, SemanticRole,
};
use eliot_contracts::{ArtifactId, ContractVersion, PolicyRevision};
use eliot_receipts::ProtectedReserves;

/// The boundary unit kind this execution path actually applies.
const EXECUTED_UNIT_KIND: eliot_context_contracts::BoundaryUnitKind =
    eliot_context_contracts::BoundaryUnitKind::Unit;

/// One approved, closed policy revision bound to `recipe`.
///
/// Mirrors `crates/smart/eliot-context-contracts/tests/recipe_policy_identity.rs`,
/// which is the owner-side proof that a policy of this shape passes
/// `ContextRecipePolicy::validate` unchanged.
/// The approved `ResolvedContextRecipe` for `recipe`.
///
/// The instance and the approved revision are ONE agreement, so a caller that
/// builds its recipe must call [`seal`] while building it, before anything
/// derives a digest from it:
///
/// ```ignore
/// let recipe = seal(recipe(&context));
/// assemble_active_view(&value, &recipe, &approved_for(&recipe), ...);
/// ```
///
/// `ContextRecipePolicy::validate` proves the revision's recorded digest is its
/// own content, and `binds_recipe` proves the instance names exactly that
/// revision. Neither digest may move afterwards: the admitted set's economy
/// receipt and the reservation both name the instance's `recipe_sha256`, so
/// sealing after admission would refuse the pair for a reason no caller can see.
pub fn approved_for(recipe: &ContextRecipe) -> ResolvedContextRecipe {
    approved_and_digest(recipe).0
}

/// The approved revision together with the digest its instance must record.
pub fn approved_and_digest(recipe: &ContextRecipe) -> (ResolvedContextRecipe, String) {
    // The approved revision must be the SAME revision the instance was issued
    // under, so its identity scalars and content digest are derived from the
    // instance rather than invented.
    let roles = configured_roles(recipe);
    let mut policy = approved_policy(recipe, &roles);
    // The recorded digest must be this revision's OWN content digest: that is what
    // `ContextRecipePolicy::validate` re-derives, so a revision carrying another
    // digest names content no approved revision produces.
    policy.policy_sha256 = policy
        .canonical_policy_digest()
        .expect("approved policy content digest");
    policy.validate().expect("closed approved policy revision");
    let policy_digest = policy.policy_sha256.clone();
    // `ResolvedContextRecipe::validate` requires the resolution's approval to be
    // the exact activation decision the selected policy names, so the two are
    // one record and carry the same identity.
    let activation = policy.supersession.activation.clone();

    let mut resolution = ResolvedContextRecipe {
        identity: eliot_context_contracts::RecipePolicyIdentity {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.policy_revision,
            policy_sha256: policy.policy_sha256.clone(),
        },
        // `ResolvedContextRecipe::validate` requires the resolution's approval to be
        // the exact activation decision the selected policy names, so the two
        // are one record and both carry the same identity.
        policy,
        approval: activation,
        applicability: RecipeApplicability {
            task_profiles: vec!["task.default".to_owned()],
            route_profiles: vec!["route.standard".to_owned()],
            impact_profiles: vec!["impact.standard".to_owned()],
            governance_profiles: vec!["governance.standard".to_owned()],
        },
        execution: RecipeExecutionContour {
            contour: ArtifactId::new("contour.assembly-fixture").expect("fixture contour"),
            generation: 1,
            transform: eliot_context_contracts::BoundaryTransformerRevision {
                transformer_id: "transform.assembly-fixture".to_owned(),
                revision: ContractVersion::new(1, 0, 0),
                configuration_sha256: "b".repeat(64),
            },
        },
        resolution_sha256: "0".repeat(64),
    };
    resolution.resolution_sha256 = resolution
        .canonical_resolution_digest()
        .expect("resolution digest");
    (resolution, policy_digest)
}

/// Seal `recipe` so it names the approved revision [`approved_for`] returns,
/// then re-derive the instance's own digest so the two agree.
///
/// Call this where the instance is BUILT, before anything derives a digest
/// from it. Nothing may re-seal it afterwards: the admitted set's economy
/// receipt and the reservation both name `recipe_sha256`, so a later change to
/// the instance would make the admitted set describe a different recipe.
pub fn seal(mut recipe: ContextRecipe) -> ContextRecipe {
    // The approved revision is derived from this instance, so ask for it once
    // and record the digest it publishes.
    let (approved, policy_digest) = approved_and_digest(&recipe);
    debug_assert_eq!(
        approved.policy.policy_sha256, policy_digest,
        "the approved revision publishes the digest it seals the instance with"
    );
    recipe.decision.policy_sha256 = policy_digest;
    recipe.recipe_sha256 = recipe
        .canonical_policy_digest()
        .expect("sealed instance recipe digest");
    recipe
}

/// Exactly the roles this instance needs the approved revision to configure:
/// its mandatory roles plus every role it carries a loss rule for.
fn configured_roles(recipe: &ContextRecipe) -> Vec<SemanticRole> {
    let mut roles: Vec<SemanticRole> = recipe.mandatory_roles.clone();
    for rule in &recipe.role_policies {
        if !roles.contains(&rule.role) {
            roles.push(rule.role);
        }
    }
    roles.sort();
    roles.dedup();
    roles
}

/// The instance's own loss rule for this role, so the policy's section budget
/// cannot disagree with the recipe it approves.
fn role_loss_policy(recipe: &ContextRecipe, role: SemanticRole) -> LossPolicy {
    recipe
        .role_policies
        .iter()
        .find(|rule| rule.role == role)
        .map_or(LossPolicy::NonDroppable, |rule| rule.loss_policy)
}

/// One closed approved revision covering exactly the roles this instance needs.
///
/// Every setting the assembly path executes is read from the contract's own
/// `EXECUTED_*` constants, so this fixture cannot disagree with the execution
/// path it proves, and every section budget mirrors the instance's own loss
/// rule so `ContextRecipePolicy::binds_recipe` cannot refuse the pair.
fn approved_policy(recipe: &ContextRecipe, roles: &[SemanticRole]) -> ContextRecipePolicy {
    ContextRecipePolicy {
        policy_schema_version: CONTEXT_RECIPE_POLICY_SCHEMA_VERSION,
        policy_id: ArtifactId::new("recipe.policy.assembly-fixture")
            .expect("fixture policy identity"),
        policy_revision: PolicyRevision::new(1).expect("fixture policy revision"),
        policy_sha256: "0".repeat(64),
        applicability: fixture_applicability(),
        stages: vec![RecipeStage {
            stage_id: ArtifactId::new(EXECUTED_CONTEXT_STAGE).expect("executed stage id"),
            semantic_role: SemanticRole::Goal,
            predecessors: Vec::new(),
        }],
        candidate_features: roles.to_vec(),
        admission: RecipeAdmissionPolicy {
            admission_rule: ArtifactId::new("admission.rule.assembly-fixture")
                .expect("fixture admission rule"),
            safety_floor: ArtifactId::new("floor.assembly-fixture").expect("fixture floor"),
            suppressible_roles: Vec::new(),
        },
        section_budgets: roles
            .iter()
            .map(|role| ContextSectionBudget {
                semantic_role: *role,
                unit_boundary_kind: EXECUTED_UNIT_KIND,
                minimum_required_whole_units: 1,
                required_exact_references: vec![
                    ArtifactId::new("required.fixture").expect("fixture required reference"),
                ],
                protected_floor_refs: vec![
                    ArtifactId::new("floor.ref.fixture").expect("fixture floor reference"),
                ],
                planning_maximum_whole_units: 4,
                planning_route_profile: "route.standard".to_owned(),
                omission_or_handle_policy: role_loss_policy(recipe, *role),
                degradation_behavior: EXECUTED_SECTION_DEGRADATION,
                disable_feature_when_floor_cannot_be_preserved: false,
            })
            .collect(),
        protected_reserve: ProtectedReservePolicy {
            reserves: ProtectedReserves {
                reasoning_reserve: 1,
                review_reserve: 1,
                evidence_reserve: 1,
                owner_ref: "protected-reserve-owner".to_owned(),
            },
            margin_reserve: 1,
        },
        layout: RecipeLayoutPolicy {
            role_positions: roles
                .iter()
                .enumerate()
                .map(|(position, role)| RecipeRolePosition {
                    semantic_role: *role,
                    position: u32::try_from(position).expect("bounded role position"),
                })
                .collect(),
            repetition: EXECUTED_REPETITION_POLICY,
        },
        omission: RecipeOmissionPolicy {
            permitted_reasons: vec![OmissionReason::Capacity],
            non_recoverable_reasons: Vec::new(),
        },
        blocking_dimensions: vec![QualityDimension::AcceptanceDecisionCoverage],
        execution: fixture_execution(),
        qualification: RecipeQualification {
            qualification: ArtifactId::new("qualification.assembly-fixture")
                .expect("fixture qualification"),
            state: RecipeQualificationState::Unqualified,
            counter_metrics: vec![RecipeCounterMetric {
                metric_id: ArtifactId::new("metric.assembly-fixture.coverage")
                    .expect("fixture counter metric"),
                forbidden_movement: CounterMetricMovement::Increase,
            }],
        },
        supersession: RecipeSupersession {
            activation: ArtifactId::new("activation.assembly-fixture").expect("fixture activation"),
        },
    }
}

/// The four applicability dimensions this fixture revision is declared against.
fn fixture_applicability() -> RecipeApplicability {
    RecipeApplicability {
        task_profiles: vec!["task.default".to_owned()],
        route_profiles: vec!["route.standard".to_owned()],
        impact_profiles: vec!["impact.standard".to_owned()],
        governance_profiles: vec!["governance.standard".to_owned()],
    }
}

/// The execution contour the resolution and the selected policy must agree on.
///
/// `ResolvedContextRecipe::validate` compares these two by value, so both
/// sides carry this one record rather than two spellings of it.
fn fixture_execution() -> RecipeExecutionContour {
    RecipeExecutionContour {
        contour: ArtifactId::new("contour.assembly-fixture").expect("fixture contour"),
        generation: 1,
        transform: eliot_context_contracts::BoundaryTransformerRevision {
            transformer_id: "transform.assembly-fixture".to_owned(),
            revision: ContractVersion::new(1, 0, 0),
            configuration_sha256: "b".repeat(64),
        },
    }
}
