//! #1724 residual: the approved policy revision's identity is recoverable from
//! the `policy_sha256` a View and a `ContextEconomyReceipt` carry.
//!
//! Implementation step 5 of #1724 asks that "every successful View and its
//! `ContextEconomyReceipt` identify the exact policy recipe ID/revision/digest".
//! `ActiveUnderstandingView` and `ContextEconomyReceipt` carry `policy_sha256`
//! and no `policy_id`/`policy_revision` scalars. This file proves, rather than
//! asserts, that the scalar pair adds nothing the digest does not already fix:
//!
//! * `policy_sha256` is the digest of the WHOLE `ContextRecipePolicy`
//!   (`ContextRecipePolicy::canonical_policy_digest` serializes every member
//!   into `CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN`), so `policy_id` and
//!   `policy_revision` are inside it. Changing either scalar MUST move the
//!   digest. `policy_identity_scalars_are_inside_the_policy_digest` is the
//!   positive case.
//! * A revision whose recorded `policy_sha256` does not match its own content
//!   is refused by the owner validator. `recorded_digest_is_validated_against_policy_content`
//!   is the refusal case: a receipt naming a digest that no approved content
//!   produces cannot be resolved to immutable approved content at all, so
//!   carrying the scalars beside it could not have made it resolvable.
//!
//! Both directions are load-bearing for closing the residual: a digest that did
//! NOT cover the scalars would mean a View could name one revision's id and
//! another revision's content, and the wire would then need the scalars. Each
//! test therefore also asserts the negative half in the same case, so a change
//! that stopped covering a scalar fails here rather than silently reopening the
//! residual.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_context_contracts::{
    BoundaryDisposition, BoundaryTransformerRevision, BoundaryUnitKind,
    CONTEXT_RECIPE_POLICY_SCHEMA_VERSION, ContextRecipePolicy, ContextSectionBudget,
    CounterMetricMovement, EXECUTED_REPETITION_POLICY, LossPolicy, OmissionReason,
    ProtectedReservePolicy, QualityDimension, RecipeAdmissionPolicy, RecipeApplicability,
    RecipeCounterMetric, RecipeExecutionContour, RecipeLayoutPolicy, RecipeOmissionPolicy,
    RecipeQualification, RecipeQualificationState, RecipeRolePosition, RecipeStage,
    RecipeSupersession, SemanticRole,
};
use eliot_contracts::{ArtifactId, ContractVersion, PolicyRevision};
use eliot_receipts::ProtectedReserves;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

/// One approved, closed policy revision covering the single semantic role
/// `SemanticRole::Goal`.
///
/// It is a real record that passes `ContextRecipePolicy::validate` unchanged,
/// so the digest assertions below measure the owner validator's own domain and
/// not a hand-written expectation.
fn policy() -> ContextRecipePolicy {
    let mut policy = ContextRecipePolicy {
        policy_schema_version: CONTEXT_RECIPE_POLICY_SCHEMA_VERSION,
        policy_id: id("recipe.policy.goal"),
        policy_revision: PolicyRevision::new(1).expect("policy revision"),
        policy_sha256: "0".repeat(64),
        applicability: RecipeApplicability {
            task_profiles: vec!["task.default".to_owned()],
            route_profiles: vec!["route.standard".to_owned()],
            impact_profiles: vec!["impact.standard".to_owned()],
            governance_profiles: vec!["governance.standard".to_owned()],
        },
        stages: vec![RecipeStage {
            stage_id: id("recipe.stage.goal"),
            semantic_role: SemanticRole::Goal,
            predecessors: Vec::new(),
        }],
        candidate_features: vec![SemanticRole::Goal],
        admission: RecipeAdmissionPolicy {
            admission_rule: id("admission.rule.goal"),
            safety_floor: id("floor.goal"),
            suppressible_roles: Vec::new(),
        },
        section_budgets: vec![ContextSectionBudget {
            semantic_role: SemanticRole::Goal,
            unit_boundary_kind: BoundaryUnitKind::Unit,
            minimum_required_whole_units: 1,
            required_exact_references: vec![id("required.goal")],
            protected_floor_refs: vec![id("floor.ref.goal")],
            planning_maximum_whole_units: 4,
            planning_route_profile: "route.standard".to_owned(),
            omission_or_handle_policy: LossPolicy::NonDroppable,
            degradation_behavior: BoundaryDisposition::ExactHandleOnly,
            disable_feature_when_floor_cannot_be_preserved: true,
        }],
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
            role_positions: vec![RecipeRolePosition {
                semantic_role: SemanticRole::Goal,
                position: 0,
            }],
            // `RecipeRepetitionPolicy` is reachable through the exported
            // execution-support constant rather than a second export added here:
            // this crate already publishes the repetition treatment its own
            // execution path applies, and the fixture states the same one.
            repetition: EXECUTED_REPETITION_POLICY,
        },
        omission: RecipeOmissionPolicy {
            permitted_reasons: vec![OmissionReason::Capacity],
            non_recoverable_reasons: Vec::new(),
        },
        blocking_dimensions: vec![QualityDimension::AcceptanceDecisionCoverage],
        execution: RecipeExecutionContour {
            contour: id("contour.standard"),
            generation: 1,
            transform: BoundaryTransformerRevision {
                transformer_id: "transform.standard".to_owned(),
                revision: ContractVersion::new(1, 0, 0),
                configuration_sha256: "b".repeat(64),
            },
        },
        qualification: RecipeQualification {
            qualification: id("qualification.evidence"),
            state: RecipeQualificationState::Unqualified,
            counter_metrics: vec![RecipeCounterMetric {
                metric_id: id("metric.goal.coverage"),
                forbidden_movement: CounterMetricMovement::Increase,
            }],
        },
        supersession: RecipeSupersession {
            activation: id("activation.goal"),
        },
    };
    policy.policy_sha256 = policy
        .canonical_policy_digest()
        .expect("policy content digest");
    policy.validate().expect("closed approved policy revision");
    policy
}

/// POSITIVE: the digest of one approved revision is stable, and moving either
/// identity scalar moves it.
///
/// This is the case that closes the residual. A View or receipt carrying only
/// `policy_sha256` identifies the exact `policy_id`/`policy_revision` pair,
/// because the owner validator's own digest domain contains both scalars: the
/// revision that produced it is the only revision that can produce it.
#[test]
fn policy_identity_scalars_are_inside_the_policy_digest() {
    let baseline = policy();
    let baseline_digest = baseline
        .canonical_policy_digest()
        .expect("baseline content digest");

    // The recorded digest is the one the owner validator re-derives, so a
    // receipt naming this digest resolves to exactly this approved content.
    assert_eq!(baseline.policy_sha256, baseline_digest);

    // Re-deriving is stable: reading the identity twice does not move it.
    assert_eq!(
        baseline
            .canonical_policy_digest()
            .expect("re-derived digest"),
        baseline_digest
    );

    let mut other_id = baseline.clone();
    other_id.policy_id = id("recipe.policy.goal.relabelled");
    other_id.policy_sha256 = "0".repeat(64);
    let relabelled = other_id
        .canonical_policy_digest()
        .expect("relabelled content digest");
    assert_ne!(
        relabelled, baseline_digest,
        "policy_id is inside the digest domain: a relabelled revision must not \
         keep the digest of the revision it was relabelled from"
    );

    let mut other_revision = baseline.clone();
    other_revision.policy_revision = PolicyRevision::new(2).expect("other policy revision");
    other_revision.policy_sha256 = "0".repeat(64);
    let reissued = other_revision
        .canonical_policy_digest()
        .expect("re-issued content digest");
    assert_ne!(
        reissued, baseline_digest,
        "policy_revision is inside the digest domain: re-issuing a revision must \
         not keep the previous revision's digest"
    );

    // Both moved, so neither scalar rides along outside the digest.
    assert_ne!(relabelled, reissued);
}

/// REFUSAL: a policy whose recorded `policy_sha256` is not its own content's
/// digest is refused by the owner validator.
///
/// A View or receipt naming such a digest names content no approved revision
/// produces, so it cannot be resolved to immutable approved content. This is
/// the typed refusal `ContextError::IdentityConflict`, the same failure the
/// neighbouring identity comparisons raise.
#[test]
fn recorded_digest_is_validated_against_policy_content() {
    let valid = policy();

    // An independently valid revision's digest is refused by a revision that
    // does not produce it: the two records cannot be substituted for one
    // another even though each is individually well-formed.
    let mut other = policy();
    other.policy_id = id("recipe.policy.goal.other");
    other.policy_sha256 = "0".repeat(64);
    other.policy_sha256 = other
        .canonical_policy_digest()
        .expect("other content digest");
    other
        .validate()
        .expect("other revision is independently valid");

    let mut substituted = valid.clone();
    substituted.policy_sha256 = other.policy_sha256.clone();
    assert_eq!(
        substituted.validate(),
        Err(eliot_context_contracts::ContextError::IdentityConflict),
        "a revision carrying another revision's content digest must be refused \
         rather than accepted as that revision"
    );

    // A digest that is well-formed but names no approved content at all is
    // refused the same way, so a receipt cannot name an unresolvable revision.
    let mut unattested = valid.clone();
    unattested.policy_sha256 = "c".repeat(64);
    assert_eq!(
        unattested.validate(),
        Err(eliot_context_contracts::ContextError::IdentityConflict)
    );
}
