//! Stable reusable `ContextRecipe` policy definition (I12.13).
//!
//! [`ContextRecipe`](crate::ContextRecipe) in `atom.rs` is the
//! compilation-bound instance: it carries the [`ContextBinding`](crate::ContextBinding),
//! a [`DecisionRevision`](crate::DecisionRevision) whose `recipe_revision` is a
//! `TaskRevision`, the provider/role denominator, the per-role loss rules, the
//! capacity envelope, the predecessor, the invalidation, and a
//! `recipe_sha256` digest that covers all of that — the compilation binding
//! included. I12.13 asks for a *versioned, reusable* recipe that is approved
//! once and applied to many compilations, and W1 of #1724 requires that this
//! policy definition be separated from that instance and from the task/input
//! revision. This module is that definition.
//!
//! It is a sibling of [`ContextRecipe`](crate::ContextRecipe), not a second
//! copy of it and not a replacement. Nothing here re-declares the denominator,
//! the per-role loss rules, the capacity envelope or the compilation binding;
//! those stay where the instance already keeps them. The two halves are joined
//! by [`ContextRecipePolicy::binds_recipe`], which compares the ORIGINAL
//! recorded values of both records.
//!
//! Field-by-field mapping of the I12.13 `ContextRecipe` block
//! (`docs/architecture/I12-13-context-compiler.md`, lines 35-50):
//!
//! ```text
//! recipe_id_revision_and_digest              -> policy_id, policy_revision, policy_sha256
//! applicable_task_route_impact_and_governance
//!   _profiles                                -> applicability
//! stage_graph_and_order                      -> stages (declared order is the graph order)
//! candidate_feature_configuration            -> candidate_features
//! admission_and_suppression_policy           -> admission
//! instruction_directive_evidence_tool_and
//!   result_budgets                           -> section_budgets
//! protected_reasoning_review_and_margin
//!   _reserve                                 -> protected_reserve
//! layout_position_and_repetition_policy      -> layout
//! omission_and_expansion_policy              -> omission
//! scorecard_blocking_dimensions              -> blocking_dimensions
//! execution_contour_and_generation           -> execution
//! empirical_qualification_and_counter_metrics-> qualification
//! parent_supersession_kill_and_rollback      -> supersession
//! ```
//!
//! Already covered by the existing instance and therefore deliberately absent
//! here: the provider/role denominator, the per-role loss rules
//! ([`RoleLossRule`](crate::RoleLossRule)), the route/output/review reserves
//! ([`CapacityLimits`](crate::CapacityLimits)), and the parent policy reference
//! (`ContextRecipe::predecessor`).
//!
//! I12.13 also states that a recipe cannot weaken the `Decision Safety Floor`,
//! `ContextAtomPolicy` classes, authority/privacy, active `Recovery`/`Conflict`
//! Directives, reversible omission or proof ceilings. The two rules that
//! belong to the policy record itself are enforced here: a mandatory role of
//! the instance may never be a role this policy declares suppressible, and a
//! privacy/authority omission may never be declared reversible. Everything
//! else in that sentence needs the independent owners and belongs to W3, not
//! to this schema.
//!
//! # W2 — resolving exactly one applicable approved recipe
//!
//! A [`ContextRecipePolicy`] is a versioned definition, not a selection. The
//! selection itself is [`ApprovedRecipeCatalogue`]: the owner-published
//! configuration that carries the compilation's own applicability dimensions
//! and compiler-generation profile, the independent
//! [`GoverningContextRequirements`] every candidate is measured against, and
//! every approved candidate revision the owner currently holds.
//! [`ApprovedRecipeCatalogue::resolve`] returns exactly one
//! [`ResolvedContextRecipe`] or a typed [`RecipeResolutionRefusal`]. There is
//! no first-match, no latest-by-name and no default. Precedence used to be the
//! owner-minted [`PolicyRevision`]; #1724 W6 replaced it with the owner's
//! explicit current-recipe pointer, because a revision number is not an
//! activation authority. An unresolved governing input still refuses before any
//! candidate is examined.
//!
//! # W3 — validating against independent governing requirements
//!
//! [`GoverningContextRequirements`] composes records owned elsewhere in this
//! crate: the owner-issued [`DecisionSafetyFloor`](crate::DecisionSafetyFloor),
//! the six applicability inputs of
//! [`QualityApplicability`](crate::QualityApplicability) over the independent
//! [`QUALITY_APPLICABILITY_INPUTS`](crate::QUALITY_APPLICABILITY_INPUTS)
//! denominator, scorecard dimensions drawn from the independent
//! [`QUALITY_DIMENSIONS`] denominator, omission reasons owned by
//! [`OmissionRecord`](crate::OmissionRecord), and
//! [`ProofCeiling`](eliot_receipts::ProofCeiling). No field is derived from a
//! candidate recipe, so the comparisons in
//! [`GoverningContextRequirements::authorize`] are never a candidate checked
//! against a copy of its own content.
//!
//! Two named owners are deliberately NOT read here and are recorded as
//! boundaries instead of being replaced by a stand-in:
//!
//! * I7.11 `ContextAtomPolicy` class comparison is owned by
//!   `eliot-context-admission` (`FloorAtomPolicy`). That crate depends on this
//!   one, so this contract cannot read its record content; the only binding
//!   available here is the admission-rule/floor evidence identity compared in
//!   `authorize`.
//! * I12.13's active `Recovery`/`Conflict` Directives have no record type
//!   anywhere in the workspace. The only owner spelling is
//!   [`QualityApplicabilityInput::ActiveDirective`], so that is what is
//!   resolved: an unresolved directive input refuses the whole resolution.
//!
//! # W7 — supersession and rollback as new owner decisions
//!
//! [`RecipeActivationRecord`] is the decision that made an approved revision
//! current; it names the exact predecessor it supersedes and the applicability
//! and compiler-generation scope it is confined to.
//! [`RecipeRevocationRecord`] is the decision that killed or rolled a revision
//! back, naming the previous compatible revision a rollback returns to.
//!
//! Neither is stored ON the approved content. That is the whole point: a kill or
//! a rollback used to be a mutable field of [`RecipeSupersession`], so revoking
//! a revision meant editing the bytes that revision's `policy_sha256` covers.
//! Every View and `ContextEconomyReceipt` produced under it still names that
//! digest, so the edit silently relabelled historical evidence instead of
//! superseding it. With the decision held beside the content, the approved
//! revision is immutable forever: a View that names `policy_sha256` P keeps
//! naming P whether or not P was later revoked, and a re-resolution under a
//! newer catalogue produces a different `resolution_sha256` rather than
//! restamping the old one.
//!
//! # W6 — recipes change only through the existing improvement gate
//!
//! I12.13: "It may be changed only as an Improvement Candidate through replay,
//! shadow/canary and rollback." The restated invariant is that a candidate, a
//! valid hash, a smaller packet or a positive token saving is NOT permission to
//! activate. Three mechanisms carry it, and none of them is a new gate: the
//! existing [`RecipeActivationRecord`] is the owner promotion decision, and this
//! slice adds only what it did not state.
//!
//! 1. [`ApprovedRecipeCatalogue::current`] is the current recipe pointer, an
//!    explicit required owner-published field. [`ApprovedRecipeCatalogue::resolve`]
//!    reads it and nothing else. It previously took the applicable candidate
//!    with the greatest [`PolicyRevision`], which made a revision NUMBER the
//!    authority: publishing a newer approved candidate silently promoted it
//!    with no promotion decision at all. Revision ordering no longer appears in
//!    selection. A held, unrevoked, applicable candidate the pointer does not
//!    name is refused as
//!    [`RecipeResolutionRefusal::ApplicableCandidateNotCurrent`] rather than
//!    selected or ignored.
//! 2. [`RecipePromotionBasis`] is the basis the promotion decision was made
//!    under, held on that decision. `InitialBuiltInBaseline` preserves an
//!    explicitly approved initial/built-in baseline with no fabricated prior
//!    experimental evidence — it is the only basis with no predecessor, and it
//!    is the only one that may carry
//!    [`RecipeQualificationState::Unqualified`].
//!    `ImprovementCandidate` carries a [`RecipeImprovementCandidate`] naming the
//!    exact predecessor, the exact proposed content, the applicability it was
//!    triaged against, the exact baseline, the replay/holdout evidence, the
//!    shadow-or-isolated-canary evidence and the counter-metrics measured
//!    against that baseline.
//! 3. An unqualified metric stays labelled unqualified. `RecipeQualificationState`
//!    is inside `policy_sha256`, so relabelling a revision produces a different
//!    identity and the pointer stops naming it; the gate adds the other half —
//!    a revision promoted as an Improvement Candidate whose own recorded metrics
//!    are still `Unqualified` is refused, because the replay/holdout and
//!    shadow/isolated-canary evidence the decision cites is then evidence about
//!    different metrics than the revision it promotes.
//!
//! The improvement candidate itself is an OWNER record and is referenced, not
//! copied: `eliot-improvement` (C1) depends on this crate, so `ImprovementSurface`
//! cannot be named from here and the surface identity is not restated as a
//! second vocabulary. This is the same owner-reference convention already used
//! for [`RecipeAdmissionPolicy::admission_rule`],
//! [`RecipeAdmissionPolicy::safety_floor`] and
//! [`RecipeQualification::qualification`].
//!
//! Run-time qualification experiments are later product-phase work. Nothing here
//! runs one, records an outcome, or defaults a missing one: the gate refuses
//! when the evidence reference is absent.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::{ArtifactId, PolicyRevision};
use eliot_receipts::{ProofCeiling, ProtectedReserves};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    BoundaryDisposition, BoundaryTransformerRevision, BoundaryUnitKind, ContextError,
    ContextRecipe, DecisionSafetyFloor, LossPolicy, NonRecoverableReason, OmissionReason,
    QUALITY_DIMENSIONS, QualityApplicability, QualityApplicabilityInput, QualityDimension,
    SemanticRole, validate_digest, validate_text,
};

/// Wire revision of the reusable recipe policy definition.
///
/// The field is required, the struct denies unknown fields, and an unknown
/// revision is refused by name. It is deliberately not
/// [`CONTEXT_CONTRACT_VERSION`](crate::CONTEXT_CONTRACT_VERSION): the
/// compilation-bound instance keeps the crate contract version, and a policy
/// revision is a different versioned thing. A payload that predates this
/// definition therefore cannot decode into it, which is the versioned
/// migration — the old accepted bytes stay with the old instance shape rather
/// than being read as a policy that declares nothing.
pub const CONTEXT_RECIPE_POLICY_SCHEMA_VERSION: u32 = 1;

/// Digest domain separator for the reusable recipe policy.
///
/// A separate domain from `ContextRecipe::canonical_policy_digest`, which
/// covers the compilation binding. One digest cannot be both a reusable policy
/// identity and a per-compilation instance identity, and the existing domain is
/// left exactly as it was.
pub const CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN: &str = "eliot.smart.context.recipe-policy.v1";

/// The one stage the current consolidated Context execution path runs.
///
/// I12.13 lets a policy declare a stage graph. The current path is a single
/// whole-unit compile-and-render stage with no predecessor edge, so a policy
/// that declares anything else is declaring a graph this path does not execute.
/// #1724 W4 requires such a policy to refuse at the point it would otherwise be
/// certified into a digest, instead of contributing a stage graph nothing reads.
pub const EXECUTED_CONTEXT_STAGE: &str = "context.stage.compile-and-render.v1";

/// The whole-unit disposition the current path applies when a section floor
/// cannot be preserved.
///
/// `BlockDependentDecisionOrEffect` is the boundary owner's own vocabulary for
/// "this operation applied no permitted degradation": the current admission and
/// assembly path never narrows, extracts or summarizes a section behind a
/// declared degradation, it refuses the dependent operation instead
/// (`ContextError::MissingFloor` / `AssemblyError::Incomplete`). A policy that
/// declares any other degradation would be describing behaviour this path does
/// not have, so it refuses rather than being digested.
pub const EXECUTED_SECTION_DEGRADATION: BoundaryDisposition =
    BoundaryDisposition::BlockDependentDecisionOrEffect;

/// The repetition treatment the current renderer actually applies.
///
/// `render` projects every admitted record exactly once, and
/// `AdmittedContextSet::validate` already refuses a repeated atom identity, so
/// the implemented treatment is "an identical unit is represented once". A
/// policy declaring a bounded repeat allowance or a repeat suppression would be
/// describing behaviour the renderer does not have.
pub const EXECUTED_REPETITION_POLICY: RecipeRepetitionPolicy =
    RecipeRepetitionPolicy::DeduplicateIdentical;

/// I12.13 `applicable_task_route_impact_and_governance_profiles`.
///
/// A profile is a named, owner-declared profile, not a caller-supplied value
/// and not a default. Each list is a genuine set: order inside one list carries
/// no meaning and is canonicalized by sorting for the policy digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeApplicability {
    /// Task profiles this policy revision applies to.
    pub task_profiles: Vec<String>,
    /// Route profiles this policy revision applies to.
    pub route_profiles: Vec<String>,
    /// Impact profiles this policy revision applies to.
    pub impact_profiles: Vec<String>,
    /// Governance profiles this policy revision applies to.
    pub governance_profiles: Vec<String>,
}

impl RecipeApplicability {
    fn validate(&self) -> Result<(), ContextError> {
        for (profiles, field) in [
            (
                &self.task_profiles,
                "recipe_policy.applicability.task_profiles",
            ),
            (
                &self.route_profiles,
                "recipe_policy.applicability.route_profiles",
            ),
            (
                &self.impact_profiles,
                "recipe_policy.applicability.impact_profiles",
            ),
            (
                &self.governance_profiles,
                "recipe_policy.applicability.governance_profiles",
            ),
        ] {
            if profiles.is_empty() || profiles.len() > 64 {
                return Err(ContextError::Bounds { field });
            }
            let mut seen = BTreeSet::new();
            for profile in profiles {
                validate_text(profile, field)?;
                if !seen.insert(profile.as_str()) {
                    return Err(ContextError::Duplicate(field));
                }
            }
        }
        Ok(())
    }

    /// Whether `declared` names every profile `required` names, in all four
    /// dimensions.
    ///
    /// This is the applicability rule I12.13 states and it is a subset test,
    /// not an equality test: a policy may apply more broadly than one
    /// compilation needs, but it cannot apply to a compilation whose declared
    /// profile it never names. A candidate therefore cannot widen its own
    /// applicability by editing the compilation side of the comparison.
    fn declared_covers(declared: &Self, required: &Self) -> bool {
        [
            (&declared.task_profiles, &required.task_profiles),
            (&declared.route_profiles, &required.route_profiles),
            (&declared.impact_profiles, &required.impact_profiles),
            (&declared.governance_profiles, &required.governance_profiles),
        ]
        .into_iter()
        .all(|(declared, required)| required.iter().all(|profile| declared.contains(profile)))
    }
}

/// One stage of the policy's stage graph.
///
/// The graph is expressed by `predecessors`; the position in
/// [`ContextRecipePolicy::stages`] is the execution order. A predecessor must
/// already have been declared, so the declared order is a topological order of
/// the graph instead of an arbitrary permutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeStage {
    /// Stable identity of this stage inside the policy.
    pub stage_id: ArtifactId,
    /// Semantic role this stage contributes.
    pub semantic_role: SemanticRole,
    /// Stages that must precede this one.
    pub predecessors: Vec<ArtifactId>,
}

/// I12.13 `admission_and_suppression_policy`.
///
/// The rule and floor are owner references, not copies: the admission rule and
/// the Decision Safety Floor keep their own owners and their own records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeAdmissionPolicy {
    /// Owner admission rule applied under this policy revision.
    pub admission_rule: ArtifactId,
    /// Owner Decision Safety Floor this policy revision admits against.
    pub safety_floor: ArtifactId,
    /// Roles this policy revision may suppress at admission.
    ///
    /// A role listed here may never also be a mandatory role of the
    /// compilation-bound instance; `binds_recipe` refuses that combination
    /// with the crate's own floor vocabulary.
    pub suppressible_roles: Vec<SemanticRole>,
}

impl RecipeAdmissionPolicy {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.admission_rule.as_str(),
            "recipe_policy.admission.admission_rule",
        )?;
        validate_text(
            self.safety_floor.as_str(),
            "recipe_policy.admission.safety_floor",
        )?;
        if self.suppressible_roles.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.admission.suppressible_roles",
            });
        }
        let mut seen = BTreeSet::new();
        for role in &self.suppressible_roles {
            if !seen.insert(*role) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.admission.suppressible_roles",
                ));
            }
        }
        Ok(())
    }
}

/// I12.13 `ContextSectionBudget`, expressed in whole addressable units.
///
/// The unit count is a count of whole units, never a token slice: a JSON
/// object, URL, source identity, tool call/result pair or evidence edge is
/// never divided to make a budget fit. The budget algorithm itself is not here
/// and is not reimplemented here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextSectionBudget {
    /// Semantic role this budget governs.
    pub semantic_role: SemanticRole,
    /// Whole-unit boundary kind of this section.
    pub unit_boundary_kind: BoundaryUnitKind,
    /// Minimum complete units retained for this role.
    pub minimum_required_whole_units: u64,
    /// Owner proof references for this section's protected floor.
    pub protected_floor_refs: Vec<ArtifactId>,
    /// Planning maximum, in the same whole units.
    pub planning_maximum_whole_units: u64,
    /// Permitted omission/handle policy for this section.
    pub omission_or_handle_policy: LossPolicy,
    /// Whole-unit degradation applied when the section cannot be preserved.
    pub degradation_behavior: BoundaryDisposition,
    /// Whether the optional feature is disabled when the floor cannot be kept.
    pub disable_feature_when_floor_cannot_be_preserved: bool,
}

impl ContextSectionBudget {
    fn validate(&self) -> Result<(), ContextError> {
        if self.minimum_required_whole_units == 0 {
            return Err(ContextError::MissingField(
                "section_budget.minimum_required_whole_units",
            ));
        }
        if self.planning_maximum_whole_units < self.minimum_required_whole_units {
            return Err(ContextError::CapacityExceeded);
        }
        if self.protected_floor_refs.len() > 64 {
            return Err(ContextError::Bounds {
                field: "section_budget.protected_floor_refs",
            });
        }
        let mut seen = BTreeSet::new();
        for reference in &self.protected_floor_refs {
            validate_text(reference.as_str(), "section_budget.protected_floor_refs")?;
            if !seen.insert(reference.clone()) {
                return Err(ContextError::Duplicate(
                    "section_budget.protected_floor_refs",
                ));
            }
        }
        Ok(())
    }
}

/// I12.13 `protected_reasoning_review_and_margin_reserve`.
///
/// The protected reasoning and review figures are the Context-budget owner's
/// existing [`ProtectedReserves`] record, reused verbatim rather than
/// re-declared, and the instance's [`CapacityLimits`](crate::CapacityLimits)
/// keeps the route, output and review capacity envelope. Only the protected
/// margin, which has no such owner record, is declared here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectedReservePolicy {
    /// Context-budget owner record of the protected reasoning/review reserve.
    pub reserves: ProtectedReserves,
    /// Protected margin reserve not covered by `reserves`.
    pub margin_reserve: u64,
}

impl ProtectedReservePolicy {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.reserves.owner_ref.as_str(),
            "recipe_policy.protected_reserve.reserves.owner_ref",
        )
    }
}

/// Declared layout position of one semantic role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeRolePosition {
    /// Positioned role.
    pub semantic_role: SemanticRole,
    /// Zero-based layout position.
    pub position: u32,
}

/// How repeated content is treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RecipeRepetitionPolicy {
    /// An identical unit is represented once.
    #[serde(rename = "DEDUPLICATE_IDENTICAL")]
    DeduplicateIdentical,
    /// A repeated unit is suppressed.
    #[serde(rename = "SUPPRESS_REPEATED")]
    SuppressRepeated,
    /// Repetition is permitted up to an explicit bound.
    #[serde(rename = "BOUNDED")]
    Bounded {
        /// Upper bound on repeats of one unit; never zero.
        maximum_repeats: u32,
    },
}

impl RecipeRepetitionPolicy {
    fn validate(self) -> Result<(), ContextError> {
        if matches!(self, Self::Bounded { maximum_repeats: 0 }) {
            return Err(ContextError::Bounds {
                field: "recipe_policy.layout.repetition.maximum_repeats",
            });
        }
        Ok(())
    }
}

/// I12.13 `layout_position_and_repetition_policy`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeLayoutPolicy {
    /// Declared position of each configured role.
    pub role_positions: Vec<RecipeRolePosition>,
    /// Repetition treatment applied to repeated content.
    pub repetition: RecipeRepetitionPolicy,
}

impl RecipeLayoutPolicy {
    fn validate(&self) -> Result<(), ContextError> {
        if self.role_positions.is_empty() || self.role_positions.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.layout.role_positions",
            });
        }
        let mut roles = BTreeSet::new();
        let mut positions = BTreeSet::new();
        for declared in &self.role_positions {
            if !roles.insert(declared.semantic_role) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.layout.role_positions.semantic_role",
                ));
            }
            if !positions.insert(declared.position) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.layout.role_positions.position",
                ));
            }
        }
        self.repetition.validate()
    }
}

/// I12.13 `omission_and_expansion_policy`.
///
/// A permitted reason that is not declared non-recoverable is reversible: an
/// exact expansion handle stands in for it. A privacy or authority omission
/// has no reversible form, so I12.13's ceiling that a recipe "cannot weaken
/// ... authority/privacy, reversible omission" requires those two reasons to
/// be declared non-recoverable here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeOmissionPolicy {
    /// Omission reasons this policy revision may apply.
    pub permitted_reasons: Vec<OmissionReason>,
    /// Reasons that may stand as an explicitly non-recoverable omission.
    pub non_recoverable_reasons: Vec<NonRecoverableReason>,
}

/// The non-recoverable reason an omitted protected unit must declare.
const fn non_recoverable_for(reason: OmissionReason) -> Option<NonRecoverableReason> {
    match reason {
        OmissionReason::Privacy => Some(NonRecoverableReason::Privacy),
        OmissionReason::Authority => Some(NonRecoverableReason::Authority),
        _ => None,
    }
}

impl RecipeOmissionPolicy {
    fn validate(&self) -> Result<(), ContextError> {
        if self.permitted_reasons.is_empty() || self.permitted_reasons.len() > 16 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.omission.permitted_reasons",
            });
        }
        if self.non_recoverable_reasons.len() > 16 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.omission.non_recoverable_reasons",
            });
        }
        let mut permitted = BTreeSet::new();
        for reason in &self.permitted_reasons {
            if !permitted.insert(*reason) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.omission.permitted_reasons",
                ));
            }
        }
        let mut declared = BTreeSet::new();
        for reason in &self.non_recoverable_reasons {
            if !declared.insert(*reason) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.omission.non_recoverable_reasons",
                ));
            }
        }
        for reason in &self.permitted_reasons {
            if let Some(required) = non_recoverable_for(*reason)
                && !declared.contains(&required)
            {
                return Err(ContextError::OmissionHandleInvalid);
            }
        }
        Ok(())
    }
}

/// I12.13 `execution_contour_and_generation`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeExecutionContour {
    /// Owner execution contour this policy revision runs under.
    pub contour: ArtifactId,
    /// Contour generation; the owner's own monotone execution generation.
    pub generation: u64,
    /// Exact transform identity and configuration the compilation is bound to.
    pub transform: BoundaryTransformerRevision,
}

impl RecipeExecutionContour {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.contour.as_str(), "recipe_policy.execution.contour")?;
        if self.generation == 0 {
            return Err(ContextError::MissingField(
                "recipe_policy.execution.generation",
            ));
        }
        validate_text(
            self.transform.transformer_id.as_str(),
            "recipe_policy.execution.transform.transformer_id",
        )?;
        validate_digest(
            &self.transform.configuration_sha256,
            "recipe_policy.execution.transform.configuration_sha256",
        )
    }
}

/// Whether this revision's recorded metrics are empirically qualified.
///
/// I12.13 and the improvement gate both require an unqualified metric to stay
/// labelled unqualified, so the state is recorded rather than inferred from the
/// presence of a qualification reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeQualificationState {
    /// Recorded metrics are not empirically qualified.
    Unqualified,
    /// Recorded metrics are qualified by the cited owner evidence.
    Qualified,
}

/// Direction in which a guardrail metric may not worsen.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CounterMetricMovement {
    /// The metric must not increase.
    Increase,
    /// The metric must not decrease.
    Decrease,
}

/// One counter-metric guardrail of this policy revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeCounterMetric {
    /// Owner metric identity.
    pub metric_id: ArtifactId,
    /// Direction in which the metric may not worsen.
    pub forbidden_movement: CounterMetricMovement,
}

/// I12.13 `empirical_qualification_and_counter_metrics`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeQualification {
    /// Owner qualification evidence reference for this revision's metrics.
    pub qualification: ArtifactId,
    /// Qualification state of the recorded metrics.
    pub state: RecipeQualificationState,
    /// Guardrail metrics that may not worsen under this revision.
    pub counter_metrics: Vec<RecipeCounterMetric>,
}

impl RecipeQualification {
    /// Closed guardrail-set bound, shared with the W6 improvement candidate so
    /// both records are checked by one rule instead of two that can drift. The
    /// two field names are passed separately because every refusal names the
    /// exact field it is about, and a runtime concatenation would not be a
    /// `&'static str`.
    pub(crate) fn validate_counter_metrics(
        metrics: &[RecipeCounterMetric],
        field: &'static str,
        metric_field: &'static str,
    ) -> Result<(), ContextError> {
        if metrics.len() > 64 {
            return Err(ContextError::Bounds { field });
        }
        let mut seen = BTreeSet::new();
        for metric in metrics {
            validate_text(metric.metric_id.as_str(), metric_field)?;
            if !seen.insert(metric.metric_id.clone()) {
                return Err(ContextError::Duplicate(metric_field));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.qualification.as_str(),
            "recipe_policy.qualification.qualification",
        )?;
        Self::validate_counter_metrics(
            &self.counter_metrics,
            "recipe_policy.qualification.counter_metrics",
            "recipe_policy.qualification.counter_metrics.metric_id",
        )
    }
}

/// I12.13 `parent_supersession_kill_and_rollback`.
///
/// The parent revision is the existing `ContextRecipe::predecessor` of the
/// instance, and the invalidation identity is its existing `invalidation`;
/// neither is repeated here. What the policy record keeps is the ONE owner
/// decision that made this revision current: [`RecipeActivationRecord`].
///
/// #1724 W7 removed the kill and rollback identities from this struct on
/// purpose. They were mutable fields ON the approved content, so a kill or a
/// rollback had to be expressed by editing the revision it revoked — which
/// re-hashes the approved content, destroys the immutability of the revision
/// that produced an existing View, and lets a later receipt be re-labelled
/// under a new `policy_sha256`. They are now
/// [`RecipeRevocationRecord`]s held beside the candidates: a new owner decision
/// naming the revoked identity, never a rewrite of that identity's bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeSupersession {
    /// Scoped activation record that made this revision current.
    pub activation: ArtifactId,
}

impl RecipeSupersession {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.activation.as_str(),
            "recipe_policy.supersession.activation",
        )
    }
}

/// Digest domain separator for one owner activation decision.
pub const RECIPE_ACTIVATION_DIGEST_DOMAIN: &str = "eliot.smart.context.recipe-activation.v1";

/// Digest domain separator for one owner kill/rollback decision.
pub const RECIPE_REVOCATION_DIGEST_DOMAIN: &str = "eliot.smart.context.recipe-revocation.v1";

/// One `PacketCompiler`-surface Improvement Candidate proposed against a recipe.
///
/// #1724 W6. I12.13: "It may be changed only as an Improvement Candidate through
/// replay, shadow/canary and rollback." Every element that sentence names is a
/// field here, and the two that only this crate can compare — the proposed
/// content and the guardrails — are compared against the real records by
/// [`RecipePromotionBasis`]'s check inside
/// [`ApprovedRecipeCatalogue::validate`], not merely recorded.
///
/// The candidate, the replay/holdout evidence and the canary evidence are OWNER
/// records and are referenced, not copied. `eliot-improvement` (C1) depends on
/// this crate, so its `ImprovementSurface` cannot be named here and its closed
/// vocabulary is deliberately not restated; naming a candidate by its owner
/// identity keeps the reference resolvable at the owner instead of duplicating
/// a spelling that a variant rename could desynchronize.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeImprovementCandidate {
    /// Owner Improvement Candidate record for this proposal.
    pub candidate: ArtifactId,
    /// Exact approved revision this candidate proposes to supersede.
    ///
    /// A candidate is tied to one predecessor, not to "whatever is current when
    /// it is promoted", so a decision cannot silently rebase a proposal onto a
    /// revision it was never measured against.
    pub predecessor: RecipePolicyIdentity,
    /// Exact approved revision this candidate proposes to make current.
    ///
    /// Checked against the activated identity of the promotion decision, so a
    /// candidate cannot be cited as the evidence for different content than the
    /// content it was measured on.
    pub proposed: RecipePolicyIdentity,
    /// Applicability this candidate was triaged and measured against.
    pub applicability: RecipeApplicability,
    /// Exact approved revision the replay/holdout comparison is measured
    /// against.
    ///
    /// Required, not defaulted: a comparison with no named baseline has no
    /// denominator. A built-in baseline carries no candidate record at all, so it
    /// never reaches this field.
    pub baseline: RecipePolicyIdentity,
    /// Owner replay/holdout evidence reference.
    pub replay_holdout: ArtifactId,
    /// Owner shadow or isolated canary evidence reference.
    pub canary: ArtifactId,
    /// Guardrail counter-metrics measured against `baseline`.
    ///
    /// Required and non-empty: a candidate measured against no guardrail is not
    /// a gated candidate, and a smaller packet or a positive token saving is
    /// not a guardrail.
    pub counter_metrics: Vec<RecipeCounterMetric>,
}

impl RecipeImprovementCandidate {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.candidate.as_str(), "improvement.candidate")?;
        self.predecessor.validate_identity()?;
        self.proposed.validate_identity()?;
        if self.predecessor == self.proposed {
            return Err(ContextError::IdentityConflict);
        }
        self.applicability.validate()?;
        self.baseline.validate_identity()?;
        validate_text(self.replay_holdout.as_str(), "improvement.replay_holdout")?;
        validate_text(self.canary.as_str(), "improvement.canary")?;
        RecipeQualification::validate_counter_metrics(
            &self.counter_metrics,
            "improvement.counter_metrics",
            "improvement.counter_metrics.metric_id",
        )?;
        if self.counter_metrics.is_empty() {
            return Err(ContextError::MissingField("improvement.counter_metrics"));
        }
        Ok(())
    }

    /// Whether every counter-metric the proposed policy declares was actually
    /// measured against the baseline.
    ///
    /// This is the content comparison a positive token saving cannot pass: a
    /// candidate that measured fewer guardrails than its proposed policy declares
    /// has not been checked against the guardrails it would ship with. It is
    /// candidate-versus-policy, NOT candidate-versus-an-independent denominator,
    /// because no owner record of the required guardrail set exists; the residual
    /// is named in the delivery report rather than papered over with a field
    /// invented here.
    fn covers_declared_counter_metrics(&self, policy: &ContextRecipePolicy) -> bool {
        let measured: BTreeSet<&ArtifactId> = self
            .counter_metrics
            .iter()
            .map(|metric| &metric.metric_id)
            .collect();
        policy
            .qualification
            .counter_metrics
            .iter()
            .all(|metric| measured.contains(&metric.metric_id))
    }
}

/// The basis an owner promotion decision was made under.
///
/// #1724 W6. Exactly two, and the choice is the whole gate: a revision is either
/// the explicitly approved initial/built-in baseline, or it is an Improvement
/// Candidate that carried replay/holdout and shadow-or-isolated-canary evidence.
/// There is no third "the owner felt like it" arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipePromotionBasis {
    /// The explicitly approved initial or built-in baseline.
    ///
    /// It has no predecessor — a revision that supersedes one is a successor, not
    /// a baseline — and it is the only basis that may record
    /// [`RecipeQualificationState::Unqualified`]. I7.11: the existing byte/token
    /// figures are unvalidated planning candidates until a route-specific profile
    /// is qualified, and this is how that is preserved rather than fabricated
    /// away: the baseline is current because it was explicitly approved, and its
    /// metrics keep saying they are unqualified.
    InitialBuiltInBaseline {
        /// Owner approval that established this revision as the initial
        /// baseline. Required, so a baseline is an approval and not a default.
        approval: ArtifactId,
    },
    /// An Improvement Candidate promoted through the existing improvement gate.
    ImprovementCandidate {
        /// The exact candidate, its predecessor, proposed content, applicability,
        /// baseline, replay/holdout, canary and counter-metrics.
        candidate: Box<RecipeImprovementCandidate>,
    },
}

impl RecipePromotionBasis {
    fn validate(&self) -> Result<(), ContextError> {
        match self {
            Self::InitialBuiltInBaseline { approval } => {
                validate_text(approval.as_str(), "promotion.initial_baseline.approval")
            }
            Self::ImprovementCandidate { candidate } => candidate.validate(),
        }
    }
}

/// The owner decision that made one approved revision current.
///
/// #1724 W7. A newly accepted recipe produces a NEW immutable revision plus this
/// record, which is what makes the change observable: it names the activated
/// identity, the exact predecessor it supersedes, the applicability and
/// compiler-generation scope the activation is confined to, and — #1724 W6 — the
/// [`RecipePromotionBasis`] the decision was made under. A decision confined
/// to a scope cannot be read as a global activation, and
/// [`ApprovedRecipeCatalogue::validate`] refuses a compilation whose own
/// applicability the activation does not cover, so a future decision revalidates
/// applicability rather than inheriting an old activation.
///
/// `basis` is inside `record_sha256`, so the gate evidence and the decision that
/// relied on it are covered by the decision's own recorded digest. Changing the
/// basis of an existing activation re-hashes that decision, which stops
/// [`ApprovedRecipeCatalogue::current`] from naming it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeActivationRecord {
    /// Owner decision identity that made `activated` current.
    pub decision: ArtifactId,
    /// The exact approved revision this decision activated.
    pub activated: RecipePolicyIdentity,
    /// The exact revision this one supersedes, when there is a predecessor.
    ///
    /// It is an identity, not content: the predecessor keeps its own bytes and
    /// its own activation, so a View produced under it still names a revision
    /// the owner actually approved.
    pub predecessor: Option<RecipePolicyIdentity>,
    /// Applicability scope this activation is confined to.
    pub applicability: RecipeApplicability,
    /// Compiler-generation scope this activation is confined to.
    pub execution: RecipeExecutionContour,
    /// The gate basis this decision was made under.
    pub basis: RecipePromotionBasis,
    /// Digest of this activation record.
    pub record_sha256: String,
}

#[derive(Serialize)]
struct RecipeActivationDigestInput<'a> {
    domain: &'static str,
    activation: &'a RecipeActivationRecord,
}

impl RecipeActivationRecord {
    /// Compute the digest expected in `record_sha256`.
    pub fn canonical_record_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.record_sha256 = "0".repeat(64);
        let input = RecipeActivationDigestInput {
            domain: RECIPE_ACTIVATION_DIGEST_DOMAIN,
            activation: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_activation.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validate the closed decision record and its own recorded digest.
    ///
    /// The basis is validated here for its own shape; the comparisons that need
    /// the activated policy's CONTENT — that the candidate's proposed content is
    /// this revision, that it covered this revision's guardrails, that a
    /// candidate's recorded metrics are qualified — belong to
    /// [`ApprovedRecipeCatalogue::validate`], which is the only place that holds
    /// the approved bytes.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.decision.as_str(), "recipe_activation.decision")?;
        self.activated.validate_identity()?;
        if let Some(predecessor) = &self.predecessor {
            if predecessor == &self.activated {
                return Err(ContextError::IdentityConflict);
            }
            predecessor.validate_identity()?;
        }
        self.applicability.validate()?;
        self.execution.validate()?;
        self.basis.validate()?;
        validate_digest(&self.record_sha256, "recipe_activation.record_sha256")?;
        if self.canonical_record_digest()? != self.record_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// The owner decision that killed or rolled back one approved revision.
///
/// #1724 W7. Rollback is a NEW decision naming the previous COMPATIBLE revision
/// the owner still holds; it never overwrites the revoked revision's content and
/// never edits the revision being returned to. `replacement` absent is a kill
/// with no replacement; present is a rollback to an identity the catalogue still
/// carries, which [`ApprovedRecipeCatalogue::validate`] requires.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeRevocationRecord {
    /// Owner decision identity that revoked the revision.
    pub decision: ArtifactId,
    /// The exact approved revision this decision revoked.
    pub revoked: RecipePolicyIdentity,
    /// The previous compatible revision this returns to, for a rollback.
    pub replacement: Option<RecipePolicyIdentity>,
    /// Digest of this revocation record.
    pub record_sha256: String,
}

#[derive(Serialize)]
struct RecipeRevocationDigestInput<'a> {
    domain: &'static str,
    revocation: &'a RecipeRevocationRecord,
}

impl RecipeRevocationRecord {
    /// Compute the digest expected in `record_sha256`.
    pub fn canonical_record_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.record_sha256 = "0".repeat(64);
        let input = RecipeRevocationDigestInput {
            domain: RECIPE_REVOCATION_DIGEST_DOMAIN,
            revocation: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_revocation.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validate the closed decision record and its own recorded digest.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.decision.as_str(), "recipe_revocation.decision")?;
        validate_text(self.revoked.policy_id.as_str(), "recipe_revocation.revoked")?;
        validate_digest(
            &self.revoked.policy_sha256,
            "recipe_revocation.revoked.policy_sha256",
        )?;
        if let Some(replacement) = &self.replacement {
            if replacement == &self.revoked {
                return Err(ContextError::IdentityConflict);
            }
            validate_text(
                replacement.policy_id.as_str(),
                "recipe_revocation.replacement",
            )?;
            validate_digest(
                &replacement.policy_sha256,
                "recipe_revocation.replacement.policy_sha256",
            )?;
        }
        validate_digest(&self.record_sha256, "recipe_revocation.record_sha256")?;
        if self.canonical_record_digest()? != self.record_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// One approved, reusable `ContextRecipe` policy revision.
///
/// The `policy_id`/`policy_revision` pair identifies the revision; the
/// `policy_sha256` binds its exact content in its own digest domain. None of
/// the three is a `TaskRevision`: the task/input revision belongs to the
/// compilation-bound instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRecipePolicy {
    /// Wire revision of this policy definition.
    pub policy_schema_version: u32,
    /// Stable identity of this policy.
    pub policy_id: ArtifactId,
    /// Reusable policy revision, distinct from any task revision.
    pub policy_revision: PolicyRevision,
    /// Digest of this policy's content in the policy digest domain.
    pub policy_sha256: String,
    /// Task/route/impact/governance applicability.
    pub applicability: RecipeApplicability,
    /// Stage graph, in execution order.
    pub stages: Vec<RecipeStage>,
    /// Candidate features this revision configures.
    pub candidate_features: Vec<SemanticRole>,
    /// Admission and suppression policy.
    pub admission: RecipeAdmissionPolicy,
    /// Whole-unit section budgets.
    pub section_budgets: Vec<ContextSectionBudget>,
    /// Protected reasoning/review reserve and protected margin.
    pub protected_reserve: ProtectedReservePolicy,
    /// Layout, position and repetition policy.
    pub layout: RecipeLayoutPolicy,
    /// Omission and expansion policy.
    pub omission: RecipeOmissionPolicy,
    /// Scorecard dimensions that block this revision.
    pub blocking_dimensions: Vec<QualityDimension>,
    /// Execution contour and generation.
    pub execution: RecipeExecutionContour,
    /// Empirical qualification and counter-metrics.
    pub qualification: RecipeQualification,
    /// Activation, kill and rollback decisions.
    pub supersession: RecipeSupersession,
}

#[derive(Serialize)]
struct RecipePolicyDigestInput<'a> {
    domain: &'static str,
    policy: &'a ContextRecipePolicy,
}

impl ContextRecipePolicy {
    /// Compute the digest expected in `policy_sha256` for this policy.
    ///
    /// Genuine sets are sorted; `stages` is not, because stage order is
    /// meaning and not a set. `ContextRecipe::canonical_policy_digest` is
    /// untouched: its domain still covers the compilation binding.
    pub fn canonical_policy_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.policy_sha256 = "0".repeat(64);
        canonical.applicability.task_profiles.sort();
        canonical.applicability.route_profiles.sort();
        canonical.applicability.impact_profiles.sort();
        canonical.applicability.governance_profiles.sort();
        canonical.candidate_features.sort();
        canonical.admission.suppressible_roles.sort();
        canonical
            .section_budgets
            .sort_by_key(|budget| budget.semantic_role);
        canonical
            .layout
            .role_positions
            .sort_by_key(|declared| declared.semantic_role);
        canonical.omission.permitted_reasons.sort();
        canonical.omission.non_recoverable_reasons.sort();
        canonical.blocking_dimensions.sort();
        canonical
            .qualification
            .counter_metrics
            .sort_by(|left, right| left.metric_id.cmp(&right.metric_id));
        let input = RecipePolicyDigestInput {
            domain: CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN,
            policy: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_policy.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validate the closed policy record and its own recorded digest.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.policy_schema_version != CONTEXT_RECIPE_POLICY_SCHEMA_VERSION {
            return Err(ContextError::InvalidField(
                "recipe_policy.policy_schema_version",
            ));
        }
        validate_text(self.policy_id.as_str(), "recipe_policy.policy_id")?;
        validate_digest(&self.policy_sha256, "recipe_policy.policy_sha256")?;
        self.applicability.validate()?;
        let features = self.configured_features()?;
        self.validate_stage_order(&features)?;
        self.admission.validate()?;
        for role in &self.admission.suppressible_roles {
            if !features.contains(role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        self.validate_section_budgets(&features)?;
        self.protected_reserve.validate()?;
        self.layout.validate()?;
        for declared in &self.layout.role_positions {
            if !features.contains(&declared.semantic_role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        self.omission.validate()?;
        Self::validate_blocking_dimensions(&self.blocking_dimensions)?;
        self.execution.validate()?;
        self.qualification.validate()?;
        self.supersession.validate()?;
        if self.canonical_policy_digest()? != self.policy_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }

    /// Check that this exact approved policy is the one the compilation-bound
    /// instance was issued under.
    ///
    /// The ORIGINAL recorded values of both records are used: the instance's
    /// own `validate()` runs first, and the policy's recorded digest is
    /// compared with the digest the instance recorded in
    /// [`DecisionRevision::policy_sha256`](crate::DecisionRevision). No digest
    /// is recomputed here to stand in for that owner record, and a recipe may
    /// not make itself applicable by dropping a mandatory role, adding a
    /// feature the policy does not configure, or declaring a mandatory role
    /// suppressible.
    pub fn binds_recipe(&self, recipe: &ContextRecipe) -> Result<(), ContextError> {
        self.validate()?;
        recipe.validate()?;
        if recipe.decision.policy_sha256 != self.policy_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        let features = self.configured_features()?;
        for role in &recipe.mandatory_roles {
            if !features.contains(role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
            if self.admission.suppressible_roles.contains(role) {
                return Err(ContextError::MissingFloor);
            }
        }
        for rule in &recipe.role_policies {
            if !features.contains(&rule.role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        Ok(())
    }

    /// Refuse a policy that declares anything this execution path does not run.
    ///
    /// This is #1724 W4's refusal clause. Every field of a policy is inside
    /// `policy_sha256`, so an unsupported declaration would otherwise be
    /// certified: a re-hashed policy with a different stage graph, a different
    /// repetition treatment, a whole-unit degradation the path never applies or
    /// a feature disable it cannot perform would pass every digest check while
    /// changing nothing about the output. Acceptance A2 requires the opposite:
    /// a policy change must move the revision/digest and the effective compiler
    /// behaviour together, or refuse.
    ///
    /// The four comparisons are exact and one-directional — the policy must
    /// declare exactly what this path applies. Nothing here reads a value the
    /// policy did not declare, and no comparison is against a value derived
    /// from the policy itself. The refusal is a typed
    /// [`RecipeResolutionRefusal::UnsupportedSetting`] naming the exact field
    /// and the identity of the revision that declares it, so a dependent
    /// compilation is blocked with a name rather than a silent degradation.
    pub fn require_executable(
        &self,
        support: &RecipeExecutionSupport,
    ) -> Result<(), RecipeResolutionRefusal> {
        self.validate()
            .map_err(|error| RecipeResolutionRefusal::InvalidCatalogue {
                reason: error.to_string(),
            })?;
        support
            .validate()
            .map_err(|error| RecipeResolutionRefusal::InvalidCatalogue {
                reason: error.to_string(),
            })?;
        let identity = RecipePolicyIdentity::of(self);
        let unsupported = |field: &str| RecipeResolutionRefusal::UnsupportedSetting {
            identity: identity.clone(),
            field: field.to_owned(),
        };
        if self.stages.len() != 1
            || self.stages[0].stage_id != support.executed_stage
            || !self.stages[0].predecessors.is_empty()
        {
            return Err(unsupported("recipe_policy.stages"));
        }
        if self.layout.repetition != support.repetition {
            return Err(unsupported("recipe_policy.layout.repetition"));
        }
        for budget in &self.section_budgets {
            if budget.degradation_behavior != support.section_degradation {
                return Err(unsupported("section_budget.degradation_behavior"));
            }
            if budget.disable_feature_when_floor_cannot_be_preserved
                && !support.supports_feature_disable
            {
                return Err(unsupported(
                    "section_budget.disable_feature_when_floor_cannot_be_preserved",
                ));
            }
        }
        Ok(())
    }

    fn configured_features(&self) -> Result<BTreeSet<SemanticRole>, ContextError> {
        if self.candidate_features.is_empty() || self.candidate_features.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.candidate_features",
            });
        }
        let features: BTreeSet<SemanticRole> = self.candidate_features.iter().copied().collect();
        if features.len() != self.candidate_features.len() {
            return Err(ContextError::Duplicate("recipe_policy.candidate_features"));
        }
        Ok(features)
    }

    fn validate_stage_order(&self, features: &BTreeSet<SemanticRole>) -> Result<(), ContextError> {
        if self.stages.is_empty() || self.stages.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.stages",
            });
        }
        let mut declared = BTreeSet::new();
        for (position, stage) in self.stages.iter().enumerate() {
            validate_text(stage.stage_id.as_str(), "recipe_policy.stages.stage_id")?;
            if !declared.insert(stage.stage_id.clone()) {
                return Err(ContextError::Duplicate("recipe_policy.stages.stage_id"));
            }
            let mut edges = BTreeSet::new();
            for predecessor in &stage.predecessors {
                validate_text(predecessor.as_str(), "recipe_policy.stages.predecessors")?;
                if !edges.insert(predecessor.clone()) {
                    return Err(ContextError::Duplicate("recipe_policy.stages.predecessors"));
                }
                if !self.stages[..position]
                    .iter()
                    .any(|earlier| earlier.stage_id == *predecessor)
                {
                    return Err(ContextError::InvalidField(
                        "recipe_policy.stages.predecessors",
                    ));
                }
            }
        }
        for stage in &self.stages {
            if !features.contains(&stage.semantic_role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        Ok(())
    }

    fn validate_section_budgets(
        &self,
        features: &BTreeSet<SemanticRole>,
    ) -> Result<(), ContextError> {
        if self.section_budgets.is_empty() || self.section_budgets.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.section_budgets",
            });
        }
        let mut budgeted = BTreeSet::new();
        for budget in &self.section_budgets {
            if !budgeted.insert(budget.semantic_role) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.section_budgets.semantic_role",
                ));
            }
            if !features.contains(&budget.semantic_role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
            budget.validate()?;
        }
        Ok(())
    }

    fn validate_blocking_dimensions(dimensions: &[QualityDimension]) -> Result<(), ContextError> {
        if dimensions.is_empty() || dimensions.len() > QUALITY_DIMENSIONS.len() {
            return Err(ContextError::Bounds {
                field: "recipe_policy.blocking_dimensions",
            });
        }
        let mut seen = BTreeSet::new();
        for dimension in dimensions {
            if !QUALITY_DIMENSIONS.contains(dimension) || !seen.insert(*dimension) {
                return Err(ContextError::InvalidField(
                    "recipe_policy.blocking_dimensions",
                ));
            }
        }
        Ok(())
    }
}

/// The independent denominator of what one Context execution path actually runs.
///
/// #1724 W4: the current candidate admission, ordering, rendering and
/// scorecard/measurement must consume the pinned recipe rather than independent
/// hidden defaults, and a stage or feature that is not supported must refuse
/// instead of appearing in a certified digest while being ignored.
///
/// This record is the executing path's own statement of the concrete settings it
/// applies. It is built by the execution owner, never by a candidate recipe, so
/// [`ContextRecipePolicy::require_executable`] compares a policy against an
/// independent answer rather than against a copy of the policy's own
/// declarations. A member is only admitted here when the path that publishes
/// this record reads that value when it compiles and renders; adding a member
/// therefore means adding the execution that reads it, not widening a check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeExecutionSupport {
    /// Stage identity this path runs for every compilation.
    pub executed_stage: ArtifactId,
    /// Rendered-ordering revision this path applies. I12.13 makes ordering part
    /// of the recipe, so the revision that fixes the order is a compiled-in
    /// execution fact and is bound next to the stage it belongs to.
    pub ordering_revision: ArtifactId,
    /// Repetition treatment this path applies to repeated content.
    pub repetition: RecipeRepetitionPolicy,
    /// Whole-unit disposition this path applies when a section floor cannot be
    /// preserved.
    pub section_degradation: BoundaryDisposition,
    /// Whether this path can disable an optional feature when a section floor
    /// cannot be preserved.
    ///
    /// The current whole-unit admission and assembly path has no such disable:
    /// an unpreservable section blocks the dependent decision instead. The
    /// field is required rather than defaulted so an executing path that gains
    /// the capability states it explicitly, and a policy that relies on it
    /// refuses until it does.
    pub supports_feature_disable: bool,
}

impl RecipeExecutionSupport {
    /// Validate the closed support record before it is compared to a policy.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.executed_stage.as_str(),
            "recipe_support.executed_stage",
        )?;
        validate_text(
            self.ordering_revision.as_str(),
            "recipe_support.ordering_revision",
        )?;
        self.repetition.validate()?;
        Ok(())
    }
}

/// Digest domain separator for one pinned recipe resolution.
///
/// A third domain, after [`CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN`] and the
/// instance's own `canonical_policy_digest`. The resolution digest binds the
/// selected revision, its exact content, the approval decision, the
/// applicability dimensions and the compiler-generation profile, so a
/// resolution cannot be replayed against a different compilation.
pub const CONTEXT_RECIPE_RESOLUTION_DIGEST_DOMAIN: &str =
    "eliot.smart.context.recipe-resolution.v1";

/// The four applicability dimensions I12.13 declares a recipe against.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeApplicabilityDimension {
    /// `applicable_task_..._profiles`.
    Task,
    /// `..._route_..._profiles`.
    Route,
    /// `..._impact_..._profiles`.
    Impact,
    /// `..._governance_profiles`.
    Governance,
}

impl RecipeApplicabilityDimension {
    /// The declared profile list of this dimension.
    fn profiles(self, applicability: &RecipeApplicability) -> &[String] {
        match self {
            Self::Task => &applicability.task_profiles,
            Self::Route => &applicability.route_profiles,
            Self::Impact => &applicability.impact_profiles,
            Self::Governance => &applicability.governance_profiles,
        }
    }
}

/// Identity of exactly one approved policy revision.
///
/// These are the three values that recover the immutable approved content: the
/// policy identity, its owner-minted revision and the digest of its bytes in
/// the policy digest domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipePolicyIdentity {
    /// Stable identity of the selected policy.
    pub policy_id: ArtifactId,
    /// Owner-minted reusable policy revision.
    pub policy_revision: PolicyRevision,
    /// Digest of the selected policy's exact content.
    pub policy_sha256: String,
}

impl RecipePolicyIdentity {
    /// Read the identity an owner-published candidate already carries.
    fn of(policy: &ContextRecipePolicy) -> Self {
        Self {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.policy_revision,
            policy_sha256: policy.policy_sha256.clone(),
        }
    }

    /// Validate the identity's own recorded fields.
    ///
    /// An identity that names nothing, or whose digest is not a digest, cannot be
    /// a predecessor, a proposed content, a baseline or a current pointer, so it
    /// is refused before any content comparison is attempted. This checks the
    /// ORIGINAL recorded values only; it derives no digest of its own.
    fn validate_identity(&self) -> Result<(), ContextError> {
        validate_text(self.policy_id.as_str(), "recipe_policy_identity.policy_id")?;
        validate_digest(
            &self.policy_sha256,
            "recipe_policy_identity.policy_sha256",
        )
    }

    /// Check that this identity still names exactly this content.
    ///
    /// The ORIGINAL recorded values of both records are compared. No digest is
    /// recomputed here to stand in for the owner's record; the policy's own
    /// `validate` is what re-derives its content digest.
    fn validate(&self, policy: &ContextRecipePolicy) -> Result<(), ContextError> {
        policy.validate()?;
        if self.policy_id != policy.policy_id
            || self.policy_revision != policy.policy_revision
            || self.policy_sha256 != policy.policy_sha256
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// Why one owner-published candidate is not the resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeRejectionReason {
    /// An owner kill or rollback decision revoked this revision.
    Revoked {
        /// The owner decision that revoked the revision.
        decision: ArtifactId,
    },
    /// The candidate does not declare one applicability profile of this
    /// compilation.
    UndeclaredApplicability {
        /// Dimension whose profile the candidate never names.
        dimension: RecipeApplicabilityDimension,
        /// The exact profile the candidate omits.
        profile: String,
    },
    /// The candidate was issued under a different compiler-generation or route
    /// profile, including a different transform configuration digest.
    StaleCompilerGeneration {
        /// The compiler-generation profile this compilation runs under.
        expected: RecipeExecutionContour,
        /// The compiler-generation profile the candidate was issued under.
        observed: RecipeExecutionContour,
    },
}

/// One rejected candidate, with the exact reason it did not apply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeCandidateRejection {
    /// Identity of the rejected candidate.
    pub identity: RecipePolicyIdentity,
    /// Why it was not selected.
    pub reason: RecipeRejectionReason,
}

/// Typed refusal of a dependent Context compilation.
///
/// I12.13 requires a missing or ambiguous applicability to block the dependent
/// compilation rather than fall back. Every variant names what was missing or
/// which candidates were indistinguishable; none of them resolves to a default.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeResolutionRefusal {
    /// The owner configuration itself is not a closed, valid record, so no
    /// resolution may be attempted from it.
    InvalidCatalogue {
        /// Bounded field-level reason from the closed record validator.
        reason: String,
    },
    /// One or more of the six independent applicability inputs is unresolved,
    /// so the candidate set cannot be compared against a governing answer.
    UnresolvedGoverningInput {
        /// Every unresolved input, in canonical order.
        inputs: Vec<QualityApplicabilityInput>,
    },
    /// The revision the current pointer names is not an applicable candidate.
    NoApplicableCandidate {
        /// The pointed revision, with its exact rejection reason.
        rejected: Vec<RecipeCandidateRejection>,
    },
    /// The owner holds an approved, unrevoked, applicable revision that the
    /// current pointer does not name.
    ///
    /// #1724 W6. This arm is the refusal a "newest candidate wins" rule could
    /// not produce. A candidate is not permission to activate, so the resolution
    /// neither silently adopts it nor silently continues on the older revision:
    /// it blocks the dependent compilation until the owner promotion decision
    /// that names the candidate is published.
    ApplicableCandidateNotCurrent {
        /// The revision the current pointer does name.
        current: RecipePolicyIdentity,
        /// Every applicable, unrevoked revision the pointer does not name, in
        /// policy-identity order.
        unpointed: Vec<RecipePolicyIdentity>,
    },
    /// The selected revision declares a setting the executing Context path does
    /// not run, so certifying it would place that setting inside a delivered
    /// digest while ignoring it.
    UnsupportedSetting {
        /// Identity of the revision that declares the unsupported setting.
        identity: RecipePolicyIdentity,
        /// Exact policy field the execution path does not implement.
        field: String,
    },
}

fn applicability_input_label(input: QualityApplicabilityInput) -> &'static str {
    match input {
        QualityApplicabilityInput::TaskAcceptance => "task_acceptance",
        QualityApplicabilityInput::Route => "route",
        QualityApplicabilityInput::Impact => "impact",
        QualityApplicabilityInput::GovernanceProfile => "governance_profile",
        QualityApplicabilityInput::ProtectedFloor => "protected_floor",
        QualityApplicabilityInput::ActiveDirective => "active_directive",
    }
}

impl fmt::Display for RecipeResolutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCatalogue { reason } => {
                write!(formatter, "owner recipe catalogue is invalid: {reason}")
            }
            Self::UnresolvedGoverningInput { inputs } => {
                let labels: Vec<&str> = inputs
                    .iter()
                    .map(|input| applicability_input_label(*input))
                    .collect();
                write!(formatter, "governing applicability unresolved: {labels:?}")
            }
            Self::NoApplicableCandidate { rejected } => write!(
                formatter,
                "no applicable approved recipe among {} owner candidate(s)",
                rejected.len()
            ),
            Self::ApplicableCandidateNotCurrent { current, unpointed } => write!(
                formatter,
                "current pointer {} leaves {} applicable approved recipe(s) not yet promoted",
                current.policy_id.as_str(),
                unpointed.len()
            ),
            Self::UnsupportedSetting { identity, field } => write!(
                formatter,
                "approved recipe {} declares {field}, which this execution path does not run",
                identity.policy_id.as_str()
            ),
        }
    }
}

impl std::error::Error for RecipeResolutionRefusal {}

#[derive(Serialize)]
struct RecipeResolutionDigestInput<'a> {
    domain: &'static str,
    resolution: &'a ResolvedContextRecipe,
}

/// Exactly one applicable approved recipe, pinned for a whole compilation.
///
/// The pinned revision is recoverable: `identity` plus `policy` re-derive the
/// immutable approved content, `approval` names the owner decision that made
/// it current, and `execution` names the compiler-generation and route profile
/// the compilation is bound to. `resolution_sha256` binds all five, so a
/// resolution cannot be carried into another compilation, another revision or
/// another generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedContextRecipe {
    /// Identity of the selected revision.
    pub identity: RecipePolicyIdentity,
    /// The exact recoverable immutable approved content that was selected.
    pub policy: ContextRecipePolicy,
    /// Owner activation decision that made the selected revision current.
    pub approval: ArtifactId,
    /// Applicability dimensions this resolution was made against.
    pub applicability: RecipeApplicability,
    /// Compiler-generation and route profile this resolution is pinned to.
    pub execution: RecipeExecutionContour,
    /// Digest pinning identity, content, approval, applicability and execution.
    pub resolution_sha256: String,
}

impl ResolvedContextRecipe {
    /// Compute the digest expected in `resolution_sha256`.
    pub fn canonical_resolution_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.resolution_sha256 = "0".repeat(64);
        let input = RecipeResolutionDigestInput {
            domain: CONTEXT_RECIPE_RESOLUTION_DIGEST_DOMAIN,
            resolution: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_resolution.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Re-derive every recorded value of this resolution from the selected
    /// policy it carries.
    ///
    /// A stored resolution is not evidence of its own applicability: the
    /// approval must be the policy's own activation decision, the pinned
    /// compiler-generation profile must equal the policy's, the declared
    /// applicability must cover every profile this compilation named, and the
    /// recorded digest must match.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.identity.validate(&self.policy)?;
        validate_text(self.approval.as_str(), "recipe_resolution.approval")?;
        self.applicability.validate()?;
        if self.approval != self.policy.supersession.activation
            || self.execution != self.policy.execution
            || !RecipeApplicability::declared_covers(
                &self.policy.applicability,
                &self.applicability,
            )
        {
            return Err(ContextError::IdentityConflict);
        }
        validate_digest(
            &self.resolution_sha256,
            "recipe_resolution.resolution_sha256",
        )?;
        if self.canonical_resolution_digest()? != self.resolution_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// Independent governing requirements every candidate is validated against.
///
/// Every member is an owner record or an owner constant that exists outside
/// this module: the Decision Safety Floor for this decision boundary, the six
/// I12.13 applicability inputs with their resolved/unknown partition, the
/// scorecard dimensions the owner requires this revision to block on, the
/// omission reasons the owner requires the revision to be able to apply, the
/// complete ceiling of reasons that may be non-recoverable, and the maximum
/// proof this decision boundary may carry. None of them is read from, or
/// derivable from, a candidate recipe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningContextRequirements {
    /// Owner-issued Decision Safety Floor for this decision boundary.
    pub floor: DecisionSafetyFloor,
    /// Applicability inputs resolved before grading, from the quality owner.
    pub applicability: QualityApplicability,
    /// Scorecard dimensions the owner requires this revision to block on.
    ///
    /// The set is required and may not be empty: an owner requirement set that
    /// blocked nothing would let any candidate pass this dimension.
    pub required_blocking_dimensions: Vec<QualityDimension>,
    /// Omission reasons the owner requires this revision to be able to apply.
    pub required_omission_reasons: Vec<OmissionReason>,
    /// Complete ceiling of reasons that may stand as non-recoverable.
    ///
    /// This is a ceiling, not a floor: a recipe may declare fewer
    /// non-recoverable reasons than this, and any reason outside it refuses.
    pub permitted_non_recoverable_reasons: Vec<NonRecoverableReason>,
    /// Maximum proof this decision boundary may carry.
    pub required_proof_ceiling: ProofCeiling,
}

impl GoverningContextRequirements {
    fn validate(&self) -> Result<(), ContextError> {
        self.floor.validate()?;
        self.applicability.validate()?;
        Self::validate_blocking_dimensions(&self.required_blocking_dimensions)?;
        Self::distinct_omissions(
            &self.required_omission_reasons,
            "governing.required_omission_reasons",
        )?;
        Self::distinct_omissions(
            &self.permitted_non_recoverable_reasons,
            "governing.permitted_non_recoverable_reasons",
        )
    }

    fn validate_blocking_dimensions(dimensions: &[QualityDimension]) -> Result<(), ContextError> {
        if dimensions.is_empty() || dimensions.len() > QUALITY_DIMENSIONS.len() {
            return Err(ContextError::Bounds {
                field: "governing.required_blocking_dimensions",
            });
        }
        let mut seen = BTreeSet::new();
        for dimension in dimensions {
            if !QUALITY_DIMENSIONS.contains(dimension) || !seen.insert(*dimension) {
                return Err(ContextError::InvalidField(
                    "governing.required_blocking_dimensions",
                ));
            }
        }
        Ok(())
    }

    fn distinct_omissions<T: Copy + Ord>(
        reasons: &[T],
        field: &'static str,
    ) -> Result<(), ContextError> {
        if reasons.len() > 16 {
            return Err(ContextError::Bounds { field });
        }
        let mut seen = BTreeSet::new();
        for reason in reasons {
            if !seen.insert(*reason) {
                return Err(ContextError::Duplicate(field));
            }
        }
        Ok(())
    }

    /// Validate one resolved recipe against these requirements.
    ///
    /// The comparisons are set comparisons against owner requirements, so a
    /// candidate cannot make itself valid: it may not drop a role the floor
    /// makes mandatory, shave the floor's capacity envelope, block fewer
    /// scorecard dimensions than the owner requires, drop a required omission
    /// reason, widen the non-recoverable set beyond the owner's ceiling, or
    /// serve a decision boundary whose proof ceiling exceeds its empirical
    /// qualification.
    pub fn authorize(
        &self,
        resolved: &ResolvedContextRecipe,
        instance: &ContextRecipe,
    ) -> Result<(), ContextError> {
        self.validate()?;
        resolved.validate()?;
        let policy = &resolved.policy;
        policy.binds_recipe(instance)?;

        if self.floor.binding != instance.binding {
            return Err(ContextError::InvalidFence);
        }
        if policy.admission.safety_floor != self.floor.rule_evidence {
            return Err(ContextError::IdentityConflict);
        }
        let features = policy.configured_features()?;
        let budgeted: BTreeSet<SemanticRole> = policy
            .section_budgets
            .iter()
            .map(|budget| budget.semantic_role)
            .collect();
        let mandatory: BTreeSet<SemanticRole> = instance.mandatory_roles.iter().copied().collect();
        for role in &self.floor.mandatory_roles {
            if !features.contains(role) || !budgeted.contains(role) || !mandatory.contains(role) {
                return Err(ContextError::MissingFloor);
            }
            if policy.admission.suppressible_roles.contains(role) {
                return Err(ContextError::MissingFloor);
            }
        }

        let floor_capacity = &self.floor.capacity;
        if instance.capacity.route_capacity < floor_capacity.route_capacity
            || instance.capacity.output_reserve < floor_capacity.output_reserve
            || instance.capacity.review_reserve < floor_capacity.review_reserve
            || instance.capacity.fixed_overhead > floor_capacity.fixed_overhead
        {
            return Err(ContextError::CapacityExceeded);
        }

        let blocked: BTreeSet<QualityDimension> =
            policy.blocking_dimensions.iter().copied().collect();
        if !self
            .required_blocking_dimensions
            .iter()
            .all(|dimension| blocked.contains(dimension))
        {
            return Err(ContextError::QualityIncomplete);
        }

        let permitted: BTreeSet<OmissionReason> =
            policy.omission.permitted_reasons.iter().copied().collect();
        if !self
            .required_omission_reasons
            .iter()
            .all(|reason| permitted.contains(reason))
        {
            return Err(ContextError::OmissionHandleInvalid);
        }
        let non_recoverable: BTreeSet<NonRecoverableReason> = policy
            .omission
            .non_recoverable_reasons
            .iter()
            .copied()
            .collect();
        let ceiling: BTreeSet<NonRecoverableReason> = self
            .permitted_non_recoverable_reasons
            .iter()
            .copied()
            .collect();
        if !non_recoverable.is_subset(&ceiling) {
            return Err(ContextError::OmissionHandleInvalid);
        }

        if self.required_proof_ceiling > ProofCeiling::Observation
            && policy.qualification.state != RecipeQualificationState::Qualified
        {
            return Err(ContextError::QualityIncomplete);
        }

        if self
            .applicability
            .resolved
            .contains(&QualityApplicabilityInput::ActiveDirective)
            && (!features.contains(&SemanticRole::Conflict)
                || !features.contains(&SemanticRole::Negative))
        {
            return Err(ContextError::MissingField(
                "recipe_policy.candidate_features",
            ));
        }
        Ok(())
    }
}

/// The current owner configuration from which exactly one applicable approved
/// recipe is resolved.
///
/// This is the owner catalogue, not the compiler. It carries the compilation's
/// own applicability dimensions and compiler-generation profile, the
/// independent governing requirements, every approved candidate revision the
/// owner currently holds, and — #1724 W7 — the owner decisions that made those
/// revisions current or revoked them. The pure compiler receives the result of
/// [`ApprovedRecipeCatalogue::resolve`]; it never consults this record, a
/// mutable registry, the filesystem, the network or a model.
///
/// `current` is the current recipe pointer and is a REQUIRED member with no
/// default, because it is the only thing that decides what is current. Before
/// #1724 W6 the pointer was implicit: `resolve` took the applicable candidate
/// with the greatest [`PolicyRevision`], which made a revision number an
/// activation authority and let a publisher change the current recipe by
/// publishing a newer candidate, with no promotion decision anywhere.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRecipeCatalogue {
    /// The one approved revision this catalogue holds current.
    ///
    /// Nothing else changes what is current: not a higher revision number, not a
    /// valid digest, not a smaller packet, not a favourable measurement. The
    /// pointer is resolved to the owner promotion decision that made it current
    /// by [`ApprovedRecipeCatalogue::validate`], which requires the pointed
    /// revision's own recorded activation identity to name an activation record
    /// this catalogue carries.
    pub current: RecipePolicyIdentity,
    /// Compiler-generation and route profile this compilation runs under.
    pub execution: RecipeExecutionContour,
    /// Applicability dimensions of this compilation.
    pub applicability: RecipeApplicability,
    /// Independent governing requirements every candidate is measured against.
    pub governing: GoverningContextRequirements,
    /// Owner-published approved candidate policy revisions.
    pub candidates: Vec<ContextRecipePolicy>,
    /// Owner activation decisions for the candidates, one per candidate.
    ///
    /// Order carries no meaning. #1724 W6 removed the reading in which the
    /// newest record here, or the highest revision, decided what was current.
    pub activations: Vec<RecipeActivationRecord>,
    /// Owner kill/rollback decisions for candidates this owner no longer serves.
    pub revocations: Vec<RecipeRevocationRecord>,
}

impl ApprovedRecipeCatalogue {
    /// Validate the closed owner configuration before any candidate is
    /// compared.
    ///
    /// #1724 W7 adds the decision closure. Every candidate must be named by
    /// exactly one activation decision whose `decision` identity equals the
    /// candidate's own recorded `supersession.activation`, so a revision cannot
    /// be served without the decision that made it current or be made current
    /// by a decision that belongs to another revision. Each activation names
    /// the exact predecessor it supersedes, which must be a revision this owner
    /// still holds, and each revocation names either nothing (a kill) or the
    /// previous compatible revision it returns to, which must likewise still be
    /// held. A rollback therefore cannot name a revision the owner does not
    /// have, and cannot be expressed at all by editing the revoked revision.
    ///
    /// #1724 W6 adds the pointer closure and the gate closure. `current` must
    /// name a revision this owner holds. Every activation's
    /// [`RecipePromotionBasis`] is then measured against the CONTENT of the
    /// revision it activated: an initial/built-in baseline has no predecessor, a
    /// candidate's declared predecessor is the decision's predecessor, the
    /// candidate's declared proposed content IS the activated revision, the
    /// candidate's applicability covers the scope the decision activates, the
    /// candidate measured every counter-metric the activated revision declares,
    /// and the activated revision records its metrics as qualified. A candidate,
    /// a valid hash, a smaller packet or a positive token saving satisfies none
    /// of those, so none of them can activate anything.
    ///
    /// #1724 A4 follows from the same shape: nothing in this record, and nothing
    /// in a View or a `ContextEconomyReceipt`, can rewrite an approved
    /// revision's `policy_sha256`. Evidence that names a digest keeps naming it
    /// after a later revocation, and a new compilation resolves a new
    /// `resolution_sha256` rather than restamping the old evidence.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.candidates.is_empty() || self.candidates.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_catalogue.candidates",
            });
        }
        if self.activations.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_catalogue.activations",
            });
        }
        if self.activations.len() != self.candidates.len() {
            return Err(ContextError::IdentityConflict);
        }
        if self.revocations.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_catalogue.revocations",
            });
        }
        self.current.validate_identity()?;
        self.execution.validate()?;
        self.applicability.validate()?;
        self.governing.validate()?;
        let mut seen = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !seen.insert((candidate.policy_id.clone(), candidate.policy_revision)) {
                return Err(ContextError::Duplicate("recipe_catalogue.candidates"));
            }
        }
        let mut held: BTreeMap<RecipePolicyIdentity, &ContextRecipePolicy> = BTreeMap::new();
        for candidate in &self.candidates {
            if held
                .insert(RecipePolicyIdentity::of(candidate), candidate)
                .is_some()
            {
                return Err(ContextError::IdentityConflict);
            }
        }

        let mut decisions = BTreeSet::new();
        let mut activated = BTreeSet::new();
        for activation in &self.activations {
            activation.validate()?;
            if !decisions.insert(activation.decision.clone())
                || !activated.insert(activation.activated.clone())
            {
                return Err(ContextError::Duplicate("recipe_catalogue.activations"));
            }
            let Some(activated_policy) = held.get(&activation.activated) else {
                return Err(ContextError::IdentityConflict);
            };
            // The activation is confined to the contour and transform
            // identity it was decided under. Its `generation` is deliberately
            // not compared here: a contour generation is the owner's monotone
            // execution counter, and freezing every historical activation on it
            // would make the catalogue unusable after one bump. Generation
            // staleness is already a per-candidate rejection
            // (`RecipeRejectionReason::StaleCompilerGeneration`), which is the
            // narrower and correct place for it.
            if activation.execution.contour != self.execution.contour
                || activation.execution.transform != self.execution.transform
            {
                return Err(ContextError::IdentityConflict);
            }
            if !RecipeApplicability::declared_covers(&activation.applicability, &self.applicability)
            {
                return Err(ContextError::IdentityConflict);
            }
            if activation
                .predecessor
                .as_ref()
                .is_some_and(|predecessor| !held.contains_key(predecessor))
            {
                return Err(ContextError::IdentityConflict);
            }
            Self::validate_promotion_basis(activation, activated_policy)?;
        }
        for candidate in &self.candidates {
            let identity = RecipePolicyIdentity::of(candidate);
            if !self.activations.iter().any(|activation| {
                activation.activated == identity
                    && activation.decision == candidate.supersession.activation
            }) {
                return Err(ContextError::IdentityConflict);
            }
        }

        self.validate_revocations(&held)?;
        if !held.contains_key(&self.current) {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }

    /// #1724 W7. Every kill or rollback names a revision this owner still holds,
    /// and a rollback names a replacement this owner still holds, so a rollback
    /// cannot return to a revision that is not there.
    fn validate_revocations(
        &self,
        held: &BTreeMap<RecipePolicyIdentity, &ContextRecipePolicy>,
    ) -> Result<(), ContextError> {
        let mut revoked = BTreeSet::new();
        let mut revocation_decisions = BTreeSet::new();
        for revocation in &self.revocations {
            revocation.validate()?;
            if !revoked.insert(revocation.revoked.clone())
                || !revocation_decisions.insert(revocation.decision.clone())
            {
                return Err(ContextError::Duplicate("recipe_catalogue.revocations"));
            }
            if !held.contains_key(&revocation.revoked) {
                return Err(ContextError::IdentityConflict);
            }
            if revocation
                .replacement
                .as_ref()
                .is_some_and(|replacement| !held.contains_key(replacement))
            {
                return Err(ContextError::IdentityConflict);
            }
        }
        Ok(())
    }

    /// #1724 W6: measure one owner promotion decision against the approved
    /// content it actually promoted.
    ///
    /// Every comparison here is against the activated revision's own recorded
    /// values or against the candidate's own recorded values, never against a
    /// value derived from the decision being checked, so a decision cannot pass
    /// by agreeing with itself.
    fn validate_promotion_basis(
        activation: &RecipeActivationRecord,
        activated_policy: &ContextRecipePolicy,
    ) -> Result<(), ContextError> {
        match &activation.basis {
            // The built-in baseline is preserved as such: it supersedes nothing
            // and it needs no fabricated prior experimental evidence, so it is
            // the one basis that may leave `qualification.state` unqualified.
            RecipePromotionBasis::InitialBuiltInBaseline { .. } => {
                if activation.predecessor.is_some() {
                    return Err(ContextError::IdentityConflict);
                }
            }
            RecipePromotionBasis::ImprovementCandidate { candidate } => {
                if activation.predecessor.as_ref() != Some(&candidate.predecessor)
                    || candidate.proposed != activation.activated
                {
                    return Err(ContextError::IdentityConflict);
                }
                // The candidate was triaged and measured in a scope at least as
                // broad as the scope this decision activates, so the evidence
                // cited is evidence about the applicability being activated.
                // `activation.applicability` is separately required to cover the
                // compilation's own applicability, so the chain reaches the
                // independent end rather than stopping at the candidate.
                if !RecipeApplicability::declared_covers(
                    &candidate.applicability,
                    &activation.applicability,
                ) {
                    return Err(ContextError::IdentityConflict);
                }
                if !candidate.covers_declared_counter_metrics(activated_policy) {
                    return Err(ContextError::QualityIncomplete);
                }
                // An unqualified metric stays labelled unqualified, and a
                // revision whose own recorded metrics are unqualified cannot be
                // promoted on the strength of evidence about different metrics.
                if activated_policy.qualification.state != RecipeQualificationState::Qualified {
                    return Err(ContextError::QualityIncomplete);
                }
            }
        }
        Ok(())
    }

    /// Resolve exactly one applicable approved recipe.
    ///
    /// #1724 W6. Selection reads [`ApprovedRecipeCatalogue::current`] and
    /// nothing else. In order, with no fallback:
    ///
    /// 1. an unresolved governing applicability input refuses the compilation
    ///    before any candidate is read;
    /// 2. the pointed revision named by an owner kill or rollback decision,
    ///    issued under another compiler-generation or route profile, or not
    ///    declaring every applicability profile of this compilation refuses with
    ///    that exact reason;
    /// 3. any OTHER held, unrevoked, applicable revision refuses as
    ///    [`RecipeResolutionRefusal::ApplicableCandidateNotCurrent`]. It is
    ///    neither adopted nor ignored: a candidate that has not been pointed at
    ///    by a promotion decision is not permission to activate, so the
    ///    dependent compilation blocks until the owner publishes that decision.
    ///
    /// There is no revision comparison anywhere in this function, because a
    /// revision number is not an activation authority. The result is pinned by
    /// its own digest so the same revision cannot be reused for another
    /// compilation, task or generation.
    pub fn resolve(&self) -> Result<ResolvedContextRecipe, RecipeResolutionRefusal> {
        self.validate()
            .map_err(|error| RecipeResolutionRefusal::InvalidCatalogue {
                reason: error.to_string(),
            })?;
        let unresolved = self.governing.applicability.unresolved();
        if !unresolved.is_empty() {
            return Err(RecipeResolutionRefusal::UnresolvedGoverningInput { inputs: unresolved });
        }

        // `validate` proved `current` names a held revision, so this lookup
        // cannot miss. It is still written as a checked lookup rather than an
        // index so the pointer is never dereferenced on trust. `current` stays a
        // `&ContextRecipePolicy`: a policy is content, not a `Copy` value, and
        // every use below either borrows it or clones it deliberately.
        let current = self
            .candidates
            .iter()
            .find(|candidate| RecipePolicyIdentity::of(candidate) == self.current)
            .ok_or_else(|| RecipeResolutionRefusal::InvalidCatalogue {
                reason: ContextError::IdentityConflict.to_string(),
            })?;

        if let Some(reason) = self.applicability_rejection(current) {
            return Err(RecipeResolutionRefusal::NoApplicableCandidate {
                rejected: vec![RecipeCandidateRejection {
                    identity: RecipePolicyIdentity::of(current),
                    reason,
                }],
            });
        }

        let mut unpointed: Vec<RecipePolicyIdentity> = self
            .candidates
            .iter()
            .filter(|candidate| RecipePolicyIdentity::of(candidate) != self.current)
            .filter(|candidate| self.applicability_rejection(candidate).is_none())
            .map(RecipePolicyIdentity::of)
            .collect();
        if !unpointed.is_empty() {
            unpointed.sort();
            return Err(RecipeResolutionRefusal::ApplicableCandidateNotCurrent {
                current: self.current.clone(),
                unpointed,
            });
        }

        let mut resolution = ResolvedContextRecipe {
            identity: self.current.clone(),
            policy: current.clone(),
            approval: current.supersession.activation.clone(),
            applicability: self.applicability.clone(),
            execution: self.execution.clone(),
            resolution_sha256: "0".repeat(64),
        };
        resolution.resolution_sha256 =
            resolution.canonical_resolution_digest().map_err(|error| {
                RecipeResolutionRefusal::InvalidCatalogue {
                    reason: error.to_string(),
                }
            })?;
        Ok(resolution)
    }

    fn applicability_rejection(
        &self,
        candidate: &ContextRecipePolicy,
    ) -> Option<RecipeRejectionReason> {
        // #1724 W7: revocation is an owner decision held BESIDE the approved
        // content, read from the identity the candidate records. A kill or a
        // rollback can therefore be observed and audited without rewriting the
        // revoked revision, and a revision the owner still serves is unaffected.
        if let Some(revocation) = self
            .revocations
            .iter()
            .find(|revocation| revocation.revoked == RecipePolicyIdentity::of(candidate))
        {
            return Some(RecipeRejectionReason::Revoked {
                decision: revocation.decision.clone(),
            });
        }
        if candidate.execution != self.execution {
            return Some(RecipeRejectionReason::StaleCompilerGeneration {
                expected: self.execution.clone(),
                observed: candidate.execution.clone(),
            });
        }
        for dimension in [
            RecipeApplicabilityDimension::Task,
            RecipeApplicabilityDimension::Route,
            RecipeApplicabilityDimension::Impact,
            RecipeApplicabilityDimension::Governance,
        ] {
            let declared = dimension.profiles(&candidate.applicability);
            for profile in dimension.profiles(&self.applicability) {
                if !declared.contains(profile) {
                    return Some(RecipeRejectionReason::UndeclaredApplicability {
                        dimension,
                        profile: profile.clone(),
                    });
                }
            }
        }
        None
    }
}
