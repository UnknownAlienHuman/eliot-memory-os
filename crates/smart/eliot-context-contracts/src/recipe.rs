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

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, PolicyRevision};
use eliot_receipts::ProtectedReserves;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    BoundaryDisposition, BoundaryTransformerRevision, BoundaryUnitKind, ContextError,
    ContextRecipe, LossPolicy, NonRecoverableReason, OmissionReason, QUALITY_DIMENSIONS,
    QualityDimension, SemanticRole, validate_digest, validate_text,
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
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.qualification.as_str(),
            "recipe_policy.qualification.qualification",
        )?;
        if self.counter_metrics.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.qualification.counter_metrics",
            });
        }
        let mut seen = BTreeSet::new();
        for metric in &self.counter_metrics {
            validate_text(
                metric.metric_id.as_str(),
                "recipe_policy.qualification.counter_metrics.metric_id",
            )?;
            if !seen.insert(metric.metric_id.clone()) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.qualification.counter_metrics.metric_id",
                ));
            }
        }
        Ok(())
    }
}

/// I12.13 `parent_supersession_kill_and_rollback`.
///
/// The parent revision is the existing `ContextRecipe::predecessor` of the
/// instance, and the invalidation identity is its existing `invalidation`;
/// neither is repeated here. What is new is the owner decision that made this
/// revision current and the owner decisions that killed it or rolled back to an
/// earlier compatible revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeSupersession {
    /// Scoped activation record that made this revision current.
    pub activation: ArtifactId,
    /// Owner kill decision, when this revision was killed.
    pub kill: Option<ArtifactId>,
    /// Owner rollback decision that returned to an earlier compatible revision.
    pub rollback: Option<ArtifactId>,
}

impl RecipeSupersession {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.activation.as_str(),
            "recipe_policy.supersession.activation",
        )?;
        for (decision, field) in [
            (self.kill.as_ref(), "recipe_policy.supersession.kill"),
            (
                self.rollback.as_ref(),
                "recipe_policy.supersession.rollback",
            ),
        ] {
            if let Some(reference) = decision {
                validate_text(reference.as_str(), field)?;
            }
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
