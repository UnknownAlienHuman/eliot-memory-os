//! Whole atom, recipe and representation contracts.

use eliot_contracts::{ArtifactId, ContractVersion, PolicyRevision};
use eliot_evidence::{Assertability, EpistemicStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CONTEXT_CONTRACT_VERSION, ContextBinding, ContextError, DecisionRevision, ExactSourceRange,
    ProofBinding, ProviderRole, QualityDimension, SemanticRole, SourceSnapshot, validate_digest,
    validate_text,
};

/// Largest source span, in the declared coordinate system's own units, that one
/// atom may claim as exact.
///
/// `1_048_576` is the ceiling `validate_content` already applies to one atom's
/// representation content, so a wider claimed span was not measured against a
/// payload this crate will hold. A producer whose original is wider states no
/// range at all rather than an unbounded one. The span is bounded, never the
/// absolute offset: a ten-megabyte snapshot may still contain a small atom at
/// any offset within it.
pub const MAX_ATOM_SOURCE_RANGE_UNITS: u64 = 1_048_576;

fn validate_content(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        || value.len() > 1_048_576
    {
        Err(ContextError::InvalidField(field))
    } else {
        Ok(())
    }
}

/// Exact normative loss policy wire names.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LossPolicy {
    /// The complete unit must be retained.
    #[serde(rename = "NON_DROPPABLE")]
    NonDroppable,
    /// Only a reversible exact handle may be retained.
    #[serde(rename = "HANDLE_ONLY")]
    HandleOnly,
    /// A declared extractive representation is permitted.
    #[serde(rename = "EXTRACTIVE")]
    Extractive,
    /// A declared summary representation is permitted.
    #[serde(rename = "SUMMARIZABLE")]
    Summarizable,
}

/// Explicit representation of one whole unit. No representation is inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum AtomRepresentation {
    /// Complete original unit.
    #[serde(rename = "WHOLE")]
    Whole { content: String },
    /// Exact reversible handle without content.
    #[serde(rename = "HANDLE")]
    Handle { handle: ArtifactId },
    /// Explicit extractive form with a manifest of retained fields.
    #[serde(rename = "EXTRACTIVE")]
    Extractive {
        content: String,
        manifest: Vec<String>,
    },
    /// Explicit summary form with source and loss evidence.
    #[serde(rename = "SUMMARY")]
    Summary {
        content: String,
        source_digest: String,
    },
}

impl AtomRepresentation {
    /// Validate representation content and bounded manifest.
    pub fn validate(&self) -> Result<(), ContextError> {
        match self {
            Self::Whole { content }
            | Self::Extractive { content, .. }
            | Self::Summary { content, .. } => {
                validate_content(content, "atom.representation.content")?;
            }
            Self::Handle { .. } => {}
        }
        if let Self::Extractive { manifest, .. } = self {
            if manifest.is_empty() || manifest.len() > 256 {
                return Err(ContextError::Bounds {
                    field: "atom.representation.manifest",
                });
            }
            for field in manifest {
                validate_text(field, "atom.representation.manifest")?;
            }
        }
        if let Self::Summary { source_digest, .. } = self {
            validate_digest(source_digest, "atom.representation.source_digest")?;
        }
        Ok(())
    }

    /// Whether this representation is a complete whole unit.
    #[must_use]
    pub const fn is_whole(&self) -> bool {
        matches!(self, Self::Whole { .. })
    }

    /// Return the closed representation kind used by loss-policy checks.
    #[must_use]
    pub const fn kind(&self) -> RepresentationKind {
        match self {
            Self::Whole { .. } => RepresentationKind::Whole,
            Self::Handle { .. } => RepresentationKind::Handle,
            Self::Extractive { .. } => RepresentationKind::Extractive,
            Self::Summary { .. } => RepresentationKind::Summary,
        }
    }
}

/// Atom-specific privacy and disclosure boundary.
///
/// The label is ENFORCED, not merely carried, and an earlier version of this
/// document said the opposite. `ContextCandidate::validate_public_privacy` refuses
/// every candidate whose class is not `Public`
/// (`ContextError::InvalidField("candidate.privacy")`), and it is called on the
/// admission path twice over: once per candidate by `AdmissionInput::validate` in
/// `admission_input.rs`, and once per admitted atom by the record projection in
/// `admission.rs`. A `Secret` or `Restricted` atom therefore never reaches
/// `eliot-context-admission` output, which is the opposite of "carried for downstream
/// use only".
///
/// The WIDER A00.3 question — which routes and identities a non-public atom may reach
/// once it is admitted — is a different rule with a different owner:
/// `crates/governor/eliot-workscope` (`PrivacyProfile::admits`, denying with
/// `WorkScopeError::PrivacyDenied`), and downstream non-public disclosure is withheld as
/// `DeliveryDisposition::WithheldPrivacy` by `eliot-reactive-context-plan`. Naming that
/// owner is the point of this paragraph; claiming it is the ONLY enforcer was not.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyClass {
    Public,
    Scoped,
    Restricted,
    Secret,
}

/// Authority/influence ceiling for context material.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityClass {
    None,
    Informational,
    DecisionRelevant,
    Governing,
}

/// Explicit atom state retained in candidate and admitted forms.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AtomAvailability {
    PresentCurrent,
    Missing,
    Stale,
    Blocked,
    Unavailable,
    Omitted,
    Exhausted,
    Unknown,
    KnownEmpty,
    Partial,
}

/// Measurement identity attached to an atom.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementRef {
    /// Exact serialized input digest.
    pub digest: String,
    /// Serializer/schema identity that produced it.
    pub serializer: String,
}

impl MeasurementRef {
    /// Validate the measurement binding.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_digest(&self.digest, "measurement.digest")?;
        validate_text(&self.serializer, "measurement.serializer")
    }
}

/// Wire revision of the accepted [`ContextRecipe`] shape.
///
/// Schema 1.0.0 (`CONTEXT_CONTRACT_VERSION`) is the frozen predecessor: binding,
/// decision, digest, denominator, mandatory roles, role loss rules, capacity,
/// predecessor and invalidation. Schema 1.1.0 adds the stable reusable policy
/// revision and the reusable [`ContextRecipePolicy`] definition. The addition is
/// explicit and migrated, never silent: [`ContextRecipe::validate`] accepts only
/// this revision, and schema-1.0.0 bytes are accepted only through
/// [`migrate_legacy_recipe_v1`].
pub const CONTEXT_RECIPE_SCHEMA_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);

/// Immutable policy recipe for one Context compilation.
///
/// This is the one accepted recipe representation (issue #1724). The smaller
/// `eliot-context::ContextRecipe` (`crates/smart/eliot-context/src/lib.rs`) is a
/// frozen compatibility projection of this shape, derived explicitly by that
/// crate's campaign-projection path; it is never a parallel owner, and no third
/// representation exists.
///
/// The struct separates three revisions that must never be conflated: the
/// stable reusable policy revision (`policy_revision`), the compilation-bound
/// task/input revision (`decision.recipe_revision`, equal to the input task
/// revision), and the wire shape revision (`schema_version`).
///
/// I12.13 field map: `recipe_id_revision_and_digest` is `policy_revision`,
/// `decision` and `recipe_sha256`; `applicable_task_route_impact_and_governance_profiles`
/// is `policy.applicability`; `stage_graph_and_order` is the ordered
/// `policy.stages`; `candidate_feature_configuration` is
/// `policy.candidate_features`; `admission_and_suppression_policy` is the
/// existing `denominator`, `mandatory_roles` and `role_policies`;
/// `instruction_directive_evidence_tool_and_result_budgets` is the existing
/// `capacity` together with `policy.section_budgets`;
/// `protected_reasoning_review_and_margin_reserve` is the existing
/// `capacity.review_reserve` and the atom `protected` flags;
/// `layout_position_and_repetition_policy` is `policy.layout`;
/// `omission_and_expansion_policy` is `policy.omission_expansion`;
/// `scorecard_blocking_dimensions` is `policy.blocking_dimensions`;
/// `execution_contour_and_generation` is `policy.execution_contour`;
/// `empirical_qualification_and_counter_metrics` is `policy.qualification`;
/// `parent_supersession_kill_and_rollback` is the existing `predecessor` and
/// `invalidation`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRecipe {
    /// Version of this public recipe shape.
    pub schema_version: ContractVersion,
    /// Exact identity of the task/attempt/scope/fence decision.
    pub binding: ContextBinding,
    /// Recipe revision and canonical policy digest.
    pub decision: DecisionRevision,
    /// Recipe digest, computed over the immutable policy shape.
    pub recipe_sha256: String,
    /// Stable reusable policy revision. This is never the task/input revision:
    /// `decision.recipe_revision` binds this instance to one compilation, while
    /// this revision identifies the reusable policy definition across
    /// compilations. Approval, revocation and activation of a revision are W2
    /// resolution work, not schema work.
    pub policy_revision: PolicyRevision,
    /// Stable reusable I12.13 policy definition bound to this compilation.
    pub policy: ContextRecipePolicy,
    /// Provider/role denominator required for this recipe.
    pub denominator: ProviderRoleDenominator,
    /// Roles that must have complete floor evidence.
    pub mandatory_roles: Vec<SemanticRole>,
    /// Representation/loss policy for each semantic role.
    pub role_policies: Vec<RoleLossRule>,
    /// Route/output/review/fixed overhead limits.
    pub capacity: CapacityLimits,
    /// Prior revision when this recipe supersedes a prior policy.
    pub predecessor: Option<ArtifactId>,
    /// Expiry or invalidation identity, if any.
    pub invalidation: Option<ArtifactId>,
}

impl ContextRecipe {
    /// Compute the digest expected in `recipe_sha256` for this policy.
    pub fn canonical_policy_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.recipe_sha256 = "0".repeat(64);

        // These fields are sets on the wire even though Serde represents them
        // as bounded arrays.  Normalize their order for the policy digest;
        // `canonical_digest` itself intentionally preserves array order for
        // values where ordering carries meaning.  The stage order is execution
        // order, so `policy.stages` is never sorted here.
        canonical.mandatory_roles.sort();
        canonical.denominator.requested.sort();
        canonical
            .denominator
            .dispositions
            .sort_by(|left, right| left.slot.cmp(&right.slot));
        for rule in &mut canonical.role_policies {
            rule.allowed_representations.sort();
        }
        canonical.role_policies.sort_by_key(|rule| rule.role);
        canonical
            .policy
            .candidate_features
            .sort_by(|left, right| left.name.cmp(&right.name));
        canonical
            .policy
            .section_budgets
            .sort_by_key(|budget| budget.semantic_role);
        for budget in &mut canonical.policy.section_budgets {
            budget.protected_floor_refs.sort();
        }
        canonical.policy.blocking_dimensions.sort();
        canonical.policy.qualification.counter_metrics.sort();
        canonical
            .policy
            .qualification
            .qualification_evidence
            .sort();
        crate::canonical_digest(&canonical)
    }

    /// Validate closed policy and denominator coherence.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != CONTEXT_RECIPE_SCHEMA_VERSION {
            return Err(ContextError::InvalidField("recipe.schema_version"));
        }
        self.binding.validate()?;
        self.decision.validate()?;
        if self.decision.decision_id != self.binding.decision_id {
            return Err(ContextError::IdentityConflict);
        }
        validate_digest(&self.recipe_sha256, "recipe.recipe_sha256")?;
        if self.canonical_policy_digest()? != self.recipe_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        self.policy.validate()?;
        self.denominator.validate()?;
        if self.mandatory_roles.is_empty() || self.mandatory_roles.len() > 64 {
            return Err(ContextError::MissingField("recipe.mandatory_roles"));
        }
        let mandatory_roles: std::collections::BTreeSet<_> =
            self.mandatory_roles.iter().copied().collect();
        if mandatory_roles.len() != self.mandatory_roles.len() {
            return Err(ContextError::Duplicate("recipe.mandatory_roles"));
        }
        for role in &self.mandatory_roles {
            if !self.role_policies.iter().any(|rule| rule.role == *role) {
                return Err(ContextError::MissingField("recipe.role_policies"));
            }
        }
        let mut roles = std::collections::BTreeSet::new();
        if self.role_policies.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe.role_policies",
            });
        }
        for rule in &self.role_policies {
            if !roles.insert(rule.role) {
                return Err(ContextError::Duplicate("recipe.role_policies.role"));
            }
            rule.validate()?;
        }
        let required_roles: std::collections::BTreeSet<_> = self
            .role_policies
            .iter()
            .filter(|rule| rule.required)
            .map(|rule| rule.role)
            .collect();
        if required_roles != mandatory_roles {
            return Err(ContextError::DenominatorMismatch);
        }
        // Every section budget governs a role the admission policy knows.
        // A budget for a role with no loss rule would govern nothing.
        for budget in &self.policy.section_budgets {
            if !self
                .role_policies
                .iter()
                .any(|rule| rule.role == budget.semantic_role)
            {
                return Err(ContextError::DenominatorMismatch);
            }
        }
        self.capacity.validate()
    }
}

/// Bounded non-blank policy text.
fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ContextError> {
    validate_text(value, field)?;
    if value.chars().count() > max_chars {
        return Err(ContextError::Bounds { field });
    }
    Ok(())
}

/// Impact class of the decisions one reusable recipe policy may shape
/// (I12.13 `applicable_task_route_impact_and_governance_profiles`).
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeImpactClass {
    Advisory,
    DecisionSupport,
    Governing,
}

/// Task, route, impact and governance scope of one reusable recipe policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeApplicability {
    /// Compatible task class this policy may be resolved for.
    pub task_class: String,
    /// Route profile this policy may be resolved for.
    pub route_profile: String,
    /// Impact class of the decisions this policy may shape.
    pub impact_class: RecipeImpactClass,
    /// Governance profile that must approve this policy.
    pub governance_profile: String,
}

impl RecipeApplicability {
    /// Validate bounded applicability text.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_bounded_text(
            &self.task_class,
            "policy.applicability.task_class",
            256,
        )?;
        validate_bounded_text(
            &self.route_profile,
            "policy.applicability.route_profile",
            256,
        )?;
        validate_bounded_text(
            &self.governance_profile,
            "policy.applicability.governance_profile",
            256,
        )?;
        Ok(())
    }
}

/// One ordered compilation stage (I12.13 `stage_graph_and_order`).
///
/// The position in `ContextRecipePolicy.stages` is the execution order.
/// `predecessors` names stages that must run earlier; it is a graph over the
/// ordered vector, never a second ordering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeStage {
    /// Stable stage name, unique within the policy.
    pub name: String,
    /// Names of stages that must run before this one.
    pub predecessors: Vec<String>,
}

impl RecipeStage {
    /// Validate bounded stage entry shapes. Graph position is checked by the
    /// owning policy, which sees the sibling stages.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_bounded_text(&self.name, "policy.stages.name", 128)?;
        if self.predecessors.len() > 64 {
            return Err(ContextError::Bounds {
                field: "policy.stages.predecessors",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for predecessor in &self.predecessors {
            validate_bounded_text(
                predecessor,
                "policy.stages.predecessors",
                128,
            )?;
            if predecessor == &self.name || !seen.insert(predecessor.clone()) {
                return Err(ContextError::InvalidField(
                    "policy.stages.predecessors",
                ));
            }
        }
        Ok(())
    }
}

/// One named candidate feature toggle (I12.13
/// `candidate_feature_configuration`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateFeature {
    /// Stable feature name, unique within the policy.
    pub name: String,
    /// Whether the compiler may use this feature under this policy.
    pub enabled: bool,
}

impl CandidateFeature {
    /// Validate the bounded feature name.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_bounded_text(&self.name, "policy.candidate_features.name", 128)
    }
}

/// Omission-or-handle rule for one section budget (I12.13
/// `omission_or_handle_policy`).
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionOmissionPolicy {
    ForbidOmission,
    AllowHandle,
    AllowOmission,
}

/// Allowed whole-unit degradation for one section budget or omission rule.
///
/// Closed transcription of the I12.13 degradation dispositions: retain the exact
/// handle only, return a narrower extractive view, mark the whole unit
/// incomplete or unsupported, route to a compatible contour, or block only the
/// dependent decision or effect.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionDegradation {
    HandleOnly,
    ExtractiveView,
    MarkIncomplete,
    RouteToCompatibleContour,
    BlockDependentEffect,
}

/// Whole-unit budget for one semantic role (I12.13 `ContextSectionBudget`).
///
/// This is the shared-schema policy #1725 consumes: it lives in the accepted
/// recipe and is covered by `ContextRecipe::canonical_policy_digest`, never in
/// a sidecar representation. Both `minimum_required_whole_units` and
/// `planning_maximum` count whole addressable units, so a minimum above the
/// maximum is unsatisfiable and refused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextSectionBudget {
    /// Semantic role governed by this budget.
    pub semantic_role: SemanticRole,
    /// Whole-unit boundary kind this budget is planned in.
    pub unit_boundary_kind: String,
    /// Whole units of this role that must be preserved.
    pub minimum_required_whole_units: u32,
    /// Protected floor or required references backing the minimum.
    pub protected_floor_refs: Vec<ArtifactId>,
    /// Planned whole-unit maximum for this role on the route.
    pub planning_maximum: u32,
    /// Route profile the maximum was planned against.
    pub route_profile: String,
    /// Whether this role may degrade to a handle or be omitted.
    pub omission_policy: SectionOmissionPolicy,
    /// Allowed degradation when the floor cannot be fully preserved.
    pub degradation: SectionDegradation,
    /// Whether the governed feature disables when the floor cannot be
    /// preserved, instead of degrading silently.
    pub disable_feature_when_floor_cannot_be_preserved: bool,
}

impl ContextSectionBudget {
    /// Validate bounded budget content and satisfiability.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_bounded_text(
            &self.unit_boundary_kind,
            "policy.section_budgets.unit_boundary_kind",
            128,
        )?;
        validate_bounded_text(
            &self.route_profile,
            "policy.section_budgets.route_profile",
            256,
        )?;
        if self.protected_floor_refs.len() > 256 {
            return Err(ContextError::Bounds {
                field: "policy.section_budgets.protected_floor_refs",
            });
        }
        let mut refs = std::collections::BTreeSet::new();
        for reference in &self.protected_floor_refs {
            if !refs.insert(reference.clone()) {
                return Err(ContextError::Duplicate(
                    "policy.section_budgets.protected_floor_refs",
                ));
            }
        }
        if self.minimum_required_whole_units > self.planning_maximum {
            return Err(ContextError::CapacityExceeded);
        }
        Ok(())
    }
}

/// Layout and repetition rules (I12.13
/// `layout_position_and_repetition_policy`).
///
/// Both rules are named owner-resolved rules carried as bounded text: the
/// compiler applies them, the recipe only selects them, so an unknown rule
/// name refuses at resolution rather than degrading silently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeLayoutPolicy {
    /// Named position rule for admitted units.
    pub position_rule: String,
    /// Named repetition rule for repeated units.
    pub repetition_rule: String,
}

impl RecipeLayoutPolicy {
    /// Validate bounded layout rule names.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_bounded_text(&self.position_rule, "policy.layout.position_rule", 256)?;
        validate_bounded_text(
            &self.repetition_rule,
            "policy.layout.repetition_rule",
            256,
        )?;
        Ok(())
    }
}

/// Omission and expansion rules (I12.13 `omission_and_expansion_policy`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeOmissionExpansionPolicy {
    /// Default degradation when a unit cannot be preserved whole.
    pub default_disposition: SectionDegradation,
    /// Whether every omission must retain an explicit expansion handle.
    pub expansion_handles_required: bool,
}

/// Execution contour and generation (I12.13
/// `execution_contour_and_generation`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeExecutionContour {
    /// Least-privileged contour this policy may execute on.
    pub contour: String,
    /// Immutable published generation this policy was qualified on.
    pub generation: String,
}

impl RecipeExecutionContour {
    /// Validate bounded contour and generation names.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_bounded_text(&self.contour, "policy.execution_contour.contour", 256)?;
        validate_bounded_text(
            &self.generation,
            "policy.execution_contour.generation",
            256,
        )?;
        Ok(())
    }
}

/// Empirical qualification and counter-metrics (I12.13
/// `empirical_qualification_and_counter_metrics`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeQualification {
    /// Evidence references backing qualification (replay, ablation, transfer).
    pub qualification_evidence: Vec<ArtifactId>,
    /// Counter-metrics that must stay qualified alongside the recipe.
    pub counter_metrics: Vec<String>,
}

impl RecipeQualification {
    /// Validate bounded qualification content.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.qualification_evidence.len() > 64 {
            return Err(ContextError::Bounds {
                field: "policy.qualification.qualification_evidence",
            });
        }
        if self.counter_metrics.len() > 64 {
            return Err(ContextError::Bounds {
                field: "policy.qualification.counter_metrics",
            });
        }
        let mut evidence = std::collections::BTreeSet::new();
        for reference in &self.qualification_evidence {
            if !evidence.insert(reference.clone()) {
                return Err(ContextError::Duplicate(
                    "policy.qualification.qualification_evidence",
                ));
            }
        }
        let mut metrics = std::collections::BTreeSet::new();
        for metric in &self.counter_metrics {
            validate_bounded_text(
                metric,
                "policy.qualification.counter_metrics",
                128,
            )?;
            if !metrics.insert(metric.clone()) {
                return Err(ContextError::Duplicate(
                    "policy.qualification.counter_metrics",
                ));
            }
        }
        Ok(())
    }
}

/// Stable reusable recipe policy definition (I12.13 `ContextRecipe` content).
///
/// This is the reusable half of the recipe identity: it carries every I12.13
/// policy field and is revised by `ContextRecipe.policy_revision`, independent
/// of any compilation-bound task/input revision. A `ContextRecipe` binds one
/// value of this type to one compilation through its digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRecipePolicy {
    /// Task, route, impact and governance scope.
    pub applicability: RecipeApplicability,
    /// Ordered stage graph. Vector order is execution order and is digest
    /// significant; it is never canonicalized by sorting.
    pub stages: Vec<RecipeStage>,
    /// Candidate feature configuration, a set keyed by name.
    pub candidate_features: Vec<CandidateFeature>,
    /// Whole-unit section budgets, a set keyed by semantic role.
    pub section_budgets: Vec<ContextSectionBudget>,
    /// Layout and repetition rules.
    pub layout: RecipeLayoutPolicy,
    /// Omission and expansion rules.
    pub omission_expansion: RecipeOmissionExpansionPolicy,
    /// Scorecard dimensions whose failure blocks the dependent decision.
    pub blocking_dimensions: Vec<QualityDimension>,
    /// Execution contour and generation.
    pub execution_contour: RecipeExecutionContour,
    /// Empirical qualification and counter-metrics.
    pub qualification: RecipeQualification,
}

impl ContextRecipePolicy {
    /// Validate closed reusable policy content.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.applicability.validate()?;
        if self.stages.is_empty() || self.stages.len() > 64 {
            return Err(ContextError::Bounds {
                field: "policy.stages",
            });
        }
        let mut prior: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for stage in &self.stages {
            stage.validate()?;
            // Each predecessor must name a strictly earlier stage, so the
            // graph is acyclic by position and needs no separate cycle check.
            for predecessor in &stage.predecessors {
                if !prior.contains(predecessor) {
                    return Err(ContextError::InvalidField("policy.stages.predecessors"));
                }
            }
            if !prior.insert(stage.name.clone()) {
                return Err(ContextError::Duplicate("policy.stages.name"));
            }
        }
        if self.candidate_features.len() > 64 {
            return Err(ContextError::Bounds {
                field: "policy.candidate_features",
            });
        }
        let mut features = std::collections::BTreeSet::new();
        for feature in &self.candidate_features {
            feature.validate()?;
            if !features.insert(feature.name.clone()) {
                return Err(ContextError::Duplicate("policy.candidate_features.name"));
            }
        }
        if self.section_budgets.len() > 64 {
            return Err(ContextError::Bounds {
                field: "policy.section_budgets",
            });
        }
        let mut budgeted = std::collections::BTreeSet::new();
        for budget in &self.section_budgets {
            budget.validate()?;
            if !budgeted.insert(budget.semantic_role) {
                return Err(ContextError::Duplicate(
                    "policy.section_budgets.semantic_role",
                ));
            }
        }
        self.layout.validate()?;
        if self.blocking_dimensions.len() > crate::QUALITY_DIMENSIONS.len() {
            return Err(ContextError::Bounds {
                field: "policy.blocking_dimensions",
            });
        }
        let mut blocking = std::collections::BTreeSet::new();
        for dimension in &self.blocking_dimensions {
            if !blocking.insert(*dimension) {
                return Err(ContextError::Duplicate("policy.blocking_dimensions"));
            }
        }
        self.execution_contour.validate()?;
        self.qualification.validate()?;
        Ok(())
    }
}

/// Frozen schema-1.0.0 wire shape of the accepted recipe (I5.22 migration
/// source only).
///
/// This carries byte-identically the pre-1.1.0 `ContextRecipe` field set. It is
/// never a parallel live representation: values of this type cannot validate as
/// current policy, and current code never emits them. They are accepted only as
/// input to [`migrate_legacy_recipe_v1`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyContextRecipeV1 {
    /// Frozen predecessor wire revision, always 1.0.0.
    pub schema_version: ContractVersion,
    /// Exact identity of the task/attempt/scope/fence decision.
    pub binding: ContextBinding,
    /// Recipe revision and canonical policy digest.
    pub decision: DecisionRevision,
    /// Recipe digest, computed over the frozen v1 policy shape.
    pub recipe_sha256: String,
    /// Provider/role denominator required for this recipe.
    pub denominator: ProviderRoleDenominator,
    /// Roles that must have complete floor evidence.
    pub mandatory_roles: Vec<SemanticRole>,
    /// Representation/loss policy for each semantic role.
    pub role_policies: Vec<RoleLossRule>,
    /// Route/output/review/fixed overhead limits.
    pub capacity: CapacityLimits,
    /// Prior revision when this recipe supersedes a prior policy.
    pub predecessor: Option<ArtifactId>,
    /// Expiry or invalidation identity, if any.
    pub invalidation: Option<ArtifactId>,
}

impl LegacyContextRecipeV1 {
    /// Compute the digest expected in `recipe_sha256` for the frozen v1 shape.
    ///
    /// This is the pre-1.1.0 algorithm, preserved verbatim so existing v1 bytes
    /// keep their hash domain through migration.
    pub fn canonical_policy_digest_v1(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.recipe_sha256 = "0".repeat(64);
        canonical.mandatory_roles.sort();
        canonical.denominator.requested.sort();
        canonical
            .denominator
            .dispositions
            .sort_by(|left, right| left.slot.cmp(&right.slot));
        for rule in &mut canonical.role_policies {
            rule.allowed_representations.sort();
        }
        canonical.role_policies.sort_by_key(|rule| rule.role);
        crate::canonical_digest(&canonical)
    }

    /// Validate the frozen v1 shape, including its own digest.
    pub fn validate_v1(&self) -> Result<(), ContextError> {
        if self.schema_version != CONTEXT_CONTRACT_VERSION {
            return Err(ContextError::InvalidField("recipe.schema_version"));
        }
        self.binding.validate()?;
        self.decision.validate()?;
        if self.decision.decision_id != self.binding.decision_id {
            return Err(ContextError::IdentityConflict);
        }
        validate_digest(&self.recipe_sha256, "recipe.recipe_sha256")?;
        if self.canonical_policy_digest_v1()? != self.recipe_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        self.denominator.validate()?;
        if self.mandatory_roles.is_empty() || self.mandatory_roles.len() > 64 {
            return Err(ContextError::MissingField("recipe.mandatory_roles"));
        }
        let mandatory_roles: std::collections::BTreeSet<_> =
            self.mandatory_roles.iter().copied().collect();
        if mandatory_roles.len() != self.mandatory_roles.len() {
            return Err(ContextError::Duplicate("recipe.mandatory_roles"));
        }
        for role in &self.mandatory_roles {
            if !self.role_policies.iter().any(|rule| rule.role == *role) {
                return Err(ContextError::MissingField("recipe.role_policies"));
            }
        }
        let mut roles = std::collections::BTreeSet::new();
        if self.role_policies.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe.role_policies",
            });
        }
        for rule in &self.role_policies {
            if !roles.insert(rule.role) {
                return Err(ContextError::Duplicate("recipe.role_policies.role"));
            }
            rule.validate()?;
        }
        let required_roles: std::collections::BTreeSet<_> = self
            .role_policies
            .iter()
            .filter(|rule| rule.required)
            .map(|rule| rule.role)
            .collect();
        if required_roles != mandatory_roles {
            return Err(ContextError::DenominatorMismatch);
        }
        self.capacity.validate()
    }
}

/// Explicit versioned migration from schema 1.0.0 to 1.1.0 (I5.22).
///
/// The v1 value must validate exactly, so altered or stale v1 bytes refuse
/// here instead of migrating. Its binding, decision, denominator, roles,
/// capacity, predecessor and invalidation are carried verbatim: the task/input
/// revision in `decision.recipe_revision` is never reinterpreted as the policy
/// revision, and the binding stays covered by the new digest. The caller
/// supplies the stable reusable `policy_revision` and `policy` content
/// explicitly; nothing is defaulted or inferred, and no sidecar representation
/// is created. The migrated recipe carries `CONTEXT_RECIPE_SCHEMA_VERSION` and
/// a recomputed digest; the v1 digest survives on the v1 bytes, which remain
/// verifiable through `LegacyContextRecipeV1::validate_v1`.
pub fn migrate_legacy_recipe_v1(
    v1: &LegacyContextRecipeV1,
    policy_revision: PolicyRevision,
    policy: ContextRecipePolicy,
) -> Result<ContextRecipe, ContextError> {
    v1.validate_v1()?;
    policy.validate()?;
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_RECIPE_SCHEMA_VERSION,
        binding: v1.binding.clone(),
        decision: v1.decision.clone(),
        recipe_sha256: "0".repeat(64),
        policy_revision,
        policy,
        denominator: v1.denominator.clone(),
        mandatory_roles: v1.mandatory_roles.clone(),
        role_policies: v1.role_policies.clone(),
        capacity: v1.capacity,
        predecessor: v1.predecessor.clone(),
        invalidation: v1.invalidation.clone(),
    };
    recipe.recipe_sha256 = recipe.canonical_policy_digest()?;
    recipe.validate()?;
    Ok(recipe)
}

/// One semantic role's explicit loss rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleLossRule {
    /// Role governed by this rule.
    pub role: SemanticRole,
    /// Four-way policy; no Boolean replacement exists.
    pub loss_policy: LossPolicy,
    /// Whether this role's whole unit is required by the floor.
    pub required: bool,
    /// Allowed representation kinds for this role.
    pub allowed_representations: Vec<RepresentationKind>,
}

impl RoleLossRule {
    /// Validate explicit allowed representation declarations.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.allowed_representations.is_empty() {
            return Err(ContextError::MissingField(
                "role_policy.allowed_representations",
            ));
        }
        let required = match self.loss_policy {
            LossPolicy::NonDroppable => RepresentationKind::Whole,
            LossPolicy::HandleOnly => RepresentationKind::Handle,
            LossPolicy::Extractive => RepresentationKind::Extractive,
            LossPolicy::Summarizable => RepresentationKind::Summary,
        };
        let mut seen = std::collections::BTreeSet::new();
        if self
            .allowed_representations
            .iter()
            .any(|kind| !seen.insert(*kind) || !self.loss_policy.allows(*kind))
        {
            return Err(ContextError::WholeUnitRequired);
        }
        if !seen.contains(&required) {
            return Err(ContextError::WholeUnitRequired);
        }
        Ok(())
    }
}

/// Closed representation kinds declared by a recipe.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RepresentationKind {
    Whole,
    Handle,
    Extractive,
    Summary,
}

impl LossPolicy {
    /// Whether a representation is exact or no more lossy than this policy.
    const fn allows(self, representation: RepresentationKind) -> bool {
        match self {
            Self::NonDroppable => matches!(representation, RepresentationKind::Whole),
            Self::HandleOnly => matches!(representation, RepresentationKind::Handle),
            Self::Extractive => matches!(
                representation,
                RepresentationKind::Whole | RepresentationKind::Extractive
            ),
            Self::Summarizable => matches!(
                representation,
                RepresentationKind::Whole
                    | RepresentationKind::Extractive
                    | RepresentationKind::Summary
            ),
        }
    }
}

/// Exact requested provider/role denominator and provider dispositions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRoleDenominator {
    /// One slot per requested provider/role.
    pub requested: Vec<ProviderRole>,
    /// Explicit status for every requested slot.
    pub dispositions: Vec<ProviderDisposition>,
}

impl ProviderRoleDenominator {
    /// Validate one disposition per requested slot with no duplicates/extras.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.requested.is_empty() {
            return Err(ContextError::MissingField("denominator.requested"));
        }
        for slot in &self.requested {
            slot.validate()?;
        }
        let mut expected = std::collections::BTreeSet::new();
        for slot in &self.requested {
            if !expected.insert((slot.provider.clone(), slot.role)) {
                return Err(ContextError::Duplicate("denominator.requested"));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for disposition in &self.dispositions {
            disposition.validate()?;
            let key = (disposition.slot.provider.clone(), disposition.slot.role);
            if !expected.contains(&key) || !seen.insert(key) {
                return Err(ContextError::DenominatorMismatch);
            }
        }
        if seen.len() != expected.len() {
            return Err(ContextError::DenominatorMismatch);
        }
        Ok(())
    }
}

/// Provider availability disposition in the denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderDisposition {
    /// Exact requested slot.
    pub slot: ProviderRole,
    /// Current availability state.
    pub state: AtomAvailability,
    /// Evidence for the state, if available.
    pub evidence: Option<ProofBinding>,
}

impl ProviderDisposition {
    /// Validate slot identity and require evidence for blocked/unavailable.
    ///
    /// A `Blocked` or `Unavailable` slot without named evidence cannot
    /// support a coverage or absence claim, so it fails closed. All other
    /// states preserve the previous acceptance shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.slot.validate()?;
        if matches!(
            self.state,
            AtomAvailability::Blocked | AtomAvailability::Unavailable
        ) && self.evidence.is_none()
        {
            return Err(ContextError::MissingField(
                "denominator.dispositions.evidence",
            ));
        }
        Ok(())
    }
}

/// Independent route capacity components.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapacityLimits {
    /// Route capacity in bytes or tokenizer units, as declared by measurement.
    pub route_capacity: u64,
    /// Fixed envelope overhead.
    pub fixed_overhead: u64,
    /// Reserved output capacity.
    pub output_reserve: u64,
    /// Reserved review/reasoning capacity.
    pub review_reserve: u64,
}

impl CapacityLimits {
    /// Ensure independently recorded reserves reconcile without overflow.
    pub fn validate(&self) -> Result<(), ContextError> {
        let used = self
            .fixed_overhead
            .checked_add(self.output_reserve)
            .and_then(|value| value.checked_add(self.review_reserve))
            .ok_or(ContextError::Overflow)?;
        if used > self.route_capacity {
            return Err(ContextError::CapacityExceeded);
        }
        Ok(())
    }
}

/// Intrinsic learning provenance bound to one Governor-issued admission.
///
/// Attached by the legitimate learning pipeline when it emits a
/// learning-derived atom. The mark cites the exact owner issuance
/// (`permit_digest`); retrieval and delivery screens compare it against the
/// owner-verified permit, so a mark transplanted from another issuance
/// fails. Bare strings here authenticate nothing on their own.
///
/// Per I5.26, adapter normalization, compaction, or restatement does not
/// clear lineage: transports must preserve this field verbatim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningProvenance {
    /// Origin campaign the influence was admitted from.
    pub campaign_id: String,
    /// Local overlay subject bound by the issuance.
    pub overlay_id: Option<String>,
    /// Reusable candidate subject bound by the issuance.
    pub candidate_id: Option<String>,
    /// Closure disposition that closed the reusable candidate.
    pub closure_ref: Option<String>,
    /// Owning decision authority.
    pub owner: Option<String>,
    /// Draft deltas are ineligible for retrieval and delivery.
    pub draft: bool,
    /// Wall-clock expiry of the local admission as unix seconds.
    pub expires_at_unix_secs: Option<u64>,
    /// Digest of the exact Governor-issued permit this mark cites.
    pub permit_digest: String,
}

impl LearningProvenance {
    /// Shape validation only; issuance binding happens in the screens.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.campaign_id, "learning.campaign_id")?;
        if self
            .overlay_id
            .as_ref()
            .is_none_or(|id| id.trim().is_empty())
            && self
                .candidate_id
                .as_ref()
                .is_none_or(|id| id.trim().is_empty())
        {
            return Err(ContextError::MissingField("learning.subject"));
        }
        validate_digest(&self.permit_digest, "learning.permit_digest")?;
        Ok(())
    }
}

/// Candidate whole atom emitted by a provider projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextCandidate {
    /// Shared task/scope/fence identity.
    pub binding: ContextBinding,
    /// Stable atom identity.
    pub atom_id: ArtifactId,
    /// Provider and semantic role.
    pub provider_role: ProviderRole,
    /// Immutable source snapshot.
    pub source: SourceSnapshot,
    /// Exact half-open range of this atom inside `source`, when the provider
    /// measured one.
    ///
    /// The value reuses the boundary owner's own `ExactSourceRange` verbatim, so
    /// a range is never a second, weaker spelling: it names its coordinate
    /// system and the exact immutable source revision it was measured against,
    /// and `ContextCandidate::validate` re-checks both against `source` instead
    /// of inferring either. Its claimed span is bounded by
    /// `MAX_ATOM_SOURCE_RANGE_UNITS`.
    ///
    /// `None` is a typed unknown, not an exact whole-unit claim: a provider that
    /// cannot say where its material came from says nothing, and an absent range
    /// is never defaulted, inferred or widened into a range that reads as exact
    /// (I12.13, "unknown source boundaries remain unknown"). It is also the shape
    /// a boundary envelope already accepts for a source member it cannot pin, so
    /// a producer that has no measurement carries the same explicit absence on
    /// both sides rather than inventing an endpoint.
    ///
    /// The field is covered by the candidate canonical digest and by
    /// `AdmittedContextSet::canonical_payload`, so removing or altering a range
    /// changes the admitted atom identity instead of being invisible to it.
    #[serde(default)]
    pub source_range: Option<ExactSourceRange>,
    /// Intrinsic learning provenance. `None` means ordinary evidence with no
    /// learning treatment; `Some` marks learning-derived material that the
    /// retrieval and delivery screens must verify against an owner-verified
    /// Governor permit before it may influence an attempt. Covered by the
    /// candidate canonical digest: removal or alteration changes the atom
    /// identity and breaks bound measurements.
    #[serde(default)]
    pub learning: Option<LearningProvenance>,
    /// Whole or explicitly lossy representation.
    pub representation: AtomRepresentation,
    /// Explicit policy governing permissible loss.
    pub loss_policy: LossPolicy,
    /// Present/missing/freshness state.
    pub availability: AtomAvailability,
    /// Protection/privacy/authority ceilings.
    pub protected: bool,
    pub privacy: PrivacyClass,
    pub authority: AuthorityClass,
    /// Epistemic status and assertability.
    pub status: EpistemicStatus,
    pub assertability: Assertability,
    /// Exact measured representation.
    pub measurement: MeasurementRef,
    /// Interpretation dependency atom identities.
    pub dependencies: Vec<ArtifactId>,
    /// Evidence/proof ceiling.
    pub proof: ProofBinding,
}

impl ContextCandidate {
    /// Apply the current public-only disclosure boundary for admission.
    ///
    /// A Governor-owned route/disclosure contract must replace this narrow
    /// prototype rule before scoped or restricted material can cross a route.
    ///
    /// Owner transfer (issue #1025 finding 2): this cell refuses every
    /// non-public atom at the validation call sites and defines no
    /// `Secret`/`Restricted` route rule of its own. Route and disclosure
    /// enforcement for non-public material is owned by Governor
    /// `eliot-workscope` (`crates/governor/eliot-workscope/src/lib.rs:587`,
    /// `PrivacyProfile::admits`, denying with `PrivacyDenied` at `:676-677`
    /// and `:737-738`); downstream non-public disclosure is additionally
    /// withheld as `WithheldPrivacy` by `classify_privacy_and_proof`
    /// (`crates/smart/eliot-reactive-context-plan/src/plan.rs:2551-2557`).
    pub(crate) fn validate_public_privacy(&self) -> Result<(), ContextError> {
        if self.privacy == PrivacyClass::Public {
            Ok(())
        } else {
            Err(ContextError::InvalidField("candidate.privacy"))
        }
    }

    /// Validate a candidate without ranking, retrieval or provider calls.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.provider_role.validate()?;
        self.source.validate()?;
        if let Some(range) = &self.source_range {
            // The range carries the coordinate system and the exact immutable
            // source revision; reusing the boundary owner's own check is what
            // makes that binding verifiable instead of asserted. A snapshot the
            // range does not name, or endpoints the snapshot cannot order, is
            // refused here rather than carried into the admitted set.
            range.validate(&self.source)?;
            if range.length > MAX_ATOM_SOURCE_RANGE_UNITS {
                return Err(ContextError::Bounds {
                    field: "candidate.source_range.length",
                });
            }
        }
        if let Some(provenance) = &self.learning {
            provenance.validate()?;
        }
        self.representation.validate()?;
        self.measurement.validate()?;
        if self.dependencies.len() > 256 {
            return Err(ContextError::Bounds {
                field: "candidate.dependencies",
            });
        }
        if !self.loss_policy.allows(self.representation.kind()) {
            return Err(ContextError::WholeUnitRequired);
        }
        if matches!(
            self.status,
            EpistemicStatus::Observed | EpistemicStatus::Unknown
        ) && self.assertability == Assertability::Assertable
        {
            return Err(ContextError::InvalidField("candidate.assertability"));
        }
        if matches!(
            self.status,
            EpistemicStatus::Stale
                | EpistemicStatus::Contested
                | EpistemicStatus::Superseded
                | EpistemicStatus::Rejected
        ) && self.assertability == Assertability::Assertable
        {
            return Err(ContextError::InvalidField("candidate.assertability"));
        }
        if self.status == EpistemicStatus::Verified
            && self.assertability != Assertability::Assertable
        {
            return Err(ContextError::InvalidField("candidate.assertability"));
        }
        if self.availability == AtomAvailability::PresentCurrent
            && matches!(
                self.status,
                EpistemicStatus::Stale | EpistemicStatus::Superseded
            )
        {
            return Err(ContextError::InvalidField("candidate.availability"));
        }
        let mut dependencies = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            if !dependencies.insert(dependency.clone()) {
                return Err(ContextError::Duplicate("candidate.dependencies"));
            }
        }
        Ok(())
    }
}

/// A candidate admitted by a decision, retaining exact identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedAtom {
    /// Original candidate, never rebuilt from a string.
    pub candidate: ContextCandidate,
    /// One explicit admission disposition.
    pub disposition: AdmissionDisposition,
    /// Applied rule/evidence identity.
    pub rule_evidence: ArtifactId,
}

/// Per-candidate/provider admission status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionDisposition {
    Include,
    HandleOnly,
    Revalidate,
    Suppress,
    Quarantine,
    Unavailable,
    Blocked,
    OverBudget,
}
