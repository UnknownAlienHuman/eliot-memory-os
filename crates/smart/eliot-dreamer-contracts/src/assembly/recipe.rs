//! Versioned, owner-neutral Dreamer job recipes.
//!
//! A recipe declares the finite roles a Dreamer job may receive. A-03 owns
//! the vocabulary and intrinsic closure checks; A-04 owns choosing admitted
//! material for a recipe. The types in this module never resolve sources,
//! perform Context admission, run screens, call a model, or promote authority.

#![forbid(unsafe_code)]

use crate::budget::BudgetLimits;
use crate::error::{
    ContractViolation, check_schema_version, check_text, check_vec_bound, is_hex64_lower,
};
use crate::grounding::AttemptIdentity;
use crate::job::{DreamJobInput, JobClass};
use eliot_context_contracts::{LossPolicy as ContextLossPolicy, MeasurementUnit};
use eliot_contracts::{ArtifactId, SourceId};
use eliot_epistemic_contracts::{DisclosureClass, PositionAssertability, PrivacyHandling};
use eliot_evidence::EvidenceAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Exact wire revision of [`DreamJobRecipe`].
pub const RECIPE_SCHEMA_VERSION: u32 = 1;

const MAX_RECIPE_TEXT: usize = 512;
const MAX_ROLES: usize = 64;
const MAX_DEPENDENCIES: usize = 64;
const MAX_ROLE_ITEMS: u32 = 1_024;

const CURATION_ROLES: &[DreamInputRole] = &[
    DreamInputRole::CurationSourceSnapshot,
    DreamInputRole::CurationSourceDenominator,
    DreamInputRole::CurationScreenProfile,
    DreamInputRole::CurationProtectionCoverage,
    DreamInputRole::CurationSubtypePayload,
    DreamInputRole::CurationTargetSet,
    DreamInputRole::CurationEvidenceSet,
    DreamInputRole::CurationTargetDenominator,
    DreamInputRole::CurationTargetScreens,
    DreamInputRole::CurationTargetDispositions,
];

#[derive(JsonSchema)]
#[allow(dead_code)]
struct AttemptIdentitySchema {
    attempt_id: String,
    attempt_number: u32,
    maximum_attempts: u32,
}

/// Closed Dreamer input-role vocabulary. Every role in I9.4 and the Curation
/// bundle correction has an explicit typed slot; no open or fallback role is
/// accepted.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DreamInputRole {
    /// Exact user or agent question supplied to the job.
    ExactQuestion,
    /// Authenticated requester context.
    Requester,
    /// Governed evidence handles and source cards.
    Evidence,
    /// Governed memory handles and source cards.
    Memory,
    /// Accepted Architecture anchors.
    Architecture,
    /// Accepted Implementation contracts and observations.
    Implementation,
    /// Conformance evidence for the requested scope.
    Conformance,
    /// Conflicts and unresolved unknowns.
    ConflictsAndUnknowns,
    /// Privacy handling profile.
    PrivacyProfile,
    /// Explicitly allowed tools.
    AllowedTools,
    /// Explicitly allowed model routes.
    AllowedModelRoutes,
    /// Independent job budget declaration.
    Budget,
    /// Optional job deadline.
    Deadline,
    /// Requested output schema identity.
    OutputSchema,
    /// Forbidden effects carried as a policy boundary.
    ForbiddenEffects,
    /// Immutable Memory-Curation source snapshot reference.
    CurationSourceSnapshot,
    /// Exact Curation source denominator.
    CurationSourceDenominator,
    /// Exact Curation screen-profile reference.
    CurationScreenProfile,
    /// Required Curation protection and coverage contract identity.
    CurationProtectionCoverage,
    /// Exact Curation subtype and typed payload identity.
    CurationSubtypePayload,
    /// Exact target set the candidate may change.
    CurationTargetSet,
    /// Immutable evidence/reference set retained outside the target set.
    CurationEvidenceSet,
    /// Complete Curation target/member denominator.
    CurationTargetDenominator,
    /// A-19c target-screen receipts supplied by the screening owner.
    CurationTargetScreens,
    /// Every target protection and coverage disposition, including unknowns.
    CurationTargetDispositions,
}

/// Typed immutable content for roles absent from [`DreamJobInput`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeInput {
    /// Exact user/job question.
    ExactQuestion { text: String },
    /// Explicit conflicts and unknowns input.
    ConflictsAndUnknowns { content: String },
    /// Closed allowed-tool identities.
    AllowedTools { tools: Vec<String> },
    /// Closed allowed-model-route identities.
    AllowedModelRoutes { routes: Vec<String> },
    /// Exact output-schema identity.
    OutputSchema {
        schema_id: ArtifactId,
        schema_version: u32,
        schema_digest: String,
    },
    /// Closed forbidden-effect identities.
    ForbiddenEffects { effects: Vec<String> },
}

impl RecipeInput {
    /// Returns the role represented by this typed input.
    #[must_use]
    pub const fn role(&self) -> DreamInputRole {
        match self {
            Self::ExactQuestion { .. } => DreamInputRole::ExactQuestion,
            Self::ConflictsAndUnknowns { .. } => DreamInputRole::ConflictsAndUnknowns,
            Self::AllowedTools { .. } => DreamInputRole::AllowedTools,
            Self::AllowedModelRoutes { .. } => DreamInputRole::AllowedModelRoutes,
            Self::OutputSchema { .. } => DreamInputRole::OutputSchema,
            Self::ForbiddenEffects { .. } => DreamInputRole::ForbiddenEffects,
        }
    }

    /// Validates bounded typed content without interpreting it.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::ExactQuestion { text } | Self::ConflictsAndUnknowns { content: text } => {
                check_text(text, "recipe.input.content", 16_384)?;
            }
            Self::AllowedTools { tools }
            | Self::AllowedModelRoutes { routes: tools }
            | Self::ForbiddenEffects { effects: tools } => {
                check_vec_bound(tools.len(), MAX_ROLE_ITEMS as usize, "recipe.input.items")?;
                let mut seen = BTreeSet::new();
                for value in tools {
                    check_text(value, "recipe.input.item", MAX_RECIPE_TEXT)?;
                    if !seen.insert(value) {
                        return Err(ContractViolation::BindingMismatch {
                            field: "recipe.input.items",
                            reason: "typed recipe input items must be unique".to_owned(),
                        });
                    }
                }
            }
            Self::OutputSchema {
                schema_id,
                schema_version,
                schema_digest,
            } => {
                check_text(
                    schema_id.as_str(),
                    "recipe.input.schema_id",
                    MAX_RECIPE_TEXT,
                )?;
                if *schema_version == 0 {
                    return Err(ContractViolation::ImplicitDefault(
                        "recipe.input.schema_version",
                    ));
                }
                if !is_hex64_lower(schema_digest) {
                    return Err(ContractViolation::Malformed {
                        field: "recipe.input.schema_digest",
                        reason: "expected lowercase SHA-256 digest".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl DreamInputRole {
    /// Returns the stable wire spelling of this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactQuestion => "exact_question",
            Self::Requester => "requester",
            Self::Evidence => "evidence",
            Self::Memory => "memory",
            Self::Architecture => "architecture",
            Self::Implementation => "implementation",
            Self::Conformance => "conformance",
            Self::ConflictsAndUnknowns => "conflicts_and_unknowns",
            Self::PrivacyProfile => "privacy_profile",
            Self::AllowedTools => "allowed_tools",
            Self::AllowedModelRoutes => "allowed_model_routes",
            Self::Budget => "budget",
            Self::Deadline => "deadline",
            Self::OutputSchema => "output_schema",
            Self::ForbiddenEffects => "forbidden_effects",
            Self::CurationSourceSnapshot => "curation_source_snapshot",
            Self::CurationSourceDenominator => "curation_source_denominator",
            Self::CurationScreenProfile => "curation_screen_profile",
            Self::CurationProtectionCoverage => "curation_protection_coverage",
            Self::CurationSubtypePayload => "curation_subtype_payload",
            Self::CurationTargetSet => "curation_target_set",
            Self::CurationEvidenceSet => "curation_evidence_set",
            Self::CurationTargetDenominator => "curation_target_denominator",
            Self::CurationTargetScreens => "curation_target_screens",
            Self::CurationTargetDispositions => "curation_target_dispositions",
        }
    }

    /// Parses the exact wire spelling of a role.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        for role in ALL_ROLES {
            if role.as_str() == value {
                return Ok(*role);
            }
        }
        Err(ContractViolation::UnknownVariant {
            field: "dream_input_role",
            value: value.to_owned(),
        })
    }
}

const ALL_ROLES: &[DreamInputRole] = &[
    DreamInputRole::ExactQuestion,
    DreamInputRole::Requester,
    DreamInputRole::Evidence,
    DreamInputRole::Memory,
    DreamInputRole::Architecture,
    DreamInputRole::Implementation,
    DreamInputRole::Conformance,
    DreamInputRole::ConflictsAndUnknowns,
    DreamInputRole::PrivacyProfile,
    DreamInputRole::AllowedTools,
    DreamInputRole::AllowedModelRoutes,
    DreamInputRole::Budget,
    DreamInputRole::Deadline,
    DreamInputRole::OutputSchema,
    DreamInputRole::ForbiddenEffects,
    DreamInputRole::CurationSourceSnapshot,
    DreamInputRole::CurationSourceDenominator,
    DreamInputRole::CurationScreenProfile,
    DreamInputRole::CurationProtectionCoverage,
    DreamInputRole::CurationSubtypePayload,
    DreamInputRole::CurationTargetSet,
    DreamInputRole::CurationEvidenceSet,
    DreamInputRole::CurationTargetDenominator,
    DreamInputRole::CurationTargetScreens,
    DreamInputRole::CurationTargetDispositions,
];

/// Returns the minimum input roles required by each existing Dreamer class.
///
/// The returned roles are inputs to the class. Outputs such as an
/// `ArchitectureBrief`, a clarification question, or a configuration intent
/// are deliberately absent from this profile.
#[must_use]
pub const fn required_roles(job_class: JobClass) -> &'static [DreamInputRole] {
    match job_class {
        JobClass::Orientation | JobClass::Curation => COMMON_ROLES,
        JobClass::Clarification => CLARIFICATION_ROLES,
        JobClass::ResearchSynthesis => RESEARCH_ROLES,
        JobClass::ArchitectureSelfQuery => ARCHITECTURE_ROLES,
        JobClass::DevelopmentDiagnosis => DEVELOPMENT_ROLES,
        JobClass::Maintenance => MAINTENANCE_ROLES,
        JobClass::OrchestrationPlanning => ORCHESTRATION_ROLES,
        JobClass::ConfigurationAssistance => CONFIGURATION_ROLES,
    }
}

use DreamInputRole::{
    AllowedModelRoutes, AllowedTools, Architecture, Budget, ConflictsAndUnknowns, Conformance,
    Evidence, ExactQuestion, ForbiddenEffects, Implementation, OutputSchema, PrivacyProfile,
    Requester,
};
const COMMON_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    PrivacyProfile,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const CLARIFICATION_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    ConflictsAndUnknowns,
    PrivacyProfile,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const RESEARCH_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    Evidence,
    ConflictsAndUnknowns,
    PrivacyProfile,
    AllowedModelRoutes,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const ARCHITECTURE_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    Architecture,
    Implementation,
    Conformance,
    ConflictsAndUnknowns,
    PrivacyProfile,
    AllowedModelRoutes,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const DEVELOPMENT_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    Evidence,
    Implementation,
    Conformance,
    ConflictsAndUnknowns,
    PrivacyProfile,
    AllowedTools,
    AllowedModelRoutes,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const MAINTENANCE_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    Evidence,
    ConflictsAndUnknowns,
    PrivacyProfile,
    AllowedTools,
    AllowedModelRoutes,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const ORCHESTRATION_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    Evidence,
    ConflictsAndUnknowns,
    PrivacyProfile,
    AllowedModelRoutes,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];
const CONFIGURATION_ROLES: &[DreamInputRole] = &[
    ExactQuestion,
    Requester,
    Implementation,
    Conformance,
    ConflictsAndUnknowns,
    PrivacyProfile,
    AllowedModelRoutes,
    Budget,
    OutputSchema,
    ForbiddenEffects,
];

/// Closed applicability of one role in a job-class recipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RoleDisposition {
    /// At least `minimum` items are required.
    Required,
    /// Items may be supplied but are not required.
    Optional,
    /// A recipe condition may make the role required; A-04 records the result.
    Conditional,
    /// The role has no meaning for this recipe and must have no items.
    NotApplicable,
}

/// Whether an omitted applicable role must retain a reversible handle or
/// explicit non-recoverable reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RoleOmissionPolicy {
    /// The role cannot be omitted.
    NonDroppable,
    /// Omission requires a reversible exact handle.
    ReversibleHandle,
    /// Omission requires an explicit non-recoverable reason.
    NonRecoverableReason,
    /// The role does not apply to this recipe.
    NotApplicable,
}

/// Source cardinality and lineage rule for one recipe role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRuleKind {
    /// The role is self-contained and has no source handle.
    None,
    /// Each item must name one governed source/reference.
    GovernedReference,
    /// The role names a governed set of source/reference items.
    GovernedSet,
}

/// Owner, privacy, authority, and proof ceilings for a source-bearing role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceRule {
    /// Source rule kind.
    pub kind: SourceRuleKind,
    /// Optional exact owner permitted by the recipe.
    pub allowed_owner: Option<SourceId>,
    /// Categorical privacy values admitted by this role.
    pub allowed_privacy: Vec<PrivacyHandling>,
    /// Categorical evidence authorities admitted by this role.
    pub allowed_authority: Vec<EvidenceAuthority>,
    /// Categorical proof/assertability values admitted by this role.
    pub allowed_proof: Vec<PositionAssertability>,
    /// Disclosure values admitted by this role.
    pub allowed_disclosure: Vec<DisclosureClass>,
}

impl SourceRule {
    /// Returns whether this role is source-free.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self.kind, SourceRuleKind::None)
    }

    /// Validates source-rule coherence.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.is_none()
            && (self.allowed_owner.is_some()
                || !self.allowed_privacy.is_empty()
                || !self.allowed_authority.is_empty()
                || !self.allowed_proof.is_empty()
                || !self.allowed_disclosure.is_empty())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "role.source_rule.allowed_owner",
                reason: "source-free roles cannot declare source policy".to_owned(),
            });
        }
        if self.is_none() {
            return Ok(());
        }
        validate_allowed_values(&self.allowed_privacy, "role.source_rule.allowed_privacy", 3)?;
        validate_allowed_values(
            &self.allowed_authority,
            "role.source_rule.allowed_authority",
            6,
        )?;
        validate_allowed_values(&self.allowed_proof, "role.source_rule.allowed_proof", 7)?;
        validate_allowed_values(
            &self.allowed_disclosure,
            "role.source_rule.allowed_disclosure",
            3,
        )
    }
}

fn validate_allowed_values<T: PartialEq>(
    values: &[T],
    field: &'static str,
    maximum: usize,
) -> Result<(), ContractViolation> {
    if values.is_empty() {
        return Err(ContractViolation::MissingField(field));
    }
    check_vec_bound(values.len(), maximum, field)?;
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "allowed categorical values must be unique".to_owned(),
            });
        }
    }
    Ok(())
}

/// One explicit reserve contribution with its measurement profile and unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyReserve {
    /// Measurement profile that qualifies the value.
    pub profile: eliot_contracts::ArtifactId,
    /// Explicit unit of the reserve value.
    pub unit: MeasurementUnit,
    /// Reserved quantity; zero is distinct from unavailable.
    pub value: u64,
}

impl AssemblyReserve {
    /// Validates the explicit profile and measurement unit.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.profile.as_str().trim().is_empty() {
            return Err(ContractViolation::MissingField("reserve.profile"));
        }
        Ok(())
    }
}

/// Independent protocol reserves carried by a Dreamer assembly recipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyReserveSet {
    /// Fixed serialization and framing reserve.
    pub fixed: AssemblyReserve,
    /// Protocol envelope reserve.
    pub protocol: AssemblyReserve,
    /// Model-output reserve.
    pub model_output: AssemblyReserve,
    /// Grounding reserve.
    pub grounding: AssemblyReserve,
    /// Review reserve.
    pub review: AssemblyReserve,
    /// Headroom reserve.
    pub headroom: AssemblyReserve,
}

impl AssemblyReserveSet {
    /// Validates all six explicit reserve contributions.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for reserve in [
            &self.fixed,
            &self.protocol,
            &self.model_output,
            &self.grounding,
            &self.review,
            &self.headroom,
        ] {
            reserve.validate()?;
        }
        Ok(())
    }

    /// Adds only reserves with this exact profile and unit.
    ///
    /// Different units or profiles are intentionally excluded from the sum;
    /// STU and tokenizer observations are never converted into bytes here.
    pub fn total_for(
        &self,
        profile: &eliot_contracts::ArtifactId,
        unit: MeasurementUnit,
    ) -> Result<u64, ContractViolation> {
        self.validate()?;
        let mut total = 0_u64;
        for reserve in [
            &self.fixed,
            &self.protocol,
            &self.model_output,
            &self.grounding,
            &self.review,
            &self.headroom,
        ] {
            if reserve.profile != *profile || reserve.unit != unit {
                return Err(ContractViolation::BindingMismatch {
                    field: "assembly_reserve",
                    reason: "all reserve categories must share the requested profile and unit"
                        .to_owned(),
                });
            }
            total = total
                .checked_add(reserve.value)
                .ok_or(ContractViolation::Budget {
                    dimension: "assembly_reserve",
                    reason: "reserve total overflow".to_owned(),
                })?;
        }
        Ok(total)
    }
}

/// Closed predicate used by a conditional role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionalPredicate {
    /// The role applies when the named evidence role has an item.
    EvidenceAvailable,
    /// The role applies when the named role has a conflict or unknown.
    ConflictPresent,
    /// The role applies when the named role is present in the bundle.
    RolePresent,
}

/// Typed conditional trigger and the role whose retained evidence proves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalRequirement {
    /// Closed predicate kind.
    pub predicate: ConditionalPredicate,
    /// Earlier role whose retained items establish the predicate.
    pub evidence_role: DreamInputRole,
    /// Optional exact CoverageDenominator/CoverageReceipt pair that may
    /// establish a qualified `KnownFalse` result.
    pub coverage: Option<ConditionalCoverageBinding>,
}

/// Exact manifest keys binding a conditional predicate to a coverage proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalCoverageBinding {
    pub denominator: String,
    pub receipt: String,
}

impl ConditionalCoverageBinding {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if !is_hex64_lower(&self.denominator) || !is_hex64_lower(&self.receipt) {
            return Err(ContractViolation::Malformed {
                field: "role.condition.coverage",
                reason: "coverage binding keys must be lowercase SHA-256 digests".to_owned(),
            });
        }
        Ok(())
    }
}

/// One ordered role declaration in a [`DreamJobRecipe`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeRole {
    /// Closed role identity.
    pub role: DreamInputRole,
    /// Whether this role applies to the selected job recipe.
    pub disposition: RoleDisposition,
    /// Minimum number of retained items when the role applies.
    pub minimum: u32,
    /// Maximum number of retained items when the role applies.
    pub maximum: u32,
    /// Earlier roles whose interpretation is required before this role.
    pub interpretation_dependencies: Vec<DreamInputRole>,
    /// Stable priority for source-bearing roles; does not select sources.
    pub source_priority: u16,
    /// Explicit source and lineage rule.
    pub source_rule: SourceRule,
    /// Whether this role is protected from silent loss.
    pub protected: bool,
    /// Explicit loss policy for omissions or non-applicability.
    pub representation_loss: ContextLossPolicy,
    /// Explicit omission/reopen policy for this role.
    pub omission_policy: RoleOmissionPolicy,
    /// Required typed predicate when this role is conditional.
    pub condition: Option<ConditionalRequirement>,
}

impl RecipeRole {
    /// Validates bounds and local role/loss coherence.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.minimum > self.maximum || self.maximum > MAX_ROLE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "role.minimum_or_maximum",
                min: i64::from(self.minimum),
                max: i64::from(MAX_ROLE_ITEMS),
                got: i64::from(self.maximum),
            });
        }
        check_vec_bound(
            self.interpretation_dependencies.len(),
            MAX_DEPENDENCIES,
            "role.interpretation_dependencies",
        )?;
        let mut dependencies = BTreeSet::new();
        for dependency in &self.interpretation_dependencies {
            if *dependency == self.role || !dependencies.insert(*dependency) {
                return Err(ContractViolation::BindingMismatch {
                    field: "role.interpretation_dependencies",
                    reason: "dependencies must be distinct and cannot include the role itself"
                        .to_owned(),
                });
            }
        }
        self.source_rule.validate()?;
        match self.disposition {
            RoleDisposition::Required if self.minimum == 0 => {
                return Err(ContractViolation::MissingField("role.minimum"));
            }
            RoleDisposition::Conditional if self.minimum == 0 || self.maximum == 0 => {
                return Err(ContractViolation::MissingField("role.minimum"));
            }
            RoleDisposition::NotApplicable
                if self.minimum != 0
                    || self.maximum != 0
                    || self.protected
                    || self.source_priority != 0
                    || !self.interpretation_dependencies.is_empty()
                    || !self.source_rule.is_none()
                    || !matches!(self.omission_policy, RoleOmissionPolicy::NotApplicable)
                    || !matches!(self.representation_loss, ContextLossPolicy::NonDroppable) =>
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "role.not_applicable",
                    reason: "not-applicable roles must have an empty source-free policy".to_owned(),
                });
            }
            _ => {}
        }
        if self.protected && !matches!(self.representation_loss, ContextLossPolicy::NonDroppable) {
            return Err(ContractViolation::BindingMismatch {
                field: "role.representation_loss",
                reason: "protected roles must preserve material without silent loss".to_owned(),
            });
        }
        if self.disposition != RoleDisposition::NotApplicable
            && (self.protected
                || matches!(self.representation_loss, ContextLossPolicy::NonDroppable))
            && !matches!(self.omission_policy, RoleOmissionPolicy::NonDroppable)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "role.omission_policy",
                reason: "protected or non-droppable roles cannot declare an omission policy"
                    .to_owned(),
            });
        }
        if matches!(self.omission_policy, RoleOmissionPolicy::NotApplicable)
            && !matches!(self.disposition, RoleDisposition::NotApplicable)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "role.omission_policy",
                reason: "not-applicable omission is only valid for a not-applicable role"
                    .to_owned(),
            });
        }
        if self.source_rule.is_none() && self.source_priority != 0 {
            return Err(ContractViolation::BindingMismatch {
                field: "role.source_priority",
                reason: "source-free roles cannot declare source priority".to_owned(),
            });
        }
        match (&self.disposition, &self.condition) {
            (RoleDisposition::Conditional, None) => {
                return Err(ContractViolation::MissingField("role.condition"));
            }
            (RoleDisposition::Conditional, Some(_)) => {}
            (_, Some(_)) => {
                return Err(ContractViolation::BindingMismatch {
                    field: "role.condition",
                    reason: "only conditional roles may declare a condition".to_owned(),
                });
            }
            _ => {}
        }
        if let Some(condition) = &self.condition
            && let Some(coverage) = &condition.coverage
        {
            coverage.validate()?;
        }
        Ok(())
    }
}

/// Versioned job-class recipe consumed by A-04 bundle assembly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamJobRecipe {
    /// Exact recipe wire revision.
    pub schema_version: u32,
    /// Stable recipe identity.
    pub recipe_id: String,
    /// Owner-issued recipe revision identity.
    pub recipe_revision: String,
    /// Canonical digest of all fields except this digest.
    pub recipe_digest: String,
    /// Complete admitted job identity, retained losslessly.
    pub job: DreamJobInput,
    /// Exact attempt identity for this recipe execution.
    #[schemars(with = "AttemptIdentitySchema")]
    pub attempt: AttemptIdentity,
    /// Typed immutable role inputs not present in the compact job envelope.
    pub inputs: Vec<RecipeInput>,
    /// Whether this recipe requires the exact A-15 admitted context closure.
    /// This declaration is independent of source-role names.
    pub context_required: bool,
    /// Ordered finite role denominator.
    pub roles: Vec<RecipeRole>,
    /// Independent declared per-dimension limits.
    pub limits: BudgetLimits,
    /// Independent protocol/model/grounding/review reserves held by the recipe.
    pub reserves: AssemblyReserveSet,
}

impl DreamJobRecipe {
    /// Computes the exact digest of one source-free recipe/job input value.
    pub fn source_free_value_digest(
        &self,
        role: DreamInputRole,
    ) -> Result<Option<String>, ContractViolation> {
        let value = match role {
            DreamInputRole::ExactQuestion
            | DreamInputRole::ConflictsAndUnknowns
            | DreamInputRole::AllowedTools
            | DreamInputRole::AllowedModelRoutes
            | DreamInputRole::OutputSchema
            | DreamInputRole::ForbiddenEffects => {
                self.inputs.iter().find(|input| input.role() == role)
            }
            _ => None,
        };
        if let Some(input) = value {
            return Ok(Some(crate::encoding::digest_hex(&super::canonical_bytes(
                input,
                "input_bytes",
                usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                    ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "input byte ceiling does not fit this platform".to_owned(),
                    }
                })?,
            )?)));
        }
        let bytes = match role {
            DreamInputRole::Requester => Some(super::canonical_bytes(
                &self.job.requester,
                "input_bytes",
                usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                    ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "input byte ceiling does not fit this platform".to_owned(),
                    }
                })?,
            )?),
            DreamInputRole::PrivacyProfile => Some(super::canonical_bytes(
                &self.job.privacy_profile,
                "input_bytes",
                usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                    ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "input byte ceiling does not fit this platform".to_owned(),
                    }
                })?,
            )?),
            DreamInputRole::Budget => Some(super::canonical_bytes(
                &self.job.budget,
                "input_bytes",
                usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                    ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "input byte ceiling does not fit this platform".to_owned(),
                    }
                })?,
            )?),
            DreamInputRole::Deadline => self
                .job
                .deadline_ms
                .as_ref()
                .map(|value| {
                    super::canonical_bytes(
                        value,
                        "input_bytes",
                        usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                            ContractViolation::Budget {
                                dimension: "input_bytes",
                                reason: "input byte ceiling does not fit this platform".to_owned(),
                            }
                        })?,
                    )
                })
                .transpose()?,
            _ => None,
        };
        Ok(bytes.map(|bytes| crate::encoding::digest_hex(&bytes)))
    }

    /// Computes the canonical recipe digest.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        self.validate_preimage_shape()?;
        self.computed_digest_unchecked()
    }

    fn computed_digest_unchecked(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct RecipeDigestPreimage<'a> {
            schema_version: u32,
            recipe_id: &'a str,
            recipe_revision: &'a str,
            recipe_digest: &'a str,
            job: &'a DreamJobInput,
            attempt: &'a AttemptIdentity,
            inputs: &'a [RecipeInput],
            context_required: bool,
            roles: &'a [RecipeRole],
            limits: &'a BudgetLimits,
            reserves: &'a AssemblyReserveSet,
        }
        let zero_digest = "0".repeat(64);
        let preimage = RecipeDigestPreimage {
            schema_version: self.schema_version,
            recipe_id: &self.recipe_id,
            recipe_revision: &self.recipe_revision,
            recipe_digest: &zero_digest,
            job: &self.job,
            attempt: &self.attempt,
            inputs: &self.inputs,
            context_required: self.context_required,
            roles: &self.roles,
            limits: &self.limits,
            reserves: &self.reserves,
        };
        let bytes = super::canonical_bytes(
            &preimage,
            "assembly_carrier",
            super::ASSEMBLY_CARRIER_CEILING,
        )?;
        Ok(crate::encoding::digest_hex(&bytes))
    }

    /// Validates recipe identity, role closure, and independent budget arithmetic.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_preimage_shape()?;
        if !is_hex64_lower(&self.recipe_digest) {
            return Err(ContractViolation::Malformed {
                field: "recipe_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        if self.computed_digest_unchecked()? != self.recipe_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "recipe_digest",
                reason: "recipe preimage digest mismatch".to_owned(),
            });
        }
        self.validate_role_closure()
    }

    fn validate_preimage_shape(&self) -> Result<(), ContractViolation> {
        super::preflight(self, "assembly_carrier", super::ASSEMBLY_CARRIER_CEILING)?;
        check_schema_version(self.schema_version, RECIPE_SCHEMA_VERSION)?;
        check_text(&self.recipe_id, "recipe_id", MAX_RECIPE_TEXT)?;
        check_text(&self.recipe_revision, "recipe_revision", MAX_RECIPE_TEXT)?;
        self.job.validate()?;
        check_text(&self.attempt.attempt_id, "attempt.attempt_id", 128)?;
        if self.attempt.attempt_number == 0
            || self.attempt.attempt_number > self.attempt.maximum_attempts
            || self.attempt.maximum_attempts == 0
            || self.job.budget.attempts != Some(u64::from(self.attempt.maximum_attempts))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "attempt",
                reason: "attempt identity must bind the finite job attempts budget".to_owned(),
            });
        }
        self.limits.require_exact()?;
        validate_limits_within_job(&self.limits, &self.job.budget)?;
        self.reserves.validate()?;
        check_vec_bound(self.inputs.len(), MAX_ROLE_ITEMS as usize, "inputs")?;
        let mut input_roles = BTreeSet::new();
        for input in &self.inputs {
            input.validate()?;
            if !input_roles.insert(input.role()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "inputs",
                    reason: "recipe inputs must contain one value per role".to_owned(),
                });
            }
        }
        check_vec_bound(self.roles.len(), MAX_ROLES, "roles")?;
        if self.roles.is_empty() {
            return Err(ContractViolation::MissingField("roles"));
        }
        for role in &self.roles {
            role.validate()?;
        }
        Ok(())
    }

    fn validate_role_closure(&self) -> Result<(), ContractViolation> {
        self.validate_role_order()?;
        self.validate_class_roles()
    }

    fn validate_role_order(&self) -> Result<(), ContractViolation> {
        let mut seen = BTreeSet::new();
        for role in &self.roles {
            if !seen.insert(role.role) {
                return Err(ContractViolation::BindingMismatch {
                    field: "roles",
                    reason: "role denominator contains a duplicate role".to_owned(),
                });
            }
            let role_index = self
                .roles
                .iter()
                .position(|candidate| candidate.role == role.role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "roles",
                    reason: "role denominator changed during validation".to_owned(),
                })?;
            if role.interpretation_dependencies.iter().any(|dependency| {
                let Some(dependency_index) = self
                    .roles
                    .iter()
                    .position(|candidate| candidate.role == *dependency)
                else {
                    return true;
                };
                let Some(dependency_role) = self.roles.get(dependency_index) else {
                    return true;
                };
                dependency_role.disposition == RoleDisposition::NotApplicable
                    || dependency_role.maximum == 0
                    || dependency_index >= role_index
            }) {
                return Err(ContractViolation::BindingMismatch {
                    field: "roles.interpretation_dependencies",
                    reason: "dependencies must name earlier denominator roles".to_owned(),
                });
            }
            if let Some(condition) = &role.condition {
                let Some(evidence) = self
                    .roles
                    .iter()
                    .find(|candidate| candidate.role == condition.evidence_role)
                else {
                    return Err(ContractViolation::BindingMismatch {
                        field: "roles.condition.evidence_role",
                        reason: "condition evidence role is absent".to_owned(),
                    });
                };
                if evidence.disposition == RoleDisposition::NotApplicable {
                    return Err(ContractViolation::BindingMismatch {
                        field: "roles.condition.evidence_role",
                        reason: "condition evidence role cannot be not-applicable".to_owned(),
                    });
                }
                let evidence_index = self
                    .roles
                    .iter()
                    .position(|candidate| candidate.role == condition.evidence_role)
                    .ok_or(ContractViolation::BindingMismatch {
                        field: "roles.condition.evidence_role",
                        reason: "condition evidence role is absent".to_owned(),
                    })?;
                if evidence_index >= role_index {
                    return Err(ContractViolation::BindingMismatch {
                        field: "roles.condition.evidence_role",
                        reason: "condition evidence must name an earlier role".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_class_roles(&self) -> Result<(), ContractViolation> {
        let input_roles: BTreeSet<_> = self.inputs.iter().map(RecipeInput::role).collect();
        if !self
            .roles
            .iter()
            .any(|role| role.disposition != RoleDisposition::NotApplicable && role.minimum > 0)
        {
            return Err(ContractViolation::MissingField("roles.minimum"));
        }
        if self.job.job_class == JobClass::Orientation {
            for role in [DreamInputRole::Architecture, DreamInputRole::Implementation] {
                if !self.roles.iter().any(|candidate| candidate.role == role) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "roles",
                        reason: format!("orientation must declare {} applicability", role.as_str()),
                    });
                }
            }
        }
        for required in required_roles(self.job.job_class) {
            let role = self
                .roles
                .iter()
                .find(|candidate| candidate.role == *required)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "roles",
                    reason: format!("required role {} is absent", required.as_str()),
                })?;
            if role.disposition != RoleDisposition::Required || role.minimum == 0 {
                return Err(ContractViolation::BindingMismatch {
                    field: "roles.disposition",
                    reason: format!("role {} must be required", required.as_str()),
                });
            }
            if requires_recipe_input(*required) && !input_roles.contains(required) {
                return Err(ContractViolation::BindingMismatch {
                    field: "inputs",
                    reason: format!("required role {} has no typed input", required.as_str()),
                });
            }
            if requires_recipe_input(*required) && (role.minimum > 1 || role.maximum < 1) {
                return Err(ContractViolation::OutOfBounds {
                    field: "role.minimum_or_maximum",
                    min: 1,
                    max: 1,
                    got: i64::from(role.minimum),
                });
            }
        }
        for input in &self.inputs {
            let role = self
                .roles
                .iter()
                .find(|candidate| candidate.role == input.role())
                .ok_or(ContractViolation::BindingMismatch {
                    field: "inputs",
                    reason: format!(
                        "typed input {} is absent from the role denominator",
                        input.role().as_str()
                    ),
                })?;
            if role.disposition == RoleDisposition::NotApplicable || !role.source_rule.is_none() {
                return Err(ContractViolation::BindingMismatch {
                    field: "inputs",
                    reason: "typed source-free input must bind an applicable source-free role"
                        .to_owned(),
                });
            }
            if role.minimum > 1 || role.maximum < 1 {
                return Err(ContractViolation::OutOfBounds {
                    field: "role.minimum_or_maximum",
                    min: 1,
                    max: 1,
                    got: i64::from(role.minimum),
                });
            }
        }
        if let Some(deadline_role) = self
            .roles
            .iter()
            .find(|candidate| candidate.role == DreamInputRole::Deadline)
            && self.job.deadline_ms.is_none()
            && deadline_role.disposition != RoleDisposition::NotApplicable
        {
            return Err(ContractViolation::BindingMismatch {
                field: "roles.deadline",
                reason: "deadline without a job deadline must be not-applicable".to_owned(),
            });
        }
        for curation_role in CURATION_ROLES {
            let role = self
                .roles
                .iter()
                .find(|candidate| candidate.role == *curation_role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "roles",
                    reason: format!("Curation role {} is absent", curation_role.as_str()),
                })?;
            let wanted = if self.job.job_class == JobClass::Curation {
                RoleDisposition::Required
            } else {
                RoleDisposition::NotApplicable
            };
            if role.disposition != wanted {
                return Err(ContractViolation::BindingMismatch {
                    field: "roles.disposition",
                    reason: format!(
                        "role {} has the wrong class disposition",
                        curation_role.as_str()
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validates that this recipe is the exact identity envelope of `job`.
    pub fn bind_job(&self, job: &DreamJobInput) -> Result<(), ContractViolation> {
        self.validate()?;
        job.validate()?;
        if self.job != *job {
            return Err(ContractViolation::BindingMismatch {
                field: "job",
                reason: "recipe and job identity differs".to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_limits_within_job(
    recipe: &BudgetLimits,
    job: &BudgetLimits,
) -> Result<(), ContractViolation> {
    for (recipe_value, job_value, dimension) in [
        (recipe.input_bytes, job.input_bytes, "input_bytes"),
        (recipe.output_bytes, job.output_bytes, "output_bytes"),
        (recipe.source_width, job.source_width, "source_width"),
        (
            recipe.reference_width,
            job.reference_width,
            "reference_width",
        ),
        (recipe.model_calls, job.model_calls, "model_calls"),
        (recipe.attempts, job.attempts, "attempts"),
        (recipe.candidates, job.candidates, "candidates"),
        (recipe.wall_ms, job.wall_ms, "wall_ms"),
        (recipe.work_fan_out, job.work_fan_out, "work_fan_out"),
        (recipe.report_bytes, job.report_bytes, "report_bytes"),
        (recipe.max_stu, job.max_stu, "max_stu"),
    ] {
        let Some(recipe_value) = recipe_value else {
            return Err(ContractViolation::MissingField("recipe.limits"));
        };
        let Some(job_value) = job_value else {
            return Err(ContractViolation::BindingMismatch {
                field: "recipe.limits",
                reason: format!("job budget is unknown for {dimension}"),
            });
        };
        if recipe_value > job_value {
            return Err(ContractViolation::Budget {
                dimension,
                reason: "recipe limit exceeds the admitted job budget".to_owned(),
            });
        }
    }
    Ok(())
}

fn requires_recipe_input(role: DreamInputRole) -> bool {
    matches!(
        role,
        DreamInputRole::ExactQuestion
            | DreamInputRole::ConflictsAndUnknowns
            | DreamInputRole::AllowedTools
            | DreamInputRole::AllowedModelRoutes
            | DreamInputRole::OutputSchema
            | DreamInputRole::ForbiddenEffects
    )
}
