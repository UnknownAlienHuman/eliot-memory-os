//! Whole atom, recipe and representation contracts.

use eliot_contracts::{ArtifactId, ContractVersion};
use eliot_evidence::{Assertability, EpistemicStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CONTEXT_CONTRACT_VERSION, ContextBinding, ContextError, DecisionRevision, ProofBinding,
    ProviderRole, SemanticRole, SourceSnapshot, validate_digest, validate_text,
};

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

/// Immutable policy recipe for one Context compilation.
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
        // values where ordering carries meaning.
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

    /// Validate closed policy and denominator coherence.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != CONTEXT_CONTRACT_VERSION {
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
        self.denominator.validate()?;
        if self.mandatory_roles.is_empty() || self.mandatory_roles.len() > 64 {
            return Err(ContextError::MissingField("recipe.mandatory_roles"));
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
        self.capacity.validate()
    }
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
            disposition.slot.validate()?;
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
    /// Validate a candidate without ranking, retrieval or provider calls.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.provider_role.validate()?;
        self.source.validate()?;
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
