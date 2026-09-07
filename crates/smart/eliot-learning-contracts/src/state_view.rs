//! Immutable recipe-bound learning state projections.

use eliot_contracts::{ArtifactId, TaskRevision};
use eliot_evidence::EvidenceFreshness;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::LearningContractError,
    identity::{
        CampaignId, ContractBinding, MemberId, OwnerId, SlotId, TargetId, digest_without_field,
        validate_digest,
    },
};

/// How a slot participates in a recipe denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SlotRequirement {
    /// The slot is required for recipe completeness.
    Required,
    /// The slot is declared but does not block completeness.
    Optional,
    /// The slot is required only when its prerequisite is present.
    Conditional { depends_on: SlotId },
}

/// Explicit reason a recipe may omit a slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OmissionPolicy {
    /// Every required slot must be represented in the view.
    RequiredSlots,
    /// A declared slot may be absent only with an explicit frontier entry.
    ExplicitFrontier,
}

/// One declared owner/member slot in a state-view recipe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlotSpec {
    /// Stable slot identity.
    pub slot_id: SlotId,
    /// Semantic owner of this slot.
    pub owner: OwnerId,
    /// Causally coherent target covered by the slot.
    pub target: TargetId,
    /// Requiredness in the declared denominator.
    pub requirement: SlotRequirement,
    /// Members declared by the owner for this slot.
    pub declared_members: Vec<MemberId>,
    /// Accepted member schema/type label.
    pub accepted_type: String,
    /// Accepted schema digest.
    pub schema_digest: String,
}

impl SlotSpec {
    /// Validate bounds, schema identity and member uniqueness.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.slot_id.validate()?;
        self.owner.validate()?;
        crate::identity::validate_external_id(self.target.as_str(), "slot.target")?;
        if self.accepted_type.trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "slot.accepted_type",
            });
        }
        validate_digest(&self.schema_digest, "slot.schema_digest")?;
        if self.declared_members.len() > 256 {
            return Err(LearningContractError::Bound {
                field: "slot.declared_members",
            });
        }
        ensure_unique(
            self.declared_members.iter().map(MemberId::as_str),
            "slot.declared_members",
        )
    }
}

/// Declared versus observed source/member counts; they are never inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceDenominator {
    /// Number of slots or members declared by the recipe.
    pub declared: u32,
    /// Number observed with a disposition in this projection.
    pub observed: u32,
}

impl SourceDenominator {
    /// Check that observed coverage cannot exceed declaration.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.declared == 0 {
            return Err(LearningContractError::Missing {
                field: "denominator.declared",
            });
        }
        if self.observed > self.declared {
            return Err(LearningContractError::IncompleteCoverage);
        }
        Ok(())
    }
}

/// One of the explicit dispositions for a declared slot/member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SlotDisposition {
    /// Projection is current for its source revision.
    Current,
    /// Retained historical material is not current.
    Historical,
    /// Source freshness has passed its boundary.
    Stale,
    /// Superseded by a later owner record.
    Superseded,
    /// Owner declared the member but its source is unavailable.
    Unavailable,
    /// Owner or dependency blocked projection.
    Blocked,
    /// Evidence exists but its position is unknown.
    Unknown,
    /// Owners disagree and the conflict remains visible.
    Conflicted,
    /// Owner affirmatively declared no member for this slot.
    KnownEmpty,
}

/// Recipe completeness, independent from lifecycle or evidence status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Completeness {
    /// Every required slot/member in the declared recipe has a disposition.
    CompleteForDeclaredRecipe,
    /// Some declared material has a disposition, but required coverage is open.
    Partial,
    /// Required source freshness has passed its declared boundary.
    Stale,
    /// A required owner/dependency prevented a complete projection.
    Blocked,
}

/// A source/member projection retained inside an immutable view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberProjection {
    /// Declared member identity.
    pub member_id: MemberId,
    /// Owner that issued the projection.
    pub owner: OwnerId,
    /// Source snapshot and revision clock.
    pub source: crate::identity::SourceLineage,
    /// Projection revision, separate from source revision.
    pub projection_revision: TaskRevision,
    /// Explicit disposition.
    pub disposition: SlotDisposition,
    /// Optional typed value identity, never an untyped payload.
    pub value_digest: Option<String>,
    /// Evidence handles supporting this disposition.
    pub evidence: Vec<ArtifactId>,
}

impl MemberProjection {
    /// Validate a member without promoting it to truth.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.member_id.validate()?;
        self.owner.validate()?;
        self.source.validate()?;
        if let Some(value) = &self.value_digest {
            validate_digest(value, "member.value_digest")?;
        }
        if matches!(self.disposition, SlotDisposition::Current) && self.value_digest.is_none() {
            return Err(LearningContractError::Missing {
                field: "member.value_digest",
            });
        }
        ensure_unique(
            self.evidence.iter().map(ArtifactId::as_str),
            "member.evidence",
        )
    }
}

/// A slot projection with one explicit disposition per declared member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlotProjection {
    /// Recipe slot identity.
    pub slot_id: SlotId,
    /// Owner-issued slot disposition.
    pub disposition: SlotDisposition,
    /// Members observed for this slot.
    pub members: Vec<MemberProjection>,
    /// Evidence handles for the slot-level disposition.
    pub evidence: Vec<ArtifactId>,
}

impl SlotProjection {
    /// Validate member uniqueness and explicit slot disposition.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.slot_id.validate()?;
        for member in &self.members {
            member.validate()?;
        }
        ensure_unique(
            self.members.iter().map(|m| m.member_id.as_str()),
            "slot.members",
        )?;
        ensure_unique(
            self.evidence.iter().map(ArtifactId::as_str),
            "slot.evidence",
        )
    }
}

/// Explicit owner disagreement retained in the derived view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerDisagreement {
    /// Slot in which owners disagree.
    pub slot_id: SlotId,
    /// Owners whose projections disagree.
    pub owners: Vec<OwnerId>,
    /// Conflict evidence handles.
    pub evidence: Vec<ArtifactId>,
}

impl OwnerDisagreement {
    /// Validate that a disagreement remains attributable.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.slot_id.validate()?;
        if self.owners.len() < 2 {
            return Err(LearningContractError::Bound {
                field: "disagreement.owners",
            });
        }
        for owner in &self.owners {
            owner.validate()?;
        }
        ensure_unique(
            self.owners.iter().map(OwnerId::as_str),
            "disagreement.owners",
        )?;
        if self.evidence.is_empty() {
            return Err(LearningContractError::Missing {
                field: "disagreement.evidence",
            });
        }
        Ok(())
    }
}

/// Exact recipe used to derive a view; this record itself is immutable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningStateViewRecipe {
    /// Recipe identity.
    pub recipe_id: ArtifactId,
    /// Campaign identity.
    pub campaign_id: CampaignId,
    /// Causally coherent target.
    pub target: TargetId,
    /// Cross-record request/task/scope/fence binding.
    pub binding: ContractBinding,
    /// Exact slot denominator.
    pub slots: Vec<SlotSpec>,
    /// Freshness boundary for source projections.
    pub freshness: EvidenceFreshness,
    /// Explicit privacy class label owned by the caller boundary.
    pub privacy_class: String,
    /// Omission semantics.
    pub omission_policy: OmissionPolicy,
    /// Canonical recipe shape digest, excluding this field.
    pub canonical_digest: String,
}

impl LearningStateViewRecipe {
    /// Validate the recipe and its exact slot denominator.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.recipe_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing { field: "recipe_id" });
        }
        self.campaign_id.validate()?;
        crate::identity::validate_external_id(self.target.as_str(), "view.target")?;
        self.binding.validate()?;
        if self.slots.is_empty() {
            return Err(LearningContractError::Missing {
                field: "recipe.slots",
            });
        }
        for slot in &self.slots {
            slot.validate()?;
        }
        ensure_unique(
            self.slots.iter().map(|s| s.slot_id.as_str()),
            "recipe.slots",
        )?;
        let slot_ids: std::collections::BTreeSet<_> = self
            .slots
            .iter()
            .map(|slot| slot.slot_id.as_str())
            .collect();
        for slot in &self.slots {
            if let SlotRequirement::Conditional { depends_on } = &slot.requirement
                && (!slot_ids.contains(depends_on.as_str()) || *depends_on == slot.slot_id)
            {
                return Err(LearningContractError::ScopeMismatch {
                    field: "slot.requirement.depends_on",
                });
            }
        }
        if self.privacy_class.trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "recipe.privacy_class",
            });
        }
        validate_digest(&self.canonical_digest, "recipe.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "recipe.canonical_digest",
            });
        }
        Ok(())
    }

    /// Populate the canonical digest after constructing the recipe.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

/// Immutable projection of the declared recipe and its observed dispositions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignLearningStateView {
    /// View identity.
    pub view_id: ArtifactId,
    /// Exact recipe identity and shape digest.
    pub recipe_id: ArtifactId,
    /// Campaign identity retained across records.
    pub campaign_id: CampaignId,
    /// Target projected by this view.
    pub target: TargetId,
    /// Same binding as the recipe.
    pub binding: ContractBinding,
    /// Recipe digest used for this derivation.
    pub recipe_digest: String,
    /// One projection per declared slot.
    pub slots: Vec<SlotProjection>,
    /// Declared and observed counts.
    pub denominator: SourceDenominator,
    /// Explicit completeness state.
    pub completeness: Completeness,
    /// Slots omitted with their frontier recorded.
    pub omissions: Vec<SlotId>,
    /// Unknown/unvisited recipe frontier.
    pub frontier: Vec<SlotId>,
    /// Owner disagreements remain visible.
    pub owner_disagreements: Vec<OwnerDisagreement>,
    /// Required objective/acceptance/evaluator/context references.
    pub required_references: Vec<ArtifactId>,
    /// Explicit invalidation marker.
    pub invalidated: bool,
    /// Why the view was invalidated, if applicable.
    pub invalidation_reason: Option<String>,
    /// Canonical view shape digest, excluding this field.
    pub canonical_digest: String,
}

impl CampaignLearningStateView {
    /// Validate exact recipe binding, denominator and one disposition per slot/member.
    #[allow(clippy::too_many_lines)]
    pub fn validate_against(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), LearningContractError> {
        recipe.validate()?;
        if self.recipe_id != recipe.recipe_id
            || self.campaign_id != recipe.campaign_id
            || self.target != recipe.target
            || self.recipe_digest != recipe.canonical_digest
            || self.binding != recipe.binding
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.recipe_binding",
            });
        }
        if self.view_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing { field: "view_id" });
        }
        self.binding.validate()?;
        self.denominator.validate()?;
        for slot in &self.slots {
            slot.validate()?;
        }
        ensure_unique(self.slots.iter().map(|s| s.slot_id.as_str()), "view.slots")?;
        let recipe_by_id: std::collections::BTreeMap<_, _> = recipe
            .slots
            .iter()
            .map(|slot| (slot.slot_id.as_str(), slot))
            .collect();
        for projection in &self.slots {
            let Some(spec) = recipe_by_id.get(projection.slot_id.as_str()) else {
                return Err(LearningContractError::ScopeMismatch {
                    field: "view.slots",
                });
            };
            let declared: std::collections::BTreeSet<_> =
                spec.declared_members.iter().map(MemberId::as_str).collect();
            let observed: std::collections::BTreeSet<_> = projection
                .members
                .iter()
                .map(|member| member.member_id.as_str())
                .collect();
            if declared != observed {
                return Err(LearningContractError::IncompleteCoverage);
            }
            if projection.disposition == SlotDisposition::KnownEmpty && !declared.is_empty() {
                return Err(LearningContractError::IncompleteCoverage);
            }
            let current_members = projection
                .members
                .iter()
                .all(|member| member.disposition == SlotDisposition::Current);
            if matches!(projection.disposition, SlotDisposition::Current)
                && (!declared.is_empty() && !current_members)
            {
                return Err(LearningContractError::IncompleteCoverage);
            }
        }
        ensure_unique(self.omissions.iter().map(SlotId::as_str), "view.omissions")?;
        ensure_unique(self.frontier.iter().map(SlotId::as_str), "view.frontier")?;
        for disagreement in &self.owner_disagreements {
            disagreement.validate()?;
        }
        if self.required_references.is_empty() {
            return Err(LearningContractError::Missing {
                field: "view.required_references",
            });
        }
        if let Some(reason) = &self.invalidation_reason
            && reason.trim().is_empty()
        {
            return Err(LearningContractError::Missing {
                field: "view.invalidation_reason",
            });
        }
        if matches!(self.completeness, Completeness::CompleteForDeclaredRecipe) && self.invalidated
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let declared_slots =
            u32::try_from(recipe.slots.len()).map_err(|_| LearningContractError::Bound {
                field: "recipe.slots",
            })?;
        let observed_slots =
            u32::try_from(self.slots.len()).map_err(|_| LearningContractError::Bound {
                field: "view.slots",
            })?;
        if self.denominator.declared != declared_slots
            || self.denominator.observed != observed_slots
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let declared_ids: std::collections::BTreeSet<_> = recipe
            .slots
            .iter()
            .map(|slot| slot.slot_id.as_str())
            .collect();
        let represented: std::collections::BTreeSet<_> = self
            .slots
            .iter()
            .map(|slot| slot.slot_id.as_str())
            .collect();
        let omissions: std::collections::BTreeSet<_> =
            self.omissions.iter().map(SlotId::as_str).collect();
        let frontier: std::collections::BTreeSet<_> =
            self.frontier.iter().map(SlotId::as_str).collect();
        let mut partition = represented.clone();
        partition.extend(omissions.iter().copied());
        partition.extend(frontier.iter().copied());
        if represented.is_disjoint(&omissions)
            && represented.is_disjoint(&frontier)
            && omissions.is_disjoint(&frontier)
            && partition == declared_ids
        {
            // The partition is exact and contains no undeclared slot identity.
        } else {
            return Err(LearningContractError::IncompleteCoverage);
        }
        if matches!(self.completeness, Completeness::CompleteForDeclaredRecipe) {
            for spec in &recipe.slots {
                let required = match &spec.requirement {
                    SlotRequirement::Required => true,
                    SlotRequirement::Optional => false,
                    SlotRequirement::Conditional { depends_on } => {
                        self.slots.iter().any(|slot| slot.slot_id == *depends_on)
                    }
                };
                if required && !self.slots.iter().any(|slot| slot.slot_id == spec.slot_id) {
                    return Err(LearningContractError::IncompleteCoverage);
                }
                if required {
                    let Some(projection) =
                        self.slots.iter().find(|slot| slot.slot_id == spec.slot_id)
                    else {
                        return Err(LearningContractError::IncompleteCoverage);
                    };
                    let members_current = projection
                        .members
                        .iter()
                        .all(|member| member.disposition == SlotDisposition::Current);
                    let empty_owner_declaration = spec.declared_members.is_empty()
                        && projection.disposition == SlotDisposition::KnownEmpty;
                    if !members_current && !empty_owner_declaration {
                        return Err(LearningContractError::IncompleteCoverage);
                    }
                }
            }
            for omission in &self.omissions {
                let Some(spec) = recipe.slots.iter().find(|spec| spec.slot_id == *omission) else {
                    return Err(LearningContractError::IncompleteCoverage);
                };
                if !matches!(spec.requirement, SlotRequirement::Optional) {
                    return Err(LearningContractError::IncompleteCoverage);
                }
            }
        }
        validate_digest(&self.canonical_digest, "view.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "view.canonical_digest",
            });
        }
        Ok(())
    }

    /// Populate the canonical view digest after constructing the view.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

fn ensure_unique<'a, I>(values: I, field: &'static str) -> Result<(), LearningContractError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(LearningContractError::Duplicate { field });
        }
    }
    Ok(())
}
