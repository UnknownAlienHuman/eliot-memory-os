//! Immutable recipe-bound learning state projections.

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, DecisionId, PolicyRevision, ResourceGeneration,
    StateFence, TaskId, TaskRevision,
};
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

/// Canonical owner identity for the authenticated Task Controller task anchor.
pub const TASK_CONTROLLER_CAMPAIGN_OWNER_ID: &str = "owner:eliot-governor/task-controller";

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
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
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
    /// Closed source role whose resolved owner record supplies this slot.
    pub source_role: CampaignSourceRole,
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

/// Closed owner records which may contribute to a campaign learning view.
/// A recipe names each record independently; labels in a task manifest never
/// stand in for a resolved record at the declared revision.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignSourceRole {
    /// Task Controller objective record.
    TaskObjective,
    /// Task Controller acceptance record.
    TaskAcceptance,
    /// Task Controller plan record.
    TaskPlan,
    /// Task Controller open-item record.
    TaskOpenItems,
    /// Attempt lineage and latest outcome record.
    AttemptLineageLatestOutcomes,
    /// Governor admission record.
    GovernorAdmission,
    /// Governor authority epoch record.
    GovernorEpoch,
    /// Governor policy record.
    GovernorPolicy,
    /// Context recipe record.
    ContextRecipe,
    /// Context tool policy record.
    ContextToolPolicy,
    /// Context delivery record.
    ContextDelivery,
    /// Evaluator contract record.
    EvaluatorContract,
    /// Evaluator holdout record.
    EvaluatorHoldout,
    /// Evaluation results record.
    EvaluationResults,
    /// Canonical memory projection record.
    MemoryProjection,
    /// Canonical experience projection record.
    ExperienceProjection,
    /// Canonical artifact projection record.
    ArtifactProjection,
    /// Frozen task-family anchor record.
    FrozenAnchor,
    /// Stable harness record.
    StableHarness,
    /// Task-family harness record.
    TaskFamilyHarness,
    /// Active learning overlay record.
    ActiveOverlay,
    /// Current progress position record.
    CurrentPosition,
    /// Experience progress position record.
    ExperiencePosition,
    /// Adaptation progress position record.
    AdaptationPosition,
    /// Evaluation progress position record.
    EvaluationPosition,
    /// Economics progress position record.
    EconomicsProgress,
}

impl CampaignSourceRole {
    /// Return every closed source role a recipe must enumerate exactly once.
    #[must_use]
    pub const fn all() -> [Self; 26] {
        [
            Self::TaskObjective,
            Self::TaskAcceptance,
            Self::TaskPlan,
            Self::TaskOpenItems,
            Self::AttemptLineageLatestOutcomes,
            Self::GovernorAdmission,
            Self::GovernorEpoch,
            Self::GovernorPolicy,
            Self::ContextRecipe,
            Self::ContextToolPolicy,
            Self::ContextDelivery,
            Self::EvaluatorContract,
            Self::EvaluatorHoldout,
            Self::EvaluationResults,
            Self::MemoryProjection,
            Self::ExperienceProjection,
            Self::ArtifactProjection,
            Self::FrozenAnchor,
            Self::StableHarness,
            Self::TaskFamilyHarness,
            Self::ActiveOverlay,
            Self::CurrentPosition,
            Self::ExperiencePosition,
            Self::AdaptationPosition,
            Self::EvaluationPosition,
            Self::EconomicsProgress,
        ]
    }
}

/// Lossless closed representation of owner-native revision types. Counter
/// revisions retain their numeric value; epoch/policy/task revisions retain
/// the foundation type; resource revisions retain their exact string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignOwnerRevision {
    /// Revision owned by Task Controller.
    Task(TaskRevision),
    /// Exact numeric revision counter supplied by an owner record.
    Counter(u64),
    /// Exact authority epoch assigned by Governor.
    AuthorityEpoch(AuthorityEpoch),
    /// Exact policy revision assigned by a policy owner.
    Policy(PolicyRevision),
    /// Exact resource-generation identity.
    ResourceGeneration(ResourceGeneration),
    /// Exact textual revision supplied by a resource snapshot owner.
    ResourceSnapshot(String),
}

/// Lossless owner-native identity for a referenced record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignOwnerRecordId {
    /// Artifact owner record.
    Artifact(ArtifactId),
    /// Contract owner record.
    Contract(ContractId),
    /// Evaluator decision record.
    Decision(DecisionId),
    /// Task Controller record.
    Task(TaskId),
    /// Resource record with its exact native resource identity.
    Resource(String),
}

/// Exact reference declared by the canonical task's owner-reference
/// manifest. This is a lookup requirement, not proof that the referenced
/// record exists or is current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignSourceRequirement {
    /// Role the task manifest requires the owner to resolve.
    pub role: CampaignSourceRole,
    /// Typed origin of the expected source record or explicit absence.
    pub source_binding: CampaignSourceBinding,
    /// Exact canonical owner responsible for the role.
    pub owner: OwnerId,
    /// Exact immutable record expected from this owner, or `None` when the
    /// canonical manifest explicitly records that no target is available.
    pub expected_reference: Option<CampaignSourceRevisionRef>,
    /// False is the only way an omitted source may leave the view PARTIAL.
    pub load_bearing: bool,
}

/// Closed declaration of how a source requirement is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignSourceBinding {
    /// The task manifest contains the exact immutable owner reference.
    ExactReference,
    /// The task manifest explicitly declares that no record is expected.
    ExplicitlyAbsent,
    /// The `TaskPlan` is the authenticated current Task Controller row itself.
    AuthenticatedTaskAnchor,
}

impl CampaignSourceRevisionRef {
    /// Validate the exact owner identity, revision, digest and original fence.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.owner.validate()?;
        let record_id = match &self.record_id {
            CampaignOwnerRecordId::Artifact(id) => id.as_str(),
            CampaignOwnerRecordId::Contract(id) => id.as_str(),
            CampaignOwnerRecordId::Decision(id) => id.as_str(),
            CampaignOwnerRecordId::Task(id) => id.as_str(),
            CampaignOwnerRecordId::Resource(id) => id,
        };
        crate::identity::validate_external_id(record_id, "source.record_id")?;
        match &self.revision {
            CampaignOwnerRevision::Task(_)
            | CampaignOwnerRevision::Counter(_)
            | CampaignOwnerRevision::AuthorityEpoch(_)
            | CampaignOwnerRevision::Policy(_)
            | CampaignOwnerRevision::ResourceGeneration(_) => {}
            CampaignOwnerRevision::ResourceSnapshot(value) => {
                crate::identity::validate_external_id(value, "source.resource_revision")?;
            }
        }
        validate_digest(&self.content_digest, "source.content_digest")?;
        if self.slot_projection_digests.len() > 256 {
            return Err(LearningContractError::Bound {
                field: "source.slot_projection_digests",
            });
        }
        ensure_unique(
            self.slot_projection_digests
                .iter()
                .map(|projection| projection.slot_id.as_str()),
            "source.slot_projection_digests",
        )?;
        for projection in &self.slot_projection_digests {
            projection.slot_id.validate()?;
            validate_digest(&projection.digest, "source.slot_projection_digest")?;
        }
        self.recorded_state_fence
            .validate()
            .map_err(|_| LearningContractError::Foundation)
    }
}

impl CampaignSourceRequirement {
    /// Validate an exact task-manifest source expectation.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.owner.validate()?;
        match (&self.source_binding, &self.expected_reference) {
            (CampaignSourceBinding::ExactReference, Some(reference)) => {
                reference.validate()?;
                if reference.role != self.role || reference.owner != self.owner {
                    return Err(LearningContractError::ScopeMismatch {
                        field: "source_requirement.expected_reference",
                    });
                }
            }
            (CampaignSourceBinding::ExplicitlyAbsent, None) => {}
            (CampaignSourceBinding::AuthenticatedTaskAnchor, None)
                if self.role == CampaignSourceRole::TaskPlan
                    && self.owner.as_str() == TASK_CONTROLLER_CAMPAIGN_OWNER_ID
                    && self.load_bearing => {}
            _ => {
                return Err(LearningContractError::ScopeMismatch {
                    field: "source_requirement.binding",
                });
            }
        }
        Ok(())
    }
}

/// Result of resolving one manifest reference against its named canonical
/// owner. A CURRENT result carries the exact resolved record and its original
/// persisted fence; that fence remains distinct from the task fence at read
/// time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignSourceRevisionRef {
    /// Role this immutable owner record satisfies.
    pub role: CampaignSourceRole,
    /// Owner that issued the record.
    pub owner: OwnerId,
    /// Exact owner-native record identity.
    pub record_id: CampaignOwnerRecordId,
    /// Exact lossless owner-native revision.
    pub revision: CampaignOwnerRevision,
    /// Digest of the full immutable owner-record content.
    pub content_digest: String,
    /// Complete slot payload digests supplied by this owner record.
    pub slot_projection_digests: Vec<CampaignSlotProjectionDigest>,
    /// State fence originally recorded on this source record.
    pub recorded_state_fence: StateFence,
}

/// Digest binding one complete normalized slot payload to its exact source
/// owner record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignSlotProjectionDigest {
    /// Slot whose complete projection is covered by this digest.
    pub slot_id: SlotId,
    /// SHA-256 digest of the canonical complete slot projection.
    pub digest: String,
}

/// Explicit owner-resolution outcome for a declared source reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignSourceResolutionStatus {
    /// The named owner returned the exact revision declared by the manifest.
    Current,
    /// The named owner record changed or failed its expected revision check.
    Stale,
    /// The owner could not resolve the record under the current fence.
    Blocked,
    /// The manifest or owner explicitly reports no record.
    Missing,
}

/// Resolved or explicitly unavailable task-manifest owner reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignSourceResolution {
    /// Role being resolved.
    pub role: CampaignSourceRole,
    /// Explicit outcome from the named owner read.
    pub status: CampaignSourceResolutionStatus,
    /// Exact record returned by the owner, when one was found.
    pub reference: Option<CampaignSourceRevisionRef>,
    /// Fence used for the current named read, distinct from the persisted
    /// source record's `recorded_state_fence`.
    pub read_state_fence: StateFence,
}

/// Whether a recipe requires an active overlay or explicitly declares the
/// campaign to have none.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignActiveOverlayPolicy {
    /// Require an active overlay source resolution.
    Required,
    /// Declare explicitly that no active overlay applies.
    ExplicitlyAbsentAllowed,
}

/// Progress dimension whose exact owner revision is retained in the view.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignPositionKind {
    /// Current task position.
    Current,
    /// Experience position.
    Experience,
    /// Adaptation position.
    Adaptation,
    /// Evaluation position.
    Evaluation,
    /// Economics progress position.
    EconomicsProgress,
}

/// Content-bound progress position linked to one resolved source revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignPositionRef {
    /// Progress dimension.
    pub kind: CampaignPositionKind,
    /// Source role that owns the position.
    pub source_role: CampaignSourceRole,
    /// Owner-native position record identity.
    pub record_id: CampaignOwnerRecordId,
    /// Owner-native record revision.
    pub revision: CampaignOwnerRevision,
    /// Digest of the complete source record.
    pub source_content_digest: String,
    /// Digest of the exact position owner projection; equals source content digest.
    pub position_digest: String,
}

/// Bounded history selected through an existing campaign-scoped
/// `RetrievalPlan`. The plan is content-addressed; only handles and digests of
/// permitted summaries/diffs/slices are retained, never transcript content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignHistoryPlanReference {
    /// Canonical digest of the validated campaign-scoped `RetrievalPlan`.
    pub retrieval_plan_digest: String,
    /// Handles selected through that plan's bounded query.
    pub selected_handles: Vec<ArtifactId>,
    /// Digest of an optional retained bounded summary.
    pub summary_digest: Option<String>,
    /// Digests of retained bounded diffs.
    pub diff_digests: Vec<String>,
    /// Handles of policy-permitted history slices.
    pub policy_slice_handles: Vec<ArtifactId>,
}

/// Typed reason a generated view must be rebuilt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignViewRebuildReason {
    /// One exact source record's owner revision changed.
    OwnerRevisionChanged,
    /// Current task read fence changed.
    StateFenceChanged,
    /// The previous view's expiry boundary passed.
    Expired,
    /// A governing policy revision changed.
    PolicyChanged,
    /// The caller explicitly requested a fresh derivation.
    ExplicitRefresh,
}

/// Immutable provenance and lifecycle metadata required to interpret a
/// campaign view safely.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignLearningStateProvenance {
    /// One explicit resolution for every recipe source role.
    pub source_resolutions: Vec<CampaignSourceResolution>,
    /// Digest of the exact current frozen anchor record.
    pub frozen_anchor_digest: String,
    /// Available progress positions tied to exact source revisions.
    pub positions: Vec<CampaignPositionRef>,
    /// Content-addressed `RetrievalPlans` and bounded history result references.
    pub history_plans: Vec<CampaignHistoryPlanReference>,
    /// Runtime supplied generation time.
    pub generated_at_ms: i64,
    /// Runtime supplied expiration boundary, if any.
    pub expires_at_ms: Option<i64>,
    /// Typed cause for this rebuild.
    pub rebuild_reason: Option<CampaignViewRebuildReason>,
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

    /// Compute a stable digest over the complete normalized slot payload.
    /// Members and all evidence-handle vectors are ordered by their stable IDs.
    pub fn canonical_digest(&self) -> Result<String, LearningContractError> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical
            .members
            .sort_by(|left, right| left.member_id.as_str().cmp(right.member_id.as_str()));
        for member in &mut canonical.members {
            member
                .evidence
                .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        }
        canonical
            .evidence
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        digest_without_field(&canonical, "")
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
    /// Exact owner-reference manifest required to compile this view.
    pub source_requirements: Vec<CampaignSourceRequirement>,
    /// Explicit policy for whether this campaign has an active overlay.
    pub active_overlay_policy: CampaignActiveOverlayPolicy,
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
        self.validate_source_manifest()?;
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

    fn validate_source_manifest(&self) -> Result<(), LearningContractError> {
        if self.source_requirements.len() != CampaignSourceRole::all().len() {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let mut source_roles = std::collections::BTreeSet::new();
        for requirement in &self.source_requirements {
            requirement.validate()?;
            if !source_roles.insert(requirement.role) {
                return Err(LearningContractError::Duplicate {
                    field: "recipe.source_requirements",
                });
            }
        }
        if CampaignSourceRole::all()
            .iter()
            .any(|role| !source_roles.contains(role))
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        for slot in &self.slots {
            let requirement = self
                .source_requirements
                .iter()
                .find(|requirement| requirement.role == slot.source_role)
                .ok_or(LearningContractError::IncompleteCoverage)?;
            if requirement.owner != slot.owner {
                return Err(LearningContractError::ScopeMismatch {
                    field: "recipe.slot_source_owner",
                });
            }
        }
        let active_overlay = self
            .source_requirements
            .iter()
            .find(|requirement| requirement.role == CampaignSourceRole::ActiveOverlay)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        let task_plan = self
            .source_requirements
            .iter()
            .find(|requirement| requirement.role == CampaignSourceRole::TaskPlan)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        if task_plan.source_binding != CampaignSourceBinding::AuthenticatedTaskAnchor
            || task_plan.expected_reference.is_some()
            || !task_plan.load_bearing
            || task_plan.owner.as_str() != TASK_CONTROLLER_CAMPAIGN_OWNER_ID
            || self.binding.state_fence.task_revision.is_none()
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "recipe.task_plan_anchor",
            });
        }
        if self.active_overlay_policy == CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed
            && (active_overlay.load_bearing
                || active_overlay.expected_reference.is_some()
                || active_overlay.source_binding != CampaignSourceBinding::ExplicitlyAbsent)
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "recipe.active_overlay_policy",
            });
        }
        if self.active_overlay_policy == CampaignActiveOverlayPolicy::Required
            && (!active_overlay.load_bearing
                || active_overlay.source_binding == CampaignSourceBinding::ExplicitlyAbsent)
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "recipe.active_overlay_policy",
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
    /// Exact source revisions, frozen-anchor, positions, history-plan refs,
    /// and lifecycle data captured by this immutable derivation.
    pub provenance: CampaignLearningStateProvenance,
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
    pub fn validate_against(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), LearningContractError> {
        self.validate_recipe_contract(recipe)?;
        self.validate_provenance(recipe)?;
        self.validate_slot_projections(recipe)?;
        self.validate_view_status()?;
        self.validate_slot_partition(recipe)?;
        self.validate_required_coverage(recipe)?;
        if self.completeness != self.derived_completeness(recipe) {
            return Err(LearningContractError::IncompleteCoverage);
        }
        self.validate_content_addressed()?;
        Ok(())
    }

    fn validate_recipe_contract(
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
        Ok(())
    }

    fn validate_provenance(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), LearningContractError> {
        validate_provenance_time(&self.provenance)?;
        validate_source_resolutions(self, recipe)?;
        validate_frozen_anchor(self, recipe)?;
        validate_positions(self)?;
        validate_history_plan_references(self)
    }

    /// Recompute completeness from declared source roles and slot dispositions.
    #[must_use]
    pub fn derived_completeness(&self, recipe: &LearningStateViewRecipe) -> Completeness {
        combine_completeness(
            derive_source_completeness(self, recipe),
            derive_slot_completeness(self, recipe),
        )
    }

    /// Validate both canonical content digest and the derived immutable ID.
    pub fn validate_content_addressed(&self) -> Result<(), LearningContractError> {
        validate_digest(&self.canonical_digest, "view.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "view.canonical_digest",
            });
        }
        let expected = self.content_addressed_view_id()?;
        if self.view_id != expected {
            return Err(LearningContractError::DigestMismatch {
                field: "view.view_id",
            });
        }
        Ok(())
    }

    fn content_addressed_view_id(&self) -> Result<ArtifactId, LearningContractError> {
        let mut preimage = self.clone();
        preimage.view_id = ArtifactId::new("pending-campaign-learning-state-view")
            .map_err(|_| LearningContractError::Foundation)?;
        preimage.canonical_digest.clear();
        let digest = digest_without_field(&preimage, "view_id")?;
        ArtifactId::new(format!("campaign-learning-state-view:sha256:{digest}"))
            .map_err(|_| LearningContractError::Foundation)
    }

    fn validate_slot_projections(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), LearningContractError> {
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
            let resolution = self
                .provenance
                .source_resolutions
                .iter()
                .find(|resolution| resolution.role == spec.source_role)
                .ok_or(LearningContractError::IncompleteCoverage)?;
            let reference = resolution
                .reference
                .as_ref()
                .ok_or(LearningContractError::IncompleteCoverage)?;
            if reference.role != spec.source_role || reference.owner != spec.owner {
                return Err(LearningContractError::ScopeMismatch {
                    field: "view.slot_source_owner",
                });
            }
            let expected_digest = reference
                .slot_projection_digests
                .iter()
                .find(|entry| entry.slot_id == spec.slot_id)
                .ok_or(LearningContractError::IncompleteCoverage)?;
            if projection.canonical_digest()? != expected_digest.digest {
                return Err(LearningContractError::DigestMismatch {
                    field: "view.slot_projection_digest",
                });
            }
            let current_members = projection
                .members
                .iter()
                .all(|member| member.disposition == SlotDisposition::Current);
            if projection
                .members
                .iter()
                .any(|member| member.owner != spec.owner)
            {
                return Err(LearningContractError::ScopeMismatch {
                    field: "view.member_owner",
                });
            }
            if matches!(projection.disposition, SlotDisposition::Current)
                && (!declared.is_empty() && !current_members)
            {
                return Err(LearningContractError::IncompleteCoverage);
            }
        }
        validate_declared_slot_digests(self, recipe)?;
        Ok(())
    }

    fn validate_view_status(&self) -> Result<(), LearningContractError> {
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
        Ok(())
    }

    fn validate_slot_partition(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), LearningContractError> {
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
        Ok(())
    }

    fn validate_required_coverage(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), LearningContractError> {
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
                    let current_projection = projection.disposition == SlotDisposition::Current
                        && (spec.declared_members.is_empty() || members_current);
                    let empty_owner_declaration = spec.declared_members.is_empty()
                        && projection.disposition == SlotDisposition::KnownEmpty
                        && !projection.evidence.is_empty();
                    if !current_projection && !empty_owner_declaration {
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
        Ok(())
    }

    /// Populate the canonical view digest after constructing the view.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }

    /// Derive the immutable view identity from the complete content, then seal it.
    pub fn seal_content_addressed(&mut self) -> Result<(), LearningContractError> {
        self.view_id = ArtifactId::new("pending-campaign-learning-state-view")
            .map_err(|_| LearningContractError::Foundation)?;
        self.canonical_digest.clear();
        self.view_id = self.content_addressed_view_id()?;
        self.seal()
    }
}

const POSITION_ROLES: [(CampaignPositionKind, CampaignSourceRole); 5] = [
    (
        CampaignPositionKind::Current,
        CampaignSourceRole::CurrentPosition,
    ),
    (
        CampaignPositionKind::Experience,
        CampaignSourceRole::ExperiencePosition,
    ),
    (
        CampaignPositionKind::Adaptation,
        CampaignSourceRole::AdaptationPosition,
    ),
    (
        CampaignPositionKind::Evaluation,
        CampaignSourceRole::EvaluationPosition,
    ),
    (
        CampaignPositionKind::EconomicsProgress,
        CampaignSourceRole::EconomicsProgress,
    ),
];

fn validate_provenance_time(
    provenance: &CampaignLearningStateProvenance,
) -> Result<(), LearningContractError> {
    if provenance.generated_at_ms < 0
        || provenance
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= provenance.generated_at_ms)
    {
        return Err(LearningContractError::ScopeMismatch {
            field: "view.provenance.time",
        });
    }
    Ok(())
}

fn validate_source_resolutions(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Result<(), LearningContractError> {
    let resolutions = &view.provenance.source_resolutions;
    if resolutions.len() != recipe.source_requirements.len() {
        return Err(LearningContractError::IncompleteCoverage);
    }
    let requirements: std::collections::BTreeMap<_, _> = recipe
        .source_requirements
        .iter()
        .map(|requirement| (requirement.role, requirement))
        .collect();
    let mut previous_role = None;
    for resolution in resolutions {
        if previous_role.is_some_and(|role| role >= resolution.role) {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.source_order",
            });
        }
        previous_role = Some(resolution.role);
        let requirement = requirements
            .get(&resolution.role)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        resolution
            .read_state_fence
            .validate()
            .map_err(|_| LearningContractError::Foundation)?;
        if resolution.read_state_fence != recipe.binding.state_fence {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.read_state_fence",
            });
        }
        validate_resolution_reference(resolution, requirement, &recipe.binding)?;
    }
    Ok(())
}

fn validate_resolution_reference(
    resolution: &CampaignSourceResolution,
    requirement: &CampaignSourceRequirement,
    binding: &ContractBinding,
) -> Result<(), LearningContractError> {
    match (resolution.status, &resolution.reference) {
        (CampaignSourceResolutionStatus::Current, Some(reference)) => {
            reference.validate()?;
            if reference.role != resolution.role
                || reference.owner != requirement.owner
                || !matches_current_source_reference(requirement, reference, binding)
            {
                return Err(LearningContractError::ScopeMismatch {
                    field: "view.provenance.current_source_reference",
                });
            }
        }
        (CampaignSourceResolutionStatus::Stale, reference) => {
            if let Some(reference) = reference {
                reference.validate()?;
                if reference.role != resolution.role || reference.owner != requirement.owner {
                    return Err(LearningContractError::ScopeMismatch {
                        field: "view.provenance.stale_source_reference",
                    });
                }
            }
        }
        (
            CampaignSourceResolutionStatus::Blocked | CampaignSourceResolutionStatus::Missing,
            None,
        ) => {}
        _ => {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.source_status",
            });
        }
    }
    Ok(())
}

fn matches_current_source_reference(
    requirement: &CampaignSourceRequirement,
    reference: &CampaignSourceRevisionRef,
    binding: &ContractBinding,
) -> bool {
    match requirement.source_binding {
        CampaignSourceBinding::ExactReference => {
            requirement.expected_reference.as_ref() == Some(reference)
        }
        CampaignSourceBinding::ExplicitlyAbsent => false,
        CampaignSourceBinding::AuthenticatedTaskAnchor => {
            let Some(task_revision) = &binding.state_fence.task_revision else {
                return false;
            };
            matches!(
                &reference.record_id,
                CampaignOwnerRecordId::Task(task_id) if task_id == &binding.task_id
            ) && matches!(
                &reference.revision,
                CampaignOwnerRevision::Task(revision) if revision == task_revision
            ) && reference.recorded_state_fence.task_revision.as_ref() == Some(task_revision)
        }
    }
}

fn validate_declared_slot_digests(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Result<(), LearningContractError> {
    for resolution in &view.provenance.source_resolutions {
        let Some(reference) = &resolution.reference else {
            continue;
        };
        for projection in &reference.slot_projection_digests {
            let slot = recipe
                .slots
                .iter()
                .find(|slot| slot.slot_id == projection.slot_id)
                .ok_or(LearningContractError::ScopeMismatch {
                    field: "view.source_slot_projection_digest.slot_id",
                })?;
            if slot.source_role != resolution.role || slot.owner != reference.owner {
                return Err(LearningContractError::ScopeMismatch {
                    field: "view.source_slot_projection_digest.owner",
                });
            }
        }
    }
    Ok(())
}

fn validate_frozen_anchor(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Result<(), LearningContractError> {
    validate_digest(
        &view.provenance.frozen_anchor_digest,
        "view.provenance.frozen_anchor_digest",
    )?;
    let requirement = recipe
        .source_requirements
        .iter()
        .find(|requirement| requirement.role == CampaignSourceRole::FrozenAnchor)
        .ok_or(LearningContractError::IncompleteCoverage)?;
    let resolution = view
        .provenance
        .source_resolutions
        .iter()
        .find(|resolution| resolution.role == CampaignSourceRole::FrozenAnchor)
        .ok_or(LearningContractError::IncompleteCoverage)?;
    let expected_digest = resolution
        .reference
        .as_ref()
        .map(|reference| &reference.content_digest)
        .or_else(|| {
            requirement
                .expected_reference
                .as_ref()
                .map(|reference| &reference.content_digest)
        })
        .ok_or(LearningContractError::Missing {
            field: "view.provenance.frozen_anchor_digest",
        })?;
    if &view.provenance.frozen_anchor_digest != expected_digest {
        return Err(LearningContractError::DigestMismatch {
            field: "view.provenance.frozen_anchor_digest",
        });
    }
    Ok(())
}

fn validate_positions(view: &CampaignLearningStateView) -> Result<(), LearningContractError> {
    let mut previous_kind = None;
    let mut seen_kinds = std::collections::BTreeSet::new();
    for position in &view.provenance.positions {
        if previous_kind.is_some_and(|kind| kind >= position.kind) {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.position_order",
            });
        }
        previous_kind = Some(position.kind);
        validate_digest(&position.source_content_digest, "position.source_digest")?;
        validate_digest(&position.position_digest, "position.digest")?;
        if !seen_kinds.insert(position.kind) {
            return Err(LearningContractError::Duplicate {
                field: "view.provenance.positions",
            });
        }
        let role = position_role(position.kind);
        if position.source_role != role {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.position_role",
            });
        }
        let resolution = view
            .provenance
            .source_resolutions
            .iter()
            .find(|resolution| resolution.role == role)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        let Some(reference) = &resolution.reference else {
            return Err(LearningContractError::IncompleteCoverage);
        };
        if resolution.status != CampaignSourceResolutionStatus::Current
            || position.record_id != reference.record_id
            || position.revision != reference.revision
            || position.source_content_digest != reference.content_digest
            || position.position_digest != reference.content_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.position_source",
            });
        }
    }
    for (kind, role) in POSITION_ROLES {
        let current = view.provenance.source_resolutions.iter().any(|resolution| {
            resolution.role == role && resolution.status == CampaignSourceResolutionStatus::Current
        });
        if current != seen_kinds.contains(&kind) {
            return Err(LearningContractError::IncompleteCoverage);
        }
    }
    Ok(())
}

fn validate_history_plan_references(
    view: &CampaignLearningStateView,
) -> Result<(), LearningContractError> {
    if view.provenance.history_plans.len() > 64 {
        return Err(LearningContractError::Bound {
            field: "view.provenance.history_plans",
        });
    }
    let mut previous_digest = None;
    for history in &view.provenance.history_plans {
        validate_digest(
            &history.retrieval_plan_digest,
            "history_plan.retrieval_plan_digest",
        )?;
        if previous_digest.is_some_and(|digest| digest >= history.retrieval_plan_digest.as_str()) {
            return Err(LearningContractError::ScopeMismatch {
                field: "view.provenance.history_plan_order",
            });
        }
        previous_digest = Some(history.retrieval_plan_digest.as_str());
        if history.selected_handles.len() > 256
            || history.policy_slice_handles.len() > 256
            || history.diff_digests.len() > 256
        {
            return Err(LearningContractError::Bound {
                field: "view.provenance.history_plan_references",
            });
        }
        ensure_unique(
            history.selected_handles.iter().map(ArtifactId::as_str),
            "history_plan.selected_handles",
        )?;
        ensure_unique(
            history.policy_slice_handles.iter().map(ArtifactId::as_str),
            "history_plan.policy_slice_handles",
        )?;
        ensure_unique(
            history.diff_digests.iter().map(String::as_str),
            "history_plan.diff_digests",
        )?;
        let selected: std::collections::BTreeSet<_> = history
            .selected_handles
            .iter()
            .map(ArtifactId::as_str)
            .collect();
        if history
            .policy_slice_handles
            .iter()
            .any(|handle| !selected.contains(handle.as_str()))
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        if let Some(summary_digest) = &history.summary_digest {
            validate_digest(summary_digest, "history_plan.summary_digest")?;
        }
        for digest in &history.diff_digests {
            validate_digest(digest, "history_plan.diff_digest")?;
        }
    }
    Ok(())
}

fn derive_source_completeness(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Completeness {
    let mut blocked = view.provenance.history_plans.is_empty();
    let mut stale = false;
    let mut partial = false;
    for requirement in &recipe.source_requirements {
        let Some(resolution) = view
            .provenance
            .source_resolutions
            .iter()
            .find(|resolution| resolution.role == requirement.role)
        else {
            if requirement.load_bearing {
                blocked = true;
            } else {
                partial = true;
            }
            continue;
        };
        if is_explicitly_absent_overlay(requirement, resolution, recipe) {
            continue;
        }
        match resolution.status {
            CampaignSourceResolutionStatus::Current => {}
            CampaignSourceResolutionStatus::Stale if requirement.load_bearing => stale = true,
            CampaignSourceResolutionStatus::Blocked | CampaignSourceResolutionStatus::Missing
                if requirement.load_bearing =>
            {
                blocked = true;
            }
            CampaignSourceResolutionStatus::Stale
            | CampaignSourceResolutionStatus::Blocked
            | CampaignSourceResolutionStatus::Missing => partial = true,
        }
    }
    completeness_from_flags(blocked, stale, partial)
}

fn derive_slot_completeness(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Completeness {
    let mut blocked = false;
    let mut stale = false;
    let mut partial = false;
    let required_ids: std::collections::BTreeSet<_> = recipe
        .slots
        .iter()
        .filter(|spec| !matches!(spec.requirement, SlotRequirement::Optional))
        .map(|spec| spec.slot_id.as_str())
        .chain(
            recipe
                .slots
                .iter()
                .filter_map(|spec| match &spec.requirement {
                    SlotRequirement::Conditional { depends_on } => Some(depends_on.as_str()),
                    SlotRequirement::Required | SlotRequirement::Optional => None,
                }),
        )
        .collect();
    for spec in &recipe.slots {
        let Some(slot) = view.slots.iter().find(|slot| slot.slot_id == spec.slot_id) else {
            if view.frontier.contains(&spec.slot_id) {
                if matches!(spec.requirement, SlotRequirement::Optional) {
                    partial = true;
                } else {
                    blocked = true;
                }
            } else if required_ids.contains(spec.slot_id.as_str())
                && !view.omissions.contains(&spec.slot_id)
            {
                blocked = true;
            }
            continue;
        };
        if !required_ids.contains(spec.slot_id.as_str()) {
            classify_optional_disposition(slot.disposition, &mut stale, &mut partial);
            for member in &slot.members {
                classify_optional_disposition(member.disposition, &mut stale, &mut partial);
            }
            continue;
        }
        classify_required_disposition_contract(
            slot.disposition,
            !slot.evidence.is_empty() && spec.declared_members.is_empty(),
            &mut blocked,
            &mut stale,
        );
        for member in &slot.members {
            classify_required_disposition_contract(
                member.disposition,
                false,
                &mut blocked,
                &mut stale,
            );
        }
    }
    completeness_from_flags(blocked, stale, partial)
}

fn classify_optional_disposition(
    disposition: SlotDisposition,
    stale: &mut bool,
    partial: &mut bool,
) {
    match disposition {
        SlotDisposition::Current => {}
        SlotDisposition::Stale => *stale = true,
        SlotDisposition::Blocked
        | SlotDisposition::Unavailable
        | SlotDisposition::Historical
        | SlotDisposition::Superseded
        | SlotDisposition::Unknown
        | SlotDisposition::Conflicted
        | SlotDisposition::KnownEmpty => *partial = true,
    }
}

fn classify_required_disposition_contract(
    disposition: SlotDisposition,
    evidenced_empty: bool,
    blocked: &mut bool,
    stale: &mut bool,
) {
    match disposition {
        SlotDisposition::Current => {}
        SlotDisposition::Stale => *stale = true,
        SlotDisposition::KnownEmpty if evidenced_empty => {}
        SlotDisposition::Blocked
        | SlotDisposition::Unavailable
        | SlotDisposition::Historical
        | SlotDisposition::Superseded
        | SlotDisposition::Unknown
        | SlotDisposition::Conflicted
        | SlotDisposition::KnownEmpty => *blocked = true,
    }
}

fn completeness_from_flags(blocked: bool, stale: bool, partial: bool) -> Completeness {
    if blocked {
        Completeness::Blocked
    } else if stale {
        Completeness::Stale
    } else if partial {
        Completeness::Partial
    } else {
        Completeness::CompleteForDeclaredRecipe
    }
}

fn combine_completeness(left: Completeness, right: Completeness) -> Completeness {
    match (left, right) {
        (Completeness::Blocked, _) | (_, Completeness::Blocked) => Completeness::Blocked,
        (Completeness::Stale, _) | (_, Completeness::Stale) => Completeness::Stale,
        (Completeness::Partial, _) | (_, Completeness::Partial) => Completeness::Partial,
        _ => Completeness::CompleteForDeclaredRecipe,
    }
}

fn is_explicitly_absent_overlay(
    requirement: &CampaignSourceRequirement,
    resolution: &CampaignSourceResolution,
    recipe: &LearningStateViewRecipe,
) -> bool {
    requirement.role == CampaignSourceRole::ActiveOverlay
        && recipe.active_overlay_policy == CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed
        && resolution.status == CampaignSourceResolutionStatus::Missing
        && resolution.reference.is_none()
}

fn position_role(kind: CampaignPositionKind) -> CampaignSourceRole {
    POSITION_ROLES
        .iter()
        .find(|(position_kind, _)| *position_kind == kind)
        .map_or(CampaignSourceRole::CurrentPosition, |(_, role)| *role)
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
