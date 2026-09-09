//! Episode-specific input records. Common curation identity and admission
//! remain owned by `eliot-dreamer-contracts`; this module only joins the
//! immutable event/source evidence needed by one episode candidate.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, TaskRevision};
use eliot_dreamer_contracts::RelationTemporalEvidence;
use eliot_dreamer_contracts::{
    ContractViolation, CurationAcceptanceCtx, ValidatedCurationItem, canonical_bytes, digest_hex,
};
use eliot_epistemic_contracts::{CoverageDenominator, CoverageReceipt};
use eliot_memory_curation_contracts::{
    ContractError as SourceError, Digest, FiniteDenominator, MemberId, ScreenCoverage,
    SourceSnapshot,
};
use eliot_observation_contracts::ObservationEventCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_EVENTS: usize = 1_024;
pub(crate) const MAX_PARTICIPANTS: usize = 4_096;
pub(crate) const MAX_OUTCOMES: usize = 2_048;
pub(crate) const MAX_LINKS: usize = 8_192;
pub(crate) const MAX_TEXT: usize = 1_024;

/// Canonical material identity computed from the actual semantic preimage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialPreimage {
    pub digest: String,
    pub bytes: u64,
}

fn material_preimage<T: Serialize>(value: &T) -> Result<MaterialPreimage, ContractViolation> {
    let bytes = canonical_bytes(value)?;
    let length = u64::try_from(bytes.len()).map_err(|_| ContractViolation::Budget {
        dimension: "episode.material_bytes",
        reason: "material length cannot be represented".to_owned(),
    })?;
    Ok(MaterialPreimage {
        digest: digest_hex(&bytes),
        bytes: length,
    })
}

fn source_error(field: &'static str, error: &SourceError) -> ContractViolation {
    ContractViolation::BindingMismatch {
        field,
        reason: error.to_string(),
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    eliot_dreamer_contracts::error::check_text(value, field, MAX_TEXT)
}

fn cap(value: usize, maximum: usize, field: &'static str) -> Result<(), ContractViolation> {
    eliot_dreamer_contracts::check_vec_bound(value, maximum, field)
}

fn fence_eq(
    left: &StateFence,
    right: &StateFence,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if left == right {
        Ok(())
    } else {
        Err(ContractViolation::BindingMismatch {
            field,
            reason: "state fence differs".to_owned(),
        })
    }
}

/// Borrow-only A-03 admission wrapper. It deliberately has no wire form.
pub struct ValidatedCurationInput<'a> {
    /// Validator-owned curation item.
    pub item: &'a ValidatedCurationItem,
    /// Validator-owned admission context.
    pub ctx: &'a CurationAcceptanceCtx<'a>,
}

impl ValidatedCurationInput<'_> {
    /// Performs only capped, nonallocating checks before common admission.
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        cap(
            self.ctx.bundle.materials.len(),
            MAX_EVENTS * 4,
            "bundle.materials",
        )?;
        cap(
            self.ctx.bundle.omissions.len(),
            MAX_EVENTS * 2,
            "bundle.omissions",
        )?;
        cap(
            self.ctx.grounded.residues.len(),
            MAX_EVENTS * 2,
            "grounded.residues",
        )?;
        cap(
            self.ctx.screen.screened_targets.len(),
            MAX_EVENTS,
            "screen.screened_targets",
        )?;
        text(&self.ctx.job.operation_id, "operation_id")?;
        text(&self.ctx.job.idempotency_key, "idempotency_key")?;
        Ok(())
    }

    /// Crosses the common acceptance seam exactly once.
    pub fn accept(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        self.item.accept(self.ctx)
    }
}

/// A source/member binding for a load-bearing Episode field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    /// Field or association being grounded.
    pub subject: String,
    /// Exact immutable source member.
    pub member_id: MemberId,
    /// Revision of the immutable member.
    pub member_revision: TaskRevision,
    /// Content digest of the immutable member.
    pub member_content_digest: Digest,
    /// Exact accepted bundle material handle for the canonical preimage.
    pub material_handle: String,
    /// SHA-256 of the canonical material preimage bytes declared by A-03.
    pub material_digest: String,
    /// Byte length of that same canonical material preimage.
    pub material_bytes: u64,
    /// Owner-issued evidence handles, retained verbatim.
    pub evidence_handles: Vec<ArtifactId>,
}

impl EvidenceBinding {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.subject, "evidence.subject")?;
        text(&self.material_handle, "evidence.material_handle")?;
        text(&self.material_digest, "evidence.material_digest")?;
        if !eliot_dreamer_contracts::is_hex64_lower(&self.material_digest) {
            return Err(ContractViolation::Malformed {
                field: "evidence.material_digest",
                reason: "must be lowercase SHA-256".to_owned(),
            });
        }
        cap(self.evidence_handles.len(), MAX_LINKS, "evidence.handles")?;
        if self.evidence_handles.is_empty() {
            return Err(ContractViolation::MissingField("evidence.handles"));
        }
        Ok(())
    }
}

/// One participant retained with its exact source association.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeParticipant {
    pub participant_id: ArtifactId,
    pub role: String,
    pub binding: EvidenceBinding,
}

impl EpisodeParticipant {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        text(self.participant_id.as_str(), "participant.id")?;
        text(&self.role, "participant.role")?;
        self.binding.validate()
    }
}

/// One outcome retained with its exact source association.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeOutcome {
    pub outcome_id: ArtifactId,
    pub status: String,
    pub binding: EvidenceBinding,
}

impl EpisodeOutcome {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        text(self.outcome_id.as_str(), "outcome.id")?;
        text(&self.status, "outcome.status")?;
        self.binding.validate()
    }
}

/// One immutable event and all Episode-specific projections of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroundedEvent {
    pub core: ObservationEventCore,
    pub source_member_id: MemberId,
    pub source_revision: TaskRevision,
    pub source_content_digest: Digest,
    pub event_binding: EvidenceBinding,
    pub temporal: RelationTemporalEvidence,
    pub temporal_binding: Option<EvidenceBinding>,
    pub participants: Vec<EpisodeParticipant>,
    pub outcomes: Vec<EpisodeOutcome>,
}

impl GroundedEvent {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        self.core
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "event.core",
                reason: error.to_string(),
            })?;
        self.event_binding.validate()?;
        cap(
            self.participants.len(),
            MAX_PARTICIPANTS,
            "event.participants",
        )?;
        cap(self.outcomes.len(), MAX_OUTCOMES, "event.outcomes")?;
        for participant in &self.participants {
            participant.validate()?;
        }
        for outcome in &self.outcomes {
            outcome.validate()?;
        }
        validate_temporal(&self.temporal)?;
        if self.temporal.event_time.is_some()
            || self.temporal.effective_time.is_some()
            || self.temporal.observation_time.is_some()
            || self.temporal.ingestion_time.is_some()
            || self.temporal.commit_time.is_some()
        {
            self.temporal_binding
                .as_ref()
                .ok_or(ContractViolation::MissingField("event.temporal_binding"))?
                .validate()?;
        }
        Ok(())
    }
}

/// Computes the versioned event material preimage over all load-bearing event
/// fields, including all five temporal roles and participant/outcome records.
pub fn event_material_preimage(
    event: &GroundedEvent,
) -> Result<MaterialPreimage, ContractViolation> {
    #[derive(Serialize)]
    struct EventMaterial<'a> {
        version: u8,
        core: &'a ObservationEventCore,
        temporal: &'a RelationTemporalEvidence,
        participants: &'a [EpisodeParticipant],
        outcomes: &'a [EpisodeOutcome],
    }
    material_preimage(&EventMaterial {
        version: 1,
        core: &event.core,
        temporal: &event.temporal,
        participants: &event.participants,
        outcomes: &event.outcomes,
    })
}

/// Computes the versioned participant material preimage.
pub fn participant_material_preimage(
    participant: &EpisodeParticipant,
) -> Result<MaterialPreimage, ContractViolation> {
    #[derive(Serialize)]
    struct ParticipantMaterial<'a> {
        version: u8,
        participant_id: &'a ArtifactId,
        role: &'a str,
    }
    material_preimage(&ParticipantMaterial {
        version: 1,
        participant_id: &participant.participant_id,
        role: &participant.role,
    })
}

/// Computes the versioned outcome material preimage.
pub fn outcome_material_preimage(
    outcome: &EpisodeOutcome,
) -> Result<MaterialPreimage, ContractViolation> {
    #[derive(Serialize)]
    struct OutcomeMaterial<'a> {
        version: u8,
        outcome_id: &'a ArtifactId,
        status: &'a str,
    }
    material_preimage(&OutcomeMaterial {
        version: 1,
        outcome_id: &outcome.outcome_id,
        status: &outcome.status,
    })
}

/// Computes the versioned five-role temporal material preimage.
pub fn temporal_material_preimage(
    temporal: &RelationTemporalEvidence,
) -> Result<MaterialPreimage, ContractViolation> {
    #[derive(Serialize)]
    struct TemporalMaterial<'a> {
        version: u8,
        temporal: &'a RelationTemporalEvidence,
    }
    material_preimage(&TemporalMaterial {
        version: 1,
        temporal,
    })
}

/// Bounded event set with a distinct event enumeration denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroundedEventSet {
    pub denominator: FiniteDenominator,
    pub events: Vec<GroundedEvent>,
}

impl GroundedEventSet {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        cap(self.events.len(), MAX_EVENTS, "events")?;
        self.denominator
            .validate(self.events.len())
            .map_err(|error| source_error("event.denominator", &error))?;
        let mut ids = BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if !ids.insert(event.source_member_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "events.source_member_id",
                    reason: "duplicate event source member".to_owned(),
                });
            }
            if !self
                .denominator
                .declared_member_ids
                .contains(&event.source_member_id)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "events.denominator",
                    reason: "event member is outside event denominator".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Source snapshot plus both owner coverage records used by the joins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventAndSourceSnapshot {
    pub source: SourceSnapshot,
    pub coverage: ScreenCoverage,
    pub event_denominator: CoverageDenominator,
    pub enumeration: CoverageReceipt,
}

impl EventAndSourceSnapshot {
    pub(crate) fn validate(
        &self,
        ctx: &CurationAcceptanceCtx<'_>,
    ) -> Result<(), ContractViolation> {
        self.source
            .validate()
            .map_err(|error| source_error("source", &error))?;
        self.coverage
            .validate_against_source(&self.source)
            .map_err(|error| source_error("coverage", &error))?;
        self.enumeration
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "enumeration",
                reason: error.to_string(),
            })?;
        self.event_denominator
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "event.denominator_owner",
                reason: error.to_string(),
            })?;
        if self.enumeration.denominator != self.event_denominator.digest
            || self.enumeration.denominator_size != self.event_denominator.members.len() as u64
            || self.enumeration.query
                != self
                    .event_denominator
                    .query
                    .clone()
                    .ok_or(ContractViolation::MissingField("event.denominator.query"))?
            || self.enumeration.frontier
                != self.event_denominator.frontier.clone().ok_or(
                    ContractViolation::MissingField("event.denominator.frontier"),
                )?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "event.denominator_receipt",
                reason: "event receipt is not bound to its owner denominator".to_owned(),
            });
        }
        fence_eq(
            &self.source.identity.state_fence,
            &ctx.job.state_fence,
            "source.state_fence",
        )?;
        if self.coverage.denominator != self.source.denominator {
            return Err(ContractViolation::BindingMismatch {
                field: "coverage.denominator",
                reason: "coverage is for a different source denominator".to_owned(),
            });
        }
        if self.enumeration.task_id.as_str() != ctx.job.task_id
            || self.enumeration.scope != ctx.job.scope_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "enumeration.task_scope",
                reason: "coverage receipt differs from accepted job".to_owned(),
            });
        }
        if self.event_denominator.fence != self.source.identity.state_fence
            || self.event_denominator.scope != self.source.identity.scope.as_str()
            || self.event_denominator.revision != self.source.identity.revision.to_string()
            || self.event_denominator.snapshot.snapshot_id
                != self.source.identity.snapshot_id.as_str()
            || self.event_denominator.snapshot.owner != self.source.identity.source_id
            || self.enumeration.fence != self.source.identity.state_fence
            || self.enumeration.policy != ctx.job.policy_ref
        {
            return Err(ContractViolation::BindingMismatch {
                field: "enumeration.identity",
                reason: "receipt fence, policy, or denominator differs from source".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn member(
        &self,
        id: &MemberId,
    ) -> Option<&eliot_memory_curation_contracts::SourceMember> {
        self.source
            .members
            .iter()
            .find(|member| &member.member_id == id)
    }
}

/// Existing Episode membership retained for exact overlap and rollback joins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExistingEpisodeMember {
    pub event_id: String,
    pub source_member_id: MemberId,
    pub revision: TaskRevision,
    pub content_digest: Digest,
}

impl ExistingEpisodeMember {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.event_id, "existing.event_id")?;
        Ok(())
    }
}

/// Existing Episode snapshot; raw/source records remain outside mutation scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExistingEpisodeSnapshot {
    pub episode_id: String,
    pub revision: TaskRevision,
    pub content_digest: Digest,
    pub state_fence: StateFence,
    pub boundary_start_event_id: String,
    pub boundary_end_event_id: Option<String>,
    pub predecessor_episode_id: Option<String>,
    pub members: Vec<ExistingEpisodeMember>,
    pub coverage: Option<CoverageReceipt>,
    pub evidence_bindings: Vec<EvidenceBinding>,
}

impl ExistingEpisodeSnapshot {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.episode_id, "existing.episode_id")?;
        if self.content_digest.as_str().len() != 64 {
            return Err(ContractViolation::Malformed {
                field: "existing.content_digest",
                reason: "must be a canonical digest".to_owned(),
            });
        }
        text(&self.boundary_start_event_id, "existing.boundary_start")?;
        if let Some(end) = &self.boundary_end_event_id {
            text(end, "existing.boundary_end")?;
        }
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "existing.state_fence",
                reason: error.to_string(),
            })?;
        cap(self.members.len(), MAX_EVENTS, "existing.members")?;
        let mut ids = BTreeSet::new();
        for member in &self.members {
            member.validate()?;
            if !ids.insert(member.event_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "existing.members",
                    reason: "duplicate existing event".to_owned(),
                });
            }
        }
        cap(
            self.evidence_bindings.len(),
            MAX_LINKS,
            "existing.evidence_bindings",
        )?;
        for binding in &self.evidence_bindings {
            binding.validate()?;
        }
        if let Some(receipt) = &self.coverage {
            receipt
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "existing.coverage",
                    reason: error.to_string(),
                })?;
        }
        Ok(())
    }
}

/// Explicit Episode boundary policy; no generic timeline or causal authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundaryRule {
    ExplicitEventAnchors,
}

/// Explicit overlap handling policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OverlapRule {
    PreserveConflict,
    Block,
}

/// Episode-only policy and bounded cancellation/capacity controls.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodePolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_digest: String,
    pub state_fence: StateFence,
    pub boundary_rule: BoundaryRule,
    pub start_event_id: Option<String>,
    pub end_event_id: Option<String>,
    pub overlap_rule: OverlapRule,
    pub max_events: usize,
    pub max_participants: usize,
    pub max_output_bytes: usize,
    pub max_source_members: usize,
    pub max_gaps: usize,
    pub max_neighborhood: usize,
    pub max_work: u64,
    pub max_input_bytes: u64,
    pub max_stu: u64,
    pub deadline_ms: Option<u64>,
    pub now_ms: Option<u64>,
    pub cancellation_requested: bool,
}

impl EpisodePolicy {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.policy_id, "policy.id")?;
        if self.schema_version != 1 {
            return Err(ContractViolation::BindingMismatch {
                field: "policy.schema_version",
                reason: "expected schema version 1".to_owned(),
            });
        }
        if !eliot_dreamer_contracts::is_hex64_lower(&self.policy_digest) {
            return Err(ContractViolation::Malformed {
                field: "policy.digest",
                reason: "must be lowercase SHA-256".to_owned(),
            });
        }
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "policy.state_fence",
                reason: error.to_string(),
            })?;
        if self.max_events == 0 || self.max_events > MAX_EVENTS {
            return Err(ContractViolation::OutOfBounds {
                field: "policy.max_events",
                min: 1,
                max: i64::try_from(MAX_EVENTS).unwrap_or(i64::MAX),
                got: i64::try_from(self.max_events).unwrap_or(i64::MAX),
            });
        }
        if self.max_participants == 0 || self.max_participants > MAX_PARTICIPANTS {
            return Err(ContractViolation::OutOfBounds {
                field: "policy.max_participants",
                min: 1,
                max: i64::try_from(MAX_PARTICIPANTS).unwrap_or(i64::MAX),
                got: i64::try_from(self.max_participants).unwrap_or(i64::MAX),
            });
        }
        if self.max_output_bytes == 0 {
            return Err(ContractViolation::MissingField("policy.max_output_bytes"));
        }
        if self.max_source_members == 0
            || self.max_gaps > MAX_EVENTS
            || self.max_neighborhood > MAX_LINKS
            || self.max_work == 0
            || self.max_input_bytes == 0
        {
            return Err(ContractViolation::OutOfBounds {
                field: "policy.capacity",
                min: 1,
                max: i64::try_from(MAX_LINKS).unwrap_or(i64::MAX),
                got: 0,
            });
        }
        if self.start_event_id.is_none() {
            return Err(ContractViolation::MissingField("policy.boundary_anchors"));
        }
        for id in [&self.start_event_id, &self.end_event_id]
            .into_iter()
            .flatten()
        {
            text(id, "policy.boundary_event")?;
        }
        Ok(())
    }

    /// Computes the policy identity excluding its self-referential digest.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct PolicyMaterial<'a> {
            version: u32,
            policy_id: &'a str,
            state_fence: &'a StateFence,
            boundary_rule: BoundaryRule,
            start_event_id: &'a Option<String>,
            end_event_id: &'a Option<String>,
            overlap_rule: OverlapRule,
            max_events: usize,
            max_participants: usize,
            max_output_bytes: usize,
            max_source_members: usize,
            max_gaps: usize,
            max_neighborhood: usize,
            max_work: u64,
            max_input_bytes: u64,
            max_stu: u64,
            deadline_ms: Option<u64>,
            now_ms: Option<u64>,
            cancellation_requested: bool,
        }
        let material = PolicyMaterial {
            version: self.schema_version,
            policy_id: &self.policy_id,
            state_fence: &self.state_fence,
            boundary_rule: self.boundary_rule,
            start_event_id: &self.start_event_id,
            end_event_id: &self.end_event_id,
            overlap_rule: self.overlap_rule,
            max_events: self.max_events,
            max_participants: self.max_participants,
            max_output_bytes: self.max_output_bytes,
            max_source_members: self.max_source_members,
            max_gaps: self.max_gaps,
            max_neighborhood: self.max_neighborhood,
            max_work: self.max_work,
            max_input_bytes: self.max_input_bytes,
            max_stu: self.max_stu,
            deadline_ms: self.deadline_ms,
            now_ms: self.now_ms,
            cancellation_requested: self.cancellation_requested,
        };
        Ok(digest_hex(&canonical_bytes(&material)?))
    }
}

fn validate_time_point(
    point: &eliot_dreamer_contracts::RelationTimePoint,
) -> Result<(), ContractViolation> {
    text(&point.clock_ref, "temporal.clock_ref")?;
    point
        .reading
        .validate()
        .map_err(|error| ContractViolation::Malformed {
            field: "temporal.reading",
            reason: error.to_string(),
        })?;
    if let Some(reference) = &point.conversion_ref {
        text(reference, "temporal.conversion_ref")?;
    }
    Ok(())
}

/// Local shape validation for the existing five-role optional temporal data.
pub(crate) fn validate_temporal(value: &RelationTemporalEvidence) -> Result<(), ContractViolation> {
    for point in [
        &value.event_time,
        &value.effective_time,
        &value.observation_time,
        &value.ingestion_time,
        &value.commit_time,
    ]
    .into_iter()
    .flatten()
    {
        validate_time_point(point)?;
    }
    if let Some(reference) = &value.uncertainty_ref {
        text(reference, "temporal.uncertainty_ref")?;
    }
    Ok(())
}

/// Returns the complete event time point only when its wall-clock reading is explicit.
pub(crate) fn event_time_point(
    value: &RelationTemporalEvidence,
) -> Option<&eliot_dreamer_contracts::RelationTimePoint> {
    value
        .event_time
        .as_ref()
        .filter(|point| point.reading.valid_time_ms.is_some())
}
