//! Complete pre-compaction handoff checkpoint payload (I12.17, I7.15).
//!
//! [`HandoffCheckpoint`] is the value that a
//! [`HandoffCausalLink`](crate::HandoffCausalLink) `checkpoint_ref` points at.
//! The link keeps its public-reference vocabulary; this payload is the complete
//! bounded content behind that reference and never replaces it.
//!
//! Two properties are encoded in the types rather than in prose:
//!
//! - the exact `done`/`open`/`killed`/`deferred` sets are closed against the
//!   declared [`HandoffWorkSet::expected_members`] denominator, so an expected
//!   member that could not be represented exactly becomes a typed
//!   [`HandoffUnavailableMember`] instead of a smaller recorded set;
//! - every unavailable unit, unreadable cursor and unreconciled effect is a
//!   named entry with a typed disposition, never an omitted field.
//!
//! Building or validating a payload performs no IO, mints no authority and
//! proves nothing about persistence. Durable capture and readback belong to the
//! Governor/Task Controller producer and to the Store.
//!
//! A retained checkpoint plus its resume-time revalidation
//! ([`RetainedHandoffCheckpoint`]) is the Resume input the decision gate
//! consumes instead of treating compaction as a fresh authority source.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ContractVersion, OperationId, ResourceGeneration, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AgentAttemptId, ContractError, HandoffAttemptIdentity, HandoffCausalLink, HandoffCheckpointId,
    HandoffContinuity, PublicReference, RevisionId, TargetId, WorkItemId, validate_collection,
    validate_text,
};

/// Stable contract name of the pre-compaction handoff checkpoint payload.
pub const HANDOFF_CHECKPOINT_CONTRACT_NAME: &str = "eliot.agent.handoff-checkpoint";

/// Current semantic revision of the pre-compaction handoff checkpoint payload.
///
/// A payload written against any other revision is refused by
/// [`HandoffCheckpoint::validate`] instead of being read as the current shape.
pub const HANDOFF_CHECKPOINT_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Required [`PublicReference::kind`] of a link's `checkpoint_ref`.
///
/// The reference locates a persisted checkpoint payload; it is neither the
/// payload itself nor a persistence proof.
pub const HANDOFF_CHECKPOINT_REFERENCE_KIND: &str = "handoff-checkpoint";

/// Required [`PublicReference::kind`] of a resume-time revalidation record.
///
/// The revalidation names the retained checkpoint it was computed over. It is
/// neither a fresh authority grant nor a rebuilt View (I12.17).
pub const HANDOFF_REVALIDATION_REFERENCE_KIND: &str = "handoff-revalidation";

/// Typed disposition of a unit the checkpoint cannot present as exact.
///
/// The variant names the loss; the entry that carries it names the subject and
/// the observed cause. A degraded unit is never replaced by a derived summary,
/// fluent prose or a smaller recorded set (I12.17, I12.13).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffDegradation {
    /// The exact source could not be read or retained. Nothing may stand in for
    /// it as original evidence, and the action that depends on it stays blocked.
    SourceUnavailable,
    /// Exact content is retained, but the named distinctions are lost. They
    /// must be re-derived from canonical state, never inferred from the
    /// retained form.
    LostDistinctions {
        /// Distinctions the retained content cannot reproduce.
        distinctions: Vec<String>,
    },
}

/// Exact work membership of the checkpoint at the capture boundary.
///
/// `expected_members` is the denominator declared before the boundary. Every
/// expected member is accounted for exactly once: by exactly one exact set, or
/// by one explicit [`HandoffUnavailableMember`]. A member is never dropped so
/// that the recorded sets fit what happened.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffWorkSet {
    /// Denominator of the exact sets, declared before the boundary.
    pub expected_members: Vec<WorkItemId>,
    /// Members whose work is complete.
    pub done: Vec<WorkItemId>,
    /// Members that are still open.
    pub open: Vec<WorkItemId>,
    /// Members that were deliberately killed.
    pub killed: Vec<WorkItemId>,
    /// Members that were deliberately deferred.
    pub deferred: Vec<WorkItemId>,
    /// Expected members whose exact disposition is not a set membership.
    pub unavailable: Vec<HandoffUnavailableMember>,
}

impl HandoffWorkSet {
    /// Proves that the exact sets are closed against the declared denominator.
    pub fn validate(&self) -> Result<(), HandoffCheckpointError> {
        validate_collection(&self.expected_members, "work.expected_members")?;
        let expected: BTreeSet<WorkItemId> = self.expected_members.iter().cloned().collect();
        let mut accounted: BTreeSet<WorkItemId> = BTreeSet::new();
        for (members, field) in [
            (&self.done, "work.done"),
            (&self.open, "work.open"),
            (&self.killed, "work.killed"),
            (&self.deferred, "work.deferred"),
        ] {
            if members.iter().collect::<BTreeSet<_>>().len() != members.len() {
                return Err(ContractError::DuplicateItem(field).into());
            }
            for member in members {
                account(&mut accounted, &expected, member)?;
            }
        }
        for entry in &self.unavailable {
            entry.validate()?;
            account(&mut accounted, &expected, &entry.work_item_id)?;
        }
        for member in &self.expected_members {
            if !accounted.contains(member) {
                return Err(HandoffCheckpointError::ExpectedWorkMemberUnaccounted {
                    work_item_id: member.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Accounts one member against the expected denominator.
fn account(
    accounted: &mut BTreeSet<WorkItemId>,
    expected: &BTreeSet<WorkItemId>,
    member: &WorkItemId,
) -> Result<(), HandoffCheckpointError> {
    if !accounted.insert(member.clone()) {
        return Err(HandoffCheckpointError::WorkMemberInMultipleSets {
            work_item_id: member.as_str().to_owned(),
        });
    }
    if !expected.contains(member) {
        return Err(HandoffCheckpointError::UnexpectedWorkMember {
            work_item_id: member.as_str().to_owned(),
        });
    }
    Ok(())
}

/// One expected work member that the checkpoint cannot place in an exact set.
///
/// The member stays in the denominator and is named here, so the loss is
/// detectable rather than a quietly shorter recorded set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffUnavailableMember {
    /// The expected member this entry accounts for.
    pub work_item_id: WorkItemId,
    /// Observed cause of the unavailability.
    pub cause: String,
    /// Typed disposition of the member.
    pub degradation: HandoffDegradation,
}

impl HandoffUnavailableMember {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        validate_text(
            self.work_item_id.as_str(),
            "unavailable_member.work_item_id",
        )?;
        validate_degradation(&self.cause, &self.degradation, self.work_item_id.as_str())
    }
}

/// A content, rationale or evidence loss already known at the boundary.
///
/// Known losses are recorded here before compaction so that a resume cannot
/// present a summary as the original rationale or evidence it replaces
/// (I12.17).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffKnownLoss {
    /// Exact unit the loss applies to.
    pub subject_ref: PublicReference,
    /// Observed cause of the loss.
    pub cause: String,
    /// Typed disposition of the lost unit.
    pub degradation: HandoffDegradation,
}

impl HandoffKnownLoss {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        self.subject_ref.validate()?;
        validate_degradation(&self.cause, &self.degradation, self.subject_ref.id.as_str())
    }
}

/// Validates a required cause and a typed degradation for one named subject.
fn validate_degradation(
    cause: &str,
    degradation: &HandoffDegradation,
    subject: &str,
) -> Result<(), HandoffCheckpointError> {
    validate_text(cause, "loss.cause")?;
    if let HandoffDegradation::LostDistinctions { distinctions } = degradation {
        if distinctions.is_empty() {
            return Err(HandoffCheckpointError::PartialLossWithoutDistinctions {
                subject: subject.to_owned(),
            });
        }
        validate_collection(distinctions, "loss.distinctions")?;
        for distinction in distinctions {
            validate_text(distinction, "loss.distinction")?;
        }
    }
    Ok(())
}

/// Whether a surviving critical item is critical attention or a conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffCriticalItemKind {
    /// Mandatory context, constraint or directive that must stay visible.
    CriticalAttention,
    /// Unresolved conflict between two claims, sources or requirements.
    Conflict,
}

/// One critical attention item or unresolved conflict surviving the boundary.
///
/// A blocking item is never dropped from the list: it is resolved, or it blocks
/// the action that depends on it after a resume (I12.13).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCriticalItem {
    /// Exact unit the item applies to.
    pub item_ref: PublicReference,
    /// Whether the item is critical attention or a conflict.
    pub kind: HandoffCriticalItemKind,
    /// Whether the item still blocks the action that depends on it.
    pub blocks_dependent_action: bool,
}

impl HandoffCriticalItem {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        self.item_ref.validate()?;
        Ok(())
    }
}

/// Recorded position of the source in one durable stream.
///
/// An unreadable stream is an explicit disposition, not an absent field: the
/// causal link cannot be admitted as causally continuous without it (I7.15).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffCursor {
    /// The exact opaque cursor text observed at the boundary.
    Observed {
        /// Opaque stream position owned by the emitting subsystem.
        cursor: String,
    },
    /// The stream position could not be observed at the boundary.
    Unavailable {
        /// Observed cause of the unreadable position.
        cause: String,
    },
}

impl HandoffCursor {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        match self {
            Self::Observed { cursor } => {
                validate_text(cursor, "cursor.cursor")?;
            }
            Self::Unavailable { cause } => {
                validate_text(cause, "cursor.cause")?;
            }
        }
        Ok(())
    }
}

/// Source event and outbox cursor positions at the boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCursors {
    /// Position in the source event stream.
    pub event: HandoffCursor,
    /// Position in the source outbox stream.
    pub outbox: HandoffCursor,
}

impl HandoffCursors {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        self.event.validate()?;
        self.outbox.validate()
    }
}

/// Recorded disposition of one in-flight operation and its external effect.
///
/// A lost acknowledgement, an expired lease or a silent retry is not proof
/// that an effect stopped, so an unreconciled operation keeps its
/// [`HandoffEffectDisposition::OutcomeUnknown`] disposition across the boundary
/// (I7.15).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffEffectDisposition {
    /// The operation was admitted but never dispatched; no effect exists.
    NotStarted,
    /// The effect completed and its receipt is retained by its owner.
    Completed {
        /// Exact receipt of the completed effect.
        receipt_ref: PublicReference,
    },
    /// The operation was dispatched and its outcome is not reconciled.
    OutcomeUnknown {
        /// Observed cause of the unreconciled outcome.
        cause: String,
    },
}

impl HandoffEffectDisposition {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        match self {
            Self::NotStarted => {}
            Self::Completed { receipt_ref } => {
                receipt_ref.validate()?;
            }
            Self::OutcomeUnknown { cause } => {
                validate_text(cause, "effect.cause")?;
            }
        }
        Ok(())
    }
}

/// One effect-capable operation that was in flight at the boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffEffectRecord {
    /// Identity of the in-flight operation.
    pub operation_id: OperationId,
    /// Recorded disposition of the operation and its external effect.
    pub disposition: HandoffEffectDisposition,
}

impl HandoffEffectRecord {
    fn validate(&self) -> Result<(), HandoffCheckpointError> {
        validate_text(self.operation_id.as_str(), "effect.operation_id")?;
        self.disposition.validate()
    }
}

/// Source scope, world, module and route generations at the boundary.
///
/// Each member is the same monotonic counter family the [`StateFence`] uses for
/// its own resource dependency; the fence's `resource_generation` is a separate
/// dependency and is never copied into these fields. A generation is
/// non-zero by construction, so a missing generation cannot be spelled as `0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffSourceGenerations {
    /// Generation of the scope the source attempt worked in.
    pub scope: ResourceGeneration,
    /// Generation of the world model the source attempt observed.
    pub world: ResourceGeneration,
    /// Generation of the module the source attempt ran in.
    pub module: ResourceGeneration,
    /// Generation of the route the source attempt was bound to.
    pub route: ResourceGeneration,
}

/// Complete, versioned and immutable pre-compaction handoff checkpoint (I12.17).
///
/// The payload is the value: a link's `checkpoint_ref` locates it and never
/// stands in for it. Every field is required on the wire, no field has a
/// default, and the struct exposes no transition, so a record written under an
/// older revision is refused instead of being read as a current checkpoint.
///
/// Validation proves internal consistency only. It does not read a store, does
/// not confirm that the referenced bytes exist, and does not admit a resume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCheckpoint {
    /// Identity of this checkpoint payload.
    pub checkpoint_id: HandoffCheckpointId,
    /// Contract revision this payload was written against.
    pub contract_version: ContractVersion,
    /// Continuity of the transfer this checkpoint supports. It must equal the
    /// continuity of the link the payload is bound to.
    pub continuity: HandoffContinuity,
    /// Task that was running at the boundary.
    pub source_task_id: TaskId,
    /// Attempt that was running at the boundary.
    pub source_attempt_id: AgentAttemptId,
    /// Public session reference of the source attempt.
    pub source_session_ref: PublicReference,
    /// Plan revision in force at the boundary.
    pub source_plan_revision: RevisionId,
    /// Acceptance revision the plan revision was admitted against.
    pub source_acceptance_revision: RevisionId,
    /// Goal reference in force at the boundary.
    pub goal_ref: PublicReference,
    /// Acceptance reference in force at the boundary.
    pub acceptance_ref: PublicReference,
    /// Exact work membership and its expected denominator.
    pub work: HandoffWorkSet,
    /// Handles of the current epistemic position at the boundary.
    pub epistemic_position_handles: Vec<PublicReference>,
    /// Handles of the exact atoms the next decision is load-bearing on.
    pub load_bearing_atom_handles: Vec<PublicReference>,
    /// Current diff, frozen as a digest-bound immutable artifact rather than a
    /// mutable path or a bare commit identity.
    pub diff_ref: PublicReference,
    /// Immutable artifacts the boundary depends on.
    pub artifact_refs: Vec<PublicReference>,
    /// Verifiers that were still pending at the boundary.
    pub pending_verifier_refs: Vec<PublicReference>,
    /// Critical attention and unresolved conflicts surviving the boundary.
    pub critical_items: Vec<HandoffCriticalItem>,
    /// The action the source attempt intended to take next.
    pub next_action: String,
    /// The condition that must stop that action.
    pub stop_condition: String,
    /// Source scope, world, module and route generations at the boundary.
    pub source_generations: HandoffSourceGenerations,
    /// State Fence the checkpoint was captured under.
    pub state_fence: StateFence,
    /// Source event and outbox cursor positions at the boundary.
    pub source_cursors: HandoffCursors,
    /// In-flight operations and their effect dispositions at the boundary.
    pub effects: Vec<HandoffEffectRecord>,
    /// Losses already known at the boundary.
    pub known_losses: Vec<HandoffKnownLoss>,
}

impl HandoffCheckpoint {
    /// Validates the complete payload against its own contract revision.
    ///
    /// Rejects a payload of another revision, a denominator that is not closed
    /// by the exact sets, a diff reference that is not digest-bound, a
    /// duplicated handle, a loss entry without a cause or named distinctions,
    /// and a cursor or effect record with a blank required field.
    pub fn validate(&self) -> Result<(), HandoffCheckpointError> {
        if self.contract_version != HANDOFF_CHECKPOINT_CONTRACT_VERSION {
            return Err(HandoffCheckpointError::UnsupportedContractVersion {
                version: self.contract_version,
            });
        }
        validate_text(self.checkpoint_id.as_str(), "checkpoint_id")?;
        validate_text(self.source_task_id.as_str(), "source_task_id")?;
        validate_text(self.source_attempt_id.as_str(), "source_attempt_id")?;
        validate_text(self.source_plan_revision.as_str(), "source_plan_revision")?;
        validate_text(
            self.source_acceptance_revision.as_str(),
            "source_acceptance_revision",
        )?;
        self.source_session_ref.validate()?;
        self.goal_ref.validate()?;
        self.acceptance_ref.validate()?;
        self.work.validate()?;
        for (references, field) in [
            (
                &self.epistemic_position_handles,
                "epistemic_position_handles",
            ),
            (&self.load_bearing_atom_handles, "load_bearing_atom_handles"),
            (&self.artifact_refs, "artifact_refs"),
            (&self.pending_verifier_refs, "pending_verifier_refs"),
        ] {
            validate_references(references, field)?;
        }
        self.diff_ref.validate()?;
        if self.diff_ref.digest.is_none() {
            return Err(HandoffCheckpointError::DiffReferenceIsNotImmutable);
        }
        for item in &self.critical_items {
            item.validate()?;
        }
        validate_unique_references(
            self.critical_items.iter().map(|item| &item.item_ref),
            "critical_items",
        )?;
        validate_text(&self.next_action, "next_action")?;
        validate_text(&self.stop_condition, "stop_condition")?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        self.source_cursors.validate()?;
        validate_effects(&self.effects)?;
        for loss in &self.known_losses {
            loss.validate()?;
        }
        Ok(())
    }

    /// Binds this payload to the causal link that references it.
    ///
    /// The link must be valid under the same attempt-identity evidence, its
    /// `checkpoint_ref` must name this payload, and the two records must agree
    /// on continuity, source attempt, source session, source plan revision and
    /// state fence. A link whose `checkpoint_ref` merely points somewhere is
    /// not a bound checkpoint.
    pub fn validate_binding(
        &self,
        link: &HandoffCausalLink,
        attempt_identity: &HandoffAttemptIdentity,
    ) -> Result<(), HandoffCheckpointError> {
        self.validate()?;
        link.validate(attempt_identity)?;
        if link.checkpoint_ref.kind != HANDOFF_CHECKPOINT_REFERENCE_KIND
            || link.checkpoint_ref.id.as_str() != self.checkpoint_id.as_str()
        {
            return Err(HandoffCheckpointError::CheckpointReferenceMismatch);
        }
        if link.continuity != self.continuity {
            return Err(HandoffCheckpointError::ContinuityMismatch);
        }
        if link.source_attempt_id != self.source_attempt_id {
            return Err(HandoffCheckpointError::SourceAttemptMismatch);
        }
        if link.source_session_ref != self.source_session_ref {
            return Err(HandoffCheckpointError::SourceSessionMismatch);
        }
        if link.source_revision != self.source_plan_revision {
            return Err(HandoffCheckpointError::SourceRevisionMismatch);
        }
        if link.source_state_fence != self.state_fence {
            return Err(HandoffCheckpointError::StateFenceMismatch);
        }
        Ok(())
    }
}

/// Resume-time revalidation of one retained checkpoint (I12.17, I7.15).
///
/// The record compares the generations retained at the capture boundary
/// against the generations the resume owner observes now. A changed member
/// fences only the dependent permissions and content, never unrelated work:
/// the flags below name exactly which members changed, so the resume owner
/// rebuilds a current delta View and obtains new authority for those members
/// instead of restamping the retained fence. Recording a change is not
/// refusing the resume; a binding or fence-shape failure is.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffResumeRevalidation {
    /// Identity of the retained checkpoint this revalidation was computed over.
    pub checkpoint_id: HandoffCheckpointId,
    /// Continuity the retained transfer supports.
    pub continuity: HandoffContinuity,
    /// Attempt that was running at the capture boundary.
    pub source_attempt_id: AgentAttemptId,
    /// Generations the resume owner observes now.
    pub current_generations: HandoffSourceGenerations,
    /// Whether the scope generation still matches the retained boundary.
    pub scope_changed: bool,
    /// Whether the world generation still matches the retained boundary.
    pub world_changed: bool,
    /// Whether the module generation still matches the retained boundary.
    pub module_changed: bool,
    /// Whether the route generation still matches the retained boundary.
    pub route_changed: bool,
    /// Whether the current fence still equals the retained fence.
    pub fence_changed: bool,
    /// Fence the resume owner observes now.
    pub current_fence: StateFence,
}

impl HandoffResumeRevalidation {
    /// Returns whether any retained generation changed, so dependent
    /// permissions and content must be fenced and rebuilt from canonical
    /// state rather than resumed under the retained fence.
    pub fn has_changed_generation(&self) -> bool {
        self.scope_changed || self.world_changed || self.module_changed || self.route_changed
    }
}

/// Retained checkpoint plus its resume-time revalidation (I12.17, I7.15).
///
/// This is the Resume input the decision gate consumes instead of treating
/// compaction as a fresh authority source. The resume owner carries this
/// value and feeds its references into the phase-aware lineage check
/// (`validate_for_phase` at `Resume` via `admit_material_decision`):
///
/// - the lineage `handoff` slot cites [`Self::checkpoint_ref`];
/// - already-due effect execution and outcome records that are still
///   unreconciled stay [`HandoffEffectDisposition::OutcomeUnknown`] here,
///   which is the evidence behind an explicit unknown lineage slot, never a
///   silent success;
/// - the lineage `omissions` slot cites the retained [`HandoffKnownLoss`] and
///   [`HandoffUnavailableMember`] entries.
///
/// Building or checking this value performs no IO, mints no authority and
/// reads no owner: the current generations and fence are caller-supplied
/// observations. When the Kernel cannot read back current authority, the
/// caller must refuse the resume instead of calling
/// [`Self::revalidate_for_resume`] with unobserved inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedHandoffCheckpoint {
    /// Retained complete payload from the capture boundary.
    pub checkpoint: HandoffCheckpoint,
    /// Causal link the retained payload is bound to.
    pub link: HandoffCausalLink,
    /// Attempt-identity evidence the link was admitted under.
    pub attempt_identity: HandoffAttemptIdentity,
    /// Resume-time revalidation of the retained payload.
    pub revalidation: HandoffResumeRevalidation,
}

impl RetainedHandoffCheckpoint {
    /// Revalidates a retained checkpoint for resume under current observations.
    ///
    /// Runs the full checkpoint-to-link binding (including the continuity
    /// attempt-identity rule) and records the retained-to-current generation
    /// and fence comparison. A changed generation is recorded, not refused:
    /// the resume owner fences the dependent authority and rebuilds. A
    /// binding mismatch or an ill-formed current fence fails closed.
    pub fn revalidate_for_resume(
        checkpoint: HandoffCheckpoint,
        link: HandoffCausalLink,
        attempt_identity: HandoffAttemptIdentity,
        current_generations: HandoffSourceGenerations,
        current_fence: StateFence,
    ) -> Result<Self, HandoffCheckpointError> {
        checkpoint.validate_binding(&link, &attempt_identity)?;
        current_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        let retained_generations = checkpoint.source_generations;
        let revalidation = HandoffResumeRevalidation {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            continuity: checkpoint.continuity,
            source_attempt_id: checkpoint.source_attempt_id.clone(),
            current_generations,
            scope_changed: retained_generations.scope != current_generations.scope,
            world_changed: retained_generations.world != current_generations.world,
            module_changed: retained_generations.module != current_generations.module,
            route_changed: retained_generations.route != current_generations.route,
            fence_changed: checkpoint.state_fence != current_fence,
            current_fence,
        };
        Ok(Self {
            checkpoint,
            link,
            attempt_identity,
            revalidation,
        })
    }

    /// Re-checks a retained value whose fields may have been reassigned after
    /// [`Self::revalidate_for_resume`] built it.
    ///
    /// Re-runs the binding, the current-fence shape and the agreement between
    /// the revalidation record and the retained payload. A revalidation that
    /// no longer describes its payload is refused.
    pub fn validate(&self) -> Result<(), HandoffCheckpointError> {
        self.checkpoint
            .validate_binding(&self.link, &self.attempt_identity)?;
        self.revalidation
            .current_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        let retained_generations = self.checkpoint.source_generations;
        let current_generations = self.revalidation.current_generations;
        if self.revalidation.checkpoint_id != self.checkpoint.checkpoint_id
            || self.revalidation.continuity != self.checkpoint.continuity
            || self.revalidation.source_attempt_id != self.checkpoint.source_attempt_id
            || self.revalidation.scope_changed
                != (retained_generations.scope != current_generations.scope)
            || self.revalidation.world_changed
                != (retained_generations.world != current_generations.world)
            || self.revalidation.module_changed
                != (retained_generations.module != current_generations.module)
            || self.revalidation.route_changed
                != (retained_generations.route != current_generations.route)
            || self.revalidation.fence_changed
                != (self.checkpoint.state_fence != self.revalidation.current_fence)
        {
            return Err(HandoffCheckpointError::RevalidationCheckpointMismatch);
        }
        Ok(())
    }

    /// Returns the canonical reference the lineage `handoff` slot cites: the
    /// checkpoint kind and identity under the retained plan revision.
    ///
    /// The reference locates the retained payload; like every reference here
    /// it carries no digest of its own and proves no persistence.
    pub fn checkpoint_ref(&self) -> Result<PublicReference, HandoffCheckpointError> {
        let reference = PublicReference {
            kind: HANDOFF_CHECKPOINT_REFERENCE_KIND.to_owned(),
            id: TargetId::new(self.checkpoint.checkpoint_id.as_str())?,
            revision: self.checkpoint.source_plan_revision.clone(),
            digest: None,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Returns the reference that names this revalidation, for the link's
    /// `post_resume_revalidation_ref` and the lineage evidence trail.
    pub fn revalidation_ref(&self) -> Result<PublicReference, HandoffCheckpointError> {
        let reference = PublicReference {
            kind: HANDOFF_REVALIDATION_REFERENCE_KIND.to_owned(),
            id: TargetId::new(self.revalidation.checkpoint_id.as_str())?,
            revision: self.checkpoint.source_plan_revision.clone(),
            digest: None,
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Validates a list of public references and rejects repeated units.
fn validate_references(
    references: &[PublicReference],
    field: &'static str,
) -> Result<(), HandoffCheckpointError> {
    for reference in references {
        reference.validate()?;
    }
    validate_unique_references(references.iter(), field)
}

/// Rejects repeated exact units in a reference stream.
fn validate_unique_references<'a>(
    references: impl IntoIterator<Item = &'a PublicReference>,
    field: &'static str,
) -> Result<(), HandoffCheckpointError> {
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    for reference in references {
        let unit = (
            reference.kind.clone(),
            reference.id.as_str().to_owned(),
            reference.revision.as_str().to_owned(),
        );
        if !seen.insert(unit) {
            return Err(ContractError::DuplicateItem(field).into());
        }
    }
    Ok(())
}

/// Validates in-flight operation records and rejects repeated operations.
fn validate_effects(effects: &[HandoffEffectRecord]) -> Result<(), HandoffCheckpointError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for effect in effects {
        effect.validate()?;
        if !seen.insert(effect.operation_id.as_str()) {
            return Err(ContractError::DuplicateItem("effects").into());
        }
    }
    Ok(())
}

/// Validation failure for the handoff checkpoint payload.
///
/// Every variant names the failing field or scope; no failure is collapsed
/// into a generic code or free text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffCheckpointError {
    /// A shared agent-contract rejection, already typed by the owner crate.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// The payload was written against another contract revision.
    #[error("handoff checkpoint contract version {version} is not the current revision")]
    UnsupportedContractVersion {
        /// Revision carried by the refused payload.
        version: ContractVersion,
    },
    /// The frozen diff is not bound to an immutable content digest.
    #[error("diff reference is not a digest-bound immutable artifact")]
    DiffReferenceIsNotImmutable,
    /// An expected member appears in more than one exact set or loss entry.
    #[error("work item {work_item_id} appears in more than one exact disposition")]
    WorkMemberInMultipleSets {
        /// The multiply accounted member.
        work_item_id: String,
    },
    /// A recorded member is not part of the declared denominator.
    #[error("work item {work_item_id} is recorded but is not an expected member")]
    UnexpectedWorkMember {
        /// The member outside the denominator.
        work_item_id: String,
    },
    /// An expected member has neither an exact set entry nor a loss entry.
    #[error("expected work member {work_item_id} has no exact disposition and no loss entry")]
    ExpectedWorkMemberUnaccounted {
        /// The unaccounted member of the denominator.
        work_item_id: String,
    },
    /// A partial loss does not name the distinctions it lost.
    #[error("partial loss for {subject} does not name its lost distinctions")]
    PartialLossWithoutDistinctions {
        /// Subject of the untyped partial loss.
        subject: String,
    },
    /// The link's checkpoint reference does not name this payload.
    #[error("the causal link checkpoint reference does not name this checkpoint payload")]
    CheckpointReferenceMismatch,
    /// The link and the payload declare different continuity.
    #[error("the causal link declares a different handoff continuity")]
    ContinuityMismatch,
    /// The link and the payload name different source attempts.
    #[error("the causal link names a different source attempt")]
    SourceAttemptMismatch,
    /// The link and the payload name different source sessions.
    #[error("the causal link names a different source session")]
    SourceSessionMismatch,
    /// The link and the payload name different source plan revisions.
    #[error("the causal link names a different source plan revision")]
    SourceRevisionMismatch,
    /// The link and the payload were captured under different state fences.
    #[error("the causal link was captured under a different state fence")]
    StateFenceMismatch,
    /// The resume revalidation no longer describes the retained payload.
    #[error("the resume revalidation does not describe the retained checkpoint payload")]
    RevalidationCheckpointMismatch,
}
