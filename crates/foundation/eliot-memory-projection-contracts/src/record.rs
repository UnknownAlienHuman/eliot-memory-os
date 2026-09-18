//! Versioned owner-neutral memory projection records.
//!
//! A [`MemoryProjectionRecord`] is the exact bounded read shape the Governor
//! projection provider hands to Smart: canonical handle and kind,
//! WorkScope/task/session applicability, compatible [`StateFence`] and
//! projection revision, epistemic status, lifecycle, freshness, provenance
//! and influence eligibility, declared procedure gates, exact cue and
//! negative-memory trigger metadata, protected roles, and the denominator
//! context (which lives on the batch, not the record).
//!
//! By design there is no score, rank, similarity, retrieval-count, or
//! model-judgment field anywhere in this module. CC-008 explicitly rejects
//! treating cue activation, retrieval, repetition, delivery, similarity, or
//! model judgment as applicability, support, or admission; carrying such a
//! number would invite exactly that misuse.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ContractError, SessionId, SourceId, StateFence, TaskId};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::MemoryProjectionError;

/// Maximum roles carried by one record.
pub const MAX_RECORD_ROLES: usize = 8;
/// Maximum preconditions declared by one record.
pub const MAX_PRECONDITIONS: usize = 32;
/// Maximum applicability limits declared by one record.
pub const MAX_APPLICABILITY_LIMITS: usize = 32;
/// Maximum cue triggers carried by one record.
pub const MAX_CUE_TRIGGERS: usize = 32;
/// Maximum Unicode scalar values accepted for one scope identity.
pub const MAX_SCOPE_CHARS: usize = 256;

fn text(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MemoryProjectionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Closed canonical memory kinds carried by a projection.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryKind {
    /// Retained episode with outcome lineage.
    Episode,
    /// Directly captured observation, not yet support for a claim.
    Observation,
    /// Procedure or skill with declared preconditions.
    Procedure,
    /// Consolidated concept or category.
    Concept,
    /// Failure memory with an exact deterministic trigger.
    NegativeMemory,
    /// Minority or rival evidence a promotion must not delete.
    Counterexample,
}

/// Influence roles a projected record may carry.
///
/// Roles travel with the record and are never stripped by projection,
/// evaluation, or consumption: popularity, retrieval repetition, or a
/// majority narrative must not delete minority, counterexample, audit, or
/// failure-fingerprint material (A14.4).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryRole {
    /// Withheld from task-local applicability pending a governed release.
    Protected,
    /// Low-use evidence that stays addressable regardless of popularity.
    Minority,
    /// Rival evidence a promotion must reconcile, never delete.
    Counterexample,
    /// Retained for audit and replay.
    Audit,
    /// Compact failure identity for recurrence detection.
    FailureFingerprint,
}

/// Freshness of one projected record relative to its declared scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshnessState {
    /// Current for the declared scope.
    Current,
    /// Known older snapshot; the note names the boundary that passed.
    Stale,
    /// Freshness cannot be established; the note names what is missing.
    Unknown,
}

/// Freshness statement carried by one record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryFreshness {
    /// Freshness state of the record.
    pub state: FreshnessState,
    /// Bounded note: which boundary passed, or what is missing.
    pub note: String,
}

impl MemoryFreshness {
    /// Validate the freshness statement shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.note, "freshness.note")
    }
}

/// One declared procedure precondition with its projection-time assessment.
///
/// `satisfied` is assessed by the projecting owner, never by Smart: `Some`
/// carries the owner's verdict, `None` means unassessed and fails closed at
/// evaluation. Similarity to a satisfied precondition is not satisfaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Precondition {
    /// Stable precondition identity.
    pub id: String,
    /// Owner assessment: `Some(true)` passes, anything else fails closed.
    pub satisfied: Option<bool>,
}

impl Precondition {
    /// Validate the precondition shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.id, "precondition.id")
    }
}

/// Exact cue trigger metadata carried by one record.
///
/// Triggers name the cue that may surface the record. A trigger firing is
/// candidate evidence only: it never proves applicability, and a semantic
/// (non-exact) trigger never satisfies an exact-match requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CueTrigger {
    /// Stable cue identity.
    pub cue_id: String,
    /// Whether surfacing through this trigger requires an exact match.
    pub exact_match_required: bool,
}

impl CueTrigger {
    /// Validate the trigger shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.cue_id, "cue_trigger.cue_id")
    }
}

/// Exact negative-memory trigger metadata (A14.3).
///
/// Only an exact deterministic trigger match may block. Semantic similarity
/// to a trigger creates a warning or inquiry obligation, never an automatic
/// hard block; that obligation is owned outside this contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeTrigger {
    /// Exact deterministic trigger text; matches only on equality.
    pub trigger: String,
    /// Action that failed under this trigger.
    pub failed_action: String,
    /// Observed outcome of the failure.
    pub outcome: String,
    /// Invariant the failure violated.
    pub violated_invariant: String,
    /// Condition under which the avoidance may reopen.
    pub reopen_condition: String,
    /// Condition under which the avoidance extinguishes.
    pub extinction_condition: String,
}

impl NegativeTrigger {
    /// Validate every trigger field.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.trigger, "negative_trigger.trigger")?;
        text(&self.failed_action, "negative_trigger.failed_action")?;
        text(&self.outcome, "negative_trigger.outcome")?;
        text(
            &self.violated_invariant,
            "negative_trigger.violated_invariant",
        )?;
        text(&self.reopen_condition, "negative_trigger.reopen_condition")?;
        text(
            &self.extinction_condition,
            "negative_trigger.extinction_condition",
        )
    }
}

/// Task/scope/session/fence binding shared by one projection batch.
///
/// This mirrors the task/scope/fence triple of the context-candidate
/// `ContextBinding` read-only: the shape is reused so provider and consumer
/// fixtures bind the exact same fence, but this foundation crate neither
/// imports nor edits the Smart-owned binding type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryScopeBinding {
    /// Durable task identity; every record must name this task.
    pub task_id: TaskId,
    /// Exact work scope; every record must name this scope.
    pub scope_id: WorkScopeId,
    /// Attached semantic session, when the projection is session-bound.
    pub session_id: Option<SessionId>,
    /// Fence every record fence must be compatible with.
    pub state_fence: StateFence,
}

impl MemoryScopeBinding {
    /// Validate identity shape and fence.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        if self.scope_id.as_str().chars().count() > MAX_SCOPE_CHARS {
            return Err(MemoryProjectionError::Bounds {
                field: "binding.scope_id",
            });
        }
        self.state_fence
            .validate()
            .map_err(MemoryProjectionError::from)
            .map_err(|error| match error {
                MemoryProjectionError::Foundation(ContractError::InvalidInterval { .. }) => {
                    MemoryProjectionError::InvalidField {
                        field: "binding.state_fence",
                        reason: "fence interval is invalid",
                    }
                }
                other => other,
            })
    }
}

/// One bounded canonical memory projection record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryProjectionRecord {
    /// Contract version this record was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Exact canonical handle of the record.
    pub handle: ArtifactId,
    /// Canonical kind of the record.
    pub kind: MemoryKind,
    /// Task/scope/session applicability declared by the projecting owner.
    pub binding: MemoryScopeBinding,
    /// Fence the record was projected under.
    pub state_fence: StateFence,
    /// Projection revision assigned by the projecting owner.
    pub projection_revision: u64,
    /// Epistemic status; consumers may cap it, never promote it.
    pub epistemic: EpistemicStatus,
    /// Assertability ceiling travelling with the record.
    pub assertability: Assertability,
    /// Lifecycle state; only `Active` participates in applicability.
    pub lifecycle: LifecycleState,
    /// Freshness statement for the declared scope.
    pub freshness: MemoryFreshness,
    /// Exact source and route lineage.
    pub provenance: Provenance,
    /// Prior projection in the immutable lineage, when superseded content is retained.
    pub predecessor: Option<ArtifactId>,
    /// Influence roles travelling with the record.
    pub roles: Vec<MemoryRole>,
    /// Whether the record is eligible for downstream influence at all.
    pub influence_eligible: bool,
    /// Declared procedure preconditions with owner assessment.
    pub preconditions: Vec<Precondition>,
    /// Declared applicability limits, where relevant.
    pub applicability_limits: Vec<String>,
    /// Exact cue trigger metadata.
    pub cue_triggers: Vec<CueTrigger>,
    /// Negative-memory trigger metadata, for failure records.
    pub negative_trigger: Option<NegativeTrigger>,
    /// Canonical source identity of the projected record.
    pub source_id: SourceId,
}

impl MemoryProjectionRecord {
    /// Validate record shape. Cross-record fence/scope gating is owned by
    /// the batch, which sees the shared binding.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(MemoryProjectionError::VersionMismatch);
        }
        self.binding.validate()?;
        self.state_fence
            .validate()
            .map_err(MemoryProjectionError::from)?;
        self.freshness.validate()?;
        self.provenance
            .validate()
            .map_err(MemoryProjectionError::from)?;
        if self.predecessor.as_ref() == Some(&self.handle) {
            return Err(MemoryProjectionError::InvalidField {
                field: "record.predecessor",
                reason: "predecessor must differ from the record handle",
            });
        }
        if self.roles.len() > MAX_RECORD_ROLES {
            return Err(MemoryProjectionError::Bounds {
                field: "record.roles",
            });
        }
        let mut seen_roles = BTreeSet::new();
        for role in &self.roles {
            if !seen_roles.insert(role) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "record.roles",
                    value: format!("{role:?}"),
                });
            }
        }
        if self.preconditions.len() > MAX_PRECONDITIONS {
            return Err(MemoryProjectionError::Bounds {
                field: "record.preconditions",
            });
        }
        let mut seen_preconditions = BTreeSet::new();
        for precondition in &self.preconditions {
            precondition.validate()?;
            if !seen_preconditions.insert(precondition.id.clone()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "record.preconditions",
                    value: precondition.id.clone(),
                });
            }
        }
        if self.applicability_limits.len() > MAX_APPLICABILITY_LIMITS {
            return Err(MemoryProjectionError::Bounds {
                field: "record.applicability_limits",
            });
        }
        for limit in &self.applicability_limits {
            text(limit, "record.applicability_limits")?;
        }
        if self.cue_triggers.len() > MAX_CUE_TRIGGERS {
            return Err(MemoryProjectionError::Bounds {
                field: "record.cue_triggers",
            });
        }
        let mut seen_triggers = BTreeSet::new();
        for trigger in &self.cue_triggers {
            trigger.validate()?;
            if !seen_triggers.insert(trigger.cue_id.clone()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "record.cue_triggers",
                    value: trigger.cue_id.clone(),
                });
            }
        }
        if let Some(trigger) = &self.negative_trigger {
            trigger.validate()?;
        }
        Ok(())
    }
}
