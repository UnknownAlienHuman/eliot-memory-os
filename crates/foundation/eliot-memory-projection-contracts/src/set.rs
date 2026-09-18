//! Task-local applicability sets: the evaluator output contract.
//!
//! An [`ApplicableMemorySet`] is what `eliot-memory-applicability` returns
//! for one [`MemoryProjectionBatch`](crate::batch::MemoryProjectionBatch):
//! the applicable handles with their preserved roles, plus every excluded
//! handle with its exact substantive reason. Cue-hit evidence travels as a
//! per-disposition flag only: a cue hit never promotes a record into
//! `applicable`, and exclusion always names the rule that excluded the
//! record, never the cue hit itself.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::batch::DenominatorState;
use crate::error::MemoryProjectionError;
use crate::record::{MemoryKind, MemoryRole, MemoryScopeBinding};

fn text(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MemoryProjectionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Substantive exclusion rule for one projected record.
///
/// Every variant names the applicability rule that failed. There is
/// deliberately no `CueHit...` variant: a cue hit is advisory evidence, and
/// using cue-hit-ness itself as an exclusion reason would invert the same
/// error (treating activation as applicability proof, only negatively).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "rule", deny_unknown_fields)]
pub enum ExclusionReason {
    /// Freshness or epistemic status reports stale material.
    #[serde(rename = "STALE")]
    Stale,
    /// Competing evidence or models remain unresolved.
    #[serde(rename = "CONFLICTED")]
    Conflicted,
    /// Explicitly rejected by a governed evaluation or adjudication.
    #[serde(rename = "REJECTED")]
    Rejected,
    /// The material cannot establish a position.
    #[serde(rename = "EPISTEMICALLY_UNKNOWN")]
    EpistemicallyUnknown,
    /// Protected role withheld from task-local applicability.
    #[serde(rename = "PROTECTED")]
    Protected,
    /// An exact negative-memory trigger matched the current task key.
    #[serde(rename = "NEGATIVE_MEMORY")]
    NegativeMemory,
    /// A declared precondition assessed `false` by the projecting owner.
    #[serde(rename = "PRECONDITION_FAILED")]
    PreconditionFailed {
        /// Stable identity of the failed precondition.
        id: String,
    },
    /// A declared precondition arrived without an owner assessment.
    #[serde(rename = "PRECONDITION_UNASSESSED")]
    PreconditionUnassessed {
        /// Stable identity of the unassessed precondition.
        id: String,
    },
    /// Lifecycle is not `Active`.
    #[serde(rename = "LIFECYCLE_INACTIVE")]
    LifecycleInactive,
    /// Record fence is incompatible with the batch fence.
    #[serde(rename = "FENCE_MISMATCH")]
    FenceMismatch,
    /// Record task/scope/session differs from the batch binding.
    #[serde(rename = "SCOPE_MISMATCH")]
    ScopeMismatch,
}

impl ExclusionReason {
    /// Validate reason payload shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        match self {
            Self::PreconditionFailed { id } | Self::PreconditionUnassessed { id } => {
                text(id, "exclusion.precondition.id")
            }
            Self::Stale
            | Self::Conflicted
            | Self::Rejected
            | Self::EpistemicallyUnknown
            | Self::Protected
            | Self::NegativeMemory
            | Self::LifecycleInactive
            | Self::FenceMismatch
            | Self::ScopeMismatch => Ok(()),
        }
    }
}

/// One record applicable to the current task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplicableMemory {
    /// Exact canonical handle of the applicable record.
    pub handle: ArtifactId,
    /// Canonical kind of the record.
    pub kind: MemoryKind,
    /// Roles preserved with the record, never stripped.
    pub roles: Vec<MemoryRole>,
    /// Whether cue-hit evidence named this record (advisory only).
    pub cue_hit: bool,
}

/// One record excluded from the current task with its exact reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExcludedMemory {
    /// Exact canonical handle of the excluded record.
    pub handle: ArtifactId,
    /// Canonical kind of the record.
    pub kind: MemoryKind,
    /// Substantive rule that excluded the record.
    pub reason: ExclusionReason,
    /// Whether cue-hit evidence named this record (advisory only).
    ///
    /// `cue_hit: true` beside an exclusion is the adversarial case the
    /// Orientation Product Pulse must show: the cue fired, the record is
    /// still not applicable, and the reason says why.
    pub cue_hit: bool,
}

impl ExcludedMemory {
    /// Validate the exclusion shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        self.reason.validate()
    }
}

/// Task-local applicability verdict over one projection batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplicableMemorySet {
    /// Contract version this set was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Binding the evaluated batch carried.
    pub binding: MemoryScopeBinding,
    /// Applicable records in deterministic evaluation order.
    pub applicable: Vec<ApplicableMemory>,
    /// Excluded records with exact reasons, in deterministic order.
    pub excluded: Vec<ExcludedMemory>,
    /// Denominator context echoed from the evaluated batch.
    pub denominator: DenominatorState,
    /// Truncation flag echoed from the evaluated batch.
    pub truncated: bool,
    /// Revalidation requirement echoed from the evaluated batch.
    pub revalidation_required: bool,
    /// Cue-hit handles considered during evaluation (advisory only).
    pub cue_hits_considered: usize,
}

impl ApplicableMemorySet {
    /// Validate set shape: binding, handle uniqueness across both lists, and
    /// exclusion reasons.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(MemoryProjectionError::VersionMismatch);
        }
        self.binding.validate()?;
        self.denominator.validate()?;
        let mut seen = BTreeSet::new();
        for record in &self.applicable {
            if !seen.insert(record.handle.as_str().to_owned()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "set.applicable",
                    value: record.handle.as_str().to_owned(),
                });
            }
        }
        for record in &self.excluded {
            record.validate()?;
            if !seen.insert(record.handle.as_str().to_owned()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "set.excluded",
                    value: record.handle.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }
}
