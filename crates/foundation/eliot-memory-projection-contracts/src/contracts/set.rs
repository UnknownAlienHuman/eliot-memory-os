//! Task-local applicability sets: the evaluator output contract.
//!
//! An [`ApplicableMemorySet`] is what `eliot-memory-applicability` returns
//! for one [`MemoryProjectionBatch`](crate::contracts::batch::MemoryProjectionBatch):
//! the applicable handles with their preserved roles, plus every excluded
//! handle with its exact substantive reason. Cue-hit evidence travels as a
//! per-disposition flag only: a cue hit never promotes a record into
//! `applicable`, and exclusion always names the rule that excluded the
//! record, never the cue hit itself.
//!
//! The set is independently deserializable, so it carries the proof ceiling
//! for a result it cannot fully recheck: the exact omission and frontier
//! identities stay on the [`MemoryProjectionBatch`] that produced it, and a
//! verdict that accounts for less than its known denominator is admissible
//! only while it declares the revalidation that incomplete state requires.
//! [`validate_against_batch`](ApplicableMemorySet::validate_against_batch) is
//! the single owner of the join between the two.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contracts::batch::{DenominatorState, MemoryProjectionBatch};
use crate::contracts::error::MemoryProjectionError;
use crate::contracts::record::{MemoryKind, MemoryRole, MemoryScopeBinding};

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
///
/// [`InfluenceIneligible`](Self::InfluenceIneligible) is the owner's own
/// prohibition, read from the record's `influence_eligible` flag. It is a
/// first-class reason and never a spelling of [`Protected`](Self::Protected),
/// [`Rejected`](Self::Rejected) or
/// [`LifecycleInactive`](Self::LifecycleInactive): those three name a
/// different owner fact (a withheld role, a governed rejection, an inactive
/// lifecycle), and reporting an influence prohibition under any of them would
/// lose the record's own admission state. I12.26 likewise evaluates
/// `MemoryAdmissionDecision` over "source assurance and allowed influence" as
/// its own dimension beside epistemic status and freshness.
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
    /// The projecting owner marked the record ineligible for downstream
    /// influence at all.
    ///
    /// `false` is a valid record state, independent of lifecycle, freshness,
    /// epistemic status and roles, so the prohibition is reportable without
    /// inventing any of them. The record itself stays in the projection and
    /// in the batch accounting: this reason withholds it from *applicability*,
    /// and never deletes, rewrites, or silently drops it.
    #[serde(rename = "INFLUENCE_INELIGIBLE")]
    InfluenceIneligible,
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
            | Self::InfluenceIneligible
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
///
/// The frozen set shape carries disposition handles and the proof-ceiling
/// flags only. Exact omission and frontier identities remain owned by the
/// [`MemoryProjectionBatch`] that produced this verdict, so a standalone set
/// cannot recheck a lossy remainder and must never be read as a complete
/// coverage artifact; [`validate_against_batch`](Self::validate_against_batch)
/// is the join that rechecks the verdict against that batch.
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
    /// Validate set shape, handle uniqueness, exclusion reasons, and the
    /// verdict's own coverage ceiling.
    ///
    /// A known denominator is required: an applicability verdict states which
    /// members of an observed population it covers, and a verdict over an
    /// unknown population is not a verdict. The disposition volume may fall
    /// short of the denominator only while `revalidation_required` declares
    /// that incomplete state, which is the proof ceiling this frozen shape can
    /// actually carry: it holds no omission or frontier identity to recheck the
    /// shortfall against. A verdict that both claims the exact denominator and
    /// closes revalidation while accounting for less is refused here rather
    /// than reconciled later by whichever consumer happens to read it.
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
        let accounted = self
            .applicable
            .len()
            .checked_add(self.excluded.len())
            .ok_or(MemoryProjectionError::CoverageMismatch {
                reason: "set disposition volume overflows",
            })?;
        if self.truncated && !self.revalidation_required {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "a truncated verdict must require revalidation",
            });
        }
        let DenominatorState::Known { total } = &self.denominator else {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "an applicability verdict requires a known denominator",
            });
        };
        if accounted > *total {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "set dispositions exceed the known denominator",
            });
        }
        if !self.revalidation_required && accounted != *total {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "a closed verdict must account for the exact known denominator",
            });
        }
        Ok(())
    }

    /// Revalidate this verdict against the exact batch it describes.
    ///
    /// [`validate`](Self::validate) proves the verdict is internally coherent
    /// and carries an honest proof ceiling; this is the join that proves the
    /// verdict is *about* that batch. It revalidates the batch, compares the
    /// batch's own coverage echoes, and requires the disposition handles to
    /// equal exactly the batch record handles, so a shape-valid verdict
    /// cannot be paired with another read's denominator or truncation posture,
    /// and no projected record can be left without a disposition or given a
    /// disposition for a record the batch never carried.
    ///
    /// The repeated per-entry `kind` and `roles` are deliberately not
    /// compared here. They are echoes, not authority: the batch record is the
    /// canonical identity and consumers must derive from it, so a verdict
    /// that repeats a stale `kind` is wrong at the consumer that reads it, not
    /// at this join. The batch also owns the omitted and deferred identities;
    /// nothing here reconstructs or re-derives them.
    pub fn validate_against_batch(
        &self,
        batch: &MemoryProjectionBatch,
    ) -> Result<(), MemoryProjectionError> {
        self.validate()?;
        batch.validate()?;
        if self.binding != batch.binding
            || self.denominator != batch.coverage.denominator
            || self.truncated != batch.coverage.truncated
            || self.revalidation_required != batch.coverage.revalidation_required
        {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "set coverage echoes do not match the bound batch",
            });
        }
        let batch_handles: BTreeSet<&str> = batch
            .records
            .iter()
            .map(|record| record.handle.as_str())
            .collect();
        let dispositions: BTreeSet<&str> = self
            .applicable
            .iter()
            .map(|entry| entry.handle.as_str())
            .chain(self.excluded.iter().map(|entry| entry.handle.as_str()))
            .collect();
        if dispositions.len() != batch_handles.len()
            || batch_handles
                .iter()
                .any(|handle| !dispositions.contains(handle))
        {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "set dispositions must equal exactly the bound batch record handles",
            });
        }
        Ok(())
    }
}
