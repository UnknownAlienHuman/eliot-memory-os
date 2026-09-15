//! Pure task-local memory applicability evaluation (CC-008).
//!
//! [`evaluate_applicability`] maps one bounded [`MemoryProjectionBatch`]
//! to an [`ApplicableMemorySet`] with an exact substantive reason per
//! excluded record. The evaluator is Smart-owned and pure:
//!
//! - it never queries storage and never expands the read set; the batch it
//!   receives is the entire denominator it may consider;
//! - cue-hit handles arrive as advisory evidence only: a hit sets the
//!   per-disposition `cue_hit` flag and can never move a record into
//!   `applicable`, nor does cue-hit-ness itself exclude anything;
//! - no score, rank, similarity, retrieval count, or model judgment is
//!   read, because the contract carries none;
//! - exact negative-memory triggers match on equality against the request
//!   task key; semantic similarity is never a block (A14.3);
//! - evaluation order is deterministic input order; the output preserves it.
//!
//! Record checks run in a fixed documented order and the first failing rule
//! decides the exclusion reason, so a record failing several rules always
//! reports the same reason.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_evidence::EpistemicStatus;
use eliot_memory_projection_contracts::{
    ApplicableMemory, ApplicableMemorySet, DenominatorState, ExcludedMemory, ExclusionReason,
    FreshnessState, MemoryProjectionBatch, MemoryProjectionError, MemoryProjectionRecord,
    MemoryRole, MemoryScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard ceiling on advisory cue-hit handles carried by one request.
pub const MAX_CUE_HITS: usize = 512;

/// Evaluation failure for a task-local applicability request.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ApplicabilityError {
    /// The supplied batch or request shape is invalid.
    #[error("memory projection: {0}")]
    Projection(#[from] MemoryProjectionError),
    /// A required request field is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field that failed validation.
        field: &'static str,
        /// Short machine-stable rule description.
        reason: &'static str,
    },
    /// A cue-hit handle appears twice.
    #[error("cue_hits contains duplicate value {value}")]
    DuplicateCueHit {
        /// Duplicated handle text.
        value: String,
    },
    /// The batch denominator is unknown: applicability without a
    /// denominator is unprovable, so evaluation fails closed instead of
    /// guessing a complete verdict.
    #[error("cannot evaluate applicability without a known denominator")]
    MissingDenominator,
}

/// Task-local applicability request over one bounded projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityRequest {
    /// Bounded projection to evaluate; the entire denominator.
    pub batch: MemoryProjectionBatch,
    /// Exact-match key for negative-memory triggers (task/action identity).
    pub task_key: String,
    /// Advisory cue-hit handles; flags only, never proof.
    pub cue_hits: Vec<ArtifactId>,
}

impl ApplicabilityRequest {
    /// Validate batch shape, task key, and cue-hit bounds.
    pub fn validate(&self) -> Result<(), ApplicabilityError> {
        self.batch.validate()?;
        if self.task_key.trim().is_empty() || self.task_key.chars().any(char::is_control) {
            return Err(ApplicabilityError::InvalidField {
                field: "request.task_key",
                reason: "must be non-blank and free of control characters",
            });
        }
        if self.cue_hits.len() > MAX_CUE_HITS {
            return Err(ApplicabilityError::InvalidField {
                field: "request.cue_hits",
                reason: "exceeds the advisory bound",
            });
        }
        let mut seen = BTreeSet::new();
        for handle in &self.cue_hits {
            if !seen.insert(handle.as_str().to_owned()) {
                return Err(ApplicabilityError::DuplicateCueHit {
                    value: handle.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Shared evaluation context: the batch binding plus the task key.
struct EvalContext<'a> {
    binding: &'a MemoryScopeBinding,
    task_key: &'a str,
}

/// Decide the exclusion reason for one record, or `None` when applicable.
///
/// Fixed rule order (first match wins): scope equality, fence
/// compatibility, active lifecycle, freshness, epistemic standing,
/// protected role, exact negative-trigger match, owner-assessed
/// preconditions.
fn classify(record: &MemoryProjectionRecord, context: &EvalContext<'_>) -> Option<ExclusionReason> {
    if record.binding.task_id != context.binding.task_id
        || record.binding.scope_id != context.binding.scope_id
        || record.binding.session_id != context.binding.session_id
    {
        return Some(ExclusionReason::ScopeMismatch);
    }
    if !record
        .state_fence
        .is_compatible_with(&context.binding.state_fence)
    {
        return Some(ExclusionReason::FenceMismatch);
    }
    if !record.lifecycle.is_active() {
        return Some(ExclusionReason::LifecycleInactive);
    }
    if matches!(record.freshness.state, FreshnessState::Stale) {
        return Some(ExclusionReason::Stale);
    }
    if matches!(record.freshness.state, FreshnessState::Unknown) {
        return Some(ExclusionReason::EpistemicallyUnknown);
    }
    if let Some(reason) = classify_epistemic(record) {
        return Some(reason);
    }
    if record.roles.contains(&MemoryRole::Protected) {
        return Some(ExclusionReason::Protected);
    }
    if record
        .negative_trigger
        .as_ref()
        .is_some_and(|trigger| trigger.trigger == context.task_key)
    {
        return Some(ExclusionReason::NegativeMemory);
    }
    classify_preconditions(record)
}

/// Map the epistemic standing to an exclusion, or `None` when it passes.
///
/// `Superseded` maps to `Stale`: the record is retained as history but is
/// not current for this task. The match is exhaustive on purpose: a new
/// source status must receive a conscious mapping here, never a silent
/// default.
fn classify_epistemic(record: &MemoryProjectionRecord) -> Option<ExclusionReason> {
    match record.epistemic {
        EpistemicStatus::Observed | EpistemicStatus::Supported | EpistemicStatus::Verified => None,
        EpistemicStatus::Contested => Some(ExclusionReason::Conflicted),
        EpistemicStatus::Rejected => Some(ExclusionReason::Rejected),
        EpistemicStatus::Stale | EpistemicStatus::Superseded => Some(ExclusionReason::Stale),
        EpistemicStatus::Unknown => Some(ExclusionReason::EpistemicallyUnknown),
    }
}

/// Map owner-assessed preconditions to an exclusion, or `None` when all pass.
///
/// The first `false` assessment wins over unassessed entries so the exact
/// failed gate is named. Any unassessed gate fails closed: Smart cannot
/// assess a procedure gate it cannot observe.
fn classify_preconditions(record: &MemoryProjectionRecord) -> Option<ExclusionReason> {
    let mut unassessed: Option<&str> = None;
    for precondition in &record.preconditions {
        match precondition.satisfied {
            Some(false) => {
                return Some(ExclusionReason::PreconditionFailed {
                    id: precondition.id.clone(),
                });
            }
            None => {
                if unassessed.is_none() {
                    unassessed = Some(precondition.id.as_str());
                }
            }
            Some(true) => {}
        }
    }
    unassessed.map(|id| ExclusionReason::PreconditionUnassessed { id: id.to_owned() })
}

/// Evaluate task-local applicability over one bounded projection.
///
/// The batch is validated, a known denominator is required, and every
/// record receives either an applicable slot (roles preserved, cue flag
/// noted) or an exclusion with its exact substantive rule.
pub fn evaluate_applicability(
    request: &ApplicabilityRequest,
) -> Result<ApplicableMemorySet, ApplicabilityError> {
    request.validate()?;
    if matches!(
        request.batch.coverage.denominator,
        DenominatorState::Unknown { .. }
    ) {
        return Err(ApplicabilityError::MissingDenominator);
    }
    let cue_hits: BTreeSet<&str> = request.cue_hits.iter().map(ArtifactId::as_str).collect();
    let context = EvalContext {
        binding: &request.batch.binding,
        task_key: request.task_key.as_str(),
    };
    let mut applicable = Vec::new();
    let mut excluded = Vec::new();
    for record in &request.batch.records {
        let cue_hit = cue_hits.contains(record.handle.as_str());
        match classify(record, &context) {
            None => applicable.push(ApplicableMemory {
                handle: record.handle.clone(),
                kind: record.kind,
                roles: record.roles.clone(),
                cue_hit,
            }),
            Some(reason) => excluded.push(ExcludedMemory {
                handle: record.handle.clone(),
                kind: record.kind,
                reason,
                cue_hit,
            }),
        }
    }
    let set = ApplicableMemorySet {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: request.batch.binding.clone(),
        applicable,
        excluded,
        denominator: request.batch.coverage.denominator.clone(),
        truncated: request.batch.coverage.truncated,
        revalidation_required: request.batch.coverage.revalidation_required,
        cue_hits_considered: request.cue_hits.len(),
    };
    set.validate()?;
    Ok(set)
}
