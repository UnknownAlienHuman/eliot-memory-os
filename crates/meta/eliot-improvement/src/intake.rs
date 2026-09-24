//! Reachable Meta-owned intake: real evidence to owner-actionable brief.
//!
//! Implements pipeline I12.24:59-72 of
//! `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`:
//! real evidence -> durable deduplicated candidate -> owner-actionable brief,
//! with class boundaries and budget gates enforced before backlog mutation.
//! This module performs no promotion and no activation; it only validates,
//! binds the safe boundary, gates, and admits into the bounded backlog.

use crate::application_class::{ChangeDescriptor, check_class_gate, classify};
use crate::brief::{ImprovementBrief, SafeBoundary, brief_at_safe_boundary};
use crate::budget_proof::{BudgetProof, require_matched_budget_for_promotion};
use crate::candidate_bounds::{
    AdmitOutcome, ArchiveCause, ArchivedCandidate, BoundedBacklog, BoundsError,
};
use crate::evidence_sources::{SourcedEvidence, candidate_from_evidence};
use crate::{ImprovementError, ImprovementLifecycle, ImprovementSurface, ReplayPlan};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntakeRequest {
    pub project_id: String,
    pub target_surface: ImprovementSurface,
    pub proposed_change: String,
    pub evidence: SourcedEvidence,
    pub replay_plan: ReplayPlan,
    pub baseline_metrics: BTreeMap<String, f64>,
    pub delivery_target: String,
    pub canary_plan: String,
    pub rollback: String,
    pub stop_condition: String,
    pub value: f64,
    pub owner: Option<String>,
    pub problem: String,
    pub likely_benefit: String,
    pub risk: String,
    pub proposed_owner: String,
    pub cost: String,
    pub next_reversible_step: String,
    pub unknowns: Vec<String>,
    pub boundary: SafeBoundary,
    pub bounded_tuning: bool,
    pub touches_protected: bool,
    pub has_work_item_ref: bool,
    pub live_experiments_on_surface: usize,
    pub work_item_ref: Option<String>,
    pub owner_approved: bool,
    pub migration_proof_ref: Option<String>,
    pub budget_proof: BudgetProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntakeOutcome {
    pub candidate_id: String,
    pub admitted: bool,
    pub merged_into: Option<String>,
    pub brief: ImprovementBrief,
    /// Explicit archive record produced when capacity pressure required
    /// retiring an already-ineligible active candidate before retrying intake.
    pub archived_candidate: Option<ArchivedCandidate>,
}

/// Archive one already-ineligible active entry when the surface is full.
///
/// This is deliberately limited to evidence already owned by the candidate
/// record: an explicit stale lifecycle, an absent normalized owner, or a value
/// below the existing surface policy floor. A full bound never silently
/// evicts an owned, high-value candidate.
fn archive_capacity_candidate(
    backlog: &mut BoundedBacklog,
    surface: ImprovementSurface,
) -> Result<Option<ArchivedCandidate>, BoundsError> {
    let floor = backlog.policy_for(surface)?.min_value;
    let selected = backlog.active_for(surface).into_iter().find_map(|entry| {
        let cause = if entry.candidate.lifecycle == ImprovementLifecycle::Stale {
            ArchiveCause::Stale
        } else if entry.owner.is_none() {
            ArchiveCause::Ownerless
        } else if entry.value < floor {
            ArchiveCause::LowValue
        } else {
            return None;
        };
        Some((entry.candidate.candidate_id.clone(), cause))
    });
    let Some((candidate_id, cause)) = selected else {
        return Ok(None);
    };
    let summary = format!(
        "capacity bound reached; archived {cause:?} candidate {candidate_id} with explicit lifecycle transition"
    );
    backlog.archive(&candidate_id, cause, summary).map(Some)
}

pub fn intake_from_evidence(
    backlog: &mut BoundedBacklog,
    request: IntakeRequest,
) -> Result<IntakeOutcome, ImprovementError> {
    let IntakeRequest {
        project_id,
        target_surface,
        proposed_change,
        evidence,
        replay_plan,
        baseline_metrics,
        delivery_target,
        canary_plan,
        rollback,
        stop_condition,
        value,
        owner,
        problem,
        likely_benefit,
        risk,
        proposed_owner,
        cost,
        next_reversible_step,
        unknowns,
        boundary,
        bounded_tuning,
        touches_protected,
        has_work_item_ref,
        live_experiments_on_surface,
        work_item_ref,
        owner_approved,
        migration_proof_ref,
        budget_proof,
    } = request;
    let mut candidate = candidate_from_evidence(
        &project_id,
        target_surface,
        &proposed_change,
        &evidence,
        replay_plan,
        baseline_metrics,
        &delivery_target,
        &canary_plan,
        &rollback,
        &stop_condition,
    )?;
    // Admitted intake is triaged for owner review: the owner-decision
    // lifecycle leaves Proposed once evidence, brief, class, and budget
    // gates below all pass and the backlog accepts the candidate.
    candidate.transition_lifecycle(crate::ImprovementLifecycle::Triaged)?;
    let brief = brief_at_safe_boundary(
        &candidate,
        &problem,
        &likely_benefit,
        &risk,
        &proposed_owner,
        &cost,
        &next_reversible_step,
        unknowns,
        &boundary,
    )?;
    let change = ChangeDescriptor {
        target_surface,
        bounded_tuning,
        touches_protected,
        has_work_item_ref,
    };
    let class = classify(&change);
    check_class_gate(
        class,
        &change,
        live_experiments_on_surface,
        &rollback,
        work_item_ref.as_deref(),
        owner_approved,
        migration_proof_ref.as_deref(),
    )?;
    require_matched_budget_for_promotion(Some(&budget_proof))?;
    let (outcome, archived_candidate) = match backlog.admit(candidate.clone(), value, owner.clone())
    {
        Ok(outcome) => (outcome, None),
        Err(error @ BoundsError::BoundExceeded { .. }) => {
            let archived =
                archive_capacity_candidate(backlog, target_surface).map_err(|archive_error| {
                    ImprovementError::BacklogRefused(archive_error.to_string())
                })?;
            if archived.is_none() {
                return Err(ImprovementError::BacklogRefused(error.to_string()));
            }
            let outcome = backlog
                .admit(candidate, value, owner)
                .map_err(|retry_error| ImprovementError::BacklogRefused(retry_error.to_string()))?;
            (outcome, archived)
        }
        Err(error) => {
            return Err(ImprovementError::BacklogRefused(error.to_string()));
        }
    };
    let (candidate_id, admitted, merged_into) = match outcome {
        AdmitOutcome::Admitted { candidate_id } => (candidate_id, true, None),
        AdmitOutcome::Merged {
            surviving_candidate_id,
            absorbed_candidate_id,
        } => (absorbed_candidate_id, false, Some(surviving_candidate_id)),
    };
    Ok(IntakeOutcome {
        candidate_id,
        admitted,
        merged_into,
        brief,
        archived_candidate,
    })
}
