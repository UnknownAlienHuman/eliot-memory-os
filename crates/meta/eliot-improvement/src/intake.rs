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
use crate::candidate_bounds::{AdmitOutcome, BoundedBacklog};
use crate::evidence_sources::{SourcedEvidence, candidate_from_evidence};
use crate::{ImprovementError, ImprovementSurface, ReplayPlan};
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
    let outcome = backlog
        .admit(candidate, value, owner)
        .map_err(|e| ImprovementError::BacklogRefused(e.to_string()))?;
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
    })
}
