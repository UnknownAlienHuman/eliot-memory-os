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
use crate::candidate_bounds::{AdmitOutcome, ArchivedCandidate, BoundedBacklog, BoundsError};
use crate::evidence_sources::{SourcedEvidence, candidate_from_evidence};
use crate::{ImprovementError, ImprovementSurface, ReplayPlan};
use eliot_governor::{LearningAdmissionOwnerRecord, VerifiedLearningAdmission};
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
    /// First explicit archive record produced by the bounded ineligible-entry
    /// sweep; the complete append-only history remains on the backlog.
    pub archived_candidate: Option<ArchivedCandidate>,
}

/// Candidate and brief after all evidence, class, budget, and safe-boundary
/// gates, but before the bounded-backlog mutation.
///
/// Keeping preparation separate lets the daemon ask the existing Governor
/// owner to issue admission for the exact candidate identity. The candidate
/// is not visible to the backlog until that owner-bound permit verifies.
pub struct PreparedIntake {
    candidate: crate::ImprovementCandidate,
    brief: ImprovementBrief,
    value: f64,
    owner: Option<String>,
    authority_ref: Option<String>,
    rollback_ref: Option<String>,
}

impl PreparedIntake {
    /// Exact candidate identity that a Governor request must bind.
    #[must_use]
    pub fn candidate_id(&self) -> &str {
        &self.candidate.candidate_id
    }

    /// Read-only candidate projection for owner-side admission preparation.
    #[must_use]
    pub const fn candidate(&self) -> &crate::ImprovementCandidate {
        &self.candidate
    }

    /// Read-only owner-facing brief projection.
    #[must_use]
    pub const fn brief(&self) -> &ImprovementBrief {
        &self.brief
    }
}

/// Archive every already-ineligible active entry on a surface.
///
/// This is deliberately limited to evidence already owned by the candidate
/// record: an explicit stale lifecycle, an absent normalized owner, or a value
/// below the existing surface policy floor. A full bound never silently
/// evicts an owned, high-value candidate. The complete append-only history is
/// retained by the backlog; the intake outcome exposes the first record for
/// bounded, one-event logging.
fn archive_capacity_candidate(
    backlog: &mut BoundedBacklog,
    surface: ImprovementSurface,
) -> Result<Vec<ArchivedCandidate>, BoundsError> {
    backlog.archive_ineligible(surface)
}

/// Prepare one intake request without mutating the backlog.
///
/// All owner-facing and replay-safety gates run here. The returned candidate
/// identity is the subject the caller must present to the Governor owner for
/// admission; a caller cannot substitute a different identity after this
/// point without failing the governed admission path.
pub fn prepare_intake(request: IntakeRequest) -> Result<PreparedIntake, ImprovementError> {
    prepare_intake_with_owner(request, None)
}

/// Prepare one intake request using the Governor's current owner projection.
///
/// The request's caller-supplied owner and rollback strings are not allowed to
/// authorize the intake. They are replaced with the owner-issued authority and
/// rollback refs before candidate construction and the class gate run. The
/// resulting [`PreparedIntake`] carries those refs so the final owner-verified
/// permit must still match the exact projection used for preparation.
pub fn prepare_intake_for_owner(
    request: IntakeRequest,
    owner: &LearningAdmissionOwnerRecord,
) -> Result<PreparedIntake, ImprovementError> {
    prepare_intake_with_owner(request, Some(owner))
}

fn prepare_intake_with_owner(
    mut request: IntakeRequest,
    owner_projection: Option<&LearningAdmissionOwnerRecord>,
) -> Result<PreparedIntake, ImprovementError> {
    if let Some(owner) = owner_projection {
        request.owner = Some(owner.authority_ref().to_owned());
        request.rollback = owner.rollback_ref().to_owned();
        request.evidence.owner_and_decision_authority = owner.authority_ref().to_owned();
    }
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
        owner: request_owner,
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
    // Admitted intake is triaged for owner review. This transition is
    // candidate preparation, not promotion or activation.
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
    Ok(PreparedIntake {
        candidate,
        brief,
        value,
        owner: request_owner,
        authority_ref: owner_projection.map(|owner| owner.authority_ref().to_owned()),
        rollback_ref: owner_projection.map(|owner| owner.rollback_ref().to_owned()),
    })
}

/// Admit a prepared request through the legacy registry primitive.
///
/// This remains available for offline evidence preparation and existing
/// callers that have not yet supplied owner evidence. Production daemon
/// intake uses [`intake_from_evidence_governed`] instead.
pub fn intake_from_evidence(
    backlog: &mut BoundedBacklog,
    request: IntakeRequest,
) -> Result<IntakeOutcome, ImprovementError> {
    let prepared = prepare_intake(request)?;
    admit_prepared_intake(backlog, prepared)
}

/// Admit a prepared request with an owner-verified Governor permit.
///
/// The permit must name the exact prepared candidate. The candidate's
/// owner is replaced by the permit-bound authority; a caller-supplied owner
/// string can therefore never authorize admission or archival.
pub fn intake_from_evidence_governed(
    backlog: &mut BoundedBacklog,
    prepared: PreparedIntake,
    verified: &VerifiedLearningAdmission<'_>,
) -> Result<IntakeOutcome, ImprovementError> {
    let permit = verified.permit();
    if permit.candidate_id() != Some(prepared.candidate_id()) {
        return Err(ImprovementError::BacklogRefused(
            "Governor permit does not bind the prepared improvement candidate".to_owned(),
        ));
    }
    let owner_binding_matches = match (
        prepared.authority_ref.as_deref(),
        prepared.rollback_ref.as_deref(),
    ) {
        (Some(authority_ref), Some(rollback_ref)) => {
            authority_ref == permit.authority_ref() && rollback_ref == permit.rollback_ref()
        }
        // A legacy prepared value may be admitted only when its already
        // materialized candidate carries the exact owner and rollback refs;
        // caller labels still cannot authorize a different binding.
        _ => {
            prepared.candidate.owner_and_decision_authority == permit.authority_ref()
                && prepared.candidate.rollback == permit.rollback_ref()
        }
    };
    if !owner_binding_matches {
        return Err(ImprovementError::BacklogRefused(
            "prepared intake does not carry the owner-bound authority and rollback refs".to_owned(),
        ));
    }
    let authority = permit.authority_ref().to_owned();
    let target_surface = prepared.candidate.target_surface;
    let mut archived_candidates = archive_capacity_candidate(backlog, target_surface)
        .map_err(|archive_error| ImprovementError::BacklogRefused(archive_error.to_string()))?;
    let initial_archive_count = archived_candidates.len();
    let outcome = match backlog.admit_governed(
        prepared.candidate.clone(),
        prepared.value,
        Some(authority),
        verified,
    ) {
        Ok(outcome) => outcome,
        Err(error @ BoundsError::BoundExceeded { .. }) => {
            let additional =
                archive_capacity_candidate(backlog, target_surface).map_err(|archive_error| {
                    ImprovementError::BacklogRefused(archive_error.to_string())
                })?;
            if initial_archive_count == 0 && additional.is_empty() {
                return Err(ImprovementError::BacklogRefused(error.to_string()));
            }
            archived_candidates.extend(additional);
            retry_governed_admission(backlog, &prepared, verified)
                .map_err(|retry_error| ImprovementError::BacklogRefused(retry_error.to_string()))?
        }
        Err(error) => {
            return Err(ImprovementError::BacklogRefused(error.to_string()));
        }
    };
    Ok(finish_intake_outcome(
        outcome,
        prepared.brief,
        archived_candidates.into_iter().next(),
    ))
}

/// Mutate the backlog through the registry primitive after preparation.
pub fn admit_prepared_intake(
    backlog: &mut BoundedBacklog,
    prepared: PreparedIntake,
) -> Result<IntakeOutcome, ImprovementError> {
    let target_surface = prepared.candidate.target_surface;
    let mut archived_candidates = archive_capacity_candidate(backlog, target_surface)
        .map_err(|archive_error| ImprovementError::BacklogRefused(archive_error.to_string()))?;
    let initial_archive_count = archived_candidates.len();
    let outcome = match backlog.admit(
        prepared.candidate.clone(),
        prepared.value,
        prepared.owner.clone(),
    ) {
        Ok(outcome) => outcome,
        Err(error @ BoundsError::BoundExceeded { .. }) => {
            let additional =
                archive_capacity_candidate(backlog, target_surface).map_err(|archive_error| {
                    ImprovementError::BacklogRefused(archive_error.to_string())
                })?;
            if initial_archive_count == 0 && additional.is_empty() {
                return Err(ImprovementError::BacklogRefused(error.to_string()));
            }
            archived_candidates.extend(additional);
            backlog
                .admit(
                    prepared.candidate.clone(),
                    prepared.value,
                    prepared.owner.clone(),
                )
                .map_err(|retry_error| ImprovementError::BacklogRefused(retry_error.to_string()))?
        }
        Err(error) => {
            return Err(ImprovementError::BacklogRefused(error.to_string()));
        }
    };
    Ok(finish_intake_outcome(
        outcome,
        prepared.brief,
        archived_candidates.into_iter().next(),
    ))
}

fn retry_governed_admission(
    backlog: &mut BoundedBacklog,
    prepared: &PreparedIntake,
    verified: &VerifiedLearningAdmission<'_>,
) -> Result<AdmitOutcome, BoundsError> {
    backlog.admit_governed(
        prepared.candidate.clone(),
        prepared.value,
        Some(verified.permit().authority_ref().to_owned()),
        verified,
    )
}

fn finish_intake_outcome(
    outcome: AdmitOutcome,
    brief: ImprovementBrief,
    archived_candidate: Option<ArchivedCandidate>,
) -> IntakeOutcome {
    let (candidate_id, admitted, merged_into) = match outcome {
        AdmitOutcome::Admitted { candidate_id } => (candidate_id, true, None),
        AdmitOutcome::Merged {
            surviving_candidate_id,
            absorbed_candidate_id,
        } => (absorbed_candidate_id, false, Some(surviving_candidate_id)),
    };
    IntakeOutcome {
        candidate_id,
        admitted,
        merged_into,
        brief,
        archived_candidate,
    }
}
