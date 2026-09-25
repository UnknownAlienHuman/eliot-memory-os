//! Reachable Meta-owned intake: real evidence to owner-actionable brief.
//!
//! Implements pipeline I12.24:59-72 of
//! `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`:
//! real evidence -> durable deduplicated candidate -> owner-actionable brief,
//! with class boundaries and budget gates enforced before backlog mutation.
//! This module performs no promotion and no activation; it only validates,
//! binds the safe boundary, gates, and admits into the bounded backlog.
//!
//! Two intake entries share one set of pre-admission gates:
//!
//! - [`intake_from_evidence`] is the registry-only entry: the surface bound
//!   is enforced by the backlog, and a full bound surfaces `BoundExceeded`
//!   for its caller to resolve.
//! - [`intake_from_evidence_governed`] is the owner-verified entry. It
//!   confirms the bound policy's owning authority against a Governor
//!   issuance, resolves the campaign's retrieval material from the backlog's
//!   owner-retained registry instead of from caller strings, and admits
//!   through the pressure-reporting path so a full bound performs and
//!   RETURNS the summarized archive transition. What is and is not atomic:
//!   every pre-admission gate refuses before anything is written, and the
//!   lineage-merge path validates the merged entry before it writes it, so a
//!   refusal from either leaves the backlog untouched. Bound relief is the
//!   one deliberate exception: it retires entries one at a time, so a
//!   failure part-way through leaves a partially relieved backlog — a state
//!   that stays observable because [`PressureAdmissionError::ReliefFailed`]
//!   carries the receipts produced so far, and a caller that drops them is
//!   discarding durable history rather than seeing an empty receipt list.
//!
//! Neither entry persists anything: the archive receipts and the owner-bound
//! overlay travel back in the returned outcome so the owning lane can make
//! the evidence durable. I12.24:293 requires raw evidence to be durable and
//! backlog/archive history not to stay process-local, so no receipt is
//! dropped inside this crate.

use crate::application_class::{ChangeDescriptor, check_class_gate, classify};
use crate::brief::{ImprovementBrief, SafeBoundary, brief_at_safe_boundary};
use crate::budget_proof::{BudgetProof, require_matched_budget_for_promotion};
use crate::candidate_bounds::{
    AdmitOutcome, ArchivedCandidate, BoundedBacklog, BoundsError, GovernedOverlay,
    PressureAdmissionError,
};
use crate::evidence_sources::{SourcedEvidence, candidate_from_evidence};
use crate::{ImprovementError, ImprovementSurface, ReplayPlan};
use eliot_governor::VerifiedLearningAdmission;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;

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

/// Outcome of the owner-verified intake entry.
///
/// `archived` is durable review history, not diagnostics: when the surface
/// bound was already full the bound-failure path performed an explicit
/// summarized archive transition, and these are its receipts. The caller
/// must persist them alongside the backlog.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GovernedIntakeOutcome {
    pub intake: IntakeOutcome,
    /// Archive receipts produced while relieving the surface bound. Empty
    /// when no relief was needed.
    pub archived: Vec<ArchivedCandidate>,
    /// The campaign's live local overlay, resolved from the backlog's
    /// owner-retained registry under the admitting permit. `None` only when
    /// the permit binds no overlay subject at all.
    pub bound_overlay: Option<GovernedOverlay>,
}

/// Fail-closed refusals of [`intake_from_evidence_governed`].
///
/// Every variant carries a typed source. No refusal is flattened into a
/// display string, and a caller cannot mistake one refusal for another.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum GovernedIntakeError {
    /// A pre-admission gate refused: candidate construction, the
    /// safe-boundary brief, the application class gate, or the matched
    /// budget-equivalence proof. The backlog was not touched.
    #[error("intake gate refused the request: {0}")]
    Gate(#[from] ImprovementError),
    /// The bounded backlog refused the admission, or its bound relief
    /// failed. [`PressureAdmissionError::into_parts`] yields any archive
    /// receipts the failed call already produced, so a partial lifecycle
    /// transition cannot discard its own history.
    #[error("bounded backlog refused the governed intake: {0}")]
    Backlog(#[from] PressureAdmissionError),
    /// A bounded-candidate gate refused: the surface bound policy is absent
    /// or its owning authority is not the one the permit authenticates, or
    /// the owner-retained overlay material for this permit is missing,
    /// re-issued, fence-drifted, foreign, expired or otherwise not live.
    #[error("bounded candidate gate refused the governed intake: {0}")]
    Bounds(#[from] BoundsError),
}

/// Candidate and brief prepared by the shared pre-admission gates, plus the
/// owner-assessed backlog coordinates the admission entries need.
struct PreparedIntake {
    candidate: crate::ImprovementCandidate,
    brief: ImprovementBrief,
    value: f64,
    owner: Option<String>,
}

/// Run the pre-admission intake gates shared by both entries: build the
/// evidence-bound candidate, move it to `Triaged`, produce the
/// owner-actionable brief at the safe boundary, enforce the application-class
/// gate, and require matched budget evidence. Nothing here mutates the
/// backlog.
fn prepare_intake(request: IntakeRequest) -> Result<PreparedIntake, ImprovementError> {
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
        target_surface: candidate.target_surface,
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
        owner,
    })
}

/// Fold a backlog admission outcome into the owner-facing intake outcome.
fn intake_outcome(outcome: AdmitOutcome, brief: ImprovementBrief) -> IntakeOutcome {
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
    }
}

pub fn intake_from_evidence(
    backlog: &mut BoundedBacklog,
    request: IntakeRequest,
) -> Result<IntakeOutcome, ImprovementError> {
    let prepared = prepare_intake(request)?;
    let outcome = backlog
        .admit(prepared.candidate, prepared.value, prepared.owner)
        .map_err(|e| ImprovementError::BacklogRefused(e.to_string()))?;
    Ok(intake_outcome(outcome, prepared.brief))
}

/// Owner-verified intake: bound policy, owner-retained retrieval material,
/// and pressure-reporting admission.
///
/// Order matters and is deliberate:
///
/// 1. the surface bound policy is confirmed against the verified permit, so a
///    surface with no policy — or a policy whose `governor_authority_ref` is
///    not the authority the permit authenticates — is refused before any
///    candidate, brief or brief cost is produced;
/// 2. the campaign's overlay is resolved from the backlog's owner-retained
///    registry under the same permit, so no caller-presented
///    `GovernedOverlay` can stand in for it. A permit that binds no overlay
///    subject has no overlay to resolve and yields `None`; a permit that
///    binds one and has no live retained overlay is refused, which is what
///    keeps a candidate from being admitted into a campaign that could never
///    use it (I12.24:295);
/// 3. the shared pre-admission gates run unchanged;
/// 4. admission goes through
///    [`BoundedBacklog::admit_reporting_pressure`], so a full surface bound
///    performs the explicit summarized archive transition and returns its
///    receipts.
///
/// What atomicity this entry actually has. It is NOT transactional and this
/// doc does not claim it is:
///
/// - Steps 1 to 3 and the backlog's own pre-admission assessment either take
///   the backlog by shared reference or run before it, so every refusal they
///   produce happens before a single field of the backlog is written. No
///   admitted candidate, archive receipt or revision bump can be left behind
///   by them.
/// - The lineage-merge arm mutates only after it has validated the resulting
///   entry: the merge computes the whole post-merge entry to one side,
///   validates it, and writes it back in a single assignment. A refused merge
///   therefore leaves the surviving entry exactly as it was, which is what
///   makes [`PressureAdmissionError::Refused`] safe to report as "nothing was
///   archived, so there are no receipts to persist".
/// - Bound relief is NOT atomic. It archives one entry per freed slot in a
///   loop, so a failure part-way through leaves a PARTIALLY relieved backlog:
///   some entries are retired and the incoming candidate is not admitted. That
///   partial state is deliberate and observable rather than hidden, because
///   [`PressureAdmissionError::ReliefFailed`] carries the
///   [`ArchivedCandidate`] receipts produced before the failure and
///   [`PressureAdmissionError::into_parts`] always hands them to the caller,
///   so a caller cannot mistake a partial relief for an untouched backlog or
///   silently discard the history the partial transition already produced.
///
/// `now` MUST be owner/host-sourced live time read at the call. It is never
/// derived from a requester envelope, a permit epoch or a closure schedule: a
/// backdated stamp would defeat overlay expiry, and I12.24:295 requires
/// expiry to invalidate influence rather than silently retain the last
/// behaviour.
pub fn intake_from_evidence_governed(
    backlog: &mut BoundedBacklog,
    request: IntakeRequest,
    verified: &VerifiedLearningAdmission<'_>,
    now: OffsetDateTime,
) -> Result<GovernedIntakeOutcome, GovernedIntakeError> {
    backlog
        .policy_for(request.target_surface)?
        .validate_governed(verified)?;
    let bound_overlay = match verified.permit().overlay_id() {
        Some(_) => Some(backlog.live_local_overlay(verified, now)?.clone()),
        None => None,
    };
    let prepared = prepare_intake(request)?;
    let report = backlog.admit_reporting_pressure(
        prepared.candidate,
        prepared.value,
        prepared.owner,
        verified,
    )?;
    Ok(GovernedIntakeOutcome {
        intake: intake_outcome(report.outcome, prepared.brief),
        archived: report.archived,
        bound_overlay,
    })
}
