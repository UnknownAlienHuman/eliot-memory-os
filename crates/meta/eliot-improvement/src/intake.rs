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
//!   issuance, BINDS the campaign owner's retained overlay and reusable
//!   material into the backlog's owner-retained registries under that same
//!   permit, RESOLVES every influence subject back out of those registries
//!   instead of from caller strings, and admits through the
//!   pressure-reporting path so a full bound performs and RETURNS the
//!   summarized archive transition. Binding and resolving on one
//!   owner-verified path is what makes the registries load-bearing: a permit
//!   that binds an influence subject with no live retained record is refused
//!   instead of served from the request. What is and is not atomic:
//!   every pre-admission gate refuses before any candidate entry is written,
//!   and the lineage-merge path validates the merged entry before it writes
//!   it, so a refusal from either leaves the backlog's entries untouched. The
//!   owner-retained bindings are the one step that can be half-done, and a
//!   half-written binding is re-checked against the same permit on every
//!   later read. Bound relief is the other deliberate exception: it retires
//!   entries one at a time, so a failure part-way through leaves a partially
//!   relieved backlog — a state that stays observable because
//!   [`PressureAdmissionError::ReliefFailed`] carries the receipts produced
//!   so far, and a caller that drops them is discarding durable history
//!   rather than seeing an empty receipt list.
//!
//! Neither entry persists anything: the archive receipts and the owner-bound
//! overlay / reusable material travel back in the returned outcome so the
//! owning lane can make the evidence durable. I12.24:293 requires raw evidence
//! to be durable and backlog/archive history not to stay process-local, so no
//! receipt is dropped inside this crate.

use crate::application_class::{ChangeDescriptor, check_class_gate, classify};
use crate::brief::{ImprovementBrief, SafeBoundary, brief_at_safe_boundary};
use crate::budget_proof::{BudgetProof, require_matched_budget_for_promotion};
use crate::candidate_bounds::{
    AdmitOutcome, ArchivedCandidate, BoundedBacklog, BoundsError, GovernedOverlay,
    PressureAdmissionError, ReusableCandidateRef,
};
use crate::evidence_sources::{SourcedEvidence, candidate_from_evidence};
use crate::{ImprovementError, ImprovementSurface, ReplayPlan};
use eliot_governor::VerifiedLearningAdmission;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;

/// The campaign owner's RETAINED learning material for one governed intake.
///
/// This is the owner-side record of what the campaign keeps, not a requester's
/// assertion about what the campaign may use. It is the input the intake path
/// writes into the backlog's owner-retained registries under the admitting
/// permit, and everything the intake then resolves comes back OUT of those
/// registries rather than out of this value.
///
/// It is deliberately not authority, and nothing here is accepted on trust:
///
/// - `local_overlay` is cross-checked field-by-field against the verified
///   permit by [`BoundedBacklog::bind_local_overlay`], and its `admission_ref`
///   must equal `permit.digest()`. A caller that presents material for another
///   campaign, task, fence or overlay is refused, and a caller that presents
///   an overlay when the permit admits none is refused too.
/// - `reusable_closure` supplies the candidate subject and the closure handle;
///   the ORIGIN CAMPAIGN is not taken from here at all, because
///   [`BoundedBacklog::bind_reusable_candidate`] derives it from
///   `permit.source_campaign_id()`. The candidate's OWNER is likewise copied
///   from the retained backlog entry, never from this request.
///
/// Both fields are `Option` because "the campaign retains no such record" is a
/// real state, and the intake must not invent one to satisfy a permit. A
/// `None` where the permit binds that influence subject is a refusal, not a
/// fallback: it is exactly the case where a candidate must not be admitted
/// into a campaign that could never use it (I12.24:295).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RetainedCampaignLearning {
    /// The campaign's retained task-local overlay record, when the campaign
    /// retains one.
    pub local_overlay: Option<GovernedOverlay>,
    /// The campaign's retained reusable-candidate closure material, when the
    /// campaign retains one.
    pub reusable_closure: Option<RetainedReusableClosure>,
}

/// The campaign owner's retained closure material for one reusable candidate.
///
/// `closure_ref` is the owner-DECLARED closure disposition handle. The
/// verified permit exposes no closure ref, so
/// [`BoundedBacklog::bind_reusable_candidate`] presence-checks it only and a
/// consumer must not read the stored handle as an owner-issued disposition
/// handle. `candidate_id` must equal the permit's bound subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedReusableClosure {
    pub candidate_id: String,
    pub closure_ref: String,
}

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
    /// The campaign's reusable-candidate material, resolved from the backlog's
    /// owner-retained registry under the admitting permit. `None` only when
    /// the permit binds no reusable candidate subject at all.
    pub bound_reusable: Option<ReusableCandidateRef>,
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
    /// the owner-retained overlay / reusable-candidate material for this
    /// permit is missing, re-issued, fence-drifted, foreign, expired or
    /// otherwise not live.
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

/// Write the campaign owner's retained learning material into the backlog's
/// owner-retained registries, under the same owner-verified permit that will
/// read it back.
///
/// This is the owner-side binding step. It runs on the admission path in this
/// crate, so `bound_overlays` and `bound_reusables` are written and read by
/// one owner-verified path instead of staying permanently empty.
///
/// The permit is the authority, not the request:
///
/// - the retained overlay's overlay id, campaign id, task id and State Fence
///   must equal the permit's own values, and its `admission_ref` must equal
///   `permit.digest()`. Anything else is refused with the matching typed
///   [`BoundsError`] and nothing is written;
/// - the reusable binding's candidate subject must equal the permit's, its
///   ORIGIN CAMPAIGN is DERIVED from `permit.source_campaign_id()` rather than
///   taken from the request, the candidate must still be an active backlog
///   entry admitted under the permit's authority, and its OWNER is copied from
///   that retained entry. An unclosed or ownerless candidate is refused.
///
/// The order is overlay first, then reusable: neither binding reads or writes
/// the other, and both precede the resolution below, so a refusal here leaves
/// no candidate admitted into a campaign whose retained material is not there.
///
/// Mutating only `bound_overlays` / `bound_reusables`. When it refuses, the
/// only possible change is a binding written before the refusal, which the
/// next resolution re-checks; no entry, revision or archive receipt is
/// touched, so [`GovernedIntakeError::Bounds`] stays truthful.
fn bind_retained_learning_material(
    backlog: &mut BoundedBacklog,
    retained: &RetainedCampaignLearning,
    verified: &VerifiedLearningAdmission<'_>,
) -> Result<(), BoundsError> {
    let permit = verified.permit();
    if let Some(overlay) = &retained.local_overlay {
        backlog.bind_local_overlay(overlay.clone(), verified)?;
    }
    if let Some(closure) = &retained.reusable_closure {
        backlog.bind_reusable_candidate(
            &closure.candidate_id,
            &closure.closure_ref,
            permit.source_campaign_id(),
            verified,
        )?;
    }
    Ok(())
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
/// 2. the campaign owner's retained material is BOUND into the backlog's
///    owner-retained registries under that same permit by
///    `bind_retained_learning_material`;
/// 3. the campaign's influence subjects are RESOLVED back out of those
///    registries — never out of the request — so no caller-presented
///    `GovernedOverlay` or reusable record can stand in for the retained one.
///    A permit that binds an overlay subject has no overlay to resolve and
///    yields `None`; a permit that binds one and has no live retained overlay
///    is refused, which is what keeps a candidate from being admitted into a
///    campaign that could never use it (I12.24:295). The same holds for the
///    reusable candidate subject;
/// 4. the shared pre-admission gates run unchanged;
/// 5. admission goes through
///    [`BoundedBacklog::admit_reporting_pressure`], so a full surface bound
///    performs the explicit summarized archive transition and returns its
///    receipts.
///
/// Steps 1 to 3 take the backlog mutably but write nothing a candidate entry
/// depends on, and step 4 never touches it, so every refusal they produce
/// happens before the admission is attempted. What atomicity this entry
/// actually has is stated below and is not a transaction:
///
/// - Step 2's binding writes only the two owner-retained registries. A
///   refusal in the middle of it can leave the first binding written, and
///   that record is re-checked by the same permit on every later read, so a
///   refused intake cannot hand a caller a usable influence it never earned.
///   No candidate entry, revision bump or archive receipt is affected.
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
    retained: &RetainedCampaignLearning,
    verified: &VerifiedLearningAdmission<'_>,
    now: OffsetDateTime,
) -> Result<GovernedIntakeOutcome, GovernedIntakeError> {
    backlog
        .policy_for(request.target_surface)?
        .validate_governed(verified)?;
    bind_retained_learning_material(backlog, retained, verified)?;
    let bound_overlay = match verified.permit().overlay_id() {
        Some(_) => Some(backlog.live_local_overlay(verified, now)?.clone()),
        None => None,
    };
    let bound_reusable = match verified.permit().candidate_id() {
        Some(candidate_id) => Some(backlog.active_reusable(candidate_id, verified)?.clone()),
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
        bound_reusable,
    })
}
