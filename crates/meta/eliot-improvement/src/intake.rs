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
//!
//! # The application class is never an input
//!
//! [`IntakeRequest`] carries no class flag, so the class gate
//! ([`check_class_gate`], I12.24:78-95) cannot be talked into a class by the
//! party presenting the evidence:
//!
//! - `touches_protected` is DERIVED, through the crate's closed
//!   [`is_prohibited_tuning_surface`](crate::application_class::is_prohibited_tuning_surface),
//!   from `candidate.target_surface`. The surface ITSELF is caller-supplied —
//!   `candidate_from_evidence` copies `IntakeRequest.target_surface` verbatim —
//!   so what this entry derives is the class, not the surface;
//! - `bounded_tuning` and `has_work_item_ref` have no parameter to be set
//!   through, because [`ChangeDescriptor::from_recorded_surface`] exposes none;
//! - `work_item_ref` is `None`, `owner_approved` is `false` and
//!   `migration_proof_ref` is `None` because no owner-issued work-item,
//!   owner-decision or migration/proof record exists to read.
//!
//! The resulting class is
//! [`ApplicationClass::Advisory`](crate::ApplicationClass::Advisory) or
//! [`ApplicationClass::Protected`](crate::ApplicationClass::Protected), and a
//! `Protected` one is REFUSED with
//! [`ImprovementError::ApplicationClassViolation`]. That is a typed refusal,
//! not a downgrade: an owner claim is never read as `false` to let a gate pass,
//! and the two evidence-bound classes stay unreachable rather than reachable
//! through an unverifiable flag.
//!
//! ## This entry has NO caller at all (issue #1867 W5)
//!
//! [`intake_from_evidence`] and [`intake_from_evidence_governed`] have no call
//! site anywhere in this repository — not in production, not in this crate's
//! tests, not in any fixture or decoder. Every occurrence of either name is
//! prose, a definition, or the crate root's `pub use`. So `prepare_intake`
//! does not execute today, and EVERY clause of the class gate is unreachable
//! END-TO-END through this module, not merely the two below.
//!
//! That is a wider statement than the two-clause ceiling, and it is recorded
//! here so this module is not read as a running gate. The crate root discloses
//! the same absence in its "No consumer outside this crate, at all" section.
//! The ONE site that does build a descriptor and run [`check_class_gate`] is
//! `bins/eliotd/src/improvement_intake_dispatch.rs`, and it carries the
//! identical class ceiling (see `enforce_advisory_class_gate` there), so no
//! path anywhere in this repository runs the tuning or code/module/config
//! arms.
//!
//! ## What this entry therefore does NOT enforce (issue #1867 W5)
//!
//! Setting the absent caller aside, two clauses of I12.24:78-95 have no
//! reachable class at all, and this module does not claim otherwise:
//!
//! - I12.24:86 "one experiment per control surface, automatic rollback". The
//!   ONE gate arm that reads `live_experiments_on_surface` is the
//!   pre-authorized-tuning arm of [`check_class_gate`]; no descriptor any
//!   constructor in this repository can build selects it, because
//!   [`ChangeDescriptor::from_recorded_surface`] takes no parameter for
//!   `bounded_tuning` or `has_work_item_ref` and those two flags are the ONLY
//!   things that select it. `prepare_intake` therefore passes `0`, and that
//!   value is provably not read. The code/module/config arm never references
//!   the count at all. The surface-concurrency bound that IS enforced here is a
//!   different rule with a different owner:
//!   [`CandidateBoundPolicy::max_active`](crate::candidate_bounds::CandidateBoundPolicy),
//!   applied by [`BoundedBacklog::admit`].
//! - I12.24:90-91, the normal work item with impact tests, immutable candidate,
//!   canary and rollback. No such record exists on `ImprovementCandidate`
//!   (I12.24:20-38) or anywhere else in this repository, so the arm has
//!   nothing to read.
//!
//! The reason is a missing owner record, not a missing check: I12.24:85 admits
//! pre-authorized tuning only "inside a declared safe range", and no declared
//! safe range record exists here to source the flag from. The ceiling is
//! therefore stated rather than papered over — see the
//! `application_class` module header for the measured absence.

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

/// Everything an intake request source supplies, and nothing it may not.
///
/// This type carries NO application-class field at all, and that is the point.
/// Every input the class gate of I12.24:78-95 reads is derived by
/// `prepare_intake` from a record the requester does not author, so no
/// application class can be ASSERTED by the party presenting the evidence:
///
/// - `touches_protected` is a fact about `target_surface`, which the candidate
///   records, and `prepare_intake` derives it through the crate's own
///   [`crate::application_class::is_prohibited_tuning_surface`] rather than
///   reading a caller's claim. A request cannot disagree with the surface it
///   names: there is no field in which to state the disagreement.
/// - `bounded_tuning` — the DECLARED SAFE RANGE of I12.24:85 — and
///   `has_work_item_ref` / `work_item_ref` — the REAL WORK ITEM of
///   I12.24:90-91 — are ALSO gone. Neither exists on `ImprovementCandidate`
///   (I12.24:20-38) or on any other record this crate holds, so a field for
///   either would be a second caller-assertable scheme with no owner-issued
///   record behind it. The descriptor is built by
///   [`ChangeDescriptor::from_recorded_surface`], which exposes no parameter
///   for them precisely because the evidence does not exist, and states the
///   unreachability instead of minting a `true`. The measured absence of both
///   owner records is recorded in the `application_class` module header.
/// - `owner_approved` and `migration_proof_ref` — the EXPLICIT OWNER DECISION
///   and MIGRATION/PROOF of I12.24:93-94 — are gone for the same reason: no
///   owner-issued owner-decision or migration/proof record exists on main that
///   this entry could read. The consequence is a refusal, not a weaker class: a
///   change whose recorded surface is prohibited classifies `Protected` and
///   `check_class_gate` refuses it with
///   [`ImprovementError::ApplicationClassViolation`].
/// - `live_experiments_on_surface` is gone, and `prepare_intake` no longer
///   counts it either: the count is read only by the two class arms that no
///   descriptor here can reach, so counting it would have been an unread
///   computation behind a comment claiming enforcement (issue #1867 W5). The
///   surface-concurrency rule that IS enforced on this path is
///   `CandidateBoundPolicy::max_active`, applied inside
///   [`BoundedBacklog::admit`] and reported by
///   [`BoundedBacklog::admit_reporting_pressure`].
///
/// What remains here is content: the evidence, the brief text, the recorded
/// delivery/canary/rollback/stop condition, the owner-assessed value and owner,
/// and the budget proof. None of it selects an application class.
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
/// gate, and require matched budget evidence. Nothing here touches the backlog.
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
    // `touches_protected` is DERIVED from the recorded surface rather than
    // read from a caller flag, so a request cannot disagree with the surface it
    // names — there is no field in which to state the disagreement:
    //
    // - it is `is_prohibited_tuning_surface` over `candidate.target_surface`,
    //   the crate's closed rule rather than a spelled constant. I12.24:93-94
    //   routes a schema/authority/verifier/privacy/Architecture change onto the
    //   explicit owner decision and migration/proof path, and I12.24:87-88 keeps
    //   a verifier-definition or reserve surface off pre-authorized tuning; a
    //   caller-supplied boolean could under-claim either and route a prohibited
    //   surface into the advisory or tuning class.
    // - `bounded_tuning` and `has_work_item_ref` are not parameters of
    //   `from_recorded_surface` at all, and cannot be: I12.24:85 admits
    //   pre-authorized tuning only inside a declared safe range and the
    //   I12.24:20-38 candidate schema lists none, and I12.24:90 admits
    //   code/module/config delivery as a real work item that I12.24:65 places
    //   after the decision owner's selection. A request that could set either
    //   would be a fabricated `true` with no owner-issued record behind it, so
    //   [`IntakeRequest`] has no field for either and the class they select is
    //   unreachable here rather than assertable.
    //
    // What is derived here is the CLASS, not the surface: `candidate.target_surface`
    // is itself the requester's, copied verbatim from `IntakeRequest` by
    // `candidate_from_evidence`.
    let change = ChangeDescriptor::from_recorded_surface(candidate.target_surface);
    let class = classify(&change);
    // Both non-derived arguments below are honest absences, not enforcement:
    //
    // - `0` is the live-experiment count I12.24:86 asks for. It is NOT read on
    //   this path: the ONE arm that reads it is the pre-authorized-tuning arm,
    //   `classify` cannot return that class from a `from_recorded_surface`
    //   descriptor, and the code/module/config arm never references the count
    //   at all. This is a literal rather than a derived count precisely so no
    //   comment here can claim an enforcement that arm does not perform. The
    //   per-surface concurrency bound that IS enforced is
    //   `CandidateBoundPolicy::max_active`, inside the backlog admission below,
    //   which is a different rule with a different owner and not a substitute
    //   for I12.24:86.
    // - `rollback` is the candidate's own recorded value, i.e. the same string
    //   `candidate_from_evidence` wrote onto it from this request. It is a
    //   caller-AUTHORED reference that `ImprovementCandidate::validate`
    //   requires non-empty and that nothing in this crate resolves (see the
    //   crate root: `canary_plan`, `rollback` and `stop_condition` are
    //   "String REFERENCES ... never resolves them"). It is therefore NOT
    //   evidence that a rollback path exists, and it is not the "automatic
    //   rollback" of I12.24:86 — no rollback is performed, scheduled or proven
    //   here. It is not read on this path either, for the same reason as `0`.
    check_class_gate(class, &change, 0, &rollback, None, false, None)?;
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
