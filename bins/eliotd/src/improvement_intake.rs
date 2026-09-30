//! Daemon-side improvement bridge for recording owner decisions and budget proofs.
//!
//! The production candidate/brief intake is owned by
//! [`crate::improvement_intake_dispatch`] and starts from the live Governor
//! maintenance observation. This module does not provide a second intake or
//! backlog-admission path; it forwards decisions and evidence to the existing
//! `eliot-improvement` owner APIs.

use eliot_improvement::{
    BudgetProof, ImprovementBrief, ImprovementError, OutcomeEvidence, OwnerDecision,
    OwnerDecisionKind, record_owner_decision, stamp_outcome_budget,
};
use thiserror::Error;

/// Failures from forwarding an improvement decision or budget proof.
#[derive(Debug, Error)]
pub enum IntakeBridgeError {
    /// The improvement owner refused the decision or budget evidence.
    #[error("improvement intake failed: {0}")]
    Intake(#[from] ImprovementError),
}

/// Record a non-mutating owner decision against an improvement brief.
///
/// `reject` and `investigate` authorize no change; `work_item` and
/// `experiment` route into the normal work-item/canary/rollback flow through
/// the owning lanes. Recording itself mutates nothing.
///
/// # `owner` is the CALLER's claim, and this function proves nothing about it
///
/// [`record_owner_decision`] is a pure record constructor: it checks that
/// `owner` is non-empty and copies it verbatim. It cannot tell a real principal
/// from a fabricated one, so the value's integrity is entirely the caller's,
/// and A12.02:3 — "Identity is not a model's self-declared string" — is
/// discharged by the call site, not here.
///
/// # What the production caller supplies as `owner` TODAY, stated precisely
///
/// This doc previously said the single production caller,
/// [`crate::improvement_intake_dispatch::record_owner_disposition`] (reached
/// from `assemble_improvement_artifact`), "records the DAEMON's own triage under
/// its own service identity". **That is no longer true and the sentence was left
/// behind by the change that made it false.**
///
/// The caller is still this function's only production caller, but the `owner`
/// it presents is no longer the daemon's: it presents
/// `selection.decision_authority()`, which is
/// [`eliot_maintenance::select_non_mutating_disposition`] having COPIED the
/// selecting principal out of the maintenance (`G-19`) owner's own
/// [`eliot_maintenance::ImprovementAdmissionPolicy`] for this exact operation,
/// beside the owner's own recorded
/// [`eliot_maintenance::AutomationDecision`](eliot_maintenance::AutomationDecision)
/// for this observation. This constructor therefore records the OWNER's
/// principal, and [`crate::DaemonComposition`]'s service identity is named
/// nowhere in it.
///
/// Two things that is NOT, and neither is claimed here:
///
/// - it is not a selection over this brief's prose. The owner ruled from its
///   recorded verdict on the family and scope; it never read the brief, and the
///   note says so verbatim;
/// - it is not an operator-PRESENTED disposition. The closed
///   `UserAutomationOperation::DecideImprovementBrief` operation is still
///   refused at both of its ends, so a Human cannot hand a disposition to this
///   process. What exists is an owner-ISSUED decision read from owner state,
///   which is why no owner ingress is claimed here.
///
/// What stays true of this function is only the weaker half: `owner` is still the
/// CALLER's claim, and the integrity of whatever string arrives here is still the
/// caller's to discharge. What changed is that the one production caller now
/// supplies an owner it did not compose.
pub fn record_brief_decision(
    brief: &ImprovementBrief,
    owner: &str,
    kind: OwnerDecisionKind,
    note: &str,
) -> Result<OwnerDecision, IntakeBridgeError> {
    Ok(record_owner_decision(brief, owner, kind, note)?)
}

/// Bind a matched-budget proof onto a promotion-bound outcome.
///
/// Refuses replay-only promotion without a bound budget-equivalence ledger,
/// conclusive complexity-economics delta, affected checks, live
/// matched-budget evidence, and delayed-harm visibility.
pub fn stamp_promotion_budget(
    outcome: &mut OutcomeEvidence,
    proof: &BudgetProof,
) -> Result<(), IntakeBridgeError> {
    Ok(stamp_outcome_budget(outcome, proof)?)
}
