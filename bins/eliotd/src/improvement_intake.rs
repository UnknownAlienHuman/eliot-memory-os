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
/// discharged by the call site, not here. The single production caller,
/// [`crate::improvement_intake_dispatch::assemble_improvement_artifact`],
/// records the DAEMON's own triage under its own service identity and says so
/// in the note; it does not name an owner that did not select the disposition,
/// and it documents there why no owner's selection reaches this process today.
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
