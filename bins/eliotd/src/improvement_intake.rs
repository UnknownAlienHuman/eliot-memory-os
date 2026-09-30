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
/// from a fabricated one, so the value's integrity is entirely the caller's, and
/// A12.02:3 — "Identity is not a model's self-declared string" — is discharged by
/// the call site, not here. There are exactly two production call sites and they
/// discharge it differently, which is why both are named:
///
/// - [`crate::improvement_intake_dispatch::record_daemon_disposition`] records
///   the DAEMON's own triage under its own service identity and says so in the
///   note. That identity is the installed service's own, named by the composition
///   and carried on every request identity this daemon commits.
/// - [`crate::improvement_intake_dispatch::record_claimed_owner_disposition`]
///   records a real OWNER's selection, claimed from the Kernel's bounded
///   owner-decision queue, and its `owner` is the identity the Kernel's
///   front-door Session authenticated and re-proved against `Session.peer` at
///   admission (`bins/eliot-kernel/src/hot_path_runtime.rs::admit_owner_decision`).
///   The integrity of that value is the Kernel's, not this daemon's, and this
///   daemon copies it rather than choosing it.
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
