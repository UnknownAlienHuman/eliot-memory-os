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
/// discharged by the call site, not here. This bridge forwards the value
/// unchanged and mints, verifies and re-derives nothing, so it can neither
/// strengthen nor weaken whatever principal its caller named.
///
/// The single production caller on this tree is
/// `improvement_intake_dispatch::record_daemon_disposition`, reached from
/// [`crate::improvement_intake_dispatch::assemble_improvement_artifact`]
/// (`improvement_intake_dispatch.rs:871`, calling `:1015`). It names the
/// DAEMON's own service identity ([`crate::SERVICE_NAME`]) as the principal that
/// recorded the disposition and says so in the note; it derives the disposition
/// kind from the Governor maintenance owner's own closed
/// [`eliot_maintenance::AutomationDecision`] rather than spelling it, so the
/// record states which principal chose and whose recorded verdict it chose on.
///
/// What this module deliberately does NOT restate is whether an OWNER's own
/// selection can reach this process. That is a property of the ingress
/// routing, not of this pure forward, it is measured and documented at the
/// caller's own module scope
/// ([`crate::improvement_intake_dispatch`], under "The recorded disposition is
/// the DAEMON's own, and no owner ingress exists" and "The exact missing route,
/// named"), and it changes as those routes are built. Asserting either answer
/// here would make a routing fact a permanent claim of a pure constructor.
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
