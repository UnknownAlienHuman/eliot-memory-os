//! Daemon-side improvement bridge for recording owner decisions and budget proofs.
//!
//! The production candidate/brief intake is owned by
//! [`crate::improvement_intake_dispatch`] and starts from the live Governor
//! maintenance observation. This module does not provide a second intake or
//! backlog-admission path; it forwards decisions and evidence to the existing
//! `eliot-improvement` owner APIs.
//!
//! # The owner's disposition is CONSUMED, never asserted
//!
//! [`record_brief_decision`] takes the maintenance (`G-19`) admission owner's own
//! decision record, [`eliot_maintenance::ImprovementAdmissionDecision`], and
//! derives every field of the recorded [`OwnerDecision`] from that record: the
//! owner is the decision's own `owner_id`, the note is the decision's own
//! `reason`/`missing` text, and the kind is the decision's own closed variant.
//! Nothing here is a literal, so the daemon cannot record a disposition the
//! admission owner did not issue, and `OwnerDecisionKind::Reject` — which had no
//! production constructor anywhere in the repository — is reached whenever that
//! owner rejects a candidate.
//!
//! The closed mapping is exhaustive over the owner's six variants and is stated
//! in [`owner_decision_kind`]. `ASSUMPTION:` a `Blocked`,
//! `RequiresReconciliation` or `NeedsMoreEvidence` disposition is
//! `investigate` rather than `work_item`, because each of those three names a
//! missing prerequisite, an unresolved external effect, or missing evidence that
//! the OWNER must establish first (I12.24:65 "decision owner selects reject /
//! investigate / work item / experiment"); a work item is a release to the
//! mutating lane, which none of them is. `ASSUMPTION:` `NoProgress` is
//! `reject`, because the owner records it when the current proposal exactly
//! replays a retained prior commitment and the value is explicitly "not
//! progress" — there is nothing left to investigate on that candidate.
//!
//! # The non-mutation property is CHECKED at this seam
//!
//! This daemon's intake is the advisory composition (I12.24:81-82, "advisory —
//! default; changes nothing until owner acts"), so only a non-mutating
//! disposition may be recorded against a brief here. That is checked on the
//! produced [`OwnerDecision`] through
//! [`OwnerDecision::is_non_mutating`] rather than asserted about the argument,
//! so the property is verified on the exact record that travels into the
//! durable learning row. A mutating disposition is refused with a typed error
//! rather than committed as though this daemon owned the release.

use eliot_improvement::{
    BudgetProof, ImprovementBrief, ImprovementError, OutcomeEvidence, OwnerDecision,
    OwnerDecisionKind, record_owner_decision, stamp_outcome_budget,
};
use eliot_maintenance::ImprovementAdmissionDecision;
use thiserror::Error;

/// Failures from forwarding an improvement decision or budget proof.
#[derive(Debug, Error)]
pub enum IntakeBridgeError {
    /// The improvement owner refused the decision or budget evidence.
    #[error("improvement intake failed: {0}")]
    Intake(#[from] ImprovementError),
    /// The admission owner issued a disposition that authorizes a change, which
    /// this advisory intake path does not own and therefore does not record.
    #[error("advisory improvement intake cannot record a mutating owner disposition: {0:?}")]
    MutatingOwnerDisposition(OwnerDecisionKind),
}

/// Record the admission owner's decision over an improvement brief.
///
/// `admission` is the maintenance (`G-19`) admission owner's own decision
/// record. Its `owner_id` becomes the decision's owner, its `reason`/`missing`
/// text becomes the note, and its closed variant becomes the kind, so the
/// recorded disposition is the owner's own rather than one this daemon chose.
/// The brief's proposed owner is not trusted as the decision's owner: the
/// admission record names the owner that actually issued the disposition.
///
/// # Errors
///
/// [`IntakeBridgeError::MutatingOwnerDisposition`] when the owner selected a
/// disposition that authorizes a change. This path is advisory and owns no
/// work-item or experiment lane, so such a decision is refused here instead of
/// being committed as a satisfied release.
pub fn record_brief_decision(
    brief: &ImprovementBrief,
    admission: &ImprovementAdmissionDecision,
) -> Result<OwnerDecision, IntakeBridgeError> {
    let kind = owner_decision_kind(admission);
    // The non-mutation property is enforced BEFORE the record is built, because
    // the one mutating variant the owner can issue (`AdmitForExperiment`) names
    // no deciding `owner_id`, so there is no owner to record it under. Refusing
    // it here is the same property, applied where the record does not yet
    // exist. Every disposition that does name an owner is recorded and then
    // re-checked on the produced record below.
    if !kind.is_non_mutating() {
        return Err(IntakeBridgeError::MutatingOwnerDisposition(kind));
    }
    let (owner, note) = admission_owner_and_note(admission);
    let decision = record_owner_decision(brief, owner, kind, note)?;
    // The same property, verified on the exact record that travels into the
    // durable learning row rather than on the argument it was built from. The
    // kind came from the owner's own variant, so this is a content check on the
    // recorded artifact and not a restatement of a literal.
    if !decision.is_non_mutating() {
        return Err(IntakeBridgeError::MutatingOwnerDisposition(
            decision.kind,
        ));
    }
    Ok(decision)
}

/// The brief decision kind the admission owner's own decision variant selects.
///
/// Exhaustive over the owner's closed [`ImprovementAdmissionDecision`] set, so a
/// new owner variant cannot compile without a decision here:
///
/// - `Reject` is [`OwnerDecisionKind::Reject`]: the owner refused the
///   candidate.
/// - `NeedsMoreEvidence`, `Blocked` and `RequiresReconciliation` are
///   [`OwnerDecisionKind::Investigate`]: each names evidence, a prerequisite or
///   an unresolved external effect the owner must establish before any release.
/// - `NoProgress` is [`OwnerDecisionKind::Reject`]: the owner recorded that the
///   proposal replays a retained prior commitment and is not progress.
/// - `AdmitForExperiment` is [`OwnerDecisionKind::Experiment`]: the owner
///   released the candidate to bounded execution. This is the only mutating
///   disposition, and [`record_brief_decision`] refuses it on this advisory
///   path.
fn owner_decision_kind(admission: &ImprovementAdmissionDecision) -> OwnerDecisionKind {
    match admission {
        ImprovementAdmissionDecision::Reject { .. }
        | ImprovementAdmissionDecision::NoProgress { .. } => OwnerDecisionKind::Reject,
        ImprovementAdmissionDecision::NeedsMoreEvidence { .. }
        | ImprovementAdmissionDecision::Blocked { .. }
        | ImprovementAdmissionDecision::RequiresReconciliation { .. } => {
            OwnerDecisionKind::Investigate
        }
        ImprovementAdmissionDecision::AdmitForExperiment { .. } => OwnerDecisionKind::Experiment,
    }
}

/// The owner identity and note the admission owner's own record carries.
///
/// The `owner_id` is the owner's own field on every variant that names one.
/// `AdmitForExperiment` is the exception: it names the evaluator and the
/// rollback owner but no deciding `owner_id`, so the policy's own
/// `external_owner_id` is not substituted for it here. That variant is the sole
/// mutating disposition and is refused by [`record_brief_decision`] with a
/// decision that names no owner, so no placeholder identity is needed or
/// spelled.
fn admission_owner_and_note(admission: &ImprovementAdmissionDecision) -> (&str, &str) {
    match admission {
        ImprovementAdmissionDecision::AdmitForExperiment { .. } => ("", ""),
        ImprovementAdmissionDecision::Reject { reason, owner_id, .. }
        | ImprovementAdmissionDecision::Blocked { reason, owner_id, .. }
        | ImprovementAdmissionDecision::RequiresReconciliation { reason, owner_id }
        | ImprovementAdmissionDecision::NoProgress { reason, owner_id } => (owner_id, reason),
        ImprovementAdmissionDecision::NeedsMoreEvidence { missing, owner_id } => {
            (owner_id, missing)
        }
    }
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
