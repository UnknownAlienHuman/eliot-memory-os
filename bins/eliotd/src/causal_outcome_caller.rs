//! Assessed intervention-outcome production caller (issue #1910 W5).
//!
//! Architecture: A6.5 keeps a causal candidate's mechanism, intervention,
//! predicted observable, counterfactual, confounders, interacting causes,
//! temporal lag, abstraction level, rival explanations and transfer boundary
//! as one record, and trust is earned by distinguishing rivals,
//! preregistering an observable, and surviving an intervention, verifier, or
//! real artifact outcome. A successful outcome supports an effect but not
//! necessarily the claimed mechanism.
//!
//! # What this module is
//!
//! [`record_arrived_causal_intervention_outcome`] is the production caller of
//! [`commit_causal_intervention_outcome`](super::improvement_candidate_dispatch::commit_causal_intervention_outcome):
//! it records one arrived, explicitly assessed intervention outcome against
//! its live candidate through the owner's own
//! [`CausalCandidate::record_intervention_outcome`](eliot_types::cognition::CausalCandidate::record_intervention_outcome)
//! transition and the same Governor-owned
//! [`DaemonComposition::commit_learning_record`](crate::DaemonComposition::commit_learning_record)
//! seam every other durable improvement record uses. The state change, the
//! record shape, the key, the scope and the deadline are all the writer's:
//! this module restates none of them and invents no owner, no seam, and no
//! error scheme.
//!
//! # What arrives, and what does not
//!
//! [`ArrivedCausalInterventionOutcome`] bundles the live candidate with the
//! explicitly assessed outcome recorded against it. Both halves arrive
//! together from the producer — the verification-dispatcher completion leg,
//! once it holds a live candidate — and this caller constructs neither: a
//! candidate assembled here would be a fabricated mechanism, and an
//! assessment assembled here would be a forged outcome. The owner refuses
//! anything whose before state disagrees with the candidate, whose assessment
//! is incomplete, or that drops a documented rival without
//! `rival_update_evidence`, so the three edge statuses stay three distinct
//! values chosen only by explicit assessment, rivals are retained, and
//! calibration and transfer boundary are updated, never overwritten.
//!
//! # What this module is NOT
//!
//! It carries no permit, no authority and no activation: recording an outcome
//! never promotes a status by itself. It reads no store scope and projects no
//! view — the inspector and Active View readers (issue #1910 W6/A1/A2) are
//! follow-ups, not this slice. Reporting stays with the invoking run-loop
//! step under the same diagnostic discipline as the other record steps: an
//! owner refusal crosses as [`ImprovementDispatchError::Contract`], a commit
//! refusal as [`ImprovementDispatchError::Commit`].

use eliot_contracts::StateFence;
use eliot_store_api::WriteReceipt;
use eliot_types::cognition::{CausalCandidate, CausalInterventionOutcomeRecord};

use super::DaemonComposition;
use super::improvement_intake_dispatch::ImprovementDispatchError;

/// One arrived, explicitly assessed intervention outcome with the live
/// candidate it was assessed against.
///
/// Both halves arrive together from the producer and travel together into
/// the writer: the outcome's before state must match this candidate's
/// current edge status, rival set, calibration and transfer boundary, or the
/// owner refuses the whole call and nothing is written. The caller that
/// invokes [`record_arrived_causal_intervention_outcome`] retains the
/// returned updated candidate beside the receipt, so it holds exactly what
/// was committed with no second construction to drift from it.
#[derive(Clone, Debug)]
pub struct ArrivedCausalInterventionOutcome {
    /// The live candidate the outcome was assessed against.
    pub candidate: CausalCandidate,
    /// The explicitly assessed outcome, with full before/after state and
    /// assessment basis.
    pub outcome: CausalInterventionOutcomeRecord,
}

/// Records one arrived intervention outcome against its candidate and returns
/// the updated candidate beside the receipt.
///
/// The call is the owner's own transition through the existing writer: the
/// outcome must name this candidate, match its current state, carry a
/// complete assessment, and cite `rival_update_evidence` for any dropped
/// rival — otherwise the typed owner refusal below carries the whole call.
/// On success the candidate carries the outcome's after state with the
/// outcome appended to its append-only history, so statuses stay distinct,
/// rivals are retained, and calibration and transfer boundary are updated,
/// never overwritten.
pub async fn record_arrived_causal_intervention_outcome(
    composition: &mut DaemonComposition,
    arrived: &ArrivedCausalInterventionOutcome,
    state_fence: &StateFence,
) -> Result<(CausalCandidate, WriteReceipt), ImprovementDispatchError> {
    super::improvement_candidate_dispatch::commit_causal_intervention_outcome(
        composition,
        &arrived.candidate,
        arrived.outcome.clone(),
        state_fence,
    )
    .await
}
