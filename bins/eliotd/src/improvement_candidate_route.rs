//! Production improvement-candidate route: candidate to experiment to evaluation.
//!
//! This module is the production caller of the Governor-owned improvement
//! pipeline (`#1100`, Governor `#18`, Testd `#20`). One improvement candidate
//! flows through bounded experiment to independent evaluation to Governor
//! admission, ending rejected or canary-admitted.
//!
//! Ownership split (handoff only, never executed here):
//! - Testd (`#20`) executes the bounded experiment and measures it;
//! - the Instrument verifier family (`#20`/`#1111`) independently evaluates;
//! - Governor maintenance (`G-19`, `#18`) admits through
//!   `run_improvement_candidate_pipeline` (transitively
//!   `admit_improvement_candidate`);
//! - Kernel generation/canary activation (`#11`) is a handoff request the
//!   Kernel owner must independently authorize and execute.
//!
//! This route is advisory-only: it never promotes, activates, installs,
//! completes, or issues authority. Pure delegation to the Governor owner
//! crate; no state machines, policy semantics, stores, providers,
//! credentials, or repair logic live here.
//!
//! # One checked commitment, never a second one
//!
//! Both consumers here read the record the Governor pipeline committed.
//! [`route_improvement_candidate`] returns the disposition whose canary handoff
//! carries that exact commitment and its discriminator projection, and
//! [`assess_improvement_repeat`] compares a retained prior record against that
//! same checked record. Neither computes a digest, substitutes a fallback, empty,
//! or legacy value, or swallows a failure: a hashing or serialization failure is
//! produced once by the pipeline and crosses into the daemon as the typed
//! `PipelineError` it is.
//!
//! # The consumer checks the producer's version or refuses the record
//!
//! Every consumer of a committed record here verifies that the record carries
//! the identity this daemon's build checks, so a record written under another
//! domain, encoding revision, or algorithm is a typed refusal
//! ([`eliot_maintenance::UncheckedRecordIdentity`]) and never a tolerated
//! value. The recorded digest is validated against the value the producer
//! recorded; it is never recomputed over local state, and no digest,
//! placeholder, or empty string stands in for a record this build cannot
//! read.

use eliot_maintenance::improvement_pipeline::{
    ImprovementCurrentProposal, RetainedImprovementProposal, compare_improvement_commitments,
};
use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_PIPELINE_OWNER, ImprovementAdmissionDecision,
    ImprovementAdmissionPolicy, ImprovementCandidateView, ImprovementEvidenceView,
    ImprovementOperation, ImprovementPipelineInputs, ImprovementProposal, RollbackContract,
    improvement_retry_permitted, reconcile_unknown_activation, run_improvement_candidate_pipeline,
};

/// Borrowed inputs for one production improvement-candidate route call.
///
/// Mirrors [`eliot_maintenance::ImprovementPipelineInputs`] so the production
/// caller forwards the exact borrowed set the Governor pipeline owns, without
/// restating any validation, binding, or admission semantics.
#[derive(Clone, Copy, Debug)]
pub struct ImprovementRouteRequest<'a> {
    /// Governor-side proposal under review.
    pub proposal: &'a ImprovementProposal,
    /// Testd-owned bounded experiment plan.
    pub experiment: &'a ExperimentPlan,
    /// Independent activation evidence for the bound candidate and experiment.
    pub evidence: &'a ActivationEvidence,
    /// Rollback contract named before admission.
    pub rollback: &'a RollbackContract,
    /// Candidate view consumed by Governor admission.
    pub candidate: &'a ImprovementCandidateView,
    /// Independent evidence view consumed by Governor admission.
    pub admission_evidence: &'a ImprovementEvidenceView,
    /// Policy governing Governor admission.
    pub policy: &'a ImprovementAdmissionPolicy,
}

/// Routes one improvement candidate through the Governor-owned pipeline.
///
/// This is the production caller of
/// [`eliot_maintenance::run_improvement_candidate_pipeline`] (and transitively
/// of `admit_improvement_candidate`). Pure thin forwarder: it constructs the
/// Governor-owned [`eliot_maintenance::ImprovementPipelineInputs`] from the
/// borrowed request and returns the advisory-only terminal disposition.
///
/// The route deliberately computes no proposal digest of its own. The checked
/// pipeline joins the inputs, computes exactly one commitment and the
/// discriminator projection of the same bytes, and carries that one record both
/// into the joined result and into the canary handoff, so a pre-validation
/// digest computed here could only disagree with the committed one. A hashing
/// or serialization failure is produced once, by the pipeline, and crosses this
/// boundary as the typed [`eliot_maintenance::PipelineError`] it is: there is no
/// fallback digest, no empty digest, and no legacy value substituted for it.
/// Never promotes, activates, or completes; a `CanaryAdmitted` disposition
/// carries an inspectable, non-authorizing handoff for Kernel (`#11`)
/// authorization.
pub fn route_improvement_candidate(
    request: ImprovementRouteRequest<'_>,
) -> Result<eliot_maintenance::ImprovementTerminalDisposition, eliot_maintenance::PipelineError> {
    run_improvement_candidate_pipeline(ImprovementPipelineInputs {
        proposal: request.proposal,
        experiment: request.experiment,
        evidence: request.evidence,
        rollback: request.rollback,
        candidate: request.candidate,
        admission_evidence: request.admission_evidence,
        policy: request.policy,
    })
}

/// Returns the owning identity for each of the eight distinct pipeline operations.
///
/// Production caller of [`ImprovementOperation::owner`]: Propose/Admit/Promote
/// resolve to Governor maintenance, Execute/Measure to Testd, Evaluate to the
/// independent Instrument verifier, `CanaryActivate` to Kernel (handoff only),
/// and Rollback to the bound rollback-contract owner.
#[must_use]
pub fn improvement_operation_owners(rollback_owner_id: &str) -> [(&'static str, String); 8] {
    [
        (
            ImprovementOperation::Propose.as_str(),
            ImprovementOperation::Propose
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::ExecuteExperiment.as_str(),
            ImprovementOperation::ExecuteExperiment
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Measure.as_str(),
            ImprovementOperation::Measure
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Evaluate.as_str(),
            ImprovementOperation::Evaluate
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Admit.as_str(),
            ImprovementOperation::Admit
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::CanaryActivate.as_str(),
            ImprovementOperation::CanaryActivate
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Promote.as_str(),
            ImprovementOperation::Promote
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Rollback.as_str(),
            ImprovementOperation::Rollback
                .owner(rollback_owner_id)
                .to_string(),
        ),
    ]
}

/// Assesses one retained prior record against the current checked record.
///
/// Production caller of
/// [`eliot_maintenance::improvement_pipeline::compare_improvement_commitments`].
/// Both arguments are records the Governor pipeline already committed: `current`
/// is the exact commitment and discriminator projection the pipeline computed
/// and carried into the canary handoff, and `retained` is the prior record its
/// owner retained. This route commits nothing and hashes nothing, so it can
/// neither substitute a second opinion, an empty digest, nor a legacy value.
///
/// # The consumer uses the producer's checked version, or refuses
///
/// The assessment is derived only when `current` carries the SAME domain,
/// encoding revision, and algorithm this daemon's build checks. A record under
/// any other identity is refused as the typed
/// [`eliot_maintenance::UncheckedRecordIdentity`], which crosses into the
/// daemon as the [`eliot_maintenance::PipelineError`] it wraps rather than
/// becoming a verdict:
/// there is no fallback assessment, no empty or legacy digest standing in for
/// the record, and no digest recomputed over what this process happens to hold.
/// A digest is validated against the ORIGINAL recorded value; it is never
/// recomputed over local state and called a match.
///
/// The caller supplies no progress boolean: a new proposal identity, a different
/// digest, or a repeat all establish no progress by themselves, an absent or
/// non-discriminating retained record establishes nothing, and no unknown
/// external effect is cleared here. Effect retry stays with its own owner.
pub fn assess_improvement_repeat(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> Result<eliot_maintenance::ImprovementReplayAssessment, eliot_maintenance::PipelineError> {
    compare_improvement_commitments(retained, current).map_err(Into::into)
}

/// Preserves an unknown external activation outcome without retrying blindly.
///
/// Production caller of [`reconcile_unknown_activation`]. The prior decision,
/// the checked record this run committed, and the gap-free rollback contract
/// this run was admitted against are all required: the resulting
/// [`eliot_maintenance::ImprovementUnknownEffect`] obligation names the exact
/// candidate, experiment, commitment, owner and forward-repair/invalidation
/// bindings whose external effect is unresolved. No owner-validated effect
/// outcome is consumed here, so the obligation remains unresolved and its
/// retry gate stays closed.
///
/// This route records the unresolved disposition and issues no new attempt.
/// Effect reconciliation and retry stay with the external owners.
///
/// The obligation names the exact commitment this run checked, so `current`
/// must carry this build's checked identity: a record under another domain,
/// encoding revision, or algorithm is refused as the typed
/// [`eliot_maintenance::UncheckedRecordIdentity`] rather than bound into an
/// obligation whose named debt no owner can verify.
pub fn reconcile_improvement_unknown(
    prior: &ImprovementAdmissionDecision,
    current: &ImprovementCurrentProposal,
    rollback: &RollbackContract,
) -> Result<eliot_maintenance::ImprovementTerminalDisposition, eliot_maintenance::PipelineError> {
    reconcile_unknown_activation(prior, current, rollback)
}

/// Returns whether one candidate disposition permits a retry attempt.
///
/// Production caller of [`eliot_maintenance::improvement_retry_permitted`]. The
/// Governor gate it forwards to is exhaustive, so this wrapper inherits a
/// decided answer for every disposition and re-decides none of them here. An
/// unresolved external effect closes the gate because its owner has not settled
/// what happened, and a retained historical completed-rollback value closes it
/// too: the Governor pipeline holds no owner-validated rollback result, so a
/// contract reference alone is not evidence that a rollback completed. A
/// rejection, an inconclusive, a typed regression, a block, an exact repeat, and
/// a bound advisory handoff each leave the gate open because each carries its
/// own owner and remedy, and a fresh attempt is that owner's to make.
#[must_use]
pub fn improvement_candidate_retry_permitted(
    disposition: &eliot_maintenance::ImprovementTerminalDisposition,
) -> bool {
    improvement_retry_permitted(disposition)
}

/// Returns the Governor maintenance owner identity for the improvement route.
pub fn improvement_route_owner() -> &'static str {
    IMPROVEMENT_PIPELINE_OWNER
}
