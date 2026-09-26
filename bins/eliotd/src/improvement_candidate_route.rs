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

use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_PIPELINE_OWNER, ImprovementAdmissionDecision,
    ImprovementAdmissionPolicy, ImprovementCandidateView, ImprovementEvidenceView,
    ImprovementOperation, ImprovementPipelineInputs, ImprovementProposal, ProposalCommitment,
    RollbackContract, assess_improvement_replay, reconcile_unknown_activation,
    run_improvement_candidate_pipeline,
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
/// pipeline joins the inputs, computes exactly one commitment, and carries that
/// commitment into the joined result, so a pre-validation digest computed here
/// could only disagree with the committed one. Never promotes, activates, or
/// completes; a `CanaryAdmitted` disposition carries an inspectable,
/// non-authorizing handoff for Kernel (`#11`) authorization.
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

/// Assesses one current proposal against a retained prior commitment.
///
/// Production caller of [`assess_improvement_replay`]. The retained commitment
/// carries its own domain, encoding revision, and algorithm identity, so a
/// legacy value is never matched as a current commitment. The caller supplies no
/// progress boolean: a new proposal identity, a different digest, or a repeat
/// all establish no progress by themselves, and no unknown external effect is
/// cleared here. Effect retry stays with its own owner.
pub fn assess_improvement_repeat(
    prior: &ProposalCommitment,
    proposal: &ImprovementProposal,
) -> Result<eliot_maintenance::ImprovementReplayAssessment, eliot_maintenance::PipelineError> {
    assess_improvement_replay(prior, proposal)
}

/// Reconciles an unknown external activation outcome without retrying blindly.
///
/// Production caller of [`reconcile_unknown_activation`].
#[must_use]
pub fn reconcile_improvement_unknown(
    prior: &ImprovementAdmissionDecision,
) -> eliot_maintenance::ImprovementTerminalDisposition {
    reconcile_unknown_activation(prior)
}

/// Returns the Governor maintenance owner identity for the improvement route.
pub fn improvement_route_owner() -> &'static str {
    IMPROVEMENT_PIPELINE_OWNER
}
