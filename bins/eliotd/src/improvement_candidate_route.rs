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
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_PIPELINE_OWNER, ImprovementAdmissionPolicy,
    ImprovementCandidateView, ImprovementEvidenceView, ImprovementPipelineInputs,
    ImprovementProposal, RollbackContract, run_improvement_candidate_pipeline,
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
/// Never promotes, activates, or completes; a `CanaryAdmitted` disposition
/// carries only a handoff request for Kernel (`#11`) authorization.
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

/// Returns the Governor maintenance owner identity for the improvement route.
pub fn improvement_route_owner() -> &'static str {
    IMPROVEMENT_PIPELINE_OWNER
}
