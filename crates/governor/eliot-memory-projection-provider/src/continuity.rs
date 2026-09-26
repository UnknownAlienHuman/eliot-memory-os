//! Governor ingestion gate for continuity evidence (I12.35).
//!
//! [`admit_continuity_for_projection`] enforces the continuity ingestion
//! rules at the Governor projection boundary before any admitted memory
//! observation reaches a record in [`project_batch`](crate::project_batch):
//! every continuity observation is validated fail-closed, so type-relative
//! identity, competing hypotheses without filename or similarity merge,
//! unknown-or-degraded status without a modality-competent evaluator, and
//! the prose-proof ban hold wherever a read reaches this gate, not only in
//! the contract crate. [`admit_workflow_view_for_projection`] binds a
//! [`WorkflowStateView`] to the shared [`MemoryScopeBinding`] the batch is
//! projected under.
//!
//! [`project_batch`](crate::project_batch) is the only caller of both gates:
//! it invokes them immediately after the request validates and before the
//! first record is built, and maps a refusal into
//! [`ProjectionError`](crate::ProjectionError) so the read fails closed. A
//! refused continuity observation therefore cannot contribute to a batch,
//! and an admitted one is accounted in the denominator as one named coverage
//! omission rather than dropped.
//!
//! "Only caller" is not "production caller", and this module does not claim
//! the stronger one. No package in this repository depends on this crate, so
//! no binary links [`project_batch`](crate::project_batch) or either gate, and
//! until the MGR04 (#19) read-side handoff supplies the admitted observations
//! this crate's own test target is the only thing that reaches them. The
//! crate manifest is the authority on that ceiling: `prototype = true` with
//! `workspace_admission = "workspace_member_prototype_proof_pending"` and
//! `proof_ceiling = "STATIC_CONTRACT_REGISTRATION_ONLY"`, per
//! `crates/AGENTS.md` — prototype presence does not grant runtime authority.

use eliot_memory_projection_contracts::{
    MemoryProjectionError, MemoryScopeBinding, WorkflowStateView,
};
use eliot_observation_contracts::{
    ContinuityError, ContinuityObservation, admit_continuity_observation,
};

/// Enforce continuity ingestion rules for observations about to be projected.
///
/// Every observation must pass [`admit_continuity_observation`]; the first
/// failure fails the whole intake closed before projection.
///
/// The error is the contract's own [`ContinuityError`]; the caller maps it
/// into its error type so a refusal stays distinguishable from a projection
/// contract failure.
pub fn admit_continuity_for_projection(
    observations: &[ContinuityObservation],
) -> Result<(), ContinuityError> {
    for observation in observations {
        admit_continuity_observation(observation)?;
    }
    Ok(())
}

/// Admit a workflow state view against the shared projection binding.
///
/// The view must validate, and its task/scope must equal the binding every
/// projected record must satisfy; otherwise the view cannot travel with the
/// batch it claims to describe. A present view is never tolerated as
/// unchecked: [`project_batch`](crate::project_batch) calls this gate, so a
/// view outside the binding fails the read instead of travelling unverified.
/// That caller is the crate's only one and is not yet on a binary path — see
/// the module documentation.
pub fn admit_workflow_view_for_projection(
    view: &WorkflowStateView,
    binding: &MemoryScopeBinding,
) -> Result<(), MemoryProjectionError> {
    view.validate()?;
    if view.task_id != binding.task_id || view.scope_id != binding.scope_id {
        return Err(MemoryProjectionError::ScopeMismatch {
            reason: "workflow view binding differs from the projection binding",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_continuity_intake_admits() {
        assert!(admit_continuity_for_projection(&[]).is_ok());
    }
}
