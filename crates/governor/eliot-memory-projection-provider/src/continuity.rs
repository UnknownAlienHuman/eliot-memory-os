//! Governor ingestion gate for continuity evidence (I12.35).
//!
//! [`admit_continuity_for_projection`] enforces the continuity ingestion
//! rules at the Governor projection boundary before any admitted memory
//! observation reaches [`project_batch`](crate::project_batch): every
//! continuity observation is validated fail-closed, so type-relative
//! identity, competing hypotheses without filename or similarity merge,
//! unknown-or-degraded status without a modality-competent evaluator, and
//! the prose-proof ban hold on the production projection path, not only in
//! the contract crate. [`admit_workflow_view_for_projection`] binds a
//! [`WorkflowStateView`] to the shared [`MemoryScopeBinding`] the batch is
//! projected under.

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
/// batch it claims to describe.
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
