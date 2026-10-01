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
//! projected under, `admit_workflow_continuity_for_projection` binds the
//! observation owner's [`WorkflowContinuity`] to the view that attests the same
//! workflow position, and `admit_view_gaps_are_typed` refuses a view whose
//! own free-text representation-gap clause has no typed per-property status
//! behind it — without which the per-property gate is never reached and an
//! absent modality property travels as prose.
//!
//! [`project_batch`](crate::project_batch) is the only caller of all four
//! gates: it invokes them immediately after the request validates and before
//! the first record is built, and maps a refusal into
//! [`ProjectionError`](crate::ProjectionError) so the read fails closed. A
//! refused continuity observation therefore cannot contribute to a batch,
//! and an admitted one is accounted in the denominator as one named coverage
//! omission rather than dropped.
//!
//! "Only caller" is not "production caller", and this module does not claim
//! the stronger one. No package in this repository depends on this crate, so
//! no binary links [`project_batch`](crate::project_batch) or any gate, and
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
    ContinuityError, ContinuityObservation, WorkflowContinuity, admit_continuity_observation,
};

use crate::ProjectionError;

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
///
/// This gate deliberately does not read the view's representation-gap clause;
/// that clause is untyped, so refusing it here would be a string rule. It is
/// `admit_view_gaps_are_typed`, run on the same read, that requires the typed
/// per-property status to exist behind a declared gap.
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

/// Refuses a view whose representation-gap clause has no typed per-property
/// status behind it.
///
/// `WorkflowStateView` carries `unresolved_representation_gaps` as free text,
/// and the projection owner does not re-type that field: the observation owner
/// supplies the typed per-property record, `WorkflowContinuity`'s
/// `unresolved_representation_gaps`, whose `RepresentationGap::property_status`
/// is non-optional and non-defaulted, so an absent modality property can only be
/// spelled `Unknown` or earned as `Degraded` behind a competent evaluator.
/// `check_gap_status` is what refuses a gap that claims more than its evidence
/// carries, and it runs on the typed record only.
///
/// The defect this closes is reachability, not a missing check. The typed gate
/// is reached solely through `ProjectionRequest.workflow_continuity`, which
/// `project_batch` admits inside `if let Some(...)`. So a view could declare
/// `unresolved_representation_gaps` as free text and supply no typed record at
/// all: `admit_workflow_view_for_projection` accepts it, because a non-blank
/// string is a well-formed string, and the gap then travels to the batch with no
/// `property_status` at all — not `Unknown`, not `Degraded`, not gated by
/// `check_gap_status`. That is exactly the state I12.35 forbids: an absent
/// modality property reported as settled prose.
///
/// The rule binds against the view's OWN recorded clause. It is a presence
/// requirement, not a re-derivation and not a string comparison: a view that
/// names at least one unresolved representation gap must arrive with the typed
/// record that governs that same workflow position, so every such property
/// reaches `check_gap_status` under its own modality and loss warning. A view
/// that declares no gap is untouched, and a view with no typed record and no
/// declared gap continues to pass exactly as before — this refuses only the
/// ungated gap clause, and it never weakens an existing gate to reach it.
///
/// A gap the typed record does not cover cannot be detected here, because the
/// view's clause is prose and the record's is typed; cross-checking the two
/// vocabularies is a re-typing of the projection owner's field and is left to its
/// owner rather than guessed at from this side.
pub fn admit_view_gaps_are_typed(
    view: &WorkflowStateView,
    continuity: Option<&WorkflowContinuity>,
) -> Result<(), ProjectionError> {
    if view.unresolved_representation_gaps.is_empty() {
        return Ok(());
    }
    if continuity.is_none() {
        return Err(ProjectionError::WorkflowContinuityDiscontinuous {
            reason: "the view names unresolved representation gaps with no typed per-property status to govern them",
        });
    }
    Ok(())
}

/// Admit workflow continuity evidence against the attested workflow view.
///
/// [`WorkflowContinuity::validate`] first runs the observation owner's own
/// fail-closed rules: every lineage hop resolves against the record's original
/// admitted hypotheses, and every unresolved representation gap keeps its
/// typed per-property modality status. This gate then binds that record to the
/// view, and the binding is a comparison against the view's OWN recorded
/// identity rather than a re-derivation:
///
/// - a record with no attested view is refused, because a workflow identity and
///   step are continuous with nothing until a view names them;
/// - `workflow_id` must equal the view's, so a record cannot re-issue a
///   position under a different workflow identity;
/// - `step_id` must be the view's current or previous step, so a record cannot
///   anchor to a step the view never names.
///
/// [`project_batch`](crate::project_batch) is the only caller and runs this
/// before the first record is built. That caller is not yet on a binary path —
/// see the module documentation.
pub fn admit_workflow_continuity_for_projection(
    continuity: &WorkflowContinuity,
    view: Option<&WorkflowStateView>,
) -> Result<(), ProjectionError> {
    continuity.validate()?;
    let Some(view) = view else {
        return Err(ProjectionError::WorkflowContinuityDiscontinuous {
            reason: "no workflow view attests the workflow position this record describes",
        });
    };
    if continuity.workflow_id != view.workflow_id {
        return Err(ProjectionError::WorkflowContinuityDiscontinuous {
            reason: "the record names a different workflow than the attested view",
        });
    }
    let attested = continuity.step.step_id == view.current_step
        || view.previous_step.as_deref() == Some(continuity.step.step_id.as_str());
    if !attested {
        return Err(ProjectionError::WorkflowContinuityDiscontinuous {
            reason: "the record anchors to a step the attested view does not name",
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
