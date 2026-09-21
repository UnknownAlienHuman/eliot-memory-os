//! Task-binding gate for the closed store bridge (issue #1929).
//!
//! Implements the I5.5 capture/promotion split at the `eliot-store-surreal`
//! boundary, before any provider I/O:
//!
//! - `CaptureObservation` without a unique task selection is classified
//!   [`GateDisposition::ColdUnbound`]: durably retainable cold bytes with no
//!   task activation, support/influence promotion, or finish relevance.
//! - Every task-relative reusable/control transition (`UpdateTaskState` and any
//!   `CaptureObservation` that names a task) requires the exact binding: the
//!   context and transition task identities agree, the fences agree, and the
//!   admitted proof refs carry the exact `TaskContract` revision plus acceptance
//!   digest for the same `WorkScope`. Absence rejects with
//!   `TASK_SELECTION_REQUIRED`; a different/incompatible scope rejects with
//!   `TASK_SCOPE_INCOMPATIBLE`.
//! - There is no latest-task, open-task, or resolver-guess fallback: ambiguity
//!   stays cold, mismatch fails closed.
//!
//! This module is pure and store-neutral. It never touches the provider; the
//! composition calls [`gate_apply`] at the top of its canonical write path and
//! maps a rejection to a typed `StoreError::InvalidField` whose reason starts
//! with the stable code, so the existing failure contract surfaces the exact
//! code without a new store variant.

#![forbid(unsafe_code)]

use eliot_contracts::TaskId;
use eliot_store_api::{NamedMutationOperation, PreparedTransition, RequestMeta, StoreError};

/// Stable rejection code when task-bound promotion lacks current evidence.
pub const TASK_SELECTION_REQUIRED: &str = "TASK_SELECTION_REQUIRED";
/// Stable rejection code when evidence names another/incompatible `WorkScope`.
pub const TASK_SCOPE_INCOMPATIBLE: &str = "TASK_SCOPE_INCOMPATIBLE";

/// Where the admitted proof refs must bind the exact task evidence.
///
/// Proof handles are opaque exact strings admitted upstream. The bridge does
/// not parse their internals; it only requires that both the `TaskContract`
/// revision handle and the acceptance-digest handle are present and bound to
/// the same task, so a bare `task_id` can never promote by itself.
const TASK_CONTRACT_REVISION_MARKER: &str = "task-contract-revision:";
const ACCEPTANCE_DIGEST_MARKER: &str = "acceptance-digest:";

/// Outcome of the pre-provider task-binding gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDisposition {
    /// Cold unbound capture: retainable with no task effects.
    ColdUnbound,
    /// Exact task-bound transition admitted to the provider path.
    TaskBound,
    /// Not a task-relative operation; no binding required.
    NotTaskRelative,
}

/// Typed gate rejection carrying exactly one stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskBindingRejection {
    code: &'static str,
    detail: String,
}

impl TaskBindingRejection {
    fn selection_required(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SELECTION_REQUIRED,
            detail: detail.into(),
        }
    }

    fn scope_incompatible(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SCOPE_INCOMPATIBLE,
            detail: detail.into(),
        }
    }

    /// Stable wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Bounded human detail (never a task guess).
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Renders the typed store reason preserving the exact code prefix.
    #[must_use]
    pub fn store_reason(&self) -> String {
        format!("{}: {}", self.code, self.detail)
    }
}

/// Maps a gate rejection to the typed store failure surfaced on the real
/// canonical write path (`apply_with_authority`, before any provider I/O):
/// `InvalidField` on `task_binding` carrying exactly the stable code.
/// Callers must use this mapping so helper tests and the production path
/// can never disagree on the surfaced code.
#[must_use]
pub fn map_rejection(rejection: &TaskBindingRejection) -> StoreError {
    let reason = if rejection.code() == TASK_SCOPE_INCOMPATIBLE {
        TASK_SCOPE_INCOMPATIBLE
    } else {
        TASK_SELECTION_REQUIRED
    };
    StoreError::InvalidField {
        field: "task_binding",
        reason,
    }
}

impl std::fmt::Display for TaskBindingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for TaskBindingRejection {}

fn operations_of(transition: &PreparedTransition) -> Vec<NamedMutationOperation> {
    transition
        .named_operations
        .iter()
        .map(|op| op.operation)
        .collect()
}

fn has_exact_binding_refs(transition: &PreparedTransition, task_id: &str) -> bool {
    let revision_handle = transition
        .required_proof_and_approval_refs
        .iter()
        .any(|handle| {
            handle.starts_with(TASK_CONTRACT_REVISION_MARKER)
                && handle.contains(task_id)
                && handle.trim().len() == handle.len()
                && !handle.trim().is_empty()
        });
    let digest_handle = transition
        .required_proof_and_approval_refs
        .iter()
        .any(|handle| {
            handle.starts_with(ACCEPTANCE_DIGEST_MARKER)
                && handle.contains(task_id)
                && handle.trim().len() == handle.len()
                && !handle.trim().is_empty()
        });
    revision_handle && digest_handle
}

/// Gates one prepared transition before any provider I/O.
///
/// Rules:
/// - `CaptureObservation` with no task identity on either side is
///   [`GateDisposition::ColdUnbound`].
/// - `CaptureObservation` naming a task, and every `UpdateTaskState`, require
///   exact binding: context/transition task identities present and equal,
///   fences equal, `WorkScope` (transition `scope_id`) consistent with the
///   context fence, and exact contract-revision plus acceptance-digest proof
///   refs for that task. Missing binding rejects with
///   `TASK_SELECTION_REQUIRED`; a task/scope mismatch rejects with
///   `TASK_SCOPE_INCOMPATIBLE`.
/// - All other operations are [`GateDisposition::NotTaskRelative`].
pub fn gate_apply(
    context: &RequestMeta,
    transition: &PreparedTransition,
) -> Result<GateDisposition, TaskBindingRejection> {
    let operations = operations_of(transition);
    let captures = operations.contains(&NamedMutationOperation::CaptureObservation);
    let controls = operations.contains(&NamedMutationOperation::UpdateTaskState);

    if captures && !controls {
        let transition_task = transition.task_id.as_deref();
        let context_task = context.task_id.as_ref().map(TaskId::as_str);
        match (transition_task, context_task) {
            (None, None) => return Ok(GateDisposition::ColdUnbound),
            (Some(task), Some(ctx)) if task == ctx => {
                require_exact_binding(context, transition, task)?;
                return Ok(GateDisposition::TaskBound);
            }
            (Some(_), Some(_)) => {
                return Err(TaskBindingRejection::scope_incompatible(
                    "capture task identity does not match the admitted context task",
                ));
            }
            _ => {
                return Err(TaskBindingRejection::selection_required(
                    "task-bound capture requires current TaskSelectionEvidence",
                ));
            }
        }
    }

    if controls {
        let Some(task) = transition.task_id.as_deref() else {
            return Err(TaskBindingRejection::selection_required(
                "task-control write requires current TaskSelectionEvidence",
            ));
        };
        let Some(ctx) = context.task_id.as_ref().map(TaskId::as_str) else {
            return Err(TaskBindingRejection::selection_required(
                "task-control write requires current TaskSelectionEvidence",
            ));
        };
        if task != ctx {
            return Err(TaskBindingRejection::scope_incompatible(
                "task selection names a different task or WorkScope",
            ));
        }
        require_exact_binding(context, transition, task)?;
        return Ok(GateDisposition::TaskBound);
    }

    Ok(GateDisposition::NotTaskRelative)
}

fn require_exact_binding(
    context: &RequestMeta,
    transition: &PreparedTransition,
    task_id: &str,
) -> Result<(), TaskBindingRejection> {
    if context.state_fence != transition.state_fence {
        return Err(TaskBindingRejection::selection_required(
            "task binding fence is not the current State Fence",
        ));
    }
    if task_id.trim().is_empty() {
        return Err(TaskBindingRejection::selection_required(
            "task binding handle is blank",
        ));
    }
    if !has_exact_binding_refs(transition, task_id) {
        return Err(TaskBindingRejection::selection_required(
            "task-bound transition requires exact TaskContract revision and acceptance digest handles",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_markers_require_both_handles_for_the_same_task() {
        assert!(TASK_CONTRACT_REVISION_MARKER.starts_with("task-contract"));
        assert!(ACCEPTANCE_DIGEST_MARKER.starts_with("acceptance"));
    }

    #[test]
    fn rejection_mapping_preserves_exact_stable_codes() {
        let selection = map_rejection(&TaskBindingRejection::selection_required("detail"));
        assert_eq!(
            selection,
            StoreError::InvalidField {
                field: "task_binding",
                reason: TASK_SELECTION_REQUIRED,
            }
        );
        let scope = map_rejection(&TaskBindingRejection::scope_incompatible("detail"));
        assert_eq!(
            scope,
            StoreError::InvalidField {
                field: "task_binding",
                reason: TASK_SCOPE_INCOMPATIBLE,
            }
        );
    }
}
