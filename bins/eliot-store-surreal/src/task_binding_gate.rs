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
//!   context and transition task identities agree, the fences agree, and at
//!   least two distinct exact evidence handles are present (the revision
//!   evidence and the digest evidence, whose values were verified upstream).
//!   Absence rejects with `TASK_SELECTION_REQUIRED`; a different/incompatible
//!   scope rejects with `TASK_SCOPE_INCOMPATIBLE`.
//! - Every Governor finish write (`RecordFinishDecision`,
//!   `RecordFinishEvidence`) is task-bearing by construction and requires the
//!   finish binding: the context and transition task identities agree, the
//!   fences agree, and at least one exact Governor finish-authority handle is
//!   present (finish envelopes carry exactly one such handle, not the
//!   revision/digest pair). A task-bearing finish that names no task, names a
//!   different task than the admitted context, or carries no exact handle
//!   rejects with the same stable codes instead of passing as
//!   `NotTaskRelative`.
//! - Every remaining task-bearing transition — any other activated operation
//!   whose transition names a task (`ApplyEpistemicRevision`, whose Governor
//!   envelope always carries the task plus evidence records, and
//!   `ApplyLifecyclePolicy`, whose envelope carries the admitted task plus
//!   the verifier/approval refs, or any future task-naming family) —
//!   requires the general task binding: the context and transition task
//!   identities agree, the fences agree, and at least one exact evidence
//!   handle is present. A bare `task_id` with no exact handle, a task the
//!   admitted context does not name, or a fence move rejects with the same
//!   stable codes instead of passing as `NotTaskRelative`.
//! - There is no latest-task, open-task, or resolver-guess fallback: ambiguity
//!   stays cold, mismatch fails closed. Task-free writes (no task identity on
//!   the transition) stay [`GateDisposition::NotTaskRelative`]: capture-first
//!   candidate rows, audit appends, and the sealed reserved-write mechanism
//!   (issue #991, separate path) are not task-bound writes.
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

/// Requires the exact evidence handles for one task-bound transition.
///
/// Proof handles are opaque exact strings admitted upstream at eliotd /
/// Governor admission, where the `TaskContract` revision value, acceptance
/// digest value, and scope binding are verified against canonical evidence.
/// The bridge parses no handle internals and invents no marker syntax: it
/// requires at least two DISTINCT exact handles (the revision evidence and
/// the digest evidence), each non-blank, trimmed, and control-free per the
/// canonical text rules, so a bare `task_id` can never promote by itself.
/// Role verification stays upstream; presence, exactness, and task/fence
/// agreement are enforced here before any provider I/O.
/// One exact evidence handle: non-blank, trimmed, and control-free, so a bare
/// `task_id` or a padded handle can never promote by itself.
fn exact_handle(handle: &str) -> bool {
    !handle.trim().is_empty()
        && handle.trim().len() == handle.len()
        && !handle.chars().any(char::is_control)
}

fn has_exact_binding_refs(transition: &PreparedTransition) -> bool {
    let mut seen: Vec<&str> = Vec::new();
    for handle in &transition.required_proof_and_approval_refs {
        if !exact_handle(handle) {
            return false;
        }
        if !seen.contains(&handle.as_str()) {
            seen.push(handle.as_str());
        }
    }
    seen.len() >= 2
}

/// Requires at least one exact task-selection evidence handle.
///
/// Finish envelopes carry exactly one finish-authority handle (not the
/// revision/digest pair of capture/control writes), and the general
/// task-bearing families carry their single-class authority handles the same
/// way — so the pair rule of [`has_exact_binding_refs`] cannot apply here:
/// one exact handle plus task and fence agreement is the binding. Every
/// carried handle must still be exact; a blank, untrimmed, or
/// control-bearing handle fails the binding.
fn has_single_authority_ref(transition: &PreparedTransition) -> bool {
    if transition.required_proof_and_approval_refs.is_empty() {
        return false;
    }
    transition
        .required_proof_and_approval_refs
        .iter()
        .all(|handle| exact_handle(handle))
}

/// Gates one prepared transition before any provider I/O.
///
/// Rules:
/// - `CaptureObservation` with no task identity on either side is
///   [`GateDisposition::ColdUnbound`].
/// - `CaptureObservation` naming a task, and every `UpdateTaskState`, require
///   exact binding: context/transition task identities present and equal,
///   fences equal, `WorkScope` (transition `scope_id`) consistent with the
///   context fence, and at least two distinct exact evidence handles covering
///   the revision and digest evidence verified upstream. Missing binding
///   rejects with `TASK_SELECTION_REQUIRED`; a task/scope mismatch rejects
///   with `TASK_SCOPE_INCOMPATIBLE`.
/// - `RecordFinishDecision` and `RecordFinishEvidence` are task-bearing
///   Governor finish writes and require the finish binding: context/transition
///   task identities present and equal, fences equal, and at least one exact
///   Governor finish-authority handle present. A finish that names no task,
///   names a different task than the admitted context, or carries no exact
///   handle rejects with the same stable codes; it never passes as
///   `NotTaskRelative`.
/// - Any remaining transition that names a task is a task-bearing write in a
///   family without a dedicated pair rule (`ApplyEpistemicRevision` always
///   carries the task plus evidence records; `ApplyLifecyclePolicy` carries
///   the admitted task plus verifier/approval refs) and requires the general
///   task binding: context/transition task identities present and equal,
///   fences equal, and at least one exact evidence handle present. A bare
///   `task_id` with no exact handle, a task the admitted context does not
///   name, or a fence move rejects with the same stable codes; it never
///   passes as `NotTaskRelative`.
/// - All other operations (no task identity on the transition) are
///   [`GateDisposition::NotTaskRelative`].
///
/// A transition that mixes operation families answers the strictest
/// applicable rule: a finish piggybacked on a control or task-bound capture
/// still has to satisfy that family's pair rule.
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

    let finishes = operations.contains(&NamedMutationOperation::RecordFinishDecision)
        || operations.contains(&NamedMutationOperation::RecordFinishEvidence);
    if finishes {
        let transition_task = transition.task_id.as_deref();
        let context_task = context.task_id.as_ref().map(TaskId::as_str);
        match (transition_task, context_task) {
            (Some(task), Some(ctx)) if task == ctx => {
                require_finish_binding(context, transition, task)?;
                return Ok(GateDisposition::TaskBound);
            }
            (Some(_), Some(_)) => {
                return Err(TaskBindingRejection::scope_incompatible(
                    "finish write task identity does not match the admitted context task",
                ));
            }
            _ => {
                return Err(TaskBindingRejection::selection_required(
                    "finish write requires current TaskSelectionEvidence",
                ));
            }
        }
    }

    // Any remaining task-bearing write: the transition names a task in a
    // family without a dedicated rule above. Task-bound reusable memory,
    // epistemic revisions, and lifecycle actions require exact current
    // TaskSelectionEvidence just like capture, control, and finish — a bare
    // task identity with no exact evidence handle is never enough to
    // promote, and a task the admitted context does not name (or a moved
    // fence) fails closed. Task-free transitions fall through to
    // `NotTaskRelative` below.
    if let Some(task) = transition.task_id.as_deref() {
        let Some(ctx) = context.task_id.as_ref().map(TaskId::as_str) else {
            return Err(TaskBindingRejection::selection_required(
                "task-bearing write requires current TaskSelectionEvidence",
            ));
        };
        if task != ctx {
            return Err(TaskBindingRejection::scope_incompatible(
                "task-bearing write names a different task or WorkScope than the admitted context",
            ));
        }
        require_general_task_binding(context, transition, task)?;
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
    if !has_exact_binding_refs(transition) {
        return Err(TaskBindingRejection::selection_required(
            "task-bound transition requires exact revision and digest evidence handles",
        ));
    }
    Ok(())
}

/// Requires the exact binding for one Governor finish write.
///
/// The Governor finish legs always name the finished task and carry exactly
/// one finish-authority evidence handle; the admitted identity metadata task
/// must equal the finished task or the Governor fails closed before commit.
/// The gate requires the same agreement here — context/transition task
/// identities present and equal, fences equal (also enforced by the
/// pre-provider admission immediately before this gate), and at least one
/// exact handle — so a wrong or ambiguous task can never receive the
/// task-bound finish write. Handle *values* stay verified upstream, as for
/// capture/control evidence.
fn require_finish_binding(
    context: &RequestMeta,
    transition: &PreparedTransition,
    task_id: &str,
) -> Result<(), TaskBindingRejection> {
    if context.state_fence != transition.state_fence {
        return Err(TaskBindingRejection::selection_required(
            "finish binding fence is not the current State Fence",
        ));
    }
    if task_id.trim().is_empty() {
        return Err(TaskBindingRejection::selection_required(
            "finish binding handle is blank",
        ));
    }
    if !has_single_authority_ref(transition) {
        return Err(TaskBindingRejection::selection_required(
            "finish write requires the exact Governor finish-authority evidence handle",
        ));
    }
    Ok(())
}

/// Requires the exact binding for one task-bearing write in a family without
/// a dedicated pair rule.
///
/// `ApplyEpistemicRevision` envelopes always carry the task plus the evidence
/// records observed upstream, and `ApplyLifecyclePolicy` envelopes always
/// carry the admitted task plus the verifier (and optional human-approval)
/// refs: neither family carries the revision/digest handle pair of
/// capture/control writes, so the pair rule of [`has_exact_binding_refs`]
/// cannot apply here. One exact evidence handle plus task and fence agreement
/// is the general binding — the same grade as the finish binding — so a bare
/// `task_id` can never promote a write the dedicated arms do not cover.
/// Handle *values* stay verified upstream, as for every other family.
fn require_general_task_binding(
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
    if !has_single_authority_ref(transition) {
        return Err(TaskBindingRejection::selection_required(
            "task-bearing write requires at least one exact task-selection evidence handle",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
