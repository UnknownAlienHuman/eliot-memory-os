//! Task-binding gate for the closed store bridge (issue #1929).
//!
//! Implements the I5.5 capture/promotion split at the `eliot-store-surreal`
//! boundary, before any provider I/O:
//!
//! - `CaptureObservation` without a task identity on either side is classified
//!   [`GateDisposition::ColdUnbound`] only for `CaptureObservation` and
//!   `AppendAuditEvent` candidate-family operations under the `Candidate`
//!   effect ceiling: durably retainable cold bytes with no task activation,
//!   task-memory, support/influence promotion, or finish relevance.
//! - Every task-relative reusable/control transition (`UpdateTaskState` and any
//!   `CaptureObservation` that names a task) requires the exact binding: the
//!   context and transition task identities agree, the complete fences agree,
//!   retained original evidence agrees with the operation's separate
//!   revision/digest/scope/source/evidence fields, and at least two distinct
//!   exact evidence handles are present. Absence rejects with
//!   `TASK_SELECTION_REQUIRED`; a different/incompatible scope rejects with
//!   `TASK_SCOPE_INCOMPATIBLE`.
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

use eliot_contracts::{LowercaseSha256, TaskId, TaskRevision};
use eliot_store_api::{
    EffectClass, NamedMutationOperation, PreparedTransition, RequestMeta, ScopeId, StoreError,
    TransitionClass,
};

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

fn operation_text<'a>(
    operation: &'a eliot_store_api::NamedMutationRequest,
    field: &'static str,
) -> Result<&'a str, TaskBindingRejection> {
    operation
        .parameters
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| exact_handle(value))
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(format!(
                "task-bound operation is missing exact {field}"
            ))
        })
}

fn operation_json_text<'a>(
    operation: &'a eliot_store_api::NamedMutationRequest,
    field: &'static str,
) -> Result<&'a str, TaskBindingRejection> {
    operation
        .parameters
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(format!(
                "task-bound operation is missing retained {field}"
            ))
        })
}

fn validate_capture_submission_binding(
    operation: &eliot_store_api::NamedMutationRequest,
    transition: &PreparedTransition,
    evidence: &serde_json::Value,
) -> Result<(), TaskBindingRejection> {
    let encoded = operation_json_text(operation, "observation_submission_json")?;
    let submission: serde_json::Value = serde_json::from_str(encoded).map_err(|_| {
        TaskBindingRejection::selection_required(
            "task-bound capture has no valid retained observation submission",
        )
    })?;
    let fence: eliot_store_api::StateFence = submission
        .get("state_fence")
        .cloned()
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(
                "retained observation submission is missing its State Fence",
            )
        })
        .and_then(|value| {
            serde_json::from_value(value).map_err(|_| {
                TaskBindingRejection::selection_required(
                    "retained observation submission has an invalid State Fence",
                )
            })
        })?;
    if fence != transition.state_fence {
        return Err(TaskBindingRejection::selection_required(
            "retained observation submission fence differs from the prepared operation",
        ));
    }

    let selection = submission.get("task_selection").ok_or_else(|| {
        TaskBindingRejection::selection_required(
            "retained observation submission is missing TaskSelectionEvidence",
        )
    })?;
    if selection != evidence {
        return Err(TaskBindingRejection::selection_required(
            "observation submission and named operation carry different original TaskSelectionEvidence",
        ));
    }

    let affected_scope = submission
        .get("record")
        .and_then(|record| record.get("event"))
        .and_then(|event| event.get("affected_scope"))
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(
                "task-bound observation submission is missing its affected WorkScope",
            )
        })?;
    let task_ref = affected_scope
        .get("task_ref")
        .and_then(serde_json::Value::as_str);
    let scope_ref = affected_scope
        .get("work_scope")
        .and_then(serde_json::Value::as_str);
    let evidence_task_ref = evidence.get("task_ref").and_then(serde_json::Value::as_str);
    let evidence_scope_ref = evidence
        .get("work_scope_ref")
        .and_then(serde_json::Value::as_str);
    if task_ref != evidence_task_ref || scope_ref != evidence_scope_ref {
        return Err(TaskBindingRejection::scope_incompatible(
            "retained observation subject task or WorkScope differs from TaskSelectionEvidence",
        ));
    }
    Ok(())
}

/// Cross-checks the retained evidence independently against the operation,
/// admitted task/fence and transition scope. The acceptance digest is compared
/// as recorded; it is never reconstructed from caller-supplied lists or bytes.
fn validate_retained_evidence_fields(
    evidence: &serde_json::Value,
) -> Result<(TaskId, TaskRevision, LowercaseSha256, ScopeId), TaskBindingRejection> {
    let task_ref = evidence
        .get("task_ref")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| TaskId::new(value).ok())
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(
                "retained task selection evidence has no valid task identity",
            )
        })?;
    let task_revision = evidence
        .get("task_revision")
        .cloned()
        .and_then(|value| serde_json::from_value::<TaskRevision>(value).ok())
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(
                "retained task selection evidence has no valid task revision",
            )
        })?;
    let recorded_acceptance_digest = evidence
        .get("acceptance_digest")
        .cloned()
        .and_then(|value| serde_json::from_value::<LowercaseSha256>(value).ok())
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(
                "retained task selection evidence has no valid recorded acceptance digest",
            )
        })?;
    let work_scope_ref = evidence
        .get("work_scope_ref")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| ScopeId::new(value).ok())
        .ok_or_else(|| {
            TaskBindingRejection::selection_required(
                "retained task selection evidence has no valid WorkScope identity",
            )
        })?;
    let Some(flags) = evidence
        .get("contamination_flags")
        .and_then(serde_json::Value::as_array)
    else {
        return Err(TaskBindingRejection::selection_required(
            "retained task selection evidence is missing contamination flags",
        ));
    };
    if !flags.is_empty() {
        return Err(TaskBindingRejection::selection_required(
            "contaminated task selection evidence cannot authorize a task-bound write",
        ));
    }
    Ok((
        task_ref,
        task_revision,
        recorded_acceptance_digest,
        work_scope_ref,
    ))
}

fn validate_retained_selection_operation(
    context: &RequestMeta,
    transition: &PreparedTransition,
    task_id: &str,
    operation: &eliot_store_api::NamedMutationRequest,
) -> Result<(), TaskBindingRejection> {
    let encoded = operation_json_text(operation, "task_selection_evidence_json")?;
    let evidence: serde_json::Value = serde_json::from_str(encoded).map_err(|_| {
        TaskBindingRejection::selection_required(
            "retained task selection evidence is not valid JSON",
        )
    })?;
    let (task_ref, task_revision, recorded_digest, work_scope_ref) =
        validate_retained_evidence_fields(&evidence)?;
    let revision = operation_text(operation, "task_selection_revision")?;
    let acceptance_digest = operation_text(operation, "task_selection_acceptance_digest")?;
    let scope_ref = operation_text(operation, "task_selection_scope_ref")?;
    let source_ref = operation_text(operation, "task_selection_source_ref")?;
    let evidence_ref = operation_text(operation, "task_selection_evidence_ref")?;

    if task_ref.as_str() != task_id {
        return Err(TaskBindingRejection::scope_incompatible(
            "retained task selection names a different task than the admitted operation",
        ));
    }
    if work_scope_ref.as_str() != transition.scope_id.as_str()
        || scope_ref != work_scope_ref.as_str()
    {
        return Err(TaskBindingRejection::scope_incompatible(
            "retained task selection WorkScope does not match the prepared operation",
        ));
    }

    let current_revision = context.state_fence.task_revision;
    let retained_revision = task_revision.value().to_string();
    if retained_revision != revision
        || current_revision != Some(task_revision)
        || recorded_digest.as_str() != acceptance_digest
        || evidence
            .get("selection_source_ref")
            .and_then(serde_json::Value::as_str)
            != Some(source_ref)
        || evidence
            .get("evidence_ref")
            .and_then(serde_json::Value::as_str)
            != Some(evidence_ref)
        || !transition
            .required_proof_and_approval_refs
            .iter()
            .any(|reference| reference == source_ref)
        || !transition
            .required_proof_and_approval_refs
            .iter()
            .any(|reference| reference == evidence_ref)
    {
        return Err(TaskBindingRejection::selection_required(
            "retained task selection revision, acceptance digest, or exact evidence references do not match the operation",
        ));
    }

    if operation.operation == NamedMutationOperation::UpdateTaskState
        && operation_text(operation, "task_id")? != task_id
    {
        return Err(TaskBindingRejection::scope_incompatible(
            "task-control payload names a different task than the admitted selection",
        ));
    }
    if operation.operation == NamedMutationOperation::CaptureObservation {
        validate_capture_submission_binding(operation, transition, &evidence)?;
    }
    Ok(())
}

fn validate_retained_selection(
    context: &RequestMeta,
    transition: &PreparedTransition,
    task_id: &str,
) -> Result<(), TaskBindingRejection> {
    let context_task = context.task_id.as_ref().map(TaskId::as_str);
    if context_task != Some(task_id) || transition.task_id.as_deref() != Some(task_id) {
        return Err(TaskBindingRejection::scope_incompatible(
            "retained task selection does not match the admitted task and prepared operation",
        ));
    }
    if context.state_fence != transition.state_fence {
        return Err(TaskBindingRejection::selection_required(
            "task selection fence differs from the complete admitted State Fence",
        ));
    }

    let mut checked = false;
    for operation in &transition.named_operations {
        if matches!(
            operation.operation,
            NamedMutationOperation::CaptureObservation | NamedMutationOperation::UpdateTaskState
        ) {
            checked = true;
            validate_retained_selection_operation(context, transition, task_id, operation)?;
        }
    }
    if !checked {
        return Err(TaskBindingRejection::selection_required(
            "task-bound capture/control requires retained TaskSelectionEvidence",
        ));
    }
    Ok(())
}

/// Gates one prepared transition before any provider I/O.
///
/// Rules:
/// - A cold unbound capture may contain only `CaptureObservation` and
///   `AppendAuditEvent`, both in the `CaptureCandidate` family under the
///   `Candidate` ceiling. Other candidate-family operations may retain task
///   memory or authority evidence and are rejected before provider I/O.
/// - `CaptureObservation` naming a task, and every `UpdateTaskState`, require
///   exact binding: context/transition task identities present and equal,
///   fences equal, retained original evidence agrees with the operation's
///   separate revision/digest/scope/source/evidence fields, `WorkScope` agrees
///   with the prepared transition's `scope_id`, and at least two distinct
///   exact evidence handles are present. Missing binding rejects with
///   `TASK_SELECTION_REQUIRED`; a task/scope mismatch rejects with
///   `TASK_SCOPE_INCOMPATIBLE`.
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
            (None, None) => {
                if operations.iter().any(|operation| {
                    !matches!(
                        operation,
                        NamedMutationOperation::CaptureObservation
                            | NamedMutationOperation::AppendAuditEvent
                    )
                }) || transition.transition_class != TransitionClass::CaptureCandidate
                    || transition.requested_effect_ceiling != EffectClass::Candidate
                {
                    return Err(TaskBindingRejection::selection_required(
                        "cold unbound capture may carry only CaptureObservation and AppendAuditEvent under the Candidate effect ceiling",
                    ));
                }
                return Ok(GateDisposition::ColdUnbound);
            }
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
    if context.state_fence.task_revision.is_none() {
        return Err(TaskBindingRejection::selection_required(
            "task-bound capture/control requires a task revision in the current State Fence",
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
    validate_retained_selection(context, transition, task_id)?;
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
    if context.state_fence.task_revision.is_none() {
        return Err(TaskBindingRejection::selection_required(
            "task-bound finish requires a task revision in the current State Fence",
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
    // EpistemicRevision carries and validates its exact task revision in its
    // closed payload, and the store receipt uses that revision when the
    // daemon-generation fence is deliberately unscoped. Other task-relative
    // families require the task revision directly in the current fence.
    let revision_is_in_payload = transition.named_operations.len() == 1
        && transition.named_operations[0].operation
            == NamedMutationOperation::ApplyEpistemicRevision;
    if !revision_is_in_payload && context.state_fence.task_revision.is_none() {
        return Err(TaskBindingRejection::selection_required(
            "task-bearing write requires a task revision in the current State Fence",
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
