//! Governor-side CC-004 projection assembly for Orientation.
//!
//! This adapter joins the existing Governor projection/readback with the
//! current task-cognition owner fields. It returns a shared projection set
//! only when the exact task commitments and next action are present in the
//! retained task-frame payload under the same admitted task, WorkScope and
//! StateFence. The retained Governor projections, seven-role read identities,
//! and original omission records travel with the result as their lineage.

use eliot_context_candidates::ProjectionState;
use eliot_context_contracts::{
    AffordanceProjection, CANONICAL_PROJECTIONS_SCHEMA_VERSION, CanonicalProjectionSet,
    ContextBinding, ContinuityProjection, OmissionRecord, SafetyProjection, TaskProjection,
};
use eliot_contracts::{TaskId, fences_match_exact};
use eliot_store_api::NamedReadOperation;
use eliot_workscope::{ScopeBindingDisposition, WorkScopeBindingSnapshot};
use serde_json::Value;

use crate::canonical_projections::GovernorProjectionSet;
use crate::context_inputs::{RoleAcquisition, SevenRoleInputs};

/// The exact task-cognition fields used by the canonical task and continuity
/// projections. Callers pass references into the real `TaskCognitionView`;
/// this type has no text constructors or fallback prose.
#[derive(Clone, Copy, Debug)]
pub struct OrientationTaskCognitionFields<'a> {
    /// `TaskCognitionView.task_contract.task_id`.
    pub task_id: &'a TaskId,
    /// `TaskCognitionView.task_contract.acceptance_items[*].description` in
    /// owner order.
    pub acceptance_descriptions: &'a [&'a str],
    /// `TaskCognitionView.active_decision_state.task_id`, when present.
    pub active_decision_task_id: Option<&'a TaskId>,
    /// `TaskCognitionView.active_decision_state.next_allowed_action`, when
    /// present.
    pub next_allowed_action: Option<&'a str>,
}

/// Inputs to the Governor-owned Orientation projection join.
pub struct OrientationProjectionOwnerInput<'a> {
    /// Binding admitted for this Orientation operation.
    pub binding: &'a ContextBinding,
    /// Existing canonical Governor projection output.
    pub governor: &'a GovernorProjectionSet,
    /// Retained WorkScope owner snapshot admitted for this operation.
    pub work_scope: &'a WorkScopeBindingSnapshot,
    /// Existing seven-role source payloads and exact retained read identities.
    pub role_inputs: &'a SevenRoleInputs,
    /// Borrowed fields from the actual task-cognition owner readback.
    pub task_cognition: OrientationTaskCognitionFields<'a>,
    /// Original owner-retained omission records. `None` means their source was
    /// not supplied; an empty slice means the source explicitly retained none.
    pub omissions: Option<&'a [OmissionRecord]>,
}

/// Joined CC-004 output. A missing `projections` value is an explicit partial
/// owner result; original owner data and read receipts remain available in all
/// cases for the runtime carrier.
#[derive(Clone, Debug)]
pub struct OrientationProjectionOwnerOutput {
    /// One complete shared set, present only when every member is grounded.
    pub projections: Option<CanonicalProjectionSet>,
    /// Overall disposition. Per-owner member dispositions below retain the
    /// exact reason a complete shared set could not be emitted.
    pub disposition: ProjectionState,
    /// Task/commitments member disposition.
    pub task: ProjectionState,
    /// Continuity/next-action member disposition.
    pub continuity: ProjectionState,
    /// Safety/negative-memory member disposition.
    pub safety: ProjectionState,
    /// WorkScope affordance member disposition.
    pub affordance: ProjectionState,
    /// Original omission-source disposition; distinct from member status.
    pub omissions_state: ProjectionState,
    /// The admitted binding used by this join.
    pub binding: ContextBinding,
    /// Exact WorkScope owner snapshot used to authorize the affordance member.
    pub work_scope: WorkScopeBindingSnapshot,
    /// Original Governor owner projection, including its own omissions.
    pub governor: GovernorProjectionSet,
    /// Original seven-role states, payloads, revision heads and read identities.
    pub role_inputs: SevenRoleInputs,
    /// Original task-cognition owner fields copied without rewriting.
    pub task_cognition: OrientationTaskCognitionSnapshot,
    /// Original owner omissions, or `None` when no retained omission source was
    /// supplied. Records are cloned unchanged.
    pub omissions: Option<Vec<OmissionRecord>>,
}

/// Owned copy of the task-cognition fields retained with the join result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientationTaskCognitionSnapshot {
    /// Exact owner task id.
    pub task_id: TaskId,
    /// Exact acceptance descriptions in owner order.
    pub acceptance_descriptions: Vec<String>,
    /// Exact active decision task id, when present.
    pub active_decision_task_id: Option<TaskId>,
    /// Exact next action, when present.
    pub next_allowed_action: Option<String>,
}

/// Joins the exact admitted task and WorkScope to the existing Governor
/// projection and retained source receipts.
///
/// The task-cognition fields are accepted only if the task-frame role's
/// original payload contains the same task id, acceptance descriptions and
/// active next action. A `ReadIdentity` beside a projection is not treated as
/// proof of content that the original payload does not contain.
#[must_use]
pub fn bind_orientation_projections(
    input: OrientationProjectionOwnerInput<'_>,
) -> OrientationProjectionOwnerOutput {
    let binding = input.binding.clone();
    let work_scope = input.work_scope.clone();
    let governor = input.governor.clone();
    let role_inputs = input.role_inputs.clone();
    let task_cognition = OrientationTaskCognitionSnapshot {
        task_id: input.task_cognition.task_id.clone(),
        acceptance_descriptions: input
            .task_cognition
            .acceptance_descriptions
            .iter()
            .map(|description| (*description).to_owned())
            .collect(),
        active_decision_task_id: input.task_cognition.active_decision_task_id.cloned(),
        next_allowed_action: input.task_cognition.next_allowed_action.map(str::to_owned),
    };
    let omissions = input.omissions.map(|records| records.to_vec());

    let mut task_state = role_projection_state(&input.role_inputs.task_frame);
    let mut continuity_state = role_projection_state(&input.role_inputs.task_frame);
    let mut safety_state = role_projection_state(&input.role_inputs.negative_memory);
    let mut affordance_state = role_projection_state(&input.role_inputs.affordances);
    let omissions_state = omission_state(input.omissions, &binding);

    if !binding.validate().is_ok()
        || !input.work_scope.validate().is_ok()
        || !fences_match_exact(&input.work_scope.state_fence, &binding.state_fence)
        || !fences_match_exact(&input.governor.fence, &binding.state_fence)
        || !input.governor.is_compatible_with(&binding.state_fence)
        || input.role_inputs.scope_id.as_str() != binding.scope_id.as_str()
        || !fences_match_exact(&input.role_inputs.state_fence, &binding.state_fence)
        || input.role_inputs.heads_before != input.role_inputs.heads_after
        || input.work_scope.binding.scope.scope_ref != binding.scope_id.as_str()
        || input.work_scope.guard_receipt.disposition != ScopeBindingDisposition::Matched
        || input.work_scope.guard_receipt.expected_scope_ref != binding.scope_id.as_str()
        || input.work_scope.guard_receipt.observed_scope_ref != binding.scope_id.as_str()
        || input.governor.task_id != binding.task_id
        || input.governor.scope_ref != binding.scope_id.as_str()
        || input.task_cognition.task_id != &binding.task_id
        || input
            .task_cognition
            .active_decision_task_id
            .is_some_and(|task_id| task_id != &binding.task_id)
    {
        return incomplete(
            binding,
            work_scope,
            governor,
            role_inputs,
            task_cognition,
            omissions,
            ProjectionState::Stale {
                reason:
                    "task, WorkScope, source heads, or StateFence differs from the admitted binding"
                        .to_owned(),
            },
            stale_if_current(task_state),
            stale_if_current(continuity_state),
            stale_if_current(safety_state),
            stale_if_current(affordance_state),
            omissions_state,
        );
    }

    if input.governor.validate().is_err() {
        return incomplete(
            binding,
            work_scope,
            governor,
            role_inputs,
            task_cognition,
            omissions,
            ProjectionState::Unknown {
                reason: "Governor projection owner output failed validation".to_owned(),
            },
            unknown_if_current(task_state),
            unknown_if_current(continuity_state),
            unknown_if_current(safety_state),
            unknown_if_current(affordance_state),
            omissions_state,
        );
    }

    if !role_identity_matches(
        &input.role_inputs.task_frame,
        NamedReadOperation::GetTaskState,
        input.role_inputs,
        &binding,
    ) {
        task_state = read_identity_state(&input.role_inputs.task_frame);
        continuity_state = read_identity_state(&input.role_inputs.task_frame);
    }
    if !role_identity_matches(
        &input.role_inputs.negative_memory,
        NamedReadOperation::GetUnderstandingProjectionInputs,
        input.role_inputs,
        &binding,
    ) {
        safety_state = read_identity_state(&input.role_inputs.negative_memory);
    }
    if !role_identity_matches(
        &input.role_inputs.affordances,
        NamedReadOperation::GetCapabilityEvidenceState,
        input.role_inputs,
        &binding,
    ) {
        affordance_state = read_identity_state(&input.role_inputs.affordances);
    }

    if task_state == ProjectionState::Complete || task_state == ProjectionState::KnownEmpty {
        task_state = task_payload_state(
            input.role_inputs.task_frame.payload.as_ref(),
            &input.task_cognition,
            input.governor.task.as_ref(),
        );
    }
    if continuity_state == ProjectionState::Complete
        || continuity_state == ProjectionState::KnownEmpty
    {
        continuity_state = continuity_payload_state(
            input.role_inputs.task_frame.payload.as_ref(),
            &input.task_cognition,
        );
    }

    if input.governor.task.is_none() {
        task_state = ProjectionState::Missing;
    }
    if input.governor.continuity.is_none() {
        continuity_state = ProjectionState::Missing;
    }
    if input.governor.safety.is_none() {
        safety_state = ProjectionState::Missing;
    }
    if input.governor.affordance.is_none() {
        affordance_state = ProjectionState::Missing;
    }
    if !governor_affordance_matches_scope(&input.governor, input.work_scope, &binding) {
        affordance_state = ProjectionState::Unknown {
            reason:
                "Governor affordance projection differs from the admitted WorkScope owner snapshot"
                    .to_owned(),
        };
    }
    if !negative_memory_matches_safety(
        &input.role_inputs.negative_memory,
        input.governor.safety.as_ref(),
    ) {
        safety_state = unknown_if_current(safety_state);
    }
    if input.role_inputs.affordances.state == ProjectionState::KnownEmpty {
        affordance_state = ProjectionState::Unknown {
            reason: "authoritative empty affordance read cannot ground the required affordance projection".to_owned(),
        };
    }

    if !member_is_complete(&task_state)
        || !member_is_complete(&continuity_state)
        || !member_is_complete(&safety_state)
        || !member_is_complete(&affordance_state)
        || !member_is_complete(&omissions_state)
        || input.governor.task.is_none()
        || input.governor.continuity.is_none()
        || input.governor.safety.is_none()
        || input.governor.affordance.is_none()
    {
        return incomplete(
            binding,
            work_scope,
            governor,
            role_inputs,
            task_cognition,
            omissions,
            ProjectionState::Partial {
                reason:
                    "one or more canonical projection members lack complete retained owner input"
                        .to_owned(),
            },
            task_state,
            continuity_state,
            safety_state,
            affordance_state,
            omissions_state,
        );
    }

    let (Some(task), Some(continuity), Some(safety), Some(affordance)) = (
        input.governor.task.as_ref(),
        input.governor.continuity.as_ref(),
        input.governor.safety.as_ref(),
        input.governor.affordance.as_ref(),
    ) else {
        return incomplete(
            binding,
            work_scope,
            governor,
            role_inputs,
            task_cognition,
            omissions,
            ProjectionState::Partial {
                reason: "Governor owner omitted a required canonical projection member".to_owned(),
            },
            task_state,
            continuity_state,
            safety_state,
            affordance_state,
            omissions_state,
        );
    };
    let commitments = task_cognition.acceptance_descriptions.clone();
    let continuity_note = task_cognition
        .next_allowed_action
        .clone()
        .expect("continuity disposition is complete only with an action");

    let projections = CanonicalProjectionSet {
        binding: binding.clone(),
        task: TaskProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            goal: task.goal.clone(),
            commitments,
        },
        continuity: ContinuityProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            plan_state: continuity.plan_state.clone(),
            continuity_note,
        },
        safety: SafetyProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            safety_note: safety.safety_note.clone(),
            negative_memory_triggers: safety.negative_memory_triggers.clone(),
        },
        affordance: AffordanceProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            affordances: affordance.affordances.clone(),
        },
        omissions: omissions.clone().expect("checked above"),
    };
    if projections.validate().is_err() {
        return incomplete(
            binding,
            work_scope,
            governor,
            role_inputs,
            task_cognition,
            omissions,
            ProjectionState::Unknown {
                reason: "joined canonical projection set failed validation".to_owned(),
            },
            unknown_if_current(task_state),
            unknown_if_current(continuity_state),
            unknown_if_current(safety_state),
            unknown_if_current(affordance_state),
            unknown_if_current(omissions_state),
        );
    }

    OrientationProjectionOwnerOutput {
        projections: Some(projections),
        disposition: ProjectionState::Complete,
        task: task_state,
        continuity: continuity_state,
        safety: safety_state,
        affordance: affordance_state,
        omissions_state,
        binding,
        work_scope,
        governor,
        role_inputs,
        task_cognition,
        omissions,
    }
}

fn incomplete(
    binding: ContextBinding,
    work_scope: WorkScopeBindingSnapshot,
    governor: GovernorProjectionSet,
    role_inputs: SevenRoleInputs,
    task_cognition: OrientationTaskCognitionSnapshot,
    omissions: Option<Vec<OmissionRecord>>,
    disposition: ProjectionState,
    task: ProjectionState,
    continuity: ProjectionState,
    safety: ProjectionState,
    affordance: ProjectionState,
    omissions_state: ProjectionState,
) -> OrientationProjectionOwnerOutput {
    OrientationProjectionOwnerOutput {
        projections: None,
        disposition,
        task,
        continuity,
        safety,
        affordance,
        omissions_state,
        binding,
        work_scope,
        governor,
        role_inputs,
        task_cognition,
        omissions,
    }
}

fn member_is_complete(state: &ProjectionState) -> bool {
    matches!(
        state,
        ProjectionState::Complete | ProjectionState::KnownEmpty
    )
}

fn role_projection_state(role: &RoleAcquisition) -> ProjectionState {
    role.state.clone()
}

fn stale_if_current(state: ProjectionState) -> ProjectionState {
    if member_is_complete(&state) {
        ProjectionState::Stale {
            reason: "source does not share the admitted task, WorkScope, or StateFence".to_owned(),
        }
    } else {
        state
    }
}

fn unknown_if_current(state: ProjectionState) -> ProjectionState {
    if member_is_complete(&state) {
        ProjectionState::Unknown {
            reason: "owner projection could not be joined without loss".to_owned(),
        }
    } else {
        state
    }
}

fn read_identity_state(role: &RoleAcquisition) -> ProjectionState {
    match &role.state {
        ProjectionState::Complete | ProjectionState::KnownEmpty => ProjectionState::Stale {
            reason: "retained read identity does not match the admitted projection source"
                .to_owned(),
        },
        state => state.clone(),
    }
}

fn role_identity_matches(
    role: &RoleAcquisition,
    expected_operation: NamedReadOperation,
    inputs: &SevenRoleInputs,
    binding: &ContextBinding,
) -> bool {
    let Some(identity) = role.identity.as_ref() else {
        return false;
    };
    role.operation == expected_operation
        && identity.operation() == expected_operation
        && identity.source().operation == expected_operation
        && identity.principal().task_id() == Some(&binding.task_id)
        && identity.scope_id() == Some(&inputs.scope_id)
        && identity.state_fence() == &binding.state_fence
        && identity.observed_revision_heads() == role.revision_heads.as_slice()
        && identity.invalidation().state_fence() == identity.state_fence()
        && identity.invalidation().scope_id() == identity.scope_id()
        && identity.invalidation().revision_heads() == identity.observed_revision_heads()
        && role
            .revision_heads
            .iter()
            .all(|head| fences_match_exact(&head.state_fence, &binding.state_fence))
}

fn task_payload_state(
    payload: Option<&Value>,
    source: &OrientationTaskCognitionFields<'_>,
    governor_task: Option<&crate::canonical_projections::GovernorTaskProjection>,
) -> ProjectionState {
    let Some(record) = payload.and_then(|payload| task_record(payload, source.task_id)) else {
        return ProjectionState::Unknown {
            reason: "retained task-frame payload does not contain the projected task source"
                .to_owned(),
        };
    };
    let Some(governor_task) = governor_task else {
        return ProjectionState::Missing;
    };
    let goal_matches =
        record.get("goal").and_then(Value::as_str) == Some(governor_task.goal.as_str());
    let revision_matches =
        record.get("revision").and_then(Value::as_u64) == Some(governor_task.revision);
    if !goal_matches || !revision_matches {
        return ProjectionState::Unknown {
            reason: "retained task-frame goal or revision differs from the Governor projection"
                .to_owned(),
        };
    }
    let contract = record.get("task_contract").unwrap_or(record);
    let Some(items) = contract.get("acceptance_items").and_then(Value::as_array) else {
        return ProjectionState::Unknown {
            reason: "retained task-frame payload omits task_contract.acceptance_items".to_owned(),
        };
    };
    let descriptions_match = items.len() == source.acceptance_descriptions.len()
        && items
            .iter()
            .zip(source.acceptance_descriptions)
            .all(|(item, expected)| {
                item.get("description").and_then(Value::as_str) == Some(*expected)
            });
    if descriptions_match && items.is_empty() {
        ProjectionState::KnownEmpty
    } else if descriptions_match {
        ProjectionState::Complete
    } else {
        ProjectionState::Unknown {
            reason: "retained task-frame acceptance descriptions differ from TaskCognitionView"
                .to_owned(),
        }
    }
}

fn omission_state(
    omissions: Option<&[OmissionRecord]>,
    binding: &ContextBinding,
) -> ProjectionState {
    let Some(omissions) = omissions else {
        return ProjectionState::Missing;
    };
    if omissions
        .iter()
        .any(|record| record.validate(binding).is_err())
    {
        return ProjectionState::Unknown {
            reason: "retained omission record does not match the admitted ContextBinding"
                .to_owned(),
        };
    }
    if omissions.is_empty() {
        ProjectionState::KnownEmpty
    } else {
        ProjectionState::Complete
    }
}

fn negative_memory_matches_safety(
    role: &RoleAcquisition,
    safety: Option<&crate::canonical_projections::GovernorSafetyProjection>,
) -> bool {
    let Some(safety) = safety else {
        return false;
    };
    match (&role.state, role.payload.as_ref()) {
        (ProjectionState::KnownEmpty, Some(payload)) => {
            safety.negative_memory_triggers.is_empty()
                && payload
                    .get("records")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        }
        (ProjectionState::Complete, Some(payload)) => {
            let Some(records) = payload.get("records").and_then(Value::as_array) else {
                return false;
            };
            !safety.negative_memory_triggers.is_empty()
                && safety.negative_memory_triggers.iter().all(|trigger| {
                    records
                        .iter()
                        .any(|record| contains_exact_string(record, trigger))
                })
        }
        _ => false,
    }
}

fn governor_affordance_matches_scope(
    governor: &GovernorProjectionSet,
    work_scope: &WorkScopeBindingSnapshot,
    binding: &ContextBinding,
) -> bool {
    let Some(affordance) = governor.affordance.as_ref() else {
        return false;
    };
    let scope_ref = work_scope.binding.scope.scope_ref.as_str();
    let mut expected = vec![
        scope_ref.to_owned(),
        work_scope.binding.scope.instance_ref.clone(),
    ];
    expected.sort();
    expected.dedup();
    affordance.scope_ref == scope_ref
        && affordance.scope_ref == binding.scope_id.as_str()
        && affordance.affordances == expected
}

fn contains_exact_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(actual) => actual == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| contains_exact_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| contains_exact_string(value, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn continuity_payload_state(
    payload: Option<&Value>,
    source: &OrientationTaskCognitionFields<'_>,
) -> ProjectionState {
    let (Some(active_task_id), Some(next_allowed_action)) =
        (source.active_decision_task_id, source.next_allowed_action)
    else {
        return ProjectionState::Missing;
    };
    if active_task_id != source.task_id || next_allowed_action.trim().is_empty() {
        return ProjectionState::Unknown {
            reason: "active decision state is not bound to the projected task".to_owned(),
        };
    }
    let Some(record) = payload.and_then(|payload| task_record(payload, source.task_id)) else {
        return ProjectionState::Unknown {
            reason: "retained task-frame payload does not contain the active decision source"
                .to_owned(),
        };
    };
    let Some(action) = record
        .get("active_decision_state")
        .and_then(|state| state.get("next_allowed_action"))
        .and_then(Value::as_str)
    else {
        return ProjectionState::Unknown {
            reason: "retained task-frame payload omits active_decision_state.next_allowed_action"
                .to_owned(),
        };
    };
    let stored_task_id = record
        .get("active_decision_state")
        .and_then(|state| state.get("task_id"))
        .and_then(Value::as_str);
    if action == next_allowed_action && stored_task_id == Some(source.task_id.as_str()) {
        ProjectionState::Complete
    } else {
        ProjectionState::Unknown {
            reason: "retained task-frame next action differs from TaskCognitionView".to_owned(),
        }
    }
}

fn task_record<'a>(payload: &'a Value, task_id: &TaskId) -> Option<&'a Value> {
    if payload
        .get("task_contract")
        .and_then(|contract| contract.get("task_id"))
        .and_then(Value::as_str)
        == Some(task_id.as_str())
    {
        return Some(payload);
    }
    if payload.get("task_id").and_then(Value::as_str) == Some(task_id.as_str()) {
        return Some(payload);
    }
    let records = payload.get("records")?.as_array()?;
    records.iter().find(|record| {
        let direct_id = record.get("task_id").and_then(Value::as_str);
        let contract_id = record
            .get("task_contract")
            .and_then(|contract| contract.get("task_id"))
            .and_then(Value::as_str);
        direct_id == Some(task_id.as_str()) || contract_id == Some(task_id.as_str())
    })
}
