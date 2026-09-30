//! Governor-side CC-004 projection assembly for Orientation.
//!
//! The join preserves borrowed owner outputs and read receipts. It copies only
//! bounded fields into shared projections after validating their source,
//! task, scope, and `StateFence` bindings. Missing native owner data remains
//! an explicit member disposition.

use std::collections::BTreeSet;

use eliot_context_candidates::ProjectionState;
use eliot_context_contracts::{
    AffordanceProjection, CANONICAL_PROJECTIONS_SCHEMA_VERSION, CanonicalProjectionSet,
    ContextBinding, ContinuityProjection, MAX_PROJECTION_ENTRIES, MAX_PROJECTION_TEXT,
    MAX_SET_OMISSIONS, OmissionRecord, SafetyProjection, TaskProjection,
};
use eliot_contracts::fences_match_exact;
use eliot_store_api::NamedReadOperation;
use eliot_workscope::{ScopeBindingDisposition, WorkScopeBindingSnapshot};
use serde_json::Value;

use crate::canonical_projections::GovernorProjectionSet;
use crate::context_inputs::{RoleAcquisition, SevenRoleInputs};

/// Original owner values supplied to the projection join.
#[derive(Clone, Copy, Debug)]
pub struct OrientationProjectionOwnerInput<'a> {
    /// Binding admitted for this Orientation operation.
    pub binding: &'a ContextBinding,
    /// Existing Governor projection output.
    pub governor: &'a GovernorProjectionSet,
    /// Retained `WorkScope` owner snapshot admitted for this operation.
    pub work_scope: &'a WorkScopeBindingSnapshot,
    /// Existing seven-role payloads and retained read identities.
    pub role_inputs: &'a SevenRoleInputs,
    /// Original owner-retained omission records; `None` means unavailable.
    pub omissions: Option<&'a [OmissionRecord]>,
}

/// Per-member completion retained when the all-members set is unavailable.
#[derive(Clone, Debug)]
pub struct OrientationProjectionMemberStates {
    /// Task and commitment member.
    pub task: ProjectionState,
    /// Continuity and next-action member.
    pub continuity: ProjectionState,
    /// Safety and negative-memory member.
    pub safety: ProjectionState,
    /// Authorized affordance member.
    pub affordance: ProjectionState,
    /// Original omission-source disposition.
    pub omissions: ProjectionState,
}

/// CC-004 output with partial members and source lineage preserved by borrow.
#[derive(Clone, Debug)]
pub struct OrientationProjectionOwnerOutput<'a> {
    /// Complete shared set only when every source member is grounded.
    pub projections: Option<CanonicalProjectionSet>,
    /// Overall disposition of the join.
    pub disposition: ProjectionState,
    /// Exact disposition for each member.
    pub members: OrientationProjectionMemberStates,
    /// Validated task member, when its named source is available.
    pub task_projection: Option<TaskProjection>,
    /// Validated continuity member, when its named source is available.
    pub continuity_projection: Option<ContinuityProjection>,
    /// Validated safety member, when its exact source is available.
    pub safety_projection: Option<SafetyProjection>,
    /// Validated affordance member, when its capability source is available.
    pub affordance_projection: Option<AffordanceProjection>,
    /// Original admitted binding.
    pub binding: &'a ContextBinding,
    /// Exact `WorkScope` owner snapshot.
    pub work_scope: &'a WorkScopeBindingSnapshot,
    /// Original Governor owner projection, including its omissions.
    pub governor: &'a GovernorProjectionSet,
    /// Original seven-role states, payloads, heads, and read identities.
    pub role_inputs: &'a SevenRoleInputs,
    /// Original retained omission records or explicit source absence.
    pub omissions: Option<&'a [OmissionRecord]>,
}

struct ProjectionParts {
    task: Option<TaskProjection>,
    continuity: Option<ContinuityProjection>,
    safety: Option<SafetyProjection>,
    affordance: Option<AffordanceProjection>,
}

/// Joins admitted task/scope lineage, the native retained task contract, and
/// existing Governor projections without manufacturing absent member data.
#[must_use]
pub fn bind_orientation_projections<'a>(
    input: &OrientationProjectionOwnerInput<'a>,
) -> OrientationProjectionOwnerOutput<'a> {
    let mut members = OrientationProjectionMemberStates {
        task: role_disposition(
            &input.role_inputs.task_frame,
            NamedReadOperation::GetTaskState,
            input,
        ),
        continuity: ProjectionState::Missing,
        safety: role_disposition(
            &input.role_inputs.negative_memory,
            NamedReadOperation::GetUnderstandingProjectionInputs,
            input,
        ),
        affordance: role_disposition(
            &input.role_inputs.affordances,
            NamedReadOperation::GetCapabilityEvidenceState,
            input,
        ),
        omissions: omission_disposition(input.omissions, input.binding),
    };

    if !admitted_lineage_matches(input) {
        mark_complete_members_stale(&mut members);
        return output(
            input,
            members,
            ProjectionParts {
                task: None,
                continuity: None,
                safety: None,
                affordance: None,
            },
            None,
            ProjectionState::Stale {
                reason: "owner lineage differs from the admitted task, scope, or StateFence".to_owned(),
            },
        );
    }

    let task_projection = task_projection(input, &mut members.task);
    let continuity_projection = continuity_projection(input, &mut members.continuity);

    // Governor safety is retained from its observation-journal composer, but
    // the seven-role read does not carry the exact journal identities that
    // produced those triggers. Preserve it as unknown until that owner receipt
    // is part of the read closure.
    if is_complete(&members.safety) {
        members.safety = ProjectionState::Unknown {
            reason: "negative-memory owner record identities are absent from the retained read".to_owned(),
        };
    }
    if is_complete(&members.affordance) {
        members.affordance = ProjectionState::Unknown {
            reason: "scope and instance identities do not establish allowed capabilities".to_owned(),
        };
    }
    let parts = ProjectionParts {
        task: task_projection,
        continuity: continuity_projection,
        safety: None,
        affordance: None,
    };
    let projections = assemble_complete_set(input, &members, &parts);
    let disposition = if projections.is_some() {
        ProjectionState::Complete
    } else if members_complete(&members) {
        ProjectionState::Unknown {
            reason: "complete member dispositions did not validate as one canonical set".to_owned(),
        }
    } else {
        overall_disposition(&members)
    };
    output(input, members, parts, projections, disposition)
}

fn output<'a>(
    input: &OrientationProjectionOwnerInput<'a>,
    members: OrientationProjectionMemberStates,
    parts: ProjectionParts,
    projections: Option<CanonicalProjectionSet>,
    disposition: ProjectionState,
) -> OrientationProjectionOwnerOutput<'a> {
    OrientationProjectionOwnerOutput {
        projections,
        disposition,
        members,
        task_projection: parts.task,
        continuity_projection: parts.continuity,
        safety_projection: parts.safety,
        affordance_projection: parts.affordance,
        binding: input.binding,
        work_scope: input.work_scope,
        governor: input.governor,
        role_inputs: input.role_inputs,
        omissions: input.omissions,
    }
}

fn assemble_complete_set(
    input: &OrientationProjectionOwnerInput<'_>,
    members: &OrientationProjectionMemberStates,
    parts: &ProjectionParts,
) -> Option<CanonicalProjectionSet> {
    if !members_complete(members) {
        return None;
    }
    let (Some(task), Some(continuity), Some(safety), Some(affordance), Some(omissions)) = (
        parts.task.as_ref(),
        parts.continuity.as_ref(),
        parts.safety.as_ref(),
        parts.affordance.as_ref(),
        input.omissions,
    ) else {
        return None;
    };
    let projections = CanonicalProjectionSet {
        binding: input.binding.clone(),
        task: task.clone(),
        continuity: continuity.clone(),
        safety: safety.clone(),
        affordance: affordance.clone(),
        omissions: omissions.to_vec(),
    };
    projections.validate().ok().map(|()| projections)
}

fn admitted_lineage_matches(input: &OrientationProjectionOwnerInput<'_>) -> bool {
    let binding = input.binding;
    let roles = input.role_inputs;
    let scope = input.work_scope;
    let governor = input.governor;
    binding.validate().is_ok()
        && scope.validate().is_ok()
        && governor.validate().is_ok()
        && roles.scope_id == binding.scope_id
        && fences_match_exact(&roles.state_fence, &binding.state_fence)
        && roles.heads_before == roles.heads_after
        && roles.heads_before.scope_id == roles.scope_id
        && fences_match_exact(&roles.heads_before.state_fence, &binding.state_fence)
        && fences_match_exact(&roles.heads_after.state_fence, &binding.state_fence)
        && fences_match_exact(&scope.state_fence, &binding.state_fence)
        && scope.binding.scope.scope_ref == binding.scope_id.as_str()
        && scope.guard_receipt.disposition == ScopeBindingDisposition::Matched
        && scope.guard_receipt.expected_scope_ref == binding.scope_id.as_str()
        && scope.guard_receipt.observed_scope_ref == binding.scope_id.as_str()
        && governor.task_id == binding.task_id
        && governor.scope_ref == binding.scope_id.as_str()
        && governor.is_compatible_with(&binding.state_fence)
}

fn role_disposition(
    role: &RoleAcquisition,
    operation: NamedReadOperation,
    input: &OrientationProjectionOwnerInput<'_>,
) -> ProjectionState {
    match &role.state {
        ProjectionState::Complete | ProjectionState::KnownEmpty
            if !role_identity_matches(role, operation, input) =>
        {
            ProjectionState::Stale {
                reason: "retained read identity differs from the admitted source closure".to_owned(),
            }
        }
        state => state.clone(),
    }
}

fn role_identity_matches(
    role: &RoleAcquisition,
    operation: NamedReadOperation,
    input: &OrientationProjectionOwnerInput<'_>,
) -> bool {
    let Some(identity) = role.identity.as_ref() else {
        return false;
    };
    let roles = input.role_inputs;
    let binding = input.binding;
    role.operation == operation
        && identity.operation() == operation
        && identity.source().operation == operation
        && !identity.source().operation_name.is_empty()
        && !identity.source().manifest_name.is_empty()
        && !identity.source().manifest_digest.is_empty()
        && identity.principal().task_id() == Some(&binding.task_id)
        && identity.scope_id() == Some(&roles.scope_id)
        && identity.state_fence() == &binding.state_fence
        && role.revision_heads.as_slice() == roles.heads_before.revision_heads.as_slice()
        && identity.observed_revision_heads() == roles.heads_before.revision_heads.as_slice()
        && identity.declared_dependency_revisions().iter().all(|(key, revision)| {
            roles
                .heads_before
                .revision_heads
                .iter()
                .any(|head| &head.key == key && head.revision == *revision)
        })
        && identity.invalidation().state_fence() == identity.state_fence()
        && identity.invalidation().scope_id() == identity.scope_id()
        && identity.invalidation().revision_heads() == identity.observed_revision_heads()
        && identity.invalidation().source() == identity.source()
        && identity.invalidation().schema() == identity.schema()
        && role
            .revision_heads
            .iter()
            .all(|head| fences_match_exact(&head.state_fence, &binding.state_fence))
}

fn task_projection(
    input: &OrientationProjectionOwnerInput<'_>,
    disposition: &mut ProjectionState,
) -> Option<TaskProjection> {
    if !role_identity_matches(
        &input.role_inputs.task_frame,
        NamedReadOperation::GetTaskState,
        input,
    ) {
        *disposition = role_disposition(
            &input.role_inputs.task_frame,
            NamedReadOperation::GetTaskState,
            input,
        );
        return None;
    }
    let Some(owner_task) = input.governor.task.as_ref() else {
        *disposition = ProjectionState::Missing;
        return None;
    };
    let record = match retained_task_contract(input.role_inputs.task_frame.payload.as_ref()) {
        Ok(Some(record)) => record,
        Ok(None) => {
            *disposition = ProjectionState::Missing;
            return None;
        }
        Err(state) => {
            *disposition = state;
            return None;
        }
    };
    let task_id = record.get("task_id").and_then(Value::as_str);
    let goal = record.get("title").and_then(Value::as_str);
    let items = record.get("acceptance_items").and_then(Value::as_array);
    let has_native_revision = record.get("memory_revision").and_then(Value::as_u64).is_some()
        && record.get("project_sequence").and_then(Value::as_u64).is_some()
        && record.get("write_id").and_then(Value::as_str).is_some_and(|id| !id.is_empty());
    let Some(((task_id, goal), items)) = task_id.zip(goal).zip(items) else {
        *disposition = ProjectionState::Unknown {
            reason: "retained task contract lacks typed identity, goal, or acceptance items".to_owned(),
        };
        return None;
    };
    if task_id != input.binding.task_id.as_str()
        || owner_task.task_id != input.binding.task_id
        || goal != owner_task.goal
        || !has_native_revision
        || items.len() > MAX_PROJECTION_ENTRIES
    {
        *disposition = ProjectionState::Unknown {
            reason: "retained task contract differs from the admitted task projection".to_owned(),
        };
        return None;
    }

    let mut seen = BTreeSet::new();
    let mut descriptions = Vec::with_capacity(items.len());
    for item in items {
        let Some(description) = item.get("description").and_then(Value::as_str) else {
            *disposition = ProjectionState::Unknown {
                reason: "retained task acceptance item has no typed description".to_owned(),
            };
            return None;
        };
        if description.trim().is_empty()
            || description.chars().any(char::is_control)
            || description.len() > MAX_PROJECTION_TEXT
            || !seen.insert(description)
        {
            *disposition = ProjectionState::Unknown {
                reason: "retained task commitments fail projection bounds or uniqueness".to_owned(),
            };
            return None;
        }
        descriptions.push(description.to_owned());
    }

    let projection = TaskProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: input.binding.clone(),
        goal: goal.to_owned(),
        commitments: descriptions,
    };
    if projection.validate().is_err() {
        *disposition = ProjectionState::Unknown {
            reason: "retained task contract fails the shared task projection contract".to_owned(),
        };
        return None;
    }
    *disposition = if projection.commitments.is_empty() {
        ProjectionState::KnownEmpty
    } else {
        ProjectionState::Complete
    };
    Some(projection)
}

fn retained_task_contract(payload: Option<&Value>) -> Result<Option<&Value>, ProjectionState> {
    let Some(source) = payload.and_then(|payload| payload.get("retained_task_contract")) else {
        return Err(ProjectionState::Unknown {
            reason: "GetTaskState did not return the retained task-contract disposition".to_owned(),
        });
    };
    match source.get("availability").and_then(Value::as_str) {
        Some("present") => source
            .get("record")
            .filter(|record| record.is_object())
            .map(Some)
            .ok_or_else(|| ProjectionState::Unknown {
                reason: "retained task-contract record is malformed".to_owned(),
            }),
        Some("absent") => Ok(None),
        _ => Err(ProjectionState::Unknown {
            reason: "retained task-contract disposition is malformed".to_owned(),
        }),
    }
}

fn continuity_projection(
    input: &OrientationProjectionOwnerInput<'_>,
    disposition: &mut ProjectionState,
) -> Option<ContinuityProjection> {
    if !role_identity_matches(
        &input.role_inputs.task_frame,
        NamedReadOperation::GetTaskState,
        input,
    ) {
        *disposition = role_disposition(
            &input.role_inputs.task_frame,
            NamedReadOperation::GetTaskState,
            input,
        );
        return None;
    }
    let Some(owner_continuity) = input.governor.continuity.as_ref() else {
        *disposition = ProjectionState::Missing;
        return None;
    };
    if owner_continuity.task_id != input.binding.task_id {
        *disposition = ProjectionState::Stale {
            reason: "continuity task differs from the admitted task".to_owned(),
        };
        return None;
    }
    let payload = input
        .role_inputs
        .task_frame
        .payload
        .as_ref();
    let Some(active) = payload.and_then(|payload| payload.get("active_decision_state")) else {
        *disposition = ProjectionState::Missing;
        return None;
    };
    let (Some(task_id), Some(action)) = (
        active.get("task_id").and_then(Value::as_str),
        active.get("next_allowed_action").and_then(Value::as_str),
    ) else {
        *disposition = ProjectionState::Unknown {
            reason: "retained active decision omits its task id or allowed action".to_owned(),
        };
        return None;
    };
    if task_id != input.binding.task_id.as_str()
        || action.trim().is_empty()
        || action.chars().any(char::is_control)
        || action.len() > MAX_PROJECTION_TEXT
    {
        *disposition = ProjectionState::Unknown {
            reason: "retained active decision is malformed or belongs to another task".to_owned(),
        };
        return None;
    }
    let projection = ContinuityProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: input.binding.clone(),
        plan_state: owner_continuity.plan_state.clone(),
        continuity_note: action.to_owned(),
    };
    if projection.validate().is_err() {
        *disposition = ProjectionState::Unknown {
            reason: "retained continuity member fails the shared projection contract".to_owned(),
        };
        return None;
    }
    *disposition = ProjectionState::Complete;
    Some(projection)
}

fn omission_disposition(
    omissions: Option<&[OmissionRecord]>,
    binding: &ContextBinding,
) -> ProjectionState {
    let Some(omissions) = omissions else {
        return ProjectionState::Missing;
    };
    if omissions.len() > MAX_SET_OMISSIONS
        || omissions.iter().any(|record| record.validate(binding).is_err())
    {
        return ProjectionState::Unknown {
            reason: "original omission records exceed bounds or differ from the binding".to_owned(),
        };
    }
    if omissions.is_empty() {
        ProjectionState::KnownEmpty
    } else {
        ProjectionState::Complete
    }
}

fn mark_complete_members_stale(members: &mut OrientationProjectionMemberStates) {
    for state in [
        &mut members.task,
        &mut members.continuity,
        &mut members.safety,
        &mut members.affordance,
        &mut members.omissions,
    ] {
        if matches!(state, ProjectionState::Complete | ProjectionState::KnownEmpty) {
            *state = ProjectionState::Stale {
                reason: "member source differs from the admitted ContextBinding".to_owned(),
            };
        }
    }
}

fn members_complete(members: &OrientationProjectionMemberStates) -> bool {
    [
        &members.task,
        &members.continuity,
        &members.safety,
        &members.affordance,
        &members.omissions,
    ]
    .into_iter()
    .all(|state| matches!(state, ProjectionState::Complete | ProjectionState::KnownEmpty))
}

fn is_complete(state: &ProjectionState) -> bool {
    matches!(state, ProjectionState::Complete | ProjectionState::KnownEmpty)
}

fn overall_disposition(members: &OrientationProjectionMemberStates) -> ProjectionState {
    if members_complete(members) {
        return ProjectionState::Complete;
    }
    if [
        &members.task,
        &members.continuity,
        &members.safety,
        &members.affordance,
        &members.omissions,
    ]
    .into_iter()
    .any(|state| matches!(state, ProjectionState::Stale { .. }))
    {
        return ProjectionState::Stale {
            reason: "one or more projection members are bound to stale owner data".to_owned(),
        };
    }
    ProjectionState::Partial {
        reason: "one or more retained owner members are missing or unknown".to_owned(),
    }
}
