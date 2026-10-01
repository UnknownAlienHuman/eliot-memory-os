//! Governor-side CC-004 projection assembly for Orientation.
//!
//! The join preserves borrowed owner outputs and read receipts. It copies only
//! bounded fields into shared projections after validating their source,
//! task, scope, and `StateFence` bindings. Missing native owner data remains
//! an explicit member disposition.

use std::collections::BTreeSet;

use eliot_agent_api::RouteFingerprint;
use eliot_context_candidates::ProjectionState;
use eliot_context_contracts::{
    AffordanceProjection, CANONICAL_PROJECTIONS_SCHEMA_VERSION, CanonicalProjectionSet,
    ContextBinding, ContinuityProjection, MAX_PROJECTION_ENTRIES, MAX_PROJECTION_TEXT,
    MAX_SET_OMISSIONS, OmissionRecord, SafetyProjection, TaskProjection,
};
use eliot_contracts::fences_match_exact;
use eliot_dreamer_failure::NegativeMemoryDisposition;
use eliot_read::{DeclaredResultSelector, ReadCoverage, ReadIdentity};
use eliot_store_api::{NamedReadOperation, NamedReadRequest, ReadConsistency, ScopeRevisionView};
use eliot_workscope::{ScopeBindingDisposition, WorkScopeBindingSnapshot};
use serde::Serialize;
use serde_json::Value;

use crate::canonical_projections::GovernorProjectionSet;
use crate::context_inputs::{
    ContextReconstructionRequest, RetainedCapabilityEvidenceRecord, RoleAcquisition,
    SevenRoleInputs,
};
use crate::{CapabilityRegistry, RouteScopeFingerprint};

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
    /// Exact original request used to acquire those seven roles.
    pub context_request: &'a ContextReconstructionRequest,
    /// Original owner-retained omission records; `None` means unavailable.
    pub omissions: Option<&'a [OmissionRecord]>,
    /// Full original execution-observed physical route from the W3 owner.
    pub original_route: Option<&'a RouteFingerprint>,
    /// Current complete capability scope retained by the route admission owner.
    pub current_route_scope: Option<&'a RouteScopeFingerprint>,
    /// Current owner-supplied evaluation instant used by capability admission.
    pub capability_now: Option<u64>,
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

/// Full original Governor read closure preserved for packet provenance.
///
/// This borrows the exact request and role readback, including every original
/// `ReadIdentity`, named request, owner payload, disposition, and the before /
/// after source snapshots. Consumers commit these retained owner values as
/// supplied; this type adds no derived digest or replacement identity.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct OrientationProjectionSourceClosure<'a> {
    /// Exact source request used to acquire the seven roles.
    pub context_request: &'a ContextReconstructionRequest,
    /// Exact Governor readback, with original read identities and payloads.
    pub role_inputs: &'a SevenRoleInputs,
    /// Exact source snapshot captured before those reads.
    pub source_snapshot_before: &'a ScopeRevisionView,
    /// Exact source snapshot captured after those reads.
    pub source_snapshot_after: &'a ScopeRevisionView,
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
    /// Full original read closure to bind into downstream packet provenance.
    pub source_closure: OrientationProjectionSourceClosure<'a>,
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
    /// Exact source snapshot observed before role acquisition; the retained
    /// after-view is equal when the join accepts this lineage.
    pub source_snapshot: &'a ScopeRevisionView,
    /// Exact original request used to acquire those seven roles.
    pub context_request: &'a ContextReconstructionRequest,
    /// Original retained omission records or explicit source absence.
    pub omissions: Option<&'a [OmissionRecord]>,
    /// Full original execution-observed physical route from the W3 owner.
    pub original_route: Option<&'a RouteFingerprint>,
    /// Current complete capability scope retained by the route admission owner.
    pub current_route_scope: Option<&'a RouteScopeFingerprint>,
    /// Current owner-supplied evaluation instant used by capability admission.
    pub capability_now: Option<u64>,
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
            NamedReadOperation::GetLearningRecordRange,
            input,
        ),
        affordance: role_disposition(
            &input.role_inputs.affordances,
            NamedReadOperation::GetCapabilityEvidenceRecordRange,
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
                reason: "owner lineage differs from the admitted task, scope, or StateFence"
                    .to_owned(),
            },
        );
    }

    let task_projection = task_projection(input, &mut members.task);
    let continuity_projection = continuity_projection(input, &mut members.continuity);
    let safety_projection = safety_projection(input, &mut members.safety);
    let affordance_projection = affordance_projection(input, &mut members.affordance);
    let parts = ProjectionParts {
        task: task_projection,
        continuity: continuity_projection,
        safety: safety_projection,
        affordance: affordance_projection,
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
        source_closure: OrientationProjectionSourceClosure {
            context_request: input.context_request,
            role_inputs: input.role_inputs,
            source_snapshot_before: &input.role_inputs.heads_before,
            source_snapshot_after: &input.role_inputs.heads_after,
        },
        task_projection: parts.task,
        continuity_projection: parts.continuity,
        safety_projection: parts.safety,
        affordance_projection: parts.affordance,
        binding: input.binding,
        work_scope: input.work_scope,
        governor: input.governor,
        role_inputs: input.role_inputs,
        source_snapshot: &input.role_inputs.heads_before,
        context_request: input.context_request,
        omissions: input.omissions,
        original_route: input.original_route,
        current_route_scope: input.current_route_scope,
        capability_now: input.capability_now,
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
        && input.context_request.validate().is_ok()
        && scope.validate().is_ok()
        && governor.validate().is_ok()
        && input.context_request.task_id == binding.task_id.as_str()
        && input.context_request.scope_id.as_str() == binding.scope_id.as_str()
        && roles.scope_id.as_str() == binding.scope_id.as_str()
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
        ProjectionState::Complete
        | ProjectionState::KnownEmpty
        | ProjectionState::Partial { .. }
            if !role_identity_matches(role, operation, input) =>
        {
            ProjectionState::Stale {
                reason: "retained read identity differs from the admitted source closure"
                    .to_owned(),
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
        && role_source_request_matches(role, identity, operation, input)
        && role.revision_heads.as_slice() == roles.heads_before.revision_heads.as_slice()
        && identity.observed_revision_heads() == roles.heads_before.revision_heads.as_slice()
        && identity
            .declared_dependency_revisions()
            .iter()
            .all(|(key, revision)| {
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

fn role_source_request_matches(
    role: &RoleAcquisition,
    identity: &ReadIdentity,
    operation: NamedReadOperation,
    input: &OrientationProjectionOwnerInput<'_>,
) -> bool {
    if !matches!(
        operation,
        NamedReadOperation::GetLearningRecordRange
            | NamedReadOperation::GetCapabilityEvidenceRecordRange
    ) {
        return role.source_request.is_none();
    }
    let Some(request) = role.source_request.as_ref() else {
        return false;
    };
    if request.validate().is_err()
        || request.operation != operation
        || request.scope_id.as_ref() != Some(&input.role_inputs.scope_id)
        || request.state_fence != input.binding.state_fence
        || request.consistency != ReadConsistency::ExactFence
        || request.parameters.len() != 2
        || request.parameters.contains_key("cursor")
    {
        return false;
    }
    let max_records = match operation {
        NamedReadOperation::GetLearningRecordRange => {
            let Ok(decoded) = eliot_store_api::decode_learning_read(operation, &request.parameters)
            else {
                return false;
            };
            if decoded.record_kind != Some(eliot_store_api::LearningRecordKind::ActivationReceipt) {
                return false;
            }
            decoded.max_records
        }
        NamedReadOperation::GetCapabilityEvidenceRecordRange => {
            let Ok(decoded) =
                eliot_store_api::decode_capability_evidence_read(operation, &request.parameters)
            else {
                return false;
            };
            if decoded.skill_id.is_none() {
                return false;
            }
            decoded.max_records
        }
        _ => return false,
    };
    let expected_coverage = ReadCoverage::BoundedByDeclaredSelector {
        selector: DeclaredResultSelector::MaxRecords,
        declared_bound: u32::from(max_records),
    };
    if identity.coverage() != expected_coverage {
        return false;
    }
    true
}

fn safety_projection(
    input: &OrientationProjectionOwnerInput<'_>,
    disposition: &mut ProjectionState,
) -> Option<SafetyProjection> {
    let role = &input.role_inputs.negative_memory;
    if !is_complete(&role.state) {
        return None;
    }
    if !role_identity_matches(role, NamedReadOperation::GetLearningRecordRange, input) {
        *disposition = role_disposition(role, NamedReadOperation::GetLearningRecordRange, input);
        return None;
    }
    let Some(owner_safety) = input.governor.safety.as_ref() else {
        *disposition = ProjectionState::Missing;
        return None;
    };
    if owner_safety.task_id != input.binding.task_id {
        *disposition = ProjectionState::Stale {
            reason: "safety projection belongs to another admitted task".to_owned(),
        };
        return None;
    }
    let (Some(records), Some(policies)) = (
        role.retained_negative_memory_records.as_deref(),
        role.retained_negative_memory_policies.as_deref(),
    ) else {
        *disposition = ProjectionState::Unknown {
            reason: "activation receipt read did not retain its original typed rules and policies"
                .to_owned(),
        };
        return None;
    };
    let Some(triggers) = negative_memory_triggers(role.payload.as_ref(), records, policies) else {
        *disposition = ProjectionState::Unknown {
            reason: "typed negative-memory rules differ from the original activation receipt rows"
                .to_owned(),
        };
        return None;
    };
    if triggers.len() > MAX_PROJECTION_ENTRIES {
        *disposition = ProjectionState::Unknown {
            reason: "retained negative-memory trigger identities exceed the projection bound"
                .to_owned(),
        };
        return None;
    }
    let projection = SafetyProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: input.binding.clone(),
        safety_note: owner_safety.safety_note.clone(),
        negative_memory_triggers: triggers,
    };
    if projection.validate().is_err() {
        *disposition = ProjectionState::Unknown {
            reason: "retained safety sources fail the shared projection contract".to_owned(),
        };
        return None;
    }
    *disposition = if projection.negative_memory_triggers.is_empty() {
        ProjectionState::KnownEmpty
    } else {
        ProjectionState::Complete
    };
    Some(projection)
}

fn negative_memory_triggers(
    payload: Option<&Value>,
    records: &[eliot_dreamer_failure::NegativeMemoryFingerprint],
    policies: &[eliot_dreamer_failure::NegativeMemoryActionPolicy],
) -> Option<Vec<String>> {
    let rows = payload
        .and_then(|payload| payload.get("records"))
        .and_then(Value::as_array)?;
    if rows.len() != records.len() || records.len() != policies.len() {
        return None;
    }
    let mut seen = BTreeSet::new();
    let mut triggers = Vec::new();
    for (row, (record, policy)) in rows.iter().zip(records.iter().zip(policies)) {
        let record_json = row.get("record_json").and_then(Value::as_str)?;
        let document =
            serde_json::from_str::<crate::NegativeMemoryActivationDocument>(record_json).ok()?;
        let handle = row.get("handle").and_then(Value::as_str)?;
        if row.get("record_kind").and_then(Value::as_str)
            != Some(eliot_store_api::LearningRecordKind::ActivationReceipt.as_str())
            || handle != document.handle()
            || document.record != *record
            || document.policy != *policy
            || policy.binding.record_id != record.record_id
            || policy.binding.rule_revision != record.rule_revision
            || policy.binding.record_digest != record.record_digest
        {
            return None;
        }
        if record.has_admitted_trigger()
            && policy.disposition != NegativeMemoryDisposition::Advisory
        {
            if handle.len() > MAX_PROJECTION_TEXT || !seen.insert(handle) {
                return None;
            }
            triggers.push(handle.to_owned());
        }
    }
    Some(triggers)
}

fn affordance_projection(
    input: &OrientationProjectionOwnerInput<'_>,
    disposition: &mut ProjectionState,
) -> Option<AffordanceProjection> {
    let records = retained_capability_records(input, disposition)?;
    let skill_id = admitted_capability_skill(input, records, disposition)?;
    let projection = AffordanceProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: input.binding.clone(),
        affordances: vec![skill_id.to_owned()],
    };
    if projection.validate().is_err() {
        *disposition = ProjectionState::Unknown {
            reason: "admitted capability fails the shared affordance projection contract"
                .to_owned(),
        };
        return None;
    }
    *disposition = ProjectionState::Complete;
    Some(projection)
}

fn retained_capability_records<'a>(
    input: &OrientationProjectionOwnerInput<'a>,
    disposition: &mut ProjectionState,
) -> Option<&'a [RetainedCapabilityEvidenceRecord]> {
    let role = &input.role_inputs.affordances;
    if !is_complete(&role.state) {
        return None;
    }
    if !role_identity_matches(
        role,
        NamedReadOperation::GetCapabilityEvidenceRecordRange,
        input,
    ) {
        *disposition = role_disposition(
            role,
            NamedReadOperation::GetCapabilityEvidenceRecordRange,
            input,
        );
        return None;
    }
    let (Some(records), Some(payload)) = (
        role.retained_capability_records.as_deref(),
        role.payload.as_ref(),
    ) else {
        *disposition = ProjectionState::Unknown {
            reason: "capability range did not retain its original typed evidence rows".to_owned(),
        };
        return None;
    };
    let Some(request) = role.source_request.as_ref() else {
        *disposition = ProjectionState::Unknown {
            reason: "capability range did not retain its original selector request".to_owned(),
        };
        return None;
    };
    if !capability_rows_match(payload, records, request) {
        *disposition = ProjectionState::Unknown {
            reason: "typed capability evidence differs from the original range rows".to_owned(),
        };
        return None;
    }
    if records.is_empty() {
        *disposition = ProjectionState::KnownEmpty;
        return None;
    }
    Some(records)
}

fn admitted_capability_skill<'a>(
    input: &OrientationProjectionOwnerInput<'_>,
    records: &'a [RetainedCapabilityEvidenceRecord],
    disposition: &mut ProjectionState,
) -> Option<&'a str> {
    let Some(route) = input.original_route else {
        *disposition = ProjectionState::Unknown {
            reason: "the full execution-observed route is absent from the owner join".to_owned(),
        };
        return None;
    };
    if route.validate().is_err() {
        *disposition = ProjectionState::Unknown {
            reason: "the execution-observed route failed its original validator".to_owned(),
        };
        return None;
    }
    let Some(current_scope) = input.current_route_scope else {
        *disposition = ProjectionState::Unknown {
            reason: "the route admission owner did not retain its complete current scope"
                .to_owned(),
        };
        return None;
    };
    if !route_scope_is_complete(current_scope) {
        *disposition = ProjectionState::Unknown {
            reason: "the current capability route scope carries unknown dimensions".to_owned(),
        };
        return None;
    }
    if !route_matches_capability_scope(route, current_scope) {
        *disposition = ProjectionState::Unknown {
            reason: "current capability scope does not bind the full execution-observed route"
                .to_owned(),
        };
        return None;
    }
    let Some(now) = input.capability_now else {
        *disposition = ProjectionState::Unknown {
            reason: "the route admission owner did not retain its evaluation instant".to_owned(),
        };
        return None;
    };
    if records.len() > MAX_PROJECTION_ENTRIES {
        *disposition = ProjectionState::Unknown {
            reason: "capability evidence exceeds the affordance projection bound".to_owned(),
        };
        return None;
    }
    let mut skills = BTreeSet::new();
    let mut registry = CapabilityRegistry::new();
    for retained in records {
        skills.insert(retained.record.skill_id.as_str());
        if !registry.insert(retained.record.clone(), retained.revision.clone()) {
            *disposition = ProjectionState::Unknown {
                reason: "capability evidence could not be retained by its bounded registry"
                    .to_owned(),
            };
            return None;
        }
    }
    if skills.len() != 1 {
        *disposition = ProjectionState::Unknown {
            reason: "capability range contains more than one requested skill identity".to_owned(),
        };
        return None;
    }
    let Some(skill_id) = skills.into_iter().next() else {
        *disposition = ProjectionState::Unknown {
            reason: "capability range has no skill identity".to_owned(),
        };
        return None;
    };
    if !registry.admit_production_route(skill_id, current_scope, now) {
        *disposition = ProjectionState::Blocked {
            reason: "retained capability evidence does not admit the exact observed route"
                .to_owned(),
        };
        return None;
    }
    Some(skill_id)
}

fn capability_rows_match(
    payload: &Value,
    retained: &[RetainedCapabilityEvidenceRecord],
    request: &NamedReadRequest,
) -> bool {
    let Some(rows) = payload.get("records").and_then(Value::as_array) else {
        return false;
    };
    if rows.len() != retained.len() {
        return false;
    }
    rows.iter().zip(retained).all(|(row, retained)| {
        let Some(record_json) = row.get("record_json").and_then(Value::as_str) else {
            return false;
        };
        let Ok(record) = serde_json::from_str::<crate::CapabilityEvidenceRecord>(record_json)
        else {
            return false;
        };
        record == retained.record
            && row.get("skill_id").and_then(Value::as_str)
                == request.parameters.get("skill_id").and_then(Value::as_str)
            && row.get("skill_id").and_then(Value::as_str)
                == Some(retained.record.skill_id.as_str())
            && row.get("scope_key").and_then(Value::as_str) == Some(retained.scope_key.as_str())
            && row.get("record_digest").and_then(Value::as_str)
                == Some(retained.revision.evidence_ref.as_str())
            && row.get("revision").and_then(Value::as_u64) == Some(retained.revision.owner_revision)
    })
}

fn route_scope_is_complete(scope: &RouteScopeFingerprint) -> bool {
    [
        scope.host_family.as_deref(),
        scope.adapter_id.as_deref(),
        scope.protocol_transport.as_deref(),
        scope.runtime_hash.as_deref(),
        scope.adapter_hash.as_deref(),
        scope.os_architecture.as_deref(),
        scope.auth_profile_class.as_deref(),
        scope.provider_model_route.as_deref(),
        scope.tool_call_id_and_role_ordering.as_deref(),
        scope.reasoning_continuation_and_compaction.as_deref(),
        scope.feature_flags_and_serializer.as_deref(),
    ]
    .into_iter()
    .all(|field| {
        field.is_some_and(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
    })
}

fn route_matches_capability_scope(route: &RouteFingerprint, scope: &RouteScopeFingerprint) -> bool {
    Some(route.host_family.as_str()) == scope.host_family.as_deref()
        && Some(route.adapter.as_str()) == scope.adapter_id.as_deref()
        && Some(route.protocol_transport.as_str()) == scope.protocol_transport.as_deref()
        && Some(route.runtime_hash.as_str()) == scope.runtime_hash.as_deref()
        && Some(route.adapter_hash.as_str()) == scope.adapter_hash.as_deref()
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
    let has_native_revision = record
        .get("memory_revision")
        .and_then(Value::as_u64)
        .is_some()
        && record
            .get("project_sequence")
            .and_then(Value::as_u64)
            .is_some()
        && record
            .get("write_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty());
    let Some(((task_id, goal), items)) = task_id.zip(goal).zip(items) else {
        *disposition = ProjectionState::Unknown {
            reason: "retained task contract lacks typed identity, goal, or acceptance items"
                .to_owned(),
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
    let Some(payload) = input.role_inputs.task_frame.payload.as_ref() else {
        *disposition = ProjectionState::Unknown {
            reason: "GetTaskState omitted its retained task event payload".to_owned(),
        };
        return None;
    };
    let Ok(Some(task_contract)) = retained_task_contract(Some(payload)) else {
        *disposition = ProjectionState::Unknown {
            reason: "active decision cannot bind to a retained native task-contract revision"
                .to_owned(),
        };
        return None;
    };
    let Some(memory_revision) = task_contract.get("memory_revision").and_then(Value::as_u64) else {
        *disposition = ProjectionState::Unknown {
            reason: "retained task contract omits its original memory revision".to_owned(),
        };
        return None;
    };
    let continuity_note =
        match retained_active_decision_action(payload, input.binding, memory_revision) {
            Ok(action) => action,
            Err(state) => {
                *disposition = state;
                return None;
            }
        };
    let projection = ContinuityProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: input.binding.clone(),
        plan_state: owner_continuity.plan_state.clone(),
        continuity_note,
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

fn retained_active_decision_action(
    payload: &Value,
    binding: &ContextBinding,
    task_contract_revision: u64,
) -> Result<String, ProjectionState> {
    let current = payload.get("current").ok_or(ProjectionState::Missing)?;
    let event_json = current
        .get("task_event_json")
        .and_then(Value::as_str)
        .ok_or(ProjectionState::Missing)?;
    let operation_id = current
        .get("operation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| ProjectionState::Unknown {
            reason: "latest task row omits its committed operation identity".to_owned(),
        })?;
    let _ = eliot_store_api::OperationId::new(operation_id.to_owned()).map_err(|_| {
        ProjectionState::Unknown {
            reason: "latest task row carries a malformed committed operation identity".to_owned(),
        }
    })?;
    let expected_revision = current
        .get("expected_revision")
        .and_then(canonical_positive_revision)
        .ok_or_else(|| ProjectionState::Unknown {
            reason: "latest task row omits its persisted expected revision".to_owned(),
        })?;
    let resulting_revision = current
        .get("resulting_revision")
        .and_then(canonical_positive_revision)
        .ok_or_else(|| ProjectionState::Unknown {
            reason: "latest task row omits its persisted resulting revision".to_owned(),
        })?;
    let receipt_fence =
        current
            .get("receipt_state_fence")
            .cloned()
            .ok_or_else(|| ProjectionState::Unknown {
                reason: "latest task row omits its original receipt StateFence".to_owned(),
            })?;
    let receipt_fence: eliot_contracts::StateFence = serde_json::from_value(receipt_fence)
        .map_err(|_| ProjectionState::Unknown {
            reason: "latest task row has a malformed original receipt StateFence".to_owned(),
        })?;
    let receipt_value =
        current
            .get("write_receipt")
            .cloned()
            .ok_or_else(|| ProjectionState::Unknown {
                reason: "latest task row omits its original committed WriteReceipt".to_owned(),
            })?;
    let receipt: eliot_store_api::WriteReceipt =
        serde_json::from_value(receipt_value).map_err(|_| ProjectionState::Unknown {
            reason: "latest task row has a malformed original WriteReceipt".to_owned(),
        })?;
    receipt.validate().map_err(|_| ProjectionState::Unknown {
        reason: "latest task row's original WriteReceipt fails validation".to_owned(),
    })?;
    let receipt_envelope =
        receipt
            .require_reconciliation_envelope()
            .map_err(|_| ProjectionState::Unknown {
                reason: "latest task row's original WriteReceipt lacks its owner envelope"
                    .to_owned(),
            })?;
    let read_scope_id = payload
        .get("scope_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ProjectionState::Unknown {
            reason: "GetTaskState omitted the exact retained read scope".to_owned(),
        })?;
    let event: eliot_task::TaskLifecycleEvent =
        serde_json::from_str(event_json).map_err(|_| ProjectionState::Unknown {
            reason: "retained TaskController event does not decode as its original type".to_owned(),
        })?;
    let Some(eliot_task::TaskCommand::SetActiveDecisionState { decision }) = &event.command else {
        return Err(ProjectionState::Missing);
    };
    let Some(active) = event.active_decision_state.as_ref() else {
        return Err(ProjectionState::Unknown {
            reason: "TaskController command omitted its retained active decision".to_owned(),
        });
    };
    let resulting_from_expected = expected_revision.checked_add(1);
    let current_task_revision = binding
        .state_fence
        .task_revision
        .as_ref()
        .map(|revision| revision.value());
    if current.get("task_id").and_then(Value::as_str) != Some(binding.task_id.as_str())
        || current.get("event_id").and_then(Value::as_str) != Some(event.event_id.as_str())
        || current.get("actor_ref").and_then(Value::as_str) != Some(event.actor_ref.as_str())
        || !task_state_row_matches_event(current, &event)
        || event.task_id.as_str() != binding.task_id.as_str()
        || decision.task_id.to_string() != binding.task_id.as_str()
        || active != decision.as_ref()
        || event.state_fence.validate().is_err()
        || receipt_fence != event.state_fence
        || receipt.operation_id.as_str() != operation_id
        || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.state_fence != event.state_fence
        || receipt_envelope.core.work_scope.scope_id.as_str() != read_scope_id
        || receipt_envelope.core.task.as_ref().is_none_or(|task| {
            task.task_id.as_str() != binding.task_id.as_str()
                || task.task_revision.value() != expected_revision
                || task.state_fence != event.state_fence
        })
        || receipt.ordering_sequences.len() != 1
        || receipt
            .ordering_sequences
            .first()
            .is_none_or(|head| head.scope.as_str() != "scope:governor")
        || !same_fence_lineage_except_task_revision(&event.state_fence, &binding.state_fence)
        || event
            .state_fence
            .task_revision
            .as_ref()
            .is_none_or(|revision| revision.value() != expected_revision)
        || event.from != Some(event.to)
        || resulting_from_expected != Some(resulting_revision)
        || current_task_revision != Some(resulting_revision)
        || active.revision_fence.value() != task_contract_revision
        || active.next_allowed_action.trim().is_empty()
        || active.next_allowed_action.chars().any(char::is_control)
        || active.next_allowed_action.len() > MAX_PROJECTION_TEXT
    {
        return Err(ProjectionState::Stale {
            reason: "latest task decision fails its persisted transition, fence, or source-revision binding".to_owned(),
        });
    }
    Ok(active.next_allowed_action.clone())
}

fn task_state_row_matches_event(current: &Value, event: &eliot_task::TaskLifecycleEvent) -> bool {
    let Ok(to) = serde_json::to_value(event.to) else {
        return false;
    };
    if current.get("to") != Some(&to) {
        return false;
    }
    match event.from {
        Some(from) => {
            serde_json::to_value(from).is_ok_and(|from| current.get("from") == Some(&from))
        }
        None => current.get("from").is_none(),
    }
}

fn canonical_positive_revision(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    let revision = text.parse::<u64>().ok()?;
    (revision > 0 && revision.to_string() == text).then_some(revision)
}

fn same_fence_lineage_except_task_revision(
    original: &eliot_contracts::StateFence,
    current: &eliot_contracts::StateFence,
) -> bool {
    original.authority_epoch == current.authority_epoch
        && original.resource_generation == current.resource_generation
        && original.policy_revision == current.policy_revision
        && original.integration_revision == current.integration_revision
}

fn omission_disposition(
    omissions: Option<&[OmissionRecord]>,
    binding: &ContextBinding,
) -> ProjectionState {
    let Some(omissions) = omissions else {
        return ProjectionState::Missing;
    };
    if omissions.len() > MAX_SET_OMISSIONS
        || omissions
            .iter()
            .any(|record| record.validate(binding).is_err())
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
        if matches!(
            state,
            ProjectionState::Complete | ProjectionState::KnownEmpty
        ) {
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
    .all(|state| {
        matches!(
            state,
            ProjectionState::Complete | ProjectionState::KnownEmpty
        )
    })
}

fn is_complete(state: &ProjectionState) -> bool {
    matches!(
        state,
        ProjectionState::Complete | ProjectionState::KnownEmpty
    )
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
