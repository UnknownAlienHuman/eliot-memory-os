//! Task Controller publication of task-backed campaign sources.
//!
//! These projections may be built only from an event and task record already
//! accepted by `TaskLifecycleOwner`. They do not perform persistence; the
//! returned publications are attached to the same canonical transition.

use eliot_contracts::{ArtifactId, SourceId, TaskRevision, canonical_json_bytes, sha256_hex};
use eliot_learning_contracts::{
    CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSlotProjectionDigest,
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole,
    LearningStateViewRecipe, MemberProjection, OwnerId, SlotDisposition, SlotProjection,
    SlotRequirement, SourceLineage, TASK_CONTROLLER_CAMPAIGN_OWNER_ID,
};
use eliot_store_api::{
    CampaignSourceDocument, CampaignSourceDocumentSchema, CampaignSourceHead,
    CampaignSourcePublication, CampaignSourcePublisher, CampaignSourceRecord,
};
use eliot_task::{TaskLifecycleEvent, TaskRecord};
use serde::Serialize;

use crate::task_lifecycle::TaskLifecycleError;

/// Exact heads returned by the two named Task Controller source reads.
#[derive(Clone, Debug, Default)]
pub(crate) struct TaskControllerCampaignSourceHeads {
    /// Current head for the task objective, if one exists.
    pub objective: Option<CampaignSourceHead>,
    /// Current head for the task plan, if one exists.
    pub plan: Option<CampaignSourceHead>,
}

/// Source publications derived from one admitted task transition.
#[derive(Clone, Debug)]
pub(crate) struct TaskControllerCampaignSources {
    /// Objective projection from the exact `TaskRecord.goal` value.
    pub objective: CampaignSourcePublication,
    /// Recipe projection anchored to the admitted task fence.
    pub plan: CampaignSourcePublication,
    /// Recipe with the exact newly built TaskObjective reference installed.
    pub recipe: LearningStateViewRecipe,
}

#[derive(Serialize)]
struct TaskObjectiveDocument {
    task_id: eliot_contracts::TaskId,
    revision: TaskRevision,
    goal: String,
    goal_digest: String,
    source_snapshot: ArtifactId,
}

#[derive(Serialize)]
struct TaskObjectiveSnapshotIdentity<'a> {
    task_id: &'a eliot_contracts::TaskId,
    revision: u64,
    goal_digest: &'a str,
}

/// Build TaskObjective and TaskPlan publications from an accepted task event.
///
/// The caller supplies the exact owner heads it read for both CAS inputs. The
/// TaskObjective snapshot handle is a source-owner-minted projection ArtifactId
/// deterministic from task ID, revision, and goal digest; it is never a typed
/// alias for the task ID. The TaskPlan source revision follows the admitted
/// task fence, while the TaskObjective revision follows the resulting record.
pub(crate) fn build_task_controller_campaign_sources(
    event: &TaskLifecycleEvent,
    record: &TaskRecord,
    mut recipe: LearningStateViewRecipe,
    expected_heads: TaskControllerCampaignSourceHeads,
) -> Result<TaskControllerCampaignSources, TaskLifecycleError> {
    validate_admitted_task_binding(event, record, &recipe)?;
    recipe
        .validate()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    let owner_id = OwnerId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let task_revision = TaskRevision::new(record.revision)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let objective_slot = task_objective_slot(&recipe, &owner_id)?;
    let objective_requirement = recipe
        .source_requirements
        .iter()
        .find(|requirement| requirement.role == CampaignSourceRole::TaskObjective)
        .ok_or_else(|| source_error("campaign recipe lacks its TaskObjective source"))?;
    if objective_requirement.owner != owner_id
        || objective_requirement.source_binding != CampaignSourceBinding::ExactReference
        || !objective_requirement.load_bearing
        || objective_requirement.expected_reference.is_none()
    {
        return Err(source_error(
            "TaskObjective must be an exact load-bearing Task Controller source",
        ));
    }

    let goal_bytes = canonical_json_bytes(&record.goal)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let goal_digest = sha256_hex(&goal_bytes);
    let snapshot_material = canonical_json_bytes(&TaskObjectiveSnapshotIdentity {
        task_id: &record.task_id,
        revision: record.revision,
        goal_digest: &goal_digest,
    })
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let source_snapshot = ArtifactId::new(format!(
        "task-objective-projection-{}",
        sha256_hex(&snapshot_material)
    ))
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let source_id = SourceId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let objective_projection = SlotProjection {
        slot_id: objective_slot.slot_id.clone(),
        disposition: SlotDisposition::Current,
        members: vec![MemberProjection {
            member_id: objective_slot.declared_members[0].clone(),
            owner: owner_id.clone(),
            source: SourceLineage {
                owner: source_id,
                snapshot: source_snapshot.clone(),
                revision: task_revision.clone(),
                digest: goal_digest.clone(),
            },
            projection_revision: task_revision.clone(),
            disposition: SlotDisposition::Current,
            value_digest: Some(goal_digest.clone()),
            evidence: vec![source_snapshot.clone()],
        }],
        evidence: vec![source_snapshot.clone()],
    };
    let slot_projection_digest = objective_projection
        .canonical_digest()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let objective_body = TaskObjectiveDocument {
        task_id: record.task_id.clone(),
        revision: task_revision.clone(),
        goal: record.goal.clone(),
        goal_digest,
        source_snapshot,
    };
    let objective_document = CampaignSourceDocument {
        schema: CampaignSourceDocumentSchema::TaskObjective,
        schema_version: CampaignSourceDocument::SCHEMA_VERSION,
        body: serde_json::to_value(&objective_body)
            .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
    };
    let objective_record = CampaignSourceRecord::new(
        CampaignSourceRole::TaskObjective,
        owner_id.clone(),
        CampaignOwnerRecordId::Task(record.task_id.clone()),
        CampaignOwnerRevision::Task(task_revision.clone()),
        record.state_fence.clone(),
        vec![CampaignSlotProjectionDigest {
            slot_id: objective_slot.slot_id.clone(),
            digest: slot_projection_digest.clone(),
        }],
        vec![objective_projection],
        vec![objective_body.source_snapshot],
        vec![],
        vec![],
        objective_document,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    let objective_reference = CampaignSourceRevisionRef {
        role: CampaignSourceRole::TaskObjective,
        owner: owner_id.clone(),
        record_id: CampaignOwnerRecordId::Task(record.task_id.clone()),
        revision: CampaignOwnerRevision::Task(task_revision),
        content_digest: objective_record.content_digest.clone(),
        slot_projection_digests: vec![CampaignSlotProjectionDigest {
            slot_id: objective_slot.slot_id,
            digest: slot_projection_digest,
        }],
        recorded_state_fence: record.state_fence.clone(),
    };
    let objective_manifest = recipe
        .source_requirements
        .iter_mut()
        .find(|requirement| requirement.role == CampaignSourceRole::TaskObjective)
        .ok_or_else(|| source_error("campaign recipe lacks its TaskObjective source"))?;
    objective_manifest.expected_reference = Some(objective_reference);
    recipe
        .seal()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    recipe
        .validate()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    let objective = CampaignSourcePublication {
        publisher: CampaignSourcePublisher::TaskController,
        record: objective_record,
        expected_head: expected_heads.objective,
    };
    objective
        .validate()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    let plan_revision = recipe
        .binding
        .state_fence
        .task_revision
        .clone()
        .ok_or_else(|| source_error("TaskPlan requires the admitted task revision"))?;
    let task_plan = recipe
        .source_requirements
        .iter()
        .find(|requirement| requirement.role == CampaignSourceRole::TaskPlan)
        .ok_or_else(|| source_error("campaign recipe lacks its TaskPlan anchor"))?;
    if task_plan.owner != owner_id
        || task_plan.source_binding != CampaignSourceBinding::AuthenticatedTaskAnchor
        || task_plan.expected_reference.is_some()
        || !task_plan.load_bearing
    {
        return Err(source_error(
            "TaskPlan must use the authenticated Task Controller task anchor",
        ));
    }
    let plan_document = CampaignSourceDocument {
        schema: CampaignSourceDocumentSchema::LearningStateViewRecipe,
        schema_version: CampaignSourceDocument::SCHEMA_VERSION,
        body: serde_json::to_value(&recipe)
            .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
    };
    let plan_record = CampaignSourceRecord::new(
        CampaignSourceRole::TaskPlan,
        owner_id,
        CampaignOwnerRecordId::Task(record.task_id.clone()),
        CampaignOwnerRevision::Task(plan_revision),
        record.state_fence.clone(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        plan_document,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let plan = CampaignSourcePublication {
        publisher: CampaignSourcePublisher::TaskController,
        record: plan_record,
        expected_head: expected_heads.plan,
    };
    plan.validate()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    Ok(TaskControllerCampaignSources {
        objective,
        plan,
        recipe,
    })
}

fn task_objective_slot<'a>(
    recipe: &'a LearningStateViewRecipe,
    expected_owner: &OwnerId,
) -> Result<&'a eliot_learning_contracts::SlotSpec, TaskLifecycleError> {
    let mut matching = recipe
        .slots
        .iter()
        .filter(|slot| slot.source_role == CampaignSourceRole::TaskObjective);
    let slot = matching
        .next()
        .ok_or_else(|| source_error("campaign recipe lacks its TaskObjective slot"))?;
    if matching.next().is_some()
        || slot.owner != *expected_owner
        || slot.target != recipe.target
        || slot.declared_members.len() != 1
        || !matches!(&slot.requirement, SlotRequirement::Required)
    {
        return Err(source_error(
            "TaskObjective requires one required slot, one declared member, and the Task Controller owner",
        ));
    }
    Ok(slot)
}

fn validate_admitted_task_binding(
    event: &TaskLifecycleEvent,
    record: &TaskRecord,
    recipe: &LearningStateViewRecipe,
) -> Result<(), TaskLifecycleError> {
    let task_revision = TaskRevision::new(record.revision)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    if event.task_id != record.task_id
        || event.state_fence != record.state_fence
        || event.authority_epoch != record.state_fence.authority_epoch
        || event.sequence != record.last_sequence
        || event.event_id != record.last_event_id
        || event.to != record.state
        || event.request_id != recipe.binding.request_id.as_str()
        || recipe.binding.task_id != record.task_id
        || recipe.binding.state_fence != record.state_fence
        || record.goal.trim().is_empty()
        || record.goal.chars().any(char::is_control)
    {
        return Err(source_error(
            "TaskController campaign sources do not match the accepted task event, record, recipe, and fence",
        ));
    }
    let Some(fenced_revision) = &recipe.binding.state_fence.task_revision else {
        return Err(source_error("task recipe has no task revision fence"));
    };
    if fenced_revision.value() > task_revision.value() {
        return Err(source_error(
            "task record revision predates its admitted task revision fence",
        ));
    }
    Ok(())
}

fn source_error(message: &'static str) -> TaskLifecycleError {
    TaskLifecycleError::Serialization(message.to_owned())
}
