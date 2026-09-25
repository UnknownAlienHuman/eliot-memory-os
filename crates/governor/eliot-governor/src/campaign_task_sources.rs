//! Task Controller publication of task-backed campaign sources.
//!
//! These projections may be built only from an event and task record already
//! accepted by `TaskLifecycleOwner`. They do not perform persistence; the
//! returned publications are attached to the same canonical transition.

use eliot_contracts::{ArtifactId, SourceId, TaskRevision, canonical_json_bytes, sha256_hex};
use eliot_learning_contracts::{
    CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSlotProjectionDigest,
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole, LearningStateViewRecipe,
    MemberProjection, OwnerId, SlotDisposition, SlotProjection, SlotRequirement,
    TASK_CONTROLLER_CAMPAIGN_OWNER_ID, identity::SourceLineage,
};
use eliot_store_api::{
    CampaignOwnerProjectionBody, CampaignSourceDocument, CampaignSourceDocumentSchema,
    CampaignSourceHead, CampaignSourcePublication, CampaignSourcePublisher, CampaignSourceRecord,
    campaign_source_schema_for_role,
};
use eliot_task::{TaskLifecycleEvent, TaskRecord};
use serde::Serialize;

use crate::campaign_source_publishers::build_task_controller_history_record;
use crate::task_lifecycle::TaskLifecycleError;

/// Exact heads returned by the named Task Controller source reads.
#[derive(Clone, Debug, Default)]
pub struct TaskControllerCampaignSourceHeads {
    /// Current head for the task objective, if one exists.
    pub objective: Option<CampaignSourceHead>,
    /// Current head for the task plan, if one exists.
    pub plan: Option<CampaignSourceHead>,
    /// Current head for the task acceptance projection, if one exists.
    pub acceptance: Option<CampaignSourceHead>,
    /// Current head for the task open-items projection, if one exists.
    pub open_items: Option<CampaignSourceHead>,
}

/// Source publications derived from one admitted task transition.
#[derive(Clone, Debug)]
pub struct TaskControllerCampaignSources {
    /// Objective projection from the exact `TaskRecord.goal` value.
    pub objective: CampaignSourcePublication,
    /// Recipe projection anchored to the admitted task fence.
    pub plan: CampaignSourcePublication,
    /// Task-state acceptance projection derived from the admitted event.
    pub acceptance: CampaignSourcePublication,
    /// Task-state open-items projection derived from the admitted event.
    pub open_items: CampaignSourcePublication,
    /// Recipe with the exact newly built `TaskObjective` reference installed.
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

fn task_state_projection(
    role: CampaignSourceRole,
    event: &TaskLifecycleEvent,
    record: &TaskRecord,
    owner_id: &OwnerId,
    goal_digest: &str,
    source_snapshot: &ArtifactId,
    expected_head: Option<CampaignSourceHead>,
) -> Result<CampaignSourcePublication, TaskLifecycleError> {
    let projection = serde_json::json!({
        "task_id": record.task_id.as_str(),
        "revision": record.revision,
        "state": record.state,
        "last_event_id": record.last_event_id.as_str(),
        "last_sequence": record.last_sequence,
        "goal_digest": goal_digest,
        "source_snapshot": source_snapshot.as_str(),
        "event_state_fence": &event.state_fence,
    });
    let projection_digest = sha256_hex(
        &canonical_json_bytes(&projection)
            .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
    );
    let body = CampaignOwnerProjectionBody {
        owner_id: owner_id.as_str().to_owned(),
        record_id: record.task_id.as_str().to_owned(),
        revision: record.revision.to_string(),
        state_fence: record.state_fence.clone(),
        projection_digest,
        required_references: vec![source_snapshot.clone()],
        projection,
    };
    let record = CampaignSourceRecord::new(
        role,
        owner_id.clone(),
        CampaignOwnerRecordId::Task(record.task_id.clone()),
        CampaignOwnerRevision::Task(
            TaskRevision::new(record.revision)
                .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
        ),
        record.state_fence.clone(),
        Vec::new(),
        Vec::new(),
        vec![source_snapshot.clone()],
        Vec::new(),
        Vec::new(),
        CampaignSourceDocument {
            schema: campaign_source_schema_for_role(role),
            schema_version: CampaignSourceDocument::SCHEMA_VERSION,
            body: serde_json::to_value(&body)
                .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
        },
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let publisher = match role {
        CampaignSourceRole::TaskAcceptance => CampaignSourcePublisher::TaskControllerAcceptance,
        CampaignSourceRole::TaskOpenItems => CampaignSourcePublisher::TaskControllerOpenItems,
        _ => {
            return Err(TaskLifecycleError::Serialization(
                "task state projection role is not a Task Controller projection".to_owned(),
            ));
        }
    };
    let read_fence = record.recorded_state_fence.clone();
    let publication = CampaignSourcePublication::from_observed_head(
        publisher,
        record,
        expected_head,
        &read_fence,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    Ok(publication)
}

/// Build `TaskObjective` and `TaskPlan` publications from an accepted task event.
///
/// The caller supplies the exact owner heads it read for both CAS inputs. The
/// `TaskObjective` snapshot handle is a source-owner-minted projection `ArtifactId`
/// deterministic from task ID, revision, and goal digest; it is never a typed
/// alias for the task ID. The `TaskPlan` source revision follows the admitted
/// task fence, while the `TaskObjective` revision follows the resulting record.
#[allow(
    clippy::result_large_err,
    reason = "TaskLifecycleError is the shared typed task-owner failure contract"
)]
#[allow(
    clippy::too_many_lines,
    reason = "the two owner publications and recipe CAS binding remain one auditable transaction builder"
)]
pub fn build_task_controller_campaign_sources(
    event: &TaskLifecycleEvent,
    record: &TaskRecord,
    mut recipe: LearningStateViewRecipe,
    expected_heads: TaskControllerCampaignSourceHeads,
) -> Result<TaskControllerCampaignSources, TaskLifecycleError> {
    validate_admitted_task_binding(event, record, &recipe)?;
    recipe
        .validate()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    let owner_id = OwnerId::from_artifact(
        ArtifactId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID)
            .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
    );
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
                revision: task_revision,
                digest: goal_digest.clone(),
            },
            projection_revision: task_revision,
            disposition: SlotDisposition::Current,
            value_digest: Some(goal_digest.clone()),
            evidence: vec![source_snapshot.clone()],
        }],
        evidence: vec![source_snapshot.clone()],
    };
    let slot_projection_digest = objective_projection
        .canonical_digest()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let history_plan = build_task_controller_history_record(
        recipe.campaign_id.as_str(),
        owner_id.as_str(),
        source_snapshot.clone(),
        &record.state_fence,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let objective_body = TaskObjectiveDocument {
        task_id: record.task_id.clone(),
        revision: task_revision,
        goal: record.goal.clone(),
        goal_digest: goal_digest.clone(),
        source_snapshot: source_snapshot.clone(),
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
        CampaignOwnerRevision::Task(task_revision),
        record.state_fence.clone(),
        vec![CampaignSlotProjectionDigest {
            slot_id: objective_slot.slot_id.clone(),
            digest: slot_projection_digest.clone(),
        }],
        vec![objective_projection],
        vec![objective_body.source_snapshot.clone()],
        vec![],
        vec![history_plan],
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
            slot_id: objective_slot.slot_id.clone(),
            digest: slot_projection_digest,
        }],
        recorded_state_fence: record.state_fence.clone(),
    };
    let acceptance = task_state_projection(
        CampaignSourceRole::TaskAcceptance,
        event,
        record,
        &owner_id,
        &goal_digest,
        &objective_body.source_snapshot,
        expected_heads.acceptance,
    )?;
    let open_items = task_state_projection(
        CampaignSourceRole::TaskOpenItems,
        event,
        record,
        &owner_id,
        &goal_digest,
        &objective_body.source_snapshot,
        expected_heads.open_items,
    )?;
    for (role, publication) in [
        (CampaignSourceRole::TaskAcceptance, &acceptance),
        (CampaignSourceRole::TaskOpenItems, &open_items),
    ] {
        let requirement = recipe
            .source_requirements
            .iter()
            .find(|requirement| requirement.role == role)
            .ok_or_else(|| source_error("campaign recipe lacks a Task Controller state source"))?;
        if requirement.owner != owner_id
            || requirement.source_binding != CampaignSourceBinding::ExactReference
            || !requirement.load_bearing
        {
            return Err(source_error(
                "Task Controller state sources must be exact load-bearing owner rows",
            ));
        }
        let reference = CampaignSourceRevisionRef {
            role,
            owner: owner_id.clone(),
            record_id: publication.record.record_id.clone(),
            revision: publication.record.revision.clone(),
            content_digest: publication.record.content_digest.clone(),
            slot_projection_digests: publication.record.slot_projection_digests.clone(),
            recorded_state_fence: publication.record.recorded_state_fence.clone(),
        };
        let requirement = recipe
            .source_requirements
            .iter_mut()
            .find(|requirement| requirement.role == role)
            .ok_or_else(|| source_error("campaign recipe lacks a Task Controller state source"))?;
        requirement.expected_reference = Some(reference);
    }

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

    let objective_fence = objective_record.recorded_state_fence.clone();
    let objective = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::TaskControllerObjective,
        objective_record,
        expected_heads.objective,
        &objective_fence,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    let plan_revision = recipe
        .binding
        .state_fence
        .task_revision
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
    let plan_fence = plan_record.recorded_state_fence.clone();
    let plan = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::TaskControllerPlan,
        plan_record,
        expected_heads.plan,
        &plan_fence,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;

    Ok(TaskControllerCampaignSources {
        objective,
        plan,
        acceptance,
        open_items,
        recipe,
    })
}

#[allow(
    clippy::result_large_err,
    reason = "TaskLifecycleError is the shared typed task-owner failure contract"
)]
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

#[allow(
    clippy::result_large_err,
    reason = "TaskLifecycleError is the shared typed task-owner failure contract"
)]
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
