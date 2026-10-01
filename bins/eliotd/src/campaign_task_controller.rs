//! Production Task Controller claim servicing for the current daemon.
//!
//! Kernel owns admission, queue ownership, and the fenced attempt capability.
//! This adapter only decodes the owner-native task payload, delegates the
//! semantic transition to the single Governor task owner, and submits the
//! exact typed result through Kernel. The Governor transition constructs the
//! Task Controller's native campaign rows; this adapter never writes a source
//! record or reconstructs a missing owner publication.

use eliot_context::campaign_publication::ContextCampaignRecipeBody;
use eliot_context_contracts::SessionDeliverySnapshot;
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::{
    CampaignOwnerSourceInput, GuardedTaskCommand, InitialScopeBindingAdmissionRequest,
    KernelPortError, KernelTransitionPort, OWNER_SNAPSHOT_SCHEMA, PreparedTaskTransition,
    TaskCommand, TaskCommandContext, TaskProposal,
};
use eliot_learning_contracts::{
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole, LearningStateViewRecipe,
};
use eliot_protocol::{
    TaskControllerAction, TaskControllerCampaignOwnerMaterials, TaskControllerResultBody,
};
use eliot_store_api::{
    CampaignSourceDocumentSchema, CampaignSourceHead, CampaignSourcePublication,
    CampaignSourcePublisher, CampaignSourceReadStatus, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRead, NamedReadOperation, NamedReadRequest, ReadConsistency, ScopeId,
    StoreFailureDisposition,
};
use eliot_workscope::ObservedScopeResources;
use serde::Deserialize;
use serde_json::json;
use crate::{
    DaemonComposition, KernelContextReadClient,
    daemon_kernel_client::{DaemonKernelClient, TaskControllerClaimedInvocation},
    kernel_recovery_client::WorkScopeOwnerWriteFailure,
    task_binding_admission::{InitialWorkScopeBindingRequest, observe_explicit_workspace},
    unix_ms,
};

/// Task Controller input fully decoded and all required campaign reads
/// completed before the daemon borrows the shared composition.
pub struct PreparedTaskControllerClaim {
    claimed: TaskControllerClaimedInvocation,
    recipe: LearningStateViewRecipe,
    source_heads: eliot_governor::TaskControllerCampaignSourceHeads,
    owner_publications: Option<Vec<CampaignSourcePublication>>,
    action: PreparedTaskControllerAction,
}

enum PreparedTaskControllerAction {
    Propose(TaskProposal),
    Apply(GuardedTaskCommand),
}

/// Either a bounded rejection body or an owned claim ready for guarded
/// semantic preparation.
pub enum TaskControllerClaimPreparation {
    Rejected(Box<TaskControllerResultBody>),
    BindScope(Box<PreparedInitialWorkScopeBinding>),
    Ready(Box<PreparedTaskControllerClaim>),
}

/// Exact BIND_SCOPE request and independent Host observation retained until
/// the Governor owner admission and durable Store CAS/readback complete.
pub struct PreparedInitialWorkScopeBinding {
    pub claimed: TaskControllerClaimedInvocation,
    pub request: InitialWorkScopeBindingRequest,
    pub observed: ObservedScopeResources,
}

/// Canonical task plan plus the exact claim which will carry its result.
pub struct PreparedTaskControllerExecution {
    claimed: TaskControllerClaimedInvocation,
    transition: PreparedTaskTransition,
}

pub enum TaskControllerTransitionPreparation {
    Rejected(Box<TaskControllerResultBody>),
    Failed(String),
    Ready(Box<PreparedTaskControllerExecution>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyTaskInput {
    context: TaskCommandContext,
    command: TaskCommand,
}

fn reject_caller_owner_material(
    materials: &TaskControllerCampaignOwnerMaterials,
) -> Result<(), String> {
    if !materials.source_heads.is_empty() || !materials.remaining_owner_inputs.is_empty() {
        return Err(
            "caller-supplied campaign owner heads and rows are not authenticated owner evidence"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_authenticated_context_recipe(
    candidate: &ContextCampaignRecipeBody,
    recipe: &LearningStateViewRecipe,
    authenticated_publications: &[CampaignSourcePublication],
    state_fence: &StateFence,
) -> Result<(), String> {
    let source_reads = context_owner_source_reads(recipe, authenticated_publications, state_fence)?;
    let prior_delivery: Option<SessionDeliverySnapshot> = source_reads
        .delivery
        .map(|read| serde_json::from_value(read.record.document.body.clone()))
        .transpose()
        .map_err(|_| "authenticated Context delivery body is invalid".to_owned())?;
    crate::campaign_context_owner::validate_context_owner_bodies(
        candidate,
        prior_delivery.as_ref(),
        &source_reads,
        state_fence,
    )?;
    Ok(())
}

fn validate_invocation_context_recipe(
    context_campaign_recipe_catalogue: &serde_json::Value,
    context_campaign_recipe: &serde_json::Value,
    context_input: &serde_json::Value,
    task_id: &str,
    work_scope_id: &str,
    state_fence: &StateFence,
) -> Result<ContextCampaignRecipeBody, String> {
    let body: ContextCampaignRecipeBody = serde_json::from_value(json!({
        "catalogue": context_campaign_recipe_catalogue.clone(),
        "recipe": context_campaign_recipe.clone(),
        "compiler_input": context_input.clone(),
    }))
    .map_err(|_| "Task Controller Context recipe body is invalid".to_owned())?;
    if body.recipe.binding.task_id.as_str() != task_id
        || body.recipe.binding.scope_id.as_str() != work_scope_id
        || body.recipe.binding.state_fence != *state_fence
    {
        return Err("Task Controller Context recipe binding does not match the claim".to_owned());
    }
    crate::campaign_context_owner::derive_context_recipe_record(&body)?;
    Ok(body)
}

fn source_reference_from_record(
    source: &eliot_store_api::CampaignSourceRecord,
) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: source.role,
        owner: source.owner_id.clone(),
        record_id: source.record_id.clone(),
        revision: source.revision.clone(),
        content_digest: source.content_digest.clone(),
        slot_projection_digests: source.slot_projection_digests.clone(),
        recorded_state_fence: source.recorded_state_fence.clone(),
    }
}

fn source_reference_from_head(head: &CampaignSourceHead) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: head.role,
        owner: head.owner_id.clone(),
        record_id: head.record_id.clone(),
        revision: head.revision.clone(),
        content_digest: head.content_digest.clone(),
        slot_projection_digests: head.slot_projection_digests.clone(),
        recorded_state_fence: head.recorded_state_fence.clone(),
    }
}

fn context_owner_read_for_role<'a>(
    recipe: &LearningStateViewRecipe,
    publications: &'a [CampaignSourcePublication],
    state_fence: &StateFence,
    role: CampaignSourceRole,
    required: bool,
) -> Result<Option<crate::campaign_context_owner::ContextOwnerSourceRead<'a>>, String> {
    let requirements = recipe
        .source_requirements
        .iter()
        .filter(|requirement| requirement.role == role)
        .collect::<Vec<_>>();
    if requirements.len() > 1 || (required && requirements.len() != 1) {
        return Err("Context owner requirement is missing or duplicated".to_owned());
    }
    let rows = publications
        .iter()
        .filter(|publication| publication.record.role == role)
        .collect::<Vec<_>>();
    let Some(requirement) = requirements.first() else {
        if required || !rows.is_empty() {
            return Err("Context owner row has no recipe requirement".to_owned());
        }
        return Ok(None);
    };
    match requirement.source_binding {
        CampaignSourceBinding::ExactReference => {
            let expected = requirement
                .expected_reference
                .as_ref()
                .ok_or_else(|| "Context owner requirement lacks its exact reference".to_owned())?;
            if expected.role != role || expected.owner != requirement.owner || rows.len() != 1 {
                return Err("Context owner read does not match its recipe requirement".to_owned());
            }
            let publication = rows[0];
            let current_head = publication
                .state
                .current_head()
                .ok_or_else(|| "Context owner read omitted its current head".to_owned())?;
            let (publisher, schema) = match role {
                CampaignSourceRole::ContextRecipe => (
                    CampaignSourcePublisher::ContextRecipe,
                    CampaignSourceDocumentSchema::ContextRecipe,
                ),
                CampaignSourceRole::ContextToolPolicy => (
                    CampaignSourcePublisher::ContextToolPolicy,
                    CampaignSourceDocumentSchema::ContextToolPolicy,
                ),
                CampaignSourceRole::ContextDelivery => (
                    CampaignSourcePublisher::ContextDelivery,
                    CampaignSourceDocumentSchema::ContextDelivery,
                ),
                _ => return Err("Unsupported Context owner source role".to_owned()),
            };
            if publication.publisher != publisher
                || publication.record.document.schema != schema
                || !publication.state.is_current_reference()
                || source_reference_from_record(&publication.record) != *expected
                || source_reference_from_head(current_head) != *expected
                || publication.read_receipt.validate().is_err()
                || !publication.read_receipt.binds_record(&publication.record)
                || publication.read_receipt.read_state_fence != *state_fence
            {
                return Err(
                    "Context owner read is not the exact authenticated current row".to_owned(),
                );
            }
            Ok(Some(
                crate::campaign_context_owner::ContextOwnerSourceRead {
                    record: &publication.record,
                    current_head,
                    read_receipt: &publication.read_receipt,
                },
            ))
        }
        CampaignSourceBinding::ExplicitlyAbsent => {
            if requirement.expected_reference.is_some() || !rows.is_empty() {
                return Err("Explicitly absent Context owner has unexpected evidence".to_owned());
            }
            Ok(None)
        }
        CampaignSourceBinding::AuthenticatedTaskAnchor => {
            Err("Context owner cannot use a Task Controller anchor".to_owned())
        }
    }
}

fn context_owner_source_reads<'a>(
    recipe: &LearningStateViewRecipe,
    publications: &'a [CampaignSourcePublication],
    state_fence: &StateFence,
) -> Result<crate::campaign_context_owner::ContextOwnerSourceReads<'a>, String> {
    let recipe_read = context_owner_read_for_role(
        recipe,
        publications,
        state_fence,
        CampaignSourceRole::ContextRecipe,
        true,
    )?
    .ok_or_else(|| "campaign owner reads omitted the Context recipe".to_owned())?;
    let tool_policy = context_owner_read_for_role(
        recipe,
        publications,
        state_fence,
        CampaignSourceRole::ContextToolPolicy,
        false,
    )?;
    let delivery = context_owner_read_for_role(
        recipe,
        publications,
        state_fence,
        CampaignSourceRole::ContextDelivery,
        false,
    )?;
    Ok(crate::campaign_context_owner::ContextOwnerSourceReads {
        recipe: recipe_read,
        tool_policy,
        delivery,
    })
}

/// Read every non-Task-Controller owner row through the authenticated Kernel
/// campaign-source route. Caller-provided owner rows and heads are deliberately
/// not consulted: the exact immutable row, its read receipt, and its current
/// head are the only inputs to the publication matrix.
async fn read_authenticated_owner_publications(
    reads: &KernelContextReadClient,
    recipe: &LearningStateViewRecipe,
    state_fence: &StateFence,
) -> Result<Vec<CampaignSourcePublication>, String> {
    let scope_id = ScopeId::new(recipe.binding.scope.as_str().to_owned())
        .map_err(|error| format!("campaign owner scope is invalid: {error}"))?;
    let mut publications = Vec::new();
    for requirement in &recipe.source_requirements {
        if matches!(
            requirement.role,
            CampaignSourceRole::TaskObjective
                | CampaignSourceRole::TaskAcceptance
                | CampaignSourceRole::TaskPlan
                | CampaignSourceRole::TaskOpenItems
        ) {
            continue;
        }
        let expected = match requirement.source_binding {
            CampaignSourceBinding::ExplicitlyAbsent
            | CampaignSourceBinding::AuthenticatedTaskAnchor => continue,
            CampaignSourceBinding::ExactReference => requirement
                .expected_reference
                .as_ref()
                .ok_or_else(|| "exact campaign owner requirement lacks its reference".to_owned())?,
        };
        let lookup = CampaignSourceRevisionLookup {
            role: requirement.role,
            owner_id: expected.owner.clone(),
            record_id: expected.record_id.clone(),
            expected_revision: Some(expected.revision.clone()),
            expected_content_digest: Some(expected.content_digest.clone()),
        };
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetCampaignSourceRevision,
            scope_id: Some(scope_id.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: state_fence.clone(),
            parameters: lookup
                .named_parameters()
                .map_err(|error| format!("campaign owner lookup is invalid: {error}"))?,
        };
        let response = KernelContextReadClient::execute_campaign_read(reads.kernel(), request)
            .await
            .map_err(|error| format!("campaign owner read failed: {error}"))?;
        let read = CampaignSourceRevisionRead::from_named_read_response(&response)
            .map_err(|error| format!("campaign owner read response is invalid: {error}"))?;
        if read.read_state_fence != *state_fence || read.status != CampaignSourceReadStatus::Current
        {
            return Err("campaign owner read is not current at the admitted fence".to_owned());
        }
        let source = read
            .source
            .ok_or_else(|| "campaign owner read omitted its source row".to_owned())?;
        let head = read
            .current_head
            .ok_or_else(|| "campaign owner read omitted its current head".to_owned())?;
        if !read
            .read_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.binds_record(&source))
            || &source_reference_from_record(&source) != expected
        {
            return Err("campaign owner read does not bind the recipe reference".to_owned());
        }
        let publisher = CampaignSourcePublisher::for_role(requirement.role)
            .ok_or_else(|| "campaign owner role has no closed publisher".to_owned())?;
        let input = CampaignOwnerSourceInput::from_authenticated_read(
            publisher,
            requirement.role,
            source.owner_id.clone(),
            source.record_id.clone(),
            source.revision.clone(),
            source.recorded_state_fence.clone(),
            read.read_state_fence,
            source.document,
            source.slot_projections,
            source.required_references,
            source.disagreements,
            source.history_plans,
        )
        .map_err(|error| format!("campaign owner row is not owner-authenticated: {error}"))?;
        publications.push(
            input
                .with_expected_head(head)
                .into_publication()
                .map_err(|error| format!("campaign owner publication is invalid: {error}"))?,
        );
    }
    Ok(publications)
}

fn task_controller_result_body(
    claimed: &TaskControllerClaimedInvocation,
    response: serde_json::Value,
) -> Result<TaskControllerResultBody, String> {
    let response_bytes = canonical_json_bytes(&response)
        .map_err(|error| format!("Task Controller result serialization failed: {error}"))?;
    let body = TaskControllerResultBody {
        wire_id: eliot_protocol::TASK_CONTROLLER_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION,
        operation_id: claimed.operation_id.as_str().to_owned(),
        request_sha256: claimed.envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&response_bytes),
        response,
        attempt: claimed.attempt.clone(),
    };
    body.validate()
        .map_err(|error| format!("Task Controller result validation failed: {error}"))?;
    Ok(body)
}

fn task_controller_rejection(
    claimed: &TaskControllerClaimedInvocation,
    reason: &str,
) -> Result<TaskControllerResultBody, String> {
    task_controller_result_body(
        claimed,
        json!({
            "status": "rejected",
            "reason": if reason.is_empty() { "rejected" } else { reason },
        }),
    )
}

/// Decodes one claim and performs every external campaign read before the
/// caller borrows the shared composition. Owner-specific checks still happen
/// under that composition through `prepare_task_controller_transition`.
pub async fn prepare_task_controller_claim(
    reads: &KernelContextReadClient,
    kernel: &dyn KernelTransitionPort,
    claimed: TaskControllerClaimedInvocation,
) -> Result<TaskControllerClaimPreparation, String> {
    let invocation = &claimed.invocation;
    if invocation.action == TaskControllerAction::BindScope {
        let Ok(request) = serde_json::from_value::<InitialWorkScopeBindingRequest>(
            invocation.task_input.clone(),
        ) else {
            return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                task_controller_rejection(&claimed, "invalid_scope_binding")?,
            )));
        };
        if request
            .validate_for_task_scope(invocation.work_scope_id.as_str())
            .is_err()
        {
            return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                task_controller_rejection(&claimed, "invalid_scope_binding")?,
            )));
        }
        let observed = match observe_explicit_workspace(
            request.explicit_root.as_path(),
            &claimed.envelope.state_fence,
        ) {
            Ok(observed) => observed,
            Err(error) => {
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, error.code())?,
                )));
            }
        };
        return Ok(TaskControllerClaimPreparation::BindScope(Box::new(
            PreparedInitialWorkScopeBinding {
                claimed,
                request,
                observed,
            },
        )));
    }
    let recipe: LearningStateViewRecipe =
        match serde_json::from_value(invocation.learning_state_view_recipe.clone()) {
            Ok(recipe) => recipe,
            Err(_) => {
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, "invalid_recipe")?,
                )));
            }
        };
    if recipe.validate().is_err()
        || recipe.binding.task_id.as_str() != invocation.task_id.as_str()
        || recipe.binding.scope.as_str() != invocation.work_scope_id
        || recipe.binding.state_fence != claimed.envelope.state_fence
    {
        return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
            task_controller_rejection(&claimed, "invalid_recipe")?,
        )));
    }
    let complete_owner_publications = match invocation.campaign_owner_materials.as_ref() {
        Some(materials) => {
            if reject_caller_owner_material(materials).is_err() {
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, "invalid_owner_materials")?,
                )));
            }
            let Ok(candidate_context_recipe) = validate_invocation_context_recipe(
                &invocation.context_campaign_recipe_catalogue,
                &invocation.context_campaign_recipe,
                &invocation.context_input,
                invocation.task_id.as_str(),
                &invocation.work_scope_id,
                &claimed.envelope.state_fence,
            ) else {
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, "invalid_owner_materials")?,
                )));
            };
            let Ok(publications) = read_authenticated_owner_publications(
                reads,
                &recipe,
                &claimed.envelope.state_fence,
            )
            .await
            else {
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, "owner_read_unavailable")?,
                )));
            };
            if validate_authenticated_context_recipe(
                &candidate_context_recipe,
                &recipe,
                &publications,
                &claimed.envelope.state_fence,
            )
            .is_err()
            {
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, "owner_read_unavailable")?,
                )));
            }
            Some(publications)
        }
        None => None,
    };

    let Ok(action) = decode_task_controller_action(&claimed) else {
        return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
            task_controller_rejection(&claimed, "invalid_task_input")?,
        )));
    };
    let Ok(source_heads) = kernel
        .campaign_source_heads(
            &invocation.task_id,
            recipe.binding.scope.as_str(),
            &claimed.envelope.state_fence,
        )
        .await
    else {
        return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
            task_controller_rejection(&claimed, "transition_rejected")?,
        )));
    };
    Ok(TaskControllerClaimPreparation::Ready(Box::new(
        PreparedTaskControllerClaim {
            claimed,
            recipe,
            source_heads,
            owner_publications: complete_owner_publications,
            action,
        },
    )))
}

async fn persist_or_reconcile_work_scope_owner(
    kernel: &DaemonKernelClient,
    claimed: &TaskControllerClaimedInvocation,
    snapshot: &eliot_governor::WorkScopeBindingSnapshot,
    expected_owner_revision: u64,
) -> Result<eliot_store_api::RecoveryRecord, WorkScopeOwnerWriteFailure> {
    match kernel
        .persist_work_scope_binding_snapshot(claimed, snapshot, expected_owner_revision)
        .await
    {
        Ok(record) => Ok(record),
        Err(WorkScopeOwnerWriteFailure::Store { failure, expected })
            if failure.disposition == StoreFailureDisposition::UnknownOutcome =>
        {
            let Ok(reconciled) = kernel
                .read_work_scope_owner(
                    &claimed.envelope.state_fence,
                    kernel.protected_snapshot_digest(),
                )
                .await
            else {
                return Err(WorkScopeOwnerWriteFailure::Store { failure, expected });
            };
            if reconciled
                .validate_for_fence(&claimed.envelope.state_fence)
                .is_err()
                || reconciled != *expected
            {
                return Err(WorkScopeOwnerWriteFailure::Store { failure, expected });
            }
            Ok(reconciled)
        }
        Err(WorkScopeOwnerWriteFailure::Kernel {
            error: error @ KernelPortError::Unknown(_),
            expected: Some(expected),
        }) => {
            let Ok(reconciled) = kernel
                .read_work_scope_owner(
                    &claimed.envelope.state_fence,
                    kernel.protected_snapshot_digest(),
                )
                .await
            else {
                return Err(WorkScopeOwnerWriteFailure::Kernel {
                    error,
                    expected: Some(expected),
                });
            };
            if reconciled
                .validate_for_fence(&claimed.envelope.state_fence)
                .is_err()
                || reconciled != *expected
            {
                return Err(WorkScopeOwnerWriteFailure::Kernel {
                    error,
                    expected: Some(expected),
                });
            }
            Ok(reconciled)
        }
        Err(failure) => Err(failure),
    }
}

async fn admit_initial_scope_owner(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    admission: InitialScopeBindingAdmissionRequest<'_>,
) -> Result<eliot_governor::WorkScopeBindingOwner, &'static str> {
    let guard = composition.lock().await;
    if guard.kernel_snapshot().state_fence() != admission.state_fence {
        return Err("TASK_SCOPE_INCOMPATIBLE");
    }
    guard
        .admit_initial_scope_binding(admission)
        .await
        .map_err(|_| "SCOPE_AUTHORITY_REQUIRED")
}

async fn install_initial_scope_owner(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    claimed: &TaskControllerClaimedInvocation,
    fence: &StateFence,
    owner: eliot_governor::WorkScopeBindingOwner,
    snapshot: eliot_governor::WorkScopeBindingSnapshot,
    readback: eliot_store_api::RecoveryRecord,
) -> Result<TaskControllerResultBody, String> {
    let installed = {
        let mut guard = composition.lock().await;
        if guard.kernel_snapshot().state_fence() != fence {
            return task_controller_rejection(claimed, "TASK_SCOPE_INCOMPATIBLE");
        }
        guard
            .install_initial_scope_binding_owner(owner)
            .map_err(|error| format!("durable WorkScope owner install failed: {error}"))?
    };
    if installed != snapshot {
        return task_controller_rejection(claimed, "scope_owner_readback_mismatch");
    }
    task_controller_result_body(
        claimed,
        json!({
            "status": "admitted",
            "work_scope_owner_revision": snapshot.owner_revision,
            "work_scope_owner_digest": readback.value_digest,
        }),
    )
}

fn initial_scope_task_revision(
    claimed: &TaskControllerClaimedInvocation,
    fence: &StateFence,
) -> Result<Option<u64>, &'static str> {
    if claimed.envelope.identity.session_id.as_deref() != Some(claimed.attempt.session_id.as_str())
        || claimed.envelope.identity.task_id.as_deref()
            != Some(claimed.invocation.task_id.as_str())
        || claimed.envelope.identity.work_scope_id.as_deref()
            != Some(claimed.invocation.work_scope_id.as_str())
        || claimed.attempt.state_fence != *fence
        || claimed.authenticated_principal.trim().is_empty()
    {
        return Err("TASK_SCOPE_INCOMPATIBLE");
    }
    // The admitted BIND_SCOPE claim contains a task handle but no semantic
    // TaskContract revision. Leave that constraint absent; Governor derives
    // the positive revision from its original task/acceptance owner proof.
    Ok(None)
}

/// Completes one explicit BIND_SCOPE request in owner order: independent
/// Host observation, Governor source/privacy/task admission, durable Store
/// CAS with original-operation reconciliation, independent readback, then
/// in-memory owner install.
pub async fn complete_initial_work_scope_binding(
    kernel: &DaemonKernelClient,
    composition: &tokio::sync::Mutex<DaemonComposition>,
    prepared: PreparedInitialWorkScopeBinding,
) -> Result<TaskControllerResultBody, String> {
    let PreparedInitialWorkScopeBinding {
        claimed,
        request,
        observed,
    } = prepared;
    let fence = &claimed.envelope.state_fence;
    let Ok(current) = kernel
        .read_work_scope_owner(fence, kernel.protected_snapshot_digest())
        .await
    else {
        return task_controller_rejection(&claimed, "owner_read_unavailable");
    };
    let Ok((expected_owner_revision, retained_snapshot)) =
        work_scope_owner_revision_state(&current, fence)
    else {
        return task_controller_rejection(&claimed, "scope_owner_invalid");
    };
    let Some(owner_revision) = expected_owner_revision.checked_add(1) else {
        return task_controller_rejection(&claimed, "scope_owner_revision_exhausted");
    };
    let task_revision = match initial_scope_task_revision(&claimed, fence) {
        Ok(revision) => revision,
        Err(code) => return task_controller_rejection(&claimed, code),
    };
    let now = unix_ms();
    let owner = match admit_initial_scope_owner(
        composition,
        InitialScopeBindingAdmissionRequest {
            now,
            authenticated_identity: (
                claimed.authenticated_principal.as_str(),
                claimed.attempt.session_id.as_str(),
            ),
            task_binding: (claimed.invocation.task_id.as_str(), task_revision),
            work_scope_ref: claimed.invocation.work_scope_id.as_str(),
            state_fence: fence,
            descriptor: &request.descriptor,
            owner_revision,
            retained_snapshot: retained_snapshot.as_ref(),
            binding: &request.binding,
            observed: &observed,
            discovery_lease: request.discovery_lease.as_ref(),
            privacy_boundary: request.bootstrap_discovery.privacy_boundary.as_ref(),
            bootstrap_discovery: &request.bootstrap_discovery,
            sources: &request.sources,
            privacy: &request.privacy,
            source_candidates: &request.source_candidates,
            declared_precedences: &request.declared_precedences,
            absence_reason_ref: request.absence_reason_ref.as_deref(),
            admission_deadline: request.admission_deadline,
        },
    )
    .await
    {
        Ok(owner) => owner,
        Err(code) => return task_controller_rejection(&claimed, code),
    };
    let snapshot = owner
        .read_current(fence)
        .map_err(|error| format!("admitted WorkScope owner read failed: {error}"))?;
    if snapshot.owner_revision != owner_revision || snapshot.state_fence != *fence {
        return task_controller_rejection(&claimed, "scope_owner_revision_mismatch");
    }
    let readback = match persist_or_reconcile_work_scope_owner(
        kernel,
        &claimed,
        &snapshot,
        expected_owner_revision,
    )
    .await
    {
        Ok(record) => record,
        Err(WorkScopeOwnerWriteFailure::Store { failure, .. }) => {
            return task_controller_result_body(
                &claimed,
                json!({"status":"rejected","store_failure":failure}),
            );
        }
        Err(WorkScopeOwnerWriteFailure::Kernel { error, .. }) => return Err(error.to_string()),
    };
    readback
        .validate_for_fence(fence)
        .map_err(|error| format!("WorkScope owner readback is invalid: {error}"))?;
    if readback.payload != canonical_json_bytes(&snapshot)
        .map_err(|error| format!("WorkScope snapshot serialization failed: {error}"))?
        || readback.revision != snapshot.owner_revision
        || readback.state_fence != *fence
        || readback.schema != OWNER_SNAPSHOT_SCHEMA
    {
        return task_controller_rejection(&claimed, "scope_owner_readback_mismatch");
    }
    install_initial_scope_owner(composition, &claimed, fence, owner, snapshot, readback).await
}

fn work_scope_owner_revision_state(
    record: &eliot_store_api::RecoveryRecord,
    expected_fence: &StateFence,
) -> Result<(u64, Option<eliot_governor::WorkScopeBindingSnapshot>), ()> {
    record.validate_for_fence(expected_fence).map_err(|_| ())?;
    if record.namespace != "owner"
        || record.key != "work_scope"
        || record.state_fence != *expected_fence
        || record.revision == 0
        || record.schema != OWNER_SNAPSHOT_SCHEMA
        || record.payload.is_empty()
    {
        return Err(());
    }
    let value: serde_json::Value = serde_json::from_slice(&record.payload).map_err(|_| ())?;
    let canonical = canonical_json_bytes(&value).map_err(|_| ())?;
    if canonical != record.payload {
        return Err(());
    }
    let Some(object) = value.as_object() else {
        return Err(());
    };
    if object.len() == 2 && object.contains_key("revision") && object.contains_key("state_fence") {
        let embedded_revision = object.get("revision").and_then(serde_json::Value::as_u64).ok_or(())?;
        let embedded_fence: StateFence = serde_json::from_value(
            object.get("state_fence").cloned().ok_or(())?,
        )
        .map_err(|_| ())?;
        if embedded_revision != record.revision || embedded_fence != *expected_fence {
            return Err(());
        }
        return Ok((record.revision, None));
    }
    let snapshot: eliot_governor::WorkScopeBindingSnapshot =
        serde_json::from_value(value).map_err(|_| ())?;
    snapshot.validate().map_err(|_| ())?;
    if snapshot.owner_revision != record.revision || snapshot.state_fence != *expected_fence {
        return Err(());
    }
    Ok((record.revision, Some(snapshot)))
}

fn decode_task_controller_action(
    claimed: &TaskControllerClaimedInvocation,
) -> Result<PreparedTaskControllerAction, ()> {
    let invocation = &claimed.invocation;
    match invocation.action {
        TaskControllerAction::Propose => {
            let proposal: TaskProposal =
                serde_json::from_value(invocation.task_input.clone()).map_err(|_| ())?;
            if proposal.task_id != invocation.task_id {
                return Err(());
            }
            Ok(PreparedTaskControllerAction::Propose(proposal))
        }
        TaskControllerAction::Apply => {
            let input: ApplyTaskInput =
                serde_json::from_value(invocation.task_input.clone()).map_err(|_| ())?;
            Ok(PreparedTaskControllerAction::Apply(GuardedTaskCommand {
                task_id: invocation.task_id.clone(),
                context: input.context,
                command: input.command,
            }))
        }
        TaskControllerAction::BindScope => Err(()),
    }
}

/// Applies the owned semantic preparation synchronously against the current
/// composition. No external I/O is performed while the caller holds its lock.
pub fn prepare_task_controller_transition(
    composition: &DaemonComposition,
    prepared: PreparedTaskControllerClaim,
) -> TaskControllerTransitionPreparation {
    let PreparedTaskControllerClaim {
        claimed,
        recipe,
        source_heads,
        owner_publications,
        action,
    } = prepared;
    let Some(request_identity) = claimed.request_identity.as_ref() else {
        return TaskControllerTransitionPreparation::Failed(
            "Task Controller claim omitted its authenticated request identity".to_owned(),
        );
    };
    let Ok(lifecycle) = composition.task_lifecycle() else {
        return match task_controller_rejection(&claimed, "owner_not_ready") {
            Ok(body) => TaskControllerTransitionPreparation::Rejected(Box::new(body)),
            Err(error) => TaskControllerTransitionPreparation::Failed(error),
        };
    };
    let transition = match (action, owner_publications) {
        (PreparedTaskControllerAction::Propose(proposal), Some(publications)) => lifecycle
            .prepare_propose_task_with_complete_campaign_sources(
                request_identity,
                claimed.operation_id.clone(),
                proposal,
                recipe,
                source_heads,
                publications,
            ),
        (PreparedTaskControllerAction::Propose(proposal), None) => lifecycle
            .prepare_propose_task_with_learning_state_recipe(
                request_identity,
                claimed.operation_id.clone(),
                proposal,
                recipe,
                source_heads,
            ),
        (PreparedTaskControllerAction::Apply(guarded), Some(publications)) => lifecycle
            .prepare_apply_task_with_complete_campaign_sources(
                request_identity,
                claimed.operation_id.clone(),
                guarded,
                recipe,
                source_heads,
                publications,
            ),
        (PreparedTaskControllerAction::Apply(guarded), None) => lifecycle
            .prepare_apply_task_with_learning_state_recipe(
                request_identity,
                claimed.operation_id.clone(),
                guarded,
                recipe,
                source_heads,
            ),
    };
    match transition {
        Ok(transition) => {
            TaskControllerTransitionPreparation::Ready(Box::new(PreparedTaskControllerExecution {
                claimed,
                transition,
            }))
        }
        Err(_) => match task_controller_rejection(&claimed, "transition_rejected") {
            Ok(body) => TaskControllerTransitionPreparation::Rejected(Box::new(body)),
            Err(error) => TaskControllerTransitionPreparation::Failed(error),
        },
    }
}

/// Gates a prepared task write through the durable cold-start owner and then
/// submits the exact original canonical envelope through the daemon's sole
/// material-write composition entry. The prepared transition's identity and
/// envelope are reused unchanged, preserving its operation, CAS heads, and
/// ordering heads across the readiness recheck and Store exchange.
pub async fn commit_task_controller_transition(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    execution: PreparedTaskControllerExecution,
) -> Result<TaskControllerResultBody, String> {
    let PreparedTaskControllerExecution { claimed, transition } = execution;
    let identity = transition.request_identity().clone();
    let envelope = transition.original_envelope().clone();
    if claimed.request_identity.as_ref() != Some(&identity)
        || transition.operation_id().as_str() != claimed.operation_id.as_str()
        || transition.state_fence() != &claimed.envelope.state_fence
        || envelope.request != identity.request.metadata
        || envelope.idempotency_key != identity.idempotency_key
    {
        return task_controller_rejection(&claimed, "transition_identity_mismatch");
    }
    let now = unix_ms();
    let principal_ref = claimed.authenticated_principal.as_str();
    let session_ref = claimed.attempt.session_id.as_str();
    let scope_ref = claimed.invocation.work_scope_id.as_str();
    let task_ref = claimed.invocation.task_id.as_str();
    let fence = claimed.envelope.state_fence.clone();
    let (task_selection, readiness) = {
        let guard = composition.lock().await;
        let task_binding = guard
            .select_current_task_binding_for_cold_start(
                now,
                principal_ref,
                session_ref,
                scope_ref,
                &fence,
                task_ref,
                None,
            )
            .await
            .map_err(|error| format!("current task selection read failed: {error}"))?;
        let eliot_workscope::TaskBindingInput::Selected(task_selection) = task_binding else {
            return task_controller_rejection(&claimed, "TASK_SELECTION_REQUIRED");
        };
        let readiness = guard
            .read_guarded_cold_start_readiness(
                principal_ref,
                session_ref,
                scope_ref,
                &task_selection,
                &fence,
                now,
            )
            .await
            .map_err(|error| format!("durable cold-start readiness read failed: {error}"))?;
        (task_selection, readiness)
    };
    if readiness.state_fence != fence
        || readiness.receipt.task_selection_evidence.as_ref()
            != Some(&task_selection)
    {
        return task_controller_rejection(&claimed, "TASK_SCOPE_INCOMPATIBLE");
    }
    let material_readiness = readiness.material_readiness_inputs();
    let receipt = composition
        .lock()
        .await
        .commit_canonical_and_refresh(
            &identity,
            envelope,
            &material_readiness,
            &readiness.original_binding_observation,
            Some((&readiness.source_set, &readiness.privacy)),
        )
        .await
        .map_err(|error| format!("canonical Task Controller commit failed: {error}"))?;
    task_controller_result_body(
        &claimed,
        json!({ "status": "committed", "receipt": receipt }),
    )
}
