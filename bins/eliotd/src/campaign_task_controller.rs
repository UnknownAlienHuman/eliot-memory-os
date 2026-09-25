//! Production Task Controller claim servicing for the current daemon.
//!
//! Kernel owns admission, queue ownership, and the fenced attempt capability.
//! This adapter only decodes the owner-native task payload, delegates the
//! semantic transition to the single Governor task owner, and submits the
//! exact typed result through Kernel. The Governor transition constructs the
//! Task Controller's native campaign rows; this adapter never writes a source
//! record or reconstructs a missing owner publication.

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::{CampaignOwnerSourceInput, TaskCommand, TaskCommandContext, TaskProposal};
use eliot_learning_contracts::{
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole, LearningStateViewRecipe,
};
use eliot_protocol::{
    TaskControllerAction, TaskControllerCampaignOwnerMaterials, TaskControllerResultBody,
};
use eliot_store_api::{
    CampaignSourcePublication, CampaignSourcePublisher, CampaignSourceReadStatus,
    CampaignSourceRevisionLookup, CampaignSourceRevisionRead, NamedReadOperation, NamedReadRequest,
    ReadConsistency, ScopeId,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    DaemonComposition, KernelContextReadClient,
    daemon_kernel_client::TaskControllerClaimedInvocation,
};

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

/// Serve one exact Kernel-claimed Task Controller invocation.
///
/// The caller has already parsed and capability-bound the invocation and the
/// Kernel-issued attempt. The recipe is validated here at the Governor
/// boundary. When a complete owner bundle is requested, non-Task-Controller
/// rows are re-read through the authenticated Kernel campaign-source route;
/// caller-supplied owner rows and heads are rejected. Every native-input or
/// transition failure is projected as a typed rejected result body; malformed
/// caller material must not terminate the daemon or escape as an untyped poll
/// error.
#[allow(
    clippy::large_futures,
    clippy::too_many_lines,
    reason = "the claim boundary preserves one exact owner transition and one fenced result body"
)]
pub async fn serve_task_controller_claim(
    composition: &DaemonComposition,
    reads: &KernelContextReadClient,
    claimed: TaskControllerClaimedInvocation,
) -> Result<TaskControllerResultBody, String> {
    let invocation = &claimed.invocation;
    let recipe: LearningStateViewRecipe =
        match serde_json::from_value(invocation.learning_state_view_recipe.clone()) {
            Ok(recipe) => recipe,
            Err(_) => return task_controller_rejection(&claimed, "invalid_recipe"),
        };
    if recipe.validate().is_err()
        || recipe.binding.task_id.as_str() != invocation.task_id.as_str()
        || recipe.binding.scope.as_str() != invocation.work_scope_id
        || recipe.binding.state_fence != claimed.envelope.state_fence
    {
        return task_controller_rejection(&claimed, "invalid_recipe");
    }
    let complete_owner_publications = match invocation.campaign_owner_materials.as_ref() {
        Some(materials) => {
            if reject_caller_owner_material(materials).is_err() {
                return task_controller_rejection(&claimed, "invalid_owner_materials");
            }
            match read_authenticated_owner_publications(
                reads,
                &recipe,
                &claimed.envelope.state_fence,
            )
            .await
            {
                Ok(publications) => Some(publications),
                Err(_) => return task_controller_rejection(&claimed, "owner_read_unavailable"),
            }
        }
        None => None,
    };

    let lifecycle = match composition.task_lifecycle() {
        Ok(lifecycle) => lifecycle,
        Err(_) => return task_controller_rejection(&claimed, "owner_not_ready"),
    };
    let outcome: Result<eliot_store_api::WriteReceipt, String> = match invocation.action {
        TaskControllerAction::Propose => {
            let proposal: TaskProposal = match serde_json::from_value(invocation.task_input.clone())
            {
                Ok(proposal) => proposal,
                Err(_) => return task_controller_rejection(&claimed, "invalid_task_input"),
            };
            if proposal.task_id != invocation.task_id {
                return task_controller_rejection(&claimed, "invalid_task_input");
            }
            if let Some(publications) = complete_owner_publications {
                lifecycle
                    .propose_task_with_complete_campaign_sources(
                        &claimed.request_identity,
                        claimed.operation_id.clone(),
                        proposal,
                        recipe,
                        publications,
                    )
                    .await
                    .map_err(|_error| "transition_rejected".to_owned())
            } else {
                lifecycle
                    .propose_task_with_learning_state_recipe(
                        &claimed.request_identity,
                        claimed.operation_id.clone(),
                        proposal,
                        recipe,
                    )
                    .await
                    .map_err(|_error| "transition_rejected".to_owned())
            }
        }
        TaskControllerAction::Apply => {
            let input: ApplyTaskInput = match serde_json::from_value(invocation.task_input.clone())
            {
                Ok(input) => input,
                Err(_) => return task_controller_rejection(&claimed, "invalid_task_input"),
            };
            if let Some(publications) = complete_owner_publications {
                lifecycle
                    .apply_task_with_complete_campaign_sources(
                        &claimed.request_identity,
                        claimed.operation_id.clone(),
                        invocation.task_id.clone(),
                        input.context,
                        input.command,
                        recipe,
                        publications,
                    )
                    .await
                    .map_err(|_error| "transition_rejected".to_owned())
            } else {
                lifecycle
                    .apply_task_with_learning_state_recipe(
                        &claimed.request_identity,
                        claimed.operation_id.clone(),
                        invocation.task_id.clone(),
                        input.context,
                        input.command,
                        recipe,
                    )
                    .await
                    .map_err(|_error| "transition_rejected".to_owned())
            }
        }
    };

    match outcome {
        Ok(receipt) => task_controller_result_body(
            &claimed,
            json!({
                "status": "committed",
                "receipt": receipt,
            }),
        ),
        Err(reason) => task_controller_rejection(&claimed, &reason),
    }
}
