//! Production Task Controller claim servicing for the current daemon.
//!
//! Kernel owns admission, queue ownership, and the fenced attempt capability.
//! This adapter only decodes the owner-native task payload, delegates the
//! semantic transition to the single Governor task owner, and submits the
//! exact typed result through Kernel. The Governor transition constructs the
//! Task Controller's native campaign rows; this adapter never writes a source
//! record or reconstructs a missing owner publication.

use std::collections::BTreeMap;

use eliot_agent_api::DecisionId;
use eliot_context::ContextInput;
use eliot_context::campaign_publication::ContextCampaignRecipeBody;
use eliot_context_contracts::{ContextRecipe, SessionDeliverySnapshot};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::{
    CampaignOwnerSourceInput, TaskCommand, TaskCommandContext, TaskControllerCampaignSources,
    TaskProposal,
};
use eliot_learning_contracts::LearningStateViewRecipe;
use eliot_product_evaluation::ProductEvaluationCampaignPublications;
use eliot_protocol::{
    TaskControllerAction, TaskControllerCampaignOwnerMaterials, TaskControllerResultBody,
};
use eliot_store_api::{CampaignSourceHead, CampaignSourcePublication, CampaignSourceRole};
use serde::Deserialize;
use serde_json::json;

use crate::{DaemonComposition, daemon_kernel_client::TaskControllerClaimedInvocation};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyTaskInput {
    context: TaskCommandContext,
    command: TaskCommand,
}

#[derive(Debug)]
struct DecodedCampaignOwnerMaterials {
    context_recipe: ContextCampaignRecipeBody,
    prior_delivery: SessionDeliverySnapshot,
    evaluation: ProductEvaluationCampaignPublications,
    heads: BTreeMap<CampaignSourceRole, CampaignSourceHead>,
    remaining_owner_inputs: Vec<CampaignOwnerSourceInput>,
}

fn decode_campaign_owner_materials(
    materials: &TaskControllerCampaignOwnerMaterials,
    invocation: &eliot_protocol::TaskControllerInvocation,
    state_fence: &StateFence,
) -> Result<DecodedCampaignOwnerMaterials, String> {
    let recipe: ContextRecipe = serde_json::from_value(invocation.context_campaign_recipe.clone())
        .map_err(|error| format!("Task Controller Context recipe decode failed: {error}"))?;
    let compiler_input: ContextInput = serde_json::from_value(invocation.context_input.clone())
        .map_err(|error| format!("Task Controller Context input decode failed: {error}"))?;
    let context_recipe = ContextCampaignRecipeBody {
        recipe,
        compiler_input,
    };
    context_recipe
        .recipe
        .validate()
        .map_err(|error| format!("Task Controller Context recipe validation failed: {error}"))?;
    context_recipe
        .compiler_input
        .validate()
        .map_err(|error| format!("Task Controller Context input validation failed: {error}"))?;
    if context_recipe.recipe.binding.task_id.as_str() != invocation.task_id.as_str()
        || context_recipe.recipe.binding.scope_id.as_str() != invocation.work_scope_id
        || context_recipe.recipe.binding.state_fence != *state_fence
        || context_recipe
            .compiler_input
            .task_id
            .as_ref()
            .map(DecisionId::as_str)
            != Some(context_recipe.recipe.binding.decision_id.as_str())
        || context_recipe.compiler_input.scope != invocation.work_scope_id
        || context_recipe.compiler_input.state_fence != *state_fence
    {
        return Err("Task Controller Context material is not bound to the invocation".to_owned());
    }

    let prior_delivery: SessionDeliverySnapshot =
        serde_json::from_value(materials.prior_delivery.clone())
            .map_err(|error| format!("Task Controller prior delivery decode failed: {error}"))?;
    prior_delivery
        .validate()
        .map_err(|error| format!("Task Controller prior delivery validation failed: {error}"))?;
    validate_prior_delivery_selector(invocation.prior_delivery_selector.as_ref(), &prior_delivery)?;

    let evaluation: ProductEvaluationCampaignPublications =
        serde_json::from_value(materials.evaluation.clone()).map_err(|error| {
            format!("Task Controller evaluation material decode failed: {error}")
        })?;
    evaluation
        .validate_for_state_fence(state_fence)
        .map_err(|error| {
            format!("Task Controller evaluation material validation failed: {error}")
        })?;

    let mut heads = BTreeMap::new();
    for value in &materials.source_heads {
        let head: CampaignSourceHead = serde_json::from_value(value.clone())
            .map_err(|error| format!("Task Controller source head decode failed: {error}"))?;
        head.validate()
            .map_err(|error| format!("Task Controller source head validation failed: {error}"))?;
        if matches!(
            head.role,
            CampaignSourceRole::TaskObjective
                | CampaignSourceRole::TaskAcceptance
                | CampaignSourceRole::TaskPlan
                | CampaignSourceRole::TaskOpenItems
        ) {
            return Err(
                "Task Controller source heads must come from the owner transition".to_owned(),
            );
        }
        if heads.insert(head.role, head).is_some() {
            return Err("Task Controller source heads contain a duplicate role".to_owned());
        }
    }
    let remaining_owner_inputs = materials
        .remaining_owner_inputs
        .iter()
        .map(|value| {
            serde_json::from_value::<CampaignOwnerSourceInput>(value.clone()).map_err(|error| {
                format!("Task Controller remaining owner input decode failed: {error}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DecodedCampaignOwnerMaterials {
        context_recipe,
        prior_delivery,
        evaluation,
        heads,
        remaining_owner_inputs,
    })
}

fn validate_prior_delivery_selector(
    selector: Option<&serde_json::Value>,
    snapshot: &SessionDeliverySnapshot,
) -> Result<(), String> {
    let selector = selector
        .ok_or_else(|| "complete owner materials require a prior delivery selector".to_owned())?;
    let object = selector
        .as_object()
        .ok_or_else(|| "prior delivery selector must be an object".to_owned())?;
    if object.len() != 5
        || object.get("task_id").and_then(serde_json::Value::as_str)
            != Some(snapshot.task_id.as_str())
        || object.get("scope_id").and_then(serde_json::Value::as_str)
            != Some(snapshot.scope_id.as_str())
        || object.get("source_id").and_then(serde_json::Value::as_str)
            != Some(snapshot.source_id.as_str())
        || object
            .get("snapshot_revision")
            .and_then(serde_json::Value::as_str)
            != Some(snapshot.snapshot_revision.as_str())
        || object
            .get("snapshot_digest")
            .and_then(serde_json::Value::as_str)
            != Some(snapshot.snapshot_digest.as_str())
    {
        return Err(
            "prior delivery selector does not identify the supplied owner snapshot".to_owned(),
        );
    }
    Ok(())
}

fn build_complete_owner_publications(
    task_sources: &TaskControllerCampaignSources,
    materials: DecodedCampaignOwnerMaterials,
) -> Result<Vec<CampaignSourcePublication>, String> {
    crate::campaign_owner_matrix::assemble_campaign_owner_publications(
        task_sources,
        &materials.context_recipe,
        &materials.prior_delivery,
        &materials.evaluation,
        &task_sources.recipe.binding.state_fence,
        &materials.heads,
        materials.remaining_owner_inputs,
    )
    .map(|bundle| bundle.publications)
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
/// Kernel-issued attempt. The recipe and owner materials are still decoded and
/// validated here at the Governor boundary. Every owner-material, native-input,
/// or transition failure is projected as a typed rejected result body; malformed
/// caller material must not terminate the daemon or escape as an untyped poll
/// error.
#[allow(
    clippy::large_futures,
    clippy::too_many_lines,
    reason = "the claim boundary preserves one exact owner transition and one fenced result body"
)]
pub async fn serve_task_controller_claim(
    composition: &DaemonComposition,
    claimed: TaskControllerClaimedInvocation,
) -> Result<TaskControllerResultBody, String> {
    let invocation = &claimed.invocation;
    let recipe: LearningStateViewRecipe =
        match serde_json::from_value(invocation.learning_state_view_recipe.clone()) {
            Ok(recipe) => recipe,
            Err(_) => return task_controller_rejection(&claimed, "invalid_recipe"),
        };
    if recipe.validate().is_err() {
        return task_controller_rejection(&claimed, "invalid_recipe");
    }
    let owner_materials = match invocation.campaign_owner_materials.as_ref() {
        Some(materials) => match decode_campaign_owner_materials(
            materials,
            invocation,
            &claimed.envelope.state_fence,
        ) {
            Ok(materials) => Some(materials),
            Err(_) => return task_controller_rejection(&claimed, "invalid_owner_materials"),
        },
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
            if let Some(materials) = owner_materials {
                lifecycle
                    .propose_task_with_complete_campaign_owner_materials(
                        &claimed.request_identity,
                        claimed.operation_id.clone(),
                        proposal,
                        recipe,
                        move |sources| build_complete_owner_publications(sources, materials),
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
            if let Some(materials) = owner_materials {
                lifecycle
                    .apply_task_with_complete_campaign_owner_materials(
                        &claimed.request_identity,
                        claimed.operation_id.clone(),
                        invocation.task_id.clone(),
                        input.context,
                        input.command,
                        recipe,
                        move |sources| build_complete_owner_publications(sources, materials),
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
