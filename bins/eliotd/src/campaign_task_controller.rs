//! Production Task Controller claim servicing for the current daemon.
//!
//! Kernel owns admission, queue ownership, and the fenced attempt capability.
//! This adapter only decodes the owner-native task payload, delegates the
//! semantic transition to the single Governor task owner, and submits the
//! exact typed result through Kernel. The Governor transition constructs the
//! Task Controller's native campaign rows; this adapter never writes a source
//! record or reconstructs a missing owner publication.

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::{
    CampaignOwnerSourceInput, GuardedTaskCommand, KernelTransitionPort, PreparedTaskTransition,
    TaskCommand, TaskCommandContext, TaskProposal,
};
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
    Rejected(TaskControllerResultBody),
    Ready(PreparedTaskControllerClaim),
}

/// Canonical task plan plus the exact claim which will carry its result.
pub struct PreparedTaskControllerExecution {
    claimed: TaskControllerClaimedInvocation,
    transition: PreparedTaskTransition,
}

pub enum TaskControllerTransitionPreparation {
    Rejected(TaskControllerResultBody),
    Failed(String),
    Ready(PreparedTaskControllerExecution),
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

/// Decodes one claim and performs every external campaign read before the
/// caller borrows the shared composition. Owner-specific checks still happen
/// under that composition through `prepare_task_controller_transition`.
pub async fn prepare_task_controller_claim(
    reads: &KernelContextReadClient,
    kernel: &dyn KernelTransitionPort,
    claimed: TaskControllerClaimedInvocation,
) -> Result<TaskControllerClaimPreparation, String> {
    let invocation = &claimed.invocation;
    let recipe: LearningStateViewRecipe =
        match serde_json::from_value(invocation.learning_state_view_recipe.clone()) {
            Ok(recipe) => recipe,
            Err(_) => {
                return Ok(TaskControllerClaimPreparation::Rejected(
                    task_controller_rejection(&claimed, "invalid_recipe")?,
                ));
            }
        };
    if recipe.validate().is_err()
        || recipe.binding.task_id.as_str() != invocation.task_id.as_str()
        || recipe.binding.scope.as_str() != invocation.work_scope_id
        || recipe.binding.state_fence != claimed.envelope.state_fence
    {
        return Ok(TaskControllerClaimPreparation::Rejected(
            task_controller_rejection(&claimed, "invalid_recipe")?,
        ));
    }
    let complete_owner_publications = match invocation.campaign_owner_materials.as_ref() {
        Some(materials) => {
            if reject_caller_owner_material(materials).is_err() {
                return Ok(TaskControllerClaimPreparation::Rejected(
                    task_controller_rejection(&claimed, "invalid_owner_materials")?,
                ));
            }
            match read_authenticated_owner_publications(
                reads,
                &recipe,
                &claimed.envelope.state_fence,
            )
            .await
            {
                Ok(publications) => Some(publications),
                Err(_) => {
                    return Ok(TaskControllerClaimPreparation::Rejected(
                        task_controller_rejection(&claimed, "owner_read_unavailable")?,
                    ));
                }
            }
        }
        None => None,
    };

    let action = match invocation.action {
        TaskControllerAction::Propose => {
            let proposal: TaskProposal = match serde_json::from_value(invocation.task_input.clone())
            {
                Ok(proposal) => proposal,
                Err(_) => {
                    return Ok(TaskControllerClaimPreparation::Rejected(
                        task_controller_rejection(&claimed, "invalid_task_input")?,
                    ));
                }
            };
            if proposal.task_id != invocation.task_id {
                return Ok(TaskControllerClaimPreparation::Rejected(
                    task_controller_rejection(&claimed, "invalid_task_input")?,
                ));
            }
            PreparedTaskControllerAction::Propose(proposal)
        }
        TaskControllerAction::Apply => {
            let input: ApplyTaskInput = match serde_json::from_value(invocation.task_input.clone())
            {
                Ok(input) => input,
                Err(_) => {
                    return Ok(TaskControllerClaimPreparation::Rejected(
                        task_controller_rejection(&claimed, "invalid_task_input")?,
                    ));
                }
            };
            PreparedTaskControllerAction::Apply(GuardedTaskCommand {
                task_id: invocation.task_id.clone(),
                context: input.context,
                command: input.command,
            })
        }
    };
    let source_heads = match kernel
        .campaign_source_heads(
            &invocation.task_id,
            recipe.binding.scope.as_str(),
            &claimed.envelope.state_fence,
        )
        .await
    {
        Ok(heads) => heads,
        Err(_) => {
            return Ok(TaskControllerClaimPreparation::Rejected(
                task_controller_rejection(&claimed, "transition_rejected")?,
            ));
        }
    };
    Ok(TaskControllerClaimPreparation::Ready(
        PreparedTaskControllerClaim {
            claimed,
            recipe,
            source_heads,
            owner_publications: complete_owner_publications,
            action,
        },
    ))
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
    let Ok(lifecycle) = composition.task_lifecycle() else {
        return match task_controller_rejection(&claimed, "owner_not_ready") {
            Ok(body) => TaskControllerTransitionPreparation::Rejected(body),
            Err(error) => TaskControllerTransitionPreparation::Failed(error),
        };
    };
    let transition = match (action, owner_publications) {
        (PreparedTaskControllerAction::Propose(proposal), Some(publications)) => lifecycle
            .prepare_propose_task_with_complete_campaign_sources(
                &claimed.request_identity,
                claimed.operation_id.clone(),
                proposal,
                recipe,
                source_heads,
                publications,
            ),
        (PreparedTaskControllerAction::Propose(proposal), None) => lifecycle
            .prepare_propose_task_with_learning_state_recipe(
                &claimed.request_identity,
                claimed.operation_id.clone(),
                proposal,
                recipe,
                source_heads,
            ),
        (PreparedTaskControllerAction::Apply(guarded), Some(publications)) => lifecycle
            .prepare_apply_task_with_complete_campaign_sources(
                &claimed.request_identity,
                claimed.operation_id.clone(),
                guarded,
                recipe,
                source_heads,
                publications,
            ),
        (PreparedTaskControllerAction::Apply(guarded), None) => lifecycle
            .prepare_apply_task_with_learning_state_recipe(
                &claimed.request_identity,
                claimed.operation_id.clone(),
                guarded,
                recipe,
                source_heads,
            ),
    };
    match transition {
        Ok(transition) => {
            TaskControllerTransitionPreparation::Ready(PreparedTaskControllerExecution {
                claimed,
                transition,
            })
        }
        Err(_) => match task_controller_rejection(&claimed, "transition_rejected") {
            Ok(body) => TaskControllerTransitionPreparation::Rejected(body),
            Err(error) => TaskControllerTransitionPreparation::Failed(error),
        },
    }
}

/// Exchanges the exact owned task transition after the composition guard has
/// been released, preserving the canonical receipt reconciliation contract.
pub async fn exchange_task_controller_transition(
    kernel: &dyn KernelTransitionPort,
    execution: PreparedTaskControllerExecution,
) -> Result<TaskControllerResultBody, String> {
    let receipt = match execution.transition.exchange(kernel).await {
        Ok(receipt) => receipt,
        Err(_) => return task_controller_rejection(&execution.claimed, "transition_rejected"),
    };
    task_controller_result_body(
        &execution.claimed,
        json!({ "status": "committed", "receipt": receipt }),
    )
}
