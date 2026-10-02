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
    CampaignOwnerSourceInput, GuardedTaskCommand, KernelTransitionPort, PreparedTaskTransition,
    TaskCommand, TaskCommandContext, TaskProposal,
};
use eliot_learning_contracts::{
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole, ContractBinding,
    LearningStateViewRecipe, ProofCeiling, WorkScopeId,
    identity::{LEARNING_SCHEMA_VERSION, SourceLineage},
};
use eliot_protocol::{
    TaskControllerAction, TaskControllerCampaignOwnerMaterials, TaskControllerResultBody,
};
use eliot_store_api::{
    CampaignSourceDocumentSchema, CampaignSourceHead, CampaignSourcePublication,
    CampaignSourcePublisher, CampaignSourceReadStatus, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRead, NamedReadOperation, NamedReadRequest, ReadConsistency, ScopeId,
};
use serde::Deserialize;

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
    Rejected(Box<TaskControllerResultBody>),
    Ready(Box<PreparedTaskControllerClaim>),
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
    let body: ContextCampaignRecipeBody = serde_json::from_value(serde_json::json!({
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
        serde_json::json!({
            "status": "rejected",
            "reason": if reason.is_empty() { "rejected" } else { reason },
        }),
    )
}

/// Canonical issuer of the `ContractBinding` the Task Controller owner
/// publishes together with the campaign learning-state recipe.
///
/// This is the single place in the daemon where a `ContractBinding` is
/// constructed. `eliot_learning_contracts::ContractBinding` carries no
/// constructor of its own, so before this issuer existed every durable
/// candidate family that binds one (use attribution, improvement experiment,
/// promotion boundary, and the campaign recipe itself) could only obtain a
/// binding from a test literal. The daemon is the composition root that already
/// holds every admitted owner value of one claim, so the binding is minted here
/// from those values and never projected from a neighbouring family's fields.
///
/// # Admitted owner values
///
/// | `ContractBinding` field | admitted owner value on `claimed` |
/// |---|---|
/// | `request_id` | `claimed.request_identity.request.metadata.request_id` |
/// | `operation_id` | `claimed.operation_id` (== `host_request_operation_id(&claimed.envelope)`) |
/// | `product_id` | `claimed.request_identity.request.metadata.product_id` |
/// | `task_id` | `claimed.invocation.task_id` (== `metadata.task_id`) |
/// | `source.owner` | `claimed.request_identity.request.metadata.source_id` |
/// | `state_fence` | `claimed.envelope.state_fence` |
/// | `scope` | `claimed.invocation.work_scope_id` (== `envelope.identity.work_scope_id`) |
///
/// `schema_version` and `proof_ceiling` are the two values this contract family
/// itself declares: `LEARNING_SCHEMA_VERSION` and `ProofCeiling::CandidateArtifact`,
/// the only ceiling `ContractBinding::validate` admits.
///
/// # Values this site does not own
///
/// `policy_revision` and `source.{snapshot,revision,digest}` are not held by any
/// admitted value of this claim and are therefore carried verbatim from the
/// presented recipe's own declaration. They are never defaulted, generated or
/// substituted here. No production consumer compares them against an owner value:
/// the recipe anchor compares `source.owner` only
/// (`eliot_governor::task_lifecycle::validate_campaign_recipe_anchor`) and the
/// remaining lineage fields are checked for shape only by `SourceLineage::validate`.
pub fn issue_admitted_campaign_recipe_binding(
    claimed: &TaskControllerClaimedInvocation,
    presented: &LearningStateViewRecipe,
) -> Option<ContractBinding> {
    let metadata = &claimed.request_identity.request.metadata;
    // `None` is the typed refusal: the admitted claim's work scope is not a
    // scope identity, so no binding can be minted for it. This is deliberately
    // NOT a `Result<_, String>` - a stringly-typed failure in a production
    // function loses the cause, and the caller is a predicate that refuses the
    // claim either way.
    let scope = WorkScopeId::new(claimed.invocation.work_scope_id.as_str()).ok()?;
    Some(ContractBinding {
        schema_version: LEARNING_SCHEMA_VERSION,
        policy_revision: presented.binding.policy_revision,
        request_id: metadata.request_id.clone(),
        operation_id: claimed.operation_id.clone(),
        product_id: metadata.product_id.clone(),
        task_id: claimed.invocation.task_id.clone(),
        scope,
        state_fence: claimed.envelope.state_fence.clone(),
        source: SourceLineage {
            owner: metadata.source_id.clone(),
            snapshot: presented.binding.source.snapshot.clone(),
            revision: presented.binding.source.revision,
            digest: presented.binding.source.digest.clone(),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

/// The daemon's admission decision for one presented campaign recipe binding.
///
/// This is the exact predicate [`prepare_task_controller_claim`] applies, kept
/// as one named function so the decision is provable without a live Kernel
/// transport. It refuses the same owner values the Governor task owner refuses,
/// one layer earlier: `validate_campaign_recipe_anchor`
/// (`crates/governor/eliot-governor/src/task_lifecycle.rs:714`) re-checks them
/// against the accepted request, operation and task fence before any canonical
/// commit, and `campaign_task_sources.rs:430` re-checks them again against the
/// accepted task event. The daemon refusal reuses the existing typed
/// `invalid_recipe` result body rather than introducing an error type, and it
/// never rewrites the presented recipe to the issued binding - a foreign value
/// stays a refusal at every layer.
fn campaign_recipe_binds_the_admitted_claim(
    claimed: &TaskControllerClaimedInvocation,
    recipe: &LearningStateViewRecipe,
) -> bool {
    recipe.validate().is_ok()
        && issue_admitted_campaign_recipe_binding(claimed, recipe)
            .is_some_and(|issued| issued == recipe.binding)
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
                return Ok(TaskControllerClaimPreparation::Rejected(Box::new(
                    task_controller_rejection(&claimed, "invalid_recipe")?,
                )));
            }
        };
    // The binding is re-issued from the admitted owner values of this claim and
    // must equal the binding the recipe presents. The recipe is never rewritten
    // to the issued value: a foreign request, operation, product, task, source
    // owner, work scope or fence stays a refusal, exactly as the Governor task
    // owner's own anchor check refuses the same values a layer down.
    if !campaign_recipe_binds_the_admitted_claim(&claimed, &recipe) {
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
    let Ok(lifecycle) = composition.task_lifecycle() else {
        return match task_controller_rejection(&claimed, "owner_not_ready") {
            Ok(body) => TaskControllerTransitionPreparation::Rejected(Box::new(body)),
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

/// Exchanges the exact owned task transition after the composition guard has
/// been released, preserving the canonical receipt reconciliation contract.
pub async fn exchange_task_controller_transition(
    kernel: &dyn KernelTransitionPort,
    execution: PreparedTaskControllerExecution,
) -> Result<TaskControllerResultBody, String> {
    let Ok(receipt) = execution.transition.exchange(kernel).await else {
        return task_controller_rejection(&execution.claimed, "transition_rejected");
    };
    task_controller_result_body(
        &execution.claimed,
        serde_json::json!({ "status": "committed", "receipt": receipt }),
    )
}

/// Issuer proof for the canonical `ContractBinding` of the campaign recipe
/// (issue #45, item A3, step 1 - CC-007).
///
/// Acceptance bullet under test: "Promotion can be rolled back without deleting
/// evidence/history." These fixtures prove only the prerequisite that bullet is
/// blocked on: a `ContractBinding` can be minted from real admitted owner
/// values instead of a test literal. They publish no candidate, name no
/// promotion owner, and do not touch the promotion gate.
///
/// What is fixed here:
///
/// - `issue_admitted_campaign_recipe_binding` reproduces, field for field, the
///   binding a recipe published under this claim must carry, and every one of
///   the six consumer-required owner values is read from the admitted claim
///   rather than from the presented recipe.
/// - `campaign_recipe_binds_the_admitted_claim` - the exact decision
///   `prepare_task_controller_claim` applies - refuses a recipe whose binding
///   names a foreign request / operation / product / task / source owner / work
///   scope, or a different fence, under the daemon's existing `invalid_recipe`
///   typed rejection. The Governor task owner refuses the same owner values at
///   `crates/governor/eliot-governor/src/task_lifecycle.rs:714`
///   (`validate_campaign_recipe_anchor`) with its existing
///   `TaskLifecycleError::Serialization`; the fixture pins exactly the values
///   that check compares, so the two layers cannot drift apart silently.
///
/// No owner value is invented: the claim, the recipe and the fence are built
/// from the same `eliot_protocol` / `eliot_contracts` / `eliot_learning_contracts`
/// types the production path decodes.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod contract_binding_issuer_tests {
    use super::{
        ContractBinding, LearningStateViewRecipe, ProofCeiling, SourceLineage,
        TaskControllerClaimedInvocation, WorkScopeId, campaign_recipe_binds_the_admitted_claim,
        issue_admitted_campaign_recipe_binding,
    };
    use eliot_contracts::{
        ArtifactId, AuthorityEpoch, ClockReading, EpochId, EpochLineageId, OperationId,
        PolicyRevision, ProductId, RequestId, RequestMetadata, ResourceGeneration, SourceId,
        StateFence, TaskId, TaskRevision, canonical_json_bytes, sha256_hex,
    };
    use eliot_learning_contracts::{
        CampaignActiveOverlayPolicy, CampaignId, CampaignOwnerRecordId, CampaignOwnerRevision,
        CampaignSourceBinding, CampaignSourceRequirement, CampaignSourceRevisionRef,
        CampaignSourceRole, MemberId, OmissionPolicy, OwnerId, SlotId, SlotRequirement, SlotSpec,
        TargetId, identity::LEARNING_SCHEMA_VERSION,
    };
    use eliot_observation::EvidenceFreshness;
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
        RequestIdentity, TaskControllerAction, TaskControllerAttempt, TaskControllerInvocation,
        host_request_operation_id,
    };
    use eliot_receipts::RequestBinding;
    use serde_json::json;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TASK_ID: &str = "task-a3-binding";
    const WORK_SCOPE: &str = "scope-a3-binding";
    const REQUEST_ID: &str = "request-a3-binding";
    const PRODUCT_ID: &str = "eliot";
    const SOURCE_OWNER: &str = "agent-bridge";
    const CAMPAIGN_OWNER: &str = "owner:eliot-governor/task-controller";

    type Proof<T> = Result<T, Box<dyn std::error::Error>>;

    fn aid(value: &str) -> Proof<ArtifactId> {
        Ok(ArtifactId::new(value)?)
    }

    fn digest(value: &str) -> String {
        sha256_hex(value.as_bytes())
    }

    fn test_fence() -> Proof<StateFence> {
        let lineage = EpochLineageId::new(TEST_LINEAGE)?;
        let epoch = EpochId::new(
            lineage,
            std::num::NonZeroU64::new(1).ok_or("epoch sequence")?,
        )?;
        Ok(StateFence::new(epoch, ResourceGeneration::genesis()))
    }

    /// One admitted Task Controller claim: the exact owner values the issuer
    /// reads.
    ///
    /// `fence` carries `task_revision: Some(1)` because
    /// `LearningStateViewRecipe::validate` requires a task-revision fence for the
    /// authenticated `TaskPlan` anchor
    /// (`crates/smart/eliot-learning-contracts/src/state_view.rs:808`).
    fn admitted_claim() -> Proof<TaskControllerClaimedInvocation> {
        let mut fence = test_fence()?;
        fence.task_revision = Some(TaskRevision::genesis());
        let task_id = TaskId::new(TASK_ID)?;
        let envelope = HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "connection-a3-binding".to_owned(),
            identity: HostRequestIdentity {
                request_id: RequestId::new(REQUEST_ID)?,
                correlation_projection: None,
                idempotency_key: "idem-a3-binding".to_owned(),
                cancellation_id: "cancel-a3-binding".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 1_800_000_000_000,
                capability: "eliot.task-controller".to_owned(),
                session_id: Some("session-a3-binding".to_owned()),
                task_id: Some(TASK_ID.to_owned()),
                work_scope_id: Some(WORK_SCOPE.to_owned()),
                payload_schema_id: "eliot.task-controller.invoke.v1".to_owned(),
                payload_sha256: digest("payload-a3-binding"),
            },
            state_fence: fence.clone(),
            descriptor_sha256: digest("descriptor-a3-binding"),
            peer_admission_receipt_sha256: digest("peer-receipt-a3-binding"),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()?;
        envelope.validate()?;
        let operation_id = OperationId::new(host_request_operation_id(&envelope))?;
        let request_identity = RequestIdentity {
            request: RequestBinding {
                metadata: RequestMetadata {
                    request_id: RequestId::new(REQUEST_ID)?,
                    session_id: None,
                    task_id: Some(task_id.clone()),
                    product_id: ProductId::new(PRODUCT_ID)?,
                    source_id: SourceId::new(SOURCE_OWNER)?,
                    state_fence: fence.clone(),
                    clock: ClockReading::default(),
                },
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-a3-binding".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-a3-binding".to_owned(),
        };
        request_identity.validate()?;
        Ok(TaskControllerClaimedInvocation {
            invocation: TaskControllerInvocation {
                wire_id: eliot_protocol::TASK_CONTROLLER_INVOCATION_WIRE_ID.to_owned(),
                wire_version: eliot_protocol::TASK_CONTROLLER_INVOCATION_WIRE_VERSION,
                action: TaskControllerAction::Propose,
                task_id: task_id.clone(),
                work_scope_id: WORK_SCOPE.to_owned(),
                task_input: json!({}),
                learning_state_view_recipe: json!({}),
                context_campaign_recipe_catalogue: json!({}),
                context_campaign_recipe: json!({}),
                context_input: json!({}),
                prior_delivery_selector: None,
                campaign_owner_materials: None,
            },
            envelope,
            tool: json!({}),
            request_identity,
            operation_id: operation_id.clone(),
            attempt: TaskControllerAttempt {
                wire_id: eliot_protocol::TASK_CONTROLLER_ATTEMPT_WIRE_ID.to_owned(),
                wire_version: eliot_protocol::TASK_CONTROLLER_ATTEMPT_WIRE_VERSION,
                operation_id: operation_id.as_str().to_owned(),
                attempt_id: "attempt-a3-binding".to_owned(),
                fencing_generation: 1,
                session_id: "session-a3-binding".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                scope_id: WORK_SCOPE.to_owned(),
                expires_at_unix_ms: 1_800_000_000_000,
                use_budget: 1,
                task_id,
                state_fence: fence,
            },
        })
    }

    /// The exact source lineage the presented recipe declares.
    ///
    /// This is the family of values the daemon does not own: they identify the
    /// authoring source of the recipe, so the issuer carries them verbatim and
    /// they must survive issuance byte-identically.
    fn presented_lineage() -> Proof<SourceLineage> {
        Ok(SourceLineage {
            owner: SourceId::new(SOURCE_OWNER)?,
            snapshot: aid("snapshot-a3-binding")?,
            revision: TaskRevision::genesis(),
            digest: digest("source-a3-binding"),
        })
    }

    /// The binding the issuer returns when handed only the presented recipe's
    /// declared lineage. Building the recipe needs the binding, and the binding
    /// needs four carried fields from the recipe, so this fixture breaks the
    /// cycle by naming those four declared values directly - it is exactly what
    /// a caller publishes, not a second source of truth.
    fn presented_binding(claimed: &TaskControllerClaimedInvocation) -> Proof<ContractBinding> {
        Ok(ContractBinding {
            schema_version: LEARNING_SCHEMA_VERSION,
            policy_revision: PolicyRevision::genesis(),
            request_id: RequestId::new(REQUEST_ID)?,
            operation_id: claimed.operation_id.clone(),
            product_id: ProductId::new(PRODUCT_ID)?,
            task_id: TaskId::new(TASK_ID)?,
            scope: WorkScopeId::new(WORK_SCOPE)?,
            state_fence: claimed.envelope.state_fence.clone(),
            source: presented_lineage()?,
            proof_ceiling: ProofCeiling::CandidateArtifact,
        })
    }

    fn source_revision(role: CampaignSourceRole) -> CampaignOwnerRevision {
        match role {
            CampaignSourceRole::TaskObjective
            | CampaignSourceRole::TaskAcceptance
            | CampaignSourceRole::TaskOpenItems
            | CampaignSourceRole::TaskPlan => CampaignOwnerRevision::Task(TaskRevision::genesis()),
            CampaignSourceRole::GovernorEpoch => {
                CampaignOwnerRevision::AuthorityEpoch(AuthorityEpoch::genesis())
            }
            CampaignSourceRole::GovernorPolicy => {
                CampaignOwnerRevision::Policy(PolicyRevision::genesis())
            }
            CampaignSourceRole::MemoryProjection
            | CampaignSourceRole::StableHarness
            | CampaignSourceRole::TaskFamilyHarness => {
                CampaignOwnerRevision::ResourceGeneration(ResourceGeneration::genesis())
            }
            CampaignSourceRole::FrozenAnchor | CampaignSourceRole::ArtifactProjection => {
                CampaignOwnerRevision::ResourceSnapshot("resource-snapshot-a3-binding".to_owned())
            }
            _ => CampaignOwnerRevision::Counter(1),
        }
    }

    /// A sealed, valid recipe carrying the admitted claim's own binding.
    ///
    /// `CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed` is the
    /// owner-declared policy under which the `ActiveOverlay` role must be
    /// `ExplicitlyAbsent` and not load-bearing
    /// (`crates/smart/eliot-learning-contracts/src/state_view.rs:814`); no
    /// active overlay is invented here.
    fn admitted_recipe(
        claimed: &TaskControllerClaimedInvocation,
    ) -> Proof<LearningStateViewRecipe> {
        let target = TargetId::new("target-a3-binding")?;
        let task_controller_owner = OwnerId::from_artifact(aid(CAMPAIGN_OWNER)?);
        let binding = presented_binding(claimed)?;
        let mut requirements = Vec::with_capacity(CampaignSourceRole::all().len());
        for role in CampaignSourceRole::all() {
            let absent = role == CampaignSourceRole::ActiveOverlay;
            let task_anchor = role == CampaignSourceRole::TaskPlan;
            let task_controller_role = matches!(
                role,
                CampaignSourceRole::TaskObjective
                    | CampaignSourceRole::TaskAcceptance
                    | CampaignSourceRole::TaskOpenItems
            );
            let owner = if absent || task_anchor || task_controller_role {
                task_controller_owner.clone()
            } else {
                OwnerId::from_artifact(aid(&format!("owner-a3-binding-{role:?}"))?)
            };
            requirements.push(CampaignSourceRequirement {
                role,
                source_binding: if absent {
                    CampaignSourceBinding::ExplicitlyAbsent
                } else if task_anchor {
                    CampaignSourceBinding::AuthenticatedTaskAnchor
                } else {
                    CampaignSourceBinding::ExactReference
                },
                owner: owner.clone(),
                expected_reference: if absent || task_anchor {
                    None
                } else {
                    Some(CampaignSourceRevisionRef {
                        role,
                        owner,
                        record_id: CampaignOwnerRecordId::Artifact(aid(&format!(
                            "record-a3-binding-{role:?}"
                        ))?),
                        revision: source_revision(role),
                        content_digest: digest(&format!("content-a3-binding-{role:?}")),
                        slot_projection_digests: Vec::new(),
                        recorded_state_fence: binding.state_fence.clone(),
                    })
                },
                load_bearing: !absent,
            });
        }
        let mut recipe = LearningStateViewRecipe {
            recipe_id: aid("recipe-a3-binding")?,
            campaign_id: CampaignId::from_artifact(aid("campaign-a3-binding")?),
            target: target.clone(),
            binding,
            slots: vec![SlotSpec {
                slot_id: SlotId::from_artifact(aid("slot-a3-binding")?),
                owner: task_controller_owner,
                source_role: CampaignSourceRole::TaskObjective,
                target,
                requirement: SlotRequirement::Required,
                declared_members: vec![MemberId::from_artifact(aid("member-a3-binding")?)],
                accepted_type: "task-objective/v1".to_owned(),
                schema_digest: digest("task-objective-schema"),
            }],
            source_requirements: requirements,
            active_overlay_policy: CampaignActiveOverlayPolicy::ExplicitlyAbsentAllowed,
            freshness: EvidenceFreshness::ExactCandidate,
            privacy_class: "task-local".to_owned(),
            omission_policy: OmissionPolicy::RequiredSlots,
            canonical_digest: String::new(),
        };
        recipe.seal()?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Positive case: the issuer reproduces the admitted binding field for
    /// field, reading every consumer-required owner value from the claim.
    #[test]
    fn issuer_reproduces_every_owner_value_from_the_admitted_claim() -> Proof<()> {
        let claimed = admitted_claim()?;
        let recipe = admitted_recipe(&claimed)?;
        let issued = issue_admitted_campaign_recipe_binding(&claimed, &recipe)
            .ok_or("the admitted claim must source a scope identity")?;

        let metadata = &claimed.request_identity.request.metadata;
        assert_eq!(
            issued.schema_version, LEARNING_SCHEMA_VERSION,
            "schema_version is the value this family declares"
        );
        assert_eq!(
            issued.proof_ceiling,
            ProofCeiling::CandidateArtifact,
            "this package never emits a higher ceiling"
        );
        assert_eq!(
            issued.request_id, metadata.request_id,
            "request_id comes from the admitted request metadata"
        );
        assert_eq!(
            issued.operation_id, claimed.operation_id,
            "operation_id comes from the admitted operation identity"
        );
        assert_eq!(
            issued.product_id, metadata.product_id,
            "product_id comes from the admitted request metadata"
        );
        assert_eq!(
            issued.task_id, claimed.invocation.task_id,
            "task_id comes from the admitted invocation"
        );
        assert_eq!(
            issued.scope.as_str(),
            claimed.invocation.work_scope_id,
            "scope comes from the admitted work scope"
        );
        assert_eq!(
            issued.state_fence, claimed.envelope.state_fence,
            "state_fence comes from the admitted envelope fence"
        );
        assert_eq!(
            issued.source.owner, metadata.source_id,
            "source owner comes from the admitted source identity"
        );

        // The lineage the daemon does not own is carried verbatim.
        assert_eq!(issued.policy_revision, recipe.binding.policy_revision);
        assert_eq!(issued.source.snapshot, recipe.binding.source.snapshot);
        assert_eq!(issued.source.revision, recipe.binding.source.revision);
        assert_eq!(issued.source.digest, recipe.binding.source.digest);

        assert_eq!(
            issued, recipe.binding,
            "a recipe published under this claim carries exactly the issued binding"
        );
        assert!(
            campaign_recipe_binds_the_admitted_claim(&claimed, &recipe),
            "the production predicate admits the admitted recipe"
        );
        Ok(())
    }

    /// Refusal case: a recipe naming a foreign request, operation, product,
    /// task, source owner or work scope, or a different fence, is refused by the
    /// production predicate before any owner read or canonical commit.
    ///
    /// Each substituted field is one of the values
    /// `validate_campaign_recipe_anchor` compares against the admitted request,
    /// operation, task, product, source owner and fence, so this fixture pins
    /// exactly the set that check re-checks one layer down.
    #[test]
    fn foreign_owner_values_are_refused_by_the_existing_anchor_check() -> Proof<()> {
        let claimed = admitted_claim()?;
        let admitted = admitted_recipe(&claimed)?;
        let metadata = &claimed.request_identity.request.metadata;

        let mut foreign_request = admitted.clone();
        foreign_request.binding.request_id = RequestId::new("request-a3-foreign")?;
        let mut foreign_operation = admitted.clone();
        foreign_operation.binding.operation_id = OperationId::new("operation-a3-foreign")?;
        let mut foreign_product = admitted.clone();
        foreign_product.binding.product_id = ProductId::new("product-a3-foreign")?;
        let mut foreign_task = admitted.clone();
        foreign_task.binding.task_id = TaskId::new("task-a3-foreign")?;
        let mut foreign_source = admitted.clone();
        foreign_source.binding.source.owner = SourceId::new("agent-bridge-a3-foreign")?;
        let mut foreign_fence = admitted.clone();
        foreign_fence.binding.state_fence.task_revision = Some(TaskRevision::new(7)?);
        let mut foreign_scope = admitted.clone();
        foreign_scope.binding.scope = WorkScopeId::new("scope-a3-foreign")?;

        for (label, recipe) in [
            ("foreign request_id", &mut foreign_request),
            ("foreign operation_id", &mut foreign_operation),
            ("foreign product_id", &mut foreign_product),
            ("foreign task_id", &mut foreign_task),
            ("foreign source.owner", &mut foreign_source),
            ("different state_fence", &mut foreign_fence),
            ("foreign work scope", &mut foreign_scope),
        ] {
            // Each substitution stays a valid, sealed recipe, so the refusal is
            // caused by the binding alone and never by a malformed fixture: a
            // stale `canonical_digest` would otherwise make `validate` fail for a
            // reason unrelated to the binding under test.
            recipe.seal()?;
            recipe
                .validate()
                .unwrap_or_else(|error| panic!("{label} fixture must stay valid: {error}"));
            assert!(
                !campaign_recipe_binds_the_admitted_claim(&claimed, recipe),
                "{label} must be refused before any owner read or canonical commit"
            );
            assert_ne!(
                issue_admitted_campaign_recipe_binding(&claimed, recipe).ok_or(
                    "each substituted field must still mint a binding to be refused by VALUE"
                )?,
                recipe.binding,
                "{label} must not equal the admitted binding"
            );
        }

        // The admitted values are exactly what the Governor anchor compares
        // against, so this layer and that check cannot disagree about which
        // value is foreign.
        assert_eq!(admitted.binding.request_id, metadata.request_id);
        assert_eq!(admitted.binding.operation_id, claimed.operation_id);
        assert_eq!(admitted.binding.product_id, metadata.product_id);
        assert_eq!(admitted.binding.task_id, claimed.invocation.task_id);
        assert_eq!(admitted.binding.source.owner, metadata.source_id);
        assert_eq!(admitted.binding.state_fence, claimed.envelope.state_fence);
        Ok(())
    }

    /// The issued binding is the one canonical JSON shape every consumer already
    /// reads: re-encoding it round-trips exactly, so issuance adds no second
    /// wire identity and no new digest scheme.
    #[test]
    fn issued_binding_round_trips_through_the_canonical_wire_shape() -> Proof<()> {
        let claimed = admitted_claim()?;
        let recipe = admitted_recipe(&claimed)?;
        let issued = issue_admitted_campaign_recipe_binding(&claimed, &recipe)
            .ok_or("the admitted claim must source a scope identity")?;
        let decoded: ContractBinding = serde_json::from_slice(&canonical_json_bytes(&issued)?)?;
        assert_eq!(decoded, issued);
        Ok(())
    }
}
