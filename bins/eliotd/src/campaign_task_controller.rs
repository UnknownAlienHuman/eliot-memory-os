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
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole, LearningStateViewRecipe,
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
    Rejected(Box<TaskControllerResultBody>),
    Ready(Box<PreparedTaskControllerClaim>),
}

/// Canonical task plan plus the exact claim which will carry its result.
pub struct PreparedTaskControllerExecution {
    claimed: TaskControllerClaimedInvocation,
    transition: PreparedTaskTransition,
}

/// The admitted, Kernel-issued material the coordination lifecycle leg consumes.
///
/// This is the exact claim material, projected without derivation: the attempt
/// is the Kernel-issued fenced capability and the identity is the admitted
/// request identity for the same claim. The coordination work-item and lease
/// identity is issued from these by
/// [`eliot_governor::issue_coordination_work`](eliot_governor::issue_coordination_work);
/// nothing in this adapter mints it.
#[derive(Clone, Debug)]
pub struct TaskControllerCoordinationSource {
    /// The Kernel-issued fenced attempt for this claim.
    pub attempt: eliot_protocol::TaskControllerAttempt,
    /// The admitted request identity the Kernel issued the attempt under.
    pub identity: eliot_protocol::RequestIdentity,
}

/// Projects the coordination source out of one admitted claim.
///
/// Called before the claim is consumed by preparation, so the coordination leg
/// is driven by the same admitted attempt that carried the task transition
/// rather than by anything re-read afterwards.
#[must_use]
pub fn task_controller_coordination_source(
    claimed: &TaskControllerClaimedInvocation,
) -> TaskControllerCoordinationSource {
    TaskControllerCoordinationSource {
        attempt: claimed.attempt.clone(),
        identity: claimed.request_identity.clone(),
    }
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
        json!({ "status": "committed", "receipt": receipt }),
    )
}

/// Records the coordination candidate reference for one admitted Task
/// Controller result (issue #370 R1).
///
/// The coordination owner is a candidate *reference* owner: what it records is
/// that one exact Kernel-admitted attempt produced one exact bounded result
/// artifact, addressed by the recorded `result_digest` of the response bytes.
/// The admitted receipt is capped at `CandidateArtifact` by the owner itself.
/// This records no provider disposition, no verifier outcome, no acceptance
/// satisfaction, and no Task finish input — a Task result is never derived from
/// it here.
///
/// `result` is the ORIGINAL RECORDED result body, not a digest handed in beside
/// it. The recorded `result_digest` is read off that body only after the body's
/// own owner validator
/// ([`TaskControllerResultBody::validate`], which re-binds `result_digest` to
/// the exact canonical response bytes and binds the embedded attempt to the
/// operation handle) has passed on the original value. Nothing is recomputed
/// here and compared against a recomputation, so a substituted or stale digest
/// cannot be recorded as this attempt's candidate artifact.
///
/// The body's embedded attempt must BE this leg's attempt. `source.attempt` is
/// the independent expected set here — the Kernel-issued capability projected
/// out of the admitted claim before preparation consumed it — so a body carried
/// over from another admitted claim is refused rather than having its digest
/// attributed to this one. This is what makes the reference bound to *this*
/// operation by content instead of by the caller's choice of which bytes to
/// pass.
///
/// The identity is issued by the Governor, not here: `source` is the exact
/// Kernel-issued attempt and admitted request identity, and
/// [`eliot_governor::issue_coordination_work`] derives the work item, lease,
/// result, and per-leg transport identities from them. This adapter mints
/// nothing and defaults nothing; an attempt with no remaining window, a fence
/// or task disagreement between the attempt and the admitted identity, and an
/// invalid attempt are each refused by the issuer before any owner is touched.
///
/// Call this only after the Kernel has accepted the result body, so the
/// coordination reference never records a result the Kernel refused to durably
/// admit.
pub async fn record_task_controller_coordination_candidate(
    composition: &mut DaemonComposition,
    source: &TaskControllerCoordinationSource,
    result: &TaskControllerResultBody,
    now: u64,
) -> Result<
    (
        eliot_governor::CommittedCoordinationResult,
        eliot_governor::CommittedCoordinationLease,
    ),
    String,
> {
    result
        .validate()
        .map_err(|error| format!("coordination candidate result body: {error}"))?;
    if result.attempt != source.attempt {
        return Err(
            "coordination candidate result body does not bind this admitted attempt".to_owned(),
        );
    }
    let issued = eliot_governor::issue_coordination_work(&source.attempt, &source.identity, now)
        .map_err(|error| format!("coordination work identity issuance: {error}"))?;
    let ingress = crate::coordination_owner_ingress::CoordinationResultIngress {
        request_id: issued.result_leg.request_id.as_str().to_owned(),
        result_id: issued.result_id.clone(),
        session_id: issued.lease.session_id.clone(),
        work_item_id: issued.lease.work_item_id.clone(),
        lease_id: issued.lease.lease_id.clone(),
        authority_epoch: source.attempt.authority_epoch.clone(),
        state_fence: source.attempt.state_fence.clone(),
        result_ref: format!(
            "{}:{}",
            eliot_governor::COORDINATION_RESULT_ARTIFACT_NAMESPACE,
            result.result_digest
        ),
        now,
    };
    // The four durable legs are awaited one after another inside this call, so
    // the whole issuance record would otherwise be held in the caller's future
    // across every await. Boxing the future keeps that state on the heap for the
    // duration of the commit instead of on the task's stack frame.
    Box::pin(composition.commit_coordination_candidate_lifecycle(issued, ingress))
        .await
        .map_err(|error| format!("coordination lifecycle commit: {error}"))
}
