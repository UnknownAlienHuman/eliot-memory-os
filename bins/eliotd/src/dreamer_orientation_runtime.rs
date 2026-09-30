//! Explicit Task Controller ingress for already-sealed Dreamer Orientation jobs.
//!
//! This path consumes the original K0 request and semantic input publication
//! supplied by an authenticated Task Controller claim. It performs only the
//! existing named-read and queue joins; it does not mint request identities,
//! admission references, source digests, or model authority.

use std::sync::Arc;

use eliot_dreamer_contracts::DreamJobInput;
use eliot_governor::CompositionError;
use eliot_protocol::{
    TaskControllerOrientationInput, TaskControllerOrientationOutputSchemaRecipe,
    TaskControllerOrientationSourceClaim,
    dreamer_job::{
        DurableJobRequest, DurableJobResponse, DurableJobRuntimeOwnerExecutionInput, JobOperation,
        OpaqueContentRef,
    },
};

/// Exact owner-publication handoff for a successfully queued Orientation
/// request. The queue response is bound to `request`; all schema fields and
/// bytes are the original submitted recipe/source and its authenticated read.
#[derive(Clone, Debug)]
pub struct OrientationQueuedOwnerPublication {
    /// Authentic Task Controller claim that admitted this ingress payload.
    pub task_controller_claim: TaskControllerClaimedInvocation,
    /// Exact already-sealed Durable Job request submitted to Kernel.
    pub request: DurableJobRequest,
    /// Exact original ContextReconstruction owner result carried into the
    /// sealed runtime publication and preserved through the claim handoff.
    pub context_reconstruction_result: eliot_protocol::HostRequestResultBody,
    /// Durable queue response bound to the exact request and original source.
    pub response: DurableJobResponse,
    /// Original semantic reference and exact canonical DreamJobInput bytes.
    pub semantic_input: OrientationSemanticInputPublication,
    /// Exact original runtime-owner execution input decoded from the sealed
    /// request and preserved in its durable response.
    pub runtime_owner_execution_input: DurableJobRuntimeOwnerExecutionInput,
    /// Original output-contract reference carried by the sealed submission.
    pub output_contract: OpaqueContentRef,
    /// Exact original OutputSchema recipe member.
    pub output_schema_recipe: TaskControllerOrientationOutputSchemaRecipe,
    /// Exact original schema-source claim from the admitted Task Controller payload.
    pub schema_source: TaskControllerOrientationSourceClaim,
    /// Exact canonical schema bytes returned by the authenticated named read.
    pub schema_bytes: Vec<u8>,
}

/// Typed refusal while assembling a Task Controller Orientation source handoff.
#[derive(Clone, Debug)]
pub enum OrientationRuntimeError {
    /// Typed input, identity, scope, fence, or bound rejection.
    Input(&'static str),
    /// Schema-source named read refused, changed, or was unavailable.
    SchemaRead(DreamerMaterialsError),
    /// Existing K0/Governor queue join refused.
    Submit(OrientationSubmitError),
    /// The durable response omitted or changed the retained semantic source.
    ResponseSemantic(OrientationSemanticInputError),
}

impl OrientationRuntimeError {
    fn reason_code(&self) -> &'static str {
        match self {
            Self::Input(reason) => reason,
            Self::SchemaRead(error) => output_schema_refusal_code(error),
            Self::Submit(error) => orientation_refusal_code(error),
            Self::ResponseSemantic(error) => semantic_refusal_code(error),
        }
    }
}
use eliot_read::ReadService;
use eliot_store_api::ScopeId;
use serde_json::json;

use crate::{
    DaemonComposition, DaemonKernelClient,
    campaign_task_controller::{PreparedTaskControllerOrientation, task_controller_result_body},
    daemon_kernel_client::TaskControllerClaimedInvocation,
    dreamer_admission::{
        KernelDreamerJobQueue, OrientationSemanticInputClaim, OrientationSemanticInputError,
        OrientationSemanticInputPublication, OrientationSubmitError, OrientationSubmitInput,
        submit_admitted_orientation_typed,
    },
    dreamer_materials::{
        AdmittedSourceClaim, DreamerMaterialsError, OrientationMaterialBudget,
        freeze_orientation_manifest, resolve_source_claim,
    },
    kernel_context_read_client::KernelContextReadClient,
};

/// Resolves and submits one Orientation action from the real Task Controller
/// claim poll path. The inner request, reference and inline bytes are retained
/// exactly as issued by the original publisher and are never resealed here.
pub async fn dispatch_task_controller_orientation_claim(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    kernel: &Arc<DaemonKernelClient>,
    prepared: PreparedTaskControllerOrientation,
) -> Result<eliot_protocol::TaskControllerResultBody, String> {
    let claimed = prepared.claimed.clone();
    match submit_task_controller_orientation_claim(composition, kernel, prepared).await {
        Ok(publication) => task_controller_result_body(
            &publication.task_controller_claim,
            json!({
                "status": "queued",
                "job_id": publication.response.job_id,
                "state": publication.response.state,
            }),
        ),
        Err(error) => blocked_result(&claimed, error.reason_code()),
    }
}

/// Resolves and submits one explicit Orientation claim, returning the exact
/// same-operation material a later model worker must consume. No original
/// request identity or source reference is minted or resealed.
pub async fn submit_task_controller_orientation_claim(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    kernel: &Arc<DaemonKernelClient>,
    prepared: PreparedTaskControllerOrientation,
) -> Result<OrientationQueuedOwnerPublication, OrientationRuntimeError> {
    let PreparedTaskControllerOrientation { claimed, input } = prepared;
    let context_reconstruction_result = input.context_reconstruction_result.clone();
    let (readiness, admitted_fence) = {
        let guard = composition.lock().await;
        (
            guard.readiness(),
            guard.kernel_snapshot().state_fence().clone(),
        )
    };

    let (orientation, output_schema, schema_source, schema_source_wire) =
        build_submit_input(input).map_err(OrientationRuntimeError::Input)?;
    let ctx = orientation
        .request
        .request_identity
        .request
        .metadata
        .clone();
    if ctx.state_fence != admitted_fence {
        return Err(OrientationRuntimeError::Input("orientation_stale_fence"));
    }
    if readiness != eliot_governor::CompositionReadiness::Ready {
        return Err(OrientationRuntimeError::Input("governor_not_ready"));
    }
    match freeze_orientation_manifest(
        orientation.scope.as_str(),
        &admitted_fence,
        &orientation.materials,
        &orientation.budget,
    ) {
        Ok(manifest) if manifest.validate().is_ok() => {}
        Err(DreamerMaterialsError::FenceMismatch) => {
            return Err(OrientationRuntimeError::Input("orientation_stale_fence"));
        }
        _ => {
            return Err(OrientationRuntimeError::Input(
                "orientation_materials_invalid",
            ));
        }
    };
    if schema_source.validate().is_err() {
        return Err(OrientationRuntimeError::Input(
            "output_schema_source_invalid",
        ));
    }

    let reads = ReadService::new(KernelContextReadClient::new(Arc::clone(kernel)));
    let schema_bytes = resolve_source_claim(&reads, &ctx, &orientation.scope, &schema_source)
        .await
        .map_err(OrientationRuntimeError::SchemaRead)?;
    let queue = KernelDreamerJobQueue::new(kernel.as_ref());
    let request = orientation.request.clone();
    let runtime_owner_execution_input = match &request.operation {
        JobOperation::Submit { submission } => submission
            .decode_runtime_owner_execution_input()
            .map_err(|_| OrientationRuntimeError::Input("runtime_owner_execution_input_mismatch"))?
            .ok_or(OrientationRuntimeError::Input(
                "runtime_owner_execution_input_unavailable",
            ))?,
        _ => {
            return Err(OrientationRuntimeError::Input(
                "invalid_orientation_request",
            ));
        }
    };
    let output_contract = match &request.operation {
        JobOperation::Submit { submission } => submission.output_contract.clone(),
        _ => {
            return Err(OrientationRuntimeError::Input(
                "invalid_orientation_request",
            ));
        }
    };
    let response = submit_admitted_orientation_typed(
        readiness,
        &admitted_fence,
        &reads,
        &ctx,
        &orientation,
        &queue,
    )
    .await
    .map_err(OrientationRuntimeError::Submit)?;
    let semantic_input = OrientationSemanticInputPublication::from_durable_response(&response)
        .map_err(OrientationRuntimeError::ResponseSemantic)?;
    Ok(OrientationQueuedOwnerPublication {
        task_controller_claim: claimed,
        request,
        context_reconstruction_result,
        response,
        semantic_input,
        runtime_owner_execution_input,
        output_contract,
        output_schema_recipe: output_schema,
        schema_source: schema_source_wire,
        schema_bytes,
    })
}

fn build_submit_input(
    input: TaskControllerOrientationInput,
) -> Result<
    (
        OrientationSubmitInput,
        TaskControllerOrientationOutputSchemaRecipe,
        AdmittedSourceClaim,
        TaskControllerOrientationSourceClaim,
    ),
    &'static str,
> {
    let JobOperation::Submit { submission } = &input.request.operation else {
        return Err("invalid_orientation_request");
    };
    let original_output_contract = submission.output_contract.clone();
    let output_schema = input.output_schema_recipe.clone();
    let schema_source_wire = input.schema_source;
    let schema_source = source_claim(schema_source_wire.clone());
    let publication = OrientationSemanticInputPublication::new(
        submission.semantic_input.clone(),
        submission
            .semantic_input_bytes
            .clone()
            .ok_or("semantic_input_unavailable")?,
    )
    .map_err(|error| match error {
        OrientationSemanticInputError::MissingBytes
        | OrientationSemanticInputError::MissingReference => "semantic_input_unavailable",
        OrientationSemanticInputError::FenceMismatch => "orientation_stale_fence",
        OrientationSemanticInputError::ReferenceBytesMismatch
        | OrientationSemanticInputError::ReferenceMismatch
        | OrientationSemanticInputError::ContractIdentityMismatch => "semantic_input_mismatch",
        _ => "semantic_input_invalid",
    })?;
    let job = publication
        .validate_for_request(&input.request, submission)
        .map_err(|error| match error {
            OrientationSemanticInputError::FenceMismatch => "orientation_stale_fence",
            OrientationSemanticInputError::ReferenceMismatch
            | OrientationSemanticInputError::ReferenceBytesMismatch => "semantic_input_mismatch",
            _ => "semantic_input_invalid",
        })?;
    validate_original_output_schema(
        &job,
        &original_output_contract,
        &output_schema,
        &schema_source,
    )?;
    if schema_source.source_handle.as_str() == input.semantic_source.source_handle.as_str()
        || input
            .materials
            .iter()
            .any(|claim| claim.source_handle.as_str() == schema_source.source_handle.as_str())
    {
        return Err("orientation_source_claim_not_distinct");
    }
    let scope = ScopeId::new(submission.work_scope.scope_id.as_str().to_owned())
        .map_err(|_| "orientation_scope_invalid")?;
    let semantic_source = OrientationSemanticInputClaim {
        publication,
        source_claim: source_claim(input.semantic_source),
    };
    Ok((
        OrientationSubmitInput {
            request: input.request,
            semantic_input_claim: semantic_source,
            scope,
            materials: input.materials.into_iter().map(source_claim).collect(),
            budget: OrientationMaterialBudget {
                max_sources: input.budget.max_sources,
                max_total_bytes: input.budget.max_total_bytes,
                max_source_bytes: input.budget.max_source_bytes,
            },
        },
        output_schema,
        schema_source,
        schema_source_wire,
    ))
}

fn validate_original_output_schema(
    job: &DreamJobInput,
    output_contract: &OpaqueContentRef,
    recipe: &TaskControllerOrientationOutputSchemaRecipe,
    source: &AdmittedSourceClaim,
) -> Result<(), &'static str> {
    if job.output_schema.as_str() != recipe.schema_id.as_str()
        || output_contract.artifact_id.as_ref() != Some(&recipe.schema_id)
        || output_contract.sha256.as_str() != recipe.schema_digest.as_str()
        || source.expected_digest.as_str() != recipe.schema_digest.as_str()
        || source.expected_byte_length != output_contract.byte_length
        || recipe.schema_version == 0
    {
        return Err("output_schema_identity_mismatch");
    }
    Ok(())
}

fn source_claim(claim: TaskControllerOrientationSourceClaim) -> AdmittedSourceClaim {
    AdmittedSourceClaim {
        source_handle: claim.source_handle,
        expected_digest: claim.expected_digest,
        expected_byte_length: claim.expected_byte_length,
        privacy_class: claim.privacy_class,
        route_class: claim.route_class,
    }
}

fn orientation_refusal_code(error: &OrientationSubmitError) -> &'static str {
    match error {
        OrientationSubmitError::SemanticInput(OrientationSemanticInputError::MissingReference)
        | OrientationSubmitError::SemanticInput(OrientationSemanticInputError::MissingBytes) => {
            "semantic_input_unavailable"
        }
        OrientationSubmitError::SemanticInput(
            OrientationSemanticInputError::FenceMismatch
            | OrientationSemanticInputError::Resolution(
                crate::dreamer_materials::DreamerMaterialsError::FenceMismatch,
            ),
        ) => "orientation_stale_fence",
        OrientationSubmitError::SemanticInput(
            OrientationSemanticInputError::ReferenceMismatch
            | OrientationSemanticInputError::ReferenceBytesMismatch
            | OrientationSemanticInputError::ResolvedBytesMismatch
            | OrientationSemanticInputError::SourceClaimMismatch,
        ) => "semantic_input_mismatch",
        OrientationSubmitError::SemanticInput(OrientationSemanticInputError::Resolution(_)) => {
            "semantic_input_read_unavailable"
        }
        OrientationSubmitError::Composition(CompositionError::NotReady) => "governor_not_ready",
        OrientationSubmitError::Composition(_) => "orientation_admission_refused",
        OrientationSubmitError::SemanticInput(_) => "semantic_input_invalid",
    }
}

fn output_schema_refusal_code(error: &DreamerMaterialsError) -> &'static str {
    match error {
        DreamerMaterialsError::FenceMismatch => "output_schema_stale_fence",
        DreamerMaterialsError::DigestMismatch | DreamerMaterialsError::LengthMismatch => {
            "output_schema_source_mismatch"
        }
        DreamerMaterialsError::Resolution(_) => "output_schema_read_unavailable",
        _ => "output_schema_source_invalid",
    }
}

fn blocked_result(
    claimed: &TaskControllerClaimedInvocation,
    reason: &str,
) -> Result<eliot_protocol::TaskControllerResultBody, String> {
    task_controller_result_body(
        claimed,
        json!({
            "status": "blocked",
            "reason": reason,
        }),
    )
}
