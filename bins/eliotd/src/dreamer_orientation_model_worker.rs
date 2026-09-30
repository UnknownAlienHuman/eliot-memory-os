//! Receipt-based production CC-002 Orientation worker.

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_coordinator::{
    HumanModelPreferencePolicy, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ModelSelectionReceipt, compile_model_selection,
};
use eliot_agent_opencode::{
    AdmittedOpenCodeAttempt, ModelSelection, ModelSelectionError, OpenCodeClient, OpenCodeRouteAdmission,
    OpenCodeRouteRole, OpenCodeRouteSelectionError, ReadOnlyRunRequest, RunRequestError,
    select_opencode_route,
};
use eliot_contracts::{
    ContractVersion, RequestMetadata, StateFence, canonical_json_bytes, contract_identity,
    sha256_hex,
};
use eliot_dreamer_contracts::{
    ContractViolation, DreamInputBundle, DreamJobAdmission, DreamJobInput, ModelRouteRequestError,
    RecipeInput,
};
use eliot_protocol::dreamer_job::{DurableJobError, OpaqueContentRef};
use eliot_read::LocalReadPort;
use eliot_store_api::ScopeId;
use serde_json::Value;

use super::agent_fabric::{
    AdmittedOpenCodeAttemptProjectionError, AgentFabric,
};
use super::dreamer_materials::{
    AdmittedSourceClaim, DreamerMaterialsError, resolve_source_claim,
};
use super::dreamer_orientation_model::{
    DreamerOrientationModelAttempt, DreamerOrientationModelInput,
    admitted_model_route_context_bytes, run_admitted_model_route,
};

/// Per-call immutable semantic, admission, route, and runtime owner inputs.
/// The semantic bytes are the original canonical DreamJobInput; the provider
/// prompt is separately derived and retained byte-for-byte by this worker.
pub struct DreamerOrientationModelWorkerInput<'a, R: LocalReadPort> {
    pub semantic_input_ref: &'a OpaqueContentRef,
    pub semantic_input_bytes: &'a [u8],
    pub admission: &'a DreamJobAdmission,
    pub bundle: &'a DreamInputBundle,
    pub catalogue: &'a ModelCatalogueSnapshot,
    pub policy: &'a HumanModelPreferencePolicy,
    pub now_unix_ms: u64,
    /// Exact recipe member from the original admitted output-schema role.
    pub output_schema_recipe: &'a RecipeInput,
    /// Unchanged output contract reference from the original durable submit.
    pub output_contract_ref: &'a OpaqueContentRef,
    /// Explicit source claim admitted with the original schema material.
    pub output_schema_source: &'a AdmittedSourceClaim,
    /// Existing Governor named-read owner used to resolve the original schema.
    pub source_reads: &'a R,
    /// Original request context and scope for the exact source read.
    pub source_read_context: &'a RequestMetadata,
    pub source_scope: &'a ScopeId,
    /// Actual runtime AgentFabric that retains the original attempt record.
    pub fabric: &'a AgentFabric,
    pub attempt_id: &'a AttemptId,
    pub current_fence: &'a StateFence,
}

#[derive(Debug, thiserror::Error)]
pub enum DreamerOrientationModelWorkerError {
    #[error(transparent)]
    SemanticReference(#[from] DurableJobError),
    #[error("original output-contract reference is invalid: {0}")]
    OutputContractReference(DurableJobError),
    #[error("retained semantic input reference does not bind its original bytes")]
    SemanticReferenceMismatch,
    #[error("retained semantic input is not valid canonical DreamJobInput: {0}")]
    SemanticInput(#[from] serde_json::Error),
    #[error("retained semantic input bytes are not canonical DreamJobInput")]
    NonCanonicalSemanticInput,
    #[error(transparent)]
    JobContract(#[from] ContractViolation),
    #[error(transparent)]
    Selection(#[from] ModelControlError),
    #[error(transparent)]
    ConfiguredRoute(#[from] OpenCodeRouteSelectionError),
    #[error(transparent)]
    ModelSelection(#[from] ModelSelectionError),
    #[error(transparent)]
    ReadOnlyRequest(#[from] RunRequestError),
    #[error(transparent)]
    ModelRoute(#[from] ModelRouteRequestError),
    #[error(transparent)]
    OutputSchemaSource(#[from] DreamerMaterialsError),
    #[error(transparent)]
    AttemptOwner(#[from] AdmittedOpenCodeAttemptProjectionError),
    #[error("original recipe, durable output-contract reference and job output schema differ")]
    OutputSchemaBindingMismatch,
    #[error("original output-contract identity does not describe the resolved schema")]
    OutputSchemaIdentityMismatch,
    #[error("resolved output schema is not a canonical JSON object")]
    OutputSchemaNotCanonicalObject,
    #[error("output-schema version is outside the contract-version range")]
    OutputSchemaVersionOutOfRange,
    #[error("coordinator-selected route differs from the exact owner-admitted route")]
    AdmittedRouteMismatch,
    #[error("coordinator-selected provider/model differs from the owner-admitted model")]
    AdmittedModelMismatch,
}

/// Compiles the current Dreamer selection through its coordinator owner,
/// requires the opaque selected entry ID in the admitted denominator, then
/// joins the configured OpenCode route and existing admitted attempt by the
/// full unchanged RouteFingerprint before executing the real route owner.
#[allow(clippy::too_many_lines)]
pub async fn execute_admitted_orientation_model(
    client: &OpenCodeClient,
    route_admission: &OpenCodeRouteAdmission,
    input: DreamerOrientationModelWorkerInput<'_, impl LocalReadPort>,
) -> Result<DreamerOrientationModelAttempt, DreamerOrientationModelWorkerError> {
    input.semantic_input_ref.validate("semantic_input")?;
    let byte_length = u64::try_from(input.semantic_input_bytes.len())
        .map_err(|_| DreamerOrientationModelWorkerError::SemanticReferenceMismatch)?;
    if byte_length != input.semantic_input_ref.byte_length
        || sha256_hex(input.semantic_input_bytes) != input.semantic_input_ref.sha256
    {
        return Err(DreamerOrientationModelWorkerError::SemanticReferenceMismatch);
    }
    let job_contract = eliot_dreamer_contracts::job::dream_job_input_contract_identity()?;
    if input.semantic_input_ref.contract != job_contract {
        return Err(DreamerOrientationModelWorkerError::SemanticReferenceMismatch);
    }

    let job: DreamJobInput = serde_json::from_slice(input.semantic_input_bytes)?;
    job.validate()?;
    if canonical_json_bytes(&job)?.as_slice() != input.semantic_input_bytes {
        return Err(DreamerOrientationModelWorkerError::NonCanonicalSemanticInput);
    }
    input.admission.validate()?;
    input.bundle.validate()?;
    let output_schema = resolve_original_output_schema(&input, &job).await?;
    if input.source_read_context.state_fence != job.state_fence
        || input.source_scope.as_str() != job.scope_id.as_str()
    {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaBindingMismatch);
    }
    let prompt_bytes = admitted_model_route_context_bytes(&job, input.admission, input.bundle)?;

    let selection = compile_model_selection(
        input.catalogue,
        input.policy,
        ModelRole::Dreamer,
        &input.bundle.job_id,
        input.now_unix_ms,
    )?;
    selection.validate_against(input.catalogue, input.policy, input.now_unix_ms)?;
    if !job
        .allowed_model_routes
        .iter()
        .any(|route| route == &selection.selected.entry_id)
    {
        return Err(ModelRouteRequestError::SelectedRouteOutsideDenominator.into());
    }
    select_opencode_route(
        route_admission,
        &selection.selected.route,
        OpenCodeRouteRole::ReadOnlyScouting,
    )?;
    let prompt = String::from_utf8(prompt_bytes.clone())
        .map_err(|_| DreamerOrientationModelWorkerError::NonCanonicalSemanticInput)?;
    let model = ModelSelection::new(
        selection.selected.provider_id.clone(),
        selection.selected.model_id.clone(),
    )?;
    let admitted = input.fabric.admitted_open_code_attempt(
        input.attempt_id,
        &selection.selected.route,
        model,
        input.current_fence,
    )?;
    ensure_selected_attempt_binding(&selection, &admitted)?;
    let read_only_request = ReadOnlyRunRequest::new(prompt, admitted.model().clone())?
        .with_output_schema(output_schema)?;
    let cancellation = admitted.attempt().cancellation;
    let runtime_generation = admitted.binding().runtime_generation.clone();
    let effect_ceiling = &admitted.attempt().authority.effect_ceiling;
    run_admitted_model_route(
        client,
        DreamerOrientationModelInput {
            job: &job,
            admission: input.admission,
            bundle: input.bundle,
            retained_context_bytes: &prompt_bytes,
            selected_route_id: &selection.selected.entry_id,
            selected_route_fingerprint: &selection.selected.route,
            cancellation,
            now_unix_ms: input.now_unix_ms,
            admitted: &admitted,
            read_only_request: &read_only_request,
            current_fence: input.current_fence,
            runtime_generation,
            effect_ceiling,
        },
    )
    .await
    .map_err(Into::into)
}

async fn resolve_original_output_schema<R: LocalReadPort>(
    input: &DreamerOrientationModelWorkerInput<'_, R>,
    job: &DreamJobInput,
) -> Result<Value, DreamerOrientationModelWorkerError> {
    input
        .output_contract_ref
        .validate("output_contract")
        .map_err(DreamerOrientationModelWorkerError::OutputContractReference)?;
    let RecipeInput::OutputSchema {
        schema_id,
        schema_version,
        schema_digest,
    } = input.output_schema_recipe
    else {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaBindingMismatch);
    };
    input.output_schema_recipe.validate()?;
    if schema_id.as_str() != job.output_schema.as_str()
        || input.output_contract_ref.artifact_id.as_ref() != Some(schema_id)
        || input.output_contract_ref.sha256.as_str() != schema_digest.as_str()
        || input.output_contract_ref.byte_length != input.output_schema_source.expected_byte_length
        || input.output_contract_ref.sha256.as_str()
            != input.output_schema_source.expected_digest.as_str()
    {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaBindingMismatch);
    }

    let schema_bytes = resolve_source_claim(
        input.source_reads,
        input.source_read_context,
        input.source_scope,
        input.output_schema_source,
    )
    .await?;
    let byte_length = u64::try_from(schema_bytes.len())
        .map_err(|_| DreamerOrientationModelWorkerError::OutputSchemaBindingMismatch)?;
    if byte_length != input.output_contract_ref.byte_length
        || sha256_hex(&schema_bytes).as_str() != schema_digest.as_str()
    {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaBindingMismatch);
    }
    let schema: Value = serde_json::from_slice(&schema_bytes)
        .map_err(|_| DreamerOrientationModelWorkerError::OutputSchemaNotCanonicalObject)?;
    if !schema.is_object() || canonical_json_bytes(&schema)?.as_slice() != schema_bytes.as_slice() {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaNotCanonicalObject);
    }

    let major = u16::try_from(*schema_version)
        .map_err(|_| DreamerOrientationModelWorkerError::OutputSchemaVersionOutOfRange)?;
    let expected_contract = contract_identity(
        schema_id.as_str().to_owned(),
        ContractVersion::new(major, 0, 0),
        &schema,
    )
    .map_err(|_| DreamerOrientationModelWorkerError::OutputSchemaIdentityMismatch)?;
    if input.output_contract_ref.contract != expected_contract {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaIdentityMismatch);
    }
    Ok(schema)
}

fn ensure_selected_attempt_binding(
    selection: &ModelSelectionReceipt,
    admitted: &AdmittedOpenCodeAttempt,
) -> Result<(), DreamerOrientationModelWorkerError> {
    let selected: &RouteFingerprint = &selection.selected.route;
    if admitted.admission().selected_route.as_ref() != Some(selected)
        || admitted.binding().route != *selected
        || admitted.attempt().route != *selected
    {
        return Err(DreamerOrientationModelWorkerError::AdmittedRouteMismatch);
    }
    let model: &ModelSelection = admitted.model();
    if model.provider_id != selection.selected.provider_id
        || model.model_id != selection.selected.model_id
        || model.provider_id != selected.provider
        || model.model_id != selected.model
    {
        return Err(DreamerOrientationModelWorkerError::AdmittedModelMismatch);
    }
    Ok(())
}
