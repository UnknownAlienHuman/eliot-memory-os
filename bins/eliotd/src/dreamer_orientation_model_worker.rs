//! Receipt-based production CC-002 Orientation worker.

use eliot_agent_api::{CancellationState, EffectCeiling, RouteFingerprint};
use eliot_agent_coordinator::{
    HumanModelPreferencePolicy, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ModelSelectionReceipt, compile_model_selection,
};
use eliot_agent_opencode::{
    AdmittedOpenCodeAttempt, ModelSelection, OpenCodeClient, OpenCodeRouteAdmission,
    OpenCodeRouteRole, OpenCodeRouteSelectionError, ReadOnlyRunRequest, RunRequestError,
    select_opencode_route,
};
use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{
    ContractViolation, DreamInputBundle, DreamJobAdmission, DreamJobInput,
    ModelRouteRequestError,
};
use eliot_protocol::dreamer_job::{DurableJobError, OpaqueContentRef};
use serde_json::Value;

use super::dreamer_orientation_model::{
    DreamerOrientationModelAttempt, DreamerOrientationModelInput,
    admitted_model_route_context_bytes, run_admitted_model_route,
};

/// Per-call immutable semantic, admission, route, and runtime owner inputs.
/// The semantic bytes are the original canonical DreamJobInput; the provider
/// prompt is separately derived and retained byte-for-byte by this worker.
pub struct DreamerOrientationModelWorkerInput<'a> {
    pub semantic_input_ref: &'a OpaqueContentRef,
    pub semantic_input_bytes: &'a [u8],
    pub admission: &'a DreamJobAdmission,
    pub bundle: &'a DreamInputBundle,
    pub catalogue: &'a ModelCatalogueSnapshot,
    pub policy: &'a HumanModelPreferencePolicy,
    pub now_unix_ms: u64,
    pub cancellation: CancellationState,
    pub admitted: &'a AdmittedOpenCodeAttempt,
    pub current_fence: &'a StateFence,
    pub runtime_generation: ResourceGeneration,
    pub effect_ceiling: &'a EffectCeiling,
}

#[derive(Debug, thiserror::Error)]
pub enum DreamerOrientationModelWorkerError {
    #[error(transparent)]
    SemanticReference(#[from] DurableJobError),
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
    ReadOnlyRequest(#[from] RunRequestError),
    #[error(transparent)]
    ModelRoute(#[from] ModelRouteRequestError),
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
    input: DreamerOrientationModelWorkerInput<'_>,
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
    ensure_selected_attempt_binding(&selection, input.admitted)?;

    let prompt = String::from_utf8(prompt_bytes.clone())
        .map_err(|_| DreamerOrientationModelWorkerError::NonCanonicalSemanticInput)?;
    let output_schema: Value = serde_json::from_str(&job.output_schema)?;
    let read_only_request = ReadOnlyRunRequest::new(prompt, input.admitted.model().clone())?
        .with_output_schema(output_schema)?;
    run_admitted_model_route(
        client,
        DreamerOrientationModelInput {
            job: &job,
            admission: input.admission,
            bundle: input.bundle,
            retained_context_bytes: &prompt_bytes,
            selected_route_id: &selection.selected.entry_id,
            selected_route_fingerprint: &selection.selected.route,
            cancellation: input.cancellation,
            now_unix_ms: input.now_unix_ms,
            admitted: input.admitted,
            read_only_request: &read_only_request,
            current_fence: input.current_fence,
            runtime_generation: input.runtime_generation,
            effect_ceiling: input.effect_ceiling,
        },
    )
    .await
    .map_err(Into::into)
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
