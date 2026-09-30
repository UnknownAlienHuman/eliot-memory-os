//! Receipt-based production CC-002 Orientation worker.

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_coordinator::{
    HumanModelPreferencePolicy, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ModelSelectionReceipt, ProviderAdmissionReceipt, compile_model_selection,
};
use eliot_agent_opencode::{
    AdmittedOpenCodeAttempt, ModelSelection, ModelSelectionError, OpenCodeClient,
    OpenCodeRouteAdmission, OpenCodeRouteRole, OpenCodeRouteSelectionError, ReadOnlyRunRequest,
    RunRequestError, select_opencode_route,
};
use eliot_contracts::{
    ContractIdentity, ContractVersion, RequestMetadata, StateFence, canonical_json_bytes,
    contract_identity, sha256_hex,
};
use eliot_coordination::{CoordinationOwner, WorkLeaseRequest};
use eliot_dreamer_contracts::{
    ContractViolation, DreamInputBundle, DreamJobAdmission, DreamJobInput, ModelRouteRequestError,
    PROVIDER_OUTPUT_SCHEMA_VERSION, RecipeInput, provider_output_schema_v2,
};
use eliot_protocol::dreamer_job::{
    DurableJobError, DurableJobRequest, DurableJobResponse, DurableJobRuntimeOwnerExecutionInput,
    JobOperation, JobState, OpaqueContentRef,
};
use eliot_read::LocalReadPort;
use eliot_receipts::WorkScopeBinding;
use eliot_store_api::ScopeId;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use super::agent_fabric::{
    AdmittedOpenCodeAttemptProjectionError, AgentFabric,
};
use super::dreamer_materials::{AdmittedSourceClaim, DreamerMaterialsError, resolve_source_claim};
use super::dreamer_model_adapter::{
    DreamerProviderStaffingRuntimeProfile, DreamerProviderStaffingRuntimeProfileError,
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
    /// Original WorkScope from the durable submit, retained unchanged by the
    /// Task Controller runtime-owner input.
    pub work_scope: &'a WorkScopeBinding,
    /// Exact typed runtime-owner input decoded from the original durable
    /// submission/claim. New v2 invocations carry the admission, bundle and
    /// staffing publications here as separate owner references and bytes.
    pub runtime_owner_input: &'a DurableJobRuntimeOwnerExecutionInput,
    /// Original immutable runtime-owner content reference from the durable
    /// request/claimed response.
    pub runtime_owner_input_ref: &'a OpaqueContentRef,
    /// Exact original canonical bytes named by `runtime_owner_input_ref`.
    pub runtime_owner_input_bytes: &'a [u8],
    /// Original K0 `LeaseNext` request which selected this worker's job.
    pub durable_lease_request: &'a DurableJobRequest,
    /// Original K0 response retaining the selected job and owner lease.
    pub durable_lease_response: &'a DurableJobResponse,
    /// Authenticated K0 `Start` request for the selected original lease.
    pub durable_start_request: &'a DurableJobRequest,
    /// Original Kernel K0 response acknowledging that start.
    pub durable_start_response: &'a DurableJobResponse,
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
    pub fabric: &'a mut AgentFabric,
    /// Live Coordination owner used to acquire or exactly replay this
    /// operation's original logical lease issuance.
    pub coordination_owner: &'a mut CoordinationOwner,
    /// Original authenticated work-lease request for this model operation.
    pub work_lease_request: WorkLeaseRequest,
    /// Original Governor-issued provider admission, verified again by the
    /// sealed AgentCoordinator on use.
    pub provider_admission: Option<&'a ProviderAdmissionReceipt>,
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
    #[error("provider staffing source is absent from the original runtime input")]
    ProviderStaffingSourceMissing,
    #[error("original v3 runtime-owner admission/bundle/frame/staffing publications are absent or incomplete")]
    RuntimeOwnerSourceMissing,
    #[error("original runtime-owner publication does not bind the decoded job/admission/bundle")]
    RuntimeOwnerSourceBindingMismatch,
    #[error("original runtime-owner publication has the wrong typed contract identity")]
    RuntimeOwnerSourceContractMismatch,
    #[error("original runtime-owner content reference is invalid: {0}")]
    RuntimeOwnerReference(DurableJobError),
    #[error("original admission or bundle content reference is invalid: {0}")]
    RuntimeOwnerSourceReference(DurableJobError),
    #[error("original K0 claimed-job request/response does not retain this model input: {0}")]
    DurableClaim(DurableJobError),
    #[error("original provider admission is absent from the runtime owner input")]
    ProviderAdmissionMissing,
    #[error(transparent)]
    ProviderStaffingProfile(#[from] DreamerProviderStaffingRuntimeProfileError),
    #[error("original staffing request is invalid: {0}")]
    StaffingPlan(String),
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
    #[error("original Coordination lease has no owner-issued Agent attempt identity")]
    LegacyWorkLeaseAttemptIdentity,
    #[error("original Coordination lease does not bind this admitted model operation")]
    WorkLeaseBindingMismatch,
    #[error("original durable WorkScope does not bind this admitted model operation")]
    WorkScopeBindingMismatch,
    #[error("original Governor provider admission does not bind the owner-issued attempt, lease, candidate, or selected lane")]
    ProviderAdmissionBindingMismatch,
    #[error(transparent)]
    WorkLeaseIssuance(#[from] eliot_coordination::WorkLeaseIssuanceFailure),
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
    validate_durable_claim(&input)?;
    validate_runtime_owner_publication(
        input.runtime_owner_input,
        input.runtime_owner_input_ref,
        input.runtime_owner_input_bytes,
    )?;
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
    let (original_admission, original_bundle, staffing_publication) =
        decode_v3_runtime_owner_sources(input.runtime_owner_input)?;
    if original_admission != *input.admission
        || original_bundle != *input.bundle
        || input.runtime_owner_input.task_id.as_str() != input.admission.task_id.as_str()
        || input.runtime_owner_input.work_scope != *input.work_scope
        || input.runtime_owner_input.state_fence != job.state_fence
        || input.runtime_owner_input.output_contract != *input.output_contract_ref
        || input.runtime_owner_input.semantic_source.expected_digest
            != input.semantic_input_ref.sha256
        || input.runtime_owner_input.semantic_source.expected_byte_length
            != input.semantic_input_ref.byte_length
        || !runtime_schema_binds_invocation(&input)
    {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
    }
    input.admission.validate()?;
    input.bundle.validate()?;
    input.work_scope
        .state_fence
        .validate()
        .map_err(|_| DreamerOrientationModelWorkerError::WorkScopeBindingMismatch)?;
    if input.work_scope.scope_id.as_str() != job.scope_id.as_str()
        || input.work_scope.scope_id.as_str() != input.bundle.scope_id.as_str()
        || input.work_scope.state_fence != job.state_fence
        || input.work_scope.state_fence != input.bundle.state_fence
        || input.work_scope.resource_generation != job.state_fence.resource_generation
        || input.work_scope.resource_generation != input.bundle.state_fence.resource_generation
    {
        return Err(DreamerOrientationModelWorkerError::WorkScopeBindingMismatch);
    }
    let output_schema = resolve_original_output_schema(&input, &job).await?;
    if input.source_read_context.state_fence != job.state_fence
        || input.source_scope.as_str() != job.scope_id.as_str()
    {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaBindingMismatch);
    }
    let prompt_bytes = admitted_model_route_context_bytes(&job, input.admission, input.bundle)?;

    let staffing_profile = DreamerProviderStaffingRuntimeProfile::from_publication(
        staffing_publication,
    )?;
    let (_, staffing_candidate) = input
        .fabric
        .define_and_plan(staffing_profile.staffing_request.clone())
        .map_err(|error| DreamerOrientationModelWorkerError::StaffingPlan(error.to_string()))?;

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
    staffing_profile.validate_for_orientation(
        &job,
        input.admission,
        input.bundle,
        &selection.selected.route,
    )?;
    let planned_lane = staffing_candidate.lanes.iter().find(|lane| {
        lane.work_unit_id == staffing_profile.orientation_work_unit_id
            && lane.role_id == staffing_profile.orientation_role_id
    });
    if planned_lane.and_then(|lane| lane.routing.selected.as_ref())
        != Some(&selection.selected.route)
    {
        return Err(DreamerProviderStaffingRuntimeProfileError::OperationBinding.into());
    }
    let work_lease_request = &input.work_lease_request;
    if job.task_id.as_deref() != Some(input.bundle.task_id.as_str())
        || work_lease_request.work_item_id != input.bundle.task_id
        || input.source_read_context.session_id.as_deref()
            != Some(work_lease_request.session_id.as_str())
        || work_lease_request.state_fence != *input.current_fence
        || work_lease_request.state_fence != job.state_fence
        || work_lease_request.authority_epoch != input.current_fence.authority_epoch
    {
        return Err(DreamerOrientationModelWorkerError::WorkLeaseBindingMismatch);
    }
    let work_lease = input
        .coordination_owner
        .acquire_work_with_issuance(work_lease_request.clone())?;
    let attempt_id = work_lease
        .agent_attempt_id()
        .cloned()
        .ok_or(DreamerOrientationModelWorkerError::LegacyWorkLeaseAttemptIdentity)?;
    if work_lease.decision().lease.state_fence != *input.current_fence {
        return Err(DreamerOrientationModelWorkerError::WorkLeaseBindingMismatch);
    }
    let provider_admission = input
        .provider_admission
        .ok_or(DreamerOrientationModelWorkerError::ProviderAdmissionMissing)?;
    let admitted_lane = provider_admission.admitted_lanes.iter().find(|lane| {
        lane.work_unit_id == staffing_profile.orientation_work_unit_id
            && lane.role_id == staffing_profile.orientation_role_id
    });
    if provider_admission.candidate_id != staffing_candidate.candidate_id
        || provider_admission.state_fence != *input.current_fence
        || provider_admission.coordinator_lease != *work_lease.work_lease_id()
        || provider_admission.provider_identity != staffing_profile.provider_identity
        || admitted_lane.is_none_or(|lane| {
            lane.attempt_id != attempt_id
                || lane.lease_id != *work_lease.work_lease_id()
                || lane.route != selection.selected.route
        })
    {
        return Err(DreamerOrientationModelWorkerError::ProviderAdmissionBindingMismatch);
    }
    input
        .fabric
        .admit_provider_admission(provider_admission.clone())?;
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
        &attempt_id,
        work_lease.work_lease_id(),
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

fn decode_v3_runtime_owner_sources(
    runtime: &DurableJobRuntimeOwnerExecutionInput,
) -> Result<
    (
        DreamJobAdmission,
        DreamInputBundle,
        &eliot_protocol::dreamer_job::ProviderStaffingRuntimeSourcePublication,
    ),
    DreamerOrientationModelWorkerError,
> {
    runtime.validate()?;
    if !runtime.has_v3_owner_publications() {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceMissing);
    }
    let admission_identity =
        eliot_dreamer_contracts::job::dream_job_admission_contract_identity()?;
    let bundle_identity = eliot_dreamer_contracts::bundle::dream_input_bundle_contract_identity()?;
    let admission = decode_original_typed_publication(
        runtime.job_admission_ref.as_ref(),
        runtime.job_admission_bytes.as_deref(),
        "job_admission",
        &admission_identity,
    )?;
    let bundle = decode_original_typed_publication(
        runtime.input_bundle_ref.as_ref(),
        runtime.input_bundle_bytes.as_deref(),
        "input_bundle",
        &bundle_identity,
    )?;
    let staffing = runtime
        .provider_staffing_source
        .as_ref()
        .ok_or(DreamerOrientationModelWorkerError::RuntimeOwnerSourceMissing)?;
    Ok((admission, bundle, staffing))
}

fn validate_runtime_owner_publication(
    runtime: &DurableJobRuntimeOwnerExecutionInput,
    reference: &OpaqueContentRef,
    bytes: &[u8],
) -> Result<(), DreamerOrientationModelWorkerError> {
    reference
        .validate("runtime_owner_execution_input")
        .and_then(|()| reference.validate_original_bytes(bytes))
        .map_err(DreamerOrientationModelWorkerError::RuntimeOwnerReference)?;
    if reference.contract != DurableJobRuntimeOwnerExecutionInput::contract_identity_v3()? {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceContractMismatch);
    }
    let canonical = canonical_json_bytes(runtime)
        .map_err(|_| DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch)?;
    if canonical.as_slice() != bytes {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
    }
    runtime
        .validate()
        .map_err(DreamerOrientationModelWorkerError::SemanticReference)
}

fn validate_durable_claim<R: LocalReadPort>(
    input: &DreamerOrientationModelWorkerInput<'_, R>,
) -> Result<(), DreamerOrientationModelWorkerError> {
    let lease_request = input.durable_lease_request;
    let lease_response = input.durable_lease_response;
    lease_response
        .validate_for(lease_request)
        .map_err(DreamerOrientationModelWorkerError::DurableClaim)?;
    let selector = match &lease_request.operation {
        JobOperation::LeaseNext { selector } => selector,
        _ => {
            return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
        }
    };
    let selected_lease = lease_response
        .lease
        .as_ref()
        .ok_or(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch)?;
    let runtime = input.runtime_owner_input;
    if lease_request.role != eliot_protocol::dreamer_job::JobRole::Worker
        || lease_response.state != JobState::Leased
        || selector.worker_artifact_id != selected_lease.owner_artifact_id
        || selector.expected_fence != *input.current_fence
        || lease_response.scope != *input.work_scope
        || lease_response.job_id != runtime.job_id
        || lease_response.attempt_id != runtime.attempt_id
        || lease_request.request_identity.request.request.metadata.session_id.as_deref()
            != Some(input.work_lease_request.session_id.as_str())
    {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
    }

    let request = input.durable_start_request;
    let response = input.durable_start_response;
    response
        .validate_for(request)
        .map_err(DreamerOrientationModelWorkerError::DurableClaim)?;
    let (start_lease, started_at_unix_ms) = match &request.operation {
        JobOperation::Start {
            lease,
            now_unix_ms,
        } => (lease, now_unix_ms),
        _ => {
            return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
        }
    };
    if *started_at_unix_ms != input.now_unix_ms
        || start_lease.validate_active_at(input.now_unix_ms).is_err()
        || response.state != JobState::Running
        || response.lease.as_ref() != Some(start_lease)
        || start_lease != selected_lease
        || &start_lease.state_fence != input.current_fence
        || &start_lease.resource_generation != &input.work_scope.resource_generation
        || request.role != eliot_protocol::dreamer_job::JobRole::Worker
        || response.runtime_owner_execution_input.as_ref() != Some(input.runtime_owner_input_ref)
        || response.runtime_owner_execution_input_bytes.as_deref()
            != Some(input.runtime_owner_input_bytes)
        || response.semantic_input.as_ref() != Some(input.semantic_input_ref)
        || response.semantic_input_bytes.as_deref() != Some(input.semantic_input_bytes)
        || response.output_contract.as_ref() != Some(input.output_contract_ref)
        || &response.scope != input.work_scope
        || input.source_read_context.state_fence != response.scope.state_fence
        || input.source_scope.as_str() != response.scope.scope_id.as_str()
        || &response.request_identity != &request.request_identity
        || request.request_identity.request.request.metadata.session_id.as_deref()
            != Some(input.work_lease_request.session_id.as_str())
    {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
    }
    Ok(())
}

fn decode_original_typed_publication<T>(
    reference: Option<&OpaqueContentRef>,
    bytes: Option<&[u8]>,
    field: &'static str,
    expected_contract: &ContractIdentity,
) -> Result<T, DreamerOrientationModelWorkerError>
where
    T: DeserializeOwned + Serialize,
{
    let (Some(reference), Some(bytes)) = (reference, bytes) else {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceMissing);
    };
    reference
        .validate(field)
        .and_then(|()| reference.validate_original_bytes(bytes))
        .map_err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceReference)?;
    if &reference.contract != expected_contract {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceContractMismatch);
    }
    let decoded: T = serde_json::from_slice(bytes)
        .map_err(|_| DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch)?;
    let canonical = canonical_json_bytes(&decoded)
        .map_err(|_| DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch)?;
    if canonical.as_slice() != bytes {
        return Err(DreamerOrientationModelWorkerError::RuntimeOwnerSourceBindingMismatch);
    }
    Ok(decoded)
}

fn runtime_schema_binds_invocation<R: LocalReadPort>(
    input: &DreamerOrientationModelWorkerInput<'_, R>,
) -> bool {
    let RecipeInput::OutputSchema {
        schema_id,
        schema_version,
        schema_digest,
    } = input.output_schema_recipe
    else {
        return false;
    };
    let runtime = input.runtime_owner_input;
    runtime.output_schema_recipe.schema_id == *schema_id
        && runtime.output_schema_recipe.schema_version == *schema_version
        && runtime.output_schema_recipe.schema_digest == *schema_digest
        && runtime.schema_source.source_handle == input.output_schema_source.source_handle
        && runtime.schema_source.expected_digest == input.output_schema_source.expected_digest
        && runtime.schema_source.expected_byte_length
            == input.output_schema_source.expected_byte_length
        && runtime.schema_source.privacy_class == input.output_schema_source.privacy_class
        && runtime.schema_source.route_class == input.output_schema_source.route_class
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
        || *schema_version != PROVIDER_OUTPUT_SCHEMA_VERSION
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
    let expected_schema = provider_output_schema_v2()
        .map_err(|_| DreamerOrientationModelWorkerError::OutputSchemaIdentityMismatch)?;
    if schema != expected_schema {
        return Err(DreamerOrientationModelWorkerError::OutputSchemaIdentityMismatch);
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
