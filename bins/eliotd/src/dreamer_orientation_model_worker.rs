//! Receipt-based production CC-002 Orientation worker.

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_coordinator::{
    HumanModelPreferencePolicy, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ModelSelectionReceipt, ProviderAdmissionReceipt, compile_model_selection,
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
use eliot_coordination::{CoordinationOwner, WorkLeaseRequest};
use eliot_dreamer_contracts::{
    ContractViolation, DreamInputBundle, DreamJobAdmission, DreamJobInput, ModelRouteRequestError,
    PROVIDER_OUTPUT_SCHEMA_VERSION, RecipeInput, provider_output_schema_v2,
};
use eliot_protocol::dreamer_job::{
    DurableJobError, OpaqueContentRef, ProviderStaffingRuntimeSourcePublication,
};
use eliot_read::LocalReadPort;
use eliot_receipts::WorkScopeBinding;
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
use super::dreamer_model_adapter::{
    DreamerProviderStaffingRuntimeProfile, DreamerProviderStaffingRuntimeProfileError,
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
    pub catalogue: &'a ModelCatalogueSnapshot,
    pub policy: &'a HumanModelPreferencePolicy,
    /// Original provider-runtime staffing profile publication. Missing is a
    /// typed residual: provider/model selection alone does not supply recipe,
    /// role, capacity, launch or provider identity.
    pub provider_staffing_source: Option<&'a ProviderStaffingRuntimeSourcePublication>,
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

    let staffing_publication = input
        .provider_staffing_source
        .ok_or(DreamerOrientationModelWorkerError::ProviderStaffingSourceMissing)?;
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
