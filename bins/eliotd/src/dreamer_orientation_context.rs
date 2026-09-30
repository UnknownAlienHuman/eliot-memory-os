//! Source-faithful CC-004 owner handoff for the admitted Dreamer Orientation path.
//!
//! This adapter joins the authenticated Context reconstruction owner output to
//! the existing candidate/admission readback. It carries the original
//! readbacks by borrow, takes omission records only from the native candidate
//! owner, and leaves incomplete projection members explicit.

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_context_admission::MaterialRankTraceDelivery;
use eliot_context_candidates::{
    CandidatePolicy, CandidateRequest, ContextCandidateSetResult,
};
use eliot_context::ContextError as SmartContextError;
use eliot_context::campaign_publication::{ContextPublicationError, context_recipe_body_digest};
use eliot_context_contracts::{
    ActiveUnderstandingViewResult, AdmissionInput, AdmissionResult, AssemblyError, AssemblyPolicy,
    ContextError, ContextRecipe, DecisionContextIncomplete, QualityScorecard, ReactiveInputError,
};
use eliot_dreamer_contracts::{DreamInputBundle, DreamJobAdmission, DreamJobInput};
use eliot_governor::{
    ContextReconstructionRequest, GovernorProjectionSet, OrientationProjectionOwnerInput,
    OrientationProjectionOwnerOutput, RouteScopeFingerprint, SevenRoleInputs,
    WorkScopeBindingSnapshot, bind_orientation_projections,
};
use eliot_protocol::{HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt, host_request_operation_id};
use eliot_store_api::{
    CampaignLearningStateViewRead, CampaignLearningStateViewReadStatus,
    CampaignSourceReadStatus, CampaignSourceRevisionRead, NamedReadOperation,
};
use serde::Deserialize;
use thiserror::Error;

use crate::context_reconstruction_route::ContextReconstructionOwnerReadback;
use crate::kernel_context_read_client::{
    ContextCompilationOwnerOutcome, ContextCompilationOwnerReadback, KernelContextReadClient,
    PacketCompositionError,
};

/// Typed failure when the compiler result is not joined to the original
/// authenticated Context reconstruction closure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum DreamerOrientationContextError {
    /// The candidate, admission input or decision changed the original binding.
    #[error("candidate/admission context binding differs from the authenticated Context owner")]
    BindingMismatch,
    /// The retained host result or its original context owner payload is invalid.
    #[error("authenticated Context result does not retain a valid original owner publication")]
    InvalidOriginalPublication,
    /// The original context owner values differ from their retained reads or request binding.
    #[error("authenticated Context owner publication does not close its original read identity")]
    OriginalPublicationMismatch,
    /// The original compiler readback does not bind the original context owner source.
    #[error("original Context compiler readback differs from the authenticated context source")]
    CompilationPublicationMismatch,
}

/// Typed refusal when original owner suppliers or the campaign view do not
/// bind to this authenticated Context reconstruction.
#[derive(Debug, Error)]
pub(crate) enum DreamerOrientationCompilationError {
    /// This legacy owner source has no native compiler supplier profile.
    #[error("authenticated Context owner source has no compiler supplier profile")]
    MissingSuppliers,
    /// The recipe and independent tool-policy readbacks do not retain the same
    /// current supplier profile and source identity.
    #[error("Context compiler suppliers are not bound by both owner readbacks")]
    SupplierReadbackMismatch,
    /// The stored recipe row has no owner content identity.
    #[error("authenticated ContextRecipe readback has no stored source body")]
    MissingRecipeSource,
    /// The profile's exact campaign view was not retained from its named read.
    #[error("authenticated compiler profile has no current campaign learning-state view")]
    MissingCampaignLearningView,
    /// The typed recipe body differs from its exact stored owner content.
    #[error("authenticated ContextRecipe body does not match its owner content identity")]
    RecipeDigestMismatch,
    /// The campaign learning-state view join refused the compilation.
    #[error("native Context packet compilation refused: {0}")]
    Composition(#[from] PacketCompositionError),
    /// The original typed Context owner profile failed its source validation.
    #[error("Context compiler supplier profile is invalid: {0}")]
    SupplierValidation(#[from] ContextPublicationError),
}

/// Typed compiler result carried inside the original authenticated context
/// result. Refusals retain their exact tagged owner payload instead of being
/// flattened to prose.
pub(crate) enum DecodedContextCompilationOutcome {
    /// Original assembly owner returned its typed completed output.
    Complete(Box<ActiveUnderstandingViewResult>),
    /// Original admission owner returned its typed incomplete decision.
    Incomplete(Box<DecisionContextIncomplete>),
    /// Original compiler owner returned its typed, structured refusal payload.
    Refused(serde_json::Value),
}

/// The typed candidate/admission/assembly records retained by the original
/// context compilation owner.
pub(crate) struct DecodedContextCompilationOwnerReadback {
    /// Exact native candidate request.
    pub request: CandidateRequest,
    /// Exact native context recipe.
    pub recipe: ContextRecipe,
    /// Exact candidate-stage policy.
    pub candidate_policy: CandidatePolicy,
    /// Exact assembly policy.
    pub assembly_policy: AssemblyPolicy,
    /// Original seven-role read closure consumed by compilation.
    pub role_inputs: SevenRoleInputs,
    /// Original scorecard consumed by assembly.
    pub quality: QualityScorecard,
    /// Original candidate set, including its typed omission records.
    pub candidates: ContextCandidateSetResult,
    /// Exact admission input supplied to the native admission owner.
    pub admission_input: AdmissionInput,
    /// Exact native admission result.
    pub admission: AdmissionResult,
    /// Original owner-authored per-material rank traces.
    pub rank_trace_delivery: MaterialRankTraceDelivery,
    /// Terminal native compilation outcome.
    pub outcome: DecodedContextCompilationOutcome,
}

/// Original compiler publication when candidate/admission readback exists,
/// or the original typed refusal when compilation could not begin.
pub(crate) enum DecodedContextCompilationPublication {
    /// Full retained candidate/admission/assembly owner readback.
    Readback(Box<DecodedContextCompilationOwnerReadback>),
    /// Pre-readback typed refusal carried by the authenticated owner result.
    Refused(DecodedDreamerOrientationCompilationRefusal),
}

/// Pre-readback compiler refusal decoded into the original owner's typed
/// disposition while retaining its exact structured source details.
pub(crate) enum DecodedDreamerOrientationCompilationRefusal {
    /// The authenticated legacy recipe has no compiler supplier profile.
    MissingSuppliers,
    /// Recipe and independent ToolPolicy readbacks do not agree.
    SupplierReadbackMismatch,
    /// The original recipe source body was not retained.
    MissingRecipeSource,
    /// The original campaign-learning view was not retained.
    MissingCampaignLearningView,
    /// The recorded source body digest does not describe the native recipe.
    RecipeDigestMismatch,
    /// Candidate/admission/assembly owner returned this native refusal.
    Composition(serde_json::Value),
    /// Existing native supplier validation returned this refusal.
    SupplierValidation(serde_json::Value),
}

/// Full typed original Context reconstruction source decoded from one already
/// authenticated and digest-validated `HostRequestResultBody`.
pub(crate) struct DecodedDreamerOrientationContextOwnerReadback<'result> {
    /// Exact authenticated response retained intact beside its typed decoding.
    pub(crate) original_result: &'result HostRequestResultBody,
    /// Exact original query envelope and claim attempt.
    pub(crate) source_envelope: HostRequestEnvelope,
    /// Exact original context reconstruction attempt.
    pub(crate) source_attempt: LocalReadAttempt,
    /// Exact selector request used for the seven-role reads.
    pub(crate) request: ContextReconstructionRequest,
    /// Original authenticated TaskPlan source and named read.
    pub(crate) task_plan: crate::context_reconstruction_route::AuthenticatedTaskRecipe,
    /// Original authenticated ContextRecipe source and named read.
    pub(crate) context_recipe: crate::context_reconstruction_route::AuthenticatedContextRecipe,
    /// Original independently retained ContextToolPolicy read, when declared.
    pub(crate) context_tool_policy:
        Option<crate::context_reconstruction_route::AuthenticatedContextToolPolicy>,
    /// Original named read of the immutable campaign learning-state view.
    pub(crate) campaign_learning_view:
        Option<crate::context_reconstruction_route::AuthenticatedCampaignLearningView>,
    /// Exact role values plus all original ReadIdentity and source-head closure.
    pub(crate) role_inputs: SevenRoleInputs,
    /// Native compiler output or its retained typed refusal.
    pub(crate) compilation: Option<DecodedContextCompilationPublication>,
}

/// Original admitted inputs and current owner values required for the CC-004
/// source join. Every member borrows its retained native source.
#[derive(Clone, Copy)]
pub(crate) struct DreamerOrientationContextBindInput<'a> {
    /// Authenticated Context source publication decoded from the original result.
    pub(crate) source: &'a DecodedDreamerOrientationContextOwnerReadback<'a>,
    /// Original admitted semantic job.
    pub(crate) job: &'a DreamJobInput,
    /// Original admitted input bundle.
    pub(crate) bundle: &'a DreamInputBundle,
    /// Original Dreamer operation admission.
    pub(crate) admission: &'a DreamJobAdmission,
    /// Original coordinator-issued attempt identity.
    pub(crate) attempt_id: &'a AttemptId,
    /// Governor owner projection set from the current composition.
    pub(crate) governor: &'a GovernorProjectionSet,
    /// Current retained WorkScope owner snapshot.
    pub(crate) work_scope: &'a WorkScopeBindingSnapshot,
    /// Full original physical route from its execution owner, when retained.
    pub(crate) original_route: Option<&'a RouteFingerprint>,
    /// Current complete capability scope from its route owner, when retained.
    pub(crate) current_route_scope: Option<&'a RouteScopeFingerprint>,
    /// Current owner-supplied capability evaluation time, when retained.
    pub(crate) capability_now: Option<u64>,
}

/// CC-004 output tied to the decoded original Context owner publication.
///
/// The decoded source remains borrowed alongside partial or complete
/// projections so the caller can hand the original reads and compiler
/// decision to the next native owner without rebuilding their identities.
pub(crate) struct DreamerOrientationContextJoinedReadback<'a> {
    /// Typed original Context request, reads, and compilation publication.
    pub(crate) source: &'a DecodedDreamerOrientationContextOwnerReadback<'a>,
    /// Original admitted semantic job and intake decision.
    pub(crate) job: &'a DreamJobInput,
    /// Original input bundle used by the admitted model operation.
    pub(crate) bundle: &'a DreamInputBundle,
    /// Original Dreamer operation admission.
    pub(crate) admission: &'a DreamJobAdmission,
    /// Original coordinator attempt identifier joined to the Context binding.
    pub(crate) attempt_id: &'a AttemptId,
    /// CC-004 projections with original source closure and partial states.
    pub(crate) projections: OrientationProjectionOwnerOutput<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextReconstructionOwnerPublicationWire {
    source_envelope: HostRequestEnvelope,
    source_attempt: LocalReadAttempt,
    request: ContextReconstructionRequest,
    task_plan: crate::context_reconstruction_route::AuthenticatedTaskRecipe,
    context_recipe: crate::context_reconstruction_route::AuthenticatedContextRecipe,
    context_tool_policy:
        Option<crate::context_reconstruction_route::AuthenticatedContextToolPolicy>,
    campaign_learning_view:
        Option<crate::context_reconstruction_route::AuthenticatedCampaignLearningView>,
    context_compilation: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextCompilationOwnerReadbackWire {
    request: CandidateRequest,
    recipe: ContextRecipe,
    candidate_policy: CandidatePolicy,
    assembly_policy: AssemblyPolicy,
    role_inputs: SevenRoleInputs,
    quality: QualityScorecard,
    candidates: ContextCandidateSetResult,
    admission_input: AdmissionInput,
    admission: AdmissionResult,
    rank_trace_delivery: MaterialRankTraceDelivery,
    outcome: serde_json::Value,
}

/// Decodes the exact source publication emitted by
/// [`crate::context_reconstruction_route::serve_context_reconstruction`].
/// The original HostRequestResultBody digest and lineage are validated before
/// any typed owner data is accepted; original read receipts and ReadIdentity
/// values are then decoded and validated in place, with no new identity or
/// digest created.
pub(crate) fn decode_dreamer_orientation_context_result<'result>(
    body: &'result HostRequestResultBody,
) -> Result<DecodedDreamerOrientationContextOwnerReadback<'result>, DreamerOrientationContextError> {
    validate_original_host_result(body)?;
    let publication = decode_owner_publication(body)?;
    let role_inputs = decode_role_inputs(body)?;
    validate_original_owner_publication(body, &publication, &role_inputs)?;
    let compilation = publication
        .context_compilation
        .map(decode_context_compilation_publication)
        .transpose()?;
    validate_compilation_publication(&publication, &role_inputs, compilation.as_ref())?;

    Ok(DecodedDreamerOrientationContextOwnerReadback {
        original_result: body,
        source_envelope: publication.source_envelope,
        source_attempt: publication.source_attempt,
        request: publication.request,
        task_plan: publication.task_plan,
        context_recipe: publication.context_recipe,
        context_tool_policy: publication.context_tool_policy,
        campaign_learning_view: publication.campaign_learning_view,
        role_inputs,
        compilation,
    })
}

fn validate_original_host_result(
    body: &HostRequestResultBody,
) -> Result<(), DreamerOrientationContextError> {
    body.validate_local_read_submission()
        .map_err(|_| DreamerOrientationContextError::InvalidOriginalPublication)?;
    if body.lineage.as_ref().is_none_or(|lineage| {
        lineage.result_class != eliot_protocol::HostRequestResultClass::NewCandidate
    }) || body.response.get("operation").and_then(serde_json::Value::as_str)
        != Some("context_reconstruction")
    {
        return Err(DreamerOrientationContextError::InvalidOriginalPublication);
    }
    Ok(())
}

fn decode_owner_publication(
    body: &HostRequestResultBody,
) -> Result<ContextReconstructionOwnerPublicationWire, DreamerOrientationContextError> {
    serde_json::from_value(
        body.response
            .get("context_reconstruction_owner_publication")
            .cloned()
            .ok_or(DreamerOrientationContextError::InvalidOriginalPublication)?,
    )
    .map_err(|_| DreamerOrientationContextError::InvalidOriginalPublication)
}

fn decode_role_inputs(
    body: &HostRequestResultBody,
) -> Result<SevenRoleInputs, DreamerOrientationContextError> {
    serde_json::from_value(
        body.response
            .get("context_reconstruction")
            .cloned()
            .ok_or(DreamerOrientationContextError::InvalidOriginalPublication)?,
    )
    .map_err(|_| DreamerOrientationContextError::InvalidOriginalPublication)
}

fn validate_original_owner_publication(
    body: &HostRequestResultBody,
    publication: &ContextReconstructionOwnerPublicationWire,
    role_inputs: &SevenRoleInputs,
) -> Result<(), DreamerOrientationContextError> {
    let source_scope = body
        .response
        .get("scope_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(DreamerOrientationContextError::InvalidOriginalPublication)?;
    let source_task = body
        .response
        .get("task_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(DreamerOrientationContextError::InvalidOriginalPublication)?;
    let envelope = &publication.source_envelope;
    let attempt = &publication.source_attempt;
    if envelope.validate().is_err()
        || attempt.validate().is_err()
        || body.attempt.as_ref() != Some(attempt)
        || body.operation_id != attempt.operation_id
        || body.request_sha256 != envelope.envelope_sha256
        || host_request_operation_id(envelope) != body.operation_id
        || envelope.identity.task_id.as_deref() != Some(source_task)
        || attempt.scope_id != source_scope
        || envelope
            .identity
            .work_scope_id
            .as_deref()
            .or(envelope.identity.session_id.as_deref())
            != Some(source_scope)
        || publication.request.validate().is_err()
        || publication.request.task_id != source_task
        || publication.request.scope_id.as_str() != source_scope
        || role_inputs.scope_id.as_str() != source_scope
        || role_inputs.state_fence != envelope.state_fence
        || role_inputs.heads_before != role_inputs.heads_after
    {
        return Err(DreamerOrientationContextError::OriginalPublicationMismatch);
    }
    validate_campaign_source_read(
        &publication.task_plan.read,
        &publication.task_plan.response,
        envelope,
        CampaignSourceReadStatus::Current,
    )?;
    validate_campaign_source_read(
        &publication.context_recipe.read,
        &publication.context_recipe.response,
        envelope,
        CampaignSourceReadStatus::Current,
    )?;
    validate_recipe_owner_source(publication, source_task, source_scope)?;
    if let Some(policy) = &publication.context_tool_policy {
        validate_campaign_source_read(
            &policy.read,
            &policy.response,
            envelope,
            CampaignSourceReadStatus::Current,
        )?;
        if policy.compiler_suppliers.as_ref()
            != publication.context_recipe.body.compiler_suppliers.as_ref()
        {
            return Err(DreamerOrientationContextError::OriginalPublicationMismatch);
        }
    }
    if let Some(view) = &publication.campaign_learning_view {
        validate_campaign_view(
            view,
            envelope,
            source_task,
            source_scope,
            &publication.context_recipe.body.recipe,
        )?;
    }
    Ok(())
}

fn validate_recipe_owner_source(
    publication: &ContextReconstructionOwnerPublicationWire,
    source_task: &str,
    source_scope: &str,
) -> Result<(), DreamerOrientationContextError> {
    let recipe = &publication.context_recipe.body.recipe;
    let context_body = &publication.context_recipe.body;
    if recipe.validate().is_err()
        || recipe.binding.task_id.to_string() != source_task
        || recipe.binding.scope_id.as_str() != source_scope
        || !publication
            .source_envelope
            .state_fence
            .is_compatible_with(&recipe.binding.state_fence)
        || serde_json::to_value(&publication.task_plan.recipe).ok()
            != publication
                .task_plan
                .read
                .source
                .as_ref()
                .map(|source| source.document.body.clone())
        || serde_json::to_value(context_body).ok()
            != publication
                .context_recipe
                .read
                .source
                .as_ref()
                .map(|source| source.document.body.clone())
    {
        return Err(DreamerOrientationContextError::OriginalPublicationMismatch);
    }
    Ok(())
}

fn validate_campaign_view(
    view: &crate::context_reconstruction_route::AuthenticatedCampaignLearningView,
    envelope: &HostRequestEnvelope,
    source_task: &str,
    source_scope: &str,
    recipe: &ContextRecipe,
) -> Result<(), DreamerOrientationContextError> {
    view.read
        .validate()
        .map_err(|_| DreamerOrientationContextError::OriginalPublicationMismatch)?;
    view.response
        .validate()
        .map_err(|_| DreamerOrientationContextError::OriginalPublicationMismatch)?;
    let response_read = CampaignLearningStateViewRead::from_named_read_response(&view.response)
        .map_err(|_| DreamerOrientationContextError::OriginalPublicationMismatch)?;
    if view.response.operation != NamedReadOperation::GetCampaignLearningStateView
        || response_read != view.read
        || view.read.status != CampaignLearningStateViewReadStatus::Current
        || view.read.read_state_fence != envelope.state_fence
        || view.response.state_fence != envelope.state_fence
        || view.lookup.scope_id.as_str() != source_scope
        || view.lookup.task_id.to_string() != source_task
        || view.read.publication.as_ref().is_none_or(|publication| {
            publication.view_id != view.lookup.view_id
                || publication.task_id != view.lookup.task_id
                || publication.scope_id != view.lookup.scope_id
                || publication.state_fence != envelope.state_fence
                || publication.view.validate_against(recipe).is_err()
        })
    {
        return Err(DreamerOrientationContextError::OriginalPublicationMismatch);
    }
    Ok(())
}

fn validate_compilation_publication(
    publication: &ContextReconstructionOwnerPublicationWire,
    role_inputs: &SevenRoleInputs,
    compilation: Option<&DecodedContextCompilationPublication>,
) -> Result<(), DreamerOrientationContextError> {
    let Some(DecodedContextCompilationPublication::Readback(compilation)) = compilation else {
        return Ok(());
    };
    let binding = &publication.context_recipe.body.recipe.binding;
    let Some(suppliers) = publication.context_recipe.body.compiler_suppliers.as_ref() else {
        return Err(DreamerOrientationContextError::CompilationPublicationMismatch);
    };
    let parts = &suppliers.admission_parts;
    if compilation.request.validate().is_err()
        || compilation.recipe != publication.context_recipe.body.recipe
        || compilation.role_inputs != *role_inputs
        || compilation.request != suppliers.candidate_request
        || compilation.candidate_policy != suppliers.candidate_policy
        || compilation.assembly_policy != suppliers.assembly_policy
        || compilation.quality != suppliers.quality_scorecard
        || compilation.request.binding != *binding
        || compilation.candidates.set.binding != *binding
        || compilation.admission_input.binding != *binding
        || compilation.admission.binding != *binding
        || compilation.candidates.validate().is_err()
        || compilation.admission_input.validate().is_err()
        || compilation.admission_input.floor != parts.floor
        || compilation.admission_input.priority != parts.priority
        || compilation.admission_input.rule != parts.rule
        || compilation.admission_input.measurement_profile != parts.measurement_profile
        || compilation.admission_input.supplied_omissions != parts.supplied_omissions
        || compilation.admission_input.measurements != parts.measurements
        || compilation
            .admission
            .validate_for(&compilation.admission_input)
            .is_err()
        || compilation.quality.validate().is_err()
        || compilation.candidate_policy.validate().is_err()
        || compilation.assembly_policy.validate().is_err()
        || compilation
            .rank_trace_delivery
            .validate(&compilation.admission)
            .is_err()
        || !compilation_outcome_matches_admission(compilation)
    {
        return Err(DreamerOrientationContextError::CompilationPublicationMismatch);
    }
    Ok(())
}

fn compilation_outcome_matches_admission(
    compilation: &DecodedContextCompilationOwnerReadback,
) -> bool {
    match (&compilation.outcome, &compilation.admission.outcome) {
        (
            DecodedContextCompilationOutcome::Complete(assembled),
            eliot_context_contracts::ContextOutcome::Complete(admitted),
        ) => assembled.admitted == *admitted && assembled.verify_boundaries().is_ok(),
        (
            DecodedContextCompilationOutcome::Incomplete(gaps),
            eliot_context_contracts::ContextOutcome::Incomplete(admitted_gaps),
        ) => gaps == admitted_gaps && gaps.validate().is_ok(),
        (
            DecodedContextCompilationOutcome::Refused(_),
            eliot_context_contracts::ContextOutcome::Complete(_),
        ) => true,
        _ => false,
    }
}

fn validate_campaign_source_read(
    read: &CampaignSourceRevisionRead,
    response: &eliot_store_api::NamedReadResponse,
    envelope: &HostRequestEnvelope,
    expected_status: CampaignSourceReadStatus,
) -> Result<(), DreamerOrientationContextError> {
    read.validate()
        .map_err(|_| DreamerOrientationContextError::OriginalPublicationMismatch)?;
    response
        .validate()
        .map_err(|_| DreamerOrientationContextError::OriginalPublicationMismatch)?;
    let decoded = CampaignSourceRevisionRead::from_named_read_response(response)
        .map_err(|_| DreamerOrientationContextError::OriginalPublicationMismatch)?;
    if response.operation != NamedReadOperation::GetCampaignSourceRevision
        || &decoded != read
        || read.status != expected_status
        || read.read_state_fence != envelope.state_fence
        || response.state_fence != envelope.state_fence
        || read.read_receipt.as_ref().is_none_or(|receipt| receipt.validate().is_err())
    {
        return Err(DreamerOrientationContextError::OriginalPublicationMismatch);
    }
    Ok(())
}

fn decode_context_compilation_publication(
    value: serde_json::Value,
) -> Result<DecodedContextCompilationPublication, DreamerOrientationContextError> {
    let outcome = value
        .get("outcome")
        .and_then(serde_json::Value::as_object)
        .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch)?;
    if let Some(refusal) = outcome.get("refused") {
        if let Some(refusal_type) = refusal.get("type").and_then(serde_json::Value::as_str) {
            if refusal_type == "DreamerOrientationCompilationError" {
                return decode_compilation_refusal(refusal)
                    .map(DecodedContextCompilationPublication::Refused);
            }
        }
    }
    let wire: ContextCompilationOwnerReadbackWire = serde_json::from_value(value)
        .map_err(|_| DreamerOrientationContextError::CompilationPublicationMismatch)?;
    let outcome = wire
        .outcome
        .as_object()
        .filter(|outcome| outcome.len() == 1)
        .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch)?;
    let (name, value) = outcome
        .iter()
        .next()
        .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch)?;
    let outcome = match name.as_str() {
        "complete" => DecodedContextCompilationOutcome::Complete(Box::new(
            serde_json::from_value(value.clone())
                .map_err(|_| DreamerOrientationContextError::CompilationPublicationMismatch)?,
        )),
        "incomplete" => DecodedContextCompilationOutcome::Incomplete(Box::new(
            serde_json::from_value(value.clone())
                .map_err(|_| DreamerOrientationContextError::CompilationPublicationMismatch)?,
        )),
        "refused"
            if value
                .get("type")
                .and_then(serde_json::Value::as_str)
                == Some("PacketCompositionError") =>
        {
            DecodedContextCompilationOutcome::Refused(value.clone())
        }
        _ => return Err(DreamerOrientationContextError::CompilationPublicationMismatch),
    };
    Ok(DecodedContextCompilationPublication::Readback(Box::new(
        DecodedContextCompilationOwnerReadback {
            request: wire.request,
            recipe: wire.recipe,
            candidate_policy: wire.candidate_policy,
            assembly_policy: wire.assembly_policy,
            role_inputs: wire.role_inputs,
            quality: wire.quality,
            candidates: wire.candidates,
            admission_input: wire.admission_input,
            admission: wire.admission,
            rank_trace_delivery: wire.rank_trace_delivery,
            outcome,
        },
    )))
}

fn decode_compilation_refusal(
    value: &serde_json::Value,
) -> Result<DecodedDreamerOrientationCompilationRefusal, DreamerOrientationContextError> {
    let refusal = value
        .as_object()
        .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch)?;
    if refusal.get("type").and_then(serde_json::Value::as_str)
        != Some("DreamerOrientationCompilationError")
    {
        return Err(DreamerOrientationContextError::CompilationPublicationMismatch);
    }
    let variant = refusal
        .get("variant")
        .and_then(serde_json::Value::as_str)
        .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch)?;
    let source = refusal.get("source").cloned();
    match variant {
        "missing_suppliers" if source.is_none() => {
            Ok(DecodedDreamerOrientationCompilationRefusal::MissingSuppliers)
        }
        "supplier_readback_mismatch" if source.is_none() => Ok(
            DecodedDreamerOrientationCompilationRefusal::SupplierReadbackMismatch,
        ),
        "missing_recipe_source" if source.is_none() => {
            Ok(DecodedDreamerOrientationCompilationRefusal::MissingRecipeSource)
        }
        "missing_campaign_learning_view" if source.is_none() => Ok(
            DecodedDreamerOrientationCompilationRefusal::MissingCampaignLearningView,
        ),
        "recipe_digest_mismatch" if source.is_none() => {
            Ok(DecodedDreamerOrientationCompilationRefusal::RecipeDigestMismatch)
        }
        "composition" => source
            .filter(serde_json::Value::is_object)
            .map(DecodedDreamerOrientationCompilationRefusal::Composition)
            .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch),
        "supplier_validation" => source
            .filter(serde_json::Value::is_object)
            .map(DecodedDreamerOrientationCompilationRefusal::SupplierValidation)
            .ok_or(DreamerOrientationContextError::CompilationPublicationMismatch),
        _ => Err(DreamerOrientationContextError::CompilationPublicationMismatch),
    }
}

/// Invoke the real candidate, admission and assembly owner chain from the
/// exact Context reconstruction and current owner suppliers retained before
/// model execution. No suppliers are synthesized from reconstructed roles.
pub(crate) fn compile_dreamer_orientation_context<'owner, 'source>(
    reconstruction: &'owner ContextReconstructionOwnerReadback<'source>,
) -> Result<ContextCompilationOwnerReadback<'owner>, DreamerOrientationCompilationError> {
    let Some(suppliers) = reconstruction
        .context_recipe
        .body
        .compiler_suppliers
        .as_ref()
    else {
        return Err(DreamerOrientationCompilationError::MissingSuppliers);
    };
    let Some(tool_policy) = reconstruction.context_tool_policy.as_ref() else {
        return Err(DreamerOrientationCompilationError::SupplierReadbackMismatch);
    };
    if tool_policy.compiler_suppliers.as_ref() != Some(suppliers)
        || tool_policy.read.validate().is_err()
        || tool_policy.read.status != eliot_store_api::CampaignSourceReadStatus::Current
        || tool_policy.read.read_state_fence != reconstruction.source_envelope.state_fence
        || reconstruction.context_recipe.read.validate().is_err()
        || reconstruction.context_recipe.read.status
            != eliot_store_api::CampaignSourceReadStatus::Current
        || reconstruction.context_recipe.read.read_state_fence
            != reconstruction.source_envelope.state_fence
    {
        return Err(DreamerOrientationCompilationError::SupplierReadbackMismatch);
    }
    suppliers.validate_for_recipe(&reconstruction.context_recipe.body.recipe)?;
    let source = reconstruction
        .context_recipe
        .read
        .source
        .as_ref()
        .ok_or(DreamerOrientationCompilationError::MissingRecipeSource)?;
    let rederived_digest = context_recipe_body_digest(&reconstruction.context_recipe.body)?;
    if rederived_digest != source.content_digest {
        return Err(DreamerOrientationCompilationError::RecipeDigestMismatch);
    }
    let campaign_learning_view = reconstruction
        .campaign_learning_view
        .as_ref()
        .ok_or(DreamerOrientationCompilationError::MissingCampaignLearningView)?;
    let campaign_view = campaign_learning_view
        .read
        .publication
        .as_ref()
        .filter(|publication| {
            publication.view_id == suppliers.campaign_learning_state_view_id
                && publication.state_fence == reconstruction.source_envelope.state_fence
        })
        .map(|publication| &publication.view)
        .ok_or(DreamerOrientationCompilationError::MissingCampaignLearningView)?;

    let admission = &suppliers.admission_parts;
    KernelContextReadClient::compile_context_packet(
        &reconstruction.seven_role_inputs,
        &suppliers.candidate_request,
        &reconstruction.context_recipe.body.recipe,
        &suppliers.candidate_policy,
        campaign_view,
        &source.content_digest,
        admission.floor.clone(),
        admission.priority.clone(),
        admission.rule.clone(),
        admission.measurement_profile.clone(),
        admission.supplied_omissions.clone(),
        admission.measurements.clone(),
        suppliers.quality_scorecard.clone(),
        &suppliers.assembly_policy,
        |payload| suppliers.measure(payload),
    )
    .map_err(DreamerOrientationCompilationError::from)
}

/// Serializes the complete native owner readback carried by the result-body
/// transport. Original request, role reads, candidate omissions, admission
/// result, rank traces, assembly disposition and original owner policies stay
/// together, including a structured refusal from the assembly stage.
pub(crate) fn compilation_owner_publication(
    compilation: &ContextCompilationOwnerReadback<'_>,
) -> Result<serde_json::Value, String> {
    let outcome = match &compilation.outcome {
        ContextCompilationOwnerOutcome::Complete(assembled) => {
            serde_json::json!({"complete": assembled})
        }
        ContextCompilationOwnerOutcome::Incomplete(gaps) => {
            serde_json::json!({"incomplete": gaps})
        }
        ContextCompilationOwnerOutcome::Refused(error) => {
            serde_json::json!({
                "refused": {
                    "type": "PacketCompositionError",
                    "reason": packet_composition_error_publication(error),
                }
            })
        }
    };
    serde_json::to_value(serde_json::json!({
        "request": compilation.request,
        "recipe": compilation.recipe,
        "candidate_policy": compilation.candidate_policy,
        "assembly_policy": compilation.assembly_policy,
        "role_inputs": compilation.role_inputs,
        "quality": compilation.quality,
        "candidates": compilation.candidates,
        "admission_input": compilation.admission_input,
        "admission": compilation.admission,
        "rank_trace_delivery": compilation.rank_trace_delivery,
        "outcome": outcome,
    }))
    .map_err(|error| error.to_string())
}

/// Retains a typed compiler refusal that occurred before candidate/admission
/// readback existed. The caller publishes it as an outcome rather than
/// converting it into a reconstruction error string.
pub(crate) fn compilation_failure_publication(
    error: &DreamerOrientationCompilationError,
) -> serde_json::Value {
    let refusal = match error {
        DreamerOrientationCompilationError::MissingSuppliers => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "missing_suppliers",
        }),
        DreamerOrientationCompilationError::SupplierReadbackMismatch => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "supplier_readback_mismatch",
        }),
        DreamerOrientationCompilationError::MissingRecipeSource => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "missing_recipe_source",
        }),
        DreamerOrientationCompilationError::MissingCampaignLearningView => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "missing_campaign_learning_view",
        }),
        DreamerOrientationCompilationError::RecipeDigestMismatch => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "recipe_digest_mismatch",
        }),
        DreamerOrientationCompilationError::Composition(error) => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "composition",
            "source": {
                "type": "PacketCompositionError",
                "reason": packet_composition_error_publication(error),
            },
        }),
        DreamerOrientationCompilationError::SupplierValidation(error) => serde_json::json!({
            "type": "DreamerOrientationCompilationError",
            "variant": "supplier_validation",
            "source": context_publication_error(error),
        }),
    };
    serde_json::json!({"outcome": {"refused": refusal}})
}

fn packet_composition_error_publication(error: &PacketCompositionError) -> serde_json::Value {
    match error {
        PacketCompositionError::BindingMismatch => serde_json::json!({
            "variant": "binding_mismatch",
        }),
        PacketCompositionError::RoleUnavailable { role } => serde_json::json!({
            "variant": "role_unavailable",
            "role": role,
        }),
        PacketCompositionError::RoleConversionMissing { role, owner } => serde_json::json!({
            "variant": "role_conversion_missing",
            "role": role,
            "owner": owner,
        }),
        PacketCompositionError::Candidates(error) => serde_json::json!({
            "variant": "candidates",
            "error": context_error_publication(error),
        }),
        PacketCompositionError::Admission(error) => serde_json::json!({
            "variant": "admission",
            "error": context_error_publication(error),
        }),
        PacketCompositionError::AdmissionIncomplete(gaps) => serde_json::json!({
            "variant": "admission_incomplete",
            "gaps": gaps,
        }),
        PacketCompositionError::CampaignView(error) => serde_json::json!({
            "variant": "campaign_view",
            "error": context_error_publication(error),
        }),
        PacketCompositionError::Assembly(error) => serde_json::json!({
            "variant": "assembly",
            "error": assembly_error_publication(error),
        }),
        PacketCompositionError::QualityIncomplete {
            attempted_recipe_digest,
            attempted_binding,
            quality,
            refusal,
        } => serde_json::json!({
            "variant": "quality_incomplete",
            "attempted_recipe_digest": attempted_recipe_digest,
            "attempted_binding": attempted_binding,
            "quality": quality,
            "refusal": refusal,
        }),
        PacketCompositionError::TraceDelivery(error) => serde_json::json!({
            "variant": "trace_delivery",
            "error": context_error_publication(error),
        }),
    }
}

fn context_error_publication(error: &ContextError) -> serde_json::Value {
    match error {
        ContextError::MissingField(field) => serde_json::json!({
            "variant": "missing_field",
            "field": field,
        }),
        ContextError::InvalidField(field) => serde_json::json!({
            "variant": "invalid_field",
            "field": field,
        }),
        ContextError::Bounds { field } => serde_json::json!({
            "variant": "bounds",
            "field": field,
        }),
        ContextError::InvalidFence => serde_json::json!({"variant": "invalid_fence"}),
        ContextError::Duplicate(field) => serde_json::json!({
            "variant": "duplicate",
            "field": field,
        }),
        ContextError::DenominatorMismatch => {
            serde_json::json!({"variant": "denominator_mismatch"})
        }
        ContextError::IdentityConflict => serde_json::json!({"variant": "identity_conflict"}),
        ContextError::WholeUnitRequired => {
            serde_json::json!({"variant": "whole_unit_required"})
        }
        ContextError::MissingFloor => serde_json::json!({"variant": "missing_floor"}),
        ContextError::StaleFloor => serde_json::json!({"variant": "stale_floor"}),
        ContextError::BlockedFloor => serde_json::json!({"variant": "blocked_floor"}),
        ContextError::OversizedFloor => serde_json::json!({"variant": "oversized_floor"}),
        ContextError::Overflow => serde_json::json!({"variant": "overflow"}),
        ContextError::CapacityExceeded => serde_json::json!({"variant": "capacity_exceeded"}),
        ContextError::UnknownMeasurement => {
            serde_json::json!({"variant": "unknown_measurement"})
        }
        ContextError::OmissionHandleInvalid => {
            serde_json::json!({"variant": "omission_handle_invalid"})
        }
        ContextError::EconomyMismatch => serde_json::json!({"variant": "economy_mismatch"}),
        ContextError::QualityIncomplete => {
            serde_json::json!({"variant": "quality_incomplete"})
        }
        ContextError::SelectionIntegrityMismatch => {
            serde_json::json!({"variant": "selection_integrity_mismatch"})
        }
        ContextError::InvalidDigest(field) => serde_json::json!({
            "variant": "invalid_digest",
            "field": field,
        }),
    }
}

fn assembly_error_publication(error: &AssemblyError) -> serde_json::Value {
    match error {
        AssemblyError::Contract(error) => serde_json::json!({
            "variant": "contract",
            "error": context_error_publication(error),
        }),
        AssemblyError::Bounds(field) => serde_json::json!({
            "variant": "bounds",
            "field": field,
        }),
        AssemblyError::MeasurementMismatch(field) => serde_json::json!({
            "variant": "measurement_mismatch",
            "field": field,
        }),
        AssemblyError::Incomplete(gaps) => serde_json::json!({
            "variant": "incomplete",
            "gaps": gaps,
        }),
        AssemblyError::QualityIncomplete(quality, refusal) => serde_json::json!({
            "variant": "quality_incomplete",
            "quality": quality,
            "refusal": refusal,
        }),
    }
}

fn context_publication_error(error: &ContextPublicationError) -> serde_json::Value {
    match error {
        ContextPublicationError::Recipe(error) => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "recipe",
            "source": context_error_publication(error),
        }),
        ContextPublicationError::Input(error) => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "input",
            "source": smart_context_error_publication(error),
        }),
        ContextPublicationError::Delivery(error) => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "delivery",
            "source": reactive_input_error_publication(error),
        }),
        ContextPublicationError::Serialization(message) => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "serialization",
            "message": message,
        }),
        ContextPublicationError::Resolution(refusal) => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "resolution",
            "refusal": refusal,
        }),
        ContextPublicationError::BindingMismatch { field } => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "binding_mismatch",
            "field": field,
        }),
        ContextPublicationError::CompilerSupplierInvalid => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "compiler_supplier_invalid",
        }),
        ContextPublicationError::MissingCurrentDelivery => serde_json::json!({
            "type": "ContextPublicationError",
            "variant": "missing_current_delivery",
        }),
    }
}

fn reactive_input_error_publication(error: &ReactiveInputError) -> serde_json::Value {
    match error {
        ReactiveInputError::Context(error) => serde_json::json!({
            "type": "ReactiveInputError",
            "variant": "context",
            "source": context_error_publication(error),
        }),
        ReactiveInputError::InvalidField { field, reason } => serde_json::json!({
            "type": "ReactiveInputError",
            "variant": "invalid_field",
            "field": field,
            "reason": reason,
        }),
        ReactiveInputError::DigestMismatch { field } => serde_json::json!({
            "type": "ReactiveInputError",
            "variant": "digest_mismatch",
            "field": field,
        }),
        ReactiveInputError::BindingMismatch { field } => serde_json::json!({
            "type": "ReactiveInputError",
            "variant": "binding_mismatch",
            "field": field,
        }),
        ReactiveInputError::QualityRefused {
            operation,
            blocking,
            unresolved_applicability,
        } => serde_json::json!({
            "type": "ReactiveInputError",
            "variant": "quality_refused",
            "operation": operation,
            "blocking": blocking,
            "unresolved_applicability": unresolved_applicability,
        }),
    }
}

fn smart_context_error_publication(error: &SmartContextError) -> serde_json::Value {
    match error {
        SmartContextError::InvalidText { field } => serde_json::json!({
            "type": "ContextError",
            "variant": "invalid_text",
            "field": field,
        }),
        SmartContextError::MissingLineage { field } => serde_json::json!({
            "type": "ContextError",
            "variant": "missing_lineage",
            "field": field,
        }),
        SmartContextError::FenceMismatch => serde_json::json!({
            "type": "ContextError",
            "variant": "fence_mismatch",
        }),
        SmartContextError::RecipeRevisionMismatch {
            recipe_revision,
            task_revision,
        } => serde_json::json!({
            "type": "ContextError",
            "variant": "recipe_revision_mismatch",
            "recipe_revision": recipe_revision,
            "task_revision": task_revision,
        }),
        SmartContextError::CampaignBindingMismatch { field } => serde_json::json!({
            "type": "ContextError",
            "variant": "campaign_binding_mismatch",
            "field": field,
        }),
        SmartContextError::CampaignSourceMismatch { role } => serde_json::json!({
            "type": "ContextError",
            "variant": "campaign_source_mismatch",
            "role": role,
        }),
        SmartContextError::CampaignSupportMismatch => serde_json::json!({
            "type": "ContextError",
            "variant": "campaign_support_mismatch",
        }),
        SmartContextError::UnsupportedCampaignPolicy(role) => serde_json::json!({
            "type": "ContextError",
            "variant": "unsupported_campaign_policy",
            "role": role,
        }),
        SmartContextError::NonDroppableCapacity => serde_json::json!({
            "type": "ContextError",
            "variant": "non_droppable_capacity",
        }),
        SmartContextError::InvalidCampaignRecipe => serde_json::json!({
            "type": "ContextError",
            "variant": "invalid_campaign_recipe",
        }),
        SmartContextError::MissingCampaignRole(role) => serde_json::json!({
            "type": "ContextError",
            "variant": "missing_campaign_role",
            "role": role,
        }),
        SmartContextError::CampaignCapacityOutOfRange => serde_json::json!({
            "type": "ContextError",
            "variant": "campaign_capacity_out_of_range",
        }),
        SmartContextError::DuplicateIdentity { field } => serde_json::json!({
            "type": "ContextError",
            "variant": "duplicate_identity",
            "field": field,
        }),
        SmartContextError::MissingRequiredRole(role) => serde_json::json!({
            "type": "ContextError",
            "variant": "missing_required_role",
            "role": role,
        }),
        SmartContextError::Unrepresentable { atom_id } => serde_json::json!({
            "type": "ContextError",
            "variant": "unrepresentable",
            "atom_id": atom_id,
        }),
        SmartContextError::RevisionOverflow => serde_json::json!({
            "type": "ContextError",
            "variant": "revision_overflow",
        }),
    }
}

/// Binds the decoded original Context owner publication to the admitted
/// Dreamer operation and its live Governor owners. The returned value borrows
/// both the complete original publication and owner projections so downstream
/// packet provenance can retain the source closure without rebuilding it.
///
/// Route evidence and capability scope are optional only when their current
/// owners do not supply those values; the Governor join then keeps affordance
/// applicability explicitly unknown.
pub(crate) fn bind_dreamer_orientation_context<'a>(
    input: DreamerOrientationContextBindInput<'a>,
) -> Result<DreamerOrientationContextJoinedReadback<'a>, DreamerOrientationContextError> {
    let DreamerOrientationContextBindInput {
        source,
        job,
        bundle,
        admission,
        attempt_id,
        governor,
        work_scope,
        original_route,
        current_route_scope,
        capability_now,
    } = input;
    let binding = &source.context_recipe.body.recipe.binding;
    if job.validate().is_err()
        || bundle.validate().is_err()
        || admission.validate().is_err()
        || job.job_class != admission.job_class
        || job.task_id.as_deref() != Some(admission.task_id.as_str())
        || job.scope_id != admission.scope_id
        || bundle.job_id != job.job_id
        || bundle.task_id != admission.task_id
        || bundle.scope_id != admission.scope_id
        || bundle.manifest_digest != job.frozen_manifest_digest
        || bundle.manifest_digest != admission.frozen_manifest_digest
        || bundle.state_fence != job.state_fence
        || admission.state_fence != job.state_fence
        || binding.task_id.to_string() != admission.task_id
        || binding.scope_id.as_str() != admission.scope_id
        || binding.attempt_id.as_str() != attempt_id.as_str()
        || binding.operation_id.as_ref().is_none_or(|operation| {
            operation.as_str() != admission.operation_id
        })
        || binding.state_fence != job.state_fence
    {
        return Err(DreamerOrientationContextError::BindingMismatch);
    }
    let source_omissions = match source.compilation.as_ref() {
        Some(DecodedContextCompilationPublication::Readback(compilation)) => {
            if compilation.recipe != source.context_recipe.body.recipe
                || compilation.request.binding != *binding
                || compilation.role_inputs != source.role_inputs
                || compilation.candidates.set.binding != *binding
                || compilation.admission_input.binding != *binding
                || compilation.admission.binding != *binding
            {
                return Err(DreamerOrientationContextError::CompilationPublicationMismatch);
            }
            Some(compilation.candidates.omissions.as_slice())
        }
        Some(DecodedContextCompilationPublication::Refused(_)) | None => None,
    };
    let projections = bind_orientation_projections(&OrientationProjectionOwnerInput {
        binding,
        governor,
        work_scope,
        role_inputs: &source.role_inputs,
        context_request: &source.request,
        omissions: source_omissions,
        original_route,
        current_route_scope,
        capability_now,
    });
    Ok(DreamerOrientationContextJoinedReadback {
        source,
        job,
        bundle,
        admission,
        attempt_id,
        projections,
    })
}
