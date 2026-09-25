//! Native governed Context Compiler delivery owned by `eliotd`.
//!
//! The standalone wasm prototype remains fail-closed for guest-marked input.
//! This module is the native owner-bound path: it composes the already
//! admitted learning candidate, governed retrieval, Context admission, and
//! delivery projection under one live Governor issuance. The daemon
//! composition supplies the owner revalidation and the retained backlog
//! identity check before calling this pure orchestration.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context_admission::admit_context_with_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, CONTEXT_CONTRACT_VERSION, CapacityLimits, ContextBinding,
    ContextError, ContextOutcome, ContextRecipe, MeasurementStatus, ProviderRole, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_contracts::{ArtifactId, sha256_hex};
use eliot_governor::{LearningAdmissionError, LearningAdmissionRequest};
use eliot_improvement::candidate_bounds::{
    BoundsError, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef, retrieve_governed,
};
use eliot_improvement::{
    LearningProduction, PresentedLearning, datetime_from_unix, produce_learning_candidate,
};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// One native learning compilation: retrieval, admission, and optional view.
#[derive(Clone, Debug)]
pub struct NativeGovernedCompilation {
    pub retrieval: RetrievalDecision,
    pub admission: AdmissionResult,
    pub view: Option<ActiveUnderstandingViewResult>,
}

/// One owner-issued Context Compiler request retained by the daemon.
///
/// The request carries context material, but never a permit, Governor handle,
/// backlog handle, or caller-selected authority. The daemon mints and verifies
/// those objects at dispatch time from its live owner projection. This keeps the
/// event queue a transport seam rather than a second learning authority.
#[derive(Clone, Debug)]
pub struct GovernedContextDispatchRequest {
    /// Subject request used only to select the live target owner.
    pub admission: LearningAdmissionRequest,
    /// Active reusable candidate to compile for this request.
    pub candidate_id: String,
    /// Closed reusable-candidate evidence handle.
    pub closure_ref: String,
    /// Exact context/task identity for the compilation.
    pub binding: ContextBinding,
    /// Learning atom identity and provider role.
    pub atom_id: String,
    pub provider_role: ProviderRole,
    /// Exact source lineage carried into the learning provenance.
    pub source_id: String,
    pub snapshot_id: String,
    pub source_revision: String,
    pub content: String,
    /// Optional local overlay expiry; required when the admission names one.
    pub overlay_id: Option<String>,
    pub expires_at_unix_secs: Option<u64>,
    pub measurement_digest: String,
    pub measurement_serializer: String,
    /// Complete context admission input supplied by the admitted caller edge.
    pub input: AdmissionInput,
    pub recipe: ContextRecipe,
    pub quality: QualityScorecard,
    pub policy: AssemblyPolicy,
    /// Identity of the attempt requesting delivery. A mismatch with the
    /// permit target causes a fresh Governor cross-task receipt.
    pub requesting_campaign_id: String,
    pub requesting_task_id: String,
}

/// Wire projection of [`AssemblyPolicy`] for the authenticated local-read
/// tool. The assembly policy is not serde-derived in its owning crate, so the
/// daemon keeps this transport mirror closed and converts it back before any
/// owner or compiler call.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernedContextPolicyWire {
    fence_digest: String,
    max_serialized_bytes: u64,
    serializer_id: String,
    serializer_version: String,
    serializer_options_digest: String,
    route_id: String,
    model_id: String,
    measurement_status: MeasurementStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernedContextDispatchWire {
    admission: LearningAdmissionRequest,
    candidate_id: String,
    closure_ref: String,
    binding: ContextBinding,
    atom_id: String,
    provider_role: ProviderRole,
    source_id: String,
    snapshot_id: String,
    source_revision: String,
    content: String,
    overlay_id: Option<String>,
    expires_at_unix_secs: Option<u64>,
    measurement_digest: String,
    measurement_serializer: String,
    input: AdmissionInput,
    recipe: ContextRecipe,
    quality: QualityScorecard,
    policy: GovernedContextPolicyWire,
    requesting_campaign_id: String,
    requesting_task_id: String,
}

impl From<GovernedContextDispatchWire> for GovernedContextDispatchRequest {
    fn from(wire: GovernedContextDispatchWire) -> Self {
        Self {
            admission: wire.admission,
            candidate_id: wire.candidate_id,
            closure_ref: wire.closure_ref,
            binding: wire.binding,
            atom_id: wire.atom_id,
            provider_role: wire.provider_role,
            source_id: wire.source_id,
            snapshot_id: wire.snapshot_id,
            source_revision: wire.source_revision,
            content: wire.content,
            overlay_id: wire.overlay_id,
            expires_at_unix_secs: wire.expires_at_unix_secs,
            measurement_digest: wire.measurement_digest,
            measurement_serializer: wire.measurement_serializer,
            input: wire.input,
            recipe: wire.recipe,
            quality: wire.quality,
            policy: AssemblyPolicy {
                fence_digest: wire.policy.fence_digest,
                max_serialized_bytes: wire.policy.max_serialized_bytes,
                serializer_id: wire.policy.serializer_id,
                serializer_version: wire.policy.serializer_version,
                serializer_options_digest: wire.policy.serializer_options_digest,
                route_id: wire.policy.route_id,
                model_id: wire.policy.model_id,
                measurement_status: wire.policy.measurement_status,
            },
            requesting_campaign_id: wire.requesting_campaign_id,
            requesting_task_id: wire.requesting_task_id,
        }
    }
}

/// Canonical local-read capability name for native governed Context Compiler
/// delivery.
pub const GOVERNED_CONTEXT_TOOL_NAME: &str = "eliot.context.governed";

/// Return whether a claimed local-read tool names native governed context
/// delivery.
#[must_use]
pub fn is_governed_context_tool(tool: &Value) -> bool {
    tool.as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .is_some_and(|name| name == GOVERNED_CONTEXT_TOOL_NAME)
}

/// Serve one claimed local-read pair through the native Context Compiler.
///
/// The pair is already Kernel-admitted. This function still checks the
/// capability/task/fence binding before decoding, and returns a typed refusal
/// body for every owner/compiler rejection so a poison request cannot spin the
/// local-read poller.
pub fn serve_governed_context_pair(
    composition: &crate::DaemonComposition,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> HostRequestResultBody {
    let outcome = drive_governed_context_request(composition, envelope, tool);
    let response = match outcome {
        Ok(compilation) => governed_context_success_response(compilation)
            .unwrap_or_else(governed_context_refusal_response),
        Err(detail) => governed_context_refusal_response(detail),
    };
    governed_context_result_body(envelope, attempt, response)
}

fn governed_context_success_response(
    compilation: NativeGovernedCompilation,
) -> Result<Value, String> {
    let retrieval = serde_json::to_value(compilation.retrieval)
        .map_err(|error| format!("governed context retrieval serialization: {error}"))?;
    let admission = serde_json::to_value(compilation.admission)
        .map_err(|error| format!("governed context admission serialization: {error}"))?;
    let view = match compilation.view {
        Some(result) => Some(
            serde_json::to_value(&result.view)
                .map_err(|error| format!("governed context view serialization: {error}"))?,
        ),
        None => None,
    };
    Ok(serde_json::json!({
        "wire_id": "eliot.governed-context-delivery",
        "wire_version": 1,
        "outcome": "compiled",
        "retrieval": retrieval,
        "admission": admission,
        "view": view,
    }))
}

fn governed_context_refusal_response(detail: impl AsRef<str>) -> Value {
    serde_json::json!({
        "wire_id": "eliot.governed-context-delivery",
        "wire_version": 1,
        "outcome": "refused",
        "detail": detail.as_ref().chars().take(512).collect::<String>(),
    })
}

fn drive_governed_context_request(
    composition: &crate::DaemonComposition,
    envelope: &HostRequestEnvelope,
    tool: &Value,
) -> Result<NativeGovernedCompilation, String> {
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != GOVERNED_CONTEXT_TOOL_NAME || name != envelope.identity.capability {
        return Err("presented tool does not match the governed context capability".to_owned());
    }
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .cloned()
        .ok_or_else(|| "governed context tool has no arguments".to_owned())?;
    let wire: GovernedContextDispatchWire = serde_json::from_value(arguments)
        .map_err(|error| format!("governed context arguments fail their shape: {error}"))?;
    let request: GovernedContextDispatchRequest = wire.into();
    let Some(task_id) = envelope.identity.task_id.as_ref() else {
        return Err("governed context envelope has no task binding".to_owned());
    };
    if task_id.as_str() != request.admission.target_task_id
        || request.binding.task_id.as_str() != request.admission.target_task_id
        || request.requesting_task_id != request.admission.target_task_id
    {
        return Err("governed context task binding is not exact".to_owned());
    }
    if envelope.state_fence != request.binding.state_fence
        || envelope.state_fence != request.input.binding.state_fence
        || envelope.state_fence != request.recipe.binding.state_fence
    {
        return Err("governed context fence binding is not exact".to_owned());
    }
    composition
        .dispatch_governed_context_request(request)
        .map_err(|error| error.to_string())
}

fn governed_context_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    response: Value,
) -> HostRequestResultBody {
    let bytes = eliot_contracts::canonical_json_bytes(&response).unwrap_or_default();
    let result_digest = sha256_hex(&bytes);
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest,
        response,
        attempt: Some(attempt.clone()),
    };
    body.validate().unwrap_or(());
    body
}

/// Measure the exact canonical payload for the native dispatch path.
///
/// The measurement identity and envelope digest are derived from the bytes
/// supplied by the Context Compiler. Route, serializer, and capacity values
/// come from the already-admitted recipe/policy; no synthetic tokenizer or STU
/// observation is introduced.
pub(crate) fn measure_governed_context_payload(
    payload: &[u8],
    binding: &ContextBinding,
    capacity: CapacityLimits,
    policy: &AssemblyPolicy,
) -> Result<SerializedContextMeasurement, ContextError> {
    if policy.measurement_status != MeasurementStatus::ExactUtf8 {
        return Err(ContextError::UnknownMeasurement);
    }
    let envelope_digest = sha256_hex(payload);
    let measurement_id = ArtifactId::new(format!("governed-context-measurement:{envelope_digest}"))
        .map_err(|_| ContextError::InvalidField("measurement.measurement_id"))?;
    let measurement = SerializedContextMeasurement {
        measurement_id,
        context: binding.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest,
        serializer_id: policy.serializer_id.clone(),
        serializer_version: policy.serializer_version.clone(),
        serializer_options_digest: policy.serializer_options_digest.clone(),
        route_id: policy.route_id.clone(),
        model_id: policy.model_id.clone(),
        rendered_utf8_bytes: u64::try_from(payload.len()).map_err(|_| ContextError::Overflow)?,
        stu_estimate: None,
        tokenizer: None,
        status: MeasurementStatus::ExactUtf8,
        fixed_overhead: capacity.fixed_overhead,
        output_reserve: capacity.output_reserve,
        review_reserve: capacity.review_reserve,
        false_safe_overflow: None,
        false_rejection_or_decomposition: None,
        valid_until: None,
    };
    measurement.validate()?;
    Ok(measurement)
}

/// Every failure refuses the complete native compilation before delivery.
#[derive(Debug, Error, PartialEq)]
pub enum NativeComposeError {
    #[error("producer and screen cite different Governor issuances")]
    PermitMismatch,
    #[error("daemon owner evidence refused native context delivery: {0}")]
    Owner(LearningAdmissionError),
    #[error("campaign overlay record required for native governed retrieval")]
    OverlayRequired,
    #[error("owner clock unavailable")]
    ClockUnavailable,
    #[error("governed production refused: {0}")]
    Production(BoundsError),
    #[error("governed retrieval refused: {0}")]
    Retrieval(BoundsError),
    #[error("governed admission refused: {0}")]
    Admission(ContextError),
    #[error("governed delivery refused: {0}")]
    Assembly(AssemblyError),
}

/// Compose one native learning compilation using the live host clock.
///
/// `production` and `presented` must cite the same owner-issued permit. The
/// caller must have already checked that `presented.backlog` is the daemon's
/// retained backlog; this function itself never creates or selects a
/// registry.
pub(crate) fn compose_governed_native_context<F>(
    production: LearningProduction<'_>,
    presented: PresentedLearning<'_>,
    mut input: AdmissionInput,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<NativeGovernedCompilation, NativeComposeError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if production.verified.permit().digest() != presented.verified.permit().digest() {
        return Err(NativeComposeError::PermitMismatch);
    }
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NativeComposeError::ClockUnavailable)?
        .as_secs();
    let presented = PresentedLearning {
        now_unix_secs,
        ..presented
    };
    let overlay = presented
        .overlay
        .ok_or(NativeComposeError::OverlayRequired)?;
    let permit = presented.verified.permit();
    let produced =
        produce_learning_candidate(production).map_err(NativeComposeError::Production)?;
    let learning = produced
        .learning
        .as_ref()
        .ok_or(NativeComposeError::Retrieval(
            BoundsError::ReusableBackingMismatch,
        ))?;
    let reusable = ReusableCandidateRef {
        candidate_id: learning
            .candidate_id
            .clone()
            .ok_or(NativeComposeError::Retrieval(
                BoundsError::ReusableBackingMismatch,
            ))?,
        closure_ref: learning.closure_ref.clone(),
        owner: learning.owner.clone(),
        origin_campaign_id: permit.source_campaign_id().to_owned(),
    };
    let retrieval = retrieve_governed(GovernedRetrieval {
        requesting_campaign_id: presented.requesting_campaign_id,
        requesting_task_id: presented.requesting_task_id,
        overlay,
        reusable: Some(&reusable),
        draft_delta_present: false,
        cross_task_admission: presented.cross_task_admission,
        backlog: presented.backlog,
        verified: presented.verified,
        now: datetime_from_unix(presented.now_unix_secs).map_err(NativeComposeError::Retrieval)?,
    })
    .map_err(NativeComposeError::Retrieval)?;

    input.candidates.candidates.push(produced);
    input.learning_tickets.push(presented.ticket.clone());
    let admission =
        admit_context_with_learning(&input, presented).map_err(NativeComposeError::Admission)?;
    let view = match &admission.outcome {
        ContextOutcome::Complete(set) => Some(
            assemble_active_view_with_learning(set, recipe, quality, policy, measure, presented)
                .map_err(NativeComposeError::Assembly)?,
        ),
        ContextOutcome::Incomplete(_) => None,
    };
    Ok(NativeGovernedCompilation {
        retrieval,
        admission,
        view,
    })
}
