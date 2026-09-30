//! Production CC-002 bridge from an admitted Dreamer job to the admitted
//! OpenCode runtime owner.
//!
//! This adapter owns no route admission, provider credentials, or authority.
//! Route IDs and fingerprints arrive from the admitted route allocator; the
//! `OpenCodeClient` remains the only executor and its original sealed outcome
//! or typed refusal stays attached to the returned record. Provider output is
//! never re-encoded as raw evidence, and a stricter Dreamer draft rejection is
//! reported as malformed with the exact owner-retained assistant bytes.

use std::time::{Duration, Instant};

use eliot_agent_api::{
    route_fingerprint_digest_for, AgentResult, CancellationState, EffectCeiling, RouteFingerprint,
};
use eliot_agent_opencode::{
    AdmittedAttemptError, AdmittedAttemptOutcome, AdmittedOpenCodeAttempt,
    AdmittedOutcomeProjectionError, AvailabilityState, ModelSelection,
    OPENCODE_PROVIDER_RAW_OUTPUT_UTF8_KEY, OpenCodeClient, OpenCodeRunError,
    ReadOnlyRunRequest, RunStatus, SealedRouteDisposition, UsageAvailability, UsageTelemetry,
};
use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{
    CostUsageReceipt, DreamInputBundle, DreamJobAdmission, DreamJobInput, MODEL_ROUTE_SCHEMA_VERSION,
    ModelDraft, ModelRouteDisposition, ModelRouteExecutionIdentity, ModelRouteOutcome,
    ModelRoutePrivacy, ModelRouteProviderUsage, ModelRouteRequest, ModelRouteUsageState,
    bundle_digest_of,
};
use eliot_dreamer_contracts::grounding::{route_fingerprint, RouteIdentity};
use serde::Serialize;
use serde_json::Value;

const OPENCODE_DREAMER_HARNESS_ID: &str = "eliot-agent-opencode/admitted-read-only-v1";
const DREAMER_MODEL_PROMPT_INSTRUCTIONS: &str = concat!(
    "Return one JSON object matching ModelDraft v1. Use admitted_job_id exactly as ModelDraft.job_id. ",
    "Treat every statement as a hypothesis; do not claim confirmed evidence."
);

/// Exact immutable inputs for one CC-002 call. `selected_route_id` is an
/// opaque ID minted by the owning route allocator. Its matching fingerprint
/// must be the exact selected fingerprint on the admitted agent-route
/// receipt; this adapter never derives a route key from provider/model names.
pub struct DreamerOrientationModelInput<'a> {
    pub job: &'a DreamJobInput,
    pub admission: &'a DreamJobAdmission,
    pub bundle: &'a DreamInputBundle,
    pub retained_context_bytes: &'a [u8],
    pub selected_route_id: &'a str,
    pub selected_route_fingerprint: &'a RouteFingerprint,
    pub cancellation: CancellationState,
    pub now_unix_ms: u64,
    pub admitted: &'a AdmittedOpenCodeAttempt,
    pub read_only_request: &'a ReadOnlyRunRequest,
    pub current_fence: &'a StateFence,
    pub runtime_generation: ResourceGeneration,
    pub effect_ceiling: &'a EffectCeiling,
}

/// Result of the real route-owner call. Success retains the original owner
/// artifact alongside both provider-neutral projections. Refusal retains the
/// exact typed owner error; when that error contains a completed malformed
/// provider payload, `model_route` carries its exact raw bytes and observed
/// route identity as a malformed outcome.
pub struct DreamerOrientationModelAttempt {
    pub request: ModelRouteRequest,
    pub owner: DreamerOrientationModelOwnerResult,
}

pub enum DreamerOrientationModelOwnerResult {
    /// The real owner returned its candidate-only seal. The `original` value
    /// remains available even when either projection fails.
    Outcome(Box<DreamerOrientationModelOutcome>),
    /// The real owner refused, timed out, cancelled, or reported an unknown
    /// result. No generic composition error replaces this cause.
    Refused {
        error: Box<AdmittedAttemptError>,
        model_route: Option<Result<Box<ModelRouteOutcome>, ModelRouteProjectionError>>,
    },
    /// The admitted cancellation state was observed before invoking the
    /// provider owner, so no provider call or output is claimed.
    CancelledBeforeDispatch {
        state: CancellationState,
        error: Option<Box<AdmittedAttemptError>>,
        model_route: Box<ModelRouteOutcome>,
    },
}

pub struct DreamerOrientationModelOutcome {
    pub original: AdmittedAttemptOutcome,
    pub agent_result: Result<AgentResult, AdmittedOutcomeProjectionError>,
    pub model_route: Result<Box<ModelRouteOutcome>, ModelRouteProjectionError>,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelRouteRequestError {
    #[error(transparent)]
    Contract(#[from] eliot_dreamer_contracts::ContractViolation),
    #[error("job, admission, bundle, and route fingerprints do not share one identity closure")]
    BindingMismatch,
    #[error("selected opaque route ID is not a member of the admitted route denominator")]
    SelectedRouteOutsideDenominator,
    #[error("retained provider context and the admitted read-only prompt differ")]
    PromptBindingMismatch,
    #[error("admitted wall budget or deadline leaves no model execution time")]
    DeadlineExpired,
    #[error("admitted model wall budget is unknown")]
    MissingWallBudget,
    #[error("canonical provider prompt could not be encoded: {0}")]
    CanonicalPrompt(#[from] serde_json::Error),
    #[error("provider prompt byte count does not fit the route receipt")]
    UsageOutOfRange,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelRouteProjectionError {
    #[error("sealed route has no execution-observed physical route")]
    RouteNotObserved {
        disposition: Box<SealedRouteDisposition>,
    },
    #[error("sealed physical route does not carry an observed fingerprint")]
    MissingObservedFingerprint,
    #[error("successful admitted run omitted exact provider output bytes")]
    MissingRawOutput,
    #[error("structured output differs from the exact retained provider bytes")]
    RawOutputMismatch,
    #[error("admitted run contains no structured output")]
    MissingStructuredOutput,
    #[error("owner run status cannot be projected to a Dreamer model disposition")]
    UnsupportedOwnerStatus,
    #[error("original admitted candidate failed owner validation before model projection")]
    OwnerCandidateRejected(#[source] Box<AdmittedAttemptError>),
    #[error(transparent)]
    Contract(#[from] eliot_dreamer_contracts::ContractViolation),
    #[error("measured usage exceeds the route contract's integer range")]
    UsageOutOfRange,
    #[error("the admitted physical route fingerprint could not be projected: {0}")]
    RouteFingerprint(String),
}

#[derive(Serialize)]
struct DreamerModelPrompt<'a> {
    schema_version: u32,
    instructions: &'static str,
    admitted_job_id: &'a str,
    job: &'a DreamJobInput,
    bundle: &'a DreamInputBundle,
}

/// Executes CC-002 through the admitted OpenCode owner after validating the
/// full job/bundle/route/prompt closure. The supplied `ReadOnlyRunRequest` is
/// never rewritten; its prompt must equal the canonical bytes retained by the
/// context owner for this exact job and bundle.
pub async fn run_admitted_model_route(
    client: &OpenCodeClient,
    input: DreamerOrientationModelInput<'_>,
) -> Result<DreamerOrientationModelAttempt, ModelRouteRequestError> {
    let request = build_model_route_request(client, &input)?;
    if let Err(error) = input.admitted.verify_request(input.read_only_request) {
        return Ok(DreamerOrientationModelAttempt {
            request,
            owner: DreamerOrientationModelOwnerResult::Refused {
                error: Box::new(error),
                model_route: None,
            },
        });
    }

    match input
        .admitted
        .verify(input.current_fence, input.runtime_generation)
    {
        Err(error @ AdmittedAttemptError::CancelRequested) if request.cancelled => {
            let model_route = cancelled_outcome(&request, 0, 0);
            model_route.validate_binding(&request)?;
            return Ok(DreamerOrientationModelAttempt {
                request,
                owner: DreamerOrientationModelOwnerResult::CancelledBeforeDispatch {
                    state: input.cancellation,
                    error: Some(Box::new(error)),
                    model_route: Box::new(model_route),
                },
            });
        }
        Err(error) => {
            return Ok(DreamerOrientationModelAttempt {
                request,
                owner: DreamerOrientationModelOwnerResult::Refused {
                    error: Box::new(error),
                    model_route: None,
                },
            });
        }
        Ok(()) if request.cancelled => {
            let model_route = cancelled_outcome(&request, 0, 0);
            model_route.validate_binding(&request)?;
            return Ok(DreamerOrientationModelAttempt {
                request,
                owner: DreamerOrientationModelOwnerResult::CancelledBeforeDispatch {
                    state: input.cancellation,
                    error: None,
                    model_route: Box::new(model_route),
                },
            });
        }
        Ok(()) => {}
    }

    let started = Instant::now();
    let input_bytes = u64::try_from(input.read_only_request.prompt.as_bytes().len())
        .map_err(|_| ModelRouteRequestError::UsageOutOfRange)?;
    let owner_result = client
        .run_admitted_read_only_with_timeout(
            input.admitted,
            input.read_only_request,
            input.current_fence,
            input.runtime_generation,
            Duration::from_millis(request.timeout_ms),
        )
        .await;
    let elapsed_ms = duration_millis(started.elapsed())
        .map_err(|_| ModelRouteRequestError::UsageOutOfRange)?;
    let owner = match owner_result {
        Ok(original) => {
            let agent_result = original.to_agent_result(
                input.admitted,
                input.current_fence,
                input.runtime_generation,
                input.effect_ceiling,
            );
            let candidate_validation = input
                .admitted
                .verify(input.current_fence, input.runtime_generation)
                .and_then(|()| {
                    original.candidate.validate_for_run(
                        input.admitted,
                        &original.run,
                        &original.route,
                    )
                });
            let model_route = match candidate_validation {
                Ok(()) => project_admitted_outcome(
                    &request,
                    &original,
                    input.selected_route_id,
                    input.selected_route_fingerprint,
                    input_bytes,
                    elapsed_ms,
                ),
                Err(error) => Err(ModelRouteProjectionError::OwnerCandidateRejected(Box::new(
                    error,
                ))),
            };
            DreamerOrientationModelOwnerResult::Outcome(Box::new(
                DreamerOrientationModelOutcome {
                    original,
                    agent_result,
                    model_route,
                },
            ))
        }
        Err(error) => {
            let malformed = project_malformed_refusal(
                &request,
                &error,
                input.selected_route_id,
                input_bytes,
                elapsed_ms,
            );
            let model_route = malformed.or_else(|| {
                project_timeout_refusal(&request, &error, elapsed_ms)
            });
            DreamerOrientationModelOwnerResult::Refused {
                error: Box::new(error),
                model_route,
            }
        }
    };
    Ok(DreamerOrientationModelAttempt { request, owner })
}

/// Builds the one canonical provider context for an admitted job/bundle pair.
/// This leaves the semantic job bytes intact while naming the admission's
/// canonical `job_id` separately for the model draft.
pub fn admitted_model_route_context_bytes(
    job: &DreamJobInput,
    admission: &DreamJobAdmission,
    bundle: &DreamInputBundle,
) -> Result<Vec<u8>, ModelRouteRequestError> {
    job.validate()?;
    admission.validate()?;
    bundle.validate()?;
    let expected_task_id = job
        .task_id
        .clone()
        .filter(|task| !task.trim().is_empty())
        .unwrap_or_else(|| format!("{}:task", job.job_id));
    let admitted_job_id = admission.canonical_id();
    if admission.job_class != job.job_class
        || admission.requester.principal != job.requester
        || admission.task_id != expected_task_id
        || admission.scope_id != job.scope_id
        || admission.scope_id != bundle.scope_id
        || admission.task_id != bundle.task_id
        || admission.privacy_profile != job.privacy_profile
        || admission.state_fence != job.state_fence
        || bundle.state_fence != job.state_fence
        || admission.frozen_manifest_digest != bundle.manifest_digest
        || bundle.job_id != admitted_job_id
    {
        return Err(ModelRouteRequestError::BindingMismatch);
    }
    Ok(canonical_json_bytes(&DreamerModelPrompt {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        instructions: DREAMER_MODEL_PROMPT_INSTRUCTIONS,
        admitted_job_id: &bundle.job_id,
        job,
        bundle,
    })?)
}

fn build_model_route_request(
    client: &OpenCodeClient,
    input: &DreamerOrientationModelInput<'_>,
) -> Result<ModelRouteRequest, ModelRouteRequestError> {
    let expected_prompt = admitted_model_route_context_bytes(
        input.job,
        input.admission,
        input.bundle,
    )?;
    if input.admitted.attempt().cancellation != input.cancellation
        || input.admitted.admission().selected_route.as_ref()
            != Some(input.selected_route_fingerprint)
        || input.admitted.binding().route != *input.selected_route_fingerprint
        || input.read_only_request.model != *input.admitted.model()
        || input.read_only_request.model.provider_id != input.selected_route_fingerprint.provider
        || input.read_only_request.model.model_id != input.selected_route_fingerprint.model
    {
        return Err(ModelRouteRequestError::BindingMismatch);
    }
    if !input
        .job
        .allowed_model_routes
        .iter()
        .any(|route| route == input.selected_route_id)
    {
        return Err(ModelRouteRequestError::SelectedRouteOutsideDenominator);
    }

    if expected_prompt.as_slice() != input.retained_context_bytes
        || input.read_only_request.prompt.as_bytes() != input.retained_context_bytes
    {
        return Err(ModelRouteRequestError::PromptBindingMismatch);
    }

    let budget_ms = input
        .admission
        .budget
        .wall_ms
        .ok_or(ModelRouteRequestError::MissingWallBudget)?;
    let job_deadline_ms = u64::try_from(input.job.deadline_ms)
        .map_err(|_| ModelRouteRequestError::DeadlineExpired)?;
    let effective_deadline_ms = input
        .admission
        .deadline_ms
        .map_or(job_deadline_ms, |admitted| admitted.min(job_deadline_ms));
    let remaining_deadline_ms = effective_deadline_ms.saturating_sub(input.now_unix_ms);
    let admitted_timeout_ms = budget_ms.min(remaining_deadline_ms);
    let timeout_ms = u64::try_from(
        client
            .cap_admitted_read_only_timeout(Duration::from_millis(admitted_timeout_ms))
            .as_millis(),
    )
    .map_err(|_| ModelRouteRequestError::UsageOutOfRange)?;
    if timeout_ms == 0 {
        return Err(ModelRouteRequestError::DeadlineExpired);
    }

    let request = ModelRouteRequest {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: input.bundle.job_id.clone(),
        bundle_digest: bundle_digest_of(input.bundle)?,
        state_fence: input.bundle.state_fence.clone(),
        allowed_routes: input.job.allowed_model_routes.clone(),
        timeout_ms,
        cancelled: input.cancellation != CancellationState::NotRequested,
        privacy: ModelRoutePrivacy::parse(&input.admission.privacy_profile)?,
    };
    request.validate_binds_bundle(input.bundle)?;
    Ok(request)
}

fn cancelled_outcome(
    request: &ModelRouteRequest,
    input_bytes: u64,
    wall_ms: u64,
) -> ModelRouteOutcome {
    ModelRouteOutcome {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        bundle_digest: request.bundle_digest.clone(),
        provider_route: None,
        execution: None,
        provider_usage: None,
        disposition: ModelRouteDisposition::Cancelled,
        raw: None,
        draft: None,
        receipt: CostUsageReceipt {
            schema_version: MODEL_ROUTE_SCHEMA_VERSION,
            job_id: request.job_id.clone(),
            input_bytes,
            output_bytes: 0,
            model_calls: 0,
            wall_ms,
        },
        state_fence: request.state_fence.clone(),
        note: "admitted cancellation was observed before provider dispatch".to_owned(),
    }
}

fn project_admitted_outcome(
    request: &ModelRouteRequest,
    original: &AdmittedAttemptOutcome,
    route_id: &str,
    selected_route: &RouteFingerprint,
    input_bytes: u64,
    elapsed_ms: u64,
) -> Result<Box<ModelRouteOutcome>, ModelRouteProjectionError> {
    if !original.route.is_observed() {
        return Err(ModelRouteProjectionError::RouteNotObserved {
            disposition: Box::new(original.route.clone()),
        });
    }
    let physical = original
        .route
        .receipt()
        .ok_or_else(|| ModelRouteProjectionError::RouteNotObserved {
            disposition: Box::new(original.route.clone()),
        })?;
    if physical.requested_route != *selected_route {
        return Err(ModelRouteProjectionError::RouteNotObserved {
            disposition: Box::new(original.route.clone()),
        });
    }
    let observed_route = physical
        .observed_route
        .as_ref()
        .ok_or(ModelRouteProjectionError::MissingObservedFingerprint)?;
    let raw_text = original
        .run
        .extra
        .get(OPENCODE_PROVIDER_RAW_OUTPUT_UTF8_KEY)
        .and_then(Value::as_str)
        .ok_or(ModelRouteProjectionError::MissingRawOutput)?;
    let raw_bytes = raw_text.as_bytes();
    let output = original
        .run
        .output
        .as_ref()
        .ok_or(ModelRouteProjectionError::MissingStructuredOutput)?;
    let decoded_raw = serde_json::from_str::<Value>(raw_text)
        .map_err(|_| ModelRouteProjectionError::RawOutputMismatch)?;
    if &decoded_raw != output {
        return Err(ModelRouteProjectionError::RawOutputMismatch);
    }
    let identity = ModelRouteExecutionIdentity {
        route: route_id.to_owned(),
        provider_id: observed_route.provider.clone(),
        model_id: observed_route.model.clone(),
        harness_id: OPENCODE_DREAMER_HARNESS_ID.to_owned(),
        grounding_route: Some(grounding_route_identity(observed_route)?),
    };
    let usage = provider_usage_from_availability(&original.run.usage);
    let receipt = measured_receipt(request, input_bytes, raw_bytes.len(), 1, elapsed_ms)?;
    let (disposition, raw, draft, note) = match serde_json::from_value::<ModelDraft>(output.clone()) {
        Ok(candidate) if candidate.validate().is_ok() => match original.run.status {
            RunStatus::Succeeded => (
                ModelRouteDisposition::Completed,
                None,
                Some(candidate),
                "admitted provider response produced a validated model draft".to_owned(),
            ),
            RunStatus::Partial => (
                ModelRouteDisposition::Partial,
                Some(raw_provider_output(request, route_id, raw_bytes)),
                Some(candidate),
                "admitted provider response retained a draft with partial disposition".to_owned(),
            ),
            RunStatus::Failed | RunStatus::Cancelled | RunStatus::Unknown => {
                return Err(ModelRouteProjectionError::UnsupportedOwnerStatus);
            }
        },
        _ => (
            ModelRouteDisposition::Malformed,
            Some(raw_provider_output(request, route_id, raw_bytes)),
            None,
            "provider payload did not satisfy the Dreamer ModelDraft schema; exact bytes retained"
                .to_owned(),
        ),
    };
    let outcome = ModelRouteOutcome {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        bundle_digest: request.bundle_digest.clone(),
        provider_route: Some(route_id.to_owned()),
        execution: Some(identity),
        provider_usage: Some(usage),
        disposition,
        raw,
        draft,
        receipt,
        state_fence: request.state_fence.clone(),
        note,
    };
    outcome.validate_binding(request)?;
    Ok(Box::new(outcome))
}

fn project_malformed_refusal(
    request: &ModelRouteRequest,
    error: &AdmittedAttemptError,
    route_id: &str,
    input_bytes: u64,
    elapsed_ms: u64,
) -> Option<Result<Box<ModelRouteOutcome>, ModelRouteProjectionError>> {
    let AdmittedAttemptError::Run(OpenCodeRunError::MalformedStructuredOutput(malformed)) = error
    else {
        return None;
    };
    Some(project_malformed_provider_output(
        request,
        route_id,
        input_bytes,
        &malformed.observed_model,
        &malformed.raw_output,
        malformed.usage.as_ref(),
        elapsed_ms,
    ))
}

fn project_timeout_refusal(
    request: &ModelRouteRequest,
    error: &AdmittedAttemptError,
    elapsed_ms: u64,
) -> Option<Result<Box<ModelRouteOutcome>, ModelRouteProjectionError>> {
    let AdmittedAttemptError::Run(OpenCodeRunError::Timeout {
        phase: "admitted pre-dispatch",
    }) = error
    else {
        return None;
    };
    let outcome = ModelRouteOutcome {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        bundle_digest: request.bundle_digest.clone(),
        provider_route: None,
        execution: None,
        provider_usage: None,
        disposition: ModelRouteDisposition::Timeout,
        raw: None,
        draft: None,
        receipt: CostUsageReceipt {
            schema_version: MODEL_ROUTE_SCHEMA_VERSION,
            job_id: request.job_id.clone(),
            input_bytes: 0,
            output_bytes: 0,
            model_calls: 0,
            wall_ms: elapsed_ms,
        },
        state_fence: request.state_fence.clone(),
        note: "admitted model deadline elapsed before provider prompt dispatch".to_owned(),
    };
    Some(
        outcome
            .validate_binding(request)
            .map(|()| Box::new(outcome))
            .map_err(Into::into),
    )
}

fn project_malformed_provider_output(
    request: &ModelRouteRequest,
    route_id: &str,
    input_bytes: u64,
    observed_model: &ModelSelection,
    raw_output: &str,
    usage: Option<&UsageTelemetry>,
    elapsed_ms: u64,
) -> Result<Box<ModelRouteOutcome>, ModelRouteProjectionError> {
    let identity = ModelRouteExecutionIdentity {
        route: route_id.to_owned(),
        provider_id: observed_model.provider_id.clone(),
        model_id: observed_model.model_id.clone(),
        harness_id: OPENCODE_DREAMER_HARNESS_ID.to_owned(),
        // The malformed refusal retained provider/model observation but did
        // not produce the owner's validated physical route receipt. Never
        // promote the requested fingerprint to an observed grounding route.
        grounding_route: None,
    };
    let raw = raw_provider_output(request, route_id, raw_output.as_bytes());
    let outcome = ModelRouteOutcome {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        bundle_digest: request.bundle_digest.clone(),
        provider_route: Some(route_id.to_owned()),
        execution: Some(identity),
        provider_usage: Some(provider_usage_from_telemetry(usage)),
        disposition: ModelRouteDisposition::Malformed,
        raw: Some(raw),
        draft: None,
        receipt: measured_receipt(
            request,
            input_bytes,
            raw_output.as_bytes().len(),
            1,
            elapsed_ms,
        )?,
        state_fence: request.state_fence.clone(),
        note: "provider returned malformed structured JSON; exact bytes retained".to_owned(),
    };
    outcome.validate_binding(request)?;
    Ok(Box::new(outcome))
}

fn raw_provider_output(
    request: &ModelRouteRequest,
    route_id: &str,
    raw_bytes: &[u8],
) -> eliot_dreamer_contracts::RawProviderOutput {
    eliot_dreamer_contracts::RawProviderOutput {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        provider_route: route_id.to_owned(),
        raw_bytes: raw_bytes.to_vec(),
        output_digest: sha256_hex(raw_bytes),
    }
}

fn grounding_route_identity(
    observed_route: &RouteFingerprint,
) -> Result<RouteIdentity, ModelRouteProjectionError> {
    let owner_fingerprint = route_fingerprint_digest_for(observed_route)
        .map_err(|error| ModelRouteProjectionError::RouteFingerprint(error.to_string()))?;
    let mut identity = RouteIdentity {
        provider: observed_route.provider.clone(),
        model: observed_route.model.clone(),
        // The admitted route owner has no separate semantic revision field.
        // Its original full execution-configuration fingerprint is the
        // content-addressed revision retained here.
        route_revision: owner_fingerprint.as_str().to_owned(),
        fingerprint: String::new(),
    };
    identity.fingerprint = route_fingerprint(&identity)?;
    Ok(identity)
}

fn provider_usage_from_availability(availability: &UsageAvailability) -> ModelRouteProviderUsage {
    match availability.state {
        AvailabilityState::Available => provider_usage_from_telemetry(availability.value.as_ref()),
        AvailabilityState::Unavailable => ModelRouteProviderUsage {
            state: ModelRouteUsageState::Unavailable,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            provider_cost_usd: None,
            unavailable_reason: availability.unavailable_reason.clone(),
        },
    }
}

fn provider_usage_from_telemetry(usage: Option<&UsageTelemetry>) -> ModelRouteProviderUsage {
    match usage {
        Some(usage) => ModelRouteProviderUsage {
            state: ModelRouteUsageState::Available,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
            provider_cost_usd: usage.cost_usd.map(|cost| cost.to_string()),
            unavailable_reason: None,
        },
        None => ModelRouteProviderUsage {
            state: ModelRouteUsageState::Unavailable,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            provider_cost_usd: None,
            unavailable_reason: Some("OpenCode response did not include provider usage".to_owned()),
        },
    }
}

fn measured_receipt(
    request: &ModelRouteRequest,
    input_bytes: u64,
    output_bytes: usize,
    model_calls: u64,
    wall_ms: u64,
) -> Result<CostUsageReceipt, ModelRouteProjectionError> {
    let output_bytes = u64::try_from(output_bytes)
        .map_err(|_| ModelRouteProjectionError::UsageOutOfRange)?;
    let receipt = CostUsageReceipt {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        input_bytes,
        output_bytes,
        model_calls,
        wall_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn duration_millis(duration: Duration) -> Result<u64, ModelRouteProjectionError> {
    u64::try_from(duration.as_millis()).map_err(|_| ModelRouteProjectionError::UsageOutOfRange)
}
