//! Runtime CC-002 model-route producer for admitted Dreamer jobs.
//!
//! [`ModelRouteRequest`](eliot_dreamer_contracts::ModelRouteRequest) and
//! [`ModelRouteOutcome`](eliot_dreamer_contracts::ModelRouteOutcome) are the
//! owner-neutral boundary the contract module deliberately leaves to "the
//! runtime": route choice, timeout/cancellation enforcement, and the returned
//! outcome all happen here, in the composition root that already holds the
//! Kernel-issued claim and the admitted pair. This binary imports no provider
//! SDK and starts no provider process, so the only terminal disposition it can
//! report honestly is the one that needs no provider round trip: a call the
//! Kernel has already proved cancelled before dispatch.
//!
//! Why nothing else is constructed here. `Completed`, `Partial`, and
//! `Malformed` each require a real provider round trip and a real
//! [`CostUsageReceipt`](eliot_dreamer_contracts::CostUsageReceipt) of observed
//! bytes and calls. This binary performs no provider call, so there is no
//! observation to report: a receipt for it would be invented evidence, which
//! the cognitive contract challenge forbids. `Timeout` is equally unavailable,
//! because it requires a measured overrun against `timeout_ms` and this binary
//! records no start instant for the route. So when the Kernel has proved no
//! cancellation, the honest answer is no outcome at all
//! ([`None`]), and the pulse stays on its typed blocked path naming the absent
//! provider execution.
//!
//! Every field below is derived from admitted material or from a Kernel-proved
//! observation, and both shapes are proved with the real owner validators
//! ([`ModelRouteRequest::validate_binds_bundle`](eliot_dreamer_contracts::ModelRouteRequest::validate_binds_bundle)
//! and [`ModelRouteOutcome::validate_binding`](eliot_dreamer_contracts::ModelRouteOutcome::validate_binding))
//! rather than by a local restatement of their rules.

use eliot_dreamer_contracts::{
    CostUsageReceipt, DreamInputBundle, MODEL_ROUTE_SCHEMA_VERSION, ModelRouteDisposition,
    ModelRouteOutcome, ModelRoutePrivacy, ModelRouteRequest, bundle_digest_of,
};

use crate::admitted_material::admission_of;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Stable refusal when the admitted pair pins no usable route denominator or
/// timeout for the CC-002 request.
///
/// The owner validator's own static field names are not forwarded: the caller
/// maps this to the same bounded `InvalidAdmission` code every other admitted
/// derivation uses, so a malformed route set cannot be told apart from any
/// other refused admitted binding at the process boundary.
const ROUTE_REQUEST_INVALID: &str = "admitted model-route request binding invalid";
/// Stable refusal when the constructed outcome is not bound to its request.
const ROUTE_OUTCOME_INVALID: &str = "admitted model-route outcome binding invalid";
/// Terminal note recorded on a call the Kernel proved cancelled before
/// dispatch. It states what was and was not observed rather than asserting a
/// provider result.
const CANCELLED_NOTE: &str =
    "cancelled before dispatch on a Kernel-proved cancellation; no provider call was performed";

/// One admitted CC-002 route: the request the runtime admitted and the outcome
/// it honestly observed.
///
/// This is an owned value the caller holds for the life of one admitted pulse,
/// which is what lets [`ProductionOrientationInputs`](crate::production_orientation::ProductionOrientationInputs)
/// borrow `&ModelRouteOutcome` without a second lifetime scheme. It is the same
/// shape as the Curation
/// [`CurationExecutionCarrier`](crate::dispatch_stage::CurationExecutionCarrier):
/// owner values assembled once per admission, then borrowed by the composer.
pub(crate) struct ModelRouteExecution {
    /// The admitted request: route denominator, timeout, privacy, fence.
    pub request: ModelRouteRequest,
    /// The observed outcome. Never synthesized.
    pub outcome: ModelRouteOutcome,
}

/// Builds the admitted CC-002 route for one pulse.
///
/// `cancelled` is the caller's Kernel-proved cancellation observation (the
/// port's own claimed-job view, read before the pipeline runs). When it is
/// false this binary has no honest outcome to report and returns [`None`];
/// when it is true the route is admitted against the exact bundle and the
/// pre-dispatch cancellation is recorded as the terminal disposition.
///
/// The request is built from admitted material only: the canonical bundle
/// identity and digest, the bundle's own fence, the admitted route
/// denominator, the admitted wall budget as `timeout_ms`, and the admitted
/// privacy profile. Nothing is defaulted and no bound is widened.
pub(crate) fn model_route_of(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    bundle: &DreamInputBundle,
    cancelled: bool,
) -> Result<Option<ModelRouteExecution>, DreamerError> {
    if !cancelled {
        return Ok(None);
    }
    let admitted = admission_of(admission, job)?;
    let timeout_ms = admitted
        .budget
        .wall_ms
        .ok_or(DreamerError::InvalidAdmission(ROUTE_REQUEST_INVALID))?;
    let request = ModelRouteRequest {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: bundle.job_id.clone(),
        bundle_digest: bundle_digest_of(bundle)
            .map_err(|_| DreamerError::InvalidAdmission(ROUTE_REQUEST_INVALID))?,
        state_fence: bundle.state_fence.clone(),
        allowed_routes: job.allowed_model_routes.clone(),
        timeout_ms,
        cancelled,
        privacy: ModelRoutePrivacy::parse(&admitted.privacy_profile)
            .map_err(|_| DreamerError::InvalidAdmission(ROUTE_REQUEST_INVALID))?,
    };
    // The owner validator enforces the route denominator bound, the route
    // length bound, and the timeout range; this binary restates none of them.
    request
        .validate_binds_bundle(bundle)
        .map_err(|_| DreamerError::InvalidAdmission(ROUTE_REQUEST_INVALID))?;
    let outcome = ModelRouteOutcome {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: request.job_id.clone(),
        bundle_digest: request.bundle_digest.clone(),
        // Cancelled/timeout outcomes must not name a route, and none was
        // chosen: the call was abandoned before any route could be taken.
        provider_route: None,
        disposition: ModelRouteDisposition::Cancelled,
        // No provider was contacted, so there is no raw payload and no draft.
        raw: None,
        draft: None,
        // Every dimension is zero because every dimension counts provider work:
        // no bytes were sent, none were received, and no call was made. Zero is
        // the observed value for a call that did not run, not a filled-in
        // placeholder.
        receipt: CostUsageReceipt {
            schema_version: MODEL_ROUTE_SCHEMA_VERSION,
            job_id: request.job_id.clone(),
            input_bytes: 0,
            output_bytes: 0,
            model_calls: 0,
            wall_ms: 0,
        },
        state_fence: request.state_fence.clone(),
        note: CANCELLED_NOTE.to_owned(),
    };
    // Binds job, bundle digest, fence, and the pre-call cancellation rule to
    // the admitted request, so the terminal disposition is proved against the
    // exact denominator rather than asserted.
    outcome
        .validate_binding(&request)
        .map_err(|_| DreamerError::InvalidAdmission(ROUTE_OUTCOME_INVALID))?;
    Ok(Some(ModelRouteExecution { request, outcome }))
}
