//! Governor composition edge for the admitted Orientation product.
//!
//! The caller supplies original native owner records. This module sequences
//! the mandatory Smart owner runner and joins its retained semantics to the
//! packet projector; it does not acquire, decode, default, or reissue owners.

use eliot_context_contracts::CanonicalProjectionSet;
use eliot_dreamer_contracts::{
    AdmittedOrientationJob, DreamInputBundle, ModelDraft, ModelRouteOutcome, ModelRouteRequest,
    ValidatedCandidate,
};
use eliot_protocol::dreamer_job::DurableJobRuntimeOwnerExecutionInput;
use eliot_dreamer_orientation::{
    CurrentEpistemicPositionHandle, OrientationOwnerProjection,
    OrientationError, OrientationPacketCandidate, OrientationPolicy, OrientationSemanticView,
    orientation_owner_inputs::{
        MandatoryStageRun, OrientationOwnerInputs, run_mandatory_stages,
    },
    projection::build_projection_with_owners,
    pulse::PulseStageId,
};

/// Original admitted records required to compose one production Orientation
/// product. Every reference must come from its owning admission/read path.
pub struct OrientationProductOwnerInput<'a> {
    /// Original admitted Orientation job and its evidence denominator.
    pub admitted_job: &'a AdmittedOrientationJob,
    /// Exact bounded material bundle admitted for the job.
    pub bundle: &'a DreamInputBundle,
    /// Existing receipt-bound candidate passed to the packet owner.
    pub validated_candidate: &'a ValidatedCandidate,
    /// Original sealed packet policy.
    pub policy: &'a OrientationPolicy,
    /// Original model-route request returned by CC-002.
    pub model_request: &'a ModelRouteRequest,
    /// Exact draft retained by the completed model owner result.
    pub model_draft: &'a ModelDraft,
    /// Original model-route owner outcome returned by CC-002.
    pub model_outcome: &'a ModelRouteOutcome,
    /// Complete canonical projection set returned by CC-004.
    pub projections: &'a CanonicalProjectionSet,
    /// Whole original runtime-owner publication retained by the claimed job.
    pub runtime_owner_input: &'a DurableJobRuntimeOwnerExecutionInput,
    /// Original Governor-issued epistemic handles for the packet.
    pub cep_handles: &'a [CurrentEpistemicPositionHandle],
    /// Exact native inputs retained for the nine mandatory stage owners, or
    /// their original missing/stale source dispositions.
    pub owner_stages: OrientationProductStageSources<'a>,
}

/// Native mandatory-stage inputs or explicit source dispositions.
pub enum OrientationProductStageSources<'a> {
    /// All nine original typed owner inputs are available.
    Ready(&'a OrientationOwnerInputs<'a>),
    /// These mandatory owner inputs have no current original source.
    Missing(Vec<PulseStageId>),
    /// These owner inputs are present only at an older state snapshot.
    Stale(Vec<PulseStageId>),
}

/// Retained product result. Source absence and owner refusal remain distinct.
pub enum OrientationProductOwnerResult {
    /// One or more mandatory owner inputs are absent from the current source set.
    Missing(Vec<PulseStageId>),
    /// One or more mandatory owner inputs are stale for this execution.
    Stale(Vec<PulseStageId>),
    /// Boundary owner values failed exact binding before stages could run.
    BoundaryRefused(OrientationError),
    /// Retained stage prefix and the packet result, if all mandatory stages ran.
    Executed {
        /// Native outputs and commitments retained in denominator order.
        mandatory_stages: Box<MandatoryStageRun>,
        /// `None` means a mandatory owner refused or blocked before projection.
        packet: Result<Option<Box<OrientationPacketCandidate>>, OrientationError>,
    },
}

/// Executes the native mandatory owners once and projects only a complete run.
pub fn compose_admitted_orientation_product(
    input: OrientationProductOwnerInput<'_>,
) -> OrientationProductOwnerResult {
    let owner_stages = match input.owner_stages {
        OrientationProductStageSources::Ready(stages) => stages,
        OrientationProductStageSources::Missing(missing) => {
            return if valid_unavailable_stage_list(&missing) {
                OrientationProductOwnerResult::Missing(missing)
            } else {
                OrientationProductOwnerResult::BoundaryRefused(OrientationError::Invalid(
                    "missing stage source list",
                ))
            };
        }
        OrientationProductStageSources::Stale(stale) => {
            return if valid_unavailable_stage_list(&stale) {
                OrientationProductOwnerResult::Stale(stale)
            } else {
                OrientationProductOwnerResult::BoundaryRefused(OrientationError::Invalid(
                    "stale stage source list",
                ))
            };
        }
    };
    if let Err(error) = validate_product_boundaries(&input) {
        return OrientationProductOwnerResult::BoundaryRefused(error);
    }
    let mandatory_stages = run_mandatory_stages(
        owner_stages,
        input.model_draft,
        input.bundle,
        input.model_outcome,
        input.projections,
    );
    if mandatory_stages.failure.is_some() {
        return OrientationProductOwnerResult::Executed {
            mandatory_stages: Box::new(mandatory_stages),
            packet: Ok(None),
        };
    }

    let Some(semantics): Option<OrientationSemanticView<'_>> =
        mandatory_stages.outputs.projection_view()
    else {
        return OrientationProductOwnerResult::Executed {
            mandatory_stages: Box::new(mandatory_stages),
            packet: Ok(None),
        };
    };
    let owners = OrientationOwnerProjection {
        model_request: input.model_request,
        model_outcome: input.model_outcome,
        projections: input.projections,
        runtime_owner_input: input.runtime_owner_input,
        semantics,
    };
    let packet = build_projection_with_owners(
        input.admitted_job,
        input.validated_candidate,
        input.bundle,
        input.cep_handles,
        input.policy,
        &owners,
    )
    .map(Box::new)
    .map(Some);

    OrientationProductOwnerResult::Executed {
        mandatory_stages: Box::new(mandatory_stages),
        packet,
    }
}

fn valid_unavailable_stage_list(stages: &[PulseStageId]) -> bool {
    !stages.is_empty()
        && stages
            .iter()
            .all(|stage| *stage != PulseStageId::Packet)
        && stages
            .iter()
            .enumerate()
            .all(|(index, stage)| !stages[..index].contains(stage))
}

fn validate_product_boundaries(
    input: &OrientationProductOwnerInput<'_>,
) -> Result<(), OrientationError> {
    input.admitted_job.validate_for(input.bundle)?;
    input.policy.validate()?;
    input
        .validated_candidate
        .validate_binding()
        .map_err(|_| OrientationError::Binding("validated candidate"))?;
    input
        .model_request
        .validate_binds_bundle(input.bundle)
        .map_err(|_| OrientationError::Binding("model request bundle"))?;
    input
        .model_outcome
        .validate()
        .map_err(|_| OrientationError::Binding("model outcome"))?;
    input
        .runtime_owner_input
        .validate()
        .map_err(|_| OrientationError::Binding("runtime owner source"))?;

    if input.validated_candidate.job != input.admitted_job.job
        || input.validated_candidate.bundle != *input.bundle
        || input.validated_candidate.model != *input.model_draft
        || input.model_outcome.draft.as_ref() != Some(input.model_draft)
        || input.model_request.job_id != input.model_outcome.job_id
        || input.model_request.bundle_digest != input.model_outcome.bundle_digest
        || input.model_request.state_fence != input.model_outcome.state_fence
        || input.model_request.job_id != input.bundle.job_id
        || input.model_request.state_fence != input.bundle.state_fence
    {
        return Err(OrientationError::Binding("model and candidate closure"));
    }
    for handle in input.cep_handles {
        handle.validate_for(&input.admitted_job.job)?;
        handle.validate_material(input.bundle)?;
    }
    Ok(())
}
