//! Cognitive Orientation Product Pulse composer (`D3A_ORIENTATION_PULSE_01`).
//!
//! Issue #41 closes CC-002 (model-route adapter) and CC-004 (canonical
//! context projections) for the Orientation pulse. The two boundaries exist as
//! versioned owner-neutral contracts; this module is the Smart-side composer
//! that turns one admitted Orientation job plus those boundary values into the
//! end-to-end pulse: classification, cue activation, Current Epistemic
//! Position, Active Understanding View, claim-grounded rivals/probes, context
//! candidates, and the candidate-only Orientation packet.
//!
//! Every stage runs through its named owner entry point; this composer owns no
//! stage semantics and duplicates no state machine:
//!
//! - classification: `eliot_dreamer_classification::classify`;
//! - cue activation: `eliot_cue_activation::evaluate_activation`;
//! - Current Epistemic Position: `eliot_epistemic::resolve`;
//! - Active Understanding View:
//!   `eliot_context_assembly::assemble_active_view`;
//! - claim grounding:
//!   `eliot_dreamer_claim_grounding::ground_draft_with_controls`;
//! - rivals: `eliot_dreamer_rival_model::structure_rival_models`;
//! - conflict analysis: `eliot_dreamer_conflict_analysis::analyze_conflict`;
//! - probes: `eliot_dreamer_probe_plan::plan_discriminative_probes`;
//! - candidates:
//!   `eliot_context_candidates::construct_context_candidates_with_canonical`;
//! - packet: `eliot_dreamer_orientation::build_projection`.
//!
//! Fail-closed sequencing: the CC-002 outcome and CC-004 projection set are
//! validated first (schema, bundle-digest binding, job binding, mutual fence
//! compatibility). A stage whose caller-supplied inputs are absent records an
//! explicit pending disposition and never blocks the packet; a stage whose
//! inputs are present but whose owner refuses fails the whole pulse, so a
//! partial pulse is never thinned into a packet silently. Error payloads are
//! bounded static fields; nothing secret flows.
//!
//! Binding notes: the resolved epistemic position is resolver policy output,
//! never a Governor-issued handle, so it is reported as its own stage and the
//! packet keeps receiving only caller-supplied
//! [`CurrentEpistemicPositionHandle`](eliot_dreamer_orientation::CurrentEpistemicPositionHandle)
//! values (G5: locally built envelopes would be self-issued authority). The
//! rival stage consumes the admitted-contracts position supplied by its owner,
//! not the resolver output, because the two vocabularies are deliberately
//! distinct.

use eliot_context_assembly::{ActiveUnderstandingViewResult, AssemblyPolicy, assemble_active_view};
use eliot_context_candidates::{
    AttentionInput, CandidatePolicy, CandidateRequest, CanonicalProjectionInput,
    ContextCandidateSetResult, CueInput, EpistemicInput, EvidenceInput, MemberMeasurement,
    construct_context_candidates_with_canonical,
};
use eliot_context_contracts::{
    AdmittedContextSet, CanonicalProjectionSet, ContextError, ContextRecipe, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_contracts::StateFence;
use eliot_cue_activation::{ActivationProfile, CueActivationEvaluation, evaluate_activation};
use eliot_cue_contracts::{ActivationRequest, CueSnapshotBuildCandidate};
use eliot_dreamer_claim_grounding::{GroundingRequest, ground_draft_with_controls};
use eliot_dreamer_classification::{ClassificationPolicy, ClassificationResult, classify};
use eliot_dreamer_conflict_analysis::{
    ConflictAnalysisCandidate, ConflictAnalysisPolicy, ConflictSupplements, analyze_conflict,
};
use eliot_dreamer_contracts::grounding::GroundedDreamDraft as GroundedClaimDraft;
use eliot_dreamer_contracts::{
    ClassificationInput, CurationAcceptanceCtx, DreamInputBundle, GroundedDreamDraft,
    ModelRouteDisposition, ModelRouteOutcome, ValidatedCandidate, ValidatedCurationItem,
    ValidatedDreamDraft, ValidatedGroundingCandidate, bundle_digest_of,
};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, CurrentEpistemicPositionHandle, OrientationError, OrientationPolicy,
    projection::{OrientationPacketCandidate, build_projection},
};
use eliot_dreamer_probe_plan::{ProbePlan, ProbePlanParams, plan_discriminative_probes};
use eliot_dreamer_rival_model::{
    RivalModelSet as StructuredRivalModelSet, RivalPolicy, structure_rival_models,
};
use eliot_epistemic::{
    CurrentEpistemicPosition as ResolvedEpistemicPosition, PositionRequest, resolve,
};
use eliot_epistemic_contracts::{ConflictSet, CurrentEpistemicPosition as AdmittedPosition};

/// Caller-supplied classification stage inputs (owner-built, never inferred).
pub(crate) struct ClassificationStage<'a> {
    /// Frozen classification input bound to the execution policy.
    pub input: &'a ClassificationInput,
    /// Governor acceptance context the selector runs under.
    pub context: &'a CurationAcceptanceCtx<'a>,
    /// Execution policy the input digest binds.
    pub policy: &'a ClassificationPolicy,
}

/// Caller-supplied cue-activation stage inputs (owner-built, never inferred).
pub(crate) struct CueActivationStage<'a> {
    /// Immutable cue-snapshot build candidate under evaluation.
    pub candidate: &'a CueSnapshotBuildCandidate,
    /// Bounded activation request.
    pub request: &'a ActivationRequest,
    /// Caller-supplied versioned numerical profile.
    pub profile: &'a ActivationProfile,
}

/// Caller-supplied understanding stage inputs (owner-built, never inferred).
pub(crate) struct UnderstandingStage<'a, F> {
    /// Exact admitted context set to project.
    pub admitted: &'a AdmittedContextSet,
    /// Recipe the admitted set must satisfy.
    pub recipe: &'a ContextRecipe,
    /// Quality scorecard bound to the admitted binding.
    pub quality: QualityScorecard,
    /// Caller-owned immutable assembly parameters.
    pub policy: &'a AssemblyPolicy,
    /// Route measurement invoked once over the canonical payload bytes.
    pub measure: F,
}

/// Caller-supplied rival stage inputs (owner-built, never inferred).
pub(crate) struct RivalStage<'a> {
    /// Grounded input bundle the rivals bind against.
    pub bundle: &'a DreamInputBundle,
    /// Validated grounding candidate carrying the rival declarations.
    pub validated_draft: &'a ValidatedGroundingCandidate,
    /// Admitted current position the rivals bind against.
    pub current_position: &'a AdmittedPosition,
    /// Local rival-structuring policy.
    pub policy: &'a RivalPolicy,
}

/// Caller-supplied conflict-analysis stage inputs (owner-built, never inferred).
pub(crate) struct ConflictStage<'a> {
    /// Validated curation item under analysis.
    pub item: &'a ValidatedCurationItem,
    /// Validator-bound draft under analysis.
    pub draft: &'a ValidatedDreamDraft,
    /// Claim-grounded draft under analysis.
    pub grounded: &'a GroundedDreamDraft,
    /// Admitted conflict set under analysis.
    pub conflict_set: &'a ConflictSet,
    /// Expected receipts and supplement bounds.
    pub supplements: &'a ConflictSupplements,
    /// Conflict-analysis policy.
    pub policy: &'a ConflictAnalysisPolicy,
}

/// Caller-supplied candidate stage inputs (owner-built, never inferred).
///
/// The CC-004 projection set itself travels on the request boundary, not here:
/// this stage runs only when both the boundary set and these inputs are
/// present, so candidates always derive from the validated shared set.
pub(crate) struct CandidateStage<'a> {
    /// Candidate request envelope.
    pub request: &'a CandidateRequest,
    /// Context recipe fixing the denominator.
    pub recipe: &'a ContextRecipe,
    /// Supplied measurements keyed by derived member identity.
    pub measurements: &'a [MemberMeasurement],
    /// Explicit attention/conflict projection (read, never produced here).
    pub attention_and_conflicts: Option<&'a AttentionInput>,
    /// Explicit epistemic projection (read, never produced here).
    pub epistemic_position: Option<&'a EpistemicInput>,
    /// Explicit cue-activation projection (read, never produced here).
    pub cue_activation_result: Option<&'a CueInput>,
    /// Explicit evidence projection (read, never produced here).
    pub evidence: Option<&'a EvidenceInput>,
    /// Candidate policy.
    pub policy: &'a CandidatePolicy,
}

/// One pulse stage outcome: either executed with owner output, or explicitly
/// pending with the static reason naming the missing owner value.
pub(crate) struct PulseStage<T> {
    /// Whether the owner entry point ran for this pulse.
    pub executed: bool,
    /// Static reason naming the missing owner value when not executed.
    pub pending_reason: Option<&'static str>,
    /// Owner output, present exactly when executed.
    pub output: Option<T>,
}

impl<T> PulseStage<T> {
    fn executed(output: T) -> Self {
        Self {
            executed: true,
            pending_reason: None,
            output: Some(output),
        }
    }

    fn pending(reason: &'static str) -> Self {
        Self {
            executed: false,
            pending_reason: Some(reason),
            output: None,
        }
    }
}

/// Complete Orientation pulse request: CC-002/CC-004 boundary values, the
/// always-required packet inputs, and optional per-stage owner inputs.
pub(crate) struct OrientationPulseRequest<'a, F> {
    /// CC-002 routed model outcome the pulse accounts for.
    pub model_outcome: Option<&'a ModelRouteOutcome>,
    /// CC-004 canonical projection set the pulse consumes.
    pub projections: Option<&'a CanonicalProjectionSet>,
    /// Admitted Orientation job.
    pub admitted_job: &'a AdmittedOrientationJob,
    /// Receipt-bound v1 validated candidate.
    pub validated_candidate: &'a ValidatedCandidate,
    /// Bounded bundle the packet projects.
    pub bundle: &'a DreamInputBundle,
    /// Governor-resolved epistemic-position handles for the packet.
    pub cep_handles: &'a [CurrentEpistemicPositionHandle],
    /// Sealed orientation policy.
    pub policy: &'a OrientationPolicy,
    /// Classification stage inputs.
    pub classification: Option<ClassificationStage<'a>>,
    /// Cue-activation stage inputs.
    pub cue_activation: Option<CueActivationStage<'a>>,
    /// Epistemic resolution request over admitted records.
    pub epistemic: Option<&'a PositionRequest>,
    /// Understanding stage inputs with the route measurement.
    pub understanding: Option<UnderstandingStage<'a, F>>,
    /// Claim-grounding request (cloned; the owner takes owned input).
    pub grounding: Option<&'a GroundingRequest>,
    /// Rival-structuring stage inputs.
    pub rivals: Option<RivalStage<'a>>,
    /// Conflict-analysis stage inputs.
    pub conflict: Option<ConflictStage<'a>>,
    /// Discriminative probe-plan parameters.
    pub probes: Option<ProbePlanParams<'a>>,
    /// Context-candidate stage inputs.
    pub candidates: Option<CandidateStage<'a>>,
}

impl<T> PulseStage<T> {
    /// Production invariant for one non-packet stage: not executed, with an
    /// explicit pending reason and no output.
    fn expect_pending(&self) {
        debug_assert!(!self.executed);
        debug_assert!(self.pending_reason.is_some());
        debug_assert!(self.output.is_none());
    }
}

/// Complete Orientation pulse: one disposition per stage plus the packet.
pub(crate) struct OrientationPulse {
    /// Classification stage outcome.
    pub classification: PulseStage<ClassificationResult>,
    /// Cue-activation stage outcome.
    pub cue_activation: PulseStage<CueActivationEvaluation>,
    /// Current Epistemic Position stage outcome.
    pub epistemic_position: PulseStage<ResolvedEpistemicPosition>,
    /// Active Understanding View stage outcome.
    pub understanding: PulseStage<ActiveUnderstandingViewResult>,
    /// Claim-grounding stage outcome.
    pub grounding: PulseStage<GroundedClaimDraft>,
    /// Rival-structuring stage outcome.
    pub rivals: PulseStage<StructuredRivalModelSet>,
    /// Conflict-analysis stage outcome.
    pub conflict: PulseStage<ConflictAnalysisCandidate>,
    /// Probe-plan stage outcome.
    pub probes: PulseStage<ProbePlan>,
    /// Context-candidate stage outcome.
    pub candidates: PulseStage<ContextCandidateSetResult>,
    /// Candidate-only Orientation packet.
    pub packet: OrientationPacketCandidate,
}

/// Fail-closed pulse error with bounded static refusal fields.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PulseError {
    /// CC-002/CC-004 boundary validation failed; carries the static field.
    #[error("pulse boundary refused: {0}")]
    Boundary(&'static str),
    /// Classification owner refused.
    #[error("pulse classification refused")]
    Classification,
    /// Cue-activation owner refused.
    #[error("pulse cue activation refused")]
    CueActivation,
    /// Epistemic resolver refused.
    #[error("pulse epistemic position refused")]
    Epistemic,
    /// Understanding assembler refused.
    #[error("pulse understanding view refused")]
    Understanding,
    /// Claim-grounding owner refused.
    #[error("pulse claim grounding refused")]
    Grounding,
    /// Rival-structuring owner refused.
    #[error("pulse rival models refused")]
    Rivals,
    /// Conflict-analysis owner refused.
    #[error("pulse conflict analysis refused")]
    Conflict,
    /// Probe planner refused.
    #[error("pulse probe plan refused")]
    Probes,
    /// Context-candidate mapper refused.
    #[error("pulse context candidates refused")]
    Candidates,
    /// Orientation projector refused; maps through the existing denial table.
    #[error("pulse packet refused")]
    Packet(#[from] OrientationError),
}

impl PulseError {
    /// Converts a production-pulse error back to the projector error.
    ///
    /// The production path supplies no stage inputs and no boundary values, so
    /// only the packet stage can fail there; any other variant indicates a
    /// wiring defect and maps to the internal projector failure.
    pub(crate) fn into_orientation_error(self) -> OrientationError {
        match self {
            Self::Packet(error) => error,
            Self::Boundary(field) => OrientationError::Binding(field),
            Self::Classification
            | Self::CueActivation
            | Self::Epistemic
            | Self::Understanding
            | Self::Grounding
            | Self::Rivals
            | Self::Conflict
            | Self::Probes
            | Self::Candidates => OrientationError::Internal,
        }
    }
}

/// Measurement closure used when the understanding stage is absent.
///
/// The concrete `fn` type pins the request generic parameter; it is never
/// invoked because the stage is `None`.
type NoMeasurement = fn(&[u8]) -> Result<SerializedContextMeasurement, ContextError>;

fn no_understanding<'a>() -> Option<UnderstandingStage<'a, NoMeasurement>> {
    None
}

fn fences_compatible(left: &StateFence, right: &StateFence) -> bool {
    left.is_compatible_with(right) && right.is_compatible_with(left)
}

fn check_model_boundary(
    outcome: &ModelRouteOutcome,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    outcome
        .validate()
        .map_err(|_| PulseError::Boundary("model outcome"))?;
    if !matches!(
        outcome.disposition,
        ModelRouteDisposition::Completed | ModelRouteDisposition::Partial
    ) {
        return Err(PulseError::Boundary("model outcome disposition"));
    }
    let digest =
        bundle_digest_of(bundle).map_err(|_| PulseError::Boundary("model bundle digest"))?;
    if digest != outcome.bundle_digest {
        return Err(PulseError::Boundary("model bundle digest"));
    }
    if outcome.job_id != bundle.job_id {
        return Err(PulseError::Boundary("model job binding"));
    }
    if !fences_compatible(&outcome.state_fence, &bundle.state_fence) {
        return Err(PulseError::Boundary("model fence"));
    }
    Ok(())
}

fn check_projection_boundary(
    projections: &CanonicalProjectionSet,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    projections
        .validate()
        .map_err(|_| PulseError::Boundary("canonical projections"))?;
    if !fences_compatible(&projections.binding.state_fence, &bundle.state_fence) {
        return Err(PulseError::Boundary("projection fence"));
    }
    Ok(())
}

fn run_classification_stage(
    stage: Option<&ClassificationStage>,
) -> Result<PulseStage<ClassificationResult>, PulseError> {
    stage.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse classification requires owner classification input",
            ))
        },
        |inputs| {
            classify(inputs.input, inputs.context, inputs.policy)
                .map(PulseStage::executed)
                .map_err(|_| PulseError::Classification)
        },
    )
}

fn run_cue_stage(
    stage: Option<&CueActivationStage>,
) -> Result<PulseStage<CueActivationEvaluation>, PulseError> {
    stage.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse cue activation requires owner cue snapshot",
            ))
        },
        |inputs| {
            evaluate_activation(inputs.candidate, inputs.request, inputs.profile)
                .map(PulseStage::executed)
                .map_err(|_| PulseError::CueActivation)
        },
    )
}

fn run_epistemic_stage(
    position_request: Option<&PositionRequest>,
) -> Result<PulseStage<ResolvedEpistemicPosition>, PulseError> {
    position_request.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse epistemic position requires admitted records",
            ))
        },
        |inputs| {
            resolve(inputs)
                .map(PulseStage::executed)
                .map_err(|_| PulseError::Epistemic)
        },
    )
}

fn run_understanding_stage<F>(
    stage: Option<UnderstandingStage<'_, F>>,
) -> Result<PulseStage<ActiveUnderstandingViewResult>, PulseError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    stage.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse understanding view requires admitted context set",
            ))
        },
        |inputs| {
            assemble_active_view(
                inputs.admitted,
                inputs.recipe,
                inputs.quality,
                inputs.policy,
                inputs.measure,
            )
            .map(PulseStage::executed)
            .map_err(|_| PulseError::Understanding)
        },
    )
}

fn run_grounding_stage(
    grounding_request: Option<&GroundingRequest>,
) -> Result<PulseStage<GroundedClaimDraft>, PulseError> {
    grounding_request.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse claim grounding requires grounding request",
            ))
        },
        |inputs| {
            ground_draft_with_controls(inputs.clone())
                .map(PulseStage::executed)
                .map_err(|_| PulseError::Grounding)
        },
    )
}

fn run_rival_stage(
    stage: Option<&RivalStage>,
) -> Result<PulseStage<StructuredRivalModelSet>, PulseError> {
    stage.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse rival models require validated rival declarations",
            ))
        },
        |inputs| {
            structure_rival_models(
                inputs.bundle,
                inputs.validated_draft,
                inputs.current_position,
                inputs.policy,
            )
            .map(PulseStage::executed)
            .map_err(|_| PulseError::Rivals)
        },
    )
}

fn run_conflict_stage(
    stage: Option<&ConflictStage>,
) -> Result<PulseStage<ConflictAnalysisCandidate>, PulseError> {
    stage.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse conflict analysis requires admitted conflict inputs",
            ))
        },
        |inputs| {
            analyze_conflict(
                inputs.item,
                inputs.draft,
                inputs.grounded,
                inputs.conflict_set,
                inputs.supplements,
                inputs.policy,
            )
            .map(PulseStage::executed)
            .map_err(|_| PulseError::Conflict)
        },
    )
}

fn run_probe_stage(
    params: Option<ProbePlanParams<'_>>,
) -> Result<PulseStage<ProbePlan>, PulseError> {
    params.map_or_else(
        || {
            Ok(PulseStage::pending(
                "pulse probe plan requires rival and affordance inputs",
            ))
        },
        |inputs| {
            plan_discriminative_probes(inputs)
                .map(PulseStage::executed)
                .map_err(|_| PulseError::Probes)
        },
    )
}

fn run_candidate_stage(
    projections: Option<&CanonicalProjectionSet>,
    stage: Option<&CandidateStage>,
) -> Result<PulseStage<ContextCandidateSetResult>, PulseError> {
    match (projections, stage) {
        (Some(projection_set), Some(inputs)) => {
            let canonical = CanonicalProjectionInput {
                set: projection_set.clone(),
                measurements: inputs.measurements.to_vec(),
            };
            construct_context_candidates_with_canonical(
                inputs.request,
                inputs.recipe,
                &canonical,
                inputs.attention_and_conflicts,
                inputs.epistemic_position,
                inputs.cue_activation_result,
                inputs.evidence,
                inputs.policy,
            )
            .map(PulseStage::executed)
            .map_err(|_| PulseError::Candidates)
        }
        (None, Some(_)) => Ok(PulseStage::pending(
            "pulse context candidates require CC-004 projection set",
        )),
        (_, None) => Ok(PulseStage::pending(
            "pulse context candidates require owner candidate request",
        )),
    }
}

/// Runs the end-to-end Orientation pulse through the named owner entries.
///
/// Boundary values validate first; each present stage executes in pulse order
/// and any owner refusal fails the pulse before the packet; absent stage
/// inputs record explicit pending dispositions. The packet always projects
/// from the caller-supplied validated candidate, bundle, handles, and policy.
pub(crate) fn run_orientation_pulse<F>(
    request: OrientationPulseRequest<'_, F>,
) -> Result<OrientationPulse, PulseError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if let Some(outcome) = request.model_outcome {
        check_model_boundary(outcome, request.bundle)?;
    }
    if let Some(projections) = request.projections {
        check_projection_boundary(projections, request.bundle)?;
    }

    let classification = run_classification_stage(request.classification.as_ref())?;
    let cue_activation = run_cue_stage(request.cue_activation.as_ref())?;
    let epistemic_position = run_epistemic_stage(request.epistemic)?;
    let understanding = run_understanding_stage(request.understanding)?;
    let grounding = run_grounding_stage(request.grounding)?;
    let rivals = run_rival_stage(request.rivals.as_ref())?;
    let conflict = run_conflict_stage(request.conflict.as_ref())?;
    let probes = run_probe_stage(request.probes)?;
    let candidates = run_candidate_stage(request.projections, request.candidates.as_ref())?;

    let packet = build_projection(
        request.admitted_job,
        request.validated_candidate,
        request.bundle,
        request.cep_handles,
        request.policy,
    )?;

    Ok(OrientationPulse {
        classification,
        cue_activation,
        epistemic_position,
        understanding,
        grounding,
        rivals,
        conflict,
        probes,
        candidates,
        packet,
    })
}

/// Runs the production Orientation pulse: packet inputs only, every other
/// stage explicitly pending until its owner values land.
///
/// This is the production call site for the pulse composer: dispatch reaches
/// the projector only through this function, so the packet path is byte-stable
/// while the composition wiring stays live in-binary.
pub(crate) fn run_production_orientation_pulse(
    admitted_job: &AdmittedOrientationJob,
    validated_candidate: &ValidatedCandidate,
    bundle: &DreamInputBundle,
    policy: &OrientationPolicy,
) -> Result<OrientationPulse, PulseError> {
    let pulse = run_orientation_pulse(OrientationPulseRequest {
        model_outcome: None,
        projections: None,
        admitted_job,
        validated_candidate,
        bundle,
        cep_handles: &[],
        policy,
        classification: None,
        cue_activation: None,
        epistemic: None,
        understanding: no_understanding(),
        grounding: None,
        rivals: None,
        conflict: None,
        probes: None,
        candidates: None,
    })?;
    pulse.classification.expect_pending();
    pulse.cue_activation.expect_pending();
    pulse.epistemic_position.expect_pending();
    pulse.understanding.expect_pending();
    pulse.grounding.expect_pending();
    pulse.rivals.expect_pending();
    pulse.conflict.expect_pending();
    pulse.probes.expect_pending();
    pulse.candidates.expect_pending();
    Ok(pulse)
}
