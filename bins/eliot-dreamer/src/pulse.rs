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
//! - conflict analysis: `eliot_dreamer_conflict_analysis::analyze_grounded_conflict`;
//! - probes: `eliot_dreamer_probe_plan::plan_discriminative_probes`;
//! - candidates:
//!   `eliot_context_candidates::construct_context_candidates_with_canonical`;
//! - packet: `eliot_dreamer_orientation::build_projection`.
//!
//! Fail-closed sequencing (issue #2901): production composes only from the
//! versioned [`ProductionOrientationInputs`](crate::production_orientation::ProductionOrientationInputs)
//! carrier, whose CC-002 outcome and CC-004 projection set are mandatory and
//! validated first (schema, bundle-digest binding, job binding, mutual fence
//! compatibility, one coherent identity closure). Missing prerequisites yield
//! a typed blocked result, never a packet. The per-stage owner entries answer
//! to the explicit mandatory [`PulseDenominator`]: a stage whose caller-supplied
//! inputs are absent records an explicit pending disposition, and a stage whose
//! inputs are present but whose owner refuses fails that stage, so a partial
//! pulse is never thinned into a packet silently. There is no packet-only
//! compatibility composition: the mandatory denominator is the only denominator
//! this crate names, so no alternative path can produce a candidate packet
//! outside the production carrier. Error payloads are bounded static fields;
//! nothing secret flows.
//!
//! Binding notes: mandatory outputs are retained in denominator order and
//! downstream calls consume the exact native predecessor where their contract
//! has a compatible input shape. The resolved epistemic position is resolver policy output,
//! never a Governor-issued handle, so it is reported as its own stage and the
//! packet keeps receiving only caller-supplied
//! [`CurrentEpistemicPositionHandle`](eliot_dreamer_orientation::CurrentEpistemicPositionHandle)
//! values (G5: locally built envelopes would be self-issued authority). The
//! rival stage consumes the admitted-contracts position supplied by its owner,
//! not the resolver output, because the two vocabularies are deliberately
//! distinct. Structured conflict analysis consumes the same original A05
//! candidate as rival structuring; probe planning consumes the rival owner's
//! exact projection; candidate mapping consumes the executed cue result and
//! exact analyzed conflict set alongside its other admitted source records.

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
    ConflictAnalysisCandidate, ConflictAnalysisPolicy, ConflictSupplements,
    analyze_grounded_conflict,
};
use eliot_dreamer_contracts::grounding::GroundedDreamDraft as StructuredGroundedDreamDraft;
use eliot_dreamer_contracts::{
    ClassificationInput, CurationAcceptanceCtx, DreamInputBundle, ModelRouteDisposition,
    ModelRouteOutcome, ValidatedCurationItem, ValidatedGroundingCandidate, bundle_digest_of,
    canonical_bytes, digest_hex,
};
use eliot_dreamer_orientation::OrientationError;
use eliot_dreamer_probe_plan::{ProbePlan, ProbePlanParams, plan_discriminative_probes};
use eliot_dreamer_rival_model::{RivalModelSet, RivalPolicy, structure_rival_models};
use eliot_epistemic::{
    AdmittedBindingError, CurrentEpistemicPosition, ObservationRecord, PositionRequest, resolve,
};
use eliot_epistemic_contracts::{
    ConflictSet, CurrentEpistemicPosition as AdmittedPosition, EpistemicPositionCandidate,
};

use crate::OrientationStageDisposition;

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

/// Original admitted source records joined to one native CEP resolver request.
pub(crate) struct EpistemicStage<'a> {
    /// Original candidate returned by storage readback.
    pub candidate: &'a EpistemicPositionCandidate,
    /// Original Current view returned beside that candidate.
    pub admitted_position: &'a AdmittedPosition,
    /// Original source observation re-acquired by Governor.
    pub observation: &'a ObservationRecord,
    /// Native resolver request built from that source observation.
    pub request: &'a PositionRequest,
}

/// Caller-supplied understanding stage inputs (owner-built, never inferred).
pub(crate) struct UnderstandingStage<'a, F> {
    /// Exact admitted context set to project.
    pub admitted: &'a AdmittedContextSet,
    /// Recipe the admitted set must satisfy.
    pub recipe: &'a ContextRecipe,
    /// Quality scorecard bound to the admitted binding.
    pub quality: &'a QualityScorecard,
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

/// Closed identity of one pulse denominator member, in composition order.
///
/// Dependency order follows the compatible native dataflow: Grounding feeds
/// Rival validation, that retained rival result feeds probe projection, the
/// original validated grounding candidate binds conflict analysis, and the
/// executed Cue result plus analyzed conflict set feed candidate compilation.
/// Every member also checks the shared route, bundle, scope and fence it owns;
/// the packet requires the full joined closure before it may project.
/// [`PulseStageId::ORDER`] is the deterministic composition order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PulseStageId {
    Classification,
    CueActivation,
    EpistemicPosition,
    Understanding,
    Grounding,
    Rivals,
    Conflict,
    Probes,
    Candidates,
    Packet,
}

impl PulseStageId {
    /// Expected members in deterministic composition order.
    pub const ORDER: [PulseStageId; 10] = [
        PulseStageId::Classification,
        PulseStageId::CueActivation,
        PulseStageId::EpistemicPosition,
        PulseStageId::Understanding,
        PulseStageId::Grounding,
        PulseStageId::Rivals,
        PulseStageId::Conflict,
        PulseStageId::Probes,
        PulseStageId::Candidates,
        PulseStageId::Packet,
    ];

    /// Closed wire spelling for the ledger record.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classification => "classification",
            Self::CueActivation => "cue_activation",
            Self::EpistemicPosition => "epistemic_position",
            Self::Understanding => "understanding",
            Self::Grounding => "grounding",
            Self::Rivals => "rivals",
            Self::Conflict => "conflict",
            Self::Probes => "probes",
            Self::Candidates => "candidates",
            Self::Packet => "packet",
        }
    }

    /// Owning entry path invoked for this member.
    pub fn owner_entry(self) -> &'static str {
        match self {
            Self::Classification => "eliot_dreamer_classification::classify",
            Self::CueActivation => "eliot_cue_activation::evaluate_activation",
            Self::EpistemicPosition => "eliot_epistemic::resolve",
            Self::Understanding => "eliot_context_assembly::assemble_active_view",
            Self::Grounding => "eliot_dreamer_claim_grounding::ground_draft_with_controls",
            Self::Rivals => "eliot_dreamer_rival_model::structure_rival_models",
            Self::Conflict => "eliot_dreamer_conflict_analysis::analyze_grounded_conflict",
            Self::Probes => "eliot_dreamer_probe_plan::plan_discriminative_probes",
            Self::Candidates => {
                "eliot_context_candidates::construct_context_candidates_with_canonical"
            }
            Self::Packet => "eliot_dreamer_orientation::build_projection",
        }
    }

    /// Required owner-record descriptor consumed by this member.
    pub fn expected_input(self) -> &'static str {
        match self {
            Self::Classification => "owner classification input",
            Self::CueActivation => "owner cue snapshot",
            Self::EpistemicPosition => "admitted epistemic records",
            Self::Understanding => "admitted context set with route measurement",
            Self::Grounding => "owner grounding request",
            Self::Rivals => "validated rival declarations",
            Self::Conflict => "admitted conflict inputs",
            Self::Probes => "rival and affordance probe inputs",
            Self::Candidates => "owner candidate request with CC-004 projection set",
            Self::Packet => "joined pulse closure with admitted packet inputs",
        }
    }

    /// Static reason naming the missing owner value when not executed.
    pub fn missing_reason(self) -> &'static str {
        match self {
            Self::Classification => "pulse classification requires owner classification input",
            Self::CueActivation => "pulse cue activation requires owner cue snapshot",
            Self::EpistemicPosition => "pulse epistemic position requires admitted records",
            Self::Understanding => "pulse understanding view requires admitted context set",
            Self::Grounding => "pulse claim grounding requires grounding request",
            Self::Rivals => "pulse rival models require validated rival declarations",
            Self::Conflict => "pulse conflict analysis requires admitted conflict inputs",
            Self::Probes => "pulse probe plan requires rival and affordance inputs",
            Self::Candidates => "pulse context candidates require owner candidate request",
            Self::Packet => "pulse packet requires the joined pulse closure",
        }
    }

    /// Static owner-refusal reason when inputs were present but refused.
    pub fn refusal_reason(self) -> &'static str {
        match self {
            Self::Classification => "pulse classification owner refused",
            Self::CueActivation => "pulse cue activation owner refused",
            Self::EpistemicPosition => "pulse epistemic position owner refused",
            Self::Understanding => "pulse understanding view owner refused",
            Self::Grounding => "pulse claim grounding owner refused",
            Self::Rivals => "pulse rival models owner refused",
            Self::Conflict => "pulse conflict analysis owner refused",
            Self::Probes => "pulse probe plan owner refused",
            Self::Candidates => "pulse context candidates owner refused",
            Self::Packet => "pulse packet projection refused",
        }
    }

    /// Static reopen condition for a member that did not execute.
    pub fn recovery(self) -> &'static str {
        match self {
            Self::Classification => "reopen when the classification owner supplies its input",
            Self::CueActivation => "reopen when the cue owner supplies its snapshot",
            Self::EpistemicPosition => "reopen when admitted epistemic records arrive",
            Self::Understanding => "reopen when the admitted context set arrives",
            Self::Grounding => "reopen when the grounding owner supplies its request",
            Self::Rivals => "reopen when validated rival declarations arrive",
            Self::Conflict => "reopen when admitted conflict inputs arrive",
            Self::Probes => "reopen when rival and affordance inputs arrive",
            Self::Candidates => "reopen when the candidate request and CC-004 set arrive",
            Self::Packet => "reopen when the joined pulse closure is available",
        }
    }
}

/// Canonical identity of the mandatory ten-member denominator.
pub(crate) const PULSE_DENOMINATOR_IDENTITY: &str =
    eliot_dreamer_orientation::projection::ORIENTATION_PRODUCT_DENOMINATOR;

/// Explicit composition denominator: the canonical member set this crate
/// composes against. Whether CC-002/CC-004 are mandatory is no longer a flag
/// on the denominator: production carries them as non-optional
/// [`ProductionOrientationInputs`](crate::production_orientation::ProductionOrientationInputs)
/// members, so the carrier itself is the admission proof and no optional
/// alternative denominator exists to weaken it.
pub(crate) struct PulseDenominator {
    /// Canonical denominator identity carried by the result.
    pub identity: &'static str,
    /// Expected members in composition order.
    pub members: &'static [PulseStageId],
}

/// Mandatory production denominator: all ten members.
pub(crate) const MANDATORY_DENOMINATOR: PulseDenominator = PulseDenominator {
    identity: PULSE_DENOMINATOR_IDENTITY,
    members: &PulseStageId::ORDER,
};

/// Proof ceiling for an executed member: candidate-only, never promoted.
pub(crate) const CEILING_CANDIDATE_ONLY: &str = "candidate_only";
/// Proof ceiling for a member that did not execute: nothing proved.
pub(crate) const CEILING_BLOCKED: &str = "blocked";

/// Whether conflict owner output qualifies toward a complete pulse.
///
/// Always false until #2869 (source/evidence provenance and proof ceilings)
/// and #2870 (canonical pair orientation, one-digest invariant) land: an
/// executed conflict stage stays unqualified and caps the overall pulse at
/// partial. Owned here, flipped only by that repair wave.
pub(crate) const CONFLICT_OUTPUT_QUALIFIED: bool = false;

/// One pulse stage outcome with typed disposition and commitments.
///
/// The member's owner output is deliberately not retained here: each stage
/// entry invokes its named owner, digests the exact owner output into
/// `output_commitment`, and returns the disposition record. The typed output
/// value itself had no reader â€” the ledger records the commitment, not the
/// value â€” so retaining it duplicated a digest the stage had already proved.
pub(crate) struct PulseStage {
    /// Denominator member identity.
    pub id: PulseStageId,
    /// Typed member disposition.
    pub disposition: OrientationStageDisposition,
    /// Input commitment when the member consumed its owner record.
    pub input_commitment: Option<String>,
    /// Output commitment when the member executed.
    pub output_commitment: Option<String>,
    /// Static reason naming the missing owner value or refusal.
    pub reason: Option<&'static str>,
    /// Exact typed value returned by the named owner, retained for the joined
    /// Orientation projection.
    pub owner_output: Option<StageOwnerOutput>,
    /// Owner-canonical bytes, when the native output contract exposes them.
    pub canonical_output: Option<Vec<u8>>,
}

impl PulseStage {
    fn executed(
        id: PulseStageId,
        input_commitment: String,
        output_commitment: String,
        owner_output: StageOwnerOutput,
        canonical_output: Option<Vec<u8>>,
    ) -> Self {
        Self {
            id,
            disposition: OrientationStageDisposition::Executed,
            input_commitment: Some(input_commitment),
            output_commitment: Some(output_commitment),
            reason: None,
            owner_output: Some(owner_output),
            canonical_output,
        }
    }

    fn pending(id: PulseStageId) -> Self {
        Self::pending_reason(id, id.missing_reason())
    }

    fn pending_reason(id: PulseStageId, reason: &'static str) -> Self {
        Self {
            id,
            disposition: OrientationStageDisposition::Pending,
            input_commitment: None,
            output_commitment: None,
            reason: Some(reason),
            owner_output: None,
            canonical_output: None,
        }
    }

    /// Records a production member that cannot proceed.
    pub(crate) fn blocked(id: PulseStageId, reason: &'static str) -> Self {
        Self {
            id,
            disposition: OrientationStageDisposition::Blocked,
            input_commitment: None,
            output_commitment: None,
            reason: Some(reason),
            owner_output: None,
            canonical_output: None,
        }
    }
}

/// Native result values returned by the mandatory stage owners.
pub(crate) enum StageOwnerOutput {
    Classification(Box<ClassificationResult>),
    CueActivation(CueActivationEvaluation),
    EpistemicPosition(CurrentEpistemicPosition),
    Understanding(Box<ActiveUnderstandingViewResult>),
    Grounding(Box<StructuredGroundedDreamDraft>),
    Rivals(RivalModelSet),
    Conflict(ConflictAnalysisCandidate),
    Probes(ProbePlan),
    Candidates(ContextCandidateSetResult),
}

#[derive(serde::Serialize)]
struct GroundingInput<'a> {
    job: &'a eliot_dreamer_contracts::DreamJobAdmission,
    bundle: &'a DreamInputBundle,
    manifest: &'a eliot_dreamer_contracts::grounding::AllowedReferenceManifest,
    draft: &'a eliot_dreamer_contracts::grounding::StructuredModelDraft,
    policy: &'a eliot_dreamer_contracts::grounding::GroundingPolicy,
    whole_claim_quota: Option<usize>,
    cancellation: &'static str,
    cancellation_reason: Option<&'a str>,
    deadline_exceeded: bool,
}

/// Canonical content digest over one owner output value.
///
/// Returns `None` only when canonical serialization fails, which the caller
/// treats as an owner defect.
pub(crate) fn output_digest<T: serde::Serialize>(value: &T) -> Option<String> {
    canonical_owner_output(value).map(|(digest, _)| digest)
}

/// Returns the exact canonical output bytes and their existing owner
/// commitment in one serialization pass.
pub(crate) fn canonical_owner_output<T: serde::Serialize>(value: &T) -> Option<(String, Vec<u8>)> {
    canonical_bytes(value)
        .ok()
        .map(|bytes| (digest_hex(&bytes), bytes))
}

/// Canonical commitment over exact immutable stage input records.
///
/// This ledger commitment does not replace or reissue any digest carried by
/// an input contract.
pub(crate) fn canonical_input_commitment<T: serde::Serialize>(value: &T) -> Option<String> {
    canonical_bytes(value).ok().map(|bytes| digest_hex(&bytes))
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
    /// Original admitted candidate, source observation, and local resolver result did not join.
    #[error("pulse admitted epistemic owner binding refused: {0}")]
    EpistemicBinding(AdmittedBindingError),
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
    /// The production carrier observed cancellation before composition.
    #[error("pulse cancelled")]
    Cancelled,
    /// The production carrier deadline passed before composition.
    #[error("pulse deadline exceeded")]
    DeadlineExceeded,
    /// Orientation projector refused; maps through the existing denial table.
    #[error("pulse packet refused")]
    Packet(#[from] OrientationError),
}

pub(crate) fn fences_compatible(left: &StateFence, right: &StateFence) -> bool {
    left.is_compatible_with(right) && right.is_compatible_with(left)
}

pub(crate) fn check_model_boundary(
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

pub(crate) fn check_projection_boundary(
    projections: &CanonicalProjectionSet,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    projections
        .validate()
        .map_err(|_| PulseError::Boundary("canonical projections"))?;
    if projections.binding.task_id.as_str() != bundle.task_id
        || projections.binding.scope_id.as_str() != bundle.scope_id
    {
        return Err(PulseError::Boundary("projection task or scope"));
    }
    if !fences_compatible(&projections.binding.state_fence, &bundle.state_fence) {
        return Err(PulseError::Boundary("projection fence"));
    }
    Ok(())
}

pub(crate) fn run_classification_stage(
    stage: Option<&ClassificationStage>,
) -> Result<PulseStage, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Classification)),
        |inputs| {
            let owner_input_digest =
                eliot_dreamer_contracts::classification_input_digest(inputs.input)
                    .map_err(|_| PulseError::Classification)?;
            let output = classify(inputs.input, inputs.context, inputs.policy)
                .map_err(|_| PulseError::Classification)?;
            if output
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.input_digest != owner_input_digest)
                || output
                    .sealed
                    .as_ref()
                    .is_some_and(|sealed| sealed.input_digest != owner_input_digest)
            {
                return Err(PulseError::Classification);
            }
            let input_commitment = canonical_input_commitment(&(
                &owner_input_digest,
                inputs.context.job,
                inputs.context.bundle,
                inputs.context.receipt,
                inputs.context.screen,
                inputs.context.grounded,
                inputs.context.request,
                inputs.context.usage,
                inputs.policy,
            ))
            .ok_or(PulseError::Classification)?;
            let canonical = canonical_bytes(&output).ok();
            let commitment = output.result_digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Classification,
                input_commitment,
                commitment,
                StageOwnerOutput::Classification(Box::new(output)),
                canonical,
            ))
        },
    )
}

pub(crate) fn run_cue_stage(stage: Option<&CueActivationStage>) -> Result<PulseStage, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::CueActivation)),
        |inputs| {
            let output = evaluate_activation(inputs.candidate, inputs.request, inputs.profile)
                .map_err(|_| PulseError::CueActivation)?;
            if output.candidate_build_digest != inputs.candidate.build_digest {
                return Err(PulseError::CueActivation);
            }
            output
                .validate_against(inputs.candidate, inputs.request, inputs.profile)
                .map_err(|_| PulseError::CueActivation)?;
            let (commitment, canonical) =
                canonical_owner_output(&output).ok_or(PulseError::CueActivation)?;
            Ok(PulseStage::executed(
                PulseStageId::CueActivation,
                output.input_digest.to_string(),
                commitment,
                StageOwnerOutput::CueActivation(output),
                Some(canonical),
            ))
        },
    )
}

pub(crate) fn run_epistemic_stage(
    stage: Option<&EpistemicStage<'_>>,
) -> Result<PulseStage, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::EpistemicPosition)),
        |inputs| {
            let output = resolve(inputs.request).map_err(|_| PulseError::Epistemic)?;
            if output.question != inputs.request.question
                || output.scope != inputs.request.scope
                || output.state_fence != inputs.request.state_fence
            {
                return Err(PulseError::Epistemic);
            }
            eliot_epistemic::bind_admitted_position(
                inputs.candidate,
                inputs.admitted_position,
                inputs.observation,
                inputs.request,
                &output,
            )
            .map_err(PulseError::EpistemicBinding)?;
            // CEP defines no native input digest; retain a canonical ledger
            // commitment over the exact source, admitted, and resolver inputs.
            let input_commitment = canonical_input_commitment(&(
                inputs.candidate,
                inputs.admitted_position,
                inputs.observation,
                inputs.request,
            ))
            .ok_or(PulseError::Epistemic)?;
            let (commitment, canonical) =
                canonical_owner_output(&output).ok_or(PulseError::Epistemic)?;
            Ok(PulseStage::executed(
                PulseStageId::EpistemicPosition,
                input_commitment,
                commitment,
                StageOwnerOutput::EpistemicPosition(output),
                Some(canonical),
            ))
        },
    )
}

pub(crate) fn run_understanding_stage<F>(
    stage: Option<UnderstandingStage<'_, F>>,
) -> Result<PulseStage, PulseError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Understanding)),
        |inputs| {
            #[derive(serde::Serialize)]
            struct UnderstandingInput<'a> {
                admitted: &'a AdmittedContextSet,
                recipe: &'a ContextRecipe,
                quality: &'a QualityScorecard,
                fence_digest: &'a str,
                max_serialized_bytes: u64,
                serializer_id: &'a str,
                serializer_version: &'a str,
                serializer_options_digest: &'a str,
                route_id: &'a str,
                model_id: &'a str,
                measurement_status: eliot_context_contracts::MeasurementStatus,
            }
            // The injected measurement function itself has no portable wire
            // identity; its owner-supplied route and serializer identities are
            // included with every immutable record it measured.
            let input_commitment = canonical_input_commitment(&UnderstandingInput {
                admitted: inputs.admitted,
                recipe: inputs.recipe,
                quality: inputs.quality,
                fence_digest: &inputs.policy.fence_digest,
                max_serialized_bytes: inputs.policy.max_serialized_bytes,
                serializer_id: &inputs.policy.serializer_id,
                serializer_version: &inputs.policy.serializer_version,
                serializer_options_digest: &inputs.policy.serializer_options_digest,
                route_id: &inputs.policy.route_id,
                model_id: &inputs.policy.model_id,
                measurement_status: inputs.policy.measurement_status,
            })
            .ok_or(PulseError::Understanding)?;
            let output = assemble_active_view(
                inputs.admitted,
                inputs.recipe,
                (*inputs.quality).clone(),
                inputs.policy,
                inputs.measure,
            )
            .map_err(|_| PulseError::Understanding)?;
            if output.admitted != *inputs.admitted
                || output.view.binding != inputs.admitted.binding
                || output.view.quality != *inputs.quality
                || output.view.recipe_digest != inputs.recipe.recipe_sha256
                || output.view.fence_digest != inputs.policy.fence_digest
                || output.verify_boundaries().is_err()
            {
                return Err(PulseError::Understanding);
            }
            // The callback has no portable function identity. Retain both its
            // exact measured bytes and its typed returned result in the
            // canonical stage output, without asserting a commitment to the
            // callback implementation itself.
            let canonical = canonical_bytes(&(
                &output.view,
                &output.admitted,
                &output.serialized_bytes,
                &output.boundaries,
                &output.boundary_binding,
            ))
            .ok();
            let commitment = output.view.output_digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Understanding,
                input_commitment,
                commitment,
                StageOwnerOutput::Understanding(Box::new(output)),
                canonical,
            ))
        },
    )
}

pub(crate) fn run_grounding_stage(
    grounding_request: Option<&GroundingRequest>,
) -> Result<PulseStage, PulseError> {
    grounding_request.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Grounding)),
        |inputs| {
            let (cancellation, cancellation_reason) = match &inputs.controls.cancellation {
                eliot_dreamer_claim_grounding::Cancellation::NotCancelled => {
                    ("not_cancelled", None)
                }
                eliot_dreamer_claim_grounding::Cancellation::Cancelled(reason) => {
                    ("cancelled", Some(reason.as_str()))
                }
            };
            // Controls are part of this owner's exact invocation and are
            // committed without interpreting or manufacturing new control
            // values.
            let input_commitment = canonical_input_commitment(&GroundingInput {
                job: &inputs.job,
                bundle: &inputs.bundle,
                manifest: &inputs.manifest,
                draft: &inputs.draft,
                policy: &inputs.policy,
                whole_claim_quota: inputs.controls.whole_claim_quota,
                cancellation,
                cancellation_reason,
                deadline_exceeded: inputs.controls.deadline_exceeded,
            })
            .ok_or(PulseError::Grounding)?;
            let output =
                ground_draft_with_controls(inputs.clone()).map_err(|_| PulseError::Grounding)?;
            output.validate().map_err(|_| PulseError::Grounding)?;
            if output.job_id != inputs.job.canonical_id()
                || output.input.job != inputs.job
                || output.input.bundle != inputs.bundle
                || output.input != inputs.draft
                || output.manifest != inputs.manifest
                || output.policy != inputs.policy
            {
                return Err(PulseError::Grounding);
            }
            let canonical = canonical_bytes(&output).ok();
            let commitment = output.output_digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Grounding,
                input_commitment,
                commitment,
                StageOwnerOutput::Grounding(Box::new(output)),
                canonical,
            ))
        },
    )
}

pub(crate) fn run_rival_stage(stage: Option<&RivalStage>) -> Result<PulseStage, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Rivals)),
        |inputs| {
            let input_commitment = canonical_input_commitment(&(
                inputs.bundle,
                inputs.validated_draft,
                inputs.current_position,
                inputs.policy,
            ))
            .ok_or(PulseError::Rivals)?;
            let output = structure_rival_models(
                inputs.bundle,
                inputs.validated_draft,
                inputs.current_position,
                inputs.policy,
            )
            .map_err(|_| PulseError::Rivals)?;
            output.validate().map_err(|_| PulseError::Rivals)?;
            let expected_bundle_digest =
                bundle_digest_of(inputs.bundle).map_err(|_| PulseError::Rivals)?;
            if output.bundle_digest != expected_bundle_digest
                || output.validated_input_digest
                    != inputs.validated_draft.validated.receipt.input_digest
                || output.task_id.as_str() != inputs.bundle.task_id
                || output.scope != inputs.bundle.scope_id
                || output.state_fence != inputs.bundle.state_fence
                || output
                    .current_position
                    .validate_against(inputs.current_position)
                    .is_err()
                || output.policy_id != inputs.policy.policy_id
                || output.policy_digest != inputs.policy.digest
            {
                return Err(PulseError::Rivals);
            }
            let canonical = canonical_bytes(&output).ok();
            let commitment = output.digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Rivals,
                input_commitment,
                commitment,
                StageOwnerOutput::Rivals(output),
                canonical,
            ))
        },
    )
}

pub(crate) fn run_conflict_stage(
    stage: Option<&ConflictStage>,
    candidate: Option<&ValidatedGroundingCandidate>,
) -> Result<PulseStage, PulseError> {
    match (stage, candidate) {
        (None, _) => Ok(PulseStage::pending(PulseStageId::Conflict)),
        (Some(_), None) => Err(PulseError::Conflict),
        (Some(inputs), Some(candidate)) => {
            candidate
                .validate_binding()
                .map_err(|_| PulseError::Conflict)?;
            if inputs.item.receipt != candidate.validated.receipt
                || inputs.supplements.expected_receipt != candidate.validated.receipt
            {
                return Err(PulseError::Boundary("conflict A05 receipt predecessor"));
            }
            let output = analyze_grounded_conflict(
                inputs.item,
                candidate,
                inputs.conflict_set,
                inputs.supplements,
                inputs.policy,
            )
            .map_err(|_| PulseError::Conflict)?;
            // The stage ledger binds every exact native analyzer input. The
            // original A05 receipt input digest remains independently checked
            // by `candidate.validate_binding()` above; it does not bind the
            // conflict set, supplements, or policy and is never reused here.
            let input_commitment = canonical_input_commitment(&(
                inputs.item,
                candidate,
                inputs.conflict_set,
                inputs.supplements,
                inputs.policy,
            ))
            .ok_or(PulseError::Conflict)?;
            let commitment = output.candidate_digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Conflict,
                input_commitment,
                commitment,
                StageOwnerOutput::Conflict(output),
                None,
            ))
        }
    }
}

pub(crate) fn run_probe_stage(
    params: Option<ProbePlanParams<'_>>,
) -> Result<PulseStage, PulseError> {
    params.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Probes)),
        |inputs| {
            let input_commitment = canonical_input_commitment(&(
                &inputs.plan_id,
                inputs.bundle,
                inputs.draft,
                inputs.rivals,
                inputs.affordances,
                inputs.limits,
                inputs.policy,
            ))
            .ok_or(PulseError::Probes)?;
            let output =
                plan_discriminative_probes(inputs.clone()).map_err(|_| PulseError::Probes)?;
            output.validate().map_err(|_| PulseError::Probes)?;
            if output.task_id.as_str() != inputs.bundle.task_id
                || output.scope != inputs.bundle.scope_id
                || output.state_fence != inputs.bundle.state_fence
                || output.draft_digest != inputs.draft.draft_digest
                || output.rival_digest != inputs.rivals.digest
                || output.affordance_digest != inputs.affordances.digest
                || output.manifest_digest != inputs.bundle.manifest_digest
                || output.ordering_policy != *inputs.policy
            {
                return Err(PulseError::Boundary("probe output predecessor bindings"));
            }
            let canonical = canonical_bytes(&output).ok();
            let commitment = output.digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Probes,
                input_commitment,
                commitment,
                StageOwnerOutput::Probes(output),
                canonical,
            ))
        },
    )
}

/// Pending reason when the candidate stage has owner inputs but the CC-004
/// projection boundary is absent.
pub(crate) const CANDIDATES_REQUIRE_PROJECTIONS: &str =
    "pulse context candidates require CC-004 projection set";

pub(crate) fn run_candidate_stage(
    projections: Option<&CanonicalProjectionSet>,
    stage: Option<&CandidateStage>,
    cue_activation: Option<&eliot_cue_activation::CueActivationEvaluation>,
    conflict_set: Option<&ConflictSet>,
) -> Result<PulseStage, PulseError> {
    match (projections, stage) {
        (Some(projection_set), Some(inputs)) => {
            if inputs.request.binding != projection_set.binding
                || inputs.recipe.binding != projection_set.binding
                || inputs.attention_and_conflicts.is_none()
                || conflict_set.is_none_or(|expected| {
                    !inputs.attention_and_conflicts.is_some_and(|attention| {
                        attention.conflicts.as_slice() == std::slice::from_ref(expected)
                    })
                })
            {
                return Err(PulseError::Boundary(
                    "candidate projection or conflict predecessor",
                ));
            }
            let supplied_cue = inputs.cue_activation_result;
            let cue_input = match (supplied_cue, cue_activation) {
                (Some(supplied), Some(actual)) => Some(CueInput {
                    result: actual.result.clone(),
                    measurements: supplied.measurements.clone(),
                }),
                (None, None) => None,
                _ => return Err(PulseError::Boundary("candidate cue activation predecessor")),
            };
            let canonical = CanonicalProjectionInput {
                set: projection_set.clone(),
                measurements: inputs.measurements.to_vec(),
            };
            let input_commitment = canonical_input_commitment(&(
                inputs.request,
                inputs.recipe,
                &canonical,
                inputs.attention_and_conflicts,
                inputs.epistemic_position,
                &cue_input,
                inputs.evidence,
                inputs.policy,
            ))
            .ok_or(PulseError::Candidates)?;
            let output = construct_context_candidates_with_canonical(
                inputs.request,
                inputs.recipe,
                &canonical,
                inputs.attention_and_conflicts,
                inputs.epistemic_position,
                cue_input.as_ref(),
                inputs.evidence,
                inputs.policy,
            )
            .map_err(|_| PulseError::Candidates)?;
            output.validate().map_err(|_| PulseError::Candidates)?;
            if output.set.binding != inputs.request.binding
                || output.set.binding != projection_set.binding
            {
                return Err(PulseError::Boundary("candidate output owner binding"));
            }
            let canonical = canonical_bytes(&output).ok();
            let commitment = output.digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Candidates,
                input_commitment,
                commitment,
                StageOwnerOutput::Candidates(output),
                canonical,
            ))
        }
        (None, Some(_)) => Ok(PulseStage::pending_reason(
            PulseStageId::Candidates,
            CANDIDATES_REQUIRE_PROJECTIONS,
        )),
        (_, None) => Ok(PulseStage::pending(PulseStageId::Candidates)),
    }
}
