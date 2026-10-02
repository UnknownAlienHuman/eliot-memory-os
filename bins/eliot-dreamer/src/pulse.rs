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
//! Binding notes: the resolved epistemic position is resolver policy output,
//! never a Governor-issued handle, so it is reported as its own stage and the
//! packet keeps receiving only caller-supplied
//! [`CurrentEpistemicPositionHandle`](eliot_dreamer_orientation::CurrentEpistemicPositionHandle)
//! values (G5: locally built envelopes would be self-issued authority). The
//! rival stage consumes the admitted-contracts position supplied by its owner,
//! not the resolver output, because the two vocabularies are deliberately
//! distinct.

use eliot_context_assembly::{AssemblyPolicy, assemble_active_view};
use eliot_context_candidates::{
    AttentionInput, CandidatePolicy, CandidateRequest, CanonicalProjectionInput, CueInput,
    EpistemicInput, EvidenceInput, MemberMeasurement, construct_context_candidates_with_canonical,
};
use eliot_context_contracts::{
    AdmittedContextSet, CanonicalProjectionSet, ContextError, ContextRecipe, QualityScorecard,
    ResolvedContextRecipe, SerializedContextMeasurement,
};
use eliot_contracts::StateFence;
use eliot_cue_activation::{ActivationProfile, evaluate_activation};
use eliot_cue_contracts::{ActivationRequest, CueSnapshotBuildCandidate};
use eliot_dreamer_claim_grounding::{GroundingRequest, ground_draft_with_controls};
use eliot_dreamer_classification::{ClassificationPolicy, classify};
use eliot_dreamer_conflict_analysis::{
    ConflictAnalysisPolicy, ConflictSupplements, analyze_conflict,
};
use eliot_dreamer_contracts::{
    ClassificationInput, CurationAcceptanceCtx, DreamInputBundle, GroundedDreamDraft,
    ModelRouteDisposition, ModelRouteOutcome, ValidatedCurationItem, ValidatedDreamDraft,
    ValidatedGroundingCandidate, bundle_digest_of, canonical_bytes, digest_hex,
};
use eliot_dreamer_orientation::OrientationError;
use eliot_dreamer_probe_plan::{ProbePlanParams, plan_discriminative_probes};
use eliot_dreamer_rival_model::{RivalPolicy, structure_rival_models};
use eliot_epistemic::{PositionRequest, resolve};
use eliot_epistemic_contracts::{ConflictSet, CurrentEpistemicPosition as AdmittedPosition};

use crate::{OrientationStageDisposition, OrientationStageRecord};

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
    /// APPROVED revision the compilation executes under (#1724).
    ///
    /// Distinct from `recipe`: the approved revision says what order and
    /// features MEAN, the bound instance supplies this task's envelope. The
    /// caller owns the resolution; nothing here derives or defaults it.
    pub approved: &'a ResolvedContextRecipe,
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

/// Closed identity of one pulse denominator member, in composition order.
///
/// Dependency order: every member consumes caller-supplied owner records,
/// never another member's output value, so no member has a stage predecessor
/// to enforce in the composer. Predecessor discipline lives in the owner
/// entries (each validates its own inputs and refuses lookalikes) and in the
/// production identity closure: candidates additionally require the CC-004
/// boundary (refused without it), and the packet requires the full joined
/// closure before it may project. [`PulseStageId::ORDER`] is the
/// deterministic composition order.
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
            Self::Conflict => "eliot_dreamer_conflict_analysis::analyze_conflict",
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
pub(crate) const PULSE_DENOMINATOR_IDENTITY: &str = "orientation-pulse-denominator:v1:classification,cue_activation,epistemic_position,understanding,grounding,rivals,conflict,probes,candidates,packet";

/// Expected member count, derived from the canonical denominator identity.
///
/// This is deliberately NOT `PulseStageId::ORDER.len()`: the denominator
/// identity is the published wire claim about how many members a complete
/// pulse carries, so completeness is checked against the claim rather than
/// against the very list the records are built from. A ledger assembled from
/// [`PulseStageId::ORDER`] always has `ORDER.len()` entries by construction,
/// so comparing it to `ORDER.len()` proves nothing; comparing it to this
/// count fails closed if the two ever drift apart.
pub(crate) const PULSE_EXPECTED_MEMBER_COUNT: usize = 10;

/// Static reason when a ledger does not cover the published denominator.
pub(crate) const PULSE_DENOMINATOR_INCOMPLETE: &str =
    "pulse ledger does not cover the mandatory denominator";

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
/// value itself had no reader — the ledger records the commitment, not the
/// value — so retaining it duplicated a digest the stage had already proved.
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
}

impl PulseStage {
    fn executed(id: PulseStageId, output_commitment: Option<String>) -> Self {
        Self {
            id,
            disposition: OrientationStageDisposition::Executed,
            input_commitment: Some(id.expected_input().to_owned()),
            output_commitment,
            reason: None,
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
        }
    }
}

/// Canonical content digest over one owner output value.
///
/// Returns `None` only when canonical serialization fails, which the caller
/// treats as an owner defect.
pub(crate) fn output_digest<T: serde::Serialize>(value: &T) -> Option<String> {
    canonical_bytes(value).ok().map(|bytes| digest_hex(&bytes))
}

/// Proves one ledger covers the published denominator, once per member.
///
/// Two independent properties, both required before a pulse result may be
/// published:
///
/// 1. The ledger holds exactly [`PULSE_EXPECTED_MEMBER_COUNT`] records - the
///    count the canonical denominator identity claims, not the count of the
///    list the records were built from.
/// 2. Every member of [`PulseStageId::ORDER`] appears exactly once, so a
///    duplicated record cannot stand in for a missing member while the total
///    count still matches.
///
/// Returns the static field naming the refusal. Both properties are checked
/// here so a caller cannot forget one; the caller keeps the failure typed.
pub(crate) fn verify_denominator_coverage(
    records: &[OrientationStageRecord],
) -> Result<(), &'static str> {
    if records.len() != PULSE_EXPECTED_MEMBER_COUNT {
        return Err(PULSE_DENOMINATOR_INCOMPLETE);
    }
    for id in PulseStageId::ORDER {
        let occurrences = records
            .iter()
            .filter(|record| record.stage == id.as_str())
            .count();
        if occurrences != 1 {
            return Err(PULSE_DENOMINATOR_INCOMPLETE);
        }
    }
    Ok(())
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
    /// The production carrier's cancellation gate fired.
    ///
    /// Unreachable on the production path as the carrier is composed today:
    /// `ProductionOrientationInputs::cancelled` is a composition-asserted
    /// negative that `resolve_production_inputs` issues as the literal `false`,
    /// so this variant is reachable only from a caller-built carrier.
    #[error("pulse cancelled")]
    Cancelled,
    /// The production carrier deadline passed before composition.
    #[error("pulse deadline exceeded")]
    DeadlineExceeded,
    /// Orientation projector refused; maps through the existing denial table.
    #[error("pulse packet refused")]
    Packet(#[from] OrientationError),
}

impl PulseError {
    /// Converts a pulse error back to the projector error.
    ///
    /// Every variant keeps a distinct refusal: boundary failures name their
    /// static field, each stage refusal names its stage, cancellation and
    /// deadline name their gate, and only the packet owner itself can report
    /// an internal projector failure. Nothing collapses to a generic
    /// `Internal`, so malformed, partial, timeout, cancellation, privacy
    /// refusal, budget exhaustion, stale source, missing owner, and owner
    /// rejection stay independently visible through dispatch.
    pub(crate) fn into_orientation_error(self) -> OrientationError {
        match self {
            Self::Packet(error) => error,
            Self::Boundary(field) => OrientationError::Binding(field),
            Self::Classification => OrientationError::Invalid("pulse classification owner refused"),
            Self::CueActivation => OrientationError::Invalid("pulse cue activation owner refused"),
            Self::Epistemic => OrientationError::Invalid("pulse epistemic position owner refused"),
            Self::Understanding => {
                OrientationError::Invalid("pulse understanding view owner refused")
            }
            Self::Grounding => OrientationError::Invalid("pulse claim grounding owner refused"),
            Self::Rivals => OrientationError::Invalid("pulse rival models owner refused"),
            Self::Conflict => OrientationError::Invalid("pulse conflict analysis owner refused"),
            Self::Probes => OrientationError::Invalid("pulse probe plan owner refused"),
            Self::Candidates => OrientationError::Invalid("pulse context candidates owner refused"),
            Self::Cancelled => OrientationError::Cancelled,
            Self::DeadlineExceeded => OrientationError::RevalidationRequired,
        }
    }
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
            let output = classify(inputs.input, inputs.context, inputs.policy)
                .map_err(|_| PulseError::Classification)?;
            let commitment = output_digest(&output).ok_or(PulseError::Classification)?;
            Ok(PulseStage::executed(
                PulseStageId::Classification,
                Some(commitment),
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
            let commitment = output_digest(&output).ok_or(PulseError::CueActivation)?;
            Ok(PulseStage::executed(
                PulseStageId::CueActivation,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_epistemic_stage(
    position_request: Option<&PositionRequest>,
) -> Result<PulseStage, PulseError> {
    position_request.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::EpistemicPosition)),
        |inputs| {
            let output = resolve(inputs).map_err(|_| PulseError::Epistemic)?;
            let commitment = output_digest(&output).ok_or(PulseError::Epistemic)?;
            Ok(PulseStage::executed(
                PulseStageId::EpistemicPosition,
                Some(commitment),
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
            let output = assemble_active_view(
                inputs.admitted,
                inputs.recipe,
                inputs.approved,
                inputs.quality,
                inputs.policy,
                inputs.measure,
            )
            .map_err(|_| PulseError::Understanding)?;
            // The owner result carries no Serialize form; commit the exact
            // owner-produced serialized bytes instead.
            let commitment = digest_hex(&output.serialized_bytes);
            Ok(PulseStage::executed(
                PulseStageId::Understanding,
                Some(commitment),
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
            let output =
                ground_draft_with_controls(inputs.clone()).map_err(|_| PulseError::Grounding)?;
            let commitment = output_digest(&output).ok_or(PulseError::Grounding)?;
            Ok(PulseStage::executed(
                PulseStageId::Grounding,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_rival_stage(stage: Option<&RivalStage>) -> Result<PulseStage, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Rivals)),
        |inputs| {
            let output = structure_rival_models(
                inputs.bundle,
                inputs.validated_draft,
                inputs.current_position,
                inputs.policy,
            )
            .map_err(|_| PulseError::Rivals)?;
            let commitment = output_digest(&output).ok_or(PulseError::Rivals)?;
            Ok(PulseStage::executed(PulseStageId::Rivals, Some(commitment)))
        },
    )
}

pub(crate) fn run_conflict_stage(stage: Option<&ConflictStage>) -> Result<PulseStage, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Conflict)),
        |inputs| {
            let output = analyze_conflict(
                inputs.item,
                inputs.draft,
                inputs.grounded,
                inputs.conflict_set,
                inputs.supplements,
                inputs.policy,
            )
            .map_err(|_| PulseError::Conflict)?;
            // The owner candidate carries no Serialize form; commit the
            // owner-issued candidate digest instead (#2870 qualifies the
            // one-digest invariant behind it).
            let commitment = output.candidate_digest.clone();
            Ok(PulseStage::executed(
                PulseStageId::Conflict,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_probe_stage(
    params: Option<ProbePlanParams<'_>>,
) -> Result<PulseStage, PulseError> {
    params.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Probes)),
        |inputs| {
            let output = plan_discriminative_probes(inputs).map_err(|_| PulseError::Probes)?;
            let commitment = output_digest(&output).ok_or(PulseError::Probes)?;
            Ok(PulseStage::executed(PulseStageId::Probes, Some(commitment)))
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
) -> Result<PulseStage, PulseError> {
    match (projections, stage) {
        (Some(projection_set), Some(inputs)) => {
            let canonical = CanonicalProjectionInput {
                set: projection_set.clone(),
                measurements: inputs.measurements.to_vec(),
            };
            let output = construct_context_candidates_with_canonical(
                inputs.request,
                inputs.recipe,
                &canonical,
                inputs.attention_and_conflicts,
                inputs.epistemic_position,
                inputs.cue_activation_result,
                inputs.evidence,
                inputs.policy,
            )
            .map_err(|_| PulseError::Candidates)?;
            let commitment = output_digest(&output).ok_or(PulseError::Candidates)?;
            Ok(PulseStage::executed(
                PulseStageId::Candidates,
                Some(commitment),
            ))
        }
        (None, Some(_)) => Ok(PulseStage::pending_reason(
            PulseStageId::Candidates,
            CANDIDATES_REQUIRE_PROJECTIONS,
        )),
        (_, None) => Ok(PulseStage::pending(PulseStageId::Candidates)),
    }
}

#[cfg(test)]
mod pulse_denominator_coverage_tests {
    use super::*;

    /// One ledger record per mandatory member, in denominator order.
    ///
    /// Built from [`PulseStageId::ORDER`] exactly as the composer's blocked and
    /// composed paths build it, so this is the ledger shape production
    /// publishes rather than a hand-assembled lookalike.
    fn complete_ledger() -> Vec<OrientationStageRecord> {
        PulseStageId::ORDER
            .iter()
            .map(|id| OrientationStageRecord {
                stage: id.as_str().to_owned(),
                owner: id.owner_entry().to_owned(),
                required: true,
                disposition: OrientationStageDisposition::Blocked,
                expected_input: id.expected_input().to_owned(),
                input_commitment: None,
                output_commitment: None,
                proof_ceiling: CEILING_BLOCKED.to_owned(),
                reason: Some(id.missing_reason().to_owned()),
                recovery: Some(id.recovery().to_owned()),
            })
            .collect()
    }

    /// The positive case: the ledger the composer actually publishes covers
    /// the published denominator exactly once per member.
    ///
    /// Also pins the count the composer relies on: `PULSE_EXPECTED_MEMBER_COUNT`
    /// is the independent expected set, so it must equal the number of members
    /// `PulseStageId::ORDER` names. If a member is ever added to or removed
    /// from the order without the published claim changing, this fails.
    #[test]
    fn complete_ledger_covers_the_published_denominator() {
        let ledger = complete_ledger();
        assert_eq!(
            ledger.len(),
            PULSE_EXPECTED_MEMBER_COUNT,
            "the published member count must equal the members the order names"
        );
        assert_eq!(
            verify_denominator_coverage(&ledger),
            Ok(()),
            "a complete ledger must satisfy the coverage proof"
        );
    }

    /// The refusal case: a ledger missing one member is refused, not published.
    ///
    /// This is the case the previous self-referential count could not detect -
    /// dropping a member still leaves a ledger that "has as many records as the
    /// order has members" while no longer covering the denominator at all.
    #[test]
    fn ledger_missing_a_member_is_refused() {
        let mut ledger = complete_ledger();
        ledger.retain(|record| record.stage != PulseStageId::Packet.as_str());
        assert_eq!(
            verify_denominator_coverage(&ledger),
            Err(PULSE_DENOMINATOR_INCOMPLETE),
            "a ledger missing a mandatory member must refuse"
        );
    }

    /// The refusal case that only property 2 can catch, and the reason it
    /// exists.
    ///
    /// A duplicated record standing in for a missing one keeps the ledger at
    /// the published count, so property 1 - the independent expected count -
    /// passes it. Dropping the last member and appending a second copy of the
    /// first leaves `len == PULSE_EXPECTED_MEMBER_COUNT` while the denominator
    /// is no longer covered: one member is missing and another is claimed
    /// twice. The exactly-once property is what refuses it.
    #[test]
    fn ledger_duplicate_standing_in_for_a_missing_member_is_refused() {
        let mut ledger = complete_ledger();
        ledger.retain(|record| record.stage != PulseStageId::Packet.as_str());
        ledger.push(complete_ledger()[0].clone());
        assert_eq!(
            ledger.len(),
            PULSE_EXPECTED_MEMBER_COUNT,
            "the substituted ledger still satisfies the published count, so the count alone cannot refuse it"
        );
        assert_eq!(
            verify_denominator_coverage(&ledger),
            Err(PULSE_DENOMINATOR_INCOMPLETE),
            "a duplicate standing in for a missing member must refuse"
        );
    }
}
