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
//! a typed blocked result, never a packet. [`run_orientation_pulse`] remains a
//! generic partial composer only behind an explicit [`PulseDenominator`]: a
//! stage whose caller-supplied inputs are absent records an explicit pending
//! disposition and never blocks the packet; a stage whose inputs are present
//! but whose owner refuses fails that composition, so a partial pulse is never
//! thinned into a packet silently. The packet-only compatibility wrapper
//! ([`run_compat_orientation_pulse`]) is not the production pulse and cannot
//! satisfy the #41 Product Pulse acceptance. Error payloads are bounded static
//! fields; nothing secret flows.
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
use eliot_cue_activation::{
    ActivationProfile, CueActivationEvaluation, PublicationGrant, SpreadEnablement,
    SpreadQualification, blocking_evidence, direct_activations, evaluate_activation,
    evaluate_published_activation, resolve_enablement,
};
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
    ValidatedDreamDraft, ValidatedGroundingCandidate, bundle_digest_of, canonical_bytes,
    digest_hex,
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
    /// Work scope this operation is admitted in.
    pub scope_id: eliot_cue_contracts::WorkScopeId,
    /// Runtime identity the qualification is compared against.
    pub runtime_identity: &'a str,
    /// Immutable qualification evidence for enabling relation spreading.
    ///
    /// `None` is the default and means spreading stays disabled. A
    /// direct-only request never consults it.
    pub qualification: Option<&'a SpreadQualification>,
    /// Live publication grant this operation reads under.
    ///
    /// `None` means the caller supplied only a build candidate. That is enough
    /// for the pure seam, and it is not enough to claim a live publication, so
    /// the stage records that the evaluated publication was not granted.
    pub publication: Option<&'a PublicationGrant>,
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

/// Explicit composition denominator: the expected member set plus the
/// boundary policy the composition answers to.
pub(crate) struct PulseDenominator {
    /// Canonical denominator identity carried by the result.
    pub identity: &'static str,
    /// Expected members in composition order.
    pub members: &'static [PulseStageId],
    /// Whether CC-002/CC-004 boundaries are mandatory prerequisites.
    pub boundaries_required: bool,
}

/// Mandatory production denominator: all ten members plus both boundaries.
pub(crate) const MANDATORY_DENOMINATOR: PulseDenominator = PulseDenominator {
    identity: PULSE_DENOMINATOR_IDENTITY,
    members: &PulseStageId::ORDER,
    boundaries_required: true,
};

/// Compatibility denominator: same ten members, boundaries optional, absent
/// stage inputs record pending instead of blocking. Packet-only compositions
/// under this denominator are candidate-only compatibility output and cannot
/// satisfy the #41 Product Pulse acceptance.
pub(crate) const COMPAT_DENOMINATOR: PulseDenominator = PulseDenominator {
    identity: PULSE_DENOMINATOR_IDENTITY,
    members: &PulseStageId::ORDER,
    boundaries_required: false,
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
pub(crate) struct PulseStage<T> {
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
    /// Owner output, present exactly when executed.
    pub output: Option<T>,
}

impl<T> PulseStage<T> {
    fn executed(id: PulseStageId, output: T, output_commitment: Option<String>) -> Self {
        Self {
            id,
            disposition: OrientationStageDisposition::Executed,
            input_commitment: Some(id.expected_input().to_owned()),
            output_commitment,
            reason: None,
            output: Some(output),
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
            output: None,
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
            output: None,
        }
    }

    /// Whether this member holds the compatibility contract: pending with a
    /// reason and no output.
    fn is_pending_compat(&self) -> bool {
        self.disposition == OrientationStageDisposition::Pending
            && self.reason.is_some()
            && self.output.is_none()
    }
}

/// Canonical content digest over one owner output value.
///
/// Returns `None` only when canonical serialization fails, which the caller
/// treats as an owner defect.
pub(crate) fn output_digest<T: serde::Serialize>(value: &T) -> Option<String> {
    canonical_bytes(value).ok().map(|bytes| digest_hex(&bytes))
}

/// Complete Orientation pulse request: CC-002/CC-004 boundary values, the
/// always-required packet inputs, and optional per-stage owner inputs.
///
/// The explicit denominator names the member set this composition answers
/// to; production never builds this request directly (it composes from the
/// versioned carrier with mandatory boundaries instead).
pub(crate) struct OrientationPulseRequest<'a, F> {
    /// Explicit composition denominator carried by the result.
    pub denominator: &'static PulseDenominator,
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

/// Complete Orientation pulse: the expected denominator, one disposition
/// per stage, plus the packet.
pub(crate) struct OrientationPulse {
    /// Explicit denominator this composition answered to.
    pub denominator: &'static PulseDenominator,
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

impl OrientationPulse {
    /// Verifies the compatibility contract: a boundaries-optional
    /// denominator with every non-packet member pending.
    ///
    /// This is a compatibility-seam self-check, not a production invariant:
    /// production answers to the mandatory denominator with typed
    /// complete/partial/blocked results instead.
    pub(crate) fn verify_compat(&self) {
        debug_assert!(!self.denominator.boundaries_required);
        debug_assert!(self.classification.is_pending_compat());
        debug_assert!(self.cue_activation.is_pending_compat());
        debug_assert!(self.epistemic_position.is_pending_compat());
        debug_assert!(self.understanding.is_pending_compat());
        debug_assert!(self.grounding.is_pending_compat());
        debug_assert!(self.rivals.is_pending_compat());
        debug_assert!(self.conflict.is_pending_compat());
        debug_assert!(self.probes.is_pending_compat());
        debug_assert!(self.candidates.is_pending_compat());
    }
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

/// Measurement closure used when the understanding stage is absent.
///
/// The concrete `fn` type pins the request generic parameter; it is never
/// invoked because the stage is `None`.
type NoMeasurement = fn(&[u8]) -> Result<SerializedContextMeasurement, ContextError>;

fn no_understanding<'a>() -> Option<UnderstandingStage<'a, NoMeasurement>> {
    None
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
) -> Result<PulseStage<ClassificationResult>, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Classification)),
        |inputs| {
            let output = classify(inputs.input, inputs.context, inputs.policy)
                .map_err(|_| PulseError::Classification)?;
            let commitment = output_digest(&output).ok_or(PulseError::Classification)?;
            Ok(PulseStage::executed(
                PulseStageId::Classification,
                output,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_cue_stage(
    stage: Option<&CueActivationStage>,
) -> Result<PulseStage<CueActivationEvaluation>, PulseError> {
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::CueActivation)),
        |inputs| {
            check_spread_enablement(inputs)?;
            let output = evaluate_under_publication(inputs)?;
            // The pulse records the blocking disposition this stage carries. A
            // derived-only result carries none, so a graph score cannot reach
            // the packet as a block; an exact direct hit still can, on the
            // direct activations named rather than on a summary.
            let blocking = cue_blocking_disposition(&output);
            if blocking && direct_activations(&output.result).is_empty() {
                return Err(PulseError::CueActivation);
            }
            let commitment = output_digest(&output).ok_or(PulseError::CueActivation)?;
            Ok(PulseStage::executed(
                PulseStageId::CueActivation,
                output,
                Some(commitment),
            ))
        },
    )
}

/// Refuses relation spreading that no qualification admits.
///
/// Default enablement is decided at the runtime composition, not in a source
/// comment. A request that asks for relation spreading carries immutable
/// qualification evidence naming the exact weights, registry, normalization
/// revision and runtime identity; without a matching qualification the stage
/// refuses rather than running an unqualified spread. A direct-only request
/// needs no qualification and keeps its exact cue either way.
fn check_spread_enablement(inputs: &CueActivationStage<'_>) -> Result<(), PulseError> {
    if inputs.request.is_direct_only() {
        return Ok(());
    }
    let enablement = resolve_enablement(
        inputs.qualification,
        inputs.profile,
        &inputs.request.normalization_profile,
        &inputs.scope_id,
        inputs.runtime_identity,
        &inputs.request.observed_at,
    );
    if enablement == SpreadEnablement::Disabled {
        return Err(PulseError::CueActivation);
    }
    Ok(())
}

/// Evaluates the request under the publication evidence the caller supplied.
///
/// With a grant, the exact live publication, disclosure and influence state are
/// bound before evaluation, so a build candidate is never evaluated as a live
/// publication and a limited direct read is refused rather than answered.
/// Without one the pure seam runs, and the caller is the party that knows no
/// publication was granted; this seam does not manufacture a grant.
fn evaluate_under_publication(
    inputs: &CueActivationStage<'_>,
) -> Result<CueActivationEvaluation, PulseError> {
    match inputs.publication {
        Some(grant) => evaluate_published_activation(
            grant,
            inputs.request,
            inputs.profile,
            &inputs.scope_id,
        ),
        None => evaluate_activation(inputs.candidate, inputs.request, inputs.profile),
    }
    .map_err(|_| PulseError::CueActivation)
}

pub(crate) fn run_epistemic_stage(
    position_request: Option<&PositionRequest>,
) -> Result<PulseStage<ResolvedEpistemicPosition>, PulseError> {
    position_request.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::EpistemicPosition)),
        |inputs| {
            let output = resolve(inputs).map_err(|_| PulseError::Epistemic)?;
            let commitment = output_digest(&output).ok_or(PulseError::Epistemic)?;
            Ok(PulseStage::executed(
                PulseStageId::EpistemicPosition,
                output,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_understanding_stage<F>(
    stage: Option<UnderstandingStage<'_, F>>,
) -> Result<PulseStage<ActiveUnderstandingViewResult>, PulseError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    stage.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Understanding)),
        |inputs| {
            let output = assemble_active_view(
                inputs.admitted,
                inputs.recipe,
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
                output,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_grounding_stage(
    grounding_request: Option<&GroundingRequest>,
) -> Result<PulseStage<GroundedClaimDraft>, PulseError> {
    grounding_request.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Grounding)),
        |inputs| {
            let output =
                ground_draft_with_controls(inputs.clone()).map_err(|_| PulseError::Grounding)?;
            let commitment = output_digest(&output).ok_or(PulseError::Grounding)?;
            Ok(PulseStage::executed(
                PulseStageId::Grounding,
                output,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_rival_stage(
    stage: Option<&RivalStage>,
) -> Result<PulseStage<StructuredRivalModelSet>, PulseError> {
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
            Ok(PulseStage::executed(
                PulseStageId::Rivals,
                output,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_conflict_stage(
    stage: Option<&ConflictStage>,
) -> Result<PulseStage<ConflictAnalysisCandidate>, PulseError> {
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
                output,
                Some(commitment),
            ))
        },
    )
}

pub(crate) fn run_probe_stage(
    params: Option<ProbePlanParams<'_>>,
) -> Result<PulseStage<ProbePlan>, PulseError> {
    params.map_or_else(
        || Ok(PulseStage::pending(PulseStageId::Probes)),
        |inputs| {
            let output = plan_discriminative_probes(inputs).map_err(|_| PulseError::Probes)?;
            let commitment = output_digest(&output).ok_or(PulseError::Probes)?;
            Ok(PulseStage::executed(
                PulseStageId::Probes,
                output,
                Some(commitment),
            ))
        },
    )
}

/// The blocking disposition this cue stage is allowed to carry into the pulse.
///
/// This is the consumer-side answer to "may this result block?". It is a
/// projection of the owner-produced result, not a new authority: an exact direct
/// hit may block, and only on the direct activations named here, so the evidence
/// a block would rest on is carried rather than summarized. A derived-only
/// result is advisory and never blocks. A real safety rule reached through a
/// derived candidate must still pass its own exact scope, trigger and authority
/// gate; this seam does not attempt that gate and does not claim it passed.
fn cue_blocking_disposition(output: &CueActivationEvaluation) -> bool {
    blocking_evidence(&output.result)
        .map(|evidence| !evidence.is_empty())
        .unwrap_or(false)
}

/// Pending reason when the candidate stage has owner inputs but the CC-004
/// projection boundary is absent.
pub(crate) const CANDIDATES_REQUIRE_PROJECTIONS: &str =
    "pulse context candidates require CC-004 projection set";

pub(crate) fn run_candidate_stage(
    projections: Option<&CanonicalProjectionSet>,
    stage: Option<&CandidateStage>,
) -> Result<PulseStage<ContextCandidateSetResult>, PulseError> {
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
                output,
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

/// Runs the generic partial Orientation pulse through the named owner entries.
///
/// This composer stays behind the explicit request denominator: supplied
/// boundary values validate first; each present stage executes in pulse order
/// and any owner refusal fails the composition before the packet; absent stage
/// inputs record explicit pending dispositions. The packet always projects
/// from the caller-supplied validated candidate, bundle, handles, and policy.
/// Production never calls this directly; it composes from the versioned
/// carrier with mandatory boundaries instead.
pub(crate) fn run_orientation_pulse<F>(
    request: OrientationPulseRequest<'_, F>,
) -> Result<OrientationPulse, PulseError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if request.denominator.boundaries_required
        && (request.model_outcome.is_none() || request.projections.is_none())
    {
        return Err(PulseError::Boundary("production boundaries required"));
    }
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
        denominator: request.denominator,
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

/// Runs the packet-only compatibility pulse: packet inputs only, every other
/// stage explicitly pending.
///
/// This is the compatibility call site for the pulse composer, retained so the
/// packet path stays byte-stable while production moves to typed
/// complete/partial/blocked results. It is not the production pulse and its
/// output cannot satisfy the #41 Product Pulse acceptance.
pub(crate) fn run_compat_orientation_pulse(
    admitted_job: &AdmittedOrientationJob,
    validated_candidate: &ValidatedCandidate,
    bundle: &DreamInputBundle,
    policy: &OrientationPolicy,
) -> Result<OrientationPulse, PulseError> {
    run_orientation_pulse(OrientationPulseRequest {
        denominator: &COMPAT_DENOMINATOR,
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
    })
}
