//! Governed native learning compilation composition (#1869).
//!
//! The owned composed path for learning-derived context: producer output
//! flows through the governed retrieval registry, the admission screen,
//! and the assembly screen into one compiled view, or the whole
//! compilation refuses before any value surfaces:
//!
//! ```text
//! produce_learning_candidate (owner-verified permit + ACTIVE backlog entry
//!   + the distinct cross-task carryover when the compilation is for
//!   another task)
//! → retrieve_governed (overlay liveness, backlog backing, cross-task
//!   carryover)
//! → admit_context_with_learning (ticket re-verification + per-mark screen + admit)
//! → assemble_active_view_with_learning (delivery re-verification + project)
//! → GovernedCompilation (retrieval decision + admission + optional view)
//! ```
//!
//! Composed retrieval always runs in overlay context: the campaign's live
//! `LOCAL_ADMITTED` overlay record is required, per I12.24 ("only the
//! exact non-expired `LOCAL_ADMITTED` overlay of the active campaign may
//! influence a compatible attempt"). Candidate-only permits without overlay
//! context use the lower-level screens directly. An incomplete admission
//! yields no view: what was not admitted is never projected.
//!
//! The produced candidate is appended to the caller-built ordinary input
//! and the presented ticket rides the input's `learning_tickets`, so the
//! wire data and the owner verification never diverge.
//!
//! Host-only logic: this module threads the live Governor issuance and the
//! governed registries, and must never enter a `wasm32` guest closure. It
//! is gated with `#[cfg(not(target_arch = "wasm32"))]` at the crate root.

use crate::conversion::{GuestRequest, GuestResponse, validate_response_shape};
use eliot_context_admission::admit_context_with_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, ContextError, ContextOutcome, ContextRecipe,
    QualityApplicabilityInput, QualityDimensionResult, QualityOperation, QualityOutputBinding,
    QualityRefusal, QualityScorecard, QualitySuitability, SerializedContextMeasurement,
};
use eliot_improvement::candidate_bounds::{
    BoundsError, CrossTaskCarryover, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef,
    retrieve_governed,
};
use eliot_improvement::{
    CarriageMark, LearningProduction, PresentedLearning, bounds_to_context_error,
    check_governed_carriage, datetime_from_unix, produce_learning_candidate,
};
use thiserror::Error;
use time::OffsetDateTime;

/// One governed learning compilation: retrieval decision, admission, and
/// the projected view when admission completed.
#[derive(Clone, Debug)]
pub struct GovernedCompilation {
    pub retrieval: RetrievalDecision,
    pub admission: AdmissionResult,
    pub view: Option<ActiveUnderstandingViewResult>,
    /// Typed quality diagnostics when the view could not be projected.
    ///
    /// `None` exactly when `view` is `Some`. This is the W6 half of the issue
    /// that the plain `Err` return could not express: an incomplete compilation
    /// retains the attempted recipe, the exact output the card claimed to grade,
    /// the complete set of failed and unknown dimension results, and the
    /// operation-scoped refusal — instead of collapsing to a single Display
    /// string and discarding every dimension that did not block. It is a
    /// diagnosis, not a view: `view` stays `None`, so a blocked packet is never
    /// handed to a consumer as a successful Active View.
    pub quality_diagnostic: Option<QualityDiagnostics>,
}

/// Why a compiled packet was not projected, with the evidence that was retained.
///
/// Every field is the owner's own value, carried rather than re-derived. The
/// attempted recipe digest and the card's own output binding are the two exact
/// handles a reader needs to re-run the compilation or to see which output the
/// twelve grades were about; the dimension results are the complete failed and
/// unknown accounting, in canonical dimension order, so a caller never has to
/// guess which anchor, directive or verifier was missing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityDiagnostics {
    /// The operation whose readiness was requested; always named.
    pub operation: QualityOperation,
    /// The recipe this compilation actually attempted, by its own digest. The
    /// attempt is retained even though it produced no view, so a refusal is
    /// reproducible and a retry names the same input.
    pub attempted_recipe_digest: String,
    /// The exact output the scorecard claimed to grade: recipe, fence, admitted
    /// and rendered digests, serializer identity and route, evidence revisions
    /// and omission handles. Retained so the refused grades stay bound to a
    /// named output rather than floating free.
    pub attempted_output: QualityOutputBinding,
    /// Every dimension result that was not a current pass, in canonical
    /// dimension order, with its state and the exact evidence it lacks. This is
    /// the complete failed/unknown accounting, not only the subset that blocked
    /// the requested operation, so nothing is dropped to fit an output limit.
    pub dimension_results: Vec<QualityDimensionResult>,
    /// Applicability inputs that were never resolved for this packet.
    pub unresolved_applicability: Vec<QualityApplicabilityInput>,
    /// The contract owner's own read-only diagnostic-display suitability for
    /// this same card.
    ///
    /// This is the A2 fact, produced by the same
    /// [`QualityScorecard::suitability`] rule every other consumer uses and asked
    /// for the read-only operation. It is `Some` exactly when the card is still
    /// displayable, and its `limitations` carry the same non-passing dimensions
    /// as `dimension_results`. Recording the owner's granted display verdict
    /// here keeps the informational unknown visible without granting any effect:
    /// `QualityOperation::DiagnosticDisplay` requires no dimension and blocks on
    /// no applicability input, which is exactly why it can never be mistaken for
    /// authorization.
    pub display_suitability: Option<QualitySuitability>,
}

impl QualityDiagnostics {
    /// Build the diagnostics for one refused quality readiness check.
    ///
    /// The card is the owner's complete twelve-dimension accounting and the
    /// refusal is its operation-scoped answer; both are carried whole. The
    /// failed and unknown set is recomputed here as the *complement* of the
    /// current passes, read off the card's own twelve results against the
    /// declared dimension denominator, so it cannot be a partial copy of the
    /// refusal's blocking subset and cannot omit a dimension that failed for a
    /// reason unrelated to this operation.
    fn refused(
        refusal: &QualityRefusal,
        quality: &QualityScorecard,
        attempted_recipe_digest: &str,
    ) -> Self {
        Self {
            operation: refusal.operation,
            attempted_recipe_digest: attempted_recipe_digest.to_owned(),
            attempted_output: quality.output.clone(),
            dimension_results: quality
                .results
                .iter()
                .filter(|result| !result.is_current_pass())
                .cloned()
                .collect(),
            unresolved_applicability: refusal.unresolved_applicability.clone(),
            // The same owner rule, asked for the read-only operation. A card that
            // cannot even be shown structurally reports `None`; a merely blocked
            // one is displayable and says so, carrying its limitations.
            display_suitability: quality
                .suitability(QualityOperation::DiagnosticDisplay, &[])
                .ok(),
        }
    }
}

/// Composed-path refusal. Every variant fails the whole compilation closed.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ComposeError {
    #[error("producer and screen cite different Governor issuances")]
    PermitMismatch,
    #[error("campaign overlay record required for composed retrieval")]
    OverlayRequired,
    #[error("owner clock unavailable")]
    ClockUnavailable,
    #[error("governed production refused: {0}")]
    Production(BoundsError),
    #[error("governed retrieval refused: {0}")]
    Retrieval(BoundsError),
    #[error("governed admission refused: {0}")]
    Admission(ContextError),
    #[error("governed assembly refused: {0}")]
    Assembly(AssemblyError),
}

/// Both surfaces must cite the same distinct cross-task admission, or neither
/// may cite one.
///
/// The producer and the retrieval/carriage screens are separate owners of the
/// two cross-task checks, so a caller that threaded one carryover into
/// production and another into the screens would let a stale record produce an
/// atom for a task the screens never checked. Identity is the owner-issued
/// pair, not the object identity: both the cross-task ticket digest and the
/// record's `admission_id` must agree, because either alone can be copied onto
/// a different record.
fn same_cross_task_carryover(
    production: Option<&CrossTaskCarryover<'_>>,
    presented: Option<&CrossTaskCarryover<'_>>,
) -> bool {
    match (production, presented) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.cross_task_permit().digest() == right.cross_task_permit().digest()
                && left.record().admission_id == right.record().admission_id
        }
        _ => false,
    }
}

/// Compose one governed learning compilation from producer output.
///
/// `production` carries everything the producer needs (including the
/// owner-verified local permit, the distinct cross-task carryover when the
/// compilation is for another task, and the production backlog); `presented`
/// carries the same issuance plus the same carryover, the overlay, registry,
/// and requesting identity for the screens. Both verified handles must cite the
/// exact same issuance digest, and the carryover must be the same one on both
/// sides. `input` is the caller-built ordinary admission input the produced
/// atom joins.
///
/// The wall clock is sourced LIVE from the host owner clock
/// ([`OffsetDateTime::now_utc`]) inside this function: any
/// caller-supplied `now_unix_secs` in `presented` is ignored, so requester
/// envelopes can never backdate mark/overlay expiry. Direct screen callers
/// (outside this composition) MUST likewise pass owner-sourced time, never
/// requester values.
///
/// # A quality refusal is a result, not a transport failure
///
/// When the scorecard cannot support the requested operation the composition
/// still returns `Ok`, with `view: None` and `quality_diagnostic` populated.
/// A blocked packet therefore never reaches a consumer as a successful Active
/// View, and the caller keeps the attempted recipe digest, the exact output
/// handles the card claimed to grade, and the complete failed and unknown
/// dimension results with the evidence each still lacks — instead of the
/// single Display string that [`ComposeError::Assembly`] would render. Every
/// other assembly failure is unchanged and still returns `Err`.
pub fn compose_governed_compilation<F>(
    production: LearningProduction<'_>,
    presented: PresentedLearning<'_>,
    mut input: AdmissionInput,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<GovernedCompilation, ComposeError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if production.verified.permit().digest() != presented.verified.permit().digest()
        || !same_cross_task_carryover(production.cross_task, presented.cross_task)
    {
        return Err(ComposeError::PermitMismatch);
    }
    let live_now_secs = u64::try_from(OffsetDateTime::now_utc().unix_timestamp().max(0))
        .map_err(|_| ComposeError::ClockUnavailable)?;
    let presented = PresentedLearning {
        now_unix_secs: live_now_secs,
        ..presented
    };
    let overlay = presented.overlay.ok_or(ComposeError::OverlayRequired)?;
    let permit = presented.verified.permit();
    let produced = produce_learning_candidate(production).map_err(ComposeError::Production)?;
    let reusable = ReusableCandidateRef {
        candidate_id: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.candidate_id.clone())
            .ok_or(ComposeError::Retrieval(
                BoundsError::ReusableBackingMismatch,
            ))?,
        closure_ref: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.closure_ref.clone()),
        owner: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.owner.clone()),
        origin_campaign_id: permit.source_campaign_id().to_string(),
    };
    let retrieval = retrieve_governed(GovernedRetrieval {
        requesting_campaign_id: presented.requesting_campaign_id,
        requesting_task_id: presented.requesting_task_id,
        overlay,
        reusable: Some(&reusable),
        draft_delta_present: false,
        cross_task: presented.cross_task,
        backlog: presented.backlog,
        verified: presented.verified,
        now: datetime_from_unix(presented.now_unix_secs).map_err(ComposeError::Retrieval)?,
    })
    .map_err(ComposeError::Retrieval)?;
    input.candidates.candidates.push(produced);
    input.learning_tickets.push(presented.ticket.clone());
    let admission =
        admit_context_with_learning(&input, presented).map_err(ComposeError::Admission)?;
    // The attempted recipe digest is read from the recipe this call was given,
    // before it is consumed by assembly. It is the exact handle the retained
    // diagnostics name, so a refusal names the compilation that was attempted
    // rather than a generic quality failure.
    let attempted_recipe_digest = recipe.recipe_sha256.clone();
    let view = match &admission.outcome {
        ContextOutcome::Complete(set) => {
            // A quality refusal is not a transport failure and must not be
            // collapsed into one. `AssemblyError::QualityIncomplete` already
            // carries the whole card and the operation-scoped refusal; this arm
            // converts that into the host-facing diagnostic, so the caller keeps
            // the attempted recipe, the exact output handles and the complete
            // failed/unknown dimension accounting. Every other assembly failure
            // still propagates as a `ComposeError`, unchanged.
            match assemble_active_view_with_learning(
                set,
                recipe,
                quality.clone(),
                policy,
                measure,
                presented,
            ) {
                Ok(result) => Some(result),
                Err(AssemblyError::QualityIncomplete(card, refusal)) => {
                    return Ok(GovernedCompilation {
                        retrieval,
                        admission,
                        view: None,
                        quality_diagnostic: Some(QualityDiagnostics::refused(
                            &refusal,
                            &card,
                            &attempted_recipe_digest,
                        )),
                    });
                }
                Err(error) => return Err(ComposeError::Assembly(error)),
            }
        }
        ContextOutcome::Incomplete(_) => None,
    };
    Ok(GovernedCompilation {
        retrieval,
        admission,
        view,
        quality_diagnostic: None,
    })
}

/// Host-side honored-output refusal: why a `GuestResponse` must not be honored.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HonorError {
    /// Response envelope does not echo the request it answers.
    #[error("guest response does not match its request envelope")]
    EnvelopeMismatch,
    /// The exclusive result-or-error choice is violated: both a result and an
    /// error are present, or neither is. Malformed contour output (#638).
    #[error("guest response carries both or neither of result and error")]
    MalformedOutput,
    /// Admitted binding drifted from the requested compilation binding.
    #[error("admitted binding does not match the requested compilation")]
    BindingMismatch,
    /// Admitted input digest does not recompute from the request: the
    /// response answers a different input (substitution).
    #[error("admitted input digest does not bind the request")]
    DigestMismatch,
    /// Owner carriage refusal over the admitted marked atoms.
    #[error("owner carriage refused the admitted learning atoms: {0}")]
    Carriage(ContextError),
}

/// Host-side honored-output check: validate a `GuestResponse` against the
/// request that produced it and the LIVE Governor issuance before the host
/// honors anything admitted in it.
///
/// This is the choke point the wasm-host composition root calls after the
/// guest (or native) retrieval returns and before any admitted atom
/// influences an attempt:
///
/// 1. envelope coherence (ABI/handler echo) and result/error presence;
/// 2. admitted binding equals the requested compilation binding
///    (task identity plus exact State Fence);
/// 3. admitted input digest recomputes from the exact request (binds the
///    response to these bytes — substitution refused);
/// 4. when the result carries learning-marked atoms (or the request
///    carried tickets), the full owner carriage gate
///    ([`check_governed_carriage`]) runs with the live Governor,
///    registry, overlay, and cross-task carryover — epoch/generation
///    rotation, dead overlays, revoked backlog entries, and unadmitted
///    cross-task use refuse here even if the producing contour passed
///    them structurally.
///
/// Unmarked results over unticketed requests pass on coherence alone;
/// ordinary evidence decides exactly as before. `presented.now_unix_secs`
/// MUST be owner/host-sourced live time, never a requester value (the
/// composed entry re-sources it itself).
pub fn check_honored_output(
    request: &GuestRequest,
    response: &GuestResponse,
    presented: PresentedLearning<'_>,
) -> Result<(), HonorError> {
    if response.abi_version != request.abi_version
        || response.handler_subtype != request.handler_subtype
    {
        return Err(HonorError::EnvelopeMismatch);
    }
    // Exclusive result-or-error choice, enforced on the typed value before the
    // error-only return so a direct typed caller cannot smuggle a foreign
    // result past the binding, input-digest and carriage checks below by
    // pairing it with an error.
    validate_response_shape(response).map_err(|_| HonorError::MalformedOutput)?;
    if response.error.is_some() {
        return Ok(());
    }
    let Some(admission) = &response.result else {
        return Err(HonorError::MalformedOutput);
    };
    if admission.binding.task_id.as_str() != request.input.binding.task_id.as_str()
        || !eliot_contracts::fences_match_exact(
            &admission.binding.state_fence,
            &request.input.binding.state_fence,
        )
    {
        return Err(HonorError::BindingMismatch);
    }
    let input_digest = request
        .input
        .canonical_digest()
        .map_err(|_| HonorError::DigestMismatch)?;
    if input_digest != admission.input_digest {
        return Err(HonorError::DigestMismatch);
    }
    let marked = match &admission.outcome {
        ContextOutcome::Complete(set) => set
            .records
            .iter()
            .any(|record| record.candidate.learning.is_some()),
        ContextOutcome::Incomplete(_) => false,
    };
    if !marked && request.input.learning_tickets.is_empty() {
        return Ok(());
    }
    let mut marks = Vec::new();
    if let ContextOutcome::Complete(set) = &admission.outcome {
        for record in &set.records {
            if let Some(provenance) = &record.candidate.learning {
                provenance.validate().map_err(HonorError::Carriage)?;
                marks.push(CarriageMark {
                    campaign_id: provenance.campaign_id.as_str(),
                    overlay_id: provenance.overlay_id.as_deref(),
                    candidate_id: provenance.candidate_id.as_deref(),
                    closure_ref: provenance.closure_ref.as_deref(),
                    owner: provenance.owner.as_deref(),
                    draft: provenance.draft,
                    expires_at_unix_secs: provenance.expires_at_unix_secs,
                    permit_digest: provenance.permit_digest.as_str(),
                    binding_task_id: record.candidate.binding.task_id.as_str(),
                });
            }
        }
    }
    check_governed_carriage(&presented, &admission.binding.state_fence, &marks)
        .map_err(bounds_to_context_error)
        .map_err(HonorError::Carriage)
}
