//! Governed native learning compilation composition (#1869).
//!
//! The owned composed path for learning-derived context: producer output
//! flows through the governed retrieval registry, the admission screen,
//! and the assembly screen into one compiled view, or the whole
//! compilation refuses before any value surfaces:
//!
//! ```text
//! produce_learning_candidate (record-bound owner-verified permit + ACTIVE backlog entry)
//! → retrieve_governed (overlay liveness, backlog backing, cross-task admission)
//! → admit_context_with_record_learning (record ticket + per-mark screen + admit)
//! → assemble_active_view_with_record_learning (delivery re-verification + project)
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

use crate::conversion::{GuestRequest, GuestResponse};
use eliot_context_admission::admit_context_with_record_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_record_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, ContextError, ContextOutcome, ContextRecipe, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_improvement::candidate_bounds::{
    BoundsError, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef, retrieve_governed,
};
use eliot_improvement::{
    CarriageMark, LearningProduction, PresentedRecordLearning, bounds_to_context_error,
    check_governed_record_carriage, datetime_from_unix, produce_learning_candidate,
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

/// Compose one governed learning compilation from producer output.
///
/// `production` carries everything the producer needs (including the
/// owner-verified permit and the production backlog); `presented` carries
/// the same issuance plus the overlay, registry, cross-task admission,
/// and requesting identity for the screens. Both verified handles must
/// cite the exact same issuance digest. `input` is the caller-built
/// ordinary admission input the produced atom joins.
///
/// The wall clock is sourced LIVE from the host owner clock
/// ([`OffsetDateTime::now_utc`]) inside this function: any
/// caller-supplied `now_unix_secs` in `presented` is ignored, so requester
/// envelopes can never backdate mark/overlay expiry. Direct screen callers
/// (outside this composition) MUST likewise pass owner-sourced time, never
/// requester values.
pub fn compose_governed_compilation<F>(
    production: LearningProduction<'_>,
    presented: PresentedRecordLearning<'_>,
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
        || production.verified.record_identity() != presented.verified.record_identity()
    {
        return Err(ComposeError::PermitMismatch);
    }
    let live_now_secs = u64::try_from(OffsetDateTime::now_utc().unix_timestamp().max(0))
        .map_err(|_| ComposeError::ClockUnavailable)?;
    let live_now_ms =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .map_err(|_| ComposeError::ClockUnavailable)?;
    let presented = PresentedRecordLearning {
        now_unix_secs: live_now_secs,
        now_unix_ms: live_now_ms,
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
        cross_task_admission: presented.cross_task_admission,
        backlog: presented.backlog,
        verified: presented.verified,
        now: datetime_from_unix(presented.now_unix_secs).map_err(ComposeError::Retrieval)?,
    })
    .map_err(ComposeError::Retrieval)?;
    input.candidates.candidates.push(produced);
    input.learning_tickets.push(presented.ticket.clone());
    let admission =
        admit_context_with_record_learning(&input, presented).map_err(ComposeError::Admission)?;
    let view = match &admission.outcome {
        ContextOutcome::Complete(set) => Some(
            assemble_active_view_with_record_learning(
                set, recipe, quality, policy, measure, presented,
            )
            .map_err(ComposeError::Assembly)?,
        ),
        ContextOutcome::Incomplete(_) => None,
    };
    Ok(GovernedCompilation {
        retrieval,
        admission,
        view,
    })
}

/// Host-side honored-output refusal: why a `GuestResponse` must not be honored.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HonorError {
    /// Response envelope does not echo the request it answers.
    #[error("guest response does not match its request envelope")]
    EnvelopeMismatch,
    /// Neither result nor error is present: malformed contour output.
    #[error("guest response carries neither result nor error")]
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
///    ([`check_governed_record_carriage`]) runs with the live Governor,
///    registry, overlay, and cross-task admission — epoch/generation
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
    presented: PresentedRecordLearning<'_>,
) -> Result<(), HonorError> {
    if response.abi_version != request.abi_version
        || response.handler_subtype != request.handler_subtype
    {
        return Err(HonorError::EnvelopeMismatch);
    }
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
            if record.candidate.binding.scope_id != admission.binding.scope_id {
                return Err(HonorError::Carriage(ContextError::IdentityConflict));
            }
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
                    record: provenance.record.as_ref(),
                });
            }
        }
    }
    check_governed_record_carriage(
        &presented,
        admission.binding.scope_id.as_str(),
        &admission.binding.state_fence,
        &marks,
    )
    .map_err(bounds_to_context_error)
    .map_err(HonorError::Carriage)
}
