//! Governed native learning compilation composition (#1869).
//!
//! The owned composed path for learning-derived context: producer output
//! flows through the governed retrieval registry, the admission screen,
//! and the assembly screen into one compiled view, or the whole
//! compilation refuses before any value surfaces:
//!
//! ```text
//! produce_learning_candidate (owner-verified permit + ACTIVE backlog entry)
//! → retrieve_governed (overlay liveness, backlog backing, cross-task admission)
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

use eliot_context_admission::admit_context_with_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy, assemble_active_view_with_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, ContextError, ContextOutcome, ContextRecipe, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_improvement::{
    LearningProduction, PresentedLearning, datetime_from_unix, produce_learning_candidate,
};
use eliot_improvement::candidate_bounds::{
    BoundsError, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef, retrieve_governed,
};
use thiserror::Error;

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
    if production.verified.permit().digest() != presented.verified.permit().digest() {
        return Err(ComposeError::PermitMismatch);
    }
    let overlay = presented.overlay.ok_or(ComposeError::OverlayRequired)?;
    let permit = presented.verified.permit();
    let produced = produce_learning_candidate(production).map_err(ComposeError::Production)?;
    let reusable = ReusableCandidateRef {
        candidate_id: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.candidate_id.clone())
            .ok_or(ComposeError::Retrieval(BoundsError::ReusableBackingMismatch))?,
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
        admit_context_with_learning(&input, presented).map_err(ComposeError::Admission)?;
    let view = match &admission.outcome {
        ContextOutcome::Complete(set) => Some(
            assemble_active_view_with_learning(set, recipe, quality, policy, measure, presented)
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
