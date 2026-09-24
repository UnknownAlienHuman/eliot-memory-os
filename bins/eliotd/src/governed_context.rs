//! Native governed Context Compiler delivery owned by `eliotd`.
//!
//! The standalone wasm prototype remains fail-closed for guest-marked input.
//! This module is the native owner-bound path: it composes the already
//! admitted learning candidate, governed retrieval, Context admission, and
//! delivery projection under one live Governor issuance. The daemon
//! composition supplies the owner revalidation and the retained backlog
//! identity check before calling this pure orchestration.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context_admission::admit_context_with_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, ContextError, ContextOutcome, ContextRecipe, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_governor::LearningAdmissionError;
use eliot_improvement::candidate_bounds::{
    BoundsError, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef, retrieve_governed,
};
use eliot_improvement::{
    LearningProduction, PresentedLearning, datetime_from_unix, produce_learning_candidate,
};
use thiserror::Error;

/// One native learning compilation: retrieval, admission, and optional view.
#[derive(Clone, Debug)]
pub struct NativeGovernedCompilation {
    pub retrieval: RetrievalDecision,
    pub admission: AdmissionResult,
    pub view: Option<ActiveUnderstandingViewResult>,
}

/// Every failure refuses the complete native compilation before delivery.
#[derive(Debug, Error, PartialEq)]
pub enum NativeComposeError {
    #[error("producer and screen cite different Governor issuances")]
    PermitMismatch,
    #[error("daemon owner evidence refused native context delivery: {0}")]
    Owner(LearningAdmissionError),
    #[error("campaign overlay record required for native governed retrieval")]
    OverlayRequired,
    #[error("owner clock unavailable")]
    ClockUnavailable,
    #[error("governed production refused: {0}")]
    Production(BoundsError),
    #[error("governed retrieval refused: {0}")]
    Retrieval(BoundsError),
    #[error("governed admission refused: {0}")]
    Admission(ContextError),
    #[error("governed delivery refused: {0}")]
    Assembly(AssemblyError),
}

/// Compose one native learning compilation using the live host clock.
///
/// `production` and `presented` must cite the same owner-issued permit. The
/// caller must have already checked that `presented.backlog` is the daemon's
/// retained backlog; this function itself never creates or selects a
/// registry.
pub(crate) fn compose_governed_native_context<F>(
    production: LearningProduction<'_>,
    presented: PresentedLearning<'_>,
    mut input: AdmissionInput,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<NativeGovernedCompilation, NativeComposeError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if production.verified.permit().digest() != presented.verified.permit().digest() {
        return Err(NativeComposeError::PermitMismatch);
    }
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NativeComposeError::ClockUnavailable)?
        .as_secs();
    let presented = PresentedLearning {
        now_unix_secs,
        ..presented
    };
    let overlay = presented
        .overlay
        .ok_or(NativeComposeError::OverlayRequired)?;
    let permit = presented.verified.permit();
    let produced =
        produce_learning_candidate(production).map_err(NativeComposeError::Production)?;
    let learning = produced
        .learning
        .as_ref()
        .ok_or(NativeComposeError::Retrieval(
            BoundsError::ReusableBackingMismatch,
        ))?;
    let reusable = ReusableCandidateRef {
        candidate_id: learning
            .candidate_id
            .clone()
            .ok_or(NativeComposeError::Retrieval(
                BoundsError::ReusableBackingMismatch,
            ))?,
        closure_ref: learning.closure_ref.clone(),
        owner: learning.owner.clone(),
        origin_campaign_id: permit.source_campaign_id().to_owned(),
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
        now: datetime_from_unix(presented.now_unix_secs).map_err(NativeComposeError::Retrieval)?,
    })
    .map_err(NativeComposeError::Retrieval)?;

    input.candidates.candidates.push(produced);
    input.learning_tickets.push(presented.ticket.clone());
    let admission =
        admit_context_with_learning(&input, presented).map_err(NativeComposeError::Admission)?;
    let view = match &admission.outcome {
        ContextOutcome::Complete(set) => Some(
            assemble_active_view_with_learning(set, recipe, quality, policy, measure, presented)
                .map_err(NativeComposeError::Assembly)?,
        ),
        ContextOutcome::Incomplete(_) => None,
    };
    Ok(NativeGovernedCompilation {
        retrieval,
        admission,
        view,
    })
}
