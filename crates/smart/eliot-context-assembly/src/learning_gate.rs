//! Learning-derived atom screen for Context Compiler compile/delivery (#1869).
//!
//! I12.24 requires the same verification at delivery as at retrieval:
//! campaign identity, local-admission status, expiry, closure status, State
//! Fence, and cross-task admission. This module is the delivery-side
//! enforcement point, driven by the existing
//! [`assemble_active_view`](crate::assemble_active_view) entrypoint:
//!
//! - Learning provenance is intrinsic (`ContextCandidate.learning`): every
//!   admitted atom carrying the mark re-passes the shared governed carriage
//!   check against the same owner-verified permit and live Governor
//!   issuance. There is no sidecar to omit.
//! - The admitted set's compilation fence must exactly match the admitted
//!   fence — drifted compilations refuse before anything renders, however
//!   the set was admitted.
//! - Overlay liveness, reusable backlog backing, and cross-task admission
//!   are enforced through the shared improvement carriage gate, exactly as
//!   at retrieval.
//!
//! The shared carriage implementation lives in exactly one place
//! (`eliot-improvement::governed_screen`); this module only maps admitted
//! records onto it and delegates rendering. Fails closed: fence drift or
//! any screen violation returns `Err` and renders nothing. Unmarked atoms
//! project exactly as before.
//!
//! Host-only logic: this module names the live Governor owner and the
//! governed registries, and must never enter a `wasm32` guest closure. It
//! is gated with `#[cfg(not(target_arch = "wasm32"))]` at the crate root.

use eliot_context_contracts::{
    AdmittedContextSet, ContextError, ContextRecipe, QualityScorecard, SerializedContextMeasurement,
};
use eliot_contracts::fences_match_exact;
use eliot_improvement::{
    CarriageMark, PresentedLearning, bounds_to_context_error, check_governed_carriage,
};

use crate::{ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy, assemble_active_view};

/// Governed compile/delivery entrypoint: re-verify learning-marked admitted
/// atoms against the live Governor issuance, then run the unchanged
/// [`assemble_active_view`] projection.
///
/// Fails closed: ticket, fence, overlay, backlog, cross-task, or per-mark
/// violations return `Err` and render nothing. Unmarked sets project
/// exactly as before.
pub fn assemble_active_view_with_learning<F>(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
    presented: PresentedLearning<'_>,
) -> Result<ActiveUnderstandingViewResult, AssemblyError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if !fences_match_exact(
        &admitted.binding.state_fence,
        presented.verified.permit().fence(),
    ) {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    let mut marks = Vec::new();
    for record in &admitted.records {
        if let Some(provenance) = &record.candidate.learning {
            provenance.validate().map_err(AssemblyError::Contract)?;
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
    check_governed_carriage(&presented, &admitted.binding.state_fence, &marks)
        .map_err(bounds_to_context_error)
        .map_err(AssemblyError::Contract)?;
    assemble_active_view(admitted, recipe, quality, policy, measure)
}
