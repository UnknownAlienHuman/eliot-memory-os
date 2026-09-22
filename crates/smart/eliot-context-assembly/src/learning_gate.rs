//! Learning-derived atom screen for Context Compiler compile/delivery (#1869).
//!
//! I12.24 requires the same verification at delivery as at retrieval:
//! campaign identity, local-admission status, expiry, closure status, State
//! Fence, and cross-task admission. This module is the delivery-side
//! enforcement point, driven by the existing
//! [`assemble_active_view`](crate::assemble_active_view) entrypoint:
//!
//! - Learning provenance is intrinsic (`ContextCandidate.learning`): every
//!   admitted atom carrying the mark re-passes the shared retrieval screen
//!   against the same owner-verified permit. There is no sidecar to omit.
//! - The admitted set's compilation fence must exactly match the admitted
//!   fence — drifted compilations refuse before anything renders, however
//!   the set was admitted.
//!
//! The screen implementation lives in exactly one place
//! (`eliot-context-admission::learning_gate`); this module only maps
//! admitted records onto it and delegates rendering.

use eliot_context_admission::learning_gate::{LearningSubject, screen_learning_subjects};
use eliot_context_contracts::{
    AdmittedContextSet, ContextError, ContextRecipe, QualityScorecard, SerializedContextMeasurement,
};
use eliot_contracts::fences_match_exact;
use eliot_governor::VerifiedLearningAdmission;

use crate::{ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy, assemble_active_view};

/// Governed compile/delivery entrypoint: re-verify learning-marked admitted
/// atoms against an owner-verified permit, then run the unchanged
/// [`assemble_active_view`] projection.
///
/// Fails closed: fence drift or any screen violation returns `Err` and
/// renders nothing. Unmarked atoms project exactly as before.
pub fn assemble_active_view_with_learning<F>(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<ActiveUnderstandingViewResult, AssemblyError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if !fences_match_exact(&admitted.binding.state_fence, verified.permit().fence()) {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    let mut subjects = Vec::new();
    for record in &admitted.records {
        if let Some(provenance) = &record.candidate.learning {
            provenance.validate().map_err(AssemblyError::Contract)?;
            subjects.push(LearningSubject {
                atom_id: &record.candidate.atom_id,
                binding_task_id: record.candidate.binding.task_id.as_str(),
                binding_fence: &record.candidate.binding.state_fence,
                provenance,
            });
        }
    }
    screen_learning_subjects(&subjects, verified, now_unix_secs)
        .map_err(AssemblyError::Contract)?;
    assemble_active_view(admitted, recipe, quality, policy, measure)
}
