//! Learning-derived atom screen for Context Compiler compile/delivery (#1869).
//!
//! I12.24 requires the same verification at delivery as at retrieval:
//! campaign identity, local-admission status, expiry, closure status, State
//! Fence, and cross-task admission. This module is the delivery-side
//! enforcement point, driven by the existing
//! [`assemble_active_view`](crate::assemble_active_view) entrypoint:
//!
//! - The admitted set's compilation fence must exactly match the fence in
//!   the owner-verified permit — drifted compilations refuse before anything
//!   renders, however the set was admitted.
//! - Every requester-declared learning atom must be present in the admitted
//!   records and re-pass the shared retrieval screen
//!   ([`screen_learning_subjects`]) against the same verified permit.
//!   Atoms absent from the claims map are projected exactly as before;
//!   historical behavior is preserved.
//!
//! The screen implementation lives in exactly one place
//! (`eliot-context-admission::learning_gate`); this module only maps
//! admitted records onto it and delegates rendering.

use std::collections::BTreeMap;

use eliot_context_admission::learning_gate::{
    LearningAtomClaim, LearningSubject, screen_learning_subjects,
};
use eliot_context_contracts::{
    AdmittedContextSet, ContextError, ContextRecipe, QualityScorecard, SerializedContextMeasurement,
};
use eliot_contracts::{ArtifactId, fences_match_exact};
use eliot_governor::VerifiedLearningAdmission;

use crate::{ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy, assemble_active_view};

/// Governed compile/delivery entrypoint: re-verify declared learning atoms
/// against an owner-verified permit, then run the unchanged
/// [`assemble_active_view`] projection.
///
/// Fails closed: fence drift, unadmitted-but-claimed atoms, or any screen
/// violation returns `Err` and renders nothing.
pub fn assemble_active_view_with_learning<F>(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
    claims: &BTreeMap<ArtifactId, LearningAtomClaim>,
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<ActiveUnderstandingViewResult, AssemblyError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    if claims.len() > 4096 {
        return Err(AssemblyError::Contract(ContextError::Bounds {
            field: "learning.claims",
        }));
    }
    if !fences_match_exact(&admitted.binding.state_fence, verified.permit().fence()) {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    let mut subjects = Vec::with_capacity(claims.len());
    for (atom_id, claim) in claims {
        let record = admitted
            .records
            .iter()
            .find(|record| record.candidate.atom_id == *atom_id)
            .ok_or(AssemblyError::Contract(ContextError::DenominatorMismatch))?;
        subjects.push(LearningSubject {
            atom_id,
            binding_task_id: record.candidate.binding.task_id.as_str(),
            binding_fence: &record.candidate.binding.state_fence,
            claim,
        });
    }
    screen_learning_subjects(&subjects, verified, now_unix_secs)
        .map_err(AssemblyError::Contract)?;
    assemble_active_view(admitted, recipe, quality, policy, measure)
}
