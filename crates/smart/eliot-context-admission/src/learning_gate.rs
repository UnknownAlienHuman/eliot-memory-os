//! Learning-derived candidate screen for Context Compiler retrieval (#1869).
//!
//! I12.24 requires that retrieval verify campaign identity, local-admission
//! status, expiry, closure status, State Fence, and cross-task admission
//! before exposing any overlay/candidate-derived behavior. This module is the
//! retrieval-side enforcement point, driven by the existing
//! [`admit_context`](crate::admit_context) entrypoint:
//!
//! - Learning provenance is *intrinsic*: [`LearningProvenance`] rides on the
//!   candidate itself (`ContextCandidate.learning`) and is covered by the
//!   candidate canonical digest, so stripping or altering it changes the atom
//!   identity and breaks bound measurements (I5.26: adapter normalization
//!   does not clear lineage). There is no sidecar to omit: any atom carrying
//!   the mark must pass this screen, and atoms without it are ordinary
//!   evidence with ordinary checks and no learning treatment.
//! - Every marked atom must match an owner-verified Governor permit
//!   ([`VerifiedLearningAdmission`], constructible only by the Governor
//!   owner): origin campaign, target task, exact State Fence, overlay and/or
//!   reusable-candidate subject, the exact cited issuance digest, liveness,
//!   non-draft state, and closed+owned reusable status. Any failure refuses
//!   the whole retrieval ([`ContextError`]) before any value surfaces.
//! - Cross-task rule: the compilation task must equal the permit's admitted
//!   target task. A different task needs its own owner-issued permit —
//!   permits do not stretch, and bare strings never authorize.

use eliot_context_contracts::{AdmissionInput, AdmissionResult, ContextError, LearningProvenance};
use eliot_contracts::{ArtifactId, StateFence, fences_match_exact};
use eliot_governor::VerifiedLearningAdmission;

use crate::admit_context;

/// One learning-marked atom with its compilation identity, for screening.
pub struct LearningSubject<'a> {
    pub atom_id: &'a ArtifactId,
    pub binding_task_id: &'a str,
    pub binding_fence: &'a StateFence,
    pub provenance: &'a LearningProvenance,
}

/// Screen learning-marked atoms against an owner-verified permit.
///
/// Fail-closed: the first violation refuses the whole retrieval. Order:
/// origin campaign, target task, exact fence, cited issuance digest,
/// overlay subject, candidate subject, expiry, draft state, reusable
/// closure/owner status.
pub fn screen_learning_subjects(
    subjects: &[LearningSubject<'_>],
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<(), ContextError> {
    if subjects.len() > 4096 {
        return Err(ContextError::Bounds {
            field: "learning.subjects",
        });
    }
    let permit = verified.permit();
    for subject in subjects {
        let mark = subject.provenance;
        if mark.campaign_id != permit.source_campaign_id() {
            return Err(ContextError::IdentityConflict);
        }
        if subject.binding_task_id != permit.target_task_id() {
            return Err(ContextError::IdentityConflict);
        }
        if !fences_match_exact(subject.binding_fence, permit.fence()) {
            return Err(ContextError::InvalidFence);
        }
        if mark.permit_digest != permit.digest() {
            return Err(ContextError::IdentityConflict);
        }
        match (&mark.overlay_id, permit.overlay_id()) {
            (Some(marked), Some(bound)) if marked == bound => {}
            (None, None) => {}
            _ => return Err(ContextError::IdentityConflict),
        }
        match (&mark.candidate_id, permit.candidate_id()) {
            (Some(marked), Some(bound)) if marked == bound => {}
            (None, None) => {}
            _ => return Err(ContextError::IdentityConflict),
        }
        if let Some(expires) = mark.expires_at_unix_secs
            && now_unix_secs >= expires
        {
            return Err(ContextError::InvalidField("learning.expires_at"));
        }
        if mark.draft {
            return Err(ContextError::InvalidField("learning.draft"));
        }
        if mark.candidate_id.is_some() {
            if mark
                .closure_ref
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ContextError::InvalidField("learning.closure_ref"));
            }
            if mark
                .owner
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ContextError::InvalidField("learning.owner"));
            }
        }
    }
    Ok(())
}

/// Standalone host-preflight primitive: screen every learning-marked atom in
/// an admission input against an owner-verified permit, without deciding.
///
/// The documented preflight for native callers (including the wasm-host
/// composition root) before invoking the guest/native retrieval entrypoint:
/// `Err` means the input must not be compiled for the bound task.
pub fn screen_admission_input_learning(
    input: &AdmissionInput,
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<(), ContextError> {
    let mut subjects = Vec::new();
    for candidate in &input.candidates.candidates {
        if let Some(provenance) = &candidate.learning {
            provenance.validate()?;
            subjects.push(LearningSubject {
                atom_id: &candidate.atom_id,
                binding_task_id: candidate.binding.task_id.as_str(),
                binding_fence: &candidate.binding.state_fence,
                provenance,
            });
        }
    }
    screen_learning_subjects(&subjects, verified, now_unix_secs)
}

/// Governed retrieval entrypoint: screen learning-marked atoms against an
/// owner-verified permit, then run the unchanged [`admit_context`] decision.
///
/// Unmarked atoms are decided exactly as before; any marked atom that fails
/// the screen refuses the whole retrieval before any value surfaces.
pub fn admit_context_with_learning(
    input: &AdmissionInput,
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<AdmissionResult, ContextError> {
    screen_admission_input_learning(input, verified, now_unix_secs)?;
    admit_context(input)
}
