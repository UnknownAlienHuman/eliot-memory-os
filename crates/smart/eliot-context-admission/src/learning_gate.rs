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
//! - The governed entrypoint ([`admit_context_with_learning`]) binds every
//!   marked atom to a live Governor issuance through the shared governed
//!   carriage check ([`check_governed_carriage`]): the presented wire ticket
//!   must be shape-valid, digest-identical to the owner-verified permit, and
//!   freshly re-verified against the live owner epoch/generation and the
//!   exact compilation fence; overlay subjects require the exact live
//!   `LOCAL_ADMITTED` overlay; reusable subjects require an ACTIVE backlog
//!   entry; cross-task carryover requires the distinct owner-issued
//!   revalidating admission. Any failure refuses the whole retrieval before
//!   any value surfaces.
//! - [`screen_admission_input_learning`] remains the standalone preflight
//!   fragment (per-mark binding against an owner-verified permit). It is NOT
//!   sufficient for authority on its own: production retrieval MUST go
//!   through [`admit_context_with_learning`].
//! - Cross-task rule: the compilation task must equal the task the presented
//!   admission admits. That is the LOCAL permit's target task when no carryover
//!   is presented, and the FOREIGN task a distinct owner-issued cross-task
//!   admission names when one is. Permits do not stretch and bare strings never
//!   authorize; a different task needs its own admission, and a carryover that
//!   does not re-check against the local one is refused here as well.
//!
//! Host-only logic: this module names the live Governor owner and the
//! governed registries, and must never enter a `wasm32` guest closure. It
//! is gated with `#[cfg(not(target_arch = "wasm32"))]` at the crate root.

use eliot_context_contracts::{AdmissionInput, AdmissionResult, ContextError, LearningProvenance};
use eliot_contracts::{ArtifactId, StateFence, fences_match_exact};
use eliot_governor::VerifiedLearningAdmission;
use eliot_improvement::candidate_bounds::{CrossTaskCarryover, bound_compilation_task};
use eliot_improvement::{
    CarriageMark, PresentedLearning, bounds_to_context_error, check_governed_carriage,
};

use crate::admit_context_inner;

/// One learning-marked atom with its compilation identity, for screening.
pub struct LearningSubject<'a> {
    pub atom_id: &'a ArtifactId,
    pub binding_task_id: &'a str,
    pub binding_fence: &'a StateFence,
    pub provenance: &'a LearningProvenance,
}

/// Screen learning-marked atoms against an owner-verified permit.
///
/// `cross_task` is the distinct owner-issued admission when the compilation is
/// for another task; the expected compilation task is resolved from it by the
/// shared [`bound_compilation_task`] rule, which also re-checks the carryover
/// against the local admission. `now_unix_secs` MUST be owner/host-sourced
/// live time, never a requester-envelope value (see
/// [`admit_context_with_learning`]).
///
/// Fail-closed: the first violation refuses the whole retrieval. Order: the
/// cross-task carryover is re-checked against the local admission once, up
/// front, so a bare or stale record never reaches a per-atom comparison; then,
/// per atom, origin campaign, target task, exact fence, cited issuance digest,
/// overlay subject, candidate subject, expiry, draft state, reusable
/// closure/owner status.
///
/// Preflight fragment only: authority additionally requires the governed
/// carriage check in [`admit_context_with_learning`].
pub fn screen_learning_subjects<'a>(
    subjects: &[LearningSubject<'_>],
    verified: &VerifiedLearningAdmission<'a>,
    cross_task: Option<&CrossTaskCarryover<'a>>,
    now_unix_secs: u64,
) -> Result<(), ContextError> {
    if subjects.len() > 4096 {
        return Err(ContextError::Bounds {
            field: "learning.subjects",
        });
    }
    let bound_task =
        bound_compilation_task(verified, cross_task).map_err(|_| ContextError::IdentityConflict)?;
    let permit = verified.permit();
    for subject in subjects {
        let mark = subject.provenance;
        if mark.campaign_id != permit.source_campaign_id() {
            return Err(ContextError::IdentityConflict);
        }
        if subject.binding_task_id != bound_task {
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
/// `cross_task` is the distinct owner-issued admission when the compilation is
/// for another task; pass `None` for a same-task compilation.
///
/// The documented preflight for native callers (including the wasm-host
/// composition root) before invoking the guest/native retrieval entrypoint:
/// `Err` means the input must not be compiled for the bound task. Preflight
/// only: production retrieval MUST use [`admit_context_with_learning`].
pub fn screen_admission_input_learning<'a>(
    input: &AdmissionInput,
    verified: &VerifiedLearningAdmission<'a>,
    cross_task: Option<&CrossTaskCarryover<'a>>,
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
    screen_learning_subjects(&subjects, verified, cross_task, now_unix_secs)
}

/// Governed retrieval entrypoint: run the owner-bound carriage gate
/// (ticket re-verification, overlay liveness, backlog backing, cross-task
/// carryover) plus the per-mark screen, then the unchanged
/// [`admit_context_inner`] decision.
///
/// Inputs without learning marks and without tickets are decided exactly
/// as before; any marked or ticketed input passes the full gate, and any
/// failure refuses the whole retrieval before any value surfaces.
pub fn admit_context_with_learning(
    input: &AdmissionInput,
    presented: PresentedLearning<'_>,
) -> Result<AdmissionResult, ContextError> {
    let marked = input
        .candidates
        .candidates
        .iter()
        .any(|candidate| candidate.learning.is_some());
    if marked || !input.learning_tickets.is_empty() {
        let mut marks = Vec::new();
        for candidate in &input.candidates.candidates {
            if let Some(provenance) = &candidate.learning {
                provenance.validate()?;
                marks.push(CarriageMark {
                    campaign_id: provenance.campaign_id.as_str(),
                    overlay_id: provenance.overlay_id.as_deref(),
                    candidate_id: provenance.candidate_id.as_deref(),
                    closure_ref: provenance.closure_ref.as_deref(),
                    owner: provenance.owner.as_deref(),
                    draft: provenance.draft,
                    expires_at_unix_secs: provenance.expires_at_unix_secs,
                    permit_digest: provenance.permit_digest.as_str(),
                    binding_task_id: candidate.binding.task_id.as_str(),
                });
            }
        }
        check_governed_carriage(&presented, &input.binding.state_fence, &marks)
            .map_err(bounds_to_context_error)?;
    }
    screen_admission_input_learning(
        input,
        presented.verified,
        presented.cross_task,
        presented.now_unix_secs,
    )?;
    admit_context_inner(input)
}
