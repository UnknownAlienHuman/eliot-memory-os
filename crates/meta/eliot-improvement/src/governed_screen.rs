//! Owner-bound governed learning carriage check (#1869).
//!
//! Single home for the native retrieval/delivery carriage gate that the
//! admission screen (`eliot-context-admission::learning_gate`) and the
//! assembly screen (`eliot-context-assembly::learning_gate`) both run
//! before any learning-marked atom may influence a compilation. It binds
//! the presented wire data to a live Governor issuance:
//!
//! - the presented [`LearningAdmissionTicket`] must be shape-valid, digest-
//!   identical to the owner-verified permit, and freshly re-verified
//!   against the live owner epoch/generation and the exact compilation
//!   fence ([`verify_learning_ticket`]) — bare strings never authorize;
//! - an overlay subject bound by the permit requires the exact live
//!   `LOCAL_ADMITTED` overlay (expiry enforced with teeth via
//!   [`GovernedOverlay::is_live_local_admitted_at_unix`]);
//! - a reusable-candidate subject requires an ACTIVE [`BoundedBacklog`]
//!   entry admitted under the permit-bound authority (`admit` grants
//!   eligibility, `archive` revokes it);
//! - cross-task carryover requires a distinct [`CrossTaskAdmission`]
//!   revalidating scope, authority, retention, evaluator, and rollback.
//!
//! Per-mark expiry/draft/closure/owner shape is enforced here as well, so
//! the mark-level `expires_at_unix_secs` is defense-in-depth behind the
//! overlay-expiry teeth, never a bare advisory bypass.
//!
//! Host-only logic: this module names the live [`Governor`] owner and must
//! never enter a `wasm32` guest closure. Depending crates gate it with
//! `#[cfg(not(target_arch = "wasm32"))]`.

use eliot_context_contracts::{ContextError, LearningAdmissionTicket};
use eliot_contracts::{StateFence, fences_match_exact};
use eliot_governor::{
    Governor, LearningAdmissionError, VerifiedLearningAdmission, verify_learning_ticket,
};
use time::OffsetDateTime;

use crate::candidate_bounds::{
    BoundedBacklog, BoundsError, CrossTaskAdmission, GovernedOverlay, OverlayState,
};

/// Pure-data view of one learning-marked atom for carriage screening.
///
/// Mapped trivially from [`eliot_context_contracts::LearningProvenance`]
/// plus the candidate's compilation binding by each screen; no owner
/// state, no strings trusted beyond the checks below.
pub struct CarriageMark<'a> {
    pub campaign_id: &'a str,
    pub overlay_id: Option<&'a str>,
    pub candidate_id: Option<&'a str>,
    pub closure_ref: Option<&'a str>,
    pub owner: Option<&'a str>,
    pub draft: bool,
    pub expires_at_unix_secs: Option<u64>,
    pub permit_digest: &'a str,
    pub binding_task_id: &'a str,
}

/// Everything a native screen must present for one governed retrieval.
///
/// The registry handle (`backlog`) is non-optional: production native
/// callers always pass the production [`BoundedBacklog`]. `overlay` and
/// `cross_task_admission` are required exactly when the permit binds an
/// overlay subject or the requesting task leaves the admitted target.
#[derive(Clone, Copy, Debug)]
pub struct PresentedLearning<'a> {
    pub governor: &'a Governor,
    pub verified: &'a VerifiedLearningAdmission<'a>,
    pub ticket: &'a LearningAdmissionTicket,
    pub overlay: Option<&'a GovernedOverlay>,
    pub backlog: &'a BoundedBacklog,
    pub cross_task_admission: Option<&'a CrossTaskAdmission>,
    pub requesting_campaign_id: &'a str,
    pub requesting_task_id: &'a str,
    /// Wall clock both expiries enforce against. MUST be sourced from the
    /// owner/host clock live at the call (the composed entry re-sources it
    /// itself); never accept this value from requester envelopes — a
    /// backdated stamp defeats mark and overlay expiry.
    pub now_unix_secs: u64,
}

fn map_admission_error(error: LearningAdmissionError) -> BoundsError {
    match error {
        LearningAdmissionError::StaleStateFence => BoundsError::StaleStateFence,
        LearningAdmissionError::InvalidFence => BoundsError::InvalidFence,
        LearningAdmissionError::MissingField(field) => BoundsError::MissingField(field),
        LearningAdmissionError::UnsupportedSchema { .. }
        | LearningAdmissionError::NoInfluenceSubject
        | LearningAdmissionError::GovernorNotAdmitting
        | LearningAdmissionError::StaleAuthorityEpoch
        | LearningAdmissionError::GenerationMismatch
        | LearningAdmissionError::DigestMismatch
        | LearningAdmissionError::OwnerEvidenceUnavailable(_)
        | LearningAdmissionError::OwnerEvidenceMismatch(_)
        | LearningAdmissionError::InvalidTargetTask => BoundsError::GovernorAuthorityUnconfirmed,
    }
}

/// Governed carriage gate: ticket re-verification plus overlay, backlog,
/// cross-task, and per-mark binding in one fail-closed pass.
///
/// `current_fence` is the compilation fence the retrieval is admitted
/// under (the input's binding fence) — never a caller-supplied copy.
///
/// Order: requesting identity, ticket shape, wire-to-owner digest binding,
/// live owner re-verification (epoch/generation/fence), per-mark binding,
/// overlay liveness, reusable backlog backing, cross-task admission.
pub fn check_governed_carriage(
    presented: &PresentedLearning<'_>,
    current_fence: &StateFence,
    marks: &[CarriageMark<'_>],
) -> Result<(), BoundsError> {
    if presented.requesting_campaign_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_campaign_id"));
    }
    if presented.requesting_task_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_task_id"));
    }
    let permit = presented.verified.permit();
    presented
        .ticket
        .validate()
        .map_err(|_| BoundsError::InvalidProduction("learning.ticket"))?;
    if presented.ticket.digest.as_str() != permit.digest() {
        return Err(BoundsError::GovernorAuthorityUnconfirmed);
    }
    verify_learning_ticket(presented.governor, presented.ticket, current_fence)
        .map_err(map_admission_error)?;

    for mark in marks {
        if mark.campaign_id != permit.source_campaign_id() {
            return Err(BoundsError::CrossCampaignLeakage);
        }
        if mark.binding_task_id != presented.requesting_task_id {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if mark.permit_digest != permit.digest() {
            return Err(BoundsError::GovernorAuthorityUnconfirmed);
        }
        match (mark.overlay_id, permit.overlay_id()) {
            (Some(marked), Some(bound)) if marked == bound => {}
            (None, None) => {}
            _ => return Err(BoundsError::OverlayBackingMismatch),
        }
        match (mark.candidate_id, permit.candidate_id()) {
            (Some(marked), Some(bound)) if marked == bound => {}
            (None, None) => {}
            _ => return Err(BoundsError::ReusableBackingMismatch),
        }
        if let Some(expires) = mark.expires_at_unix_secs
            && presented.now_unix_secs >= expires
        {
            return Err(BoundsError::ExpiredOverlay);
        }
        if mark.draft {
            return Err(BoundsError::DraftDeltaIneligible);
        }
        if mark.candidate_id.is_some() {
            if mark
                .closure_ref
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(BoundsError::UnclosedReusable);
            }
            if mark
                .owner
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(BoundsError::OwnerlessRecord);
            }
            if mark.owner != Some(permit.authority_ref()) {
                return Err(BoundsError::GovernorAuthorityUnconfirmed);
            }
        }
    }

    if let Some(bound_overlay) = permit.overlay_id() {
        let overlay = presented
            .overlay
            .ok_or(BoundsError::OverlayBackingMismatch)?;
        if overlay.overlay_id != bound_overlay {
            return Err(BoundsError::OverlayBackingMismatch);
        }
        if !fences_match_exact(&overlay.fence, permit.fence()) {
            return Err(BoundsError::StaleStateFence);
        }
        if overlay.campaign_id != permit.source_campaign_id() {
            return Err(BoundsError::CrossCampaignLeakage);
        }
        if !overlay.is_live_local_admitted_at_unix(presented.now_unix_secs) {
            let expired = overlay.state == OverlayState::Expired
                || overlay.expires_at.is_some_and(|expires| {
                    i64::try_from(presented.now_unix_secs)
                        .ok()
                        .and_then(|now| OffsetDateTime::from_unix_timestamp(now).ok())
                        .is_some_and(|now| now >= expires)
                });
            if expired {
                return Err(BoundsError::ExpiredOverlay);
            }
            return Err(BoundsError::OverlayNotAdmitted);
        }
    } else if presented.overlay.is_some() {
        return Err(BoundsError::OverlayBackingMismatch);
    }

    for mark in marks {
        if let Some(candidate_id) = mark.candidate_id {
            let retained = presented
                .backlog
                .entry_for(candidate_id)
                .ok_or(BoundsError::NotBacklogAdmitted)?;
            if retained.admitted_under_authority.as_deref() != Some(permit.authority_ref()) {
                return Err(BoundsError::GovernorAuthorityUnconfirmed);
            }
            if mark.owner != retained.owner.as_deref() {
                return Err(BoundsError::GovernorAuthorityUnconfirmed);
            }
        }
    }

    let source = permit.source_campaign_id();
    let target = permit.target_task_id();
    let local =
        presented.requesting_campaign_id == source && presented.requesting_task_id == target;
    if !local {
        let admission = presented
            .cross_task_admission
            .ok_or(BoundsError::CrossTaskAdmissionMissing)?;
        admission.validate()?;
        if admission.source_campaign_id != source
            || admission.target_task_id != target
            || !admission.matches_permit(presented.verified)
        {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if presented.requesting_task_id != target {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
    } else if presented.cross_task_admission.is_some() {
        return Err(BoundsError::CrossTaskAdmissionMismatch);
    }
    Ok(())
}

/// Convert a unix-seconds clock into owner time for registry gates.
///
/// Fail-closed: out-of-range stamps refuse with `InvalidProduction`
/// instead of wrapping or clamping.
pub fn datetime_from_unix(now_unix_secs: u64) -> Result<OffsetDateTime, BoundsError> {
    i64::try_from(now_unix_secs)
        .ok()
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .ok_or(BoundsError::InvalidProduction("learning.now"))
}

/// Map a carriage refusal onto the contract error space for screens.///
/// Variants reachable from [`check_governed_carriage`] map precisely;
/// backlog-policy/archive/closure-assembly variants cannot occur on this
/// path and collapse to `IdentityConflict` rather than inventing semantics.
pub fn bounds_to_context_error(error: BoundsError) -> ContextError {
    match error {
        BoundsError::MissingField(field) => ContextError::MissingField(field),
        BoundsError::InvalidProduction(field) => ContextError::InvalidField(field),
        BoundsError::InvalidFence => ContextError::InvalidFence,
        BoundsError::StaleStateFence => ContextError::InvalidFence,
        BoundsError::OverlayNotAdmitted => ContextError::InvalidField("learning.overlay"),
        BoundsError::ExpiredOverlay => ContextError::InvalidField("learning.expires_at"),
        BoundsError::DraftDeltaIneligible => ContextError::InvalidField("learning.draft"),
        BoundsError::UnclosedReusable => ContextError::InvalidField("learning.closure_ref"),
        BoundsError::OwnerlessRecord => ContextError::InvalidField("learning.owner"),
        BoundsError::CrossTaskAdmissionMissing
        | BoundsError::CrossTaskAdmissionMismatch
        | BoundsError::CrossCampaignLeakage
        | BoundsError::GovernorAuthorityUnconfirmed
        | BoundsError::NotBacklogAdmitted
        | BoundsError::OverlayBackingMismatch
        | BoundsError::ReusableBackingMismatch => ContextError::IdentityConflict,
        BoundsError::NoPolicyForSurface
        | BoundsError::InvalidPolicy(_)
        | BoundsError::InvalidValue
        | BoundsError::EmptyEvidenceLineage
        | BoundsError::BoundExceeded { .. }
        | BoundsError::BelowValueFloor { .. }
        | BoundsError::UnknownCandidate
        | BoundsError::NotActive
        | BoundsError::MissingSummary
        | BoundsError::ArchiveCauseMismatch
        | BoundsError::ClosureCampaignMismatch
        | BoundsError::Candidate(_) => ContextError::IdentityConflict,
    }
}
