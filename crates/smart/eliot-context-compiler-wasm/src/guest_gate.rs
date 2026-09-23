//! In-guest learning ticket enforcement for Context Compiler retrieval (#1869).
//!
//! Structural prefilter, NOT authority: every learning-marked atom in the
//! input must be covered by a matching owner-minted ticket carried in the
//! same input, and the mark, ticket, and compilation binding must agree
//! exactly. Violations refuse the retrieval before the native gate runs
//! (`native_calls == 0`).
//!
//! On the guest contour this screen runs AFTER the
//! `LearningRequiresGovernedPath` refusal in `conversion.rs`, which rejects
//! any marked/ticketed input outright: the guest cannot owner-verify
//! issuance, liveness, or expiry, so marked influence admits only through
//! the governed native path (`admit_context_with_learning`). This screen
//! remains as defense in depth and as the binding rulebook for host-side
//! rlib callers presenting marks with owner verification in hand.
//!
//! Honest boundary (read before relying on this):
//!
//! - Recomputation detects tampering, transplanting across campaigns/tasks/
//!   subjects, fence drift *within the presented data*, draft use, and
//!   unclosed/unowned reusables. A from-scratch forgery for currently-valid
//!   parameters is equivalent to legitimate issuance, because the issuance
//!   checks ARE the admission policy; what forgery cannot do is backdate
//!   (live-epoch recompute fails after rotation at native layers), drift
//!   fences against a live compilation, or widen subjects.
//! - Wall-clock expiry and live-epoch freshness are NOT checkable here (the
//!   guest has no clock and no ambient authority): they are enforced by the
//!   native retrieval gates and host contour fence freshness. A stale-
//!   together full-compilation replay passes these structural checks and
//!   relies on those layers, exactly as generation fencing (I14.14) models.

use eliot_context_contracts::{
    AdmissionInput, ContextError, LearningAdmissionTicket, LearningProvenance,
};
use eliot_contracts::fences_match_exact;

/// Screen learning-marked atoms against tickets carried in the same input.
///
/// Fail-closed whole-input refusal. Every marked atom needs exactly one
/// covering ticket; every covering ticket must be internally consistent
/// and bound to this compilation.
pub fn check_guest_tickets(input: &AdmissionInput) -> Result<(), ContextError> {
    if input.learning_tickets.len() > 4096 {
        return Err(ContextError::Bounds {
            field: "learning.tickets",
        });
    }
    for ticket in &input.learning_tickets {
        ticket.validate()?;
    }
    let mut marked = 0usize;
    for candidate in &input.candidates.candidates {
        let Some(mark) = &candidate.learning else {
            continue;
        };
        marked += 1;
        if marked > 4096 {
            return Err(ContextError::Bounds {
                field: "learning.marked",
            });
        }
        mark.validate()?;
        let ticket = find_covering_ticket(&input.learning_tickets, mark)
            .ok_or(ContextError::IdentityConflict)?;
        check_ticket_for_atom(input, mark, ticket)?;
    }
    Ok(())
}

/// Locate the ticket covering one marked atom: exact campaign + subject
/// match. At most one ticket may match; ambiguity refuses.
fn find_covering_ticket<'a>(
    tickets: &'a [LearningAdmissionTicket],
    mark: &LearningProvenance,
) -> Option<&'a LearningAdmissionTicket> {
    let mut found = None;
    for ticket in tickets {
        if ticket.source_campaign_id != mark.campaign_id {
            continue;
        }
        if ticket.overlay_id.as_deref() != mark.overlay_id.as_deref()
            || ticket.candidate_id.as_deref() != mark.candidate_id.as_deref()
        {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(ticket);
    }
    found
}

fn check_ticket_for_atom(
    input: &AdmissionInput,
    mark: &LearningProvenance,
    ticket: &LearningAdmissionTicket,
) -> Result<(), ContextError> {
    // Tamper evidence: the digest must recompute from the ticket fields.
    let recomputed = eliot_context_contracts::learning_ticket_digest(ticket)
        .map_err(|_| ContextError::IdentityConflict)?;
    if recomputed != ticket.digest {
        return Err(ContextError::IdentityConflict);
    }
    // Issuance binding: the mark must cite this exact issuance.
    if mark.permit_digest != ticket.digest {
        return Err(ContextError::IdentityConflict);
    }
    // Compilation binding: ticket fence and target task must be this
    // compilation's fence and task, exactly.
    if !fences_match_exact(&input.binding.state_fence, &ticket.fence) {
        return Err(ContextError::InvalidFence);
    }
    if input.binding.task_id.as_str() != ticket.target_task_id {
        return Err(ContextError::IdentityConflict);
    }
    // Draft deltas are ineligible; reusables must be closed and owned.
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
    Ok(())
}
