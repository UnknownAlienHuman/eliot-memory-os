//! Governed local overlay lifecycle state machine.
//!
//! Encodes the normative lifecycle from `docs/architecture/I12-24`
//! (S211-216):
//!
//! ```text
//! PROPOSED → SHAPE_VALIDATED → LOCAL_ADMITTED → ACTIVE_FOR_NEXT_ATTEMPT
//!   → OBSERVED → RETAIN_LOCAL | OPEN_REUSABLE_CANDIDATE | REVISE
//!   | ROLLBACK | EXPIRE | INVALIDATE
//! ```
//!
//! Admission and activation are externally owned; this module only tracks the
//! local evidence labels. It performs no I/O, admits nothing, and promotes
//! nothing. [`transition`] enforces exactly the chain above:
//!
//! - forward progress follows one edge at a time;
//! - `Expire` and `Invalidate` preempt from any non-terminal state;
//! - the six `OBSERVED` dispositions are terminal, and a terminal state never
//!   returns to an earlier state.
//!
//! `REVISE` is the disposition of the observed revision whose next
//! discriminator was inconclusive. It is terminal for that revision, exactly
//! like the other five `OBSERVED` dispositions, and it is not a backward edge.
//! The revised overlay is a distinct revision with a named parent
//! (`overlay_id_revision_parent_and_state_fence`, I12.24:189); it re-freezes
//! the pre-evaluation fields required for every nontrivial revision
//! (I12.24:209) and re-enters this same machine at `Proposed` through
//! [`crate::compose_campaign_harness_overlay`], then re-enters eligibility
//! through [`crate::admit_local_with_refs`].
//!
//! Illegal transitions fail as [`crate::OverlayError::Contract`] with a
//! `ScopeMismatch` on `"overlay.lifecycle"`.

use crate::OverlayError;
use eliot_learning_contracts::LearningContractError;

/// Local lifecycle state of one task-local overlay candidate.
///
/// States are evidence labels only; they confer no admission, activation, or
/// promotion authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OverlayLifecycle {
    /// Candidate composed but shape not yet validated.
    Proposed,
    /// Candidate shape validated, not yet locally admitted.
    ShapeValidated,
    /// Locally admitted, frozen before evaluation, not yet active.
    LocalAdmitted,
    /// Frozen overlay armed for exactly the next attempt.
    ActiveForNextAttempt,
    /// Attempt observed against the frozen overlay.
    Observed,
    /// Terminal: retained locally, never promoted.
    RetainLocal,
    /// Terminal: handed off as a reusable candidate for external review.
    OpenReusableCandidate,
    /// Terminal: the next discriminator was inconclusive, so this revision is
    /// revised. The revised overlay is a new revision with a named parent.
    Revise,
    /// Terminal: rolled back via exact inverses.
    Rollback,
    /// Terminal: expired before or during evaluation.
    Expire,
    /// Terminal: explicitly invalidated.
    Invalidate,
}

/// Governed event advancing one overlay lifecycle state.
///
/// The single `Revise` event is admissible only from `Observed`, and only as
/// the disposition of that observed revision. It does not reopen the state it
/// leaves: the revised overlay is a new revision with a named parent, composed
/// through [`crate::compose_campaign_harness_overlay`] and admitted through
/// [`crate::admit_local_with_refs`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleEvent {
    /// Validate candidate shape: `Proposed → ShapeValidated`.
    ValidateShape,
    /// Admit locally under the pre-evaluation freeze: `ShapeValidated → LocalAdmitted`.
    AdmitLocal,
    /// Arm the frozen overlay for the next attempt: `LocalAdmitted → ActiveForNextAttempt`.
    ActivateForNextAttempt,
    /// Record observation of the active overlay: `ActiveForNextAttempt → Observed`.
    Observe,
    /// Retain the observed overlay locally: `Observed → RetainLocal`.
    RetainLocal,
    /// Open the observed overlay as a reusable candidate: `Observed → OpenReusableCandidate`.
    OpenReusableCandidate,
    /// Revise the observed overlay: `Observed → Revise`.
    Revise,
    /// Roll back the observed overlay: `Observed → Rollback`.
    Rollback,
    /// Expire the overlay from any non-terminal state.
    Expire,
    /// Invalidate the overlay from any non-terminal state.
    Invalidate,
}

impl OverlayLifecycle {
    /// Report whether this state is terminal.
    ///
    /// Terminal states ([`OverlayLifecycle::RetainLocal`],
    /// [`OverlayLifecycle::OpenReusableCandidate`],
    /// [`OverlayLifecycle::Revise`], [`OverlayLifecycle::Rollback`],
    /// [`OverlayLifecycle::Expire`], and [`OverlayLifecycle::Invalidate`])
    /// accept no further events.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::RetainLocal
                | Self::OpenReusableCandidate
                | Self::Revise
                | Self::Rollback
                | Self::Expire
                | Self::Invalidate
        )
    }
}

/// Advance one overlay lifecycle state by one governed event.
///
/// Accepts exactly the normative chain `Proposed → ShapeValidated →
/// LocalAdmitted → ActiveForNextAttempt → Observed → {RetainLocal |
/// OpenReusableCandidate | Revise | Rollback | Expire | Invalidate}`, plus
/// preemptive `Expire` / `Invalidate` from any non-terminal state. Terminal
/// states have no outgoing transitions, and no event resurrects an earlier
/// state.
///
/// # Errors
///
/// Returns [`crate::OverlayError::Contract`] (`ScopeMismatch` on
/// `"overlay.lifecycle"`) for any event that is not the single governed
/// successor of `state`, including every event applied to a terminal state.
/// Revising a terminal revision is composition of a new revision, not an event
/// out of [`OverlayLifecycle::Revise`].
pub const fn transition(
    state: OverlayLifecycle,
    event: LifecycleEvent,
) -> Result<OverlayLifecycle, OverlayError> {
    if state.is_terminal() {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "overlay.lifecycle",
            },
        ));
    }
    match (state, event) {
        (OverlayLifecycle::Proposed, LifecycleEvent::ValidateShape) => {
            Ok(OverlayLifecycle::ShapeValidated)
        }
        (OverlayLifecycle::ShapeValidated, LifecycleEvent::AdmitLocal) => {
            Ok(OverlayLifecycle::LocalAdmitted)
        }
        (OverlayLifecycle::LocalAdmitted, LifecycleEvent::ActivateForNextAttempt) => {
            Ok(OverlayLifecycle::ActiveForNextAttempt)
        }
        (OverlayLifecycle::ActiveForNextAttempt, LifecycleEvent::Observe) => {
            Ok(OverlayLifecycle::Observed)
        }
        (OverlayLifecycle::Observed, LifecycleEvent::RetainLocal) => {
            Ok(OverlayLifecycle::RetainLocal)
        }
        (OverlayLifecycle::Observed, LifecycleEvent::OpenReusableCandidate) => {
            Ok(OverlayLifecycle::OpenReusableCandidate)
        }
        (OverlayLifecycle::Observed, LifecycleEvent::Revise) => Ok(OverlayLifecycle::Revise),
        (OverlayLifecycle::Observed, LifecycleEvent::Rollback) => Ok(OverlayLifecycle::Rollback),
        (_, LifecycleEvent::Expire) => Ok(OverlayLifecycle::Expire),
        (_, LifecycleEvent::Invalidate) => Ok(OverlayLifecycle::Invalidate),
        _ => Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "overlay.lifecycle",
            },
        )),
    }
}
