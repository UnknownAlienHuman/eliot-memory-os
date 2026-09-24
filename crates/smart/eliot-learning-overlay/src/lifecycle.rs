//! Governed local overlay lifecycle state machine.
//!
//! Encodes the normative lifecycle from `docs/architecture/I12-24`
//! (S211-216):
//!
//! ```text
//! PROPOSED → SHAPE_VALIDATED → LOCAL_ADMITTED → ACTIVE_FOR_NEXT_ATTEMPT
//!   → OBSERVED → RETAIN_LOCAL | OPEN_REUSABLE_CANDIDATE | ROLLBACK
//!   | EXPIRE | INVALIDATE
//! ```
//!
//! Admission and activation are externally owned; this module only tracks the
//! local evidence labels. It performs no I/O, admits nothing, and promotes
//! nothing. [`transition`] enforces exactly the chain above:
//!
//! - forward progress follows one edge at a time;
//! - `Expire` and `Invalidate` preempt from any non-terminal state;
//! - terminal states have no outgoing transitions;
//! - there is intentionally no `Revise` event and no resurrection: a terminal
//!   state never returns to an earlier state. Correcting or retrying a
//!   terminal overlay requires composing a new overlay revision.
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
    /// Terminal: rolled back via exact inverses.
    Rollback,
    /// Terminal: expired before or during evaluation.
    Expire,
    /// Terminal: explicitly invalidated.
    Invalidate,
}

/// Governed event advancing one overlay lifecycle state.
///
/// There is intentionally no `Revise` event: revision of any overlay,
/// including a terminal one, requires a new overlay revision rather than a
/// transition of the existing state.
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
    /// [`OverlayLifecycle::Rollback`], [`OverlayLifecycle::Expire`], and
    /// [`OverlayLifecycle::Invalidate`]) accept no further events.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::RetainLocal
                | Self::OpenReusableCandidate
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
/// OpenReusableCandidate | Rollback | Expire | Invalidate}`, plus preemptive
/// `Expire` / `Invalidate` from any non-terminal state. Terminal states have
/// no outgoing transitions, and no event resurrects an earlier state.
///
/// # Errors
///
/// Returns [`crate::OverlayError::Contract`] (`ScopeMismatch` on
/// `"overlay.lifecycle"`) for any event that is not the single governed
/// successor of `state`, including every event applied to a terminal state.
/// There is no `Revise` event; callers needing a correction must compose a
/// new overlay revision.
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
