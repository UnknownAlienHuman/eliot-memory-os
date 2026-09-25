//! Wall-clock and invalidation expiry gate for overlay candidates.
//!
//! [`CampaignHarnessOverlayCandidate::validate`] checks representation only:
//! a zero `expires_at_ms` fails as `Missing`, but it never compares against a
//! wall-clock observation and never inspects `invalidated`. This module closes
//! that partial-representation gap (work item W7) for callers that deliver or
//! compile an overlay after composition.
//!
//! Expiry invalidates influence; it does not silently retain the last
//! behavior (doc S295). A delivery or compile caller that observes
//! [`OverlayError::Expired`] from either gate below must fall back to the base
//! view only and must never serve, cache, or replay the expired candidate's
//! prior behavior as if it were still eligible.
//!
//! Both gates are pure: they read the supplied fields and `now_ms` and return
//! [`OverlayError::Expired`] on ineligibility. They admit, activate, deliver,
//! evaluate, persist, or promote nothing, and they perform no I/O.

use eliot_learning_contracts::CampaignHarnessOverlayCandidate;

use crate::OverlayError;

/// Fail closed when a candidate is no longer retrievable at `now_ms`.
///
/// Returns [`OverlayError::Expired`] when `invalidated` is set, when
/// `expires_at_ms` is zero (missing deadline), or when `expires_at_ms` is at
/// or before the caller-supplied wall-clock observation `now_ms`. Otherwise
/// returns `Ok(())`.
///
/// The caller supplies `now_ms`; this gate never reads a clock, so
/// determinism and testability stay with the caller.
///
/// # Errors
///
/// Returns [`OverlayError::Expired`] when the candidate was invalidated or
/// its expiry deadline is missing or has passed.
pub fn check_retrievable(
    invalidated: bool,
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(), OverlayError> {
    if invalidated || expires_at_ms == 0 || expires_at_ms <= now_ms {
        return Err(OverlayError::Expired);
    }
    Ok(())
}

/// Fail closed when a composed overlay candidate is no longer retrievable.
///
/// Convenience wrapper over [`check_retrievable`] that reads `invalidated`
/// and `expires_at_ms` from `candidate`. Like [`check_retrievable`], it never
/// consults [`CampaignHarnessOverlayCandidate::validate`]; run representation
/// validation separately before or after this gate as the caller requires.
///
/// # Errors
///
/// Returns [`OverlayError::Expired`] when the candidate was invalidated or
/// its expiry deadline is missing or has passed at `now_ms`.
pub fn check_candidate_retrievable(
    candidate: &CampaignHarnessOverlayCandidate,
    now_ms: u64,
) -> Result<(), OverlayError> {
    check_retrievable(candidate.invalidated, candidate.expires_at_ms, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_revision_is_not_retrievable_for_a_later_attempt() {
        assert_eq!(
            check_retrievable(false, 2_000, 2_000),
            Err(OverlayError::Expired)
        );
        assert_eq!(
            check_retrievable(false, 2_000, 3_000),
            Err(OverlayError::Expired)
        );
    }

    #[test]
    fn invalidated_revision_is_not_retrievable_while_live_deadline_stands() {
        assert_eq!(
            check_retrievable(true, 9_000, 1_000),
            Err(OverlayError::Expired)
        );
        assert!(check_retrievable(false, 9_000, 1_000).is_ok());
    }
}
