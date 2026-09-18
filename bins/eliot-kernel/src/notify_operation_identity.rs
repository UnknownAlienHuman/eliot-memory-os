//! Kernel-side cross-operation reuse rejection for notification children.
//!
//! Architecture: A13.2 Kernel failure domains, A12.2 principal/session
//! binding, I7.4 lifecycle (every request owns idempotency, deadline and
//! cancellation). This module proves a negative: **no Kernel notify owner
//! exists**. Kernel never interprets notification semantics, mints notify
//! receipts, owns the one-shot ledger, or performs provider delivery. Its
//! only notify-adjacent duty is fail-closed transport rejection: a caller
//! idempotency key already bound to one `(operation, canonical bytes)` pair
//! cannot be rebound to a different operation or different bytes. Exact
//! replay returns the recorded disposition; anything else is
//! `IDENTITY_CONFLICT` before any effect.
//!
//! The notify process (`bins/eliot-notify`) owns parent-to-child derivation;
//! this module owns the Kernel-side guard that makes cross-step reuse
//! unrepresentable even if a caller bypasses the process issuer. It carries
//! no notify state machine, no receipt, no ledger and no provider call.

#![forbid(unsafe_code)]

use std::fmt;

/// Stable conflict code surfaced when a caller reuses one idempotency key
/// across operations or payloads.
pub const IDENTITY_CONFLICT: &str = "IDENTITY_CONFLICT";

/// Exact Kernel operation selectors guarded by this classifier. They mirror
/// the notify provider bundle without owning any of its semantics.
pub const NOTIFY_OPERATIONS: &[&str] = &[
    "eliot.notify.g08.verify",
    "eliot.notify.a08.admit",
    "eliot.notify.watchdog.verify",
    "eliot.notify.delivery.verify",
    "eliot.notify.ledger.reserve",
    "eliot.notify.ledger.commit",
];

/// Returns true when the selector is one of the six guarded notify steps.
#[must_use]
pub fn is_notify_operation(selector: &str) -> bool {
    NOTIFY_OPERATIONS.contains(&selector)
}

/// Disposition for one incoming `(idempotency_key, operation, digest)` triple
/// against the recorded owner of that key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyReuseDisposition {
    /// Key is unbound: the caller may proceed to the exactly-once effect.
    Accept,
    /// Same key, same operation, same bytes: idempotent replay, no new effect.
    ExactReplay,
    /// Same key with a different operation or different bytes: reject before
    /// any effect with [`IDENTITY_CONFLICT`].
    Conflict,
}

/// Pure replay classifier. No I/O, no clock, no state mutation.
#[must_use]
pub fn classify_notify_reuse(
    recorded_operation: &str,
    recorded_digest: &str,
    incoming_operation: &str,
    incoming_digest: &str,
) -> NotifyReuseDisposition {
    if recorded_operation == incoming_operation && recorded_digest == incoming_digest {
        NotifyReuseDisposition::ExactReplay
    } else {
        NotifyReuseDisposition::Conflict
    }
}

/// Typed fail-closed rejection for cross-operation reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyOperationIdentityConflict {
    /// Operation selector that already owns the idempotency key.
    pub recorded_operation: String,
    /// Operation selector attempted with the same key.
    pub incoming_operation: String,
}

impl fmt::Display for NotifyOperationIdentityConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{IDENTITY_CONFLICT}: idempotency key is already bound to {} and cannot be reused by {}",
            self.recorded_operation, self.incoming_operation
        )
    }
}

impl std::error::Error for NotifyOperationIdentityConflict {}

/// Rejects cross-operation or cross-payload idempotency reuse before any
/// effect. Exact replay (`same operation, same bytes`) is `Ok(())` and means
/// the caller must return the recorded result without a second effect.
pub fn reject_cross_operation_reuse(
    recorded_operation: &str,
    recorded_digest: &str,
    incoming_operation: &str,
    incoming_digest: &str,
) -> Result<(), NotifyOperationIdentityConflict> {
    match classify_notify_reuse(
        recorded_operation,
        recorded_digest,
        incoming_operation,
        incoming_digest,
    ) {
        NotifyReuseDisposition::ExactReplay | NotifyReuseDisposition::Accept => Ok(()),
        NotifyReuseDisposition::Conflict => Err(NotifyOperationIdentityConflict {
            recorded_operation: recorded_operation.to_owned(),
            incoming_operation: incoming_operation.to_owned(),
        }),
    }
}

/// Validates that reserve and commit remain separate operations. A commit
/// carrying a reserve digest is a lineage link, never an identity reuse: the
/// selectors must differ even when the claim digest matches.
#[must_use]
pub fn reserve_and_commit_are_distinct(
    reserve_operation: &str,
    commit_operation: &str,
) -> bool {
    reserve_operation != commit_operation
        && is_notify_operation(reserve_operation)
        && is_notify_operation(commit_operation)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn exact_replay_is_not_a_conflict() {
        assert_eq!(
            classify_notify_reuse("eliot.notify.g08.verify", "aa", "eliot.notify.g08.verify", "aa"),
            NotifyReuseDisposition::ExactReplay
        );
        assert!(
            reject_cross_operation_reuse(
                "eliot.notify.g08.verify",
                "aa",
                "eliot.notify.g08.verify",
                "aa"
            )
            .is_ok()
        );
    }

    #[test]
    fn cross_step_reuse_is_identity_conflict() {
        assert_eq!(
            classify_notify_reuse(
                "eliot.notify.g08.verify",
                "aa",
                "eliot.notify.ledger.reserve",
                "aa"
            ),
            NotifyReuseDisposition::Conflict
        );
        let error = reject_cross_operation_reuse(
            "eliot.notify.g08.verify",
            "aa",
            "eliot.notify.ledger.reserve",
            "aa",
        )
        .expect_err("cross-step reuse must conflict");
        assert!(error.to_string().contains(IDENTITY_CONFLICT));
    }

    #[test]
    fn same_step_different_bytes_is_identity_conflict() {
        assert_eq!(
            classify_notify_reuse(
                "eliot.notify.ledger.reserve",
                "aa",
                "eliot.notify.ledger.reserve",
                "bb"
            ),
            NotifyReuseDisposition::Conflict
        );
    }

    #[test]
    fn reserve_and_commit_are_never_one_operation() {
        assert!(reserve_and_commit_are_distinct(
            "eliot.notify.ledger.reserve",
            "eliot.notify.ledger.commit"
        ));
        assert!(!reserve_and_commit_are_distinct(
            "eliot.notify.ledger.reserve",
            "eliot.notify.ledger.reserve"
        ));
    }

    #[test]
    fn unknown_selectors_are_not_notify_operations() {
        assert!(!is_notify_operation("eliot.notify.unknown"));
        assert_eq!(NOTIFY_OPERATIONS.len(), 6);
    }
}
