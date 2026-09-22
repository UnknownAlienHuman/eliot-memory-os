//! Recipient-owner session-envelope fact (issue #1942, lane O1).
//!
//! Owner: delivery recipients are typed by this crate ([`Recipient`]:
//! principal plus role, admitted per delivery effect in `user_automation.rs`
//! `bind_failure_notification`, carried per notification in
//! `NotificationEnvelope::recipients`). The related per-automation recipient
//! config lives with the kernel automation owner
//! (`eliot-kernel-core/src/user_automation.rs::AutomationRecipient`).
//!
//! Absence: none of those holders is session-bound. Recipients live per
//! delivery effect and per notification envelope; no live per-reactive-session
//! recipient exists anywhere in the notification owner state. There is
//! therefore no live source for `snapshot.recipient_id`, and
//! [`produce_recipient_id`] fails closed naming it instead of conflating the
//! recipient with the attach principal (the snapshot carries `principal_id`
//! as a separate live bridge fact; recipient and principal are distinct
//! owners and identities).
//!
//! Consumer: `resolve_runtime_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) names the missing `snapshot.recipient_id` fact. When
//! a session-bound recipient admission lands in the notification owner, this
//! producer gains an owner-state borrow and reads it; until then the
//! fail-closed shape is the contract.

use thiserror::Error;

/// Fail-closed recipient-envelope errors. Each names the exact D2 fact that
/// cannot be resolved from live owner state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RecipientEnvelopeError {
    /// No session-bound delivery recipient exists in the notification owner
    /// state, so `snapshot.recipient_id` has no live source. Recipients are
    /// admitted per delivery effect (`Recipient` in `lib.rs`) and carried
    /// per notification envelope (`user_automation.rs`
    /// `bind_failure_notification`), never per reactive session.
    #[error("notification owner holds no session-bound recipient for snapshot.recipient_id")]
    RecipientNotOwned,
}

/// Attempt to produce the delivery recipient identity for the session
/// envelope.
///
/// Always fails closed (see [`RecipientEnvelopeError::RecipientNotOwned`]):
/// the notification owner admits recipients per delivery effect and per
/// notification, never per reactive session. The zero-argument shape is
/// deliberate — there is no owner state to read, so no borrow is threaded
/// and no caller value is accepted.
pub fn produce_recipient_id() -> Result<String, RecipientEnvelopeError> {
    Err(RecipientEnvelopeError::RecipientNotOwned)
}
