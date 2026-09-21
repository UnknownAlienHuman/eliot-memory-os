//! Production binding for deterministic UserAutomation failure notifications.
//!
//! The UserAutomation owner supplies the immutable identity references and an
//! already prepared notification envelope. This module derives the existing
//! notification identity from those references and leaves source
//! authentication, admission, canonical state, and delivery to the existing
//! G-08/A-08 and notification-state route.

use crate::{NotificationEnvelope, NotifyError, ProviderId, UserAutomationFailureIdentity};

/// Typed input emitted by the UserAutomation deterministic preflight/failure
/// boundary.
///
/// `notification.source_receipt` is the owner-issued evidence that the
/// existing notification route authenticates before canonical upsert. The
/// three identity strings are opaque references from that same owner; this
/// producer never classifies a failure or derives a fingerprint from prose.
#[derive(
    Clone, Debug, Eq, schemars::JsonSchema, PartialEq, serde::Deserialize, serde::Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailureRequest {
    /// Stable identity of the UserAutomation object.
    pub automation_id: String,
    /// Immutable revision that was admitted for the failed occurrence.
    pub automation_revision: String,
    /// Canonical failure-class reference supplied by preflight.
    pub failure_fingerprint: String,
    /// Existing notification content and authenticated source receipt.
    pub notification: NotificationEnvelope,
}

impl UserAutomationFailureRequest {
    /// Binds the immutable automation failure identity to the existing
    /// notification envelope.
    ///
    /// The returned envelope is consumed by [`crate::NotifyCore::deliver`],
    /// which performs the authenticated G-08 source verification, A-08
    /// admission, canonical notification upsert/read-back, and delivery. No
    /// model, scheduler, store, or authority operation is performed here.
    pub fn into_notification_envelope(self) -> Result<NotificationEnvelope, NotifyError> {
        let identity = UserAutomationFailureIdentity::new(
            self.automation_id,
            self.automation_revision,
            self.failure_fingerprint,
        )?;
        self.notification
            .source_receipt
            .validate()
            .map_err(|error| NotifyError::ReceiptInvalid {
                provider: ProviderId::G08Problem,
                reason: error.to_string(),
            })?;

        let NotificationEnvelope {
            canonical,
            subject,
            summary,
            recipients,
            source_receipt,
            ..
        } = self.notification;
        let canonical = identity.bind_draft(canonical)?;
        if canonical.subject != subject || canonical.summary != summary {
            return Err(NotifyError::RequestEnvelopeMismatch);
        }

        Ok(NotificationEnvelope {
            notification_id: canonical.notification_id.clone(),
            canonical,
            subject,
            summary,
            recipients,
            source_receipt,
            user_automation_failure: Some(identity),
        })
    }
}
