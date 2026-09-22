//! Production [`UserAutomationNotificationPort`] over the real delivery route.
//!
//! Registration hook for the automation runtime owner (Beauvoir): construct
//! [`AutomationNotificationAdapter::new`] with a closure that calls the live
//! `NotifyCore::deliver_user_automation_failure` route, then pass the adapter
//! as the `N` port of `UserAutomationRuntimeComposition`. History stays
//! recorded first by that composition (A2 owner); this adapter only delivers
//! already-recorded failures and maps the outcome back.
//!
//! Every derived value comes from owner-supplied inputs with fail-closed
//! ambiguity handling: the audience is the owner-designated primary
//! recipient (first of the bound envelope list, never invented); the body
//! digest is the single `Artifact`-role digest bound in the owner source
//! receipt (zero or several fail closed, never guessed); the parent request
//! reuses the record context with notification/hash rebound from the
//! envelope exactly like `bind_notification_request`. Nothing here mints
//! principals, digests, routes, or receipts.

use std::sync::Mutex;

use eliot_kernel_service::{
    UserAutomationFailureRecord, UserAutomationNotificationDelivery,
    UserAutomationNotificationPort, UserAutomationRuntimeError,
};
use eliot_notify_core::{
    DeliveryObservation, NotifyError, UserAutomationFailureRequest, audience_for_envelope,
    failure_artifact_digest,
};
use eliot_platform::{NotificationRequest, PlatformHandle};

/// Production automation-failure notification adapter.
///
/// `F` is the live delivery call, typically closed over a composed
/// `NotifyCore`: `|failure, parent| composition.deliver_user_automation_failure(failure, parent)`.
pub struct AutomationNotificationAdapter<F>
where
    F: FnMut(
        UserAutomationFailureRequest,
        &NotificationRequest,
    ) -> Result<DeliveryObservation, NotifyError>,
{
    deliver: Mutex<F>,
}

impl<F> AutomationNotificationAdapter<F>
where
    F: FnMut(
        UserAutomationFailureRequest,
        &NotificationRequest,
    ) -> Result<DeliveryObservation, NotifyError>,
{
    /// Registers the live delivery call as the automation notification port.
    pub fn new(deliver: F) -> Self {
        Self {
            deliver: Mutex::new(deliver),
        }
    }
}

/// Owner-designated primary recipient and single bound artifact digest are
/// shared derivations owned by `eliot-notify-core` (see
/// [`audience_for_envelope`] and [`failure_artifact_digest`]); this adapter
/// only maps their failures into the port error vocabulary.
///
/// Provider gaps stay unavailable; every other adapter failure rejects.
fn map_notify_error(error: &NotifyError) -> UserAutomationRuntimeError {
    match error {
        NotifyError::PlanGap { reason, .. } => {
            UserAutomationRuntimeError::Unavailable(reason.to_string())
        }
        _ => UserAutomationRuntimeError::Rejected(error.to_string()),
    }
}

#[allow(async_fn_in_trait)]
impl<F> UserAutomationNotificationPort for AutomationNotificationAdapter<F>
where
    F: FnMut(
            UserAutomationFailureRequest,
            &NotificationRequest,
        ) -> Result<DeliveryObservation, NotifyError>
        + Send,
{
    async fn deliver_user_automation_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationNotificationDelivery, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let failure = UserAutomationFailureRequest::from_owner_failure(
            &request.failure,
            &request.preflight.source_receipt,
            &request.revision.automation_id,
            &request.revision.revision,
            &request.context.state_fence,
        )
        .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let source_receipt = request.preflight.source_receipt.clone();
        let envelope = failure
            .clone()
            .into_notification_envelope()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let body_digest = failure_artifact_digest(&source_receipt.core.artifacts)
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let parent = NotificationRequest {
            context: request.context.clone(),
            notification: envelope.notification_id.clone(),
            canonical_request_hash: PlatformHandle::new(envelope.source_receipt.canonical_sha256())
                .map_err(|_| {
                    UserAutomationRuntimeError::Rejected(
                        "automation canonical request hash invalid".to_owned(),
                    )
                })?,
            audience: audience_for_envelope(&envelope.recipients)
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?,
            body_digest: PlatformHandle::new(body_digest).map_err(|_| {
                UserAutomationRuntimeError::Rejected("automation body digest invalid".to_owned())
            })?,
        };
        let mut deliver = self
            .deliver
            .lock()
            .map_err(|_| UserAutomationRuntimeError::Rejected("adapter lock failed".to_owned()))?;
        let observation = deliver(failure, &parent).map_err(|error| map_notify_error(&error))?;
        let delivery = UserAutomationNotificationDelivery {
            state_fence: request.context.state_fence.clone(),
            dedup_key: envelope.canonical.dedup_key.clone(),
            deduplicated: observation.deduplicated,
            notification_receipt_ref: None,
        };
        delivery
            .validate_for(&request)
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        Ok(delivery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::ArtifactId;
    use eliot_notify_core::{ProviderId, Recipient, RecipientRole};
    use eliot_receipts::{ArtifactBinding, ReceiptKind};

    fn recipient(principal: &str) -> Recipient {
        Recipient {
            principal: PlatformHandle::new(principal).expect("principal"),
            role: RecipientRole::Requester,
        }
    }

    fn artifact(sha256: &str, role: ReceiptKind) -> ArtifactBinding {
        ArtifactBinding {
            artifact_id: ArtifactId::new("evidence-1").expect("artifact id"),
            sha256: sha256.to_owned(),
            role,
            source_revision: None,
        }
    }

    #[test]
    fn audience_picks_primary_recipient_and_rejects_empty() {
        let audience =
            audience_for_envelope(&[recipient("human-1"), recipient("human-2")]).expect("audience");
        assert_eq!(audience.as_str(), "human-1");
        assert!(audience_for_envelope(&[]).is_err());
    }

    #[test]
    fn artifact_digest_requires_exactly_one_bound_artifact() {
        let digest = "a".repeat(64);
        assert_eq!(
            failure_artifact_digest(&[artifact(&digest, ReceiptKind::Artifact)])
                .expect("single artifact"),
            digest
        );
        assert!(failure_artifact_digest(&[]).is_err());
        assert!(
            failure_artifact_digest(&[
                artifact(&digest, ReceiptKind::Artifact),
                artifact(&digest, ReceiptKind::Artifact),
            ])
            .is_err()
        );
        assert!(failure_artifact_digest(&[artifact(&digest, ReceiptKind::Verification)]).is_err());
    }

    #[test]
    fn plan_gap_stays_unavailable_and_contract_errors_reject() {
        assert!(matches!(
            map_notify_error(&NotifyError::PlanGap {
                provider: ProviderId::G08Problem,
                reason: "missing port",
            }),
            UserAutomationRuntimeError::Unavailable(_)
        ));
        assert!(matches!(
            map_notify_error(&NotifyError::InvalidEnvelope("recipients")),
            UserAutomationRuntimeError::Rejected(_)
        ));
    }
}
