//! Thin notification adapter for the Kernel-owned UserAutomation contract.
//!
//! The immutable revision, schedule, occurrence identity, execution
//! projection, preflight decision and failure fingerprint are owned by
//! [`eliot_kernel_core`]. This module only binds an owner-issued failure
//! projection to the existing G-08/A-08 notification envelope and delivery
//! request. It owns no scheduler, revision store, provider route, or preflight
//! authority.

use crate::{
    NotificationEnvelope, NotifyError, ProviderId, Recipient, RecipientRole,
    UserAutomationFailureIdentity,
};
use eliot_contracts::RequestMetadata;
use eliot_kernel_core::{
    AutomationFailureNotificationProjection, AutomationRecipientRole, UserAutomationError,
    UserAutomationFailureProjection, UserAutomationPreflightContext,
    UserAutomationPreflightDecision as KernelPreflightDecision,
    UserAutomationPreflightProjection as KernelPreflightProjection,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use eliot_receipts::ReceiptEnvelope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use eliot_kernel_core::{
    UserAutomationConfigurationState, UserAutomationDeferReason, UserAutomationExecutionMode,
    UserAutomationInvocation, UserAutomationPreflightReceipt, UserAutomationTrigger,
};

/// Surface-level preflight error. The semantic error remains the Kernel error;
/// notification binding errors are kept at this adapter boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationPreflightError {
    /// Kernel rejected the immutable projection or authenticated context.
    #[error("Kernel UserAutomation preflight rejected: {0}")]
    Kernel(#[from] UserAutomationError),
    /// The owner failure projection could not be bound to the notification request.
    #[error("UserAutomation failure notification projection rejected: {0}")]
    Notification(String),
}

/// Owner-projected notification content retained as a surface DTO for callers
/// that construct the envelope adapter directly.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationNotificationProjection {
    /// Canonical notification draft before identity binding.
    pub canonical: eliot_kernel_core::NotificationDraft,
    /// Human-facing subject.
    pub subject: String,
    /// Human-facing summary.
    pub summary: String,
    /// Surface recipient list.
    pub recipients: Vec<Recipient>,
}

/// Backward-compatible descriptive alias for this surface content.
pub type UserAutomationFailureNotification = UserAutomationNotificationProjection;

/// Canonical Kernel projection decoded directly at the notification surface.
pub type UserAutomationPreflightProjection = KernelPreflightProjection;

/// Runs the Kernel's model-free preflight and adapts a blocked failure to the
/// existing authenticated notification route.
pub fn preflight_user_automation(
    projection: &UserAutomationPreflightProjection,
    invocation: &UserAutomationInvocation,
    request: &NotificationRequest,
) -> Result<UserAutomationPreflightDecision, UserAutomationPreflightError> {
    let decision = projection.preflight(invocation, &preflight_context(request))?;
    match decision {
        KernelPreflightDecision::Admitted { receipt } => {
            Ok(UserAutomationPreflightDecision::Admitted { receipt })
        }
        KernelPreflightDecision::Deferred { receipt, reason } => {
            Ok(UserAutomationPreflightDecision::Deferred { receipt, reason })
        }
        KernelPreflightDecision::BlockedConfig { receipt, failure } => {
            let failure = UserAutomationFailureRequest::from_kernel_projection(
                &failure,
                &projection.source_receipt,
                &projection.automation_id,
                &projection.automation_revision,
                request,
            )
            .map_err(|error| UserAutomationPreflightError::Notification(error.to_string()))?;
            Ok(UserAutomationPreflightDecision::BlockedConfig { receipt, failure })
        }
    }
}

/// Surface-adapted deterministic preflight decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationPreflightDecision {
    /// The occurrence may join the existing Durable Job route.
    Admitted {
        /// Kernel-issued preflight receipt.
        receipt: UserAutomationPreflightReceipt,
    },
    /// The occurrence remains unadmitted under an existing owner policy.
    Deferred {
        /// Kernel-issued preflight receipt.
        receipt: UserAutomationPreflightReceipt,
        /// Existing owner that must release or requeue the occurrence.
        reason: eliot_kernel_core::UserAutomationDeferReason,
    },
    /// Configuration failure ready for one identity-bound notification.
    BlockedConfig {
        /// Kernel-issued preflight receipt.
        receipt: UserAutomationPreflightReceipt,
        /// Existing notification delivery request with canonical failure identity.
        failure: UserAutomationFailureRequest,
    },
}

/// Typed input emitted by the notification adapter for one blocked occurrence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailureRequest {
    /// Stable automation identity supplied by the Kernel owner.
    pub automation_id: String,
    /// Immutable revision supplied by the Kernel owner.
    pub automation_revision: String,
    /// Owner-issued deterministic failure class.
    pub failure_fingerprint: String,
    /// Existing notification envelope content and source receipt.
    pub notification: NotificationEnvelope,
}

impl UserAutomationFailureRequest {
    fn from_kernel_projection(
        failure: &UserAutomationFailureProjection,
        source_receipt: &ReceiptEnvelope,
        automation_id: &str,
        automation_revision: &str,
        request: &NotificationRequest,
    ) -> Result<Self, NotifyError> {
        let notification = bind_failure_notification(
            &failure.notification,
            source_receipt,
            automation_id,
            automation_revision,
            &failure.failure_fingerprint,
            request,
        )?;
        Ok(Self {
            automation_id: automation_id.to_owned(),
            automation_revision: automation_revision.to_owned(),
            failure_fingerprint: failure.failure_fingerprint.clone(),
            notification,
        })
    }

    /// Binds the owner identity to the existing notification request without
    /// changing its authenticated context, audience or effect ceiling.
    pub fn bind_notification_request(
        &self,
        request: &NotificationRequest,
    ) -> Result<NotificationRequest, NotifyError> {
        let envelope = self.clone().into_notification_envelope()?;
        let mut bound = request.clone();
        bound.notification = envelope.notification_id;
        bound.canonical_request_hash =
            PlatformHandle::new(envelope.source_receipt.canonical_sha256())
                .map_err(NotifyError::Port)?;
        bound.validate().map_err(NotifyError::Port)?;
        Ok(bound)
    }

    /// Rebinds the identity and verifies the existing source receipt before
    /// passing the envelope to the normal G-08/A-08 delivery path.
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

fn bind_failure_notification(
    projection: &AutomationFailureNotificationProjection,
    source_receipt: &ReceiptEnvelope,
    automation_id: &str,
    automation_revision: &str,
    failure_fingerprint: &str,
    request: &NotificationRequest,
) -> Result<NotificationEnvelope, NotifyError> {
    let identity = UserAutomationFailureIdentity::new(
        automation_id,
        automation_revision,
        failure_fingerprint,
    )?;
    if projection.canonical.state_fence != request.context.state_fence
        || projection.canonical.subject != projection.subject
        || projection.canonical.summary != projection.summary
        || projection.recipients.is_empty()
        || projection.canonical.state_fence != source_receipt.core.request.state_fence
    {
        return Err(NotifyError::InvalidEnvelope(
            "user_automation_failure.projection",
        ));
    }
    let recipients = projection
        .recipients
        .iter()
        .map(|recipient| {
            Ok(Recipient {
                principal: recipient.principal.clone(),
                role: map_recipient_role(recipient.role),
            })
        })
        .collect::<Result<Vec<_>, NotifyError>>()?;
    let canonical = identity.bind_draft(projection.canonical.clone())?;
    Ok(NotificationEnvelope {
        notification_id: canonical.notification_id.clone(),
        canonical,
        subject: projection.subject.clone(),
        summary: projection.summary.clone(),
        recipients,
        source_receipt: source_receipt.clone(),
        user_automation_failure: Some(identity),
    })
}

fn map_recipient_role(role: AutomationRecipientRole) -> RecipientRole {
    match role {
        AutomationRecipientRole::Requester => RecipientRole::Requester,
        AutomationRecipientRole::DomainOwner => RecipientRole::DomainOwner,
        AutomationRecipientRole::ArchitectureOwner => RecipientRole::ArchitectureOwner,
        AutomationRecipientRole::SystemOwner => RecipientRole::SystemOwner,
        AutomationRecipientRole::WorkScopeOwner => RecipientRole::WorkScopeOwner,
        AutomationRecipientRole::Approver => RecipientRole::Approver,
        AutomationRecipientRole::RecoveryPrincipal => RecipientRole::RecoveryPrincipal,
        AutomationRecipientRole::AuthorizedRole => RecipientRole::AuthorizedRole,
    }
}

/// Constructs the Kernel context explicitly from the authenticated request.
#[must_use]
pub fn preflight_context(request: &NotificationRequest) -> UserAutomationPreflightContext {
    UserAutomationPreflightContext {
        request_metadata: RequestMetadata {
            ..request.context.clone()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SessionId,
        SourceId, StateFence,
    };
    use std::num::NonZeroU64;

    fn request() -> NotificationRequest {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
        fence.policy_revision = Some(eliot_contracts::PolicyRevision::genesis());
        let metadata = eliot_contracts::RequestMetadata {
            request_id: RequestId::new("automation-request").expect("request"),
            session_id: Some(SessionId::new("session-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("eliot-test").expect("product"),
            source_id: SourceId::new("eliot-user-automation").expect("source"),
            state_fence: fence,
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        };
        NotificationRequest {
            context: metadata,
            canonical_request_hash: PlatformHandle::new("placeholder").expect("hash"),
            notification: PlatformHandle::new("placeholder").expect("notification"),
            audience: PlatformHandle::new("human-1").expect("audience"),
            body_digest: PlatformHandle::new("body").expect("body"),
        }
    }

    #[test]
    fn adapter_preserves_kernel_occurrence_identity_and_failure_identity() {
        let invocation = UserAutomationInvocation {
            automation_id: "automation-1".to_owned(),
            automation_revision: "revision-7".to_owned(),
            trigger: UserAutomationTrigger::Manual {
                nonce: "manual-1".to_owned(),
            },
            mode: UserAutomationExecutionMode::DeterministicProcess,
            principal_ref: "human-1".to_owned(),
            work_scope_ref: "scope-1".to_owned(),
            workdir_ref: "workdir-1".to_owned(),
            trigger_origin: eliot_kernel_core::UserAutomationTriggerOrigin::Human,
            child_depth: 0,
        };
        let replay = invocation.clone();
        assert_eq!(
            invocation.occurrence_identity(),
            replay.occurrence_identity()
        );

        let identity = UserAutomationFailureIdentity::new(
            &invocation.automation_id,
            &invocation.automation_revision,
            "failure-fingerprint",
        )
        .expect("identity");
        let replay_identity = UserAutomationFailureIdentity::new(
            &invocation.automation_id,
            &invocation.automation_revision,
            "failure-fingerprint",
        )
        .expect("replay identity");
        assert_eq!(identity.dedup_key(), replay_identity.dedup_key());
        let _ = request();
    }
}
