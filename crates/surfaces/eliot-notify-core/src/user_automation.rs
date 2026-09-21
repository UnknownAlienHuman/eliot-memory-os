//! Canonical UserAutomation preflight and notification-failure producer.
//!
//! The Kernel/Host owner supplies one authenticated projection for the exact
//! immutable automation revision and occurrence. This module performs the
//! deterministic, model-free preflight boundary and turns a canonical
//! `blocked_config` result into the existing notification request. It owns no
//! scheduler, durable job, store, configuration authority, or model route.

use crate::{
    NotificationEnvelope, NotifyError, ProviderId, Recipient, UserAutomationFailureIdentity,
};
use eliot_config::ConfigPolicySnapshot;
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_kernel_core::NotificationDraft;
use eliot_platform::{NotificationRequest, PlatformHandle};
use eliot_receipts::ReceiptEnvelope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const OCCURRENCE_IDENTITY_DOMAIN: &str = "ELIOT/I11.12/USER-AUTOMATION-OCCURRENCE/V1";

/// Execution mode admitted by the immutable UserAutomation revision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationExecutionMode {
    Agent,
    DeterministicProcess,
}

/// Configuration state projected by the canonical UserAutomation owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationConfigurationState {
    Active,
    Paused,
    BlockedConfig,
    Retired,
}

/// The explicit trigger material used to identify one occurrence.
///
/// Scheduled keys are the owner-normalized exact calendar occurrence. Manual
/// execution requires a distinct explicit nonce and never mutates the
/// schedule.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationTrigger {
    Scheduled { occurrence_key: String },
    Manual { nonce: String },
}

/// Minimal invocation selector accepted by the production preflight entry.
/// It carries no settings, route, provider, credentials, or ambient identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationInvocation {
    pub automation_id: String,
    pub automation_revision: String,
    pub trigger: UserAutomationTrigger,
    pub mode: UserAutomationExecutionMode,
}

impl UserAutomationInvocation {
    /// Validates the opaque owner-issued revision and trigger references.
    pub fn validate(&self) -> Result<(), UserAutomationPreflightError> {
        validate_text(&self.automation_id, "automation_id")?;
        validate_text(&self.automation_revision, "automation_revision")?;
        match &self.trigger {
            UserAutomationTrigger::Scheduled { occurrence_key } => {
                validate_text(occurrence_key, "trigger.occurrence_key")?;
            }
            UserAutomationTrigger::Manual { nonce } => {
                validate_text(nonce, "trigger.nonce")?;
            }
        }
        Ok(())
    }

    /// Returns the stable identity for one normalized occurrence.
    ///
    /// Replayed scheduled wakes use the same owner-normalized key and
    /// therefore derive the same identity. A manual nonce creates a distinct
    /// identity without changing the schedule.
    pub fn occurrence_identity(&self) -> Result<String, UserAutomationPreflightError> {
        self.validate()?;
        let bytes = canonical_json_bytes(&(
            OCCURRENCE_IDENTITY_DOMAIN,
            &self.automation_id,
            &self.automation_revision,
            &self.trigger,
        ))
        .map_err(|_| UserAutomationPreflightError::Invalid("occurrence_identity"))?;
        Ok(format!("user-automation-occurrence:{}", sha256_hex(&bytes)))
    }
}

/// Owner-produced notification content for a blocked deterministic preflight.
///
/// The identity and deduplication key are deliberately omitted from this
/// projection. They are derived below from the immutable revision and
/// failure fingerprint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationNotificationProjection {
    pub canonical: NotificationDraft,
    pub subject: String,
    pub summary: String,
    pub recipients: Vec<Recipient>,
}

/// Backward-compatible descriptive alias for callers that name this content
/// as the failure notification itself.
pub type UserAutomationFailureNotification = UserAutomationNotificationProjection;

/// Typed response returned by the canonical Kernel/Host preflight read.
///
/// `config_snapshot` is the existing B-owned `ConfigPolicySnapshot`; this
/// module consumes and validates it but does not project or persist settings.
/// `source_receipt` is the owner-issued notification source receipt consumed
/// by the existing G-08 route. It is never minted here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightProjection {
    pub automation_id: String,
    pub automation_revision: String,
    pub occurrence_id: String,
    pub mode: UserAutomationExecutionMode,
    pub configuration_state: UserAutomationConfigurationState,
    pub config_snapshot: ConfigPolicySnapshot,
    pub source_receipt: ReceiptEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification: Option<UserAutomationNotificationProjection>,
}

/// Receipt-shaped preflight result returned to the runtime caller.
///
/// The embedded receipt is the existing owner-issued receipt. This type only
/// binds it to the immutable UserAutomation projection for the caller's
/// response; it is not a second authority or receipt issuer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightReceipt {
    pub automation_id: String,
    pub automation_revision: String,
    pub occurrence_id: String,
    pub config_snapshot_id: String,
    pub configuration_state: UserAutomationConfigurationState,
    pub source_receipt: ReceiptEnvelope,
}

/// Deterministic preflight outcome. No branch invokes a model.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationPreflightDecision {
    Admitted {
        receipt: UserAutomationPreflightReceipt,
    },
    Deferred {
        receipt: UserAutomationPreflightReceipt,
    },
    BlockedConfig {
        receipt: UserAutomationPreflightReceipt,
        failure: UserAutomationFailureRequest,
    },
}

/// Fail-closed errors for the deterministic UserAutomation boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationPreflightError {
    #[error("invalid UserAutomation preflight field: {0}")]
    Invalid(&'static str),
    #[error("canonical configuration snapshot is invalid: {0}")]
    Config(String),
    #[error("authenticated source receipt is invalid: {0}")]
    Receipt(String),
    #[error("authenticated source receipt does not match the notification request")]
    ReceiptBinding,
    #[error("preflight projection does not match the requested automation revision")]
    RevisionMismatch,
    #[error("preflight projection does not match the requested occurrence")]
    OccurrenceMismatch,
    #[error("blocked_config requires an owner-issued failure fingerprint")]
    FailureFingerprintMissing,
    #[error("blocked_config requires an owner-issued notification projection")]
    NotificationMissing,
}

impl UserAutomationPreflightProjection {
    /// Runs the model-free canonical preflight and, when blocked, produces the
    /// exact request consumed by the existing authenticated notify route.
    pub fn preflight(
        &self,
        invocation: &UserAutomationInvocation,
        request: &NotificationRequest,
    ) -> Result<UserAutomationPreflightDecision, UserAutomationPreflightError> {
        invocation.validate()?;
        if self.automation_id != invocation.automation_id
            || self.automation_revision != invocation.automation_revision
        {
            return Err(UserAutomationPreflightError::RevisionMismatch);
        }
        if self.mode != invocation.mode {
            return Err(UserAutomationPreflightError::Invalid("mode"));
        }
        if self.occurrence_id != invocation.occurrence_identity()? {
            return Err(UserAutomationPreflightError::OccurrenceMismatch);
        }
        self.config_snapshot
            .validate()
            .map_err(|error| UserAutomationPreflightError::Config(error.to_string()))?;
        if self.config_snapshot.state_fence != request.context.state_fence
            || self.config_snapshot.state_fence.policy_revision
                != Some(self.config_snapshot.revision)
        {
            return Err(UserAutomationPreflightError::Invalid(
                "config_snapshot.state_fence",
            ));
        }
        self.source_receipt
            .validate()
            .map_err(|error| UserAutomationPreflightError::Receipt(error.to_string()))?;
        if self.source_receipt.core.request.metadata != request.context
            || self.source_receipt.core.request.state_fence != request.context.state_fence
            || self.source_receipt.core.work_scope.product_id != request.context.product_id
            || self.source_receipt.core.work_scope.state_fence != request.context.state_fence
        {
            return Err(UserAutomationPreflightError::ReceiptBinding);
        }

        let receipt = UserAutomationPreflightReceipt {
            automation_id: self.automation_id.clone(),
            automation_revision: self.automation_revision.clone(),
            occurrence_id: self.occurrence_id.clone(),
            config_snapshot_id: self.config_snapshot.snapshot_id.clone(),
            configuration_state: self.configuration_state,
            source_receipt: self.source_receipt.clone(),
        };
        match self.configuration_state {
            UserAutomationConfigurationState::Active => {
                if self.failure_fingerprint.is_some() || self.notification.is_some() {
                    return Err(UserAutomationPreflightError::Invalid(
                        "active failure projection",
                    ));
                }
                Ok(UserAutomationPreflightDecision::Admitted { receipt })
            }
            UserAutomationConfigurationState::Paused
            | UserAutomationConfigurationState::Retired => {
                if self.failure_fingerprint.is_some() || self.notification.is_some() {
                    return Err(UserAutomationPreflightError::Invalid(
                        "deferred failure projection",
                    ));
                }
                Ok(UserAutomationPreflightDecision::Deferred { receipt })
            }
            UserAutomationConfigurationState::BlockedConfig => {
                let failure_fingerprint = self
                    .failure_fingerprint
                    .as_deref()
                    .ok_or(UserAutomationPreflightError::FailureFingerprintMissing)?;
                validate_text(failure_fingerprint, "failure_fingerprint")?;
                let notification = self
                    .notification
                    .as_ref()
                    .ok_or(UserAutomationPreflightError::NotificationMissing)?;
                let failure = self.failure_request(failure_fingerprint, notification, request)?;
                Ok(UserAutomationPreflightDecision::BlockedConfig { receipt, failure })
            }
        }
    }

    fn failure_request(
        &self,
        failure_fingerprint: &str,
        notification: &UserAutomationNotificationProjection,
        request: &NotificationRequest,
    ) -> Result<UserAutomationFailureRequest, UserAutomationPreflightError> {
        let identity = UserAutomationFailureIdentity::new(
            self.automation_id.clone(),
            self.automation_revision.clone(),
            failure_fingerprint,
        )
        .map_err(|_| UserAutomationPreflightError::Invalid("failure_identity"))?;
        if notification.canonical.state_fence != request.context.state_fence
            || notification.canonical.subject != notification.subject
            || notification.canonical.summary != notification.summary
            || notification.recipients.is_empty()
        {
            return Err(UserAutomationPreflightError::Invalid(
                "notification_projection",
            ));
        }
        let canonical = identity
            .bind_draft(notification.canonical.clone())
            .map_err(|_| UserAutomationPreflightError::Invalid("notification_projection"))?;
        let envelope = NotificationEnvelope {
            notification_id: canonical.notification_id.clone(),
            canonical,
            subject: notification.subject.clone(),
            summary: notification.summary.clone(),
            recipients: notification.recipients.clone(),
            source_receipt: self.source_receipt.clone(),
            user_automation_failure: Some(identity),
        };
        Ok(UserAutomationFailureRequest {
            automation_id: self.automation_id.clone(),
            automation_revision: self.automation_revision.clone(),
            failure_fingerprint: failure_fingerprint.to_owned(),
            notification: envelope,
        })
    }
}

/// Typed input emitted by a UserAutomation deterministic preflight/failure
/// boundary that already has an owner-issued notification envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Deserialize, Serialize)]
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

    /// Rebinds only the derived notification identity and source receipt hash
    /// on a parent request. Context, body digest, audience and all authority
    /// fields remain caller-owned and are checked by the existing route.
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
}

fn validate_text(value: &str, field: &'static str) -> Result<(), UserAutomationPreflightError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(UserAutomationPreflightError::Invalid(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FailureFingerprintRef, RecipientRole};
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_security_contracts::PolicyFence;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
        fence.policy_revision = Some(eliot_contracts::PolicyRevision::genesis());
        fence
    }

    fn request() -> NotificationRequest {
        let metadata = RequestMetadata {
            request_id: RequestId::new("automation-request").expect("request id"),
            session_id: Some(SessionId::new("session-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("eliot-test").expect("product"),
            source_id: SourceId::new("eliot-user-automation").expect("source"),
            state_fence: fence(),
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

    fn snapshot() -> ConfigPolicySnapshot {
        let state_fence = fence();
        ConfigPolicySnapshot {
            snapshot_id: "snapshot-1".to_owned(),
            machine_id: "machine-1".to_owned(),
            scope_id: "user-automation".to_owned(),
            revision: eliot_contracts::PolicyRevision::genesis(),
            source_completeness: eliot_config::SourceCompleteness::Complete,
            settings: Vec::new(),
            policy_owner: eliot_config::HumanOwner {
                owner_ref: "human-1".to_owned(),
            },
            policy_fence: PolicyFence {
                policy_snapshot_id: "snapshot-1".to_owned(),
                state_fence: state_fence.clone(),
            },
            state_fence,
            parent_snapshot_id: None,
            rollback_of: None,
        }
    }

    fn invocation(trigger: UserAutomationTrigger) -> UserAutomationInvocation {
        UserAutomationInvocation {
            automation_id: "automation-1".to_owned(),
            automation_revision: "revision-7".to_owned(),
            trigger,
            mode: UserAutomationExecutionMode::DeterministicProcess,
        }
    }

    fn source_receipt(request: &NotificationRequest) -> ReceiptEnvelope {
        let core: eliot_receipts::ReceiptCore = serde_json::from_value(serde_json::json!({
            "contract": eliot_receipts::contract_identity().expect("contract"),
            "kind":"VERIFICATION",
            "work_scope": {"scope_id":"scope-1","product_id":"eliot-test","resource_generation":request.context.state_fence.resource_generation,"state_fence":request.context.state_fence},
            "task": null,
            "session": {"session_id":request.context.session_id,"authority_epoch":request.context.state_fence.authority_epoch,"state_fence":request.context.state_fence},
            "causal": {"state_fence":request.context.state_fence,"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]},
            "request": {"metadata":request.context,"state_fence":request.context.state_fence},
            "operation": {"operation_id":"operation-g08","request_id":request.context.request_id,"idempotency_key":"source-key","operation_kind":"g08_notification_projection","effect": "READ","state_fence":request.context.state_fence},
            "authority": {"authority_id":"authority-g08","authority_owner":"G-08","authority_epoch":request.context.state_fence.authority_epoch,"state_fence":request.context.state_fence,"allowed_effect":"READ","proof_ceiling":"SCOPED_VERIFICATION"},
            "artifacts": [],
            "verifier": null,
            "problem": null,
            "coordination": null,
            "disposition": {"kind":"SUCCESS","proof":"SCOPED_VERIFICATION"}
        }))
        .expect("receipt core fixture");
        ReceiptEnvelope::issue(core).expect("receipt fixture")
    }

    fn projection(
        request: &NotificationRequest,
        state: UserAutomationConfigurationState,
        notification: Option<UserAutomationNotificationProjection>,
        fingerprint: Option<&str>,
    ) -> (UserAutomationInvocation, UserAutomationPreflightProjection) {
        let invocation = invocation(UserAutomationTrigger::Scheduled {
            occurrence_key: "2026-09-21T12:00:00Z".to_owned(),
        });
        let projection = UserAutomationPreflightProjection {
            automation_id: invocation.automation_id.clone(),
            automation_revision: invocation.automation_revision.clone(),
            occurrence_id: invocation.occurrence_identity().expect("occurrence"),
            mode: invocation.mode,
            configuration_state: state,
            config_snapshot: snapshot(),
            source_receipt: source_receipt(request),
            failure_fingerprint: fingerprint.map(str::to_owned),
            notification,
        };
        (invocation, projection)
    }

    fn notification(request: &NotificationRequest) -> UserAutomationNotificationProjection {
        UserAutomationNotificationProjection {
            canonical: NotificationDraft {
                notification_id: PlatformHandle::new("caller-id").expect("id"),
                severity: crate::NotificationSeverity::ActionRequired,
                subject: "Automation blocked".to_owned(),
                summary: "Configuration requires attention".to_owned(),
                evidence_handles: vec!["preflight-receipt".to_owned()],
                affected_scope: "automation-1".to_owned(),
                owner: "UserAutomation".to_owned(),
                required_action: "Review configuration".to_owned(),
                deadline_or_review: None,
                dedup_key: "caller-key".to_owned(),
                delivery_channels: vec![
                    eliot_kernel_core::DeliveryChannel::ControlBoard,
                    eliot_kernel_core::DeliveryChannel::NativeToast,
                ],
                state_fence: request.context.state_fence.clone(),
            },
            subject: "Automation blocked".to_owned(),
            summary: "Configuration requires attention".to_owned(),
            recipients: vec![Recipient {
                principal: PlatformHandle::new("human-1").expect("principal"),
                role: RecipientRole::AuthorizedRole,
            }],
        }
    }

    #[test]
    fn occurrence_identity_replays_scheduled_wakes_and_separates_manual_nonce() {
        let scheduled = invocation(UserAutomationTrigger::Scheduled {
            occurrence_key: "2026-09-21T12:00:00Z".to_owned(),
        });
        let replay = scheduled.clone();
        let manual = invocation(UserAutomationTrigger::Manual {
            nonce: "manual-1".to_owned(),
        });
        assert_eq!(
            scheduled.occurrence_identity(),
            replay.occurrence_identity()
        );
        assert_ne!(
            scheduled.occurrence_identity(),
            manual.occurrence_identity()
        );
    }

    #[test]
    fn blocked_config_produces_identity_bound_failure_before_any_model_path() {
        let request = request();
        let (invocation, projection) = projection(
            &request,
            UserAutomationConfigurationState::BlockedConfig,
            Some(notification(&request)),
            Some("blocked_config:provider-fingerprint"),
        );
        let decision = projection
            .preflight(&invocation, &request)
            .expect("blocked preflight");
        let UserAutomationPreflightDecision::BlockedConfig { failure, .. } = decision else {
            panic!("blocked configuration must produce a failure notification request");
        };
        let envelope = failure
            .clone()
            .into_notification_envelope()
            .expect("failure envelope");
        assert_eq!(
            envelope
                .user_automation_failure
                .as_ref()
                .expect("identity")
                .failure_fingerprint,
            FailureFingerprintRef {
                fingerprint: "blocked_config:provider-fingerprint".to_owned(),
            }
        );
        let bound = failure
            .bind_notification_request(&request)
            .expect("bound request");
        assert_eq!(bound.notification, envelope.notification_id);
        assert_eq!(
            bound.canonical_request_hash.as_str(),
            envelope.source_receipt.canonical_sha256()
        );
    }

    #[test]
    fn active_projection_admits_without_failure_payload() {
        let request = request();
        let (invocation, projection) = projection(
            &request,
            UserAutomationConfigurationState::Active,
            None,
            None,
        );
        assert!(matches!(
            projection.preflight(&invocation, &request),
            Ok(UserAutomationPreflightDecision::Admitted { .. })
        ));
    }
}
