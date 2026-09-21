//! Canonical notification-state wire contract (issue #1780, I11.5/I11.7).
//!
//! This module owns the shared typed notification record, the closed
//! notification mutation/read contract, wire validation, and the pure
//! record-state transition model used by the canonical backend. It contains
//! no database, transport, clock, or authority implementation: persistence,
//! locking, receipt/outbox commit, and front-door authentication live in the
//! adapter and Kernel service owners, which call into this contract.
//!
//! Wire identity: [`NOTIFICATION_STATE_SCHEMA_V1`] (`eliot.notify.state.v1`).
//! Mutation operation: `ApplyNotificationState`. Read operation:
//! `GetNotificationState`. Transition class: `NotificationState` with a
//! `ReversibleMutation` ceiling. Records are keyed by `dedup_key`; repeats
//! update one record and increment `occurrences`, never create a second
//! record. Delivery, acknowledgement, and evidence-backed resolution are
//! separate mutations; acknowledgement never resolves.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    EffectClass, NamedMutationOperation, NamedMutationRequest, NamedReadOperation,
    NamedReadRequest, OperationIdentity, ProofCeiling, ReadConsistency, ReceiptDisposition,
    ReceiptEnvelope, ReceiptKind, RequestMetadata, StateFence, StoreError,
};
use eliot_contracts::fences_match_exact;

/// Versioned wire/schema identity for canonical notification state.
pub const NOTIFICATION_STATE_SCHEMA_V1: &str = "eliot.notify.state.v1";
/// Closed mutation operation name for notification-state transitions.
pub const NOTIFICATION_STATE_MUTATION_NAME: &str = "ApplyNotificationState";
/// Closed read operation name for the notification-state projection.
pub const NOTIFICATION_STATE_READ_NAME: &str = "GetNotificationState";
/// Fixed transition scope for all notification records.
pub const NOTIFICATION_STATE_SCOPE: &str = "notification-state";
/// Maximum accepted `dedup_key` length in bytes.
pub const MAX_DEDUP_KEY_BYTES: usize = 256;
/// Maximum accepted read page size.
pub const MAX_NOTIFICATION_PAGE_LIMIT: u16 = 128;

/// Mutation discriminator parameter.
pub const NOTIFY_PARAM_MUTATION: &str = "mutation";
/// Deduplication-key parameter (record index; exact read selector).
pub const NOTIFY_PARAM_DEDUP_KEY: &str = "dedup_key";
/// Optional record-scope filter (read).
pub const NOTIFY_PARAM_SCOPE: &str = "scope";
/// Notification identity parameter (delivery/ack/resolve legs).
pub const NOTIFY_PARAM_NOTIFICATION_ID: &str = "notification_id";
/// Canonical `NotificationRecordInput` JSON (upsert leg).
pub const NOTIFY_PARAM_RECORD_JSON: &str = "record_json";
/// Canonical source `ReceiptEnvelope` JSON (upsert leg).
pub const NOTIFY_PARAM_SOURCE_RECEIPT_JSON: &str = "source_receipt_json";
/// Canonical `DeliveryState` JSON (delivery leg).
pub const NOTIFY_PARAM_DELIVERY_JSON: &str = "delivery_json";
/// Delivery channel selector (delivery leg).
pub const NOTIFY_PARAM_CHANNEL: &str = "channel";
/// Acknowledging principal (acknowledge leg).
pub const NOTIFY_PARAM_PRINCIPAL: &str = "principal";
/// Human disposition (resolve leg).
pub const NOTIFY_PARAM_DISPOSITION: &str = "disposition";
/// Canonical resolution authorization JSON (resolve leg).
pub const NOTIFY_PARAM_AUTHORIZATION_JSON: &str = "authorization_json";
/// Optional record-scope filter (read).
/// `"true"` or `"false"` resolved-row inclusion (read, required).
pub const NOTIFY_PARAM_INCLUDE_RESOLVED: &str = "include_resolved";
/// Decimal page-size bound (read, required).
pub const NOTIFY_PARAM_PAGE_LIMIT: &str = "page_limit";
/// Opaque dedup-key cursor (read, optional).
pub const NOTIFY_PARAM_CURSOR: &str = "cursor";

/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_UPSERT: &str = "UPSERT";
/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_DELIVERY: &str = "DELIVERY";
/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_ACKNOWLEDGE: &str = "ACKNOWLEDGE";
/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_RESOLVE: &str = "RESOLVE";

/// Fail-closed notification contract errors before [`StoreError`] projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NotificationContractError {
    /// A field failed bounded validation.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// The mutation discriminator is unknown.
    #[error("unknown notification mutation leg")]
    UnknownMutation,
    /// A required leg parameter is absent.
    #[error("missing notification parameter: {0}")]
    MissingParameter(&'static str),
}

impl NotificationContractError {
    /// Projects the contract error onto the closed store error set.
    #[must_use]
    pub const fn into_store_error(self) -> StoreError {
        match self {
            Self::InvalidField { field, reason } => StoreError::InvalidField { field, reason },
            Self::UnknownMutation => StoreError::UnknownOperation,
            Self::MissingParameter(name) => StoreError::InvalidField {
                field: name,
                reason: "missing required notification parameter",
            },
        }
    }
}

/// Severity carried on the canonical I11.5 record.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationSeverity {
    /// Integrity, security, unknown-effect or control-loss condition.
    Critical,
    /// Approval, blocked task, failed credential or failed repair requiring action.
    ActionRequired,
    /// Degraded hook, repeated failure, stale backup or pressure condition.
    Warning,
    /// Verified completion, maintenance result or available update.
    #[serde(rename = "INFO")]
    Information,
}

/// Canonical delivery channel recorded with the notification.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryChannel {
    /// Persistent ControlBoard inbox/read projection.
    ControlBoard,
    /// Normal authenticated user-session native toast.
    NativeToast,
    /// Windows Event Log fallback channel.
    WindowsEventLog,
    /// Watchdog or User Broker recovery route.
    RecoveryFallback,
}

impl DeliveryChannel {
    /// Parses the closed wire channel selector.
    pub fn parse_wire(value: &str) -> Result<Self, NotificationContractError> {
        match value {
            "CONTROL_BOARD" => Ok(Self::ControlBoard),
            "NATIVE_TOAST" => Ok(Self::NativeToast),
            "WINDOWS_EVENT_LOG" => Ok(Self::WindowsEventLog),
            "RECOVERY_FALLBACK" => Ok(Self::RecoveryFallback),
            _ => Err(NotificationContractError::InvalidField {
                field: "notification.channel",
                reason: "unknown delivery channel",
            }),
        }
    }
}

/// Latest canonical delivery observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DeliveryState {
    /// Canonical record exists, but no delivery outcome is known yet.
    Pending,
    /// Latest attempt was delivered without resolving the record.
    Delivered,
    /// Latest attempt failed and remains visible to the operator.
    Failed {
        /// Stable machine-readable failure reason.
        reason: String,
    },
    /// Some delivery evidence is known while named gaps remain.
    Partial {
        /// Named gap description.
        reason: String,
    },
    /// Delivery crossed an uncertain boundary and needs reconciliation.
    Unknown {
        /// Uncertainty description.
        reason: String,
    },
}

impl DeliveryState {
    /// Validates a delivery observation before the canonical owner admits it.
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        match self {
            Self::Pending | Self::Delivered => Ok(()),
            Self::Failed { reason } | Self::Partial { reason } | Self::Unknown { reason } => {
                text(reason, "notification.delivery.reason")
            }
        }
    }

    /// Returns whether the latest attempt must remain visible as degraded.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::Failed { .. } | Self::Partial { .. } | Self::Unknown { .. }
        )
    }
}

/// Optional deadline or human review boundary from I11.5.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlineOrReview {
    /// Absolute Unix milliseconds when a bounded deadline exists.
    pub deadline_unix_ms: Option<i64>,
    /// Stable review/approval handle when a human review is required.
    pub review_ref: Option<String>,
}

impl DeadlineOrReview {
    /// Validates the deadline/review boundary.
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        if self.deadline_unix_ms.is_none() && self.review_ref.is_none() {
            return Err(NotificationContractError::InvalidField {
                field: "notification.deadline_or_review",
                reason: "deadline or review handle is required",
            });
        }
        if self.deadline_unix_ms.is_some_and(|value| value < 0) {
            return Err(NotificationContractError::InvalidField {
                field: "notification.deadline_unix_ms",
                reason: "deadline must not be negative",
            });
        }
        if let Some(review_ref) = &self.review_ref {
            text(review_ref, "notification.review_ref")?;
        }
        Ok(())
    }
}

/// Toast-suppression acknowledgement. It never resolves the record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    /// Principal that acknowledged the record.
    pub principal: String,
    /// Owner sequence at acknowledgement time (backend-assigned).
    pub sequence: u64,
}

/// Evidence-backed terminal disposition stored on the canonical record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRef {
    /// Immutable receipt identity that authorized the disposition.
    pub receipt_id: String,
    /// Protected authority identity, derived from the receipt.
    pub authority_id: String,
    /// Protected authority owner, derived from the receipt.
    pub authority_owner: String,
    /// Evidence handles bound by that receipt.
    pub evidence_handles: Vec<String>,
    /// Human disposition recorded by the owner.
    pub disposition: String,
}

/// Protected authorization presented with the resolve mutation.
///
/// The receipt is the authority and evidence binding. There is deliberately
/// no caller-controlled `authorized` boolean and no free-standing authorizer
/// string accepted by the transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionAuthorization {
    /// Immutable Kernel-issued authority/evidence envelope.
    pub receipt: ReceiptEnvelope,
    /// Handles that the disposition claims as its supporting evidence.
    pub evidence_handles: Vec<String>,
}

/// Complete canonical I11.5 caller input before lifecycle observations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRecordInput {
    /// Caller-proposed notification identity (store owns the dedup index and
    /// rejects identity substitution under an existing key).
    pub notification_id: String,
    /// I11.5 severity.
    pub severity: NotificationSeverity,
    /// Short operator-visible subject.
    pub subject: String,
    /// Operator-visible summary.
    pub summary: String,
    /// Evidence handles available at creation.
    pub evidence_handles: Vec<String>,
    /// Affected scope handle.
    pub affected_scope: String,
    /// Owning principal for resolution authority binding.
    pub owner: String,
    /// Required operator action.
    pub required_action: String,
    /// Optional deadline or review boundary.
    pub deadline_or_review: Option<DeadlineOrReview>,
    /// Stable key owning exactly one canonical record.
    pub dedup_key: String,
    /// Delivery channels eligible for this record.
    pub delivery_channels: Vec<DeliveryChannel>,
    /// Fence the record is admitted under.
    pub state_fence: StateFence,
}

impl NotificationRecordInput {
    /// Validates all caller-provided canonical fields before owner admission.
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        text(&self.notification_id, "notification.notification_id")?;
        validate_dedup_key(&self.dedup_key)?;
        text(&self.subject, "notification.subject")?;
        text(&self.summary, "notification.summary")?;
        validate_text_list(&self.evidence_handles, "notification.evidence_handle")?;
        text(&self.affected_scope, "notification.affected_scope")?;
        text(&self.owner, "notification.owner")?;
        text(&self.required_action, "notification.required_action")?;
        if let Some(deadline_or_review) = &self.deadline_or_review {
            deadline_or_review.validate()?;
        }
        if self.delivery_channels.is_empty() {
            return Err(NotificationContractError::InvalidField {
                field: "notification.delivery_channels",
                reason: "at least one delivery channel is required",
            });
        }
        let mut channels = BTreeSet::new();
        if self
            .delivery_channels
            .iter()
            .any(|channel| !channels.insert(channel))
        {
            return Err(NotificationContractError::InvalidField {
                field: "notification.delivery_channels",
                reason: "delivery channels must be unique",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| NotificationContractError::InvalidField {
                field: "notification.state_fence",
                reason: "state fence is invalid",
            })
    }
}

/// Canonical persistent notification record owned by the Kernel/store path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRecord {
    /// Canonical notification identity.
    pub notification_id: String,
    /// I11.5 severity.
    pub severity: NotificationSeverity,
    /// Short operator-visible subject.
    pub subject: String,
    /// Operator-visible summary.
    pub summary: String,
    /// Evidence handles available on the record.
    pub evidence_handles: Vec<String>,
    /// Affected scope handle.
    pub affected_scope: String,
    /// Owning principal for resolution authority binding.
    pub owner: String,
    /// Required operator action.
    pub required_action: String,
    /// Optional deadline or review boundary.
    pub deadline_or_review: Option<DeadlineOrReview>,
    /// Stable key owning exactly one canonical record.
    pub dedup_key: String,
    /// Delivery channels eligible for this record.
    pub delivery_channels: Vec<DeliveryChannel>,
    /// Count of events coalesced under the dedup key.
    pub occurrences: u64,
    /// Latest canonical delivery observation.
    pub delivery: DeliveryState,
    /// Toast-suppression acknowledgement (never a resolution).
    pub acknowledgement: Option<Acknowledgement>,
    /// Evidence-backed terminal disposition.
    pub resolution_ref: Option<ResolutionRef>,
    /// Fence the record is admitted under.
    pub state_fence: StateFence,
    /// Monotonic owner revision, also used for projection/readback cursors.
    pub revision: u64,
}

impl NotificationRecord {
    /// Validates the complete canonical record shape.
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        NotificationRecordInput {
            notification_id: self.notification_id.clone(),
            severity: self.severity,
            subject: self.subject.clone(),
            summary: self.summary.clone(),
            evidence_handles: self.evidence_handles.clone(),
            affected_scope: self.affected_scope.clone(),
            owner: self.owner.clone(),
            required_action: self.required_action.clone(),
            deadline_or_review: self.deadline_or_review.clone(),
            dedup_key: self.dedup_key.clone(),
            delivery_channels: self.delivery_channels.clone(),
            state_fence: self.state_fence.clone(),
        }
        .validate()?;
        if self.occurrences == 0 || self.revision == 0 {
            return Err(NotificationContractError::InvalidField {
                field: "notification.record_revision",
                reason: "occurrences and revision must be non-zero",
            });
        }
        self.delivery.validate()?;
        if let Some(acknowledgement) = &self.acknowledgement {
            text(&acknowledgement.principal, "notification.acknowledgement")?;
        }
        if let Some(resolution) = &self.resolution_ref {
            text(&resolution.receipt_id, "notification.resolution")?;
            text(&resolution.authority_id, "notification.resolution")?;
            text(&resolution.authority_owner, "notification.resolution")?;
            text(&resolution.disposition, "notification.resolution")?;
            validate_text_list(
                &resolution.evidence_handles,
                "notification.resolution.evidence_handle",
            )?;
        }
        Ok(())
    }

    /// Returns true while the record still needs operator attention.
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        self.resolution_ref.is_none()
    }

    /// Returns true when the latest delivery attempt failed or is uncertain.
    #[must_use]
    pub const fn is_failed_delivery(&self) -> bool {
        self.delivery.is_failed()
    }
}

/// Verified delivery outcome for one channel attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryAttempt {
    /// Verified latest delivery observation for the attempt.
    pub state: DeliveryState,
}

/// Closed notification-state mutation legs.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "leg", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationStateMutation {
    /// Create or coalesce exactly one record before any delivery attempt.
    Upsert {
        /// Caller canonical fields.
        record: NotificationRecordInput,
        /// Admission/provenance receipt for the upsert.
        source_receipt: ReceiptEnvelope,
    },
    /// Record the verified latest delivery state without resolving the item.
    Delivery {
        /// Canonical notification identity.
        notification_id: String,
        /// Channel the attempt used.
        channel: DeliveryChannel,
        /// Verified delivery outcome.
        attempt: DeliveryAttempt,
    },
    /// Suppress repeated toast selection; never resolves the record.
    Acknowledge {
        /// Canonical notification identity.
        notification_id: String,
        /// Acknowledging principal.
        principal: String,
    },
    /// Resolve only with a protected, evidence-bound authority receipt.
    Resolve {
        /// Canonical notification identity.
        notification_id: String,
        /// Human disposition recorded by the owner.
        disposition: String,
        /// Protected receipt/evidence authorization.
        authorization: ResolutionAuthorization,
    },
}

/// Authenticated notification-state write request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationStateRequest {
    /// Exact operation identity (idempotency + canonical request hash).
    pub operation: OperationIdentity,
    /// Caller request metadata bound by the Kernel front door.
    pub context: RequestMetadata,
    /// Fence the mutation is admitted under.
    pub state_fence: StateFence,
    /// Closed mutation leg.
    pub mutation: NotificationStateMutation,
}

impl NotificationStateRequest {
    /// Validates identity, fence binding, and the mutation leg shape.
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        self.operation
            .validate()
            .map_err(|_| NotificationContractError::InvalidField {
                field: "notification.operation",
                reason: "operation identity is invalid",
            })?;
        if self.context.state_fence != self.state_fence {
            return Err(NotificationContractError::InvalidField {
                field: "notification.state_fence",
                reason: "request fence must match context fence",
            });
        }
        match &self.mutation {
            NotificationStateMutation::Upsert {
                record,
                source_receipt,
            } => {
                record.validate()?;
                if record.state_fence != self.state_fence {
                    return Err(NotificationContractError::InvalidField {
                        field: "notification.state_fence",
                        reason: "record fence must match request fence",
                    });
                }
                source_receipt
                    .validate()
                    .map_err(|_| NotificationContractError::InvalidField {
                        field: "notification.source_receipt",
                        reason: "source receipt is invalid",
                    })?;
            }
            NotificationStateMutation::Delivery {
                notification_id,
                attempt,
                ..
            } => {
                text(notification_id, "notification.notification_id")?;
                attempt.state.validate()?;
            }
            NotificationStateMutation::Acknowledge {
                notification_id,
                principal,
            } => {
                text(notification_id, "notification.notification_id")?;
                text(principal, "notification.principal")?;
            }
            NotificationStateMutation::Resolve {
                notification_id,
                disposition,
                authorization,
            } => {
                text(notification_id, "notification.notification_id")?;
                text(disposition, "notification.disposition")?;
                if authorization.evidence_handles.is_empty() {
                    return Err(NotificationContractError::InvalidField {
                        field: "notification.evidence_handles",
                        reason: "resolution requires evidence",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Notification-state write response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationStateResponse {
    /// Current canonical record after the mutation.
    pub record: NotificationRecord,
    /// Exact store response receipt (never fabricated by the caller).
    pub receipt: ReceiptEnvelope,
    /// True when the response replays an already-admitted operation identity.
    pub replayed: bool,
}

/// Same-fence canonical read request for the ControlBoard projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationStateReadRequest {
    /// Caller request metadata bound by the Kernel front door.
    pub context: RequestMetadata,
    /// Fence the projection is admitted under.
    pub state_fence: StateFence,
    /// Optional record-scope filter (never a quiet-hours filter).
    pub scope: Option<String>,
    /// Whether resolved rows are included.
    pub include_resolved: bool,
    /// Page-size bound (1..=`MAX_NOTIFICATION_PAGE_LIMIT`).
    pub page_limit: u16,
    /// Opaque dedup-key cursor for paging.
    pub cursor: Option<String>,
}

impl NotificationStateReadRequest {
    /// Validates the read projection request.
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        if self.context.state_fence != self.state_fence {
            return Err(NotificationContractError::InvalidField {
                field: "notification.state_fence",
                reason: "request fence must match context fence",
            });
        }
        if let Some(scope) = &self.scope {
            text(scope, "notification.scope")?;
        }
        if self.page_limit == 0 || self.page_limit > MAX_NOTIFICATION_PAGE_LIMIT {
            return Err(NotificationContractError::InvalidField {
                field: "notification.page_limit",
                reason: "page limit is out of range",
            });
        }
        if let Some(cursor) = &self.cursor {
            text(cursor, "notification.cursor")?;
        }
        Ok(())
    }
}

/// Canonical inbox metrics preserved by the read projection.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMetrics {
    /// Unresolved records in the projected set.
    pub unresolved_total: u64,
    /// Unresolved critical records.
    pub critical_unresolved: u64,
    /// Unresolved action-required records.
    pub action_required_unresolved: u64,
    /// Unresolved records with failed/uncertain delivery.
    pub failed_delivery_unresolved: u64,
    /// Unresolved acknowledged records (still visible).
    pub acknowledged_unresolved: u64,
    /// Resolved records in the projected set.
    pub resolved_total: u64,
}

impl NotificationMetrics {
    /// Folds one projected record into the metrics.
    pub fn observe(&mut self, record: &NotificationRecord) {
        if record.is_unresolved() {
            self.unresolved_total = self.unresolved_total.saturating_add(1);
            match record.severity {
                NotificationSeverity::Critical => {
                    self.critical_unresolved = self.critical_unresolved.saturating_add(1);
                }
                NotificationSeverity::ActionRequired => {
                    self.action_required_unresolved =
                        self.action_required_unresolved.saturating_add(1);
                }
                _ => {}
            }
            if record.is_failed_delivery() {
                self.failed_delivery_unresolved =
                    self.failed_delivery_unresolved.saturating_add(1);
            }
            if record.acknowledgement.is_some() {
                self.acknowledged_unresolved = self.acknowledged_unresolved.saturating_add(1);
            }
        } else {
            self.resolved_total = self.resolved_total.saturating_add(1);
        }
    }
}

/// Same-fence canonical read response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationStateReadResponse {
    /// Projected records in deterministic dedup-key order.
    pub records: Vec<NotificationRecord>,
    /// Inbox metrics over the projected set.
    pub metrics: NotificationMetrics,
    /// Fence the projection was admitted under.
    pub state_fence: StateFence,
    /// Owner revision the projection was read at.
    pub revision: u64,
}

/// Pure canonical record-state transition model used by the backend.
///
/// It has no persistence side effect. The canonical backend drives these
/// transitions within its existing fenced transaction and outbox owner.
#[derive(Clone, Debug, Default)]
pub struct NotificationRecordStore {
    records: BTreeMap<String, NotificationRecord>,
    sequence: u64,
}

impl NotificationRecordStore {
    /// Creates an empty transition model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            sequence: 0,
        }
    }

    /// Returns the number of canonical records in this model.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true when the model holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the current owner sequence (projection/readback cursor).
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Reads one record by its canonical deduplication key.
    #[must_use]
    pub fn get(&self, dedup_key: &str) -> Option<&NotificationRecord> {
        self.records.get(dedup_key)
    }

    /// Resolves the dedup index key for a canonical notification identity.
    ///
    /// Notification identities are unique across keys (enforced at upsert),
    /// so lifecycle legs addressing `notification_id` resolve deterministically.
    #[must_use]
    pub fn key_for_notification_id(&self, notification_id: &str) -> Option<String> {
        self.records
            .values()
            .find(|record| record.notification_id == notification_id)
            .map(|record| record.dedup_key.clone())
    }

    /// Iterates records in deterministic deduplication-key order.
    pub fn iter(&self) -> impl Iterator<Item = &NotificationRecord> {
        self.records.values()
    }

    /// Creates or updates exactly one record before any delivery attempt.
    pub fn upsert(
        &mut self,
        draft: NotificationRecordInput,
    ) -> Result<&NotificationRecord, StoreError> {
        draft
            .validate()
            .map_err(NotificationContractError::into_store_error)?;
        if let Some(existing) = self.records.get(&draft.dedup_key) {
            if existing.resolution_ref.is_some() {
                return Err(StoreError::InvalidField {
                    field: "notification.resolution",
                    reason: "record is already resolved",
                });
            }
            if !same_payload(existing, &draft) {
                return Err(StoreError::IdentityConflict);
            }
        }
        if self
            .records
            .values()
            .any(|record| record.notification_id == draft.notification_id
                && record.dedup_key != draft.dedup_key)
        {
            return Err(StoreError::IdentityConflict);
        }
        self.sequence = self.sequence.saturating_add(1);
        let revision = self.sequence;
        let existing = self.records.get(&draft.dedup_key);
        let occurrences = existing.map_or(1, |record| record.occurrences.saturating_add(1));
        let acknowledgement = existing.and_then(|record| record.acknowledgement.clone());
        let record = NotificationRecord {
            notification_id: draft.notification_id,
            severity: draft.severity,
            subject: draft.subject,
            summary: draft.summary,
            evidence_handles: draft.evidence_handles,
            affected_scope: draft.affected_scope,
            owner: draft.owner,
            required_action: draft.required_action,
            deadline_or_review: draft.deadline_or_review,
            dedup_key: draft.dedup_key.clone(),
            delivery_channels: draft.delivery_channels,
            occurrences,
            delivery: DeliveryState::Pending,
            acknowledgement,
            resolution_ref: None,
            state_fence: draft.state_fence,
            revision,
        };
        record
            .validate()
            .map_err(NotificationContractError::into_store_error)?;
        let key = record.dedup_key.clone();
        self.records.insert(key.clone(), record);
        self.records.get(&key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })
    }

    /// Records the verified latest delivery state without resolving the item.
    pub fn record_delivery(
        &mut self,
        dedup_key: &str,
        delivery: DeliveryState,
    ) -> Result<&NotificationRecord, StoreError> {
        validate_dedup_key(dedup_key).map_err(NotificationContractError::into_store_error)?;
        delivery
            .validate()
            .map_err(NotificationContractError::into_store_error)?;
        let existing = self.records.get(dedup_key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })?;
        if existing.resolution_ref.is_some() {
            return Err(StoreError::InvalidField {
                field: "notification.resolution",
                reason: "record is already resolved",
            });
        }
        self.sequence = self.sequence.saturating_add(1);
        let revision = self.sequence;
        let mut updated = existing.clone();
        updated.delivery = delivery;
        updated.revision = revision;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records.get(dedup_key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })
    }

    /// Acknowledges one record; acknowledgement never resolves it.
    pub fn acknowledge(
        &mut self,
        dedup_key: &str,
        principal: &str,
    ) -> Result<&NotificationRecord, StoreError> {
        validate_dedup_key(dedup_key).map_err(NotificationContractError::into_store_error)?;
        text(principal, "notification.principal")
            .map_err(NotificationContractError::into_store_error)?;
        let existing = self.records.get(dedup_key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })?;
        if existing.resolution_ref.is_some() {
            return Err(StoreError::InvalidField {
                field: "notification.resolution",
                reason: "record is already resolved",
            });
        }
        self.sequence = self.sequence.saturating_add(1);
        let revision = self.sequence;
        let mut updated = existing.clone();
        updated.acknowledgement = Some(Acknowledgement {
            principal: principal.to_owned(),
            sequence: revision,
        });
        updated.revision = revision;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records.get(dedup_key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })
    }

    /// Resolves only with a protected, evidence-bound authority receipt.
    pub fn resolve(
        &mut self,
        dedup_key: &str,
        disposition: &str,
        authorization: &ResolutionAuthorization,
    ) -> Result<&NotificationRecord, StoreError> {
        validate_dedup_key(dedup_key).map_err(NotificationContractError::into_store_error)?;
        let existing = self.records.get(dedup_key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })?;
        if existing.resolution_ref.is_some() {
            return Err(StoreError::InvalidField {
                field: "notification.resolution",
                reason: "record is already resolved",
            });
        }
        validate_resolution(existing, disposition, authorization)?;
        self.sequence = self.sequence.saturating_add(1);
        let revision = self.sequence;
        let mut updated = existing.clone();
        updated.resolution_ref = Some(ResolutionRef {
            receipt_id: authorization
                .receipt
                .identity
                .receipt_id
                .to_string(),
            authority_id: authorization
                .receipt
                .core
                .authority
                .authority_id
                .to_string(),
            authority_owner: authorization
                .receipt
                .core
                .authority
                .authority_owner
                .clone(),
            evidence_handles: authorization.evidence_handles.clone(),
            disposition: disposition.to_owned(),
        });
        updated.revision = revision;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records.get(dedup_key).ok_or(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        })
    }
}

/// Validates receipt-bound resolution: the seven handoff checks.
///
/// 1. `receipt.validate()` succeeds; 2. receipt/work-scope/state-fence match
/// the request and target record; 3. receipt authority owner/epoch is live
/// (epoch agreement is enforced by the front door against the live epoch; the
/// owner/record binding is enforced here); 4. `allowed_effect` is at least
/// `ReversibleMutation`; 5. proof ceiling is sufficient for the disposition;
/// 6. every supplied evidence handle is bound by the receipt AND present on
/// the record; 7. the disposition is non-blank and the receipt is not
/// partial/unknown/cancelled. The recorded authorizer derives from the
/// receipt; caller booleans and free-standing authorizer text are never read.
pub fn validate_resolution(
    record: &NotificationRecord,
    disposition: &str,
    authorization: &ResolutionAuthorization,
) -> Result<(), StoreError> {
    text(disposition, "notification.disposition").map_err(contract_store_error)?;
    if authorization.evidence_handles.is_empty() {
        return Err(StoreError::InvalidField {
            field: "notification.evidence_handles",
            reason: "resolution requires evidence",
        });
    }
    validate_text_list(&authorization.evidence_handles, "notification.evidence_handle")
        .map_err(contract_store_error)?;
    authorization
        .receipt
        .validate()
        .map_err(|_| StoreError::InvalidReceipt)?;
    let core = &authorization.receipt.core;
    if !matches!(core.kind, ReceiptKind::Operation | ReceiptKind::Verification) {
        return Err(StoreError::InvalidReceipt);
    }
    if !matches!(
        core.authority.allowed_effect,
        EffectClass::ReversibleMutation | EffectClass::ExternalEffect
    ) {
        return Err(StoreError::EffectCeilingExceeded);
    }
    if !ProofCeiling::ScopedVerification.is_at_most(core.authority.proof_ceiling) {
        return Err(StoreError::EffectCeilingExceeded);
    }
    let valid_disposition = matches!(
        core.disposition,
        ReceiptDisposition::Success { proof }
            if ProofCeiling::ScopedVerification.is_at_most(proof)
    );
    if !valid_disposition || !evidence_is_bound(authorization) {
        return Err(StoreError::InvalidField {
            field: "notification.evidence_handles",
            reason: "resolution evidence is not bound by the authority receipt",
        });
    }
    if !fences_match_exact(&record.state_fence, &core.authority.state_fence) {
        return Err(StoreError::FenceMismatch);
    }
    if core.request.metadata.state_fence != record.state_fence
        || core.request.state_fence != record.state_fence
        || core.work_scope.state_fence != record.state_fence
    {
        return Err(StoreError::FenceMismatch);
    }
    if core.authority.authority_owner != record.owner {
        return Err(StoreError::EffectCeilingExceeded);
    }
    if authorization
        .evidence_handles
        .iter()
        .any(|handle| !record.evidence_handles.contains(handle))
    {
        return Err(StoreError::InvalidField {
            field: "notification.evidence_handles",
            reason: "resolution evidence is not present on the record",
        });
    }
    Ok(())
}

/// Builds the closed `ApplyNotificationState` mutation request.
#[must_use]
pub fn notification_mutation_request(params: BTreeMap<String, Value>) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::ApplyNotificationState,
        parameters: params,
    }
}

/// Builds the closed `GetNotificationState` read request.
pub fn notification_read_request(
    scope: Option<String>,
    dedup_key: Option<String>,
    notification_id: Option<String>,
    include_resolved: bool,
    page_limit: u16,
    cursor: Option<String>,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut parameters = BTreeMap::new();
    if let Some(scope) = scope {
        parameters.insert(NOTIFY_PARAM_SCOPE.to_owned(), Value::String(scope));
    }
    if let Some(dedup_key) = dedup_key {
        parameters.insert(
            NOTIFY_PARAM_DEDUP_KEY.to_owned(),
            Value::String(dedup_key),
        );
    }
    if let Some(notification_id) = notification_id {
        parameters.insert(
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String(notification_id),
        );
    }
    parameters.insert(
        NOTIFY_PARAM_INCLUDE_RESOLVED.to_owned(),
        Value::String(include_resolved.to_string()),
    );
    parameters.insert(
        NOTIFY_PARAM_PAGE_LIMIT.to_owned(),
        Value::String(page_limit.to_string()),
    );
    if let Some(cursor) = cursor {
        parameters.insert(NOTIFY_PARAM_CURSOR.to_owned(), Value::String(cursor));
    }
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetNotificationState,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Validates closed mutation parameters: exact leg discriminator plus
/// conditional leg presence (the declaration table enforces membership and
/// per-value shape; this enforces leg completeness).
pub fn validate_notification_mutation_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let leg = parameters
        .get(NOTIFY_PARAM_MUTATION)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "notification.mutation",
            reason: "mutation leg discriminator is required",
        })?;
    let require_text = |name: &'static str| -> Result<(), StoreError> {
        match parameters.get(name).and_then(Value::as_str) {
            Some(value)
                if !value.trim().is_empty() && !value.chars().any(char::is_control) =>
            {
                Ok(())
            }
            _ => Err(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be non-blank text",
            }),
        }
    };
    let require_object = |name: &'static str| -> Result<(), StoreError> {
        match parameters.get(name) {
            Some(Value::Object(_)) => Ok(()),
            _ => Err(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be a JSON object",
            }),
        }
    };
    require_text(NOTIFY_PARAM_MUTATION)?;
    match leg {
        NOTIFY_MUTATION_UPSERT => {
            require_text(NOTIFY_PARAM_DEDUP_KEY)?;
            require_object(NOTIFY_PARAM_RECORD_JSON)?;
            require_object(NOTIFY_PARAM_SOURCE_RECEIPT_JSON)?;
        }
        NOTIFY_MUTATION_DELIVERY => {
            require_text(NOTIFY_PARAM_NOTIFICATION_ID)?;
            require_text(NOTIFY_PARAM_CHANNEL)?;
            DeliveryChannel::parse_wire(
                parameters
                    .get(NOTIFY_PARAM_CHANNEL)
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
            .map_err(NotificationContractError::into_store_error)?;
            require_object(NOTIFY_PARAM_DELIVERY_JSON)?;
        }
        NOTIFY_MUTATION_ACKNOWLEDGE => {
            require_text(NOTIFY_PARAM_NOTIFICATION_ID)?;
            require_text(NOTIFY_PARAM_PRINCIPAL)?;
        }
        NOTIFY_MUTATION_RESOLVE => {
            require_text(NOTIFY_PARAM_NOTIFICATION_ID)?;
            require_text(NOTIFY_PARAM_DISPOSITION)?;
            require_object(NOTIFY_PARAM_AUTHORIZATION_JSON)?;
        }
        _ => return Err(StoreError::UnknownOperation),
    }
    Ok(())
}

/// Decodes one validated mutation parameter map into its typed leg parts.
pub fn decode_notification_mutation(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedNotificationMutation, StoreError> {
    validate_notification_mutation_params(parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be present",
            })
    };
    let object_of = |name: &'static str| -> Result<Value, StoreError> {
        parameters.get(name).cloned().ok_or(StoreError::InvalidField {
            field: name,
            reason: "leg parameter must be present",
        })
    };
    let leg = text_of(NOTIFY_PARAM_MUTATION)?;
    match leg.as_str() {
        NOTIFY_MUTATION_UPSERT => {
            let record: NotificationRecordInput =
                serde_json::from_value(object_of(NOTIFY_PARAM_RECORD_JSON)?).map_err(|error| {
                    StoreError::Serialization(error.to_string())
                })?;
            let source_receipt: ReceiptEnvelope = serde_json::from_value(object_of(
                NOTIFY_PARAM_SOURCE_RECEIPT_JSON,
            )?)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
            Ok(DecodedNotificationMutation::Upsert {
                dedup_key: text_of(NOTIFY_PARAM_DEDUP_KEY)?,
                record,
                source_receipt,
            })
        }
        NOTIFY_MUTATION_DELIVERY => {
            let notification_id = text_of(NOTIFY_PARAM_NOTIFICATION_ID)?;
            let channel = DeliveryChannel::parse_wire(&text_of(NOTIFY_PARAM_CHANNEL)?)
                .map_err(NotificationContractError::into_store_error)?;
            let state: DeliveryState = serde_json::from_value(object_of(
                NOTIFY_PARAM_DELIVERY_JSON,
            )?)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
            Ok(DecodedNotificationMutation::Delivery {
                notification_id,
                channel,
                attempt: DeliveryAttempt { state },
            })
        }
        NOTIFY_MUTATION_ACKNOWLEDGE => Ok(DecodedNotificationMutation::Acknowledge {
            notification_id: text_of(NOTIFY_PARAM_NOTIFICATION_ID)?,
            principal: text_of(NOTIFY_PARAM_PRINCIPAL)?,
        }),
        NOTIFY_MUTATION_RESOLVE => {
            let disposition = text_of(NOTIFY_PARAM_DISPOSITION)?;
            let authorization: ResolutionAuthorization = serde_json::from_value(object_of(
                NOTIFY_PARAM_AUTHORIZATION_JSON,
            )?)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
            Ok(DecodedNotificationMutation::Resolve {
                notification_id: text_of(NOTIFY_PARAM_NOTIFICATION_ID)?,
                disposition,
                authorization,
            })
        }
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Typed legs decoded from a validated mutation parameter map.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedNotificationMutation {
    /// Create or coalesce one record.
    Upsert {
        /// Deduplication index key.
        dedup_key: String,
        /// Caller canonical fields.
        record: NotificationRecordInput,
        /// Admission/provenance receipt.
        source_receipt: ReceiptEnvelope,
    },
    /// Record verified delivery state.
    Delivery {
        /// Canonical notification identity (backend resolves the dedup key).
        notification_id: String,
        /// Channel the attempt used.
        channel: DeliveryChannel,
        /// Verified delivery outcome.
        attempt: DeliveryAttempt,
    },
    /// Acknowledge without resolving.
    Acknowledge {
        /// Canonical notification identity (backend resolves the dedup key).
        notification_id: String,
        /// Acknowledging principal.
        principal: String,
    },
    /// Resolve with receipt-bound authorization.
    Resolve {
        /// Canonical notification identity (backend resolves the dedup key).
        notification_id: String,
        /// Human disposition.
        disposition: String,
        /// Protected receipt/evidence authorization.
        authorization: ResolutionAuthorization,
    },
}

/// Encodes the canonical read payload: records plus metrics, fence, revision.
pub fn encode_notification_page(
    records: &[NotificationRecord],
    metrics: &NotificationMetrics,
    state_fence: &StateFence,
    revision: u64,
) -> Result<Value, StoreError> {
    let record_values = records
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    serde_json::to_value(serde_json::json!({
        "records": record_values,
        "metrics": metrics,
        "state_fence": state_fence,
        "revision": revision,
    }))
    .map_err(|error| StoreError::Serialization(error.to_string()))
}

/// Decodes a canonical read payload into the full read response shape.
pub fn decode_notification_page(payload: &Value) -> Result<NotificationStateReadResponse, StoreError> {
    serde_json::from_value(payload.clone())
        .map_err(|error| StoreError::Serialization(error.to_string()))
}

/// Decodes records from a canonical read payload.
pub fn decode_notification_page_records(payload: &Value) -> Result<Vec<NotificationRecord>, StoreError> {
    let records = payload
        .get("records")
        .ok_or(StoreError::InvalidField {
            field: "notification.records",
            reason: "read payload must carry records",
        })?
        .as_array()
        .ok_or(StoreError::InvalidField {
            field: "notification.records",
            reason: "records must be an array",
        })?;
    records
        .iter()
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))
        })
        .collect()
}

/// Projects the same-fence read set: scope filter, exact identity selectors,
/// resolved preservation, unresolved/failed/critical retention, deterministic
/// paging.
pub fn project_notification_read(
    records: impl Iterator<Item = NotificationRecord>,
    scope: Option<&str>,
    dedup_key: Option<&str>,
    notification_id: Option<&str>,
    include_resolved: bool,
    page_limit: u16,
    cursor: Option<&str>,
) -> (Vec<NotificationRecord>, NotificationMetrics) {
    let limit = usize::from(page_limit.max(1));
    let mut metrics = NotificationMetrics::default();
    let mut selected = Vec::new();
    let mut past_cursor = cursor.unwrap_or_default().is_empty();
    for record in records {
        if let Some(scope) = scope
            && record.affected_scope != scope
        {
            continue;
        }
        if let Some(dedup_key) = dedup_key
            && record.dedup_key != dedup_key
        {
            continue;
        }
        if let Some(notification_id) = notification_id
            && record.notification_id != notification_id
        {
            continue;
        }
        metrics.observe(&record);
        if !include_resolved && !record.is_unresolved() {
            continue;
        }
        if !past_cursor {
            if record.dedup_key.as_str() == cursor.unwrap_or_default() {
                past_cursor = true;
            }
            continue;
        }
        if selected.len() >= limit {
            break;
        }
        selected.push(record);
    }
    (selected, metrics)
}

fn same_payload(record: &NotificationRecord, draft: &NotificationRecordInput) -> bool {
    record.notification_id == draft.notification_id
        && record.severity == draft.severity
        && record.subject == draft.subject
        && record.summary == draft.summary
        && record.evidence_handles == draft.evidence_handles
        && record.affected_scope == draft.affected_scope
        && record.owner == draft.owner
        && record.required_action == draft.required_action
        && record.deadline_or_review == draft.deadline_or_review
        && record.delivery_channels == draft.delivery_channels
        && record.state_fence == draft.state_fence
}

fn evidence_is_bound(authorization: &ResolutionAuthorization) -> bool {
    authorization.evidence_handles.iter().all(|handle| {
        authorization.receipt.core.artifacts.iter().any(|artifact| {
            artifact.sha256 == *handle || artifact.artifact_id.as_str() == handle
        })
    })
}

fn text(value: &str, field: &'static str) -> Result<(), NotificationContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NotificationContractError::InvalidField { field, reason: "must be non-blank text" });
    }
    Ok(())
}

fn contract_store_error(error: NotificationContractError) -> StoreError {
    error.into_store_error()
}

fn validate_dedup_key(value: &str) -> Result<(), NotificationContractError> {
    text(value, "notification.dedup_key")?;
    if value.len() > MAX_DEDUP_KEY_BYTES {
        return Err(NotificationContractError::InvalidField {
            field: "notification.dedup_key",
            reason: "dedup key exceeds maximum length",
        });
    }
    Ok(())
}

fn validate_text_list(
    values: &[String],
    field: &'static str,
) -> Result<(), NotificationContractError> {
    if values.is_empty() {
        return Err(NotificationContractError::InvalidField {
            field,
            reason: "at least one entry is required",
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(NotificationContractError::InvalidField {
                field,
                reason: "entries must be unique",
            });
        }
    }
    Ok(())
}
