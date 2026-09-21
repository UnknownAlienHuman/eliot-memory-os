//! Canonical persistent notification state (issue #1780, I11.5/I11.7).
//!
//! This module owns the typed notification record and its fail-closed state
//! transitions. Durable persistence remains a Kernel/store responsibility: the
//! [`NotificationStore`] is a deterministic decision model used by that owner,
//! never a second surface database. Repeated events keyed by `dedup_key` update
//! one record, delivery never resolves it, acknowledgement only suppresses
//! repeated toast selection, and resolution requires a validated
//! evidence-backed authority receipt.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, fences_match_exact};
use eliot_platform::PlatformHandle;
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptDisposition, ReceiptEnvelope, ReceiptKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Latest canonical delivery observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DeliveryState {
    /// Canonical record exists, but no delivery outcome is known yet.
    Pending,
    /// Latest attempt was delivered without resolving the record.
    Delivered,
    /// Latest attempt failed and remains visible to the operator.
    Failed { reason: String },
    /// Some delivery evidence is known while named gaps remain.
    Partial { reason: String },
    /// Delivery crossed an uncertain boundary and needs reconciliation.
    Unknown { reason: String },
}

impl DeliveryState {
    /// Validates a delivery observation before the canonical owner admits it.
    pub fn validate(&self) -> Result<(), NotificationError> {
        match self {
            Self::Pending | Self::Delivered => Ok(()),
            Self::Failed { reason } | Self::Partial { reason } | Self::Unknown { reason } => {
                text(reason, "delivery.reason")
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
    fn validate(&self) -> Result<(), NotificationError> {
        if self.deadline_unix_ms.is_none() && self.review_ref.is_none() {
            return Err(NotificationError::InvalidField("deadline_or_review"));
        }
        if self.deadline_unix_ms.is_some_and(|value| value < 0) {
            return Err(NotificationError::InvalidField("deadline_unix_ms"));
        }
        if let Some(review_ref) = &self.review_ref {
            text(review_ref, "review_ref")?;
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
    /// Kernel sequence at acknowledgement time.
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

/// Compatibility name for consumers that used the pre-I11.5 resolution type.
pub type Resolution = ResolutionRef;

/// Protected authorization presented to the Kernel resolution transition.
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

/// Complete canonical I11.5 input before lifecycle observations are added.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDraft {
    pub notification_id: PlatformHandle,
    pub severity: NotificationSeverity,
    pub subject: String,
    pub summary: String,
    pub evidence_handles: Vec<String>,
    pub affected_scope: String,
    pub owner: String,
    pub required_action: String,
    pub deadline_or_review: Option<DeadlineOrReview>,
    pub dedup_key: String,
    pub delivery_channels: Vec<DeliveryChannel>,
    pub state_fence: StateFence,
}

impl NotificationDraft {
    /// Validates all caller-provided canonical fields before owner admission.
    pub fn validate(&self) -> Result<(), NotificationError> {
        text(self.notification_id.as_str(), "notification_id")?;
        validate_dedup_key(&self.dedup_key)?;
        text(&self.subject, "subject")?;
        text(&self.summary, "summary")?;
        validate_text_list(&self.evidence_handles, "evidence_handle")?;
        text(&self.affected_scope, "affected_scope")?;
        text(&self.owner, "owner")?;
        text(&self.required_action, "required_action")?;
        if let Some(deadline_or_review) = &self.deadline_or_review {
            deadline_or_review.validate()?;
        }
        if self.delivery_channels.is_empty() {
            return Err(NotificationError::InvalidField("delivery_channels"));
        }
        let mut channels = BTreeSet::new();
        if self
            .delivery_channels
            .iter()
            .any(|channel| !channels.insert(channel))
        {
            return Err(NotificationError::InvalidField("delivery_channels"));
        }
        self.state_fence
            .validate()
            .map_err(|_| NotificationError::InvalidField("state_fence"))
    }
}

/// Canonical persistent notification record owned by the Kernel/store path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub notification_id: PlatformHandle,
    pub severity: NotificationSeverity,
    pub subject: String,
    pub summary: String,
    pub evidence_handles: Vec<String>,
    pub affected_scope: String,
    pub owner: String,
    pub required_action: String,
    pub deadline_or_review: Option<DeadlineOrReview>,
    /// Stable key owning exactly one canonical record.
    pub dedup_key: String,
    pub delivery_channels: Vec<DeliveryChannel>,
    /// Count of events coalesced under the dedup key.
    pub occurrences: u64,
    pub delivery: DeliveryState,
    pub acknowledgement: Option<Acknowledgement>,
    pub resolution_ref: Option<ResolutionRef>,
    pub state_fence: StateFence,
    /// Monotonic owner revision, also used for projection/readback cursors.
    pub revision: u64,
}

impl Notification {
    /// Validates the complete canonical record shape.
    pub fn validate(&self) -> Result<(), NotificationError> {
        NotificationDraft {
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
            return Err(NotificationError::InvalidField("record_revision"));
        }
        self.delivery.validate()
    }

    /// Returns true while the record still needs operator attention.
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        self.resolution_ref.is_none()
    }

    /// Returns whether every canonical draft field matches this record.
    ///
    /// The owner uses this before coalescing a repeated deduplication event so
    /// a changed payload cannot silently overwrite the existing identity.
    #[must_use]
    pub fn matches_draft(&self, draft: &NotificationDraft) -> bool {
        self.notification_id == draft.notification_id
            && self.severity == draft.severity
            && self.subject == draft.subject
            && self.summary == draft.summary
            && self.evidence_handles == draft.evidence_handles
            && self.affected_scope == draft.affected_scope
            && self.owner == draft.owner
            && self.required_action == draft.required_action
            && self.deadline_or_review == draft.deadline_or_review
            && self.dedup_key == draft.dedup_key
            && self.delivery_channels == draft.delivery_channels
            && self.state_fence == draft.state_fence
    }

    /// Returns true when the latest delivery attempt failed or is uncertain.
    #[must_use]
    pub const fn is_failed_delivery(&self) -> bool {
        self.delivery.is_failed()
    }

    /// Pure popup predicate. Quiet hours never affect canonical creation or
    /// ControlBoard visibility.
    #[must_use]
    pub fn should_popup(&self, quiet_hours_active: bool) -> bool {
        if self.resolution_ref.is_some() || self.acknowledgement.is_some() {
            return false;
        }
        if quiet_hours_active && self.severity != NotificationSeverity::Critical {
            return false;
        }
        true
    }
}

/// Fail-closed errors for notification lifecycle transitions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NotificationError {
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("unknown notification")]
    UnknownNotification,
    #[error("notification identity conflicts with the existing dedup record")]
    IdentityConflict,
    #[error("resolution requires evidence")]
    ResolutionRequiresEvidence,
    #[error("resolution requires a protected authority receipt")]
    ResolutionRequiresAuthorization,
    #[error("resolution receipt is invalid or misbound")]
    InvalidResolutionReceipt,
    #[error("resolution authority cannot perform a reversible mutation")]
    ResolutionAuthorityInsufficient,
    #[error("resolution evidence is not bound by the authority receipt")]
    ResolutionEvidenceUnbound,
    #[error("resolution fence does not match the canonical record")]
    ResolutionFenceMismatch,
    #[error("record is already resolved")]
    AlreadyResolved,
}

fn text(value: &str, field: &'static str) -> Result<(), NotificationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NotificationError::InvalidField(field));
    }
    Ok(())
}

fn validate_dedup_key(value: &str) -> Result<(), NotificationError> {
    text(value, "dedup_key")?;
    if value.len() > 256 {
        return Err(NotificationError::InvalidField("dedup_key"));
    }
    Ok(())
}

fn validate_text_list(values: &[String], field: &'static str) -> Result<(), NotificationError> {
    if values.is_empty() {
        return Err(NotificationError::InvalidField(field));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(NotificationError::InvalidField(field));
        }
    }
    Ok(())
}

fn evidence_is_bound(auth: &ResolutionAuthorization) -> bool {
    auth.evidence_handles.iter().all(|handle| {
        auth.receipt.core.artifacts.iter().any(|artifact| {
            artifact.role == ReceiptKind::Artifact
                && (artifact.sha256 == *handle || artifact.artifact_id.as_str() == handle)
        })
    })
}

fn validate_resolution(
    record: &Notification,
    disposition: &str,
    authorization: &ResolutionAuthorization,
) -> Result<(), NotificationError> {
    text(disposition, "disposition")?;
    if authorization.evidence_handles.is_empty() {
        return Err(NotificationError::ResolutionRequiresEvidence);
    }
    validate_text_list(&authorization.evidence_handles, "evidence_handle")
        .map_err(|_| NotificationError::ResolutionRequiresEvidence)?;
    authorization
        .receipt
        .validate()
        .map_err(|_| NotificationError::InvalidResolutionReceipt)?;
    let core = &authorization.receipt.core;
    if !matches!(
        core.authority.allowed_effect,
        EffectClass::ReversibleMutation | EffectClass::ExternalEffect
    ) {
        return Err(NotificationError::ResolutionAuthorityInsufficient);
    }
    if core.authority.proof_ceiling < ProofCeiling::ScopedVerification {
        return Err(NotificationError::ResolutionAuthorityInsufficient);
    }
    let valid_disposition = matches!(
        core.disposition,
        ReceiptDisposition::Success { proof } if proof >= ProofCeiling::ScopedVerification
    );
    if !valid_disposition || !evidence_is_bound(authorization) {
        return Err(NotificationError::ResolutionEvidenceUnbound);
    }
    if !fences_match_exact(&record.state_fence, &core.authority.state_fence) {
        return Err(NotificationError::ResolutionFenceMismatch);
    }
    if core.causal.state_fence != record.state_fence
        || core.operation.state_fence != record.state_fence
        || core.request.metadata.state_fence != record.state_fence
        || core.request.state_fence != record.state_fence
        || core.work_scope.state_fence != record.state_fence
    {
        return Err(NotificationError::ResolutionFenceMismatch);
    }
    if core.work_scope.scope_id.as_str() != record.affected_scope {
        return Err(NotificationError::ResolutionFenceMismatch);
    }
    if core.authority.authority_owner != record.owner {
        return Err(NotificationError::ResolutionAuthorityInsufficient);
    }
    if authorization
        .evidence_handles
        .iter()
        .any(|handle| !record.evidence_handles.contains(handle))
    {
        return Err(NotificationError::ResolutionEvidenceUnbound);
    }
    Ok(())
}

/// Canonical transition model used by the Kernel/store owner.
///
/// It has no persistence side effect. The canonical backend must call these
/// transitions within its existing fenced transaction and outbox owner.
#[derive(Clone, Debug, Default)]
pub struct NotificationStore {
    records: BTreeMap<String, Notification>,
    notification_ids: BTreeMap<String, String>,
    sequence: u64,
}

impl NotificationStore {
    /// Creates an empty transition model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            notification_ids: BTreeMap::new(),
            sequence: 0,
        }
    }

    /// Returns the number of canonical records in this model.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reads one record by its canonical deduplication key.
    #[must_use]
    pub fn get(&self, dedup_key: &str) -> Option<&Notification> {
        self.records.get(dedup_key)
    }

    /// Iterates records in deterministic deduplication-key order.
    pub fn iter(&self) -> impl Iterator<Item = &Notification> {
        self.records.values()
    }

    /// Creates or updates exactly one record before any delivery attempt.
    pub fn upsert(&mut self, draft: NotificationDraft) -> Result<&Notification, NotificationError> {
        draft.validate()?;
        let notification_id = draft.notification_id.as_str().to_owned();
        if let Some(existing_dedup_key) = self.notification_ids.get(&notification_id)
            && existing_dedup_key != &draft.dedup_key
        {
            return Err(NotificationError::IdentityConflict);
        }
        if let Some(existing) = self.records.get(&draft.dedup_key) {
            if existing.resolution_ref.is_some() {
                return Err(NotificationError::AlreadyResolved);
            }
            if !existing.matches_draft(&draft) {
                return Err(NotificationError::IdentityConflict);
            }
        }
        self.sequence = self.sequence.saturating_add(1);
        let existing = self.records.get(&draft.dedup_key);
        let occurrences = existing.map_or(1, |record| record.occurrences.saturating_add(1));
        let acknowledgement = existing.and_then(|record| record.acknowledgement.clone());
        let record = Notification {
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
            revision: self.sequence,
        };
        record.validate()?;
        self.notification_ids
            .insert(notification_id, draft.dedup_key.clone());
        self.records.insert(draft.dedup_key.clone(), record);
        self.records
            .get(&draft.dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }

    /// Records the verified latest delivery state without resolving the item.
    pub fn record_delivery(
        &mut self,
        dedup_key: &str,
        delivery: DeliveryState,
    ) -> Result<&Notification, NotificationError> {
        validate_dedup_key(dedup_key)?;
        if matches!(delivery, DeliveryState::Pending) {
            return Err(NotificationError::InvalidField("delivery"));
        }
        delivery.validate()?;
        let existing = self
            .records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)?;
        if existing.resolution_ref.is_some() {
            return Err(NotificationError::AlreadyResolved);
        }
        self.sequence = self.sequence.saturating_add(1);
        let mut updated = existing.clone();
        updated.delivery = delivery;
        updated.revision = self.sequence;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }

    /// Acknowledges one record; acknowledgement never resolves it.
    pub fn acknowledge(
        &mut self,
        dedup_key: &str,
        principal: &str,
    ) -> Result<&Notification, NotificationError> {
        validate_dedup_key(dedup_key)?;
        text(principal, "principal")?;
        let existing = self
            .records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)?;
        if existing.resolution_ref.is_some() {
            return Err(NotificationError::AlreadyResolved);
        }
        self.sequence = self.sequence.saturating_add(1);
        let mut updated = existing.clone();
        updated.acknowledgement = Some(Acknowledgement {
            principal: principal.to_owned(),
            sequence: self.sequence,
        });
        updated.revision = self.sequence;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }

    /// Resolves only with a protected, evidence-bound authority receipt.
    pub fn resolve(
        &mut self,
        dedup_key: &str,
        disposition: &str,
        authorization: &ResolutionAuthorization,
    ) -> Result<&Notification, NotificationError> {
        validate_dedup_key(dedup_key)?;
        let existing = self
            .records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)?;
        if existing.resolution_ref.is_some() {
            return Err(NotificationError::AlreadyResolved);
        }
        validate_resolution(existing, disposition, authorization)?;
        self.sequence = self.sequence.saturating_add(1);
        let mut updated = existing.clone();
        updated.resolution_ref = Some(ResolutionRef {
            receipt_id: authorization
                .receipt
                .identity
                .receipt_id
                .as_str()
                .to_owned(),
            authority_id: authorization
                .receipt
                .core
                .authority
                .authority_id
                .as_str()
                .to_owned(),
            authority_owner: authorization.receipt.core.authority.authority_owner.clone(),
            evidence_handles: authorization.evidence_handles.clone(),
            disposition: disposition.to_owned(),
        });
        updated.revision = self.sequence;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, OperationId, ProductId,
        RequestId, RequestMetadata, ResourceGeneration, SourceId, TransactionSequence,
    };
    use eliot_receipts::{
        ArtifactBinding, AuthorityBinding, CausalBinding, OperationBinding, ReceiptCore,
        RequestBinding, WorkScopeBinding, WorkScopeId, contract_identity,
    };
    use std::num::NonZeroU64;

    fn fence() -> StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
        StateFence::new(
            EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch"),
            ResourceGeneration::genesis(),
        )
    }

    fn draft(key: &str, severity: NotificationSeverity) -> NotificationDraft {
        NotificationDraft {
            notification_id: PlatformHandle::new(format!("notification-{key}")).expect("id"),
            severity,
            subject: "subject".to_owned(),
            summary: "summary".to_owned(),
            evidence_handles: vec!["evidence-1".to_owned()],
            affected_scope: "scope-1".to_owned(),
            owner: "owner-1".to_owned(),
            required_action: "review".to_owned(),
            deadline_or_review: None,
            dedup_key: key.to_owned(),
            delivery_channels: vec![DeliveryChannel::ControlBoard, DeliveryChannel::NativeToast],
            state_fence: fence(),
        }
    }

    fn resolution_receipt() -> ReceiptEnvelope {
        let state_fence = fence();
        let request_id = RequestId::new("resolve-request").expect("request id");
        let metadata = RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1").expect("product"),
            source_id: SourceId::new("owner-1").expect("source"),
            state_fence: state_fence.clone(),
            clock: ClockReading::default(),
        };
        let artifact_id = ArtifactId::new("evidence-1").expect("artifact id");
        ReceiptEnvelope::issue(ReceiptCore {
            contract: contract_identity().expect("contract"),
            kind: ReceiptKind::Verification,
            work_scope: WorkScopeBinding {
                scope_id: WorkScopeId::new("scope-1").expect("scope"),
                product_id: metadata.product_id.clone(),
                resource_generation: ResourceGeneration::genesis(),
                state_fence: state_fence.clone(),
            },
            task: None,
            session: None,
            causal: CausalBinding {
                state_fence: state_fence.clone(),
                transaction_sequence: TransactionSequence::genesis(),
                parent_receipt_id: None,
                predecessor_receipt_ids: Vec::new(),
            },
            request: RequestBinding {
                metadata,
                state_fence: state_fence.clone(),
            },
            operation: OperationBinding {
                operation_id: OperationId::new("resolve-operation").expect("operation"),
                request_id,
                idempotency_key: "resolve-idempotency".to_owned(),
                operation_kind: "notification.resolve".to_owned(),
                effect: EffectClass::ReversibleMutation,
                state_fence: state_fence.clone(),
            },
            authority: AuthorityBinding {
                authority_id: ContractId::new("authority-owner-1").expect("authority"),
                authority_owner: "owner-1".to_owned(),
                authority_epoch: state_fence.authority_epoch.clone(),
                state_fence: state_fence.clone(),
                allowed_effect: EffectClass::ReversibleMutation,
                proof_ceiling: ProofCeiling::ScopedVerification,
            },
            artifacts: vec![ArtifactBinding {
                artifact_id,
                sha256: eliot_contracts::sha256_hex(b"evidence-1"),
                role: ReceiptKind::Artifact,
                source_revision: Some("test".to_owned()),
            }],
            verifier: None,
            problem: None,
            coordination: None,
            disposition: ReceiptDisposition::Success {
                proof: ProofCeiling::ScopedVerification,
            },
        })
        .expect("receipt")
    }

    #[test]
    fn repeated_events_update_one_full_record() {
        let mut store = NotificationStore::new();
        store
            .upsert(draft("disk-full", NotificationSeverity::Warning))
            .expect("first");
        store
            .upsert(draft("disk-full", NotificationSeverity::Warning))
            .expect("repeat");
        assert_eq!(store.len(), 1);
        let record = store.get("disk-full").expect("record");
        assert_eq!(record.occurrences, 2);
        assert_eq!(record.delivery, DeliveryState::Pending);
        assert_eq!(record.evidence_handles, vec!["evidence-1"]);
    }

    #[test]
    fn one_notification_id_cannot_own_two_dedup_records() {
        let mut store = NotificationStore::new();
        let first = draft("first", NotificationSeverity::Warning);
        let mut second = draft("second", NotificationSeverity::Warning);
        second.notification_id = first.notification_id.clone();
        store.upsert(first).expect("first");
        assert_eq!(
            store.upsert(second),
            Err(NotificationError::IdentityConflict)
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn acknowledgement_keeps_critical_record_unresolved() {
        let mut store = NotificationStore::new();
        store
            .upsert(draft("backup-failed", NotificationSeverity::Critical))
            .expect("create");
        store
            .record_delivery(
                "backup-failed",
                DeliveryState::Failed {
                    reason: "toast provider failed".to_owned(),
                },
            )
            .expect("failure");
        store
            .acknowledge("backup-failed", "operator-1")
            .expect("ack");
        let record = store.get("backup-failed").expect("record");
        assert!(record.is_unresolved());
        assert!(record.is_failed_delivery());
        assert!(!record.should_popup(false));
        assert_eq!(record.severity, NotificationSeverity::Critical);
    }

    #[test]
    fn resolution_requires_bound_authority_and_evidence() {
        let mut store = NotificationStore::new();
        store
            .upsert(draft("kernel-fence", NotificationSeverity::Critical))
            .expect("create");
        let empty = ResolutionAuthorization {
            receipt: resolution_receipt(),
            evidence_handles: Vec::new(),
        };
        assert_eq!(
            store.resolve("kernel-fence", "fixed", &empty),
            Err(NotificationError::ResolutionRequiresEvidence)
        );
        let authorization = ResolutionAuthorization {
            receipt: resolution_receipt(),
            evidence_handles: vec!["evidence-1".to_owned()],
        };
        store
            .resolve("kernel-fence", "rotated and verified", &authorization)
            .expect("bound resolution");
        let record = store.get("kernel-fence").expect("record");
        assert!(!record.is_unresolved());
        assert!(!record.should_popup(false));
        assert_eq!(
            record
                .resolution_ref
                .as_ref()
                .expect("resolution")
                .authority_owner,
            "owner-1"
        );
    }

    #[test]
    fn resolution_uses_receipt_proof_without_operation_name_shortcut() {
        let mut store = NotificationStore::new();
        store
            .upsert(draft(
                "operator-review",
                NotificationSeverity::ActionRequired,
            ))
            .expect("create");
        let mut receipt = resolution_receipt();
        receipt.core.operation.operation_kind = "operator.review".to_owned();
        receipt.core.operation.effect = EffectClass::Read;
        let receipt = ReceiptEnvelope::issue(receipt.core).expect("receipt");
        let authorization = ResolutionAuthorization {
            receipt,
            evidence_handles: vec!["evidence-1".to_owned()],
        };
        store
            .resolve("operator-review", "reviewed", &authorization)
            .expect("proof-bound resolution");
    }

    #[test]
    fn quiet_hours_suppress_noncritical_popups_only() {
        let mut store = NotificationStore::new();
        store
            .upsert(draft("routine-sync", NotificationSeverity::Information))
            .expect("info");
        store
            .upsert(draft("action", NotificationSeverity::ActionRequired))
            .expect("action");
        store
            .upsert(draft("disk-critical", NotificationSeverity::Critical))
            .expect("critical");
        assert!(!store.get("routine-sync").expect("info").should_popup(true));
        assert!(!store.get("action").expect("action").should_popup(true));
        assert!(
            store
                .get("disk-critical")
                .expect("critical")
                .should_popup(true)
        );
        assert_eq!(store.iter().count(), 3);
    }
}
