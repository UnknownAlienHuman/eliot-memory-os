//! Store-neutral wire contract for durable directed mailbox delivery.
//!
//! Kernel owns admission of these records through the canonical write path
//! (issue #1820, I10.18). The Governor peer channel keeps the live delivery
//! protocol; the store arbitrates only identity, per-stream ordering,
//! delivery/acknowledgement observations, and expiry. Records never grant
//! task acceptance, truth, authority, or effect.
//!
//! Identity, principals, timestamps, ordering, provenance, privacy, State
//! Fence, and delivery receipts travel on the shared `EventEnvelope`
//! (`eliot-protocol`) and `ReceiptEnvelope` (`eliot-receipts`); this record
//! carries only what the store must arbitrate plus exact digests and
//! durable handles into those envelopes and the Blob Store. Large payloads
//! are referenced by handle, never inlined.

use std::collections::BTreeMap;

use eliot_contracts::{
    EpochId, MailboxAttemptRecord, MailboxDeliveryOutcome, MailboxDeliveryState, PeerMailboxKind,
    PeerMailboxRouteProfile, TaskId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DurableRecordHandle, NamedMutationOperation, NamedMutationRequest, NamedReadOperation,
    NamedReadRequest, ReadConsistency, ScopeId, StateFence, StoreError, canonical_json_bytes,
    validate_text,
};

/// Schema identifier for persisted mailbox item records.
pub const MAILBOX_ITEM_SCHEMA_V1: &str = "eliot.mailbox.item.v1";
/// Schema identifier for persisted per-stream ordering heads.
pub const MAILBOX_STREAM_HEAD_SCHEMA_V1: &str = "eliot.mailbox.stream-head.v1";
/// Stable named mutation used for mailbox admission.
pub const ADMIT_MAILBOX_ITEM_MUTATION_NAME: &str = "AdmitMailboxItem";
/// Stable named mutation used for delivery-attempt observations.
pub const RECORD_MAILBOX_DELIVERY_MUTATION_NAME: &str = "RecordMailboxDelivery";
/// Stable named mutation used for recipient acknowledgements.
pub const ACKNOWLEDGE_MAILBOX_ITEM_MUTATION_NAME: &str = "AcknowledgeMailboxItem";
/// Stable named mutation used for terminal expiry.
pub const EXPIRE_MAILBOX_ITEM_MUTATION_NAME: &str = "ExpireMailboxItem";
/// Stable named read used for exact mailbox item readback.
pub const MAILBOX_ITEM_READ_NAME: &str = "GetMailboxItem";
/// Maximum retained delivery-attempt entries per mailbox head.
pub const MAX_MAILBOX_ATTEMPT_HISTORY: usize = 32;
/// Maximum admitted payload size in bytes (content travels by handle).
pub const MAX_MAILBOX_PAYLOAD_BYTES: u64 = 65_536;
/// Maximum evidence/artifact references per mailbox item.
pub const MAX_MAILBOX_REFERENCES: usize = 16;

/// Identity of one ordered mailbox stream: one recipient task queue.
/// Ordering is per stream only; the store keeps no global order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxStreamId {
    pub recipient_session_id: String,
    pub work_item_id: String,
}

impl MailboxStreamId {
    /// Stable key used in diagnostics and stream-head addressing.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.recipient_session_id, self.work_item_id)
    }
}

/// Durable per-stream ordering head: the last admitted sequence and message.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxStreamHead {
    pub stream: MailboxStreamId,
    pub seq: u64,
    pub message_id: String,
}

/// One retained directed mailbox item with its exact identity, ordering,
/// route capability, and delivery lifecycle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxItemRecord {
    /// Stable message identity; admission is idempotent per identity.
    pub message_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Ordered recipient/task stream of this item.
    pub stream: MailboxStreamId,
    /// Per-stream sequence, assigned by Governor admission starting at 1.
    pub stream_seq: u64,
    /// Previous stream message; absent only for the first stream item.
    pub predecessor_message_id: Option<String>,
    /// Closed I10.18 message kind.
    pub kind: PeerMailboxKind,
    /// Session that submitted the item, bound by Kernel admission.
    pub sender_session_id: String,
    /// Coordination scope of the item.
    pub scope: String,
    /// Authority epoch of admission.
    pub authority_epoch: EpochId,
    /// Fence at which this item was admitted.
    pub state_fence: StateFence,
    /// Digest of the exact payload bytes held behind the handle.
    pub payload_digest: String,
    /// Payload size in bytes; content itself travels by handle.
    pub payload_bytes: u64,
    /// Durable handle to the item payload, when staged.
    pub payload_handle: Option<DurableRecordHandle>,
    /// Durable evidence handles cited by the item.
    pub evidence_handles: Vec<DurableRecordHandle>,
    /// Durable artifact handles cited by the item.
    pub artifact_handles: Vec<DurableRecordHandle>,
    /// Route capability at which the item may be delivered.
    pub route_profile: PeerMailboxRouteProfile,
    /// Immutable admission revision; acknowledgement covers this exactly.
    pub revision: u64,
    /// Lifecycle advance count; zero at admission, plus one per advance.
    pub advance_seq: u64,
    /// Current delivery lifecycle of the retained head.
    pub delivery: MailboxDeliveryState,
    /// Counted delivery attempts, including converged late duplicates.
    pub attempts: u32,
    /// Bounded retained delivery-attempt history, oldest first.
    pub attempt_history: Vec<MailboxAttemptRecord>,
    /// Acknowledged admission revision, once acknowledged.
    pub acknowledged_revision: Option<u64>,
    /// Acknowledging recipient session, once acknowledged.
    pub acknowledged_by: Option<String>,
    /// Expiry horizon in milliseconds, when configured.
    pub expires_at: Option<u64>,
    /// Recipient session generation; a generation change never inherits
    /// old acknowledgements.
    pub session_generation: u64,
    /// Prior message this admission is reassigned from, when reassigned
    /// after Session loss. Retained verbatim as Governor-asserted linkage.
    pub reassigned_from: Option<String>,
    /// Admission time in milliseconds on the owner's time base.
    pub created_at: u64,
}

impl MailboxItemRecord {
    /// Validates the closed persisted record without assigning delivery
    /// semantics or granting any decision/effect authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_identity()?;
        self.validate_stream_linkage()?;
        self.validate_handles()?;
        self.validate_counters()?;
        self.validate_attempt_history()?;
        validate_delivery(&self.delivery)?;
        self.validate_ack_linkage()?;
        if let Some(from) = &self.reassigned_from {
            validate_text(from, "mailbox.reassigned_from")?;
            if from == &self.message_id {
                return Err(StoreError::InvalidField {
                    field: "mailbox.reassigned_from",
                    reason: "must not reference the item itself",
                });
            }
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), StoreError> {
        validate_text(&self.message_id, "mailbox.message_id")?;
        validate_text(
            &self.stream.recipient_session_id,
            "mailbox.stream.recipient_session_id",
        )?;
        validate_text(&self.stream.work_item_id, "mailbox.stream.work_item_id")?;
        validate_text(&self.sender_session_id, "mailbox.sender_session_id")?;
        validate_text(&self.scope, "mailbox.scope")?;
        validate_text(&self.payload_digest, "mailbox.payload_digest")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        Ok(())
    }

    fn validate_stream_linkage(&self) -> Result<(), StoreError> {
        if self.stream_seq == 0 || self.stream_seq > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "mailbox.stream_seq",
                reason: "must be a positive stream sequence",
            });
        }
        let first = self.stream_seq == 1;
        match &self.predecessor_message_id {
            Some(predecessor) => {
                if first {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.predecessor_message_id",
                        reason: "first stream item has no predecessor",
                    });
                }
                validate_text(predecessor, "mailbox.predecessor_message_id")?;
                if predecessor == &self.message_id {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.predecessor_message_id",
                        reason: "must not reference the item itself",
                    });
                }
            }
            None => {
                if !first {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.predecessor_message_id",
                        reason: "non-first stream item must name its predecessor",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_handles(&self) -> Result<(), StoreError> {
        if self.payload_bytes > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(StoreError::InvalidField {
                field: "mailbox.payload_bytes",
                reason: "exceeds the bounded mailbox payload size",
            });
        }
        if let Some(handle) = &self.payload_handle {
            validate_handle(handle, "mailbox.payload_handle")?;
        }
        if self.evidence_handles.len() > MAX_MAILBOX_REFERENCES {
            return Err(StoreError::InvalidField {
                field: "mailbox.evidence_handles",
                reason: "exceeds the bounded mailbox reference count",
            });
        }
        if self.artifact_handles.len() > MAX_MAILBOX_REFERENCES {
            return Err(StoreError::InvalidField {
                field: "mailbox.artifact_handles",
                reason: "exceeds the bounded mailbox reference count",
            });
        }
        for handle in &self.evidence_handles {
            validate_handle(handle, "mailbox.evidence_handle")?;
        }
        for handle in &self.artifact_handles {
            validate_handle(handle, "mailbox.artifact_handle")?;
        }
        Ok(())
    }

    fn validate_counters(&self) -> Result<(), StoreError> {
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "mailbox.revision",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self.advance_seq > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "mailbox.advance_seq",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self.attempts < u32::try_from(self.attempt_history.len()).unwrap_or(u32::MAX) {
            return Err(StoreError::InvalidField {
                field: "mailbox.attempts",
                reason: "must cover the retained attempt history",
            });
        }
        Ok(())
    }

    fn validate_attempt_history(&self) -> Result<(), StoreError> {
        if self.attempt_history.len() > MAX_MAILBOX_ATTEMPT_HISTORY {
            return Err(StoreError::InvalidField {
                field: "mailbox.attempt_history",
                reason: "exceeds the bounded attempt history",
            });
        }
        // Entries are retained oldest-first with monotonic numbering;
        // truncation may drop the oldest entries but never reorders.
        let mut previous_attempt = 0_u32;
        for entry in &self.attempt_history {
            if entry.attempt == 0 || entry.attempt < previous_attempt {
                return Err(StoreError::InvalidField {
                    field: "mailbox.attempt_history.attempt",
                    reason: "attempt numbers must be positive and non-decreasing",
                });
            }
            previous_attempt = entry.attempt;
            validate_outcome(&entry.outcome)?;
        }
        Ok(())
    }

    fn validate_ack_linkage(&self) -> Result<(), StoreError> {
        match (&self.acknowledged_revision, &self.acknowledged_by) {
            (Some(revision), Some(by)) => {
                validate_text(by, "mailbox.acknowledged_by")?;
                if *revision != self.revision {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.acknowledged_revision",
                        reason: "must cover the exact admission revision",
                    });
                }
                if !matches!(&self.delivery, MailboxDeliveryState::Acknowledged { .. }) {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.delivery",
                        reason: "acknowledged items must carry the acknowledged state",
                    });
                }
            }
            (None, None) => {}
            _ => {
                return Err(StoreError::InvalidField {
                    field: "mailbox.acknowledged_by",
                    reason: "revision and session must be recorded together",
                });
            }
        }
        Ok(())
    }

    /// Returns canonical JSON used as the immutable durable record body.
    pub fn canonical_record_json(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// Re-validates one durable handle through its canonical constructor.
fn validate_handle(handle: &DurableRecordHandle, field: &'static str) -> Result<(), StoreError> {
    DurableRecordHandle::new(handle.as_str()).map_err(|_| StoreError::InvalidField {
        field,
        reason: "must be a bounded durable record handle",
    })?;
    Ok(())
}

fn validate_outcome(outcome: &MailboxDeliveryOutcome) -> Result<(), StoreError> {
    match outcome {
        MailboxDeliveryOutcome::Delivered { endpoint } => {
            validate_text(endpoint, "mailbox.attempt.endpoint")?;
        }
        MailboxDeliveryOutcome::Unavailable { reason }
        | MailboxDeliveryOutcome::Unknown { reason } => {
            validate_text(reason, "mailbox.attempt.reason")?;
        }
    }
    Ok(())
}

fn validate_delivery(delivery: &MailboxDeliveryState) -> Result<(), StoreError> {
    match delivery {
        MailboxDeliveryState::Staged | MailboxDeliveryState::Expired { .. } => {}
        MailboxDeliveryState::Delivered { endpoint } => {
            validate_text(endpoint, "mailbox.delivery.endpoint")?;
        }
        MailboxDeliveryState::Acknowledged { by_session, .. } => {
            validate_text(by_session, "mailbox.delivery.by_session")?;
        }
        MailboxDeliveryState::Unavailable { reason } | MailboxDeliveryState::Unknown { reason } => {
            validate_text(reason, "mailbox.delivery.reason")?;
        }
    }
    Ok(())
}

/// One mailbox admission with the exact expected stream predecessor.
///
/// The predecessor is the previous stream record, not a previous revision
/// of this item: it arbitrates per-recipient/per-task ordering. Absent only
/// for the first stream item.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxItemRevision {
    /// Complete immutable admitted item.
    pub record: MailboxItemRecord,
    /// Exact stream predecessor observed by Governor; absent only for first admission.
    pub expected_predecessor: Option<MailboxItemRecord>,
}

impl MailboxItemRevision {
    /// Validates admission shape and stream-ordering linkage.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate()?;
        if self.record.advance_seq != 0 {
            return Err(StoreError::InvalidField {
                field: "mailbox.advance_seq",
                reason: "admission starts unlived",
            });
        }
        if self.record.attempts != 0 || !self.record.attempt_history.is_empty() {
            return Err(StoreError::InvalidField {
                field: "mailbox.attempts",
                reason: "admission starts without attempts",
            });
        }
        if !matches!(self.record.delivery, MailboxDeliveryState::Staged) {
            return Err(StoreError::InvalidField {
                field: "mailbox.delivery",
                reason: "admission starts staged",
            });
        }
        match &self.expected_predecessor {
            Some(predecessor) => {
                predecessor.validate()?;
                if predecessor.task_id != self.record.task_id
                    || predecessor.stream != self.record.stream
                {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.expected_predecessor",
                        reason: "task and stream must remain bound",
                    });
                }
                if predecessor.stream_seq.checked_add(1) != Some(self.record.stream_seq) {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.stream_seq",
                        reason: "must immediately follow the expected predecessor",
                    });
                }
                if self.record.predecessor_message_id.as_deref()
                    != Some(predecessor.message_id.as_str())
                {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.predecessor_message_id",
                        reason: "must name the expected predecessor",
                    });
                }
            }
            None => {
                if self.record.stream_seq != 1 {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.stream_seq",
                        reason: "first admission starts the stream at 1",
                    });
                }
            }
        }
        Ok(())
    }
}

/// One delivery-step observation against an exact expected head.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDeliveryAdvance {
    pub message_id: String,
    pub task_id: TaskId,
    /// Observation time in milliseconds on the owner's time base.
    pub attempt_at: u64,
    /// Route capability the step was attempted under.
    pub route_profile: PeerMailboxRouteProfile,
    pub outcome: MailboxDeliveryOutcome,
    /// Exact current head the step advances; compare-and-set identity.
    pub expected_head: MailboxItemRecord,
}

impl MailboxDeliveryAdvance {
    /// Validates the advance against its expected head. Terminal heads admit
    /// no advance; acknowledged heads converge late duplicates only.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.message_id, "mailbox.message_id")?;
        self.expected_head.validate()?;
        validate_outcome(&self.outcome)?;
        if self.expected_head.message_id != self.message_id
            || self.expected_head.task_id != self.task_id
        {
            return Err(StoreError::InvalidField {
                field: "mailbox.expected_head",
                reason: "message and task must remain bound",
            });
        }
        if !self.expected_head.delivery.is_live() {
            return Err(StoreError::InvalidField {
                field: "mailbox.delivery",
                reason: "terminal heads admit no delivery advance",
            });
        }
        if self.route_profile != self.expected_head.route_profile {
            return Err(StoreError::InvalidField {
                field: "mailbox.route_profile",
                reason: "delivery is qualified by the admitted route profile",
            });
        }
        Ok(())
    }

    /// Computes the deterministic successor head of this observation.
    ///
    /// The attempt is counted and retained; acknowledged heads converge
    /// late duplicates without changing delivery state. Every other live
    /// head takes the outcome state.
    pub fn applied_head(&self) -> Result<MailboxItemRecord, StoreError> {
        self.validate()?;
        let mut head = self.expected_head.clone();
        head.attempts = head.attempts.saturating_add(1);
        let attempt = head.attempts;
        head.attempt_history.push(MailboxAttemptRecord {
            attempt,
            at: self.attempt_at,
            outcome: self.outcome.clone(),
        });
        while head.attempt_history.len() > MAX_MAILBOX_ATTEMPT_HISTORY {
            head.attempt_history.remove(0);
        }
        head.advance_seq = head.advance_seq.saturating_add(1);
        if !matches!(head.delivery, MailboxDeliveryState::Acknowledged { .. }) {
            head.delivery = match &self.outcome {
                MailboxDeliveryOutcome::Delivered { endpoint } => MailboxDeliveryState::Delivered {
                    endpoint: endpoint.clone(),
                },
                MailboxDeliveryOutcome::Unavailable { reason } => {
                    MailboxDeliveryState::Unavailable {
                        reason: reason.clone(),
                    }
                }
                MailboxDeliveryOutcome::Unknown { reason } => MailboxDeliveryState::Unknown {
                    reason: reason.clone(),
                },
            };
        }
        head.validate()?;
        Ok(head)
    }
}

/// One recipient acknowledgement of an exact admission revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAckAdvance {
    pub message_id: String,
    pub task_id: TaskId,
    /// Exact admission revision covered by this acknowledgement.
    pub revision: u64,
    /// Acknowledging recipient session.
    pub by_session: String,
    /// Observation time in milliseconds on the owner's time base.
    pub at: u64,
    /// Exact current head the acknowledgement advances.
    pub expected_head: MailboxItemRecord,
}

impl MailboxAckAdvance {
    /// Validates the acknowledgement against its expected head. Only
    /// delivered, unknown, or already-acknowledged heads admit it;
    /// acknowledgement proves only that the revision reached the
    /// recipient and is never agreement, use, or completion.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.message_id, "mailbox.message_id")?;
        validate_text(&self.by_session, "mailbox.by_session")?;
        self.expected_head.validate()?;
        if self.expected_head.message_id != self.message_id
            || self.expected_head.task_id != self.task_id
        {
            return Err(StoreError::InvalidField {
                field: "mailbox.expected_head",
                reason: "message and task must remain bound",
            });
        }
        if self.revision != self.expected_head.revision {
            return Err(StoreError::InvalidField {
                field: "mailbox.revision",
                reason: "must cover the exact admission revision",
            });
        }
        if self.expected_head.stream.recipient_session_id != self.by_session {
            return Err(StoreError::InvalidField {
                field: "mailbox.by_session",
                reason: "only the recipient session acknowledges",
            });
        }
        match &self.expected_head.delivery {
            MailboxDeliveryState::Delivered { .. }
            | MailboxDeliveryState::Unknown { .. }
            | MailboxDeliveryState::Acknowledged { .. } => {}
            MailboxDeliveryState::Staged | MailboxDeliveryState::Unavailable { .. } => {
                return Err(StoreError::InvalidField {
                    field: "mailbox.delivery",
                    reason: "unobserved heads admit no acknowledgement",
                });
            }
            MailboxDeliveryState::Expired { .. } => {
                return Err(StoreError::InvalidField {
                    field: "mailbox.delivery",
                    reason: "terminal heads admit no acknowledgement",
                });
            }
        }
        Ok(())
    }

    /// Computes the deterministic successor head of this acknowledgement.
    ///
    /// A repeated identical acknowledgement converges to the unchanged
    /// head; otherwise the head takes the acknowledged state with the
    /// exact covered revision and session.
    pub fn applied_head(&self) -> Result<MailboxItemRecord, StoreError> {
        self.validate()?;
        if self.expected_head.delivery
            == (MailboxDeliveryState::Acknowledged {
                revision: self.revision,
                by_session: self.by_session.clone(),
            })
        {
            return Ok(self.expected_head.clone());
        }
        let mut head = self.expected_head.clone();
        head.delivery = MailboxDeliveryState::Acknowledged {
            revision: self.revision,
            by_session: self.by_session.clone(),
        };
        head.acknowledged_revision = Some(self.revision);
        head.acknowledged_by = Some(self.by_session.clone());
        head.advance_seq = head.advance_seq.saturating_add(1);
        head.validate()?;
        Ok(head)
    }
}

/// Closed terminal-expiry cause.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MailboxExpiryCause {
    /// The configured horizon lapsed while the head was live.
    Expired,
    /// The recipient Session was lost; reassignment linkage, when any, is
    /// retained on the successor admission.
    SessionLoss { session_id: String },
}

/// One terminal expiry observation against an exact expected head.
/// Delivery history is retained on the expired head.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxExpiryAdvance {
    pub message_id: String,
    pub task_id: TaskId,
    pub cause: MailboxExpiryCause,
    /// Observation time in milliseconds on the owner's time base.
    pub observed_at: u64,
    /// Exact current head the expiry advances.
    pub expected_head: MailboxItemRecord,
}

impl MailboxExpiryAdvance {
    /// Validates the expiry against its expected head. Horizon expiry
    /// requires a due horizon; Session-loss expiry always applies to a
    /// live head of the lost session.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.message_id, "mailbox.message_id")?;
        self.expected_head.validate()?;
        if self.expected_head.message_id != self.message_id
            || self.expected_head.task_id != self.task_id
        {
            return Err(StoreError::InvalidField {
                field: "mailbox.expected_head",
                reason: "message and task must remain bound",
            });
        }
        if !self.expected_head.delivery.is_live() {
            return Err(StoreError::InvalidField {
                field: "mailbox.delivery",
                reason: "terminal heads admit no expiry",
            });
        }
        match &self.cause {
            MailboxExpiryCause::Expired => {
                let Some(horizon) = self.expected_head.expires_at else {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.expires_at",
                        reason: "horizon expiry requires a configured horizon",
                    });
                };
                if self.observed_at < horizon {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.observed_at",
                        reason: "horizon has not lapsed",
                    });
                }
            }
            MailboxExpiryCause::SessionLoss { session_id } => {
                validate_text(session_id, "mailbox.session_id")?;
                if self.expected_head.stream.recipient_session_id != *session_id
                    && self.expected_head.sender_session_id != *session_id
                {
                    return Err(StoreError::InvalidField {
                        field: "mailbox.session_id",
                        reason: "must name a session of this item",
                    });
                }
            }
        }
        Ok(())
    }

    /// Computes the deterministic successor head of this expiry. Delivery
    /// history is retained on the expired head; expiry is terminal.
    pub fn applied_head(&self) -> Result<MailboxItemRecord, StoreError> {
        self.validate()?;
        let mut head = self.expected_head.clone();
        head.delivery = MailboxDeliveryState::Expired {
            at: self.observed_at,
        };
        head.advance_seq = head.advance_seq.saturating_add(1);
        head.validate()?;
        Ok(head)
    }
}

/// Builds the closed named mutation for one mailbox admission.
pub fn mailbox_item_request(
    revision: MailboxItemRevision,
) -> Result<NamedMutationRequest, StoreError> {
    revision.validate()?;
    let parameters = BTreeMap::from([(
        "revision".to_owned(),
        serde_json::to_value(revision)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::AdmitMailboxItem,
        parameters,
    })
}

/// Decodes and validates one closed mailbox admission.
pub fn decode_mailbox_item(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<MailboxItemRevision, StoreError> {
    if operation != NamedMutationOperation::AdmitMailboxItem {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let revision: MailboxItemRevision =
        serde_json::from_value(parameters.get("revision").cloned().ok_or(
            StoreError::InvalidField {
                field: "mailbox.revision",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    revision.validate()?;
    Ok(revision)
}

/// Builds the closed named mutation for one delivery observation.
pub fn mailbox_delivery_request(
    advance: MailboxDeliveryAdvance,
) -> Result<NamedMutationRequest, StoreError> {
    advance.validate()?;
    let parameters = BTreeMap::from([(
        "advance".to_owned(),
        serde_json::to_value(advance)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::RecordMailboxDelivery,
        parameters,
    })
}

/// Decodes and validates one closed delivery observation.
pub fn decode_mailbox_delivery(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<MailboxDeliveryAdvance, StoreError> {
    if operation != NamedMutationOperation::RecordMailboxDelivery {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let advance: MailboxDeliveryAdvance =
        serde_json::from_value(parameters.get("advance").cloned().ok_or(
            StoreError::InvalidField {
                field: "mailbox.advance",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    advance.validate()?;
    Ok(advance)
}

/// Builds the closed named mutation for one acknowledgement.
pub fn mailbox_ack_request(advance: MailboxAckAdvance) -> Result<NamedMutationRequest, StoreError> {
    advance.validate()?;
    let parameters = BTreeMap::from([(
        "advance".to_owned(),
        serde_json::to_value(advance)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::AcknowledgeMailboxItem,
        parameters,
    })
}

/// Decodes and validates one closed acknowledgement.
pub fn decode_mailbox_ack(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<MailboxAckAdvance, StoreError> {
    if operation != NamedMutationOperation::AcknowledgeMailboxItem {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let advance: MailboxAckAdvance =
        serde_json::from_value(parameters.get("advance").cloned().ok_or(
            StoreError::InvalidField {
                field: "mailbox.advance",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    advance.validate()?;
    Ok(advance)
}

/// Builds the closed named mutation for one terminal expiry.
pub fn mailbox_expiry_request(
    advance: MailboxExpiryAdvance,
) -> Result<NamedMutationRequest, StoreError> {
    advance.validate()?;
    let parameters = BTreeMap::from([(
        "advance".to_owned(),
        serde_json::to_value(advance)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::ExpireMailboxItem,
        parameters,
    })
}

/// Decodes and validates one closed terminal expiry.
pub fn decode_mailbox_expiry(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<MailboxExpiryAdvance, StoreError> {
    if operation != NamedMutationOperation::ExpireMailboxItem {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let advance: MailboxExpiryAdvance =
        serde_json::from_value(parameters.get("advance").cloned().ok_or(
            StoreError::InvalidField {
                field: "mailbox.advance",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    advance.validate()?;
    Ok(advance)
}

/// Builds an exact task/message read request. Readback returns the typed
/// head record; delivery history is retained on the head itself.
pub fn mailbox_item_read_request(
    task_id: TaskId,
    message_id: impl Into<String>,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let message_id = message_id.into();
    validate_text(&message_id, "mailbox.message_id")?;
    let parameters = BTreeMap::from([
        (
            "task_id".to_owned(),
            serde_json::to_value(task_id)
                .map_err(|error| StoreError::Serialization(error.to_string()))?,
        ),
        ("message_id".to_owned(), Value::String(message_id)),
    ]);
    Ok(NamedReadRequest {
        operation: NamedReadOperation::GetMailboxItem,
        scope_id: None::<ScopeId>,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    })
}
