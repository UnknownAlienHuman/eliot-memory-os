//! Store-neutral wire contract for durable typed mailbox admissions.
//!
//! Kernel owns semantic admission. Store retains the Kernel-admitted record,
//! binds each message to its exact stream head, and enforces message-id
//! idempotency with per-recipient/per-task ordering. This mirrors the
//! blackboard precedent: the Kernel binds the message to its recipient/task,
//! fence and principals, while the store persists the admitted bytes verbatim
//! and arbitrates identity and head keys with convergent replay.

use std::collections::BTreeMap;

use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, StoreError, canonical_json_bytes, validate_text,
};

/// Schema identifier for persisted mailbox records. This is the exact key the
/// Kernel surface declares (`COORDINATION_MAILBOX_SCHEMA_V1`); the store
/// bridge slice registers this value, never a second one.
pub const MAILBOX_ITEM_SCHEMA_V1: &str = "eliot.coordination.mailbox.v1";
/// Stable named mutation used for mailbox admission. This is the exact name
/// the Kernel surface declares (`COORDINATION_MAILBOX_ADMIT_NAME`); the store
/// bridge slice registers this value, never a second one.
pub const MAILBOX_ITEM_MUTATION_NAME: &str = "AdmitMailboxMessage";
/// Bound for one inline message body, in bytes. This is the payload bound
/// shared with the durable mailbox; larger content travels by handle on a
/// later slice, never as an unbounded inline body here.
pub const MAX_MAILBOX_BODY_BYTES: usize = 65_536;

/// One immutable, stream-scoped admitted mailbox message.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxItemRecord {
    /// Stable identity for the message across retries and redelivery.
    pub message_id: String,
    /// Addressable recipient identity spelled by the producer.
    pub recipient_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Producer-claimed sender principal, retained as opaque evidence.
    pub sender_principal: String,
    /// Authenticated submitting principal bound by the admitting caller.
    pub submitter_principal: String,
    /// Producer-supplied origin handle, retained as opaque evidence.
    pub provenance: String,
    /// Producer-declared privacy class, retained opaquely.
    pub privacy_class: String,
    /// Producer-declared disclosure scope, retained opaquely.
    pub disclosure: String,
    /// Inline message body.
    pub body: String,
    /// Whether the recipient must acknowledge this control message.
    pub requires_acknowledgement: bool,
    /// Fence at which the message was admitted.
    pub state_fence: StateFence,
    /// Producer-observed submission time, Unix milliseconds, never zero.
    pub submitted_at_unix_ms: u64,
    /// Per-recipient/per-task ordering key assigned at admission. The first
    /// message for a recipient/task pair carries 1; every later message
    /// carries one more than the highest key already known for that pair.
    pub sequence: u64,
}

impl MailboxItemRecord {
    /// Validates the closed persisted record without assigning admission
    /// semantics or granting any delivery/effect authority. Identity-shaped
    /// fields follow the store text rule; the inline body follows the shared
    /// durable-mailbox bound, mirroring the Kernel admission envelope.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.message_id, "mailbox.message_id")?;
        validate_text(&self.recipient_id, "mailbox.recipient_id")?;
        validate_text(&self.sender_principal, "mailbox.sender_principal")?;
        validate_text(&self.submitter_principal, "mailbox.submitter_principal")?;
        validate_text(&self.provenance, "mailbox.provenance")?;
        validate_text(&self.privacy_class, "mailbox.privacy_class")?;
        validate_text(&self.disclosure, "mailbox.disclosure")?;
        if self.body.len() > MAX_MAILBOX_BODY_BYTES {
            return Err(StoreError::InvalidField {
                field: "mailbox.body",
                reason: "exceeds admission bound",
            });
        }
        if self.body.chars().any(char::is_control) {
            return Err(StoreError::InvalidField {
                field: "mailbox.body",
                reason: "blank or control character",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.submitted_at_unix_ms == 0 {
            return Err(StoreError::InvalidField {
                field: "mailbox.submitted_at_unix_ms",
                reason: "must carry the producer-observed time, never zero",
            });
        }
        if self.submitted_at_unix_ms > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "mailbox.submitted_at_unix_ms",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "mailbox.sequence",
                reason: "must fit a positive Surreal integer",
            });
        }
        Ok(())
    }
}

/// One admitted message and the exact stream head observed at its admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxItemAdmission {
    /// Complete immutable admitted message.
    pub record: MailboxItemRecord,
    /// Exact immutable stream head observed by Kernel; absent only for the
    /// first message of a recipient/task pair. This is the predecessor
    /// compare-and-set over the stream head, mirroring the blackboard
    /// predecessor over the item head: a different message, never a prior
    /// revision of the same item.
    pub expected_head: Option<MailboxItemRecord>,
}

impl MailboxItemAdmission {
    /// Validates stream binding and ordering: the record must immediately
    /// follow the expected head for the same recipient/task pair, or carry
    /// sequence 1 when no head exists.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate()?;
        let expected_sequence = if let Some(head) = &self.expected_head {
            head.validate()?;
            if head.recipient_id != self.record.recipient_id || head.task_id != self.record.task_id
            {
                return Err(StoreError::InvalidField {
                    field: "mailbox.expected_head",
                    reason: "recipient and task must remain bound",
                });
            }
            head.sequence
                .checked_add(1)
                .ok_or(StoreError::InvalidField {
                    field: "mailbox.expected_head.sequence",
                    reason: "sequence overflow",
                })?
        } else {
            1
        };
        if expected_sequence > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "mailbox.expected_head.sequence",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self.record.sequence != expected_sequence {
            return Err(StoreError::InvalidField {
                field: "mailbox.sequence",
                reason: "must immediately follow the expected head",
            });
        }
        Ok(())
    }

    /// Returns canonical JSON used as the immutable durable record body.
    pub fn canonical_record_json(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(&self.record)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// Builds the closed named mutation for one admitted message.
pub fn mailbox_item_request(
    admission: MailboxItemAdmission,
) -> Result<NamedMutationRequest, StoreError> {
    admission.validate()?;
    let parameters = BTreeMap::from([(
        "admission".to_owned(),
        serde_json::to_value(admission)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::AdmitMailboxMessage,
        parameters,
    })
}

/// Decodes and validates one closed mailbox admission mutation.
pub fn decode_mailbox_item(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<MailboxItemAdmission, StoreError> {
    if operation != NamedMutationOperation::AdmitMailboxMessage {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let admission: MailboxItemAdmission =
        serde_json::from_value(parameters.get("admission").cloned().ok_or(
            StoreError::InvalidField {
                field: "mailbox.admission",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    admission.validate()?;
    Ok(admission)
}
