//! Kernel-owned canonical mailbox record (issue #1820, W1a).
//!
//! Architecture: I10.18 durable mailbox delivery. Directed coordination must
//! provide durable at-least-once delivery, recipient/task ordering, message-id
//! idempotency, and control acknowledgements when required. The shared envelope
//! owns identity, principals, timestamps, ordering, provenance,
//! privacy/disclosure, State Fence, and delivery receipts.
//!
//! This module is the Kernel-mechanical half of that contract: the record shape
//! ([`CoordinationMailboxRecord`]), the named idempotent admission
//! ([`admit_mailbox_message`], stable name
//! [`COORDINATION_MAILBOX_ADMIT_NAME`]) which validates the envelope and
//! assigns the per-recipient/per-task ordering key, the named read by identity
//! ([`read_mailbox_message`], stable name
//! [`COORDINATION_MAILBOX_READ_NAME`]), the delivery receipt
//! ([`record_mailbox_delivery`], stable name
//! [`COORDINATION_MAILBOX_DELIVER_NAME`]), the required control-message
//! acknowledgement handling ([`acknowledge_mailbox_message`], stable name
//! [`COORDINATION_MAILBOX_ACKNOWLEDGE_NAME`]), and the derived delivery-order
//! projection ([`project_mailbox_queue`]). Durability stays with the canonical
//! Store through the existing Store bridge; this module builds no scheduler,
//! task graph, subscription engine, or routing authority, keeps no rows, and
//! owns no lease.
//!
//! # Production chain
//!
//! The Store bridge slice calls [`admit_mailbox_message`] for every submitted
//! message before any delivery work starts, passing the already-known records
//! it read back through the Store bridge so a retried submission with a reused
//! identity replays the existing record as [`MailboxAdmission`] with
//! `replayed: true` instead of recording a second effect. The delivery path
//! calls [`record_mailbox_delivery`] against the admitted record, and the
//! control path calls [`acknowledge_mailbox_message`] for records admitted
//! with `requires_acknowledgement`. The stable `*_NAME` and `*_SCHEMA_V1`
//! constants are the exact keys those slices register on the Store bridge;
//! they are declared here so the names cannot drift between the Kernel surface
//! and the bridge registration.
//!
//! # What this deliberately does not do
//!
//! No `CoordinationMapView`, no large-payload handles, no route capabilities,
//! and no expiry/reassignment: those are later slices. A message admitted here
//! starts undelivered; every later delivery step is owned by the slice that
//! performs it.
//!
//! # Relation to the coordination record
//!
//! `eliot-coordination` already types the Governor-side peer channel
//! (peer envelopes, enqueue/delivery/ack receipts, obligations). That
//! vocabulary is Governor semantics, which the Kernel composition root must
//! not duplicate or interpret (`bins/AGENTS.md`). This record is the
//! Kernel-mechanical admission shape built only from foundation contracts
//! (`StateFence`, `TaskId`) and plain bounded text, following the `blackboard`
//! precedent: Kernel binds the message to its recipient/task, fence and
//! principals, while semantic meaning stays with the producing owner.

use eliot_contracts::{ContractError, StateFence, TaskId};
use serde::{Deserialize, Serialize};

/// Schema identifier for persisted mailbox records. The Store bridge slice
/// registers this exact key; the Kernel surface never mints a second one.
pub const COORDINATION_MAILBOX_SCHEMA_V1: &str = "eliot.coordination.mailbox.v1";
/// Stable named admission. The Store bridge slice registers this exact name
/// for mailbox admission.
pub const COORDINATION_MAILBOX_ADMIT_NAME: &str = "AdmitMailboxMessage";
/// Stable named read. The Store bridge slice registers this exact name for
/// exact-identity mailbox readback.
pub const COORDINATION_MAILBOX_READ_NAME: &str = "GetMailboxMessage";
/// Stable named delivery step. The delivery slice registers this exact name
/// when it records a delivery receipt against an admitted record.
pub const COORDINATION_MAILBOX_DELIVER_NAME: &str = "RecordMailboxDelivery";
/// Stable named acknowledgement step. The control slice registers this exact
/// name when it records a required control-message acknowledgement.
pub const COORDINATION_MAILBOX_ACKNOWLEDGE_NAME: &str = "AcknowledgeMailboxMessage";

/// Bound for every identity-shaped field: message, recipient, and principal text.
pub const MAX_IDENTITY_LEN: usize = 256;
/// Bound for the producer-supplied provenance handle.
pub const MAX_PROVENANCE_LEN: usize = 1024;
/// Bound for the producer-declared privacy class text.
pub const MAX_PRIVACY_LEN: usize = 128;
/// Bound for the producer-declared disclosure scope text.
pub const MAX_DISCLOSURE_LEN: usize = 256;
/// Bound for one inline message body, in bytes. This is the payload bound
/// shared with the durable mailbox; larger content travels by handle on a
/// later slice, never as an unbounded inline body here.
pub const MAX_MAILBOX_BODY_BYTES: usize = 65_536;

/// Typed mailbox-surface failures. Every rejection names its field and reason;
/// misses, conflicts, and unrequired acknowledgements name the exact identity.
#[derive(Clone, Debug)]
pub enum CoordinationMailboxError {
    /// A field failed admission bounds. No record was created.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The message identity is already known for a different recipient/task.
    /// No second record was created and the existing one was not returned,
    /// because the identity no longer names the same logical message.
    IdentityConflict {
        /// Exact identity that collided.
        message_id: String,
    },
    /// No record carries the requested identity.
    NotFound {
        /// Exact identity that was looked up.
        message_id: String,
    },
    /// The record does not require acknowledgement. No receipt was recorded.
    AcknowledgementNotRequired {
        /// Exact identity that was presented.
        message_id: String,
    },
    /// The carried State Fence failed its own owner validation.
    Foundation(ContractError),
}

impl std::fmt::Display for CoordinationMailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid mailbox message field {field}: {reason}")
            }
            Self::IdentityConflict { message_id } => {
                write!(f, "mailbox message identity conflict: {message_id}")
            }
            Self::NotFound { message_id } => {
                write!(f, "mailbox message not found: {message_id}")
            }
            Self::AcknowledgementNotRequired { message_id } => {
                write!(f, "mailbox message requires no acknowledgement: {message_id}")
            }
            Self::Foundation(error) => {
                write!(f, "mailbox message foundation contract: {error}")
            }
        }
    }
}

impl std::error::Error for CoordinationMailboxError {}

/// Unvalidated submission input for one directed message. `message_id` is the
/// exact idempotency identity: a retried submission reuses it, and admission
/// replays the existing record instead of recording a second effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessageDraft {
    /// Stable identity for the message across retries and redelivery.
    pub message_id: String,
    /// Addressable recipient identity spelled by the producer.
    pub recipient_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Producer-claimed sender principal, retained as opaque evidence. Kernel
    /// does not authenticate this binding; the admitting caller binds
    /// `submitter_principal` to the authenticated session.
    pub sender_principal: String,
    /// Authenticated submitting principal bound by the admitting caller.
    pub submitter_principal: String,
    /// Producer-supplied origin handle. The Kernel retains this evidence but
    /// does not authenticate its provenance.
    pub provenance: String,
    /// Producer-declared privacy class, retained opaquely. Interpretation
    /// stays with the owning consumer, never with admission.
    pub privacy_class: String,
    /// Producer-declared disclosure scope, retained opaquely.
    pub disclosure: String,
    /// Inline message body. Bounded by [`MAX_MAILBOX_BODY_BYTES`]; larger
    /// content travels by handle on a later slice.
    pub body: String,
    /// Whether the recipient must acknowledge this control message. Plain
    /// informs leave this false; the control slice records the required
    /// acknowledgement through [`acknowledge_mailbox_message`].
    pub requires_acknowledgement: bool,
    /// Fence at which the message was admitted.
    pub state_fence: StateFence,
    /// Producer-observed submission time, Unix milliseconds, never zero.
    pub submitted_at_unix_ms: u64,
}

/// The Kernel-owned canonical mailbox record. Immutable after admission; the
/// delivery and control slices observe it through receipts, never by mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationMailboxRecord {
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
    /// Producer-supplied origin handle.
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
    /// Producer-observed submission time, Unix milliseconds.
    pub submitted_at_unix_ms: u64,
    /// Per-recipient/per-task ordering key assigned at admission. The first
    /// message for a recipient/task pair carries 1; every later message
    /// carries one more than the highest key already known for that pair.
    pub sequence: u64,
}

/// Admission outcome (`AdmitMailboxMessage`).
///
/// A fresh identity yields the newly admitted record with `replayed: false`. A
/// reused identity yields the already-known record with `replayed: true` and
/// produces no second effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAdmission {
    /// The admitted record, new or replayed.
    pub record: CoordinationMailboxRecord,
    /// True when the identity was already known and no new record was created.
    pub replayed: bool,
}

/// Delivery receipt for one admitted record (`RecordMailboxDelivery`).
///
/// One receipt exists per admitted message: recording delivery twice replays
/// the existing receipt instead of recording a second delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDeliveryReceipt {
    /// Identity of the delivered message.
    pub message_id: String,
    /// Ordering key of the delivered record.
    pub sequence: u64,
    /// Producer-observed delivery time, Unix milliseconds.
    pub delivered_at_unix_ms: u64,
    /// True when delivery was already recorded and this is the replay.
    pub replayed: bool,
}

/// Control-message acknowledgement (`AcknowledgeMailboxMessage`).
///
/// One acknowledgement exists per (message, principal) pair: the same
/// principal acknowledging twice replays the existing acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAcknowledgement {
    /// Identity of the acknowledged message.
    pub message_id: String,
    /// Principal that acknowledged, bound by the recording caller.
    pub acknowledged_by: String,
    /// Producer-observed acknowledgement time, Unix milliseconds.
    pub acknowledged_at_unix_ms: u64,
    /// True when this principal already acknowledged and this is the replay.
    pub replayed: bool,
}

/// Derived delivery-order projection for one recipient/task pair. This is a
/// pure view over already-known records ordered by their admission sequence,
/// never a scheduler, subscription engine, or routing authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxQueue {
    /// Recipient this projection was derived for.
    pub recipient_id: String,
    /// Task this projection was derived for.
    pub task_id: TaskId,
    /// Known records for the pair ordered by `(sequence, message_id)`.
    pub queued: Vec<CoordinationMailboxRecord>,
}

/// Named admission (`AdmitMailboxMessage`).
///
/// Validates the draft's envelope, replays the already-known record when
/// `message_id` is already present, and otherwise returns the canonical record
/// with the next per-recipient/per-task ordering key. `existing` is the
/// caller-read-back record view (the Store bridge readback in production);
/// this function stores nothing itself.
pub fn admit_mailbox_message(
    draft: MailboxMessageDraft,
    existing: &[CoordinationMailboxRecord],
) -> Result<MailboxAdmission, CoordinationMailboxError> {
    validate_mailbox_draft(&draft)?;
    if let Some(known) = existing
        .iter()
        .find(|record| record.message_id == draft.message_id)
    {
        if !draft_matches_record(&draft, known) {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: draft.message_id,
            });
        }
        return Ok(MailboxAdmission {
            record: known.clone(),
            replayed: true,
        });
    }
    let sequence = next_sequence(existing, &draft.recipient_id, &draft.task_id)?;
    Ok(MailboxAdmission {
        record: CoordinationMailboxRecord {
            message_id: draft.message_id,
            recipient_id: draft.recipient_id,
            task_id: draft.task_id,
            sender_principal: draft.sender_principal,
            submitter_principal: draft.submitter_principal,
            provenance: draft.provenance,
            privacy_class: draft.privacy_class,
            disclosure: draft.disclosure,
            body: draft.body,
            requires_acknowledgement: draft.requires_acknowledgement,
            state_fence: draft.state_fence,
            submitted_at_unix_ms: draft.submitted_at_unix_ms,
            sequence,
        },
        replayed: false,
    })
}

/// Named read by identity (`GetMailboxMessage`).
///
/// Returns the exact record carrying `message_id`, or
/// [`CoordinationMailboxError::NotFound`]. The caller supplies the read-back
/// view; this function interprets nothing beyond identity.
pub fn read_mailbox_message<'a>(
    messages: &'a [CoordinationMailboxRecord],
    message_id: &str,
) -> Result<&'a CoordinationMailboxRecord, CoordinationMailboxError> {
    require_text(message_id, "message_id", MAX_IDENTITY_LEN)?;
    messages
        .iter()
        .find(|record| record.message_id == message_id)
        .ok_or_else(|| CoordinationMailboxError::NotFound {
            message_id: message_id.to_owned(),
        })
}

/// Derives the delivery order for one recipient/task pair.
///
/// The projection holds the pair's known records ordered by
/// `(sequence, message_id)`, so two distinct messages admitted in order are
/// delivered in that order. Records for any other recipient or task never
/// join this projection.
pub fn project_mailbox_queue(
    messages: &[CoordinationMailboxRecord],
    recipient_id: &str,
    task_id: &TaskId,
) -> Result<MailboxQueue, CoordinationMailboxError> {
    require_text(recipient_id, "recipient_id", MAX_IDENTITY_LEN)?;
    let mut queued: Vec<CoordinationMailboxRecord> = messages
        .iter()
        .filter(|record| record.recipient_id == recipient_id && record.task_id == *task_id)
        .cloned()
        .collect();
    queued.sort_by(|a, b| (a.sequence, &a.message_id).cmp(&(b.sequence, &b.message_id)));
    Ok(MailboxQueue {
        recipient_id: recipient_id.to_owned(),
        task_id: task_id.clone(),
        queued,
    })
}

/// Records delivery of one admitted record (`RecordMailboxDelivery`).
///
/// Returns the existing receipt with `replayed: true` when delivery of this
/// message was already recorded; otherwise returns the fresh receipt.
/// `existing` is the caller-read-back receipt view; this function stores
/// nothing itself.
pub fn record_mailbox_delivery(
    record: &CoordinationMailboxRecord,
    existing: &[MailboxDeliveryReceipt],
    delivered_at_unix_ms: u64,
) -> Result<MailboxDeliveryReceipt, CoordinationMailboxError> {
    if let Some(known) = existing
        .iter()
        .find(|receipt| receipt.message_id == record.message_id)
    {
        return Ok(MailboxDeliveryReceipt {
            replayed: true,
            ..known.clone()
        });
    }
    require_timestamp(delivered_at_unix_ms, "delivered_at_unix_ms")?;
    Ok(MailboxDeliveryReceipt {
        message_id: record.message_id.clone(),
        sequence: record.sequence,
        delivered_at_unix_ms,
        replayed: false,
    })
}

/// Records a required control-message acknowledgement
/// (`AcknowledgeMailboxMessage`).
///
/// Refuses with [`CoordinationMailboxError::AcknowledgementNotRequired`] when
/// the record was admitted without `requires_acknowledgement`, and replays
/// the existing acknowledgement when this principal already acknowledged.
/// `existing` is the caller-read-back acknowledgement view; this function
/// stores nothing itself.
pub fn acknowledge_mailbox_message(
    record: &CoordinationMailboxRecord,
    existing: &[MailboxAcknowledgement],
    acknowledged_by: &str,
    acknowledged_at_unix_ms: u64,
) -> Result<MailboxAcknowledgement, CoordinationMailboxError> {
    if !record.requires_acknowledgement {
        return Err(CoordinationMailboxError::AcknowledgementNotRequired {
            message_id: record.message_id.clone(),
        });
    }
    require_text(acknowledged_by, "acknowledged_by", MAX_IDENTITY_LEN)?;;
    if let Some(known) = existing.iter().find(|acknowledgement| {
        acknowledgement.message_id == record.message_id
            && acknowledgement.acknowledged_by == acknowledged_by
    }) {
        return Ok(MailboxAcknowledgement {
            replayed: true,
            ..known.clone()
        });
    }
    require_timestamp(acknowledged_at_unix_ms, "acknowledged_at_unix_ms")?;
    Ok(MailboxAcknowledgement {
        message_id: record.message_id.clone(),
        acknowledged_by: acknowledged_by.to_owned(),
        acknowledged_at_unix_ms,
        replayed: false,
    })
}

/// Validates every draft field: identities, task, principals, provenance,
/// privacy/disclosure, body, fence, and timestamp.
fn validate_mailbox_draft(draft: &MailboxMessageDraft) -> Result<(), CoordinationMailboxError> {
    require_text(&draft.message_id, "message_id", MAX_IDENTITY_LEN)?;
    require_text(&draft.recipient_id, "recipient_id", MAX_IDENTITY_LEN)?;
    require_text(&draft.sender_principal, "sender_principal", MAX_IDENTITY_LEN)?;
    require_text(&draft.submitter_principal, "submitter_principal", MAX_IDENTITY_LEN)?;;
    require_text(&draft.provenance, "provenance", MAX_PROVENANCE_LEN)?;
    require_text(&draft.privacy_class, "privacy_class", MAX_PRIVACY_LEN)?;
    require_text(&draft.disclosure, "disclosure", MAX_DISCLOSURE_LEN)?;
    if draft.body.len() > MAX_MAILBOX_BODY_BYTES {
        return Err(CoordinationMailboxError::InvalidField {
            field: "body",
            reason: "exceeds admission bound",
        });
    }
    if draft.body.chars().any(char::is_control) {
        return Err(CoordinationMailboxError::InvalidField {
            field: "body",
            reason: "blank or control character",
        });
    }
    draft
        .state_fence
        .validate()
        .map_err(CoordinationMailboxError::Foundation)?;
    require_timestamp(draft.submitted_at_unix_ms, "submitted_at_unix_ms")?;
    Ok(())
}

/// Whether a redrafted submission still names the same logical message as the
/// known record. A reused identity with a different recipient, task, sender,
/// provenance, privacy, body, acknowledgement duty, timestamp, or fence is an
/// identity conflict, never a silent replay.
fn draft_matches_record(
    draft: &MailboxMessageDraft,
    record: &CoordinationMailboxRecord,
) -> bool {
    draft.recipient_id == record.recipient_id
        && draft.task_id == record.task_id
        && draft.sender_principal == record.sender_principal
        && draft.submitter_principal == record.submitter_principal
        && draft.provenance == record.provenance
        && draft.privacy_class == record.privacy_class
        && draft.disclosure == record.disclosure
        && draft.body == record.body
        && draft.requires_acknowledgement == record.requires_acknowledgement
        && draft.submitted_at_unix_ms == record.submitted_at_unix_ms
        && draft.state_fence == record.state_fence
}

/// Assigns the next per-recipient/per-task ordering key: one more than the
/// highest key already known for the pair, starting at 1.
fn next_sequence(
    existing: &[CoordinationMailboxRecord],
    recipient_id: &str,
    task_id: &TaskId,
) -> Result<u64, CoordinationMailboxError> {
    let highest = existing
        .iter()
        .filter(|record| record.recipient_id == recipient_id && record.task_id == *task_id)
        .map(|record| record.sequence)
        .max();
    match highest {
        None => Ok(1),
        Some(sequence) => sequence.checked_add(1).ok_or(CoordinationMailboxError::InvalidField {
            field: "sequence",
            reason: "sequence overflow",
        }),
    }
}

/// Requires bounded, non-blank text with no control characters, mirroring the
/// Store owner's text rule plus an admission length bound.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), CoordinationMailboxError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoordinationMailboxError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(CoordinationMailboxError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires a producer-observed time that was actually observed, never zero.
fn require_timestamp(value: u64, field: &'static str) -> Result<(), CoordinationMailboxError> {
    if value == 0 {
        return Err(CoordinationMailboxError::InvalidField {
            field,
            reason: "must carry the producer-observed time, never zero",
        });
    }
    Ok(())
}
