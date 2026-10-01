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
//! [`COORDINATION_MAILBOX_ACKNOWLEDGE_NAME`]), the derived delivery-order
//! projection ([`project_mailbox_queue`]), and the rebuildable coordination
//! map ([`rebuild_coordination_map_view`], stable name
//! [`COORDINATION_MAP_VIEW_NAME`]). Durability stays with the canonical
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
//! with `requires_acknowledgement`. The route/delivery slice calls
//! [`rebuild_coordination_map_view`] under [`COORDINATION_MAP_VIEW_NAME`]
//! before resolving recipients: it rebuilds the map from the frozen plan/wave
//! revision pair plus the current assignments, resolves the attempt/work-item
//! recipient through [`CoordinationMapView::resolve_recipient`], and delivers
//! through that entry's queue. Every entry queue is the
//! [`project_mailbox_queue`] projection of the already-known records; the
//! view carries no rows of its own. The stable `*_NAME` and `*_SCHEMA_V1`
//! constants are the exact keys those slices register on the Store bridge;
//! they are declared here so the names cannot drift between the Kernel surface
//! and the bridge registration.
//!
//! # What this deliberately does not do
//!
//! No large-payload handles, no route capabilities, and no expiry/reassignment:
//! those are later slices. A message admitted here starts undelivered; every
//! later delivery step is owned by the slice that performs it.
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
                write!(
                    f,
                    "mailbox message requires no acknowledgement: {message_id}"
                )
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
    require_text(acknowledged_by, "acknowledged_by", MAX_IDENTITY_LEN)?;
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
    require_text(
        &draft.sender_principal,
        "sender_principal",
        MAX_IDENTITY_LEN,
    )?;
    require_text(
        &draft.submitter_principal,
        "submitter_principal",
        MAX_IDENTITY_LEN,
    )?;
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
fn draft_matches_record(draft: &MailboxMessageDraft, record: &CoordinationMailboxRecord) -> bool {
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
        Some(sequence) => sequence
            .checked_add(1)
            .ok_or(CoordinationMailboxError::InvalidField {
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

// ============================================================================
// Derived coordination map view (issue #1820, map-view slice).
//
// The view is rebuilt strictly from one frozen plan/wave revision pair plus
// the current assignments, over the already-known mailbox records: it admits
// no rows, runs no scheduler, keeps no subscription state, and grants no
// routing authority. Each entry pairs one assignment with the delivery-order
// projection for its initial recipient (the assigned attempt when the work
// item is currently assigned, else the work item itself), derived through
// [`project_mailbox_queue`], so the queue a recipient routes to is exactly
// the queue admission order already defines. Typed failures stay typed:
// every rejection is a [`CoordinationMailboxError`].
//
// Out of scope here: large-payload handles, route capabilities, and
// expiry/reassignment (later slices).
// ============================================================================

/// Schema identifier for a rebuilt coordination map. The route/delivery slice
/// binds this exact key to the view it rebuilt; the Kernel surface never mints
/// a second one.
pub const COORDINATION_MAP_VIEW_SCHEMA_V1: &str = "eliot.coordination.map_view.v1";
/// Stable named rebuild. The route/delivery slice calls
/// [`rebuild_coordination_map_view`] under this exact name before resolving
/// recipients.
pub const COORDINATION_MAP_VIEW_NAME: &str = "RebuildCoordinationMapView";

/// One current assignment the map is rebuilt from. `work_item_id` is the
/// addressable work-item identity spelled by the producing owner;
/// `assigned_attempt_id` names the attempt currently holding it, when any.
/// Both spellings stay in the record's text-plus-`TaskId` scheme: no second
/// identity scheme is introduced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapAssignment {
    /// Addressable work-item identity spelled by the producing owner.
    pub work_item_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Attempt currently holding the work item, if assigned.
    pub assigned_attempt_id: Option<String>,
}

/// Addressable recipient from the rebuilt map: exactly one of an assigned
/// attempt or an unassigned work item. This is the initial-routing spelling
/// the route/delivery slice resolves before delivering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapRecipient {
    /// Explicit attempt recipient, if assigned.
    pub attempt_id: Option<String>,
    /// Explicit work-item recipient, if not yet assigned.
    pub work_item_id: Option<String>,
}

impl MapRecipient {
    /// Creates an attempt recipient.
    pub fn attempt(id: String) -> Self {
        Self {
            attempt_id: Some(id),
            work_item_id: None,
        }
    }
    /// Creates a work-item recipient.
    pub fn work_item(id: String) -> Self {
        Self {
            attempt_id: None,
            work_item_id: Some(id),
        }
    }
    /// Requires exactly one of attempt or work item. Called by
    /// [`CoordinationMapView::resolve_recipient`]; there is no other caller.
    fn validate(&self) -> Result<(), CoordinationMailboxError> {
        if self.attempt_id.is_none() == self.work_item_id.is_none() {
            return Err(CoordinationMailboxError::InvalidField {
                field: "recipient",
                reason: "must name exactly one of attempt or work item",
            });
        }
        Ok(())
    }
}

/// One entry in the rebuilt coordination map: one assignment plus the
/// delivery-order projection for its initial recipient. The queue's
/// `recipient_id` names that initial recipient (the assigned attempt when
/// present, else the work item), so the routing decision is explicit in the
/// derived data, never recomputed by the consumer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationMapEntry {
    /// Work item this entry was rebuilt for.
    pub work_item_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Attempt currently holding the work item, if assigned.
    pub assigned_attempt_id: Option<String>,
    /// Known records for the initial recipient ordered by
    /// `(sequence, message_id)`.
    pub queue: MailboxQueue,
}

/// Derived recipient-addressing view. It carries the frozen revision pair it
/// was rebuilt from and owns no plan state: it cannot mutate assignments,
/// grant routing authority, or schedule delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationMapView {
    /// Frozen plan revision the view was rebuilt from.
    pub plan_revision: String,
    /// Frozen wave revision the view was rebuilt from.
    pub wave_revision: String,
    /// One entry per assignment, in assignment order.
    pub entries: Vec<CoordinationMapEntry>,
}

impl CoordinationMapView {
    /// Returns the exact entry for an attempt/work-item recipient, or a typed
    /// failure. An attempt matches only the entry currently assigned to it; a
    /// work item matches only its own entry. Anything else names a recipient
    /// that is not present in this frozen map.
    pub fn resolve_recipient(
        &self,
        recipient: &MapRecipient,
    ) -> Result<&CoordinationMapEntry, CoordinationMailboxError> {
        recipient.validate()?;
        self.entries
            .iter()
            .find(|entry| {
                let by_work_item = recipient
                    .work_item_id
                    .as_ref()
                    .is_some_and(|id| *id == entry.work_item_id);
                let by_attempt = recipient
                    .attempt_id
                    .as_ref()
                    .is_some_and(|id| entry.assigned_attempt_id.as_ref() == Some(id));
                by_work_item || by_attempt
            })
            .ok_or(CoordinationMailboxError::InvalidField {
                field: "recipient",
                reason: "not present in the frozen coordination map",
            })
    }
}

/// Named rebuild (`RebuildCoordinationMapView`).
///
/// Derives the view strictly from the frozen plan/wave revision pair plus the
/// current assignments, over the caller-read-back records (the Store bridge
/// readback in production); this function stores nothing itself. Each entry's
/// queue is the [`project_mailbox_queue`] projection for the entry's initial
/// recipient, so typed queue failures propagate unchanged. A repeated
/// (work item, task) assignment is a typed rejection, never a silent
/// first-match: the map must route every recipient explicitly.
pub fn rebuild_coordination_map_view(
    plan_revision: &str,
    wave_revision: &str,
    assignments: &[MapAssignment],
    messages: &[CoordinationMailboxRecord],
) -> Result<CoordinationMapView, CoordinationMailboxError> {
    require_text(plan_revision, "plan_revision", MAX_IDENTITY_LEN)?;
    require_text(wave_revision, "wave_revision", MAX_IDENTITY_LEN)?;
    let mut entries: Vec<CoordinationMapEntry> = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        require_text(&assignment.work_item_id, "work_item_id", MAX_IDENTITY_LEN)?;
        if let Some(attempt_id) = assignment.assigned_attempt_id.as_deref() {
            require_text(attempt_id, "assigned_attempt_id", MAX_IDENTITY_LEN)?;
        }
        if entries.iter().any(|entry| {
            entry.work_item_id == assignment.work_item_id && entry.task_id == assignment.task_id
        }) {
            return Err(CoordinationMailboxError::InvalidField {
                field: "assignments",
                reason: "duplicate assignment",
            });
        }
        let initial = assignment
            .assigned_attempt_id
            .as_deref()
            .unwrap_or(assignment.work_item_id.as_str());
        entries.push(CoordinationMapEntry {
            work_item_id: assignment.work_item_id.clone(),
            task_id: assignment.task_id.clone(),
            assigned_attempt_id: assignment.assigned_attempt_id.clone(),
            queue: project_mailbox_queue(messages, initial, &assignment.task_id)?,
        });
    }
    Ok(CoordinationMapView {
        plan_revision: plan_revision.to_owned(),
        wave_revision: wave_revision.to_owned(),
        entries,
    })
}
// Large-payload handles (issue #1820, payload-handles slice W4).
//
// Large content never travels as inline bytes above the shared bound:
// [`MAX_MAILBOX_BODY_BYTES`] still caps every admitted `body`, and a handle
// carries only the artifact locator, the content digest, and the byte bound.
// The record stays immutable after admission; attachment is a separate durable
// row keyed by the message identity, attached and detached by identity.
//
// The owner seam is `eliot-artifact` (`ArtifactOwner::read` through the
// injected `ArtifactBlobReader` around the one `BlobStoreClient` owner, plus
// `ArtifactReference`/`ArtifactIdentity`/`ContentAddress` for the
// locator-plus-digest shape). The Kernel handle reuses only foundation types
// (`ArtifactId` from `eliot-contracts`, plain bounded text, `u64` bound) and
// never mints a second identity scheme: the Governor `payload_handle` text in
// `eliot-coordination` is Governor semantics and is not interpreted here.
//
// Production chain: the Store bridge / delivery slice reads the bytes through
// the artifact owner, then calls [`resolve_mailbox_payload_handle`] with the
// owner-supplied bytes for the pure digest-plus-length check. That read lives
// in the bridge/dispatch seam outside this file, so the production caller is
// STITCH. Typed failures stay typed: every rejection is a
// [`CoordinationMailboxError`].
//
// Out of scope here: map view, route capabilities, and expiry/reassignment
// (other slices).
// ============================================================================

/// Large-payload handle for one message whose content exceeds the inline
/// bound. Carries the artifact locator, the content digest, and the byte
/// bound; it never carries payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxPayloadHandle {
    /// Immutable artifact identity bound by the producing owner (foundation
    /// type, no second scheme).
    pub artifact_id: eliot_contracts::ArtifactId,
    /// Opaque artifact locator issued by the owning store. Bounded like
    /// provenance: retained opaquely, never interpreted here.
    pub locator: String,
    /// Lowercase SHA-256 hex digest of the exact payload bytes.
    pub content_digest: String,
    /// Exact payload length in bytes. Always above [`MAX_MAILBOX_BODY_BYTES`]:
    /// content that fits inline travels inline, never by handle.
    pub byte_len: u64,
}

/// Durable attachment of one handle to one admitted message, keyed by the
/// message identity. The attachment carries the handle only, never payload
/// bytes, so a stored row cannot duplicate the artifact content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxPayloadAttachment {
    /// Identity of the admitted message this handle is attached to.
    pub message_id: String,
    /// The attached handle.
    pub handle: MailboxPayloadHandle,
}

/// Attaches a large-payload handle to one admitted message, by identity.
///
/// The message must already be admitted; `existing` is the caller-read-back
/// attachment view (the Store bridge readback in production) and this
/// function stores nothing itself. A reused identity with the identical
/// handle replays the existing attachment with no second effect; a reused
/// identity with a different handle is an identity conflict, never a silent
/// overwrite.
pub fn attach_mailbox_payload_handle(
    messages: &[CoordinationMailboxRecord],
    existing: &[MailboxPayloadAttachment],
    message_id: &str,
    handle: MailboxPayloadHandle,
) -> Result<MailboxPayloadAttachment, CoordinationMailboxError> {
    require_text(message_id, "message_id", MAX_IDENTITY_LEN)?;
    if !messages
        .iter()
        .any(|record| record.message_id == message_id)
    {
        return Err(CoordinationMailboxError::NotFound {
            message_id: message_id.to_owned(),
        });
    }
    validate_payload_handle(&handle)?;
    if let Some(known) = existing
        .iter()
        .find(|attachment| attachment.message_id == message_id)
    {
        if known.handle != handle {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: message_id.to_owned(),
            });
        }
        return Ok(known.clone());
    }
    Ok(MailboxPayloadAttachment {
        message_id: message_id.to_owned(),
        handle,
    })
}

/// Detaches the handle attached to one message, by identity.
///
/// Returns the removed attachment view so the caller drops exactly the row
/// it read back; this function stores nothing itself.
pub fn detach_mailbox_payload_handle(
    existing: &[MailboxPayloadAttachment],
    message_id: &str,
) -> Result<MailboxPayloadAttachment, CoordinationMailboxError> {
    require_text(message_id, "message_id", MAX_IDENTITY_LEN)?;
    existing
        .iter()
        .find(|attachment| attachment.message_id == message_id)
        .cloned()
        .ok_or_else(|| CoordinationMailboxError::NotFound {
            message_id: message_id.to_owned(),
        })
}

/// Resolves a handle to the owner-supplied bytes.
///
/// `bytes` are the exact bytes the production caller read through the
/// artifact owner (`ArtifactOwner::read` via the injected
/// `ArtifactBlobReader`); this function verifies length and digest and
/// returns the same slice, never a copy beside the handle. Mismatches are
/// typed rejections, never silent truncation.
pub fn resolve_mailbox_payload_handle<'a>(
    handle: &MailboxPayloadHandle,
    bytes: &'a [u8],
) -> Result<&'a [u8], CoordinationMailboxError> {
    validate_payload_handle(handle)?;
    if bytes.len() as u64 != handle.byte_len {
        return Err(CoordinationMailboxError::InvalidField {
            field: "payload",
            reason: "length mismatch",
        });
    }
    if eliot_contracts::sha256_hex(bytes) != handle.content_digest {
        return Err(CoordinationMailboxError::InvalidField {
            field: "payload",
            reason: "digest mismatch",
        });
    }
    Ok(bytes)
}

/// Validates one handle: opaque locator bound, digest shape, and the shared
/// inline-bound ceiling (handles are only for content above it).
fn validate_payload_handle(handle: &MailboxPayloadHandle) -> Result<(), CoordinationMailboxError> {
    require_text(&handle.locator, "locator", MAX_PROVENANCE_LEN)?;
    require_payload_digest(&handle.content_digest)?;
    if handle.byte_len <= MAX_MAILBOX_BODY_BYTES as u64 {
        return Err(CoordinationMailboxError::InvalidField {
            field: "byte_len",
            reason: "must exceed the inline admission bound",
        });
    }
    Ok(())
}

/// Requires a lowercase SHA-256 hex digest, matching the artifact owner's
/// digest shape without importing its error type.
fn require_payload_digest(value: &str) -> Result<(), CoordinationMailboxError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CoordinationMailboxError::InvalidField {
            field: "content_digest",
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

// ============================================================================
// Anchored review items (issue #1823, review slice W1a: W6/A1/A2/A4).
//
// I10.18 durable review coordination under the existing coordination/attention
// path: this module is the Kernel-mechanical half. It admits one review item
// per idempotency identity with its own independent lifecycle, derives batch
// envelopes over submitted-together items without giving the batch a
// lifecycle of its own, retains an ambiguous anchor as an explicitly
// ambiguous unattached status, classifies real blockers and hands them to
// the existing Problem/Conflict/Critical-Attention owner, and carries a
// RequestedChange candidate to the normal owner/effect/verifier path without
// granting any direct write.
//
// The closed vocabularies below mirror the existing owners instead of
// inventing a second scheme: target kinds, review kinds, and lifecycles match
// `eliot-coordination` (`ReviewTargetKind`, `ReviewKind`,
// `PeerReviewLifecycle`) and `eliot-agent-contracts` (`ReviewLifecycle`,
// `ReviewKind`); anchor statuses match the I10.21 seven-status vocabulary
// produced by `eliot-change-monitor` (`resolve_anchored_review`). The Kernel
// retains the producer's spellings and binds them to task, fence, and
// principals; semantic meaning stays with the producing owner, following the
// mailbox precedent above. No Governor or problem-owner crate is imported: a
// `bins` root never depends on Governor crates.
//
// Production chain (STITCH):
//
// - the Store bridge slice calls [`admit_review_item`] /
//   [`admit_review_batch`] with the caller-read-back record view, then stores
//   the returned records; a retried submission replays instead of duplicating;
// - the delivery/answer slice calls [`advance_review_item`] against the
//   stored record; the returned record replaces it under its own identity;
// - the observation slice calls [`observe_review_batch`] over the stored
//   records to report every item's own disposition;
// - the Governor coordination owner consumes admitted records through its own
//   `submit_peer_review` / `advance_peer_review` tables, which these
//   transitions mirror; the resolver supplies `anchor_status` from its
//   `AnchorResolutionObservation`;
// - the Problem/Conflict/Critical-Attention owner consumes
//   [`ReviewBlockerEscalation`] rows produced by
//   [`escalate_review_blocker`];
// - the normal effect owner consumes [`RequestedChangeCandidate`] rows
//   produced by [`submit_requested_change`] through its own admission, and
//   the verifier binds them through its own evidence path.
//
// What this deliberately does not do:
//
// - no current-target resolution: the record carries the resolver-supplied
//   `anchor_status` and no current-target field exists, so an ambiguous item
//   can never be attached to a similar fragment here;
// - no second problem system: escalation names one of the three existing
//   owners and carries evidence only;
// - no direct write: the requested-change candidate carries no effect field,
//   and no function converts it into one.
// ============================================================================

/// Schema identifier for persisted review rows. The Store bridge slice
/// registers this exact key; the Kernel surface never mints a second one.
pub const COORDINATION_REVIEW_SCHEMA_V1: &str = "eliot.coordination.review.v1";
/// Stable named admission for one review item.
pub const COORDINATION_REVIEW_ADMIT_NAME: &str = "AdmitReviewItem";
/// Stable named admission for one derived batch envelope.
pub const COORDINATION_REVIEW_BATCH_ADMIT_NAME: &str = "AdmitReviewBatch";
/// Stable named lifecycle advance for one review item.
pub const COORDINATION_REVIEW_ADVANCE_NAME: &str = "AdvanceReviewItem";
/// Stable named batch observation.
pub const COORDINATION_REVIEW_OBSERVE_NAME: &str = "ObserveReviewBatch";
/// Stable named blocker escalation.
pub const COORDINATION_REVIEW_ESCALATE_NAME: &str = "EscalateReviewBlocker";
/// Stable named requested-change submission.
pub const COORDINATION_REVIEW_CHANGE_SUBMIT_NAME: &str = "SubmitRequestedChange";

/// Bound for one review body, in bytes. Shared with the durable mailbox and
/// the contract delta bound; larger content travels by handle, never inline.
pub const MAX_REVIEW_CONTENT_BYTES: usize = 65_536;
/// Bound for each response/change/verifier reference list. Shared with the
/// contract reference bound.
pub const MAX_REVIEW_REFS: usize = 16;
/// Bound for a rejection or escalation reason.
pub const MAX_REVIEW_REASON_LEN: usize = 1024;

/// Closed review target vocabulary (I10.18). Mirrors the existing owner
/// vocabularies; hidden reasoning is not expressible here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewTargetKind {
    PublicMessage,
    PublicPlan,
    PublicRationale,
    ToolResult,
    Diff,
    Source,
    VerifierResult,
}

/// Closed review kind vocabulary (I10.18). `RequestedChange` is a candidate
/// kind: it takes effect solely through the normal owner, effect, and
/// verifier paths, never through the review record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    Question,
    Correction,
    Objection,
    RequestedChange,
    MissingEvidence,
    ScopeIssue,
    AcceptanceIssue,
}

/// Review lifecycle (I10.18). Resolution stays distinct from acknowledgement
/// and delivery; the batch envelope below carries no lifecycle of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLifecycle {
    Draft,
    PendingDelivery,
    Delivered,
    Answered,
    Resolved,
    RejectedWithReason,
    Stale,
    Superseded,
}

/// Anchor status at submit time (I10.21 seven-status vocabulary). This is the
/// resolver-supplied claim retained verbatim: the Kernel never recomputes it
/// and never attaches an ambiguous item to a similar fragment, because no
/// current-target field exists on the record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAnchorStatus {
    Exact,
    Moved,
    Modified,
    Ambiguous,
    Stale,
    Deleted,
    Unavailable,
}

impl ReviewAnchorStatus {
    /// Whether this status may back a resolution. Only an attached status
    /// resolves: an ambiguous, stale, deleted, or unavailable anchor stays
    /// retained but never counts as resolved. Mirrors the existing owner
    /// `satisfies_required_review` rule without re-typing it.
    #[must_use]
    pub const fn supports_resolution(self) -> bool {
        match self {
            Self::Exact | Self::Moved | Self::Modified => true,
            Self::Ambiguous | Self::Stale | Self::Deleted | Self::Unavailable => false,
        }
    }
}

impl ReviewLifecycle {
    /// Whether the item is still open. Only an open item can block a target
    /// (W6) or advance along the answer path.
    #[must_use]
    pub const fn is_open(self) -> bool {
        match self {
            Self::PendingDelivery | Self::Delivered | Self::Answered => true,
            Self::Draft
            | Self::Resolved
            | Self::RejectedWithReason
            | Self::Stale
            | Self::Superseded => false,
        }
    }

    /// Whether the item reached a recorded disposition. Delivery,
    /// acknowledgement, and answering are not dispositions: only an explicit
    /// resolution or a rejection carrying its reason closes the obligation,
    /// so one answered review never discharges a batch (A1).
    #[must_use]
    pub const fn is_disposed(self) -> bool {
        matches!(
            self,
            Self::Resolved | Self::RejectedWithReason
        )
    }
}

/// Lifecycle advance for one review item. Mirrors the union of the existing
/// owner transition tables: rejection always requires a reason, and
/// resolution is distinct from answering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAdvance {
    Deliver,
    Answer,
    Resolve,
    RejectWithReason,
    MarkStale,
    MarkSuperseded,
}

/// The existing owner a real blocker escalates to (W6). These name the one
/// Problem/Conflict/Critical-Attention ownership the issue already has; the
/// escalation carries evidence to it and creates no second problem system.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewEscalationOwner {
    Problem,
    Conflict,
    CriticalAttention,
}

/// Unvalidated submission input for one anchored review item.
/// `review_item_id` is the exact idempotency identity: a retried submission
/// reuses it, and admission replays the existing record instead of recording
/// a second effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemDraft {
    /// Stable identity for the item across retries and redelivery.
    pub review_item_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Producer-claimed author principal, retained as opaque evidence. Kernel
    /// does not authenticate this binding; the admitting caller binds
    /// `submitter_principal` to the authenticated session.
    pub author_principal: String,
    /// Authenticated submitting principal bound by the admitting caller.
    pub submitter_principal: String,
    /// Exact public target kind under review.
    pub target_kind: ReviewTargetKind,
    /// Immutable original target revision, retained verbatim and never
    /// rewritten. The Kernel does not interpret it.
    pub original_target_revision: String,
    /// Immutable original anchor selector, retained verbatim and never
    /// rewritten. The Kernel does not interpret it.
    pub original_target_anchor: String,
    /// Review kind exactly as authored.
    pub kind: ReviewKind,
    /// Review body exactly as authored.
    pub content: String,
    /// Response references bound at submit. Typed public handles retained
    /// opaquely; they grant no write, effect, goal, or acceptance authority.
    pub response_refs: Vec<String>,
    /// Requested-change references bound at submit. Candidates only: they
    /// take effect solely through the normal owner, effect, and verifier
    /// paths, never through this record.
    pub change_refs: Vec<String>,
    /// Verifier-result references bound at submit. Evidence handles only,
    /// never verifier authority.
    pub verifier_refs: Vec<String>,
    /// Resolver-supplied anchor status retained verbatim. `Ambiguous` is
    /// admitted and retained as explicitly ambiguous, never refused and
    /// never attached to a similar fragment (A2).
    pub anchor_status: ReviewAnchorStatus,
    /// Fence at which the item was admitted.
    pub state_fence: StateFence,
    /// Producer-observed submission time, Unix milliseconds, never zero.
    pub submitted_at_unix_ms: u64,
}

/// The Kernel-owned canonical review-item record. The original revision and
/// anchor are immutable after admission; the lifecycle advances only through
/// [`advance_review_item`], one item at a time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemRecord {
    /// Stable identity for the item across retries and redelivery.
    pub review_item_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Producer-claimed author principal, retained as opaque evidence.
    pub author_principal: String,
    /// Authenticated submitting principal bound by the admitting caller.
    pub submitter_principal: String,
    /// Exact public target kind under review.
    pub target_kind: ReviewTargetKind,
    /// Immutable original target revision.
    pub original_target_revision: String,
    /// Immutable original anchor selector.
    pub original_target_anchor: String,
    /// Review kind exactly as authored.
    pub kind: ReviewKind,
    /// Review body exactly as authored.
    pub content: String,
    /// Response references bound at submit.
    pub response_refs: Vec<String>,
    /// Requested-change references bound at submit, candidates only.
    pub change_refs: Vec<String>,
    /// Verifier-result references bound at submit, evidence only.
    pub verifier_refs: Vec<String>,
    /// Resolver-supplied anchor status retained verbatim.
    pub anchor_status: ReviewAnchorStatus,
    /// Current lifecycle of this item alone. Never shared with a batch.
    pub lifecycle: ReviewLifecycle,
    /// The reason retained when this item is rejected. `None` unless the
    /// lifecycle is `RejectedWithReason`.
    pub rejection_reason: Option<String>,
    /// Fence at which the item was admitted.
    pub state_fence: StateFence,
    /// Producer-observed submission time, Unix milliseconds.
    pub submitted_at_unix_ms: u64,
}

/// Admission outcome (`AdmitReviewItem`). A fresh identity yields the newly
/// admitted record with `replayed: false`; a reused identity yields the
/// already-known record with `replayed: true` and produces no second effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemAdmission {
    /// The admitted record, new or replayed.
    pub record: ReviewItemRecord,
    /// True when the identity was already known and no new record was created.
    pub replayed: bool,
}

/// Derived batch envelope over independently submitted items (A1). It carries
/// membership only: no lifecycle, no disposition, and no authority of its
/// own. Every item keeps its own lifecycle and disposition; unresolved items
/// remain visible obligations and cannot disappear because a surrounding
/// item was answered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBatchRecord {
    /// Stable identity for the batch across retries.
    pub batch_id: String,
    /// Frozen plan revision the batch was submitted under, retained opaquely.
    pub plan_revision: String,
    /// Member item identities, in submission order. Unique and non-empty.
    pub review_item_ids: Vec<String>,
}

/// Batch admission outcome (`AdmitReviewBatch`). Every draft is admitted
/// through [`admit_review_item`] under its own identity, so each item keeps
/// an independent lifecycle and replay state. A batch that fails on one
/// draft returns that draft's typed error; admission is per-item, never
/// all-or-nothing across the envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBatchAdmission {
    /// The derived envelope: membership only, no lifecycle.
    pub batch: ReviewBatchRecord,
    /// One per-item admission, in batch order.
    pub items: Vec<ReviewItemAdmission>,
}

/// One item's own disposition inside a batch observation. Copied from the
/// item's record alone, so answering one item never resolves or hides
/// another.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemDisposition {
    /// Identity of the observed item.
    pub review_item_id: String,
    /// The item's own lifecycle.
    pub lifecycle: ReviewLifecycle,
    /// The item's retained anchor status, reported explicitly.
    pub anchor_status: ReviewAnchorStatus,
    /// True once the item reached a recorded disposition.
    pub disposed: bool,
}

/// Batch observation outcome (`ObserveReviewBatch`). A pure join of the
/// derived envelope with the caller-read-back records: member identities
/// without a stored record stay listed under `missing` as visible
/// unresolved obligations instead of being dropped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBatchObservation {
    /// Identity of the observed batch.
    pub batch_id: String,
    /// One disposition per admitted member, in batch order.
    pub items: Vec<ReviewItemDisposition>,
    /// Member identities with no stored record. Still unresolved, never
    /// hidden.
    pub missing: Vec<String>,
}

/// Blocker classification verdict (W6). Only a real blocker may escalate:
/// an open item whose kind contests the target (objection, requested change,
/// scope issue, or acceptance issue). Questions, corrections, missing
/// evidence, and closed items never escalate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBlockerVerdict {
    /// Identity of the classified item.
    pub review_item_id: String,
    /// True when the item is a real blocker.
    pub is_blocker: bool,
}

/// Blocker escalation handoff (`EscalateReviewBlocker`). Evidence for the
/// existing Problem/Conflict/Critical-Attention owner, addressed to exactly
/// one of those owners. It carries no authority and resolves nothing by
/// itself; the owning path admits and works it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBlockerEscalation {
    /// Stable identity for the escalation across retries.
    pub escalation_id: String,
    /// Identity of the escalated review item.
    pub review_item_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// The existing owner this evidence is addressed to.
    pub target_owner: ReviewEscalationOwner,
    /// Why this item blocks its target. Required, never blank.
    pub reason: String,
    /// Fence at which the escalation was raised.
    pub state_fence: StateFence,
    /// Producer-observed escalation time, Unix milliseconds.
    pub escalated_at_unix_ms: u64,
    /// True when the identity was already known and this is the replay.
    pub replayed: bool,
}

/// Unvalidated submission input for one requested change (A4). Names the
/// normal owner route that must accept and verify it; the candidate itself
/// grants no write, effect, goal, or acceptance authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedChangeDraft {
    /// Stable identity for the candidate across retries.
    pub candidate_id: String,
    /// Normal-owner identity the candidate is submitted to, spelled by the
    /// producing caller. Retained opaquely; the Kernel admits no owner
    /// semantics and invents no route.
    pub owner_handle: String,
    /// Requested-change references carried to the owner, candidates only.
    pub change_refs: Vec<String>,
    /// Verifier-result references carried as evidence for the owner's
    /// verifier binding.
    pub verifier_refs: Vec<String>,
    /// Fence at which the candidate was submitted.
    pub state_fence: StateFence,
    /// Producer-observed submission time, Unix milliseconds, never zero.
    pub submitted_at_unix_ms: u64,
}

/// Requested-change candidate (`SubmitRequestedChange`). A handoff to the
/// normal owner, effect, and verifier paths: it carries the change and its
/// evidence, and it contains no effect field, so no caller can convert it
/// into a direct write. Acceptance and verification stay with the normal
/// owner at its own admission (STITCH).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedChangeCandidate {
    /// Stable identity for the candidate across retries.
    pub candidate_id: String,
    /// Identity of the review item that requested the change.
    pub review_item_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Normal-owner identity the candidate is submitted to.
    pub owner_handle: String,
    /// Requested-change references, candidates only.
    pub change_refs: Vec<String>,
    /// Verifier-result references, evidence only.
    pub verifier_refs: Vec<String>,
    /// Fence at which the candidate was submitted.
    pub state_fence: StateFence,
    /// Producer-observed submission time, Unix milliseconds.
    pub submitted_at_unix_ms: u64,
    /// True when the identity was already known and this is the replay.
    pub replayed: bool,
}

/// Named admission (`AdmitReviewItem`).
///
/// Validates the draft, replays the already-known record when
/// `review_item_id` is already present, and otherwise returns the canonical
/// record. `existing` is the caller-read-back record view (the Store bridge
/// readback in production); this function stores nothing itself.
///
/// An ambiguous anchor is admitted and retained as explicitly ambiguous
/// (A2): it is never refused, and because the record has no current-target
/// field it can never be attached to a similar fragment. A stale anchor is
/// admitted directly as `Stale`, mirroring the existing owner; every other
/// status starts at `PendingDelivery` with its status retained verbatim.
pub fn admit_review_item(
    draft: ReviewItemDraft,
    existing: &[ReviewItemRecord],
) -> Result<ReviewItemAdmission, CoordinationMailboxError> {
    validate_review_draft(&draft)?;
    if let Some(known) = existing
        .iter()
        .find(|record| record.review_item_id == draft.review_item_id)
    {
        if !review_draft_matches_record(&draft, known) {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: draft.review_item_id,
            });
        }
        return Ok(ReviewItemAdmission {
            record: known.clone(),
            replayed: true,
        });
    }
    let lifecycle = match draft.anchor_status {
        ReviewAnchorStatus::Stale => ReviewLifecycle::Stale,
        _ => ReviewLifecycle::PendingDelivery,
    };
    Ok(ReviewItemAdmission {
        record: ReviewItemRecord {
            review_item_id: draft.review_item_id,
            task_id: draft.task_id,
            author_principal: draft.author_principal,
            submitter_principal: draft.submitter_principal,
            target_kind: draft.target_kind,
            original_target_revision: draft.original_target_revision,
            original_target_anchor: draft.original_target_anchor,
            kind: draft.kind,
            content: draft.content,
            response_refs: draft.response_refs,
            change_refs: draft.change_refs,
            verifier_refs: draft.verifier_refs,
            anchor_status: draft.anchor_status,
            lifecycle,
            rejection_reason: None,
            state_fence: draft.state_fence,
            submitted_at_unix_ms: draft.submitted_at_unix_ms,
        },
        replayed: false,
    })
}

/// Named batch admission (`AdmitReviewBatch`).
///
/// Validates the derived envelope, then admits every draft through
/// [`admit_review_item`] under its own identity against the same
/// caller-read-back view plus the items admitted earlier in this batch. Each
/// item keeps its own lifecycle and replay state (A1): the batch carries
/// membership only. An empty batch, a blank identity, or a duplicate member
/// identity is a typed rejection, never a silent merge.
pub fn admit_review_batch(
    batch_id: &str,
    plan_revision: &str,
    drafts: &[ReviewItemDraft],
    existing: &[ReviewItemRecord],
) -> Result<ReviewBatchAdmission, CoordinationMailboxError> {
    require_text(batch_id, "batch_id", MAX_IDENTITY_LEN)?;
    require_text(plan_revision, "plan_revision", MAX_IDENTITY_LEN)?;
    if drafts.is_empty() {
        return Err(CoordinationMailboxError::InvalidField {
            field: "review_batch",
            reason: "must carry at least one review item",
        });
    }
    let mut seen: Vec<String> = Vec::with_capacity(drafts.len());
    for draft in drafts {
        require_text(&draft.review_item_id, "review_item_id", MAX_IDENTITY_LEN)?;
        if seen.iter().any(|id| *id == draft.review_item_id) {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: draft.review_item_id.clone(),
            });
        }
        seen.push(draft.review_item_id.clone());
    }
    let mut admitted: Vec<ReviewItemRecord> = Vec::with_capacity(drafts.len());
    let mut items: Vec<ReviewItemAdmission> = Vec::with_capacity(drafts.len());
    for draft in drafts {
        let mut view: Vec<ReviewItemRecord> = Vec::with_capacity(existing.len() + admitted.len());
        view.extend(existing.iter().cloned());
        view.extend(admitted.iter().cloned());
        let admission = admit_review_item(draft.clone(), &view)?;
        admitted.push(admission.record.clone());
        items.push(admission);
    }
    Ok(ReviewBatchAdmission {
        batch: ReviewBatchRecord {
            batch_id: batch_id.to_owned(),
            plan_revision: plan_revision.to_owned(),
            review_item_ids: seen,
        },
        items,
    })
}

/// Named lifecycle advance (`AdvanceReviewItem`).
///
/// Moves one item along the exact review lifecycle; illegal transitions are
/// rejected with [`CoordinationMailboxError::InvalidState`]-shaped typed
/// failures. Only the author advances their own item: `by_principal` must
/// name the retained author, mirroring the existing owner rule. Rejection
/// requires a reason, which is retained on the record. Resolution additionally
/// requires an attached anchor status (`Exact`, `Moved`, or `Modified`): an
/// ambiguous, stale, deleted, or unavailable item stays retained but never
/// counts as resolved and is never attached to a similar fragment (A2).
/// `observed_at_unix_ms` is the producer-observed advance time, never zero.
pub fn advance_review_item(
    record: &ReviewItemRecord,
    advance: ReviewAdvance,
    by_principal: &str,
    reason: Option<&str>,
    observed_at_unix_ms: u64,
) -> Result<ReviewItemRecord, CoordinationMailboxError> {
    require_text(by_principal, "by_principal", MAX_IDENTITY_LEN)?;
    if by_principal != record.author_principal {
        return Err(CoordinationMailboxError::InvalidField {
            field: "by_principal",
            reason: "only the review author advances the item",
        });
    }
    require_timestamp(observed_at_unix_ms, "observed_at_unix_ms")?;
    let mut recorded_rejection_reason = None;
    let next = match (record.lifecycle, advance) {
        (ReviewLifecycle::PendingDelivery, ReviewAdvance::Deliver) => ReviewLifecycle::Delivered,
        (ReviewLifecycle::Delivered, ReviewAdvance::Answer) => ReviewLifecycle::Answered,
        (ReviewLifecycle::Answered, ReviewAdvance::Resolve) => {
            if !record.anchor_status.supports_resolution() {
                return Err(CoordinationMailboxError::InvalidField {
                    field: "anchor_status",
                    reason: "an unattached anchor never resolves",
                });
            }
            ReviewLifecycle::Resolved
        }
        (
            ReviewLifecycle::Delivered | ReviewLifecycle::Answered,
            ReviewAdvance::RejectWithReason,
        ) => {
            let value = reason
                .filter(|text| !text.trim().is_empty())
                .ok_or(CoordinationMailboxError::InvalidField {
                    field: "rejection_reason",
                    reason: "rejection requires a reason",
                })?;
            require_text(value, "rejection_reason", MAX_REVIEW_REASON_LEN)?;
            recorded_rejection_reason = Some(value.to_owned());
            ReviewLifecycle::RejectedWithReason
        }
        (
            ReviewLifecycle::PendingDelivery
            | ReviewLifecycle::Delivered
            | ReviewLifecycle::Answered,
            ReviewAdvance::MarkStale,
        ) => ReviewLifecycle::Stale,
        (
            ReviewLifecycle::PendingDelivery
            | ReviewLifecycle::Delivered
            | ReviewLifecycle::Answered,
            ReviewAdvance::MarkSuperseded,
        ) => ReviewLifecycle::Superseded,
        _ => {
            return Err(CoordinationMailboxError::InvalidField {
                field: "lifecycle",
                reason: "illegal review lifecycle transition",
            });
        }
    };
    let mut advanced = record.clone();
    advanced.lifecycle = next;
    if let Some(value) = recorded_rejection_reason {
        advanced.rejection_reason = Some(value);
    }
    Ok(advanced)
}

/// Named batch observation (`ObserveReviewBatch`).
///
/// Joins the derived envelope with the caller-read-back records and reports
/// every member's own disposition (A1). The batch itself carries no lifecycle:
/// each disposition is copied from its own record, so answering one item
/// never resolves or hides another. Member identities with no stored record
/// stay listed under `missing` as visible unresolved obligations.
pub fn observe_review_batch(
    batch: &ReviewBatchRecord,
    records: &[ReviewItemRecord],
) -> Result<ReviewBatchObservation, CoordinationMailboxError> {
    require_text(&batch.batch_id, "batch_id", MAX_IDENTITY_LEN)?;
    if batch.review_item_ids.is_empty() {
        return Err(CoordinationMailboxError::InvalidField {
            field: "review_batch",
            reason: "must carry at least one review item",
        });
    }
    let mut items: Vec<ReviewItemDisposition> = Vec::with_capacity(batch.review_item_ids.len());
    let mut missing: Vec<String> = Vec::new();
    for review_item_id in &batch.review_item_ids {
        match records
            .iter()
            .find(|record| record.review_item_id == *review_item_id)
        {
            Some(record) => items.push(ReviewItemDisposition {
                review_item_id: record.review_item_id.clone(),
                lifecycle: record.lifecycle,
                anchor_status: record.anchor_status,
                disposed: record.lifecycle.is_disposed(),
            }),
            None => missing.push(review_item_id.clone()),
        }
    }
    Ok(ReviewBatchObservation {
        batch_id: batch.batch_id.clone(),
        items,
        missing,
    })
}

/// Classifies one review item as a real blocker or not (W6).
///
/// A real blocker is an open item whose kind contests its target:
/// objection, requested change, scope issue, or acceptance issue. Questions,
/// corrections, missing evidence, and closed items are never blockers and
/// therefore never escalate. The verdict names the item only; routing stays
/// with [`escalate_review_blocker`] and working stays with the existing
/// owner.
pub fn classify_review_blocker(record: &ReviewItemRecord) -> ReviewBlockerVerdict {
    let contests_target = matches!(
        record.kind,
        ReviewKind::Objection
            | ReviewKind::RequestedChange
            | ReviewKind::ScopeIssue
            | ReviewKind::AcceptanceIssue
    );
    ReviewBlockerVerdict {
        review_item_id: record.review_item_id.clone(),
        is_blocker: record.lifecycle.is_open() && contests_target,
    }
}

/// Named blocker escalation (`EscalateReviewBlocker`).
///
/// Rejects non-blockers with a typed failure: only real blockers escalate
/// (W6). A real blocker yields the evidence handoff addressed to exactly one
/// existing owner (`Problem`, `Conflict`, or `CriticalAttention`); the
/// handoff resolves nothing by itself. `existing` is the caller-read-back
/// escalation view; this function stores nothing itself. A reused
/// `escalation_id` with an identical body replays the existing handoff; the
/// same identity with a different body is an identity conflict.
pub fn escalate_review_blocker(
    record: &ReviewItemRecord,
    target_owner: ReviewEscalationOwner,
    reason: &str,
    escalation_id: &str,
    existing: &[ReviewBlockerEscalation],
    escalated_at_unix_ms: u64,
) -> Result<ReviewBlockerEscalation, CoordinationMailboxError> {
    require_text(escalation_id, "escalation_id", MAX_IDENTITY_LEN)?;
    let verdict = classify_review_blocker(record);
    if !verdict.is_blocker {
        return Err(CoordinationMailboxError::InvalidField {
            field: "review_item_id",
            reason: "only a real blocker escalates",
        });
    }
    require_text(reason, "reason", MAX_REVIEW_REASON_LEN)?;
    require_timestamp(escalated_at_unix_ms, "escalated_at_unix_ms")?;
    if let Some(known) = existing
        .iter()
        .find(|escalation| escalation.escalation_id == escalation_id)
    {
        if known.review_item_id != record.review_item_id
            || known.target_owner != target_owner
            || known.reason != reason
            || known.state_fence != record.state_fence
        {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: escalation_id.to_owned(),
            });
        }
        return Ok(ReviewBlockerEscalation {
            replayed: true,
            ..known.clone()
        });
    }
    Ok(ReviewBlockerEscalation {
        escalation_id: escalation_id.to_owned(),
        review_item_id: record.review_item_id.clone(),
        task_id: record.task_id.clone(),
        target_owner,
        reason: reason.to_owned(),
        state_fence: record.state_fence.clone(),
        escalated_at_unix_ms,
        replayed: false,
    })
}

/// Named requested-change submission (`SubmitRequestedChange`).
///
/// Routes a `RequestedChange` item to the normal owner, effect, and verifier
/// paths through a candidate handoff (A4). Only that kind submits; any other
/// kind, or a closed item, is a typed rejection. The candidate carries the
/// change and its evidence to the named owner route and contains no effect
/// field, so no caller can convert it into a direct write: a requested
/// change produces no direct write until the normal effect owner accepts and
/// verifies it at its own admission. `existing` is the caller-read-back
/// candidate view; this function stores nothing itself.
pub fn submit_requested_change(
    record: &ReviewItemRecord,
    draft: RequestedChangeDraft,
    existing: &[RequestedChangeCandidate],
) -> Result<RequestedChangeCandidate, CoordinationMailboxError> {
    require_text(&draft.candidate_id, "candidate_id", MAX_IDENTITY_LEN)?;
    if record.kind != ReviewKind::RequestedChange {
        return Err(CoordinationMailboxError::InvalidField {
            field: "kind",
            reason: "only a requested change submits a change candidate",
        });
    }
    if !record.lifecycle.is_open() {
        return Err(CoordinationMailboxError::InvalidField {
            field: "lifecycle",
            reason: "a closed item submits no change candidate",
        });
    }
    require_text(&draft.owner_handle, "owner_handle", MAX_IDENTITY_LEN)?;
    validate_review_refs(&draft.change_refs, "change_refs")?;
    validate_review_refs(&draft.verifier_refs, "verifier_refs")?;
    draft
        .state_fence
        .validate()
        .map_err(CoordinationMailboxError::Foundation)?;
    require_timestamp(draft.submitted_at_unix_ms, "submitted_at_unix_ms")?;
    if let Some(known) = existing
        .iter()
        .find(|candidate| candidate.candidate_id == draft.candidate_id)
    {
        if known.review_item_id != record.review_item_id
            || known.owner_handle != draft.owner_handle
            || known.change_refs != draft.change_refs
            || known.verifier_refs != draft.verifier_refs
            || known.state_fence != draft.state_fence
        {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: draft.candidate_id,
            });
        }
        return Ok(RequestedChangeCandidate {
            replayed: true,
            ..known.clone()
        });
    }
    Ok(RequestedChangeCandidate {
        candidate_id: draft.candidate_id,
        review_item_id: record.review_item_id.clone(),
        task_id: record.task_id.clone(),
        owner_handle: draft.owner_handle,
        change_refs: draft.change_refs,
        verifier_refs: draft.verifier_refs,
        state_fence: draft.state_fence,
        submitted_at_unix_ms: draft.submitted_at_unix_ms,
        replayed: false,
    })
}

/// Validates every draft field: identities, principals, immutable originals,
/// kind payload, reference bounds, retained anchor status, fence, and time.
fn validate_review_draft(draft: &ReviewItemDraft) -> Result<(), CoordinationMailboxError> {
    require_text(
        &draft.review_item_id,
        "review_item_id",
        MAX_IDENTITY_LEN,
    )?;
    require_text(
        &draft.author_principal,
        "author_principal",
        MAX_IDENTITY_LEN,
    )?;
    require_text(
        &draft.submitter_principal,
        "submitter_principal",
        MAX_IDENTITY_LEN,
    )?;
    require_text(
        &draft.original_target_revision,
        "original_target_revision",
        MAX_IDENTITY_LEN,
    )?;
    require_text(
        &draft.original_target_anchor,
        "original_target_anchor",
        MAX_PROVENANCE_LEN,
    )?;
    if draft.content.len() > MAX_REVIEW_CONTENT_BYTES {
        return Err(CoordinationMailboxError::InvalidField {
            field: "content",
            reason: "exceeds admission bound",
        });
    }
    if draft.content.trim().is_empty() || draft.content.chars().any(char::is_control) {
        return Err(CoordinationMailboxError::InvalidField {
            field: "content",
            reason: "blank or control character",
        });
    }
    validate_review_refs(&draft.response_refs, "response_refs")?;
    validate_review_refs(&draft.change_refs, "change_refs")?;
    validate_review_refs(&draft.verifier_refs, "verifier_refs")?;
    draft
        .state_fence
        .validate()
        .map_err(CoordinationMailboxError::Foundation)?;
    require_timestamp(draft.submitted_at_unix_ms, "submitted_at_unix_ms")?;
    Ok(())
}

/// Validates one reference list: bounded count, and every entry bounded,
/// non-blank text. Entries stay opaque evidence; the Kernel interprets none.
fn validate_review_refs(
    refs: &[String],
    field: &'static str,
) -> Result<(), CoordinationMailboxError> {
    if refs.len() > MAX_REVIEW_REFS {
        return Err(CoordinationMailboxError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    for reference in refs {
        require_text(reference, field, MAX_PROVENANCE_LEN)?;
    }
    Ok(())
}

/// Whether a redrafted submission still names the same logical item as the
/// known record. A reused identity with a different task, author, target,
/// original, kind, content, reference, status, timestamp, or fence is an
/// identity conflict, never a silent replay. The lifecycle and rejection
/// reason are advance state, not submit identity, so they are excluded.
fn review_draft_matches_record(draft: &ReviewItemDraft, record: &ReviewItemRecord) -> bool {
    draft.task_id == record.task_id
        && draft.author_principal == record.author_principal
        && draft.submitter_principal == record.submitter_principal
        && draft.target_kind == record.target_kind
        && draft.original_target_revision == record.original_target_revision
        && draft.original_target_anchor == record.original_target_anchor
        && draft.kind == record.kind
        && draft.content == record.content
        && draft.response_refs == record.response_refs
        && draft.change_refs == record.change_refs
        && draft.verifier_refs == record.verifier_refs
        && draft.anchor_status == record.anchor_status
        && draft.submitted_at_unix_ms == record.submitted_at_unix_ms
        && draft.state_fence == record.state_fence
}
