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
//! [`COORDINATION_MAILBOX_ACKNOWLEDGE_NAME`]), the route-qualified delivery
//! resolution ([`resolve_mailbox_route`], stable name
//! [`COORDINATION_MAILBOX_ROUTE_NAME`]) with its durable degraded state, the
//! session-loss expiry/reassignment rows ([`expire_mailbox_message`] under
//! [`COORDINATION_MAILBOX_EXPIRE_NAME`], [`reassign_mailbox_message`] under
//! [`COORDINATION_MAILBOX_REASSIGN_NAME`]), the derived delivery-order
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
//! view carries no rows of its own. The route slice calls
//! [`resolve_mailbox_route`] with the caller-attested route capability and
//! recipient liveness: a deliverable route records the
//! [`record_mailbox_delivery`] receipt, while an unavailable route or a lapsed
//! recipient retains the item as a durable [`MailboxDegradedReceipt`] that
//! names the capability gap without claiming passive awareness. The
//! session-loss slice calls [`expire_mailbox_message`] and
//! [`reassign_mailbox_message`] with the caller-observed time and session
//! liveness; both rows carry the retained delivery count so delivery history
//! survives the transition. The stable `*_NAME` and `*_SCHEMA_V1`
//! constants are the exact keys those slices register on the Store bridge;
//! they are declared here so the names cannot drift between the Kernel surface
//! and the bridge registration.
//!
//! # Live status
//!
//! The Store bridge slice named above is not compiled. Measured on this tree,
//! no code in any crate names any of this module's `pub` entries other than
//! their defining lines and the prose in this header, and no path in
//! `daemon_request_dispatch.rs` matches any `COORDINATION_MAILBOX_*` or
//! `COORDINATION_MAP_VIEW_NAME` key, so none of the named slices can reach
//! them. That covers the whole surface, not one entry: the internal
//! cross-references ([`record_mailbox_delivery`] from
//! [`resolve_mailbox_route`], [`project_mailbox_queue`] from
//! [`rebuild_coordination_map_view`]) are the only call edges that exist, and
//! their callers are themselves uncalled. The module is declared
//! `pub mod coordination_mailbox` in `lib.rs`, so it compiles and its shapes
//! are documented, but no production route reaches it. No wiring was added and
//! no caller was invented; whether the front door registers these keys or the
//! surface is retired is an owner decision.
//!
//! # What this deliberately does not do
//!
//! No scheduler, task graph, subscription engine, or routing authority: route
//! resolution names the capability gap but never reroutes by itself, and a
//! reassignment row names the new recipient without moving delivery history.
//! Session liveness arrives as a caller-attested boolean; this module keeps no
//! session table and owns no lease. A message admitted here starts undelivered;
//! every later delivery step is owned by the slice that performs it.
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
    /// The message is neither past its horizon nor past a lost session. No
    /// expiry row was recorded.
    ExpiryNotDue {
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
            Self::ExpiryNotDue { message_id } => {
                write!(f, "mailbox message expiry not due: {message_id}")
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
// Out of scope here: large-payload handles (payload-handles slice below).
// Route capabilities and session-loss expiry/reassignment live in their own
// slices below.
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
// Intended production chain: the Store bridge / delivery slice reads the bytes
// through the artifact owner, then calls [`resolve_mailbox_payload_handle`]
// with the owner-supplied bytes for the pure digest-plus-length check. That read
// belongs in the bridge/dispatch seam outside this file. Live status: no
// production caller is built; see the `# Live status` section on that function.
// Typed failures stay typed: every rejection is a
// [`CoordinationMailboxError`].
//
// Out of scope here: map view (map-view slice above), route capabilities
// (route slice below), and expiry/reassignment (session-loss slice below).
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
/// `bytes` are the exact bytes the caller read through the artifact owner
/// (`ArtifactOwner::read` via the injected `ArtifactBlobReader`); this function
/// verifies length and digest and returns the same slice, never a copy beside
/// the handle. Mismatches are typed rejections, never silent truncation.
///
/// # Live status
///
/// No production caller. Measured on this tree, no code in any crate names this
/// function other than its defining line, so the earlier wording that named "the
/// production caller" as an existing fact was false and has been corrected to a
/// description of the intended contract. The owner seam this contract describes
/// is real and separately owned, but the read-and-resolve route is not built:
/// the sibling attach/detach pair ([`attach_mailbox_payload_handle`],
/// [`detach_mailbox_payload_handle`]) and the rest of the mailbox route are
/// likewise uncalled, so this is the unused resolve half of that unwired
/// surface, not a live step inside a working chain. Whether the bridge/dispatch
/// seam is wired to it or this accessor is retired is an owner decision; no
/// caller was added to close the gap.
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
// Route-qualified delivery with durable degraded state (issue #1820, route
// slice W5).
//
// I10.18 requires route-qualified delivery capability and visible degradation:
// when the route is unavailable the item remains durable, the result names the
// delivery capability gap, and no passive recipient awareness is claimed. The
// closed capability vocabulary below spells the four I10.18 delivery profiles
// 1:1 with an independent closed decode: the Governor `DeliveryPolicy` in
// `eliot-coordination` is Governor semantics and is not interpreted here, and
// this composition root takes no new dependency to name it twice.
//
// Production chain: the route/delivery slice calls [`resolve_mailbox_route`]
// under [`COORDINATION_MAILBOX_ROUTE_NAME`] with the caller-attested route
// capability and recipient liveness (session state lives with the session
// owner, never here). A deliverable route records the
// [`record_mailbox_delivery`] receipt through the same resolution path, so
// delivery and degradation share one named operation; an unavailable route or
// a lapsed recipient retains the item as a durable [`MailboxDegradedReceipt`]
// row keyed by the message identity. A reused identity with the identical
// route and cause replays the existing degraded row with no second effect; a
// reused identity with a different route or cause is an identity conflict,
// never a silent overwrite. Typed failures stay typed: every rejection is a
// [`CoordinationMailboxError`].
//
// Out of scope here: map view (map-view slice above), large-payload handles
// (payload-handles slice above), and expiry/reassignment (session-loss slice
// below).
// ============================================================================

/// Stable named route resolution. The route/delivery slice calls
/// [`resolve_mailbox_route`] under this exact name before delivering.
pub const COORDINATION_MAILBOX_ROUTE_NAME: &str = "ResolveMailboxRoute";

/// Closed route-capability vocabulary (I10.18 delivery profiles). Unknown
/// spellings are rejected by [`MailboxRouteProfile::decode`], never coerced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MailboxRouteProfile {
    EventIntegrated,
    ToolOnly,
    OfflineWorker,
    Unavailable,
}

impl MailboxRouteProfile {
    /// Canonical wire spelling of one profile.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::EventIntegrated => "event_integrated",
            Self::ToolOnly => "tool_only",
            Self::OfflineWorker => "offline_worker",
            Self::Unavailable => "unavailable",
        }
    }

    /// Closed decode: unknown spellings are rejected, never coerced.
    pub fn decode(text: &str) -> Result<Self, CoordinationMailboxError> {
        match text {
            "event_integrated" => Ok(Self::EventIntegrated),
            "tool_only" => Ok(Self::ToolOnly),
            "offline_worker" => Ok(Self::OfflineWorker),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(CoordinationMailboxError::InvalidField {
                field: "route_profile",
                reason: "unknown route profile",
            }),
        }
    }

    /// Exact closed denominator of the route vocabulary.
    #[must_use]
    pub const fn all() -> [&'static str; 4] {
        [
            "event_integrated",
            "tool_only",
            "offline_worker",
            "unavailable",
        ]
    }
}

/// Closed cause of one durable degraded record: either the route capability
/// itself is unavailable, or the recipient session has lapsed. Both retain
/// the item; neither claims passive recipient awareness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MailboxDegradedCause {
    RouteUnavailable,
    RecipientNotLive,
}

impl MailboxDegradedCause {
    /// Canonical wire spelling of one cause.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::RouteUnavailable => "route_unavailable",
            Self::RecipientNotLive => "recipient_not_live",
        }
    }
}

/// Durable degraded record for one admitted message whose route cannot
/// deliver now. The item stays durable under its identity; the row names the
/// exact capability gap (`route` plus `cause`) and carries no delivery claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDegradedReceipt {
    /// Identity of the retained message.
    pub message_id: String,
    /// Ordering key of the retained record.
    pub sequence: u64,
    /// Route capability observed at resolution time.
    pub route: MailboxRouteProfile,
    /// Why delivery cannot proceed on this route now.
    pub cause: MailboxDegradedCause,
    /// Producer-observed resolution time, Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// True when the identical degraded row was already recorded.
    pub replayed: bool,
}

/// Route-resolution outcome (`ResolveMailboxRoute`): either the delivery
/// receipt or the durable degraded record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MailboxDeliveryOutcome {
    Delivered(MailboxDeliveryReceipt),
    Degraded(MailboxDegradedReceipt),
}

/// Resolves one admitted record against the caller-attested route
/// (`ResolveMailboxRoute`).
///
/// When the route is unavailable, or the recipient session has lapsed, the
/// item is retained as a durable [`MailboxDegradedReceipt`] naming the exact
/// capability gap; no delivery is claimed and no passive awareness is
/// reported. Otherwise the call records delivery through
/// [`record_mailbox_delivery`] against the already-known receipts. A message
/// already delivered replays its delivery receipt however the route reads now:
/// history is never revised. `existing_deliveries` and `existing_degraded`
/// are the caller-read-back row views (the Store bridge readback in
/// production); this function stores nothing itself.
pub fn resolve_mailbox_route(
    record: &CoordinationMailboxRecord,
    existing_deliveries: &[MailboxDeliveryReceipt],
    existing_degraded: &[MailboxDegradedReceipt],
    route: MailboxRouteProfile,
    recipient_live: bool,
    observed_at_unix_ms: u64,
) -> Result<MailboxDeliveryOutcome, CoordinationMailboxError> {
    require_timestamp(observed_at_unix_ms, "observed_at_unix_ms")?;
    if let Some(known) = existing_deliveries
        .iter()
        .find(|receipt| receipt.message_id == record.message_id)
    {
        return Ok(MailboxDeliveryOutcome::Delivered(MailboxDeliveryReceipt {
            replayed: true,
            ..known.clone()
        }));
    }
    let cause = if route == MailboxRouteProfile::Unavailable {
        Some(MailboxDegradedCause::RouteUnavailable)
    } else if !recipient_live {
        Some(MailboxDegradedCause::RecipientNotLive)
    } else {
        None
    };
    let Some(cause) = cause else {
        return Ok(MailboxDeliveryOutcome::Delivered(record_mailbox_delivery(
            record,
            existing_deliveries,
            observed_at_unix_ms,
        )?));
    };
    if let Some(known) = existing_degraded
        .iter()
        .find(|receipt| receipt.message_id == record.message_id)
    {
        if known.route != route || known.cause != cause {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: record.message_id.clone(),
            });
        }
        return Ok(MailboxDeliveryOutcome::Degraded(MailboxDegradedReceipt {
            replayed: true,
            ..known.clone()
        }));
    }
    Ok(MailboxDeliveryOutcome::Degraded(MailboxDegradedReceipt {
        message_id: record.message_id.clone(),
        sequence: record.sequence,
        route,
        cause,
        observed_at_unix_ms,
        replayed: false,
    }))
}

// ============================================================================
// Session-loss expiry and reassignment (issue #1820, session-loss slice W6).
//
// I10.18 requires expiry/reassignment after Session loss while retaining
// delivery history. The record stays immutable after admission, so expiry and
// reassignment are separate durable rows keyed by the message identity, the
// same way payload attachments are: the original record and every delivery
// receipt keep their identity, and each new row binds the retained delivery
// count the caller read back, so a transition that drops history cannot
// produce the same row.
//
// Session liveness arrives as a caller-attested boolean: the session table
// lives with the session owner, and this module keeps no rows and owns no
// lease. The expiry horizon is supplied per call by the owning slice for the
// same reason: no ambient clock and no config surface here. Expiry is
// terminal: an expired identity is never reassigned. Reassignment names the
// replacement recipient for a lost session without moving delivery history;
// the consumer routes through the rebuilt coordination map afterwards. Typed
// failures stay typed: every rejection is a [`CoordinationMailboxError`].
//
// Production chain: the session-loss slice calls [`expire_mailbox_message`]
// under [`COORDINATION_MAILBOX_EXPIRE_NAME`] when the recipient session lapses
// or the horizon passes, and [`reassign_mailbox_message`] under
// [`COORDINATION_MAILBOX_REASSIGN_NAME`] to name the replacement recipient.
// Both callers persist the returned rows through the Store bridge (STITCH).
//
// Out of scope here: map view (map-view slice above), large-payload handles
// (payload-handles slice above), and route capabilities (route slice above).
// ============================================================================

/// Stable named expiry. The session-loss slice calls
/// [`expire_mailbox_message`] under this exact name.
pub const COORDINATION_MAILBOX_EXPIRE_NAME: &str = "ExpireMailboxMessage";
/// Stable named reassignment. The session-loss slice calls
/// [`reassign_mailbox_message`] under this exact name.
pub const COORDINATION_MAILBOX_REASSIGN_NAME: &str = "ReassignMailboxMessage";

/// Closed cause of one session-loss transition: the configured horizon
/// passed, or the recipient session was lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MailboxExpiryCause {
    HorizonReached,
    SessionLoss,
}

impl MailboxExpiryCause {
    /// Canonical wire spelling of one cause.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::HorizonReached => "horizon_reached",
            Self::SessionLoss => "session_loss",
        }
    }
}

/// Durable expiry row for one admitted message (`ExpireMailboxMessage`).
/// Terminal: an expired identity is never reassigned and admits no further
/// delivery step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxExpiryReceipt {
    /// Identity of the expired message.
    pub message_id: String,
    /// Ordering key of the expired record.
    pub sequence: u64,
    /// Why the message expired.
    pub cause: MailboxExpiryCause,
    /// Producer-observed expiry time, Unix milliseconds.
    pub expired_at_unix_ms: u64,
    /// Delivery receipts the caller read back for this identity: the history
    /// retained through the transition, bound into the row.
    pub retained_deliveries: u64,
    /// True when this identity was already expired.
    pub replayed: bool,
}

/// Expires one admitted message after Session loss or horizon expiry
/// (`ExpireMailboxMessage`).
///
/// A lost session expires the message with [`MailboxExpiryCause::SessionLoss`];
/// a live session expires it with [`MailboxExpiryCause::HorizonReached`] only
/// once the caller-observed time reaches the owning slice's horizon. A message
/// that is neither past its horizon nor past a lost session is rejected with
/// [`CoordinationMailboxError::ExpiryNotDue`]. `existing` is the
/// caller-read-back expiry view and `deliveries` the caller-read-back delivery
/// view (the Store bridge readback in production); this function stores
/// nothing itself.
pub fn expire_mailbox_message(
    record: &CoordinationMailboxRecord,
    existing: &[MailboxExpiryReceipt],
    deliveries: &[MailboxDeliveryReceipt],
    observed_at_unix_ms: u64,
    session_live: bool,
    expiry_horizon_unix_ms: Option<u64>,
) -> Result<MailboxExpiryReceipt, CoordinationMailboxError> {
    require_timestamp(observed_at_unix_ms, "observed_at_unix_ms")?;
    if let Some(horizon) = expiry_horizon_unix_ms {
        require_timestamp(horizon, "expiry_horizon_unix_ms")?;
    }
    if let Some(known) = existing
        .iter()
        .find(|receipt| receipt.message_id == record.message_id)
    {
        return Ok(MailboxExpiryReceipt {
            replayed: true,
            ..known.clone()
        });
    }
    let cause = if !session_live {
        Some(MailboxExpiryCause::SessionLoss)
    } else if expiry_horizon_unix_ms.is_some_and(|horizon| observed_at_unix_ms >= horizon) {
        Some(MailboxExpiryCause::HorizonReached)
    } else {
        None
    };
    let Some(cause) = cause else {
        return Err(CoordinationMailboxError::ExpiryNotDue {
            message_id: record.message_id.clone(),
        });
    };
    Ok(MailboxExpiryReceipt {
        message_id: record.message_id.clone(),
        sequence: record.sequence,
        cause,
        expired_at_unix_ms: observed_at_unix_ms,
        retained_deliveries: retained_delivery_count(deliveries, &record.message_id),
        replayed: false,
    })
}

/// Durable reassignment row for one admitted message
/// (`ReassignMailboxMessage`): the replacement recipient after the recorded
/// recipient's session was lost. The original record is untouched and every
/// delivery receipt stays keyed by the message identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxReassignment {
    /// Identity of the reassigned message.
    pub message_id: String,
    /// Ordering key of the reassigned record.
    pub sequence: u64,
    /// Recipient named on the admitted record.
    pub from_recipient_id: String,
    /// Replacement recipient named by the session-loss slice.
    pub to_recipient_id: String,
    /// Task that owns the coordination context.
    pub task_id: TaskId,
    /// Producer-observed reassignment time, Unix milliseconds.
    pub reassigned_at_unix_ms: u64,
    /// Delivery receipts the caller read back for this identity: the history
    /// retained through the transition, bound into the row.
    pub retained_deliveries: u64,
    /// True when this identity was already reassigned to this recipient.
    pub replayed: bool,
}

/// Reassigns one admitted message after its recipient session was lost
/// (`ReassignMailboxMessage`).
///
/// Reassignment requires a lost session: a live session is a typed rejection,
/// never a silent no-op. The replacement must name a different recipient, and
/// an expired identity is never reassigned. A reused identity with the same
/// replacement replays the existing row with no second effect; a reused
/// identity with a different replacement is an identity conflict, never a
/// silent overwrite. `existing` is the caller-read-back reassignment view,
/// `deliveries` the caller-read-back delivery view, and `expiries` the
/// caller-read-back expiry view (the Store bridge readback in production);
/// this function stores nothing itself.
pub fn reassign_mailbox_message(
    record: &CoordinationMailboxRecord,
    existing: &[MailboxReassignment],
    deliveries: &[MailboxDeliveryReceipt],
    expiries: &[MailboxExpiryReceipt],
    new_recipient_id: &str,
    observed_at_unix_ms: u64,
    session_live: bool,
) -> Result<MailboxReassignment, CoordinationMailboxError> {
    require_timestamp(observed_at_unix_ms, "observed_at_unix_ms")?;
    if session_live {
        return Err(CoordinationMailboxError::InvalidField {
            field: "session_live",
            reason: "reassignment requires a lost session",
        });
    }
    require_text(new_recipient_id, "new_recipient_id", MAX_IDENTITY_LEN)?;
    if new_recipient_id == record.recipient_id {
        return Err(CoordinationMailboxError::InvalidField {
            field: "new_recipient_id",
            reason: "must name a different recipient",
        });
    }
    if expiries
        .iter()
        .any(|receipt| receipt.message_id == record.message_id)
    {
        return Err(CoordinationMailboxError::InvalidField {
            field: "message_id",
            reason: "message already expired",
        });
    }
    if let Some(known) = existing
        .iter()
        .find(|row| row.message_id == record.message_id)
    {
        if known.to_recipient_id != new_recipient_id {
            return Err(CoordinationMailboxError::IdentityConflict {
                message_id: record.message_id.clone(),
            });
        }
        return Ok(MailboxReassignment {
            replayed: true,
            ..known.clone()
        });
    }
    Ok(MailboxReassignment {
        message_id: record.message_id.clone(),
        sequence: record.sequence,
        from_recipient_id: record.recipient_id.clone(),
        to_recipient_id: new_recipient_id.to_owned(),
        task_id: record.task_id.clone(),
        reassigned_at_unix_ms: observed_at_unix_ms,
        retained_deliveries: retained_delivery_count(deliveries, &record.message_id),
        replayed: false,
    })
}

/// Counts the delivery receipts the caller read back for one identity, so a
/// session-loss row binds the history it retains.
fn retained_delivery_count(deliveries: &[MailboxDeliveryReceipt], message_id: &str) -> u64 {
    let mut retained: u64 = 0;
    for receipt in deliveries {
        if receipt.message_id == message_id {
            retained = retained.saturating_add(1);
        }
    }
    retained
}
