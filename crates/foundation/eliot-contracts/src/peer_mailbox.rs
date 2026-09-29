//! Owner-neutral closed vocabulary for durable directed mailbox delivery.
//!
//! These values identify retained mailbox records, route capabilities, and
//! delivery observations only (issue #1820, I10.18). They do not grant task
//! acceptance, truth, authority, or effect. Wire spellings match the Governor
//! mailbox vocabulary exactly so the durable record and the semantic channel
//! name the same closed sets; the Governor representation itself is unchanged.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Closed mailbox message-kind vocabulary (I10.18 kinds plus the
/// note/evidence/request/response/objection/review family).
///
/// Work assignment is deliberately absent: peers cannot assign work through
/// this channel. Spellings match `PeerMessageKind` wire names one-to-one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerMailboxKind {
    Note,
    Evidence,
    Question,
    Answer,
    Objection,
    ReviewItem,
    ReviewBatch,
    Checkpoint,
    ConflictNotice,
    Result,
    VerifierResult,
    CancelSupersede,
    AttentionEscalation,
    LivePeerDelta,
    Retraction,
    Supersession,
}

impl PeerMailboxKind {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Evidence => "evidence",
            Self::Question => "question",
            Self::Answer => "answer",
            Self::Objection => "objection",
            Self::ReviewItem => "review_item",
            Self::ReviewBatch => "review_batch",
            Self::Checkpoint => "checkpoint",
            Self::ConflictNotice => "conflict_notice",
            Self::Result => "result",
            Self::VerifierResult => "verifier_result",
            Self::CancelSupersede => "cancel_supersede",
            Self::AttentionEscalation => "attention_escalation",
            Self::LivePeerDelta => "live_peer_delta",
            Self::Retraction => "retraction",
            Self::Supersession => "supersession",
        }
    }

    /// Closed decode: unknown spellings are rejected, never coerced.
    pub fn decode(text: &str) -> Result<Self, PeerMailboxKindError> {
        match text {
            "note" => Ok(Self::Note),
            "evidence" => Ok(Self::Evidence),
            "question" => Ok(Self::Question),
            "answer" => Ok(Self::Answer),
            "objection" => Ok(Self::Objection),
            "review_item" => Ok(Self::ReviewItem),
            "review_batch" => Ok(Self::ReviewBatch),
            "checkpoint" => Ok(Self::Checkpoint),
            "conflict_notice" => Ok(Self::ConflictNotice),
            "result" => Ok(Self::Result),
            "verifier_result" => Ok(Self::VerifierResult),
            "cancel_supersede" => Ok(Self::CancelSupersede),
            "attention_escalation" => Ok(Self::AttentionEscalation),
            "live_peer_delta" => Ok(Self::LivePeerDelta),
            "retraction" => Ok(Self::Retraction),
            "supersession" => Ok(Self::Supersession),
            _ => Err(PeerMailboxKindError::Unknown(text.to_owned())),
        }
    }

    #[must_use]
    pub const fn all() -> [&'static str; 16] {
        [
            "note",
            "evidence",
            "question",
            "answer",
            "objection",
            "review_item",
            "review_batch",
            "checkpoint",
            "conflict_notice",
            "result",
            "verifier_result",
            "cancel_supersede",
            "attention_escalation",
            "live_peer_delta",
            "retraction",
            "supersession",
        ]
    }
}

/// Failure to decode a closed mailbox message kind.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PeerMailboxKindError {
    /// The spelling is outside the exact I10.18 mailbox kind set.
    #[error("unknown mailbox message kind: {0}")]
    Unknown(String),
}

/// Closed route capability at which a mailbox item may be delivered (I10.18
/// delivery profiles). Spellings match the Governor route vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerMailboxRouteProfile {
    EventIntegrated,
    ToolOnly,
    OfflineWorker,
    Unavailable,
}

impl PeerMailboxRouteProfile {
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
    pub fn decode(text: &str) -> Result<Self, PeerMailboxRouteError> {
        match text {
            "event_integrated" => Ok(Self::EventIntegrated),
            "tool_only" => Ok(Self::ToolOnly),
            "offline_worker" => Ok(Self::OfflineWorker),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(PeerMailboxRouteError::Unknown(text.to_owned())),
        }
    }

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

/// Failure to decode a closed mailbox route profile.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PeerMailboxRouteError {
    /// The spelling is outside the exact I10.18 route profile set.
    #[error("unknown mailbox route profile: {0}")]
    Unknown(String),
}

/// One recorded delivery-step outcome. Delivery proves only that the step
/// ran; it is never agreement, use, completion, or passive awareness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MailboxDeliveryOutcome {
    Delivered { endpoint: String },
    Unavailable { reason: String },
    Unknown { reason: String },
}

impl MailboxDeliveryOutcome {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Delivered { .. } => "delivered",
            Self::Unavailable { .. } => "unavailable",
            Self::Unknown { .. } => "unknown",
        }
    }
}

/// One retained delivery-attempt entry of a mailbox head's bounded history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailboxAttemptRecord {
    pub attempt: u32,
    pub at: u64,
    pub outcome: MailboxDeliveryOutcome,
}

/// Delivery lifecycle of one retained mailbox head. Recorded/admitted,
/// delivery-attempted, delivered, acknowledged, unavailable, unknown, and
/// expired stay distinct; acknowledgement covers one exact message revision
/// only and is never agreement, use, or completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MailboxDeliveryState {
    Staged,
    Delivered { endpoint: String },
    Acknowledged { revision: u64, by_session: String },
    Unavailable { reason: String },
    Unknown { reason: String },
    Expired { at: u64 },
}

impl MailboxDeliveryState {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Delivered { .. } => "delivered",
            Self::Acknowledged { .. } => "acknowledged",
            Self::Unavailable { .. } => "unavailable",
            Self::Unknown { .. } => "unknown",
            Self::Expired { .. } => "expired",
        }
    }

    /// Terminal states admit no further delivery protocol transition.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        match self {
            Self::Staged
            | Self::Delivered { .. }
            | Self::Acknowledged { .. }
            | Self::Unavailable { .. }
            | Self::Unknown { .. } => true,
            Self::Expired { .. } => false,
        }
    }
}
