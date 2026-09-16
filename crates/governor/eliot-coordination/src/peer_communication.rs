//! B-PEER worker-to-worker mailbox and blackboard channel for Concilium.
//!
//! This module extends the existing [`super::CoordinationOwner`] with the
//! bounded peer channel: a directed mailbox with per-stream ordering and
//! live-delivery protocol state, a shared blackboard with revision chains and
//! frozen paged reads, structured conflict retention, and revision-anchored
//! review. All channel state lives in the single coordination owner; this
//! module adds cohesive reducers and adapters only.
//!
//! The channel runs over injected ports exclusively. Delivery, durability
//! attestation and time arrive through caller-supplied port objects
//! ([`PeerClockPort`], [`PeerDurabilityPort`], [`PeerDeliveryPort`]); the
//! module performs no I/O, keeps no ambient clock, and owns no execution,
//! assignment or finish authority. Peer content can never assign work, grant
//! effects, or declare finish: asserted effects are rejected fail-closed and
//! embedded command/tool/instruction markers are admitted as inert evidence.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ClockReading, EpochId, EpochRelation, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{CoordinationError, CoordinationEventKind, CoordinationOwner};

/// Revision of the peer channel record family.
pub const PEER_CHANNEL_REVISION: &str = "eliot.governor.peer-communication.v1";
/// Closed wire schema accepted by [`decode_peer_envelope`].
pub const PEER_MESSAGE_SCHEMA: &str = "peer-message/v1";
/// Largest admitted inline payload, in bytes.
pub const MAX_PEER_MESSAGE_BYTES: u64 = 65_536;
/// Largest admitted inline text, in bytes.
pub const MAX_PEER_INLINE_TEXT: usize = 8_192;
/// Largest admitted evidence/artifact reference fan-out per record.
pub const MAX_PEER_REFERENCES: usize = 16;
/// Largest admitted live (non-terminal) queue depth per stream.
pub const MAX_PEER_STREAM_DEPTH: usize = 256;
/// Largest admitted live (non-terminal) outbound backlog per sender.
pub const MAX_PEER_OUTSTANDING_PER_SENDER: usize = 512;
/// Largest admitted live (non-terminal) inbound backlog per recipient.
pub const MAX_PEER_OUTSTANDING_PER_RECIPIENT: usize = 512;
/// Largest admitted board head count per scope.
pub const MAX_BOARD_ENTRIES_PER_SCOPE: usize = 128;
/// Largest admitted revision chain per board entry.
pub const MAX_BOARD_REVISIONS_PER_ENTRY: usize = 32;
/// Largest admitted page slice per frozen board read.
pub const MAX_BOARD_PAGE_SIZE: u64 = 50;
/// Largest retained per-message delivery attempt history.
pub const MAX_PEER_ATTEMPT_HISTORY: usize = 32;

/// Required raw fields of a peer message envelope.
pub const REQUIRED_PEER_ENVELOPE_FIELDS: &[&str] = &[
    "message_id",
    "kind",
    "stream_recipient",
    "stream_work_item",
    "sender",
    "payload_digest",
];

/// Optional raw fields of a peer message envelope.
pub const OPTIONAL_PEER_ENVELOPE_FIELDS: &[&str] =
    &["delta_kind", "scope", "revision", "expiry", "privacy"];

/// Closed normative mailbox vocabulary (I10.18 message kinds plus the
/// note/evidence/request/response/objection/review family). Work assignment
/// is deliberately absent: peers cannot assign work through this channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerMessageKind {
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

impl PeerMessageKind {
    /// Canonical wire spelling of one kind.
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
    pub fn decode(text: &str) -> Result<Self, CoordinationError> {
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
            _ => Err(CoordinationError::UnknownPeerKind(text.to_owned())),
        }
    }

    /// Exact closed denominator of the mailbox vocabulary.
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

/// Closed live-delta sub-kinds carried by [`PeerMessageKind::LivePeerDelta`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiveDeltaKind {
    RelevantFinding,
    AssumptionInvalidated,
    DependencyDiscovered,
    PlanContradiction,
    Obstacle,
    AbandonedDeadEnd,
}

impl LiveDeltaKind {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::RelevantFinding => "relevant_finding",
            Self::AssumptionInvalidated => "assumption_invalidated",
            Self::DependencyDiscovered => "dependency_discovered",
            Self::PlanContradiction => "plan_contradiction",
            Self::Obstacle => "obstacle",
            Self::AbandonedDeadEnd => "abandoned_dead_end",
        }
    }

    pub fn decode(text: &str) -> Result<Self, CoordinationError> {
        match text {
            "relevant_finding" => Ok(Self::RelevantFinding),
            "assumption_invalidated" => Ok(Self::AssumptionInvalidated),
            "dependency_discovered" => Ok(Self::DependencyDiscovered),
            "plan_contradiction" => Ok(Self::PlanContradiction),
            "obstacle" => Ok(Self::Obstacle),
            "abandoned_dead_end" => Ok(Self::AbandonedDeadEnd),
            _ => Err(CoordinationError::UnknownPeerKind(text.to_owned())),
        }
    }

    #[must_use]
    pub const fn all() -> [&'static str; 6] {
        [
            "relevant_finding",
            "assumption_invalidated",
            "dependency_discovered",
            "plan_contradiction",
            "obstacle",
            "abandoned_dead_end",
        ]
    }
}

/// Closed blackboard entry vocabulary (I10.18). The board is typed
/// facts/candidates, never a transcript or group chat.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerBoardKind {
    FindingCandidate,
    EvidenceHandle,
    Unknown,
    HypothesisCandidate,
    ConflictNotice,
    DecisionRequest,
    VerifierResult,
    ArtifactHandle,
    Blocker,
}

impl PeerBoardKind {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::FindingCandidate => "finding_candidate",
            Self::EvidenceHandle => "evidence_handle",
            Self::Unknown => "unknown",
            Self::HypothesisCandidate => "hypothesis_candidate",
            Self::ConflictNotice => "conflict_notice",
            Self::DecisionRequest => "decision_request",
            Self::VerifierResult => "verifier_result",
            Self::ArtifactHandle => "artifact_handle",
            Self::Blocker => "blocker",
        }
    }

    pub fn decode(text: &str) -> Result<Self, CoordinationError> {
        match text {
            "finding_candidate" => Ok(Self::FindingCandidate),
            "evidence_handle" => Ok(Self::EvidenceHandle),
            "unknown" => Ok(Self::Unknown),
            "hypothesis_candidate" => Ok(Self::HypothesisCandidate),
            "conflict_notice" => Ok(Self::ConflictNotice),
            "decision_request" => Ok(Self::DecisionRequest),
            "verifier_result" => Ok(Self::VerifierResult),
            "artifact_handle" => Ok(Self::ArtifactHandle),
            "blocker" => Ok(Self::Blocker),
            _ => Err(CoordinationError::UnknownPeerKind(text.to_owned())),
        }
    }

    #[must_use]
    pub const fn all() -> [&'static str; 9] {
        [
            "finding_candidate",
            "evidence_handle",
            "unknown",
            "hypothesis_candidate",
            "conflict_notice",
            "decision_request",
            "verifier_result",
            "artifact_handle",
            "blocker",
        ]
    }
}

/// Closed conflict vocabulary (I13.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerConflictType {
    Epistemic,
    State,
    Plan,
    Authority,
    Artifact,
    Instruction,
    Resource,
    Architecture,
}

impl PeerConflictType {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Epistemic => "epistemic",
            Self::State => "state",
            Self::Plan => "plan",
            Self::Authority => "authority",
            Self::Artifact => "artifact",
            Self::Instruction => "instruction",
            Self::Resource => "resource",
            Self::Architecture => "architecture",
        }
    }

    pub fn decode(text: &str) -> Result<Self, CoordinationError> {
        match text {
            "epistemic" => Ok(Self::Epistemic),
            "state" => Ok(Self::State),
            "plan" => Ok(Self::Plan),
            "authority" => Ok(Self::Authority),
            "artifact" => Ok(Self::Artifact),
            "instruction" => Ok(Self::Instruction),
            "resource" => Ok(Self::Resource),
            "architecture" => Ok(Self::Architecture),
            _ => Err(CoordinationError::UnknownPeerKind(text.to_owned())),
        }
    }

    #[must_use]
    pub const fn all() -> [&'static str; 8] {
        [
            "epistemic",
            "state",
            "plan",
            "authority",
            "artifact",
            "instruction",
            "resource",
            "architecture",
        ]
    }
}

/// Supplied structured conflict dimensions (I13.1 scope/time/terminology/
/// evidence differences). Dimensions are caller-supplied classifications;
/// the owner never infers contradiction from prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerConflictDimension {
    ScopeDifference,
    TimeDifference,
    TerminologyDifference,
    EvidenceDifference,
}

impl PeerConflictDimension {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::ScopeDifference => "scope_difference",
            Self::TimeDifference => "time_difference",
            Self::TerminologyDifference => "terminology_difference",
            Self::EvidenceDifference => "evidence_difference",
        }
    }

    pub fn decode(text: &str) -> Result<Self, CoordinationError> {
        match text {
            "scope_difference" => Ok(Self::ScopeDifference),
            "time_difference" => Ok(Self::TimeDifference),
            "terminology_difference" => Ok(Self::TerminologyDifference),
            "evidence_difference" => Ok(Self::EvidenceDifference),
            _ => Err(CoordinationError::UnknownPeerKind(text.to_owned())),
        }
    }
}

/// Structured claim acceptability inside one conflict set (I13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentAcceptability {
    Grounded,
    Contested,
    Defeated,
    AssumptionDependent,
    Undecided,
}

/// Lifecycle of one retained peer conflict (I13.2 states).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerConflictState {
    Open,
    Investigating,
    Decided,
    Superseded,
    Resolved,
}

/// Closed review target vocabulary (I10.18 anchored review).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
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

/// Closed review kind vocabulary (I10.18 anchored review).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
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

/// Review lifecycle (I10.18). Resolution stays distinct from acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerReviewLifecycle {
    Draft,
    PendingDelivery,
    Delivered,
    Answered,
    Resolved,
    RejectedWithReason,
    Stale,
    Superseded,
}

/// Supplied review completeness; expiry is derived by the owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCompleteness {
    Complete,
    Partial,
    Abstain,
}

/// Owner-derived review standing used by the expected-review denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerReviewStanding {
    Complete,
    Partial,
    Abstained,
    Expired,
}

/// Review recommendation. A recommendation never carries admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRecommendation {
    Approve,
    ApproveWithChanges,
    RequestChanges,
    Abstain,
}

/// Anchor resolution at submit time. Only exact/moved/modified anchors can
/// satisfy a required review; ambiguous/stale/deleted/unavailable anchors
/// are rejected fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnchorResolution {
    Exact,
    Moved,
    Modified,
    Ambiguous,
    Stale,
    Deleted,
    Unavailable,
}

impl AnchorResolution {
    /// Whether this resolution may back a required review.
    #[must_use]
    pub const fn satisfies_required_review(&self) -> bool {
        match self {
            Self::Exact | Self::Moved | Self::Modified => true,
            Self::Ambiguous | Self::Stale | Self::Deleted | Self::Unavailable => false,
        }
    }
}

/// Privacy classes bound to every peer record (I5.16 `privacy_class`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    Open,
    Restricted,
    Secret,
}

/// Declared embedded executable-adjacent content. Markers are admitted as
/// inert evidence only; the channel exposes no evaluation path for them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedMarkerKind {
    Command,
    ToolCall,
    Instruction,
}

/// Disposition of an embedded marker. Only the inert disposition exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarkerDisposition {
    Inert,
}

/// Authority/effect assertions a peer draft may attempt to inject. Any
/// present assertion is rejected; the enum exists so the rejection is typed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum AssertedEffect {
    AssignWork { work_item_id: String },
    GrantEffect { detail: String },
    DeclareFinish { work_item_id: String },
    DirectCommand { detail: String },
}

/// One raw decoded envelope field, in raw arrival order. The sequence
/// preserves raw duplicate keys so closed decoding can reject them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawField {
    pub name: String,
    pub value: String,
}

/// Validated header of one closed peer envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerEnvelopeHeader {
    pub message_id: String,
    pub kind: PeerMessageKind,
    pub stream_recipient: String,
    pub stream_work_item: String,
    pub sender: String,
    pub payload_digest: String,
    pub delta_kind: Option<LiveDeltaKind>,
}

/// Closed envelope decoding over a raw field sequence.
///
/// Rejects unknown schemas, unknown kinds, unknown fields, raw duplicate
/// keys, and missing required fields. Live deltas must name their sub-kind.
pub fn decode_peer_envelope(
    schema: &str,
    kind_text: &str,
    fields: &[RawField],
) -> Result<PeerEnvelopeHeader, CoordinationError> {
    if schema != PEER_MESSAGE_SCHEMA {
        return Err(CoordinationError::UnknownPeerSchema(schema.to_owned()));
    }
    let kind = PeerMessageKind::decode(kind_text)?;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for field in fields {
        if !seen.insert(field.name.as_str()) {
            return Err(CoordinationError::DuplicatePeerField(field.name.clone()));
        }
        let allowed = REQUIRED_PEER_ENVELOPE_FIELDS
            .iter()
            .chain(OPTIONAL_PEER_ENVELOPE_FIELDS.iter())
            .any(|name| *name == field.name.as_str());
        if !allowed {
            return Err(CoordinationError::UnknownPeerField(field.name.clone()));
        }
        values.insert(field.name.as_str(), field.value.as_str());
    }
    let mut required = BTreeMap::new();
    for name in REQUIRED_PEER_ENVELOPE_FIELDS {
        match values.get(name) {
            Some(value) => {
                required.insert(*name, *value);
            }
            None => return Err(CoordinationError::MissingPeerField((*name).to_owned())),
        }
    }
    let delta_kind = match values.get("delta_kind") {
        Some(text) => Some(LiveDeltaKind::decode(text)?),
        None => None,
    };
    if kind == PeerMessageKind::LivePeerDelta && delta_kind.is_none() {
        return Err(CoordinationError::MissingPeerField("delta_kind".to_owned()));
    }
    Ok(PeerEnvelopeHeader {
        message_id: required["message_id"].to_owned(),
        kind,
        stream_recipient: required["stream_recipient"].to_owned(),
        stream_work_item: required["stream_work_item"].to_owned(),
        sender: required["sender"].to_owned(),
        payload_digest: required["payload_digest"].to_owned(),
        delta_kind,
    })
}

/// Injected time source. Callers supply time; the channel keeps no clock.
pub trait PeerClockPort {
    /// Supplied time in milliseconds on the owner's time base.
    fn now_ms(&self) -> u64;
}

/// Durability attestation of the backing owner behind the channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum PeerDurabilityAttestation {
    Durable { owner_receipt: String },
    VolatileMemoryOnly,
    Unavailable { reason: String },
}

/// Injected durability source. Admission records the attested ceiling and
/// never claims persistence the backing owner did not attest.
pub trait PeerDurabilityPort {
    fn attest(&self) -> PeerDurabilityAttestation;
}

/// Delivery target handed to the injected delivery port.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerDeliveryTarget {
    pub message_id: String,
    pub recipient_session_id: String,
    pub endpoint: String,
    pub stream_seq: u64,
}

/// Outcome reported back by the injected delivery port.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum PeerDeliveryAttempt {
    Delivered { endpoint: String },
    Unavailable { reason: String },
    Unknown { reason: String },
}

/// Injected delivery source. The channel stages, orders and records; the
/// port alone performs the single delivery step.
pub trait PeerDeliveryPort {
    fn attempt(&mut self, target: &PeerDeliveryTarget) -> PeerDeliveryAttempt;
}

/// Recorded durability ceiling of one admitted peer record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum PeerDurability {
    Durable { owner_receipt: String },
    Volatile,
    Unavailable { reason: String },
}

impl PeerDurability {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Durable { .. } => "durable",
            Self::Volatile => "volatile",
            Self::Unavailable { .. } => "unavailable",
        }
    }
}

/// Identity of one ordered mailbox stream: one recipient task queue.
/// Ordering is per stream only; the channel keeps no fabricated global order.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerStreamId {
    pub recipient_session_id: String,
    pub work_item_id: String,
}

impl PeerStreamId {
    /// Stable key used in diagnostics and backpressure reports.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.recipient_session_id, self.work_item_id)
    }
}

/// Cursor key: one recipient generation holds one cursor per stream, so a
/// generation/session change never inherits old acknowledgements.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerCursorKey {
    pub recipient_session_id: String,
    pub stream: PeerStreamId,
}

/// Per-stream admission head: next sequence to assign and admitted count.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerStreamHead {
    pub stream: PeerStreamId,
    pub next_seq: u64,
    pub admitted: u64,
}

/// Durable per-recipient stream cursor: next expected sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerCursor {
    pub key: PeerCursorKey,
    pub next_expected_seq: u64,
    pub last_reconciled_at: u64,
}

/// Live-delivery lifecycle of one mailbox message. Rejected/not-enqueued
/// never becomes a record; recorded, delivery-attempted, delivered,
/// acknowledged, consumed, expired, cancelled, unavailable and unknown stay
/// distinct. Acknowledgement covers one exact message revision only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum PeerMessageState {
    Staged,
    DeliveryAttempted {
        attempts: u32,
    },
    Delivered {
        endpoint: String,
    },
    Acknowledged {
        revision: u64,
        by_session: String,
    },
    Consumed {
        evidence_handle: String,
        by_session: String,
    },
    Expired {
        at: u64,
    },
    Cancelled {
        by_session: String,
        at: u64,
    },
    Unavailable {
        reason: String,
    },
    Unknown {
        reason: String,
    },
}

impl PeerMessageState {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::DeliveryAttempted { .. } => "delivery_attempted",
            Self::Delivered { .. } => "delivered",
            Self::Acknowledged { .. } => "acknowledged",
            Self::Consumed { .. } => "consumed",
            Self::Expired { .. } => "expired",
            Self::Cancelled { .. } => "cancelled",
            Self::Unavailable { .. } => "unavailable",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Terminal states admit no further delivery protocol transition.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        match self {
            Self::Staged
            | Self::DeliveryAttempted { .. }
            | Self::Delivered { .. }
            | Self::Acknowledged { .. }
            | Self::Unavailable { .. }
            | Self::Unknown { .. } => true,
            Self::Consumed { .. } | Self::Expired { .. } | Self::Cancelled { .. } => false,
        }
    }
}

/// Declared embedded marker admitted as inert evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedMarker {
    pub marker: EmbeddedMarkerKind,
    pub detail: String,
    pub disposition: MarkerDisposition,
}

/// One recorded delivery attempt outcome (bounded history per message).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerAttemptRecord {
    pub attempt: u32,
    pub at: u64,
    pub outcome: PeerDeliveryAttempt,
}

/// One admitted mailbox message with its exact identity, ordering,
/// durability ceiling and live-delivery protocol state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerMessage {
    pub message_id: String,
    pub request_id: String,
    pub kind: PeerMessageKind,
    pub delta_kind: Option<LiveDeltaKind>,
    pub stream: PeerStreamId,
    pub stream_seq: u64,
    pub predecessor: Option<u64>,
    pub sender_session_id: String,
    pub scope: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub payload_handle: Option<String>,
    pub inline_text: Option<String>,
    pub evidence_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub privacy: PrivacyClass,
    pub disclosure_handle: Option<String>,
    pub revision: u64,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub embedded: Vec<EmbeddedMarker>,
    pub durability: PeerDurability,
    pub state: PeerMessageState,
    pub attempts: u32,
    pub duplicate_deliveries: u32,
    pub acknowledged_revision: Option<u64>,
    pub acknowledged_by: Option<String>,
    pub attempt_history: Vec<PeerAttemptRecord>,
}

impl PeerMessage {
    /// Whether this message still occupies live queue depth.
    #[must_use]
    pub const fn occupies_depth(&self) -> bool {
        matches!(
            self.state,
            PeerMessageState::Staged
                | PeerMessageState::DeliveryAttempted { .. }
                | PeerMessageState::Unknown { .. }
        )
    }

    /// Redacted diagnostic view: inline text survives only for open
    /// privacy; digests and handles are non-disclosing and retained.
    #[must_use]
    pub fn diagnostic(&self) -> PeerMessageDiagnostic {
        let (inline_text, redacted) = match self.privacy {
            PrivacyClass::Open => (self.inline_text.clone(), false),
            PrivacyClass::Restricted | PrivacyClass::Secret => (None, true),
        };
        PeerMessageDiagnostic {
            message_id: self.message_id.clone(),
            kind: self.kind.as_wire().to_owned(),
            stream: self.stream.key(),
            stream_seq: self.stream_seq,
            revision: self.revision,
            state: self.state.as_wire().to_owned(),
            durability: self.durability.as_wire().to_owned(),
            payload_digest: self.payload_digest.clone(),
            inline_text,
            redacted,
        }
    }
}

/// Non-disclosing diagnostic projection of one mailbox message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerMessageDiagnostic {
    pub message_id: String,
    pub kind: String,
    pub stream: String,
    pub stream_seq: u64,
    pub revision: u64,
    pub state: String,
    pub durability: String,
    pub payload_digest: String,
    pub inline_text: Option<String>,
    pub redacted: bool,
}

/// Caller-supplied mailbox admission draft. Time arrives only through the
/// injected clock port; the draft carries no clock of its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnqueuePeerMessage {
    pub request_id: String,
    pub message_id: String,
    pub kind: PeerMessageKind,
    pub delta_kind: Option<LiveDeltaKind>,
    pub sender_session_id: String,
    pub recipient_session_id: String,
    pub scope: String,
    pub work_item_id: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub payload_handle: Option<String>,
    pub inline_text: Option<String>,
    pub evidence_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub privacy: PrivacyClass,
    pub disclosure_handle: Option<String>,
    pub revision: u64,
    pub expires_at: Option<u64>,
    pub embedded: Vec<EmbeddedMarkerDraft>,
    pub asserted: Option<AssertedEffect>,
}

/// Declared embedded marker on an admission draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedMarkerDraft {
    pub marker: EmbeddedMarkerKind,
    pub detail: String,
}

/// Admission receipt: the stored record, its causal event, the attested
/// durability ceiling, and whether the call replayed an existing entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerEnqueueReceipt {
    pub message: PeerMessage,
    pub event: super::CoordinationEvent,
    pub durability: PeerDurability,
    pub replayed: bool,
}

/// Delivery receipt for one port-driven delivery step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerDeliveryReceipt {
    pub message_id: String,
    pub stream_seq: u64,
    pub outcome: PeerDeliveryAttempt,
    pub attempts: u32,
    pub duplicate: bool,
}

/// Acknowledgement receipt for one exact message revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerAckReceipt {
    pub message_id: String,
    pub revision: u64,
    pub by_session: String,
    pub replayed: bool,
}

/// Consumption receipt for one explicitly evidenced read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerConsumeReceipt {
    pub message_id: String,
    pub evidence_handle: String,
    pub by_session: String,
}

/// Endpoint-loss report: messages that became unknown and stay reconcilable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerEndpointLossReport {
    pub session_id: String,
    pub marked_unknown: Vec<String>,
    pub at: u64,
}

/// Reconnect report: same semantic entries replayed in stream order with
/// the visible gap set and the adopted cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerReconnectReport {
    pub session_id: String,
    pub replayed: Vec<String>,
    pub gaps: Vec<u64>,
    pub cursor: PeerCursor,
}

/// Deterministic digest over ordered string parts (FNV-1a, hex).
#[must_use]
pub fn peer_digest_hex(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn empty_clock() -> ClockReading {
    ClockReading {
        valid_time_ms: None,
        known_time_ms: None,
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

/// Records the attested durability ceiling without ever claiming
/// persistence the backing port did not attest.
fn attest_peer_durability(
    durability: &dyn PeerDurabilityPort,
) -> Result<PeerDurability, CoordinationError> {
    match durability.attest() {
        PeerDurabilityAttestation::Durable { owner_receipt } => {
            peer_text(&owner_receipt, "owner_receipt")?;
            Ok(PeerDurability::Durable { owner_receipt })
        }
        PeerDurabilityAttestation::VolatileMemoryOnly => Ok(PeerDurability::Volatile),
        PeerDurabilityAttestation::Unavailable { reason } => {
            peer_text(&reason, "durability_reason")?;
            Ok(PeerDurability::Unavailable { reason })
        }
    }
}

fn peer_text(value: &str, field: &'static str) -> Result<(), CoordinationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoordinationError::InvalidField(field));
    }
    Ok(())
}

fn peer_epoch_is_stale(requested: &EpochId, known: &EpochId) -> bool {
    // `relation_to` reports `known` relative to `requested`: a known direct
    // child (or newer same-lineage epoch) means the request rides a stale
    // term; an unrelated lineage is never current.
    match requested.relation_to(known) {
        EpochRelation::Same | EpochRelation::DirectParent | EpochRelation::SameLineageOlder => {
            false
        }
        EpochRelation::DirectChild
        | EpochRelation::SameLineageNewer
        | EpochRelation::UnrelatedLineage => true,
    }
}

impl CoordinationOwner {
    fn peer_sender(
        &self,
        session_id: &str,
        epoch: &EpochId,
        fence: &StateFence,
        now: u64,
    ) -> Result<(), CoordinationError> {
        let known = self
            .sessions
            .get(session_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "session",
                id: session_id.to_owned(),
            })?;
        if peer_epoch_is_stale(epoch, &known.authority_epoch) {
            return Err(CoordinationError::EpochMismatch);
        }
        if !known.authority_epoch.is_same_authority(epoch)
            || !known.state_fence.is_compatible_with(fence)
            || known.state != super::SessionState::Active
        {
            return Err(CoordinationError::FenceMismatch);
        }
        if known.heartbeat_deadline == 0 || known.last_heartbeat > known.heartbeat_deadline {
            return Err(CoordinationError::InvalidField("heartbeat_deadline"));
        }
        if known.last_heartbeat > now {
            return Err(CoordinationError::InvalidField("last_heartbeat"));
        }
        if now > known.heartbeat_deadline {
            return Err(CoordinationError::SessionExpired);
        }
        Ok(())
    }

    fn peer_recipient_live(&self, session_id: &str, now: u64) -> bool {
        self.sessions.get(session_id).is_some_and(|known| {
            known.state == super::SessionState::Active
                && known.heartbeat_deadline != 0
                && known.last_heartbeat <= known.heartbeat_deadline
                && known.last_heartbeat <= now
                && now <= known.heartbeat_deadline
        })
    }

    fn peer_message_exact_replay(
        &self,
        request_id: &str,
        draft: &EnqueuePeerMessage,
    ) -> Result<Option<PeerEnqueueReceipt>, CoordinationError> {
        let Some(message_id) = self.peer_request_index.get(request_id) else {
            return Ok(None);
        };
        let stored = self
            .peer_messages
            .get(message_id)
            .ok_or(CoordinationError::InvalidState)?;
        let identical = stored.kind == draft.kind
            && stored.delta_kind == draft.delta_kind
            && stored.stream.recipient_session_id == draft.recipient_session_id
            && stored.stream.work_item_id == draft.work_item_id
            && stored.sender_session_id == draft.sender_session_id
            && stored.scope == draft.scope
            && stored.payload_digest == draft.payload_digest
            && stored.payload_bytes == draft.payload_bytes
            && stored.payload_handle == draft.payload_handle
            && stored.inline_text == draft.inline_text
            && stored.evidence_refs == draft.evidence_refs
            && stored.artifact_refs == draft.artifact_refs
            && stored.privacy == draft.privacy
            && stored.disclosure_handle == draft.disclosure_handle
            && stored.revision == draft.revision
            && stored.expires_at == draft.expires_at;
        if !identical {
            return Err(CoordinationError::PeerSemanticConflict(
                draft.message_id.clone(),
            ));
        }
        let event = self
            .event_by_request
            .get(request_id)
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        Ok(Some(PeerEnqueueReceipt {
            message: stored.clone(),
            event,
            durability: stored.durability.clone(),
            replayed: true,
        }))
    }

    fn peer_live_depth(&self, stream: &PeerStreamId) -> usize {
        self.peer_messages
            .values()
            .filter(|message| message.stream == *stream && message.occupies_depth())
            .count()
    }

    fn peer_outstanding_from(&self, sender: &str) -> usize {
        self.peer_messages
            .values()
            .filter(|message| {
                message.sender_session_id == sender
                    && matches!(
                        message.state,
                        PeerMessageState::Staged
                            | PeerMessageState::DeliveryAttempted { .. }
                            | PeerMessageState::Unknown { .. }
                    )
            })
            .count()
    }

    fn peer_outstanding_for(&self, recipient: &str) -> usize {
        self.peer_messages
            .values()
            .filter(|message| {
                message.stream.recipient_session_id == recipient
                    && matches!(
                        message.state,
                        PeerMessageState::Staged
                            | PeerMessageState::DeliveryAttempted { .. }
                            | PeerMessageState::Unknown { .. }
                    )
            })
            .count()
    }

    fn peer_expire_if_due(&mut self, message_id: &str, now: u64) -> Result<(), CoordinationError> {
        let due = self.peer_messages.get(message_id).is_some_and(|message| {
            message.state.is_live() && message.expires_at.is_some_and(|expiry| now >= expiry)
        });
        if due {
            if let Some(message) = self.peer_messages.get_mut(message_id) {
                message.state = PeerMessageState::Expired { at: now };
            }
            return Err(CoordinationError::PeerExpired(message_id.to_owned()));
        }
        Ok(())
    }

    fn peer_push_attempt(
        &mut self,
        message_id: &str,
        at: u64,
        outcome: PeerDeliveryAttempt,
    ) -> Result<(), CoordinationError> {
        let message = self
            .peer_messages
            .get_mut(message_id)
            .ok_or(CoordinationError::InvalidState)?;
        message.attempts = message.attempts.saturating_add(1);
        message.attempt_history.push(PeerAttemptRecord {
            attempt: message.attempts,
            at,
            outcome,
        });
        while message.attempt_history.len() > MAX_PEER_ATTEMPT_HISTORY {
            message.attempt_history.remove(0);
        }
        Ok(())
    }

    /// Validates one mailbox draft against identity, role, audience, size,
    /// privacy and expiry. Returns whether the recipient is currently live;
    /// a lapsed recipient still records, marked unavailable.
    fn validate_enqueue_draft(
        &self,
        draft: &EnqueuePeerMessage,
        now: u64,
    ) -> Result<bool, CoordinationError> {
        peer_text(&draft.request_id, "request_id")?;
        peer_text(&draft.message_id, "message_id")?;
        peer_text(&draft.sender_session_id, "sender_session_id")?;
        peer_text(&draft.recipient_session_id, "recipient_session_id")?;
        peer_text(&draft.scope, "scope")?;
        peer_text(&draft.work_item_id, "work_item_id")?;
        peer_text(&draft.payload_digest, "payload_digest")?;
        if draft.asserted.is_some() {
            return Err(CoordinationError::PeerAuthorityRejected(
                draft.message_id.clone(),
            ));
        }
        self.common(draft.authority_epoch.clone(), &draft.state_fence)?;
        self.peer_sender(
            &draft.sender_session_id,
            &draft.authority_epoch,
            &draft.state_fence,
            now,
        )?;
        if !self.sessions.contains_key(&draft.recipient_session_id) {
            return Err(CoordinationError::NotFound {
                kind: "session",
                id: draft.recipient_session_id.clone(),
            });
        }
        let recipient_live = self.peer_recipient_live(&draft.recipient_session_id, now);
        if !self.work.contains_key(&draft.work_item_id) {
            return Err(CoordinationError::NotFound {
                kind: "work_item",
                id: draft.work_item_id.clone(),
            });
        }
        if draft.privacy == PrivacyClass::Secret
            && draft.disclosure_handle.as_deref().is_none_or(str::is_empty)
        {
            return Err(CoordinationError::PeerPrivacyDenied(
                draft.message_id.clone(),
            ));
        }
        if draft.revision == 0 {
            return Err(CoordinationError::InvalidField("revision"));
        }
        if draft.kind == PeerMessageKind::LivePeerDelta && draft.delta_kind.is_none() {
            return Err(CoordinationError::MissingPeerField("delta_kind".to_owned()));
        }
        if draft.payload_bytes > MAX_PEER_MESSAGE_BYTES {
            return Err(CoordinationError::InvalidField("payload_bytes"));
        }
        if draft
            .inline_text
            .as_ref()
            .is_some_and(|text| text.len() > MAX_PEER_INLINE_TEXT)
        {
            return Err(CoordinationError::InvalidField("inline_text"));
        }
        if draft.evidence_refs.len() > MAX_PEER_REFERENCES
            || draft.artifact_refs.len() > MAX_PEER_REFERENCES
        {
            return Err(CoordinationError::InvalidField("peer_references"));
        }
        for reference in draft.evidence_refs.iter().chain(draft.artifact_refs.iter()) {
            peer_text(reference, "peer_reference")?;
        }
        if let Some(handle) = draft.payload_handle.as_deref() {
            peer_text(handle, "payload_handle")?;
        }
        if let Some(handle) = draft.disclosure_handle.as_deref() {
            peer_text(handle, "disclosure_handle")?;
        }
        for marker in &draft.embedded {
            peer_text(&marker.detail, "embedded_marker")?;
        }
        if draft.expires_at.is_some_and(|expiry| now >= expiry) {
            return Err(CoordinationError::PeerExpired(draft.message_id.clone()));
        }
        Ok(recipient_live)
    }

    /// Replays an identical draft or rejects a changed same-ID draft.
    /// Returns `None` when the draft is new to the owner.
    fn replay_enqueue_draft(
        &self,
        draft: &EnqueuePeerMessage,
    ) -> Result<Option<PeerEnqueueReceipt>, CoordinationError> {
        if let Some(replayed) = self.peer_message_exact_replay(&draft.request_id, draft)? {
            return Ok(Some(replayed));
        }
        if let Some(stored) = self.peer_messages.get(&draft.message_id) {
            let identical = stored.kind == draft.kind
                && stored.delta_kind == draft.delta_kind
                && stored.stream.recipient_session_id == draft.recipient_session_id
                && stored.stream.work_item_id == draft.work_item_id
                && stored.sender_session_id == draft.sender_session_id
                && stored.scope == draft.scope
                && stored.payload_digest == draft.payload_digest
                && stored.revision == draft.revision
                && stored.expires_at == draft.expires_at;
            if identical {
                let event = self
                    .event_by_request
                    .values()
                    .find(|event| {
                        event.kind == CoordinationEventKind::MessageSent
                            && event.subject_id == draft.message_id
                    })
                    .cloned()
                    .ok_or(CoordinationError::InvalidState)?;
                return Ok(Some(PeerEnqueueReceipt {
                    message: stored.clone(),
                    event,
                    durability: stored.durability.clone(),
                    replayed: true,
                }));
            }
            return Err(CoordinationError::PeerSemanticConflict(
                draft.message_id.clone(),
            ));
        }
        Ok(None)
    }

    /// Enforces the independent stream-depth and outstanding ceilings.
    fn check_enqueue_backpressure(
        &self,
        draft: &EnqueuePeerMessage,
        stream: &PeerStreamId,
    ) -> Result<(), CoordinationError> {
        if self.peer_live_depth(stream) >= MAX_PEER_STREAM_DEPTH {
            return Err(CoordinationError::PeerBackpressure {
                scope: stream.key(),
                limit: MAX_PEER_STREAM_DEPTH,
            });
        }
        if self.peer_outstanding_from(&draft.sender_session_id) >= MAX_PEER_OUTSTANDING_PER_SENDER {
            return Err(CoordinationError::PeerBackpressure {
                scope: draft.sender_session_id.clone(),
                limit: MAX_PEER_OUTSTANDING_PER_SENDER,
            });
        }
        if self.peer_outstanding_for(&draft.recipient_session_id)
            >= MAX_PEER_OUTSTANDING_PER_RECIPIENT
        {
            return Err(CoordinationError::PeerBackpressure {
                scope: draft.recipient_session_id.clone(),
                limit: MAX_PEER_OUTSTANDING_PER_RECIPIENT,
            });
        }
        Ok(())
    }

    /// Admits one peer mailbox message through the existing owner.
    ///
    /// Admission validates identity, role, audience, size, privacy and
    /// expiry, records through the existing causal event log, and stores the
    /// attested durability ceiling without ever claiming persistence the
    /// backing port did not attest. Exact replays return the single semantic
    /// entry; changed payload/audience/scope/revision/expiry conflict.
    pub fn enqueue_peer_message(
        &mut self,
        draft: &EnqueuePeerMessage,
        clock: &dyn PeerClockPort,
        durability: &dyn PeerDurabilityPort,
    ) -> Result<PeerEnqueueReceipt, CoordinationError> {
        let now = clock.now_ms();
        let recipient_live = self.validate_enqueue_draft(draft, now)?;
        if let Some(replayed) = self.replay_enqueue_draft(draft)? {
            return Ok(replayed);
        }
        let stream = PeerStreamId {
            recipient_session_id: draft.recipient_session_id.clone(),
            work_item_id: draft.work_item_id.clone(),
        };
        self.check_enqueue_backpressure(draft, &stream)?;
        let recorded = attest_peer_durability(durability)?;
        self.admit_enqueue_message(draft, stream, recorded, recipient_live, now)
    }

    /// Assigns the per-stream sequence and records one validated draft with
    /// its causal event, durability ceiling and recipient cursor.
    fn admit_enqueue_message(
        &mut self,
        draft: &EnqueuePeerMessage,
        stream: PeerStreamId,
        recorded: PeerDurability,
        recipient_live: bool,
        now: u64,
    ) -> Result<PeerEnqueueReceipt, CoordinationError> {
        let head = self
            .peer_streams
            .entry(stream.clone())
            .or_insert_with(|| PeerStreamHead {
                stream: stream.clone(),
                next_seq: 1,
                admitted: 0,
            });
        let seq = head.next_seq;
        let predecessor = if seq > 1 { Some(seq - 1) } else { None };
        head.next_seq = seq.saturating_add(1);
        head.admitted = head.admitted.saturating_add(1);
        let embedded = draft
            .embedded
            .iter()
            .map(|marker| EmbeddedMarker {
                marker: marker.marker,
                detail: marker.detail.clone(),
                disposition: MarkerDisposition::Inert,
            })
            .collect();
        let state = if recipient_live {
            PeerMessageState::Staged
        } else {
            PeerMessageState::Unavailable {
                reason: format!(
                    "recipient session {} is not active",
                    draft.recipient_session_id
                ),
            }
        };
        let message = PeerMessage {
            message_id: draft.message_id.clone(),
            request_id: draft.request_id.clone(),
            kind: draft.kind,
            delta_kind: draft.delta_kind,
            stream: stream.clone(),
            stream_seq: seq,
            predecessor,
            sender_session_id: draft.sender_session_id.clone(),
            scope: draft.scope.clone(),
            authority_epoch: draft.authority_epoch.clone(),
            state_fence: draft.state_fence.clone(),
            payload_digest: draft.payload_digest.clone(),
            payload_bytes: draft.payload_bytes,
            payload_handle: draft.payload_handle.clone(),
            inline_text: draft.inline_text.clone(),
            evidence_refs: draft.evidence_refs.clone(),
            artifact_refs: draft.artifact_refs.clone(),
            privacy: draft.privacy,
            disclosure_handle: draft.disclosure_handle.clone(),
            revision: draft.revision,
            created_at: now,
            expires_at: draft.expires_at,
            embedded,
            durability: recorded.clone(),
            state,
            attempts: 0,
            duplicate_deliveries: 0,
            acknowledged_revision: None,
            acknowledged_by: None,
            attempt_history: Vec::new(),
        };
        let event = self.event(
            &draft.request_id,
            format!("peer-message:{}", draft.message_id),
            CoordinationEventKind::MessageSent,
            draft.message_id.clone(),
            draft.sender_session_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            draft.authority_epoch.clone(),
            draft.state_fence.clone(),
            draft.payload_digest.clone(),
            empty_clock(),
        )?;
        let event = self.commit(&draft.request_id, event)?;
        self.peer_messages
            .insert(draft.message_id.clone(), message.clone());
        self.peer_request_index
            .insert(draft.request_id.clone(), draft.message_id.clone());
        let cursor_key = PeerCursorKey {
            recipient_session_id: draft.recipient_session_id.clone(),
            stream,
        };
        self.peer_cursors
            .entry(cursor_key.clone())
            .or_insert(PeerCursor {
                key: cursor_key,
                next_expected_seq: 1,
                last_reconciled_at: now,
            });
        Ok(PeerEnqueueReceipt {
            message,
            event,
            durability: recorded,
            replayed: false,
        })
    }

    /// Records one injected delivery step for an admitted message.
    ///
    /// Out-of-order delivery is admitted and stays visible through the
    /// stream gap query; redelivery of an already observed message is
    /// preserved as a counted late duplicate without changing protocol
    /// state. Expiry is evaluated against the supplied clock first.
    pub fn attempt_peer_delivery(
        &mut self,
        message_id: &str,
        endpoint: &str,
        clock: &dyn PeerClockPort,
        delivery: &mut dyn PeerDeliveryPort,
    ) -> Result<PeerDeliveryReceipt, CoordinationError> {
        peer_text(message_id, "message_id")?;
        peer_text(endpoint, "endpoint")?;
        let now = clock.now_ms();
        if self.peer_expire_if_due(message_id, now).is_err() {
            return Err(CoordinationError::PeerExpired(message_id.to_owned()));
        }
        let snapshot = self.peer_messages.get(message_id).cloned().ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_message",
                id: message_id.to_owned(),
            }
        })?;
        match &snapshot.state {
            PeerMessageState::Delivered { .. }
            | PeerMessageState::Acknowledged { .. }
            | PeerMessageState::Consumed { .. } => {
                self.peer_push_attempt(
                    message_id,
                    now,
                    PeerDeliveryAttempt::Delivered {
                        endpoint: endpoint.to_owned(),
                    },
                )?;
                let stored = self
                    .peer_messages
                    .get_mut(message_id)
                    .ok_or(CoordinationError::InvalidState)?;
                stored.duplicate_deliveries = stored.duplicate_deliveries.saturating_add(1);
                let attempts = stored.attempts;
                let seq = stored.stream_seq;
                return Ok(PeerDeliveryReceipt {
                    message_id: message_id.to_owned(),
                    stream_seq: seq,
                    outcome: PeerDeliveryAttempt::Delivered {
                        endpoint: endpoint.to_owned(),
                    },
                    attempts,
                    duplicate: true,
                });
            }
            PeerMessageState::Cancelled { .. } => {
                return Err(CoordinationError::InvalidState);
            }
            PeerMessageState::Expired { .. } => {
                return Err(CoordinationError::PeerExpired(message_id.to_owned()));
            }
            PeerMessageState::Staged
            | PeerMessageState::DeliveryAttempted { .. }
            | PeerMessageState::Unavailable { .. }
            | PeerMessageState::Unknown { .. } => {}
        }
        let target = PeerDeliveryTarget {
            message_id: message_id.to_owned(),
            recipient_session_id: snapshot.stream.recipient_session_id.clone(),
            endpoint: endpoint.to_owned(),
            stream_seq: snapshot.stream_seq,
        };
        let outcome = delivery.attempt(&target);
        self.peer_push_attempt(message_id, now, outcome.clone())?;
        let stored = self
            .peer_messages
            .get_mut(message_id)
            .ok_or(CoordinationError::InvalidState)?;
        stored.state = match &outcome {
            PeerDeliveryAttempt::Delivered { endpoint } => PeerMessageState::Delivered {
                endpoint: endpoint.clone(),
            },
            PeerDeliveryAttempt::Unavailable { reason } => PeerMessageState::Unavailable {
                reason: reason.clone(),
            },
            PeerDeliveryAttempt::Unknown { reason } => PeerMessageState::Unknown {
                reason: reason.clone(),
            },
        };
        let attempts = stored.attempts;
        let seq = stored.stream_seq;
        Ok(PeerDeliveryReceipt {
            message_id: message_id.to_owned(),
            stream_seq: seq,
            outcome,
            attempts,
            duplicate: false,
        })
    }

    /// Acknowledges one exact message revision.
    ///
    /// Acknowledgement proves only that revision reached the recipient; it
    /// is never agreement, use, or completion. Acknowledgements arriving
    /// after endpoint loss reconcile the same unknown message instead of
    /// creating a new entry.
    pub fn acknowledge_peer_message(
        &mut self,
        message_id: &str,
        revision: u64,
        by_session: &str,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerAckReceipt, CoordinationError> {
        peer_text(message_id, "message_id")?;
        peer_text(by_session, "by_session")?;
        if self.peer_expire_if_due(message_id, clock.now_ms()).is_err() {
            return Err(CoordinationError::PeerExpired(message_id.to_owned()));
        }
        let snapshot = self.peer_messages.get(message_id).cloned().ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_message",
                id: message_id.to_owned(),
            }
        })?;
        if snapshot.stream.recipient_session_id != by_session {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: snapshot.stream.recipient_session_id.clone(),
            });
        }
        if revision != snapshot.revision {
            return Err(CoordinationError::PeerSemanticConflict(
                message_id.to_owned(),
            ));
        }
        match &snapshot.state {
            PeerMessageState::Delivered { .. }
            | PeerMessageState::Unknown { .. }
            | PeerMessageState::Acknowledged { .. }
            | PeerMessageState::Consumed { .. } => {}
            PeerMessageState::Staged
            | PeerMessageState::DeliveryAttempted { .. }
            | PeerMessageState::Unavailable { .. }
            | PeerMessageState::Cancelled { .. } => {
                return Err(CoordinationError::InvalidState);
            }
            PeerMessageState::Expired { .. } => {
                return Err(CoordinationError::PeerExpired(message_id.to_owned()));
            }
        }
        if snapshot.state
            == (PeerMessageState::Acknowledged {
                revision,
                by_session: by_session.to_owned(),
            })
            || matches!(snapshot.state, PeerMessageState::Consumed { .. })
        {
            return Ok(PeerAckReceipt {
                message_id: message_id.to_owned(),
                revision,
                by_session: by_session.to_owned(),
                replayed: true,
            });
        }
        let stored = self
            .peer_messages
            .get_mut(message_id)
            .ok_or(CoordinationError::InvalidState)?;
        stored.state = PeerMessageState::Acknowledged {
            revision,
            by_session: by_session.to_owned(),
        };
        stored.acknowledged_revision = Some(revision);
        stored.acknowledged_by = Some(by_session.to_owned());
        Ok(PeerAckReceipt {
            message_id: message_id.to_owned(),
            revision,
            by_session: by_session.to_owned(),
            replayed: false,
        })
    }

    /// Records one explicitly evidenced read after acknowledgement.
    /// Consumption requires an evidence handle and never follows from
    /// delivery or acknowledgement alone.
    pub fn consume_peer_message(
        &mut self,
        message_id: &str,
        by_session: &str,
        evidence_handle: &str,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerConsumeReceipt, CoordinationError> {
        peer_text(message_id, "message_id")?;
        peer_text(by_session, "by_session")?;
        peer_text(evidence_handle, "evidence_handle")?;
        if self.peer_expire_if_due(message_id, clock.now_ms()).is_err() {
            return Err(CoordinationError::PeerExpired(message_id.to_owned()));
        }
        let snapshot = self.peer_messages.get(message_id).cloned().ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_message",
                id: message_id.to_owned(),
            }
        })?;
        if snapshot.stream.recipient_session_id != by_session {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: snapshot.stream.recipient_session_id.clone(),
            });
        }
        match &snapshot.state {
            PeerMessageState::Acknowledged { .. } => {}
            PeerMessageState::Unknown { .. } => {
                return Err(CoordinationError::PeerDeliveryUnknown(
                    message_id.to_owned(),
                ));
            }
            _ => return Err(CoordinationError::InvalidState),
        }
        let stored = self
            .peer_messages
            .get_mut(message_id)
            .ok_or(CoordinationError::InvalidState)?;
        stored.state = PeerMessageState::Consumed {
            evidence_handle: evidence_handle.to_owned(),
            by_session: by_session.to_owned(),
        };
        Ok(PeerConsumeReceipt {
            message_id: message_id.to_owned(),
            evidence_handle: evidence_handle.to_owned(),
            by_session: by_session.to_owned(),
        })
    }

    /// Cancels one staged message. Only the sender cancels, and cancellation
    /// can never retract observed evidence: delivered, acknowledged or
    /// consumed messages reject retraction.
    pub fn cancel_peer_message(
        &mut self,
        message_id: &str,
        by_session: &str,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerMessage, CoordinationError> {
        peer_text(message_id, "message_id")?;
        peer_text(by_session, "by_session")?;
        let now = clock.now_ms();
        let snapshot = self.peer_messages.get(message_id).cloned().ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_message",
                id: message_id.to_owned(),
            }
        })?;
        if snapshot.sender_session_id != by_session {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: snapshot.sender_session_id.clone(),
            });
        }
        match &snapshot.state {
            PeerMessageState::Staged
            | PeerMessageState::DeliveryAttempted { .. }
            | PeerMessageState::Unknown { .. }
            | PeerMessageState::Unavailable { .. } => {}
            PeerMessageState::Delivered { .. }
            | PeerMessageState::Acknowledged { .. }
            | PeerMessageState::Consumed { .. } => {
                return Err(CoordinationError::PeerRetractionRejected(
                    message_id.to_owned(),
                ));
            }
            PeerMessageState::Expired { .. } | PeerMessageState::Cancelled { .. } => {
                return Err(CoordinationError::InvalidState);
            }
        }
        let stored = self
            .peer_messages
            .get_mut(message_id)
            .ok_or(CoordinationError::InvalidState)?;
        stored.state = PeerMessageState::Cancelled {
            by_session: by_session.to_owned(),
            at: now,
        };
        Ok(stored.clone())
    }

    /// Marks in-flight and delivered-but-unacked traffic of one endpoint as
    /// unknown after a possible send. Unknown messages stay reconcilable;
    /// nothing is dropped or duplicated.
    pub fn note_peer_endpoint_loss(
        &mut self,
        session_id: &str,
        reason: &str,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerEndpointLossReport, CoordinationError> {
        peer_text(session_id, "session_id")?;
        peer_text(reason, "reason")?;
        let now = clock.now_ms();
        let mut marked = Vec::new();
        for message in self.peer_messages.values_mut() {
            let touches = message.sender_session_id == session_id
                || message.stream.recipient_session_id == session_id;
            let in_flight = matches!(
                message.state,
                PeerMessageState::DeliveryAttempted { .. } | PeerMessageState::Delivered { .. }
            );
            if touches && in_flight {
                message.state = PeerMessageState::Unknown {
                    reason: reason.to_owned(),
                };
                marked.push(message.message_id.clone());
            }
        }
        marked.sort();
        Ok(PeerEndpointLossReport {
            session_id: session_id.to_owned(),
            marked_unknown: marked,
            at: now,
        })
    }

    /// Reconnects one recipient generation with its durable cursor.
    ///
    /// Unknown messages requeue as the same semantic entries; no new entry
    /// is admitted and the global causal sequence does not advance. A cursor
    /// past the admitted head is rejected; a new generation starts from its
    /// own cursor without inheriting old acknowledgements.
    pub fn reconnect_peer_endpoint(
        &mut self,
        session_id: &str,
        stream: &PeerStreamId,
        next_expected_seq: u64,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerReconnectReport, CoordinationError> {
        peer_text(session_id, "session_id")?;
        peer_text(&stream.recipient_session_id, "stream_recipient")?;
        peer_text(&stream.work_item_id, "stream_work_item")?;
        if next_expected_seq == 0 {
            return Err(CoordinationError::InvalidField("next_expected_seq"));
        }
        let now = clock.now_ms();
        let head_next = self
            .peer_streams
            .get(stream)
            .map_or(1, |head| head.next_seq);
        if next_expected_seq > head_next {
            return Err(CoordinationError::InvalidField("next_expected_seq"));
        }
        let key = PeerCursorKey {
            recipient_session_id: session_id.to_owned(),
            stream: stream.clone(),
        };
        let cursor = self.peer_cursors.entry(key.clone()).or_insert(PeerCursor {
            key: key.clone(),
            next_expected_seq,
            last_reconciled_at: now,
        });
        cursor.next_expected_seq = next_expected_seq;
        cursor.last_reconciled_at = now;
        let mut replayed = Vec::new();
        for message in self.peer_messages.values_mut() {
            if message.stream == *stream
                && message.stream.recipient_session_id == session_id
                && message.stream_seq >= next_expected_seq
                && matches!(
                    message.state,
                    PeerMessageState::Staged
                        | PeerMessageState::DeliveryAttempted { .. }
                        | PeerMessageState::Delivered { .. }
                        | PeerMessageState::Unknown { .. }
                        | PeerMessageState::Unavailable { .. }
                )
            {
                if matches!(message.state, PeerMessageState::Unknown { .. }) {
                    message.state = PeerMessageState::Staged;
                }
                replayed.push((message.stream_seq, message.message_id.clone()));
            }
        }
        replayed.sort();
        let replayed = replayed.into_iter().map(|(_, id)| id).collect();
        let gaps = self
            .peer_stream_gaps(stream)
            .into_iter()
            .filter(|seq| *seq >= next_expected_seq)
            .collect();
        let cursor = self
            .peer_cursors
            .get(&key)
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        Ok(PeerReconnectReport {
            session_id: session_id.to_owned(),
            replayed,
            gaps,
            cursor,
        })
    }

    /// Guards audience and scope immutability. Forwarding that would move a
    /// message across scopes or audiences is rejected; the same-target call
    /// replays the existing entry without admitting anything new.
    pub fn forward_peer_message(
        &self,
        message_id: &str,
        request_id: &str,
        recipient_session_id: &str,
        scope: &str,
    ) -> Result<PeerMessage, CoordinationError> {
        peer_text(message_id, "message_id")?;
        peer_text(request_id, "request_id")?;
        peer_text(recipient_session_id, "recipient_session_id")?;
        peer_text(scope, "scope")?;
        let stored = self.peer_messages.get(message_id).cloned().ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_message",
                id: message_id.to_owned(),
            }
        })?;
        if stored.stream.recipient_session_id == recipient_session_id && stored.scope == scope {
            return Ok(stored);
        }
        if stored.scope != scope {
            return Err(CoordinationError::PeerCrossScopeRejected(
                message_id.to_owned(),
            ));
        }
        Err(CoordinationError::PeerSemanticConflict(
            message_id.to_owned(),
        ))
    }

    /// Visible gap set of one stream: admitted sequences below the highest
    /// observed sequence that are not delivered, acknowledged or consumed.
    /// The per-stream order is preserved; no fabricated global order exists.
    #[must_use]
    pub fn peer_stream_gaps(&self, stream: &PeerStreamId) -> Vec<u64> {
        let mut observed: BTreeSet<u64> = BTreeSet::new();
        let mut settled_below: BTreeSet<u64> = BTreeSet::new();
        let mut ceiling = 0;
        for message in self.peer_messages.values() {
            if message.stream == *stream {
                ceiling = ceiling.max(message.stream_seq);
                match &message.state {
                    PeerMessageState::Delivered { .. }
                    | PeerMessageState::Acknowledged { .. }
                    | PeerMessageState::Consumed { .. } => {
                        settled_below.insert(message.stream_seq);
                    }
                    _ => {
                        observed.insert(message.stream_seq);
                    }
                }
            }
        }
        (1..=ceiling)
            .filter(|seq| !settled_below.contains(seq) && observed.contains(seq))
            .collect()
    }

    /// Deterministic canonical digest of one stream's admitted entries.
    /// Equivalent duplicate-event permutations converge to one digest.
    #[must_use]
    pub fn peer_mailbox_digest(&self, stream: &PeerStreamId) -> String {
        let mut entries: Vec<(u64, String)> = Vec::new();
        for message in self.peer_messages.values() {
            if message.stream == *stream {
                entries.push((
                    message.stream_seq,
                    peer_digest_hex(&[
                        &message.message_id,
                        message.kind.as_wire(),
                        &message.payload_digest,
                        message.state.as_wire(),
                        &message.revision.to_string(),
                        &message.scope,
                    ]),
                ));
            }
        }
        entries.sort();
        let parts: Vec<&str> = entries.iter().map(|(_, digest)| digest.as_str()).collect();
        peer_digest_hex(&parts)
    }

    /// Reads one admitted peer message as an owned clone.
    pub fn read_peer_message(&self, message_id: &str) -> Result<PeerMessage, CoordinationError> {
        peer_text(message_id, "message_id")?;
        self.peer_messages
            .get(message_id)
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "peer_message",
                id: message_id.to_owned(),
            })
    }
}

/// Lifecycle of one board entry head. History is retained through
/// revisions; superseded revisions stay readable, retracted heads stay
/// visible until a receipted compaction reclaims them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum BoardEntryState {
    Current,
    Superseded { by_revision: u64 },
    Retracted { by_session: String, at: u64 },
}

/// Exact source anchor of one board entry revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardAnchor {
    pub artifact_id: String,
    pub revision: u64,
    pub digest: String,
}

/// One blackboard entry revision: bounded, authored, fenced, and bound to
/// its predecessor. Concurrent proposals stay separate records; there is no
/// last-write-wins merge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardEntry {
    pub entry_id: String,
    pub request_id: String,
    pub scope: String,
    pub kind: PeerBoardKind,
    pub author_session_id: String,
    pub audience_scope: String,
    pub source_refs: Vec<String>,
    pub anchor: Option<BoardAnchor>,
    pub content_digest: String,
    pub content_handle: Option<String>,
    pub privacy: PrivacyClass,
    pub disclosure_handle: Option<String>,
    pub required_evidence: bool,
    pub dissent: bool,
    pub withheld: bool,
    pub lineage: Vec<String>,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub revision: u64,
    pub predecessor_revision: Option<u64>,
    pub supersedes: Option<u64>,
    pub admitted_seq: u64,
    pub created_at: u64,
    pub durability: PeerDurability,
    pub state: BoardEntryState,
}

/// Admission draft for one board entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PostBoardEntry {
    pub request_id: String,
    pub entry_id: String,
    pub scope: String,
    pub kind: PeerBoardKind,
    pub author_session_id: String,
    pub audience_scope: String,
    pub source_refs: Vec<String>,
    pub anchor: Option<BoardAnchor>,
    pub content_digest: String,
    pub content_handle: Option<String>,
    pub privacy: PrivacyClass,
    pub disclosure_handle: Option<String>,
    pub required_evidence: bool,
    pub dissent: bool,
    pub withheld: bool,
    pub lineage: Vec<String>,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
}

/// Revision draft for one existing board entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviseBoardEntry {
    pub request_id: String,
    pub entry_id: String,
    pub predecessor_revision: u64,
    pub author_session_id: String,
    pub source_refs: Vec<String>,
    pub anchor: Option<BoardAnchor>,
    pub content_digest: String,
    pub content_handle: Option<String>,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
}

/// Admission receipt for one board post or revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardEntryReceipt {
    pub entry: BoardEntry,
    pub event: super::CoordinationEvent,
    pub durability: PeerDurability,
    pub replayed: bool,
}

/// Non-disclosing summary carried by frozen board pages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardEntrySummary {
    pub entry_id: String,
    pub revision: u64,
    pub kind: String,
    pub content_digest: String,
    pub author_session_id: String,
    pub admitted_seq: u64,
}

/// One frozen paged board read with its complete-or-partial denominator,
/// omission count and next cursor. A truncated page is never complete, and
/// a page over withheld material stays incomplete with omissions counted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardPage {
    pub scope: String,
    pub frozen_at: u64,
    pub total: u64,
    pub visible: u64,
    pub omitted: u64,
    pub entries: Vec<BoardEntrySummary>,
    pub next_cursor: Option<u64>,
    pub complete: bool,
}

/// Exact compaction policy. Dissent and required evidence are always
/// retained; a policy asking to drop them is rejected fail-closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardCompactionPolicy {
    pub policy_id: String,
    pub lineage_receipt: String,
    pub retain_dissent: bool,
    pub retain_required_evidence: bool,
}

/// Omission receipt for one receipted compaction: what left the live board,
/// what was retained and under which policy lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardCompactionReceipt {
    pub scope: String,
    pub policy_id: String,
    pub lineage_receipt: String,
    pub omitted: Vec<BoardOmission>,
    pub retained_dissent: Vec<String>,
    pub retained_required: Vec<String>,
    pub at: u64,
}

/// One compacted-away record reference kept in the tombstone set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardOmission {
    pub entry_id: String,
    pub revision: u64,
    pub content_digest: String,
}

/// Tombstone of one compacted board record, recoverable by omission receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardTombstone {
    pub entry_id: String,
    pub revision: u64,
    pub content_digest: String,
    pub policy_id: String,
    pub lineage_receipt: String,
    pub at: u64,
}

impl CoordinationOwner {
    fn board_scope_heads(&self, scope: &str) -> usize {
        self.peer_board_heads
            .values()
            .filter(|entry| entry.scope == scope)
            .count()
    }

    fn board_entry_revisions(&self, entry_id: &str) -> usize {
        self.peer_board_revisions
            .keys()
            .filter(|(id, _)| id == entry_id)
            .count()
    }

    fn board_exact_replay(
        &self,
        request_id: &str,
        entry_id: &str,
        revision: u64,
    ) -> Result<Option<BoardEntryReceipt>, CoordinationError> {
        let Some(indexed) = self.peer_board_requests.get(request_id) else {
            return Ok(None);
        };
        let (stored_id, stored_rev) = indexed
            .rsplit_once(':')
            .ok_or(CoordinationError::InvalidState)?;
        if stored_id != entry_id {
            return Err(CoordinationError::PeerSemanticConflict(entry_id.to_owned()));
        }
        let stored_rev: u64 = stored_rev
            .parse()
            .map_err(|_| CoordinationError::InvalidState)?;
        if stored_rev != revision {
            return Err(CoordinationError::PeerSemanticConflict(entry_id.to_owned()));
        }
        let entry = self
            .peer_board_revisions
            .get(&(entry_id.to_owned(), revision))
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        let event = self
            .event_by_request
            .get(request_id)
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        Ok(Some(BoardEntryReceipt {
            durability: entry.durability.clone(),
            entry,
            event,
            replayed: true,
        }))
    }

    /// Validates one board post draft against identity, role, privacy and
    /// anchor shape before any replay or bound check runs.
    fn validate_post_draft(
        &self,
        draft: &PostBoardEntry,
        now: u64,
    ) -> Result<(), CoordinationError> {
        peer_text(&draft.request_id, "request_id")?;
        peer_text(&draft.entry_id, "entry_id")?;
        peer_text(&draft.scope, "scope")?;
        peer_text(&draft.author_session_id, "author_session_id")?;
        peer_text(&draft.audience_scope, "audience_scope")?;
        peer_text(&draft.content_digest, "content_digest")?;
        self.common(draft.authority_epoch.clone(), &draft.state_fence)?;
        self.peer_sender(
            &draft.author_session_id,
            &draft.authority_epoch,
            &draft.state_fence,
            now,
        )?;
        if draft.privacy == PrivacyClass::Secret
            && draft.disclosure_handle.as_deref().is_none_or(str::is_empty)
        {
            return Err(CoordinationError::PeerPrivacyDenied(draft.entry_id.clone()));
        }
        if draft.source_refs.len() > MAX_PEER_REFERENCES {
            return Err(CoordinationError::InvalidField("source_refs"));
        }
        for reference in &draft.source_refs {
            peer_text(reference, "source_ref")?;
        }
        for lineage in &draft.lineage {
            peer_text(lineage, "lineage")?;
        }
        if let Some(handle) = draft.content_handle.as_deref() {
            peer_text(handle, "content_handle")?;
        }
        if let Some(handle) = draft.disclosure_handle.as_deref() {
            peer_text(handle, "disclosure_handle")?;
        }
        if let Some(anchor) = draft.anchor.as_ref() {
            peer_text(&anchor.artifact_id, "anchor_artifact")?;
            peer_text(&anchor.digest, "anchor_digest")?;
            if anchor.revision == 0 {
                return Err(CoordinationError::InvalidField("anchor_revision"));
            }
        }
        Ok(())
    }

    /// Posts one bounded blackboard entry through the existing owner.
    /// Concurrent proposals stay separate; changed same-ID content
    /// conflicts instead of merging.
    pub fn post_board_entry(
        &mut self,
        draft: &PostBoardEntry,
        clock: &dyn PeerClockPort,
        durability: &dyn PeerDurabilityPort,
    ) -> Result<BoardEntryReceipt, CoordinationError> {
        let now = clock.now_ms();
        self.validate_post_draft(draft, now)?;
        if let Some(replayed) = self.board_exact_replay(&draft.request_id, &draft.entry_id, 1)? {
            return Ok(replayed);
        }
        if self.peer_board_heads.contains_key(&draft.entry_id) {
            return Err(CoordinationError::Duplicate(draft.entry_id.clone()));
        }
        if self.board_scope_heads(&draft.scope) >= MAX_BOARD_ENTRIES_PER_SCOPE {
            return Err(CoordinationError::PeerBackpressure {
                scope: draft.scope.clone(),
                limit: MAX_BOARD_ENTRIES_PER_SCOPE,
            });
        }
        let recorded = attest_peer_durability(durability)?;
        let entry = BoardEntry {
            entry_id: draft.entry_id.clone(),
            request_id: draft.request_id.clone(),
            scope: draft.scope.clone(),
            kind: draft.kind,
            author_session_id: draft.author_session_id.clone(),
            audience_scope: draft.audience_scope.clone(),
            source_refs: draft.source_refs.clone(),
            anchor: draft.anchor.clone(),
            content_digest: draft.content_digest.clone(),
            content_handle: draft.content_handle.clone(),
            privacy: draft.privacy,
            disclosure_handle: draft.disclosure_handle.clone(),
            required_evidence: draft.required_evidence,
            dissent: draft.dissent,
            withheld: draft.withheld,
            lineage: draft.lineage.clone(),
            authority_epoch: draft.authority_epoch.clone(),
            state_fence: draft.state_fence.clone(),
            revision: 1,
            predecessor_revision: None,
            supersedes: None,
            admitted_seq: self.sequence.saturating_add(1),
            created_at: now,
            durability: recorded.clone(),
            state: BoardEntryState::Current,
        };
        let event = self.event(
            &draft.request_id,
            format!("board:{}:1", draft.entry_id),
            CoordinationEventKind::BoardEntryPosted,
            draft.entry_id.clone(),
            draft.author_session_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            draft.authority_epoch.clone(),
            draft.state_fence.clone(),
            draft.content_digest.clone(),
            empty_clock(),
        )?;
        let event = self.commit(&draft.request_id, event)?;
        self.peer_board_revisions
            .insert((draft.entry_id.clone(), 1), entry.clone());
        self.peer_board_heads
            .insert(draft.entry_id.clone(), entry.clone());
        self.peer_board_requests
            .insert(draft.request_id.clone(), format!("{}:1", draft.entry_id));
        Ok(BoardEntryReceipt {
            entry,
            event,
            durability: recorded,
            replayed: false,
        })
    }

    /// Validates one board revision draft against identity, role and
    /// anchor shape before any predecessor or bound check runs.
    fn validate_revise_draft(
        &self,
        draft: &ReviseBoardEntry,
        now: u64,
    ) -> Result<(), CoordinationError> {
        peer_text(&draft.request_id, "request_id")?;
        peer_text(&draft.entry_id, "entry_id")?;
        peer_text(&draft.author_session_id, "author_session_id")?;
        peer_text(&draft.content_digest, "content_digest")?;
        self.common(draft.authority_epoch.clone(), &draft.state_fence)?;
        self.peer_sender(
            &draft.author_session_id,
            &draft.authority_epoch,
            &draft.state_fence,
            now,
        )?;
        if draft.source_refs.len() > MAX_PEER_REFERENCES {
            return Err(CoordinationError::InvalidField("source_refs"));
        }
        for reference in &draft.source_refs {
            peer_text(reference, "source_ref")?;
        }
        if let Some(handle) = draft.content_handle.as_deref() {
            peer_text(handle, "content_handle")?;
        }
        if let Some(anchor) = draft.anchor.as_ref() {
            peer_text(&anchor.artifact_id, "anchor_artifact")?;
            peer_text(&anchor.digest, "anchor_digest")?;
            if anchor.revision == 0 {
                return Err(CoordinationError::InvalidField("anchor_revision"));
            }
        }
        Ok(())
    }

    /// Revises one board entry with an exact predecessor. The prior
    /// revision stays readable; a predecessor mismatch is rejected.
    pub fn revise_board_entry(
        &mut self,
        draft: &ReviseBoardEntry,
        clock: &dyn PeerClockPort,
        durability: &dyn PeerDurabilityPort,
    ) -> Result<BoardEntryReceipt, CoordinationError> {
        let now = clock.now_ms();
        self.validate_revise_draft(draft, now)?;
        let head = self
            .peer_board_heads
            .get(&draft.entry_id)
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "board_entry",
                id: draft.entry_id.clone(),
            })?;
        if !matches!(head.state, BoardEntryState::Current) {
            return Err(CoordinationError::InvalidState);
        }
        if draft.predecessor_revision != head.revision {
            if self.peer_board_requests.contains_key(&draft.request_id) {
                return Err(CoordinationError::PeerSemanticConflict(
                    draft.entry_id.clone(),
                ));
            }
            return Err(CoordinationError::CausalPredecessorMismatch);
        }
        let revision = head.revision.saturating_add(1);
        if let Some(replayed) =
            self.board_exact_replay(&draft.request_id, &draft.entry_id, revision)?
        {
            return Ok(replayed);
        }
        if self.board_entry_revisions(&draft.entry_id) >= MAX_BOARD_REVISIONS_PER_ENTRY {
            return Err(CoordinationError::PeerBackpressure {
                scope: draft.entry_id.clone(),
                limit: MAX_BOARD_REVISIONS_PER_ENTRY,
            });
        }
        let recorded = attest_peer_durability(durability)?;
        let entry = BoardEntry {
            entry_id: head.entry_id.clone(),
            request_id: draft.request_id.clone(),
            scope: head.scope.clone(),
            kind: head.kind,
            author_session_id: draft.author_session_id.clone(),
            audience_scope: head.audience_scope.clone(),
            source_refs: draft.source_refs.clone(),
            anchor: draft.anchor.clone(),
            content_digest: draft.content_digest.clone(),
            content_handle: draft.content_handle.clone(),
            privacy: head.privacy,
            disclosure_handle: head.disclosure_handle.clone(),
            required_evidence: head.required_evidence,
            dissent: head.dissent,
            withheld: head.withheld,
            lineage: head.lineage.clone(),
            authority_epoch: draft.authority_epoch.clone(),
            state_fence: draft.state_fence.clone(),
            revision,
            predecessor_revision: Some(head.revision),
            supersedes: Some(head.revision),
            admitted_seq: self.sequence.saturating_add(1),
            created_at: now,
            durability: recorded.clone(),
            state: BoardEntryState::Current,
        };
        let event = self.event(
            &draft.request_id,
            format!("board:{}:{revision}", draft.entry_id),
            CoordinationEventKind::BoardEntryRevised,
            draft.entry_id.clone(),
            draft.author_session_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            draft.authority_epoch.clone(),
            draft.state_fence.clone(),
            draft.content_digest.clone(),
            empty_clock(),
        )?;
        let event = self.commit(&draft.request_id, event)?;
        if let Some(prior) = self.peer_board_heads.get_mut(&draft.entry_id) {
            prior.state = BoardEntryState::Superseded {
                by_revision: revision,
            };
        }
        self.peer_board_revisions
            .insert((draft.entry_id.clone(), revision), entry.clone());
        self.peer_board_heads
            .insert(draft.entry_id.clone(), entry.clone());
        self.peer_board_requests.insert(
            draft.request_id.clone(),
            format!("{}:{revision}", draft.entry_id),
        );
        Ok(BoardEntryReceipt {
            entry,
            event,
            durability: recorded,
            replayed: false,
        })
    }

    /// Reads one frozen board revision as an owned clone.
    pub fn read_board_revision(
        &self,
        entry_id: &str,
        revision: u64,
    ) -> Result<BoardEntry, CoordinationError> {
        peer_text(entry_id, "entry_id")?;
        self.peer_board_revisions
            .get(&(entry_id.to_owned(), revision))
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "board_revision",
                id: entry_id.to_owned(),
            })
    }

    /// Reads one compacted tombstone by omission receipt reference.
    pub fn read_board_tombstone(
        &self,
        entry_id: &str,
        revision: u64,
    ) -> Result<BoardTombstone, CoordinationError> {
        peer_text(entry_id, "entry_id")?;
        self.peer_board_tombstones
            .get(&(entry_id.to_owned(), revision))
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "board_tombstone",
                id: entry_id.to_owned(),
            })
    }

    /// Retracts one board head. Only the author retracts, and retraction
    /// keeps history visible; it never erases observed evidence.
    pub fn retract_board_entry(
        &mut self,
        entry_id: &str,
        by_session: &str,
        clock: &dyn PeerClockPort,
    ) -> Result<BoardEntry, CoordinationError> {
        peer_text(entry_id, "entry_id")?;
        peer_text(by_session, "by_session")?;
        let now = clock.now_ms();
        let author = self
            .peer_board_heads
            .get(entry_id)
            .map(|entry| entry.author_session_id.clone())
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "board_entry",
                id: entry_id.to_owned(),
            })?;
        if author != by_session {
            return Err(CoordinationError::LeaseOwnerMismatch { holder: author });
        }
        let head = self
            .peer_board_heads
            .get_mut(entry_id)
            .ok_or(CoordinationError::InvalidState)?;
        if !matches!(head.state, BoardEntryState::Current) {
            return Err(CoordinationError::InvalidState);
        }
        head.state = BoardEntryState::Retracted {
            by_session: by_session.to_owned(),
            at: now,
        };
        Ok(head.clone())
    }

    /// Reads one frozen paged slice of a scope board. The frozen sequence
    /// ceiling excludes later admissions; withheld material contributes to
    /// the omission count and keeps the page incomplete.
    pub fn read_board_page(
        &self,
        scope: &str,
        cursor: u64,
        page_size: u64,
        frozen_at: u64,
    ) -> Result<BoardPage, CoordinationError> {
        peer_text(scope, "scope")?;
        if page_size == 0 || page_size > MAX_BOARD_PAGE_SIZE {
            return Err(CoordinationError::InvalidField("page_size"));
        }
        let mut ordered: Vec<&BoardEntry> = self
            .peer_board_heads
            .values()
            .filter(|entry| entry.scope == scope && entry.admitted_seq <= frozen_at)
            .collect();
        ordered.sort_by_key(|entry| entry.admitted_seq);
        let total = ordered.len() as u64;
        let omitted = ordered.iter().filter(|entry| entry.withheld).count() as u64;
        let visible: Vec<&BoardEntry> = ordered
            .into_iter()
            .filter(|entry| !entry.withheld)
            .collect();
        let bound = visible.len();
        let start = usize::try_from(cursor).unwrap_or(usize::MAX).min(bound);
        let end = usize::try_from(cursor.saturating_add(page_size))
            .unwrap_or(usize::MAX)
            .min(bound);
        let entries = visible[start..end]
            .iter()
            .map(|entry| BoardEntrySummary {
                entry_id: entry.entry_id.clone(),
                revision: entry.revision,
                kind: entry.kind.as_wire().to_owned(),
                content_digest: entry.content_digest.clone(),
                author_session_id: entry.author_session_id.clone(),
                admitted_seq: entry.admitted_seq,
            })
            .collect();
        let next_cursor = if end < visible.len() {
            Some(end as u64)
        } else {
            None
        };
        let complete = next_cursor.is_none() && omitted == 0;
        Ok(BoardPage {
            scope: scope.to_owned(),
            frozen_at,
            total,
            visible: visible.len() as u64,
            omitted,
            entries,
            next_cursor,
            complete,
        })
    }

    /// Compacts one scope board under an exact policy. Retracted heads move
    /// to receipted tombstones; dissent and required-evidence heads are
    /// always retained with their lineage. A missing or dissent-dropping
    /// policy is rejected instead of compacting.
    pub fn compact_board_scope(
        &mut self,
        scope: &str,
        policy: BoardCompactionPolicy,
        clock: &dyn PeerClockPort,
    ) -> Result<BoardCompactionReceipt, CoordinationError> {
        peer_text(scope, "scope")?;
        if policy.policy_id.trim().is_empty()
            || policy.lineage_receipt.trim().is_empty()
            || !policy.retain_dissent
            || !policy.retain_required_evidence
        {
            return Err(CoordinationError::PeerCompactionRequiresPolicy {
                scope: scope.to_owned(),
            });
        }
        let now = clock.now_ms();
        let mut omitted = Vec::new();
        let mut retained_dissent = Vec::new();
        let mut retained_required = Vec::new();
        let candidates: Vec<String> = self
            .peer_board_heads
            .values()
            .filter(|entry| {
                entry.scope == scope && matches!(entry.state, BoardEntryState::Retracted { .. })
            })
            .map(|entry| entry.entry_id.clone())
            .collect();
        for entry_id in candidates {
            let Some(head) = self.peer_board_heads.get(&entry_id).cloned() else {
                continue;
            };
            if head.dissent {
                retained_dissent.push(entry_id);
                continue;
            }
            if head.required_evidence {
                retained_required.push(entry_id);
                continue;
            }
            let revisions: Vec<u64> = self
                .peer_board_revisions
                .keys()
                .filter(|(id, _)| *id == entry_id)
                .map(|(_, revision)| *revision)
                .collect();
            for revision in revisions {
                if let Some(record) = self
                    .peer_board_revisions
                    .remove(&(entry_id.clone(), revision))
                {
                    self.peer_board_tombstones.insert(
                        (entry_id.clone(), revision),
                        BoardTombstone {
                            entry_id: entry_id.clone(),
                            revision,
                            content_digest: record.content_digest.clone(),
                            policy_id: policy.policy_id.clone(),
                            lineage_receipt: policy.lineage_receipt.clone(),
                            at: now,
                        },
                    );
                    omitted.push(BoardOmission {
                        entry_id: entry_id.clone(),
                        revision,
                        content_digest: record.content_digest,
                    });
                }
            }
            self.peer_board_heads.remove(&entry_id);
        }
        omitted.sort_by(|left, right| {
            left.entry_id
                .cmp(&right.entry_id)
                .then(left.revision.cmp(&right.revision))
        });
        retained_dissent.sort();
        retained_required.sort();
        Ok(BoardCompactionReceipt {
            scope: scope.to_owned(),
            policy_id: policy.policy_id,
            lineage_receipt: policy.lineage_receipt,
            omitted,
            retained_dissent,
            retained_required,
            at: now,
        })
    }
}

/// One retained conflict candidate position with its author, evidence
/// and source lineage. Positions are never merged, voted, or inferred
/// from prose similarity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConflictCandidate {
    pub position: String,
    pub author_session_id: String,
    pub evidence_refs: Vec<String>,
    pub lineage: Vec<String>,
}

/// Admission draft for one conflict candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConflictCandidateDraft {
    pub position: String,
    pub author_session_id: String,
    pub evidence_refs: Vec<String>,
    pub lineage: Vec<String>,
}

/// External resolution receipt. Only an external receipt establishes a
/// resolved state; peer consensus can never self-resolve.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalResolutionReceipt {
    pub receipt_id: String,
    pub issuer: String,
    pub detail: String,
}

/// One retained peer conflict set with two-sided positions, supplied
/// structured dimensions, lineage independence analysis, and lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerConflict {
    pub conflict_id: String,
    pub request_id: String,
    pub conflict_type: PeerConflictType,
    pub scope_id: String,
    pub task_id: String,
    pub candidates: Vec<ConflictCandidate>,
    pub dimensions: Vec<PeerConflictDimension>,
    pub acceptability: ArgumentAcceptability,
    pub lineage_independent: bool,
    pub common_mode_exposure: bool,
    pub authority_owner: String,
    pub affected_actions: Vec<String>,
    pub state: PeerConflictState,
    pub resolution: Option<ExternalResolutionReceipt>,
    pub created_at: u64,
    pub resolved_at: Option<u64>,
}

/// Admission draft for one peer conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordPeerConflict {
    pub request_id: String,
    pub conflict_id: String,
    pub conflict_type: PeerConflictType,
    pub scope_id: String,
    pub task_id: String,
    pub candidates: Vec<ConflictCandidateDraft>,
    pub dimensions: Vec<PeerConflictDimension>,
    pub authority_owner: String,
    pub affected_actions: Vec<String>,
}

/// Admission receipt for one recorded conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerConflictReceipt {
    pub conflict: PeerConflict,
    pub event: super::CoordinationEvent,
    pub replayed: bool,
}

impl CoordinationOwner {
    /// Validates one conflict draft: every candidate author must be a live
    /// bound peer and every position, evidence handle and lineage must be
    /// well-formed text. No contradiction is ever inferred from prose.
    fn validate_conflict_draft(
        &self,
        draft: &RecordPeerConflict,
        now: u64,
    ) -> Result<(), CoordinationError> {
        peer_text(&draft.request_id, "request_id")?;
        peer_text(&draft.conflict_id, "conflict_id")?;
        peer_text(&draft.scope_id, "scope_id")?;
        peer_text(&draft.task_id, "task_id")?;
        peer_text(&draft.authority_owner, "authority_owner")?;
        if draft.candidates.is_empty() {
            return Err(CoordinationError::InvalidField("candidates"));
        }
        if draft.dimensions.is_empty() {
            return Err(CoordinationError::InvalidField("dimensions"));
        }
        for candidate in &draft.candidates {
            peer_text(&candidate.position, "position")?;
            peer_text(&candidate.author_session_id, "candidate_author")?;
            let bound = self
                .sessions
                .get(&candidate.author_session_id)
                .cloned()
                .ok_or_else(|| CoordinationError::NotFound {
                    kind: "session",
                    id: candidate.author_session_id.clone(),
                })?;
            self.peer_sender(
                &candidate.author_session_id,
                &bound.authority_epoch,
                &bound.state_fence,
                now,
            )?;
            for reference in &candidate.evidence_refs {
                peer_text(reference, "candidate_evidence")?;
            }
            for lineage in &candidate.lineage {
                peer_text(lineage, "candidate_lineage")?;
            }
        }
        for action in &draft.affected_actions {
            peer_text(action, "affected_action")?;
        }
        Ok(())
    }

    /// Replays an identical conflict draft. Returns `None` when new.
    fn replay_conflict_draft(
        &self,
        draft: &RecordPeerConflict,
    ) -> Result<Option<PeerConflictReceipt>, CoordinationError> {
        let Some(indexed) = self.peer_conflict_requests.get(&draft.request_id) else {
            return Ok(None);
        };
        if indexed != &draft.conflict_id {
            return Err(CoordinationError::PeerSemanticConflict(
                draft.conflict_id.clone(),
            ));
        }
        let stored = self
            .peer_conflicts
            .get(&draft.conflict_id)
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        let event = self
            .event_by_request
            .get(&draft.request_id)
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        Ok(Some(PeerConflictReceipt {
            conflict: stored,
            event,
            replayed: true,
        }))
    }

    /// Derives two-sided acceptability and lineage independence from the
    /// supplied candidates. Distinct authors contest; shared lineage
    /// exposes a common mode; both stay visible either way.
    fn conflict_acceptability(draft: &RecordPeerConflict) -> (ArgumentAcceptability, bool) {
        let mut authors = BTreeSet::new();
        for candidate in &draft.candidates {
            authors.insert(candidate.author_session_id.clone());
        }
        let acceptability = if authors.len() >= 2 {
            ArgumentAcceptability::Contested
        } else {
            ArgumentAcceptability::Undecided
        };
        let mut seen_lineage = BTreeSet::new();
        let mut shared = false;
        for candidate in &draft.candidates {
            for lineage in &candidate.lineage {
                if !seen_lineage.insert(lineage.clone()) {
                    shared = true;
                }
            }
        }
        (acceptability, shared)
    }

    /// Records one structured conflict set through the existing owner.
    /// Two-sided and minority positions are retained together; a lone
    /// position stays undecided and can never resolve itself.
    pub fn record_peer_conflict(
        &mut self,
        draft: &RecordPeerConflict,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerConflictReceipt, CoordinationError> {
        let now = clock.now_ms();
        self.validate_conflict_draft(draft, now)?;
        if let Some(replayed) = self.replay_conflict_draft(draft)? {
            return Ok(replayed);
        }
        if self.peer_conflicts.contains_key(&draft.conflict_id) {
            return Err(CoordinationError::Duplicate(draft.conflict_id.clone()));
        }
        let (acceptability, shared) = Self::conflict_acceptability(draft);
        let digest = peer_digest_hex(
            &draft
                .candidates
                .iter()
                .flat_map(|candidate| {
                    [
                        candidate.position.as_str(),
                        candidate.author_session_id.as_str(),
                    ]
                })
                .collect::<Vec<&str>>(),
        );
        let conflict = PeerConflict {
            conflict_id: draft.conflict_id.clone(),
            request_id: draft.request_id.clone(),
            conflict_type: draft.conflict_type,
            scope_id: draft.scope_id.clone(),
            task_id: draft.task_id.clone(),
            candidates: draft
                .candidates
                .iter()
                .map(|candidate| ConflictCandidate {
                    position: candidate.position.clone(),
                    author_session_id: candidate.author_session_id.clone(),
                    evidence_refs: candidate.evidence_refs.clone(),
                    lineage: candidate.lineage.clone(),
                })
                .collect(),
            dimensions: draft.dimensions.clone(),
            acceptability,
            lineage_independent: !shared,
            common_mode_exposure: shared,
            authority_owner: draft.authority_owner.clone(),
            affected_actions: draft.affected_actions.clone(),
            state: PeerConflictState::Open,
            resolution: None,
            created_at: now,
            resolved_at: None,
        };
        let first_author = draft
            .candidates
            .first()
            .ok_or(CoordinationError::InvalidState)?
            .author_session_id
            .clone();
        let head_session = self
            .sessions
            .get(&first_author)
            .ok_or(CoordinationError::InvalidState)?;
        let event = self.event(
            &draft.request_id,
            format!("peer-conflict:{}", draft.conflict_id),
            CoordinationEventKind::PeerConflictRecorded,
            draft.conflict_id.clone(),
            first_author,
            (self.sequence != 0).then_some(self.sequence),
            head_session.authority_epoch.clone(),
            head_session.state_fence.clone(),
            digest,
            empty_clock(),
        )?;
        let event = self.commit(&draft.request_id, event)?;
        self.peer_conflicts
            .insert(draft.conflict_id.clone(), conflict.clone());
        self.peer_conflict_requests
            .insert(draft.request_id.clone(), draft.conflict_id.clone());
        Ok(PeerConflictReceipt {
            conflict,
            event,
            replayed: false,
        })
    }

    /// Resolves one conflict set with an exact external receipt. A missing
    /// receipt (peer consensus alone) is rejected; the set stays open.
    pub fn resolve_peer_conflict(
        &mut self,
        conflict_id: &str,
        receipt: Option<ExternalResolutionReceipt>,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerConflict, CoordinationError> {
        peer_text(conflict_id, "conflict_id")?;
        let Some(external) = receipt else {
            return Err(CoordinationError::PeerResolutionRequiresExternal(
                conflict_id.to_owned(),
            ));
        };
        peer_text(&external.receipt_id, "receipt_id")?;
        peer_text(&external.issuer, "receipt_issuer")?;
        peer_text(&external.detail, "receipt_detail")?;
        let now = clock.now_ms();
        let conflict = self.peer_conflicts.get_mut(conflict_id).ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_conflict",
                id: conflict_id.to_owned(),
            }
        })?;
        if !matches!(
            conflict.state,
            PeerConflictState::Open | PeerConflictState::Investigating
        ) {
            return Err(CoordinationError::InvalidState);
        }
        conflict.state = PeerConflictState::Resolved;
        conflict.resolution = Some(external);
        conflict.resolved_at = Some(now);
        Ok(conflict.clone())
    }

    /// Reads one retained peer conflict as an owned clone.
    pub fn read_peer_conflict(&self, conflict_id: &str) -> Result<PeerConflict, CoordinationError> {
        peer_text(conflict_id, "conflict_id")?;
        self.peer_conflicts
            .get(conflict_id)
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "peer_conflict",
                id: conflict_id.to_owned(),
            })
    }
}

/// Head of one reviewed artifact's exact revision chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerArtifactHead {
    pub artifact_id: String,
    pub revision: u64,
    pub digest: String,
    pub admitted_at: u64,
}

/// Admission draft for one artifact revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmitArtifactRevision {
    pub artifact_id: String,
    pub revision: u64,
    pub digest: String,
    pub author_session_id: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
}

/// One revision-anchored review. The review binds the exact artifact
/// revision and digest observed at submit; a review of revision N never
/// approves revision N+1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnchoredReview {
    pub review_id: String,
    pub request_id: String,
    pub artifact_id: String,
    pub artifact_revision: u64,
    pub artifact_digest: String,
    pub reviewer_session_id: String,
    pub operation: String,
    pub target_kind: ReviewTargetKind,
    pub kind: ReviewKind,
    pub criteria: Vec<String>,
    pub proof_refs: Vec<String>,
    pub anchor_field: String,
    pub anchor_resolution: AnchorResolution,
    pub findings: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub dissent: Option<String>,
    pub uncertainty: Option<String>,
    pub recommendation: ReviewRecommendation,
    pub completeness: ReviewCompleteness,
    pub standing: PeerReviewStanding,
    pub lifecycle: PeerReviewLifecycle,
    pub expires_at: Option<u64>,
    pub conflict_id: Option<String>,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub created_at: u64,
    pub durability: PeerDurability,
}

/// Submission draft for one anchored review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmitPeerReview {
    pub request_id: String,
    pub review_id: String,
    pub artifact_id: String,
    pub artifact_revision: u64,
    pub reviewer_session_id: String,
    pub operation: String,
    pub target_kind: ReviewTargetKind,
    pub kind: ReviewKind,
    pub criteria: Vec<String>,
    pub proof_refs: Vec<String>,
    pub anchor_field: String,
    pub anchor_resolution: AnchorResolution,
    pub findings: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub dissent: Option<String>,
    pub uncertainty: Option<String>,
    pub recommendation: ReviewRecommendation,
    pub completeness: ReviewCompleteness,
    pub expires_at: Option<u64>,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
}

/// Submission receipt for one anchored review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerReviewReceipt {
    pub review: AnchoredReview,
    pub event: super::CoordinationEvent,
    pub durability: PeerDurability,
    pub replayed: bool,
}

/// Lifecycle advance for one anchored review.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerReviewAdvance {
    Deliver,
    Answer,
    Resolve,
    RejectWithReason,
    MarkSuperseded,
}

/// Acknowledgement receipt for one review. Acknowledgement records receipt
/// only: it never merges, admits, or finishes anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerReviewAckReceipt {
    pub review_id: String,
    pub lifecycle: PeerReviewLifecycle,
    pub by_session: String,
    pub admitted: bool,
    pub merged: bool,
    pub finished: bool,
}

/// Expected-review denominator for one artifact: expected versus submitted
/// with partial, abstained, expired and stale positions retained visibly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerReviewDenominator {
    pub artifact_id: String,
    pub expected: u64,
    pub submitted: u64,
    pub complete: u64,
    pub partial: u64,
    pub abstained: u64,
    pub expired: u64,
    pub stale: u64,
    pub open_conflicts: u64,
}

fn recommendations_conflict(left: ReviewRecommendation, right: ReviewRecommendation) -> bool {
    let approves = |recommendation: ReviewRecommendation| {
        matches!(
            recommendation,
            ReviewRecommendation::Approve | ReviewRecommendation::ApproveWithChanges
        )
    };
    approves(left) != approves(right)
        && !matches!(left, ReviewRecommendation::Abstain)
        && !matches!(right, ReviewRecommendation::Abstain)
}

impl CoordinationOwner {
    /// Admits one exact artifact revision head. Revisions must be
    /// contiguous; a skipped or repeated revision is rejected.
    pub fn admit_artifact_revision(
        &mut self,
        draft: &AdmitArtifactRevision,
        clock: &dyn PeerClockPort,
    ) -> Result<PeerArtifactHead, CoordinationError> {
        peer_text(&draft.artifact_id, "artifact_id")?;
        peer_text(&draft.digest, "digest")?;
        peer_text(&draft.author_session_id, "author_session_id")?;
        self.common(draft.authority_epoch.clone(), &draft.state_fence)?;
        let now = clock.now_ms();
        self.peer_sender(
            &draft.author_session_id,
            &draft.authority_epoch,
            &draft.state_fence,
            now,
        )?;
        if draft.revision == 0 {
            return Err(CoordinationError::InvalidField("artifact_revision"));
        }
        let expected = self
            .peer_artifact_heads
            .get(&draft.artifact_id)
            .map_or(1, |head| head.revision.saturating_add(1));
        if draft.revision != expected {
            if let Some(stored) = self
                .peer_artifact_revisions
                .get(&(draft.artifact_id.clone(), draft.revision))
            {
                if stored == &draft.digest {
                    return self
                        .peer_artifact_heads
                        .get(&draft.artifact_id)
                        .cloned()
                        .ok_or(CoordinationError::InvalidState);
                }
                return Err(CoordinationError::PeerSemanticConflict(
                    draft.artifact_id.clone(),
                ));
            }
            return Err(CoordinationError::CausalPredecessorMismatch);
        }
        let head = PeerArtifactHead {
            artifact_id: draft.artifact_id.clone(),
            revision: draft.revision,
            digest: draft.digest.clone(),
            admitted_at: now,
        };
        self.peer_artifact_revisions.insert(
            (draft.artifact_id.clone(), draft.revision),
            draft.digest.clone(),
        );
        self.peer_artifact_heads
            .insert(draft.artifact_id.clone(), head.clone());
        Ok(head)
    }

    /// Establishes the expected-review count for one artifact. The
    /// expectation is immutable once set; a changed expectation conflicts.
    pub fn expect_peer_reviews(
        &mut self,
        artifact_id: &str,
        expected: u64,
        author_session_id: &str,
        epoch: &EpochId,
        fence: &StateFence,
        clock: &dyn PeerClockPort,
    ) -> Result<u64, CoordinationError> {
        peer_text(artifact_id, "artifact_id")?;
        peer_text(author_session_id, "author_session_id")?;
        if expected == 0 {
            return Err(CoordinationError::InvalidField("expected_reviews"));
        }
        self.common(epoch.clone(), fence)?;
        let now = clock.now_ms();
        self.peer_sender(author_session_id, epoch, fence, now)?;
        if let Some(stored) = self.peer_review_expectations.get(artifact_id) {
            if *stored == expected {
                return Ok(expected);
            }
            return Err(CoordinationError::PeerSemanticConflict(
                artifact_id.to_owned(),
            ));
        }
        self.peer_review_expectations
            .insert(artifact_id.to_owned(), expected);
        Ok(expected)
    }

    /// Submits one revision-anchored review through the existing owner.
    /// The review binds the exact artifact digest at its revision; a stale
    /// revision is retained as stale and never satisfies a requirement.
    /// Conflicting recommendations on one revision retain a conflict set.
    #[allow(clippy::too_many_lines)]
    pub fn submit_peer_review(
        &mut self,
        draft: &SubmitPeerReview,
        clock: &dyn PeerClockPort,
        durability: &dyn PeerDurabilityPort,
    ) -> Result<PeerReviewReceipt, CoordinationError> {
        peer_text(&draft.request_id, "request_id")?;
        peer_text(&draft.review_id, "review_id")?;
        peer_text(&draft.artifact_id, "artifact_id")?;
        peer_text(&draft.reviewer_session_id, "reviewer_session_id")?;
        peer_text(&draft.operation, "operation")?;
        peer_text(&draft.anchor_field, "anchor_field")?;
        self.common(draft.authority_epoch.clone(), &draft.state_fence)?;
        let now = clock.now_ms();
        self.peer_sender(
            &draft.reviewer_session_id,
            &draft.authority_epoch,
            &draft.state_fence,
            now,
        )?;
        if draft.artifact_revision == 0 {
            return Err(CoordinationError::InvalidField("artifact_revision"));
        }
        if draft.criteria.is_empty() {
            return Err(CoordinationError::InvalidField("criteria"));
        }
        if draft.findings.is_empty() {
            return Err(CoordinationError::InvalidField("findings"));
        }
        for criterion in draft.criteria.iter().chain(draft.proof_refs.iter()) {
            peer_text(criterion, "review_criterion")?;
        }
        for finding in draft.findings.iter().chain(draft.evidence_refs.iter()) {
            peer_text(finding, "review_finding")?;
        }
        if let Some(indexed) = self.peer_review_requests.get(&draft.request_id) {
            if indexed != &draft.review_id {
                return Err(CoordinationError::PeerSemanticConflict(
                    draft.review_id.clone(),
                ));
            }
            let stored = self
                .peer_reviews
                .get(&draft.review_id)
                .cloned()
                .ok_or(CoordinationError::InvalidState)?;
            let event = self
                .event_by_request
                .get(&draft.request_id)
                .cloned()
                .ok_or(CoordinationError::InvalidState)?;
            return Ok(PeerReviewReceipt {
                durability: stored.durability.clone(),
                review: stored,
                event,
                replayed: true,
            });
        }
        if self.peer_reviews.contains_key(&draft.review_id) {
            return Err(CoordinationError::Duplicate(draft.review_id.clone()));
        }
        let head = self
            .peer_artifact_heads
            .get(&draft.artifact_id)
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "artifact",
                id: draft.artifact_id.clone(),
            })?;
        if draft.artifact_revision > head.revision {
            return Err(CoordinationError::InvalidField("artifact_revision"));
        }
        let bound_digest = self
            .peer_artifact_revisions
            .get(&(draft.artifact_id.clone(), draft.artifact_revision))
            .cloned()
            .ok_or(CoordinationError::InvalidState)?;
        let stale = draft.artifact_revision < head.revision;
        let lifecycle = if stale {
            PeerReviewLifecycle::Stale
        } else {
            if !draft.anchor_resolution.satisfies_required_review() {
                return Err(CoordinationError::PeerReviewAnchorInvalid(
                    draft.review_id.clone(),
                ));
            }
            PeerReviewLifecycle::PendingDelivery
        };
        let standing = if draft.expires_at.is_some_and(|expiry| now >= expiry) {
            PeerReviewStanding::Expired
        } else {
            match draft.completeness {
                ReviewCompleteness::Complete => PeerReviewStanding::Complete,
                ReviewCompleteness::Partial => PeerReviewStanding::Partial,
                ReviewCompleteness::Abstain => PeerReviewStanding::Abstained,
            }
        };
        let recorded = attest_peer_durability(durability)?;
        let mut review = AnchoredReview {
            review_id: draft.review_id.clone(),
            request_id: draft.request_id.clone(),
            artifact_id: draft.artifact_id.clone(),
            artifact_revision: draft.artifact_revision,
            artifact_digest: bound_digest,
            reviewer_session_id: draft.reviewer_session_id.clone(),
            operation: draft.operation.clone(),
            target_kind: draft.target_kind,
            kind: draft.kind,
            criteria: draft.criteria.clone(),
            proof_refs: draft.proof_refs.clone(),
            anchor_field: draft.anchor_field.clone(),
            anchor_resolution: draft.anchor_resolution,
            findings: draft.findings.clone(),
            evidence_refs: draft.evidence_refs.clone(),
            dissent: draft.dissent.clone(),
            uncertainty: draft.uncertainty.clone(),
            recommendation: draft.recommendation,
            completeness: draft.completeness,
            standing,
            lifecycle,
            expires_at: draft.expires_at,
            conflict_id: None,
            authority_epoch: draft.authority_epoch.clone(),
            state_fence: draft.state_fence.clone(),
            created_at: now,
            durability: recorded.clone(),
        };
        if !stale {
            let rivals: Vec<AnchoredReview> = self
                .peer_reviews
                .values()
                .filter(|existing| {
                    existing.artifact_id == draft.artifact_id
                        && existing.artifact_revision == draft.artifact_revision
                        && !matches!(
                            existing.lifecycle,
                            PeerReviewLifecycle::Stale | PeerReviewLifecycle::Superseded
                        )
                        && recommendations_conflict(existing.recommendation, draft.recommendation)
                })
                .cloned()
                .collect();
            if let Some(rival) = rivals.first() {
                let conflict_id = format!("conflict-review:{}", draft.review_id);
                let conflict = PeerConflict {
                    conflict_id: conflict_id.clone(),
                    request_id: draft.request_id.clone(),
                    conflict_type: PeerConflictType::Epistemic,
                    scope_id: draft.artifact_id.clone(),
                    task_id: draft.artifact_id.clone(),
                    candidates: vec![
                        ConflictCandidate {
                            position: format!(
                                "review:{}:{:?}",
                                rival.review_id, rival.recommendation
                            ),
                            author_session_id: rival.reviewer_session_id.clone(),
                            evidence_refs: rival.evidence_refs.clone(),
                            lineage: vec![format!("review:{}", rival.review_id)],
                        },
                        ConflictCandidate {
                            position: format!(
                                "review:{}:{:?}",
                                draft.review_id, draft.recommendation
                            ),
                            author_session_id: draft.reviewer_session_id.clone(),
                            evidence_refs: draft.evidence_refs.clone(),
                            lineage: vec![format!("review:{}", draft.review_id)],
                        },
                    ],
                    dimensions: vec![PeerConflictDimension::EvidenceDifference],
                    acceptability: ArgumentAcceptability::Contested,
                    lineage_independent: true,
                    common_mode_exposure: false,
                    authority_owner: rival.reviewer_session_id.clone(),
                    affected_actions: vec![draft.operation.clone()],
                    state: PeerConflictState::Open,
                    resolution: None,
                    created_at: now,
                    resolved_at: None,
                };
                self.peer_conflicts.insert(conflict_id.clone(), conflict);
                review.conflict_id = Some(conflict_id.clone());
                if let Some(stored_rival) = self.peer_reviews.get_mut(&rival.review_id) {
                    stored_rival.conflict_id = Some(conflict_id);
                }
            }
        }
        let event = self.event(
            &draft.request_id,
            format!("peer-review:{}", draft.review_id),
            CoordinationEventKind::ReviewItemSubmitted,
            draft.review_id.clone(),
            draft.reviewer_session_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            draft.authority_epoch.clone(),
            draft.state_fence.clone(),
            review.artifact_digest.clone(),
            empty_clock(),
        )?;
        let event = self.commit(&draft.request_id, event)?;
        self.peer_reviews
            .insert(draft.review_id.clone(), review.clone());
        self.peer_review_requests
            .insert(draft.request_id.clone(), draft.review_id.clone());
        Ok(PeerReviewReceipt {
            review,
            event,
            durability: recorded,
            replayed: false,
        })
    }

    /// Advances one review along its lifecycle. Illegal transitions are
    /// rejected; only the reviewer advances their own review.
    pub fn advance_peer_review(
        &mut self,
        review_id: &str,
        advance: PeerReviewAdvance,
        by_session: &str,
        rejection_reason: Option<&str>,
    ) -> Result<AnchoredReview, CoordinationError> {
        peer_text(review_id, "review_id")?;
        peer_text(by_session, "by_session")?;
        let stored = self.peer_reviews.get(review_id).cloned().ok_or_else(|| {
            CoordinationError::NotFound {
                kind: "peer_review",
                id: review_id.to_owned(),
            }
        })?;
        if stored.reviewer_session_id != by_session {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: stored.reviewer_session_id.clone(),
            });
        }
        let next = match (stored.lifecycle, advance) {
            (PeerReviewLifecycle::PendingDelivery, PeerReviewAdvance::Deliver) => {
                PeerReviewLifecycle::Delivered
            }
            (PeerReviewLifecycle::Delivered, PeerReviewAdvance::Answer) => {
                PeerReviewLifecycle::Answered
            }
            (PeerReviewLifecycle::Answered, PeerReviewAdvance::Resolve) => {
                PeerReviewLifecycle::Resolved
            }
            (
                PeerReviewLifecycle::Delivered | PeerReviewLifecycle::Answered,
                PeerReviewAdvance::RejectWithReason,
            ) => {
                let reason = rejection_reason
                    .filter(|text| !text.trim().is_empty())
                    .ok_or(CoordinationError::InvalidField("rejection_reason"))?;
                peer_text(reason, "rejection_reason")?;
                PeerReviewLifecycle::RejectedWithReason
            }
            (
                PeerReviewLifecycle::PendingDelivery
                | PeerReviewLifecycle::Delivered
                | PeerReviewLifecycle::Answered,
                PeerReviewAdvance::MarkSuperseded,
            ) => PeerReviewLifecycle::Superseded,
            _ => return Err(CoordinationError::InvalidState),
        };
        let stored = self
            .peer_reviews
            .get_mut(review_id)
            .ok_or(CoordinationError::InvalidState)?;
        stored.lifecycle = next;
        Ok(stored.clone())
    }

    /// Acknowledges one review without changing it. The receipt proves the
    /// acknowledgement merged, admitted and finished nothing.
    pub fn acknowledge_peer_review(
        &self,
        review_id: &str,
        by_session: &str,
    ) -> Result<PeerReviewAckReceipt, CoordinationError> {
        peer_text(review_id, "review_id")?;
        peer_text(by_session, "by_session")?;
        if !self.sessions.contains_key(by_session) {
            return Err(CoordinationError::NotFound {
                kind: "session",
                id: by_session.to_owned(),
            });
        }
        let stored =
            self.peer_reviews
                .get(review_id)
                .ok_or_else(|| CoordinationError::NotFound {
                    kind: "peer_review",
                    id: review_id.to_owned(),
                })?;
        Ok(PeerReviewAckReceipt {
            review_id: review_id.to_owned(),
            lifecycle: stored.lifecycle,
            by_session: by_session.to_owned(),
            admitted: false,
            merged: false,
            finished: false,
        })
    }

    /// Derives the expected-review denominator for one artifact. Partial,
    /// abstained, expired and stale positions stay visible in the count.
    #[must_use]
    pub fn peer_review_denominator(&self, artifact_id: &str) -> PeerReviewDenominator {
        let expected = self
            .peer_review_expectations
            .get(artifact_id)
            .copied()
            .unwrap_or(0);
        let mut denominator = PeerReviewDenominator {
            artifact_id: artifact_id.to_owned(),
            expected,
            submitted: 0,
            complete: 0,
            partial: 0,
            abstained: 0,
            expired: 0,
            stale: 0,
            open_conflicts: 0,
        };
        for review in self.peer_reviews.values() {
            if review.artifact_id != artifact_id {
                continue;
            }
            denominator.submitted = denominator.submitted.saturating_add(1);
            match review.standing {
                PeerReviewStanding::Complete => {
                    denominator.complete = denominator.complete.saturating_add(1);
                }
                PeerReviewStanding::Partial => {
                    denominator.partial = denominator.partial.saturating_add(1);
                }
                PeerReviewStanding::Abstained => {
                    denominator.abstained = denominator.abstained.saturating_add(1);
                }
                PeerReviewStanding::Expired => {
                    denominator.expired = denominator.expired.saturating_add(1);
                }
            }
            if review.lifecycle == PeerReviewLifecycle::Stale {
                denominator.stale = denominator.stale.saturating_add(1);
            }
        }
        for conflict in self.peer_conflicts.values() {
            if conflict.scope_id == artifact_id && matches!(conflict.state, PeerConflictState::Open)
            {
                denominator.open_conflicts = denominator.open_conflicts.saturating_add(1);
            }
        }
        denominator
    }

    /// Reads one anchored review as an owned clone.
    pub fn read_peer_review(&self, review_id: &str) -> Result<AnchoredReview, CoordinationError> {
        peer_text(review_id, "review_id")?;
        self.peer_reviews
            .get(review_id)
            .cloned()
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "peer_review",
                id: review_id.to_owned(),
            })
    }
}
