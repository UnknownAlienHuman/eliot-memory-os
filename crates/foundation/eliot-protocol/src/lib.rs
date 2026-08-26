//! Store- and transport-neutral ELIOT Bridge Protocol (`EBP/1`) contracts.
//!
//! The crate owns the semantic frame, lifecycle/event, handshake, request
//! identity and JSON compatibility surfaces.  It does not open sockets or
//! pipes, start processes, persist events, or issue authority.  A transport
//! may use [`JsonCodec`] and the pure validation helpers without changing the
//! protocol meaning.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fmt, io::Read};

use eliot_agent_contracts::LivePeerMessage;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractError, ContractIdentity, ContractVersion, RequestId,
    ResourceGeneration, StateFence, canonical_json_bytes, contract_identity,
};
use eliot_evidence::EvidenceEnvelope;
use eliot_instrument_api::{InstrumentInvocation, VerificationRun};
use eliot_receipts::{ReceiptEnvelope, ReceiptKind, RequestBinding};
pub use eliot_runtime_contracts::ModuleGeneration as ProtocolModuleGeneration;
use eliot_runtime_contracts::{ModuleContract, ModuleGeneration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable identity of this protocol surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.protocol";
/// Current EBP semantic contract revision.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// EBP wire protocol major version.
pub const EBP_MAJOR: u16 = 1;
/// EBP wire protocol minor version.
pub const EBP_MINOR: u16 = 0;
/// Default maximum encoded body size, four mebibytes.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAME_BYTES_U32: u32 = 4 * 1024 * 1024;
/// Default bounded response body size for hot-path responses.
pub const HOT_RESPONSE_BYTES: usize = 64 * 1024;
/// Hard maximum for structured MCP response bodies.
pub const HARD_STRUCTURED_RESPONSE_BYTES: usize = 256 * 1024;
/// Stable module identity for the external agent bridge.
pub const AGENT_BRIDGE_MODULE_ID: &str = "eliot-agent-bridge";
/// Stable identity of the protected agent-bridge client declaration.
pub const AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID: &str =
    "eliot.protocol.agent-bridge-client-declaration";
/// Current protected agent-bridge client declaration version.
pub const AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION: u16 = 1;
const FRAME_PREFIX_BYTES: usize = 4;

/// A protocol contract validation or compatibility failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// A shared C0-01 primitive rejected a value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    /// A direct C0 provider rejected one of its owned public contract types.
    #[error("{provider} contract rejected the protocol value: {reason}")]
    Provider {
        /// Stable provider package name.
        provider: &'static str,
        /// Provider-owned validation error.
        reason: String,
    },
    /// A required protocol field is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field that failed validation.
        field: &'static str,
        /// Stable reason for the failure.
        reason: &'static str,
    },
    /// The protocol major versions do not overlap.
    #[error("protocol major versions are incompatible")]
    IncompatibleMajor,
    /// The protocol minor ranges do not overlap.
    #[error("protocol minor ranges are incompatible")]
    IncompatibleMinor,
    /// A message type is not admitted by this protocol surface.
    #[error("unknown message type")]
    UnknownMessageType,
    /// The negotiated encoding has no implementation in this crate.
    #[error("unsupported encoding profile: {0}")]
    UnsupportedEncoding(String),
    /// A frame body is empty.
    #[error("frame body length must be greater than zero")]
    ZeroLengthFrame,
    /// A frame body exceeds the negotiated or hard limit.
    #[error("frame body length {actual} exceeds maximum {maximum}")]
    OversizeFrame {
        /// Actual encoded body length.
        actual: usize,
        /// Admitted maximum body length.
        maximum: usize,
    },
    /// A wire frame ended before its declared body was available.
    #[error("partial frame: expected {expected} body bytes, received {actual}")]
    PartialFrame {
        /// Declared body length.
        expected: usize,
        /// Bytes actually available.
        actual: usize,
    },
    /// A frame had bytes after its declared body.
    #[error("trailing bytes after frame body")]
    TrailingBytes,
    /// The body was not valid UTF-8.
    #[error("frame body is not valid UTF-8")]
    InvalidUtf8,
    /// JSON decoding failed.
    #[error("invalid JSON frame body: {0}")]
    Json(String),
    /// The source reader failed while reading a complete frame.
    #[error("frame read failed: {0}")]
    Io(String),
    /// An event with the same identity was observed with different content.
    #[error("replay identity conflicts with a previously observed event")]
    ReplayConflict,
    /// An acknowledgement phase moved backwards or skipped a required phase.
    #[error("invalid event acknowledgement transition from {from} to {to}")]
    InvalidAckTransition {
        /// Previous phase.
        from: AckPhase,
        /// Requested phase.
        to: AckPhase,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn unique_texts(values: &[String], field: &'static str) -> Result<(), ProtocolError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(ProtocolError::InvalidField {
                field,
                reason: "must not contain duplicate values",
            });
        }
    }
    Ok(())
}

fn lowercase_sha256(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn windows_sid(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if !value.strip_prefix("S-1-").is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 180
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be canonical Windows SID text",
        });
    }
    Ok(())
}

fn provider_error(provider: &'static str, error: impl fmt::Display) -> ProtocolError {
    ProtocolError::Provider {
        provider,
        reason: error.to_string(),
    }
}

/// An EBP wire version.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    /// Breaking wire version.
    pub major: u16,
    /// Additive wire version.
    pub minor: u16,
}

impl ProtocolVersion {
    /// The current EBP/1 version.
    pub const CURRENT: Self = Self {
        major: EBP_MAJOR,
        minor: EBP_MINOR,
    };

    /// Validates this version against the EBP major line.
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.major == EBP_MAJOR {
            Ok(())
        } else {
            Err(ProtocolError::InvalidField {
                field: "protocol_version.major",
                reason: "must use the admitted EBP/1 major",
            })
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A compatible inclusive protocol version range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRange {
    /// Lowest supported version.
    pub minimum: ProtocolVersion,
    /// Highest supported version.
    pub maximum: ProtocolVersion,
}

impl ProtocolRange {
    /// Validates ordering and a common major line.
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.minimum.major != self.maximum.major {
            return Err(ProtocolError::IncompatibleMajor);
        }
        if self.minimum > self.maximum {
            return Err(ProtocolError::IncompatibleMinor);
        }
        self.minimum.validate()?;
        self.maximum.validate()
    }

    /// Selects the highest overlapping version, preserving minor compatibility.
    pub fn select(self, other: Self) -> Result<ProtocolVersion, ProtocolError> {
        self.validate()?;
        other.validate()?;
        if self.minimum.major != other.minimum.major {
            return Err(ProtocolError::IncompatibleMajor);
        }
        let minimum = if self.minimum > other.minimum {
            self.minimum
        } else {
            other.minimum
        };
        let maximum = if self.maximum < other.maximum {
            self.maximum
        } else {
            other.maximum
        };
        if minimum > maximum {
            return Err(ProtocolError::IncompatibleMinor);
        }
        Ok(maximum)
    }
}

/// Encoding selected for an EBP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum EncodingProfile {
    /// UTF-8 JSON generated from the Serde contract types.
    #[serde(rename = "json-v1")]
    JsonV1,
}

/// Semantic kind of an EBP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    /// A caller request.
    Request,
    /// A correlated response.
    Response,
    /// A server or module event.
    Event,
    /// A cancellation request.
    Cancel,
    /// A liveness heartbeat.
    Heartbeat,
    /// A protocol control message.
    Control,
}

/// Explicitly admitted EBP lifecycle message types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum MessageType {
    /// Module start.
    Start,
    /// Module ready.
    Ready,
    /// Module health.
    Health,
    /// Execute a request.
    Execute,
    /// Return an execute result.
    Result,
    /// Publish an event.
    Event,
    /// Cancel an operation.
    Cancel,
    /// Quiesce a module.
    Quiesce,
    /// Save a checkpoint.
    Checkpoint,
    /// Restore a checkpoint.
    RestoreCheckpoint,
    /// Report drain state.
    DrainStatus,
    /// Shut down a module.
    Shutdown,
    /// Report a fatal module failure.
    Fatal,
}

/// Request identity carried by request and cancellation boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestIdentity {
    /// Shared request and State Fence binding owned by C0-02.
    pub request: RequestBinding,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
    /// Absolute deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Cancellation identity for the request lifecycle.
    pub cancellation_id: String,
}

impl RequestIdentity {
    /// Validates identity fields without checking an external authority state.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.request.metadata.validate()?;
        self.request.state_fence.validate()?;
        if self.request.metadata.state_fence != self.request.state_fence {
            return Err(ProtocolError::InvalidField {
                field: "request.state_fence",
                reason: "must match request metadata state_fence",
            });
        }
        text(&self.idempotency_key, "idempotency_key")?;
        if self.deadline_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "deadline_unix_ms",
                reason: "must be greater than zero",
            });
        }
        text(&self.cancellation_id, "cancellation_id")?;
        Ok(())
    }
}

/// Typed payloads admitted by the first EBP compatibility surface.
///
/// `Json` remains the language-neutral extension point.  The other variants
/// preserve the public C0 owner types at the protocol boundary instead of
/// copying or weakening their validation semantics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum ProtocolPayload {
    /// A generated JSON contract not yet represented by a direct C0 variant.
    Json(Value),
    /// Immutable receipt owned and validated by C0-02.
    Receipt(Box<ReceiptEnvelope>),
    /// Normalized evidence envelope owned and validated by C0-03.
    Evidence(EvidenceEnvelope),
    /// Instrument request owned and validated by C0-05.
    InstrumentInvocation(InstrumentInvocation),
    /// Verification observation owned and validated by C0-05.
    VerificationRun(VerificationRun),
    /// Public bounded peer delta owned and validated by C0-06.
    AgentMessage(LivePeerMessage),
}

impl ProtocolPayload {
    /// Delegates validation to the public owner of each typed payload.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Json(_) => Ok(()),
            Self::Receipt(receipt) => receipt
                .validate()
                .map_err(|error| provider_error("eliot-receipts", error)),
            Self::Evidence(evidence) => evidence
                .validate()
                .map_err(|error| provider_error("eliot-evidence", error)),
            Self::InstrumentInvocation(invocation) => invocation
                .validate()
                .map_err(|error| provider_error("eliot-instrument-api", error)),
            Self::VerificationRun(run) => run
                .validate()
                .map_err(|error| provider_error("eliot-instrument-api", error)),
            Self::AgentMessage(message) => message
                .validate()
                .map_err(|error| provider_error("eliot-agent-contracts", error)),
        }
    }
}

/// The semantic EBP frame before transport framing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    /// Selected protocol version.
    pub protocol_version: ProtocolVersion,
    /// Selected encoding profile.
    pub encoding_profile: EncodingProfile,
    /// Connection identity assigned by the transport owner.
    pub connection_id: String,
    /// Correlation identity when the frame belongs to a request lifecycle.
    pub request_id: Option<RequestId>,
    /// Semantic frame kind.
    pub kind: FrameKind,
    /// Explicit lifecycle/control message type.
    pub message_type: MessageType,
    /// Typed request identity when the frame starts or cancels work.
    pub request_identity: Option<RequestIdentity>,
    /// Message payload owned by the selected semantic message type.
    pub payload: ProtocolPayload,
    /// Non-authoritative trace correlation values.
    pub trace_context: BTreeMap<String, String>,
}

impl Frame {
    /// Validates identity, version and the request correlation boundary.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.protocol_version.validate()?;
        text(&self.connection_id, "connection_id")?;
        if matches!(self.kind, FrameKind::Request | FrameKind::Cancel) && self.request_id.is_none()
        {
            return Err(ProtocolError::InvalidField {
                field: "request_id",
                reason: "required for request and cancel frames",
            });
        }
        if matches!(self.kind, FrameKind::Request | FrameKind::Cancel)
            && self.request_identity.is_none()
        {
            return Err(ProtocolError::InvalidField {
                field: "request_identity",
                reason: "required for request and cancel frames",
            });
        }
        if let Some(identity) = &self.request_identity {
            identity.validate()?;
            if self.request_id.as_ref() != Some(&identity.request.metadata.request_id) {
                return Err(ProtocolError::InvalidField {
                    field: "request_identity.request_id",
                    reason: "must match frame request_id",
                });
            }
        }
        self.payload.validate()?;
        for (key, value) in &self.trace_context {
            text(key, "trace_context.key")?;
            text(value, "trace_context.value")?;
        }
        Ok(())
    }
}

/// Durable event delivery class from the EBP event envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum DeliveryClass {
    /// Durable control event, replayed until acknowledged.
    #[serde(rename = "durable_control")]
    DurableControl,
    /// Durable observation event, replayed until acknowledged.
    #[serde(rename = "durable_observation")]
    DurableObservation,
    /// Best-effort telemetry, with explicit gap signalling on drops.
    #[serde(rename = "best_effort_telemetry")]
    BestEffortTelemetry,
}

/// Event payload either inline or addressed through an immutable resource.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum EventPayload {
    /// Small payload encoded in the frame.
    #[serde(rename = "inline")]
    Inline(Box<ProtocolPayload>),
    /// Large payload addressed by a stable immutable handle.
    #[serde(rename = "blob_ref")]
    BlobRef(String),
}

impl EventPayload {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Inline(payload) => payload.validate()?,
            Self::BlobRef(reference) => text(reference, "payload_or_blob_ref")?,
        }
        Ok(())
    }
}

/// Durable/control event envelope used for replay and acknowledgement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    /// Stream identity.
    pub stream_id: String,
    /// Producer module identity.
    pub producer_id: String,
    /// Producer generation used to fence old producers.
    pub producer_generation: ResourceGeneration,
    /// Authority epoch observed when the event was produced.
    pub authority_epoch: AuthorityEpoch,
    /// Stable event identity used for idempotent replay.
    pub event_id: String,
    /// Monotonic stream sequence.
    pub sequence: u64,
    /// Causal predecessor event identities.
    pub causal_predecessor_refs: Vec<String>,
    /// Delivery durability class.
    pub delivery_class: DeliveryClass,
    /// Whether the receiver must issue an explicit acknowledgement.
    pub ack_required: bool,
    /// Stable payload type discriminator.
    pub payload_type: String,
    /// Inline payload or immutable blob/resource handle.
    pub payload_or_blob_ref: EventPayload,
    /// Fence binding event production to the observed state.
    pub state_fence: StateFence,
    /// Non-authoritative trace correlation values.
    pub trace_context: BTreeMap<String, String>,
}

impl EventEnvelope {
    /// Validates event identity, sequencing and fence fields.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        text(&self.stream_id, "stream_id")?;
        text(&self.producer_id, "producer_id")?;
        text(&self.event_id, "event_id")?;
        text(&self.payload_type, "payload_type")?;
        if self.sequence == 0 {
            return Err(ProtocolError::InvalidField {
                field: "sequence",
                reason: "must be greater than zero",
            });
        }
        unique_texts(&self.causal_predecessor_refs, "causal_predecessor_refs")?;
        self.payload_or_blob_ref.validate()?;
        self.state_fence.validate()?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(ProtocolError::InvalidField {
                field: "authority_epoch",
                reason: "must match state_fence.authority_epoch",
            });
        }
        for (key, value) in &self.trace_context {
            text(key, "trace_context.key")?;
            text(value, "trace_context.value")?;
        }
        Ok(())
    }

    fn replay_key(&self) -> EventIdentityKey {
        EventIdentityKey::new(&self.stream_id, &self.event_id)
    }
}

/// Explicit acknowledgement phase for a durable event.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum AckPhase {
    /// Event bytes were received.
    #[serde(rename = "RECEIVED")]
    Received,
    /// Event was durably staged by the receiver.
    #[serde(rename = "DURABLE")]
    Durable,
    /// Event was normalized without implying application.
    #[serde(rename = "NORMALIZED")]
    Normalized,
    /// Event was applied to the receiver's admitted projection.
    #[serde(rename = "APPLIED")]
    Applied,
    /// Event was rejected by the receiver.
    #[serde(rename = "REJECTED")]
    Rejected,
    /// Event outcome is not yet known.
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl fmt::Display for AckPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Received => "RECEIVED",
            Self::Durable => "DURABLE",
            Self::Normalized => "NORMALIZED",
            Self::Applied => "APPLIED",
            Self::Rejected => "REJECTED",
            Self::Unknown => "UNKNOWN",
        })
    }
}

/// Receiver disposition attached to an event acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum EventDisposition {
    /// Event identity has been accepted for the current phase.
    #[serde(rename = "accepted")]
    Accepted,
    /// The same event identity was replayed with the same sequence.
    #[serde(rename = "duplicate")]
    Duplicate,
    /// Event was explicitly rejected.
    #[serde(rename = "rejected")]
    Rejected,
    /// Event identity has an incompatible sequence/content.
    #[serde(rename = "conflict")]
    Conflict,
}

/// Receipt for one event acknowledgement phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventAckReceipt {
    /// Stream identity.
    pub stream_id: String,
    /// Event identity.
    pub event_id: String,
    /// Highest phase declared by this receipt.
    pub phase: AckPhase,
    /// Receiver disposition.
    pub disposition: EventDisposition,
    /// Fence under which the phase was observed.
    pub state_fence: StateFence,
    /// Immutable coordination receipt binding identity, authority and fence.
    pub receipt: ReceiptEnvelope,
}

impl EventAckReceipt {
    /// Validates receipt identity and fence without claiming canonical apply.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        text(&self.stream_id, "stream_id")?;
        text(&self.event_id, "event_id")?;
        self.state_fence.validate()?;
        self.receipt
            .validate()
            .map_err(|error| provider_error("eliot-receipts", error))?;
        if self.receipt.core.kind != ReceiptKind::Coordination {
            return Err(ProtocolError::InvalidField {
                field: "receipt.core.kind",
                reason: "event acknowledgements require a coordination receipt",
            });
        }
        let coordination =
            self.receipt
                .core
                .coordination
                .as_ref()
                .ok_or(ProtocolError::InvalidField {
                    field: "receipt.core.coordination",
                    reason: "event acknowledgement identity is required",
                })?;
        if coordination.event_id.as_str() != self.event_id {
            return Err(ProtocolError::InvalidField {
                field: "receipt.core.coordination.event_id",
                reason: "must match the acknowledged event_id",
            });
        }
        if self.receipt.core.work_scope.state_fence != self.state_fence {
            return Err(ProtocolError::InvalidField {
                field: "receipt.core.work_scope.state_fence",
                reason: "must match the acknowledgement state_fence",
            });
        }
        Ok(())
    }

    /// Checks whether a phase can advance to another explicit phase.
    pub fn can_advance(from: AckPhase, to: AckPhase) -> bool {
        match (from, to) {
            (AckPhase::Received, AckPhase::Durable | AckPhase::Rejected | AckPhase::Unknown)
            | (AckPhase::Durable, AckPhase::Normalized | AckPhase::Rejected | AckPhase::Unknown)
            | (AckPhase::Normalized, AckPhase::Applied | AckPhase::Rejected | AckPhase::Unknown)
            | (AckPhase::Applied, AckPhase::Applied)
            | (AckPhase::Rejected, AckPhase::Rejected)
            | (AckPhase::Unknown, AckPhase::Unknown) => true,
            (left, right) if left == right => true,
            _ => false,
        }
    }

    /// Validates a phase advance without changing any state.
    pub fn validate_advance(from: AckPhase, to: AckPhase) -> Result<(), ProtocolError> {
        if Self::can_advance(from, to) {
            Ok(())
        } else {
            Err(ProtocolError::InvalidAckTransition { from, to })
        }
    }
}

const EVENT_IDENTITY_DOMAIN_TAG: &[u8] = b"eliot:event:v1";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EventIdentityKey {
    stream_id: String,
    event_id: String,
}

impl EventIdentityKey {
    pub fn new(stream_id: impl Into<String>, event_id: impl Into<String>) -> Self {
        Self {
            stream_id: stream_id.into(),
            event_id: event_id.into(),
        }
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            EVENT_IDENTITY_DOMAIN_TAG.len() + 16 + self.stream_id.len() + self.event_id.len(),
        );
        out.extend_from_slice(EVENT_IDENTITY_DOMAIN_TAG);
        out.extend_from_slice(&(self.stream_id.len() as u64).to_be_bytes());
        out.extend_from_slice(self.stream_id.as_bytes());
        out.extend_from_slice(&(self.event_id.len() as u64).to_be_bytes());
        out.extend_from_slice(self.event_id.as_bytes());
        out
    }

    pub fn canonical_hex(&self) -> String {
        eliot_contracts::sha256_hex(&self.canonical_bytes())
    }

    pub fn canonical_key(&self) -> String {
        self.canonical_hex()
    }
}

pub type EventReplayKey = EventIdentityKey;

pub fn event_replay_key(stream_id: &str, event_id: &str) -> String {
    EventIdentityKey::new(stream_id, event_id).canonical_hex()
}

/// A pure replay identity ledger for compatibility and fixture checking.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayLedger {
    entries: BTreeMap<EventIdentityKey, (u64, String)>,
}

impl ReplayLedger {
    /// Creates an empty replay ledger.  It is not durable storage.
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Records an event identity and returns its idempotent disposition.
    pub fn observe(&mut self, event: &EventEnvelope) -> Result<EventDisposition, ProtocolError> {
        event.validate()?;
        let key = event.replay_key();
        let digest =
            canonical_json_bytes(event).map_err(|error| ProtocolError::Json(error.to_string()))?;
        let digest = eliot_contracts::sha256_hex(&digest);
        if let Some((sequence, previous_digest)) = self.entries.get(&key) {
            if *sequence == event.sequence && previous_digest == &digest {
                return Ok(EventDisposition::Duplicate);
            }
            return Err(ProtocolError::ReplayConflict);
        }
        self.entries.insert(key, (event.sequence, digest));
        Ok(EventDisposition::Accepted)
    }

    /// Returns the number of identities currently held by this pure ledger.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this pure ledger has no identities.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Client-side EBP handshake declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    /// Supported protocol range.
    pub protocol_range: ProtocolRange,
    /// Module or bridge identity.
    pub module_bridge_identity: String,
    /// Immutable artifact identity/hash.
    pub artifact_hash: ArtifactId,
    /// Registered module contract asserted by the client.
    pub module_contract: ModuleContract,
    /// Exact immutable runtime generation asserted by the client.
    pub module_generation: ModuleGeneration,
    /// Launch nonce bound by the process/host owner.
    pub launch_nonce: String,
    /// Requested capabilities.
    pub capabilities: Vec<String>,
    /// Privacy classes the client may handle.
    pub privacy_classes: Vec<String>,
    /// Maximum frame body accepted by the client.
    pub max_frame: u32,
    /// State/authority epoch observed by the client.
    pub authority_epoch: AuthorityEpoch,
}

impl ClientHello {
    /// Validates the handshake declaration without authenticating it.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.protocol_range.validate()?;
        text(&self.module_bridge_identity, "module_bridge_identity")?;
        self.module_contract
            .validate()
            .map_err(|error| provider_error("eliot-runtime-contracts", error))?;
        self.module_generation
            .validate()
            .map_err(|error| provider_error("eliot-runtime-contracts", error))?;
        if self.module_contract.module_id.as_str() != self.module_bridge_identity
            || self.module_generation.module_id != self.module_contract.module_id
        {
            return Err(ProtocolError::InvalidField {
                field: "module_bridge_identity",
                reason: "must match module contract and generation identity",
            });
        }
        if self.module_contract.artifact_id != self.artifact_hash
            || self.module_generation.artifact_id != self.artifact_hash
        {
            return Err(ProtocolError::InvalidField {
                field: "artifact_hash",
                reason: "must match module contract and generation artifact",
            });
        }
        if self.module_generation.state_fence.authority_epoch != self.authority_epoch {
            return Err(ProtocolError::InvalidField {
                field: "authority_epoch",
                reason: "must match the registered module generation fence",
            });
        }
        text(&self.launch_nonce, "launch_nonce")?;
        unique_texts(&self.capabilities, "capabilities")?;
        unique_texts(&self.privacy_classes, "privacy_classes")?;
        if self.max_frame == 0 || self.max_frame > MAX_FRAME_BYTES_U32 {
            return Err(ProtocolError::InvalidField {
                field: "max_frame",
                reason: "must be within the admitted frame limit",
            });
        }
        Ok(())
    }
}

/// Immutable protected client declaration for one admitted agent-bridge generation.
///
/// This value is configuration, not authority. It contains no reusable request
/// identity, semantic principal, Session, task, `WorkScope`, plan, clock, current
/// fence, or admission-descriptor digest. Its Kernel principal/configuration
/// fields describe the expected transport handshake, not an `AgentSession`. Its
/// `ClientHello` is an immutable Host-materialized claim; Kernel must still
/// compare it with the separate admission descriptor and live evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeClientDeclaration {
    /// Declaration wire identity.
    pub wire_id: String,
    /// Declaration wire version.
    pub wire_version: u16,
    /// Exact module identity (`eliot-agent-bridge`).
    pub module_id: String,
    /// Stable connection identity assigned by the Kernel owner.
    pub connection_id: String,
    /// SID of the Kernel service process expected at the pipe peer.
    pub expected_kernel_sid: String,
    /// Session id of the Kernel service process expected at the pipe peer.
    /// Session zero is valid for a service process.
    pub expected_kernel_session_id: u32,
    /// Exact client handshake declaration approved for this installation.
    pub client_hello: ClientHello,
    /// Lowercase SHA-256 of canonical serialized `client_hello` bytes.
    pub client_hello_sha256: String,
    /// Protected Kernel handshake principal binding. This is not an `AgentSession` principal.
    pub expected_kernel_principal_binding: String,
    /// Protected authority epoch expected from the Kernel server.
    pub expected_kernel_authority_epoch: AuthorityEpoch,
    /// Protected immutable generation expected from the Kernel server.
    pub expected_kernel_generation: ResourceGeneration,
    /// Lowercase SHA-256 of the expected Kernel artifact.
    pub expected_kernel_artifact_sha256: String,
    /// Lowercase SHA-256 of the canonical Kernel `ServerHello.config_snapshot`.
    pub expected_kernel_config_snapshot_sha256: String,
    /// Lowercase SHA-256 over every declaration field except this field.
    pub declaration_sha256: String,
}

impl AgentBridgeClientDeclaration {
    /// Current declaration contract version.
    pub const CONTRACT_VERSION: u16 = AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION;

    /// Returns deterministic bytes covered by `declaration_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.declaration_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    /// Computes the canonical declaration digest.
    pub fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    /// Computes the canonical `ClientHello` digest bound by the admission descriptor.
    pub fn client_hello_digest(&self) -> Result<String, ProtocolError> {
        let bytes = canonical_json_bytes(&self.client_hello)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Populates the canonical declaration digest.
    pub fn with_computed_digest(mut self) -> Result<Self, ProtocolError> {
        self.declaration_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the protected declaration without opening a transport or issuing authority.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
            || self.module_id != AGENT_BRIDGE_MODULE_ID
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_bridge_client.wire",
                reason: "unsupported agent-bridge client declaration",
            });
        }
        text(&self.connection_id, "agent_bridge_client.connection_id")?;
        windows_sid(
            &self.expected_kernel_sid,
            "agent_bridge_client.expected_kernel_sid",
        )?;
        self.client_hello.validate()?;
        if self.client_hello.module_bridge_identity != AGENT_BRIDGE_MODULE_ID {
            return Err(ProtocolError::InvalidField {
                field: "agent_bridge_client.client_hello",
                reason: "must declare the exact agent-bridge module",
            });
        }
        if self.client_hello.module_generation.generation
            != self
                .client_hello
                .module_generation
                .state_fence
                .resource_generation
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_bridge_client.client_hello",
                reason: "generation must match the immutable ClientHello fence",
            });
        }
        for (value, field) in [
            (
                self.client_hello_sha256.as_str(),
                "agent_bridge_client.client_hello_sha256",
            ),
            (
                self.expected_kernel_artifact_sha256.as_str(),
                "agent_bridge_client.expected_kernel_artifact_sha256",
            ),
            (
                self.expected_kernel_config_snapshot_sha256.as_str(),
                "agent_bridge_client.expected_kernel_config_snapshot_sha256",
            ),
            (
                self.declaration_sha256.as_str(),
                "agent_bridge_client.declaration_sha256",
            ),
        ] {
            lowercase_sha256(value, field)?;
        }
        if self.client_hello_sha256 != self.client_hello_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_bridge_client.client_hello_sha256",
                reason: "must match the exact canonical ClientHello bytes",
            });
        }
        text(
            &self.expected_kernel_principal_binding,
            "agent_bridge_client.expected_kernel_principal_binding",
        )?;
        if self.declaration_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_bridge_client.declaration_sha256",
                reason: "declaration digest mismatch",
            });
        }
        Ok(())
    }
}

/// Server-side EBP handshake selection and capability declaration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    /// Selected protocol version.
    pub selected_protocol: ProtocolVersion,
    /// Session/principal binding assigned by the authority owner.
    pub session_principal_binding: String,
    /// Capabilities admitted for this session.
    pub allowed_capabilities: Vec<String>,
    /// Effects admitted for this session.
    pub allowed_effects: Vec<String>,
    /// Configuration snapshot associated with the handshake.
    pub config_snapshot: Value,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_ms: u32,
    /// Control channel identity.
    pub control_channel: String,
    /// Rejection reason when no session was admitted.
    pub rejection_reason: Option<String>,
    /// Authority epoch selected for the session.
    pub authority_epoch: AuthorityEpoch,
}

impl ServerHello {
    /// Validates the selected handshake shape without issuing authority.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.selected_protocol.validate()?;
        text(&self.session_principal_binding, "session_principal_binding")?;
        unique_texts(&self.allowed_capabilities, "allowed_capabilities")?;
        unique_texts(&self.allowed_effects, "allowed_effects")?;
        text(&self.control_channel, "control_channel")?;
        if self.heartbeat_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "heartbeat_ms",
                reason: "must be greater than zero",
            });
        }
        if let Some(reason) = &self.rejection_reason {
            text(reason, "rejection_reason")?;
        }
        Ok(())
    }
}

/// Stable identity for this protocol contract shape.
pub fn protocol_contract_identity() -> Result<ContractIdentity, ProtocolError> {
    #[derive(Serialize)]
    struct Shape {
        contract: &'static str,
        version: ContractVersion,
        frame_prefix_bytes: usize,
        max_frame_bytes: usize,
        encoding: EncodingProfile,
    }

    contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            contract: "EBP/1",
            version: CONTRACT_VERSION,
            frame_prefix_bytes: FRAME_PREFIX_BYTES,
            max_frame_bytes: MAX_FRAME_BYTES,
            encoding: EncodingProfile::JsonV1,
        },
    )
    .map_err(ProtocolError::Foundation)
}

/// JSON compatibility codec for the first EBP delivery profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonCodec {
    /// Maximum accepted encoded body length.
    pub max_frame_bytes: usize,
}

impl Default for JsonCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonCodec {
    /// Creates a codec with the governing four-mebibyte default.
    pub const fn new() -> Self {
        Self {
            max_frame_bytes: MAX_FRAME_BYTES,
        }
    }

    /// Creates a codec with a smaller bounded body limit.
    pub const fn with_max_frame_bytes(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes }
    }

    /// Encodes one validated JSON frame with a four-byte little-endian length.
    pub fn encode(&self, frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
        frame.validate()?;
        if frame.encoding_profile != EncodingProfile::JsonV1 {
            return Err(ProtocolError::UnsupportedEncoding(format!(
                "{:?}",
                frame.encoding_profile
            )));
        }
        let body =
            canonical_json_bytes(frame).map_err(|error| ProtocolError::Json(error.to_string()))?;
        let length = body.len();
        self.check_body_length(length)?;
        let length_u32 = u32::try_from(length).map_err(|_| ProtocolError::OversizeFrame {
            actual: length,
            maximum: self.max_frame_bytes,
        })?;
        let mut output = Vec::with_capacity(FRAME_PREFIX_BYTES + length);
        output.extend_from_slice(&length_u32.to_le_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes one complete length-delimited JSON frame.
    pub fn decode(&self, wire: &[u8]) -> Result<Frame, ProtocolError> {
        if wire.len() < FRAME_PREFIX_BYTES {
            return Err(ProtocolError::PartialFrame {
                expected: FRAME_PREFIX_BYTES,
                actual: wire.len(),
            });
        }
        let length = usize::try_from(u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]))
            .map_err(|_| ProtocolError::OversizeFrame {
                actual: usize::MAX,
                maximum: self.max_frame_bytes.min(MAX_FRAME_BYTES),
            })?;
        self.check_body_length(length)?;
        let available = wire.len() - FRAME_PREFIX_BYTES;
        if available < length {
            return Err(ProtocolError::PartialFrame {
                expected: length,
                actual: available,
            });
        }
        if available > length {
            return Err(ProtocolError::TrailingBytes);
        }
        self.decode_body(&wire[FRAME_PREFIX_BYTES..])
    }

    /// Reads one complete length-delimited frame from a synchronous reader.
    pub fn read_from<R: Read>(&self, reader: &mut R) -> Result<Frame, ProtocolError> {
        let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
        reader
            .read_exact(&mut prefix)
            .map_err(|error| ProtocolError::Io(error.to_string()))?;
        let length = usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| {
            ProtocolError::OversizeFrame {
                actual: usize::MAX,
                maximum: self.max_frame_bytes.min(MAX_FRAME_BYTES),
            }
        })?;
        self.check_body_length(length)?;
        let mut body = vec![0_u8; length];
        reader
            .read_exact(&mut body)
            .map_err(|error| ProtocolError::Io(error.to_string()))?;
        self.decode_body(&body)
    }

    fn decode_body(self, body: &[u8]) -> Result<Frame, ProtocolError> {
        self.check_body_length(body.len())?;
        if std::str::from_utf8(body).is_err() {
            return Err(ProtocolError::InvalidUtf8);
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|error| ProtocolError::Json(error.to_string()))?;
        if let Value::Object(object) = &value
            && let Some(Value::String(message_type)) = object.get("message_type")
            && !is_known_message_type(message_type)
        {
            return Err(ProtocolError::UnknownMessageType);
        }
        let frame: Frame = serde_json::from_value(value)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        frame.validate()?;
        Ok(frame)
    }

    fn check_body_length(self, length: usize) -> Result<(), ProtocolError> {
        if length == 0 {
            return Err(ProtocolError::ZeroLengthFrame);
        }
        let maximum = self.max_frame_bytes.min(MAX_FRAME_BYTES);
        if length > maximum {
            return Err(ProtocolError::OversizeFrame {
                actual: length,
                maximum,
            });
        }
        Ok(())
    }
}

fn is_known_message_type(value: &str) -> bool {
    matches!(
        value,
        "Start"
            | "Ready"
            | "Health"
            | "Execute"
            | "Result"
            | "Event"
            | "Cancel"
            | "Quiesce"
            | "Checkpoint"
            | "RestoreCheckpoint"
            | "DrainStatus"
            | "Shutdown"
            | "Fatal"
    )
}

/// Negotiates a protocol version and validates both handshake declarations.
pub fn negotiate(
    client: &ClientHello,
    server_range: ProtocolRange,
) -> Result<ProtocolVersion, ProtocolError> {
    client.validate()?;
    client.protocol_range.select(server_range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractVersion, ProductId,
        RequestMetadata, ResourceGeneration, SourceId,
    };
    use eliot_runtime_contracts::{HealthVector, ModuleGenerationState};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn agent_bridge_client_declaration() -> Result<AgentBridgeClientDeclaration, ProtocolError> {
        let module_id = ContractId::new(AGENT_BRIDGE_MODULE_ID)?;
        let artifact_id = ArtifactId::new("a".repeat(64))?;
        let client_hello = ClientHello {
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_bridge_identity: AGENT_BRIDGE_MODULE_ID.to_owned(),
            artifact_hash: artifact_id.clone(),
            module_contract: ModuleContract {
                module_id: module_id.clone(),
                version: ContractVersion::new(1, 0, 0),
                artifact_id: artifact_id.clone(),
                protocols: vec!["eliot.agent-bridge.v1".to_owned()],
                required_capabilities: vec!["agent.bridge.activate".to_owned()],
                optional_capabilities: Vec::new(),
                advisory_capabilities: Vec::new(),
                state_owner: "eliot-host".to_owned(),
                failure_domain: "agent-bridge".to_owned(),
                hot_replace: false,
            },
            module_generation: ModuleGeneration {
                module_id,
                generation: ResourceGeneration::genesis(),
                artifact_id,
                state: ModuleGenerationState::Starting,
                health: HealthVector::healthy(),
                state_fence: fence(),
            },
            launch_nonce: "agent-bridge:0123456789abcdef0123456789abcdef".to_owned(),
            capabilities: vec!["agent.bridge.activate".to_owned()],
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: MAX_FRAME_BYTES_U32,
            authority_epoch: AuthorityEpoch::genesis(),
        };
        let client_hello_sha256 = eliot_contracts::sha256_hex(
            &canonical_json_bytes(&client_hello)
                .map_err(|error| ProtocolError::Json(error.to_string()))?,
        );
        AgentBridgeClientDeclaration {
            wire_id: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            connection_id: "agent-bridge-connection-1".to_owned(),
            expected_kernel_sid: "S-1-5-18".to_owned(),
            expected_kernel_session_id: 0,
            client_hello,
            client_hello_sha256,
            expected_kernel_principal_binding: "kernel:agent-bridge".to_owned(),
            expected_kernel_authority_epoch: AuthorityEpoch::new(7)?,
            expected_kernel_generation: ResourceGeneration::new(11)?,
            expected_kernel_artifact_sha256: "b".repeat(64),
            expected_kernel_config_snapshot_sha256: "c".repeat(64),
            declaration_sha256: String::new(),
        }
        .with_computed_digest()
    }

    #[test]
    fn agent_bridge_client_declaration_roundtrips_and_admits_kernel_session_zero()
    -> Result<(), ProtocolError> {
        let declaration = agent_bridge_client_declaration()?;
        declaration.validate()?;
        assert_eq!(declaration.expected_kernel_session_id, 0);
        assert_ne!(
            declaration.expected_kernel_authority_epoch,
            declaration.client_hello.authority_epoch
        );
        assert_ne!(
            declaration.expected_kernel_generation,
            declaration.client_hello.module_generation.generation
        );
        assert_eq!(
            declaration.declaration_sha256,
            declaration.compute_digest()?
        );
        assert_eq!(
            declaration.client_hello_digest()?,
            eliot_contracts::sha256_hex(
                &canonical_json_bytes(&declaration.client_hello)
                    .map_err(|error| ProtocolError::Json(error.to_string()))?
            )
        );

        let encoded = serde_json::to_vec(&declaration)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        let decoded: AgentBridgeClientDeclaration = serde_json::from_slice(&encoded)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        assert_eq!(decoded, declaration);

        let mut forbidden = serde_json::to_value(&declaration)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        let object = forbidden
            .as_object_mut()
            .ok_or(ProtocolError::InvalidField {
                field: "agent_bridge_client",
                reason: "test declaration must serialize as an object",
            })?;
        for forbidden_field in [
            "descriptor_sha256",
            "request_identity",
            "principal_id",
            "session_id",
            "task_id",
            "work_scope_id",
            "plan_id",
            "current_fence",
        ] {
            assert!(!object.contains_key(forbidden_field));
        }
        object.insert(
            "descriptor_sha256".to_owned(),
            Value::String("d".repeat(64)),
        );
        assert!(serde_json::from_value::<AgentBridgeClientDeclaration>(forbidden).is_err());
        Ok(())
    }

    #[test]
    fn agent_bridge_client_declaration_rejects_digest_and_authority_mismatches()
    -> Result<(), ProtocolError> {
        let declaration = agent_bridge_client_declaration()?;

        let mut stale_generation = declaration.clone();
        stale_generation.client_hello.module_generation.generation = ResourceGeneration::new(2)?;
        stale_generation.declaration_sha256 = stale_generation.compute_digest()?;
        assert!(stale_generation.validate().is_err());

        let mut wrong_hello = declaration.clone();
        wrong_hello.client_hello_sha256 = "0".repeat(64);
        wrong_hello.declaration_sha256 = wrong_hello.compute_digest()?;
        assert!(wrong_hello.validate().is_err());

        let mut uppercase_digest = declaration.clone();
        uppercase_digest.expected_kernel_artifact_sha256 = "A".repeat(64);
        uppercase_digest.declaration_sha256 = uppercase_digest.compute_digest()?;
        assert!(uppercase_digest.validate().is_err());

        let mut wrong_module = declaration.clone();
        wrong_module.module_id = "other-bridge".to_owned();
        wrong_module.declaration_sha256 = wrong_module.compute_digest()?;
        assert!(wrong_module.validate().is_err());

        let mut wrong_self_digest = declaration;
        wrong_self_digest.declaration_sha256 = "f".repeat(64);
        assert!(wrong_self_digest.validate().is_err());
        Ok(())
    }

    fn encoded_length(length: usize) -> Result<u32, ProtocolError> {
        u32::try_from(length).map_err(|_| ProtocolError::OversizeFrame {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        })
    }

    fn decoded_length(prefix: [u8; 4]) -> Result<usize, ProtocolError> {
        usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| ProtocolError::OversizeFrame {
            actual: usize::MAX,
            maximum: MAX_FRAME_BYTES,
        })
    }

    fn frame() -> Result<Frame, ProtocolError> {
        let request_id = RequestId::new("request-1")?;
        let state_fence = fence();
        Ok(Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: "connection-1".to_owned(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(RequestIdentity {
                request: RequestBinding {
                    metadata: RequestMetadata {
                        request_id,
                        session_id: None,
                        task_id: None,
                        product_id: ProductId::new("product-1")?,
                        source_id: SourceId::new("source-1")?,
                        state_fence: state_fence.clone(),
                        clock: ClockReading::default(),
                    },
                    state_fence,
                },
                idempotency_key: "idem-1".to_owned(),
                deadline_unix_ms: 10,
                cancellation_id: "cancel-1".to_owned(),
            }),
            payload: ProtocolPayload::Json(serde_json::json!({"command":"health"})),
            trace_context: BTreeMap::from([(String::from("trace"), String::from("t-1"))]),
        })
    }

    fn event() -> EventEnvelope {
        EventEnvelope {
            stream_id: "stream-1".to_owned(),
            producer_id: "module-1".to_owned(),
            producer_generation: ResourceGeneration::genesis(),
            authority_epoch: AuthorityEpoch::genesis(),
            event_id: "event-1".to_owned(),
            sequence: 1,
            causal_predecessor_refs: Vec::new(),
            delivery_class: DeliveryClass::DurableControl,
            ack_required: true,
            payload_type: "health".to_owned(),
            payload_or_blob_ref: EventPayload::Inline(Box::new(ProtocolPayload::Json(
                serde_json::json!({"ok":true}),
            ))),
            state_fence: fence(),
            trace_context: BTreeMap::new(),
        }
    }

    #[test]
    fn json_codec_roundtrips_length_delimited_frame() -> Result<(), ProtocolError> {
        let codec = JsonCodec::new();
        let source = frame()?;
        let wire = codec.encode(&source)?;
        assert_eq!(
            decoded_length([wire[0], wire[1], wire[2], wire[3]])?,
            wire.len() - 4
        );
        assert_eq!(codec.decode(&wire)?, source);
        Ok(())
    }

    #[test]
    fn malformed_zero_partial_oversize_and_trailing_frames_fail_closed() -> Result<(), ProtocolError>
    {
        let codec = JsonCodec::new();
        assert!(matches!(
            codec.decode(&[0, 0, 0, 0]),
            Err(ProtocolError::ZeroLengthFrame)
        ));
        assert!(matches!(
            codec.decode(&[1, 0]),
            Err(ProtocolError::PartialFrame { .. })
        ));
        assert!(matches!(
            codec.decode(&[5, 0, 0, 0, b'{']),
            Err(ProtocolError::PartialFrame { .. })
        ));
        let oversized = [0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            codec.decode(&oversized),
            Err(ProtocolError::OversizeFrame { .. })
        ));
        let source = frame()?;
        let mut trailing = codec.encode(&source)?;
        trailing.push(0);
        assert!(matches!(
            codec.decode(&trailing),
            Err(ProtocolError::TrailingBytes)
        ));
        Ok(())
    }

    #[test]
    fn malformed_types_and_unknown_fields_are_rejected() -> Result<(), ProtocolError> {
        let malformed = br#"{"protocol_version":{"major":"1","minor":0},"encoding_profile":"json-v1","connection_id":"c","request_id":null,"kind":"heartbeat","message_type":"Execute","request_identity":null,"payload":{},"trace_context":{}}"#;
        let mut wire = Vec::with_capacity(4 + malformed.len());
        wire.extend_from_slice(&encoded_length(malformed.len())?.to_le_bytes());
        wire.extend_from_slice(malformed);
        assert!(matches!(
            JsonCodec::new().decode(&wire),
            Err(ProtocolError::Json(_))
        ));

        let source = frame()?;
        let mut value =
            serde_json::to_value(source).map_err(|error| ProtocolError::Json(error.to_string()))?;
        if let Value::Object(object) = &mut value {
            object.insert("unknown".to_owned(), Value::Bool(true));
        }
        let body =
            serde_json::to_vec(&value).map_err(|error| ProtocolError::Json(error.to_string()))?;
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&encoded_length(body.len())?.to_le_bytes());
        wire.extend_from_slice(&body);
        assert!(matches!(
            JsonCodec::new().decode(&wire),
            Err(ProtocolError::Json(_))
        ));

        if let Value::Object(object) = &mut value {
            object.insert(
                "message_type".to_owned(),
                Value::String("UnknownLifecycleMessage".to_owned()),
            );
        }
        let body =
            serde_json::to_vec(&value).map_err(|error| ProtocolError::Json(error.to_string()))?;
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&encoded_length(body.len())?.to_le_bytes());
        wire.extend_from_slice(&body);
        assert!(matches!(
            JsonCodec::new().decode(&wire),
            Err(ProtocolError::UnknownMessageType)
        ));
        Ok(())
    }

    #[test]
    fn duplicate_replay_is_idempotent_but_conflicting_sequence_fails() -> Result<(), ProtocolError>
    {
        let mut ledger = ReplayLedger::new();
        let first = event();
        assert_eq!(ledger.observe(&first)?, EventDisposition::Accepted);
        assert_eq!(ledger.observe(&first)?, EventDisposition::Duplicate);
        let mut conflict = first.clone();
        conflict.sequence = 2;
        assert_eq!(
            ledger.observe(&conflict),
            Err(ProtocolError::ReplayConflict)
        );
        assert_eq!(ledger.len(), 1);
        Ok(())
    }

    #[test]
    fn event_ack_phases_do_not_skip_durable_normalization() {
        assert!(EventAckReceipt::validate_advance(AckPhase::Received, AckPhase::Durable).is_ok());
        assert!(EventAckReceipt::validate_advance(AckPhase::Received, AckPhase::Applied).is_err());
        assert!(EventAckReceipt::validate_advance(AckPhase::Normalized, AckPhase::Unknown).is_ok());
    }

    #[test]
    fn handshake_selection_preserves_major_and_highest_minor() -> Result<(), ProtocolError> {
        let left = ProtocolRange {
            minimum: ProtocolVersion { major: 1, minor: 0 },
            maximum: ProtocolVersion { major: 1, minor: 2 },
        };
        let right = ProtocolRange {
            minimum: ProtocolVersion { major: 1, minor: 1 },
            maximum: ProtocolVersion { major: 1, minor: 3 },
        };
        assert_eq!(left.select(right)?, ProtocolVersion { major: 1, minor: 2 });
        Ok(())
    }

    #[test]
    fn event_rejects_authority_epoch_mismatch() -> Result<(), ProtocolError> {
        let mut value = event();
        value.authority_epoch = AuthorityEpoch::new(2)?;
        assert!(matches!(
            value.validate(),
            Err(ProtocolError::InvalidField {
                field: "authority_epoch",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn contract_identity_is_stable() -> Result<(), ProtocolError> {
        let identity = protocol_contract_identity()?;
        assert_eq!(identity.name.as_str(), CONTRACT_NAME);
        assert_eq!(identity.version, CONTRACT_VERSION);
        Ok(())
    }

    #[test]
    fn colon_pair_stream_event_remains_distinct_via_length_prefixed_key()
    -> Result<(), ProtocolError> {
        let mut ledger = ReplayLedger::new();
        let mut first = event();
        first.stream_id = "s:e".to_owned();
        first.event_id = "x".to_owned();
        first.sequence = 1;
        let mut second = event();
        second.stream_id = "s".to_owned();
        second.event_id = "e:x".to_owned();
        second.sequence = 1;
        assert_ne!(
            event_replay_key(&first.stream_id, &first.event_id),
            event_replay_key(&second.stream_id, &second.event_id)
        );
        assert_ne!(first.replay_key(), second.replay_key());
        assert_eq!(ledger.observe(&first)?, EventDisposition::Accepted);
        assert_eq!(ledger.observe(&second)?, EventDisposition::Accepted);
        assert_eq!(ledger.len(), 2);
        let duplicate = first.clone();
        assert_eq!(ledger.observe(&duplicate)?, EventDisposition::Duplicate);
        let mut conflict = first.clone();
        conflict.sequence = 2;
        assert_eq!(
            ledger.observe(&conflict),
            Err(ProtocolError::ReplayConflict)
        );
        Ok(())
    }

    #[test]
    fn event_replay_key_is_injective_for_empty_vs_colon() {
        assert_ne!(event_replay_key("a:b", "c"), event_replay_key("a", "b:c"));
        assert_ne!(event_replay_key("s:e", "x"), event_replay_key("s", "e:x"));
        assert_eq!(
            event_replay_key("s", "e"),
            EventReplayKey::new("s", "e").canonical_key()
        );
    }
}
