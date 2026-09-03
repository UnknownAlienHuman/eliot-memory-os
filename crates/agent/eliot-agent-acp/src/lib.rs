//! A bounded, provider-neutral ACP v1 compatibility cell.
//!
//! This package owns protocol framing, typed JSON-RPC shapes, capability
//! negotiation, and the mapping between an external ACP session and one ELIOT
//! attempt.  It deliberately does not spawn a process, open a socket, render
//! UI, persist task state, or create authority.  Callers provide transport and
//! use [`AcpProcessBinding`] when physical process lifecycle is required; that
//! binding delegates only to the P-03 [`eliot_process::ProcessExecutor`]
//! contract.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_agent_api::{
    ActualRouteReceipt, AgentAttempt, AgentResult, AttemptId, AuthorityEnvelope, EffectKind,
    EventCursor, EventId, HostEventKind, QuotaKnowledge, ResultDisposition, RouteFingerprint,
    RouteFingerprintId, TaskId, UsageReceipt,
};
use eliot_process::{
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessRequest,
    ProcessStartReceipt,
};
use eliot_source_assurance::{
    AdmissionExpectation, AdmissionOutcome, SourceAssurance, SourceAssuranceError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;
use thiserror::Error;

/// Stable package schema revision.
pub const ACP_SCHEMA_VERSION: &str = "eliot-agent-acp/v1";
/// Stable ACP protocol line supported by this adapter.
pub const ACP_PROTOCOL_VERSION: u16 = 1;
/// Maximum header section accepted by the bounded framing parser.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8 * 1024;
/// Maximum JSON payload accepted by the bounded framing parser.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Error returned by the bounded ACP frame parser and wire validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcpProtocolError {
    /// The frame or header exceeded a configured bound.
    #[error("ACP {field} exceeds limit {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    /// A required framing header was absent or repeated.
    #[error("ACP framing header is invalid: {0}")]
    InvalidHeader(&'static str),
    /// The body length did not match the frame.
    #[error("ACP frame body is incomplete")]
    IncompleteFrame,
    /// The body was not UTF-8 JSON.
    #[error("ACP JSON payload is invalid: {0}")]
    InvalidJson(String),
    /// The JSON-RPC envelope is structurally invalid.
    #[error("ACP JSON-RPC envelope is invalid: {0}")]
    InvalidEnvelope(String),
    /// A stable protocol version is required.
    #[error("ACP protocol version {observed} is not supported")]
    UnsupportedVersion { observed: u16 },
}

/// Typed unavailable outcome.  Unavailability is not a failed execution and
/// must never be converted into a successful result by a fallback.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcpUnavailableReason {
    /// The remote advertised a capability that was not probed/admitted.
    #[error("capability was not negotiated: {0}")]
    CapabilityNotNegotiated(String),
    /// The requested operation is outside the ELIOT authority ceiling.
    #[error("operation is outside the authority ceiling")]
    AuthorityCeiling,
    /// Q-01 did not admit the bound source set.
    #[error("source assurance was not admitted")]
    SourceNotAdmitted,
    /// The stable protocol line is unavailable.
    #[error("stable ACP protocol line is unavailable")]
    UnsupportedProtocol,
    /// The external route is not attached.
    #[error("ACP route is unavailable: {0}")]
    RouteUnavailable(String),
}

/// A typed, non-authoritative unknown result requiring reconciliation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("ACP operation outcome is unknown and requires reconciliation: {reason}")]
pub struct AcpUnknownOutcome {
    /// ELIOT operation identity, not a vendor task identity.
    pub operation_id: String,
    /// Safe, bounded explanation.
    pub reason: String,
    /// External session identity when one was known.
    pub session_id: Option<String>,
}

/// An operation result whose unavailable and unknown states remain explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcpOutcome<T> {
    /// The adapter observed a complete response.
    Completed(T),
    /// The operation was not admitted or cannot be performed.
    Unavailable {
        operation: String,
        reason: AcpUnavailableReason,
    },
    /// The operation may have had an external effect and must be reconciled.
    Unknown(AcpUnknownOutcome),
}

impl<T> AcpOutcome<T> {
    /// Returns whether this is a completed result.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }
}

/// A bounded ACP content-length frame codec.  ACP stdio is transport-neutral
/// here: this codec accepts arbitrary chunks and never reads stdin itself.
#[derive(Clone, Debug)]
pub struct AcpFrameCodec {
    buffer: Vec<u8>,
    max_header_bytes: usize,
    max_frame_bytes: usize,
}

impl Default for AcpFrameCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_FRAME_BYTES)
    }
}

impl AcpFrameCodec {
    /// Creates a parser with explicit header and body bounds.
    pub fn new(max_header_bytes: usize, max_frame_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_header_bytes,
            max_frame_bytes,
        }
    }

    /// Encodes one JSON payload using ACP's deterministic content-length
    /// framing.  The payload is not parsed, allowing callers to retain exact
    /// JSON bytes while the protocol layer remains vendor-neutral.
    pub fn encode(payload: &[u8]) -> Result<Vec<u8>, AcpProtocolError> {
        Self::encode_bounded(payload, DEFAULT_MAX_FRAME_BYTES)
    }

    /// Encodes one payload with an explicit configured bound.
    pub fn encode_bounded(
        payload: &[u8],
        max_frame_bytes: usize,
    ) -> Result<Vec<u8>, AcpProtocolError> {
        if payload.is_empty() {
            return Err(AcpProtocolError::InvalidHeader("empty payload"));
        }
        if payload.len() > max_frame_bytes {
            return Err(AcpProtocolError::LimitExceeded {
                field: "frame",
                limit: max_frame_bytes,
            });
        }
        let mut frame = format!("Content-Length: {}\r\n\r\n", payload.len()).into_bytes();
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    /// Feeds one arbitrary transport chunk and returns every complete body.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, AcpProtocolError> {
        self.buffer.extend_from_slice(chunk);
        let mut output = Vec::new();
        loop {
            let Some(separator) = find_header_end(&self.buffer) else {
                if self.buffer.len() > self.max_header_bytes {
                    return Err(AcpProtocolError::LimitExceeded {
                        field: "headers",
                        limit: self.max_header_bytes,
                    });
                }
                break;
            };
            if separator > self.max_header_bytes {
                return Err(AcpProtocolError::LimitExceeded {
                    field: "headers",
                    limit: self.max_header_bytes,
                });
            }
            let headers = parse_content_length(&self.buffer[..separator])?;
            if headers > self.max_frame_bytes {
                return Err(AcpProtocolError::LimitExceeded {
                    field: "frame",
                    limit: self.max_frame_bytes,
                });
            }
            let body_start = separator + 4;
            let needed =
                body_start
                    .checked_add(headers)
                    .ok_or(AcpProtocolError::LimitExceeded {
                        field: "frame",
                        limit: self.max_frame_bytes,
                    })?;
            if self.buffer.len() < needed {
                break;
            }
            output.push(self.buffer[body_start..needed].to_vec());
            self.buffer.drain(..needed);
        }
        Ok(output)
    }

    /// Rejects a transport close while a partial frame is buffered.
    pub fn finish(&self) -> Result<(), AcpProtocolError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(AcpProtocolError::IncompleteFrame)
        }
    }

    /// Returns the configured frame bound.
    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

/// Alias used by callers that prefer decoder terminology.
pub type AcpFrameDecoder = AcpFrameCodec;

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Result<usize, AcpProtocolError> {
    let text = std::str::from_utf8(headers)
        .map_err(|_| AcpProtocolError::InvalidHeader("headers are not UTF-8"))?;
    let mut length = None;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            return Err(AcpProtocolError::InvalidHeader("malformed header"));
        };
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if length.is_some() {
            return Err(AcpProtocolError::InvalidHeader("duplicate content-length"));
        }
        let parsed = value
            .trim()
            .parse::<usize>()
            .map_err(|_| AcpProtocolError::InvalidHeader("invalid content-length"))?;
        if parsed == 0 {
            return Err(AcpProtocolError::InvalidHeader(
                "content-length must be greater than zero",
            ));
        }
        length = Some(parsed);
    }
    length.ok_or(AcpProtocolError::InvalidHeader("missing content-length"))
}

/// JSON-RPC request identifier.  ACP permits string or integer identifiers.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
pub enum AcpRequestId {
    /// Integer JSON-RPC identifier.
    Number(u64),
    /// Non-empty string JSON-RPC identifier.
    Text(String),
}

impl Serialize for AcpRequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Number(value) => serializer.serialize_u64(*value),
            Self::Text(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for AcpRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => number
                .as_u64()
                .map(Self::Number)
                .ok_or_else(|| de::Error::custom("request id must be a non-negative integer")),
            Value::String(value) if !value.trim().is_empty() => Ok(Self::Text(value)),
            _ => Err(de::Error::custom("request id must be a string or integer")),
        }
    }
}

/// JSON-RPC error object with bounded, provider-safe data.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpRpcError {
    /// JSON-RPC error code.
    pub code: i64,
    /// Safe error summary.
    pub message: String,
    /// Optional structured details, never required for reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC request in the ACP wire format.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpJsonRpcRequest {
    /// JSON-RPC version marker.
    pub jsonrpc: String,
    /// Request identity.
    pub id: AcpRequestId,
    /// ACP method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC notification in the ACP wire format.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpJsonRpcNotification {
    /// JSON-RPC version marker.
    pub jsonrpc: String,
    /// ACP method name.
    pub method: String,
    /// Notification parameters.
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC response in the ACP wire format.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpJsonRpcResponse {
    /// JSON-RPC version marker.
    pub jsonrpc: String,
    /// Request identity.
    pub id: AcpRequestId,
    /// Successful result, mutually exclusive with `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error result, mutually exclusive with `result`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AcpRpcError>,
}

/// A validated JSON-RPC message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcpJsonRpcMessage {
    /// Request message.
    Request(AcpJsonRpcRequest),
    /// Notification message.
    Notification(AcpJsonRpcNotification),
    /// Response message.
    Response(AcpJsonRpcResponse),
}

impl AcpJsonRpcMessage {
    /// Parses and validates exactly one ACP JSON-RPC message.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, AcpProtocolError> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| AcpProtocolError::InvalidJson(error.to_string()))?;
        Self::from_value(value)
    }

    /// Parses one body returned by [`AcpFrameCodec::feed`].
    pub fn from_frame(body: &[u8]) -> Result<Self, AcpProtocolError> {
        Self::from_json_slice(body)
    }

    /// Serializes the validated message as compact deterministic JSON.
    pub fn to_json_vec(&self) -> Result<Vec<u8>, AcpProtocolError> {
        serde_json::to_vec(self).map_err(|error| AcpProtocolError::InvalidJson(error.to_string()))
    }

    fn from_value(value: Value) -> Result<Self, AcpProtocolError> {
        let object = value
            .as_object()
            .ok_or_else(|| AcpProtocolError::InvalidEnvelope("message must be an object".into()))?;
        let jsonrpc = object
            .get("jsonrpc")
            .and_then(Value::as_str)
            .ok_or_else(|| AcpProtocolError::InvalidEnvelope("jsonrpc is missing".into()))?;
        if jsonrpc != "2.0" {
            return Err(AcpProtocolError::InvalidEnvelope(
                "jsonrpc must be 2.0".into(),
            ));
        }
        let has_method = object.contains_key("method");
        let has_id = object.contains_key("id");
        let has_result = object.contains_key("result");
        let has_error = object.contains_key("error");
        if has_method {
            if has_result || has_error {
                return Err(AcpProtocolError::InvalidEnvelope(
                    "method cannot be combined with result/error".into(),
                ));
            }
            if has_id {
                let request: AcpJsonRpcRequest = serde_json::from_value(value)
                    .map_err(|error| AcpProtocolError::InvalidEnvelope(error.to_string()))?;
                if request.method.trim().is_empty() {
                    return Err(AcpProtocolError::InvalidEnvelope(
                        "method must not be blank".into(),
                    ));
                }
                Ok(Self::Request(request))
            } else {
                let notification: AcpJsonRpcNotification = serde_json::from_value(value)
                    .map_err(|error| AcpProtocolError::InvalidEnvelope(error.to_string()))?;
                if notification.method.trim().is_empty() {
                    return Err(AcpProtocolError::InvalidEnvelope(
                        "method must not be blank".into(),
                    ));
                }
                Ok(Self::Notification(notification))
            }
        } else if has_id && (has_result ^ has_error) {
            let response: AcpJsonRpcResponse = serde_json::from_value(value)
                .map_err(|error| AcpProtocolError::InvalidEnvelope(error.to_string()))?;
            if let Some(error) = &response.error
                && error.message.trim().is_empty()
            {
                return Err(AcpProtocolError::InvalidEnvelope(
                    "error message must not be blank".into(),
                ));
            }
            Ok(Self::Response(response))
        } else {
            Err(AcpProtocolError::InvalidEnvelope(
                "message must be request, notification, or response".into(),
            ))
        }
    }
}

impl<'de> Deserialize<'de> for AcpJsonRpcMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(de::Error::custom)
    }
}

impl Serialize for AcpJsonRpcMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Request(value) => value.serialize(serializer),
            Self::Notification(value) => value.serialize(serializer),
            Self::Response(value) => value.serialize(serializer),
        }
    }
}

/// Short provider-neutral aliases for callers that do not need to distinguish
/// the JSON-RPC layer from the ACP adapter layer.
pub type AcpRequest = AcpJsonRpcRequest;
/// Short notification alias.
pub type AcpNotification = AcpJsonRpcNotification;
/// Short response alias.
pub type AcpResponse = AcpJsonRpcResponse;
/// Short message alias.
pub type AcpMessage = AcpJsonRpcMessage;

/// A protocol capability is a stable string so unknown future capabilities
/// can be retained without vendor types in this crate's public API.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpCapabilitySet {
    /// Capabilities advertised by the remote.
    #[serde(default)]
    pub advertised: BTreeSet<String>,
    /// Capabilities directly probed on the exact adapter/runtime.
    #[serde(default)]
    pub probed: BTreeSet<String>,
    /// Capabilities admitted for this ELIOT binding.
    #[serde(default)]
    pub admitted: BTreeSet<String>,
}

impl AcpCapabilitySet {
    /// Creates a set from advertisement only.  It has no admitted operations.
    pub fn advertised(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            advertised: values.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Marks a capability as directly probed and admitted only when advertised.
    pub fn probe(&mut self, capability: impl Into<String>) -> Result<(), AcpUnavailableReason> {
        let capability = capability.into();
        if !self.advertised.contains(&capability) {
            return Err(AcpUnavailableReason::CapabilityNotNegotiated(capability));
        }
        self.probed.insert(capability.clone());
        self.admitted.insert(capability);
        Ok(())
    }

    /// Validates the evidence ordering: admitted ⊆ probed ⊆ advertised.
    pub fn validate(&self) -> Result<(), AcpUnavailableReason> {
        if let Some(capability) = self
            .probed
            .iter()
            .find(|value| !self.advertised.contains(*value))
        {
            return Err(AcpUnavailableReason::CapabilityNotNegotiated(
                capability.clone(),
            ));
        }
        if let Some(capability) = self
            .admitted
            .iter()
            .find(|value| !self.probed.contains(*value))
        {
            return Err(AcpUnavailableReason::CapabilityNotNegotiated(
                capability.clone(),
            ));
        }
        Ok(())
    }

    /// Returns whether the operation is admitted after a direct probe.
    #[must_use]
    pub fn admits(&self, capability: &str) -> bool {
        self.admitted.contains(capability)
    }

    /// Intersects remote advertisement, probes and local requirements.
    pub fn negotiate(&self, required: &BTreeSet<String>) -> Result<Self, AcpUnavailableReason> {
        self.validate()?;
        let missing = required
            .iter()
            .find(|capability| !self.admitted.contains(*capability));
        if let Some(capability) = missing {
            return Err(AcpUnavailableReason::CapabilityNotNegotiated(
                capability.clone(),
            ));
        }
        Ok(self.clone())
    }
}

/// Stable/experimental ACP version line.  V2 is represented for explicit
/// diagnostic state but never silently admitted by this compatibility cell.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcpVersionLine {
    /// ACP v1 production compatibility baseline.
    V1,
    /// ACP v2 draft, requiring a separately admitted profile.
    V2Draft,
}

impl TryFrom<u16> for AcpVersionLine {
    type Error = AcpProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2Draft),
            observed => Err(AcpProtocolError::UnsupportedVersion { observed }),
        }
    }
}

/// ACP initialize request projection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpHandshakeRequest {
    /// ACP protocol integer version.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u16,
    /// Adapter identity, not a provider model identity.
    #[serde(rename = "clientName")]
    pub client_name: String,
    /// Exact adapter version.
    #[serde(rename = "clientVersion")]
    pub client_version: String,
    /// Advertisement and probe state for this adapter.
    pub capabilities: AcpCapabilitySet,
}

/// ACP initialize response projection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpHandshakeResponse {
    /// ACP protocol integer version.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u16,
    /// External runtime identity.
    #[serde(rename = "serverName")]
    pub server_name: String,
    /// External runtime version.
    #[serde(rename = "serverVersion")]
    pub server_version: String,
    /// Capabilities advertised by the exact runtime.
    pub capabilities: AcpCapabilitySet,
}

/// Result of a stable v1 handshake after capability intersection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpNegotiation {
    /// Stable protocol line.
    pub version: AcpVersionLine,
    /// Exact client/runtime identity used for route evidence.
    pub server_name: String,
    /// Exact runtime version used for route evidence.
    pub server_version: String,
    /// Capability state after direct probes.
    pub capabilities: AcpCapabilitySet,
}

impl AcpNegotiation {
    /// Accepts only ACP v1 and already-probed required capabilities.
    pub fn accept(
        response: AcpHandshakeResponse,
        required: &BTreeSet<String>,
    ) -> Result<Self, AcpProtocolError> {
        if response.protocol_version != ACP_PROTOCOL_VERSION {
            return Err(AcpProtocolError::UnsupportedVersion {
                observed: response.protocol_version,
            });
        }
        if response.server_name.trim().is_empty() || response.server_version.trim().is_empty() {
            return Err(AcpProtocolError::InvalidEnvelope(
                "server identity must not be blank".into(),
            ));
        }
        response
            .capabilities
            .negotiate(required)
            .map(|capabilities| Self {
                version: AcpVersionLine::V1,
                server_name: response.server_name,
                server_version: response.server_version,
                capabilities,
            })
            .map_err(|reason| AcpProtocolError::InvalidEnvelope(reason.to_string()))
    }
}

/// A deterministic mapping from one external ACP session to one ELIOT attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpSessionBinding {
    /// Durable ELIOT attempt identity.
    pub attempt_id: AttemptId,
    /// Durable ELIOT task identity.
    pub task_id: TaskId,
    /// External ACP session identity.
    pub external_session_id: String,
    /// Route fingerprint captured at bind time.
    pub route: RouteFingerprint,
    /// Exact adapter/runtime revision.
    pub adapter_revision: String,
    /// Monotonic reconnect epoch.
    pub reconnect_epoch: u64,
}

impl AcpSessionBinding {
    /// Validates an external mapping without making it authoritative.
    pub fn validate(&self) -> Result<(), AcpSessionError> {
        if self.external_session_id.trim().is_empty() || self.adapter_revision.trim().is_empty() {
            return Err(AcpSessionError::InvalidBinding);
        }
        if self.reconnect_epoch == 0 {
            return Err(AcpSessionError::InvalidBinding);
        }
        self.route
            .validate()
            .map_err(|_| AcpSessionError::InvalidBinding)
    }
}

/// Session mapping errors, including stale/reused external sessions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcpSessionError {
    /// A mapping did not satisfy its identity invariants.
    #[error("ACP session binding is invalid")]
    InvalidBinding,
    /// The external session identity is already mapped to another attempt.
    #[error("ACP session is already bound to another attempt")]
    DuplicateSession,
    /// No mapping exists for the requested external session.
    #[error("ACP session is not bound")]
    NotBound,
    /// A reconnect carried a stale epoch or mismatched route.
    #[error("ACP reconnect is stale or mismatched")]
    StaleReconnect,
}

/// Bounded external-session registry; it is an in-memory projection only.
#[derive(Clone, Debug, Default)]
pub struct AcpSessionRegistry {
    bindings: BTreeMap<String, AcpSessionBinding>,
    max_sessions: usize,
}

impl AcpSessionRegistry {
    /// Creates a registry with a non-zero session bound.
    pub fn new(max_sessions: usize) -> Result<Self, AcpSessionError> {
        if max_sessions == 0 {
            return Err(AcpSessionError::InvalidBinding);
        }
        Ok(Self {
            bindings: BTreeMap::new(),
            max_sessions,
        })
    }

    /// Binds a new external session exactly once.
    pub fn bind(&mut self, binding: AcpSessionBinding) -> Result<(), AcpSessionError> {
        binding.validate()?;
        if self.bindings.contains_key(&binding.external_session_id) {
            return Err(AcpSessionError::DuplicateSession);
        }
        if self.bindings.len() >= self.max_sessions {
            return Err(AcpSessionError::InvalidBinding);
        }
        self.bindings
            .insert(binding.external_session_id.clone(), binding);
        Ok(())
    }

    /// Looks up a session mapping without changing it.
    pub fn get(&self, external_session_id: &str) -> Result<&AcpSessionBinding, AcpSessionError> {
        self.bindings
            .get(external_session_id)
            .ok_or(AcpSessionError::NotBound)
    }

    /// Checks that an incoming event still belongs to the mapped attempt and
    /// exact route.  A stale external event cannot create or move a mapping.
    pub fn validate_event(
        &self,
        external_session_id: &str,
        attempt_id: &AttemptId,
        route: &RouteFingerprint,
    ) -> Result<(), AcpSessionError> {
        let binding = self.get(external_session_id)?;
        if &binding.attempt_id != attempt_id || &binding.route != route {
            return Err(AcpSessionError::StaleReconnect);
        }
        Ok(())
    }

    /// Replaces a mapping only with a strictly newer reconnect epoch and the
    /// same attempt/route identity.
    pub fn reconnect(&mut self, binding: AcpSessionBinding) -> Result<(), AcpSessionError> {
        binding.validate()?;
        let current = self
            .bindings
            .get(&binding.external_session_id)
            .ok_or(AcpSessionError::NotBound)?;
        if current.attempt_id != binding.attempt_id
            || current.task_id != binding.task_id
            || current.route != binding.route
            || binding.reconnect_epoch <= current.reconnect_epoch
        {
            return Err(AcpSessionError::StaleReconnect);
        }
        self.bindings
            .insert(binding.external_session_id.clone(), binding);
        Ok(())
    }

    /// Removes a session mapping after a caller-owned close decision.
    pub fn unbind(
        &mut self,
        external_session_id: &str,
    ) -> Result<AcpSessionBinding, AcpSessionError> {
        self.bindings
            .remove(external_session_id)
            .ok_or(AcpSessionError::NotBound)
    }

    /// Returns the number of active external mappings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Returns whether no external mappings are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// Provider-neutral ACP operation kind.  The string value is deliberately
/// stable and does not import a vendor SDK enum.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpOperationKind {
    /// Create a session.
    SessionNew,
    /// Load a persisted external session when directly probed.
    SessionLoad,
    /// Resume a known external session when directly probed.
    SessionResume,
    /// Submit one prompt/request.
    Prompt,
    /// Request cancellation.
    Cancel,
    /// Close an external session.
    SessionClose,
    /// Reconnect to the same session/attempt mapping.
    Reconnect,
    /// Probe an optional capability on the exact runtime.
    Probe,
}

impl AcpOperationKind {
    /// Returns the stable capability marker challenged before this operation.
    #[must_use]
    pub const fn capability_name(&self) -> &'static str {
        match self {
            Self::SessionNew => "session/new",
            Self::SessionLoad => "session/load",
            Self::SessionResume => "session/resume",
            Self::Prompt => "session/prompt",
            Self::Cancel => "session/cancel",
            Self::SessionClose => "session/close",
            Self::Reconnect => "session/reconnect",
            Self::Probe => "capability/probe",
        }
    }

    /// Returns whether this operation must carry an existing external session.
    #[must_use]
    pub const fn requires_session(&self) -> bool {
        matches!(
            self,
            Self::SessionLoad
                | Self::SessionResume
                | Self::Prompt
                | Self::Cancel
                | Self::SessionClose
                | Self::Reconnect
        )
    }
}

/// Provider-neutral request projection above JSON-RPC.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpRequestEnvelope {
    /// ELIOT request identity.
    pub request_id: String,
    /// ELIOT operation identity.
    pub operation_id: String,
    /// Attempt bound by A-01.
    pub attempt_id: AttemptId,
    /// External session mapping.
    pub session_id: Option<String>,
    /// Operation kind.
    pub operation: AcpOperationKind,
    /// Provider-neutral parameters.
    pub payload: Value,
    /// Route identity captured at admission.
    pub route: RouteFingerprint,
}

impl AcpRequestEnvelope {
    /// Validates request identities and payload shape without trusting payload
    /// content as authority.
    pub fn validate(&self) -> Result<(), AcpAdapterError> {
        for (field, value) in [
            ("request_id", &self.request_id),
            ("operation_id", &self.operation_id),
        ] {
            if value.trim().is_empty() {
                return Err(AcpAdapterError::InvalidInput(field));
            }
        }
        self.route
            .validate()
            .map_err(AcpAdapterError::ContractValidation)?;
        if self.operation.requires_session()
            && self
                .session_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(AcpAdapterError::InvalidInput("session_id"));
        }
        Ok(())
    }

    /// Validates the request and applies a caller-owned payload bound.
    pub fn validate_bounded(&self, max_payload_bytes: usize) -> Result<(), AcpAdapterError> {
        self.validate()?;
        let payload_bytes = serde_json::to_vec(&self.payload)
            .map_err(|_| AcpAdapterError::InvalidInput("payload"))?;
        if payload_bytes.len() > max_payload_bytes {
            return Err(AcpAdapterError::InvalidInput("payload exceeds bound"));
        }
        Ok(())
    }
}

/// Normalized ACP event.  Raw provider details remain an observation payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpEvent {
    /// ELIOT event identity.
    pub event_id: EventId,
    /// Attempt identity.
    pub attempt_id: AttemptId,
    /// External session identity.
    pub session_id: String,
    /// Monotonic sequence supplied by the adapter.
    pub sequence: u64,
    /// Resume cursor.
    pub cursor: EventCursor,
    /// Normalized event kind.
    pub kind: HostEventKind,
    /// Route fingerprint.
    pub route: RouteFingerprint,
    /// Safe normalized payload.
    pub payload: Value,
}

impl AcpEvent {
    /// Converts a normalized event to the A-01 host-event contract.
    pub fn into_host_event(
        self,
        raw_payload_digest: String,
        observed_at: String,
    ) -> Result<eliot_agent_api::HostEventEnvelope, AcpAdapterError> {
        if self.session_id.trim().is_empty() || self.sequence == 0 {
            return Err(AcpAdapterError::InvalidInput("event session/sequence"));
        }
        let event = eliot_agent_api::HostEventEnvelope {
            event_id: self.event_id,
            attempt_id: self.attempt_id,
            sequence: self.sequence,
            cursor: self.cursor,
            kind: self.kind,
            route: self.route,
            raw_payload_digest,
            normalized_payload: self.payload,
            parent_event_id: None,
            observed_at,
        };
        event
            .validate()
            .map_err(AcpAdapterError::ContractValidation)?;
        Ok(event)
    }
}

/// Normalized result projection.  A provider completion remains only an
/// adapter result until A-01/Governor verification accepts it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpResultEnvelope {
    /// ELIOT operation identity.
    pub operation_id: String,
    /// Attempt identity.
    pub attempt_id: AttemptId,
    /// External session identity.
    pub session_id: Option<String>,
    /// Provider-neutral result payload.
    pub payload: Value,
    /// Whether the response was terminal at the transport boundary.
    pub terminal: bool,
}

/// Outcome supplied by the caller that assembled an ACP result.  ACP payloads
/// are provider observations and do not, by themselves, establish completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcpResultOutcome {
    /// The provider returned a terminal response; verification is still owned
    /// by A-01/Governor.
    Completed,
    /// The operation was cancelled.
    Cancelled,
    /// The provider reported a failure.
    Failed { reason: String },
    /// The outcome could not be established.
    Unknown { reason: String },
}

impl AcpResultEnvelope {
    /// Projects ACP metadata onto the provider-neutral A-01 result boundary.
    ///
    /// The raw payload remains in this envelope.  This projection never turns
    /// it into evidence or an authorized effect, never claims an observed
    /// route, and never fabricates usage or a terminal timestamp.
    pub fn into_agent_result(
        self,
        route: RouteFingerprint,
        route_id: RouteFingerprintId,
        started_at: impl Into<String>,
        outcome: AcpResultOutcome,
    ) -> Result<AgentResult, AcpAdapterError> {
        let (disposition, unknown_reason) = match outcome {
            AcpResultOutcome::Completed => (ResultDisposition::DegradedNoProof, None),
            AcpResultOutcome::Cancelled => (ResultDisposition::Cancelled, None),
            AcpResultOutcome::Failed { reason } => {
                (ResultDisposition::FailedVerification, Some(reason))
            }
            AcpResultOutcome::Unknown { reason } => {
                (ResultDisposition::UnknownOutcome, Some(reason))
            }
        };
        let usage = UsageReceipt {
            input_tokens: None,
            output_tokens: None,
            cost_microunits: None,
            quota: QuotaKnowledge::Unknown,
        };
        let result = AgentResult {
            attempt_id: self.attempt_id,
            disposition,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: Vec::new(),
            effect_receipts: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: usage.clone(),
            actual_route: ActualRouteReceipt {
                requested: route,
                observed: None,
                route_id,
                usage,
                started_at: started_at.into(),
                terminal_at: None,
            },
            unknown_reason,
        };
        result
            .actual_route
            .validate()
            .map_err(AcpAdapterError::ContractValidation)?;
        if result.disposition == ResultDisposition::UnknownOutcome
            && result.unknown_reason.as_deref().is_none_or(str::is_empty)
        {
            return Err(AcpAdapterError::ContractValidation(
                eliot_agent_api::ContractError::MissingUnknownReason,
            ));
        }
        Ok(result)
    }
}

/// Short result alias.
pub type AcpResult = AcpResultEnvelope;

/// Durable cancel projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpCancelRequest {
    /// ELIOT operation identity to cancel.
    pub operation_id: String,
    /// Attempt identity.
    pub attempt_id: AttemptId,
    /// External session identity.
    pub session_id: String,
    /// A-01 cancellation reason.
    pub reason: eliot_agent_api::CancelReason,
    /// State fence from the caller-owned authority/attempt projection.
    pub state_fence: String,
}

/// Short cancel alias.
pub type AcpCancel = AcpCancelRequest;

/// Reconnect projection.  Reconnect never creates a new attempt implicitly.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpReconnectRequest {
    /// Attempt to which the external session remains bound.
    pub attempt_id: AttemptId,
    /// External session identity.
    pub session_id: String,
    /// Last observed cursor.
    pub last_cursor: Option<EventCursor>,
    /// New strictly monotonic reconnect epoch.
    pub reconnect_epoch: u64,
    /// Route must be identical to the existing mapping.
    pub route: RouteFingerprint,
}

/// Short reconnect alias.
pub type AcpReconnect = AcpReconnectRequest;

/// A source/authority admission input for the adapter.  The adapter consumes
/// Q-01's result and A-01's attempt/authority projection; it creates neither.
#[derive(Clone, Debug)]
pub struct AcpAdmission {
    /// A-01 attempt projection.
    pub attempt: AgentAttempt,
    /// Q-01 immutable source assurance.
    pub source_assurance: SourceAssurance,
    /// Q-01 caller-owned expectation.
    pub expectation: AdmissionExpectation,
}

/// Admission failures remain typed unavailable states where possible.
#[derive(Debug, Error)]
pub enum AcpAdmissionError {
    /// A-01 contract validation failed.
    #[error("A-01 attempt validation failed: {0}")]
    AgentContract(String),
    /// Q-01 contract validation failed before admission.
    #[error("Q-01 source assurance validation failed: {0}")]
    SourceContract(#[from] SourceAssuranceError),
    /// Q-01 returned a non-admitted typed outcome.
    #[error("Q-01 source assurance was not admitted: {0:?}")]
    SourceNotAdmitted(AdmissionOutcome),
}

impl AcpAdmission {
    /// Alias for [`Self::validate`] matching the Q-01 admission vocabulary.
    pub fn admit(self) -> Result<Self, AcpAdmissionError> {
        self.validate()
    }

    /// Validates and admits one source/attempt binding without granting new
    /// authority.  The authority is copied only from A-01's attempt.
    pub fn validate(self) -> Result<Self, AcpAdmissionError> {
        self.attempt
            .validate()
            .map_err(|error| AcpAdmissionError::AgentContract(error.to_string()))?;
        match self.source_assurance.admit(&self.expectation)? {
            AdmissionOutcome::Admitted { .. } => Ok(self),
            other => Err(AcpAdmissionError::SourceNotAdmitted(other)),
        }
    }

    /// Returns the A-01 authority envelope without allowing callers to mutate
    /// or replace it through this adapter.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityEnvelope {
        &self.attempt.authority
    }

    /// Checks the effect needed by an operation against the already admitted
    /// A-01 ceiling.
    pub fn permits(&self, operation: &AcpOperationKind) -> Result<(), AcpUnavailableReason> {
        let effect = match operation {
            AcpOperationKind::Probe | AcpOperationKind::Reconnect => EffectKind::Observe,
            AcpOperationKind::SessionNew
            | AcpOperationKind::SessionLoad
            | AcpOperationKind::SessionResume
            | AcpOperationKind::Prompt
            | AcpOperationKind::Cancel
            | AcpOperationKind::SessionClose => EffectKind::ProcessExecution,
        };
        if self.attempt.authority.effect_ceiling.permits(effect) {
            Ok(())
        } else {
            Err(AcpUnavailableReason::AuthorityCeiling)
        }
    }
}

impl AcpCapabilitySet {
    /// Checks the exact capability marker associated with an operation.
    pub fn permits_operation(
        &self,
        operation: &AcpOperationKind,
    ) -> Result<(), AcpUnavailableReason> {
        self.validate()?;
        if self.admits(operation.capability_name()) {
            Ok(())
        } else {
            Err(AcpUnavailableReason::CapabilityNotNegotiated(
                operation.capability_name().to_owned(),
            ))
        }
    }
}

/// Adapter-level errors which preserve typed unavailable/unknown states.
#[derive(Debug, Error)]
pub enum AcpAdapterError {
    /// Framing or JSON-RPC protocol error.
    #[error(transparent)]
    Protocol(#[from] AcpProtocolError),
    /// A-01 contract rejected an adapter projection.
    #[error("A-01 contract validation failed: {0}")]
    ContractValidation(eliot_agent_api::ContractError),
    /// Input was blank or structurally invalid before transport.
    #[error("invalid ACP input: {0}")]
    InvalidInput(&'static str),
    /// The caller-owned transport closed or rejected an operation.
    #[error("ACP transport is unavailable")]
    TransportUnavailable,
    /// Session mapping was stale or ambiguous.
    #[error(transparent)]
    Session(#[from] AcpSessionError),
    /// The operation is unavailable without a transport-side effect.
    #[error("ACP operation unavailable: {0}")]
    Unavailable(#[from] AcpUnavailableReason),
    /// Process contract rejected the delegated physical lifecycle operation.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

/// Caller-owned ACP byte transport.  Implementations may use stdio, a test
/// queue, or another explicitly admitted mechanism; this crate never opens it.
#[allow(async_fn_in_trait)]
pub trait AcpTransport {
    /// Transport-specific error; its text is intentionally redacted by the
    /// adapter boundary.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Writes one encoded frame.
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<(), Self::Error>;

    /// Reads one arbitrary byte chunk, or `None` on transport close.
    async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Framing/JSON-RPC facade over a caller-owned ACP transport.
#[derive(Debug)]
pub struct AcpWire<T> {
    transport: T,
    codec: AcpFrameCodec,
    pending: VecDeque<Vec<u8>>,
}

impl<T> AcpWire<T> {
    /// Creates a wire facade with the default parser bounds.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            codec: AcpFrameCodec::default(),
            pending: VecDeque::new(),
        }
    }

    /// Creates a wire facade with explicit parser bounds.
    pub fn with_limits(transport: T, max_header_bytes: usize, max_frame_bytes: usize) -> Self {
        Self {
            transport,
            codec: AcpFrameCodec::new(max_header_bytes, max_frame_bytes),
            pending: VecDeque::new(),
        }
    }

    /// Returns the caller-owned transport.
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: AcpTransport> AcpWire<T> {
    /// Sends one validated JSON-RPC message through the caller-owned channel.
    pub async fn send(&mut self, message: &AcpJsonRpcMessage) -> Result<(), AcpAdapterError> {
        let payload = message.to_json_vec()?;
        let frame = AcpFrameCodec::encode_bounded(&payload, self.codec.max_frame_bytes())?;
        self.transport
            .write_frame(frame)
            .await
            .map_err(|_| AcpAdapterError::TransportUnavailable)
    }

    /// Receives one complete JSON-RPC message.  A close before completion is
    /// an explicit unknown outcome because a response may have been accepted.
    pub async fn receive(&mut self) -> Result<AcpOutcome<AcpJsonRpcMessage>, AcpAdapterError> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Ok(AcpOutcome::Completed(AcpJsonRpcMessage::from_frame(
                    &frame,
                )?));
            }
            let Some(chunk) = self
                .transport
                .read_chunk()
                .await
                .map_err(|_| AcpAdapterError::TransportUnavailable)?
            else {
                return Ok(AcpOutcome::Unknown(AcpUnknownOutcome {
                    operation_id: "wire-receive".into(),
                    reason: "transport closed before a complete response".into(),
                    session_id: None,
                }));
            };
            let frames = self.codec.feed(&chunk)?;
            self.pending.extend(frames);
        }
    }
}

/// The only process-facing adapter boundary in A-05.  It delegates every
/// physical lifecycle operation to P-03 and never calls a process API itself.
#[derive(Clone, Debug)]
pub struct AcpProcessBinding<E> {
    executor: E,
}

impl<E> AcpProcessBinding<E> {
    /// Wraps an existing P-03 executor implementation.
    pub const fn new(executor: E) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor> AcpProcessBinding<E> {
    /// Delegates process start to P-03.
    pub async fn start(
        &self,
        request: ProcessRequest,
        sink: std::sync::Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        self.executor.start(request, sink).await
    }

    /// Delegates cancellation to P-03.
    pub async fn cancel(
        &self,
        operation_id: eliot_process::OperationId,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        self.executor.cancel(operation_id).await
    }

    /// Delegates inspection to P-03.
    pub async fn inspect(
        &self,
        operation_id: eliot_process::OperationId,
    ) -> Result<eliot_process::ProcessExecutionView, ProcessExecutionError> {
        self.executor.inspect(operation_id).await
    }

    /// Delegates unknown-outcome reconciliation to P-03.
    pub async fn reconcile(
        &self,
        operation_id: eliot_process::OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        self.executor.reconcile(operation_id).await
    }
}

/// Returns a deterministic digest for route/adapter evidence without exposing
/// provider-native state as canonical ELIOT state.
pub fn adapter_fingerprint(
    route: &RouteFingerprint,
    adapter_revision: &str,
) -> Result<String, AcpAdapterError> {
    if adapter_revision.trim().is_empty() {
        return Err(AcpAdapterError::InvalidInput("adapter_revision"));
    }
    route
        .validate()
        .map_err(AcpAdapterError::ContractValidation)?;
    let mut material = route
        .canonical_json()
        .map_err(|_| AcpAdapterError::InvalidInput("route"))?;
    material.push('|');
    material.push_str(adapter_revision);
    Ok(blake3::hash(material.as_bytes()).to_hex().to_string())
}

/// Returns the generated public schema for deterministic fixture publication.
pub fn acp_schema() -> schemars::Schema {
    schemars::schema_for!(AcpRequestEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct FakeExecutor;

    impl eliot_process::ProcessExecutor for FakeExecutor {
        async fn start(
            &self,
            _request: eliot_process::ProcessRequest,
            _sink: std::sync::Arc<dyn eliot_process::ProcessEvidenceSink>,
        ) -> Result<eliot_process::ProcessStartReceipt, eliot_process::ProcessExecutionError>
        {
            Err(eliot_process::ProcessExecutionError::Unavailable(
                "fake executor".into(),
            ))
        }

        async fn inspect(
            &self,
            _operation_id: eliot_process::OperationId,
        ) -> Result<eliot_process::ProcessExecutionView, eliot_process::ProcessExecutionError>
        {
            Err(eliot_process::ProcessExecutionError::Unavailable(
                "fake executor".into(),
            ))
        }

        async fn cancel(
            &self,
            _operation_id: eliot_process::OperationId,
        ) -> Result<eliot_process::CancellationReceipt, eliot_process::ProcessExecutionError>
        {
            Err(eliot_process::ProcessExecutionError::Unavailable(
                "fake executor".into(),
            ))
        }

        async fn reconcile(
            &self,
            _operation_id: eliot_process::OperationId,
        ) -> Result<eliot_process::ProcessEvidence, eliot_process::ProcessExecutionError> {
            Err(eliot_process::ProcessExecutionError::UnknownOutcome)
        }
    }

    fn route() -> RouteFingerprint {
        RouteFingerprint {
            host_family: "acp-agent".into(),
            adapter: "eliot-acp-test".into(),
            protocol_transport: "acp-stdio".into(),
            runtime_hash: "runtime".into(),
            adapter_hash: "adapter".into(),
            provider: "provider".into(),
            model: "model".into(),
            auth_billing: "subscription".into(),
            serializer_hash: "serializer".into(),
            tool_semantics_hash: "tools".into(),
            reasoning_mode: "default".into(),
            continuation_behavior: "native".into(),
            feature_flags_hash: "features".into(),
        }
    }

    #[test]
    fn frame_codec_handles_partial_and_multiple_frames() -> Result<(), Box<dyn std::error::Error>> {
        let first = AcpFrameCodec::encode(br#"{"jsonrpc":"2.0","method":"ping"}"#)?;
        let second = AcpFrameCodec::encode(br#"{"jsonrpc":"2.0","method":"pong"}"#)?;
        let mut bytes = first;
        bytes.extend(second);
        let split = bytes.len() / 2;
        let mut codec = AcpFrameCodec::default();
        let mut frames = codec.feed(&bytes[..split])?;
        assert!(frames.len() <= 1);
        frames.extend(codec.feed(&bytes[split..])?);
        assert_eq!(frames.len(), 2);
        codec.finish()?;
        Ok(())
    }

    #[test]
    fn malformed_and_oversized_frames_fail() -> Result<(), Box<dyn std::error::Error>> {
        let mut codec = AcpFrameCodec::new(32, 8);
        assert!(matches!(
            codec.feed(b"Content-Length: 9\r\n\r\n123456789"),
            Err(AcpProtocolError::LimitExceeded { field: "frame", .. })
        ));
        let mut codec = AcpFrameCodec::default();
        assert!(matches!(
            codec.feed(b"Content-Length: x\r\n\r\n"),
            Err(AcpProtocolError::InvalidHeader(_))
        ));
        let mut codec = AcpFrameCodec::default();
        codec.feed(b"Content-Length: 4\r\n\r\n{}")?;
        assert!(matches!(
            codec.finish(),
            Err(AcpProtocolError::IncompleteFrame)
        ));
        Ok(())
    }

    #[test]
    fn json_rpc_rejects_ambiguous_response_and_wrong_version() {
        assert!(matches!(
            AcpJsonRpcMessage::from_json_slice(
                br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#
            ),
            Err(AcpProtocolError::InvalidEnvelope(_))
        ));
        assert!(matches!(
            AcpJsonRpcMessage::from_json_slice(br#"{"jsonrpc":"1.0","method":"x"}"#),
            Err(AcpProtocolError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn golden_json_rpc_serialization_is_stable() -> Result<(), Box<dyn std::error::Error>> {
        let message = AcpJsonRpcMessage::Request(AcpJsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: AcpRequestId::Number(7),
            method: "session/prompt".into(),
            params: serde_json::json!({"sessionId":"s1","prompt":"hello"}),
        });
        let json = String::from_utf8(message.to_json_vec()?)?;
        assert_eq!(
            json,
            r#"{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"prompt":"hello","sessionId":"s1"}}"#
        );
        let decoded: AcpJsonRpcMessage = serde_json::from_str(&json)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn operation_requires_session_and_capability_after_cancel()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(AcpOperationKind::Cancel.requires_session());
        assert_eq!(AcpOperationKind::Cancel.capability_name(), "session/cancel");
        let route = route();
        let request = AcpRequestEnvelope {
            request_id: "request".into(),
            operation_id: "operation".into(),
            attempt_id: AttemptId::new("attempt")?,
            session_id: None,
            operation: AcpOperationKind::Cancel,
            payload: Value::Null,
            route,
        };
        assert!(matches!(
            request.validate(),
            Err(AcpAdapterError::InvalidInput("session_id"))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn fake_executor_is_the_only_physical_process_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = AcpProcessBinding::new(FakeExecutor);
        let operation = eliot_process::OperationId::new("operation")?;
        assert!(matches!(
            binding.cancel(operation.clone()).await,
            Err(eliot_process::ProcessExecutionError::Unavailable(_))
        ));
        assert!(matches!(
            binding.reconcile(operation).await,
            Err(eliot_process::ProcessExecutionError::UnknownOutcome)
        ));
        Ok(())
    }

    #[test]
    fn advertisement_alone_does_not_admit_capability() {
        let capabilities = AcpCapabilitySet::advertised(["session/load"]);
        assert!(!capabilities.admits("session/load"));
        assert!(
            capabilities
                .negotiate(&BTreeSet::from(["session/load".to_string()]))
                .is_err()
        );
    }

    #[test]
    fn forged_admitted_capability_without_probe_is_rejected() {
        let capabilities = AcpCapabilitySet {
            advertised: BTreeSet::from(["session/load".to_owned()]),
            probed: BTreeSet::new(),
            admitted: BTreeSet::from(["session/load".to_owned()]),
        };
        assert!(capabilities.validate().is_err());
        assert!(
            capabilities
                .permits_operation(&AcpOperationKind::SessionLoad)
                .is_err()
        );
    }

    #[test]
    fn probe_requires_advertisement_and_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let mut capabilities = AcpCapabilitySet::advertised(["session/load"]);
        assert!(capabilities.probe("session/resume").is_err());
        capabilities.probe("session/load")?;
        assert!(capabilities.admits("session/load"));
        Ok(())
    }

    #[test]
    fn v2_is_not_silently_admitted() {
        let response = AcpHandshakeResponse {
            protocol_version: 2,
            server_name: "server".into(),
            server_version: "2".into(),
            capabilities: AcpCapabilitySet::default(),
        };
        assert!(matches!(
            AcpNegotiation::accept(response, &BTreeSet::new()),
            Err(AcpProtocolError::UnsupportedVersion { observed: 2 })
        ));
    }

    #[test]
    fn session_registry_rejects_stale_and_duplicate_mappings()
    -> Result<(), Box<dyn std::error::Error>> {
        let attempt_id = AttemptId::new("attempt")?;
        let task_id = TaskId::new("task")?;
        let binding = AcpSessionBinding {
            attempt_id: attempt_id.clone(),
            task_id: task_id.clone(),
            external_session_id: "session".into(),
            route: route(),
            adapter_revision: "rev".into(),
            reconnect_epoch: 1,
        };
        let mut registry = AcpSessionRegistry::new(2)?;
        registry.bind(binding.clone())?;
        assert_eq!(
            registry.bind(binding.clone()),
            Err(AcpSessionError::DuplicateSession)
        );
        assert_eq!(
            registry.reconnect(AcpSessionBinding {
                reconnect_epoch: 1,
                ..binding.clone()
            }),
            Err(AcpSessionError::StaleReconnect)
        );
        registry.reconnect(AcpSessionBinding {
            reconnect_epoch: 2,
            ..binding
        })?;
        Ok(())
    }

    #[test]
    fn event_conversion_preserves_attempt_and_route() -> Result<(), Box<dyn std::error::Error>> {
        let event = AcpEvent {
            event_id: EventId::new("event")?,
            attempt_id: AttemptId::new("attempt")?,
            session_id: "session".into(),
            sequence: 1,
            cursor: EventCursor::new("cursor")?,
            kind: HostEventKind::AssistantDelta,
            route: route(),
            payload: serde_json::json!({"text":"ok"}),
        };
        let host = event.into_host_event("digest".into(), "now".into())?;
        assert_eq!(host.sequence, 1);
        assert_eq!(host.attempt_id.as_str(), "attempt");
        Ok(())
    }

    // `AttemptId::new` reports `eliot_agent_contracts::ContractError` while the
    // sibling `RouteFingerprintId::new` reports `eliot_agent_api::ContractError`,
    // so the two cannot share one `?`. The conversion is written out here rather
    // than added as a cross-crate `From`, which would silently merge two
    // unrelated error taxonomies across a public boundary.
    fn result_envelope() -> Result<AcpResultEnvelope, AcpAdapterError> {
        Ok(AcpResultEnvelope {
            operation_id: "operation".into(),
            attempt_id: AttemptId::new("attempt").map_err(|_| {
                AcpAdapterError::ContractValidation(eliot_agent_api::ContractError::EmptyIdentity(
                    "attempt_id",
                ))
            })?,
            session_id: Some("session".into()),
            payload: serde_json::json!({"provider":"candidate"}),
            terminal: true,
        })
    }

    fn project_result(
        outcome: AcpResultOutcome,
    ) -> Result<eliot_agent_api::AgentResult, AcpAdapterError> {
        result_envelope()?.into_agent_result(
            route(),
            RouteFingerprintId::new("route").map_err(AcpAdapterError::ContractValidation)?,
            "started",
            outcome,
        )
    }

    #[test]
    fn result_projection_is_candidate_only_without_usage_or_route_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let result = project_result(AcpResultOutcome::Completed)?;
        assert_eq!(result.disposition, ResultDisposition::DegradedNoProof);
        assert!(result.evidence_refs.is_empty());
        assert!(result.proposed_effects.is_empty());
        assert!(result.effect_receipts.is_empty());
        assert!(result.actual_route.observed.is_none());
        assert_eq!(result.actual_route.usage.quota, QuotaKnowledge::Unknown);
        assert!(result.actual_route.usage.input_tokens.is_none());
        assert!(result.actual_route.usage.output_tokens.is_none());
        assert!(result.actual_route.usage.cost_microunits.is_none());
        assert!(result.actual_route.terminal_at.is_none());
        Ok(())
    }

    #[test]
    fn result_projection_preserves_cancelled_disposition() -> Result<(), Box<dyn std::error::Error>>
    {
        let result = project_result(AcpResultOutcome::Cancelled)?;
        assert_eq!(result.disposition, ResultDisposition::Cancelled);
        assert!(result.unknown_reason.is_none());
        Ok(())
    }

    #[test]
    fn result_projection_preserves_failed_and_unknown_reasons()
    -> Result<(), Box<dyn std::error::Error>> {
        let failed = project_result(AcpResultOutcome::Failed {
            reason: "provider rejected request".into(),
        })?;
        assert_eq!(failed.disposition, ResultDisposition::FailedVerification);
        assert_eq!(
            failed.unknown_reason.as_deref(),
            Some("provider rejected request")
        );

        let unknown = project_result(AcpResultOutcome::Unknown {
            reason: "transport closed".into(),
        })?;
        assert_eq!(unknown.disposition, ResultDisposition::UnknownOutcome);
        assert_eq!(unknown.unknown_reason.as_deref(), Some("transport closed"));
        Ok(())
    }
}
