//! P-02 bounded EBP/1 transport mechanics.
//!
//! Semantic frames remain owned by `eliot-protocol`.  This crate owns only the
//! transport boundary: negotiation, bounded admission, session fencing and
//! transport-level reconciliation.  It never reports durable application
//! commit or sink acceptance.

use std::future::Future;
use std::time::Duration;

use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, JsonCodec, MessageType, ProtocolError,
    ProtocolPayload, ProtocolRange, ProtocolVersion, ServerHello, negotiate,
};
use eliot_runtime_contracts::ModuleGeneration;
use thiserror::Error;

/// A provider-neutral peer result. A PID or pipe name is not an identity proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerIdentity {
    /// Identity established by a provider after its SID/ACL/impersonation proof.
    Authenticated {
        process_id: u32,
        user_identity: String,
        session_identity: String,
        proof: IdentityProof,
    },
    /// The transport is usable, but this composition does not prove peer identity.
    Unavailable { reason: PeerIdentityUnavailable },
}

/// Handle-bound process identity returned by the platform adapter.
///
/// A PID is only a lookup key.  The adapter must obtain the start time and
/// image path from the same live process handle before this value is admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessBinding {
    process_id: u32,
    start_time_100ns: u64,
    image_path: String,
}

impl ProcessBinding {
    /// Creates the value observed by a trusted platform adapter.
    ///
    /// The constructor is intentionally boring: authority comes from the
    /// adapter's handle-bound observation, never from a caller-provided
    /// boolean.
    fn from_observation(
        process_id: u32,
        start_time_100ns: u64,
        image_path: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let image_path = image_path.into();
        if process_id == 0 || start_time_100ns == 0 || image_path.trim().is_empty() {
            return Err(TransportError::UnauthenticatedPeer);
        }
        if image_path.chars().any(char::is_control) {
            return Err(TransportError::UnauthenticatedPeer);
        }
        Ok(Self {
            process_id,
            start_time_100ns,
            image_path,
        })
    }

    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub const fn start_time_100ns(&self) -> u64 {
        self.start_time_100ns
    }

    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.image_path
    }
}

/// Platform-owned identity proof.  The fields are private so a transport
/// caller cannot turn a PID, SID or a pair of booleans into authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityProof {
    process: ProcessBinding,
    sid: String,
    session: String,
}

impl PeerIdentity {
    #[cfg(windows)]
    fn from_platform_evidence(
        evidence: &eliot_platform_windows::NamedPipePeerEvidence,
    ) -> Result<Self, TransportError> {
        let observed = evidence.process();
        let process = ProcessBinding::from_observation(
            observed.process_id,
            observed.start_time_100ns,
            observed.image_path.clone(),
        )?;
        let sid = evidence.sid().to_owned();
        let session = evidence.session_id().to_string();
        let identity = Self::Authenticated {
            process_id: process.process_id(),
            user_identity: sid.clone(),
            session_identity: session.clone(),
            proof: IdentityProof {
                process,
                sid,
                session,
            },
        };
        identity.validate().map(|()| identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIdentityUnavailable {
    /// The platform adapter has not supplied SID/ACL/impersonation evidence.
    ProviderProofNotComposed,
}

impl PeerIdentity {
    /// Validates the non-secret identity binding.
    pub fn validate(&self) -> Result<(), TransportError> {
        match self {
            Self::Authenticated {
                process_id,
                user_identity,
                session_identity,
                proof,
            } if *process_id != 0
                && !user_identity.trim().is_empty()
                && !session_identity.trim().is_empty()
                && !user_identity.chars().any(char::is_control)
                && !session_identity.chars().any(char::is_control) =>
            {
                if proof.process.process_id() == *process_id
                    && proof.sid == *user_identity
                    && proof.session == *session_identity
                {
                    Ok(())
                } else {
                    Err(TransportError::UnauthenticatedPeer)
                }
            }
            Self::Unavailable { .. } => Err(TransportError::PeerIdentityUnavailable),
            Self::Authenticated { .. } => Err(TransportError::UnauthenticatedPeer),
        }
    }

    /// Returns the provider-observed, handle-bound process identity when peer
    /// authentication succeeded.
    ///
    /// This is read-only evidence: callers still cannot construct an
    /// [`IdentityProof`] or turn a PID/path supplied on the wire into an
    /// authenticated peer.
    #[must_use]
    pub fn process_binding(&self) -> Option<&ProcessBinding> {
        if self.validate().is_err() {
            return None;
        }
        match self {
            Self::Authenticated { proof, .. } => Some(&proof.process),
            Self::Unavailable { .. } => None,
        }
    }
}

/// Transport limits.  A queue item is admitted only when both item and byte
/// limits fit; the reserved control lane remains available during saturation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub max_frame_bytes: usize,
    pub queue_capacity: usize,
    pub queue_bytes: usize,
    pub control_reserve: usize,
    pub operation_timeout: Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: eliot_protocol::MAX_FRAME_BYTES,
            queue_capacity: 128,
            queue_bytes: 8 * 1024 * 1024,
            control_reserve: 4,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl TransportLimits {
    fn validate(self) -> Result<Self, TransportError> {
        if self.max_frame_bytes == 0
            || self.max_frame_bytes > eliot_protocol::MAX_FRAME_BYTES
            || self.queue_capacity == 0
            || self.queue_bytes < self.max_frame_bytes
            || self.control_reserve >= self.queue_capacity
            || self.operation_timeout.is_zero()
        {
            return Err(TransportError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Transport failures are deliberately distinct from application outcomes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("invalid transport limits")]
    InvalidLimits,
    #[error("peer identity could not be authenticated")]
    UnauthenticatedPeer,
    #[error("peer identity proof is unavailable in this composition")]
    PeerIdentityUnavailable,
    #[error("protocol negotiation failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("session is fenced or closed")]
    SessionFenced,
    #[error("transport queue is full")]
    Backpressure,
    #[error("transport operation timed out")]
    Timeout,
    #[error("transport operation was cancelled")]
    Cancelled,
    #[error("invalid named-pipe name")]
    InvalidPipeName,
    #[error("transport disconnected; application outcome is unknown")]
    UnknownOutcome,
    #[error("transport I/O failed: {0}")]
    Io(String),
    #[error("required lower-layer adapter is unavailable: {dependency} ({reason})")]
    PlanGap {
        dependency: &'static str,
        reason: &'static str,
    },
    #[error("unknown request or cancellation identity")]
    UnknownRequest,
    #[error("request or cancellation identity conflicts with a prior operation")]
    IdentityConflict,
    #[error("bounded transport registry is full")]
    RegistryFull,
}

#[cfg(windows)]
fn map_platform_error(error: eliot_platform_windows::WindowsAdapterError) -> TransportError {
    use eliot_platform_windows::WindowsAdapterError;
    match error {
        WindowsAdapterError::IdentityMismatch | WindowsAdapterError::AclMismatch => {
            TransportError::UnauthenticatedPeer
        }
        WindowsAdapterError::Unavailable => TransportError::PlanGap {
            dependency: "eliot-platform-windows",
            reason: "named-pipe peer evidence is unavailable",
        },
        WindowsAdapterError::Timeout => TransportError::Timeout,
        WindowsAdapterError::InvalidInput => TransportError::InvalidPipeName,
        WindowsAdapterError::NotFound
        | WindowsAdapterError::AlreadyExists
        | WindowsAdapterError::PermissionDenied
        | WindowsAdapterError::Failed => TransportError::Io(error.to_string()),
    }
}

#[cfg(windows)]
fn require_authenticated_peer(peer: &PeerIdentity) -> Result<(), TransportError> {
    match peer {
        PeerIdentity::Authenticated { .. } => Ok(()),
        PeerIdentity::Unavailable { .. } => Err(TransportError::PlanGap {
            dependency: "eliot-platform-windows",
            reason: "handle-bound SID/ACL/impersonation/session proof is not composed",
        }),
    }
}

/// Outcome of a transport attempt. `Delivered` is not a commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// Bytes were written to the transport; application processing is unknown.
    Delivered,
    /// The attempt crossed an uncertainty boundary and requires reconciliation.
    UnknownOutcome,
}

/// Typed uncertainty at the transport/application commit boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationOutcome {
    NotStarted,
    Partial,
    PostCommitUnknown,
}

/// No ORS or migration owner is assumed by this transport candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationDependency {
    PlanGap,
}

#[must_use]
pub const fn classify_write(after_write_started: bool) -> OperationOutcome {
    if after_write_started {
        OperationOutcome::PostCommitUnknown
    } else {
        OperationOutcome::NotStarted
    }
}

#[must_use]
pub const fn classify_write_progress(
    write_started: bool,
    frame_complete: bool,
) -> OperationOutcome {
    if !write_started {
        OperationOutcome::NotStarted
    } else if frame_complete {
        OperationOutcome::PostCommitUnknown
    } else {
        OperationOutcome::Partial
    }
}

/// Explicit transport session lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Negotiating,
    Open,
    Reconnecting,
    Fenced,
    Closed,
}

/// Server-owned inputs for the complete EBP/1 handshake.  These values must
/// come from the Kernel/Generation Registry; a client assertion is never
/// copied into authority state.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerHandshakePolicy {
    pub protocol_range: ProtocolRange,
    pub module_id: String,
    /// Exact immutable generation/fence/artifact selected by the server owner.
    pub module_generation: ModuleGeneration,
    pub launch_nonce: String,
    pub allowed_capabilities: Vec<String>,
    pub allowed_privacy_classes: Vec<String>,
    pub allowed_effects: Vec<String>,
    pub session_principal_binding: String,
    pub control_channel: String,
    pub heartbeat_ms: u32,
    pub config_snapshot: serde_json::Value,
    pub max_frame: u32,
}

impl ServerHandshakePolicy {
    fn validate(&self) -> Result<(), TransportError> {
        self.protocol_range.validate()?;
        if self.module_id.trim().is_empty()
            || self.launch_nonce.trim().is_empty()
            || self.session_principal_binding.trim().is_empty()
            || self.control_channel.trim().is_empty()
            || self.heartbeat_ms == 0
            || self.max_frame == 0
            || usize::try_from(self.max_frame).unwrap_or(usize::MAX)
                > eliot_protocol::MAX_FRAME_BYTES
        {
            return Err(TransportError::SessionFenced);
        }
        self.module_generation
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        validate_unique_texts(&self.allowed_capabilities)?;
        validate_unique_texts(&self.allowed_privacy_classes)?;
        validate_unique_texts(&self.allowed_effects)?;
        Ok(())
    }
}

/// Successful complete handshake, including the exact capability intersection.
#[derive(Clone, Debug, PartialEq)]
pub struct HandshakeResult {
    pub session: Session,
    pub server_hello: ServerHello,
    pub capabilities: Vec<String>,
    pub privacy_classes: Vec<String>,
    pub effects: Vec<String>,
}

/// Encodes the typed `ClientHello` on the authenticated EBP control lane.
///
/// The authentication preface is deliberately separate from this frame. A
/// caller must first pass the platform identity boundary, then send exactly
/// one Control/Start frame containing the validated `ClientHello` JSON.
pub fn client_hello_frame(
    connection_id: impl Into<String>,
    client: &ClientHello,
) -> Result<Frame, TransportError> {
    client.validate()?;
    handshake_frame(
        connection_id,
        FrameKind::Control,
        MessageType::Start,
        serde_json::to_value(client).map_err(|error| ProtocolError::Json(error.to_string()))?,
    )
}

/// Decodes and validates a typed `ClientHello` from an authenticated EBP frame.
pub fn decode_client_hello_frame(
    frame: &Frame,
    expected_connection_id: &str,
) -> Result<ClientHello, TransportError> {
    let payload = validate_handshake_frame(
        frame,
        Some(expected_connection_id),
        FrameKind::Control,
        MessageType::Start,
    )?;
    let client: ClientHello = serde_json::from_value(payload.clone())
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    client.validate()?;
    Ok(client)
}

/// Decodes a `ClientHello` before its client-selected connection identity has
/// been admitted by the server.
///
/// The authenticated peer and server handshake policy remain independent
/// authorities. The caller must bind the returned hello and this frame's
/// non-blank connection identity together before admitting the session.
pub fn decode_client_hello_frame_unbound(frame: &Frame) -> Result<ClientHello, TransportError> {
    let payload = validate_handshake_frame(frame, None, FrameKind::Control, MessageType::Start)?;
    let client: ClientHello = serde_json::from_value(payload.clone())
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    client.validate()?;
    Ok(client)
}

/// Encodes the server-authoritative typed `ServerHello` on the control lane.
pub fn server_hello_frame(
    connection_id: impl Into<String>,
    server: &ServerHello,
) -> Result<Frame, TransportError> {
    server.validate()?;
    handshake_frame(
        connection_id,
        FrameKind::Control,
        MessageType::Ready,
        serde_json::to_value(server).map_err(|error| ProtocolError::Json(error.to_string()))?,
    )
}

/// Decodes and validates a typed `ServerHello` from an authenticated EBP frame.
pub fn decode_server_hello_frame(
    frame: &Frame,
    expected_connection_id: &str,
) -> Result<ServerHello, TransportError> {
    let payload = validate_handshake_frame(
        frame,
        Some(expected_connection_id),
        FrameKind::Control,
        MessageType::Ready,
    )?;
    let server: ServerHello = serde_json::from_value(payload.clone())
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    server.validate()?;
    Ok(server)
}

/// Encodes a typed handshake rejection on the authenticated control lane.
pub fn handshake_rejection_frame(
    connection_id: impl Into<String>,
    reason: impl Into<String>,
) -> Result<Frame, TransportError> {
    let reason = reason.into();
    if reason.trim().is_empty() || reason.chars().any(char::is_control) {
        return Err(TransportError::Protocol(ProtocolError::InvalidField {
            field: "rejection_reason",
            reason: "must be non-blank and free of control characters",
        }));
    }
    handshake_frame(
        connection_id,
        FrameKind::Control,
        MessageType::Fatal,
        serde_json::json!({"rejection_reason": reason}),
    )
}

fn handshake_frame(
    connection_id: impl Into<String>,
    kind: FrameKind,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<Frame, TransportError> {
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: None,
        kind,
        message_type,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate()?;
    Ok(frame)
}

fn validate_handshake_frame<'a>(
    frame: &'a Frame,
    expected_connection_id: Option<&str>,
    expected_kind: FrameKind,
    expected_message_type: MessageType,
) -> Result<&'a serde_json::Value, TransportError> {
    frame.validate()?;
    if frame.connection_id.trim().is_empty()
        || expected_connection_id
            .is_some_and(|expected| expected.trim().is_empty() || frame.connection_id != expected)
        || frame.kind != expected_kind
        || frame.message_type != expected_message_type
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err(TransportError::SessionFenced);
    }
    match &frame.payload {
        ProtocolPayload::Json(value) => Ok(value),
        _ => Err(TransportError::Protocol(ProtocolError::InvalidField {
            field: "payload",
            reason: "handshake frames require a JSON payload",
        })),
    }
}

fn validate_unique_texts(values: &[String]) -> Result<(), TransportError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || value.chars().any(char::is_control) || !seen.insert(value) {
            return Err(TransportError::SessionFenced);
        }
    }
    Ok(())
}

/// Negotiated, authenticated session binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub connection_id: String,
    pub protocol_version: ProtocolVersion,
    pub peer: PeerIdentity,
    /// Authority epoch captured by the handshake; reconnects must bind anew.
    pub authority_epoch: u64,
    /// Complete immutable generation, artifact and Kernel fence captured by the handshake.
    pub module_generation: ModuleGeneration,
    pub launch_nonce: String,
    pub capabilities: Vec<String>,
    pub privacy_classes: Vec<String>,
    pub effects: Vec<String>,
    /// Monotonic transport session fence, never reused after disconnect.
    pub session_epoch: u64,
    pub state: SessionState,
}

impl Session {
    /// Performs the protocol and peer checks needed before application frames.
    pub fn establish(
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &ClientHello,
        server_range: ProtocolRange,
    ) -> Result<Self, TransportError> {
        let connection_id = connection_id.into();
        if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()?;
        let protocol_version = negotiate(client, server_range)?;
        Ok(Self {
            connection_id,
            protocol_version,
            peer,
            authority_epoch: client.authority_epoch.value(),
            module_generation: client.module_generation.clone(),
            launch_nonce: client.launch_nonce.clone(),
            capabilities: client.capabilities.clone(),
            privacy_classes: client.privacy_classes.clone(),
            effects: Vec::new(),
            session_epoch: 1,
            state: SessionState::Open,
        })
    }

    /// Performs the server-authoritative handshake and capability intersection.
    pub fn establish_with_server(
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &ClientHello,
        server: &ServerHandshakePolicy,
    ) -> Result<HandshakeResult, TransportError> {
        server.validate()?;
        client.validate()?;
        peer.validate()?;
        if client.module_bridge_identity != server.module_id
            || client.module_generation.module_id.as_str() != server.module_id
            || client.module_generation != server.module_generation
            || client.artifact_hash != server.module_generation.artifact_id
            || client.authority_epoch != server.module_generation.state_fence.authority_epoch
            || client.launch_nonce != server.launch_nonce
        {
            return Err(TransportError::SessionFenced);
        }
        let protocol_version = negotiate(client, server.protocol_range)?;
        let capabilities = intersection(&client.capabilities, &server.allowed_capabilities);
        let privacy_classes =
            intersection(&client.privacy_classes, &server.allowed_privacy_classes);
        let effects = server.allowed_effects.clone();
        let session = Self {
            connection_id: connection_id.into(),
            protocol_version,
            peer,
            authority_epoch: server.module_generation.state_fence.authority_epoch.value(),
            module_generation: server.module_generation.clone(),
            launch_nonce: server.launch_nonce.clone(),
            capabilities: capabilities.clone(),
            privacy_classes: privacy_classes.clone(),
            effects: effects.clone(),
            session_epoch: 1,
            state: SessionState::Open,
        };
        let server_hello = eliot_protocol::ServerHello {
            selected_protocol: protocol_version,
            session_principal_binding: server.session_principal_binding.clone(),
            allowed_capabilities: capabilities.clone(),
            allowed_effects: effects.clone(),
            config_snapshot: server.config_snapshot.clone(),
            heartbeat_ms: server.heartbeat_ms,
            control_channel: server.control_channel.clone(),
            rejection_reason: None,
            authority_epoch: server.module_generation.state_fence.authority_epoch,
        };
        server_hello.validate()?;
        Ok(HandshakeResult {
            session,
            server_hello,
            capabilities,
            privacy_classes,
            effects,
        })
    }

    /// Fences this connection before it can be reused after a disconnect.
    pub fn fence(&mut self) {
        self.state = SessionState::Fenced;
        self.session_epoch = self.session_epoch.saturating_add(1);
    }

    /// Marks a bounded reconnect attempt; it does not revive the old session.
    pub fn begin_reconnect(&mut self) -> Result<(), TransportError> {
        if matches!(self.state, SessionState::Open | SessionState::Reconnecting) {
            self.state = SessionState::Reconnecting;
            Ok(())
        } else {
            Err(TransportError::SessionFenced)
        }
    }

    /// Returns whether a frame belongs to this still-live session fence.
    pub fn accepts(&self, authority_epoch: u64, session_epoch: u64) -> bool {
        self.state == SessionState::Open
            && self.authority_epoch == authority_epoch
            && self.session_epoch == session_epoch
    }

    /// Checks all generation/fence bindings, not only the numeric epoch.
    pub fn accepts_bound(&self, generation: &ModuleGeneration, launch_nonce: &str) -> bool {
        self.state == SessionState::Open
            && self.authority_epoch == generation.state_fence.authority_epoch.value()
            && self.module_generation == *generation
            && self.launch_nonce == launch_nonce
    }
}

fn intersection(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .filter(|item| right.contains(item))
        .cloned()
        .collect()
}

/// Bounded admission ledger used by async and platform adapters.
#[derive(Clone, Debug)]
pub struct AdmissionQueue {
    limits: TransportLimits,
    identity: u64,
    normal_items: usize,
    control_items: usize,
    normal_bytes: usize,
    control_bytes: usize,
}

/// A one-shot reservation. Releasing anything other than this token is impossible.
#[derive(Debug)]
pub struct QueueReservation {
    owner: u64,
    encoded_bytes: usize,
    control: bool,
}

impl AdmissionQueue {
    /// Creates an empty queue ledger.
    pub fn new(limits: TransportLimits) -> Result<Self, TransportError> {
        Ok(Self {
            limits: limits.validate()?,
            identity: 1,
            normal_items: 0,
            control_items: 0,
            normal_bytes: 0,
            control_bytes: 0,
        })
    }

    /// Reserves capacity without silently dropping or unboundedly buffering.
    pub fn admit(
        &mut self,
        encoded_bytes: usize,
        control: bool,
    ) -> Result<QueueReservation, TransportError> {
        if encoded_bytes == 0 || encoded_bytes > self.limits.max_frame_bytes {
            return Err(TransportError::Backpressure);
        }
        let items = self
            .normal_items
            .checked_add(self.control_items)
            .ok_or(TransportError::Backpressure)?;
        let normal_limit = self.limits.queue_capacity - self.limits.control_reserve;
        let total_bytes = self
            .normal_bytes
            .checked_add(self.control_bytes)
            .and_then(|bytes| bytes.checked_add(encoded_bytes))
            .ok_or(TransportError::Backpressure)?;
        let control_reserve_bytes = self
            .limits
            .queue_bytes
            .saturating_mul(self.limits.control_reserve)
            / self.limits.queue_capacity;
        let normal_byte_limit = self
            .limits
            .queue_bytes
            .saturating_sub(control_reserve_bytes);
        let admitted_limit = if control {
            self.limits.queue_bytes
        } else {
            normal_byte_limit
        };
        if total_bytes > admitted_limit
            || items >= self.limits.queue_capacity
            || (!control && self.normal_items >= normal_limit)
        {
            return Err(TransportError::Backpressure);
        }
        if control {
            self.control_items += 1;
            self.control_bytes += encoded_bytes;
        } else {
            self.normal_items += 1;
            self.normal_bytes += encoded_bytes;
        }
        Ok(QueueReservation {
            owner: self.identity,
            encoded_bytes,
            control,
        })
    }

    /// Releases one previously admitted item.
    #[allow(clippy::needless_pass_by_value)]
    pub fn release(&mut self, reservation: QueueReservation) -> Result<(), TransportError> {
        let QueueReservation {
            owner,
            encoded_bytes,
            control,
        } = reservation;
        if owner != self.identity {
            return Err(TransportError::Backpressure);
        }
        let count = if control {
            &mut self.control_items
        } else {
            &mut self.normal_items
        };
        let bytes = if control {
            &mut self.control_bytes
        } else {
            &mut self.normal_bytes
        };
        if *count == 0 || encoded_bytes > *bytes {
            return Err(TransportError::Backpressure);
        }
        *count -= 1;
        *bytes -= encoded_bytes;
        Ok(())
    }

    /// Returns current item and byte usage for diagnostics.
    pub const fn usage(&self) -> (usize, usize) {
        (
            self.normal_items + self.control_items,
            self.normal_bytes + self.control_bytes,
        )
    }
}

/// Incremental decoder that preserves bytes after a partial read for recovery.
#[derive(Debug)]
pub struct FrameDecoder {
    bytes: Vec<u8>,
}

impl FrameDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Adds a read fragment and returns at most one complete frame.
    pub fn push(
        &mut self,
        fragment: &[u8],
        limits: TransportLimits,
    ) -> Result<Option<Frame>, TransportError> {
        let limits = limits.validate()?;
        if fragment.is_empty() {
            return Ok(None);
        }
        // Inspect the prefix before admitting attacker-controlled bytes.  A
        // giant fragment must never be appended merely to discover that it is
        // oversized.
        let declared = if self.bytes.len() < 4 {
            if self.bytes.len() + fragment.len() < 4 {
                self.bytes.extend_from_slice(fragment);
                return Ok(None);
            }
            let mut prefix = [0_u8; 4];
            let existing = self.bytes.len();
            prefix[..existing].copy_from_slice(&self.bytes);
            prefix[existing..].copy_from_slice(&fragment[..4 - existing]);
            usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| {
                TransportError::Protocol(ProtocolError::OversizeFrame {
                    actual: usize::MAX,
                    maximum: limits.max_frame_bytes,
                })
            })?
        } else {
            usize::try_from(u32::from_le_bytes([
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
            ]))
            .map_err(|_| {
                TransportError::Protocol(ProtocolError::OversizeFrame {
                    actual: usize::MAX,
                    maximum: limits.max_frame_bytes,
                })
            })?
        };
        if declared == 0 || declared > limits.max_frame_bytes {
            self.bytes.clear();
            return Err(TransportError::Protocol(ProtocolError::OversizeFrame {
                actual: declared,
                maximum: limits.max_frame_bytes,
            }));
        }
        let total = 4 + declared;
        if self.bytes.len() + fragment.len() > total {
            return Err(TransportError::Backpressure);
        }
        self.bytes.extend_from_slice(fragment);
        if self.bytes.len() < 4 {
            return Ok(None);
        }
        if self.bytes.len() < total {
            return Ok(None);
        }
        let wire: Vec<u8> = self.bytes.drain(..total).collect();
        decode_frame(&wire, limits).map(Some)
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay disposition for at-least-once control/event delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    New,
    Duplicate,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundIdentity {
    pub stream_id: String,
    pub module_generation: ModuleGeneration,
    pub id: String,
}

impl Ord for BoundIdentity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.stream_id,
            serde_json::to_string(&self.module_generation).unwrap_or_default(),
            &self.id,
        )
            .cmp(&(
                &other.stream_id,
                serde_json::to_string(&other.module_generation).unwrap_or_default(),
                &other.id,
            ))
    }
}

impl PartialOrd for BoundIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl BoundIdentity {
    pub fn new(
        stream_id: impl Into<String>,
        module_generation: ModuleGeneration,
        id: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let key = Self {
            stream_id: stream_id.into(),
            module_generation,
            id: id.into(),
        };
        if key.stream_id.trim().is_empty() || key.id.trim().is_empty() {
            return Err(TransportError::IdentityConflict);
        }
        key.module_generation
            .validate()
            .map_err(|_| TransportError::IdentityConflict)?;
        Ok(key)
    }
}

#[derive(Debug)]
pub struct ReplayLedger {
    entries: std::collections::BTreeMap<String, Frame>,
    bound_entries: std::collections::BTreeMap<BoundIdentity, Frame>,
    capacity: usize,
}

impl Default for ReplayLedger {
    fn default() -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
            bound_entries: std::collections::BTreeMap::new(),
            capacity: 1024,
        }
    }
}

impl ReplayLedger {
    pub fn observe(&mut self, id: impl Into<String>, frame: &Frame) -> ReplayDisposition {
        let id = id.into();
        match self.entries.get(&id) {
            Some(previous) if previous == frame => ReplayDisposition::Duplicate,
            Some(_) => ReplayDisposition::Conflict,
            None => {
                if self.entries.len() >= self.capacity {
                    ReplayDisposition::Conflict
                } else {
                    self.entries.insert(id, frame.clone());
                    ReplayDisposition::New
                }
            }
        }
    }

    pub fn observe_bound(
        &mut self,
        identity: BoundIdentity,
        frame: &Frame,
    ) -> Result<ReplayDisposition, TransportError> {
        match self.bound_entries.get(&identity) {
            Some(previous) if previous == frame => Ok(ReplayDisposition::Duplicate),
            Some(_) => Ok(ReplayDisposition::Conflict),
            None if self.bound_entries.len() >= self.capacity => Err(TransportError::RegistryFull),
            None => {
                self.bound_entries.insert(identity, frame.clone());
                Ok(ReplayDisposition::New)
            }
        }
    }

    pub fn with_capacity(capacity: usize) -> Result<Self, TransportError> {
        if capacity == 0 {
            return Err(TransportError::RegistryFull);
        }
        Ok(Self {
            entries: std::collections::BTreeMap::new(),
            bound_entries: std::collections::BTreeMap::new(),
            capacity,
        })
    }
}

/// Cancellation state is explicit and reapable; it never revives a fenced work item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationState {
    Active,
    Cancelled,
    Reaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationDisposition {
    New,
    Duplicate,
    Conflict,
    Unknown,
}

#[derive(Debug, Default)]
pub struct CancellationRegistry {
    entries: std::collections::BTreeMap<String, CancellationState>,
    bound_entries: std::collections::BTreeMap<BoundIdentity, (String, CancellationState)>,
    capacity: usize,
}

impl CancellationRegistry {
    pub fn register(&mut self, id: impl Into<String>) -> Result<(), TransportError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(TransportError::IdentityConflict);
        }
        if !self.entries.contains_key(&id) && self.entries.len() >= self.capacity() {
            return Err(TransportError::RegistryFull);
        }
        self.entries.entry(id).or_insert(CancellationState::Active);
        Ok(())
    }
    pub fn cancel(&mut self, id: &str) -> Result<(), TransportError> {
        match self.entries.get_mut(id) {
            Some(state @ CancellationState::Active) => {
                *state = CancellationState::Cancelled;
                Ok(())
            }
            _ => Err(TransportError::UnknownRequest),
        }
    }
    pub fn reap(&mut self, id: &str) -> Result<(), TransportError> {
        match self.entries.get_mut(id) {
            Some(state @ CancellationState::Cancelled) => {
                *state = CancellationState::Reaped;
                Ok(())
            }
            _ => Err(TransportError::UnknownRequest),
        }
    }
    #[must_use]
    pub fn state(&self, id: &str) -> Option<CancellationState> {
        self.entries.get(id).copied()
    }

    fn capacity(&self) -> usize {
        if self.capacity == 0 {
            1024
        } else {
            self.capacity
        }
    }

    pub fn with_capacity(capacity: usize) -> Result<Self, TransportError> {
        if capacity == 0 {
            return Err(TransportError::RegistryFull);
        }
        Ok(Self {
            entries: std::collections::BTreeMap::new(),
            bound_entries: std::collections::BTreeMap::new(),
            capacity,
        })
    }

    pub fn register_bound(
        &mut self,
        identity: BoundIdentity,
        fingerprint: impl Into<String>,
    ) -> Result<CancellationDisposition, TransportError> {
        let fingerprint = fingerprint.into();
        if fingerprint.trim().is_empty() {
            return Err(TransportError::IdentityConflict);
        }
        match self.bound_entries.get(&identity) {
            Some((previous, _)) if previous == &fingerprint => {
                Ok(CancellationDisposition::Duplicate)
            }
            Some(_) => Ok(CancellationDisposition::Conflict),
            None if self.bound_entries.len() >= self.capacity() => {
                Err(TransportError::RegistryFull)
            }
            None => {
                self.bound_entries
                    .insert(identity, (fingerprint, CancellationState::Active));
                Ok(CancellationDisposition::New)
            }
        }
    }

    pub fn cancel_bound(&mut self, identity: &BoundIdentity) -> CancellationDisposition {
        match self.bound_entries.get_mut(identity) {
            Some((_, state @ CancellationState::Active)) => {
                *state = CancellationState::Cancelled;
                CancellationDisposition::New
            }
            Some((_, CancellationState::Cancelled | CancellationState::Reaped)) => {
                CancellationDisposition::Duplicate
            }
            None => CancellationDisposition::Unknown,
        }
    }

    pub fn reap_bound(&mut self, identity: &BoundIdentity) -> CancellationDisposition {
        match self.bound_entries.get_mut(identity) {
            Some((_, state @ CancellationState::Cancelled)) => {
                *state = CancellationState::Reaped;
                CancellationDisposition::New
            }
            Some((_, CancellationState::Reaped)) => CancellationDisposition::Duplicate,
            Some((_, CancellationState::Active)) => CancellationDisposition::Conflict,
            None => CancellationDisposition::Unknown,
        }
    }
}

/// Encodes one validated semantic frame using the negotiated bounded profile.
pub fn encode_frame(frame: &Frame, limits: TransportLimits) -> Result<Vec<u8>, TransportError> {
    let limits = limits.validate()?;
    JsonCodec::with_max_frame_bytes(limits.max_frame_bytes)
        .encode(frame)
        .map_err(TransportError::Protocol)
}

/// Decodes one complete frame and rejects trailing or partial bytes.
pub fn decode_frame(wire: &[u8], limits: TransportLimits) -> Result<Frame, TransportError> {
    let limits = limits.validate()?;
    JsonCodec::with_max_frame_bytes(limits.max_frame_bytes)
        .decode(wire)
        .map_err(TransportError::Protocol)
}

/// Maps an uncertain write boundary without fabricating application proof.
pub fn classify_disconnect(after_write_started: bool) -> DeliveryOutcome {
    let _ = after_write_started;
    DeliveryOutcome::UnknownOutcome
}

/// Validates a fully qualified local Windows pipe name without accepting path-like input.
pub fn validate_pipe_name(name: &str) -> Result<(), TransportError> {
    const PREFIX: &str = r"\\.\pipe\eliot\";
    let Some(path) = name.strip_prefix(PREFIX) else {
        return Err(TransportError::InvalidPipeName);
    };
    if path.is_empty() || path.len() > 240 || name.chars().any(char::is_control) {
        return Err(TransportError::InvalidPipeName);
    }
    let components = path.split('\\').collect::<Vec<_>>();
    if components.iter().any(|component| {
        component.is_empty()
            || *component == "."
            || *component == ".."
            || component.contains('/')
            || component.contains(':')
            || component.contains('\0')
            || !component.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
    }) {
        return Err(TransportError::InvalidPipeName);
    }
    Ok(())
}

/// Windows named-pipe adapter. The concrete pipe and Win32 handles are private.
#[cfg(windows)]
pub struct NamedPipeTransport {
    inner: windows_transport::Inner,
}

#[cfg(windows)]
const AUTHENTICATION_PREFACE: &[u8; 8] = b"ELIOT-P2";

/// Private owner for the server's protected named-pipe DACL. Raw security
/// attributes never cross the `eliot-ipc` public package boundary.
#[cfg(windows)]
struct PipeSecurityDescriptor {
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl PipeSecurityDescriptor {
    fn for_principal(
        expectation: &eliot_platform_windows::NamedPipePeerExpectation,
    ) -> Result<Self, TransportError> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        let sddl = pipe_security_sddl(expectation);
        let sddl = std::ffi::OsStr::new(&sddl)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(TransportError::Io(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let Ok(n_length) = u32::try_from(std::mem::size_of::<
            windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
        >()) else {
            unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor.cast()) };
            return Err(TransportError::Io(
                "SECURITY_ATTRIBUTES size is not representable".to_owned(),
            ));
        };
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: n_length,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }

    fn raw_attributes(&mut self) -> *mut core::ffi::c_void {
        (&raw mut self.attributes).cast()
    }
}

#[cfg(windows)]
fn pipe_security_sddl(expectation: &eliot_platform_windows::NamedPipePeerExpectation) -> String {
    if expectation.requires_builtin_administrators() {
        // The one-shot installer control pipe admits only an elevated
        // Administrators client, while the client independently pins the
        // LocalService Host. Both authenticators therefore read back the same
        // exact SY+BA+LS kernel-object DACL.
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)".to_owned()
    } else {
        format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", expectation.expected_sid())
    }
}

#[cfg(windows)]
impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.descriptor.cast()) };
    }
}

/// Named-pipe server created with an explicit current-installation principal
/// ACL. Creating a server does not authenticate a client or grant authority.
#[cfg(windows)]
pub struct NamedPipeServer {
    inner: tokio::net::windows::named_pipe::NamedPipeServer,
    peer: PeerIdentity,
}

#[cfg(windows)]
impl NamedPipeServer {
    /// Creates the first named-pipe instance for a Kernel front door.
    pub fn create(
        name: &str,
        expectation: &eliot_platform_windows::NamedPipePeerExpectation,
    ) -> Result<Self, TransportError> {
        Self::create_with_first_instance(name, expectation, true)
    }

    /// Creates an additional named-pipe instance for a concurrent connection.
    pub fn create_additional(
        name: &str,
        expectation: &eliot_platform_windows::NamedPipePeerExpectation,
    ) -> Result<Self, TransportError> {
        Self::create_with_first_instance(name, expectation, false)
    }

    fn create_with_first_instance(
        name: &str,
        expectation: &eliot_platform_windows::NamedPipePeerExpectation,
        first_pipe_instance: bool,
    ) -> Result<Self, TransportError> {
        use tokio::net::windows::named_pipe::ServerOptions;
        validate_pipe_name(name)?;
        let mut security = PipeSecurityDescriptor::for_principal(expectation)?;
        let inner = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first_pipe_instance)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, security.raw_attributes())
        }
        .map_err(|error| TransportError::Io(error.to_string()))?;
        Ok(Self {
            inner,
            peer: PeerIdentity::Unavailable {
                reason: PeerIdentityUnavailable::ProviderProofNotComposed,
            },
        })
    }

    pub async fn wait_for_client(&self, timeout: Duration) -> Result<(), TransportError> {
        tokio::time::timeout(timeout, self.inner.connect())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Io(error.to_string()))
    }

    /// Connects and authenticates the client PID, process image, SID and
    /// session through the server-end pipe handle. A fixed transport preface is
    /// read before impersonation so Windows can bind the thread token to the
    /// connected client's last message.
    pub async fn wait_for_authenticated_client(
        &mut self,
        timeout: Duration,
        expectation: &eliot_platform_windows::NamedPipePeerExpectation,
    ) -> Result<(), TransportError> {
        use std::os::windows::io::{AsRawHandle, BorrowedHandle};
        self.wait_for_client(timeout).await?;
        windows_transport::read_authentication_preface(&mut self.inner, timeout).await?;
        let raw = self.inner.as_raw_handle();
        // SAFETY: `self.inner` owns the connected server handle and remains
        // alive for the complete borrowed-handle authentication call.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
        let evidence =
            eliot_platform_windows::authenticate_named_pipe_client(borrowed, expectation)
                .map_err(map_platform_error)?;
        self.peer = PeerIdentity::from_platform_evidence(&evidence)?;
        Ok(())
    }

    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    pub async fn send_frame(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, TransportError> {
        require_authenticated_peer(&self.peer)?;
        let wire = encode_frame(frame, limits)?;
        windows_transport::send_wire(&mut self.inner, &wire, limits.operation_timeout).await
    }

    pub async fn receive_frame(
        &mut self,
        limits: TransportLimits,
    ) -> Result<Frame, TransportError> {
        require_authenticated_peer(&self.peer)?;
        windows_transport::receive_wire(&mut self.inner, limits).await
    }
}

#[cfg(windows)]
impl NamedPipeTransport {
    /// Connects to an Eliot-local named pipe with a bounded timeout.
    pub async fn connect(name: &str, timeout: Duration) -> Result<Self, TransportError> {
        Ok(Self {
            inner: windows_transport::connect(name, timeout).await?,
        })
    }

    /// Connects and composes the real lower-layer proof supplied by the
    /// sibling Windows platform adapter.  Without this port composition the
    /// transport remains a typed [`TransportError::PlanGap`].
    pub async fn connect_authenticated(
        name: &str,
        timeout: Duration,
        expectation: &eliot_platform_windows::NamedPipePeerExpectation,
    ) -> Result<Self, TransportError> {
        let mut transport = Self::connect(name, timeout).await?;
        transport.inner.authenticate(expectation)?;
        transport.inner.send_authentication_preface(timeout).await?;
        Ok(transport)
    }

    /// Returns the authenticated provider-neutral peer binding.
    pub fn peer_identity(&self) -> &PeerIdentity {
        self.inner.peer()
    }

    /// Sends one frame. A successful write proves transport delivery only.
    pub async fn send_frame(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, TransportError> {
        self.inner.require_authenticated()?;
        let wire = encode_frame(frame, limits)?;
        self.inner.send(&wire, limits.operation_timeout).await
    }

    /// Sends one frame while allowing the owning operation to cancel it.
    pub async fn send_frame_with_cancel<F>(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
        cancellation: F,
    ) -> Result<DeliveryOutcome, TransportError>
    where
        F: Future<Output = ()>,
    {
        self.inner.require_authenticated()?;
        let wire = encode_frame(frame, limits)?;
        self.inner
            .send_with_cancel(&wire, limits.operation_timeout, cancellation)
            .await
    }

    /// Receives one frame with the negotiated length and byte bounds.
    pub async fn receive_frame(
        &mut self,
        limits: TransportLimits,
    ) -> Result<Frame, TransportError> {
        self.inner.require_authenticated()?;
        self.inner.receive(limits).await
    }
}

#[cfg(windows)]
mod windows_transport {
    use super::{
        AUTHENTICATION_PREFACE, DeliveryOutcome, Duration, Frame, PeerIdentity,
        PeerIdentityUnavailable, ProtocolError, TransportError, TransportLimits, decode_frame,
        map_platform_error, require_authenticated_peer,
    };
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    pub struct Inner {
        client: tokio::net::windows::named_pipe::NamedPipeClient,
        peer: PeerIdentity,
    }

    impl Inner {
        async fn read_exact_reported<R: AsyncRead + Unpin>(
            reader: &mut R,
            buffer: &mut [u8],
        ) -> Result<(), TransportError> {
            let mut read = 0;
            while read < buffer.len() {
                let count = reader
                    .read(&mut buffer[read..])
                    .await
                    .map_err(|error| TransportError::Io(error.to_string()))?;
                if count == 0 {
                    return Err(TransportError::Protocol(ProtocolError::PartialFrame {
                        expected: buffer.len(),
                        actual: read,
                    }));
                }
                read += count;
            }
            Ok(())
        }

        pub fn peer(&self) -> &PeerIdentity {
            &self.peer
        }

        pub fn authenticate(
            &mut self,
            expectation: &eliot_platform_windows::NamedPipePeerExpectation,
        ) -> Result<(), TransportError> {
            let raw = self.client.as_raw_handle();
            // SAFETY: `self.client` owns this live handle for the duration of
            // the platform adapter call and is not moved or closed here.
            let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
            let evidence =
                eliot_platform_windows::authenticate_named_pipe_server(borrowed, expectation)
                    .map_err(map_platform_error)?;
            self.peer = PeerIdentity::from_platform_evidence(&evidence)?;
            Ok(())
        }

        pub fn require_authenticated(&self) -> Result<(), TransportError> {
            require_authenticated_peer(&self.peer)
        }

        pub async fn send_authentication_preface(
            &mut self,
            timeout: Duration,
        ) -> Result<(), TransportError> {
            tokio::time::timeout(timeout, self.client.write_all(AUTHENTICATION_PREFACE))
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|error| TransportError::Io(error.to_string()))
        }

        pub async fn send(
            &mut self,
            wire: &[u8],
            timeout: Duration,
        ) -> Result<DeliveryOutcome, TransportError> {
            send_wire(&mut self.client, wire, timeout).await
        }

        pub async fn send_with_cancel<F>(
            &mut self,
            wire: &[u8],
            timeout: Duration,
            cancellation: F,
        ) -> Result<DeliveryOutcome, TransportError>
        where
            F: Future<Output = ()>,
        {
            let write = self.client.write_all(wire);
            tokio::pin!(write);
            tokio::pin!(cancellation);
            tokio::select! {
                result = tokio::time::timeout(timeout, &mut write) => match result {
                    Ok(Ok(())) => Ok(DeliveryOutcome::Delivered),
                    Ok(Err(_error)) => Ok(DeliveryOutcome::UnknownOutcome),
                    Err(_) => Ok(DeliveryOutcome::UnknownOutcome),
                },
                // The write may have reached the peer before cancellation won.
                () = &mut cancellation => Ok(DeliveryOutcome::UnknownOutcome),
            }
        }

        pub async fn receive(&mut self, limits: TransportLimits) -> Result<Frame, TransportError> {
            receive_wire(&mut self.client, limits).await
        }
    }

    pub async fn connect(name: &str, timeout: Duration) -> Result<Inner, TransportError> {
        super::validate_pipe_name(name)?;
        let pipe_name = name.to_owned();
        let client = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || ClientOptions::new().open(pipe_name)),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(|error| TransportError::Io(error.to_string()))?
        .map_err(|error| TransportError::Io(error.to_string()))?;
        let peer = PeerIdentity::Unavailable {
            reason: PeerIdentityUnavailable::ProviderProofNotComposed,
        };
        Ok(Inner { client, peer })
    }

    pub(super) async fn read_authentication_preface<R: AsyncRead + Unpin>(
        reader: &mut R,
        timeout: Duration,
    ) -> Result<(), TransportError> {
        let mut preface = [0_u8; AUTHENTICATION_PREFACE.len()];
        tokio::time::timeout(timeout, Inner::read_exact_reported(reader, &mut preface))
            .await
            .map_err(|_| TransportError::Timeout)??;
        if &preface != AUTHENTICATION_PREFACE {
            return Err(TransportError::UnauthenticatedPeer);
        }
        Ok(())
    }

    pub(super) async fn send_wire<W: AsyncWrite + Unpin>(
        writer: &mut W,
        wire: &[u8],
        timeout: Duration,
    ) -> Result<DeliveryOutcome, TransportError> {
        let result = tokio::time::timeout(timeout, writer.write_all(wire)).await;
        match result {
            Ok(Ok(())) => Ok(DeliveryOutcome::Delivered),
            Ok(Err(_)) | Err(_) => Ok(DeliveryOutcome::UnknownOutcome),
        }
    }

    pub(super) async fn receive_wire<R: AsyncRead + Unpin>(
        reader: &mut R,
        limits: TransportLimits,
    ) -> Result<Frame, TransportError> {
        let limits = limits.validate()?;
        let mut prefix = [0_u8; 4];
        tokio::time::timeout(
            limits.operation_timeout,
            Inner::read_exact_reported(reader, &mut prefix),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
        let length = usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| {
            TransportError::Protocol(ProtocolError::OversizeFrame {
                actual: usize::MAX,
                maximum: limits.max_frame_bytes,
            })
        })?;
        if length == 0 || length > limits.max_frame_bytes {
            return Err(TransportError::Protocol(ProtocolError::OversizeFrame {
                actual: length,
                maximum: limits.max_frame_bytes,
            }));
        }
        let mut wire = Vec::with_capacity(4 + length);
        wire.extend_from_slice(&prefix);
        wire.resize(4 + length, 0);
        tokio::time::timeout(
            limits.operation_timeout,
            Inner::read_exact_reported(reader, &mut wire[4..]),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
        decode_frame(&wire, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_protocol::{EncodingProfile, FrameKind, MessageType, ProtocolPayload};
    use std::collections::BTreeMap;

    fn module_generation(epoch: u64) -> ModuleGeneration {
        serde_json::from_value(serde_json::json!({
            "module_id": "module.test",
            "generation": 1,
            "artifact_id": "artifact",
            "state": "ACTIVE",
            "health": {
                "liveness": "HEALTHY",
                "readiness": "HEALTHY",
                "freshness": "HEALTHY",
                "compatibility": "HEALTHY",
                "integrity": "HEALTHY",
                "capacity": "HEALTHY"
            },
            "state_fence": {
                "authority_epoch": epoch,
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            }
        }))
        .expect("canonical module generation")
    }

    fn limits() -> TransportLimits {
        TransportLimits {
            max_frame_bytes: 64,
            queue_capacity: 4,
            queue_bytes: 256,
            control_reserve: 1,
            operation_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn queue_preserves_control_reserve() {
        let mut queue = AdmissionQueue::new(limits()).expect("valid limits");
        let first = queue.admit(8, false).expect("normal one");
        queue.admit(8, false).expect("normal two");
        queue.admit(8, false).expect("normal three");
        assert!(matches!(
            queue.admit(8, false),
            Err(TransportError::Backpressure)
        ));
        queue.admit(8, true).expect("control reserve");
        queue.release(first).expect("release exact reservation");
        assert_eq!(queue.usage(), (3, 24));
    }

    #[test]
    fn invalid_limits_and_identity_fail_closed() {
        assert!(AdmissionQueue::new(TransportLimits::default()).is_ok());
        let process = ProcessBinding::from_observation(1, 2, "C:/eliot-test.exe").expect("process");
        let invalid = PeerIdentity::Authenticated {
            process_id: 0,
            user_identity: String::new(),
            session_identity: String::new(),
            proof: IdentityProof {
                process,
                sid: "sid".into(),
                session: "session".into(),
            },
        };
        assert_eq!(invalid.validate(), Err(TransportError::UnauthenticatedPeer));
        assert!(invalid.process_binding().is_none());
        let valid_process =
            ProcessBinding::from_observation(7, 11, "C:/eliot-valid.exe").expect("process");
        let valid = PeerIdentity::Authenticated {
            process_id: 7,
            user_identity: "sid".to_owned(),
            session_identity: "session".to_owned(),
            proof: IdentityProof {
                process: valid_process,
                sid: "sid".to_owned(),
                session: "session".to_owned(),
            },
        };
        let observed = valid.process_binding().expect("valid process evidence");
        assert_eq!(observed.process_id(), 7);
        assert_eq!(observed.start_time_100ns(), 11);
        assert_eq!(observed.image_path(), "C:/eliot-valid.exe");
        let unavailable = PeerIdentity::Unavailable {
            reason: PeerIdentityUnavailable::ProviderProofNotComposed,
        };
        assert_eq!(
            unavailable.validate(),
            Err(TransportError::PeerIdentityUnavailable)
        );
        assert!(unavailable.process_binding().is_none());
    }

    #[test]
    fn uncertainty_never_becomes_delivery_proof() {
        assert_eq!(classify_disconnect(false), DeliveryOutcome::UnknownOutcome);
        assert_eq!(classify_disconnect(true), DeliveryOutcome::UnknownOutcome);
    }

    fn heartbeat() -> Frame {
        Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: "connection".into(),
            request_id: None,
            kind: FrameKind::Heartbeat,
            message_type: MessageType::Health,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::Value::Null),
            trace_context: BTreeMap::new(),
        }
    }

    #[test]
    fn stale_epoch_duplicate_conflict_and_reap_are_explicit() {
        let mut session = Session {
            connection_id: "c".into(),
            protocol_version: ProtocolVersion::CURRENT,
            peer: PeerIdentity::Unavailable {
                reason: PeerIdentityUnavailable::ProviderProofNotComposed,
            },
            authority_epoch: 4,
            module_generation: module_generation(4),
            launch_nonce: "nonce".into(),
            capabilities: Vec::new(),
            privacy_classes: Vec::new(),
            effects: Vec::new(),
            session_epoch: 2,
            state: SessionState::Open,
        };
        assert!(!session.accepts(3, 2));
        let frame = heartbeat();
        let mut ledger = ReplayLedger::default();
        assert_eq!(ledger.observe("event", &frame), ReplayDisposition::New);
        assert_eq!(
            ledger.observe("event", &frame),
            ReplayDisposition::Duplicate
        );
        let mut changed = frame.clone();
        changed.connection_id = "other".into();
        assert_eq!(
            ledger.observe("event", &changed),
            ReplayDisposition::Conflict
        );
        let mut cancellation = CancellationRegistry::default();
        cancellation.register("request").expect("registration");
        cancellation.cancel("request").expect("cancel");
        cancellation.reap("request").expect("reap");
        assert_eq!(
            cancellation.state("request"),
            Some(CancellationState::Reaped)
        );
        assert_eq!(classify_write(true), OperationOutcome::PostCommitUnknown);
        assert_eq!(classify_write(false), OperationOutcome::NotStarted);
        assert_eq!(
            classify_write_progress(true, false),
            OperationOutcome::Partial
        );
        assert_eq!(
            IntegrationDependency::PlanGap,
            IntegrationDependency::PlanGap
        );
        session.fence();
        assert!(!session.accepts(4, 2));
    }

    #[test]
    fn partial_frame_decoder_recovers_across_reads() {
        let frame = heartbeat();
        let frame_limits = TransportLimits {
            max_frame_bytes: 512,
            queue_capacity: 4,
            queue_bytes: 2048,
            control_reserve: 1,
            operation_timeout: Duration::from_secs(1),
        };
        let wire = encode_frame(&frame, frame_limits).expect("encode");
        let split = wire.len() / 2;
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decoder
                .push(&wire[..split], frame_limits)
                .expect("first read"),
            None
        );
        assert_eq!(
            decoder
                .push(&wire[split..], frame_limits)
                .expect("second read"),
            Some(frame)
        );
    }

    #[test]
    fn codec_rejects_partial_zero_and_oversize_frames() {
        assert!(matches!(
            decode_frame(&[0, 0, 0, 0], limits()),
            Err(TransportError::Protocol(ProtocolError::ZeroLengthFrame))
        ));
        assert!(matches!(
            decode_frame(&[1, 0], limits()),
            Err(TransportError::Protocol(ProtocolError::PartialFrame { .. }))
        ));
        assert!(matches!(
            decode_frame(&[65, 0, 0, 0], limits()),
            Err(TransportError::Protocol(
                ProtocolError::OversizeFrame { .. }
            ))
        ));
    }

    #[test]
    fn decoder_rejects_oversized_fragment_before_buffer_growth() {
        let mut decoder = FrameDecoder::new();
        let limits = limits();
        let mut fragment = vec![0_u8; 4 + limits.max_frame_bytes + 1];
        fragment[..4].copy_from_slice(
            &u32::try_from(limits.max_frame_bytes + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(matches!(
            decoder.push(&fragment, limits),
            Err(TransportError::Protocol(
                ProtocolError::OversizeFrame { .. }
            ))
        ));
        assert_eq!(decoder.bytes.len(), 0);
    }

    #[test]
    fn bound_ledgers_reject_conflicts_and_remain_bounded() {
        let key =
            BoundIdentity::new("stream", module_generation(1), "cancel").expect("bound identity");
        let frame = heartbeat();
        let mut replay = ReplayLedger::with_capacity(1).expect("capacity");
        assert_eq!(
            replay.observe_bound(key.clone(), &frame).expect("new"),
            ReplayDisposition::New
        );
        assert_eq!(
            replay
                .observe_bound(key.clone(), &frame)
                .expect("duplicate"),
            ReplayDisposition::Duplicate
        );
        let mut conflict = frame.clone();
        conflict.connection_id = "different".into();
        assert_eq!(
            replay
                .observe_bound(key.clone(), &conflict)
                .expect("conflict"),
            ReplayDisposition::Conflict
        );
        let mut cancellation = CancellationRegistry::with_capacity(1).expect("capacity");
        assert_eq!(
            cancellation
                .register_bound(key.clone(), "request-a")
                .expect("new"),
            CancellationDisposition::New
        );
        assert_eq!(
            cancellation
                .register_bound(key.clone(), "request-b")
                .expect("conflict"),
            CancellationDisposition::Conflict
        );
        assert_eq!(
            cancellation.cancel_bound(&key),
            CancellationDisposition::New
        );
        assert_eq!(cancellation.reap_bound(&key), CancellationDisposition::New);
        assert_eq!(
            cancellation.cancel_bound(&key),
            CancellationDisposition::Duplicate
        );
    }

    #[test]
    fn pipe_names_reject_traversal_and_controls() {
        assert!(validate_pipe_name(r"\\.\pipe\eliot\kernel\frontdoor").is_ok());
        for name in [
            r"\\.\pipe\eliot\..\other",
            r"\\.\pipe\eliot\kernel/other",
            "\\\\.\\pipe\\eliot\\kernel\0test",
            "\\\\.\\pipe\\eliot\\kernel\n",
        ] {
            assert_eq!(
                validate_pipe_name(name),
                Err(TransportError::InvalidPipeName)
            );
        }
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn real_named_pipe_connect_disconnect_reports_identity_gap() {
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = format!(r"\\.\pipe\eliot\test\{}", std::process::id());
        let server = ServerOptions::new().create(&name).expect("test pipe");
        let server_task = tokio::spawn(async move { server.connect().await });
        let client = NamedPipeTransport::connect(&name, Duration::from_secs(2))
            .await
            .expect("client connection");
        let server_result = server_task.await.expect("server task");
        server_result.expect("server connection");
        assert_eq!(
            client.peer_identity(),
            &PeerIdentity::Unavailable {
                reason: PeerIdentityUnavailable::ProviderProofNotComposed,
            }
        );
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn explicit_acl_pipe_authenticates_handle_bound_server_identity() {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current token expectation");
        let name = format!(
            r"\\.\pipe\eliot\authenticated\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let mut server = NamedPipeServer::create(&name, &expectation).expect("secured pipe");
        let server_expectation = expectation.clone();
        let server_task = tokio::spawn(async move {
            server
                .wait_for_authenticated_client(Duration::from_secs(2), &server_expectation)
                .await?;
            Ok::<_, TransportError>(server)
        });
        let client =
            NamedPipeTransport::connect_authenticated(&name, Duration::from_secs(2), &expectation)
                .await
                .expect("authenticated client");
        let server = server_task
            .await
            .expect("server task")
            .expect("server connection");
        assert!(matches!(
            client.peer_identity(),
            PeerIdentity::Authenticated { .. }
        ));
        assert!(matches!(
            server.peer_identity(),
            PeerIdentity::Authenticated { .. }
        ));
        assert_eq!(
            eliot_platform_windows::current_process_named_pipe_expectation()
                .expect("server reverted to its process token"),
            expectation
        );
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn handle_bound_authentication_rejects_wrong_session() {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current token expectation");
        let wrong_session = eliot_platform_windows::NamedPipePeerExpectation::new(
            expectation.expected_sid(),
            expectation.expected_session_id().wrapping_add(1),
        )
        .expect("inert mismatched expectation");
        let name = format!(
            r"\\.\pipe\eliot\wrong-session\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let server = NamedPipeServer::create(&name, &expectation).expect("secured pipe");
        let server_task =
            tokio::spawn(async move { server.wait_for_client(Duration::from_secs(2)).await });
        let result = NamedPipeTransport::connect_authenticated(
            &name,
            Duration::from_secs(2),
            &wrong_session,
        )
        .await;
        server_task
            .await
            .expect("server task")
            .expect("server connection");
        assert!(matches!(result, Err(TransportError::UnauthenticatedPeer)));
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn real_named_pipe_partial_frame_is_not_decoded() {
        use tokio::io::AsyncWriteExt;

        let name = format!(r"\\.\pipe\eliot\test-partial\{}", std::process::id());
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current token expectation");
        let mut server = NamedPipeServer::create(&name, &expectation).expect("test pipe");
        let server_expectation = expectation.clone();
        let server_task = tokio::spawn(async move {
            server
                .wait_for_authenticated_client(Duration::from_secs(2), &server_expectation)
                .await
                .expect("authenticated server connection");
            server
                .inner
                .write_all(&[5, 0, 0, 0, b'{'])
                .await
                .expect("partial frame write");
        });
        let mut client =
            NamedPipeTransport::connect_authenticated(&name, Duration::from_secs(2), &expectation)
                .await
                .expect("authenticated client connection");
        assert!(matches!(
            client.receive_frame(limits()).await,
            Err(TransportError::Protocol(ProtocolError::PartialFrame {
                expected: 5,
                actual: 1,
            }))
        ));
        server_task.await.expect("server task");
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn server_rejects_wrong_authentication_preface_before_client_authority() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::windows::named_pipe::ClientOptions;

        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current token expectation");
        let name = format!(
            r"\\.\pipe\eliot\wrong-preface\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let mut server = NamedPipeServer::create(&name, &expectation).expect("secured pipe");
        let client_name = name.clone();
        let client = tokio::spawn(async move {
            let mut client = ClientOptions::new().open(client_name).expect("raw client");
            client.write_all(b"NOT-ELIO").await.expect("wrong preface");
        });
        assert_eq!(
            server
                .wait_for_authenticated_client(Duration::from_secs(2), &expectation)
                .await,
            Err(TransportError::UnauthenticatedPeer)
        );
        assert!(matches!(
            server.peer_identity(),
            PeerIdentity::Unavailable { .. }
        ));
        client.await.expect("client task");
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_pipe_child_process() {
        let Ok(name) = std::env::var("ELIOT_P02_PIPE_CHILD") else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("child runtime");
        runtime.block_on(async move {
            let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
                .expect("child expectation");
            let mut transport = NamedPipeTransport::connect_authenticated(
                &name,
                Duration::from_secs(5),
                &expectation,
            )
            .await
            .expect("child authenticated connection");
            assert_eq!(
                transport
                    .send_frame(&heartbeat(), TransportLimits::default())
                    .await,
                Ok(DeliveryOutcome::Delivered)
            );
            assert_eq!(
                transport
                    .receive_frame(TransportLimits::default())
                    .await
                    .expect("server acknowledgement"),
                heartbeat()
            );
        });
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn server_authenticates_distinct_client_pid_sid_session_and_process() {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current token expectation");
        let name = format!(
            r"\\.\pipe\eliot\client-binding\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let mut server = NamedPipeServer::create(&name, &expectation).expect("secured pipe");
        let mut child = std::process::Command::new(std::env::current_exe().expect("test image"))
            .arg("--exact")
            .arg("tests::authenticated_pipe_child_process")
            .arg("--nocapture")
            .env("ELIOT_P02_PIPE_CHILD", &name)
            .spawn()
            .expect("pipe client process");
        server
            .wait_for_authenticated_client(Duration::from_secs(5), &expectation)
            .await
            .expect("server authenticated client");
        match server.peer_identity() {
            PeerIdentity::Authenticated {
                process_id, proof, ..
            } => {
                assert_eq!(*process_id, child.id());
                assert_eq!(proof.process.process_id(), child.id());
                assert!(proof.process.start_time_100ns() > 0);
                assert!(!proof.process.image_path().is_empty());
            }
            PeerIdentity::Unavailable { .. } => panic!("client proof must be composed"),
        }
        assert_eq!(
            server
                .receive_frame(TransportLimits::default())
                .await
                .expect("child frame"),
            heartbeat()
        );
        assert_eq!(
            server
                .send_frame(&heartbeat(), TransportLimits::default())
                .await,
            Ok(DeliveryOutcome::Delivered)
        );
        assert!(child.wait().expect("child exit").success());
    }

    #[cfg(windows)]
    #[test]
    fn installer_control_pipe_dacl_binds_admin_client_and_local_service_host() {
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .expect("administrator expectation");
        assert_eq!(
            pipe_security_sddl(&expectation),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)"
        );
    }
}
