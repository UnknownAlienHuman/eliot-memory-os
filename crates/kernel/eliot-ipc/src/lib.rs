//! P-02 bounded EBP/1 transport mechanics.
//!
//! Semantic frames remain owned by `eliot-protocol`.  This crate owns only the
//! transport boundary: negotiation, bounded admission, session fencing and
//! transport-level reconciliation.  It never reports durable application
//! commit or sink acceptance.

use std::future::Future;
use std::time::Duration;

use eliot_protocol::{
    AgentBridgeClientDeclaration, AgentBridgePeerAdmissionReceipt, AgentBridgePeerChallenge,
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolError, ProtocolPayload,
    ProtocolRange, ProtocolVersion, ServerHello, negotiate,
};
use eliot_runtime_contracts::ModuleGeneration;
use thiserror::Error;

mod frame_codec;

pub use frame_codec::{FrameDecoder, decode_frame, encode_frame};

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
    executable_file: Option<(u32, u64)>,
}

impl ProcessBinding {
    fn from_observation_inner(
        process_id: u32,
        start_time_100ns: u64,
        image_path: String,
    ) -> Result<Self, TransportError> {
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
            executable_file: None,
        })
    }

    /// Creates the value observed by a trusted platform adapter.
    ///
    /// The constructor is intentionally boring: authority comes from the
    /// adapter's handle-bound observation, never from a caller-provided
    /// boolean.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_observation(
        process_id: u32,
        start_time_100ns: u64,
        image_path: impl Into<String>,
    ) -> Result<Self, TransportError> {
        Self::from_observation_inner(process_id, start_time_100ns, image_path.into())
    }

    pub(crate) fn from_observation_for_platform(
        process_id: u32,
        start_time_100ns: u64,
        image_path: String,
        executable_file: Option<(u32, u64)>,
    ) -> Result<Self, TransportError> {
        let mut binding = Self::from_observation_inner(process_id, start_time_100ns, image_path)?;
        binding.executable_file = executable_file;
        Ok(binding)
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

    /// Returns the handle-bound executable file identity when supplied by the
    /// platform adapter.
    #[must_use]
    pub const fn executable_file_identity(&self) -> Option<(u32, u64)> {
        self.executable_file
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

impl IdentityProof {
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(process: ProcessBinding, sid: String, session: String) -> Self {
        Self {
            process,
            sid,
            session,
        }
    }
}

impl PeerIdentity {
    #[cfg(windows)]
    fn from_platform_evidence(
        evidence: &eliot_platform_windows::NamedPipePeerEvidence,
    ) -> Result<Self, TransportError> {
        let observed = evidence.process();
        let process = ProcessBinding::from_observation_for_platform(
            observed.process_id,
            observed.start_time_100ns,
            observed.image_path.clone(),
            evidence
                .executable_file_identity()
                .map(|identity| (identity.volume_serial_number, identity.file_index)),
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn authenticated_for_test(
        process: ProcessBinding,
        sid: String,
        session: String,
    ) -> Result<Self, TransportError> {
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

/// Encodes the Kernel-issued peer challenge on the authenticated control lane.
///
/// The challenge is correlation-only. It does not carry or establish a
/// semantic Session, principal, task, scope, plan, or request identity.
pub fn peer_challenge_frame(
    connection_id: impl Into<String>,
    challenge: &AgentBridgePeerChallenge,
) -> Result<Frame, TransportError> {
    challenge.validate()?;
    handshake_frame(
        connection_id,
        FrameKind::Control,
        MessageType::Challenge,
        serde_json::to_value(challenge).map_err(|error| ProtocolError::Json(error.to_string()))?,
    )
}

/// Decodes the exact typed peer challenge from an authenticated control frame.
pub fn decode_peer_challenge_frame(
    frame: &Frame,
    expected_connection_id: &str,
) -> Result<AgentBridgePeerChallenge, TransportError> {
    let payload = validate_handshake_frame(
        frame,
        Some(expected_connection_id),
        FrameKind::Control,
        MessageType::Challenge,
    )?;
    let challenge: AgentBridgePeerChallenge = serde_json::from_value(payload.clone())
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    challenge.validate()?;
    Ok(challenge)
}

/// Encodes the Kernel-issued bridge admission receipt on the authenticated
/// control lane. The receipt is transport evidence only; it carries no
/// request identity or semantic Session binding.
pub fn agent_bridge_admission_receipt_frame(
    connection_id: impl Into<String>,
    receipt: &AgentBridgePeerAdmissionReceipt,
) -> Result<Frame, TransportError> {
    let connection_id = connection_id.into();
    receipt.validate()?;
    if receipt.connection_id != connection_id {
        return Err(TransportError::SessionFenced);
    }
    handshake_frame(
        connection_id,
        FrameKind::Control,
        MessageType::Ready,
        serde_json::to_value(receipt).map_err(|error| ProtocolError::Json(error.to_string()))?,
    )
}

/// Decodes the exact Kernel-issued bridge admission receipt from a control
/// frame and rejects connection, request-correlation, or receipt substitutions.
pub fn decode_agent_bridge_admission_receipt_frame(
    frame: &Frame,
    expected_connection_id: &str,
) -> Result<AgentBridgePeerAdmissionReceipt, TransportError> {
    let payload = validate_handshake_frame(
        frame,
        Some(expected_connection_id),
        FrameKind::Control,
        MessageType::Ready,
    )?;
    let receipt: AgentBridgePeerAdmissionReceipt = serde_json::from_value(payload.clone())
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    receipt.validate()?;
    if receipt.connection_id != expected_connection_id {
        return Err(TransportError::SessionFenced);
    }
    Ok(receipt)
}

/// One-shot server-first handshake state owned by a single transport
/// connection.
///
/// The server creates the connection identity and supplies the already
/// selected challenge/declaration pair. This type deliberately does not
/// reference [`ServerHandshakePolicy`]: it cannot mutate shared handshake
/// policy or issue any application authority. A malformed, mismatched, or
/// repeated `ClientHello` permanently fences this connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerFirstState {
    /// The challenge was sent and one exact `ClientHello` is expected.
    Challenged,
    /// The exact one-shot `ClientHello` was accepted.
    Accepted,
    /// The connection is permanently fenced after a protocol failure.
    Fenced,
    /// The owner explicitly aborted before acceptance.
    Aborted,
}

/// Provider-neutral server-first challenge/hello exchange.
///
/// `ServerFirstConnection` is intentionally not `Clone`: copying a pending
/// state would allow two owners to accept the same one-shot challenge.
///
/// ```compile_fail
/// use eliot_ipc::ServerFirstConnection;
///
/// let connection: ServerFirstConnection = panic!("owned pending connection");
/// let _duplicate = connection.clone();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct ServerFirstConnection {
    connection_id: String,
    challenge: AgentBridgePeerChallenge,
    declaration: AgentBridgeClientDeclaration,
    client_hello: Option<ClientHello>,
    state: ServerFirstState,
}

/// Reusable accepted bridge transport state.  It retains every transport
/// binding needed by later Kernel routing; it does not contain semantic
/// Session, task, scope, or plan state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedAgentBridgeTransport {
    connection_id: String,
    challenge: AgentBridgePeerChallenge,
    declaration: AgentBridgeClientDeclaration,
    client_hello: ClientHello,
    peer: PeerIdentity,
    admission_receipt: AgentBridgePeerAdmissionReceipt,
}

impl AcceptedAgentBridgeTransport {
    /// Returns the Kernel-created connection identity.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the retained Kernel challenge.
    #[must_use]
    pub const fn challenge(&self) -> &AgentBridgePeerChallenge {
        &self.challenge
    }

    /// Returns the exact static declaration used by the bridge.
    #[must_use]
    pub const fn declaration(&self) -> &AgentBridgeClientDeclaration {
        &self.declaration
    }

    /// Returns the exact dynamic client hello accepted on this connection.
    #[must_use]
    pub const fn client_hello(&self) -> &ClientHello {
        &self.client_hello
    }

    /// Returns the trusted platform peer identity.
    #[must_use]
    pub const fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    /// Returns the immutable v2 Kernel admission receipt.
    #[must_use]
    pub const fn admission_receipt(&self) -> &AgentBridgePeerAdmissionReceipt {
        &self.admission_receipt
    }
}

impl ServerFirstConnection {
    /// Creates a server-owned one-shot exchange after validating the exact
    /// challenge/declaration relationship.
    pub fn new(
        connection_id: impl Into<String>,
        challenge: AgentBridgePeerChallenge,
        declaration: &AgentBridgeClientDeclaration,
    ) -> Result<Self, TransportError> {
        let connection_id = connection_id.into();
        validate_server_connection_id(&connection_id)?;
        challenge.validate_declaration(declaration)?;
        Ok(Self {
            connection_id,
            challenge,
            declaration: declaration.clone(),
            client_hello: None,
            state: ServerFirstState::Challenged,
        })
    }

    /// Returns the server-created connection identity.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the validated one-shot challenge.
    #[must_use]
    pub const fn challenge(&self) -> &AgentBridgePeerChallenge {
        &self.challenge
    }

    /// Returns the current exchange state.
    #[must_use]
    pub const fn state(&self) -> ServerFirstState {
        self.state
    }

    /// Builds the exact Control/Challenge frame for this connection.
    pub fn challenge_frame(&self) -> Result<Frame, TransportError> {
        peer_challenge_frame(&self.connection_id, &self.challenge)
    }

    /// Accepts exactly one Control/Start `ClientHello` matching the supplied
    /// static declaration and this challenge's nonce.
    ///
    /// The declaration is revalidated and rebound on every attempt. Any
    /// malformed frame, identity mismatch, declaration substitution, nonce
    /// substitution, digest mismatch, or second attempt fences the exchange.
    pub fn accept_client_hello(
        &mut self,
        frame: &Frame,
        declaration: &AgentBridgeClientDeclaration,
    ) -> Result<ClientHello, TransportError> {
        if self.state != ServerFirstState::Challenged {
            self.state = ServerFirstState::Fenced;
            return Err(TransportError::SessionFenced);
        }

        let result = (|| {
            self.challenge.validate_declaration(declaration)?;
            let hello = decode_client_hello_frame(frame, &self.connection_id)?;
            let expected = declaration.client_hello(self.challenge.challenge_nonce.clone())?;
            if hello != expected {
                return Err(TransportError::SessionFenced);
            }
            Ok(hello)
        })();
        if let Ok(hello) = result {
            self.client_hello = Some(hello.clone());
            self.state = ServerFirstState::Accepted;
            Ok(hello)
        } else {
            self.state = ServerFirstState::Fenced;
            Err(TransportError::SessionFenced)
        }
    }

    /// Explicitly aborts this exchange for an owner-observed timeout or
    /// disconnect. No clock is invented by this transport-neutral type.
    pub fn abort(&mut self) {
        self.state = ServerFirstState::Aborted;
    }

    /// Explicitly fences this exchange for an owner-observed transport fault.
    pub fn fence(&mut self) {
        self.state = ServerFirstState::Fenced;
    }

    /// Accepts the exact hello and seals the reusable bridge transport state
    /// against trusted, handle-bound peer evidence.
    pub fn accept_client_hello_with_peer(
        &mut self,
        frame: &Frame,
        declaration: &AgentBridgeClientDeclaration,
        peer: &PeerIdentity,
    ) -> Result<AcceptedAgentBridgeTransport, TransportError> {
        let hello = self.accept_client_hello(frame, declaration)?;
        build_accepted_bridge_transport(self, peer, hello)
    }
}

fn build_accepted_bridge_transport(
    connection: &ServerFirstConnection,
    peer: &PeerIdentity,
    hello: ClientHello,
) -> Result<AcceptedAgentBridgeTransport, TransportError> {
    peer.validate()?;
    let PeerIdentity::Authenticated {
        user_identity,
        session_identity,
        proof,
        ..
    } = peer
    else {
        return Err(TransportError::PeerIdentityUnavailable);
    };
    let session_id = session_identity
        .parse::<u32>()
        .map_err(|_| TransportError::UnauthenticatedPeer)?;
    let (volume_serial_number, file_index) = proof
        .process
        .executable_file_identity()
        .ok_or(TransportError::UnauthenticatedPeer)?;
    let receipt = AgentBridgePeerAdmissionReceipt {
        wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
        wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
        module_id: connection.challenge.module_id.clone(),
        connection_id: connection.connection_id.clone(),
        profile_id: connection.challenge.profile_id.clone(),
        descriptor_sha256: connection.challenge.descriptor_sha256.clone(),
        client_declaration_sha256: connection.challenge.client_declaration_sha256.clone(),
        bridge_generation: connection.challenge.bridge_generation,
        state_fence: connection.challenge.state_fence.clone(),
        activation_deadline_unix_ms: connection.challenge.activation_deadline_unix_ms,
        challenge_nonce: connection.challenge.challenge_nonce.clone(),
        challenge_sha256: connection.challenge.challenge_sha256.clone(),
        client_hello_sha256: eliot_platform_windows::sha256_hex(
            &canonical_json_bytes(&hello).map_err(|error| {
                TransportError::Protocol(ProtocolError::Json(error.to_string()))
            })?,
        ),
        observed_sid: user_identity.clone(),
        observed_session_id: session_id,
        observed_process_id: proof.process.process_id(),
        observed_process_start_time_100ns: proof.process.start_time_100ns(),
        observed_image_path: proof.process.image_path().to_owned(),
        observed_image_volume_serial: volume_serial_number,
        observed_image_file_index: file_index,
        receipt_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(TransportError::Protocol)?;
    receipt
        .validate_challenge(&connection.challenge)
        .map_err(TransportError::Protocol)?;
    receipt
        .validate_client_hello(&connection.declaration, &hello)
        .map_err(TransportError::Protocol)?;
    Ok(AcceptedAgentBridgeTransport {
        connection_id: connection.connection_id.clone(),
        challenge: connection.challenge.clone(),
        declaration: connection.declaration.clone(),
        client_hello: hello,
        peer: peer.clone(),
        admission_receipt: receipt,
    })
}

fn canonical_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    fn canonicalize(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(canonicalize).collect())
            }
            serde_json::Value::Object(object) => {
                let mut sorted = serde_json::Map::new();
                let mut entries = object.into_iter().collect::<Vec<_>>();
                entries.sort_by(|left, right| left.0.cmp(&right.0));
                for (key, value) in entries {
                    sorted.insert(key, canonicalize(value));
                }
                serde_json::Value::Object(sorted)
            }
            scalar => scalar,
        }
    }
    serde_json::to_vec(&canonicalize(serde_json::to_value(value)?))
}

fn validate_server_connection_id(connection_id: &str) -> Result<(), TransportError> {
    if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
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
    /// Establishes the post-resolution bridge transport session.
    ///
    /// This constructor accepts only Kernel-owned transport inputs. It does
    /// not accept or derive semantic principal, task, scope, plan, capability,
    /// or effect authority; those remain in the activation response binding.
    pub fn establish_agent_bridge(
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        module_generation: ModuleGeneration,
        session_nonce: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let connection_id = connection_id.into();
        let session_nonce = session_nonce.into();
        if connection_id.trim().is_empty() || session_nonce.trim().is_empty() {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()?;
        module_generation
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(Self {
            connection_id,
            protocol_version: ProtocolVersion::CURRENT,
            peer,
            authority_epoch: module_generation.state_fence.authority_epoch.value(),
            module_generation,
            launch_nonce: session_nonce,
            capabilities: Vec::new(),
            privacy_classes: Vec::new(),
            effects: Vec::new(),
            session_epoch: 1,
            state: SessionState::Open,
        })
    }

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
    pub fn observe(
        &mut self,
        id: impl Into<String>,
        frame: &Frame,
    ) -> Result<ReplayDisposition, TransportError> {
        let id = id.into();
        match self.entries.get(&id) {
            Some(previous) if previous == frame => Ok(ReplayDisposition::Duplicate),
            Some(_) => Ok(ReplayDisposition::Conflict),
            None if self.entries.len() >= self.capacity => Err(TransportError::RegistryFull),
            None => {
                self.entries.insert(id, frame.clone());
                Ok(ReplayDisposition::New)
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

    fn for_peer_set(
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<Self, TransportError> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        let sddl = pipe_security_sddl_for_peer_set(peers);
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
fn pipe_security_sddl_for_peer_set(peers: &eliot_platform_windows::NamedPipePeerSet) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)");
    if peers.requires_builtin_administrators() {
        sddl.push_str("(A;;GA;;;BA)");
    }
    for sid in peers.expected_sids() {
        let ace = format!("(A;;GA;;;{sid})");
        if !sddl.contains(&ace) {
            sddl.push_str(&ace);
        }
    }
    sddl
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
    evidence: Option<eliot_platform_windows::NamedPipePeerEvidence>,
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

    /// Creates the first instance with a bounded allow-list of Host, Eliotd,
    /// and/or `AgentBridge` principals.  Selection is deferred until the live
    /// connected handle has yielded complete platform evidence.
    pub fn create_with_peer_set(
        name: &str,
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<Self, TransportError> {
        Self::create_with_peer_set_and_first_instance(name, peers, true)
    }

    /// Creates an additional instance for a bounded peer set.
    pub fn create_additional_with_peer_set(
        name: &str,
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<Self, TransportError> {
        Self::create_with_peer_set_and_first_instance(name, peers, false)
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
            evidence: None,
        })
    }

    fn create_with_peer_set_and_first_instance(
        name: &str,
        peers: &eliot_platform_windows::NamedPipePeerSet,
        first_pipe_instance: bool,
    ) -> Result<Self, TransportError> {
        use tokio::net::windows::named_pipe::ServerOptions;
        validate_pipe_name(name)?;
        let mut security = PipeSecurityDescriptor::for_peer_set(peers)?;
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
            evidence: None,
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
        self.evidence = Some(evidence);
        Ok(())
    }

    /// Connects, reads the fixed transport preface, and selects exactly one
    /// role from the sealed peer set using observations tied to this pipe
    /// handle. Zero or multiple matches fail closed.
    pub async fn wait_for_authenticated_client_with_peer_set(
        &mut self,
        timeout: Duration,
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<eliot_platform_windows::NamedPipePeerSelection, TransportError> {
        use std::os::windows::io::{AsRawHandle, BorrowedHandle};
        self.wait_for_client(timeout).await?;
        windows_transport::read_authentication_preface(&mut self.inner, timeout).await?;
        let raw = self.inner.as_raw_handle();
        // SAFETY: `self.inner` owns the connected server handle and remains
        // alive for the complete borrowed-handle authentication call.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
        let (evidence, selection) =
            eliot_platform_windows::authenticate_named_pipe_client_with_peer_set(borrowed, peers)
                .map_err(map_platform_error)?;
        self.peer = PeerIdentity::from_platform_evidence(&evidence)?;
        self.evidence = Some(evidence);
        Ok(selection)
    }

    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    /// Selects the exact role only after the platform has sealed live peer
    /// evidence for this connected pipe handle.
    pub fn selected_peer_profile(
        &self,
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<eliot_platform_windows::NamedPipePeerSelection, TransportError> {
        let evidence = self
            .evidence
            .as_ref()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        peers
            .select(evidence)
            .map_err(|_| TransportError::UnauthenticatedPeer)
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

    /// Connects and selects exactly one server role from a sealed peer set.
    /// The client sends the preface only after the server process has been
    /// authenticated from the connected handle.
    pub async fn connect_authenticated_with_peer_set(
        name: &str,
        timeout: Duration,
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<(Self, eliot_platform_windows::NamedPipePeerSelection), TransportError> {
        let mut transport = Self::connect(name, timeout).await?;
        let selection = transport.inner.authenticate_peer_set(peers)?;
        transport.inner.send_authentication_preface(timeout).await?;
        Ok((transport, selection))
    }

    /// Connects to the Kernel front door and proves the live Kernel server
    /// process, exact executable bytes, and bounded front-door DACL before
    /// sending the authentication preface. The opaque platform proof remains
    /// retained by the transport until it is dropped.
    pub async fn connect_authenticated_kernel_front_door(
        name: &str,
        timeout: Duration,
        expectation: &eliot_platform_windows::KernelFrontDoorServerExpectation,
    ) -> Result<Self, TransportError> {
        let mut transport = Self::connect(name, timeout).await?;
        transport
            .inner
            .authenticate_kernel_front_door(expectation)?;
        transport.inner.send_authentication_preface(timeout).await?;
        Ok(transport)
    }

    /// Returns the authenticated provider-neutral peer binding.
    pub fn peer_identity(&self) -> &PeerIdentity {
        self.inner.peer()
    }

    /// Returns the exact extra user SID observed in the Kernel front-door
    /// DACL, when the bounded optional-client contour was used.
    #[must_use]
    pub fn kernel_front_door_observed_extra_sid(&self) -> Option<&str> {
        self.inner.kernel_front_door_observed_extra_sid()
    }

    /// Selects the exact remote role only from retained platform evidence.
    pub fn selected_peer_profile(
        &self,
        peers: &eliot_platform_windows::NamedPipePeerSet,
    ) -> Result<eliot_platform_windows::NamedPipePeerSelection, TransportError> {
        self.inner.selected_peer_profile(peers)
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
        evidence: Option<eliot_platform_windows::NamedPipePeerEvidence>,
        kernel_front_door_proof: Option<eliot_platform_windows::KernelFrontDoorServerProof>,
        kernel_front_door_observed_extra_sid: Option<String>,
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

        pub fn kernel_front_door_observed_extra_sid(&self) -> Option<&str> {
            self.kernel_front_door_observed_extra_sid.as_deref()
        }

        pub fn selected_peer_profile(
            &self,
            peers: &eliot_platform_windows::NamedPipePeerSet,
        ) -> Result<eliot_platform_windows::NamedPipePeerSelection, TransportError> {
            let evidence = self
                .evidence
                .as_ref()
                .ok_or(TransportError::PeerIdentityUnavailable)?;
            peers
                .select(evidence)
                .map_err(|_| TransportError::UnauthenticatedPeer)
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
            self.evidence = Some(evidence);
            Ok(())
        }

        pub fn authenticate_peer_set(
            &mut self,
            peers: &eliot_platform_windows::NamedPipePeerSet,
        ) -> Result<eliot_platform_windows::NamedPipePeerSelection, TransportError> {
            let raw = self.client.as_raw_handle();
            // SAFETY: `self.client` owns this live handle for the duration of
            // the platform adapter call and is not moved or closed here.
            let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
            let (evidence, selection) =
                eliot_platform_windows::authenticate_named_pipe_server_with_peer_set(
                    borrowed, peers,
                )
                .map_err(map_platform_error)?;
            self.peer = PeerIdentity::from_platform_evidence(&evidence)?;
            self.evidence = Some(evidence);
            Ok(selection)
        }

        pub fn authenticate_kernel_front_door(
            &mut self,
            expectation: &eliot_platform_windows::KernelFrontDoorServerExpectation,
        ) -> Result<(), TransportError> {
            let raw = self.client.as_raw_handle();
            // SAFETY: `self.client` owns this live handle for the duration of
            // the platform adapter call and is not moved or closed here.
            let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
            let proof = eliot_platform_windows::authenticate_kernel_front_door_server(
                borrowed,
                expectation,
            )
            .map_err(map_platform_error)?;
            self.peer = PeerIdentity::from_platform_evidence(proof.evidence())?;
            self.evidence = Some(proof.evidence().clone());
            self.kernel_front_door_observed_extra_sid =
                proof.observed_extra_sid().map(str::to_owned);
            self.kernel_front_door_proof = Some(proof);
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
        Ok(Inner {
            client,
            peer,
            evidence: None,
            kernel_front_door_proof: None,
            kernel_front_door_observed_extra_sid: None,
        })
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
    use eliot_protocol::{
        AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID, AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        AGENT_BRIDGE_MODULE_ID, AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID,
        AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentBridgeClientDeclaration,
        AgentBridgePeerChallenge, EncodingProfile, FrameKind, MessageType, ProtocolPayload,
    };
    use std::collections::BTreeMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn module_generation(epoch: u64) -> Result<ModuleGeneration, serde_json::Error> {
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
    fn agent_bridge_session_is_live_until_explicit_fence() -> TestResult {
        let process = ProcessBinding::from_observation(7, 11, "C:/eliot-bridge.exe")?;
        let peer = PeerIdentity::Authenticated {
            process_id: 7,
            user_identity: "S-1-5-21-100-200-300-1001".to_owned(),
            session_identity: "7".to_owned(),
            proof: IdentityProof {
                process,
                sid: "S-1-5-21-100-200-300-1001".to_owned(),
                session: "7".to_owned(),
            },
        };
        let mut session = Session::establish_agent_bridge(
            "agent-bridge:connection-1",
            peer,
            module_generation(7)?,
            "kernel-session-fence-1",
        )?;
        assert!(session.accepts(7, 1));
        session.fence();
        assert!(!session.accepts(7, 1));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn peer_set_dacl_contains_only_sealed_principals() -> TestResult {
        let binding = eliot_platform_windows::observe_named_pipe_peer_process(std::process::id())?;
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?
            .with_process_binding(binding.clone())?;
        let host = eliot_platform_windows::NamedPipePeerProfile::new(
            eliot_platform_windows::NamedPipePeerKind::Host,
            expectation,
            None,
        )?;
        let set = eliot_platform_windows::NamedPipePeerSet::new(vec![host])?;
        let sddl = pipe_security_sddl_for_peer_set(&set);
        assert!(sddl.contains("(A;;GA;;;SY)"));
        assert!(sddl.contains(set.entries()[0].expectation().expected_sid()));
        assert!(!sddl.contains("(A;;GA;;;BA)"));
        assert!(!sddl.contains("(A;;GA;;;LS)"));

        let admin_expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()?
                .with_process_binding(binding)?;
        let admin = eliot_platform_windows::NamedPipePeerProfile::new(
            eliot_platform_windows::NamedPipePeerKind::Host,
            admin_expectation,
            None,
        )?;
        let admin_set = eliot_platform_windows::NamedPipePeerSet::new(vec![admin])?;
        assert!(pipe_security_sddl_for_peer_set(&admin_set).contains("(A;;GA;;;BA)"));
        Ok(())
    }

    fn bridge_declaration() -> Result<AgentBridgeClientDeclaration, ProtocolError> {
        serde_json::from_value::<AgentBridgeClientDeclaration>(serde_json::json!({
            "wire_id": AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID,
            "wire_version": AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
            "module_id": AGENT_BRIDGE_MODULE_ID,
            "profile_id": "agent-bridge-profile-1",
            "protocol_range": {
                "minimum": {"major": 1, "minor": 0},
                "maximum": {"major": 1, "minor": 0}
            },
            "module_contract": {
                "module_id": AGENT_BRIDGE_MODULE_ID,
                "version": {"major": 1, "minor": 0, "patch": 0},
                "artifact_id": "a".repeat(64),
                "protocols": ["eliot.agent-bridge.v1"],
                "required_capabilities": ["agent.bridge.activate"],
                "optional_capabilities": [],
                "advisory_capabilities": [],
                "state_owner": "eliot-host",
                "failure_domain": "agent-bridge",
                "hot_replace": false
            },
            "module_generation": {
                "module_id": AGENT_BRIDGE_MODULE_ID,
                "generation": 1,
                "artifact_id": "a".repeat(64),
                "state": "STARTING",
                "health": {
                    "liveness": "HEALTHY",
                    "readiness": "HEALTHY",
                    "freshness": "HEALTHY",
                    "compatibility": "HEALTHY",
                    "integrity": "HEALTHY",
                    "capacity": "HEALTHY"
                },
                "state_fence": {
                    "authority_epoch": 7,
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                }
            },
            "capabilities": ["agent.bridge.activate"],
            "privacy_classes": ["PUBLIC"],
            "max_frame": 4_194_304,
            "expected_kernel_sid": "S-1-5-18",
            "expected_kernel_session_id": 0,
            "expected_kernel_principal_binding": "kernel:agent-bridge",
            "expected_kernel_authority_epoch": 8,
            "expected_kernel_generation": 2,
            "expected_kernel_artifact_sha256": "b".repeat(64),
            "expected_kernel_config_snapshot_sha256": "c".repeat(64),
            "declaration_sha256": ""
        }))
        .map_err(|error| ProtocolError::Json(error.to_string()))?
        .with_computed_digest()
    }

    fn bridge_challenge(
        declaration: &AgentBridgeClientDeclaration,
    ) -> Result<AgentBridgePeerChallenge, ProtocolError> {
        AgentBridgePeerChallenge {
            wire_id: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: declaration.profile_id.clone(),
            descriptor_sha256: "d".repeat(64),
            client_declaration_sha256: declaration.declaration_sha256.clone(),
            bridge_generation: declaration.module_generation.generation,
            state_fence: declaration.module_generation.state_fence.clone(),
            kernel_principal_binding: declaration.expected_kernel_principal_binding.clone(),
            kernel_authority_epoch: declaration.expected_kernel_authority_epoch,
            kernel_generation: declaration.expected_kernel_generation,
            kernel_artifact_sha256: declaration.expected_kernel_artifact_sha256.clone(),
            kernel_config_snapshot_sha256: declaration
                .expected_kernel_config_snapshot_sha256
                .clone(),
            activation_deadline_unix_ms: 10_000,
            challenge_nonce: "kernel-challenge-1".to_owned(),
            challenge_sha256: String::new(),
        }
        .with_computed_digest()
    }

    #[test]
    fn queue_preserves_control_reserve() -> TestResult {
        let mut queue = AdmissionQueue::new(limits())?;
        let first = queue.admit(8, false)?;
        queue.admit(8, false)?;
        queue.admit(8, false)?;
        assert!(matches!(
            queue.admit(8, false),
            Err(TransportError::Backpressure)
        ));
        queue.admit(8, true)?;
        queue.release(first)?;
        assert_eq!(queue.usage(), (3, 24));
        Ok(())
    }

    #[test]
    fn invalid_limits_and_identity_fail_closed() -> TestResult {
        assert!(AdmissionQueue::new(TransportLimits::default()).is_ok());
        let process = ProcessBinding::from_observation(1, 2, "C:/eliot-test.exe")?;
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
        let valid_process = ProcessBinding::from_observation(7, 11, "C:/eliot-valid.exe")?;
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
        let observed = valid
            .process_binding()
            .ok_or_else(|| std::io::Error::other("valid process evidence missing"))?;
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
        Ok(())
    }

    #[test]
    fn uncertainty_never_becomes_delivery_proof() {
        assert_eq!(classify_disconnect(false), DeliveryOutcome::UnknownOutcome);
        assert_eq!(classify_disconnect(true), DeliveryOutcome::UnknownOutcome);
    }

    #[test]
    fn server_first_challenge_codec_and_one_shot_acceptance() -> TestResult {
        let declaration = bridge_declaration()?;
        let challenge = bridge_challenge(&declaration)?;
        let exchange =
            ServerFirstConnection::new("server-connection", challenge.clone(), &declaration)?;
        let challenge_frame = exchange.challenge_frame()?;
        assert_eq!(
            decode_peer_challenge_frame(&challenge_frame, "server-connection")?,
            challenge
        );
        let hello = declaration.client_hello(challenge.challenge_nonce.clone())?;
        let hello_frame = client_hello_frame("server-connection", &hello)?;
        let mut exchange = exchange;
        assert_eq!(
            exchange.accept_client_hello(&hello_frame, &declaration)?,
            hello
        );
        assert_eq!(exchange.state(), ServerFirstState::Accepted);
        assert_eq!(
            exchange.accept_client_hello(&hello_frame, &declaration),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(exchange.state(), ServerFirstState::Fenced);
        Ok(())
    }

    #[test]
    fn accepted_bridge_state_seals_receipt_from_trusted_peer_and_kernel_deadline() -> TestResult {
        let declaration = bridge_declaration()?;
        let challenge = bridge_challenge(&declaration)?;
        let hello = declaration.client_hello(challenge.challenge_nonce.clone())?;
        let frame = client_hello_frame("server-connection", &hello)?;
        let mut process = ProcessBinding::from_observation(41, 99, r"C:\Eliot\bridge.exe")?;
        process.executable_file = Some((7, 11));
        let peer = PeerIdentity::authenticated_for_test(
            process,
            "S-1-5-21-1000".to_owned(),
            "4".to_owned(),
        )?;
        let mut exchange =
            ServerFirstConnection::new("server-connection", challenge.clone(), &declaration)?;
        let accepted = exchange.accept_client_hello_with_peer(&frame, &declaration, &peer)?;
        assert_eq!(accepted.connection_id(), "server-connection");
        assert_eq!(accepted.challenge(), &challenge);
        assert_eq!(accepted.declaration(), &declaration);
        assert_eq!(accepted.client_hello(), &hello);
        assert_eq!(accepted.peer(), &peer);
        assert_eq!(
            accepted.admission_receipt().connection_id,
            "server-connection"
        );
        assert_eq!(
            accepted.admission_receipt().activation_deadline_unix_ms,
            challenge.activation_deadline_unix_ms
        );
        accepted.admission_receipt().validate()?;

        let receipt_frame = agent_bridge_admission_receipt_frame(
            "server-connection",
            accepted.admission_receipt(),
        )?;
        assert_eq!(receipt_frame.kind, FrameKind::Control);
        assert_eq!(receipt_frame.message_type, MessageType::Ready);
        assert!(receipt_frame.request_id.is_none());
        assert!(receipt_frame.request_identity.is_none());
        assert_eq!(
            decode_agent_bridge_admission_receipt_frame(&receipt_frame, "server-connection")?,
            *accepted.admission_receipt()
        );
        assert_eq!(
            decode_agent_bridge_admission_receipt_frame(&receipt_frame, "other-connection"),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(
            agent_bridge_admission_receipt_frame("other-connection", accepted.admission_receipt()),
            Err(TransportError::SessionFenced)
        );
        let mut bad_digest = receipt_frame.clone();
        if let ProtocolPayload::Json(serde_json::Value::Object(payload)) = &mut bad_digest.payload {
            payload.insert(
                "receipt_sha256".to_owned(),
                serde_json::Value::String("0".repeat(64)),
            );
        }
        assert!(
            decode_agent_bridge_admission_receipt_frame(&bad_digest, "server-connection").is_err()
        );

        let missing_file = PeerIdentity::authenticated_for_test(
            ProcessBinding::from_observation(41, 99, r"C:\Eliot\bridge.exe")?,
            "S-1-5-21-1000".to_owned(),
            "4".to_owned(),
        )?;
        let mut fenced = ServerFirstConnection::new("server-connection", challenge, &declaration)?;
        assert_eq!(
            fenced.accept_client_hello_with_peer(&frame, &declaration, &missing_file),
            Err(TransportError::UnauthenticatedPeer)
        );
        Ok(())
    }

    #[test]
    fn server_first_fences_identity_and_binding_substitutions() -> TestResult {
        let declaration = bridge_declaration()?;
        let challenge = bridge_challenge(&declaration)?;

        let wrong_connection = peer_challenge_frame("other-connection", &challenge)?;
        assert_eq!(
            decode_peer_challenge_frame(&wrong_connection, "server-connection"),
            Err(TransportError::SessionFenced)
        );
        let mut wrong_kind = peer_challenge_frame("server-connection", &challenge)?;
        wrong_kind.kind = FrameKind::Event;
        assert_eq!(
            decode_peer_challenge_frame(&wrong_kind, "server-connection"),
            Err(TransportError::SessionFenced)
        );
        let mut wrong_type = peer_challenge_frame("server-connection", &challenge)?;
        wrong_type.message_type = MessageType::Start;
        assert_eq!(
            decode_peer_challenge_frame(&wrong_type, "server-connection"),
            Err(TransportError::SessionFenced)
        );

        let mut substituted_profile = declaration.clone();
        substituted_profile.profile_id = "other-profile".to_owned();
        substituted_profile.declaration_sha256 = substituted_profile.compute_digest()?;
        let mut exchange =
            ServerFirstConnection::new("server-connection", challenge.clone(), &declaration)?;
        let hello = declaration.client_hello(challenge.challenge_nonce.clone())?;
        let hello_frame = client_hello_frame("server-connection", &hello)?;
        assert_eq!(
            exchange.accept_client_hello(&hello_frame, &substituted_profile),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(exchange.state(), ServerFirstState::Fenced);

        let mut nonce_exchange =
            ServerFirstConnection::new("server-connection", challenge.clone(), &declaration)?;
        let wrong_nonce = declaration.client_hello("different-nonce")?;
        let wrong_nonce_frame = client_hello_frame("server-connection", &wrong_nonce)?;
        assert_eq!(
            nonce_exchange.accept_client_hello(&wrong_nonce_frame, &declaration),
            Err(TransportError::SessionFenced)
        );

        let mut generation_challenge = challenge.clone();
        generation_challenge.bridge_generation = serde_json::from_value(serde_json::json!(2))?;
        generation_challenge = generation_challenge.with_computed_digest()?;
        assert!(
            ServerFirstConnection::new("server-connection", generation_challenge, &declaration)
                .is_err()
        );

        let mut digest_challenge = challenge.clone();
        digest_challenge.client_declaration_sha256 = "e".repeat(64);
        digest_challenge = digest_challenge.with_computed_digest()?;
        assert!(
            ServerFirstConnection::new("server-connection", digest_challenge, &declaration)
                .is_err()
        );

        let mut fence_challenge = challenge.clone();
        fence_challenge.state_fence.authority_epoch = serde_json::from_value(serde_json::json!(8))?;
        fence_challenge = fence_challenge.with_computed_digest()?;
        assert!(
            ServerFirstConnection::new("server-connection", fence_challenge, &declaration).is_err()
        );

        let mut request_id_frame = client_hello_frame("server-connection", &hello)?;
        request_id_frame.request_id = Some(serde_json::from_value(serde_json::json!("request"))?);
        let mut identity_exchange =
            ServerFirstConnection::new("server-connection", challenge, &declaration)?;
        assert_eq!(
            identity_exchange.accept_client_hello(&request_id_frame, &declaration),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(identity_exchange.state(), ServerFirstState::Fenced);

        let mut request_identity_frame = hello_frame;
        request_identity_frame.kind = FrameKind::Request;
        request_identity_frame.request_id =
            Some(serde_json::from_value(serde_json::json!("request"))?);
        let mut identity_exchange = ServerFirstConnection::new(
            "server-connection",
            bridge_challenge(&declaration)?,
            &declaration,
        )?;
        assert_eq!(
            identity_exchange.accept_client_hello(&request_identity_frame, &declaration),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(identity_exchange.state(), ServerFirstState::Fenced);
        Ok(())
    }

    #[test]
    fn server_first_owner_abort_and_fence_are_explicit() -> TestResult {
        let declaration = bridge_declaration()?;
        let challenge = bridge_challenge(&declaration)?;
        let mut aborted =
            ServerFirstConnection::new("server-connection", challenge.clone(), &declaration)?;
        aborted.abort();
        assert_eq!(aborted.state(), ServerFirstState::Aborted);
        let hello = declaration.client_hello(challenge.challenge_nonce.clone())?;
        let hello_frame = client_hello_frame("server-connection", &hello)?;
        assert_eq!(
            aborted.accept_client_hello(&hello_frame, &declaration),
            Err(TransportError::SessionFenced)
        );

        let mut fenced = ServerFirstConnection::new("server-connection", challenge, &declaration)?;
        fenced.fence();
        assert_eq!(fenced.state(), ServerFirstState::Fenced);
        assert_eq!(
            fenced.accept_client_hello(&hello_frame, &declaration),
            Err(TransportError::SessionFenced)
        );
        Ok(())
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
    fn stale_epoch_duplicate_conflict_and_reap_are_explicit() -> TestResult {
        let mut session = Session {
            connection_id: "c".into(),
            protocol_version: ProtocolVersion::CURRENT,
            peer: PeerIdentity::Unavailable {
                reason: PeerIdentityUnavailable::ProviderProofNotComposed,
            },
            authority_epoch: 4,
            module_generation: module_generation(4)?,
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
        assert_eq!(ledger.observe("event", &frame)?, ReplayDisposition::New);
        assert_eq!(
            ledger.observe("event", &frame)?,
            ReplayDisposition::Duplicate
        );
        let mut changed = frame.clone();
        changed.connection_id = "other".into();
        assert_eq!(
            ledger.observe("event", &changed)?,
            ReplayDisposition::Conflict
        );
        let mut cancellation = CancellationRegistry::default();
        cancellation.register("request")?;
        cancellation.cancel("request")?;
        cancellation.reap("request")?;
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
        Ok(())
    }

    #[test]
    fn partial_frame_decoder_recovers_across_reads() -> TestResult {
        let frame = heartbeat();
        let frame_limits = TransportLimits {
            max_frame_bytes: 512,
            queue_capacity: 4,
            queue_bytes: 2048,
            control_reserve: 1,
            operation_timeout: Duration::from_secs(1),
        };
        let wire = encode_frame(&frame, frame_limits)?;
        let split = wire.len() / 2;
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.push(&wire[..split], frame_limits)?, None);
        assert_eq!(decoder.push(&wire[split..], frame_limits)?, Some(frame));
        Ok(())
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
    fn decoder_rejects_oversized_fragment_before_buffer_growth() -> TestResult {
        let mut decoder = FrameDecoder::new();
        let limits = limits();
        let mut fragment = vec![0_u8; 4 + limits.max_frame_bytes + 1];
        fragment[..4].copy_from_slice(&u32::try_from(limits.max_frame_bytes + 1)?.to_le_bytes());
        assert!(matches!(
            decoder.push(&fragment, limits),
            Err(TransportError::Protocol(
                ProtocolError::OversizeFrame { .. }
            ))
        ));
        assert_eq!(decoder.bytes.len(), 0);
        Ok(())
    }

    #[test]
    fn bound_ledgers_reject_conflicts_and_remain_bounded() -> TestResult {
        let key = BoundIdentity::new("stream", module_generation(1)?, "cancel")?;
        let frame = heartbeat();
        let mut replay = ReplayLedger::with_capacity(1)?;
        assert_eq!(
            replay.observe_bound(key.clone(), &frame)?,
            ReplayDisposition::New
        );
        assert_eq!(
            replay.observe_bound(key.clone(), &frame)?,
            ReplayDisposition::Duplicate
        );
        let mut conflict = frame.clone();
        conflict.connection_id = "different".into();
        assert_eq!(
            replay.observe_bound(key.clone(), &conflict)?,
            ReplayDisposition::Conflict
        );
        let mut cancellation = CancellationRegistry::with_capacity(1)?;
        assert_eq!(
            cancellation.register_bound(key.clone(), "request-a")?,
            CancellationDisposition::New
        );
        assert_eq!(
            cancellation.register_bound(key.clone(), "request-b")?,
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
        Ok(())
    }

    #[test]
    fn registry_full_is_distinct_from_conflict_and_preserves_duplicate() -> TestResult {
        let mut ledger = ReplayLedger::with_capacity(1)?;
        let frame = heartbeat();
        let mut conflict = frame.clone();
        conflict.connection_id = "other".into();
        assert_eq!(ledger.observe("first", &frame)?, ReplayDisposition::New);
        assert_eq!(
            ledger.observe("first", &frame)?,
            ReplayDisposition::Duplicate
        );
        assert_eq!(
            ledger.observe("first", &conflict)?,
            ReplayDisposition::Conflict
        );
        assert_eq!(
            ledger.observe("second", &conflict),
            Err(TransportError::RegistryFull)
        );
        assert_eq!(
            ledger.observe("first", &frame)?,
            ReplayDisposition::Duplicate
        );
        Ok(())
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
    async fn real_named_pipe_connect_disconnect_reports_identity_gap() -> TestResult {
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = format!(r"\\.\pipe\eliot\test\{}", std::process::id());
        let server = ServerOptions::new().create(&name)?;
        let server_task = tokio::spawn(async move { server.connect().await });
        let client = NamedPipeTransport::connect(&name, Duration::from_secs(2)).await?;
        let server_result = server_task.await?;
        server_result?;
        assert_eq!(
            client.peer_identity(),
            &PeerIdentity::Unavailable {
                reason: PeerIdentityUnavailable::ProviderProofNotComposed,
            }
        );
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn explicit_acl_pipe_authenticates_handle_bound_server_identity() -> TestResult {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?;
        let name = format!(
            r"\\.\pipe\eliot\authenticated\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let mut server = NamedPipeServer::create(&name, &expectation)?;
        let server_expectation = expectation.clone();
        let server_task = tokio::spawn(async move {
            server
                .wait_for_authenticated_client(Duration::from_secs(2), &server_expectation)
                .await?;
            Ok::<_, TransportError>(server)
        });
        let client =
            NamedPipeTransport::connect_authenticated(&name, Duration::from_secs(2), &expectation)
                .await?;
        let server = server_task.await??;
        assert!(matches!(
            client.peer_identity(),
            PeerIdentity::Authenticated { .. }
        ));
        assert!(matches!(
            server.peer_identity(),
            PeerIdentity::Authenticated { .. }
        ));
        assert_eq!(
            eliot_platform_windows::current_process_named_pipe_expectation()?,
            expectation
        );
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn handle_bound_authentication_rejects_wrong_session() -> TestResult {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?;
        let wrong_session = eliot_platform_windows::NamedPipePeerExpectation::new(
            expectation.expected_sid(),
            expectation.expected_session_id().wrapping_add(1),
        )?;
        let name = format!(
            r"\\.\pipe\eliot\wrong-session\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let server = NamedPipeServer::create(&name, &expectation)?;
        let server_task =
            tokio::spawn(async move { server.wait_for_client(Duration::from_secs(2)).await });
        let result = NamedPipeTransport::connect_authenticated(
            &name,
            Duration::from_secs(2),
            &wrong_session,
        )
        .await;
        let server_result = server_task.await?;
        assert!(server_result.is_ok(), "{server_result:?}");
        assert!(matches!(result, Err(TransportError::UnauthenticatedPeer)));
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn real_named_pipe_partial_frame_is_not_decoded() -> TestResult {
        use tokio::io::AsyncWriteExt;

        let name = format!(r"\\.\pipe\eliot\test-partial\{}", std::process::id());
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?;
        let mut server = NamedPipeServer::create(&name, &expectation)?;
        let server_expectation = expectation.clone();
        let server_task = tokio::spawn(async move {
            server
                .wait_for_authenticated_client(Duration::from_secs(2), &server_expectation)
                .await
                .map_err(|error| error.to_string())?;
            server
                .inner
                .write_all(&[5, 0, 0, 0, b'{'])
                .await
                .map_err(|error| error.to_string())
        });
        let mut client =
            NamedPipeTransport::connect_authenticated(&name, Duration::from_secs(2), &expectation)
                .await?;
        assert!(matches!(
            client.receive_frame(limits()).await,
            Err(TransportError::Protocol(ProtocolError::PartialFrame {
                expected: 5,
                actual: 1,
            }))
        ));
        let server_result = server_task.await?;
        assert!(server_result.is_ok(), "{server_result:?}");
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn server_rejects_wrong_authentication_preface_before_client_authority() -> TestResult {
        use tokio::io::AsyncWriteExt;
        use tokio::net::windows::named_pipe::ClientOptions;

        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?;
        let name = format!(
            r"\\.\pipe\eliot\wrong-preface\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let mut server = NamedPipeServer::create(&name, &expectation)?;
        let client_name = name.clone();
        let client = tokio::spawn(async move {
            let mut client = ClientOptions::new()
                .open(client_name)
                .map_err(|error| error.to_string())?;
            client
                .write_all(b"NOT-ELIO")
                .await
                .map_err(|error| error.to_string())
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
        let client_result = client.await?;
        assert!(client_result.is_ok(), "{client_result:?}");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_pipe_child_process() -> TestResult {
        let Ok(name) = std::env::var("ELIOT_P02_PIPE_CHILD") else {
            return Ok(());
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?;
            let mut transport = NamedPipeTransport::connect_authenticated(
                &name,
                Duration::from_secs(5),
                &expectation,
            )
            .await?;
            assert_eq!(
                transport
                    .send_frame(&heartbeat(), TransportLimits::default())
                    .await,
                Ok(DeliveryOutcome::Delivered)
            );
            assert_eq!(
                transport.receive_frame(TransportLimits::default()).await?,
                heartbeat()
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn server_authenticates_distinct_client_pid_sid_session_and_process() -> TestResult {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()?;
        let name = format!(
            r"\\.\pipe\eliot\client-binding\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let mut server = NamedPipeServer::create(&name, &expectation)?;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("tests::authenticated_pipe_child_process")
            .arg("--nocapture")
            .env("ELIOT_P02_PIPE_CHILD", &name)
            .spawn()?;
        server
            .wait_for_authenticated_client(Duration::from_secs(5), &expectation)
            .await?;
        match server.peer_identity() {
            PeerIdentity::Authenticated {
                process_id, proof, ..
            } => {
                assert_eq!(*process_id, child.id());
                assert_eq!(proof.process.process_id(), child.id());
                assert!(proof.process.start_time_100ns() > 0);
                assert!(!proof.process.image_path().is_empty());
            }
            PeerIdentity::Unavailable { .. } => {
                return Err(std::io::Error::other("client proof must be composed").into());
            }
        }
        assert_eq!(
            server.receive_frame(TransportLimits::default()).await?,
            heartbeat()
        );
        assert_eq!(
            server
                .send_frame(&heartbeat(), TransportLimits::default())
                .await,
            Ok(DeliveryOutcome::Delivered)
        );
        assert!(child.wait()?.success());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn kernel_front_door_authenticated_child() -> TestResult {
        let Ok(name) = std::env::var("ELIOT_KERNEL_FRONT_DOOR_PIPE") else {
            return Ok(());
        };
        let server_sid = std::env::var("ELIOT_KERNEL_FRONT_DOOR_SERVER_SID")?;
        let server_session =
            std::env::var("ELIOT_KERNEL_FRONT_DOOR_SERVER_SESSION")?.parse::<u32>()?;
        let artifact = std::env::var("ELIOT_KERNEL_FRONT_DOOR_ARTIFACT")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let expectation = eliot_platform_windows::KernelFrontDoorServerExpectation::new(
                server_sid,
                server_session,
                artifact,
                eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient,
            )?;
            let transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
                &name,
                Duration::from_secs(5),
                &expectation,
            )
            .await?;
            assert!(transport.kernel_front_door_observed_extra_sid().is_some());
            match transport.peer_identity() {
                PeerIdentity::Authenticated { proof, .. } => {
                    assert!(proof.process.executable_file_identity().is_some());
                }
                PeerIdentity::Unavailable { .. } => {
                    return Err(std::io::Error::other("Kernel proof was not retained").into());
                }
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn kernel_front_door_live_proof_retains_process_file_and_extra_sid() -> TestResult {
        let current = eliot_platform_windows::current_process_named_pipe_expectation()?;
        if current.expected_session_id() == 0 {
            return Ok(());
        }
        let image = std::env::current_exe()?;
        let image_text = image.to_string_lossy().into_owned();
        let executable_file = eliot_platform_windows::file_identity_for_path(&image)?;
        let bridge_expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_dynamic_process(
                current.expected_sid(),
                image_text,
                executable_file,
            )?;
        let bridge = eliot_platform_windows::NamedPipePeerProfile::new(
            eliot_platform_windows::NamedPipePeerKind::AgentBridge,
            bridge_expectation,
            Some("test-front-door".to_owned()),
        )?;
        // The synthetic LS role contributes the service ACE to the DACL but
        // cannot match the current-user child, keeping selection unambiguous.
        let process = eliot_platform_windows::observe_named_pipe_peer_process(std::process::id())?;
        let local_service =
            eliot_platform_windows::NamedPipePeerExpectation::new_with_process_binding(
                "S-1-5-19", 0, process,
            )?;
        let service = eliot_platform_windows::NamedPipePeerProfile::new(
            eliot_platform_windows::NamedPipePeerKind::Eliotd,
            local_service,
            None,
        )?;
        let peers = eliot_platform_windows::NamedPipePeerSet::new(vec![bridge, service])?;
        let name = format!(
            r"\\.\pipe\eliot\kernel-front-door-test\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let mut server = NamedPipeServer::create_with_peer_set(&name, &peers)?;
        let artifact =
            eliot_platform_windows::sha256_hex(&std::fs::read(std::env::current_exe()?)?);
        let server_sid = current.expected_sid().to_owned();
        let server_session = current.expected_session_id().to_string();
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("tests::kernel_front_door_authenticated_child")
            .arg("--nocapture")
            .env("ELIOT_KERNEL_FRONT_DOOR_PIPE", &name)
            .env("ELIOT_KERNEL_FRONT_DOOR_SERVER_SID", server_sid)
            .env("ELIOT_KERNEL_FRONT_DOOR_SERVER_SESSION", server_session)
            .env("ELIOT_KERNEL_FRONT_DOOR_ARTIFACT", artifact)
            .spawn()?;
        let selection = server
            .wait_for_authenticated_client_with_peer_set(Duration::from_secs(5), &peers)
            .await?;
        assert_eq!(
            selection.kind(),
            eliot_platform_windows::NamedPipePeerKind::AgentBridge
        );
        assert!(server.peer_identity().validate().is_ok());
        assert!(child.wait()?.success());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn installer_control_pipe_dacl_binds_admin_client_and_local_service_host() -> TestResult {
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()?;
        assert_eq!(
            pipe_security_sddl(&expectation),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn kernel_front_door_transport_surface_is_distinct_and_retains_extra_sid_accessor() {
        let specialized = NamedPipeTransport::connect_authenticated_kernel_front_door;
        let generic = NamedPipeTransport::connect_authenticated;
        let extra_sid = NamedPipeTransport::kernel_front_door_observed_extra_sid;
        let _ = (specialized, generic, extra_sid);
    }
}
