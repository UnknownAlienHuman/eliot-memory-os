//! Authenticated local Kernel front-door client shared by Stage 7 surfaces.
//!
//! This client owns only the protected connection declaration and EBP peer,
//! handshake, request, and response bindings. Callers own operation-specific
//! payload and receipt contracts.

#[cfg(windows)]
use std::time::Duration;

use eliot_contracts::{EpochId, RequestId, sha256_hex};
use eliot_platform_windows::NamedPipePeerExpectation;
#[cfg(windows)]
use eliot_platform_windows::{ProtectedPathLease, protected_program_data_path};
#[cfg(windows)]
use eliot_protocol::EncodingProfile;
use eliot_protocol::{
    ClientHello, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion, RequestIdentity,
    ServerHello,
};
use serde::Deserialize;
use serde_json::Value;
#[cfg(windows)]
use serde_json::json;
use thiserror::Error;

#[cfg(windows)]
const KERNEL_FRONT_DOOR_PIPE: &str = r"\\.\pipe\eliot\kernel\frontdoor";
#[cfg(windows)]
const CONFIG_RELATIVE_PATH: &str = "Eliot/kernel/application-client.json";
#[cfg(windows)]
const CONFIG_LIMIT: u64 = 64 * 1024;
const OPERATION_LIMIT: usize = 160;
const KERNEL_SERVICE_NAME: &str = "eliot-kernel";
const KERNEL_PROTOCOL_VERSION: &str = "eliot.kernel.v1";

/// Protected installation-provided connection declaration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelClientConfig {
    /// Stable connection identity assigned by the Kernel owner.
    pub connection_id: String,
    /// SID of the Kernel service process expected at the pipe peer.
    pub expected_kernel_sid: String,
    /// Session id of the Kernel service process expected at the pipe peer.
    pub expected_kernel_session_id: u32,
    /// Exact client handshake declaration approved for this installation.
    pub client_hello: ClientHello,
    /// SHA-256 of canonical JSON `client_hello` bytes from the approved
    /// installation manifest.
    pub client_hello_sha256: String,
    /// Protected principal binding selected by the Kernel owner.
    pub expected_server_principal_binding: String,
    /// Protected authority epoch for the configured module generation.
    pub expected_authority_epoch: EpochId,
    /// Numeric identity of the expected immutable module generation.
    pub expected_generation: u64,
    /// Digest/identity of the expected server artifact.
    pub expected_artifact_digest: String,
    /// SHA-256 of the exact canonical JSON `ServerHello.config_snapshot`.
    pub expected_config_snapshot_sha256: String,
}

/// Failure at the authenticated application front door.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelClientError {
    /// No protected front-door configuration is available on this host.
    #[error("kernel application front door is closed: {0}")]
    FrontDoorClosed(&'static str),
    /// The protected configuration or operation was rejected locally.
    #[error("kernel client configuration rejected: {0}")]
    Configuration(String),
    /// A request lacked the exact EBP identity required by the gateway.
    #[error("kernel request identity is missing")]
    MissingRequestIdentity,
    /// The authenticated provider rejected or fenced the operation.
    #[error("kernel front door rejected the request: {0}")]
    Rejected(String),
    /// The request may have reached the provider, but its outcome was not
    /// proven by an exact typed reply and must be reconciled by operation.
    #[error("kernel front door outcome is unknown: {0}")]
    UnknownOutcome(String),
}

/// Authenticated client for the installation-owned Kernel front door.
///
/// A new pipe session is established for each operation. The client does not
/// mint request identity and does not interpret operation-specific JSON.
pub struct KernelClient {
    config: KernelClientConfig,
    request_identity: Option<RequestIdentity>,
    #[cfg(windows)]
    config_lease: ProtectedPathLease,
}

/// In-process result returned only after the protected Kernel peer,
/// `ServerHello`, and exact Execute response bindings have been validated.
///
/// This carrier intentionally has no serialization or public constructor. Its
/// operation and original request identity are retained alongside the
/// operation payload so a downstream authority boundary can require the
/// authenticated client result instead of accepting caller-created JSON.
#[derive(Debug, PartialEq)]
pub struct AuthenticatedKernelResponse {
    operation: String,
    request_identity: RequestIdentity,
    payload: Value,
}

impl AuthenticatedKernelResponse {
    fn after_verified_exchange(
        operation: String,
        request_identity: RequestIdentity,
        payload: Value,
    ) -> Self {
        Self {
            operation,
            request_identity,
            payload,
        }
    }

    /// Operation selector sent over the authenticated Kernel connection.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Exact caller identity carried by the request whose response was
    /// authenticated.
    pub const fn request_identity(&self) -> &RequestIdentity {
        &self.request_identity
    }

    /// Validated JSON payload from the exact typed Kernel response frame.
    pub const fn payload(&self) -> &Value {
        &self.payload
    }
}

impl KernelClient {
    /// Loads the installation-owned protected client declaration.
    pub fn load() -> Result<Self, KernelClientError> {
        #[cfg(not(windows))]
        {
            Err(KernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door",
            ))
        }
        #[cfg(windows)]
        {
            let path = protected_program_data_path(CONFIG_RELATIVE_PATH)
                .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
            let lease = ProtectedPathLease::open_existing_absolute(&path)
                .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
            let bytes = lease
                .read_bounded(CONFIG_LIMIT)
                .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
            let config: KernelClientConfig = serde_json::from_slice(&bytes).map_err(|error| {
                KernelClientError::Configuration(format!(
                    "decode Kernel client configuration: {error}"
                ))
            })?;
            validate_config(&config)?;
            Ok(Self {
                config,
                request_identity: None,
                config_lease: lease,
            })
        }
    }

    /// Binds the exact caller identity for the next application request.
    pub fn set_request_identity(&mut self, identity: RequestIdentity) {
        self.request_identity = Some(identity);
    }

    /// Performs a bounded authenticated health exchange with Kernel.
    pub fn probe(&mut self) -> Result<Value, KernelClientError> {
        #[cfg(not(windows))]
        {
            Err(KernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door",
            ))
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
            runtime.block_on(self.probe_async())
        }
    }

    /// Sends one exact provider operation through the authenticated EBP
    /// Execute seam. The operation string is a contract selector, not local
    /// command authority.
    pub fn transact_json(
        &mut self,
        operation: &str,
        payload: Value,
    ) -> Result<Value, KernelClientError> {
        self.transact_json_authenticated(operation, payload)
            .map(|response| response.payload)
    }

    /// Performs one authenticated Execute exchange and retains the
    /// non-serializable proof carrier for the caller's consuming authority
    /// boundary.
    pub fn transact_json_authenticated(
        &mut self,
        operation: &str,
        payload: Value,
    ) -> Result<AuthenticatedKernelResponse, KernelClientError> {
        validate_operation(operation)?;
        let identity = self
            .request_identity
            .clone()
            .ok_or(KernelClientError::MissingRequestIdentity)?;
        #[cfg(not(windows))]
        {
            let _ = (identity, payload);
            Err(KernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door",
            ))
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
            runtime.block_on(self.transact_json_authenticated_async(operation, payload, identity))
        }
    }

    /// Asynchronous authenticated health exchange.
    pub async fn probe_async(&self) -> Result<Value, KernelClientError> {
        #[cfg(not(windows))]
        {
            Err(KernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door",
            ))
        }
        #[cfg(windows)]
        {
            let (mut transport, limits) = self.connect().await?;
            let frame = Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: EncodingProfile::JsonV1,
                connection_id: self.config.connection_id.clone(),
                request_id: None,
                kind: FrameKind::Heartbeat,
                message_type: MessageType::Health,
                request_identity: None,
                payload: ProtocolPayload::Json(json!({"status": "probe"})),
                trace_context: std::collections::BTreeMap::new(),
            };
            require_delivery(
                transport.send_frame(&frame, limits).await,
                "Kernel health probe",
            )?;
            let response = transport
                .receive_frame(limits)
                .await
                .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
            validate_health_response(&self.config.connection_id, &response)
        }
    }

    /// Asynchronous authenticated Execute operation using the caller's exact
    /// admitted request identity.
    pub async fn transact_json_async(
        &self,
        operation: &str,
        payload: Value,
        identity: RequestIdentity,
    ) -> Result<Value, KernelClientError> {
        self.transact_json_authenticated_async(operation, payload, identity)
            .await
            .map(|response| response.payload)
    }

    /// Asynchronous authenticated Execute exchange retaining the exact
    /// operation and request identity in a non-serializable result carrier.
    pub async fn transact_json_authenticated_async(
        &self,
        operation: &str,
        payload: Value,
        identity: RequestIdentity,
    ) -> Result<AuthenticatedKernelResponse, KernelClientError> {
        validate_operation(operation)?;
        identity.validate().map_err(|error| {
            KernelClientError::Configuration(format!("Kernel request identity is invalid: {error}"))
        })?;
        #[cfg(not(windows))]
        {
            let _ = (payload, identity);
            Err(KernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door",
            ))
        }
        #[cfg(windows)]
        {
            let (mut transport, limits) = self.connect().await?;
            let request_id = identity.request.metadata.request_id.clone();
            let frame = Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: EncodingProfile::JsonV1,
                connection_id: self.config.connection_id.clone(),
                request_id: Some(request_id.clone()),
                kind: FrameKind::Request,
                message_type: MessageType::Execute,
                request_identity: Some(identity.clone()),
                payload: ProtocolPayload::Json(json!({"operation": operation, "payload": payload})),
                trace_context: std::collections::BTreeMap::new(),
            };
            require_delivery(
                transport.send_frame(&frame, limits).await,
                "Kernel application request",
            )?;
            let response = transport
                .receive_frame(limits)
                .await
                .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
            let payload =
                validate_result_response(&self.config.connection_id, &request_id, &response)?;
            Ok(AuthenticatedKernelResponse::after_verified_exchange(
                operation.to_owned(),
                identity,
                payload,
            ))
        }
    }

    #[cfg(windows)]
    async fn connect(
        &self,
    ) -> Result<(crate::NamedPipeTransport, crate::TransportLimits), KernelClientError> {
        self.config_lease
            .verify_stable_identity()
            .and_then(|()| self.config_lease.verify_path_identity())
            .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
        let expectation = NamedPipePeerExpectation::new(
            &self.config.expected_kernel_sid,
            self.config.expected_kernel_session_id,
        )
        .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
        let mut transport = crate::NamedPipeTransport::connect_authenticated(
            KERNEL_FRONT_DOOR_PIPE,
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
        let limits = crate::TransportLimits::default();
        let hello =
            crate::client_hello_frame(&self.config.connection_id, &self.config.client_hello)
                .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
        require_delivery(
            transport.send_frame(&hello, limits).await,
            "Kernel client hello",
        )?;
        let server = transport
            .receive_frame(limits)
            .await
            .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
        let hello = crate::decode_server_hello_frame(&server, &self.config.connection_id)
            .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
        validate_server_hello(&self.config, &hello)?;
        Ok((transport, limits))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KernelConfigSnapshot {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: EpochId,
    artifact_digest: String,
}

fn validate_config(config: &KernelClientConfig) -> Result<(), KernelClientError> {
    if config.connection_id.trim().is_empty() || config.connection_id.chars().any(char::is_control)
    {
        return Err(KernelClientError::Configuration(
            "Kernel connection identity is invalid".to_owned(),
        ));
    }
    if config.expected_kernel_sid.trim().is_empty()
        || config.expected_kernel_sid.chars().any(char::is_control)
    {
        return Err(KernelClientError::Configuration(
            "Kernel service SID is invalid".to_owned(),
        ));
    }
    NamedPipePeerExpectation::new(
        &config.expected_kernel_sid,
        config.expected_kernel_session_id,
    )
    .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
    config
        .client_hello
        .validate()
        .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
    validate_digest(&config.client_hello_sha256, "Kernel client hello digest")?;
    let hello_bytes = serde_json::to_vec(&config.client_hello)
        .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
    if !config
        .client_hello_sha256
        .eq_ignore_ascii_case(&sha256_hex(&hello_bytes))
    {
        return Err(KernelClientError::Configuration(
            "Kernel client hello digest does not match approved bytes".to_owned(),
        ));
    }
    if config.expected_server_principal_binding.trim().is_empty()
        || config
            .expected_server_principal_binding
            .chars()
            .any(char::is_control)
        || config.expected_artifact_digest.trim().is_empty()
    {
        return Err(KernelClientError::Configuration(
            "Kernel server binding declaration is invalid".to_owned(),
        ));
    }
    validate_digest(&config.expected_artifact_digest, "Kernel artifact digest")?;
    if config.expected_generation == 0 {
        return Err(KernelClientError::Configuration(
            "Kernel server binding digest/epoch is invalid".to_owned(),
        ));
    }
    validate_digest(
        &config.expected_config_snapshot_sha256,
        "Kernel config snapshot digest",
    )
}

fn validate_digest(digest: &str, label: &str) -> Result<(), KernelClientError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KernelClientError::Configuration(format!(
            "{label} is invalid"
        )));
    }
    Ok(())
}

fn validate_server_hello(
    config: &KernelClientConfig,
    hello: &ServerHello,
) -> Result<(), KernelClientError> {
    hello
        .validate()
        .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
    if hello.rejection_reason.is_some()
        || hello.selected_protocol != ProtocolVersion::CURRENT
        || hello.session_principal_binding != config.expected_server_principal_binding
        || !hello
            .authority_epoch
            .is_same_authority(&config.expected_authority_epoch)
    {
        return Err(KernelClientError::Rejected(
            "Kernel ServerHello is not bound to the protected authority".to_owned(),
        ));
    }
    validate_server_snapshot(
        hello,
        &config.expected_authority_epoch,
        config.expected_generation,
        &config.expected_artifact_digest,
    )?;
    let snapshot_bytes = serde_json::to_vec(&hello.config_snapshot)
        .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
    if !config
        .expected_config_snapshot_sha256
        .eq_ignore_ascii_case(&sha256_hex(&snapshot_bytes))
    {
        return Err(KernelClientError::Rejected(
            "Kernel ServerHello configuration snapshot digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_server_snapshot(
    hello: &ServerHello,
    expected_authority_epoch: &EpochId,
    expected_generation: u64,
    expected_artifact_digest: &str,
) -> Result<(), KernelClientError> {
    let snapshot: KernelConfigSnapshot = serde_json::from_value(hello.config_snapshot.clone())
        .map_err(|error| {
            KernelClientError::Rejected(format!(
                "Kernel ServerHello configuration snapshot shape is invalid: {error}"
            ))
        })?;
    if snapshot.service != KERNEL_SERVICE_NAME
        || snapshot.protocol != KERNEL_PROTOCOL_VERSION
        || snapshot.generation == 0
        || snapshot.generation != expected_generation
        || !snapshot
            .authority_epoch
            .is_same_authority(expected_authority_epoch)
        || !hello
            .authority_epoch
            .is_same_authority(&snapshot.authority_epoch)
        || snapshot.artifact_digest.len() != 64
        || !snapshot
            .artifact_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || snapshot.artifact_digest != expected_artifact_digest
    {
        return Err(KernelClientError::Rejected(
            "Kernel ServerHello generation/authority/artifact binding mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_health_response(
    connection_id: &str,
    response: &Frame,
) -> Result<Value, KernelClientError> {
    response
        .validate()
        .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
    if response.protocol_version != ProtocolVersion::CURRENT
        || response.connection_id != connection_id
        || response.kind != FrameKind::Heartbeat
        || response.message_type != MessageType::Health
        || response.request_id.is_some()
        || response.request_identity.is_some()
    {
        return Err(KernelClientError::UnknownOutcome(
            "Kernel health reply binding mismatch".to_owned(),
        ));
    }
    match &response.payload {
        ProtocolPayload::Json(value) if value.get("rejection_reason").is_none() => {
            Ok(value.clone())
        }
        ProtocolPayload::Json(_) => Err(KernelClientError::Rejected(
            "Kernel health reply was rejected".to_owned(),
        )),
        _ => Err(KernelClientError::UnknownOutcome(
            "Kernel health response was not typed JSON".to_owned(),
        )),
    }
}

fn validate_result_response(
    connection_id: &str,
    request_id: &RequestId,
    response: &Frame,
) -> Result<Value, KernelClientError> {
    response
        .validate()
        .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
    if response.protocol_version != ProtocolVersion::CURRENT
        || response.connection_id != connection_id
        || response.request_id.as_ref() != Some(request_id)
        || response.kind != FrameKind::Response
        || response.message_type != MessageType::Result
        || response.request_identity.is_some()
    {
        return Err(KernelClientError::UnknownOutcome(
            "Kernel result reply binding mismatch".to_owned(),
        ));
    }
    match &response.payload {
        ProtocolPayload::Json(value) if value.get("rejection_reason").is_none() => {
            Ok(value.clone())
        }
        ProtocolPayload::Json(_) => Err(KernelClientError::Rejected(
            "Kernel result reply was rejected".to_owned(),
        )),
        _ => Err(KernelClientError::UnknownOutcome(
            "Kernel result response was not typed JSON".to_owned(),
        )),
    }
}

fn validate_operation(operation: &str) -> Result<(), KernelClientError> {
    if operation.trim().is_empty()
        || operation.len() > OPERATION_LIMIT
        || operation.chars().any(char::is_control)
    {
        return Err(KernelClientError::Configuration(
            "Kernel operation selector is invalid".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_delivery(
    result: Result<crate::DeliveryOutcome, crate::TransportError>,
    operation: &str,
) -> Result<(), KernelClientError> {
    match result {
        Ok(crate::DeliveryOutcome::Delivered) => Ok(()),
        Ok(crate::DeliveryOutcome::UnknownOutcome) => Err(KernelClientError::UnknownOutcome(
            format!("{operation} delivery outcome is unknown"),
        )),
        Err(error) => Err(KernelClientError::UnknownOutcome(format!(
            "{operation}: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use eliot_protocol::EncodingProfile;
    use serde_json::json;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440001";
    const FRONT_DOOR: &str = r"\\.\pipe\eliot\kernel\frontdoor";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn server_hello(snapshot: Value) -> ServerHello {
        ServerHello {
            selected_protocol: ProtocolVersion::CURRENT,
            session_principal_binding: "local-user".to_owned(),
            allowed_capabilities: vec!["interactive-user-broker".to_owned()],
            allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
            config_snapshot: snapshot,
            heartbeat_ms: 1_000,
            control_channel: FRONT_DOOR.to_owned(),
            rejection_reason: None,
            authority_epoch: test_epoch(7),
        }
    }

    fn snapshot() -> Value {
        json!({
            "service": KERNEL_SERVICE_NAME,
            "protocol": KERNEL_PROTOCOL_VERSION,
            "generation": 11,
            "authority_epoch": {"lineage_id": TEST_LINEAGE, "sequence": 7},
            "artifact_digest": "a".repeat(64),
        })
    }

    fn result_frame(connection_id: &str, request_id: RequestId, payload: Value) -> Frame {
        Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.to_owned(),
            request_id: Some(request_id),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(payload),
            trace_context: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn server_hello_accepts_original_protected_generation_and_artifact() {
        assert_eq!(
            validate_server_snapshot(
                &server_hello(snapshot()),
                &test_epoch(7),
                11,
                &"a".repeat(64)
            ),
            Ok(())
        );
    }

    #[test]
    fn server_hello_refuses_foreign_peer_authority_or_artifact() {
        let hello = server_hello(snapshot());
        let foreign = EpochId::new(
            EpochLineageId::new(OTHER_LINEAGE).expect("valid foreign lineage"),
            NonZeroU64::new(7).expect("nonzero foreign epoch"),
        )
        .expect("valid foreign epoch");
        assert!(validate_server_snapshot(&hello, &foreign, 11, &"a".repeat(64)).is_err());
        assert!(validate_server_snapshot(&hello, &test_epoch(7), 11, &"b".repeat(64)).is_err());
        assert!(validate_server_snapshot(&hello, &test_epoch(7), 12, &"a".repeat(64)).is_err());
    }

    #[test]
    fn result_response_accepts_exact_request_frame_and_payload() {
        let request_id = RequestId::new("request-kernel-client-1814").expect("request id");
        let response = result_frame("kernel-connection", request_id.clone(), json!({"ok": true}));

        assert_eq!(
            validate_result_response("kernel-connection", &request_id, &response),
            Ok(json!({"ok": true})),
        );
    }

    #[test]
    fn result_response_refuses_substituted_identity_and_kernel_rejection() {
        let request_id = RequestId::new("request-kernel-client-1814").expect("request id");
        let other_id = RequestId::new("request-kernel-client-other").expect("other request id");
        let substituted = result_frame("kernel-connection", other_id, json!({"ok": true}));
        assert!(matches!(
            validate_result_response("kernel-connection", &request_id, &substituted),
            Err(KernelClientError::UnknownOutcome(_))
        ));

        let rejected = result_frame(
            "kernel-connection",
            request_id.clone(),
            json!({"rejection_reason": "fenced"}),
        );
        assert_eq!(
            validate_result_response("kernel-connection", &request_id, &rejected),
            Err(KernelClientError::Rejected(
                "Kernel result reply was rejected".to_owned()
            )),
        );
    }
}
