//! Authenticated Kernel front-door client for one bounded research-provider
//! operation.
//!
//! I21.11: "Endpoint reachability or a successful login proves neither source
//! coverage nor permission to disclose a bundle." Accordingly this client
//! treats a connected pipe and a `200`-shaped reply as transport facts only:
//! the single value it can return is a
//! [`ResearchProviderDispatchReceipt`] that has passed the wire owner's
//! `validate` **and** `verify_echo` against the exact dispatch this process
//! holds. A receipt that fails either check is a typed refusal carrying the
//! exact I7.20 reason code, never an admission.
//!
//! Dependency note (issue #24 boundary audit): this client is composed from
//! the narrowest owner crates the front door is built from — `eliot-ipc` for
//! the named-pipe transport and handshake frames, `eliot-protocol` for the
//! EBP frame/request identity, and `eliot-platform-windows` for the protected
//! installation declaration — plus `eliot-kernel-service` for the research
//! wire contract. It deliberately does **not** depend on `eliot-cli`: that
//! crate's `eliot-bootstrap` edge reaches the `eliot-agent-` closure, which
//! `config/architecture-boundaries.toml` forbids for this runtime root. The
//! transport primitives used here are the very same owner primitives
//! `eliot_cli::kernel_client` uses (`NamedPipeTransport::connect_authenticated`,
//! `client_hello_frame`, `decode_server_hello_frame`, `TransportLimits`).
//!
//! No environment variable selects an executable, a pipe, or a peer here: the
//! pipe name is the frozen Kernel front-door constant and the peer expectation
//! comes from the protected installation declaration under a
//! `ProtectedPathLease`.

use std::time::Duration;

use eliot_contracts::{
    ClockReading, EpochId, ProductId, RequestId, ResourceGeneration, SourceId, StateFence,
};
use eliot_ipc::{
    NamedPipeTransport, TransportLimits, client_hello_frame, decode_server_hello_frame,
};
use eliot_kernel_service::{
    RESEARCH_PROVIDER_CANCEL_OPERATION, RESEARCH_PROVIDER_DISPATCH_OPERATION,
    RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION, RESEARCH_PROVIDER_RECONCILE_OPERATION,
    RESEARCH_PROVIDER_STATUS_OPERATION, RESEARCH_PROVIDER_WIRE_ID, ResearchProviderDispatch,
    ResearchProviderDispatchReceipt, ResearchProviderError,
};
use eliot_platform_windows::{
    NamedPipePeerExpectation, ProtectedPathLease, protected_program_data_path,
};
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity, ServerHello,
};
use eliot_receipts::RequestBinding;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch_authority::unix_ms;

/// Canonical authenticated Kernel front-door pipe.
const KERNEL_FRONT_DOOR_PIPE: &str = r"\\.\pipe\eliot\kernel\frontdoor";
/// Protected installation-provided connection declaration.
const CONFIG_RELATIVE_PATH: &str = "Eliot/kernel/application-client.json";
/// Maximum bytes read from the protected declaration.
const CONFIG_LIMIT: u64 = 64 * 1024;
/// Bounded connect/handshake window.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Product/source identity this process presents.
const SERVICE_NAME: &str = "eliot-mod-research";

/// Failure at the authenticated application front door.
///
/// Every variant carries the exact I7.20 `reason_code` a caller must report,
/// so a degraded Kernel never collapses into prose.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResearchKernelClientError {
    /// The front door is closed, unreachable, or refused the handshake.
    #[error("kernel application front door is closed: {0}")]
    FrontDoorClosed(String),
    /// The protected installation declaration was rejected locally.
    #[error("kernel client configuration rejected: {0}")]
    Configuration(String),
    /// The authenticated owner fenced or rejected the operation.
    #[error("kernel front door rejected the research dispatch: {0}")]
    Rejected(String),
    /// The owner returned a receipt that does not verify against this
    /// process's own dispatch, so it is not an admission.
    #[error("kernel receipt did not verify for {reason_code}: {detail}")]
    UnverifiedReceipt {
        /// Exact I7.20 reason code for the refusal.
        reason_code: &'static str,
        /// Bounded detail of what failed to echo.
        detail: String,
    },
    /// The request may have reached the Kernel; its outcome is unproven and
    /// must be reconciled by the stable operation identity.
    #[error("kernel research dispatch outcome is unknown: {0}")]
    UnknownOutcome(String),
}

impl ResearchKernelClientError {
    /// Returns the exact I7.20 `reason_code` for this failure.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::FrontDoorClosed(_) => eliot_kernel_service::REASON_CAPABILITY_UNAVAILABLE,
            Self::Configuration(_) => eliot_kernel_service::REASON_INVALID_ARGUMENT,
            Self::Rejected(_) => eliot_kernel_service::REASON_IDENTITY_CONFLICT,
            Self::UnverifiedReceipt { reason_code, .. } => reason_code,
            Self::UnknownOutcome(_) => eliot_kernel_service::REASON_UNKNOWN_OUTCOME,
        }
    }

    /// Returns whether the outcome must be reconciled by operation identity
    /// before any retry. An unproven delivery is never a blind retry.
    #[must_use]
    pub const fn requires_reconciliation(&self) -> bool {
        matches!(self, Self::UnknownOutcome(_))
    }
}

/// Protected installation-provided connection declaration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchClientDeclaration {
    connection_id: String,
    expected_kernel_sid: String,
    expected_kernel_session_id: u32,
    client_hello: ClientHello,
    client_hello_sha256: String,
    expected_server_principal_binding: String,
    expected_authority_epoch: EpochId,
    expected_generation: u64,
    expected_artifact_digest: String,
    expected_config_snapshot_sha256: String,
}

/// Exact server-owned configuration snapshot carried by `ServerHello`.
///
/// The `service` and `protocol` spellings are part of the closed snapshot
/// shape, so they are decoded and compared rather than ignored: a Kernel
/// serving a different service or protocol line is not the owner this
/// declaration admits.
#[cfg(windows)]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfigSnapshot {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: EpochId,
    artifact_digest: String,
}

/// The service identity the Kernel front door must present.
#[cfg(windows)]
const KERNEL_SERVICE_NAME: &str = "eliot-kernel";
/// The protocol identity the Kernel front door must present.
#[cfg(windows)]
const KERNEL_PROTOCOL_VERSION: &str = "eliot.kernel.v1";

/// One short-lived authenticated session against the Kernel front door.
///
/// It is intentionally not a durable authority token and reconnects for each
/// operation. It holds no research semantics: it moves one owner-typed
/// envelope out and one owner-typed receipt back.
pub struct ResearchKernelClient {
    declaration: ResearchClientDeclaration,
    #[cfg(windows)]
    lease: ProtectedPathLease,
    request_sequence: std::sync::atomic::AtomicU64,
}

impl ResearchKernelClient {
    /// Loads the installation-owned protected client declaration under a
    /// bounded lease.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchKernelClientError::Configuration`] when no protected
    /// declaration exists or its shape is not the admitted one. A missing
    /// declaration is a closed front door, never a fallback to a default pipe
    /// peer or a caller-supplied identity.
    pub fn load() -> Result<Self, ResearchKernelClientError> {
        #[cfg(not(windows))]
        {
            Err(ResearchKernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door".to_owned(),
            ))
        }
        #[cfg(windows)]
        {
            let path = protected_program_data_path(CONFIG_RELATIVE_PATH)
                .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
            let lease = ProtectedPathLease::open_existing_absolute(&path)
                .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
            let bytes = lease
                .read_bounded(CONFIG_LIMIT)
                .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
            let declaration: ResearchClientDeclaration =
                serde_json::from_slice(&bytes).map_err(|error| {
                    ResearchKernelClientError::Configuration(format!(
                        "decode Kernel client declaration: {error}"
                    ))
                })?;
            validate_declaration(&declaration)?;
            Ok(Self {
                declaration,
                lease,
                request_sequence: std::sync::atomic::AtomicU64::new(0),
            })
        }
    }

    /// Dispatches one bounded research-provider request and returns the
    /// verified Kernel receipt.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the front door is closed, when the owner
    /// fences or rejects the request, or when the returned receipt does not
    /// verify against the presented dispatch. A delivery whose response was
    /// never received returns
    /// [`ResearchKernelClientError::UnknownOutcome`], which the caller must
    /// reconcile by the stable operation identity rather than retry.
    pub fn dispatch(
        &self,
        dispatch: &ResearchProviderDispatch,
        operation: &str,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchKernelClientError> {
        let payload = json!({
            "wire_id": RESEARCH_PROVIDER_WIRE_ID,
            "wire_version": RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION,
            "operation": operation,
            "dispatch": dispatch,
        });
        self.transact(dispatch, &payload)
    }

    /// Requests the terminal classification of one admitted operation.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal exactly as [`ResearchKernelClient::dispatch`]
    /// does.
    pub fn status(
        &self,
        dispatch: &ResearchProviderDispatch,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchKernelClientError> {
        self.dispatch(dispatch, RESEARCH_PROVIDER_STATUS_OPERATION)
    }

    /// Requests cancellation of one admitted operation by stable identity.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal exactly as [`ResearchKernelClient::dispatch`]
    /// does. A refused cancellation is a cancellation-unconfirmed state, never
    /// a proven no-effect claim.
    pub fn cancel(
        &self,
        dispatch: &ResearchProviderDispatch,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchKernelClientError> {
        self.dispatch(dispatch, RESEARCH_PROVIDER_CANCEL_OPERATION)
    }

    /// Requests unknown-outcome reconciliation of one admitted operation.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal exactly as [`ResearchKernelClient::dispatch`]
    /// does.
    pub fn reconcile(
        &self,
        dispatch: &ResearchProviderDispatch,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchKernelClientError> {
        self.dispatch(dispatch, RESEARCH_PROVIDER_RECONCILE_OPERATION)
    }

    /// Sends one research operation through the authenticated Execute seam and
    /// re-verifies the reply before it can become an admission.
    fn transact(
        &self,
        dispatch: &ResearchProviderDispatch,
        payload: &Value,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchKernelClientError> {
        let request_identity = self.next_identity(dispatch, payload)?;
        let served = Self::block_on(self.transact_async(
            payload,
            request_identity,
            &dispatch.authority_epoch,
        ))??;
        decode_verified_receipt(&served, dispatch)
    }

    /// Returns the exact request identity for one operation, bound to the live
    /// `ServerHello` State Fence.
    ///
    /// The fence is taken from the live handshake, never from a local guess, a
    /// cached value, or a task-supplied fence. The deadline and the
    /// cancellation identity are derived from the admitted operation identity,
    /// so both are stable across a retry of the same logical operation.
    fn next_identity(
        &self,
        dispatch: &ResearchProviderDispatch,
        payload: &Value,
    ) -> Result<RequestIdentity, ResearchKernelClientError> {
        let fence = self.live_fence()?;
        let sequence = self
            .request_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request_id = RequestId::new(format!(
            "{SERVICE_NAME}:{}:{}:{sequence}",
            dispatch.operation_id,
            payload
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or(RESEARCH_PROVIDER_DISPATCH_OPERATION)
        ))
        .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
        let now = unix_ms();
        Ok(RequestIdentity {
            request: RequestBinding {
                metadata: eliot_contracts::RequestMetadata {
                    request_id: request_id.clone(),
                    session_id: None,
                    task_id: None,
                    product_id: ProductId::new(SERVICE_NAME).map_err(|error| {
                        ResearchKernelClientError::Configuration(error.to_string())
                    })?,
                    source_id: SourceId::new(SERVICE_NAME).map_err(|error| {
                        ResearchKernelClientError::Configuration(error.to_string())
                    })?,
                    state_fence: fence.clone(),
                    clock: ClockReading {
                        valid_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                        known_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                        transaction_sequence: None,
                        monotonic_ns: None,
                    },
                },
                state_fence: fence,
            },
            idempotency_key: dispatch.idempotency_key.clone(),
            deadline_unix_ms: u64::try_from(dispatch.deadline_ms).unwrap_or(u64::MAX),
            cancellation_id: dispatch.cancellation_id.clone(),
        })
    }

    /// Returns the live Kernel Authority Epoch observed on a fresh
    /// authenticated handshake.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the front door is closed or the handshake
    /// is not bound to the protected authority. A caller uses this to refuse
    /// presented admitted material whose epoch is not the live authority.
    pub fn live_authority_epoch(&self) -> Result<EpochId, ResearchKernelClientError> {
        #[cfg(not(windows))]
        {
            Err(ResearchKernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door".to_owned(),
            ))
        }
        #[cfg(windows)]
        {
            Ok(Self::block_on(self.handshake_async())??.authority_epoch)
        }
    }

    /// Returns the live State Fence observed on a fresh authenticated
    /// handshake.
    fn live_fence(&self) -> Result<StateFence, ResearchKernelClientError> {
        #[cfg(not(windows))]
        {
            Err(ResearchKernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door".to_owned(),
            ))
        }
        #[cfg(windows)]
        {
            let live = Self::block_on(self.handshake_async())??;
            let generation = ResourceGeneration::new(live.generation)
                .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
            Ok(StateFence::new(live.authority_epoch, generation))
        }
    }

    /// Opens one authenticated connection and returns the live server
    /// binding.
    #[cfg(windows)]
    async fn handshake_async(&self) -> Result<ServerBinding, ResearchKernelClientError> {
        self.lease
            .verify_stable_identity()
            .and_then(|()| self.lease.verify_path_identity())
            .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
        let expectation = NamedPipePeerExpectation::new(
            &self.declaration.expected_kernel_sid,
            self.declaration.expected_kernel_session_id,
        )
        .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated(
            KERNEL_FRONT_DOOR_PIPE,
            CONNECT_TIMEOUT,
            &expectation,
        )
        .await
        .map_err(|error| ResearchKernelClientError::FrontDoorClosed(bound(&error.to_string())))?;
        let limits = TransportLimits::default();
        let hello = client_hello_frame(
            &self.declaration.connection_id,
            &self.declaration.client_hello,
        )
        .map_err(|error| ResearchKernelClientError::Rejected(error.to_string()))?;
        require_delivery(
            transport.send_frame(&hello, limits).await,
            "Kernel client hello",
        )?;
        let server = transport
            .receive_frame(limits)
            .await
            .map_err(|error| ResearchKernelClientError::Rejected(bound(&error.to_string())))?;
        let hello = decode_server_hello_frame(&server, &self.declaration.connection_id)
            .map_err(|error| ResearchKernelClientError::Rejected(bound(&error.to_string())))?;
        validate_server_hello(&self.declaration, &hello)
    }

    /// Sends one Execute frame and returns the raw reply body.
    #[cfg(windows)]
    async fn transact_async(
        &self,
        payload: &Value,
        identity: RequestIdentity,
        presented_epoch: &EpochId,
    ) -> Result<Value, ResearchKernelClientError> {
        self.lease
            .verify_stable_identity()
            .and_then(|()| self.lease.verify_path_identity())
            .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
        let expectation = NamedPipePeerExpectation::new(
            &self.declaration.expected_kernel_sid,
            self.declaration.expected_kernel_session_id,
        )
        .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated(
            KERNEL_FRONT_DOOR_PIPE,
            CONNECT_TIMEOUT,
            &expectation,
        )
        .await
        .map_err(|error| ResearchKernelClientError::FrontDoorClosed(bound(&error.to_string())))?;
        let limits = TransportLimits::default();
        let hello = client_hello_frame(
            &self.declaration.connection_id,
            &self.declaration.client_hello,
        )
        .map_err(|error| ResearchKernelClientError::Rejected(error.to_string()))?;
        require_delivery(
            transport.send_frame(&hello, limits).await,
            "Kernel client hello",
        )?;
        let server = transport
            .receive_frame(limits)
            .await
            .map_err(|error| ResearchKernelClientError::Rejected(bound(&error.to_string())))?;
        let server_hello = decode_server_hello_frame(&server, &self.declaration.connection_id)
            .map_err(|error| ResearchKernelClientError::Rejected(bound(&error.to_string())))?;
        // Re-validating the live server binding on the dispatch connection is
        // what makes a second request a fresh authenticated exchange rather
        // than a replay of a cached handshake, and it proves the serving
        // Kernel is the same authority the presented dispatch was admitted
        // under before a single request byte is written.
        let live = validate_server_hello(&self.declaration, &server_hello)?;
        if !live.authority_epoch.is_same_authority(presented_epoch) {
            return Err(ResearchKernelClientError::UnverifiedReceipt {
                reason_code: eliot_kernel_service::REASON_STALE_AUTHORITY_EPOCH,
                detail: "serving Kernel authority is not the presented dispatch authority"
                    .to_owned(),
            });
        }
        let request_id = identity.request.metadata.request_id.clone();
        let frame = Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: self.declaration.connection_id.clone(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(payload.clone()),
            trace_context: std::collections::BTreeMap::new(),
        };
        frame
            .validate()
            .map_err(|error| ResearchKernelClientError::Rejected(error.to_string()))?;
        require_delivery(
            transport.send_frame(&frame, limits).await,
            "Kernel research dispatch",
        )?;
        let response = transport.receive_frame(limits).await.map_err(|error| {
            // The request was delivered; the reply was not proven. That is an
            // unknown outcome, reconciled by the stable operation identity,
            // never a blind retry.
            ResearchKernelClientError::UnknownOutcome(bound(&error.to_string()))
        })?;
        validate_result_response(&self.declaration.connection_id, &request_id, &response)
    }

    /// Drives one front-door future to completion on the calling thread.
    ///
    /// A current-thread reactor with I/O and time enabled is required because
    /// the named-pipe transport is genuinely asynchronous; the shared process
    /// executor future is *not* driven here (see `execution::block_on`).
    /// A reactor that cannot be constructed is reported as a closed front door
    /// rather than as a fabricated reply.
    fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, ResearchKernelClientError> {
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    ResearchKernelClientError::FrontDoorClosed(bound(&error.to_string()))
                })?;
            Ok(runtime.block_on(future))
        }
        #[cfg(not(windows))]
        {
            let _ = future;
            Err(ResearchKernelClientError::FrontDoorClosed(
                "Windows authenticated Kernel front door".to_owned(),
            ))
        }
    }
}

/// Live server facts observed on one authenticated handshake.
#[cfg(windows)]
struct ServerBinding {
    authority_epoch: EpochId,
    generation: u64,
}

/// Decodes and re-verifies one served receipt against the held dispatch.
///
/// A well-formed receipt is not an admission: `verify_echo` re-proves the
/// operation identity, cancellation identity, request digest, admitted
/// generation, State Fence, and Authority Epoch. Any disagreement is a typed
/// refusal with the exact I7.20 reason code.
fn decode_verified_receipt(
    served: &Value,
    dispatch: &ResearchProviderDispatch,
) -> Result<ResearchProviderDispatchReceipt, ResearchKernelClientError> {
    let body = served
        .get("payload")
        .ok_or_else(|| ResearchKernelClientError::UnverifiedReceipt {
            reason_code: eliot_kernel_service::REASON_INVALID_ARGUMENT,
            detail: "served reply carries no payload".to_owned(),
        })?
        .get("receipt")
        .ok_or_else(|| ResearchKernelClientError::UnverifiedReceipt {
            reason_code: eliot_kernel_service::REASON_INVALID_ARGUMENT,
            detail: "served reply carries no receipt".to_owned(),
        })?;
    let receipt: ResearchProviderDispatchReceipt =
        serde_json::from_value(body.clone()).map_err(|error| {
            ResearchKernelClientError::UnverifiedReceipt {
                reason_code: eliot_kernel_service::REASON_INVALID_ARGUMENT,
                detail: bound(&error.to_string()),
            }
        })?;
    receipt
        .verify_echo(dispatch)
        .map_err(
            |error: ResearchProviderError| ResearchKernelClientError::UnverifiedReceipt {
                reason_code: echo_reason_code(error),
                detail: bound(&error.to_string()),
            },
        )?;
    Ok(receipt)
}

/// Maps one wire-owner refusal onto the exact I7.20 reason code.
fn echo_reason_code(error: ResearchProviderError) -> &'static str {
    match error {
        ResearchProviderError::StaleEpoch => eliot_kernel_service::REASON_STALE_AUTHORITY_EPOCH,
        ResearchProviderError::StaleFence => eliot_kernel_service::REASON_STALE_STATE_FENCE,
        ResearchProviderError::EchoMismatch => eliot_kernel_service::REASON_IDENTITY_CONFLICT,
        _ => eliot_kernel_service::REASON_INVALID_ARGUMENT,
    }
}

/// Validates the protected installation declaration shape.
#[cfg(windows)]
fn validate_declaration(
    declaration: &ResearchClientDeclaration,
) -> Result<(), ResearchKernelClientError> {
    for text in [
        &declaration.connection_id,
        &declaration.expected_kernel_sid,
        &declaration.expected_server_principal_binding,
    ] {
        if text.trim().is_empty() || text.chars().any(char::is_control) {
            return Err(ResearchKernelClientError::Configuration(
                "Kernel client declaration identity is invalid".to_owned(),
            ));
        }
    }
    NamedPipePeerExpectation::new(
        &declaration.expected_kernel_sid,
        declaration.expected_kernel_session_id,
    )
    .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
    declaration
        .client_hello
        .validate()
        .map_err(|error| ResearchKernelClientError::Configuration(error.to_string()))?;
    if declaration.expected_generation == 0
        || !is_hex_digest(&declaration.expected_artifact_digest)
        || !is_hex_digest(&declaration.expected_config_snapshot_sha256)
        || !is_hex_digest(&declaration.client_hello_sha256)
    {
        return Err(ResearchKernelClientError::Configuration(
            "Kernel client declaration digest or generation is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the live `ServerHello` against the protected declaration.
#[cfg(windows)]
fn validate_server_hello(
    declaration: &ResearchClientDeclaration,
    hello: &ServerHello,
) -> Result<ServerBinding, ResearchKernelClientError> {
    hello
        .validate()
        .map_err(|error| ResearchKernelClientError::Rejected(error.to_string()))?;
    if hello.rejection_reason.is_some()
        || hello.selected_protocol != ProtocolVersion::CURRENT
        || hello.session_principal_binding != declaration.expected_server_principal_binding
        || !hello
            .authority_epoch
            .is_same_authority(&declaration.expected_authority_epoch)
    {
        return Err(ResearchKernelClientError::Rejected(
            "Kernel ServerHello is not bound to the protected authority".to_owned(),
        ));
    }
    let snapshot: ServerConfigSnapshot = serde_json::from_value(hello.config_snapshot.clone())
        .map_err(|error| {
            ResearchKernelClientError::Rejected(format!(
                "Kernel ServerHello configuration snapshot shape is invalid: {error}"
            ))
        })?;
    if snapshot.service != KERNEL_SERVICE_NAME
        || snapshot.protocol != KERNEL_PROTOCOL_VERSION
        || snapshot.generation == 0
        || snapshot.generation != declaration.expected_generation
        || !snapshot
            .authority_epoch
            .is_same_authority(&declaration.expected_authority_epoch)
        || !snapshot
            .artifact_digest
            .eq_ignore_ascii_case(&declaration.expected_artifact_digest)
    {
        return Err(ResearchKernelClientError::Rejected(
            "Kernel ServerHello generation or artifact binding mismatch".to_owned(),
        ));
    }
    let snapshot_bytes = serde_json::to_vec(&hello.config_snapshot)
        .map_err(|error| ResearchKernelClientError::Rejected(error.to_string()))?;
    if !sha256_hex(&snapshot_bytes)
        .eq_ignore_ascii_case(&declaration.expected_config_snapshot_sha256)
    {
        return Err(ResearchKernelClientError::Rejected(
            "Kernel ServerHello configuration snapshot digest mismatch".to_owned(),
        ));
    }
    Ok(ServerBinding {
        authority_epoch: hello.authority_epoch.clone(),
        generation: snapshot.generation,
    })
}

/// Validates the served Result frame and returns its JSON payload.
#[cfg(windows)]
fn validate_result_response(
    connection_id: &str,
    request_id: &RequestId,
    response: &Frame,
) -> Result<Value, ResearchKernelClientError> {
    if response.connection_id != connection_id
        || response.request_id.as_ref() != Some(request_id)
        || response.kind != FrameKind::Response
        || response.message_type != MessageType::Result
    {
        return Err(ResearchKernelClientError::UnverifiedReceipt {
            reason_code: eliot_kernel_service::REASON_IDENTITY_CONFLICT,
            detail: "served frame does not correlate with the request".to_owned(),
        });
    }
    response
        .validate()
        .map_err(|error| ResearchKernelClientError::Rejected(error.to_string()))?;
    match &response.payload {
        ProtocolPayload::Json(payload) => Ok(payload.clone()),
        _ => Err(ResearchKernelClientError::UnverifiedReceipt {
            reason_code: eliot_kernel_service::REASON_INVALID_ARGUMENT,
            detail: "served frame payload is not JSON".to_owned(),
        }),
    }
}

/// Requires a proven delivery outcome; a bare write is not delivery.
///
/// `TransportError::UnknownOutcome` means the bytes may have crossed the
/// uncertainty boundary, so it is reported as an unknown outcome requiring
/// reconciliation by the stable operation identity, never as a closed door
/// that would invite a blind retry.
#[cfg(windows)]
fn require_delivery<T>(
    outcome: Result<T, eliot_ipc::TransportError>,
    stage: &'static str,
) -> Result<T, ResearchKernelClientError> {
    match outcome {
        Ok(value) => Ok(value),
        Err(error) => {
            let detail = format!("{stage}: {error}");
            if error == eliot_ipc::TransportError::UnknownOutcome {
                Err(ResearchKernelClientError::UnknownOutcome(bound(&detail)))
            } else {
                Err(ResearchKernelClientError::FrontDoorClosed(bound(&detail)))
            }
        }
    }
}

/// Returns true when the value is a hexadecimal SHA-256 digest of any case.
#[cfg(windows)]
fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Computes the lowercase SHA-256 hex digest of exact bytes.
#[cfg(windows)]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Bounds one error detail to a fixed character budget.
fn bound(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}
