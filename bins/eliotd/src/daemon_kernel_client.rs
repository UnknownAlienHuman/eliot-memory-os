//! Authenticated Kernel client transport for `eliotd`.
//!
//! Architecture: A13.2 (Governor/Kernel authenticated IPC boundary), A13.8
//! (process-receipt-gated pre-admission).
//! Implementation: I1.8 (artifact-bound session), I2.16 (generation fencing),
//! I2.23 (typed contract payloads).
//! This module owns only the EBP transport/session proof; Kernel remains the
//! sole process, Store, and canonical authority owner.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationSnapshot, KernelPortError};
use eliot_protocol::{
    AgentActivationResolutionDecision, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResultAck, AgentActivationResultReconcile,
    AgentActivationResultSubmit, EncodingProfile, Frame, FrameKind,
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HostRequestEnvelope, HostRequestInvokeReadPayload,
    HostRequestResultBody, MessageType, ProtocolPayload, ProtocolVersion, RequestIdentity,
    host_request_operation_id,
};
use eliot_receipts::RequestBinding;
use eliot_store_api::{NamedReadRequest, NamedReadResponse};

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
#[cfg(windows)]
use eliot_platform_windows::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};

mod handshake;

#[cfg(windows)]
use handshake::client_hello;
use handshake::expected_snapshot;
pub(super) use handshake::{KernelClientError, WireOutcome, kernel_port_error, operation_payload};
#[cfg(windows)]
pub(super) use handshake::{is_pre_admission_pending_rejection, validate_server_hello};

use super::{
    KERNEL_OPERATION_TIMEOUT, KernelLaunchBinding, PRE_ADMISSION_RETRY_DELAY, SERVICE_NAME,
    unix_ms, unix_ms_i64,
};

pub struct DaemonKernelClient {
    launch: GovernorLaunchConfig,
    pub(super) kernel_binding: KernelLaunchBinding,
    pub(super) connection_id: String,
    pub(super) snapshot: KernelGenerationSnapshot,
    request_counter: Arc<AtomicU64>,
    /// Literal Kernel-issued `sid=..;session=..` binding string retained only
    /// after a successful [`validate_server_hello`](handshake::validate_server_hello)
    /// in this process (AUD-C02-B, Implements #1187). Never the whole
    /// `ServerHello`, never a constant, no secret: identity refs only. `None`
    /// until the first validated handshake, so pre-handshake reads stay
    /// fail-closed to "no live session".
    validated_session_binding: Mutex<Option<String>>,
}

/// Already-validated Kernel-issued owner session facts for the single live
/// owner session (AUD-C02-B, Implements #1187; single-owner decision #1376).
///
/// Every field is cloned from state this client already holds after the
/// authenticated handshake: the validated `sid=..;session=..` binding string,
/// the Kernel snapshot principal and receipt-relevant artifact digests, the
/// local connection correlation id, and the descriptor launch nonce carried
/// in [`KernelLaunchBinding::launch_nonce`]. No re-handshake, no secret, no
/// constant, no parsing of constants.
#[derive(Clone, Debug)]
pub struct OwnerSessionFacts {
    pub(crate) session_binding: String,
    pub(crate) kernel_principal: String,
    pub(crate) connection_id: String,
    pub(crate) launch_nonce: String,
    pub(crate) artifact_digest: String,
    pub(crate) protected_snapshot_digest: String,
}

#[cfg(windows)]
pub(super) async fn retry_pre_admission<T, F, Fut>(
    timeout: Duration,
    mut operation: F,
    deadline_error: &'static str,
) -> Result<T, KernelClientError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, KernelClientError>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match operation().await {
            Err(
                KernelClientError::PreAdmissionPending
                | KernelClientError::PreAdmissionTransport(_),
            ) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(KernelClientError::Transport(deadline_error.to_owned()));
                }
                tokio::time::sleep(PRE_ADMISSION_RETRY_DELAY.min(deadline - now)).await;
            }
            outcome => return outcome,
        }
    }
}

/// Typed outcome of one `local_read_result` submit (Implements #18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalReadSubmitOutcome {
    /// Kernel persisted the body through the ORS result path. An exact replay
    /// of an already-resulted operation reports here too — idempotent, even
    /// across deadline expiry.
    Accepted,
    /// The absolute deadline elapsed before the body could persist. This is
    /// the expected claim/submit race, projected as a known outcome — never
    /// as a transport error.
    Expired,
}

/// Parses one unwrapped `local_read_claim` answer value into the claimed
/// admitted pair.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::local_read_claim`)
/// answers the single-`operation`-key poll with `{"pair": {"envelope",
/// "tool"}}` or `{"pair": null}`. `None` is the empty-queue backoff signal,
/// not an error — exactly like the activation ticket `None` case. The claimed
/// envelope must already decode as admitted shape; its closed linkage and
/// fence binding are re-proved inside
/// [`forward_admitted_local_read`](super::forward_admitted_local_read) before
/// any read or submit touches it.
pub fn parse_local_read_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<(HostRequestEnvelope, serde_json::Value)>, String> {
    let pair = value
        .get("pair")
        .ok_or_else(|| "Kernel local_read_claim answer omits the pair".to_owned())?;
    match pair {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(_) => {
            let envelope_value = pair
                .get("envelope")
                .cloned()
                .ok_or_else(|| "Kernel local_read_claim pair omits the envelope".to_owned())?;
            let tool = pair
                .get("tool")
                .cloned()
                .ok_or_else(|| "Kernel local_read_claim pair omits the tool".to_owned())?;
            let envelope: HostRequestEnvelope =
                serde_json::from_value(envelope_value).map_err(|error| {
                    format!("Kernel local_read_claim pair envelope does not decode: {error}")
                })?;
            envelope.validate().map_err(|error| {
                format!("Kernel local_read_claim pair envelope is not admitted shape: {error}")
            })?;
            Ok(Some((envelope, tool)))
        }
        _ => Err("Kernel local_read_claim pair is neither an admitted pair nor null".to_owned()),
    }
}

/// Parses one unwrapped `local_read_result` answer value into the typed
/// submit outcome.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::local_read_result`)
/// answers `{"accepted": true}` on persist (exact replays included) and
/// `{"accepted": false, "expired": true}` when the absolute deadline elapsed
/// first. Anything else is a contract violation, never a silent accept.
pub fn parse_local_read_submit_outcome(
    value: &serde_json::Value,
) -> Result<LocalReadSubmitOutcome, String> {
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "Kernel local_read_result answer omits the accepted outcome".to_owned())?;
    if accepted {
        return Ok(LocalReadSubmitOutcome::Accepted);
    }
    if value
        .get("expired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(LocalReadSubmitOutcome::Expired);
    }
    Err("Kernel local_read_result answer is neither accepted nor expired".to_owned())
}

impl DaemonKernelClient {
    #[cfg(windows)]
    pub async fn claim_agent_activation_ticket(
        &self,
    ) -> Result<Option<AgentActivationResolutionTicket>, super::DaemonError> {
        let value = self
            .transact_async("agent_activation_claim", serde_json::json!({}))
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let ticket = value.get("ticket").cloned().ok_or_else(|| {
            super::DaemonError::Kernel("Kernel claim response omitted ticket".to_owned())
        })?;
        match ticket {
            serde_json::Value::Null => Ok(None),
            value => serde_json::from_value(value)
                .map(Some)
                .map_err(|error| super::DaemonError::Kernel(error.to_string())),
        }
    }

    #[cfg(windows)]
    pub async fn submit_agent_activation_decision(
        &self,
        decision: &AgentActivationResolutionDecision,
    ) -> Result<(), super::DaemonError> {
        decision
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        self.transact_async(
            "agent_activation_submit",
            serde_json::json!({ "decision": decision }),
        )
        .await
        .map(|_| ())
        .map_err(|error| super::DaemonError::Kernel(error.to_string()))
    }

    #[cfg(windows)]
    pub async fn submit_agent_activation_result(
        &self,
        result: &AgentActivationResolutionResult,
    ) -> Result<AgentActivationResultAck, super::DaemonError> {
        let submit = AgentActivationResultSubmit::new(result.clone())
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "agent_activation_submit",
                serde_json::json!({ "result": submit }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let ack_value = value.get("ack").cloned().ok_or_else(|| {
            super::DaemonError::Kernel("Kernel submit response omitted acknowledgement".to_owned())
        })?;
        let ack: AgentActivationResultAck = serde_json::from_value(ack_value)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        ack.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        Ok(ack)
    }

    #[cfg(windows)]
    pub async fn reconcile_agent_activation_result(
        &self,
        query: &AgentActivationResultReconcile,
    ) -> Result<AgentActivationResultAck, super::DaemonError> {
        query
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "agent_activation_reconcile",
                serde_json::json!({ "reconcile": query }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let ack_value = value.get("ack").cloned().ok_or_else(|| {
            super::DaemonError::Kernel(
                "Kernel reconcile response omitted acknowledgement".to_owned(),
            )
        })?;
        let ack: AgentActivationResultAck = serde_json::from_value(ack_value)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        ack.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        Ok(ack)
    }

    pub fn connect(config: &super::DaemonConfig) -> Result<Arc<Self>, super::DaemonError> {
        let client = Self {
            launch: config.launch.clone(),
            connection_id: format!(
                "eliotd:{}:{}:{}:{}",
                config.launch.instance_id,
                config.launch.kernel.generation.value(),
                config.launch.kernel.authority_epoch.lineage_id.as_str(),
                config.launch.kernel.authority_epoch.sequence.get()
            ),
            snapshot: expected_snapshot(&config.launch)?,
            kernel_binding: config.kernel_binding.clone(),
            request_counter: Arc::new(AtomicU64::new(1)),
            validated_session_binding: Mutex::new(None),
        };
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            let snapshot = runtime
                .block_on(client.snapshot_request_with_pre_admission_retry())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            let mut client = client;
            client.snapshot = snapshot;
            Ok(Arc::new(client))
        }
        #[cfg(not(windows))]
        {
            let _ = client;
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    /// Returns the already-validated Kernel-issued owner session facts for
    /// the single live owner session (AUD-C02-B, Implements #1187).
    ///
    /// Read-only over held fields: the retained `sid=..;session=..` binding
    /// string (set only on successful `validate_server_hello`, never a
    /// constant), the snapshot principal and artifact digests, the connection
    /// id, and the descriptor launch nonce. No re-handshake, no secret.
    /// `None` until a handshake in this process has validated a `ServerHello`,
    /// so daemon composition without a live session keeps the empty
    /// (unadmitted) controlboard behaviour.
    #[must_use]
    pub fn owner_session_facts(&self) -> Option<OwnerSessionFacts> {
        Some(OwnerSessionFacts {
            session_binding: self.validated_session_binding()?,
            kernel_principal: self.snapshot.principal.clone(),
            connection_id: self.connection_id.clone(),
            launch_nonce: self.kernel_binding.launch_nonce.clone(),
            artifact_digest: self.snapshot.artifact_digest.clone(),
            protected_snapshot_digest: self.snapshot.protected_snapshot_digest.clone(),
        })
    }

    /// Clones the retained validated binding string, if any. A poisoned slot
    /// reads as absent (fail-closed to "no live session"), never invented.
    fn validated_session_binding(&self) -> Option<String> {
        self.validated_session_binding
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub fn report_ready(&self) -> Result<(), super::DaemonError> {
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(self.report_ready_with_pre_admission_retry())
                .map(|_| ())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    pub fn report_degraded(&self, reason: impl Into<String>) -> Result<(), super::DaemonError> {
        let reason = reason.into();
        if reason.trim().is_empty() || reason.chars().any(char::is_control) || reason.len() > 512 {
            return Err(super::DaemonError::Kernel(
                "daemon degradation reason is blank, unbounded, or contains control characters"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(self.transact_async(
                    "daemon_degraded",
                    serde_json::json!({
                        "reason": reason,
                    }),
                ))
                .map(|_| ())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    pub fn report_fatal(&self, reason: impl Into<String>) -> Result<(), super::DaemonError> {
        let reason = reason.into();
        if reason.trim().is_empty() || reason.chars().any(char::is_control) || reason.len() > 512 {
            return Err(super::DaemonError::Kernel(
                "daemon fatal reason is blank, unbounded, or contains control characters"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(
                    self.transact_async("daemon_fatal", serde_json::json!({ "reason": reason })),
                )
                .map(|_| ())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    #[cfg(windows)]
    async fn snapshot_request_with_pre_admission_retry(
        &self,
    ) -> Result<KernelGenerationSnapshot, KernelClientError> {
        retry_pre_admission(
            KERNEL_OPERATION_TIMEOUT,
            || self.snapshot_request(),
            "exact launched process receipt was not published before the Kernel operation deadline",
        )
        .await
    }

    #[cfg(windows)]
    async fn report_ready_with_pre_admission_retry(
        &self,
    ) -> Result<serde_json::Value, KernelClientError> {
        retry_pre_admission(
            KERNEL_OPERATION_TIMEOUT,
            || {
                self.transact_async(
                    "daemon_ready",
                    serde_json::json!({
                        "generation": self.snapshot.generation.value(),
                        "authority_epoch": self.snapshot.authority_epoch.clone(),
                    }),
                )
            },
            "exact launched process receipt was not published before daemon ready deadline",
        )
        .await
    }

    #[cfg(windows)]
    pub(super) async fn transact_async(
        &self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelClientError> {
        let identity = self.next_identity(operation)?;
        self.transact_async_with_identity(operation, payload, identity)
            .await
    }

    #[cfg(windows)]
    pub(super) async fn transact_async_with_identity(
        &self,
        operation: &str,
        payload: serde_json::Value,
        identity: RequestIdentity,
    ) -> Result<serde_json::Value, KernelClientError> {
        let (mut transport, limits) = self.connect_transport().await?;
        let request_id = identity.request.metadata.request_id.clone();
        let frame = Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: self.connection_id.clone(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(operation_payload(operation, payload)?),
            trace_context: BTreeMap::new(),
        };
        if transport
            .send_frame(&frame, limits)
            .await
            .map_err(|error| KernelClientError::Transport(error.to_string()))?
            != DeliveryOutcome::Delivered
        {
            return Err(KernelClientError::Unknown(
                "Kernel request delivery was not proven".to_owned(),
            ));
        }
        let response = transport
            .receive_frame(limits)
            .await
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        response
            .validate()
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if response.connection_id != self.connection_id
            || response.request_id.as_ref() != Some(&request_id)
            || response.kind != FrameKind::Response
            || response.message_type != MessageType::Result
            || response.request_identity.is_some()
        {
            return Err(KernelClientError::Unknown(
                "Kernel response correlation is invalid".to_owned(),
            ));
        }
        let ProtocolPayload::Json(value) = response.payload else {
            return Err(KernelClientError::Unknown(
                "Kernel response is not JSON".to_owned(),
            ));
        };
        match serde_json::from_value::<WireOutcome>(value)
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?
        {
            WireOutcome::Known { value, recovery } => {
                let _ = recovery;
                Ok(value)
            }
            WireOutcome::Error { code, reason } => {
                Err(KernelClientError::Contract(format!("{code}: {reason}")))
            }
            WireOutcome::Partial { reason, value } => {
                let _ = value;
                Err(KernelClientError::Unknown(reason))
            }
            WireOutcome::Unknown { reason } => Err(KernelClientError::Unknown(reason)),
        }
    }

    #[cfg(not(windows))]
    pub(super) async fn transact_async(
        &self,
        _operation: &str,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelClientError> {
        Err(KernelClientError::Unsupported)
    }

    #[cfg(not(windows))]
    pub(super) async fn transact_async_with_identity(
        &self,
        _operation: &str,
        _payload: serde_json::Value,
        _identity: RequestIdentity,
    ) -> Result<serde_json::Value, KernelClientError> {
        Err(KernelClientError::Unsupported)
    }

    #[cfg(windows)]
    async fn connect_transport(
        &self,
    ) -> Result<(NamedPipeTransport, TransportLimits), KernelClientError> {
        let expectation = KernelFrontDoorServerExpectation::new(
            self.kernel_binding.expected_kernel_sid.as_str(),
            self.kernel_binding.expected_kernel_session_id,
            self.kernel_binding.kernel_artifact_sha256.as_str(),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient,
        )
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
            self.kernel_binding.kernel_pipe_name.as_str(),
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .map_err(|error| KernelClientError::PreAdmissionTransport(error.to_string()))?;
        match transport.peer_identity() {
            eliot_ipc::PeerIdentity::Authenticated {
                process_id,
                user_identity,
                session_identity,
                ..
            } if *process_id != 0
                && user_identity == self.kernel_binding.expected_kernel_sid.as_str()
                && session_identity
                    == &self.kernel_binding.expected_kernel_session_id.to_string() => {}
            _ => {
                return Err(KernelClientError::Contract(
                    "Kernel pipe peer identity did not match the protected daemon declaration"
                        .to_owned(),
                ));
            }
        }
        let limits = TransportLimits::default();
        let hello = client_hello(&self.kernel_binding)?;
        let frame = eliot_ipc::client_hello_frame(&self.connection_id, &hello)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        if transport
            .send_frame(&frame, limits)
            .await
            .map_err(|error| KernelClientError::Transport(error.to_string()))?
            != DeliveryOutcome::Delivered
        {
            return Err(KernelClientError::Unknown(
                "Kernel hello delivery was not proven".to_owned(),
            ));
        }
        let response = transport
            .receive_frame(limits)
            .await
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if is_pre_admission_pending_rejection(&response, &self.connection_id) {
            return Err(KernelClientError::PreAdmissionPending);
        }
        let server = eliot_ipc::decode_server_hello_frame(&response, &self.connection_id)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        validate_server_hello(&self.launch, &self.kernel_binding, &server)?;
        // Retain the literal Kernel-issued binding string only now that it
        // validated: the owner session facts reader forwards these exact
        // bytes, never a locally minted session. A lock failure keeps the
        // previous value, so admission stays fail-closed, never invented.
        if let Ok(mut slot) = self.validated_session_binding.lock() {
            *slot = Some(server.session_principal_binding.clone());
        }
        Ok((transport, limits))
    }

    fn next_identity(&self, operation: &str) -> Result<RequestIdentity, KernelClientError> {
        let sequence = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let request_id =
            RequestId::new(format!("{}:{}:{}", self.connection_id, operation, sequence))
                .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let fence = self.snapshot.state_fence();
        let metadata = RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: None,
            product_id: ProductId::new(SERVICE_NAME)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            source_id: SourceId::new(SERVICE_NAME)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(unix_ms_i64()),
                known_time_ms: Some(unix_ms_i64()),
                transaction_sequence: None,
                monotonic_ns: None,
            },
        };
        Ok(RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence,
            },
            idempotency_key: format!("{SERVICE_NAME}:{operation}:{sequence}"),
            deadline_unix_ms: unix_ms().saturating_add(30_000),
            cancellation_id: format!("{SERVICE_NAME}:{operation}:{sequence}:cancel"),
        })
    }

    fn blocking<T, F>(future: F) -> Result<T, KernelPortError>
    where
        T: Send + 'static,
        F: std::future::Future<Output = Result<T, KernelClientError>> + Send + 'static,
    {
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| KernelPortError::NotAdmitted(error.to_string()))?;
            runtime.block_on(future).map_err(kernel_port_error)
        }
        #[cfg(not(windows))]
        {
            let _ = future;
            Err(KernelPortError::NotAdmitted(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    pub(super) fn request_blocking(
        &self,
        operation: &'static str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError> {
        let client = self.clone_for_future();
        Self::blocking(async move { client.transact_async(operation, payload).await })
    }

    pub(super) fn request_blocking_with_identity(
        &self,
        operation: &'static str,
        payload: serde_json::Value,
        identity: RequestIdentity,
    ) -> Result<serde_json::Value, KernelPortError> {
        let client = self.clone_for_future();
        Self::blocking(async move {
            client
                .transact_async_with_identity(operation, payload, identity)
                .await
        })
    }

    /// Executes one closed named read through the authenticated Kernel route.
    ///
    /// Mirrors the `receipt` / `store_recovery` transport template: the
    /// request validates before any transport is touched, the call travels as
    /// the `"store_named"` operation with a fresh operation-bound identity,
    /// and the typed response is decoded through the closed
    /// `"store_named"` kind before exact validation. Kernel remains the route
    /// and fence authority; this method performs no consistency algorithm and
    /// no catalogue widening — callers enforce the operation/scope
    /// capability (T11.1 activates `GetEvidencePack` only at the
    /// `CanonicalReadClient` boundary).
    ///
    /// Errors: `Contract` when the request is malformed, the admitted fence
    /// does not bind the request, the Kernel kind is unexpected, the payload
    /// does not decode, the response does not validate, or the response
    /// substitutes the operation or fence; `NotAdmitted` / `Unknown` for
    /// transport outcomes via [`kernel_port_error`].
    pub(super) async fn store_named_async(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, KernelPortError> {
        request
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if self.snapshot.state_fence() != request.state_fence {
            return Err(KernelPortError::Contract(
                "daemon named read fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self
            .transact_async(
                "store_named",
                serde_json::json!({
                    "request": request,
                }),
            )
            .await
            .map_err(kernel_port_error)?;
        let value = super::kind_value(&value, "store_named")?;
        let response: NamedReadResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        response
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if response.operation != request.operation || response.state_fence != request.state_fence {
            return Err(KernelPortError::Contract(
                "daemon named read response does not match the requested operation and active state fence"
                    .to_owned(),
            ));
        }
        Ok(response)
    }

    /// Claims one queued admitted `eliot.query` pair for the outbound-only
    /// local-read poller (Implements #18).
    ///
    /// Mirrors
    /// [`claim_agent_activation_ticket`](Self::claim_agent_activation_ticket):
    /// the call travels as the single-`operation`-key `"local_read_claim"`
    /// payload and a null `pair` is the empty-queue backoff signal, not an
    /// error. The claimed pair still proves its closed linkage and fence
    /// binding inside
    /// [`forward_admitted_local_read`](super::forward_admitted_local_read)
    /// before any read or submit touches it.
    #[cfg(windows)]
    pub async fn claim_local_read_pair_async(
        &self,
    ) -> Result<Option<(HostRequestEnvelope, serde_json::Value)>, super::DaemonError> {
        let value = self
            .transact_async(
                "local_read_claim",
                serde_json::json!({ "operation": "local_read_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_local_read_claimed_pair(&value).map_err(super::DaemonError::Kernel)
    }

    /// Submits one daemon-produced local-read result body for its waiting
    /// host request (Implements #18).
    ///
    /// The body travels as the single-`result`-key `"local_read_result"`
    /// payload and is validated before any transport is touched. Kernel
    /// persists through the ORS result path: an exact replay stays idempotent
    /// (even across deadline expiry); an elapsed absolute deadline is the
    /// expected race and projects as
    /// [`LocalReadSubmitOutcome::Expired`], never as a transport error.
    #[cfg(windows)]
    pub async fn submit_local_read_result_async(
        &self,
        body: &HostRequestResultBody,
    ) -> Result<LocalReadSubmitOutcome, super::DaemonError> {
        body.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async("local_read_result", serde_json::json!({ "result": body }))
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_local_read_submit_outcome(&value).map_err(super::DaemonError::Kernel)
    }

    /// Executes one closed local read through the authenticated Kernel route.
    ///
    /// Twin of [`store_named_async`](Self::store_named_async): the admitted
    /// envelope+tool pair proves its closed linkage before any transport is
    /// touched, the call travels as the `"local_read"` operation with a fresh
    /// operation-bound identity, and the persisted result body behind the
    /// admitted receipt+record is decoded through its closed body contract
    /// with exact envelope binding before return. Kernel remains the
    /// admission, read, and persistence authority; this method performs no
    /// admission decision and no consistency algorithm.
    ///
    /// Wire note: the `local_read` leg answers the documented admission
    /// shape (`accepted` plus receipt plus record); the `{kind: local_read}`
    /// wrapper exists only on the error envelope, which never decodes past
    /// the frame outcome (surfacing as `Unknown`, never as a body).
    ///
    /// Errors: `Contract` when the pair is malformed or unlinked, the
    /// admitted fence does not bind the envelope, the admitted answer does
    /// not bind this envelope, or the persisted body is absent (a packet
    /// admission carries no result body by design), fails to decode, or fails
    /// its own digest binding; `NotAdmitted` / `Unknown` for transport
    /// outcomes via [`kernel_port_error`].
    ///
    /// Production caller:
    /// [`forward_admitted_local_read`](super::forward_admitted_local_read),
    /// driven per claimed pair by the daemon runtime poller.
    pub(crate) async fn local_read_async(
        &self,
        envelope: HostRequestEnvelope,
        tool: serde_json::Value,
    ) -> Result<HostRequestResultBody, KernelPortError> {
        let pair = HostRequestInvokeReadPayload {
            wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
            wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
            envelope,
            tool,
        };
        pair.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if self.snapshot.state_fence() != pair.envelope.state_fence {
            return Err(KernelPortError::Contract(
                "daemon local read fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self
            .transact_async(
                "local_read",
                serde_json::json!({
                    "envelope": pair.envelope,
                    "tool": pair.tool,
                }),
            )
            .await
            .map_err(kernel_port_error)?;
        let admitted = value.as_object().ok_or_else(|| {
            KernelPortError::Contract("Kernel local read answer is not an object".to_owned())
        })?;
        if admitted.get("accepted") != Some(&serde_json::Value::Bool(true)) {
            return Err(KernelPortError::Contract(
                "Kernel local read answer is not an admission".to_owned(),
            ));
        }
        let operation_id = admitted
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel local read admission omits the operation handle".to_owned(),
                )
            })?;
        if operation_id != host_request_operation_id(&pair.envelope) {
            return Err(KernelPortError::Contract(
                "Kernel local read admission does not bind the admitted envelope".to_owned(),
            ));
        }
        let body_value = admitted
            .get("record")
            .and_then(|record| record.get("result_response"))
            .cloned()
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel local read admission carries no result body; packet admissions stay admission-only"
                        .to_owned(),
                )
            })?;
        let body: HostRequestResultBody = serde_json::from_value(body_value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        body.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if body.request_sha256 != pair.envelope.envelope_sha256
            || body.operation_id != host_request_operation_id(&pair.envelope)
        {
            return Err(KernelPortError::Contract(
                "Kernel local read result does not bind the admitted envelope".to_owned(),
            ));
        }
        Ok(body)
    }

    fn clone_for_future(&self) -> Arc<Self> {
        Arc::new(Self {
            launch: self.launch.clone(),
            kernel_binding: self.kernel_binding.clone(),
            connection_id: self.connection_id.clone(),
            snapshot: self.snapshot.clone(),
            request_counter: Arc::clone(&self.request_counter),
            validated_session_binding: Mutex::new(self.validated_session_binding()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_governor::{
        GovernorLaunchConfig, KernelGenerationExpectation, KernelGenerationSnapshot,
        KernelPortError,
    };
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
    };
    use eliot_read::{
        ProvenanceDisposition, ReadError, ReadProvenance, ReadService, StoreReadFailure,
    };
    use eliot_store_api::{
        CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, RevisionHead,
        RevisionKey, StoreError,
    };
    use serde_json::{Value, json};

    use crate::KernelLaunchBinding;
    use crate::forward_admitted_local_read;
    use crate::kernel_context_read_client::KernelContextReadClient;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        let lineage =
            EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
        let sequence = NonZeroU64::new(sequence).ok_or("non-zero test sequence")?;
        EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}").into())
    }

    fn test_fence(generation: u64) -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(
            test_epoch(1)?,
            ResourceGeneration::new(generation).map_err(|error| format!("generation: {error}"))?,
        ))
    }

    fn tool_digest(tool: &Value) -> Result<String, Box<dyn std::error::Error>> {
        let bytes = eliot_contracts::canonical_json_bytes(tool)
            .map_err(|error| format!("canonical tool bytes: {error}"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    fn query_tool() -> Value {
        json!({"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri": null
        }})
    }

    fn packet_tool() -> Value {
        json!({"name":"eliot.packet","arguments":{
            "packet_ref": null,
            "material_refs": []
        }})
    }

    fn test_envelope(
        capability: &str,
        fence: &StateFence,
        payload_sha256: &str,
    ) -> Result<HostRequestEnvelope, Box<dyn std::error::Error>> {
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1")
                    .map_err(|error| format!("request id: {error}"))?,
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: capability.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_sha256.to_owned(),
            },
            state_fence: fence.clone(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|error| format!("envelope digest: {error}").into())
    }

    fn test_client(fence: &StateFence) -> Result<DaemonKernelClient, Box<dyn std::error::Error>> {
        let epoch = test_epoch(1)?;
        let generation =
            ResourceGeneration::new(1).map_err(|error| format!("generation: {error}"))?;
        Ok(DaemonKernelClient {
            launch: GovernorLaunchConfig {
                instance_id: "test-eliotd".to_owned(),
                kernel: KernelGenerationExpectation {
                    service: "eliot-kernel".to_owned(),
                    protocol: "test".to_owned(),
                    artifact_digest: "a".repeat(64),
                    protected_snapshot_digest: "b".repeat(64),
                    principal: "test-principal".to_owned(),
                    generation,
                    authority_epoch: epoch.clone(),
                },
                protected_snapshot_digest: "b".repeat(64),
            },
            kernel_binding: KernelLaunchBinding {
                kernel_pipe_name: r"\\.\pipe\eliot\test".to_owned(),
                expected_kernel_sid: "S-1-5-18".to_owned(),
                expected_kernel_session_id: 0,
                module_generation: generation,
                authority_epoch: epoch.clone(),
                state_fence: fence.clone(),
                launch_nonce: "test-nonce".to_owned(),
                kernel_artifact_sha256: "a".repeat(64),
                daemon_artifact_sha256: "c".repeat(64),
            },
            connection_id: "test-connection".to_owned(),
            snapshot: KernelGenerationSnapshot {
                service: "eliot-kernel".to_owned(),
                protocol: "test".to_owned(),
                generation,
                authority_epoch: epoch,
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "test-principal".to_owned(),
            },
            request_counter: Arc::new(AtomicU64::new(1)),
            validated_session_binding: Mutex::new(None),
        })
    }

    /// Minimal in-test evidence table. It stores captured subjects in capture
    /// order and derives every response field from the incoming request: real
    /// request validation, the closed evidence operation, exact fence
    /// equality, the declared `subject` / `max_records` selectors, and the
    /// catalogue bound. Nothing is canned.
    struct EvidenceTable {
        fence: StateFence,
        captured: Vec<String>,
    }

    impl EvidenceTable {
        fn new(fence: StateFence) -> Self {
            Self {
                fence,
                captured: Vec::new(),
            }
        }

        fn capture(&mut self, subject: &str) {
            self.captured.push(subject.to_owned());
        }

        fn selectors(parameters: &BTreeMap<String, Value>) -> Result<(String, u32), StoreError> {
            let subject = parameters
                .get("subject")
                .and_then(Value::as_str)
                .filter(|subject| !subject.trim().is_empty())
                .ok_or(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "evidence subject must be exact",
                })?;
            let bound = parameters
                .get("max_records")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "max_records must ride as an exact decimal string",
                })?;
            let bound: u32 = bound.parse().map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must ride as an exact decimal string",
            })?;
            if bound == 0 || bound > EVIDENCE_PACK_MAX_RECORDS {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "max_records must be within the catalogue bound",
                });
            }
            Ok((subject.to_owned(), bound))
        }
    }

    #[allow(async_fn_in_trait)]
    impl CanonicalReadClient for EvidenceTable {
        async fn revision_heads(
            &self,
            _keys: Vec<RevisionKey>,
        ) -> Result<Vec<RevisionHead>, StoreError> {
            Ok(Vec::new())
        }

        async fn execute_named(
            &self,
            query: NamedReadRequest,
        ) -> Result<NamedReadResponse, StoreError> {
            query.validate()?;
            if query.operation != NamedReadOperation::GetEvidencePack {
                return Err(StoreError::UnknownOperation);
            }
            if query.scope_id.is_none() {
                return Err(StoreError::InvalidField {
                    field: "scope_id",
                    reason: "GetEvidencePack requires an exact scope",
                });
            }
            if query.state_fence != self.fence {
                return Err(StoreError::FenceMismatch);
            }
            let (subject, bound) = Self::selectors(&query.parameters)?;
            let limit = usize::try_from(bound).map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must be within the catalogue bound",
            })?;
            let records: Vec<Value> = self
                .captured
                .iter()
                .filter(|captured| *captured == &subject)
                .take(limit)
                .map(|captured| json!({"subject": captured}))
                .collect();
            let response = NamedReadResponse {
                operation: query.operation,
                state_fence: query.state_fence.clone(),
                revision_heads: Vec::new(),
                payload: json!({
                    "version": 1,
                    "subject": subject,
                    "max_records": bound,
                    "records": records,
                }),
            };
            response.validate()?;
            Ok(response)
        }
    }

    #[test]
    fn local_read_bridge_serves_captured_evidence_and_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence(1)?;
        let client = test_client(&fence)?;
        assert_eq!(
            client.snapshot.state_fence(),
            fence,
            "the test client must bind the admitted fence or every leg fails before reading"
        );

        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &fence, &tool_digest(&tool)?)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("test runtime: {error}"))?;

        // Capture an observation, then bridge eliot.query for the captured
        // subject: the exact evidence record, provenance, and fence return.
        let mut table = EvidenceTable::new(fence.clone());
        table.capture("evidence-alpha");
        let service = ReadService::new(table);
        let result = runtime.block_on(KernelContextReadClient::execute_local_read(
            &service, &fence, &envelope, &tool,
        ))?;
        assert_eq!(result.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(result.state_fence, fence);
        let records = result
            .payload
            .get("records")
            .and_then(Value::as_array)
            .ok_or("evidence records must ride the payload")?;
        assert_eq!(
            records.len(),
            1,
            "the captured subject reads back exactly once"
        );
        assert_eq!(
            records[0].get("subject").and_then(Value::as_str),
            Some("evidence-alpha"),
            "the readback record is the captured evidence, never a substitute"
        );
        assert_eq!(
            result.provenance,
            ReadProvenance {
                handles: Vec::new(),
                disposition: ProvenanceDisposition::Unavailable,
            },
            "the readback provenance is the exact facade lineage"
        );

        // A wrong fence fails closed before any read: FenceMismatch, never
        // Ok-empty.
        let wrong = test_fence(2)?;
        let wrong_envelope = test_envelope("eliot.query", &wrong, &tool_digest(&tool)?)?;
        let fenced = runtime.block_on(KernelContextReadClient::execute_local_read(
            &service,
            &fence,
            &wrong_envelope,
            &tool,
        ));
        assert!(
            matches!(
                fenced,
                Err(ReadError::Store(StoreReadFailure::FenceMismatch))
            ),
            "a wrong fence must fail closed as FenceMismatch, got {fenced:?}"
        );

        // Packet pairs stay admission-only: Unavailable, never a read.
        let packet = packet_tool();
        let packet_envelope = test_envelope("eliot.packet", &fence, &tool_digest(&packet)?)?;
        let admitted_only = runtime.block_on(KernelContextReadClient::execute_local_read(
            &service,
            &fence,
            &packet_envelope,
            &packet,
        ));
        assert!(
            matches!(
                admitted_only,
                Err(ReadError::Store(StoreReadFailure::Unavailable))
            ),
            "packet must stay admission-only as Unavailable, got {admitted_only:?}"
        );

        // The production forwarding bridge fails closed before transport: a
        // wrong fence is Contract (not a Kernel round-trip), never Ok-empty.
        let transport_fenced = runtime.block_on(forward_admitted_local_read(
            &client,
            wrong_envelope,
            tool.clone(),
        ));
        assert!(
            matches!(transport_fenced, Err(KernelPortError::Contract(_))),
            "a wrong fence must fail the local_read transport closed as Contract, got {transport_fenced:?}"
        );

        // A malformed pair is Contract before transport is touched.
        let malformed = runtime.block_on(forward_admitted_local_read(
            &client,
            envelope.clone(),
            json!("not-an-object"),
        ));
        assert!(
            matches!(malformed, Err(KernelPortError::Contract(_))),
            "a malformed pair must fail the local_read transport closed as Contract, got {malformed:?}"
        );
        Ok(())
    }

    #[test]
    fn local_read_claim_submit_wire_shapes_parse_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{parse_local_read_claimed_pair, parse_local_read_submit_outcome};
        use crate::LocalReadSubmitOutcome;

        // A null pair is the empty-queue backoff signal, not an error.
        let empty = serde_json::json!({ "pair": null });
        assert_eq!(
            parse_local_read_claimed_pair(&empty)
                .map_err(|error| format!("empty claim must not fail: {error}"))?,
            None,
            "an empty claim must poll null"
        );

        // A claimed pair round-trips the exact admitted envelope and tool.
        let fence = test_fence(1)?;
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &fence, &tool_digest(&tool)?)?;
        let answer = serde_json::json!({
            "pair": {
                "envelope": envelope.clone(),
                "tool": tool.clone(),
            }
        });
        let (claimed_envelope, claimed_tool) = parse_local_read_claimed_pair(&answer)
            .map_err(|error| format!("queued pair must parse: {error}"))?
            .ok_or("a queued pair must claim")?;
        assert_eq!(
            claimed_envelope.envelope_sha256, envelope.envelope_sha256,
            "the claim returns the exact admitted envelope"
        );
        assert_eq!(claimed_tool, tool, "the claim returns the exact tool bytes");

        // A pair omitting the envelope, a non-pair value, and an answer
        // omitting the pair all fail closed — never Ok-empty, never invented.
        for bad in [
            serde_json::json!({ "pair": { "tool": tool.clone() } }),
            serde_json::json!({ "pair": "not-a-pair" }),
            serde_json::json!({ "operation": "local_read_claim" }),
        ] {
            assert!(
                parse_local_read_claimed_pair(&bad).is_err(),
                "a malformed claim answer must fail closed, got {bad}"
            );
        }

        // Accepted persists (exact replays included); expired is the expected
        // deadline race, never a transport error.
        assert_eq!(
            parse_local_read_submit_outcome(&serde_json::json!({ "accepted": true }))
                .map_err(|error| format!("accepted must parse: {error}"))?,
            LocalReadSubmitOutcome::Accepted,
        );
        assert_eq!(
            parse_local_read_submit_outcome(
                &serde_json::json!({ "accepted": false, "expired": true })
            )
            .map_err(|error| format!("expired must parse: {error}"))?,
            LocalReadSubmitOutcome::Expired,
        );
        for bad in [
            serde_json::json!({}),
            serde_json::json!({ "accepted": false }),
            serde_json::json!({ "accepted": "yes" }),
        ] {
            assert!(
                parse_local_read_submit_outcome(&bad).is_err(),
                "an unknown submit answer must fail closed, got {bad}"
            );
        }
        Ok(())
    }
}
