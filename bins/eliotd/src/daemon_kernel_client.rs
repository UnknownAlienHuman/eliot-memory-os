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
    AgentActivationResultSubmit, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload,
    ProtocolVersion, RequestIdentity,
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
