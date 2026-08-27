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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractVersion, ProductId, RequestId,
    RequestMetadata, ResourceGeneration, SourceId,
};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationSnapshot, KernelPortError};
use eliot_protocol::{
    AgentActivationResolutionDecision, AgentActivationResolutionTicket, ClientHello,
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange,
    ProtocolVersion, RequestIdentity, ServerHello,
};
use eliot_receipts::RequestBinding;
use eliot_runtime_contracts::{ModuleContract, ModuleGeneration, ModuleGenerationState};
use serde::Deserialize;
use thiserror::Error;

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
#[cfg(windows)]
use eliot_platform_windows::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};

use super::{
    ELIOTD_RECEIPT_PENDING_REJECTION, KERNEL_OPERATION_TIMEOUT, KernelLaunchBinding,
    PRE_ADMISSION_RETRY_DELAY, PROTOCOL_VERSION, SERVICE_NAME, unix_ms, unix_ms_i64,
};

pub struct DaemonKernelClient {
    launch: GovernorLaunchConfig,
    pub(super) kernel_binding: KernelLaunchBinding,
    pub(super) connection_id: String,
    pub(super) snapshot: KernelGenerationSnapshot,
    request_counter: Arc<AtomicU64>,
}

#[derive(Debug, Error)]
pub(super) enum KernelClientError {
    #[cfg(not(windows))]
    #[error("Kernel client is unavailable on this target")]
    Unsupported,
    #[error("Kernel client contract: {0}")]
    Contract(String),
    #[error("Kernel client unknown outcome: {0}")]
    Unknown(String),
    #[error("Kernel transport: {0}")]
    Transport(String),
    #[error("Kernel pre-admission transport: {0}")]
    PreAdmissionTransport(String),
    #[error("Kernel has not yet published the exact launched eliotd process receipt")]
    PreAdmissionPending,
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

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum WireOutcome {
    Known {
        value: serde_json::Value,
        recovery: Option<serde_json::Value>,
    },
    Partial {
        reason: String,
        value: serde_json::Value,
    },
    Unknown {
        reason: String,
    },
    Error {
        code: String,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelSnapshotWire {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: u64,
    artifact_digest: String,
    protected_snapshot_digest: String,
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

    pub fn connect(config: &super::DaemonConfig) -> Result<Arc<Self>, super::DaemonError> {
        let client = Self {
            launch: config.launch.clone(),
            connection_id: format!(
                "eliotd:{}:{}:{}",
                config.launch.instance_id,
                config.launch.kernel.generation.value(),
                config.launch.kernel.authority_epoch.value()
            ),
            snapshot: expected_snapshot(&config.launch)?,
            kernel_binding: config.kernel_binding.clone(),
            request_counter: Arc::new(AtomicU64::new(1)),
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
                        "authority_epoch": self.snapshot.authority_epoch.value(),
                    }),
                )
            },
            "exact launched process receipt was not published before daemon ready deadline",
        )
        .await
    }

    #[cfg(windows)]
    async fn snapshot_request(&self) -> Result<KernelGenerationSnapshot, KernelClientError> {
        let value = self
            .transact_async("snapshot", serde_json::json!({}))
            .await?;
        let wire: KernelSnapshotWire = serde_json::from_value(value)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let snapshot = KernelGenerationSnapshot {
            service: wire.service,
            protocol: wire.protocol,
            generation: ResourceGeneration::new(wire.generation)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            authority_epoch: AuthorityEpoch::new(wire.authority_epoch)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            artifact_digest: wire.artifact_digest,
            protected_snapshot_digest: wire.protected_snapshot_digest,
            principal: self.launch.kernel.principal.clone(),
        };
        snapshot
            .validate()
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        self.launch
            .kernel
            .admits(&snapshot)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        Ok(snapshot)
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

    fn clone_for_future(&self) -> Arc<Self> {
        Arc::new(Self {
            launch: self.launch.clone(),
            kernel_binding: self.kernel_binding.clone(),
            connection_id: self.connection_id.clone(),
            snapshot: self.snapshot.clone(),
            request_counter: Arc::clone(&self.request_counter),
        })
    }
}

fn expected_snapshot(
    launch: &GovernorLaunchConfig,
) -> Result<KernelGenerationSnapshot, super::DaemonError> {
    let snapshot = KernelGenerationSnapshot {
        service: launch.kernel.service.clone(),
        protocol: launch.kernel.protocol.clone(),
        generation: launch.kernel.generation,
        authority_epoch: launch.kernel.authority_epoch,
        artifact_digest: launch.kernel.artifact_digest.clone(),
        protected_snapshot_digest: launch.protected_snapshot_digest.clone(),
        principal: launch.kernel.principal.clone(),
    };
    snapshot
        .validate()
        .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
    Ok(snapshot)
}

#[cfg(windows)]
fn client_hello(binding: &KernelLaunchBinding) -> Result<ClientHello, KernelClientError> {
    let module_id = ContractId::new("eliotd")
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(binding.daemon_artifact_sha256.as_str())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let contract = ModuleContract {
        module_id: module_id.clone(),
        version: ContractVersion::new(1, 0, 0),
        artifact_id: artifact_id.clone(),
        protocols: vec![PROTOCOL_VERSION.to_owned()],
        required_capabilities: vec!["daemon".to_owned()],
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: SERVICE_NAME.to_owned(),
        failure_domain: "daemon".to_owned(),
        hot_replace: true,
    };
    let generation = ModuleGeneration {
        module_id,
        generation: binding.module_generation,
        artifact_id,
        state: ModuleGenerationState::Starting,
        health: eliot_runtime_contracts::HealthVector::healthy(),
        state_fence: binding.state_fence.clone(),
    };
    Ok(ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: SERVICE_NAME.to_owned(),
        artifact_hash: generation.artifact_id.clone(),
        module_contract: contract,
        module_generation: generation,
        launch_nonce: binding.launch_nonce.clone(),
        capabilities: vec!["daemon".to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
            .map_err(|_| KernelClientError::Contract("maximum frame exceeds u32".to_owned()))?,
        authority_epoch: binding.authority_epoch,
    })
}

#[cfg(windows)]
pub(super) fn is_pre_admission_pending_rejection(
    frame: &Frame,
    expected_connection_id: &str,
) -> bool {
    if frame.validate().is_err()
        || frame.connection_id != expected_connection_id
        || frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Fatal
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return false;
    }
    let ProtocolPayload::Json(serde_json::Value::Object(payload)) = &frame.payload else {
        return false;
    };
    payload.len() == 1
        && payload
            .get("rejection_reason")
            .and_then(serde_json::Value::as_str)
            == Some(ELIOTD_RECEIPT_PENDING_REJECTION)
}

#[cfg(windows)]
pub(super) fn validate_server_hello(
    launch: &GovernorLaunchConfig,
    binding: &KernelLaunchBinding,
    hello: &ServerHello,
) -> Result<(), KernelClientError> {
    hello
        .validate()
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    if hello.selected_protocol != ProtocolVersion::CURRENT
        || hello.authority_epoch != launch.kernel.authority_epoch
        || hello.session_principal_binding
            != format!(
                "sid={};session={}",
                binding.expected_kernel_sid, binding.expected_kernel_session_id
            )
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello principal/protocol/epoch mismatch".to_owned(),
        ));
    }
    let snapshot: KernelSnapshotWire = serde_json::from_value(hello.config_snapshot.clone())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    if snapshot.service != launch.kernel.service
        || snapshot.protocol != launch.kernel.protocol
        || snapshot.generation != launch.kernel.generation.value()
        || snapshot.authority_epoch != launch.kernel.authority_epoch.value()
        || snapshot.artifact_digest != launch.kernel.artifact_digest
        || snapshot.protected_snapshot_digest != launch.protected_snapshot_digest
        || snapshot.protected_snapshot_digest != launch.kernel.protected_snapshot_digest
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello generation snapshot mismatch".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn operation_payload(
    operation: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, KernelClientError> {
    let serde_json::Value::Object(mut object) = payload else {
        return Err(KernelClientError::Contract(
            "Kernel application payload must be an object".to_owned(),
        ));
    };
    object.insert(
        "operation".to_owned(),
        serde_json::Value::String(operation.to_owned()),
    );
    Ok(serde_json::Value::Object(object))
}

pub(super) fn kernel_port_error(error: KernelClientError) -> KernelPortError {
    match error {
        KernelClientError::Contract(error) => KernelPortError::Contract(error),
        KernelClientError::Unknown(error) => KernelPortError::Unknown(error),
        KernelClientError::Transport(error) => KernelPortError::NotAdmitted(error),
        KernelClientError::PreAdmissionTransport(error) => KernelPortError::NotAdmitted(error),
        KernelClientError::PreAdmissionPending => KernelPortError::NotAdmitted(
            "Kernel has not published the exact launched process receipt".to_owned(),
        ),
        #[cfg(not(windows))]
        KernelClientError::Unsupported => {
            KernelPortError::NotAdmitted("Windows Kernel transport is required".to_owned())
        }
    }
}
