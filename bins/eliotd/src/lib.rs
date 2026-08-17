//! Production N4 Governor daemon composition root.
//!
//! `eliotd` owns application scheduling and the pure Governor projections. It
//! does not own a Kernel, a canonical store client, a store adapter, or a
//! physical process executor. Canonical transitions leave this process only
//! through the neutral authenticated [`KernelTransitionPort`].

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractVersion, OperationId, ProductId,
    RequestId, RequestMetadata, ResourceGeneration, SourceId, StateFence,
};
use eliot_governor::{
    CompositionError, CompositionReadiness, GovernorComposition, GovernorGenesisRequest,
    GovernorLaunchConfig, KernelDurableJobPort, KernelGenerationPort, KernelGenerationSnapshot,
    KernelGenerationSnapshotProvider, KernelNamedReadReply, KernelNamedReadRequest,
    KernelPortError, KernelPortFuture, KernelRecoveryPort, KernelServiceRecovery,
    KernelTransitionPort, QueueLimits,
};
use eliot_maintenance::MaintenanceJob;
use eliot_platform_windows::{
    NamedPipePeerExpectation, ProtectedPathError, ProtectedPathLease, prepare_protected_directory,
    protected_program_data_path,
};
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange,
    ProtocolVersion, RequestIdentity, ServerHello,
};
use eliot_receipts::RequestBinding;
use eliot_runtime_contracts::{ModuleContract, ModuleGeneration, ModuleGenerationState};
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, ScopeRevisionView,
    StoreHealth, WriteReceipt,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};

/// Stable daemon identity.
pub const SERVICE_NAME: &str = "eliotd";
/// Stable daemon protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.daemon.v1";
/// Protected Host-approved launch configuration relative to `ProgramData`.
pub const PROTECTED_CONFIG_RELATIVE: &str = r"Eliot\governor\eliotd.json";
/// Protected daemon state directory relative to `ProgramData`.
pub const PROTECTED_STATE_RELATIVE: &str = r"Eliot\governor\state";
/// Maximum accepted launch-config bytes.
pub const MAX_CONFIG_BYTES: u64 = 128 * 1024;
/// Host-approved Kernel front-door identity. The Kernel client contract must
/// eventually provide these values through the protected handoff; until then
/// this fixed identity is deliberately fail-closed by the authenticated
/// handshake.
const KERNEL_PIPE_NAME: &str = r"\\.\pipe\eliot\kernel\frontdoor";
const KERNEL_SYSTEM_SID: &str = "S-1-5-18";
const KERNEL_SYSTEM_SESSION: u32 = 0;

#[derive(Clone, Debug)]
struct KernelLaunchBinding {
    kernel_pipe_name: String,
    expected_kernel_sid: String,
    expected_kernel_session_id: u32,
    module_generation: ResourceGeneration,
    authority_epoch: AuthorityEpoch,
    state_fence: StateFence,
    launch_nonce: String,
    artifact_hash: String,
}

/// Errors raised while loading or composing the daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Protected `ProgramData` path policy rejected the requested object.
    #[error("protected daemon path: {0}")]
    Protected(#[from] ProtectedPathError),
    /// The protected launch file was not a valid typed config.
    #[error("launch configuration: {0}")]
    LaunchConfig(String),
    /// Exact Kernel/provider or Governor recovery admission failed.
    #[error("Governor composition: {0}")]
    Composition(#[from] CompositionError),
    /// Authenticated Kernel B1 transport or admission failed.
    #[error("Kernel B1 transport: {0}")]
    Kernel(String),
    /// A second daemon owner cannot be admitted in this process.
    #[error("daemon lifecycle: {0}")]
    Lifecycle(String),
}

/// Typed protected launch inputs. The values are read from the fixed
/// `ProgramData` path; environment variables, current directory and arbitrary
/// caller paths are not authority sources.
#[derive(Debug)]
pub struct DaemonConfig {
    launch: GovernorLaunchConfig,
    config_path: PathBuf,
    state_root: PathBuf,
    config_lease: Option<ProtectedPathLease>,
    kernel_binding: KernelLaunchBinding,
}

impl DaemonConfig {
    /// Loads the Host-approved launch file through a bounded protected read.
    pub fn load_protected() -> Result<Self, DaemonError> {
        let config_path = protected_program_data_path(PROTECTED_CONFIG_RELATIVE)?;
        let config_lease = ProtectedPathLease::open_existing_absolute(&config_path)?;
        let bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let launch: GovernorLaunchConfig = serde_json::from_slice(&bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        let mut config = Self::from_launch(launch, config_path)?;
        config.config_lease = Some(config_lease);
        Ok(config)
    }

    /// Creates a config only for the exact protected path used by production.
    /// This constructor is also useful to tests that provide a protected
    /// fixture; it rejects arbitrary roots before composition.
    pub fn from_launch(
        launch: GovernorLaunchConfig,
        config_path: PathBuf,
    ) -> Result<Self, DaemonError> {
        launch.validate()?;
        let expected_config = protected_program_data_path(PROTECTED_CONFIG_RELATIVE)?;
        if config_path != expected_config {
            return Err(DaemonError::LaunchConfig(
                "launch config path is not the fixed ProgramData identity".to_owned(),
            ));
        }
        let state_root = protected_program_data_path(PROTECTED_STATE_RELATIVE)?;
        let kernel_binding = KernelLaunchBinding {
            kernel_pipe_name: KERNEL_PIPE_NAME.to_owned(),
            expected_kernel_sid: KERNEL_SYSTEM_SID.to_owned(),
            expected_kernel_session_id: KERNEL_SYSTEM_SESSION,
            module_generation: launch.kernel.generation,
            authority_epoch: launch.kernel.authority_epoch,
            state_fence: StateFence::new(launch.kernel.authority_epoch, launch.kernel.generation),
            launch_nonce: format!("eliotd:{}", launch.instance_id),
            artifact_hash: launch.kernel.artifact_digest.clone(),
        };
        Ok(Self {
            launch,
            config_path,
            state_root,
            config_lease: None,
            kernel_binding,
        })
    }

    /// Returns the immutable Host-approved launch config.
    #[must_use]
    pub const fn launch(&self) -> &GovernorLaunchConfig {
        &self.launch
    }

    /// Returns the retained protected config identity path.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the protected daemon state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

/// Authenticated, reconnectable B1 client used by the daemon composition.
/// The client owns only EBP transport/session proof; Kernel remains the sole
/// process, Store, and canonical authority owner.
pub struct DaemonKernelClient {
    launch: GovernorLaunchConfig,
    kernel_binding: KernelLaunchBinding,
    connection_id: String,
    snapshot: KernelGenerationSnapshot,
    request_counter: Arc<AtomicU64>,
}

#[derive(Debug, Error)]
enum KernelClientError {
    #[cfg(not(windows))]
    #[error("Kernel client is unavailable on this target")]
    Unsupported,
    #[error("Kernel client contract: {0}")]
    Contract(String),
    #[error("Kernel client unknown outcome: {0}")]
    Unknown(String),
    #[error("Kernel transport: {0}")]
    Transport(String),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireOutcome {
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
}

impl DaemonKernelClient {
    /// Establishes an authenticated Kernel session and retrieves the
    /// server-owned generation snapshot before returning a client.
    pub fn connect(config: &DaemonConfig) -> Result<Arc<Self>, DaemonError> {
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
                .map_err(|error| DaemonError::Kernel(error.to_string()))?;
            let snapshot = runtime
                .block_on(client.snapshot_request())
                .map_err(|error| DaemonError::Kernel(error.to_string()))?;
            let mut client = client;
            client.snapshot = snapshot;
            Ok(Arc::new(client))
        }
        #[cfg(not(windows))]
        {
            let _ = client;
            Err(DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    /// Sends the authenticated daemon-ready disposition to Kernel.
    pub fn report_ready(&self) -> Result<(), DaemonError> {
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(self.transact_async(
                    "daemon_ready",
                    serde_json::json!({
                        "generation": self.snapshot.generation.value(),
                        "authority_epoch": self.snapshot.authority_epoch.value(),
                    }),
                ))
                .map(|_| ())
                .map_err(|error| DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            Err(DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    /// Closes normal Kernel admission while retaining the generation for
    /// operator-visible health and recovery evidence.
    pub fn report_degraded(&self, reason: impl Into<String>) -> Result<(), DaemonError> {
        let reason = reason.into();
        if reason.trim().is_empty() || reason.chars().any(char::is_control) || reason.len() > 512 {
            return Err(DaemonError::Kernel(
                "daemon degradation reason is blank, unbounded, or contains control characters"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(self.transact_async(
                    "daemon_degraded",
                    serde_json::json!({
                        "reason": reason,
                    }),
                ))
                .map(|_| ())
                .map_err(|error| DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Err(DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    /// Sends a bounded fatal lifecycle disposition to Kernel. The Kernel owns
    /// fencing and relaunch; this client never mutates canonical state.
    pub fn report_fatal(&self, reason: impl Into<String>) -> Result<(), DaemonError> {
        let reason = reason.into();
        if reason.trim().is_empty() || reason.chars().any(char::is_control) || reason.len() > 512 {
            return Err(DaemonError::Kernel(
                "daemon fatal reason is blank, unbounded, or contains control characters"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(
                    self.transact_async("daemon_fatal", serde_json::json!({ "reason": reason })),
                )
                .map(|_| ())
                .map_err(|error| DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Err(DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    #[cfg(windows)]
    async fn snapshot_request(&self) -> Result<KernelGenerationSnapshot, KernelClientError> {
        let value = self
            .transact_async(
                "snapshot",
                serde_json::json!({
                    "protected_snapshot_digest": self.launch.protected_snapshot_digest,
                }),
            )
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
            protected_snapshot_digest: self.launch.protected_snapshot_digest.clone(),
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
    async fn transact_async(
        &self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelClientError> {
        let (mut transport, limits) = self.connect_transport().await?;
        let identity = self.next_identity(operation)?;
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
    async fn transact_async(
        &self,
        _operation: &str,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelClientError> {
        Err(KernelClientError::Unsupported)
    }

    #[cfg(windows)]
    async fn connect_transport(
        &self,
    ) -> Result<(NamedPipeTransport, TransportLimits), KernelClientError> {
        let expectation = NamedPipePeerExpectation::new(
            self.kernel_binding.expected_kernel_sid.as_str(),
            self.kernel_binding.expected_kernel_session_id,
        )
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated(
            self.kernel_binding.kernel_pipe_name.as_str(),
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .map_err(|error| KernelClientError::Transport(error.to_string()))?;
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

    fn request_blocking(
        &self,
        operation: &'static str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError> {
        let client = self.clone_for_future();
        Self::blocking(async move { client.transact_async(operation, payload).await })
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

fn kind_value(
    value: &serde_json::Value,
    expected_kind: &str,
) -> Result<serde_json::Value, KernelPortError> {
    let object = value.as_object().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed application value is not an object".to_owned())
    })?;
    if object.get("kind").and_then(serde_json::Value::as_str) != Some(expected_kind) {
        return Err(KernelPortError::Contract(format!(
            "Kernel returned unexpected application kind; expected {expected_kind}"
        )));
    }
    object.get("value").cloned().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed value is missing payload".to_owned())
    })
}

impl KernelGenerationSnapshotProvider for DaemonKernelClient {
    fn snapshot(&self) -> &KernelGenerationSnapshot {
        &self.snapshot
    }
}

impl KernelTransitionPort for DaemonKernelClient {
    fn apply_prepared<'a>(
        &'a self,
        request: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        let request = request.clone();
        Box::pin(async move {
            if request.source_id.as_str() != SERVICE_NAME {
                return Err(KernelPortError::Contract(
                    "daemon transition source is not the fixed eliotd identity".to_owned(),
                ));
            }
            let value = self
                .transact_async(
                    "apply_prepared",
                    serde_json::json!({
                        "transition": transition,
                        "expected_revision_heads": expected_revision_heads,
                        "expected_ordering_heads": expected_ordering_heads,
                    }),
                )
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "write_receipt")?;
            serde_json::from_value(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))
        })
    }

    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        Box::pin(async move {
            let value = self
                .transact_async(
                    "receipt",
                    serde_json::json!({ "operation_id": operation_id }),
                )
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "receipt")?;
            serde_json::from_value(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))
        })
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        Box::pin(async move {
            let value = self
                .transact_async("health", serde_json::json!({}))
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "health")?;
            serde_json::from_value(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))
        })
    }
}

impl KernelRecoveryPort for DaemonKernelClient {
    fn named_read(
        &self,
        request: KernelNamedReadRequest,
    ) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
        let value =
            self.request_blocking("named_read", serde_json::json!({ "request": request }))?;
        let value = kind_value(&value, "named_read")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn initialize_governor_genesis(
        &self,
        request: &GovernorGenesisRequest,
    ) -> Result<(), KernelPortError> {
        let _ = self.request_blocking(
            "initialize_governor_genesis",
            serde_json::json!({ "request": request }),
        )?;
        Ok(())
    }

    fn canonical_scope(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<ScopeRevisionView, KernelPortError> {
        let value = self.request_blocking(
            "canonical_scope",
            serde_json::json!({
                "state_fence": state_fence,
                "protected_snapshot_digest": protected_snapshot_digest,
            }),
        )?;
        let value = kind_value(&value, "canonical_scope")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn receipts(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<WriteReceipt>, KernelPortError> {
        let value = self.request_blocking(
            "receipts",
            serde_json::json!({
                "state_fence": state_fence,
                "protected_snapshot_digest": protected_snapshot_digest,
            }),
        )?;
        let value = kind_value(&value, "receipts")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn durable_jobs(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<MaintenanceJob>, KernelPortError> {
        let value = self.request_blocking(
            "durable_jobs",
            serde_json::json!({
                "state_fence": state_fence,
                "protected_snapshot_digest": protected_snapshot_digest,
            }),
        )?;
        let value = kind_value(&value, "durable_jobs")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn services(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
        let value = self.request_blocking(
            "services",
            serde_json::json!({
                "state_fence": state_fence,
                "protected_snapshot_digest": protected_snapshot_digest,
            }),
        )?;
        let value = kind_value(&value, "services")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }
}

impl KernelDurableJobPort for DaemonKernelClient {
    fn load_durable_job(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<Option<MaintenanceJob>, KernelPortError> {
        let value = self.request_blocking(
            "load_durable_job",
            serde_json::json!({ "job_id": job_id, "state_fence": state_fence }),
        )?;
        let value = kind_value(&value, "durable_job")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError> {
        let _ = self.request_blocking("save_durable_job", serde_json::json!({ "job": job }))?;
        Ok(())
    }
}

fn expected_snapshot(
    launch: &GovernorLaunchConfig,
) -> Result<KernelGenerationSnapshot, DaemonError> {
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
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    Ok(snapshot)
}

#[cfg(windows)]
fn client_hello(binding: &KernelLaunchBinding) -> Result<ClientHello, KernelClientError> {
    let module_id = ContractId::new("eliotd")
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(binding.artifact_hash.as_str())
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
fn validate_server_hello(
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
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello generation snapshot mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn operation_payload(
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

fn kernel_port_error(error: KernelClientError) -> KernelPortError {
    match error {
        KernelClientError::Contract(error) => KernelPortError::Contract(error),
        KernelClientError::Unknown(error) => KernelPortError::Unknown(error),
        KernelClientError::Transport(error) => KernelPortError::NotAdmitted(error),
        #[cfg(not(windows))]
        KernelClientError::Unsupported => {
            KernelPortError::NotAdmitted("Windows Kernel transport is required".to_owned())
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

fn unix_ms_i64() -> i64 {
    i64::try_from(unix_ms()).unwrap_or(i64::MAX)
}

/// Readiness/status projection emitted by the daemon. It is derived only
/// after exact Kernel and recovery admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonStatus {
    /// Service identity.
    pub service: String,
    /// Daemon protocol revision.
    pub protocol: String,
    /// Active Kernel resource generation.
    pub generation: u64,
    /// Active authority epoch.
    pub authority_epoch: u64,
    /// Whether the owner set is admitted and accepting work.
    pub ready: bool,
    /// Bounded health projection for operators and the control loop.
    pub health: String,
    /// Whether normal admission is closed while the process remains observable.
    pub degraded: bool,
}

/// The one production daemon composition. Application scheduling belongs here;
/// physical process execution and canonical persistence remain outside it.
pub struct DaemonComposition {
    governor: GovernorComposition<dyn KernelGenerationPort>,
    config_lease: ProtectedPathLease,
    state_lease: ProtectedPathLease,
    config_path: PathBuf,
    state_root: PathBuf,
    started: bool,
}

impl DaemonComposition {
    /// Composes the daemon only from a Host-approved authenticated Kernel port.
    ///
    /// The port is retained exactly once. Its snapshot and the recovered owner
    /// set are checked before this method returns a composition marked ready.
    pub fn start(
        mut config: DaemonConfig,
        kernel: Arc<dyn KernelGenerationPort>,
    ) -> Result<Self, DaemonError> {
        let config_lease = config.config_lease.take().ok_or_else(|| {
            DaemonError::Lifecycle(
                "production start requires the retained Host-approved config lease".to_owned(),
            )
        })?;
        config_lease.verify_stable_identity()?;
        let retained_bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let retained_launch: GovernorLaunchConfig = serde_json::from_slice(&retained_bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        if retained_launch != config.launch {
            return Err(DaemonError::Lifecycle(
                "retained config bytes changed before composition".to_owned(),
            ));
        }
        prepare_protected_directory(config.state_root())?;
        let state_file = config.state_root().join("daemon.lifecycle");
        let state_lease = ProtectedPathLease::open_or_create(
            Path::new(PROTECTED_STATE_RELATIVE).join("daemon.lifecycle"),
        )?;
        if state_lease.path() != state_file {
            return Err(DaemonError::Lifecycle(
                "protected lifecycle identity changed during composition".to_owned(),
            ));
        }
        let governor =
            GovernorComposition::new(kernel, &config.launch().kernel, QueueLimits::default())?;
        Ok(Self {
            governor,
            config_lease,
            state_lease,
            config_path: config.config_path,
            state_root: config.state_root,
            started: true,
        })
    }

    /// Returns the admitted Kernel snapshot.
    #[must_use]
    pub fn kernel_snapshot(&self) -> &eliot_governor::KernelGenerationSnapshot {
        self.governor.kernel_snapshot()
    }

    /// Returns the retained protected config path, for diagnostics only.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the retained protected daemon state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Computes the digest of the provider-owned recovery snapshot admitted at
    /// startup. This is evidence only; Kernel remains the authority.
    pub fn recovery_digest(&self) -> Result<String, DaemonError> {
        let bytes = serde_json::to_vec(self.governor.recovery()).map_err(|error| {
            DaemonError::Composition(CompositionError::Recovery(error.to_string()))
        })?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Returns the exact readiness state.
    #[must_use]
    pub const fn readiness(&self) -> CompositionReadiness {
        self.governor.readiness()
    }

    /// Returns a bounded status projection.
    #[must_use]
    pub fn status(&self) -> DaemonStatus {
        let snapshot = self.kernel_snapshot();
        DaemonStatus {
            service: SERVICE_NAME.to_owned(),
            protocol: PROTOCOL_VERSION.to_owned(),
            generation: snapshot.generation.value(),
            authority_epoch: snapshot.authority_epoch.value(),
            ready: self.started && self.readiness() == CompositionReadiness::Ready,
            health: if !self.started {
                "stopped".to_owned()
            } else if self.readiness() == CompositionReadiness::Ready {
                "healthy".to_owned()
            } else {
                "degraded".to_owned()
            },
            degraded: !self.started || self.readiness() != CompositionReadiness::Ready,
        }
    }

    /// Stops the one daemon owner and releases protected handles together.
    pub fn shutdown(mut self) -> Result<(), DaemonError> {
        if !self.started {
            return Err(DaemonError::Lifecycle(
                "daemon shutdown was already completed".to_owned(),
            ));
        }
        self.governor.stop();
        self.started = false;
        let _ = (&self.config_lease, &self.state_lease);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_config_has_no_root_or_environment_override() {
        assert!(!PROTECTED_CONFIG_RELATIVE.contains("ProgramData"));
        assert!(!PROTECTED_CONFIG_RELATIVE.contains(".."));
        assert!(!PROTECTED_STATE_RELATIVE.contains(".."));
    }

    #[test]
    fn application_payload_always_carries_a_closed_operation_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = operation_payload("health", serde_json::json!({}))?;
        assert_eq!(payload["operation"], "health");
        assert!(operation_payload("health", serde_json::json!([])).is_err());
        Ok(())
    }

    #[test]
    fn unknown_kernel_outcome_is_not_treated_as_success() -> Result<(), Box<dyn std::error::Error>>
    {
        let outcome: WireOutcome = serde_json::from_value(serde_json::json!({
            "status": "unknown",
            "reason": "delivery outcome was not proven"
        }))?;
        assert!(matches!(outcome, WireOutcome::Unknown { .. }));
        Ok(())
    }

    #[test]
    fn snapshot_expectation_rejects_unbound_digest() -> Result<(), Box<dyn std::error::Error>> {
        let launch = GovernorLaunchConfig {
            instance_id: "test-instance".to_owned(),
            kernel: eliot_governor::KernelGenerationExpectation {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "local-user".to_owned(),
                generation: ResourceGeneration::new(1)?,
                authority_epoch: AuthorityEpoch::new(1)?,
            },
            protected_snapshot_digest: "c".repeat(64),
        };
        assert!(launch.validate().is_err());
        Ok(())
    }
}
