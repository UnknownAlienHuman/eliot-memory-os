//! The Kernel composition root.
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{ArtifactId, AuthorityEpoch, ContractId, ResourceGeneration, StateFence};
use eliot_ipc::{HandshakeResult, PeerIdentity, ServerHandshakePolicy, Session, TransportLimits};
use eliot_kernel_core::{GenerationRoute, GenerationRouter, RouteScope};
use eliot_kernel_service::{
    KernelControlCommand, KernelService, KernelServiceError, KernelServiceState,
};
use eliot_ors::{CanonicalEvidenceProvider, OrsCoordinator, RedbRecoveryStore};
use eliot_platform::PortError;
use eliot_platform_windows::WindowsPlatform;
use eliot_process::{
    ProcessExecutionError, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_runtime::{Runtime, RuntimeConfig, ShutdownOutcome};
use eliot_runtime_contracts::{HealthVector, ModuleGeneration, ModuleGenerationState};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use eliot_ipc::NamedPipeServer;

/// Stable Kernel process identity and wire revision.
pub const SERVICE_NAME: &str = "eliot-kernel";
pub const PROTOCOL_VERSION: &str = "eliot.kernel.v1";
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\eliot\kernel\frontdoor";

/// The only transport implementation admitted by the Windows-first Kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcImplementation {
    /// Local authenticated EBP/1 named pipe.
    WindowsNamedPipe { name: String },
}

impl IpcImplementation {
    fn new(name: impl Into<String>) -> Result<Self, KernelBuildError> {
        let name = name.into();
        eliot_ipc::validate_pipe_name(&name).map_err(KernelBuildError::Transport)?;
        Ok(Self::WindowsNamedPipe { name })
    }

    /// Returns the selected transport name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::WindowsNamedPipe { name } => name,
        }
    }

    /// Returns the transport limits selected by the Kernel composition.
    #[must_use]
    pub const fn limits(&self) -> TransportLimits {
        TransportLimits {
            max_frame_bytes: eliot_protocol::MAX_FRAME_BYTES,
            queue_capacity: 128,
            queue_bytes: 8 * 1024 * 1024,
            control_reserve: 4,
            operation_timeout: Duration::from_secs(30),
        }
    }

    /// Performs the complete server-authoritative principal/session binding.
    ///
    /// The peer must already be authenticated by the platform transport.  A
    /// client assertion alone is never promoted into Kernel authority.
    pub fn bind_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
        policy: &ServerHandshakePolicy,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        Session::establish_with_server(connection_id, peer, client, policy)
    }
}

/// Explicit construction input for the Kernel process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelConfig {
    /// Existing absolute WorkScope root bound to the platform adapter.
    pub work_root: PathBuf,
    /// Local pipe selected once by the composition root.
    pub pipe_name: String,
}

impl KernelConfig {
    /// Creates the production configuration using the canonical pipe.
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
        }
    }
}

/// Errors raised before the Kernel is admitted to its service loop.
#[derive(Debug)]
pub enum KernelBuildError {
    /// The platform adapter rejected the WorkScope root.
    Platform(PortError),
    /// The selected transport is not valid.
    Transport(eliot_ipc::TransportError),
    /// The bounded runtime rejected its fixed production policy.
    Runtime(eliot_runtime::ConfigError),
    /// The durable ORS store could not be opened.
    Ors(String),
    /// The generation route could not be initialized.
    Core(String),
    /// The Kernel lifecycle gateway could not be initialized.
    Service(String),
    /// The platform could not bind the authenticated local front door.
    Principal(String),
}

impl fmt::Display for KernelBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform composition failed: {error}"),
            Self::Transport(error) => write!(f, "IPC composition failed: {error}"),
            Self::Runtime(error) => write!(f, "runtime composition failed: {error:?}"),
            Self::Ors(error) => write!(f, "ORS composition failed: {error}"),
            Self::Core(error) => write!(f, "Kernel decision composition failed: {error}"),
            Self::Service(error) => write!(f, "Kernel service composition failed: {error}"),
            Self::Principal(error) => write!(f, "principal composition failed: {error}"),
        }
    }
}

impl std::error::Error for KernelBuildError {}

/// The complete, production Kernel composition.
pub struct KernelComposition {
    runtime: Runtime,
    platform: WindowsPlatform,
    ipc: IpcImplementation,
    ors: OrsCoordinator<RedbRecoveryStore>,
    service: Mutex<KernelService>,
    generations: Mutex<GenerationRouter>,
    front_door_policy: ServerHandshakePolicy,
    process_executor: WindowsProcessExecutor,
}

/// Fail-closed authority adapter used until the Host handoff supplies the
/// active P-07 dispatch controller.  The physical executor is still composed
/// once and owns Job/descendant cleanup; no alternate authority is invented.
struct HandoffDispatchPort;

impl DispatchValidationPort for HandoffDispatchPort {
    fn validate_and_consume(
        &self,
        _request: ProcessRequest,
        _observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "Kernel Host handoff has not activated process dispatch authority".to_owned(),
        ))
    }
}

impl KernelComposition {
    /// Builds all lower-layer surfaces once and binds them to one runtime.
    ///
    /// The default authority remains fail-closed until Host performs its
    /// authenticated handoff.  Integrations with those provider proofs use
    /// [`Self::new_with_adapters`].
    pub fn new(config: KernelConfig) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = OrsCoordinator::open(&ors_path)
            .map_err(|error| KernelBuildError::Ors(error.to_string()))?;
        Self::assemble(config, ors, Arc::new(HandoffDispatchPort))
    }

    /// Builds the production composition with Host-owned canonical evidence
    /// and the active P-07 dispatch authority adapters.
    pub fn new_with_adapters(
        config: KernelConfig,
        authority: Arc<dyn DispatchValidationPort>,
        evidence: Arc<dyn CanonicalEvidenceProvider>,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = OrsCoordinator::new(
            RedbRecoveryStore::open_with_evidence(&ors_path, evidence)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble(config, ors, authority)
    }

    fn assemble(
        config: KernelConfig,
        ors: OrsCoordinator<RedbRecoveryStore>,
        authority: Arc<dyn DispatchValidationPort>,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            WindowsPlatform::new(config.work_root).map_err(KernelBuildError::Platform)?;
        let ipc = IpcImplementation::new(config.pipe_name)?;
        let authority_epoch = AuthorityEpoch::genesis();
        let generation = ResourceGeneration::genesis();
        let mut generations = GenerationRouter::new();
        generations
            .register(
                GenerationRoute::new(
                    RouteScope::new("daemon")
                        .map_err(|error| KernelBuildError::Core(error.to_string()))?,
                    generation,
                    authority_epoch,
                )
                .map_err(|error| KernelBuildError::Core(error.to_string()))?,
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let service = KernelService::new(dispatch_key(&work_root), 4, 128)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let module_id =
            ContractId::new("eliotd").map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let artifact_id = ArtifactId::new("eliotd-child-generation")
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let module_generation = ModuleGeneration {
            module_id: module_id.clone(),
            generation,
            artifact_id,
            state: ModuleGenerationState::Starting,
            health: HealthVector::healthy(),
            state_fence: StateFence::new(authority_epoch, generation),
        };
        let front_door_policy = ServerHandshakePolicy {
            protocol_range: eliot_protocol::ProtocolRange {
                minimum: eliot_protocol::ProtocolVersion::CURRENT,
                maximum: eliot_protocol::ProtocolVersion::CURRENT,
            },
            module_id: module_id.as_str().to_owned(),
            module_generation,
            launch_nonce: format!("kernel-{}", std::process::id()),
            allowed_capabilities: vec!["daemon".to_owned()],
            allowed_privacy_classes: vec!["PUBLIC".to_owned()],
            allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
            session_principal_binding: "local-user".to_owned(),
            control_channel: ipc.name().to_owned(),
            heartbeat_ms: 1_000,
            config_snapshot: serde_json::json!({
                "service": SERVICE_NAME,
                "protocol": PROTOCOL_VERSION,
                "generation": generation.value(),
            }),
            max_frame: eliot_protocol::MAX_FRAME_BYTES as u32,
        };
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 128,
                control_reserve: 4,
                concurrency: 4,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 3,
                restart_window: Duration::from_secs(60),
                restart_backoff: Duration::from_millis(100),
                shutdown_grace: Duration::from_secs(5),
            },
            None,
        )
        .map_err(KernelBuildError::Runtime)?;
        Ok(Self {
            runtime,
            platform,
            ipc,
            ors,
            service: Mutex::new(service),
            generations: Mutex::new(generations),
            front_door_policy,
            process_executor: WindowsProcessExecutor::new(authority),
        })
    }

    /// Returns the selected local IPC implementation.
    #[must_use]
    pub const fn ipc(&self) -> &IpcImplementation {
        &self.ipc
    }

    /// Returns the platform surface owned by this composition.
    #[must_use]
    pub const fn platform(&self) -> &WindowsPlatform {
        &self.platform
    }

    /// Returns the server-owned EBP handshake policy.
    #[must_use]
    pub const fn front_door_policy(&self) -> &ServerHandshakePolicy {
        &self.front_door_policy
    }

    /// Binds an authenticated local peer to the selected principal/session.
    pub fn bind_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        self.ipc
            .bind_session(connection_id, peer, client, &self.front_door_policy)
    }

    /// Binds the authenticated local Windows front door to the current
    /// installation principal.  The returned server must be retained by the
    /// service loop for the lifetime of the accepted connection.
    #[cfg(windows)]
    pub fn bind_authenticated_front_door(&self) -> Result<NamedPipeServer, KernelBuildError> {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        NamedPipeServer::create(self.ipc.name(), &expectation)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Applies one lifecycle command through the sole Kernel transition gateway.
    pub fn apply_control(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        self.service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .apply(command)
    }

    /// Returns the current Kernel service lifecycle state.
    pub fn service_state(&self) -> Result<KernelServiceState, KernelServiceError> {
        Ok(self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .state())
    }

    /// Returns the generation router that owns daemon/child cutovers.
    pub fn generations(&self) -> Result<std::sync::MutexGuard<'_, GenerationRouter>, String> {
        self.generations
            .lock()
            .map_err(|_| "generation router lock poisoned".to_owned())
    }

    /// Exposes the transactional ORS bridge without exposing storage internals.
    #[must_use]
    pub const fn store_bridge(&self) -> &RedbRecoveryStore {
        self.ors.store()
    }

    /// Returns the sole physical ProcessExecutor for child generations.
    #[must_use]
    pub const fn process_executor(&self) -> &WindowsProcessExecutor {
        &self.process_executor
    }

    /// Returns the runtime's protected-control capacity.
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }

    /// Requests shutdown without starting a second lifecycle owner.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        self.runtime.shutdown_handle().request()
    }

    /// Completes the bounded cooperative-then-forced shutdown sequence.
    pub async fn shutdown(&self) -> ShutdownOutcome {
        let _ = self.process_executor.shutdown();
        self.runtime.shutdown().await
    }
}

fn dispatch_key(work_root: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(work_root.as_os_str().to_string_lossy().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
            .to_le_bytes(),
    );
    hasher.finalize().into()
}

/// Resolves and validates the default WorkScope root for the binary entrypoint.
pub fn default_work_root() -> Result<PathBuf, std::io::Error> {
    let root = std::env::var_os("ELIOT_WORK_ROOT")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);
    std::fs::canonicalize(Path::new(&root))
}
