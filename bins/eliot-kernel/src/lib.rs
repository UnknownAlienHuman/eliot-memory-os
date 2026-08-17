//! The Kernel composition root.
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, RequestId, RequestMetadata, ResourceGeneration,
    StateFence,
};
use eliot_ipc::{
    HandshakeResult, PeerIdentity, ServerHandshakePolicy, Session, TransportError, TransportLimits,
};
use eliot_kernel_core::{
    AuthoritySnapshotBinding, AuthoritySnapshotBindingWire, DispatchSnapshotCodec, GenerationRoute,
    GenerationRouter, ProcessDispatchAuthorityController, ProcessExecutionReplayAbort,
    ProcessExecutionReplayBegin, ProcessExecutionReplayRecord, ProcessExecutionReplayState,
    ProcessExecutionReplayStore, ProcessExecutionReplayStoreWithAbort, RouteScope,
    process_admission_digest,
};
use eliot_kernel_service::{
    EbpCanonicalStoreClient, HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE,
    KernelControlCommand, KernelControlRequest, KernelControlResponse, KernelService,
    KernelServiceError, KernelServiceState, ProcessAuthorityHandoffDescriptor,
    ProcessExecutionRequest, ProcessExecutionResponse, StoreClientError,
};
#[cfg(test)]
use eliot_ors::CanonicalEvidenceProvider;
use eliot_ors::{
    AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, ProcessEvidenceRecord,
    ProcessStartReplayRecord as OrsReplayRecord, ProcessStartReplayState as OrsReplayState,
};
use eliot_ors::{OperationalRecoveryStore, RedbRecoveryStore};
use eliot_platform::{ClockObservation, PortError};
use eliot_platform_windows::{
    ProtectedPathLease, ProtectedSecret, RetainedProcessPathLease, UserOwnedPathLease,
    UserOwnedRootLease, WindowsPlatform,
};
#[cfg(test)]
use eliot_process::ProcessIntent;
use eliot_process::{
    DispatchAuthorityId, DispatchValidationContext, FencingToken, Generation, KernelDispatchKey,
    PermitIssuance, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionAdmissionRequest,
    ProcessExecutionError, ProcessExecutor, ProcessLaunchAdmission, ProcessOwnerBinding,
    ProcessRequest, ProcessSessionBinding, ProcessStartReceipt, SuspendedLaunchEvidence,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};
use eliot_runtime::{Runtime, RuntimeConfig, ShutdownOutcome};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
    HealthVector, ModuleGeneration, ModuleGenerationState,
};
use eliot_store_api::{
    CanonicalStoreClient, CanonicalValidationSnapshot, OrderingHeadExpectation, PreparedTransition,
    RevisionHead, RevisionHeadExpectation, StateFence as StoreStateFence, StoreError, WriteReceipt,
    canonical_json_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use eliot_ipc::{NamedPipeServer, NamedPipeTransport};
#[cfg(windows)]
use eliot_platform_windows::NamedPipePeerExpectation;

/// Stable Kernel process identity and wire revision.
pub const SERVICE_NAME: &str = "eliot-kernel";
pub const PROTOCOL_VERSION: &str = "eliot.kernel.v1";
pub const DEFAULT_PIPE_NAME: &str = KERNEL_CONTROL_PIPE;
const STORE_BRIDGE_ROUTE: &str = "store_bridge";
const ACTIVE_DAEMON_CALLER: &str = "eliotd";

/// The only transport implementation admitted by the Windows-first Kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
enum IpcImplementation {
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
    fn name(&self) -> &str {
        match self {
            Self::WindowsNamedPipe { name } => name,
        }
    }

    /// Returns the transport limits selected by the Kernel composition.
    #[must_use]
    const fn limits() -> TransportLimits {
        TransportLimits {
            max_frame_bytes: eliot_protocol::MAX_FRAME_BYTES,
            queue_capacity: 128,
            queue_bytes: 8 * 1024 * 1024,
            control_reserve: 4,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

/// Explicit construction input for the Kernel process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelConfig {
    /// Existing absolute `WorkScope` root bound to the platform adapter.
    pub work_root: PathBuf,
    /// Local pipe selected once by the composition root.
    pub pipe_name: String,
    /// Host-approved canonical-store binding. No store gateway is admitted
    /// until this requirement is injected explicitly.
    pub store_bootstrap: Option<HostStoreBootstrapRequirement>,
}

impl KernelConfig {
    /// Creates the production configuration using the canonical pipe.
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            store_bootstrap: None,
        }
    }

    /// Injects the Host-approved canonical-store bootstrap requirement.
    #[must_use]
    pub fn with_store_bootstrap(mut self, requirement: HostStoreBootstrapRequirement) -> Self {
        self.store_bootstrap = Some(requirement);
        self
    }
}

/// Errors raised before the Kernel is admitted to its service loop.
#[derive(Debug)]
pub enum KernelBuildError {
    /// The platform adapter rejected the `WorkScope` root.
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
    /// Host has not injected an approved canonical-store bootstrap binding.
    StoreBootstrapRequired,
    /// This composition already owns its one canonical-store client/gateway.
    StoreAlreadyConnected,
    /// The platform could not bind the authenticated local front door.
    Principal(String),
}

/// Exact protected contour selected for one authority descriptor read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityDescriptorContour {
    /// Current-user portable contour rooted at an existing user-owned directory.
    PortableCurrentUser { root: PathBuf },
    /// Installation-wide protected `ProgramData` contour.
    ProgramData,
}

/// Typed fail-closed result for protected authority preparation.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthorityPreparationError {
    /// The descriptor path could not be retained and read in the selected contour.
    ProtectedInput,
    /// The independent expected digest was malformed or did not match the bytes.
    DigestMismatch,
    /// The descriptor failed its closed contract validation.
    DescriptorInvalid,
    /// Credential Manager did not return an acceptable secret.
    CredentialUnavailable,
    /// The credential was not exactly one non-zero 32-byte dispatch key.
    CredentialInvalid,
    /// The durable one-shot handoff was already reserved, consumed, or unknown.
    Replay,
    /// Durable handoff persistence did not establish a known outcome.
    PersistenceUnknown,
}

impl fmt::Display for AuthorityPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProtectedInput => "protected authority input unavailable",
            Self::DigestMismatch => "authority descriptor digest mismatch",
            Self::DescriptorInvalid => "authority descriptor is invalid",
            Self::CredentialUnavailable => "authority credential unavailable",
            Self::CredentialInvalid => "authority credential is invalid",
            Self::Replay => "authority handoff replay or recovery is required",
            Self::PersistenceUnknown => "authority handoff persistence outcome is unknown",
        })
    }
}

impl std::error::Error for AuthorityPreparationError {}

#[allow(dead_code)]
struct PreparedAuthorityMaterial {
    descriptor: ProcessAuthorityHandoffDescriptor,
    key: KernelDispatchKey,
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
            Self::StoreBootstrapRequired => {
                write!(f, "Host-approved canonical-store bootstrap is required")
            }
            Self::StoreAlreadyConnected => {
                write!(f, "canonical-store client/gateway is already connected")
            }
            Self::Principal(error) => write!(f, "principal composition failed: {error}"),
        }
    }
}

impl std::error::Error for KernelBuildError {}

/// The complete, production Kernel composition.
pub struct KernelComposition {
    work_root: PathBuf,
    runtime: Runtime,
    platform: Arc<WindowsPlatform>,
    ipc: IpcImplementation,
    generation_gateway: OrsGenerationCoordinator,
    service: Arc<Mutex<KernelService>>,
    generations: Mutex<GenerationRouter>,
    generation_poison: Mutex<Option<String>>,
    front_door_policy: Mutex<ServerHandshakePolicy>,
    process_gateway: Option<Arc<ProcessExecutionGateway>>,
    store_bootstrap: Option<HostStoreBootstrapRequirement>,
    canonical_store_claimed: AtomicBool,
    #[cfg(windows)]
    canonical_store_gateway: Mutex<Option<Arc<KernelStoreGateway>>>,
}

/// Result of the closed Kernel semantic gateway for one authenticated frame.
///
/// The transport/session loop owns the connection lifetime. This action only
/// says whether a validated frame may receive a bounded protocol reply, must
/// fence the session, or requests the one Kernel shutdown path.
#[derive(Debug)]
pub enum KernelFrameAction {
    /// Return a bounded liveness or status reply.
    Reply(Frame),
    /// Execute one authenticated, provider-neutral process operation.
    Process {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Validated inert operation.
        request: ProcessExecutionRequest,
        /// Server-derived ephemeral session binding; never wire supplied.
        session_binding: ProcessSessionBinding,
    },
    /// Return a typed rejection, then fence the connection.
    Fence(Frame),
}

/// External production bindings required before Kernel can admit process work.
/// No default key, codec, replay store or evidence sink is fabricated.
pub struct ProcessExecutionAuthorityConfig {
    /// Stable authority identity selected by Host/installation state.
    pub authority_id: DispatchAuthorityId,
    /// Host-provided secret material consumed into the Kernel controller.
    pub key: KernelDispatchKey,
    /// Exact ORS epoch/fence binding for this authority generation.
    pub snapshot_binding: AuthoritySnapshotBinding,
    /// Host/platform codec for the opaque durable authority snapshot.
    pub snapshot_codec: Arc<dyn DispatchSnapshotCodec>,
}

struct OrsProcessReplayStore {
    store: Arc<RedbRecoveryStore>,
}

struct OrsProcessEvidenceSink {
    store: Arc<RedbRecoveryStore>,
    owner: ProcessOwnerBinding,
}

impl ProcessEvidenceSink for OrsProcessEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        let observed_at_ms = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        let record =
            ProcessEvidenceRecord::from_evidence(evidence, self.owner.clone(), observed_at_ms)
                .map_err(|error| eliot_process::EvidenceSinkError {
                    message: error.to_string(),
                })?;
        self.store
            .persist_process_evidence(&record)
            .map_err(|error| eliot_process::EvidenceSinkError {
                message: error.to_string(),
            })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedDispatchSnapshot {
    authority_id: DispatchAuthorityId,
    binding: AuthoritySnapshotBindingWire,
    snapshot: eliot_process::DispatchPermitReplaySnapshot,
}

/// Production DPAPI-backed snapshot codec with exact binding checks.
pub struct WindowsDispatchSnapshotCodec {
    platform: Arc<WindowsPlatform>,
    key_reference: eliot_platform::SecretReference,
}

impl WindowsDispatchSnapshotCodec {
    /// Creates a codec bound to one Credential Manager reference.
    pub fn new(
        platform: Arc<WindowsPlatform>,
        key_reference: eliot_platform::SecretReference,
    ) -> Self {
        Self {
            platform,
            key_reference,
        }
    }
}

impl DispatchSnapshotCodec for WindowsDispatchSnapshotCodec {
    fn seal(
        &self,
        snapshot: &eliot_process::DispatchPermitReplaySnapshot,
        binding: &AuthoritySnapshotBinding,
    ) -> Result<eliot_kernel_core::SealedAuthoritySnapshot, eliot_kernel_core::KernelError> {
        let envelope = ProtectedDispatchSnapshot {
            authority_id: binding.authority_id().clone(),
            binding: binding.to_wire(),
            snapshot: snapshot.clone(),
        };
        let plaintext = serde_json::to_vec(&envelope).map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        let ciphertext = self.platform.protect_secret(&plaintext).map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        eliot_kernel_core::SealedAuthoritySnapshot::new(
            self.key_reference.clone(),
            ciphertext.as_bytes().to_vec(),
        )
    }

    fn open(
        &self,
        payload: &eliot_ors::RecoveryPayload,
        binding: &AuthoritySnapshotBinding,
    ) -> Result<eliot_process::DispatchPermitReplaySnapshot, eliot_kernel_core::KernelError> {
        let eliot_ors::RecoveryPayload::Encrypted { key, ciphertext } = payload else {
            return Err(eliot_kernel_core::KernelError::RecoveryUnavailable(
                "authority snapshot is not encrypted".to_owned(),
            ));
        };
        if key != &self.key_reference {
            return Err(eliot_kernel_core::KernelError::RecoveryUnavailable(
                "authority snapshot credential reference mismatch".to_owned(),
            ));
        }
        let protected = ProtectedSecret::from_ciphertext(ciphertext.clone()).map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        let plaintext = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| {
                eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
            })?;
        let envelope: ProtectedDispatchSnapshot = serde_json::from_slice(plaintext.expose())
            .map_err(|error| {
                eliot_kernel_core::KernelError::RecoveryUnavailable(error.to_string())
            })?;
        AuthoritySnapshotBinding::from_wire_exact(envelope.binding, binding)?;
        if envelope.authority_id != *binding.authority_id() {
            return Err(eliot_kernel_core::KernelError::FenceMismatch);
        }
        envelope.snapshot.validate().map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        Ok(envelope.snapshot)
    }
}

impl ProcessExecutionReplayStore for OrsProcessReplayStore {
    fn load_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
    ) -> Result<Option<ProcessExecutionReplayRecord>, eliot_kernel_core::KernelError> {
        self.store
            .load_process_start(
                &eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(|e| {
                    eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string())
                })?,
            )
            .map_err(|e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()))?
            .map(|record| {
                Ok(ProcessExecutionReplayRecord {
                    admission_digest: record.admission_digest,
                    owner: record.owner,
                    state: match record.state {
                        OrsReplayState::Reserved => ProcessExecutionReplayState::Reserved,
                        OrsReplayState::Completed => ProcessExecutionReplayState::Completed,
                        OrsReplayState::Unknown => ProcessExecutionReplayState::Unknown,
                    },
                    receipt: record.receipt,
                })
            })
            .transpose()
    }

    fn begin_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        admission_digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, eliot_kernel_core::KernelError> {
        let record = OrsReplayRecord {
            operation_id: eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(
                |e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()),
            )?,
            admission_digest: admission_digest.to_owned(),
            owner: owner.clone(),
            state: OrsReplayState::Reserved,
            receipt: None,
        };
        self.store
            .begin_process_start(&record)
            .map_err(|e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()))
            .map(|existing| {
                existing.map_or(ProcessExecutionReplayBegin::Acquired, |record| {
                    ProcessExecutionReplayBegin::Existing(ProcessExecutionReplayRecord {
                        admission_digest: record.admission_digest,
                        owner: record.owner,
                        state: match record.state {
                            OrsReplayState::Reserved => ProcessExecutionReplayState::Reserved,
                            OrsReplayState::Completed => ProcessExecutionReplayState::Completed,
                            OrsReplayState::Unknown => ProcessExecutionReplayState::Unknown,
                        },
                        receipt: record.receipt,
                    })
                })
            })
    }

    fn persist_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        record: ProcessExecutionReplayRecord,
    ) -> Result<(), eliot_kernel_core::KernelError> {
        self.store
            .persist_process_start(&OrsReplayRecord {
                operation_id: eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(
                    |e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()),
                )?,
                admission_digest: record.admission_digest,
                owner: record.owner,
                state: match record.state {
                    ProcessExecutionReplayState::Reserved => OrsReplayState::Reserved,
                    ProcessExecutionReplayState::Completed => OrsReplayState::Completed,
                    ProcessExecutionReplayState::Unknown => OrsReplayState::Unknown,
                },
                receipt: record.receipt,
            })
            .map_err(|e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()))
    }
}

impl ProcessExecutionReplayStoreWithAbort for OrsProcessReplayStore {
    fn abort_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        admission_digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, eliot_kernel_core::KernelError> {
        self.store
            .abort_process_start(
                &eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(|error| {
                    eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
                })?,
                admission_digest,
                owner,
            )
            .map(|result| match result {
                eliot_ors::ProcessStartReplayAbort::Released => {
                    ProcessExecutionReplayAbort::Released
                }
                eliot_ors::ProcessStartReplayAbort::NotReleased => {
                    ProcessExecutionReplayAbort::NotReleased
                }
            })
            .map_err(|error| {
                eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
            })
    }
}

const RESERVED_STORE_SNAPSHOT_HEAD: &str = "__eliot_store_snapshot__";
const STORE_IDENTITY_BINDING: &str = "eliot.storage.store-api";

#[derive(Serialize)]
struct CanonicalStoreRevision<'a> {
    key: &'a str,
    revision: u64,
    state_fence: &'a StoreStateFence,
}

#[derive(Serialize)]
struct CanonicalStoreSnapshot<'a> {
    store_identity: &'static str,
    state_fence: &'a StoreStateFence,
    revision_heads: Vec<CanonicalStoreRevision<'a>>,
    validation_revision: u64,
}

fn project_store_snapshot(
    snapshot: &CanonicalValidationSnapshot,
) -> Result<(FencingToken, BTreeMap<String, String>), ProcessExecutionError> {
    snapshot
        .validate()
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
    let mut ordered_heads: Vec<&RevisionHead> = snapshot.revision_heads.iter().collect();
    ordered_heads.sort_by(|left, right| left.key.cmp(&right.key));
    if ordered_heads
        .iter()
        .any(|head| head.key.as_str() == RESERVED_STORE_SNAPSHOT_HEAD)
    {
        return Err(ProcessExecutionError::Unavailable(
            "Store revision key collides with reserved snapshot binding".to_owned(),
        ));
    }
    let mut projected = BTreeMap::new();
    let mut canonical_heads = Vec::with_capacity(ordered_heads.len());
    for head in ordered_heads {
        let binding = CanonicalStoreRevision {
            key: head.key.as_str(),
            revision: head.revision,
            state_fence: &snapshot.state_fence,
        };
        let digest = sha256_hex(
            &canonical_json_bytes(&binding)
                .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?,
        );
        projected.insert(head.key.to_string(), digest);
        canonical_heads.push(binding);
    }
    let snapshot_binding = CanonicalStoreSnapshot {
        store_identity: STORE_IDENTITY_BINDING,
        state_fence: &snapshot.state_fence,
        revision_heads: canonical_heads,
        validation_revision: snapshot.validation_revision,
    };
    let snapshot_digest = sha256_hex(
        &canonical_json_bytes(&snapshot_binding)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?,
    );
    projected.insert(
        RESERVED_STORE_SNAPSHOT_HEAD.to_owned(),
        snapshot_digest.clone(),
    );
    let fence = FencingToken::new(
        snapshot.state_fence.authority_epoch.value(),
        Generation::new(snapshot.state_fence.resource_generation.value())
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?,
        format!("store-snapshot-{snapshot_digest}"),
    )
    .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
    Ok((fence, projected))
}

struct ValidationContextSlot {
    contexts: Mutex<BTreeMap<eliot_process::OperationId, (u64, DispatchValidationContext)>>,
    next_owner: AtomicU64,
}

struct ValidationContextGuard {
    slot: Arc<ValidationContextSlot>,
    operation_id: eliot_process::OperationId,
    owner: u64,
    active: bool,
}

impl Drop for ValidationContextGuard {
    fn drop(&mut self) {
        if self.active {
            self.slot.remove_owned(&self.operation_id, self.owner);
        }
    }
}

impl ValidationContextSlot {
    fn new() -> Self {
        Self {
            contexts: Mutex::new(BTreeMap::new()),
            next_owner: AtomicU64::new(1),
        }
    }

    fn insert(
        self: &Arc<Self>,
        operation_id: eliot_process::OperationId,
        context: DispatchValidationContext,
    ) -> Result<ValidationContextGuard, ProcessExecutionError> {
        let mut contexts = self.contexts.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("validation context lock poisoned".to_owned())
        })?;
        let owner = self.next_owner.fetch_add(1, Ordering::Relaxed);
        match contexts.entry(operation_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert((owner, context));
                Ok(ValidationContextGuard {
                    slot: Arc::clone(self),
                    operation_id,
                    owner,
                    active: true,
                })
            }
            Entry::Occupied(_) => Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            )),
        }
    }

    fn take(
        &self,
        operation_id: &eliot_process::OperationId,
    ) -> Result<DispatchValidationContext, ProcessExecutionError> {
        self.contexts
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("validation context lock poisoned".to_owned())
            })?
            .remove(operation_id)
            .map(|(_, context)| context)
            .ok_or(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ))
    }

    fn remove_owned(&self, operation_id: &eliot_process::OperationId, owner: u64) {
        if let Ok(mut contexts) = self.contexts.lock()
            && contexts
                .get(operation_id)
                .is_some_and(|(current_owner, _)| *current_owner == owner)
        {
            contexts.remove(operation_id);
        }
    }
}

struct ControllerDispatchPort {
    controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
    binding: AuthoritySnapshotBinding,
    validation_contexts: Arc<ValidationContextSlot>,
}

impl DispatchValidationPort for ControllerDispatchPort {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self.validation_contexts.take(request.operation_id())?;
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current, &self.binding)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }
}

struct ProcessExecutionGateway {
    controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
    executor: WindowsProcessExecutor,
    replay_store: Arc<dyn ProcessExecutionReplayStoreWithAbort>,
    evidence_store: Arc<RedbRecoveryStore>,
    snapshot_binding: AuthoritySnapshotBinding,
    validation_contexts: Arc<ValidationContextSlot>,
    #[cfg(windows)]
    canonical_store: Arc<Mutex<Option<Arc<KernelStoreGateway>>>>,
    path_admission: Arc<KernelPathAdmission>,
}

#[cfg(windows)]
struct CanonicalStoreAttachment<'a> {
    gateway: Arc<KernelStoreGateway>,
    process_gateway: &'a ProcessExecutionGateway,
    active: bool,
}

#[cfg(windows)]
trait CanonicalStoreAttachmentTransaction: Send {
    fn commit(self: Box<Self>);
}

#[cfg(windows)]
impl CanonicalStoreAttachment<'_> {
    fn commit(mut self) {
        self.active = false;
    }
}

#[cfg(windows)]
impl CanonicalStoreAttachmentTransaction for CanonicalStoreAttachment<'_> {
    fn commit(self: Box<Self>) {
        (*self).commit();
    }
}

#[cfg(windows)]
impl Drop for CanonicalStoreAttachment<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut retained) = self.process_gateway.canonical_store.lock()
            && retained
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gateway))
        {
            *retained = None;
        }
    }
}

#[cfg(windows)]
fn attach_then_retain_canonical_store<'a, T, Attach>(
    gateway: Arc<T>,
    retained: &'a Mutex<Option<Arc<T>>>,
    attach: Attach,
) -> Result<(), KernelBuildError>
where
    T: Send + Sync + 'static,
    Attach: FnOnce(
            Arc<T>,
        )
            -> Result<Box<dyn CanonicalStoreAttachmentTransaction + 'a>, KernelBuildError>
        + 'a,
{
    let process_attachment = attach(Arc::clone(&gateway))?;
    let mut retained = retained
        .lock()
        .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?;
    if retained.is_some() {
        return Err(KernelBuildError::StoreAlreadyConnected);
    }
    *retained = Some(gateway);
    drop(retained);
    process_attachment.commit();
    Ok(())
}

trait ProcessStartGuard: Send {}

impl<T: Send> ProcessStartGuard for T {}

#[allow(async_fn_in_trait)]
trait ProcessStartPorts {
    type PathProof;
    type Request;
    type Receipt: Clone + Send + 'static;

    fn validate_admission(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        owner: &ProcessOwnerBinding,
    ) -> Result<(), ProcessExecutionError>;
    fn now(&self) -> u64;

    fn validate_path(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        path_proof: &Self::PathProof,
    ) -> Result<(), ProcessExecutionError>;
    fn begin(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, ProcessExecutionError>;
    fn completed_receipt(
        &self,
        record: ProcessExecutionReplayRecord,
    ) -> Result<Option<Self::Receipt>, ProcessExecutionError>;
    async fn snapshot(&self) -> Result<CanonicalValidationSnapshot, ProcessExecutionError>;
    fn build_context(
        &self,
        clock: ClockObservation,
        store_fence: FencingToken,
        authority_epoch: u64,
        revision_heads: BTreeMap<String, String>,
        validation_revision: u64,
    ) -> Result<DispatchValidationContext, ProcessExecutionError>;
    fn insert_context(
        &self,
        operation_id: eliot_process::OperationId,
        context: DispatchValidationContext,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError>;
    fn issue(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        store_fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        now: u64,
        validation_revision: u64,
    ) -> Result<Self::Request, ProcessExecutionError>;
    fn insert_path(
        &self,
        operation_id: eliot_process::OperationId,
        path_proof: Self::PathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError>;
    async fn execute(
        &self,
        owner: &ProcessOwnerBinding,
        request: Self::Request,
    ) -> Result<Self::Receipt, ProcessExecutionError>;
    fn persist_completed(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
        receipt: Self::Receipt,
    ) -> Result<(), ProcessExecutionError>;
    fn mark_unknown(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    );
    fn abort(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, ProcessExecutionError>;
}

struct ProcessStartReservation<'a, P: ProcessStartPorts + ?Sized> {
    ports: &'a P,
    operation_id: eliot_process::OperationId,
    admission_digest: String,
    owner: ProcessOwnerBinding,
    active: bool,
}

impl<P: ProcessStartPorts + ?Sized> ProcessStartReservation<'_, P> {
    fn release(&mut self) -> Result<(), ProcessExecutionError> {
        if !self.active {
            return Ok(());
        }
        let result = self
            .ports
            .abort(&self.operation_id, &self.admission_digest, &self.owner)?;
        self.active = false;
        match result {
            ProcessExecutionReplayAbort::Released => Ok(()),
            ProcessExecutionReplayAbort::NotReleased => Err(ProcessExecutionError::UnknownOutcome),
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl<P: ProcessStartPorts + ?Sized> Drop for ProcessStartReservation<'_, P> {
    fn drop(&mut self) {
        if self.active {
            let _ = self
                .ports
                .abort(&self.operation_id, &self.admission_digest, &self.owner);
        }
    }
}

/// Platform-owned path proof captured immediately before authority issuance.
/// The executor receives the proof as an opaque Kernel-owned handoff; raw
/// lexical/canonical containment is never used as the admission rule.
#[derive(Debug)]
struct ProcessPathProof {
    executable: PathBuf,
    working_directory: PathBuf,
    lease: Arc<RetainedProcessPathLease>,
}

struct KernelPathAdmission {
    proofs: Mutex<BTreeMap<eliot_process::OperationId, ProcessPathProof>>,
}

struct PathAdmissionGuard {
    admission: Arc<KernelPathAdmission>,
    operation_id: eliot_process::OperationId,
}

impl Drop for PathAdmissionGuard {
    fn drop(&mut self) {
        self.admission.remove(&self.operation_id);
    }
}

impl KernelPathAdmission {
    fn new(_platform: Arc<WindowsPlatform>) -> Self {
        Self {
            proofs: Mutex::new(BTreeMap::new()),
        }
    }

    fn insert(
        &self,
        operation_id: eliot_process::OperationId,
        proof: ProcessPathProof,
    ) -> Result<(), ProcessExecutionError> {
        let mut proofs = self.proofs.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("path admission lock poisoned".to_owned())
        })?;
        match proofs.entry(operation_id) {
            Entry::Vacant(entry) => {
                entry.insert(proof);
                Ok(())
            }
            Entry::Occupied(_) => Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            )),
        }
    }

    fn remove(&self, operation_id: &eliot_process::OperationId) {
        if let Ok(mut proofs) = self.proofs.lock() {
            proofs.remove(operation_id);
        }
    }
}

impl ProcessLaunchAdmission for KernelPathAdmission {
    fn validate_launch(
        &self,
        request: &ProcessRequest,
        observed: &SuspendedProcessIdentity,
        launch: &SuspendedLaunchEvidence,
    ) -> Result<(), eliot_process::ContractError> {
        let proofs =
            self.proofs
                .lock()
                .map_err(|_| eliot_process::ContractError::InvalidValue {
                    field: "path_admission",
                    reason: "proof lock poisoned",
                })?;
        let proof = proofs
            .get(request.operation_id())
            .ok_or(eliot_process::ContractError::DispatchBindingMismatch)?;
        if proof.executable.to_string_lossy() != request.executable()
            || proof.working_directory.to_string_lossy() != request.working_directory()
            || observed.executable_sha256() != request.executable_sha256()
            || launch.requested_executable() != request.executable()
            || launch.executable_volume_serial_number()
                != proof.lease.executable_identity().volume_serial_number
            || launch.executable_file_index() != proof.lease.executable_identity().file_index
        {
            return Err(eliot_process::ContractError::DispatchBindingMismatch);
        }
        proof
            .lease
            .validate(
                Path::new(request.executable()),
                Path::new(request.working_directory()),
                request.executable_sha256(),
            )
            .map_err(|_| eliot_process::ContractError::DispatchBindingMismatch)
    }
}

impl ProcessExecutionGateway {
    fn new(
        controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
        ors: Arc<RedbRecoveryStore>,
        snapshot_binding: AuthoritySnapshotBinding,
        path_admission: Arc<KernelPathAdmission>,
    ) -> Self {
        let validation_contexts = Arc::new(ValidationContextSlot::new());
        let replay_store = Arc::new(OrsProcessReplayStore {
            store: Arc::clone(&ors),
        });
        let port = Arc::new(ControllerDispatchPort {
            controller: Arc::clone(&controller),
            binding: snapshot_binding.clone(),
            validation_contexts: Arc::clone(&validation_contexts),
        });
        let launch_admission: Arc<dyn ProcessLaunchAdmission> = path_admission.clone();
        Self {
            controller,
            executor: WindowsProcessExecutor::new_with_launch_admission(port, launch_admission),
            replay_store,
            evidence_store: ors,
            snapshot_binding,
            validation_contexts,
            #[cfg(windows)]
            canonical_store: Arc::new(Mutex::new(None)),
            path_admission,
        }
    }

    #[cfg(windows)]
    fn attach_canonical_store(
        &self,
        gateway: Arc<KernelStoreGateway>,
    ) -> Result<CanonicalStoreAttachment<'_>, KernelBuildError> {
        let mut retained = self
            .canonical_store
            .lock()
            .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?;
        if retained.is_some() {
            return Err(KernelBuildError::StoreAlreadyConnected);
        }
        *retained = Some(Arc::clone(&gateway));
        Ok(CanonicalStoreAttachment {
            gateway,
            process_gateway: self,
            active: true,
        })
    }

    #[cfg(windows)]
    async fn canonical_validation_snapshot(
        &self,
    ) -> Result<CanonicalValidationSnapshot, ProcessExecutionError> {
        let gateway = self
            .canonical_store
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("store gateway lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("canonical store is not connected".to_owned())
            })?;
        gateway
            .validation_snapshot()
            .await
            .map_err(ProcessExecutionError::Unavailable)
    }

    fn attach_path_proof(
        &self,
        operation_id: eliot_process::OperationId,
        path_proof: ProcessPathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        self.path_admission
            .insert(operation_id.clone(), path_proof)?;
        Ok(Box::new(PathAdmissionGuard {
            admission: Arc::clone(&self.path_admission),
            operation_id,
        }))
    }

    fn mark_unknown(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) {
        let _ = self.replay_store.persist_process_start(
            operation_id,
            ProcessExecutionReplayRecord {
                admission_digest: digest.to_owned(),
                owner: owner.clone(),
                state: ProcessExecutionReplayState::Unknown,
                receipt: None,
            },
        );
    }

    async fn start(
        &self,
        owner: &ProcessOwnerBinding,
        admission: ProcessExecutionAdmissionRequest,
        path_proof: ProcessPathProof,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        run_process_start(self, owner, admission, path_proof).await
    }

    async fn inspect(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<eliot_process::ProcessExecutionView, ProcessExecutionError> {
        self.authorize_operation(owner, &operation_id)?;
        self.executor.inspect(operation_id).await
    }

    async fn cancel(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        self.authorize_operation(owner, &operation_id)?;
        self.executor.cancel(operation_id.clone()).await
    }

    async fn reconcile(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        self.authorize_operation(owner, &operation_id)?;
        self.executor.reconcile(operation_id).await
    }

    fn authorize_operation(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
    ) -> Result<(), ProcessExecutionError> {
        let record = self
            .replay_store
            .load_process_start(operation_id)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
            .ok_or(ProcessExecutionError::NotFound)?;
        authorize_process_owner(&record.owner, owner)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "reservation, canonical projection, authority issue, executor handoff, and replay linearization are one ordered operation"
)]
async fn run_process_start<P: ProcessStartPorts>(
    ports: &P,
    owner: &ProcessOwnerBinding,
    admission: ProcessExecutionAdmissionRequest,
    path_proof: P::PathProof,
) -> Result<P::Receipt, ProcessExecutionError> {
    admission.validate()?;
    ports.validate_path(&admission, &path_proof)?;
    ports.validate_admission(&admission, owner)?;
    let digest = process_admission_digest(&admission)
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
    let now = ports.now();
    if admission.deadline_unix_ms() <= now {
        return Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::ExpiredDispatchPermit,
        ));
    }
    let mut reservation = match ports.begin(admission.intent().operation_id(), &digest, owner)? {
        ProcessExecutionReplayBegin::Acquired => ProcessStartReservation {
            ports,
            operation_id: admission.intent().operation_id().clone(),
            admission_digest: digest.clone(),
            owner: owner.clone(),
            active: true,
        },
        ProcessExecutionReplayBegin::Existing(record) => {
            if record.admission_digest != digest || record.owner != *owner {
                return Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ));
            }
            return match record.state {
                ProcessExecutionReplayState::Completed => ports
                    .completed_receipt(record)?
                    .ok_or(ProcessExecutionError::UnknownOutcome),
                ProcessExecutionReplayState::Reserved | ProcessExecutionReplayState::Unknown => {
                    Err(ProcessExecutionError::UnknownOutcome)
                }
            };
        }
    };
    let snapshot = match ports.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    if let Err(error) = snapshot.validate() {
        let failure = ProcessExecutionError::Unavailable(error.to_string());
        return Err(match reservation.release() {
            Ok(()) => failure,
            Err(_) => ProcessExecutionError::UnknownOutcome,
        });
    }
    if admission.state_fence().authority_epoch() != snapshot.state_fence.authority_epoch.value()
        || admission.state_fence().generation().get()
            != snapshot.state_fence.resource_generation.value()
    {
        let failure =
            ProcessExecutionError::Contract(eliot_process::ContractError::StaleStateFence);
        return Err(match reservation.release() {
            Ok(()) => failure,
            Err(_) => ProcessExecutionError::UnknownOutcome,
        });
    }
    let (store_fence, revision_heads) = match project_store_snapshot(&snapshot) {
        Ok(projected) => projected,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let context = match ports.build_context(
        ClockObservation {
            valid_time_ms: Some(snapshot.observed_at_unix_ms),
            known_time_ms: Some(snapshot.observed_at_unix_ms),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        store_fence.clone(),
        snapshot.state_fence.authority_epoch.value(),
        revision_heads.clone(),
        snapshot.validation_revision,
    ) {
        Ok(context) => context,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let operation_id = admission.intent().operation_id().clone();
    let context_guard = match ports.insert_context(operation_id.clone(), context) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let request = match ports.issue(
        &admission,
        store_fence,
        revision_heads,
        now,
        snapshot.validation_revision,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let path_guard = match ports.insert_path(operation_id.clone(), path_proof) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let receipt = match ports.execute(owner, request).await {
        Ok(receipt) => receipt,
        Err(error) => {
            drop(context_guard);
            drop(path_guard);
            reservation.disarm();
            ports.mark_unknown(admission.intent().operation_id(), &digest, owner);
            return Err(error);
        }
    };
    drop(context_guard);
    drop(path_guard);
    if let Err(error) = ports.persist_completed(
        admission.intent().operation_id(),
        &digest,
        owner,
        receipt.clone(),
    ) {
        reservation.disarm();
        ports.mark_unknown(admission.intent().operation_id(), &digest, owner);
        return Err(error);
    }
    reservation.disarm();
    Ok(receipt)
}

impl ProcessStartPorts for ProcessExecutionGateway {
    type PathProof = ProcessPathProof;
    type Request = ProcessRequest;
    type Receipt = ProcessStartReceipt;

    fn validate_admission(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        owner: &ProcessOwnerBinding,
    ) -> Result<(), ProcessExecutionError> {
        if admission.recipient_module_id() != owner.module_id()
            || admission.state_fence().authority_epoch() != owner.authority_epoch()
            || admission.state_fence().generation().get() != owner.generation().get()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        if admission.state_fence().authority_epoch()
            != self.snapshot_binding.authority_epoch().current.epoch
            || admission.state_fence().generation() != admission.intent().generation()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::StaleStateFence,
            ));
        }
        Ok(())
    }

    fn now(&self) -> u64 {
        unix_ms()
    }

    fn validate_path(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        path_proof: &Self::PathProof,
    ) -> Result<(), ProcessExecutionError> {
        if path_proof.executable.to_string_lossy() != admission.intent().executable()
            || path_proof.working_directory.to_string_lossy()
                != admission.intent().working_directory()
            || path_proof.lease.executable_identity().file_index == 0
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        Ok(())
    }

    fn begin(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, ProcessExecutionError> {
        self.replay_store
            .begin_process_start(operation_id, digest, owner)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn completed_receipt(
        &self,
        record: ProcessExecutionReplayRecord,
    ) -> Result<Option<Self::Receipt>, ProcessExecutionError> {
        Ok(record.receipt)
    }

    async fn snapshot(&self) -> Result<CanonicalValidationSnapshot, ProcessExecutionError> {
        #[cfg(windows)]
        {
            self.canonical_validation_snapshot().await
        }
        #[cfg(not(windows))]
        {
            Err(ProcessExecutionError::Unavailable(
                "canonical store validation is unavailable on this platform".to_owned(),
            ))
        }
    }

    fn build_context(
        &self,
        clock: ClockObservation,
        store_fence: FencingToken,
        authority_epoch: u64,
        revision_heads: BTreeMap<String, String>,
        validation_revision: u64,
    ) -> Result<DispatchValidationContext, ProcessExecutionError> {
        DispatchValidationContext::new(
            clock,
            store_fence,
            authority_epoch,
            revision_heads,
            validation_revision,
        )
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn insert_context(
        &self,
        operation_id: eliot_process::OperationId,
        context: DispatchValidationContext,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        self.validation_contexts
            .insert(operation_id, context)
            .map(|guard| Box::new(guard) as Box<dyn ProcessStartGuard>)
    }

    fn issue(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        store_fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        now: u64,
        validation_revision: u64,
    ) -> Result<Self::Request, ProcessExecutionError> {
        let permit_issuance = PermitIssuance::new_with_validation_revision(
            admission.action_lease_ref().clone(),
            store_fence,
            revision_heads,
            now,
            admission.deadline_unix_ms(),
            format!(
                "process-start:{}",
                admission.intent().operation_id().as_str()
            ),
            validation_revision,
        )
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        let permit = self
            .controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .issue(admission.intent(), permit_issuance, &self.snapshot_binding)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        ProcessRequest::new(admission.intent().clone(), permit)
            .map_err(ProcessExecutionError::Contract)
    }

    fn insert_path(
        &self,
        operation_id: eliot_process::OperationId,
        path_proof: Self::PathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        self.attach_path_proof(operation_id, path_proof)
    }

    async fn execute(
        &self,
        owner: &ProcessOwnerBinding,
        request: Self::Request,
    ) -> Result<Self::Receipt, ProcessExecutionError> {
        self.executor
            .start(
                request,
                Arc::new(OrsProcessEvidenceSink {
                    store: Arc::clone(&self.evidence_store),
                    owner: owner.clone(),
                }),
            )
            .await
    }

    fn persist_completed(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
        receipt: Self::Receipt,
    ) -> Result<(), ProcessExecutionError> {
        self.replay_store
            .persist_process_start(
                operation_id,
                ProcessExecutionReplayRecord {
                    admission_digest: digest.to_owned(),
                    owner: owner.clone(),
                    state: ProcessExecutionReplayState::Completed,
                    receipt: Some(receipt),
                },
            )
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn mark_unknown(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) {
        ProcessExecutionGateway::mark_unknown(self, operation_id, digest, owner);
    }

    fn abort(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, ProcessExecutionError> {
        self.replay_store
            .abort_process_start(operation_id, digest, owner)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }
}

fn authorize_process_owner(
    expected: &ProcessOwnerBinding,
    presented: &ProcessOwnerBinding,
) -> Result<(), ProcessExecutionError> {
    if expected != presented {
        return Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::DispatchBindingMismatch,
        ));
    }
    Ok(())
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn caller_binding(
    session: &Session,
) -> Result<(ProcessOwnerBinding, ProcessSessionBinding), TransportError> {
    session
        .peer
        .validate()
        .map_err(|_| TransportError::PeerIdentityUnavailable)?;
    let generation = Generation::new(session.module_generation.generation.value())
        .map_err(|_| TransportError::SessionFenced)?;
    let stable_sid = match &session.peer {
        PeerIdentity::Authenticated { user_identity, .. } => user_identity,
        PeerIdentity::Unavailable { .. } => return Err(TransportError::PeerIdentityUnavailable),
    };
    let principal_digest = stable_owner_principal_digest(
        stable_sid,
        session.module_generation.module_id.as_str(),
        session.authority_epoch,
        generation,
    );
    let owner = ProcessOwnerBinding::new(
        session.module_generation.module_id.as_str(),
        principal_digest,
        session.authority_epoch,
        generation,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let session_binding = ProcessSessionBinding::new(&session.connection_id, session.session_epoch)
        .map_err(|_| TransportError::SessionFenced)?;
    Ok((owner, session_binding))
}

fn stable_owner_principal_digest(
    stable_sid: &str,
    module_id: &str,
    authority_epoch: u64,
    generation: Generation,
) -> String {
    let mut principal = Sha256::new();
    principal.update(stable_sid.as_bytes());
    principal.update(module_id.as_bytes());
    principal.update(authority_epoch.to_le_bytes());
    principal.update(generation.get().to_le_bytes());
    format!("{:x}", Sha256::digest(principal.finalize()))
}

/// The concrete, non-generic S-03 gateway retained by one Kernel composition.
///
/// There is deliberately no public constructor accepting a client or caller:
/// [`KernelComposition::connect_canonical_store`] is the only production
/// construction path and supplies the Host-approved client, fixed
/// `store_bridge` route, and fixed active daemon caller.
#[cfg(windows)]
pub struct KernelStoreGateway {
    service: Arc<Mutex<KernelService>>,
    store: Arc<EbpCanonicalStoreClient<NamedPipeTransport>>,
    route: GenerationRoute,
}

#[cfg(windows)]
impl std::fmt::Debug for KernelStoreGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelStoreGateway")
            .field("route", &self.route)
            .field("caller", &ACTIVE_DAEMON_CALLER)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl KernelStoreGateway {
    fn new(
        service: Arc<Mutex<KernelService>>,
        store: Arc<EbpCanonicalStoreClient<NamedPipeTransport>>,
        route: GenerationRoute,
    ) -> Self {
        Self {
            service,
            store,
            route,
        }
    }

    /// Applies one already prepared transition after fixed Kernel admission.
    pub async fn apply(
        &self,
        context: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, String> {
        context.validate().map_err(|error| error.to_string())?;
        transition.validate().map_err(|error| error.to_string())?;
        if context.source_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err("transition caller is not the active daemon".to_owned());
        }
        if transition.state_fence != context.state_fence {
            return Err("transition state fence does not match request metadata".to_owned());
        }

        let lease = {
            let service = self
                .service
                .lock()
                .map_err(|_| "Kernel service lock poisoned".to_owned())?;
            if service.generation_fenced() {
                return Err("Kernel generation is fenced".to_owned());
            }
            if self.route.authority_epoch() != service.authority_epoch()
                || self.route.active_generation() != transition.state_fence.resource_generation
            {
                return Err(
                    "canonical-store route is outside the active Kernel generation".to_owned(),
                );
            }
            let lease = service
                .acquire_admission()
                .map_err(|error| error.to_string())?;
            if lease.authority_epoch() != transition.state_fence.authority_epoch {
                return Err("canonical-store route authority epoch is stale".to_owned());
            }
            lease
        };

        let result = self
            .store
            .apply_prepared(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(|error: StoreError| error.to_string());
        drop(lease);
        result
    }

    /// Reads one Host-bound canonical validation snapshot.
    pub async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, String> {
        self.store
            .validation_snapshot()
            .await
            .map_err(|error| error.to_string())
    }
}

/// The sole semantic bridge between ORS cutover evidence and the in-memory
/// route table.  ORS owns the durable linearization point; this type owns no
/// mutable store escape and publishes only after that point succeeds.
struct OrsGenerationCoordinator {
    ors: Arc<RedbRecoveryStore>,
}

impl OrsGenerationCoordinator {
    fn new(ors: Arc<RedbRecoveryStore>) -> Self {
        Self { ors }
    }

    fn recover(
        &self,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        // A staged candidate is evidence of an interrupted attempt.  Mark it
        // forward-only before rebuilding routes; never activate staged data.
        let _ = self
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        let snapshots = self
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        if snapshots.is_empty() {
            return Ok(());
        }

        let epoch_value = snapshots
            .iter()
            .map(|snapshot| snapshot.record().new_epoch.value())
            .max()
            .ok_or_else(|| "committed cutover projection was empty".to_owned())?;
        let epoch = AuthorityEpoch::new(epoch_value).map_err(|error| error.to_string())?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            if record.state != GenerationCutoverState::Committed
                || record.new_epoch.value() > epoch_value
            {
                return Err("ORS route projection has invalid committed epochs".to_owned());
            }
        }
        // Synchronization is a bounded direct fast-forward.  It rejects a
        // corrupt/oversized durable epoch before any route becomes visible.
        service
            .synchronize_authority_epoch(epoch)
            .map_err(|error| error.to_string())?;
        let mut recovered = GenerationRouter::at_epoch(epoch).map_err(|error| error.to_string())?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            let scope =
                RouteScope::new(record.route_scope.clone()).map_err(|error| error.to_string())?;
            let route = GenerationRoute::new(scope, record.new_generation, epoch)
                .map_err(|error| error.to_string())?;
            recovered
                .register(route)
                .map_err(|error| error.to_string())?;
        }
        update_handshake_policy(policy, &recovered)?;
        *generations = recovered;
        Ok(())
    }

    fn persist_and_publish(
        &self,
        decision: &eliot_kernel_core::CutoverDecision,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        let mut candidate = generations.clone();
        candidate
            .cutover(decision)
            .map_err(|error| error.to_string())?;
        let staged = RuntimeGenerationCutoverRecord {
            cutover_id: decision.cutover_id().to_owned(),
            route_scope: decision.route_scope().as_str().to_owned(),
            old_generation: decision.old_generation(),
            new_generation: decision.new_generation(),
            old_epoch: decision.old_epoch(),
            new_epoch: decision.new_epoch(),
            state: GenerationCutoverState::Armed,
        };
        self.ors
            .stage_generation_cutover(staged.clone())
            .map_err(|error| error.to_string())?;
        let committed = self
            .ors
            .commit_generation_cutover_state(staged)
            .map_err(|error| error.to_string())?;
        if committed.record().state != GenerationCutoverState::Committed {
            return Err("ORS did not return a committed cutover".to_owned());
        }

        // No in-memory publication occurs before the durable cutover.  Any
        // failure below is surfaced to the composition, which poisons the
        // gateway rather than claiming a partially published transition.
        service
            .synchronize_authority_epoch(decision.new_epoch())
            .map_err(|error| error.to_string())?;
        update_handshake_policy(policy, &candidate)?;
        *generations = candidate;
        Ok(())
    }
}

fn update_handshake_policy(
    policy: &mut ServerHandshakePolicy,
    generations: &GenerationRouter,
) -> Result<(), String> {
    let daemon = RouteScope::new("daemon").map_err(|error| error.to_string())?;
    if let Ok(route) = generations.route(&daemon) {
        policy.module_generation.generation = route.active_generation();
        policy.module_generation.state_fence =
            StateFence::new(route.authority_epoch(), route.active_generation());
        policy.config_snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": route.active_generation().value(),
            "authority_epoch": route.authority_epoch().value(),
        });
    }
    Ok(())
}

impl KernelComposition {
    /// Builds all lower-layer surfaces once and binds them to one runtime.
    ///
    /// The default authority remains fail-closed until Host performs its
    /// authenticated handoff. Test-only adapter construction is available
    /// under the test configuration.
    pub fn new(config: KernelConfig) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble(config, ors, None, platform)
    }

    /// Consumes the Host-approved protected authority descriptor before
    /// constructing the process-execution gateway.  The descriptor, secret,
    /// snapshot codec and replay binding remain inside this composition path.
    pub fn new_with_authority_descriptor(
        config: KernelConfig,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        let prepared = Self::prepare_authority_descriptor_material(
            &platform,
            &ors,
            path,
            expected_sha256,
            contour,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let snapshot_binding = AuthoritySnapshotBinding::from_wire(
            prepared.descriptor.snapshot_binding.clone(),
            &prepared.descriptor.authority_id,
        )
        .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(WindowsDispatchSnapshotCodec::new(
            Arc::clone(&platform),
            prepared.descriptor.dispatch_key.clone(),
        ));
        let authority = ProcessExecutionAuthorityConfig {
            authority_id: prepared.descriptor.authority_id,
            key: prepared.key,
            snapshot_binding,
            snapshot_codec: codec,
        };
        Self::assemble_with_process_authority(config, authority, ors, platform)
    }

    /// Builds a production composition with an externally supplied process
    /// authority key, opaque snapshot codec and durable replay binding.
    /// Missing bindings are never replaced by a default or in-memory issuer.
    pub fn new_with_process_authority(
        config: KernelConfig,
        authority_config: ProcessExecutionAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble_with_process_authority(config, authority_config, ors, platform)
    }

    fn assemble_with_process_authority(
        config: KernelConfig,
        authority_config: ProcessExecutionAuthorityConfig,
        ors: Arc<RedbRecoveryStore>,
        platform: Arc<WindowsPlatform>,
    ) -> Result<Self, KernelBuildError> {
        let authority_store: Arc<dyn OperationalRecoveryStore> = ors.clone();
        let controller = Arc::new(Mutex::new(
            ProcessDispatchAuthorityController::restore(
                authority_config.authority_id,
                authority_config.key,
                authority_store,
                authority_config.snapshot_codec,
                &authority_config.snapshot_binding,
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?,
        ));
        let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
        let gateway = Arc::new(ProcessExecutionGateway::new(
            Arc::clone(&controller),
            Arc::clone(&ors),
            authority_config.snapshot_binding,
            path_admission,
        ));
        Self::assemble(config, ors, Some(gateway), platform)
    }

    /// Reads, validates, and consumes one protected authority descriptor.
    ///
    /// This remains Kernel-private until the live Store-derived validation
    /// context is available in K1C. The descriptor and credential never leave
    /// this process as serialized authority material.
    #[allow(dead_code)]
    fn prepare_authority_descriptor(
        &self,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<PreparedAuthorityMaterial, AuthorityPreparationError> {
        Self::prepare_authority_descriptor_material(
            &self.platform,
            &self.generation_gateway.ors,
            path,
            expected_sha256,
            contour,
        )
    }

    fn prepare_authority_descriptor_material(
        platform: &WindowsPlatform,
        ors: &RedbRecoveryStore,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<PreparedAuthorityMaterial, AuthorityPreparationError> {
        if !is_lower_sha256(expected_sha256) {
            return Err(AuthorityPreparationError::DigestMismatch);
        }
        let bytes = match contour {
            AuthorityDescriptorContour::PortableCurrentUser { root } => {
                let root_lease = UserOwnedRootLease::open_existing(&root)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                let file_lease = UserOwnedPathLease::open_existing(&root_lease, path)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .verify_stable_identity()
                    .and_then(|()| file_lease.verify_path_identity())
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?
            }
            AuthorityDescriptorContour::ProgramData => {
                let file_lease = ProtectedPathLease::open_existing_absolute(path)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .verify_stable_identity()
                    .and_then(|()| file_lease.verify_path_identity())
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?
            }
        };
        if sha256_hex(&bytes) != expected_sha256 {
            return Err(AuthorityPreparationError::DigestMismatch);
        }
        let descriptor: ProcessAuthorityHandoffDescriptor = serde_json::from_slice(&bytes)
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        descriptor
            .validate(now)
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        let secret = platform
            .read_credential(descriptor.dispatch_key.key.as_str())
            .map_err(|_| AuthorityPreparationError::CredentialUnavailable)?;
        if secret.expose().len() != 32 || secret.expose().iter().all(|byte| *byte == 0) {
            return Err(AuthorityPreparationError::CredentialInvalid);
        }
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(secret.expose());
        let key = KernelDispatchKey::from_secret_bytes(key_bytes)
            .map_err(|_| AuthorityPreparationError::CredentialInvalid)?;

        let handoff_id = eliot_ors::OperationIdentity::new(descriptor.handoff_id.as_str())
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        let candidate = AuthorityHandoffRecord {
            contract_version: eliot_ors::CONTRACT_VERSION,
            handoff_id,
            descriptor_digest: descriptor.descriptor_sha256.clone(),
            authority_id: eliot_ors::OpaqueLabel::new(descriptor.authority_id.as_str())
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            snapshot_record_id: descriptor.snapshot_binding.record_id.clone(),
            snapshot_binding_digest: sha256_json(&descriptor.snapshot_binding)
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            authority_epoch: descriptor.state_fence.authority_epoch.value(),
            generation: descriptor.generation.value(),
            state_fence_digest: sha256_json(&descriptor.state_fence)
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            secret_reference_identity_digest: sha256_json(&descriptor.dispatch_key)
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            state: AuthorityHandoffState::Reserved,
            issued_at_ms: descriptor.issued_at_ms,
            expires_at_ms: descriptor.expires_at_ms,
            consumed_at_ms: None,
            reconciliation_evidence: None,
        };
        match ors
            .begin_authority_handoff(&candidate)
            .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?
        {
            AuthorityHandoffBegin::Acquired => {}
            AuthorityHandoffBegin::Existing(_) => return Err(AuthorityPreparationError::Replay),
        }
        let consumed = AuthorityHandoffRecord {
            state: AuthorityHandoffState::Consumed,
            consumed_at_ms: Some(now),
            ..candidate.clone()
        };
        if ors.persist_authority_handoff(&consumed).is_err() {
            let unknown = AuthorityHandoffRecord {
                state: AuthorityHandoffState::Unknown,
                reconciliation_evidence: Some(
                    eliot_ors::OpaqueLabel::new("consume-commit-outcome-unknown")
                        .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?,
                ),
                ..candidate
            };
            let _ = ors.persist_authority_handoff(&unknown);
            return Err(AuthorityPreparationError::PersistenceUnknown);
        }
        Ok(PreparedAuthorityMaterial { descriptor, key })
    }

    /// Builds the production composition with Host-owned canonical evidence
    /// and the active P-07 dispatch authority adapters.
    #[cfg(test)]
    pub fn new_with_adapters(
        config: KernelConfig,
        _authority: Arc<dyn DispatchValidationPort>,
        evidence: Arc<dyn CanonicalEvidenceProvider>,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = Arc::new(
            RedbRecoveryStore::open_with_evidence(&ors_path, evidence)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble(config, ors, None, platform)
    }

    /// Keeps ordered generation, authority, and handoff construction in one
    /// composition path so no intermediate partially wired authority escapes.
    #[allow(clippy::too_many_lines)]
    fn assemble(
        config: KernelConfig,
        ors: Arc<RedbRecoveryStore>,
        process_gateway: Option<Arc<ProcessExecutionGateway>>,
        platform: Arc<WindowsPlatform>,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let store_bootstrap = config.store_bootstrap.clone();
        let _ = &platform;
        let ipc = IpcImplementation::new(config.pipe_name)?;
        // An integrated Kernel must construct its active store route from the
        // exact Host-approved bootstrap fence. Falling back to genesis is
        // reserved for the explicitly standalone composition, where no Store
        // authority has been injected.
        let (authority_epoch, generation) = store_bootstrap.as_ref().map_or(
            (AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            |requirement| {
                (
                    requirement.state_fence.authority_epoch,
                    requirement.state_fence.resource_generation,
                )
            },
        );
        let mut generations = GenerationRouter::at_epoch(authority_epoch)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
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
        // The canonical store bridge has its own route scope.  It starts at
        // the independent genesis generation and is cut over separately from
        // the daemon process route.
        generations
            .register(
                GenerationRoute::new(
                    RouteScope::new("store_bridge")
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
        let artifact_id = std::env::var("ELIOT_APPROVED_ARTIFACT")
            .ok()
            .and_then(|value| ArtifactId::new(value).ok())
            .unwrap_or_else(|| {
                ArtifactId::new("eliotd-child-generation").expect("static artifact")
            });
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
            max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
                .map_err(|_| KernelBuildError::Core("maximum frame exceeds u32".to_owned()))?,
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
        let generation_gateway = OrsGenerationCoordinator::new(ors);
        let mut service = service;
        service
            .synchronize_authority_epoch(authority_epoch)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let mut policy = front_door_policy;
        generation_gateway
            .recover(&mut generations, &mut service, &mut policy)
            .map_err(KernelBuildError::Ors)?;
        Ok(Self {
            work_root,
            runtime,
            platform,
            ipc,
            generation_gateway,
            service: Arc::new(Mutex::new(service)),
            generations: Mutex::new(generations),
            generation_poison: Mutex::new(None),
            front_door_policy: Mutex::new(policy),
            process_gateway,
            store_bootstrap,
            canonical_store_claimed: AtomicBool::new(false),
            #[cfg(windows)]
            canonical_store_gateway: Mutex::new(None),
        })
    }

    /// Returns the selected local IPC name for diagnostics and ready output.
    ///
    /// This is intentionally only a string snapshot.  It carries no
    /// transport or handshake authority and cannot be used to establish a
    /// session.
    #[must_use]
    pub fn ipc(&self) -> &str {
        self.ipc.name()
    }

    /// Returns the fixed transport limits for receive/send loops.
    ///
    /// The limits are diagnostic configuration only; session establishment
    /// remains owned by [`Self::bind_session`].
    #[must_use]
    pub const fn ipc_limits(&self) -> TransportLimits {
        IpcImplementation::limits()
    }

    /// Returns the Host-approved store bootstrap requirement, if injected.
    #[must_use]
    pub fn store_bootstrap(&self) -> Option<&HostStoreBootstrapRequirement> {
        self.store_bootstrap.as_ref()
    }

    /// Returns whether Host/installation authority bindings were injected.
    /// The normal composition is intentionally not process-ready.
    #[must_use]
    pub fn process_execution_configured(&self) -> bool {
        self.process_gateway.is_some()
    }

    /// Connects and retains the one Host-approved canonical-store client and
    /// concrete Kernel gateway. The caller and route are fixed by this
    /// composition; neither can be injected by a daemon or test adapter.
    #[cfg(windows)]
    pub async fn connect_canonical_store(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        self.claim_canonical_store_slot()?;
        let result = self.connect_canonical_store_inner(timeout).await;
        if result.is_err() {
            self.canonical_store_claimed.store(false, Ordering::Release);
        }
        result
    }

    #[cfg(windows)]
    async fn connect_canonical_store_inner(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        let requirement = self
            .store_bootstrap
            .clone()
            .ok_or(KernelBuildError::StoreBootstrapRequired)?;
        requirement
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let expectation = NamedPipePeerExpectation::new(
            requirement.expected_peer_sid.as_str(),
            requirement.expected_peer_session_id,
        )
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let transport = NamedPipeTransport::connect_authenticated(
            requirement.canonical_pipe_identity.as_str(),
            timeout,
            &expectation,
        )
        .await
        .map_err(KernelBuildError::Transport)?;
        let client = EbpCanonicalStoreClient::connect(transport, requirement.clone())
            .await
            .map_err(|error| match error {
                StoreClientError::Transport(error) | StoreClientError::Contract(error) => {
                    KernelBuildError::Service(error)
                }
                StoreClientError::Store(error) => KernelBuildError::Service(error.to_string()),
            })?;
        let route_scope = RouteScope::new(STORE_BRIDGE_ROUTE)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let routes = self
            .generation_route_snapshot()
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let route = routes
            .route(&route_scope)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?
            .clone();
        if route.authority_epoch() != requirement.authority_epoch()
            || route.active_generation() != requirement.store_generation
            || requirement.route_identity.as_str() != STORE_BRIDGE_ROUTE
        {
            return Err(KernelBuildError::Core(
                "store bootstrap does not match the active Kernel store route".to_owned(),
            ));
        }
        let gateway = Arc::new(KernelStoreGateway::new(
            self.service.clone(),
            Arc::new(client),
            route,
        ));
        // Attach to the process gateway first.  The returned transaction rolls
        // that exact pointer back if composition retention fails, so a failed
        // attach cannot poison the retry path or disturb another gateway.
        attach_then_retain_canonical_store(
            Arc::clone(&gateway),
            &self.canonical_store_gateway,
            |gateway| {
                self.process_gateway.as_ref().map_or_else(
                    || {
                        struct NoopAttachment;
                        impl CanonicalStoreAttachmentTransaction for NoopAttachment {
                            fn commit(self: Box<Self>) {}
                        }
                        Ok(Box::new(NoopAttachment)
                            as Box<dyn CanonicalStoreAttachmentTransaction>)
                    },
                    |process_gateway| {
                        process_gateway
                            .attach_canonical_store(gateway)
                            .map(|attachment| {
                                Box::new(attachment) as Box<dyn CanonicalStoreAttachmentTransaction>
                            })
                    },
                )
            },
        )?;
        Ok(gateway)
    }

    fn claim_canonical_store_slot(&self) -> Result<(), KernelBuildError> {
        self.canonical_store_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| KernelBuildError::StoreAlreadyConnected)
    }

    /// Returns the platform surface owned by this composition.
    #[must_use]
    pub fn platform(&self) -> &WindowsPlatform {
        &self.platform
    }

    /// Binds an authenticated local peer to the selected principal/session.
    pub fn bind_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        let generation_poison = self
            .generation_poison
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if generation_poison.is_some() {
            return Err(TransportError::SessionFenced);
        }
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Session::establish_with_server(connection_id, peer, client, &policy)
    }

    #[cfg(test)]
    fn poison_generation_for_test(&self) {
        let Ok(mut generation_poison) = self.generation_poison.lock() else {
            panic!("generation poison lock");
        };
        *generation_poison = Some("test publication failure".to_owned());
        if let Ok(mut service) = self.service.lock() {
            let _ = service.fence_generation("test publication failure");
        }
    }

    /// Runs the currently admitted, deliberately closed semantic gateway.
    ///
    /// Heartbeats are handled locally. Other validated frames, including
    /// shutdown requests, are rejected and fenced until the durable
    /// execution gateway is supplied; this boundary never fabricates
    /// execution success or accepts a peer-owned shutdown authority.
    pub fn dispatch_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .is_some()
        {
            return Err(TransportError::SessionFenced);
        }
        frame.validate()?;
        if !session.accepts(session.authority_epoch, session.session_epoch)
            || frame.connection_id != session.connection_id
            || frame.protocol_version != session.protocol_version
        {
            return Err(TransportError::SessionFenced);
        }
        if let Some(identity) = &frame.request_identity
            && !session
                .module_generation
                .state_fence
                .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }

        if frame.kind == FrameKind::Heartbeat && frame.message_type == MessageType::Health {
            return Ok(KernelFrameAction::Reply(status_frame(
                session,
                FrameKind::Heartbeat,
                MessageType::Health,
                serde_json::json!({
                    "status": "OPEN",
                    "authority_epoch": session.authority_epoch,
                }),
            )?));
        }

        if (frame.kind == FrameKind::Request && frame.message_type == MessageType::Execute)
            || (frame.kind == FrameKind::Cancel && frame.message_type == MessageType::Cancel)
        {
            if self
                .service_state()
                .map_err(|_| TransportError::SessionFenced)?
                != KernelServiceState::Ready
            {
                return Err(TransportError::SessionFenced);
            }
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            session
                .peer
                .validate()
                .map_err(|_| TransportError::PeerIdentityUnavailable)?;
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => return Err(TransportError::SessionFenced),
            };
            let request: ProcessExecutionRequest =
                serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
            request
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            let identity = frame
                .request_identity
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            if request
                .operation_id()
                .is_none_or(|operation_id| identity.idempotency_key != operation_id.as_str())
            {
                return Err(TransportError::SessionFenced);
            }
            if let ProcessExecutionRequest::Start(admission) = &request {
                if admission.recipient_module_id() != session.module_generation.module_id.as_str() {
                    return Err(TransportError::SessionFenced);
                }
                if admission.intent().session_id().as_str() != session.connection_id {
                    return Err(TransportError::SessionFenced);
                }
                if identity.deadline_unix_ms != admission.deadline_unix_ms()
                    || identity.request.state_fence.authority_epoch.value()
                        != admission.state_fence().authority_epoch()
                    || identity.request.state_fence.resource_generation.value()
                        != admission.state_fence().generation().get()
                {
                    return Err(TransportError::SessionFenced);
                }
            }
            let (_, session_binding) = caller_binding(session)?;
            return Ok(KernelFrameAction::Process {
                request_id,
                request,
                session_binding,
            });
        }

        Ok(KernelFrameAction::Fence(
            eliot_ipc::handshake_rejection_frame(
                &session.connection_id,
                "kernel semantic gateway is closed for this session",
            )?,
        ))
    }

    /// Executes one already authenticated process operation and returns only
    /// an inert protocol projection. A composition without the mandatory
    /// external authority bindings fails closed with a typed rejection.
    pub async fn execute_process_request(
        &self,
        session: &Session,
        session_binding: ProcessSessionBinding,
        request: ProcessExecutionRequest,
    ) -> ProcessExecutionResponse {
        let Ok((owner, expected_session_binding)) = caller_binding(session) else {
            return ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection {
                    code: "AUTHENTICATED_CALLER_REQUIRED".to_owned(),
                    detail: "the established authenticated session binding is unavailable"
                        .to_owned(),
                },
            );
        };
        if session_binding != expected_session_binding {
            return ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection {
                    code: "SESSION_BINDING_MISMATCH".to_owned(),
                    detail: "process operation session binding does not match the established authenticated session".to_owned(),
                },
            );
        }
        let Some(gateway) = &self.process_gateway else {
            return ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection {
                    code: "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED".to_owned(),
                    detail: "external process authority key, snapshot, replay, and evidence bindings are required".to_owned(),
                },
            );
        };
        let result = match request {
            ProcessExecutionRequest::Start(admission) => {
                let proof = match self.retain_process_path_proof(&admission) {
                    Ok(proof) => proof,
                    Err(error) => {
                        return ProcessExecutionResponse::Rejected(
                            eliot_kernel_service::ProcessExecutionRejection::from_error(&error),
                        );
                    }
                };
                gateway
                    .start(&owner, admission, proof)
                    .await
                    .map(ProcessExecutionResponse::Started)
            }
            ProcessExecutionRequest::Inspect { operation_id } => gateway
                .inspect(&owner, operation_id)
                .await
                .map(ProcessExecutionResponse::Status),
            ProcessExecutionRequest::Cancel { operation_id } => gateway
                .cancel(&owner, operation_id)
                .await
                .map(ProcessExecutionResponse::Cancelled),
            ProcessExecutionRequest::Reconcile { operation_id } => gateway
                .reconcile(&owner, operation_id)
                .await
                .map(ProcessExecutionResponse::Reconciled),
        };
        result.unwrap_or_else(|error| {
            ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection::from_error(&error),
            )
        })
    }

    fn retain_process_path_proof(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> Result<ProcessPathProof, ProcessExecutionError> {
        let executable = PathBuf::from(admission.intent().executable());
        let working_directory = PathBuf::from(admission.intent().working_directory());
        executable.strip_prefix(&self.work_root).map_err(|_| {
            ProcessExecutionError::Contract(eliot_process::ContractError::InvalidValue {
                field: "process_root",
                reason: "executable is outside the retained WorkScope root",
            })
        })?;
        working_directory
            .strip_prefix(&self.work_root)
            .map_err(|_| {
                ProcessExecutionError::Contract(eliot_process::ContractError::InvalidValue {
                    field: "process_root",
                    reason: "working directory is outside the retained WorkScope root",
                })
            })?;
        let lease = self
            .platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        Ok(ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        })
    }

    /// Builds the correlated response frame for one process operation.
    pub fn process_response_frame(
        &self,
        session: &Session,
        request_id: RequestId,
        response: &ProcessExecutionResponse,
    ) -> Result<Frame, TransportError> {
        let mut frame = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
        )?;
        frame.request_id = Some(request_id);
        frame.validate()?;
        Ok(frame)
    }

    /// Binds the authenticated local Windows front door to the current
    /// installation principal.  The returned server must be retained by the
    /// service loop for the lifetime of the accepted connection.
    #[cfg(windows)]
    pub fn bind_authenticated_front_door(&self) -> Result<NamedPipeServer, KernelBuildError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| KernelBuildError::Principal("generation poison lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Principal(
                "generation gateway fenced; forward recovery is required".to_owned(),
            ));
        }
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        NamedPipeServer::create(self.ipc.name(), &expectation)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Binds one additional authenticated Windows front-door instance for a
    /// concurrent session while the first instance remains connected.
    #[cfg(windows)]
    pub fn bind_authenticated_front_door_next(&self) -> Result<NamedPipeServer, KernelBuildError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| KernelBuildError::Principal("generation poison lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Principal(
                "generation gateway fenced; forward recovery is required".to_owned(),
            ));
        }
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        NamedPipeServer::create_additional(self.ipc.name(), &expectation)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Returns a cloned, read-only route projection.  Callers cannot obtain a
    /// mutable router guard or bypass the ORS transition gateway.
    pub fn generation_route_snapshot(&self) -> Result<GenerationRouter, KernelServiceError> {
        if let Some(reason) = self
            .generation_poison
            .lock()
            .map_err(|_| {
                KernelServiceError::Platform("generation poison lock poisoned".to_owned())
            })?
            .clone()
        {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        self.generations
            .lock()
            .map(|router| router.clone())
            .map_err(|_| KernelServiceError::Platform("generation lock poisoned".to_owned()))
    }

    /// Persists and publishes one epoch-raising generation cutover through the
    /// sole semantic gateway.  A failed publish permanently fences this
    /// composition instance until restart/recovery proves a durable route.
    pub fn apply_generation_cutover(
        &self,
        decision: &eliot_kernel_core::CutoverDecision,
    ) -> Result<(), KernelServiceError> {
        let mut poison = self.generation_poison.lock().map_err(|_| {
            KernelServiceError::Platform("generation poison lock poisoned".to_owned())
        })?;
        if let Some(reason) = poison.clone() {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        let result = (|| {
            let mut generations = self
                .generations
                .lock()
                .map_err(|_| "generation lock poisoned".to_owned())?;
            let mut service = self
                .service
                .lock()
                .map_err(|_| "service lock poisoned".to_owned())?;
            let mut policy = self
                .front_door_policy
                .lock()
                .map_err(|_| "front-door policy lock poisoned".to_owned())?;
            self.generation_gateway.persist_and_publish(
                decision,
                &mut generations,
                &mut service,
                &mut policy,
            )
        })();
        if let Err(reason) = result {
            *poison = Some(reason.clone());
            if let Ok(mut service) = self.service.lock() {
                let _ = service.fence_generation(reason.clone());
            }
            return Err(KernelServiceError::Platform(format!(
                "generation cutover fenced: {reason}"
            )));
        }
        Ok(())
    }

    /// Applies one lifecycle command through the sole Kernel transition gateway.
    pub fn apply_control(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        if let Some(reason) = self
            .generation_poison
            .lock()
            .map_err(|_| {
                KernelServiceError::Platform("generation poison lock poisoned".to_owned())
            })?
            .clone()
        {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        self.service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .apply(command)
    }

    /// Applies one authenticated Host control request after binding the
    /// transport's handle-proven peer and the approved generation contour.
    pub fn apply_control_request(
        &self,
        request: KernelControlRequest,
        peer: &PeerIdentity,
        expected_sequence: u64,
    ) -> Result<KernelControlResponse, TransportError> {
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        peer.validate()?;
        let observed_peer = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if request.sequence != expected_sequence
            || request.peer_process_id != observed_peer.process_id()
            || request.handshake.pipe_identity.as_str() != self.ipc.name()
        {
            return Err(TransportError::SessionFenced);
        }
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if request.generation != policy.module_generation.generation
            || request.handshake.kernel_epoch
                != policy.module_generation.state_fence.authority_epoch
            || request.handshake.artifact_hash.as_str()
                != policy.module_generation.artifact_id.as_str()
        {
            return Err(TransportError::SessionFenced);
        }
        drop(policy);
        if let KernelControlCommand::Reconcile(handshake) = &request.command {
            if handshake != &request.handshake {
                return Err(TransportError::SessionFenced);
            }
        }
        let receipt = match &request.command {
            KernelControlCommand::Ready(receipt) => Some(receipt.clone()),
            _ => None,
        };
        self.apply_control(request.command)
            .map_err(|_| TransportError::SessionFenced)?;
        let state = self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?;
        KernelControlResponse {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: request.message_id,
            request_digest: request.payload_digest,
            state,
            receipt,
            error: None,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)
    }

    /// Returns the current Kernel service lifecycle state.
    pub fn service_state(&self) -> Result<KernelServiceState, KernelServiceError> {
        Ok(self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .state())
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
    pub async fn shutdown(&self) -> Result<ShutdownOutcome, ProcessExecutionError> {
        let process_result = self
            .process_gateway
            .as_ref()
            .map_or(Ok(()), |gateway| gateway.executor.shutdown());
        let runtime_outcome = self.runtime.shutdown().await;
        process_result?;
        Ok(runtime_outcome)
    }
}

fn status_frame(
    session: &Session,
    kind: FrameKind,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<Frame, TransportError> {
    let frame = Frame {
        protocol_version: session.protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
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

#[allow(dead_code)]
fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[allow(dead_code)]
fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[allow(dead_code)]
fn sha256_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

/// Resolves and validates the default `WorkScope` root for the binary entrypoint.
pub fn default_work_root() -> Result<PathBuf, std::io::Error> {
    let root = std::env::var_os("ELIOT_WORK_ROOT").map_or(std::env::current_dir()?, PathBuf::from);
    std::fs::canonicalize(Path::new(&root))
}

#[cfg(test)]
#[allow(clippy::default_trait_access, clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::ContractVersion;
    use eliot_kernel_core::{KernelError, KernelResult, SealedAuthoritySnapshot};
    use eliot_ors::{
        EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, RecoveryPayload,
        StateFenceSnapshot,
    };
    use eliot_platform::{PlatformHandle, SecretReference};
    use eliot_process::{
        ActionLeaseRef, DispatchPermitReplaySnapshot, EnvironmentInheritance,
        EnvironmentProjection, FencingToken, ImageId, JobId, OperationId, PermitIssuance,
        ProcessTreeId, ResourceLimits, SessionId,
    };
    use eliot_runtime_contracts::ModuleContract;
    use eliot_store_api::{RevisionHead, RevisionKey};

    fn test_client(policy: &ServerHandshakePolicy) -> eliot_protocol::ClientHello {
        eliot_protocol::ClientHello {
            protocol_range: policy.protocol_range,
            module_bridge_identity: policy.module_id.clone(),
            artifact_hash: policy.module_generation.artifact_id.clone(),
            module_contract: ModuleContract {
                module_id: policy.module_generation.module_id.clone(),
                version: ContractVersion::new(1, 0, 0),
                artifact_id: policy.module_generation.artifact_id.clone(),
                protocols: vec![PROTOCOL_VERSION.to_owned()],
                required_capabilities: Vec::new(),
                optional_capabilities: Vec::new(),
                advisory_capabilities: Vec::new(),
                state_owner: SERVICE_NAME.to_owned(),
                failure_domain: SERVICE_NAME.to_owned(),
                hot_replace: false,
            },
            module_generation: policy.module_generation.clone(),
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            max_frame: policy.max_frame,
            authority_epoch: policy.module_generation.state_fence.authority_epoch,
        }
    }

    struct JsonSnapshotCodec;

    impl DispatchSnapshotCodec for JsonSnapshotCodec {
        fn seal(
            &self,
            snapshot: &DispatchPermitReplaySnapshot,
            _binding: &AuthoritySnapshotBinding,
        ) -> KernelResult<SealedAuthoritySnapshot> {
            let ciphertext = serde_json::to_vec(snapshot)
                .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
            let key = SecretReference::new("test-provider", "kernel-authority")
                .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
            SealedAuthoritySnapshot::new(key, ciphertext)
        }

        fn open(
            &self,
            payload: &RecoveryPayload,
            _binding: &AuthoritySnapshotBinding,
        ) -> KernelResult<DispatchPermitReplaySnapshot> {
            let RecoveryPayload::Encrypted { ciphertext, .. } = payload else {
                return Err(KernelError::RecoveryUnavailable(
                    "authority fixture payload is not encrypted".to_owned(),
                ));
            };
            serde_json::from_slice(ciphertext)
                .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))
        }
    }

    fn authority_binding(authority_id: &DispatchAuthorityId) -> AuthoritySnapshotBinding {
        let epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new("kernel-test-lineage").expect("lineage"),
                epoch: 1,
            },
            predecessor: None,
        };
        let state_fence =
            StateFenceSnapshot::capture(&serde_json::json!({"authority": "kernel-test"}), 1)
                .expect("state fence");
        AuthoritySnapshotBinding::new(
            authority_id.clone(),
            OperationIdentity::new("kernel-test-authority-record").expect("record id"),
            epoch,
            state_fence,
            1,
            None,
        )
        .expect("authority binding")
    }

    fn seed_intent() -> ProcessIntent {
        ProcessIntent::new(
            OperationId::new("kernel-authority-seed-operation").expect("operation"),
            ProcessTreeId::new("kernel-authority-seed-tree").expect("tree"),
            JobId::new("kernel-authority-seed-job").expect("job"),
            ImageId::new("kernel-authority-seed-image").expect("image"),
            SessionId::new("kernel-authority-seed-session").expect("session"),
            Generation::new(1).expect("generation"),
            "C:\\eliot\\seed-worker.exe",
            "c".repeat(64),
            vec!["--seed".to_owned()],
            "C:\\eliot",
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .expect("environment"),
            ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
                .expect("limits"),
        )
        .expect("intent")
    }

    fn test_validation_context(seed: &str) -> DispatchValidationContext {
        DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(1_000),
                known_time_ms: Some(1_000),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            FencingToken::new(1, Generation::new(1).expect("generation"), "context-fence")
                .expect("fence"),
            1,
            BTreeMap::from([(seed.to_owned(), "a".repeat(64))]),
            1,
        )
        .expect("context")
    }

    #[derive(Clone)]
    struct GatewayTestPorts {
        state: Arc<Mutex<GatewayTestState>>,
    }

    struct GatewayTestState {
        snapshot: Result<CanonicalValidationSnapshot, String>,
        snapshot_calls: usize,
        issue_calls: usize,
        executor_starts: usize,
        validations: usize,
        resumes: usize,
        retained_contexts: BTreeMap<OperationId, (FencingToken, BTreeMap<String, String>, u64)>,
        retained_paths: std::collections::BTreeSet<OperationId>,
        context_count_tx: tokio::sync::watch::Sender<usize>,
        replay: BTreeMap<OperationId, ProcessExecutionReplayRecord>,
        completed_persisted: usize,
        fail_context: bool,
        abort_not_released: bool,
        abort_calls: usize,
        pause_executor: Option<Arc<tokio::sync::Notify>>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct GatewayTestRequest {
        operation_id: OperationId,
        fence: FencingToken,
        heads: BTreeMap<String, String>,
        validation_revision: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct GatewayTestReceipt {
        operation_id: OperationId,
    }

    struct GatewayTestGuard {
        state: Arc<Mutex<GatewayTestState>>,
        operation_id: OperationId,
        context: bool,
    }

    impl Drop for GatewayTestGuard {
        fn drop(&mut self) {
            if let Ok(mut state) = self.state.lock() {
                if self.context {
                    state.retained_contexts.remove(&self.operation_id);
                } else {
                    state.retained_paths.remove(&self.operation_id);
                }
                let _ = state.context_count_tx.send(state.retained_contexts.len());
            }
        }
    }

    fn gateway_test_snapshot() -> CanonicalValidationSnapshot {
        let fence = StoreStateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        );
        CanonicalValidationSnapshot {
            state_fence: fence.clone(),
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new("scope:test").expect("key"),
                revision: 7,
                state_fence: fence,
            }],
            validation_revision: 9,
            observed_at_unix_ms: 1_000,
        }
    }

    fn gateway_test_owner() -> ProcessOwnerBinding {
        ProcessOwnerBinding::new(
            "eliotd",
            "a".repeat(64),
            1,
            Generation::new(1).expect("generation"),
        )
        .expect("owner")
    }

    fn gateway_test_admission(operation: &str) -> ProcessExecutionAdmissionRequest {
        let mut intent = seed_intent();
        intent = ProcessIntent::new(
            OperationId::new(operation).expect("operation"),
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            intent.generation(),
            intent.executable(),
            intent.executable_sha256(),
            intent.argv().to_vec(),
            intent.working_directory(),
            intent.environment().clone(),
            *intent.resource_limits(),
        )
        .expect("unique intent");
        ProcessExecutionAdmissionRequest::new(
            "eliotd",
            intent,
            ActionLeaseRef::new(format!("lease-{operation}")).expect("lease"),
            FencingToken::new(
                1,
                Generation::new(1).expect("generation"),
                format!("fence-{operation}"),
            )
            .expect("fence"),
            unix_ms().saturating_add(60_000),
        )
        .expect("admission")
    }

    impl GatewayTestPorts {
        fn new(snapshot: Result<CanonicalValidationSnapshot, String>) -> Self {
            let (context_count_tx, _context_count_rx) = tokio::sync::watch::channel(0_usize);
            Self {
                state: Arc::new(Mutex::new(GatewayTestState {
                    snapshot,
                    snapshot_calls: 0,
                    issue_calls: 0,
                    executor_starts: 0,
                    validations: 0,
                    resumes: 0,
                    retained_contexts: BTreeMap::new(),
                    retained_paths: std::collections::BTreeSet::new(),
                    context_count_tx,
                    replay: BTreeMap::new(),
                    completed_persisted: 0,
                    fail_context: false,
                    abort_not_released: false,
                    abort_calls: 0,
                    pause_executor: None,
                })),
            }
        }

        async fn wait_contexts(&self, target: usize) {
            let mut receiver = self
                .state
                .lock()
                .expect("test state")
                .context_count_tx
                .subscribe();
            while *receiver.borrow() < target {
                receiver.changed().await.expect("context count channel");
            }
        }

        fn pause_executor(&self, pause: Arc<tokio::sync::Notify>) {
            self.state.lock().expect("test state").pause_executor = Some(pause);
        }

        fn fail_context(&self) {
            self.state.lock().expect("test state").fail_context = true;
        }

        fn allow_context(&self) {
            self.state.lock().expect("test state").fail_context = false;
        }

        fn fail_abort(&self) {
            self.state.lock().expect("test state").abort_not_released = true;
        }

        fn allow_abort(&self) {
            self.state.lock().expect("test state").abort_not_released = false;
        }

        fn counts(&self) -> (usize, usize, usize, usize, usize) {
            let state = self.state.lock().expect("test state");
            (
                state.snapshot_calls,
                state.issue_calls,
                state.executor_starts,
                state.validations,
                state.resumes,
            )
        }

        fn retained(&self) -> (usize, usize) {
            let state = self.state.lock().expect("test state");
            (state.retained_contexts.len(), state.retained_paths.len())
        }

        fn abort_calls(&self) -> usize {
            self.state.lock().expect("test state").abort_calls
        }
    }

    impl ProcessStartPorts for GatewayTestPorts {
        type PathProof = ();
        type Request = GatewayTestRequest;
        type Receipt = GatewayTestReceipt;

        fn validate_admission(
            &self,
            admission: &ProcessExecutionAdmissionRequest,
            owner: &ProcessOwnerBinding,
        ) -> Result<(), ProcessExecutionError> {
            if admission.recipient_module_id() != owner.module_id()
                || admission.state_fence().authority_epoch() != owner.authority_epoch()
                || admission.state_fence().generation() != owner.generation()
            {
                return Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ));
            }
            Ok(())
        }

        fn now(&self) -> u64 {
            unix_ms()
        }

        fn validate_path(
            &self,
            _admission: &ProcessExecutionAdmissionRequest,
            _path_proof: &Self::PathProof,
        ) -> Result<(), ProcessExecutionError> {
            Ok(())
        }

        fn begin(
            &self,
            operation_id: &OperationId,
            digest: &str,
            owner: &ProcessOwnerBinding,
        ) -> Result<ProcessExecutionReplayBegin, ProcessExecutionError> {
            let mut state = self.state.lock().expect("test state");
            if let Some(existing) = state.replay.get(operation_id) {
                return Ok(ProcessExecutionReplayBegin::Existing(existing.clone()));
            }
            let record = ProcessExecutionReplayRecord {
                admission_digest: digest.to_owned(),
                owner: owner.clone(),
                state: ProcessExecutionReplayState::Reserved,
                receipt: None,
            };
            state.replay.insert(operation_id.clone(), record);
            Ok(ProcessExecutionReplayBegin::Acquired)
        }

        fn completed_receipt(
            &self,
            _record: ProcessExecutionReplayRecord,
        ) -> Result<Option<Self::Receipt>, ProcessExecutionError> {
            Err(ProcessExecutionError::UnknownOutcome)
        }

        async fn snapshot(&self) -> Result<CanonicalValidationSnapshot, ProcessExecutionError> {
            let snapshot = {
                let mut state = self.state.lock().expect("test state");
                state.snapshot_calls += 1;
                state.snapshot.clone()
            };
            snapshot.map_err(ProcessExecutionError::Unavailable)
        }

        fn build_context(
            &self,
            clock: ClockObservation,
            store_fence: FencingToken,
            authority_epoch: u64,
            revision_heads: BTreeMap<String, String>,
            validation_revision: u64,
        ) -> Result<DispatchValidationContext, ProcessExecutionError> {
            if self.state.lock().expect("test state").fail_context {
                return Err(ProcessExecutionError::Unavailable(
                    "injected validation context failure".to_owned(),
                ));
            }
            DispatchValidationContext::new(
                clock,
                store_fence,
                authority_epoch,
                revision_heads,
                validation_revision,
            )
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
        }

        fn insert_context(
            &self,
            operation_id: OperationId,
            context: DispatchValidationContext,
        ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
            {
                let mut state = self.state.lock().expect("test state");
                if state.retained_contexts.contains_key(&operation_id) {
                    return Err(ProcessExecutionError::Contract(
                        eliot_process::ContractError::DispatchBindingMismatch,
                    ));
                }
                let _ = context;
                state.retained_contexts.insert(
                    operation_id.clone(),
                    (
                        FencingToken::new(1, Generation::new(1).expect("generation"), "pending")
                            .expect("pending fence"),
                        BTreeMap::new(),
                        0,
                    ),
                );
                let _ = state.context_count_tx.send(state.retained_contexts.len());
            }
            Ok(Box::new(GatewayTestGuard {
                state: Arc::clone(&self.state),
                operation_id,
                context: true,
            }))
        }

        fn issue(
            &self,
            admission: &ProcessExecutionAdmissionRequest,
            store_fence: FencingToken,
            revision_heads: BTreeMap<String, String>,
            _now: u64,
            validation_revision: u64,
        ) -> Result<Self::Request, ProcessExecutionError> {
            let mut state = self.state.lock().expect("test state");
            state.issue_calls += 1;
            if let Some(context) = state
                .retained_contexts
                .get_mut(admission.intent().operation_id())
            {
                *context = (
                    store_fence.clone(),
                    revision_heads.clone(),
                    validation_revision,
                );
            }
            Ok(GatewayTestRequest {
                operation_id: admission.intent().operation_id().clone(),
                fence: store_fence,
                heads: revision_heads,
                validation_revision,
            })
        }

        fn insert_path(
            &self,
            operation_id: OperationId,
            _path_proof: Self::PathProof,
        ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
            let mut state = self.state.lock().expect("test state");
            if !state.retained_paths.insert(operation_id.clone()) {
                return Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ));
            }
            Ok(Box::new(GatewayTestGuard {
                state: Arc::clone(&self.state),
                operation_id,
                context: false,
            }))
        }

        async fn execute(
            &self,
            _owner: &ProcessOwnerBinding,
            request: Self::Request,
        ) -> Result<Self::Receipt, ProcessExecutionError> {
            let pause = {
                let mut state = self.state.lock().expect("test state");
                state.executor_starts += 1;
                let context = state.retained_contexts.get(&request.operation_id).ok_or(
                    ProcessExecutionError::Contract(
                        eliot_process::ContractError::DispatchBindingMismatch,
                    ),
                )?;
                if context.0 != request.fence
                    || context.1 != request.heads
                    || context.2 != request.validation_revision
                {
                    return Err(ProcessExecutionError::Contract(
                        eliot_process::ContractError::DispatchBindingMismatch,
                    ));
                }
                state.validations += 1;
                state.pause_executor.clone()
            };
            if let Some(pause) = pause {
                pause.notified().await;
            }
            self.state.lock().expect("test state").resumes += 1;
            Ok(GatewayTestReceipt {
                operation_id: request.operation_id,
            })
        }

        fn persist_completed(
            &self,
            operation_id: &OperationId,
            digest: &str,
            owner: &ProcessOwnerBinding,
            receipt: Self::Receipt,
        ) -> Result<(), ProcessExecutionError> {
            let mut state = self.state.lock().expect("test state");
            state.completed_persisted += 1;
            state.replay.insert(
                operation_id.clone(),
                ProcessExecutionReplayRecord {
                    admission_digest: digest.to_owned(),
                    owner: owner.clone(),
                    state: ProcessExecutionReplayState::Completed,
                    receipt: None,
                },
            );
            assert_eq!(receipt.operation_id, *operation_id);
            Ok(())
        }

        fn mark_unknown(
            &self,
            operation_id: &OperationId,
            digest: &str,
            owner: &ProcessOwnerBinding,
        ) {
            if let Ok(mut state) = self.state.lock() {
                state.replay.insert(
                    operation_id.clone(),
                    ProcessExecutionReplayRecord {
                        admission_digest: digest.to_owned(),
                        owner: owner.clone(),
                        state: ProcessExecutionReplayState::Unknown,
                        receipt: None,
                    },
                );
            }
        }

        fn abort(
            &self,
            operation_id: &OperationId,
            digest: &str,
            owner: &ProcessOwnerBinding,
        ) -> Result<ProcessExecutionReplayAbort, ProcessExecutionError> {
            let mut state = self.state.lock().expect("test state");
            state.abort_calls += 1;
            if state.abort_not_released {
                return Ok(ProcessExecutionReplayAbort::NotReleased);
            }
            let Some(record) = state.replay.get(operation_id) else {
                return Err(ProcessExecutionError::Unavailable(
                    "missing replay".to_owned(),
                ));
            };
            if record.state == ProcessExecutionReplayState::Reserved
                && record.admission_digest == digest
                && record.owner == *owner
            {
                state.replay.remove(operation_id);
                return Ok(ProcessExecutionReplayAbort::Released);
            }
            Ok(ProcessExecutionReplayAbort::NotReleased)
        }
    }

    #[cfg(windows)]
    fn authority_test_suffix() -> String {
        format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        )
    }

    #[cfg(windows)]
    struct AuthorityTestCleanup {
        paths: Vec<PathBuf>,
    }

    #[cfg(windows)]
    impl Drop for AuthorityTestCleanup {
        fn drop(&mut self) {
            for path in &self.paths {
                let _ = std::fs::remove_dir_all(path);
                let _ = std::fs::remove_file(path);
            }
        }
    }

    #[cfg(windows)]
    struct CredentialCleanup {
        platform: Arc<WindowsPlatform>,
        key: String,
    }

    #[cfg(windows)]
    impl Drop for CredentialCleanup {
        fn drop(&mut self) {
            let _ = self.platform.delete_credential(&self.key);
        }
    }

    #[cfg(windows)]
    fn authority_descriptor(suffix: &str, provider: &str) -> ProcessAuthorityHandoffDescriptor {
        let authority_id =
            DispatchAuthorityId::new(format!("authority-{suffix}")).expect("authority id");
        let state_fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        let epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new(format!("handoff-lineage-{suffix}")).expect("lineage"),
                epoch: 1,
            },
            predecessor: None,
        };
        let snapshot_binding = AuthoritySnapshotBindingWire {
            authority_id: authority_id.clone(),
            record_id: OperationIdentity::new(format!("snapshot-{suffix}"))
                .expect("snapshot record"),
            authority_epoch: epoch,
            state_fence: StateFenceSnapshot::capture(&state_fence, 1).expect("snapshot fence"),
            created_at_ms: 1,
            cleanup_after_ms: Some(2),
        };
        let now = i64::try_from(unix_ms()).expect("test clock");
        ProcessAuthorityHandoffDescriptor {
            contract_version: ProcessAuthorityHandoffDescriptor::CONTRACT_VERSION,
            handoff_id: PlatformHandle::new(format!("handoff-{suffix}")).expect("handoff"),
            handoff_nonce: PlatformHandle::new(format!("nonce-{suffix}")).expect("nonce"),
            authority_id,
            snapshot_binding,
            state_fence,
            generation: ResourceGeneration::genesis(),
            revision_policy_binding: PlatformHandle::new(format!("policy-{suffix}"))
                .expect("policy"),
            dispatch_key: SecretReference::new(provider, format!("eliot/kernel/test/{suffix}"))
                .expect("credential reference"),
            descriptor_sha256: String::new(),
            issued_at_ms: now.saturating_sub(1_000),
            expires_at_ms: now.saturating_add(60_000),
            contour_refs: vec![
                PlatformHandle::new("portable_dev").expect("contour"),
                PlatformHandle::new("authority_descriptor").expect("descriptor contour"),
            ],
        }
        .with_computed_digest()
        .expect("descriptor digest")
    }

    #[cfg(windows)]
    fn write_authority_descriptor(
        root: &Path,
        name: &str,
        descriptor: &ProcessAuthorityHandoffDescriptor,
    ) -> (PathBuf, String) {
        let bytes = serde_json::to_vec(descriptor).expect("descriptor bytes");
        let path = root.join(format!("{name}.json"));
        std::fs::write(&path, &bytes).expect("descriptor file");
        (path, sha256_hex(&bytes))
    }

    #[cfg(windows)]
    fn write_authority_bytes(root: &Path, name: &str, bytes: &[u8]) -> (PathBuf, String) {
        let path = root.join(format!("{name}.json"));
        std::fs::write(&path, bytes).expect("descriptor bytes");
        (path, sha256_hex(bytes))
    }

    #[cfg(windows)]
    fn credential_cleanup(platform: &Arc<WindowsPlatform>, key: &str) -> CredentialCleanup {
        CredentialCleanup {
            platform: Arc::clone(platform),
            key: key.to_owned(),
        }
    }

    #[test]
    fn pre_poison_ipc_handles_cannot_establish_handshake() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-ipc-fence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");

        // These are the only public IPC values retained across the fence:
        // immutable diagnostics, not a transport or policy authority.
        let saved_ipc_name = kernel.ipc().to_owned();
        let saved_limits = kernel.ipc_limits();
        let stale_client = {
            let policy = kernel
                .front_door_policy
                .lock()
                .expect("front-door policy lock");
            test_client(&policy)
        };

        kernel.poison_generation_for_test();

        assert_eq!(kernel.ipc(), saved_ipc_name);
        assert_eq!(kernel.ipc_limits(), saved_limits);
        assert!(matches!(
            kernel.bind_session(
                "pre-poison-connection",
                PeerIdentity::Unavailable {
                    reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
                },
                &stale_client,
            ),
            Err(TransportError::SessionFenced)
        ));

        #[cfg(windows)]
        {
            assert!(matches!(
                kernel.bind_authenticated_front_door(),
                Err(KernelBuildError::Principal(reason))
                    if reason.contains("generation gateway fenced")
            ));
            assert!(matches!(
                kernel.bind_authenticated_front_door_next(),
                Err(KernelBuildError::Principal(reason))
                    if reason.contains("generation gateway fenced")
            ));
        }

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn canonical_store_slot_rejects_a_second_client_or_writer() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-store-slot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");

        assert!(kernel.claim_canonical_store_slot().is_ok());
        assert!(matches!(
            kernel.claim_canonical_store_slot(),
            Err(KernelBuildError::StoreAlreadyConnected)
        ));

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    struct TestCanonicalStoreAttachment {
        slot: Arc<Mutex<Option<Arc<u8>>>>,
        gateway: Arc<u8>,
        active: Arc<AtomicBool>,
    }

    #[cfg(windows)]
    impl CanonicalStoreAttachmentTransaction for TestCanonicalStoreAttachment {
        fn commit(self: Box<Self>) {
            self.active.store(false, Ordering::Release);
        }
    }

    #[cfg(windows)]
    impl Drop for TestCanonicalStoreAttachment {
        fn drop(&mut self) {
            if self.active.load(Ordering::Acquire)
                && let Ok(mut slot) = self.slot.lock()
                && slot
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &self.gateway))
            {
                *slot = None;
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_store_attach_failure_does_not_retain_or_poison_retry() {
        let retained = Mutex::new(None);
        let gateway = Arc::new(7_u8);
        assert!(matches!(
            attach_then_retain_canonical_store(Arc::clone(&gateway), &retained, |_| {
                Err(KernelBuildError::StoreAlreadyConnected)
            }),
            Err(KernelBuildError::StoreAlreadyConnected)
        ));
        assert!(retained.lock().expect("retained lock").is_none());

        let process_slot = Arc::new(Mutex::new(None));
        let active = Arc::new(AtomicBool::new(true));
        assert!(retained.lock().expect("retry lock").is_none());
        assert!(
            attach_then_retain_canonical_store(Arc::clone(&gateway), &retained, |gateway| {
                *process_slot.lock().expect("process slot") = Some(Arc::clone(&gateway));
                Ok(Box::new(TestCanonicalStoreAttachment {
                    slot: Arc::clone(&process_slot),
                    gateway,
                    active: Arc::clone(&active),
                })
                    as Box<dyn CanonicalStoreAttachmentTransaction>)
            },)
            .is_ok()
        );
        assert!(retained.lock().expect("retry lock").is_some());
        assert!(!active.load(Ordering::Acquire));
    }

    #[cfg(windows)]
    #[test]
    fn canonical_store_retain_failure_rolls_back_only_new_process_attachment() {
        let retained = Arc::new(Mutex::new(None));
        let poisoned = Arc::clone(&retained);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().expect("poison lock");
            panic!("force composition retain failure");
        })
        .join();

        let process_slot = Arc::new(Mutex::new(None));
        let unrelated = Arc::new(99_u8);
        let unrelated_slot = Arc::new(Mutex::new(Some(Arc::clone(&unrelated))));
        let gateway = Arc::new(7_u8);
        assert!(matches!(
            attach_then_retain_canonical_store(
                Arc::clone(&gateway),
                &retained,
                |gateway| {
                    *process_slot.lock().expect("process slot") = Some(Arc::clone(&gateway));
                    Ok(Box::new(TestCanonicalStoreAttachment {
                        slot: Arc::clone(&process_slot),
                        gateway,
                        active: Arc::new(AtomicBool::new(true)),
                    }) as Box<dyn CanonicalStoreAttachmentTransaction>)
                },
            ),
            Err(KernelBuildError::Service(reason)) if reason == "store gateway lock poisoned"
        ));
        assert!(
            process_slot
                .lock()
                .expect("process rollback slot")
                .is_none()
        );
        assert!(Arc::ptr_eq(
            unrelated_slot
                .lock()
                .expect("unrelated slot")
                .as_ref()
                .expect("unrelated gateway"),
            &unrelated
        ));
    }

    #[test]
    fn normal_composition_is_not_process_ready_without_host_handoff() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-no-process-authority-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
        assert!(!kernel.process_execution_configured());
        assert_eq!(Arc::strong_count(&kernel.generation_gateway.ors), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn validation_context_slot_is_entry_based_and_one_shot() {
        let slot = Arc::new(ValidationContextSlot::new());
        let operation = OperationId::new("slot-operation").expect("operation");
        let first = test_validation_context("first");
        let second = test_validation_context("second");
        let guard = slot
            .insert(operation.clone(), first.clone())
            .expect("first insertion");
        assert!(slot.insert(operation.clone(), second).is_err());
        assert_eq!(slot.take(&operation).expect("take first"), first);
        assert!(slot.take(&operation).is_err());
        drop(guard);
        let guard = slot
            .insert(operation.clone(), test_validation_context("replacement"))
            .expect("replacement insertion");
        drop(guard);
        assert!(slot.take(&operation).is_err());
    }

    #[test]
    fn validation_context_slot_guards_independent_operations_and_abort_cleanup() {
        let slot = Arc::new(ValidationContextSlot::new());
        let first_id = OperationId::new("slot-first").expect("operation");
        let second_id = OperationId::new("slot-second").expect("operation");
        let first_guard = slot
            .insert(first_id.clone(), test_validation_context("first"))
            .expect("first insertion");
        let second_guard = slot
            .insert(second_id.clone(), test_validation_context("second"))
            .expect("second insertion");
        let second = slot.take(&second_id).expect("second take");
        assert_eq!(second, test_validation_context("second"));
        drop(first_guard);
        drop(second_guard);
        assert!(slot.take(&first_id).is_err());
        assert!(slot.take(&second_id).is_err());
    }

    #[tokio::test]
    async fn actual_process_start_orchestration_proves_canonical_ordering() {
        let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        let owner = gateway_test_owner();
        let admission = gateway_test_admission("gateway-positive");
        let receipt = run_process_start(&ports, &owner, admission, ())
            .await
            .expect("start");
        assert_eq!(receipt.operation_id.as_str(), "gateway-positive");
        assert_eq!(ports.counts(), (1, 1, 1, 1, 1));
        assert_eq!(ports.retained(), (0, 0));
        let state = ports.state.lock().expect("test state");
        assert_eq!(state.completed_persisted, 1);
        assert_eq!(
            state
                .replay
                .get(&OperationId::new("gateway-positive").expect("operation"))
                .expect("completed replay")
                .state,
            ProcessExecutionReplayState::Completed
        );
    }

    #[tokio::test]
    async fn actual_process_start_orchestration_fails_closed_and_releases_reserved() {
        let mut malformed = gateway_test_snapshot();
        malformed.validation_revision = 0;
        let mut stale = gateway_test_snapshot();
        stale.state_fence = StoreStateFence::new(
            eliot_contracts::AuthorityEpoch::new(2).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        );
        for head in &mut stale.revision_heads {
            head.state_fence = stale.state_fence.clone();
        }
        let mut substituted = gateway_test_snapshot();
        substituted.revision_heads[0].state_fence = StoreStateFence::new(
            eliot_contracts::AuthorityEpoch::new(8).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        );
        for (name, snapshot) in [
            ("unavailable", Err("store unavailable".to_owned())),
            ("malformed", Ok(malformed)),
            ("stale", Ok(stale)),
            ("substituted", Ok(substituted)),
        ] {
            let ports = GatewayTestPorts::new(snapshot);
            let owner = gateway_test_owner();
            let admission = gateway_test_admission(&format!("gateway-{name}"));
            assert!(
                run_process_start(&ports, &owner, admission.clone(), ())
                    .await
                    .is_err()
            );
            assert_eq!(ports.counts(), (1, 0, 0, 0, 0));
            assert_eq!(ports.retained(), (0, 0));
            assert!(ports.state.lock().expect("test state").replay.is_empty());
            let digest = process_admission_digest(&admission).expect("digest");
            assert!(matches!(
                ports.begin(admission.intent().operation_id(), &digest, &owner),
                Ok(ProcessExecutionReplayBegin::Acquired)
            ));
            assert!(matches!(
                ports.abort(admission.intent().operation_id(), &digest, &owner),
                Ok(ProcessExecutionReplayAbort::Released)
            ));
        }
    }

    #[tokio::test]
    async fn actual_process_start_context_failure_explicitly_aborts_and_maps_abort_failure() {
        let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        ports.fail_context();
        ports.fail_abort();
        let owner = gateway_test_owner();
        let admission = gateway_test_admission("gateway-context-failure");
        assert!(matches!(
            run_process_start(&ports, &owner, admission.clone(), ()).await,
            Err(ProcessExecutionError::UnknownOutcome)
        ));
        assert_eq!(ports.counts(), (1, 0, 0, 0, 0));
        assert_eq!(ports.abort_calls(), 1);
        assert_eq!(ports.retained(), (0, 0));
        assert_eq!(
            ports
                .state
                .lock()
                .expect("test state")
                .replay
                .get(admission.intent().operation_id())
                .expect("reserved replay")
                .state,
            ProcessExecutionReplayState::Reserved
        );

        ports.allow_abort();
        let digest = process_admission_digest(&admission).expect("digest");
        assert!(matches!(
            ports.abort(admission.intent().operation_id(), &digest, &owner),
            Ok(ProcessExecutionReplayAbort::Released)
        ));
        ports.allow_context();
        assert!(
            run_process_start(&ports, &owner, admission, ())
                .await
                .is_ok(),
            "exact retry after explicit release"
        );
        assert_eq!(ports.abort_calls(), 2);
        assert_eq!(ports.retained(), (0, 0));
    }

    #[tokio::test]
    async fn actual_process_start_orchestration_isolated_for_concurrent_and_duplicate_ops() {
        let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        let owner = gateway_test_owner();
        let first_ports = ports.clone();
        let first_owner = owner.clone();
        let first = tokio::spawn(async move {
            run_process_start(
                &first_ports,
                &first_owner,
                gateway_test_admission("gateway-concurrent-a"),
                (),
            )
            .await
        });
        let second_ports = ports.clone();
        let second_owner = owner.clone();
        let second = tokio::spawn(async move {
            run_process_start(
                &second_ports,
                &second_owner,
                gateway_test_admission("gateway-concurrent-b"),
                (),
            )
            .await
        });
        assert!(first.await.expect("first task").is_ok());
        assert!(second.await.expect("second task").is_ok());
        assert_eq!(ports.counts(), (2, 2, 2, 2, 2));
        assert_eq!(ports.retained(), (0, 0));

        let paused = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        let pause = Arc::new(tokio::sync::Notify::new());
        paused.pause_executor(Arc::clone(&pause));
        let duplicate_admission = gateway_test_admission("gateway-duplicate");
        let first_admission = duplicate_admission.clone();
        let duplicate_ports = paused.clone();
        let duplicate_owner = owner.clone();
        let first = tokio::spawn(async move {
            run_process_start(&duplicate_ports, &duplicate_owner, first_admission, ()).await
        });
        paused.wait_contexts(1).await;
        let duplicate = run_process_start(&paused, &owner, duplicate_admission, ()).await;
        assert!(matches!(
            duplicate,
            Err(ProcessExecutionError::UnknownOutcome)
        ));
        assert_eq!(paused.retained(), (1, 1));
        pause.notify_waiters();
        assert!(first.await.expect("duplicate task").is_ok());
        assert_eq!(paused.retained(), (0, 0));
    }

    #[tokio::test]
    async fn actual_process_start_orchestration_abort_cleans_exact_context_path_and_replay() {
        let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        let pause = Arc::new(tokio::sync::Notify::new());
        ports.pause_executor(Arc::clone(&pause));
        let task_ports = ports.clone();
        let owner = gateway_test_owner();
        let task_owner = owner.clone();
        let task = tokio::spawn(async move {
            run_process_start(
                &task_ports,
                &task_owner,
                gateway_test_admission("gateway-cancelled"),
                (),
            )
            .await
        });
        ports.wait_contexts(1).await;
        assert_eq!(ports.retained(), (1, 1));
        task.abort();
        assert!(task.await.expect_err("cancelled task").is_cancelled());
        assert_eq!(ports.retained(), (0, 0));
        assert!(ports.state.lock().expect("test state").replay.is_empty());

        let retry = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        assert!(
            run_process_start(
                &retry,
                &owner,
                gateway_test_admission("gateway-cancelled"),
                (),
            )
            .await
            .is_ok()
        );
        assert_eq!(retry.counts(), (1, 1, 1, 1, 1));
    }

    #[test]
    fn store_projection_is_deterministic_and_binds_empty_and_full_fence_state() {
        let fence = StoreStateFence::new(
            eliot_contracts::AuthorityEpoch::new(3).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(4).expect("generation"),
        );
        let first = CanonicalValidationSnapshot {
            state_fence: fence.clone(),
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new("scope:b").expect("key"),
                revision: 2,
                state_fence: fence.clone(),
            }],
            validation_revision: 9,
            observed_at_unix_ms: 1_000,
        };
        let mut reordered = first.clone();
        reordered.observed_at_unix_ms = 2_000;
        let (first_fence, first_heads) = project_store_snapshot(&first).expect("projection");
        let (reordered_fence, reordered_heads) =
            project_store_snapshot(&reordered).expect("projection");
        assert_eq!(first_fence, reordered_fence);
        assert_eq!(first_heads, reordered_heads);
        assert!(first_heads.contains_key(RESERVED_STORE_SNAPSHOT_HEAD));
        assert_eq!(first_heads.len(), 2);

        let empty = CanonicalValidationSnapshot {
            state_fence: fence.clone(),
            revision_heads: Vec::new(),
            validation_revision: 1,
            observed_at_unix_ms: 1_000,
        };
        let (_, empty_heads) = project_store_snapshot(&empty).expect("empty projection");
        assert_eq!(empty_heads.len(), 1);
        assert!(empty_heads.contains_key(RESERVED_STORE_SNAPSHOT_HEAD));

        let mut changed = first.clone();
        changed.state_fence.task_revision =
            Some(eliot_contracts::TaskRevision::new(1).expect("task revision"));
        for head in &mut changed.revision_heads {
            head.state_fence = changed.state_fence.clone();
        }
        let (changed_fence, changed_heads) = project_store_snapshot(&changed).expect("changed");
        assert_ne!(first_fence, changed_fence);
        assert_ne!(first_heads, changed_heads);

        let mut changed_head = first.clone();
        changed_head.revision_heads[0].revision += 1;
        let (_, changed_head_projection) =
            project_store_snapshot(&changed_head).expect("changed head");
        assert_ne!(first_heads, changed_head_projection);
        let mut changed_validation_revision = first;
        changed_validation_revision.validation_revision += 1;
        let (_, changed_revision_projection) =
            project_store_snapshot(&changed_validation_revision).expect("changed revision");
        assert_ne!(first_heads, changed_revision_projection);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn process_authority_constructor_reuses_one_real_ors_store() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-process-authority-constructor-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let ors_path = root.join(".eliot").join("kernel-ors.redb");
        let authority_id = DispatchAuthorityId::new("kernel-test-authority").expect("authority");
        let binding = authority_binding(&authority_id);
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(JsonSnapshotCodec);
        let store = Arc::new(RedbRecoveryStore::open(&ors_path).expect("real ORS store"));
        let seed_store: Arc<dyn OperationalRecoveryStore> = store.clone();
        let seed_key = KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("seed key");
        let mut seeder = ProcessDispatchAuthorityController::activate(
            authority_id.clone(),
            seed_key,
            seed_store,
            Arc::clone(&codec),
        );
        let seed_fence =
            FencingToken::new(1, Generation::new(1).expect("generation"), "seed-fence")
                .expect("seed fence");
        seeder
            .issue(
                &seed_intent(),
                PermitIssuance::new(
                    ActionLeaseRef::new("seed-lease").expect("lease"),
                    seed_fence,
                    BTreeMap::from([("authority".to_owned(), "a".repeat(64))]),
                    1,
                    2,
                    "seed-nonce",
                )
                .expect("issuance"),
                &binding,
            )
            .expect("production authority snapshot seed");
        drop(seeder);

        let subject = OperationIdentity::new(authority_id.as_str()).expect("authority subject");
        let original_input = store
            .load_authority_snapshot(&subject)
            .expect("load seeded authority snapshot")
            .expect("seeded authority snapshot")
            .snapshot()
            .record()
            .clone();
        for substitution in 0..3 {
            let mut tampered = original_input.clone();
            match substitution {
                0 => {
                    tampered.record_id =
                        OperationIdentity::new("substituted-record").expect("record");
                }
                1 => tampered.created_at_ms += 1,
                2 => tampered.cleanup_after_ms = Some(3_000),
                _ => unreachable!(),
            }
            eliot_ors::test_support::substitute_authority_snapshot_metadata(
                &store,
                eliot_ors::test_support::AuthoritySnapshotMetadataSubstitution {
                    record_id: tampered.record_id,
                    created_at_ms: tampered.created_at_ms,
                    cleanup_after_ms: tampered.cleanup_after_ms,
                },
            )
            .expect("persist metadata substitution");
            assert!(
                ProcessDispatchAuthorityController::restore(
                    authority_id.clone(),
                    KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("restore key"),
                    store.clone(),
                    Arc::clone(&codec),
                    &binding,
                )
                .is_err()
            );
            eliot_ors::test_support::substitute_authority_snapshot_metadata(
                &store,
                eliot_ors::test_support::AuthoritySnapshotMetadataSubstitution {
                    record_id: original_input.record_id.clone(),
                    created_at_ms: original_input.created_at_ms,
                    cleanup_after_ms: original_input.cleanup_after_ms,
                },
            )
            .expect("restore original metadata");
        }
        drop(store);

        let kernel = KernelComposition::new_with_process_authority(
            KernelConfig::new(&root),
            ProcessExecutionAuthorityConfig {
                authority_id,
                key: KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("restore key"),
                snapshot_binding: binding,
                snapshot_codec: codec,
            },
        )
        .expect("process authority constructor");
        assert!(kernel.process_execution_configured());
        assert_eq!(Arc::strong_count(&kernel.generation_gateway.ors), 4);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn process_owner_survives_reconnect_but_rejects_cross_owner() {
        let generation = Generation::new(7).expect("generation");
        let owner =
            ProcessOwnerBinding::new("testd", "a".repeat(64), 3, generation).expect("owner");
        let reconnected =
            ProcessOwnerBinding::new("testd", "a".repeat(64), 3, generation).expect("owner");
        assert!(authorize_process_owner(&owner, &reconnected).is_ok());

        let wrong_module =
            ProcessOwnerBinding::new("native", "a".repeat(64), 3, generation).expect("owner");
        let wrong_principal =
            ProcessOwnerBinding::new("testd", "b".repeat(64), 3, generation).expect("owner");
        let wrong_generation = ProcessOwnerBinding::new(
            "testd",
            "a".repeat(64),
            3,
            Generation::new(8).expect("generation"),
        )
        .expect("owner");
        for candidate in [wrong_module, wrong_principal, wrong_generation] {
            assert!(authorize_process_owner(&owner, &candidate).is_err());
        }
    }

    #[test]
    fn protected_authority_preparation_rejects_untrusted_input_before_consumption() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-authority-preparation-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
        let descriptor_path = root.join("authority.json");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &descriptor_path,
                "not-a-digest",
                AuthorityDescriptorContour::ProgramData,
            ),
            Err(AuthorityPreparationError::DigestMismatch)
        ));
        let empty_digest = sha256_hex(&[]);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &descriptor_path,
                &empty_digest,
                AuthorityDescriptorContour::ProgramData,
            ),
            Err(AuthorityPreparationError::ProtectedInput)
        ));
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn protected_authority_preparation_acceptance_matrix() {
        let suffix = authority_test_suffix();
        let root = std::env::temp_dir().join(format!("eliot-kernel-authority-{suffix}"));
        let outside = std::env::temp_dir().join(format!("eliot-kernel-authority-outside-{suffix}"));
        let _cleanup = AuthorityTestCleanup {
            paths: vec![root.clone(), outside.clone()],
        };
        std::fs::create_dir_all(&root).expect("test work root");
        std::fs::create_dir_all(&outside).expect("outside root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
        let platform = Arc::new(WindowsPlatform::new(&root).expect("platform"));

        let positive =
            authority_descriptor(&format!("{suffix}-positive"), "windows-credential-manager");
        let (positive_path, positive_digest) =
            write_authority_descriptor(&root, "positive", &positive);
        let positive_key = positive.dispatch_key.key.as_str().to_owned();
        let positive_cleanup = credential_cleanup(&platform, &positive_key);
        platform
            .write_credential(&positive_key, &[0x5a; 32])
            .expect("positive credential");
        let prepared = kernel
            .prepare_authority_descriptor(
                &positive_path,
                &positive_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            )
            .expect("positive authority preparation");
        assert_eq!(prepared.descriptor, positive);
        let handoff_id = OperationIdentity::new(positive.handoff_id.as_str()).expect("handoff id");
        let consumed = kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&handoff_id)
            .expect("load consumed handoff")
            .expect("consumed handoff");
        assert_eq!(consumed.state, AuthorityHandoffState::Consumed);
        assert_eq!(consumed.descriptor_digest, positive.descriptor_sha256);
        assert_eq!(
            consumed.authority_id.as_str(),
            positive.authority_id.as_str()
        );
        assert_eq!(
            consumed.snapshot_record_id,
            positive.snapshot_binding.record_id
        );
        assert_eq!(
            consumed.snapshot_binding_digest,
            sha256_json(&positive.snapshot_binding).expect("binding digest")
        );
        assert_eq!(
            consumed.authority_epoch,
            positive.state_fence.authority_epoch.value()
        );
        assert_eq!(consumed.generation, positive.generation.value());
        assert_eq!(
            consumed.state_fence_digest,
            sha256_json(&positive.state_fence).expect("state fence digest")
        );
        assert_eq!(
            consumed.secret_reference_identity_digest,
            sha256_json(&positive.dispatch_key).expect("secret reference digest")
        );
        drop(positive_cleanup);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &positive_path,
                &positive_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::CredentialUnavailable)
        ));

        let replay_key = positive.dispatch_key.key.as_str().to_owned();
        let replay_cleanup = credential_cleanup(&platform, &replay_key);
        platform
            .write_credential(&replay_key, &[0x5a; 32])
            .expect("replay credential");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &positive_path,
                &positive_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::Replay)
        ));
        drop(replay_cleanup);

        let missing =
            authority_descriptor(&format!("{suffix}-missing"), "windows-credential-manager");
        let (missing_path, missing_digest) = write_authority_descriptor(&root, "missing", &missing);
        let mismatch_digest = "0".repeat(64);
        let mismatch_handoff_id =
            OperationIdentity::new(missing.handoff_id.as_str()).expect("handoff id");
        assert_ne!(missing_digest, mismatch_digest);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &missing_path,
                &mismatch_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DigestMismatch)
        ));
        assert!(
            kernel
                .generation_gateway
                .ors
                .load_authority_handoff(&mismatch_handoff_id)
                .expect("digest mismatch lookup")
                .is_none()
        );
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &missing_path,
                &missing_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::CredentialUnavailable)
        ));

        for (name, secret) in [("short", vec![1_u8]), ("long", vec![1_u8; 33])] {
            let descriptor =
                authority_descriptor(&format!("{suffix}-{name}"), "windows-credential-manager");
            let (path, digest) = write_authority_descriptor(&root, name, &descriptor);
            let key = descriptor.dispatch_key.key.as_str().to_owned();
            let cleanup = credential_cleanup(&platform, &key);
            platform
                .write_credential(&key, &secret)
                .expect("invalid credential");
            assert!(matches!(
                kernel.prepare_authority_descriptor(
                    &path,
                    &digest,
                    AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
                ),
                Err(AuthorityPreparationError::CredentialInvalid)
            ));
            drop(cleanup);
        }

        let zero = authority_descriptor(&format!("{suffix}-zero"), "windows-credential-manager");
        let (zero_path, zero_digest) = write_authority_descriptor(&root, "zero", &zero);
        let zero_key = zero.dispatch_key.key.as_str().to_owned();
        let zero_cleanup = credential_cleanup(&platform, &zero_key);
        platform
            .write_credential(&zero_key, &[0_u8; 32])
            .expect("zero credential");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &zero_path,
                &zero_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::CredentialInvalid)
        ));
        drop(zero_cleanup);

        let wrong_provider = authority_descriptor(&format!("{suffix}-provider"), "not-a-provider");
        let (wrong_provider_path, wrong_provider_digest) =
            write_authority_descriptor(&root, "wrong-provider", &wrong_provider);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &wrong_provider_path,
                &wrong_provider_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorInvalid)
        ));

        let malformed = b"not-json".to_vec();
        let (malformed_path, malformed_digest) =
            write_authority_bytes(&root, "malformed", &malformed);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &malformed_path,
                &malformed_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorInvalid)
        ));

        let unknown =
            authority_descriptor(&format!("{suffix}-unknown"), "windows-credential-manager");
        let mut unknown_wire = serde_json::to_value(&unknown).expect("unknown descriptor value");
        unknown_wire["unknown"] = serde_json::json!(true);
        let unknown_bytes = serde_json::to_vec(&unknown_wire).expect("unknown descriptor bytes");
        let (unknown_path, unknown_digest) =
            write_authority_bytes(&root, "unknown", &unknown_bytes);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &unknown_path,
                &unknown_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorInvalid)
        ));

        let mut expired =
            authority_descriptor(&format!("{suffix}-expired"), "windows-credential-manager");
        expired.issued_at_ms = 1;
        expired.expires_at_ms = 2;
        expired = expired.with_computed_digest().expect("expired digest");
        let (expired_path, expired_digest) = write_authority_descriptor(&root, "expired", &expired);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &expired_path,
                &expired_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorInvalid)
        ));

        let valid_substitution = authority_descriptor(
            &format!("{suffix}-substitution"),
            "windows-credential-manager",
        );
        let mut descriptor_substitution = valid_substitution.clone();
        descriptor_substitution.authority_id =
            DispatchAuthorityId::new(format!("substituted-{suffix}"))
                .expect("substituted authority");
        descriptor_substitution = descriptor_substitution
            .with_computed_digest()
            .expect("substituted descriptor digest");
        let (descriptor_substitution_path, descriptor_substitution_digest) =
            write_authority_descriptor(&root, "descriptor-substitution", &descriptor_substitution);
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &descriptor_substitution_path,
                &descriptor_substitution_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorInvalid)
        ));
        let descriptor_substitution_id =
            OperationIdentity::new(descriptor_substitution.handoff_id.as_str())
                .expect("handoff id");
        assert!(
            kernel
                .generation_gateway
                .ors
                .load_authority_handoff(&descriptor_substitution_id)
                .expect("substitution lookup")
                .is_none()
        );

        let mut state_fence_substitution = valid_substitution;
        state_fence_substitution.state_fence = StateFence::new(
            AuthorityEpoch::new(2).expect("epoch"),
            ResourceGeneration::genesis(),
        );
        state_fence_substitution = state_fence_substitution
            .with_computed_digest()
            .expect("state fence substitution digest");
        let (state_fence_path, state_fence_digest) = write_authority_descriptor(
            &root,
            "state-fence-substitution",
            &state_fence_substitution,
        );
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &state_fence_path,
                &state_fence_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorInvalid)
        ));
        let state_fence_id = OperationIdentity::new(state_fence_substitution.handoff_id.as_str())
            .expect("handoff id");
        assert!(
            kernel
                .generation_gateway
                .ors
                .load_authority_handoff(&state_fence_id)
                .expect("state fence lookup")
                .is_none()
        );

        let out_of_contour_descriptor = authority_descriptor(
            &format!("{suffix}-out-of-contour"),
            "windows-credential-manager",
        );
        let outside_path = outside.join("authority.json");
        let outside_bytes = serde_json::to_vec(&out_of_contour_descriptor).expect("outside bytes");
        std::fs::write(&outside_path, &outside_bytes).expect("outside descriptor");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &outside_path,
                &sha256_hex(&outside_bytes),
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::ProtectedInput)
        ));
        // Reparse/junction substitution coverage is lower-layer-owned by
        // user_owned_portable_dev_rejects_reparse_path_when_available and
        // protected_path_lease_rejects_directory_and_file_reparse_substitution.
    }

    #[cfg(windows)]
    #[test]
    fn protected_authority_preparation_persists_unknown_after_uncertain_consume() {
        let suffix = authority_test_suffix();
        let root = std::env::temp_dir().join(format!("eliot-kernel-authority-unknown-{suffix}"));
        let _cleanup = AuthorityTestCleanup {
            paths: vec![root.clone()],
        };
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
        let platform = Arc::new(WindowsPlatform::new(&root).expect("platform"));
        let descriptor = authority_descriptor(
            &format!("{suffix}-unknown-outcome"),
            "windows-credential-manager",
        );
        let (path, digest) = write_authority_descriptor(&root, "unknown-outcome", &descriptor);
        let key = descriptor.dispatch_key.key.as_str().to_owned();
        let credential = credential_cleanup(&platform, &key);
        platform
            .write_credential(&key, &[0x6b; 32])
            .expect("credential");
        let failpoint =
            Arc::new(eliot_ors::test_support::AuthorityHandoffPersistenceFailpoint::default());
        eliot_ors::test_support::install_authority_handoff_failpoint(
            &kernel.generation_gateway.ors,
            Arc::clone(&failpoint),
        );
        failpoint.fail_next_consume_commit_after_durable_effect();
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &path,
                &digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::PersistenceUnknown)
        ));
        let handoff_id =
            OperationIdentity::new(descriptor.handoff_id.as_str()).expect("handoff id");
        let unknown = kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&handoff_id)
            .expect("load unknown handoff")
            .expect("unknown handoff");
        assert_eq!(unknown.state, AuthorityHandoffState::Unknown);
        assert!(
            unknown
                .reconciliation_evidence
                .as_ref()
                .is_some_and(|evidence| !evidence.as_str().trim().is_empty())
        );
        drop(credential);
    }

    #[test]
    fn stable_sid_owner_digest_ignores_process_and_session_replacement() {
        let generation = Generation::new(7).expect("generation");
        let first_digest = stable_owner_principal_digest("S-1-5-18", "testd", 3, generation);
        let restarted_digest = stable_owner_principal_digest("S-1-5-18", "testd", 3, generation);
        assert_eq!(first_digest, restarted_digest);
        let first = ProcessOwnerBinding::new("testd", first_digest, 3, generation).expect("owner");
        let restarted =
            ProcessOwnerBinding::new("testd", restarted_digest, 3, generation).expect("owner");
        let first_session = ProcessSessionBinding::new("connection-a", 1).expect("session");
        let restarted_session = ProcessSessionBinding::new("connection-b", 2).expect("session");
        assert_ne!(first_session, restarted_session);
        assert!(authorize_process_owner(&first, &restarted).is_ok());

        for (sid, module, authority, candidate_generation) in [
            ("S-1-5-19", "testd", 3, generation),
            ("S-1-5-18", "native", 3, generation),
            ("S-1-5-18", "testd", 4, generation),
            (
                "S-1-5-18",
                "testd",
                3,
                Generation::new(8).expect("generation"),
            ),
        ] {
            let digest =
                stable_owner_principal_digest(sid, module, authority, candidate_generation);
            let candidate =
                ProcessOwnerBinding::new(module, digest, authority, candidate_generation)
                    .expect("owner");
            assert!(authorize_process_owner(&first, &candidate).is_err());
        }
    }
}

// Store implementation E2E belongs to the Store/Host boundary. Kernel tests
// exercise only the neutral descriptor and route/fence behavior.
