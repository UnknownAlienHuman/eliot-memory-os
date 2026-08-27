//! The Kernel composition root.
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.

#![forbid(unsafe_code)]

mod canonical_store_runtime;
mod composition_bootstrap;
mod control_plane;
mod kernel_config;

pub use kernel_config::KernelConfig;

#[cfg(all(test, windows))]
use canonical_store_runtime::attach_then_retain_canonical_store;

#[cfg(feature = "r13-os-harness")]
pub mod r13_os_harness;

mod daemon_request_dispatch;
mod frame_dispatch;
mod front_door_listener;
mod front_door_session;
mod generation_recovery;
mod health_view;
use generation_recovery::OrsGenerationCoordinator;
#[cfg(test)]
use generation_recovery::update_handshake_policy;

use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, RequestId, ResourceGeneration, StateFence,
};
use eliot_ipc::{
    AcceptedAgentBridgeTransport, HandshakeResult, PeerIdentity, ServerFirstConnection,
    ServerHandshakePolicy, Session, TransportError, TransportLimits,
    agent_bridge_admission_receipt_frame,
};
use eliot_kernel_core::{
    AuthoritySnapshotBinding, AuthoritySnapshotBindingWire, DispatchSnapshotCodec, GenerationRoute,
    GenerationRouter, KernelError, ProcessDispatchAuthorityController, ProcessExecutionReplayAbort,
    ProcessExecutionReplayBegin, ProcessExecutionReplayRecord, ProcessExecutionReplayState,
    ProcessExecutionReplayStore, ProcessExecutionReplayStoreWithAbort, RouteScope,
    process_admission_digest,
};
#[cfg(windows)]
pub use eliot_kernel_service::KernelStoreGateway;
#[cfg(windows)]
use eliot_kernel_service::StoreRebindQuery;
use eliot_kernel_service::{
    AgentBridgeAdmissionDescriptor, EliotdLaunchDescriptor, HostKernelCandidateBinding,
    HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE, KernelActivationReceipt,
    KernelControlCommand, KernelControlRequest, KernelControlResponse, KernelReadyReceipt,
    KernelService, KernelServiceError, KernelServiceState, ProcessAuthorityHandoffDescriptor,
    ProcessExecutionRequest, ProcessExecutionResponse, ProcessObservation, StoreBootstrapHandoff,
};
#[cfg(test)]
use eliot_ors::CanonicalEvidenceProvider;
use eliot_ors::{
    AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, OrsError,
    ProcessEvidenceRecord, ProcessStartReplayRecord as OrsReplayRecord,
    ProcessStartReplayState as OrsReplayState,
};
use eliot_ors::{
    OperationIdentity, OperationalRecoveryStore, RedbRecoveryStore, SupervisionLeaseCommitTicket,
    SupervisionLeaseOperation, SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
    SupervisionLeaseStageReceipt,
};
use eliot_platform::{ClockObservation, PlatformHandle, PortError};
#[cfg(windows)]
use eliot_platform_windows::{
    FileIdentity as WindowsFileIdentity, NamedPipePeerKind, NamedPipePeerProfile,
    NamedPipePeerSelection, NamedPipePeerSet, ProtectedRootLease, ProtectedRuntimePathLease,
    PublicationOutcome, PublicationPrecondition, fresh_activation_nonce_material,
    publish_atomic_owned_runtime_receipt, read_protected_file, windows_paths_equal,
};
use eliot_platform_windows::{
    InstallerRootPrimitiveSpec, InstallerRootProfile, ProtectedSecret, RecoverableJobBinding,
    RecoverableJobObject, RetainedProcessPathLease, UserOwnedPathLease, UserOwnedRootLease,
    WindowsPlatform, WindowsSupervisionAuthorityKeyStore, protected_program_data_root,
};
use eliot_process::{
    ActionLeaseRef, CancellationStatus, DispatchAuthorityId, DispatchValidationContext,
    EliotdLiveReadyEvidence, EliotdLiveReceipt, EliotdLiveSupervisionEvidence,
    EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionAdmissionRequest, ProcessExecutionError, ProcessExecutor, ProcessIntent,
    ProcessLaunchAdmission, ProcessLifecycle, ProcessOwnerBinding, ProcessRequest,
    ProcessSessionBinding, ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
    SuspendedLaunchEvidence, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_protocol::{
    AGENT_BRIDGE_ACTIVATION_OPERATION, AGENT_BRIDGE_MODULE_ID, AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID,
    AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentActivationResolutionDecision,
    AgentActivationResolutionTicket, AgentBridgeActivationDenialCode,
    AgentBridgeActivationDisposition, AgentBridgeActivationFence, AgentBridgeActivationRequest,
    AgentBridgeActivationResponse, AgentBridgeAuthenticatedBinding, AgentBridgeClientDeclaration,
    AgentBridgePeerAdmissionReceipt, AgentBridgePeerChallenge, EncodingProfile, Frame, FrameKind,
    MessageType, ProtocolPayload,
};
use eliot_runtime::{Runtime, RuntimeConfig, ShutdownOutcome};
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, HealthVector, LeaseState, ModuleGeneration,
    ModuleGenerationState, ProvisionedSupervisionAuthority, SupervisionGenerationBinding,
    SupervisionLease, SupervisionLeaseActiveStateBinding, SupervisionLeaseError,
    SupervisionLeaseIncarnationBinding, SupervisionLeasePredecessorIdentity,
    SupervisionLeasePredecessorProof, SupervisionLeaseSigner, SupervisionLeaseTerminalDisposition,
    SupervisionLeaseVerificationContext, SupervisionLeaseVerifier, SupervisionSealedKeyReference,
    SupervisionTrustAnchor,
};
use eliot_store_api::{
    CanonicalValidationSnapshot, RevisionHead, StateFence as StoreStateFence, StoreHealth,
    StoreHealthStatus, canonical_json_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(all(test, windows))]
use eliot_ipc::NamedPipeServer;
#[cfg(all(test, windows))]
use eliot_ipc::NamedPipeTransport;
#[cfg(windows)]
use eliot_platform_windows::{
    NamedPipePeerExpectation, current_process_named_pipe_expectation,
    observe_named_pipe_peer_process, observe_named_pipe_peer_process_in_job,
};

use front_door_session::IpcImplementation;

/// Stable Kernel process identity and wire revision.
pub const SERVICE_NAME: &str = "eliot-kernel";
pub const PROTOCOL_VERSION: &str = "eliot.kernel.v1";
pub const DEFAULT_PIPE_NAME: &str = KERNEL_CONTROL_PIPE;
/// Stable production-boundary identity for the Kernel Store-rebind seam.
pub const KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-kernel::production-store-rebind:v1";
const STORE_BRIDGE_ROUTE: &str = "store_bridge";
const ACTIVE_DAEMON_CALLER: &str = "eliotd";
#[cfg(windows)]
const SUPERVISION_LEASE_VALIDITY_MS: u64 = 60_000;
#[cfg(windows)]
const SUPERVISION_LEASE_RENEW_AFTER_MS: u64 = 30_000;
const ELIOTD_RECEIPT_PENDING_DEPENDENCY: &str = "eliotd-process-receipt";
const ELIOTD_RECEIPT_PENDING_REASON: &str = "exact launched process receipt publication is pending";
#[cfg(windows)]
const AGENT_BRIDGE_ACTIVATION_WINDOW_MS: u64 = 30_000;
#[cfg(windows)]
/// A daemon claim is retained for a short, bounded interval.  If semantic
/// resolution fails transiently, the same Kernel-owned ticket becomes
/// claimable again without allocating a new request or ticket identity.
const AGENT_ACTIVATION_CLAIM_LEASE_MS: u64 = 1_000;
#[cfg(windows)]
const ELIOTD_MAX_RECOVERY_ATTEMPTS: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KernelStoreRebindProductionBoundary;

#[cfg(windows)]
fn observed_session_principal_binding() -> Result<String, KernelBuildError> {
    let expectation = current_process_named_pipe_expectation()
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
    Ok(format!(
        "sid={};session={}",
        expectation.expected_sid(),
        expectation.expected_session_id()
    ))
}

#[cfg(windows)]
fn eliotd_launch_attempt_identity(
    launch: &EliotdLaunchDescriptor,
    kernel_process_id: u32,
    kernel_start_time_100ns: u64,
    kernel_image_path: &str,
) -> Result<String, KernelBuildError> {
    #[derive(Serialize)]
    struct AttemptBinding<'a> {
        authority_epoch: u64,
        generation: u64,
        launch_nonce: &'a str,
        kernel_process_id: u32,
        kernel_start_time_100ns: u64,
        kernel_image_path: &'a str,
    }

    let bytes = serde_json::to_vec(&AttemptBinding {
        authority_epoch: launch.authority_epoch.value(),
        generation: launch.generation.value(),
        launch_nonce: launch.launch_nonce.as_str(),
        kernel_process_id,
        kernel_start_time_100ns,
        kernel_image_path,
    })
    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

#[cfg(windows)]
fn eliotd_operation_id(
    generation: Generation,
    launch_attempt_identity: &str,
) -> Result<eliot_process::OperationId, KernelBuildError> {
    let short = launch_attempt_identity.get(..16).ok_or_else(|| {
        KernelBuildError::Service("eliotd launch attempt identity is malformed".to_owned())
    })?;
    eliot_process::OperationId::new(format!("eliotd-launch-{}-{short}", generation.get()))
        .map_err(|error| KernelBuildError::Service(error.to_string()))
}

#[cfg(windows)]
fn fresh_eliotd_launch_descriptor(
    previous: &EliotdLaunchDescriptor,
    recovery_attempt: u64,
) -> Result<EliotdLaunchDescriptor, KernelBuildError> {
    previous
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let nonce_material = format!(
        "{}:{}:{}:{}",
        previous.descriptor_sha256,
        previous.launch_nonce.as_str(),
        recovery_attempt,
        unix_ms(),
    );
    let launch_nonce =
        PlatformHandle::new(format!("eliotd:{}", sha256_hex(nonce_material.as_bytes())))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let mut next = previous.clone();
    next.launch_nonce = launch_nonce.clone();
    if next.arguments.len() != 8 {
        return Err(KernelBuildError::Service(
            "eliotd launch descriptor has a non-canonical argv contour".to_owned(),
        ));
    }
    next.arguments[5] = launch_nonce;
    next.with_computed_digest()
        .map_err(|error| KernelBuildError::Service(error.to_string()))
}

const fn probe_ready_state_admitted(state: KernelServiceState) -> bool {
    matches!(
        state,
        KernelServiceState::Activating | KernelServiceState::Ready | KernelServiceState::Degraded
    )
}

/// Host-approved protected key reference and installation-pinned public trust
/// anchor for Kernel-owned supervision leases.
///
/// The reference identifies a service-SID-bound DPAPI-NG ciphertext below the
/// approved Kernel work root; it never carries the signing seed.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionLeaseAuthorityConfig {
    pub authority: ProvisionedSupervisionAuthority,
}

/// Host-injected, manifest-bound roots and generation identity for the
/// Kernel-owned eliotd live receipt.  The absolute paths are not authority on
/// their own: the full `RuntimeStateRoots` digest and active manifest identities
/// are mandatory members of the same launch binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EliotdReceiptRootBinding {
    receipt_root: PathBuf,
    kernel_ors_root: PathBuf,
    runtime_state_roots_digest: String,
    installation_id: String,
    approved_generation: String,
}

impl EliotdReceiptRootBinding {
    /// Constructs the complete manifest-derived publication binding.
    pub fn new(
        receipt_root: impl Into<PathBuf>,
        kernel_ors_root: impl Into<PathBuf>,
        runtime_state_roots_digest: impl Into<String>,
        installation_id: impl Into<String>,
        approved_generation: impl Into<String>,
    ) -> Result<Self, String> {
        let binding = Self {
            receipt_root: receipt_root.into(),
            kernel_ors_root: kernel_ors_root.into(),
            runtime_state_roots_digest: runtime_state_roots_digest.into(),
            installation_id: installation_id.into(),
            approved_generation: approved_generation.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), String> {
        for (name, path) in [
            ("receipt_root", &self.receipt_root),
            ("kernel_ors_root", &self.kernel_ors_root),
        ] {
            if !path.is_absolute()
                || path.as_os_str().is_empty()
                || path.to_string_lossy().chars().any(char::is_control)
            {
                return Err(format!(
                    "eliotd {name} must be an absolute control-free path"
                ));
            }
        }
        if !is_lower_sha256(&self.runtime_state_roots_digest) {
            return Err("RuntimeStateRoots digest must be lowercase SHA-256".to_owned());
        }
        for (name, value) in [
            ("installation identity", &self.installation_id),
            ("approved generation", &self.approved_generation),
        ] {
            if value.trim().is_empty()
                || value != value.trim()
                || value.chars().any(char::is_control)
            {
                return Err(format!("eliotd {name} is empty or contains control"));
            }
        }
        Ok(())
    }

    /// Returns the manifest-selected Host state root.
    pub fn receipt_root(&self) -> &Path {
        &self.receipt_root
    }

    /// Returns the manifest-selected Kernel ORS root.
    pub fn kernel_ors_root(&self) -> &Path {
        &self.kernel_ors_root
    }

    /// Returns the installer-owned `RuntimeStateRoots` digest.
    pub fn runtime_state_roots_digest(&self) -> &str {
        &self.runtime_state_roots_digest
    }

    /// Returns the active installation identity.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the active manifest generation identity.
    pub fn approved_generation(&self) -> &str {
        &self.approved_generation
    }
}

#[cfg(windows)]
impl SupervisionLeaseAuthorityConfig {
    /// Validates the installer receipt before any ciphertext file is opened.
    pub fn validate(&self) -> Result<(), String> {
        self.authority.validate().map_err(|error| error.to_string())
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
    /// The descriptor is absent from ORS and outside its fresh admission
    /// interval at the reservation linearization point.
    DescriptorNotFresh,
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
            Self::DescriptorNotFresh => "authority descriptor is not fresh for admission",
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
    /// The durable Reserved/Consumed handoff identity that gates this
    /// controller.  Reserved is the activation intent committed by ORS;
    /// it must never be replaced by an in-memory marker.
    handoff: AuthorityHandoffRecord,
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
    #[allow(
        dead_code,
        reason = "zero-sized marker binds the production Store-rebind seam"
    )]
    store_rebind_boundary: KernelStoreRebindProductionBoundary,
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
    daemon_launch: Option<EliotdLaunchDescriptor>,
    eliotd_receipt_binding: Option<EliotdReceiptRootBinding>,
    /// The current immutable launch binding. Recovery replaces this only
    /// after the previous process effect is known terminal; the original
    /// Host-approved descriptor remains retained in `daemon_launch`.
    daemon_active_launch: Mutex<Option<EliotdLaunchDescriptor>>,
    kernel_artifact_sha256: Option<String>,
    eliotd_descriptor_artifact_sha256: Option<String>,
    daemon_runtime: Mutex<DaemonRuntimeState>,
    daemon_status_changed: tokio::sync::Notify,
    #[cfg(windows)]
    daemon_recovery_gate: tokio::sync::Mutex<()>,
    #[cfg(windows)]
    daemon_recovery_attempts: AtomicU64,
    #[cfg(windows)]
    store_handoff: Mutex<Option<StoreBootstrapHandoff>>,
    #[cfg(windows)]
    /// Serializes Store rebind mutation with exact replay queries.  A service
    /// receipt is created before the ORS commit boundary, so a query must not
    /// observe that in-memory receipt while the rebind transaction is still
    /// able to roll back.
    store_rebind_gate: tokio::sync::Mutex<()>,
    approved_config_hash: Option<String>,
    canonical_store_claimed: AtomicBool,
    #[cfg(windows)]
    canonical_store_gateway: Mutex<Option<Arc<KernelStoreGateway>>>,
    #[cfg(windows)]
    supervision_lease_authority: Option<Arc<KernelSupervisionLeaseAuthority>>,
    /// The atomically retained Host-approved bridge profile and its protected
    /// declaration, if the active candidate supplied one.
    #[cfg(windows)]
    agent_bridge_profile: Mutex<Option<AgentBridgeProfile>>,
    #[cfg(windows)]
    /// Host-carried descriptor retained as inert composition input. It is
    /// never exposed to the front door until the matching candidate is Ready.
    agent_bridge_admission: Option<AgentBridgeAdmissionDescriptor>,
    #[cfg(windows)]
    agent_bridge_peer_set_revision: AtomicU64,
    #[cfg(windows)]
    agent_bridge_peer_set_changed: tokio::sync::Notify,
    #[cfg(windows)]
    agent_bridge_connections: Mutex<BTreeMap<String, AgentBridgeConnectionState>>,
    #[cfg(windows)]
    agent_activation_pending: Mutex<AgentActivationPendingState>,
    #[cfg(windows)]
    agent_activation_changed: tokio::sync::Notify,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct AgentBridgeProfile {
    admission: AgentBridgeAdmissionDescriptor,
    declaration: AgentBridgeClientDeclaration,
}

#[cfg(windows)]
#[derive(Debug)]
struct AgentBridgeConnectionState {
    exchange: ServerFirstConnection,
    declaration: AgentBridgeClientDeclaration,
    peer: PeerIdentity,
    accepted_transport: Option<AcceptedAgentBridgeTransport>,
    /// Kernel-owned transport Session retained after successful activation.
    session: Option<Session>,
    activation_completed: bool,
}

#[cfg(windows)]
#[derive(Default)]
struct AgentActivationPendingState {
    fifo: VecDeque<String>,
    entries: BTreeMap<String, AgentActivationPending>,
    /// Bounded replay ledger. A request identity is never rebound to a new
    /// connection after completion or disconnect.
    replay: BTreeMap<String, String>,
}

#[cfg(windows)]
#[derive(Clone)]
struct AgentActivationPending {
    ticket: AgentActivationResolutionTicket,
    request: AgentBridgeActivationRequest,
    decision: Option<AgentActivationResolutionDecision>,
    /// Private Kernel claim lease; it is deliberately absent from the wire
    /// ticket so retries cannot mint or select a caller-owned identity.
    claim_lease_until_unix_ms: Option<u64>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationDecisionDisposition {
    Commit,
    ExactReplay,
    Conflict,
}

#[cfg(windows)]
fn classify_activation_decision(
    existing: Option<&AgentActivationResolutionDecision>,
    incoming: &AgentActivationResolutionDecision,
) -> ActivationDecisionDisposition {
    match existing {
        None => ActivationDecisionDisposition::Commit,
        Some(existing) if existing == incoming => ActivationDecisionDisposition::ExactReplay,
        Some(_) => ActivationDecisionDisposition::Conflict,
    }
}

#[cfg(windows)]
impl AgentActivationPendingState {
    fn claim_at(&mut self, now: u64) -> Option<AgentActivationResolutionTicket> {
        let queue_len = self.fifo.len();
        for _ in 0..queue_len {
            let ticket_id = self.fifo.pop_front()?;
            let Some(entry) = self.entries.get_mut(&ticket_id) else {
                continue;
            };
            if entry.decision.is_some()
                || activation_deadline_expired(now, entry.ticket.kernel_deadline_unix_ms)
            {
                continue;
            }
            if entry
                .claim_lease_until_unix_ms
                .is_some_and(|lease_until| now < lease_until)
            {
                self.fifo.push_back(ticket_id);
                continue;
            }
            entry.claim_lease_until_unix_ms = Some(
                now.saturating_add(AGENT_ACTIVATION_CLAIM_LEASE_MS)
                    .min(entry.ticket.kernel_deadline_unix_ms),
            );
            let ticket = entry.ticket.clone();
            self.fifo.push_back(ticket_id);
            return Some(ticket);
        }
        None
    }
}

/// Server-first bridge handshake material returned by Kernel composition.
/// This carries transport evidence only; it is not a Kernel `Session`.
#[cfg(windows)]
#[derive(Debug)]
pub struct AgentBridgeHandshake {
    pub connection_id: String,
    pub challenge: AgentBridgePeerChallenge,
    pub challenge_frame: Frame,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DaemonRuntimeStatus {
    NotLaunched,
    Launching,
    Running,
    Ready,
    Degraded(String),
    Failed(String),
}

const fn daemon_status_proves_ready(status: &DaemonRuntimeStatus) -> bool {
    matches!(status, DaemonRuntimeStatus::Ready)
}

struct DaemonRuntimeState {
    status: DaemonRuntimeStatus,
    receipt: Option<ProcessStartReceipt>,
    recovery_fenced: bool,
    #[cfg(windows)]
    supervision: Option<DaemonSupervisionContour>,
    #[cfg(windows)]
    live_ready: Option<EliotdLiveReadyEvidence>,
}

#[cfg(windows)]
impl DaemonRuntimeState {
    fn bind_live_receipt_publication_operation(
        &mut self,
        ready: &EliotdLiveReadyEvidence,
    ) -> Result<(), KernelServiceError> {
        if !matches!(
            self.status,
            DaemonRuntimeStatus::Running | DaemonRuntimeStatus::Ready
        ) || self.receipt.is_none()
            || self.live_ready.as_ref().is_some_and(|bound| bound != ready)
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        self.live_ready = Some(ready.clone());
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DaemonSupervisionContour {
    candidate_digest: String,
    incarnation: SupervisionLeaseIncarnationBinding,
    activation: KernelActivationReceipt,
    generation_binding: SupervisionGenerationBinding,
    state_fence: StateFence,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct EliotdSupervisionSuccessorEvidence {
    operation: SupervisionLeaseOperation,
    state: LeaseState,
    lease_id: String,
    revision: u64,
    receipt_sha256: String,
    previous_receipt_sha256: Option<String>,
}

#[cfg(windows)]
impl From<&SupervisionLeaseSnapshot> for EliotdSupervisionSuccessorEvidence {
    fn from(snapshot: &SupervisionLeaseSnapshot) -> Self {
        Self {
            operation: snapshot.record.operation,
            state: snapshot.record.state,
            lease_id: snapshot.record.lease_id.as_str().to_owned(),
            revision: snapshot.record.revision,
            receipt_sha256: snapshot.receipt.receipt_sha256.clone(),
            previous_receipt_sha256: snapshot.record.previous_receipt_sha256.clone(),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EliotdLiveReceiptDisposition {
    ExactReplay,
    ReplaceActivationPredecessor,
    ReplaceRenewalPredecessor,
}

#[cfg(windows)]
fn classify_eliotd_live_receipt_transition(
    old: &EliotdLiveReceipt,
    expected: &EliotdLiveReceipt,
    status_is_ready: bool,
    activation_predecessor: Option<&SupervisionLeasePredecessorIdentity>,
    supervision_successor: Option<&EliotdSupervisionSuccessorEvidence>,
) -> Result<EliotdLiveReceiptDisposition, KernelServiceError> {
    if old == expected {
        return Ok(EliotdLiveReceiptDisposition::ExactReplay);
    }
    let exact_activation_predecessor = activation_predecessor.is_some_and(|predecessor| {
        predecessor.supervision_lease_id == old.supervision.lease_id
            && predecessor.ors_receipt_sha256 == old.supervision.receipt_sha256
            && old.installation_id == expected.installation_id
            && old.runtime_state_roots_digest == expected.runtime_state_roots_digest
            && old.supervision.public_key_fingerprint == expected.supervision.public_key_fingerprint
    });
    if !status_is_ready && exact_activation_predecessor {
        return Ok(EliotdLiveReceiptDisposition::ReplaceActivationPredecessor);
    }
    let exact_renewal_predecessor = supervision_successor.is_some_and(|successor| {
        successor.operation == SupervisionLeaseOperation::Renew
            && successor.state == LeaseState::Active
            && successor.lease_id == expected.supervision.lease_id
            && successor.revision == expected.supervision.revision
            && successor.receipt_sha256 == expected.supervision.receipt_sha256
            && successor.previous_receipt_sha256.as_deref()
                == Some(old.supervision.receipt_sha256.as_str())
            && old.supervision.revision.checked_add(1) == Some(expected.supervision.revision)
            && old.process == expected.process
            && old.ready == expected.ready
            && old.receipt_root_identity_sha256 == expected.receipt_root_identity_sha256
            && old.runtime_state_roots_digest == expected.runtime_state_roots_digest
            && old.installation_id == expected.installation_id
            && old.approved_generation == expected.approved_generation
            && old.generation == expected.generation
            && old.authority_epoch == expected.authority_epoch
            && old.config_descriptor_sha256 == expected.config_descriptor_sha256
            && old.descriptor_sha256 == expected.descriptor_sha256
            && old.kernel_artifact_sha256 == expected.kernel_artifact_sha256
            && old.supervision.lease_id == expected.supervision.lease_id
            && old.supervision.public_key_fingerprint == expected.supervision.public_key_fingerprint
    });
    if status_is_ready && exact_renewal_predecessor {
        return Ok(EliotdLiveReceiptDisposition::ReplaceRenewalPredecessor);
    }
    Err(KernelServiceError::ReadinessNotProven)
}

/// Fail-closed errors for the Kernel-owned supervision lease authority.  The
/// protected-key branch deliberately exposes only stable categories; provider
/// diagnostics are never allowed to include a secret target's contents.
#[cfg(windows)]
#[derive(Debug)]
pub enum SupervisionLeaseAuthorityError {
    Configuration(String),
    ProtectedKeyUnavailable,
    Contract(String),
    Ors(OrsError),
}

#[cfg(windows)]
impl fmt::Display for SupervisionLeaseAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(reason) => {
                write!(formatter, "invalid supervision authority: {reason}")
            }
            Self::ProtectedKeyUnavailable => {
                formatter.write_str("protected supervision signing key is unavailable")
            }
            Self::Contract(reason) => {
                write!(formatter, "supervision lease contract rejected: {reason}")
            }
            Self::Ors(error) => {
                write!(formatter, "supervision ORS rejected the operation: {error}")
            }
        }
    }
}

#[cfg(windows)]
impl std::error::Error for SupervisionLeaseAuthorityError {}

#[cfg(windows)]
impl From<OrsError> for SupervisionLeaseAuthorityError {
    fn from(error: OrsError) -> Self {
        Self::Ors(error)
    }
}

/// Kernel-held signer which reopens and revalidates the exact installer-owned
/// ciphertext file, then asks DPAPI-NG to unseal it under the current
/// `EliotHost` service-SID token for each operation.
#[cfg(windows)]
pub struct ProtectedSupervisionLeaseSigner {
    kernel_root: PathBuf,
    key_store: WindowsSupervisionAuthorityKeyStore,
    authority: ProvisionedSupervisionAuthority,
    signer_id: String,
    key_id: String,
    expected_public_key_fingerprint: String,
}

#[cfg(windows)]
impl fmt::Debug for ProtectedSupervisionLeaseSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedSupervisionLeaseSigner")
            .field("signer_id", &self.signer_id)
            .field("key_id", &self.key_id)
            .field(
                "expected_public_key_fingerprint",
                &self.expected_public_key_fingerprint,
            )
            .field("key_provider", &self.authority.key_reference.provider)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl ProtectedSupervisionLeaseSigner {
    fn new(
        kernel_root: PathBuf,
        config: &SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, SupervisionLeaseAuthorityError> {
        config
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Configuration)?;
        let signer = Self {
            kernel_root,
            key_store: WindowsSupervisionAuthorityKeyStore::new(),
            authority: config.authority.clone(),
            signer_id: config.authority.trust_anchor.signer_id.clone(),
            key_id: config.authority.trust_anchor.key_id.clone(),
            expected_public_key_fingerprint: config
                .authority
                .trust_anchor
                .public_key_fingerprint
                .clone(),
        };
        signer
            .load_signer()
            .map_err(|_| SupervisionLeaseAuthorityError::ProtectedKeyUnavailable)?;
        Ok(signer)
    }

    fn load_signer(&self) -> Result<Ed25519SupervisionLeaseSigner, SupervisionLeaseError> {
        let spec = supervision_authority_root_spec(&self.kernel_root)?;
        let secret = self
            .key_store
            .unseal_for_kernel(&spec, &self.kernel_root, &self.authority)
            .map_err(|_| {
                SupervisionLeaseError::Signing(
                    "service-SID sealed supervision key unavailable".to_owned(),
                )
            })?;
        if secret.expose().len() != 32 || secret.expose().iter().all(|byte| *byte == 0) {
            return Err(SupervisionLeaseError::Signing(
                "protected key has invalid length or value".to_owned(),
            ));
        }
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(secret.expose());
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
            self.signer_id.clone(),
            self.key_id.clone(),
            key_bytes,
        )?;
        // CredentialSecret zeroizes its provider-owned buffer on drop. Clear
        // this independent stack copy as soon as the signing key owns its
        // internal zeroizing representation.
        key_bytes.fill(0);
        if sha256_hex(&signer.public_key()) != self.expected_public_key_fingerprint {
            return Err(SupervisionLeaseError::Signing(
                "protected key does not match the installation trust anchor".to_owned(),
            ));
        }
        Ok(signer)
    }

    /// Returns the provider reference only; no secret bytes cross this API.
    pub fn key_reference(&self) -> &SupervisionSealedKeyReference {
        &self.authority.key_reference
    }
}

#[cfg(windows)]
fn supervision_authority_root_spec(
    kernel_root: &Path,
) -> Result<InstallerRootPrimitiveSpec, SupervisionLeaseError> {
    if !kernel_root.is_absolute()
        || kernel_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(SupervisionLeaseError::Signing(
            "Kernel supervision root must be absolute".to_owned(),
        ));
    }
    let profile_anchor = protected_program_data_root().map_err(|_| {
        SupervisionLeaseError::Signing("protected ProgramData root unavailable".to_owned())
    })?;
    // `WindowsInstallerRootPrimitive` independently validates this exact
    // installation contour (`ProgramData\\Eliot`) and that `kernel_root` is
    // below it before opening the retained ciphertext file. Never substitute
    // `kernel_root` itself as the installation root.
    let installation_root = profile_anchor.join("Eliot");
    Ok(InstallerRootPrimitiveSpec {
        root: kernel_root.to_path_buf(),
        installation_root,
        profile_anchor,
        profile: InstallerRootProfile::SystemService,
    })
}

#[cfg(windows)]
impl SupervisionLeaseSigner for ProtectedSupervisionLeaseSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, SupervisionLeaseError> {
        let signer = self.load_signer()?;
        signer.sign(canonical_payload)
    }
}

/// The one Kernel composition that may turn an ORS ticket into a signed
/// supervision-lease record.  ORS remains the only durable ticket/transition
/// issuer; this type owns only the protected key boundary and authenticated
/// orchestration around it.
#[cfg(windows)]
pub struct KernelSupervisionLeaseAuthority {
    ors: Arc<RedbRecoveryStore>,
    signer: ProtectedSupervisionLeaseSigner,
    trust_anchor: SupervisionTrustAnchor,
    supervision_lease_scope_id: String,
}

#[cfg(windows)]
impl fmt::Debug for KernelSupervisionLeaseAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelSupervisionLeaseAuthority")
            .field("trust_anchor", &self.trust_anchor)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl KernelSupervisionLeaseAuthority {
    fn new(
        ors: Arc<RedbRecoveryStore>,
        kernel_root: PathBuf,
        config: SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        let signer = ProtectedSupervisionLeaseSigner::new(kernel_root, &config)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        Ok(Self {
            ors,
            signer,
            trust_anchor: config.authority.trust_anchor,
            supervision_lease_scope_id: config.authority.supervision_lease_scope_id,
        })
    }

    /// Returns the installation-pinned public trust anchor.
    pub fn trust_anchor(&self) -> &SupervisionTrustAnchor {
        &self.trust_anchor
    }

    /// Returns the protected key reference; no seed is exposed.
    pub fn key_reference(&self) -> &SupervisionSealedKeyReference {
        self.signer.key_reference()
    }

    /// Returns the exact lease identity selected by the installer plan.
    pub fn supervision_lease_scope_id(&self) -> &str {
        &self.supervision_lease_scope_id
    }

    /// Returns the exact authoritative ORS head selected by the provisioned
    /// lease identity. `ProbeReady` callers fail closed when this is absent.
    pub fn current_snapshot(
        &self,
        supervision_lease_id: &str,
    ) -> Result<Option<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        let lease_id = OperationIdentity::new(supervision_lease_id.to_owned())?;
        self.ors
            .load_current_supervision_lease(&lease_id)
            .map_err(Into::into)
    }

    fn staged_snapshot(
        &self,
        supervision_lease_id: &str,
    ) -> Result<Option<SupervisionLeaseStageReceipt>, SupervisionLeaseAuthorityError> {
        let lease_id = OperationIdentity::new(supervision_lease_id.to_owned())?;
        self.ors
            .reconcile_staged_supervision_lease(&lease_id)
            .map_err(Into::into)
    }

    fn verify_active_snapshot(
        &self,
        snapshot: &SupervisionLeaseSnapshot,
        supervision_lease_id: &str,
        now_ms: u64,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        snapshot
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        if snapshot.record.lease_id.as_str() != supervision_lease_id
            || snapshot.record.state != LeaseState::Active
            || snapshot.record.projection != eliot_ors::SupervisionLeaseProjection::Active
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let context = snapshot
            .active_verification_context(self.trust_anchor.public_key_fingerprint(), now_ms)
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        self.trust_anchor
            .verify(&snapshot.record.artifact, &context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        Ok(())
    }

    fn verify_superseded_replay(
        &self,
        terminal: &SupervisionLeaseSnapshot,
        expected_predecessor: &SupervisionLeasePredecessorIdentity,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        verify_superseded_supervision_replay(
            self.ors.as_ref(),
            &self.trust_anchor,
            terminal,
            expected_predecessor,
        )
    }

    /// Reads and authenticates the exact active ORS head embedded in the
    /// Kernel-owned eliotd receipt. Missing, terminal, stale, foreign, or
    /// differently fenced records are never projected as readiness evidence.
    pub fn current_eliotd_live_evidence(
        &self,
        expected_supervision_lease_id: &str,
        expected_generation: u64,
        expected_authority_epoch: u64,
    ) -> Result<EliotdLiveSupervisionEvidence, SupervisionLeaseAuthorityError> {
        self.current_eliotd_live_projection(
            expected_supervision_lease_id,
            expected_generation,
            expected_authority_epoch,
        )
        .map(|(evidence, _)| evidence)
    }

    fn current_eliotd_live_projection(
        &self,
        expected_supervision_lease_id: &str,
        expected_generation: u64,
        expected_authority_epoch: u64,
    ) -> Result<(EliotdLiveSupervisionEvidence, u64), SupervisionLeaseAuthorityError> {
        let current = self
            .current_snapshot(expected_supervision_lease_id)?
            .ok_or(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ))?;
        current
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || current.record.lease_id.as_str() != expected_supervision_lease_id
            || current
                .record
                .binding
                .state_fence
                .resource_generation
                .value()
                != expected_generation
            || current.record.binding.state_fence.authority_epoch.value()
                != expected_authority_epoch
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let payload = &current.record.artifact.payload;
        let now_ms = unix_ms();
        if payload.installation_id != self.trust_anchor.installation_id
            || payload.issued_at_ms == 0
            || now_ms < payload.issued_at_ms
            || now_ms >= payload.expires_at_ms
            || payload.ors_mirror.record_id != current.record.record_id.as_str()
            || payload.ors_mirror.lease_revision != current.record.revision
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let context = self.verification_context(payload, now_ms);
        let verified = self
            .trust_anchor
            .verify(&current.record.artifact, &context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        if verified.payload() != payload {
            return Err(SupervisionLeaseAuthorityError::Contract(
                "verified supervision payload diverged from the durable ORS artifact".to_owned(),
            ));
        }
        let envelope_sha256 = current
            .record
            .artifact
            .envelope_digest()
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        Ok((
            EliotdLiveSupervisionEvidence {
                lease_id: current.record.lease_id.as_str().to_owned(),
                record_id: current.record.record_id.as_str().to_owned(),
                revision: current.record.revision,
                receipt_sha256: current.receipt.receipt_sha256.clone(),
                envelope_sha256,
                payload_sha256: current.record.artifact.payload_sha256.clone(),
                public_key_fingerprint: self.trust_anchor.public_key_fingerprint().to_owned(),
            },
            payload.issued_at_ms,
        ))
    }

    fn validate_binding(
        &self,
        binding: &eliot_ors::SupervisionLeaseBinding,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        if binding.installation_id.as_str() != self.trust_anchor.installation_id {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "lease installation identity does not match the trust anchor".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reserves one exact operation/revision/predecessor through ORS.
    pub fn prepare(
        &self,
        request: SupervisionLeasePrepareRequest,
    ) -> Result<SupervisionLeaseStageReceipt, SupervisionLeaseAuthorityError> {
        self.validate_binding(&request.binding)?;
        self.ors
            .prepare_supervision_lease(request)
            .map_err(Into::into)
    }

    fn verification_context(
        &self,
        payload: &SupervisionLease,
        now_ms: u64,
    ) -> SupervisionLeaseVerificationContext {
        verification_context_for_supervision_payload(&self.trust_anchor, payload, now_ms)
    }

    fn staged_ticket(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        let stage = self
            .ors
            .reconcile_staged_supervision_lease(&ticket.lease_id)?
            .ok_or({
                SupervisionLeaseAuthorityError::Ors(OrsError::SupervisionLeaseTicketNotStaged)
            })?;
        if stage.ticket != *ticket || stage.ticket_sha256 != ticket.ticket_sha256()? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseTicketConflict,
            ));
        }
        Ok(())
    }

    /// Signs and commits an active/renewed ticket.  An already committed
    /// result is returned before Credential Manager is read, preventing a
    /// response-loss retry from signing or reusing the revision again.
    pub fn commit_active(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        if !matches!(
            ticket.operation,
            SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew
        ) {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "active commit requires COMMIT or RENEW".to_owned(),
            ));
        }
        if let Some(snapshot) = self.ors.replay_supervision_lease_commit(ticket)? {
            return Ok(snapshot);
        }
        self.staged_ticket(ticket)?;
        let payload = ticket
            .expected_payload()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        self.validate_binding(&ticket.binding)?;
        let envelope = payload.sign(&self.signer).map_err(|error| match error {
            SupervisionLeaseError::Signing(_) => {
                SupervisionLeaseAuthorityError::ProtectedKeyUnavailable
            }
            error => SupervisionLeaseAuthorityError::Contract(error.to_string()),
        })?;
        let context = self.verification_context(&payload, unix_ms());
        let verified = self
            .trust_anchor
            .verify(&envelope, &context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        self.ors
            .commit_supervision_lease(ticket, &verified)
            .map_err(Into::into)
    }

    /// Signs and commits a terminal transition using the exact active ORS
    /// predecessor.  The caller cannot substitute a predecessor proof.
    pub fn commit_terminal(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        if matches!(
            ticket.operation,
            SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew
        ) {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "terminal commit requires a terminal operation".to_owned(),
            ));
        }
        if let Some(snapshot) = self.ors.replay_supervision_lease_commit(ticket)? {
            return Ok(snapshot);
        }
        self.staged_ticket(ticket)?;
        let current = self
            .ors
            .load_current_supervision_lease(&ticket.lease_id)?
            .ok_or(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ))?;
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || ticket.expected_revision != Some(current.record.revision)
            || ticket.previous_receipt_sha256.as_deref()
                != Some(current.receipt.receipt_sha256.as_str())
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        self.validate_binding(&ticket.binding)?;
        let prior_context = self.verification_context(
            &current.record.artifact.payload,
            current.record.artifact.payload.issued_at_ms,
        );
        let prior_active = self
            .trust_anchor
            .verify(&current.record.artifact, &prior_context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        let predecessor = SupervisionLeasePredecessorProof {
            lease_id: current.record.lease_id.as_str().to_owned(),
            record_id: current.record.record_id.as_str().to_owned(),
            lease_revision: current.record.revision,
            receipt_sha256: current.receipt.receipt_sha256.clone(),
            envelope_sha256: current
                .record
                .artifact
                .envelope_digest()
                .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
        };
        let payload = ticket
            .expected_payload()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        let envelope = payload.sign(&self.signer).map_err(|error| match error {
            SupervisionLeaseError::Signing(_) => {
                SupervisionLeaseAuthorityError::ProtectedKeyUnavailable
            }
            error => SupervisionLeaseAuthorityError::Contract(error.to_string()),
        })?;
        let verified = self
            .trust_anchor
            .verify_terminal_transition(&prior_active, &envelope, &predecessor)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        self.ors
            .commit_terminal_supervision_lease(ticket, &verified)
            .map_err(Into::into)
    }

    /// Reconciles bounded staged tickets after a Kernel restart.  It never
    /// promotes an unrecognized or corrupt row and leaves the durable stage
    /// in place when the protected key cannot be reloaded.
    pub fn reconcile(
        &self,
        limit: u16,
    ) -> Result<Vec<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        let stages = self.ors.reconcile_staged_supervision_leases(limit)?;
        let mut committed = Vec::with_capacity(stages.len());
        for stage in stages {
            let snapshot = match stage.ticket.operation {
                SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew => {
                    self.commit_active(&stage.ticket)?
                }
                SupervisionLeaseOperation::Revoke
                | SupervisionLeaseOperation::Expire
                | SupervisionLeaseOperation::Supersede
                | SupervisionLeaseOperation::Close => self.commit_terminal(&stage.ticket)?,
            };
            committed.push(snapshot);
        }
        Ok(committed)
    }
}

#[cfg(windows)]
fn verification_context_for_supervision_payload(
    trust_anchor: &SupervisionTrustAnchor,
    payload: &SupervisionLease,
    now_ms: u64,
) -> SupervisionLeaseVerificationContext {
    SupervisionLeaseVerificationContext {
        now_ms,
        lease_id: payload.lease_id.clone(),
        host_epoch: payload.host_epoch,
        activation_id: payload.activation_id.clone(),
        activation_generation: payload.activation_generation,
        kernel_epoch: payload.kernel_epoch,
        watchdog_epoch: payload.watchdog_epoch,
        state_fence: payload.state_fence.clone(),
        scope_ref: payload.scope_ref.clone(),
        observation_scope: payload.observation_scope.clone(),
        target_id: payload.generation_binding.target_id.clone(),
        module_id: payload.generation_binding.module_id.clone(),
        process_id: payload.generation_binding.process_id.clone(),
        target_generation: payload.generation_binding.target_generation,
        module_generation: payload.generation_binding.module_generation,
        process_generation: payload.generation_binding.process_generation,
        public_key_fingerprint: trust_anchor.public_key_fingerprint.clone(),
        ors_mirror: payload.ors_mirror.clone(),
        active_state: SupervisionLeaseActiveStateBinding {
            state: payload.state,
            revocation_id: payload.revocation_id.clone(),
            revocation_epoch: payload.revocation_epoch,
        },
    }
}

#[cfg(windows)]
fn verify_superseded_supervision_replay(
    ors: &RedbRecoveryStore,
    trust_anchor: &SupervisionTrustAnchor,
    terminal: &SupervisionLeaseSnapshot,
    expected_predecessor: &SupervisionLeasePredecessorIdentity,
) -> Result<(), SupervisionLeaseAuthorityError> {
    terminal
        .validate()
        .map_err(SupervisionLeaseAuthorityError::Ors)?;
    expected_predecessor
        .validate()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    if terminal.record.operation != SupervisionLeaseOperation::Supersede
        || terminal.record.state != LeaseState::Superseded
        || terminal.record.projection != eliot_ors::SupervisionLeaseProjection::Terminal
        || terminal.record.binding.terminal_disposition
            != Some(SupervisionLeaseTerminalDisposition::Superseded)
        || terminal.record.lease_id.as_str() != expected_predecessor.supervision_lease_id
        || terminal.record.previous_receipt_sha256.as_deref()
            != Some(expected_predecessor.ors_receipt_sha256.as_str())
    {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let lease_id = OperationIdentity::new(expected_predecessor.supervision_lease_id.clone())?;
    let history = ors.load_supervision_lease_history(&lease_id, 2)?;
    if history.len() != 2 || history.first() != Some(terminal) {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let prior = &history[1];
    prior
        .validate()
        .map_err(SupervisionLeaseAuthorityError::Ors)?;
    if prior.record.state != LeaseState::Active
        || prior.record.projection != eliot_ors::SupervisionLeaseProjection::Active
        || prior.record.lease_id != lease_id
        || prior.record.revision.checked_add(1) != Some(terminal.record.revision)
        || prior.receipt.receipt_sha256 != expected_predecessor.ors_receipt_sha256
    {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let prior_context = verification_context_for_supervision_payload(
        trust_anchor,
        &prior.record.artifact.payload,
        prior.record.artifact.payload.issued_at_ms,
    );
    let verified_prior = trust_anchor
        .verify(&prior.record.artifact, &prior_context)
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    let predecessor_proof = SupervisionLeasePredecessorProof {
        lease_id: prior.record.lease_id.as_str().to_owned(),
        record_id: prior.record.record_id.as_str().to_owned(),
        lease_revision: prior.record.revision,
        receipt_sha256: prior.receipt.receipt_sha256.clone(),
        envelope_sha256: prior
            .record
            .artifact
            .envelope_digest()
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
    };
    trust_anchor
        .verify_terminal_transition(
            &verified_prior,
            &terminal.record.artifact,
            &predecessor_proof,
        )
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    Ok(())
}

#[cfg(windows)]
fn supervision_operation_identity(
    kind: &str,
    lease_id: &str,
    predecessor_receipt: Option<&str>,
) -> Result<OperationIdentity, SupervisionLeaseAuthorityError> {
    let digest = sha256_json(&(kind, lease_id, predecessor_receipt))
        .map_err(|error| SupervisionLeaseAuthorityError::Configuration(error.to_string()))?;
    OperationIdentity::new(format!("eliot-supervision:{kind}:{digest}")).map_err(Into::into)
}

#[cfg(windows)]
fn supervision_binding_matches_contour(
    binding: &eliot_ors::SupervisionLeaseBinding,
    contour: &DaemonSupervisionContour,
) -> Result<bool, SupervisionLeaseAuthorityError> {
    let incarnation = &contour.incarnation;
    let scope_ref = incarnation
        .derived_scope_ref()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    let watchdog_epoch = AuthorityEpoch::new(incarnation.watchdog_epoch.sequence)
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    Ok(binding.scope_ref.as_str() == scope_ref
        && binding.observation_scope == incarnation.observation_scope
        && binding.installation_id.as_str() == incarnation.installation_id
        && binding.host_epoch.value() == incarnation.host_epoch.sequence
        && binding.activation_id.as_str() == incarnation.activation_id
        && binding.activation_generation == contour.activation.generation
        && binding.kernel_epoch == contour.activation.authority_epoch
        && binding.watchdog_epoch == watchdog_epoch
        && binding.generation_binding == contour.generation_binding
        && binding.state_fence == contour.state_fence
        && binding.wake_policy == incarnation.wake_policy)
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
    /// Execute one narrow authenticated `eliotd` lifecycle operation.  The
    /// operation is handled by Kernel's daemon contour, while Store-backed
    /// health remains an asynchronous physical probe.
    Daemon {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Closed operation name from the daemon application wire.
        operation: String,
        /// Bounded operation payload.
        payload: serde_json::Value,
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
        self.gateway.fence();
    }
}

#[cfg(windows)]
struct CanonicalStoreReplace<'a> {
    gateway: Arc<KernelStoreGateway>,
    process_gateway: &'a ProcessExecutionGateway,
    old: Option<Arc<KernelStoreGateway>>,
    active: bool,
}

#[cfg(windows)]
impl CanonicalStoreReplace<'_> {
    fn commit(mut self) {
        self.active = false;
    }
}

#[cfg(windows)]
impl CanonicalStoreAttachmentTransaction for CanonicalStoreReplace<'_> {
    fn commit(self: Box<Self>) {
        (*self).commit();
    }
}

#[cfg(windows)]
impl Drop for CanonicalStoreReplace<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut retained) = self.process_gateway.canonical_store.lock()
            && retained
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gateway))
        {
            retained.clone_from(&self.old);
        }
        self.gateway.fence();
    }
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
    async fn completed_receipt(
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

    fn readiness_configuration_valid(&self) -> bool {
        let binding = self.snapshot_binding.to_wire();
        binding.validate().is_ok()
            && self
                .controller
                .lock()
                .is_ok_and(|controller| controller.authority_id() == &binding.authority_id)
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
    fn replace_canonical_store(
        &self,
        gateway: Arc<KernelStoreGateway>,
    ) -> Result<CanonicalStoreReplace<'_>, KernelBuildError> {
        let mut retained = self
            .canonical_store
            .lock()
            .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?;
        let old = retained.clone();
        *retained = Some(Arc::clone(&gateway));
        Ok(CanonicalStoreReplace {
            gateway,
            process_gateway: self,
            old,
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

    #[cfg(windows)]
    async fn inspect_exact_running_receipt(
        &self,
        receipt: &ProcessStartReceipt,
    ) -> Result<(), ProcessExecutionError> {
        receipt.validate()?;
        let record = self
            .replay_store
            .load_process_start(receipt.operation_id())
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
            .ok_or(ProcessExecutionError::NotFound)?;
        if record.state != ProcessExecutionReplayState::Completed
            || record.receipt.as_ref() != Some(receipt)
        {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let view = match self
            .inspect(&record.owner, receipt.operation_id().clone())
            .await
        {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            Err(error) => return Err(error),
        };
        if view.lifecycle() != ProcessLifecycle::Running
            || view.binding() != receipt.binding()
            || view.identity() != Some(receipt.identity())
        {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        Ok(())
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
                    .completed_receipt(record)
                    .await?
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

    async fn completed_receipt(
        &self,
        record: ProcessExecutionReplayRecord,
    ) -> Result<Option<Self::Receipt>, ProcessExecutionError> {
        let receipt = record
            .receipt
            .ok_or(ProcessExecutionError::UnknownOutcome)?;
        receipt.validate()?;
        let view = match self.executor.inspect(receipt.operation_id().clone()).await {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            Err(error) => return Err(error),
        };
        if view.lifecycle() != ProcessLifecycle::Running
            || view.binding() != receipt.binding()
            || view.identity() != Some(receipt.identity())
        {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        Ok(Some(receipt))
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

#[cfg(windows)]
fn activation_deadline_expired(now: u64, deadline: u64) -> bool {
    now >= deadline
}

#[cfg(windows)]
fn load_agent_bridge_declaration(
    admission: &AgentBridgeAdmissionDescriptor,
) -> Result<AgentBridgeClientDeclaration, KernelBuildError> {
    admission
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let path = Path::new(admission.client_declaration_path.as_str());
    let bytes = read_protected_file(path, eliot_protocol::MAX_FRAME_BYTES as u64)
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let declaration: AgentBridgeClientDeclaration = serde_json::from_slice(&bytes)
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    admission
        .validate_client_declaration(&declaration)
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    Ok(declaration)
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

#[cfg(windows)]
fn store_rebind_record_matches(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    record.operation_id.as_str() == handoff.operation_id.as_str()
        && record.request_digest == request_digest
        && record.candidate_binding_digest == handoff.candidate_binding_digest
        && record.store_fence == handoff.store_fence
        && record.requirement_digest == requirement_digest
        && record.process_id == handoff.process_binding.process.process_id
        && record.process_start_time_100ns == handoff.process_binding.process.start_time_100ns
        && record.process_image_path == handoff.process_binding.process.image_path
        && record.job_name == handoff.process_binding.job.as_str()
        && record.generation == handoff.generation.value()
        && record.authority_epoch == handoff.authority_epoch.value()
}

#[cfg(windows)]
fn store_rebind_record_is_committed(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
        && record.state == eliot_ors::StoreRebindReplayState::Committed
        && record.receipt.as_deref() == Some(request_digest)
}

#[cfg(windows)]
fn store_rebind_record_is_pending(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
        && record.state == eliot_ors::StoreRebindReplayState::Pending
        && record.receipt.is_none()
}

#[cfg(windows)]
fn store_rebind_receipt_from_ors_record(
    record: &eliot_ors::StoreRebindReplayRecord,
) -> Result<eliot_kernel_service::StoreRebindReceipt, KernelBuildError> {
    if record.state != eliot_ors::StoreRebindReplayState::Committed
        || record.receipt.as_deref() != Some(record.request_digest.as_str())
    {
        return Err(KernelBuildError::Service(
            "ORS Store rebind record is not an exact committed receipt".to_owned(),
        ));
    }
    let receipt = eliot_kernel_service::StoreRebindReceipt {
        operation_id: PlatformHandle::new(record.operation_id.as_str())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        request_digest: record.request_digest.clone(),
        requirement_digest: record.requirement_digest.clone(),
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: eliot_kernel_service::HostProcessBinding {
                process_id: record.process_id,
                start_time_100ns: record.process_start_time_100ns,
                image_path: record.process_image_path.clone(),
            },
            job: PlatformHandle::new(record.job_name.clone())
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        },
        candidate_binding_digest: record.candidate_binding_digest.clone(),
        generation: ResourceGeneration::new(record.generation)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        authority_epoch: AuthorityEpoch::new(record.authority_epoch)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        store_fence: record.store_fence.clone(),
    };
    receipt
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    Ok(receipt)
}

#[cfg(windows)]
#[allow(clippy::unwrap_used)]
fn is_store_rebind_latest_committed(
    ors: &eliot_ors::RedbRecoveryStore,
    record: &eliot_ors::StoreRebindReplayRecord,
) -> Result<bool, KernelBuildError> {
    let all = ors
        .load_all_store_rebinds()
        .map_err(|e| KernelBuildError::Service(e.to_string()))?;
    let committed: Vec<_> = all
        .iter()
        .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Committed)
        .collect();
    if committed.is_empty() {
        return Ok(true);
    }
    let same_lineage_zeros = committed
        .iter()
        .filter(|r| {
            r.commit_order == 0
                && r.requirement_digest == record.requirement_digest
                && r.generation == record.generation
                && r.authority_epoch == record.authority_epoch
        })
        .count();
    if same_lineage_zeros > 1 {
        return Err(KernelBuildError::Service(
            "Store rebind legacy commit order requires migration/recovery".to_owned(),
        ));
    }
    let legacy_zeros = committed.iter().filter(|r| r.commit_order == 0).count();
    if legacy_zeros > 1 && record.commit_order == 0 {
        return Ok(false);
    }
    if record.commit_order == 0 {
        let max_order = committed.iter().map(|r| r.commit_order).max().unwrap_or(0);
        if max_order > 0 {
            return Ok(false);
        }
    }
    let latest = committed
        .iter()
        .max_by_key(|r| {
            (
                r.commit_order,
                r.operation_id.as_str().to_owned(),
                r.request_digest.clone(),
            )
        })
        .unwrap();
    Ok(latest.commit_order == record.commit_order
        && latest.operation_id == record.operation_id
        && latest.request_digest == record.request_digest)
}

#[cfg(windows)]
impl KernelComposition {
    fn ors_path_for_config(config: &KernelConfig) -> Result<PathBuf, KernelBuildError> {
        let Some(binding) = config.eliotd_receipt_binding.as_ref() else {
            return Ok(config.work_root.join(".eliot").join("kernel-ors.redb"));
        };
        binding.validate().map_err(KernelBuildError::Service)?;
        #[cfg(windows)]
        {
            let lease = ProtectedRootLease::open_existing(binding.kernel_ors_root())
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            let canonical = lease
                .canonical_path()
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            if !windows_paths_equal(&canonical, binding.kernel_ors_root())
                || lease.verify_stable_identity().is_err()
            {
                return Err(KernelBuildError::Service(
                    "manifest-bound Kernel ORS root identity is unavailable".to_owned(),
                ));
            }
            Ok(canonical.join("kernel-ors.redb"))
        }
        #[cfg(not(windows))]
        {
            Err(KernelBuildError::Service(
                "manifest-bound Kernel ORS root requires Windows retained-path proof".to_owned(),
            ))
        }
    }

    /// Returns the discriminator bound to the production Kernel composition.
    #[must_use]
    pub const fn production_store_rebind_discriminator() -> &'static str {
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    }

    #[allow(clippy::too_many_lines)]
    fn recover_store_rebind_state(
        ors: &RedbRecoveryStore,
        service: &mut eliot_kernel_service::KernelService,
        store_bootstrap: Option<&HostStoreBootstrapRequirement>,
    ) -> Result<Option<eliot_kernel_service::StoreBootstrapHandoff>, String> {
        let mut records = ors.load_all_store_rebinds().map_err(|e| e.to_string())?;
        let mut reconciled_committed = Vec::new();
        for pending in records
            .iter()
            .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Pending)
        {
            let aborted = ors
                .abort_store_rebind(&pending.operation_id, &pending.request_digest)
                .map_err(|error| {
                    format!(
                        "startup Store rebind abort/reconciliation failed for {}: {error}",
                        pending.operation_id.as_str()
                    )
                })?;
            if !aborted {
                let after = ors
                    .load_store_rebind(&pending.operation_id, &pending.request_digest)
                    .map_err(|error| {
                        format!(
                            "startup Store rebind abort readback failed for {}: {error}",
                            pending.operation_id.as_str()
                        )
                    })?
                    .ok_or_else(|| {
                        format!(
                            "startup Store rebind abort returned false without exact readback for {}",
                            pending.operation_id.as_str()
                        )
                    })?;
                if after.state != eliot_ors::StoreRebindReplayState::Committed
                    || after.receipt.as_deref() != Some(after.request_digest.as_str())
                {
                    return Err(format!(
                        "startup Store rebind abort did not reach a terminal disposition for {}",
                        pending.operation_id.as_str()
                    ));
                }
                reconciled_committed.push(after);
            }
        }
        records.extend(reconciled_committed);
        let Some(requirement) = store_bootstrap else {
            return Ok(None);
        };
        let requirement_digest = {
            let bytes = serde_json::to_vec(requirement).map_err(|e| e.to_string())?;
            format!("{:x}", Sha256::digest(&bytes))
        };
        // Select the latest durable commit only within the exact current
        // bootstrap lineage. An unrelated newer lineage must not shadow a
        // recoverable handoff for this requirement.
        let lineage_committed: Vec<_> = records
            .iter()
            .filter(|r| {
                r.state == eliot_ors::StoreRebindReplayState::Committed
                    && r.requirement_digest == requirement_digest
                    && r.generation == requirement.state_fence.resource_generation.value()
                    && r.authority_epoch == requirement.state_fence.authority_epoch.value()
            })
            .cloned()
            .collect();
        let legacy_zeros = lineage_committed
            .iter()
            .filter(|r| r.commit_order == 0)
            .count();
        if legacy_zeros > 1 {
            return Err(
                "Store rebind legacy commit order requires migration/recovery: ambiguous lineage"
                    .to_owned(),
            );
        }
        if legacy_zeros == 1 && lineage_committed.len() > 1 {
            let max_order = lineage_committed
                .iter()
                .map(|r| r.commit_order)
                .max()
                .unwrap_or(0);
            if max_order > 0 {
                let non_zero_latest = lineage_committed
                    .iter()
                    .filter(|r| r.commit_order > 0)
                    .max_by_key(|r| {
                        (
                            r.commit_order,
                            r.operation_id.as_str().to_owned(),
                            r.request_digest.clone(),
                        )
                    });
                if let Some(record) = non_zero_latest.cloned() {
                    let receipt = store_rebind_receipt_from_ors_record(&record)
                        .map_err(|error| error.to_string())?;
                    service
                        .restore_store_rebind_for_recovery(
                            receipt.clone(),
                            record.request_digest.clone(),
                        )
                        .map_err(|e| e.to_string())?;
                    return Ok(Some(eliot_kernel_service::StoreBootstrapHandoff {
                        requirement: requirement.clone(),
                        process_binding: receipt.process_binding.clone(),
                    }));
                }
            } else {
                return Err(
                    "Store rebind legacy commit order requires migration/recovery".to_owned(),
                );
            }
        }
        let committed = lineage_committed.into_iter().max_by_key(|r| {
            (
                r.commit_order,
                r.operation_id.as_str().to_owned(),
                r.request_digest.clone(),
            )
        });
        let Some(record) = committed else {
            return Ok(None);
        };
        let receipt =
            store_rebind_receipt_from_ors_record(&record).map_err(|error| error.to_string())?;
        service
            .restore_store_rebind_for_recovery(receipt.clone(), record.request_digest.clone())
            .map_err(|e| e.to_string())?;
        Ok(Some(eliot_kernel_service::StoreBootstrapHandoff {
            requirement: requirement.clone(),
            process_binding: receipt.process_binding.clone(),
        }))
    }
}

impl KernelComposition {
    /// Monotonic revision of the promoted bridge profile. The production
    /// listener uses this to rebuild a pending pipe after Host activation
    /// changes the bounded DACL/peer set.
    #[cfg(windows)]
    #[must_use]
    pub fn agent_bridge_peer_set_revision(&self) -> u64 {
        self.agent_bridge_peer_set_revision.load(Ordering::Acquire)
    }

    /// Waits for a real peer-set change without cancelling an in-flight pipe
    /// authentication. The revision check before and after registration makes
    /// the notification lost-wake safe.
    #[cfg(windows)]
    pub async fn wait_for_agent_bridge_peer_set_revision(&self, observed: u64) -> u64 {
        loop {
            let current = self.agent_bridge_peer_set_revision();
            if current != observed {
                return current;
            }
            let notified = self.agent_bridge_peer_set_changed.notified();
            if self.agent_bridge_peer_set_revision() != observed {
                return self.agent_bridge_peer_set_revision();
            }
            notified.await;
        }
    }

    #[cfg(windows)]
    fn note_agent_bridge_peer_set_change(&self) {
        self.agent_bridge_peer_set_revision
            .fetch_add(1, Ordering::AcqRel);
        // `notify_one` retains a permit if the listener changes state in the
        // check-to-await gap; `notify_waiters` would lose that wake.
        self.agent_bridge_peer_set_changed.notify_one();
    }

    #[cfg(windows)]
    async fn fence_store_rebind_runtime(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        if let Ok(mut service) = self.service.lock() {
            let _ = service.fence_generation(reason);
        }
        gateway.fence();
        let old = self
            .canonical_store_gateway
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        if let Some(old) = old
            && !Arc::ptr_eq(&old, gateway)
        {
            let _ = old.fence_and_drain(Duration::from_secs(5)).await;
        }
    }

    #[cfg(windows)]
    fn commit_store_rebind_attachment<'a>(
        attachment: &mut Option<Box<dyn CanonicalStoreAttachmentTransaction + 'a>>,
    ) {
        if let Some(attachment) = attachment.take() {
            attachment.commit();
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "single ordered Store rebind transaction"
    )]
    async fn rebind_store(
        &self,
        handoff: eliot_kernel_service::StoreRebindHandoff,
        request_digest: String,
    ) -> Result<eliot_kernel_service::StoreRebindReceipt, KernelBuildError> {
        handoff
            .validate()
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
        handoff
            .validate_canonical_digest()
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
        if request_digest != handoff.request_digest {
            return Err(KernelBuildError::Service(
                "Store rebind request digest must equal canonical handoff digest".to_owned(),
            ));
        }
        if self.store_bootstrap.as_ref() != Some(&handoff.requirement) {
            return Err(KernelBuildError::Service(
                "Store rebind requirement is not the immutable bootstrap descriptor".to_owned(),
            ));
        }
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelBuildError::Service(
                "Store rebind outer digest invalid".to_owned(),
            ));
        }
        let expected_fence = {
            let mut hasher = Sha256::new();
            hasher.update(
                serde_json::to_vec(&handoff.requirement.state_fence)
                    .map_err(|e| KernelBuildError::Service(e.to_string()))?,
            );
            hasher.update(handoff.generation.value().to_le_bytes());
            hasher.update(handoff.authority_epoch.value().to_le_bytes());
            hasher.update(
                handoff
                    .requirement
                    .approved_artifact_hash
                    .as_str()
                    .as_bytes(),
            );
            hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
            hasher.update(handoff.process_binding.process.process_id.to_le_bytes());
            hasher.update(
                handoff
                    .process_binding
                    .process
                    .start_time_100ns
                    .to_le_bytes(),
            );
            hasher.update(handoff.process_binding.process.image_path.as_bytes());
            hasher.update(handoff.process_binding.job.as_str().as_bytes());
            hasher.update(handoff.candidate_binding_digest.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        if expected_fence != handoff.store_fence {
            return Err(KernelBuildError::Service(
                "Store rebind fence does not bind fresh peer evidence".to_owned(),
            ));
        }
        let observed = observe_named_pipe_peer_process_in_job(
            handoff.process_binding.job.as_str(),
            handoff.process_binding.process.process_id,
        )
        .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        let observed_binding = observed.process_binding();
        if observed_binding.process_id() != handoff.process_binding.process.process_id
            || observed_binding.start_time_100ns()
                != handoff.process_binding.process.start_time_100ns
            || observed_binding.image_path() != handoff.process_binding.process.image_path
        {
            return Err(KernelBuildError::Principal(
                "Store rebind process binding does not match observed Job peer".to_owned(),
            ));
        }
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_with_process_and_job_binding(
                handoff.requirement.expected_peer_sid.as_str(),
                handoff.requirement.expected_peer_session_id,
                observed,
            )
            .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        let _ = expectation;
        let timeout = Duration::from_millis(handoff.requirement.timeout_ms());
        let requirement = handoff.requirement.clone();
        let job = handoff.process_binding.job.clone();
        let process = handoff.process_binding.process.clone();
        let observed2 = observe_named_pipe_peer_process_in_job(job.as_str(), process.process_id)
            .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        if observed2.process_binding().process_id() != process.process_id
            || observed2.process_binding().start_time_100ns() != process.start_time_100ns
            || observed2.process_binding().image_path() != process.image_path
        {
            return Err(KernelBuildError::Principal(
                "Store rebind second observation mismatch".to_owned(),
            ));
        }
        let expectation2 =
            eliot_platform_windows::NamedPipePeerExpectation::new_with_process_and_job_binding(
                requirement.expected_peer_sid.as_str(),
                requirement.expected_peer_session_id,
                observed2,
            )
            .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        let transport = eliot_ipc::NamedPipeTransport::connect_authenticated(
            requirement.canonical_pipe_identity.as_str(),
            timeout,
            &expectation2,
        )
        .await
        .map_err(KernelBuildError::Transport)?;
        let client =
            eliot_kernel_service::EbpCanonicalStoreClient::connect(transport, requirement.clone())
                .await
                .map_err(|e| match e {
                    eliot_kernel_service::StoreClientError::Transport(e)
                    | eliot_kernel_service::StoreClientError::Contract(e) => {
                        KernelBuildError::Service(e)
                    }
                    eliot_kernel_service::StoreClientError::Store(e) => {
                        KernelBuildError::Service(e.to_string())
                    }
                })?;
        let route_scope = eliot_kernel_core::RouteScope::new(STORE_BRIDGE_ROUTE)
            .map_err(|e| KernelBuildError::Core(e.to_string()))?;
        let routes = self
            .generation_route_snapshot()
            .map_err(|e| KernelBuildError::Core(e.to_string()))?;
        let route = routes
            .route(&route_scope)
            .map_err(|e| KernelBuildError::Core(e.to_string()))?
            .clone();
        if route.authority_epoch() != requirement.authority_epoch()
            || route.active_generation() != requirement.store_generation
            || requirement.route_identity.as_str() != STORE_BRIDGE_ROUTE
        {
            return Err(KernelBuildError::Core(
                "store rebind does not match active Kernel store route".to_owned(),
            ));
        }
        let requirement_digest = {
            let bytes = serde_json::to_vec(&handoff.requirement)
                .map_err(|e| KernelBuildError::Service(e.to_string()))?;
            format!("{:x}", Sha256::digest(&bytes))
        };
        let operation = eliot_ors::OperationIdentity::new(handoff.operation_id.as_str())
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
        let durable_replay = if let Some(existing) = self
            .generation_gateway
            .ors
            .load_store_rebind(&operation, &request_digest)
            .map_err(|e| KernelBuildError::Service(e.to_string()))?
        {
            if store_rebind_record_is_committed(
                &existing,
                &handoff,
                &request_digest,
                &requirement_digest,
            ) {
                if !is_store_rebind_latest_committed(&self.generation_gateway.ors, &existing)
                    .map_err(|e| KernelBuildError::Service(e.to_string()))?
                {
                    return Err(KernelBuildError::Service(
                        "Store rebind superseded by newer durable commit".to_owned(),
                    ));
                }
                Some(store_rebind_receipt_from_ors_record(&existing)?)
            } else {
                if !store_rebind_record_matches(
                    &existing,
                    &handoff,
                    &request_digest,
                    &requirement_digest,
                ) {
                    return Err(KernelBuildError::Service(
                        "existing store rebind conflicts".to_owned(),
                    ));
                }
                None
            }
        } else {
            None
        };
        // A durable exact commit is the idempotence source of truth.  Check
        // it before requiring the volatile service to be Ready so a replay
        // after Kernel publication loss can recover from ORS rather than
        // treating the in-memory Degraded state as a conflicting operation.
        {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if service.state() != eliot_kernel_service::KernelServiceState::Ready
                && !(durable_replay.is_some()
                    && service.state() == eliot_kernel_service::KernelServiceState::Degraded)
            {
                return Err(KernelBuildError::Service(
                    "Store rebind requires Ready Kernel".to_owned(),
                ));
            }
            let candidate = service
                .candidate_binding()
                .ok_or(KernelBuildError::Service(
                    "Store rebind missing candidate".to_owned(),
                ))?;
            let expected = candidate
                .compute_digest()
                .map_err(|e| KernelBuildError::Service(e.to_string()))?;
            if expected != handoff.candidate_binding_digest {
                return Err(KernelBuildError::Service(
                    "Store rebind candidate binding mismatch".to_owned(),
                ));
            }
        }
        let gateway = std::sync::Arc::new(KernelStoreGateway::new(
            self.service.clone(),
            std::sync::Arc::new(client),
            route.clone(),
        ));
        let receipt = {
            let mut svc = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if durable_replay.is_none()
                && svc.state() != eliot_kernel_service::KernelServiceState::Ready
            {
                return Err(KernelBuildError::Service(
                    "Store rebind requires Ready Kernel (fence recheck)".to_owned(),
                ));
            }
            if svc.candidate_binding().is_some_and(|c| {
                c.compute_digest()
                    .is_ok_and(|d| d != handoff.candidate_binding_digest)
            }) {
                return Err(KernelBuildError::Service(
                    "Store rebind candidate binding mismatch (fence recheck)".to_owned(),
                ));
            }
            if let Some(restored) = durable_replay.clone() {
                svc.restore_store_rebind_for_replay(restored.clone(), request_digest.clone())
                    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
                restored
            } else {
                svc.rebind_store(&handoff, request_digest.clone())
                    .map_err(|error| KernelBuildError::Service(error.to_string()))
                    .inspect_err(|_| gateway.fence())?
            }
        };
        // Close service admission before exposing the replacement gateway.
        // This ordering is the no-dual-writer fence: the old gateway remains
        // retained but cannot admit new work while ORS is being finalized.
        let attachment_result: Result<
            Box<dyn CanonicalStoreAttachmentTransaction>,
            KernelBuildError,
        > = self
            .process_gateway
            .as_ref()
            .map_or_else(
                || {
                    struct NoopAttachment;
                    impl CanonicalStoreAttachmentTransaction for NoopAttachment {
                        fn commit(self: Box<Self>) {}
                    }
                    Ok(Box::new(NoopAttachment) as Box<dyn CanonicalStoreAttachmentTransaction>)
                },
                |pg| {
                    pg.replace_canonical_store(Arc::clone(&gateway))
                        .map(|a| Box::new(a) as Box<dyn CanonicalStoreAttachmentTransaction>)
                        .map_err(|e| KernelBuildError::Service(e.to_string()))
                },
            )
            .inspect_err(|_| gateway.fence());
        let mut attachment = Some(match attachment_result {
            Ok(attachment) => attachment,
            Err(error) => {
                let mut service = self
                    .service
                    .lock()
                    .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
                service.rollback_store_rebind_for_recovery_failure();
                return Err(error);
            }
        });
        if durable_replay.is_none() {
            let pending = eliot_ors::StoreRebindReplayRecord {
                operation_id: operation.clone(),
                request_digest: request_digest.clone(),
                candidate_binding_digest: handoff.candidate_binding_digest.clone(),
                store_fence: handoff.store_fence.clone(),
                requirement_digest: requirement_digest.clone(),
                process_id: handoff.process_binding.process.process_id,
                process_start_time_100ns: handoff.process_binding.process.start_time_100ns,
                process_image_path: handoff.process_binding.process.image_path.clone(),
                job_name: handoff.process_binding.job.as_str().to_owned(),
                generation: handoff.generation.value(),
                authority_epoch: handoff.authority_epoch.value(),
                state: eliot_ors::StoreRebindReplayState::Pending,
                receipt: None,
                commit_order: 0,
            };
            let begin_result = self.generation_gateway.ors.begin_store_rebind(&pending);
            if let Err(begin_error) = begin_result {
                let reconciled = self
                    .generation_gateway
                    .ors
                    .load_store_rebind(&operation, &request_digest);
                match reconciled {
                    Ok(Some(record))
                        if store_rebind_record_is_committed(
                            &record,
                            &handoff,
                            &request_digest,
                            &requirement_digest,
                        ) => {}
                    Ok(Some(record))
                        if store_rebind_record_is_pending(
                            &record,
                            &handoff,
                            &request_digest,
                            &requirement_digest,
                        ) =>
                    {
                        match self
                            .generation_gateway
                            .ors
                            .abort_store_rebind(&operation, &request_digest)
                        {
                            Ok(_) => {
                                let after_abort = match self
                                    .generation_gateway
                                    .ors
                                    .load_store_rebind(&operation, &request_digest)
                                {
                                    Ok(after_abort) => after_abort,
                                    Err(readback_error) => {
                                        Self::commit_store_rebind_attachment(&mut attachment);
                                        self.fence_store_rebind_runtime(
                                            &gateway,
                                            format!(
                                                "Store rebind abort readback failed: {readback_error}"
                                            ),
                                        )
                                        .await;
                                        return Err(KernelBuildError::Service(format!(
                                            "Store rebind begin outcome is uncertain after abort: {begin_error}; abort readback: {readback_error}"
                                        )));
                                    }
                                };
                                match after_abort {
                                    None => {
                                        let mut service = self.service.lock().map_err(|_| {
                                            KernelBuildError::Service(
                                                "service lock poisoned".to_owned(),
                                            )
                                        })?;
                                        service.rollback_store_rebind_for_recovery_failure();
                                        return Err(KernelBuildError::Service(
                                            begin_error.to_string(),
                                        ));
                                    }
                                    Some(record)
                                        if store_rebind_record_is_committed(
                                            &record,
                                            &handoff,
                                            &request_digest,
                                            &requirement_digest,
                                        ) => {}
                                    Some(_) => {
                                        Self::commit_store_rebind_attachment(&mut attachment);
                                        self.fence_store_rebind_runtime(
                                        &gateway,
                                        format!(
                                            "Store rebind begin abort remained durable: {begin_error}"
                                        ),
                                    )
                                    .await;
                                        return Err(KernelBuildError::Service(format!(
                                            "Store rebind begin outcome is uncertain after abort: {begin_error}"
                                        )));
                                    }
                                }
                            }
                            Err(abort_error) => {
                                Self::commit_store_rebind_attachment(&mut attachment);
                                self.fence_store_rebind_runtime(
                                &gateway,
                                format!(
                                    "Store rebind begin abort failed ({begin_error}): {abort_error}"
                                ),
                            )
                            .await;
                                return Err(KernelBuildError::Service(format!(
                                    "Store rebind begin outcome is uncertain: {begin_error}; abort: {abort_error}"
                                )));
                            }
                        }
                    }
                    Ok(None) => {
                        let mut service = self.service.lock().map_err(|_| {
                            KernelBuildError::Service("service lock poisoned".to_owned())
                        })?;
                        service.rollback_store_rebind_for_recovery_failure();
                        return Err(KernelBuildError::Service(begin_error.to_string()));
                    }
                    Ok(Some(record)) => {
                        Self::commit_store_rebind_attachment(&mut attachment);
                        self.fence_store_rebind_runtime(
                            &gateway,
                            format!(
                                "Store rebind begin readback conflicted for {}",
                                record.operation_id.as_str()
                            ),
                        )
                        .await;
                        return Err(KernelBuildError::Service(
                            "Store rebind begin readback conflicted".to_owned(),
                        ));
                    }
                    Err(readback_error) => {
                        Self::commit_store_rebind_attachment(&mut attachment);
                        self.fence_store_rebind_runtime(
                            &gateway,
                            format!(
                                "Store rebind begin readback failed ({begin_error}): {readback_error}"
                            ),
                        )
                        .await;
                        return Err(KernelBuildError::Service(format!(
                            "Store rebind begin outcome is uncertain: {begin_error}; readback: {readback_error}"
                        )));
                    }
                }
            }
        }
        let committed_result = {
            let committed = eliot_ors::StoreRebindReplayRecord {
                operation_id: operation.clone(),
                request_digest: request_digest.clone(),
                candidate_binding_digest: handoff.candidate_binding_digest.clone(),
                store_fence: handoff.store_fence.clone(),
                requirement_digest: requirement_digest.clone(),
                process_id: handoff.process_binding.process.process_id,
                process_start_time_100ns: handoff.process_binding.process.start_time_100ns,
                process_image_path: handoff.process_binding.process.image_path.clone(),
                job_name: handoff.process_binding.job.as_str().to_owned(),
                generation: handoff.generation.value(),
                authority_epoch: handoff.authority_epoch.value(),
                state: eliot_ors::StoreRebindReplayState::Committed,
                receipt: Some(receipt.request_digest.clone()),
                commit_order: 0,
            };
            self.generation_gateway
                .ors
                .persist_store_rebind(&committed)
                .map_err(|error| KernelBuildError::Service(error.to_string()))
        };
        if let Err(error) = committed_result {
            let readback = self
                .generation_gateway
                .ors
                .load_store_rebind(&operation, &request_digest);
            match readback {
                Ok(Some(record))
                    if store_rebind_record_is_committed(
                        &record,
                        &handoff,
                        &request_digest,
                        &requirement_digest,
                    ) => {}
                Ok(Some(record))
                    if store_rebind_record_is_pending(
                        &record,
                        &handoff,
                        &request_digest,
                        &requirement_digest,
                    ) =>
                {
                    match self
                        .generation_gateway
                        .ors
                        .abort_store_rebind(&operation, &request_digest)
                    {
                        Ok(_) => {
                            let after_abort = self
                                .generation_gateway
                                .ors
                                .load_store_rebind(&operation, &request_digest);
                            match after_abort {
                                Ok(None) => {
                                    let mut service = self.service.lock().map_err(|_| {
                                        KernelBuildError::Service(
                                            "service lock poisoned".to_owned(),
                                        )
                                    })?;
                                    service.rollback_store_rebind_for_recovery_failure();
                                    return Err(error);
                                }
                                Ok(Some(after))
                                    if store_rebind_record_is_committed(
                                        &after,
                                        &handoff,
                                        &request_digest,
                                        &requirement_digest,
                                    ) => {}
                                Ok(Some(_)) => {
                                    Self::commit_store_rebind_attachment(&mut attachment);
                                    self.fence_store_rebind_runtime(
                                        &gateway,
                                        "Store rebind commit abort readback remained non-terminal",
                                    )
                                    .await;
                                    return Err(KernelBuildError::Service(
                                        "Store rebind commit outcome is uncertain after abort"
                                            .to_owned(),
                                    ));
                                }
                                Err(readback_error) => {
                                    Self::commit_store_rebind_attachment(&mut attachment);
                                    self.fence_store_rebind_runtime(
                                    &gateway,
                                    format!(
                                        "Store rebind commit abort readback failed: {readback_error}"
                                    ),
                                )
                                .await;
                                    return Err(KernelBuildError::Service(format!(
                                        "Store rebind commit outcome is uncertain: {error}; abort readback: {readback_error}"
                                    )));
                                }
                            }
                        }
                        Err(abort_error) => {
                            Self::commit_store_rebind_attachment(&mut attachment);
                            self.fence_store_rebind_runtime(
                                &gateway,
                                format!(
                                    "Store rebind commit abort failed ({error}): {abort_error}"
                                ),
                            )
                            .await;
                            return Err(KernelBuildError::Service(format!(
                                "Store rebind commit outcome is uncertain: {error}; abort: {abort_error}"
                            )));
                        }
                    }
                }
                Ok(None) => {
                    let mut service = self.service.lock().map_err(|_| {
                        KernelBuildError::Service("service lock poisoned".to_owned())
                    })?;
                    service.rollback_store_rebind_for_recovery_failure();
                    return Err(error);
                }
                Ok(Some(record)) => {
                    Self::commit_store_rebind_attachment(&mut attachment);
                    self.fence_store_rebind_runtime(
                        &gateway,
                        format!(
                            "Store rebind commit readback conflicted for {}",
                            record.operation_id.as_str()
                        ),
                    )
                    .await;
                    return Err(KernelBuildError::Service(
                        "Store rebind commit readback conflicted".to_owned(),
                    ));
                }
                Err(readback_error) => {
                    Self::commit_store_rebind_attachment(&mut attachment);
                    self.fence_store_rebind_runtime(
                        &gateway,
                        format!("Store rebind commit readback failed ({error}): {readback_error}"),
                    )
                    .await;
                    return Err(KernelBuildError::Service(format!(
                        "Store rebind commit outcome is uncertain: {error}; readback: {readback_error}"
                    )));
                }
            }
        }
        let service_commit_error = self
            .service
            .lock()
            .map(|mut service| {
                service
                    .commit_store_rebind()
                    .err()
                    .map(|error| error.to_string())
            })
            .map_err(|_| {
                KernelBuildError::Service("service lock poisoned after ORS commit".to_owned())
            });
        let service_commit_error = match service_commit_error {
            Ok(error) => error,
            Err(error) => {
                Self::commit_store_rebind_attachment(&mut attachment);
                self.fence_store_rebind_runtime(
                    &gateway,
                    "Store rebind service lock poisoned after ORS commit",
                )
                .await;
                return Err(error);
            }
        };
        if let Some(error) = service_commit_error {
            Self::commit_store_rebind_attachment(&mut attachment);
            self.fence_store_rebind_runtime(
                &gateway,
                format!("Store rebind service commit publication failed: {error}"),
            )
            .await;
            return Err(KernelBuildError::Service(error));
        }
        let old_gateway_for_drain = self
            .canonical_store_gateway
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        if let Some(old) = old_gateway_for_drain
            && !Arc::ptr_eq(&old, &gateway)
            && let Err(error) = old.fence_and_drain(Duration::from_secs(5)).await
        {
            Self::commit_store_rebind_attachment(&mut attachment);
            self.fence_store_rebind_runtime(
                &gateway,
                format!("Store rebind old gateway drain failed: {error}"),
            )
            .await;
            return Err(KernelBuildError::Service(format!(
                "Store rebind old gateway drain failed: {error}"
            )));
        }
        let old_gateway = match (|| {
            let mut gw_guard = self
                .canonical_store_gateway
                .lock()
                .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?;
            let mut handoff_guard = self
                .store_handoff
                .lock()
                .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?;
            let old = gw_guard.replace(Arc::clone(&gateway));
            *handoff_guard = Some(eliot_kernel_service::StoreBootstrapHandoff {
                requirement: handoff.requirement.clone(),
                process_binding: handoff.process_binding.clone(),
            });
            Ok::<Option<Arc<KernelStoreGateway>>, KernelBuildError>(old)
        })() {
            Ok(old) => old,
            Err(error) => {
                Self::commit_store_rebind_attachment(&mut attachment);
                let mut svc = self
                    .service
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = svc.fence_generation(format!("store rebind composition fenced: {error}"));
                gateway.fence();
                return Err(error);
            }
        };
        Self::commit_store_rebind_attachment(&mut attachment);
        if let Some(old) = old_gateway {
            old.fence();
        }
        Ok(receipt)
    }

    /// Returns whether Host/installation authority bindings were injected.
    /// The normal composition is intentionally not process-ready.
    #[must_use]
    pub fn process_execution_configured(&self) -> bool {
        self.process_gateway.is_some()
    }

    /// Returns the immutable approved child contour, if integrated startup
    /// supplied one.  Absence is an integration error, not a permission to
    /// infer a sibling executable.
    #[must_use]
    pub fn daemon_launch(&self) -> Option<&EliotdLaunchDescriptor> {
        self.daemon_launch.as_ref()
    }

    /// Returns the protected supervision authority only when Host injected a
    /// complete key reference and installation trust anchor.
    #[cfg(windows)]
    #[must_use]
    pub fn supervision_lease_authority(&self) -> Option<&KernelSupervisionLeaseAuthority> {
        self.supervision_lease_authority.as_deref()
    }

    fn active_daemon_launch(&self) -> Result<Option<EliotdLaunchDescriptor>, KernelServiceError> {
        self.daemon_active_launch
            .lock()
            .map(|launch| launch.clone())
            .map_err(|_| KernelServiceError::Platform("daemon launch lock poisoned".to_owned()))
    }

    /// Launches the approved `eliotd` through the existing Kernel process
    /// authority.  Store bootstrap must already be connected; the child is
    /// never spawned from a raw command or an ambient environment.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the launch admission sequence is intentionally contiguous so every authority check precedes the single process start"
    )]
    pub async fn launch_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        launch
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let gateway = self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required before eliotd launch".to_owned(),
            )
        })?;
        {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_some() {
                return Err(KernelBuildError::Service(
                    "eliotd launch was already admitted for this Kernel generation".to_owned(),
                ));
            }
        }
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let launch_identity = eliotd_launch_attempt_identity(
            &launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )?;
        let operation_id = eliotd_operation_id(generation, &launch_identity)?;
        let process_tree_id = ProcessTreeId::new(format!("eliotd-tree-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let job_id = JobId::new(format!("eliotd-job-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let image_id = ImageId::new(format!("eliotd-image-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let session_id = SessionId::new(format!("eliotd-session-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let arguments = launch
            .arguments
            .iter()
            .map(|argument| argument.as_str().to_owned())
            .collect::<Vec<_>>();
        let intent = ProcessIntent::new(
            operation_id.clone(),
            process_tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            launch.executable.as_str(),
            launch.executable_sha256.clone(),
            arguments,
            launch.working_directory.as_str(),
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            ResourceLimits::new(86_400_000, None, None, 64 * 1024, 64 * 1024, 4)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let state_fence = FencingToken::new(
            launch.authority_epoch.value(),
            generation,
            format!("eliotd-launch-fence-{launch_identity}"),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let admission = ProcessExecutionAdmissionRequest::new(
            ACTIVE_DAEMON_CALLER,
            intent,
            ActionLeaseRef::new(format!("eliotd-kernel-launch-{launch_identity}"))
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            state_fence,
            unix_ms().saturating_add(60_000),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_expectation = current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let owner = ProcessOwnerBinding::new(
            ACTIVE_DAEMON_CALLER,
            stable_owner_principal_digest(
                kernel_expectation.expected_sid(),
                ACTIVE_DAEMON_CALLER,
                launch.authority_epoch.value(),
                generation,
            ),
            launch.authority_epoch.value(),
            generation,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let proof = Self::retain_eliotd_path_proof(&launch, &admission)?;
        {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_some() || state.status != DaemonRuntimeStatus::NotLaunched {
                return Err(KernelBuildError::Service(
                    "eliotd launch state changed before process resume".to_owned(),
                ));
            }
            state.status = DaemonRuntimeStatus::Launching;
            state.supervision = None;
            state.live_ready = None;
        }
        let receipt = match gateway.start(&owner, admission, proof).await {
            Ok(receipt) => receipt,
            Err(error) => {
                let reason = format!("eliotd process start failed: {error}");
                let unknown_outcome = matches!(&error, ProcessExecutionError::UnknownOutcome);
                let _ = self.record_daemon_failed(&reason, unknown_outcome);
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelBuildError::Service("daemon runtime lock poisoned".to_owned()))?;
        state.status = DaemonRuntimeStatus::Running;
        state.receipt = Some(receipt.clone());
        drop(state);
        self.note_agent_bridge_peer_set_change();
        Ok(receipt)
    }

    #[cfg(windows)]
    fn retain_eliotd_path_proof(
        launch: &EliotdLaunchDescriptor,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> Result<ProcessPathProof, KernelBuildError> {
        let executable = PathBuf::from(launch.executable.as_str());
        let working_directory = PathBuf::from(launch.working_directory.as_str());
        let daemon_platform =
            WindowsPlatform::new(working_directory.clone()).map_err(KernelBuildError::Platform)?;
        let lease = daemon_platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .map_err(KernelBuildError::Platform)?;
        Ok(ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        })
    }

    /// Returns whether `eliotd` has completed its authenticated ready report.
    #[must_use]
    pub fn daemon_ready(&self) -> bool {
        self.daemon_runtime
            .lock()
            .is_ok_and(|state| daemon_status_proves_ready(&state.status))
    }

    #[cfg(windows)]
    async fn await_daemon_ready(
        &self,
        launched: &ProcessStartReceipt,
        timeout: Duration,
    ) -> Result<(), KernelBuildError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.daemon_status_changed.notified();
            {
                let state = self.daemon_runtime.lock().map_err(|_| {
                    KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
                })?;
                if state.receipt.as_ref() != Some(launched) {
                    return Err(KernelBuildError::Service(
                        "eliotd readiness is not bound to the exact launched process receipt"
                            .to_owned(),
                    ));
                }
                match &state.status {
                    DaemonRuntimeStatus::Ready => return Ok(()),
                    DaemonRuntimeStatus::Running => {}
                    DaemonRuntimeStatus::Degraded(reason) => {
                        return Err(KernelBuildError::Service(format!(
                            "eliotd degraded before authenticated readiness: {reason}"
                        )));
                    }
                    DaemonRuntimeStatus::Failed(reason) => {
                        return Err(KernelBuildError::Service(format!(
                            "eliotd failed before authenticated readiness: {reason}"
                        )));
                    }
                    DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Launching => {
                        return Err(KernelBuildError::Service(
                            "eliotd readiness wait has no launched process".to_owned(),
                        ));
                    }
                }
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                let reason = format!(
                    "eliotd did not complete authenticated Governor recovery and report_ready within {} ms",
                    timeout.as_millis()
                );
                let _ = self.mark_daemon_failed(reason.clone());
                return Err(KernelBuildError::Service(reason));
            }
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "recovery closure keeps exact disposition inspection and terminal proof ordered"
    )]
    async fn close_previous_daemon_process(
        &self,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
    ) -> Result<(), KernelBuildError> {
        let gateway = self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required for eliotd recovery".to_owned(),
            )
        })?;
        receipt
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let launch_identity = eliotd_launch_attempt_identity(
            launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )?;
        let expected_operation = eliotd_operation_id(generation, &launch_identity)?;
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation().get() != launch.generation.value()
            || receipt.binding().state_fence().authority_epoch() != launch.authority_epoch.value()
            || receipt.binding().state_fence().generation() != generation
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || !receipt
                .identity()
                .physical()
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            return Err(KernelBuildError::Service(
                "eliotd recovery refused a stale or substituted process receipt".to_owned(),
            ));
        }
        let kernel_expectation = current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let owner = ProcessOwnerBinding::new(
            ACTIVE_DAEMON_CALLER,
            stable_owner_principal_digest(
                kernel_expectation.expected_sid(),
                ACTIVE_DAEMON_CALLER,
                launch.authority_epoch.value(),
                generation,
            ),
            launch.authority_epoch.value(),
            generation,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let view = match gateway
            .inspect(&owner, receipt.operation_id().clone())
            .await
        {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => return Err(KernelBuildError::Service(error.to_string())),
        };
        if view.binding() != receipt.binding() || view.identity() != Some(receipt.identity()) {
            return Err(KernelBuildError::Service(
                "eliotd previous process inspection does not match its receipt".to_owned(),
            ));
        }
        match view.lifecycle() {
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled => {
                Ok(())
            }
            ProcessLifecycle::Running => {
                let cancellation = gateway
                    .cancel(&owner, receipt.operation_id().clone())
                    .await
                    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
                if cancellation.binding() != receipt.binding() {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process cancellation binding changed".to_owned(),
                    ));
                }
                let closed = gateway
                    .inspect(&owner, receipt.operation_id().clone())
                    .await
                    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
                if closed.binding() != receipt.binding()
                    || closed.identity() != Some(receipt.identity())
                    || closed.lifecycle() != ProcessLifecycle::Exited
                    || closed.cancellation() != CancellationStatus::Completed
                    || !closed.descendants().is_some_and(|descendants| {
                        descendants.complete() && descendants.tree_terminated()
                    })
                {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process tree closure was not proven".to_owned(),
                    ));
                }
                Ok(())
            }
            ProcessLifecycle::Created
            | ProcessLifecycle::Starting
            | ProcessLifecycle::Cancelling
            | ProcessLifecycle::UnknownOutcome
            | ProcessLifecycle::Quarantined => Err(KernelBuildError::Service(
                "eliotd previous process is not in a known terminal state".to_owned(),
            )),
        }
    }

    /// Performs one Kernel-owned bounded recovery of a failed daemon
    /// attempt. The old process effect must be known terminal before the
    /// active descriptor, nonce, and operation identity are replaced.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "bounded recovery keeps disposition, fresh binding, and readiness rendezvous ordered"
    )]
    pub async fn recover_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        let _recovery_gate = self.daemon_recovery_gate.lock().await;
        let service_state = self
            .service_state()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if !probe_ready_state_admitted(service_state) {
            return Err(KernelBuildError::Service(
                "eliotd recovery requires an admitted Activating, Ready, or Degraded Kernel state"
                    .to_owned(),
            ));
        }
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        let (status, previous_receipt, recovery_fenced) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            (
                state.status.clone(),
                state.receipt.clone(),
                state.recovery_fenced,
            )
        };
        if recovery_fenced {
            return Err(KernelBuildError::Service(
                "eliotd previous process start has an unknown outcome; recovery is fenced"
                    .to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Ready) {
            if let Some(receipt) = previous_receipt {
                self.validate_daemon_process_readiness(&launch, &receipt)
                    .await
                    .map_err(|_| {
                        KernelBuildError::Service(
                            "eliotd Ready receipt is no longer physically proven".to_owned(),
                        )
                    })?;
                return Ok(receipt);
            }
            return Err(KernelBuildError::Service(
                "eliotd Ready state has no exact process receipt".to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Launching) && previous_receipt.is_none() {
            return Err(KernelBuildError::Service(
                "eliotd launch is still awaiting its process receipt".to_owned(),
            ));
        }
        let attempt = self.daemon_recovery_attempts.fetch_add(1, Ordering::AcqRel);
        if attempt >= ELIOTD_MAX_RECOVERY_ATTEMPTS {
            let reason = "eliotd bounded recovery budget is exhausted".to_owned();
            let _ = self.mark_daemon_failed(reason.clone());
            return Err(KernelBuildError::Service(reason));
        }
        if let Some(receipt) = previous_receipt.as_ref() {
            if let Err(error) = self.close_previous_daemon_process(&launch, receipt).await {
                let reason = error.to_string();
                let _ = self.mark_daemon_failed(reason.clone());
                return Err(KernelBuildError::Service(reason));
            }
        } else if !matches!(
            status,
            DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Failed(_)
        ) {
            let reason = "eliotd recovery has no exact prior process disposition".to_owned();
            let _ = self.mark_daemon_failed(reason.clone());
            return Err(KernelBuildError::Service(reason));
        }
        let next_launch = fresh_eliotd_launch_descriptor(&launch, attempt + 1)?;
        {
            let mut policy = self.front_door_policy.lock().map_err(|_| {
                KernelBuildError::Service("front-door policy lock poisoned".to_owned())
            })?;
            if policy.module_generation.generation != next_launch.generation
                || policy.module_generation.state_fence.authority_epoch
                    != next_launch.authority_epoch
            {
                return Err(KernelBuildError::Service(
                    "eliotd recovery descriptor has the wrong generation or authority".to_owned(),
                ));
            }
            next_launch
                .launch_nonce
                .as_str()
                .clone_into(&mut policy.launch_nonce);
        }
        *self
            .daemon_active_launch
            .lock()
            .map_err(|_| KernelBuildError::Service("daemon launch lock poisoned".to_owned()))? =
            Some(next_launch);
        {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            state.status = DaemonRuntimeStatus::NotLaunched;
            state.receipt = None;
            state.recovery_fenced = false;
            state.supervision = None;
            state.live_ready = None;
        }
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        let launched = match self.launch_eliotd().await {
            Ok(receipt) => receipt,
            Err(error) => {
                let reason = error.to_string();
                let _ = self.mark_daemon_failed(reason.clone());
                return Err(KernelBuildError::Service(reason));
            }
        };
        if let Err(error) = self
            .await_daemon_ready(&launched, self.ipc_limits().operation_timeout)
            .await
        {
            let reason = error.to_string();
            let _ = self.mark_daemon_failed(reason.clone());
            return Err(KernelBuildError::Service(reason));
        }
        Ok(launched)
    }

    #[cfg(windows)]
    async fn ensure_daemon_ready_for_probe(
        &self,
    ) -> Result<ProcessStartReceipt, KernelServiceError> {
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let (status, receipt) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            (state.status.clone(), state.receipt.clone())
        };
        if let Some(receipt) = receipt.as_ref() {
            if status == DaemonRuntimeStatus::Ready {
                if self
                    .validate_daemon_process_readiness(&launch, receipt)
                    .await
                    .is_ok()
                {
                    return Ok(receipt.clone());
                }
            } else if status == DaemonRuntimeStatus::Running
                && self
                    .await_daemon_ready(receipt, self.ipc_limits().operation_timeout)
                    .await
                    .is_ok()
            {
                self.validate_daemon_process_readiness(&launch, receipt)
                    .await?;
                return Ok(receipt.clone());
            }
        }
        let recovered = self
            .recover_eliotd()
            .await
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let current_launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        self.validate_daemon_process_readiness(&current_launch, &recovered)
            .await?;
        Ok(recovered)
    }

    /// Records an authenticated daemon-ready report after generation checks
    /// have been performed by the front-door dispatcher.
    pub fn mark_daemon_ready(&self) -> Result<(), KernelServiceError> {
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        #[cfg(windows)]
        if state.receipt.is_some()
            && state.status == DaemonRuntimeStatus::Ready
            && state.supervision.is_some()
        {
            return Ok(());
        }
        #[cfg(windows)]
        if state.supervision.is_none() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Ready;
        drop(state);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        Ok(())
    }

    /// Records a bounded authenticated daemon degradation.
    pub fn mark_daemon_degraded(&self, reason: String) -> Result<(), KernelServiceError> {
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        if state.receipt.is_none() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Degraded(reason);
        drop(state);
        #[cfg(windows)]
        let _ = self.promote_agent_bridge_profile(None);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        Ok(())
    }

    /// Records a bounded authenticated daemon fatal disposition and closes
    /// normal admission without fencing the generation. Kernel remains the
    /// sole lifecycle owner and may consume its one fresh recovery attempt.
    pub fn mark_daemon_failed(&self, reason: impl Into<String>) -> Result<(), KernelServiceError> {
        let reason = reason.into();
        self.record_daemon_failed(&reason, false)
    }

    fn record_daemon_failed(
        &self,
        reason: &str,
        recovery_fenced: bool,
    ) -> Result<(), KernelServiceError> {
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        state.status = DaemonRuntimeStatus::Failed(reason.to_owned());
        state.recovery_fenced |= recovery_fenced;
        #[cfg(windows)]
        {
            state.supervision = None;
            state.live_ready = None;
        }
        drop(state);
        #[cfg(windows)]
        let _ = self.promote_agent_bridge_profile(None);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        let mut service = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
        if matches!(
            service.state(),
            KernelServiceState::Activating
                | KernelServiceState::Ready
                | KernelServiceState::Degraded
        ) {
            let reason_handle =
                PlatformHandle::new(format!("eliotd-failed:{}", sha256_hex(reason.as_bytes())))
                    .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
            service.apply(KernelControlCommand::Degrade(reason_handle))?;
        }
        Ok(())
    }

    /// Returns the platform surface owned by this composition.
    #[must_use]
    pub fn platform(&self) -> &WindowsPlatform {
        &self.platform
    }

    /// Reports whether the exact bounded peer-set selection and Host-approved
    /// bridge profile admit this authenticated OS peer. A positive result is
    /// transport admission only; it does not create a semantic Session or
    /// principal.
    #[cfg(windows)]
    pub fn agent_bridge_peer_admitted(
        &self,
        selection: &NamedPipePeerSelection,
        peer: &PeerIdentity,
    ) -> bool {
        self.agent_bridge_profile
            .lock()
            .ok()
            .and_then(|profile| profile.clone())
            .is_some_and(|profile| {
                selection.kind() == NamedPipePeerKind::AgentBridge
                    && selection.module_id() == AGENT_BRIDGE_MODULE_ID
                    && selection.profile_id() == Some(profile.admission.profile_id.as_str())
                    && Self::validate_agent_bridge_peer(&profile.admission, peer).is_ok()
            })
    }

    #[cfg(windows)]
    fn validate_agent_bridge_peer(
        admission: &AgentBridgeAdmissionDescriptor,
        peer: &PeerIdentity,
    ) -> Result<(), TransportError> {
        admission
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let PeerIdentity::Authenticated {
            user_identity,
            session_identity,
            ..
        } = peer
        else {
            return Err(TransportError::PeerIdentityUnavailable);
        };
        if user_identity != &admission.approved_user_sid {
            return Err(TransportError::SessionFenced);
        }
        let session_id = session_identity
            .parse::<u32>()
            .map_err(|_| TransportError::SessionFenced)?;
        if session_id == 0 {
            return Err(TransportError::SessionFenced);
        }
        match admission.process_policy {
            eliot_kernel_service::AgentBridgeProcessPolicy::ExactProcessPerConnection => {}
        }
        let process = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if !process
            .image_path()
            .eq_ignore_ascii_case(admission.executable.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        let (volume_serial_number, file_index) = process
            .executable_file_identity()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if volume_serial_number != admission.executable_identity.volume_serial_number
            || file_index != admission.executable_identity.file_index
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Validates and materializes the exact protected declaration before the
    /// enclosing Host activation mutates service state.
    #[cfg(windows)]
    fn prepare_agent_bridge_admission(
        admission: Option<&AgentBridgeAdmissionDescriptor>,
    ) -> Result<Option<AgentBridgeProfile>, TransportError> {
        admission
            .as_ref()
            .map(|admission| -> Result<AgentBridgeProfile, TransportError> {
                admission
                    .validate()
                    .map_err(|_| TransportError::SessionFenced)?;
                Ok(AgentBridgeProfile {
                    admission: (*admission).clone(),
                    declaration: load_agent_bridge_declaration(admission)
                        .map_err(|_| TransportError::SessionFenced)?,
                })
            })
            .transpose()
    }

    /// Atomically replaces the live bridge profile after the enclosing Host
    /// activation succeeds. Replacing or removing a profile revokes every
    /// pending connection from the previous activation lineage.
    #[cfg(windows)]
    fn promote_agent_bridge_profile(
        &self,
        next: Option<AgentBridgeProfile>,
    ) -> Result<(), TransportError> {
        self.revoke_all_agent_bridges()?;
        *self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)? = next;
        self.note_agent_bridge_peer_set_change();
        Ok(())
    }

    #[cfg(windows)]
    fn revoke_all_agent_bridges(&self) -> Result<(), TransportError> {
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        for (_, mut state) in std::mem::take(&mut *connections) {
            state.exchange.abort();
            if let Some(mut session) = state.session {
                session.fence();
            }
            state.accepted_transport = None;
        }
        if let Ok(mut pending) = self.agent_activation_pending.lock() {
            pending.fifo.clear();
            pending.entries.clear();
        } else {
            return Err(TransportError::SessionFenced);
        }
        self.agent_activation_changed.notify_waiters();
        Ok(())
    }

    #[cfg(windows)]
    fn validate_active_bridge_profile(
        &self,
        admission: &AgentBridgeAdmissionDescriptor,
    ) -> Result<(), TransportError> {
        let service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if service.state() != KernelServiceState::Ready {
            return Err(TransportError::SessionFenced);
        }
        let candidate = service
            .candidate_binding()
            .ok_or(TransportError::SessionFenced)?;
        if candidate.agent_bridge_admission.as_ref() != Some(admission) {
            return Err(TransportError::SessionFenced);
        }
        let activation = service
            .activation_receipt()
            .ok_or(TransportError::SessionFenced)?;
        if activation.generation != admission.generation
            || activation.authority_epoch != admission.authority_epoch
            || activation.candidate_binding_digest
                != candidate
                    .compute_digest()
                    .map_err(|_| TransportError::SessionFenced)?
            || admission.state_fence.resource_generation != activation.generation
            || admission.state_fence.authority_epoch != activation.authority_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Starts one server-first bridge exchange for the exact admitted peer.
    /// The returned identity and nonce are fresh and retained by Kernel until
    /// hello acceptance, timeout, disconnect, or explicit revocation.
    #[cfg(windows)]
    pub fn begin_agent_bridge(
        &self,
        selection: &NamedPipePeerSelection,
        peer: PeerIdentity,
    ) -> Result<AgentBridgeHandshake, TransportError> {
        let profile = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let admission = &profile.admission;
        self.validate_active_bridge_profile(admission)?;
        if selection.kind() != NamedPipePeerKind::AgentBridge
            || selection.module_id() != AGENT_BRIDGE_MODULE_ID
            || selection.profile_id() != Some(admission.profile_id.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        Self::validate_agent_bridge_peer(admission, &peer)?;
        let declaration = profile.declaration;
        let kernel_policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        let kernel_artifact_sha256 = kernel_policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?
            .to_owned();
        let kernel_config_snapshot_sha256 = sha256_json(&kernel_policy.config_snapshot)
            .map_err(|_| TransportError::SessionFenced)?;
        if declaration.expected_kernel_principal_binding != kernel_policy.session_principal_binding
            || declaration.expected_kernel_authority_epoch
                != kernel_policy.module_generation.state_fence.authority_epoch
            || declaration.expected_kernel_generation != kernel_policy.module_generation.generation
            || declaration.expected_kernel_artifact_sha256 != kernel_artifact_sha256
            || declaration.expected_kernel_config_snapshot_sha256 != kernel_config_snapshot_sha256
        {
            return Err(TransportError::SessionFenced);
        }
        let nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let connection_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let connection_id = format!("agent-bridge:{connection_nonce}");
        let challenge = AgentBridgePeerChallenge {
            wire_id: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: admission.profile_id.as_str().to_owned(),
            descriptor_sha256: admission.descriptor_sha256.clone(),
            client_declaration_sha256: admission.client_declaration_sha256.clone(),
            bridge_generation: admission.generation,
            state_fence: admission.state_fence.clone(),
            kernel_principal_binding: kernel_policy.session_principal_binding,
            kernel_authority_epoch: kernel_policy.module_generation.state_fence.authority_epoch,
            kernel_generation: kernel_policy.module_generation.generation,
            kernel_artifact_sha256,
            kernel_config_snapshot_sha256,
            activation_deadline_unix_ms: unix_ms()
                .saturating_add(AGENT_BRIDGE_ACTIVATION_WINDOW_MS),
            challenge_nonce: nonce,
            challenge_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        let exchange = ServerFirstConnection::new(&connection_id, challenge.clone(), &declaration)?;
        let challenge_frame = exchange.challenge_frame()?;
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if connections.contains_key(&connection_id) {
            return Err(TransportError::SessionFenced);
        }
        connections.insert(
            connection_id.clone(),
            AgentBridgeConnectionState {
                exchange,
                declaration,
                peer,
                accepted_transport: None,
                session: None,
                activation_completed: false,
            },
        );
        Ok(AgentBridgeHandshake {
            connection_id,
            challenge,
            challenge_frame,
        })
    }

    /// Accepts the one exact dynamic bridge hello and retains its immutable
    /// OS-observation receipt for the subsequent closed activation operation.
    #[cfg(windows)]
    pub fn accept_agent_bridge_hello(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<AgentBridgePeerAdmissionReceipt, TransportError> {
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let result = {
            let state = connections
                .get_mut(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            if activation_deadline_expired(
                unix_ms(),
                state.exchange.challenge().activation_deadline_unix_ms,
            ) {
                return Err(TransportError::SessionFenced);
            }
            state
                .exchange
                .accept_client_hello_with_peer(frame, &state.declaration, &state.peer)
                .map(|accepted| {
                    let receipt = accepted.admission_receipt().clone();
                    state.accepted_transport = Some(accepted);
                    receipt
                })
        };
        if result.is_err()
            && let Some(mut state) = connections.remove(connection_id)
        {
            state.exchange.fence();
            state.accepted_transport = None;
        }
        result
    }

    /// Builds the typed Control/Ready receipt sent after the exact bridge
    /// hello. The bridge must consume this Kernel-authored receipt to form its
    /// activation request; it is never reconstructed from caller input.
    #[cfg(windows)]
    pub fn agent_bridge_admission_receipt_frame(
        &self,
        connection_id: &str,
    ) -> Result<Frame, TransportError> {
        let connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let state = connections
            .get(connection_id)
            .ok_or(TransportError::SessionFenced)?;
        let receipt = state
            .accepted_transport
            .as_ref()
            .ok_or(TransportError::SessionFenced)?
            .admission_receipt();
        agent_bridge_admission_receipt_frame(connection_id, receipt)
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the queue admission gate keeps request, receipt, and replay checks ordered"
    )]
    fn enqueue_agent_bridge_activation(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<AgentActivationResolutionTicket, TransportError> {
        let (request, receipt) = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let state = connections
                .get(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            if state.activation_completed || state.session.is_some() {
                return Err(TransportError::IdentityConflict);
            }
            let accepted = state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            let receipt = accepted.admission_receipt();
            let profile = self
                .agent_bridge_profile
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
                || receipt.profile_id != profile.admission.profile_id.as_str()
                || receipt.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            self.validate_active_bridge_profile(&profile.admission)?;
            if activation_deadline_expired(unix_ms(), receipt.activation_deadline_unix_ms) {
                return Err(TransportError::Timeout);
            }
            frame.validate()?;
            if frame.connection_id != connection_id
                || frame.kind != FrameKind::Request
                || frame.message_type != MessageType::Execute
                || frame.request_identity.is_none()
            {
                return Err(TransportError::SessionFenced);
            }
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let ProtocolPayload::Json(payload) = &frame.payload else {
                return Err(TransportError::SessionFenced);
            };
            let request: AgentBridgeActivationRequest = serde_json::from_value(payload.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if frame.request_identity.as_ref() != Some(&request.request_identity)
                || request.request_identity.request.metadata.request_id != request_id
                || request.operation != AGENT_BRIDGE_ACTIVATION_OPERATION
            {
                return Err(TransportError::SessionFenced);
            }
            request
                .validate_admission(receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            (request, receipt.clone())
        };
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let request_id = request
            .request_identity
            .request
            .metadata
            .request_id
            .as_str();
        if pending.replay.contains_key(request_id)
            || pending.entries.values().any(|entry| {
                entry.ticket.connection_id == connection_id
                    || entry.ticket.activation_request_id
                        == request.request_identity.request.metadata.request_id
            })
        {
            return Err(TransportError::IdentityConflict);
        }
        if pending.entries.len() >= 32 {
            return Err(TransportError::RegistryFull);
        }
        let ticket_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: format!("agent-activation:{ticket_nonce}"),
            activation_request_id: request.request_identity.request.metadata.request_id.clone(),
            activation_request_sha256: request.request_sha256.clone(),
            peer_admission_receipt_sha256: receipt.receipt_sha256.clone(),
            connection_id: connection_id.to_owned(),
            state_fence: receipt.state_fence.clone(),
            kernel_deadline_unix_ms: receipt.activation_deadline_unix_ms,
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        ticket
            .validate_against(&request, &receipt)
            .map_err(|_| TransportError::SessionFenced)?;
        pending.fifo.push_back(ticket.ticket_id.clone());
        if pending.replay.len() >= 64
            && let Some(oldest) = pending.replay.keys().next().cloned()
        {
            pending.replay.remove(&oldest);
        }
        pending
            .replay
            .insert(request_id.to_owned(), ticket.ticket_id.clone());
        pending.entries.insert(
            ticket.ticket_id.clone(),
            AgentActivationPending {
                ticket: ticket.clone(),
                request,
                decision: None,
                claim_lease_until_unix_ms: None,
            },
        );
        self.agent_activation_changed.notify_waiters();
        Ok(ticket)
    }

    #[cfg(windows)]
    fn claim_agent_activation_ticket(
        &self,
    ) -> Result<Option<AgentActivationResolutionTicket>, TransportError> {
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(pending.claim_at(unix_ms()))
    }

    #[cfg(windows)]
    fn submit_agent_activation_decision(
        &self,
        decision: AgentActivationResolutionDecision,
    ) -> Result<(), TransportError> {
        decision
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let entry = pending
            .entries
            .get_mut(&decision.ticket_id)
            .ok_or(TransportError::UnknownRequest)?;
        decision
            .validate_against(&entry.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        match classify_activation_decision(entry.decision.as_ref(), &decision) {
            ActivationDecisionDisposition::ExactReplay => return Ok(()),
            ActivationDecisionDisposition::Conflict => {
                return Err(TransportError::IdentityConflict);
            }
            ActivationDecisionDisposition::Commit => {}
        }
        if activation_deadline_expired(unix_ms(), entry.ticket.kernel_deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        entry.decision = Some(decision);
        // A decision is terminal for this ticket.  Remove its FIFO marker so
        // no later claim can reclaim a ticket that already crossed the
        // resolver decision boundary.
        let ticket_id = entry.ticket.ticket_id.clone();
        pending.fifo.retain(|queued_id| queued_id != &ticket_id);
        drop(pending);
        self.agent_activation_changed.notify_waiters();
        Ok(())
    }

    #[cfg(windows)]
    fn activation_response_frame(
        &self,
        connection_id: &str,
        original: &Frame,
        pending: &AgentActivationPending,
        decision: &AgentActivationResolutionDecision,
    ) -> Result<Frame, TransportError> {
        decision
            .validate_against(&pending.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        let session_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let accepted = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let state = connections
                .get(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .clone()
        };
        let session = Session::establish_agent_bridge(
            connection_id,
            accepted.peer().clone(),
            accepted.client_hello().module_generation.clone(),
            session_nonce.clone(),
        )?;
        let binding = AgentBridgeAuthenticatedBinding {
            principal_id: decision.principal_id.clone(),
            session_id: decision.session_id.clone(),
            activation_generation: decision.state_fence.resource_generation,
            state_fence: AgentBridgeActivationFence {
                authority_epoch: decision.state_fence.authority_epoch,
                generation: decision.state_fence.resource_generation,
                nonce: session_nonce,
            },
            task_id: decision.task_id.clone(),
            work_unit_id: decision.work_unit_id.clone(),
            work_scope_id: decision.work_scope_id.clone(),
            task_revision: decision.task_revision.clone(),
            plan_id: decision.plan_id.clone(),
            plan_revision: decision.plan_revision.clone(),
        };
        let response = AgentBridgeActivationResponse {
            wire_id: eliot_protocol::AGENT_BRIDGE_ACTIVATION_RESPONSE_WIRE_ID.to_owned(),
            wire_version: AgentBridgeActivationResponse::CONTRACT_VERSION,
            request_id: pending
                .request
                .request_identity
                .request
                .metadata
                .request_id
                .clone(),
            request_sha256: pending.request.request_sha256.clone(),
            disposition: AgentBridgeActivationDisposition::Authenticated {
                binding: Box::new(binding),
            },
            response_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        response
            .validate_request(&pending.request)
            .map_err(|_| TransportError::SessionFenced)?;
        let reply = Frame {
            protocol_version: original.protocol_version,
            encoding_profile: original.encoding_profile,
            connection_id: connection_id.to_owned(),
            request_id: Some(response.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(
                serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
            ),
            trace_context: original.trace_context.clone(),
        };
        reply.validate()?;
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let state = connections
            .get_mut(connection_id)
            .ok_or(TransportError::SessionFenced)?;
        if state.activation_completed || state.session.is_some() {
            return Err(TransportError::IdentityConflict);
        }
        state.session = Some(session);
        state.activation_completed = true;
        Ok(reply)
    }

    /// Queues one validated bridge request and waits for the sole eliotd
    /// resolver decision. Kernel owns the final transport Session/fence.
    #[cfg(windows)]
    pub async fn await_agent_bridge_activation_response(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        let ticket = self.enqueue_agent_bridge_activation(connection_id, frame)?;
        loop {
            let outcome = {
                let pending = self
                    .agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?;
                pending
                    .entries
                    .get(&ticket.ticket_id)
                    .and_then(|entry| entry.decision.clone())
            };
            if let Some(decision) = outcome {
                let pending = {
                    let pending = self
                        .agent_activation_pending
                        .lock()
                        .map_err(|_| TransportError::SessionFenced)?;
                    pending
                        .entries
                        .get(&ticket.ticket_id)
                        .ok_or(TransportError::SessionFenced)?
                        .clone()
                };
                let reply =
                    self.activation_response_frame(connection_id, frame, &pending, &decision)?;
                self.agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .entries
                    .remove(&ticket.ticket_id);
                return Ok(reply);
            }
            let now = unix_ms();
            if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
                let request = {
                    let pending = self
                        .agent_activation_pending
                        .lock()
                        .map_err(|_| TransportError::SessionFenced)?;
                    pending
                        .entries
                        .get(&ticket.ticket_id)
                        .ok_or(TransportError::SessionFenced)?
                        .request
                        .clone()
                };
                self.agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .entries
                    .remove(&ticket.ticket_id);
                self.revoke_agent_bridge(connection_id);
                let response = AgentBridgeActivationResponse::denied(
                    &request,
                    AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                let reply = Frame {
                    protocol_version: frame.protocol_version,
                    encoding_profile: frame.encoding_profile,
                    connection_id: connection_id.to_owned(),
                    request_id: Some(response.request_id.clone()),
                    kind: FrameKind::Response,
                    message_type: MessageType::Result,
                    request_identity: None,
                    payload: ProtocolPayload::Json(
                        serde_json::to_value(response)
                            .map_err(|_| TransportError::SessionFenced)?,
                    ),
                    trace_context: frame.trace_context.clone(),
                };
                reply.validate()?;
                return Ok(reply);
            }
            let notified = self.agent_activation_changed.notified();
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    }

    /// Validates one closed bridge activation operation and emits the sole
    /// R13.1b typed denial. No Kernel `Session` or semantic authority is made.
    #[cfg(windows)]
    pub fn agent_bridge_activation_response(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let result = (|| {
            let state = connections
                .get_mut(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            let accepted = state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            let receipt = accepted.admission_receipt();
            let profile = self
                .agent_bridge_profile
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
                || receipt.profile_id != profile.admission.profile_id.as_str()
                || receipt.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            self.validate_active_bridge_profile(&profile.admission)?;
            if activation_deadline_expired(unix_ms(), receipt.activation_deadline_unix_ms) {
                return Err(TransportError::SessionFenced);
            }
            frame.validate()?;
            if frame.connection_id != connection_id
                || frame.kind != FrameKind::Request
                || frame.message_type != MessageType::Execute
                || frame.request_identity.is_none()
            {
                return Err(TransportError::SessionFenced);
            }
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let ProtocolPayload::Json(payload) = &frame.payload else {
                return Err(TransportError::SessionFenced);
            };
            let request: AgentBridgeActivationRequest = serde_json::from_value(payload.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if frame.request_identity.as_ref() != Some(&request.request_identity)
                || request.request_identity.request.metadata.request_id != request_id
                || request.operation != AGENT_BRIDGE_ACTIVATION_OPERATION
            {
                return Err(TransportError::SessionFenced);
            }
            request
                .validate_admission(receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            let response = AgentBridgeActivationResponse::denied(
                &request,
                AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
            )
            .map_err(|_| TransportError::SessionFenced)?;
            response
                .validate_request(&request)
                .map_err(|_| TransportError::SessionFenced)?;
            let reply = Frame {
                protocol_version: frame.protocol_version,
                encoding_profile: frame.encoding_profile,
                connection_id: connection_id.to_owned(),
                request_id: Some(response.request_id.clone()),
                kind: FrameKind::Response,
                message_type: MessageType::Result,
                request_identity: None,
                payload: ProtocolPayload::Json(
                    serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
                ),
                trace_context: frame.trace_context.clone(),
            };
            reply.validate()?;
            Ok(reply)
        })();
        if let Some(mut state) = connections.remove(connection_id) {
            if result.is_ok() {
                state.exchange.abort();
            } else {
                state.exchange.fence();
            }
            state.accepted_transport = None;
        }
        result
    }

    /// Revokes all retained bridge authority for one disconnected connection.
    #[cfg(windows)]
    pub fn revoke_agent_bridge(&self, connection_id: &str) {
        if let Ok(mut connections) = self.agent_bridge_connections.lock()
            && let Some(mut state) = connections.remove(connection_id)
        {
            state.exchange.abort();
            if let Some(mut session) = state.session.take() {
                session.fence();
            }
            state.accepted_transport = None;
        }
        if let Ok(mut pending) = self.agent_activation_pending.lock() {
            let removed = pending
                .entries
                .iter()
                .filter(|(_, entry)| entry.ticket.connection_id == connection_id)
                .map(|(ticket_id, _)| ticket_id.clone())
                .collect::<Vec<_>>();
            for ticket_id in removed {
                pending.entries.remove(&ticket_id);
            }
            let live_ticket_ids = pending.entries.keys().cloned().collect::<BTreeSet<_>>();
            pending
                .fifo
                .retain(|ticket_id| live_ticket_ids.contains(ticket_id));
        }
        self.agent_activation_changed.notify_waiters();
    }

    #[cfg(windows)]
    fn require_current_daemon_session(&self, session: &Session) -> Result<(), TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Ok(());
        }
        let Some(launch) = self
            .active_daemon_launch()
            .map_err(|_| TransportError::SessionFenced)?
        else {
            return Ok(());
        };
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if session.accepts_bound(&policy.module_generation, launch.launch_nonce.as_str()) {
            Ok(())
        } else {
            Err(TransportError::SessionFenced)
        }
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

    #[cfg(windows)]
    fn validate_candidate_process_binding(
        &self,
        candidate: &HostKernelCandidateBinding,
    ) -> Result<(), KernelServiceError> {
        #[cfg(test)]
        if candidate.job_object_id.as_str() == "Local\\Eliot-Host-Kernel-test" {
            return Ok(());
        }
        let binding: RecoverableJobBinding =
            serde_json::from_value(serde_json::to_value(&candidate.job_binding).map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding cannot be encoded".to_owned())
            })?)
            .map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding is malformed".to_owned())
            })?;
        if binding.job_identity().name() != candidate.job_object_id.as_str() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "job_object_id",
            });
        }
        let job = RecoverableJobObject::open(binding)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let current = self
            .platform
            .process_identity(std::process::id())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if job.binding().root().process() != &current
            || !job
                .live_processes()
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?
                .iter()
                .any(|process| process.process() == &current)
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "candidate_process_job_binding",
            });
        }
        Ok(())
    }

    #[cfg(windows)]
    fn daemon_supervision_contour(
        &self,
        session: &Session,
        process: &ProcessStartReceipt,
    ) -> Result<DaemonSupervisionContour, KernelServiceError> {
        process
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let (candidate, activation) = {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
            let candidate = service
                .candidate_binding()
                .cloned()
                .ok_or(KernelServiceError::ReadinessNotProven)?;
            let activation = service
                .activation_receipt()
                .cloned()
                .ok_or(KernelServiceError::ReadinessNotProven)?;
            (candidate, activation)
        };
        candidate
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        candidate
            .supervision_incarnation
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.authority_epoch != candidate.kernel_epoch
            || session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER
            || session.authority_epoch != activation.authority_epoch.value()
            || session.module_generation.generation != activation.generation
            || process.accepted_generation().get() != session.module_generation.generation.value()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let state_fence = StateFence::new(activation.authority_epoch, activation.generation);
        if session.module_generation.state_fence != state_fence {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if authority.supervision_lease_scope_id()
            != candidate.supervision_incarnation.supervision_lease_scope_id
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let physical = process.identity().physical();
        let generation_binding = SupervisionGenerationBinding {
            target_id: session.module_generation.artifact_id.as_str().to_owned(),
            target_generation: session.module_generation.generation,
            module_id: session.module_generation.module_id.as_str().to_owned(),
            module_generation: session.module_generation.generation,
            process_id: format!(
                "pid:{}:start:{}",
                physical.process_id(),
                physical.start_time_100ns()
            ),
            process_generation: ResourceGeneration::new(process.accepted_generation().get())
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
        };
        Ok(DaemonSupervisionContour {
            candidate_digest,
            incarnation: candidate.supervision_incarnation,
            activation,
            generation_binding,
            state_fence,
        })
    }

    #[cfg(windows)]
    fn active_supervision_binding(
        contour: &DaemonSupervisionContour,
        issued_at_ms: u64,
    ) -> Result<eliot_ors::SupervisionLeaseBinding, SupervisionLeaseAuthorityError> {
        if issued_at_ms == 0 {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "supervision issue time is zero".to_owned(),
            ));
        }
        let expires_at_ms = issued_at_ms
            .checked_add(SUPERVISION_LEASE_VALIDITY_MS)
            .ok_or_else(|| {
                SupervisionLeaseAuthorityError::Configuration(
                    "supervision validity interval overflowed".to_owned(),
                )
            })?;
        let renew_before_ms = issued_at_ms
            .checked_add(SUPERVISION_LEASE_RENEW_AFTER_MS)
            .ok_or_else(|| {
                SupervisionLeaseAuthorityError::Configuration(
                    "supervision renewal interval overflowed".to_owned(),
                )
            })?;
        let incarnation = &contour.incarnation;
        Ok(eliot_ors::SupervisionLeaseBinding {
            scope_ref: OperationIdentity::new(
                incarnation
                    .derived_scope_ref()
                    .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
            )?,
            observation_scope: incarnation.observation_scope.clone(),
            installation_id: OperationIdentity::new(incarnation.installation_id.clone())?,
            host_epoch: AuthorityEpoch::new(incarnation.host_epoch.sequence)
                .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
            activation_id: OperationIdentity::new(incarnation.activation_id.clone())?,
            activation_generation: contour.activation.generation,
            kernel_epoch: contour.activation.authority_epoch,
            watchdog_epoch: AuthorityEpoch::new(incarnation.watchdog_epoch.sequence)
                .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
            generation_binding: contour.generation_binding.clone(),
            state_fence: contour.state_fence.clone(),
            issued_at_ms,
            expires_at_ms,
            renew_before_ms,
            wake_policy: incarnation.wake_policy.clone(),
            state: LeaseState::Active,
            terminal_disposition: None,
            revocation_reason: None,
            revocation_id: None,
            revocation_epoch: None,
        })
    }

    #[cfg(windows)]
    fn supersede_predecessor(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        let Some(predecessor) = contour.incarnation.predecessor.as_ref() else {
            return Ok(());
        };
        predecessor
            .validate()
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        let current = authority
            .current_snapshot(&predecessor.supervision_lease_id)?
            .ok_or(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ))?;
        current
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        if current.record.state == LeaseState::Superseded
            && current.record.projection == eliot_ors::SupervisionLeaseProjection::Terminal
            && current
                .record
                .artifact
                .payload
                .ors_mirror
                .previous_receipt_sha256
                .as_deref()
                == Some(predecessor.ors_receipt_sha256.as_str())
        {
            return authority.verify_superseded_replay(&current, predecessor);
        }
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || current.receipt.receipt_sha256 != predecessor.ors_receipt_sha256
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let stage = if let Some(stage) =
            authority.staged_snapshot(&predecessor.supervision_lease_id)?
        {
            if stage.ticket.operation != SupervisionLeaseOperation::Supersede
                || stage.ticket.expected_revision != Some(current.record.revision)
                || stage.ticket.previous_receipt_sha256.as_deref()
                    != Some(predecessor.ors_receipt_sha256.as_str())
                || stage.ticket.binding.state != LeaseState::Superseded
                || stage.ticket.binding.terminal_disposition
                    != Some(SupervisionLeaseTerminalDisposition::Superseded)
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            let mut binding = current.record.binding.clone();
            binding.state = LeaseState::Superseded;
            binding.terminal_disposition = Some(SupervisionLeaseTerminalDisposition::Superseded);
            let ticket_id = supervision_operation_identity(
                "supersede-ticket",
                &predecessor.supervision_lease_id,
                Some(&predecessor.ors_receipt_sha256),
            )?;
            authority.prepare(SupervisionLeasePrepareRequest {
                operation_id: supervision_operation_identity(
                    "supersede-operation",
                    &predecessor.supervision_lease_id,
                    Some(&predecessor.ors_receipt_sha256),
                )?,
                ticket_id,
                lease_id: OperationIdentity::new(predecessor.supervision_lease_id.clone())?,
                expected_revision: Some(current.record.revision),
                operation: SupervisionLeaseOperation::Supersede,
                binding,
            })?
        };
        let terminal = authority.commit_terminal(&stage.ticket)?;
        if terminal.record.state != LeaseState::Superseded
            || terminal.record.projection != eliot_ors::SupervisionLeaseProjection::Terminal
            || terminal
                .record
                .artifact
                .payload
                .ors_mirror
                .previous_receipt_sha256
                .as_deref()
                != Some(predecessor.ors_receipt_sha256.as_str())
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        authority.verify_superseded_replay(&terminal, predecessor)
    }

    #[cfg(windows)]
    fn commit_or_replay_active_supervision(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
        now_ms: u64,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        Self::supersede_predecessor(authority, contour)?;
        if let Some(current) = authority.current_snapshot(lease_id)? {
            authority.verify_active_snapshot(&current, lease_id, now_ms)?;
            if !supervision_binding_matches_contour(&current.record.binding, contour)? {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseBindingMismatch,
                ));
            }
            return Ok(current);
        }
        let stage = if let Some(stage) = authority.staged_snapshot(lease_id)? {
            if stage.ticket.operation != SupervisionLeaseOperation::Commit
                || stage.ticket.expected_revision.is_some()
                || stage.ticket.binding.state != LeaseState::Active
                || !supervision_binding_matches_contour(&stage.ticket.binding, contour)?
                || now_ms >= stage.ticket.binding.expires_at_ms
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            let binding = Self::active_supervision_binding(contour, now_ms)?;
            authority.prepare(SupervisionLeasePrepareRequest {
                ticket_id: supervision_operation_identity("commit-ticket", lease_id, None)?,
                operation_id: supervision_operation_identity("commit-operation", lease_id, None)?,
                lease_id: OperationIdentity::new(lease_id.to_owned())?,
                expected_revision: None,
                operation: SupervisionLeaseOperation::Commit,
                binding,
            })?
        };
        let current = authority.commit_active(&stage.ticket)?;
        authority.verify_active_snapshot(&current, lease_id, now_ms)?;
        if !supervision_binding_matches_contour(&current.record.binding, contour)? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        Ok(current)
    }

    #[cfg(windows)]
    fn renew_current_supervision(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
        now_ms: u64,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        let current =
            authority
                .current_snapshot(lease_id)?
                .ok_or(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseBindingMismatch,
                ))?;
        authority.verify_active_snapshot(&current, lease_id, now_ms)?;
        if !supervision_binding_matches_contour(&current.record.binding, contour)? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        if now_ms < current.record.binding.renew_before_ms {
            return Ok(current);
        }
        let stage = if let Some(stage) = authority.staged_snapshot(lease_id)? {
            if stage.ticket.operation != SupervisionLeaseOperation::Renew
                || stage.ticket.expected_revision != Some(current.record.revision)
                || stage.ticket.previous_receipt_sha256.as_deref()
                    != Some(current.receipt.receipt_sha256.as_str())
                || stage.ticket.binding.state != LeaseState::Active
                || !supervision_binding_matches_contour(&stage.ticket.binding, contour)?
                || now_ms >= stage.ticket.binding.expires_at_ms
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            let binding = Self::active_supervision_binding(contour, now_ms)?;
            authority.prepare(SupervisionLeasePrepareRequest {
                ticket_id: supervision_operation_identity(
                    "renew-ticket",
                    lease_id,
                    Some(&current.receipt.receipt_sha256),
                )?,
                operation_id: supervision_operation_identity(
                    "renew-operation",
                    lease_id,
                    Some(&current.receipt.receipt_sha256),
                )?,
                lease_id: OperationIdentity::new(lease_id.to_owned())?,
                expected_revision: Some(current.record.revision),
                operation: SupervisionLeaseOperation::Renew,
                binding,
            })?
        };
        let renewed = authority.commit_active(&stage.ticket)?;
        authority.verify_active_snapshot(&renewed, lease_id, now_ms)?;
        if renewed.record.revision <= current.record.revision
            || !supervision_binding_matches_contour(&renewed.record.binding, contour)?
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        Ok(renewed)
    }

    #[cfg(windows)]
    fn establish_daemon_supervision(
        &self,
        session: &Session,
        process: &ProcessStartReceipt,
    ) -> Result<(DaemonSupervisionContour, SupervisionLeaseSnapshot), KernelServiceError> {
        let contour = self.daemon_supervision_contour(session, process)?;
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let snapshot = Self::commit_or_replay_active_supervision(authority, &contour, unix_ms())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        Ok((contour, snapshot))
    }

    #[cfg(windows)]
    fn renew_daemon_supervision_for_probe(
        &self,
        request: &KernelControlRequest,
    ) -> Result<(SupervisionLeaseSnapshot, EliotdLiveReceipt), KernelServiceError> {
        let (contour, process, ready) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            if state.status != DaemonRuntimeStatus::Ready {
                return Err(KernelServiceError::ReadinessNotProven);
            }
            (
                state
                    .supervision
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?,
                state
                    .receipt
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?,
                state
                    .live_ready
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?,
            )
        };
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let activation = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .activation_receipt()
            .cloned()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if contour.candidate_digest != candidate_digest
            || contour.incarnation != request.candidate.supervision_incarnation
            || contour.activation != activation
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let lease_id = &contour.incarnation.supervision_lease_id;
        let before = authority
            .current_snapshot(lease_id)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        authority
            .verify_active_snapshot(&before, lease_id, unix_ms())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !supervision_binding_matches_contour(&before.record.binding, &contour)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        // A retry first reconciles any exact current ORS successor left by an
        // earlier ambiguous publication. This prevents a second Renew from
        // skipping over the receipt that still names the older ORS head.
        let _ =
            self.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, Some(&before))?;
        let renewed = Self::renew_current_supervision(authority, &contour, unix_ms())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let published =
            self.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, Some(&renewed))?;
        Ok((renewed, published))
    }

    #[cfg(windows)]
    fn eliotd_live_ready_evidence(
        session: &Session,
        request_id: &RequestId,
        payload: &serde_json::Value,
    ) -> Result<EliotdLiveReadyEvidence, KernelServiceError> {
        Ok(EliotdLiveReadyEvidence {
            request_id: request_id.as_str().to_owned(),
            request_payload_sha256: sha256_json(payload)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
            connection_id: session.connection_id.clone(),
            session_epoch: session.session_epoch,
            authority_epoch: session.authority_epoch,
            generation: session.module_generation.generation.value(),
            launch_nonce_sha256: format!("{:x}", Sha256::digest(session.launch_nonce.as_bytes())),
        })
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    fn publish_eliotd_live_receipt(
        &self,
        launch: &EliotdLaunchDescriptor,
        process: &ProcessStartReceipt,
        ready: &EliotdLiveReadyEvidence,
        supervision_contour: &DaemonSupervisionContour,
        supervision_successor: Option<&SupervisionLeaseSnapshot>,
    ) -> Result<EliotdLiveReceipt, KernelServiceError> {
        let runtime_binding = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        runtime_binding
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let receipt_root = runtime_binding.receipt_root();
        if !receipt_root.is_absolute() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let root_lease = ProtectedRootLease::open_existing(receipt_root)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let canonical_root = root_lease
            .canonical_path()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !windows_paths_equal(&canonical_root, receipt_root)
            || root_lease.verify_stable_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let kernel_artifact = self
            .kernel_artifact_sha256
            .as_deref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let descriptor_artifact = self
            .eliotd_descriptor_artifact_sha256
            .as_deref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let supervision_authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if let Some(expected_successor) = supervision_successor {
            let observed = supervision_authority
                .current_snapshot(&supervision_contour.incarnation.supervision_lease_id)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            if observed.as_ref() != Some(expected_successor) {
                return Err(KernelServiceError::ReadinessNotProven);
            }
            supervision_authority
                .verify_active_snapshot(
                    expected_successor,
                    &supervision_contour.incarnation.supervision_lease_id,
                    unix_ms(),
                )
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        }
        let (supervision, supervision_issued_at_ms) = supervision_authority
            .current_eliotd_live_projection(
                &supervision_contour.incarnation.supervision_lease_id,
                launch.generation.value(),
                launch.authority_epoch.value(),
            )
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let receipt = EliotdLiveReceipt::new(
            canonical_root.to_string_lossy(),
            sha256_json(&root_lease.identity())
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
            runtime_binding.runtime_state_roots_digest(),
            runtime_binding.installation_id(),
            runtime_binding.approved_generation(),
            launch.generation.value(),
            launch.authority_epoch.value(),
            launch.config_descriptor_sha256.as_str(),
            descriptor_artifact,
            kernel_artifact,
            process.clone(),
            supervision.clone(),
            ready.clone(),
            supervision_issued_at_ms,
        )
        .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        receipt
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let bytes = eliot_contracts::canonical_json_bytes(&receipt)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let path = canonical_root.join("eliotd-receipt.json");

        let existing = match ProtectedRuntimePathLease::open_existing_absolute(&path) {
            Ok(lease) => {
                if lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err()
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let old_bytes = lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?;
                let old: EliotdLiveReceipt = serde_json::from_slice(&old_bytes)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?;
                old.validate()
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?;
                if eliot_contracts::canonical_json_bytes(&old)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?
                    != old_bytes
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                if !windows_paths_equal(Path::new(&old.receipt_root), &canonical_root)
                    || old.receipt_root_identity_sha256
                        != sha256_json(&root_lease.identity())
                            .map_err(|_| KernelServiceError::ReadinessNotProven)?
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let same_active_contour = old.runtime_state_roots_digest
                    == receipt.runtime_state_roots_digest
                    && old.installation_id == receipt.installation_id
                    && old.approved_generation == receipt.approved_generation
                    && old.generation == receipt.generation
                    && old.authority_epoch == receipt.authority_epoch
                    && old.config_descriptor_sha256 == receipt.config_descriptor_sha256
                    && old.descriptor_sha256 == receipt.descriptor_sha256
                    && old.kernel_artifact_sha256 == receipt.kernel_artifact_sha256
                    && old.supervision.lease_id == receipt.supervision.lease_id
                    && old.supervision.public_key_fingerprint
                        == receipt.supervision.public_key_fingerprint;
                let exact_predecessor = supervision_contour
                    .incarnation
                    .predecessor
                    .as_ref()
                    .is_some_and(|predecessor| {
                        predecessor.supervision_lease_id == old.supervision.lease_id
                            && predecessor.ors_receipt_sha256 == old.supervision.receipt_sha256
                            && old.installation_id == receipt.installation_id
                            && old.supervision.public_key_fingerprint
                                == receipt.supervision.public_key_fingerprint
                    });
                // The destination is replaceable only by the same active
                // contour or by the exact journal-bound predecessor that was
                // durably Superseded before this publication.
                if !same_active_contour && !exact_predecessor {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                if old.runtime_state_roots_digest != receipt.runtime_state_roots_digest
                    || old.installation_id != receipt.installation_id
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                Some((
                    old_bytes.clone(),
                    PublicationPrecondition::from_bytes(lease.identity(), &old_bytes),
                ))
            }
            Err(_) => match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                _ => return Err(KernelServiceError::ReadinessNotProven),
            },
        };

        let status_is_ready = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?
            .status
            == DaemonRuntimeStatus::Ready;
        let successor_evidence = supervision_successor.map(Into::into);
        let existing_disposition = if let Some((old_bytes, _)) = &existing {
            let old: EliotdLiveReceipt = serde_json::from_slice(old_bytes)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            Some(classify_eliotd_live_receipt_transition(
                &old,
                &receipt,
                status_is_ready,
                supervision_contour.incarnation.predecessor.as_ref(),
                successor_evidence.as_ref(),
            )?)
        } else if status_is_ready {
            return Err(KernelServiceError::ReadinessNotProven);
        } else {
            None
        };
        let reconciled_existing =
            existing_disposition == Some(EliotdLiveReceiptDisposition::ExactReplay);

        let published_identity = if reconciled_existing {
            None
        } else {
            let expected_existing = existing.as_ref().map(|(_, fence)| fence);
            let outcome = publish_atomic_owned_runtime_receipt(&path, &bytes, expected_existing)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            match outcome {
                PublicationOutcome::Published(receipt) => Some(receipt.identity),
                // Exact destination reconciliation is deliberately deferred
                // to a replay of the same authenticated daemon_ready request.
                // An ambiguous attempt itself never advances readiness.
                PublicationOutcome::Unknown(_) => {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
            }
        };
        let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if published_identity
            .as_ref()
            .is_some_and(|identity| lease.identity() != *identity)
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let readback = lease
            .read_bounded(1024 * 1024)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if readback != bytes {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if root_lease.verify_stable_identity().is_err()
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let post_root = root_lease
            .canonical_path()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !windows_paths_equal(&post_root, &canonical_root)
            || root_lease.verify_stable_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        // Re-read the protected ORS identity and exact active signature after
        // the receipt CAS. A successful destination readback alone must not
        // outlive a concurrent authority rotation or ORS root substitution.
        let (post_supervision, post_issued_at_ms) = supervision_authority
            .current_eliotd_live_projection(
                &supervision_contour.incarnation.supervision_lease_id,
                launch.generation.value(),
                launch.authority_epoch.value(),
            )
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if post_supervision != supervision || post_issued_at_ms != supervision_issued_at_ms {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(receipt)
    }

    #[cfg(windows)]
    fn verify_published_eliotd_live_receipt(
        &self,
        expected: &EliotdLiveReceipt,
    ) -> Result<(), KernelServiceError> {
        expected
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let runtime_binding = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        runtime_binding
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let root_lease = ProtectedRootLease::open_existing(runtime_binding.receipt_root())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let canonical_root = root_lease
            .canonical_path()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !windows_paths_equal(&canonical_root, runtime_binding.receipt_root())
            || !windows_paths_equal(Path::new(&expected.receipt_root), &canonical_root)
            || expected.receipt_root_identity_sha256
                != sha256_json(&root_lease.identity())
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let path = canonical_root.join("eliotd-receipt.json");
        let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if root_lease.verify_stable_identity().is_err()
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let observed = lease
            .read_bounded(1024 * 1024)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let expected_bytes = eliot_contracts::canonical_json_bytes(expected)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if observed != expected_bytes
            || root_lease.verify_stable_identity().is_err()
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(())
    }

    #[cfg(windows)]
    async fn validated_authenticated_daemon_ready_inputs(
        &self,
    ) -> Result<(EliotdLaunchDescriptor, ProcessStartReceipt), KernelServiceError> {
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let receipt = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?
            .receipt
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        self.validate_daemon_process_readiness(&launch, &receipt)
            .await?;
        Ok((launch, receipt))
    }

    #[cfg(windows)]
    async fn validate_daemon_process_readiness(
        &self,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
    ) -> Result<(), KernelServiceError> {
        let Some(gateway) = self.process_gateway.as_ref() else {
            let _ = self
                .mark_daemon_failed("eliotd physical process authority is unavailable".to_owned());
            return Err(KernelServiceError::ReadinessNotProven);
        };
        if gateway
            .inspect_exact_running_receipt(receipt)
            .await
            .is_err()
        {
            let _ = self
                .mark_daemon_failed("eliotd physical process is not freshly Running".to_owned());
            return Err(KernelServiceError::ReadinessNotProven);
        }

        let generation = Generation::new(launch.generation.value()).map_err(|_| {
            let _ = self.mark_daemon_failed("eliotd launch generation is invalid".to_owned());
            KernelServiceError::ReadinessNotProven
        })?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id()).map_err(|_| {
            let _ = self.mark_daemon_failed(
                "Kernel physical identity is unavailable for eliotd readiness".to_owned(),
            );
            KernelServiceError::ReadinessNotProven
        })?;
        let launch_identity = eliotd_launch_attempt_identity(
            launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )
        .map_err(|_| {
            let _ = self.mark_daemon_failed("eliotd launch attempt identity is invalid".to_owned());
            KernelServiceError::ReadinessNotProven
        })?;
        let expected_operation =
            eliotd_operation_id(generation, &launch_identity).map_err(|_| {
                let _ = self
                    .mark_daemon_failed("eliotd launch operation identity is invalid".to_owned());
                KernelServiceError::ReadinessNotProven
            })?;
        let physical = receipt.identity().physical();
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation().get() != launch.generation.value()
            || receipt.binding().state_fence().authority_epoch() != launch.authority_epoch.value()
            || receipt.binding().state_fence().generation() != generation
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || !physical
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            let _ = self.mark_daemon_failed(
                "eliotd physical process binding does not match the approved launch contour"
                    .to_owned(),
            );
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(())
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "ordered live process, Job, authority, configuration, and Store proof remains explicit"
    )]
    async fn self_authored_ready_receipt(
        &self,
        request: &KernelControlRequest,
        peer: &PeerIdentity,
    ) -> Result<KernelReadyReceipt, KernelServiceError> {
        let candidate: &HostKernelCandidateBinding = &request.candidate;
        let observed_peer = peer.process_binding().ok_or(KernelServiceError::Platform(
            "authenticated Host process binding is unavailable".to_owned(),
        ))?;
        if observed_peer.process_id() != candidate.host_process.process_id
            || observed_peer.start_time_100ns() != candidate.host_process.start_time_100ns
            || observed_peer.image_path() != candidate.host_process.image_path
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "host_process",
            });
        }
        let binding: RecoverableJobBinding =
            serde_json::from_value(serde_json::to_value(&candidate.job_binding).map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding cannot be encoded".to_owned())
            })?)
            .map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding is malformed".to_owned())
            })?;
        if binding.job_identity().name() != candidate.job_object_id.as_str() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "job_object_id",
            });
        }
        let job = RecoverableJobObject::open(binding)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let current = self
            .platform
            .process_identity(std::process::id())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let root = job.binding().root().process();
        if root != &current
            || !job
                .live_processes()
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?
                .iter()
                .any(|process| process.process() == &current)
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if !self
            .process_gateway
            .as_ref()
            .is_some_and(|gateway| gateway.readiness_configuration_valid())
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if self.approved_config_hash.as_deref() != Some(candidate.config_hash.as_str()) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "config_hash",
            });
        }
        {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
            if !probe_ready_state_admitted(service.state())
                || service.candidate_binding() != Some(candidate)
                || service.authority_epoch() != candidate.kernel_epoch
            {
                return Err(KernelServiceError::ReadinessNotProven);
            }
            if let Some(receipt) = service.store_rebind_receipt() {
                let handoff = self
                    .store_handoff
                    .lock()
                    .map_err(|_| {
                        KernelServiceError::Platform("store handoff lock poisoned".to_owned())
                    })?
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?;
                if handoff.process_binding != receipt.process_binding {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let expected_digest = serde_json::to_vec(&handoff.requirement)
                    .map(|b| format!("{:x}", Sha256::digest(b)))
                    .map_err(|_| {
                        KernelServiceError::Platform("store requirement digest failed".to_owned())
                    })?;
                if receipt.requirement_digest != expected_digest
                    || receipt.candidate_binding_digest
                        != candidate.compute_digest().map_err(|_| {
                            KernelServiceError::Platform("candidate digest failed".to_owned())
                        })?
                    || receipt.generation != request.generation
                    || receipt.authority_epoch != candidate.kernel_epoch
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let ors_records = self
                    .generation_gateway
                    .ors
                    .load_all_store_rebinds()
                    .map_err(|_| KernelServiceError::Platform("ORS load failed".to_owned()))?;
                let committed: Vec<_> = ors_records
                    .iter()
                    .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Committed)
                    .collect();
                let lineage_zeros = committed
                    .iter()
                    .filter(|r| {
                        r.commit_order == 0
                            && r.requirement_digest == receipt.requirement_digest
                            && r.generation == receipt.generation.value()
                            && r.authority_epoch == receipt.authority_epoch.value()
                    })
                    .count();
                if lineage_zeros > 1 {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let latest = committed.into_iter().max_by_key(|r| {
                    (
                        r.commit_order,
                        r.operation_id.as_str().to_owned(),
                        r.request_digest.clone(),
                    )
                });
                match latest {
                    Some(latest)
                        if latest.operation_id.as_str() == receipt.operation_id.as_str()
                            && latest.request_digest == receipt.request_digest
                            && latest.store_fence == receipt.store_fence =>
                    {
                        if latest.commit_order == 0 {
                            let total_legacy = ors_records
                                .iter()
                                .filter(|r| {
                                    r.state == eliot_ors::StoreRebindReplayState::Committed
                                        && r.commit_order == 0
                                })
                                .count();
                            if total_legacy > 1 {
                                return Err(KernelServiceError::ReadinessNotProven);
                            }
                        }
                    }
                    _ => return Err(KernelServiceError::ReadinessNotProven),
                }
            } else {
                let ors_has_committed = self
                    .generation_gateway
                    .ors
                    .load_all_store_rebinds()
                    .map_err(|_| KernelServiceError::Platform("ORS load failed".to_owned()))?
                    .iter()
                    .any(|r| r.state == eliot_ors::StoreRebindReplayState::Committed);
                if ors_has_committed {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
            }
        }
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| KernelServiceError::Platform("store gateway lock poisoned".to_owned()))?
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let health = gateway
            .health()
            .await
            .map_err(KernelServiceError::Platform)?;
        if health.status != StoreHealthStatus::Ready {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let snapshot = gateway
            .validation_snapshot()
            .await
            .map_err(KernelServiceError::Platform)?;
        snapshot
            .validate()
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if snapshot.state_fence.authority_epoch != candidate.kernel_epoch
            || snapshot.state_fence.resource_generation != request.generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_state_fence",
            });
        }
        let daemon_evidence = if self.active_daemon_launch()?.is_some() {
            let daemon_receipt = self.ensure_daemon_ready_for_probe().await?;
            let launch = self
                .active_daemon_launch()?
                .ok_or(KernelServiceError::ReadinessNotProven)?;
            self.validate_daemon_process_readiness(&launch, &daemon_receipt)
                .await?;
            Some(
                PlatformHandle::new(format!(
                    "eliotd-ready:{}:{}",
                    daemon_receipt.identity().pid(),
                    launch.descriptor_sha256.as_str(),
                ))
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
            )
        } else {
            None
        };
        let process_id = PlatformHandle::new(format!(
            "pid:{}:start:{}",
            current.process_id, current.start_time_100ns
        ))
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let process = ProcessObservation {
            process_id,
            job_object_id: candidate.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![
                PlatformHandle::new(format!(
                    "kernel-process:{}:{}",
                    current.process_id, current.start_time_100ns
                ))
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
                PlatformHandle::new(format!(
                    "kernel-job:{}:{}",
                    candidate.job_object_id.as_str(),
                    job.active_process_count()
                        .map_err(|error| KernelServiceError::Platform(error.to_string()))?
                ))
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
            ],
        };
        let mut evidence_refs = KernelReadyReceipt::probe_binding_evidence(request)?;
        evidence_refs.extend([
            PlatformHandle::new(format!(
                "kernel-store-validation:{}",
                snapshot.validation_revision
            ))
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
            PlatformHandle::new(format!(
                "kernel-store-health:{}",
                health.manifest_digest.as_str()
            ))
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        ]);
        if let Some(daemon_evidence) = daemon_evidence {
            evidence_refs.push(daemon_evidence);
        }
        let activation = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .activation_receipt()
            .cloned()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let receipt = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process,
            health: HealthVector::healthy(),
            evidence_refs,
        };
        receipt.validate_for_probe(request, &activation)?;
        Ok(receipt)
    }

    #[cfg(windows)]
    fn rollback_store_rebind_if_exact_query(
        &self,
        query: &StoreRebindQuery,
    ) -> Result<(), TransportError> {
        let mut service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        match service.reconcile_store_rebind(query) {
            Ok(Some(receipt))
                if service.state() == KernelServiceState::Degraded
                    && service.store_rebind_receipt() == Some(&receipt)
                    && service.failure().is_some_and(|failure| {
                        matches!(
                            failure,
                            eliot_kernel_service::ServiceFailure::Contract(reason)
                                if reason == "store-rebind:degraded-for-fence"
                        )
                    }) =>
            {
                // A service-first receipt is volatile until ORS readback. If
                // exact ORS reconciliation proves the operation absent, put
                // the same in-memory service back on its pre-rebind contour
                // before Host is allowed to persist Aborted.
                service.rollback_store_rebind_for_recovery_failure();
                Ok(())
            }
            Ok(Some(_)) => Ok(()),
            Ok(None) | Err(eliot_kernel_service::KernelServiceError::HandshakeMismatch { .. }) => {
                Ok(())
            }
            Err(_) => Err(TransportError::SessionFenced),
        }
    }

    #[cfg(windows)]
    fn validate_store_rebind_admission(
        &self,
        request: &KernelControlRequest,
    ) -> Result<(), TransportError> {
        if matches!(
            &request.command,
            KernelControlCommand::ReconcileRebindStore(_)
        ) {
            return Ok(());
        }
        let receipt = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .store_rebind_receipt()
            .cloned();
        let Some(receipt) = receipt else {
            return Ok(());
        };
        self.validate_store_rebind_receipt_admission(request, &receipt)
    }

    #[cfg(windows)]
    fn validate_store_rebind_receipt_admission(
        &self,
        request: &KernelControlRequest,
        receipt: &eliot_kernel_service::StoreRebindReceipt,
    ) -> Result<(), TransportError> {
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.candidate_binding_digest != candidate_digest
            || receipt.generation != request.generation
            || receipt.authority_epoch != request.candidate.kernel_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if receipt.process_binding != handoff.process_binding {
            return Err(TransportError::SessionFenced);
        }
        let expected_requirement_digest = serde_json::to_vec(&handoff.requirement)
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.requirement_digest != expected_requirement_digest {
            return Err(TransportError::SessionFenced);
        }
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_vec(&handoff.requirement.state_fence)
                .map_err(|_| TransportError::SessionFenced)?,
        );
        hasher.update(receipt.generation.value().to_le_bytes());
        hasher.update(receipt.authority_epoch.value().to_le_bytes());
        hasher.update(
            handoff
                .requirement
                .approved_artifact_hash
                .as_str()
                .as_bytes(),
        );
        hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
        hasher.update(receipt.process_binding.process.process_id.to_le_bytes());
        hasher.update(
            receipt
                .process_binding
                .process
                .start_time_100ns
                .to_le_bytes(),
        );
        hasher.update(receipt.process_binding.process.image_path.as_bytes());
        hasher.update(receipt.process_binding.job.as_str().as_bytes());
        hasher.update(candidate_digest.as_bytes());
        if receipt.store_fence != format!("{:x}", hasher.finalize()) {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn validate_store_rebind_ors_record_admission(
        request: &KernelControlRequest,
        query: &eliot_kernel_service::StoreRebindQuery,
        record: &eliot_ors::StoreRebindReplayRecord,
    ) -> Result<(), TransportError> {
        let receipt = store_rebind_receipt_from_ors_record(record)
            .map_err(|_| TransportError::SessionFenced)?;
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.operation_id.as_str() != query.operation_id.as_str()
            || receipt.request_digest != query.request_digest
            || receipt.candidate_binding_digest != candidate_digest
            || receipt.generation != request.generation
            || receipt.authority_epoch != request.candidate.kernel_epoch
            || receipt.requirement_digest != record.requirement_digest
            || receipt.store_fence != record.store_fence
            || receipt.process_binding.process.process_id != record.process_id
            || receipt.process_binding.process.start_time_100ns != record.process_start_time_100ns
            || receipt.process_binding.process.image_path != record.process_image_path
            || receipt.process_binding.job.as_str() != record.job_name
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn verify_store_rebind_publication_complete(
        &self,
        receipt: &eliot_kernel_service::StoreRebindReceipt,
    ) -> Result<(), TransportError> {
        let service_receipt = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .store_rebind_receipt()
            .cloned();
        if service_receipt.as_ref() != Some(receipt) {
            return Err(TransportError::SessionFenced);
        }
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if handoff.process_binding != receipt.process_binding {
            return Err(TransportError::SessionFenced);
        }
        let expected_requirement_digest = serde_json::to_vec(&handoff.requirement)
            .map(|b| format!("{:x}", Sha256::digest(b)))
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.requirement_digest != expected_requirement_digest {
            return Err(TransportError::SessionFenced);
        }
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if gateway.is_fenced() {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
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
mod tests;

// Store implementation E2E belongs to the Store/Host boundary. Kernel tests
// exercise only the neutral descriptor and route/fence behavior.
