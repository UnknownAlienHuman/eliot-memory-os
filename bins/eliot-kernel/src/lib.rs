//! The Kernel composition root.
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04
//! Implementation: I1.4, I1.5, I2.2, I2.23, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15
//! Forbidden authority: no semantic oracle, alternate lease authority, unbounded restart, or daemon-owned canonical transition.

#![forbid(unsafe_code)]

mod canonical_store_runtime;
mod composition_bootstrap;
mod control_plane;
mod kernel_build_contract;
mod kernel_config;
mod process_execution;

pub(crate) use kernel_build_contract::PreparedAuthorityMaterial;
#[cfg(windows)]
pub use kernel_build_contract::SupervisionLeaseAuthorityConfig;
pub use kernel_build_contract::{
    AuthorityDescriptorContour, AuthorityPreparationError, EliotdReceiptRootBinding,
    KernelBuildError,
};
pub use kernel_config::KernelConfig;
pub(crate) use process_execution::{
    CanonicalStoreAttachmentTransaction, KernelPathAdmission, ProcessExecutionGateway,
    ProcessPathProof,
};
pub use process_execution::{ProcessExecutionAuthorityConfig, WindowsDispatchSnapshotCodec};
#[cfg(test)]
use process_execution::{
    ProcessStartGuard, ProcessStartPorts, RESERVED_STORE_SNAPSHOT_HEAD, ValidationContextSlot,
    authorize_process_owner, project_store_snapshot, run_process_start,
};

#[cfg(test)]
use eliot_kernel_core::{
    AuthoritySnapshotBindingWire, ProcessExecutionReplayAbort, ProcessExecutionReplayBegin,
    ProcessExecutionReplayRecord, ProcessExecutionReplayState, process_admission_digest,
};

#[cfg(feature = "r13-os-harness")]
pub mod r13_os_harness;

mod daemon_live_receipt;
mod daemon_request_dispatch;
mod daemon_runtime;
mod daemon_session_guard;
mod daemon_supervision;
mod frame_dispatch;
mod front_door_listener;
mod front_door_session;
mod generation_control;
mod generation_recovery;
mod health_view;
mod runtime_identity;
use daemon_session_guard::caller_binding;
#[cfg(all(windows, test))]
use daemon_supervision::EliotdSupervisionSuccessorEvidence;
use daemon_supervision::{DaemonRuntimeState, DaemonRuntimeStatus, daemon_status_proves_ready};
#[cfg(windows)]
use daemon_supervision::{
    DaemonSupervisionContour, EliotdLiveReceiptDisposition, classify_eliotd_live_receipt_transition,
};
use generation_recovery::OrsGenerationCoordinator;
#[cfg(test)]
use generation_recovery::update_handshake_policy;
use runtime_identity::stable_owner_principal_digest;
#[cfg(windows)]
use runtime_identity::{
    eliotd_launch_attempt_identity, eliotd_operation_id, fresh_eliotd_launch_descriptor,
    observed_session_principal_binding,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
    AuthoritySnapshotBinding, DispatchSnapshotCodec, GenerationRoute, GenerationRouter,
    KernelError, ProcessDispatchAuthorityController, RouteScope,
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
use eliot_ors::{AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, OrsError};
use eliot_ors::{
    OperationIdentity, OperationalRecoveryStore, RedbRecoveryStore, SupervisionLeaseCommitTicket,
    SupervisionLeaseOperation, SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
    SupervisionLeaseStageReceipt,
};
#[cfg(test)]
use eliot_platform::ClockObservation;
use eliot_platform::PlatformHandle;
#[cfg(windows)]
use eliot_platform_windows::{
    FileIdentity as WindowsFileIdentity, NamedPipePeerKind, NamedPipePeerProfile,
    NamedPipePeerSelection, NamedPipePeerSet, ProtectedRootLease, ProtectedRuntimePathLease,
    PublicationOutcome, PublicationPrecondition, fresh_activation_nonce_material,
    publish_atomic_owned_runtime_receipt, read_protected_file, windows_paths_equal,
};
use eliot_platform_windows::{
    InstallerRootPrimitiveSpec, InstallerRootProfile, UserOwnedPathLease, UserOwnedRootLease,
    WindowsPlatform, WindowsSupervisionAuthorityKeyStore, protected_program_data_root,
};
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, EliotdLiveReadyEvidence, EliotdLiveReceipt,
    EliotdLiveSupervisionEvidence, EnvironmentInheritance, EnvironmentProjection, FencingToken,
    Generation, ImageId, JobId, KernelDispatchKey, ProcessExecutionAdmissionRequest,
    ProcessExecutionError, ProcessIntent, ProcessOwnerBinding, ProcessSessionBinding,
    ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
};
#[cfg(test)]
use eliot_process::{
    DispatchValidationContext, ProcessLaunchAdmission, ProcessLifecycle, ProcessRequest,
    SuspendedProcessIdentity, ValidatedDispatch,
};
#[cfg(test)]
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
    SupervisionLeasePredecessorIdentity, SupervisionLeasePredecessorProof, SupervisionLeaseSigner,
    SupervisionLeaseTerminalDisposition, SupervisionLeaseVerificationContext,
    SupervisionLeaseVerifier, SupervisionSealedKeyReference, SupervisionTrustAnchor,
};
use eliot_store_api::StoreHealth;
#[cfg(test)]
use eliot_store_api::{
    CanonicalValidationSnapshot, StateFence as StoreStateFence, StoreHealthStatus,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[cfg(all(test, windows))]
use canonical_store_runtime::attach_then_retain_canonical_store;
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

const fn probe_ready_state_admitted(state: KernelServiceState) -> bool {
    matches!(
        state,
        KernelServiceState::Activating | KernelServiceState::Ready | KernelServiceState::Degraded
    )
}

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

    /// Returns the protected supervision authority only when Host injected a
    /// complete key reference and installation trust anchor.
    #[cfg(windows)]
    #[must_use]
    pub fn supervision_lease_authority(&self) -> Option<&KernelSupervisionLeaseAuthority> {
        self.supervision_lease_authority.as_deref()
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
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
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
