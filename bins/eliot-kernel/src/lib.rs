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
    GenerationRouter, KernelError, ProcessDispatchAuthorityController, ProcessExecutionReplayAbort,
    ProcessExecutionReplayBegin, ProcessExecutionReplayRecord, ProcessExecutionReplayState,
    ProcessExecutionReplayStore, ProcessExecutionReplayStoreWithAbort, RouteScope,
    process_admission_digest,
};
use eliot_kernel_service::{
    EbpCanonicalStoreClient, EliotdLaunchDescriptor, HostKernelCandidateBinding,
    HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE, KernelActivationReceipt,
    KernelControlCommand, KernelControlRequest, KernelControlResponse, KernelReadyReceipt,
    KernelService, KernelServiceError, KernelServiceState, ProcessAuthorityHandoffDescriptor,
    ProcessExecutionRequest, ProcessExecutionResponse, ProcessObservation, StoreBootstrapHandoff,
    StoreClientError,
};
#[cfg(test)]
use eliot_ors::CanonicalEvidenceProvider;
use eliot_ors::{
    AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, OrsError,
    ProcessEvidenceRecord, ProcessStartReplayRecord as OrsReplayRecord,
    ProcessStartReplayState as OrsReplayState,
};
use eliot_ors::{
    OperationalRecoveryStore, RedbRecoveryStore, SupervisionLeaseCommitTicket,
    SupervisionLeaseOperation, SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
    SupervisionLeaseStageReceipt,
};
use eliot_platform::{ClockObservation, PlatformHandle, PortError, SecretReference};
use eliot_platform_windows::{
    ProtectedPathLease, ProtectedSecret, RecoverableJobBinding, RecoverableJobObject,
    RetainedProcessPathLease, UserOwnedPathLease, UserOwnedRootLease, WindowsPlatform,
};
use eliot_process::{
    ActionLeaseRef, CancellationStatus, DispatchAuthorityId, DispatchValidationContext,
    EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionAdmissionRequest, ProcessExecutionError, ProcessExecutor, ProcessIntent,
    ProcessLaunchAdmission, ProcessLifecycle, ProcessOwnerBinding, ProcessRequest,
    ProcessSessionBinding, ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
    SuspendedLaunchEvidence, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};
use eliot_runtime::{Runtime, RuntimeConfig, ShutdownOutcome};
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, GenerationCutoverRecord as RuntimeGenerationCutoverRecord,
    GenerationCutoverState, HealthVector, LeaseState, ModuleGeneration, ModuleGenerationState,
    SupervisionLease, SupervisionLeaseActiveStateBinding, SupervisionLeaseError,
    SupervisionLeasePredecessorProof, SupervisionLeaseSigner, SupervisionLeaseVerificationContext,
    SupervisionLeaseVerifier, SupervisionTrustAnchor,
};
use eliot_store_api::{
    CanonicalStoreClient, CanonicalValidationSnapshot, OrderingHeadExpectation, PreparedTransition,
    RevisionHead, RevisionHeadExpectation, StateFence as StoreStateFence, StoreError, StoreHealth,
    StoreHealthStatus, WriteReceipt, canonical_json_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use eliot_ipc::{NamedPipeServer, NamedPipeTransport};
#[cfg(windows)]
use eliot_platform_windows::{
    NamedPipePeerExpectation, current_process_named_pipe_expectation,
    observe_named_pipe_peer_process, observe_named_pipe_peer_process_in_job,
};

/// Stable Kernel process identity and wire revision.
pub const SERVICE_NAME: &str = "eliot-kernel";
pub const PROTOCOL_VERSION: &str = "eliot.kernel.v1";
pub const DEFAULT_PIPE_NAME: &str = KERNEL_CONTROL_PIPE;
const STORE_BRIDGE_ROUTE: &str = "store_bridge";
const ACTIVE_DAEMON_CALLER: &str = "eliotd";
const ELIOTD_RECEIPT_PENDING_DEPENDENCY: &str = "eliotd-process-receipt";
const ELIOTD_RECEIPT_PENDING_REASON: &str = "exact launched process receipt publication is pending";
#[cfg(windows)]
const ELIOTD_MAX_RECOVERY_ATTEMPTS: u64 = 1;

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

/// Host-approved protected key reference and installation-pinned public trust
/// anchor for Kernel-owned supervision leases.
///
/// The reference identifies a Windows Credential Manager item; it never
/// carries the signing seed.  The public key is safe to retain in the
/// installation binding and is used to reject a substituted/missing secret
/// before any ORS ticket is signed.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionLeaseAuthorityConfig {
    pub key_reference: SecretReference,
    pub trust_anchor: SupervisionTrustAnchor,
}

#[cfg(windows)]
impl SupervisionLeaseAuthorityConfig {
    /// Validates the secret-provider contour before Credential Manager is
    /// touched.  The key itself is checked by the Kernel authority at
    /// construction and before every signing operation.
    pub fn validate(&self) -> Result<(), String> {
        self.trust_anchor
            .validate()
            .map_err(|error| error.to_string())?;
        if self.key_reference.provider.as_str() != "windows-credential-manager" {
            return Err("supervision signing requires Windows Credential Manager".to_owned());
        }
        Ok(())
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
    /// Host/installer-approved `eliotd` child launch contour.  Integrated
    /// startup must inject this explicitly; there is no path or argv default.
    pub daemon_launch: Option<EliotdLaunchDescriptor>,
    /// Independent digest of the Kernel executable advertised in the
    /// daemon's generation snapshot. This is a different artifact domain
    /// from the `eliotd` child executable digest.
    pub kernel_artifact_sha256: Option<String>,
    /// Host-approved protected supervision signing authority.  The absence of
    /// this binding keeps the lease surface unavailable; no in-memory or test
    /// signer is fabricated by the production composition.
    #[cfg(windows)]
    pub supervision_lease_authority: Option<SupervisionLeaseAuthorityConfig>,
}

impl KernelConfig {
    /// Creates the production configuration using the canonical pipe.
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            store_bootstrap: None,
            daemon_launch: None,
            kernel_artifact_sha256: None,
            #[cfg(windows)]
            supervision_lease_authority: None,
        }
    }

    /// Injects the Host-approved canonical-store bootstrap requirement.
    #[must_use]
    pub fn with_store_bootstrap(mut self, requirement: HostStoreBootstrapRequirement) -> Self {
        self.store_bootstrap = Some(requirement);
        self
    }

    /// Selects the trusted launch-context control pipe for this Kernel
    /// generation. Production Host launch strips inherited overrides before
    /// injecting this value.
    #[must_use]
    pub fn with_pipe_name(mut self, pipe_name: impl Into<String>) -> Self {
        self.pipe_name = pipe_name.into();
        self
    }

    /// Injects the exact approved `eliotd` child launch descriptor.
    #[must_use]
    pub fn with_daemon_launch(mut self, launch: EliotdLaunchDescriptor) -> Self {
        self.daemon_launch = Some(launch);
        self
    }

    /// Injects the independently approved Kernel executable digest.
    #[must_use]
    pub fn with_kernel_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.kernel_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the Host-approved protected supervision signer and trust
    /// anchor.  The seed itself is intentionally not part of this config.
    #[cfg(windows)]
    #[must_use]
    pub fn with_supervision_lease_authority(
        mut self,
        authority: SupervisionLeaseAuthorityConfig,
    ) -> Self {
        self.supervision_lease_authority = Some(authority);
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
    /// The current immutable launch binding. Recovery replaces this only
    /// after the previous process effect is known terminal; the original
    /// Host-approved descriptor remains retained in `daemon_launch`.
    daemon_active_launch: Mutex<Option<EliotdLaunchDescriptor>>,
    kernel_artifact_sha256: Option<String>,
    daemon_runtime: Mutex<DaemonRuntimeState>,
    daemon_status_changed: tokio::sync::Notify,
    #[cfg(windows)]
    daemon_recovery_gate: tokio::sync::Mutex<()>,
    #[cfg(windows)]
    daemon_recovery_attempts: AtomicU64,
    #[cfg(windows)]
    store_handoff: Mutex<Option<StoreBootstrapHandoff>>,
    approved_config_hash: Option<String>,
    canonical_store_claimed: AtomicBool,
    #[cfg(windows)]
    canonical_store_gateway: Mutex<Option<Arc<KernelStoreGateway>>>,
    #[cfg(windows)]
    supervision_lease_authority: Option<Arc<KernelSupervisionLeaseAuthority>>,
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

/// Kernel-held signer which reloads a 32-byte Ed25519 seed from the existing
/// Windows Credential Manager reference for each operation.  It retains no
/// seed bytes, has no serializable representation, and redacts its Debug view.
#[cfg(windows)]
pub struct ProtectedSupervisionLeaseSigner {
    platform: Arc<WindowsPlatform>,
    key_reference: SecretReference,
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
            .field("key_provider", &self.key_reference.provider.as_str())
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl ProtectedSupervisionLeaseSigner {
    fn new(
        platform: Arc<WindowsPlatform>,
        config: &SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, SupervisionLeaseAuthorityError> {
        config
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Configuration)?;
        let signer = Self {
            platform,
            key_reference: config.key_reference.clone(),
            signer_id: config.trust_anchor.signer_id.clone(),
            key_id: config.trust_anchor.key_id.clone(),
            expected_public_key_fingerprint: config.trust_anchor.public_key_fingerprint.clone(),
        };
        signer
            .load_signer()
            .map_err(|_| SupervisionLeaseAuthorityError::ProtectedKeyUnavailable)?;
        Ok(signer)
    }

    fn load_signer(&self) -> Result<Ed25519SupervisionLeaseSigner, SupervisionLeaseError> {
        let secret = self
            .platform
            .read_credential(self.key_reference.key.as_str())
            .map_err(|_| SupervisionLeaseError::Signing("protected key read failed".to_owned()))?;
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
    pub fn key_reference(&self) -> &SecretReference {
        &self.key_reference
    }
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
        platform: &Arc<WindowsPlatform>,
        config: SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        let signer = ProtectedSupervisionLeaseSigner::new(Arc::clone(platform), &config)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        Ok(Self {
            ors,
            signer,
            trust_anchor: config.trust_anchor,
        })
    }

    /// Returns the installation-pinned public trust anchor.
    pub fn trust_anchor(&self) -> &SupervisionTrustAnchor {
        &self.trust_anchor
    }

    /// Returns the protected key reference; no seed is exposed.
    pub fn key_reference(&self) -> &SecretReference {
        self.signer.key_reference()
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
            public_key_fingerprint: self.trust_anchor.public_key_fingerprint.clone(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: payload.revocation_id.clone(),
                revocation_epoch: payload.revocation_epoch,
            },
        }
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
    fenced: AtomicBool,
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
            fenced: AtomicBool::new(false),
        }
    }

    fn fence(&self) {
        self.fenced.store(true, Ordering::Release);
    }

    fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }

    /// Applies one already prepared transition after fixed Kernel admission.
    pub async fn apply(
        &self,
        context: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, String> {
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
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

    /// Reads and validates the retained canonical Store health observation.
    pub async fn health(&self) -> Result<StoreHealth, String> {
        let health = self
            .store
            .health()
            .await
            .map_err(|error| error.to_string())?;
        health.validate().map_err(|error| error.to_string())?;
        Ok(health)
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
        let authority_id = prepared.descriptor.authority_id.clone();
        let handoff = prepared.handoff.clone();
        let controller = Self::prepare_descriptor_controller(
            authority_id.clone(),
            prepared.key,
            Arc::clone(&ors) as Arc<dyn OperationalRecoveryStore>,
            Arc::clone(&codec),
            &snapshot_binding,
            &prepared.descriptor,
            &handoff,
        )
        .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        Self::consume_authority_handoff(&ors, &handoff)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        Self::assemble_with_process_controller(config, controller, snapshot_binding, ors, platform)
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
        Self::assemble_with_process_controller(
            config,
            controller,
            authority_config.snapshot_binding,
            ors,
            platform,
        )
    }

    fn assemble_with_process_controller(
        config: KernelConfig,
        controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
        snapshot_binding: AuthoritySnapshotBinding,
        ors: Arc<RedbRecoveryStore>,
        platform: Arc<WindowsPlatform>,
    ) -> Result<Self, KernelBuildError> {
        let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
        let gateway = Arc::new(ProcessExecutionGateway::new(
            controller,
            Arc::clone(&ors),
            snapshot_binding,
            path_admission,
        ));
        Self::assemble(config, ors, Some(gateway), platform)
    }

    /// Reconciles the durable activation intent and replay snapshot before a
    /// process gateway is constructed.  A Reserved handoff with no snapshot
    /// is the only clean-boot path and is admitted only while its immutable
    /// descriptor is fresh.  An exact snapshot proves that activation had
    /// already reached its durable boundary, so restart recovery is allowed
    /// after the one-shot admission interval has elapsed.
    fn prepare_descriptor_controller(
        authority_id: DispatchAuthorityId,
        key: KernelDispatchKey,
        store: Arc<dyn OperationalRecoveryStore>,
        codec: Arc<dyn DispatchSnapshotCodec>,
        binding: &AuthoritySnapshotBinding,
        descriptor: &ProcessAuthorityHandoffDescriptor,
        handoff: &AuthorityHandoffRecord,
    ) -> eliot_kernel_core::KernelResult<Arc<Mutex<ProcessDispatchAuthorityController>>> {
        match handoff.state {
            AuthorityHandoffState::Consumed => ProcessDispatchAuthorityController::restore(
                authority_id,
                key,
                store,
                codec,
                binding,
            )
            .map(|controller| Arc::new(Mutex::new(controller))),
            AuthorityHandoffState::Reserved => {
                if ProcessDispatchAuthorityController::exact_snapshot_present(
                    &authority_id,
                    store.as_ref(),
                    binding,
                )? {
                    return ProcessDispatchAuthorityController::restore(
                        authority_id,
                        key,
                        store,
                        codec,
                        binding,
                    )
                    .map(|controller| Arc::new(Mutex::new(controller)));
                }
                let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
                if !Self::authority_descriptor_is_fresh(descriptor, now) {
                    return Err(KernelError::RecoveryUnavailable(
                        "fresh authority admission interval is not active".to_owned(),
                    ));
                }
                ProcessDispatchAuthorityController::activate_and_persist_initial(
                    authority_id,
                    key,
                    store,
                    codec,
                    binding,
                )
                .map(|controller| Arc::new(Mutex::new(controller)))
            }
            AuthorityHandoffState::Unknown => Err(KernelError::RecoveryUnavailable(
                "authority handoff outcome is unknown and requires reconciliation".to_owned(),
            )),
        }
    }

    /// Commits the terminal handoff only after the controller has proven an
    /// exact durable replay snapshot.  An uncertain consume write is
    /// reconciled by rereading ORS; a committed Consumed record is accepted
    /// idempotently, while Reserved/Unknown are left untouched and fail
    /// closed.  In particular, this path never demotes a possible Consumed
    /// record to Unknown.
    fn consume_authority_handoff(
        ors: &RedbRecoveryStore,
        handoff: &AuthorityHandoffRecord,
    ) -> Result<(), AuthorityPreparationError> {
        let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        let consumed = AuthorityHandoffRecord {
            state: AuthorityHandoffState::Consumed,
            consumed_at_ms: Some(now),
            ..handoff.clone()
        };
        if ors.persist_authority_handoff(&consumed).is_ok() {
            return Ok(());
        }
        let observed = ors
            .load_authority_handoff(&consumed.handoff_id)
            .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?
            .ok_or(AuthorityPreparationError::PersistenceUnknown)?;
        if observed.state == AuthorityHandoffState::Consumed
            && Self::same_authority_handoff_identity(&observed, &consumed)
        {
            return Ok(());
        }
        if observed.state == AuthorityHandoffState::Unknown {
            return Err(AuthorityPreparationError::Replay);
        }
        Err(AuthorityPreparationError::PersistenceUnknown)
    }

    fn same_authority_handoff_identity(
        left: &AuthorityHandoffRecord,
        right: &AuthorityHandoffRecord,
    ) -> bool {
        left.handoff_id == right.handoff_id
            && left.descriptor_digest == right.descriptor_digest
            && left.authority_id == right.authority_id
            && left.snapshot_record_id == right.snapshot_record_id
            && left.snapshot_binding_digest == right.snapshot_binding_digest
            && left.authority_epoch == right.authority_epoch
            && left.generation == right.generation
            && left.state_fence_digest == right.state_fence_digest
            && left.secret_reference_identity_digest == right.secret_reference_identity_digest
            && left.issued_at_ms == right.issued_at_ms
            && left.expires_at_ms == right.expires_at_ms
    }

    fn authority_descriptor_is_fresh(
        descriptor: &ProcessAuthorityHandoffDescriptor,
        now_ms: i64,
    ) -> bool {
        descriptor.issued_at_ms <= now_ms && now_ms < descriptor.expires_at_ms
    }

    /// Reads, validates, and reserves one protected authority descriptor.
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
        descriptor
            .validate_structure()
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        let candidate = Self::authority_handoff_candidate(&descriptor)?;

        // Inspect the immutable handoff identity before touching Credential
        // Manager. An exact existing handoff is replay evidence and may be
        // recovered after its admission interval; only an absent handoff is
        // required to be fresh before the credential boundary is crossed.
        let existing = ors
            .load_authority_handoff(&candidate.handoff_id)
            .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?;
        if let Some(existing) = &existing {
            if !Self::same_authority_handoff_identity(existing, &candidate) {
                return Err(AuthorityPreparationError::Replay);
            }
        } else {
            let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
            if !Self::authority_descriptor_is_fresh(&descriptor, now) {
                return Err(AuthorityPreparationError::DescriptorNotFresh);
            }
        }

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

        let outcome = match ors.begin_authority_handoff_fresh(&candidate) {
            Ok(outcome) => outcome,
            Err(OrsError::AuthorityHandoffNotFresh) => {
                return Err(AuthorityPreparationError::DescriptorNotFresh);
            }
            Err(_) => return Err(AuthorityPreparationError::PersistenceUnknown),
        };
        let handoff = match outcome {
            AuthorityHandoffBegin::Acquired => candidate,
            AuthorityHandoffBegin::Existing(existing) => match existing.state {
                AuthorityHandoffState::Reserved | AuthorityHandoffState::Consumed => existing,
                AuthorityHandoffState::Unknown => return Err(AuthorityPreparationError::Replay),
            },
        };
        Ok(PreparedAuthorityMaterial {
            descriptor,
            key,
            handoff,
        })
    }

    fn authority_handoff_candidate(
        descriptor: &ProcessAuthorityHandoffDescriptor,
    ) -> Result<AuthorityHandoffRecord, AuthorityPreparationError> {
        let handoff_id = eliot_ors::OperationIdentity::new(descriptor.handoff_id.as_str())
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        Ok(AuthorityHandoffRecord {
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
        })
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
        let daemon_launch = config.daemon_launch.clone();
        let kernel_artifact_sha256 = config.kernel_artifact_sha256.clone();
        if let Some(launch) = &daemon_launch {
            launch
                .validate()
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            if store_bootstrap.as_ref().is_some_and(|requirement| {
                requirement.state_fence.authority_epoch != launch.authority_epoch
                    || requirement.state_fence.resource_generation != launch.generation
            }) {
                return Err(KernelBuildError::Service(
                    "eliotd launch descriptor does not match Store bootstrap fence".to_owned(),
                ));
            }
        }
        if let Some(digest) = &kernel_artifact_sha256
            && !is_lower_sha256(digest)
        {
            return Err(KernelBuildError::Service(
                "Kernel artifact digest must be lowercase SHA-256".to_owned(),
            ));
        }
        if daemon_launch.is_some() && kernel_artifact_sha256.is_none() {
            return Err(KernelBuildError::Service(
                "integrated eliotd launch requires an independent Kernel artifact digest"
                    .to_owned(),
            ));
        }
        // The integrated contour has no environment/default authority. The
        // daemon config digest is carried by the Host-approved launch
        // descriptor and is checked again by eliotd when its retained file is
        // opened. Standalone test compositions intentionally have no approved
        // config hash and therefore cannot admit an integrated daemon.
        let approved_config_hash = daemon_launch
            .as_ref()
            .map(|launch| launch.config_descriptor_sha256.clone());
        #[cfg(windows)]
        let supervision_lease_authority = config
            .supervision_lease_authority
            .clone()
            .map(|authority| {
                KernelSupervisionLeaseAuthority::new(Arc::clone(&ors), &platform, authority)
            })
            .transpose()?;
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
        let artifact_id = daemon_launch
            .as_ref()
            .map_or_else(
                || ArtifactId::new("eliot-kernel-standalone"),
                |launch| ArtifactId::new(launch.executable_sha256.clone()),
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let module_generation = ModuleGeneration {
            module_id: module_id.clone(),
            generation,
            artifact_id,
            state: ModuleGenerationState::Starting,
            health: HealthVector::healthy(),
            state_fence: StateFence::new(authority_epoch, generation),
        };
        #[cfg(windows)]
        let session_principal_binding = observed_session_principal_binding()?;
        #[cfg(not(windows))]
        let session_principal_binding = "unsupported-non-windows-principal".to_owned();
        let front_door_policy = ServerHandshakePolicy {
            protocol_range: eliot_protocol::ProtocolRange {
                minimum: eliot_protocol::ProtocolVersion::CURRENT,
                maximum: eliot_protocol::ProtocolVersion::CURRENT,
            },
            module_id: module_id.as_str().to_owned(),
            module_generation,
            launch_nonce: daemon_launch.as_ref().map_or_else(
                || format!("kernel-{}", std::process::id()),
                |launch| launch.launch_nonce.as_str().to_owned(),
            ),
            allowed_capabilities: vec!["daemon".to_owned()],
            allowed_privacy_classes: vec!["PUBLIC".to_owned()],
            allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
            session_principal_binding,
            control_channel: ipc.name().to_owned(),
            heartbeat_ms: 1_000,
            config_snapshot: serde_json::json!({
                "service": SERVICE_NAME,
                "protocol": PROTOCOL_VERSION,
                "generation": generation.value(),
                "authority_epoch": authority_epoch.value(),
                "artifact_digest": kernel_artifact_sha256
                    .as_deref()
                    .unwrap_or("eliot-kernel-standalone"),
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
            daemon_active_launch: Mutex::new(daemon_launch.clone()),
            daemon_launch,
            kernel_artifact_sha256,
            daemon_runtime: Mutex::new(DaemonRuntimeState {
                status: DaemonRuntimeStatus::NotLaunched,
                receipt: None,
                recovery_fenced: false,
            }),
            daemon_status_changed: tokio::sync::Notify::new(),
            #[cfg(windows)]
            daemon_recovery_gate: tokio::sync::Mutex::new(()),
            #[cfg(windows)]
            daemon_recovery_attempts: AtomicU64::new(0),
            #[cfg(windows)]
            store_handoff: Mutex::new(None),
            approved_config_hash,
            canonical_store_claimed: AtomicBool::new(false),
            #[cfg(windows)]
            canonical_store_gateway: Mutex::new(None),
            #[cfg(windows)]
            supervision_lease_authority: supervision_lease_authority.map(Arc::new),
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

    #[cfg(windows)]
    /// Retains the one fresh post-launch Store process/Job handoff.
    pub fn install_store_bootstrap(
        &self,
        handoff: StoreBootstrapHandoff,
    ) -> Result<(), KernelBuildError> {
        handoff
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if self.store_bootstrap.as_ref() != Some(&handoff.requirement) {
            return Err(KernelBuildError::Service(
                "Store handoff does not match the immutable bootstrap descriptor".to_owned(),
            ));
        }
        let mut retained = self
            .store_handoff
            .lock()
            .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?;
        if retained.is_some() {
            return Err(KernelBuildError::Service(
                "Store bootstrap handoff is already retained".to_owned(),
            ));
        }
        *retained = Some(handoff);
        Ok(())
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
        {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if service.state() != eliot_kernel_service::KernelServiceState::Ready {
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
        let receipt = self
            .service
            .lock()
            .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?
            .rebind_store(&handoff, request_digest.clone())
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
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
        let gateway = std::sync::Arc::new(KernelStoreGateway::new(
            self.service.clone(),
            std::sync::Arc::new(client),
            route,
        ));
        let attachment_result: Result<
            Box<dyn CanonicalStoreAttachmentTransaction>,
            KernelBuildError,
        > = self.process_gateway.as_ref().map_or_else(
            || {
                struct NoopAttachment;
                impl CanonicalStoreAttachmentTransaction for NoopAttachment {
                    fn commit(self: Box<Self>) {}
                }
                Ok(Box::new(NoopAttachment) as Box<dyn CanonicalStoreAttachmentTransaction>)
            },
            |pg| {
                pg.attach_canonical_store(Arc::clone(&gateway))
                    .map(|a| Box::new(a) as Box<dyn CanonicalStoreAttachmentTransaction>)
                    .map_err(|e| KernelBuildError::Service(e.to_string()))
            },
        );
        let attachment: Box<dyn CanonicalStoreAttachmentTransaction> = match attachment_result {
            Ok(attachment) => attachment,
            Err(error) => {
                gateway.fence();
                return Err(error);
            }
        };
        let old_gateway =
            {
                let mut gw_guard = self.canonical_store_gateway.lock().map_err(|_| {
                    KernelBuildError::Service("store gateway lock poisoned".to_owned())
                })?;
                let old = gw_guard.replace(gateway);
                let mut handoff_guard = self.store_handoff.lock().map_err(|_| {
                    KernelBuildError::Service("Store handoff lock poisoned".to_owned())
                })?;
                *handoff_guard = Some(eliot_kernel_service::StoreBootstrapHandoff {
                    requirement: handoff.requirement.clone(),
                    process_binding: handoff.process_binding.clone(),
                });
                old
            };
        attachment.commit();
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
        }
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
        if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Ready;
        drop(state);
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
        drop(state);
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
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?
            .clone()
            .ok_or(KernelBuildError::StoreBootstrapRequired)?;
        requirement
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let process = &handoff.process_binding.process;
        let observed = observe_named_pipe_peer_process_in_job(
            handoff.process_binding.job.as_str(),
            process.process_id,
        )
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        if observed.process_binding().process_id() != process.process_id
            || observed.process_binding().start_time_100ns() != process.start_time_100ns
            || observed.process_binding().image_path() != process.image_path
        {
            return Err(KernelBuildError::Principal(
                "Store process binding changed before pipe admission".to_owned(),
            ));
        }
        let expectation = NamedPipePeerExpectation::new_with_process_and_job_binding(
            requirement.expected_peer_sid.as_str(),
            requirement.expected_peer_session_id,
            observed,
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
        #[cfg(windows)]
        if client.module_bridge_identity == ACTIVE_DAEMON_CALLER {
            self.validate_eliotd_peer(&peer, client)?;
        }
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Session::establish_with_server(connection_id, peer, client, &policy)
    }

    #[cfg(windows)]
    fn validate_eliotd_peer(
        &self,
        peer: &PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        let launch = self
            .active_daemon_launch()
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_eliotd_client_binding(&launch, &policy, client)?;
        drop(policy);
        let peer_binding = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        let receipt = {
            let state = self
                .daemon_runtime
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            Self::published_daemon_receipt(&state)?
        };
        receipt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let physical = receipt.identity().physical();
        if receipt.accepted_generation().get() != launch.generation.value()
            || receipt.binding().state_fence().authority_epoch() != launch.authority_epoch.value()
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || peer_binding.process_id() != physical.process_id()
            || peer_binding.start_time_100ns() != physical.start_time_100ns()
            || !peer_binding
                .image_path()
                .eq_ignore_ascii_case(physical.image_path())
        {
            return Err(TransportError::SessionFenced);
        }
        let observed = observe_named_pipe_peer_process_in_job(
            physical.executor_job_name(),
            physical.process_id(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let observed_binding = observed.process_binding();
        if observed_binding.process_id() != peer_binding.process_id()
            || observed_binding.start_time_100ns() != peer_binding.start_time_100ns()
            || observed_binding.start_time_100ns() != physical.start_time_100ns()
            || !observed_binding
                .image_path()
                .eq_ignore_ascii_case(physical.image_path())
            || !observed_binding
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn validate_eliotd_client_binding(
        launch: &EliotdLaunchDescriptor,
        policy: &ServerHandshakePolicy,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        if client.artifact_hash.as_str() != policy.module_generation.artifact_id.as_str()
            || client.module_generation.artifact_id.as_str() != launch.executable_sha256.as_str()
            || client.module_generation.generation != launch.generation
            || client.authority_epoch != launch.authority_epoch
            || client.launch_nonce.as_str() != launch.launch_nonce.as_str()
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
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

    #[cfg(windows)]
    fn published_daemon_receipt(
        state: &DaemonRuntimeState,
    ) -> Result<ProcessStartReceipt, TransportError> {
        match (&state.status, &state.receipt) {
            (DaemonRuntimeStatus::Launching, None) => Err(TransportError::PlanGap {
                dependency: ELIOTD_RECEIPT_PENDING_DEPENDENCY,
                reason: ELIOTD_RECEIPT_PENDING_REASON,
            }),
            (_, Some(receipt)) => Ok(receipt.clone()),
            _ => Err(TransportError::SessionFenced),
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

    /// Runs the currently admitted, deliberately closed semantic gateway.
    ///
    /// Heartbeats are handled locally. Other validated frames, including
    /// shutdown requests, are rejected and fenced until the durable
    /// execution gateway is supplied; this boundary never fabricates
    /// execution success or accepts a peer-owned shutdown authority.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed dispatch matrix keeps session, identity, and service-state gates in one auditable order"
    )]
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
        #[cfg(windows)]
        self.require_current_daemon_session(session)?;
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

        if frame.kind == FrameKind::Request && frame.message_type == MessageType::Execute {
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => return Err(TransportError::SessionFenced),
            };
            let operation = payload
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or(TransportError::SessionFenced)?;
            if session.module_generation.module_id.as_str() == ACTIVE_DAEMON_CALLER
                && matches!(
                    operation,
                    "snapshot" | "daemon_ready" | "health" | "daemon_degraded" | "daemon_fatal"
                )
            {
                if !probe_ready_state_admitted(
                    self.service_state()
                        .map_err(|_| TransportError::SessionFenced)?,
                ) {
                    return Err(TransportError::SessionFenced);
                }
                let identity = frame
                    .request_identity
                    .as_ref()
                    .ok_or(TransportError::SessionFenced)?;
                if !session
                    .module_generation
                    .state_fence
                    .is_compatible_with(&identity.request.state_fence)
                {
                    return Err(TransportError::SessionFenced);
                }
                return Ok(KernelFrameAction::Daemon {
                    request_id,
                    operation: operation.to_owned(),
                    payload,
                });
            }
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

    /// Executes one authenticated daemon lifecycle request.  Only the
    /// narrow handshake/health dispositions are handled here; semantic
    /// Governor mutations remain owned by `eliotd` and the existing Kernel
    /// transition gateway.
    pub async fn execute_daemon_request(
        &self,
        session: &Session,
        request_id: RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.require_current_daemon_session(session)?;
        let result = match operation {
            "snapshot" => self.daemon_snapshot().map(|value| {
                serde_json::json!({
                    "status": "known",
                    "value": value,
                    "recovery": null,
                })
            }),
            "daemon_ready" => {
                let generation = payload
                    .get("generation")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(TransportError::SessionFenced)?;
                let authority_epoch = payload
                    .get("authority_epoch")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(TransportError::SessionFenced)?;
                if generation != session.module_generation.generation.value()
                    || authority_epoch != session.authority_epoch
                {
                    return Err(TransportError::SessionFenced);
                }
                #[cfg(windows)]
                self.validate_authenticated_daemon_ready()
                    .await
                    .map_err(|_| TransportError::SessionFenced)?;
                self.mark_daemon_ready()
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "health" => self
                .daemon_health()
                .await
                .map_err(|_| TransportError::SessionFenced)
                .map(|value| {
                    serde_json::json!({
                        "status": "known",
                        "value": value,
                        "recovery": null,
                    })
                }),
            "daemon_degraded" => {
                let reason = payload
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 512
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?
                    .to_owned();
                self.mark_daemon_degraded(reason)
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "daemon_fatal" => {
                let reason = payload
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 512
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?
                    .to_owned();
                self.mark_daemon_failed(reason)
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            _ => return Err(TransportError::SessionFenced),
        };
        let value = result.map_err(|_| TransportError::SessionFenced)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        frame.request_id = Some(request_id);
        frame.validate()?;
        Ok(frame)
    }

    fn accepted_daemon_response() -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": true },
            "recovery": null,
        })
    }

    fn daemon_snapshot(&self) -> Result<serde_json::Value, TransportError> {
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let kernel_artifact_digest = policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?;
        Ok(serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": policy.module_generation.generation.value(),
            "authority_epoch": policy.module_generation.state_fence.authority_epoch.value(),
            // This is the Kernel peer artifact domain. The daemon child
            // artifact remains in module_generation.artifact_id and ClientHello.
            "artifact_digest": kernel_artifact_digest,
        }))
    }

    #[cfg(windows)]
    async fn daemon_health(&self) -> Result<eliot_store_api::StoreHealth, KernelServiceError> {
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| KernelServiceError::Platform("store gateway lock poisoned".to_owned()))?
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        gateway.health().await.map_err(KernelServiceError::Platform)
    }

    #[cfg(not(windows))]
    async fn daemon_health(&self) -> Result<eliot_store_api::StoreHealth, KernelServiceError> {
        Err(KernelServiceError::ReadinessNotProven)
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

    #[cfg(windows)]
    fn validate_candidate_process_binding(
        &self,
        candidate: &HostKernelCandidateBinding,
    ) -> Result<(), KernelServiceError> {
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
    async fn validate_authenticated_daemon_ready(&self) -> Result<(), KernelServiceError> {
        let Some(launch) = self.active_daemon_launch()? else {
            return Ok(());
        };
        let receipt = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?
            .receipt
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        self.validate_daemon_process_readiness(&launch, &receipt)
            .await
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

    /// Applies one authenticated Host control request after binding the
    /// transport's handle-proven peer and the approved generation contour.
    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated control handler preserves one visible validation and command-order boundary"
    )]
    pub async fn apply_control_request(
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
            || request.candidate.pipe_identity.as_str() != self.ipc.name()
            || observed_peer.process_id() != request.candidate.host_process.process_id
            || observed_peer.start_time_100ns() != request.candidate.host_process.start_time_100ns
            || observed_peer.image_path() != request.candidate.host_process.image_path
        {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.validate_candidate_process_binding(&request.candidate)
            .map_err(|_| TransportError::SessionFenced)?;
        let bootstrap = match &request.command {
            KernelControlCommand::BootstrapStore(handoff) => Some(handoff.clone()),
            _ => None,
        };
        {
            let mut policy = self
                .front_door_policy
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let reconcile = matches!(&request.command, KernelControlCommand::Reconcile);
            let policy_epoch = policy.module_generation.state_fence.authority_epoch;
            if request.generation != policy.module_generation.generation
                || request.candidate.kernel_epoch.value() < policy_epoch.value()
                || (!reconcile && request.candidate.kernel_epoch != policy_epoch)
                || self
                    .kernel_artifact_sha256
                    .as_deref()
                    .is_some_and(|digest| request.candidate.artifact_hash.as_str() != digest)
                || self
                    .approved_config_hash
                    .as_deref()
                    .is_some_and(|hash| hash != request.candidate.config_hash.as_str())
            {
                return Err(TransportError::SessionFenced);
            }
            if request.candidate.kernel_epoch != policy_epoch {
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .synchronize_authority_epoch(request.candidate.kernel_epoch)
                    .map_err(|_| TransportError::SessionFenced)?;
                policy.module_generation.state_fence =
                    StateFence::new(request.candidate.kernel_epoch, request.generation);
            }
        }
        if let Some(handoff) = bootstrap {
            self.install_store_bootstrap(handoff.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if let Err(error) = self
                .connect_canonical_store(Duration::from_millis(handoff.requirement.timeout_ms()))
                .await
            {
                if let Ok(mut retained) = self.store_handoff.lock() {
                    *retained = None;
                }
                let _ = error;
                return Err(TransportError::SessionFenced);
            }
        }
        let store_rebind_receipt: Option<eliot_kernel_service::StoreRebindReceipt> =
            match &request.command {
                KernelControlCommand::RebindStore(handoff) => {
                    let receipt = self
                        .rebind_store(handoff.clone(), request.payload_digest.clone())
                        .await
                        .map_err(|_| TransportError::SessionFenced)?;
                    Some(receipt)
                }
                KernelControlCommand::ReconcileRebindStore(query) => self
                    .service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .reconcile_store_rebind(query)
                    .map_err(|_| TransportError::SessionFenced)?,
                _ => None,
            };
        let is_probe = matches!(&request.command, KernelControlCommand::ProbeReady);
        let receipt = if is_probe {
            #[cfg(windows)]
            {
                Some(
                    self.self_authored_ready_receipt(&request, peer)
                        .await
                        .map_err(|_| TransportError::SessionFenced)?,
                )
            }
            #[cfg(not(windows))]
            {
                return Err(TransportError::SessionFenced);
            }
        } else {
            None
        };
        let activation_receipt: Option<KernelActivationReceipt> = match &request.command {
            KernelControlCommand::Activate(permit) => Some(
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .activate_permit(permit, request.generation, request.payload_digest.clone())
                    .map_err(|_| TransportError::SessionFenced)?,
            ),
            KernelControlCommand::ReconcileActivation(query) => self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .reconcile_activation(query)
                .map_err(|_| TransportError::SessionFenced)?,
            _ => None,
        };
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::Activate(_))
            && self
                .active_daemon_launch()
                .map_err(|_| TransportError::SessionFenced)?
                .is_some()
        {
            let launched = self
                .launch_eliotd()
                .await
                .map_err(|_| TransportError::SessionFenced)?;
            self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout)
                .await
                .map_err(|_| TransportError::SessionFenced)?;
        }
        if let Some(receipt) = &receipt {
            self.service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .publish_ready(receipt.clone())
                .map_err(|_| TransportError::SessionFenced)?;
        } else {
            match &request.command {
                KernelControlCommand::Reconcile => self
                    .service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .reconcile(request.candidate.clone())
                    .map_err(|_| TransportError::SessionFenced)?,
                KernelControlCommand::BootstrapStore(_)
                | KernelControlCommand::Activate(_)
                | KernelControlCommand::ReconcileActivation(_)
                | KernelControlCommand::RebindStore(_)
                | KernelControlCommand::ReconcileRebindStore(_) => {}
                command => {
                    self.apply_control(command.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                }
            }
        }
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
            activation_receipt,
            store_rebind_receipt,
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
        StateFenceSnapshot, SupervisionLeaseBinding,
    };
    use eliot_platform::{PlatformHandle, SecretReference};
    use eliot_process::{
        ActionLeaseRef, DispatchPermitAuthority, DispatchPermitReplaySnapshot,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, ImageId, JobId, OperationId,
        PermitIssuance, ProcessTreeId, ResourceLimits, SessionId,
    };
    use eliot_runtime_contracts::{
        ModuleContract, RegisteredActivityWakePolicy, SupervisionGenerationBinding,
        SupervisionLeaseTerminalDisposition, SupervisionObservationScope,
    };
    use eliot_store_api::{RevisionHead, RevisionKey};

    #[cfg(windows)]
    const BIND_SESSION_CHILD_PIPE_ENV: &str = "ELIOT_TEST_BIND_SESSION_CHILD_PIPE";
    #[cfg(windows)]
    const REAL_EXECUTOR_CHILD_ENV: &str = "ELIOT_TEST_REAL_EXECUTOR_CHILD";

    #[cfg(windows)]
    struct RealExecutorTestAuthority {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
        fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        issued_at_ms: u64,
    }

    #[cfg(windows)]
    impl RealExecutorTestAuthority {
        fn new(authority_id: DispatchAuthorityId) -> Self {
            let issued_at_ms = unix_ms();
            let generation = Generation::new(1).expect("generation");
            let fence =
                FencingToken::new(1, generation, "real-executor-test-fence").expect("test fence");
            let revision_heads = BTreeMap::from([("real-executor".to_owned(), "a".repeat(64))]);
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                    known_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                    transaction_sequence: None,
                    monotonic_ns: None,
                },
                fence.clone(),
                1,
                revision_heads.clone(),
                1,
            )
            .expect("test validation context");
            Self {
                authority: Mutex::new(DispatchPermitAuthority::activate(
                    authority_id,
                    KernelDispatchKey::from_secret_bytes([0x7e; 32]).expect("executor test key"),
                )),
                context,
                fence,
                revision_heads,
                issued_at_ms,
            }
        }

        fn issue(&self, admission: &ProcessExecutionAdmissionRequest) -> ProcessRequest {
            let issuance = PermitIssuance::new_with_validation_revision(
                admission.action_lease_ref().clone(),
                self.fence.clone(),
                self.revision_heads.clone(),
                self.issued_at_ms,
                admission.deadline_unix_ms(),
                format!(
                    "real-executor:{}",
                    admission.intent().operation_id().as_str()
                ),
                1,
            )
            .expect("permit issuance");
            let permit = self
                .authority
                .lock()
                .expect("test authority lock")
                .issue(admission.intent(), issuance)
                .expect("test dispatch permit");
            ProcessRequest::new(admission.intent().clone(), permit).expect("test process request")
        }
    }

    #[cfg(windows)]
    impl DispatchValidationPort for RealExecutorTestAuthority {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            self.authority
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable(
                        "real executor test authority lock poisoned".to_owned(),
                    )
                })?
                .validate_and_consume(request, observed, &self.context)
                .map_err(ProcessExecutionError::Contract)
        }
    }

    #[cfg(windows)]
    fn real_process_gateway(
        root: &Path,
        containment_root: &Path,
    ) -> (
        ProcessExecutionGateway,
        Arc<WindowsPlatform>,
        Arc<RealExecutorTestAuthority>,
    ) {
        std::fs::create_dir_all(root).expect("real gateway test root");
        let ors = Arc::new(
            RedbRecoveryStore::open(root.join("kernel-ors.redb")).expect("real gateway ORS store"),
        );
        let authority_id =
            DispatchAuthorityId::new("kernel-real-executor-authority").expect("authority id");
        let snapshot_binding = authority_binding(&authority_id);
        let authority_store: Arc<dyn OperationalRecoveryStore> = ors.clone();
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(JsonSnapshotCodec);
        let controller = Arc::new(Mutex::new(ProcessDispatchAuthorityController::activate(
            authority_id,
            KernelDispatchKey::from_secret_bytes([0x6d; 32]).expect("dispatch key"),
            authority_store,
            codec,
        )));
        let platform = Arc::new(
            WindowsPlatform::new(containment_root.to_path_buf())
                .expect("real gateway platform root"),
        );
        let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
        let test_authority = Arc::new(RealExecutorTestAuthority::new(
            DispatchAuthorityId::new("kernel-real-executor-test-permit")
                .expect("test permit authority"),
        ));
        let validation_port: Arc<dyn DispatchValidationPort> = test_authority.clone();
        let launch_admission: Arc<dyn ProcessLaunchAdmission> = path_admission.clone();
        let mut gateway =
            ProcessExecutionGateway::new(controller, ors, snapshot_binding, path_admission);
        gateway.executor =
            WindowsProcessExecutor::new_with_launch_admission(validation_port, launch_admission);
        (gateway, platform, test_authority)
    }

    #[cfg(windows)]
    fn real_executor_admission(
        executable: &Path,
        executable_sha256: &str,
        operation: &str,
        child_test: &str,
        environment: BTreeMap<String, String>,
    ) -> ProcessExecutionAdmissionRequest {
        let generation = Generation::new(1).expect("generation");
        let working_directory = executable.parent().expect("test executable parent");
        let intent = ProcessIntent::new(
            OperationId::new(operation).expect("operation id"),
            ProcessTreeId::new(format!("real-executor-tree-{operation}")).expect("process tree"),
            JobId::new(format!("real-executor-logical-job-{operation}")).expect("logical Job id"),
            ImageId::new(format!("real-executor-image-{operation}")).expect("image id"),
            SessionId::new(format!("real-executor-session-{operation}")).expect("session id"),
            generation,
            executable.to_string_lossy(),
            executable_sha256,
            vec![
                "--exact".to_owned(),
                child_test.to_owned(),
                "--nocapture".to_owned(),
            ],
            working_directory.to_string_lossy(),
            EnvironmentProjection::new(environment, Vec::new(), EnvironmentInheritance::None)
                .expect("closed child environment"),
            ResourceLimits::new(60_000, Some(30_000), None, 64 * 1024, 64 * 1024, 4)
                .expect("resource limits"),
        )
        .expect("real executor intent");
        ProcessExecutionAdmissionRequest::new(
            ACTIVE_DAEMON_CALLER,
            intent,
            ActionLeaseRef::new(format!("real-executor-lease-{operation}")).expect("action lease"),
            FencingToken::new(1, generation, format!("real-executor-fence-{operation}"))
                .expect("state fence"),
            unix_ms().saturating_add(60_000),
        )
        .expect("real executor admission")
    }

    #[cfg(windows)]
    fn real_executor_path_proof(
        platform: &WindowsPlatform,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> ProcessPathProof {
        let executable = PathBuf::from(admission.intent().executable());
        let working_directory = PathBuf::from(admission.intent().working_directory());
        let lease = platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .expect("retained real executor path proof");
        ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        }
    }

    #[cfg(windows)]
    async fn start_real_executor_child(
        gateway: &ProcessExecutionGateway,
        platform: &WindowsPlatform,
        authority: &RealExecutorTestAuthority,
        admission: &ProcessExecutionAdmissionRequest,
        owner: &ProcessOwnerBinding,
    ) -> ProcessStartReceipt {
        let request = authority.issue(admission);
        let path_guard = gateway
            .insert_path(
                admission.intent().operation_id().clone(),
                real_executor_path_proof(platform, admission),
            )
            .expect("retain path proof");
        let receipt = gateway
            .execute(owner, request)
            .await
            .expect("WindowsProcessExecutor start");
        drop(path_guard);
        receipt
    }

    #[test]
    fn runtime_probe_gate_admits_only_initial_repeat_and_recovery_states() {
        for state in [
            KernelServiceState::Activating,
            KernelServiceState::Ready,
            KernelServiceState::Degraded,
        ] {
            assert!(probe_ready_state_admitted(state));
        }
        for state in [
            KernelServiceState::Cold,
            KernelServiceState::Reconciling,
            KernelServiceState::ShadowNoAuthority,
            KernelServiceState::HandoffPrepared,
            KernelServiceState::Draining,
            KernelServiceState::Stopped,
            KernelServiceState::Failed,
            KernelServiceState::ManualRecovery,
        ] {
            assert!(!probe_ready_state_admitted(state));
        }
    }

    #[test]
    fn ready_receipt_rejects_absent_running_degraded_and_fatal_daemon_states() {
        assert!(daemon_status_proves_ready(&DaemonRuntimeStatus::Ready));
        for status in [
            DaemonRuntimeStatus::NotLaunched,
            DaemonRuntimeStatus::Launching,
            DaemonRuntimeStatus::Running,
            DaemonRuntimeStatus::Degraded("store unavailable".to_owned()),
            DaemonRuntimeStatus::Failed("fatal".to_owned()),
        ] {
            assert!(!daemon_status_proves_ready(&status));
        }
    }

    #[cfg(windows)]
    #[test]
    fn recovery_attempt_uses_fresh_nonce_descriptor_and_operation_identity() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-recovery-attempt-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let original = test_daemon_launch(&root);
        let first = fresh_eliotd_launch_descriptor(&original, 1).expect("first recovery launch");
        let second = fresh_eliotd_launch_descriptor(&first, 2).expect("second recovery launch");
        first.validate().expect("first descriptor remains exact");
        second.validate().expect("second descriptor remains exact");
        assert_ne!(original.launch_nonce, first.launch_nonce);
        assert_ne!(first.launch_nonce, second.launch_nonce);
        assert_eq!(first.arguments[5], first.launch_nonce);
        assert_eq!(second.arguments[5], second.launch_nonce);
        let first_identity = eliotd_launch_attempt_identity(&first, 41_001, 9_001, "kernel.exe")
            .expect("first launch identity");
        let second_identity = eliotd_launch_attempt_identity(&second, 41_001, 9_001, "kernel.exe")
            .expect("second launch identity");
        let first_operation = eliotd_operation_id(
            Generation::new(first.generation.value()).expect("generation"),
            &first_identity,
        )
        .expect("first operation");
        let second_operation = eliotd_operation_id(
            Generation::new(second.generation.value()).expect("generation"),
            &second_identity,
        )
        .expect("second operation");
        assert_ne!(first_operation, second_operation);
        assert_eq!(first.authority_epoch, original.authority_epoch);
        assert_eq!(first.generation, original.generation);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn recovery_nonce_rotation_fences_stale_daemon_sessions() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-recovery-session-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let original = test_daemon_launch(&root);
        let kernel = KernelComposition::new(
            KernelConfig::new(&root)
                .with_daemon_launch(original.clone())
                .with_kernel_artifact_sha256("c".repeat(64)),
        )
        .expect("kernel composition");
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let stale = Session {
            connection_id: "stale-eliotd-session".to_owned(),
            protocol_version: policy.protocol_range.maximum,
            peer: PeerIdentity::Unavailable {
                reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
            },
            authority_epoch: policy.module_generation.state_fence.authority_epoch.value(),
            module_generation: policy.module_generation.clone(),
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            effects: policy.allowed_effects.clone(),
            session_epoch: 1,
            state: eliot_ipc::SessionState::Open,
        };
        kernel
            .require_current_daemon_session(&stale)
            .expect("original session binding is current");
        let next = fresh_eliotd_launch_descriptor(&original, 1).expect("fresh recovery launch");
        *kernel
            .daemon_active_launch
            .lock()
            .expect("active launch lock") = Some(next.clone());
        kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .launch_nonce = next.launch_nonce.as_str().to_owned();
        assert!(matches!(
            kernel.require_current_daemon_session(&stale),
            Err(TransportError::SessionFenced)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn production_handshake_policy_binds_observed_current_process_principal() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-observed-principal-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let observed = current_process_named_pipe_expectation().expect("current process identity");
        let expected = format!(
            "sid={};session={}",
            observed.expected_sid(),
            observed.expected_session_id()
        );
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock");
        assert_eq!(policy.session_principal_binding, expected);
        assert_ne!(policy.session_principal_binding, "local-user");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_job_bind_session_child_connector() {
        let Ok(pipe_name) = std::env::var(BIND_SESSION_CHILD_PIPE_ENV) else {
            return;
        };
        let expectation = current_process_named_pipe_expectation().expect("child expectation");
        let _transport = NamedPipeTransport::connect_authenticated(
            &pipe_name,
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .expect("child authenticated connection");
        tokio::time::sleep(Duration::from_secs(30)).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn real_executor_receipt_child() {
        if std::env::var(REAL_EXECUTOR_CHILD_ENV).as_deref() != Ok("1") {
            return;
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the production discriminator must retain one real named Job child, authenticated pipe peer, receipt, and bind_session call"
    )]
    async fn bind_session_uses_physical_executor_job_not_logical_job_id() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-bind-session-job-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let executable = std::env::current_exe().expect("test executable");
        let executable_sha256 =
            sha256_hex(&std::fs::read(&executable).expect("read test executable"));
        let executable_handle =
            PlatformHandle::new(executable.to_string_lossy()).expect("test executable handle");
        let mut launch = test_daemon_launch(&root);
        launch.executable = executable_handle;
        launch.executable_sha256.clone_from(&executable_sha256);
        launch.working_directory = PlatformHandle::new(
            executable
                .parent()
                .expect("test executable parent")
                .to_string_lossy(),
        )
        .expect("working directory handle");
        launch.arguments[7] = PlatformHandle::new(launch.executable_sha256.clone())
            .expect("executable digest argument");
        launch.descriptor_sha256 = String::new();
        launch = launch.with_computed_digest().expect("test launch digest");
        let kernel = KernelComposition::new(
            KernelConfig::new(&root)
                .with_daemon_launch(launch.clone())
                .with_kernel_artifact_sha256("c".repeat(64)),
        )
        .expect("kernel composition");

        let expectation = current_process_named_pipe_expectation().expect("server expectation");
        let pipe_name = format!(
            r"\\.\pipe\eliot\kernel-bind-session-test\{}-{}",
            std::process::id(),
            unix_ms()
        );
        let mut server = NamedPipeServer::create(&pipe_name, &expectation).expect("test pipe");
        let containment_root = executable.parent().expect("test executable parent");
        let (gateway, platform, test_authority) =
            real_process_gateway(&root.join("real-executor"), containment_root);
        let operation = format!("bind-session-real-executor-{}", unix_ms());
        let admission = real_executor_admission(
            &executable,
            &executable_sha256,
            &operation,
            "tests::named_job_bind_session_child_connector",
            BTreeMap::from([(BIND_SESSION_CHILD_PIPE_ENV.to_owned(), pipe_name.clone())]),
        );
        let owner = gateway_test_owner();
        let receipt =
            start_real_executor_child(&gateway, &platform, &test_authority, &admission, &owner)
                .await;
        server
            .wait_for_authenticated_client(Duration::from_secs(5), &expectation)
            .await
            .expect("authenticated child peer");
        let peer = server.peer_identity().clone();
        {
            let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = Some(receipt.clone());
        }
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let client = test_client(&policy);
        kernel
            .bind_session("eliotd-real-job", peer.clone(), &client)
            .expect("physical Job-bound session");

        let mut substituted = serde_json::to_value(&receipt).expect("serialize actual receipt");
        substituted["identity"]["suspended"]["physical"]["executor_job_name"] =
            serde_json::Value::String(r"Local\Eliot-Missing-Executor-Job".to_owned());
        let missing_job_receipt: ProcessStartReceipt =
            serde_json::from_value(substituted).expect("structurally valid substituted receipt");
        missing_job_receipt
            .validate()
            .expect("substitution remains structurally valid but has no live OS Job proof");
        kernel
            .daemon_runtime
            .lock()
            .expect("daemon runtime lock")
            .receipt = Some(missing_job_receipt);
        assert!(
            kernel
                .bind_session("eliotd-logical-job-only", peer, &client)
                .is_err()
        );
        gateway
            .executor
            .shutdown()
            .expect("terminate real executor child Job");
        drop(gateway);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

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

    #[cfg(windows)]
    fn test_daemon_launch(root: &Path) -> EliotdLaunchDescriptor {
        let executable =
            PlatformHandle::new(root.join("eliotd.exe").to_string_lossy()).expect("eliotd path");
        let config = PlatformHandle::new(root.join("eliotd-governor.json").to_string_lossy())
            .expect("eliotd config path");
        let working_directory =
            PlatformHandle::new(root.to_string_lossy()).expect("working directory");
        let executable_sha256 = "a".repeat(64);
        let config_sha256 = "b".repeat(64);
        let nonce =
            PlatformHandle::new("eliotd:0123456789abcdef0123456789abcdef").expect("launch nonce");
        EliotdLaunchDescriptor {
            wire_id: "eliot.kernel.eliotd-launch".to_owned(),
            wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
            executable,
            executable_sha256: executable_sha256.clone(),
            arguments: vec![
                PlatformHandle::new("--config-descriptor").expect("argument"),
                config.clone(),
                PlatformHandle::new("--config-descriptor-sha256").expect("argument"),
                PlatformHandle::new(&config_sha256).expect("argument"),
                PlatformHandle::new("--launch-nonce").expect("argument"),
                nonce.clone(),
                PlatformHandle::new("--executable-sha256").expect("argument"),
                PlatformHandle::new(&executable_sha256).expect("argument"),
            ],
            working_directory,
            config_descriptor: config,
            config_descriptor_sha256: config_sha256,
            launch_nonce: nonce,
            authority_epoch: AuthorityEpoch::genesis(),
            generation: ResourceGeneration::genesis(),
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("descriptor digest")
    }

    #[cfg(windows)]
    fn test_process_start_receipt(pid: u32) -> ProcessStartReceipt {
        test_process_start_receipt_with_physical(
            pid,
            1,
            r"C:\ProgramData\Eliot\bin\eliotd.exe",
            r"Local\Eliot-P04-test",
        )
    }

    #[cfg(windows)]
    fn test_process_start_receipt_with_physical(
        pid: u32,
        start_time_100ns: u64,
        image_path: &str,
        executor_job_name: &str,
    ) -> ProcessStartReceipt {
        serde_json::from_value(serde_json::json!({
            "binding": {
                "operation_id": "eliotd-ready-test-operation",
                "process_tree_id": "eliotd-ready-test-tree",
                "job_id": "eliotd-ready-test-job",
                "image_id": "eliotd-ready-test-image",
                "session_id": "eliotd-ready-test-session",
                "generation": 1,
                "action_lease_ref": "eliotd-ready-test-lease",
                "authority_id": "eliotd",
                "authority_epoch": 1,
                "state_fence": {
                    "authority_epoch": 1,
                    "generation": 1,
                    "nonce": "eliotd-ready-test-fence"
                },
                "request_digest": "a".repeat(64),
                "permit_digest": "b".repeat(64),
                "effect_digest": "c".repeat(64),
                "validation_revision": 1
            },
            "identity": {
                "suspended": {
                    "process_id": "eliotd-ready-test-process",
                    "process_tree_id": "eliotd-ready-test-tree",
                    "job_id": "eliotd-ready-test-job",
                    "image_id": "eliotd-ready-test-image",
                "session_id": "eliotd-ready-test-session",
                "generation": 1,
                "physical": {
                    "process_id": pid,
                    "start_time_100ns": start_time_100ns,
                    "image_path": image_path,
                    "executor_job_name": executor_job_name
                },
                "created_suspended_at_unix_ms": 1,
                    "executable_sha256": "a".repeat(64)
                },
                "resumed_at_unix_ms": 2
            },
            "lifecycle": "running"
        }))
        .expect("test process start receipt")
    }

    #[cfg(windows)]
    #[test]
    fn eliotd_attempt_identity_is_stable_within_one_kernel_and_changes_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-attempt-identity-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let launch = test_daemon_launch(&root);
        let first = eliotd_launch_attempt_identity(
            &launch,
            41_001,
            9_001,
            r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
        )
        .expect("first attempt identity");
        let same = eliotd_launch_attempt_identity(
            &launch,
            41_001,
            9_001,
            r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
        )
        .expect("same attempt identity");
        let restarted = eliotd_launch_attempt_identity(
            &launch,
            41_001,
            9_002,
            r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
        )
        .expect("restarted attempt identity");
        assert_eq!(first, same);
        assert_ne!(first, restarted);
        assert_ne!(
            first,
            sha256_hex(launch.launch_nonce.as_str().as_bytes()),
            "the fixed descriptor nonce alone must never key a process effect replay"
        );
    }

    #[cfg(windows)]
    #[test]
    fn receipt_publication_race_is_retryable_only_for_exact_bound_client() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-receipt-race-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let launch = test_daemon_launch(&root);
        let kernel = KernelComposition::new(
            KernelConfig::new(&root)
                .with_daemon_launch(launch.clone())
                .with_kernel_artifact_sha256("c".repeat(64)),
        )
        .expect("kernel composition");
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let exact_client = test_client(&policy);
        KernelComposition::validate_eliotd_client_binding(&launch, &policy, &exact_client)
            .expect("exact descriptor-bound client");
        let mut substituted = exact_client.clone();
        substituted.launch_nonce = "eliotd:ffffffffffffffffffffffffffffffff".to_owned();
        assert!(matches!(
            KernelComposition::validate_eliotd_client_binding(&launch, &policy, &substituted),
            Err(TransportError::SessionFenced)
        ));

        let receipt = test_process_start_receipt(std::process::id());
        let mut state = DaemonRuntimeState {
            status: DaemonRuntimeStatus::Launching,
            receipt: None,
            recovery_fenced: false,
        };
        assert!(matches!(
            KernelComposition::published_daemon_receipt(&state),
            Err(TransportError::PlanGap {
                dependency: ELIOTD_RECEIPT_PENDING_DEPENDENCY,
                reason: ELIOTD_RECEIPT_PENDING_REASON,
            })
        ));
        state.status = DaemonRuntimeStatus::Running;
        state.receipt = Some(receipt.clone());
        assert_eq!(
            KernelComposition::published_daemon_receipt(&state).expect("published exact receipt"),
            receipt
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the production-bound handshake test proves success, timeout, and non-ready daemon states through one retained contour"
    )]
    async fn authenticated_handshake_and_bounded_ready_rendezvous_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-ready-rendezvous-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel =
            Arc::new(KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition"));
        let expectation = current_process_named_pipe_expectation().expect("current identity");
        let pipe_name = format!(
            r"\\.\pipe\eliot\kernel-ready-test\{}-{}",
            std::process::id(),
            unix_ms()
        );
        let mut server = NamedPipeServer::create(&pipe_name, &expectation).expect("test pipe");
        let server_expectation = expectation.clone();
        let server_task = tokio::spawn(async move {
            server
                .wait_for_authenticated_client(Duration::from_secs(2), &server_expectation)
                .await
                .expect("authenticated client");
            server
        });
        let _client = NamedPipeTransport::connect_authenticated(
            &pipe_name,
            Duration::from_secs(2),
            &expectation,
        )
        .await
        .expect("authenticated transport");
        let server = server_task.await.expect("server task");
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let handshake = Session::establish_with_server(
            "eliotd-ready-test",
            server.peer_identity().clone(),
            &test_client(&policy),
            &policy,
        )
        .expect("authenticated daemon handshake");
        assert_eq!(
            handshake.server_hello.session_principal_binding,
            observed_session_principal_binding().expect("observed binding")
        );

        let receipt = test_process_start_receipt(std::process::id());
        {
            let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = Some(receipt.clone());
        }
        let wait_kernel = Arc::clone(&kernel);
        let wait_receipt = receipt.clone();
        let waiter = tokio::spawn(async move {
            wait_kernel
                .await_daemon_ready(&wait_receipt, Duration::from_secs(1))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        assert!(
            kernel
                .execute_daemon_request(
                    &handshake.session,
                    RequestId::new("eliotd-ready-wrong-generation").expect("request id"),
                    "daemon_ready",
                    serde_json::json!({
                        "generation": policy.module_generation.generation.value() + 1,
                        "authority_epoch": policy
                            .module_generation
                            .state_fence
                            .authority_epoch
                            .value(),
                    }),
                )
                .await
                .is_err()
        );
        assert!(!waiter.is_finished());
        kernel
            .execute_daemon_request(
                &handshake.session,
                RequestId::new("eliotd-ready-exact").expect("request id"),
                "daemon_ready",
                serde_json::json!({
                    "generation": policy.module_generation.generation.value(),
                    "authority_epoch": policy
                        .module_generation
                        .state_fence
                        .authority_epoch
                        .value(),
                }),
            )
            .await
            .expect("authenticated ready report");
        waiter
            .await
            .expect("ready waiter task")
            .expect("ready rendezvous");

        let substituted = test_process_start_receipt(41_002);
        assert!(
            kernel
                .await_daemon_ready(&substituted, Duration::from_millis(10))
                .await
                .is_err()
        );

        {
            let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
            state.status = DaemonRuntimeStatus::Running;
        }
        assert!(
            kernel
                .await_daemon_ready(&receipt, Duration::from_millis(1))
                .await
                .is_err()
        );
        let state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        assert!(matches!(state.status, DaemonRuntimeStatus::Failed(_)));
        drop(state);
        assert_eq!(
            kernel
                .front_door_policy
                .lock()
                .expect("front-door policy")
                .launch_nonce,
            policy.launch_nonce
        );
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

        async fn completed_receipt(
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

    #[cfg(windows)]
    fn supervision_authority_binding(
        state: LeaseState,
        issued_at_ms: u64,
    ) -> Result<SupervisionLeaseBinding, Box<dyn std::error::Error>> {
        let terminal_disposition = match state {
            LeaseState::Released => Some(SupervisionLeaseTerminalDisposition::Released),
            LeaseState::Expired => Some(SupervisionLeaseTerminalDisposition::Expired),
            LeaseState::Revoked => Some(SupervisionLeaseTerminalDisposition::Revoked),
            LeaseState::Superseded => Some(SupervisionLeaseTerminalDisposition::Superseded),
            LeaseState::Closed => Some(SupervisionLeaseTerminalDisposition::Closed),
            LeaseState::Requested
            | LeaseState::Active
            | LeaseState::Expiring
            | LeaseState::Reconciling => None,
        };
        let revoked = state == LeaseState::Revoked;
        Ok(SupervisionLeaseBinding {
            scope_ref: OpaqueLabel::new("kernel-supervision-scope")?,
            observation_scope: SupervisionObservationScope {
                targets: vec!["kernel-target".to_owned()],
                sensor_profile: "kernel-supervision-test".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live".to_owned(),
            },
            installation_id: OpaqueLabel::new("installation-1")?,
            host_epoch: AuthorityEpoch::new(1)?,
            activation_id: OpaqueLabel::new("kernel-supervision-activation")?,
            activation_generation: ResourceGeneration::new(1)?,
            kernel_epoch: AuthorityEpoch::new(2)?,
            watchdog_epoch: AuthorityEpoch::new(1)?,
            generation_binding: SupervisionGenerationBinding {
                target_id: "kernel-target".to_owned(),
                target_generation: ResourceGeneration::new(1)?,
                module_id: "kernel-supervision-module".to_owned(),
                module_generation: ResourceGeneration::new(1)?,
                process_id: "eliot-kernel".to_owned(),
                process_generation: ResourceGeneration::new(1)?,
            },
            state_fence: StateFence::new(AuthorityEpoch::new(2)?, ResourceGeneration::new(1)?),
            issued_at_ms,
            expires_at_ms: issued_at_ms.saturating_add(120_000),
            renew_before_ms: issued_at_ms.saturating_add(60_000),
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            state,
            terminal_disposition,
            revocation_reason: revoked.then(|| "kernel supervision test revocation".to_owned()),
            revocation_id: revoked.then(|| "kernel-supervision-revocation".to_owned()),
            revocation_epoch: revoked.then(|| AuthorityEpoch::new(2)).transpose()?,
        })
    }

    #[cfg(windows)]
    fn supervision_authority_request(
        ticket_id: &str,
        operation_id: &str,
        lease_id: &str,
        expected_revision: Option<u64>,
        operation: SupervisionLeaseOperation,
        binding: SupervisionLeaseBinding,
    ) -> Result<SupervisionLeasePrepareRequest, Box<dyn std::error::Error>> {
        Ok(SupervisionLeasePrepareRequest {
            ticket_id: OpaqueLabel::new(ticket_id)?,
            operation_id: OpaqueLabel::new(operation_id)?,
            lease_id: OpaqueLabel::new(lease_id)?,
            expected_revision,
            operation,
            binding,
        })
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

    #[cfg(windows)]
    #[tokio::test]
    async fn stale_completed_restart_never_replays_and_new_attempt_starts_fresh() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-stale-completed-attempt-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let launch = test_daemon_launch(&root);
        let generation = Generation::new(launch.generation.value()).expect("generation");
        let old_attempt = eliotd_launch_attempt_identity(
            &launch,
            42_001,
            7_001,
            r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
        )
        .expect("old attempt");
        let restarted_attempt = eliotd_launch_attempt_identity(
            &launch,
            42_001,
            7_002,
            r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
        )
        .expect("restarted attempt");
        let old_operation =
            eliotd_operation_id(generation, &old_attempt).expect("old operation identity");
        let restarted_operation = eliotd_operation_id(generation, &restarted_attempt)
            .expect("restarted operation identity");
        assert_ne!(old_operation, restarted_operation);

        let ports = GatewayTestPorts::new(Ok(gateway_test_snapshot()));
        let owner = gateway_test_owner();
        run_process_start(
            &ports,
            &owner,
            gateway_test_admission(old_operation.as_str()),
            (),
        )
        .await
        .expect("old attempt start");
        assert!(
            run_process_start(
                &ports,
                &owner,
                gateway_test_admission(old_operation.as_str()),
                (),
            )
            .await
            .is_err(),
            "a Completed record without fresh live executor evidence must not replay"
        );
        assert_eq!(ports.counts().2, 1);
        run_process_start(
            &ports,
            &owner,
            gateway_test_admission(restarted_operation.as_str()),
            (),
        )
        .await
        .expect("restarted Kernel gets a fresh exact attempt");
        assert_eq!(ports.counts().2, 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart discriminator must exercise a live WindowsProcessExecutor receipt, durable Completed replay, a fresh production gateway inspect, and a new attempt"
    )]
    async fn real_gateway_completed_replay_requires_live_executor_inspection() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-real-completed-replay-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        let executable = std::env::current_exe().expect("test executable");
        let containment_root = executable.parent().expect("test executable parent");
        let executable_sha256 =
            sha256_hex(&std::fs::read(&executable).expect("read test executable"));
        let owner = gateway_test_owner();
        let old_operation = format!("real-completed-old-{}", unix_ms());
        let old_admission = real_executor_admission(
            &executable,
            &executable_sha256,
            &old_operation,
            "tests::real_executor_receipt_child",
            BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
        );
        let (old_gateway, old_platform, old_authority) =
            real_process_gateway(&root.join("old-kernel"), containment_root);
        let old_receipt = start_real_executor_child(
            &old_gateway,
            &old_platform,
            &old_authority,
            &old_admission,
            &owner,
        )
        .await;
        let completed_record = ProcessExecutionReplayRecord {
            admission_digest: process_admission_digest(&old_admission)
                .expect("old admission digest"),
            owner: owner.clone(),
            state: ProcessExecutionReplayState::Completed,
            receipt: Some(old_receipt.clone()),
        };
        let same_kernel_replay = old_gateway
            .completed_receipt(completed_record.clone())
            .await
            .expect("same Kernel live inspection")
            .expect("same Kernel exact Completed receipt");
        assert_eq!(same_kernel_replay, old_receipt);

        let (restarted_gateway, restarted_platform, restarted_authority) =
            real_process_gateway(&root.join("restarted-kernel"), containment_root);
        let stale = restarted_gateway.completed_receipt(completed_record).await;
        assert!(matches!(stale, Err(ProcessExecutionError::UnknownOutcome)));

        let new_operation = format!("real-completed-restarted-{}", unix_ms());
        let new_admission = real_executor_admission(
            &executable,
            &executable_sha256,
            &new_operation,
            "tests::real_executor_receipt_child",
            BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
        );
        let new_receipt = start_real_executor_child(
            &restarted_gateway,
            &restarted_platform,
            &restarted_authority,
            &new_admission,
            &owner,
        )
        .await;
        assert_eq!(
            new_receipt.operation_id(),
            new_admission.intent().operation_id()
        );
        assert_ne!(
            new_receipt.operation_id(),
            old_admission.intent().operation_id()
        );

        old_gateway
            .executor
            .shutdown()
            .expect("shutdown old Kernel executor");
        restarted_gateway
            .executor
            .shutdown()
            .expect("shutdown restarted Kernel executor");
        drop(old_gateway);
        drop(restarted_gateway);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn daemon_readiness_requires_fresh_running_executor_receipt() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-readiness-executor-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        std::fs::create_dir_all(root.join("kernel")).expect("kernel work root");
        let executable = std::env::current_exe().expect("test executable");
        let executable_sha256 =
            sha256_hex(&std::fs::read(&executable).expect("read test executable"));
        let containment_root = executable.parent().expect("test executable parent");
        let mut launch = test_daemon_launch(&root);
        launch.executable =
            PlatformHandle::new(executable.to_string_lossy()).expect("test executable handle");
        launch.executable_sha256.clone_from(&executable_sha256);
        launch.working_directory = PlatformHandle::new(containment_root.to_string_lossy())
            .expect("working directory handle");
        launch.arguments[7] =
            PlatformHandle::new(launch.executable_sha256.clone()).expect("executable digest");
        launch.descriptor_sha256.clear();
        launch = launch.with_computed_digest().expect("test launch digest");
        let mut kernel = KernelComposition::new(
            KernelConfig::new(root.join("kernel"))
                .with_daemon_launch(launch.clone())
                .with_kernel_artifact_sha256("c".repeat(64)),
        )
        .expect("kernel composition");
        let kernel_process =
            observe_named_pipe_peer_process(std::process::id()).expect("Kernel process identity");
        let generation = Generation::new(launch.generation.value()).expect("generation");
        let attempt = eliotd_launch_attempt_identity(
            &launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )
        .expect("launch attempt identity");
        let operation = eliotd_operation_id(generation, &attempt).expect("operation identity");
        let admission = real_executor_admission(
            &executable,
            &executable_sha256,
            operation.as_str(),
            "tests::real_executor_receipt_child",
            BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
        );
        let (gateway, platform, authority) =
            real_process_gateway(&root.join("real-executor"), containment_root);
        let gateway = Arc::new(gateway);
        let owner = gateway_test_owner();
        let receipt =
            start_real_executor_child(&gateway, &platform, &authority, &admission, &owner).await;
        assert_eq!(receipt.operation_id(), &operation);
        gateway
            .persist_completed(
                receipt.operation_id(),
                &process_admission_digest(&admission).expect("admission digest"),
                &owner,
                receipt.clone(),
            )
            .expect("persist live completion");
        kernel.process_gateway = Some(Arc::clone(&gateway));
        {
            let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
            state.status = DaemonRuntimeStatus::Ready;
            state.receipt = Some(receipt.clone());
        }

        let inspection = gateway.inspect_exact_running_receipt(&receipt).await;
        assert!(
            inspection.is_ok(),
            "gateway exact inspection must accept the live receipt: {inspection:?}"
        );
        kernel
            .validate_daemon_process_readiness(&launch, &receipt)
            .await
            .expect("live exact process accepted");
        assert!(kernel.daemon_ready());

        gateway
            .executor
            .shutdown()
            .expect("terminate executor child");
        assert!(
            kernel
                .validate_daemon_process_readiness(&launch, &receipt)
                .await
                .is_err(),
            "terminal executor inspection must reject readiness"
        );
        assert!(!kernel.daemon_ready());
        assert!(matches!(
            kernel
                .daemon_runtime
                .lock()
                .expect("daemon runtime lock")
                .status,
            DaemonRuntimeStatus::Failed(_)
        ));
        drop(gateway);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the production-bound recovery proof retains one real Job, receipt, stale rejection, and cleanup path"
    )]
    async fn daemon_recovery_closes_exact_prior_tree_and_rejects_stale_receipt() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-recovery-proof-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        std::fs::create_dir_all(root.join("kernel")).expect("kernel work root");
        let executable = std::env::current_exe().expect("test executable");
        let executable_sha256 =
            sha256_hex(&std::fs::read(&executable).expect("read test executable"));
        let containment_root = executable.parent().expect("test executable parent");
        let mut launch = test_daemon_launch(&root);
        launch.executable =
            PlatformHandle::new(executable.to_string_lossy()).expect("test executable handle");
        launch.executable_sha256.clone_from(&executable_sha256);
        launch.working_directory = PlatformHandle::new(containment_root.to_string_lossy())
            .expect("working directory handle");
        launch.arguments[7] =
            PlatformHandle::new(launch.executable_sha256.clone()).expect("executable digest");
        launch.descriptor_sha256.clear();
        launch = launch.with_computed_digest().expect("test launch digest");
        let mut kernel = KernelComposition::new(
            KernelConfig::new(root.join("kernel"))
                .with_daemon_launch(launch.clone())
                .with_kernel_artifact_sha256("c".repeat(64)),
        )
        .expect("kernel composition");
        let kernel_process =
            observe_named_pipe_peer_process(std::process::id()).expect("Kernel identity");
        let generation = Generation::new(launch.generation.value()).expect("generation");
        let attempt = eliotd_launch_attempt_identity(
            &launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )
        .expect("launch attempt");
        let operation = eliotd_operation_id(generation, &attempt).expect("operation");
        let admission = real_executor_admission(
            &executable,
            &executable_sha256,
            operation.as_str(),
            "tests::real_executor_receipt_child",
            BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
        );
        let (gateway, platform, authority) =
            real_process_gateway(&root.join("real-executor"), containment_root);
        let gateway = Arc::new(gateway);
        let expectation = current_process_named_pipe_expectation().expect("Kernel expectation");
        let owner = ProcessOwnerBinding::new(
            ACTIVE_DAEMON_CALLER,
            stable_owner_principal_digest(
                expectation.expected_sid(),
                ACTIVE_DAEMON_CALLER,
                launch.authority_epoch.value(),
                generation,
            ),
            launch.authority_epoch.value(),
            generation,
        )
        .expect("daemon owner");
        let receipt =
            start_real_executor_child(&gateway, &platform, &authority, &admission, &owner).await;
        gateway
            .persist_completed(
                receipt.operation_id(),
                &process_admission_digest(&admission).expect("admission digest"),
                &owner,
                receipt.clone(),
            )
            .expect("persist exact completed receipt");
        kernel.process_gateway = Some(Arc::clone(&gateway));
        {
            let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
            state.status = DaemonRuntimeStatus::Failed("daemon timeout".to_owned());
            state.receipt = Some(receipt.clone());
        }
        kernel
            .close_previous_daemon_process(&launch, &receipt)
            .await
            .expect("exact prior process tree closure");
        let closed = gateway
            .inspect(&owner, receipt.operation_id().clone())
            .await
            .expect("closed prior operation inspection");
        assert_eq!(closed.lifecycle(), ProcessLifecycle::Exited);

        let stale = test_process_start_receipt(41_002);
        assert!(
            kernel
                .close_previous_daemon_process(&launch, &stale)
                .await
                .is_err(),
            "a stale completed receipt must not be adopted for recovery"
        );
        gateway
            .executor
            .shutdown()
            .expect("shutdown recovery proof executor");
        drop(gateway);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
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
    fn process_authority_first_issue_is_versioned_and_stale_controller_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-process-authority-cas-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let ors_path = root.join("kernel-ors.redb");
        let authority_id = DispatchAuthorityId::new("kernel-cas-authority").expect("authority");
        let binding = authority_binding(&authority_id);
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(JsonSnapshotCodec);
        let store = Arc::new(RedbRecoveryStore::open(&ors_path).expect("real ORS store"));
        let authority_store: Arc<dyn OperationalRecoveryStore> = store.clone();
        let key = || KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("dispatch key");
        let issuance = |nonce: &str| {
            PermitIssuance::new(
                ActionLeaseRef::new("cas-lease").expect("lease"),
                FencingToken::new(1, Generation::new(1).expect("generation"), "cas-fence")
                    .expect("fence"),
                BTreeMap::from([("authority".to_owned(), "a".repeat(64))]),
                1,
                2,
                nonce,
            )
            .expect("issuance")
        };

        let mut winner = ProcessDispatchAuthorityController::activate_and_persist_initial(
            authority_id.clone(),
            key(),
            Arc::clone(&authority_store),
            Arc::clone(&codec),
            &binding,
        )
        .expect("initial snapshot");
        let mut stale = ProcessDispatchAuthorityController::restore(
            authority_id.clone(),
            key(),
            Arc::clone(&authority_store),
            Arc::clone(&codec),
            &binding,
        )
        .expect("stale controller restore");
        winner
            .issue(&seed_intent(), issuance("cas-winner"), &binding)
            .expect("one controller wins the CAS");
        assert!(matches!(
            stale.issue(&seed_intent(), issuance("cas-stale"), &binding),
            Err(KernelError::RecoveryState(
                eliot_ors::OrsError::DuplicateConflict
            ))
        ));
        assert!(matches!(
            stale.issue(&seed_intent(), issuance("cas-stale-retry"), &binding),
            Err(KernelError::DependencyUnavailable(_))
        ));

        let subject = OperationIdentity::new(authority_id.as_str()).expect("subject");
        let current = store
            .load_authority_snapshot(&subject)
            .expect("load current snapshot")
            .expect("current snapshot");
        assert!(current.operation_order() > 1);
        let mut restarted = ProcessDispatchAuthorityController::restore(
            authority_id,
            key(),
            authority_store,
            codec,
            &binding,
        )
        .expect("restart snapshot");
        assert!(
            restarted
                .issue(&seed_intent(), issuance("cas-winner"), &binding)
                .is_err()
        );
        drop(restarted);
        drop(stale);
        drop(winner);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
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
        assert_eq!(prepared.handoff.state, AuthorityHandoffState::Reserved);
        // The preparation step only commits the activation intent.  The
        // production constructor owns initial snapshot persistence and the
        // terminal handoff transition.
        drop(kernel);
        let resumed = KernelComposition::new_with_authority_descriptor(
            KernelConfig::new(&root),
            &positive_path,
            &positive_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        )
        .expect("clean first boot resumes reserved intent");
        assert!(resumed.process_execution_configured());
        drop(resumed);
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("reopen ORS");
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
        drop(kernel);
        // A second production start is exact recovery, not a replay failure:
        // it restores the same durable replay fence without minting a key or
        // a new nonce.
        let restart = KernelComposition::new_with_authority_descriptor(
            KernelConfig::new(&root),
            &positive_path,
            &positive_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        )
        .expect("exact same-generation restart");
        drop(restart);
        drop(positive_cleanup);
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("reopen ORS");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &positive_path,
                &positive_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::CredentialUnavailable)
        ));

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
        let expired_key = expired.dispatch_key.key.as_str().to_owned();
        let expired_cleanup = credential_cleanup(&platform, &expired_key);
        platform
            .write_credential(&expired_key, &[0x4a; 32])
            .expect("expired credential");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &expired_path,
                &expired_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorNotFresh)
        ));
        let expired_id = OperationIdentity::new(expired.handoff_id.as_str()).expect("handoff id");
        assert!(
            kernel
                .generation_gateway
                .ors
                .load_authority_handoff(&expired_id)
                .expect("expired handoff lookup")
                .is_none()
        );
        drop(expired_cleanup);

        let now = i64::try_from(unix_ms()).expect("test clock");
        let mut future = authority_descriptor(
            &format!("{suffix}-future-issued"),
            "windows-credential-manager",
        );
        future.issued_at_ms = now.saturating_add(60_000);
        future.expires_at_ms = now.saturating_add(120_000);
        future = future.with_computed_digest().expect("future-issued digest");
        let (future_path, future_digest) =
            write_authority_descriptor(&root, "future-issued", &future);
        let future_key = future.dispatch_key.key.as_str().to_owned();
        let future_cleanup = credential_cleanup(&platform, &future_key);
        platform
            .write_credential(&future_key, &[0x4b; 32])
            .expect("future-issued credential");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &future_path,
                &future_digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::DescriptorNotFresh)
        ));
        let future_id = OperationIdentity::new(future.handoff_id.as_str()).expect("handoff id");
        assert!(
            kernel
                .generation_gateway
                .ors
                .load_authority_handoff(&future_id)
                .expect("future-issued handoff lookup")
                .is_none()
        );
        drop(future_cleanup);

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
    fn protected_authority_restart_after_admission_expiry_restores_exact_snapshot() {
        let suffix = authority_test_suffix();
        let root = std::env::temp_dir().join(format!("eliot-kernel-authority-expiry-{suffix}"));
        let _cleanup = AuthorityTestCleanup {
            paths: vec![root.clone()],
        };
        std::fs::create_dir_all(&root).expect("test work root");
        let platform = Arc::new(WindowsPlatform::new(&root).expect("platform"));
        let now = i64::try_from(unix_ms()).expect("test clock");
        let mut descriptor =
            authority_descriptor(&format!("{suffix}-expiry"), "windows-credential-manager");
        descriptor.issued_at_ms = now.saturating_sub(1_000);
        descriptor.expires_at_ms = now.saturating_add(2_000);
        descriptor = descriptor
            .with_computed_digest()
            .expect("descriptor digest");
        let (path, digest) = write_authority_descriptor(&root, "expiry", &descriptor);
        let key = descriptor.dispatch_key.key.as_str().to_owned();
        let credential = credential_cleanup(&platform, &key);
        platform
            .write_credential(&key, &[0x4d; 32])
            .expect("credential");

        // Persist the initial replay snapshot while the activation intent is
        // still Reserved.  This is the exact crash boundary that must remain
        // recoverable after the descriptor's one-shot admission interval.
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
        let prepared = kernel
            .prepare_authority_descriptor(
                &path,
                &digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            )
            .expect("reserve handoff before admission expiry");
        assert_eq!(prepared.handoff.state, AuthorityHandoffState::Reserved);
        let binding = AuthoritySnapshotBinding::from_wire(
            prepared.descriptor.snapshot_binding.clone(),
            &prepared.descriptor.authority_id,
        )
        .expect("snapshot binding");
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(WindowsDispatchSnapshotCodec::new(
            Arc::clone(&platform),
            prepared.descriptor.dispatch_key.clone(),
        ));
        let controller = KernelComposition::prepare_descriptor_controller(
            prepared.descriptor.authority_id.clone(),
            prepared.key,
            Arc::clone(&kernel.generation_gateway.ors) as Arc<dyn OperationalRecoveryStore>,
            codec,
            &binding,
            &prepared.descriptor,
            &prepared.handoff,
        )
        .expect("initial snapshot before handoff consume");
        let handoff_id =
            OperationIdentity::new(descriptor.handoff_id.as_str()).expect("handoff id");
        assert_eq!(
            kernel
                .generation_gateway
                .ors
                .load_authority_handoff(&handoff_id)
                .expect("reserved handoff")
                .expect("reserved handoff record")
                .state,
            AuthorityHandoffState::Reserved
        );
        drop(controller);
        drop(kernel);
        std::thread::sleep(Duration::from_millis(2_200));

        let restarted = KernelComposition::new_with_authority_descriptor(
            KernelConfig::new(&root),
            &path,
            &digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        )
        .expect("exact Reserved restart after admission expiry");
        assert!(restarted.process_execution_configured());
        drop(restarted);
        drop(credential);
    }

    #[cfg(windows)]
    #[test]
    fn protected_authority_consume_reconciles_without_demoting_consumed() {
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
        let prepared = kernel
            .prepare_authority_descriptor(
                &path,
                &digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            )
            .expect("reserve handoff before consume");
        let binding = AuthoritySnapshotBinding::from_wire(
            prepared.descriptor.snapshot_binding.clone(),
            &prepared.descriptor.authority_id,
        )
        .expect("snapshot binding");
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(WindowsDispatchSnapshotCodec::new(
            Arc::clone(&platform),
            prepared.descriptor.dispatch_key.clone(),
        ));
        let controller = KernelComposition::prepare_descriptor_controller(
            prepared.descriptor.authority_id.clone(),
            prepared.key,
            Arc::clone(&kernel.generation_gateway.ors) as Arc<dyn OperationalRecoveryStore>,
            codec,
            &binding,
            &prepared.descriptor,
            &prepared.handoff,
        )
        .expect("initial snapshot");
        KernelComposition::consume_authority_handoff(
            &kernel.generation_gateway.ors,
            &prepared.handoff,
        )
        .expect("uncertain consume reconciles to committed state");
        drop(controller);
        let handoff_id =
            OperationIdentity::new(descriptor.handoff_id.as_str()).expect("handoff id");
        let consumed = kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&handoff_id)
            .expect("load consumed handoff")
            .expect("consumed handoff");
        assert_eq!(consumed.state, AuthorityHandoffState::Consumed);
        drop(credential);
    }

    #[cfg(windows)]
    #[allow(clippy::format_collect, clippy::too_many_lines)]
    #[test]
    fn protected_supervision_authority_restarts_replays_and_rejects_key_substitution() {
        let suffix = authority_test_suffix();
        let root = std::env::temp_dir().join(format!("eliot-kernel-supervision-{suffix}"));
        let _cleanup = AuthorityTestCleanup {
            paths: vec![root.clone()],
        };
        std::fs::create_dir_all(root.join(".eliot")).expect("supervision test root");

        let platform = Arc::new(WindowsPlatform::new(&root).expect("supervision test platform"));
        let key = format!("eliot/kernel/supervision/{suffix}");
        let credential = credential_cleanup(&platform, &key);
        let seed = [0xa5; 32];
        let seed_hex = "a5".repeat(32);
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
            "kernel-supervision",
            "kernel-supervision-key",
            seed,
        )
        .expect("supervision test signer");
        let trust_anchor = SupervisionTrustAnchor::new(
            "installation-1",
            "kernel-supervision",
            "kernel-supervision-key",
            signer.public_key().to_vec(),
        )
        .expect("supervision trust anchor");
        let authority_config = SupervisionLeaseAuthorityConfig {
            key_reference: SecretReference::new("windows-credential-manager", &key)
                .expect("supervision key reference"),
            trust_anchor,
        };
        platform
            .write_credential(&key, &seed)
            .expect("write supervision protected seed");

        let ors_path = root.join(".eliot").join("kernel-ors.redb");
        let ors = Arc::new(RedbRecoveryStore::open(&ors_path).expect("supervision ORS"));
        let authority = KernelSupervisionLeaseAuthority::new(
            Arc::clone(&ors),
            &platform,
            authority_config.clone(),
        )
        .expect("protected supervision authority");
        let authority_debug = format!("{authority:?}");
        let signer_debug = format!("{:?}", authority.signer);
        assert!(!authority_debug.contains(&seed_hex));
        assert!(!signer_debug.contains(&seed_hex));
        assert!(authority_debug.contains("KernelSupervisionLeaseAuthority"));

        // The durable stage is the crash boundary: no current record exists
        // until a restarted Kernel reconciles and signs the exact ticket.
        let issued_at_ms = unix_ms().saturating_sub(1_000);
        let stage = authority
            .prepare(
                supervision_authority_request(
                    "supervision-ticket-1",
                    "supervision-operation-1",
                    "supervision-lease-1",
                    None,
                    SupervisionLeaseOperation::Commit,
                    supervision_authority_binding(LeaseState::Active, issued_at_ms)
                        .expect("supervision binding"),
                )
                .expect("supervision request"),
            )
            .expect("stage supervision ticket");
        assert!(
            ors.load_current_supervision_lease(&stage.ticket.lease_id)
                .expect("load pre-commit current")
                .is_none()
        );
        drop(authority);
        drop(ors);

        // Restart recovery consumes only the authoritative ORS stage and
        // reloads the protected key reference; it does not invent a revision.
        let ors = Arc::new(RedbRecoveryStore::open(&ors_path).expect("reopen supervision ORS"));
        let authority = KernelSupervisionLeaseAuthority::new(
            Arc::clone(&ors),
            &platform,
            authority_config.clone(),
        )
        .expect("restart supervision authority");
        let recovered = authority
            .reconcile(4)
            .expect("reconcile staged supervision ticket");
        assert_eq!(recovered.len(), 1);
        let first = recovered.into_iter().next().expect("recovered snapshot");
        assert_eq!(first.record.revision, 1);
        assert_eq!(
            first.record.projection,
            eliot_ors::SupervisionLeaseProjection::Active
        );

        // A lost response is an exact ORS result replay. Removing the
        // provider item proves this path does not read or sign again.
        platform
            .delete_credential(&key)
            .expect("delete seed for response-loss replay");
        let replay = authority
            .commit_active(&stage.ticket)
            .expect("replay durable supervision result");
        assert_eq!(replay, first);

        // A fresh successor ticket must fail closed on a substituted key and
        // remain staged until the exact trusted key is restored.
        platform
            .write_credential(&key, &seed)
            .expect("restore supervision protected seed");
        let renew_issued_at_ms = unix_ms();
        let renew_stage = authority
            .prepare(
                supervision_authority_request(
                    "supervision-ticket-2",
                    "supervision-operation-2",
                    "supervision-lease-1",
                    Some(1),
                    SupervisionLeaseOperation::Renew,
                    supervision_authority_binding(LeaseState::Active, renew_issued_at_ms)
                        .expect("renew supervision binding"),
                )
                .expect("renew supervision request"),
            )
            .expect("stage renew supervision ticket");
        platform
            .write_credential(&key, &[0x5a; 32])
            .expect("substitute supervision protected seed");
        let substitution = authority
            .commit_active(&renew_stage.ticket)
            .expect_err("substituted supervision key must fail closed");
        assert!(matches!(
            substitution,
            SupervisionLeaseAuthorityError::ProtectedKeyUnavailable
        ));
        assert!(
            ors.reconcile_staged_supervision_lease(&renew_stage.ticket.lease_id)
                .expect("load staged renew ticket")
                .is_some()
        );
        assert_eq!(
            ors.load_current_supervision_lease(&stage.ticket.lease_id)
                .expect("load current after substitution")
                .expect("current active lease")
                .record
                .revision,
            1
        );

        platform
            .write_credential(&key, &seed)
            .expect("restore trusted supervision seed");
        let renewed = authority
            .commit_active(&renew_stage.ticket)
            .expect("commit trusted supervision renewal");
        assert_eq!(renewed.record.revision, 2);

        let revoke_stage = authority
            .prepare(
                supervision_authority_request(
                    "supervision-ticket-3",
                    "supervision-operation-3",
                    "supervision-lease-1",
                    Some(2),
                    SupervisionLeaseOperation::Revoke,
                    supervision_authority_binding(LeaseState::Revoked, renew_issued_at_ms)
                        .expect("revoke supervision binding"),
                )
                .expect("revoke supervision request"),
            )
            .expect("stage revoke supervision ticket");
        let revoked = authority
            .commit_terminal(&revoke_stage.ticket)
            .expect("commit trusted supervision revoke");
        assert_eq!(revoked.record.revision, 3);
        assert_eq!(
            revoked.record.projection,
            eliot_ors::SupervisionLeaseProjection::Terminal
        );
        platform
            .delete_credential(&key)
            .expect("delete seed for terminal response-loss replay");
        let terminal_replay = authority
            .commit_terminal(&revoke_stage.ticket)
            .expect("replay durable terminal supervision result");
        assert_eq!(terminal_replay, revoked);

        // Restart after the durable result still exposes the exact ORS replay
        // through the composition-injected authority.
        drop(authority);
        drop(ors);
        // The terminal response-loss replay above intentionally left the
        // provider item absent; retain that absence for the constructor test.
        let missing_ors =
            Arc::new(RedbRecoveryStore::open(&ors_path).expect("open ORS for missing-key restart"));
        assert!(matches!(
            KernelSupervisionLeaseAuthority::new(
                Arc::clone(&missing_ors),
                &platform,
                authority_config.clone(),
            ),
            Err(KernelBuildError::Service(_))
        ));
        drop(missing_ors);
        platform
            .write_credential(&key, &seed)
            .expect("restore seed for composition restart");
        let composition = KernelComposition::new(
            KernelConfig::new(&root).with_supervision_lease_authority(authority_config.clone()),
        )
        .expect("composition with protected supervision authority");
        let restarted_authority = composition
            .supervision_lease_authority()
            .expect("injected supervision authority");
        let restarted_replay = restarted_authority
            .commit_terminal(&revoke_stage.ticket)
            .expect("restart exact supervision replay");
        assert_eq!(restarted_replay, revoked);

        drop(composition);
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
