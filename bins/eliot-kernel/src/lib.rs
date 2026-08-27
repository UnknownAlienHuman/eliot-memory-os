//! The Kernel composition root — ARCH-MOD-01 (A13.2/A13.3; I6.4-I6.5/I7.1-I7.5/I7.14).
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.
//!
//! Architecture: ARCH-MOD-01, A13.2, A13.3, A8.1, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04
//! Implementation: I6.4, I6.5, I7.1, I7.2, I7.3, I7.4, I7.5, I7.14, I1.4, I1.5, I2.2, I2.23, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15
//! Neutral Kernel admission/transport only; no Governor semantics, Store SDK, or default success.
//! Forbidden authority: no semantic oracle, alternate lease authority, unbounded restart, or daemon-owned canonical transition.

#![forbid(unsafe_code)]

#[cfg(windows)]
mod agent_bridge;
mod canonical_store_runtime;
mod composition_bootstrap;
mod control_plane;
mod kernel_build_contract;
mod kernel_config;
mod process_execution;
mod supervision_lease_authority;

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
#[cfg(windows)]
pub use supervision_lease_authority::{
    KernelSupervisionLeaseAuthority, ProtectedSupervisionLeaseSigner,
    SupervisionLeaseAuthorityError,
};
#[cfg(all(test, windows))]
pub(crate) use supervision_lease_authority::{
    supervision_authority_root_spec, verification_context_for_supervision_payload,
    verify_superseded_supervision_replay,
};
#[cfg(windows)]
use supervision_lease_authority::{
    supervision_binding_matches_contour, supervision_operation_identity,
};

#[cfg(test)]
use eliot_kernel_core::{
    AuthoritySnapshotBindingWire, ProcessExecutionReplayAbort, ProcessExecutionReplayBegin,
    ProcessExecutionReplayRecord, ProcessExecutionReplayState, process_admission_digest,
};

#[cfg(feature = "r13-os-harness")]
pub mod r13_os_harness;

mod daemon_live_receipt;
#[cfg(windows)]
mod daemon_process_launch;
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

use std::collections::{BTreeMap, VecDeque};
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
    OperationIdentity, OperationalRecoveryStore, RedbRecoveryStore, SupervisionLeaseOperation,
    SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
};
#[cfg(test)]
pub use eliot_ors::{SupervisionLeaseCommitTicket, SupervisionLeaseStageReceipt};
#[cfg(test)]
use eliot_platform::ClockObservation;
use eliot_platform::PlatformHandle;
#[cfg(windows)]
use eliot_platform_windows::{
    FileIdentity as WindowsFileIdentity, NamedPipePeerKind, NamedPipePeerProfile, NamedPipePeerSet,
    ProtectedRootLease, ProtectedRuntimePathLease, PublicationOutcome, PublicationPrecondition,
    publish_atomic_owned_runtime_receipt, read_protected_file, windows_paths_equal,
};
#[cfg(test)]
pub use eliot_platform_windows::{
    InstallerRootPrimitiveSpec, InstallerRootProfile, WindowsSupervisionAuthorityKeyStore,
    protected_program_data_root,
};
use eliot_platform_windows::{UserOwnedPathLease, UserOwnedRootLease, WindowsPlatform};
#[cfg(test)]
pub use eliot_process::EliotdLiveSupervisionEvidence;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, EliotdLiveReadyEvidence, EliotdLiveReceipt,
    EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, ProcessExecutionAdmissionRequest, ProcessExecutionError, ProcessIntent,
    ProcessOwnerBinding, ProcessSessionBinding, ProcessStartReceipt, ProcessTreeId, ResourceLimits,
    SessionId,
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
#[cfg(test)]
pub use eliot_runtime_contracts::SupervisionLeasePredecessorIdentity;
#[cfg(windows)]
use eliot_runtime_contracts::SupervisionLeaseTerminalDisposition;
#[cfg(test)]
pub use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, ProvisionedSupervisionAuthority, SupervisionLease,
    SupervisionLeaseActiveStateBinding, SupervisionLeaseError, SupervisionLeasePredecessorProof,
    SupervisionLeaseSigner, SupervisionLeaseVerificationContext, SupervisionLeaseVerifier,
    SupervisionSealedKeyReference, SupervisionTrustAnchor,
};
use eliot_runtime_contracts::{
    HealthVector, LeaseState, ModuleGeneration, ModuleGenerationState, SupervisionGenerationBinding,
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

    /// Returns the platform surface owned by this composition.
    #[must_use]
    pub fn platform(&self) -> &WindowsPlatform {
        &self.platform
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

#[cfg(windows)]
const _: () = {
    let _ = AGENT_BRIDGE_MODULE_ID;
    let _ = AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID;
    let _ = AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION;
    let _ = AGENT_BRIDGE_ACTIVATION_OPERATION;
    let _: Option<AgentBridgeActivationDenialCode> = None;
    let _: Option<AgentBridgeActivationDisposition> = None;
    let _: Option<AgentBridgeActivationFence> = None;
    let _: Option<AgentBridgeActivationResponse> = None;
    let _: Option<AgentBridgeAuthenticatedBinding> = None;
    let _: Option<AgentBridgePeerAdmissionReceipt> = None;
};

#[cfg(test)]
mod tests;

// Store implementation E2E belongs to the Store/Host boundary. Kernel tests
// exercise only the neutral descriptor and route/fence behavior.
