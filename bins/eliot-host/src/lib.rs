//! Production Host composition root.
//!
//! Host is the outer Windows lifecycle owner. It opens the crash-safe Host
//! journal under the installation's durable data root, keeps approved
//! generations separate from semantic state, and owns independent Job Object
//! branches for Kernel and the canonical store dependency.

#![forbid(unsafe_code)]
#![allow(
    dead_code,
    reason = "windows-only helpers are live on Windows; allow for cross-platform check"
)]

mod credential_control;
#[cfg(windows)]
mod host_activation_durable;
#[cfg(windows)]
mod host_composition_phase_b;
#[cfg(windows)]
mod host_composition_store_recovery;
mod host_composition_validation;
#[cfg(windows)]
mod launch_artifact;
mod launch_options;
mod runtime_control;
mod scm_launch;

pub use credential_control::{HostCredentialControl, HostPhaseBRequest, HostPhaseBRequestQueue};
#[cfg(windows)]
use launch_artifact::{
    LaunchLease, approved_locator, approved_phase_b_destination_locator, open_launch_lease,
    verify_launch_digest,
};
pub use launch_options::HostLaunchOptions;
use launch_options::valid_sha256_text;
use runtime_control::runtime_control_unknown_ref;
pub use runtime_control::{
    HOST_RUNTIME_CONTROL_PIPE, HostKernelRestartReceipt, HostRuntimeControl,
    HostRuntimeControlOperation, HostRuntimeControlQueue, HostRuntimeControlRequest,
    HostRuntimeControlResponse, HostStoreRecoveryReceipt,
};
pub use scm_launch::{ValidatedHostScmLaunch, validate_host_scm_bootstrap};

use std::ffi::OsString;
use std::io;
#[cfg(windows)]
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
#[cfg(windows)]
use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence};
use eliot_host_state::{
    ActivationState, AppendReceipt, DrainCommitRecord, DrainRecord, DrainState, EpochIdentity,
    EpochTransition, HostInstallationEpoch, HostObservationRecord, HostState,
    HostStateJournalService, HostStateRecord, IdempotencyIdentity, JournalBackend, JournalError,
    KernelJobBinding, KernelRecord, NonceState, OneTimeNonceState, PriorKernelDisposition,
    ProductionHostStateJournal, ReconcileOutcome, RecordFence, RecoveryLineageEvidence,
    RedbJournalBackend, StoreRebindRecord, StoreRebindState, WakeDisposition,
    host_owner_epoch_digest, record_checksum,
};
use eliot_installation::{
    ActivationCommitFence, ActivePhaseBRebindIntent, ActivePhaseBRebindReceipt,
    ActivePhaseBRebindRecovery, AgentBridgePhaseBBinding, AgentBridgePreparedBinding,
    AgentBridgeStagePrepared, ApprovedGenerationRegistry, CandidateManifest,
    CredentialAccessReceipt, HostCredentialControlResponse, HostPhaseBMaterializationIntent,
    HostPhaseBMaterializationReceipt, HostPhaseBPreparedMaterialization, HostPhaseBPreparedReceipt,
    InstallationEpoch, InstallationError, InstallationProfile,
    InstallerServiceRegistrationApproval, InstallerServiceRole, LOCAL_SERVICE_SID,
    PHASE_B_PENDING_MARKER, PendingActivationState, PhaseBLiveBinding,
    ProvisionedSupervisionAuthority, RedbInstallationRegistry, RuntimeLaunchDescriptor,
    StoreCredentialProvider, StoreCredentialScope,
    phase_b_credential_receipt_digest as installation_phase_b_credential_receipt_digest,
    phase_b_host_state_root_digest as installation_phase_b_host_state_root_digest,
    phase_b_scm_selector, phase_b_static_template_for_candidate,
    phase_b_watchdog_selector_digest as installation_phase_b_watchdog_selector_digest,
    verify_file_digest_with_lease, verify_file_digest_with_user_lease,
};
#[cfg(windows)]
use eliot_kernel_core::AuthoritySnapshotBindingWire;
use eliot_kernel_service::{
    EliotdLaunchDescriptor, HostJobBinding, HostKernelCandidateBinding, HostProcessBinding,
    HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE, KernelActivationPermit,
    KernelActivationQuery, KernelActivationReceipt, KernelControlCommand, KernelControlRequest,
    KernelControlResponse, KernelReadyReceipt, KernelServiceState,
    ProcessAuthorityHandoffDescriptor, RestartBudget, StoreBootstrapHandoff, StoreProcessBinding,
    StoreRebindHandoff, StoreRebindQuery, StoreRebindReceipt, control_request_frame,
    decode_control_response_frame, semantic_store_config_hash_from_json,
};
use eliot_observation_contracts::{
    CoverageGap, GapDisposition, ObservationRecordEnvelope, ObservationRecordKind,
};
#[cfg(windows)]
use eliot_ors::{
    EpochIdentity as OrsEpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity,
    StateFenceSnapshot,
};
use eliot_platform::{PlatformHandle, SecretReference, ServiceState};
#[cfg(windows)]
use eliot_platform_windows::{
    DirectoryPublicationError, DirectoryPublicationOutcome, FileIdentity,
    OwnedDirectoryPublication, OwnedDirectoryRetirementOutcome,
    OwnedDirectoryRetirementPrecondition, ProtectedRuntimePathLease, retire_owned_directory_exact,
    windows_paths_equal,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_NAME, HostOwnerLease, HostOwnerLeaseError,
    HostOwnerLeaseReleaseError, ProtectedRootLease, ServiceAccount, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, TerminatedJobChild, WindowsPlatform,
    fresh_kernel_activation_nonce,
};
#[cfg(windows)]
use eliot_process::DispatchAuthorityId;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, KernelActivationState, ServiceProcessRecord,
    ServiceProcessState, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    SUPERVISION_LEASE_FILE_NAME, SignedSupervisionLease, SupervisionLeaseVerifier,
    WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_DIRECTORY_PREFIX,
    WATCHDOG_PUBLICATION_FILE_NAME, WATCHDOG_PUBLICATION_RETAINED_LIMIT, WatchdogAdmissionTemplate,
    WatchdogPublicationBundle, WatchdogPublicationRetentionPlan,
};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, PeerIdentity, TransportLimits};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = ELIOT_HOST_SERVICE_NAME;
pub const PROTOCOL_VERSION: &str = "eliot.host.v1";
pub const HOST_JOURNAL_RELATIVE_PATH: &str = "Eliot/host/host-state-journal.redb";
const HOST_JOURNAL_FILE_NAME: &str = "host-state-journal.redb";
/// Stable production-boundary identity for the Host Store-rebind seam.
pub const HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-host::production-store-rebind:v1";
/// Stable discriminator for the crash fence that exists because Host-owned
/// `KILL_ON_JOB_CLOSE` Jobs make a prior Store/Kernel process contour
/// unattachable after Host death.  The fenced query is deliberately an
/// operation-specific Unknown/manual new-lineage directive, never a positive
/// attach or receipt adoption.
pub const HOST_STORE_RECOVERY_KILL_ON_JOB_CLOSE_CRASH_FENCE_DISCRIMINATOR: &str =
    "eliot-host::store-recovery::kill-on-job-close-crash-fence:v1";
const STORE_RECOVERY_CRASH_FENCE_UNKNOWN_REASON: &str =
    "store-recovery-crash-fence-manual-new-lineage";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostStoreRebindProductionBoundary;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostRuntimeControlProductionBoundary;
const STORE_SEMANTIC_CONFIG_HASH_PENDING: &str = PHASE_B_PENDING_MARKER;
pub const HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR: &str =
    runtime_control::HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR;

#[cfg(test)]
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(test)]
type TestError = Box<dyn std::error::Error>;

#[cfg(test)]
mod launch_options_tests;

#[derive(Debug, Error)]
pub enum HostError {
    #[error("host state store: {0}")]
    State(#[from] eliot_platform::HostStateError),
    #[error("host state journal: {0}")]
    Journal(#[from] JournalError),
    #[error("installation registry: {0}")]
    Installation(#[from] InstallationError),
    #[error("host platform: {0}")]
    Platform(String),
    #[error("host is already stopped")]
    Stopped,
    #[error("host installation identity is required")]
    MissingInstallation,
    #[error("approved process contour is unavailable: {0}")]
    ProcessContour(String),
    #[error("Store child is not live ({evidence})")]
    StoreNotLive { evidence: StoreLivenessEvidence },
    #[error("Host child cleanup requires recovery: {0}")]
    RecoveryRequired(String),
    #[cfg(windows)]
    #[error("Host-owned Store recovery is required: {0}")]
    StoreRecoveryRequired(#[from] StoreRecoveryRequired),
    #[error("another live Host owns this installation")]
    OwnerLeaseHeld,
    #[error("Host owner lease recovery is required: {0}")]
    OwnerLeaseRecovery(String),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StoreLivenessEvidence {
    #[error("dead")]
    Dead,
    #[error("unknown: {0}")]
    Unknown(String),
}

#[cfg(windows)]
enum StoreKernelLaunchError<S> {
    Launch(HostError),
    StoreNotLive { evidence: StoreLivenessEvidence },
    CleanupRequired { store: S, reason: String },
    Kernel { error: HostError },
}

#[cfg(windows)]
fn launch_store_then_kernel<S, K, LF, OF, KF, CF>(
    launch_store: LF,
    observe_store: OF,
    launch_kernel: KF,
    cleanup_store: CF,
) -> Result<(S, K), StoreKernelLaunchError<S>>
where
    LF: FnOnce() -> Result<S, HostError>,
    OF: FnOnce(&S) -> Result<(), StoreLivenessEvidence>,
    KF: FnOnce() -> Result<K, HostError>,
    CF: FnOnce(S) -> Result<(), Box<(S, String)>>,
{
    let store = launch_store().map_err(StoreKernelLaunchError::Launch)?;
    if let Err(evidence) = observe_store(&store) {
        return match cleanup_store(store) {
            Ok(()) => Err(StoreKernelLaunchError::StoreNotLive { evidence }),
            Err(boxed) => {
                let (store, reason) = *boxed;
                Err(StoreKernelLaunchError::CleanupRequired { store, reason })
            }
        };
    }
    let kernel = match launch_kernel() {
        Ok(kernel) => kernel,
        Err(error) => {
            return match cleanup_store(store) {
                Ok(()) => Err(StoreKernelLaunchError::Kernel { error }),
                Err(boxed) => {
                    let (store, reason) = *boxed;
                    Err(StoreKernelLaunchError::CleanupRequired {
                        store,
                        reason: format!(
                            "Kernel launch failed ({error}); Store cleanup is unknown: {reason}"
                        ),
                    })
                }
            };
        }
    };
    Ok((store, kernel))
}

#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, PinnedRuntimeFile, ProcessIdentity, RunningJobChild, SuspendedJobChild,
    SuspendedLaunchSpec, UserOwnedRootLease, WindowsAdapterError, observe_named_pipe_peer_process,
    observe_named_pipe_peer_process_in_job,
};

#[cfg(windows)]
const KERNEL_BOOTSTRAP_ENVIRONMENT: [&str; 7] = [
    "ELIOT_KERNEL_CONTROL_PIPE",
    "ELIOT_HOST_PROCESS_ID",
    "ELIOT_HOST_PROCESS_START",
    "ELIOT_HOST_PROCESS_IMAGE",
    "ELIOT_KERNEL_RECEIPT_ROOT",
    "ELIOT_KERNEL_ORS_ROOT",
    "ELIOT_RUNTIME_STATE_ROOTS_DIGEST",
];

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelLaunchBinding {
    pipe_identity: PlatformHandle,
    host_process: HostProcessBinding,
}

#[cfg(windows)]
impl KernelLaunchBinding {
    fn observe_current() -> Result<Self, WindowsAdapterError> {
        let observed = observe_named_pipe_peer_process(std::process::id())?;
        let host_process = HostProcessBinding {
            process_id: observed.process_id(),
            start_time_100ns: observed.start_time_100ns(),
            image_path: observed.image_path().to_owned(),
        };
        host_process
            .validate()
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let pipe_identity = PlatformHandle::new(KERNEL_CONTROL_PIPE)
            .map_err(|_| WindowsAdapterError::InvalidInput)?;
        Ok(Self {
            pipe_identity,
            host_process,
        })
    }

    fn validate_current(&self) -> Result<(), HostError> {
        let observed = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if !self.matches_observed(
            observed.process_id(),
            observed.start_time_100ns(),
            observed.image_path(),
        ) {
            return Err(HostError::ProcessContour(
                "retained Host process identity changed before Kernel control".to_owned(),
            ));
        }
        Ok(())
    }

    fn matches_observed(&self, process_id: u32, start_time_100ns: u64, image_path: &str) -> bool {
        self.host_process.process_id == process_id
            && self.host_process.start_time_100ns == start_time_100ns
            && self.host_process.image_path == image_path
    }
}

#[cfg(windows)]
fn verify_host_artifact_at(
    manifest: &CandidateManifest,
    current_executable: &Path,
) -> Result<(), HostError> {
    let (approved_path, approved_digest) = manifest
        .host_artifact_binding()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let launch = &manifest.runtime_launch;
    let portable_root = if launch.profile == InstallationProfile::PortableDev {
        Some(
            UserOwnedRootLease::open_existing(Path::new(
                launch
                    .portable_root
                    .as_ref()
                    .ok_or_else(|| {
                        HostError::ProcessContour("portable root is missing".to_owned())
                    })?
                    .as_str(),
            ))
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        )
    } else {
        None
    };
    let current_executable = approved_locator(current_executable, approved_path, launch.profile)?;
    let lease = open_launch_lease(launch.profile, portable_root.as_ref(), &current_executable)?;
    verify_launch_digest(&lease, approved_digest, "runtime.host_artifact")
}

#[cfg(windows)]
fn verify_current_host_artifact(manifest: &CandidateManifest) -> Result<(), HostError> {
    // The OS-reported current image is process identity evidence, never a
    // fallback for the approved launch descriptor.
    let current_executable =
        std::env::current_exe().map_err(|error| HostError::ProcessContour(error.to_string()))?;
    verify_host_artifact_at(manifest, &current_executable)
}

#[cfg(windows)]
fn validate_store_bootstrap_descriptor(
    lease: &LaunchLease,
    approved_digest: &PlatformHandle,
    expected_artifact: &PlatformHandle,
    expected_config: &PlatformHandle,
    expected_nonce: &PlatformHandle,
) -> Result<HostStoreBootstrapRequirement, HostError> {
    lease.verify().map_err(HostError::ProcessContour)?;
    let bytes = match lease {
        LaunchLease::Protected(lease) => lease.read_bounded(1024 * 1024),
        LaunchLease::Portable(lease) => lease.read_bounded(1024 * 1024),
    }
    .map_err(|error| {
        HostError::ProcessContour(format!("read Store bootstrap descriptor: {error}"))
    })?;
    let actual = Sha256::digest(&bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        return Err(HostError::ProcessContour(
            "Store bootstrap descriptor digest changed before launch".to_owned(),
        ));
    }
    let requirement: HostStoreBootstrapRequirement =
        serde_json::from_slice(&bytes).map_err(|error| {
            HostError::ProcessContour(format!("parse Store bootstrap descriptor: {error}"))
        })?;
    requirement.validate().map_err(|error| {
        HostError::ProcessContour(format!("validate Store bootstrap descriptor: {error}"))
    })?;
    if requirement.approved_artifact_hash != *expected_artifact
        || requirement.approved_config_hash != *expected_config
        || requirement.launch_nonce != *expected_nonce
    {
        return Err(HostError::ProcessContour(
            "Store bootstrap descriptor is not bound to the approved generation".to_owned(),
        ));
    }
    Ok(requirement)
}

#[cfg(windows)]
fn validate_eliotd_launch_descriptor(
    lease: &LaunchLease,
    approved_digest: &PlatformHandle,
    launch: &RuntimeLaunchDescriptor,
) -> Result<(), HostError> {
    lease.verify().map_err(HostError::ProcessContour)?;
    let bytes = lease.read_bounded(1024 * 1024).map_err(|error| {
        HostError::ProcessContour(format!("read eliotd launch descriptor: {error}"))
    })?;
    validate_eliotd_launch_descriptor_bytes(&bytes, approved_digest, launch)
}

#[cfg(windows)]
fn validate_eliotd_launch_descriptor_bytes(
    bytes: &[u8],
    approved_digest: &PlatformHandle,
    launch: &RuntimeLaunchDescriptor,
) -> Result<(), HostError> {
    let actual = Sha256::digest(bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor digest changed before launch".to_owned(),
        ));
    }
    let descriptor: EliotdLaunchDescriptor = serde_json::from_slice(bytes).map_err(|error| {
        HostError::ProcessContour(format!("parse eliotd launch descriptor: {error}"))
    })?;
    descriptor.validate().map_err(|error| {
        HostError::ProcessContour(format!("validate eliotd launch descriptor: {error}"))
    })?;
    if descriptor.executable != launch.eliotd_executable_path
        || descriptor.executable_sha256 != launch.eliotd_artifact_digest.as_str()
        || descriptor.working_directory != launch.kernel_work_root
        || descriptor.config_descriptor != launch.eliotd_config_path
        || descriptor.config_descriptor_sha256 != launch.eliotd_config_digest.as_str()
        || descriptor.launch_nonce != launch.eliotd_launch_nonce
        || descriptor.authority_epoch != launch.authority_state_fence.authority_epoch
        || descriptor.generation != launch.authority_generation
        || descriptor.generation != launch.authority_state_fence.resource_generation
    {
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor is not bound to the approved generation".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod phase_b_projection;
#[cfg(windows)]
use phase_b_projection::{
    host_process_identity_digest, host_process_identity_digest_for_host, phase_b_authority_marker,
    phase_b_build_authority_descriptor, phase_b_build_authority_descriptor_for_rebind,
    phase_b_credential_receipt_digest, phase_b_manifest_digest, phase_b_prepared_public_receipt,
    phase_b_public_receipt, phase_b_public_receipt_from_binding, phase_b_root_binding_digest,
    phase_b_watchdog_selector_digest, validate_phase_b_credential_receipt,
};

#[cfg(windows)]
mod phase_b_previous_authority;
#[cfg(windows)]
use phase_b_previous_authority::{
    PhaseBPreviousBinding, phase_b_authority_is_observable, phase_b_observe_previous_binding,
    phase_b_open_existing, phase_b_validate_authority, phase_b_validate_durable_previous_binding,
};

#[cfg(windows)]
mod phase_b_materialization;
#[cfg(windows)]
use phase_b_materialization::{
    agent_bridge_admission_descriptor, open_agent_bridge_final_lease, phase_b_bytes_digest,
    phase_b_lease_bytes, phase_b_lease_identity, phase_b_materialize_file_with_rollback,
    phase_b_remove_rollback_backup, phase_b_restore_or_remove, phase_b_template_bytes,
};
#[cfg(all(windows, test))]
use phase_b_materialization::{phase_b_materialize_file, phase_b_template_path};

#[cfg(windows)]
mod phase_b_previous_projection;
#[cfg(all(test, windows))]
use phase_b_previous_projection::phase_b_live_installation_epoch;
#[cfg(windows)]
use phase_b_previous_projection::{
    phase_b_activation_binding, phase_b_json_string, phase_b_json_u64, phase_b_live_launch,
    phase_b_previous_bootstrap_digest, phase_b_previous_config_digest,
    phase_b_previous_config_value, phase_b_previous_eliotd_digest, phase_b_previous_live_launch,
    phase_b_receipt_digest,
};

fn nonce_after_activation_failure(
    current: &OneTimeNonceState,
) -> Result<OneTimeNonceState, JournalError> {
    match current.state() {
        NonceState::Issued => current.revoke(),
        NonceState::Unissued | NonceState::Consumed | NonceState::Revoked => Ok(current.clone()),
    }
}

fn finish_active_kernel_cleanup(
    durable: Result<(), HostError>,
    cleanup: impl FnOnce() -> Result<(), HostError>,
) -> Result<(), HostError> {
    let cleanup = cleanup();
    match (durable, cleanup) {
        (Ok(()), cleanup) => cleanup,
        (Err(durable), Err(cleanup)) => Err(HostError::RecoveryRequired(format!(
            "durable Kernel failure transition failed ({durable}); contour cleanup result: {cleanup}"
        ))),
        (Err(durable), Ok(())) => Err(durable),
    }
}

#[cfg(windows)]
mod kernel_activation_driver;
#[cfg(windows)]
use kernel_activation_driver::DurableKernelActivationDriver;

#[cfg(windows)]
fn kernel_control_request(
    candidate: &HostKernelCandidateBinding,
    generation: ResourceGeneration,
    command: KernelControlCommand,
    sequence: u64,
) -> Result<KernelControlRequest, HostError> {
    KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new(format!("{}:{sequence}", candidate.activation_id.as_str()))
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        sequence,
        peer_process_id: std::process::id(),
        generation,
        candidate: candidate.clone(),
        command,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
fn activation_response_or_reconcile(
    response: Result<KernelControlResponse, HostError>,
    expected_message_id: &PlatformHandle,
    expected_request_digest: &str,
) -> Result<Option<KernelActivationReceipt>, HostError> {
    let Ok(response) = response else {
        return Ok(None);
    };
    if response.message_id != *expected_message_id
        || response.request_digest != expected_request_digest
    {
        return Ok(None);
    }
    if let Some(error) = response.error {
        return Err(HostError::ProcessContour(format!(
            "Kernel rejected Activate: {error}"
        )));
    }
    Ok(response.activation_receipt)
}

#[cfg(windows)]
fn validate_authenticated_kernel_peer(
    peer: &PeerIdentity,
    expected_pid: u32,
    expected_start_time_100ns: u64,
    expected_image: &Path,
) -> Result<(), HostError> {
    let peer = peer.process_binding().ok_or_else(|| {
        HostError::ProcessContour("Kernel peer identity is unavailable".to_owned())
    })?;
    let observed_image = std::fs::canonicalize(peer.image_path())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let approved_image = std::fs::canonicalize(expected_image)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if peer.process_id() != expected_pid
        || peer.start_time_100ns() != expected_start_time_100ns
        || observed_image != approved_image
    {
        return Err(HostError::ProcessContour(
            "authenticated Kernel peer is not the retained approved process".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn kernel_front_door_expectation(
    candidate: &HostKernelCandidateBinding,
    kernel_process: &ProcessIdentity,
) -> Result<eliot_platform_windows::KernelFrontDoorServerExpectation, HostError> {
    let binding = observe_named_pipe_peer_process_in_job(
        candidate.job_object_id.as_str(),
        kernel_process.process_id,
    )
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let observed = binding.process_binding().identity();
    if observed != kernel_process {
        return Err(HostError::ProcessContour(
            "Kernel Job observation is not the retained process identity".to_owned(),
        ));
    }
    if binding
        .process_binding()
        .executable_file_identity()
        .is_none()
    {
        return Err(HostError::ProcessContour(
            "Kernel process executable FileIdentity is unavailable".to_owned(),
        ));
    }
    let expected_extra_sid = candidate
        .agent_bridge_admission
        .as_ref()
        .map(|descriptor| descriptor.approved_user_sid.clone());
    let acl_mode = kernel_front_door_acl_mode(expected_extra_sid.as_deref());
    eliot_platform_windows::KernelFrontDoorServerExpectation::new(
        LOCAL_SERVICE_SID,
        0,
        candidate.artifact_hash.as_str(),
        acl_mode,
    )
    .map(|expectation| expectation.with_process_and_job_binding(binding))
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
fn kernel_front_door_acl_mode(
    approved_user_sid: Option<&str>,
) -> eliot_platform_windows::KernelFrontDoorAclMode {
    match approved_user_sid {
        None => eliot_platform_windows::KernelFrontDoorAclMode::ServiceOnly,
        Some(client_sid) => {
            eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: client_sid.to_owned(),
            }
        }
    }
}

#[cfg(windows)]
async fn connect_authenticated_kernel_front_door(
    candidate: &HostKernelCandidateBinding,
    kernel_process: &ProcessIdentity,
) -> Result<NamedPipeTransport, HostError> {
    let expected_extra_sid = candidate
        .agent_bridge_admission
        .as_ref()
        .map(|descriptor| descriptor.approved_user_sid.as_str());
    let expectation = kernel_front_door_expectation(candidate, kernel_process)?;
    let transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
        candidate.pipe_identity.as_str(),
        Duration::from_secs(5),
        &expectation,
    )
    .await
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    match (
        transport.kernel_front_door_observed_extra_sid(),
        expected_extra_sid,
    ) {
        (None, None) => Ok(transport),
        (Some(observed), Some(expected)) if observed == expected => Ok(transport),
        _ => Err(HostError::ProcessContour(
            "Kernel front-door extra SID does not match the retained bridge policy".to_owned(),
        )),
    }
}

#[cfg(all(windows, test))]
mod kernel_front_door_tests {
    use super::{LOCAL_SERVICE_SID, kernel_front_door_acl_mode};
    use eliot_platform_windows::KernelFrontDoorAclMode;

    #[test]
    fn bridge_disabled_uses_service_only_acl() {
        assert_eq!(
            kernel_front_door_acl_mode(None),
            KernelFrontDoorAclMode::ServiceOnly
        );
    }

    #[test]
    fn bridge_sid_is_the_only_extra_acl_contour() {
        let approved = "S-1-5-21-1000";
        assert_eq!(
            kernel_front_door_acl_mode(Some(approved)),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: approved.to_owned()
            }
        );
        assert_ne!(
            kernel_front_door_acl_mode(Some("S-1-5-21-2000")),
            kernel_front_door_acl_mode(Some(approved))
        );
        assert_ne!(approved, LOCAL_SERVICE_SID);
    }
}

fn unique_ready_evidence<'a>(
    ready: &'a KernelReadyReceipt,
    prefix: &str,
) -> Result<&'a PlatformHandle, HostError> {
    let mut matching = ready
        .evidence_refs
        .iter()
        .filter(|evidence| evidence.as_str().starts_with(prefix));
    let evidence = matching.next().ok_or_else(|| {
        HostError::ProcessContour(format!("Kernel readiness is missing {prefix} evidence"))
    })?;
    if matching.next().is_some() {
        return Err(HostError::ProcessContour(format!(
            "Kernel readiness contains ambiguous {prefix} evidence"
        )));
    }
    Ok(evidence)
}

fn validated_store_proof_fence(
    requirement: &HostStoreBootstrapRequirement,
    ready: &KernelReadyReceipt,
    approved_store_artifact: &PlatformHandle,
    approved_config: &PlatformHandle,
    request_generation: ResourceGeneration,
) -> Result<PlatformHandle, HostError> {
    requirement
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if requirement.approved_artifact_hash != *approved_store_artifact
        || requirement.approved_config_hash != *approved_config
        || requirement.store_generation != request_generation
        || requirement.state_fence.resource_generation != request_generation
    {
        return Err(HostError::ProcessContour(
            "Store proof is not bound to the approved generation contour".to_owned(),
        ));
    }
    let validation = unique_ready_evidence(ready, "kernel-store-validation:")?;
    let revision = validation
        .as_str()
        .strip_prefix("kernel-store-validation:")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            HostError::ProcessContour(
                "Kernel readiness carries a stale or invalid Store validation snapshot".to_owned(),
            )
        })?;
    let health = unique_ready_evidence(ready, "kernel-store-health:")?;
    let health_binding = health
        .as_str()
        .strip_prefix("kernel-store-health:")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            HostError::ProcessContour(
                "Kernel readiness carries an invalid Store health proof".to_owned(),
            )
        })?;
    let digest = sha256_json(&(
        &requirement.state_fence,
        requirement.store_generation,
        approved_store_artifact,
        approved_config,
        revision,
        health_binding,
    ))?;
    PlatformHandle::new(digest).map_err(|error| HostError::Platform(error.to_string()))
}

fn validate_probe_response(
    request: &KernelControlRequest,
    activation: &KernelActivationReceipt,
    response: &KernelControlResponse,
) -> Result<KernelReadyReceipt, HostError> {
    request
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    response
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if !matches!(&request.command, KernelControlCommand::ProbeReady)
        || response.message_id != request.message_id
        || response.request_digest != request.payload_digest
        || response.error.is_some()
        || response.state != KernelServiceState::Ready
        || response.activation_receipt.is_some()
    {
        return Err(HostError::ProcessContour(
            "Kernel ProbeReady response binding failed".to_owned(),
        ));
    }
    let ready = response.receipt.clone().ok_or_else(|| {
        HostError::ProcessContour("Kernel did not return a ready receipt".to_owned())
    })?;
    let supervision = response.supervision_lease.as_ref().ok_or_else(|| {
        HostError::ProcessContour(
            "Kernel did not return the exact current supervision ORS snapshot".to_owned(),
        )
    })?;
    supervision
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let payload = &supervision.record.artifact.payload;
    if payload.installation_id != request.candidate.installation_id.as_str()
        || payload.host_epoch != request.candidate.host_epoch
        || payload.activation_id != request.candidate.activation_id.as_str()
        || payload.activation_generation != activation.generation
        || payload.kernel_epoch != request.candidate.kernel_epoch
        || payload.state_fence.authority_epoch != request.candidate.kernel_epoch
        || payload.state_fence.resource_generation != activation.generation
        || supervision.record.state != eliot_runtime_contracts::LeaseState::Active
        || supervision.record.projection != eliot_ors::SupervisionLeaseProjection::Active
    {
        return Err(HostError::ProcessContour(
            "Kernel supervision snapshot is foreign to the exact readiness contour".to_owned(),
        ));
    }
    ready
        .validate_for_probe(request, activation)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok(ready)
}

#[cfg(windows)]
struct AuthenticatedKernelReadiness {
    request: KernelControlRequest,
    response: KernelControlResponse,
    ready: KernelReadyReceipt,
    supervision_lease: eliot_ors::SupervisionLeaseSnapshot,
    store_fence: PlatformHandle,
    peer_evidence: PlatformHandle,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishedSupervisionIdentity {
    lease_id: PlatformHandle,
    ors_receipt_digest: PlatformHandle,
    publication_digest: PlatformHandle,
}

#[cfg(windows)]
impl PublishedSupervisionIdentity {
    fn evidence_refs(&self) -> Result<[PlatformHandle; 3], HostError> {
        Ok([
            PlatformHandle::new(format!("supervision-lease:{}", self.lease_id.as_str()))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(format!(
                "supervision-ors-receipt:{}",
                self.ors_receipt_digest.as_str()
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(format!(
                "watchdog-publication:{}",
                self.publication_digest.as_str()
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
        ])
    }

    fn is_bound_by(&self, evidence_refs: &[PlatformHandle]) -> Result<bool, HostError> {
        Ok(self
            .evidence_refs()?
            .iter()
            .all(|expected| evidence_refs.contains(expected)))
    }
}

#[cfg(windows)]
fn readiness_supervision_fence_matches(
    supervision: &PublishedSupervisionIdentity,
    publication_is_exact: bool,
    evidence_refs: &[PlatformHandle],
) -> bool {
    publication_is_exact && supervision.is_bound_by(evidence_refs).unwrap_or(false)
}

#[cfg(windows)]
fn require_exact_supervision_head(
    expected: &eliot_ors::SupervisionLeaseSnapshot,
    read_current: impl FnOnce() -> Result<eliot_ors::SupervisionLeaseSnapshot, HostError>,
) -> Result<(), HostError> {
    if read_current()? != *expected {
        return Err(HostError::RecoveryRequired(
            "Kernel ORS head changed after Watchdog publication and before readiness journal admission"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) struct HostJobBranches {
    kernel: Option<RunningJobChild<PlatformHandle>>,
    store: Option<RunningJobChild<PlatformHandle>>,
    kernel_identity: JobObjectIdentity,
    store_identity: JobObjectIdentity,
    kernel_launch_binding: Option<KernelLaunchBinding>,
    kernel_executable: Option<PathBuf>,
    store_bridge_executable: Option<PathBuf>,
    kernel_lease: Option<LaunchLease>,
    store_lease: Option<LaunchLease>,
    config_path: Option<PathBuf>,
    config_lease: Option<LaunchLease>,
    store_bootstrap_lease: Option<LaunchLease>,
    eliotd_config_lease: Option<LaunchLease>,
    eliotd_descriptor_lease: Option<LaunchLease>,
    store_bootstrap_requirement: Option<HostStoreBootstrapRequirement>,
    config_pin: Option<PinnedRuntimeFile>,
    portable_root: Option<UserOwnedRootLease>,
    launch: Option<RuntimeLaunchDescriptor>,
    kernel_artifact_digest: Option<PlatformHandle>,
    store_artifact_digest: Option<PlatformHandle>,
    config_digest: Option<PlatformHandle>,
    store_config_semantic_hash: Option<PlatformHandle>,
    approved_generation: Option<PlatformHandle>,
    agent_bridge_admission: Option<eliot_kernel_service::AgentBridgeAdmissionDescriptor>,
    kernel_candidate: Option<HostKernelCandidateBinding>,
    kernel_activation_receipt: Option<KernelActivationReceipt>,
    kernel_restart_attempts: u8,
    store_restart_attempts: u8,
}

/// Independent branch disposition after one bounded reconciliation pass.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostBranchDisposition {
    /// Both Host-owned branches are live but have not yet supplied a fresh
    /// authenticated readiness proof.
    LiveAwaitingReadiness,
    /// Both Host-owned branches have an authenticated readiness proof inside
    /// its exact bounded lease.
    Healthy,
    /// Both branches may still be live, but the authoritative readiness proof
    /// is absent, expired, rejected, or durably unknown.  The retained contour
    /// remains independently recoverable and is not killed by this outcome.
    ReadinessDegraded,
    /// Kernel authority is unavailable; the canonical store is not stopped.
    KernelDegraded,
    /// Canonical store is unavailable; Kernel is not stopped.
    StoreDegraded,
    /// Both process branches are unavailable after their independent bounds.
    BothDegraded,
}

#[cfg(windows)]
mod readiness_gate;
#[cfg(all(windows, test))]
use readiness_gate::{DEFAULT_READINESS_CADENCE, ReadinessFailureKind};
#[cfg(windows)]
use readiness_gate::{
    HostReadinessGate, ReadinessCadence, ReadinessContourIdentity, ReadinessGateAction,
    readiness_failure_kind, reconcile_authenticated_readiness,
};

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScmStoreRecoveryRoute {
    Recovered,
    Fenced(HostBranchDisposition),
    Continue(HostBranchDisposition),
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four independent liveness facts are the explicit SCM route discriminator"
)]
struct ScmStoreRecoveryObservation {
    store_requires_restart: bool,
    kernel_live: bool,
    kernel_requires_activation: bool,
    store_present: bool,
}

/// Routes both the early Store-dead observation and the late Store-dead result
/// from generic reconciliation through the Host-owned durable operation. The
/// callback is `execute_store_recovery` in production; this shared discriminator
/// is also the deterministic seam for proving the liveness race cannot bypass
/// the durable outer intent.
#[cfg(windows)]
fn route_scm_store_recovery(
    observation: ScmStoreRecoveryObservation,
    reconciled: Option<Result<HostBranchDisposition, HostError>>,
    request: &HostRuntimeControlRequest,
    recover: impl FnOnce(&HostRuntimeControlRequest) -> Result<(), HostError>,
) -> Result<ScmStoreRecoveryRoute, HostError> {
    let recovery_required = if observation.store_requires_restart {
        true
    } else {
        match reconciled {
            Some(Ok(disposition)) => return Ok(ScmStoreRecoveryRoute::Continue(disposition)),
            Some(Err(HostError::StoreRecoveryRequired(_))) => true,
            Some(Err(error)) => return Err(error),
            None => {
                return Err(HostError::RecoveryRequired(
                    "Store reconciliation result was omitted without an early Store-dead observation"
                        .to_owned(),
                ));
            }
        }
    };
    debug_assert!(recovery_required);
    if !observation.kernel_live || observation.kernel_requires_activation {
        return Ok(ScmStoreRecoveryRoute::Fenced(
            HostBranchDisposition::BothDegraded,
        ));
    }
    if !observation.store_present {
        return Ok(ScmStoreRecoveryRoute::Fenced(
            HostBranchDisposition::StoreDegraded,
        ));
    }
    match recover(request) {
        Ok(()) => Ok(ScmStoreRecoveryRoute::Recovered),
        Err(_) => Ok(ScmStoreRecoveryRoute::Fenced(
            HostBranchDisposition::StoreDegraded,
        )),
    }
}

/// Result of one cheap SCM liveness tick.  The tick never performs bounded
/// restart, file/digest verification, Kernel pipe I/O, or journal append.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostLivenessTick {
    /// A prior authenticated proof remains valid for the entire exact contour.
    HealthyLeasePreserved,
    /// A failed proof is still inside its bounded retry cadence.
    ReadinessRetryPending,
    /// Full reconciliation and, if live, authoritative readiness are due.
    FullReconcileDue,
}

#[cfg(windows)]
fn classify_liveness_tick(
    gate: &mut HostReadinessGate,
    liveness: HostBranchDisposition,
    contour: Option<Result<ReadinessContourIdentity, HostError>>,
    now: std::time::Instant,
) -> HostLivenessTick {
    if liveness != HostBranchDisposition::LiveAwaitingReadiness {
        gate.branch_degraded();
        return HostLivenessTick::FullReconcileDue;
    }
    let contour = match contour {
        Some(Ok(contour)) => Some(contour),
        Some(Err(_)) | None => None,
    };
    match gate.action(contour.as_ref(), now) {
        ReadinessGateAction::PreserveAuthenticatedHealth => HostLivenessTick::HealthyLeasePreserved,
        ReadinessGateAction::RetryPending(_failure) => HostLivenessTick::ReadinessRetryPending,
        ReadinessGateAction::ProbeDue => HostLivenessTick::FullReconcileDue,
    }
}

#[cfg(windows)]
fn descriptor_bound_liveness_tick(
    gate: &mut HostReadinessGate,
    liveness: HostBranchDisposition,
    active_manifest: Option<&CandidateManifest>,
    current_contour: impl FnOnce(
        &PlatformHandle,
        &PlatformHandle,
        &PlatformHandle,
        &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError>,
    now: std::time::Instant,
) -> HostLivenessTick {
    let contour = (liveness == HostBranchDisposition::LiveAwaitingReadiness).then(|| {
        let manifest = active_manifest
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let (kernel_artifact, store_artifact) = manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        current_contour(
            &manifest.generation,
            kernel_artifact,
            store_artifact,
            &manifest.config_digest,
        )
    });
    classify_liveness_tick(gate, liveness, contour, now)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BranchLiveness {
    Live,
    Dead,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StoreRecoveryRequired {
    #[error("Store became dead during branch reconciliation")]
    LateDead,
}

#[cfg(windows)]
#[allow(dead_code)]
enum CutoverLaunchOutcome {
    Candidate,
    Rollback { candidate_error: String },
}

#[cfg(windows)]
#[allow(dead_code)]
impl CutoverLaunchOutcome {
    fn activation_generation<'a>(
        &self,
        candidate: &'a PlatformHandle,
        prior: &'a PlatformHandle,
    ) -> &'a PlatformHandle {
        match self {
            Self::Candidate => candidate,
            Self::Rollback { .. } => prior,
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationObservation {
    Live,
    Dead,
    Unknown,
}

#[cfg(windows)]
struct ReconciliationState<S, K> {
    store: Option<S>,
    kernel: Option<K>,
    store_restart_attempts: u8,
    kernel_restart_attempts: u8,
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "bounded Kernel-only restart stays ordered while Store recovery remains Host-owned"
)]
fn reconcile_state_machine<S, K, SO, KO, KT, KL>(
    state: &mut ReconciliationState<S, K>,
    mut observe_store: SO,
    mut observe_kernel: KO,
    mut terminate_kernel: KT,
    mut launch_kernel: KL,
) -> Result<HostBranchDisposition, StoreRecoveryRequired>
where
    SO: FnMut(Option<&S>) -> ReconciliationObservation,
    KO: FnMut(Option<&K>) -> ReconciliationObservation,
    KT: FnMut(&mut Option<K>) -> Result<(), ()>,
    KL: FnMut() -> Result<K, ()>,
{
    let kernel_observation = observe_kernel(state.kernel.as_ref());
    let store_observation = observe_store(state.store.as_ref());
    if store_observation == ReconciliationObservation::Dead {
        // The generic branch machine may retain and restart Kernel, but it
        // has no durable outer-intent authority for Store mutation.  A Store
        // death observed after its caller's guard is therefore handed back to
        // HostComposition, which owns execute_store_recovery.
        return Err(StoreRecoveryRequired::LateDead);
    }
    let kernel_dead = kernel_observation == ReconciliationObservation::Dead;
    let mut kernel_degraded = kernel_observation == ReconciliationObservation::Unknown;
    let store_degraded = store_observation == ReconciliationObservation::Unknown;

    if kernel_dead && !store_degraded && state.store.is_some() {
        if terminate_kernel(&mut state.kernel).is_err() || state.kernel_restart_attempts >= 1 {
            kernel_degraded = true;
        } else {
            state.kernel_restart_attempts += 1;
            if let Ok(kernel) = launch_kernel() {
                state.kernel = Some(kernel);
                if observe_kernel(state.kernel.as_ref()) != ReconciliationObservation::Live {
                    kernel_degraded = true;
                    if terminate_kernel(&mut state.kernel).is_err() {
                        kernel_degraded = true;
                    }
                }
            } else {
                kernel_degraded = true;
            }
        }
    } else if kernel_dead {
        kernel_degraded = true;
    }

    if state.kernel.is_none() || kernel_observation == ReconciliationObservation::Unknown {
        kernel_degraded = true;
    }
    Ok(match (kernel_degraded, store_degraded) {
        (false, false) => HostBranchDisposition::LiveAwaitingReadiness,
        (true, false) => HostBranchDisposition::KernelDegraded,
        (false, true) => HostBranchDisposition::StoreDegraded,
        (true, true) => HostBranchDisposition::BothDegraded,
    })
}

#[cfg(windows)]
#[allow(dead_code)]
impl HostJobBranches {
    /// Installs the exact Phase-B bridge descriptor for the next Kernel
    /// launch/relaunch. `None` is the legacy, bridge-disabled contour.
    fn set_agent_bridge_admission(
        &mut self,
        descriptor: Option<eliot_kernel_service::AgentBridgeAdmissionDescriptor>,
    ) {
        self.agent_bridge_admission = descriptor;
    }

    /// Creates two owner-scoped Job identities.  The actual Job handles are
    /// created only by the approved suspended launch below; there is no
    /// unbound PID assignment path.
    ///
    /// # Errors
    ///
    /// Returns an error if either owner-scoped Job identity is invalid.
    pub fn new(host: &HostInstallationEpoch) -> Result<Self, WindowsAdapterError> {
        let suffix = format!(
            "{}-{}",
            host.epoch.current.lineage.as_str(),
            host.epoch.current.sequence
        );
        let kernel_identity = JobObjectIdentity::new(format!("Local\\Eliot-Host-Kernel-{suffix}"))?;
        let store_identity = JobObjectIdentity::new(format!("Local\\Eliot-Host-Store-{suffix}"))?;
        let kernel_launch_binding = KernelLaunchBinding::observe_current()?;
        Ok(Self {
            kernel: None,
            store: None,
            kernel_identity,
            store_identity,
            kernel_launch_binding: Some(kernel_launch_binding),
            kernel_executable: None,
            store_bridge_executable: None,
            kernel_lease: None,
            store_lease: None,
            config_path: None,
            config_lease: None,
            store_bootstrap_lease: None,
            eliotd_config_lease: None,
            eliotd_descriptor_lease: None,
            store_bootstrap_requirement: None,
            config_pin: None,
            portable_root: None,
            launch: None,
            kernel_artifact_digest: None,
            store_artifact_digest: None,
            config_digest: None,
            store_config_semantic_hash: None,
            approved_generation: None,
            agent_bridge_admission: None,
            kernel_candidate: None,
            kernel_activation_receipt: None,
            kernel_restart_attempts: 0,
            store_restart_attempts: 0,
        })
    }

    /// Creates an inert Job projection for feature-gated physical recovery
    /// tests without requiring a live Kernel named-pipe peer. The production
    /// constructor above remains the only path that observes the current
    /// process binding; this helper never launches or adopts a child.
    #[cfg(test)]
    pub(crate) fn new_test_support(
        host: &HostInstallationEpoch,
    ) -> Result<Self, WindowsAdapterError> {
        let mut branches = Self::new_fenced(host)?;
        let image_path = std::env::current_exe()
            .map_err(|_| WindowsAdapterError::InvalidInput)?
            .to_string_lossy()
            .into_owned();
        branches.kernel_launch_binding = Some(KernelLaunchBinding {
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE)
                .map_err(|_| WindowsAdapterError::InvalidInput)?,
            host_process: HostProcessBinding {
                process_id: std::process::id(),
                start_time_100ns: 1,
                image_path,
            },
        });
        Ok(branches)
    }

    /// Creates the inert identity projection used while Store recovery is
    /// fenced. No current-process observation or child/Job launch is allowed
    /// on this startup path; the binding is populated only by a later
    /// approved contour admission.
    pub fn new_fenced(host: &HostInstallationEpoch) -> Result<Self, WindowsAdapterError> {
        let suffix = format!(
            "{}-{}",
            host.epoch.current.lineage.as_str(),
            host.epoch.current.sequence
        );
        Ok(Self {
            kernel: None,
            store: None,
            kernel_identity: JobObjectIdentity::new(format!("Local\\Eliot-Host-Kernel-{suffix}"))?,
            store_identity: JobObjectIdentity::new(format!("Local\\Eliot-Host-Store-{suffix}"))?,
            kernel_launch_binding: None,
            kernel_executable: None,
            store_bridge_executable: None,
            kernel_lease: None,
            store_lease: None,
            config_path: None,
            config_lease: None,
            store_bootstrap_lease: None,
            eliotd_config_lease: None,
            eliotd_descriptor_lease: None,
            store_bootstrap_requirement: None,
            config_pin: None,
            portable_root: None,
            launch: None,
            kernel_artifact_digest: None,
            store_artifact_digest: None,
            config_digest: None,
            store_config_semantic_hash: None,
            approved_generation: None,
            agent_bridge_admission: None,
            kernel_candidate: None,
            kernel_activation_receipt: None,
            kernel_restart_attempts: 0,
            store_restart_attempts: 0,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "each value is an explicit launch-authority binding; ambient input is injectable only for scrub tests"
    )]
    fn environment_from<I>(
        ambient: I,
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        job_identity: &JobObjectIdentity,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
        receipt_binding: Option<(&Path, &Path, &PlatformHandle)>,
    ) -> Vec<(OsString, OsString)>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let mut environment = ambient
            .into_iter()
            .filter(|(key, _)| {
                let key = key.to_string_lossy();
                ![
                    "ELIOT_APPROVED_GENERATION",
                    "ELIOT_GENERATION_CONFIG_DIGEST",
                    "ELIOT_APPROVED_ARTIFACT",
                    "ELIOT_GENERATION_CONFIG_PATH",
                    "ELIOT_HOST_INSTALLATION",
                    "ELIOT_HOST_EPOCH",
                    "ELIOT_ACTIVATION_NONCE",
                    "ELIOT_JOB_OBJECT_ID",
                ]
                .into_iter()
                .chain(KERNEL_BOOTSTRAP_ENVIRONMENT)
                .any(|reserved| key.eq_ignore_ascii_case(reserved))
            })
            .collect::<Vec<_>>();
        environment.extend([
            (
                OsString::from("ELIOT_APPROVED_GENERATION"),
                OsString::from(generation.as_str()),
            ),
            (
                OsString::from("ELIOT_GENERATION_CONFIG_DIGEST"),
                OsString::from(config_digest.as_str()),
            ),
            (
                OsString::from("ELIOT_APPROVED_ARTIFACT"),
                OsString::from(artifact.as_str()),
            ),
            (
                OsString::from("ELIOT_GENERATION_CONFIG_PATH"),
                config_path.as_os_str().to_owned(),
            ),
            (
                OsString::from("ELIOT_HOST_INSTALLATION"),
                OsString::from(host.installation.as_str()),
            ),
            (
                OsString::from("ELIOT_HOST_EPOCH"),
                OsString::from(host.epoch.current.sequence.to_string()),
            ),
            (
                OsString::from("ELIOT_JOB_OBJECT_ID"),
                OsString::from(job_identity.name()),
            ),
        ]);
        if let Some(binding) = kernel_launch_binding {
            environment.extend([
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[0]),
                    OsString::from(binding.pipe_identity.as_str()),
                ),
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[1]),
                    OsString::from(binding.host_process.process_id.to_string()),
                ),
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[2]),
                    OsString::from(binding.host_process.start_time_100ns.to_string()),
                ),
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[3]),
                    OsString::from(&binding.host_process.image_path),
                ),
            ]);
            if let Some((receipt_root, ors_root, roots_digest)) = receipt_binding {
                environment.extend([
                    (
                        OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[4]),
                        receipt_root.as_os_str().to_owned(),
                    ),
                    (
                        OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[5]),
                        ors_root.as_os_str().to_owned(),
                    ),
                    (
                        OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[6]),
                        OsString::from(roots_digest.as_str()),
                    ),
                ]);
            }
        }
        environment
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the launch environment projection binds the complete admitted Host, generation, process, and receipt contour"
    )]
    fn environment(
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        job_identity: &JobObjectIdentity,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
        receipt_binding: Option<(&Path, &Path, &PlatformHandle)>,
    ) -> Vec<(OsString, OsString)> {
        Self::environment_from(
            std::env::vars_os(),
            host,
            generation,
            config_digest,
            artifact,
            config_path,
            job_identity,
            kernel_launch_binding,
            receipt_binding,
        )
    }

    /// Completes the authenticated Host↔Kernel lifecycle before Host
    /// publishes any successful contour observation.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the explicit durable activation transaction preserves the ordered generation, journal, prior-disposition, and authority bindings"
    )]
    fn complete_kernel_control<B: JournalBackend>(
        &mut self,
        generation: &PlatformHandle,
        host: &HostInstallationEpoch,
        journal: &HostStateJournalService<B>,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
        prior_kernel_disposition: PriorKernelDisposition,
        kernel_generation: EpochTransition,
        kernel_authority_epoch: AuthorityEpoch,
    ) -> Result<(KernelActivationReceipt, KernelReadyReceipt), HostError> {
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let kernel_artifact = self.kernel_artifact_digest.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Kernel artifact digest is missing".to_owned())
        })?;
        let config_digest = self
            .config_digest
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("config digest is missing".to_owned()))?;
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel process is missing".to_owned()))?;
        let process = kernel.evidence().process();
        if !kernel
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == process)
        {
            return Err(HostError::ProcessContour(
                "Job observation does not contain the exact launched Kernel process".to_owned(),
            ));
        }
        match kernel
            .observe()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
        {
            eliot_platform_windows::RunningJobObservation::Running { active_processes }
                if active_processes > 0 => {}
            eliot_platform_windows::RunningJobObservation::Running { .. } => {
                return Err(HostError::ProcessContour(
                    "Kernel Job reports zero active processes".to_owned(),
                ));
            }
            eliot_platform_windows::RunningJobObservation::RootExited { .. }
            | eliot_platform_windows::RunningJobObservation::Exited { .. } => {
                return Err(HostError::ProcessContour(
                    "Kernel exited before authenticated control".to_owned(),
                ));
            }
        }
        let expected_kernel_image = self
            .kernel_executable
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is missing".to_owned()))?
            .clone();
        let authority_epoch = AuthorityEpoch::new(host.epoch.current.sequence)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        // Kernel authenticates the connected Host peer against this exact
        // value, so it is read from the live current-process handle. A PID
        // alone would not make PID reuse or image substitution observable.
        let kernel_launch_binding = self.kernel_launch_binding.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "Kernel launch binding is unavailable while Host is fenced".to_owned(),
            )
        })?;
        kernel_launch_binding.validate_current()?;
        // Inert projection of the Host-retained Kernel Job. It grants nothing:
        // Kernel must reopen the named Job and re-observe its own root
        // membership before it will author readiness.
        let recoverable_job = kernel.evidence().recoverable_job_binding();
        let job_binding: HostJobBinding = serde_json::from_value(
            serde_json::to_value(&recoverable_job)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        job_binding
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let journal_state = journal
            .snapshot()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let activation_record = journal_state.activation.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "Host journal has no current activation for supervision incarnation".to_owned(),
            )
        })?;
        if activation_record.activation_id != *activation_id {
            return Err(HostError::ProcessContour(
                "Host journal activation identity does not match Kernel candidate".to_owned(),
            ));
        }
        let predecessor = match (
            matches!(
                prior_kernel_disposition,
                PriorKernelDisposition::NoPriorKernel
            ),
            journal_state.readiness_observations.last(),
        ) {
            (true, None) => None,
            (true, Some(_)) => {
                return Err(HostError::RecoveryRequired(
                    "NoPriorKernel is inconsistent with retained readiness history".to_owned(),
                ));
            }
            (false, None) => {
                return Err(HostError::RecoveryRequired(
                    "Kernel restart has no retained supervision predecessor observation".to_owned(),
                ));
            }
            (false, Some(observation)) => Some(
                observation
                    .active_supervision_lease
                    .clone()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "retained readiness observation has no exact supervision predecessor"
                                .to_owned(),
                        )
                    })?,
            ),
        };
        let approved_supervision_authority = launch
            .provisioned_supervision_authority()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let approved_template = approved_supervision_authority
            .watchdog_admission_template()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let supervision_incarnation = SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: launch.supervision_lease_scope_id().to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: host.installation.as_str().to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: host.epoch.current.lineage.as_str().to_owned(),
                sequence: host.epoch.current.sequence,
            },
            activation_id: activation_id.as_str().to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: activation_generation.current.lineage.as_str().to_owned(),
                sequence: activation_generation.current.sequence,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: kernel_generation.current.lineage.as_str().to_owned(),
                sequence: kernel_generation.current.sequence,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: activation_record
                    .lineage
                    .watchdog_epoch
                    .lineage
                    .as_str()
                    .to_owned(),
                sequence: activation_record.lineage.watchdog_epoch.sequence,
            },
            observation_scope: approved_template.observation_scope.clone(),
            wake_policy: approved_template.wake_policy.clone(),
            predecessor,
        }
        .with_derived_ids()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        supervision_incarnation
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let candidate = HostKernelCandidateBinding {
            installation_id: host.installation.clone(),
            host_epoch: authority_epoch,
            kernel_epoch: kernel_authority_epoch,
            activation_id: activation_id.clone(),
            artifact_hash: kernel_artifact.clone(),
            config_hash: config_digest.clone(),
            job_object_id: PlatformHandle::new(kernel.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            pipe_identity: kernel_launch_binding.pipe_identity.clone(),
            host_process: kernel_launch_binding.host_process.clone(),
            job_binding,
            supervision_incarnation,
            restart_budget: RestartBudget::new(3, 3)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            // The bridge descriptor is projected only after the exact
            // Phase-B public receipt and protected profile/declaration pair
            // have been reopened and the staged executable revalidated.
            agent_bridge_admission: self.agent_bridge_admission.clone(),
            containment_action: None,
        };
        candidate
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let root = recoverable_job.root();
        let root_process = root.process();
        let file_identity = root.executable_file_identity();
        let durable_job = KernelJobBinding {
            job_name: PlatformHandle::new(recoverable_job.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            owner: PlatformHandle::new("Kernel")
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            root_pid: root_process.process_id,
            root_start_time_100ns: root_process.start_time_100ns,
            root_image_path: PlatformHandle::new(root_process.image_path.clone())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            root_volume_serial_number: file_identity.volume_serial_number,
            root_file_index: file_identity.file_index,
        };
        let process_record = ServiceProcessRecord {
            process_id: format!(
                "pid:{}:start:{}",
                root_process.process_id, root_process.start_time_100ns
            ),
            owner: "Kernel".to_owned(),
            state: ServiceProcessState::Starting,
            health: HealthVector::healthy(),
            authority_epoch: candidate.kernel_epoch,
        };
        let mut activation = DurableKernelActivationDriver::bind_candidate(
            journal,
            host,
            activation_id,
            activation_generation,
            kernel_artifact.clone(),
            candidate.pipe_identity.clone(),
            durable_job,
            prior_kernel_disposition,
            kernel_generation,
            process_record,
        )?;
        let store = self.store.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store process is missing before Kernel bootstrap".to_owned())
        })?;
        let store_process = store.evidence().process();
        if !store
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == store_process)
        {
            return Err(HostError::ProcessContour(
                "Store Job observation does not contain the exact launched Store process"
                    .to_owned(),
            ));
        }
        let store_handoff = StoreBootstrapHandoff {
            requirement: self.store_bootstrap_requirement.clone().ok_or_else(|| {
                HostError::ProcessContour(
                    "Store bootstrap requirement is missing before Kernel bootstrap".to_owned(),
                )
            })?,
            process_binding: StoreProcessBinding {
                process: HostProcessBinding {
                    process_id: store_process.process_id,
                    start_time_100ns: store_process.start_time_100ns,
                    image_path: store_process.image_path.clone(),
                },
                job: PlatformHandle::new(store.job_identity().name())
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            },
        };
        store_handoff
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        // Host deliberately authors no readiness receipt. Readiness is proven
        // by Kernel from its own live process, Job, authority, configuration
        // and Store observations, and arrives on the ProbeReady response.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let ready = runtime.block_on(async {
            let mut transport =
                connect_authenticated_kernel_front_door(&candidate, process).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                process.process_id,
                process.start_time_100ns,
                &expected_kernel_image,
            )?;
            let limits = TransportLimits::default();
            let commands = vec![
                KernelControlCommand::BootstrapStore(store_handoff),
                KernelControlCommand::Reconcile,
                KernelControlCommand::Shadow,
                KernelControlCommand::PrepareHandoff,
            ];
            for (index, command) in commands.into_iter().enumerate() {
                let sequence = u64::try_from(index + 1)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let message_id = PlatformHandle::new(format!(
                    "{}:{}",
                    candidate.activation_id.as_str(),
                    sequence
                ))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let request = KernelControlRequest {
                    wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                    wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                    message_id: message_id.clone(),
                    sequence,
                    peer_process_id: std::process::id(),
                    generation: launch.authority_generation,
                    candidate: candidate.clone(),
                    command,
                    payload_digest: String::new(),
                }
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let frame = control_request_frame(
                    format!(
                        "host-control:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                match transport
                    .send_frame(&frame, limits)
                    .await
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?
                {
                    DeliveryOutcome::Delivered => {}
                    DeliveryOutcome::UnknownOutcome => {
                        return Err(HostError::RecoveryRequired(
                            "Kernel control delivery outcome is unknown".to_owned(),
                        ));
                    }
                }
                let response = transport
                    .receive_frame(limits)
                    .await
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let response = decode_control_response_frame(&response)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                if response.message_id != message_id
                    || response.request_digest != request.payload_digest
                    || response.error.is_some()
                {
                    return Err(HostError::ProcessContour(
                        "Kernel control response binding failed".to_owned(),
                    ));
                }
            }
            activation.handoff_prepared()?;
            activation.prior_disposition_committed()?;
            let permit = activation.issue_nonce(&candidate, launch.authority_generation)?;
            activation.activating()?;
            let activate_request = kernel_control_request(
                &candidate,
                launch.authority_generation,
                KernelControlCommand::Activate(permit.clone()),
                5,
            )?;
            let activate_digest = activate_request.payload_digest.clone();
            let activate_frame = control_request_frame(
                format!(
                    "host-control:{}:{}",
                    generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &activate_request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let delivered_response = match transport.send_frame(&activate_frame, limits).await {
                Ok(DeliveryOutcome::Delivered) => Some(
                    transport
                        .receive_frame(limits)
                        .await
                        .map_err(|error| HostError::RecoveryRequired(error.to_string()))
                        .and_then(|frame| {
                            decode_control_response_frame(&frame)
                                .map_err(|error| HostError::RecoveryRequired(error.to_string()))
                        }),
                ),
                Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => None,
            };
            let direct_receipt = delivered_response
                .map(|response| {
                    activation_response_or_reconcile(
                        response,
                        &activate_request.message_id,
                        &activate_request.payload_digest,
                    )
                })
                .transpose()?
                .flatten();
            let (activation_receipt, probe_sequence) = if let Some(receipt) = direct_receipt {
                (receipt, 6)
            } else {
                // Do not resend the permit.  Reconnect and query the exact
                // operation/request digest without carrying nonce material.
                // Receive/decode/binding loss after Delivered is also an
                // unknown outcome and follows this same path.
                drop(transport);
                transport = connect_authenticated_kernel_front_door(&candidate, process)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                validate_authenticated_kernel_peer(
                    transport.peer_identity(),
                    process.process_id,
                    process.start_time_100ns,
                    &expected_kernel_image,
                )
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let query = KernelActivationQuery {
                    operation_id: permit.operation_id.clone(),
                    activate_request_digest: activate_digest,
                };
                let query_request = kernel_control_request(
                    &candidate,
                    launch.authority_generation,
                    KernelControlCommand::ReconcileActivation(query),
                    1,
                )?;
                let query_frame = control_request_frame(
                    format!(
                        "host-control:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &query_request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                match transport
                    .send_frame(&query_frame, limits)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
                {
                    DeliveryOutcome::Delivered => {}
                    DeliveryOutcome::UnknownOutcome => {
                        return Err(HostError::RecoveryRequired(
                            "Kernel activation reconciliation outcome is unknown".to_owned(),
                        ));
                    }
                }
                let response = transport
                    .receive_frame(limits)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let response = decode_control_response_frame(&response)
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                if response.message_id != query_request.message_id
                    || response.request_digest != query_request.payload_digest
                    || response.error.is_some()
                {
                    return Err(HostError::RecoveryRequired(
                        "Kernel activation reconciliation response was not exact".to_owned(),
                    ));
                }
                let receipt = response.activation_receipt.ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Kernel did not retain the queried activation operation".to_owned(),
                    )
                })?;
                (receipt, 2)
            };
            activation_receipt
                .validate(&permit)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let probe_request = kernel_control_request(
                &candidate,
                launch.authority_generation,
                KernelControlCommand::ProbeReady,
                probe_sequence,
            )?;
            let probe_frame = control_request_frame(
                format!(
                    "host-control:{}:{}",
                    generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &probe_request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            match transport
                .send_frame(&probe_frame, limits)
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
            {
                DeliveryOutcome::Delivered => {}
                DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel ProbeReady delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let response = transport
                .receive_frame(limits)
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let response = decode_control_response_frame(&response)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            if response.message_id != probe_request.message_id
                || response.request_digest != probe_request.payload_digest
                || response.error.is_some()
                || response.state != KernelServiceState::Ready
            {
                return Err(HostError::ProcessContour(
                    "Kernel ProbeReady response binding failed".to_owned(),
                ));
            }
            let ready = response.receipt.ok_or_else(|| {
                HostError::ProcessContour("Kernel did not return a ready receipt".to_owned())
            })?;
            ready
                .validate_for_probe(&probe_request, &activation_receipt)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            Ok((activation_receipt, ready))
        });
        let (activation_receipt, ready) = match ready {
            Ok(receipts) => receipts,
            Err(error) => {
                let failure = activation.fail("kernel-control-activation-failed");
                return Err(match failure {
                    Ok(()) => error,
                    Err(failure) => HostError::RecoveryRequired(format!(
                        "Kernel activation failed ({error}); durable failure transition failed ({failure})"
                    )),
                });
            }
        };
        if let Err(error) = activation.active(&candidate, &activation_receipt, &ready) {
            let failure = activation.fail("kernel-active-commit-failed");
            return Err(match failure {
                Ok(()) => error,
                Err(failure) => HostError::RecoveryRequired(format!(
                    "Kernel Active commit failed ({error}); durable revoke failed ({failure})"
                )),
            });
        }
        self.kernel_candidate = Some(candidate);
        self.kernel_activation_receipt = Some(activation_receipt.clone());
        self.reconcile_store_rebind_records(
            generation,
            journal,
            host,
            activation_id,
            activation_generation,
        )?;
        Ok((activation_receipt, ready))
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the exact query carries every authenticated process and request binding"
    )]
    async fn query_store_rebind_exact(
        operation_id: &PlatformHandle,
        request_digest: &str,
        generation: &PlatformHandle,
        candidate: &HostKernelCandidateBinding,
        authority_generation: ResourceGeneration,
        kernel_process_id: u32,
        kernel_process_start_time_100ns: u64,
        expected_kernel_image: &Path,
        label: &str,
    ) -> Result<Option<StoreRebindReceipt>, HostError> {
        let kernel_process = ProcessIdentity {
            process_id: kernel_process_id,
            start_time_100ns: kernel_process_start_time_100ns,
            image_path: expected_kernel_image
                .to_str()
                .ok_or_else(|| HostError::ProcessContour("Kernel image is not UTF-8".to_owned()))?
                .to_owned(),
        };
        let mut transport = connect_authenticated_kernel_front_door(candidate, &kernel_process)
            .await
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        validate_authenticated_kernel_peer(
            transport.peer_identity(),
            kernel_process_id,
            kernel_process_start_time_100ns,
            expected_kernel_image,
        )
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let query = StoreRebindQuery {
            operation_id: operation_id.clone(),
            request_digest: request_digest.to_owned(),
        };
        let request = KernelControlRequest {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: fresh_identity(&format!("{label}-message"))?,
            sequence: 1,
            peer_process_id: std::process::id(),
            generation: authority_generation,
            candidate: candidate.clone(),
            command: KernelControlCommand::ReconcileRebindStore(query),
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let frame = control_request_frame(
            format!(
                "{label}:{}:{}",
                generation.as_str(),
                candidate.activation_id.as_str()
            ),
            &request,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        match transport
            .send_frame(&frame, TransportLimits::default())
            .await
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(HostError::RecoveryRequired(
                    "Store rebind exact query delivery outcome is unknown".to_owned(),
                ));
            }
        }
        let frame = transport
            .receive_frame(TransportLimits::default())
            .await
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let response = decode_control_response_frame(&frame)
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if response.message_id != request.message_id
            || response.request_digest != request.payload_digest
            || response.error.is_some()
        {
            return Err(HostError::RecoveryRequired(
                "Store rebind exact query response was not bound".to_owned(),
            ));
        }
        let Some(receipt) = response.store_rebind_receipt else {
            return Ok(None);
        };
        if receipt.operation_id != *operation_id || receipt.request_digest != request_digest {
            return Err(HostError::RecoveryRequired(
                "Store rebind exact query receipt identity mismatch".to_owned(),
            ));
        }
        receipt
            .validate()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if receipt.candidate_binding_digest != candidate_digest
            || receipt.generation != authority_generation
            || receipt.authority_epoch != candidate.kernel_epoch
        {
            return Err(HostError::RecoveryRequired(
                "Store rebind exact query receipt candidate lineage mismatch".to_owned(),
            ));
        }
        Ok(Some(receipt))
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "exact Store recovery keeps Host journal, candidate, peer and terminal disposition checks in one boundary"
    )]
    fn reconcile_store_rebind_records<B: JournalBackend>(
        &self,
        generation: &PlatformHandle,
        journal: &HostStateJournalService<B>,
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
    ) -> Result<(), HostError> {
        let records = journal
            .snapshot()?
            .store_rebinds
            .into_iter()
            .filter(|record| {
                matches!(
                    record.state,
                    StoreRebindState::Pending | StoreRebindState::Unknown
                )
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(());
        }
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no runtime launch descriptor".to_owned(),
            )
        })?;
        let candidate = self.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no Kernel candidate".to_owned(),
            )
        })?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let active_fence = record_fence(host, activation_id, activation_generation);
        let kernel = self.kernel.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no live Kernel".to_owned(),
            )
        })?;
        let kernel_process = kernel.evidence().process();
        let expected_kernel_image = self.kernel_executable.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no Kernel image".to_owned(),
            )
        })?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let mut unknown = Vec::new();
        runtime.block_on(async {
            for record in records {
                if record.fence != active_fence
                    || record.candidate_binding_digest.as_str() != candidate_digest
                {
                    let operation_id = record.operation_id.clone();
                    let request_digest = record.request_digest.as_str().to_owned();
                    persist_store_rebind_disposition(
                        journal,
                        &operation_id,
                        &request_digest,
                        StoreRebindState::Unknown,
                    )?;
                    unknown.push(format!(
                        "{}:{}: Store rebind journal lineage is not the active Host candidate",
                        operation_id.as_str(),
                        request_digest
                    ));
                    continue;
                }
                let result = Self::query_store_rebind_exact(
                    &record.operation_id,
                    record.request_digest.as_str(),
                    generation,
                    candidate,
                    launch.authority_generation,
                    kernel_process.process_id,
                    kernel_process.start_time_100ns,
                    expected_kernel_image,
                    "host-store-rebind-startup-query",
                )
                .await;
                match result {
                    Ok(Some(receipt)) => {
                        append_store_rebind_terminal(
                            journal,
                            record,
                            StoreRebindState::Committed,
                            Some(&receipt),
                        )?;
                    }
                    Ok(None) => {
                        append_store_rebind_terminal(
                            journal,
                            record,
                            StoreRebindState::Aborted,
                            None,
                        )?;
                    }
                    Err(error) => {
                        let operation_id = record.operation_id.clone();
                        let request_digest = record.request_digest.as_str().to_owned();
                        persist_store_rebind_disposition(
                            journal,
                            &operation_id,
                            &request_digest,
                            StoreRebindState::Unknown,
                        )?;
                        unknown.push(format!(
                            "{}:{}: {}",
                            operation_id.as_str(),
                            request_digest,
                            error
                        ));
                    }
                }
            }
            Ok::<(), HostError>(())
        })?;
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(HostError::RecoveryRequired(format!(
                "Store rebind startup recovery remains unknown: {}",
                unknown.join(", ")
            )))
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "single ordered Host↔Kernel rebind transaction"
    )]
    fn rebind_store_control(
        &self,
        generation: &PlatformHandle,
        journal: &ProductionHostStateJournal,
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
        store_recovery: Option<(&Path, &HostRuntimeControlRequest)>,
    ) -> Result<StoreRebindReceipt, HostError> {
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let candidate = self.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        self.kernel_activation_receipt.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel activation receipt is missing".to_owned())
        })?;
        let requirement = self.store_bootstrap_requirement.clone().ok_or_else(|| {
            HostError::ProcessContour("retained Store bootstrap requirement is missing".to_owned())
        })?;
        let store = self.store.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store process is missing for rebind".to_owned())
        })?;
        let store_process = store.evidence().process();
        if !store
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == store_process)
        {
            return Err(HostError::ProcessContour(
                "Store Job observation does not contain exact relaunched Store process".to_owned(),
            ));
        }
        self.reconcile_store_rebind_records(
            generation,
            journal,
            host,
            activation_id,
            activation_generation,
        )?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_vec(&requirement.state_fence)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
        hasher.update(launch.authority_generation.value().to_le_bytes());
        hasher.update(candidate.kernel_epoch.value().to_le_bytes());
        hasher.update(requirement.approved_artifact_hash.as_str().as_bytes());
        hasher.update(requirement.approved_config_hash.as_str().as_bytes());
        hasher.update(store_process.process_id.to_le_bytes());
        hasher.update(store_process.start_time_100ns.to_le_bytes());
        hasher.update(store_process.image_path.as_bytes());
        hasher.update(
            PlatformHandle::new(store.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
                .as_str()
                .as_bytes(),
        );
        hasher.update(candidate_digest.as_bytes());
        let store_fence = format!("{:x}", hasher.finalize());
        let snapshot = journal.snapshot().map_err(HostError::Journal)?;
        let snapshot_pending = snapshot.store_rebinds.into_iter().find(|record| {
            matches!(
                record.state,
                StoreRebindState::Pending | StoreRebindState::Unknown
            )
        });
        let mut disposition_operation_id = snapshot_pending
            .as_ref()
            .map(|record| record.operation_id.clone());
        let mut disposition_request_digest = snapshot_pending
            .as_ref()
            .map(|record| record.request_digest.as_str().to_owned());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let result = runtime.block_on(async {
            let expected_kernel_image = self
                .kernel_executable
                .as_ref()
                .ok_or_else(|| HostError::ProcessContour("Kernel image is missing".to_owned()))?
                .clone();
            let kprocess = self
                .kernel
                .as_ref()
                .ok_or_else(|| HostError::ProcessContour("Kernel process is missing".to_owned()))?
                .evidence()
                .process();
            let mut transport =
                connect_authenticated_kernel_front_door(candidate, kprocess).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                kprocess.process_id,
                kprocess.start_time_100ns,
                &expected_kernel_image,
            )?;
            if let Some(pending) = snapshot_pending.clone() {
                let pending_query = StoreRebindQuery {
                    operation_id: pending.operation_id.clone(),
                    request_digest: pending.request_digest.as_str().to_owned(),
                };
                let pending_query_request = KernelControlRequest {
                    wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                    wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                    message_id: fresh_identity("store-rebind-query-pending")?,
                    sequence: 1,
                    peer_process_id: std::process::id(),
                    generation: launch.authority_generation,
                    candidate: candidate.clone(),
                    command: KernelControlCommand::ReconcileRebindStore(pending_query.clone()),
                    payload_digest: String::new(),
                }
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let pending_frame = control_request_frame(
                    format!(
                        "host-rebind-query-pending:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &pending_query_request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let mut query_transport =
                    connect_authenticated_kernel_front_door(candidate, kprocess)
                        .await
                        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                validate_authenticated_kernel_peer(
                    query_transport.peer_identity(),
                    kprocess.process_id,
                    kprocess.start_time_100ns,
                    &expected_kernel_image,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                if query_transport
                    .send_frame(&pending_frame, TransportLimits::default())
                    .await
                    .is_ok()
                    && let Ok(frame) = query_transport
                        .receive_frame(TransportLimits::default())
                        .await
                    && let Ok(response) = decode_control_response_frame(&frame)
                    && response.message_id == pending_query_request.message_id
                    && response.request_digest == pending_query_request.payload_digest
                    && response.error.is_none()
                    && let Some(receipt) = response.store_rebind_receipt
                    && receipt.operation_id == pending.operation_id
                    && receipt.request_digest == pending.request_digest.as_str()
                {
                    append_store_rebind_terminal(
                        journal,
                        pending,
                        StoreRebindState::Committed,
                        Some(&receipt),
                    )?;
                    return Ok(receipt);
                }
                return Err(HostError::RecoveryRequired(
                    "store rebind pending requires successful query before fresh operation"
                        .to_owned(),
                ));
            }
            let operation_id = fresh_identity("store-rebind")?;
            disposition_operation_id = Some(operation_id.clone());
            let handoff = StoreRebindHandoff {
                operation_id: operation_id.clone(),
                request_digest: "0".repeat(64),
                requirement: requirement.clone(),
                process_binding: StoreProcessBinding {
                    process: HostProcessBinding {
                        process_id: store_process.process_id,
                        start_time_100ns: store_process.start_time_100ns,
                        image_path: store_process.image_path.clone(),
                    },
                    job: PlatformHandle::new(store.job_identity().name())
                        .map_err(|error| HostError::ProcessContour(error.to_string()))?,
                },
                candidate_binding_digest: candidate_digest.clone(),
                generation: launch.authority_generation,
                authority_epoch: candidate.kernel_epoch,
                store_fence: store_fence.clone(),
            };
            handoff
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let mut handoff_with_digest = handoff.clone();
            let canonical = handoff_with_digest
                .canonical_request_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            handoff_with_digest.request_digest = canonical.clone();
            handoff_with_digest
                .validate_canonical_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            if let Some((host_state_root, recovery_request)) = store_recovery {
                // Publish the outer->inner identity before the inner journal
                // request or delivery. A crash after Kernel commits can then
                // identify exactly one canonical StoreRebind; destination
                // state and an unrelated committed record are insufficient.
                persist_store_recovery_inner_binding(
                    host_state_root,
                    recovery_request,
                    host,
                    &handoff_with_digest,
                )?;
            }
            // Retain the exact request identity before any frame construction
            // or delivery can fail; every later terminal disposition must use
            // this operation/request pair rather than a current fence.
            disposition_request_digest = Some(canonical.clone());
            let request = KernelControlRequest {
                wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                message_id: fresh_identity("store-rebind-req")?,
                sequence: 1,
                peer_process_id: std::process::id(),
                generation: launch.authority_generation,
                candidate: candidate.clone(),
                command: KernelControlCommand::RebindStore(handoff_with_digest.clone()),
                payload_digest: canonical.clone(),
            };
            request
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let pending_record = StoreRebindRecord {
                fence: record_fence(host, activation_id, activation_generation),
                operation: operation(&format!(
                    "store-rebind:{}",
                    handoff_with_digest.operation_id.as_str()
                ))?,
                state: StoreRebindState::Pending,
                operation_id: handoff_with_digest.operation_id.clone(),
                request_digest: PlatformHandle::new(canonical.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                requirement: PlatformHandle::new(format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&handoff.requirement)
                            .map_err(|error| HostError::Platform(error.to_string()))?
                    )
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
                candidate_binding_digest: PlatformHandle::new(
                    handoff_with_digest.candidate_binding_digest.clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                store_fence: PlatformHandle::new(handoff_with_digest.store_fence.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                process_id: handoff_with_digest.process_binding.process.process_id,
                process_start_time_100ns: handoff_with_digest
                    .process_binding
                    .process
                    .start_time_100ns,
                process_image_path: PlatformHandle::new(
                    handoff_with_digest
                        .process_binding
                        .process
                        .image_path
                        .clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                job_name: handoff_with_digest.process_binding.job.clone(),
                generation: handoff_with_digest.generation.value(),
                authority_epoch: handoff_with_digest.authority_epoch.value(),
                receipt_request_digest: None,
                receipt_store_fence: None,
            };
            append_reconciled(journal, HostStateRecord::StoreRebind(pending_record))?;
            let frame = control_request_frame(
                format!(
                    "host-rebind:{}:{}",
                    generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let limits = TransportLimits::default();
            let outer_digest = request.payload_digest.clone();
            let outer_message_id = request.message_id.clone();
            let delivered = match transport.send_frame(&frame, limits).await {
                Ok(DeliveryOutcome::Delivered) => true,
                Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => false,
            };
            let receipt = if delivered {
                match transport.receive_frame(limits).await {
                    Ok(frame) => match decode_control_response_frame(&frame) {
                        Ok(response)
                            if response.message_id == outer_message_id
                                && response.request_digest == outer_digest
                                && response.error.is_none() =>
                        {
                            response.store_rebind_receipt
                        }
                        Ok(_) | Err(_) => None,
                    },
                    Err(_) => None,
                }
            } else {
                None
            };
            let final_receipt = if let Some(r) = receipt {
                if r.operation_id != operation_id || r.request_digest != outer_digest {
                    return Err(HostError::ProcessContour(
                        "Store rebind direct receipt mismatch".to_owned(),
                    ));
                }
                r
            } else {
                drop(transport);
                let mut transport2 = connect_authenticated_kernel_front_door(candidate, kprocess)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                validate_authenticated_kernel_peer(
                    transport2.peer_identity(),
                    kprocess.process_id,
                    kprocess.start_time_100ns,
                    &expected_kernel_image,
                )
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let query = StoreRebindQuery {
                    operation_id: operation_id.clone(),
                    request_digest: outer_digest.clone(),
                };
                let query_request = KernelControlRequest {
                    wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                    wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                    message_id: fresh_identity("store-rebind-query")?,
                    sequence: 1,
                    peer_process_id: std::process::id(),
                    generation: launch.authority_generation,
                    candidate: candidate.clone(),
                    command: KernelControlCommand::ReconcileRebindStore(query),
                    payload_digest: String::new(),
                }
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let query_frame = control_request_frame(
                    format!(
                        "host-rebind-query:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &query_request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                match transport2.send_frame(&query_frame, limits).await {
                    Ok(DeliveryOutcome::Delivered) => {}
                    _ => {
                        return Err(HostError::RecoveryRequired(
                            "Store rebind reconciliation delivery is unknown".to_owned(),
                        ));
                    }
                }
                let response = transport2
                    .receive_frame(limits)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let response = decode_control_response_frame(&response)
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                if response.message_id != query_request.message_id
                    || response.request_digest != query_request.payload_digest
                    || response.error.is_some()
                {
                    return Err(HostError::RecoveryRequired(
                        "Store rebind reconciliation response not exact".to_owned(),
                    ));
                }
                response.store_rebind_receipt.ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store rebind reconciliation confirmed operation is not committed"
                            .to_owned(),
                    )
                })?
            };
            if final_receipt.candidate_binding_digest != candidate_digest
                || final_receipt.generation != launch.authority_generation
                || final_receipt.authority_epoch != candidate.kernel_epoch
                || final_receipt.store_fence != store_fence
                || final_receipt.process_binding.process.process_id != store_process.process_id
                || final_receipt.process_binding.process.start_time_100ns
                    != store_process.start_time_100ns
                || final_receipt.process_binding.process.image_path != store_process.image_path
                || final_receipt.process_binding.job.as_str() != store.job_identity().name()
            {
                return Err(HostError::ProcessContour(
                    "Store rebind receipt binding mismatch".to_owned(),
                ));
            }
            if final_receipt.request_digest != canonical
                || final_receipt.operation_id != handoff_with_digest.operation_id
                || final_receipt.store_fence != handoff_with_digest.store_fence
            {
                return Err(HostError::ProcessContour(
                    "Store rebind receipt exact fields mismatch".to_owned(),
                ));
            }
            final_receipt
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let expected_requirement_digest = format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&handoff.requirement)
                        .map_err(|error| HostError::Platform(error.to_string()))?
                )
            );
            if final_receipt.requirement_digest != expected_requirement_digest {
                return Err(HostError::ProcessContour(
                    "Store rebind receipt requirement digest mismatch".to_owned(),
                ));
            }
            let committed_record = StoreRebindRecord {
                fence: record_fence(host, activation_id, activation_generation),
                operation: operation(&format!(
                    "store-rebind:{}:committed",
                    handoff_with_digest.operation_id.as_str()
                ))?,
                state: StoreRebindState::Committed,
                operation_id: handoff_with_digest.operation_id.clone(),
                request_digest: PlatformHandle::new(canonical.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                requirement: PlatformHandle::new(format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&handoff.requirement)
                            .map_err(|error| HostError::Platform(error.to_string()))?
                    )
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
                candidate_binding_digest: PlatformHandle::new(
                    handoff_with_digest.candidate_binding_digest.clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                store_fence: PlatformHandle::new(handoff_with_digest.store_fence.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                process_id: handoff_with_digest.process_binding.process.process_id,
                process_start_time_100ns: handoff_with_digest
                    .process_binding
                    .process
                    .start_time_100ns,
                process_image_path: PlatformHandle::new(
                    handoff_with_digest
                        .process_binding
                        .process
                        .image_path
                        .clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                job_name: handoff_with_digest.process_binding.job.clone(),
                generation: handoff_with_digest.generation.value(),
                authority_epoch: handoff_with_digest.authority_epoch.value(),
                receipt_request_digest: Some(
                    PlatformHandle::new(final_receipt.request_digest.clone())
                        .map_err(|error| HostError::Platform(error.to_string()))?,
                ),
                receipt_store_fence: Some(
                    PlatformHandle::new(final_receipt.store_fence.clone())
                        .map_err(|error| HostError::Platform(error.to_string()))?,
                ),
            };
            append_reconciled(journal, HostStateRecord::StoreRebind(committed_record))?;
            Ok(final_receipt)
        });
        if let Err(error) = &result {
            let disposition = if error
                .to_string()
                .contains("Store rebind reconciliation confirmed operation is not committed")
            {
                StoreRebindState::Aborted
            } else {
                StoreRebindState::Unknown
            };
            let disposition_operation_id = disposition_operation_id.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store rebind failed before an exact operation identity was retained"
                        .to_owned(),
                )
            })?;
            let disposition_request_digest =
                disposition_request_digest.as_deref().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store rebind failed before an exact request digest was retained"
                            .to_owned(),
                    )
                })?;
            if let Err(disposition_error) = persist_store_rebind_disposition(
                journal,
                disposition_operation_id,
                disposition_request_digest,
                disposition,
            ) {
                return Err(HostError::RecoveryRequired(format!(
                    "Store rebind failed ({error}); durable disposition failed: {disposition_error}"
                )));
            }
        }
        result
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated repeat keeps retained contour, peer, request, response, and Store proof checks in one fail-closed boundary"
    )]
    fn probe_kernel_readiness(
        &self,
        approved_generation: &PlatformHandle,
        approved_kernel_artifact: &PlatformHandle,
        approved_store_artifact: &PlatformHandle,
        approved_config: &PlatformHandle,
    ) -> Result<AuthenticatedKernelReadiness, HostError> {
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let candidate = self.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        let activation = self.kernel_activation_receipt.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel activation receipt is missing".to_owned())
        })?;
        let requirement = self.store_bootstrap_requirement.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Store bootstrap requirement is missing".to_owned())
        })?;
        let semantic_config_hash = self.store_config_semantic_hash.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Store semantic config hash is missing".to_owned())
        })?;
        if self.approved_generation.as_ref() != Some(approved_generation)
            || self.kernel_artifact_digest.as_ref() != Some(approved_kernel_artifact)
            || self.store_artifact_digest.as_ref() != Some(approved_store_artifact)
            || self.config_digest.as_ref() != Some(approved_config)
            || candidate.artifact_hash != *approved_kernel_artifact
            || candidate.config_hash != *approved_config
            || activation.candidate_binding_digest
                != candidate
                    .compute_digest()
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?
            || activation.generation != launch.authority_generation
            || activation.authority_epoch != candidate.kernel_epoch
        {
            return Err(HostError::ProcessContour(
                "retained Kernel control contour is not the approved active generation".to_owned(),
            ));
        }
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel process is missing".to_owned()))?;
        let process = kernel.evidence().process();
        if !kernel
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == process)
        {
            return Err(HostError::ProcessContour(
                "Job observation does not contain the exact active Kernel process".to_owned(),
            ));
        }
        match kernel
            .observe()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
        {
            eliot_platform_windows::RunningJobObservation::Running { active_processes }
                if active_processes > 0 => {}
            _ => {
                return Err(HostError::ProcessContour(
                    "active Kernel Job is not live for ProbeReady".to_owned(),
                ));
            }
        }
        let expected_kernel_image = self
            .kernel_executable
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is missing".to_owned()))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        runtime.block_on(async {
            let mut transport = connect_authenticated_kernel_front_door(candidate, process).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                process.process_id,
                process.start_time_100ns,
                expected_kernel_image,
            )?;
            let peer_digest = sha256_json(&(
                process.process_id,
                process.start_time_100ns,
                expected_kernel_image,
                approved_kernel_artifact,
            ))?;
            let peer_evidence = PlatformHandle::new(format!("kernel-peer:{peer_digest}"))
                .map_err(|error| HostError::Platform(error.to_string()))?;
            let request = KernelControlRequest {
                wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                message_id: fresh_identity("kernel-probe")?,
                sequence: 1,
                peer_process_id: std::process::id(),
                generation: launch.authority_generation,
                candidate: candidate.clone(),
                command: KernelControlCommand::ProbeReady,
                payload_digest: String::new(),
            }
            .with_computed_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let frame = control_request_frame(
                format!(
                    "host-probe:{}:{}",
                    approved_generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            match transport
                .send_frame(&frame, TransportLimits::default())
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
            {
                DeliveryOutcome::Delivered => {}
                DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel repeat ProbeReady delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let frame = transport
                .receive_frame(TransportLimits::default())
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let response = decode_control_response_frame(&frame)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let ready = validate_probe_response(&request, activation, &response)?;
            let supervision_lease = response.supervision_lease.clone().ok_or_else(|| {
                HostError::ProcessContour(
                    "Kernel did not return the exact current supervision ORS snapshot".to_owned(),
                )
            })?;
            let store_fence = validated_store_proof_fence(
                requirement,
                &ready,
                approved_store_artifact,
                semantic_config_hash,
                request.generation,
            )?;
            Ok(AuthenticatedKernelReadiness {
                request,
                response,
                ready,
                supervision_lease,
                store_fence,
                peer_evidence,
            })
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the ordered suspended-launch inputs are separate authority bindings and must remain explicit"
    )]
    fn launch(
        executable: &Path,
        executable_lease: &LaunchLease,
        identity: &JobObjectIdentity,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        config_lease: &LaunchLease,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        _config_pin: &PinnedRuntimeFile,
        host: &HostInstallationEpoch,
        arguments: &[eliot_platform::PlatformHandle],
        working_directory: &Path,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
        receipt_binding: Option<(&Path, &Path, &PlatformHandle)>,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        if executable_lease.path() != executable || config_lease.path() != config_path {
            return Err(HostError::ProcessContour(
                "launch locator is not bound to its retained protected file".to_owned(),
            ));
        }
        let approved_executable = std::fs::canonicalize(executable)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let approved_executable_canonical =
            std::fs::canonicalize(Path::new(approved_executable_path.as_str()))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if approved_executable != executable || approved_executable_canonical != approved_executable
        {
            return Err(HostError::ProcessContour(
                "executable locator is not the approved path".to_owned(),
            ));
        }
        let approved_config = std::fs::canonicalize(config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let approved_config_canonical =
            std::fs::canonicalize(Path::new(approved_config_path.as_str()))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if approved_config != config_path || approved_config_canonical != approved_config {
            return Err(HostError::ProcessContour(
                "config locator is not the approved path".to_owned(),
            ));
        }
        executable_lease
            .verify()
            .map_err(HostError::ProcessContour)?;
        config_lease.verify().map_err(HostError::ProcessContour)?;
        match executable_lease {
            LaunchLease::Protected(lease) => {
                verify_file_digest_with_lease(lease, artifact, "runtime.artifact")
            }
            LaunchLease::Portable(lease) => {
                verify_file_digest_with_user_lease(lease, artifact, "runtime.artifact")
            }
        }
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        match config_lease {
            LaunchLease::Protected(lease) => {
                verify_file_digest_with_lease(lease, config_digest, "runtime.config")
            }
            LaunchLease::Portable(lease) => {
                verify_file_digest_with_user_lease(lease, config_digest, "runtime.config")
            }
        }
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let spec = SuspendedLaunchSpec::new(
            executable.to_path_buf(),
            arguments
                .iter()
                .map(|argument| OsString::from(argument.as_str()))
                .collect(),
            working_directory,
            Self::environment(
                host,
                generation,
                config_digest,
                artifact,
                config_path,
                identity,
                kernel_launch_binding,
                receipt_binding,
            ),
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let child = SuspendedJobChild::spawn_named(spec, identity.clone())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let expected = executable;
        let validated = child
            .validate(|evidence| {
                let observed = std::fs::canonicalize(&evidence.process().image_path)
                    .map_err(|error| error.to_string())?;
                if observed != expected {
                    return Err("approved image identity changed before resume".to_owned());
                }
                let observed_executable =
                    std::fs::canonicalize(&observed).map_err(|error| error.to_string())?;
                let approved_executable_canonical =
                    std::fs::canonicalize(Path::new(approved_executable_path.as_str()))
                        .map_err(|error| error.to_string())?;
                if observed_executable != expected
                    || approved_executable_canonical != observed_executable
                {
                    return Err("approved image path changed before resume".to_owned());
                }
                executable_lease.verify()?;
                match executable_lease {
                    LaunchLease::Protected(lease) => {
                        verify_file_digest_with_lease(lease, artifact, "runtime.artifact")
                    }
                    LaunchLease::Portable(lease) => {
                        verify_file_digest_with_user_lease(lease, artifact, "runtime.artifact")
                    }
                }
                .map_err(|error| error.to_string())?;
                let observed_config =
                    std::fs::canonicalize(config_path).map_err(|error| error.to_string())?;
                let approved_config_canonical =
                    std::fs::canonicalize(Path::new(approved_config_path.as_str()))
                        .map_err(|error| error.to_string())?;
                if observed_config != config_path || approved_config_canonical != observed_config {
                    return Err("approved config path changed before resume".to_owned());
                }
                config_lease.verify()?;
                match config_lease {
                    LaunchLease::Protected(lease) => {
                        verify_file_digest_with_lease(lease, config_digest, "runtime.config")
                    }
                    LaunchLease::Portable(lease) => {
                        verify_file_digest_with_user_lease(lease, config_digest, "runtime.config")
                    }
                }
                .map_err(|error| error.to_string())?;
                Ok(generation.clone())
            })
            .map_err(|error| HostError::ProcessContour(format!("validation failed: {error:?}")))?;
        validated
            .resume()
            .map_err(|error| HostError::ProcessContour(error.to_string()))
    }

    /// Resolves the approved Kernel and Store working directories.
    fn approved_working_directories(
        launch: &RuntimeLaunchDescriptor,
        portable_root: Option<&UserOwnedRootLease>,
        config_path: &Path,
    ) -> Result<(PathBuf, PathBuf), HostError> {
        if launch.profile != InstallationProfile::PortableDev {
            return Ok((
                PathBuf::from(launch.runtime_state_roots.kernel_work_root.as_str()),
                PathBuf::from(launch.runtime_state_roots.store_work_root.as_str()),
            ));
        }
        let root = portable_root
            .ok_or_else(|| HostError::ProcessContour("portable root lease is missing".to_owned()))?
            .path();
        let root = std::fs::canonicalize(root)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_path = std::fs::canonicalize(config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if !config_path.starts_with(&root) {
            return Err(HostError::ProcessContour(
                "portable launch config is outside the retained root".to_owned(),
            ));
        }
        let canonicalize = |path: &PlatformHandle, field: &str| {
            let working_directory = std::fs::canonicalize(Path::new(path.as_str()))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            if !working_directory.starts_with(&root) {
                return Err(HostError::ProcessContour(format!(
                    "portable {field} is outside the retained root"
                )));
            }
            Ok(working_directory)
        };
        Ok((
            canonicalize(
                &launch.runtime_state_roots.kernel_work_root,
                "Kernel working directory",
            )?,
            canonicalize(
                &launch.runtime_state_roots.store_work_root,
                "Store working directory",
            )?,
        ))
    }

    /// Starts the approved Kernel and Store images in separate Job Objects.
    /// Both images are pinned and validated while suspended, then resumed only
    /// after the generation identity has been accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if an approved path, retained file identity, digest,
    /// suspended launch, or rollback cleanup cannot be validated or completed.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "each argument is an independently validated process-contour authority binding"
    )]
    pub fn start_approved(
        &mut self,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        approved_kernel_path: &PlatformHandle,
        approved_store_bridge_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
        launch: &RuntimeLaunchDescriptor,
    ) -> Result<(), HostError> {
        if self.kernel.is_some() || self.store.is_some() {
            return Err(HostError::ProcessContour(
                "approved contour is already running".to_owned(),
            ));
        }
        launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        launch
            .validate_for_config(
                &PlatformHandle::new(config_path.to_string_lossy().into_owned())
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let portable_root = if launch.profile == InstallationProfile::PortableDev {
            let root = PathBuf::from(
                launch
                    .portable_root
                    .as_ref()
                    .ok_or_else(|| {
                        HostError::ProcessContour("portable root is missing".to_owned())
                    })?
                    .as_str(),
            );
            Some(
                UserOwnedRootLease::open_existing(&root)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            )
        } else {
            None
        };
        let kernel_executable =
            approved_locator(kernel_executable, approved_kernel_path, launch.profile)?;
        let kernel_lease =
            open_launch_lease(launch.profile, portable_root.as_ref(), &kernel_executable)?;
        verify_launch_digest(&kernel_lease, kernel_artifact, "runtime.kernel_artifact")?;
        let store_bridge_executable = approved_locator(
            store_bridge_executable,
            approved_store_bridge_path,
            launch.profile,
        )?;
        let store_lease = open_launch_lease(
            launch.profile,
            portable_root.as_ref(),
            &store_bridge_executable,
        )?;
        verify_launch_digest(&store_lease, store_artifact, "runtime.store_artifact")?;
        let config_path = approved_locator(config_path, approved_config_path, launch.profile)?;
        let config_pin = PinnedRuntimeFile::open(&config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_lease = open_launch_lease(launch.profile, portable_root.as_ref(), &config_path)?;
        verify_launch_digest(&config_lease, config_digest, "runtime.config")?;
        let semantic_config_hash = semantic_store_config_hash_from_json(
            &config_lease.read_bounded(1024 * 1024).map_err(|error| {
                HostError::ProcessContour(format!("read Store config for semantic digest: {error}"))
            })?,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_bootstrap_path = approved_locator(
            Path::new(launch.store_bootstrap_descriptor_path.as_str()),
            &launch.store_bootstrap_descriptor_path,
            launch.profile,
        )?;
        let store_bootstrap_lease = open_launch_lease(
            launch.profile,
            portable_root.as_ref(),
            &store_bootstrap_path,
        )?;
        let store_bootstrap_requirement = validate_store_bootstrap_descriptor(
            &store_bootstrap_lease,
            &launch.store_bootstrap_descriptor_digest,
            store_artifact,
            &semantic_config_hash,
            host.host_process_nonce().as_handle(),
        )?;
        let eliotd_config_path = approved_locator(
            Path::new(launch.eliotd_config_path.as_str()),
            &launch.eliotd_config_path,
            launch.profile,
        )?;
        let eliotd_config_lease =
            open_launch_lease(launch.profile, portable_root.as_ref(), &eliotd_config_path)?;
        verify_launch_digest(
            &eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_path = approved_locator(
            Path::new(launch.eliotd_descriptor_path.as_str()),
            &launch.eliotd_descriptor_path,
            launch.profile,
        )?;
        let eliotd_descriptor_lease = open_launch_lease(
            launch.profile,
            portable_root.as_ref(),
            &eliotd_descriptor_path,
        )?;
        verify_launch_digest(
            &eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            "runtime.eliotd_descriptor",
        )?;
        validate_eliotd_launch_descriptor(
            &eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let store_config_path = approved_locator(
            Path::new(launch.store_config_path.as_str()),
            approved_config_path,
            launch.profile,
        )?;
        if store_config_path != config_path {
            return Err(HostError::ProcessContour(
                "Store config is not the approved generation config".to_owned(),
            ));
        }
        let (kernel_working_directory, store_working_directory) =
            Self::approved_working_directories(launch, portable_root.as_ref(), &config_path)?;
        let launch_result = launch_store_then_kernel(
            || {
                Self::launch(
                    &store_bridge_executable,
                    &store_lease,
                    &self.store_identity,
                    generation,
                    config_digest,
                    store_artifact,
                    &config_path,
                    &config_lease,
                    approved_store_bridge_path,
                    approved_config_path,
                    &config_pin,
                    host,
                    &launch.store_bridge_arguments,
                    &store_working_directory,
                    None,
                    None,
                )
            },
            |store| -> Result<(), StoreLivenessEvidence> {
                let process = store.evidence().process();
                let member = store
                    .job_processes()
                    .map(|members| members.iter().any(|observed| observed == process));
                if !matches!(member, Ok(true)) {
                    return Err(StoreLivenessEvidence::Unknown(
                        "Store process is not an exact member of its approved Job".to_owned(),
                    ));
                }
                match store.observe() {
                    Ok(eliot_platform_windows::RunningJobObservation::Running {
                        active_processes,
                    }) if active_processes > 0 => Ok(()),
                    Ok(eliot_platform_windows::RunningJobObservation::Running { .. }) => {
                        Err(StoreLivenessEvidence::Unknown(
                            "Store reports zero active processes".to_owned(),
                        ))
                    }
                    Ok(
                        eliot_platform_windows::RunningJobObservation::RootExited { .. }
                        | eliot_platform_windows::RunningJobObservation::Exited { .. },
                    ) => Err(StoreLivenessEvidence::Dead),
                    Err(error) => Err(StoreLivenessEvidence::Unknown(error.to_string())),
                }
            },
            || {
                Self::launch(
                    &kernel_executable,
                    &kernel_lease,
                    &self.kernel_identity,
                    generation,
                    config_digest,
                    kernel_artifact,
                    &config_path,
                    &config_lease,
                    approved_kernel_path,
                    approved_config_path,
                    &config_pin,
                    host,
                    &launch.kernel_arguments,
                    &kernel_working_directory,
                    self.kernel_launch_binding.as_ref(),
                    Some((
                        Path::new(launch.runtime_state_roots.host_state_root.as_str()),
                        Path::new(launch.runtime_state_roots.kernel_ors_root.as_str()),
                        &launch.runtime_state_roots.roots_digest,
                    )),
                )
            },
            |mut store| {
                store
                    .terminate_in_place(0xE017_0002)
                    .map(|_| ())
                    .map_err(|error| Box::new((store, error.to_string())))
            },
        );
        match launch_result {
            Ok((store, kernel)) => {
                self.kernel_executable = Some(kernel_executable);
                self.store_bridge_executable = Some(store_bridge_executable);
                self.kernel_lease = Some(kernel_lease);
                self.store_lease = Some(store_lease);
                self.config_path = Some(config_path);
                self.config_lease = Some(config_lease);
                self.store_bootstrap_lease = Some(store_bootstrap_lease);
                self.eliotd_config_lease = Some(eliotd_config_lease);
                self.eliotd_descriptor_lease = Some(eliotd_descriptor_lease);
                self.store_bootstrap_requirement = Some(store_bootstrap_requirement);
                self.config_pin = Some(config_pin);
                self.portable_root = portable_root;
                self.launch = Some(launch.clone());
                self.kernel_artifact_digest = Some(kernel_artifact.clone());
                self.store_artifact_digest = Some(store_artifact.clone());
                self.config_digest = Some(config_digest.clone());
                self.store_config_semantic_hash = Some(semantic_config_hash);
                self.approved_generation = Some(generation.clone());
                self.kernel_candidate = None;
                self.kernel_activation_receipt = None;
                self.kernel_restart_attempts = 0;
                self.store_restart_attempts = 0;
                self.kernel = Some(kernel);
                self.store = Some(store);
                let kernel_live = match Self::branch_state(self.kernel.as_ref()) {
                    Ok(BranchLiveness::Live) => Ok(()),
                    Ok(BranchLiveness::Dead) => {
                        Err("Kernel exited immediately after launch".to_owned())
                    }
                    Err(error) => Err(error),
                };
                match kernel_live {
                    Ok(()) => Ok(()),
                    Err(reason) => {
                        let store_cleanup = self.terminate_store();
                        let kernel_cleanup = self.terminate_kernel();
                        if store_cleanup.is_ok() && kernel_cleanup.is_ok() {
                            self.clear_recorded_contour();
                        }
                        Err(if store_cleanup.is_err() || kernel_cleanup.is_err() {
                            HostError::RecoveryRequired(format!(
                                "Kernel launch observation failed ({reason}); Store cleanup={store_cleanup:?}; Kernel cleanup={kernel_cleanup:?}"
                            ))
                        } else {
                            HostError::ProcessContour(format!(
                                "Kernel child is not live after launch ({reason})"
                            ))
                        })
                    }
                }
            }
            Err(
                StoreKernelLaunchError::Launch(error) | StoreKernelLaunchError::Kernel { error },
            ) => {
                self.clear_recorded_contour();
                Err(error)
            }
            Err(StoreKernelLaunchError::StoreNotLive { evidence }) => {
                self.clear_recorded_contour();
                Err(HostError::StoreNotLive { evidence })
            }
            Err(StoreKernelLaunchError::CleanupRequired { store, reason }) => {
                self.kernel_executable = Some(kernel_executable);
                self.store_bridge_executable = Some(store_bridge_executable);
                self.kernel_lease = Some(kernel_lease);
                self.store_lease = Some(store_lease);
                self.config_path = Some(config_path);
                self.config_lease = Some(config_lease);
                self.store_bootstrap_lease = Some(store_bootstrap_lease);
                self.eliotd_config_lease = Some(eliotd_config_lease);
                self.eliotd_descriptor_lease = Some(eliotd_descriptor_lease);
                self.store_bootstrap_requirement = Some(store_bootstrap_requirement);
                self.config_pin = Some(config_pin);
                self.portable_root = portable_root;
                self.launch = Some(launch.clone());
                self.kernel_artifact_digest = Some(kernel_artifact.clone());
                self.store_artifact_digest = Some(store_artifact.clone());
                self.config_digest = Some(config_digest.clone());
                self.approved_generation = Some(generation.clone());
                self.kernel_candidate = None;
                self.kernel_activation_receipt = None;
                self.kernel_restart_attempts = 0;
                self.store_restart_attempts = 0;
                self.store = Some(store);
                Err(HostError::RecoveryRequired(reason))
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "relaunch keeps every approved authority binding explicit at the process boundary"
    )]
    fn relaunch_kernel(
        &self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        artifact: &PlatformHandle,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        let executable = self
            .kernel_executable
            .clone()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is not recorded".to_owned()))?;
        let executable_lease = self
            .kernel_lease
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image lease is missing".to_owned()))?;
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        let config_pin = self.config_pin.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config pin is missing".to_owned())
        })?;
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let config_handle = PlatformHandle::new(config_path.to_string_lossy().into_owned())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        launch
            .validate_for_config(&config_handle)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let eliotd_config_lease = self.eliotd_config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd Governor config lease is missing".to_owned())
        })?;
        if eliotd_config_lease.path() != Path::new(launch.eliotd_config_path.as_str()) {
            return Err(HostError::ProcessContour(
                "eliotd Governor config lease is not bound to the approved path".to_owned(),
            ));
        }
        verify_launch_digest(
            eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_lease = self.eliotd_descriptor_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd launch descriptor lease is missing".to_owned())
        })?;
        validate_eliotd_launch_descriptor(
            eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let (kernel_working_directory, _) =
            Self::approved_working_directories(launch, self.portable_root.as_ref(), config_path)?;
        let child = Self::launch(
            &executable,
            executable_lease,
            &self.kernel_identity,
            generation,
            config_digest,
            artifact,
            config_path,
            config_lease,
            approved_executable_path,
            approved_config_path,
            config_pin,
            host,
            &launch.kernel_arguments,
            &kernel_working_directory,
            self.kernel_launch_binding.as_ref(),
            Some((
                Path::new(launch.runtime_state_roots.host_state_root.as_str()),
                Path::new(launch.runtime_state_roots.kernel_ors_root.as_str()),
                &launch.runtime_state_roots.roots_digest,
            )),
        )?;
        Ok(child)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "relaunch keeps every approved authority binding explicit at the process boundary"
    )]
    fn relaunch_store(
        &self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        artifact: &PlatformHandle,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        let executable = self
            .store_bridge_executable
            .clone()
            .ok_or_else(|| HostError::ProcessContour("store image is not recorded".to_owned()))?;
        let executable_lease = self
            .store_lease
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("store image lease is missing".to_owned()))?;
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        let config_pin = self.config_pin.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config pin is missing".to_owned())
        })?;
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let config_handle = PlatformHandle::new(config_path.to_string_lossy().into_owned())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        launch
            .validate_for_config(&config_handle)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_bootstrap_lease = self.store_bootstrap_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store bootstrap descriptor lease is missing".to_owned())
        })?;
        if store_bootstrap_lease.path()
            != Path::new(launch.store_bootstrap_descriptor_path.as_str())
        {
            return Err(HostError::ProcessContour(
                "Store bootstrap descriptor lease is not bound to the approved path".to_owned(),
            ));
        }
        let semantic_config_hash = self.store_config_semantic_hash.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store semantic config hash is missing".to_owned())
        })?;
        let expected_bootstrap = validate_store_bootstrap_descriptor(
            store_bootstrap_lease,
            &launch.store_bootstrap_descriptor_digest,
            artifact,
            semantic_config_hash,
            host.host_process_nonce().as_handle(),
        )?;
        if self.store_bootstrap_requirement.as_ref() != Some(&expected_bootstrap) {
            return Err(HostError::ProcessContour(
                "retained Store bootstrap requirement changed before relaunch".to_owned(),
            ));
        }
        let eliotd_config_lease = self.eliotd_config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd Governor config lease is missing".to_owned())
        })?;
        if eliotd_config_lease.path() != Path::new(launch.eliotd_config_path.as_str()) {
            return Err(HostError::ProcessContour(
                "eliotd Governor config lease is not bound to the approved path".to_owned(),
            ));
        }
        verify_launch_digest(
            eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_lease = self.eliotd_descriptor_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd launch descriptor lease is missing".to_owned())
        })?;
        validate_eliotd_launch_descriptor(
            eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let (_, store_working_directory) =
            Self::approved_working_directories(launch, self.portable_root.as_ref(), config_path)?;
        let child = Self::launch(
            &executable,
            executable_lease,
            &self.store_identity,
            generation,
            config_digest,
            artifact,
            config_path,
            config_lease,
            approved_executable_path,
            approved_config_path,
            config_pin,
            host,
            &launch.store_bridge_arguments,
            &store_working_directory,
            None,
            None,
        )?;
        Ok(child)
    }

    fn branch_state(
        child: Option<&RunningJobChild<PlatformHandle>>,
    ) -> Result<BranchLiveness, String> {
        match child {
            Some(child) => {
                let process = child.evidence().process();
                if !child
                    .job_processes()
                    .map_err(|error| error.to_string())?
                    .iter()
                    .any(|observed| observed == process)
                {
                    return Err(
                        "Job observation does not contain the exact launched process".to_owned(),
                    );
                }
                match child.observe().map_err(|error| error.to_string())? {
                    eliot_platform_windows::RunningJobObservation::Running { active_processes }
                        if active_processes > 0 =>
                    {
                        Ok(BranchLiveness::Live)
                    }
                    eliot_platform_windows::RunningJobObservation::Running { .. } => {
                        Err("running observation reports zero active processes".to_owned())
                    }
                    eliot_platform_windows::RunningJobObservation::RootExited { .. }
                    | eliot_platform_windows::RunningJobObservation::Exited { .. } => {
                        Ok(BranchLiveness::Dead)
                    }
                }
            }
            None => Ok(BranchLiveness::Dead),
        }
    }

    fn liveness_only(&self) -> HostBranchDisposition {
        let kernel_live = matches!(
            Self::branch_state(self.kernel.as_ref()),
            Ok(BranchLiveness::Live)
        );
        let store_live = matches!(
            Self::branch_state(self.store.as_ref()),
            Ok(BranchLiveness::Live)
        );
        match (kernel_live, store_live) {
            (true, true) => HostBranchDisposition::LiveAwaitingReadiness,
            (false, true) => HostBranchDisposition::KernelDegraded,
            (true, false) => HostBranchDisposition::StoreDegraded,
            (false, false) => HostBranchDisposition::BothDegraded,
        }
    }

    fn validate_running_kernel_candidate(
        &self,
        candidate: &HostKernelCandidateBinding,
    ) -> Result<(), HostError> {
        let running_kernel = self.kernel.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel process is missing".to_owned())
        })?;
        let running_process = running_kernel.evidence().process();
        let candidate_job = &candidate.job_binding;
        if candidate_job.job.name != self.kernel_identity.name()
            || running_process.process_id != candidate_job.root.process.process_id
            || running_process.start_time_100ns != candidate_job.root.process.start_time_100ns
            || running_process.image_path != candidate_job.root.process.image_path
        {
            return Err(HostError::ProcessContour(
                "live Kernel Job/process is not the retained candidate binding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reconciles the retained Kernel branch and an already-live Store with one
    /// bounded restart attempt for Kernel failure. A failed branch never
    /// terminates a healthy sibling or reuses an observed PID. A dead Store is
    /// rejected here because only [`HostComposition`] owns the durable outer
    /// recovery intent required before Store termination.
    ///
    /// # Errors
    ///
    /// Returns an error if retained process/configuration identity changes or
    /// a protected file, digest, or approved path cannot be revalidated.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "ordered branch reconciliation keeps all authority bindings visible and fail-closed"
    )]
    pub fn reconcile(
        &mut self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        approved_kernel_path: &PlatformHandle,
        approved_store_bridge_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<HostBranchDisposition, HostError> {
        // This low-level branch helper has no journal/outer-intent authority.
        // A dead Store must therefore be recovered by HostComposition's one
        // durable Store-recovery operation, never by the generic relaunch
        // closures below.  Keep the guard here as a fail-closed backstop for
        // future callers that might otherwise reintroduce the old bypass.
        if matches!(
            Self::branch_state(self.store.as_ref()),
            Ok(BranchLiveness::Dead)
        ) {
            return Err(StoreRecoveryRequired::LateDead.into());
        }
        if self
            .kernel_artifact_digest
            .as_ref()
            .is_some_and(|digest| digest != kernel_artifact)
            || self
                .store_artifact_digest
                .as_ref()
                .is_some_and(|digest| digest != store_artifact)
            || self
                .config_digest
                .as_ref()
                .is_some_and(|digest| digest != config_digest)
        {
            return Err(HostError::ProcessContour(
                "approved generation material changed; bounded cutover is required".to_owned(),
            ));
        }
        let profile = self
            .launch
            .as_ref()
            .map_or(InstallationProfile::SystemService, |launch| launch.profile);
        if let Some(root) = self.portable_root.as_ref() {
            root.verify_stable_identity()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let approved_root = self
                .launch
                .as_ref()
                .and_then(|launch| launch.portable_root.as_ref())
                .ok_or_else(|| {
                    HostError::ProcessContour("portable root binding is missing".to_owned())
                })?;
            if root.path() != Path::new(approved_root.as_str()) {
                return Err(HostError::ProcessContour(
                    "portable root lease path changed outside the approved contour".to_owned(),
                ));
            }
        }
        let canonical_config = approved_locator(config_path, approved_config_path, profile)?;
        if self.config_path.as_ref() != Some(&canonical_config) {
            return Err(HostError::ProcessContour(
                "generation config path changed outside the approved contour".to_owned(),
            ));
        }
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        if config_lease.path() != canonical_config {
            return Err(HostError::ProcessContour(
                "generation config lease is not the approved path".to_owned(),
            ));
        }
        config_lease.verify().map_err(HostError::ProcessContour)?;
        verify_launch_digest(config_lease, config_digest, "runtime.config")?;
        if let Some(kernel) = &self.kernel_executable {
            let approved = approved_locator(kernel, approved_kernel_path, profile)?;
            let lease = self.kernel_lease.as_ref().ok_or_else(|| {
                HostError::ProcessContour("Kernel image lease is missing".to_owned())
            })?;
            if approved != *kernel || lease.path() != kernel {
                return Err(HostError::ProcessContour(
                    "Kernel image lease is not the approved path".to_owned(),
                ));
            }
            lease.verify().map_err(HostError::ProcessContour)?;
            verify_launch_digest(lease, kernel_artifact, "runtime.kernel_artifact")?;
        }
        if let Some(store) = &self.store_bridge_executable {
            let approved = approved_locator(store, approved_store_bridge_path, profile)?;
            let lease = self.store_lease.as_ref().ok_or_else(|| {
                HostError::ProcessContour("store image lease is missing".to_owned())
            })?;
            if approved != *store || lease.path() != store {
                return Err(HostError::ProcessContour(
                    "store image lease is not the approved path".to_owned(),
                ));
            }
            lease.verify().map_err(HostError::ProcessContour)?;
            verify_launch_digest(lease, store_artifact, "runtime.store_artifact")?;
        }
        let mut state = ReconciliationState {
            store: self.store.take(),
            kernel: self.kernel.take(),
            store_restart_attempts: self.store_restart_attempts,
            kernel_restart_attempts: self.kernel_restart_attempts,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            |store| match Self::branch_state(store) {
                Ok(BranchLiveness::Live) => ReconciliationObservation::Live,
                Ok(BranchLiveness::Dead) => ReconciliationObservation::Dead,
                Err(_) => ReconciliationObservation::Unknown,
            },
            |kernel| match Self::branch_state(kernel) {
                Ok(BranchLiveness::Live) => ReconciliationObservation::Live,
                Ok(BranchLiveness::Dead) => ReconciliationObservation::Dead,
                Err(_) => ReconciliationObservation::Unknown,
            },
            |kernel| {
                let Some(child) = kernel.as_mut() else {
                    return Ok(());
                };
                child
                    .terminate_in_place(0xE017_0001)
                    .map(|_| {
                        kernel.take();
                    })
                    .map_err(|_| ())
            },
            || {
                self.relaunch_kernel(
                    generation,
                    config_digest,
                    config_path,
                    kernel_artifact,
                    approved_kernel_path,
                    approved_config_path,
                    host,
                )
                .map_err(|_| ())
            },
        )
        .map_err(HostError::from);
        self.store = state.store;
        self.kernel = state.kernel;
        self.store_restart_attempts = state.store_restart_attempts;
        self.kernel_restart_attempts = state.kernel_restart_attempts;
        disposition
    }

    /// Performs a bounded side-by-side cutover with an explicit rollback
    /// image.  The old branches are drained before the candidate is admitted;
    /// if candidate startup or suspended validation fails, only the supplied
    /// prior approved images may be relaunched.
    ///
    /// # Errors
    ///
    /// Returns an error when shutdown, candidate admission, or restoration of
    /// the prior approved contour fails.
    #[allow(
        clippy::too_many_arguments,
        dead_code,
        reason = "candidate and rollback authority sets stay explicit to prevent cross-generation substitution"
    )]
    fn cutover_with_rollback(
        &mut self,
        candidate_kernel: &Path,
        candidate_store: &Path,
        prior_kernel: &Path,
        prior_store: &Path,
        candidate_generation: &PlatformHandle,
        candidate_config_digest: &PlatformHandle,
        candidate_config_path: &Path,
        candidate_kernel_path: &PlatformHandle,
        candidate_store_path: &PlatformHandle,
        candidate_approved_config_path: &PlatformHandle,
        candidate_kernel_artifact: &PlatformHandle,
        candidate_store_artifact: &PlatformHandle,
        prior_generation: &PlatformHandle,
        prior_config_digest: &PlatformHandle,
        prior_config_path: &Path,
        prior_kernel_path: &PlatformHandle,
        prior_store_path: &PlatformHandle,
        prior_approved_config_path: &PlatformHandle,
        prior_kernel_artifact: &PlatformHandle,
        prior_store_artifact: &PlatformHandle,
        candidate_launch: &RuntimeLaunchDescriptor,
        prior_launch: &RuntimeLaunchDescriptor,
        host: &HostInstallationEpoch,
    ) -> Result<CutoverLaunchOutcome, HostError> {
        self.terminate_store_then_kernel()?;
        match self.start_approved(
            candidate_kernel,
            candidate_store,
            candidate_generation,
            candidate_config_digest,
            candidate_config_path,
            candidate_kernel_path,
            candidate_store_path,
            candidate_approved_config_path,
            candidate_kernel_artifact,
            candidate_store_artifact,
            host,
            candidate_launch,
        ) {
            Ok(()) => Ok(CutoverLaunchOutcome::Candidate),
            Err(candidate_error) => {
                let rollback = self
                    .start_approved(
                        prior_kernel,
                        prior_store,
                        prior_generation,
                        prior_config_digest,
                        prior_config_path,
                        prior_kernel_path,
                        prior_store_path,
                        prior_approved_config_path,
                        prior_kernel_artifact,
                        prior_store_artifact,
                        host,
                        prior_launch,
                    )
                    .map_err(|error| {
                        HostError::ProcessContour(format!(
                            "candidate failed ({candidate_error}); rollback failed ({error})"
                        ))
                    });
                rollback.map(|()| CutoverLaunchOutcome::Rollback {
                    candidate_error: candidate_error.to_string(),
                })
            }
        }
    }

    /// Terminates the Kernel branch during bounded rollback or shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned Kernel Job branch cannot be terminated.
    pub fn terminate_kernel(&mut self) -> Result<(), HostError> {
        if let Some(kernel) = self.kernel.as_mut() {
            kernel
                .terminate_in_place(0xE017_0001)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            self.kernel.take();
        }
        self.kernel_candidate = None;
        self.kernel_activation_receipt = None;
        Ok(())
    }

    /// Terminates the store branch during bounded rollback or shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned store Job branch cannot be terminated.
    pub fn terminate_store(&mut self) -> Result<(), HostError> {
        if let Some(store) = self.store.as_mut() {
            store
                .terminate_in_place(0xE017_0002)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            self.store.take();
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn terminate_store_then_kernel(&mut self) -> Result<(), HostError> {
        let store = self.terminate_store();
        let kernel = self.terminate_kernel();
        match (store, kernel) {
            (Ok(()), Ok(())) => Ok(()),
            (store, kernel) => Err(HostError::RecoveryRequired(format!(
                "Store-first termination was incomplete: store={store:?}; kernel={kernel:?}"
            ))),
        }
    }

    fn clear_recorded_contour(&mut self) {
        self.kernel_executable = None;
        self.store_bridge_executable = None;
        self.kernel_lease = None;
        self.store_lease = None;
        self.config_path = None;
        self.config_lease = None;
        self.store_bootstrap_lease = None;
        self.eliotd_config_lease = None;
        self.eliotd_descriptor_lease = None;
        self.store_bootstrap_requirement = None;
        self.config_pin = None;
        self.kernel_artifact_digest = None;
        self.store_artifact_digest = None;
        self.config_digest = None;
        self.agent_bridge_admission = None;
        self.store_config_semantic_hash = None;
        self.approved_generation = None;
        self.kernel_candidate = None;
        self.kernel_activation_receipt = None;
        self.portable_root = None;
        self.launch = None;
        self.kernel_restart_attempts = 0;
        self.store_restart_attempts = 0;
    }

    /// Returns the durable mechanics identity of the Kernel branch.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        self.kernel_identity.name()
    }

    /// Returns the durable mechanics identity of the store branch.
    #[must_use]
    pub fn store_name(&self) -> &str {
        self.store_identity.name()
    }

    #[must_use]
    pub fn kernel_process(&self) -> Option<&ProcessIdentity> {
        self.kernel.as_ref().map(|child| child.evidence().process())
    }

    #[must_use]
    pub fn store_process(&self) -> Option<&ProcessIdentity> {
        self.store.as_ref().map(|child| child.evidence().process())
    }

    #[must_use]
    pub fn has_recorded_contour(&self) -> bool {
        self.kernel.is_some()
            || self.store.is_some()
            || self.kernel_executable.is_some()
            || self.store_bridge_executable.is_some()
    }
}

fn fresh_identity(prefix: &str) -> Result<PlatformHandle, HostError> {
    PlatformHandle::new(format!("{prefix}-{}", Uuid::new_v4().simple()))
        .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
mod watchdog_service_start;
#[cfg(all(test, windows))]
use watchdog_service_start::{
    InstalledWatchdogControl, InstalledWatchdogRuntimeInspection, InstalledWatchdogStartControl,
    WATCHDOG_START_TIMEOUT_MS, WatchdogStartClock, require_running_watchdog,
    start_installed_watchdog_with_clock, watchdog_start_wait,
};
#[cfg(windows)]
use watchdog_service_start::{
    approved_service_registration_request, select_watchdog_approval_for_inspection,
    start_installed_watchdog,
};

fn sha256_json(value: &impl serde::Serialize) -> Result<String, HostError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(windows)]
mod watchdog_publication;
#[cfg(windows)]
use watchdog_publication::{
    observe_host_watchdog_publication, publish_current_watchdog_supervision_bundle,
    read_manifest_current_supervision_lease, supervision_publication_identity,
    verify_exact_current_watchdog_publication,
};

#[cfg(windows)]
fn host_owned_store_recovery_request(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    generation: &PlatformHandle,
    config_digest: &PlatformHandle,
) -> Result<HostRuntimeControlRequest, HostError> {
    let identity_digest = sha256_json(&(
        "eliot-host::scm-store-recovery:v1",
        &host.installation,
        &host.epoch,
        activation_id,
        activation_generation,
        generation,
        config_digest,
    ))?;
    let request_id =
        PlatformHandle::new(format!("host-owned-scm-store-recovery:{identity_digest}"))
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    HostRuntimeControlRequest::new(HostRuntimeControlOperation::RecoverStore, request_id)
        .map_err(HostError::ProcessContour)
}

fn phase_b_unknown_ref(
    prefix: &str,
    operation: &str,
    intent: &HostPhaseBMaterializationIntent,
) -> PlatformHandle {
    PlatformHandle::new(format!(
        "{prefix}:operation={operation}:transaction_id={}:effect_id={}:request_digest={}",
        intent.transaction_id.as_str(),
        intent.effect_id.as_str(),
        intent.request_digest.as_str()
    ))
    .unwrap_or_else(|_| unreachable!())
}

fn root_epoch(lineage: PlatformHandle) -> EpochTransition {
    EpochTransition {
        current: EpochIdentity {
            lineage,
            sequence: 1,
        },
        parent: None,
    }
}

fn fresh_host_epoch(
    installation: PlatformHandle,
    recovery: Option<RecoveryLineageEvidence>,
) -> Result<HostInstallationEpoch, HostError> {
    Ok(HostInstallationEpoch {
        installation,
        epoch: root_epoch(fresh_identity("host-lineage")?),
        nonce: fresh_identity("host-process-nonce")?,
        recovery,
    })
}

fn child_host_epoch(parent: &HostInstallationEpoch) -> Result<HostInstallationEpoch, HostError> {
    Ok(HostInstallationEpoch {
        installation: parent.installation.clone(),
        epoch: parent.epoch.direct_child()?,
        nonce: fresh_identity("host-process-nonce")?,
        recovery: None,
    })
}

fn operation(label: &str) -> Result<IdempotencyIdentity, HostError> {
    Ok(IdempotencyIdentity {
        operation_id: fresh_identity(label)?,
        idempotency_key: fresh_identity(&format!("{label}-idempotency"))?,
    })
}

fn record_fence(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> RecordFence {
    RecordFence {
        host: host.clone(),
        activation_id: activation_id.clone(),
        activation_generation: activation_generation.clone(),
    }
}

mod journal_append;
#[cfg(windows)]
use journal_append::{
    append_authenticated_kernel_readiness, append_store_rebind_terminal,
    persist_store_rebind_disposition,
};
#[cfg(test)]
use journal_append::{append_clean_marker, exact_termination_binding_matches};
use journal_append::{
    append_reconciled, clean_marker_record, initial_activation_record, pending_activation_binding,
    terminated_prior_kernel, transition_activation_record,
};

mod store_recovery_fence;
use store_recovery_fence::{
    ActivePhaseBRebindRecoveryKind, StoreRecoveryReopenFence, StoreRecoveryStartupFence,
    active_phase_b_rebind_recovery_kind,
};

mod host_epoch_reopen;
#[cfg(all(windows, test))]
use host_epoch_reopen::open_test_support_epoch;
#[cfg(windows)]
use host_epoch_reopen::{open_production_epoch, persist_pending_recovery};
#[cfg(test)]
use host_epoch_reopen::{open_production_epoch_from_backend, reopen_existing_epoch};

#[cfg(windows)]
mod runtime_restart_state;
#[cfg(windows)]
use runtime_restart_state::{
    RuntimeRestartPendingPublication, has_runtime_restart_pending, load_durable_runtime_restarts,
    persist_runtime_restart_pending, persist_runtime_restart_receipt,
    read_bounded_runtime_restart_file, rebind_runtime_restart_receipt,
};
#[cfg(all(windows, test))]
use runtime_restart_state::{
    runtime_restart_pending_path, runtime_restart_receipt_path, runtime_restart_store_dir,
};

#[cfg(windows)]
mod store_recovery_persistence;
#[cfg(all(windows, test))]
use store_recovery_persistence::store_recovery_receipt_path;
#[cfg(windows)]
use store_recovery_persistence::{
    StoreRecoveryPendingIdentity, StoreRecoveryPendingPublication,
    cleanup_completed_store_recovery_supporting_evidence,
    cleanup_store_recovery_supporting_evidence_for, committed_store_rebind_receipt,
    has_store_recovery_pending, load_durable_store_recoveries,
    persist_store_recovery_inner_binding, persist_store_recovery_pending,
    persist_store_recovery_receipt, persist_store_recovery_termination_evidence,
    read_store_recovery_pending_identity, read_store_recovery_receipt,
    rebind_store_recovery_receipt, store_recovery_inner_binding_path, store_recovery_pending_path,
    store_recovery_termination_path,
};

#[cfg(windows)]
mod store_recovery_evidence;
#[cfg(windows)]
use store_recovery_evidence::{
    StoreRecoveryInnerBinding, StoreRecoveryTerminationEvidence, read_store_recovery_inner_binding,
    read_store_recovery_termination_evidence,
};

/// Host-owned lifecycle state and installation activation registry.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the lifecycle flags are independent durable shutdown and lease-release fences"
)]
pub struct HostComposition {
    #[allow(
        dead_code,
        reason = "zero-sized marker binds the production Store-rebind seam"
    )]
    store_rebind_boundary: HostStoreRebindProductionBoundary,
    #[allow(
        dead_code,
        reason = "zero-sized marker binds the production runtime-control seam"
    )]
    runtime_control_boundary: HostRuntimeControlProductionBoundary,
    journal: ProductionHostStateJournal,
    registry_store: RedbInstallationRegistry,
    registry: ApprovedGenerationRegistry,
    launch_options: HostLaunchOptions,
    host: HostInstallationEpoch,
    activation_generation: EpochTransition,
    activation_id: PlatformHandle,
    running: bool,
    #[cfg(windows)]
    jobs: HostJobBranches,
    #[cfg(windows)]
    readiness_gate: HostReadinessGate,
    #[cfg(windows)]
    phase_b: Option<HostPhaseBMaterialization>,
    #[cfg(windows)]
    runtime_restarts: std::collections::HashMap<String, HostKernelRestartReceipt>,
    #[cfg(windows)]
    runtime_control_queue: HostRuntimeControlQueue,
    #[cfg(windows)]
    store_recovery_startup_fence: StoreRecoveryStartupFence,
    active_phase_b_rebind_recovery: ActivePhaseBRebindRecoveryKind,
    owner_lease: HostOwnerLease,
    pending_record: Option<HostStateRecord>,
    durable_finalized: bool,
    owner_released: bool,
    shutdown_failed: bool,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostStartupBranch {
    Active,
    Pending,
}

/// Exact external authority bytes supplied for Host Phase B.
///
/// The installer never constructs this value. Host accepts it only after the
/// real Host installation epoch is open and validates the descriptor's digest,
/// ORS snapshot fence, and candidate/epoch binding before publication.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPhaseBInput {
    /// Canonical serialized [`ProcessAuthorityHandoffDescriptor`] bytes.
    pub authority_descriptor_bytes: Vec<u8>,
}

/// Receipt for one complete Host Phase B materialization.
///
/// The manifest remains immutable. `file_identities` are post-publication OS
/// observations and therefore are deliberately kept out of the manifest and
/// its digest domain.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPhaseBMaterialization {
    transaction_id: Option<PlatformHandle>,
    effect_id: Option<PlatformHandle>,
    credential_receipt_digest: Option<PlatformHandle>,
    host_owner_epoch: Option<PlatformHandle>,
    host_process_identity: Option<PlatformHandle>,
    manifest_digest: PlatformHandle,
    host_epoch: EpochIdentity,
    host_process_nonce: PlatformHandle,
    activation_generation: EpochIdentity,
    authority_descriptor_digest: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    config_file_digest: PlatformHandle,
    semantic_config_hash: PlatformHandle,
    eliotd_descriptor_digest: PlatformHandle,
    /// Exact Phase-B request bound to this materialization, when it was
    /// published through the transaction-owned installer handoff.
    request_digest: Option<PlatformHandle>,
    public_receipt_digest: Option<PlatformHandle>,
    /// Exact stage/profile/declaration proof for the optional Agent Bridge.
    /// This is never synthesized from a manifest or runtime descriptor.
    agent_bridge: Option<AgentBridgePreparedBinding>,
    /// Final provider proof, populated only after `FinalizePhaseB` CAS.
    agent_bridge_final: Option<AgentBridgePhaseBBinding>,
    file_identities: [FileIdentity; 4],
    launch: RuntimeLaunchDescriptor,
}

#[cfg(windows)]
impl HostPhaseBMaterialization {
    /// Returns the immutable candidate manifest digest bound by this receipt.
    #[must_use]
    pub const fn manifest_digest(&self) -> &PlatformHandle {
        &self.manifest_digest
    }

    /// Returns the exact Host epoch observed before Phase B publication.
    #[must_use]
    pub const fn host_epoch(&self) -> &EpochIdentity {
        &self.host_epoch
    }

    /// Returns the fresh Host process nonce that owns this materialization.
    #[must_use]
    pub const fn host_process_nonce(&self) -> &PlatformHandle {
        &self.host_process_nonce
    }

    /// Returns the live launch overlay consumed by Host process admission.
    #[must_use]
    pub const fn launch(&self) -> &RuntimeLaunchDescriptor {
        &self.launch
    }

    /// Returns the physical SHA-256 of the materialized Store config bytes.
    #[must_use]
    pub const fn config_file_digest(&self) -> &PlatformHandle {
        &self.config_file_digest
    }

    /// Returns the semantic Store approved-config hash.
    #[must_use]
    pub const fn semantic_config_hash(&self) -> &PlatformHandle {
        &self.semantic_config_hash
    }

    /// Returns post-materialization identities in authority/config/bootstrap/
    /// eliotd descriptor order.
    #[must_use]
    pub const fn file_identities(&self) -> &[FileIdentity; 4] {
        &self.file_identities
    }

    /// Returns the verified Agent Bridge proof, when this is a bridge-enabled
    /// Phase-B materialization.
    #[must_use]
    pub const fn agent_bridge(&self) -> Option<&AgentBridgePreparedBinding> {
        self.agent_bridge.as_ref()
    }

    #[must_use]
    pub const fn final_agent_bridge(&self) -> Option<&AgentBridgePhaseBBinding> {
        self.agent_bridge_final.as_ref()
    }
}

#[cfg(windows)]
trait ApprovedHostStartupPort {
    fn start_approved_manifest(
        &mut self,
        manifest: &CandidateManifest,
        branch: HostStartupBranch,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        store_artifact: &PlatformHandle,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError>;
}

#[cfg(windows)]
fn start_approved_manifest_contour<P: ApprovedHostStartupPort>(
    port: &mut P,
    manifest: &CandidateManifest,
    branch: HostStartupBranch,
    pending: Option<&eliot_installation::PendingActivation>,
) -> Result<(), HostError> {
    let (approved_kernel_path, approved_store_bridge_path, _) = manifest.host_child_paths();
    let (_, store_artifact) = manifest
        .host_child_artifact_digests()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    port.start_approved_manifest(
        manifest,
        branch,
        Path::new(approved_kernel_path.as_str()),
        Path::new(approved_store_bridge_path.as_str()),
        store_artifact,
        pending,
    )
}

impl HostComposition {
    /// Opens the durable Host contour for one installation identity and
    /// advances its persisted epoch before any process admission.
    ///
    /// # Errors
    ///
    /// Returns an error if installation identity, owner-lease acquisition,
    /// durable admission, recovery state, or approved process startup fails.
    #[allow(
        clippy::too_many_lines,
        reason = "Host reopen keeps the epoch, registry, and Phase-B crash-recovery ordering in one boundary"
    )]
    pub fn open(launch_options: HostLaunchOptions) -> Result<Self, HostError> {
        if launch_options.installation().as_str().trim().is_empty() {
            return Err(HostError::MissingInstallation);
        }
        let installation = launch_options.installation().clone();
        let owner_lease = HostOwnerLease::acquire(&installation).map_err(owner_lease_error)?;
        let host_state_root = launch_options.host_state_root().to_path_buf();
        let root_lease = ProtectedRootLease::open_existing(&host_state_root)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let canonical_root = root_lease
            .canonical_path()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        if canonical_root != host_state_root {
            return Err(HostError::ProcessContour(
                "SCM Host state root is not the exact retained installation root".to_owned(),
            ));
        }
        let registry_store =
            RedbInstallationRegistry::open_existing_at(root_lease)?.ok_or_else(|| {
                HostError::ProcessContour(
                    "SCM Host state root has no approved-generation registry".to_owned(),
                )
            })?;
        let mut registry = registry_store.load()?;
        let pending_for_reopen = registry.pending_activation().cloned();
        Self::validate_launch_options_for_registry(
            &launch_options,
            &registry,
            pending_for_reopen.as_ref(),
        )?;
        #[cfg(windows)]
        {
            let startup_manifest = pending_for_reopen
                .as_ref()
                .map(|pending| &pending.manifest)
                .or_else(|| registry.active().map(|generation| &generation.manifest))
                .ok_or_else(|| {
                    HostError::ProcessContour(
                        "SCM launch authority has no approved generation".to_owned(),
                    )
                })?;
            verify_current_host_artifact(startup_manifest)?;
        }
        if let Some(pending) = pending_for_reopen.as_ref()
            && pending
                .manifest
                .runtime_launch
                .installation_epoch
                .installation
                != installation
        {
            let reason = "pending activation installation epoch is stale";
            let host_capability = owner_lease.activation_capability();
            persist_pending_recovery(
                &registry_store,
                &mut registry,
                &host_capability,
                pending,
                reason,
            )?;
            return Err(HostError::RecoveryRequired(reason.to_owned()));
        }
        // Rehydrate and validate every durable runtime-restart record before
        // opening the journal or creating any runtime job branch. A malformed
        // or ambiguous record must stop admission before Host can mutate the
        // physical runtime or adopt a restart outcome.
        let durable_restarts = {
            #[cfg(windows)]
            {
                load_durable_runtime_restarts(&host_state_root)?
            }
            #[cfg(not(windows))]
            {
                std::collections::HashMap::new()
            }
        };
        let durable_store_recovery_fences = {
            #[cfg(windows)]
            {
                load_durable_store_recoveries(&host_state_root)?
            }
            #[cfg(not(windows))]
            {
                Vec::new()
            }
        };
        let journal_path = host_state_root.join(HOST_JOURNAL_FILE_NAME);
        let (
            journal,
            host,
            activation_generation,
            activation_id,
            store_recovery_startup_fence,
            active_phase_b_rebind_recovery,
        ) = open_production_epoch(
            &journal_path,
            installation,
            pending_for_reopen.as_ref(),
            registry.active_phase_b_rebind(),
            &durable_store_recovery_fences,
        )?;
        #[cfg(windows)]
        let jobs = if store_recovery_startup_fence.is_fenced() {
            HostJobBranches::new_fenced(&host)
        } else {
            HostJobBranches::new(&host)
        }
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut composition = Self {
            store_rebind_boundary: HostStoreRebindProductionBoundary,
            runtime_control_boundary: HostRuntimeControlProductionBoundary,
            journal,
            registry_store,
            registry,
            launch_options,
            host,
            activation_generation,
            activation_id,
            running: true,
            #[cfg(windows)]
            jobs,
            #[cfg(windows)]
            readiness_gate: HostReadinessGate::with_cadence(ReadinessCadence::default()),
            #[cfg(windows)]
            phase_b: None,
            #[cfg(windows)]
            runtime_restarts: durable_restarts,
            #[cfg(windows)]
            runtime_control_queue: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            )),
            #[cfg(windows)]
            store_recovery_startup_fence,
            active_phase_b_rebind_recovery,
            owner_lease,
            pending_record: None,
            durable_finalized: false,
            owner_released: false,
            shutdown_failed: false,
        };
        #[cfg(windows)]
        if composition.store_recovery_startup_fence.is_fenced() {
            // A durable Store recovery fence is resolved only by the
            // authenticated ReconcileStoreRecovery route.  The `jobs` value
            // above is an inert identity holder with no current-process
            // observation, Job handle, or child; no Phase-B materialization,
            // child launch, or readiness publication may run before the exact
            // inner contour is reconstructed.
            composition.readiness_gate.branch_degraded();
            return Ok(composition);
        }
        #[cfg(windows)]
        if let Some(pending) = composition.registry.pending_activation().cloned() {
            if pending.phase_b_agent_bridge_stage_prepared.is_some()
                && pending.phase_b_prepared.is_none()
            {
                // The executable stage is an independent durable crash
                // carrier.  Reconcile it before considering prepared data,
                // but do not manufacture a profile/declaration or publish a
                // pair: the exact original handoff must retry preparation.
                Self::reconcile_pending_agent_bridge_stage(&pending)?;
                composition.readiness_gate.branch_degraded();
                return Ok(composition);
            }
            if let Some(prepared) = pending.phase_b_prepared.as_ref() {
                let prior_bridge = composition
                    .registry
                    .last_committed_activation_fence()
                    .and_then(|fence| fence.phase_b_live_binding.as_ref())
                    .and_then(|binding| binding.agent_bridge.as_ref());
                let mut materialization = match composition.rehydrate_phase_b_from_prepared(
                    &pending.manifest,
                    prepared,
                    Some(&pending),
                    prior_bridge,
                ) {
                    Ok(materialization) => materialization,
                    Err(error) if pending.phase_b_receipt.is_none() => {
                        composition.rollback_uncommitted_phase_b(&pending, prepared)?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                if let Some(receipt) = pending.phase_b_receipt.as_ref() {
                    materialization
                        .agent_bridge_final
                        .clone_from(&receipt.agent_bridge);
                }
                composition.phase_b = Some(materialization.clone());
                let pending_after_readback = composition
                    .registry
                    .pending_activation()
                    .cloned()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "Phase-B preparation disappeared during restart readback".to_owned(),
                        )
                    })?;
                if pending_after_readback.phase_b_receipt.is_none() {
                    if pending_after_readback.phase_b_prepared_receipt.is_none() {
                        let intent =
                            pending_after_readback
                                .phase_b_intent
                                .as_ref()
                                .ok_or_else(|| {
                                    HostError::RecoveryRequired(
                                        "Phase-B preparation has no matching transaction intent"
                                            .to_owned(),
                                    )
                                })?;
                        let receipt = phase_b_prepared_public_receipt(
                            intent,
                            &materialization,
                            &composition.host,
                            Some(&pending_after_readback),
                        )?;
                        let host_capability = composition.owner_lease.activation_capability();
                        composition.persist_pending_phase_b_prepared_receipt(
                            &pending_after_readback,
                            &receipt,
                            &host_capability,
                        )?;
                    }
                    composition.readiness_gate.branch_degraded();
                    return Ok(composition);
                } else if let Some(binding) = materialization.agent_bridge() {
                    // A crash after the receipt CAS and before backup cleanup
                    // is harmless: exact receipt readback above is the
                    // durable ownership proof, so cleanup may now finish.
                    phase_b_remove_rollback_backup(
                        std::path::Path::new(binding.profile_path.as_str()),
                        "Agent Bridge admission profile",
                    )?;
                    phase_b_remove_rollback_backup(
                        std::path::Path::new(binding.declaration_path.as_str()),
                        "Agent Bridge client declaration",
                    )?;
                }
                composition.resume_pending_activation_after_phase_b()?;
            }
            // Phase A deliberately has no authority descriptor. Keep this
            // Host owner alive in a fenced, non-admissible state until the
            // external ORS handoff reaches the Host-owned Phase-B method.
            // Once a destination is observable, startup performs exact
            // readback/reconciliation; an incomplete/stale Phase-B contour
            // remains fenced and is resumable only with a fresh exact handoff.
            if phase_b_authority_is_observable(&pending.manifest)? {
                match Self::reconcile_phase_b_for_manifest(&pending.manifest) {
                    Ok(_) => composition.reconcile_pending_activation(&pending)?,
                    Err(HostError::RecoveryRequired(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        } else if let Some(active) = composition.registry.active().cloned() {
            if composition.store_recovery_startup_fence.is_fenced() {
                // A prior Host died while an exact RecoverStore intent was
                // unresolved. New Job names, PIDs, activation nonce, and Host
                // epoch cannot satisfy the prior committed inner receipt.
                // Keep the runtime-control query surface alive, but admit no
                // Phase-B/process/readiness contour for this fresh owner.
                composition.readiness_gate.branch_degraded();
                return Ok(composition);
            }
            // A committed ActiveVerified fence is source evidence only.  Every
            // Host restart must mint a fresh owner-bound Phase-B rebind before
            // any approved child contour is admitted; destination bytes alone
            // are never treated as current authority.
            composition
                .rebind_active_phase_b(&active, composition.active_phase_b_rebind_recovery)?;
            start_approved_manifest_contour(
                &mut composition,
                &active.manifest,
                HostStartupBranch::Active,
                None,
            )?;
        }
        Ok(composition)
    }

    /// Returns the Host epoch bound to this process.
    #[must_use]
    pub const fn host_epoch(&self) -> &HostInstallationEpoch {
        &self.host
    }

    /// Creates the credential control only from this live Host composition's
    /// owner lease.  Callers receive an opaque authenticated server handle;
    /// the raw `LocalService` Credential Manager provider is not public.
    ///
    /// # Errors
    ///
    /// Returns an error if the live Host owner capability or protected state
    /// root cannot be admitted.
    #[cfg(windows)]
    pub fn credential_control(&self) -> Result<HostCredentialControl, HostError> {
        let capability = self
            .owner_lease
            .credential_mutation_capability()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        HostCredentialControl::new(
            self.host.clone(),
            self.launch_options.host_state_root().to_path_buf(),
            capability,
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        )
        .map_err(HostError::Platform)
    }

    /// Handles one authenticated, transaction-bound Phase-B request on the
    /// mutable Host owner thread. The worker has already authenticated the
    /// installer and verified the prior `LocalService` receipt; this method is
    /// the only production ingress that can publish the live overlay and
    /// resume the pending activation.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "Phase-B request keeps authenticated handoff, durable CAS reload, receipt, and resume ordering together"
    )]
    pub fn handle_phase_b_request(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
        credential_receipt: &CredentialAccessReceipt,
    ) -> HostCredentialControlResponse {
        if self.store_recovery_startup_fence.is_fenced() {
            return HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref(
                    "store-recovery-fence",
                    "MaterializePhaseB",
                    intent,
                ),
            };
        }
        let result = (|| {
            intent
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B handoff requires the exact pending activation".to_owned(),
                )
            })?;
            validate_phase_b_credential_receipt(credential_receipt, &pending.manifest, intent)?;
            let manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
            let expected_static_template = phase_b_static_template_for_candidate(&pending.manifest)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let credential_receipt_digest = phase_b_credential_receipt_digest(credential_receipt)?;
            if let Some(receipt) = pending.phase_b_receipt.as_ref()
                && receipt.validate().is_ok()
                && receipt.transaction_id == intent.transaction_id
                && receipt.effect_id == intent.effect_id
                && receipt.candidate_manifest_digest == manifest_digest
                && receipt.request_digest == intent.request_digest
                && intent.credential_receipt_digest == credential_receipt_digest
            {
                // A prior Host process may have completed publication and
                // the pending registry CAS while the installer response was
                // lost. Rehydrate the prepared contour and continue the
                // activation handoff without rematerializing any destination.
                // This closes the response-loss window after the receipt CAS
                // but before the activation terminal CAS.
                return Err(HostError::RecoveryRequired(
                    "Phase-B is already final; use ReconcilePhaseB".to_owned(),
                ));
            }
            let live_process_identity = host_process_identity_digest()?;
            if intent.transaction_id != pending.transaction_id
                || intent.installation_plan_digest != pending.plan_digest
                || intent.candidate_manifest_digest != manifest_digest
                || intent.static_template != expected_static_template
                || credential_receipt.transaction_id != pending.transaction_id
                || credential_receipt.effect_id != intent.credential_effect_id
                || credential_receipt.host_owner_epoch != host_owner_epoch_digest(&self.host)?
                || credential_receipt.host_process_identity != live_process_identity
                || intent.host_state_root_digest != phase_b_root_binding_digest(&pending.manifest)?
                || intent.watchdog_selector_digest
                    != phase_b_watchdog_selector_digest(&pending.manifest)?
                || intent.credential_receipt_digest != credential_receipt_digest
            {
                return Err(HostError::RecoveryRequired(
                    "Phase-B handoff binding does not match the live Host contour".to_owned(),
                ));
            }
            let host_capability = self.owner_lease.activation_capability();
            // This CAS is the durable crash boundary immediately before the
            // first destination publication. A restarted Host can therefore
            // distinguish an untouched pending activation from an interrupted
            // Phase-B contour without consulting `self.phase_b` memory.
            self.persist_pending_phase_b_intent(&pending, intent, &host_capability)?;
            let authority_descriptor_bytes = phase_b_build_authority_descriptor(
                &pending.manifest,
                &self.host,
                &self.activation_generation.current,
                intent,
            )?;
            let mut materialization = self.materialize_phase_b(
                &pending.manifest,
                &HostPhaseBInput {
                    authority_descriptor_bytes,
                },
                None,
            )?;
            materialization.transaction_id = Some(intent.transaction_id.clone());
            materialization.effect_id = Some(intent.effect_id.clone());
            materialization.credential_receipt_digest =
                Some(intent.credential_receipt_digest.clone());
            materialization.request_digest = Some(intent.request_digest.clone());
            // `materialize_phase_b` durably records the executable-stage
            // proof and prepared binding.  The pre-materialization snapshot
            // is therefore stale; constructing a receipt from it would omit
            // the bridge proof and make a response-loss restart unable to
            // validate the exact contour.
            let pending_after_materialization =
                self.registry.pending_activation().cloned().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B materialization lost the exact pending activation".to_owned(),
                    )
                })?;
            if pending_after_materialization.transaction_id != pending.transaction_id
                || pending_after_materialization.plan_digest != pending.plan_digest
                || pending_after_materialization.approval != pending.approval
                || pending_after_materialization.phase_b_intent.as_ref() != Some(intent)
            {
                return Err(HostError::RecoveryRequired(
                    "Phase-B materialization changed the exact pending transaction contour"
                        .to_owned(),
                ));
            }
            let receipt = phase_b_prepared_public_receipt(
                intent,
                &materialization,
                &self.host,
                Some(&pending_after_materialization),
            )?;
            materialization.host_owner_epoch = Some(receipt.host_owner_epoch.clone());
            materialization.host_process_identity = Some(receipt.host_process_identity.clone());
            materialization.public_receipt_digest = Some(receipt.receipt_digest.clone());
            self.persist_pending_phase_b_prepared_receipt(
                &pending_after_materialization,
                &receipt,
                &host_capability,
            )?;
            self.phase_b = Some(materialization.clone());
            Ok(receipt)
        })();
        match result {
            Ok(receipt) => HostCredentialControlResponse::PhaseBPrepared {
                receipt: Box::new(receipt),
            },
            Err(_error) => HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref("phase-b", "MaterializePhaseB", intent),
            },
        }
    }

    /// Commits the provider's final Phase-B proof after retained-handle
    /// verification. Prepared state alone never resumes activation.
    #[cfg(windows)]
    pub fn finalize_phase_b_request(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
        credential_receipt: &CredentialAccessReceipt,
        final_receipt: &HostPhaseBMaterializationReceipt,
    ) -> HostCredentialControlResponse {
        let result = (|| {
            intent
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            final_receipt
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "FinalizePhaseB requires the exact pending activation".to_owned(),
                )
            })?;
            validate_phase_b_credential_receipt(credential_receipt, &pending.manifest, intent)?;
            let prepared = pending.phase_b_prepared_receipt.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "FinalizePhaseB has no durable prepared receipt".to_owned(),
                )
            })?;
            if pending.phase_b_receipt.is_some()
                || final_receipt.transaction_id != intent.transaction_id
                || final_receipt.effect_id != intent.effect_id
                || final_receipt.candidate_manifest_digest != intent.candidate_manifest_digest
                || final_receipt.request_digest != intent.request_digest
                || prepared.transaction_id != final_receipt.transaction_id
                || prepared.effect_id != final_receipt.effect_id
                || prepared.request_digest != final_receipt.request_digest
                || prepared.candidate_manifest_digest != final_receipt.candidate_manifest_digest
                || prepared.host_owner_epoch != final_receipt.host_owner_epoch
                || prepared.host_process_identity != final_receipt.host_process_identity
                || prepared.authority_descriptor_digest != final_receipt.authority_descriptor_digest
                || prepared.config_file_digest != final_receipt.config_file_digest
                || prepared.store_bootstrap_descriptor_digest
                    != final_receipt.store_bootstrap_descriptor_digest
                || prepared.eliotd_descriptor_digest != final_receipt.eliotd_descriptor_digest
                || prepared.provisioned_supervision_authority
                    != final_receipt.provisioned_supervision_authority
                || prepared
                    .agent_bridge
                    .as_ref()
                    .map(|b| b.stage_prepared.clone())
                    != final_receipt
                        .agent_bridge
                        .as_ref()
                        .map(|b| b.prepared.stage_prepared.clone())
            {
                return Err(HostError::RecoveryRequired(
                    "final Phase-B receipt is not bound to the prepared proof".to_owned(),
                ));
            }
            if let Some(final_bridge) = final_receipt.agent_bridge.as_ref() {
                let prepared_bridge = prepared.agent_bridge.as_ref().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "final bridge proof has no prepared counterpart".to_owned(),
                    )
                })?;
                if !final_bridge.matches_prepared_core(prepared_bridge) {
                    return Err(HostError::RecoveryRequired(
                        "final bridge proof substituted its prepared core".to_owned(),
                    ));
                }
                final_bridge
                    .validate_against_phase_b(intent, &pending)
                    .map_err(HostError::Installation)?;
                let _lease = open_agent_bridge_final_lease(
                    final_bridge,
                    final_bridge.approved_user_sid.as_str(),
                )?;
            } else if intent.agent_bridge_source.is_some() || prepared.agent_bridge.is_some() {
                return Err(HostError::RecoveryRequired(
                    "bridge-enabled Phase-B final proof is absent".to_owned(),
                ));
            }
            let host_capability = self.owner_lease.activation_capability();
            self.persist_pending_phase_b_receipt(&pending, final_receipt, &host_capability)?;
            if let Some(materialization) = self.phase_b.as_mut() {
                materialization
                    .agent_bridge_final
                    .clone_from(&final_receipt.agent_bridge);
            }
            self.resume_pending_activation_after_phase_b()?;
            Ok(final_receipt.clone())
        })();
        match result {
            Ok(receipt) => HostCredentialControlResponse::PhaseBReady {
                receipt: Box::new(receipt),
            },
            Err(_) => HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref("phase-b-finalize", "FinalizePhaseB", intent),
            },
        }
    }

    /// Handles a durable Phase-B response-loss retry without invoking any
    /// materialization or activation mutation. The live Host composition is
    /// the query owner; after activation commit it first authenticates the
    /// exact registry terminal and then reuses only its matching in-memory
    /// receipt. The committed registry fence is sufficient to rehydrate the
    /// public receipt after a Host process restart; destination bytes are
    /// never accepted as a substitute.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "Phase-B query keeps pending/committed binding and response-loss reconciliation in one fail-closed boundary"
    )]
    pub fn reconcile_phase_b_request(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
        credential_receipt: &CredentialAccessReceipt,
    ) -> HostCredentialControlResponse {
        if self.store_recovery_startup_fence.is_fenced() {
            return HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref("store-recovery-fence", "ReconcilePhaseB", intent),
            };
        }
        // Query-only prepared readback: return the exact durable prepared
        // wire proof without rehydrating, converging ACLs, or resuming.
        if let Some(pending) = self.registry.pending_activation().cloned()
            && let Some(receipt) = pending.phase_b_prepared_receipt.as_ref()
            && pending.phase_b_receipt.is_none()
            && intent.validate().is_ok()
            && validate_phase_b_credential_receipt(credential_receipt, &pending.manifest, intent)
                .is_ok()
            && receipt.validate().is_ok()
            && receipt.transaction_id == intent.transaction_id
            && receipt.effect_id == intent.effect_id
            && receipt.request_digest == intent.request_digest
        {
            return HostCredentialControlResponse::PhaseBPrepared {
                receipt: Box::new(receipt.clone()),
            };
        }
        let result = (|| {
            intent
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let (
                manifest,
                plan_digest,
                committed_binding,
                pending_intent,
                pending_prepared,
                pending_prepared_receipt,
                pending_receipt,
            ) = if let Some(pending) = self.registry.pending_activation().cloned() {
                if pending
                    .phase_b_intent
                    .as_ref()
                    .is_some_and(|saved| saved != intent)
                {
                    return Err(HostError::RecoveryRequired(
                        "pending Phase-B intent belongs to a different request".to_owned(),
                    ));
                }
                (
                    pending.manifest,
                    pending.plan_digest,
                    None,
                    pending.phase_b_intent,
                    pending.phase_b_prepared,
                    pending.phase_b_prepared_receipt,
                    pending.phase_b_receipt,
                )
            } else {
                let active = self.registry.active().cloned().ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "Phase-B query has neither the exact pending nor committed active generation"
                                .to_owned(),
                        )
                    })?;
                let manifest_digest = phase_b_manifest_digest(&active.manifest)?;
                let terminal = self
                    .registry_store
                    .read_committed_activation_receipt(
                        &intent.transaction_id,
                        &intent.installation_plan_digest,
                        &active.manifest.generation,
                    )
                    .map_err(HostError::Installation)?;
                let binding = terminal
                    .commit_fence()
                    .phase_b_live_binding
                    .clone()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "committed activation is missing its Phase-B binding".to_owned(),
                        )
                    })?;
                if binding.manifest_digest != manifest_digest {
                    return Err(HostError::RecoveryRequired(
                        "committed Phase-B binding belongs to a different manifest".to_owned(),
                    ));
                }
                (
                    active.manifest,
                    terminal.plan_digest().clone(),
                    Some(binding),
                    None,
                    None,
                    None,
                    None,
                )
            };
            let manifest_digest = phase_b_manifest_digest(&manifest)?;
            let expected_static_template = phase_b_static_template_for_candidate(&manifest)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            validate_phase_b_credential_receipt(credential_receipt, &manifest, intent)?;
            let live_process_identity = if committed_binding.is_none()
                && pending_receipt.is_none()
                && pending_intent.is_none()
            {
                Some(host_process_identity_digest()?)
            } else {
                None
            };
            if intent.installation_plan_digest != plan_digest
                || intent.candidate_manifest_digest != manifest_digest
                || intent.static_template != expected_static_template
                || credential_receipt.transaction_id != intent.transaction_id
                || credential_receipt.effect_id != intent.credential_effect_id
                || (committed_binding.is_none()
                    && pending_receipt.is_none()
                    && pending_intent.is_none()
                    && (credential_receipt.host_owner_epoch
                        != host_owner_epoch_digest(&self.host)?
                        || Some(credential_receipt.host_process_identity.clone())
                            != live_process_identity))
                || intent.host_state_root_digest != phase_b_root_binding_digest(&manifest)?
                || intent.watchdog_selector_digest != phase_b_watchdog_selector_digest(&manifest)?
                || intent.credential_receipt_digest
                    != phase_b_credential_receipt_digest(credential_receipt)?
                || pending_prepared.as_ref().is_some_and(|prepared| {
                    prepared.host_owner_epoch != credential_receipt.host_owner_epoch
                        || prepared.host_process_identity
                            != credential_receipt.host_process_identity
                })
            {
                return Err(HostError::RecoveryRequired(
                    "Phase-B query binding does not match the live Host contour".to_owned(),
                ));
            }
            if let Some(binding) = committed_binding.as_ref() {
                return phase_b_public_receipt_from_binding(
                    intent,
                    binding,
                    credential_receipt,
                    self.registry.pending_activation(),
                );
            }
            if let Some(receipt) = pending_receipt.as_ref() {
                if receipt.validate().is_err()
                    || receipt.transaction_id != intent.transaction_id
                    || receipt.effect_id != intent.effect_id
                    || receipt.candidate_manifest_digest != manifest_digest
                    || receipt.request_digest != intent.request_digest
                    || receipt.host_owner_epoch != credential_receipt.host_owner_epoch
                    || receipt.host_process_identity != credential_receipt.host_process_identity
                {
                    return Err(HostError::RecoveryRequired(
                        "pending Phase-B receipt is not bound to the exact query".to_owned(),
                    ));
                }
                // ReconcilePhaseB is query-only.  The receipt CAS may be
                // durable while activation continuation was interrupted, but
                // this operation must not rehydrate, start children, append
                // journal records, or advance the registry.  The mutable
                // continuation is owned by the Host startup/worker contour.
                return Ok(receipt.clone());
            }
            if let Some(receipt) = pending_prepared_receipt.as_ref() {
                if receipt.validate().is_err()
                    || receipt.transaction_id != intent.transaction_id
                    || receipt.effect_id != intent.effect_id
                    || receipt.candidate_manifest_digest != manifest_digest
                    || receipt.request_digest != intent.request_digest
                {
                    return Err(HostError::RecoveryRequired(
                        "pending prepared Phase-B receipt is not bound to the exact query"
                            .to_owned(),
                    ));
                }
                return Err(HostError::RecoveryRequired(
                    "Phase-B remains prepared; provider finalization is required".to_owned(),
                ));
            }
            if pending_intent.is_some() && pending_prepared.is_none() {
                return Err(HostError::RecoveryRequired(
                    "Phase-B publication was interrupted after its durable intent and before its receipt; rollback/recovery is required"
                        .to_owned(),
                ));
            }
            let materialization = self.phase_b.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Host has no rehydrated Phase-B materialization for the durable preparation"
                        .to_owned(),
                )
            })?;
            if materialization.manifest_digest != manifest_digest {
                return Err(HostError::RecoveryRequired(
                    "Host Phase-B receipt belongs to a different manifest".to_owned(),
                ));
            }
            if let Some(prepared) = pending_prepared.as_ref()
                && (materialization.transaction_id.as_ref() != Some(&prepared.transaction_id)
                    || materialization.effect_id.as_ref() != Some(&prepared.effect_id)
                    || materialization.request_digest.as_ref() != Some(&prepared.request_digest)
                    || materialization.credential_receipt_digest.as_ref()
                        != Some(&prepared.credential_receipt_digest)
                    || materialization.authority_descriptor_digest
                        != prepared.authority_descriptor_digest
                    || materialization.config_file_digest != prepared.config_file_digest
                    || materialization.store_bootstrap_descriptor_digest
                        != prepared.store_bootstrap_descriptor_digest
                    || materialization.eliotd_descriptor_digest
                        != prepared.eliotd_descriptor_digest
                    || materialization.launch != prepared.launch)
            {
                return Err(HostError::RecoveryRequired(
                    "in-memory Phase-B materialization does not match the durable preparation"
                        .to_owned(),
                ));
            }
            phase_b_public_receipt(
                intent,
                materialization,
                &self.host,
                self.registry.pending_activation(),
            )
        })();
        match result {
            Ok(receipt) => HostCredentialControlResponse::PhaseBReady {
                receipt: Box::new(receipt),
            },
            Err(_error) => HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref("phase-b-query", "ReconcilePhaseB", intent),
            },
        }
    }

    #[cfg(windows)]
    #[allow(missing_docs, clippy::missing_errors_doc)]
    pub fn runtime_control(&self) -> Result<HostRuntimeControl, HostError> {
        let capability = self.owner_lease.activation_capability();
        let _guard = capability
            .live_guard()
            .map_err(|e| HostError::Platform(e.to_string()))?;
        HostRuntimeControl::new_with_capability(
            std::sync::Arc::clone(&self.runtime_control_queue),
            &capability,
        )
        .map_err(HostError::Platform)
    }

    #[cfg(windows)]
    #[allow(missing_docs)]
    pub fn runtime_control_queue(&self) -> HostRuntimeControlQueue {
        std::sync::Arc::clone(&self.runtime_control_queue)
    }

    #[cfg(windows)]
    pub fn handle_kernel_restart_request(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        if request.operation == HostRuntimeControlOperation::ReconcileKernelRestart {
            return self.reconcile_kernel_restart_request(request);
        }
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart", request),
            );
        }
        let result = self.execute_kernel_restart(request);
        match result {
            Ok(receipt) => HostRuntimeControlResponse::restarted_for(request, receipt),
            Err(_error) => HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart", request),
            ),
        }
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines, missing_docs)]
    pub fn reconcile_kernel_restart_request(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-reconcile", request),
            );
        }
        if request.validate().is_err() {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-reconcile", request),
            );
        }
        let key = request.mutation_digest.as_str().to_owned();
        if let Some(receipt) = self.runtime_restarts.get(&key).cloned() {
            return match rebind_runtime_restart_receipt(&receipt, request) {
                Ok(receipt) => HostRuntimeControlResponse::restarted_for(request, receipt),
                Err(_) => HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-reconcile-conflict", request),
                ),
            };
        }
        match has_runtime_restart_pending(self.launch_options.host_state_root(), &key) {
            Ok(true) | Err(_) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-pending", request),
                );
            }
            Ok(false) => {}
        }
        let snapshot = match self.journal.snapshot() {
            Ok(s) => s,
            Err(_e) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-reconcile-snapshot", request),
                );
            }
        };
        if let Some(kernel) = snapshot.kernel.as_ref() {
            let _ = kernel;
        }
        HostRuntimeControlResponse::unknown_for(
            request,
            runtime_control_unknown_ref("kernel-restart-reconcile-unknown", request),
        )
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        clippy::map_unwrap_or,
        clippy::needless_borrow,
        missing_docs
    )]
    fn execute_kernel_restart(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> Result<HostKernelRestartReceipt, HostError> {
        request.validate().map_err(HostError::ProcessContour)?;
        if request.operation != HostRuntimeControlOperation::RestartKernel {
            return Err(HostError::ProcessContour(
                "unsupported runtime-control operation".to_owned(),
            ));
        }
        let key = request.mutation_digest.as_str().to_owned();
        if let Some(existing) = self.runtime_restarts.get(&key).cloned() {
            return Ok(existing);
        }
        if has_runtime_restart_pending(self.launch_options.host_state_root(), &key)? {
            return Err(HostError::RecoveryRequired(
                "Kernel restart intent is pending and outcome is unknown; reconcile required"
                    .to_owned(),
            ));
        }
        self.ensure_admission_open()?;
        let capability = self.owner_lease.activation_capability();
        let guard = capability
            .live_guard()
            .map_err(|e| HostError::Platform(e.to_string()))?;
        if persist_runtime_restart_pending(
            self.launch_options.host_state_root(),
            request,
            &self.host,
        )? == RuntimeRestartPendingPublication::Replay
        {
            return Err(HostError::RecoveryRequired(
                "Kernel restart intent is already pending; reconcile required".to_owned(),
            ));
        }
        drop(guard);
        drop(capability);
        let store_before = self.jobs.store_process().cloned().ok_or_else(|| {
            HostError::ProcessContour("Store process is missing before Kernel restart".to_owned())
        })?;
        let store_job_before = self.jobs.store_name().to_owned();
        let store_fence_before = match self.journal.snapshot()?.readiness_observations.last() {
            Some(observation) => observation.store_fence.clone(),
            None => PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        let current_kernel =
            self.journal.snapshot()?.kernel.clone().ok_or_else(|| {
                HostError::ProcessContour("no active Kernel to restart".to_owned())
            })?;
        if current_kernel.state != KernelActivationState::Active {
            return Err(HostError::ProcessContour(
                "Kernel is not Active; restart requires Active".to_owned(),
            ));
        }
        if current_kernel.process.is_none() || current_kernel.candidate_job_binding.is_none() {
            return Err(HostError::OwnerLeaseRecovery(
                "prior Kernel process/job binding is absent; cannot prove termination".to_owned(),
            ));
        }
        let old_generation = current_kernel.kernel_generation.clone();
        let host_clone = self.host.clone();
        let activation_id = self.activation_id.clone();
        let activation_generation = self.activation_generation.clone();
        let terminated_child = {
            let kernel_mut = self
                .jobs
                .kernel
                .as_mut()
                .ok_or_else(|| HostError::ProcessContour("Kernel Job is missing".to_owned()))?;
            kernel_mut
                .terminate_in_place(0xE017_0001)
                .map_err(|e| HostError::RecoveryRequired(e.to_string()))?
        };
        if !terminated_child.job_empty() || !terminated_child.root_reaped() {
            return Err(HostError::RecoveryRequired(
                "Kernel termination did not produce job-empty/root-reaped evidence".to_owned(),
            ));
        }
        if terminated_child.process().process_id == 0
            || terminated_child.process().start_time_100ns == 0
        {
            return Err(HostError::RecoveryRequired(
                "Terminated Kernel child has invalid identity".to_owned(),
            ));
        }
        self.jobs.kernel.take();
        let fail_driver =
            DurableKernelActivationDriver::resume(&self.journal, current_kernel.clone());
        let fail_result = {
            let mut driver = fail_driver;
            driver.fail(&format!(
                "kernel-restart:{}",
                request.request_digest.as_str()
            ))
        };
        match fail_result {
            Ok(()) => {}
            Err(HostError::Journal(JournalError::OutcomeUnknown { transaction_id })) => {
                match self.journal.reconcile(&transaction_id)? {
                    ReconcileOutcome::Committed => {
                        let _ = self.journal.reconcile(&transaction_id);
                    }
                    ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                        return Err(HostError::Journal(JournalError::OutcomeUnknown {
                            transaction_id,
                        }));
                    }
                }
            }
            Err(e) => return Err(e),
        }
        let (next_prior, kernel_generation, kernel_authority_epoch) = self
            .next_kernel_activation_context(
                self.jobs
                    .launch
                    .as_ref()
                    .ok_or_else(|| HostError::ProcessContour("launch missing".to_owned()))?
                    .authority_state_fence
                    .authority_epoch,
                Some(&terminated_child),
            )?;
        let prior_kernel = terminated_prior_kernel(&current_kernel, &terminated_child)?;
        if !matches!(prior_kernel, PriorKernelDisposition::Terminated(_))
            || !matches!(next_prior, PriorKernelDisposition::Terminated(_))
        {
            return Err(HostError::ProcessContour(
                "next context did not prove terminated".to_owned(),
            ));
        }
        if prior_kernel != next_prior {
            return Err(HostError::RecoveryRequired(
                "Prior kernel disposition does not match durable terminated evidence".to_owned(),
            ));
        }
        let active_manifest = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no active manifest".to_owned()))?
            .manifest
            .clone();
        let (kernel_artifact, _) = active_manifest
            .host_child_artifact_digests()
            .map_err(|e| HostError::ProcessContour(e.to_string()))?;
        let config_digest = self
            .jobs
            .config_digest
            .clone()
            .ok_or_else(|| HostError::ProcessContour("config digest missing".to_owned()))?;
        let config_path = self
            .jobs
            .config_path
            .clone()
            .ok_or_else(|| HostError::ProcessContour("config path missing".to_owned()))?;
        let approved_kernel_path = active_manifest.host_child_paths().0;
        let new_child = self.jobs.relaunch_kernel(
            &active_manifest.generation,
            &config_digest,
            &config_path,
            &kernel_artifact,
            &approved_kernel_path,
            &active_manifest.host_child_paths().2,
            &host_clone,
        )?;
        self.jobs.kernel = Some(new_child);
        let launch_generation = active_manifest.generation.clone();
        let complete_result = self.jobs.complete_kernel_control(
            &launch_generation,
            &host_clone,
            &self.journal,
            &activation_id,
            &activation_generation,
            prior_kernel,
            kernel_generation.clone(),
            kernel_authority_epoch,
        );
        let (activation_receipt, ready_receipt) = match complete_result {
            Ok(v) => v,
            Err(HostError::Journal(JournalError::OutcomeUnknown { transaction_id })) => {
                let query = KernelActivationQuery {
                    operation_id: PlatformHandle::new(
                        kernel_generation.current.lineage.as_str().to_owned(),
                    )
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                    activate_request_digest: transaction_id.as_str().to_owned(),
                };
                let _ = self.journal.reconcile(&transaction_id)?;
                let _ = query;
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id,
                }));
            }
            Err(e) => {
                let _ = self.jobs.terminate_kernel();
                return Err(e);
            }
        };
        let store_after =
            self.jobs.store_process().cloned().ok_or_else(|| {
                HostError::ProcessContour("Store missing after restart".to_owned())
            })?;
        if store_before.process_id != store_after.process_id
            || store_before.start_time_100ns != store_after.start_time_100ns
            || store_before.image_path != store_after.image_path
            || store_job_before != self.jobs.store_name()
        {
            return Err(HostError::ProcessContour(
                "Store PID/start/image/Job changed during Kernel restart".to_owned(),
            ));
        }
        let store_snapshot_before = store_fence_before;
        let store_snapshot_after = self
            .journal
            .snapshot()?
            .readiness_observations
            .last()
            .map(|o| o.store_fence.clone())
            .unwrap_or(store_snapshot_before.clone());
        if store_snapshot_before != store_snapshot_after
            && !store_snapshot_after.as_str().is_empty()
        {
            return Err(HostError::RecoveryRequired(
                "Store fence changed during Kernel restart; exact unchanged fence required"
                    .to_owned(),
            ));
        }
        let ready_digest = PlatformHandle::new(sha256_json(&ready_receipt)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let activation_digest = PlatformHandle::new(sha256_json(&activation_receipt)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let store_fence = match self.journal.snapshot()?.readiness_observations.last() {
            Some(observation) => observation.store_fence.clone(),
            None => PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        let old_gen_handle = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}",
                    old_generation.current.lineage.as_str(),
                    old_generation.current.sequence
                )
                .as_bytes()
            )
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let new_gen_handle = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}",
                    kernel_generation.current.lineage.as_str(),
                    kernel_generation.current.sequence
                )
                .as_bytes()
            )
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: old_gen_handle,
            new_kernel_generation: new_gen_handle,
            store_fence,
            activation_receipt_digest: activation_digest,
            ready_receipt_digest: ready_digest,
            receipt_digest: PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        receipt.receipt_digest = receipt.computed_digest().map_err(HostError::Platform)?;
        receipt.validate().map_err(HostError::Platform)?;
        persist_runtime_restart_receipt(self.launch_options.host_state_root(), &receipt)?;
        self.runtime_restarts.insert(key, receipt.clone());
        self.readiness_gate.branch_degraded();
        Ok(receipt)
    }

    /// Returns the canonical owner-object name held for this composition.
    ///
    /// The handle itself remains private and is released only after durable
    /// shutdown completion and `HostComposition` drop.
    #[must_use]
    pub fn owner_lease_name(&self) -> &str {
        self.owner_lease.name()
    }

    /// Reads the Host-only operational state from the crash-safe journal.
    ///
    /// # Errors
    ///
    /// Returns an error if the durable Host state cannot be loaded.
    pub fn snapshot(&self) -> Result<HostState, HostError> {
        self.journal.snapshot().map_err(HostError::Journal)
    }

    /// Returns the installation-owned approved-generation registry.
    #[must_use]
    pub const fn registry(&self) -> &ApprovedGenerationRegistry {
        &self.registry
    }

    fn resume_pending_record(&mut self) -> Result<(), HostError> {
        if let Some(pending) = self.pending_record.take()
            && let Err(error) = append_reconciled(&self.journal, pending.clone())
        {
            self.pending_record = Some(pending);
            return Err(error);
        }
        Ok(())
    }

    fn append_record(&mut self, record: HostStateRecord) -> Result<AppendReceipt, HostError> {
        self.resume_pending_record()?;
        match append_reconciled(&self.journal, record.clone()) {
            Ok(receipt) => Ok(receipt),
            Err(error @ HostError::Journal(JournalError::OutcomeUnknown { .. })) => {
                self.pending_record = Some(record);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn transition_activation(
        &mut self,
        state: ActivationState,
        label: &str,
    ) -> Result<(), HostError> {
        let current = self.journal.snapshot()?.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        self.append_record(HostStateRecord::Activation(transition_activation_record(
            &current, state, label,
        )?))?;
        Ok(())
    }

    #[cfg(windows)]
    fn start_watchdog(
        phase_b: &HostPhaseBMaterialization,
        scm_launch: &RuntimeLaunchDescriptor,
        approval: &InstallerServiceRegistrationApproval,
        context: RequestMetadata,
    ) -> Result<(), HostError> {
        phase_b
            .launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if phase_b.authority_descriptor_digest.as_str() == PHASE_B_PENDING_MARKER
            || phase_b.authority_descriptor_digest != phase_b.launch.authority_descriptor_digest
        {
            return Err(HostError::RecoveryRequired(
                "Watchdog admission lacks the exact Host-published authority digest".to_owned(),
            ));
        }
        let launch = &phase_b.launch;
        if scm_launch.generation != launch.generation
            || scm_launch.authority_descriptor_path != launch.authority_descriptor_path
            || scm_launch.watchdog_executable_path != launch.watchdog_executable_path
        {
            return Err(HostError::RecoveryRequired(
                "Watchdog SCM selector source is not the immutable manifest launch".to_owned(),
            ));
        }
        if approval.role() != InstallerServiceRole::Watchdog
            || approval.generation() != &launch.generation
        {
            return Err(HostError::ProcessContour(
                "Watchdog SCM approval is not bound to the requested generation".to_owned(),
            ));
        }
        let image = PathBuf::from(launch.watchdog_executable_path.as_str());
        let portable_root = if launch.profile == InstallationProfile::PortableDev {
            Some(
                UserOwnedRootLease::open_existing(Path::new(
                    launch
                        .portable_root
                        .as_ref()
                        .ok_or_else(|| {
                            HostError::ProcessContour("portable root is missing".to_owned())
                        })?
                        .as_str(),
                ))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            )
        } else {
            None
        };
        let lease = open_launch_lease(launch.profile, portable_root.as_ref(), &image)?;
        verify_launch_digest(
            &lease,
            &launch.watchdog_artifact_digest,
            "runtime.watchdog_artifact",
        )?;
        let mut platform = WindowsPlatform::new(PathBuf::from(launch.kernel_work_root.as_str()))
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let registration = approved_service_registration_request(
            scm_launch,
            approval,
            InstallerServiceRole::Watchdog,
            &launch.watchdog_executable_path,
        )?;
        debug_assert_eq!(registration.binary_path(), image.as_path());
        start_installed_watchdog(&mut platform, &registration, context)
    }

    #[cfg(windows)]
    fn next_kernel_activation_context(
        &self,
        manifest_authority_epoch: AuthorityEpoch,
        termination: Option<&eliot_platform_windows::TerminatedJobChild>,
    ) -> Result<(PriorKernelDisposition, EpochTransition, AuthorityEpoch), HostError> {
        let state = self.journal.snapshot()?;
        if state.prior_kernel_unknown {
            return Err(HostError::OwnerLeaseRecovery(
                "prior Kernel disposition is unknown".to_owned(),
            ));
        }
        let prior = state.kernel.as_ref().or(state.prior_kernel.as_ref());
        let Some(prior) = prior else {
            let activation = state.activation.ok_or_else(|| {
                HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
            })?;
            return Ok((
                PriorKernelDisposition::NoPriorKernel,
                EpochTransition {
                    current: activation.lineage.kernel_epoch,
                    parent: None,
                },
                manifest_authority_epoch,
            ));
        };
        if state.kernel.is_some()
            && !matches!(
                prior.state,
                KernelActivationState::Failed | KernelActivationState::ManualRecovery
            )
        {
            return Err(HostError::OwnerLeaseRecovery(
                "current Kernel must be durably failed before direct-child restart".to_owned(),
            ));
        }
        let generation = prior.direct_child_generation()?;
        let prior_authority = prior
            .process
            .as_ref()
            .ok_or_else(|| {
                HostError::OwnerLeaseRecovery("prior Kernel process binding is absent".to_owned())
            })?
            .authority_epoch
            .value();
        let next_authority_value =
            manifest_authority_epoch
                .value()
                .max(prior_authority.checked_add(1).ok_or_else(|| {
                    HostError::OwnerLeaseRecovery("Kernel authority epoch overflow".to_owned())
                })?);
        let authority = AuthorityEpoch::new(next_authority_value)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let prior_disposition = terminated_prior_kernel(
            prior,
            termination.ok_or_else(|| {
                HostError::OwnerLeaseRecovery(
                    "authoritative prior Kernel termination evidence is unavailable".to_owned(),
                )
            })?,
        )?;
        Ok((prior_disposition, generation, authority))
    }

    #[cfg(windows)]
    #[allow(dead_code)]
    fn fail_current_kernel_record(&self, evidence: &str) -> Result<(), HostError> {
        let current = self.journal.snapshot()?.kernel.ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "Kernel failure transition has no durable Kernel record".to_owned(),
            )
        })?;
        DurableKernelActivationDriver::resume(&self.journal, current).fail(evidence)
    }

    #[cfg(windows)]
    #[allow(dead_code)]
    fn activate_launched_kernel(
        &mut self,
        generation: &PlatformHandle,
        manifest_authority_epoch: AuthorityEpoch,
    ) -> Result<KernelReadyReceipt, HostError> {
        let (prior_kernel, kernel_generation, kernel_authority_epoch) =
            self.next_kernel_activation_context(manifest_authority_epoch, None)?;
        let (_, receipt) = self.jobs.complete_kernel_control(
            generation,
            &self.host,
            &self.journal,
            &self.activation_id,
            &self.activation_generation,
            prior_kernel,
            kernel_generation,
            kernel_authority_epoch,
        )?;
        if let Err(error) = self.accept_kernel_ready(&receipt) {
            let durable = self.fail_current_kernel_record("kernel-ready-accept-failed");
            return Err(match durable {
                Ok(()) => error,
                Err(durable) => HostError::RecoveryRequired(format!(
                    "Kernel ready receipt failed ({error}); durable failure transition failed ({durable})"
                )),
            });
        }
        Ok(receipt)
    }

    /// Starts the currently approved Kernel and store images in their
    /// independent Host-owned Job branches.  The registry is checked before
    /// any process is created, and the launch contour binds generation,
    /// configuration digest, installation and Host epoch into the child
    /// environment.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, no approved generation exists,
    /// or process identity, artifact, configuration, launch, or persistence fails.
    #[cfg(windows)]
    pub fn start_approved_contour(
        &mut self,
        kernel_executable: impl AsRef<Path>,
        store_executable: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let active =
            self.registry.active().cloned().ok_or_else(|| {
                HostError::ProcessContour("no approved active generation".to_owned())
            })?;
        let (_, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.start_manifest_contour(
            &active.manifest,
            kernel_executable.as_ref(),
            store_executable.as_ref(),
            store_artifact,
            None,
        )
    }

    /// Resumes one pending activation after Host Phase B has materialized its
    /// exact live authority and Store descriptors. The pending registry record
    /// remains non-admissible until this explicit Host-owned continuation
    /// observes the fresh process/readiness contour and commits it.
    ///
    /// # Errors
    ///
    /// Returns an error if no pending activation exists, Phase B is absent or
    /// stale, or the exact pending contour cannot be reconciled.
    #[cfg(windows)]
    pub fn resume_pending_activation_after_phase_b(&mut self) -> Result<(), HostError> {
        let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
            HostError::ProcessContour("no pending activation requires Phase-B resume".to_owned())
        })?;
        let manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
        if self
            .phase_b
            .as_ref()
            .is_none_or(|receipt| receipt.manifest_digest != manifest_digest)
        {
            return Err(HostError::RecoveryRequired(
                "pending activation has no exact Phase-B materialization receipt".to_owned(),
            ));
        }
        self.reconcile_pending_activation(&pending)
    }

    #[cfg(windows)]
    fn resume_pending_phase_b_receipt(&mut self) -> Result<(), HostError> {
        let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Phase-B receipt continuation has no exact pending activation".to_owned(),
            )
        })?;
        let manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
        if self
            .phase_b
            .as_ref()
            .is_none_or(|materialization| materialization.manifest_digest != manifest_digest)
        {
            let prepared = pending.phase_b_prepared.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B receipt continuation has no durable preparation".to_owned(),
                )
            })?;
            let prior_bridge = self
                .registry
                .last_committed_activation_fence()
                .and_then(|fence| fence.phase_b_live_binding.as_ref())
                .and_then(|binding| binding.agent_bridge.as_ref());
            let materialization = self.rehydrate_phase_b_from_prepared(
                &pending.manifest,
                prepared,
                Some(&pending),
                prior_bridge,
            )?;
            self.phase_b = Some(materialization);
        }
        // This is the exact post-receipt continuation. It may start the
        // already-approved child contour, but it never republishes Phase-B
        // bytes or issues a second materialization effect.
        self.resume_pending_activation_after_phase_b()
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "ordered Phase-B receipt admission, sibling start, and child readiness remain one fenced lifecycle boundary"
    )]
    fn start_manifest_contour(
        &mut self,
        manifest: &CandidateManifest,
        kernel_executable: &Path,
        store_executable: &Path,
        store_artifact: &PlatformHandle,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        Self::validate_launch_options_for_manifest(&self.launch_options, manifest)?;
        let manifest_digest = phase_b_manifest_digest(manifest)?;
        let phase_b = match self
            .phase_b
            .clone()
            .filter(|receipt| receipt.manifest_digest == manifest_digest)
        {
            Some(receipt) => receipt,
            None => Self::reconcile_phase_b_for_manifest(manifest)?,
        };
        phase_b
            .launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if phase_b.host_epoch != self.host.epoch.current
            || phase_b.host_process_nonce != self.host.nonce
        {
            return Err(HostError::RecoveryRequired(
                "Host Phase-B receipt is not bound to the current Host epoch/nonce".to_owned(),
            ));
        }
        let watchdog_approval = select_watchdog_approval_for_inspection(&self.registry, manifest)?;
        let current = self.journal.snapshot()?.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let mut next = transition_activation_record(
            &current,
            ActivationState::Starting,
            if pending.is_some() {
                "host-start-pending"
            } else {
                "host-start-approved"
            },
        )?;
        if let Some(pending) = pending {
            next.trigger_evidence
                .push(pending_activation_binding(pending)?);
        }
        next.trigger_evidence
            .push(phase_b_activation_binding(&phase_b)?);
        self.append_record(HostStateRecord::Activation(next))?;
        if let Some(watchdog_approval) = watchdog_approval.as_ref() {
            Self::start_watchdog(
                &phase_b,
                &manifest.runtime_launch,
                watchdog_approval,
                lifecycle_context(&self.host, "watchdog-start")?,
            )?;
        }
        let (kernel_artifact, approved_store_artifact) = manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if approved_store_artifact != store_artifact {
            return Err(HostError::ProcessContour(
                "Store bridge artifact digest is not the approved manifest digest".to_owned(),
            ));
        }
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            manifest.host_child_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        let (prior_kernel, kernel_generation, kernel_authority_epoch) = self
            .next_kernel_activation_context(
                phase_b.launch.authority_state_fence.authority_epoch,
                None,
            )?;
        self.jobs.start_approved(
            kernel_executable,
            store_executable,
            &manifest.generation,
            &phase_b.config_file_digest,
            &config_path,
            approved_kernel_path,
            approved_store_path,
            approved_config_path,
            kernel_artifact,
            store_artifact,
            &self.host,
            &phase_b.launch,
        )?;
        let agent_bridge_admission = match (phase_b.agent_bridge(), phase_b.final_agent_bridge()) {
            (Some(_prepared), None) => Err(HostError::RecoveryRequired(
                "Agent Bridge admission requires the final provider binding".to_owned(),
            )),
            (_, Some(binding)) => agent_bridge_admission_descriptor(
                phase_b.launch.profile,
                self.jobs.portable_root.as_ref(),
                binding,
            )
            .map(Some),
            (None, None) => Ok(None),
        };
        let agent_bridge_admission = match agent_bridge_admission {
            Ok(value) => value,
            Err(error) => return self.cleanup_launched_contour(error),
        };
        self.jobs.set_agent_bridge_admission(agent_bridge_admission);
        let (_activation_receipt, receipt) = match self.jobs.complete_kernel_control(
            &manifest.generation,
            &self.host,
            &self.journal,
            &self.activation_id,
            &self.activation_generation,
            prior_kernel,
            kernel_generation,
            kernel_authority_epoch,
        ) {
            Ok(value) => value,
            Err(error) => return self.cleanup_launched_contour(error),
        };
        if let Err(error) = self.accept_kernel_ready(&receipt) {
            return self.cleanup_active_kernel_contour(error, "kernel-ready-accept-failed");
        }
        if let Err(error) =
            self.transition_activation(ActivationState::ControlReady, "host-kernel-control-ready")
        {
            return self.cleanup_active_kernel_contour(error, "host-control-ready-commit-failed");
        }
        if let Err(error) =
            self.transition_activation(ActivationState::Active, "host-runtime-active")
        {
            return self.cleanup_active_kernel_contour(error, "host-active-commit-failed");
        }
        if let Err(error) = self.persist_process_observations(&manifest.generation) {
            self.cleanup_active_kernel_contour(error, "host-process-observation-failed")
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn accept_kernel_ready(&self, receipt: &KernelReadyReceipt) -> Result<(), HostError> {
        if receipt.activation_id != self.activation_id {
            return Err(HostError::ProcessContour(
                "Kernel ready receipt activation mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Activates one approved generation only after a bounded process cutover;
    /// a rejected candidate restores the registry's previous LKG projection.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, either generation is invalid,
    /// cutover or rollback fails, or the registry cannot be persisted.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        dead_code,
        reason = "candidate activation and exact rollback reactivation form one ordered durable cutover transaction"
    )]
    fn cutover_generation(
        &mut self,
        generation: &PlatformHandle,
        candidate_kernel: impl AsRef<Path>,
        candidate_store: impl AsRef<Path>,
        prior_kernel: impl AsRef<Path>,
        prior_store: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let host_capability = self.owner_lease.activation_capability();
        let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
            HostError::ProcessContour("cutover requires a pending activation".to_owned())
        })?;
        if pending.manifest.generation != *generation {
            return Err(HostError::ProcessContour(
                "cutover pending generation does not match request".to_owned(),
            ));
        }
        let prior = self.registry.active().cloned().ok_or_else(|| {
            HostError::ProcessContour("no active generation to cut over".to_owned())
        })?;
        let candidate = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour("candidate generation is not approved".to_owned())
            })?;
        let (candidate_kernel_artifact, candidate_store_artifact) = candidate
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (prior_kernel_artifact, prior_store_artifact) = prior
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (candidate_kernel_path, candidate_store_path, candidate_config_path) =
            candidate.manifest.host_child_paths();
        let (prior_kernel_path, prior_store_path, prior_config_path) =
            prior.manifest.host_child_paths();
        let candidate_config_locator = PathBuf::from(candidate_config_path.as_str());
        let prior_config_locator = PathBuf::from(prior_config_path.as_str());
        let result = self.jobs.cutover_with_rollback(
            candidate_kernel.as_ref(),
            candidate_store.as_ref(),
            prior_kernel.as_ref(),
            prior_store.as_ref(),
            &candidate.manifest.generation,
            &candidate.manifest.config_digest,
            &candidate_config_locator,
            candidate_kernel_path,
            candidate_store_path,
            candidate_config_path,
            candidate_kernel_artifact,
            candidate_store_artifact,
            &prior.manifest.generation,
            &prior.manifest.config_digest,
            &prior_config_locator,
            prior_kernel_path,
            prior_store_path,
            prior_config_path,
            prior_kernel_artifact,
            prior_store_artifact,
            &candidate.manifest.runtime_launch,
            &prior.manifest.runtime_launch,
            &self.host,
        );
        let launch = match result {
            Ok(launch) => launch,
            Err(error) => {
                persist_pending_recovery(
                    &self.registry_store,
                    &mut self.registry,
                    &host_capability,
                    &pending,
                    &error.to_string(),
                )?;
                return Err(error);
            }
        };
        if let Err(error) = self.fail_current_kernel_record("kernel-cutover-prior-terminated") {
            let cleanup = self.cleanup_launched_contour(error);
            persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                &host_capability,
                &pending,
                "prior Kernel termination evidence failed",
            )?;
            return cleanup;
        }

        let launched_generation = launch
            .activation_generation(&candidate.manifest.generation, &prior.manifest.generation);
        if launched_generation == &prior.manifest.generation {
            let CutoverLaunchOutcome::Rollback { candidate_error } = &launch else {
                return Err(HostError::OwnerLeaseRecovery(
                    "cutover launch target discriminator was inconsistent".to_owned(),
                ));
            };
            if let Err(error) = self.activate_launched_kernel(
                &prior.manifest.generation,
                prior
                    .manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch,
            ) {
                return self.cleanup_launched_contour(HostError::RecoveryRequired(format!(
                    "candidate launch failed ({candidate_error}); rollback activation failed ({error})"
                )));
            }
            if let Err(error) = persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                &host_capability,
                &pending,
                candidate_error,
            ) {
                return self.cleanup_active_kernel_contour(error, "rollback-registry-save-failed");
            }
            if let Err(error) = self.persist_process_observations(&prior.manifest.generation) {
                return self
                    .cleanup_active_kernel_contour(error, "rollback-process-observation-failed");
            }
            return Err(HostError::ProcessContour(format!(
                "candidate rejected; prior approved contour durably reactivated: {candidate_error}"
            )));
        }

        if let Err(candidate_error) = self.activate_launched_kernel(
            &candidate.manifest.generation,
            candidate
                .manifest
                .runtime_launch
                .authority_state_fence
                .authority_epoch,
        ) {
            self.jobs.terminate_store_then_kernel()?;
            self.jobs.start_approved(
                prior_kernel.as_ref(),
                prior_store.as_ref(),
                &prior.manifest.generation,
                &prior.manifest.config_digest,
                &prior_config_locator,
                prior_kernel_path,
                prior_store_path,
                prior_config_path,
                prior_kernel_artifact,
                prior_store_artifact,
                &self.host,
                &prior.manifest.runtime_launch,
            )?;
            if let Err(rollback_error) = self.activate_launched_kernel(
                &prior.manifest.generation,
                prior
                    .manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch,
            ) {
                return self.cleanup_launched_contour(HostError::RecoveryRequired(format!(
                    "candidate activation failed ({candidate_error}); rollback activation failed ({rollback_error})"
                )));
            }
            let reason = candidate_error.to_string();
            if let Err(error) = persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                &host_capability,
                &pending,
                &reason,
            ) {
                return self.cleanup_active_kernel_contour(error, "rollback-registry-save-failed");
            }
            if let Err(error) = self.persist_process_observations(&prior.manifest.generation) {
                return self
                    .cleanup_active_kernel_contour(error, "rollback-process-observation-failed");
            }
            return Err(HostError::ProcessContour(format!(
                "candidate activation failed; prior approved contour durably reactivated: {candidate_error}"
            )));
        }

        if let Err(error) = self.persist_process_observations(&candidate.manifest.generation) {
            let reason = error.to_string();
            let cleanup =
                self.cleanup_active_kernel_contour(error, "candidate-process-observation-failed");
            persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                &host_capability,
                &pending,
                &reason,
            )?;
            cleanup
        } else {
            self.commit_pending_durable(&pending, &host_capability)?;
            Ok(())
        }
    }

    /// Runs one liveness-only SCM tick against the retained process handles.
    ///
    /// This path observes only Job/process liveness and rederives the exact
    /// readiness identity from in-memory approved bindings plus the journal
    /// service's in-memory snapshot projection.  It never restarts a branch,
    /// rehashes a file, opens the Kernel pipe, or performs durable journal I/O.
    ///
    /// # Errors
    ///
    /// Returns an error only when Host admission itself is fenced.
    #[cfg(windows)]
    pub fn liveness_tick(&mut self) -> Result<HostLivenessTick, HostError> {
        self.ensure_admission_open()?;
        let liveness = self.jobs.liveness_only();
        let active_manifest = self.registry.active().map(|active| &active.manifest);
        let mut readiness_gate = std::mem::take(&mut self.readiness_gate);
        let tick = descriptor_bound_liveness_tick(
            &mut readiness_gate,
            liveness,
            active_manifest,
            |generation, kernel, store, config| {
                self.current_readiness_contour(generation, kernel, store, config)
            },
            std::time::Instant::now(),
        );
        self.readiness_gate = readiness_gate;
        Ok(tick)
    }

    /// Reconciles the approved contour and records fresh process observations.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, approved material cannot be
    /// revalidated, or branch reconciliation/activation fails.  Authoritative
    /// readiness failures return [`HostBranchDisposition::ReadinessDegraded`]
    /// while preserving the independently recoverable process contour.
    #[cfg(windows)]
    #[allow(clippy::too_many_lines, reason = "ordered branch reconciliation")]
    pub fn reconcile_approved_contour(&mut self) -> Result<HostBranchDisposition, HostError> {
        self.ensure_admission_open()?;
        let active =
            self.registry.active().cloned().ok_or_else(|| {
                HostError::ProcessContour("no approved active generation".to_owned())
            })?;
        let (kernel_artifact, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            active.manifest.host_child_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        let materialized_config_digest = self.jobs.config_digest.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "approved reconciliation has no Phase-B materialized config".to_owned(),
            )
        })?;
        let live_launch = self.jobs.launch.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "approved reconciliation has no Phase-B live launch".to_owned(),
            )
        })?;
        let kernel_requires_activation = matches!(
            HostJobBranches::branch_state(self.jobs.kernel.as_ref()),
            Ok(BranchLiveness::Dead)
        );
        let store_requires_restart = matches!(
            HostJobBranches::branch_state(self.jobs.store.as_ref()),
            Ok(BranchLiveness::Dead)
        );
        if kernel_requires_activation || store_requires_restart {
            self.readiness_gate.branch_degraded();
        }
        if kernel_requires_activation {
            let current = self.journal.snapshot()?.kernel.ok_or_else(|| {
                HostError::OwnerLeaseRecovery(
                    "dead Kernel branch has no durable Kernel record".to_owned(),
                )
            })?;
            DurableKernelActivationDriver::resume(&self.journal, current)
                .fail("kernel-process-observed-dead")?;
        }
        let reconciled = if store_requires_restart {
            None
        } else {
            Some(self.jobs.reconcile(
                &active.manifest.generation,
                &materialized_config_digest,
                &config_path,
                approved_kernel_path,
                approved_store_path,
                approved_config_path,
                kernel_artifact,
                store_artifact,
                &self.host,
            ))
        };
        // Re-observe after generic reconciliation.  A Store can die after
        // the outer liveness check and the generic guard; only this shared
        // route may turn that typed late-dead result into Store mutation.
        let kernel_live = matches!(
            HostJobBranches::branch_state(self.jobs.kernel.as_ref()),
            Ok(BranchLiveness::Live)
        );
        let request = self
            .scm_store_recovery_request(&active.manifest.generation, &materialized_config_digest)?;
        let route = route_scm_store_recovery(
            ScmStoreRecoveryObservation {
                store_requires_restart,
                kernel_live,
                kernel_requires_activation,
                store_present: self.jobs.store.is_some(),
            },
            reconciled,
            &request,
            |request| self.execute_store_recovery(request).map(|_| ()),
        )?;
        let disposition = match route {
            ScmStoreRecoveryRoute::Recovered => {
                return Ok(self.reconcile_branch_readiness_at(
                    &active.manifest.generation,
                    kernel_artifact,
                    store_artifact,
                    &materialized_config_digest,
                    HostBranchDisposition::LiveAwaitingReadiness,
                    std::time::Instant::now(),
                ));
            }
            ScmStoreRecoveryRoute::Fenced(disposition) => {
                if let Err(error) = self
                    .persist_degraded_process_observation(&active.manifest.generation, disposition)
                {
                    self.readiness_gate.fail(
                        None,
                        readiness_failure_kind(&error),
                        std::time::Instant::now(),
                    );
                    return Ok(HostBranchDisposition::ReadinessDegraded);
                }
                return Ok(disposition);
            }
            ScmStoreRecoveryRoute::Continue(disposition) => disposition,
        };
        if kernel_requires_activation && self.jobs.kernel.is_some() {
            let (prior_kernel, kernel_generation, kernel_authority_epoch) = self
                .next_kernel_activation_context(
                    live_launch.authority_state_fence.authority_epoch,
                    None,
                )?;
            if let Err(error) = self.jobs.complete_kernel_control(
                &active.manifest.generation,
                &self.host,
                &self.journal,
                &self.activation_id,
                &self.activation_generation,
                prior_kernel,
                kernel_generation,
                kernel_authority_epoch,
            ) {
                let cleanup = self.jobs.terminate_kernel();
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => HostError::RecoveryRequired(format!(
                        "Kernel restart activation failed ({error}); Kernel cleanup failed ({cleanup})"
                    )),
                });
            }
        }
        Ok(self.reconcile_branch_readiness_at(
            &active.manifest.generation,
            kernel_artifact,
            store_artifact,
            &materialized_config_digest,
            disposition,
            std::time::Instant::now(),
        ))
    }

    #[cfg(windows)]
    fn reconcile_branch_readiness_at(
        &mut self,
        generation: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        config: &PlatformHandle,
        disposition: HostBranchDisposition,
        now: std::time::Instant,
    ) -> HostBranchDisposition {
        if disposition != HostBranchDisposition::LiveAwaitingReadiness {
            self.readiness_gate.branch_degraded();
            if let Err(error) = self.persist_degraded_process_observation(generation, disposition) {
                self.readiness_gate
                    .fail(None, readiness_failure_kind(&error), now);
                return HostBranchDisposition::ReadinessDegraded;
            }
            return disposition;
        }
        let contour =
            self.current_readiness_contour(generation, kernel_artifact, store_artifact, config);
        let mut readiness_gate = std::mem::take(&mut self.readiness_gate);
        let outcome = reconcile_authenticated_readiness(&mut readiness_gate, contour, now, || {
            self.persist_fresh_authenticated_readiness(generation)
        });
        self.readiness_gate = readiness_gate;
        outcome
    }

    /// Returns whether either approved process branch or its bounded recovery
    /// record remains present for reconciliation.
    #[cfg(windows)]
    #[must_use]
    pub fn has_process_contour(&self) -> bool {
        self.jobs.has_recorded_contour()
    }

    #[cfg(windows)]
    fn persist_process_observations(
        &mut self,
        generation: &PlatformHandle,
    ) -> Result<(), HostError> {
        let now = std::time::Instant::now();
        let contour = self.persist_fresh_authenticated_readiness(generation)?;
        if !self.readiness_gate.grant(contour, now) {
            return Err(HostError::ProcessContour(
                "journaled readiness contour has no Store proof fence".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "readiness contour validates the retained Kernel, Store, semantic-config, Job, and journal identities as one fence"
    )]
    fn current_readiness_contour(
        &self,
        generation: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        config: &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError> {
        if self.jobs.approved_generation.as_ref() != Some(generation)
            || self.jobs.kernel_artifact_digest.as_ref() != Some(kernel_artifact)
            || self.jobs.store_artifact_digest.as_ref() != Some(store_artifact)
            || self.jobs.config_digest.as_ref() != Some(config)
        {
            return Err(HostError::ProcessContour(
                "retained readiness contour is not the approved active generation".to_owned(),
            ));
        }
        let candidate = self.jobs.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        let requirement = self
            .jobs
            .store_bootstrap_requirement
            .as_ref()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "retained Store bootstrap requirement is missing".to_owned(),
                )
            })?;
        requirement
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let semantic_config_hash =
            self.jobs
                .store_config_semantic_hash
                .as_ref()
                .ok_or_else(|| {
                    HostError::ProcessContour(
                        "retained Store semantic config hash is missing".to_owned(),
                    )
                })?;
        if candidate.artifact_hash != *kernel_artifact
            || candidate.config_hash != *config
            || requirement.approved_artifact_hash != *store_artifact
            || requirement.approved_config_hash != *semantic_config_hash
            || requirement.state_fence.authority_epoch != candidate.kernel_epoch
        {
            return Err(HostError::ProcessContour(
                "retained readiness authority or artifact binding is stale".to_owned(),
            ));
        }
        self.jobs.validate_running_kernel_candidate(candidate)?;
        let candidate_job = &candidate.job_binding;
        let state = self.journal.snapshot()?;
        let active = state.kernel.as_ref().ok_or_else(|| {
            HostError::ProcessContour("readiness contour has no Kernel record".to_owned())
        })?;
        let active_process = active.process.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel process binding is absent".to_owned())
        })?;
        let active_job = active.candidate_job_binding.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel Job binding is absent".to_owned())
        })?;
        if active.state != KernelActivationState::Active
            || active.one_time_nonce.state() != NonceState::Consumed
            || active.activation_identity != candidate.activation_id
            || active.approved_artifact_hash != *kernel_artifact
            || active.active_pipe_identity.as_ref() != Some(&candidate.pipe_identity)
            || active_process.authority_epoch != candidate.kernel_epoch
            || active_process.process_id
                != format!(
                    "pid:{}:start:{}",
                    candidate_job.root.process.process_id,
                    candidate_job.root.process.start_time_100ns
                )
            || active_job.job_name.as_str() != candidate_job.job.name
            || active_job.root_pid != candidate_job.root.process.process_id
            || active_job.root_start_time_100ns != candidate_job.root.process.start_time_100ns
            || active_job.root_image_path.as_str() != candidate_job.root.process.image_path
            || active_job.root_volume_serial_number
                != candidate_job.root.executable.volume_serial_number
            || active_job.root_file_index != candidate_job.root.executable.file_index
        {
            return Err(HostError::ProcessContour(
                "durable Kernel is not the retained Active+Consumed contour".to_owned(),
            ));
        }
        let active_kernel_record_checksum =
            PlatformHandle::new(record_checksum(&HostStateRecord::Kernel(active.clone()))?)
                .map_err(|error| HostError::Platform(error.to_string()))?;
        let candidate_binding_digest = PlatformHandle::new(
            candidate
                .compute_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        )
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let store_requirement_digest = PlatformHandle::new(sha256_json(requirement)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let registry_generation = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness generation is absent from the durable registry".to_owned(),
                )
            })?;
        let registry_authority = self
            .registry
            .provisioned_supervision_authority_for_generation(generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness generation has no durable provisioned supervision authority"
                        .to_owned(),
                )
            })?;
        let launch_authority = self
            .jobs
            .launch
            .as_ref()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness contour has no retained Phase-B launch overlay".to_owned(),
                )
            })?
            .provisioned_supervision_authority()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if launch_authority != registry_authority {
            return Err(HostError::ProcessContour(
                "retained Phase-B launch authority differs from durable registry authority"
                    .to_owned(),
            ));
        }
        let template = registry_authority
            .watchdog_admission_template()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let current_supervision = read_manifest_current_supervision_lease(
            &registry_generation.manifest,
            &candidate.supervision_incarnation.supervision_lease_id,
        )?;
        let supervision_identity =
            supervision_publication_identity(&template, &current_supervision)?;
        let expected_publication_path = self.launch_options.host_state_root().join(format!(
            "{WATCHDOG_PUBLICATION_DIRECTORY_PREFIX}{}",
            current_supervision.receipt.receipt_sha256
        ));
        let publication_is_exact = observe_host_watchdog_publication(&expected_publication_path)
            .and_then(|observed| {
                verify_exact_current_watchdog_publication(
                    &observed,
                    &template,
                    &current_supervision,
                )
            })
            .is_ok();
        let store_proof_fence = state.readiness_observations.last().and_then(|observation| {
            (readiness_supervision_fence_matches(
                &supervision_identity,
                publication_is_exact,
                &observation.evidence_refs,
            ) && observation.active_kernel_record_checksum == active_kernel_record_checksum
                && observation.fence == active.fence
                && observation.kernel_process.process_id == active_process.process_id
                && observation.kernel_job == *active_job
                && observation.config_digest == *config
                && observation.authority_epoch == candidate.kernel_epoch.value())
            .then(|| observation.store_fence.clone())
        });
        Ok(ReadinessContourIdentity {
            approved_generation: generation.clone(),
            approved_kernel_artifact: kernel_artifact.clone(),
            approved_store_artifact: store_artifact.clone(),
            approved_config: config.clone(),
            active_kernel_record_checksum,
            candidate_binding_digest,
            store_requirement_digest,
            store_proof_fence,
            supervision_lease_id: Some(supervision_identity.lease_id),
            supervision_ors_receipt_digest: Some(supervision_identity.ors_receipt_digest),
            watchdog_publication_digest: Some(supervision_identity.publication_digest),
        })
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "fresh readiness keeps probe, exact supervision publication, final ORS fence, journal append, and readback in causal order"
    )]
    fn persist_fresh_authenticated_readiness(
        &mut self,
        generation: &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError> {
        // A pending candidate is approved but intentionally not active until
        // this fresh proof crosses the registry CAS.  Resolve the exact
        // generation from the registry projection rather than treating the
        // active pointer as readiness authority.
        let active = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness probe generation is not present in the approved registry".to_owned(),
                )
            })?;
        let (kernel_artifact, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let materialized_config_digest = self.jobs.config_digest.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "readiness probe has no materialized Store config digest".to_owned(),
            )
        })?;
        let contour = self.current_readiness_contour(
            generation,
            kernel_artifact,
            store_artifact,
            materialized_config_digest,
        )?;
        let proof = self.jobs.probe_kernel_readiness(
            generation,
            kernel_artifact,
            store_artifact,
            materialized_config_digest,
        )?;
        let registry_authority = self
            .registry
            .provisioned_supervision_authority_for_generation(generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness generation has no durable provisioned supervision authority"
                        .to_owned(),
                )
            })?;
        let launch_authority = self
            .jobs
            .launch
            .as_ref()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness contour has no retained Phase-B launch overlay".to_owned(),
                )
            })?
            .provisioned_supervision_authority()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if launch_authority != &registry_authority {
            return Err(HostError::ProcessContour(
                "retained Phase-B launch authority differs from durable registry authority"
                    .to_owned(),
            ));
        }
        let watchdog_template = registry_authority
            .watchdog_admission_template()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let published_supervision = publish_current_watchdog_supervision_bundle(
            self.launch_options.host_state_root(),
            &active.manifest,
            &watchdog_template,
            &registry_authority.watchdog_admission_template_digest,
            &proof.supervision_lease,
        )?;
        require_exact_supervision_head(&proof.supervision_lease, || {
            read_manifest_current_supervision_lease(
                &active.manifest,
                proof.supervision_lease.record.lease_id.as_str(),
            )
        })?;
        append_authenticated_kernel_readiness(
            &self.journal,
            &proof,
            kernel_artifact,
            materialized_config_digest,
            &published_supervision,
        )?;
        let confirmed = self.current_readiness_contour(
            generation,
            kernel_artifact,
            store_artifact,
            materialized_config_digest,
        )?;
        if !confirmed.same_probe_input_contour(&contour)
            || confirmed.store_proof_fence.as_ref() != Some(&proof.store_fence)
            || confirmed.supervision_lease_id.as_ref() != Some(&published_supervision.lease_id)
            || confirmed.supervision_ors_receipt_digest.as_ref()
                != Some(&published_supervision.ors_receipt_digest)
            || confirmed.watchdog_publication_digest.as_ref()
                != Some(&published_supervision.publication_digest)
        {
            return Err(HostError::ProcessContour(
                "readiness contour changed while admitting the proof".to_owned(),
            ));
        }
        Ok(confirmed)
    }

    #[cfg(windows)]
    fn persist_degraded_process_observation(
        &mut self,
        generation: &PlatformHandle,
        disposition: HostBranchDisposition,
    ) -> Result<(), HostError> {
        debug_assert_ne!(
            disposition,
            HostBranchDisposition::LiveAwaitingReadiness,
            "degraded observations cannot admit readiness"
        );
        let state = self.journal.snapshot()?;
        let activation = state.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let observation_id = fresh_identity("host-branch-observation")?;
        self.append_record(HostStateRecord::Observation(HostObservationRecord {
            fence: activation.fence,
            operation: operation("host-process-observation")?,
            observation: ObservationRecordEnvelope {
                record_id: observation_id.as_str().to_owned(),
                kind: ObservationRecordKind::CoverageGap,
                event: None,
                coverage_gap: Some(CoverageGap {
                    gap_id: observation_id.as_str().to_owned(),
                    obligation_profile_ref: "runtime-live-v3-readiness".to_owned(),
                    reason_ref: "host-branch-degraded".to_owned(),
                    affected_interval: None,
                    disposition: GapDisposition::BlockDependentTransition,
                    protected: true,
                    evidence_refs: vec![generation.as_str().to_owned()],
                }),
                journal_control_event: false,
                parent_record_id: None,
            },
            binding_evidence_refs: vec![generation.clone()],
        }))?;
        Ok(())
    }

    #[cfg(windows)]
    /// Returns whether a durable degraded-branch recovery fence is active.
    ///
    /// # Errors
    ///
    /// Returns an error if the durable Host state cannot be loaded.
    pub fn has_durable_branch_fence(&self) -> Result<bool, HostError> {
        let state = self.snapshot()?;
        Ok(self.store_recovery_startup_fence.is_fenced()
            || self.pending_record.is_some()
            || state.activation.as_ref().is_some_and(|activation| {
                matches!(
                    activation.state,
                    ActivationState::Failed | ActivationState::DegradedRecovery
                )
            }))
    }

    #[cfg(windows)]
    fn cleanup_active_kernel_contour(
        &mut self,
        error: HostError,
        evidence: &str,
    ) -> Result<(), HostError> {
        let durable = self
            .journal
            .snapshot()
            .map_err(HostError::Journal)
            .and_then(|state| {
                let current = state.kernel.ok_or_else(|| {
                    HostError::OwnerLeaseRecovery(
                        "active Kernel cleanup has no durable Kernel record".to_owned(),
                    )
                })?;
                DurableKernelActivationDriver::resume(&self.journal, current).fail(evidence)
            });
        finish_active_kernel_cleanup(durable, || self.cleanup_launched_contour(error))
    }

    #[cfg(windows)]
    fn cleanup_launched_contour(&mut self, error: HostError) -> Result<(), HostError> {
        let store = self.jobs.terminate_store();
        let kernel = self.jobs.terminate_kernel();
        match (kernel, store) {
            (Ok(()), Ok(())) => {
                self.jobs.clear_recorded_contour();
                Err(error)
            }
            (kernel, store) => Err(HostError::RecoveryRequired(format!(
                "persistence failed ({error}); launched contour cleanup requires recovery: kernel={kernel:?}, store={store:?}"
            ))),
        }
    }

    fn ensure_admission_open(&self) -> Result<(), HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        #[cfg(windows)]
        if self.store_recovery_startup_fence.is_fenced() {
            return Err(HostError::OwnerLeaseRecovery(
                "crashed Store recovery fence blocks fresh admission".to_owned(),
            ));
        }
        if self.pending_record.is_some() || self.shutdown_failed {
            return Err(HostError::OwnerLeaseRecovery(
                "durable Host release/recovery is still pending".to_owned(),
            ));
        }
        Ok(())
    }

    /// Requests a bounded Host stop. SCM owns the sibling Watchdog and is not
    /// represented by either Host Job Object branch.
    ///
    /// # Errors
    ///
    /// Returns an error if the Host is already stopped or if process
    /// termination, durable shutdown finalization, or owner-lease release fails.
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered durable drain, process termination, clean-marker commit, and lease-release sequence is one security-critical transaction"
    )]
    pub fn stop(&mut self) -> Result<(), HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        #[cfg(windows)]
        if self.store_recovery_startup_fence.is_fenced() {
            self.readiness_gate.branch_degraded();
            self.shutdown_failed = true;
            return Err(HostError::RecoveryRequired(
                "crashed Store recovery remains Unknown; clean shutdown cannot erase its fence"
                    .to_owned(),
            ));
        }
        self.resume_pending_record()?;
        if !self.durable_finalized {
            let state = self.journal.snapshot()?;
            let activation = state.activation.clone().ok_or_else(|| {
                HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
            })?;
            match activation.state {
                ActivationState::Stopped => {}
                ActivationState::Active => {
                    let drain_generation = activation.fence.activation_generation.clone();
                    if state.drain.is_none() {
                        self.append_record(HostStateRecord::Drain(DrainRecord {
                            fence: activation.fence.clone(),
                            operation: operation("host-drain-request")?,
                            drain_generation: drain_generation.clone(),
                            state: DrainState::Requested,
                            evidence_refs: vec![
                                PlatformHandle::new("scm-stop-request")
                                    .map_err(|error| HostError::Platform(error.to_string()))?,
                            ],
                        }))?;
                    }
                    if self
                        .journal
                        .snapshot()?
                        .drain
                        .as_ref()
                        .is_some_and(|drain| drain.state == DrainState::Requested)
                    {
                        self.append_record(HostStateRecord::Drain(DrainRecord {
                            fence: activation.fence.clone(),
                            operation: operation("host-drain-start")?,
                            drain_generation: drain_generation.clone(),
                            state: DrainState::Draining,
                            evidence_refs: vec![
                                PlatformHandle::new("host-admission-closed")
                                    .map_err(|error| HostError::Platform(error.to_string()))?,
                            ],
                        }))?;
                    }
                    if self
                        .journal
                        .snapshot()?
                        .activation
                        .as_ref()
                        .is_some_and(|current| current.state == ActivationState::Active)
                    {
                        self.transition_activation(ActivationState::Draining, "host-draining")?;
                    }
                    if self.journal.snapshot()?.drain_commit.is_none() {
                        self.append_record(HostStateRecord::DrainCommit(DrainCommitRecord {
                            fence: activation.fence.clone(),
                            operation: operation("host-drain-commit")?,
                            drain_generation,
                            last_admission_closed_at: fresh_identity("host-admission-closed-at")?,
                            lease_and_pending_operation_snapshot: Vec::new(),
                            authority_epochs_fenced: vec![activation.lineage.kernel_epoch.clone()],
                            processes_modules_and_store_branches_to_stop: vec![
                                PlatformHandle::new("canonical-store-branch")
                                    .map_err(|error| HostError::Platform(error.to_string()))?,
                                PlatformHandle::new("kernel-branch")
                                    .map_err(|error| HostError::Platform(error.to_string()))?,
                            ],
                            wake_during_drain_disposition: WakeDisposition::QueueNextGeneration,
                            irreversible_stage: PlatformHandle::new("authority-fenced")
                                .map_err(|error| HostError::Platform(error.to_string()))?,
                            recovery_owner: PlatformHandle::new("host-composition")
                                .map_err(|error| HostError::Platform(error.to_string()))?,
                            committed_at: fresh_identity("host-drain-committed-at")?,
                        }))?;
                    }
                }
                ActivationState::Draining if state.drain_commit.is_some() => {}
                other => {
                    return Err(HostError::OwnerLeaseRecovery(format!(
                        "Host activation {other:?} cannot enter clean shutdown"
                    )));
                }
            }
            #[cfg(windows)]
            {
                let store = self.jobs.terminate_store();
                let kernel = self.jobs.terminate_kernel();
                if store.is_err() || kernel.is_err() {
                    self.shutdown_failed = true;
                    return Err(HostError::RecoveryRequired(format!(
                        "Store-first stop requires recovery: store={store:?}; kernel={kernel:?}"
                    )));
                }
            }
            if self
                .journal
                .snapshot()?
                .activation
                .as_ref()
                .is_some_and(|current| current.state == ActivationState::Draining)
            {
                self.transition_activation(ActivationState::StoppedClean, "host-stopped-clean")?;
            }
            #[cfg(windows)]
            cleanup_completed_store_recovery_supporting_evidence(
                self.launch_options.host_state_root(),
            )?;
            let state = self.journal.snapshot()?;
            let marker = clean_marker_record(
                &state,
                &self.host,
                &self.activation_id,
                &self.activation_generation,
            )?;
            self.append_record(marker)?;
            self.durable_finalized = true;
        }
        if !self.owner_released {
            if let Err(error) = self
                .owner_lease
                .release()
                .map_err(owner_lease_release_error)
            {
                self.shutdown_failed = true;
                return Err(error);
            }
            self.owner_released = true;
        }
        self.running = false;
        self.shutdown_failed = false;
        Ok(())
    }

    #[must_use]
    pub const fn running(&self) -> bool {
        self.running
    }

    /// Returns whether a prior shutdown attempt recorded a release/recovery
    /// failure. A stopped composition with this flag is not a clean success.
    #[must_use]
    pub const fn shutdown_failed(&self) -> bool {
        self.shutdown_failed
    }

    #[cfg(windows)]
    /// Returns the physical Host job branches for service composition.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn jobs(&self) -> &HostJobBranches {
        &self.jobs
    }
}

#[cfg(windows)]
impl ApprovedHostStartupPort for HostComposition {
    fn start_approved_manifest(
        &mut self,
        manifest: &CandidateManifest,
        branch: HostStartupBranch,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        store_artifact: &PlatformHandle,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        debug_assert_eq!(
            matches!(branch, HostStartupBranch::Pending),
            pending.is_some()
        );
        self.start_manifest_contour(
            manifest,
            kernel_executable,
            store_bridge_executable,
            store_artifact,
            pending,
        )
    }
}

#[cfg(windows)]
fn lifecycle_context(
    host: &HostInstallationEpoch,
    operation: &str,
) -> Result<RequestMetadata, HostError> {
    let request_id = RequestId::new(format!(
        "host:{}:{}:{}:{}",
        host.epoch.current.lineage,
        host.epoch.current.sequence,
        operation,
        std::process::id()
    ))
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let authority_epoch = AuthorityEpoch::new(host.epoch.current.sequence)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(RequestMetadata {
        request_id,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("eliot-host")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        source_id: SourceId::new("eliot-host-service")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        state_fence: StateFence::new(authority_epoch, ResourceGeneration::genesis()),
        clock: ClockReading::default(),
    })
}

fn owner_lease_error(error: HostOwnerLeaseError) -> HostError {
    match error {
        HostOwnerLeaseError::LiveOwner => HostError::OwnerLeaseHeld,
        HostOwnerLeaseError::ExistingObject => HostError::OwnerLeaseRecovery(
            "a pre-existing Host owner object is untrusted; explicit recovery is required"
                .to_owned(),
        ),
        HostOwnerLeaseError::AbandonedOwner => HostError::OwnerLeaseRecovery(
            "the previous Host owner abandoned its mutex; inspect durable shutdown state before retrying"
                .to_owned(),
        ),
        HostOwnerLeaseError::OwnershipUncertain { win32_error } => HostError::OwnerLeaseRecovery(
            format!("Windows could not classify the owner mutex (Win32 error {win32_error})"),
        ),
        HostOwnerLeaseError::CreationFailed { win32_error } => HostError::Platform(format!(
            "Host owner mutex could not be created or opened (Win32 error {win32_error})"
        )),
        HostOwnerLeaseError::UnsupportedPlatform => HostError::Platform(
            "Host owner lease is unavailable on this platform; refusing Host admission".to_owned(),
        ),
    }
}

fn owner_lease_release_error(error: HostOwnerLeaseReleaseError) -> HostError {
    HostError::OwnerLeaseRecovery(format!(
        "owner release failed; durable recovery remains required: {error}"
    ))
}

#[cfg(test)]
fn test_provisioned_supervision_authority(
    installation_id: &str,
    candidate_generation: &str,
    authority_generation: ResourceGeneration,
) -> ProvisionedSupervisionAuthority {
    let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
        "eliot-kernel",
        "test-supervision-key",
        [0x39; 32],
    )
    .unwrap_or_else(|_| unreachable!());
    let trust_anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
        installation_id,
        "eliot-kernel",
        "test-supervision-key",
        signer.public_key().to_vec(),
    )
    .unwrap_or_else(|_| unreachable!());
    let key_reference = eliot_runtime_contracts::SupervisionSealedKeyReference::new(
        "test-supervision-authority.sealed",
        "S-1-5-80-1-2-3-4-5",
        eliot_runtime_contracts::SupervisionSealedKeyFileIdentity {
            canonical_path_digest: "1".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "2".repeat(64),
        },
        "3".repeat(64),
    )
    .unwrap_or_else(|_| unreachable!());
    ProvisionedSupervisionAuthority::new(
        "test-supervision-scope",
        candidate_generation,
        authority_generation,
        key_reference,
        trust_anchor,
    )
    .unwrap_or_else(|_| unreachable!())
}

#[cfg(all(test, windows))]
mod watchdog_service_tests;

#[cfg(test)]
mod journal_tests;

#[cfg(all(test, windows))]
mod tests;

impl From<io::Error> for HostError {
    fn from(error: io::Error) -> Self {
        Self::Platform(error.to_string())
    }
}
