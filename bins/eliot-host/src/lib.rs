//! Production Host composition root.
//!
//! Host is the outer Windows lifecycle owner. It opens the crash-safe Host
//! journal under the installation's durable data root, keeps approved
//! generations separate from semantic state, and owns independent Job Object
//! branches for Kernel and the canonical store dependency.

#![forbid(unsafe_code)]

mod credential_control;

pub use credential_control::HostCredentialControl;

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_host_state::{
    ActivationState, AppendReceipt, CleanMarker, DrainCommitRecord, DrainRecord, DrainState,
    EliotActivationRecord, EpochIdentity, EpochTransition, HostInstallationEpoch,
    HostKernelStoreLineage, HostObservationRecord, HostState, HostStateJournalService,
    HostStateRecord, IdempotencyIdentity, JOURNAL_VERSION, JournalBackend, JournalError,
    JournalManifest, KernelJobBinding, KernelReadinessObservationRecord, KernelRecord,
    LifecycleTimestamps, NonceState, OneTimeNonceState, PriorKernelDisposition, PriorKernelSource,
    ProductionHostStateJournal, ReadinessApprovedContour, ReadinessEvidence, ReconcileOutcome,
    RecordFence, RecoveryLineageEvidence, RedbJournalBackend, WakeDisposition, record_checksum,
};
use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, InstallationError, InstallationProfile,
    RedbInstallationRegistry, RuntimeLaunchDescriptor, verify_approved_path,
    verify_file_digest_with_lease, verify_file_digest_with_user_lease,
};
use eliot_kernel_service::{
    EliotdLaunchDescriptor, HostJobBinding, HostKernelCandidateBinding, HostProcessBinding,
    HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE, KernelActivationPermit,
    KernelActivationQuery, KernelActivationReceipt, KernelControlCommand, KernelControlRequest,
    KernelControlResponse, KernelReadyReceipt, KernelServiceState, RestartBudget,
    StoreBootstrapHandoff, StoreProcessBinding, control_request_frame,
    decode_control_response_frame,
};
use eliot_observation_contracts::{
    CoverageGap, GapDisposition, ObservationRecordEnvelope, ObservationRecordKind,
};
use eliot_platform::{
    PlatformHandle, PortOutcome, ServiceOperation, ServicePort, ServiceRequest, ServiceState,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_NAME, HostOwnerLease, HostOwnerLeaseError,
    HostOwnerLeaseReleaseError, ProtectedPathLease, ServiceAccount, ServiceRegistrationInspection,
    ServiceRegistrationRequest, ServiceStartMode, WindowsPlatform, fresh_kernel_activation_nonce,
};
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, KernelActivationState, ServiceProcessRecord, ServiceProcessState,
};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, PeerIdentity, TransportLimits};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = ELIOT_HOST_SERVICE_NAME;
pub const PROTOCOL_VERSION: &str = "eliot.host.v1";
pub const HOST_JOURNAL_RELATIVE_PATH: &str = "Eliot/host/host-state-journal.redb";

/// Exact launch authority supplied by the Runtime Live SCM registration.
///
/// `SystemService` Host startup is argv-bound.  The service must not recover any
/// of these values from ambient environment or current-directory state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostLaunchOptions {
    config_descriptor_path: PathBuf,
    config_descriptor_digest: PlatformHandle,
    installation: PlatformHandle,
    transaction_plan_generation: u64,
    registration_nonce: Option<PlatformHandle>,
}

impl HostLaunchOptions {
    /// Parses the canonical SCM argv after argv[0] (the service name).
    ///
    /// The four authority pairs must appear exactly once and in the order
    /// rendered by [`ServiceBootstrapArguments`].  The established optional
    /// registration nonce is accepted only as the final pair. That nonce is
    /// effect-scoped SCM readback evidence, not a Host admission binding; the
    /// approved manifest's four authority values remain independently required.
    /// All other flags and all substitutions are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the argv shape or a typed value is
    /// invalid.
    pub fn parse<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() != 8 && args.len() != 10 {
            return Err(Self::invalid_argv("expected exactly four authority pairs"));
        }
        let flag = |index: usize, expected: &str| {
            args.get(index)
                .and_then(|value| value.to_str())
                .is_some_and(|actual| actual == expected)
        };
        if !flag(0, "--config-descriptor")
            || !flag(2, "--config-descriptor-sha256")
            || !flag(4, "--installation-id")
            || !flag(6, "--tx-plan-generation")
        {
            return Err(Self::invalid_argv(
                "authority flags are missing, reordered, or substituted",
            ));
        }
        if args.len() == 10 && !flag(8, "--registration-nonce") {
            return Err(Self::invalid_argv("unknown or substituted trailing flag"));
        }

        let config_descriptor_path = PathBuf::from(&args[1]);
        if !config_descriptor_path.is_absolute()
            || config_descriptor_path.as_os_str().is_empty()
            || !valid_launch_os_path(config_descriptor_path.as_os_str())
        {
            return Err(Self::invalid_argv(
                "config descriptor path must be absolute and valid",
            ));
        }
        let config_descriptor_digest = parse_launch_text(&args[3], "config descriptor digest")?;
        if !valid_sha256_text(&config_descriptor_digest) {
            return Err(Self::invalid_argv(
                "config descriptor digest must be lowercase SHA-256",
            ));
        }
        let installation_value = parse_launch_text(&args[5], "installation id")?;
        if !valid_launch_identity(&installation_value) {
            return Err(Self::invalid_argv("installation id is invalid"));
        }
        let transaction_plan_generation =
            parse_launch_text(&args[7], "transaction plan generation")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| {
                    Self::invalid_argv("transaction plan generation must be non-zero")
                })?;
        let registration_nonce = if args.len() == 10 {
            let nonce = parse_launch_text(&args[9], "registration nonce")?;
            if !valid_sha256_text(&nonce) {
                return Err(Self::invalid_argv(
                    "registration nonce must be lowercase SHA-256",
                ));
            }
            Some(
                PlatformHandle::new(nonce)
                    .map_err(|error| Self::invalid_argv(&error.to_string()))?,
            )
        } else {
            None
        };
        let installation = PlatformHandle::new(installation_value)
            .map_err(|error| Self::invalid_argv(&error.to_string()))?;
        let config_descriptor_digest = PlatformHandle::new(config_descriptor_digest)
            .map_err(|error| Self::invalid_argv(&error.to_string()))?;
        Ok(Self {
            config_descriptor_path,
            config_descriptor_digest,
            installation,
            transaction_plan_generation,
            registration_nonce,
        })
    }

    /// Parses the mandatory argv contract for an installed `SystemService`.
    ///
    /// Installer service effects persist a registration nonce before SCM
    /// mutation, so a live SCM callback must include that final pair. The
    /// nonce remains effect-scoped readback evidence; the four manifest
    /// bindings below are still the Host admission authority.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the canonical argv is malformed or
    /// omits the required registration nonce.
    pub fn parse_system_service<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let options = Self::parse(args)?;
        if options.registration_nonce.is_none() {
            return Err(Self::invalid_argv(
                "SystemService requires the registration nonce pair",
            ));
        }
        Ok(options)
    }

    #[must_use]
    pub fn config_descriptor_path(&self) -> &Path {
        &self.config_descriptor_path
    }

    #[must_use]
    pub fn config_descriptor_digest(&self) -> &PlatformHandle {
        &self.config_descriptor_digest
    }

    #[must_use]
    pub const fn installation(&self) -> &PlatformHandle {
        &self.installation
    }

    #[must_use]
    pub const fn transaction_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    #[must_use]
    pub fn registration_nonce(&self) -> Option<&PlatformHandle> {
        self.registration_nonce.as_ref()
    }

    fn invalid_argv(reason: &str) -> HostError {
        HostError::Platform(format!("invalid Host launch argv: {reason}"))
    }
}

fn parse_launch_text(value: &OsString, field: &str) -> Result<String, HostError> {
    value
        .to_str()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| HostLaunchOptions::invalid_argv(&format!("{field} is not valid text")))
}

fn valid_launch_os_path(value: &std::ffi::OsStr) -> bool {
    value
        .to_str()
        .is_some_and(|value| !value.is_empty() && !value.chars().any(char::is_control))
}

fn valid_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || matches!(value, b'a'..=b'f'))
}

fn valid_launch_identity(value: &str) -> bool {
    !value.is_empty() && !value.contains('"') && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod launch_options_tests {
    use super::*;
    use eliot_platform_windows::ServiceBootstrapArguments;

    fn valid_bootstrap() -> ServiceBootstrapArguments {
        ServiceBootstrapArguments::new(
            std::env::temp_dir().join("eliot-authority.json"),
            "a".repeat(64),
            "installation-7",
            7,
            std::iter::empty::<String>(),
        )
        .and_then(|bootstrap| bootstrap.with_registration_nonce("b".repeat(64)))
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn valid_args() -> Vec<OsString> {
        valid_bootstrap()
            .argv()
            .into_iter()
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn launch_options_parse_exact_registration_contract() {
        let bootstrap = valid_bootstrap();
        let options =
            HostLaunchOptions::parse(bootstrap.argv()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            options.config_descriptor_path(),
            &std::env::temp_dir().join("eliot-authority.json")
        );
        assert_eq!(options.config_descriptor_digest().as_str(), "a".repeat(64));
        assert_eq!(options.installation().as_str(), "installation-7");
        assert_eq!(options.transaction_plan_generation(), 7);
        assert_eq!(
            options.registration_nonce().map(PlatformHandle::as_str),
            Some("b".repeat(64).as_str())
        );
    }

    #[test]
    fn launch_options_reject_missing_duplicate_reordered_unknown_and_substituted_args() {
        let mut missing = valid_args();
        missing.truncate(8);
        missing.remove(6);
        missing.remove(6);
        assert!(HostLaunchOptions::parse(missing).is_err());

        let mut duplicate = valid_args();
        duplicate[8] = OsString::from("--config-descriptor");
        assert!(HostLaunchOptions::parse(duplicate).is_err());

        let mut reordered = valid_args();
        reordered.swap(0, 2);
        reordered.swap(1, 3);
        assert!(HostLaunchOptions::parse(reordered).is_err());

        let mut unknown = valid_args();
        unknown[8] = OsString::from("--unknown");
        assert!(HostLaunchOptions::parse(unknown).is_err());

        let mut substituted = valid_args();
        substituted[1] = OsString::from("relative-authority.json");
        assert!(HostLaunchOptions::parse(substituted).is_err());
    }

    #[test]
    fn system_service_launch_options_require_registration_nonce() {
        let mut without_nonce = valid_args();
        without_nonce.truncate(8);
        assert!(HostLaunchOptions::parse(without_nonce.clone()).is_ok());
        assert!(HostLaunchOptions::parse_system_service(without_nonce).is_err());
        assert!(HostLaunchOptions::parse_system_service(valid_args()).is_ok());
    }
}

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
    SuspendedLaunchSpec, UserOwnedPathLease, UserOwnedRootLease, WindowsAdapterError,
    observe_named_pipe_peer_process,
};

#[cfg(windows)]
const KERNEL_BOOTSTRAP_ENVIRONMENT: [&str; 4] = [
    "ELIOT_KERNEL_CONTROL_PIPE",
    "ELIOT_HOST_PROCESS_ID",
    "ELIOT_HOST_PROCESS_START",
    "ELIOT_HOST_PROCESS_IMAGE",
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

/// The two physical process ownership branches controlled by Host.
#[cfg(windows)]
enum LaunchLease {
    Protected(ProtectedPathLease),
    Portable(UserOwnedPathLease),
}

#[cfg(windows)]
impl LaunchLease {
    fn path(&self) -> &Path {
        match self {
            Self::Protected(lease) => lease.path(),
            Self::Portable(lease) => lease.path(),
        }
    }

    fn verify(&self) -> Result<(), String> {
        match self {
            Self::Protected(lease) => lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| error.to_string()),
            Self::Portable(lease) => lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| error.to_string()),
        }
    }

    fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, String> {
        match self {
            Self::Protected(lease) => lease.read_bounded(limit).map_err(|error| error.to_string()),
            Self::Portable(lease) => lease.read_bounded(limit).map_err(|error| error.to_string()),
        }
    }
}

#[cfg(windows)]
fn approved_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
) -> Result<PathBuf, HostError> {
    if profile != InstallationProfile::PortableDev {
        return verify_approved_path(supplied, approved, "runtime.approved_locator")
            .map_err(|error| HostError::ProcessContour(error.to_string()));
    }
    if !supplied.is_absolute() {
        return Err(HostError::ProcessContour(
            "portable locator must be absolute".to_owned(),
        ));
    }
    let canonical_supplied = std::fs::canonicalize(supplied)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let canonical_approved = std::fs::canonicalize(Path::new(approved.as_str()))
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if canonical_supplied != canonical_approved {
        return Err(HostError::ProcessContour(
            "portable locator is not the approved canonical path".to_owned(),
        ));
    }
    // The retained portable root lease and every child path must stay in the
    // same declared DOS-path namespace. `std::fs::canonicalize` adds a
    // verbatim prefix on Windows, which would make the exact root-containment
    // proof reject an otherwise identical approved child.
    Ok(supplied.to_path_buf())
}

#[cfg(windows)]
fn open_launch_lease(
    profile: InstallationProfile,
    root: Option<&UserOwnedRootLease>,
    path: &Path,
) -> Result<LaunchLease, HostError> {
    match profile {
        InstallationProfile::PortableDev => {
            let root = root.ok_or_else(|| {
                HostError::ProcessContour("portable root lease is missing".to_owned())
            })?;
            Ok(LaunchLease::Portable(
                UserOwnedPathLease::open_existing(root, path)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            ))
        }
        InstallationProfile::SystemService | InstallationProfile::UserMode => {
            Ok(LaunchLease::Protected(
                ProtectedPathLease::open_existing_absolute(path)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            ))
        }
    }
}

#[cfg(windows)]
fn verify_launch_digest(
    lease: &LaunchLease,
    digest: &PlatformHandle,
    field: &str,
) -> Result<(), HostError> {
    let result = match lease {
        LaunchLease::Protected(lease) => verify_file_digest_with_lease(lease, digest, field),
        LaunchLease::Portable(lease) => verify_file_digest_with_user_lease(lease, digest, field),
    };
    result.map_err(|error| HostError::ProcessContour(error.to_string()))
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
    let actual = Sha256::digest(&bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor digest changed before launch".to_owned(),
        ));
    }
    let descriptor: EliotdLaunchDescriptor = serde_json::from_slice(&bytes).map_err(|error| {
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
struct DurableKernelActivationDriver<'a, B: JournalBackend> {
    journal: &'a HostStateJournalService<B>,
    current: KernelRecord,
    issued_permit: Option<KernelActivationPermit>,
}

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
impl<'a, B: JournalBackend> DurableKernelActivationDriver<'a, B> {
    fn resume(journal: &'a HostStateJournalService<B>, current: KernelRecord) -> Self {
        Self {
            journal,
            current,
            issued_permit: None,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable candidate record keeps every authority and mechanics binding explicit"
    )]
    fn bind_candidate(
        journal: &'a HostStateJournalService<B>,
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
        approved_artifact_hash: PlatformHandle,
        candidate_pipe_identity: PlatformHandle,
        candidate_job_binding: KernelJobBinding,
        prior_kernel_disposition: PriorKernelDisposition,
        kernel_generation: EpochTransition,
        process: ServiceProcessRecord,
    ) -> Result<Self, HostError> {
        let current = KernelRecord {
            fence: record_fence(host, activation_id, activation_generation),
            operation: operation("kernel-candidate-shadow")?,
            activation_identity: activation_id.clone(),
            approved_artifact_hash,
            active_pipe_identity: None,
            candidate_pipe_identity: Some(candidate_pipe_identity),
            candidate_job_binding: Some(candidate_job_binding),
            prior_kernel_disposition,
            kernel_generation,
            one_time_nonce: OneTimeNonceState::unissued(),
            state: KernelActivationState::ShadowNoAuthority,
            process: Some(process),
            readiness_evidence: Vec::new(),
            disposition_evidence: vec![
                PlatformHandle::new("candidate-process-job-bound")
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            ],
        };
        append_reconciled(journal, HostStateRecord::Kernel(current.clone()))?;
        Ok(Self {
            journal,
            current,
            issued_permit: None,
        })
    }

    fn transition(
        &mut self,
        state: KernelActivationState,
        label: &str,
        mutate: impl FnOnce(&mut KernelRecord) -> Result<(), HostError>,
    ) -> Result<AppendReceipt, HostError> {
        let mut next = self.current.clone();
        next.operation = operation(label)?;
        next.state = state;
        mutate(&mut next)?;
        let receipt = append_reconciled(self.journal, HostStateRecord::Kernel(next.clone()))?;
        self.current = next;
        Ok(receipt)
    }

    fn handoff_prepared(&mut self) -> Result<(), HostError> {
        self.transition(
            KernelActivationState::HandoffPrepared,
            "kernel-handoff-prepared",
            |_| Ok(()),
        )?;
        Ok(())
    }

    fn prior_disposition_committed(&mut self) -> Result<(), HostError> {
        self.transition(
            KernelActivationState::OldTerminated,
            "kernel-prior-disposition",
            |_| Ok(()),
        )?;
        Ok(())
    }

    fn issue_nonce(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
    ) -> Result<KernelActivationPermit, HostError> {
        if self.current.state != KernelActivationState::OldTerminated {
            return Err(HostError::ProcessContour(
                "activation nonce cannot be issued before prior disposition commit".to_owned(),
            ));
        }
        let nonce = fresh_kernel_activation_nonce()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let receipt = self.transition(
            KernelActivationState::NonceIssued,
            "kernel-nonce-issued",
            |next| {
                next.one_time_nonce = OneTimeNonceState::issued(nonce.clone());
                Ok(())
            },
        )?;
        let prior_kernel_disposition_digest = sha256_json(&self.current.prior_kernel_disposition)?;
        let permit = KernelActivationPermit {
            operation_id: self.current.operation.operation_id.clone(),
            candidate_binding_digest: candidate
                .compute_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            prior_kernel_disposition_digest,
            journal_transaction_id: receipt.transaction_id().clone(),
            journal_sequence: receipt.sequence(),
            generation,
            authority_epoch: candidate.kernel_epoch,
            activation_nonce: nonce,
        };
        permit
            .validate(candidate, generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.issued_permit = Some(permit.clone());
        Ok(permit)
    }

    fn activating(&mut self) -> Result<(), HostError> {
        if self.issued_permit.is_none() {
            return Err(HostError::ProcessContour(
                "Activate is forbidden before a committed NonceIssued receipt".to_owned(),
            ));
        }
        self.transition(
            KernelActivationState::Activating,
            "kernel-activating",
            |_| Ok(()),
        )?;
        Ok(())
    }

    fn active(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        activation_receipt: &KernelActivationReceipt,
        ready: &KernelReadyReceipt,
    ) -> Result<(), HostError> {
        let permit = self.issued_permit.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel is missing its issued permit".to_owned())
        })?;
        activation_receipt
            .validate(permit)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        ready
            .validate(candidate, activation_receipt)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.transition(KernelActivationState::Active, "kernel-active", |next| {
            next.active_pipe_identity = next.candidate_pipe_identity.clone();
            next.one_time_nonce = next.one_time_nonce.consume()?;
            let process = next.process.as_mut().ok_or_else(|| {
                HostError::ProcessContour("active Kernel process binding is absent".to_owned())
            })?;
            process.state = ServiceProcessState::Ready;
            process.health = ready.health;
            next.readiness_evidence.clone_from(&ready.evidence_refs);
            next.readiness_evidence.push(
                PlatformHandle::new(format!(
                    "kernel-activation-receipt:{}",
                    activation_receipt.operation_id.as_str()
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            );
            Ok(())
        })?;
        Ok(())
    }

    fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
        if self.current.state == KernelActivationState::Failed {
            return Ok(());
        }
        let evidence = PlatformHandle::new(evidence)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        self.transition(
            KernelActivationState::Failed,
            "kernel-activation-failed",
            |next| {
                next.one_time_nonce = nonce_after_activation_failure(&next.one_time_nonce)?;
                if next.one_time_nonce.state() != NonceState::Consumed {
                    next.active_pipe_identity = None;
                }
                next.readiness_evidence.clear();
                next.disposition_evidence.push(evidence);
                if let Some(process) = next.process.as_mut() {
                    process.state = ServiceProcessState::Failed;
                    process.health.liveness = HealthDimension::Unknown;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

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
    store_fence: PlatformHandle,
    peer_evidence: PlatformHandle,
}

#[cfg(windows)]
pub struct HostJobBranches {
    kernel: Option<RunningJobChild<PlatformHandle>>,
    store: Option<RunningJobChild<PlatformHandle>>,
    kernel_identity: JobObjectIdentity,
    store_identity: JobObjectIdentity,
    kernel_launch_binding: KernelLaunchBinding,
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
    approved_generation: Option<PlatformHandle>,
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
const DEFAULT_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(windows)]
const MIN_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_millis(250);
#[cfg(windows)]
const MAX_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadinessCadence(std::time::Duration);

#[cfg(windows)]
impl ReadinessCadence {
    fn bounded(interval: std::time::Duration) -> Result<Self, HostError> {
        if !(MIN_READINESS_CADENCE..=MAX_READINESS_CADENCE).contains(&interval) {
            return Err(HostError::ProcessContour(format!(
                "readiness cadence must be between {}ms and {}ms",
                MIN_READINESS_CADENCE.as_millis(),
                MAX_READINESS_CADENCE.as_millis()
            )));
        }
        Ok(Self(interval))
    }

    fn deadline(self, now: std::time::Instant) -> std::time::Instant {
        now.checked_add(self.0).unwrap_or(now)
    }
}

#[cfg(windows)]
impl Default for ReadinessCadence {
    fn default() -> Self {
        match Self::bounded(DEFAULT_READINESS_CADENCE) {
            Ok(cadence) => cadence,
            Err(_) => Self(DEFAULT_READINESS_CADENCE),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadinessContourIdentity {
    approved_generation: PlatformHandle,
    approved_kernel_artifact: PlatformHandle,
    approved_store_artifact: PlatformHandle,
    approved_config: PlatformHandle,
    active_kernel_record_checksum: PlatformHandle,
    candidate_binding_digest: PlatformHandle,
    store_requirement_digest: PlatformHandle,
    store_proof_fence: Option<PlatformHandle>,
}

#[cfg(windows)]
impl ReadinessContourIdentity {
    fn same_authority_contour(&self, other: &Self) -> bool {
        self.approved_generation == other.approved_generation
            && self.approved_kernel_artifact == other.approved_kernel_artifact
            && self.approved_store_artifact == other.approved_store_artifact
            && self.approved_config == other.approved_config
            && self.active_kernel_record_checksum == other.active_kernel_record_checksum
            && self.candidate_binding_digest == other.candidate_binding_digest
            && self.store_requirement_digest == other.store_requirement_digest
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessFailureKind {
    ContourUnavailable,
    ProbeRejected,
    DeliveryUnknown,
    JournalRejected,
    JournalOutcomeUnknown,
}

#[cfg(windows)]
fn readiness_failure_kind(error: &HostError) -> ReadinessFailureKind {
    match error {
        HostError::RecoveryRequired(_) => ReadinessFailureKind::DeliveryUnknown,
        HostError::Journal(JournalError::OutcomeUnknown { .. }) => {
            ReadinessFailureKind::JournalOutcomeUnknown
        }
        HostError::Journal(_) => ReadinessFailureKind::JournalRejected,
        HostError::ProcessContour(_)
        | HostError::State(_)
        | HostError::Installation(_)
        | HostError::Platform(_)
        | HostError::Stopped
        | HostError::MissingInstallation
        | HostError::StoreNotLive { .. }
        | HostError::OwnerLeaseHeld
        | HostError::OwnerLeaseRecovery(_) => ReadinessFailureKind::ProbeRejected,
    }
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ReadinessLease {
    contour: ReadinessContourIdentity,
    valid_until: std::time::Instant,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ReadinessRetry {
    contour: Option<ReadinessContourIdentity>,
    failure: ReadinessFailureKind,
    retry_at: std::time::Instant,
}

#[cfg(windows)]
#[derive(Debug, Default)]
struct HostReadinessGate {
    cadence: ReadinessCadence,
    lease: Option<ReadinessLease>,
    retry: Option<ReadinessRetry>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessGateAction {
    PreserveAuthenticatedHealth,
    ProbeDue,
    RetryPending(ReadinessFailureKind),
}

#[cfg(windows)]
impl HostReadinessGate {
    fn with_cadence(cadence: ReadinessCadence) -> Self {
        Self {
            cadence,
            lease: None,
            retry: None,
        }
    }

    fn action(
        &mut self,
        contour: Option<&ReadinessContourIdentity>,
        now: std::time::Instant,
    ) -> ReadinessGateAction {
        if self.lease.as_ref().is_some_and(|lease| {
            contour == Some(&lease.contour)
                && lease.contour.store_proof_fence.is_some()
                && now < lease.valid_until
        }) {
            return ReadinessGateAction::PreserveAuthenticatedHealth;
        }
        self.lease = None;
        if let Some(retry) = self
            .retry
            .as_ref()
            .filter(|retry| retry.contour.as_ref() == contour && now < retry.retry_at)
        {
            return ReadinessGateAction::RetryPending(retry.failure);
        }
        self.retry = None;
        ReadinessGateAction::ProbeDue
    }

    fn grant(&mut self, contour: ReadinessContourIdentity, now: std::time::Instant) -> bool {
        if contour.store_proof_fence.is_none() {
            self.lease = None;
            return false;
        }
        self.lease = Some(ReadinessLease {
            contour,
            valid_until: self.cadence.deadline(now),
        });
        self.retry = None;
        true
    }

    fn fail(
        &mut self,
        contour: Option<ReadinessContourIdentity>,
        failure: ReadinessFailureKind,
        now: std::time::Instant,
    ) {
        self.lease = None;
        self.retry = Some(ReadinessRetry {
            contour,
            failure,
            retry_at: self.cadence.deadline(now),
        });
    }

    fn branch_degraded(&mut self) {
        self.lease = None;
        self.retry = None;
    }

    #[cfg(test)]
    fn last_failure(&self) -> Option<ReadinessFailureKind> {
        self.retry.as_ref().map(|retry| retry.failure)
    }
}

#[cfg(windows)]
fn reconcile_authenticated_readiness(
    gate: &mut HostReadinessGate,
    contour: Result<ReadinessContourIdentity, HostError>,
    now: std::time::Instant,
    authenticate_and_journal: impl FnOnce() -> Result<ReadinessContourIdentity, HostError>,
) -> HostBranchDisposition {
    let contour = match contour {
        Ok(contour) => contour,
        Err(_error) => {
            gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
            return HostBranchDisposition::ReadinessDegraded;
        }
    };
    match gate.action(Some(&contour), now) {
        ReadinessGateAction::PreserveAuthenticatedHealth => HostBranchDisposition::Healthy,
        ReadinessGateAction::RetryPending(_failure) => HostBranchDisposition::ReadinessDegraded,
        ReadinessGateAction::ProbeDue => match authenticate_and_journal() {
            Ok(journaled_contour) => {
                if gate.grant(journaled_contour, now) {
                    HostBranchDisposition::Healthy
                } else {
                    gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
                    HostBranchDisposition::ReadinessDegraded
                }
            }
            Err(error) => {
                let failure = readiness_failure_kind(&error);
                gate.fail(Some(contour), failure, now);
                HostBranchDisposition::ReadinessDegraded
            }
        },
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
    reason = "Store restart must rebind and, when needed, restart Kernel in one ordered state machine"
)]
fn reconcile_state_machine<S, K, SO, KO, ST, KT, SL, KL>(
    state: &mut ReconciliationState<S, K>,
    mut observe_store: SO,
    mut observe_kernel: KO,
    mut terminate_store: ST,
    mut terminate_kernel: KT,
    mut launch_store: SL,
    mut launch_kernel: KL,
) -> HostBranchDisposition
where
    SO: FnMut(Option<&S>) -> ReconciliationObservation,
    KO: FnMut(Option<&K>) -> ReconciliationObservation,
    ST: FnMut(&mut Option<S>) -> Result<(), ()>,
    KT: FnMut(&mut Option<K>) -> Result<(), ()>,
    SL: FnMut() -> Result<S, ()>,
    KL: FnMut() -> Result<K, ()>,
{
    let kernel_observation = observe_kernel(state.kernel.as_ref());
    let store_observation = observe_store(state.store.as_ref());
    let kernel_dead = kernel_observation == ReconciliationObservation::Dead;
    let mut store_dead = store_observation == ReconciliationObservation::Dead;
    let mut kernel_degraded = kernel_observation == ReconciliationObservation::Unknown;
    let mut store_degraded = store_observation == ReconciliationObservation::Unknown;

    let both_dead = kernel_dead && store_dead;
    if both_dead {
        if store_degraded
            || terminate_store(&mut state.store).is_err()
            || state.store_restart_attempts >= 1
        {
            store_degraded = true;
        } else {
            state.store_restart_attempts += 1;
            if let Ok(store) = launch_store() {
                state.store = Some(store);
                if observe_store(state.store.as_ref()) != ReconciliationObservation::Live {
                    store_degraded = true;
                    if terminate_store(&mut state.store).is_err() {
                        store_degraded = true;
                    }
                } else if state.kernel.is_some() {
                    // A fresh Store process necessarily has a new PID/start
                    // binding. Restart Kernel before publishing a contour so
                    // its one-shot Store handoff cannot retain the old peer.
                    if terminate_kernel(&mut state.kernel).is_err()
                        || state.kernel_restart_attempts >= 1
                    {
                        kernel_degraded = true;
                    } else {
                        state.kernel_restart_attempts += 1;
                        if let Ok(kernel) = launch_kernel() {
                            state.kernel = Some(kernel);
                            if observe_kernel(state.kernel.as_ref())
                                != ReconciliationObservation::Live
                            {
                                kernel_degraded = true;
                                if terminate_kernel(&mut state.kernel).is_err() {
                                    kernel_degraded = true;
                                }
                            }
                        } else {
                            kernel_degraded = true;
                        }
                    }
                }
            } else {
                store_degraded = true;
            }
        }
        store_dead = state.store.is_none() || store_degraded;
    }

    if kernel_dead && !store_dead && !store_degraded && state.store.is_some() {
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

    if store_dead && !both_dead {
        if terminate_store(&mut state.store).is_err() || state.store_restart_attempts >= 1 {
            store_degraded = true;
        } else {
            state.store_restart_attempts += 1;
            if let Ok(store) = launch_store() {
                state.store = Some(store);
                if observe_store(state.store.as_ref()) != ReconciliationObservation::Live {
                    store_degraded = true;
                    if terminate_store(&mut state.store).is_err() {
                        store_degraded = true;
                    }
                } else if state.kernel.is_some() {
                    // Store peer identity is immutable for one Kernel
                    // lineage; a Store restart therefore requires a fresh
                    // Kernel handoff before the contour can be healthy.
                    if terminate_kernel(&mut state.kernel).is_err()
                        || state.kernel_restart_attempts >= 1
                    {
                        kernel_degraded = true;
                    } else {
                        state.kernel_restart_attempts += 1;
                        if let Ok(kernel) = launch_kernel() {
                            state.kernel = Some(kernel);
                            if observe_kernel(state.kernel.as_ref())
                                != ReconciliationObservation::Live
                            {
                                kernel_degraded = true;
                                if terminate_kernel(&mut state.kernel).is_err() {
                                    kernel_degraded = true;
                                }
                            }
                        } else {
                            kernel_degraded = true;
                        }
                    }
                }
            } else {
                store_degraded = true;
            }
        }
    }

    if state.kernel.is_none() {
        kernel_degraded = true;
    }
    if state.store.is_none() {
        store_degraded = true;
    }
    match (kernel_degraded, store_degraded) {
        (false, false) => HostBranchDisposition::LiveAwaitingReadiness,
        (true, false) => HostBranchDisposition::KernelDegraded,
        (false, true) => HostBranchDisposition::StoreDegraded,
        (true, true) => HostBranchDisposition::BothDegraded,
    }
}

#[cfg(windows)]
impl HostJobBranches {
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
            kernel_launch_binding,
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
            approved_generation: None,
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
        }
        environment
    }

    fn environment(
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        job_identity: &JobObjectIdentity,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
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
        self.kernel_launch_binding.validate_current()?;
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
        let candidate = HostKernelCandidateBinding {
            installation_id: host.installation.clone(),
            host_epoch: authority_epoch,
            kernel_epoch: kernel_authority_epoch,
            activation_id: activation_id.clone(),
            artifact_hash: kernel_artifact.clone(),
            config_hash: config_digest.clone(),
            job_object_id: PlatformHandle::new(kernel.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            pipe_identity: self.kernel_launch_binding.pipe_identity.clone(),
            host_process: self.kernel_launch_binding.host_process.clone(),
            job_binding,
            restart_budget: RestartBudget::new(3, 3)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
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
            let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let mut transport = NamedPipeTransport::connect_authenticated(
                KERNEL_CONTROL_PIPE,
                std::time::Duration::from_secs(5),
                &expectation,
            )
            .await
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
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
                transport = NamedPipeTransport::connect_authenticated(
                    KERNEL_CONTROL_PIPE,
                    std::time::Duration::from_secs(5),
                    &expectation,
                )
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
        Ok((activation_receipt, ready))
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
            let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let mut transport = NamedPipeTransport::connect_authenticated(
                candidate.pipe_identity.as_str(),
                std::time::Duration::from_secs(5),
                &expectation,
            )
            .await
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
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
            let store_fence = validated_store_proof_fence(
                requirement,
                &ready,
                approved_store_artifact,
                approved_config,
                request.generation,
            )?;
            Ok(AuthenticatedKernelReadiness {
                request,
                response,
                ready,
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
            config_digest,
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
                    Some(&self.kernel_launch_binding),
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
            Some(&self.kernel_launch_binding),
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

    /// Reconciles Kernel and store branches independently with one bounded
    /// restart attempt per branch failure. A failed branch never terminates a
    /// healthy sibling or reuses an observed PID.
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
            |store| {
                let Some(child) = store.as_mut() else {
                    return Ok(());
                };
                child
                    .terminate_in_place(0xE017_0002)
                    .map(|_| {
                        store.take();
                    })
                    .map_err(|_| ())
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
                self.relaunch_store(
                    generation,
                    config_digest,
                    config_path,
                    store_artifact,
                    approved_store_bridge_path,
                    approved_config_path,
                    host,
                )
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
        );
        self.store = state.store;
        self.kernel = state.kernel;
        self.store_restart_attempts = state.store_restart_attempts;
        self.kernel_restart_attempts = state.kernel_restart_attempts;
        Ok(disposition)
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
trait InstalledWatchdogControl {
    fn inspect_registration(
        &mut self,
        request: &ServiceRegistrationRequest,
    ) -> ServiceRegistrationInspection;

    fn start(
        &mut self,
        request: &ServiceRequest,
    ) -> PortOutcome<eliot_platform::ServiceObservation>;
}

#[cfg(windows)]
impl InstalledWatchdogControl for WindowsPlatform {
    fn inspect_registration(
        &mut self,
        request: &ServiceRegistrationRequest,
    ) -> ServiceRegistrationInspection {
        self.inspect_service_registration(request)
    }

    fn start(
        &mut self,
        request: &ServiceRequest,
    ) -> PortOutcome<eliot_platform::ServiceObservation> {
        debug_assert_eq!(request.operation, ServiceOperation::Start);
        self.execute(request)
    }
}

#[cfg(windows)]
fn start_installed_watchdog<C>(
    control: &mut C,
    registration: &ServiceRegistrationRequest,
    context: RequestMetadata,
) -> Result<(), HostError>
where
    C: InstalledWatchdogControl,
{
    match control.inspect_registration(registration) {
        ServiceRegistrationInspection::Matching { observation }
            if observation.state == ServiceState::Running =>
        {
            return Ok(());
        }
        ServiceRegistrationInspection::Matching { observation }
            if observation.state == ServiceState::Stopped => {}
        ServiceRegistrationInspection::Matching { observation } => {
            return Err(HostError::Platform(format!(
                "canonical Watchdog service is not startable from observed state {:?}",
                observation.state
            )));
        }
        ServiceRegistrationInspection::Absent => {
            return Err(HostError::Platform(
                "canonical Watchdog service is not installed".to_owned(),
            ));
        }
        ServiceRegistrationInspection::Mismatched => {
            return Err(HostError::Platform(
                "canonical Watchdog service registration does not match the approved plan"
                    .to_owned(),
            ));
        }
        ServiceRegistrationInspection::Unknown => {
            return Err(HostError::Platform(
                "canonical Watchdog service registration is not authoritatively observable"
                    .to_owned(),
            ));
        }
    }

    let service = PlatformHandle::new(ELIOT_WATCHDOG_SERVICE_NAME)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    match control.start(&ServiceRequest {
        context,
        service,
        operation: ServiceOperation::Start,
    }) {
        PortOutcome::Known(observation) if observation.state == ServiceState::Running => Ok(()),
        PortOutcome::Known(observation) => Err(HostError::Platform(format!(
            "Watchdog did not reach Known(Running): {:?}",
            observation.state
        ))),
        PortOutcome::Partial { value, .. } => Err(HostError::RecoveryRequired(format!(
            "Watchdog start observation is partial and state is {:?}",
            value.state
        ))),
        PortOutcome::Unknown(reason) => Err(HostError::RecoveryRequired(format!(
            "Watchdog SCM start outcome is unknown: {reason:?}"
        ))),
        PortOutcome::Error(error) => Err(HostError::Platform(error.to_string())),
    }
}

fn sha256_json(value: &impl serde::Serialize) -> Result<String, HostError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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

fn terminated_prior_kernel(prior: &KernelRecord) -> Result<PriorKernelDisposition, HostError> {
    let job = prior.candidate_job_binding.clone().ok_or_else(|| {
        HostError::OwnerLeaseRecovery("prior Kernel Job binding is absent".to_owned())
    })?;
    let mut process = prior.process.clone().ok_or_else(|| {
        HostError::OwnerLeaseRecovery("prior Kernel process binding is absent".to_owned())
    })?;
    process.state = ServiceProcessState::Stopped;
    process.health = HealthVector {
        liveness: HealthDimension::Unknown,
        readiness: HealthDimension::Unknown,
        freshness: HealthDimension::Unknown,
        compatibility: HealthDimension::Unknown,
        integrity: HealthDimension::Unknown,
        capacity: HealthDimension::Unknown,
    };
    Ok(PriorKernelDisposition::Terminated(PriorKernelSource {
        host: prior.fence.host.clone(),
        activation_identity: prior.activation_identity.clone(),
        generation: prior.kernel_generation.clone(),
        job,
        process,
        history_complete: true,
        job_empty: true,
        root_reaped: true,
    }))
}

fn initial_activation_record(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    state: ActivationState,
    label: &str,
) -> Result<EliotActivationRecord, HostError> {
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    let drain_generation = matches!(
        state,
        ActivationState::Draining | ActivationState::StoppedClean
    )
    .then(|| activation_generation.clone());
    Ok(EliotActivationRecord {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation(label)?,
        activation_id: activation_id.clone(),
        trigger_class: PlatformHandle::new("host-runtime-lifecycle")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        trigger_evidence: vec![
            PlatformHandle::new("host-owner-lease-held")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        requester_principal_session_or_scheduler: PlatformHandle::new("host-composition")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        requested_capabilities: vec![
            PlatformHandle::new("runtime-supervision")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        candidate_scope: host.installation.clone(),
        state,
        drain_generation,
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: EpochIdentity {
                lineage: fresh_identity("kernel-lineage")?,
                sequence: 1,
            },
            watchdog_epoch: EpochIdentity {
                lineage: fresh_identity("watchdog-lineage")?,
                sequence: 1,
            },
            store_generation: EpochIdentity {
                lineage: fresh_identity("store-lineage")?,
                sequence: 1,
            },
        },
        readiness: ReadinessEvidence {
            supervision_ready: ready,
            control_ready: ready,
            evidence_refs: vec![
                PlatformHandle::new(if ready {
                    "kernel-ready-receipt-validated"
                } else {
                    "host-lifecycle-not-ready"
                })
                .map_err(|error| HostError::Platform(error.to_string()))?,
            ],
        },
        governance_profile: PlatformHandle::new("runtime-live-v3")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        runtime_lease_refs: Vec::new(),
        supervision_lease_refs: Vec::new(),
        wake_intent_refs: Vec::new(),
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![
            PlatformHandle::new("host-process-epoch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        power_transition_evidence: Vec::new(),
        timestamps: LifecycleTimestamps {
            started_at: (state != ActivationState::Stopped)
                .then(|| fresh_identity("host-started-at"))
                .transpose()?,
            ready_at: ready.then(|| fresh_identity("host-ready-at")).transpose()?,
            draining_at: (state == ActivationState::Draining)
                .then(|| fresh_identity("host-draining-at"))
                .transpose()?,
            stopped_at: (state == ActivationState::StoppedClean)
                .then(|| fresh_identity("host-stopped-at"))
                .transpose()?,
        },
        failure_and_recovery_directive: None,
    })
}

fn transition_activation_record(
    current: &EliotActivationRecord,
    state: ActivationState,
    label: &str,
) -> Result<EliotActivationRecord, HostError> {
    let mut next = current.clone();
    next.operation = operation(label)?;
    next.state = state;
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    next.readiness.control_ready = ready;
    next.readiness.supervision_ready = ready;
    if ready {
        next.readiness.evidence_refs = vec![
            PlatformHandle::new("kernel-ready-receipt-validated")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        next.timestamps.ready_at = Some(fresh_identity("host-ready-at")?);
    }
    if state == ActivationState::Draining {
        next.drain_generation = Some(next.fence.activation_generation.clone());
        next.timestamps.draining_at = Some(fresh_identity("host-draining-at")?);
    }
    if state == ActivationState::StoppedClean {
        next.timestamps.stopped_at = Some(fresh_identity("host-stopped-at")?);
    }
    Ok(next)
}

fn append_reconciled<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    record: HostStateRecord,
) -> Result<AppendReceipt, HostError> {
    match journal.append(record.clone()) {
        Ok(receipt) => Ok(receipt),
        Err(JournalError::OutcomeUnknown { transaction_id }) => {
            match journal.reconcile(&transaction_id)? {
                ReconcileOutcome::Committed => journal.append(record).map_err(HostError::Journal),
                ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                    Err(HostError::Journal(JournalError::OutcomeUnknown {
                        transaction_id,
                    }))
                }
            }
        }
        Err(error) => Err(HostError::Journal(error)),
    }
}

fn append_reconciled_readiness<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    observation: KernelReadinessObservationRecord,
    expected: &ReadinessApprovedContour,
) -> Result<AppendReceipt, HostError> {
    match journal.append_readiness_observation(observation.clone(), expected) {
        Ok(receipt) => Ok(receipt),
        Err(JournalError::OutcomeUnknown { transaction_id }) => {
            match journal.reconcile(&transaction_id)? {
                ReconcileOutcome::Committed => journal
                    .append_readiness_observation(observation, expected)
                    .map_err(HostError::Journal),
                ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                    Err(HostError::Journal(JournalError::OutcomeUnknown {
                        transaction_id,
                    }))
                }
            }
        }
        Err(error) => Err(HostError::Journal(error)),
    }
}

#[cfg(windows)]
fn append_authenticated_kernel_readiness<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    proof: &AuthenticatedKernelReadiness,
    approved_kernel_artifact: &PlatformHandle,
    approved_config: &PlatformHandle,
) -> Result<AppendReceipt, HostError> {
    let snapshot = journal.snapshot()?;
    let active = snapshot.kernel.as_ref().ok_or_else(|| {
        HostError::ProcessContour("readiness admission has no active Kernel record".to_owned())
    })?;
    let active_process = active.process.as_ref().ok_or_else(|| {
        HostError::ProcessContour("active Kernel process binding is absent".to_owned())
    })?;
    let active_job = active.candidate_job_binding.as_ref().ok_or_else(|| {
        HostError::ProcessContour("active Kernel Job binding is absent".to_owned())
    })?;
    let candidate = &proof.request.candidate;
    let job = &candidate.job_binding;
    if active.state != KernelActivationState::Active
        || active.one_time_nonce.state() != NonceState::Consumed
        || candidate.installation_id != snapshot.host.installation
        || candidate.host_epoch.value() != snapshot.host.epoch.current.sequence
        || active.activation_identity != candidate.activation_id
        || active.approved_artifact_hash != *approved_kernel_artifact
        || candidate.artifact_hash != *approved_kernel_artifact
        || candidate.config_hash != *approved_config
        || active.active_pipe_identity.as_ref() != Some(&candidate.pipe_identity)
        || active_process.authority_epoch.value() != candidate.kernel_epoch.value()
        || active_process.process_id != proof.ready.process.process_id.as_str()
        || active_job.job_name.as_str() != job.job.name
        || active_job.root_pid != job.root.process.process_id
        || active_job.root_start_time_100ns != job.root.process.start_time_100ns
        || active_job.root_image_path.as_str() != job.root.process.image_path
        || active_job.root_volume_serial_number != job.root.executable.volume_serial_number
        || active_job.root_file_index != job.root.executable.file_index
    {
        return Err(HostError::ProcessContour(
            "Kernel readiness proof is not bound to the active journal contour".to_owned(),
        ));
    }
    let active_checksum = record_checksum(&HostStateRecord::Kernel(active.clone()))?;
    let response_digest = PlatformHandle::new(proof.response.payload_digest.clone())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let mut evidence_refs = proof.ready.evidence_refs.clone();
    evidence_refs.push(proof.peer_evidence.clone());
    evidence_refs.push(
        PlatformHandle::new(format!("kernel-response:{}", response_digest.as_str()))
            .map_err(|error| HostError::Platform(error.to_string()))?,
    );
    let expected = ReadinessApprovedContour {
        config_digest: approved_config.clone(),
        store_fence: proof.store_fence.clone(),
    };
    append_reconciled_readiness(
        journal,
        KernelReadinessObservationRecord {
            fence: active.fence.clone(),
            operation: operation("kernel-readiness-observation")?,
            active_kernel_record_checksum: PlatformHandle::new(active_checksum)
                .map_err(|error| HostError::Platform(error.to_string()))?,
            probe_request_digest: PlatformHandle::new(proof.request.payload_digest.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
            ready_receipt_digest: response_digest,
            kernel_process: ServiceProcessRecord {
                process_id: proof.ready.process.process_id.as_str().to_owned(),
                owner: active_process.owner.clone(),
                state: ServiceProcessState::Ready,
                health: proof.ready.health,
                authority_epoch: candidate.kernel_epoch,
            },
            kernel_job: active_job.clone(),
            config_digest: approved_config.clone(),
            authority_epoch: candidate.kernel_epoch.value(),
            store_fence: proof.store_fence.clone(),
            observed_at: fresh_identity("kernel-readiness-observed-at")?,
            evidence_refs,
        },
        &expected,
    )
}

fn clean_marker_record(
    snapshot: &HostState,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<HostStateRecord, HostError> {
    Ok(HostStateRecord::CleanMarker(CleanMarker {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation("host-clean-marker")?,
        manifest: JournalManifest {
            schema_version: JOURNAL_VERSION,
            last_sequence: snapshot.sequence,
            last_checksum: PlatformHandle::new(
                snapshot.last_checksum.as_deref().unwrap_or("GENESIS"),
            )
            .map_err(|error| HostError::Platform(error.to_string()))?,
        },
        shutdown_evidence_refs: vec![
            PlatformHandle::new("host-owner-release-fenced")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
    }))
}

#[cfg(test)]
fn append_clean_marker<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(), HostError> {
    let snapshot = journal.snapshot()?;
    append_reconciled(
        journal,
        clean_marker_record(&snapshot, host, activation_id, activation_generation)?,
    )?;
    Ok(())
}

/// Digest of the immutable installer identity that a fresh Host journal
/// activation must carry before it can be reconciled.  The journal does not
/// become an authority source: this binding is written into the new
/// Starting/ControlReady contour after a crash and never turns historical
/// Active evidence into live process proof.
fn pending_activation_binding(
    pending: &eliot_installation::PendingActivation,
) -> Result<PlatformHandle, HostError> {
    let digest = sha256_json(&(
        "pending-activation-binding-v1",
        &pending.transaction_id,
        &pending.plan_digest,
        &pending.manifest.generation,
        &pending.config_digest,
        &pending.kernel_artifact_digest,
        &pending.store_bridge_artifact_digest,
        &pending.canonical_store_artifact_digest,
        &pending.runtime_state_roots_digest,
        &pending.manifest_digest,
    ))?;
    PlatformHandle::new(format!("pending-activation-binding:{digest}"))
        .map_err(|error| HostError::Platform(error.to_string()))
}

fn reopen_existing_epoch<B: JournalBackend>(
    current: HostStateJournalService<B>,
    last_host: &HostInstallationEpoch,
    installation: &PlatformHandle,
    pending: Option<&eliot_installation::PendingActivation>,
) -> Result<
    (
        HostStateJournalService<B>,
        HostInstallationEpoch,
        EpochTransition,
    ),
    HostError,
> {
    if last_host.installation != *installation {
        return Err(HostError::OwnerLeaseRecovery(
            "Host journal installation identity does not match admission".to_owned(),
        ));
    }
    for pending in current.pending_transactions()? {
        match current.reconcile(&pending.transaction_id)? {
            ReconcileOutcome::Committed => {}
            ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id: pending.transaction_id,
                }));
            }
        }
    }
    let replayed = current.snapshot()?;
    if pending.is_none() && replayed.clean_marker.is_none() {
        return Err(HostError::OwnerLeaseRecovery(
            "current Host journal epoch is unclean; explicit new-lineage recovery is required"
                .to_owned(),
        ));
    }
    // Host-owned kill-on-close Jobs terminate their children when the prior
    // Host process dies.  Historical Active records therefore authorize only
    // a fresh direct-child recovery attempt, never a registry commit.
    let activation_generation = replayed
        .activation
        .as_ref()
        .map(|activation| activation.fence.activation_generation.direct_child())
        .transpose()?
        .unwrap_or(root_epoch(fresh_identity("activation-lineage")?));
    let host = child_host_epoch(last_host)?;
    let backend = current.into_backend()?;
    Ok((
        HostStateJournalService::from_backend(backend, host.clone())?,
        host,
        activation_generation,
    ))
}

fn persist_pending_recovery(
    registry_store: &RedbInstallationRegistry,
    registry: &mut ApprovedGenerationRegistry,
    host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    pending: &eliot_installation::PendingActivation,
    reason: &str,
) -> Result<(), HostError> {
    if let Err(mark_error) = registry.mark_pending_recovery(
        host_capability,
        &pending.transaction_id,
        &pending.plan_digest,
        reason,
    ) {
        return Err(HostError::RecoveryRequired(format!(
            "{reason}; durable recovery disposition failed: {mark_error}"
        )));
    }
    registry_store.save(registry).map_err(|save_error| {
        HostError::RecoveryRequired(format!(
            "{reason}; durable recovery disposition save failed: {save_error}"
        ))
    })
}

#[allow(clippy::too_many_lines)]
fn open_production_epoch(
    path: &Path,
    installation: PlatformHandle,
    pending: Option<&eliot_installation::PendingActivation>,
) -> Result<
    (
        ProductionHostStateJournal,
        HostInstallationEpoch,
        EpochTransition,
        PlatformHandle,
    ),
    HostError,
> {
    let inspection = RedbJournalBackend::inspect_existing(path).map_err(JournalError::Backend)?;
    let last_host = inspection
        .as_ref()
        .and_then(|value| value.image.epochs.last())
        .map(|epoch| epoch.host.clone());
    drop(inspection);

    let (journal, host, activation_generation) = if let Some(last_host) = last_host {
        let current = ProductionHostStateJournal::open(path, last_host.clone())?;
        let (journal, host, activation_generation) =
            reopen_existing_epoch(current, &last_host, &installation, pending)?;
        (journal, host, activation_generation)
    } else {
        let host = fresh_host_epoch(installation, None)?;
        (
            ProductionHostStateJournal::open(path, host.clone())?,
            host,
            root_epoch(fresh_identity("activation-lineage")?),
        )
    };
    let activation_id = fresh_identity("activation")?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Stopped,
            "host-open",
        )?),
    )?;
    Ok((journal, host, activation_generation, activation_id))
}

/// Host-owned lifecycle state and installation activation registry.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the lifecycle flags are independent durable shutdown and lease-release fences"
)]
pub struct HostComposition {
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
    owner_lease: HostOwnerLease,
    pending_record: Option<HostStateRecord>,
    durable_finalized: bool,
    owner_released: bool,
    shutdown_failed: bool,
}

impl HostComposition {
    fn validate_launch_options_for_manifest(
        options: &HostLaunchOptions,
        manifest: &CandidateManifest,
    ) -> Result<(), HostError> {
        let launch = &manifest.runtime_launch;
        // The optional registration nonce belongs to the installer effect
        // receipt. It has no approved-generation field to bind here, so it is
        // deliberately excluded; none of the four Host authority fields may
        // be substituted by it.
        let manifest_descriptor_path = PathBuf::from(launch.authority_descriptor_path.as_str());
        if manifest_descriptor_path != options.config_descriptor_path
            || launch.authority_descriptor_digest != *options.config_descriptor_digest()
            || launch.installation_epoch.installation != *options.installation()
            || launch.authority_generation.value() != options.transaction_plan_generation()
        {
            return Err(HostError::ProcessContour(
                "SCM launch authority does not match the approved generation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_launch_options_for_registry(
        options: &HostLaunchOptions,
        registry: &ApprovedGenerationRegistry,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        if let Some(pending) = pending {
            return Self::validate_launch_options_for_manifest(options, &pending.manifest);
        }
        if let Some(active) = registry.active() {
            return Self::validate_launch_options_for_manifest(options, &active.manifest);
        }
        Err(HostError::ProcessContour(
            "SCM launch authority has no approved generation".to_owned(),
        ))
    }

    /// Opens the durable Host contour for one installation identity and
    /// advances its persisted epoch before any process admission.
    ///
    /// # Errors
    ///
    /// Returns an error if installation identity, owner-lease acquisition,
    /// durable admission, recovery state, or approved process startup fails.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the public constructor owns the installation identity while retaining its established API"
    )]
    pub fn open(
        path: impl AsRef<Path>,
        launch_options: HostLaunchOptions,
    ) -> Result<Self, HostError> {
        let path = path.as_ref();
        if launch_options.installation().as_str().trim().is_empty() {
            return Err(HostError::MissingInstallation);
        }
        let installation = launch_options.installation().clone();
        let owner_lease = HostOwnerLease::acquire(&installation).map_err(owner_lease_error)?;
        let registry_path = path.with_file_name("installation-registry.redb");
        let registry_store = RedbInstallationRegistry::open(registry_path)?;
        let mut registry = registry_store.load()?;
        let pending_for_reopen = registry.pending_activation().cloned();
        Self::validate_launch_options_for_registry(
            &launch_options,
            &registry,
            pending_for_reopen.as_ref(),
        )?;
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
        let (journal, host, activation_generation, activation_id) =
            open_production_epoch(path, installation, pending_for_reopen.as_ref())?;
        #[cfg(windows)]
        let jobs =
            HostJobBranches::new(&host).map_err(|error| HostError::Platform(error.to_string()))?;
        let mut composition = Self {
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
            owner_lease,
            pending_record: None,
            durable_finalized: false,
            owner_released: false,
            shutdown_failed: false,
        };
        #[cfg(windows)]
        if let Some(pending) = composition.registry.pending_activation().cloned() {
            composition.reconcile_pending_activation(&pending)?;
        } else if let Some(active) = composition.registry.active().cloned() {
            composition.start_approved_contour(
                PathBuf::from(active.manifest.kernel_executable_path.as_str()),
                PathBuf::from(active.manifest.canonical_store_executable_path.as_str()),
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
    pub fn credential_control(
        &self,
        host_state_root: std::path::PathBuf,
    ) -> Result<HostCredentialControl, HostError> {
        let capability = self
            .owner_lease
            .credential_mutation_capability()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        HostCredentialControl::new(self.host.clone(), host_state_root, capability)
            .map_err(HostError::Platform)
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
    fn request_watchdog(&self, launch: &RuntimeLaunchDescriptor) -> Result<(), HostError> {
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
        let registration = ServiceRegistrationRequest::new(
            ELIOT_WATCHDOG_SERVICE_NAME,
            "Eliot Watchdog",
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .map_err(|error| HostError::Platform(error.to_string()))?;
        start_installed_watchdog(
            &mut platform,
            &registration,
            lifecycle_context(&self.host, "watchdog-start")?,
        )
    }

    #[cfg(windows)]
    fn next_kernel_activation_context(
        &self,
        manifest_authority_epoch: AuthorityEpoch,
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
        Ok((terminated_prior_kernel(prior)?, generation, authority))
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
            self.next_kernel_activation_context(manifest_authority_epoch)?;
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
        self.start_manifest_contour(
            &active.manifest,
            kernel_executable.as_ref(),
            store_executable.as_ref(),
            None,
        )
    }

    #[cfg(windows)]
    fn start_manifest_contour(
        &mut self,
        manifest: &CandidateManifest,
        kernel_executable: &Path,
        store_executable: &Path,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        Self::validate_launch_options_for_manifest(&self.launch_options, manifest)?;
        if let Some(pending) = pending {
            let current = self.journal.snapshot()?.activation.ok_or_else(|| {
                HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
            })?;
            let mut next = transition_activation_record(
                &current,
                ActivationState::Starting,
                "host-start-pending",
            )?;
            next.trigger_evidence
                .push(pending_activation_binding(pending)?);
            self.append_record(HostStateRecord::Activation(next))?;
        } else {
            self.transition_activation(ActivationState::Starting, "host-start-approved")?;
        }
        self.request_watchdog(&manifest.runtime_launch)?;
        let (kernel_artifact, store_artifact) = manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            manifest.host_child_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        let (prior_kernel, kernel_generation, kernel_authority_epoch) = self
            .next_kernel_activation_context(
                manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch,
            )?;
        self.jobs.start_approved(
            kernel_executable,
            store_executable,
            &manifest.generation,
            &manifest.config_digest,
            &config_path,
            approved_kernel_path,
            approved_store_path,
            approved_config_path,
            kernel_artifact,
            store_artifact,
            &self.host,
            &manifest.runtime_launch,
        )?;
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
    fn reconcile_pending_activation(
        &mut self,
        pending: &eliot_installation::PendingActivation,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let host_capability = self.owner_lease.activation_capability();
        let pending = self.registry.claim_pending_activation(
            &host_capability,
            &pending.transaction_id,
            &pending.plan_digest,
            &pending.manifest.generation,
        )?;
        self.registry_store.save(&self.registry)?;
        if pending
            .manifest
            .runtime_launch
            .installation_epoch
            .installation
            != self.host.installation
        {
            let reason = "pending activation installation epoch is stale";
            persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                &host_capability,
                &pending,
                reason,
            )?;
            return Err(HostError::RecoveryRequired(reason.to_owned()));
        }
        let kernel = PathBuf::from(pending.manifest.kernel_executable_path.as_str());
        let store = PathBuf::from(pending.manifest.canonical_store_executable_path.as_str());
        if let Err(error) =
            self.start_manifest_contour(&pending.manifest, &kernel, &store, Some(&pending))
        {
            if pending.prior_active_generation.is_none() {
                self.registry.abort_pending_activation(
                    &host_capability,
                    &pending.transaction_id,
                    &pending.plan_digest,
                )?;
            } else {
                let reason = error.to_string();
                persist_pending_recovery(
                    &self.registry_store,
                    &mut self.registry,
                    &host_capability,
                    &pending,
                    &reason,
                )?;
            }
            if pending.prior_active_generation.is_none() {
                self.registry_store.save(&self.registry)?;
            }
            return Err(error);
        }
        self.commit_pending_durable(&pending, &host_capability)?;
        Ok(())
    }

    #[cfg(windows)]
    fn commit_pending_durable(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let before = self.registry.clone();
        self.registry.commit_pending_activation(
            host_capability,
            &pending.transaction_id,
            &pending.plan_digest,
            &pending.manifest.generation,
        )?;
        if let Err(error) = self.registry_store.save(&self.registry) {
            self.registry = before;
            let recovery_result = self.registry.mark_pending_recovery(
                host_capability,
                &pending.transaction_id,
                &pending.plan_digest,
                "activation commit outcome is unknown",
            );
            let durable_recovery =
                recovery_result.and_then(|()| self.registry_store.save(&self.registry));
            return match durable_recovery {
                Ok(()) => Err(error.into()),
                Err(recovery_error) => Err(HostError::RecoveryRequired(format!(
                    "activation commit outcome is unknown and recovery disposition could not be durably recorded: {recovery_error}"
                ))),
            };
        }
        Ok(())
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
        let disposition = self.jobs.reconcile(
            &active.manifest.generation,
            &active.manifest.config_digest,
            &config_path,
            approved_kernel_path,
            approved_store_path,
            approved_config_path,
            kernel_artifact,
            store_artifact,
            &self.host,
        )?;
        if kernel_requires_activation && self.jobs.kernel.is_some() {
            let (prior_kernel, kernel_generation, kernel_authority_epoch) = self
                .next_kernel_activation_context(
                    active
                        .manifest
                        .runtime_launch
                        .authority_state_fence
                        .authority_epoch,
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
            &active.manifest.config_digest,
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
        if candidate.artifact_hash != *kernel_artifact
            || candidate.config_hash != *config
            || requirement.approved_artifact_hash != *store_artifact
            || requirement.approved_config_hash != *config
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
        let store_proof_fence = state.readiness_observations.last().and_then(|observation| {
            (observation.active_kernel_record_checksum == active_kernel_record_checksum
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
        })
    }

    #[cfg(windows)]
    fn persist_fresh_authenticated_readiness(
        &mut self,
        generation: &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError> {
        let active =
            self.registry.active().cloned().ok_or_else(|| {
                HostError::ProcessContour("no approved active generation".to_owned())
            })?;
        if active.manifest.generation != *generation {
            return Err(HostError::ProcessContour(
                "readiness probe generation is not the approved active generation".to_owned(),
            ));
        }
        let (kernel_artifact, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let contour = self.current_readiness_contour(
            generation,
            kernel_artifact,
            store_artifact,
            &active.manifest.config_digest,
        )?;
        let proof = self.jobs.probe_kernel_readiness(
            generation,
            kernel_artifact,
            store_artifact,
            &active.manifest.config_digest,
        )?;
        append_authenticated_kernel_readiness(
            &self.journal,
            &proof,
            kernel_artifact,
            &active.manifest.config_digest,
        )?;
        let confirmed = self.current_readiness_contour(
            generation,
            kernel_artifact,
            store_artifact,
            &active.manifest.config_digest,
        )?;
        if !confirmed.same_authority_contour(&contour)
            || confirmed.store_proof_fence.as_ref() != Some(&proof.store_fence)
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
        Ok(self.pending_record.is_some()
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
    pub const fn jobs(&self) -> &HostJobBranches {
        &self.jobs
    }
}

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

#[cfg(all(test, windows))]
mod watchdog_service_tests {
    use super::*;

    struct FakeInstalledWatchdog {
        inspection: Option<ServiceRegistrationInspection>,
        start_outcome: Option<PortOutcome<eliot_platform::ServiceObservation>>,
        starts: usize,
    }

    impl InstalledWatchdogControl for FakeInstalledWatchdog {
        fn inspect_registration(
            &mut self,
            _request: &ServiceRegistrationRequest,
        ) -> ServiceRegistrationInspection {
            self.inspection.take().unwrap_or_else(|| unreachable!())
        }

        fn start(
            &mut self,
            _request: &ServiceRequest,
        ) -> PortOutcome<eliot_platform::ServiceObservation> {
            self.starts += 1;
            self.start_outcome.take().unwrap_or_else(|| unreachable!())
        }
    }

    fn registration() -> ServiceRegistrationRequest {
        ServiceRegistrationRequest::new(
            ELIOT_WATCHDOG_SERVICE_NAME,
            "Eliot Watchdog",
            std::env::current_exe().unwrap_or_else(|_| unreachable!()),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|_| unreachable!())
    }

    fn observation(state: ServiceState) -> eliot_platform::ServiceObservation {
        eliot_platform::ServiceObservation {
            service: PlatformHandle::new(ELIOT_WATCHDOG_SERVICE_NAME)
                .unwrap_or_else(|_| unreachable!()),
            state,
            generation: None,
            process: None,
        }
    }

    fn context() -> RequestMetadata {
        let host = fresh_host_epoch(
            PlatformHandle::new("installation:test").unwrap_or_else(|_| unreachable!()),
            None,
        )
        .unwrap_or_else(|_| unreachable!());
        lifecycle_context(&host, "watchdog-test").unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn host_watchdog_surface_contains_no_registration_mutation() {
        let source = include_str!("lib.rs");
        let registration_mutation = [".register_", "service("].concat();
        let registration_operation = ["ServiceOperation::", "Register"].concat();
        assert!(!source.contains(&registration_mutation));
        assert!(!source.contains(&registration_operation));
        assert_eq!(SERVICE_NAME, ELIOT_HOST_SERVICE_NAME);
    }

    #[test]
    fn absent_mismatched_or_unknown_registration_never_starts() {
        for inspection in [
            ServiceRegistrationInspection::Absent,
            ServiceRegistrationInspection::Mismatched,
            ServiceRegistrationInspection::Unknown,
        ] {
            let mut control = FakeInstalledWatchdog {
                inspection: Some(inspection),
                start_outcome: None,
                starts: 0,
            };

            assert!(start_installed_watchdog(&mut control, &registration(), context()).is_err());
            assert_eq!(control.starts, 0);
        }
    }

    #[test]
    fn partial_running_start_outcome_requires_recovery() {
        let mut control = FakeInstalledWatchdog {
            inspection: Some(ServiceRegistrationInspection::Matching {
                observation: observation(ServiceState::Stopped),
            }),
            start_outcome: Some(PortOutcome::Partial {
                value: observation(ServiceState::Running),
                missing: vec![
                    PlatformHandle::new("authority_bound_process_record")
                        .unwrap_or_else(|_| unreachable!()),
                ],
            }),
            starts: 0,
        };

        assert!(matches!(
            start_installed_watchdog(&mut control, &registration(), context()),
            Err(HostError::RecoveryRequired(_))
        ));
        assert_eq!(control.starts, 1);
    }

    #[test]
    fn exact_stopped_registration_accepts_only_known_running() {
        let mut control = FakeInstalledWatchdog {
            inspection: Some(ServiceRegistrationInspection::Matching {
                observation: observation(ServiceState::Stopped),
            }),
            start_outcome: Some(PortOutcome::Known(observation(ServiceState::Running))),
            starts: 0,
        };

        start_installed_watchdog(&mut control, &registration(), context())
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(control.starts, 1);
    }

    #[test]
    fn unknown_start_outcome_requires_recovery() {
        let mut control = FakeInstalledWatchdog {
            inspection: Some(ServiceRegistrationInspection::Matching {
                observation: observation(ServiceState::Stopped),
            }),
            start_outcome: Some(PortOutcome::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            )),
            starts: 0,
        };

        assert!(matches!(
            start_installed_watchdog(&mut control, &registration(), context()),
            Err(HostError::RecoveryRequired(_))
        ));
        assert_eq!(control.starts, 1);
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;
    use eliot_host_state::{
        BackendError, BackendReconcileState, DurableImage, FaultPoint, MemoryBackend,
        PreparedAppend,
    };
    #[cfg(windows)]
    use eliot_installation::{InstallationEpoch, RuntimeStateRoots};

    struct ImageBackend {
        image: DurableImage,
    }

    struct UnknownAppendBackend {
        image: DurableImage,
        prepared: Option<PreparedAppend>,
    }

    impl JournalBackend for UnknownAppendBackend {
        fn load(&mut self) -> Result<DurableImage, BackendError> {
            Ok(self.image.clone())
        }

        fn prepared_appends(&mut self) -> Result<Vec<PreparedAppend>, BackendError> {
            Ok(self.prepared.clone().into_iter().collect())
        }

        fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError> {
            self.prepared = Some(append.clone());
            Ok(())
        }

        fn append_prepared(
            &mut self,
            _transaction_id: &PlatformHandle,
            _bytes: &[u8],
        ) -> Result<(), BackendError> {
            Ok(())
        }

        fn flush(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
            Ok(())
        }

        fn sync(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
            Ok(())
        }

        fn commit(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
            Err(BackendError::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            ))
        }

        fn reconcile(
            &mut self,
            _transaction_id: &PlatformHandle,
        ) -> Result<BackendReconcileState, BackendError> {
            Ok(if self.prepared.is_some() {
                BackendReconcileState::Prepared
            } else {
                BackendReconcileState::Absent
            })
        }
    }

    impl JournalBackend for ImageBackend {
        fn load(&mut self) -> Result<DurableImage, BackendError> {
            Ok(self.image.clone())
        }

        fn prepared_appends(&mut self) -> Result<Vec<PreparedAppend>, BackendError> {
            Ok(Vec::new())
        }

        fn prepare(&mut self, _append: &PreparedAppend) -> Result<(), BackendError> {
            Err(BackendError::Unavailable)
        }

        fn append_prepared(
            &mut self,
            _transaction_id: &PlatformHandle,
            _bytes: &[u8],
        ) -> Result<(), BackendError> {
            Err(BackendError::Unavailable)
        }

        fn flush(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
            Err(BackendError::Unavailable)
        }

        fn sync(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
            Err(BackendError::Unavailable)
        }

        fn commit(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
            Err(BackendError::Unavailable)
        }

        fn reconcile(
            &mut self,
            _transaction_id: &PlatformHandle,
        ) -> Result<BackendReconcileState, BackendError> {
            Ok(BackendReconcileState::Absent)
        }
    }

    fn test_host() -> HostInstallationEpoch {
        fresh_host_epoch(
            PlatformHandle::new("test-installation").unwrap_or_else(|_| unreachable!()),
            None,
        )
        .unwrap_or_else(|_| unreachable!())
    }

    #[cfg(windows)]
    struct ReadinessFixture {
        journal: HostStateJournalService<MemoryBackend>,
        candidate: HostKernelCandidateBinding,
        activation: KernelActivationReceipt,
        requirement: HostStoreBootstrapRequirement,
        kernel_artifact: PlatformHandle,
        store_artifact: PlatformHandle,
        config: PlatformHandle,
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture establishes one complete durable activation contour for Host-level request/response/journal tests"
    )]
    fn active_readiness_fixture() -> ReadinessFixture {
        let host = test_host();
        let activation_generation =
            root_epoch(fresh_identity("readiness-activation-lineage").unwrap());
        let activation_id = fresh_identity("readiness-activation").unwrap();
        let journal =
            HostStateJournalService::from_backend(MemoryBackend::default(), host.clone()).unwrap();
        append_reconciled(
            &journal,
            HostStateRecord::Activation(
                initial_activation_record(
                    &host,
                    &activation_id,
                    &activation_generation,
                    ActivationState::Starting,
                    "readiness-starting",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let kernel_artifact = PlatformHandle::new("a".repeat(64)).unwrap();
        let store_artifact = PlatformHandle::new("b".repeat(64)).unwrap();
        let config = PlatformHandle::new("c".repeat(64)).unwrap();
        let job_name = PlatformHandle::new("Local\\Eliot-Host-Kernel-readiness").unwrap();
        let image = "C:\\eliot\\eliot-kernel.exe".to_owned();
        let candidate = HostKernelCandidateBinding {
            installation_id: host.installation.clone(),
            host_epoch: AuthorityEpoch::new(host.epoch.current.sequence).unwrap(),
            kernel_epoch: AuthorityEpoch::new(2).unwrap(),
            activation_id: activation_id.clone(),
            artifact_hash: kernel_artifact.clone(),
            config_hash: config.clone(),
            job_object_id: job_name.clone(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\eliot-host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: job_name.as_str().to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: image.clone(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            restart_budget: RestartBudget::new(1, 1).unwrap(),
            containment_action: None,
        };
        let durable_job = KernelJobBinding {
            job_name,
            owner: PlatformHandle::new("Kernel").unwrap(),
            root_pid: 42,
            root_start_time_100ns: 10,
            root_image_path: PlatformHandle::new(image).unwrap(),
            root_volume_serial_number: 1,
            root_file_index: 2,
        };
        let mut driver = DurableKernelActivationDriver::bind_candidate(
            &journal,
            &host,
            &activation_id,
            &activation_generation,
            kernel_artifact.clone(),
            candidate.pipe_identity.clone(),
            durable_job,
            PriorKernelDisposition::NoPriorKernel,
            root_epoch(fresh_identity("readiness-kernel-lineage").unwrap()),
            ServiceProcessRecord {
                process_id: "pid:42:start:10".to_owned(),
                owner: "Kernel".to_owned(),
                state: ServiceProcessState::Starting,
                health: HealthVector::healthy(),
                authority_epoch: candidate.kernel_epoch,
            },
        )
        .unwrap();
        driver.handoff_prepared().unwrap();
        driver.prior_disposition_committed().unwrap();
        let permit = driver
            .issue_nonce(&candidate, ResourceGeneration::genesis())
            .unwrap();
        driver.activating().unwrap();
        let activation = KernelActivationReceipt::issue(&permit);
        let initial_ready = KernelReadyReceipt {
            activation_id: activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("initial-process-proof").unwrap()],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("initial-ready-proof").unwrap()],
        };
        driver
            .active(&candidate, &activation, &initial_ready)
            .unwrap();
        drop(driver);
        let requirement = HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)
                .unwrap(),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-readiness")
                .unwrap(),
            store_generation: ResourceGeneration::genesis(),
            state_fence: StateFence::new(candidate.kernel_epoch, ResourceGeneration::genesis()),
            launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
            connection_id: PlatformHandle::new("store-connection").unwrap(),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
            expected_peer_session_id: 0,
            approved_artifact_hash: store_artifact.clone(),
            approved_config_hash: config.clone(),
            timeout_ms: 5_000,
        };
        ReadinessFixture {
            journal,
            candidate,
            activation,
            requirement,
            kernel_artifact,
            store_artifact,
            config,
        }
    }

    #[cfg(windows)]
    fn probe_exchange(
        fixture: &ReadinessFixture,
        validation_revision: u64,
    ) -> (
        KernelControlRequest,
        KernelControlResponse,
        KernelReadyReceipt,
    ) {
        let request = KernelControlRequest {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: fresh_identity("test-kernel-probe").unwrap(),
            sequence: 1,
            peer_process_id: 7,
            generation: ResourceGeneration::genesis(),
            candidate: fixture.candidate.clone(),
            command: KernelControlCommand::ProbeReady,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let mut evidence_refs = KernelReadyReceipt::probe_binding_evidence(&request).unwrap();
        evidence_refs.extend([
            PlatformHandle::new(format!("kernel-store-validation:{validation_revision}")).unwrap(),
            PlatformHandle::new("kernel-store-health:manifest-ready").unwrap(),
        ]);
        let ready = KernelReadyReceipt {
            activation_id: fixture.candidate.activation_id.clone(),
            activation_operation_id: fixture.activation.operation_id.clone(),
            activation_nonce_digest: fixture.activation.activation_nonce_digest.clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: fixture.candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("repeat-process-proof").unwrap()],
            },
            health: HealthVector::healthy(),
            evidence_refs,
        };
        let response = KernelControlResponse {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: request.message_id.clone(),
            request_digest: request.payload_digest.clone(),
            state: KernelServiceState::Ready,
            receipt: Some(ready.clone()),
            activation_receipt: None,
            error: None,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        (request, response, ready)
    }

    #[cfg(windows)]
    fn authenticated_proof(
        fixture: &ReadinessFixture,
        validation_revision: u64,
    ) -> AuthenticatedKernelReadiness {
        let (request, response, _ready) = probe_exchange(fixture, validation_revision);
        let ready = validate_probe_response(&request, &fixture.activation, &response).unwrap();
        let store_fence = validated_store_proof_fence(
            &fixture.requirement,
            &ready,
            &fixture.store_artifact,
            &fixture.config,
            request.generation,
        )
        .unwrap();
        AuthenticatedKernelReadiness {
            request,
            response,
            ready,
            store_fence,
            peer_evidence: PlatformHandle::new("kernel-peer:test-authenticated").unwrap(),
        }
    }

    #[cfg(windows)]
    fn readiness_contour(fixture: &ReadinessFixture) -> ReadinessContourIdentity {
        let state = fixture.journal.snapshot().unwrap();
        let active = state.kernel.unwrap();
        let active_kernel_record_checksum =
            PlatformHandle::new(record_checksum(&HostStateRecord::Kernel(active)).unwrap())
                .unwrap();
        let store_proof_fence = state
            .readiness_observations
            .last()
            .filter(|observation| {
                observation.active_kernel_record_checksum == active_kernel_record_checksum
            })
            .map(|observation| observation.store_fence.clone());
        ReadinessContourIdentity {
            approved_generation: PlatformHandle::new("approved-generation").unwrap(),
            approved_kernel_artifact: fixture.kernel_artifact.clone(),
            approved_store_artifact: fixture.store_artifact.clone(),
            approved_config: fixture.config.clone(),
            active_kernel_record_checksum,
            candidate_binding_digest: PlatformHandle::new(
                fixture.candidate.compute_digest().unwrap(),
            )
            .unwrap(),
            store_requirement_digest: PlatformHandle::new(
                sha256_json(&fixture.requirement).unwrap(),
            )
            .unwrap(),
            store_proof_fence,
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs one fully validated split Store launch descriptor for the production liveness boundary"
    )]
    fn liveness_manifest_with_distinct_store_digests() -> (CandidateManifest, std::path::PathBuf) {
        fn handle(value: impl Into<String>) -> PlatformHandle {
            PlatformHandle::new(value.into()).unwrap_or_else(|_| unreachable!())
        }

        fn path(root: &Path, name: &str) -> PlatformHandle {
            handle(root.join(name).to_string_lossy().into_owned())
        }

        #[derive(serde::Serialize)]
        struct UnsignedLaunch<'a> {
            profile: InstallationProfile,
            portable_root: &'a Option<PlatformHandle>,
            installation_epoch: &'a InstallationEpoch,
            generation: &'a PlatformHandle,
            authority_generation: ResourceGeneration,
            authority_state_fence: &'a StateFence,
            authority_descriptor_path: &'a PlatformHandle,
            authority_descriptor_digest: &'a PlatformHandle,
            runtime_state_roots: &'a RuntimeStateRoots,
            kernel_work_root: &'a PlatformHandle,
            kernel_artifact_digest: &'a PlatformHandle,
            eliotd_executable_path: &'a PlatformHandle,
            eliotd_artifact_digest: &'a PlatformHandle,
            eliotd_config_path: &'a PlatformHandle,
            eliotd_config_digest: &'a PlatformHandle,
            eliotd_descriptor_path: &'a PlatformHandle,
            eliotd_descriptor_digest: &'a PlatformHandle,
            eliotd_launch_nonce: &'a PlatformHandle,
            store_config_path: &'a PlatformHandle,
            store_credential_target: &'a PlatformHandle,
            store_bootstrap_descriptor_path: &'a PlatformHandle,
            store_bootstrap_descriptor_digest: &'a PlatformHandle,
            canonical_store_executable_path: &'a PlatformHandle,
            canonical_store_artifact_digest: &'a PlatformHandle,
            kernel_arguments: &'a [PlatformHandle],
            store_bridge_executable_path: &'a PlatformHandle,
            store_bridge_artifact_digest: &'a PlatformHandle,
            store_bridge_arguments: &'a [PlatformHandle],
            canonical_store_arguments: &'a [PlatformHandle],
            watchdog_executable_path: &'a PlatformHandle,
            watchdog_artifact_digest: &'a PlatformHandle,
        }

        let root = std::env::temp_dir().join(format!(
            "eliot-host-liveness-store-split-{}",
            Uuid::new_v4()
        ));
        let portable = root.join("portable");
        std::fs::create_dir_all(&portable).unwrap_or_else(|_| unreachable!());
        drop(
            UserOwnedRootLease::open_existing(&portable)
                .unwrap_or_else(|error| panic!("portable root lease: {error}")),
        );
        let portable_handle = handle(portable.to_string_lossy().into_owned());
        let runtime_state_roots = RuntimeStateRoots::derive_portable(portable_handle.clone())
            .unwrap_or_else(|error| panic!("portable roots: {error}"));
        let generation = handle("generation:liveness-store-split");
        let kernel_digest = handle("a".repeat(64));
        let bridge_digest = handle("b".repeat(64));
        let provider_digest = handle("d".repeat(64));
        let config_digest = handle("c".repeat(64));
        let config_path = path(&portable, "generation.json");
        let bootstrap_path = path(&portable, "store-bootstrap.json");
        let authority_path = path(&portable, "authority.json");
        let credential_target = handle("eliot/store/v1/0123456789abcdef0123456789abcdef");
        let bridge_path = path(&portable, "eliot-store-surreal.exe");
        let provider_path = path(&portable, "surreal.exe");
        let mut runtime_launch = RuntimeLaunchDescriptor {
            profile: InstallationProfile::PortableDev,
            portable_root: Some(portable_handle.clone()),
            installation_epoch: InstallationEpoch {
                installation: handle("installation:liveness-store-split"),
                lineage_id: handle("lineage:liveness-store-split"),
                sequence: 1,
            },
            generation: generation.clone(),
            authority_generation: ResourceGeneration::genesis(),
            authority_state_fence: StateFence::new(
                AuthorityEpoch::genesis(),
                ResourceGeneration::genesis(),
            ),
            authority_descriptor_path: authority_path.clone(),
            authority_descriptor_digest: handle("9".repeat(64)),
            runtime_state_roots: runtime_state_roots.clone(),
            kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
            kernel_artifact_digest: kernel_digest.clone(),
            eliotd_executable_path: path(&portable, "eliotd.exe"),
            eliotd_artifact_digest: handle("e".repeat(64)),
            eliotd_config_path: path(&portable, "eliotd-governor.json"),
            eliotd_config_digest: handle("2".repeat(64)),
            eliotd_descriptor_path: path(&portable, "eliotd.json"),
            eliotd_descriptor_digest: handle("f".repeat(64)),
            eliotd_launch_nonce: handle(format!("eliotd:{}", "1".repeat(32))),
            store_config_path: config_path.clone(),
            store_credential_target: credential_target,
            store_bridge_executable_path: bridge_path.clone(),
            store_bridge_artifact_digest: bridge_digest.clone(),
            store_bootstrap_descriptor_path: bootstrap_path.clone(),
            store_bootstrap_descriptor_digest: handle("8".repeat(64)),
            canonical_store_executable_path: provider_path.clone(),
            canonical_store_artifact_digest: provider_digest.clone(),
            kernel_arguments: vec![
                handle("--work-root"),
                runtime_state_roots.kernel_work_root.clone(),
                handle("--store-bootstrap"),
                bootstrap_path,
                handle("--store-bootstrap-sha256"),
                handle("8".repeat(64)),
                handle("--authority-descriptor"),
                authority_path,
                handle("--authority-descriptor-sha256"),
                handle("9".repeat(64)),
                handle("--kernel-artifact-sha256"),
                kernel_digest.clone(),
                handle("--eliotd-descriptor"),
                path(&portable, "eliotd.json"),
                handle("--eliotd-descriptor-sha256"),
                handle("f".repeat(64)),
            ],
            store_bridge_arguments: vec![
                handle("--portable-dev-root"),
                portable_handle,
                handle("--config"),
                config_path.clone(),
            ],
            canonical_store_arguments: vec![
                handle("start"),
                handle("--no-banner"),
                handle("--bind"),
                handle("127.0.0.1:8000"),
                handle("--temporary-directory"),
                runtime_state_roots.store_temp_root.clone(),
                handle("--log-file-enabled"),
                handle("--log-file-path"),
                runtime_state_roots.store_work_root.clone(),
                handle("--log-file-name"),
                handle("surrealdb.log"),
                handle(format!(
                    "surrealkv://{}",
                    runtime_state_roots
                        .store_data_root
                        .as_str()
                        .replace('\\', "/")
                )),
            ],
            watchdog_executable_path: path(&portable, "eliot-watchdog.exe"),
            watchdog_artifact_digest: handle("7".repeat(64)),
            descriptor_digest: handle("0".repeat(64)),
        };
        let unsigned = UnsignedLaunch {
            profile: runtime_launch.profile,
            portable_root: &runtime_launch.portable_root,
            installation_epoch: &runtime_launch.installation_epoch,
            generation: &runtime_launch.generation,
            authority_generation: runtime_launch.authority_generation,
            authority_state_fence: &runtime_launch.authority_state_fence,
            authority_descriptor_path: &runtime_launch.authority_descriptor_path,
            authority_descriptor_digest: &runtime_launch.authority_descriptor_digest,
            runtime_state_roots: &runtime_launch.runtime_state_roots,
            kernel_work_root: &runtime_launch.kernel_work_root,
            kernel_artifact_digest: &runtime_launch.kernel_artifact_digest,
            eliotd_executable_path: &runtime_launch.eliotd_executable_path,
            eliotd_artifact_digest: &runtime_launch.eliotd_artifact_digest,
            eliotd_config_path: &runtime_launch.eliotd_config_path,
            eliotd_config_digest: &runtime_launch.eliotd_config_digest,
            eliotd_descriptor_path: &runtime_launch.eliotd_descriptor_path,
            eliotd_descriptor_digest: &runtime_launch.eliotd_descriptor_digest,
            eliotd_launch_nonce: &runtime_launch.eliotd_launch_nonce,
            store_config_path: &runtime_launch.store_config_path,
            store_credential_target: &runtime_launch.store_credential_target,
            store_bootstrap_descriptor_path: &runtime_launch.store_bootstrap_descriptor_path,
            store_bootstrap_descriptor_digest: &runtime_launch.store_bootstrap_descriptor_digest,
            canonical_store_executable_path: &runtime_launch.canonical_store_executable_path,
            canonical_store_artifact_digest: &runtime_launch.canonical_store_artifact_digest,
            kernel_arguments: &runtime_launch.kernel_arguments,
            store_bridge_executable_path: &runtime_launch.store_bridge_executable_path,
            store_bridge_artifact_digest: &runtime_launch.store_bridge_artifact_digest,
            store_bridge_arguments: &runtime_launch.store_bridge_arguments,
            canonical_store_arguments: &runtime_launch.canonical_store_arguments,
            watchdog_executable_path: &runtime_launch.watchdog_executable_path,
            watchdog_artifact_digest: &runtime_launch.watchdog_artifact_digest,
        };
        let bytes = serde_json::to_vec(&unsigned).unwrap_or_else(|_| unreachable!());
        runtime_launch.descriptor_digest = handle(format!("{:x}", Sha256::digest(bytes)));
        let manifest = CandidateManifest {
            generation,
            components: vec![handle("component:kernel"), handle("component:store")],
            kernel_artifact_digest: kernel_digest,
            store_bridge_artifact_digest: bridge_digest,
            canonical_store_artifact_digest: provider_digest,
            kernel_executable_path: path(&portable, "eliot-kernel.exe"),
            store_bridge_executable_path: bridge_path,
            canonical_store_executable_path: provider_path,
            config_path,
            dependency_closure_refs: vec![handle("evidence:dependency-closure")],
            license_refs: vec![handle("evidence:licenses")],
            config_digest,
            store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            supervision_key_fingerprint: handle("6".repeat(64)),
            signature_ref: handle("evidence:signature"),
            runtime_state_roots_digest: runtime_state_roots.roots_digest.clone(),
            runtime_launch,
        };
        manifest
            .validate()
            .unwrap_or_else(|error| panic!("liveness manifest: {error}"));
        (manifest, root)
    }

    #[cfg(windows)]
    fn materialize_descriptor_bound_host_fixture(
        manifest: &mut CandidateManifest,
        host: &HostInstallationEpoch,
        descriptor_generation: ResourceGeneration,
    ) {
        fn write_digest(path: &Path, bytes: &[u8]) -> PlatformHandle {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("fixture parent");
            }
            std::fs::write(path, bytes).expect("fixture write");
            PlatformHandle::new(format!("{:x}", Sha256::digest(bytes))).expect("fixture digest")
        }

        let launch = &mut manifest.runtime_launch;
        for directory in [
            launch.runtime_state_roots.kernel_work_root.as_str(),
            launch.runtime_state_roots.store_work_root.as_str(),
        ] {
            std::fs::create_dir_all(directory).expect("fixture work root");
        }
        let kernel_digest = write_digest(
            Path::new(manifest.kernel_executable_path.as_str()),
            b"kernel-fixture",
        );
        let store_digest = write_digest(
            Path::new(manifest.store_bridge_executable_path.as_str()),
            b"store-fixture",
        );
        let store_config_digest = write_digest(
            Path::new(manifest.config_path.as_str()),
            b"store-config-fixture",
        );
        let eliotd_digest = write_digest(
            Path::new(launch.eliotd_executable_path.as_str()),
            b"eliotd-fixture",
        );
        let eliotd_config_digest = write_digest(
            Path::new(launch.eliotd_config_path.as_str()),
            b"governor-config-fixture",
        );
        manifest.kernel_artifact_digest = kernel_digest.clone();
        manifest.store_bridge_artifact_digest = store_digest.clone();
        manifest.config_digest = store_config_digest.clone();
        launch.kernel_artifact_digest = kernel_digest.clone();
        launch.store_bridge_artifact_digest = store_digest.clone();
        launch.eliotd_artifact_digest = eliotd_digest.clone();
        launch.eliotd_config_digest = eliotd_config_digest.clone();
        launch.kernel_arguments[11] = kernel_digest;

        let requirement = HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)
                .expect("store route"),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store")
                .expect("store pipe"),
            store_generation: launch.authority_generation,
            state_fence: launch.authority_state_fence.clone(),
            launch_nonce: host.host_process_nonce().as_handle().clone(),
            connection_id: PlatformHandle::new("host-descriptor-test-store").expect("connection"),
            expected_peer_sid: PlatformHandle::new("S-1-5-19").expect("peer sid"),
            expected_peer_session_id: 0,
            approved_artifact_hash: store_digest,
            approved_config_hash: store_config_digest,
            timeout_ms: 5_000,
        };
        let bootstrap_bytes = serde_json::to_vec(&requirement).expect("bootstrap bytes");
        let bootstrap_digest = write_digest(
            Path::new(launch.store_bootstrap_descriptor_path.as_str()),
            &bootstrap_bytes,
        );
        launch.store_bootstrap_descriptor_digest = bootstrap_digest.clone();
        launch.kernel_arguments[5] = bootstrap_digest;

        let nonce = launch.eliotd_launch_nonce.clone();
        let descriptor = EliotdLaunchDescriptor {
            wire_id: "eliot.kernel.eliotd-launch".to_owned(),
            wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
            executable: launch.eliotd_executable_path.clone(),
            executable_sha256: eliotd_digest.as_str().to_owned(),
            arguments: vec![
                PlatformHandle::new("--config-descriptor").expect("argument"),
                launch.eliotd_config_path.clone(),
                PlatformHandle::new("--config-descriptor-sha256").expect("argument"),
                eliotd_config_digest,
                PlatformHandle::new("--launch-nonce").expect("argument"),
                nonce.clone(),
                PlatformHandle::new("--executable-sha256").expect("argument"),
                eliotd_digest,
            ],
            working_directory: launch.kernel_work_root.clone(),
            config_descriptor: launch.eliotd_config_path.clone(),
            config_descriptor_sha256: launch.eliotd_config_digest.as_str().to_owned(),
            launch_nonce: nonce,
            authority_epoch: launch.authority_state_fence.authority_epoch,
            generation: descriptor_generation,
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("eliotd descriptor");
        let descriptor_bytes = serde_json::to_vec(&descriptor).expect("descriptor bytes");
        let descriptor_digest = write_digest(
            Path::new(launch.eliotd_descriptor_path.as_str()),
            &descriptor_bytes,
        );
        launch.eliotd_descriptor_digest = descriptor_digest.clone();
        launch.kernel_arguments[15] = descriptor_digest;
        launch.descriptor_digest =
            PlatformHandle::new(launch.compute_digest().expect("runtime launch digest"))
                .expect("runtime launch digest handle");
    }

    #[cfg(windows)]
    #[test]
    fn production_initial_and_relaunch_reject_descriptor_generation_substitution() {
        let host = test_host();
        let (mut manifest, root) = liveness_manifest_with_distinct_store_digests();
        let substituted_generation =
            ResourceGeneration::new(manifest.runtime_launch.authority_generation.value() + 1)
                .expect("substituted generation");
        materialize_descriptor_bound_host_fixture(&mut manifest, &host, substituted_generation);
        let config_path = PathBuf::from(manifest.config_path.as_str());
        let mut initial = HostJobBranches::new(&host).expect("initial branches");
        let initial_error = initial
            .start_approved(
                Path::new(manifest.kernel_executable_path.as_str()),
                Path::new(manifest.store_bridge_executable_path.as_str()),
                &manifest.generation,
                &manifest.config_digest,
                &config_path,
                &manifest.kernel_executable_path,
                &manifest.store_bridge_executable_path,
                &manifest.config_path,
                &manifest.kernel_artifact_digest,
                &manifest.store_bridge_artifact_digest,
                &host,
                &manifest.runtime_launch,
            )
            .expect_err("initial descriptor generation substitution must fail");
        assert!(
            initial_error
                .to_string()
                .contains("eliotd launch descriptor"),
            "unexpected initial validation error: {initial_error}"
        );
        assert!(initial.kernel.is_none());
        assert!(initial.store.is_none());

        let mut relaunch = HostJobBranches::new(&host).expect("relaunch branches");
        let portable_root = PathBuf::from(
            manifest
                .runtime_launch
                .portable_root
                .as_ref()
                .expect("portable root")
                .as_str(),
        );
        let portable_lease =
            UserOwnedRootLease::open_existing(&portable_root).expect("portable root lease");
        relaunch.kernel_executable = Some(PathBuf::from(manifest.kernel_executable_path.as_str()));
        relaunch.kernel_lease = Some(
            open_launch_lease(
                manifest.runtime_launch.profile,
                Some(&portable_lease),
                Path::new(manifest.kernel_executable_path.as_str()),
            )
            .expect("kernel lease"),
        );
        relaunch.config_lease = Some(
            open_launch_lease(
                manifest.runtime_launch.profile,
                Some(&portable_lease),
                &config_path,
            )
            .expect("config lease"),
        );
        relaunch.config_pin = Some(PinnedRuntimeFile::open(&config_path).expect("config pin"));
        relaunch.eliotd_config_lease = Some(
            open_launch_lease(
                manifest.runtime_launch.profile,
                Some(&portable_lease),
                Path::new(manifest.runtime_launch.eliotd_config_path.as_str()),
            )
            .expect("eliotd config lease"),
        );
        relaunch.eliotd_descriptor_lease = Some(
            open_launch_lease(
                manifest.runtime_launch.profile,
                Some(&portable_lease),
                Path::new(manifest.runtime_launch.eliotd_descriptor_path.as_str()),
            )
            .expect("eliotd descriptor lease"),
        );
        relaunch.portable_root = Some(portable_lease);
        relaunch.launch = Some(manifest.runtime_launch.clone());
        let Err(relaunch_error) = relaunch.relaunch_kernel(
            &manifest.generation,
            &manifest.config_digest,
            &config_path,
            &manifest.kernel_artifact_digest,
            &manifest.kernel_executable_path,
            &manifest.config_path,
            &host,
        ) else {
            panic!("relaunch descriptor generation substitution must fail");
        };
        assert!(
            relaunch_error
                .to_string()
                .contains("eliotd launch descriptor"),
            "unexpected relaunch validation error: {relaunch_error}"
        );
        assert!(relaunch.kernel.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn host_launch_options_bind_exact_manifest_and_require_registry_evidence() {
        let (manifest, root) = liveness_manifest_with_distinct_store_digests();
        let options = HostLaunchOptions {
            config_descriptor_path: PathBuf::from(
                manifest.runtime_launch.authority_descriptor_path.as_str(),
            ),
            config_descriptor_digest: manifest.runtime_launch.authority_descriptor_digest.clone(),
            installation: manifest
                .runtime_launch
                .installation_epoch
                .installation
                .clone(),
            transaction_plan_generation: manifest.runtime_launch.authority_generation.value(),
            registration_nonce: Some(PlatformHandle::new("e".repeat(64)).unwrap()),
        };
        assert!(HostComposition::validate_launch_options_for_manifest(&options, &manifest).is_ok());

        let mut substituted = options.clone();
        substituted.config_descriptor_digest =
            PlatformHandle::new("f".repeat(64)).unwrap_or_else(|_| unreachable!());
        assert!(
            HostComposition::validate_launch_options_for_manifest(&substituted, &manifest).is_err()
        );
        let mut nonce_substitution = options.clone();
        nonce_substitution.config_descriptor_digest = nonce_substitution
            .registration_nonce
            .clone()
            .unwrap_or_else(|| unreachable!());
        assert!(
            HostComposition::validate_launch_options_for_manifest(&nonce_substitution, &manifest,)
                .is_err()
        );
        assert!(
            HostComposition::validate_launch_options_for_registry(
                &options,
                &ApprovedGenerationRegistry::new(),
                None,
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn production_start_and_relaunch_store_cwd_use_canonical_store_root() {
        let (manifest, root) = liveness_manifest_with_distinct_store_digests();
        for directory in [
            manifest
                .runtime_launch
                .runtime_state_roots
                .kernel_work_root
                .as_str(),
            manifest
                .runtime_launch
                .runtime_state_roots
                .store_work_root
                .as_str(),
        ] {
            std::fs::create_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
        }
        let portable_root = manifest
            .runtime_launch
            .portable_root
            .as_ref()
            .map_or_else(|| unreachable!(), |path| PathBuf::from(path.as_str()));
        let lease = UserOwnedRootLease::open_existing(&portable_root)
            .unwrap_or_else(|error| panic!("portable root lease: {error}"));
        let config_path = portable_root.join("generation.json");
        std::fs::write(&config_path, b"fixture").unwrap_or_else(|error| panic!("{error}"));
        let start = HostJobBranches::approved_working_directories(
            &manifest.runtime_launch,
            Some(&lease),
            &config_path,
        )
        .unwrap_or_else(|error| panic!("start cwd: {error}"));
        let relaunch = HostJobBranches::approved_working_directories(
            &manifest.runtime_launch,
            Some(&lease),
            &config_path,
        )
        .unwrap_or_else(|error| panic!("relaunch cwd: {error}"));
        assert_eq!(start, relaunch);
        assert_ne!(start.0, start.1);
        assert_eq!(
            start.1,
            std::fs::canonicalize(
                manifest
                    .runtime_launch
                    .runtime_state_roots
                    .store_work_root
                    .as_str(),
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );
        drop(lease);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn host_controller_liveness_tick_uses_bridge_digest_not_provider_digest() {
        let (manifest, root) = liveness_manifest_with_distinct_store_digests();
        assert_ne!(
            manifest.store_bridge_artifact_digest,
            manifest.canonical_store_artifact_digest
        );
        let now = std::time::Instant::now();
        let exact = ReadinessContourIdentity {
            approved_generation: manifest.generation.clone(),
            approved_kernel_artifact: manifest.kernel_artifact_digest.clone(),
            approved_store_artifact: manifest.store_bridge_artifact_digest.clone(),
            approved_config: manifest.config_digest.clone(),
            active_kernel_record_checksum: PlatformHandle::new("kernel-record")
                .unwrap_or_else(|_| unreachable!()),
            candidate_binding_digest: PlatformHandle::new("candidate-binding")
                .unwrap_or_else(|_| unreachable!()),
            store_requirement_digest: PlatformHandle::new("store-requirement")
                .unwrap_or_else(|_| unreachable!()),
            store_proof_fence: Some(
                PlatformHandle::new("store-proof").unwrap_or_else(|_| unreachable!()),
            ),
        };
        let mut gate = HostReadinessGate::default();
        assert!(gate.grant(exact.clone(), now));
        let mut selected_store = None;
        let tick = descriptor_bound_liveness_tick(
            &mut gate,
            HostBranchDisposition::LiveAwaitingReadiness,
            Some(&manifest),
            |generation, kernel, store, config| {
                assert_eq!(generation, &manifest.generation);
                assert_eq!(kernel, &manifest.kernel_artifact_digest);
                assert_eq!(config, &manifest.config_digest);
                selected_store = Some(store.clone());
                Ok(exact)
            },
            now + std::time::Duration::from_millis(1),
        );
        assert_eq!(tick, HostLivenessTick::HealthyLeasePreserved);
        assert_eq!(
            selected_store.as_ref(),
            Some(&manifest.store_bridge_artifact_digest)
        );
        assert_ne!(
            selected_store.as_ref(),
            Some(&manifest.canonical_store_artifact_digest)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn ready_repeat_appends_fresh_proofs_without_mutating_activation_authority() {
        let fixture = active_readiness_fixture();
        let before = fixture.journal.snapshot().unwrap().kernel.unwrap();
        let first = authenticated_proof(&fixture, 7);
        let first_disposition = append_authenticated_kernel_readiness(
            &fixture.journal,
            &first,
            &fixture.kernel_artifact,
            &fixture.config,
        )
        .map(|_| HostBranchDisposition::Healthy)
        .unwrap();
        let second = authenticated_proof(&fixture, 8);
        let second_disposition = append_authenticated_kernel_readiness(
            &fixture.journal,
            &second,
            &fixture.kernel_artifact,
            &fixture.config,
        )
        .map(|_| HostBranchDisposition::Healthy)
        .unwrap();
        let state = fixture.journal.snapshot().unwrap();
        let after = state.kernel.unwrap();
        assert_eq!(first_disposition, HostBranchDisposition::Healthy);
        assert_eq!(second_disposition, HostBranchDisposition::Healthy);
        assert_eq!(state.readiness_observations.len(), 2);
        assert_ne!(first.request.payload_digest, second.request.payload_digest);
        assert!(matches!(
            first.request.command,
            KernelControlCommand::ProbeReady
        ));
        assert!(matches!(
            second.request.command,
            KernelControlCommand::ProbeReady
        ));
        assert_eq!(after.one_time_nonce, before.one_time_nonce);
        assert_eq!(after.kernel_generation, before.kernel_generation);
        assert_eq!(
            after.process.unwrap().authority_epoch,
            before.process.unwrap().authority_epoch
        );
    }

    #[cfg(windows)]
    #[test]
    fn readiness_lease_separates_cheap_polling_from_expired_repeat() {
        assert_eq!(
            ReadinessCadence::default().0,
            std::time::Duration::from_secs(5)
        );
        assert!(ReadinessCadence::bounded(std::time::Duration::from_millis(249)).is_err());
        assert!(ReadinessCadence::bounded(std::time::Duration::from_secs(61)).is_err());

        let fixture = active_readiness_fixture();
        let contour = readiness_contour(&fixture);
        let mut gate = HostReadinessGate::with_cadence(ReadinessCadence::default());
        let now = std::time::Instant::now();
        let probes = std::cell::Cell::new(0_u8);
        let admit = |revision| -> Result<ReadinessContourIdentity, HostError> {
            probes.set(probes.get() + 1);
            let proof = authenticated_proof(&fixture, revision);
            append_authenticated_kernel_readiness(
                &fixture.journal,
                &proof,
                &fixture.kernel_artifact,
                &fixture.config,
            )?;
            Ok(readiness_contour(&fixture))
        };

        let first =
            reconcile_authenticated_readiness(&mut gate, Ok(contour.clone()), now, || admit(20));
        assert_eq!(first, HostBranchDisposition::Healthy);
        assert_eq!(probes.get(), 1);
        let journaled_contour = readiness_contour(&fixture);

        let cheap = classify_liveness_tick(
            &mut gate,
            HostBranchDisposition::LiveAwaitingReadiness,
            Some(Ok(journaled_contour.clone())),
            now + std::time::Duration::from_millis(250),
        );
        assert_eq!(cheap, HostLivenessTick::HealthyLeasePreserved);
        assert_eq!(probes.get(), 1);

        let before_expiry = classify_liveness_tick(
            &mut gate,
            HostBranchDisposition::LiveAwaitingReadiness,
            Some(Ok(journaled_contour.clone())),
            (now + DEFAULT_READINESS_CADENCE)
                .checked_sub(std::time::Duration::from_millis(1))
                .unwrap(),
        );
        assert_eq!(before_expiry, HostLivenessTick::HealthyLeasePreserved);

        let expired_tick = classify_liveness_tick(
            &mut gate,
            HostBranchDisposition::LiveAwaitingReadiness,
            Some(Ok(journaled_contour.clone())),
            now + DEFAULT_READINESS_CADENCE,
        );
        assert_eq!(expired_tick, HostLivenessTick::FullReconcileDue);
        let expired = reconcile_authenticated_readiness(
            &mut gate,
            Ok(journaled_contour),
            now + DEFAULT_READINESS_CADENCE,
            || admit(21),
        );
        assert_eq!(expired, HostBranchDisposition::Healthy);
        assert_eq!(probes.get(), 2);
        assert_eq!(
            fixture
                .journal
                .snapshot()
                .unwrap()
                .readiness_observations
                .len(),
            2
        );
    }

    #[cfg(windows)]
    #[test]
    fn production_fast_path_invalidates_every_exact_contour_field() {
        let fixture = active_readiness_fixture();
        let mut exact = readiness_contour(&fixture);
        exact.store_proof_fence = Some(PlatformHandle::new("store-proof-exact").unwrap());
        let changed = |label: &str| PlatformHandle::new(format!("changed-{label}")).unwrap();
        let mut variants = Vec::new();

        let mut contour = exact.clone();
        contour.approved_generation = changed("generation");
        variants.push(("approved_generation", contour));
        let mut contour = exact.clone();
        contour.approved_kernel_artifact = changed("kernel-artifact");
        variants.push(("approved_kernel_artifact", contour));
        let mut contour = exact.clone();
        contour.approved_store_artifact = changed("store-artifact");
        variants.push(("approved_store_artifact", contour));
        let mut contour = exact.clone();
        contour.approved_config = changed("config");
        variants.push(("approved_config", contour));
        let mut contour = exact.clone();
        contour.active_kernel_record_checksum = changed("kernel-checksum");
        variants.push(("active_kernel_record_checksum", contour));
        let mut contour = exact.clone();
        contour.candidate_binding_digest = changed("candidate-binding");
        variants.push(("candidate_binding_digest", contour));
        let mut contour = exact.clone();
        contour.store_requirement_digest = changed("store-requirement");
        variants.push(("store_requirement_digest", contour));
        let mut contour = exact.clone();
        contour.store_proof_fence = Some(changed("store-proof"));
        variants.push(("store_proof_fence", contour));

        let now = std::time::Instant::now();
        for (field, current) in variants {
            let mut gate = HostReadinessGate::default();
            assert!(gate.grant(exact.clone(), now));
            assert_eq!(
                classify_liveness_tick(
                    &mut gate,
                    HostBranchDisposition::LiveAwaitingReadiness,
                    Some(Ok(current)),
                    now + std::time::Duration::from_millis(250),
                ),
                HostLivenessTick::FullReconcileDue,
                "{field} mismatch preserved an inexact lease"
            );
        }

        let mut exact_gate = HostReadinessGate::default();
        assert!(exact_gate.grant(exact.clone(), now));
        assert_eq!(
            classify_liveness_tick(
                &mut exact_gate,
                HostBranchDisposition::LiveAwaitingReadiness,
                Some(Ok(exact)),
                now + std::time::Duration::from_millis(250),
            ),
            HostLivenessTick::HealthyLeasePreserved
        );

        let mut missing_gate = HostReadinessGate::default();
        missing_gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
        assert_eq!(
            classify_liveness_tick(
                &mut missing_gate,
                HostBranchDisposition::LiveAwaitingReadiness,
                Some(Err(HostError::ProcessContour(
                    "retained Store proof is missing".to_owned(),
                ))),
                now + std::time::Duration::from_millis(250),
            ),
            HostLivenessTick::ReadinessRetryPending
        );
    }

    #[cfg(windows)]
    #[test]
    fn degraded_recovery_becomes_healthy_only_after_journaled_probe() {
        let fixture = active_readiness_fixture();
        let contour = readiness_contour(&fixture);
        let mut gate = HostReadinessGate::default();
        let degraded = HostBranchDisposition::KernelDegraded;
        gate.branch_degraded();
        assert_ne!(degraded, HostBranchDisposition::Healthy);
        let proof = authenticated_proof(&fixture, 9);
        let request_digest = proof.request.payload_digest.clone();
        let response_digest = proof.response.payload_digest.clone();
        let recovered = reconcile_authenticated_readiness(
            &mut gate,
            Ok(contour),
            std::time::Instant::now(),
            || {
                append_authenticated_kernel_readiness(
                    &fixture.journal,
                    &proof,
                    &fixture.kernel_artifact,
                    &fixture.config,
                )?;
                Ok(readiness_contour(&fixture))
            },
        );
        assert_eq!(recovered, HostBranchDisposition::Healthy);
        let state = fixture.journal.snapshot().unwrap();
        assert_eq!(state.readiness_observations.len(), 1);
        assert_eq!(
            state.readiness_observations[0]
                .probe_request_digest
                .as_str(),
            request_digest
        );
        assert_eq!(
            state.readiness_observations[0]
                .ready_receipt_digest
                .as_str(),
            response_digest
        );
    }

    #[cfg(windows)]
    #[test]
    fn stale_store_snapshot_and_response_substitution_never_become_healthy() {
        let fixture = active_readiness_fixture();
        let (request, response, ready) = probe_exchange(&fixture, 0);
        validate_probe_response(&request, &fixture.activation, &response).unwrap();
        let stale_result = validated_store_proof_fence(
            &fixture.requirement,
            &ready,
            &fixture.store_artifact,
            &fixture.config,
            request.generation,
        );
        assert!(stale_result.is_err());

        let (request, mut substituted, _) = probe_exchange(&fixture, 10);
        substituted.request_digest = "d".repeat(64);
        substituted = substituted.with_computed_digest().unwrap();
        assert!(validate_probe_response(&request, &fixture.activation, &substituted).is_err());
        let snapshot = fixture.journal.snapshot().unwrap();
        assert!(snapshot.readiness_observations.is_empty());
        assert_eq!(
            snapshot.kernel.unwrap().state,
            KernelActivationState::Active
        );
    }

    #[cfg(windows)]
    #[test]
    fn unknown_readiness_journal_outcome_remains_non_healthy() {
        let fixture = active_readiness_fixture();
        let proof = authenticated_proof(&fixture, 11);
        let host = fixture.journal.snapshot().unwrap().host;
        let backend = fixture.journal.into_backend().unwrap();
        let journal = HostStateJournalService::from_backend(
            UnknownAppendBackend {
                image: backend.durable_image().clone(),
                prepared: None,
            },
            host,
        )
        .unwrap();
        let outcome = append_authenticated_kernel_readiness(
            &journal,
            &proof,
            &fixture.kernel_artifact,
            &fixture.config,
        );
        assert!(matches!(
            outcome,
            Err(HostError::Journal(JournalError::OutcomeUnknown { .. }))
        ));
        assert!(
            journal
                .snapshot()
                .unwrap()
                .readiness_observations
                .is_empty()
        );
    }

    #[cfg(windows)]
    #[test]
    fn pending_activation_reopen_starts_a_fresh_child_after_historical_active() {
        let fixture = active_readiness_fixture();
        let (mut manifest, _root) = liveness_manifest_with_distinct_store_digests();
        manifest.runtime_launch.installation_epoch.installation = fixture
            .journal
            .snapshot()
            .unwrap()
            .host
            .installation
            .clone();
        let pending = eliot_installation::PendingActivation {
            transaction_id: PlatformHandle::new("transaction:reopen").unwrap(),
            plan_digest: PlatformHandle::new("e".repeat(64)).unwrap(),
            config_digest: manifest.config_digest.clone(),
            kernel_artifact_digest: manifest.kernel_artifact_digest.clone(),
            store_bridge_artifact_digest: manifest.store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: manifest.canonical_store_artifact_digest.clone(),
            runtime_state_roots_digest: manifest.runtime_state_roots_digest.clone(),
            manifest_digest: PlatformHandle::new(sha256_json(&manifest).unwrap()).unwrap(),
            prior_active_generation: None,
            approval_ref: PlatformHandle::new("approval:reopen").unwrap(),
            manifest,
            state: eliot_installation::PendingActivationState::Pending,
        };
        let proof = authenticated_proof(&fixture, 17);
        append_authenticated_kernel_readiness(
            &fixture.journal,
            &proof,
            &fixture.kernel_artifact,
            &fixture.config,
        )
        .unwrap();
        let snapshot = fixture.journal.snapshot().unwrap();
        let mut control_ready = transition_activation_record(
            snapshot.activation.as_ref().unwrap(),
            ActivationState::ControlReady,
            "pending-reopen-control-ready",
        )
        .unwrap();
        control_ready
            .trigger_evidence
            .push(pending_activation_binding(&pending).unwrap());
        append_reconciled(&fixture.journal, HostStateRecord::Activation(control_ready)).unwrap();
        let ready_snapshot = fixture.journal.snapshot().unwrap();
        let active = transition_activation_record(
            ready_snapshot.activation.as_ref().unwrap(),
            ActivationState::Active,
            "pending-reopen-active",
        )
        .unwrap();
        append_reconciled(&fixture.journal, HostStateRecord::Activation(active)).unwrap();

        // Drive the same persisted replay/reopen path used by production Host
        // (with an in-memory durable backend so the test never touches the
        // machine-wide protected ProgramData journal).  The historical Active
        // record is deliberately not accepted as a live contour: a Host-owned
        // kill-on-close Job has already terminated its children by the time a
        // new Host process reaches this path.
        let durable = fixture.journal.snapshot().unwrap();
        let last_host = durable.host;
        let installation = pending
            .manifest
            .runtime_launch
            .installation_epoch
            .installation
            .clone();
        let prior_generation = durable
            .activation
            .as_ref()
            .unwrap()
            .fence
            .activation_generation
            .clone();
        let (reopened, reopened_host, reopened_generation) =
            reopen_existing_epoch(fixture.journal, &last_host, &installation, Some(&pending))
                .unwrap();
        assert_ne!(reopened_host, last_host);
        assert_eq!(
            reopened_host.epoch.parent,
            Some(last_host.epoch.current.clone())
        );
        assert_eq!(
            reopened_generation,
            prior_generation.direct_child().unwrap()
        );
        let recovered = reopened.snapshot().unwrap();
        assert!(recovered.activation.is_none());
        assert!(recovered.prior_kernel.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn production_reopen_fails_closed_on_unknown_prepared_append() {
        let fixture = active_readiness_fixture();
        let host = fixture.journal.snapshot().unwrap().host;
        let activation = fixture.journal.snapshot().unwrap().activation.unwrap();
        let backend = fixture.journal.into_backend().unwrap();
        let mut faulted_backend = backend;
        faulted_backend.inject_fault(FaultPoint::CommitBeforeUnknown);
        let journal = HostStateJournalService::from_backend(faulted_backend, host.clone()).unwrap();
        let draining = transition_activation_record(
            &activation,
            ActivationState::ControlReady,
            "faulted-reopen-control-ready",
        )
        .unwrap();
        let append_result = append_reconciled(&journal, HostStateRecord::Activation(draining));
        assert!(
            matches!(
                &append_result,
                Err(HostError::Journal(JournalError::OutcomeUnknown { .. }))
            ),
            "unexpected fault result: {append_result:?}"
        );
        assert!(matches!(
            reopen_existing_epoch(journal, &host, &host.installation, None,),
            Err(HostError::Journal(JournalError::OutcomeUnknown { .. }))
        ));
    }

    #[test]
    fn host_composition_production_field_is_the_redb_journal_service() {
        fn production_journal(
            composition: &HostComposition,
        ) -> &HostStateJournalService<RedbJournalBackend> {
            &composition.journal
        }
        let typed_reachability: fn(
            &HostComposition,
        ) -> &HostStateJournalService<RedbJournalBackend> = production_journal;
        assert_eq!(
            std::any::type_name_of_val(&typed_reachability),
            std::any::type_name::<
                fn(&HostComposition) -> &HostStateJournalService<RedbJournalBackend>,
            >()
        );
    }

    #[test]
    fn open_activation_clean_stop_and_child_reopen_replay() {
        let host = test_host();
        let generation = root_epoch(fresh_identity("test-activation-lineage").unwrap());
        let activation_id = fresh_identity("test-activation").unwrap();
        let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())
            .unwrap_or_else(|_| unreachable!());
        append_reconciled(
            &journal,
            HostStateRecord::Activation(
                initial_activation_record(
                    &host,
                    &activation_id,
                    &generation,
                    ActivationState::Stopped,
                    "test-open",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        append_clean_marker(&journal, &host, &activation_id, &generation).unwrap();
        let backend = journal.into_backend().unwrap();

        let child = child_host_epoch(&host).unwrap();
        let reopened = HostStateJournalService::from_backend(backend, child.clone()).unwrap();
        assert_eq!(reopened.snapshot().unwrap().retained_epochs.len(), 1);
        let child_generation = generation.direct_child().unwrap();
        let child_activation = fresh_identity("test-child-activation").unwrap();
        append_reconciled(
            &reopened,
            HostStateRecord::Activation(
                initial_activation_record(
                    &child,
                    &child_activation,
                    &child_generation,
                    ActivationState::Stopped,
                    "test-child-open",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(reopened.snapshot().unwrap().sequence, 1);
        assert!(reopened.snapshot().unwrap().clean_marker.is_none());
    }

    #[test]
    fn unknown_commit_is_reconciled_by_transaction_identity() {
        let host = test_host();
        let generation = root_epoch(fresh_identity("unknown-lineage").unwrap());
        let activation_id = fresh_identity("unknown-activation").unwrap();
        let journal = HostStateJournalService::from_backend(
            MemoryBackend::with_fault(FaultPoint::CommitAfterUnknown),
            host.clone(),
        )
        .unwrap();
        append_reconciled(
            &journal,
            HostStateRecord::Activation(
                initial_activation_record(
                    &host,
                    &activation_id,
                    &generation,
                    ActivationState::Stopped,
                    "unknown-open",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(journal.snapshot().unwrap().sequence, 1);
    }

    #[test]
    fn torn_current_epoch_fails_closed() {
        let host = test_host();
        let generation = root_epoch(fresh_identity("torn-lineage").unwrap());
        let activation_id = fresh_identity("torn-activation").unwrap();
        let journal =
            HostStateJournalService::from_backend(MemoryBackend::default(), host.clone()).unwrap();
        append_reconciled(
            &journal,
            HostStateRecord::Activation(
                initial_activation_record(
                    &host,
                    &activation_id,
                    &generation,
                    ActivationState::Stopped,
                    "torn-open",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let backend = journal.into_backend().unwrap();
        let mut image = backend.durable_image().clone();
        image.epochs[0].bytes.pop();
        assert!(matches!(
            HostStateJournalService::from_backend(ImageBackend { image }, host),
            Err(JournalError::Torn { .. })
        ));
    }

    #[test]
    fn activation_failure_nonce_discriminator_revokes_only_pre_active_issuance() {
        let nonce = || {
            eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).unwrap_or_else(|_| unreachable!()),
            )
            .unwrap_or_else(|_| unreachable!())
        };
        let unissued = OneTimeNonceState::unissued();
        assert_eq!(
            nonce_after_activation_failure(&unissued)
                .unwrap_or_else(|_| unreachable!())
                .state(),
            NonceState::Unissued
        );
        let issued = OneTimeNonceState::issued(nonce());
        assert_eq!(
            nonce_after_activation_failure(&issued)
                .unwrap_or_else(|_| unreachable!())
                .state(),
            NonceState::Revoked
        );
        let consumed = OneTimeNonceState::issued(nonce())
            .consume()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            nonce_after_activation_failure(&consumed)
                .unwrap_or_else(|_| unreachable!())
                .state(),
            NonceState::Consumed
        );
    }

    #[cfg(windows)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression constructs a real Active+Consumed record and drives stale, unknown, and recovered readiness admissions"
    )]
    fn reconciled_active_readiness_failure_preserves_contour_then_recovers() {
        let host = test_host();
        let activation_generation =
            root_epoch(fresh_identity("reconcile-activation-lineage").unwrap());
        let activation_id = fresh_identity("reconcile-activation").unwrap();
        let journal =
            HostStateJournalService::from_backend(MemoryBackend::default(), host.clone()).unwrap();
        append_reconciled(
            &journal,
            HostStateRecord::Activation(
                initial_activation_record(
                    &host,
                    &activation_id,
                    &activation_generation,
                    ActivationState::Starting,
                    "reconcile-starting",
                )
                .unwrap(),
            ),
        )
        .unwrap();

        let job_name = PlatformHandle::new("Local\\Eliot-Host-Kernel-reconcile").unwrap();
        let kernel_image = "C:\\eliot\\eliot-kernel.exe".to_owned();
        let candidate = HostKernelCandidateBinding {
            installation_id: host.installation.clone(),
            host_epoch: AuthorityEpoch::new(host.epoch.current.sequence).unwrap(),
            kernel_epoch: AuthorityEpoch::new(2).unwrap(),
            activation_id: activation_id.clone(),
            artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
            config_hash: PlatformHandle::new("c".repeat(64)).unwrap(),
            job_object_id: job_name.clone(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\eliot-host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: job_name.as_str().to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: kernel_image.clone(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            restart_budget: RestartBudget::new(1, 1).unwrap(),
            containment_action: None,
        };
        let durable_job = KernelJobBinding {
            job_name: job_name.clone(),
            owner: PlatformHandle::new("Kernel").unwrap(),
            root_pid: 42,
            root_start_time_100ns: 10,
            root_image_path: PlatformHandle::new(kernel_image.clone()).unwrap(),
            root_volume_serial_number: 1,
            root_file_index: 2,
        };
        let kernel_generation = root_epoch(fresh_identity("reconcile-kernel-lineage").unwrap());
        let mut driver = DurableKernelActivationDriver::bind_candidate(
            &journal,
            &host,
            &activation_id,
            &activation_generation,
            candidate.artifact_hash.clone(),
            candidate.pipe_identity.clone(),
            durable_job,
            PriorKernelDisposition::NoPriorKernel,
            kernel_generation,
            ServiceProcessRecord {
                process_id: "pid:42:start:10".to_owned(),
                owner: "Kernel".to_owned(),
                state: ServiceProcessState::Starting,
                health: HealthVector::healthy(),
                authority_epoch: candidate.kernel_epoch,
            },
        )
        .unwrap();
        driver.handoff_prepared().unwrap();
        driver.prior_disposition_committed().unwrap();
        let permit = driver
            .issue_nonce(&candidate, ResourceGeneration::genesis())
            .unwrap();
        driver.activating().unwrap();
        let activation_receipt = KernelActivationReceipt::issue(&permit);
        let ready = KernelReadyReceipt {
            activation_id: activation_id.clone(),
            activation_operation_id: activation_receipt.operation_id.clone(),
            activation_nonce_digest: activation_receipt.activation_nonce_digest.clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: job_name,
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("reconcile-process-evidence").unwrap()],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("reconcile-ready-evidence").unwrap()],
        };
        driver
            .active(&candidate, &activation_receipt, &ready)
            .unwrap();
        drop(driver);
        let active = journal.snapshot().unwrap().kernel.unwrap();
        assert_eq!(active.state, KernelActivationState::Active);
        assert_eq!(active.one_time_nonce.state(), NonceState::Consumed);

        let kernel_artifact = candidate.artifact_hash.clone();
        let store_artifact = PlatformHandle::new("b".repeat(64)).unwrap();
        let config = candidate.config_hash.clone();
        let requirement = HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)
                .unwrap(),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-readiness")
                .unwrap(),
            store_generation: ResourceGeneration::genesis(),
            state_fence: StateFence::new(candidate.kernel_epoch, ResourceGeneration::genesis()),
            launch_nonce: PlatformHandle::new("reconcile-store-launch").unwrap(),
            connection_id: PlatformHandle::new("reconcile-store-connection").unwrap(),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
            expected_peer_session_id: 0,
            approved_artifact_hash: store_artifact.clone(),
            approved_config_hash: config.clone(),
            timeout_ms: 5_000,
        };
        let fixture = ReadinessFixture {
            journal,
            candidate,
            activation: activation_receipt,
            requirement,
            kernel_artifact,
            store_artifact,
            config,
        };
        let contour = readiness_contour(&fixture);
        let mut gate = HostReadinessGate::with_cadence(ReadinessCadence::default());
        let now = std::time::Instant::now();
        let probes = std::cell::Cell::new(0_u8);

        let stale = reconcile_authenticated_readiness(&mut gate, Ok(contour.clone()), now, || {
            probes.set(probes.get() + 1);
            let (request, response, ready) = probe_exchange(&fixture, 0);
            validate_probe_response(&request, &fixture.activation, &response)?;
            let store_proof_fence = validated_store_proof_fence(
                &fixture.requirement,
                &ready,
                &fixture.store_artifact,
                &fixture.config,
                request.generation,
            )?;
            Ok(ReadinessContourIdentity {
                store_proof_fence: Some(store_proof_fence),
                ..contour.clone()
            })
        });
        assert_eq!(stale, HostBranchDisposition::ReadinessDegraded);
        assert_eq!(
            gate.last_failure(),
            Some(ReadinessFailureKind::ProbeRejected)
        );
        assert_eq!(probes.get(), 1);

        let throttled = reconcile_authenticated_readiness(
            &mut gate,
            Ok(contour.clone()),
            now + std::time::Duration::from_millis(250),
            || panic!("250ms liveness poll must not repeat authoritative readiness"),
        );
        assert_eq!(throttled, HostBranchDisposition::ReadinessDegraded);

        let unknown = reconcile_authenticated_readiness(
            &mut gate,
            Ok(contour.clone()),
            now + DEFAULT_READINESS_CADENCE,
            || {
                probes.set(probes.get() + 1);
                Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id: fresh_identity("readiness-unknown").unwrap(),
                }))
            },
        );
        assert_eq!(unknown, HostBranchDisposition::ReadinessDegraded);
        assert_eq!(
            gate.last_failure(),
            Some(ReadinessFailureKind::JournalOutcomeUnknown)
        );
        let retained = fixture.journal.snapshot().unwrap().kernel.unwrap();
        assert_eq!(retained.state, KernelActivationState::Active);
        assert_eq!(retained.one_time_nonce.state(), NonceState::Consumed);
        assert!(
            fixture
                .journal
                .snapshot()
                .unwrap()
                .readiness_observations
                .is_empty()
        );

        let recovered = reconcile_authenticated_readiness(
            &mut gate,
            Ok(contour),
            now + DEFAULT_READINESS_CADENCE + DEFAULT_READINESS_CADENCE,
            || {
                probes.set(probes.get() + 1);
                let proof = authenticated_proof(&fixture, 12);
                append_authenticated_kernel_readiness(
                    &fixture.journal,
                    &proof,
                    &fixture.kernel_artifact,
                    &fixture.config,
                )?;
                Ok(readiness_contour(&fixture))
            },
        );
        assert_eq!(recovered, HostBranchDisposition::Healthy);
        assert_eq!(probes.get(), 3);
        let recovered_state = fixture.journal.snapshot().unwrap();
        let recovered_kernel = recovered_state.kernel.unwrap();
        assert_eq!(recovered_kernel.state, KernelActivationState::Active);
        assert_eq!(
            recovered_kernel.one_time_nonce.state(),
            NonceState::Consumed
        );
        assert_eq!(recovered_state.readiness_observations.len(), 1);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;

    use super::{
        CutoverLaunchOutcome, HostBranchDisposition, HostError, HostJobBranches,
        HostProcessBinding, KERNEL_BOOTSTRAP_ENVIRONMENT, KERNEL_CONTROL_PIPE,
        KernelControlResponse, KernelLaunchBinding, KernelServiceState, PlatformHandle,
        ReconciliationObservation, ReconciliationState, StoreKernelLaunchError,
        StoreLivenessEvidence, activation_response_or_reconcile, fresh_host_epoch,
        launch_store_then_kernel, reconcile_state_machine,
    };
    use eliot_platform_windows::JobObjectIdentity;

    #[derive(Debug, Eq, PartialEq)]
    struct MockChild {
        id: u8,
        live: bool,
    }

    fn mock_observation(child: Option<&MockChild>) -> ReconciliationObservation {
        match child {
            Some(child) if child.live => ReconciliationObservation::Live,
            Some(_) | None => ReconciliationObservation::Dead,
        }
    }

    fn launch_environment(kernel: Option<&KernelLaunchBinding>) -> BTreeMap<String, String> {
        let host = fresh_host_epoch(
            PlatformHandle::new("launch-test-installation").expect("installation"),
            None,
        )
        .expect("host epoch");
        HostJobBranches::environment_from(
            [
                (OsString::from("Path"), OsString::from(r"C:\\Windows")),
                (
                    OsString::from("eliot_kernel_control_pipe"),
                    OsString::from("ambient-pipe"),
                ),
                (
                    OsString::from("ELIOT_HOST_PROCESS_ID"),
                    OsString::from("999"),
                ),
                (
                    OsString::from("eliot_host_process_start"),
                    OsString::from("888"),
                ),
                (
                    OsString::from("ELIOT_HOST_PROCESS_IMAGE"),
                    OsString::from("ambient.exe"),
                ),
                (
                    OsString::from("ELIOT_ACTIVATION_NONCE"),
                    OsString::from("must-not-cross-process-boundary"),
                ),
            ],
            &host,
            &PlatformHandle::new("generation").expect("generation"),
            &PlatformHandle::new("config-digest").expect("config"),
            &PlatformHandle::new("artifact-digest").expect("artifact"),
            Path::new(r"C:\\eliot\\config.json"),
            &JobObjectIdentity::new(r"Local\Eliot-Host-Test").expect("job"),
            kernel,
        )
        .into_iter()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect()
    }

    #[test]
    fn store_and_unrelated_child_environment_scrubs_kernel_bootstrap_authority() {
        let environment = launch_environment(None);
        assert_eq!(
            environment.get("Path").map(String::as_str),
            Some(r"C:\\Windows")
        );
        for name in KERNEL_BOOTSTRAP_ENVIRONMENT {
            assert!(!environment.keys().any(|key| key.eq_ignore_ascii_case(name)));
        }
        assert!(!environment.contains_key("ELIOT_ACTIVATION_NONCE"));
    }

    #[test]
    fn kernel_launch_environment_uses_exact_retained_binding() {
        let binding = KernelLaunchBinding {
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).expect("pipe"),
            host_process: HostProcessBinding {
                process_id: 41,
                start_time_100ns: 73,
                image_path: r"C:\\eliot\\eliot-host.exe".to_owned(),
            },
        };
        let environment = launch_environment(Some(&binding));
        assert_eq!(
            environment
                .get("ELIOT_KERNEL_CONTROL_PIPE")
                .map(String::as_str),
            Some(KERNEL_CONTROL_PIPE)
        );
        assert_eq!(
            environment.get("ELIOT_HOST_PROCESS_ID").map(String::as_str),
            Some("41")
        );
        assert_eq!(
            environment
                .get("ELIOT_HOST_PROCESS_START")
                .map(String::as_str),
            Some("73")
        );
        assert_eq!(
            environment
                .get("ELIOT_HOST_PROCESS_IMAGE")
                .map(String::as_str),
            Some(r"C:\\eliot\\eliot-host.exe")
        );
        assert!(!environment.contains_key("ELIOT_ACTIVATION_NONCE"));
    }

    #[test]
    fn retained_host_binding_rejects_pid_reuse_and_image_substitution() {
        let binding = KernelLaunchBinding {
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).expect("pipe"),
            host_process: HostProcessBinding {
                process_id: 41,
                start_time_100ns: 73,
                image_path: r"C:\\eliot\\eliot-host.exe".to_owned(),
            },
        };
        assert!(binding.matches_observed(41, 73, r"C:\\eliot\\eliot-host.exe"));
        assert!(!binding.matches_observed(42, 73, r"C:\\eliot\\eliot-host.exe"));
        assert!(!binding.matches_observed(41, 74, r"C:\\eliot\\eliot-host.exe"));
        assert!(!binding.matches_observed(41, 73, r"C:\\eliot\\replacement.exe"));
    }

    #[test]
    fn cutover_launch_discriminator_selects_only_the_process_that_was_launched() {
        let candidate = PlatformHandle::new("candidate-generation").expect("candidate");
        let prior = PlatformHandle::new("prior-generation").expect("prior");
        assert_eq!(
            CutoverLaunchOutcome::Candidate.activation_generation(&candidate, &prior),
            &candidate
        );
        assert_eq!(
            CutoverLaunchOutcome::Rollback {
                candidate_error: "launch rejected".to_owned(),
            }
            .activation_generation(&candidate, &prior),
            &prior
        );
    }

    #[test]
    fn activate_response_uncertainty_reconciles_but_exact_rejection_does_not() {
        let message = PlatformHandle::new("activate-message").expect("message");
        let digest = "a".repeat(64);
        let response = |message_id: PlatformHandle, error: Option<String>| KernelControlResponse {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id,
            request_digest: digest.clone(),
            state: KernelServiceState::Activating,
            receipt: None,
            activation_receipt: None,
            error,
            payload_digest: String::new(),
        };
        assert!(
            activation_response_or_reconcile(
                Err(HostError::RecoveryRequired("receive lost".to_owned())),
                &message,
                &digest,
            )
            .expect("unknown receive outcome")
            .is_none()
        );
        assert!(
            activation_response_or_reconcile(
                Ok(response(
                    PlatformHandle::new("wrong-message").expect("wrong message"),
                    None,
                )),
                &message,
                &digest,
            )
            .expect("binding loss is unknown")
            .is_none()
        );
        assert!(
            activation_response_or_reconcile(
                Ok(response(message.clone(), None)),
                &message,
                &digest
            )
            .expect("missing receipt is unknown")
            .is_none()
        );
        assert!(
            activation_response_or_reconcile(
                Ok(response(message.clone(), Some("rejected".to_owned()))),
                &message,
                &digest,
            )
            .is_err()
        );
    }

    #[test]
    fn approved_launch_records_store_before_kernel() {
        let launches = RefCell::new(Vec::new());
        let result = launch_store_then_kernel(
            || {
                launches.borrow_mut().push("Store");
                Ok::<_, HostError>(())
            },
            |()| -> Result<(), StoreLivenessEvidence> { Ok(()) },
            || {
                launches.borrow_mut().push("Kernel");
                Ok::<_, HostError>(())
            },
            |()| -> Result<(), Box<((), String)>> { Ok(()) },
        );
        assert!(result.is_ok());
        assert_eq!(*launches.borrow(), ["Store", "Kernel"]);
    }

    #[test]
    fn dead_store_launch_is_cleaned_without_kernel_attempt() {
        let launches = RefCell::new(Vec::new());
        let cleaned = RefCell::new(false);
        let result = launch_store_then_kernel(
            || {
                launches.borrow_mut().push("Store");
                Ok::<_, HostError>(())
            },
            |()| -> Result<(), StoreLivenessEvidence> { Err(StoreLivenessEvidence::Dead) },
            || {
                launches.borrow_mut().push("Kernel");
                Ok::<_, HostError>(())
            },
            |()| -> Result<(), Box<((), String)>> {
                *cleaned.borrow_mut() = true;
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(StoreKernelLaunchError::StoreNotLive {
                evidence: StoreLivenessEvidence::Dead
            })
        ));
        assert_eq!(*launches.borrow(), ["Store"]);
        assert!(*cleaned.borrow());
    }

    #[test]
    fn unknown_store_launch_is_fail_closed_without_kernel_attempt() {
        let launches = RefCell::new(Vec::new());
        let result = launch_store_then_kernel(
            || {
                launches.borrow_mut().push("Store");
                Ok::<_, HostError>(())
            },
            |()| {
                Err(StoreLivenessEvidence::Unknown(
                    "observation failed".to_owned(),
                ))
            },
            || {
                launches.borrow_mut().push("Kernel");
                Ok::<_, HostError>(())
            },
            |()| -> Result<(), Box<((), String)>> { Ok(()) },
        );
        assert!(matches!(
            result,
            Err(StoreKernelLaunchError::StoreNotLive {
                evidence: StoreLivenessEvidence::Unknown(_)
            })
        ));
        assert_eq!(*launches.borrow(), ["Store"]);
    }

    #[test]
    fn kernel_failure_cleans_store_after_single_store_first_attempt() {
        let launches = RefCell::new(Vec::new());
        let cleaned = RefCell::new(0);
        let result = launch_store_then_kernel(
            || {
                launches.borrow_mut().push("Store");
                Ok::<_, HostError>(())
            },
            |()| -> Result<(), StoreLivenessEvidence> { Ok(()) },
            || {
                launches.borrow_mut().push("Kernel");
                Err::<(), _>(HostError::ProcessContour("kernel launch failed".to_owned()))
            },
            |()| -> Result<(), Box<((), String)>> {
                *cleaned.borrow_mut() += 1;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(*launches.borrow(), ["Store", "Kernel"]);
        assert_eq!(*cleaned.borrow(), 1);
    }

    #[test]
    fn unknown_store_cleanup_retains_owner_and_blocks_kernel() {
        let launches = RefCell::new(Vec::new());
        let result = launch_store_then_kernel(
            || {
                launches.borrow_mut().push("Store");
                Ok::<_, HostError>(42_u8)
            },
            |store| {
                assert_eq!(*store, 42);
                Err(StoreLivenessEvidence::Unknown("reap timeout".to_owned()))
            },
            || {
                launches.borrow_mut().push("Kernel");
                Ok::<_, HostError>(())
            },
            |store| Err(Box::new((store, "bounded termination failed".to_owned()))),
        );
        assert!(matches!(
            result,
            Err(StoreKernelLaunchError::CleanupRequired { store: 42, .. })
        ));
        assert_eq!(*launches.borrow(), ["Store"]);
    }

    #[test]
    fn reconcile_store_first_then_kernel() {
        let events = RefCell::new(Vec::new());
        let mut state = ReconciliationState {
            store: None,
            kernel: None,
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            |child| {
                if child.is_some() {
                    events.borrow_mut().push("observe Store");
                }
                mock_observation(child)
            },
            mock_observation,
            |_| Ok(()),
            |_| Ok(()),
            || {
                events.borrow_mut().push("launch Store");
                Ok(MockChild { id: 1, live: true })
            },
            || {
                events.borrow_mut().push("launch Kernel");
                Ok(MockChild { id: 2, live: true })
            },
        );
        assert_eq!(disposition, HostBranchDisposition::LiveAwaitingReadiness);
        assert_eq!(
            *events.borrow(),
            ["launch Store", "observe Store", "launch Kernel"]
        );
    }

    #[test]
    fn reconcile_store_failure_or_unknown_blocks_kernel() {
        for unknown in [false, true] {
            let kernel_launches = RefCell::new(0);
            let mut state = ReconciliationState {
                store: unknown.then_some(MockChild { id: 7, live: true }),
                kernel: None,
                store_restart_attempts: 0,
                kernel_restart_attempts: 0,
            };
            let disposition = reconcile_state_machine(
                &mut state,
                |child| {
                    if unknown {
                        ReconciliationObservation::Unknown
                    } else {
                        mock_observation(child)
                    }
                },
                mock_observation,
                |_| Ok(()),
                |_| Ok(()),
                || {
                    if unknown {
                        Ok(MockChild { id: 8, live: true })
                    } else {
                        Err(())
                    }
                },
                || {
                    *kernel_launches.borrow_mut() += 1;
                    Ok(MockChild { id: 9, live: true })
                },
            );
            assert_eq!(disposition, HostBranchDisposition::BothDegraded);
            assert_eq!(*kernel_launches.borrow(), 0);
        }
    }

    #[test]
    fn reconcile_live_store_restarts_kernel_once_and_then_is_bounded() {
        let kernel_launches = RefCell::new(0);
        let mut state = ReconciliationState {
            store: Some(MockChild { id: 7, live: true }),
            kernel: None,
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let run = |state: &mut ReconciliationState<MockChild, MockChild>| {
            reconcile_state_machine(
                state,
                mock_observation,
                mock_observation,
                |_| Ok(()),
                |_| Ok(()),
                || Ok(MockChild { id: 8, live: true }),
                || {
                    *kernel_launches.borrow_mut() += 1;
                    Ok(MockChild { id: 9, live: true })
                },
            )
        };
        assert_eq!(
            run(&mut state),
            HostBranchDisposition::LiveAwaitingReadiness
        );
        state.kernel.as_mut().expect("kernel restart").live = false;
        assert_eq!(run(&mut state), HostBranchDisposition::KernelDegraded);
        assert_eq!(*kernel_launches.borrow(), 1);
    }

    #[test]
    fn reconcile_failed_termination_retains_owned_handle() {
        let mut state = ReconciliationState {
            store: Some(MockChild { id: 7, live: false }),
            kernel: Some(MockChild { id: 9, live: true }),
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            mock_observation,
            mock_observation,
            |_| Err(()),
            |_| Ok(()),
            || Ok(MockChild { id: 8, live: true }),
            || Ok(MockChild { id: 10, live: true }),
        );
        assert_eq!(disposition, HostBranchDisposition::StoreDegraded);
        assert_eq!(state.store, Some(MockChild { id: 7, live: false }));
    }

    #[test]
    fn reconcile_kernel_failure_retains_restarted_store() {
        let mut state = ReconciliationState {
            store: None,
            kernel: None,
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            mock_observation,
            mock_observation,
            |_| Ok(()),
            |_| Ok(()),
            || Ok(MockChild { id: 7, live: true }),
            || Err(()),
        );
        assert_eq!(disposition, HostBranchDisposition::KernelDegraded);
        assert_eq!(state.store, Some(MockChild { id: 7, live: true }));
        assert!(state.kernel.is_none());
    }

    #[test]
    fn replacement_kernel_dead_or_unknown_is_not_healthy() {
        for observation in [
            ReconciliationObservation::Dead,
            ReconciliationObservation::Unknown,
        ] {
            let mut state = ReconciliationState {
                store: Some(MockChild { id: 1, live: true }),
                kernel: Some(MockChild { id: 2, live: false }),
                store_restart_attempts: 0,
                kernel_restart_attempts: 0,
            };
            let disposition = reconcile_state_machine(
                &mut state,
                mock_observation,
                |child| {
                    if child.is_some() {
                        observation
                    } else {
                        ReconciliationObservation::Dead
                    }
                },
                |_| Ok(()),
                |kernel| {
                    kernel.take();
                    Ok(())
                },
                || Ok(MockChild { id: 3, live: true }),
                || Ok(MockChild { id: 4, live: false }),
            );
            assert_eq!(disposition, HostBranchDisposition::KernelDegraded);
            if observation == ReconciliationObservation::Dead {
                assert!(state.kernel.is_none());
            } else {
                assert_eq!(state.kernel, Some(MockChild { id: 2, live: false }));
            }
        }
    }

    #[test]
    fn replacement_kernel_termination_failure_retains_binding() {
        let mut state = ReconciliationState {
            store: Some(MockChild { id: 1, live: true }),
            kernel: Some(MockChild { id: 2, live: false }),
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            mock_observation,
            mock_observation,
            |_| Ok(()),
            |_| Err(()),
            || Ok(MockChild { id: 3, live: true }),
            || Ok(MockChild { id: 4, live: true }),
        );
        assert_eq!(disposition, HostBranchDisposition::KernelDegraded);
        assert_eq!(state.kernel, Some(MockChild { id: 2, live: false }));
    }
}

impl From<io::Error> for HostError {
    fn from(error: io::Error) -> Self {
        Self::Platform(error.to_string())
    }
}
