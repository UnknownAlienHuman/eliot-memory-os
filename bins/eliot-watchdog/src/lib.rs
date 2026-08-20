//! Composition root for the independent Runtime 0.17 watchdog.
//!
//! The watchdog owns timing and supervision admission only.  Kernel effects
//! remain behind [`KernelWatchdogPort`], which makes it impossible for this
//! binary to turn a stale observation into process authority by itself.

#![forbid(unsafe_code)]
#![cfg_attr(test, recursion_limit = "256")]

use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{AuthorityEpoch, sha256_hex};
use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, InstallationProfile,
    InstallerServiceRegistrationApproval, InstallerServiceRole, PendingActivationState,
    RedbInstallationRegistry, RuntimeStateRoots, ValidatedRuntimeRootLeases,
    WindowsRuntimeRootLease, WindowsRuntimeRootLeaseProvider, verify_file_digest,
    verify_file_digest_with_lease,
};
use eliot_platform_windows::{
    NamedPipePeerProcessBinding, ProcessIdentity, ProtectedPathLease, ProtectedRootLease,
    ProtectedRuntimePathLease, ServiceBootstrapArguments, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, WindowsAdapterError, WindowsPlatform,
    protected_program_data_root, require_protected_program_data_path, windows_paths_equal,
};
use eliot_runtime::{
    ChildClass, Runtime, RuntimeConfig, ShutdownOutcome, SupervisionStrategy, TaskFailure,
};
use eliot_runtime_contracts::{
    SignedSupervisionLease, SupervisionLeaseError, SupervisionLeaseVerificationContext,
    SupervisionLeaseVerifier, SupervisionTrustAnchor, VerifiedSupervisionLease,
};
use eliot_watchdog_core::{Epoch, Watchdog};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;

#[cfg(test)]
mod registry_fixture;

pub const SERVICE_NAME: &str = "EliotWatchdog";
pub const PROTOCOL_VERSION: &str = "eliot.watchdog.v1";
/// Fixed files owned by the installer below the approved per-installation
/// Host state root. These are never resolved from `ProgramData`, the current
/// directory, or an environment variable.
pub const SUPERVISION_LEASE_FILE_NAME: &str = "supervision-lease.json";
/// Watchdog admission configuration below the approved Host state root.
pub const WATCHDOG_ADMISSION_FILE_NAME: &str = "watchdog-admission.json";
/// Approved-generation registry below the approved Host state root.
pub const INSTALLATION_REGISTRY_FILE_NAME: &str = "installation-registry.redb";
const ADMISSION_CONFIG_SCHEMA: &str = "eliot.watchdog-admission.v1";
const ADMISSION_CONFIG_LIMIT: u64 = 1024 * 1024;
const LEASE_FILE_LIMIT: u64 = 1024 * 1024;

/// Failure while validating the immutable argv contract supplied by SCM.
#[derive(Debug, Error)]
pub enum WatchdogScmLaunchError {
    #[error("invalid Watchdog SCM argv: {0}")]
    InvalidArgv(String),
    #[error("Watchdog SCM executable: {0}")]
    Executable(#[source] std::io::Error),
    #[error("Watchdog SCM platform inspection: {0}")]
    Platform(#[from] WindowsAdapterError),
    #[error("Watchdog SCM platform root: {0}")]
    PlatformRoot(String),
    #[error("Watchdog SCM registration is not an exact read-only runtime match: {0:?}")]
    Registration(WatchdogRuntimeReadback),
    #[error("Watchdog SCM installer approval is unavailable or invalid")]
    ApprovalUnavailable,
    #[error("Watchdog SCM bootstrap does not match the installer-approved registration")]
    ApprovalMismatch,
}

/// Exact, read-only launch evidence accepted from the Windows Service Control
/// Manager.  The registration request is retained only as an inspection query;
/// this type exposes no SCM mutation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWatchdogScmLaunch {
    bootstrap: ServiceBootstrapArguments,
    registration: ServiceRegistrationRequest,
    inspection: WatchdogRuntimeReadback,
}

impl ValidatedWatchdogScmLaunch {
    #[must_use]
    pub fn bootstrap(&self) -> &ServiceBootstrapArguments {
        &self.bootstrap
    }

    #[must_use]
    pub fn registration(&self) -> &ServiceRegistrationRequest {
        &self.registration
    }

    #[must_use]
    pub fn inspection(&self) -> &WatchdogRuntimeReadback {
        &self.inspection
    }
}

/// Opaque Host registration proof retained by the Watchdog observer.
///
/// The contained request is reconstructed from the installer projection and
/// has no public field or nonce accessor. It can therefore cross the library
/// to the binary composition root only as an inspection capability, never as
/// a caller-supplied SCM authority.
#[derive(Clone, Debug)]
pub struct ApprovedHostRegistration {
    request: ServiceRegistrationRequest,
}

impl ApprovedHostRegistration {
    fn from_approval(approval: &InstallerServiceRegistrationApproval) -> Result<Self, SpoolError> {
        if approval.role() != InstallerServiceRole::Host {
            return Err(SpoolError::InvalidLease(
                "installer SCM approval is not a Host registration".to_owned(),
            ));
        }
        let request = approval.service_registration_request().map_err(|_| {
            SpoolError::InvalidLease("installer Host SCM approval is invalid".to_owned())
        })?;
        if request.service_name() != eliot_platform_windows::ELIOT_HOST_SERVICE_NAME {
            return Err(SpoolError::InvalidLease(
                "installer Host SCM approval has the wrong service name".to_owned(),
            ));
        }
        Ok(Self { request })
    }
}

/// Parses the complete argv vector delivered to the SCM service callback.
///
/// `argv[0]` must be the canonical service name and the remaining twelve
/// values must be exactly the ordered bootstrap pairs rendered by
/// [`ServiceBootstrapArguments`], including the installer-approved
/// per-installation Host root and registration nonce. No optional or unknown
/// arguments are accepted for the installed service.
///
/// # Errors
///
/// Returns a typed error when SCM supplies a malformed, reordered, substituted,
/// or incomplete launch vector.
pub fn parse_watchdog_scm_argv<I, S>(
    args: I,
) -> Result<ServiceBootstrapArguments, WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.len() != 13 {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "expected service name plus six canonical pairs".to_owned(),
        ));
    }
    if args[0].to_str() != Some(SERVICE_NAME) {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "service name is not EliotWatchdog".to_owned(),
        ));
    }
    let flag = |index: usize, expected: &str| {
        args.get(index)
            .and_then(|value| value.to_str())
            .is_some_and(|actual| actual == expected)
    };
    if !flag(1, "--config-descriptor")
        || !flag(3, "--config-descriptor-sha256")
        || !flag(5, "--installation-id")
        || !flag(7, "--tx-plan-generation")
        || !flag(9, "--host-state-root")
        || !flag(11, "--registration-nonce")
    {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "bootstrap flags are missing, reordered, or substituted".to_owned(),
        ));
    }

    let descriptor_path = PathBuf::from(&args[2]);
    if !descriptor_path.is_absolute()
        || descriptor_path.as_os_str().is_empty()
        || descriptor_path
            .to_str()
            .is_none_or(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "config descriptor path must be absolute and valid".to_owned(),
        ));
    }
    let host_state_root = PathBuf::from(&args[10]);
    if !host_state_root.is_absolute()
        || host_state_root.as_os_str().is_empty()
        || host_state_root
            .to_str()
            .is_none_or(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "Host state root must be absolute and valid".to_owned(),
        ));
    }
    let text = |index: usize, field: &str| {
        args[index]
            .to_str()
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .map(str::to_owned)
            .ok_or_else(|| {
                WatchdogScmLaunchError::InvalidArgv(format!("{field} is not valid text"))
            })
    };
    let descriptor_digest = text(4, "config descriptor digest")?;
    let installation_id = text(6, "installation id")?;
    let generation_text = text(8, "transaction plan generation")?;
    let registration_nonce = text(12, "registration nonce")?;
    let generation = generation_text.parse::<u64>().map_err(|_| {
        WatchdogScmLaunchError::InvalidArgv(
            "transaction plan generation must be non-zero".to_owned(),
        )
    })?;
    if generation == 0 {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "transaction plan generation must be non-zero".to_owned(),
        ));
    }
    let bootstrap = ServiceBootstrapArguments::new(
        descriptor_path,
        descriptor_digest,
        installation_id,
        generation,
        std::iter::empty::<String>(),
    )
    .map_err(|error| WatchdogScmLaunchError::InvalidArgv(error.to_string()))?
    .with_host_state_root(host_state_root)
    .map_err(|error| WatchdogScmLaunchError::InvalidArgv(error.to_string()))?
    .with_registration_nonce(registration_nonce)
    .map_err(|error| WatchdogScmLaunchError::InvalidArgv(error.to_string()))?;
    Ok(bootstrap)
}

/// Parses the process command line that contains the immutable SCM image-path
/// bootstrap. Windows passes `ServiceMain` a separate argv vector: its
/// `argv[0]` is the service name and its remaining values are only the
/// arguments supplied to `StartService`. See
/// <https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-servicemain>.
///
/// # Errors
///
/// Returns an error when the process arguments do not form the exact
/// canonical bootstrap.
pub fn parse_watchdog_process_argv<I, S>(
    args: I,
) -> Result<ServiceBootstrapArguments, WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut full = vec![OsString::from(SERVICE_NAME)];
    full.extend(args.into_iter().map(Into::into));
    parse_watchdog_scm_argv(full)
}

/// Validates the distinct `ServiceMain` callback argv. Auto-start must provide
/// only the canonical service name; bootstrap values are parsed from the
/// process command line by [`parse_watchdog_process_argv`].
///
/// # Errors
///
/// Returns an error when the callback vector contains anything other than the
/// canonical service name.
pub fn validate_watchdog_service_main_argv<I, S>(args: I) -> Result<(), WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.len() == 1 && args[0].to_str() == Some(SERVICE_NAME) {
        Ok(())
    } else {
        Err(WatchdogScmLaunchError::InvalidArgv(
            "ServiceMain argv must contain only EliotWatchdog".to_owned(),
        ))
    }
}

/// Parses SCM argv, rebuilds the canonical registration request, and performs
/// only the platform adapter's read-only registration inspection.
///
/// # Errors
///
/// Returns an error for malformed argv, an unavailable current executable, or
/// any non-matching/unknown SCM registration. This function never calls an SCM
/// mutation API.
pub fn validate_watchdog_scm_launch<I, S>(
    args: I,
) -> Result<ValidatedWatchdogScmLaunch, WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let bootstrap = parse_watchdog_scm_argv(args)?;
    validate_watchdog_scm_bootstrap(&bootstrap)
}

/// Rebuilds and read-only-inspects the canonical Watchdog SCM registration
/// from the process bootstrap. This is intentionally separate from
/// `ServiceMain` argv validation because the two Windows vectors have
/// different origins and semantics.
///
/// # Errors
///
/// Returns an error when the current executable, canonical registration
/// request, or read-only SCM registration inspection is invalid or unknown.
pub fn validate_watchdog_scm_bootstrap(
    bootstrap: &ServiceBootstrapArguments,
) -> Result<ValidatedWatchdogScmLaunch, WatchdogScmLaunchError> {
    let (_, _, registration) =
        read_approved_service_registration(bootstrap, InstallerServiceRole::Watchdog)
            .map_err(|_| WatchdogScmLaunchError::ApprovalUnavailable)?;
    let executable = std::env::current_exe().map_err(WatchdogScmLaunchError::Executable)?;
    if registration.service_name() != SERVICE_NAME
        || registration.bootstrap() != Some(bootstrap)
        || !windows_paths_equal(registration.binary_path(), &executable)
    {
        return Err(WatchdogScmLaunchError::ApprovalMismatch);
    }
    let root = executable.parent().ok_or_else(|| {
        WatchdogScmLaunchError::InvalidArgv("current executable has no parent".to_owned())
    })?;
    let platform = WindowsPlatform::new(root.to_path_buf())
        .map_err(|error| WatchdogScmLaunchError::PlatformRoot(error.to_string()))?;
    let inspection = project_service_runtime_inspection(
        platform.inspect_service_registration_runtime(&registration),
    );
    if matches!(
        inspection,
        WatchdogRuntimeReadback::Absent | WatchdogRuntimeReadback::Mismatched
    ) {
        return Err(WatchdogScmLaunchError::Registration(inspection));
    }
    Ok(ValidatedWatchdogScmLaunch {
        bootstrap: bootstrap.clone(),
        registration,
        inspection,
    })
}

/// Installation-owned Watchdog admission configuration. It is loaded from
/// fixed children of the installer-approved per-installation Host root and
/// independently bound to the active registry manifest digest; no value is
/// selected from the lease envelope.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogAdmissionConfig {
    /// Strict admission-config schema marker.
    pub schema: String,
    /// Installation identity expected by the service environment.
    pub installation_id: String,
    /// Active approved generation identity.
    pub approved_generation: String,
    /// External installation-pinned trust anchor.
    pub trust_anchor: SupervisionTrustAnchor,
    /// Independently configured current lease verification values.
    pub context: SupervisionLeaseVerificationContext,
}

impl WatchdogAdmissionConfig {
    fn validate_shape(&self) -> Result<(), SpoolError> {
        if self.schema != ADMISSION_CONFIG_SCHEMA {
            return Err(SpoolError::InvalidLease(
                "watchdog admission config schema is unsupported".to_owned(),
            ));
        }
        validate_text(&self.installation_id, "admission.installation_id")?;
        validate_text(&self.approved_generation, "admission.approved_generation")?;
        self.trust_anchor
            .validate()
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
        let mut context = self.context.clone();
        context.now_ms = 1;
        context
            .validate()
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))
    }
}

/// Verified admission result.  Only the authenticated lease crosses into the
/// Watchdog composition; the independently configured epoch is retained only
/// to seed the sensor's decision clock.
pub struct VerifiedWatchdogAdmission {
    lease: VerifiedSupervisionLease,
    watchdog_epoch: AuthorityEpoch,
}

impl VerifiedWatchdogAdmission {
    /// Returns the authenticated lease newtype.
    #[must_use]
    pub fn lease(&self) -> &VerifiedSupervisionLease {
        &self.lease
    }

    /// Returns the independently configured Watchdog epoch.
    #[must_use]
    pub const fn watchdog_epoch(&self) -> AuthorityEpoch {
        self.watchdog_epoch
    }
}

/// Installation-backed admission source.  A composition must call this for
/// every observation; the returned verified lease is never retained as a
/// long-lived authority by the watchdog loop.
pub trait WatchdogAdmissionSource: Send + Sync + 'static {
    /// Reloads and verifies the current short-lived supervision authority.
    ///
    /// # Errors
    ///
    /// Returns an error if any lease, trust, configuration, registry, or time
    /// binding is unavailable or fails validation.
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError>;

    /// Returns the immutable Host image bound to the active generation, when
    /// this admission source has one. A production source must provide it
    /// before constructing the live Host observer.
    #[must_use]
    fn approved_host_image(&self) -> Option<PathBuf> {
        None
    }

    /// Returns the immutable installer approval used to reconstruct the exact
    /// Host SCM request, when this admission source has one.
    #[must_use]
    fn approved_host_registration(&self) -> Option<ApprovedHostRegistration> {
        None
    }
}

/// File-backed admission source for the Host/Kernel lease and its independent
/// trust/configuration/registry inputs.
#[allow(
    clippy::struct_field_names,
    reason = "the explicit path suffix distinguishes three independently protected filesystem inputs"
)]
pub struct FileWatchdogAdmission {
    lease_path: PathBuf,
    admission_config_path: PathBuf,
    registry_path: PathBuf,
    installation_id: String,
    roots_digest: String,
    bootstrap: ServiceBootstrapArguments,
    binding: WatchdogRuntimeBinding,
}

/// Approved runtime roots plus the retained no-follow leases that prove them.
#[derive(Clone)]
pub struct WatchdogRuntimeBinding {
    /// Canonical installer-approved Host root selected by SCM and the
    /// registry manifest.
    host_state_root: PathBuf,
    roots: RuntimeStateRoots,
    selected_manifest: Arc<CandidateManifest>,
    approved_host_image: PathBuf,
    approved_host_registration: ApprovedHostRegistration,
    approved_watchdog_registration: ServiceRegistrationRequest,
    /// Retained for the complete lifetime of the admission and sensor. This
    /// is the no-follow proof that the Host-state contour cannot be replaced
    /// underneath path-based redb/file consumers.
    host_state_root_lease: Arc<ProtectedRootLease>,
    _approved_host_image_lease: Arc<ProtectedPathLease>,
    _root_leases: Arc<ValidatedRuntimeRootLeases<WindowsRuntimeRootLease>>,
}

impl WatchdogRuntimeBinding {
    /// Returns the canonical installer-approved Host state root.
    #[must_use]
    pub fn host_state_root(&self) -> &Path {
        &self.host_state_root
    }

    #[must_use]
    pub fn watchdog_state_root(&self) -> &Path {
        Path::new(self.roots.watchdog_state_root.as_str())
    }

    /// Returns the immutable `eliot-host.exe` sibling derived from the active
    /// generation's approved Watchdog image path.
    #[must_use]
    pub fn approved_host_image(&self) -> &Path {
        &self.approved_host_image
    }
}

impl FileWatchdogAdmission {
    /// # Errors
    ///
    /// Returns an error when the registry is missing, invalid, has no exact
    /// bootstrap-selected active/pending contour, or its runtime roots cannot
    /// be retained and validated.
    pub fn from_registry(
        lease_path: impl Into<PathBuf>,
        admission_config_path: impl Into<PathBuf>,
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
        let lease_path = lease_path.into();
        let admission_config_path = admission_config_path.into();
        let registry_path = registry_path.into();
        let (installation_id, binding) = load_runtime_binding(&registry_path, &bootstrap)?;
        validate_host_admission_paths(
            &binding,
            &lease_path,
            &admission_config_path,
            &registry_path,
        )?;
        Ok(Self {
            lease_path,
            admission_config_path,
            registry_path,
            installation_id,
            roots_digest: binding.roots.roots_digest.as_str().to_owned(),
            bootstrap,
            binding,
        })
    }

    /// # Errors
    ///
    /// Returns an error when the registry is missing, invalid, has no exact
    /// bootstrap-selected active/pending contour, or its runtime roots cannot
    /// be retained and validated.
    pub fn new(
        lease_path: impl Into<PathBuf>,
        admission_config_path: impl Into<PathBuf>,
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
        Self::from_registry(lease_path, admission_config_path, registry_path, bootstrap)
    }

    #[must_use]
    pub fn runtime_binding(&self) -> WatchdogRuntimeBinding {
        self.binding.clone()
    }
}

impl WatchdogAdmissionSource for FileWatchdogAdmission {
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
        load_supervision_lease_bound(self)
    }

    fn approved_host_image(&self) -> Option<PathBuf> {
        Some(self.binding.approved_host_image().to_owned())
    }

    fn approved_host_registration(&self) -> Option<ApprovedHostRegistration> {
        Some(self.binding.approved_host_registration.clone())
    }
}

/// Errors from the independent protected watchdog spool.
#[derive(Debug, Error)]
pub enum SpoolError {
    #[error("watchdog spool I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("watchdog spool path is not the canonical protected path")]
    InvalidProtectedRoot,
    #[error("watchdog spool serialization: {0}")]
    Serialization(String),
    #[error("watchdog spool redb database: {0}")]
    Database(String),
    #[error("watchdog spool corruption requires recovery: {0}")]
    Corrupt(String),
    #[error("watchdog lease is unavailable or invalid: {0}")]
    InvalidLease(String),
    #[error("watchdog lease is stale: {0}")]
    LeaseStale(String),
    #[error("watchdog lease is fenced: {0}")]
    LeaseFenced(String),
}

const SPOOL_SCHEMA_VERSION: u16 = 1;
const SPOOL_HEADER_KEY: u64 = 0;
const SPOOL_MAX_RECORDS: u64 = 4096;
const SPOOL_MAX_BYTES: u64 = 4 * 1024 * 1024;
const SPOOL_MAX_RECORD_BYTES: usize = 64 * 1024;
const SPOOL_RELATIVE_PATH: &str = "Eliot/watchdog/watchdog.redb";
const SPOOL_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("eliot_watchdog_spool_v1");
// The high-water record deliberately lives in a different redb table from
// the bounded observation records.  A damaged header or record must not be
// able to make recovery reuse an identity that was already allocated.
const SPOOL_HIGH_WATER_KEY: u64 = 0;
const SPOOL_HIGH_WATER_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_high_water_v1");

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogSpoolHeader {
    schema_version: u16,
    next_sequence: u64,
    first_sequence: u64,
    record_count: u64,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogSpoolHighWater {
    schema_version: u16,
    high_water_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatchdogSpoolPayload {
    Heartbeat {
        service: String,
        lease_id: String,
        scope_ref: String,
        kernel_epoch: u64,
        watchdog_epoch: u64,
        payload_digest: String,
        envelope_digest: String,
        signer_id: String,
        key_id: String,
        signature_algorithm: String,
        signature: String,
        public_key_fingerprint: String,
        lease_revision: u64,
    },
    Gap {
        service: String,
        reason: GapRecoveryReason,
        coverage_claimed: bool,
    },
    Recovery {
        service: String,
        reason: String,
        corrupt_sequence: Option<u64>,
        corrupt_digest: String,
    },
}

/// One typed, ordered and bounded Watchdog spool record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogSpoolEntry {
    pub schema_version: u16,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub payload: WatchdogSpoolPayload,
}

#[derive(Debug)]
struct WatchdogSpool {
    database: Database,
    _path_lease: Option<ProtectedPathLease>,
}

impl WatchdogSpool {
    fn open_runtime_binding(binding: &WatchdogRuntimeBinding) -> Result<Self, SpoolError> {
        let root = binding.watchdog_state_root();
        let path = root.join("watchdog.redb");
        let program_data =
            protected_program_data_root().map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let relative = runtime_spool_relative_path(&path, &program_data)?;
        let path_lease = ProtectedPathLease::open_or_create(relative)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let spool = Self {
            database,
            _path_lease: Some(path_lease),
        };
        spool.initialize_or_recover()?;
        Ok(spool)
    }

    #[cfg(test)]
    fn open_test(path: &Path) -> Result<Self, SpoolError> {
        let database =
            Database::create(path).map_err(|error| SpoolError::Database(error.to_string()))?;
        let spool = Self {
            database,
            _path_lease: None,
        };
        spool.initialize_or_recover()?;
        Ok(spool)
    }

    fn readback(&self) -> Result<Vec<WatchdogSpoolEntry>, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let header: WatchdogSpoolHeader = serde_json::from_slice(header.value())
            .map_err(|error| SpoolError::Corrupt(format!("invalid spool header: {error}")))?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let high_water = read_high_water(&high_water)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water(&header, &entries, high_water)?;
        Ok(entries)
    }

    fn initialize_or_recover(&self) -> Result<(), SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                drop(read);
                return self.write_header(&WatchdogSpoolHeader {
                    schema_version: SPOOL_SCHEMA_VERSION,
                    next_sequence: 1,
                    first_sequence: 1,
                    record_count: 0,
                    bytes: 0,
                });
            }
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let entries = collect_entries(&table);
        let parsed_header = header
            .as_ref()
            .and_then(|value| serde_json::from_slice::<WatchdogSpoolHeader>(value.value()).ok());
        let high_water_table = match read.open_table(SPOOL_HIGH_WATER_TABLE) {
            Ok(table) => Some(table),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let parsed_high_water = high_water_table
            .as_ref()
            .map(read_high_water)
            .transpose()?
            .flatten();
        let header_and_entries_valid = parsed_header
            .as_ref()
            .zip(entries.as_ref().ok())
            .is_some_and(|(header, entries)| validate_header(header, entries).is_ok());
        let valid = header_and_entries_valid
            && parsed_high_water.is_some_and(|high_water| {
                parsed_header
                    .as_ref()
                    .zip(entries.as_ref().ok())
                    .is_some_and(|(header, entries)| {
                        validate_high_water(header, entries, high_water).is_ok()
                    })
            });
        if valid {
            return Ok(());
        }
        if header_and_entries_valid
            && let Some(high_water) = parsed_high_water
            && let Some((header, entries)) = parsed_header.as_ref().zip(entries.as_ref().ok())
        {
            validate_high_water(header, entries, high_water)?;
        }
        let corrupt_digest = header
            .as_ref()
            .map_or_else(|| "missing".to_owned(), |value| sha256_hex(value.value()));
        drop(table);
        drop(read);
        self.recover(
            "existing spool header or record set failed validation",
            None,
            corrupt_digest,
        )
    }

    fn write_header(&self, header: &WatchdogSpoolHeader) -> Result<(), SpoolError> {
        let bytes = serde_json::to_vec(header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        let high_water = header.next_sequence.saturating_sub(1);
        let high_water_bytes = encode_high_water(high_water)?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(SPOOL_HEADER_KEY, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(table);
            let mut high_water_table = write
                .open_table(SPOOL_HIGH_WATER_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            high_water_table
                .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(high_water_table);
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    fn recover(
        &self,
        reason: &str,
        corrupt_sequence: Option<u64>,
        corrupt_digest: String,
    ) -> Result<(), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is missing; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let previous_high_water = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let previous_high_water = decode_high_water(&previous_high_water)?;
        let recovery_sequence = previous_high_water
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?;
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence: recovery_sequence,
            observed_at_ms: current_unix_ms()?.max(1),
            payload: WatchdogSpoolPayload::Recovery {
                service: SERVICE_NAME.to_owned(),
                reason: reason.to_owned(),
                corrupt_sequence,
                corrupt_digest,
            },
        };
        let bytes = encode_entry(&entry)?;
        let header = WatchdogSpoolHeader {
            schema_version: SPOOL_SCHEMA_VERSION,
            next_sequence: recovery_sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?,
            first_sequence: recovery_sequence,
            record_count: 1,
            bytes: bytes.len() as u64,
        };
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let keys = table
                .iter()
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .map(|item| {
                    item.map(|(key, _)| key.value())
                        .map_err(|error| SpoolError::Database(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if keys
                .iter()
                .filter(|key| **key != SPOOL_HEADER_KEY)
                .any(|key| *key > previous_high_water)
            {
                return Err(SpoolError::Corrupt(
                    "high-water metadata is below a retained sequence; continuity cannot be proven"
                        .to_owned(),
                ));
            }
            for key in keys {
                table
                    .remove(key)
                    .map_err(|error| SpoolError::Database(error.to_string()))?;
            }
            table
                .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(entry.sequence, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let high_water_bytes = encode_high_water(recovery_sequence)?;
            high_water_table
                .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(table);
        }
        drop(high_water_table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    fn append(&self, observed_at_ms: u64, payload: WatchdogSpoolPayload) -> Result<(), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut table = write
            .open_table(SPOOL_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is unavailable; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let mut header: WatchdogSpoolHeader = serde_json::from_slice(&header_bytes)
            .map_err(|error| SpoolError::Corrupt(format!("invalid spool header: {error}")))?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let high_water = decode_high_water(&high_water)?;
        validate_high_water(&header, &entries, high_water)?;
        let sequence = high_water
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?;
        if sequence != header.next_sequence {
            return Err(SpoolError::Corrupt(
                "spool header next sequence does not match high-water metadata".to_owned(),
            ));
        }
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence,
            observed_at_ms,
            payload,
        };
        let bytes = encode_entry(&entry)?;
        while header.record_count >= SPOOL_MAX_RECORDS
            || header.bytes.saturating_add(bytes.len() as u64) > SPOOL_MAX_BYTES
        {
            if header.record_count == 0 {
                break;
            }
            let old_sequence = header.first_sequence;
            let old = table
                .remove(old_sequence)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .ok_or_else(|| SpoolError::Corrupt("retention record is missing".to_owned()))?;
            header.bytes = header
                .bytes
                .checked_sub(old.value().len() as u64)
                .ok_or_else(|| SpoolError::Corrupt("spool byte counter underflow".to_owned()))?;
            header.first_sequence = old_sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
            header.record_count -= 1;
        }
        table
            .insert(sequence, bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        header.schema_version = SPOOL_SCHEMA_VERSION;
        header.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
        if header.record_count == 0 {
            header.first_sequence = sequence;
        }
        header.record_count += 1;
        header.bytes = header
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| SpoolError::Corrupt("spool byte counter overflow".to_owned()))?;
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        table
            .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let high_water_bytes = encode_high_water(sequence)?;
        high_water_table
            .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        drop(table);
        drop(high_water_table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }
}

fn runtime_spool_relative_path(path: &Path, program_data: &Path) -> Result<PathBuf, SpoolError> {
    path.strip_prefix(program_data)
        .map(Path::to_path_buf)
        .map_err(|_| SpoolError::InvalidProtectedRoot)
}

fn encode_entry(entry: &WatchdogSpoolEntry) -> Result<Vec<u8>, SpoolError> {
    let bytes =
        serde_json::to_vec(entry).map_err(|error| SpoolError::Serialization(error.to_string()))?;
    if bytes.len() > SPOOL_MAX_RECORD_BYTES {
        return Err(SpoolError::Serialization(
            "watchdog spool record exceeds the bounded frame size".to_owned(),
        ));
    }
    Ok(bytes)
}

fn encode_high_water(sequence: u64) -> Result<Vec<u8>, SpoolError> {
    serde_json::to_vec(&WatchdogSpoolHighWater {
        schema_version: SPOOL_SCHEMA_VERSION,
        high_water_sequence: sequence,
    })
    .map_err(|error| SpoolError::Serialization(error.to_string()))
}

fn decode_high_water(bytes: &[u8]) -> Result<u64, SpoolError> {
    let high_water: WatchdogSpoolHighWater = serde_json::from_slice(bytes)
        .map_err(|error| SpoolError::Corrupt(format!("invalid high-water metadata: {error}")))?;
    if high_water.schema_version != SPOOL_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(
            "high-water metadata schema is unsupported".to_owned(),
        ));
    }
    Ok(high_water.high_water_sequence)
}

fn read_high_water<T>(table: &T) -> Result<Option<u64>, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    table
        .get(SPOOL_HIGH_WATER_KEY)
        .map_err(|error| SpoolError::Database(error.to_string()))?
        .map(|value| decode_high_water(value.value()))
        .transpose()
}

fn collect_entries<T>(table: &T) -> Result<Vec<WatchdogSpoolEntry>, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    let mut entries = Vec::new();
    for item in table
        .iter()
        .map_err(|error| SpoolError::Database(error.to_string()))?
    {
        let (key, value) = item.map_err(|error| SpoolError::Database(error.to_string()))?;
        if key.value() == SPOOL_HEADER_KEY {
            continue;
        }
        if value.value().len() > SPOOL_MAX_RECORD_BYTES {
            return Err(SpoolError::Corrupt(format!(
                "record {} exceeds the bounded frame size",
                key.value()
            )));
        }
        let entry: WatchdogSpoolEntry = serde_json::from_slice(value.value()).map_err(|error| {
            SpoolError::Corrupt(format!("record {} is invalid: {error}", key.value()))
        })?;
        if entry.schema_version != SPOOL_SCHEMA_VERSION || entry.sequence != key.value() {
            return Err(SpoolError::Corrupt(format!(
                "record {} has an invalid schema or sequence",
                key.value()
            )));
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.sequence);
    Ok(entries)
}

fn validate_header(
    header: &WatchdogSpoolHeader,
    entries: &[WatchdogSpoolEntry],
) -> Result<(), SpoolError> {
    if header.schema_version != SPOOL_SCHEMA_VERSION
        || header.next_sequence == 0
        || header.first_sequence == 0
        || header.record_count != entries.len() as u64
        || header.record_count > SPOOL_MAX_RECORDS
        || header.bytes > SPOOL_MAX_BYTES
        || entries
            .iter()
            .map(|entry| serde_json::to_vec(entry).map(|bytes| bytes.len() as u64))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| SpoolError::Serialization(error.to_string()))?
            .into_iter()
            .sum::<u64>()
            != header.bytes
    {
        return Err(SpoolError::Corrupt(
            "spool header counters or schema are inconsistent".to_owned(),
        ));
    }
    let expected_first = entries
        .first()
        .map_or(header.next_sequence, |entry| entry.sequence);
    if header.first_sequence != expected_first
        || entries
            .windows(2)
            .any(|window| window[1].sequence <= window[0].sequence)
        || entries
            .last()
            .is_some_and(|entry| entry.sequence >= header.next_sequence)
    {
        return Err(SpoolError::Corrupt(
            "spool sequence ordering is inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_high_water(
    header: &WatchdogSpoolHeader,
    entries: &[WatchdogSpoolEntry],
    high_water: u64,
) -> Result<(), SpoolError> {
    let expected = header
        .next_sequence
        .checked_sub(1)
        .ok_or_else(|| SpoolError::Corrupt("spool header next sequence is invalid".to_owned()))?;
    let last = entries.last().map_or(0, |entry| entry.sequence);
    if high_water != expected || high_water < last {
        return Err(SpoolError::Corrupt(
            "high-water metadata does not bind the spool sequence".to_owned(),
        ));
    }
    Ok(())
}

/// Bounded, non-authoritative record emitted when admission is lost.  A gap
/// never claims coverage and carries no replacement trust material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GapRecoveryReason {
    AdmissionUnavailable,
    LeaseStale,
    LeaseInvalid,
    LeaseFenced,
    HostAbsentOrStopped,
    HostPidReused,
    HostImageSubstituted,
    HostIdentityChanged,
    HostUnknown,
}

fn admission_gap_reason(error: &SpoolError) -> GapRecoveryReason {
    match error {
        SpoolError::LeaseStale(_) => GapRecoveryReason::LeaseStale,
        SpoolError::LeaseFenced(_) => GapRecoveryReason::LeaseFenced,
        SpoolError::InvalidLease(_) => GapRecoveryReason::LeaseInvalid,
        _ => GapRecoveryReason::AdmissionUnavailable,
    }
}

fn kernel_gap_reason(error: &KernelWatchdogError) -> GapRecoveryReason {
    match error {
        KernelWatchdogError::LeaseStale => GapRecoveryReason::LeaseStale,
        KernelWatchdogError::LeaseFenced => GapRecoveryReason::LeaseFenced,
        _ => GapRecoveryReason::LeaseInvalid,
    }
}

/// Result of one read-only Host liveness observation.  This is evidence only;
/// it never grants authority to start, stop, restart, or kill a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostObservation {
    pub state: HostObservationState,
    pub identity: Option<ProcessIdentity>,
}

impl HostObservation {
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, HostObservationState::Running)
    }

    #[must_use]
    pub const fn gap_reason(&self) -> Option<GapRecoveryReason> {
        match self.state {
            HostObservationState::Running => None,
            HostObservationState::AbsentOrStopped => Some(GapRecoveryReason::HostAbsentOrStopped),
            HostObservationState::PidReused => Some(GapRecoveryReason::HostPidReused),
            HostObservationState::ImageSubstituted => Some(GapRecoveryReason::HostImageSubstituted),
            HostObservationState::IdentityChanged => Some(GapRecoveryReason::HostIdentityChanged),
            HostObservationState::Unknown => Some(GapRecoveryReason::HostUnknown),
        }
    }
}

/// Process-identity state machine used by the Watchdog's read-only Host sensor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostObservationState {
    Running,
    AbsentOrStopped,
    PidReused,
    ImageSubstituted,
    IdentityChanged,
    Unknown,
}

/// Provider-neutral lifecycle state projected from one Windows SCM runtime
/// observation. The projection keeps the Watchdog composition independent of
/// the lower-level `eliot-platform` crate while preserving every state needed
/// by bounded self-admission and Host liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogRuntimeState {
    Absent,
    Stopped,
    Starting,
    Running,
    Stopping,
    Unknown,
}

/// One atomic read-only SCM registration/runtime readback. The `Matching`
/// variant already contains the configuration, lifecycle state, and
/// handle-bound process identity from one platform query; callers must not
/// reconstruct a second status/PID observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogRuntimeReadback {
    Matching {
        state: WatchdogRuntimeState,
        process: Option<ProcessIdentity>,
        checkpoint: u32,
        wait_hint_ms: u32,
    },
    Absent,
    Mismatched,
    Unknown,
}

/// Projects the Windows runtime seam into the small state surface used by
/// Watchdog. The Windows adapter has already checked the complete service
/// configuration and, when required by the service state, captured process
/// PID, creation time, and image path through a live process handle.
#[must_use]
pub fn project_service_runtime_inspection(
    inspection: ServiceRegistrationRuntimeInspection,
) -> WatchdogRuntimeReadback {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation } => {
            let state = if observation.is_starting() {
                WatchdogRuntimeState::Starting
            } else if observation.is_running() {
                WatchdogRuntimeState::Running
            } else if observation.is_stopping() {
                WatchdogRuntimeState::Stopping
            } else if observation.is_stopped() {
                WatchdogRuntimeState::Stopped
            } else {
                WatchdogRuntimeState::Unknown
            };
            WatchdogRuntimeReadback::Matching {
                state,
                process: observation.process().cloned(),
                checkpoint: observation.checkpoint(),
                wait_hint_ms: observation.wait_hint_ms(),
            }
        }
        ServiceRegistrationRuntimeInspection::Absent => WatchdogRuntimeReadback::Absent,
        ServiceRegistrationRuntimeInspection::Mismatched => WatchdogRuntimeReadback::Mismatched,
        ServiceRegistrationRuntimeInspection::Unknown => WatchdogRuntimeReadback::Unknown,
    }
}

/// Fixed maximum interval in which the Watchdog may remain in
/// `SERVICE_START_PENDING` while it reconciles its own SCM runtime identity.
pub const WATCHDOG_SELF_ADMISSION_DEADLINE_MS: u64 = 30_000;
const SELF_ADMISSION_MIN_POLL_MS: u32 = 25;
const SELF_ADMISSION_MAX_POLL_MS: u32 = 250;
const SELF_ADMISSION_DEFAULT_WAIT_HINT_MS: u32 = 250;

/// Fail-closed outcomes for the bounded Watchdog self-admission gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum WatchdogSelfAdmissionError {
    #[error("current Watchdog process identity is unavailable")]
    CurrentProcessUnavailable,
    #[error("Watchdog SCM registration is absent during self-admission")]
    RegistrationAbsent,
    #[error("Watchdog SCM registration or process identity mismatched during self-admission")]
    RegistrationMismatched,
    #[error("Watchdog SCM service stopped before self-admission")]
    ServiceStopped,
    #[error("Watchdog SCM service is stopping during self-admission")]
    ServiceStopping,
    #[error("Watchdog SCM self-admission timed out after the bounded deadline")]
    Timeout,
}

/// Injectable read-only mechanics used by the bounded self-admission loop.
/// Production supplies the Windows SCM runtime inspection and a monotonic
/// clock; tests supply a deterministic sequence without sleeping 30 seconds.
pub trait WatchdogSelfAdmissionProbe {
    fn now_ms(&mut self) -> u64;
    fn current_process_identity(&mut self) -> Option<ProcessIdentity>;
    fn inspect(&mut self) -> WatchdogRuntimeReadback;
    fn sleep_ms(&mut self, milliseconds: u32);
}

/// Injectable SCM status publisher for the self-admission loop. It is limited
/// to progress updates while the service is already `START_PENDING`; it has
/// no start/stop or registration mutation capability.
pub trait WatchdogSelfAdmissionStatus {
    fn report_start_pending(&mut self, checkpoint: u32, wait_hint_ms: u32);
}

/// Performs the production bounded self-admission with the fixed 30-second
/// deadline required by the Runtime Live service contract.
///
/// # Errors
///
/// Returns a fail-closed error when the current process identity cannot be
/// observed, the SCM registration is absent/mismatched/stopped, or the
/// bounded deadline expires before an exact `Starting`/`Running` match.
pub fn admit_watchdog_self_start<P, S>(
    probe: &mut P,
    status: &mut S,
) -> Result<ProcessIdentity, WatchdogSelfAdmissionError>
where
    P: WatchdogSelfAdmissionProbe,
    S: WatchdogSelfAdmissionStatus,
{
    admit_watchdog_self_start_with_deadline(probe, status, WATCHDOG_SELF_ADMISSION_DEADLINE_MS)
}

/// Testable form of [`admit_watchdog_self_start`] with a bounded injected
/// deadline. The production entry point always uses the fixed 30-second
/// value above; this form exists only to make timeout and transient-unknown
/// behavior deterministic in unit tests.
///
/// # Errors
///
/// Returns a fail-closed error when the current process identity cannot be
/// observed, the SCM registration is absent/mismatched/stopped, or the
/// injected deadline expires before an exact `Starting`/`Running` match.
pub fn admit_watchdog_self_start_with_deadline<P, S>(
    probe: &mut P,
    status: &mut S,
    deadline_ms: u64,
) -> Result<ProcessIdentity, WatchdogSelfAdmissionError>
where
    P: WatchdogSelfAdmissionProbe,
    S: WatchdogSelfAdmissionStatus,
{
    let expected = probe
        .current_process_identity()
        .ok_or(WatchdogSelfAdmissionError::CurrentProcessUnavailable)?;
    let started_at = probe.now_ms();
    let deadline = started_at.saturating_add(deadline_ms);
    let mut checkpoint = 1u32;

    loop {
        let now = probe.now_ms();
        if now >= deadline {
            return Err(WatchdogSelfAdmissionError::Timeout);
        }
        let observation = probe.inspect();
        let wait_hint_ms = match observation {
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Starting | WatchdogRuntimeState::Running,
                process: Some(ref actual),
                ..
            } if same_process_identity(actual, &expected) => {
                if probe.now_ms() >= deadline {
                    return Err(WatchdogSelfAdmissionError::Timeout);
                }
                return Ok(actual.clone());
            }
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Starting | WatchdogRuntimeState::Running,
                process: Some(_),
                ..
            }
            | WatchdogRuntimeReadback::Mismatched => {
                return Err(WatchdogSelfAdmissionError::RegistrationMismatched);
            }
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Stopped,
                ..
            } => return Err(WatchdogSelfAdmissionError::ServiceStopped),
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Stopping,
                ..
            } => return Err(WatchdogSelfAdmissionError::ServiceStopping),
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Absent,
                ..
            } => return Err(WatchdogSelfAdmissionError::RegistrationAbsent),
            WatchdogRuntimeReadback::Absent => {
                return Err(WatchdogSelfAdmissionError::RegistrationAbsent);
            }
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Starting | WatchdogRuntimeState::Running,
                process: None,
                wait_hint_ms,
                ..
            }
            | WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Unknown,
                wait_hint_ms,
                ..
            } => wait_hint_ms,
            WatchdogRuntimeReadback::Unknown => 0,
        };

        let wait_hint_ms = bounded_wait_hint_ms(wait_hint_ms);
        let remaining_ms = deadline.saturating_sub(probe.now_ms());
        if remaining_ms == 0 {
            return Err(WatchdogSelfAdmissionError::Timeout);
        }
        let status_wait_hint_ms = wait_hint_ms.min(u32::try_from(remaining_ms).unwrap_or(u32::MAX));
        checkpoint = checkpoint.saturating_add(1);
        status.report_start_pending(checkpoint, status_wait_hint_ms);
        let poll_ms = u64::from(bounded_poll_ms(wait_hint_ms)).min(remaining_ms);
        probe.sleep_ms(u32::try_from(poll_ms).unwrap_or(u32::MAX));
    }
}

fn bounded_wait_hint_ms(wait_hint_ms: u32) -> u32 {
    if wait_hint_ms == 0 {
        SELF_ADMISSION_DEFAULT_WAIT_HINT_MS
    } else {
        wait_hint_ms.clamp(SELF_ADMISSION_MIN_POLL_MS, 1_000)
    }
}

fn bounded_poll_ms(wait_hint_ms: u32) -> u32 {
    wait_hint_ms
        .saturating_div(4)
        .clamp(SELF_ADMISSION_MIN_POLL_MS, SELF_ADMISSION_MAX_POLL_MS)
}

fn same_process_identity(observed: &ProcessIdentity, expected: &ProcessIdentity) -> bool {
    observed.process_id == expected.process_id
        && observed.start_time_100ns == expected.start_time_100ns
        && windows_paths_equal(
            Path::new(&observed.image_path),
            Path::new(&expected.image_path),
        )
}

/// Retains the last trusted Host process identity and compares every later
/// platform observation against PID, creation time, and image path.
#[derive(Debug)]
pub struct HostIdentityMonitor {
    canonical: Option<ProcessIdentity>,
    expected_image: Option<PathBuf>,
    expected_registration: Option<ApprovedHostRegistration>,
    expected_image_lease: Option<ProtectedPathLease>,
    require_image_lease: bool,
    require_registration_readback: bool,
}

impl HostIdentityMonitor {
    #[must_use]
    pub fn new(expected_image: Option<PathBuf>) -> Self {
        Self {
            canonical: None,
            expected_image,
            expected_registration: None,
            expected_image_lease: None,
            require_image_lease: false,
            require_registration_readback: false,
        }
    }

    fn with_approved_image_lease(
        expected_image: PathBuf,
        lease: ProtectedPathLease,
        expected_registration: ApprovedHostRegistration,
    ) -> Self {
        Self {
            canonical: None,
            expected_image: Some(expected_image),
            expected_registration: Some(expected_registration),
            expected_image_lease: Some(lease),
            require_image_lease: true,
            require_registration_readback: true,
        }
    }

    fn with_unavailable_image_lease(
        expected_image: PathBuf,
        expected_registration: ApprovedHostRegistration,
    ) -> Self {
        Self {
            canonical: None,
            expected_image: Some(expected_image),
            expected_registration: Some(expected_registration),
            expected_image_lease: None,
            require_image_lease: true,
            require_registration_readback: true,
        }
    }

    #[must_use]
    pub fn canonical_identity(&self) -> Option<&ProcessIdentity> {
        self.canonical.as_ref()
    }

    /// Clears the prior process identity after a fresh lease has been
    /// independently verified. A new process is never trusted merely because
    /// it appeared; the caller must establish the lease boundary first.
    pub fn rebaseline(&mut self) {
        self.canonical = None;
    }

    /// Observes the canonical `EliotHost` service through the existing Windows
    /// runtime readback primitive and classifies all non-authoritative
    /// outcomes. Configuration and process identity are read atomically from
    /// one SCM query; a second status/PID query is deliberately not used.
    #[must_use]
    pub fn observe(&mut self) -> HostObservation {
        if self.require_image_lease
            && self.expected_image_lease.is_none()
            && let Some(expected_image) = self.expected_image.as_deref()
            && let Ok(lease) = ProtectedPathLease::open_existing_absolute(expected_image)
        {
            self.expected_image_lease = Some(lease);
        }
        if self.require_image_lease
            && (self.expected_image_lease.is_none()
                || self.expected_image_lease.as_ref().is_some_and(|lease| {
                    lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err()
                }))
        {
            return HostObservation {
                state: HostObservationState::Unknown,
                identity: None,
            };
        }
        if self.require_registration_readback {
            let runtime = self.expected_registration.as_ref().map_or(
                WatchdogRuntimeReadback::Unknown,
                read_host_registration_runtime,
            );
            return self.observe_runtime_readback(runtime);
        }
        HostObservation {
            state: HostObservationState::Unknown,
            identity: None,
        }
    }

    #[must_use]
    fn observe_runtime_readback(&mut self, runtime: WatchdogRuntimeReadback) -> HostObservation {
        match runtime {
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Running,
                process: Some(process),
                ..
            } => self.observe_process_identity(process),
            WatchdogRuntimeReadback::Matching {
                state:
                    WatchdogRuntimeState::Stopped
                    | WatchdogRuntimeState::Starting
                    | WatchdogRuntimeState::Stopping,
                ..
            }
            | WatchdogRuntimeReadback::Absent => HostObservation {
                state: HostObservationState::AbsentOrStopped,
                identity: None,
            },
            WatchdogRuntimeReadback::Matching {
                state:
                    WatchdogRuntimeState::Absent
                    | WatchdogRuntimeState::Running
                    | WatchdogRuntimeState::Unknown,
                ..
            }
            | WatchdogRuntimeReadback::Mismatched
            | WatchdogRuntimeReadback::Unknown => HostObservation {
                state: HostObservationState::Unknown,
                identity: None,
            },
        }
    }

    /// Applies one sealed platform identity. This small seam keeps PID-reuse
    /// and image-substitution tests independent from a live SCM installation.
    #[must_use]
    pub fn observe_identity(&mut self, binding: &NamedPipePeerProcessBinding) -> HostObservation {
        self.observe_process_identity(binding.identity().clone())
    }

    #[must_use]
    fn observe_process_identity(&mut self, observed: ProcessIdentity) -> HostObservation {
        if self
            .expected_image
            .as_deref()
            .is_some_and(|expected| !windows_paths_equal(Path::new(&observed.image_path), expected))
        {
            return HostObservation {
                state: HostObservationState::ImageSubstituted,
                identity: Some(observed),
            };
        }
        let Some(canonical) = self.canonical.as_ref() else {
            self.canonical = Some(observed.clone());
            return HostObservation {
                state: HostObservationState::Running,
                identity: Some(observed),
            };
        };
        let state = if observed.process_id == canonical.process_id
            && observed.start_time_100ns != canonical.start_time_100ns
        {
            HostObservationState::PidReused
        } else if observed.process_id == canonical.process_id
            && observed.start_time_100ns == canonical.start_time_100ns
            && !windows_paths_equal(
                Path::new(&observed.image_path),
                Path::new(&canonical.image_path),
            )
        {
            HostObservationState::ImageSubstituted
        } else if observed == *canonical {
            HostObservationState::Running
        } else {
            HostObservationState::IdentityChanged
        };
        HostObservation {
            state,
            identity: Some(observed),
        }
    }
}

#[cfg(test)]
#[must_use]
fn classify_host_error(error: WindowsAdapterError) -> HostObservationState {
    match error {
        WindowsAdapterError::Unavailable => HostObservationState::AbsentOrStopped,
        _ => HostObservationState::Unknown,
    }
}

/// Source of read-only Host process observations.
pub trait HostObservationSource: Send + Sync + 'static {
    fn observe(&self) -> HostObservation;

    /// Permits a process-identity rebaseline only after the composition has
    /// verified a fresh supervision lease. The default is deliberately a
    /// no-op for test/read-only sources.
    fn rebaseline_after_verified_lease(&self, _lease: &VerifiedSupervisionLease) {}
}

/// Production observation source backed by the canonical `EliotHost` SCM
/// query. It retains no process handle, only a read-only image identity lease,
/// and cannot perform lifecycle effects.
pub struct LiveHostObservationSource {
    monitor: Mutex<HostIdentityMonitor>,
}

impl LiveHostObservationSource {
    #[must_use]
    pub fn new(expected_image: PathBuf) -> Self {
        Self {
            monitor: Mutex::new(HostIdentityMonitor::new(Some(expected_image))),
        }
    }

    /// Creates the production observer from a registry-bound runtime
    /// binding. The caller cannot provide or replace the SCM request.
    #[must_use]
    pub fn from_binding(binding: &WatchdogRuntimeBinding) -> Self {
        Self::try_new(
            binding.approved_host_image.clone(),
            binding.approved_host_registration.clone(),
        )
    }

    /// Opens the approved Host image through the protected no-follow adapter
    /// so a same-path replacement is an identity gap, not a fresh baseline.
    /// If the image cannot be retained, the source stays alive but emits only
    /// fail-closed `Unknown` observations until the approved image can be
    /// retained again.
    #[must_use]
    pub fn try_new(
        expected_image: PathBuf,
        expected_registration: ApprovedHostRegistration,
    ) -> Self {
        let monitor = match ProtectedPathLease::open_existing_absolute(&expected_image) {
            Ok(lease) => HostIdentityMonitor::with_approved_image_lease(
                expected_image,
                lease,
                expected_registration,
            ),
            Err(_) => HostIdentityMonitor::with_unavailable_image_lease(
                expected_image,
                expected_registration,
            ),
        };
        Self {
            monitor: Mutex::new(monitor),
        }
    }
}

impl HostObservationSource for LiveHostObservationSource {
    fn observe(&self) -> HostObservation {
        self.monitor.lock().map_or(
            HostObservation {
                state: HostObservationState::Unknown,
                identity: None,
            },
            |mut monitor| monitor.observe(),
        )
    }

    fn rebaseline_after_verified_lease(&self, _lease: &VerifiedSupervisionLease) {
        if let Ok(mut monitor) = self.monitor.lock() {
            monitor.rebaseline();
        }
    }
}

/// Bounded recovery disposition written after a failed continuous admission
/// check.  It is an observation only; a later admission must still reload and
/// verify the signed lease and independently pinned configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GapRecoveryDisposition {
    pub record_type: &'static str,
    pub service: &'static str,
    pub observed_at_ms: u64,
    pub reason: GapRecoveryReason,
    pub coverage_claimed: bool,
}

/// Minimal independent sensor surface used by the SCM sibling process.
pub struct IndependentKernelSensor {
    watchdog: Mutex<Option<Watchdog>>,
    spool: WatchdogSpool,
    _runtime_binding: WatchdogRuntimeBinding,
}

impl IndependentKernelSensor {
    /// Opens a sensor from an approved binding and retains its root leases.
    ///
    /// # Errors
    ///
    /// Returns an error when the root or its spool file cannot be opened and
    /// retained as a protected file, or when the epoch is invalid.
    pub fn open_runtime_binding(
        binding: WatchdogRuntimeBinding,
        watchdog_epoch: u64,
    ) -> Result<Self, SpoolError> {
        let spool = WatchdogSpool::open_runtime_binding(&binding)?;
        let watchdog = Watchdog::new(
            eliot_watchdog_core::WatchdogConfig::default(),
            Epoch(watchdog_epoch),
        )
        .map_err(|_| SpoolError::InvalidLease("watchdog epoch is invalid".to_owned()))?;
        Ok(Self {
            watchdog: Mutex::new(Some(watchdog)),
            spool,
            _runtime_binding: binding,
        })
    }

    /// Opens a gap-only sensor for startup when the signed lease is stale or
    /// unavailable. A fresh lease lazily creates the epoch-bound sensor on its
    /// first successful heartbeat; this constructor cannot emit a heartbeat.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected spool cannot be opened or retained.
    pub fn open_runtime_binding_without_epoch(
        binding: WatchdogRuntimeBinding,
    ) -> Result<Self, SpoolError> {
        let spool = WatchdogSpool::open_runtime_binding(&binding)?;
        Ok(Self {
            watchdog: Mutex::new(None),
            spool,
            _runtime_binding: binding,
        })
    }

    /// Reads and validates the ordered spool records for an independent
    /// reader. The redb file remains observation-only and is not authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not the protected canonical spool or
    /// if its retained identity, database, header, sequence, or records fail validation.
    pub fn readback(path: impl AsRef<Path>) -> Result<Vec<WatchdogSpoolEntry>, SpoolError> {
        let path = path.as_ref();
        require_protected_program_data_path(path, SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let path_lease = ProtectedPathLease::open_existing(SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        WatchdogSpool {
            database,
            _path_lease: Some(path_lease),
        }
        .readback()
    }

    fn record_heartbeat(
        &self,
        lease: &VerifiedSupervisionLease,
    ) -> Result<(), KernelWatchdogError> {
        let mut watchdog = self
            .watchdog
            .lock()
            .map_err(|_| KernelWatchdogError::Failed)?;
        let epoch = watchdog.as_ref().map_or_else(
            || lease.lease().watchdog_epoch.value(),
            |value| value.epoch().0,
        );
        if epoch == 0 || lease.lease().watchdog_epoch.value() != epoch {
            return Err(KernelWatchdogError::LeaseFenced);
        }
        let now_ms = current_unix_ms().map_err(|_| KernelWatchdogError::LeaseInvalid)?;
        if !lease_window_is_current(
            now_ms,
            lease.lease().issued_at_ms,
            lease.lease().expires_at_ms,
        ) {
            return Err(KernelWatchdogError::LeaseStale);
        }
        if watchdog.is_none() {
            let created =
                Watchdog::new(eliot_watchdog_core::WatchdogConfig::default(), Epoch(epoch))
                    .map_err(|_| KernelWatchdogError::LeaseInvalid)?;
            *watchdog = Some(created);
        }
        let digest = lease
            .payload_digest()
            .map_err(|_| KernelWatchdogError::LeaseInvalid)?;
        self.spool
            .append(
                now_ms,
                WatchdogSpoolPayload::Heartbeat {
                    service: SERVICE_NAME.to_owned(),
                    lease_id: lease.lease().lease_id.clone(),
                    scope_ref: lease.lease().scope_ref.clone(),
                    kernel_epoch: lease.lease().kernel_epoch.value(),
                    watchdog_epoch: lease.lease().watchdog_epoch.value(),
                    payload_digest: digest,
                    envelope_digest: lease.envelope_digest().to_owned(),
                    signer_id: lease.signer_id().to_owned(),
                    key_id: lease.key_id().to_owned(),
                    signature_algorithm: lease.algorithm().to_owned(),
                    signature: lease.signature().to_owned(),
                    public_key_fingerprint: lease.public_key_fingerprint().to_owned(),
                    lease_revision: lease.lease_revision(),
                },
            )
            .map_err(|error| KernelWatchdogError::FailedWithDetail(error.to_string()))
    }

    fn record_gap(&self, disposition: GapRecoveryDisposition) -> Result<(), KernelWatchdogError> {
        self.spool
            .append(
                disposition.observed_at_ms,
                WatchdogSpoolPayload::Gap {
                    service: disposition.service.to_owned(),
                    reason: disposition.reason,
                    coverage_claimed: disposition.coverage_claimed,
                },
            )
            .map_err(|error| KernelWatchdogError::FailedWithDetail(error.to_string()))
    }
}
impl KernelWatchdogPort for IndependentKernelSensor {
    fn supervise<'a>(
        &'a self,
        lease: &'a VerifiedSupervisionLease,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
        Box::pin(async move { self.record_heartbeat(lease) })
    }

    fn report_gap<'a>(
        &'a self,
        disposition: GapRecoveryDisposition,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
        Box::pin(async move { self.record_gap(disposition) })
    }
}

#[must_use]
fn lease_window_is_current(now_ms: u64, issued_at_ms: u64, expires_at_ms: u64) -> bool {
    now_ms >= issued_at_ms && now_ms < expires_at_ms
}

/// Tunables for the watchdog's bounded control loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogConfig {
    pub tick_interval: Duration,
    pub mailbox_capacity: usize,
    pub control_reserve: usize,
    pub restart_budget: usize,
    pub shutdown_grace: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(2),
            mailbox_capacity: 16,
            control_reserve: 2,
            restart_budget: 3,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

impl WatchdogConfig {
    fn runtime(&self) -> Result<Runtime, CompositionError> {
        Runtime::new(
            RuntimeConfig {
                mailbox_capacity: self.mailbox_capacity,
                control_reserve: self.control_reserve,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 4,
                restart_budget: self.restart_budget,
                restart_window: Duration::from_secs(60),
                restart_backoff: Duration::from_millis(250),
                shutdown_grace: self.shutdown_grace,
            },
            None,
        )
        .map_err(CompositionError::Runtime)
    }

    fn validate(&self) -> Result<(), CompositionError> {
        if self.tick_interval.is_zero() {
            return Err(CompositionError::InvalidConfiguration(
                "tick_interval must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Kernel-owned effect boundary used by the watchdog control loop.
pub trait KernelWatchdogPort: Send + Sync + 'static {
    fn supervise<'a>(
        &'a self,
        lease: &'a VerifiedSupervisionLease,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>>;

    /// Emits a bounded non-authoritative gap when continuous admission fails.
    /// Implementations which do not own a durable observation spool may leave
    /// this as the default no-op; they still receive no lease after failure.
    fn report_gap<'a>(
        &'a self,
        _disposition: GapRecoveryDisposition,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

async fn report_gap_nonfatal(kernel: &dyn KernelWatchdogPort, reason: GapRecoveryReason) {
    let disposition = GapRecoveryDisposition {
        record_type: "watchdog_gap",
        service: SERVICE_NAME,
        observed_at_ms: current_unix_ms().unwrap_or(0),
        reason,
        coverage_claimed: false,
    };
    // A spool/provider failure is itself only an observation gap. Never turn
    // it into TaskFailure: the SCM process stays alive for the next tick.
    let _ = kernel.report_gap(disposition).await;
}

/// Non-secret failure returned by the kernel supervision boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelWatchdogError {
    #[error("kernel supervision endpoint is unavailable")]
    Unavailable,
    #[error("kernel rejected stale supervision lease")]
    LeaseStale,
    #[error("kernel rejected fenced supervision lease")]
    LeaseFenced,
    #[error("kernel rejected invalid supervision lease")]
    LeaseInvalid,
    #[error("kernel supervision failed")]
    Failed,
    #[error("kernel supervision failed: {0}")]
    FailedWithDetail(String),
}

/// Errors raised while composing the watchdog process.
#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("invalid watchdog configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid supervision lease: {0}")]
    InvalidLease(String),
    #[error("runtime configuration: {0:?}")]
    Runtime(eliot_runtime::ConfigError),
    #[error("watchdog admission was denied during shutdown")]
    AdmissionClosed,
}

/// Readiness data emitted by the process entrypoint.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WatchdogReadiness {
    pub service: &'static str,
    pub protocol: &'static str,
    pub authority_state: WatchdogAuthorityState,
    pub coverage_claimed: bool,
    pub kernel_epoch: u64,
    pub watchdog_epoch: u64,
    pub tick_interval_ms: u128,
}

/// Separates SCM/process liveness from admitted heartbeat authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum WatchdogAuthorityState {
    /// The SCM sibling is alive and records gap-only evidence, but no current
    /// Host-issued lease has been admitted for heartbeat authority.
    RunningNoAuthority = 0,
    /// Exact Host identity and a current signed lease were admitted and the
    /// Kernel accepted the corresponding heartbeat.
    AdmittedHeartbeat = 1,
}

impl WatchdogAuthorityState {
    fn from_atomic(value: u8) -> Self {
        if value == Self::AdmittedHeartbeat as u8 {
            Self::AdmittedHeartbeat
        } else {
            Self::RunningNoAuthority
        }
    }
}

/// Runtime-owned watchdog composition.
pub struct WatchdogComposition {
    runtime: Runtime,
    admission: Arc<dyn WatchdogAdmissionSource>,
    kernel_epoch: u64,
    watchdog_epoch: u64,
    authority_state: Arc<AtomicU8>,
    config: WatchdogConfig,
    task: eliot_runtime::SupervisedHandle,
    shutdown_requested: Arc<AtomicBool>,
}

impl WatchdogComposition {
    /// Builds and admits the watchdog loop against an injected kernel port.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration or initial supervision
    /// authority is invalid, or if the runtime is already shutting down.
    pub fn start(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown(config, admission, kernel, Arc::new(AtomicBool::new(false)))
    }

    /// Starts the composition with a caller-owned stop flag.  SCM control
    /// handlers use this flag because they execute outside the Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration is invalid or if the runtime
    /// denies task admission. An unavailable initial lease is represented by
    /// zero readiness epochs and remains a nonfatal observation gap.
    pub fn start_with_shutdown(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        let expected_host_image = admission.approved_host_image().ok_or_else(|| {
            CompositionError::InvalidConfiguration(
                "approved Host image is required for the production observer".to_owned(),
            )
        })?;
        let expected_host_registration =
            admission.approved_host_registration().ok_or_else(|| {
                CompositionError::InvalidConfiguration(
                    "installer-approved Host registration is required for the production observer"
                        .to_owned(),
                )
            })?;
        let host = Arc::new(LiveHostObservationSource::try_new(
            expected_host_image,
            expected_host_registration,
        ));
        Self::start_with_shutdown_and_host(config, admission, kernel, host, shutdown_requested)
    }

    /// Starts the composition with an injected read-only Host observation
    /// source. The source can classify Host loss but cannot perform lifecycle
    /// effects or supply supervision authority.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration is invalid or if the runtime
    /// denies task admission. An unavailable initial lease is represented by
    /// zero readiness epochs and remains a nonfatal observation gap.
    pub fn start_with_shutdown_and_host(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        host: Arc<dyn HostObservationSource>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        config.validate()?;
        let runtime = config.runtime()?;
        let initial = admission.reload().ok();
        let kernel_epoch = initial
            .as_ref()
            .map_or(0, |value| value.lease().lease().kernel_epoch.value());
        let watchdog_epoch = initial
            .as_ref()
            .map_or(0, |value| value.watchdog_epoch().value());
        let task_admission = admission.clone();
        let task_host = host;
        let authority_state = Arc::new(AtomicU8::new(
            WatchdogAuthorityState::RunningNoAuthority as u8,
        ));
        let task_authority_state = authority_state.clone();
        let interval = config.tick_interval;
        let task = match runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            SERVICE_NAME,
            ChildClass::Worker,
            move |token| {
                let kernel = kernel.clone();
                let admission = task_admission.clone();
                let host = task_host.clone();
                let authority_state = task_authority_state.clone();
                async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => return Ok(()),
                            () = tokio::time::sleep(interval) => {}
                        }
                        // Host liveness is an independent sibling observation.
                        // It must run even when a lease is missing, stale, or
                        // otherwise unavailable during first install/recovery.
                        let host_observation = host.observe();
                        let host_gap = host_observation.gap_reason();
                        let admission = match admission.reload() {
                            Ok(admission) => admission,
                            Err(error) => {
                                authority_state.store(
                                    WatchdogAuthorityState::RunningNoAuthority as u8,
                                    Ordering::Release,
                                );
                                if let Some(reason) = host_gap {
                                    report_gap_nonfatal(kernel.as_ref(), reason).await;
                                }
                                report_gap_nonfatal(kernel.as_ref(), admission_gap_reason(&error))
                                    .await;
                                continue;
                            }
                        };
                        if let Some(reason) = host_gap {
                            authority_state.store(
                                WatchdogAuthorityState::RunningNoAuthority as u8,
                                Ordering::Release,
                            );
                            // Observation/spool failure is nonfatal. The
                            // Watchdog remains alive and will retry on the
                            // next bounded tick; no restart-budget path is
                            // entered for a lost Host or stale lease.
                            report_gap_nonfatal(kernel.as_ref(), reason).await;
                            if matches!(
                                host_observation.state,
                                HostObservationState::PidReused
                                    | HostObservationState::ImageSubstituted
                                    | HostObservationState::IdentityChanged
                            ) {
                                // A changed process identity is eligible for
                                // one fresh baseline only after this tick's
                                // signed lease was verified. Absent/unknown
                                // observations never get a free baseline.
                                host.rebaseline_after_verified_lease(admission.lease());
                            }
                            continue;
                        }
                        match kernel.supervise(admission.lease()).await {
                            Ok(()) => authority_state.store(
                                WatchdogAuthorityState::AdmittedHeartbeat as u8,
                                Ordering::Release,
                            ),
                            Err(error) => {
                                authority_state.store(
                                    WatchdogAuthorityState::RunningNoAuthority as u8,
                                    Ordering::Release,
                                );
                                report_gap_nonfatal(kernel.as_ref(), kernel_gap_reason(&error))
                                    .await;
                            }
                        }
                    }
                }
            },
        ) {
            eliot_runtime::SpawnDisposition::Admitted(task) => task,
            eliot_runtime::SpawnDisposition::DeniedShuttingDown => {
                return Err(CompositionError::AdmissionClosed);
            }
        };
        Ok(Self {
            runtime,
            admission,
            kernel_epoch,
            watchdog_epoch,
            authority_state,
            config,
            task,
            shutdown_requested,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> WatchdogReadiness {
        let authority_state =
            WatchdogAuthorityState::from_atomic(self.authority_state.load(Ordering::Acquire));
        WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state,
            coverage_claimed: matches!(authority_state, WatchdogAuthorityState::AdmittedHeartbeat),
            kernel_epoch: self.kernel_epoch,
            watchdog_epoch: self.watchdog_epoch,
            tick_interval_ms: self.config.tick_interval.as_millis(),
        }
    }

    /// Waits for process termination and performs ordered runtime shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the supervised watchdog task, shutdown signal, or
    /// externally requested shutdown path fails.
    pub async fn run_until_shutdown(self) -> Result<ShutdownOutcome, TaskFailure> {
        let WatchdogComposition {
            runtime,
            admission,
            task,
            shutdown_requested,
            ..
        } = self;
        let _admission_source = admission;
        let mut task_result = Box::pin(task.join());
        tokio::select! {
            result = &mut task_result => {
                let shutdown = runtime.shutdown().await;
                result.map(|_| shutdown)
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    return Err(TaskFailure::Failed("failed to receive shutdown signal".to_owned()));
                }
                runtime.shutdown_handle().request();
                let result = task_result.await;
                let shutdown = runtime.shutdown().await;
                complete_requested_shutdown(result, shutdown)
            }
            result = wait_for_shutdown(shutdown_requested) => {
                if result {
                    runtime.shutdown_handle().request();
                    let result = task_result.await;
                    let shutdown = runtime.shutdown().await;
                    complete_requested_shutdown(result, shutdown)
                } else {
                    Err(TaskFailure::Failed("watchdog shutdown signal failed".to_owned()))
                }
            }
        }
    }

    /// Requests bounded shutdown from an SCM control path.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
    }
}

fn complete_requested_shutdown<T>(
    result: Result<T, TaskFailure>,
    shutdown: ShutdownOutcome,
) -> Result<ShutdownOutcome, TaskFailure> {
    match result {
        Ok(_) | Err(TaskFailure::Cancelled) => Ok(shutdown),
        Err(error) => Err(error),
    }
}

async fn wait_for_shutdown(shutdown_requested: Arc<AtomicBool>) -> bool {
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn load_runtime_binding(
    registry_path: &Path,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(String, WatchdogRuntimeBinding), SpoolError> {
    let declared_host_root = bootstrap.host_state_root().ok_or_else(|| {
        SpoolError::InvalidLease(
            "Watchdog SCM bootstrap omitted the installer-approved Host state root".to_owned(),
        )
    })?;
    let host_state_root_lease =
        ProtectedRootLease::open_existing(declared_host_root).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root open failed: {error}"))
        })?;
    let canonical_host_root = host_state_root_lease.canonical_path().map_err(|error| {
        SpoolError::InvalidLease(format!("Host state root resolve failed: {error}"))
    })?;
    if !windows_paths_equal(&canonical_host_root, declared_host_root) {
        return Err(SpoolError::InvalidLease(
            "SCM Host state root is not the exact retained installation root".to_owned(),
        ));
    }
    let expected_registry_path = canonical_host_root.join(INSTALLATION_REGISTRY_FILE_NAME);
    if !windows_paths_equal(registry_path, &expected_registry_path) {
        return Err(SpoolError::InvalidLease(
            "Watchdog registry path is not the exact approved Host child".to_owned(),
        ));
    }
    let registry = RedbInstallationRegistry::inspect_existing_at(
        ProtectedRootLease::open_existing(&canonical_host_root).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root reopen failed: {error}"))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
    let (approved_host_registration, watchdog_request) =
        load_approved_service_registrations(&registry, &selected_manifest, bootstrap)?;
    let roots = selected_manifest.runtime_launch.runtime_state_roots.clone();
    let watchdog_image = PathBuf::from(
        selected_manifest
            .runtime_launch
            .watchdog_executable_path
            .as_str(),
    );
    let approved_host_image = approved_host_artifact_path(&selected_manifest)?;
    let approved_host_image_lease =
        ProtectedPathLease::open_existing_absolute(&approved_host_image).map_err(|error| {
            SpoolError::InvalidLease(format!("approved Host image open failed: {error}"))
        })?;
    verify_file_digest_with_lease(
        &approved_host_image_lease,
        &selected_manifest.runtime_launch.host_artifact_digest,
        "runtime_launch.host_artifact_digest",
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let current_image =
        std::env::current_exe().map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if !windows_paths_equal(&current_image, &watchdog_image) {
        return Err(SpoolError::InvalidLease(
            "running Watchdog image is not the active approved generation image".to_owned(),
        ));
    }
    verify_file_digest(
        &watchdog_image,
        &selected_manifest.runtime_launch.watchdog_artifact_digest,
        "runtime_launch.watchdog_artifact_digest",
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if roots.profile != InstallationProfile::SystemService {
        return Err(SpoolError::InvalidLease(
            "watchdog has no retained file adapter for this installation profile".to_owned(),
        ));
    }
    let mut provider = WindowsRuntimeRootLeaseProvider::for_roots(&roots)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let leases = roots
        .retain_and_validate(&mut provider)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok((
        selected_manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str()
            .to_owned(),
        WatchdogRuntimeBinding {
            host_state_root: canonical_host_root,
            roots,
            selected_manifest: Arc::new(selected_manifest),
            approved_host_image,
            approved_host_registration,
            approved_watchdog_registration: watchdog_request,
            host_state_root_lease: Arc::new(host_state_root_lease),
            _approved_host_image_lease: Arc::new(approved_host_image_lease),
            _root_leases: Arc::new(leases),
        },
    ))
}

fn validate_host_admission_paths(
    binding: &WatchdogRuntimeBinding,
    lease_path: &Path,
    admission_config_path: &Path,
    registry_path: &Path,
) -> Result<(), SpoolError> {
    let expected = [
        (lease_path, SUPERVISION_LEASE_FILE_NAME),
        (admission_config_path, WATCHDOG_ADMISSION_FILE_NAME),
        (registry_path, INSTALLATION_REGISTRY_FILE_NAME),
    ];
    for (actual, leaf) in expected {
        validate_host_admission_child(&binding.host_state_root, actual, leaf)?;
    }
    Ok(())
}

fn validate_host_admission_child(
    host_state_root: &Path,
    actual: &Path,
    leaf: &str,
) -> Result<(), SpoolError> {
    let expected_path = host_state_root.join(leaf);
    if windows_paths_equal(actual, &expected_path) {
        Ok(())
    } else {
        Err(SpoolError::InvalidLease(format!(
            "Watchdog admission path is not the approved Host child: {leaf}"
        )))
    }
}

fn select_runtime_manifest(
    registry: &ApprovedGenerationRegistry,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<CandidateManifest, SpoolError> {
    let matching_generations = registry
        .generations()
        .iter()
        .filter(|generation| manifest_matches_bootstrap(&generation.manifest, bootstrap))
        .collect::<Vec<_>>();
    if matching_generations.len() > 1 {
        return Err(SpoolError::InvalidLease(
            "multiple approved generations match the SCM bootstrap".to_owned(),
        ));
    }
    let active_match = registry
        .active()
        .filter(|active| manifest_matches_bootstrap(&active.manifest, bootstrap));
    if let Some(pending) = registry.pending_activation() {
        if !matches!(pending.state, PendingActivationState::Pending) {
            return Err(SpoolError::InvalidLease(
                "pending activation is recovery-required".to_owned(),
            ));
        }
        let pending_match = manifest_matches_bootstrap(&pending.manifest, bootstrap);
        match (active_match, pending_match) {
            // A running active contour must remain selectable while a staged
            // upgrade is present. The pending record is not an implicit
            // override of the SCM command line.
            (Some(active), false) => {
                let Some(matching) = matching_generations.first() else {
                    return Err(SpoolError::InvalidLease(
                        "active generation has no approved projection".to_owned(),
                    ));
                };
                if matching.manifest != active.manifest {
                    return Err(SpoolError::InvalidLease(
                        "active generation projection was substituted".to_owned(),
                    ));
                }
                Ok(active.manifest.clone())
            }
            // A pending contour is valid during first install (no active) or
            // when the SCM registration explicitly selects the upgrade.
            (None, true) => {
                let Some(matching) = matching_generations.first() else {
                    return Err(SpoolError::InvalidLease(
                        "pending activation has no approved generation projection".to_owned(),
                    ));
                };
                if matching.manifest != pending.manifest {
                    return Err(SpoolError::InvalidLease(
                        "pending activation projection was substituted".to_owned(),
                    ));
                }
                Ok(pending.manifest.clone())
            }
            (Some(_), true) => Err(SpoolError::InvalidLease(
                "active and pending generations both match the SCM bootstrap".to_owned(),
            )),
            (None, false) => Err(SpoolError::InvalidLease(
                "pending activation does not match the SCM bootstrap".to_owned(),
            )),
        }
    } else {
        let Some(active) = active_match.or_else(|| registry.active()) else {
            return Err(SpoolError::InvalidLease(
                "no active or matching pending approved generation".to_owned(),
            ));
        };
        if !manifest_matches_bootstrap(&active.manifest, bootstrap) {
            return Err(SpoolError::InvalidLease(
                "active approved generation does not match the SCM bootstrap".to_owned(),
            ));
        }
        let Some(matching) = matching_generations.first() else {
            return Err(SpoolError::InvalidLease(
                "active approved generation has no approved projection".to_owned(),
            ));
        };
        if matching.manifest != active.manifest {
            return Err(SpoolError::InvalidLease(
                "active approved generation projection was substituted".to_owned(),
            ));
        }
        Ok(active.manifest.clone())
    }
}

fn manifest_matches_bootstrap(
    manifest: &CandidateManifest,
    bootstrap: &ServiceBootstrapArguments,
) -> bool {
    let launch = &manifest.runtime_launch;
    bootstrap.host_state_root().is_some_and(|host_state_root| {
        windows_paths_equal(
            host_state_root,
            Path::new(launch.runtime_state_roots.host_state_root.as_str()),
        )
    }) && bootstrap.config_descriptor_path() == Path::new(launch.authority_descriptor_path.as_str())
        && bootstrap.config_descriptor_digest() == launch.authority_descriptor_digest.as_str()
        && bootstrap.installation_id() == launch.installation_epoch.installation.as_str()
        && bootstrap.transaction_plan_generation() == launch.authority_generation.value()
}

fn approved_host_artifact_path(manifest: &CandidateManifest) -> Result<PathBuf, SpoolError> {
    let (path, _) = manifest
        .runtime_launch
        .host_artifact_binding()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok(PathBuf::from(path.as_str()))
}

fn read_registry_for_bootstrap(
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(ApprovedGenerationRegistry, CandidateManifest), SpoolError> {
    let host_state_root = bootstrap.host_state_root().ok_or_else(|| {
        SpoolError::InvalidLease(
            "Watchdog SCM bootstrap omitted the installer-approved Host state root".to_owned(),
        )
    })?;
    let registry = RedbInstallationRegistry::inspect_existing_at(
        ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root open failed: {error}"))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let manifest = select_runtime_manifest(&registry, bootstrap)?;
    Ok((registry, manifest))
}

fn service_approval_matches_manifest(
    approval: &InstallerServiceRegistrationApproval,
    request: &ServiceRegistrationRequest,
    manifest: &CandidateManifest,
    role: InstallerServiceRole,
) -> bool {
    let launch = &manifest.runtime_launch;
    let Some(bootstrap) = request.bootstrap() else {
        return false;
    };
    let Some(host_state_root) = bootstrap.host_state_root() else {
        return false;
    };
    let expected_image = match role {
        InstallerServiceRole::Host => launch.host_executable_path.as_str(),
        InstallerServiceRole::Watchdog => launch.watchdog_executable_path.as_str(),
    };
    approval.generation() == &manifest.generation
        && approval.role() == role
        && request.service_name()
            == match role {
                InstallerServiceRole::Host => eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
                InstallerServiceRole::Watchdog => SERVICE_NAME,
            }
        && windows_paths_equal(
            bootstrap.config_descriptor_path(),
            Path::new(launch.authority_descriptor_path.as_str()),
        )
        && bootstrap.config_descriptor_digest() == launch.authority_descriptor_digest.as_str()
        && bootstrap.installation_id() == launch.installation_epoch.installation.as_str()
        && bootstrap.transaction_plan_generation() == launch.authority_generation.value()
        && windows_paths_equal(
            host_state_root,
            Path::new(launch.runtime_state_roots.host_state_root.as_str()),
        )
        && windows_paths_equal(request.binary_path(), Path::new(expected_image))
}

fn approved_service_registration(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    role: InstallerServiceRole,
) -> Result<
    (
        InstallerServiceRegistrationApproval,
        ServiceRegistrationRequest,
    ),
    SpoolError,
> {
    let approval = registry
        .service_registration_approval(&manifest.generation, role)
        .ok_or_else(|| {
            SpoolError::InvalidLease("installer SCM registration approval is missing".to_owned())
        })?;
    let request = approval.service_registration_request().map_err(|_| {
        SpoolError::InvalidLease("installer SCM registration approval is invalid".to_owned())
    })?;
    if !service_approval_matches_manifest(approval, &request, manifest, role) {
        return Err(SpoolError::InvalidLease(
            "installer SCM registration approval does not bind the selected generation".to_owned(),
        ));
    }
    Ok((approval.clone(), request))
}

fn load_approved_service_registrations(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(ApprovedHostRegistration, ServiceRegistrationRequest), SpoolError> {
    let (host_approval, _) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Host)?;
    let (_, watchdog_request) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Watchdog)?;
    if watchdog_request.bootstrap() != Some(bootstrap) {
        return Err(SpoolError::InvalidLease(
            "Watchdog SCM bootstrap does not match the installer approval".to_owned(),
        ));
    }
    let approved_host_registration = ApprovedHostRegistration::from_approval(&host_approval)?;
    Ok((approved_host_registration, watchdog_request))
}

fn read_approved_service_registration(
    bootstrap: &ServiceBootstrapArguments,
    role: InstallerServiceRole,
) -> Result<
    (
        CandidateManifest,
        InstallerServiceRegistrationApproval,
        ServiceRegistrationRequest,
    ),
    SpoolError,
> {
    let (registry, manifest) = read_registry_for_bootstrap(bootstrap)?;
    let (approval, request) = approved_service_registration(&registry, &manifest, role)?;
    Ok((manifest, approval, request))
}

fn validate_bound_service_registrations(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    expected_host_request: &ServiceRegistrationRequest,
    expected_watchdog_request: &ServiceRegistrationRequest,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(), SpoolError> {
    let (_, host_request) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Host)?;
    let (_, watchdog_request) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Watchdog)?;
    if host_request != *expected_host_request
        || watchdog_request != *expected_watchdog_request
        || watchdog_request.bootstrap() != Some(bootstrap)
    {
        return Err(SpoolError::InvalidLease(
            "installer SCM registration approval changed after watchdog binding".to_owned(),
        ));
    }
    Ok(())
}

/// Performs a read-only SCM readback for the exact Host sibling selected by
/// the immutable runtime contour. The binding is constructed only after the
/// installer-owned registry approval has been selected and validated, so this
/// function cannot accept an arbitrary deserialized approval as authority.
/// It fails closed on absent, mismatched, or unknown registration and never
/// creates or changes a service.
///
/// # Errors
///
/// Returns an error when the canonical Host service registration is absent,
/// mismatched, or cannot be observed authoritatively.
pub fn inspect_approved_host_registration(
    binding: &WatchdogRuntimeBinding,
) -> Result<(), SpoolError> {
    inspect_host_registration(&binding.approved_host_registration)
}

fn inspect_host_registration(approved: &ApprovedHostRegistration) -> Result<(), SpoolError> {
    match read_host_registration_runtime(approved) {
        WatchdogRuntimeReadback::Matching { .. } => Ok(()),
        other => Err(SpoolError::InvalidLease(format!(
            "approved Host SCM registration is not an exact read-only runtime match: {other:?}"
        ))),
    }
}

fn read_host_registration_runtime(approved: &ApprovedHostRegistration) -> WatchdogRuntimeReadback {
    let registration = &approved.request;
    let Some(root) = registration.binary_path().parent() else {
        return WatchdogRuntimeReadback::Unknown;
    };
    let Ok(platform) = WindowsPlatform::new(root.to_path_buf()) else {
        return WatchdogRuntimeReadback::Unknown;
    };
    project_service_runtime_inspection(platform.inspect_service_registration_runtime(registration))
}

fn validate_runtime_binding(
    active_installation_id: &str,
    active_roots_digest: &str,
    expected_installation_id: &str,
    expected_roots_digest: &str,
) -> Result<(), SpoolError> {
    if active_installation_id != expected_installation_id {
        return Err(SpoolError::InvalidLease(
            "active generation installation identity changed after binding".to_owned(),
        ));
    }
    if active_roots_digest != expected_roots_digest {
        return Err(SpoolError::InvalidLease(
            "active generation runtime roots changed after binding".to_owned(),
        ));
    }
    Ok(())
}

fn load_supervision_lease_bound(
    source: &FileWatchdogAdmission,
) -> Result<VerifiedWatchdogAdmission, SpoolError> {
    let lease_path = source.lease_path.as_path();
    let admission_config_path = source.admission_config_path.as_path();
    let registry_path = source.registry_path.as_path();
    let expected_installation_id = source.installation_id.as_str();
    let expected_roots_digest = source.roots_digest.as_str();
    let bootstrap = &source.bootstrap;
    let expected_manifest = &source.binding.selected_manifest;
    let binding = &source.binding;
    binding
        .host_state_root_lease
        .verify_stable_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Host state root changed: {error}")))?;
    validate_host_admission_paths(binding, lease_path, admission_config_path, registry_path)?;
    validate_text(expected_installation_id, "installation_id")?;
    let config_bytes = read_bounded(admission_config_path, ADMISSION_CONFIG_LIMIT)?;
    let config: WatchdogAdmissionConfig = serde_json::from_slice(&config_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    config.validate_shape()?;
    let registry = RedbInstallationRegistry::inspect_existing_at(
        ProtectedRootLease::open_existing(binding.host_state_root()).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root reopen failed: {error}"))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
    if selected_manifest != **expected_manifest {
        return Err(SpoolError::InvalidLease(
            "selected runtime contour changed after watchdog binding".to_owned(),
        ));
    }
    validate_bound_service_registrations(
        &registry,
        &selected_manifest,
        &binding.approved_host_registration.request,
        &binding.approved_watchdog_registration,
        bootstrap,
    )?;
    if config.installation_id != expected_installation_id
        || config.trust_anchor.installation_id != expected_installation_id
    {
        return Err(SpoolError::InvalidLease(
            "admission installation identity does not match the service installation".to_owned(),
        ));
    }
    validate_runtime_binding(
        selected_manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str(),
        selected_manifest
            .runtime_launch
            .runtime_state_roots
            .roots_digest
            .as_str(),
        expected_installation_id,
        expected_roots_digest,
    )?;
    if config.approved_generation != selected_manifest.generation.as_str() {
        return Err(SpoolError::InvalidLease(
            "admission generation is not the selected approved generation".to_owned(),
        ));
    }
    let expected_config_digest = selected_manifest.config_digest.as_str();
    if !is_sha256_hex(expected_config_digest) || sha256_hex(&config_bytes) != expected_config_digest
    {
        return Err(SpoolError::InvalidLease(
            "admission config digest is not the selected manifest config digest".to_owned(),
        ));
    }
    let expected_fingerprint = selected_manifest.supervision_key_fingerprint.as_str();
    if config.trust_anchor.public_key_fingerprint() != expected_fingerprint
        || config.context.public_key_fingerprint != expected_fingerprint
    {
        return Err(SpoolError::InvalidLease(
            "admission trust fingerprint is not the selected manifest fingerprint".to_owned(),
        ));
    }
    let now_ms = current_unix_ms()?;
    let mut context = config.context;
    context.now_ms = now_ms;
    context
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let lease_bytes = read_bounded(lease_path, LEASE_FILE_LIMIT)?;
    let envelope: SignedSupervisionLease = serde_json::from_slice(&lease_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let lease = config
        .trust_anchor
        .verify(&envelope, &context)
        .map_err(|error| map_lease_verification_error(&error))?;
    Ok(VerifiedWatchdogAdmission {
        watchdog_epoch: context.watchdog_epoch,
        lease,
    })
}

fn map_lease_verification_error(error: &SupervisionLeaseError) -> SpoolError {
    let detail = error.to_string();
    match error {
        SupervisionLeaseError::Expired => SpoolError::LeaseStale(detail),
        SupervisionLeaseError::EpochOrActivationMismatch
        | SupervisionLeaseError::LeaseIdentityMismatch
        | SupervisionLeaseError::GenerationMismatch
        | SupervisionLeaseError::OrsMirrorMismatch
        | SupervisionLeaseError::ActiveStateMismatch
        | SupervisionLeaseError::InactiveLease => SpoolError::LeaseFenced(detail),
        _ => SpoolError::InvalidLease(detail),
    }
}

fn current_unix_ms() -> Result<u64, SpoolError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| SpoolError::InvalidLease("current time overflows u64".to_owned()))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, SpoolError> {
    ProtectedRuntimePathLease::open_existing_absolute(path)
        .and_then(|lease| lease.read_bounded(limit))
        .map_err(|error| match error {
            eliot_platform_windows::ProtectedPathError::SizeExceeded => SpoolError::InvalidLease(
                "protected admission file exceeds the bounded size".to_owned(),
            ),
            _ => SpoolError::InvalidProtectedRoot,
        })
}

fn validate_text(value: &str, field: &str) -> Result<(), SpoolError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SpoolError::InvalidLease(format!("{field} is invalid")));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::registry_fixture::RegistryFixture;
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn protected_redb_registry_selection_matrix() {
        let fixture = RegistryFixture::new();

        fixture.write_registry(&fixture.pending_only());
        let (registry, manifest) = read_registry_for_bootstrap(&fixture.base_bootstrap())
            .unwrap_or_else(|error| panic!("pending-only protected registry: {error}"));
        assert_eq!(manifest.generation.as_str(), "generation-7");
        assert!(registry.active().is_none());
        assert!(matches!(
            registry.pending_activation().map(|pending| &pending.state),
            Some(PendingActivationState::Pending)
        ));

        fixture.write_registry(&fixture.active_with_pending());
        let (registry, active_manifest) = read_registry_for_bootstrap(&fixture.bootstrap_for(6))
            .unwrap_or_else(|error| panic!("active protected registry selection: {error}"));
        assert_eq!(active_manifest.generation.as_str(), "generation-6");
        assert_eq!(
            registry
                .active()
                .map(|generation| generation.manifest.generation.as_str()),
            Some("generation-6")
        );
        let (_, pending_manifest) = read_registry_for_bootstrap(&fixture.bootstrap_for(7))
            .unwrap_or_else(|error| {
                panic!("pending upgrade protected registry selection: {error}")
            });
        assert_eq!(pending_manifest.generation.as_str(), "generation-7");

        fixture.write_registry(&fixture.ambiguous_generations());
        assert!(read_registry_for_bootstrap(&fixture.base_bootstrap()).is_err());

        fixture.write_registry(&fixture.recovery_required());
        assert!(read_registry_for_bootstrap(&fixture.base_bootstrap()).is_err());

        let missing_fixture = RegistryFixture::new();
        assert!(read_registry_for_bootstrap(&missing_fixture.base_bootstrap()).is_err());

        let migration_fixture = RegistryFixture::new();
        migration_fixture.write_registry(&migration_fixture.migration_wire());
        assert!(read_registry_for_bootstrap(&migration_fixture.base_bootstrap()).is_err());

        let legacy_fixture = RegistryFixture::new();
        legacy_fixture.write_legacy_table();
        assert!(read_registry_for_bootstrap(&legacy_fixture.base_bootstrap()).is_err());

        let corrupt_fixture = RegistryFixture::new();
        corrupt_fixture.write_current_bytes(b"not-json");
        assert!(read_registry_for_bootstrap(&corrupt_fixture.base_bootstrap()).is_err());
    }

    #[test]
    fn protected_redb_registry_approval_and_bootstrap_substitution_matrix() {
        let fixture = RegistryFixture::new();
        fixture.write_registry(&fixture.active_only());
        let (registry, manifest) = read_registry_for_bootstrap(&fixture.base_bootstrap())
            .unwrap_or_else(|error| panic!("active protected registry: {error}"));
        assert!(
            approved_service_registration(&registry, &manifest, InstallerServiceRole::Host).is_ok()
        );
        assert!(
            approved_service_registration(&registry, &manifest, InstallerServiceRole::Watchdog)
                .is_ok()
        );
        assert!(
            load_approved_service_registrations(&registry, &manifest, &fixture.base_bootstrap())
                .is_ok()
        );

        for (field, replacement) in [
            ("role", serde_json::json!("WATCHDOG")),
            ("generation", serde_json::json!("generation-other")),
            ("service_name", serde_json::json!("OtherService")),
            (
                "executable_path",
                serde_json::json!(fixture.host_root().join("other.exe")),
            ),
            ("account", serde_json::json!("LOCAL_SYSTEM")),
            ("automatic_start", serde_json::json!(false)),
            ("registration_nonce", serde_json::json!("f".repeat(64))),
            ("configuration_digest", serde_json::json!("e".repeat(64))),
            (
                "descriptor_path",
                serde_json::json!(fixture.host_root().join("other.json")),
            ),
            ("descriptor_digest", serde_json::json!("d".repeat(64))),
            ("installation_id", serde_json::json!("other-installation")),
            ("plan_generation", serde_json::json!(8)),
            (
                "host_state_root",
                serde_json::json!(fixture.host_root().join("other")),
            ),
        ] {
            fixture.write_registry(&fixture.substituted_service_approval(field, replacement));
            let result = read_registry_for_bootstrap(&fixture.base_bootstrap());
            if let Ok((registry, manifest)) = result {
                assert!(
                    approved_service_registration(&registry, &manifest, InstallerServiceRole::Host)
                        .is_err(),
                    "service approval substitution {field} unexpectedly survived"
                );
            }
        }

        let base = fixture.base_bootstrap();
        let bootstrap = |descriptor_path: PathBuf,
                         descriptor_digest: String,
                         installation_id: String,
                         plan_generation: u64,
                         host_state_root: PathBuf| {
            ServiceBootstrapArguments::new(
                descriptor_path,
                descriptor_digest,
                installation_id,
                plan_generation,
                std::iter::empty::<String>(),
            )
            .and_then(|value| value.with_host_state_root(host_state_root))
            .and_then(|value| value.with_registration_nonce("c".repeat(64)))
            .unwrap_or_else(|error| panic!("bootstrap substitution fixture: {error}"))
        };
        let cases = [
            bootstrap(
                base.config_descriptor_path().with_file_name("other.json"),
                base.config_descriptor_digest().to_owned(),
                base.installation_id().to_owned(),
                base.transaction_plan_generation(),
                fixture.host_root().to_path_buf(),
            ),
            bootstrap(
                base.config_descriptor_path().to_path_buf(),
                "b".repeat(64),
                base.installation_id().to_owned(),
                base.transaction_plan_generation(),
                fixture.host_root().to_path_buf(),
            ),
            bootstrap(
                base.config_descriptor_path().to_path_buf(),
                base.config_descriptor_digest().to_owned(),
                "other-installation".to_owned(),
                base.transaction_plan_generation(),
                fixture.host_root().to_path_buf(),
            ),
            bootstrap(
                base.config_descriptor_path().to_path_buf(),
                base.config_descriptor_digest().to_owned(),
                base.installation_id().to_owned(),
                8,
                fixture.host_root().to_path_buf(),
            ),
            bootstrap(
                base.config_descriptor_path().to_path_buf(),
                base.config_descriptor_digest().to_owned(),
                base.installation_id().to_owned(),
                base.transaction_plan_generation(),
                fixture.host_root().join("other"),
            ),
        ];
        for substituted in cases {
            assert!(read_registry_for_bootstrap(&substituted).is_err());
        }
    }

    #[test]
    fn protected_redb_registry_reopen_reload_drift_fails_closed() {
        let fixture = RegistryFixture::new();
        fixture.write_registry(&fixture.active_only());
        let (_, first_manifest) = read_registry_for_bootstrap(&fixture.base_bootstrap())
            .unwrap_or_else(|error| panic!("initial protected registry read: {error}"));
        assert_eq!(first_manifest.generation.as_str(), "generation-7");

        fixture.write_registry(&fixture.drifted_active_projection());
        assert!(
            read_registry_for_bootstrap(&fixture.base_bootstrap()).is_err(),
            "reopened registry must reject a substituted projection"
        );
    }

    fn valid_scm_args() -> Vec<OsString> {
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\config\watchdog.json"),
            "a".repeat(64),
            "installation-7",
            7,
            std::iter::empty::<String>(),
        )
        .and_then(|value| {
            value.with_host_state_root(PathBuf::from(
                r"C:\ProgramData\Eliot\installations\installation-7\host",
            ))
        })
        .and_then(|value| value.with_registration_nonce("b".repeat(64)))
        .unwrap_or_else(|error| panic!("{error}"));
        let mut args = vec![OsString::from(SERVICE_NAME)];
        args.extend(bootstrap.argv().into_iter().map(OsString::from));
        args
    }

    fn installer_approval_fixture(
        role: InstallerServiceRole,
        registration_nonce: &str,
    ) -> (
        InstallerServiceRegistrationApproval,
        ServiceRegistrationRequest,
    ) {
        let descriptor =
            std::env::current_exe().unwrap_or_else(|error| panic!("current exe: {error}"));
        let host_state_root = std::env::temp_dir().join(format!(
            "eliot-watchdog-scm-host-state-{}",
            std::process::id()
        ));
        let bootstrap = ServiceBootstrapArguments::new(
            descriptor,
            "a".repeat(64),
            "installation-fixture",
            7,
            std::iter::empty::<String>(),
        )
        .and_then(|value| value.with_host_state_root(host_state_root))
        .unwrap_or_else(|error| panic!("bootstrap fixture: {error}"));
        installer_approval_fixture_for_bootstrap(role, registration_nonce, &bootstrap)
    }

    fn installer_approval_fixture_for_bootstrap(
        role: InstallerServiceRole,
        registration_nonce: &str,
        template: &ServiceBootstrapArguments,
    ) -> (
        InstallerServiceRegistrationApproval,
        ServiceRegistrationRequest,
    ) {
        let source_image =
            std::env::current_exe().unwrap_or_else(|error| panic!("current exe: {error}"));
        let fixture_id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let fixture_directory = std::env::temp_dir().join(format!(
            "eliot-watchdog-scm-fixture-{}-{fixture_id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&fixture_directory)
            .unwrap_or_else(|error| panic!("create fixture directory: {error}"));
        let image = fixture_directory.join(match role {
            InstallerServiceRole::Host => "eliot-host.exe",
            InstallerServiceRole::Watchdog => "eliot-watchdog.exe",
        });
        std::fs::copy(&source_image, &image)
            .unwrap_or_else(|error| panic!("copy fixture image: {error}"));
        let bootstrap = template
            .clone()
            .with_registration_nonce(registration_nonce)
            .unwrap_or_else(|error| panic!("bootstrap fixture: {error}"));
        let descriptor = bootstrap.config_descriptor_path().to_path_buf();
        let host_state_root = bootstrap
            .host_state_root()
            .unwrap_or_else(|| panic!("bootstrap fixture has no Host state root"))
            .to_path_buf();
        let generation = format!("generation-{}", bootstrap.transaction_plan_generation());
        let descriptor_digest = bootstrap.config_descriptor_digest().to_owned();
        let installation_id = bootstrap.installation_id().to_owned();
        let plan_generation = bootstrap.transaction_plan_generation();
        let (service_name, display_name) = match role {
            InstallerServiceRole::Host => (
                eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
                eliot_platform_windows::ELIOT_HOST_SERVICE_DISPLAY_NAME,
            ),
            InstallerServiceRole::Watchdog => (
                SERVICE_NAME,
                eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
            ),
        };
        let request = ServiceRegistrationRequest::with_bootstrap(
            service_name,
            display_name,
            image.clone(),
            eliot_platform_windows::ServiceStartMode::Automatic,
            eliot_platform_windows::ServiceAccount::LocalService,
            bootstrap.clone(),
        )
        .unwrap_or_else(|error| panic!("request fixture: {error}"));
        let wire = serde_json::json!({
            "transaction_id": "transaction-fixture",
            "generation": generation,
            "effect_id": format!("effect-{service_name}"),
            "role": match role {
                InstallerServiceRole::Host => "HOST",
                InstallerServiceRole::Watchdog => "WATCHDOG",
            },
            "service_name": service_name,
            "executable_path": image.to_string_lossy(),
            "account": "LOCAL_SERVICE",
            "automatic_start": true,
            "service_bootstrap": {
                "descriptor_path": descriptor.to_string_lossy(),
                "descriptor_digest": descriptor_digest,
                "installation_id": installation_id,
                "plan_generation": plan_generation,
                "host_state_root": host_state_root.to_string_lossy(),
            },
            "registration_nonce": registration_nonce,
            "configuration_digest": request.expected_configuration_digest(),
        });
        let approval = serde_json::from_value(wire)
            .unwrap_or_else(|error| panic!("approval fixture: {error}"));
        (approval, request)
    }

    fn manifest_fixture(
        bootstrap: &ServiceBootstrapArguments,
        generation: &str,
    ) -> CandidateManifest {
        let descriptor_path = bootstrap
            .config_descriptor_path()
            .to_string_lossy()
            .into_owned();
        let host_state_root = bootstrap
            .host_state_root()
            .unwrap_or_else(|| panic!("bootstrap fixture has no Host state root"))
            .to_string_lossy()
            .into_owned();
        let installation = bootstrap.installation_id().to_owned();
        let authority_generation = bootstrap.transaction_plan_generation();
        let roots_digest = "f".repeat(64);
        let config_digest = "d".repeat(64);
        let descriptor = serde_json::json!({
            "profile": "system_service",
            "portable_root": null,
            "installation_epoch": {
                "installation": installation,
                "lineage_id": "lineage-fixture",
                "sequence": 1
            },
            "generation": generation,
            "authority_generation": authority_generation,
            "authority_state_fence": {
                "authority_epoch": 1,
                "resource_generation": authority_generation,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            },
            "authority_descriptor_path": descriptor_path,
            "authority_descriptor_digest": bootstrap.config_descriptor_digest(),
            "runtime_state_roots": {
                "profile": "system_service",
                "profile_anchor_root": r"C:\ProgramData",
                "installation_root": r"C:\ProgramData\Eliot\installations\installation-7",
                "host_state_root": host_state_root,
                "kernel_ors_root": r"C:\ProgramData\Eliot\state\kernel\state",
                "kernel_work_root": r"C:\ProgramData\Eliot\state\kernel\work",
                "store_data_root": r"C:\ProgramData\Eliot\state\store\data",
                "store_work_root": r"C:\ProgramData\Eliot\state\store\work",
                "store_temp_root": r"C:\ProgramData\Eliot\state\store\tmp",
                "watchdog_state_root": r"C:\ProgramData\Eliot\state\watchdog",
                "roots_digest": roots_digest
            },
            "kernel_work_root": r"C:\ProgramData\Eliot\state\kernel\work",
            "kernel_artifact_digest": "0".repeat(64),
            "eliotd_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliotd.exe",
            "eliotd_artifact_digest": "1".repeat(64),
            "eliotd_config_path": r"C:\ProgramData\Eliot\packages\generation-7\eliotd.json",
            "eliotd_config_digest": "2".repeat(64),
            "eliotd_descriptor_path": r"C:\ProgramData\Eliot\packages\generation-7\eliotd-descriptor.json",
            "eliotd_descriptor_digest": "3".repeat(64),
            "eliotd_launch_nonce": "eliotd-fixture-nonce",
            "store_config_path": r"C:\ProgramData\Eliot\packages\generation-7\store.json",
            "store_credential_target": "eliot/store/v1/0123456789abcdef0123456789abcdef",
            "store_bridge_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-store-surreal.exe",
            "store_bridge_artifact_digest": "4".repeat(64),
            "store_bootstrap_descriptor_path": r"C:\ProgramData\Eliot\packages\generation-7\store-bootstrap.json",
            "store_bootstrap_descriptor_digest": "5".repeat(64),
            "canonical_store_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\surreal.exe",
            "canonical_store_artifact_digest": "6".repeat(64),
            "kernel_arguments": [],
            "store_bridge_arguments": [],
            "canonical_store_arguments": [],
            "host_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\host\eliot-host.exe",
            "host_artifact_digest": "7".repeat(64),
            "watchdog_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-watchdog.exe",
            "watchdog_artifact_digest": "8".repeat(64),
            "descriptor_digest": "9".repeat(64)
        });
        serde_json::from_value(serde_json::json!({
            "generation": generation,
            "components": ["component-kernel", "component-store"],
            "kernel_artifact_digest": "0".repeat(64),
            "store_bridge_artifact_digest": "4".repeat(64),
            "canonical_store_artifact_digest": "6".repeat(64),
            "host_artifact_digest": "7".repeat(64),
            "kernel_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-kernel.exe",
            "store_bridge_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-store-surreal.exe",
            "canonical_store_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\surreal.exe",
            "host_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\host\eliot-host.exe",
            "config_path": r"C:\ProgramData\Eliot\packages\generation-7\store.json",
            "dependency_closure_refs": ["evidence-dependencies"],
            "license_refs": ["evidence-licenses"],
            "config_digest": config_digest,
            "store_credential_target": "eliot/store/v1/0123456789abcdef0123456789abcdef",
            "supervision_key_fingerprint": "a".repeat(64),
            "signature_ref": "evidence-signature",
            "runtime_state_roots_digest": roots_digest,
            "runtime_launch": descriptor
        }))
        .unwrap_or_else(|error| panic!("manifest fixture: {error}"))
    }

    #[test]
    fn scm_argv_reconstructs_exact_bootstrap_and_rejects_substitution() {
        let args = valid_scm_args();
        let bootstrap =
            parse_watchdog_scm_argv(args.clone()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            bootstrap.argv(),
            args[1..]
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );

        let mut reordered = args.clone();
        reordered.swap(1, 3);
        reordered.swap(2, 4);
        assert!(parse_watchdog_scm_argv(reordered).is_err());

        let mut substituted = args;
        substituted[12] = OsString::from("C".repeat(64));
        assert!(parse_watchdog_scm_argv(substituted).is_err());
    }

    #[test]
    fn scm_argv_requires_registration_nonce_and_exact_service_name() {
        let mut missing_nonce = valid_scm_args();
        missing_nonce.truncate(11);
        assert!(parse_watchdog_scm_argv(missing_nonce).is_err());

        let mut missing_root = valid_scm_args();
        missing_root.drain(9..11);
        assert!(parse_watchdog_scm_argv(missing_root).is_err());

        let mut wrong_service = valid_scm_args();
        wrong_service[0] = OsString::from("EliotHost");
        assert!(parse_watchdog_scm_argv(wrong_service).is_err());
    }

    #[test]
    fn installer_role_approvals_reconstruct_exact_sibling_requests() {
        let (host_approval, host_expected) =
            installer_approval_fixture(InstallerServiceRole::Host, &"a".repeat(64));
        let (watchdog_approval, watchdog_expected) =
            installer_approval_fixture(InstallerServiceRole::Watchdog, &"b".repeat(64));
        let host_request = host_approval
            .service_registration_request()
            .unwrap_or_else(|error| panic!("Host approval reconstruction: {error}"));
        let watchdog_request = watchdog_approval
            .service_registration_request()
            .unwrap_or_else(|error| panic!("Watchdog approval reconstruction: {error}"));

        assert_eq!(host_request, host_expected);
        assert_eq!(watchdog_request, watchdog_expected);
        assert_eq!(
            host_request.service_name(),
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME
        );
        assert_eq!(watchdog_request.service_name(), SERVICE_NAME);
        assert_eq!(
            host_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            watchdog_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce),
            Some("b".repeat(64).as_str())
        );
        assert_ne!(
            host_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce),
            watchdog_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce)
        );
        assert_eq!(
            watchdog_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::host_state_root),
            host_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::host_state_root)
        );
    }

    #[test]
    fn service_approval_projection_fences_substitutions_and_reload() {
        let (host_approval, host_expected) =
            installer_approval_fixture(InstallerServiceRole::Host, &"a".repeat(64));
        let (watchdog_approval, watchdog_expected) =
            installer_approval_fixture(InstallerServiceRole::Watchdog, &"b".repeat(64));
        let host_request = host_approval
            .service_registration_request()
            .unwrap_or_else(|error| panic!("Host approval reconstruction: {error}"));
        let watchdog_request = watchdog_approval
            .service_registration_request()
            .unwrap_or_else(|error| panic!("Watchdog approval reconstruction: {error}"));

        assert_eq!(host_request, host_expected);
        assert_eq!(watchdog_request, watchdog_expected);
        assert_eq!(
            host_request.service_name(),
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME
        );
        assert_eq!(watchdog_request.service_name(), SERVICE_NAME);
        assert_eq!(
            host_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            watchdog_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce),
            Some("b".repeat(64).as_str())
        );
        assert_ne!(
            host_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce),
            watchdog_request
                .bootstrap()
                .and_then(ServiceBootstrapArguments::registration_nonce)
        );

        assert!(ApprovedHostRegistration::from_approval(&watchdog_approval).is_err());
        let changed_bootstrap = host_request
            .bootstrap()
            .unwrap_or_else(|| panic!("Host approval has no bootstrap"))
            .clone()
            .with_registration_nonce("c".repeat(64))
            .unwrap_or_else(|error| panic!("changed bootstrap: {error}"));
        let changed_request = ServiceRegistrationRequest::with_bootstrap(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            eliot_platform_windows::ELIOT_HOST_SERVICE_DISPLAY_NAME,
            host_request.binary_path().to_path_buf(),
            eliot_platform_windows::ServiceStartMode::Automatic,
            eliot_platform_windows::ServiceAccount::LocalService,
            changed_bootstrap,
        )
        .unwrap_or_else(|error| panic!("changed Host request: {error}"));
        assert_ne!(changed_request, host_request);
    }

    #[test]
    fn missing_or_substituted_role_approval_fails_closed() {
        let (host_approval, _) =
            installer_approval_fixture(InstallerServiceRole::Host, &"a".repeat(64));
        let (watchdog_approval, _) =
            installer_approval_fixture(InstallerServiceRole::Watchdog, &"b".repeat(64));
        assert!(ApprovedHostRegistration::from_approval(&host_approval).is_ok());
        assert!(ApprovedHostRegistration::from_approval(&watchdog_approval).is_err());
        let registry = ApprovedGenerationRegistry::new();
        let generation = host_approval.generation().clone();
        assert!(
            registry
                .service_registration_approval(&generation, InstallerServiceRole::Host)
                .is_none()
        );
        assert!(
            registry
                .service_registration_approval(&generation, InstallerServiceRole::Watchdog)
                .is_none()
        );
        let bootstrap = parse_watchdog_scm_argv(valid_scm_args())
            .unwrap_or_else(|error| panic!("bootstrap fixture: {error}"));
        assert!(select_runtime_manifest(&registry, &bootstrap).is_err());
        assert!(read_registry_for_bootstrap(&bootstrap).is_err());
    }

    #[test]
    fn pending_registry_selects_first_install_without_synthesizing_active() {
        let bootstrap = parse_watchdog_scm_argv(valid_scm_args())
            .unwrap_or_else(|error| panic!("bootstrap fixture: {error}"));
        assert!(read_registry_for_bootstrap(&bootstrap).is_err());
        assert!(validate_runtime_binding("installation-7", "a", "installation-8", "a").is_err());
    }

    #[test]
    fn active_generation_wins_only_for_its_bootstrap_when_pending_upgrade_exists() {
        let mut active_args = valid_scm_args();
        active_args[2] = OsString::from(r"C:\ProgramData\Eliot\config\active.json");
        active_args[4] = OsString::from("9".repeat(64));
        active_args[8] = OsString::from("6");
        let active_bootstrap =
            parse_watchdog_scm_argv(active_args).unwrap_or_else(|error| panic!("{error}"));
        let pending_bootstrap =
            parse_watchdog_scm_argv(valid_scm_args()).unwrap_or_else(|error| panic!("{error}"));
        assert_ne!(active_bootstrap, pending_bootstrap);
        let sealed_empty = ApprovedGenerationRegistry::new();
        assert!(select_runtime_manifest(&sealed_empty, &active_bootstrap).is_err());
        assert!(select_runtime_manifest(&sealed_empty, &pending_bootstrap).is_err());
        let active_manifest = manifest_fixture(&active_bootstrap, "generation-6");
        let pending_manifest = manifest_fixture(&pending_bootstrap, "generation-7");
        assert!(manifest_matches_bootstrap(
            &active_manifest,
            &active_bootstrap
        ));
        assert!(manifest_matches_bootstrap(
            &pending_manifest,
            &pending_bootstrap
        ));
        assert!(!manifest_matches_bootstrap(
            &active_manifest,
            &pending_bootstrap
        ));
        assert!(!manifest_matches_bootstrap(
            &pending_manifest,
            &active_bootstrap
        ));
        assert!(
            validate_runtime_binding(
                active_bootstrap.installation_id(),
                active_bootstrap.config_descriptor_digest(),
                pending_bootstrap.installation_id(),
                pending_bootstrap.config_descriptor_digest(),
            )
            .is_err()
        );
    }

    #[test]
    fn pending_registry_rejects_substitution_multiple_and_unmatched_bootstrap() {
        let bootstrap =
            parse_watchdog_scm_argv(valid_scm_args()).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            validate_runtime_binding(
                bootstrap.installation_id(),
                bootstrap.config_descriptor_digest(),
                "different-installation",
                bootstrap.config_descriptor_digest(),
            )
            .is_err()
        );
        assert!(
            validate_runtime_binding(
                bootstrap.installation_id(),
                bootstrap.config_descriptor_digest(),
                bootstrap.installation_id(),
                &"c".repeat(64),
            )
            .is_err()
        );
        assert!(read_registry_for_bootstrap(&bootstrap).is_err());
    }

    #[test]
    fn manifest_bootstrap_and_reload_substitutions_fail_closed() {
        let bootstrap =
            parse_watchdog_scm_argv(valid_scm_args()).unwrap_or_else(|error| panic!("{error}"));
        let manifest = manifest_fixture(&bootstrap, "generation-7");
        assert!(manifest_matches_bootstrap(&manifest, &bootstrap));

        for (index, replacement) in [
            (2, OsString::from(r"C:\ProgramData\Eliot\config\other.json")),
            (4, OsString::from("c".repeat(64))),
            (8, OsString::from("6")),
            (
                10,
                OsString::from(r"C:\ProgramData\Eliot\installations\different-installation\host"),
            ),
        ] {
            let mut substituted_args = valid_scm_args();
            substituted_args[index] = replacement;
            let substituted = parse_watchdog_scm_argv(substituted_args)
                .unwrap_or_else(|error| panic!("substituted bootstrap: {error}"));
            assert!(!manifest_matches_bootstrap(&manifest, &substituted));
            assert!(read_registry_for_bootstrap(&substituted).is_err());
        }

        let mut wire = serde_json::to_value(&manifest)
            .unwrap_or_else(|error| panic!("serialize manifest fixture: {error}"));
        wire["runtime_launch"]["runtime_state_roots"]["host_state_root"] =
            serde_json::Value::String(
                r"C:\ProgramData\Eliot\installations\different-installation\host".to_owned(),
            );
        let substituted_manifest: CandidateManifest = serde_json::from_value(wire)
            .unwrap_or_else(|error| panic!("substituted manifest fixture: {error}"));
        assert!(!manifest_matches_bootstrap(
            &substituted_manifest,
            &bootstrap
        ));
    }

    #[test]
    fn process_and_service_main_argv_have_distinct_contracts() {
        let full = valid_scm_args();
        let process = parse_watchdog_process_argv(full[1..].to_vec())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            process.argv(),
            full[1..]
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        assert!(validate_watchdog_service_main_argv([OsString::from(SERVICE_NAME)]).is_ok());
        assert!(validate_watchdog_service_main_argv(full).is_err());
        assert!(validate_watchdog_service_main_argv(std::iter::empty::<OsString>()).is_err());
    }

    #[test]
    fn service_main_surface_is_read_only_and_identity_mismatch_fails_closed() {
        assert_eq!(
            classify_host_error(WindowsAdapterError::IdentityMismatch),
            HostObservationState::Unknown
        );
        let source = include_str!("main.rs");
        let library = include_str!("lib.rs");
        let default_surface = ["LiveHostObservationSource", "::", "default"].concat();
        let removed_observer = ["observe_running_", "eliot_host_process"].concat();
        let removed_config_probe = ["inspect_service_registration", "(registration)"].concat();
        assert!(!library.contains(&default_surface));
        assert!(library.contains("inspect_service_registration_runtime"));
        assert!(!library.contains(&removed_observer));
        assert!(!library.contains(&removed_config_probe));
        for forbidden in [
            "register_service(",
            "update_service_registration(",
            "delete_service_registration(",
            "start_service(",
            "stop_service(",
            "TerminateProcess",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden SCM/process effect: {forbidden}"
            );
        }
    }

    #[test]
    fn approved_host_image_comes_from_manifest_not_watchdog_sibling() {
        let (_, host_request) =
            installer_approval_fixture(InstallerServiceRole::Host, &"a".repeat(64));
        let (_, watchdog_request) =
            installer_approval_fixture(InstallerServiceRole::Watchdog, &"b".repeat(64));
        let host_image = host_request.binary_path();
        let derived_sibling = watchdog_request
            .binary_path()
            .parent()
            .unwrap_or_else(|| unreachable!())
            .join("eliot-host.exe");
        assert_ne!(host_image, derived_sibling);
        assert_eq!(
            host_image.file_name().and_then(|name| name.to_str()),
            Some("eliot-host.exe")
        );
    }

    #[test]
    fn host_identity_state_machine_detects_pid_reuse_and_image_substitution() {
        let mut monitor = HostIdentityMonitor::new(None);
        let canonical = ProcessIdentity {
            process_id: 41,
            start_time_100ns: 100,
            image_path: r"C:\ProgramData\Eliot\eliot-host.exe".to_owned(),
        };
        assert_eq!(
            monitor.observe_process_identity(canonical.clone()).state,
            HostObservationState::Running
        );
        assert_eq!(
            monitor
                .observe_process_identity(ProcessIdentity {
                    start_time_100ns: 101,
                    ..canonical.clone()
                })
                .state,
            HostObservationState::PidReused
        );
        assert_eq!(
            monitor
                .observe_process_identity(ProcessIdentity {
                    image_path: r"C:\Temp\evil.exe".to_owned(),
                    ..canonical
                })
                .state,
            HostObservationState::ImageSubstituted
        );
        assert_eq!(
            HostObservation {
                state: HostObservationState::AbsentOrStopped,
                identity: None,
            }
            .gap_reason(),
            Some(GapRecoveryReason::HostAbsentOrStopped)
        );
    }

    #[test]
    fn host_runtime_readback_maps_stopped_and_starting_without_baselining() {
        let identity = ProcessIdentity {
            process_id: 41,
            start_time_100ns: 100,
            image_path: r"C:\ProgramData\Eliot\eliot-host.exe".to_owned(),
        };
        let mut monitor =
            HostIdentityMonitor::new(Some(PathBuf::from(r"C:\ProgramData\Eliot\eliot-host.exe")));
        assert_eq!(
            monitor
                .observe_runtime_readback(WatchdogRuntimeReadback::Matching {
                    state: WatchdogRuntimeState::Stopped,
                    process: None,
                    checkpoint: 0,
                    wait_hint_ms: 0,
                })
                .state,
            HostObservationState::AbsentOrStopped
        );
        assert!(monitor.canonical_identity().is_none());
        assert_eq!(
            monitor
                .observe_runtime_readback(WatchdogRuntimeReadback::Matching {
                    state: WatchdogRuntimeState::Starting,
                    process: Some(identity.clone()),
                    checkpoint: 1,
                    wait_hint_ms: 250,
                })
                .state,
            HostObservationState::AbsentOrStopped
        );
        assert!(monitor.canonical_identity().is_none());
        assert_eq!(
            monitor
                .observe_runtime_readback(WatchdogRuntimeReadback::Matching {
                    state: WatchdogRuntimeState::Running,
                    process: Some(identity),
                    checkpoint: 0,
                    wait_hint_ms: 0,
                })
                .state,
            HostObservationState::Running
        );
        assert!(monitor.canonical_identity().is_some());
    }

    #[derive(Default)]
    struct SelfAdmissionFixture {
        now_ms: u64,
        inspect_advance_ms: u64,
        current: Option<ProcessIdentity>,
        observations: VecDeque<WatchdogRuntimeReadback>,
        sleeps: Vec<u32>,
    }

    impl WatchdogSelfAdmissionProbe for SelfAdmissionFixture {
        fn now_ms(&mut self) -> u64 {
            self.now_ms
        }

        fn current_process_identity(&mut self) -> Option<ProcessIdentity> {
            self.current.clone()
        }

        fn inspect(&mut self) -> WatchdogRuntimeReadback {
            self.now_ms = self.now_ms.saturating_add(self.inspect_advance_ms);
            self.observations
                .pop_front()
                .unwrap_or(WatchdogRuntimeReadback::Unknown)
        }

        fn sleep_ms(&mut self, milliseconds: u32) {
            self.sleeps.push(milliseconds);
            self.now_ms = self.now_ms.saturating_add(u64::from(milliseconds));
        }
    }

    #[derive(Default)]
    struct SelfAdmissionStatusFixture {
        reports: Vec<(u32, u32)>,
    }

    impl WatchdogSelfAdmissionStatus for SelfAdmissionStatusFixture {
        fn report_start_pending(&mut self, checkpoint: u32, wait_hint_ms: u32) {
            self.reports.push((checkpoint, wait_hint_ms));
        }
    }

    fn self_identity() -> ProcessIdentity {
        ProcessIdentity {
            process_id: 99,
            start_time_100ns: 1234,
            image_path: r"C:\ProgramData\Eliot\eliot-watchdog.exe".to_owned(),
        }
    }

    fn self_matching(
        state: WatchdogRuntimeState,
        process: Option<ProcessIdentity>,
    ) -> WatchdogRuntimeReadback {
        WatchdogRuntimeReadback::Matching {
            state,
            process,
            checkpoint: 2,
            wait_hint_ms: 250,
        }
    }

    #[test]
    fn self_admission_accepts_exact_starting_identity_without_start_effect() {
        let identity = self_identity();
        let mut fixture = SelfAdmissionFixture {
            current: Some(identity.clone()),
            observations: VecDeque::from([self_matching(
                WatchdogRuntimeState::Starting,
                Some(identity.clone()),
            )]),
            ..SelfAdmissionFixture::default()
        };
        let mut status = SelfAdmissionStatusFixture::default();
        let admitted = admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30)
            .unwrap_or_else(|error| panic!("self-admission failed: {error}"));
        assert_eq!(admitted, identity);
        assert!(status.reports.is_empty());
        assert!(fixture.sleeps.is_empty());
    }

    #[test]
    fn self_admission_accepts_exact_running_identity() {
        let identity = self_identity();
        let mut fixture = SelfAdmissionFixture {
            current: Some(identity.clone()),
            observations: VecDeque::from([self_matching(
                WatchdogRuntimeState::Running,
                Some(identity.clone()),
            )]),
            ..SelfAdmissionFixture::default()
        };
        let mut status = SelfAdmissionStatusFixture::default();
        let admitted = admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30)
            .unwrap_or_else(|error| panic!("self-admission failed: {error}"));
        assert_eq!(admitted, identity);
    }

    #[test]
    fn self_admission_rejects_exact_identity_observed_at_deadline() {
        let identity = self_identity();
        let mut fixture = SelfAdmissionFixture {
            inspect_advance_ms: 30,
            current: Some(identity.clone()),
            observations: VecDeque::from([self_matching(
                WatchdogRuntimeState::Starting,
                Some(identity),
            )]),
            ..SelfAdmissionFixture::default()
        };
        let mut status = SelfAdmissionStatusFixture::default();

        assert_eq!(
            admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30),
            Err(WatchdogSelfAdmissionError::Timeout)
        );
        assert!(status.reports.is_empty());
        assert!(fixture.sleeps.is_empty());
    }

    #[test]
    fn self_admission_rejects_pid_reuse_and_image_substitution() {
        let identity = self_identity();
        for substituted in [
            ProcessIdentity {
                start_time_100ns: identity.start_time_100ns + 1,
                ..identity.clone()
            },
            ProcessIdentity {
                image_path: r"C:\Temp\evil.exe".to_owned(),
                ..identity.clone()
            },
        ] {
            let mut fixture = SelfAdmissionFixture {
                current: Some(identity.clone()),
                observations: VecDeque::from([self_matching(
                    WatchdogRuntimeState::Starting,
                    Some(substituted),
                )]),
                ..SelfAdmissionFixture::default()
            };
            let mut status = SelfAdmissionStatusFixture::default();
            assert_eq!(
                admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30),
                Err(WatchdogSelfAdmissionError::RegistrationMismatched)
            );
        }
    }

    #[test]
    fn self_admission_rejects_stopped_service_and_times_out_unknown() {
        let identity = self_identity();
        let mut stopped = SelfAdmissionFixture {
            current: Some(identity.clone()),
            observations: VecDeque::from([self_matching(WatchdogRuntimeState::Stopped, None)]),
            ..SelfAdmissionFixture::default()
        };
        let mut stopped_status = SelfAdmissionStatusFixture::default();
        assert_eq!(
            admit_watchdog_self_start_with_deadline(&mut stopped, &mut stopped_status, 30),
            Err(WatchdogSelfAdmissionError::ServiceStopped)
        );

        let mut unknown = SelfAdmissionFixture {
            current: Some(identity),
            ..SelfAdmissionFixture::default()
        };
        let mut unknown_status = SelfAdmissionStatusFixture::default();
        assert_eq!(
            admit_watchdog_self_start_with_deadline(&mut unknown, &mut unknown_status, 100),
            Err(WatchdogSelfAdmissionError::Timeout)
        );
        assert!(
            unknown.now_ms <= 100,
            "poll must not overshoot the deadline"
        );
        assert!(!unknown_status.reports.is_empty());
        assert!(!unknown.sleeps.is_empty());
        assert!(unknown_status.reports.windows(2).all(|window| {
            window[1].0 > window[0].0 && window[1].1 >= SELF_ADMISSION_MIN_POLL_MS
        }));
    }

    #[test]
    fn self_admission_retries_missing_starting_identity_then_accepts() {
        let identity = self_identity();
        let mut fixture = SelfAdmissionFixture {
            current: Some(identity.clone()),
            observations: VecDeque::from([
                self_matching(WatchdogRuntimeState::Starting, None),
                self_matching(WatchdogRuntimeState::Running, Some(identity.clone())),
            ]),
            ..SelfAdmissionFixture::default()
        };
        let mut status = SelfAdmissionStatusFixture::default();
        let admitted = admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 100)
            .unwrap_or_else(|error| panic!("self-admission failed: {error}"));
        assert_eq!(admitted, identity);
        assert_eq!(status.reports.len(), 1);
        assert_eq!(fixture.sleeps.len(), 1);
    }

    #[test]
    fn lease_gap_classification_is_typed_and_rebaseline_is_explicit() {
        assert_eq!(
            admission_gap_reason(&SpoolError::LeaseStale("expired".to_owned())),
            GapRecoveryReason::LeaseStale
        );
        assert_eq!(
            admission_gap_reason(&SpoolError::LeaseFenced("expired".to_owned())),
            GapRecoveryReason::LeaseFenced
        );
        assert_eq!(
            admission_gap_reason(&SpoolError::InvalidLease("expired".to_owned())),
            GapRecoveryReason::LeaseInvalid
        );
        assert_eq!(
            kernel_gap_reason(&KernelWatchdogError::LeaseStale),
            GapRecoveryReason::LeaseStale
        );
        assert_eq!(
            kernel_gap_reason(&KernelWatchdogError::LeaseFenced),
            GapRecoveryReason::LeaseFenced
        );

        let mut monitor = HostIdentityMonitor::new(None);
        let identity = ProcessIdentity {
            process_id: 42,
            start_time_100ns: 100,
            image_path: r"C:\ProgramData\Eliot\eliot-host.exe".to_owned(),
        };
        assert_eq!(
            monitor.observe_process_identity(identity.clone()).state,
            HostObservationState::Running
        );
        monitor.rebaseline();
        assert_eq!(
            monitor.observe_process_identity(identity).state,
            HostObservationState::Running
        );
    }

    #[test]
    fn stale_lease_is_observation_only_and_never_current() {
        assert!(lease_window_is_current(100, 99, 101));
        assert!(!lease_window_is_current(101, 99, 101));
        assert!(!lease_window_is_current(98, 99, 101));
        assert!(
            !HostObservation {
                state: HostObservationState::AbsentOrStopped,
                identity: None,
            }
            .is_running()
        );
    }

    #[test]
    fn host_loss_disposition_is_nonfatal_and_bounded() {
        let observation = HostObservation {
            state: HostObservationState::ImageSubstituted,
            identity: None,
        };
        let disposition = GapRecoveryDisposition {
            record_type: "watchdog_gap",
            service: SERVICE_NAME,
            observed_at_ms: 1,
            reason: observation
                .gap_reason()
                .unwrap_or(GapRecoveryReason::HostUnknown),
            coverage_claimed: false,
        };
        assert_eq!(disposition.service, SERVICE_NAME);
        assert_eq!(disposition.reason, GapRecoveryReason::HostImageSubstituted);
        assert!(!disposition.coverage_claimed);
    }

    struct FailingGapPort {
        calls: Arc<AtomicUsize>,
    }

    impl KernelWatchdogPort for FailingGapPort {
        fn supervise<'a>(
            &'a self,
            _lease: &'a VerifiedSupervisionLease,
        ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
            Box::pin(async { Err(KernelWatchdogError::Unavailable) })
        }

        fn report_gap<'a>(
            &'a self,
            _disposition: GapRecoveryDisposition,
        ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(KernelWatchdogError::Failed) })
        }
    }

    struct AlwaysInvalidAdmission;

    impl WatchdogAdmissionSource for AlwaysInvalidAdmission {
        fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
            Err(SpoolError::InvalidLease("lease expired".to_owned()))
        }
    }

    struct CountingHost {
        calls: Arc<AtomicUsize>,
    }

    impl HostObservationSource for CountingHost {
        fn observe(&self) -> HostObservation {
            self.calls.fetch_add(1, Ordering::Relaxed);
            HostObservation {
                state: HostObservationState::Running,
                identity: None,
            }
        }
    }

    #[tokio::test]
    async fn host_loss_does_not_terminate_watchdog_when_spool_fails() {
        let calls = Arc::new(AtomicUsize::new(0));
        let port = FailingGapPort {
            calls: calls.clone(),
        };
        report_gap_nonfatal(&port, GapRecoveryReason::HostAbsentOrStopped).await;
        report_gap_nonfatal(&port, GapRecoveryReason::LeaseStale).await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn production_loop_survives_lease_and_spool_failures() {
        let calls = Arc::new(AtomicUsize::new(0));
        let host_calls = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let config = WatchdogConfig {
            tick_interval: Duration::from_millis(5),
            ..WatchdogConfig::default()
        };
        let composition = WatchdogComposition::start_with_shutdown_and_host(
            config,
            Arc::new(AlwaysInvalidAdmission),
            Arc::new(FailingGapPort {
                calls: calls.clone(),
            }),
            Arc::new(CountingHost {
                calls: host_calls.clone(),
            }),
            shutdown.clone(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let readiness = composition.readiness();
        assert_eq!(
            readiness.authority_state,
            WatchdogAuthorityState::RunningNoAuthority
        );
        assert!(!readiness.coverage_claimed);
        tokio::time::sleep(Duration::from_millis(35)).await;
        assert!(calls.load(Ordering::Relaxed) > 0);
        assert!(
            host_calls.load(Ordering::Relaxed) > 0,
            "Host observation must continue while admission is unavailable"
        );
        shutdown.store(true, Ordering::Release);
        composition
            .run_until_shutdown()
            .await
            .unwrap_or_else(|error| panic!("{error:?}"));
    }

    fn heartbeat(sequence: u64) -> WatchdogSpoolEntry {
        WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence,
            observed_at_ms: sequence,
            payload: WatchdogSpoolPayload::Gap {
                service: SERVICE_NAME.to_owned(),
                reason: GapRecoveryReason::AdmissionUnavailable,
                coverage_claimed: false,
            },
        }
    }

    #[test]
    fn canonical_service_identity_binds_runtime_evidence() {
        assert_eq!(SERVICE_NAME, "EliotWatchdog");
        assert_ne!(SERVICE_NAME, "eliot-watchdog");

        let entry = heartbeat(1);
        let WatchdogSpoolPayload::Gap { service, .. } = entry.payload else {
            unreachable!();
        };
        assert_eq!(service, "EliotWatchdog");
    }

    #[test]
    fn spool_schema_roundtrips_and_binds_sequence() {
        let entry = heartbeat(4);
        let bytes = encode_entry(&entry).unwrap_or_else(|_| unreachable!());
        let decoded: WatchdogSpoolEntry =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded, entry);
        let header = WatchdogSpoolHeader {
            schema_version: SPOOL_SCHEMA_VERSION,
            next_sequence: 5,
            first_sequence: 4,
            record_count: 1,
            bytes: bytes.len() as u64,
        };
        assert!(validate_header(&header, &[entry]).is_ok());
    }

    #[test]
    fn spool_schema_rejects_counter_or_sequence_substitution() {
        let entry = heartbeat(4);
        let bytes = encode_entry(&entry).unwrap_or_else(|_| unreachable!());
        let mut header = WatchdogSpoolHeader {
            schema_version: SPOOL_SCHEMA_VERSION,
            next_sequence: 5,
            first_sequence: 4,
            record_count: 2,
            bytes: bytes.len() as u64,
        };
        assert!(validate_header(&header, std::slice::from_ref(&entry)).is_err());
        header.record_count = 1;
        header.first_sequence = 3;
        assert!(validate_header(&header, &[entry]).is_err());
    }

    #[test]
    fn runtime_binding_rejects_missing_or_substituted_root_identity() {
        assert!(validate_runtime_binding("install-a", "roots-a", "install-a", "roots-a").is_ok());
        assert!(validate_runtime_binding("install-a", "roots-a", "install-b", "roots-a").is_err());
        assert!(validate_runtime_binding("install-a", "roots-a", "install-a", "roots-b").is_err());
        assert!(validate_runtime_binding("", "", "install-a", "roots-a").is_err());
    }

    #[test]
    fn host_admission_children_are_exact_and_never_legacy_or_created() {
        let host_root = Path::new(
            r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
        );
        assert!(
            validate_host_admission_child(
                host_root,
                &host_root.join(SUPERVISION_LEASE_FILE_NAME),
                SUPERVISION_LEASE_FILE_NAME,
            )
            .is_ok()
        );
        assert!(
            validate_host_admission_child(
                host_root,
                Path::new(r"C:\ProgramData\Eliot\host\supervision-lease.json"),
                SUPERVISION_LEASE_FILE_NAME,
            )
            .is_err()
        );
        assert!(
            validate_host_admission_child(
                host_root,
                &host_root.join(r"..\other\supervision-lease.json"),
                SUPERVISION_LEASE_FILE_NAME,
            )
            .is_err()
        );
        assert!(validate_host_admission_child(
            host_root,
            Path::new(
                r"C:\ProgramData\Eliot\installations\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\host\installation-registry.redb",
            ),
            INSTALLATION_REGISTRY_FILE_NAME,
        )
        .is_err());
    }

    #[test]
    fn watchdog_production_path_is_root_bound_and_read_only() {
        let source = include_str!("main.rs");
        let library = include_str!("lib.rs");
        assert!(source.contains("host_state_root"));
        assert!(!source.contains("protected_program_data_path"));
        assert!(library.contains("ProtectedRootLease::open_existing"));
        assert!(library.contains("RedbInstallationRegistry::inspect_existing_at"));
        let legacy_registry_call = ["RedbInstallationRegistry::inspect_existing", "("].concat();
        let mutating_registry_call = ["RedbInstallationRegistry::open_at", "("].concat();
        assert!(!library.contains(&legacy_registry_call));
        assert!(!library.contains(&mutating_registry_call));
        for forbidden in [
            ["RedbInstallationRegistry::", "open("].concat(),
            ["RedbInstallationRegistry::", "open_existing_at("].concat(),
            ["RedbInstallationRegistry::", "load("].concat(),
            [".", "claim_pending_activation("].concat(),
            [".", "mark_pending_recovery("].concat(),
            [".", "commit_pending_activation("].concat(),
            [".", "abort_pending_activation("].concat(),
            [".", "save("].concat(),
        ] {
            assert!(
                !library.contains(&forbidden),
                "Watchdog production must remain read-only: {forbidden}"
            );
        }
    }

    #[test]
    fn runtime_spool_path_rejects_root_substitution() {
        let program_data = Path::new(r"C:\ProgramData");
        let outside = Path::new(r"C:\Users\Public\watchdog.redb");
        assert!(matches!(
            runtime_spool_relative_path(outside, program_data),
            Err(SpoolError::InvalidProtectedRoot)
        ));
    }

    #[test]
    fn redb_spool_reopens_and_retains_bounded_records() {
        let root =
            std::env::temp_dir().join(format!("eliot-watchdog-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("watchdog.redb");
        let spool = WatchdogSpool::open_test(&path).unwrap_or_else(|error| panic!("{error}"));
        let bounded_payload = || WatchdogSpoolPayload::Recovery {
            service: SERVICE_NAME.to_owned(),
            reason: "x".repeat(16_000),
            corrupt_sequence: None,
            corrupt_digest: "digest".to_owned(),
        };
        for sequence in 0..300 {
            spool
                .append(sequence + 1, bounded_payload())
                .unwrap_or_else(|error| panic!("{error}"));
        }
        let retained = spool.readback().unwrap_or_else(|error| panic!("{error}"));
        assert!(retained.len() < 300);
        drop(spool);
        let reopened = WatchdogSpool::open_test(&path).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            reopened
                .readback()
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            retained.len()
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    fn prepared_spool(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("eliot-watchdog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("watchdog.redb");
        let spool = WatchdogSpool::open_test(&path).unwrap_or_else(|error| panic!("{error}"));
        spool
            .append(
                1,
                WatchdogSpoolPayload::Gap {
                    service: SERVICE_NAME.to_owned(),
                    reason: GapRecoveryReason::AdmissionUnavailable,
                    coverage_claimed: false,
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        drop(spool);
        (root, path)
    }

    fn replace_high_water(path: &std::path::Path, bytes: Option<&[u8]>) {
        let database = Database::open(path).unwrap_or_else(|error| panic!("{error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("{error}"));
        {
            let mut table = write
                .open_table(SPOOL_HIGH_WATER_TABLE)
                .unwrap_or_else(|error| panic!("{error}"));
            match bytes {
                Some(bytes) => table
                    .insert(SPOOL_HIGH_WATER_KEY, bytes)
                    .unwrap_or_else(|error| panic!("{error}")),
                None => table
                    .remove(SPOOL_HIGH_WATER_KEY)
                    .unwrap_or_else(|error| panic!("{error}")),
            };
        }
        write.commit().unwrap_or_else(|error| panic!("{error}"));
        drop(database);
    }

    #[test]
    fn redb_spool_missing_high_water_fails_closed() {
        let (root, path) = prepared_spool("missing-high-water");
        replace_high_water(&path, None);
        assert!(matches!(
            WatchdogSpool::open_test(&path),
            Err(SpoolError::Corrupt(detail)) if detail.contains("high-water")
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn redb_spool_malformed_high_water_fails_closed() {
        let (root, path) = prepared_spool("malformed-high-water");
        replace_high_water(&path, Some(b"not-json"));
        assert!(matches!(
            WatchdogSpool::open_test(&path),
            Err(SpoolError::Corrupt(detail)) if detail.contains("high-water")
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn redb_spool_mismatched_high_water_fails_closed() {
        let (root, path) = prepared_spool("mismatched-high-water");
        let bytes = encode_high_water(99).unwrap_or_else(|error| panic!("{error}"));
        replace_high_water(&path, Some(&bytes));
        assert!(matches!(
            WatchdogSpool::open_test(&path),
            Err(SpoolError::Corrupt(detail)) if detail.contains("high-water")
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn redb_spool_corruption_writes_recovery_evidence_without_reusing_sequence() {
        let root =
            std::env::temp_dir().join(format!("eliot-watchdog-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("watchdog.redb");
        let spool = WatchdogSpool::open_test(&path).unwrap_or_else(|error| panic!("{error}"));
        spool
            .append(
                1,
                WatchdogSpoolPayload::Gap {
                    service: SERVICE_NAME.to_owned(),
                    reason: GapRecoveryReason::AdmissionUnavailable,
                    coverage_claimed: false,
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        drop(spool);
        let database = Database::open(&path).unwrap_or_else(|error| panic!("{error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("{error}"));
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .unwrap_or_else(|error| panic!("{error}"));
            table
                .insert(1, b"not-json".as_slice())
                .unwrap_or_else(|error| panic!("{error}"));
        }
        write.commit().unwrap_or_else(|error| panic!("{error}"));
        drop(database);
        let recovered = WatchdogSpool::open_test(&path).unwrap_or_else(|error| panic!("{error}"));
        let entries = recovered
            .readback()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            entries.first().map(|entry| &entry.payload),
            Some(WatchdogSpoolPayload::Recovery { .. })
        ));
        assert_eq!(entries.first().map(|entry| entry.sequence), Some(2));
        recovered
            .append(
                3,
                WatchdogSpoolPayload::Gap {
                    service: SERVICE_NAME.to_owned(),
                    reason: GapRecoveryReason::AdmissionUnavailable,
                    coverage_claimed: false,
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let appended = recovered
            .readback()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            appended
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        drop(recovered);
        let reopened = WatchdogSpool::open_test(&path).unwrap_or_else(|error| panic!("{error}"));
        let reopened_entries = reopened
            .readback()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            reopened_entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }
}
