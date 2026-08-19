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
    ApprovedGenerationRegistry, CandidateManifest, InstallationProfile, PendingActivationState,
    RedbInstallationRegistry, RuntimeStateRoots, ValidatedRuntimeRootLeases,
    WindowsRuntimeRootLease, WindowsRuntimeRootLeaseProvider, verify_file_digest,
    verify_file_digest_with_lease,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
    NamedPipePeerProcessBinding, ProcessIdentity, ProtectedPathLease, ServiceAccount,
    ServiceBootstrapArguments, ServiceRegistrationInspection, ServiceRegistrationRequest,
    ServiceStartMode, WindowsAdapterError, WindowsPlatform, observe_running_eliot_host_process,
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

pub const SERVICE_NAME: &str = "EliotWatchdog";
pub const PROTOCOL_VERSION: &str = "eliot.watchdog.v1";
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
    #[error("Watchdog SCM registration is not an exact read-only match: {0:?}")]
    Registration(ServiceRegistrationInspection),
}

/// Exact, read-only launch evidence accepted from the Windows Service Control
/// Manager.  The registration request is retained only as an inspection query;
/// this type exposes no SCM mutation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWatchdogScmLaunch {
    bootstrap: ServiceBootstrapArguments,
    registration: ServiceRegistrationRequest,
    inspection: ServiceRegistrationInspection,
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
    pub fn inspection(&self) -> &ServiceRegistrationInspection {
        &self.inspection
    }
}

/// Parses the complete argv vector delivered to the SCM service callback.
///
/// `argv[0]` must be the canonical service name and the remaining ten values
/// must be exactly the ordered bootstrap pairs rendered by
/// [`ServiceBootstrapArguments`], including the registration nonce.  No
/// optional or unknown arguments are accepted for the installed service.
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
    if args.len() != 11 {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "expected service name plus five canonical pairs".to_owned(),
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
        || !flag(9, "--registration-nonce")
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
    let registration_nonce = text(10, "registration nonce")?;
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
    let executable = std::env::current_exe().map_err(WatchdogScmLaunchError::Executable)?;
    let display_name = ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME;
    let registration = ServiceRegistrationRequest::with_bootstrap(
        SERVICE_NAME,
        display_name,
        executable.clone(),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap.clone(),
    )
    .map_err(WatchdogScmLaunchError::Platform)?;
    let root = executable.parent().ok_or_else(|| {
        WatchdogScmLaunchError::InvalidArgv("current executable has no parent".to_owned())
    })?;
    let platform = WindowsPlatform::new(root.to_path_buf())
        .map_err(|error| WatchdogScmLaunchError::PlatformRoot(error.to_string()))?;
    let inspection = platform.inspect_service_registration(&registration);
    if !matches!(inspection, ServiceRegistrationInspection::Matching { .. }) {
        return Err(WatchdogScmLaunchError::Registration(inspection));
    }
    Ok(ValidatedWatchdogScmLaunch {
        bootstrap: bootstrap.clone(),
        registration,
        inspection,
    })
}

/// Installation-owned Watchdog admission configuration.  It is loaded from a
/// fixed `ProgramData` path and independently bound to the active registry
/// manifest digest; no value is selected from the lease envelope.
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
    roots: RuntimeStateRoots,
    selected_manifest: Arc<CandidateManifest>,
    approved_host_image: PathBuf,
    _approved_host_image_lease: Arc<ProtectedPathLease>,
    _root_leases: Arc<ValidatedRuntimeRootLeases<WindowsRuntimeRootLease>>,
}

impl WatchdogRuntimeBinding {
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
        let registry_path = registry_path.into();
        let (installation_id, binding) = load_runtime_binding(&registry_path, &bootstrap)?;
        Ok(Self {
            lease_path: lease_path.into(),
            admission_config_path: admission_config_path.into(),
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
        load_supervision_lease_bound(
            &self.lease_path,
            &self.admission_config_path,
            &self.registry_path,
            &self.installation_id,
            &self.roots_digest,
            &self.bootstrap,
            &self.binding.selected_manifest,
        )
    }

    fn approved_host_image(&self) -> Option<PathBuf> {
        Some(self.binding.approved_host_image().to_owned())
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

/// Retains the last trusted Host process identity and compares every later
/// platform observation against PID, creation time, and image path.
#[derive(Debug)]
pub struct HostIdentityMonitor {
    canonical: Option<ProcessIdentity>,
    expected_image: Option<PathBuf>,
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
            expected_image_lease: None,
            require_image_lease: false,
            require_registration_readback: false,
        }
    }

    fn with_approved_image_lease(expected_image: PathBuf, lease: ProtectedPathLease) -> Self {
        Self {
            canonical: None,
            expected_image: Some(expected_image),
            expected_image_lease: Some(lease),
            require_image_lease: true,
            require_registration_readback: true,
        }
    }

    fn with_unavailable_image_lease(expected_image: PathBuf) -> Self {
        Self {
            canonical: None,
            expected_image: Some(expected_image),
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
    /// platform primitive and classifies all non-authoritative outcomes.
    #[must_use]
    pub fn observe(&mut self) -> HostObservation {
        if self.require_registration_readback {
            let registration_ok = self
                .expected_image
                .as_deref()
                .is_some_and(|image| inspect_approved_host_registration(image).is_ok());
            if !registration_ok {
                return HostObservation {
                    state: HostObservationState::Unknown,
                    identity: None,
                };
            }
        }
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
        match observe_running_eliot_host_process() {
            Ok(binding) => self.observe_identity(&binding),
            Err(error) => HostObservation {
                state: classify_host_error(error),
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

    /// Opens the approved Host image through the protected no-follow adapter
    /// so a same-path replacement is an identity gap, not a fresh baseline.
    /// If the image cannot be retained, the source stays alive but emits only
    /// fail-closed `Unknown` observations until the approved image can be
    /// retained again.
    #[must_use]
    pub fn try_new(expected_image: PathBuf) -> Self {
        let monitor = match ProtectedPathLease::open_existing_absolute(&expected_image) {
            Ok(lease) => HostIdentityMonitor::with_approved_image_lease(expected_image, lease),
            Err(_) => HostIdentityMonitor::with_unavailable_image_lease(expected_image),
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
        let host = Arc::new(LiveHostObservationSource::try_new(expected_host_image));
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
    let registry = RedbInstallationRegistry::inspect_existing(registry_path)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
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
            roots,
            selected_manifest: Arc::new(selected_manifest),
            approved_host_image,
            _approved_host_image_lease: Arc::new(approved_host_image_lease),
            _root_leases: Arc::new(leases),
        },
    ))
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
    bootstrap.config_descriptor_path() == Path::new(launch.authority_descriptor_path.as_str())
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

/// Performs a read-only SCM readback for the exact Host sibling selected by
/// the immutable runtime contour. This binds the observation path to the
/// installed service command and fails closed on absent, mismatched, or
/// unknown registration; it never creates or changes a service.
///
/// # Errors
///
/// Returns an error when the canonical Host service registration is absent,
/// mismatched, or cannot be observed authoritatively.
pub fn inspect_approved_host_registration(host_image: &Path) -> Result<(), SpoolError> {
    let display_name = ELIOT_HOST_SERVICE_DISPLAY_NAME;
    let registration = ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        display_name,
        host_image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let root = host_image.parent().ok_or_else(|| {
        SpoolError::InvalidLease("approved Host image has no generation root".to_owned())
    })?;
    let platform = WindowsPlatform::new(root.to_path_buf())
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let inspection = platform.inspect_service_registration(&registration);
    if matches!(inspection, ServiceRegistrationInspection::Matching { .. }) {
        Ok(())
    } else {
        Err(SpoolError::InvalidLease(format!(
            "approved Host SCM registration is not an exact read-only match: {inspection:?}"
        )))
    }
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
    lease_path: impl AsRef<Path>,
    admission_config_path: impl AsRef<Path>,
    registry_path: impl AsRef<Path>,
    expected_installation_id: &str,
    expected_roots_digest: &str,
    bootstrap: &ServiceBootstrapArguments,
    expected_manifest: &CandidateManifest,
) -> Result<VerifiedWatchdogAdmission, SpoolError> {
    let lease_path = lease_path.as_ref();
    let admission_config_path = admission_config_path.as_ref();
    let registry_path = registry_path.as_ref();
    for (path, relative) in [
        (lease_path, "Eliot/host/supervision-lease.json"),
        (admission_config_path, "Eliot/host/watchdog-admission.json"),
        (registry_path, "Eliot/host/installation-registry.redb"),
    ] {
        require_protected_program_data_path(path, relative)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
    }
    validate_text(expected_installation_id, "installation_id")?;
    let config_bytes = read_bounded(admission_config_path, ADMISSION_CONFIG_LIMIT)?;
    let config: WatchdogAdmissionConfig = serde_json::from_slice(&config_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    config.validate_shape()?;
    let registry = RedbInstallationRegistry::inspect_existing(registry_path)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
    if selected_manifest != *expected_manifest {
        return Err(SpoolError::InvalidLease(
            "selected runtime contour changed after watchdog binding".to_owned(),
        ));
    }
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
    ProtectedPathLease::open_existing_absolute(path)
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
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn valid_scm_args() -> Vec<OsString> {
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\config\watchdog.json"),
            "a".repeat(64),
            "installation-7",
            7,
            std::iter::empty::<String>(),
        )
        .and_then(|value| value.with_registration_nonce("b".repeat(64)))
        .unwrap_or_else(|error| panic!("{error}"));
        let mut args = vec![OsString::from(SERVICE_NAME)];
        args.extend(bootstrap.argv().into_iter().map(OsString::from));
        args
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the explicit JSON fixture preserves the complete fail-closed registry wire projection"
    )]
    fn pending_registry_fixture(
        bootstrap: &ServiceBootstrapArguments,
        generation_count: usize,
    ) -> ApprovedGenerationRegistry {
        let descriptor_path = bootstrap
            .config_descriptor_path()
            .to_string_lossy()
            .into_owned();
        let descriptor_digest = bootstrap.config_descriptor_digest().to_owned();
        let installation = bootstrap.installation_id().to_owned();
        let authority_generation = bootstrap.transaction_plan_generation();
        let watchdog_path = r"C:\ProgramData\Eliot\packages\generation-7\eliot-watchdog.exe";
        let host_path = r"C:\ProgramData\Eliot\packages\generation-7\host\eliot-host.exe";
        let host_root = r"C:\ProgramData\Eliot\state\host";
        let kernel_root = r"C:\ProgramData\Eliot\state\kernel\state";
        let kernel_work_root = r"C:\ProgramData\Eliot\state\kernel\work";
        let store_data_root = r"C:\ProgramData\Eliot\state\store\data";
        let store_work_root = r"C:\ProgramData\Eliot\state\store\work";
        let store_temp_root = r"C:\ProgramData\Eliot\state\store\tmp";
        let watchdog_root = r"C:\ProgramData\Eliot\state\watchdog";
        let roots_digest = "f".repeat(64);
        let config_digest = "d".repeat(64);
        let supervision_fingerprint = "e".repeat(64);
        let manifest = serde_json::json!({
            "generation": "generation-7",
            "components": ["component-kernel", "component-store"],
            "kernel_artifact_digest": "0".repeat(64),
            "store_bridge_artifact_digest": "1".repeat(64),
            "canonical_store_artifact_digest": "2".repeat(64),
            "host_artifact_digest": "8".repeat(64),
            "kernel_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-kernel.exe",
            "store_bridge_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-store-surreal.exe",
            "canonical_store_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\surreal.exe",
            "host_executable_path": host_path,
            "config_path": descriptor_path.clone(),
            "dependency_closure_refs": ["evidence-dependencies"],
            "license_refs": ["evidence-licenses"],
            "config_digest": config_digest.clone(),
            "store_credential_target": "eliot/store/v1/0123456789abcdef0123456789abcdef",
            "supervision_key_fingerprint": supervision_fingerprint.clone(),
            "signature_ref": "evidence-signature",
            "runtime_state_roots_digest": roots_digest.clone(),
            "runtime_launch": {
                "profile": "system_service",
                "portable_root": null,
                "installation_epoch": {
                    "installation": installation,
                    "lineage_id": "lineage-7",
                    "sequence": 1
                },
                "generation": "generation-7",
                "authority_generation": authority_generation,
                "authority_state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": authority_generation,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                },
                "authority_descriptor_path": descriptor_path,
                "authority_descriptor_digest": descriptor_digest,
                "runtime_state_roots": {
                    "profile": "system_service",
                    "profile_anchor_root": r"C:\ProgramData",
                    "installation_root": r"C:\ProgramData\Eliot\state",
                    "host_state_root": host_root,
                    "kernel_ors_root": kernel_root,
                    "kernel_work_root": kernel_work_root,
                    "store_data_root": store_data_root,
                    "store_work_root": store_work_root,
                    "store_temp_root": store_temp_root,
                    "watchdog_state_root": watchdog_root,
                    "roots_digest": roots_digest
                },
                "kernel_work_root": kernel_work_root,
                "kernel_artifact_digest": "0".repeat(64),
                "eliotd_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliotd.exe",
                "eliotd_artifact_digest": "9".repeat(64),
                "eliotd_config_path": r"C:\ProgramData\Eliot\packages\generation-7\eliotd-governor.json",
                "eliotd_config_digest": "a".repeat(64),
                "eliotd_descriptor_path": r"C:\ProgramData\Eliot\packages\generation-7\eliotd.json",
                "eliotd_descriptor_digest": "b".repeat(64),
                "eliotd_launch_nonce": "eliotd:0123456789abcdef0123456789abcdef",
                "store_config_path": descriptor_path.clone(),
                "store_credential_target": "eliot/store/v1/0123456789abcdef0123456789abcdef",
                "store_bridge_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\eliot-store-surreal.exe",
                "store_bridge_artifact_digest": "1".repeat(64),
                "store_bootstrap_descriptor_path": r"C:\ProgramData\Eliot\packages\generation-7\store-bootstrap.json",
                "store_bootstrap_descriptor_digest": "3".repeat(64),
                "canonical_store_executable_path": r"C:\ProgramData\Eliot\packages\generation-7\surreal.exe",
                "canonical_store_artifact_digest": "2".repeat(64),
                "kernel_arguments": [],
                "store_bridge_arguments": [],
                "canonical_store_arguments": [],
                "host_executable_path": host_path,
                "host_artifact_digest": "8".repeat(64),
                "watchdog_executable_path": watchdog_path,
                "watchdog_artifact_digest": "4".repeat(64),
                "descriptor_digest": "5".repeat(64)
            }
        });
        let approved = serde_json::json!({
            "manifest": manifest.clone(),
            "approval_ref": "approval-generation-7",
            "active": false,
            "last_known_good": false
        });
        let generations = (0..generation_count)
            .map(|_| approved.clone())
            .collect::<Vec<_>>();
        serde_json::from_value(serde_json::json!({
            "generations": generations,
            "active_generation": null,
            "last_known_good_generation": null,
            "pending_activation": {
                "transaction_id": "transaction-generation-7",
                "plan_digest": "6".repeat(64),
                "manifest": manifest,
                "config_digest": config_digest,
                "kernel_artifact_digest": "0".repeat(64),
                "store_bridge_artifact_digest": "1".repeat(64),
                "canonical_store_artifact_digest": "2".repeat(64),
                "host_executable_path": host_path,
                "host_artifact_digest": "8".repeat(64),
                "runtime_state_roots_digest": roots_digest,
                "manifest_digest": "7".repeat(64),
                "prior_active_generation": null,
                "approval_ref": "approval-generation-7",
                "state": {"state": "PENDING"}
            },
            "last_terminal_activation": null
        }))
        .unwrap_or_else(|error| panic!("{error}"))
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
        substituted[10] = OsString::from("C".repeat(64));
        assert!(parse_watchdog_scm_argv(substituted).is_err());
    }

    #[test]
    fn scm_argv_requires_registration_nonce_and_exact_service_name() {
        let mut missing_nonce = valid_scm_args();
        missing_nonce.truncate(9);
        assert!(parse_watchdog_scm_argv(missing_nonce).is_err());

        let mut wrong_service = valid_scm_args();
        wrong_service[0] = OsString::from("EliotHost");
        assert!(parse_watchdog_scm_argv(wrong_service).is_err());
    }

    #[test]
    fn pending_registry_selects_first_install_without_synthesizing_active() {
        let args = valid_scm_args();
        let bootstrap = parse_watchdog_scm_argv(args).unwrap_or_else(|error| panic!("{error}"));
        let registry = pending_registry_fixture(&bootstrap, 1);
        assert!(registry.active().is_none());
        let selected = select_runtime_manifest(&registry, &bootstrap)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            selected.runtime_launch.authority_descriptor_path.as_str(),
            bootstrap
                .config_descriptor_path()
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(selected.runtime_launch.authority_generation.value(), 7);
    }

    #[test]
    fn active_generation_wins_only_for_its_bootstrap_when_pending_upgrade_exists() {
        let pending_args = valid_scm_args();
        let pending_bootstrap =
            parse_watchdog_scm_argv(pending_args).unwrap_or_else(|error| panic!("{error}"));
        let mut active_args = valid_scm_args();
        active_args[2] = OsString::from(r"C:\ProgramData\Eliot\config\active.json");
        active_args[4] = OsString::from("9".repeat(64));
        active_args[8] = OsString::from("6");
        let active_bootstrap =
            parse_watchdog_scm_argv(active_args).unwrap_or_else(|error| panic!("{error}"));

        let pending_registry = pending_registry_fixture(&pending_bootstrap, 1);
        let mut wire =
            serde_json::to_value(pending_registry).unwrap_or_else(|error| panic!("{error}"));
        let mut active_manifest = wire["pending_activation"]["manifest"].clone();
        active_manifest["generation"] = serde_json::json!("generation-6");
        active_manifest["runtime_launch"]["generation"] = serde_json::json!("generation-6");
        active_manifest["runtime_launch"]["authority_descriptor_path"] = serde_json::json!(
            active_bootstrap
                .config_descriptor_path()
                .to_string_lossy()
                .into_owned()
        );
        active_manifest["runtime_launch"]["authority_descriptor_digest"] =
            serde_json::json!(active_bootstrap.config_descriptor_digest());
        active_manifest["runtime_launch"]["authority_generation"] =
            serde_json::json!(active_bootstrap.transaction_plan_generation());
        let pending_manifest = wire["pending_activation"]["manifest"].clone();
        wire["generations"] = serde_json::json!([
            {
                "manifest": active_manifest,
                "approval_ref": "approval-generation-6",
                "active": true,
                "last_known_good": false
            },
            {
                "manifest": pending_manifest,
                "approval_ref": "approval-generation-7",
                "active": false,
                "last_known_good": false
            }
        ]);
        wire["active_generation"] = serde_json::json!("generation-6");
        let registry: ApprovedGenerationRegistry =
            serde_json::from_value(wire).unwrap_or_else(|error| panic!("{error}"));

        let active = select_runtime_manifest(&registry, &active_bootstrap)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(active.runtime_launch.authority_generation.value(), 6);
        let pending = select_runtime_manifest(&registry, &pending_bootstrap)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(pending.runtime_launch.authority_generation.value(), 7);
    }

    #[test]
    fn pending_registry_rejects_substitution_multiple_and_unmatched_bootstrap() {
        let args = valid_scm_args();
        let bootstrap = parse_watchdog_scm_argv(args).unwrap_or_else(|error| panic!("{error}"));
        let multiple = pending_registry_fixture(&bootstrap, 2);
        assert!(select_runtime_manifest(&multiple, &bootstrap).is_err());

        let mut substituted_args = valid_scm_args();
        substituted_args[4] = OsString::from("c".repeat(64));
        let substituted =
            parse_watchdog_scm_argv(substituted_args).unwrap_or_else(|error| panic!("{error}"));
        let registry = pending_registry_fixture(&bootstrap, 1);
        assert!(select_runtime_manifest(&registry, &substituted).is_err());

        let mut unmatched_args = valid_scm_args();
        unmatched_args[2] = OsString::from(r"C:\ProgramData\Eliot\config\other.json");
        let unmatched =
            parse_watchdog_scm_argv(unmatched_args).unwrap_or_else(|error| panic!("{error}"));
        assert!(select_runtime_manifest(&registry, &unmatched).is_err());
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
        assert!(!library.contains(&default_surface));
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
        let args = valid_scm_args();
        let bootstrap = parse_watchdog_scm_argv(args).unwrap_or_else(|error| panic!("{error}"));
        let registry = pending_registry_fixture(&bootstrap, 1);
        let manifest = select_runtime_manifest(&registry, &bootstrap)
            .unwrap_or_else(|error| panic!("{error}"));
        let approved_host = Path::new(manifest.runtime_launch.host_executable_path.as_str());
        let derived_sibling = Path::new(manifest.runtime_launch.watchdog_executable_path.as_str())
            .parent()
            .unwrap_or_else(|| unreachable!())
            .join("eliot-host.exe");

        assert_eq!(
            approved_host,
            Path::new(r"C:\ProgramData\Eliot\packages\generation-7\host\eliot-host.exe")
        );
        assert_ne!(approved_host, derived_sibling);
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
