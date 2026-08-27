//! Composition root for the independent Runtime 0.17 watchdog.
//!
//! The watchdog owns timing and supervision admission only.  Kernel effects
//! remain behind [`KernelWatchdogPort`], which makes it impossible for this
//! binary to turn a stale observation into process authority by itself.

#![forbid(unsafe_code)]
#![cfg_attr(test, recursion_limit = "256")]

#[cfg(test)]
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{AuthorityEpoch, sha256_hex};
#[cfg(test)]
use eliot_installation::{
    ApprovedGenerationRegistry, InstallerServiceRegistrationApproval, InstallerServiceRole,
    PendingActivationState, phase_b_scm_selector,
};
use eliot_installation::{
    CandidateManifest, InstallationProfile, RedbInstallationRegistry, RuntimeStateRoots,
    ValidatedRuntimeRootLeases, WindowsRuntimeRootLease, WindowsRuntimeRootLeaseProvider,
    verify_file_digest, verify_file_digest_with_lease,
};
use eliot_ors::{SupervisionLeaseSnapshot, read_current_supervision_lease_read_only};
#[cfg(test)]
use eliot_platform_windows::WindowsAdapterError;
use eliot_platform_windows::{
    NamedPipePeerProcessBinding, ProcessIdentity, ProtectedPathLease, ProtectedRootLease,
    ProtectedRuntimePathLease, ServiceBootstrapArguments, ServiceRegistrationRequest,
    WindowsPlatform, observe_owned_directory_exact, windows_paths_equal,
};
use eliot_runtime::{
    ChildClass, Runtime, RuntimeConfig, ShutdownOutcome, SupervisionStrategy, TaskFailure,
};
use eliot_runtime_contracts::{
    ProvisionedSupervisionAuthority, SignedSupervisionLease, SupervisionLeaseError,
    SupervisionLeaseVerificationContext, SupervisionLeaseVerifier, SupervisionTrustAnchor,
    VerifiedSupervisionLease, WATCHDOG_PUBLICATION_DIRECTORY_PREFIX, WatchdogAdmissionTemplate,
    WatchdogPublicationBundle,
};
pub use eliot_runtime_contracts::{
    SUPERVISION_LEASE_FILE_NAME, WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_FILE_NAME,
};
use eliot_watchdog_core::{Epoch, Watchdog};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;

#[cfg(test)]
mod registry_fixture;

pub const SERVICE_NAME: &str = "EliotWatchdog";
pub const PROTOCOL_VERSION: &str = "eliot.watchdog.v1";
/// Approved-generation registry below the approved Host state root.
pub const INSTALLATION_REGISTRY_FILE_NAME: &str = "installation-registry.redb";
const LEASE_FILE_LIMIT: u64 = 1024 * 1024;
const KERNEL_ORS_FILE_NAME: &str = "kernel-ors.redb";
const HOST_JOURNAL_FILE_NAME: &str = "host-state-journal.redb";

mod runtime_manifest_selection;
mod scm_launch;
mod self_admission;
mod service_registration_projection;
mod supervision_lease_load;

#[cfg(test)]
pub(crate) use service_registration_projection::{
    approved_service_registration, service_approval_matches_manifest,
};
pub(crate) use service_registration_projection::{
    load_approved_service_registrations, read_approved_service_registration,
    validate_bound_service_registrations,
};

#[cfg(test)]
use runtime_manifest_selection::manifest_matches_bootstrap;
use runtime_manifest_selection::{
    approved_host_artifact_path, read_registry_for_bootstrap, select_runtime_manifest,
};
pub use scm_launch::{
    ApprovedHostRegistration, ValidatedWatchdogScmLaunch, WatchdogScmLaunchError,
    parse_watchdog_process_argv, parse_watchdog_scm_argv, validate_watchdog_scm_bootstrap,
    validate_watchdog_scm_launch, validate_watchdog_service_main_argv,
};
#[cfg(test)]
use self_admission::SELF_ADMISSION_MIN_POLL_MS;
pub use self_admission::{
    WATCHDOG_SELF_ADMISSION_DEADLINE_MS, WatchdogRuntimeReadback, WatchdogRuntimeState,
    WatchdogSelfAdmissionError, WatchdogSelfAdmissionProbe, WatchdogSelfAdmissionStatus,
    admit_watchdog_self_start, admit_watchdog_self_start_with_deadline,
    project_service_runtime_inspection,
};

/// Canonical public admission template shared with Host/runtime-status.
pub type WatchdogAdmissionConfig = WatchdogAdmissionTemplate;

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

/// Registry- and ORS-backed admission source for the immutable Host
/// publication selected by the current authoritative ORS receipt.
pub struct FileWatchdogAdmission {
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
    provisioned_supervision_authority: ProvisionedSupervisionAuthority,
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
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
        let registry_path = registry_path.into();
        let (installation_id, binding) = load_runtime_binding(&registry_path, &bootstrap)?;
        Ok(Self {
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
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
        Self::from_registry(registry_path, bootstrap)
    }

    #[must_use]
    pub fn runtime_binding(&self) -> WatchdogRuntimeBinding {
        self.binding.clone()
    }
}

impl WatchdogAdmissionSource for FileWatchdogAdmission {
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
        let template = self
            .binding
            .provisioned_supervision_authority
            .watchdog_admission_template()
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
        supervision_lease_load::load_content_addressed_supervision_lease_bound(
            self,
            &template,
            &self
                .binding
                .provisioned_supervision_authority
                .watchdog_admission_template_digest,
        )
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
const WATCHDOG_SPOOL_FILE_NAME: &str = "watchdog.redb";
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
    _path_lease: Option<ProtectedRuntimePathLease>,
}

impl WatchdogSpool {
    fn open_runtime_binding(binding: &WatchdogRuntimeBinding) -> Result<Self, SpoolError> {
        let path = watchdog_spool_path(binding.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_or_create_absolute(&path)
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

    fn open_existing_runtime_binding(binding: &WatchdogRuntimeBinding) -> Result<Self, SpoolError> {
        let path = watchdog_spool_path(binding.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: Some(path_lease),
        })
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

fn watchdog_spool_path(watchdog_state_root: &Path) -> PathBuf {
    watchdog_state_root.join(WATCHDOG_SPOOL_FILE_NAME)
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
    /// Returns an error if the retained per-installation spool cannot be
    /// opened or if its identity, database, header, sequence, or records fail
    /// validation.
    pub fn readback(
        binding: &WatchdogRuntimeBinding,
    ) -> Result<Vec<WatchdogSpoolEntry>, SpoolError> {
        WatchdogSpool::open_existing_runtime_binding(binding)?.readback()
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
                restart_window: Duration::from_mins(1),
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

#[allow(
    clippy::too_many_lines,
    reason = "runtime binding selection keeps protected registry, manifest, bootstrap, and retained-root checks in one fail-closed read transaction"
)]
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
    let provisioned_supervision_authority = registry
        .provisioned_supervision_authority_for_generation(&selected_manifest.generation)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .cloned()
        .ok_or_else(|| {
            SpoolError::InvalidLease(
                "selected generation has no durable provisioned supervision authority".to_owned(),
            )
        })?;
    provisioned_supervision_authority
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if provisioned_supervision_authority.candidate_generation
        != selected_manifest.generation.as_str()
    {
        return Err(SpoolError::InvalidLease(
            "provisioned supervision authority is foreign to the selected generation".to_owned(),
        ));
    }
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
            provisioned_supervision_authority,
            host_state_root_lease: Arc::new(host_state_root_lease),
            _approved_host_image_lease: Arc::new(approved_host_image_lease),
            _root_leases: Arc::new(leases),
        },
    ))
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedWatchdogPublication {
    marker: WatchdogPublicationBundle,
    admission: WatchdogAdmissionConfig,
    lease: SignedSupervisionLease,
    raw: eliot_platform_windows::OwnedDirectoryObservation,
}

fn observe_watchdog_publication(path: &Path) -> Result<ObservedWatchdogPublication, SpoolError> {
    let raw = observe_owned_directory_exact(
        path,
        &[
            WATCHDOG_ADMISSION_FILE_NAME,
            SUPERVISION_LEASE_FILE_NAME,
            WATCHDOG_PUBLICATION_FILE_NAME,
        ],
        LEASE_FILE_LIMIT,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let admission_bytes = raw
        .bytes(WATCHDOG_ADMISSION_FILE_NAME)
        .ok_or_else(|| SpoolError::InvalidLease("admission child is absent".to_owned()))?;
    let lease_bytes = raw
        .bytes(SUPERVISION_LEASE_FILE_NAME)
        .ok_or_else(|| SpoolError::InvalidLease("lease child is absent".to_owned()))?;
    let marker_bytes = raw
        .bytes(WATCHDOG_PUBLICATION_FILE_NAME)
        .ok_or_else(|| SpoolError::InvalidLease("publication marker is absent".to_owned()))?;
    let admission: WatchdogAdmissionConfig = serde_json::from_slice(admission_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let lease: SignedSupervisionLease = serde_json::from_slice(lease_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let marker: WatchdogPublicationBundle = serde_json::from_slice(marker_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    admission
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    lease
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    marker
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if admission
        .canonical_bytes()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        != admission_bytes
        || serde_json::to_vec(&lease)
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
            != lease_bytes
        || marker
            .canonical_bytes()
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
            != marker_bytes
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog publication children are not canonical".to_owned(),
        ));
    }
    marker
        .verify_bytes(admission_bytes, lease_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if marker.installation_id != admission.installation_id
        || marker.approved_generation != admission.approved_generation
        || marker.supervision_lease_scope_id != admission.supervision_lease_scope_id
        || marker.supervision_lease_id != lease.payload.lease_id
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog marker is not bound to its admission template".to_owned(),
        ));
    }
    let expected_name = marker
        .directory_name()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| !name.eq_ignore_ascii_case(&expected_name))
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog directory is not keyed by its ORS receipt".to_owned(),
        ));
    }
    Ok(ObservedWatchdogPublication {
        marker,
        admission,
        lease,
        raw,
    })
}

fn scan_watchdog_publications(
    host_state_root: &Path,
) -> Result<Vec<ObservedWatchdogPublication>, SpoolError> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(host_state_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or(SpoolError::InvalidProtectedRoot)?;
        if name
            .to_ascii_lowercase()
            .starts_with(WATCHDOG_PUBLICATION_DIRECTORY_PREFIX)
        {
            observed.push(observe_watchdog_publication(&entry.path())?);
        }
    }
    Ok(observed)
}

fn read_manifest_selected_ors_current(
    selected_manifest: &CandidateManifest,
    lease_id: &eliot_ors::OperationIdentity,
) -> Result<Option<SupervisionLeaseSnapshot>, SpoolError> {
    let kernel_ors_path = PathBuf::from(
        selected_manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_ors_root
            .as_str(),
    )
    .join(KERNEL_ORS_FILE_NAME);
    let kernel_ors_lease = ProtectedRuntimePathLease::open_existing_absolute(&kernel_ors_path)
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS open failed: {error}")))?;
    if !windows_paths_equal(kernel_ors_lease.path(), &kernel_ors_path) {
        return Err(SpoolError::InvalidLease(
            "Kernel ORS path is not the manifest-selected path".to_owned(),
        ));
    }
    kernel_ors_lease
        .verify_stable_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS changed: {error}")))?;
    kernel_ors_lease
        .verify_path_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS path changed: {error}")))?;
    read_current_supervision_lease_read_only(kernel_ors_lease.path(), lease_id)
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS read failed: {error}")))
}

fn verify_against_durable_current(
    trust_anchor: &SupervisionTrustAnchor,
    context: &SupervisionLeaseVerificationContext,
    envelope: &SignedSupervisionLease,
    durable_current: Option<SupervisionLeaseSnapshot>,
) -> Result<VerifiedSupervisionLease, SpoolError> {
    let durable_current = durable_current.ok_or_else(|| {
        SpoolError::LeaseFenced("Kernel ORS has no current supervision lease".to_owned())
    })?;
    if durable_current.record.artifact != *envelope {
        return Err(SpoolError::LeaseFenced(
            "signed supervision lease is not the exact durable Kernel ORS artifact".to_owned(),
        ));
    }
    validate_payload_bindings(context, &envelope.payload)
        .map_err(|error| map_lease_verification_error(&error))?;
    let mut context = context.clone();
    context.ors_mirror = durable_current.record.artifact.payload.ors_mirror.clone();
    context
        .validate()
        .map_err(|error| map_lease_verification_error(&error))?;
    let lease = trust_anchor
        .verify(envelope, &context)
        .map_err(|error| map_lease_verification_error(&error))?;
    if lease.payload() != &durable_current.record.artifact.payload {
        return Err(SpoolError::LeaseFenced(
            "verified supervision lease diverged from the durable Kernel ORS artifact".to_owned(),
        ));
    }
    Ok(lease)
}

/// Validates the independently admitted lease contour before replacing the
/// context ORS mirror with the exact durable artifact.  The Store-base
/// runtime-contracts crate predates the shared helper, so this composition
/// root keeps the same comparison local rather than accepting a payload-owned
/// ORS mirror.
fn validate_payload_bindings(
    context: &SupervisionLeaseVerificationContext,
    payload: &eliot_runtime_contracts::SupervisionLease,
) -> Result<(), SupervisionLeaseError> {
    context.validate()?;
    payload
        .validate()
        .map_err(SupervisionLeaseError::InvalidPayload)?;
    if payload.lease_id != context.lease_id {
        return Err(SupervisionLeaseError::LeaseIdentityMismatch);
    }
    if payload.host_epoch != context.host_epoch
        || payload.activation_generation != context.activation_generation
        || payload.activation_id != context.activation_id
        || payload.kernel_epoch != context.kernel_epoch
        || payload.watchdog_epoch != context.watchdog_epoch
        || payload.state_fence != context.state_fence
        || payload.scope_ref != context.scope_ref
        || payload.observation_scope != context.observation_scope
    {
        return Err(SupervisionLeaseError::EpochOrActivationMismatch);
    }
    let binding = &payload.generation_binding;
    if binding.target_id != context.target_id
        || binding.module_id != context.module_id
        || binding.process_id != context.process_id
        || binding.target_generation != context.target_generation
        || binding.module_generation != context.module_generation
        || binding.process_generation != context.process_generation
    {
        return Err(SupervisionLeaseError::GenerationMismatch);
    }
    if payload.state != context.active_state.state
        || payload.revocation_id != context.active_state.revocation_id
        || payload.revocation_epoch != context.active_state.revocation_epoch
    {
        return Err(SupervisionLeaseError::ActiveStateMismatch);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::registry_fixture::RegistryFixture;
    use super::*;
    use eliot_runtime_contracts::{SupervisionLeaseSigner, SupervisionLeaseVerifier};
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

    #[allow(
        clippy::too_many_lines,
        reason = "the matrix keeps all protected approval and bootstrap substitutions together"
    )]
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
        let service_control_grant = match role {
            InstallerServiceRole::Host => serde_json::Value::Null,
            InstallerServiceRole::Watchdog => {
                let principal_sid = "S-1-5-80-1-2-3-4-5";
                let security_descriptor_digest =
                    match eliot_platform_windows::watchdog_service_security_descriptor_digest(
                        principal_sid,
                    ) {
                        Ok(digest) => digest,
                        Err(error) => panic!("Watchdog control-grant fixture: {error}"),
                    };
                serde_json::json!({
                    "principal_service": eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
                    "principal_sid": principal_sid,
                    "access_mask": eliot_platform_windows::ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                    "security_descriptor_digest": security_descriptor_digest,
                })
            }
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
            "service_control_grant": service_control_grant,
        });
        let approval = serde_json::from_value(wire)
            .unwrap_or_else(|error| panic!("approval fixture: {error}"));
        (approval, request)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the manifest fixture explicitly initializes the full deny-unknown production contract"
    )]
    fn manifest_fixture(
        bootstrap: &ServiceBootstrapArguments,
        generation: &str,
    ) -> CandidateManifest {
        use eliot_runtime_contracts::SupervisionLeaseSigner as _;

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
        let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
            "eliot-kernel",
            "test-supervision-key",
            [0x39; 32],
        )
        .unwrap_or_else(|error| panic!("test supervision signer: {error}"));
        let trust_anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
            &installation,
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap_or_else(|error| panic!("test supervision anchor: {error}"));
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
        .unwrap_or_else(|error| panic!("test sealed key reference: {error}"));
        let provisioned_authority = ProvisionedSupervisionAuthority::new(
            "test-supervision-lease",
            generation,
            eliot_contracts::ResourceGeneration::new(authority_generation)
                .unwrap_or_else(|error| panic!("test authority generation: {error}")),
            key_reference,
            trust_anchor,
        )
        .unwrap_or_else(|error| panic!("test provisioned supervision authority: {error}"));
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
            "supervision_authority": {
                "state": "PROVISIONED",
                "authority": provisioned_authority
            },
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
            "protected_snapshot_digest": "a".repeat(64),
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

    fn bootstrap_fixture(digest: &str) -> ServiceBootstrapArguments {
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\config\watchdog.json"),
            digest,
            "installation-7",
            7,
            std::iter::empty::<String>(),
        )
        .and_then(|value| {
            value.with_host_state_root(PathBuf::from(
                r"C:\ProgramData\Eliot\installations\installation-7\host",
            ))
        })
        .unwrap_or_else(|error| panic!("bootstrap fixture: {error}"))
    }

    fn manifest_with_authority_digest(
        bootstrap: &ServiceBootstrapArguments,
        authority_digest: &str,
    ) -> CandidateManifest {
        let mut wire = serde_json::to_value(manifest_fixture(bootstrap, "generation-7"))
            .unwrap_or_else(|error| panic!("serialize manifest fixture: {error}"));
        wire["runtime_launch"]["authority_descriptor_digest"] =
            serde_json::Value::String(authority_digest.to_owned());
        serde_json::from_value(wire)
            .unwrap_or_else(|error| panic!("authority digest fixture: {error}"))
    }

    fn bind_manifest_host_image(
        manifest: CandidateManifest,
        request: &ServiceRegistrationRequest,
    ) -> CandidateManifest {
        let mut wire = serde_json::to_value(manifest)
            .unwrap_or_else(|error| panic!("serialize service manifest fixture: {error}"));
        wire["runtime_launch"]["host_executable_path"] =
            serde_json::Value::String(request.binary_path().to_string_lossy().into_owned());
        serde_json::from_value(wire)
            .unwrap_or_else(|error| panic!("service manifest fixture: {error}"))
    }

    #[test]
    fn pending_phase_b_marker_is_accepted_by_both_watchdog_bootstrap_paths() {
        let bootstrap = bootstrap_fixture(eliot_installation::PHASE_B_PENDING_SCM_DIGEST);
        let (approval, request) = installer_approval_fixture_for_bootstrap(
            InstallerServiceRole::Host,
            &"b".repeat(64),
            &bootstrap,
        );
        let manifest = bind_manifest_host_image(
            manifest_with_authority_digest(&bootstrap, eliot_installation::PHASE_B_PENDING_MARKER),
            &request,
        );
        let approved_bootstrap = request
            .bootstrap()
            .unwrap_or_else(|| panic!("approval bootstrap fixture is missing"));

        assert_eq!(
            phase_b_scm_selector(&manifest.runtime_launch.authority_descriptor_digest)
                .unwrap_or_else(|error| panic!("pending selector canonicalization: {error}"))
                .as_str(),
            approved_bootstrap.config_descriptor_digest()
        );
        assert!(manifest_matches_bootstrap(&manifest, approved_bootstrap));
        assert!(service_approval_matches_manifest(
            &approval,
            &request,
            &manifest,
            InstallerServiceRole::Host
        ));
    }

    #[test]
    fn raw_or_substituted_phase_b_selector_is_rejected() {
        let bootstrap = bootstrap_fixture(eliot_installation::PHASE_B_PENDING_SCM_DIGEST);
        let (approval, request) = installer_approval_fixture_for_bootstrap(
            InstallerServiceRole::Host,
            &"b".repeat(64),
            &bootstrap,
        );
        let manifest = bind_manifest_host_image(
            manifest_with_authority_digest(&bootstrap, eliot_installation::PHASE_B_PENDING_MARKER),
            &request,
        );
        let raw_bootstrap = ServiceBootstrapArguments::new(
            bootstrap.config_descriptor_path().to_path_buf(),
            eliot_installation::PHASE_B_PENDING_MARKER,
            bootstrap.installation_id(),
            bootstrap.transaction_plan_generation(),
            std::iter::empty::<String>(),
        );
        assert!(raw_bootstrap.is_err());

        let substituted_bootstrap = bootstrap_fixture(&"c".repeat(64))
            .with_registration_nonce("d".repeat(64))
            .unwrap_or_else(|error| panic!("substituted bootstrap fixture: {error}"));
        assert!(!manifest_matches_bootstrap(
            &manifest,
            &substituted_bootstrap
        ));
        let substituted_request = ServiceRegistrationRequest::with_bootstrap(
            request.service_name(),
            request.display_name(),
            request.binary_path().to_path_buf(),
            request.start_mode(),
            request.account(),
            substituted_bootstrap,
        )
        .unwrap_or_else(|error| panic!("substituted request fixture: {error}"));
        assert!(!service_approval_matches_manifest(
            &approval,
            &substituted_request,
            &manifest,
            InstallerServiceRole::Host
        ));
    }

    #[test]
    fn verified_phase_b_marker_remains_an_exact_selector() {
        let bootstrap = bootstrap_fixture(&"a".repeat(64));
        let (approval, request) = installer_approval_fixture_for_bootstrap(
            InstallerServiceRole::Host,
            &"b".repeat(64),
            &bootstrap,
        );
        let manifest = bind_manifest_host_image(
            manifest_with_authority_digest(&bootstrap, bootstrap.config_descriptor_digest()),
            &request,
        );
        let approved_bootstrap = request
            .bootstrap()
            .unwrap_or_else(|| panic!("approval bootstrap fixture is missing"));
        let selector = phase_b_scm_selector(&manifest.runtime_launch.authority_descriptor_digest)
            .unwrap_or_else(|error| panic!("verified selector canonicalization: {error}"));

        assert_eq!(
            selector.as_str(),
            manifest.runtime_launch.authority_descriptor_digest.as_str()
        );
        assert!(manifest_matches_bootstrap(&manifest, approved_bootstrap));
        assert!(service_approval_matches_manifest(
            &approval,
            &request,
            &manifest,
            InstallerServiceRole::Host
        ));
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
    fn production_admission_uses_only_ors_addressed_publications() {
        let library = include_str!("lib.rs");
        assert!(library.contains("load_content_addressed_supervision_lease_bound"));
        assert!(library.contains("provisioned_supervision_authority_for_generation"));
        assert!(library.contains("WATCHDOG_PUBLICATION_DIRECTORY_PREFIX"));
        let legacy_fixed_loader = ["fn load_supervision_lease_", "bound("].concat();
        assert!(!library.contains(&legacy_fixed_loader));
        let fixed_lease_child = ["host_state_root.join(SUPERVISION_", "LEASE_FILE_NAME)"].concat();
        let fixed_admission_child =
            ["host_state_root.join(WATCHDOG_", "ADMISSION_FILE_NAME)"].concat();
        assert!(!library.contains(&fixed_lease_child));
        assert!(!library.contains(&fixed_admission_child));
    }

    #[test]
    fn watchdog_production_path_is_root_bound_and_read_only() {
        let source = include_str!("main.rs");
        let library = include_str!("lib.rs");
        assert!(source.contains("host_state_root"));
        assert!(source.contains("FileWatchdogAdmission::from_registry"));
        assert!(!source.contains("protected_program_data_path"));
        assert!(!source.contains("std::env::var"));
        assert!(!source.contains("std::env::current_dir"));
        assert!(!source.contains(r"C:\ProgramData\Eliot\host\installation-registry.redb"));
        assert!(library.contains("ProtectedRootLease::open_existing"));
        assert!(library.contains("RedbInstallationRegistry::inspect_existing_at"));
        assert!(library.contains("ProtectedRuntimePathLease::open_existing_absolute"));
        assert!(library.contains("read_current_supervision_lease_read_only"));
        assert!(library.contains("validate_payload_bindings"));
        assert!(library.contains("trust_anchor.verify"));
        assert!(library.contains("binding.watchdog_state_root()"));
        let legacy_spool_path = ["Eliot/", "watchdog/watchdog.redb"].concat();
        assert!(!library.contains(&legacy_spool_path));
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

    fn supervision_fixture_path() -> PathBuf {
        let serial = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "eliot-watchdog-supervision-{pid}-{serial}.redb",
            pid = std::process::id()
        ))
    }

    fn supervision_fixture_binding(
        issued_at_ms: u64,
    ) -> Result<eliot_ors::SupervisionLeaseBinding, Box<dyn std::error::Error>> {
        Ok(eliot_ors::SupervisionLeaseBinding {
            scope_ref: eliot_ors::OperationIdentity::new("scope-supervision")?,
            observation_scope: eliot_runtime_contracts::SupervisionObservationScope {
                targets: vec!["target-1".to_owned()],
                sensor_profile: "kernel-heartbeat".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live".to_owned(),
            },
            installation_id: eliot_ors::OperationIdentity::new("installation-1")?,
            host_epoch: AuthorityEpoch::new(1)?,
            activation_id: eliot_ors::OperationIdentity::new("activation-1")?,
            activation_generation: eliot_contracts::ResourceGeneration::new(1)?,
            kernel_epoch: AuthorityEpoch::new(2)?,
            watchdog_epoch: AuthorityEpoch::new(1)?,
            generation_binding: eliot_runtime_contracts::SupervisionGenerationBinding {
                target_id: "target-1".to_owned(),
                target_generation: eliot_contracts::ResourceGeneration::new(1)?,
                module_id: "module-1".to_owned(),
                module_generation: eliot_contracts::ResourceGeneration::new(1)?,
                process_id: "kernel-process-1".to_owned(),
                process_generation: eliot_contracts::ResourceGeneration::new(1)?,
            },
            state_fence: eliot_contracts::StateFence::new(
                AuthorityEpoch::new(2)?,
                eliot_contracts::ResourceGeneration::new(1)?,
            ),
            issued_at_ms,
            expires_at_ms: issued_at_ms + 900,
            renew_before_ms: issued_at_ms + 450,
            wake_policy: eliot_runtime_contracts::RegisteredActivityWakePolicy::Disabled,
            state: eliot_runtime_contracts::LeaseState::Active,
            terminal_disposition: None,
            revocation_reason: None,
            revocation_id: None,
            revocation_epoch: None,
        })
    }

    fn supervision_fixture_request(
        ticket_id: &str,
        operation_id: &str,
        lease_id: &str,
        expected_revision: Option<u64>,
        operation: eliot_ors::SupervisionLeaseOperation,
        binding: eliot_ors::SupervisionLeaseBinding,
    ) -> Result<eliot_ors::SupervisionLeasePrepareRequest, Box<dyn std::error::Error>> {
        Ok(eliot_ors::SupervisionLeasePrepareRequest {
            ticket_id: eliot_ors::OperationIdentity::new(ticket_id)?,
            operation_id: eliot_ors::OperationIdentity::new(operation_id)?,
            lease_id: eliot_ors::OperationIdentity::new(lease_id)?,
            expected_revision,
            operation,
            binding,
        })
    }

    fn supervision_fixture_signer()
    -> Result<eliot_runtime_contracts::Ed25519SupervisionLeaseSigner, Box<dyn std::error::Error>>
    {
        Ok(
            eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
                "kernel-1",
                "kernel-key-1",
                [7; 32],
            )?,
        )
    }

    fn supervision_fixture_envelope(
        stage: &eliot_ors::SupervisionLeaseStageReceipt,
    ) -> Result<SignedSupervisionLease, Box<dyn std::error::Error>> {
        Ok(stage
            .ticket
            .expected_payload()?
            .sign(&supervision_fixture_signer()?)?)
    }

    fn supervision_fixture_verifier(
        envelope: &SignedSupervisionLease,
    ) -> Result<
        (SupervisionTrustAnchor, SupervisionLeaseVerificationContext),
        Box<dyn std::error::Error>,
    > {
        let signer = supervision_fixture_signer()?;
        let anchor = SupervisionTrustAnchor::new(
            envelope.payload.installation_id.clone(),
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )?;
        let generation = &envelope.payload.generation_binding;
        let context = SupervisionLeaseVerificationContext {
            now_ms: envelope.payload.issued_at_ms + 1,
            lease_id: envelope.payload.lease_id.clone(),
            host_epoch: envelope.payload.host_epoch,
            activation_id: envelope.payload.activation_id.clone(),
            activation_generation: envelope.payload.activation_generation,
            kernel_epoch: envelope.payload.kernel_epoch,
            watchdog_epoch: envelope.payload.watchdog_epoch,
            state_fence: envelope.payload.state_fence.clone(),
            scope_ref: envelope.payload.scope_ref.clone(),
            observation_scope: envelope.payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: envelope.payload.ors_mirror.clone(),
            active_state: eliot_runtime_contracts::SupervisionLeaseActiveStateBinding {
                state: envelope.payload.state,
                revocation_id: envelope.payload.revocation_id.clone(),
                revocation_epoch: envelope.payload.revocation_epoch,
            },
        };
        Ok((anchor, context))
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the renewal matrix keeps exact, stale, substituted, missing and unknown ORS cases together"
    )]
    fn watchdog_renewal_requires_exact_current_ors_artifact()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = supervision_fixture_path();
        let store = eliot_ors::RedbRecoveryStore::open(&path)?;
        let now_ms = current_unix_ms()?;
        let first_stage = store.prepare_supervision_lease(supervision_fixture_request(
            "ticket-r1",
            "operation-r1",
            "lease-renewal",
            None,
            eliot_ors::SupervisionLeaseOperation::Commit,
            supervision_fixture_binding(now_ms.saturating_sub(200))?,
        )?)?;
        let first_envelope = supervision_fixture_envelope(&first_stage)?;
        let (first_anchor, first_context) = supervision_fixture_verifier(&first_envelope)?;
        let first_verified = first_anchor.verify(&first_envelope, &first_context)?;
        let first = store.commit_supervision_lease(&first_stage.ticket, &first_verified)?;

        let second_stage = store.prepare_supervision_lease(supervision_fixture_request(
            "ticket-r2",
            "operation-r2",
            "lease-renewal",
            Some(1),
            eliot_ors::SupervisionLeaseOperation::Renew,
            supervision_fixture_binding(now_ms.saturating_sub(100))?,
        )?)?;
        let second_envelope = supervision_fixture_envelope(&second_stage)?;
        let (second_anchor, second_context) = supervision_fixture_verifier(&second_envelope)?;
        let second_verified = second_anchor.verify(&second_envelope, &second_context)?;
        let second = store.commit_supervision_lease(&second_stage.ticket, &second_verified)?;
        drop(store);

        let (anchor, mut stale_context) = supervision_fixture_verifier(&first_envelope)?;
        stale_context.now_ms = second_envelope.payload.issued_at_ms + 1;
        let lease_id = eliot_ors::OperationIdentity::new("lease-renewal")?;
        let durable_r2 = eliot_ors::read_current_supervision_lease_read_only(&path, &lease_id)?;
        assert_eq!(
            durable_r2
                .as_ref()
                .map(|snapshot| &snapshot.record.artifact),
            Some(&second_envelope)
        );
        let accepted = verify_against_durable_current(
            &anchor,
            &stale_context,
            &second_envelope,
            durable_r2.clone(),
        )?;
        assert_eq!(accepted.lease_revision(), 2);
        assert_eq!(accepted.payload(), &second_envelope.payload);

        assert!(
            verify_against_durable_current(
                &anchor,
                &stale_context,
                &second_envelope,
                Some(first.clone()),
            )
            .is_err()
        );

        let mut substituted = second.clone();
        substituted.record.artifact = first_envelope.clone();
        assert!(
            verify_against_durable_current(
                &anchor,
                &stale_context,
                &second_envelope,
                Some(substituted),
            )
            .is_err()
        );

        assert!(
            verify_against_durable_current(&anchor, &stale_context, &second_envelope, None,)
                .is_err()
        );

        let unknown_lease = eliot_ors::OperationIdentity::new("lease-unknown")?;
        let unknown_current =
            eliot_ors::read_current_supervision_lease_read_only(&path, &unknown_lease)?;
        assert!(unknown_current.is_none());
        assert!(
            verify_against_durable_current(
                &anchor,
                &stale_context,
                &second_envelope,
                unknown_current,
            )
            .is_err()
        );

        let missing_path = path.with_file_name("eliot-watchdog-supervision-missing.redb");
        assert!(
            eliot_ors::read_current_supervision_lease_read_only(&missing_path, &unknown_lease,)
                .is_err()
        );
        let _ignored = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn watchdog_spool_path_is_bound_to_the_retained_installation_root() {
        let watchdog_root = Path::new(
            r"C:\ProgramData\Eliot\installations\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\watchdog",
        );
        let expected = watchdog_root.join("watchdog.redb");
        assert_eq!(watchdog_spool_path(watchdog_root), expected);
        assert_ne!(
            expected,
            Path::new(r"C:\ProgramData\Eliot\watchdog\watchdog.redb")
        );
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
