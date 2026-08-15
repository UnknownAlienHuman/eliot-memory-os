//! Composition root for the independent Runtime 0.17 watchdog.
//!
//! The watchdog owns timing and supervision admission only.  Kernel effects
//! remain behind [`KernelWatchdogPort`], which makes it impossible for this
//! binary to turn a stale observation into process authority by itself.

#![forbid(unsafe_code)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{AuthorityEpoch, sha256_hex};
use eliot_installation::RedbInstallationRegistry;
use eliot_platform_windows::{
    ProtectedPathLease, protected_program_data_path, require_protected_program_data_path,
};
use eliot_runtime::{
    ChildClass, Runtime, RuntimeConfig, ShutdownOutcome, SupervisionStrategy, TaskFailure,
};
use eliot_runtime_contracts::{
    SignedSupervisionLease, SupervisionLeaseVerificationContext, SupervisionLeaseVerifier,
    SupervisionTrustAnchor, VerifiedSupervisionLease,
};
use eliot_watchdog_core::{Epoch, Watchdog};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-watchdog";
pub const PROTOCOL_VERSION: &str = "eliot.watchdog.v1";
const ADMISSION_CONFIG_SCHEMA: &str = "eliot.watchdog-admission.v1";
const ADMISSION_CONFIG_LIMIT: u64 = 1024 * 1024;
const LEASE_FILE_LIMIT: u64 = 1024 * 1024;

/// Installation-owned Watchdog admission configuration.  It is loaded from a
/// fixed ProgramData path and independently bound to the active registry
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
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError>;
}

/// File-backed admission source for the Host/Kernel lease and its independent
/// trust/configuration/registry inputs.
#[derive(Clone, Debug)]
pub struct FileWatchdogAdmission {
    lease_path: PathBuf,
    admission_config_path: PathBuf,
    registry_path: PathBuf,
}

impl FileWatchdogAdmission {
    #[must_use]
    pub fn new(
        lease_path: impl Into<PathBuf>,
        admission_config_path: impl Into<PathBuf>,
        registry_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            lease_path: lease_path.into(),
            admission_config_path: admission_config_path.into(),
            registry_path: registry_path.into(),
        }
    }
}

impl WatchdogAdmissionSource for FileWatchdogAdmission {
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
        load_supervision_lease(
            &self.lease_path,
            &self.admission_config_path,
            &self.registry_path,
        )
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
}

const SPOOL_SCHEMA_VERSION: u16 = 1;
const SPOOL_HEADER_KEY: u64 = 0;
const SPOOL_MAX_RECORDS: u64 = 4096;
const SPOOL_MAX_BYTES: u64 = 4 * 1024 * 1024;
const SPOOL_MAX_RECORD_BYTES: usize = 64 * 1024;
const SPOOL_RELATIVE_PATH: &str = "Eliot/watchdog/watchdog.redb";
const SPOOL_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("eliot_watchdog_spool_v1");

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
    fn open(path: &Path) -> Result<Self, SpoolError> {
        require_protected_program_data_path(path, SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let path_lease = ProtectedPathLease::open_or_create(SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        let database = Database::create(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
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
                return self.write_header(WatchdogSpoolHeader {
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
        let valid = parsed_header
            .as_ref()
            .zip(entries.as_ref().ok())
            .is_some_and(|(header, entries)| validate_header(header, entries).is_ok());
        if valid {
            return Ok(());
        }
        let corrupt_digest = header
            .as_ref()
            .map(|value| sha256_hex(value.value()))
            .unwrap_or_else(|| "missing".to_owned());
        drop(table);
        drop(read);
        self.recover(
            "existing spool header or record set failed validation",
            None,
            corrupt_digest,
        )
    }

    fn write_header(&self, header: WatchdogSpoolHeader) -> Result<(), SpoolError> {
        let bytes = serde_json::to_vec(&header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
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
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence: 1,
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
            next_sequence: 2,
            first_sequence: 1,
            record_count: 1,
            bytes: bytes.len() as u64,
        };
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
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
        }
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
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let mut header: WatchdogSpoolHeader = serde_json::from_slice(&header_bytes)
            .map_err(|error| SpoolError::Corrupt(format!("invalid spool header: {error}")))?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let sequence = header.next_sequence;
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
        drop(table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }
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

/// Bounded, non-authoritative record emitted when admission is lost.  A gap
/// never claims coverage and carries no replacement trust material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GapRecoveryReason {
    AdmissionUnavailable,
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
    watchdog: Mutex<Watchdog>,
    spool: WatchdogSpool,
}

impl IndependentKernelSensor {
    /// Opens the one canonical protected redb spool below ProgramData.
    pub fn open(path: impl Into<PathBuf>, watchdog_epoch: u64) -> Result<Self, SpoolError> {
        let spool = path.into();
        require_protected_program_data_path(&spool, SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let spool_store = WatchdogSpool::open(&spool)?;
        let watchdog = Watchdog::new(
            eliot_watchdog_core::WatchdogConfig::default(),
            Epoch(watchdog_epoch),
        )
        .map_err(|_| SpoolError::InvalidLease("watchdog epoch is invalid".to_owned()))?;
        Ok(Self {
            watchdog: Mutex::new(watchdog),
            spool: spool_store,
        })
    }

    /// Opens the exact canonical protected watchdog spool below ProgramData.
    pub fn open_program_data(
        relative_path: impl Into<PathBuf>,
        watchdog_epoch: u64,
    ) -> Result<Self, SpoolError> {
        let relative = relative_path.into();
        let spool =
            protected_program_data_path(&relative).map_err(|_| SpoolError::InvalidProtectedRoot)?;
        Self::open(spool, watchdog_epoch)
    }

    /// Reads and validates the ordered spool records for an independent
    /// reader. The redb file remains observation-only and is not authority.
    pub fn readback(path: impl AsRef<Path>) -> Result<Vec<WatchdogSpoolEntry>, SpoolError> {
        let path = path.as_ref();
        require_protected_program_data_path(path, SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let path_lease = ProtectedPathLease::open_existing(SPOOL_RELATIVE_PATH)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
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
        let watchdog = self
            .watchdog
            .lock()
            .map_err(|_| KernelWatchdogError::Failed)?;
        let epoch = watchdog.epoch();
        if epoch.0 == 0 || lease.lease().watchdog_epoch.value() != epoch.0 {
            return Err(KernelWatchdogError::LeaseRejected);
        }
        let now_ms = current_unix_ms().map_err(|_| KernelWatchdogError::LeaseRejected)?;
        if now_ms < lease.lease().issued_at_ms || now_ms >= lease.lease().expires_at_ms {
            return Err(KernelWatchdogError::LeaseRejected);
        }
        let digest = lease
            .payload_digest()
            .map_err(|_| KernelWatchdogError::LeaseRejected)?;
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

/// Non-secret failure returned by the kernel supervision boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelWatchdogError {
    #[error("kernel supervision endpoint is unavailable")]
    Unavailable,
    #[error("kernel rejected supervision lease")]
    LeaseRejected,
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
    pub kernel_epoch: u64,
    pub watchdog_epoch: u64,
    pub tick_interval_ms: u128,
}

/// Runtime-owned watchdog composition.
pub struct WatchdogComposition {
    runtime: Runtime,
    admission: Arc<dyn WatchdogAdmissionSource>,
    kernel_epoch: u64,
    watchdog_epoch: u64,
    config: WatchdogConfig,
    task: eliot_runtime::SupervisedHandle,
    shutdown_requested: Arc<AtomicBool>,
}

impl WatchdogComposition {
    /// Builds and admits the watchdog loop against an injected kernel port.
    pub fn start(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown(config, admission, kernel, Arc::new(AtomicBool::new(false)))
    }

    /// Starts the composition with a caller-owned stop flag.  SCM control
    /// handlers use this flag because they execute outside the Tokio runtime.
    pub fn start_with_shutdown(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        config.validate()?;
        let runtime = config.runtime()?;
        let initial = admission
            .reload()
            .map_err(|error| CompositionError::InvalidLease(error.to_string()))?;
        let kernel_epoch = initial.lease().lease().kernel_epoch.value();
        let watchdog_epoch = initial.watchdog_epoch().value();
        let task_admission = admission.clone();
        let interval = config.tick_interval;
        let task = match runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            SERVICE_NAME,
            ChildClass::Critical,
            move |token| {
                let kernel = kernel.clone();
                let admission = task_admission.clone();
                async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => return Ok(()),
                            () = tokio::time::sleep(interval) => {}
                        }
                        let admission = match admission.reload() {
                            Ok(admission) => admission,
                            Err(error) => {
                                let disposition = GapRecoveryDisposition {
                                    record_type: "watchdog_gap",
                                    service: SERVICE_NAME,
                                    observed_at_ms: current_unix_ms().unwrap_or(0),
                                    reason: GapRecoveryReason::AdmissionUnavailable,
                                    coverage_claimed: false,
                                };
                                kernel
                                    .report_gap(disposition)
                                    .await
                                    .map_err(|report_error| {
                                        TaskFailure::Failed(format!(
                                            "watchdog admission failed ({error}); gap reporting failed ({report_error})"
                                        ))
                                    })?;
                                return Err(TaskFailure::Failed(format!(
                                    "watchdog admission failed: {error}"
                                )));
                            }
                        };
                        if let Err(error) = kernel.supervise(admission.lease()).await {
                            let disposition = GapRecoveryDisposition {
                                record_type: "watchdog_gap",
                                service: SERVICE_NAME,
                                observed_at_ms: current_unix_ms().unwrap_or(0),
                                reason: GapRecoveryReason::AdmissionUnavailable,
                                coverage_claimed: false,
                            };
                            kernel
                                .report_gap(disposition)
                                .await
                                .map_err(|report_error| {
                                    TaskFailure::Failed(format!(
                                        "watchdog supervision failed ({error}); gap reporting failed ({report_error})"
                                    ))
                                })?;
                            return Err(TaskFailure::Failed(error.to_string()));
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
            config,
            task,
            shutdown_requested,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> WatchdogReadiness {
        WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            kernel_epoch: self.kernel_epoch,
            watchdog_epoch: self.watchdog_epoch,
            tick_interval_ms: self.config.tick_interval.as_millis(),
        }
    }

    /// Waits for process termination and performs ordered runtime shutdown.
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
                result.map(|_| shutdown)
            }
            result = wait_for_shutdown(shutdown_requested) => {
                if result {
                    runtime.shutdown_handle().request();
                    let result = task_result.await;
                    let shutdown = runtime.shutdown().await;
                    result.map(|_| shutdown)
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

async fn wait_for_shutdown(shutdown_requested: Arc<AtomicBool>) -> bool {
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Loads and validates the current Host/Kernel-issued lease.  Missing,
/// malformed, stale or non-active bytes are a hard startup failure.
pub fn load_supervision_lease(
    lease_path: impl AsRef<Path>,
    admission_config_path: impl AsRef<Path>,
    registry_path: impl AsRef<Path>,
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
    let installation_id = std::env::var("ELIOT_INSTALLATION_ID")
        .map_err(|_| SpoolError::InvalidLease("installation identity is unavailable".to_owned()))?;
    validate_text(&installation_id, "environment.installation_id")?;
    let config_bytes = read_bounded(admission_config_path, ADMISSION_CONFIG_LIMIT)?;
    let config: WatchdogAdmissionConfig = serde_json::from_slice(&config_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    config.validate_shape()?;
    let registry = RedbInstallationRegistry::open(registry_path)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .load()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let active = registry
        .active()
        .ok_or_else(|| SpoolError::InvalidLease("no active approved generation".to_owned()))?;
    if config.installation_id != installation_id
        || config.trust_anchor.installation_id != installation_id
    {
        return Err(SpoolError::InvalidLease(
            "admission installation identity does not match the service installation".to_owned(),
        ));
    }
    if config.approved_generation != active.manifest.generation.as_str() {
        return Err(SpoolError::InvalidLease(
            "admission generation is not the active approved generation".to_owned(),
        ));
    }
    let expected_config_digest = active.manifest.config_digest.as_str();
    if !is_sha256_hex(expected_config_digest) || sha256_hex(&config_bytes) != expected_config_digest
    {
        return Err(SpoolError::InvalidLease(
            "admission config digest is not the active manifest config digest".to_owned(),
        ));
    }
    let expected_fingerprint = active.manifest.supervision_key_fingerprint.as_str();
    if config.trust_anchor.public_key_fingerprint() != expected_fingerprint
        || config.context.public_key_fingerprint != expected_fingerprint
    {
        return Err(SpoolError::InvalidLease(
            "admission trust fingerprint is not the active manifest fingerprint".to_owned(),
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
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok(VerifiedWatchdogAdmission {
        watchdog_epoch: context.watchdog_epoch,
        lease,
    })
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
        assert!(validate_header(&header, &[entry.clone()]).is_err());
        header.record_count = 1;
        header.first_sequence = 3;
        assert!(validate_header(&header, &[entry]).is_err());
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

    #[test]
    fn redb_spool_corruption_writes_recovery_evidence_before_readback() {
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
                .insert(SPOOL_HEADER_KEY, b"not-json".as_slice())
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
        drop(recovered);
        let _ = std::fs::remove_dir_all(root);
    }
}
