#![allow(dead_code)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_platform::PlatformHandle;
use redb::{
    Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition, TableHandle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const LEGACY_SCM_STORE_MAGIC_V1: &str = "ELIOT-SCM-OP-STORE-V1";
const SCM_STORE_MAGIC: &str = "ELIOT-SCM-OP-STORE-V2";
const SCM_STORE_VERSION: u16 = 2;
const LEGACY_SCM_RECORD_ENVELOPE_MAGIC_V1: &str = "ELIOT-SCM-OP-RECORD-V1";
const SCM_RECORD_ENVELOPE_MAGIC: &str = "ELIOT-SCM-OP-RECORD-V2";
const SCM_RECORD_ENVELOPE_VERSION: u16 = 2;
const SCM_RECORD_VERSION: u16 = 2;
const SCM_INDEX_MAGIC: &str = "ELIOT-SCM-OP-INDEX-V1";
const SCM_INDEX_VERSION: u16 = 1;
const MAX_HISTORY_ENTRIES: usize = 4096;
// Physical v1 table names are retained deliberately: opening an old file must
// reach the metadata/version classifier, never appear to be an empty new store.
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_scm_store_meta_v1");
const OPS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_scm_operations_v1");
const INDEX_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_scm_operation_index_v1");
const META_KEY: &str = "meta";
const CANONICAL_SERVICE: &str = "EliotHost";

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ScmOperationStoreError {
    #[error("scm operation store is unavailable")]
    Unavailable,
    #[error("scm operation store file is missing")]
    MissingFile,
    #[error("scm operation store is corrupt")]
    Corrupt,
    #[error("scm operation store legacy version {version}")]
    Legacy { version: u16 },
    #[error("scm operation store is missing")]
    MissingTable,
    #[error("scm operation store record is invalid: {0}")]
    InvalidRecord(String),
    #[error("scm operation revision conflict")]
    Conflict,
    #[error("scm operation digest conflict")]
    DigestConflict,
    #[error("scm operation illegal transition from {from:?} to {to:?}")]
    IllegalTransition { from: String, to: String },
    #[error("scm operation is quarantined")]
    Quarantined,
    #[error("scm operation coordinator is not bound to this store")]
    NotOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ScmOperationState {
    StopIntentCommitted,
    StopObserved,
    StartIntentCommitted,
    StartedObserved,
    Completed,
    Unknown,
}

impl ScmOperationState {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Unknown)
    }
}

fn is_legal_transition(from: ScmOperationState, to: ScmOperationState) -> bool {
    matches!(
        (from, to),
        (
            ScmOperationState::StopIntentCommitted,
            ScmOperationState::StopObserved
        ) | (
            ScmOperationState::StopObserved,
            ScmOperationState::StartIntentCommitted
        ) | (
            ScmOperationState::StartIntentCommitted,
            ScmOperationState::StartedObserved
        ) | (
            ScmOperationState::StartedObserved,
            ScmOperationState::Completed
        )
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreMeta {
    magic: String,
    version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmOperationHistoryLink {
    revision: u64,
    checksum: String,
    /// A deterministic commitment to this predecessor and the complete chain
    /// before it. Current-wire records cannot deserialize without it.
    chain_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum ScmOperationHistoryFormat {
    AnchoredV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmOperationIdentity {
    pub installation: PlatformHandle,
    pub service: PlatformHandle,
    pub approval_digest: PlatformHandle,
    pub config_digest: PlatformHandle,
    pub operation_id: PlatformHandle,
    pub request_digest: PlatformHandle,
}

impl ScmOperationIdentity {
    fn validate(&self) -> Result<(), ScmOperationStoreError> {
        handle(&self.installation, "installation")?;
        handle(&self.service, "service")?;
        if self.service.as_str() != CANONICAL_SERVICE {
            return Err(ScmOperationStoreError::InvalidRecord(
                "service must be canonical EliotHost".into(),
            ));
        }
        digest(&self.approval_digest, "approval_digest")?;
        digest(&self.config_digest, "config_digest")?;
        handle(&self.operation_id, "operation_id")?;
        digest(&self.request_digest, "request_digest")?;
        Ok(())
    }

    fn key(&self) -> String {
        [
            self.installation.as_str(),
            self.service.as_str(),
            self.approval_digest.as_str(),
            self.config_digest.as_str(),
            self.operation_id.as_str(),
            self.request_digest.as_str(),
        ]
        .join("\x1f")
    }

    fn stable_key(&self) -> String {
        [
            self.installation.as_str(),
            self.service.as_str(),
            self.operation_id.as_str(),
        ]
        .join("\x1f")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmOperationRecordEnvelope {
    magic: String,
    version: u16,
    record: ScmOperationRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmOperationIndexEntry {
    magic: String,
    version: u16,
    stable_key: String,
    record_key: String,
}

/// Durable record. Fields are private to prevent forging.
///
/// ```compile_fail
/// use eliot_host_state::ScmOperationRecord;
/// use eliot_platform::PlatformHandle;
/// let r = ScmOperationRecord {
///     magic: "x".into(),
///     version: 1,
///     installation: PlatformHandle::new("i").unwrap(),
///     service: PlatformHandle::new("EliotHost").unwrap(),
///     approval_digest: PlatformHandle::new(&"a".repeat(64)).unwrap(),
///     config_digest: PlatformHandle::new(&"b".repeat(64)).unwrap(),
///     operation_id: PlatformHandle::new("o").unwrap(),
///     request_digest: PlatformHandle::new(&"c".repeat(64)).unwrap(),
///     state: eliot_host_state::ScmOperationState::StopIntentCommitted,
///     revision: 1,
///     prior_sha256: "GENESIS".into(),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmOperationRecord {
    magic: String,
    version: u16,
    history_format: ScmOperationHistoryFormat,
    installation: PlatformHandle,
    service: PlatformHandle,
    approval_digest: PlatformHandle,
    config_digest: PlatformHandle,
    operation_id: PlatformHandle,
    request_digest: PlatformHandle,
    state: ScmOperationState,
    revision: u64,
    prior_sha256: String,
    checksum: String,
    history: Vec<ScmOperationHistoryLink>,
}

impl ScmOperationRecord {
    pub fn installation(&self) -> &PlatformHandle {
        &self.installation
    }
    pub fn service(&self) -> &PlatformHandle {
        &self.service
    }
    pub fn approval_digest(&self) -> &PlatformHandle {
        &self.approval_digest
    }
    pub fn config_digest(&self) -> &PlatformHandle {
        &self.config_digest
    }
    pub fn operation_id(&self) -> &PlatformHandle {
        &self.operation_id
    }
    pub fn request_digest(&self) -> &PlatformHandle {
        &self.request_digest
    }
    pub fn state(&self) -> ScmOperationState {
        self.state
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn prior_sha256(&self) -> &str {
        &self.prior_sha256
    }
    pub fn checksum(&self) -> &str {
        &self.checksum
    }
    pub fn key(&self) -> String {
        [
            self.installation.as_str(),
            self.service.as_str(),
            self.approval_digest.as_str(),
            self.config_digest.as_str(),
            self.operation_id.as_str(),
            self.request_digest.as_str(),
        ]
        .join("\x1f")
    }
    fn stable_key(&self) -> String {
        [
            self.installation.as_str(),
            self.service.as_str(),
            self.operation_id.as_str(),
        ]
        .join("\x1f")
    }

    fn validate(&self) -> Result<(), ScmOperationStoreError> {
        if self.magic == LEGACY_SCM_STORE_MAGIC_V1 && self.version == 1 {
            return Err(ScmOperationStoreError::Legacy { version: 1 });
        }
        if self.magic != SCM_STORE_MAGIC {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if self.version != SCM_RECORD_VERSION {
            return Err(ScmOperationStoreError::Legacy {
                version: self.version,
            });
        }
        handle(&self.installation, "installation")?;
        handle(&self.service, "service")?;
        if self.service.as_str() != CANONICAL_SERVICE {
            return Err(ScmOperationStoreError::InvalidRecord(
                "service must be canonical EliotHost".into(),
            ));
        }
        digest(&self.approval_digest, "approval_digest")?;
        digest(&self.config_digest, "config_digest")?;
        handle(&self.operation_id, "operation_id")?;
        digest(&self.request_digest, "request_digest")?;
        if self.revision == 0 {
            return Err(ScmOperationStoreError::InvalidRecord(
                "revision must be positive".into(),
            ));
        }
        if self.history.len() > MAX_HISTORY_ENTRIES {
            return Err(ScmOperationStoreError::InvalidRecord(
                "operation history exceeds bounded limit".into(),
            ));
        }
        let expected_history_len = self.revision.checked_sub(1).ok_or_else(|| {
            ScmOperationStoreError::InvalidRecord("revision must be positive".into())
        })?;
        if usize::try_from(expected_history_len).ok() != Some(self.history.len()) {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if self.history.is_empty() {
            if self.prior_sha256 != "GENESIS" {
                return Err(ScmOperationStoreError::Corrupt);
            }
        } else {
            let mut previous_anchor = "GENESIS".to_owned();
            for (index, link) in self.history.iter().enumerate() {
                let expected_revision = u64::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ScmOperationStoreError::Corrupt)?;
                if link.revision != expected_revision || !is_sha256(&link.checksum) {
                    return Err(ScmOperationStoreError::Corrupt);
                }
                if !is_sha256(&link.chain_sha256)
                    || history_link_anchor(link.revision, &link.checksum, &previous_anchor)?
                        != link.chain_sha256
                {
                    return Err(ScmOperationStoreError::Corrupt);
                }
                previous_anchor.clone_from(&link.chain_sha256);
            }
            if self
                .history
                .last()
                .is_none_or(|link| link.checksum != self.prior_sha256)
            {
                return Err(ScmOperationStoreError::Corrupt);
            }
        }
        if !is_sha256(&self.checksum) {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if normalized_sha(self)? != self.checksum {
            return Err(ScmOperationStoreError::Corrupt);
        }
        Ok(())
    }
}

fn handle(value: &PlatformHandle, field: &'static str) -> Result<(), ScmOperationStoreError> {
    let text = value.as_str();
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(ScmOperationStoreError::InvalidRecord(format!(
            "{field} must be non-blank"
        )));
    }
    Ok(())
}

fn digest(value: &PlatformHandle, field: &'static str) -> Result<(), ScmOperationStoreError> {
    handle(value, field)?;
    let text = value.as_str();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ScmOperationStoreError::InvalidRecord(format!(
            "{field} must be 64 hex"
        )));
    }
    let lower = text.to_ascii_lowercase();
    if lower != text {
        return Err(ScmOperationStoreError::InvalidRecord(format!(
            "{field} must be lowercase hex"
        )));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn history_link_anchor(
    revision: u64,
    checksum: &str,
    previous_anchor: &str,
) -> Result<String, ScmOperationStoreError> {
    let bytes = serde_json::to_vec(&(revision, checksum, previous_anchor))
        .map_err(|_| ScmOperationStoreError::Corrupt)?;
    Ok(sha256_hex(&bytes))
}

fn anchored_history(
    history: &[ScmOperationHistoryLink],
) -> Result<Vec<ScmOperationHistoryLink>, ScmOperationStoreError> {
    let mut previous_anchor = "GENESIS".to_owned();
    let mut result = Vec::with_capacity(history.len());
    for link in history {
        let anchor = history_link_anchor(link.revision, &link.checksum, &previous_anchor)?;
        result.push(ScmOperationHistoryLink {
            revision: link.revision,
            checksum: link.checksum.clone(),
            chain_sha256: anchor.clone(),
        });
        previous_anchor = anchor;
    }
    Ok(result)
}

fn append_history_link(
    stored: &ScmOperationRecord,
) -> Result<Vec<ScmOperationHistoryLink>, ScmOperationStoreError> {
    let mut history = anchored_history(&stored.history)?;
    let previous_anchor = history
        .last()
        .map_or("GENESIS", |link| link.chain_sha256.as_str());
    let anchor = history_link_anchor(stored.revision, &stored.checksum, previous_anchor)?;
    history.push(ScmOperationHistoryLink {
        revision: stored.revision,
        checksum: stored.checksum.clone(),
        chain_sha256: anchor,
    });
    Ok(history)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn map_database_open_error(error: redb::DatabaseError) -> ScmOperationStoreError {
    match error {
        redb::DatabaseError::Storage(redb::StorageError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            ScmOperationStoreError::MissingFile
        }
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => {
            ScmOperationStoreError::Corrupt
        }
        redb::DatabaseError::UpgradeRequired(version) => ScmOperationStoreError::Legacy {
            version: u16::from(version),
        },
        _ => ScmOperationStoreError::Unavailable,
    }
}

#[derive(Serialize)]
struct ScmOperationRecordDigest<'a> {
    magic: &'a str,
    version: u16,
    history_format: ScmOperationHistoryFormat,
    installation: &'a PlatformHandle,
    service: &'a PlatformHandle,
    approval_digest: &'a PlatformHandle,
    config_digest: &'a PlatformHandle,
    operation_id: &'a PlatformHandle,
    request_digest: &'a PlatformHandle,
    state: ScmOperationState,
    revision: u64,
    prior_sha256: &'a str,
    history: &'a [ScmOperationHistoryLink],
}

fn normalized_sha(record: &ScmOperationRecord) -> Result<String, ScmOperationStoreError> {
    let digest_input = ScmOperationRecordDigest {
        magic: &record.magic,
        version: record.version,
        history_format: record.history_format,
        installation: &record.installation,
        service: &record.service,
        approval_digest: &record.approval_digest,
        config_digest: &record.config_digest,
        operation_id: &record.operation_id,
        request_digest: &record.request_digest,
        state: record.state,
        revision: record.revision,
        prior_sha256: &record.prior_sha256,
        history: &record.history,
    };
    let bytes = serde_json::to_vec(&digest_input).map_err(|_| ScmOperationStoreError::Corrupt)?;
    Ok(sha256_hex(&bytes))
}

fn encode_record(record: &ScmOperationRecord) -> Result<Vec<u8>, ScmOperationStoreError> {
    let envelope = ScmOperationRecordEnvelope {
        magic: SCM_RECORD_ENVELOPE_MAGIC.to_owned(),
        version: SCM_RECORD_ENVELOPE_VERSION,
        record: record.clone(),
    };
    serde_json::to_vec(&envelope).map_err(|_| ScmOperationStoreError::Corrupt)
}

fn decode_record(bytes: &[u8]) -> Result<ScmOperationRecord, ScmOperationStoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ScmOperationStoreError::Corrupt)?;
    let object = value.as_object().ok_or(ScmOperationStoreError::Corrupt)?;

    // The pre-envelope v1 representation is migration input only. It is
    // classified without deserializing or synthesizing the now-mandatory
    // history provenance.
    if !object.contains_key("record") {
        let magic = object
            .get("magic")
            .and_then(serde_json::Value::as_str)
            .ok_or(ScmOperationStoreError::Corrupt)?;
        let version = object
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u16::try_from(version).ok())
            .ok_or(ScmOperationStoreError::Corrupt)?;
        if (magic == LEGACY_SCM_STORE_MAGIC_V1 && version == 1)
            || (magic == SCM_STORE_MAGIC && version != SCM_RECORD_VERSION)
        {
            return Err(ScmOperationStoreError::Legacy { version });
        }
        return Err(ScmOperationStoreError::Corrupt);
    }

    let magic = object
        .get("magic")
        .and_then(serde_json::Value::as_str)
        .ok_or(ScmOperationStoreError::Corrupt)?;
    let version = object
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u16::try_from(version).ok())
        .ok_or(ScmOperationStoreError::Corrupt)?;
    if magic == LEGACY_SCM_RECORD_ENVELOPE_MAGIC_V1 && version == 1 {
        return Err(ScmOperationStoreError::Legacy { version });
    }
    if magic != SCM_RECORD_ENVELOPE_MAGIC {
        return Err(ScmOperationStoreError::Corrupt);
    }
    if version != SCM_RECORD_ENVELOPE_VERSION {
        return Err(ScmOperationStoreError::Legacy { version });
    }
    // A current envelope is parsed strictly only after its wire version has
    // been authenticated as current. Missing provenance/anchors are corrupt,
    // never reclassified as a trusted legacy shape.
    let envelope: ScmOperationRecordEnvelope =
        serde_json::from_value(value).map_err(|_| ScmOperationStoreError::Corrupt)?;
    envelope.record.validate()?;
    Ok(envelope.record)
}

fn encode_index(stable_key: &str, record_key: &str) -> Result<Vec<u8>, ScmOperationStoreError> {
    let entry = ScmOperationIndexEntry {
        magic: SCM_INDEX_MAGIC.to_owned(),
        version: SCM_INDEX_VERSION,
        stable_key: stable_key.to_owned(),
        record_key: record_key.to_owned(),
    };
    serde_json::to_vec(&entry).map_err(|_| ScmOperationStoreError::Corrupt)
}

fn decode_index(bytes: &[u8]) -> Result<ScmOperationIndexEntry, ScmOperationStoreError> {
    let entry: ScmOperationIndexEntry =
        serde_json::from_slice(bytes).map_err(|_| ScmOperationStoreError::Corrupt)?;
    if entry.magic != SCM_INDEX_MAGIC {
        return Err(ScmOperationStoreError::Corrupt);
    }
    if entry.version != SCM_INDEX_VERSION {
        return Err(ScmOperationStoreError::Legacy {
            version: entry.version,
        });
    }
    if entry.stable_key.is_empty() || entry.record_key.is_empty() {
        return Err(ScmOperationStoreError::Corrupt);
    }
    Ok(entry)
}

/// Validate every durable operation key and stable-identity index candidate
/// in one snapshot.  The secondary index is an optimization, not an
/// integrity boundary: a second full-key record with the same stable identity
/// is corruption even when the index points at one of them.
fn scan_operation_records<T>(
    operations: &T,
    target_stable: Option<&str>,
) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let mut stable_keys = BTreeMap::<String, String>::new();
    let mut target = None;
    for item in operations
        .iter()
        .map_err(|_| ScmOperationStoreError::Corrupt)?
    {
        let (record_key, value) = item.map_err(|_| ScmOperationStoreError::Corrupt)?;
        let record_key = record_key.value().to_owned();
        let record = decode_record(value.value())?;
        if record.key() != record_key {
            return Err(ScmOperationStoreError::Corrupt);
        }
        let stable_key = record.stable_key();
        if stable_keys.insert(stable_key.clone(), record_key).is_some() {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if target_stable == Some(stable_key.as_str()) {
            target = Some(record);
        }
    }
    Ok(target)
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed, store-bound coordinator capability. Only
/// `ScmOperationStore::coordinator` can create it, and the capability cannot
/// be used with another store instance.
///
/// ```compile_fail
/// use eliot_host_state::ScmOperationCoordinator;
/// let c = ScmOperationCoordinator { _private: () };
/// ```
///
#[derive(Clone, Debug)]
pub struct ScmOperationCoordinator {
    owner: Arc<ScmOperationStoreOwner>,
}

impl sealed::Sealed for ScmOperationCoordinator {}

#[derive(Debug)]
struct ScmOperationStoreOwner;

impl ScmOperationCoordinator {
    fn new(owner: Arc<ScmOperationStoreOwner>) -> Self {
        Self { owner }
    }
}

#[derive(Debug)]
pub struct ScmOperationStore {
    path: PathBuf,
    owner: Arc<ScmOperationStoreOwner>,
}

impl ScmOperationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ScmOperationStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| ScmOperationStoreError::Unavailable)?;
        }
        let database = Database::create(&path).map_err(|_| ScmOperationStoreError::Unavailable)?;
        let store = Self {
            path,
            owner: Arc::new(ScmOperationStoreOwner),
        };
        Self::ensure_schema(&database)?;
        drop(database);
        Ok(store)
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, ScmOperationStoreError> {
        let path = path.as_ref().to_path_buf();
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScmOperationStoreError::MissingFile);
            }
            Err(_) => return Err(ScmOperationStoreError::Unavailable),
        }
        let database = ReadOnlyDatabase::open(&path).map_err(map_database_open_error)?;
        let store = Self {
            path,
            owner: Arc::new(ScmOperationStoreOwner),
        };
        // Opening an existing store is deliberately read-only with respect to
        // the schema. In particular, a blank/partial file must not be turned
        // into a usable store as a side effect of a query or status read.
        Self::validate_existing_schema(&database)?;
        drop(database);
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn open_unprotected_for_test(
        path: impl AsRef<Path>,
    ) -> Result<Self, ScmOperationStoreError> {
        Self::open(path)
    }

    pub fn coordinator(&self) -> ScmOperationCoordinator {
        ScmOperationCoordinator::new(Arc::clone(&self.owner))
    }

    fn open_write_database(&self) -> Result<Database, ScmOperationStoreError> {
        Database::open(&self.path).map_err(|_| ScmOperationStoreError::Unavailable)
    }

    fn open_read_only_database(&self) -> Result<ReadOnlyDatabase, ScmOperationStoreError> {
        ReadOnlyDatabase::open(&self.path).map_err(map_database_open_error)
    }

    fn authorize(
        &self,
        coordinator: &ScmOperationCoordinator,
    ) -> Result<(), ScmOperationStoreError> {
        if Arc::ptr_eq(&self.owner, &coordinator.owner) {
            Ok(())
        } else {
            Err(ScmOperationStoreError::NotOwner)
        }
    }

    fn ensure_schema(database: &Database) -> Result<(), ScmOperationStoreError> {
        let read = database
            .begin_read()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let has_meta = match read.open_table(META_TABLE) {
            Ok(_) => true,
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(_) => return Err(ScmOperationStoreError::Corrupt),
        };
        let has_ops = match read.open_table(OPS_TABLE) {
            Ok(_) => true,
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(_) => return Err(ScmOperationStoreError::Corrupt),
        };
        let has_index = match read.open_table(INDEX_TABLE) {
            Ok(_) => true,
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(_) => return Err(ScmOperationStoreError::Corrupt),
        };
        if !has_meta && !has_ops && !has_index {
            drop(read);
            let write = database
                .begin_write()
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            {
                let mut meta = write
                    .open_table(META_TABLE)
                    .map_err(|_| ScmOperationStoreError::Unavailable)?;
                let _ops = write
                    .open_table(OPS_TABLE)
                    .map_err(|_| ScmOperationStoreError::Unavailable)?;
                let _index = write
                    .open_table(INDEX_TABLE)
                    .map_err(|_| ScmOperationStoreError::Unavailable)?;
                let m = StoreMeta {
                    magic: SCM_STORE_MAGIC.to_owned(),
                    version: SCM_STORE_VERSION,
                };
                let bytes =
                    serde_json::to_vec(&m).map_err(|_| ScmOperationStoreError::Unavailable)?;
                meta.insert(META_KEY, bytes.as_slice())
                    .map_err(|_| ScmOperationStoreError::Unavailable)?;
            }
            write
                .commit()
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            return Ok(());
        }
        if !has_meta || !has_ops || !has_index {
            return Err(ScmOperationStoreError::MissingTable);
        }
        let table = read
            .open_table(META_TABLE)
            .map_err(|_| ScmOperationStoreError::Corrupt)?;
        let mut count = 0usize;
        let mut found: Option<StoreMeta> = None;
        for item in table.iter().map_err(|_| ScmOperationStoreError::Corrupt)? {
            let (k, v) = item.map_err(|_| ScmOperationStoreError::Corrupt)?;
            if k.value() != META_KEY {
                return Err(ScmOperationStoreError::Corrupt);
            }
            let meta: StoreMeta =
                serde_json::from_slice(v.value()).map_err(|_| ScmOperationStoreError::Corrupt)?;
            found = Some(meta);
            count += 1;
        }
        if count != 1 {
            return Err(ScmOperationStoreError::Corrupt);
        }
        let meta = found.ok_or(ScmOperationStoreError::Corrupt)?;
        if meta.magic == LEGACY_SCM_STORE_MAGIC_V1 && meta.version == 1 {
            return Err(ScmOperationStoreError::Legacy { version: 1 });
        }
        if meta.magic != SCM_STORE_MAGIC {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if meta.version != SCM_STORE_VERSION {
            return Err(ScmOperationStoreError::Legacy {
                version: meta.version,
            });
        }
        Ok(())
    }

    fn validate_existing_schema<D: ReadableDatabase>(
        database: &D,
    ) -> Result<(), ScmOperationStoreError> {
        let read = database
            .begin_read()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        for table in [META_TABLE.name(), OPS_TABLE.name(), INDEX_TABLE.name()] {
            let result = match table {
                name if name == META_TABLE.name() => read.open_table(META_TABLE).map(|_| ()),
                name if name == OPS_TABLE.name() => read.open_table(OPS_TABLE).map(|_| ()),
                name if name == INDEX_TABLE.name() => read.open_table(INDEX_TABLE).map(|_| ()),
                _ => unreachable!("all schema tables are listed explicitly"),
            };
            match result {
                Ok(()) => {}
                Err(redb::TableError::TableDoesNotExist(_)) => {
                    return Err(ScmOperationStoreError::MissingTable);
                }
                Err(_) => return Err(ScmOperationStoreError::Corrupt),
            }
        }
        let table = read.open_table(META_TABLE).map_err(|error| match error {
            redb::TableError::TableDoesNotExist(_) => ScmOperationStoreError::MissingTable,
            _ => ScmOperationStoreError::Corrupt,
        })?;
        let mut found = None;
        let mut count = 0usize;
        for item in table.iter().map_err(|_| ScmOperationStoreError::Corrupt)? {
            let (key, value) = item.map_err(|_| ScmOperationStoreError::Corrupt)?;
            if key.value() != META_KEY {
                return Err(ScmOperationStoreError::Corrupt);
            }
            found = Some(
                serde_json::from_slice::<StoreMeta>(value.value())
                    .map_err(|_| ScmOperationStoreError::Corrupt)?,
            );
            count = count
                .checked_add(1)
                .ok_or(ScmOperationStoreError::Corrupt)?;
        }
        if count != 1 {
            return Err(ScmOperationStoreError::Corrupt);
        }
        let meta = found.ok_or(ScmOperationStoreError::Corrupt)?;
        if meta.magic == LEGACY_SCM_STORE_MAGIC_V1 && meta.version == 1 {
            return Err(ScmOperationStoreError::Legacy { version: 1 });
        }
        if meta.magic != SCM_STORE_MAGIC {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if meta.version != SCM_STORE_VERSION {
            return Err(ScmOperationStoreError::Legacy {
                version: meta.version,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn create_operation(
        &self,
        coordinator: &ScmOperationCoordinator,
        identity: ScmOperationIdentity,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        self.authorize(coordinator)?;
        identity.validate()?;
        let key = identity.key();
        let stable = identity.stable_key();
        let database = self.open_write_database()?;
        let write = database
            .begin_write()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let existing: Option<ScmOperationRecord> = {
            let ops = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let scanned = scan_operation_records(&ops, Some(&stable))?;
            drop(ops);
            let index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let index_bytes = index
                .get(stable.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
                .map(|value| value.value().to_vec());
            drop(index);
            if let Some(index_bytes) = index_bytes {
                let entry = decode_index(&index_bytes)?;
                if entry.stable_key != stable {
                    return Err(ScmOperationStoreError::Corrupt);
                }
                let ops = write
                    .open_table(OPS_TABLE)
                    .map_err(|_| ScmOperationStoreError::Unavailable)?;
                let record = match ops
                    .get(entry.record_key.as_str())
                    .map_err(|_| ScmOperationStoreError::Corrupt)?
                {
                    Some(v) => {
                        let rec = decode_record(v.value())?;
                        if rec.key() != entry.record_key || rec.stable_key() != stable {
                            return Err(ScmOperationStoreError::Corrupt);
                        }
                        rec
                    }
                    None => return Err(ScmOperationStoreError::Corrupt),
                };
                if scanned
                    .as_ref()
                    .is_none_or(|record| record.key() != entry.record_key)
                {
                    return Err(ScmOperationStoreError::Corrupt);
                }
                Some(record)
            } else {
                // Never repair a missing index during create. If the record
                // exists, the index is corrupt and must be rebuilt by an
                // explicit migration/recovery operation.
                if scanned.is_some() {
                    return Err(ScmOperationStoreError::Corrupt);
                }
                None
            }
        };
        if let Some(existing) = existing {
            if existing.installation != identity.installation
                || existing.service != identity.service
                || existing.approval_digest != identity.approval_digest
                || existing.config_digest != identity.config_digest
                || existing.operation_id != identity.operation_id
                || existing.request_digest != identity.request_digest
            {
                return Err(ScmOperationStoreError::DigestConflict);
            }
            return Ok(existing);
        }
        let mut record = ScmOperationRecord {
            magic: SCM_STORE_MAGIC.to_owned(),
            version: SCM_RECORD_VERSION,
            history_format: ScmOperationHistoryFormat::AnchoredV1,
            installation: identity.installation,
            service: identity.service,
            approval_digest: identity.approval_digest,
            config_digest: identity.config_digest,
            operation_id: identity.operation_id,
            request_digest: identity.request_digest,
            state: ScmOperationState::StopIntentCommitted,
            revision: 1,
            prior_sha256: "GENESIS".to_owned(),
            checksum: String::new(),
            history: Vec::new(),
        };
        record.checksum = normalized_sha(&record)?;
        record.validate()?;
        let bytes = encode_record(&record)?;
        let index_bytes = encode_index(&stable, &key)?;
        {
            let mut ops = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            ops.insert(key.as_str(), bytes.as_slice())
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let mut index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            index
                .insert(stable.as_str(), index_bytes.as_slice())
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
        }
        write
            .commit()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        drop(database);
        Ok(record)
    }

    pub fn load_operation(
        &self,
        identity: &ScmOperationIdentity,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        identity.validate()?;
        let database = self.open_read_only_database()?;
        let result = Self::load_by_stable(&database, &identity.stable_key(), identity);
        drop(database);
        result
    }

    pub fn query_operation(
        &self,
        identity: &ScmOperationIdentity,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        self.load_operation(identity)
    }

    fn load_by_key<D: ReadableDatabase>(
        database: &D,
        key: &str,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        Self::validate_existing_schema(database)?;
        let read = database
            .begin_read()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let table = read
            .open_table(OPS_TABLE)
            .map_err(|_| ScmOperationStoreError::MissingTable)?;
        let _ = scan_operation_records(&table, None)?;
        let Some(v) = table
            .get(key)
            .map_err(|_| ScmOperationStoreError::Corrupt)?
        else {
            return Ok(None);
        };
        let rec = decode_record(v.value())?;
        if rec.key() != key {
            return Err(ScmOperationStoreError::Corrupt);
        }
        Ok(Some(rec))
    }

    fn load_by_stable(
        database: &impl ReadableDatabase,
        stable: &str,
        identity: &ScmOperationIdentity,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        Self::validate_existing_schema(database)?;
        let read = database
            .begin_read()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let index = read
            .open_table(INDEX_TABLE)
            .map_err(|_| ScmOperationStoreError::MissingTable)?;
        let index_bytes = index
            .get(stable)
            .map_err(|_| ScmOperationStoreError::Corrupt)?
            .map(|value| value.value().to_vec());
        drop(index);
        let ops = read
            .open_table(OPS_TABLE)
            .map_err(|_| ScmOperationStoreError::MissingTable)?;
        let scanned = scan_operation_records(&ops, Some(stable))?;
        let Some(index_bytes) = index_bytes else {
            // An index miss is only a legitimate absence when no durable
            // operation with this stable identity exists. Do not turn a
            // damaged index into a fresh operation by returning `None`.
            if scanned.is_some() {
                return Err(ScmOperationStoreError::Corrupt);
            }
            return Ok(None);
        };
        let entry = decode_index(&index_bytes)?;
        if entry.stable_key != stable {
            return Err(ScmOperationStoreError::Corrupt);
        }
        let Some(v) = ops
            .get(entry.record_key.as_str())
            .map_err(|_| ScmOperationStoreError::Corrupt)?
        else {
            return Err(ScmOperationStoreError::Corrupt);
        };
        let rec = decode_record(v.value())?;
        if rec.key() != entry.record_key || rec.stable_key() != stable {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if scanned
            .as_ref()
            .is_none_or(|record| record.key() != entry.record_key)
        {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if rec.installation != identity.installation
            || rec.service != identity.service
            || rec.operation_id != identity.operation_id
        {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if rec.approval_digest != identity.approval_digest
            || rec.config_digest != identity.config_digest
            || rec.request_digest != identity.request_digest
        {
            return Err(ScmOperationStoreError::DigestConflict);
        }
        Ok(Some(rec))
    }

    #[allow(clippy::too_many_lines)]
    fn cas_transition(
        &self,
        coordinator: &ScmOperationCoordinator,
        identity: &ScmOperationIdentity,
        expected_revision: u64,
        expected_prior_sha: &str,
        target: ScmOperationState,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        self.authorize(coordinator)?;
        identity.validate()?;
        let database = self.open_write_database()?;
        let write = database
            .begin_write()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let stored: ScmOperationRecord = {
            let stable = identity.stable_key();
            let index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let Some(index_bytes) = index
                .get(stable.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
                .map(|value| value.value().to_vec())
            else {
                return Err(ScmOperationStoreError::InvalidRecord("not found".into()));
            };
            let entry = decode_index(&index_bytes)?;
            if entry.stable_key != stable {
                return Err(ScmOperationStoreError::Corrupt);
            }
            let ops = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let scanned = scan_operation_records(&ops, Some(&stable))?;
            let Some(v) = ops
                .get(entry.record_key.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
            else {
                return Err(ScmOperationStoreError::Corrupt);
            };
            let rec = decode_record(v.value())?;
            if rec.key() != entry.record_key || rec.stable_key() != stable {
                return Err(ScmOperationStoreError::Corrupt);
            }
            if scanned
                .as_ref()
                .is_none_or(|record| record.key() != entry.record_key)
            {
                return Err(ScmOperationStoreError::Corrupt);
            }
            if rec.installation != identity.installation
                || rec.service != identity.service
                || rec.operation_id != identity.operation_id
            {
                return Err(ScmOperationStoreError::Corrupt);
            }
            if rec.approval_digest != identity.approval_digest
                || rec.config_digest != identity.config_digest
                || rec.request_digest != identity.request_digest
            {
                return Err(ScmOperationStoreError::DigestConflict);
            }
            rec
        };
        if stored.state == ScmOperationState::Unknown {
            return Err(ScmOperationStoreError::Quarantined);
        }
        if stored.state == target {
            let computed = normalized_sha(&stored)?;
            if stored.revision == expected_revision && computed == expected_prior_sha {
                return Ok(stored);
            }
            if expected_revision
                .checked_add(1)
                .is_some_and(|revision| stored.revision == revision)
                && stored.prior_sha256 == expected_prior_sha
            {
                return Ok(stored);
            }
            if stored.revision != expected_revision {
                return Err(ScmOperationStoreError::Conflict);
            }
            if computed != expected_prior_sha {
                return Err(ScmOperationStoreError::Conflict);
            }
            return Ok(stored);
        }
        if stored.state.is_terminal() {
            return Err(ScmOperationStoreError::IllegalTransition {
                from: format!("{stored_state:?}", stored_state = stored.state),
                to: format!("{target:?}"),
            });
        }
        if !is_legal_transition(stored.state, target) {
            return Err(ScmOperationStoreError::IllegalTransition {
                from: format!("{stored_state:?}", stored_state = stored.state),
                to: format!("{target:?}"),
            });
        }
        let computed = normalized_sha(&stored)?;
        if stored.revision != expected_revision {
            return Err(ScmOperationStoreError::Conflict);
        }
        if computed != expected_prior_sha {
            return Err(ScmOperationStoreError::Conflict);
        }
        let next_revision = stored
            .revision
            .checked_add(1)
            .ok_or(ScmOperationStoreError::Conflict)?;
        let history = append_history_link(&stored)?;
        let mut next = ScmOperationRecord {
            magic: SCM_STORE_MAGIC.to_owned(),
            version: SCM_RECORD_VERSION,
            history_format: ScmOperationHistoryFormat::AnchoredV1,
            installation: stored.installation.clone(),
            service: stored.service.clone(),
            approval_digest: stored.approval_digest.clone(),
            config_digest: stored.config_digest.clone(),
            operation_id: stored.operation_id.clone(),
            request_digest: stored.request_digest.clone(),
            state: target,
            revision: next_revision,
            prior_sha256: computed,
            checksum: String::new(),
            history,
        };
        next.checksum = normalized_sha(&next)?;
        next.validate()?;
        let bytes = encode_record(&next)?;
        {
            let mut table = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            table
                .insert(next.key().as_str(), bytes.as_slice())
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
        }
        write
            .commit()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        drop(database);
        Ok(next)
    }

    /// Advance an operation through the Host-owned state machine.
    ///
    /// The coordinator is a non-forgeable capability bound to this exact
    /// store instance; a coordinator obtained from another store is rejected
    /// before any database read or write.
    pub fn advance_to(
        &self,
        coordinator: &ScmOperationCoordinator,
        identity: &ScmOperationIdentity,
        expected_revision: u64,
        expected_prior_sha: &str,
        target: ScmOperationState,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        self.cas_transition(
            coordinator,
            identity,
            expected_revision,
            expected_prior_sha,
            target,
        )
    }

    /// Quarantine an operation after an ambiguous effect outcome.
    ///
    /// This is also guarded by the store-bound coordinator and is terminal;
    /// callers must reconcile the external effect before any later action.
    #[allow(clippy::too_many_lines)]
    pub fn quarantine_to_unknown(
        &self,
        coordinator: &ScmOperationCoordinator,
        identity: &ScmOperationIdentity,
        expected_revision: u64,
        expected_prior_sha: &str,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        self.authorize(coordinator)?;
        identity.validate()?;
        let database = self.open_write_database()?;
        let write = database
            .begin_write()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let stored: ScmOperationRecord = {
            let stable = identity.stable_key();
            let index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let Some(index_bytes) = index
                .get(stable.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
                .map(|value| value.value().to_vec())
            else {
                return Err(ScmOperationStoreError::InvalidRecord("not found".into()));
            };
            let entry = decode_index(&index_bytes)?;
            if entry.stable_key != stable {
                return Err(ScmOperationStoreError::Corrupt);
            }
            let ops = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let scanned = scan_operation_records(&ops, Some(&stable))?;
            let Some(v) = ops
                .get(entry.record_key.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
            else {
                return Err(ScmOperationStoreError::Corrupt);
            };
            let rec = decode_record(v.value())?;
            if rec.key() != entry.record_key || rec.stable_key() != stable {
                return Err(ScmOperationStoreError::Corrupt);
            }
            if scanned
                .as_ref()
                .is_none_or(|record| record.key() != entry.record_key)
            {
                return Err(ScmOperationStoreError::Corrupt);
            }
            if rec.installation != identity.installation
                || rec.service != identity.service
                || rec.operation_id != identity.operation_id
            {
                return Err(ScmOperationStoreError::Corrupt);
            }
            if rec.approval_digest != identity.approval_digest
                || rec.config_digest != identity.config_digest
                || rec.request_digest != identity.request_digest
            {
                return Err(ScmOperationStoreError::DigestConflict);
            }
            rec
        };
        if stored.state == ScmOperationState::Unknown {
            let computed = normalized_sha(&stored)?;
            if stored.revision == expected_revision && computed == expected_prior_sha {
                return Ok(stored);
            }
            if expected_revision
                .checked_add(1)
                .is_some_and(|revision| stored.revision == revision)
                && stored.prior_sha256 == expected_prior_sha
            {
                return Ok(stored);
            }
            return Err(ScmOperationStoreError::Conflict);
        }
        if stored.state == ScmOperationState::Completed {
            return Err(ScmOperationStoreError::IllegalTransition {
                from: format!("{stored_state:?}", stored_state = stored.state),
                to: format!("{:?}", ScmOperationState::Unknown),
            });
        }
        let computed = normalized_sha(&stored)?;
        if stored.revision != expected_revision || computed != expected_prior_sha {
            return Err(ScmOperationStoreError::Conflict);
        }
        let next_revision = stored
            .revision
            .checked_add(1)
            .ok_or(ScmOperationStoreError::Conflict)?;
        let history = append_history_link(&stored)?;
        let mut next = ScmOperationRecord {
            magic: SCM_STORE_MAGIC.to_owned(),
            version: SCM_RECORD_VERSION,
            history_format: ScmOperationHistoryFormat::AnchoredV1,
            installation: stored.installation.clone(),
            service: stored.service.clone(),
            approval_digest: stored.approval_digest.clone(),
            config_digest: stored.config_digest.clone(),
            operation_id: stored.operation_id.clone(),
            request_digest: stored.request_digest.clone(),
            state: ScmOperationState::Unknown,
            revision: next_revision,
            prior_sha256: computed,
            checksum: String::new(),
            history,
        };
        next.checksum = normalized_sha(&next)?;
        next.validate()?;
        let bytes = encode_record(&next)?;
        {
            let mut table = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            table
                .insert(next.key().as_str(), bytes.as_slice())
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
        }
        write
            .commit()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        drop(database);
        Ok(next)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn _assert_sealed_only_coordinator_can_advance() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn h(v: &str) -> PlatformHandle {
        PlatformHandle::new(v).unwrap()
    }
    fn digest_handle(c: char) -> PlatformHandle {
        h(&c.to_string().repeat(64))
    }
    fn identity(op: &str) -> ScmOperationIdentity {
        ScmOperationIdentity {
            installation: h("test-installation"),
            service: h(CANONICAL_SERVICE),
            approval_digest: digest_handle('a'),
            config_digest: digest_handle('b'),
            operation_id: h(op),
            request_digest: digest_handle('c'),
        }
    }
    fn temp_path(label: &str) -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("scm-op-{label}-{pid}-{nanos}-{n}.redb"))
    }
    fn fingerprint(path: &Path) -> (Vec<u8>, std::time::SystemTime) {
        (
            std::fs::read(path).unwrap(),
            std::fs::metadata(path).unwrap().modified().unwrap(),
        )
    }
    fn sha_of(rec: &ScmOperationRecord) -> String {
        normalized_sha(rec).unwrap()
    }

    #[derive(Serialize)]
    struct UnanchoredHistoryLinkDigest<'a> {
        revision: u64,
        checksum: &'a str,
    }

    #[derive(Serialize)]
    struct UnanchoredCurrentRecordDigest<'a> {
        magic: &'a str,
        version: u16,
        history_format: ScmOperationHistoryFormat,
        installation: &'a PlatformHandle,
        service: &'a PlatformHandle,
        approval_digest: &'a PlatformHandle,
        config_digest: &'a PlatformHandle,
        operation_id: &'a PlatformHandle,
        request_digest: &'a PlatformHandle,
        state: ScmOperationState,
        revision: u64,
        prior_sha256: &'a str,
        history: Vec<UnanchoredHistoryLinkDigest<'a>>,
    }

    #[derive(Serialize)]
    struct LegacyV1RecordDigest<'a> {
        magic: &'a str,
        version: u16,
        installation: &'a PlatformHandle,
        service: &'a PlatformHandle,
        approval_digest: &'a PlatformHandle,
        config_digest: &'a PlatformHandle,
        operation_id: &'a PlatformHandle,
        request_digest: &'a PlatformHandle,
        state: ScmOperationState,
        revision: u64,
        prior_sha256: &'a str,
        history: Vec<UnanchoredHistoryLinkDigest<'a>>,
    }

    fn unanchored_history(record: &ScmOperationRecord) -> Vec<UnanchoredHistoryLinkDigest<'_>> {
        record
            .history
            .iter()
            .map(|link| UnanchoredHistoryLinkDigest {
                revision: link.revision,
                checksum: &link.checksum,
            })
            .collect()
    }

    fn unanchored_current_sha(record: &ScmOperationRecord) -> String {
        let digest = UnanchoredCurrentRecordDigest {
            magic: &record.magic,
            version: record.version,
            history_format: record.history_format,
            installation: &record.installation,
            service: &record.service,
            approval_digest: &record.approval_digest,
            config_digest: &record.config_digest,
            operation_id: &record.operation_id,
            request_digest: &record.request_digest,
            state: record.state,
            revision: record.revision,
            prior_sha256: &record.prior_sha256,
            history: unanchored_history(record),
        };
        sha256_hex(&serde_json::to_vec(&digest).unwrap())
    }

    fn legacy_v1_sha(record: &ScmOperationRecord) -> String {
        let digest = LegacyV1RecordDigest {
            magic: LEGACY_SCM_STORE_MAGIC_V1,
            version: 1,
            installation: &record.installation,
            service: &record.service,
            approval_digest: &record.approval_digest,
            config_digest: &record.config_digest,
            operation_id: &record.operation_id,
            request_digest: &record.request_digest,
            state: record.state,
            revision: record.revision,
            prior_sha256: &record.prior_sha256,
            history: unanchored_history(record),
        };
        sha256_hex(&serde_json::to_vec(&digest).unwrap())
    }

    fn create(store: &ScmOperationStore, identity: ScmOperationIdentity) -> ScmOperationRecord {
        let coordinator = store.coordinator();
        store.create_operation(&coordinator, identity).unwrap()
    }

    #[test]
    fn transition_monotonic() {
        let path = temp_path("mono");
        let store = ScmOperationStore::open(&path).unwrap();
        let id = identity("op-mono");
        let r1 = create(&store, id.clone());
        assert_eq!(r1.state(), ScmOperationState::StopIntentCommitted);
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let r2 = store
            .advance_to(
                &coord,
                &id,
                r1.revision(),
                &s1,
                ScmOperationState::StopObserved,
            )
            .unwrap();
        assert_eq!(r2.state(), ScmOperationState::StopObserved);
        let s2 = sha_of(&r2);
        let r3 = store
            .advance_to(
                &coord,
                &id,
                r2.revision(),
                &s2,
                ScmOperationState::StartIntentCommitted,
            )
            .unwrap();
        let s3 = sha_of(&r3);
        let r4 = store
            .advance_to(
                &coord,
                &id,
                r3.revision(),
                &s3,
                ScmOperationState::StartedObserved,
            )
            .unwrap();
        let s4 = sha_of(&r4);
        let r5 = store
            .advance_to(
                &coord,
                &id,
                r4.revision(),
                &s4,
                ScmOperationState::Completed,
            )
            .unwrap();
        assert_eq!(r5.state(), ScmOperationState::Completed);
        let s5 = sha_of(&r5);
        assert_eq!(
            store.advance_to(
                &coord,
                &id,
                r5.revision(),
                &s5,
                ScmOperationState::StopObserved
            ),
            Err(ScmOperationStoreError::IllegalTransition {
                from: format!("{:?}", ScmOperationState::Completed),
                to: format!("{:?}", ScmOperationState::StopObserved)
            })
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn idempotent_replay_create_and_transition() {
        let path = temp_path("replay");
        let store = ScmOperationStore::open(&path).unwrap();
        let id = identity("op-replay");
        let r1 = create(&store, id.clone());
        let r1b = create(&store, id.clone());
        assert_eq!(r1, r1b);
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let r2 = store
            .advance_to(
                &coord,
                &id,
                r1.revision(),
                &s1,
                ScmOperationState::StopObserved,
            )
            .unwrap();
        let r2_replay = store
            .advance_to(
                &coord,
                &id,
                r1.revision(),
                &s1,
                ScmOperationState::StopObserved,
            )
            .unwrap();
        assert_eq!(r2, r2_replay);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn digest_conflict() {
        let path = temp_path("digest");
        let store = ScmOperationStore::open(&path).unwrap();
        let id = identity("op-digest");
        let r1 = create(&store, id.clone());
        let mut bad = id.clone();
        bad.approval_digest = digest_handle('d');
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        assert_eq!(
            store.advance_to(
                &coord,
                &bad,
                r1.revision(),
                &s1,
                ScmOperationState::StopObserved
            ),
            Err(ScmOperationStoreError::DigestConflict)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn same_revision_drift_conflict() {
        let path = temp_path("drift");
        let store = ScmOperationStore::open(&path).unwrap();
        let id = identity("op-drift");
        let r1 = create(&store, id.clone());
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let mut bad_sha = s1.clone();
        bad_sha.replace_range(0..1, "f");
        assert_eq!(
            store.advance_to(
                &coord,
                &id,
                r1.revision(),
                &bad_sha,
                ScmOperationState::StopObserved
            ),
            Err(ScmOperationStoreError::Conflict)
        );
        assert_eq!(
            store.advance_to(
                &coord,
                &id,
                r1.revision() + 1,
                &s1,
                ScmOperationState::StopObserved
            ),
            Err(ScmOperationStoreError::Conflict)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn crash_reopen_preserves() {
        let path = temp_path("crash");
        let id = identity("op-crash");
        let (rev, sha) = {
            let store = ScmOperationStore::open(&path).unwrap();
            let r1 = create(&store, id.clone());
            let coord = store.coordinator();
            let s1 = sha_of(&r1);
            let r2 = store
                .advance_to(
                    &coord,
                    &id,
                    r1.revision(),
                    &s1,
                    ScmOperationState::StopObserved,
                )
                .unwrap();
            (r2.revision(), sha_of(&r2))
        };
        let store2 = ScmOperationStore::open(&path).unwrap();
        let loaded = store2.load_operation(&id).unwrap().unwrap();
        assert_eq!(loaded.revision(), rev);
        assert_eq!(sha_of(&loaded), sha);
        let coord2 = store2.coordinator();
        let r3 = store2
            .advance_to(
                &coord2,
                &id,
                loaded.revision(),
                &sha_of(&loaded),
                ScmOperationState::StartIntentCommitted,
            )
            .unwrap();
        assert_eq!(r3.state(), ScmOperationState::StartIntentCommitted);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unknown_query_is_query_only() {
        let path = temp_path("unknown");
        let store = ScmOperationStore::open(&path).unwrap();
        let id = identity("op-unknown");
        let r1 = create(&store, id.clone());
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let u = store
            .quarantine_to_unknown(&coord, &id, r1.revision(), &s1)
            .unwrap();
        assert_eq!(u.state(), ScmOperationState::Unknown);
        let q = store.query_operation(&id).unwrap().unwrap();
        assert_eq!(q.state(), ScmOperationState::Unknown);
        let sq = sha_of(&q);
        assert_eq!(
            store.advance_to(
                &coord,
                &id,
                q.revision(),
                &sq,
                ScmOperationState::StopObserved
            ),
            Err(ScmOperationStoreError::Quarantined)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn response_loss_query_never_authorizes_resend() {
        let path = temp_path("resend");
        let id = identity("op-resend");
        let store = ScmOperationStore::open(&path).unwrap();
        let r1 = create(&store, id.clone());
        let q = store.query_operation(&id).unwrap().unwrap();
        assert_eq!(q.state(), ScmOperationState::StopIntentCommitted);
        assert_eq!(r1, q);
        drop(store);
        let store2 = ScmOperationStore::open(&path).unwrap();
        let q2 = store2.query_operation(&id).unwrap().unwrap();
        assert_eq!(q2.state(), ScmOperationState::StopIntentCommitted);
        assert_eq!(q2.revision(), r1.revision());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn corruption_is_fail_closed() {
        let path = temp_path("corrupt");
        let id = identity("op-corrupt");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, id.clone());
        }
        {
            let db = Database::open(&path).unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut t = w.open_table(OPS_TABLE).unwrap();
                t.insert(id.key().as_str(), b"not-json".as_slice()).unwrap();
            }
            w.commit().unwrap();
        }
        let store2 = ScmOperationStore::open(&path).unwrap();
        assert_eq!(
            store2.load_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_version_is_distinct() {
        let path = temp_path("legacy");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, identity("op-legacy"));
            drop(store);
            let db = Database::open(&path).unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut t = w.open_table(META_TABLE).unwrap();
                let m = StoreMeta {
                    magic: SCM_STORE_MAGIC.to_owned(),
                    version: 99,
                };
                let b = serde_json::to_vec(&m).unwrap();
                t.insert(META_KEY, b.as_slice()).unwrap();
            }
            w.commit().unwrap();
        }
        let err = ScmOperationStore::open(&path).unwrap_err();
        assert_eq!(err, ScmOperationStoreError::Legacy { version: 99 });
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v1_store_requires_explicit_migration() {
        let path = temp_path("legacy-v1-store");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, identity("op-legacy-v1-store"));
        }
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut table = write.open_table(META_TABLE).unwrap();
                let meta = StoreMeta {
                    magic: LEGACY_SCM_STORE_MAGIC_V1.to_owned(),
                    version: 1,
                };
                let bytes = serde_json::to_vec(&meta).unwrap();
                table.insert(META_KEY, bytes.as_slice()).unwrap();
            }
            write.commit().unwrap();
        }
        assert_eq!(
            ScmOperationStore::open_existing(&path).unwrap_err(),
            ScmOperationStoreError::Legacy { version: 1 }
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_table_is_distinct() {
        let path = temp_path("missing");
        {
            let db = Database::create(&path).unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut t = w.open_table(META_TABLE).unwrap();
                let m = StoreMeta {
                    magic: SCM_STORE_MAGIC.to_owned(),
                    version: SCM_STORE_VERSION,
                };
                let b = serde_json::to_vec(&m).unwrap();
                t.insert(META_KEY, b.as_slice()).unwrap();
            }
            w.commit().unwrap();
        }
        let e = ScmOperationStore::open_existing(&path).unwrap_err();
        assert_eq!(e, ScmOperationStoreError::MissingTable);
        assert_eq!(
            ScmOperationStore::open_existing("nonexistent/missing.redb").unwrap_err(),
            ScmOperationStoreError::MissingFile
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn open_existing_is_read_only_for_blank_database() {
        let path = temp_path("blank-read-only");
        {
            let database = Database::create(&path).unwrap();
            drop(database);
        }
        assert_eq!(
            ScmOperationStore::open_existing(&path).unwrap_err(),
            ScmOperationStoreError::MissingTable
        );
        let database = Database::open(&path).unwrap();
        let read = database.begin_read().unwrap();
        assert!(matches!(
            read.open_table(META_TABLE),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
        drop(read);
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn open_existing_and_query_leave_bytes_and_mtime_unchanged() {
        let path = temp_path("read-only-fingerprint");
        let id = identity("op-read-only-fingerprint");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, id.clone());
        }
        let before = fingerprint(&path);
        let existing = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            existing
                .query_operation(&id)
                .unwrap()
                .unwrap()
                .operation_id(),
            &id.operation_id
        );
        drop(existing);
        assert_eq!(fingerprint(&path), before);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_index_with_existing_record_is_corrupt() {
        let path = temp_path("missing-index");
        let id = identity("op-missing-index");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, id.clone());
        }
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut index = write.open_table(INDEX_TABLE).unwrap();
                index.remove(id.stable_key().as_str()).unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn index_binds_stable_key_and_record_key() {
        let path = temp_path("index-binding");
        let id = identity("op-index-binding");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, id.clone());
        }
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut index = write.open_table(INDEX_TABLE).unwrap();
                let entry = ScmOperationIndexEntry {
                    magic: SCM_INDEX_MAGIC.to_owned(),
                    version: SCM_INDEX_VERSION,
                    stable_key: "other-stable".to_owned(),
                    record_key: id.key(),
                };
                let bytes = serde_json::to_vec(&entry).unwrap();
                index
                    .insert(id.stable_key().as_str(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn duplicate_stable_identity_is_corrupt_even_when_index_points_to_one_record() {
        let path = temp_path("duplicate-stable");
        let id = identity("op-duplicate-stable");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, id.clone());
        }
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut operations = write.open_table(OPS_TABLE).unwrap();
                let mut envelope: ScmOperationRecordEnvelope = serde_json::from_slice(
                    operations.get(id.key().as_str()).unwrap().unwrap().value(),
                )
                .unwrap();
                envelope.record.request_digest = digest_handle('d');
                envelope.record.checksum = normalized_sha(&envelope.record).unwrap();
                let duplicate_key = envelope.record.key();
                let bytes = serde_json::to_vec(&envelope).unwrap();
                operations
                    .insert(duplicate_key.as_str(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn current_checksum_and_predecessor_history_are_verified() {
        let path = temp_path("checksum-history");
        let id = identity("op-checksum-history");
        let record = {
            let store = ScmOperationStore::open(&path).unwrap();
            let first = create(&store, id.clone());
            let coordinator = store.coordinator();
            store
                .advance_to(
                    &coordinator,
                    &id,
                    first.revision(),
                    first.checksum(),
                    ScmOperationState::StopObserved,
                )
                .unwrap()
        };
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut operations = write.open_table(OPS_TABLE).unwrap();
                let mut envelope: ScmOperationRecordEnvelope = serde_json::from_slice(
                    operations.get(id.key().as_str()).unwrap().unwrap().value(),
                )
                .unwrap();
                envelope.record.checksum = "0".repeat(64);
                let bytes = serde_json::to_vec(&envelope).unwrap();
                operations
                    .insert(id.key().as_str(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        drop(store);

        // A current checksum can be recomputed, but an invalid predecessor
        // link must still fail closed.
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut operations = write.open_table(OPS_TABLE).unwrap();
                let mut envelope: ScmOperationRecordEnvelope = serde_json::from_slice(
                    operations.get(id.key().as_str()).unwrap().unwrap().value(),
                )
                .unwrap();
                envelope.record.checksum = record.checksum().to_owned();
                envelope.record.prior_sha256 = "d".repeat(64);
                envelope.record.checksum = normalized_sha(&envelope.record).unwrap();
                let bytes = serde_json::to_vec(&envelope).unwrap();
                operations
                    .insert(id.key().as_str(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tampered_middle_history_link_is_rejected_after_current_checksum_recomputed() {
        let path = temp_path("history-anchor-tamper");
        let id = identity("op-history-anchor-tamper");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            let first = create(&store, id.clone());
            let coordinator = store.coordinator();
            let second = store
                .advance_to(
                    &coordinator,
                    &id,
                    first.revision(),
                    first.checksum(),
                    ScmOperationState::StopObserved,
                )
                .unwrap();
            store
                .advance_to(
                    &coordinator,
                    &id,
                    second.revision(),
                    second.checksum(),
                    ScmOperationState::StartIntentCommitted,
                )
                .unwrap();
        }
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut operations = write.open_table(OPS_TABLE).unwrap();
                let mut envelope: ScmOperationRecordEnvelope = serde_json::from_slice(
                    operations.get(id.key().as_str()).unwrap().unwrap().value(),
                )
                .unwrap();
                assert_eq!(envelope.record.history.len(), 2);
                envelope.record.history[0].checksum = "d".repeat(64);
                // Recompute the current checksum to prove the independent
                // history anchor, rather than only the current-record digest,
                // catches this tamper.
                envelope.record.checksum = normalized_sha(&envelope.record).unwrap();
                let bytes = serde_json::to_vec(&envelope).unwrap();
                operations
                    .insert(id.key().as_str(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Corrupt
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stripping_all_anchors_and_recomputing_current_checksum_is_rejected() {
        let path = temp_path("history-anchor-strip");
        let id = identity("op-history-anchor-strip");
        let record = {
            let store = ScmOperationStore::open(&path).unwrap();
            let first = create(&store, id.clone());
            let coordinator = store.coordinator();
            let second = store
                .advance_to(
                    &coordinator,
                    &id,
                    first.revision(),
                    first.checksum(),
                    ScmOperationState::StopObserved,
                )
                .unwrap();
            store
                .advance_to(
                    &coordinator,
                    &id,
                    second.revision(),
                    second.checksum(),
                    ScmOperationState::StartIntentCommitted,
                )
                .unwrap()
        };
        assert_eq!(record.history.len(), 2);

        let mut value: serde_json::Value =
            serde_json::from_slice(&encode_record(&record).unwrap()).unwrap();
        let record_object = value["record"].as_object_mut().unwrap();
        for link in record_object["history"].as_array_mut().unwrap() {
            assert!(
                link.as_object_mut()
                    .unwrap()
                    .remove("chain_sha256")
                    .is_some()
            );
        }
        record_object.insert(
            "checksum".to_owned(),
            serde_json::Value::String(unanchored_current_sha(&record)),
        );
        let tampered = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            decode_record(&tampered),
            Err(ScmOperationStoreError::Corrupt)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn current_record_roundtrip_requires_explicit_anchored_provenance() {
        let path = temp_path("history-v2-roundtrip");
        let id = identity("op-history-v2-roundtrip");
        let record = {
            let store = ScmOperationStore::open(&path).unwrap();
            let first = create(&store, id.clone());
            let coordinator = store.coordinator();
            store
                .advance_to(
                    &coordinator,
                    &id,
                    first.revision(),
                    first.checksum(),
                    ScmOperationState::StopObserved,
                )
                .unwrap()
        };
        let encoded = encode_record(&record).unwrap();
        let envelope: ScmOperationRecordEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(envelope.version, SCM_RECORD_ENVELOPE_VERSION);
        assert_eq!(envelope.record.version, SCM_RECORD_VERSION);
        assert_eq!(
            envelope.record.history_format,
            ScmOperationHistoryFormat::AnchoredV1
        );
        assert!(
            envelope
                .record
                .history
                .iter()
                .all(|link| is_sha256(&link.chain_sha256))
        );
        assert_eq!(decode_record(&encoded).unwrap(), record);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn downgraded_unanchored_v1_record_is_migration_input_not_current_truth() {
        let path = temp_path("history-v1-migration");
        let id = identity("op-history-v1-migration");
        let record = {
            let store = ScmOperationStore::open(&path).unwrap();
            let first = create(&store, id.clone());
            let coordinator = store.coordinator();
            store
                .advance_to(
                    &coordinator,
                    &id,
                    first.revision(),
                    first.checksum(),
                    ScmOperationState::StopObserved,
                )
                .unwrap()
        };
        let mut value: serde_json::Value =
            serde_json::from_slice(&encode_record(&record).unwrap()).unwrap();
        value["magic"] = serde_json::json!(LEGACY_SCM_RECORD_ENVELOPE_MAGIC_V1);
        value["version"] = serde_json::json!(1);
        let record_object = value["record"].as_object_mut().unwrap();
        record_object.insert(
            "magic".to_owned(),
            serde_json::json!(LEGACY_SCM_STORE_MAGIC_V1),
        );
        record_object.insert("version".to_owned(), serde_json::json!(1));
        assert!(record_object.remove("history_format").is_some());
        for link in record_object["history"].as_array_mut().unwrap() {
            assert!(
                link.as_object_mut()
                    .unwrap()
                    .remove("chain_sha256")
                    .is_some()
            );
        }
        record_object.insert(
            "checksum".to_owned(),
            serde_json::Value::String(legacy_v1_sha(&record)),
        );
        let legacy_envelope = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            decode_record(&legacy_envelope),
            Err(ScmOperationStoreError::Legacy { version: 1 })
        );

        let legacy_record = serde_json::to_vec(&value["record"]).unwrap();
        assert_eq!(
            decode_record(&legacy_record),
            Err(ScmOperationStoreError::Legacy { version: 1 })
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn coordinator_is_bound_to_its_store() {
        let path = temp_path("owner-a");
        let other_path = temp_path("owner-b");
        let store = ScmOperationStore::open(&path).unwrap();
        let other = ScmOperationStore::open(&other_path).unwrap();
        let id = identity("op-owner");
        let record = create(&store, id.clone());
        let coordinator = store.coordinator();
        assert_eq!(
            other.advance_to(
                &coordinator,
                &id,
                record.revision(),
                record.checksum(),
                ScmOperationState::StopObserved,
            ),
            Err(ScmOperationStoreError::NotOwner)
        );
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(other_path);
    }

    #[test]
    fn create_requires_the_store_bound_coordinator() {
        let path = temp_path("create-owner-a");
        let other_path = temp_path("create-owner-b");
        let store = ScmOperationStore::open(&path).unwrap();
        let other = ScmOperationStore::open(&other_path).unwrap();
        let id = identity("op-create-owner");
        let other_coordinator = other.coordinator();
        assert_eq!(
            store.create_operation(&other_coordinator, id.clone()),
            Err(ScmOperationStoreError::NotOwner)
        );
        let coordinator = store.coordinator();
        assert!(store.create_operation(&coordinator, id).is_ok());
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(other_path);
    }

    #[test]
    fn record_envelope_rejects_unversioned_legacy_payload() {
        let path = temp_path("record-envelope");
        let id = identity("op-record-envelope");
        {
            let store = ScmOperationStore::open(&path).unwrap();
            create(&store, id.clone());
        }
        {
            let database = Database::open(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut operations = write.open_table(OPS_TABLE).unwrap();
                let envelope: ScmOperationRecordEnvelope = serde_json::from_slice(
                    operations.get(id.key().as_str()).unwrap().unwrap().value(),
                )
                .unwrap();
                let mut legacy = serde_json::to_value(&envelope.record).unwrap();
                let legacy_object = legacy.as_object_mut().unwrap();
                legacy_object.insert(
                    "magic".to_owned(),
                    serde_json::json!(LEGACY_SCM_STORE_MAGIC_V1),
                );
                legacy_object.insert("version".to_owned(), serde_json::json!(1));
                assert!(legacy_object.remove("history_format").is_some());
                legacy_object.insert(
                    "checksum".to_owned(),
                    serde_json::Value::String(legacy_v1_sha(&envelope.record)),
                );
                let bytes = serde_json::to_vec(&legacy).unwrap();
                operations
                    .insert(id.key().as_str(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let store = ScmOperationStore::open_existing(&path).unwrap();
        assert_eq!(
            store.query_operation(&id).unwrap_err(),
            ScmOperationStoreError::Legacy { version: 1 }
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strict_serde_no_defaults() {
        let v = serde_json::json!({
            "magic": SCM_STORE_MAGIC,
            "version": SCM_RECORD_VERSION,
            "installation": "test-installation",
            "service": CANONICAL_SERVICE,
            "approval_digest": "a".repeat(64),
            "config_digest": "b".repeat(64),
            "operation_id": "op-strict",
            "request_digest": "c".repeat(64),
            "state": "STOP_INTENT_COMMITTED",
            "revision": 1,
            "prior_sha256": "GENESIS",
            "extra": "field"
        });
        assert!(serde_json::from_value::<ScmOperationRecord>(v).is_err());
        let missing = serde_json::json!({
            "magic": SCM_STORE_MAGIC,
            "version": SCM_RECORD_VERSION,
            "installation": "test-installation",
            "service": CANONICAL_SERVICE,
            "approval_digest": "a".repeat(64),
            "config_digest": "b".repeat(64),
            "operation_id": "op-strict",
            "request_digest": "c".repeat(64),
            "state": "STOP_INTENT_COMMITTED",
            "revision": 1
        });
        assert!(serde_json::from_value::<ScmOperationRecord>(missing).is_err());
    }
}
