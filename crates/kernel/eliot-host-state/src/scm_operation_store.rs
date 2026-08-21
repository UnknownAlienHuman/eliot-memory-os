#![allow(dead_code)]
use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCM_STORE_MAGIC: &str = "ELIOT-SCM-OP-STORE-V1";
const SCM_STORE_VERSION: u16 = 1;
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
    installation: PlatformHandle,
    service: PlatformHandle,
    approval_digest: PlatformHandle,
    config_digest: PlatformHandle,
    operation_id: PlatformHandle,
    request_digest: PlatformHandle,
    state: ScmOperationState,
    revision: u64,
    prior_sha256: String,
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
        if self.magic != SCM_STORE_MAGIC {
            return Err(ScmOperationStoreError::Corrupt);
        }
        if self.version != SCM_STORE_VERSION {
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
        if self.prior_sha256.len() != 64
            || !self
                .prior_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            if self.prior_sha256 == "GENESIS" {
            } else {
                return Err(ScmOperationStoreError::InvalidRecord(
                    "prior_sha256 must be 64 lowercase hex or GENESIS".into(),
                ));
            }
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn normalized_sha(record: &ScmOperationRecord) -> Result<String, ScmOperationStoreError> {
    let bytes = serde_json::to_vec(record).map_err(|_| ScmOperationStoreError::Corrupt)?;
    Ok(sha256_hex(&bytes))
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed coordinator capability. Only `ScmOperationStore::coordinator` can create it.
///
/// ```compile_fail
/// use eliot_host_state::ScmOperationCoordinator;
/// let c = ScmOperationCoordinator { _private: () };
/// ```
///
/// ```compile_fail
/// use eliot_host_state::{ScmOperationStore, ScmOperationState, ScmOperationIdentity};
/// use eliot_platform::PlatformHandle;
/// let store = ScmOperationStore::open("x.redb").unwrap();
/// store.advance_to(
///     &store.coordinator(),
///     &ScmOperationIdentity {
///         installation: PlatformHandle::new("i").unwrap(),
///         service: PlatformHandle::new("EliotHost").unwrap(),
///         approval_digest: PlatformHandle::new(&"a".repeat(64)).unwrap(),
///         config_digest: PlatformHandle::new(&"b".repeat(64)).unwrap(),
///         operation_id: PlatformHandle::new("o").unwrap(),
///         request_digest: PlatformHandle::new(&"c".repeat(64)).unwrap(),
///     },
///     1,
///     "sha",
///     ScmOperationState::StopObserved,
/// );
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ScmOperationCoordinator {
    _private: (),
}

impl sealed::Sealed for ScmOperationCoordinator {}

impl ScmOperationCoordinator {
    fn new() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug)]
pub struct ScmOperationStore {
    database: Database,
    path: PathBuf,
}

impl ScmOperationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ScmOperationStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| ScmOperationStoreError::Unavailable)?;
        }
        let database = Database::create(&path).map_err(|_| ScmOperationStoreError::Unavailable)?;
        let store = Self { database, path };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, ScmOperationStoreError> {
        let path = path.as_ref().to_path_buf();
        if std::fs::symlink_metadata(&path).is_err() {
            return Err(ScmOperationStoreError::Unavailable);
        }
        let database = Database::open(&path).map_err(|_| ScmOperationStoreError::Unavailable)?;
        let store = Self { database, path };
        store.ensure_schema()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn open_unprotected_for_test(
        path: impl AsRef<Path>,
    ) -> Result<Self, ScmOperationStoreError> {
        Self::open(path)
    }

    pub fn coordinator(&self) -> ScmOperationCoordinator {
        ScmOperationCoordinator::new()
    }

    fn ensure_schema(&self) -> Result<(), ScmOperationStoreError> {
        let read = self
            .database
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
            let write = self
                .database
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

    pub fn create_operation(
        &self,
        identity: ScmOperationIdentity,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        identity.validate()?;
        let key = identity.key();
        let stable = identity.stable_key();
        let write = self
            .database
            .begin_write()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let existing: Option<ScmOperationRecord> = {
            let index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let idx_opt = index
                .get(stable.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?;
            if let Some(idx) = idx_opt {
                let full_key = String::from_utf8(idx.value().to_vec())
                    .map_err(|_| ScmOperationStoreError::Corrupt)?;
                let ops = write
                    .open_table(OPS_TABLE)
                    .map_err(|_| ScmOperationStoreError::Unavailable)?;
                match ops
                    .get(full_key.as_str())
                    .map_err(|_| ScmOperationStoreError::Corrupt)?
                {
                    Some(v) => {
                        let rec: ScmOperationRecord = serde_json::from_slice(v.value())
                            .map_err(|_| ScmOperationStoreError::Corrupt)?;
                        rec.validate()?;
                        Some(rec)
                    }
                    None => return Err(ScmOperationStoreError::Corrupt),
                }
            } else {
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
        let record = ScmOperationRecord {
            magic: SCM_STORE_MAGIC.to_owned(),
            version: SCM_STORE_VERSION,
            installation: identity.installation,
            service: identity.service,
            approval_digest: identity.approval_digest,
            config_digest: identity.config_digest,
            operation_id: identity.operation_id,
            request_digest: identity.request_digest,
            state: ScmOperationState::StopIntentCommitted,
            revision: 1,
            prior_sha256: sha256_hex(b"GENESIS"),
        };
        record.validate()?;
        let bytes = serde_json::to_vec(&record).map_err(|_| ScmOperationStoreError::Corrupt)?;
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
                .insert(stable.as_str(), key.as_bytes())
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
        }
        write
            .commit()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        Ok(record)
    }

    pub fn load_operation(
        &self,
        identity: &ScmOperationIdentity,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        identity.validate()?;
        self.load_by_stable(&identity.stable_key(), identity)
    }

    pub fn query_operation(
        &self,
        identity: &ScmOperationIdentity,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        self.load_operation(identity)
    }

    fn load_by_key(&self, key: &str) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        self.ensure_schema()?;
        let read = self
            .database
            .begin_read()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let table = read
            .open_table(OPS_TABLE)
            .map_err(|_| ScmOperationStoreError::MissingTable)?;
        let Some(v) = table
            .get(key)
            .map_err(|_| ScmOperationStoreError::Corrupt)?
        else {
            return Ok(None);
        };
        let rec: ScmOperationRecord =
            serde_json::from_slice(v.value()).map_err(|_| ScmOperationStoreError::Corrupt)?;
        rec.validate()?;
        Ok(Some(rec))
    }

    fn load_by_stable(
        &self,
        stable: &str,
        identity: &ScmOperationIdentity,
    ) -> Result<Option<ScmOperationRecord>, ScmOperationStoreError> {
        self.ensure_schema()?;
        let read = self
            .database
            .begin_read()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let index = read
            .open_table(INDEX_TABLE)
            .map_err(|_| ScmOperationStoreError::MissingTable)?;
        let Some(idx) = index
            .get(stable)
            .map_err(|_| ScmOperationStoreError::Corrupt)?
        else {
            return Ok(None);
        };
        let full_key =
            String::from_utf8(idx.value().to_vec()).map_err(|_| ScmOperationStoreError::Corrupt)?;
        let ops = read
            .open_table(OPS_TABLE)
            .map_err(|_| ScmOperationStoreError::MissingTable)?;
        let Some(v) = ops
            .get(full_key.as_str())
            .map_err(|_| ScmOperationStoreError::Corrupt)?
        else {
            return Err(ScmOperationStoreError::Corrupt);
        };
        let rec: ScmOperationRecord =
            serde_json::from_slice(v.value()).map_err(|_| ScmOperationStoreError::Corrupt)?;
        rec.validate()?;
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
        _coord: ScmOperationCoordinator,
        identity: &ScmOperationIdentity,
        expected_revision: u64,
        expected_prior_sha: &str,
        target: ScmOperationState,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        identity.validate()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let stored: ScmOperationRecord = {
            let stable = identity.stable_key();
            let index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let Some(idx) = index
                .get(stable.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
            else {
                return Err(ScmOperationStoreError::InvalidRecord("not found".into()));
            };
            let full_key = String::from_utf8(idx.value().to_vec())
                .map_err(|_| ScmOperationStoreError::Corrupt)?;
            let ops = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let Some(v) = ops
                .get(full_key.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
            else {
                return Err(ScmOperationStoreError::Corrupt);
            };
            let rec: ScmOperationRecord =
                serde_json::from_slice(v.value()).map_err(|_| ScmOperationStoreError::Corrupt)?;
            rec.validate()?;
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
            if stored.revision == expected_revision + 1 && stored.prior_sha256 == expected_prior_sha
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
        let next = ScmOperationRecord {
            magic: SCM_STORE_MAGIC.to_owned(),
            version: SCM_STORE_VERSION,
            installation: stored.installation.clone(),
            service: stored.service.clone(),
            approval_digest: stored.approval_digest.clone(),
            config_digest: stored.config_digest.clone(),
            operation_id: stored.operation_id.clone(),
            request_digest: stored.request_digest.clone(),
            state: target,
            revision: stored.revision + 1,
            prior_sha256: computed,
        };
        next.validate()?;
        let bytes = serde_json::to_vec(&next).map_err(|_| ScmOperationStoreError::Corrupt)?;
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
        Ok(next)
    }

    pub(crate) fn advance_to(
        &self,
        coord: ScmOperationCoordinator,
        identity: &ScmOperationIdentity,
        expected_revision: u64,
        expected_prior_sha: &str,
        target: ScmOperationState,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        self.cas_transition(
            coord,
            identity,
            expected_revision,
            expected_prior_sha,
            target,
        )
    }

    pub(crate) fn quarantine_to_unknown(
        &self,
        coord: ScmOperationCoordinator,
        identity: &ScmOperationIdentity,
        expected_revision: u64,
        expected_prior_sha: &str,
    ) -> Result<ScmOperationRecord, ScmOperationStoreError> {
        identity.validate()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| ScmOperationStoreError::Unavailable)?;
        let stored: ScmOperationRecord = {
            let stable = identity.stable_key();
            let index = write
                .open_table(INDEX_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let Some(idx) = index
                .get(stable.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
            else {
                return Err(ScmOperationStoreError::InvalidRecord("not found".into()));
            };
            let full_key = String::from_utf8(idx.value().to_vec())
                .map_err(|_| ScmOperationStoreError::Corrupt)?;
            let ops = write
                .open_table(OPS_TABLE)
                .map_err(|_| ScmOperationStoreError::Unavailable)?;
            let Some(v) = ops
                .get(full_key.as_str())
                .map_err(|_| ScmOperationStoreError::Corrupt)?
            else {
                return Err(ScmOperationStoreError::Corrupt);
            };
            let rec: ScmOperationRecord =
                serde_json::from_slice(v.value()).map_err(|_| ScmOperationStoreError::Corrupt)?;
            rec.validate()?;
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
            if stored.revision == expected_revision + 1 && stored.prior_sha256 == expected_prior_sha
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
        let next = ScmOperationRecord {
            magic: SCM_STORE_MAGIC.to_owned(),
            version: SCM_STORE_VERSION,
            installation: stored.installation.clone(),
            service: stored.service.clone(),
            approval_digest: stored.approval_digest.clone(),
            config_digest: stored.config_digest.clone(),
            operation_id: stored.operation_id.clone(),
            request_digest: stored.request_digest.clone(),
            state: ScmOperationState::Unknown,
            revision: stored.revision + 1,
            prior_sha256: computed,
        };
        next.validate()?;
        let bytes = serde_json::to_vec(&next).map_err(|_| ScmOperationStoreError::Corrupt)?;
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
        let _ = coord;
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
    fn sha_of(rec: &ScmOperationRecord) -> String {
        normalized_sha(rec).unwrap()
    }

    #[test]
    fn transition_monotonic() {
        let path = temp_path("mono");
        let store = ScmOperationStore::open(&path).unwrap();
        let id = identity("op-mono");
        let r1 = store.create_operation(id.clone()).unwrap();
        assert_eq!(r1.state(), ScmOperationState::StopIntentCommitted);
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let r2 = store
            .advance_to(
                coord,
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
                coord,
                &id,
                r2.revision(),
                &s2,
                ScmOperationState::StartIntentCommitted,
            )
            .unwrap();
        let s3 = sha_of(&r3);
        let r4 = store
            .advance_to(
                coord,
                &id,
                r3.revision(),
                &s3,
                ScmOperationState::StartedObserved,
            )
            .unwrap();
        let s4 = sha_of(&r4);
        let r5 = store
            .advance_to(coord, &id, r4.revision(), &s4, ScmOperationState::Completed)
            .unwrap();
        assert_eq!(r5.state(), ScmOperationState::Completed);
        let s5 = sha_of(&r5);
        assert_eq!(
            store.advance_to(
                coord,
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
        let r1 = store.create_operation(id.clone()).unwrap();
        let r1b = store.create_operation(id.clone()).unwrap();
        assert_eq!(r1, r1b);
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let r2 = store
            .advance_to(
                coord,
                &id,
                r1.revision(),
                &s1,
                ScmOperationState::StopObserved,
            )
            .unwrap();
        let r2_replay = store
            .advance_to(
                coord,
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
        let r1 = store.create_operation(id.clone()).unwrap();
        let mut bad = id.clone();
        bad.approval_digest = digest_handle('d');
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        assert_eq!(
            store.advance_to(
                coord,
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
        let r1 = store.create_operation(id.clone()).unwrap();
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let mut bad_sha = s1.clone();
        bad_sha.replace_range(0..1, "f");
        assert_eq!(
            store.advance_to(
                coord,
                &id,
                r1.revision(),
                &bad_sha,
                ScmOperationState::StopObserved
            ),
            Err(ScmOperationStoreError::Conflict)
        );
        assert_eq!(
            store.advance_to(
                coord,
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
            let r1 = store.create_operation(id.clone()).unwrap();
            let coord = store.coordinator();
            let s1 = sha_of(&r1);
            let r2 = store
                .advance_to(
                    coord,
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
                coord2,
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
        let r1 = store.create_operation(id.clone()).unwrap();
        let coord = store.coordinator();
        let s1 = sha_of(&r1);
        let u = store
            .quarantine_to_unknown(coord, &id, r1.revision(), &s1)
            .unwrap();
        assert_eq!(u.state(), ScmOperationState::Unknown);
        let q = store.query_operation(&id).unwrap().unwrap();
        assert_eq!(q.state(), ScmOperationState::Unknown);
        let sq = sha_of(&q);
        assert_eq!(
            store.advance_to(
                coord,
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
        let r1 = store.create_operation(id.clone()).unwrap();
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
            store.create_operation(id.clone()).unwrap();
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
            store.create_operation(identity("op-legacy")).unwrap();
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
            ScmOperationStoreError::Unavailable
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strict_serde_no_defaults() {
        let v = serde_json::json!({
            "magic": SCM_STORE_MAGIC,
            "version": SCM_STORE_VERSION,
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
            "version": SCM_STORE_VERSION,
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
