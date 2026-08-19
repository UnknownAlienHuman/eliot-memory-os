//! Explicit-path redb persistence for durable installer transactions.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{
    INSTALLATION_TRANSACTION_WIRE_VERSION, InstallationError, InstallationTransaction,
    InstallationTransactionStore, decode_installation_transaction_json,
    transaction_store_private::{self, TransactionVersion},
};
use eliot_contracts::ContractVersion;
use eliot_platform::PlatformHandle;

const TRANSACTION_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("installation_transactions_v7");
const TRANSACTION_TEMP_CREATE_ATTEMPTS: usize = 16;
static NEXT_TRANSACTION_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionEnvelope {
    wire_version: ContractVersion,
    transaction: InstallationTransaction,
}

/// Production redb transaction store rooted at one caller-selected exact path.
pub struct RedbInstallationTransactionStore {
    path: PathBuf,
}

impl RedbInstallationTransactionStore {
    /// Creates a new database at `path` without creating its parent directory.
    pub fn create_at_exact_path(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
        let path = path.as_ref();
        require_existing_parent(path)?;
        if path.exists() {
            return Err(InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "create requires an absent exact file".to_owned(),
            });
        }
        let database = Database::create(path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        drop(database);
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Creates and atomically publishes a new exact-path database containing
    /// one planned constructor-produced transaction in its v7 table.
    ///
    /// The transaction is committed and synced in a unique same-directory
    /// temporary database before a no-clobber hard-link publication. A caller
    /// cannot observe an empty final store between database creation and the
    /// first durable transaction record, and a publication race never
    /// overwrites an existing path. The published path is reopened and
    /// classified before this method returns.
    pub fn create_planned_at_exact_path(
        path: impl AsRef<Path>,
        transaction: &InstallationTransaction,
    ) -> Result<Self, InstallationError> {
        transaction.validate()?;
        if !transaction.is_constructor_planned() {
            return Err(InstallationError::InvalidField {
                field: "transaction".to_owned(),
                reason: "create_planned accepts only constructor-produced Planned/Pending v7 state"
                    .to_owned(),
            });
        }
        let path = path.as_ref();
        require_existing_parent(path)?;
        if path.exists() {
            return Err(existing_path_error());
        }

        let (publication, reserved) = PendingTransactionStorePublication::reserve(path)?;
        drop(reserved);
        let temporary = publication.temporary().to_owned();
        let database = Database::create(&temporary)
            .map_err(|error| InstallationError::Platform(format!("temporary create: {error}")))?;
        insert_planned(&database, transaction).map_err(|error| match error {
            InstallationError::Platform(reason) => {
                InstallationError::Platform(format!("temporary populate: {reason}"))
            }
            other => other,
        })?;
        drop(database);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(publication.temporary())
            .and_then(|file| file.sync_all())
            .map_err(|error| InstallationError::Platform(format!("temporary sync: {error}")))?;
        publication.publish(path).map_err(|error| match error {
            InstallationError::Platform(reason) => {
                InstallationError::Platform(format!("publish: {reason}"))
            }
            other => other,
        })?;
        let store = Self {
            path: path.to_path_buf(),
        };
        let reopened = Self::open_existing_exact_path(path).map_err(|error| match error {
            InstallationError::Platform(reason) => {
                InstallationError::Platform(format!("published reopen: {reason}"))
            }
            other => other,
        })?;
        drop(reopened);
        Ok(store)
    }

    /// Opens an existing regular database file without creating any path.
    pub fn open_existing_exact_path(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
        let path = path.as_ref();
        require_existing_parent(path)?;
        let metadata =
            std::fs::symlink_metadata(path).map_err(|error| InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: format!("existing regular file required: {error}"),
            })?;
        if !metadata.is_file() {
            return Err(InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "existing regular file required".to_owned(),
            });
        }
        let database = ReadOnlyDatabase::open(path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        drop(database);
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    fn open_read_only(&self) -> Result<ReadOnlyDatabase, InstallationError> {
        ReadOnlyDatabase::open(&self.path)
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }

    fn open_for_mutation(&self) -> Result<Database, InstallationError> {
        Database::open(&self.path).map_err(|error| InstallationError::Platform(error.to_string()))
    }
}

struct PendingTransactionStorePublication {
    temporary: PathBuf,
    owns_temporary: bool,
}

impl PendingTransactionStorePublication {
    fn reserve(destination: &Path) -> Result<(Self, File), InstallationError> {
        let directory = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "exact path must name a file".to_owned(),
            })?;
        let file_name = destination
            .file_name()
            .ok_or_else(|| InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "exact path must name a file".to_owned(),
            })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        for _ in 0..TRANSACTION_TEMP_CREATE_ATTEMPTS {
            let sequence = NEXT_TRANSACTION_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let mut temporary_name = OsString::from(".");
            temporary_name.push(file_name);
            temporary_name.push(format!(
                ".eliot-transaction-{}-{nonce}-{sequence}.tmp",
                std::process::id()
            ));
            let temporary = directory.join(temporary_name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => {
                    return Ok((
                        Self {
                            temporary,
                            owns_temporary: true,
                        },
                        file,
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(InstallationError::Platform(error.to_string())),
            }
        }
        Err(InstallationError::InvalidField {
            field: "transaction_store.path".to_owned(),
            reason: "could not reserve a unique same-directory temporary file".to_owned(),
        })
    }

    fn temporary(&self) -> &Path {
        &self.temporary
    }

    fn publish(mut self, destination: &Path) -> Result<(), InstallationError> {
        match fs::hard_link(&self.temporary, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(existing_path_error());
            }
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        }
        let directory = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "exact path must name a file".to_owned(),
            })?;
        sync_parent_directory(directory)?;
        self.remove_temporary()?;
        sync_parent_directory(directory)
    }

    fn remove_temporary(&mut self) -> Result<(), InstallationError> {
        match fs::remove_file(&self.temporary) {
            Ok(()) => {
                self.owns_temporary = false;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.owns_temporary = false;
                Ok(())
            }
            Err(error) => Err(InstallationError::Platform(error.to_string())),
        }
    }
}

impl Drop for PendingTransactionStorePublication {
    fn drop(&mut self) {
        if self.owns_temporary {
            let _ = fs::remove_file(&self.temporary);
        }
    }
}

fn existing_path_error() -> InstallationError {
    InstallationError::InvalidField {
        field: "transaction_store.path".to_owned(),
        reason: "create requires an absent exact file".to_owned(),
    }
}

#[cfg(unix)]
fn sync_parent_directory(directory: &Path) -> Result<(), InstallationError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| InstallationError::Platform(error.to_string()))
}

#[cfg(windows)]
fn sync_parent_directory(directory: &Path) -> Result<(), InstallationError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .and_then(|file| file.sync_all())
        .or_else(|error| match error.kind() {
            std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::Unsupported => Ok(()),
            _ => Err(error),
        })
        .map_err(|error| InstallationError::Platform(error.to_string()))
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_directory: &Path) -> Result<(), InstallationError> {
    Ok(())
}

impl InstallationTransactionStore for RedbInstallationTransactionStore {
    fn create_planned(
        &mut self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        transaction.validate()?;
        if !transaction.is_constructor_planned() {
            return Err(InstallationError::InvalidField {
                field: "transaction".to_owned(),
                reason: "create_planned accepts only constructor-produced Planned/Pending v7 state"
                    .to_owned(),
            });
        }
        let database = self.open_for_mutation()?;
        insert_planned(&database, transaction)
    }

    fn load(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<Option<InstallationTransaction>, InstallationError> {
        let database = self.open_read_only()?;
        let read = database
            .begin_read()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let table = match read.open_table(TRANSACTION_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                classify_missing_v7_table(&read)?;
                return Ok(None);
            }
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        };
        let Some(value) = table
            .get(transaction_id.as_str())
            .map_err(|error| InstallationError::Platform(error.to_string()))?
        else {
            return Ok(None);
        };
        decode(value.value()).map(Some)
    }
}

impl transaction_store_private::Sealed for RedbInstallationTransactionStore {
    fn compare_and_save(
        &mut self,
        expected: TransactionVersion,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        transaction.validate()?;
        let bytes = encode(transaction)?;
        let database = self.open_for_mutation()?;
        if !classify_v7_table(&database)? {
            return Err(InstallationError::TransactionNotFound {
                transaction_id: transaction.transaction_id.as_str().to_owned(),
            });
        }
        let write = database
            .begin_write()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        {
            let mut table = write
                .open_table(TRANSACTION_TABLE)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            let key = transaction.transaction_id.as_str();
            let current_bytes = {
                let current = table
                    .get(key)
                    .map_err(|error| InstallationError::Platform(error.to_string()))?
                    .ok_or_else(|| InstallationError::TransactionNotFound {
                        transaction_id: key.to_owned(),
                    })?;
                current.value().to_vec()
            };
            let current = decode(&current_bytes)?;
            let current_version = TransactionVersion::of(&current)?;
            if current_version.revision != expected.revision {
                return Err(InstallationError::CompareAndSaveConflict {
                    expected: expected.revision,
                    actual: current_version.revision,
                });
            }
            if current_version.checksum != expected.checksum {
                return Err(InstallationError::IdentityConflict);
            }
            let next_revision = expected.revision.checked_add(1).ok_or_else(|| {
                InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                }
            })?;
            if transaction.revision != next_revision {
                return Err(InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "compare_and_save requires exactly one revision step".to_owned(),
                });
            }
            if current.transaction_id != transaction.transaction_id
                || current.installer_plan_digest != transaction.installer_plan_digest
                || current.installer_effects != transaction.installer_effects
            {
                return Err(InstallationError::IdentityConflict);
            }
            table
                .insert(key, bytes.as_slice())
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }
}

fn insert_planned(
    database: &Database,
    transaction: &InstallationTransaction,
) -> Result<(), InstallationError> {
    let bytes = encode(transaction)?;
    classify_v7_table(database)?;
    let write = database
        .begin_write()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    {
        let mut table = write
            .open_table(TRANSACTION_TABLE)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let key = transaction.transaction_id.as_str();
        if table
            .get(key)
            .map_err(|error| InstallationError::Platform(error.to_string()))?
            .is_some()
        {
            return Err(InstallationError::CompareAndSaveConflict {
                expected: 0,
                actual: transaction.revision,
            });
        }
        table
            .insert(key, bytes.as_slice())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| InstallationError::Platform(error.to_string()))
}

fn classify_v7_table(database: &impl ReadableDatabase) -> Result<bool, InstallationError> {
    let read = database
        .begin_read()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    match read.open_table(TRANSACTION_TABLE) {
        Ok(_) => Ok(true),
        Err(redb::TableError::TableDoesNotExist(_)) => {
            classify_missing_v7_table(&read)?;
            Ok(false)
        }
        Err(error) => Err(InstallationError::Platform(error.to_string())),
    }
}

fn classify_missing_v7_table(read: &redb::ReadTransaction) -> Result<(), InstallationError> {
    let has_standard_tables = read
        .list_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .next()
        .is_some();
    let has_multimap_tables = read
        .list_multimap_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .next()
        .is_some();
    if has_standard_tables || has_multimap_tables {
        return Err(InstallationError::MigrationRequired {
            reason: "existing nonempty redb store has no installation_transactions_v7 table"
                .to_owned(),
        });
    }
    Ok(())
}

fn require_existing_parent(path: &Path) -> Result<(), InstallationError> {
    if !path.is_absolute() {
        return Err(InstallationError::InvalidField {
            field: "transaction_store.path".to_owned(),
            reason: "an explicit absolute path is required".to_owned(),
        });
    }
    let parent = path
        .parent()
        .ok_or_else(|| InstallationError::InvalidField {
            field: "transaction_store.path".to_owned(),
            reason: "path must have a parent".to_owned(),
        })?;
    let metadata =
        std::fs::symlink_metadata(parent).map_err(|error| InstallationError::InvalidField {
            field: "transaction_store.path".to_owned(),
            reason: format!("parent must already exist: {error}"),
        })?;
    if !metadata.is_dir() {
        return Err(InstallationError::InvalidField {
            field: "transaction_store.path".to_owned(),
            reason: "parent must already be a directory".to_owned(),
        });
    }
    Ok(())
}

fn encode(transaction: &InstallationTransaction) -> Result<Vec<u8>, InstallationError> {
    serde_json::to_vec(&TransactionEnvelope {
        wire_version: INSTALLATION_TRANSACTION_WIRE_VERSION,
        transaction: transaction.clone(),
    })
    .map_err(|error| InstallationError::CorruptRegistry {
        reason: error.to_string(),
    })
}

fn decode(bytes: &[u8]) -> Result<InstallationTransaction, InstallationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let version =
        value
            .get("wire_version")
            .ok_or_else(|| InstallationError::MigrationRequired {
                reason: "transaction envelope predates required v7 wire discriminator".to_owned(),
            })?;
    let version: ContractVersion = serde_json::from_value(version.clone()).map_err(|_| {
        InstallationError::MigrationRequired {
            reason: "transaction envelope has an unsupported wire discriminator".to_owned(),
        }
    })?;
    if version != INSTALLATION_TRANSACTION_WIRE_VERSION {
        return Err(InstallationError::MigrationRequired {
            reason: format!(
                "transaction envelope wire {version} requires explicit migration to {INSTALLATION_TRANSACTION_WIRE_VERSION}"
            ),
        });
    }
    let transaction_value =
        value
            .get("transaction")
            .ok_or_else(|| InstallationError::MigrationRequired {
                reason: "transaction envelope predates the required v7 payload".to_owned(),
            })?;
    let transaction_bytes = serde_json::to_vec(transaction_value).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: error.to_string(),
        }
    })?;
    let transaction = decode_installation_transaction_json(&transaction_bytes)?;
    let envelope: TransactionEnvelope =
        serde_json::from_value(value).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    if envelope.transaction != transaction {
        return Err(InstallationError::MigrationRequired {
            reason: "transaction payload did not round-trip through the v7 envelope".to_owned(),
        });
    }
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_TRANSACTION_TABLE: TableDefinition<&str, &[u8]> =
        TableDefinition::new("installation_transactions_v2");
    const V4_TRANSACTION_TABLE: TableDefinition<&str, &[u8]> =
        TableDefinition::new("installation_transactions_v3");
    const V5_TRANSACTION_TABLE: TableDefinition<&str, &[u8]> =
        TableDefinition::new("installation_transactions_v5");

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eliot-installation-transaction-{name}-{}.redb",
            std::process::id()
        ))
    }

    #[test]
    fn publication_conflict_never_overwrites_and_cleans_temporary() {
        let directory = std::env::temp_dir().join(format!(
            "eliot-installation-publication-conflict-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("create publication fixture directory: {error}"));
        let destination = directory.join("transaction.redb");
        let (publication, reserved) = PendingTransactionStorePublication::reserve(&destination)
            .unwrap_or_else(|error| panic!("reserve temporary: {error}"));
        drop(reserved);
        let temporary = publication.temporary().to_owned();
        let original = b"caller-owned-publish-conflict";
        fs::write(&destination, original)
            .unwrap_or_else(|error| panic!("create publication race: {error}"));

        assert!(publication.publish(&destination).is_err());
        let actual =
            fs::read(&destination).unwrap_or_else(|error| panic!("read conflict: {error}"));
        assert_eq!(actual.as_slice(), original);
        assert!(!temporary.exists(), "failed publication leaked temporary");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn legacy_transaction_record_requires_explicit_migration() {
        let path = test_path("legacy-v2");
        let _ = std::fs::remove_file(&path);
        let database =
            Database::create(&path).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("begin fixture write: {error}"));
        {
            let mut table = write
                .open_table(LEGACY_TRANSACTION_TABLE)
                .unwrap_or_else(|error| panic!("open fixture table: {error}"));
            table
                .insert(
                    "transaction:legacy",
                    br#"{"wire_version":{"major":2,"minor":0,"patch":0},"transaction":{"stage":"PLANNED"}}"#
                        .as_slice(),
                )
                .unwrap_or_else(|error| panic!("insert fixture: {error}"));
        }
        write
            .commit()
            .unwrap_or_else(|error| panic!("commit fixture: {error}"));
        drop(database);
        let store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
            .unwrap_or_else(|error| panic!("open fixture read-only: {error}"));
        let id = PlatformHandle::new("transaction:legacy")
            .unwrap_or_else(|error| panic!("fixture identity: {error}"));
        let result = store.load(&id);
        assert!(matches!(
            result,
            Err(InstallationError::MigrationRequired { .. })
        ));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v4_transaction_table_requires_explicit_migration() {
        let path = test_path("legacy-v4");
        let _ = std::fs::remove_file(&path);
        let database =
            Database::create(&path).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("begin fixture write: {error}"));
        {
            let mut table = write
                .open_table(V4_TRANSACTION_TABLE)
                .unwrap_or_else(|error| panic!("open v4 fixture table: {error}"));
            table
                .insert(
                    "transaction:v4",
                    br#"{"wire_version":{"major":4,"minor":0,"patch":0},"transaction":{}}"#
                        .as_slice(),
                )
                .unwrap_or_else(|error| panic!("insert v4 fixture: {error}"));
        }
        write
            .commit()
            .unwrap_or_else(|error| panic!("commit v4 fixture: {error}"));
        drop(database);
        let store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
            .unwrap_or_else(|error| panic!("open v4 fixture: {error}"));
        let id = PlatformHandle::new("transaction:v4")
            .unwrap_or_else(|error| panic!("fixture identity: {error}"));
        assert!(matches!(
            store.load(&id),
            Err(InstallationError::MigrationRequired { .. })
        ));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v5_transaction_table_requires_migration_before_payload_deserialization() {
        let path = test_path("legacy-v5");
        let _ = std::fs::remove_file(&path);
        let database =
            Database::create(&path).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("begin fixture write: {error}"));
        {
            let mut table = write
                .open_table(V5_TRANSACTION_TABLE)
                .unwrap_or_else(|error| panic!("open v5 fixture table: {error}"));
            table
                .insert(
                    "transaction:v5",
                    br#"{"wire_version":{"major":5,"minor":0,"patch":0},"transaction":{}}"#
                        .as_slice(),
                )
                .unwrap_or_else(|error| panic!("insert v5 fixture: {error}"));
        }
        write
            .commit()
            .unwrap_or_else(|error| panic!("commit v5 fixture: {error}"));
        drop(database);
        let store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
            .unwrap_or_else(|error| panic!("open v5 fixture: {error}"));
        let id = PlatformHandle::new("transaction:v5")
            .unwrap_or_else(|error| panic!("fixture identity: {error}"));
        assert!(matches!(
            store.load(&id),
            Err(InstallationError::MigrationRequired { reason })
                if reason.contains("installation_transactions_v7")
        ));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v5_transaction_envelope_requires_migration_before_payload_deserialization() {
        let bytes = br#"{"wire_version":{"major":5,"minor":0,"patch":0},"transaction":{}}"#;
        assert!(matches!(
            decode(bytes),
            Err(InstallationError::MigrationRequired { reason })
                if reason.contains("wire 5.0.0")
        ));
    }

    #[test]
    fn explicit_path_api_does_not_create_missing_parent() {
        let parent = std::env::temp_dir().join(format!(
            "eliot-installation-missing-parent-{}",
            std::process::id()
        ));
        let path = parent.join("transactions.redb");
        assert!(!parent.exists());
        assert!(RedbInstallationTransactionStore::create_at_exact_path(&path).is_err());
        assert!(!parent.exists());
    }

    #[test]
    fn open_existing_does_not_create_missing_file() {
        let path = test_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(RedbInstallationTransactionStore::open_existing_exact_path(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn open_existing_does_not_initialize_or_replace_an_empty_file() {
        let path = test_path("existing-empty-file");
        let _ = std::fs::remove_file(&path);
        std::fs::File::create(&path)
            .unwrap_or_else(|error| panic!("create empty fixture: {error}"));
        let canonical_before =
            std::fs::canonicalize(&path).unwrap_or_else(|error| panic!("canonicalize: {error}"));
        let metadata_before =
            std::fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));
        let bytes_before =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read fixture: {error}"));

        assert!(RedbInstallationTransactionStore::open_existing_exact_path(&path).is_err());

        let canonical_after =
            std::fs::canonicalize(&path).unwrap_or_else(|error| panic!("canonicalize: {error}"));
        let metadata_after =
            std::fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));
        let bytes_after =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read fixture: {error}"));
        assert_eq!(canonical_after, canonical_before);
        assert_eq!(metadata_after.len(), metadata_before.len());
        assert_eq!(
            metadata_after.created().ok(),
            metadata_before.created().ok()
        );
        assert_eq!(bytes_after, bytes_before);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn genuinely_empty_redb_store_loads_as_empty() {
        let path = test_path("empty-redb");
        let _ = std::fs::remove_file(&path);
        let store = RedbInstallationTransactionStore::create_at_exact_path(&path)
            .unwrap_or_else(|error| panic!("create empty store: {error}"));
        drop(store);
        let store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
            .unwrap_or_else(|error| panic!("open empty store read-only: {error}"));
        let id = PlatformHandle::new("transaction:absent")
            .unwrap_or_else(|error| panic!("fixture identity: {error}"));
        assert_eq!(
            store
                .load(&id)
                .unwrap_or_else(|error| panic!("load empty store: {error}")),
            None
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
