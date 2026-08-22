//! Explicit-path redb persistence for durable installer transactions.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{
    ActivationCommitReceipt, INSTALLATION_TRANSACTION_WIRE_VERSION, InstallationError,
    InstallationStage, InstallationStepOutcome, InstallationTransaction,
    InstallationTransactionStore, decode_installation_transaction_json_from_store,
    transaction_store_private::{self, TransactionVersion},
};
use eliot_contracts::ContractVersion;
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    FileIdentity, delete_owned_file_handle, file_identity_for_open_handle,
    open_no_follow_directory, open_no_follow_file, open_no_follow_file_for_delete,
};

const TRANSACTION_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("installation_transactions_v7");
const TRANSACTION_TEMP_CREATE_ATTEMPTS: usize = 16;
static NEXT_TRANSACTION_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
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
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(existing_path_error()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        }
        let database = Database::create(path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        drop(database);
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Creates and atomically publishes a new exact-path database containing
    /// one planned constructor-produced transaction in its versioned table.
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
                reason: "create_planned accepts only constructor-produced Planned/Pending v9 state"
                    .to_owned(),
            });
        }
        let path = path.as_ref();
        require_existing_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(existing_path_error()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        }

        let mut publication = PendingTransactionStorePublication::reserve(path)?;
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
        publication.retain_written_temporary()?;
        publication
            .publish(path, transaction)
            .map_err(|error| match error {
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
        #[cfg(windows)]
        let parent = retain_transaction_directory(path.parent().ok_or_else(|| {
            InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "path must have a parent".to_owned(),
            }
        })?)?;
        #[cfg(windows)]
        let (identity, file) =
            open_no_follow_file(path).map_err(|error| InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: format!("existing regular non-reparse file required: {error}"),
            })?;
        #[cfg(windows)]
        let expected_identity = identity;
        #[cfg(windows)]
        verify_transaction_parent(&parent)?;
        let database = ReadOnlyDatabase::open(path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        drop(database);
        #[cfg(windows)]
        {
            let readback_identity = file_identity_for_open_handle(&file).map_err(|error| {
                InstallationError::InvalidField {
                    field: "transaction_store.path".to_owned(),
                    reason: format!("existing file identity readback failed: {error}"),
                }
            })?;
            if readback_identity != expected_identity {
                return Err(InstallationError::IdentityConflict);
            }
        }
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
    #[cfg(windows)]
    parent: RetainedTransactionDirectory,
    #[cfg(windows)]
    temporary_file: Option<RetainedTransactionFile>,
}

#[cfg(windows)]
struct RetainedTransactionDirectory {
    identity: FileIdentity,
    _file: File,
}

#[cfg(windows)]
struct RetainedTransactionFile {
    identity: FileIdentity,
    file: File,
}

impl PendingTransactionStorePublication {
    fn reserve(destination: &Path) -> Result<Self, InstallationError> {
        let directory = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| InstallationError::InvalidField {
                field: "transaction_store.path".to_owned(),
                reason: "exact path must name a file".to_owned(),
            })?;
        #[cfg(windows)]
        let parent = retain_transaction_directory(directory)?;
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
            #[cfg(windows)]
            let result = eliot_platform_windows::create_no_follow_file_for_delete(&temporary)
                .map_err(|error| InstallationError::Platform(error.to_string()));
            #[cfg(not(windows))]
            let result = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map(|file| {
                    (
                        FileIdentity {
                            volume_serial_number: 0,
                            file_index: 0,
                        },
                        file,
                    )
                })
                .map_err(|error| InstallationError::Platform(error.to_string()));
            match result {
                Ok((identity, file)) => {
                    return Ok(Self {
                        temporary: temporary.clone(),
                        #[cfg(windows)]
                        parent,
                        #[cfg(windows)]
                        temporary_file: Some(RetainedTransactionFile { identity, file }),
                    });
                }
                Err(InstallationError::Platform(reason))
                    if reason.contains("already exists") || reason.contains("AlreadyExists") => {}
                Err(error) => return Err(error),
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

    fn retain_written_temporary(&mut self) -> Result<(), InstallationError> {
        #[cfg(windows)]
        {
            verify_transaction_parent(&self.parent)?;
            let retained =
                self.temporary_file
                    .as_ref()
                    .ok_or(InstallationError::UnknownOutcome {
                        stage: InstallationStage::Planned,
                    })?;
            verify_retained_transaction_file(retained)?;
        }
        Ok(())
    }

    fn publish(
        mut self,
        destination: &Path,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        #[cfg(windows)]
        {
            verify_transaction_parent(&self.parent)?;
            let retained =
                self.temporary_file
                    .as_ref()
                    .ok_or(InstallationError::UnknownOutcome {
                        stage: InstallationStage::Planned,
                    })?;
            verify_retained_transaction_file(retained)?;
        }
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
        if sync_parent_directory(directory).is_err() {
            return Err(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            });
        }
        let expected_bytes = encode(transaction)?;
        verify_published_transaction(destination, &transaction.transaction_id, &expected_bytes)?;
        #[cfg(windows)]
        {
            let retained = self
                .temporary_file
                .take()
                .ok_or(InstallationError::UnknownOutcome {
                    stage: InstallationStage::Planned,
                })?;
            if delete_owned_file_handle(retained.file, retained.identity).is_err() {
                return Err(InstallationError::UnknownOutcome {
                    stage: InstallationStage::Planned,
                });
            }
        }
        sync_parent_directory(directory).map_err(|_| InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })
    }
}

impl Drop for PendingTransactionStorePublication {
    fn drop(&mut self) {
        // Never delete by pathname from Drop: after a failed create-only
        // publication the name may have been substituted.  The retained
        // Windows handle is consumed only after exact identity/content
        // readback in publish; otherwise the temporary remains recoverable.
    }
}

#[cfg(windows)]
fn retain_transaction_directory(
    path: &Path,
) -> Result<RetainedTransactionDirectory, InstallationError> {
    let (identity, file) =
        open_no_follow_directory(path).map_err(|error| InstallationError::InvalidField {
            field: "transaction_store.path".to_owned(),
            reason: format!("existing non-reparse parent directory required: {error}"),
        })?;
    Ok(RetainedTransactionDirectory {
        identity,
        _file: file,
    })
}

#[cfg(windows)]
fn verify_transaction_parent(
    parent: &RetainedTransactionDirectory,
) -> Result<(), InstallationError> {
    let identity = file_identity_for_open_handle(&parent._file).map_err(|_| {
        InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        }
    })?;
    if identity != parent.identity {
        return Err(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        });
    }
    Ok(())
}

#[cfg(windows)]
fn verify_retained_transaction_file(
    retained: &RetainedTransactionFile,
) -> Result<(), InstallationError> {
    let identity = file_identity_for_open_handle(&retained.file).map_err(|_| {
        InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        }
    })?;
    if identity != retained.identity {
        return Err(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        });
    }
    Ok(())
}

fn verify_published_transaction(
    destination: &Path,
    expected_transaction_id: &PlatformHandle,
    expected_bytes: &[u8],
) -> Result<(), InstallationError> {
    #[cfg(windows)]
    let (published_identity, published_file) = open_no_follow_file_for_delete(destination)
        .map_err(|_| InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
    let store = RedbInstallationTransactionStore {
        path: destination.to_path_buf(),
    };
    let actual = store
        .load(expected_transaction_id)
        .map_err(|_| InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?
        .ok_or(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
    let actual_bytes = encode(&actual).map_err(|_| InstallationError::UnknownOutcome {
        stage: InstallationStage::Planned,
    })?;
    let expected_digest = format!("{:x}", Sha256::digest(expected_bytes));
    let actual_digest = format!("{:x}", Sha256::digest(&actual_bytes));
    if actual_bytes != expected_bytes || actual_digest != expected_digest {
        return Err(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        });
    }
    #[cfg(windows)]
    {
        let identity = file_identity_for_open_handle(&published_file).map_err(|_| {
            InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            }
        })?;
        if identity != published_identity
            || published_identity.volume_serial_number == 0
            || published_identity.file_index == 0
        {
            return Err(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            });
        }
        drop(published_file);
    }
    Ok(())
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
                reason: "create_planned accepts only constructor-produced Planned/Pending v9 state"
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

    fn reconcile_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let mut transaction = self.load(&receipt.transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: receipt.transaction_id.as_str().to_owned(),
            }
        })?;
        transaction.validate()?;
        match transaction.stage() {
            InstallationStage::ActiveVerified
            | InstallationStage::Cleaning
            | InstallationStage::Completed => {
                let binding = transaction
                    .active_verified_receipt
                    .as_ref()
                    .ok_or_else(|| {
                        InstallationError::IncompleteObservation(
                            "active transaction is missing its committed activation receipt"
                                .to_owned(),
                        )
                    })?;
                if !binding.matches_receipt(&receipt) {
                    return Err(InstallationError::IdentityConflict);
                }
                Ok(InstallationStepOutcome::Applied {
                    stage: transaction.stage(),
                    evidence_refs: transaction.observed_postconditions.clone(),
                })
            }
            InstallationStage::Activating => {
                let expected = TransactionVersion::of(&transaction)?;
                transaction.advance_to_active_verified(receipt, evidence)?;
                <Self as transaction_store_private::Sealed>::compare_and_save(
                    self,
                    expected,
                    &transaction,
                )?;
                Ok(InstallationStepOutcome::Applied {
                    stage: transaction.stage(),
                    evidence_refs: transaction.observed_postconditions.clone(),
                })
            }
            InstallationStage::Planned
            | InstallationStage::Staging
            | InstallationStage::StaticVerified
            | InstallationStage::Registering => Err(InstallationError::IncompleteObservation(
                "activation terminal cannot advance a transaction before Activating".to_owned(),
            )),
            InstallationStage::RollbackRequired
            | InstallationStage::RolledBack
            | InstallationStage::Quarantined => Err(InstallationError::IncompleteObservation(
                "activation terminal cannot reconcile a pending, aborted, or unknown transaction"
                    .to_owned(),
            )),
        }
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
                reason: "transaction envelope predates the required transaction wire discriminator"
                    .to_owned(),
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
                reason: "transaction envelope predates the required transaction payload".to_owned(),
            })?;
    let transaction_bytes = serde_json::to_vec(transaction_value).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: error.to_string(),
        }
    })?;
    let transaction = decode_installation_transaction_json_from_store(&transaction_bytes)?;
    let canonical_transaction =
        serde_json::to_value(&transaction).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    if transaction_value != &canonical_transaction {
        return Err(InstallationError::MigrationRequired {
            reason: "transaction payload did not round-trip through the current envelope"
                .to_owned(),
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
        let publication = PendingTransactionStorePublication::reserve(&destination)
            .unwrap_or_else(|error| panic!("reserve temporary: {error}"));
        let temporary = publication.temporary().to_owned();
        let original = b"caller-owned-publish-conflict";
        fs::write(&destination, original)
            .unwrap_or_else(|error| panic!("create publication race: {error}"));

        assert!(fs::hard_link(&temporary, &destination).is_err());
        let actual =
            fs::read(&destination).unwrap_or_else(|error| panic!("read conflict: {error}"));
        assert_eq!(actual.as_slice(), original);
        drop(publication);
        assert!(
            temporary.exists(),
            "failed publication must remain quarantined"
        );
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_dir_all(&directory);
    }

    #[cfg(windows)]
    #[test]
    fn create_planned_rejects_reparse_parent_before_publication() {
        let root = std::env::temp_dir().join(format!(
            "eliot-installation-reparse-parent-{}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "eliot-installation-reparse-parent-outside-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create root: {error}"));
        fs::create_dir(&outside).unwrap_or_else(|error| panic!("create outside: {error}"));
        let parent = root.join("parent");
        let link = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&parent)
            .arg(&outside)
            .output()
            .unwrap_or_else(|error| panic!("launch mklink: {error}"));
        if !link.status.success() {
            let _ = fs::remove_dir_all(&root);
            let _ = fs::remove_dir_all(&outside);
            return;
        }
        let result = retain_transaction_directory(&parent);
        assert!(result.is_err());
        assert!(!outside.join("transaction.redb").exists());
        let _ = fs::remove_dir(&parent);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn published_transaction_readback_requires_exact_content_as_unknown() {
        let path = test_path("postcommit-content-mismatch");
        let _ = fs::remove_file(&path);
        let database = Database::create(&path)
            .unwrap_or_else(|error| panic!("create readback fixture: {error}"));
        drop(database);
        let expected_transaction_id = PlatformHandle::new("transaction:postcommit-mismatch")
            .unwrap_or_else(|error| panic!("create transaction id fixture: {error}"));
        let expected = br#"exact-serialized-transaction-bytes"#;
        assert!(matches!(
            verify_published_transaction(&path, &expected_transaction_id, expected),
            Err(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned
            })
        ));
        let _ = fs::remove_file(path);
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
