//! Explicit-path redb persistence for durable installer transactions.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::package_planner::REQUIRED_PACKAGE_ROLES as SOURCE_BUNDLE_REQUIRED_ROLES;
use super::{
    ActivationCommitReceipt, GenerationPackagePlanner, INSTALLATION_TRANSACTION_WIRE_VERSION,
    InstallationError, InstallationStage, InstallationStepOutcome, InstallationTransaction,
    InstallationTransactionStore, InstallerEffectPlan, PackageArtifactDigest,
    decode_installation_transaction_json_from_store,
    transaction_store_private::{self, TransactionVersion},
};
use eliot_contracts::ContractVersion;
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    AuthenticodeEvidence, AuthenticodeVerdict, AuthenticodeVerifier, DirectoryPublicationReceipt,
    FileIdentity, OwnedDirectoryPublication, PackageFileSpec, PackageManifest, PeCoffEvidence,
    TrustedSourceBundle, WindowsAuthenticodeVerifier, canonical_windows_path,
    delete_owned_file_handle, file_identity_for_open_handle, open_no_follow_directory,
    open_no_follow_file, validate_package_relative_path, windows_paths_equal,
};

const TRANSACTION_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("installation_transactions_v7");
const PUBLICATION_JOURNAL_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("source_bundle_publication_journal_v1");
const TRANSACTION_TEMP_CREATE_ATTEMPTS: usize = 16;
static NEXT_TRANSACTION_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Typed durable state of one source-bundle directory publication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceBundlePublicationJournalState {
    /// Intent was persisted and read back before the native directory move.
    Intent,
    /// The move and exact destination readback completed.
    Published,
    /// The move may have completed, but the caller must reconcile the exact
    /// operation before planning or retrying it.
    CommittedUnknown,
}

/// Durable source-bundle publication journal bound to one exact transaction,
/// output path and complete precommit inventory digest.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundlePublicationJournal {
    /// Explicit journal wire discriminator.
    pub wire_version: u32,
    /// Deterministic operation identity used for exact replay.
    pub operation_id: PlatformHandle,
    /// Planned installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Exact destination bundle path.
    pub output_bundle: PathBuf,
    /// Canonical same-parent temporary directory retained before the move.
    pub temporary_path: PathBuf,
    /// Exact relative temporary leaf below the retained destination parent.
    pub temporary_name: String,
    /// Identity of the retained destination parent before the move.
    pub parent_identity: FileIdentity,
    /// Candidate generation identity.
    pub generation: PlatformHandle,
    /// Canonical package manifest digest.
    pub manifest_digest: PlatformHandle,
    /// Complete nine-role artifact evidence digest.
    pub evidence_digest: PlatformHandle,
    /// Digest of the complete typed precommit role inventory.
    pub precommit_digest: PlatformHandle,
    /// Complete typed role inventory retained for destination-only restart
    /// reconciliation. This is the journal's authority evidence; a retry
    /// must not reopen the original source bundle to reconstruct it.
    pub precommit_files: Vec<SourceBundlePublicationRole>,
    /// Identity of the owned temporary publication directory.
    pub source_identity: FileIdentity,
    /// Durable operation state.
    pub state: SourceBundlePublicationJournalState,
    /// Exact destination identity after a successful move/readback.
    pub destination_identity: Option<FileIdentity>,
    /// Complete native publication receipt, retained for restart recovery.
    pub directory_receipt: Option<DirectoryPublicationReceipt>,
    /// Bounded operator diagnostic for an unknown outcome.
    pub diagnostic: Option<String>,
}

/// One source-bundle role fact retained in the durable publication journal.
///
/// The fact is intentionally independent of the source pathname. It lets a
/// restart reconstruct the exact published receipt from the durable journal
/// and a destination-only readback, even when the original release files were
/// removed or changed.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundlePublicationRole {
    /// Canonical nine-role relative path.
    pub relative_path: String,
    /// Whether this role is an executable PE.
    pub executable: bool,
    /// Exact bytes measured before the move.
    pub size: u64,
    /// Lowercase SHA-256 of the exact bytes measured before the move.
    pub sha256: PlatformHandle,
    /// Identity of the caller-supplied release file, or generated role.
    pub source_identity: FileIdentity,
    /// Identity of the role in the owned temporary tree.
    pub temporary_identity: FileIdentity,
    /// PE evidence for executable roles.
    pub pe: Option<PeCoffEvidence>,
    /// Authenticode evidence for executable roles.
    pub authenticode: Option<AuthenticodeEvidence>,
}

/// Current source-bundle publication journal wire version.
pub const SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION: u32 = 3;

/// Derive the stable operation key for one exact source-bundle publication.
pub fn source_bundle_publication_operation_id(
    transaction_id: &PlatformHandle,
    output_bundle: &Path,
    generation: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(eliot_contracts::sha256_hex(
        &serde_json::to_vec(&(
            "eliot-source-bundle-publication-v1",
            transaction_id,
            output_bundle,
            generation,
        ))
        .map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?,
    ))
    .map_err(|error| InstallationError::InvalidField {
        field: "publication.operation_id".to_owned(),
        reason: error.to_string(),
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationJournalEnvelope {
    wire_version: u32,
    journal: SourceBundlePublicationJournal,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionEnvelope {
    wire_version: ContractVersion,
    transaction: InstallationTransaction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedTransactionEnvelope {
    wire_version: ContractVersion,
    transaction: serde_json::Value,
}

/// Production redb transaction store rooted at one caller-selected exact path.
pub struct RedbInstallationTransactionStore {
    path: PathBuf,
    #[cfg(windows)]
    parent: RetainedTransactionDirectory,
    #[cfg(windows)]
    file: RetainedTransactionFile,
    #[cfg(test)]
    allow_unpublished_stage_fixture: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationJournalStoreFault {
    None,
    #[cfg(test)]
    AfterTemporaryCreateBeforeInsert,
    #[cfg(test)]
    AfterJournalCommitBeforePublish,
    #[cfg(test)]
    AfterFinalPublishBeforeResponse,
}

impl RedbInstallationTransactionStore {
    /// Persist and read back a source-bundle publication intent in the exact
    /// caller-selected store before any native directory move occurs.
    pub fn begin_source_bundle_publication_at_exact_path(
        path: impl AsRef<Path>,
        journal: &SourceBundlePublicationJournal,
    ) -> Result<SourceBundlePublicationJournal, InstallationError> {
        Self::begin_source_bundle_publication_with_fault(
            path.as_ref(),
            journal,
            PublicationJournalStoreFault::None,
        )
    }

    #[cfg(test)]
    fn begin_source_bundle_publication_at_exact_path_with_fault(
        path: impl AsRef<Path>,
        journal: &SourceBundlePublicationJournal,
        fault: PublicationJournalStoreFault,
    ) -> Result<SourceBundlePublicationJournal, InstallationError> {
        Self::begin_source_bundle_publication_with_fault(path.as_ref(), journal, fault)
    }

    fn begin_source_bundle_publication_with_fault(
        path: &Path,
        journal: &SourceBundlePublicationJournal,
        fault: PublicationJournalStoreFault,
    ) -> Result<SourceBundlePublicationJournal, InstallationError> {
        validate_publication_journal(journal)?;
        if journal.state != SourceBundlePublicationJournalState::Intent {
            return Err(InstallationError::InvalidField {
                field: "publication.state".to_owned(),
                reason: "begin accepts only an Intent journal".to_owned(),
            });
        }
        require_existing_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {
                let store = Self::open_existing_exact_path(path)?;
                let current = store
                    .load_source_bundle_publication(&journal.operation_id)?
                    .ok_or_else(|| InstallationError::MigrationRequired {
                        reason: "existing store has no matching source publication journal"
                            .to_owned(),
                    })?;
                validate_publication_journal(&current)?;
                if !publication_journal_identity_matches(&current, journal) {
                    return Err(InstallationError::IdentityConflict);
                }
                match current.state {
                    SourceBundlePublicationJournalState::Intent => {
                        verify_publication_intent(&current)?;
                    }
                    SourceBundlePublicationJournalState::Published => {
                        verify_published_source_bundle_journal_live(&current)?;
                    }
                    SourceBundlePublicationJournalState::CommittedUnknown => {}
                }
                Ok(current)
            }
            Ok(_) => Err(existing_path_error()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                verify_publication_intent(journal)?;
                begin_new_source_bundle_publication_store(path, journal, fault)
            }
            Err(error) => Err(InstallationError::Platform(error.to_string())),
        }
    }

    /// Read one exact durable source-bundle publication journal.
    pub fn load_source_bundle_publication(
        &self,
        operation_id: &PlatformHandle,
    ) -> Result<Option<SourceBundlePublicationJournal>, InstallationError> {
        let database = self.open_read_only()?;
        read_publication_journal(&database, operation_id)
    }

    /// Load and independently verify one exact durable `Published` source
    /// bundle before a caller treats its receipt as authority.
    ///
    /// This is the only public read boundary that promotes a publication row
    /// to authoritative materialized state. It reuses the central live
    /// verifier, including sealed `WinTrust` verification of all six executable
    /// identities and hashes.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the operation is absent, is not durably
    /// `Published`, or any filesystem, identity, digest, manifest, receipt, or
    /// Authenticode readback differs from the journal.
    pub fn load_verified_published_source_bundle_publication(
        &self,
        operation_id: &PlatformHandle,
    ) -> Result<SourceBundlePublicationJournal, InstallationError> {
        let journal = self
            .load_source_bundle_publication(operation_id)?
            .ok_or_else(|| InstallationError::TransactionNotFound {
                transaction_id: operation_id.as_str().to_owned(),
            })?;
        verify_published_source_bundle_journal_live(&journal)?;
        Ok(journal)
    }

    /// Corrupt one publication fixture with fixed stale signer evidence.
    ///
    /// This deliberately narrow seam exists only in the non-default
    /// `test-support` feature so downstream tests can prove that legacy or
    /// forged durable rows are not adopted. It accepts no evidence or verifier
    /// from the caller and is absent from the production feature tree.
    ///
    /// # Errors
    ///
    /// Returns a typed error unless the exact operation exists in `Intent` or
    /// `Published` state with an executable role and the fixed corruption is
    /// durably read back.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn corrupt_source_bundle_authenticode_fixture(
        &self,
        operation_id: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let database = self.open_for_mutation()?;
        let mut journal = read_publication_journal(&database, operation_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: operation_id.as_str().to_owned(),
            }
        })?;
        if !matches!(
            journal.state,
            SourceBundlePublicationJournalState::Intent
                | SourceBundlePublicationJournalState::Published
        ) {
            return Err(InstallationError::IdentityConflict);
        }
        let evidence = journal
            .precommit_files
            .iter_mut()
            .find(|role| role.executable)
            .and_then(|role| role.authenticode.as_mut())
            .ok_or(InstallationError::IdentityConflict)?;
        evidence.signer_subject = Some("ELIOT forged stale Valid fixture".to_owned());
        journal.precommit_digest = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&journal.precommit_files).map_err(|error| {
                    InstallationError::CorruptRegistry {
                        reason: error.to_string(),
                    }
                })?
            )
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "publication.precommit_digest".to_owned(),
            reason: error.to_string(),
        })?;
        write_publication_journal(&database, &journal)?;
        drop(database);
        let reopened = Self::open_existing_exact_path(&self.path)?;
        let recorded = reopened
            .load_source_bundle_publication(operation_id)?
            .ok_or(InstallationError::IdentityConflict)?;
        if recorded != journal {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Advance a publication journal after the native move.  The operation
    /// identity is immutable and a second move is never authorized by this
    /// method; only `INTENT -> PUBLISHED/COMMITTED_UNKNOWN` and
    /// `COMMITTED_UNKNOWN -> PUBLISHED` are accepted.
    pub fn record_source_bundle_publication(
        &self,
        journal: &SourceBundlePublicationJournal,
    ) -> Result<SourceBundlePublicationJournal, InstallationError> {
        validate_publication_journal(journal)?;
        if journal.state == SourceBundlePublicationJournalState::Published {
            verify_published_source_bundle_journal_live(journal)?;
        }
        let database = self.open_for_mutation()?;
        compare_and_write_publication_journal(&database, journal)?;
        drop(database);
        let reopened = Self::open_existing_exact_path(&self.path)?;
        let recorded = reopened
            .load_source_bundle_publication(&journal.operation_id)?
            .ok_or(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            })?;
        if recorded.state == SourceBundlePublicationJournalState::Published {
            verify_published_source_bundle_journal_live(&recorded)?;
        }
        Ok(recorded)
    }

    /// Creates a new database at `path` without creating its parent directory.
    #[cfg(test)]
    pub(crate) fn create_at_exact_path(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
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
        Self::open_existing_exact_path(path)
    }

    /// Test-only raw fixture seam for legacy state-machine tests whose
    /// synthetic `StagePackage` paths intentionally have no live package.
    /// Production builds do not contain this bypass.
    #[cfg(test)]
    pub(crate) fn create_unpublished_stage_fixture_at_exact_path(
        path: impl AsRef<Path>,
        transaction: &InstallationTransaction,
    ) -> Result<Self, InstallationError> {
        transaction.validate()?;
        if !transaction.is_constructor_planned() {
            return Err(InstallationError::InvalidField {
                field: "transaction".to_owned(),
                reason: "fixture create accepts only constructor-produced planned state".to_owned(),
            });
        }
        let mut store = Self::create_at_exact_path(path)?;
        let database = store.open_for_mutation()?;
        insert_planned(&database, transaction)?;
        drop(database);
        store.allow_unpublished_stage_fixture = true;
        Ok(store)
    }

    /// Reopens an explicit test-only raw `StagePackage` fixture.
    #[cfg(test)]
    pub(crate) fn open_unpublished_stage_fixture_exact_path(
        path: impl AsRef<Path>,
    ) -> Result<Self, InstallationError> {
        let mut store = Self::open_existing_exact_path(path)?;
        store.allow_unpublished_stage_fixture = true;
        Ok(store)
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
                reason:
                    "create_planned accepts only constructor-produced Planned/Pending v23 state"
                        .to_owned(),
            });
        }
        let path = path.as_ref();
        require_existing_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {
                let store = Self::open_existing_exact_path(path)?;
                require_publication_for_stage_package(&store, transaction)?;
                let database = store.open_for_mutation()?;
                insert_planned(&database, transaction)?;
                return Ok(store);
            }
            Ok(_) => return Err(existing_path_error()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        }

        if transaction_has_stage_package(transaction) {
            return Err(InstallationError::MigrationRequired {
                reason: "StagePackage admission requires a pre-existing verified Published source publication journal"
                    .to_owned(),
            });
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
        let reopened = Self::open_existing_exact_path(path).map_err(|error| match error {
            InstallationError::Platform(reason) => {
                InstallationError::Platform(format!("published reopen: {reason}"))
            }
            other => other,
        })?;
        Ok(reopened)
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
        #[cfg(windows)]
        let file = RetainedTransactionFile {
            identity: expected_identity,
            file,
        };
        Ok(Self {
            path: path.to_path_buf(),
            #[cfg(windows)]
            parent,
            #[cfg(windows)]
            file,
            #[cfg(test)]
            allow_unpublished_stage_fixture: false,
        })
    }

    fn open_read_only(&self) -> Result<ReadOnlyDatabase, InstallationError> {
        self.verify_bound_path()?;
        ReadOnlyDatabase::open(&self.path)
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }

    fn open_for_mutation(&self) -> Result<Database, InstallationError> {
        self.verify_bound_path()?;
        Database::open(&self.path).map_err(|error| InstallationError::Platform(error.to_string()))
    }

    fn verify_bound_path(&self) -> Result<(), InstallationError> {
        #[cfg(windows)]
        {
            verify_transaction_parent(&self.parent)?;
            verify_retained_transaction_file(&self.file)?;
            let (identity, file) =
                open_no_follow_file(&self.path).map_err(|_| InstallationError::UnknownOutcome {
                    stage: InstallationStage::Planned,
                })?;
            if identity != self.file.identity {
                return Err(InstallationError::IdentityConflict);
            }
            drop(file);
        }
        Ok(())
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
    file: File,
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
        #[cfg(windows)]
        let expected_identity = self
            .temporary_file
            .as_ref()
            .ok_or(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            })?
            .identity;
        verify_published_transaction(
            destination,
            &transaction.transaction_id,
            &expected_bytes,
            #[cfg(windows)]
            Some(expected_identity),
            #[cfg(not(windows))]
            None,
        )?;
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

    fn publish_publication_journal(
        mut self,
        destination: &Path,
        journal: &SourceBundlePublicationJournal,
        fault: PublicationJournalStoreFault,
    ) -> Result<(), InstallationError> {
        #[cfg(not(test))]
        let _ = fault;
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
        sync_parent_directory(directory).map_err(|_| InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
        #[cfg(windows)]
        let expected_identity = self
            .temporary_file
            .as_ref()
            .ok_or(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            })?
            .identity;
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
        })?;
        verify_published_publication_journal(
            destination,
            journal,
            #[cfg(windows)]
            Some(expected_identity),
            #[cfg(not(windows))]
            None,
        )?;
        #[cfg(test)]
        if fault == PublicationJournalStoreFault::AfterFinalPublishBeforeResponse {
            return Err(injected_publication_store_fault(
                "after final publication before response",
            ));
        }
        Ok(())
    }
}

fn begin_new_source_bundle_publication_store(
    destination: &Path,
    journal: &SourceBundlePublicationJournal,
    fault: PublicationJournalStoreFault,
) -> Result<SourceBundlePublicationJournal, InstallationError> {
    let mut publication = PendingTransactionStorePublication::reserve(destination)?;
    #[cfg(test)]
    if fault == PublicationJournalStoreFault::AfterTemporaryCreateBeforeInsert {
        return Err(injected_publication_store_fault(
            "after temporary create before journal insert",
        ));
    }
    #[cfg(windows)]
    let database = Database::builder()
        .create_file(
            publication
                .temporary_file
                .as_ref()
                .ok_or(InstallationError::UnknownOutcome {
                    stage: InstallationStage::Planned,
                })?
                .file
                .try_clone()
                .map_err(|error| {
                    InstallationError::Platform(format!("temporary handle clone: {error}"))
                })?,
        )
        .map_err(|error| InstallationError::Platform(format!("temporary create: {error}")))?;
    #[cfg(not(windows))]
    let database = Database::create(publication.temporary())
        .map_err(|error| InstallationError::Platform(format!("temporary create: {error}")))?;
    insert_publication_journal(&database, journal).map_err(|error| match error {
        InstallationError::Platform(reason) => {
            InstallationError::Platform(format!("temporary journal populate: {reason}"))
        }
        other => other,
    })?;
    #[cfg(windows)]
    publication
        .temporary_file
        .as_ref()
        .ok_or(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?
        .file
        .sync_all()
        .map_err(|error| InstallationError::Platform(format!("temporary sync: {error}")))?;
    #[cfg(not(windows))]
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(publication.temporary())
        .and_then(|file| file.sync_all())
        .map_err(|error| InstallationError::Platform(format!("temporary sync: {error}")))?;
    verify_publication_journal_database(&database, journal)?;
    drop(database);
    publication.retain_written_temporary()?;
    #[cfg(not(windows))]
    verify_published_publication_journal(publication.temporary(), journal, None)?;
    #[cfg(test)]
    if fault == PublicationJournalStoreFault::AfterJournalCommitBeforePublish {
        return Err(injected_publication_store_fault(
            "after journal commit before final publication",
        ));
    }
    publication.publish_publication_journal(destination, journal, fault)?;
    let store = RedbInstallationTransactionStore::open_existing_exact_path(destination)?;
    let recorded = store
        .load_source_bundle_publication(&journal.operation_id)?
        .ok_or(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
    if recorded != *journal {
        return Err(InstallationError::IdentityConflict);
    }
    verify_publication_intent(&recorded)?;
    Ok(recorded)
}

fn verify_publication_journal_database(
    database: &impl ReadableDatabase,
    expected: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    let actual = read_publication_journal(database, &expected.operation_id)?.ok_or(
        InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        },
    )?;
    if actual != *expected {
        return Err(InstallationError::IdentityConflict);
    }
    verify_publication_intent(&actual)
}

fn verify_published_publication_journal(
    path: &Path,
    expected: &SourceBundlePublicationJournal,
    expected_identity: Option<FileIdentity>,
) -> Result<(), InstallationError> {
    #[cfg(windows)]
    let (published_identity, published_file) =
        open_no_follow_file(path).map_err(|_| InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
    #[cfg(windows)]
    if expected_identity != Some(published_identity) {
        return Err(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        });
    }
    let store = RedbInstallationTransactionStore::open_existing_exact_path(path).map_err(|_| {
        InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        }
    })?;
    let actual = store
        .load_source_bundle_publication(&expected.operation_id)?
        .ok_or(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
    if actual != *expected {
        return Err(InstallationError::IdentityConflict);
    }
    verify_publication_intent(&actual)?;
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
    }
    #[cfg(not(windows))]
    let _ = expected_identity;
    Ok(())
}

#[cfg(test)]
fn injected_publication_store_fault(boundary: &str) -> InstallationError {
    InstallationError::Platform(format!(
        "injected source publication journal store fault {boundary}"
    ))
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
    Ok(RetainedTransactionDirectory { identity, file })
}

#[cfg(windows)]
fn verify_transaction_parent(
    parent: &RetainedTransactionDirectory,
) -> Result<(), InstallationError> {
    let identity = file_identity_for_open_handle(&parent.file).map_err(|_| {
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
    expected_identity: Option<FileIdentity>,
) -> Result<(), InstallationError> {
    #[cfg(windows)]
    let (published_identity, published_file) =
        open_no_follow_file(destination).map_err(|_| InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        })?;
    #[cfg(windows)]
    if expected_identity != Some(published_identity) {
        return Err(InstallationError::UnknownOutcome {
            stage: InstallationStage::Planned,
        });
    }
    let store =
        RedbInstallationTransactionStore::open_existing_exact_path(destination).map_err(|_| {
            InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            }
        })?;
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
    let actual_digest = format!("{:x}", Sha256::digest(actual_bytes.as_slice()));
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
                reason:
                    "create_planned accepts only constructor-produced Planned/Pending v23 state"
                        .to_owned(),
            });
        }
        require_publication_for_stage_package(self, transaction)?;
        let database = self.open_for_mutation()?;
        insert_planned(&database, transaction)
    }

    fn load(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<Option<InstallationTransaction>, InstallationError> {
        let bytes = {
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
            value.value().to_vec()
        };
        let transaction = decode(&bytes)?;
        if transaction.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        require_publication_for_stage_package(self, &transaction)?;
        Ok(Some(transaction))
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
        require_publication_for_stage_package(self, transaction)?;
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

#[expect(
    clippy::too_many_lines,
    reason = "W3-02 will extract the publication journal capability cell"
)]
fn validate_publication_journal(
    journal: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    if journal.wire_version != SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION
        || !journal.output_bundle.is_absolute()
        || !journal.temporary_path.is_absolute()
        || journal.output_bundle.to_str().is_none()
        || journal.temporary_path.to_str().is_none()
        || journal.parent_identity.volume_serial_number == 0
        || journal.parent_identity.file_index == 0
        || journal.source_identity.volume_serial_number == 0
        || journal.source_identity.file_index == 0
    {
        return Err(InstallationError::InvalidField {
            field: "publication.journal".to_owned(),
            reason: "invalid publication journal identity or path".to_owned(),
        });
    }
    for (value, field) in [
        (&journal.operation_id, "publication.operation_id"),
        (&journal.transaction_id, "publication.transaction_id"),
        (&journal.generation, "publication.generation"),
        (&journal.manifest_digest, "publication.manifest_digest"),
        (&journal.evidence_digest, "publication.evidence_digest"),
        (&journal.precommit_digest, "publication.precommit_digest"),
    ] {
        if value.as_str().is_empty() {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "publication journal handle cannot be blank".to_owned(),
            });
        }
    }
    for (value, field) in [
        (&journal.manifest_digest, "publication.manifest_digest"),
        (&journal.evidence_digest, "publication.evidence_digest"),
        (&journal.precommit_digest, "publication.precommit_digest"),
    ] {
        let value = value.as_str();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "publication journal digest must be lowercase SHA-256".to_owned(),
            });
        }
    }
    let expected_operation = source_bundle_publication_operation_id(
        &journal.transaction_id,
        &journal.output_bundle,
        &journal.generation,
    )?;
    if journal.operation_id != expected_operation {
        return Err(InstallationError::IdentityConflict);
    }
    let output_parent =
        journal
            .output_bundle
            .parent()
            .ok_or_else(|| InstallationError::InvalidField {
                field: "publication.output_bundle".to_owned(),
                reason: "destination must have an existing parent contour".to_owned(),
            })?;
    let temporary_parent =
        journal
            .temporary_path
            .parent()
            .ok_or_else(|| InstallationError::InvalidField {
                field: "publication.temporary_path".to_owned(),
                reason: "temporary path must have the destination parent".to_owned(),
            })?;
    if !windows_paths_equal(output_parent, temporary_parent)
        || journal
            .temporary_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            != Some(journal.temporary_name.as_str())
    {
        return Err(InstallationError::IdentityConflict);
    }
    validate_publication_temporary_name(
        &journal.temporary_name,
        journal
            .output_bundle
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| InstallationError::InvalidField {
                field: "publication.output_bundle".to_owned(),
                reason: "destination leaf is invalid".to_owned(),
            })?,
    )?;
    if journal.precommit_files.len() != SOURCE_BUNDLE_REQUIRED_ROLES.len() {
        return Err(InstallationError::InvalidField {
            field: "publication.precommit_files".to_owned(),
            reason: "publication journal must retain the exact nine-role inventory".to_owned(),
        });
    }
    for (role, (expected_path, expected_executable)) in journal
        .precommit_files
        .iter()
        .zip(SOURCE_BUNDLE_REQUIRED_ROLES)
    {
        validate_package_relative_path(Path::new(&role.relative_path)).map_err(|error| {
            InstallationError::InvalidField {
                field: "publication.precommit_files.relative_path".to_owned(),
                reason: error.to_string(),
            }
        })?;
        if role.relative_path != expected_path
            || role.executable != expected_executable
            || role.sha256.as_str().len() != 64
            || !role
                .sha256
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || role.source_identity.volume_serial_number == 0
            || role.source_identity.file_index == 0
            || role.temporary_identity.volume_serial_number == 0
            || role.temporary_identity.file_index == 0
            || (role.executable && (role.pe.is_none() || role.authenticode.is_none()))
            || (!role.executable && (role.pe.is_some() || role.authenticode.is_some()))
            || role.authenticode.as_ref().is_some_and(|evidence| {
                evidence.verdict != eliot_platform_windows::AuthenticodeVerdict::Valid
            })
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    let precommit_bytes = serde_json::to_vec(&journal.precommit_files).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: error.to_string(),
        }
    })?;
    if format!("{:x}", Sha256::digest(precommit_bytes)) != journal.precommit_digest.as_str() {
        return Err(InstallationError::IdentityConflict);
    }
    let (manifest, expected_files) = publication_manifest_and_expected(journal)?;
    if manifest.canonical_digest() != journal.manifest_digest.as_str()
        || GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected_files)?
            != journal.evidence_digest
    {
        return Err(InstallationError::IdentityConflict);
    }
    match journal.state {
        SourceBundlePublicationJournalState::Intent => {
            if journal.destination_identity.is_some()
                || journal.directory_receipt.is_some()
                || journal.diagnostic.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        SourceBundlePublicationJournalState::Published => {
            if journal.destination_identity.is_none()
                || journal.directory_receipt.is_none()
                || journal.diagnostic.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        SourceBundlePublicationJournalState::CommittedUnknown => {
            if journal.destination_identity.is_some()
                || journal.directory_receipt.is_some()
                || journal.diagnostic.as_ref().is_none_or(|diagnostic| {
                    diagnostic.trim().is_empty()
                        || diagnostic.len() > 4096
                        || diagnostic.chars().any(char::is_control)
                })
            {
                return Err(InstallationError::InvalidField {
                    field: "publication.diagnostic".to_owned(),
                    reason: "unknown publication requires a bounded diagnostic".to_owned(),
                });
            }
        }
    }
    if journal
        .destination_identity
        .is_some_and(|identity| identity.volume_serial_number == 0 || identity.file_index == 0)
    {
        return Err(InstallationError::IdentityConflict);
    }
    if let Some(receipt) = &journal.directory_receipt
        && (Some(receipt.destination_identity) != journal.destination_identity
            || receipt.source_identity != journal.source_identity
            || !windows_paths_equal(Path::new(&receipt.destination_path), &journal.output_bundle)
            || !windows_paths_equal(Path::new(&receipt.canonical_parent_path), output_parent)
            || receipt.parent_identity != journal.parent_identity)
    {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

fn validate_publication_temporary_name(
    temporary_name: &str,
    destination_name: &str,
) -> Result<(), InstallationError> {
    let prefix = format!(".{destination_name}.tmp.");
    let Some(suffix) = temporary_name.strip_prefix(&prefix) else {
        return Err(InstallationError::InvalidField {
            field: "publication.temporary_name".to_owned(),
            reason: "temporary leaf does not match the publication grammar".to_owned(),
        });
    };
    let Some((pid, index)) = suffix.split_once('.') else {
        return Err(InstallationError::InvalidField {
            field: "publication.temporary_name".to_owned(),
            reason: "temporary leaf does not retain process and attempt components".to_owned(),
        });
    };
    let pid_value = pid
        .parse::<u32>()
        .map_err(|_| InstallationError::InvalidField {
            field: "publication.temporary_name".to_owned(),
            reason: "temporary process component is invalid".to_owned(),
        })?;
    let index_value = index
        .parse::<u32>()
        .map_err(|_| InstallationError::InvalidField {
            field: "publication.temporary_name".to_owned(),
            reason: "temporary attempt component is invalid".to_owned(),
        })?;
    if pid_value == 0
        || index_value >= 64
        || pid != pid_value.to_string()
        || index != index_value.to_string()
    {
        return Err(InstallationError::InvalidField {
            field: "publication.temporary_name".to_owned(),
            reason: "temporary leaf is not canonical".to_owned(),
        });
    }
    Ok(())
}

fn publication_manifest_and_expected(
    journal: &SourceBundlePublicationJournal,
) -> Result<(PackageManifest, Vec<PackageArtifactDigest>), InstallationError> {
    let mut specs = Vec::with_capacity(SOURCE_BUNDLE_REQUIRED_ROLES.len());
    let mut expected = Vec::with_capacity(SOURCE_BUNDLE_REQUIRED_ROLES.len());
    for role in &journal.precommit_files {
        specs.push(
            PackageFileSpec::new(&role.relative_path, role.executable, role.size).map_err(
                |error| InstallationError::InvalidField {
                    field: "publication.precommit_files".to_owned(),
                    reason: error.to_string(),
                },
            )?,
        );
        expected.push(PackageArtifactDigest {
            relative_path: role.relative_path.clone(),
            expected_size: role.size,
            sha256: role.sha256.clone(),
        });
    }
    let manifest =
        PackageManifest::new(Path::new(journal.generation.as_str()), specs).map_err(|error| {
            InstallationError::InvalidField {
                field: "publication.manifest".to_owned(),
                reason: error.to_string(),
            }
        })?;
    Ok((manifest, expected))
}

fn verify_publication_tree(
    journal: &SourceBundlePublicationJournal,
    path: &Path,
    expected_root_identity: FileIdentity,
) -> Result<(), InstallationError> {
    let parent = path
        .parent()
        .ok_or_else(|| InstallationError::InvalidField {
            field: "publication.path".to_owned(),
            reason: "publication path has no parent".to_owned(),
        })?;
    let canonical_parent = canonical_windows_path(parent)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let (parent_identity, parent_handle) = open_no_follow_directory(&canonical_parent)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    if parent_identity != journal.parent_identity {
        return Err(InstallationError::IdentityConflict);
    }
    let leaf = path
        .file_name()
        .ok_or_else(|| InstallationError::InvalidField {
            field: "publication.path".to_owned(),
            reason: "publication path has no leaf".to_owned(),
        })?;
    let canonical_path = canonical_parent.join(leaf);
    if !windows_paths_equal(path, &canonical_path) {
        return Err(InstallationError::IdentityConflict);
    }
    let bundle = TrustedSourceBundle::open(&canonical_path)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    if bundle.identity() != expected_root_identity
        || !windows_paths_equal(bundle.path(), &canonical_path)
    {
        return Err(InstallationError::IdentityConflict);
    }
    verify_publication_bundle(journal, &bundle, expected_root_identity)?;
    let parent_readback = file_identity_for_open_handle(&parent_handle)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    if parent_readback != journal.parent_identity {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

fn verify_publication_bundle(
    journal: &SourceBundlePublicationJournal,
    bundle: &TrustedSourceBundle,
    expected_root_identity: FileIdentity,
) -> Result<(), InstallationError> {
    if bundle.identity() != expected_root_identity {
        return Err(InstallationError::IdentityConflict);
    }
    let observation = bundle
        .observe()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    if observation.files.len() != SOURCE_BUNDLE_REQUIRED_ROLES.len() {
        return Err(InstallationError::IdentityConflict);
    }
    for role in &journal.precommit_files {
        let Some(actual) = observation
            .files
            .iter()
            .find(|actual| actual.relative_path == role.relative_path)
        else {
            return Err(InstallationError::IdentityConflict);
        };
        if actual.identity != role.temporary_identity
            || actual.size != role.size
            || actual.sha256 != role.sha256.as_str()
            || actual.pe != role.pe
        {
            return Err(InstallationError::IdentityConflict);
        }
        if role.executable {
            let expected_authenticode = role
                .authenticode
                .as_ref()
                .ok_or(InstallationError::IdentityConflict)?;
            let verified_authenticode = verify_publication_authenticode(
                &bundle.path().join(&role.relative_path),
                actual.identity,
                &actual.sha256,
                expected_authenticode,
            )?;
            if verified_authenticode.verdict != AuthenticodeVerdict::Valid
                || verified_authenticode != *expected_authenticode
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
    }
    Ok(())
}

fn verify_publication_authenticode(
    path: &Path,
    identity: FileIdentity,
    sha256: &str,
    expected: &AuthenticodeEvidence,
) -> Result<AuthenticodeEvidence, InstallationError> {
    #[cfg(any(test, feature = "test-support"))]
    if is_explicit_test_support_authenticode(expected) {
        return Ok(expected.clone());
    }
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = expected;
    WindowsAuthenticodeVerifier
        .verify(path, identity, sha256)
        .map_err(|error| InstallationError::Platform(format!("Authenticode readback: {error}")))
}

#[cfg(any(test, feature = "test-support"))]
fn is_explicit_test_support_authenticode(evidence: &AuthenticodeEvidence) -> bool {
    evidence.verdict == AuthenticodeVerdict::Valid
        && evidence.signer_certificate_sha256.as_deref()
            == Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        && evidence.signer_subject.as_deref() == Some("ELIOT test-support unsigned fixture")
        && evidence.signer_not_before_unix_seconds == Some(1)
        && evidence.signer_not_after_unix_seconds == Some(2)
        && evidence.verification_time_unix_seconds == Some(1)
        && evidence.countersigner_certificate_sha256.is_none()
        && evidence.trust_status == 0
}

fn verify_publication_intent(
    journal: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    validate_publication_journal(journal)?;
    if journal.state != SourceBundlePublicationJournalState::Intent {
        return Err(InstallationError::InvalidField {
            field: "publication.state".to_owned(),
            reason: "begin accepts only an Intent journal".to_owned(),
        });
    }
    let publication = OwnedDirectoryPublication::resume(
        &journal.output_bundle,
        &journal.temporary_path,
        &journal.temporary_name,
        journal.parent_identity,
        journal.source_identity,
    )
    .map_err(|error| InstallationError::Platform(error.to_string()))?;
    if publication.parent_identity() != journal.parent_identity
        || publication.temporary_identity() != journal.source_identity
    {
        return Err(InstallationError::IdentityConflict);
    }
    let bundle = publication
        .trusted_source_bundle()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    verify_publication_bundle(journal, &bundle, journal.source_identity)
}

fn verify_published_source_bundle_journal_live(
    journal: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    validate_publication_journal(journal)?;
    if journal.state != SourceBundlePublicationJournalState::Published {
        return Err(InstallationError::MigrationRequired {
            reason: "source publication journal is not durably Published".to_owned(),
        });
    }
    let destination_identity = journal
        .destination_identity
        .ok_or(InstallationError::IdentityConflict)?;
    if destination_identity != journal.source_identity {
        return Err(InstallationError::IdentityConflict);
    }
    verify_publication_tree(journal, &journal.output_bundle, destination_identity)?;
    let receipt = journal
        .directory_receipt
        .as_ref()
        .ok_or(InstallationError::IdentityConflict)?;
    let parent = journal
        .output_bundle
        .parent()
        .ok_or(InstallationError::IdentityConflict)?;
    let canonical_parent = canonical_windows_path(parent)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let (parent_identity, parent_handle) = open_no_follow_directory(&canonical_parent)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    if parent_identity != journal.parent_identity
        || receipt.parent_identity != parent_identity
        || receipt.source_identity != journal.source_identity
        || receipt.destination_identity != destination_identity
        || !windows_paths_equal(Path::new(&receipt.destination_path), &journal.output_bundle)
        || !windows_paths_equal(Path::new(&receipt.canonical_parent_path), &canonical_parent)
        || file_identity_for_open_handle(&parent_handle)
            .map_err(|error| InstallationError::Platform(error.to_string()))?
            != parent_identity
    {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

fn publication_journal_identity_matches(
    left: &SourceBundlePublicationJournal,
    right: &SourceBundlePublicationJournal,
) -> bool {
    left.wire_version == right.wire_version
        && left.operation_id == right.operation_id
        && left.transaction_id == right.transaction_id
        && left.output_bundle == right.output_bundle
        && left.temporary_path == right.temporary_path
        && left.temporary_name == right.temporary_name
        && left.parent_identity == right.parent_identity
        && left.generation == right.generation
        && left.manifest_digest == right.manifest_digest
        && left.evidence_digest == right.evidence_digest
        && left.precommit_digest == right.precommit_digest
        && left.precommit_files == right.precommit_files
        && left.source_identity == right.source_identity
}

fn insert_publication_journal(
    database: &Database,
    journal: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    let bytes = encode_publication_journal(journal)?;
    let write = database
        .begin_write()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    {
        let mut table = write
            .open_table(PUBLICATION_JOURNAL_TABLE)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if table
            .get(journal.operation_id.as_str())
            .map_err(|error| InstallationError::Platform(error.to_string()))?
            .is_some()
        {
            return Err(InstallationError::IdentityConflict);
        }
        table
            .insert(journal.operation_id.as_str(), bytes.as_slice())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| InstallationError::Platform(error.to_string()))
}

#[cfg(feature = "test-support")]
fn write_publication_journal(
    database: &Database,
    journal: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    let bytes = encode_publication_journal(journal)?;
    let write = database
        .begin_write()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    {
        let mut table = write
            .open_table(PUBLICATION_JOURNAL_TABLE)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        table
            .insert(journal.operation_id.as_str(), bytes.as_slice())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| InstallationError::Platform(error.to_string()))
}

fn compare_and_write_publication_journal(
    database: &Database,
    journal: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    let bytes = encode_publication_journal(journal)?;
    let write = database
        .begin_write()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    {
        let mut table = write
            .open_table(PUBLICATION_JOURNAL_TABLE)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let current = {
            let value = table
                .get(journal.operation_id.as_str())
                .map_err(|error| InstallationError::Platform(error.to_string()))?
                .ok_or_else(|| InstallationError::TransactionNotFound {
                    transaction_id: journal.transaction_id.as_str().to_owned(),
                })?;
            decode_publication_journal(value.value(), &journal.operation_id)?
        };
        validate_publication_journal_transition(&current, journal)?;
        table
            .insert(journal.operation_id.as_str(), bytes.as_slice())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| InstallationError::Platform(error.to_string()))
}

fn validate_publication_journal_transition(
    current: &SourceBundlePublicationJournal,
    proposed: &SourceBundlePublicationJournal,
) -> Result<(), InstallationError> {
    if !publication_journal_identity_matches(current, proposed) {
        return Err(InstallationError::IdentityConflict);
    }
    if matches!(
        (&current.state, &proposed.state),
        (
            SourceBundlePublicationJournalState::Published,
            SourceBundlePublicationJournalState::Published
        ) | (
            SourceBundlePublicationJournalState::CommittedUnknown,
            SourceBundlePublicationJournalState::CommittedUnknown
        )
    ) && current != proposed
    {
        return Err(InstallationError::IdentityConflict);
    }
    let allowed = matches!(
        (&current.state, &proposed.state),
        (
            SourceBundlePublicationJournalState::Intent
                | SourceBundlePublicationJournalState::CommittedUnknown,
            SourceBundlePublicationJournalState::Published
                | SourceBundlePublicationJournalState::CommittedUnknown
        ) | (
            SourceBundlePublicationJournalState::Published,
            SourceBundlePublicationJournalState::Published
        )
    );
    if !allowed {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

fn encode_publication_journal(
    journal: &SourceBundlePublicationJournal,
) -> Result<Vec<u8>, InstallationError> {
    serde_json::to_vec(&PublicationJournalEnvelope {
        wire_version: SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION,
        journal: journal.clone(),
    })
    .map_err(|error| InstallationError::CorruptRegistry {
        reason: error.to_string(),
    })
}

fn read_publication_journal(
    database: &impl ReadableDatabase,
    operation_id: &PlatformHandle,
) -> Result<Option<SourceBundlePublicationJournal>, InstallationError> {
    let read = database
        .begin_read()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let table = match read.open_table(PUBLICATION_JOURNAL_TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(error) => return Err(InstallationError::Platform(error.to_string())),
    };
    let Some(value) = table
        .get(operation_id.as_str())
        .map_err(|error| InstallationError::Platform(error.to_string()))?
    else {
        return Ok(None);
    };
    decode_publication_journal(value.value(), operation_id).map(Some)
}

fn decode_publication_journal(
    bytes: &[u8],
    operation_id: &PlatformHandle,
) -> Result<SourceBundlePublicationJournal, InstallationError> {
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let envelope_wire = raw.get("wire_version").and_then(serde_json::Value::as_u64);
    let journal_value = raw.get("journal");
    let journal_wire = journal_value
        .and_then(|journal| journal.get("wire_version"))
        .and_then(serde_json::Value::as_u64);
    let has_v3_restart_authority = journal_value.is_some_and(|journal| {
        journal.get("temporary_path").is_some()
            && journal.get("temporary_name").is_some()
            && journal.get("parent_identity").is_some()
    });
    if envelope_wire != Some(u64::from(SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION))
        || journal_wire != Some(u64::from(SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION))
        || !has_v3_restart_authority
    {
        return Err(InstallationError::MigrationRequired {
            reason: "source publication journal predates the mandatory v3 temporary publication authority"
                .to_owned(),
        });
    }
    let envelope: PublicationJournalEnvelope =
        serde_json::from_value(raw).map_err(|error| InstallationError::CorruptRegistry {
            reason: format!("source publication journal is not the strict current shape: {error}"),
        })?;
    if envelope.journal.operation_id != *operation_id {
        return Err(InstallationError::IdentityConflict);
    }
    validate_publication_journal(&envelope.journal)?;
    Ok(envelope.journal)
}

fn transaction_has_stage_package(transaction: &InstallationTransaction) -> bool {
    transaction
        .installer_effects
        .iter()
        .any(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
}

fn require_publication_for_stage_package(
    store: &RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
) -> Result<(), InstallationError> {
    #[cfg(test)]
    if store.allow_unpublished_stage_fixture {
        return Ok(());
    }
    if transaction_has_stage_package(transaction) {
        require_published_source_bundle_journal(store, transaction)
    } else {
        Ok(())
    }
}

/// Require and independently revalidate the durable source publication
/// journal that precedes any `StagePackage` transaction admission or load.
pub fn require_published_source_bundle_journal(
    store: &RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
) -> Result<(), InstallationError> {
    let Some((source_bundle, generation, manifest, expected)) = transaction
        .installer_effects
        .iter()
        .find_map(|effect| match effect {
            InstallerEffectPlan::StagePackage {
                source_bundle,
                generation,
                manifest,
                expected_file_digests,
                ..
            } => Some((source_bundle, generation, manifest, expected_file_digests)),
            _ => None,
        })
    else {
        return Ok(());
    };
    let output = PathBuf::from(source_bundle.as_str());
    let operation_id =
        source_bundle_publication_operation_id(&transaction.transaction_id, &output, generation)?;
    let journal = store
        .load_source_bundle_publication(&operation_id)?
        .ok_or_else(|| InstallationError::MigrationRequired {
            reason: "planned transaction requires a durable source publication journal".to_owned(),
        })?;
    verify_published_source_bundle_journal_live(&journal)?;
    if journal.state != SourceBundlePublicationJournalState::Published
        || journal.destination_identity.is_none()
        || journal.directory_receipt.is_none()
        || journal.output_bundle != output
        || journal.transaction_id != transaction.transaction_id
        || journal.generation != *generation
        || journal.manifest_digest.as_str() != manifest.canonical_digest()
        || journal.evidence_digest
            != GenerationPackagePlanner::artifact_set_evidence_digest(manifest, expected)?
    {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
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
    let standard_table_count = read
        .list_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .count();
    let multimap_table_count = read
        .list_multimap_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .count();
    let publication_only = standard_table_count == 1
        && multimap_table_count == 0
        && read.open_table(PUBLICATION_JOURNAL_TABLE).is_ok();
    if (standard_table_count != 0 || multimap_table_count != 0) && !publication_only {
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
    let envelope: DecodedTransactionEnvelope =
        serde_json::from_value(value).map_err(|error| InstallationError::CorruptRegistry {
            reason: format!("transaction envelope is not the strict current shape: {error}"),
        })?;
    if envelope.wire_version != INSTALLATION_TRANSACTION_WIRE_VERSION {
        return Err(InstallationError::MigrationRequired {
            reason: format!(
                "transaction envelope wire {} requires explicit migration to {}",
                envelope.wire_version, INSTALLATION_TRANSACTION_WIRE_VERSION
            ),
        });
    }
    let transaction_value = &envelope.transaction;
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
    #![allow(clippy::expect_used)]

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

    #[expect(
        clippy::too_many_lines,
        reason = "W3-01 will extract the installation test surface"
    )]
    fn publication_journal_fixture(
        output_bundle: &std::path::Path,
    ) -> SourceBundlePublicationJournal {
        let transaction_id =
            PlatformHandle::new("transaction:publication-fixture").expect("journal transaction");
        let generation = PlatformHandle::new("generation.json").expect("journal generation");
        let source_identity = FileIdentity {
            volume_serial_number: 11,
            file_index: 101,
        };
        let precommit_files = [
            ("eliot-host.exe", true),
            ("eliot-watchdog.exe", true),
            ("eliot-kernel.exe", true),
            ("eliot-store-surreal.exe", true),
            ("surreal.exe", true),
            ("eliotd.exe", true),
            ("generation.json", false),
            ("eliotd-governor.json", false),
            ("eliotd.json", false),
        ]
        .into_iter()
        .enumerate()
        .map(
            |(index, (relative_path, executable))| SourceBundlePublicationRole {
                relative_path: relative_path.to_owned(),
                executable,
                size: 1,
                sha256: PlatformHandle::new(format!("{:064x}", index + 1))
                    .expect("journal role digest"),
                source_identity: FileIdentity {
                    volume_serial_number: 11,
                    file_index: 1000 + index as u64,
                },
                temporary_identity: FileIdentity {
                    volume_serial_number: 11,
                    file_index: 2000 + index as u64,
                },
                pe: executable.then_some(PeCoffEvidence {
                    machine: 0x8664,
                    optional_header_magic: 0x20b,
                    characteristics: 0x0002,
                    sections: 1,
                    pe32_plus: true,
                }),
                authenticode: executable.then_some(AuthenticodeEvidence {
                    verdict: eliot_platform_windows::AuthenticodeVerdict::Valid,
                    signer_certificate_sha256: Some("a".repeat(64)),
                    signer_subject: Some("ELIOT test-support unsigned fixture".to_owned()),
                    signer_not_before_unix_seconds: Some(1),
                    signer_not_after_unix_seconds: Some(2),
                    verification_time_unix_seconds: Some(1),
                    countersigner_certificate_sha256: None,
                    trust_status: 0,
                }),
            },
        )
        .collect::<Vec<_>>();
        let precommit_digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&precommit_files).expect("serialize journal inventory"),
            )
        );
        let manifest = PackageManifest::new(
            Path::new(generation.as_str()),
            precommit_files
                .iter()
                .map(|role| {
                    PackageFileSpec::new(&role.relative_path, role.executable, role.size)
                        .expect("manifest role")
                })
                .collect(),
        )
        .expect("publication manifest");
        let expected = precommit_files
            .iter()
            .map(|role| PackageArtifactDigest {
                relative_path: role.relative_path.clone(),
                expected_size: role.size,
                sha256: role.sha256.clone(),
            })
            .collect::<Vec<_>>();
        let evidence_digest =
            GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected)
                .expect("publication evidence");
        let output_name = output_bundle
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("output name");
        let temporary_name = format!(".{output_name}.tmp.4242.0");
        let temporary_path = output_bundle
            .parent()
            .expect("output parent")
            .join(&temporary_name);
        SourceBundlePublicationJournal {
            wire_version: SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION,
            operation_id: source_bundle_publication_operation_id(
                &transaction_id,
                output_bundle,
                &generation,
            )
            .expect("journal operation"),
            transaction_id,
            output_bundle: output_bundle.to_path_buf(),
            temporary_path,
            temporary_name,
            parent_identity: FileIdentity {
                volume_serial_number: 11,
                file_index: 303,
            },
            generation,
            manifest_digest: PlatformHandle::new(manifest.canonical_digest())
                .expect("manifest digest"),
            evidence_digest,
            precommit_digest: PlatformHandle::new(precommit_digest).expect("inventory digest"),
            precommit_files,
            source_identity,
            state: SourceBundlePublicationJournalState::Intent,
            destination_identity: None,
            directory_receipt: None,
            diagnostic: None,
        }
    }

    #[cfg(windows)]
    fn minimal_pe() -> Vec<u8> {
        let pe_offset = 0x80_usize;
        let optional_size = 0xf0_usize;
        let section_end = pe_offset + 4 + 20 + optional_size + 40;
        let mut bytes = vec![0_u8; section_end];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0002_u16.to_le_bytes());
        bytes[coff + 20..coff + 22].copy_from_slice(&0x020b_u16.to_le_bytes());
        bytes
    }

    #[cfg(windows)]
    fn live_publication_journal_fixture(
        output_bundle: &Path,
    ) -> (
        eliot_platform_windows::OwnedDirectoryPublication,
        SourceBundlePublicationJournal,
    ) {
        let publication = eliot_platform_windows::OwnedDirectoryPublication::create(output_bundle)
            .expect("reserve source publication");
        for (index, (role, executable)) in SOURCE_BUNDLE_REQUIRED_ROLES.iter().enumerate() {
            let bytes = if *executable {
                minimal_pe()
            } else {
                format!("{{\"fixture\":{index}}}").into_bytes()
            };
            fs::write(publication.temporary_path().join(role), bytes)
                .expect("write publication role");
        }
        let bundle = publication
            .trusted_source_bundle()
            .expect("retain publication bundle");
        let observation = bundle.observe().expect("observe publication bundle");
        let precommit_files = SOURCE_BUNDLE_REQUIRED_ROLES
            .iter()
            .map(|(role, executable)| {
                let observed = observation
                    .files
                    .iter()
                    .find(|observed| observed.relative_path == *role)
                    .expect("observed role");
                SourceBundlePublicationRole {
                    relative_path: (*role).to_owned(),
                    executable: *executable,
                    size: observed.size,
                    sha256: PlatformHandle::new(observed.sha256.clone()).expect("role digest"),
                    source_identity: observed.identity,
                    temporary_identity: observed.identity,
                    pe: observed.pe.clone(),
                    authenticode: (*executable).then_some(AuthenticodeEvidence {
                        verdict: eliot_platform_windows::AuthenticodeVerdict::Valid,
                        signer_certificate_sha256: Some("a".repeat(64)),
                        signer_subject: Some("ELIOT test-support unsigned fixture".to_owned()),
                        signer_not_before_unix_seconds: Some(1),
                        signer_not_after_unix_seconds: Some(2),
                        verification_time_unix_seconds: Some(1),
                        countersigner_certificate_sha256: None,
                        trust_status: 0,
                    }),
                }
            })
            .collect::<Vec<_>>();
        drop(bundle);
        let transaction_id =
            PlatformHandle::new("transaction:publication-live-fixture").expect("transaction");
        let generation = PlatformHandle::new("generation.json").expect("generation");
        let manifest = PackageManifest::new(
            Path::new(generation.as_str()),
            precommit_files
                .iter()
                .map(|role| {
                    PackageFileSpec::new(&role.relative_path, role.executable, role.size)
                        .expect("manifest role")
                })
                .collect(),
        )
        .expect("manifest");
        let expected = precommit_files
            .iter()
            .map(|role| PackageArtifactDigest {
                relative_path: role.relative_path.clone(),
                expected_size: role.size,
                sha256: role.sha256.clone(),
            })
            .collect::<Vec<_>>();
        let evidence_digest =
            GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected)
                .expect("evidence");
        let precommit_digest = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&precommit_files).expect("serialize journal inventory")
            )
        ))
        .expect("precommit digest");
        let operation_id =
            source_bundle_publication_operation_id(&transaction_id, output_bundle, &generation)
                .expect("operation");
        let journal = SourceBundlePublicationJournal {
            wire_version: SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION,
            operation_id,
            transaction_id,
            output_bundle: output_bundle.to_path_buf(),
            temporary_path: publication.temporary_path().to_path_buf(),
            temporary_name: publication.temporary_name().to_owned(),
            parent_identity: publication.parent_identity(),
            generation,
            manifest_digest: PlatformHandle::new(manifest.canonical_digest()).expect("manifest"),
            evidence_digest,
            precommit_digest,
            precommit_files,
            source_identity: publication.temporary_identity(),
            state: SourceBundlePublicationJournalState::Intent,
            destination_identity: None,
            directory_receipt: None,
            diagnostic: None,
        };
        (publication, journal)
    }

    #[cfg(windows)]
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "W3-01 will extract the installation test surface"
    )]
    fn source_publication_journal_is_readback_bound_and_replay_safe() {
        let directory = std::env::temp_dir().join(format!(
            "eliot-installation-source-publication-journal-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create journal directory");
        let path = directory.join("transactions.redb");
        let output_bundle = directory.join("bundle");
        let (publication, intent) = live_publication_journal_fixture(&output_bundle);
        drop(publication);
        let first =
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &path, &intent,
            )
            .expect("persist publication intent");
        assert_eq!(first, intent);
        let store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
            .expect("reopen publication store");
        assert_eq!(
            store
                .load_source_bundle_publication(&intent.operation_id)
                .expect("read publication journal"),
            Some(intent.clone())
        );

        let mut forged_inventory = intent.clone();
        forged_inventory.precommit_files[0].size = 2;
        assert!(matches!(
            store.record_source_bundle_publication(&forged_inventory),
            Err(InstallationError::IdentityConflict | InstallationError::InvalidField { .. })
        ));

        let caller_authored_published = SourceBundlePublicationJournal {
            state: SourceBundlePublicationJournalState::Published,
            destination_identity: Some(intent.source_identity),
            directory_receipt: Some(DirectoryPublicationReceipt {
                destination_path: output_bundle.to_string_lossy().into_owned(),
                canonical_parent_path: directory.to_string_lossy().into_owned(),
                parent_identity: intent.parent_identity,
                source_identity: intent.source_identity,
                destination_identity: intent.source_identity,
            }),
            ..intent.clone()
        };
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &path,
                &caller_authored_published,
            ),
            Err(InstallationError::InvalidField { .. })
        ));
        assert!(matches!(
            store.record_source_bundle_publication(&caller_authored_published),
            Err(InstallationError::Platform(_) | InstallationError::IdentityConflict)
        ));

        let resumed = eliot_platform_windows::OwnedDirectoryPublication::resume(
            &intent.output_bundle,
            &intent.temporary_path,
            &intent.temporary_name,
            intent.parent_identity,
            intent.source_identity,
        )
        .expect("resume exact publication");
        let publication_receipt = match resumed
            .publish(intent.source_identity)
            .expect("publish source bundle")
        {
            eliot_platform_windows::DirectoryPublicationOutcome::Published(receipt) => receipt,
            eliot_platform_windows::DirectoryPublicationOutcome::CommittedUnknown(other) => {
                panic!("expected exact publication receipt, got {other:?}")
            }
        };
        let published = SourceBundlePublicationJournal {
            state: SourceBundlePublicationJournalState::Published,
            destination_identity: Some(publication_receipt.destination_identity),
            directory_receipt: Some(publication_receipt),
            ..intent.clone()
        };
        let committed = store
            .record_source_bundle_publication(&published)
            .expect("persist publication receipt");
        assert_eq!(committed, published);
        let stale_unknown = SourceBundlePublicationJournal {
            state: SourceBundlePublicationJournalState::CommittedUnknown,
            destination_identity: None,
            directory_receipt: None,
            diagnostic: Some("stale Intent-derived unknown".to_owned()),
            ..intent.clone()
        };
        let second_store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
            .expect("open concurrent store view");
        assert!(matches!(
            second_store.record_source_bundle_publication(&stale_unknown),
            Err(InstallationError::IdentityConflict)
        ));
        assert_eq!(
            store
                .load_source_bundle_publication(&intent.operation_id)
                .expect("read monotonic publication")
                .expect("published row"),
            published,
            "a stale CommittedUnknown transition must never demote Published"
        );
        assert_eq!(
            second_store
                .record_source_bundle_publication(&published)
                .expect("exact Published replay"),
            published,
            "exact Published replay must remain idempotent"
        );

        let mut replay = published.clone();
        replay
            .directory_receipt
            .as_mut()
            .expect("receipt")
            .parent_identity
            .file_index += 1;
        assert!(matches!(
            store.record_source_bundle_publication(&replay),
            Err(InstallationError::IdentityConflict)
        ));
        fs::remove_dir_all(&output_bundle).expect("remove published directory");
        fs::create_dir(&output_bundle).expect("substitute published directory");
        assert!(matches!(
            store.record_source_bundle_publication(&published),
            Err(InstallationError::IdentityConflict)
        ));
        drop(store);
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(windows)]
    #[test]
    fn source_publication_journal_store_is_atomic_at_every_publication_boundary() {
        let directory = std::env::temp_dir().join(format!(
            "eliot-installation-source-publication-atomic-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create atomic journal directory");
        let output_bundle = directory.join("bundle");
        let (publication, intent) = live_publication_journal_fixture(&output_bundle);
        drop(publication);

        let unauthorized_final = directory.join("unauthorized-existing.redb");
        drop(Database::create(&unauthorized_final).expect("create caller-owned final store"));
        let unauthorized_before = fs::read(&unauthorized_final).expect("read caller-owned store");
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &unauthorized_final,
                &intent,
            ),
            Err(InstallationError::MigrationRequired { .. })
        ));
        assert_eq!(
            fs::read(&unauthorized_final).expect("read untouched caller-owned store"),
            unauthorized_before,
            "an existing final without the exact journal must never be adopted or mutated"
        );

        for (name, fault) in [
            (
                "before-publish.redb",
                PublicationJournalStoreFault::AfterJournalCommitBeforePublish,
            ),
            (
                "before-insert.redb",
                PublicationJournalStoreFault::AfterTemporaryCreateBeforeInsert,
            ),
        ] {
            let path = directory.join(name);
            let fault_result =
                RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path_with_fault(
                    &path,
                    &intent,
                    fault,
                );
            assert!(
                matches!(
                    &fault_result,
                    Err(InstallationError::Platform(reason)) if reason.contains("injected source publication journal store fault")
                ),
                "unexpected fault result: {fault_result:?}"
            );
            assert!(
                !path.exists(),
                "a crash before no-replace publication must leave the final store absent"
            );
            assert_eq!(
                RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                    &path, &intent,
                )
                .expect("retry atomic journal publication"),
                intent
            );
        }

        let response_loss_path = directory.join("after-publish.redb");
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path_with_fault(
                &response_loss_path,
                &intent,
                PublicationJournalStoreFault::AfterFinalPublishBeforeResponse,
            ),
            Err(InstallationError::Platform(reason)) if reason.contains("injected source publication journal store fault")
        ));
        assert!(
            response_loss_path.exists(),
            "the deterministic response-loss seam must expose the committed final store"
        );
        assert_eq!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &response_loss_path,
                &intent,
            )
            .expect("reconcile response-loss journal publication"),
            intent
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_or_caller_forged_valid_authenticode_never_creates_journal_authority() {
        let directory = std::env::temp_dir().join(format!(
            "eliot-installation-source-publication-authenticode-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create Authenticode journal directory");
        let output_bundle = directory.join("bundle");
        let (publication, intent) = live_publication_journal_fixture(&output_bundle);
        drop(publication);

        let mut unsigned = intent.clone();
        unsigned.precommit_files[0]
            .authenticode
            .as_mut()
            .expect("executable evidence")
            .verdict = AuthenticodeVerdict::Unsigned;
        unsigned.precommit_digest = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&unsigned.precommit_files).expect("unsigned inventory")
            )
        ))
        .expect("unsigned digest");
        let unsigned_store = directory.join("unsigned.redb");
        assert!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &unsigned_store,
                &unsigned,
            )
            .is_err()
        );
        assert!(!unsigned_store.exists());

        let mut forged_valid = intent;
        for role in forged_valid
            .precommit_files
            .iter_mut()
            .filter(|role| role.executable)
        {
            role.authenticode
                .as_mut()
                .expect("executable evidence")
                .signer_subject = Some("caller-forged Valid evidence".to_owned());
        }
        forged_valid.precommit_digest = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&forged_valid.precommit_files).expect("forged inventory")
            )
        ))
        .expect("forged digest");
        let forged_store = directory.join("forged-valid.redb");
        assert!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &forged_store,
                &forged_valid,
            )
            .is_err(),
            "caller-authored Valid evidence must be rechecked by official WinTrust"
        );
        assert!(!forged_store.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn source_publication_journal_rejects_wrong_wire_and_inventory_digest() {
        let directory = std::env::temp_dir().join(format!(
            "eliot-installation-source-publication-invalid-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create invalid journal directory");
        let path = directory.join("transactions.redb");
        let output_bundle = directory.join("bundle");
        let mut wrong_wire = publication_journal_fixture(&output_bundle);
        wrong_wire.wire_version -= 1;
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &path,
                &wrong_wire,
            ),
            Err(InstallationError::InvalidField { .. })
        ));
        let mut forged_digest = publication_journal_fixture(&output_bundle);
        forged_digest.precommit_digest = PlatformHandle::new("d".repeat(64)).expect("digest");
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &path,
                &forged_digest,
            ),
            Err(InstallationError::IdentityConflict)
        ));
        let mut forged_operation = publication_journal_fixture(&output_bundle);
        forged_operation.operation_id =
            PlatformHandle::new("operation:forged").expect("forged operation");
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &path,
                &forged_operation,
            ),
            Err(InstallationError::IdentityConflict)
        ));
        let mut substituted_role = publication_journal_fixture(&output_bundle);
        substituted_role.precommit_files.swap(0, 1);
        substituted_role.precommit_digest = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&substituted_role.precommit_files).expect("role substitution")
            )
        ))
        .expect("role digest");
        assert!(matches!(
            RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
                &path,
                &substituted_role,
            ),
            Err(InstallationError::IdentityConflict)
        ));
        assert!(!path.exists(), "invalid journal must not create a store");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn pre_v3_or_missing_restart_authority_requires_explicit_migration() {
        for (name, remove_restart_fields) in [("wire-v2", false), ("v3-missing-temp", true)] {
            let path = test_path(name);
            let _ = fs::remove_file(&path);
            let output_bundle = path.with_extension("bundle");
            let journal = publication_journal_fixture(&output_bundle);
            let mut raw = serde_json::json!({
                "wire_version": SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION,
                "journal": journal,
            });
            if remove_restart_fields {
                let journal = raw
                    .get_mut("journal")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("journal object");
                journal.remove("temporary_path");
                journal.remove("temporary_name");
                journal.remove("parent_identity");
            } else {
                raw["wire_version"] = serde_json::json!(2);
                raw["journal"]["wire_version"] = serde_json::json!(2);
            }
            let database = Database::create(&path).expect("create journal store");
            let write = database.begin_write().expect("begin journal write");
            {
                let mut table = write
                    .open_table(PUBLICATION_JOURNAL_TABLE)
                    .expect("open journal table");
                table
                    .insert(
                        journal.operation_id.as_str(),
                        serde_json::to_vec(&raw)
                            .expect("encode raw journal")
                            .as_slice(),
                    )
                    .expect("insert raw journal");
            }
            write.commit().expect("commit raw journal");
            drop(database);
            let store = RedbInstallationTransactionStore::open_existing_exact_path(&path)
                .expect("open journal store");
            assert!(matches!(
                store.load_source_bundle_publication(&journal.operation_id),
                Err(InstallationError::MigrationRequired { .. })
            ));
            drop(store);
            let _ = fs::remove_file(path);
        }
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
        let expected = br"exact-serialized-transaction-bytes";
        assert!(matches!(
            verify_published_transaction(&path, &expected_transaction_id, expected, None),
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
    fn transaction_envelope_requires_v22_migration_and_rejects_unknown_current_outer_members() {
        let legacy_bytes = br#"{"wire_version":{"major":22,"minor":0,"patch":0},"transaction":{},"unexpected":true}"#;
        assert!(matches!(
            decode(legacy_bytes),
            Err(InstallationError::MigrationRequired { reason })
                if reason.contains("wire 22.0.0")
        ));

        let bytes = br#"{"wire_version":{"major":23,"minor":0,"patch":0},"transaction":{},"unexpected":true}"#;
        assert!(matches!(
            decode(bytes),
            Err(InstallationError::CorruptRegistry { reason })
                if reason.contains("unknown field")
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

    #[cfg(windows)]
    #[test]
    fn retained_store_handles_fence_parent_and_destination_replacement() {
        let directory = std::env::temp_dir().join(format!(
            "eliot-installation-retained-store-fence-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let path = directory.join("transactions.redb");
        let store = RedbInstallationTransactionStore::create_at_exact_path(&path)
            .unwrap_or_else(|error| panic!("create store: {error}"));

        let replacement = directory.join("replacement.redb");
        fs::write(&replacement, b"foreign")
            .unwrap_or_else(|error| panic!("write replacement: {error}"));
        assert!(
            fs::rename(&replacement, &path).is_err(),
            "retained destination handle must deny replacement"
        );
        assert!(
            fs::remove_file(&path).is_err(),
            "retained destination handle must deny deletion"
        );
        let renamed_parent = directory.with_extension("renamed");
        assert!(
            fs::rename(&directory, &renamed_parent).is_err(),
            "retained parent handle must deny parent replacement"
        );

        drop(store);
        let _ = fs::remove_file(replacement);
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(renamed_parent);
        let _ = fs::remove_dir_all(directory);
    }
}
