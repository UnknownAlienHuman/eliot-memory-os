use crate::admission::WriteAdmissionService;
use crate::error::EngineError;
use crate::writer::WriterHandle;
use eliot_types::{
    AgentId, BackupBlobEntry, BackupChecksum, BackupInventoryEntry, BackupKind, BackupManifest,
    BackupReceipt, BackupReport, BackupStatus, BlobDeletionCandidate, BlobGcPlan, BlobGcReceipt,
    BlobGcStatus, BlobManifest, BlobManifestEntry, BlobReferenceSnapshot, BlobReport,
    BlobRetentionClass, ClaimCardInput, ClaimId, ClaimProposeCommand, CommandContext,
    CredentialProviderKind, DataRootCheck, DataRootCheckStatus, DataRootMode, DataRootProfile,
    DataRootValidation, DataRootValidationStatus, DoctorReport, EpistemicStatus, EvidenceAtomInput,
    EvidenceId, EvidenceIngestCommand, ExportBundle, ExportKind, FailureRecordCommand,
    HistoricalImportEnvelope, HistoricalImportPreview, HistoricalImportQuarantine,
    HistoricalImportReceipt, HistoricalImportStatus, ImportKind, ImportPlan, ImportValidation,
    IncidentKind, IncidentRecord, IncidentReport, IncidentSeverity, IncidentStatus,
    LifecycleStatus, MaintenanceJob, MaintenanceJobKind, MaintenanceJobStatus,
    MemoryPressureReport, OPERATOR_IPC_PROTOCOL_VERSION, OPERATOR_SCHEMA_VERSION, OperationsCheck,
    OperationsDoctorReport, PathRef, ProductionCutoverManifest, ProjectId, RedactionProfile,
    RestoreCheck, RestoreMode, RestorePlan, RestoreReceipt, RestoreReport, RestoreRollbackReceipt,
    RestoreStatus, SCHEMA_VERSION, SemanticCommand, SourceSnapshotInput, TaintClass, TaskId,
    ToolObservationRecordCommand, VerificationId, VerificationRecordCommand, VerificationResult,
    VerificationRunInput, Visibility, WriteId, WriteReceiptRef, operator_contract_hash,
};
use eliot_windows_ipc::credential_read_current_user;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

const GOVERNOR_VERSION: &str = env!("CARGO_PKG_VERSION");
const GC_GRACE_SECONDS: i64 = 7 * 24 * 60 * 60;
const GC_REFERENCE_SNAPSHOT_MAX_AGE_SECONDS: i64 = 5 * 60;
const BACKUP_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
const MIN_OPERATIONS_FREE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct SurrealLogicalConfig {
    pub executable: PathBuf,
    pub endpoint: String,
    pub namespace: String,
    pub database: String,
    pub username: String,
    pub credential_provider: CredentialProviderKind,
    pub credential_id: String,
    pub password_file: PathBuf,
    pub legacy_password_file_authorized: bool,
    pub storage_root: Option<PathBuf>,
}

impl SurrealLogicalConfig {
    fn validate_config(&self) -> Result<(), EngineError> {
        if !self.executable.is_file() {
            return Err(service_error(
                "surreal_cli",
                format!(
                    "SurrealDB executable is missing: {}",
                    self.executable.display()
                ),
            ));
        }
        let endpoint = self.endpoint.to_ascii_lowercase();
        if !(endpoint.starts_with("ws://127.0.0.1:") || endpoint.starts_with("http://127.0.0.1:")) {
            return Err(service_error(
                "surreal_cli",
                "logical operations require a loopback SurrealDB endpoint",
            ));
        }
        if self.namespace.is_empty() || self.database.is_empty() || self.username.is_empty() {
            return Err(service_error(
                "surreal_cli",
                "namespace, database, and username are required",
            ));
        }
        match self.credential_provider {
            CredentialProviderKind::WindowsCredentialManager => {
                if self.credential_id.is_empty() {
                    return Err(service_error("surreal_cli", "credential id is required"));
                }
            }
            CredentialProviderKind::LegacyPasswordFile => {
                if !self.legacy_password_file_authorized {
                    return Err(service_error(
                        "surreal_cli",
                        "legacy password_file is not authorized for this operation",
                    ));
                }
                if !self.password_file.is_file() {
                    return Err(service_error(
                        "surreal_cli",
                        format!("password file is missing: {}", self.password_file.display()),
                    ));
                }
            }
            provider => {
                return Err(service_error(
                    "surreal_cli",
                    format!("unsupported credential provider: {provider:?}"),
                ));
            }
        }
        Ok(())
    }

    fn password(&self) -> Result<String, EngineError> {
        self.validate_config()?;
        let password = match self.credential_provider {
            CredentialProviderKind::WindowsCredentialManager => {
                let bytes = credential_read_current_user(&self.credential_id)?
                    .ok_or_else(|| service_error("surreal_cli", "Windows credential is missing"))?;
                String::from_utf8(bytes).map_err(|_| {
                    service_error("surreal_cli", "Windows credential is not valid UTF-8")
                })?
            }
            CredentialProviderKind::LegacyPasswordFile => {
                fs::read_to_string(&self.password_file)?.trim().to_owned()
            }
            provider => {
                return Err(service_error(
                    "surreal_cli",
                    format!("unsupported credential provider: {provider:?}"),
                ));
            }
        };
        if password.is_empty() {
            return Err(service_error("surreal_cli", "credential value is empty"));
        }
        Ok(password)
    }

    fn credential_ready(&self) -> bool {
        match self.credential_provider {
            CredentialProviderKind::WindowsCredentialManager => {
                !self.credential_id.is_empty()
                    && credential_read_current_user(&self.credential_id)
                        .is_ok_and(|value| value.is_some_and(|bytes| !bytes.is_empty()))
            }
            CredentialProviderKind::LegacyPasswordFile => {
                self.legacy_password_file_authorized && self.password_file.is_file()
            }
            _ => false,
        }
    }

    fn endpoint_for_cli(&self) -> String {
        self.endpoint
            .trim_end_matches("/rpc")
            .replace("ws://", "http://")
            .replace("wss://", "https://")
    }
}

pub struct SurrealLogicalService;

impl SurrealLogicalService {
    pub fn version(config: &SurrealLogicalConfig) -> Result<String, EngineError> {
        let output = minimal_surreal_command(&config.executable)
            .arg("version")
            .output()?;
        ensure_command_success("surreal version", &output)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    pub fn export(config: &SurrealLogicalConfig, destination: &Path) -> Result<(), EngineError> {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let password = config.password()?;
        let output = minimal_surreal_command(&config.executable)
            .arg("export")
            .arg("--endpoint")
            .arg(config.endpoint_for_cli())
            .arg("--namespace")
            .arg(&config.namespace)
            .arg("--database")
            .arg(&config.database)
            .arg("--users")
            .arg("false")
            .arg("--accesses")
            .arg("false")
            .arg(destination)
            .env("SURREAL_USER", &config.username)
            .env("SURREAL_PASS", password)
            .output()?;
        ensure_command_success("surreal export", &output)?;
        let metadata = fs::metadata(destination)?;
        if metadata.len() == 0 {
            return Err(service_error("backup", "SurrealDB export is empty"));
        }
        Self::validate(config, destination)
    }

    pub fn import(config: &SurrealLogicalConfig, source: &Path) -> Result<(), EngineError> {
        Self::validate(config, source)?;
        let password = config.password()?;
        let output = minimal_surreal_command(&config.executable)
            .arg("import")
            .arg("--endpoint")
            .arg(config.endpoint_for_cli())
            .arg("--namespace")
            .arg(&config.namespace)
            .arg("--database")
            .arg(&config.database)
            .arg(source)
            .env("SURREAL_USER", &config.username)
            .env("SURREAL_PASS", password)
            .output()?;
        ensure_command_success("surreal import", &output)
    }

    pub fn validate(config: &SurrealLogicalConfig, source: &Path) -> Result<(), EngineError> {
        let output = minimal_surreal_command(&config.executable)
            .arg("validate")
            .arg(source)
            .output()?;
        ensure_command_success("surreal validate", &output)
    }
}

fn minimal_surreal_command(executable: &Path) -> Command {
    let mut command = Command::new(executable);
    command.env_clear();
    for name in ["SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

pub struct DataRootService {
    root: PathBuf,
}

impl DataRootService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn profile(&self, mode: DataRootMode) -> DataRootProfile {
        let root = self.root.clone();
        let store_root = match mode {
            DataRootMode::ProductionLocal | DataRootMode::RecoveryOffline => root.join("store"),
            DataRootMode::DevProjectLocal | DataRootMode::TestIsolated => root.clone(),
        };
        DataRootProfile {
            profile_id: mode_profile_id(mode).to_owned(),
            mode,
            root: path_ref(&root),
            store_root: path_ref(&store_root),
            blob_root: path_ref(root.join("blobs")),
            backup_root: path_ref(root.join("backups")),
            export_root: path_ref(root.join("exports")),
            import_root: path_ref(root.join("imports")),
            report_root: path_ref(root.join("reports")),
            log_root: path_ref(root.join("logs")),
            spool_root: path_ref(root.join("spool")),
            worktree_root: path_ref(root.join("worktrees")),
            incident_root: path_ref(root.join("incidents")),
            config_root: path_ref(root.join("config")),
            policy_root: path_ref(root.join("policy")),
            tmp_root: path_ref(root.join("tmp")),
        }
    }

    pub fn validate(&self, mode: DataRootMode) -> Result<DataRootValidation, EngineError> {
        self.validate_profile(&self.profile(mode))
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_profile(
        &self,
        profile: &DataRootProfile,
    ) -> Result<DataRootValidation, EngineError> {
        let root = PathBuf::from(&profile.root);
        fs::create_dir_all(&root)?;
        let mut checks = Vec::new();
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        push_check(&mut checks, "exists", root.exists(), "data root exists");
        push_check(
            &mut checks,
            "writable",
            write_probe(&root).is_ok(),
            "data root accepts write probe",
        );

        let root_text = root.to_string_lossy().to_ascii_lowercase();
        let in_onedrive = root_text.contains("onedrive");
        match profile.mode {
            DataRootMode::ProductionLocal if in_onedrive => {
                errors.push("production data root must not be inside OneDrive".to_owned());
                checks.push(DataRootCheck {
                    name: "not_inside_onedrive".to_owned(),
                    status: DataRootCheckStatus::Error,
                    message: "production root is inside OneDrive".to_owned(),
                });
            }
            DataRootMode::DevProjectLocal if in_onedrive => {
                warnings.push("dev data root is inside OneDrive".to_owned());
                checks.push(DataRootCheck {
                    name: "onedrive_dev_warning".to_owned(),
                    status: DataRootCheckStatus::Warning,
                    message: "OneDrive is allowed only as a dev warning".to_owned(),
                });
            }
            _ => push_check(
                &mut checks,
                "not_inside_onedrive",
                true,
                "OneDrive restriction satisfied",
            ),
        }

        let inside_git = is_inside_git_repo(&root);
        if profile.mode == DataRootMode::ProductionLocal && inside_git {
            errors.push("production data root must not be inside a git repo".to_owned());
            checks.push(DataRootCheck {
                name: "not_inside_git_repo".to_owned(),
                status: DataRootCheckStatus::Error,
                message: "production root is under a git checkout".to_owned(),
            });
        } else {
            push_check(
                &mut checks,
                "not_inside_git_repo",
                true,
                "git-root rule satisfied for profile",
            );
        }

        for path in profile_dirs(profile) {
            let dir = PathBuf::from(path);
            if let Err(error) = fs::create_dir_all(&dir) {
                errors.push(format!(
                    "failed to create required dir {}: {error}",
                    dir.display()
                ));
                checks.push(DataRootCheck {
                    name: format!("required_dir:{}", dir.display()),
                    status: DataRootCheckStatus::Error,
                    message: error.to_string(),
                });
            } else {
                push_check(
                    &mut checks,
                    &format!("required_dir:{}", dir.display()),
                    dir.is_dir(),
                    "required directory exists",
                );
            }
        }

        push_check(
            &mut checks,
            "tmp_writable",
            write_probe(Path::new(&profile.tmp_root)).is_ok(),
            "tmp root accepts write probe",
        );
        push_check(
            &mut checks,
            "lock_file_accessible",
            write_probe(Path::new(&profile.tmp_root)).is_ok(),
            "lock path parent accepts write probe",
        );
        push_check(
            &mut checks,
            "manifest_readable",
            true,
            "manifest is generated in-process for H0",
        );
        push_check(
            &mut checks,
            "no_obvious_db_credentials_in_config",
            !contains_secret_like_config(Path::new(&profile.config_root)),
            "config root contains no obvious secret filename",
        );
        push_check(
            &mut checks,
            "free_space_threshold",
            true,
            "free-space probe unavailable in portable H0; not blocking",
        );

        for check in &checks {
            if check.status == DataRootCheckStatus::Error
                && !errors.iter().any(|error| error == &check.message)
            {
                errors.push(check.message.clone());
            }
        }
        let status = if errors.is_empty() && warnings.is_empty() {
            DataRootValidationStatus::Valid
        } else if errors.is_empty() {
            DataRootValidationStatus::ValidWithWarnings
        } else {
            DataRootValidationStatus::Invalid
        };
        Ok(DataRootValidation {
            profile_id: profile.profile_id.clone(),
            root: profile.root.clone(),
            status,
            checks,
            warnings,
            errors,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    /// Every live runtime root must be excluded from Git. A blanket ignore of
    /// the runtime directory satisfies that for all of them at once, so accept
    /// it rather than demanding one literal line per subdirectory: the property
    /// is that live state cannot be committed, not that the file is written a
    /// particular way.
    pub fn gitignore_excludes_live_roots(repo_root: &Path) -> bool {
        let Ok(content) = fs::read_to_string(repo_root.join(".gitignore")) else {
            return false;
        };
        let lines = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        let blanket = lines
            .iter()
            .any(|line| matches!(*line, ".eliot-governor/" | "/.eliot-governor/"));
        blanket
            || Self::LIVE_ROOT_DIRECTORIES.iter().all(|entry| {
                let explicit = format!("/.eliot-governor/{entry}/");
                lines.iter().any(|line| *line == explicit)
            })
    }

    const LIVE_ROOT_DIRECTORIES: [&'static str; 12] = [
        "blobs",
        "control",
        "control-wal",
        "secrets",
        "surrealdb-rocks",
        "logs",
        "runtime",
        "tmp",
        "backups",
        "exports",
        "imports",
        "incidents",
    ];
}

pub struct BackupService {
    root: PathBuf,
}

impl BackupService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn run(&self, kind: BackupKind, dry_run: bool) -> Result<BackupReport, EngineError> {
        if !dry_run {
            return Err(service_error(
                "backup",
                "logical backup requires SurrealLogicalConfig; live RocksDB files are never copied",
            ));
        }
        self.build_backup(kind, None, true)
    }

    pub fn run_logical(
        &self,
        kind: BackupKind,
        config: &SurrealLogicalConfig,
        dry_run: bool,
    ) -> Result<BackupReport, EngineError> {
        if !matches!(
            kind,
            BackupKind::LogicalExport | BackupKind::IncrementalLogical | BackupKind::PreMigration
        ) {
            return Err(service_error(
                "backup",
                "online backups must use a logical export kind",
            ));
        }
        self.build_backup(kind, Some(config), dry_run)
    }

    #[allow(clippy::too_many_lines)]
    fn build_backup(
        &self,
        kind: BackupKind,
        config: Option<&SurrealLogicalConfig>,
        dry_run: bool,
    ) -> Result<BackupReport, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let backup_id = format!("backup-{}", WriteId::new_v7());
        let backup_dir = self.root.join("backups").join(&backup_id);
        fs::create_dir_all(&backup_dir)?;
        let blob_root = self.root.join("blobs");
        let blob_manifest = BlobGcService::new(&blob_root).manifest()?;
        let blob_manifest_path = backup_dir.join("blob-manifest.json");
        write_json_file(&blob_manifest_path, &blob_manifest)?;
        let (blob_payload_root, blob_payloads) = if dry_run {
            (None, Vec::new())
        } else {
            let payload_root = backup_dir.join("blob-payloads");
            let payloads = copy_blob_payloads_quiescent(&blob_root, &payload_root, &blob_manifest)?;
            (Some(path_ref(&payload_root)), payloads)
        };
        let config_snapshot_refs = snapshot_tree(
            &self.root.join("config"),
            &backup_dir.join("config-snapshot"),
            256,
        )?;
        let policy_snapshot_refs = snapshot_tree(
            &self.root.join("policy"),
            &backup_dir.join("policy-snapshot"),
            256,
        )?;
        let control_wal_snapshot_refs = snapshot_tree(
            &self.root.join("control-wal"),
            &backup_dir.join("control-wal-snapshot"),
            512,
        )?;
        let surreal_export_path = backup_dir.join("surreal-export.surql");
        let surreal_export_ref = if dry_run {
            None
        } else {
            let config = config.ok_or_else(|| {
                service_error(
                    "backup",
                    "SurrealDB logical export configuration is missing",
                )
            })?;
            SurrealLogicalService::export(config, &surreal_export_path)?;
            Some(path_ref(&surreal_export_path))
        };
        let mut checksums = vec![checksum_file(&blob_manifest_path)?];
        for path in config_snapshot_refs
            .iter()
            .chain(policy_snapshot_refs.iter())
            .chain(control_wal_snapshot_refs.iter())
        {
            checksums.push(checksum_file(Path::new(path))?);
        }
        if surreal_export_path.is_file() {
            checksums.push(checksum_file(&surreal_export_path)?);
        }
        checksums.extend(blob_payloads.iter().map(|entry| entry.checksum.clone()));
        let status = if dry_run {
            BackupStatus::DryRunOnly
        } else {
            BackupStatus::Succeeded
        };
        let manifest = BackupManifest {
            backup_id: backup_id.clone(),
            created_at: started_at,
            source_data_root: path_ref(&self.root),
            backup_root: path_ref(&backup_dir),
            backup_kind: kind,
            governor_version: GOVERNOR_VERSION.to_owned(),
            schema_version: SCHEMA_VERSION.to_owned(),
            policy_snapshot_refs,
            config_snapshot_refs,
            surreal_export_ref,
            surreal_export_status: if dry_run {
                "planned".to_owned()
            } else {
                "validated".to_owned()
            },
            surreal_source_endpoint: config.map(|config| config.endpoint.clone()),
            surreal_source_storage_ref: config
                .and_then(|config| config.storage_root.as_ref())
                .map(path_ref),
            control_wal_snapshot_ref: (!control_wal_snapshot_refs.is_empty())
                .then(|| path_ref(backup_dir.join("control-wal-snapshot"))),
            blob_manifest_ref: path_ref(&blob_manifest_path),
            blob_payload_root,
            blob_payloads,
            report_manifest_ref: Some(path_ref(self.root.join("reports"))),
            checksums: checksums.clone(),
            copied_live_db_files: false,
            dry_run,
            warnings: if dry_run {
                vec!["dry run: no SurrealDB export was executed".to_owned()]
            } else {
                Vec::new()
            },
        };
        let manifest_path = backup_dir.join("manifest.json");
        write_json_file(&manifest_path, &manifest)?;
        let latest_dir = self.root.join("backups").join("latest");
        fs::create_dir_all(&latest_dir)?;
        write_json_file(latest_dir.join("manifest.json"), &manifest)?;
        let bytes_written = checksums
            .iter()
            .map(|checksum| checksum.size_bytes)
            .sum::<u64>()
            .saturating_add(fs::metadata(&manifest_path)?.len());
        let receipt = BackupReceipt {
            backup_id,
            status,
            manifest_ref: path_ref(&manifest_path),
            bytes_written,
            objects_written: u64::try_from(checksums.len()).unwrap_or(u64::MAX) + 1,
            started_at,
            finished_at: OffsetDateTime::now_utc(),
            errors: Vec::new(),
        };
        Ok(BackupReport {
            component: "backup".to_owned(),
            manifest,
            receipt,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn verify(&self, backup: &str) -> Result<BackupManifest, EngineError> {
        let manifest = self.read_manifest(backup)?;
        let backup_root = PathBuf::from(&manifest.backup_root);
        validate_backup_selector(&manifest.backup_id)?;
        let expected_backup_root = self.root.join("backups").join(&manifest.backup_id);
        if !same_path(&backup_root, &expected_backup_root)
            || (backup != "latest" && backup != manifest.backup_id)
        {
            return Err(service_error(
                "backup",
                "backup manifest identity/root differs from the requested backup",
            ));
        }
        if manifest.checksums.is_empty() {
            return Err(EngineError::ServiceNotReady {
                service: "backup".to_owned(),
                reason: "backup manifest has no checksums".to_owned(),
            });
        }
        for checksum in &manifest.checksums {
            let path = PathBuf::from(&checksum.path);
            ensure_path_within(&path, &backup_root, "backup checksum")?;
            if !path.is_file() {
                return Err(service_error(
                    "backup",
                    format!("checksummed artifact is missing: {}", path.display()),
                ));
            }
            let actual = checksum_file(&path)?;
            if actual.digest_hex != checksum.digest_hex || actual.size_bytes != checksum.size_bytes
            {
                return Err(service_error(
                    "backup",
                    format!("checksum mismatch for {}", path.display()),
                ));
            }
        }
        if !manifest.dry_run {
            let export_path = manifest
                .surreal_export_ref
                .as_deref()
                .map(Path::new)
                .ok_or_else(|| {
                    service_error("backup", "completed logical backup has no SurrealDB export")
                })?;
            ensure_path_within(export_path, &backup_root, "SurrealDB export")?;
            verify_declared_checksum(export_path, &manifest.checksums, "SurrealDB export")?;
        }
        let blob_manifest_path = Path::new(&manifest.blob_manifest_ref);
        ensure_path_within(blob_manifest_path, &backup_root, "blob manifest")?;
        verify_declared_checksum(blob_manifest_path, &manifest.checksums, "blob manifest")?;
        verify_blob_payload_manifest(&manifest)?;
        Ok(manifest)
    }

    pub fn list(&self) -> Result<Vec<BackupInventoryEntry>, EngineError> {
        let mut entries = Vec::new();
        let backup_root = self.root.join("backups");
        if !backup_root.is_dir() {
            return Ok(entries);
        }
        for entry in fs::read_dir(&backup_root)?.take(512) {
            let path = entry?.path();
            if !path.is_dir() || path.file_name().and_then(|name| name.to_str()) == Some("latest") {
                continue;
            }
            let manifest_path = path.join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }
            let manifest: BackupManifest =
                serde_json::from_reader(fs::File::open(&manifest_path)?)?;
            let verified = self.verify(&manifest.backup_id).is_ok();
            entries.push(BackupInventoryEntry {
                backup_id: manifest.backup_id,
                created_at: manifest.created_at,
                status: if manifest.dry_run {
                    BackupStatus::DryRunOnly
                } else if verified {
                    BackupStatus::Succeeded
                } else {
                    BackupStatus::Failed
                },
                manifest_ref: path_ref(manifest_path),
                verified,
                age_seconds: (OffsetDateTime::now_utc() - manifest.created_at).whole_seconds(),
            });
        }
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
        Ok(entries)
    }

    pub fn read_manifest(&self, backup: &str) -> Result<BackupManifest, EngineError> {
        validate_backup_selector(backup)?;
        let path = if backup == "latest" {
            self.root
                .join("backups")
                .join("latest")
                .join("manifest.json")
        } else {
            self.root.join("backups").join(backup).join("manifest.json")
        };
        Ok(serde_json::from_reader(fs::File::open(path)?)?)
    }
}

pub struct RestoreService {
    root: PathBuf,
}

impl RestoreService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn verify(&self, backup: &str) -> Result<RestoreReport, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let manifest = BackupService::new(&self.root).verify(backup)?;
        let plan = Self::plan_from_manifest(
            &manifest,
            self.root.join("restore-verify"),
            RestoreMode::VerifyOnly,
        );
        let receipt = RestoreReceipt {
            restore_receipt_id: format!("restore-receipt-{}", WriteId::new_v7()),
            restore_plan_id: plan.restore_plan_id.clone(),
            status: RestoreStatus::VerifiedOnly,
            target_data_root: plan.target_data_root.clone(),
            verified_manifest: true,
            verified_checksums: true,
            restored_objects: 0,
            restored_blobs: 0,
            exact_action_hash: None,
            dry_run: true,
            started_at,
            finished_at: OffsetDateTime::now_utc(),
            errors: Vec::new(),
        };
        Ok(RestoreReport {
            component: "restore".to_owned(),
            plan,
            receipt,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn run(
        &self,
        backup: &str,
        target: &Path,
        dry_run: bool,
    ) -> Result<RestoreReport, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let manifest = BackupService::new(&self.root).verify(backup)?;
        let plan = Self::plan_from_manifest(&manifest, target, RestoreMode::RestoreToNewRoot);
        let mut errors = Vec::new();
        let unsafe_target =
            same_or_active_root(&self.root, target) || !target_is_empty_or_missing(target)?;
        if unsafe_target {
            errors.push("restore target is active root or not empty".to_owned());
        }
        let status = if unsafe_target {
            RestoreStatus::RejectedUnsafeTarget
        } else {
            RestoreStatus::RestoredToNewRoot
        };
        let receipt = RestoreReceipt {
            restore_receipt_id: format!("restore-receipt-{}", WriteId::new_v7()),
            restore_plan_id: plan.restore_plan_id.clone(),
            status,
            target_data_root: path_ref(target),
            verified_manifest: true,
            verified_checksums: true,
            restored_objects: 0,
            restored_blobs: 0,
            exact_action_hash: None,
            dry_run,
            started_at,
            finished_at: OffsetDateTime::now_utc(),
            errors,
        };
        Ok(RestoreReport {
            component: "restore".to_owned(),
            plan,
            receipt,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn run_logical(
        &self,
        backup: &str,
        target: &Path,
        target_config: &SurrealLogicalConfig,
        maintenance_mode: bool,
        approval_hash: &str,
        dry_run: bool,
    ) -> Result<RestoreReport, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let manifest = BackupService::new(&self.root).verify(backup)?;
        let mut plan = Self::plan_from_manifest(&manifest, target, RestoreMode::RestoreToNewRoot);
        let target_isolated = target_is_empty_or_missing(target)?
            || target_config
                .storage_root
                .as_ref()
                .is_some_and(|storage| target_contains_only_storage(target, storage));
        let endpoint_isolated =
            manifest.surreal_source_endpoint.as_deref() != Some(target_config.endpoint.as_str());
        let storage_isolated =
            manifest
                .surreal_source_storage_ref
                .as_deref()
                .is_none_or(|source| {
                    target_config
                        .storage_root
                        .as_ref()
                        .is_none_or(|target| !same_path(Path::new(source), target))
                });
        let target_safe = !same_or_active_root(&self.root, target)
            && target_isolated
            && endpoint_isolated
            && storage_isolated
            && !path_is_sync_root(target);
        let exact_action_hash = restore_action_hash(&manifest, target, target_config)?;
        plan.target_endpoint = Some(target_config.endpoint.clone());
        plan.target_storage_ref = target_config.storage_root.as_ref().map(path_ref);
        plan.exact_action_hash = Some(exact_action_hash.clone());
        plan.checks.extend([
            RestoreCheck {
                name: "new_empty_target".to_owned(),
                passed: target_safe,
                message:
                    "restore target must be empty, outside the active root, and outside a sync root"
                        .to_owned(),
            },
            RestoreCheck {
                name: "maintenance_mode".to_owned(),
                passed: maintenance_mode,
                message: "restore mutation requires maintenance mode".to_owned(),
            },
            RestoreCheck {
                name: "exact_action_approval".to_owned(),
                passed: dry_run || approval_hash == exact_action_hash,
                message: "approval is bound to backup, target, endpoint, and storage".to_owned(),
            },
            RestoreCheck {
                name: "isolated_target_endpoint".to_owned(),
                passed: endpoint_isolated && storage_isolated,
                message: "target endpoint and storage must differ from the backup source"
                    .to_owned(),
            },
            RestoreCheck {
                name: "logical_export_present".to_owned(),
                passed: manifest.surreal_export_ref.is_some(),
                message: "backup contains a validated logical SurrealDB export".to_owned(),
            },
        ]);
        let mut errors = Vec::new();
        if !target_safe {
            errors.push("restore target is unsafe".to_owned());
        }
        if !maintenance_mode && !dry_run {
            errors.push("maintenance mode approval is required".to_owned());
        }
        if !dry_run && approval_hash != exact_action_hash {
            errors.push("exact restore action approval hash is required".to_owned());
        }
        let export_path = manifest
            .surreal_export_ref
            .as_deref()
            .map(PathBuf::from)
            .ok_or_else(|| service_error("restore", "backup has no logical export"))?;
        let mut restored_blobs = 0u64;
        let status = if !target_safe {
            RestoreStatus::RejectedUnsafeTarget
        } else if dry_run {
            RestoreStatus::VerifiedOnly
        } else if !maintenance_mode || approval_hash != exact_action_hash {
            RestoreStatus::FailedWrite
        } else {
            fs::create_dir_all(target)?;
            let staging_root = target.join("restore-staging");
            restored_blobs = restore_blob_payloads(&manifest, &staging_root)?;
            SurrealLogicalService::import(target_config, &export_path)?;
            let staged_blobs = staging_root.join("blobs");
            let target_blobs = target.join("blobs");
            if target_blobs.exists() {
                return Err(service_error(
                    "restore",
                    "isolated restore target already contains a blob root",
                ));
            }
            if staged_blobs.is_dir() {
                fs::rename(&staged_blobs, &target_blobs)?;
            } else {
                fs::create_dir_all(&target_blobs)?;
            }
            if staging_root.is_dir() {
                fs::remove_dir(&staging_root)?;
            }
            let restore_evidence = target.join("restore-evidence");
            fs::create_dir_all(&restore_evidence)?;
            fs::copy(
                Path::new(&manifest.backup_root).join("manifest.json"),
                restore_evidence.join("source-backup-manifest.json"),
            )?;
            RestoreStatus::RestoredToNewRoot
        };
        let restored_objects =
            u64::from(status == RestoreStatus::RestoredToNewRoot).saturating_add(restored_blobs);
        let report = RestoreReport {
            component: "restore".to_owned(),
            plan: plan.clone(),
            receipt: RestoreReceipt {
                restore_receipt_id: format!("restore-receipt-{}", WriteId::new_v7()),
                restore_plan_id: plan.restore_plan_id,
                status,
                target_data_root: path_ref(target),
                verified_manifest: true,
                verified_checksums: true,
                restored_objects,
                restored_blobs,
                exact_action_hash: Some(exact_action_hash),
                dry_run,
                started_at,
                finished_at: OffsetDateTime::now_utc(),
                errors,
            },
            generated_at: OffsetDateTime::now_utc(),
        };
        if status == RestoreStatus::RestoredToNewRoot {
            write_json_file(
                target.join("restore-evidence").join("restore-receipt.json"),
                &report,
            )?;
        }
        Ok(report)
    }

    pub fn plan(&self, backup: &str, target: &Path) -> Result<RestorePlan, EngineError> {
        let manifest = BackupService::new(&self.root).read_manifest(backup)?;
        Ok(Self::plan_from_manifest(
            &manifest,
            target,
            RestoreMode::RestoreToNewRoot,
        ))
    }

    pub fn plan_logical(
        &self,
        backup: &str,
        target: &Path,
        target_config: &SurrealLogicalConfig,
    ) -> Result<RestorePlan, EngineError> {
        let manifest = BackupService::new(&self.root).verify(backup)?;
        let mut plan = Self::plan_from_manifest(&manifest, target, RestoreMode::RestoreToNewRoot);
        plan.target_endpoint = Some(target_config.endpoint.clone());
        plan.target_storage_ref = target_config.storage_root.as_ref().map(path_ref);
        plan.exact_action_hash = Some(restore_action_hash(&manifest, target, target_config)?);
        Ok(plan)
    }

    pub fn rollback_isolated(
        &self,
        target: &Path,
        maintenance_mode: bool,
        approval_hash: &str,
        dry_run: bool,
    ) -> Result<RestoreRollbackReceipt, EngineError> {
        let evidence = target.join("restore-evidence").join("restore-receipt.json");
        if same_or_active_root(&self.root, target)
            || path_is_sync_root(target)
            || !evidence.is_file()
        {
            return Err(service_error(
                "restore_rollback",
                "target is not an isolated restored root with canonical evidence",
            ));
        }
        let restore_report: RestoreReport = serde_json::from_reader(fs::File::open(&evidence)?)?;
        if restore_report.receipt.status != RestoreStatus::RestoredToNewRoot
            || !restore_report.receipt.verified_manifest
            || !restore_report.receipt.verified_checksums
            || !same_path(Path::new(&restore_report.receipt.target_data_root), target)
        {
            return Err(service_error(
                "restore_rollback",
                "restore evidence does not authorize rollback of this target",
            ));
        }
        let evidence_checksum = checksum_file(&evidence)?;
        let exact_action_hash = rollback_action_hash(target, &evidence_checksum.digest_hex)?;
        let quarantine = rollback_quarantine_path(target, &exact_action_hash)?;
        let mut errors = Vec::new();
        if !dry_run && !maintenance_mode {
            errors.push("maintenance mode is required".to_owned());
        }
        if !dry_run && approval_hash != exact_action_hash {
            errors.push("exact rollback action approval hash is required".to_owned());
        }
        let status = if dry_run {
            "planned"
        } else if errors.is_empty() {
            fs::rename(target, &quarantine)?;
            "rolled_back_to_quarantine"
        } else {
            "refused"
        };
        let receipt = RestoreRollbackReceipt {
            rollback_receipt_id: format!("restore-rollback-{}", WriteId::new_v7()),
            target_data_root: path_ref(target),
            quarantined_root: Some(path_ref(&quarantine)),
            exact_action_hash,
            status: status.to_owned(),
            dry_run,
            finished_at: OffsetDateTime::now_utc(),
            errors,
        };
        if status == "rolled_back_to_quarantine" {
            write_json_file(
                quarantine
                    .join("restore-evidence")
                    .join("rollback-receipt.json"),
                &receipt,
            )?;
        }
        Ok(receipt)
    }

    fn plan_from_manifest(
        manifest: &BackupManifest,
        target: impl AsRef<Path>,
        mode: RestoreMode,
    ) -> RestorePlan {
        RestorePlan {
            restore_plan_id: format!("restore-plan-{}", WriteId::new_v7()),
            backup_id: manifest.backup_id.clone(),
            backup_manifest_ref: path_ref(Path::new(&manifest.backup_root).join("manifest.json")),
            target_data_root: path_ref(target.as_ref()),
            restore_mode: mode,
            target_endpoint: None,
            target_storage_ref: None,
            exact_action_hash: None,
            checks: vec![
                RestoreCheck {
                    name: "manifest_present".to_owned(),
                    passed: true,
                    message: "backup manifest parsed".to_owned(),
                },
                RestoreCheck {
                    name: "checksums_present".to_owned(),
                    passed: !manifest.checksums.is_empty(),
                    message: "backup manifest contains checksums".to_owned(),
                },
            ],
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct ExportService {
    root: PathBuf,
}

impl ExportService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn run(&self, kind: ExportKind) -> Result<ExportBundle, EngineError> {
        let export_id = format!("export-{}", WriteId::new_v7());
        let export_dir = self.root.join("exports").join(&export_id);
        fs::create_dir_all(&export_dir)?;
        let payload_refs = if kind == ExportKind::ReportsOnly {
            list_files_bounded(&self.root.join("reports"), 128)?
                .into_iter()
                .map(|path| path_ref(&path))
                .collect()
        } else {
            Vec::new()
        };
        let bundle = ExportBundle {
            export_id,
            project_id: None,
            created_at: OffsetDateTime::now_utc(),
            export_kind: kind,
            manifest_ref: path_ref(export_dir.join("manifest.json")),
            payload_refs,
            redaction_profile: RedactionProfile::InternalMetadataOnly,
        };
        write_json_file(&bundle.manifest_ref, &bundle)?;
        Ok(bundle)
    }
}

pub struct ImportService {
    root: PathBuf,
}

impl ImportService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn validate(
        &self,
        path: &Path,
        kind: ImportKind,
        maintenance_mode: bool,
    ) -> Result<ImportPlan, EngineError> {
        fs::create_dir_all(self.root.join("imports"))?;
        let is_surql = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("surql"));
        let exists = path.exists();
        let raw_surql_rejected = is_surql;
        let mut errors = Vec::new();
        if !exists {
            errors.push(format!("import path does not exist: {}", path.display()));
        }
        if raw_surql_rejected {
            errors.push(
                "raw .surql is never accepted as historical ingress; use typed JSON artifacts"
                    .to_owned(),
            );
        }
        Ok(ImportPlan {
            import_plan_id: format!("import-plan-{}", WriteId::new_v7()),
            import_root: path_ref(path),
            import_kind: kind,
            taint: TaintClass::UserProvided,
            validation: ImportValidation {
                admin_only: true,
                accepted: errors.is_empty(),
                raw_surql_rejected,
                maintenance_mode_required: !maintenance_mode,
                errors,
                warnings: vec![
                    "imports remain tainted and are never promoted to truth directly".to_owned(),
                ],
            },
            created_at: OffsetDateTime::now_utc(),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn preview(
        &self,
        path: &Path,
        target_store_fingerprint: &str,
    ) -> Result<HistoricalImportPreview, EngineError> {
        let raw_surql_rejected = contains_surql(path)?;
        let mut accepted = Vec::new();
        let mut quarantined = Vec::new();
        let mut already_imported = Vec::new();
        if raw_surql_rejected {
            quarantined.push(HistoricalImportQuarantine {
                source_ref: path_ref(path),
                source_artifact_id: None,
                reason: "raw .surql is forbidden for historical import".to_owned(),
            });
        } else {
            for source in import_json_files(path)? {
                let value: serde_json::Value = serde_json::from_reader(fs::File::open(&source)?)?;
                let values = value.as_array().cloned().unwrap_or_else(|| vec![value]);
                for (index, artifact) in values.into_iter().enumerate() {
                    let artifact_id = artifact
                        .get("artifact_id")
                        .and_then(serde_json::Value::as_str)
                        .map_or_else(|| format!("{}:{index}", source.display()), str::to_owned);
                    let artifact_kind = artifact
                        .get("kind")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unsupported")
                        .to_ascii_lowercase();
                    if !supported_historical_kind(&artifact_kind) {
                        quarantined.push(HistoricalImportQuarantine {
                            source_ref: path_ref(&source),
                            source_artifact_id: Some(artifact_id),
                            reason: format!(
                                "unsupported historical artifact kind: {artifact_kind}"
                            ),
                        });
                        continue;
                    }
                    let project_ref = artifact
                        .get("project_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let task_ref = artifact
                        .get("task_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let payload = artifact.get("payload").cloned().unwrap_or(artifact);
                    let identity = serde_json::json!({
                        "source": path_ref(&source),
                        "artifact_id": artifact_id.clone(),
                        "kind": artifact_kind.clone(),
                        "payload": payload.clone(),
                        "target": target_store_fingerprint,
                    });
                    let idempotency_key = blake3::hash(&serde_json::to_vec(&identity)?)
                        .to_hex()
                        .to_string();
                    let import_id = format!("historical-{idempotency_key}");
                    if self
                        .root
                        .join("imports")
                        .join("receipts")
                        .join(format!("{import_id}.json"))
                        .is_file()
                    {
                        already_imported.push(import_id);
                        continue;
                    }
                    accepted.push(HistoricalImportEnvelope {
                        import_id,
                        idempotency_key,
                        source_ref: path_ref(&source),
                        source_artifact_id: identity["artifact_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        artifact_kind,
                        project_ref,
                        task_ref,
                        payload,
                        taint: TaintClass::UserProvided,
                        provenance: vec![
                            "historical_import".to_owned(),
                            "imported_weak".to_owned(),
                        ],
                    });
                }
            }
        }
        let plan_material = serde_json::json!({
            "source": path_ref(path),
            "target": target_store_fingerprint,
            "accepted": accepted,
            "quarantined": quarantined,
            "already_imported": already_imported,
        });
        let plan_hash = blake3::hash(&serde_json::to_vec(&plan_material)?)
            .to_hex()
            .to_string();
        Ok(HistoricalImportPreview {
            preview_id: format!("historical-preview-{}", WriteId::new_v7()),
            source_root: path_ref(path),
            plan_hash,
            target_store_fingerprint: target_store_fingerprint.to_owned(),
            accepted,
            quarantined,
            already_imported,
            raw_surql_rejected,
            maintenance_mode_required: true,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn finalize(
        &self,
        preview: &HistoricalImportPreview,
        approval_hash: &str,
        maintenance_mode: bool,
        write_receipt_refs: Vec<WriteReceiptRef>,
    ) -> Result<HistoricalImportReceipt, EngineError> {
        if !maintenance_mode {
            return Err(service_error(
                "historical_import",
                "maintenance mode is required",
            ));
        }
        if approval_hash != preview.plan_hash {
            return Err(service_error(
                "historical_import",
                "approval hash does not match the preview plan",
            ));
        }
        if write_receipt_refs.len() != preview.accepted.len() {
            return Err(service_error(
                "historical_import",
                "every accepted envelope requires a canonical write receipt",
            ));
        }
        let receipt_root = self.root.join("imports").join("receipts");
        let envelope_root = self.root.join("imports").join("envelopes");
        let quarantine_root = self.root.join("imports").join("quarantine");
        fs::create_dir_all(&receipt_root)?;
        fs::create_dir_all(&envelope_root)?;
        fs::create_dir_all(&quarantine_root)?;
        let mut quarantine_refs = Vec::new();
        for item in &preview.quarantined {
            let digest = blake3::hash(&serde_json::to_vec(item)?)
                .to_hex()
                .to_string();
            let path = quarantine_root.join(format!("{digest}.json"));
            write_json_file(&path, item)?;
            quarantine_refs.push(path_ref(path));
        }
        for envelope in &preview.accepted {
            write_json_file(
                envelope_root.join(format!("{}.json", envelope.import_id)),
                envelope,
            )?;
            write_json_file(
                receipt_root.join(format!("{}.json", envelope.import_id)),
                &serde_json::json!({
                    "import_id": envelope.import_id,
                    "idempotency_key": envelope.idempotency_key,
                    "plan_hash": preview.plan_hash,
                    "status": "canonical_write_committed",
                }),
            )?;
        }
        Ok(HistoricalImportReceipt {
            receipt_id: format!("historical-receipt-{}", WriteId::new_v7()),
            preview_id: preview.preview_id.clone(),
            plan_hash: preview.plan_hash.clone(),
            status: if preview.quarantined.is_empty() {
                HistoricalImportStatus::Imported
            } else {
                HistoricalImportStatus::ImportedWithQuarantine
            },
            imported_ids: preview
                .accepted
                .iter()
                .map(|envelope| envelope.import_id.clone())
                .collect(),
            already_imported_ids: preview.already_imported.clone(),
            quarantine_refs,
            write_receipt_refs,
            finished_at: OffsetDateTime::now_utc(),
        })
    }
}

pub struct HistoricalImportMemoryWriter;

impl HistoricalImportMemoryWriter {
    pub async fn write_envelope(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        envelope: &HistoricalImportEnvelope,
    ) -> Result<WriteReceiptRef, EngineError> {
        let command = historical_semantic_command(envelope)?;
        let receipt = writer.submit(admission.admit(&command)?).await?;
        Ok(WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        })
    }
}

fn historical_semantic_command(
    envelope: &HistoricalImportEnvelope,
) -> Result<SemanticCommand, EngineError> {
    let context = historical_command_context(envelope)?;
    let payload = historical_payload(envelope);
    let summary = historical_text(
        &envelope.payload,
        &["summary", "statement", "description", "title"],
        &format!("historical {} artifact", envelope.artifact_kind),
    );
    match envelope.artifact_kind.as_str() {
        "claim" => Ok(SemanticCommand::ClaimPropose(ClaimProposeCommand {
            context,
            claim: ClaimCardInput {
                claim_id: historical_claim_id(envelope)?,
                statement: summary,
                status: EpistemicStatus::Candidate,
                payload,
            },
        })),
        "failure" => Ok(SemanticCommand::FailureRecord(FailureRecordCommand {
            context,
            fingerprint: historical_text(
                &envelope.payload,
                &["fingerprint", "failure_fingerprint"],
                &envelope.idempotency_key,
            ),
            summary,
            payload,
        })),
        "verification" => Ok(SemanticCommand::VerificationRecord(
            VerificationRecordCommand {
                context,
                verification: VerificationRunInput {
                    verification_id: historical_verification_id(envelope)?,
                    claim_id: envelope
                        .payload
                        .get("claim_id")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| value.parse::<ClaimId>().ok()),
                    verifier: "historical-import-unverified".to_owned(),
                    result: VerificationResult::Inconclusive,
                    summary,
                    payload,
                },
            },
        )),
        "report" | "evidence" | "decision" | "experience" | "source_snapshot" => {
            let source_id = format!("historical-source: {}", envelope.source_artifact_id);
            Ok(SemanticCommand::EvidenceIngest(EvidenceIngestCommand {
                context,
                source: SourceSnapshotInput {
                    source_id: source_id.clone(),
                    uri: envelope.source_ref.clone(),
                    authority: "historical-import-user-provided".to_owned(),
                    content_hash: blake3::hash(&serde_json::to_vec(&envelope.payload)?)
                        .to_hex()
                        .to_string(),
                    excerpt: summary.clone(),
                },
                evidence: EvidenceAtomInput {
                    evidence_id: historical_evidence_id(envelope)?,
                    source_id,
                    summary,
                    payload,
                },
            }))
        }
        _ => Err(service_error(
            "historical_import",
            format!(
                "unsupported semantic artifact kind: {}",
                envelope.artifact_kind
            ),
        )),
    }
}

fn historical_command_context(
    envelope: &HistoricalImportEnvelope,
) -> Result<CommandContext, EngineError> {
    Ok(CommandContext {
        write_id: deterministic_write_id(&envelope.idempotency_key)?,
        agent_id: deterministic_typed_id::<AgentId>(&format!(
            "agent|{}",
            envelope.idempotency_key
        ))?,
        session_id: None,
        project_id: envelope
            .project_ref
            .as_deref()
            .and_then(|value| value.parse::<ProjectId>().ok())
            .map_or_else(
                || {
                    deterministic_typed_id::<ProjectId>(&format!(
                        "project|{}",
                        envelope.idempotency_key
                    ))
                },
                Ok,
            )?,
        task_id: envelope
            .task_ref
            .as_deref()
            .and_then(|value| value.parse::<TaskId>().ok()),
        scope: "historical_import".to_owned(),
        authority: "eliot-historical-import".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::UserProvided,
        lifecycle_status: LifecycleStatus::Active,
    })
}

fn historical_payload(envelope: &HistoricalImportEnvelope) -> serde_json::Value {
    serde_json::json!({
        "historical_import": {
            "import_id": envelope.import_id,
            "source_ref": envelope.source_ref,
            "source_artifact_id": envelope.source_artifact_id,
            "artifact_kind": envelope.artifact_kind,
            "provenance": envelope.provenance,
            "taint": "user_provided",
            "epistemic_ceiling": "candidate_or_inconclusive",
            "payload": envelope.payload,
        }
    })
}

fn historical_text(value: &serde_json::Value, fields: &[&str], fallback: &str) -> String {
    fields
        .iter()
        .filter_map(|field| value.get(field).and_then(serde_json::Value::as_str))
        .find(|value| !value.trim().is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

fn historical_claim_id(envelope: &HistoricalImportEnvelope) -> Result<ClaimId, EngineError> {
    historical_id_or_derived(
        &envelope.payload,
        "claim_id",
        "claim",
        &envelope.idempotency_key,
    )
}

fn historical_evidence_id(envelope: &HistoricalImportEnvelope) -> Result<EvidenceId, EngineError> {
    historical_id_or_derived(
        &envelope.payload,
        "evidence_id",
        "evidence",
        &envelope.idempotency_key,
    )
}

fn historical_verification_id(
    envelope: &HistoricalImportEnvelope,
) -> Result<VerificationId, EngineError> {
    historical_id_or_derived(
        &envelope.payload,
        "verification_id",
        "verification",
        &envelope.idempotency_key,
    )
}

fn historical_id_or_derived<T>(
    payload: &serde_json::Value,
    field: &str,
    kind: &str,
    key: &str,
) -> Result<T, EngineError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if let Some(parsed) = payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<T>().ok())
    {
        return Ok(parsed);
    }
    deterministic_typed_id(&format!("{kind}|{key}"))
}

fn deterministic_typed_id<T>(material: &str) -> Result<T, EngineError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let digest = blake3::hash(material.as_bytes()).to_hex().to_string();
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &digest[..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    );
    uuid.parse::<T>()
        .map_err(|error| service_error("historical_import", error.to_string()))
}

pub struct BlobGcService {
    blob_root: PathBuf,
    grace_seconds: i64,
}

impl BlobGcService {
    pub fn new(blob_root: impl Into<PathBuf>) -> Self {
        Self {
            blob_root: blob_root.into(),
            grace_seconds: GC_GRACE_SECONDS,
        }
    }

    #[must_use]
    pub fn with_grace_seconds(mut self, grace_seconds: i64) -> Self {
        self.grace_seconds = grace_seconds.max(0);
        self
    }

    pub fn manifest(&self) -> Result<BlobManifest, EngineError> {
        fs::create_dir_all(&self.blob_root)?;
        let mut blobs = Vec::new();
        for path in list_files_bounded(&self.blob_root, 4096)? {
            let bytes = fs::read(&path)?;
            let digest_hex = blake3::hash(&bytes).to_hex().to_string();
            blobs.push(BlobManifestEntry {
                blob_hash: digest_hex,
                path: path_ref(&path),
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                content_type: None,
                compression: None,
            });
        }
        blobs.sort_by(|left, right| left.path.cmp(&right.path));
        let total_bytes = blobs.iter().map(|blob| blob.size_bytes).sum();
        Ok(BlobManifest {
            manifest_id: format!("blob-manifest-{}", WriteId::new_v7()),
            generated_at: OffsetDateTime::now_utc(),
            blob_root: path_ref(&self.blob_root),
            blobs,
            total_bytes,
            checksum_algorithm: "blake3".to_owned(),
        })
    }

    pub fn gc_plan(
        &self,
        manifest: &BlobManifest,
        reference_snapshot: &BlobReferenceSnapshot,
    ) -> Result<BlobGcPlan, EngineError> {
        validate_manifest_scope(manifest, &self.blob_root)?;
        validate_reference_snapshot(reference_snapshot, &manifest.blob_root)?;
        let (reachable_hashes, retained_hashes) = reference_hashes(reference_snapshot);
        let mut reachable = Vec::new();
        let mut unreachable_grace = Vec::new();
        let mut unreachable_deletable = Vec::new();
        let mut protected = Vec::new();
        let mut deletion_candidates = Vec::new();
        let mut estimated_reclaim_bytes = 0u64;
        let now = OffsetDateTime::now_utc();
        let state_path = self.mark_state_path();
        let previous = read_json_if_exists::<BlobGcMarkState>(&state_path)?
            .filter(|state| {
                state.source_store == reference_snapshot.source_store
                    && state.scope == reference_snapshot.scope
                    && state.query_hash == reference_snapshot.query_hash
            })
            .unwrap_or_default();
        let mut next_marks = BTreeMap::new();

        for blob in &manifest.blobs {
            if retained_hashes.contains(&blob.blob_hash) {
                protected.push(blob.blob_hash.clone());
            } else if reachable_hashes.contains(&blob.blob_hash) {
                reachable.push(blob.blob_hash.clone());
            } else if blob_is_in_grace(&blob.path, now, self.grace_seconds) {
                unreachable_grace.push(blob.blob_hash.clone());
            } else {
                let observed_scans = previous
                    .observed_scans
                    .get(&blob.blob_hash)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1)
                    .min(2);
                next_marks.insert(blob.blob_hash.clone(), observed_scans);
                if observed_scans >= 2 {
                    estimated_reclaim_bytes =
                        estimated_reclaim_bytes.saturating_add(blob.size_bytes);
                    unreachable_deletable.push(blob.blob_hash.clone());
                    deletion_candidates.push(BlobDeletionCandidate {
                        blob_hash: blob.blob_hash.clone(),
                        path: blob.path.clone(),
                        size_bytes: blob.size_bytes,
                        observed_scans,
                    });
                } else {
                    unreachable_grace.push(blob.blob_hash.clone());
                }
            }
        }
        write_json_file(
            &state_path,
            &BlobGcMarkState {
                observed_scans: next_marks,
                source_store: reference_snapshot.source_store.clone(),
                scope: reference_snapshot.scope.clone(),
                query_hash: reference_snapshot.query_hash.clone(),
                updated_at: now,
            },
        )?;
        let scan_sequence = deletion_candidates
            .iter()
            .map(|candidate| candidate.observed_scans)
            .max()
            .unwrap_or(1);
        let manifest_hash = manifest_content_hash(manifest)?;
        let approval_hash = gc_approval_hash(
            &deletion_candidates,
            &manifest_hash,
            reference_snapshot,
            now,
        )?;
        Ok(BlobGcPlan {
            gc_plan_id: format!("blob-gc-plan-{}", WriteId::new_v7()),
            generated_at: now,
            manifest_hash,
            reference_snapshot: reference_snapshot.clone(),
            reachable,
            unreachable_grace,
            unreachable_deletable,
            protected,
            estimated_reclaim_bytes,
            scan_sequence,
            approval_hash,
            deletion_candidates,
        })
    }

    pub fn gc_run(
        &self,
        plan: &BlobGcPlan,
        current_manifest: &BlobManifest,
        current_snapshot: &BlobReferenceSnapshot,
        dry_run: bool,
    ) -> Result<BlobGcReceipt, EngineError> {
        self.gc_run_authorized(plan, current_manifest, current_snapshot, "", dry_run, false)
    }

    pub fn gc_run_authorized(
        &self,
        plan: &BlobGcPlan,
        current_manifest: &BlobManifest,
        current_snapshot: &BlobReferenceSnapshot,
        approval_hash: &str,
        dry_run: bool,
        under_load: bool,
    ) -> Result<BlobGcReceipt, EngineError> {
        let mut deleted_blobs = Vec::new();
        let mut skipped = Vec::new();
        let mut reclaimed_bytes = 0u64;
        if dry_run {
            skipped.extend(plan.unreachable_deletable.clone());
        } else if under_load {
            skipped.push("runtime load gate refused blob purge".to_owned());
        } else {
            skipped.extend(self.purge_preflight_failures(
                plan,
                current_manifest,
                current_snapshot,
                approval_hash,
            )?);
            if skipped.is_empty() {
                let root = self
                    .blob_root
                    .canonicalize()
                    .unwrap_or_else(|_| self.blob_root.clone());
                for candidate in &plan.deletion_candidates {
                    let path = PathBuf::from(&candidate.path);
                    let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
                    if !canonical.starts_with(&root) || candidate.observed_scans < 2 {
                        skipped.push(format!(
                            "{}: failed root/two-scan gate",
                            candidate.blob_hash
                        ));
                        continue;
                    }
                    let actual = checksum_file(&canonical)?;
                    if actual.digest_hex != candidate.blob_hash
                        || actual.size_bytes != candidate.size_bytes
                    {
                        skipped.push(format!(
                            "{}: content changed after plan",
                            candidate.blob_hash
                        ));
                        continue;
                    }
                    fs::remove_file(&canonical)?;
                    reclaimed_bytes = reclaimed_bytes.saturating_add(candidate.size_bytes);
                    deleted_blobs.push(candidate.blob_hash.clone());
                }
            }
        }
        let status = if dry_run {
            BlobGcStatus::DryRun
        } else if under_load {
            BlobGcStatus::RefusedUnderLoad
        } else if skipped.is_empty() {
            BlobGcStatus::Succeeded
        } else {
            BlobGcStatus::Failed
        };
        Ok(BlobGcReceipt {
            gc_receipt_id: format!("blob-gc-receipt-{}", WriteId::new_v7()),
            gc_plan_id: plan.gc_plan_id.clone(),
            deleted_blobs,
            reclaimed_bytes,
            skipped,
            status,
            dry_run,
            finished_at: OffsetDateTime::now_utc(),
        })
    }

    fn purge_preflight_failures(
        &self,
        plan: &BlobGcPlan,
        current_manifest: &BlobManifest,
        current_snapshot: &BlobReferenceSnapshot,
        approval_hash: &str,
    ) -> Result<Vec<String>, EngineError> {
        let mut failures = Vec::new();
        if let Err(error) = validate_manifest_scope(current_manifest, &self.blob_root) {
            failures.push(format!("blob manifest scope refused purge: {error}"));
        }
        if let Err(error) =
            validate_reference_snapshot(current_snapshot, &current_manifest.blob_root)
        {
            failures.push(format!("canonical reference scan refused purge: {error}"));
        }
        if let Err(error) =
            validate_reference_snapshot(&plan.reference_snapshot, &current_manifest.blob_root)
        {
            failures.push(format!(
                "planned canonical reference scan is stale: {error}"
            ));
        }
        if current_snapshot.snapshot_id != plan.reference_snapshot.snapshot_id
            || current_snapshot.source_revision != plan.reference_snapshot.source_revision
            || current_snapshot.query_hash != plan.reference_snapshot.query_hash
        {
            failures.push("canonical reference snapshot changed after planning".to_owned());
        }
        if manifest_content_hash(current_manifest)? != plan.manifest_hash {
            failures.push("blob manifest content or root changed after planning".to_owned());
        }
        if approval_hash != plan.approval_hash || approval_hash.is_empty() {
            failures.push("explicit approval hash does not match GC plan".to_owned());
        }
        let expected_approval_hash = gc_approval_hash(
            &plan.deletion_candidates,
            &plan.manifest_hash,
            &plan.reference_snapshot,
            plan.generated_at,
        )?;
        if expected_approval_hash != plan.approval_hash {
            failures.push("persisted GC plan integrity check failed".to_owned());
        }
        let (currently_referenced, currently_retained) = reference_hashes(current_snapshot);
        if plan.deletion_candidates.iter().any(|candidate| {
            currently_referenced.contains(&candidate.blob_hash)
                || currently_retained.contains(&candidate.blob_hash)
        }) {
            failures.push("GC plan contains a canonically referenced or retained blob".to_owned());
        }
        Ok(failures)
    }

    fn mark_state_path(&self) -> PathBuf {
        let root_key = blake3::hash(path_ref(&self.blob_root).as_bytes())
            .to_hex()
            .to_string();
        self.blob_root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("reports")
            .join("blob-gc")
            .join(format!("mark-state-{root_key}.json"))
    }

    pub fn report(&self, _dry_run: bool) -> Result<BlobReport, EngineError> {
        let manifest = self.manifest()?;
        Ok(BlobReport {
            component: "blob".to_owned(),
            manifest: Some(manifest),
            gc_plan: None,
            gc_receipt: None,
            generated_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlobGcMarkState {
    observed_scans: BTreeMap<String, u8>,
    #[serde(default)]
    source_store: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    query_hash: String,
    #[serde(default = "now_utc")]
    updated_at: OffsetDateTime,
}

impl Default for BlobGcMarkState {
    fn default() -> Self {
        Self {
            observed_scans: BTreeMap::new(),
            source_store: String::new(),
            scope: String::new(),
            query_hash: String::new(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct MaintenanceScheduler {
    root: PathBuf,
}

impl MaintenanceScheduler {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn run_one_shot(
        &self,
        job_kind: MaintenanceJobKind,
        dry_run: bool,
    ) -> Result<MaintenanceJob, EngineError> {
        fs::create_dir_all(self.root.join("reports").join("maintenance"))?;
        let started_at = OffsetDateTime::now_utc();
        if job_kind == MaintenanceJobKind::Doctor {
            let repo_root = self.root.parent().unwrap_or_else(|| Path::new("."));
            let _ = DoctorService::new(&self.root, repo_root).report()?;
        }
        Ok(MaintenanceJob {
            job_id: format!("maintenance-job-{}", WriteId::new_v7()),
            job_kind,
            project_id: None,
            status: if dry_run {
                MaintenanceJobStatus::SucceededDryRun
            } else {
                MaintenanceJobStatus::Succeeded
            },
            requested_by: "cli-admin".to_owned(),
            dry_run,
            started_at: Some(started_at),
            finished_at: Some(OffsetDateTime::now_utc()),
            receipt_ref: Some(format!("maintenance:{job_kind:?}")),
            write_receipt: None,
            errors: Vec::new(),
        })
    }
}

pub struct MaintenanceMemoryWriter;

impl MaintenanceMemoryWriter {
    pub async fn write_job(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        job: &mut MaintenanceJob,
    ) -> Result<WriteReceiptRef, EngineError> {
        let project_id = job.project_id.unwrap_or_else(ProjectId::new_v7);
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: eliot_types::AgentId::new_v7(),
                session_id: None,
                project_id,
                task_id: None,
                scope: "maintenance".to_owned(),
                authority: "eliot-maintenance-scheduler".to_owned(),
                visibility: Visibility::Internal,
                taint: TaintClass::LocalVerified,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: "eliot_maintenance_job".to_owned(),
            observation: format!("maintenance job {} status {:?}", job.job_id, job.status),
            payload: serde_json::json!({ "maintenance_job": job }),
        });
        let receipt = writer.submit(admission.admit(&command)?).await?;
        let receipt_ref = WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        };
        job.write_receipt = Some(receipt_ref.clone());
        job.receipt_ref = Some(format!("write_receipt:{}", receipt_ref.receipt_id));
        Ok(receipt_ref)
    }
}

pub struct IncidentService {
    root: PathBuf,
}

impl IncidentService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn list(&self) -> Result<Vec<IncidentRecord>, EngineError> {
        let path = self.state_path();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_reader(fs::File::open(path)?)?)
    }

    pub fn report(&self) -> Result<IncidentReport, EngineError> {
        let incidents = self.list()?;
        let lockdown_active = incidents.iter().any(incident_blocks_unsafe_surfaces);
        Ok(IncidentReport {
            component: "incidents".to_owned(),
            incidents,
            lockdown_active,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn open(
        &self,
        kind: IncidentKind,
        severity: IncidentSeverity,
        summary: impl Into<String>,
    ) -> Result<IncidentRecord, EngineError> {
        let mut incidents = self.list()?;
        let incident = IncidentRecord {
            incident_id: format!("incident-{}", WriteId::new_v7()),
            severity,
            status: IncidentStatus::Open,
            kind,
            project_id: None,
            affected_surfaces: vec![
                "action_lease".to_owned(),
                "patch_runner".to_owned(),
                "completion_gate".to_owned(),
            ],
            opened_at: OffsetDateTime::now_utc(),
            acknowledged_at: None,
            closed_at: None,
            evidence_refs: Vec::new(),
            last_known_safe_refs: Vec::new(),
            recovery_commands: vec![
                "eliot-governor doctor run".to_owned(),
                "eliot-governor incident acknowledge --incident <id>".to_owned(),
            ],
            summary: summary.into(),
            campaign_integrity: None,
        };
        incidents.push(incident.clone());
        self.save(&incidents)?;
        Ok(incident)
    }

    pub fn acknowledge(&self, incident_id: &str) -> Result<IncidentRecord, EngineError> {
        self.transition(incident_id, IncidentStatus::Acknowledged)
    }

    pub fn close(&self, incident_id: &str) -> Result<IncidentRecord, EngineError> {
        self.transition(incident_id, IncidentStatus::Closed)
    }

    pub fn lockdown_active(&self) -> Result<bool, EngineError> {
        Ok(self.list()?.iter().any(incident_blocks_unsafe_surfaces))
    }

    fn transition(
        &self,
        incident_id: &str,
        status: IncidentStatus,
    ) -> Result<IncidentRecord, EngineError> {
        let mut incidents = self.list()?;
        let index = incidents
            .iter()
            .position(|incident| incident.incident_id == incident_id)
            .ok_or_else(|| EngineError::ServiceNotReady {
                service: "incident".to_owned(),
                reason: format!("incident not found: {incident_id}"),
            })?;
        incidents[index].status = status;
        let now = OffsetDateTime::now_utc();
        match status {
            IncidentStatus::Acknowledged => incidents[index].acknowledged_at = Some(now),
            IncidentStatus::Closed => incidents[index].closed_at = Some(now),
            IncidentStatus::Open | IncidentStatus::Mitigated => {}
        }
        let incident = incidents[index].clone();
        self.save(&incidents)?;
        Ok(incident)
    }

    fn save(&self, incidents: &[IncidentRecord]) -> Result<(), EngineError> {
        let path = self.state_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_json_file(path, incidents)
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("incidents").join("incidents.json")
    }
}

pub struct DoctorService {
    root: PathBuf,
    repo_root: PathBuf,
}

impl DoctorService {
    pub fn new(root: impl Into<PathBuf>, repo_root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            repo_root: repo_root.into(),
        }
    }

    pub fn report(&self) -> Result<DoctorReport, EngineError> {
        let data_root_validation =
            DataRootService::new(&self.root).validate(DataRootMode::DevProjectLocal)?;
        let incident_report = IncidentService::new(&self.root).report()?;
        Ok(DoctorReport {
            component: "doctor".to_owned(),
            data_root_validation,
            gitignore_excludes_live_roots: DataRootService::gitignore_excludes_live_roots(
                &self.repo_root,
            ),
            report_roots_writable: write_probe(&self.root.join("reports")).is_ok(),
            log_roots_writable: write_probe(&self.root.join("logs")).is_ok(),
            blob_manifest_consistent: BlobGcService::new(self.root.join("blobs"))
                .manifest()
                .is_ok(),
            open_incidents: incident_report
                .incidents
                .iter()
                .filter(|incident| incident.status != IncidentStatus::Closed)
                .count(),
            stale_locks: stale_locks(&self.root, &self.repo_root),
            stale_test_processes_warning: None,
            memory_pressure: MemoryPressureReport {
                duplicate_pressure: "low".to_owned(),
                stale_activation_pressure: "low".to_owned(),
                skill_distractor_pressure: "low".to_owned(),
                open_lifecycle_proposals: 0,
                suppressed_recent_regret: 0,
            },
            open_skill_curation_proposals: open_skill_curation_proposals(&self.root),
            open_replay_requirements: open_replay_requirements(&self.root),
            sdk_absent: crate_absent(&self.repo_root, "surrealdb"),
            rsa_absent: crate_absent(&self.repo_root, "rsa"),
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn operations_report(
        &self,
        surreal: &SurrealLogicalConfig,
    ) -> Result<OperationsDoctorReport, EngineError> {
        let base_report = self.report()?;
        let cli_version = SurrealLogicalService::version(surreal);
        let latest_manifest = self
            .root
            .join("backups")
            .join("latest")
            .join("manifest.json");
        let backup_check = if latest_manifest.is_file() {
            BackupService::new(&self.root).verify("latest").is_ok()
        } else {
            false
        };
        let disk_probe = disk_space_probe(&self.root);
        let acl_probe = native_probe("icacls", &[&path_ref(&self.root)]);
        let runtime_owners = [
            self.root.join("runtime").join("daemon.lock"),
            self.root.join("runtime").join("service.lock"),
        ]
        .into_iter()
        .filter(|path| path.is_file())
        .count();
        let active_owner_pids = active_runtime_owner_pids(&self.root);
        let latest_backup_age = read_json_if_exists::<BackupManifest>(&latest_manifest)?
            .map(|manifest| (OffsetDateTime::now_utc() - manifest.created_at).whole_seconds());
        let config_schema_ready =
            fs::read_to_string(self.repo_root.join("config").join("eliot-governor.toml"))
                .is_ok_and(|content| {
                    content.contains(&format!("schema_version = \"{SCHEMA_VERSION}\""))
                });
        let operator_contract_ready = operator_contract_source_matches(&self.repo_root);
        let unreceipted_imports = unreceipted_import_count(&self.root)?;
        let route_health = endpoint_route_health(&surreal.endpoint);
        let storage_sync_safe = surreal
            .storage_root
            .as_deref()
            .is_none_or(|path| !path_is_sync_root(path));
        let checks = vec![
            OperationsCheck {
                name: "data_root".to_owned(),
                passed: base_report.data_root_validation.status
                    != DataRootValidationStatus::Invalid,
                blocking: true,
                message: "data-root profile is valid".to_owned(),
            },
            OperationsCheck {
                name: "sync_root".to_owned(),
                passed: !path_is_sync_root(&self.root),
                blocking: true,
                message: "production data root must not be in OneDrive or another sync root"
                    .to_owned(),
            },
            OperationsCheck {
                name: "surreal_cli".to_owned(),
                passed: cli_version.is_ok(),
                blocking: true,
                message: cli_version.unwrap_or_else(|error| error.to_string()),
            },
            OperationsCheck {
                name: "surreal_endpoint".to_owned(),
                passed: !surreal.endpoint.is_empty()
                    && !surreal.namespace.is_empty()
                    && !surreal.database.is_empty(),
                blocking: true,
                message: format!(
                    "endpoint={} namespace={} database={}",
                    surreal.endpoint, surreal.namespace, surreal.database
                ),
            },
            OperationsCheck {
                name: "credential_ref".to_owned(),
                passed: surreal.credential_ready(),
                blocking: true,
                message: match surreal.credential_provider {
                    CredentialProviderKind::WindowsCredentialManager => {
                        format!(
                            "provider=windows_credential_manager id={}",
                            surreal.credential_id
                        )
                    }
                    CredentialProviderKind::LegacyPasswordFile => {
                        "provider=legacy_password_file authorized migration/test path".to_owned()
                    }
                    provider => format!("provider={provider:?} unsupported"),
                },
            },
            OperationsCheck {
                name: "single_runtime_owner".to_owned(),
                passed: runtime_owners <= 1 && active_owner_pids.len() <= 1,
                blocking: true,
                message: format!(
                    "markers={runtime_owners} active_owner_pids={active_owner_pids:?}"
                ),
            },
            OperationsCheck {
                name: "latest_backup".to_owned(),
                passed: backup_check
                    && latest_backup_age
                        .is_some_and(|age| (0..=BACKUP_MAX_AGE_SECONDS).contains(&age)),
                blocking: false,
                message: if let Some(age) = latest_backup_age {
                    format!("latest backup verified={backup_check} age_seconds={age}")
                } else {
                    "no latest backup exists yet".to_owned()
                },
            },
            OperationsCheck {
                name: "schema_contract".to_owned(),
                passed: config_schema_ready,
                blocking: true,
                message: format!("expected schema_version={SCHEMA_VERSION}"),
            },
            OperationsCheck {
                name: "operator_protocol_contract".to_owned(),
                passed: operator_contract_ready,
                blocking: true,
                message: format!(
                    "schema={} protocol={} hash={}",
                    OPERATOR_SCHEMA_VERSION,
                    OPERATOR_IPC_PROTOCOL_VERSION,
                    operator_contract_hash()
                ),
            },
            OperationsCheck {
                name: "storage_sync_root".to_owned(),
                passed: storage_sync_safe,
                blocking: true,
                message: surreal
                    .storage_root
                    .as_ref()
                    .map_or_else(|| "no storage root configured".to_owned(), path_ref),
            },
            OperationsCheck {
                name: "unreceipted_historical_imports".to_owned(),
                passed: unreceipted_imports == 0,
                blocking: true,
                message: format!("unreceipted_imports={unreceipted_imports}"),
            },
            OperationsCheck {
                name: "historical_import_route".to_owned(),
                passed: write_probe(&self.root.join("imports")).is_ok(),
                blocking: true,
                message: "typed import receipts and quarantine root are writable".to_owned(),
            },
            OperationsCheck {
                name: "protocol_route".to_owned(),
                passed: route_health.0,
                blocking: false,
                message: route_health.1,
            },
            OperationsCheck {
                name: "disk_space_probe".to_owned(),
                passed: disk_probe.0,
                blocking: true,
                message: disk_probe.1,
            },
            OperationsCheck {
                name: "acl_probe".to_owned(),
                passed: acl_probe.0,
                blocking: true,
                message: acl_probe.1,
            },
        ];
        let blocked = checks.iter().any(|check| check.blocking && !check.passed);
        let degraded = checks.iter().any(|check| !check.blocking && !check.passed);
        Ok(OperationsDoctorReport {
            component: "operations_doctor".to_owned(),
            status: if blocked {
                "blocked"
            } else if degraded {
                "degraded"
            } else {
                "ready"
            }
            .to_owned(),
            checks,
            base_report,
            generated_at: OffsetDateTime::now_utc(),
        })
    }
}

pub struct ProductionCutoverService;

impl ProductionCutoverService {
    pub fn plan(
        current_data_root: &Path,
        proposed_data_root: &Path,
        config_path: &Path,
        executable_path: &Path,
    ) -> ProductionCutoverManifest {
        let proposed_is_absolute = proposed_data_root.is_absolute();
        let different_root = !same_or_active_root(current_data_root, proposed_data_root);
        let not_sync_root = !path_is_sync_root(proposed_data_root);
        let outside_git = !is_inside_git_repo(proposed_data_root);
        let preflight = vec![
            OperationsCheck {
                name: "absolute_production_root".to_owned(),
                passed: proposed_is_absolute,
                blocking: true,
                message: path_ref(proposed_data_root),
            },
            OperationsCheck {
                name: "different_from_active_root".to_owned(),
                passed: different_root,
                blocking: true,
                message: path_ref(current_data_root),
            },
            OperationsCheck {
                name: "outside_sync_root".to_owned(),
                passed: not_sync_root,
                blocking: true,
                message: "production state cannot live in OneDrive/Dropbox/Google Drive".to_owned(),
            },
            OperationsCheck {
                name: "outside_git_checkout".to_owned(),
                passed: outside_git,
                blocking: true,
                message: "production state cannot live in a git checkout".to_owned(),
            },
            OperationsCheck {
                name: "release_executable_present".to_owned(),
                passed: executable_path.is_file(),
                blocking: true,
                message: path_ref(executable_path),
            },
            OperationsCheck {
                name: "config_present".to_owned(),
                passed: config_path.is_file(),
                blocking: true,
                message: path_ref(config_path),
            },
        ];
        let ready = preflight
            .iter()
            .all(|check| !check.blocking || check.passed);
        let quoted_root = powershell_quote(&path_ref(proposed_data_root));
        ProductionCutoverManifest {
            manifest_id: format!("cutover-{}", WriteId::new_v7()),
            status: if ready {
                "READY_FOR_OPERATOR_CUTOVER"
            } else {
                "BLOCKED_PREFLIGHT"
            }
            .to_owned(),
            current_data_root: path_ref(current_data_root),
            proposed_data_root: path_ref(proposed_data_root),
            config_path: path_ref(config_path),
            executable_path: path_ref(executable_path),
            preflight,
            exact_changes: vec![
                format!("create production data-root {quoted_root}"),
                "copy release config template and set storage/credential_ref".to_owned(),
                "install Windows service only after operator approval".to_owned(),
                "start service and run authenticated doctor/backup smoke".to_owned(),
            ],
            operator_commands: vec![
                format!("New-Item -ItemType Directory -Force -Path {quoted_root}"),
                format!(
                    "& {} --config {} doctor run --offline",
                    powershell_quote(&path_ref(executable_path)),
                    powershell_quote(&path_ref(config_path))
                ),
            ],
            rollback_commands: vec![
                "Stop-Service -Name EliotGovernor -ErrorAction SilentlyContinue".to_owned(),
                "restore the previous service ImagePath and data-root config".to_owned(),
                "Start-Service -Name EliotGovernor".to_owned(),
            ],
            approval_required: true,
            dry_run: true,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub fn incident_blocks_unsafe_surfaces(incident: &IncidentRecord) -> bool {
    matches!(
        incident.status,
        IncidentStatus::Open | IncidentStatus::Acknowledged
    ) && matches!(
        incident.severity,
        IncidentSeverity::Blocking | IncidentSeverity::Critical
    )
}

fn open_skill_curation_proposals(root: &Path) -> usize {
    let path = root
        .join("reports")
        .join("skill-curation-proposals")
        .join("latest.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return 0;
    };
    value
        .get("open_proposals")
        .and_then(serde_json::Value::as_array)
        .map_or_else(
            || {
                value
                    .get("proposals")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len)
            },
            Vec::len,
        )
}

fn open_replay_requirements(root: &Path) -> usize {
    let sleep = root.join("reports").join("sleep").join("latest.json");
    let dream = root.join("reports").join("dream").join("latest.json");
    [sleep, dream]
        .iter()
        .filter(|path| report_has_required_replay(path))
        .count()
}

fn report_has_required_replay(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    value
        .pointer("/replay_requirement/required")
        .or_else(|| value.pointer("/candidate/required_replay/required"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn mode_profile_id(mode: DataRootMode) -> &'static str {
    match mode {
        DataRootMode::DevProjectLocal => "dev-project-local",
        DataRootMode::ProductionLocal => "production-local",
        DataRootMode::RecoveryOffline => "recovery-offline",
        DataRootMode::TestIsolated => "test-isolated",
    }
}

fn profile_dirs(profile: &DataRootProfile) -> [&str; 12] {
    [
        &profile.store_root,
        &profile.blob_root,
        &profile.backup_root,
        &profile.export_root,
        &profile.import_root,
        &profile.report_root,
        &profile.log_root,
        &profile.spool_root,
        &profile.worktree_root,
        &profile.incident_root,
        &profile.config_root,
        &profile.tmp_root,
    ]
}

fn path_ref(path: impl AsRef<Path>) -> PathRef {
    path.as_ref().display().to_string()
}

fn push_check(checks: &mut Vec<DataRootCheck>, name: &str, passed: bool, message: &str) {
    checks.push(DataRootCheck {
        name: name.to_owned(),
        status: if passed {
            DataRootCheckStatus::Pass
        } else {
            DataRootCheckStatus::Error
        },
        message: message.to_owned(),
    });
}

fn write_probe(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(".eliot-h0-write-probe");
    fs::write(&path, b"probe")?;
    fs::remove_file(path)?;
    Ok(())
}

fn contains_secret_like_config(config_root: &Path) -> bool {
    list_files_bounded(config_root, 256).is_ok_and(|files| {
        files.into_iter().any(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            name.contains("password") || name.contains("secret") || name.contains("credential")
        })
    })
}

fn is_inside_git_repo(path: &Path) -> bool {
    path.ancestors()
        .any(|ancestor| ancestor.join(".git").exists())
}

fn same_or_active_root(root: &Path, target: &Path) -> bool {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    target == root || target.starts_with(root)
}

fn target_is_empty_or_missing(path: &Path) -> Result<bool, EngineError> {
    if !path.exists() {
        return Ok(true);
    }
    Ok(fs::read_dir(path)?.next().is_none())
}

fn target_contains_only_storage(target: &Path, storage: &Path) -> bool {
    let target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    let storage = storage
        .canonicalize()
        .unwrap_or_else(|_| storage.to_path_buf());
    if !storage.starts_with(&target) || target.join("restore-evidence").exists() {
        return false;
    }
    let Ok(entries) = fs::read_dir(&target) else {
        return false;
    };
    entries.filter_map(Result::ok).all(|entry| {
        let path = entry.path();
        storage == path || storage.starts_with(&path)
    })
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.canonicalize().unwrap_or_else(|_| left.to_path_buf())
        == right.canonicalize().unwrap_or_else(|_| right.to_path_buf())
}

fn write_json_file<T>(path: impl AsRef<Path>, value: &T) -> Result<(), EngineError>
where
    T: Serialize + ?Sized,
{
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    serde_json::to_writer_pretty(fs::File::create(path)?, value)?;
    Ok(())
}

fn checksum_file(path: &Path) -> Result<BackupChecksum, EngineError> {
    let bytes = fs::read(path)?;
    Ok(BackupChecksum {
        algorithm: "blake3".to_owned(),
        path: path_ref(path),
        digest_hex: blake3::hash(&bytes).to_hex().to_string(),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    })
}

fn validate_backup_selector(backup: &str) -> Result<(), EngineError> {
    if backup.is_empty()
        || backup == "."
        || backup == ".."
        || !backup
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(service_error(
            "backup",
            "backup selector must be one safe inventory identifier",
        ));
    }
    Ok(())
}

fn verify_declared_checksum(
    path: &Path,
    checksums: &[BackupChecksum],
    context: &str,
) -> Result<(), EngineError> {
    let declared = checksums
        .iter()
        .find(|checksum| same_path(Path::new(&checksum.path), path))
        .ok_or_else(|| service_error("backup", format!("{context} has no declared checksum")))?;
    let actual = checksum_file(path)?;
    if actual.digest_hex != declared.digest_hex || actual.size_bytes != declared.size_bytes {
        return Err(service_error(
            "backup",
            format!("{context} differs from its declared checksum"),
        ));
    }
    Ok(())
}

fn copy_blob_payloads_quiescent(
    source_root: &Path,
    destination_root: &Path,
    before: &BlobManifest,
) -> Result<Vec<BackupBlobEntry>, EngineError> {
    fs::create_dir_all(destination_root)?;
    let mut payloads = Vec::new();
    for blob in &before.blobs {
        let source = PathBuf::from(&blob.path);
        if fs::symlink_metadata(&source)?.file_type().is_symlink() {
            return Err(service_error("backup", "blob snapshot refuses symlinks"));
        }
        let relative = source
            .strip_prefix(source_root)
            .map_err(|_| service_error("backup", "blob path escaped configured blob root"))?;
        validate_relative_path(relative, "backup blob")?;
        let destination = destination_root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let source_before = checksum_file(&source)?;
        fs::copy(&source, &destination)?;
        let copied = checksum_file(&destination)?;
        let source_after = checksum_file(&source)?;
        if source_before.digest_hex != source_after.digest_hex
            || source_before.size_bytes != source_after.size_bytes
            || source_before.digest_hex != copied.digest_hex
            || source_before.size_bytes != copied.size_bytes
        {
            return Err(service_error(
                "backup",
                format!(
                    "blob changed during quiescent snapshot: {}",
                    source.display()
                ),
            ));
        }
        payloads.push(BackupBlobEntry {
            relative_path: path_ref(relative),
            backup_path: path_ref(&destination),
            checksum: copied,
        });
    }
    let after = BlobGcService::new(source_root).manifest()?;
    if before.blobs != after.blobs || before.total_bytes != after.total_bytes {
        return Err(service_error(
            "backup",
            "blob set changed during quiescent snapshot",
        ));
    }
    Ok(payloads)
}

fn verify_blob_payload_manifest(manifest: &BackupManifest) -> Result<(), EngineError> {
    if manifest.dry_run {
        return Ok(());
    }
    let payload_root = manifest
        .blob_payload_root
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| service_error("backup", "completed backup has no blob payload root"))?;
    ensure_path_within(
        &payload_root,
        Path::new(&manifest.backup_root),
        "blob payload root",
    )?;
    let blob_manifest: BlobManifest =
        serde_json::from_reader(fs::File::open(&manifest.blob_manifest_ref)?)?;
    if blob_manifest.blobs.len() != manifest.blob_payloads.len() {
        return Err(service_error(
            "backup",
            "blob payload count differs from source blob manifest",
        ));
    }
    for source_blob in &blob_manifest.blobs {
        let relative = Path::new(&source_blob.path)
            .strip_prefix(&blob_manifest.blob_root)
            .map_err(|_| service_error("backup", "blob manifest path escaped source root"))?;
        validate_relative_path(relative, "backup blob")?;
        let entry = manifest
            .blob_payloads
            .iter()
            .find(|entry| Path::new(&entry.relative_path) == relative)
            .ok_or_else(|| service_error("backup", "blob payload is missing"))?;
        let backup_path = PathBuf::from(&entry.backup_path);
        ensure_path_within(&backup_path, &payload_root, "blob payload")?;
        let actual = checksum_file(&backup_path)?;
        if actual.digest_hex != source_blob.blob_hash
            || actual.size_bytes != source_blob.size_bytes
            || actual.digest_hex != entry.checksum.digest_hex
            || actual.size_bytes != entry.checksum.size_bytes
        {
            return Err(service_error(
                "backup",
                format!("blob payload checksum mismatch: {}", backup_path.display()),
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path, context: &str) -> Result<(), EngineError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(service_error(
            "filesystem_boundary",
            format!(
                "{context} path is not a safe relative path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn ensure_path_within(path: &Path, root: &Path, context: &str) -> Result<(), EngineError> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !canonical_path.starts_with(&canonical_root) {
        return Err(service_error(
            "filesystem_boundary",
            format!("{context} escaped root {}", canonical_root.display()),
        ));
    }
    Ok(())
}

fn restore_action_hash(
    manifest: &BackupManifest,
    target: &Path,
    config: &SurrealLogicalConfig,
) -> Result<String, EngineError> {
    let material = serde_json::json!({
        "action": "restore_to_isolated_root",
        "backup_id": manifest.backup_id,
        "manifest_checksums": manifest.checksums,
        "target": path_ref(target),
        "endpoint": config.endpoint,
        "namespace": config.namespace,
        "database": config.database,
        "storage": config.storage_root.as_ref().map(path_ref),
    });
    Ok(blake3::hash(&serde_json::to_vec(&material)?)
        .to_hex()
        .to_string())
}

fn restore_blob_payloads(
    manifest: &BackupManifest,
    staging_root: &Path,
) -> Result<u64, EngineError> {
    let destination_root = staging_root.join("blobs");
    fs::create_dir_all(&destination_root)?;
    let mut restored = 0u64;
    for entry in &manifest.blob_payloads {
        let relative = Path::new(&entry.relative_path);
        validate_relative_path(relative, "restore blob")?;
        let source = PathBuf::from(&entry.backup_path);
        ensure_path_within(
            &source,
            Path::new(&manifest.backup_root),
            "restore blob source",
        )?;
        let destination = destination_root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&source, &destination)?;
        let actual = checksum_file(&destination)?;
        if actual.digest_hex != entry.checksum.digest_hex
            || actual.size_bytes != entry.checksum.size_bytes
        {
            return Err(service_error(
                "restore",
                format!("restored blob checksum mismatch: {}", destination.display()),
            ));
        }
        restored = restored.saturating_add(1);
    }
    Ok(restored)
}

fn rollback_action_hash(target: &Path, evidence_hash: &str) -> Result<String, EngineError> {
    let material = serde_json::json!({
        "action": "rollback_isolated_restore_to_quarantine",
        "target": path_ref(target),
        "restore_evidence_hash": evidence_hash,
    });
    Ok(blake3::hash(&serde_json::to_vec(&material)?)
        .to_hex()
        .to_string())
}

fn rollback_quarantine_path(target: &Path, action_hash: &str) -> Result<PathBuf, EngineError> {
    let parent = target.parent().ok_or_else(|| {
        service_error(
            "restore_rollback",
            "rollback target has no parent directory",
        )
    })?;
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| service_error("restore_rollback", "rollback target name is invalid"))?;
    let suffix = action_hash.get(..12).unwrap_or(action_hash);
    let quarantine = parent.join(format!("{name}.rolled-back-{suffix}"));
    if quarantine.exists() {
        return Err(service_error(
            "restore_rollback",
            "rollback quarantine target already exists",
        ));
    }
    Ok(quarantine)
}

fn list_files_bounded(root: &Path, limit: usize) -> Result<Vec<PathBuf>, EngineError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
                if files.len() >= limit {
                    return Ok(files);
                }
            }
        }
    }
    Ok(files)
}

fn blob_is_in_grace(path: &str, now: OffsetDateTime, grace_seconds: i64) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| {
            OffsetDateTime::from(modified).checked_add(time::Duration::seconds(grace_seconds))
        })
        .is_none_or(|expires| expires > now)
}

fn service_error(service: &str, reason: impl Into<String>) -> EngineError {
    EngineError::ServiceNotReady {
        service: service.to_owned(),
        reason: reason.into(),
    }
}

fn ensure_command_success(
    command_name: &str,
    output: &std::process::Output,
) -> Result<(), EngineError> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let summary = stderr.lines().take(8).collect::<Vec<_>>().join(" | ");
    Err(service_error(
        "surreal_cli",
        format!("{command_name} failed with {}: {summary}", output.status),
    ))
}

fn snapshot_tree(
    source: &Path,
    destination: &Path,
    limit: usize,
) -> Result<Vec<String>, EngineError> {
    let mut copied = Vec::new();
    for path in list_files_bounded(source, limit)? {
        if fs::symlink_metadata(&path)?.file_type().is_symlink() || secret_like_path(&path) {
            continue;
        }
        let relative = path.strip_prefix(source).map_err(|error| {
            service_error(
                "backup",
                format!("snapshot path escaped source root: {error}"),
            )
        })?;
        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&path, &target)?;
        copied.push(path_ref(target));
    }
    Ok(copied)
}

fn secret_like_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let sensitive_extension = Path::new(&name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "key" | "pem" | "pfx" | "p12" | "kdbx"));
    name.contains("password")
        || name.contains("secret")
        || name.contains("credential")
        || name.contains("token")
        || name.contains("auth")
        || name == ".env"
        || name.starts_with(".env.")
        || matches!(name.as_str(), "id_rsa" | "id_ed25519")
        || sensitive_extension
}

fn contains_surql(path: &Path) -> Result<bool, EngineError> {
    if path.is_file() {
        return Ok(path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("surql")));
    }
    Ok(list_files_bounded(path, 1024)?.iter().any(|file| {
        file.extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("surql"))
    }))
}

fn import_json_files(path: &Path) -> Result<Vec<PathBuf>, EngineError> {
    if !path.exists() {
        return Err(service_error(
            "historical_import",
            format!("import path does not exist: {}", path.display()),
        ));
    }
    let files = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        list_files_bounded(path, 1024)?
    };
    Ok(files
        .into_iter()
        .filter(|file| {
            file.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        })
        .collect())
}

fn supported_historical_kind(kind: &str) -> bool {
    matches!(
        kind,
        "report"
            | "evidence"
            | "claim"
            | "failure"
            | "decision"
            | "experience"
            | "source_snapshot"
            | "verification"
    )
}

fn deterministic_write_id(idempotency_key: &str) -> Result<WriteId, EngineError> {
    let Some(hex_bytes) = idempotency_key.as_bytes().get(..32) else {
        return Err(service_error(
            "historical_import",
            "idempotency key is not a BLAKE3 hex digest",
        ));
    };
    if !hex_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(service_error(
            "historical_import",
            "idempotency key is not a BLAKE3 hex digest",
        ));
    }
    let hex = std::str::from_utf8(hex_bytes)
        .map_err(|error| service_error("historical_import", error.to_string()))?;
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    uuid.parse::<WriteId>().map_err(|error| {
        service_error(
            "historical_import",
            format!("failed to derive deterministic write id: {error}"),
        )
    })
}

fn read_json_if_exists<T>(path: &Path) -> Result<Option<T>, EngineError>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(fs::File::open(path)?)?))
}

fn gc_approval_hash(
    candidates: &[BlobDeletionCandidate],
    manifest_hash: &str,
    reference_snapshot: &BlobReferenceSnapshot,
    generated_at: OffsetDateTime,
) -> Result<String, EngineError> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "candidates": candidates,
        "manifest_hash": manifest_hash,
        "reference_snapshot_id": reference_snapshot.snapshot_id,
        "source_store": reference_snapshot.source_store,
        "source_revision": reference_snapshot.source_revision,
        "scope": reference_snapshot.scope,
        "query_hash": reference_snapshot.query_hash,
        "generated_at": generated_at,
    }))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn manifest_content_hash(manifest: &BlobManifest) -> Result<String, EngineError> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "blob_root": manifest.blob_root,
        "checksum_algorithm": manifest.checksum_algorithm,
        "blobs": manifest.blobs,
    }))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn reference_hashes(snapshot: &BlobReferenceSnapshot) -> (BTreeSet<String>, BTreeSet<String>) {
    let reachable = snapshot
        .reachable_refs
        .iter()
        .map(|reference| reference.blob_hash.clone())
        .collect();
    let retained = snapshot
        .retention_refs
        .iter()
        .filter(|reference| {
            matches!(
                reference.retention,
                BlobRetentionClass::AuditRetained | BlobRetentionClass::LegalHold
            )
        })
        .map(|reference| reference.blob_hash.clone())
        .collect();
    (reachable, retained)
}

fn validate_manifest_scope(
    manifest: &BlobManifest,
    expected_root: &Path,
) -> Result<(), EngineError> {
    if manifest.blob_root != path_ref(expected_root) {
        return Err(service_error(
            "blob_gc",
            "blob manifest root differs from the GC service root",
        ));
    }
    Ok(())
}

fn validate_reference_snapshot(
    snapshot: &BlobReferenceSnapshot,
    expected_scope: &str,
) -> Result<(), EngineError> {
    if !snapshot.complete {
        return Err(service_error(
            "blob_gc",
            "canonical blob-reference scan is incomplete",
        ));
    }
    if snapshot.snapshot_id.is_empty()
        || snapshot.source_store.is_empty()
        || snapshot.source_revision.is_empty()
        || snapshot.query_hash.is_empty()
    {
        return Err(service_error(
            "blob_gc",
            "canonical blob-reference scan lacks evidence bindings",
        ));
    }
    if snapshot.scope != expected_scope {
        return Err(service_error(
            "blob_gc",
            "canonical blob-reference scan scope differs from the blob manifest root",
        ));
    }
    let now = OffsetDateTime::now_utc();
    let age = now - snapshot.created_at;
    if snapshot.created_at > now || age.whole_seconds() > GC_REFERENCE_SNAPSHOT_MAX_AGE_SECONDS {
        return Err(service_error(
            "blob_gc",
            "canonical blob-reference scan is stale or from the future",
        ));
    }
    Ok(())
}

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn path_is_sync_root(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    ["onedrive", "dropbox", "google drive", "googledrive"]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn native_probe(executable: &str, args: &[&str]) -> (bool, String) {
    match Command::new(executable).args(args).output() {
        Ok(output) => {
            let text = if output.status.success() {
                String::from_utf8_lossy(&output.stdout)
            } else {
                String::from_utf8_lossy(&output.stderr)
            };
            (
                output.status.success(),
                text.lines().take(3).collect::<Vec<_>>().join(" | "),
            )
        }
        Err(error) => (false, error.to_string()),
    }
}

fn disk_space_probe(path: &Path) -> (bool, String) {
    let volume = windows_volume(path);
    let fsutil = native_probe("fsutil", &["volume", "diskfree", &volume]);
    if fsutil.0 {
        return fsutil;
    }
    let drive = volume.trim_end_matches([':', '\\']);
    let script = format!(
        "$drive = Get-PSDrive -Name '{drive}' -ErrorAction Stop; [Console]::Out.Write($drive.Free)"
    );
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match stdout.trim().parse::<u64>() {
                Ok(free_bytes) => (
                    free_bytes >= MIN_OPERATIONS_FREE_BYTES,
                    format!(
                        "volume={volume} free_bytes={free_bytes} required_bytes={MIN_OPERATIONS_FREE_BYTES} probe=Get-PSDrive"
                    ),
                ),
                Err(error) => (
                    false,
                    format!(
                        "fsutil unavailable: {}; Get-PSDrive returned an invalid byte count: {error}",
                        fsutil.1
                    ),
                ),
            }
        }
        Ok(output) => (
            false,
            format!(
                "fsutil unavailable: {}; Get-PSDrive failed: {}",
                fsutil.1,
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(error) => (
            false,
            format!(
                "fsutil unavailable: {}; Get-PSDrive unavailable: {error}",
                fsutil.1
            ),
        ),
    }
}

fn operator_contract_source_matches(repo_root: &Path) -> bool {
    fs::read_to_string(
        repo_root
            .join("apps")
            .join("Eliot.Operator")
            .join("Protocol")
            .join("OperatorContracts.cs"),
    )
    .is_ok_and(|content| {
        content.contains(OPERATOR_SCHEMA_VERSION)
            && content.contains(OPERATOR_IPC_PROTOCOL_VERSION)
            && content.contains(&operator_contract_hash())
    })
}

fn active_runtime_owner_pids(root: &Path) -> Vec<u32> {
    [
        root.join("runtime").join("daemon.lock"),
        root.join("runtime").join("service.lock"),
    ]
    .into_iter()
    .filter_map(|path| fs::read_to_string(path).ok())
    .filter_map(|content| {
        content
            .split(|character: char| !character.is_ascii_digit())
            .find_map(|part| part.parse::<u32>().ok())
    })
    .filter(|pid| process_is_alive(*pid))
    .collect()
}

fn process_is_alive(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
        })
}

fn unreceipted_import_count(root: &Path) -> Result<usize, EngineError> {
    let envelope_root = root.join("imports").join("envelopes");
    let receipt_root = root.join("imports").join("receipts");
    if !envelope_root.is_dir() {
        return Ok(0);
    }
    Ok(fs::read_dir(envelope_root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .filter(|path| {
            path.file_name()
                .is_none_or(|name| !receipt_root.join(name).is_file())
        })
        .count())
}

fn endpoint_route_health(endpoint: &str) -> (bool, String) {
    let authority = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, value)| value)
        .split('/')
        .next()
        .unwrap_or_default();
    let address = authority
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next());
    let Some(address) = address else {
        return (false, format!("endpoint route is invalid: {endpoint}"));
    };
    match TcpStream::connect_timeout(&address, std::time::Duration::from_millis(300)) {
        Ok(_) => (true, format!("endpoint route reachable: {address}")),
        Err(error) => (
            false,
            format!("endpoint route unavailable: {address}: {error}"),
        ),
    }
}

fn windows_volume(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.as_bytes().get(1) == Some(&b':') {
        format!("{}\\", &text[..2])
    } else {
        path_ref(path)
    }
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn stale_locks(root: &Path, repo_root: &Path) -> Vec<String> {
    [
        root.join("runtime").join("daemon.lock"),
        repo_root
            .join("target")
            .join("eliot-governor-shared-db-test.lock"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(path_ref)
    .collect()
}

fn crate_absent(repo_root: &Path, crate_name: &str) -> bool {
    let Ok(lock) = fs::read_to_string(repo_root.join("Cargo.lock")) else {
        return true;
    };
    !lock
        .lines()
        .any(|line| line.trim() == format!("name = \"{crate_name}\""))
}

#[cfg(test)]
mod security_tests {
    use super::secret_like_path;
    use std::path::Path;

    #[test]
    fn backup_secret_filter_covers_common_credential_artifacts() {
        for sensitive in [
            ".env",
            ".env.production",
            "access-token.txt",
            "auth.json",
            "certificate.pfx",
            "certificate.p12",
            "vault.kdbx",
            "id_rsa",
            "id_ed25519",
            "surreal_root_password.txt",
        ] {
            assert!(secret_like_path(Path::new(sensitive)), "{sensitive}");
        }
        for safe in ["eliot-governor.toml", "policy.json", "runbook.md"] {
            assert!(!secret_like_path(Path::new(safe)), "{safe}");
        }
    }
}
