//! Bounded backup logical-export cluster.
//!
//! Architecture: `A13.7` (Backups, restore и migration) — canonical state + blobs + config/policy snapshots + manifest/checksums + purge ledger binding.
//! Architecture: `ARCH-RES-03` — Recovery cannot resurrect invalid state; backup/restore preserve history/purge/revocation/fencing.
//! Implementation: `I5.13` (Backup and restore) — explicit `full_recovery`/`canonical_only_degraded`/`scope_export` classes, `ExportFence`/`OrsSnapshotFence`, isolated restore, receipt verification.
//! Ownership: this child owns `BackupService` (`run`/`run_logical`/`build_backup`/`verify` + `list`/`read_manifest` and backup-owned helpers `copy_blob_payloads_quiescent`/`verify_blob_payload_manifest`/`validate_backup_selector`/`verify_declared_checksum`/`snapshot_tree`); parent `safety.rs` remains facade/re-export and retains shared filesystem/Surreal boundary helpers and unrelated services.

use std::fs;
use std::path::{Path, PathBuf};

use eliot_types::{
    BackupBlobEntry, BackupChecksum, BackupInventoryEntry, BackupKind, BackupManifest,
    BackupReceipt, BackupReport, BackupStatus, BlobManifest, SCHEMA_VERSION, WriteId,
};
use time::OffsetDateTime;

use crate::error::EngineError;

use super::{
    BlobGcService, GOVERNOR_VERSION, SurrealLogicalConfig, SurrealLogicalService, checksum_file,
    ensure_path_within, list_files_bounded, path_ref, same_path, secret_like_path, service_error,
    validate_relative_path, write_json_file,
};

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
