//! Backup/restore class entrypoints (issue #1873).
//!
//! Argument decoding plus typed calls into `eliot_backup::product_command`
//! (class parsing, create/restore previews) and the `product_run` issuance and
//! isolated-execution entrypoints, plus the portable-recovery key coverage
//! check. Previews never issue or execute; `issue` persists validated archives
//! with class receipts, and `restore-run` executes only into a temp-enforced
//! isolated root with no cutover. Library mismatches print as JSON reports
//! with a nonzero exit; only input errors share the invalid-request exit.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use eliot_backup::{
    BackupBundle, BackupCreateArgs, RestoreContext, RestoreEpochSpec, WrappedKeyManifest,
    issue_backup, preview_backup_create, preview_restore, run_restore, verify_key_coverage,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
use serde_json::json;

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Preview one backup creation: parse the class and check it against the
    /// structural selection without issuing anything.
    CreatePreview {
        /// Backup identity the preview binds.
        #[arg(long)]
        backup_id: String,
        /// Requested class (`full_recovery`, `canonical_only_degraded`, `scope_export`).
        #[arg(long)]
        class: String,
        /// Declared scope for scope transfers; absent for installation exports.
        #[arg(long)]
        scope_id: Option<String>,
        /// Whether a self-consistent ORS snapshot is present.
        #[arg(long, default_value_t = false)]
        ors_present: bool,
    },
    /// Preview one restore plan from a bundle file without executing it.
    RestorePreview {
        /// Absolute path to the bundle JSON file.
        #[arg(long, value_parser = crate::absolute_path)]
        bundle_json: PathBuf,
        /// Isolated-restore target identity (planning input, not authority).
        #[arg(long)]
        target_id: String,
        /// Target authority lineage UUID (planning input, not authority).
        #[arg(long)]
        target_lineage: String,
        /// Target authority sequence (planning input, not authority).
        #[arg(long)]
        target_sequence: u64,
        /// Target Host/Kernel resource generation (planning input).
        #[arg(long)]
        target_generation: u64,
    },
    /// Check wrapped-key coverage for a bundle file plus a key-manifest file.
    KeyCoverage {
        /// Absolute path to the bundle JSON file.
        #[arg(long, value_parser = crate::absolute_path)]
        bundle_json: PathBuf,
        /// Absolute path to the wrapped-key manifest JSON file.
        #[arg(long, value_parser = crate::absolute_path)]
        key_manifest_json: PathBuf,
    },
    /// Issue one backup archive from an exporter-assembled export file.
    Issue {
        /// Absolute path to the exporter-assembled export (`BackupInput`) JSON file.
        #[arg(long, value_parser = crate::absolute_path)]
        export_json: PathBuf,
        /// Absolute path to the wrapped-key manifest JSON file, when the
        /// archive carries sealed blobs.
        #[arg(long, value_parser = crate::absolute_path)]
        key_manifest_json: Option<PathBuf>,
        /// Absolute output directory for the bundle, receipts, and report.
        #[arg(long, value_parser = crate::absolute_path)]
        out_dir: PathBuf,
        /// Re-issue a `full_recovery` request that cannot meet its denominator
        /// as explicitly labeled `canonical_only_degraded` instead of failing.
        #[arg(long, default_value_t = false)]
        allow_degraded: bool,
    },
    /// Execute one isolated restore of a bundle file into a temp-enforced root.
    RestoreRun {
        /// Absolute path to the bundle JSON file.
        #[arg(long, value_parser = crate::absolute_path)]
        bundle_json: PathBuf,
        /// Absolute path to the wrapped-key manifest JSON file, when the
        /// archive carries sealed blobs.
        #[arg(long, value_parser = crate::absolute_path)]
        key_manifest_json: Option<PathBuf>,
        /// Isolated-restore target identity (planning input, not authority).
        #[arg(long)]
        target_id: String,
        /// Target authority lineage UUID for an explicit epoch (planning input).
        #[arg(long)]
        target_lineage: Option<String>,
        /// Target authority sequence for an explicit epoch (planning input).
        #[arg(long)]
        target_sequence: Option<u64>,
        /// Target Host/Kernel resource generation for an explicit epoch.
        #[arg(long)]
        target_generation: Option<u64>,
        /// Fresh activation lineage UUID: mints a genesis epoch on a new
        /// lineage one generation past the archived source fence instead of
        /// the explicit triple. Mutually exclusive with the triple.
        #[arg(long)]
        new_lineage: Option<String>,
    },
}

fn read_json(path: &Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {what}"))
}

fn target_context(
    target_id: &str,
    lineage: &str,
    sequence: u64,
    generation: u64,
) -> Result<RestoreContext> {
    let lineage_id =
        EpochLineageId::new(lineage).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let sequence =
        NonZeroU64::new(sequence).ok_or_else(|| anyhow::anyhow!("sequence must be nonzero"))?;
    Ok(RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: EpochId::new(lineage_id, sequence)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        target_resource_generation: ResourceGeneration::new(generation)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    })
}

pub fn run_backup(command: BackupCommand) -> Result<i32> {
    match command {
        BackupCommand::CreatePreview {
            backup_id,
            class,
            scope_id,
            ors_present,
        } => run_create_preview(&backup_id, &class, scope_id.as_deref(), ors_present),
        BackupCommand::RestorePreview {
            bundle_json,
            target_id,
            target_lineage,
            target_sequence,
            target_generation,
        } => run_restore_preview(
            &bundle_json,
            &target_id,
            &target_lineage,
            target_sequence,
            target_generation,
        ),
        BackupCommand::KeyCoverage {
            bundle_json,
            key_manifest_json,
        } => run_key_coverage(&bundle_json, &key_manifest_json),
        BackupCommand::Issue {
            export_json,
            key_manifest_json,
            out_dir,
            allow_degraded,
        } => run_issue(
            &export_json,
            key_manifest_json.as_deref(),
            &out_dir,
            allow_degraded,
        ),
        BackupCommand::RestoreRun {
            bundle_json,
            key_manifest_json,
            target_id,
            target_lineage,
            target_sequence,
            target_generation,
            new_lineage,
        } => run_restore_run(
            &bundle_json,
            key_manifest_json.as_deref(),
            &target_id,
            target_lineage.as_deref(),
            target_sequence,
            target_generation,
            new_lineage.as_deref(),
        ),
    }
}

fn run_create_preview(
    backup_id: &str,
    class: &str,
    scope_id: Option<&str>,
    ors_present: bool,
) -> Result<i32> {
    // `preview_backup_create` parses the class string itself, so
    // unknown names fail with the same JSON report shape below.
    match preview_backup_create(
        &BackupCreateArgs {
            backup_id: backup_id.to_owned(),
            class: class.to_owned(),
            scope_id: scope_id.map(str::to_owned),
        },
        ors_present,
    ) {
        Ok(preview) => {
            println!("{}", serde_json::to_string_pretty(&preview)?);
            Ok(0)
        }
        Err(error) => {
            crate::write_installation_error("BACKUP_CREATE_PREVIEW_INVALID", &error.to_string());
            Ok(crate::INVALID_REQUEST_EXIT)
        }
    }
}

fn run_restore_preview(
    bundle_json: &Path,
    target_id: &str,
    target_lineage: &str,
    target_sequence: u64,
    target_generation: u64,
) -> Result<i32> {
    let bytes = read_json(bundle_json, "bundle file")?;
    let bundle =
        BackupBundle::decode(&bytes).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let target = target_context(
        target_id,
        target_lineage,
        target_sequence,
        target_generation,
    )?;
    match preview_restore(&bundle, &target) {
        Ok(preview) => {
            println!("{}", serde_json::to_string_pretty(&preview)?);
            Ok(0)
        }
        Err(error) => {
            crate::write_installation_error("BACKUP_RESTORE_PREVIEW_INVALID", &error.to_string());
            Ok(crate::INVALID_REQUEST_EXIT)
        }
    }
}

fn run_key_coverage(bundle_json: &Path, key_manifest_json: &Path) -> Result<i32> {
    let bundle = BackupBundle::decode(&read_json(bundle_json, "bundle file")?)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let manifest: WrappedKeyManifest =
        serde_json::from_slice(&read_json(key_manifest_json, "key manifest file")?)
            .with_context(|| "parse key manifest file")?;
    manifest
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    match verify_key_coverage(&bundle.blobs, &manifest) {
        Ok(()) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "covered": true,
                    "backup_id": bundle.manifest.backup_id,
                    "manifest_id": manifest.manifest_id,
                }))?
            );
            Ok(0)
        }
        Err(error) => {
            crate::write_installation_error("BACKUP_KEY_COVERAGE_INVALID", &error.to_string());
            Ok(crate::INVALID_REQUEST_EXIT)
        }
    }
}

fn run_issue(
    export_json: &Path,
    key_manifest_json: Option<&Path>,
    out_dir: &Path,
    allow_degraded: bool,
) -> Result<i32> {
    let export_bytes = read_json(export_json, "export file")?;
    let key_bytes = key_manifest_json
        .as_ref()
        .map(|path| read_json(path, "key manifest file"))
        .transpose()?;
    match issue_backup(&export_bytes, key_bytes.as_deref(), out_dir, allow_degraded) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        Err(error) => {
            crate::write_installation_error("BACKUP_ISSUE_INVALID", &error.to_string());
            Ok(crate::INVALID_REQUEST_EXIT)
        }
    }
}

fn run_restore_run(
    bundle_json: &Path,
    key_manifest_json: Option<&Path>,
    target_id: &str,
    target_lineage: Option<&str>,
    target_sequence: Option<u64>,
    target_generation: Option<u64>,
    new_lineage: Option<&str>,
) -> Result<i32> {
    let epoch_spec = match (
        new_lineage,
        target_lineage,
        target_sequence,
        target_generation,
    ) {
        (Some(lineage), None, None, None) => RestoreEpochSpec::NewLineage {
            lineage: lineage.to_owned(),
        },
        (None, Some(lineage), Some(sequence), Some(generation)) => RestoreEpochSpec::Explicit {
            lineage: lineage.to_owned(),
            sequence,
            generation,
        },
        _ => {
            crate::write_installation_error(
                "BACKUP_RESTORE_RUN_INVALID",
                "pass either --new-lineage or the full --target-lineage/--target-sequence/--target-generation triple",
            );
            return Ok(crate::INVALID_REQUEST_EXIT);
        }
    };
    let bundle_bytes = read_json(bundle_json, "bundle file")?;
    let key_bytes = key_manifest_json
        .as_ref()
        .map(|path| read_json(path, "key manifest file"))
        .transpose()?;
    match run_restore(
        &bundle_bytes,
        key_bytes.as_deref(),
        target_id,
        &epoch_spec,
        "backup-restore",
    ) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        Err(error) => {
            crate::write_installation_error("BACKUP_RESTORE_RUN_INVALID", &error.to_string());
            Ok(crate::INVALID_REQUEST_EXIT)
        }
    }
}
