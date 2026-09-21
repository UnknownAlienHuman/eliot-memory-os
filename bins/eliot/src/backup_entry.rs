//! Backup/restore class entrypoints (issue #1873).
//!
//! Argument decoding plus typed calls into `eliot_backup::product_command`
//! (class parsing, create/restore previews) and the portable-recovery key
//! coverage check. Preview-only: no issuance, execution, or cutover happens
//! here. Library mismatches print as JSON reports with a nonzero exit;
//! only input errors share the invalid-request exit.

use std::num::NonZeroU64;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use eliot_backup::{
    BackupBundle, BackupCreateArgs, RestoreContext, WrappedKeyManifest, preview_backup_create,
    preview_restore, verify_key_coverage,
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
}

fn read_json(path: &PathBuf, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {what}"))
}

fn target_context(
    target_id: String,
    lineage: &str,
    sequence: u64,
    generation: u64,
) -> Result<RestoreContext> {
    let lineage_id =
        EpochLineageId::new(lineage).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let sequence =
        NonZeroU64::new(sequence).ok_or_else(|| anyhow::anyhow!("sequence must be nonzero"))?;
    Ok(RestoreContext {
        target_id,
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
        } => {
            // `preview_backup_create` parses the class string itself, so
            // unknown names fail with the same JSON report shape below.
            match preview_backup_create(
                &BackupCreateArgs {
                    backup_id,
                    class,
                    scope_id,
                },
                ors_present,
            ) {
                Ok(preview) => {
                    println!("{}", serde_json::to_string_pretty(&preview)?);
                    Ok(0)
                }
                Err(error) => {
                    crate::write_installation_error(
                        "BACKUP_CREATE_PREVIEW_INVALID",
                        &error.to_string(),
                    );
                    Ok(crate::INVALID_REQUEST_EXIT)
                }
            }
        }
        BackupCommand::RestorePreview {
            bundle_json,
            target_id,
            target_lineage,
            target_sequence,
            target_generation,
        } => {
            let bytes = read_json(&bundle_json, "bundle file")?;
            let bundle =
                BackupBundle::decode(&bytes).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let target = target_context(
                target_id,
                &target_lineage,
                target_sequence,
                target_generation,
            )?;
            match preview_restore(&bundle, &target) {
                Ok(preview) => {
                    println!("{}", serde_json::to_string_pretty(&preview)?);
                    Ok(0)
                }
                Err(error) => {
                    crate::write_installation_error(
                        "BACKUP_RESTORE_PREVIEW_INVALID",
                        &error.to_string(),
                    );
                    Ok(crate::INVALID_REQUEST_EXIT)
                }
            }
        }
        BackupCommand::KeyCoverage {
            bundle_json,
            key_manifest_json,
        } => {
            let bundle = BackupBundle::decode(&read_json(&bundle_json, "bundle file")?)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let manifest: WrappedKeyManifest =
                serde_json::from_slice(&read_json(&key_manifest_json, "key manifest file")?)
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
                    crate::write_installation_error(
                        "BACKUP_KEY_COVERAGE_INVALID",
                        &error.to_string(),
                    );
                    Ok(crate::INVALID_REQUEST_EXIT)
                }
            }
        }
    }
}
