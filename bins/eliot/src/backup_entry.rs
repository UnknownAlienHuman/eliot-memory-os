//! Backup/restore class entrypoints (issue #1873, extended by #963).
//!
//! Argument decoding plus typed calls into `eliot_backup::product_command`
//! (class parsing, create/restore previews) and the `product_run` issuance and
//! isolated-execution entrypoints, plus the portable-recovery key coverage
//! check. Previews never issue or execute; `issue` persists validated archives
//! with class receipts, and `restore-run` executes only into a temp-enforced
//! isolated root with no cutover. Library mismatches print as JSON reports
//! with a nonzero exit; only input errors share the invalid-request exit.
//!
//! The three advertised `create` / `verify` / `restore-test` catalogue
//! commands (#963) are the other half of this tree. They carry no typed
//! field on argv: each one reads exactly one admitted
//! [`eliot_cli::CommandRequest`] from the same JSON channel `eliot dispatch`
//! reads, because the correlated `RequestIdentity` — principal, session,
//! fence, deadline, and idempotency identity — belongs to the admitted
//! host-request path and the CLI never mints one. The bounded typed fields
//! therefore arrive inside that admitted envelope, where the closed parsers
//! in `eliot_cli::backup` admit them; a request that names another command,
//! omits a required field, or carries a defaulted scope or destination
//! refuses as a typed usage failure before any byte reaches the Kernel.

use std::io::Read;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use eliot_backup::{
    BackupBundle, BackupCreateArgs, RestoreContext, RestoreEpochSpec, WrappedKeyManifest,
    issue_backup, preview_backup_create, preview_restore, run_restore, verify_key_coverage,
};
use eliot_cli::{CommandId, CommandRequest};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
use serde_json::json;

/// Maximum admitted bytes for one backup command request read from the
/// operator front door.
///
/// Bounded by the closed archive bound byte-exact: a 1 MiB archive becomes
/// 2 MiB of lowercase hex inside the request envelope, and 3 MiB leaves
/// envelope headroom without admitting an unbounded stream.
const BACKUP_REQUEST_INPUT_LIMIT: u64 = 3 * 1024 * 1024;

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
        ///
        /// This is a preview input only: it selects no capture, writes no
        /// archive, and never becomes a default for the routed
        /// `create` command, which requires an explicit scope descriptor and
        /// an explicit class.
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
    /// Route the advertised `backup-create` command through the
    /// authenticated Kernel front door.
    ///
    /// Reads exactly one admitted `backup-create` command request from
    /// standard input, with the explicit `scope_descriptor` and `class`
    /// typed fields the closed parser requires. Neither is ever defaulted,
    /// and a create request is never satisfied by a preview.
    Create,
    /// Route the advertised `backup-verify` command through the
    /// authenticated Kernel front door.
    ///
    /// Reads exactly one admitted `backup-verify` command request from
    /// standard input, with the explicit bounded `bundle_hex` archive bytes
    /// the closed parser requires. Verification is bounded: it never
    /// restores and never changes an installation.
    Verify,
    /// Route the advertised `backup-restore-test` command through the
    /// authenticated Kernel front door.
    ///
    /// Reads exactly one admitted `backup-restore-test` command request from
    /// standard input, with every explicit binding the closed parser
    /// requires. The rehearsal is isolated and never cuts over, retires the
    /// source, or selects an installation change.
    RestoreTest,
}

fn read_json(path: &Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {what}"))
}

/// Reads exactly one admitted backup command request from the operator front
/// door.
///
/// The read is bounded by [`BACKUP_REQUEST_INPUT_LIMIT`] and never truncated:
/// an oversized stream refuses instead of delivering a partial request. The
/// correlated `RequestIdentity` inside that envelope is the only correlation
/// this process ever uses — the CLI never mints principal, session, fence,
/// deadline, or idempotency identity — and a blank stream is exactly as
/// unadmitted as a malformed one.
fn read_admitted_backup_request() -> Result<CommandRequest> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(BACKUP_REQUEST_INPUT_LIMIT + 1)
        .read_to_end(&mut input)
        .context("read the admitted backup command request")?;
    if input.len() as u64 > BACKUP_REQUEST_INPUT_LIMIT {
        anyhow::bail!(
            "the admitted backup command request exceeds the {BACKUP_REQUEST_INPUT_LIMIT} byte limit"
        );
    }
    if input.iter().all(u8::is_ascii_whitespace) {
        anyhow::bail!(
            "no admitted backup command request was supplied; the correlated request identity must arrive from the admitted host request path"
        );
    }
    serde_json::from_slice::<CommandRequest>(&input)
        .context("decode the admitted backup command request")
}

/// Routes one advertised backup catalogue command through the authenticated
/// Kernel front door.
///
/// The subcommand name is the operator's selection and the admitted request's
/// `command` is the typed one; they must agree exactly, so `eliot backup
/// verify` can never run a create or a restore rehearsal. Validation of the
/// bounded typed arguments runs before any byte reaches the Kernel, and a
/// missing, unknown, oversized, or non-isolated field is a typed usage
/// failure rather than a guessed production scope or a default production
/// destination.
fn run_routed_backup(expected: CommandId) -> Result<i32> {
    let request = match read_admitted_backup_request() {
        Ok(request) => request,
        Err(error) => {
            crate::write_installation_error("BACKUP_REQUEST_NOT_ADMITTED", &error.to_string());
            return Ok(crate::INVALID_REQUEST_EXIT);
        }
    };
    if let Err(error) = request.validate() {
        crate::write_installation_error("BACKUP_REQUEST_INVALID", &error.to_string());
        return Ok(crate::INVALID_REQUEST_EXIT);
    }
    if request.command != expected {
        crate::write_installation_error(
            "BACKUP_COMMAND_MISMATCH",
            &format!(
                "this subcommand routes {}, but the admitted request carries {}",
                expected.as_str(),
                request.command.as_str()
            ),
        );
        return Ok(crate::INVALID_REQUEST_EXIT);
    }
    crate::dispatch_backup_command(&request)
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
        BackupCommand::Create => run_routed_backup(CommandId::BackupCreate),
        BackupCommand::Verify => run_routed_backup(CommandId::BackupVerify),
        BackupCommand::RestoreTest => run_routed_backup(CommandId::BackupRestoreTest),
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
