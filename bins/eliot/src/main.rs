#![forbid(unsafe_code)]
// Machine-readable and human CLI output is the public contract of this binary.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use eliot_bootstrap::capture::{capture_snapshot, write_snapshot_artifact};
use eliot_cli::{CommandCatalogue, CommandPort, CommandPortError, CommandRequest};
use eliot_installation::{
    GenerationPackagePlanInput, GenerationPackagePlanner, InstallationEpoch, InstallationError,
    InstallationProfile, InstallationStage, InstallationStepOutcome, InstallationTransaction,
    InstallationTransactionStore, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    decode_installation_transaction_json, parse_installation_transaction_id,
};
use eliot_platform_windows::{InstallerRootError, ProtectedRootLease, is_process_elevated};
use serde_json::json;
use std::path::PathBuf;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use tracing_subscriber::EnvFilter;

mod source_bundle_materializer;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const INVALID_REQUEST_EXIT: i32 = 2;
const FRONT_DOOR_CLOSED_EXIT: i32 = 69;
const INSTALLATION_INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const INSTALLATION_CONTRACT_VERSION: &str = "3.0.0";
const INSTALLATION_SCOPE: &str = "bounded_all_effects_or_exact_rollback";

#[derive(Debug, Parser)]
#[command(name = "eliot", about = "ELIOT Memory OS command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    Catalogue {
        #[command(subcommand)]
        command: CatalogueCommand,
    },
    /// Read one typed command request from stdin and forward it to Kernel.
    Dispatch,
    /// Compile an immutable current-system evidence artifact.
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },
    /// Inspect or validate the governed installation transaction surfaces.
    Installation {
        #[command(subcommand)]
        command: InstallationCommand,
    },
    /// Read the manifest-bound Runtime Live status contour.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Version,
    /// Start or reuse the authenticated User Broker and launch Operator.
    Ui,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum InstallationCommand {
    /// Derive one complete trusted generation transaction from explicit roots
    /// and installation identity. No candidate/package JSON is accepted here.
    #[command(alias = "plan-generation", alias = "generation-plan")]
    Generate {
        /// Absolute retained source bundle containing the exact nine-file Phase-A inventory.
        #[arg(long, value_parser = absolute_path)]
        source_root: PathBuf,
        /// Explicit installation profile (`system_service`, `user_mode`, or `portable_dev`).
        #[arg(long, value_parser = parse_installation_profile)]
        profile: InstallationProfile,
        /// Absolute OS-validated profile anchor root.
        #[arg(long, value_parser = absolute_path)]
        profile_anchor_root: PathBuf,
        /// Lowercase SHA-256 installation key; required for profiled installations.
        #[arg(long)]
        installation_key: Option<String>,
        /// Stable installation identity.
        #[arg(long)]
        installation: String,
        /// Stable lineage identity.
        #[arg(long)]
        lineage_id: String,
        /// Non-zero sequence within the lineage.
        #[arg(long)]
        sequence: u64,
        /// Canonical relative package generation identity.
        #[arg(long)]
        generation: String,
        /// Absolute immutable staging root.
        #[arg(long, value_parser = absolute_path)]
        staging_root: PathBuf,
        /// Stable transaction identity.
        #[arg(long)]
        transaction_id: String,
        /// Explicit non-zero Store-space policy value.
        #[arg(long)]
        minimum_store_available_bytes: u64,
        /// Explicit recovery command/reference retained by the transaction.
        #[arg(long)]
        recovery_command: String,
        /// Absolute new output JSON path. Its parent must already exist.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
        /// Optional exact transaction store to create from this planner output.
        #[arg(long, value_parser = absolute_path)]
        store: Option<PathBuf>,
    },
    /// Validate an immutable v8 installation plan JSON without applying it (untrusted import/validation only).
    Plan {
        /// Absolute path to an existing serialized `InstallationTransaction`.
        #[arg(long, value_parser = absolute_path)]
        input: PathBuf,
    },
    /// Retired raw transaction-import compatibility command.
    ///
    /// Production transaction creation is owned by `installation generate
    /// --store`; this command always rejects caller-authored JSON.
    Create {
        /// Absolute path to an existing serialized `InstallationTransaction`.
        #[arg(long, value_parser = absolute_path)]
        input: PathBuf,
        /// Absolute path to a new transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
    },
    /// Drive all durable effects through the bounded production coordinator loop.
    #[command(alias = "resume")]
    Apply {
        /// Absolute path to an existing transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
        /// Stable transaction identity retained in the durable store.
        #[arg(long)]
        transaction_id: String,
    },
    /// Reconcile and roll back a transaction already marked `ROLLBACK_REQUIRED`.
    Recover {
        /// Absolute path to an existing transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
        /// Stable transaction identity retained in the durable store.
        #[arg(long)]
        transaction_id: String,
    },
    /// Read the existing approved-generation registry without changing it.
    #[command(alias = "open")]
    Status {
        /// Absolute path to the retained per-installation Host state root.
        #[arg(long, value_parser = absolute_path)]
        host_state_root: PathBuf,
        /// Bounded deadline in milliseconds from now (default 2000).
        #[arg(long, default_value = "2000")]
        deadline_ms: u64,
    },
    /// Report the unsupported canary-removal seam without mutating the machine.
    RemoveCanary {
        /// Optional transaction store, accepted only to make the refusal scope explicit.
        #[arg(long, value_parser = absolute_path)]
        store: Option<PathBuf>,
        /// Optional transaction identity, accepted only to make the refusal scope explicit.
        #[arg(long)]
        transaction_id: Option<String>,
    },
    /// Materialize an exact nine-role Phase-A source bundle and feed it through
    /// the existing trusted Generate/Plan path.
    MaterializeSourceBundle {
        #[arg(long, value_parser = absolute_path)]
        eliot_host: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_watchdog: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_kernel: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_store_surreal: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        surreal: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliotd: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        output_bundle: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        store: Option<PathBuf>,
        #[arg(long)]
        generation: String,
        #[arg(long)]
        installation: String,
        #[arg(long)]
        lineage_id: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        transaction_id: String,
        #[arg(long, value_parser = absolute_path)]
        staging_root: PathBuf,
        #[arg(long)]
        minimum_store_available_bytes: u64,
        #[arg(long)]
        recovery_command: String,
        #[arg(long, value_parser = parse_installation_profile)]
        profile: InstallationProfile,
        #[arg(long, value_parser = absolute_path)]
        profile_anchor_root: PathBuf,
        #[arg(long)]
        installation_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    /// Emit the production Runtime Live status contract as JSON.
    Status {
        /// The machine-readable output contract is mandatory for this command.
        #[arg(long)]
        json: bool,
        /// Absolute path to the retained per-installation Host state root.
        #[arg(long, value_parser = absolute_path)]
        host_state_root: PathBuf,
        /// Bounded deadline in milliseconds from now (default 2000).
        #[arg(long, default_value = "2000")]
        deadline_ms: u64,
    },
}

#[derive(Debug, Subcommand)]
enum SystemCommand {
    /// Capture source/build/runtime/store/integration evidence.
    Snapshot {
        /// Absolute repository root. Git evidence is always scoped to this path.
        #[arg(long, value_parser = absolute_path)]
        repo_root: PathBuf,
        /// Absolute destination. Existing artifacts are never overwritten.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CatalogueCommand {
    Help,
    Schema,
    Validate,
}

fn main() -> Result<()> {
    let exit_code = std::thread::Builder::new()
        .name("eliot-cli-main".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(run)
        .context("spawn the CLI entrypoint")?
        .join()
        .map_err(|_| anyhow::anyhow!("CLI entrypoint panicked"))??;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn run() -> Result<i32> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("eliot {VERSION}");
            Ok(0)
        }
        Command::Catalogue { command } => {
            run_catalogue(&command)?;
            Ok(0)
        }
        Command::System { command } => run_system(command),
        Command::Installation { command } => run_installation(command),
        Command::Runtime { command } => run_runtime(command),
        Command::Dispatch => run_dispatch(),
        Command::Ui => run_ui(),
    }
}

fn run_runtime(command: RuntimeCommand) -> Result<i32> {
    match command {
        RuntimeCommand::Status {
            json,
            host_state_root,
            deadline_ms,
        } => {
            if !json {
                write_installation_error(
                    "RUNTIME_STATUS_JSON_REQUIRED",
                    "runtime status requires --json; no inspection or filesystem mutation was attempted",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            run_installation_runtime_status(&host_state_root, deadline_ms)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_installation(command: InstallationCommand) -> Result<i32> {
    match command {
        InstallationCommand::Generate {
            source_root,
            profile,
            profile_anchor_root,
            installation_key,
            installation,
            lineage_id,
            sequence,
            generation,
            staging_root,
            transaction_id,
            minimum_store_available_bytes,
            recovery_command,
            output,
            store,
        } => run_installation_generate(
            source_root,
            profile,
            profile_anchor_root,
            installation_key,
            installation,
            lineage_id,
            sequence,
            generation,
            staging_root,
            transaction_id,
            minimum_store_available_bytes,
            recovery_command,
            output,
            store,
        ),
        InstallationCommand::Plan { input } => {
            let bytes = match load_input(&input) {
                Ok(bytes) => bytes,
                Err(error) => {
                    write_installation_error("INSTALLATION_PLAN_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let transaction = match decode_installation_transaction_json(&bytes) {
                Ok(transaction) => transaction,
                Err(error @ InstallationError::MigrationRequired { .. }) => {
                    write_installation_error(
                        "INSTALLATION_PLAN_MIGRATION_REQUIRED",
                        &error.to_string(),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                Err(error) => {
                    write_installation_error("INSTALLATION_PLAN_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            println!("{}", serde_json::to_string_pretty(&transaction)?);
            Ok(0)
        }
        InstallationCommand::Create { input, store } => Ok(run_installation_create(&input, &store)),
        InstallationCommand::Apply {
            store,
            transaction_id,
        } => run_installation_effect(&store, &transaction_id, false),
        InstallationCommand::Recover {
            store,
            transaction_id,
        } => run_installation_effect(&store, &transaction_id, true),
        InstallationCommand::Status {
            host_state_root,
            deadline_ms,
        } => run_installation_runtime_status(&host_state_root, deadline_ms),
        InstallationCommand::RemoveCanary {
            store,
            transaction_id,
        } => {
            let scope = match (store, transaction_id) {
                (Some(store), Some(transaction_id)) => {
                    format!(" for transaction {transaction_id} in {}", store.display())
                }
                (Some(store), None) => format!(" for store {}", store.display()),
                (None, Some(transaction_id)) => format!(" for transaction {transaction_id}"),
                (None, None) => String::new(),
            };
            write_installation_error(
                "INSTALLATION_REMOVE_CANARY_UNSUPPORTED",
                &format!(
                    "remove-canary{scope} is not implemented: no durable canary removal, activation, or generation-retirement API exists; no filesystem or SCM mutation was attempted"
                ),
            );
            Ok(INVALID_REQUEST_EXIT)
        }
        InstallationCommand::MaterializeSourceBundle {
            eliot_host,
            eliot_watchdog,
            eliot_kernel,
            eliot_store_surreal,
            surreal,
            eliotd,
            output_bundle,
            output,
            store,
            generation,
            installation,
            lineage_id,
            sequence,
            transaction_id,
            staging_root,
            minimum_store_available_bytes,
            recovery_command,
            profile,
            profile_anchor_root,
            installation_key,
        } => run_installation_materialize_source_bundle(
            eliot_host,
            eliot_watchdog,
            eliot_kernel,
            eliot_store_surreal,
            surreal,
            eliotd,
            output_bundle,
            output,
            store,
            generation,
            installation,
            lineage_id,
            sequence,
            transaction_id,
            staging_root,
            minimum_store_available_bytes,
            recovery_command,
            profile,
            profile_anchor_root,
            installation_key,
        ),
    }
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn run_installation_generate(
    source_root: PathBuf,
    profile: InstallationProfile,
    profile_anchor_root: PathBuf,
    installation_key: Option<String>,
    installation: String,
    lineage_id: String,
    sequence: u64,
    generation: String,
    staging_root: PathBuf,
    transaction_id: String,
    minimum_store_available_bytes: u64,
    recovery_command: String,
    output: PathBuf,
    store_path: Option<PathBuf>,
) -> Result<i32> {
    let input = GenerationPackagePlanInput {
        transaction_id: cli_handle(transaction_id, "transaction_id")?,
        installation_epoch: InstallationEpoch {
            installation: cli_handle(installation, "installation")?,
            lineage_id: cli_handle(lineage_id, "lineage_id")?,
            sequence,
        },
        profile,
        profile_anchor_root: cli_path_handle(&profile_anchor_root, "profile_anchor_root")?,
        installation_key: installation_key
            .map(|value| cli_handle(value, "installation_key"))
            .transpose()?,
        generation: cli_handle(generation, "generation")?,
        source_root: cli_path_handle(&source_root, "source_root")?,
        staging_root: cli_path_handle(&staging_root, "staging_root")?,
        minimum_store_available_bytes,
        recovery_command: cli_handle(recovery_command, "recovery_command")?,
    };
    let transaction = match GenerationPackagePlanner::plan(input) {
        Ok(transaction) => transaction,
        Err(error) => {
            write_installation_error("INSTALLATION_GENERATION_REJECTED", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if let Some(store_path) = &store_path
        && let Err(error) =
            RedbInstallationTransactionStore::create_planned_at_exact_path(store_path, &transaction)
    {
        write_installation_error("INSTALLATION_GENERATION_STORE_REJECTED", &error.to_string());
        return Ok(INVALID_REQUEST_EXIT);
    }
    write_transaction_artifact(&output, &transaction)
        .map_err(|error| anyhow::anyhow!("write generated installation transaction: {error}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "GENERATED",
            "transaction_id": transaction.transaction_id,
            "generation": transaction.candidate_manifest.generation,
            "profile": transaction.profile,
            "effect_count": transaction.effect_progress().len(),
            "package_file_count": transaction
                .installer_effects
                .iter()
                .find_map(|effect| match effect {
                    eliot_installation::InstallerEffectPlan::StagePackage { manifest, .. } => {
                        Some(manifest.files.len())
                    }
                    _ => None,
                })
                .unwrap_or(0),
            "output": output.display().to_string(),
            "store": store_path.as_ref().map(|path| path.display().to_string()),
            "scope": "trusted_generation_planner_only",
        }))?
    );
    Ok(0)
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn run_installation_materialize_source_bundle(
    eliot_host: PathBuf,
    eliot_watchdog: PathBuf,
    eliot_kernel: PathBuf,
    eliot_store_surreal: PathBuf,
    surreal: PathBuf,
    eliotd: PathBuf,
    output_bundle: PathBuf,
    output: PathBuf,
    store: Option<PathBuf>,
    generation: String,
    installation: String,
    lineage_id: String,
    sequence: u64,
    transaction_id: String,
    staging_root: PathBuf,
    minimum_store_available_bytes: u64,
    recovery_command: String,
    profile: InstallationProfile,
    profile_anchor_root: PathBuf,
    installation_key: Option<String>,
) -> Result<i32> {
    let materialize_input = source_bundle_materializer::CanarySourceBundleMaterializeInput {
        eliot_host_exe: eliot_host,
        eliot_watchdog_exe: eliot_watchdog,
        eliot_kernel_exe: eliot_kernel,
        eliot_store_surreal_exe: eliot_store_surreal,
        surreal_exe: surreal,
        eliotd_exe: eliotd,
        output_bundle: output_bundle.clone(),
        generation: cli_handle(generation.clone(), "generation")?,
        installation_epoch: InstallationEpoch {
            installation: cli_handle(installation.clone(), "installation")?,
            lineage_id: cli_handle(lineage_id.clone(), "lineage_id")?,
            sequence,
        },
        profile,
        profile_anchor_root: cli_path_handle(&profile_anchor_root, "profile_anchor_root")?,
        installation_key: installation_key
            .clone()
            .map(|value| cli_handle(value, "installation_key"))
            .transpose()?,
        transaction_id: cli_handle(transaction_id.clone(), "transaction_id")?,
        staging_root: cli_path_handle(&staging_root, "staging_root")?,
    };
    let receipt =
        match source_bundle_materializer::materialize_canary_source_bundle(&materialize_input) {
            Ok(source_bundle_materializer::CanarySourceBundleMaterializeOutcome::Published(
                receipt,
            )) => receipt,
            Ok(
                source_bundle_materializer::CanarySourceBundleMaterializeOutcome::CommittedUnknown(
                    reconciliation,
                ),
            ) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "contract": "eliot.kernel.installation",
                        "contract_version": INSTALLATION_CONTRACT_VERSION,
                        "status": "SOURCE_BUNDLE_PUBLICATION_RECONCILIATION_REQUIRED",
                        "reconciliation": reconciliation,
                    }))?
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(error) => {
                write_installation_error(
                    "SOURCE_BUNDLE_MATERIALIZATION_REJECTED",
                    &error.to_string(),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "SOURCE_BUNDLE_MATERIALIZED",
            "bundle_path": receipt.bundle_path,
            "generation": receipt.generation,
            "evidence_digest": receipt.evidence_digest,
            "file_count": receipt.files.len(),
            "files": receipt.files,
            "source_identity": receipt.source_identity,
            "directory_publication": receipt.directory_publication,
        }))?
    );
    run_installation_generate(
        output_bundle,
        profile,
        profile_anchor_root,
        installation_key,
        installation,
        lineage_id,
        sequence,
        generation,
        staging_root,
        transaction_id,
        minimum_store_available_bytes,
        recovery_command,
        output,
        store,
    )
}

fn run_installation_create(_input: &Path, _store_path: &Path) -> i32 {
    write_installation_error(
        "INSTALLATION_CREATE_PRODUCTION_DISABLED",
        "raw transaction import is not a production constructor; use installation generate --store",
    );
    INVALID_REQUEST_EXIT
}

fn run_installation_runtime_status(host_state_root: &Path, deadline_ms: u64) -> Result<i32> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(deadline_ms);
    if std::time::Instant::now() >= deadline {
        write_runtime_status_error(
            "RUNTIME_STATUS_TIMEOUT",
            "deadline exceeded before inspection",
            true,
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    match eliot_runtime_status::collect_status(host_state_root, deadline) {
        Ok(report) => {
            let status_code = if report.status == "RUNTIME_LIVE" {
                "RUNTIME_LIVE"
            } else {
                "NOT_HEALTHY"
            };
            let completed = status_code == "RUNTIME_LIVE";
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "contract": report.contract,
                    "contract_version": report.contract_version,
                    "status": status_code,
                    "host_state_root": report.host_state_root,
                    "active_generation": report.active_generation,
                    "last_known_good_generation": report.last_known_good_generation,
                    "generations": report.generations,
                    "host_journal": {
                        "state": report.host_journal.state,
                        "clean": report.host_journal.clean,
                        "sequence": report.host_journal.sequence,
                        "last_checksum": report.host_journal.last_checksum,
                        "prior_kernel_unknown": report.host_journal.prior_kernel_unknown,
                        "gap": report.host_journal.gap,
                    },
                    "ors": {
                        "state": report.ors.state,
                        "gap": report.ors.gap,
                    },
                    "transaction_stage": report.transaction_stage,
                    "services": {
                        "kernel": report.services.kernel,
                        "store": report.services.store,
                        "eliotd": report.services.eliotd,
                        "watchdog": report.services.watchdog,
                        "host_service_registration": report.services.host_service_registration,
                        "watchdog_service_registration": report.services.watchdog_service_registration,
                    },
                    "readiness": {
                        "proof_status": report.readiness.proof_status,
                        "gap": report.readiness.age_gap,
                    },
                    "recovery_command": report.recovery_command,
                    "gaps": report.gaps,
                    "components": report.components,
                    "deadline_exceeded": report.deadline_exceeded,
                    "completed": completed,
                    "scope": INSTALLATION_SCOPE,
                }))?
            );
            Ok(if completed { 0 } else { INVALID_REQUEST_EXIT })
        }
        Err(error) => {
            let deadline_exceeded =
                matches!(&error, eliot_runtime_status::StatusError::DeadlineExceeded);
            let (code, detail) = match error {
                eliot_runtime_status::StatusError::DeadlineExceeded => (
                    "RUNTIME_STATUS_TIMEOUT",
                    "deadline exceeded during inspection".to_owned(),
                ),
                eliot_runtime_status::StatusError::Invalid(msg) => {
                    if msg.contains("does not exist") || msg.contains("absent") {
                        ("INSTALLATION_STATUS_UNAVAILABLE", msg)
                    } else {
                        ("INSTALLATION_STATUS_INVALID", msg)
                    }
                }
                eliot_runtime_status::StatusError::Unavailable(msg) => {
                    ("INSTALLATION_STATUS_UNAVAILABLE", msg)
                }
            };
            write_runtime_status_error(code, &detail, deadline_exceeded);
            Ok(INVALID_REQUEST_EXIT)
        }
    }
}

#[allow(dead_code)]
fn validate_registry_host_state_root(
    registry: &eliot_installation::ApprovedGenerationRegistry,
    canonical_host_state_root: &Path,
) -> std::result::Result<(), InstallationError> {
    for generation in registry.generations() {
        validate_manifest_host_state_root(
            &generation
                .manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root,
            canonical_host_state_root,
            "approved_generation",
        )?;
    }
    if let Some(pending) = registry.pending_activation() {
        validate_manifest_host_state_root(
            &pending
                .manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root,
            canonical_host_state_root,
            "pending_activation",
        )?;
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_manifest_host_state_root(
    declared_host_state_root: &eliot_installation::PlatformHandle,
    canonical_host_state_root: &Path,
    field_prefix: &str,
) -> std::result::Result<(), InstallationError> {
    if eliot_platform_windows::windows_paths_equal(
        canonical_host_state_root,
        Path::new(declared_host_state_root.as_str()),
    ) {
        return Ok(());
    }
    Err(InstallationError::InvalidField {
        field: format!("{field_prefix}.runtime_state_roots.host_state_root"),
        reason: "manifest Host state root does not equal the retained installation root".to_owned(),
    })
}

#[allow(dead_code)]
fn installation_status_error_code(error: &InstallationError) -> &'static str {
    match error {
        InstallationError::MigrationRequired { .. } => "INSTALLATION_STATUS_MIGRATION_REQUIRED",
        _ => "INSTALLATION_STATUS_INVALID",
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the CLI keeps coordinator reopen, sealed readback and bounded outcome output in one auditable boundary"
)]
fn run_installation_effect(
    store_path: &Path,
    raw_transaction_id: &str,
    recover: bool,
) -> Result<i32> {
    let transaction_id = match parse_installation_transaction_id(raw_transaction_id) {
        Ok(transaction_id) => transaction_id,
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_INVALID"
                } else {
                    "INSTALLATION_APPLY_INVALID"
                },
                &error.to_string(),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path) {
        Ok(store) => store,
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_UNAVAILABLE"
                } else {
                    "INSTALLATION_APPLY_UNAVAILABLE"
                },
                &error.to_string(),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let preflight_transaction = match store.load(&transaction_id) {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_NOT_FOUND"
                } else {
                    "INSTALLATION_APPLY_NOT_FOUND"
                },
                &format!("transaction is not present in {}", store_path.display()),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_ERROR"
                } else {
                    "INSTALLATION_APPLY_ERROR"
                },
                &format!("transaction preflight could not read durable state: {error}"),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if preflight_transaction.profile == InstallationProfile::SystemService {
        match is_process_elevated() {
            Ok(true) => {}
            Ok(false) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_NOT_ELEVATED"
                    } else {
                        "INSTALLATION_APPLY_NOT_ELEVATED"
                    },
                    "SystemService requires an elevated token; no effect was attempted",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(InstallerRootError::UnsupportedPlatform) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_NOT_ELEVATED"
                    } else {
                        "INSTALLATION_APPLY_NOT_ELEVATED"
                    },
                    "SystemService requires Windows elevation; no effect was attempted",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(error) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_RECOVERY_REQUIRED"
                    } else {
                        "INSTALLATION_APPLY_RECOVERY_REQUIRED"
                    },
                    &format!("elevation is unknown ({error}); recovery is required"),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        }
    }
    let preflight_status = installation_preflight_status(preflight_transaction.stage(), recover);
    let should_query_host_terminal =
        should_query_host_terminal(preflight_transaction.profile, preflight_transaction.stage());
    if let Some(status) = preflight_status.filter(|_| !should_query_host_terminal) {
        let staging = InstallationStagingDisposition::not_attempted(if status == "ROLLED_BACK" {
            "transaction is already rolled back; no recovery effect was attempted"
        } else {
            "transaction stage is terminal or incompatible; no effect was attempted"
        });
        print_transaction_projection(
            if recover {
                "RECOVERY_RESULT"
            } else {
                "EFFECT_RESULT"
            },
            store_path,
            &preflight_transaction,
            None,
            Some(&staging),
            Some(status),
        )?;
        return Ok(installation_command_exit_code(status));
    }

    // A response can be lost after Host has durably committed activation.  A
    // recovery command must query that exact terminal before it is allowed to
    // enter rollback; otherwise a perfectly good live generation would remain
    // stranded in Activating.  The query is deliberately read/reconcile-only:
    // it does not resend any effect or touch SCM/registry projection.
    if should_query_host_terminal {
        let host_terminal_outcome =
            match reconcile_host_activation_terminal(store_path, &preflight_transaction) {
                Ok(outcome) => outcome,
                Err(error) => {
                    write_installation_error(
                        if recover {
                            "INSTALLATION_RECOVER_ERROR"
                        } else {
                            "INSTALLATION_APPLY_ERROR"
                        },
                        &format!("Host activation terminal query failed: {error}"),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
        if let Some(outcome) = host_terminal_outcome {
            let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path)
            {
                Ok(store) => store,
                Err(error) => {
                    write_installation_error(
                        "INSTALLATION_STATE_UNAVAILABLE",
                        &format!(
                            "Host terminal was observed but transaction readback failed: {error}"
                        ),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let transaction = match store.load(&transaction_id) {
                Ok(Some(transaction)) => transaction,
                Ok(None) => {
                    write_installation_error(
                        "INSTALLATION_STATE_UNAVAILABLE",
                        "Host terminal was observed but the transaction disappeared",
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                Err(error) => {
                    write_installation_error(
                        "INSTALLATION_STATE_UNAVAILABLE",
                        &format!("Host terminal transaction readback failed: {error}"),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let staging = InstallationStagingDisposition::not_attempted(if recover {
                "recovery reconciled the exact Host terminal; no rollback effect was attempted"
            } else {
                "apply observed the exact Host terminal before projection; no effect was attempted"
            });
            print_transaction_projection(
                if recover {
                    "RECOVERY_RESULT"
                } else {
                    "EFFECT_RESULT"
                },
                store_path,
                &transaction,
                Some(&outcome),
                Some(&staging),
                Some("ACTIVE_VERIFIED"),
            )?;
            return Ok(installation_command_exit_code("ACTIVE_VERIFIED"));
        }
    }

    // A queryable stage with no committed Host terminal remains subject to the
    // ordinary preflight disposition.  Keeping this return after the query is
    // what makes apply and recover response-loss safe without allowing either
    // path to resend an effect or enter rollback before the readback.
    if let Some(status) = preflight_status {
        let staging = InstallationStagingDisposition::not_attempted(if status == "ROLLED_BACK" {
            "transaction is already rolled back; no recovery effect was attempted"
        } else {
            "transaction stage is terminal or incompatible; no effect was attempted"
        });
        print_transaction_projection(
            if recover {
                "RECOVERY_RESULT"
            } else {
                "EFFECT_RESULT"
            },
            store_path,
            &preflight_transaction,
            None,
            Some(&staging),
            Some(status),
        )?;
        return Ok(installation_command_exit_code(status));
    }

    let mut coordinator = WindowsInstallationCoordinator::new(store);
    let outcome = if recover {
        coordinator.rollback(&transaction_id)
    } else if preflight_transaction.profile == InstallationProfile::SystemService {
        match coordinator.drive_until_host_bootstrap(&transaction_id) {
            Ok(InstallationStepOutcome::Applied { .. }) => {
                let current = match coordinator.store().load(&transaction_id) {
                    Ok(Some(transaction)) => transaction,
                    Ok(None) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_NOT_FOUND",
                            "transaction disappeared before pending registry projection",
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!(
                                "transaction readback before pending projection failed: {error}"
                            ),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                let host_root = match ProtectedRootLease::open_existing(Path::new(
                    current
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots
                        .host_state_root
                        .as_str(),
                )) {
                    Ok(root) => root,
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!("retained Host root could not be reopened: {error}"),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                let registry = match RedbInstallationRegistry::open_at(host_root) {
                    Ok(registry) => registry,
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!("pending registry could not be opened: {error}"),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                let expected_revision = match registry.load() {
                    Ok(registry) => registry.revision(),
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!("pending registry preflight failed: {error}"),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                if let Err(error) = coordinator.stage_bootstrap_pending_activation(
                    &registry,
                    &transaction_id,
                    expected_revision,
                ) {
                    write_installation_error(
                        "INSTALLATION_APPLY_ERROR",
                        &format!("pending registry projection failed: {error}"),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                coordinator.drive_all_effects_until_blocked(&transaction_id)
            }
            outcome => outcome,
        }
    } else {
        coordinator.drive_all_effects_until_blocked(&transaction_id)
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            let code = match &error {
                InstallationError::UnknownOutcome { .. } => {
                    if recover {
                        "INSTALLATION_RECOVER_RECOVERY_REQUIRED"
                    } else {
                        "INSTALLATION_APPLY_RECOVERY_REQUIRED"
                    }
                }
                _ => {
                    if recover {
                        "INSTALLATION_RECOVER_ERROR"
                    } else {
                        "INSTALLATION_APPLY_ERROR"
                    }
                }
            };
            write_installation_error(code, &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    drop(coordinator);
    let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path) {
        Ok(store) => store,
        Err(error) => {
            write_installation_error(
                "INSTALLATION_STATE_UNAVAILABLE",
                &format!(
                    "effect outcome was returned but durable state could not be reopened: {error}"
                ),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = match store.load(&transaction_id) {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            write_installation_error(
                "INSTALLATION_STATE_UNAVAILABLE",
                "effect outcome was returned but the transaction disappeared from the durable store",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error("INSTALLATION_STATE_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let host_terminal_outcome = if transaction.profile == InstallationProfile::SystemService
        && matches!(transaction.stage(), InstallationStage::Activating)
    {
        match reconcile_host_activation_terminal(store_path, &transaction) {
            Ok(outcome) => outcome,
            Err(error) => {
                write_installation_error(
                    "INSTALLATION_STATE_INVALID",
                    &format!("Host activation terminal reconciliation failed: {error}"),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        }
    } else {
        None
    };
    let transaction = if host_terminal_outcome.is_some() {
        match RedbInstallationTransactionStore::open_existing_exact_path(store_path)
            .and_then(|store| store.load(&transaction_id))
        {
            Ok(Some(transaction)) => transaction,
            Ok(None) => {
                write_installation_error(
                    "INSTALLATION_STATE_UNAVAILABLE",
                    "Host terminal was observed but the transaction disappeared",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(error) => {
                write_installation_error(
                    "INSTALLATION_STATE_UNAVAILABLE",
                    &format!("Host terminal transaction readback failed: {error}"),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        }
    } else {
        transaction
    };
    let effective_outcome = host_terminal_outcome.as_ref().unwrap_or(&outcome);
    let all_effects_applied = transaction.effect_progress().iter().all(|progress| {
        matches!(
            progress.state,
            eliot_installation::InstallationEffectProgressState::Applied { .. }
        )
    });
    // Phase-B response loss is represented by a durable IntentCommitted
    // effect and a rejected drive step.  Keep the public command state honest:
    // activation is pending and the next invocation will query-reconcile the
    // Host receipt rather than retrying materialization.
    let phase_b_pending = !recover
        && transaction.profile == InstallationProfile::SystemService
        && transaction.stage() == InstallationStage::Activating
        && matches!(effective_outcome, InstallationStepOutcome::Rejected);
    let staging = if phase_b_pending {
        InstallationStagingDisposition {
            disposition: "PENDING_RUNTIME",
            reason: Some(
                "Host Phase-B response is unresolved; activation remains fenced and the next command will query-reconcile the exact receipt"
                    .to_owned(),
            ),
            registry: None,
        }
    } else {
        installation_staging_disposition(
            transaction.profile,
            effective_outcome,
            all_effects_applied,
            recover,
        )
    };
    let overall_status = if phase_b_pending {
        "PENDING_RUNTIME"
    } else {
        installation_command_status(
            transaction.profile,
            effective_outcome,
            all_effects_applied,
            recover,
        )
    };
    print_transaction_projection(
        if recover {
            "RECOVERY_RESULT"
        } else {
            "EFFECT_RESULT"
        },
        store_path,
        &transaction,
        Some(effective_outcome),
        Some(&staging),
        Some(overall_status),
    )?;
    Ok(installation_command_exit_code(overall_status))
}

/// Reconciles only an exact Host-committed registry terminal.  A missing
/// terminal is the expected fenced first-install state and remains pending;
/// this query never starts services, rewrites descriptors, or retries a
/// credential/SCM effect.
fn reconcile_host_activation_terminal(
    store_path: &Path,
    transaction: &InstallationTransaction,
) -> Result<Option<InstallationStepOutcome>, InstallationError> {
    let host_root = ProtectedRootLease::open_existing(Path::new(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    ))
    .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let Some(registry) = RedbInstallationRegistry::open_existing_at(host_root)? else {
        return Ok(None);
    };
    let receipt = match registry.read_committed_activation_receipt(
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
    ) {
        Ok(receipt) => receipt,
        Err(InstallationError::IncompleteObservation(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let evidence = vec![
        receipt.terminal_digest().clone(),
        receipt.candidate_manifest_digest().clone(),
    ];
    let store = RedbInstallationTransactionStore::open_existing_exact_path(store_path)?;
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    coordinator
        .reconcile_active_verified(receipt, evidence)
        .map(Some)
}

#[derive(Debug)]
struct InstallationStagingDisposition {
    disposition: &'static str,
    reason: Option<String>,
    registry: Option<PathBuf>,
}

impl InstallationStagingDisposition {
    fn not_attempted(reason: &str) -> Self {
        Self {
            disposition: "NOT_ATTEMPTED",
            reason: Some(reason.to_owned()),
            registry: None,
        }
    }
}

/// Classifies the deferred registry surface without accepting caller-shaped
/// approval input.  The registry write remains a separate transaction-bound
/// operation and is intentionally never performed by this bounded command.
fn installation_staging_disposition(
    profile: InstallationProfile,
    outcome: &InstallationStepOutcome,
    all_effects_applied: bool,
    recover: bool,
) -> InstallationStagingDisposition {
    if recover {
        return InstallationStagingDisposition::not_attempted(
            "recovery does not stage activation; the recovery outcome is authoritative",
        );
    }
    if !matches!(outcome, InstallationStepOutcome::Applied { .. }) {
        return InstallationStagingDisposition::not_attempted(
            "the effect outcome is not Applied; activation remains unstaged",
        );
    }
    if !all_effects_applied {
        return InstallationStagingDisposition::not_attempted(
            "sealed transaction still contains Pending, IntentCommitted, or Unknown effects",
        );
    }
    if profile == InstallationProfile::SystemService {
        if matches!(
            outcome,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::Activating,
                ..
            }
        ) {
            return InstallationStagingDisposition {
                disposition: "PENDING_RUNTIME",
                reason: Some(
                    "Host bootstrap effects are applied; activation remains pending until the Host-owned live commit fence is observed"
                        .to_owned(),
                ),
                registry: None,
            };
        }
        if matches!(
            outcome,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::ActiveVerified,
                ..
            }
        ) {
            return InstallationStagingDisposition {
                disposition: "COMMITTED",
                reason: Some(
                    "the exact Host registry terminal was reconciled into the transaction"
                        .to_owned(),
                ),
                registry: None,
            };
        }
        return InstallationStagingDisposition {
            disposition: "APPROVAL_REQUIRED",
            reason: Some(
                "transaction-bound approval is required before registry staging; no registry write was attempted"
                    .to_owned(),
            ),
            registry: None,
        };
    }
    InstallationStagingDisposition {
        disposition: "NOT_APPLICABLE",
        reason: Some(
            "registry staging is not part of the PortableDev/UserMode effect command".to_owned(),
        ),
        registry: None,
    }
}

fn installation_command_status(
    profile: InstallationProfile,
    outcome: &InstallationStepOutcome,
    all_effects_applied: bool,
    recover: bool,
) -> &'static str {
    match outcome {
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        } if recover => "ROLLED_BACK",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack | InstallationStage::Completed,
            ..
        }
        | InstallationStepOutcome::Rejected => "REJECTED",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Quarantined,
            ..
        }
        | InstallationStepOutcome::Quarantined { .. } => "QUARANTINED",
        InstallationStepOutcome::Applied { .. } if recover => "ERROR",
        InstallationStepOutcome::Applied { .. } if !all_effects_applied => "ERROR",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Activating,
            ..
        } if !recover && profile == InstallationProfile::SystemService => "PENDING_RUNTIME",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::ActiveVerified,
            ..
        } if !recover && profile == InstallationProfile::SystemService => "ACTIVE_VERIFIED",
        InstallationStepOutcome::Applied { .. }
            if !recover && profile == InstallationProfile::SystemService =>
        {
            "APPROVAL_REQUIRED"
        }
        InstallationStepOutcome::Applied { .. } => "EFFECTS_APPLIED",
        InstallationStepOutcome::RollbackRequired { .. } => "ROLLBACK_REQUIRED",
    }
}

fn installation_preflight_status(stage: InstallationStage, recover: bool) -> Option<&'static str> {
    if recover {
        return match stage {
            InstallationStage::RolledBack => Some("ROLLED_BACK"),
            InstallationStage::Quarantined => Some("QUARANTINED"),
            InstallationStage::ActiveVerified => Some("ACTIVE_VERIFIED"),
            InstallationStage::Cleaning | InstallationStage::Completed => Some("REJECTED"),
            _ => None,
        };
    }
    match stage {
        InstallationStage::RollbackRequired => Some("ROLLBACK_REQUIRED"),
        InstallationStage::Quarantined => Some("QUARANTINED"),
        InstallationStage::ActiveVerified => Some("ACTIVE_VERIFIED"),
        InstallationStage::Cleaning
        | InstallationStage::Completed
        | InstallationStage::RolledBack => Some("REJECTED"),
        _ => None,
    }
}

fn should_query_host_terminal(profile: InstallationProfile, stage: InstallationStage) -> bool {
    profile == InstallationProfile::SystemService
        && matches!(
            stage,
            InstallationStage::Activating | InstallationStage::RollbackRequired
        )
}

fn print_transaction_projection(
    status: &str,
    store_path: &Path,
    transaction: &InstallationTransaction,
    outcome: Option<&InstallationStepOutcome>,
    staging: Option<&InstallationStagingDisposition>,
    overall_status: Option<&str>,
) -> Result<()> {
    let transaction_value = serde_json::to_value(transaction)?;
    let outcome_value = outcome.map(serde_json::to_value).transpose()?;
    let projected_status = overall_status
        .or_else(|| outcome.map(installation_outcome_status))
        .unwrap_or(status);
    let completed = installation_projection_completed(transaction.stage());
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": projected_status,
            "store": store_path.display().to_string(),
            "transaction_id": transaction.transaction_id,
            "transaction_wire_version": transaction.transaction_wire_version,
            "stage": transaction.stage(),
            "revision": transaction.revision(),
            "completed": completed,
            "outcome": outcome_value,
            "staging": staging.map(|value| {
                json!({
                    "disposition": value.disposition,
                    "reason": value.reason,
                    "registry": value.registry.as_ref().map(|path| path.display().to_string()),
                })
            }),
            "transaction": transaction_value,
            "scope": INSTALLATION_SCOPE,
            "deferred_scope": [
                "generation_activation",
                "service_start",
                "runtime_health",
                "canary_removal"
            ],
        }))?
    );
    Ok(())
}

fn installation_outcome_status(outcome: &InstallationStepOutcome) -> &'static str {
    match outcome {
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        } => "ROLLED_BACK",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Quarantined,
            ..
        }
        | InstallationStepOutcome::Quarantined { .. } => "QUARANTINED",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Completed,
            ..
        }
        | InstallationStepOutcome::Rejected => "REJECTED",
        InstallationStepOutcome::Applied { .. } => "EFFECTS_APPLIED",
        InstallationStepOutcome::RollbackRequired { .. } => "ROLLBACK_REQUIRED",
    }
}

fn installation_command_exit_code(status: &str) -> i32 {
    if matches!(
        status,
        "EFFECTS_APPLIED" | "ROLLED_BACK" | "ACTIVE_VERIFIED"
    ) {
        0
    } else {
        INVALID_REQUEST_EXIT
    }
}

fn load_input(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("read input metadata: {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("input is not a regular file: {}", path.display());
    }
    if metadata.len() > INSTALLATION_INPUT_LIMIT {
        anyhow::bail!("input exceeds the 16 MiB limit: {}", path.display());
    }
    fs::read(path).with_context(|| format!("read input: {}", path.display()))
}

#[cfg(windows)]
fn run_ui() -> Result<i32> {
    let mut client =
        AuthenticatedKernelPort::load().map_err(|error| anyhow::anyhow!(error.to_string()))?;
    match client.ensure_operator_launch() {
        Ok(receipt) => {
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(0)
        }
        Err(eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract)) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
        Err(error) => {
            write_json_error("KERNEL_OPERATOR_LAUNCH_REJECTED", &error.to_string());
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
    }
}

#[cfg(not(windows))]
fn run_ui() -> Result<i32> {
    write_json_error(
        "KERNEL_APPLICATION_PORT_CLOSED",
        "Windows authenticated User Broker UI",
    );
    Ok(FRONT_DOOR_CLOSED_EXIT)
}

fn run_system(command: SystemCommand) -> Result<i32> {
    match command {
        SystemCommand::Snapshot { repo_root, output } => {
            let artifact =
                capture_snapshot(&repo_root).context("capture current-system evidence")?;
            write_snapshot_artifact(&artifact, &output).context("write current-system artifact")?;
            println!("{}", serde_json::to_string_pretty(&artifact)?);
            Ok(0)
        }
    }
}

fn absolute_path(value: &str) -> std::result::Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("path must be absolute".to_owned())
    }
}

fn parse_installation_profile(value: &str) -> std::result::Result<InstallationProfile, String> {
    match value {
        "system_service" => Ok(InstallationProfile::SystemService),
        "user_mode" => Ok(InstallationProfile::UserMode),
        "portable_dev" => Ok(InstallationProfile::PortableDev),
        _ => Err("profile must be one of system_service, user_mode, portable_dev".to_owned()),
    }
}

fn cli_handle(value: String, field: &str) -> Result<PlatformHandle> {
    PlatformHandle::new(value).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))
}

fn cli_path_handle(path: &Path, field: &str) -> Result<PlatformHandle> {
    if !path.is_absolute() {
        anyhow::bail!("{field} must be absolute");
    }
    cli_handle(path.to_string_lossy().into_owned(), field)
}

fn write_transaction_artifact(
    path: &Path,
    transaction: &InstallationTransaction,
) -> Result<(), std::io::Error> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "transaction output must be absolute",
        ));
    }
    let bytes = serde_json::to_vec_pretty(transaction)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")
}

/// Non-Windows builds have no authenticated Windows Kernel front door.
#[cfg(not(windows))]
struct ClosedKernelPort;

#[cfg(not(windows))]
impl CommandPort for ClosedKernelPort {
    fn dispatch(
        &mut self,
        _request: &CommandRequest,
    ) -> Result<eliot_cli::CommandResponse, CommandPortError> {
        Err(CommandPortError::FrontDoorClosed {
            contract: "N4 application command port",
        })
    }
}

fn run_dispatch() -> Result<i32> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("read one command request from stdin")?;
    if input.iter().all(u8::is_ascii_whitespace) {
        write_json_error(
            "REQUEST_REQUIRED",
            "dispatch requires one JSON command request",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let request = match serde_json::from_slice::<CommandRequest>(&input) {
        Ok(request) => request,
        Err(error) => {
            write_json_error("REQUEST_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    #[cfg(windows)]
    let mut port = match AuthenticatedKernelPort::load() {
        Ok(port) => port,
        Err(CommandPortError::FrontDoorClosed { contract }) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            return Ok(FRONT_DOOR_CLOSED_EXIT);
        }
        Err(error) => {
            write_json_error("KERNEL_CLIENT_CONFIGURATION_REJECTED", &error.to_string());
            return Ok(FRONT_DOOR_CLOSED_EXIT);
        }
    };
    #[cfg(not(windows))]
    let mut port = ClosedKernelPort;
    match CommandCatalogue::current().dispatch(&mut port, &request) {
        Ok(response) => {
            println!("{}", serde_json::to_string(&response)?);
            Ok(0)
        }
        Err(eliot_cli::CliError::Port(CommandPortError::FrontDoorClosed { contract })) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
        Err(error) => {
            write_json_error("REQUEST_REJECTED", &error.to_string());
            Ok(INVALID_REQUEST_EXIT)
        }
    }
}

fn write_json_error(code: &str, detail: &str) {
    println!(
        "{}",
        json!({"status": "error", "code": code, "detail": detail})
    );
}

fn write_installation_error(code: &str, detail: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "completed": false,
            "scope": INSTALLATION_SCOPE,
        })
    );
}

fn write_runtime_status_error(code: &str, detail: &str, deadline_exceeded: bool) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "deadline_exceeded": deadline_exceeded,
            "completed": false,
            "scope": INSTALLATION_SCOPE,
        })
    );
}

fn installation_projection_completed(stage: InstallationStage) -> bool {
    stage == InstallationStage::Completed
}

#[cfg(windows)]
struct AuthenticatedKernelPort {
    client: eliot_cli::kernel_client::KernelClient,
}

#[cfg(windows)]
impl AuthenticatedKernelPort {
    fn load() -> Result<Self, CommandPortError> {
        eliot_cli::kernel_client::KernelClient::load()
            .map(|client| Self { client })
            .map_err(|error| match error {
                eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract) => {
                    CommandPortError::FrontDoorClosed { contract }
                }
                other => CommandPortError::Rejected(other.to_string()),
            })
    }

    fn ensure_operator_launch(
        &mut self,
    ) -> std::result::Result<serde_json::Value, eliot_cli::kernel_client::KernelClientError> {
        self.client.ensure_operator_launch()
    }
}

#[cfg(windows)]
impl CommandPort for AuthenticatedKernelPort {
    fn dispatch(
        &mut self,
        request: &CommandRequest,
    ) -> Result<eliot_cli::CommandResponse, CommandPortError> {
        self.client.set_request_identity(request.request.clone());
        let payload = serde_json::to_value(request)
            .map_err(|error| CommandPortError::Rejected(error.to_string()))?;
        let response = self
            .client
            .transact_json("eliot.cli.command", payload)
            .map_err(|error| match error {
                eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract) => {
                    CommandPortError::FrontDoorClosed { contract }
                }
                other => CommandPortError::Rejected(other.to_string()),
            })?;
        serde_json::from_value(response)
            .map_err(|error| CommandPortError::Rejected(error.to_string()))
    }
}

fn run_catalogue(command: &CatalogueCommand) -> Result<()> {
    let catalogue = eliot_cli::CommandCatalogue::current();
    match command {
        CatalogueCommand::Help => println!("{}", catalogue.help_text()?),
        CatalogueCommand::Schema => println!("{}", catalogue.schema_json()?),
        CatalogueCommand::Validate => {
            catalogue.validate()?;
            println!("catalogue {} is valid", eliot_cli::CATALOGUE_REVISION);
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "small pure status tests use explicit panic messages for impossible fixture states"
)]
mod tests {
    use super::*;

    fn applied_outcome() -> InstallationStepOutcome {
        InstallationStepOutcome::Applied {
            stage: eliot_installation::InstallationStage::Planned,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn portable_all_effects_are_not_reported_as_one_effect() {
        let outcome = applied_outcome();
        assert_eq!(
            installation_command_status(InstallationProfile::PortableDev, &outcome, true, false,),
            "EFFECTS_APPLIED"
        );
        assert_eq!(installation_command_exit_code("EFFECTS_APPLIED"), 0);
        assert_ne!(installation_outcome_status(&outcome), "EFFECT_APPLIED");
    }

    #[test]
    fn system_service_all_effects_require_transaction_bound_approval() {
        let outcome = applied_outcome();
        let staging = installation_staging_disposition(
            InstallationProfile::SystemService,
            &outcome,
            true,
            false,
        );
        assert_eq!(staging.disposition, "APPROVAL_REQUIRED");
        assert_eq!(
            installation_command_status(InstallationProfile::SystemService, &outcome, true, false,),
            "APPROVAL_REQUIRED"
        );
        assert_eq!(
            installation_command_exit_code("APPROVAL_REQUIRED"),
            INVALID_REQUEST_EXIT
        );
        assert!(staging.registry.is_none());
        assert!(
            staging
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no registry write"))
        );
    }

    #[test]
    fn applied_outcome_with_incomplete_readback_is_an_error() {
        let outcome = applied_outcome();
        let staging = installation_staging_disposition(
            InstallationProfile::PortableDev,
            &outcome,
            false,
            false,
        );
        assert_eq!(staging.disposition, "NOT_ATTEMPTED");
        assert_eq!(
            installation_command_status(InstallationProfile::PortableDev, &outcome, false, false,),
            "ERROR"
        );
        assert_eq!(
            installation_command_exit_code("ERROR"),
            INVALID_REQUEST_EXIT
        );
    }

    #[test]
    fn blocked_outcomes_have_distinct_nonzero_statuses() {
        let outcome = InstallationStepOutcome::RollbackRequired {
            pending_refs: Vec::new(),
        };
        assert_eq!(
            installation_command_status(InstallationProfile::SystemService, &outcome, false, false,),
            "ROLLBACK_REQUIRED"
        );
        assert_eq!(
            installation_command_status(
                InstallationProfile::SystemService,
                &InstallationStepOutcome::Quarantined {
                    pending_refs: Vec::new(),
                },
                false,
                false,
            ),
            "QUARANTINED"
        );
        assert_eq!(
            installation_command_status(
                InstallationProfile::SystemService,
                &InstallationStepOutcome::Rejected,
                false,
                false,
            ),
            "REJECTED"
        );
        assert_eq!(
            installation_command_exit_code("ROLLBACK_REQUIRED"),
            INVALID_REQUEST_EXIT
        );
        assert_eq!(
            installation_command_exit_code("QUARANTINED"),
            INVALID_REQUEST_EXIT
        );
        assert_eq!(
            installation_command_exit_code("REJECTED"),
            INVALID_REQUEST_EXIT
        );
    }

    #[test]
    fn successful_rollback_is_reported_as_rolled_back() {
        let outcome = InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            evidence_refs: Vec::new(),
        };
        let staging = installation_staging_disposition(
            InstallationProfile::SystemService,
            &outcome,
            true,
            true,
        );

        assert_eq!(staging.disposition, "NOT_ATTEMPTED");
        assert_eq!(
            installation_command_status(InstallationProfile::SystemService, &outcome, true, true,),
            "ROLLED_BACK"
        );
        assert_eq!(installation_command_exit_code("ROLLED_BACK"), 0);
        assert!(!installation_projection_completed(
            InstallationStage::RolledBack
        ));
    }

    #[test]
    fn terminal_apply_preflight_never_reports_effects_applied() {
        for stage in [
            InstallationStage::Cleaning,
            InstallationStage::Completed,
            InstallationStage::RolledBack,
            InstallationStage::Quarantined,
        ] {
            let status = installation_preflight_status(stage, false)
                .expect("incompatible terminal stage must be rejected");
            assert_ne!(status, "EFFECTS_APPLIED");
            assert_ne!(installation_command_exit_code(status), 0);
        }
        assert_eq!(
            installation_preflight_status(InstallationStage::RollbackRequired, false),
            Some("ROLLBACK_REQUIRED")
        );
        assert_eq!(
            installation_preflight_status(InstallationStage::ActiveVerified, false),
            Some("ACTIVE_VERIFIED")
        );
        assert_eq!(
            installation_preflight_status(InstallationStage::ActiveVerified, true),
            Some("ACTIVE_VERIFIED")
        );
        assert_eq!(installation_command_exit_code("ACTIVE_VERIFIED"), 0);
    }

    #[test]
    fn host_terminal_query_precedes_apply_and_recover_rollback_paths() {
        for stage in [
            InstallationStage::Activating,
            InstallationStage::RollbackRequired,
        ] {
            assert!(should_query_host_terminal(
                InstallationProfile::SystemService,
                stage,
            ));
        }
        assert!(!should_query_host_terminal(
            InstallationProfile::PortableDev,
            InstallationStage::RollbackRequired,
        ));
        // A missing terminal still leaves the original preflight disposition;
        // the query is read-only and must not turn RollbackRequired into a
        // successful result by itself.
        assert_eq!(
            installation_preflight_status(InstallationStage::RollbackRequired, false),
            Some("ROLLBACK_REQUIRED")
        );
        assert_eq!(
            installation_preflight_status(InstallationStage::RollbackRequired, true),
            None
        );
    }

    #[test]
    fn rolled_back_projection_serializes_completed_false() {
        let projection = json!({
            "status": "ROLLED_BACK",
            "stage": InstallationStage::RolledBack,
            "completed": installation_projection_completed(InstallationStage::RolledBack),
            "scope": INSTALLATION_SCOPE,
        });
        let serialized = serde_json::to_string(&projection).expect("serialize projection");
        let decoded: serde_json::Value =
            serde_json::from_str(&serialized).expect("decode serialized projection");
        assert_eq!(decoded["status"], "ROLLED_BACK");
        assert_eq!(decoded["stage"], "ROLLED_BACK");
        assert_eq!(decoded["completed"], false);
        assert_eq!(decoded["scope"], INSTALLATION_SCOPE);
    }

    #[test]
    fn installation_status_preserves_migration_and_corruption_classification() {
        assert_eq!(
            installation_status_error_code(&InstallationError::MigrationRequired {
                reason: "old table".to_owned(),
            }),
            "INSTALLATION_STATUS_MIGRATION_REQUIRED"
        );
        assert_eq!(
            installation_status_error_code(&InstallationError::CorruptRegistry {
                reason: "bad bytes".to_owned(),
            }),
            "INSTALLATION_STATUS_INVALID"
        );
        assert_eq!(
            installation_status_error_code(&InstallationError::InvalidField {
                field: "path".to_owned(),
                reason: "reparse".to_owned(),
            }),
            "INSTALLATION_STATUS_INVALID"
        );
        assert_eq!(
            installation_status_error_code(&InstallationError::Platform(
                "access denied".to_owned()
            )),
            "INSTALLATION_STATUS_INVALID"
        );
    }

    #[test]
    fn installation_status_accepts_manifest_root_bound_to_retained_root() {
        let retained_root = Path::new(
            r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
        );
        let declared_root = parse_installation_transaction_id(retained_root.to_string_lossy())
            .expect("valid retained root fixture");
        assert!(validate_manifest_host_state_root(&declared_root, retained_root, "active").is_ok());
    }

    #[test]
    fn installation_status_rejects_manifest_root_substitution() {
        let retained_root = Path::new(
            r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
        );
        let substituted_root = parse_installation_transaction_id(
            r"C:\ProgramData\Eliot\installations\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\host",
        )
        .expect("valid substituted root fixture");
        let error = validate_manifest_host_state_root(&substituted_root, retained_root, "active")
            .expect_err("substituted manifest root must fail closed");
        assert!(matches!(
            error,
            InstallationError::InvalidField { field, .. }
                if field == "active.runtime_state_roots.host_state_root"
        ));
    }

    #[test]
    fn runtime_status_cli_requires_absolute_host_state_root() {
        let result = Cli::try_parse_from([
            "eliot",
            "installation",
            "status",
            "--host-state-root",
            "relative/path",
        ]);
        assert!(
            result.is_err(),
            "relative host-state-root must be rejected by value_parser"
        );
    }

    #[test]
    fn runtime_status_cli_accepts_production_json_surface() {
        let root = std::env::temp_dir().join("eliot-runtime-status-production");
        let root_arg = root.to_string_lossy().into_owned();
        let cli = Cli::try_parse_from([
            "eliot",
            "runtime",
            "status",
            "--json",
            "--host-state-root",
            root_arg.as_str(),
        ])
        .expect("production runtime status surface must parse");
        match cli.command {
            Command::Runtime { command } => match command {
                RuntimeCommand::Status {
                    json,
                    host_state_root,
                    deadline_ms,
                } => {
                    assert!(json);
                    assert_eq!(host_state_root, root);
                    assert_eq!(deadline_ms, 2000);
                }
            },
            _ => panic!("expected runtime command"),
        }
    }

    #[test]
    fn runtime_status_cli_accepts_absolute_host_state_root() {
        let temp = std::env::temp_dir().join(format!("eliot-cli-abs-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        let arg = temp.to_string_lossy().into_owned();
        let cli = Cli::try_parse_from([
            "eliot",
            "installation",
            "status",
            "--host-state-root",
            arg.as_str(),
        ])
        .expect("absolute root must parse");
        match cli.command {
            Command::Installation { command } => match command {
                InstallationCommand::Status {
                    host_state_root,
                    deadline_ms,
                } => {
                    assert!(host_state_root.is_absolute());
                    assert_eq!(deadline_ms, 2000);
                }
                _ => panic!("expected status command"),
            },
            _ => panic!("expected installation command"),
        }
        let _ = std::fs::remove_dir_all(temp);
    }

    fn honest_cli_temp_root(prefix: &str) -> PathBuf {
        #[cfg(windows)]
        {
            let base = eliot_platform_windows::protected_program_data_root()
                .unwrap_or_else(|_| std::env::temp_dir());
            base.join(format!(
                "eliot-test-cli-{}-{}-{}",
                prefix,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
        }
        #[cfg(not(windows))]
        {
            let _ = prefix;
            std::env::temp_dir().join(format!(
                "eliot-cli-collect-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
        }
    }

    #[test]
    fn runtime_status_collect_via_cli_construction_is_not_healthy_with_explicit_gaps_and_no_synthesis()
     {
        let root = honest_cli_temp_root("collect");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let report = eliot_runtime_status::collect_status(&root, deadline)
            .expect("honest collect must succeed");
        assert_eq!(report.status, "NOT_HEALTHY");
        assert_eq!(report.contract, "eliot.runtime.live");
        assert!(
            report
                .gaps
                .iter()
                .any(|g| g.contains("freshness cannot be proven"))
        );
        assert!(report.gaps.iter().any(|g| g.contains("trust anchor")));
        assert!(report.gaps.iter().any(|g| g.contains("transaction stage")));
        assert!(report.gaps.iter().any(|g| g.contains("Kernel")));
        assert!(report.gaps.iter().any(|g| g.contains("Store")));
        let json = serde_json::to_value(json!({
            "status": report.status,
            "host_state_root": report.host_state_root,
            "ors": report.ors,
            "transaction_stage": report.transaction_stage,
            "gaps": report.gaps,
            "components": report.components,
        }))
        .expect("serialize");
        let text = serde_json::to_string(&json)
            .expect("stringify")
            .to_ascii_lowercase();
        assert!(!text.contains("\"pid\""));
        assert!(!text.contains("\"fence\""));
        assert!(!text.contains("\"nonce\""));
        assert!(matches!(
            report.transaction_stage.state,
            eliot_runtime_status::ComponentState::Unknown { .. }
        ));
        assert_eq!(
            report.transaction_stage.gap,
            eliot_runtime_status::transaction_stage_gap_for()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_status_cli_never_synthesizes_pid_key_nonce_fence_via_collect() {
        let root = honest_cli_temp_root("no-synth");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let report = eliot_runtime_status::collect_status(&root, deadline).expect("collect");
        let serialized = serde_json::to_string(&report)
            .expect("serialize report")
            .to_ascii_lowercase();
        assert!(!serialized.contains("\"pid\""));
        assert!(!serialized.contains("\"fence\""));
        assert!(!serialized.contains("\"nonce\""));
        assert!(!serialized.contains("\"public_key\""));
        let _ = std::fs::remove_dir_all(root);
    }
}
