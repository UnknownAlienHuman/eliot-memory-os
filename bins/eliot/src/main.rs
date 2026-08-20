#![forbid(unsafe_code)]
// Machine-readable and human CLI output is the public contract of this binary.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use eliot_bootstrap::capture::{capture_snapshot, write_snapshot_artifact};
use eliot_cli::{CommandCatalogue, CommandPort, CommandPortError, CommandRequest};
use eliot_installation::{
    ApprovedGenerationRegistry, InstallationError, InstallationProfile, InstallationStage,
    InstallationStepOutcome, InstallationTransaction, InstallationTransactionStore,
    RedbInstallationRegistry, RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    decode_installation_transaction_json, parse_installation_transaction_id,
};
use eliot_platform_windows::{ProtectedRootLease, windows_paths_equal};
use serde_json::json;
use std::path::PathBuf;
use std::{fs, io::Read, path::Path};
use tracing_subscriber::EnvFilter;

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
    Version,
    /// Start or reuse the authenticated User Broker and launch Operator.
    Ui,
}

#[derive(Debug, Subcommand)]
enum InstallationCommand {
    /// Validate an immutable v8 installation plan JSON without applying it.
    Plan {
        /// Absolute path to an existing serialized `InstallationTransaction`.
        #[arg(long, value_parser = absolute_path)]
        input: PathBuf,
    },
    /// Persist one validated constructor-produced transaction in an exact redb file.
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
        host_state_root: Option<PathBuf>,
        /// Absolute path to an existing durable transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: Option<PathBuf>,
        /// Stable transaction identity retained in the durable store.
        #[arg(long)]
        transaction_id: Option<String>,
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
        Command::Dispatch => run_dispatch(),
        Command::Ui => run_ui(),
    }
}

fn run_installation(command: InstallationCommand) -> Result<i32> {
    match command {
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
        InstallationCommand::Create { input, store } => run_installation_create(&input, &store),
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
            store,
            transaction_id,
        } => match (host_state_root, store, transaction_id) {
            (Some(host_state_root), None, None) => {
                run_installation_registry_status(&host_state_root)
            }
            (None, Some(store), Some(transaction_id)) => {
                run_installation_transaction_status(&store, &transaction_id)
            }
            _ => {
                write_installation_error(
                    "INSTALLATION_STATUS_INVALID",
                    "status requires either --host-state-root or both --store and --transaction-id",
                );
                Ok(INVALID_REQUEST_EXIT)
            }
        },
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
    }
}

fn run_installation_create(input: &Path, store_path: &Path) -> Result<i32> {
    let bytes = match load_input(input) {
        Ok(bytes) => bytes,
        Err(error) => {
            write_installation_error("INSTALLATION_CREATE_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = match decode_installation_transaction_json(&bytes) {
        Ok(transaction) => transaction,
        Err(error @ InstallationError::MigrationRequired { .. }) => {
            write_installation_error("INSTALLATION_CREATE_MIGRATION_REQUIRED", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error("INSTALLATION_CREATE_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let store = match RedbInstallationTransactionStore::create_planned_at_exact_path(
        store_path,
        &transaction,
    ) {
        Ok(store) => store,
        Err(error) => {
            let code = match &error {
                InstallationError::InvalidField { field, .. } if field == "transaction" => {
                    "INSTALLATION_CREATE_REJECTED"
                }
                _ => "INSTALLATION_CREATE_STORE_INVALID",
            };
            write_installation_error(code, &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    drop(store);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "CREATED",
            "store": store_path.display().to_string(),
            "transaction_id": transaction.transaction_id,
            "transaction_wire_version": transaction.transaction_wire_version,
            "stage": transaction.stage(),
            "revision": transaction.revision(),
            "effect_count": transaction.effect_progress().len(),
            "scope": "durable_transaction_only",
        }))?
    );
    Ok(0)
}

fn run_installation_registry_status(host_state_root: &Path) -> Result<i32> {
    if !host_state_root.is_absolute() {
        write_installation_error(
            "INSTALLATION_STATUS_INVALID",
            "Host state root must be absolute",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    match std::fs::symlink_metadata(host_state_root) {
        Ok(metadata) if metadata.is_dir() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_installation_error(
                "INSTALLATION_STATUS_UNAVAILABLE",
                "Host state root does not exist; status never creates it",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Ok(_) | Err(_) => {
            write_installation_error(
                "INSTALLATION_STATUS_INVALID",
                "Host state root is not an existing directory",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    }
    let retained_root = match ProtectedRootLease::open_existing(host_state_root) {
        Ok(root) => root,
        Err(error) => {
            write_installation_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let canonical_host_state_root = match retained_root.canonical_path() {
        Ok(root) => root,
        Err(error) => {
            write_installation_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if !windows_paths_equal(&canonical_host_state_root, host_state_root) {
        write_installation_error(
            "INSTALLATION_STATUS_INVALID",
            "Host state root is not the exact retained installation root",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let read_root = match ProtectedRootLease::open_existing(&canonical_host_state_root) {
        Ok(root) => root,
        Err(error) => {
            write_installation_error(
                "INSTALLATION_STATUS_INVALID",
                &format!("Host state root reopen failed: {error}"),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let registry_value = match RedbInstallationRegistry::inspect_existing_at(read_root) {
        Ok(Some(registry_value)) => registry_value,
        Ok(None) => {
            write_installation_error(
                "INSTALLATION_STATUS_UNAVAILABLE",
                "registry does not exist; status never creates it",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error(installation_status_error_code(&error), &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if let Err(error) = retained_root.verify_stable_identity() {
        write_installation_error("INSTALLATION_STATUS_INVALID", &error.to_string());
        return Ok(INVALID_REQUEST_EXIT);
    }
    if let Err(error) =
        validate_registry_host_state_root(&registry_value, &canonical_host_state_root)
    {
        write_installation_error(installation_status_error_code(&error), &error.to_string());
        return Ok(INVALID_REQUEST_EXIT);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": if registry_value.active().is_some() { "ACTIVE_GENERATION" } else { "NO_ACTIVE_GENERATION" },
            "active_generation": registry_value.active_generation(),
            "last_known_good_generation": registry_value.last_known_good_generation(),
            "generations": registry_value.generations(),
        }))?
    );
    Ok(0)
}

fn validate_registry_host_state_root(
    registry: &ApprovedGenerationRegistry,
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

fn validate_manifest_host_state_root(
    declared_host_state_root: &eliot_installation::PlatformHandle,
    canonical_host_state_root: &Path,
    field_prefix: &str,
) -> std::result::Result<(), InstallationError> {
    if windows_paths_equal(
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

fn run_installation_transaction_status(store_path: &Path, raw_transaction_id: &str) -> Result<i32> {
    let transaction_id = match parse_installation_transaction_id(raw_transaction_id) {
        Ok(transaction_id) => transaction_id,
        Err(error) => {
            write_installation_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path) {
        Ok(store) => store,
        Err(error) => {
            write_installation_error("INSTALLATION_STATUS_UNAVAILABLE", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = match store.load(&transaction_id) {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            write_installation_error(
                "INSTALLATION_TRANSACTION_NOT_FOUND",
                &format!("transaction is not present in {}", store_path.display()),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    print_transaction_projection(
        "TRANSACTION_STATUS",
        store_path,
        &transaction,
        None,
        None,
        None,
    )?;
    Ok(0)
}

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
    if let Some(status) = installation_preflight_status(preflight_transaction.stage(), recover) {
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
    } else {
        coordinator.drive_all_effects_until_blocked(&transaction_id)
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_ERROR"
                } else {
                    "INSTALLATION_APPLY_ERROR"
                },
                &error.to_string(),
            );
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
    let all_effects_applied = transaction.effect_progress().iter().all(|progress| {
        matches!(
            progress.state,
            eliot_installation::InstallationEffectProgressState::Applied { .. }
        )
    });
    let staging = installation_staging_disposition(
        transaction.profile,
        &outcome,
        all_effects_applied,
        recover,
    );
    let overall_status =
        installation_command_status(transaction.profile, &outcome, all_effects_applied, recover);
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
        Some(overall_status),
    )?;
    Ok(installation_command_exit_code(overall_status))
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
            InstallationStage::ActiveVerified
            | InstallationStage::Cleaning
            | InstallationStage::Completed => Some("REJECTED"),
            _ => None,
        };
    }
    match stage {
        InstallationStage::RollbackRequired => Some("ROLLBACK_REQUIRED"),
        InstallationStage::Quarantined => Some("QUARANTINED"),
        InstallationStage::ActiveVerified
        | InstallationStage::Cleaning
        | InstallationStage::Completed
        | InstallationStage::RolledBack => Some("REJECTED"),
        _ => None,
    }
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
    if matches!(status, "EFFECTS_APPLIED" | "ROLLED_BACK") {
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
            InstallationStage::ActiveVerified,
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
}
