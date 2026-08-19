#![forbid(unsafe_code)]
// Machine-readable and human CLI output is the public contract of this binary.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use eliot_bootstrap::capture::{capture_snapshot, write_snapshot_artifact};
use eliot_cli::{CommandCatalogue, CommandPort, CommandPortError, CommandRequest};
use eliot_installation::{
    InstallationError, InstallationStepOutcome, InstallationTransaction,
    InstallationTransactionStore, RedbInstallationRegistry, RedbInstallationTransactionStore,
    WindowsInstallationCoordinator, decode_installation_transaction_json,
    parse_installation_transaction_id,
};
use eliot_platform_windows::{ProtectedRootLease, canonical_windows_path};
use serde_json::json;
use std::path::PathBuf;
use std::{fs, io::Read, path::Path};
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const INVALID_REQUEST_EXIT: i32 = 2;
const FRONT_DOOR_CLOSED_EXIT: i32 = 69;
const INSTALLATION_INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const INSTALLATION_CONTRACT_VERSION: &str = "3.0.0";

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
    /// Validate an immutable v7 installation plan JSON without applying it.
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
    /// Drive exactly one durable effect through the production coordinator.
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
        /// Absolute path to an existing approved-generation registry redb file.
        #[arg(long, value_parser = absolute_path)]
        registry: Option<PathBuf>,
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
                    write_json_error("INSTALLATION_PLAN_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let transaction = match decode_installation_transaction_json(&bytes) {
                Ok(transaction) => transaction,
                Err(error @ InstallationError::MigrationRequired { .. }) => {
                    write_json_error("INSTALLATION_PLAN_MIGRATION_REQUIRED", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
                Err(error) => {
                    write_json_error("INSTALLATION_PLAN_INVALID", &error.to_string());
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
            registry,
            store,
            transaction_id,
        } => match (registry, store, transaction_id) {
            (Some(registry), None, None) => run_installation_registry_status(&registry),
            (None, Some(store), Some(transaction_id)) => {
                run_installation_transaction_status(&store, &transaction_id)
            }
            _ => {
                write_json_error(
                    "INSTALLATION_STATUS_INVALID",
                    "status requires either --registry or both --store and --transaction-id",
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
            write_json_error(
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
            write_json_error("INSTALLATION_CREATE_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = match decode_installation_transaction_json(&bytes) {
        Ok(transaction) => transaction,
        Err(error @ InstallationError::MigrationRequired { .. }) => {
            write_json_error("INSTALLATION_CREATE_MIGRATION_REQUIRED", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_json_error("INSTALLATION_CREATE_INVALID", &error.to_string());
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
            write_json_error(code, &error.to_string());
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

fn run_installation_registry_status(registry: &Path) -> Result<i32> {
    let registry_file_name = registry.file_name().and_then(|value| value.to_str());
    if registry_file_name
        .is_none_or(|value| !value.eq_ignore_ascii_case("installation-registry.redb"))
    {
        write_json_error(
            "INSTALLATION_STATUS_INVALID",
            "registry must name the fixed installation-registry.redb child",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    match std::fs::symlink_metadata(registry) {
        Ok(metadata) if metadata.is_file() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_json_error(
                "INSTALLATION_STATUS_UNAVAILABLE",
                "registry does not exist; status never creates it",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Ok(_) | Err(_) => {
            write_json_error(
                "INSTALLATION_STATUS_INVALID",
                "registry is not an existing regular file",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    }
    let Some(host_state_root) = registry.parent() else {
        write_json_error(
            "INSTALLATION_STATUS_INVALID",
            "registry has no absolute Host-state parent",
        );
        return Ok(INVALID_REQUEST_EXIT);
    };
    let host_state_root = match ProtectedRootLease::open_existing(host_state_root) {
        Ok(root) => root,
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let expected_registry = match host_state_root.canonical_path() {
        Ok(root) => root.join("installation-registry.redb"),
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let observed_registry = match canonical_windows_path(registry) {
        Ok(path) => path,
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if observed_registry != expected_registry {
        write_json_error(
            "INSTALLATION_STATUS_INVALID",
            "registry is not the exact retained Host-state child",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let registry_value = match RedbInstallationRegistry::inspect_existing_at(host_state_root) {
        Ok(Some(registry_value)) => registry_value,
        Ok(None) => {
            write_json_error(
                "INSTALLATION_STATUS_UNAVAILABLE",
                "registry does not exist; status never creates it",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
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

fn run_installation_transaction_status(store_path: &Path, raw_transaction_id: &str) -> Result<i32> {
    let transaction_id = match parse_installation_transaction_id(raw_transaction_id) {
        Ok(transaction_id) => transaction_id,
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path) {
        Ok(store) => store,
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_UNAVAILABLE", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = match store.load(&transaction_id) {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            write_json_error(
                "INSTALLATION_TRANSACTION_NOT_FOUND",
                &format!("transaction is not present in {}", store_path.display()),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_json_error("INSTALLATION_STATUS_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    print_transaction_projection("TRANSACTION_STATUS", store_path, &transaction, None)?;
    Ok(0)
}

fn run_installation_effect(
    store_path: &Path,
    raw_transaction_id: &str,
    recover: bool,
) -> Result<i32> {
    let transaction_id = match parse_installation_transaction_id(raw_transaction_id) {
        Ok(transaction_id) => transaction_id,
        Err(error) => {
            write_json_error(
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
            write_json_error(
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
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    let outcome = if recover {
        coordinator.rollback(&transaction_id)
    } else {
        coordinator.drive_effect(&transaction_id)
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            write_json_error(
                if recover {
                    "INSTALLATION_RECOVER_REJECTED"
                } else {
                    "INSTALLATION_APPLY_REJECTED"
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
            write_json_error(
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
            write_json_error(
                "INSTALLATION_STATE_UNAVAILABLE",
                "effect outcome was returned but the transaction disappeared from the durable store",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_json_error("INSTALLATION_STATE_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    print_transaction_projection(
        if recover {
            "RECOVERY_RESULT"
        } else {
            "EFFECT_RESULT"
        },
        store_path,
        &transaction,
        Some(&outcome),
    )?;
    Ok(installation_outcome_exit_code(&outcome))
}

fn print_transaction_projection(
    status: &str,
    store_path: &Path,
    transaction: &InstallationTransaction,
    outcome: Option<&InstallationStepOutcome>,
) -> Result<()> {
    let transaction_value = serde_json::to_value(transaction)?;
    let outcome_value = outcome.map(serde_json::to_value).transpose()?;
    let outcome_status = outcome.map(installation_outcome_status);
    let completed = matches!(
        transaction.stage(),
        eliot_installation::InstallationStage::Completed
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": outcome_status.unwrap_or(status),
            "store": store_path.display().to_string(),
            "transaction_id": transaction.transaction_id,
            "transaction_wire_version": transaction.transaction_wire_version,
            "stage": transaction.stage(),
            "revision": transaction.revision(),
            "completed": completed,
            "outcome": outcome_value,
            "transaction": transaction_value,
            "scope": "one_durable_effect_or_exact_rollback",
            "deferred_scope": [
                "package_staging",
                "static_verification",
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
        InstallationStepOutcome::Applied { .. } => "EFFECT_APPLIED",
        InstallationStepOutcome::RollbackRequired { .. } => "ROLLBACK_REQUIRED",
        InstallationStepOutcome::Quarantined { .. } => "QUARANTINED",
        InstallationStepOutcome::Rejected => "EFFECT_REJECTED",
    }
}

fn installation_outcome_exit_code(outcome: &InstallationStepOutcome) -> i32 {
    match outcome {
        InstallationStepOutcome::Applied { .. } => 0,
        InstallationStepOutcome::RollbackRequired { .. }
        | InstallationStepOutcome::Quarantined { .. }
        | InstallationStepOutcome::Rejected => INVALID_REQUEST_EXIT,
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
