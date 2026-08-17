#![forbid(unsafe_code)]
// Machine-readable and human CLI output is the public contract of this binary.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use eliot_bootstrap::capture::{capture_snapshot, write_snapshot_artifact};
use eliot_cli::{CommandCatalogue, CommandPort, CommandPortError, CommandRequest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const INVALID_REQUEST_EXIT: i32 = 2;
const FRONT_DOOR_CLOSED_EXIT: i32 = 69;

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
    Version,
    /// Start or reuse the authenticated User Broker and launch Operator.
    Ui,
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
        Command::Dispatch => run_dispatch(),
        Command::Ui => run_ui(),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorEndpoint {
    pipe_name: String,
    broker_epoch: u64,
    interactive_session_id: String,
    handoff_nonce: String,
    role: String,
    capabilities: Vec<String>,
}

#[cfg(windows)]
fn run_ui() -> Result<i32> {
    let mut client =
        AuthenticatedKernelPort::load().map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let endpoint = client.ensure_operator_endpoint()?;
    if endpoint.role != "human_operator"
        || endpoint.broker_epoch == 0
        || endpoint.pipe_name.trim().is_empty()
        || endpoint.interactive_session_id.trim().is_empty()
        || endpoint.handoff_nonce.trim().is_empty()
        || endpoint.capabilities.is_empty()
    {
        anyhow::bail!("Kernel returned an invalid role-filtered Operator endpoint");
    }
    let operator = std::env::var_os("ELIOT_OPERATOR_EXE")
        .map_or_else(
            || {
                std::env::current_exe().ok().and_then(|path| {
                    path.parent()
                        .map(|parent| parent.join("Eliot.Operator.exe").into_os_string())
                })
            },
            Some,
        )
        .ok_or_else(|| anyhow::anyhow!("ELIOT_OPERATOR_EXE is not configured"))?;
    let status = std::process::Command::new(operator)
        .env(
            "ELIOT_OPERATOR_ENDPOINT",
            serde_json::to_string(&endpoint).context("encode Operator endpoint")?,
        )
        .spawn()
        .context("launch Eliot.Operator through the authenticated User Broker")?;
    println!(
        "eliot ui attached to User Broker epoch {}",
        endpoint.broker_epoch
    );
    drop(status);
    Ok(0)
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

    fn ensure_operator_endpoint(&mut self) -> Result<OperatorEndpoint> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let request_id = format!("eliot-ui-{now}-{}", std::process::id());
        let identity: eliot_protocol::RequestIdentity = serde_json::from_value(json!({
            "request": {
                "metadata": {
                    "request_id": request_id,
                    "session_id": null,
                    "task_id": null,
                    "product_id": "eliot-ui",
                    "source_id": "eliot-cli",
                    "state_fence": {
                        "authority_epoch": 1,
                        "resource_generation": 1,
                        "task_revision": null,
                        "policy_revision": null,
                        "integration_revision": null
                    },
                    "clock": {
                        "valid_time_ms": now,
                        "known_time_ms": now,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    }
                },
                "state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                }
            },
            "idempotency_key": format!("eliot-ui-{now}"),
            "deadline_unix_ms": now + 30_000,
            "cancellation_id": format!("eliot-ui:{now}")
        }))?;
        self.client.set_request_identity(identity);
        let payload = self
            .client
            .transact_json(
                "eliot.user-broker.ensure-operator",
                json!({
                    "role": "human_operator",
                    "capabilities": ["controlboard.read", "operator.command"]
                }),
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        serde_json::from_value(payload).context("decode User Broker Operator endpoint")
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
