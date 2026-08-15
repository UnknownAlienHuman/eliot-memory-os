#![forbid(unsafe_code)]

mod composition;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use composition::GovernorComposition;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "eliot-governor", about = "ELIOT Memory OS Governor")]
struct Cli {
    #[arg(long, env = "ELIOT_DATA_ROOT", global = true)]
    data_root: Option<PathBuf>,

    #[arg(long, env = "ELIOT_INSTANCE", default_value = "default", global = true)]
    instance: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    Catalogue {
        #[command(subcommand)]
        command: CatalogueCommand,
    },
    Version,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Run,
    Status,
}

#[derive(Debug, Subcommand)]
enum CatalogueCommand {
    Help,
    Schema,
    Validate,
}

fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("eliot-governor-main".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| run())
        .context("spawn the Governor entrypoint")?
        .join()
        .map_err(|_| anyhow::anyhow!("Governor entrypoint panicked"))?
}

fn run() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let data_root = cli
        .data_root
        .map(Ok)
        .unwrap_or_else(default_data_root)
        .context("resolve the Governor data root")?;

    match cli.command {
        Command::Version => {
            println!("eliot-governor {VERSION}");
            Ok(())
        }
        Command::Catalogue { command } => run_catalogue(command),
        Command::Daemon { command } => {
            let composition = GovernorComposition::new(data_root, cli.instance);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build the Governor Tokio runtime")?;
            runtime.block_on(run_daemon(composition, command))
        }
    }
}

async fn run_daemon(mut composition: GovernorComposition, command: DaemonCommand) -> Result<()> {
    match command {
        DaemonCommand::Run => composition.run_until_interrupt().await,
        DaemonCommand::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&composition.status()?)?
            );
            Ok(())
        }
    }
}

fn run_catalogue(command: CatalogueCommand) -> Result<()> {
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

fn default_data_root() -> Result<PathBuf> {
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data).join("Eliot"));
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(home).join("AppData").join("Local").join("Eliot"));
    }
    std::env::current_dir()
        .map(|path| path.join(".eliot"))
        .context("resolve the current directory for the Governor data root")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}
