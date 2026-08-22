#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use clap::Parser;
use eliot_live_canary::{
    CANARY_DEVELOPMENT_SCHEMA, CanaryConfig, CanaryEvidenceAuthority, DEFAULT_DEADLINE_MS,
    MAX_DEADLINE_MS, ProductionCanary, Pulse, write_development_evidence,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "eliot-live-canary",
    version,
    about = "Non-production development runner for bounded ELIOT canary Pulses 1-5"
)]
struct Args {
    #[arg(long)]
    host_state_root: PathBuf,
    #[arg(long)]
    /// Arbitrary development/test output only; never a production authority location.
    evidence_dir: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
    pulse: u8,
    #[arg(long, default_value_t = DEFAULT_DEADLINE_MS, value_parser = clap::value_parser!(u64).range(1..=MAX_DEADLINE_MS))]
    deadline_ms: u64,
    /// Required before any Kernel/Store mutation or Host SCM restart can be attempted.
    #[arg(long)]
    execute_faults: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let pulse = Pulse::try_from(args.pulse).map_err(|error| anyhow::anyhow!(error))?;
    let config = CanaryConfig {
        host_state_root: args.host_state_root,
        evidence_dir: args.evidence_dir,
        pulse,
        deadline: Duration::from_millis(args.deadline_ms),
        execute_faults: args.execute_faults,
    };
    let canary = ProductionCanary::new(config.clone()).map_err(|error| anyhow::anyhow!(error))?;
    let disposition = canary.run().await;
    let publication = write_development_evidence(&config.evidence_dir, pulse, &disposition)
        .map_err(|error| anyhow::anyhow!(error))?;
    let result = serde_json::json!({
        "schema": CANARY_DEVELOPMENT_SCHEMA,
        "authority": CanaryEvidenceAuthority::NonProductionDevelopment,
        "pulse": pulse,
        "disposition": disposition,
        "evidence_path": publication.path,
        "evidence_digest": publication.digest,
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    if result
        .get("disposition")
        .and_then(|value| value.get("disposition"))
        .and_then(serde_json::Value::as_str)
        == Some("PASS")
    {
        return Ok(());
    }
    let code = if result
        .get("disposition")
        .and_then(|value| value.get("disposition"))
        .and_then(serde_json::Value::as_str)
        == Some("BLOCKED")
    {
        75
    } else {
        2
    };
    std::process::exit(code);
}
