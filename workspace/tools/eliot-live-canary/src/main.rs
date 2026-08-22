#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use clap::Parser;
use eliot_live_canary::{
    CanaryConfig, DEFAULT_DEADLINE_MS, MAX_DEADLINE_MS, ProductionCanary, Pulse, write_evidence,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "eliot-live-canary",
    version,
    about = "Bounded, fail-closed ELIOT runtime-live canary Pulses 1-4"
)]
struct Args {
    #[arg(long)]
    host_state_root: PathBuf,
    #[arg(long)]
    evidence_dir: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=4))]
    pulse: u8,
    #[arg(long, default_value_t = DEFAULT_DEADLINE_MS, value_parser = clap::value_parser!(u64).range(1..=MAX_DEADLINE_MS))]
    deadline_ms: u64,
    /// Required before any Kernel/Store mutation can be attempted.
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
    let (evidence_path, evidence_digest) =
        write_evidence(&config.evidence_dir, pulse, &disposition)
            .map_err(|error| anyhow::anyhow!(error))?;
    let result = serde_json::json!({
        "schema": eliot_live_canary::CANARY_SCHEMA,
        "pulse": pulse,
        "disposition": disposition,
        "evidence_path": evidence_path,
        "evidence_digest": evidence_digest,
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
