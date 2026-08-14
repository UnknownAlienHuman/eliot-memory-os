use clap::Parser;
use eliot_runtime_compiler::{CompileOptions, compile};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "eliot-runtime-compiler",
    version,
    about = "Deterministically verifies the sealed ELIOT runtime projections"
)]
struct Args {
    /// Runtime projection root containing `Eliot_Runtime_BundleManifest.json`.
    #[arg(long, conflicts_with = "runtime_root")]
    bundle: Option<PathBuf>,
    #[arg(long)]
    runtime_root: Option<PathBuf>,
    /// Canonical normative-book root containing `ELIOT_ARCHITECTURE.md` and
    /// `ELIOT_IMPLEMENTATION.md`.
    #[arg(long)]
    normative_root: Option<PathBuf>,
    #[arg(long)]
    repository: PathBuf,
    /// Optional external report. Existing reports are immutable unless bytes are identical.
    #[arg(long)]
    report: Option<PathBuf>,
}

// This CLI's sole contract is emitting exactly one JSON receipt on stdout.
#[allow(clippy::print_stdout)]
fn main() {
    let args = Args::parse();
    let runtime_root = args
        .runtime_root
        .or(args.bundle)
        .unwrap_or_else(|| PathBuf::from("."));
    let normative_root = args.normative_root.unwrap_or_else(|| runtime_root.clone());
    let receipt = compile(&CompileOptions {
        runtime_root,
        normative_root,
        repository: args.repository,
        report: args.report,
    });
    let encoded = match serde_json::to_string(&receipt) {
        Ok(encoded) => encoded,
        Err(error) => panic!("receipt serialization failed unexpectedly: {error}"),
    };
    println!("{encoded}");
    if receipt.get("verdict").and_then(serde_json::Value::as_str) != Some("PASS") {
        std::process::exit(1);
    }
}
