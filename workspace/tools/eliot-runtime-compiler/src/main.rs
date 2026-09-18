use clap::Parser;
use eliot_runtime_compiler::{CompileOptions, compile};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "eliot-runtime-compiler",
    version,
    about = "Read-only historical D-01 verifier (LEGACY_D01); not current support evidence; read-only, non-authoritative"
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

// This CLI's sole contract is emitting exactly one JSON receipt on stdout — legacy, non-authoritative; verifier PASS alone never implies runtime/Product support.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() {
    let args = Args::parse();
    let runtime_root = args
        .runtime_root
        .or(args.bundle)
        .unwrap_or_else(|| PathBuf::from("."));
    let normative_root = args.normative_root.unwrap_or_else(|| runtime_root.clone());
    // LEGACY_D01: compile() is the deprecated alias of verify_legacy_d01 (other half of this slice).
    let receipt = compile(&CompileOptions {
        runtime_root,
        normative_root,
        repository: args.repository,
        report: args.report,
    });
    let encoded = match serde_json::to_string(&receipt) {
        Ok(encoded) => encoded,
        Err(error) => {
            // LEGACY_D01 typed fail-closed serialization failure: never panic, never partial PASS.
            // Mirrors lib.rs `report.serialize` FAIL shape with a minimal FAIL receipt.
            if let Ok(fallback) = serde_json::to_string(&serde_json::json!({
                "schema_version": "eliot-runtime-compiler-receipt-v1",
                "work_id": "D-01",
                "verdict": "FAIL",
                "errors": [{"check_id": "report.serialize", "message": error.to_string()}]
            })) {
                println!("{fallback}");
            }
            eprintln!("receipt serialization failed: {error}");
            std::process::exit(2);
        }
    };
    println!("{encoded}");
    if receipt.get("verdict").and_then(serde_json::Value::as_str) != Some("PASS") {
        std::process::exit(1);
    }
}
