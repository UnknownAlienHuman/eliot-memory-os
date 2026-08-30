//! Zero-model Codex App Server stable-wire diagnostic.

#[path = "../app_server_stable_wire.rs"]
mod app_server_stable_wire;

use std::io::{self, BufRead, Write};

use app_server_stable_wire::{
    ModelCatalogueAccumulator, encode_jsonl, initialize_request, initialized_notification,
};

const USAGE: &str =
    "usage: codex_app_server_preflight --emit-requests-only | --validate-model-pages";

fn main() {
    if let Err(error) = run() {
        eprintln!("codex app-server preflight failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("--emit-requests-only") => emit_requests(),
        Some("--validate-model-pages") => validate_model_pages(),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE).into()),
    }
}

fn emit_requests() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for message in [
        initialize_request(1, "eliot", Some("ELIOT"), env!("CARGO_PKG_VERSION"))?,
        initialized_notification(),
        ModelCatalogueAccumulator::new().request(2)?,
    ] {
        output.write_all(&encode_jsonl(&message)?)?;
    }
    output.flush()?;
    Ok(())
}

fn validate_model_pages() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut catalogue = ModelCatalogueAccumulator::new();
    let mut request_id = 2_u64;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        catalogue.accept_response_line(line.as_bytes(), request_id)?;
        request_id = request_id.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "model-list request id overflow",
            )
        })?;
    }
    let catalogue = catalogue.finish()?;
    serde_json::to_writer(io::stdout().lock(), &catalogue)?;
    println!();
    Ok(())
}
