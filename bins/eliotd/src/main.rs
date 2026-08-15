//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! deliberately refuses to construct a local provider or derive authority
//! from command-line, environment, or current-directory state.

use std::io::{self, Write};

use eliotd::{DaemonConfig, PROTOCOL_VERSION, SERVICE_NAME};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ReadyMessage {
    Error {
        service: &'static str,
        protocol: &'static str,
        error: String,
    },
}

fn main() {
    let error = match DaemonConfig::load_protected() {
        Ok(_config) => {
            "Host-approved authenticated Kernel generation client bootstrap is required before eliotd can compose"
                .to_owned()
        }
        Err(error) => error.to_string(),
    };
    write_json(&ReadyMessage::Error {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        error,
    });
    std::process::exit(78);
}

fn write_json(message: &ReadyMessage) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _ = serde_json::to_writer(&mut output, message);
    let _ = output.write_all(b"\n");
    let _ = output.flush();
}
