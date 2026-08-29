//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! composes Governor only from that transport and never creates a local Store,
//! `ProcessExecutor`, or authority source.

mod daemon_runtime;

use eliotd::{PROTOCOL_VERSION, SERVICE_NAME};

fn main() {
    if let Err(error) = daemon_runtime::run() {
        let message = daemon_runtime::ReadyMessage::Error {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            error: error.clone(),
        };
        if let Err(output_error) = daemon_runtime::write_json(&message) {
            eprintln!(
                "eliotd structured error output failed: {output_error}; original failure: {error}"
            );
        }
        std::process::exit(1);
    }
}
