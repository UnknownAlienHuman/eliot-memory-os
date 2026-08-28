//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! composes Governor only from that transport and never creates a local Store,
//! `ProcessExecutor`, or authority source.

mod daemon_runtime;

use eliotd::{PROTOCOL_VERSION, SERVICE_NAME};

fn main() {
    if let Err(error) = daemon_runtime::run() {
        daemon_runtime::write_json(&daemon_runtime::ReadyMessage::Error {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            error,
        });
        std::process::exit(1);
    }
}
