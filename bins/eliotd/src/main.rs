#![forbid(unsafe_code)]

//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! composes Governor only from that transport and never creates a local Store,
//! `ProcessExecutor`, or authority source.

mod daemon_runtime;

use eliotd::{PROTOCOL_VERSION, SERVICE_NAME};

fn main() {
    // #740: one bounded stderr subscriber for the process. Protocol/status
    // stdout bytes and framing stay unchanged; init failure keeps the first
    // owner's subscriber and never alters exit/control behavior.
    let _diagnostics = eliotd::diagnostics::init_daemon_diagnostics();
    let _startup = eliotd::diagnostics::emit_startup();
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
