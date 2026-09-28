#![forbid(unsafe_code)]

//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! composes Governor only from that transport and never creates a local Store,
//! `ProcessExecutor`, or authority source.

mod daemon_runtime;
mod observability;

use eliotd::{PROTOCOL_VERSION, SERVICE_NAME};

#[expect(
    clippy::print_stderr,
    reason = "last-resort operator stderr only after structured write_json failed; statement-level expect is unsupported here (#838)"
)]
fn main() {
    // #740: one bounded stderr subscriber for the process. Protocol/status
    // stdout bytes and framing stay unchanged; init failure keeps the first
    // owner's subscriber and never alters exit/control behavior.
    let _diagnostics = eliotd::diagnostics::init_daemon_diagnostics();
    // Issue #1836 (W1): install the shared observability runtime from the
    // canonical roots this binary already resolves, before the daemon run
    // loop starts. Best-effort by the same contract as the subscriber above:
    // a refused configuration leaves the daemon running on its existing
    // diagnostics and is never turned into a startup failure.
    let _observability = eliot_observability_runtime::install(&observability::daemon_config());
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
