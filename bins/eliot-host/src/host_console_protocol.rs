//! Host console protocol envelope serialization only.
//!
//! This child owns the existing `Request`/`Response` wire shapes and the
//! newline/flush-preserving response writer. It owns no Host lifecycle, SCM,
//! credential, launch-option, semantic, canonical, or authority capability.
//!
//! Canonical anchors: Architecture `A13.2` places Host Supervisor outside the
//! Kernel/Watchdog/Doctor process failure domain; Implementation `I1.2`
//! assigns Host lifecycle ownership while excluding project semantics and
//! canonical memory, `I1.8` keeps transport identity separate from semantic
//! session authority, and `I2.23` requires bounded extraction ownership.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Status,
    Stop,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
    },
    State {
        running: bool,
        active_process: bool,
        managed_dependencies: usize,
    },
    Stopped,
    Error {
        error: String,
    },
}

pub(super) fn write_response(response: &Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

/// Combines the primary console outcome with the single drain outcome.
///
/// Audit 5910117501 item 1 (cases 8, 9, 11): a read/write/protocol failure is
/// the primary console outcome, so it stays failure even when cleanup
/// (`finish_console_shutdown`) succeeds and `main` still reaches the existing
/// `console_failed` terminal/capsule/exit path. The drain itself still runs
/// exactly once per `run_console` path; this only decides the returned bool.
#[must_use]
pub(super) fn console_run_ok(primary_ok: bool, drained: bool) -> bool {
    primary_ok && drained
}

#[cfg(test)]
mod tests {
    use super::console_run_ok;

    // Positive: a clean console run with a clean drain stays successful.
    #[test]
    fn console_run_ok_keeps_clean_drain_successful() {
        assert!(console_run_ok(true, true));
    }

    // Refusal: audit 5910117501 item 1 — a read/write/protocol failure must
    // remain failure even when cleanup succeeds (drain `true`).
    #[test]
    fn console_run_ok_keeps_protocol_failure_failed_after_clean_drain() {
        assert!(!console_run_ok(false, true));
    }
}
