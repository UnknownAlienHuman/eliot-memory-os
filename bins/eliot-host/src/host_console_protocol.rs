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
