use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_host::{HostComposition, PROTOCOL_VERSION, SERVICE_NAME};
use eliot_host_state::{EpochIdentity, EpochTransition, HostInstallationEpoch};
use eliot_platform::PlatformHandle;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Stop,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
    },
    State {
        running: bool,
        sequence: u64,
    },
    Stopped,
    Error {
        error: String,
    },
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let state = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("eliot-host-state.json"));
    let host = HostInstallationEpoch {
        installation: handle("installation"),
        epoch: EpochTransition {
            current: EpochIdentity {
                lineage: handle("host"),
                sequence: 1,
            },
            parent: None,
        },
        nonce: handle("boot"),
        recovery: None,
    };
    let mut host = match HostComposition::open(state, host) {
        Ok(host) => host,
        Err(error) => {
            write_response(Response::Error {
                error: error.to_string(),
            });
            return;
        }
    };
    if !write_response(Response::Ready {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
    }) {
        return;
    }
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut host, &line),
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        };
        if !write_response(response) {
            break;
        }
        if !host.running() {
            break;
        }
    }
}

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn dispatch(host: &mut HostComposition, line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(Request::Status) => match host.snapshot() {
            Ok(state) => Response::State {
                running: host.running(),
                sequence: state.sequence,
            },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Ok(Request::Stop) => match host.stop() {
            Ok(()) => Response::Stopped,
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Err(error) => Response::Error {
            error: error.to_string(),
        },
    }
}

fn write_response(response: Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
