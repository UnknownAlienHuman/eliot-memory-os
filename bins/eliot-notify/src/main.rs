use std::io::{self, BufRead, Write};

use eliot_notify::{default_work_root, NotificationComposition, PROTOCOL_VERSION, SERVICE_NAME};
use eliot_notify_core::{NotificationEnvelope, SignedWatchdogFallbackEnvelope, VerificationPorts};
use eliot_platform::NotificationRequest;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Deliver {
        envelope: NotificationEnvelope,
        request: NotificationRequest,
    },
    DeliverWatchdogFallback {
        envelope: SignedWatchdogFallbackEnvelope,
        request: NotificationRequest,
    },
    Stop,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
    },
    Delivered {
        observation: eliot_notify_core::DeliveryObservation,
    },
    Stopped,
    Error {
        error: String,
    },
}

fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => {
            write_response(Response::Error {
                error: error.to_string(),
            });
            return;
        }
    };
    let mut composition = match NotificationComposition::new(
        root,
        VerificationPorts {
            a08: None,
            g08: None,
            watchdog: None,
            delivery_receipt: None,
            ledger: None,
        },
    ) {
        Ok(composition) => composition,
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
            Ok(line) => dispatch(&mut composition, &line),
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        };
        let stop = matches!(response, Response::Stopped);
        if !write_response(response) || stop {
            break;
        }
    }
}

fn parse_root() -> Result<std::path::PathBuf, io::Error> {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => default_work_root(),
        Some(value) if value == "--work-root" => match args.next() {
            Some(root) if args.next().is_none() => std::fs::canonicalize(root),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--work-root requires exactly one path",
            )),
        },
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown argument: {}", value.to_string_lossy()),
        )),
    }
}

fn dispatch(composition: &mut NotificationComposition, line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(Request::Deliver { envelope, request }) => composition
            .deliver(&envelope, &request)
            .map(|observation| Response::Delivered { observation })
            .unwrap_or_else(|error| Response::Error {
                error: error.to_string(),
            }),
        Ok(Request::DeliverWatchdogFallback { envelope, request }) => composition
            .deliver_watchdog_fallback(&envelope, &request)
            .map(|observation| Response::Delivered { observation })
            .unwrap_or_else(|error| Response::Error {
                error: error.to_string(),
            }),
        Ok(Request::Stop) => Response::Stopped,
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
