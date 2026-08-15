use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_protocol::RequestIdentity;
use eliot_user_broker::{BrokerComposition, BrokerConfig, canonical_root};
use eliot_user_broker_core::{BrokerError, HeartbeatRequest, LaunchRequest, RegistrationRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PROVIDER_REJECTED_EXIT: i32 = 69;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Register {
        identity: RequestIdentity,
        request: RegistrationRequest,
    },
    Heartbeat {
        identity: RequestIdentity,
        request: HeartbeatRequest,
    },
    Launch {
        identity: RequestIdentity,
        request: LaunchRequest,
    },
    Status,
    Stop,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Message {
    Ready { readiness: Value },
    Registered { receipt: Value },
    Heartbeat { receipt: Value },
    Launched { receipt: Value },
    Stopped,
    Error { code: &'static str, detail: String },
}

fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => exit(
            PROVIDER_REJECTED_EXIT,
            "BROKER_CONFIGURATION_REJECTED",
            error,
        ),
    };
    if let Err(error) = eliot_platform_windows::prepare_protected_directory(&root) {
        exit(
            PROVIDER_REJECTED_EXIT,
            "BROKER_PROTECTED_ROOT_REJECTED",
            error.to_string(),
        );
    }
    let root = match canonical_root(&root) {
        Ok(root) => root,
        Err(error) => exit(
            PROVIDER_REJECTED_EXIT,
            "BROKER_ROOT_REJECTED",
            error.to_string(),
        ),
    };
    let mut composition = match BrokerComposition::start_with_kernel(BrokerConfig::from_root(root))
    {
        Ok(composition) => composition,
        Err(error) => exit(
            PROVIDER_REJECTED_EXIT,
            "BROKER_COMPOSITION_REJECTED",
            error.to_string(),
        ),
    };
    let readiness = serde_json::to_value(composition.readiness())
        .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()}));
    if !write_message(Message::Ready { readiness }) {
        return;
    }
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut composition, &line),
            Err(error) => Message::Error {
                code: "INPUT_FAILURE",
                detail: error.to_string(),
            },
        };
        let stop = matches!(response, Message::Stopped);
        if !write_message(response) || stop {
            break;
        }
    }
}

fn parse_root() -> Result<PathBuf, String> {
    let expected = eliot_platform_windows::protected_program_data_path("Eliot/user-broker")
        .map_err(|error| error.to_string())?;
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => Ok(expected),
        Some(value) if value == "--data-root" => {
            let supplied = args
                .next()
                .ok_or_else(|| "--data-root requires exactly one path".to_owned())?;
            if args.next().is_some() {
                return Err("--data-root requires exactly one path".to_owned());
            }
            let supplied = PathBuf::from(supplied);
            if supplied != expected {
                return Err(
                    "data root must equal the protected ProgramData broker contour".to_owned(),
                );
            }
            Ok(supplied)
        }
        Some(value) => Err(format!("unknown argument: {}", value.to_string_lossy())),
    }
}

fn dispatch(composition: &mut BrokerComposition, line: &str) -> Message {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Message::Error {
                code: "REQUEST_INVALID",
                detail: error.to_string(),
            };
        }
    };
    match request {
        Request::Register { identity, request } => {
            if let Err(error) = composition.set_request_identity(identity) {
                return composition_error(error.to_string());
            }
            composition
                .broker()
                .register(request)
                .map(|receipt| Message::Registered {
                    receipt: serde_json::to_value(receipt)
                        .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()})),
                })
                .unwrap_or_else(broker_error)
        }
        Request::Heartbeat { identity, request } => {
            if let Err(error) = composition.set_request_identity(identity) {
                return composition_error(error.to_string());
            }
            composition
                .broker()
                .heartbeat(request)
                .map(|receipt| Message::Heartbeat {
                    receipt: serde_json::to_value(receipt)
                        .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()})),
                })
                .unwrap_or_else(broker_error)
        }
        Request::Launch { identity, request } => {
            if let Err(error) = composition.set_request_identity(identity) {
                return composition_error(error.to_string());
            }
            composition
                .broker()
                .launch(request)
                .map(|receipt| Message::Launched {
                    receipt: serde_json::json!({
                        "operation_id": receipt.operation_id.as_str(),
                        "request_digest": receipt.request_digest,
                        "registration_digest": receipt.registration_digest,
                        "user_broker_epoch": receipt.user_broker_epoch,
                        "fence_id": receipt.fence_id,
                        "process_receipt": receipt.process_receipt,
                        "proof_ceiling": receipt.proof_ceiling,
                        "lineage_verified": receipt.lineage_verified,
                        "disposition": receipt.disposition,
                    }),
                })
                .unwrap_or_else(broker_error)
        }
        Request::Status => Message::Ready {
            readiness: serde_json::to_value(composition.readiness())
                .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()})),
        },
        Request::Stop => Message::Stopped,
    }
}

fn broker_error(error: BrokerError) -> Message {
    let code = if matches!(error, BrokerError::PlanGap(_)) {
        "KERNEL_PROVIDER_REJECTED"
    } else {
        "BROKER_REQUEST_REJECTED"
    };
    Message::Error {
        code,
        detail: error.to_string(),
    }
}

fn composition_error(detail: String) -> Message {
    Message::Error {
        code: "BROKER_COMPOSITION_REJECTED",
        detail,
    }
}

fn write_message(message: Message) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &message).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

fn exit(code: i32, error_code: &'static str, detail: String) -> ! {
    let _ = write_message(Message::Error {
        code: error_code,
        detail,
    });
    std::process::exit(code);
}
