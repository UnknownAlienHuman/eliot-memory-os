use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use eliot_process::OperationId;
use eliot_user_broker::{BrokerComposition, BrokerConfig, canonical_root};
use eliot_user_broker_core::LaunchRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PROVIDER_REJECTED_EXIT: i32 = 69;
// The authenticated registration lease is refreshed while the broker is
// idle.  This interval is deliberately short and bounded; a failed refresh
// terminates the broker rather than allowing an expired registration to serve
// launch requests.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
// The line protocol mirrors the existing launch contract without a second boxed wire shape.
#[allow(clippy::large_enum_variant)]
enum Request {
    Launch { request: LaunchRequest },
    Cancel { operation_id: OperationId },
    Reconcile { operation_id: OperationId },
    Status,
    Stop,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Message {
    Ready { readiness: Value },
    Launched { receipt: Value },
    Cancelled { receipt: Value },
    Reconciled { view: Value },
    Stopped,
    Error { code: &'static str, detail: String },
}

// One loop owns heartbeat timing, request dispatch, and fail-closed shutdown accounting.
#[allow(clippy::too_many_lines)]
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
    if let Err(error) = composition.self_register() {
        exit(
            PROVIDER_REJECTED_EXIT,
            "BROKER_SELF_AUTHENTICATION_REJECTED",
            error.to_string(),
        );
    }
    let readiness = serde_json::to_value(composition.readiness())
        .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()}));
    if !write_message(&Message::Ready { readiness }) {
        return;
    }
    // Keep stdin as an admitted-role operation stream while the composition
    // owner retains the only authority-bearing state.  A reader thread lets
    // the owner service the authenticated heartbeat timer even when no input
    // arrives; register/heartbeat identities are never accepted from stdin.
    let (sender, receiver) = mpsc::channel::<Result<String, String>>();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let line = line.map_err(|error| error.to_string());
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
    let mut closed = false;
    loop {
        if Instant::now() >= next_heartbeat {
            if let Err(error) = composition.heartbeat() {
                heartbeat_failure(composition, error.to_string());
            }
            next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
            continue;
        }
        let timeout = next_heartbeat.saturating_duration_since(Instant::now());
        let input_result = match receiver.recv_timeout(timeout) {
            Ok(input_result) => input_result,
            Err(RecvTimeoutError::Timeout) => {
                if let Err(error) = composition.heartbeat() {
                    heartbeat_failure(composition, error.to_string());
                }
                next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let response = match input_result {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut composition, &line),
            Err(error) => Message::Error {
                code: "INPUT_FAILURE",
                detail: error,
            },
        };
        let stop = matches!(response, Message::Stopped);
        if stop {
            let (response, close_failed) = match close_with_retry(&mut composition) {
                Ok(()) => (response, false),
                Err(error) => (
                    Message::Error {
                        code: "BROKER_CLOSE_REJECTED",
                        detail: error,
                    },
                    true,
                ),
            };
            if !close_failed {
                closed = true;
            }
            if !write_message(&response) {
                break;
            }
            if close_failed {
                std::process::exit(PROVIDER_REJECTED_EXIT);
            }
            break;
        }
        if !write_message(&response) {
            break;
        }
    }
    if !closed && let Err(error) = close_with_retry(&mut composition) {
        exit(PROVIDER_REJECTED_EXIT, "BROKER_CLOSE_REJECTED", error);
    }
}

fn close_with_retry(composition: &mut BrokerComposition) -> Result<(), String> {
    match composition.close() {
        Ok(()) => Ok(()),
        Err(first) => composition
            .close()
            .map_err(|second| format!("{first}; retry: {second}")),
    }
}

fn heartbeat_failure(composition: BrokerComposition, detail: String) -> ! {
    // A failed heartbeat has an unknown ORS outcome, so issuing a second
    // close request here could duplicate or misclassify the authoritative
    // fence.  Dropping the composition first closes the broker-owned
    // kill-on-close Job contour; its durable Active/Unknown snapshot remains
    // for the next authenticated startup heartbeat/reconciliation pass.
    drop(composition);
    exit(PROVIDER_REJECTED_EXIT, "BROKER_HEARTBEAT_REJECTED", detail)
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
        Request::Launch { request } => composition.launch(request).map_or_else(
            |error| composition_error(error.to_string()),
            |receipt| Message::Launched {
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
            },
        ),
        Request::Cancel { operation_id } => composition.cancel(&operation_id).map_or_else(
            |error| composition_error(error.to_string()),
            |receipt| Message::Cancelled {
                receipt: serde_json::to_value(receipt)
                    .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()})),
            },
        ),
        Request::Reconcile { operation_id } => composition.reconcile(&operation_id).map_or_else(
            |error| composition_error(error.to_string()),
            |view| Message::Reconciled {
                view: serde_json::to_value(view)
                    .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()})),
            },
        ),
        Request::Status => Message::Ready {
            readiness: serde_json::to_value(composition.readiness())
                .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()})),
        },
        Request::Stop => Message::Stopped,
    }
}

fn composition_error(detail: String) -> Message {
    Message::Error {
        code: "BROKER_COMPOSITION_REJECTED",
        detail,
    }
}

fn write_message(message: &Message) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, message).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

fn exit(code: i32, error_code: &'static str, detail: String) -> ! {
    let message = Message::Error {
        code: error_code,
        detail,
    };
    let _ = write_message(&message);
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use eliot_process::OperationId;

    use super::Request;

    #[test]
    fn stdin_cannot_supply_registration_or_request_identity_authority() {
        assert!(
            serde_json::from_str::<Request>(r#"{"op":"register","identity":{},"request":{}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Request>(r#"{"op":"heartbeat","identity":{},"request":{}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Request>(r#"{"op":"launch","identity":{},"request":{}}"#)
                .is_err()
        );
        let cancel = serde_json::json!({
            "op": "cancel",
            "operation_id": "operation-1"
        });
        assert!(serde_json::from_value::<Request>(cancel).is_ok());
        assert!(
            serde_json::from_str::<Request>(
                r#"{"op":"cancel","operation_id":"operation-1","permit":{}}"#
            )
            .is_err()
        );
        assert!(OperationId::new("operation-1").is_ok());
    }
}
