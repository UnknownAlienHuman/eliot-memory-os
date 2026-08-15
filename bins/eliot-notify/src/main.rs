use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_notify::{NotificationComposition, PROTOCOL_VERSION, SERVICE_NAME};
use eliot_notify_core::{NotificationEnvelope, NotifyError, SignedWatchdogFallbackEnvelope};
use eliot_platform::NotificationRequest;
use serde::{Deserialize, Serialize};

const REQUEST_INVALID_EXIT: i32 = 2;
const PROVIDER_REJECTED_EXIT: i32 = 69;

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
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Delivered {
        service: &'static str,
        protocol: &'static str,
        observation: eliot_notify_core::DeliveryObservation,
    },
    Error {
        code: &'static str,
        detail: String,
    },
}

fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => exit(PROVIDER_REJECTED_EXIT, "NOTIFY_ROOT_REJECTED", error),
    };
    if let Err(error) = eliot_platform_windows::prepare_protected_directory(&root) {
        exit(
            PROVIDER_REJECTED_EXIT,
            "NOTIFY_PROTECTED_ROOT_REJECTED",
            error.to_string(),
        );
    }
    let root = match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => exit(
            PROVIDER_REJECTED_EXIT,
            "NOTIFY_ROOT_REJECTED",
            error.to_string(),
        ),
    };
    let mut composition = match NotificationComposition::from_kernel(root) {
        Ok(composition) => composition,
        Err(error) => exit(
            PROVIDER_REJECTED_EXIT,
            "NOTIFY_COMPOSITION_REJECTED",
            error.to_string(),
        ),
    };

    // Notification is intentionally one-shot: no persistent stdin service,
    // replay loop, or local delivery authority is created here.
    let line = match io::stdin()
        .lock()
        .lines()
        .find_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
    {
        Some(line) => line,
        None => exit(
            REQUEST_INVALID_EXIT,
            "NOTIFICATION_REQUEST_REQUIRED",
            "one JSON notification request is required".to_owned(),
        ),
    };
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(request) => dispatch(&mut composition, request),
        Err(error) => Response::Error {
            code: "REQUEST_INVALID",
            detail: error.to_string(),
        },
    };
    let provider_error = matches!(response, Response::Error { code, .. } if code == "NOTIFICATION_PROVIDER_REJECTED");
    if !write_response(response) {
        std::process::exit(PROVIDER_REJECTED_EXIT);
    }
    if provider_error {
        std::process::exit(PROVIDER_REJECTED_EXIT);
    }
}

fn parse_root() -> Result<PathBuf, String> {
    let expected = eliot_platform_windows::protected_program_data_path("Eliot/notify")
        .map_err(|error| error.to_string())?;
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => Ok(expected),
        Some(value) if value == "--work-root" => {
            let supplied = args
                .next()
                .ok_or_else(|| "--work-root requires exactly one path".to_owned())?;
            if args.next().is_some() {
                return Err("--work-root requires exactly one path".to_owned());
            }
            let supplied = PathBuf::from(supplied);
            if supplied != expected {
                return Err(
                    "work root must equal the protected ProgramData notification contour"
                        .to_owned(),
                );
            }
            Ok(supplied)
        }
        Some(value) => Err(format!("unknown argument: {}", value.to_string_lossy())),
    }
}

fn dispatch(composition: &mut NotificationComposition, request: Request) -> Response {
    match request {
        Request::Deliver { envelope, request } => composition
            .deliver(&envelope, &request)
            .map(|observation| Response::Delivered {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                observation,
            })
            .unwrap_or_else(notify_error),
        Request::DeliverWatchdogFallback { envelope, request } => composition
            .deliver_watchdog_fallback(&envelope, &request)
            .map(|observation| Response::Delivered {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                observation,
            })
            .unwrap_or_else(notify_error),
    }
}

fn notify_error(error: NotifyError) -> Response {
    let code = if matches!(error, NotifyError::PlanGap { .. }) {
        "NOTIFICATION_PROVIDER_REJECTED"
    } else {
        "NOTIFICATION_REQUEST_REJECTED"
    };
    Response::Error {
        code,
        detail: error.to_string(),
    }
}

fn write_response(response: Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

fn exit(code: i32, error_code: &'static str, detail: String) -> ! {
    let _ = write_response(Response::Error {
        code: error_code,
        detail,
    });
    std::process::exit(code);
}
