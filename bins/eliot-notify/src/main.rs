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
    let (root, watchdog_fallback) = match parse_launch() {
        Ok(root) => root,
        Err(error) => exit(PROVIDER_REJECTED_EXIT, "NOTIFY_ROOT_REJECTED", error),
    };
    let root = match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => exit(
            PROVIDER_REJECTED_EXIT,
            "NOTIFY_ROOT_REJECTED",
            error.to_string(),
        ),
    };
    if watchdog_fallback {
        let (envelope, request) = match eliot_notify::load_watchdog_fallback_request() {
            Ok(value) => value,
            Err(error) => exit(
                PROVIDER_REJECTED_EXIT,
                "WATCHDOG_FALLBACK_REJECTED",
                error.to_string(),
            ),
        };
        let response = match NotificationComposition::from_fallback(root) {
            Ok(mut composition) => dispatch_fallback(&mut composition, envelope, request),
            Err(error) => composition_error(error.to_string()),
        };
        let provider_error = matches!(response, Response::Error { code, .. } if code == "NOTIFICATION_PROVIDER_REJECTED");
        if !write_response(response) {
            std::process::exit(PROVIDER_REJECTED_EXIT);
        }
        if provider_error {
            std::process::exit(PROVIDER_REJECTED_EXIT);
        }
        return;
    }

    // Normal notification is intentionally one-shot. The caller selects the
    // Kernel-backed route through an authenticated provider operation; the
    // scheduler fallback above has no caller-supplied request authority.
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
        Ok(Request::Deliver { envelope, request }) => {
            match NotificationComposition::from_kernel(root) {
                Ok(mut composition) => dispatch_deliver(&mut composition, envelope, request),
                Err(error) => composition_error(error.to_string()),
            }
        }
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

fn parse_launch() -> Result<(PathBuf, bool), String> {
    let expected = eliot_platform_windows::protected_program_data_path("Eliot/notify")
        .map_err(|error| error.to_string())?;
    let mut args = std::env::args_os().skip(1);
    let mut watchdog_fallback = false;
    let mut supplied_root = None;
    while let Some(value) = args.next() {
        if value == "--watchdog-fallback" {
            if watchdog_fallback {
                return Err("--watchdog-fallback may only be supplied once".to_owned());
            }
            watchdog_fallback = true;
        } else if value == "--work-root" {
            if supplied_root.is_some() {
                return Err("--work-root may only be supplied once".to_owned());
            }
            supplied_root = Some(
                args.next()
                    .ok_or_else(|| "--work-root requires exactly one path".to_owned())?,
            );
        } else {
            return Err(format!("unknown argument: {}", value.to_string_lossy()));
        }
    }
    let supplied_root_given = supplied_root.is_some();
    let root = supplied_root.map_or_else(
        || Ok(expected.clone()),
        |value| {
            let supplied = PathBuf::from(value);
            if supplied != expected {
                return Err(
                    "work root must equal the protected ProgramData notification contour"
                        .to_owned(),
                );
            }
            Ok(supplied)
        },
    )?;
    if watchdog_fallback && supplied_root_given {
        // Keep the scheduler mode deterministic: it always resolves the
        // installer-owned contour and does not accept a caller-selected root.
        return Err("watchdog fallback does not accept --work-root".to_owned());
    }
    Ok((root, watchdog_fallback))
}

fn dispatch_deliver(
    composition: &mut NotificationComposition,
    envelope: NotificationEnvelope,
    request: NotificationRequest,
) -> Response {
    composition
        .deliver(&envelope, &request)
        .map(|observation| Response::Delivered {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            observation,
        })
        .unwrap_or_else(notify_error)
}

fn dispatch_fallback(
    composition: &mut NotificationComposition,
    envelope: SignedWatchdogFallbackEnvelope,
    request: NotificationRequest,
) -> Response {
    composition
        .deliver_watchdog_fallback(&envelope, &request)
        .map(|observation| Response::Delivered {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            observation,
        })
        .unwrap_or_else(notify_error)
}

fn composition_error(detail: String) -> Response {
    Response::Error {
        code: "NOTIFICATION_PROVIDER_REJECTED",
        detail,
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
