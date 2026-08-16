use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_notify::{NotificationComposition, PROTOCOL_VERSION, SERVICE_NAME};
use eliot_notify_core::{NotificationEnvelope, NotifyError, SignedWatchdogFallbackEnvelope};
use eliot_platform::NotificationRequest;
use serde::{Deserialize, Serialize};

const REQUEST_INVALID_EXIT: i32 = 2;
const PROVIDER_REJECTED_EXIT: i32 = 69;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchMode {
    Normal,
    WatchdogFallback,
    RegisterWatchdogFallback,
    ActivateWatchdogFallback,
}

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
        observation: Box<eliot_notify_core::DeliveryObservation>,
    },
    WatchdogTaskRegistered {
        service: &'static str,
        protocol: &'static str,
        task_name: String,
        sid: String,
        session_id: u32,
        notify_artifact_sha256: String,
        verifier_sha256: String,
        task_xml_sha256: String,
    },
    WatchdogTaskActivated {
        service: &'static str,
        protocol: &'static str,
        task_name: String,
        sid: String,
        session_id: u32,
        task_xml_sha256: String,
    },
    Error {
        code: &'static str,
        detail: String,
    },
}

#[allow(
    clippy::too_many_lines,
    reason = "the one-shot launcher keeps protected root validation, scheduler modes, and stdin dispatch in an explicit ordered state machine"
)]
fn main() {
    let (root, mode) = match parse_launch() {
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
    if mode == LaunchMode::RegisterWatchdogFallback {
        let receipt = match eliot_notify::register_watchdog_fallback_task() {
            Ok(receipt) => receipt,
            Err(error) => exit(
                PROVIDER_REJECTED_EXIT,
                "WATCHDOG_SCHEDULER_REJECTED",
                error.to_string(),
            ),
        };
        let response = Response::WatchdogTaskRegistered {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            task_name: receipt.task_name().to_owned(),
            sid: receipt.sid().to_owned(),
            session_id: receipt.session_id(),
            notify_artifact_sha256: receipt.notify_artifact_sha256().to_owned(),
            verifier_sha256: receipt.verifier_sha256().to_owned(),
            task_xml_sha256: receipt.task_xml_sha256().to_owned(),
        };
        if !write_response(&response) {
            std::process::exit(PROVIDER_REJECTED_EXIT);
        }
        return;
    }
    if mode == LaunchMode::ActivateWatchdogFallback {
        let receipt = match eliot_notify::activate_watchdog_fallback_task() {
            Ok(receipt) => receipt,
            Err(error) => exit(
                PROVIDER_REJECTED_EXIT,
                "WATCHDOG_SCHEDULER_UNKNOWN",
                error.to_string(),
            ),
        };
        let response = Response::WatchdogTaskActivated {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            task_name: receipt.task_name().to_owned(),
            sid: receipt.sid().to_owned(),
            session_id: receipt.session_id(),
            task_xml_sha256: receipt.task_xml_sha256().to_owned(),
        };
        if !write_response(&response) {
            std::process::exit(PROVIDER_REJECTED_EXIT);
        }
        return;
    }
    if mode == LaunchMode::WatchdogFallback {
        let (envelope, request) = match eliot_notify::load_watchdog_fallback_request() {
            Ok(value) => value,
            Err(error) => exit(
                PROVIDER_REJECTED_EXIT,
                "WATCHDOG_FALLBACK_REJECTED",
                error.to_string(),
            ),
        };
        let response = match NotificationComposition::from_fallback(root) {
            Ok(mut composition) => dispatch_fallback(&mut composition, &envelope, &request),
            Err(error) => composition_error(error.to_string()),
        };
        let provider_error = matches!(response, Response::Error { code, .. } if code == "NOTIFICATION_PROVIDER_REJECTED");
        if !write_response(&response) {
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
    let Some(line) = io::stdin()
        .lock()
        .lines()
        .find_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
    else {
        exit(
            REQUEST_INVALID_EXIT,
            "NOTIFICATION_REQUEST_REQUIRED",
            "one JSON notification request is required".to_owned(),
        )
    };
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(Request::Deliver { envelope, request }) => {
            match NotificationComposition::from_kernel(root) {
                Ok(mut composition) => dispatch_deliver(&mut composition, &envelope, &request),
                Err(error) => composition_error(error.to_string()),
            }
        }
        Err(error) => Response::Error {
            code: "REQUEST_INVALID",
            detail: error.to_string(),
        },
    };
    let provider_error = matches!(response, Response::Error { code, .. } if code == "NOTIFICATION_PROVIDER_REJECTED");
    if !write_response(&response) {
        std::process::exit(PROVIDER_REJECTED_EXIT);
    }
    if provider_error {
        std::process::exit(PROVIDER_REJECTED_EXIT);
    }
}

fn parse_launch() -> Result<(PathBuf, LaunchMode), String> {
    let expected = eliot_platform_windows::protected_program_data_path("Eliot/notify")
        .map_err(|error| error.to_string())?;
    parse_launch_args(std::env::args_os().skip(1), &expected)
}

fn parse_launch_args<I, S>(
    arguments: I,
    expected: &PathBuf,
) -> Result<(PathBuf, LaunchMode), String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut args = arguments.into_iter().map(Into::into);
    let mut mode = LaunchMode::Normal;
    let mut supplied_root = None;
    while let Some(value) = args.next() {
        let requested_mode = if value == "--watchdog-fallback" {
            Some(LaunchMode::WatchdogFallback)
        } else if value == "--register-watchdog-fallback" {
            Some(LaunchMode::RegisterWatchdogFallback)
        } else if value == "--activate-watchdog-fallback" {
            Some(LaunchMode::ActivateWatchdogFallback)
        } else {
            None
        };
        if let Some(requested_mode) = requested_mode {
            if mode != LaunchMode::Normal {
                return Err("only one Watchdog launch mode may be supplied".to_owned());
            }
            mode = requested_mode;
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
            if supplied != *expected {
                return Err(
                    "work root must equal the protected ProgramData notification contour"
                        .to_owned(),
                );
            }
            Ok(supplied)
        },
    )?;
    if mode != LaunchMode::Normal && supplied_root_given {
        // Keep the scheduler mode deterministic: it always resolves the
        // installer-owned contour and does not accept a caller-selected root.
        return Err("watchdog fallback does not accept --work-root".to_owned());
    }
    Ok((root, mode))
}

fn dispatch_deliver(
    composition: &mut NotificationComposition,
    envelope: &NotificationEnvelope,
    request: &NotificationRequest,
) -> Response {
    match composition.deliver(envelope, request) {
        Ok(observation) => Response::Delivered {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            observation: Box::new(observation),
        },
        Err(error) => notify_error(&error),
    }
}

fn dispatch_fallback(
    composition: &mut NotificationComposition,
    envelope: &SignedWatchdogFallbackEnvelope,
    request: &NotificationRequest,
) -> Response {
    match composition.deliver_watchdog_fallback(envelope, request) {
        Ok(observation) => Response::Delivered {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            observation: Box::new(observation),
        },
        Err(error) => notify_error(&error),
    }
}

fn composition_error(detail: String) -> Response {
    Response::Error {
        code: "NOTIFICATION_PROVIDER_REJECTED",
        detail,
    }
}

fn notify_error(error: &NotifyError) -> Response {
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

fn write_response(response: &Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

fn exit(code: i32, error_code: &'static str, detail: String) -> ! {
    let response = Response::Error {
        code: error_code,
        detail,
    };
    let _ = write_response(&response);
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "launch-mode tests use expect for fixed-valid argument fixtures"
    )]

    use super::*;

    #[test]
    fn watchdog_fallback_is_a_no_stdin_protected_launch_mode() {
        let expected = PathBuf::from(r"C:\ProgramData\Eliot\notify");
        let (root, fallback) = parse_launch_args(["--watchdog-fallback"], &expected)
            .expect("watchdog mode parses without a request stream");
        assert_eq!(root, expected);
        assert_eq!(fallback, LaunchMode::WatchdogFallback);
        assert!(
            parse_launch_args(
                [
                    "--watchdog-fallback",
                    "--work-root",
                    r"C:\ProgramData\Eliot\notify"
                ],
                &PathBuf::from(r"C:\ProgramData\Eliot\notify")
            )
            .is_err()
        );
        assert_eq!(
            parse_launch_args(["--register-watchdog-fallback"], &expected)
                .expect("registration mode parses without stdin")
                .1,
            LaunchMode::RegisterWatchdogFallback
        );
        assert_eq!(
            parse_launch_args(["--activate-watchdog-fallback"], &expected)
                .expect("activation mode parses without stdin")
                .1,
            LaunchMode::ActivateWatchdogFallback
        );
        assert!(
            parse_launch_args(
                ["--watchdog-fallback", "--activate-watchdog-fallback"],
                &expected
            )
            .is_err()
        );
        assert!(parse_launch_args(["--unknown"], &PathBuf::from("C:\\notify")).is_err());
    }
}
