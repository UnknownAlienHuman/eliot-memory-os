#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_notify::{
    DeliveryOutcome, NotificationComposition, PROTOCOL_VERSION, SERVICE_NAME, UnsatisfiedObligation,
};
use eliot_notify_core::{
    NotificationEnvelope, NotificationStateReadRequest, NotifyError,
    SignedWatchdogFallbackEnvelope, UserAutomationFailureRequest, UserAutomationInvocation,
    UserAutomationPreflightDecision,
};
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
    DeliverUserAutomationFailure {
        failure: UserAutomationFailureRequest,
        request: NotificationRequest,
    },
    RunUserAutomation {
        invocation: UserAutomationInvocation,
        request: NotificationRequest,
    },
    ReadInbox {
        parent: NotificationRequest,
        read: NotificationStateReadRequest,
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
    /// Delivery lost its observed OS acceptance. I11.6:19: this degrades
    /// delivery only — the payload carries the persisted Event Log / spool
    /// obligation and the canonical obligation read back from its owner, and
    /// `claimed_toast` is always false. Nothing here is a resolution.
    Degraded {
        service: &'static str,
        protocol: &'static str,
        code: &'static str,
        detail: String,
        obligation: Box<UnsatisfiedObligation>,
    },
    PreflightAdmitted {
        service: &'static str,
        protocol: &'static str,
        receipt: Box<eliot_notify_core::UserAutomationPreflightReceipt>,
    },
    PreflightDeferred {
        service: &'static str,
        protocol: &'static str,
        receipt: Box<eliot_notify_core::UserAutomationPreflightReceipt>,
        reason: eliot_notify_core::UserAutomationDeferReason,
    },
    PreflightBlocked {
        service: &'static str,
        protocol: &'static str,
        receipt: Box<eliot_notify_core::UserAutomationPreflightReceipt>,
        observation: Box<eliot_notify_core::DeliveryObservation>,
    },
    Inbox {
        service: &'static str,
        protocol: &'static str,
        read: Box<eliot_notify_core::NotificationStateReadResponse>,
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
        let provider_error = is_provider_rejection(&response);
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
            match NotificationComposition::from_kernel_with_quiet_hours(root, &request) {
                Ok(mut composition) => dispatch_deliver(&mut composition, &envelope, &request),
                Err(error) => composition_error(error.to_string()),
            }
        }
        Ok(Request::DeliverUserAutomationFailure { failure, request }) => {
            match NotificationComposition::from_kernel_with_quiet_hours(root, &request) {
                Ok(mut composition) => {
                    dispatch_user_automation_failure(&mut composition, failure, &request)
                }
                Err(error) => composition_error(error.to_string()),
            }
        }
        Ok(Request::RunUserAutomation {
            invocation,
            request,
        }) => {
            match NotificationComposition::from_kernel_with_user_automation(
                root,
                &request,
                &invocation,
            ) {
                Ok((mut composition, projection)) => {
                    dispatch_user_automation(&mut composition, invocation, projection, &request)
                }
                Err(error) => composition_error(error.to_string()),
            }
        }
        Ok(Request::ReadInbox { parent, read }) => {
            match NotificationComposition::from_kernel_with_quiet_hours(root, &parent) {
                Ok(mut composition) => dispatch_read_inbox(&mut composition, &parent, &read),
                Err(error) => composition_error(error.to_string()),
            }
        }
        Err(error) => Response::Error {
            code: "REQUEST_INVALID",
            detail: error.to_string(),
        },
    };
    let provider_error = is_provider_rejection(&response);
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
    degraded_response(composition.deliver_with_obligation(envelope, request))
}

fn dispatch_user_automation_failure(
    composition: &mut NotificationComposition,
    failure: UserAutomationFailureRequest,
    request: &NotificationRequest,
) -> Response {
    degraded_response(composition.deliver_user_automation_failure_with_obligation(failure, request))
}

fn dispatch_user_automation(
    composition: &mut NotificationComposition,
    invocation: UserAutomationInvocation,
    projection: eliot_notify_core::UserAutomationPreflightProjection,
    request: &NotificationRequest,
) -> Response {
    let decision =
        match eliot_notify_core::preflight_user_automation(&projection, &invocation, request) {
            Ok(decision) => decision,
            Err(error) => return preflight_error(error.to_string()),
        };
    match decision {
        UserAutomationPreflightDecision::Admitted { receipt } => Response::PreflightAdmitted {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            receipt: Box::new(receipt),
        },
        UserAutomationPreflightDecision::Deferred { receipt, reason } => {
            Response::PreflightDeferred {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                receipt: Box::new(receipt),
                reason,
            }
        }
        UserAutomationPreflightDecision::BlockedConfig { receipt, failure } => {
            match composition.deliver_user_automation_failure(failure, request) {
                Ok(observation) => Response::PreflightBlocked {
                    service: SERVICE_NAME,
                    protocol: PROTOCOL_VERSION,
                    receipt: Box::new(receipt),
                    observation: Box::new(observation),
                },
                Err(error) => notify_error(&error),
            }
        }
    }
}

/// Queries the authenticated canonical notification inbox through the same
/// Kernel exchange used by delivery. The response carries the owner records
/// plus inbox metrics (unresolved / critical / failed-delivery /
/// acknowledged counts); board projection of ack/critical/failure semantics
/// is preserved end to end because the records travel unchanged.
fn dispatch_read_inbox(
    composition: &mut NotificationComposition,
    parent: &NotificationRequest,
    read: &NotificationStateReadRequest,
) -> Response {
    match composition.read_notification_state(parent, read) {
        Ok(response) => Response::Inbox {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            read: Box::new(response),
        },
        Err(error) => notify_error(&error),
    }
}

fn dispatch_fallback(
    composition: &mut NotificationComposition,
    envelope: &SignedWatchdogFallbackEnvelope,
    request: &NotificationRequest,
) -> Response {
    degraded_response(composition.deliver_watchdog_fallback_with_obligation(envelope, request))
}

/// Projects one delivery outcome plus its durable obligation onto the wire.
///
/// `Some(obligation)` means the adapter returned no observed OS acceptance; the
/// response then reports a delivery degradation carrying the persisted Event
/// Log / spool record and the canonical obligation read back from its owner,
/// never a resolution and never a claimed toast. The composition already
/// persisted that obligation before handing the pair over, so this projection
/// only decides what the caller is told.
fn degraded_response(outcome: DeliveryOutcome) -> Response {
    let DeliveryOutcome {
        delivery,
        obligation,
    } = outcome;
    let Some(obligation) = obligation else {
        return match delivery {
            Ok(observation) => Response::Delivered {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                observation: Box::new(observation),
            },
            Err(error) => notify_error(&error),
        };
    };
    let (code, detail) = match delivery {
        Ok(observation) => {
            let confidence = &observation.confidence;
            let delivered = &observation.delivered;
            (
                NOTIFICATION_DELIVERY_DEGRADED,
                format!("delivery confidence {confidence:?}, delivered {delivered:?}"),
            )
        }
        Err(error) => (notify_error_code(&error), error.to_string()),
    };
    Response::Degraded {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        code,
        detail,
        obligation: Box::new(obligation),
    }
}

/// Stable code for one delivery that lost its observed OS acceptance while an
/// obligation was still outstanding. It is a degradation, never a resolution.
const NOTIFICATION_DELIVERY_DEGRADED: &str = "NOTIFICATION_DELIVERY_DEGRADED";

/// Reports whether one response must exit with the provider-rejection code.
///
/// Both a plain rejection and a degradation carry the same code when the
/// underlying cause was a plan gap, so recording a delivery obligation never
/// changes the process's exit semantics for its caller.
fn is_provider_rejection(response: &Response) -> bool {
    match response {
        Response::Error { code, .. } | Response::Degraded { code, .. } => {
            *code == "NOTIFICATION_PROVIDER_REJECTED"
        }
        _ => false,
    }
}

fn composition_error(detail: String) -> Response {
    Response::Error {
        code: "NOTIFICATION_PROVIDER_REJECTED",
        detail,
    }
}

fn preflight_error(detail: String) -> Response {
    Response::Error {
        code: "NOTIFICATION_REQUEST_REJECTED",
        detail,
    }
}

fn notify_error(error: &NotifyError) -> Response {
    Response::Error {
        code: notify_error_code(error),
        detail: error.to_string(),
    }
}

/// Classifies one core failure onto its stable wire code. A plan gap is a
/// provider rejection (non-zero exit); every other core failure is a rejected
/// request. The same classification is reused by the degradation projection so
/// an adapter loss never changes the process's exit semantics.
fn notify_error_code(error: &NotifyError) -> &'static str {
    if matches!(error, NotifyError::PlanGap { .. }) {
        "NOTIFICATION_PROVIDER_REJECTED"
    } else {
        "NOTIFICATION_REQUEST_REJECTED"
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

    #[test]
    fn read_inbox_response_preserves_ack_critical_and_failure_for_the_board() {
        let read: eliot_notify_core::NotificationStateReadResponse =
            serde_json::from_value(serde_json::json!({
                "records": [{
                    "notification_id": "notification-1",
                    "severity": "CRITICAL",
                    "subject": "subject",
                    "summary": "summary",
                    "evidence_handles": ["evidence-1"],
                    "affected_scope": "scope-1",
                    "owner": "owner-1",
                    "required_action": "review",
                    "deadline_or_review": null,
                    "dedup_key": "backup-failed",
                    "delivery_channels": ["CONTROL_BOARD"],
                    "occurrences": 2,
                    "delivery": {"kind": "FAILED", "reason": "toast provider failed"},
                    "acknowledgement": {"principal": "operator-1", "sequence": 1},
                    "resolution_ref": null,
                    "state_fence": {
                        "authority_epoch": {
                            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                            "sequence": 1
                        },
                        "resource_generation": 1,
                        "task_revision": 1,
                        "policy_revision": 1,
                        "integration_revision": 1
                    },
                    "revision": 2
                }],
                "metrics": {
                    "unresolved_total": 1,
                    "critical_unresolved": 1,
                    "action_required_unresolved": 0,
                    "failed_delivery_unresolved": 1,
                    "acknowledged_unresolved": 1,
                    "resolved_total": 0
                },
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 1
                    },
                    "resource_generation": 1,
                    "task_revision": 1,
                    "policy_revision": 1,
                    "integration_revision": 1
                },
                "revision": 2
            }))
            .expect("inbox read response decodes");
        let response = Response::Inbox {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            read: Box::new(read),
        };
        let rendered = serde_json::to_value(&response).expect("inbox renders");
        assert_eq!(rendered["status"], "inbox");
        assert_eq!(rendered["read"]["records"][0]["dedup_key"], "backup-failed");
        assert_eq!(
            rendered["read"]["records"][0]["acknowledgement"]["principal"],
            "operator-1"
        );
        assert_eq!(
            rendered["read"]["records"][0]["delivery"]["reason"],
            "toast provider failed"
        );
        assert_eq!(rendered["read"]["metrics"]["critical_unresolved"], 1);
        assert_eq!(rendered["read"]["metrics"]["failed_delivery_unresolved"], 1);
        assert_eq!(rendered["read"]["metrics"]["acknowledged_unresolved"], 1);
    }
}
