use std::io::{self, BufRead, Write};

use eliot_agent_bridge::{BridgeRunner, CliError, Profile, kernel_ports, parse_args};
use eliot_agent_bridge_core::{AttachRequest, BridgeError, HostEventEnvelope};
use eliot_protocol::{EventEnvelope, Frame};
use serde::{Deserialize, Serialize};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const PROVIDER_PORT_EXIT: i32 = 69;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
// This closed line protocol mirrors the existing frame contracts without an
// extra heap representation at the trusted process boundary.
#[allow(clippy::large_enum_variant)]
enum Request {
    Attach { request: AttachRequest },
    ForwardFrame { frame: Frame },
    ForwardHook { event: HostEventEnvelope },
    ForwardEvent { event: EventEnvelope },
    ReconcileExternal {},
    Status,
    Stop,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Status {
        profile: &'static str,
        control_capacity: usize,
        activation_port: &'static str,
        forwarding_port: &'static str,
    },
    Attached,
    Forwarded,
    Reconciled,
    Stopped,
    Error {
        code: &'static str,
        detail: String,
    },
}

// The entrypoint keeps the complete request/identity/response loop in one place
// so every branch shares the same provider-failure exit accounting.
#[allow(clippy::too_many_lines)]
fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            let (code, detail) = match error {
                CliError::MissingProfile => ("MISSING_PROFILE", "--profile is required".to_owned()),
                CliError::UnsupportedProfile(profile) => ("UNSUPPORTED_PROFILE", profile),
                CliError::MalformedArgument(argument) => ("MALFORMED_ARGUMENT", argument),
                CliError::RemoteTransportForbidden(transport) => {
                    ("REMOTE_TRANSPORT_FORBIDDEN", transport)
                }
            };
            emit_error(code, &detail);
            std::process::exit(INVALID_ARGUMENT_EXIT);
        }
    };

    let (host_activation, mcp_forwarding) = match kernel_ports() {
        Ok(ports) => ports,
        Err(error) => {
            let code = if matches!(
                error,
                eliot_agent_bridge::RuntimeBuildError::KernelAdmissionRequired(_)
            ) {
                "KERNEL_ADMISSION_REQUIRED"
            } else {
                "KERNEL_CLIENT_REJECTED"
            };
            emit_error(code, &error.to_string());
            std::process::exit(PROVIDER_PORT_EXIT);
        }
    };
    let mut runner = match BridgeRunner::new(
        config.profile,
        eliot_agent_bridge_core::ProviderReadiness::unprobed(),
        Some(host_activation),
        Some(mcp_forwarding),
    ) {
        Ok(runner) => runner,
        Err(error) => {
            emit_error("BRIDGE_COMPOSITION_REJECTED", &error.to_string());
            std::process::exit(PROVIDER_PORT_EXIT);
        }
    };
    let mut provider_failure = false;
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => match serde_json::from_str::<Request>(&line) {
                Ok(Request::Attach { request }) => match runner.attach(request) {
                    Ok(_) => Response::Attached,
                    Err(error) => {
                        provider_failure |= matches!(error, BridgeError::PlanGap(_));
                        bridge_error(&error)
                    }
                },
                Ok(Request::ForwardFrame { frame }) => match runner.forward_frame(&frame) {
                    Ok(()) => Response::Forwarded,
                    Err(error) => {
                        provider_failure |= is_provider_failure(&error);
                        bridge_error(&error)
                    }
                },
                Ok(Request::ForwardHook { event }) => match runner.forward_hook(&event) {
                    Ok(()) => Response::Forwarded,
                    Err(error) => {
                        provider_failure |= is_provider_failure(&error);
                        bridge_error(&error)
                    }
                },
                Ok(Request::ForwardEvent { event }) => match runner.forward_event(&event) {
                    Ok(_) => Response::Forwarded,
                    Err(error) => {
                        provider_failure |= is_provider_failure(&error);
                        bridge_error(&error)
                    }
                },
                Ok(Request::ReconcileExternal {}) => match runner.reconcile_external() {
                    Ok(_) => Response::Reconciled,
                    Err(error) => {
                        provider_failure |= is_provider_failure(&error);
                        bridge_error(&error)
                    }
                },
                Ok(Request::Status) => Response::Status {
                    profile: Profile::as_str(config.profile),
                    control_capacity: runner.control_capacity(),
                    activation_port: "observed after Kernel admission",
                    forwarding_port: "observed after Kernel admission",
                },
                Ok(Request::Stop) => Response::Stopped,
                Err(error) => Response::Error {
                    code: "REQUEST_INVALID",
                    detail: error.to_string(),
                },
            },
            Err(error) => Response::Error {
                code: "INPUT_FAILURE",
                detail: error.to_string(),
            },
        };
        let stop = matches!(response, Response::Stopped);
        if !write_response(&response) || stop {
            break;
        }
    }
    if provider_failure {
        std::process::exit(PROVIDER_PORT_EXIT);
    }
}

fn bridge_error(error: &BridgeError) -> Response {
    if matches!(error, BridgeError::PlanGap(_)) {
        Response::Error {
            code: "KERNEL_ACTIVATION_PORT_REJECTED",
            detail: "Kernel-owned HostActivationPort rejected or fenced the request".to_owned(),
        }
    } else {
        Response::Error {
            code: "BRIDGE_REQUEST_REJECTED",
            detail: error.to_string(),
        }
    }
}

fn is_provider_failure(error: &BridgeError) -> bool {
    matches!(error, BridgeError::PlanGap(_) | BridgeError::Provider(_))
}

fn emit_error(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":{code:?},\"detail\":{detail:?}}}");
}

fn write_response(response: &Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
