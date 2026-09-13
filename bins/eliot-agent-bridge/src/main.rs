#![forbid(unsafe_code)]

use eliot_agent_bridge::{
    BridgeRunner, CliError, Profile, kernel_ports_with_declaration, parse_args,
};
use eliot_agent_bridge_core::{AttachRequest, BridgeError, HostEventEnvelope};
#[cfg(test)]
use eliot_mcp::{HostCancellationPortOutcome, HostInvocationPortOutcome, PortFailure};
use eliot_mcp::{
    HostCancellationRequest, HostCancellationResult, HostCorrelationReceipt, HostGatewayError,
    HostInvocationRequest, HostInvocationResult, HostRequestGateway, KernelHostRequestPort,
};
use eliot_protocol::EventEnvelope;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const PROVIDER_PORT_EXIT: i32 = 69;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
enum Request {
    Attach { request: AttachRequest },
    Invoke { request: HostInvocationRequest },
    Cancel { request: HostCancellationRequest },
    ForwardHook { event: HostEventEnvelope },
    ForwardEvent { event: EventEnvelope },
    ReconcileExternal {},
    Status,
    Stop,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Status {
        profile: &'static str,
        control_capacity: usize,
        activation_port: &'static str,
        host_request_port: &'static str,
        observation_forwarding_port: &'static str,
    },
    Attached,
    Invocation {
        result: HostInvocationResult,
        completion: HostCorrelationReceipt,
    },
    Cancellation {
        result: HostCancellationResult,
    },
    Forwarded,
    Reconciled,
    Stopped,
    Error {
        code: &'static str,
        detail: String,
    },
}

/// Fail-closed placeholder retained for unit tests only.
///
/// Production wiring uses the shared-transport `KernelHostRequestClient`
/// built beside the activation port; this type keeps the gateway correlation
/// proofs compiling without a live Kernel.
#[cfg(test)]
#[derive(Debug, Default)]
struct UnavailableKernelHostRequestPort;

#[cfg(test)]
impl KernelHostRequestPort for UnavailableKernelHostRequestPort {
    fn invoke(
        &mut self,
        _request: &HostInvocationRequest,
    ) -> Result<HostInvocationPortOutcome, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
            reason: "Kernel host-request identity binding and dispatch are not admitted".to_owned(),
        })
    }

    fn cancel(
        &mut self,
        _request: &HostCancellationRequest,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: "kernel.host-request.cancel".to_owned(),
            reason: "Kernel host-request cancellation binding is not admitted".to_owned(),
        })
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            let (code, detail) = match error {
                CliError::MissingProfile => ("MISSING_PROFILE", "--profile is required".to_owned()),
                CliError::MissingClientDeclaration => (
                    "MISSING_CLIENT_DECLARATION",
                    "--client-declaration is required".to_owned(),
                ),
                CliError::UnsupportedProfile(profile) => ("UNSUPPORTED_PROFILE", profile),
                CliError::MalformedArgument(argument) => ("MALFORMED_ARGUMENT", argument),
                CliError::RemoteTransportForbidden(transport) => {
                    ("REMOTE_TRANSPORT_FORBIDDEN", transport)
                }
                CliError::InvalidClientDeclarationPath(path) => {
                    ("INVALID_CLIENT_DECLARATION_PATH", path)
                }
            };
            emit_error(code, &detail);
            std::process::exit(INVALID_ARGUMENT_EXIT);
        }
    };
    let (host_activation, mut host_request_port, mcp_forwarding) =
        match kernel_ports_with_declaration(&config.client_declaration) {
            Ok(ports) => ports,
            Err(error) => {
                emit_error("KERNEL_CLIENT_REJECTED", &error.to_string());
                std::process::exit(PROVIDER_PORT_EXIT);
            }
        };
    let mut runner = match BridgeRunner::new(
        config.profile,
        eliot_agent_bridge_core::ProviderReadiness::all_admitted(),
        Some(host_activation),
        Some(mcp_forwarding),
    ) {
        Ok(runner) => runner,
        Err(error) => {
            emit_error("BRIDGE_COMPOSITION_REJECTED", &error.to_string());
            std::process::exit(PROVIDER_PORT_EXIT);
        }
    };
    let host_gateway = HostRequestGateway;
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
                Ok(Request::Invoke { request }) => {
                    handle_invocation(&host_gateway, &mut *host_request_port, &request)
                }
                Ok(Request::Cancel { request }) => {
                    handle_cancellation(&host_gateway, &mut *host_request_port, &request)
                }
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
                    host_request_port: "typed ingress active; shared transport live after Kernel activation",
                    observation_forwarding_port: "unavailable: Kernel observation route not admitted",
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
        let receipt = write_response(&response);
        // A zero-byte emission proves nothing reached the host, so the loop
        // must not continue as if the correlation had been delivered.
        if receipt.bytes_written() == 0 || receipt.should_break() || stop {
            break;
        }
    }
    if provider_failure {
        std::process::exit(PROVIDER_PORT_EXIT);
    }
}

fn handle_invocation<P: KernelHostRequestPort + ?Sized>(
    gateway: &HostRequestGateway,
    port: &mut P,
    request: &HostInvocationRequest,
) -> Response {
    match gateway.invoke_with_receipt(port, request) {
        Ok((result, completion)) => Response::Invocation {
            result,
            completion,
        },
        Err(error) => host_gateway_error(&error),
    }
}

fn handle_cancellation<P: KernelHostRequestPort + ?Sized>(
    gateway: &HostRequestGateway,
    port: &mut P,
    request: &HostCancellationRequest,
) -> Response {
    match gateway.cancel(port, request) {
        Ok(result) => Response::Cancellation { result },
        Err(error) => host_gateway_error(&error),
    }
}

fn host_gateway_error(error: &HostGatewayError) -> Response {
    let code = match error {
        HostGatewayError::HostContract(_) => "HOST_REQUEST_INVALID",
        HostGatewayError::InvalidPortResult { .. }
        | HostGatewayError::ResponseSerialization(_)
        | HostGatewayError::ResponseTooLarge { .. } => "KERNEL_HOST_RESULT_INVALID",
    };
    Response::Error {
        code,
        detail: error.to_string(),
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

/// Immutable disposition of one stdio response emission.
///
/// Populated at the exact write/flush stage with the real framed byte count
/// and the real flush outcome. `bytes` counts only fully placed frames; a
/// failed emission carries zero bytes even if the transport accepted a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StdioWriteReceipt {
    /// Exact bytes placed on stdout, including the framing newline.
    bytes: usize,
    /// Whether the stream flush succeeded after the bytes were written.
    flushed: bool,
    /// Terminal cause of this emission; decides loop continuation.
    cause: StdioBreakCause,
}

/// Terminal cause of one stdio response emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StdioBreakCause {
    /// Bytes were written and flushed; continue unless the peer asked to stop.
    Emitted,
    /// Response serialization failed; nothing was written.
    SerializeFailed,
    /// Framed bytes were not fully written.
    WriteFailed,
    /// Bytes were written but the flush failed, so host delivery is unconfirmed.
    FlushFailed,
}

impl StdioWriteReceipt {
    /// Exact bytes placed on stdout for this emission.
    const fn bytes_written(&self) -> usize {
        self.bytes
    }

    /// Whether the main loop must break after this emission.
    const fn should_break(&self) -> bool {
        !self.flushed || !matches!(self.cause, StdioBreakCause::Emitted)
    }
}

fn write_response(response: &Response) -> StdioWriteReceipt {
    let Ok(mut framed) = serde_json::to_vec(response) else {
        return StdioWriteReceipt {
            bytes: 0,
            flushed: false,
            cause: StdioBreakCause::SerializeFailed,
        };
    };
    framed.push(b'\n');
    let bytes = framed.len();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if output.write_all(&framed).is_err() {
        return StdioWriteReceipt {
            bytes: 0,
            flushed: false,
            cause: StdioBreakCause::WriteFailed,
        };
    }
    if output.flush().is_err() {
        return StdioWriteReceipt {
            bytes,
            flushed: false,
            cause: StdioBreakCause::FlushFailed,
        };
    }
    StdioWriteReceipt {
        bytes,
        flushed: true,
        cause: StdioBreakCause::Emitted,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::Value;

    const INVOKE: &str = r#"{
        "op":"invoke",
        "request":{
            "protocol_version":"2026-07-28",
            "correlation_id":"host-request-1",
            "client_capabilities":{"tasks":false},
            "tool":{"name":"eliot.state","arguments":{"include":["task"]}},
            "deadline_preference_ms":5000,
            "observed_context":{
                "host_session_hint":"host-turn-1",
                "observed_resource_refs":[],
                "event_cursors":[],
                "trace_context":{}
            }
        }
    }"#;

    const CANCEL: &str = r#"{
        "op":"cancel",
        "request":{
            "protocol_version":"2026-07-28",
            "correlation_id":"host-cancel-1",
            "operation_handle":"kernel-operation-1",
            "reason":null,
            "deadline_preference_ms":2000,
            "observed_context":{
                "host_session_hint":null,
                "observed_resource_refs":[],
                "event_cursors":[],
                "trace_context":{}
            }
        }
    }"#;

    #[test]
    fn raw_forward_frame_is_not_a_public_operation() {
        let error = serde_json::from_str::<Request>(r#"{"op":"forward_frame","frame":{}}"#)
            .expect_err("raw canonical Frame ingress must be absent");
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn typed_invoke_and_cancel_deserialize() {
        assert!(matches!(
            serde_json::from_str::<Request>(INVOKE).expect("invoke must deserialize"),
            Request::Invoke { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(CANCEL).expect("cancel must deserialize"),
            Request::Cancel { .. }
        ));
    }

    #[test]
    fn forged_kernel_identity_field_is_rejected() {
        let forged = INVOKE.replace(
            "\"client_capabilities\":{\"tasks\":false},",
            "\"client_capabilities\":{\"tasks\":false},\"identity\":{},",
        );
        let error = serde_json::from_str::<Request>(&forged)
            .expect_err("host must not supply Kernel RequestIdentity");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn unavailable_kernel_binding_returns_correlated_typed_rejection() {
        let Request::Invoke { request } =
            serde_json::from_str::<Request>(INVOKE).expect("invoke must deserialize")
        else {
            panic!("expected invoke");
        };
        let mut port = UnavailableKernelHostRequestPort;
        let response = handle_invocation(&HostRequestGateway, &mut port, &request);
        let value = serde_json::to_value(response).expect("response must serialize");
        assert_eq!(value["status"], Value::String("invocation".to_owned()));
        assert_eq!(
            value["result"]["correlation_id"],
            Value::String("host-request-1".to_owned())
        );
        assert_eq!(
            value["result"]["outcome"]["disposition"],
            Value::String("REJECTED".to_owned())
        );
        assert_eq!(
            value["result"]["outcome"]["failure"]["missing_capability"],
            Value::String("kernel.host-request.bind-dispatch".to_owned())
        );
    }

    #[test]
    fn cancellation_needs_no_prose_and_preserves_exact_target() {
        let Request::Cancel { request } =
            serde_json::from_str::<Request>(CANCEL).expect("cancel must deserialize")
        else {
            panic!("expected cancel");
        };
        assert!(request.reason.is_none());
        let mut port = UnavailableKernelHostRequestPort;
        let response = handle_cancellation(&HostRequestGateway, &mut port, &request);
        let value = serde_json::to_value(response).expect("response must serialize");
        assert_eq!(value["status"], Value::String("cancellation".to_owned()));
        assert_eq!(
            value["result"]["correlation_id"],
            Value::String("host-cancel-1".to_owned())
        );
        assert_eq!(
            value["result"]["operation_handle"],
            Value::String("kernel-operation-1".to_owned())
        );
        assert_eq!(
            value["result"]["outcome"]["disposition"],
            Value::String("REJECTED".to_owned())
        );
    }
}
