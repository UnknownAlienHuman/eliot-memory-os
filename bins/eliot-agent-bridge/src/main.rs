#![forbid(unsafe_code)]

mod request_input;

use eliot_agent_bridge::{
    BridgeRunner, CliError, Profile, kernel_ports_with_declaration, parse_args,
};
use eliot_agent_bridge_core::{
    AttachRequest, BridgeError, ConnectionId, FencingToken, Generation, HostEventEnvelope,
    ReconnectRequest, SessionId,
};
use eliot_contracts::EpochId;
#[cfg(test)]
use eliot_mcp::{HostCancellationPortOutcome, HostInvocationPortOutcome, PortFailure};
use eliot_mcp::{
    HostCancellationRequest, HostCancellationResult, HostCorrelationReceipt, HostGatewayError,
    HostInvocationRequest, HostInvocationResult, HostRequestGateway, KernelHostRequestPort,
};
use eliot_protocol::EventEnvelope;
use request_input::{
    REQUEST_INPUT_PROFILE, REQUEST_INPUT_PROFILE_ID, ReadOutcome, read_bounded_record,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const PROVIDER_PORT_EXIT: i32 = 69;

/// Closed kernel entry that rehydrates one exact operation from the durable record.
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs`
/// (`AGENT_HOST_REQUEST_REHYDRATE_OPERATION`); the literal is repeated here
/// for typed recovery routing only because that constant is `pub(crate)` to
/// the kernel binary. This process never sends it: rehydrate consumes the
/// exact (envelope, admission-receipt) pair, and a transport replacement keeps
/// neither alive across the old connection — a replacement connection requires
/// a new admission, and cached state cannot revive the prior one.
const AGENT_HOST_REQUEST_REHYDRATE_OPERATION: &str = "agent_host_request_rehydrate";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
enum Request {
    Attach {
        request: AttachRequest,
    },
    Invoke {
        request: HostInvocationRequest,
    },
    Cancel {
        request: HostCancellationRequest,
    },
    ForwardHook {
        event: HostEventEnvelope,
    },
    ForwardEvent {
        event: EventEnvelope,
    },
    ReconcileExternal {},
    Reconnect {
        expected_connection_id: ConnectionId,
        new_connection_id: ConnectionId,
        session_id: String,
        activation_generation: u64,
        authority_epoch: EpochId,
        fence_nonce: String,
    },
    Status,
    Stop,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Status {
        profile: &'static str,
        control_capacity: usize,
        attached: bool,
        connection_id: Option<String>,
        session_id: Option<String>,
        activation_generation: Option<u64>,
        authority_epoch: Option<EpochId>,
        reconciliation_required: bool,
        activation_port: &'static str,
        host_request_port: &'static str,
        observation_forwarding_port: &'static str,
        recovery: &'static str,
    },
    Attached,
    Reconnected {
        previous_connection_id: String,
        connection_id: String,
        session_id: String,
        activation_generation: u64,
        authority_epoch: EpochId,
    },
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
    if REQUEST_INPUT_PROFILE.validate().is_err() {
        let detail =
            format!("request input profile {REQUEST_INPUT_PROFILE_ID} is internally inconsistent");
        emit_error("BRIDGE_COMPOSITION_REJECTED", &detail);
        std::process::exit(PROVIDER_PORT_EXIT);
    }
    let mut stdin_lock = io::stdin().lock();
    // Total non-blank bounded records observed (dispatched or malformed) and
    // the current run of consecutive acquisition/deserialization failures.
    // Both counters use checked arithmetic so neither can wrap into a bypass.
    let mut total_records: u64 = 0;
    let mut consecutive_invalid: u32 = 0;
    loop {
        let outcome = match read_bounded_record(&mut stdin_lock, REQUEST_INPUT_PROFILE) {
            Ok(outcome) => outcome,
            Err(error) => {
                let Some(next_invalid) = consecutive_invalid.checked_add(1) else {
                    break;
                };
                consecutive_invalid = next_invalid;
                let rejection = Response::Error {
                    code: "INPUT_FAILURE",
                    detail: error.to_string(),
                };
                if emit_bounded_rejection(&rejection) {
                    break;
                }
                if consecutive_invalid >= REQUEST_INPUT_PROFILE.max_consecutive_invalid_records {
                    break;
                }
                continue;
            }
        };
        // Framing failures are rejected here without reaching any handler,
        // gateway, port, or runner call below: each arm only shapes one
        // redacted rejection and then continues or breaks fail-closed.
        let record_bytes = match outcome {
            ReadOutcome::Eof => break,
            ReadOutcome::Oversize {
                discarded_bytes,
                found_terminator,
            } => {
                let Some(next_invalid) = consecutive_invalid.checked_add(1) else {
                    break;
                };
                consecutive_invalid = next_invalid;
                let rejection = Response::Error {
                    code: "REQUEST_INVALID",
                    detail: format!(
                        "record exceeds {} encoded bytes ({REQUEST_INPUT_PROFILE_ID}); discarded {discarded_bytes} bytes",
                        REQUEST_INPUT_PROFILE.max_record_bytes
                    ),
                };
                if emit_bounded_rejection(&rejection) {
                    break;
                }
                if !found_terminator {
                    break;
                }
                if consecutive_invalid >= REQUEST_INPUT_PROFILE.max_consecutive_invalid_records {
                    break;
                }
                continue;
            }
            ReadOutcome::InvalidUtf8 => {
                let Some(next_invalid) = consecutive_invalid.checked_add(1) else {
                    break;
                };
                consecutive_invalid = next_invalid;
                let rejection = Response::Error {
                    code: "REQUEST_INVALID",
                    detail: format!("record is not valid UTF-8 ({REQUEST_INPUT_PROFILE_ID})"),
                };
                if emit_bounded_rejection(&rejection) {
                    break;
                }
                if consecutive_invalid >= REQUEST_INPUT_PROFILE.max_consecutive_invalid_records {
                    break;
                }
                continue;
            }
            ReadOutcome::Record(bytes) => bytes,
        };
        // The bounded reader only yields `Record` for valid UTF-8, so the
        // rejection below is a defensive second gate that still never
        // dispatches.
        let Ok(text) = std::str::from_utf8(&record_bytes) else {
            let Some(next_invalid) = consecutive_invalid.checked_add(1) else {
                break;
            };
            consecutive_invalid = next_invalid;
            let rejection = Response::Error {
                code: "REQUEST_INVALID",
                detail: format!("record is not valid UTF-8 ({REQUEST_INPUT_PROFILE_ID})"),
            };
            if emit_bounded_rejection(&rejection) {
                break;
            }
            if consecutive_invalid >= REQUEST_INPUT_PROFILE.max_consecutive_invalid_records {
                break;
            }
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        if total_records >= REQUEST_INPUT_PROFILE.max_requests_per_process {
            break;
        }
        let Some(next_total) = total_records.checked_add(1) else {
            break;
        };
        total_records = next_total;
        let response = match serde_json::from_str::<Request>(text) {
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
            Ok(Request::Reconnect {
                expected_connection_id,
                new_connection_id,
                session_id,
                activation_generation,
                authority_epoch,
                fence_nonce,
            }) => handle_reconnect(
                &mut runner,
                &expected_connection_id,
                &new_connection_id,
                &session_id,
                activation_generation,
                authority_epoch,
                &fence_nonce,
            ),
            Ok(Request::Status) => status_response(config.profile, &runner),
            Ok(Request::Stop) => Response::Stopped,
            Err(error) => Response::Error {
                code: "REQUEST_INVALID",
                detail: error.to_string(),
            },
        };
        // Only the deserialization-failure arm above produces REQUEST_INVALID:
        // every handler, gateway, and runner error path uses a distinct code,
        // so this flag exactly tracks whether a request was dispatched. Valid
        // dispatches reset the consecutive-invalid run; malformed records
        // extend it without ever having reached a handler.
        let dispatched = !matches!(
            &response,
            Response::Error {
                code: "REQUEST_INVALID",
                ..
            }
        );
        if dispatched {
            consecutive_invalid = 0;
        } else {
            let Some(next_invalid) = consecutive_invalid.checked_add(1) else {
                break;
            };
            consecutive_invalid = next_invalid;
        }
        let stop = matches!(response, Response::Stopped);
        let receipt = write_response(&response);
        // A zero-byte emission proves nothing reached the host, so the loop
        // must not continue as if the correlation had been delivered.
        if receipt.bytes_written() == 0 || receipt.should_break() || stop {
            break;
        }
        if !dispatched
            && consecutive_invalid >= REQUEST_INPUT_PROFILE.max_consecutive_invalid_records
        {
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
        Ok((result, completion)) => Response::Invocation { result, completion },
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

/// Validates one closed reconnect claim and advances the host-facing transport binding.
///
/// This follows the [`HostRequestGateway`] pattern without adding gateway
/// surface: inert claims are shaped into typed authority facts *before* the
/// runner is touched (validate before dispatch), and the response preserves
/// the caller's connection correlation alongside the owner-derived binding.
/// Host text is never trusted: `session_id`, `activation_generation`,
/// `authority_epoch`, and `fence_nonce` are bearer claims compared by
/// `Runner::reconnect` against the live activation binding, and any mismatch
/// fails closed with typed recovery. The session, generation, and fence stay
/// kernel-issued — sealed at activation from the admission receipt established
/// by `kernel_ports_with_declaration` (declaration lease, front-door
/// expectation/SID, challenge → hello → receipt, fence joins) — and are never
/// minted, widened, or inferred from process identity here. Cursors and replay
/// inheritance survive only through that exact owner-authorized match; the
/// kernel transport itself is untouched, so kernel envelopes keep riding the
/// admitted receipt connection until a new process admission replaces it (the
/// activation one-shot guard is preserved: this path never reactivates).
fn handle_reconnect(
    runner: &mut BridgeRunner,
    expected_connection_id: &ConnectionId,
    new_connection_id: &ConnectionId,
    session_id: &str,
    activation_generation: u64,
    authority_epoch: EpochId,
    fence_nonce: &str,
) -> Response {
    let Some(live) = runner.attach_view() else {
        return Response::Error {
            code: "BRIDGE_NOT_ATTACHED",
            detail: "bridge is not attached; attach and activate before reconnect — reconnect preserves only the owner-authorized session, generation, and fence of a live attach".to_owned(),
        };
    };
    if expected_connection_id.as_str() != live.binding().connection_id().as_str() {
        return Response::Error {
            code: "RECONNECT_STALE_CONNECTION",
            detail: format!(
                "reconnect presents stale connection `{}`; the live connection is `{}` — re-read status for the live facts and retry; wrong/stale targets fail closed",
                expected_connection_id.as_str(),
                live.binding().connection_id().as_str(),
            ),
        };
    }
    if new_connection_id.as_str() == live.binding().connection_id().as_str() {
        return Response::Error {
            code: "RECONNECT_INVALID",
            detail: "reconnect requires a new connection identity distinct from the live connection; resending the live connection performs no replacement".to_owned(),
        };
    }
    let Ok(session) = SessionId::new(session_id) else {
        return Response::Error {
            code: "RECONNECT_INVALID",
            detail: "reconnect session_id is not a valid opaque identity; present the exact live session from status".to_owned(),
        };
    };
    let Ok(generation) = Generation::new(activation_generation) else {
        return Response::Error {
            code: "RECONNECT_INVALID",
            detail: "reconnect activation_generation must be non-zero; present the exact live generation from status".to_owned(),
        };
    };
    let Ok(fence) = FencingToken::new(authority_epoch, generation, fence_nonce) else {
        return Response::Error {
            code: "RECONNECT_INVALID",
            detail: "reconnect authority_epoch must be non-zero and fence_nonce must be a non-blank opaque value; present the exact live fence from status".to_owned(),
        };
    };
    let replacement = new_connection_id.clone();
    let request = match ReconnectRequest::new(session, generation, fence, replacement) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                code: "RECONNECT_INVALID",
                detail: format!(
                    "reconnect authority triple is malformed: {error}; present the exact live session, generation, epoch, and fence nonce from status"
                ),
            };
        }
    };
    match runner.reconnect(request) {
        Ok(view) => Response::Reconnected {
            previous_connection_id: expected_connection_id.as_str().to_owned(),
            connection_id: view.binding().connection_id().as_str().to_owned(),
            session_id: view.binding().session_id().as_str().to_owned(),
            activation_generation: view.binding().activation_generation().get(),
            authority_epoch: view.binding().state_fence().authority_epoch().clone(),
        },
        Err(BridgeError::StaleAuthority) => Response::Error {
            code: "RECONNECT_STALE_AUTHORITY",
            detail: format!(
                "reconnect session, generation, or fence does not match the live attach; re-attach and activate for a new admission. A replacement connection requires a new admission and cached state cannot revive the prior connection; the kernel-owned `{AGENT_HOST_REQUEST_REHYDRATE_OPERATION}` entry serves only the exact (envelope, admission-receipt) pair"
            ),
        },
        Err(BridgeError::NotAttached) => Response::Error {
            code: "BRIDGE_NOT_ATTACHED",
            detail: "bridge attach lapsed during reconnect; attach and activate before retrying"
                .to_owned(),
        },
        Err(error) => bridge_error(&error),
    }
}

/// Projects owner-derived bridge liveness without probing the Kernel.
///
/// Every fact comes from the composition or activation owners: the profile
/// from CLI decoding, capacity from the runtime, and attach/session/fence
/// facts from the activation-sealed binding (the kernel-issued
/// `activated_session` captured by the one-shot activation exchange).
/// Pre-activation reports `not-attached` with no liveness text; post-activation
/// reports the admitted-session facts but never a probe-backed readiness claim —
/// dispatch still traverses the live admitted transport per operation, and
/// staleness surfaces as typed `RECONNECT_*` failures pointing back at this
/// status and the reconnect operation.
fn status_response(profile: Profile, runner: &BridgeRunner) -> Response {
    match runner.attach_view() {
        None => Response::Status {
            profile: Profile::as_str(profile),
            control_capacity: runner.control_capacity(),
            attached: false,
            connection_id: None,
            session_id: None,
            activation_generation: None,
            authority_epoch: None,
            reconciliation_required: false,
            activation_port: "not-attached",
            host_request_port: "no-session: attach and activate before host-request dispatch",
            observation_forwarding_port: "unavailable: Kernel observation route not admitted",
            recovery: "attach and activate before host requests; reconnect requires a live attach",
        },
        Some(view) => Response::Status {
            profile: Profile::as_str(profile),
            control_capacity: runner.control_capacity(),
            attached: true,
            connection_id: Some(view.binding().connection_id().as_str().to_owned()),
            session_id: Some(view.binding().session_id().as_str().to_owned()),
            activation_generation: Some(view.binding().activation_generation().get()),
            authority_epoch: Some(view.binding().state_fence().authority_epoch().clone()),
            reconciliation_required: view.reconciliation_required(),
            activation_port: "attached",
            host_request_port: "session-bound: dispatch joins the admitted Kernel session",
            observation_forwarding_port: "unavailable: Kernel observation route not admitted",
            recovery: "reconnect with the live connection, session, generation, epoch, and fence nonce from this status; stale targets fail closed",
        },
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

/// Emits one typed stdin rejection without touching any request handler,
/// gateway, port, or runner.
///
/// Oversize, non-UTF-8, and transport failures are shaped into responses by
/// the caller, so the dispatch match is unreachable for them by construction:
/// this helper only writes the already-shaped rejection and reports whether
/// the acquisition loop must break afterwards.
fn emit_bounded_rejection(response: &Response) -> bool {
    let receipt = write_response(response);
    receipt.bytes_written() == 0 || receipt.should_break()
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
