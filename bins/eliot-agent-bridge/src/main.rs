#![forbid(unsafe_code)]

mod request_input;

use eliot_agent_bridge::{
    BootstrapContext, BootstrapTaskInputs, BridgeRunner, CliError, CurrentAssessment,
    HotResourceView, InjectionReceipt, Profile, ResultFlowInputs, ScopeLevel,
    UnderstandingBootstrap, kernel_ports_with_declaration, parse_args,
    reactive_runtime_composition,
};
use eliot_agent_bridge_core::{
    AttachRequest, BridgeError, ConnectionId, FencingToken, Generation, HostEventEnvelope,
    ReconnectRequest, SessionId, ToolResultReceipt,
};
use eliot_contracts::EpochId;
#[cfg(test)]
use eliot_mcp::{HostCancellationPortOutcome, HostInvocationPortOutcome, PortFailure};
use eliot_mcp::{
    HostCancellationRequest, HostCancellationResult, HostCorrelationReceipt, HostGatewayError,
    HostInvocationRequest, HostInvocationResult, HostRequestGateway, KernelHostRequestPort,
    ToolRequest,
};
use eliot_protocol::EventEnvelope;
use request_input::{
    REQUEST_INPUT_LIMIT_TABLE, REQUEST_INPUT_PROFILE, REQUEST_INPUT_PROFILE_ID, ReadOutcome,
    check_profile_id, check_request_envelope, classify_serde_error, prevalidate_record,
    read_bounded_record, scratch_budget,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::mpsc;
use std::time::Duration;

const INVALID_ARGUMENT_EXIT: i32 = 2;
const PROVIDER_PORT_EXIT: i32 = 69;

/// Stable identity of the binary-private stdio output profile.
const STDIO_OUTPUT_PROFILE_ID: &str = "eliot.agent-bridge.stdio-output.v1";
/// Maximum framed stdout bytes for one response, including the framing newline.
///
/// Bridge-local decision: twice the hard structured-response ceiling (256 KiB)
/// so one bounded structured answer plus its correlated completion receipt and
/// framing fits, without permitting unbounded accumulation. This is distinct
/// from the I7.2 4 MiB transport-frame default and from the 1 MiB stdin
/// outer-record ceiling: a transport frame, a request line, and a response
/// frame are separate budgets.
const MAX_OUTPUT_FRAME_BYTES: usize = 524_288;
/// Maximum responses outstanding on the synchronous stdio transport.
///
/// The loop serializes, writes, and flushes exactly one response before the
/// next dispatch, so no queue ever holds more than one frame. The constant
/// makes the bound explicit: pipelining a second frame is rejected by
/// construction rather than by overflow.
const MAX_OUTSTANDING_RESPONSES: usize = 1;
const _: () = assert!(
    MAX_OUTSTANDING_RESPONSES == 1,
    "stdio stays synchronous with one outstanding frame"
);
/// Links the reviewed limit/source/version/stage table into the binary so the
/// documented table cannot drift from the enforced profile unnoticed.
const _: &str = REQUEST_INPUT_LIMIT_TABLE;
/// Bounded wall-clock for one stdout write plus flush.
///
/// A blocking stdio pipe offers no deadline of its own, so the emission runs
/// on a joined helper thread and the main loop waits at most this long. A
/// slow consumer past this bound fails closed with a typed secret-free
/// stderr diagnostic and terminates instead of blocking forever.
const STDOUT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum outstanding delivery identities reported inside one Stopped frame.
///
/// Keeps the terminal drain report itself within the output bound when many
/// durable deliveries are pending: the first identities keep their exact
/// original order and the remainder is counted as truncated rather than
/// dropped silently.
const MAX_STOP_DRAIN_ITEMS: usize = 32;
/// Maximum sticky attention identities projected inside one Status frame.
///
/// The attention projection itself is unbounded in ledger terms (up to
/// `MAX_LEDGER_ITEMS` records); the status frame carries only the first
/// identities in ledger order and counts the remainder as truncated rather
/// than dropping them silently.
const MAX_STATUS_ATTENTION_ITEMS: usize = 64;

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
    /// Dry-run preview of one invocation (I7.17).
    ///
    /// Validates the inert request exactly like [`Request::Invoke`] and then
    /// answers with a typed static preview instead of dispatching: the
    /// gateway, the trusted port, the runner, and the admitted transport are
    /// never touched, so no envelope is built, no replay entry is recorded,
    /// and no external effect can occur. Read-only tools receive a validated
    /// preview; effectful tools receive `DRY_RUN_UNSUPPORTED`.
    DryRunInvoke {
        request: HostInvocationRequest,
    },
    /// Dry-run preview of one cancellation (I7.17).
    ///
    /// The bridge owns no safe cancellation simulator, so this always answers
    /// `DRY_RUN_UNSUPPORTED` with the best static preview after inert
    /// validation. The exact target handle is echoed without interpretation
    /// and no probe, cancel, or reconcile envelope is ever sent.
    DryRunCancel {
        request: HostCancellationRequest,
    },
    ForwardHook {
        event: HostEventEnvelope,
    },
    ForwardEvent {
        event: EventEnvelope,
    },
    ReconcileExternal {},
    Bootstrap {
        context: Option<BootstrapContext>,
        tasks: BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    },
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reactive: Option<ReactiveStatusView>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resources: Option<ResourceRegistryView>,
    },
    Attached {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
    },
    Reconnected {
        previous_connection_id: String,
        connection_id: String,
        session_id: String,
        activation_generation: u64,
        authority_epoch: EpochId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
    },
    Invocation {
        result: HostInvocationResult,
        completion: HostCorrelationReceipt,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
        /// Bounded hot-resource projection recorded for this delivery.
        ///
        /// Present only when the delivered result was snapshotted into the
        /// attach-scoped evidence projection (supported kind with content
        /// beyond the hot preview bound): the handle URI plus digest names
        /// the immutable bytes, the preview carries the hot-visible prefix,
        /// and full bytes require explicit expansion through the owning
        /// reader. Absent otherwise — never estimated, never invented.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<HotResourceView>,
    },
    Cancellation {
        result: HostCancellationResult,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
    },
    Forwarded {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reactive_receipts: Vec<InjectionReceipt>,
    },
    Reconciled {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
    },
    Bootstrap {
        bootstrap: UnderstandingBootstrap,
    },
    /// Typed dry-run envelope (I7.17).
    ///
    /// Deliberately distinct from [`Response::Invocation`] and
    /// [`Response::Cancellation`]: reusing the admitted/responded shape would
    /// let a preview be mistaken for kernel admission, which the bridge must
    /// never imply. The envelope stays normalized stdio framing carrying the
    /// caller correlation, the dry-run disposition, the static effect preview
    /// with its evidence/source, and the owner-derived attach binding the
    /// preview is valid under.
    DryRun {
        correlation_id: String,
        operation: &'static str,
        disposition: &'static str,
        preview: DryRunPreview,
        evidence: DryRunEvidence,
        binding: DryRunBinding,
    },
    Stopped {
        outstanding: usize,
        drained: usize,
        truncated: bool,
        pending: Vec<StopPendingIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap: Option<UnderstandingBootstrap>,
    },
    Error {
        code: &'static str,
        detail: String,
    },
}

/// Bounded sticky-attention projection for the Status frame.
///
/// `pending` counts undelivered injections for the live session;
/// `attention_item_ids` carries the first sticky attention identities in
/// ledger order with `attention_truncated` marking a remainder. Facts come
/// from the runner's delivery-record ledger; nothing here admits, delivers,
/// or resolves.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReactiveStatusView {
    pending: usize,
    attention_item_ids: Vec<String>,
    attention_truncated: bool,
}

/// Attach-scoped resource projection summary for the Status frame.
///
/// `entries` counts the immutable snapshots retained for the live attach;
/// content bytes are never carried here — previews ride hot responses and
/// full bytes require explicit expansion through the owning reader.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceRegistryView {
    entries: usize,
}

/// Original identity of one durable in-flight delivery pending at Stop.
///
/// Carries only the exact stream, event, and sequence facts from the core
/// outstanding view: no payload, no recomputed digest, and no new connection,
/// session, or request id. The host reconciles each entry under this original
/// identity; a replacement connection still requires a new admission.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StopPendingIdentity {
    stream_id: String,
    event_id: String,
    sequence: u64,
}

/// Stable identity of the bridge-local static dry-run preview contract.
const DRY_RUN_PREVIEW_SOURCE: &str = "bridge-static-preview.v1";
/// Disposition of a dry run over a read-only tool with real inert validation.
const DRY_RUN_PREVIEW_DISPOSITION: &str = "DRY_RUN_PREVIEW";
/// Honest disposition where the bridge owns no safe simulator (I7.17).
const DRY_RUN_UNSUPPORTED_DISPOSITION: &str = "DRY_RUN_UNSUPPORTED";
/// Route label used when no entry may be named as a would-be dispatch.
const DRY_RUN_ROUTE_WITHHELD: &str = "withheld-no-simulator";

/// Closed kernel entries that serve real dispatch, owned by
/// `bins/eliot-kernel/src/host_request_route.rs`. Repeated here for dry-run
/// route labeling only: a dry run never sends them, it only names which entry
/// a validated read-only request would have ridden.
const DRY_RUN_SUBMIT_OPERATION: &str = "agent_host_request_submit";
const DRY_RUN_INVOKE_READ_OPERATION: &str = "agent_host_request_invoke_read";

/// Static effect preview for one dry run: what the validated request names,
/// without any claim that the target accepted, staged, or simulated it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DryRunPreview {
    /// Canonical tool the request names (`None` for cancellation previews).
    canonical_tool_name: Option<String>,
    /// Exact opaque cancellation target (`None` for invocation previews).
    operation_handle: Option<String>,
    /// `read-only`, `effectful`, or `cancellation-probe`.
    effect_class: &'static str,
    /// Would-be kernel entry, or `withheld-no-simulator`.
    route: &'static str,
    /// Caller deadline preference echoed verbatim; the kernel would own it.
    deadline_preference_ms: Option<u64>,
    /// Always false: the bridge owns no simulator, so nothing was simulated.
    simulated: bool,
}

/// Evidence and source for one dry-run preview (I7.17).
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DryRunEvidence {
    /// Static preview contract identity.
    source: &'static str,
    /// Outcome of bridge-local inert request validation.
    inert_validation: &'static str,
    /// Honest statement of what ran and what explicitly did not.
    statement: String,
}

/// Owner-derived attach binding a dry-run preview is valid under.
///
/// Every fact is echoed from the live activation-sealed binding; nothing is
/// minted here. When unattached the preview says so instead of binding stale
/// facts, so callers cannot treat it as current.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DryRunBinding {
    attached: bool,
    connection_id: Option<String>,
    session_id: Option<String>,
    activation_generation: Option<u64>,
    authority_epoch: Option<EpochId>,
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
    if REQUEST_INPUT_PROFILE.validate().is_err()
        || check_profile_id(REQUEST_INPUT_PROFILE_ID).is_err()
        || scratch_budget(REQUEST_INPUT_PROFILE).is_none()
    {
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
        let mut response = match decode_bounded_request(text) {
            Ok(Request::Attach { request }) => match runner.attach(request) {
                Ok(_) => {
                    // Best-effort durable restore for the fresh attach: a
                    // refused or absent restore keeps the current empty-ledger
                    // behavior and is reported on stderr without failing the
                    // attach that already succeeded.
                    if let Err(error) = reactive_runtime_composition::restore_reactive_runtime(
                        &mut runner,
                        &mut *host_request_port,
                        &[],
                    ) {
                        emit_error("REACTIVE_RESTORE_REFUSED", &error.to_string());
                    }
                    Response::Attached { bootstrap: None }
                }
                Err(error) => {
                    provider_failure |= matches!(error, BridgeError::PlanGap(_));
                    bridge_error(&error)
                }
            },
            Ok(Request::Invoke { request }) => {
                let mut response =
                    handle_invocation(&host_gateway, &mut *host_request_port, &request);
                record_invocation_delivery(&mut runner, &mut response);
                response
            }
            Ok(Request::Cancel { request }) => {
                handle_cancellation(&host_gateway, &mut *host_request_port, &request)
            }
            Ok(Request::DryRunInvoke { request }) => dry_run_invocation(&runner, &request),
            Ok(Request::DryRunCancel { request }) => dry_run_cancellation(&runner, &request),
            Ok(Request::ForwardHook { event }) => {
                let (response, provider_failed) = handle_forward_hook(&mut runner, &event);
                provider_failure |= provider_failed;
                response
            }
            Ok(Request::ForwardEvent { event }) => {
                let (response, provider_failed) = handle_forward_event(&mut runner, &event);
                provider_failure |= provider_failed;
                response
            }
            Ok(Request::ReconcileExternal {}) => match runner.reconcile_external() {
                Ok(_) => Response::Reconciled { bootstrap: None },
                Err(error) => {
                    provider_failure |= is_provider_failure(&error);
                    bridge_error(&error)
                }
            },
            Ok(Request::Bootstrap {
                context,
                tasks,
                requested_assessment,
            }) => handle_bootstrap(&mut runner, context, &tasks, requested_assessment),
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
            Ok(Request::Stop) => handle_stop(&runner),
            Err(detail) => Response::Error {
                code: "REQUEST_INVALID",
                detail,
            },
        };
        // I7.17 auto-boot: the first successful ELIOT response in a session
        // carries the bounded bootstrap exactly once. Explicit retrieval
        // through the bootstrap operation stays available afterwards.
        attach_auto_bootstrap(&mut runner, &mut response);
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
        let stop = matches!(response, Response::Stopped { .. });
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

/// Serves one bounded `GetUnderstandingBootstrap` retrieval.
///
/// An optional context establishes the session inputs first; invalid context
/// fails closed and stores nothing. The first successful retrieval in a
/// session also satisfies the once-per-session auto-boot; later retrievals
/// use the explicit path so they stay available after auto-boot delivery.
fn handle_bootstrap(
    runner: &mut BridgeRunner,
    context: Option<BootstrapContext>,
    tasks: &BootstrapTaskInputs,
    requested_assessment: CurrentAssessment,
) -> Response {
    if let Some(context) = context {
        if let Err(error) = runner.note_bootstrap_context(context) {
            return Response::Error {
                code: "BOOTSTRAP_CONTEXT_REJECTED",
                detail: error.to_string(),
            };
        }
    }
    if let Some(bootstrap) = runner.take_first_response_bootstrap(tasks, requested_assessment) {
        return Response::Bootstrap { bootstrap };
    }
    match runner.get_understanding_bootstrap(tasks, requested_assessment) {
        Ok(bootstrap) => Response::Bootstrap { bootstrap },
        Err(error) => Response::Error {
            code: "BOOTSTRAP_REJECTED",
            detail: error.to_string(),
        },
    }
}

/// Injects the once-per-session auto-boot into the first successful response.
///
/// Error and dry-run responses never carry a bootstrap: a dry run is a
/// zero-side-effect preview, not a successful ELIOT response, and its
/// envelope has no bootstrap slot. When no valid context is noted
/// the response is left untouched rather than carrying invented authority.
fn attach_auto_bootstrap(runner: &mut BridgeRunner, response: &mut Response) {
    let slot = match response {
        Response::Status { bootstrap, .. }
        | Response::Attached { bootstrap }
        | Response::Reconnected { bootstrap, .. }
        | Response::Invocation { bootstrap, .. }
        | Response::Cancellation { bootstrap, .. }
        | Response::Forwarded { bootstrap, .. }
        | Response::Reconciled { bootstrap }
        | Response::Stopped { bootstrap, .. } => bootstrap,
        Response::Bootstrap { .. } | Response::Error { .. } | Response::DryRun { .. } => {
            return;
        }
    };
    if slot.is_none() {
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        *slot = runner.take_first_response_bootstrap(&tasks, CurrentAssessment::Ready);
    }
}
/// Fail-closed bounded decode bound to the accepted input profile.
///
/// Runs, in order: the decode pre-scan (single-value shape, nesting depth,
/// per-container member counts, total scalar counts, per-string decoded
/// bounds, and duplicate-key rejection with escape-equivalent comparison),
/// the top-level operation-envelope check (exact key set per operation, so
/// Serde unit variants cannot silently ignore extra members), then typed
/// `Request` construction with failures mapped to redacted diagnostics.
/// Diagnostics carry only static reasons and bounded control names; raw
/// request bytes, unknown-key text beyond the bound, body content, and
/// credentials never cross into responses. This function grants no authority
/// and performs no dispatch.
fn decode_bounded_request(text: &str) -> Result<Request, String> {
    if let Err(reject) = prevalidate_record(text, REQUEST_INPUT_PROFILE) {
        return Err(reject.to_string());
    }
    if let Err(reject) = check_request_envelope(text, REQUEST_INPUT_PROFILE) {
        return Err(reject.to_string());
    }
    serde_json::from_str::<Request>(text).map_err(|error| classify_serde_error(&error).to_string())
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
            bootstrap: None,
            evidence: None,
        },
        Err(error) => host_gateway_error(&error),
    }
}

/// Records one supported tool-result delivery after gateway return and
/// projects its handle onto the outgoing Invocation response.
///
/// Runs on the normal Invoke path with the exact authenticated outcome the gateway
/// produced. The gateway-shaped result and completion are never touched: only the
/// additive `evidence` slot is filled, and only when recording yields a snapshot
/// (supported kind with content beyond the hot preview bound). Auxiliary only: a
/// `None` (admission, rejection, gap, unsupported kind, small inline content,
/// detached runner, or full registry) leaves the response exactly as the gateway
/// shaped it, with the key absent on the wire.
/// See [`BridgeRunner::record_tool_result_delivery`].
fn record_invocation_delivery(runner: &mut BridgeRunner, response: &mut Response) {
    if let Response::Invocation {
        result, evidence, ..
    } = response
    {
        if evidence.is_none()
            && let Some(view) = runner.record_tool_result_delivery(result.outcome())
        {
            *evidence = Some(view);
        }
    }
}

/// Measured tool-result delivery hook (issue #1941 result flow).
///
/// Same auxiliary position as [`record_invocation_delivery`]: runs on the
/// normal Invoke path after the gateway returns, and never touches the
/// gateway-shaped `result`/`completion`. The live measurement inputs the
/// BIN cannot source itself (exact provider model, live observation,
/// current admission plus execution binding, admissible source handle,
/// owner-observed delivery) arrive in `inputs` from the caller holding
/// them. Returns the projected receipt for the caller that attaches it to
/// the Invocation response evidence path; `None` (unsupported outcome,
/// measurement withhold, intake rejection) leaves the response exactly as
/// the gateway shaped it. A3 owns the response-slot wiring; this hook only
/// records through [`BridgeRunner::record_measured_tool_result_delivery`].
///
/// Staged: no live holder of [`ResultFlowInputs`] exists yet (the Invoke
/// path holds bytes plus disposition only), so this stays uncalled until
/// the input holder is wired — the C1 transport staged the same way
/// before its Governor assessor landed.
#[allow(dead_code)]
fn record_measured_invocation_delivery(
    runner: &BridgeRunner,
    response: &Response,
    inputs: &ResultFlowInputs<'_>,
) -> Option<ToolResultReceipt> {
    let Response::Invocation { result, .. } = response else {
        return None;
    };
    runner.record_measured_tool_result_delivery(result.outcome(), inputs)
}

/// Delivers hook-carried reactive injections through the live stdio consumer.
///
/// Runs the exact ForwardHook dispatch step: forwards the owner-observed
/// hook event, then drains the live session's pending injections through
/// that hook, issuing one Delivery/Injection Receipt per item on the
/// Forwarded response. Pure wiring over [`BridgeRunner`]: no planning, no
/// assessment, no minting — admitted items arrive through the transport and
/// this consumer only carries them to the host. Returns the response with
/// whether the failure (if any) was a provider failure for exit accounting.
fn handle_forward_hook(
    runner: &mut BridgeRunner,
    event: &HostEventEnvelope,
) -> (Response, bool) {
    match runner.forward_hook(event) {
        Ok(()) => match runner.deliver_reactive_pending_via_hook(event.event_id.as_str()) {
            Ok(receipts) => (
                Response::Forwarded {
                    bootstrap: None,
                    reactive_receipts: receipts,
                },
                false,
            ),
            Err(error) => (
                Response::Error {
                    code: "REACTIVE_RECEIPT_REJECTED",
                    detail: error.to_string(),
                },
                false,
            ),
        },
        Err(error) => (bridge_error(&error), is_provider_failure(&error)),
    }
}

/// Delivers response-piggybacked reactive injections through the live stdio
/// consumer.
///
/// Runs the exact ForwardEvent dispatch step: forwards the event, then
/// drains the live session's pending injections inside the next bridge
/// response named by that event. Same wiring contract as
/// [`handle_forward_hook`]: no planning, no assessment, no minting.
fn handle_forward_event(runner: &mut BridgeRunner, event: &EventEnvelope) -> (Response, bool) {
    match runner.forward_event(event) {
        Ok(_) => {
            let response_id = format!("forward-event:{}", event.event_id);
            match runner.deliver_reactive_pending_via_response(&response_id) {
                Ok(receipts) => (
                    Response::Forwarded {
                        bootstrap: None,
                        reactive_receipts: receipts,
                    },
                    false,
                ),
                Err(error) => (
                    Response::Error {
                        code: "REACTIVE_RECEIPT_REJECTED",
                        detail: error.to_string(),
                    },
                    false,
                ),
            }
        }
        Err(error) => (bridge_error(&error), is_provider_failure(&error)),
    }
}

fn handle_cancellation<P: KernelHostRequestPort + ?Sized>(
    gateway: &HostRequestGateway,
    port: &mut P,
    request: &HostCancellationRequest,
) -> Response {
    match gateway.cancel(port, request) {
        Ok(result) => Response::Cancellation {
            result,
            bootstrap: None,
        },
        Err(error) => host_gateway_error(&error),
    }
}

/// Reads the live activation-sealed binding for one dry-run preview.
///
/// Read-only: echoes kernel-issued connection/session/generation/epoch facts
/// from the runner attach view without dispatching, probing, or minting
/// anything, so the preview stays bound to the revision it was computed under.
fn dry_run_binding(runner: &BridgeRunner) -> DryRunBinding {
    match runner.attach_view() {
        None => DryRunBinding {
            attached: false,
            connection_id: None,
            session_id: None,
            activation_generation: None,
            authority_epoch: None,
        },
        Some(view) => DryRunBinding {
            attached: true,
            connection_id: Some(view.binding().connection_id().as_str().to_owned()),
            session_id: Some(view.binding().session_id().as_str().to_owned()),
            activation_generation: Some(view.binding().activation_generation().get()),
            authority_epoch: Some(view.binding().state_fence().authority_epoch().clone()),
        },
    }
}

/// Classifies one invocation tool for dry-run preview (I7.17).
///
/// Read-only projections (`eliot.state`, `eliot.packet`, `eliot.query`) carry
/// no external effects, so the bridge answers them with a validated static
/// preview naming the entry they would have ridden. Every other tool is
/// effectful and the bridge owns no safe simulator for it, so the honest
/// answer is `DRY_RUN_UNSUPPORTED`. Returns the effect class, the route
/// label, and the disposition in that order.
fn dry_run_invoke_plan(tool: &ToolRequest) -> (&'static str, &'static str, &'static str) {
    match tool {
        ToolRequest::State(_) => (
            "read-only",
            DRY_RUN_SUBMIT_OPERATION,
            DRY_RUN_PREVIEW_DISPOSITION,
        ),
        ToolRequest::Packet(_) | ToolRequest::Query(_) => (
            "read-only",
            DRY_RUN_INVOKE_READ_OPERATION,
            DRY_RUN_PREVIEW_DISPOSITION,
        ),
        ToolRequest::Observe(_)
        | ToolRequest::Act(_)
        | ToolRequest::Verify(_)
        | ToolRequest::Coordinate(_)
        | ToolRequest::Finish(_)
        | ToolRequest::UserAutomation(_)
        | ToolRequest::SkillInject(_)
        | ToolRequest::SkillDisplay(_) => (
            "effectful",
            DRY_RUN_ROUTE_WITHHELD,
            DRY_RUN_UNSUPPORTED_DISPOSITION,
        ),
    }
}

/// Answers one invocation dry run with zero side effects (I7.17).
///
/// Runs the same bridge-local inert validation as a real invoke so malformed
/// input fails closed with the identical `HOST_REQUEST_INVALID` shape, then
/// returns the normalized dry-run envelope with the static preview and its
/// evidence/source. The gateway, the trusted port, and the admitted transport
/// are never called: no envelope is built, no replay entry is recorded, and
/// the target state plus the external-effect ledger stay exactly unchanged.
/// No kernel simulation or external validation runs on this path.
fn dry_run_invocation(runner: &BridgeRunner, request: &HostInvocationRequest) -> Response {
    if let Err(error) = request.validate() {
        return host_gateway_error(&HostGatewayError::from(error));
    }
    let (effect_class, route, disposition) = dry_run_invoke_plan(&request.tool);
    let statement = if disposition == DRY_RUN_UNSUPPORTED_DISPOSITION {
        "DRY_RUN_UNSUPPORTED: no validation/simulation ran against the target operation; \
         only bridge-local request-shape validation passed; no effects were issued and \
         no transport bytes were sent"
    } else {
        "bridge-local inert validation passed; no kernel simulation or external validation \
         ran; no effects were issued and no transport bytes were sent"
    };
    Response::DryRun {
        correlation_id: request.correlation_id.as_str().to_owned(),
        operation: "invoke",
        disposition,
        preview: DryRunPreview {
            canonical_tool_name: Some(request.tool.canonical_name().to_owned()),
            operation_handle: None,
            effect_class,
            route,
            deadline_preference_ms: request.deadline_preference_ms,
            simulated: false,
        },
        evidence: DryRunEvidence {
            source: DRY_RUN_PREVIEW_SOURCE,
            inert_validation: "passed",
            statement: statement.to_owned(),
        },
        binding: dry_run_binding(runner),
    }
}

/// Answers one cancellation dry run with zero side effects (I7.17).
///
/// The bridge owns no safe cancellation simulator, so after the same
/// bridge-local inert validation as a real cancel this always answers
/// `DRY_RUN_UNSUPPORTED` with the best static preview: the exact opaque
/// target echoed without interpretation plus the live attach binding. No
/// probe, cancel, or reconcile envelope is ever sent and the target operation
/// is untouched. No validation/simulation ran against the target operation.
fn dry_run_cancellation(runner: &BridgeRunner, request: &HostCancellationRequest) -> Response {
    if let Err(error) = request.validate() {
        return host_gateway_error(&HostGatewayError::from(error));
    }
    Response::DryRun {
        correlation_id: request.correlation_id.as_str().to_owned(),
        operation: "cancel",
        disposition: DRY_RUN_UNSUPPORTED_DISPOSITION,
        preview: DryRunPreview {
            canonical_tool_name: None,
            operation_handle: Some(request.operation_handle.as_str().to_owned()),
            effect_class: "cancellation-probe",
            route: DRY_RUN_ROUTE_WITHHELD,
            deadline_preference_ms: request.deadline_preference_ms,
            simulated: false,
        },
        evidence: DryRunEvidence {
            source: DRY_RUN_PREVIEW_SOURCE,
            inert_validation: "passed",
            statement:
                "DRY_RUN_UNSUPPORTED: no validation/simulation ran against the target operation; \
                only bridge-local request-shape validation passed; the exact target was echoed \
                without interpretation and no cancellation was issued"
                    .to_owned(),
        },
        binding: dry_run_binding(runner),
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
            bootstrap: None,
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

/// Builds the terminal Stop response with bounded drain accounting.
///
/// Snapshots the exact core-retained outstanding deliveries without
/// completing, acknowledging, or recomputing anything: each pending entry
/// keeps its original stream, event, and sequence identity so the host
/// reconciles it under that identity instead of dropping it and re-issuing
/// under a new id. `drained` is always zero because this binary owns no
/// acknowledgement path that could complete a durable delivery; pending
/// entries stay pending for explicit reconcile. The report itself is bounded
/// to `MAX_STOP_DRAIN_ITEMS` identities so the terminal frame always fits
/// `MAX_OUTPUT_FRAME_BYTES`; any remainder is counted via `truncated` rather
/// than dropped silently. No new connection, session, or request id is
/// minted here: Stop preserves the live attach binding verbatim.
fn build_stop_response(pending_all: Vec<StopPendingIdentity>) -> Response {
    let outstanding = pending_all.len();
    let truncated = outstanding > MAX_STOP_DRAIN_ITEMS;
    let pending = pending_all
        .into_iter()
        .take(MAX_STOP_DRAIN_ITEMS)
        .collect::<Vec<_>>();
    Response::Stopped {
        outstanding,
        drained: 0,
        truncated,
        pending,
        bootstrap: None,
    }
}

/// Handles one Stop request by accounting for durable in-flight deliveries.
///
/// Reads only: maps the runner's outstanding view into original identities
/// and shapes the bounded terminal response. Never touches dispatch,
/// activation, or transport, and never clears core state.
fn handle_stop(runner: &BridgeRunner) -> Response {
    let pending = runner
        .outstanding_deliveries()
        .iter()
        .map(|view| StopPendingIdentity {
            stream_id: view.stream_id().to_owned(),
            event_id: view.event_id().to_owned(),
            sequence: view.sequence(),
        })
        .collect::<Vec<_>>();
    build_stop_response(pending)
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
            reactive: None,
            bootstrap: None,
            resources: None,
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
            reactive: Some(reactive_status_view(runner)),
            bootstrap: None,
            resources: Some(resource_status_view(runner)),
        },
    }
}

/// Projects the bounded reactive delivery-record summary for Status.
///
/// Read-only: counts live-session pending injections and lists the first
/// sticky attention identities. The caller selects absence for the detached
/// arm. Never touches dispatch, activation, transport, or ledger state.
fn reactive_status_view(runner: &BridgeRunner) -> ReactiveStatusView {
    let attention = runner.reactive_attention();
    let truncated = attention.len() > MAX_STATUS_ATTENTION_ITEMS;
    ReactiveStatusView {
        pending: runner.reactive_pending_count(),
        attention_item_ids: attention
            .iter()
            .take(MAX_STATUS_ATTENTION_ITEMS)
            .map(|item| item.item_id.clone())
            .collect(),
        attention_truncated: truncated,
    }
}

/// Projects the attach-scoped resource projection summary for Status.
///
/// Read-only: counts retained immutable snapshots. Never touches dispatch,
/// activation, transport, or registry state.
fn resource_status_view(runner: &BridgeRunner) -> ResourceRegistryView {
    ResourceRegistryView {
        entries: runner.resource_registry_len(),
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
    /// Framed response exceeds the output bound; nothing was written.
    OutputTooLarge,
    /// Framed bytes were not fully written.
    WriteFailed,
    /// Bytes were written but the flush failed, so host delivery is unconfirmed.
    FlushFailed,
    /// Write plus flush did not complete within the output timeout, so host
    /// delivery is unconfirmed and the leaked writer thread must not be reused.
    WriteTimeout,
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

/// Outcome of waiting for a spawned emission thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AwaitOutcome {
    /// The operation could not be spawned; nothing ran.
    SpawnFailed,
    /// The operation did not report within the bound; it may still be blocked.
    Timeout,
    /// The worker died without reporting; delivery is unconfirmed.
    Disconnected,
}

/// Runs one owned `'static` operation on a helper thread with a bounded wait.
///
/// The operation owns everything it needs (framed bytes for production,
/// sleeps for tests), so the wait never borrows caller state. A timeout
/// leaves the helper blocked on the slow consumer: the caller must break
/// fail-closed and never reuse the contended stream, because the leaked
/// thread still holds its lock. Secret-free by construction: only the
/// operation's return value crosses the channel, never request bytes.
fn await_with_timeout<T>(
    timeout: Duration,
    op: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AwaitOutcome>
where
    T: Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let spawn = std::thread::Builder::new()
        .name("eliot-bridge-stdout-write".to_owned())
        .spawn(move || {
            let output = op();
            let _ = sender.send(output);
        });
    if spawn.is_err() {
        return Err(AwaitOutcome::SpawnFailed);
    }
    receiver.recv_timeout(timeout).map_err(|error| match error {
        mpsc::RecvTimeoutError::Timeout => AwaitOutcome::Timeout,
        mpsc::RecvTimeoutError::Disconnected => AwaitOutcome::Disconnected,
    })
}

/// Serializes one response into its newline-framed stdout bytes with the
/// output bound enforced before any I/O.
///
/// Exactly one frame is produced per call, which enforces
/// `MAX_OUTSTANDING_RESPONSES == 1` by construction: the synchronous loop
/// never pipelines a second frame. Oversize frames are refused without
/// writing a prefix and without including payload bytes in any diagnostic.
fn frame_response(response: &Response) -> Result<Vec<u8>, StdioBreakCause> {
    let mut framed = serde_json::to_vec(response).map_err(|_| StdioBreakCause::SerializeFailed)?;
    framed.push(b'\n');
    if framed.len() > MAX_OUTPUT_FRAME_BYTES {
        return Err(StdioBreakCause::OutputTooLarge);
    }
    Ok(framed)
}

fn write_response(response: &Response) -> StdioWriteReceipt {
    let framed = match frame_response(response) {
        Ok(framed) => framed,
        Err(StdioBreakCause::OutputTooLarge) => {
            emit_error(
                "STDOUT_RESPONSE_TOO_LARGE",
                &format!(
                    "framed response exceeds {MAX_OUTPUT_FRAME_BYTES} bytes for {STDIO_OUTPUT_PROFILE_ID}; emission refused"
                ),
            );
            return StdioWriteReceipt {
                bytes: 0,
                flushed: false,
                cause: StdioBreakCause::OutputTooLarge,
            };
        }
        Err(cause) => {
            return StdioWriteReceipt {
                bytes: 0,
                flushed: false,
                cause,
            };
        }
    };
    let bytes = framed.len();
    let awaited = await_with_timeout(STDOUT_WRITE_TIMEOUT, move || {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        if output.write_all(&framed).is_err() {
            return Err(StdioBreakCause::WriteFailed);
        }
        if output.flush().is_err() {
            return Err(StdioBreakCause::FlushFailed);
        }
        Ok(bytes)
    });
    match awaited {
        Ok(Ok(written)) => StdioWriteReceipt {
            bytes: written,
            flushed: true,
            cause: StdioBreakCause::Emitted,
        },
        Ok(Err(StdioBreakCause::FlushFailed)) => StdioWriteReceipt {
            bytes,
            flushed: false,
            cause: StdioBreakCause::FlushFailed,
        },
        Ok(Err(_)) | Err(AwaitOutcome::SpawnFailed | AwaitOutcome::Disconnected) => {
            StdioWriteReceipt {
                bytes: 0,
                flushed: false,
                cause: StdioBreakCause::WriteFailed,
            }
        }
        Err(AwaitOutcome::Timeout) => {
            emit_error(
                "STDOUT_WRITE_TIMEOUT",
                &format!(
                    "stdout write plus flush exceeded {} ms for {STDIO_OUTPUT_PROFILE_ID}; slow consumer, emission unconfirmed",
                    STDOUT_WRITE_TIMEOUT.as_millis()
                ),
            );
            StdioWriteReceipt {
                bytes: 0,
                flushed: false,
                cause: StdioBreakCause::WriteTimeout,
            }
        }
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

    const DRY_RUN_INVOKE: &str = r#"{
        "op":"dry_run_invoke",
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

    const DRY_RUN_CANCEL: &str = r#"{
        "op":"dry_run_cancel",
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

    const DRY_RUN_SEND: &str = r#"{
        "op":"dry_run_invoke",
        "request":{
            "protocol_version":"2026-07-28",
            "correlation_id":"host-dryrun-send-1",
            "client_capabilities":{"tasks":false},
            "tool":{"name":"eliot.coordinate","arguments":{"operation":"send","recipient_ref":"peer-1","message":{"text":"hello"}}},
            "deadline_preference_ms":5000,
            "observed_context":{
                "host_session_hint":"host-turn-1",
                "observed_resource_refs":[],
                "event_cursors":[],
                "trace_context":{}
            }
        }
    }"#;

    const DRY_RUN_SKILL: &str = r#"{
        "op":"dry_run_invoke",
        "request":{
            "protocol_version":"2026-07-28",
            "correlation_id":"host-dryrun-skill-1",
            "client_capabilities":{"tasks":false},
            "tool":{"name":"skill.inject","arguments":{"contract_version":1}},
            "deadline_preference_ms":5000,
            "observed_context":{
                "host_session_hint":"host-turn-1",
                "observed_resource_refs":[],
                "event_cursors":[],
                "trace_context":{}
            }
        }
    }"#;

    fn dry_run_test_runner() -> BridgeRunner {
        BridgeRunner::new(
            Profile::SpineFunctional,
            eliot_agent_bridge_core::ProviderReadiness::all_admitted(),
            None,
            None,
        )
        .expect("test runner must compose without a kernel port")
    }

    // WORK_UNIT_CASE: 977/11
    #[test]
    fn raw_forward_frame_is_not_a_public_operation() {
        let error = serde_json::from_str::<Request>(r#"{"op":"forward_frame","frame":{}}"#)
            .expect_err("raw canonical Frame ingress must be absent");
        assert!(error.to_string().contains("unknown variant"));
    }

    // WORK_UNIT_CASE: 977/2
    #[test]
    fn dry_run_ops_deserialize_and_real_ops_take_no_dry_run_flag() {
        assert!(matches!(
            serde_json::from_str::<Request>(DRY_RUN_INVOKE)
                .expect("dry-run invoke must deserialize"),
            Request::DryRunInvoke { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(DRY_RUN_CANCEL)
                .expect("dry-run cancel must deserialize"),
            Request::DryRunCancel { .. }
        ));
        // The live Invoke/Cancel shapes are unchanged: a dry_run flag on them
        // is rejected instead of silently altering dispatch semantics.
        let flagged = INVOKE.replace("\"op\":\"invoke\",", "\"op\":\"invoke\",\"dry_run\":true,");
        let error = serde_json::from_str::<Request>(&flagged)
            .expect_err("live invoke must not accept a dry_run flag");
        assert!(error.to_string().contains("unknown field"));
        let bogus = DRY_RUN_INVOKE.replace(
            "\"op\":\"dry_run_invoke\",",
            "\"op\":\"dry_run_invoke\",\"bogus\":1,",
        );
        let error = serde_json::from_str::<Request>(&bogus)
            .expect_err("dry-run invoke must reject unknown fields");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn dry_run_ops_pass_production_decode_gate_to_dispatch() {
        // The production stdio loop decodes through decode_bounded_request
        // (pre-scan + envelope shape + typed Request), not raw serde: dry-run
        // wire ingress must survive that exact pipeline to reach the
        // implementation, and foreign members must fail closed there.
        assert!(matches!(
            decode_bounded_request(DRY_RUN_INVOKE).expect("dry-run invoke must pass the gate"),
            Request::DryRunInvoke { .. }
        ));
        assert!(matches!(
            decode_bounded_request(DRY_RUN_CANCEL).expect("dry-run cancel must pass the gate"),
            Request::DryRunCancel { .. }
        ));
        let bogus = DRY_RUN_INVOKE.replace(
            "\"op\":\"dry_run_invoke\",",
            "\"op\":\"dry_run_invoke\",\"bogus\":1,",
        );
        let detail = decode_bounded_request(&bogus).expect_err("gate must reject foreign members");
        assert!(
            detail.contains(REQUEST_INPUT_PROFILE_ID),
            "gate rejection must cite the profile, got: {detail}"
        );
    }

    #[test]
    fn dry_run_read_only_invoke_returns_preview_without_dispatch() {
        // Zero side effects hold by construction: dry_run_invocation takes
        // only a read-only runner view and the inert request. No gateway, no
        // trusted port, and no mutable runner cross this call, so no envelope
        // is built, no replay entry is recorded, and no transport byte moves.
        let Request::DryRunInvoke { request } =
            serde_json::from_str::<Request>(DRY_RUN_INVOKE).expect("dry-run must deserialize")
        else {
            panic!("expected dry-run invoke");
        };
        let runner = dry_run_test_runner();
        let response = dry_run_invocation(&runner, &request);
        let Response::DryRun {
            correlation_id,
            operation,
            disposition,
            preview,
            evidence,
            binding,
        } = response
        else {
            panic!("dry run must answer its own envelope, never an admission");
        };
        assert_eq!(correlation_id, "host-request-1");
        assert_eq!(operation, "invoke");
        assert_eq!(disposition, "DRY_RUN_PREVIEW");
        assert_eq!(preview.canonical_tool_name.as_deref(), Some("eliot.state"));
        assert_eq!(preview.effect_class, "read-only");
        assert_eq!(preview.route, "agent_host_request_submit");
        assert_eq!(preview.deadline_preference_ms, Some(5000));
        assert!(!preview.simulated);
        assert_eq!(evidence.source, "bridge-static-preview.v1");
        assert_eq!(evidence.inert_validation, "passed");
        assert!(evidence.statement.contains("no kernel simulation"));
        assert!(!binding.attached, "unattached preview must say so");
        assert!(binding.connection_id.is_none());
        let value = serde_json::to_value(&Response::DryRun {
            correlation_id: correlation_id.clone(),
            operation,
            disposition,
            preview: preview.clone(),
            evidence: evidence.clone(),
            binding: binding.clone(),
        })
        .expect("dry-run envelope must serialize");
        assert_eq!(value["status"], Value::String("dry_run".to_owned()));
        assert_eq!(
            value["disposition"],
            Value::String("DRY_RUN_PREVIEW".to_owned())
        );
    }

    #[test]
    fn dry_run_effectful_invoke_returns_unsupported_with_static_preview() {
        let Request::DryRunInvoke { request } =
            serde_json::from_str::<Request>(DRY_RUN_SEND).expect("dry-run must deserialize")
        else {
            panic!("expected dry-run invoke");
        };
        let runner = dry_run_test_runner();
        let response = dry_run_invocation(&runner, &request);
        let Response::DryRun {
            disposition,
            preview,
            evidence,
            ..
        } = response
        else {
            panic!("effectful dry run must stay a dry-run envelope");
        };
        assert_eq!(disposition, "DRY_RUN_UNSUPPORTED");
        assert_eq!(
            preview.canonical_tool_name.as_deref(),
            Some("eliot.coordinate")
        );
        assert_eq!(preview.effect_class, "effectful");
        assert_eq!(preview.route, "withheld-no-simulator");
        assert!(!preview.simulated);
        assert!(evidence.statement.contains("DRY_RUN_UNSUPPORTED"));
        assert!(
            evidence.statement.contains("no validation/simulation ran"),
            "unsupported preview must state plainly that no validation/simulation ran"
        );
        assert!(
            !evidence.statement.contains("simulation succeeded")
                && !evidence.statement.contains("validation succeeded")
                && !evidence.statement.contains("admitted"),
            "unsupported preview must not assert external validation occurred"
        );
    }

    #[test]
    fn dry_run_skill_carrier_returns_unsupported_without_dispatch() {
        // Skill carriers are effectful (install/issue) with no bridge-owned
        // simulator: the dry run stays a static preview naming the skill
        // route, dispatching nothing.
        let Request::DryRunInvoke { request } =
            serde_json::from_str::<Request>(DRY_RUN_SKILL).expect("dry-run must deserialize")
        else {
            panic!("expected dry-run invoke");
        };
        assert_eq!(request.tool.canonical_name(), "skill.inject");
        let runner = dry_run_test_runner();
        let response = dry_run_invocation(&runner, &request);
        let Response::DryRun {
            disposition,
            preview,
            evidence,
            ..
        } = response
        else {
            panic!("skill dry run must stay a dry-run envelope");
        };
        assert_eq!(disposition, "DRY_RUN_UNSUPPORTED");
        assert_eq!(preview.canonical_tool_name.as_deref(), Some("skill.inject"));
        assert_eq!(preview.effect_class, "effectful");
        assert_eq!(preview.route, "withheld-no-simulator");
        assert!(!preview.simulated);
        assert!(evidence.statement.contains("DRY_RUN_UNSUPPORTED"));
    }

    #[test]
    fn dry_run_cancel_returns_unsupported_with_exact_target_echo() {
        let Request::DryRunCancel { request } =
            serde_json::from_str::<Request>(DRY_RUN_CANCEL).expect("dry-run must deserialize")
        else {
            panic!("expected dry-run cancel");
        };
        let runner = dry_run_test_runner();
        let response = dry_run_cancellation(&runner, &request);
        let Response::DryRun {
            correlation_id,
            operation,
            disposition,
            preview,
            evidence,
            ..
        } = response
        else {
            panic!("cancel dry run must stay a dry-run envelope");
        };
        assert_eq!(correlation_id, "host-cancel-1");
        assert_eq!(operation, "cancel");
        assert_eq!(disposition, "DRY_RUN_UNSUPPORTED");
        assert_eq!(
            preview.operation_handle.as_deref(),
            Some("kernel-operation-1")
        );
        assert_eq!(preview.effect_class, "cancellation-probe");
        assert!(!preview.simulated);
        assert!(evidence.statement.contains("no validation/simulation ran"));
    }

    #[test]
    fn dry_run_malformed_input_fails_closed_like_live_dispatch() {
        let Request::DryRunInvoke { mut request } =
            serde_json::from_str::<Request>(DRY_RUN_INVOKE).expect("dry-run must deserialize")
        else {
            panic!("expected dry-run invoke");
        };
        request.deadline_preference_ms = Some(0);
        let runner = dry_run_test_runner();
        let response = dry_run_invocation(&runner, &request);
        let value = serde_json::to_value(&response).expect("error must serialize");
        assert_eq!(
            value["status"],
            Value::String("error".to_owned()),
            "malformed dry run must fail closed, never preview"
        );
        assert_eq!(
            value["code"],
            Value::String("HOST_REQUEST_INVALID".to_owned()),
            "malformed dry run must reuse the live-dispatch rejection shape"
        );
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

    // WORK_UNIT_CASE: 977/9
    // WORK_UNIT_CASE: 977/13
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

    // WORK_UNIT_CASE: 977/17
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

    // WORK_UNIT_CASE: 977/2
    // WORK_UNIT_CASE: 977/15
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

    // WORK_UNIT_CASE: 977/18
    #[test]
    fn output_bound_refuses_oversize_and_timeout_is_explicit() {
        let small = Response::Error {
            code: "REQUEST_INVALID",
            detail: "bounded".to_owned(),
        };
        let framed = frame_response(&small).expect("small frame must fit");
        assert!(!framed.is_empty());
        assert!(framed.len() <= MAX_OUTPUT_FRAME_BYTES);
        assert_eq!(framed.last(), Some(&b'\n'));

        let oversize = Response::Error {
            code: "REQUEST_INVALID",
            detail: "X".repeat(MAX_OUTPUT_FRAME_BYTES),
        };
        let cause = frame_response(&oversize).expect_err("oversize must be refused");
        assert_eq!(cause, StdioBreakCause::OutputTooLarge);
        assert!(!format!("{cause:?}").contains('X'));
        let receipt = StdioWriteReceipt {
            bytes: 0,
            flushed: false,
            cause,
        };
        assert_eq!(receipt.bytes_written(), 0);
        assert!(receipt.should_break());

        let slow = await_with_timeout(Duration::from_millis(20), || {
            std::thread::sleep(Duration::from_millis(500));
            1_u8
        });
        assert_eq!(slow, Err(AwaitOutcome::Timeout));
        let timeout_receipt = StdioWriteReceipt {
            bytes: 0,
            flushed: false,
            cause: StdioBreakCause::WriteTimeout,
        };
        assert_eq!(timeout_receipt.bytes_written(), 0);
        assert!(timeout_receipt.should_break());

        let fast = await_with_timeout(Duration::from_secs(5), || 7_u8)
            .expect("fast operation must complete");
        assert_eq!(fast, 7_u8);
    }

    // WORK_UNIT_CASE: 977/16
    #[test]
    fn stop_reports_bounded_drain_with_original_identity() {
        let clean = build_stop_response(Vec::new());
        let clean_value = serde_json::to_value(&clean).expect("stop must serialize");
        assert_eq!(clean_value["status"], Value::String("stopped".to_owned()));
        assert_eq!(clean_value["outstanding"], Value::from(0_u64));
        assert_eq!(clean_value["drained"], Value::from(0_u64));
        assert_eq!(clean_value["truncated"], Value::Bool(false));
        assert_eq!(clean_value["pending"], Value::Array(Vec::new()));

        let many = (0..(MAX_STOP_DRAIN_ITEMS + 8))
            .map(|index| StopPendingIdentity {
                stream_id: format!("stream-{index}"),
                event_id: format!("event-{index}"),
                sequence: u64::try_from(index).expect("test index must fit"),
            })
            .collect::<Vec<_>>();
        let total = many.len();
        let first_stream = many[0].stream_id.clone();
        let capped_last_stream = many[MAX_STOP_DRAIN_ITEMS - 1].stream_id.clone();
        let response = build_stop_response(many);
        let value = serde_json::to_value(&response).expect("stop must serialize");
        assert_eq!(
            value["outstanding"],
            Value::from(u64::try_from(total).expect("count must fit"))
        );
        assert_eq!(value["drained"], Value::from(0_u64));
        assert_eq!(value["truncated"], Value::Bool(true));
        let pending = value["pending"].as_array().expect("pending must list");
        assert_eq!(pending.len(), MAX_STOP_DRAIN_ITEMS);
        assert_eq!(pending[0]["stream_id"], Value::String(first_stream));
        assert_eq!(
            pending[MAX_STOP_DRAIN_ITEMS - 1]["stream_id"],
            Value::String(capped_last_stream)
        );
        let framed = frame_response(&response).expect("bounded drain report must fit");
        assert!(framed.len() <= MAX_OUTPUT_FRAME_BYTES);
    }

    /// I7.19 stdio-shape proof: issued Delivery/Injection Receipts ride the
    /// `Forwarded` frame that carried them, the key stays absent when no
    /// receipt was issued, and Status projects the bounded reactive summary.
    #[test]
    fn forwarded_response_carries_receipts_only_when_issued() {
        use eliot_agent_bridge::{
            AdmissionBasis, DeliveryPoint, FiringEvidence, RiskTier, Severity, UseOutcome,
        };

        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let receipt = InjectionReceipt {
            receipt_id: "injection-receipt-1".to_owned(),
            item_id: "reactive-item-1".to_owned(),
            session_id: "session-reactive-1".to_owned(),
            firing: FiringEvidence {
                rule_id: "exact-rule-reactive-7".to_owned(),
                cue_id: "cue-reactive-1".to_owned(),
                cue_digest: DIGEST.to_owned(),
            },
            admission: AdmissionBasis {
                scope_id: "scope-reactive-1".to_owned(),
                status: "active".to_owned(),
                risk: RiskTier::Severe,
                governance_profile_rev: "gov-reactive-3".to_owned(),
                fence_epoch: "epoch-reactive-1".to_owned(),
                fence_generation: 2,
                admitted_severity: Severity::Critical,
            },
            delivery: DeliveryPoint::HostHook {
                hook_id: "hook-reactive-1".to_owned(),
            },
            use_status: UseOutcome::Unknown,
        };
        let empty = Response::Forwarded {
            bootstrap: None,
            reactive_receipts: Vec::new(),
        };
        let empty_value = serde_json::to_value(&empty).expect("forwarded must serialize");
        assert_eq!(empty_value["status"], Value::String("forwarded".to_owned()));
        assert!(
            empty_value.get("reactive_receipts").is_none(),
            "no receipts means no key on the wire"
        );
        let carried = Response::Forwarded {
            bootstrap: None,
            reactive_receipts: vec![receipt],
        };
        let value = serde_json::to_value(&carried).expect("carried must serialize");
        let receipts = value["reactive_receipts"]
            .as_array()
            .expect("receipts must list");
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0]["receipt_id"],
            Value::String("injection-receipt-1".to_owned())
        );
        assert_eq!(
            receipts[0]["firing"]["rule_id"],
            Value::String("exact-rule-reactive-7".to_owned())
        );
        assert_eq!(
            receipts[0]["admission"]["scope_id"],
            Value::String("scope-reactive-1".to_owned())
        );
        assert_eq!(
            receipts[0]["delivery"]["kind"],
            Value::String("HOST_HOOK".to_owned())
        );
        assert!(receipts[0].get("use_status").is_some());
        let framed = frame_response(&carried).expect("receipt frame must fit");
        assert!(framed.len() <= MAX_OUTPUT_FRAME_BYTES);
    }

    #[test]
    fn detached_status_omits_reactive_summary_and_view_is_empty() {
        let runner = fixture_runner();
        let view = reactive_status_view(&runner);
        assert_eq!(view.pending, 0);
        assert!(view.attention_item_ids.is_empty());
        assert!(!view.attention_truncated);
        let resources = resource_status_view(&runner);
        assert_eq!(resources.entries, 0);
        let response = status_response(Profile::SpineFunctional, &runner);
        let value = serde_json::to_value(&response).expect("status must serialize");
        assert_eq!(value["attached"], Value::Bool(false));
        assert!(
            value.get("reactive").is_none(),
            "detached status carries no reactive key"
        );
        assert!(
            value.get("resources").is_none(),
            "detached status carries no resources key"
        );
    }

    /// Bounded-decoder proof over the versioned JSON corpus.
    ///
    /// Drives every `tests/data/request_input_cases.json` entry through the
    /// exact production pipeline (`prevalidate_record` →
    /// `check_request_envelope` → typed `Request` construction with
    /// redacted classification, or `read_bounded_record` framing for the
    /// non-UTF-8 entry). Accepts assert the operation discriminant;
    /// rejections assert the profile citation, the bound-specific reason,
    /// and — for the secret canary — that the sensitive body never crosses
    /// into the diagnostic.
    ///
    /// Case 977/14 holds by construction here: every rejection below is
    /// produced by the pure `decode_bounded_request` stage (`&str` in,
    /// `Result` out), which takes no handler, gateway, port, or runner
    /// handle, so a rejected record cannot have dispatched before the
    /// `Err` is observed. Startup failures stay on the separate
    /// `emit_error` + process-exit path and never enter this pipeline.
    // WORK_UNIT_CASE: 977/2
    // WORK_UNIT_CASE: 977/4
    // WORK_UNIT_CASE: 977/5
    // WORK_UNIT_CASE: 977/9
    // WORK_UNIT_CASE: 977/12
    // WORK_UNIT_CASE: 977/13
    // WORK_UNIT_CASE: 977/14
    // WORK_UNIT_CASE: 977/15
    // WORK_UNIT_CASE: 977/18
    // WORK_UNIT_CASE: 977/19
    #[test]
    fn bounded_decoder_fixture_covers_accept_skip_and_reject() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/data/request_input_cases.json"))
                .expect("decoder fixture must parse");
        assert_eq!(
            fixture["profile_id"],
            Value::String(REQUEST_INPUT_PROFILE_ID.to_owned())
        );
        let cases = fixture["cases"]
            .as_array()
            .expect("fixture must list cases");
        assert!(
            cases.len() >= 20,
            "proof suite needs at least 20 cases, found {}",
            cases.len()
        );
        let mut covered: usize = 0;
        for case in cases {
            let id = case["id"].as_str().expect("case needs an id");
            let expect = case["expect"].as_str().expect("case needs an expect");
            if expect == "reject" && id == "invalid-utf8-bytes" {
                let bytes: Vec<u8> = case["raw_bytes"]
                    .as_array()
                    .expect("raw_bytes must list")
                    .iter()
                    .map(|byte| {
                        u8::try_from(byte.as_u64().expect("byte must fit")).expect("byte must fit")
                    })
                    .collect();
                let mut cursor = std::io::BufReader::new(bytes.as_slice());
                assert!(
                    matches!(
                        read_bounded_record(&mut cursor, REQUEST_INPUT_PROFILE),
                        Ok(ReadOutcome::InvalidUtf8)
                    ),
                    "{id} must fail closed at framing"
                );
                covered += 1;
                continue;
            }
            let text: String = if let Some(raw) = case.get("raw").and_then(Value::as_str) {
                raw.to_owned()
            } else if let Some(generator) = case.get("raw_is").and_then(Value::as_str) {
                match generator {
                    "generated-object-5000-members" => {
                        let mut generated = String::from("{");
                        for index in 0..5000_usize {
                            if index > 0 {
                                generated.push(',');
                            }
                            generated.push_str(&format!("\"k{index:05}\":{index}"));
                        }
                        generated.push('}');
                        generated
                    }
                    "generated-nested-20000-scalars" => {
                        let chunk = (0..2500_usize)
                            .map(|index| index.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        let chunks = (0..8_usize)
                            .map(|_| format!("[{chunk}]"))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("[{chunks}]")
                    }
                    "generated-long-string-600k" => {
                        format!("{{\"s\":\"{}\"}}", "x".repeat(600_000))
                    }
                    _ => panic!("case {id} names an unknown generator"),
                }
            } else {
                panic!("case {id} needs raw, raw_is, or raw_bytes");
            };
            match expect {
                "skip" => {
                    assert!(text.trim().is_empty(), "{id} must be a blank line");
                    covered += 1;
                }
                "accept" => {
                    let request = match decode_bounded_request(&text) {
                        Ok(request) => request,
                        Err(detail) => panic!("{id} must decode: {detail}"),
                    };
                    let seen = match request {
                        Request::Attach { .. } => "attach",
                        Request::Invoke { .. } => "invoke",
                        Request::Cancel { .. } => "cancel",
                        Request::DryRunInvoke { .. } => "dry_run_invoke",
                        Request::DryRunCancel { .. } => "dry_run_cancel",
                        Request::ForwardHook { .. } => "forward_hook",
                        Request::ForwardEvent { .. } => "forward_event",
                        Request::ReconcileExternal {} => "reconcile_external",
                        Request::Reconnect { .. } => "reconnect",
                        Request::Status => "status",
                        Request::Stop => "stop",
                        Request::Bootstrap { .. } => "bootstrap",
                    };
                    if let Some(op) = case.get("op").and_then(Value::as_str) {
                        assert_eq!(seen, op, "{id} decoded the wrong operation");
                    }
                    covered += 1;
                }
                "reject" => {
                    let reason = case["reason"].as_str().expect("reject needs a reason");
                    let detail = match decode_bounded_request(&text) {
                        Ok(_) => panic!("{id} must reject"),
                        Err(detail) => detail,
                    };
                    assert!(
                        detail.contains(REQUEST_INPUT_PROFILE_ID),
                        "{id} rejection must cite the profile"
                    );
                    match reason {
                        "trailing-bytes" => assert!(
                            detail.contains("trailing bytes"),
                            "{id} must report trailing bytes"
                        ),
                        "unknown-variant" => assert!(
                            detail.contains("unsupported operation variant"),
                            "{id} must report the unknown variant"
                        ),
                        "duplicate-key" => assert!(
                            detail.contains("duplicate protected key"),
                            "{id} must report the duplicate key"
                        ),
                        "depth-exceeded" => assert!(
                            detail.contains("admitted depth"),
                            "{id} must report the depth bound"
                        ),
                        "too-many-members" => assert!(
                            detail.contains("admitted member bound"),
                            "{id} must report the member bound"
                        ),
                        "too-many-scalars" => assert!(
                            detail.contains("admitted scalar bound"),
                            "{id} must report the scalar bound"
                        ),
                        "string-too-long" => assert!(
                            detail.contains("admitted decoded bound"),
                            "{id} must report the string bound"
                        ),
                        "redacted" => assert!(
                            !detail.contains("canary-marker-7f3a-secret-body"),
                            "{id} must not echo the canary body"
                        ),
                        _ => {}
                    }
                    if id == "secret-canary" {
                        assert!(
                            !detail.contains("canary-marker-7f3a-secret-body"),
                            "canary body must never cross into diagnostics"
                        );
                    }
                    covered += 1;
                }
                _ => panic!("case {id} names an unknown expectation"),
            }
        }
        assert!(
            covered >= 20,
            "proof suite must cover at least 20 cases, covered {covered}"
        );
    }

    const BOOTSTRAP_OP: &str = r#"{
        "op":"bootstrap",
        "context":{
            "principal_ref":"principal-1",
            "profile_ref":"SPINE_FUNCTIONAL",
            "workscope_ref":"workscope-1",
            "onboarding_readiness_ref":"readiness-receipt-1",
            "onboarding_disposition":"READY_MATERIAL",
            "revision_refs":["source-gen-9"],
            "orientation_handles":[],
            "attention_handles":[],
            "problem_handles":[],
            "role_lease_ref":"role-lease-1",
            "state_fence_ref":"fence-epoch-3-gen-7",
            "governance":{
                "profile_ref":"governance-profile-1",
                "profile_revision":"rev-7",
                "limiting_integration_evidence":["coverage:PreToolUse:ENFORCED"]
            },
            "supported_count":4,
            "verified_count":3,
            "candidate_count":1,
            "conflicts_unknowns":[],
            "next_safe_expansion":"bind task before material effects"
        },
        "tasks":{"scope_level":"session"},
        "requested_assessment":"READY"
    }"#;

    const BOOTSTRAP_CONTEXT_JSON: &str = r#"{        "principal_ref":"principal-1",
        "profile_ref":"SPINE_FUNCTIONAL",
        "workscope_ref":"workscope-1",
        "onboarding_readiness_ref":"readiness-receipt-1",
        "onboarding_disposition":"READY_MATERIAL",
        "revision_refs":["source-gen-9"],
        "orientation_handles":[],
        "attention_handles":[],
        "problem_handles":[],
        "role_lease_ref":"role-lease-1",
        "state_fence_ref":"fence-epoch-3-gen-7",
        "governance":{
            "profile_ref":"governance-profile-1",
            "profile_revision":"rev-7",
            "limiting_integration_evidence":["coverage:PreToolUse:ENFORCED"]
        },
        "supported_count":4,
        "verified_count":3,
        "candidate_count":1,
        "conflicts_unknowns":[],
        "next_safe_expansion":"bind task before material effects"
    }"#;

    fn empty_tasks() -> BootstrapTaskInputs {
        BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        }
    }

    fn fixture_runner() -> BridgeRunner {
        use eliot_agent_bridge_core::ProviderReadiness;
        BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::unprobed(),
            None,
            None,
        )
        .expect("test runner composes")
    }

    #[test]
    fn merged_decode_path_and_first_response_bootstrap_composition() {
        // Main-side bounded decode dispatches known operations — including
        // the bridge-side bootstrap op through the admitted envelope shape —
        // and rejects malformed input without dispatch.
        let decoded =
            decode_bounded_request(r#"{"op":"status"}"#).expect("status op must decode");
        assert!(
            matches!(decoded, Request::Status),
            "status op must decode to its own request"
        );
        let bootstrap_decoded =
            decode_bounded_request(BOOTSTRAP_OP).expect("valid bootstrap op must decode");
        assert!(
            matches!(bootstrap_decoded, Request::Bootstrap { .. }),
            "explicit bootstrap retrieval must survive the envelope gate"
        );
        assert!(
            decode_bounded_request("{not json").is_err(),
            "malformed input must reject"
        );
        // An unknown op, an extra member on the bootstrap shape, and an
        // oversized bootstrap record stay rejected: the envelope gate is
        // not bypassed for the new row.
        assert!(
            decode_bounded_request(r#"{"op":"bootstrap_unknown"}"#).is_err(),
            "unknown operations must reject"
        );
        assert!(
            decode_bounded_request(
                &BOOTSTRAP_OP.replace(
                    "\"requested_assessment\":\"READY\"",
                    "\"requested_assessment\":\"READY\",\"extra\":1"
                )
            )
            .is_err(),
            "extra envelope members must reject"
        );
        assert!(
            decode_bounded_request(
                &BOOTSTRAP_OP.replace("source-gen-9", &"g".repeat(600_000))
            )
            .is_err(),
            "oversized records must reject"
        );
        // Bridge-side bootstrap injection: the first successful response
        // carries the bounded bootstrap with the actual governance
        // evidence; the second carries none, while explicit retrieval
        // stays available (including via the admitted stdio op above).
        let mut runner = fixture_runner();
        let context: BootstrapContext =
            serde_json::from_str(BOOTSTRAP_CONTEXT_JSON).unwrap();
        runner
            .note_bootstrap_context(context)
            .expect("valid context must note");
        let mut first = Response::Forwarded {
            bootstrap: None,
            reactive_receipts: Vec::new(),
        };
        attach_auto_bootstrap(&mut runner, &mut first);
        let carried = match first {
            Response::Forwarded {
                bootstrap: Some(ref bootstrap),
                ..
            } => bootstrap,
            _ => panic!("first successful response must carry the bootstrap"),
        };
        assert!(
            !carried.governance.limiting_integration_evidence.is_empty(),
            "bootstrap must carry limiting integration evidence"
        );
        let mut second = Response::Forwarded {
            bootstrap: None,
            reactive_receipts: Vec::new(),
        };
        attach_auto_bootstrap(&mut runner, &mut second);
        assert!(
            matches!(
                second,
                Response::Forwarded {
                    bootstrap: None,
                    reactive_receipts: _
                }
            ),
            "bootstrap must be injected exactly once"
        );
        let explicit = runner
            .get_understanding_bootstrap(&empty_tasks(), CurrentAssessment::Ready)
            .expect("explicit retrieval stays available");
        assert_eq!(explicit.governance.profile_ref, "governance-profile-1");
    }

    /// C3 production-path proof: supported Kernel read-result bytes reaching the normal
    /// Invoke path populate the attach-scoped evidence registry through the real caller
    /// chain (gateway → authenticated outcome → runner record), and the snapshot expands
    /// back to the exact bytes. No manual publisher feed: the only producer here is the
    /// stubbed trusted port standing in for the Kernel boundary, exactly as the
    /// `UnavailableKernelHostRequestPort` placeholder does for rejections.
    mod tool_result_delivery_tests {
        use super::super::{
            BridgeRunner, Profile, record_invocation_delivery, status_response,
        };
        use super::{
            HostInvocationRequest, PortFailure, decode_bounded_request,
            handle_invocation,
        };
        use eliot_agent_bridge_core::{
            ActivationPortOutcome, ActivationPortResult, AttachRequest, DemandId, FencingToken,
            Generation, HostActivationPort, PrincipalId, ProviderFailure, ProviderReadiness,
            SessionId, TaskId, WorkUnitId,
        };
        use eliot_contracts::{EpochId, EpochLineageId};
        use eliot_mcp::{
            HostInvocationPortOutcome, HostOperationHandle, KernelHostRequestPort, McpResponse,
            ResponseKind,
        };
        use eliot_receipts::ProofCeiling;
        use std::num::NonZeroU64;

        const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        const DIGEST_A: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        struct StaticActivation {
            result: ActivationPortResult,
        }

        impl HostActivationPort for StaticActivation {
            fn activate(
                &mut self,
                _request: &AttachRequest,
            ) -> Result<ActivationPortOutcome, ProviderFailure> {
                Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
            }
        }

        fn attached_runner() -> BridgeRunner {
            let generation = Generation::new(5).expect("non-zero test generation");
            let fence = FencingToken::new(
                EpochId::new(
                    EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
                    NonZeroU64::new(2).expect("nonzero test sequence"),
                )
                .expect("valid test epoch"),
                generation,
                "fence-delivery-5",
            )
            .expect("valid test fence");
            let result = ActivationPortResult::authenticated(
                PrincipalId::new("principal-delivery-1").expect("valid principal"),
                SessionId::new("session-delivery-1").expect("valid session"),
                generation,
                fence,
                TaskId::new("task-delivery-1").expect("valid task"),
                WorkUnitId::new("work-unit-delivery-1").expect("valid work unit"),
                "scope-delivery-1",
                "task-revision-1",
                "plan-delivery-1",
                "plan-revision-1",
            )
            .expect("valid activation result");
            let mut runner = BridgeRunner::new(
                Profile::SpineFunctional,
                ProviderReadiness::all_admitted(),
                Some(Box::new(StaticActivation { result })),
                None,
            )
            .expect("runner composes");
            runner
                .attach(AttachRequest::managed(
                    DemandId::new("demand-delivery-1").expect("valid demand"),
                    super::super::ConnectionId::new("conn-delivery-1").expect("valid connection"),
                ))
                .expect("managed attach admits");
            runner
        }

        fn projection_response(kind: ResponseKind, content: serde_json::Value) -> McpResponse {
            McpResponse {
                request_id: "req-delivery-1".to_owned(),
                idempotency_key: "idem-delivery-1".to_owned(),
                canonical_request_sha256: DIGEST_A.to_owned(),
                kind,
                canonical_tool_name: "eliot.state".to_owned(),
                content,
                artifacts: Vec::new(),
                proof_ceiling: ProofCeiling::Observation,
                resource: None,
                job: None,
            }
        }

        struct RespondedPort {
            response: McpResponse,
        }

        impl KernelHostRequestPort for RespondedPort {
            fn invoke(
                &mut self,
                _request: &HostInvocationRequest,
            ) -> Result<HostInvocationPortOutcome, PortFailure> {
                Ok(HostInvocationPortOutcome::Responded {
                    operation_handle: HostOperationHandle::new("kernel-operation-9")
                        .expect("valid handle"),
                    response: Box::new(self.response.clone()),
                })
            }

            fn cancel(
                &mut self,
                _request: &super::super::HostCancellationRequest,
            ) -> Result<super::HostCancellationPortOutcome, PortFailure> {
                Err(PortFailure::PlanGap {
                    missing_capability: "test.responded-port.cancel".to_owned(),
                    reason: "cancel not exercised".to_owned(),
                })
            }
        }

        fn invoke_request() -> HostInvocationRequest {
            let decoded = decode_bounded_request(super::INVOKE).expect("invoke must decode");
            match decoded {
                super::Request::Invoke { request } => request,
                _ => panic!("expected invoke"),
            }
        }

        fn large_content() -> serde_json::Value {
            serde_json::json!({"evidence": "x".repeat(4096)})
        }

        #[test]
        fn large_supported_tool_result_populates_registry_and_expands() {
            use eliot_agent_bridge::MAX_PREVIEW_BYTES;

            let mut runner = attached_runner();
            assert_eq!(runner.resource_registry_len(), 0);
            let request = invoke_request();
            let mut port = RespondedPort {
                response: projection_response(ResponseKind::Projection, large_content()),
            };
            // Exact production order: gateway dispatch, then delivery recording.
            let mut response = handle_invocation(&super::HostRequestGateway, &mut port, &request);
            record_invocation_delivery(&mut runner, &mut response);
            let super::Response::Invocation {
                result, evidence, ..
            } = &response
            else {
                panic!("invoke must answer an invocation envelope");
            };
            assert_eq!(result.correlation_id().as_str(), "host-request-1");
            assert!(
                evidence.is_some(),
                "large supported delivery must carry its recorded view"
            );
            // The response itself is forwarded exactly as the gateway shaped it.
            let value = serde_json::to_value(&response).expect("response must serialize");
            assert_eq!(
                value["status"],
                serde_json::Value::String("invocation".to_owned())
            );
            // The recorded handle rides the response: host-discoverable with
            // its immutable URI, digest, and bounded preview.
            let evidence = value
                .get("evidence")
                .expect("large supported delivery must project its handle");
            let uri = evidence["handle"]["uri"]
                .as_str()
                .expect("handle must carry its canonical URI");
            assert!(
                uri.starts_with("eliot://evidence/"),
                "evidence handle must be content-addressed, got {uri}"
            );
            let digest = evidence["handle"]["digest"]
                .as_str()
                .expect("handle must carry its content digest");
            assert_eq!(digest.len(), 64);
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "handle digest must stay lowercase SHA-256 hex"
            );
            // The real caller path populated the registry with one snapshot.
            assert_eq!(runner.resource_registry_len(), 1);
            let stored = serde_json::to_vec(&large_content()).expect("content serializes");
            assert!(stored.len() > MAX_PREVIEW_BYTES);
            // Recording the same delivered bytes again rebinds the same handle:
            // content-addressing is idempotent, never a second entry.
            let again = runner
                .record_tool_result_delivery(result.outcome())
                .expect("re-record rebinds");
            assert_eq!(runner.resource_registry_len(), 1);
            // Expansion retrieves the exact delivered bytes behind a bounded preview.
            assert!(again.preview().len() <= MAX_PREVIEW_BYTES);
            assert!(again.is_truncated());
            let expanded = runner
                .expand_resource(again.handle())
                .expect("expand resolves the issued handle");
            assert_eq!(expanded, stored);
            // Status projects the populated registry.
            let status = status_response(Profile::SpineFunctional, &runner);
            let status_value = serde_json::to_value(&status).expect("status must serialize");
            assert_eq!(
                status_value["resources"]["entries"],
                serde_json::Value::from(1)
            );
        }

        #[test]
        fn unsupported_small_and_failed_tool_results_record_nothing() {
            let mut runner = attached_runner();
            let request = invoke_request();
            // Unsupported kind carries no result semantics: nothing snapshotted.
            let mut unsupported = RespondedPort {
                response: projection_response(ResponseKind::Unsupported, large_content()),
            };
            let mut response =
                handle_invocation(&super::HostRequestGateway, &mut unsupported, &request);
            record_invocation_delivery(&mut runner, &mut response);
            assert_eq!(runner.resource_registry_len(), 0);
            let value = serde_json::to_value(&response).expect("response must serialize");
            assert!(
                value.get("evidence").is_none(),
                "unsupported delivery must not project a handle"
            );
            // Small inline content stays fully visible: nothing withheld, nothing stored.
            let mut small = RespondedPort {
                response: projection_response(
                    ResponseKind::Projection,
                    serde_json::json!({"ok": true}),
                ),
            };
            let mut response = handle_invocation(&super::HostRequestGateway, &mut small, &request);
            record_invocation_delivery(&mut runner, &mut response);
            assert_eq!(runner.resource_registry_len(), 0);
            let value = serde_json::to_value(&response).expect("response must serialize");
            assert!(
                value.get("evidence").is_none(),
                "small inline delivery must not project a handle"
            );
            // Rejected invocations carry no result: the error envelope records nothing.
            let mut unavailable = super::UnavailableKernelHostRequestPort;
            let mut response =
                handle_invocation(&super::HostRequestGateway, &mut unavailable, &request);
            record_invocation_delivery(&mut runner, &mut response);
            assert_eq!(runner.resource_registry_len(), 0);
        }

        #[test]
        fn detached_runner_records_nothing() {
            let mut runner = super::fixture_runner();
            let request = invoke_request();
            let mut port = RespondedPort {
                response: projection_response(ResponseKind::Projection, large_content()),
            };
            let mut response = handle_invocation(&super::HostRequestGateway, &mut port, &request);
            record_invocation_delivery(&mut runner, &mut response);
            assert_eq!(runner.resource_registry_len(), 0);
            let value = serde_json::to_value(&response).expect("response must serialize");
            assert!(
                value.get("evidence").is_none(),
                "detached recording must not project a handle"
            );
        }
    }

    /// C1 live-consumer proof: items admitted through the REAL production
    /// chain (hand batch → live Governor derivation → transport → ledger)
    /// are consumed by the REAL stdio ForwardHook dispatch step, and the
    /// issued receipts ride the Forwarded wire frame. Withheld items yield
    /// an empty Forwarded frame with no receipt key. No stub assessor, no
    /// stub ledger, no direct ledger calls: the only producer is the
    /// transport, the only consumer the extracted dispatch step.
    mod reactive_hook_consumer_tests {
        #![allow(clippy::expect_used)]

        use super::super::handle_forward_hook;
        use eliot_agent_bridge::{
            BridgeRunner, Profile, RiskTier, SettledPlanAdmission, governor_assess,
        };
        use eliot_agent_bridge_core::{
            ActivationPortOutcome, ActivationPortResult, AttachBinding, AttachRequest,
            CoverageGap, DemandId, EventEnvelope, EventPortOutcome, FencingToken, Generation,
            HostActivationPort, HostEventEnvelope, McpForwardingPort, PrincipalId,
            ProviderFailure, ProviderReadiness, ReconciliationPortOutcome, SessionId, TaskId,
            WorkUnitId,
        };
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use eliot_integration_coverage::{
            ALL_EVENTS, DispatchOrdering, EventCompleteness, EventCoverage, EventDisposition,
            GovernorCoverageDerivation, IntegrationCoverageProfile, LogicalEvent,
            TraceFreshness, WatchdogEvidence,
        };
        use eliot_reactive_context_plan::{
            BridgeAdmissionBatch, BridgeAdmissionDelivery, BridgeAdmissionInstruction,
            BridgeAdmissionSeverity,
        };
        use std::num::NonZeroU64;

        const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        const TEST_SESSION: &str = "session-consumer-1";
        const TEST_DIGEST: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        struct StaticActivation {
            result: ActivationPortResult,
        }

        impl HostActivationPort for StaticActivation {
            fn activate(
                &mut self,
                _request: &AttachRequest,
            ) -> Result<ActivationPortOutcome, ProviderFailure> {
                Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
            }
        }

        struct OkForwarder;

        impl McpForwardingPort for OkForwarder {
            fn forward_hook(
                &mut self,
                _binding: &AttachBinding,
                _event: &HostEventEnvelope,
            ) -> Result<(), ProviderFailure> {
                Ok(())
            }
            fn forward_event(
                &mut self,
                _binding: &AttachBinding,
                _event: &EventEnvelope,
            ) -> Result<EventPortOutcome, ProviderFailure> {
                Ok(EventPortOutcome::BestEffortForwarded)
            }
            fn forward_gap(
                &mut self,
                _binding: &AttachBinding,
                _gap: &CoverageGap,
            ) -> Result<(), ProviderFailure> {
                Err(ProviderFailure::new("test-forwarder", "gap not exercised"))
            }
            fn reconcile_external(
                &mut self,
                _binding: &AttachBinding,
            ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
                Err(ProviderFailure::new(
                    "test-forwarder",
                    "reconciliation not exercised",
                ))
            }
        }

        fn test_epoch(sequence: u64) -> EpochId {
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
                NonZeroU64::new(sequence).expect("nonzero test sequence"),
            )
            .expect("valid test epoch")
        }

        fn test_fence() -> StateFence {
            StateFence::new(
                test_epoch(3),
                ResourceGeneration::new(7).expect("non-zero test generation"),
            )
        }

        fn consumer_runner() -> BridgeRunner {
            let generation = Generation::new(7).expect("non-zero test generation");
            let fence = FencingToken::new(test_epoch(3), generation, "fence-consumer-7")
                .expect("valid test fence");
            let result = ActivationPortResult::authenticated(
                PrincipalId::new("principal-consumer-1").expect("valid principal"),
                SessionId::new(TEST_SESSION).expect("valid session"),
                generation,
                fence,
                TaskId::new("task-consumer-1").expect("valid task"),
                WorkUnitId::new("work-unit-consumer-1").expect("valid work unit"),
                "scope-consumer-1",
                "task-revision-1",
                "plan-consumer-1",
                "plan-revision-1",
            )
            .expect("valid activation result");
            let mut runner = BridgeRunner::new(
                Profile::SpineFunctional,
                ProviderReadiness::all_admitted(),
                Some(Box::new(StaticActivation { result })),
                Some(Box::new(OkForwarder)),
            )
            .expect("runner composes");
            runner
                .attach(AttachRequest::managed(
                    DemandId::new("demand-consumer-1").expect("valid demand"),
                    super::super::ConnectionId::new("conn-consumer-1")
                        .expect("valid connection"),
                ))
                .expect("managed attach admits");
            runner
        }

        fn hook_event(hook_id: &str) -> HostEventEnvelope {
            serde_json::from_value(serde_json::json!({
                "event_id": hook_id,
                "attempt_id": "attempt-consumer-1",
                "sequence": 1,
                "cursor": "cursor-consumer-1",
                "kind": "tool_result",
                "route": {
                    "host_family": "test",
                    "adapter": "test",
                    "protocol_transport": "stdio",
                    "runtime_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "adapter_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "provider": "provider",
                    "model": "model",
                    "auth_billing": "test",
                    "serializer_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tool_semantics_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "reasoning_mode": "test",
                    "continuation_behavior": "fresh",
                    "feature_flags_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                },
                "raw_payload_digest": "digest-consumer-1",
                "normalized_payload": {},
                "parent_event_id": null,
                "observed_at": "2026-09-21T00:00:00Z"
            }))
            .expect("valid hook fixture")
        }

        fn live_derivation() -> GovernorCoverageDerivation {
            let events: Vec<EventCoverage> = ALL_EVENTS
                .iter()
                .map(|event| EventCoverage {
                    event: *event,
                    disposition: if matches!(
                        event,
                        LogicalEvent::PreToolUse | LogicalEvent::PermissionRequest
                    ) {
                        EventDisposition::Enforced
                    } else {
                        EventDisposition::Observed
                    },
                    ordering: DispatchOrdering::PreDispatch,
                    completeness: EventCompleteness::Complete,
                    proof_ceiling: "test-ceiling".to_owned(),
                    source: "test-source".to_owned(),
                    gaps: Vec::new(),
                })
                .collect();
            let coverage = IntegrationCoverageProfile::candidate(
                "fingerprint-1",
                events,
                EventCompleteness::Complete,
                "test-ceiling",
                "test-source",
                Vec::new(),
            )
            .expect("candidate")
            .verify("fingerprint-1", true)
            .expect("verified");
            let mut derivation = GovernorCoverageDerivation::new();
            derivation
                .derive(
                    &coverage,
                    &WatchdogEvidence {
                        supervisor_id: "watchdog-1".to_owned(),
                        fresh: true,
                        summary: "test supervision".to_owned(),
                    },
                    TraceFreshness::Fresh,
                )
                .expect("derive");
            derivation
        }

        fn instruction(item_id: &str) -> BridgeAdmissionInstruction {
            BridgeAdmissionInstruction {
                cue_id: item_id.to_owned(),
                cue_source: "tool-surface-1".to_owned(),
                cue_source_revision: "rev-1".to_owned(),
                cue_digest: TEST_DIGEST.to_owned(),
                rule_id: "reactive-activation:plan-digest-1".to_owned(),
                relations: vec!["rel-a".to_owned()],
                scope_id: "scope-consumer-1".to_owned(),
                status: "EVENT_PLAN".to_owned(),
                governance_profile_rev: "policy-digest-1".to_owned(),
                fence: test_fence(),
                severity: BridgeAdmissionSeverity::Critical,
                delivery: BridgeAdmissionDelivery::HostHook,
                dedup_key: format!("plan-digest-1:{item_id}"),
                plan_item_id: item_id.to_owned(),
                plan_result_digest: "plan-digest-1".to_owned(),
                item_reason: "fixture reason".to_owned(),
                attention: None,
            }
        }

        fn batch(item_id: &str) -> BridgeAdmissionBatch {
            BridgeAdmissionBatch {
                session_id: eliot_contracts::SessionId::new(TEST_SESSION)
                    .expect("valid session"),
                scope_id: eliot_receipts::WorkScopeId::new("scope-consumer-1")
                    .expect("valid scope"),
                invalidations: Vec::new(),
                items: vec![instruction(item_id)],
                skipped_sticky: 0,
                skipped_ineligible: 0,
            }
        }

        #[test]
        fn admitted_item_rides_the_live_hook_frame_with_governor_receipt() {
            let mut runner = consumer_runner();
            let mut driver = SettledPlanAdmission::new();
            let derivation = live_derivation();
            // Production chain only: batch → live Governor assessment →
            // transport → ledger. No direct ledger calls.
            let report = driver
                .admit_batch(&mut runner, &batch("item-hook-1"), |item, critical| {
                    governor_assess(&derivation, item, critical)
                })
                .expect("live assessment admits");
            assert_eq!(report.admitted.len(), 1);
            assert!(report.withheld.is_empty());
            assert_eq!(runner.reactive_pending_count(), 1);
            // Live stdio consumer: the extracted ForwardHook dispatch step
            // drains the pending item through the real forwarded event.
            let event = hook_event("hook-consumer-1");
            let (response, provider_failed) = handle_forward_hook(&mut runner, &event);
            assert!(!provider_failed);
            let super::Response::Forwarded {
                reactive_receipts, ..
            } = &response
            else {
                panic!("hook consumer answers a forwarded envelope");
            };
            assert_eq!(reactive_receipts.len(), 1);
            let receipt = &reactive_receipts[0];
            assert_eq!(receipt.session_id, TEST_SESSION);
            assert_eq!(receipt.admission.risk, RiskTier::Severe);
            assert_eq!(
                receipt.admission.fence_epoch,
                format!("{TEST_LINEAGE}:3")
            );
            assert_eq!(receipt.admission.fence_generation, 7);
            assert_eq!(runner.reactive_pending_count(), 0);
            // The receipt rides the wire frame with the Governor tier.
            let value = serde_json::to_value(&response).expect("response must serialize");
            assert_eq!(
                value["status"],
                serde_json::Value::String("forwarded".to_owned())
            );
            let wire = value["reactive_receipts"]
                .as_array()
                .expect("receipts must list");
            assert_eq!(wire.len(), 1);
            assert_eq!(
                wire[0]["admission"]["risk"],
                serde_json::Value::String("SEVERE".to_owned())
            );
            assert_eq!(
                wire[0]["delivery"]["hook_id"],
                serde_json::Value::String("hook-consumer-1".to_owned())
            );
        }

        #[test]
        fn withheld_item_yields_an_empty_hook_frame() {
            let mut runner = consumer_runner();
            let mut driver = SettledPlanAdmission::new();
            // Nothing derived: the real assessment withholds, the ledger
            // stays empty, and the live consumer emits a receipt-less frame.
            let bare = GovernorCoverageDerivation::new();
            let report = driver
                .admit_batch(&mut runner, &batch("item-hook-2"), |item, critical| {
                    governor_assess(&bare, item, critical)
                })
                .expect("withhold is honest, not failure");
            assert!(report.admitted.is_empty());
            assert_eq!(report.withheld.len(), 1);
            let event = hook_event("hook-consumer-2");
            let (response, provider_failed) = handle_forward_hook(&mut runner, &event);
            assert!(!provider_failed);
            let value = serde_json::to_value(&response).expect("response must serialize");
            assert_eq!(
                value["status"],
                serde_json::Value::String("forwarded".to_owned())
            );
            assert!(
                value.get("reactive_receipts").is_none(),
                "no delivery means no receipt key on the wire"
            );
        }
    }
}
