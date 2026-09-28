#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use eliot_process::OperationId;
use eliot_user_broker::{
    BrokerComposition, BrokerConfig, CompositionError, HumanStateAuthority, NotifyAcknowledge,
    OperatorClientBinding, canonical_root, request_names_notify_image,
};
use eliot_user_broker_core::{
    CutoverReceipt, LaunchRequest, OPERATOR_HANDOFF_TTL_MS, OperatorEndpoint,
    OperatorHandoffRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PROVIDER_REJECTED_EXIT: i32 = 69;
const OPERATOR_PIPE_NAME: &str = r"\\.\pipe\eliot\user-broker\operator";
const OPERATOR_PIPE_PREFACE: &str = "ELIOT-BROKER-1\n";
const MAX_OPERATOR_PIPE_LINE_BYTES: usize = eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
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
    /// Admitted launch on a Kernel-authorized grant. The explicit
    /// authenticated Human authority is admitted before anything is
    /// dispatched: a missing principal, stale session token, cross-session
    /// identity, ungranted capability, or missing approval hash is refused
    /// before any state change.
    Launch {
        request: LaunchRequest,
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    /// Per-notification spawn of the canonical installed `eliot-notify.exe` on
    /// a Kernel-authorized grant. This is the ONLY operation that can start the
    /// notification adapter: the generic `Launch` operation refuses that image.
    NotifyLaunch {
        request: LaunchRequest,
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    /// Spawns the notification adapter to record one authenticated Human
    /// acknowledgement of one canonical notification (issue #1780, A2).
    ///
    /// This is the production initiator of the acknowledgement leg. It is a
    /// separate operation, not a flag on `NotifyLaunch`, because the two
    /// differ in what the child receives: delivery launches the adapter with
    /// no standard input, while this operation composes the exact
    /// acknowledgement line and hands it to the child (I11.6:7 — the broker is
    /// the only admitted spawner, and the broker composes what the adapter
    /// serves). A delivery request may not smuggle bytes onto this path; the
    /// composition refuses any caller-supplied `stdin_payload` and renders the
    /// line itself.
    ///
    /// The acknowledging act is a Human role action (I11.3:13) and the
    /// principal is record data, not authority: the transition is applied and
    /// re-validated on the admitted Kernel route inside the adapter, and the
    /// record stays unresolved (I11.7:5). The same `admit_human_state_change`
    /// and the same notify-image binding gate as delivery apply before
    /// anything is dispatched.
    ///
    /// The acknowledged record's identity travels as typed fields and never as
    /// caller bytes: the acknowledged principal is deliberately NOT a wire
    /// field here — [`NotifyAcknowledge`] names only the record — and the line
    /// the child reads is composed by this broker from the principal it
    /// admitted. `request.stdin_payload` on the inbound request is REPLACED by
    /// that line, and the generic `Launch` and `NotifyLaunch` operations both
    /// refuse a caller-supplied payload, so this is the only request shape
    /// that can put bytes on a Notify child's standard input.
    ///
    /// Acknowledgement suppresses repeated toast, not the problem: the record
    /// stays unresolved and a critical item stays on the board
    /// (I11.7:5-6), and the admitted Kernel route re-validates the transition
    /// before the store applies it.
    NotifyAcknowledge {
        request: LaunchRequest,
        acknowledgement: NotifyAcknowledge,
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    Cancel {
        operation_id: OperationId,
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    Reconcile {
        operation_id: OperationId,
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    /// Initial or reconnect handoff for the one-shot Operator child. The broker
    /// mints the nonce, the endpoint generation, and the expiry; this request
    /// may name only the role and capability set, and a reconnect is a fresh
    /// request rather than a replayed endpoint.
    OperatorHandoff {
        request: OperatorHandoffRequest,
    },
    /// Redemption is refused on stdin because this transport has no connected
    /// broker pipe from which to observe the OS client process. Redemption
    /// requires connected broker-pipe peer evidence before composition.
    RedeemOperatorHandoff {
        #[serde(rename = "endpoint")]
        _endpoint: OperatorEndpoint,
        #[serde(rename = "client")]
        _client: OperatorClientBinding,
    },
    /// Publication of the registration/cutover receipt for the broker
    /// generation transition this lineage performed (I14.17).
    ///
    /// The request carries only the authenticated Human authority. Both
    /// generations, both epochs, the transferred Session binding and the
    /// pre-cutover operation dispositions are read from the broker's own
    /// durable record, so no caller can name them. It is a durable state
    /// change and is admitted as one, against the live registration digest.
    ///
    /// It is never a completion signal: this broker cannot prove termination
    /// of the superseded generation's Job Object, so the candidate is not
    /// marked active and the transition is left for reconciliation.
    Cutover {
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    Status,
    Stop,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Message {
    Ready {
        readiness: Value,
    },
    Launched {
        receipt: Value,
    },
    Cancelled {
        receipt: Value,
    },
    Reconciled {
        view: Value,
    },
    /// One owner-issued, generation-bound, expiring, single-use handoff.
    OperatorHandoff {
        endpoint: Value,
    },
    Stopped,
    Error {
        code: &'static str,
        detail: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum OperatorPipeRequest {
    OperatorChallenge {
        endpoint: OperatorEndpoint,
    },
    RedeemOperatorHandoff {
        endpoint: OperatorEndpoint,
        client: OperatorClientBinding,
    },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OperatorPipeMessage {
    Challenge {
        kernel_session_token: String,
        broker_epoch: u64,
        handoff_nonce: String,
        role: String,
        capabilities: Vec<String>,
    },
    Redeemed {
        principal: String,
        interactive_session_id: String,
        client_process_id: u32,
        kernel_session_token: String,
        role: String,
        capabilities: Vec<String>,
    },
    Error {
        code: &'static str,
        detail: String,
    },
}

enum BrokerInput {
    Stdin(Result<String, String>),
    StdinClosed,
    OperatorPipe {
        request: Box<OperatorPipeRequest>,
        peer: Box<eliot_platform_windows::NamedPipePeerEvidence>,
        response: tokio::sync::oneshot::Sender<OperatorPipeMessage>,
    },
    OperatorPipeFailure(String),
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
    // Per-user bootstrap trigger for the optional Task Scheduler fallback:
    // best-effort and infallible by design, so fallback setup can never fail
    // broker startup. Absence skips explicitly; failure defers to the next
    // start. Normal User-Broker launch is unaffected. The outcome is folded
    // into the `Ready` diagnostic below (I11.7: a perpetually deferred
    // fallback stays visible); only stable state/reason codes cross that
    // boundary, never paths, digests, or payloads.
    let fallback = eliot_user_broker::ensure_notify_fallback_registered(
        &eliot_user_broker::LiveNotifyFallbackEffects,
    );
    let fallback_status = fallback.status_value();
    // Normal-launch staging for the installer-published Notify declaration:
    // best-effort and infallible by design, so staging can never fail broker
    // startup. The verified launch reference is RETAINED by the composition —
    // `staged` means this broker verified it can name the exact installed
    // `eliot-notify.exe` and holds the authority to spawn exactly that image on
    // a Kernel-authorized notify grant through `composition.launch_notify`.
    composition.stage_notify_launch();
    let notify_launch_status = composition.notify_launch_authority().status_value();
    let mut readiness = serde_json::to_value(composition.readiness())
        .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()}));
    if let Value::Object(map) = &mut readiness {
        map.insert("notify_fallback".to_owned(), fallback_status.clone());
        map.insert("notify_launch".to_owned(), notify_launch_status.clone());
    }
    let (sender, receiver) = mpsc::channel::<BrokerInput>();
    if let Err(error) = start_operator_pipe_server(sender.clone()) {
        exit(
            PROVIDER_REJECTED_EXIT,
            "BROKER_OPERATOR_PIPE_REJECTED",
            error,
        );
    }
    if !write_message(&Message::Ready { readiness }) {
        return;
    }
    // Keep stdin as an admitted-role operation stream while the composition
    // owner retains the only authority-bearing state.  A reader thread lets
    // the owner service the authenticated heartbeat timer even when no input
    // arrives; register/heartbeat identities are never accepted from stdin.
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let line = line.map_err(|error| error.to_string());
            if sender.send(BrokerInput::Stdin(line)).is_err() {
                break;
            }
        }
        let _ = sender.send(BrokerInput::StdinClosed);
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
        let input = match receiver.recv_timeout(timeout) {
            Ok(input) => input,
            Err(RecvTimeoutError::Timeout) => {
                if let Err(error) = composition.heartbeat() {
                    heartbeat_failure(composition, error.to_string());
                }
                next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let response = match input {
            BrokerInput::Stdin(Ok(line)) if line.trim().is_empty() => continue,
            BrokerInput::Stdin(Ok(line)) => dispatch(
                &mut composition,
                &line,
                &fallback_status,
                &notify_launch_status,
            ),
            BrokerInput::Stdin(Err(error)) => Message::Error {
                code: "INPUT_FAILURE",
                detail: error,
            },
            BrokerInput::StdinClosed => break,
            BrokerInput::OperatorPipe {
                request,
                peer,
                response,
            } => {
                let _ = response.send(dispatch_operator_pipe(&mut composition, *request, &peer));
                continue;
            }
            BrokerInput::OperatorPipeFailure(error) => exit(
                PROVIDER_REJECTED_EXIT,
                "BROKER_OPERATOR_PIPE_FAILURE",
                error,
            ),
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
    // fence.  The composition is deliberately NOT dropped here: since #1889
    // this broker generation owns a kill-on-close Job Object that contains
    // this very process, so dropping it would terminate the broker inside
    // `drop` and the `BROKER_HEARTBEAT_REJECTED` diagnostic below would never
    // be written.  `std::process::exit` does not run destructors, so the
    // kill-on-close contour and every other handle are released by process
    // teardown after the diagnostic is flushed, and the durable
    // Active/Unknown snapshot remains for the next authenticated startup
    // heartbeat/reconciliation pass either way.
    let _composition = composition;
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

fn dispatch(
    composition: &mut BrokerComposition,
    line: &str,
    fallback_status: &Value,
    notify_launch_status: &Value,
) -> Message {
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
        Request::Launch { request, authority } => {
            // I11.6:3: normal `eliot-notify` delivery is launched through the
            // authorized User Broker's notify-specific admitted path. A generic
            // launch naming the canonical notify image is refused here, so no
            // other request shape can produce a normal notification invocation.
            if request_names_notify_image(&request) {
                return Message::Error {
                    code: "BROKER_NOTIFY_LAUNCH_REQUIRES_ADMISSION",
                    detail: "the canonical notify image is only launchable through the admitted notify operation"
                        .to_owned(),
                };
            }
            let operation_key = request.approved.idempotency_key.clone();
            match composition.admit_human_state_change(authority.as_ref(), &operation_key) {
                Err(error) => composition_rejection(&error),
                Ok(()) => dispatch_launch(composition.launch(request)),
            }
        }
        Request::NotifyLaunch { request, authority } => {
            let operation_key = request.approved.idempotency_key.clone();
            match composition.admit_human_state_change(authority.as_ref(), &operation_key) {
                Err(error) => composition_rejection(&error),
                Ok(()) => dispatch_launch(composition.launch_notify(request)),
            }
        }
        Request::NotifyAcknowledge {
            request,
            acknowledgement,
            authority,
        } => {
            // I11.3:13 — the acknowledging act belongs to an authorized Human
            // role, so the authenticated Human authority is admitted here
            // exactly as it is for delivery and before anything is dispatched.
            // The generic `Launch` refusal is unnecessary: this arm already
            // requires the notify image, which `launch_notify_acknowledge`
            // re-proves against the broker's retained verified bytes.
            let operation_key = request.approved.idempotency_key.clone();
            match admit_authenticated_human(composition, authority.as_ref(), &operation_key) {
                Err(message) => message,
                Ok(principal) => dispatch_launch(
                    composition.launch_notify_acknowledge(request, &acknowledgement, &principal),
                ),
            }
        }
        Request::Cancel {
            operation_id,
            authority,
        } => {
            match composition.admit_human_state_change(authority.as_ref(), operation_id.as_str()) {
                Err(error) => composition_rejection(&error),
                Ok(()) => composition.cancel(&operation_id).map_or_else(
                    |error| composition_rejection(&error),
                    |receipt| Message::Cancelled {
                        receipt: serde_json::to_value(receipt).unwrap_or_else(
                            |error| serde_json::json!({"error": error.to_string()}),
                        ),
                    },
                ),
            }
        }
        Request::Reconcile {
            operation_id,
            authority,
        } => {
            match composition.admit_human_state_change(authority.as_ref(), operation_id.as_str()) {
                Err(error) => composition_rejection(&error),
                Ok(()) => composition.reconcile(&operation_id).map_or_else(
                    |error| composition_rejection(&error),
                    |view| Message::Reconciled {
                        view: serde_json::to_value(view).unwrap_or_else(
                            |error| serde_json::json!({"error": error.to_string()}),
                        ),
                    },
                ),
            }
        }
        Request::OperatorHandoff { request } => {
            dispatch_admitted_handoff(composition.admit_operator_handoff(&request))
        }
        Request::RedeemOperatorHandoff { .. } => Message::Error {
            code: eliot_user_broker::BrokerAdmissionRefusal::OperatorClientProcessForeign.code(),
            detail: "stdin has no OS-observed peer process; redemption requires authenticated broker-pipe peer evidence"
                .to_owned(),
        },
        Request::Cutover { authority } => {
            dispatch_cutover(composition.publish_cutover_receipt(authority.as_ref()))
        }
        Request::Status => {
            let mut readiness = serde_json::to_value(composition.readiness())
                .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()}));
            if let Value::Object(map) = &mut readiness {
                map.insert("notify_fallback".to_owned(), fallback_status.clone());
                map.insert("notify_launch".to_owned(), notify_launch_status.clone());
            }
            Message::Ready { readiness }
        }
        Request::Stop => Message::Stopped,
    }
}

fn dispatch_operator_pipe(
    composition: &mut BrokerComposition,
    request: OperatorPipeRequest,
    peer: &eliot_platform_windows::NamedPipePeerEvidence,
) -> OperatorPipeMessage {
    match request {
        OperatorPipeRequest::OperatorChallenge { endpoint } => composition
            .challenge_operator_handoff(&endpoint, peer)
            .map_or_else(
                |error| operator_pipe_rejection(&error),
                |kernel_session_token| OperatorPipeMessage::Challenge {
                    kernel_session_token,
                    broker_epoch: endpoint.broker_epoch,
                    handoff_nonce: endpoint.handoff_nonce,
                    role: endpoint.role,
                    capabilities: endpoint.capabilities,
                },
            ),
        OperatorPipeRequest::RedeemOperatorHandoff { endpoint, client } => composition
            .redeem_operator_handoff(&endpoint, &client, peer)
            .map_or_else(
                |error| operator_pipe_rejection(&error),
                |_| OperatorPipeMessage::Redeemed {
                    principal: peer.sid().to_owned(),
                    interactive_session_id: peer.session_id().to_string(),
                    client_process_id: peer.process().process_id,
                    kernel_session_token: client.kernel_session_token,
                    role: endpoint.role,
                    capabilities: endpoint.capabilities,
                },
            ),
    }
}

/// Admits one state-changing request and returns the authenticated Human
/// principal it was admitted for.
///
/// The returned principal is the identity [`BrokerComposition::admit_human_state_change`]
/// proved against the live registration, so a canonical record that names it
/// names the admitted Human and never caller-supplied text. A request with no
/// authority at all is refused here with the same stable code the composition
/// itself uses, so the wire behaviour is identical to the composition's.
fn admit_authenticated_human(
    composition: &mut BrokerComposition,
    authority: Option<&HumanStateAuthority>,
    operation_key: &str,
) -> Result<String, Message> {
    let Some(authority) = authority else {
        return Err(Message::Error {
            code: eliot_user_broker::BrokerAdmissionRefusal::HumanPrincipalRequired.code(),
            detail: "state-changing request carries no authenticated Human principal".to_owned(),
        });
    };
    composition
        .admit_human_state_change(Some(authority), operation_key)
        .map_err(|error| composition_rejection(&error))?;
    Ok(authority.principal.clone())
}

fn operator_pipe_rejection(error: &CompositionError) -> OperatorPipeMessage {
    match error {
        CompositionError::Admission { refusal, .. } => OperatorPipeMessage::Error {
            code: refusal.code(),
            detail: error.to_string(),
        },
        other => OperatorPipeMessage::Error {
            code: "BROKER_COMPOSITION_REJECTED",
            detail: other.to_string(),
        },
    }
}

fn composition_error(detail: String) -> Message {
    Message::Error {
        code: "BROKER_COMPOSITION_REJECTED",
        detail,
    }
}

/// Projects one composition failure onto the wire without collapsing the
/// broker's own admission refusals into the generic composition code: each
/// refusal keeps its exact stable cause and only its adapter detail is
/// rendered as text.
fn composition_rejection(error: &eliot_user_broker::CompositionError) -> Message {
    match error {
        eliot_user_broker::CompositionError::Admission { refusal, .. } => Message::Error {
            code: refusal.code(),
            detail: error.to_string(),
        },
        other => composition_error(other.to_string()),
    }
}

/// Projects one admitted launch outcome onto the wire, validating the exact
/// operator receipt binding before it leaves the broker.
fn dispatch_launch(
    outcome: Result<eliot_user_broker_core::LaunchReceipt, eliot_user_broker::CompositionError>,
) -> Message {
    match outcome {
        Err(error) => composition_rejection(&error),
        Ok(receipt) => {
            let projection = receipt.operator_receipt();
            match projection.validate() {
                Err(error) => Message::Error {
                    code: "BROKER_RECEIPT_BINDING_REJECTED",
                    detail: error.to_string(),
                },
                Ok(()) => match serde_json::to_value(projection) {
                    Ok(receipt) => Message::Launched { receipt },
                    Err(error) => Message::Error {
                        code: "BROKER_RECEIPT_ENCODING",
                        detail: error.to_string(),
                    },
                },
            }
        }
    }
}

/// Projects one cutover publication onto the wire.
///
/// There is no success message for this request. The receipt's Job Object
/// termination state has exactly one inhabitant — the superseded generation's
/// Job Object identity is a Kernel/N4 contour this broker never infers and the
/// process executor never returns, so no termination of it is observable from
/// here — so publication can only ever end in the typed reconciliation refusal
/// that `composition_rejection` renders.
///
/// The `Ok` arm is projected as an explicit non-completion carrying the
/// receipt's own reason, never as a success: a receipt that cannot claim a
/// completed cutover must not be able to say that it did, and an operator
/// reading the wire has to be able to tell a stopped cutover from a finished
/// one without inspecting the composition.
fn dispatch_cutover(
    outcome: Result<CutoverReceipt, eliot_user_broker::CompositionError>,
) -> Message {
    match outcome {
        Err(error) => composition_rejection(&error),
        Ok(receipt) => Message::Error {
            code: "BROKER_CUTOVER_NOT_COMPLETED",
            detail: format!(
                "cutover receipt published without a proven Job Object termination: {}",
                receipt.old_job_object_termination.reason()
            ),
        },
    }
}

/// Validates one handoff value against its owner contract and encodes it.
fn encode_handoff<T: Serialize>(
    validated: Result<(), eliot_user_broker_core::BrokerError>,
    value: T,
) -> Result<Value, Message> {
    validated.map_err(|error| Message::Error {
        code: "BROKER_HANDOFF_BINDING_REJECTED",
        detail: error.to_string(),
    })?;
    serde_json::to_value(value).map_err(|error| Message::Error {
        code: "BROKER_RECEIPT_ENCODING",
        detail: error.to_string(),
    })
}

/// Projects one admitted handoff issuance onto the wire.
///
/// An issued endpoint carries no bearer credential and no filesystem auth
/// reference. It is validated by its owner contract before it leaves the
/// broker. A refusal keeps its own stable code; it is never folded into the
/// generic composition code.
fn dispatch_admitted_handoff(
    outcome: Result<OperatorEndpoint, eliot_user_broker::CompositionError>,
) -> Message {
    match outcome {
        Err(error) => composition_rejection(&error),
        Ok(endpoint) => match encode_handoff(endpoint.validate(), endpoint) {
            Ok(endpoint) => Message::OperatorHandoff { endpoint },
            Err(message) => message,
        },
    }
}

#[cfg(windows)]
fn start_operator_pipe_server(sender: mpsc::Sender<BrokerInput>) -> Result<(), String> {
    let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|error| error.to_string())?;
    let allowed_sid = expectation.expected_sid().to_owned();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let failure_sender = sender.clone();
    std::thread::Builder::new()
        .name("eliot-user-broker-operator-pipe".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let detail = format!("Operator pipe runtime initialization failed: {error}");
                    let _ = ready_sender.send(Err(detail.clone()));
                    let _ = failure_sender.send(BrokerInput::OperatorPipeFailure(detail));
                    return;
                }
            };
            let result = runtime.block_on(operator_pipe_server_loop(
                sender,
                allowed_sid,
                expectation,
                Some(ready_sender),
            ));
            if let Err(error) = result {
                let _ = failure_sender.send(BrokerInput::OperatorPipeFailure(error));
            }
        })
        .map_err(|error| format!("could not start Operator pipe thread: {error}"))?;
    match ready_receiver.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(format!("Operator pipe startup ended before bind: {error}")),
    }
}

#[cfg(not(windows))]
fn start_operator_pipe_server(_sender: mpsc::Sender<BrokerInput>) -> Result<(), String> {
    Err("the authenticated Operator pipe is available only on Windows".to_owned())
}

#[cfg(windows)]
async fn operator_pipe_server_loop(
    sender: mpsc::Sender<BrokerInput>,
    allowed_sid: String,
    expectation: eliot_platform_windows::NamedPipePeerExpectation,
    mut ready_sender: Option<mpsc::SyncSender<Result<(), String>>>,
) -> Result<(), String> {
    use std::os::windows::io::AsHandle;
    use tokio::io::AsyncReadExt;

    let mut server =
        eliot_windows_ipc::create_current_user_server(OPERATOR_PIPE_NAME, &allowed_sid, true)
            .map_err(|error| format!("could not bind authenticated Operator pipe: {error}"))?;
    if let Some(ready_sender) = ready_sender.take() {
        let _ = ready_sender.send(Ok(()));
    }
    loop {
        server
            .connect()
            .await
            .map_err(|error| format!("Operator pipe connection failed: {error}"))?;
        // Keep the broker's first pipe instance open while creating its
        // successor. A gap with no broker-owned instance would let another
        // same-user process pre-create the public name before the next bind.
        let next_server =
            eliot_windows_ipc::create_current_user_server(OPERATOR_PIPE_NAME, &allowed_sid, false)
                .map_err(|error| format!("could not retain Operator pipe ownership: {error}"))?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(OPERATOR_HANDOFF_TTL_MS);
        let mut preface = vec![0_u8; OPERATOR_PIPE_PREFACE.len()];
        let preface_read = tokio::time::timeout_at(deadline, server.read_exact(&mut preface)).await;
        if !matches!(preface_read, Ok(Ok(_)))
            || preface.as_slice() != OPERATOR_PIPE_PREFACE.as_bytes()
        {
            server = next_server;
            continue;
        }
        let Ok(peer) = eliot_platform_windows::authenticate_named_pipe_client(
            server.as_handle(),
            &expectation,
        ) else {
            server = next_server;
            continue;
        };
        let _ = tokio::time::timeout_at(
            deadline,
            serve_operator_pipe_connection(server, peer, &sender),
        )
        .await;
        server = next_server;
    }
}

#[cfg(windows)]
async fn serve_operator_pipe_connection(
    server: tokio::net::windows::named_pipe::NamedPipeServer,
    peer: eliot_platform_windows::NamedPipePeerEvidence,
    sender: &mpsc::Sender<BrokerInput>,
) -> io::Result<()> {
    use tokio::io::BufReader;

    let (reader, mut writer) = tokio::io::split(server);
    let mut reader = BufReader::with_capacity(4096, reader);

    let Some(first_line) = read_operator_pipe_line(&mut reader).await? else {
        return Ok(());
    };
    let first_request = match serde_json::from_str::<OperatorPipeRequest>(&first_line) {
        Ok(request) => request,
        Err(error) => {
            write_operator_pipe_message(
                &mut writer,
                &OperatorPipeMessage::Error {
                    code: "REQUEST_INVALID",
                    detail: error.to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    if !matches!(
        &first_request,
        OperatorPipeRequest::OperatorChallenge { .. }
    ) {
        write_operator_pipe_message(
            &mut writer,
            &OperatorPipeMessage::Error {
                code: "BROKER_PROTOCOL_SEQUENCE_REJECTED",
                detail: "the first Operator pipe request must be operator_challenge".to_owned(),
            },
        )
        .await?;
        return Ok(());
    }
    let first_response = dispatch_operator_pipe_to_owner(sender, first_request, &peer).await;
    let challenged = matches!(&first_response, OperatorPipeMessage::Challenge { .. });
    write_operator_pipe_message(&mut writer, &first_response).await?;
    if !challenged {
        return Ok(());
    }

    let Some(second_line) = read_operator_pipe_line(&mut reader).await? else {
        return Ok(());
    };
    let second_request = match serde_json::from_str::<OperatorPipeRequest>(&second_line) {
        Ok(request) => request,
        Err(error) => {
            write_operator_pipe_message(
                &mut writer,
                &OperatorPipeMessage::Error {
                    code: "REQUEST_INVALID",
                    detail: error.to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    if !matches!(
        &second_request,
        OperatorPipeRequest::RedeemOperatorHandoff { .. }
    ) {
        write_operator_pipe_message(
            &mut writer,
            &OperatorPipeMessage::Error {
                code: "BROKER_PROTOCOL_SEQUENCE_REJECTED",
                detail: "the second Operator pipe request must be redeem_operator_handoff"
                    .to_owned(),
            },
        )
        .await?;
        return Ok(());
    }
    let second_response = dispatch_operator_pipe_to_owner(sender, second_request, &peer).await;
    write_operator_pipe_message(&mut writer, &second_response).await
}

#[cfg(windows)]
async fn dispatch_operator_pipe_to_owner(
    sender: &mpsc::Sender<BrokerInput>,
    request: OperatorPipeRequest,
    peer: &eliot_platform_windows::NamedPipePeerEvidence,
) -> OperatorPipeMessage {
    let (response, receiver) = tokio::sync::oneshot::channel();
    if sender
        .send(BrokerInput::OperatorPipe {
            request: Box::new(request),
            peer: Box::new(peer.clone()),
            response,
        })
        .is_err()
    {
        return OperatorPipeMessage::Error {
            code: "BROKER_OWNER_UNAVAILABLE",
            detail: "the broker composition owner is no longer available".to_owned(),
        };
    }
    receiver
        .await
        .unwrap_or_else(|_| OperatorPipeMessage::Error {
            code: "BROKER_OWNER_UNAVAILABLE",
            detail: "the broker composition owner ended without a response".to_owned(),
        })
}

#[cfg(windows)]
async fn read_operator_pipe_line<R>(reader: &mut R) -> io::Result<Option<String>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Operator pipe closed before line terminator",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(count) > MAX_OPERATOR_PIPE_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Operator pipe line exceeds the configured frame limit",
            ));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            break;
        }
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(windows)]
async fn write_operator_pipe_message<W>(
    writer: &mut W,
    message: &OperatorPipeMessage,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let bytes = serde_json::to_vec(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(&bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
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
