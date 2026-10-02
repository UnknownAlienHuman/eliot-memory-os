#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use eliot_process::OperationId;
use eliot_user_broker::{
    BrokerAdmissionRefusal, BrokerComposition, BrokerConfig, CompositionError, HumanStateAuthority,
    NotifyAcknowledge, NotifyDeliver, OperatorClientBinding, canonical_root,
    request_names_notify_image,
};
// There is exactly one operator pipe name. The minted `OperatorEndpoint` and
// the pipe the broker serves are the same name, owned by the handoff contract
// crate that also validates it; a second literal here would mint endpoints
// naming a pipe nobody serves.
use eliot_user_broker_core::{
    CutoverReceipt, LaunchRequest, OPERATOR_HANDOFF_TTL_MS, OPERATOR_PIPE_NAME, OperatorEndpoint,
    OperatorHandoffRequest, OperatorNativeResourceSelectionInput,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PROVIDER_REJECTED_EXIT: i32 = 69;
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
        /// Explicit authenticated Human-selected root/object candidate. The
        /// broker measures it before Kernel authorization; this path pair is
        /// never included in the Kernel request or child launch.
        #[serde(default)]
        resource_selection: Option<OperatorNativeResourceSelectionInput>,
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
    /// Spawns the canonical installed `eliot-notify.exe` to deliver one
    /// canonical notification as a native toast on a Kernel-authorized grant
    /// (issue #1781, W2/A1).
    ///
    /// This is the production initiator of the delivery leg. It is a separate
    /// operation, not a flag on `NotifyLaunch`, because the two differ in what
    /// the child receives: `NotifyLaunch` stages and admits the spawn with no
    /// standard input, while this operation composes the exact delivery line
    /// and hands it to the child (I11.6:7 — the broker is the only admitted
    /// spawner, and the broker composes what the adapter serves). The delivery
    /// content travels as typed fields and never as caller bytes: [`NotifyDeliver`]
    /// names the canonical envelope plus its binding request, and the line the
    /// child reads is composed by this broker. A `stdin_payload` on the
    /// inbound request is refused by the notify admission gate before anything
    /// is dispatched, and the payload this request is finally launched with is
    /// the broker's own rendered line. The delivery itself is applied and
    /// re-validated on the admitted Kernel-backed route inside the adapter.
    NotifyDeliver {
        request: LaunchRequest,
        delivery: NotifyDeliver,
        #[serde(default)]
        authority: Option<HumanStateAuthority>,
    },
    /// Spawns the notification adapter to record one authenticated Human
    /// acknowledgement of one canonical notification (issue #1780, A2).
    ///
    /// This is the production initiator of the acknowledgement leg. It is a
    /// separate operation, not a flag on `NotifyLaunch`, because the two
    /// differ in what the child receives: `NotifyLaunch` stages and admits the
    /// spawn with no standard input, while this operation composes the exact
    /// acknowledgement line and hands it to the child (I11.6:7 — the broker is
    /// the only admitted spawner, and the broker composes what the adapter
    /// serves; the delivery leg carries its own broker-composed line through
    /// `NotifyDeliver`). A delivery request may not smuggle bytes onto this path; the
    /// composition refuses any caller-supplied `stdin_payload` and renders the
    /// line itself.
    ///
    /// The acknowledging act is a Human role action (I11.3:13) and the
    /// principal is record data, not authority: the admitted triple is
    /// validated but no child is spawned and no canonical write is performed
    /// here — the transition is owned by `eliotd` (issue #1780, A2) — and the
    /// record stays unresolved (I11.7:5). The same `admit_human_state_change`
    /// and the same notify-image binding gate as delivery apply before
    /// anything is answered.
    ///
    /// The acknowledged record's identity travels as typed fields and never as
    /// caller bytes: the acknowledged principal is deliberately NOT a wire
    /// field here — [`NotifyAcknowledge`] names only the record — and the line
    /// the child reads is composed by this broker from the principal it
    /// admitted. A `stdin_payload` on the inbound request is refused by the
    /// notify admission gate before anything is dispatched, and the payload
    /// this request is finally launched with is the broker's own rendered line.
    /// Together with the generic `Launch` operation refusing the notify image
    /// at all, this makes the acknowledgement the only request shape that can
    /// put bytes on a Notify child's standard input.
    ///
    /// Acknowledgement suppresses repeated toast, not the problem: the record
    /// stays unresolved and a critical item stays on the board
    /// (I11.7:5-6). The admitted triple is answered here with an explicit
    /// non-completion until the acknowledgement intake lane forwards it to
    /// the owning `eliotd` route; no launch receipt is issued for a write
    /// this broker cannot perform.
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

/// The one Operator binding this broker process has actually redeemed for a
/// connected, OS-authenticated pipe peer, retained for the lifetime of this
/// process and for nothing longer.
///
/// Every value here is read back from the redemption this broker performed; none
/// is declared by the caller and none is composed:
///
/// * `principal` and `interactive_session_id` are the sealed
///   `NamedPipePeerEvidence` values the pipe server obtained from the live
///   connection with `GetNamedPipeClientProcessId` (and the peer-token SID /
///   logon Session), never the PID/SID/Session tuple the client wrote into its
///   request;
/// * `kernel_session_token` is the value the client presented, which
///   `redeem_operator_handoff` has just proved equal to the fresh, short-lived
///   Kernel-issued token of this exact binding, inside that token's own lease;
/// * `role` and `capabilities` are the granted set, which the same call proved
///   equal to the issued endpoint's requested set;
/// * `handoff_nonce` names the retained `OperatorSessionBinding` row inside the
///   composition, so the authority a state-changing arm consumes is built from
///   the binding this redemption created and not from request text.
///
/// This value lives in one broker process's memory. Nothing restores it on
/// start-up, so a restarted UI — which cannot present a nonce this process
/// never issued — has no retained binding and every state-changing arm refuses
/// until a fresh challenge/redemption happens on a live connection.
struct RedeemedOperatorBinding {
    handoff_nonce: String,
    principal: String,
    interactive_session_id: String,
    kernel_session_token: String,
    role: String,
    capabilities: Vec<String>,
}

impl RedeemedOperatorBinding {
    /// Reads the retained record back from one completed redemption, using the
    /// OS-observed peer evidence the pipe server sealed for that connection.
    fn read_back(
        endpoint: &OperatorEndpoint,
        client: &OperatorClientBinding,
        peer: &eliot_platform_windows::NamedPipePeerEvidence,
    ) -> Self {
        Self {
            handoff_nonce: endpoint.handoff_nonce.clone(),
            principal: peer.sid().to_owned(),
            interactive_session_id: peer.session_id().to_string(),
            kernel_session_token: client.kernel_session_token.clone(),
            role: endpoint.role.clone(),
            capabilities: endpoint.capabilities.clone(),
        }
    }
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
    // The retained Operator binding of THIS process, and nothing else. It
    // starts empty on every start, is written only by a redemption that the
    // composition admitted against an OS-observed peer, and is superseded (never
    // merged, never reloaded) by the next redemption. There is no cache and no
    // durable form: a broker restart discards it, so a restarted UI has to earn
    // a fresh binding before any state-changing arm can be admitted.
    let mut redeemed_binding: Option<RedeemedOperatorBinding> = None;
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
                redeemed_binding.as_ref(),
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
                let answered = dispatch_operator_pipe(
                    &mut composition,
                    *request,
                    &peer,
                    &mut redeemed_binding,
                );
                let _ = response.send(answered);
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

/// Dispatches one broker-admitted notify delivery.
///
/// The arm body lives here rather than inline so `dispatch` keeps its line
/// budget: admit the Human state change, then launch the broker-composed
/// delivery line through `launch_notify_deliver`.
fn dispatch_notify_deliver(
    composition: &mut BrokerComposition,
    request: LaunchRequest,
    delivery: &NotifyDeliver,
    authority: Option<&HumanStateAuthority>,
    redeemed: Option<&RedeemedOperatorBinding>,
) -> Message {
    let operation_key = request.approved.idempotency_key.clone();
    match admit_retained_human(composition, redeemed, authority, &operation_key) {
        Err(message) => message,
        Ok(_) => dispatch_launch(composition.launch_notify_deliver(request, delivery)),
    }
}

/// Parses one inbound broker request line.
///
/// A malformed line is a stable `REQUEST_INVALID` error, never a dispatch.
fn parse_request(line: &str) -> Result<Request, Message> {
    serde_json::from_str::<Request>(line).map_err(|error| Message::Error {
        code: "REQUEST_INVALID",
        detail: error.to_string(),
    })
}

fn dispatch(
    composition: &mut BrokerComposition,
    line: &str,
    fallback_status: &Value,
    notify_launch_status: &Value,
    redeemed: Option<&RedeemedOperatorBinding>,
) -> Message {
    let request = match parse_request(line) {
        Ok(request) => request,
        Err(message) => return message,
    };
    match request {
        Request::OperatorHandoff { request } => {
            dispatch_admitted_handoff(composition.admit_operator_handoff(&request))
        }
        Request::RedeemOperatorHandoff { .. } => Message::Error {
            code: BrokerAdmissionRefusal::OperatorClientProcessForeign.code(),
            detail: "stdin has no OS-observed peer process; redemption requires authenticated broker-pipe peer evidence"
                .to_owned(),
        },
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
        state_change => dispatch_state_change(composition, state_change, redeemed),
    }
}

/// Dispatches one state-changing request shape under the retained Human
/// authority.
///
/// `dispatch` routes every shape that changes broker state here, and each arm
/// keeps its own `admit_retained_human` / `retained_state_authority` call, so
/// the admission happens before that arm dispatches anything. The arms are the
/// ones `dispatch` used to hold inline, unchanged.
fn dispatch_state_change(
    composition: &mut BrokerComposition,
    request: Request,
    redeemed: Option<&RedeemedOperatorBinding>,
) -> Message {
    match request {
        Request::Launch {
            request,
            resource_selection,
            authority,
        } => dispatch_generic_launch(
            composition,
            request,
            resource_selection,
            authority.as_ref(),
            redeemed,
        ),
        Request::NotifyLaunch { request, authority } => {
            let operation_key = request.approved.idempotency_key.clone();
            match admit_retained_human(composition, redeemed, authority.as_ref(), &operation_key) {
                Err(message) => message,
                Ok(_) => dispatch_launch(composition.launch_notify(request)),
            }
        }
        Request::NotifyDeliver {
            request,
            delivery,
            authority,
        } => dispatch_notify_deliver(
            composition,
            request,
            &delivery,
            authority.as_ref(),
            redeemed,
        ),
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
            match admit_retained_human(composition, redeemed, authority.as_ref(), &operation_key) {
                Err(message) => message,
                Ok(principal) => dispatch_launch(composition.launch_notify_acknowledge(
                    &request,
                    &acknowledgement,
                    &principal,
                )),
            }
        }
        Request::Cancel {
            operation_id,
            authority,
        } => {
            match admit_retained_human(
                composition,
                redeemed,
                authority.as_ref(),
                operation_id.as_str(),
            ) {
                Err(message) => message,
                Ok(_) => composition.cancel(&operation_id).map_or_else(
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
            match admit_retained_human(
                composition,
                redeemed,
                authority.as_ref(),
                operation_id.as_str(),
            ) {
                Err(message) => message,
                Ok(_) => composition.reconcile(&operation_id).map_or_else(
                    |error| composition_rejection(&error),
                    |view| Message::Reconciled {
                        view: serde_json::to_value(view).unwrap_or_else(
                            |error| serde_json::json!({"error": error.to_string()}),
                        ),
                    },
                ),
            }
        }
        // The publication admits the same retained authority as every other
        // state-changing arm; `publish_cutover_receipt` re-admits it against the
        // live registration digest itself, so only the authority is built here.
        Request::Cutover { authority } => {
            match retained_state_authority(composition, redeemed, authority.as_ref()) {
                Err(message) => message,
                Ok(retained) => {
                    dispatch_cutover(composition.publish_cutover_receipt(Some(&retained)))
                }
            }
        }
        // Unreachable by construction: `dispatch` routes only the
        // state-changing shapes here and `Request` is a closed enum. It is
        // refused rather than panicked so a shape this broker does not admit can
        // never be answered as if it had been.
        _ => Message::Error {
            code: "REQUEST_INVALID",
            detail: "this broker admits no state change for this request shape".to_owned(),
        },
    }
}

fn dispatch_generic_launch(
    composition: &mut BrokerComposition,
    request: LaunchRequest,
    resource_selection: Option<OperatorNativeResourceSelectionInput>,
    authority: Option<&HumanStateAuthority>,
    redeemed: Option<&RedeemedOperatorBinding>,
) -> Message {
    // I11.6:3: normal `eliot-notify` delivery is launched through the
    // authorized User Broker's notify-specific admitted path. A generic
    // launch naming the canonical notify image is refused here.
    if request_names_notify_image(&request) {
        return Message::Error {
            code: "BROKER_NOTIFY_LAUNCH_REQUIRES_ADMISSION",
            detail: "the canonical notify image is only launchable through the admitted notify operation"
                .to_owned(),
        };
    }
    let operation_key = request.approved.idempotency_key.clone();
    match admit_retained_human(composition, redeemed, authority, &operation_key) {
        Err(message) => message,
        Ok(_) => dispatch_launch(match resource_selection {
            Some(selection) => {
                composition.launch_with_native_resource_selection(request, selection)
            }
            None => composition.launch(request),
        }),
    }
}

fn dispatch_operator_pipe(
    composition: &mut BrokerComposition,
    request: OperatorPipeRequest,
    peer: &eliot_platform_windows::NamedPipePeerEvidence,
    redeemed: &mut Option<RedeemedOperatorBinding>,
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
        // Redemption is the only production site of state authority. It runs
        // only here, on the connected named pipe, with the OS-observed peer
        // the pipe server sealed for this connection, and only after the
        // composition admitted the handoff against that same peer. A refusal
        // changes nothing at all: `redeemed` is left unset inside the
        // composition and the retained binding here is left exactly as it was,
        // because a refused redemption proves no binding.
        OperatorPipeRequest::RedeemOperatorHandoff { endpoint, client } => {
            if let Err(error) = composition.redeem_operator_handoff(&endpoint, &client, peer) {
                return operator_pipe_rejection(&error);
            }
            // Reached only after the composition admitted the handoff against
            // this observed peer, so the retained binding is written here and
            // nowhere else, and never on a refusal.
            *redeemed = Some(RedeemedOperatorBinding::read_back(&endpoint, &client, peer));
            OperatorPipeMessage::Redeemed {
                principal: peer.sid().to_owned(),
                interactive_session_id: peer.session_id().to_string(),
                client_process_id: peer.process().process_id,
                kernel_session_token: client.kernel_session_token,
                role: endpoint.role,
                capabilities: endpoint.capabilities,
            }
        }
    }
}

/// Refuses a declared authority that disagrees with what this process's own
/// redemption observed and was granted.
///
/// The request's own `authority` block is caller text. It is never trusted as
/// identity: the Windows SID, the logon Session, the Kernel session token and
/// the exact role/capability set the request claims must equal the values this
/// broker read back from the OS-observed peer of the binding it actually
/// redeemed. A principal or session this broker never observed on that
/// connection is a foreign peer, and a role or capability outside the granted
/// set is a widened request; both are refused by name before any authority is
/// built and before any state change is considered.
fn declared_authority_matches_redemption(
    redeemed: &RedeemedOperatorBinding,
    declared: &HumanStateAuthority,
) -> Result<(), BrokerAdmissionRefusal> {
    if declared.principal != redeemed.principal
        || declared.interactive_session_id != redeemed.interactive_session_id
    {
        return Err(BrokerAdmissionRefusal::OperatorBindingCrossSession);
    }
    if declared.role != redeemed.role || declared.capabilities != redeemed.capabilities {
        return Err(BrokerAdmissionRefusal::HumanCapabilityNotGranted);
    }
    if declared.kernel_session_token != redeemed.kernel_session_token {
        return Err(BrokerAdmissionRefusal::OperatorSessionTokenStale);
    }
    Ok(())
}

/// Builds the authority one state-changing arm consumes, from the binding this
/// broker process redeemed on its connected, OS-authenticated pipe peer.
///
/// The authority is not assembled from the request: every identity, role and
/// capability field is read from the retained `OperatorSessionBinding` row the
/// redemption created, and only the approval hash the request claims is taken
/// from the request — that is the one field here that names an *action*, and it
/// stays a claim for the Kernel to canonicalize. A request with no retained
/// redemption, no declared principal, or a declared authority that disagrees
/// with the redemption is refused by name; none of those paths reaches
/// [`BrokerComposition::admit_human_state_change`] with a half-built value.
fn retained_state_authority(
    composition: &BrokerComposition,
    redeemed: Option<&RedeemedOperatorBinding>,
    declared: Option<&HumanStateAuthority>,
) -> Result<HumanStateAuthority, Message> {
    let Some(redeemed) = redeemed else {
        return Err(Message::Error {
            code: BrokerAdmissionRefusal::HumanPrincipalRequired.code(),
            detail: "no Operator binding was redeemed in this broker process, so there is no authenticated Human principal to admit; a fresh challenge and redemption on the connected pipe are required"
                .to_owned(),
        });
    };
    let Some(declared) = declared else {
        return Err(Message::Error {
            code: BrokerAdmissionRefusal::HumanPrincipalRequired.code(),
            detail: "state-changing request carries no authenticated Human principal".to_owned(),
        });
    };
    declared_authority_matches_redemption(redeemed, declared).map_err(|refusal| Message::Error {
        code: refusal.code(),
        detail: format!(
            "state-changing request authority disagrees with the redemption this broker observed: {refusal}"
        ),
    })?;
    // PREREQUISITE, written in `lib.rs` and not in this file (this file owns
    // only the call site):
    //
    // * `HumanStateAuthority::from_redeemed_binding(&OperatorSessionBinding,
    //   &str)` must be `pub`, and
    // * `BrokerComposition` must expose the retained `OperatorSessionBinding`
    //   of one redeemed handoff nonce, named `operator_session_binding` here.
    //
    // Both are required because `OperatorSessionBinding` and the binding map
    // are crate-private in `lib.rs`: this file cannot construct or reach the
    // binding it redeemed by any other route, and it will not substitute the
    // caller-declared PID/SID/Session tuple for it. Everything the authority
    // carries is read back from that row — the observed peer identity, the
    // Kernel-issued token and the granted role/capability set — so this call is
    // the only place a state-changing arm's identity can come from.
    let Some(binding) = composition.operator_session_binding(&redeemed.handoff_nonce) else {
        return Err(Message::Error {
            code: BrokerAdmissionRefusal::HumanCapabilityNotGranted.code(),
            detail: "the retained Operator binding is no longer held by this broker process, so it grants no authority"
                .to_owned(),
        });
    };
    HumanStateAuthority::from_redeemed_binding(binding, &declared.approval_hash)
        .map_err(|error| composition_rejection(&error))
}

/// Admits one state-changing request under the retained Human authority and
/// returns the authenticated Human principal it was admitted for.
///
/// The string returned is the retained authority's own principal, which
/// `from_redeemed_binding` read back from the redeemed binding, so it is the
/// Windows SID of the peer this broker OS-authenticated — never text the
/// request supplied. It is handed on only after
/// [`BrokerComposition::admit_human_state_change`] has proved the principal
/// against the live registration and session and proved a redeemed
/// Kernel-backed binding for that same identity, so a principal that is not the
/// admitted Human never reaches the canonical record.
fn admit_retained_human(
    composition: &mut BrokerComposition,
    redeemed: Option<&RedeemedOperatorBinding>,
    declared: Option<&HumanStateAuthority>,
    operation_key: &str,
) -> Result<String, Message> {
    let authority = retained_state_authority(composition, redeemed, declared)?;
    composition
        .admit_human_state_change(Some(&authority), operation_key)
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
    use eliot_user_broker::{BrokerAdmissionRefusal, HumanStateAuthority};

    use super::{RedeemedOperatorBinding, Request, declared_authority_matches_redemption};

    /// The identity this broker reads back from the OS-observed pipe peer of
    /// the redemption: a real-shaped SID, a logon Session, the fresh
    /// Kernel-issued session token, and the exact granted role/capability set.
    fn observed_redemption() -> RedeemedOperatorBinding {
        RedeemedOperatorBinding {
            handoff_nonce: "handoff-nonce-1".to_owned(),
            principal: "S-1-5-21-1004336348-1177238915-682003330-1001".to_owned(),
            interactive_session_id: "3".to_owned(),
            kernel_session_token: "a".repeat(64),
            role: "control_board".to_owned(),
            capabilities: vec!["state.read".to_owned()],
        }
    }

    fn declared_authority() -> HumanStateAuthority {
        HumanStateAuthority {
            principal: "S-1-5-21-1004336348-1177238915-682003330-1001".to_owned(),
            interactive_session_id: "3".to_owned(),
            role: "control_board".to_owned(),
            capabilities: vec!["state.read".to_owned()],
            approval_hash: "b".repeat(64),
            kernel_session_token: "a".repeat(64),
        }
    }

    #[test]
    fn redemption_on_the_observed_peer_admits_the_matching_declared_authority() {
        // A request whose declared principal, session, Kernel session token,
        // role and capability set are exactly the ones this broker read back
        // from the peer it OS-authenticated on the connected pipe is the only
        // shape that reaches the admitted authority; the state-changing arm
        // therefore has an authority built from the retained binding rather
        // than one assembled from request text.
        let redeemed = observed_redemption();
        assert_eq!(
            declared_authority_matches_redemption(&redeemed, &declared_authority()),
            Ok(())
        );
    }

    #[test]
    fn caller_declared_peer_and_widened_capability_are_refused_by_name() {
        let redeemed = observed_redemption();

        // A principal/Session this broker never observed on the connected pipe
        // is a foreign peer, refused by name.
        let mut foreign = declared_authority();
        foreign.principal = "S-1-5-21-1004336348-1177238915-682003330-1002".to_owned();
        assert_eq!(
            declared_authority_matches_redemption(&redeemed, &foreign),
            Err(BrokerAdmissionRefusal::OperatorBindingCrossSession)
        );
        assert_eq!(
            BrokerAdmissionRefusal::OperatorBindingCrossSession.code(),
            "BROKER_REGISTRATION_IDENTITY_FOREIGN"
        );

        // A role/capability set that disagrees with the granted row is a
        // widened request, refused by name rather than narrowed.
        let mut widened = declared_authority();
        widened.capabilities.push("state.write".to_owned());
        assert_eq!(
            declared_authority_matches_redemption(&redeemed, &widened),
            Err(BrokerAdmissionRefusal::HumanCapabilityNotGranted)
        );
        assert_eq!(
            BrokerAdmissionRefusal::HumanCapabilityNotGranted.code(),
            "CAPABILITY_INTRODUCTION_REQUIRED"
        );

        // A Kernel session token from another binding is stale here.
        let mut replayed = declared_authority();
        replayed.kernel_session_token = "c".repeat(64);
        assert_eq!(
            declared_authority_matches_redemption(&redeemed, &replayed),
            Err(BrokerAdmissionRefusal::OperatorSessionTokenStale)
        );
    }

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
