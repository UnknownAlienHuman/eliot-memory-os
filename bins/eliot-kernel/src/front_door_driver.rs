//! Front-door accept/rotation/session driver (cell 1, §15 req.1/req.2/req.6).
//!
//! Binary-private driver owning the authenticated Windows front-door loop:
//! peer-set rotation, 24h accept, `JoinSet` sessions, `ctrl_c` drain,
//! fence-on-error, revoke-on-exit, single-shot `ProbeReady`, and
//! `Delivered` vs `UnknownOutcome` mapping. Public-API-only seam: drives
//! `KernelComposition` exclusively through its public methods plus
//! `std`/`tokio`/pipe types, touching zero `KernelComposition` privates.
//! Terminal projection (`exit_*`/`write_error`) stays in `main` and is reused
//! here without duplication. Capability cell: 1 (front-door/IPC admission).

use std::sync::Arc;

use eliot_ipc::{
    DeliveryOutcome, NamedPipeServer, TransportError, TransportLimits,
    decode_client_hello_frame_unbound, handshake_rejection_frame, server_hello_frame,
};
#[cfg(windows)]
use eliot_kernel::kernel_diagnostics::{EntrypointStage, observe_entrypoint_with_detail};
use eliot_kernel::{KernelComposition, KernelFrameAction};
use eliot_kernel_service::{
    KernelControlCommand, control_response_frame, decode_control_request_frame,
};
use eliot_platform_windows::{
    NamedPipePeerKind, NamedPipePeerSelection, current_process_named_pipe_expectation,
};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::startup_binding::KernelStartupBinding;
use crate::{exit_build_error, exit_error, write_error};

#[cfg(windows)]
const MAX_SESSIONS: usize = 32;

/// Runs the authenticated front-door accept/rotation/session loop to drain.
///
/// Keeps startup, authenticated listener rotation, and fenced shutdown in one
/// ordered authority path. Returns after `ctrl_c` or a fenced front-door
/// failure, once every spawned session has drained; the caller owns terminal
/// shutdown projection.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the ordered accept/rotation/drain authority path stays in one loop, as in `main`"
)]
pub async fn run_front_door_loop(kernel: Arc<KernelComposition>, binding: &KernelStartupBinding) {
    let observed_host = match binding.observe_host() {
        Ok(binding) => binding,
        Err(error) => exit_error("PRINCIPAL_FAILURE", &error),
    };
    let principal = match current_process_named_pipe_expectation()
        .and_then(|expectation| expectation.with_process_binding(observed_host))
    {
        Ok(expectation) => expectation,
        Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
    };
    let (mut peer_set_revision, mut peer_set) =
        match kernel.front_door_peer_set_snapshot(&principal) {
            Ok(snapshot) => snapshot,
            Err(error) => exit_build_error(&error),
        };
    let mut front_door = match kernel.bind_authenticated_front_door_with_peer_set(&peer_set) {
        Ok(server) => server,
        Err(error) => exit_build_error(&error),
    };
    let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut sessions: JoinSet<Result<(), TransportError>> = JoinSet::new();
    loop {
        tokio::select! {
            joined = sessions.join_next(), if !sessions.is_empty() => {
                // F-LOG-KERNEL-0 (#895 W2/T15): JoinSet evidence projection
                // (I14.20): Ok(Ok)/Ok(Err)/Err/None map to
                // success/failure/join-failure/drained. Observation only,
                // no peer/session payload (I15.4).
                match joined {
                    Some(Ok(Ok(()))) => observe_entrypoint_with_detail(
                        EntrypointStage::SessionTaskOutcome,
                        "kernel.session.outcome:success",
                    ),
                    Some(Ok(Err(error))) => {
                        observe_entrypoint_with_detail(
                            EntrypointStage::SessionTaskOutcome,
                            "kernel.session.outcome:failure",
                        );
                        write_error("SESSION_FAILURE", &error.to_string());
                    }
                    Some(Err(error)) => {
                        observe_entrypoint_with_detail(
                            EntrypointStage::SessionTaskOutcome,
                            "kernel.session.outcome:join_failure",
                        );
                        write_error("SESSION_TASK_FAILURE", &error.to_string());
                    }
                    None => observe_entrypoint_with_detail(
                        EntrypointStage::SessionTaskOutcome,
                        "kernel.session.outcome:drained",
                    ),
                }
            }
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal {
                    write_error("SIGNAL_FAILURE", &error.to_string());
                }
                break;
            }
            _ = kernel.wait_for_agent_bridge_peer_set_revision(peer_set_revision) => {
                let (next_revision, next_peers) = match kernel.front_door_peer_set_snapshot(&principal) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        write_error("FRONT_DOOR_FAILURE", &error.to_string());
                        break;
                    }
                };
                let next_front_door = match kernel.bind_authenticated_front_door_next_with_peer_set(&next_peers) {
                    Ok(server) => server,
                    Err(error) => {
                        write_error("FRONT_DOOR_FAILURE", &error.to_string());
                        break;
                    }
                };
                drop(front_door);
                front_door = next_front_door;
                peer_set = next_peers;
                peer_set_revision = next_revision;
            }
            result = front_door.wait_for_authenticated_client_with_peer_set(
                std::time::Duration::from_hours(24),
                &peer_set,
            ) => {
                let selection = match result {
                    Ok(selection) => selection,
                    Err(error) => {
                    write_error("FRONT_DOOR_FAILURE", &error.to_string());
                    drop(front_door);
                    let (next_revision, next_peers) = match kernel.front_door_peer_set_snapshot(&principal) {
                        Ok(snapshot) => snapshot,
                        Err(bind_error) => {
                            write_error("FRONT_DOOR_FAILURE", &bind_error.to_string());
                            break;
                        }
                    };
                    front_door = match kernel.bind_authenticated_front_door_next_with_peer_set(&next_peers) {
                        Ok(server) => server,
                        Err(bind_error) => {
                            write_error("FRONT_DOOR_FAILURE", &bind_error.to_string());
                            break;
                        }
                    };
                    peer_set = next_peers;
                    peer_set_revision = next_revision;
                    continue;
                    }
                };
                let (replacement_revision, replacement_peers) = match kernel.front_door_peer_set_snapshot(&principal) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        write_error("FRONT_DOOR_FAILURE", &error.to_string());
                        break;
                    }
                };
                let replacement = match kernel.bind_authenticated_front_door_next_with_peer_set(&replacement_peers) {
                    Ok(server) => server,
                    Err(error) => {
                        write_error("FRONT_DOOR_FAILURE", &error.to_string());
                        break;
                    }
                };
                let accepted_server = std::mem::replace(&mut front_door, replacement);
                peer_set = replacement_peers;
                peer_set_revision = replacement_revision;
                let Some(permit) = permits.clone().try_acquire_owned().ok() else {
                    // F-LOG-KERNEL-0 (#895 W2/T14): permit exhaustion is
                    // visible here without a false success/failure claim:
                    // neither a terminal record nor a success event, only
                    // the admission observation. No peer/session payload.
                    observe_entrypoint_with_detail(
                        EntrypointStage::SessionPermitAdmission,
                        "kernel.session.admission:deferred_capacity",
                    );
                    drop(accepted_server);
                    continue;
                };
                let task_kernel = Arc::clone(&kernel);
                let task_shutdown = shutdown_rx.clone();
                sessions.spawn(async move {
                    let result = Box::pin(serve_connection(
                        task_kernel,
                        accepted_server,
                        task_shutdown,
                        selection,
                    ))
                    .await;
                    drop(permit);
                    result
                });
            }
        }
    }
    let _ = shutdown_tx.send(true);
    while let Some(joined) = sessions.join_next().await {
        // F-LOG-KERNEL-0 (#895 W2/T15): same JoinSet projection as the
        // in-loop arms; drain outcomes are recorded, never discarded.
        match joined {
            Ok(Ok(())) => observe_entrypoint_with_detail(
                EntrypointStage::SessionTaskOutcome,
                "kernel.session.outcome:success",
            ),
            Ok(Err(_)) => observe_entrypoint_with_detail(
                EntrypointStage::SessionTaskOutcome,
                "kernel.session.outcome:failure",
            ),
            Err(_) => observe_entrypoint_with_detail(
                EntrypointStage::SessionTaskOutcome,
                "kernel.session.outcome:join_failure",
            ),
        }
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "authenticated front-door receive, handshake, and control dispatch stay ordered"
)]
async fn serve_connection(
    kernel: Arc<KernelComposition>,
    mut front_door: NamedPipeServer,
    mut shutdown: watch::Receiver<bool>,
    selection: NamedPipePeerSelection,
) -> Result<(), TransportError> {
    let limits = kernel.ipc_limits();
    let peer = front_door.peer_identity().clone();
    if selection.kind() == NamedPipePeerKind::AgentBridge {
        return Box::pin(serve_agent_bridge_connection(
            kernel, front_door, shutdown, selection, peer,
        ))
        .await;
    }
    let Some(client_frame) =
        receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await?
    else {
        return Ok(());
    };
    let connection_id = client_frame.connection_id.clone();
    if decode_control_request_frame(&client_frame).is_ok() {
        return Box::pin(serve_control_connection(
            kernel,
            front_door,
            shutdown,
            client_frame,
            peer,
        ))
        .await;
    }
    let client = match decode_client_hello_frame_unbound(&client_frame) {
        Ok(client) => client,
        Err(error) => {
            if !connection_id.trim().is_empty() {
                let rejection = handshake_rejection_frame(&connection_id, error.to_string())?;
                send_checked(&mut front_door, &rejection, limits).await?;
            }
            return Ok(());
        }
    };
    let handshake = match kernel.bind_session(connection_id.clone(), peer, &client) {
        Ok(handshake) => handshake,
        Err(error) => {
            let rejection = handshake_rejection_frame(&connection_id, error.to_string())?;
            send_checked(&mut front_door, &rejection, limits).await?;
            return Ok(());
        }
    };
    let server_frame = server_hello_frame(&connection_id, &handshake.server_hello)?;
    let mut session = handshake.session;
    if let Err(error) = send_checked(&mut front_door, &server_frame, limits).await {
        session.fence();
        return Err(error);
    }
    loop {
        let received = match receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await
        {
            Ok(received) => received,
            Err(error) => {
                session.fence();
                return Err(error);
            }
        };
        let Some(frame) = received else {
            session.fence();
            return Ok(());
        };
        let action = match kernel.dispatch_frame(&session, &frame) {
            Ok(action) => action,
            Err(error) => {
                session.fence();
                return Err(error);
            }
        };
        match action {
            KernelFrameAction::Reply(reply) => {
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Process {
                request_id,
                request,
                session_binding,
            } => {
                use eliot_kernel::process_execution_client;
                use eliot_kernel_service::{ProcessExecutionClient, ProcessExecutionResponse};
                let response = match process_execution_client(&kernel, &session, &session_binding) {
                    Ok(client) => client.execute(request).await,
                    Err(rejection) => ProcessExecutionResponse::Rejected(rejection),
                };
                let reply = kernel.process_response_frame(&session, request_id, &response)?;
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Daemon {
                request_id,
                identity,
                operation,
                payload,
            } => {
                let reply = kernel
                    .execute_daemon_request_with_identity(
                        &session, request_id, identity, &operation, payload,
                    )
                    .await?;
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Doctor {
                request_id,
                operation,
                payload,
                control,
            } => {
                // P-07 Doctor repair intake: one bounded request/response
                // through the closed P-07 handler
                // (`KernelComposition::execute_doctor_request`). Frames are
                // served strictly in receive order on this connection, so a
                // second activation can never run concurrently with the
                // first; unknown operations never reach this arm (dispatch
                // fences them) and any handler failure fences the session
                // instead of silently dropping the submit.
                let reply = kernel
                    .execute_doctor_request_with_control(
                        &session, request_id, &operation, payload, control,
                    )
                    .await?;
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Testd {
                request_id,
                identity,
                operation,
                payload,
                control,
            } => {
                // P-07 testd admission intake: one bounded request/response
                // through the closed P-07 handler
                // (`KernelComposition::execute_testd_request`). Frames are
                // served strictly in receive order on this connection, so a
                // second admission can never run concurrently with the
                // first; unknown operations never reach this arm (dispatch
                // fences them) and any handler failure fences the session
                // instead of silently dropping the submit.
                let reply = if operation == eliot_kernel::TESTD_TERMINAL_COMPLETION_OPERATION {
                    kernel
                        .execute_testd_terminal_completion(
                            &session, request_id, &identity, &operation, payload,
                        )
                        .await?
                } else if operation == eliot_testd_core::TESTD_OWNER_SUBMIT_OPERATION {
                    kernel
                        .execute_testd_owner_submit(
                            &session, request_id, &identity, &operation, payload,
                        )
                        .await?
                } else {
                    kernel
                        .execute_testd_request_with_control(
                            &session, request_id, &operation, payload, control,
                        )
                        .await?
                };
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Dreamer {
                request_id,
                operation,
                payload,
            } => {
                // T12-05 K2 Dreamer requester routing: one bounded
                // request/response through the closed K2 handler
                // (`KernelComposition::execute_dreamer_request`). Frames are
                // served strictly in receive order on this connection, so a
                // second call can never run concurrently with the first;
                // unknown operations never reach this arm (dispatch fences
                // them) and any handler failure fences the session instead
                // of silently dropping the submit. No process is spawned
                // here.
                let reply = Box::pin(
                    kernel.execute_dreamer_request(&session, request_id, &operation, payload),
                )
                .await?;
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Research {
                request_id,
                operation,
                payload,
            } => {
                // #24 bounded research-provider dispatch/reconcile: one
                // request/response through the closed route handler
                // (`KernelComposition::handle_research_provider`). Frames are
                // served strictly in receive order on this connection, so a
                // second dispatch can never run concurrently with the first;
                // unknown operations never reach this arm (dispatch fences
                // them) and any handler failure fences the session instead of
                // silently dropping the submit. No provider process is spawned
                // here: the admitted operation runs in `eliot-mod-research`
                // through the shared governed process contour.
                let reply = kernel.research_provider_reply_frame(
                    &session,
                    &request_id,
                    &operation,
                    &payload,
                )?;
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    session.fence();
                    return Err(error);
                }
            }
            KernelFrameAction::Fence(rejection) => {
                let result = send_checked(&mut front_door, &rejection, limits).await;
                session.fence();
                result?;
                return Ok(());
            }
        }
    }
}

#[cfg(windows)]
async fn serve_agent_bridge_connection(
    kernel: Arc<KernelComposition>,
    mut front_door: NamedPipeServer,
    mut shutdown: watch::Receiver<bool>,
    selection: NamedPipePeerSelection,
    peer: eliot_ipc::PeerIdentity,
) -> Result<(), TransportError> {
    let limits = kernel.ipc_limits();
    let Ok(handshake) = kernel.begin_agent_bridge(&selection, peer) else {
        // A peer-set match is transport admission only. Until the exact
        // promoted Ready profile is present, close without a legacy
        // client-first rejection or semantic response.
        return Ok(());
    };
    let connection_id = handshake.connection_id.clone();
    if let Err(error) = send_checked(&mut front_door, &handshake.challenge_frame, limits).await {
        kernel.revoke_agent_bridge(&connection_id);
        return Err(error);
    }
    let hello = match receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await {
        Err(error) => {
            kernel.revoke_agent_bridge(&connection_id);
            return Err(error);
        }
        Ok(Some(frame)) => frame,
        Ok(None) => {
            kernel.revoke_agent_bridge(&connection_id);
            return Ok(());
        }
    };
    if let Err(error) = kernel.accept_agent_bridge_hello(&connection_id, &hello) {
        kernel.revoke_agent_bridge(&connection_id);
        return Err(error);
    }
    let receipt_frame = match kernel.agent_bridge_admission_receipt_frame(&connection_id) {
        Ok(frame) => frame,
        Err(error) => {
            kernel.revoke_agent_bridge(&connection_id);
            return Err(error);
        }
    };
    if let Err(error) = send_checked(&mut front_door, &receipt_frame, limits).await {
        kernel.revoke_agent_bridge(&connection_id);
        return Err(error);
    }
    let request = match receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await {
        Err(error) => {
            kernel.revoke_agent_bridge(&connection_id);
            return Err(error);
        }
        Ok(Some(frame)) => frame,
        Ok(None) => {
            kernel.revoke_agent_bridge(&connection_id);
            return Ok(());
        }
    };
    let response = match kernel
        .await_agent_bridge_activation_response(&connection_id, &request)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            kernel.revoke_agent_bridge(&connection_id);
            return Err(error);
        }
    };
    if let Err(error) = send_checked(&mut front_door, &response, limits).await {
        kernel.revoke_agent_bridge(&connection_id);
        return Err(error);
    }
    // The admitted bridge Session stays alive across host-request frames on
    // this same transport: a successful activation response is not a
    // disconnect boundary. The post-activation loop below serves every
    // further frame through the closed Kernel gateway against the retained
    // admitted Session.
    Box::pin(serve_admitted_bridge_host_requests(
        kernel,
        front_door,
        shutdown,
        connection_id,
    ))
    .await
}

/// Serves host-request frames on one admitted bridge transport until detach.
///
/// Each frame is dispatched through the closed Kernel gateway
/// ([`KernelComposition::dispatch_frame`]) against the retained admitted
/// Session snapshot, so durable Session continuity comes from the
/// Kernel-owned admission — never from process identity or caller-supplied
/// bindings. Only typed host-request replies continue the loop. Orderly
/// detach revokes and closes clean; an unknown operation returns its typed
/// rejection before revocation; any other violation (unexpected
/// process/daemon actions, failed dispatch, failed send) revokes and fences.
/// Connections without a retained admitted Session — including typed
/// activation denials — serve no further frames: their next frame fences
/// exactly as before, and their disconnect still closes clean. Capacity
/// saturation is the one dispatch failure that never revokes: a
/// `Backpressure` error is answered with a typed pressure reply on the
/// ordinary reply channel and the loop continues, so authorized
/// recovery/retirement stays usable on the retained session.
#[cfg(windows)]
async fn serve_admitted_bridge_host_requests(
    kernel: Arc<KernelComposition>,
    mut front_door: NamedPipeServer,
    mut shutdown: watch::Receiver<bool>,
    connection_id: String,
) -> Result<(), TransportError> {
    let limits = kernel.ipc_limits();
    loop {
        let received = match receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await
        {
            Err(error) => {
                kernel.revoke_agent_bridge(&connection_id);
                return Err(error);
            }
            Ok(received) => received,
        };
        let Some(frame) = received else {
            kernel.revoke_agent_bridge(&connection_id);
            return Ok(());
        };
        let session = match kernel.host_request_bridge_session(&connection_id) {
            Ok(session) => session,
            Err(error) => {
                kernel.revoke_agent_bridge(&connection_id);
                return Err(error);
            }
        };
        let action = match kernel.dispatch_frame(&session, &frame) {
            Ok(action) => action,
            Err(TransportError::Backpressure) => {
                // Capacity saturation is typed backpressure with its
                // exhausted dimension and permitted recovery action, never
                // an authentication failure (issue #2731, item 6): the
                // admitted session is retained so the gap, reconcile, and
                // eligible-retirement recovery legs stay usable on this same
                // transport, and the shed frame is answered on the ordinary
                // reply channel instead of tearing the exchange down. The
                // reply envelope mirrors the Kernel status-reply shape
                // (`Response`/`Result`, echoed correlation, no request
                // identity) but carries no acceptance claim — the shed
                // frame's commit fate is unknown at this layer, so the
                // bridge must resolve it through the idempotent
                // duplicate/reconcile legs rather than a blind retry. Any
                // send failure still revokes and fences exactly as for the
                // other kinds.
                let signal = TransportError::Backpressure
                    .backpressure_signal()
                    .unwrap_or(eliot_ipc::BACKPRESSURE_BRIDGE_DISPATCH);
                let reply = eliot_protocol::Frame {
                    protocol_version: session.protocol_version,
                    encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
                    connection_id: session.connection_id.clone(),
                    request_id: frame.request_id.clone(),
                    kind: eliot_protocol::FrameKind::Response,
                    message_type: eliot_protocol::MessageType::Result,
                    request_identity: None,
                    payload: eliot_protocol::ProtocolPayload::Json(serde_json::json!({
                        "status": "known",
                        "value": {
                            "backpressure": true,
                            "dimension": signal.dimension,
                            "recovery_action": signal.recovery_action,
                            "shed_work": signal.shed_work,
                            "outcome": "unknown",
                        },
                    })),
                    trace_context: std::collections::BTreeMap::new(),
                };
                if let Err(error) = reply.validate() {
                    kernel.revoke_agent_bridge(&connection_id);
                    return Err(TransportError::Protocol(error));
                }
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    kernel.revoke_agent_bridge(&connection_id);
                    return Err(error);
                }
                continue;
            }
            Err(error) => {
                kernel.revoke_agent_bridge(&connection_id);
                return Err(error);
            }
        };
        match action {
            KernelFrameAction::Reply(reply) => {
                if let Err(error) = send_checked(&mut front_door, &reply, limits).await {
                    kernel.revoke_agent_bridge(&connection_id);
                    return Err(error);
                }
            }
            KernelFrameAction::Fence(rejection) => {
                let result = send_checked(&mut front_door, &rejection, limits).await;
                kernel.revoke_agent_bridge(&connection_id);
                result?;
                return Ok(());
            }
            KernelFrameAction::Process { .. }
            | KernelFrameAction::Daemon { .. }
            | KernelFrameAction::Doctor { .. }
            | KernelFrameAction::Testd { .. }
            | KernelFrameAction::Research { .. }
            | KernelFrameAction::Dreamer { .. } => {
                // Bridge transports never carry process, daemon, Doctor,
                // testd, research-provider, or Dreamer authority: the Doctor
                // serves only its own admitted generation-bound
                // session/connection (T6-D2 P-07), testd serves only its own
                // admitted generation-bound session/connection (T6-X1 P-07),
                // the research-provider route serves only its own admitted
                // module-generation session/connection (#24), and Dreamer
                // serves only its own admitted eliotd requester
                // session/connection (T12-05 K2), never the bridge's. Revoke
                // and fence exactly as for the other kinds.
                kernel.revoke_agent_bridge(&connection_id);
                return Err(TransportError::SessionFenced);
            }
        }
    }
}

#[cfg(windows)]
async fn serve_control_connection(
    kernel: Arc<KernelComposition>,
    mut front_door: NamedPipeServer,
    mut shutdown: watch::Receiver<bool>,
    first_frame: eliot_protocol::Frame,
    peer: eliot_ipc::PeerIdentity,
) -> Result<(), TransportError> {
    let limits = kernel.ipc_limits();
    let mut expected_sequence = 1_u64;
    let mut frame = Some(first_frame);
    loop {
        let received = if let Some(first) = frame.take() {
            first
        } else {
            match receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await? {
                Some(frame) => frame,
                None => return Ok(()),
            }
        };
        let request = decode_control_request_frame(&received)?;
        let is_ready = matches!(&request.command, KernelControlCommand::ProbeReady);
        let response =
            Box::pin(kernel.apply_control_request(request, &peer, expected_sequence)).await?;
        expected_sequence = expected_sequence.saturating_add(1);
        let response_frame = control_response_frame(&received.connection_id, &response)?;
        send_checked(&mut front_door, &response_frame, limits).await?;
        if is_ready {
            return Ok(());
        }
    }
}

#[cfg(windows)]
async fn receive_frame_or_shutdown(
    front_door: &mut NamedPipeServer,
    limits: TransportLimits,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<eliot_protocol::Frame>, TransportError> {
    if *shutdown.borrow() {
        return Ok(None);
    }
    tokio::select! {
        result = front_door.receive_frame(limits) => result.map(Some),
        changed = shutdown.changed() => {
            changed.map_err(|_| TransportError::Cancelled)?;
            Ok(None)
        }
    }
}

#[cfg(windows)]
async fn send_checked(
    front_door: &mut NamedPipeServer,
    frame: &eliot_protocol::Frame,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    match front_door.send_frame(frame, limits).await? {
        DeliveryOutcome::Delivered => Ok(()),
        DeliveryOutcome::UnknownOutcome => Err(TransportError::UnknownOutcome),
    }
}
