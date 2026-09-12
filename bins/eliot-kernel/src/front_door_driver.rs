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
                match joined {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => write_error("SESSION_FAILURE", &error.to_string()),
                    Some(Err(error)) => write_error("SESSION_TASK_FAILURE", &error.to_string()),
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
        match joined {
            Ok(Ok(()) | Err(_)) | Err(_) => {}
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
                operation,
                payload,
            } => {
                let reply = kernel
                    .execute_daemon_request(&session, request_id, &operation, payload)
                    .await?;
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
    // Keep the Kernel-owned Session retained until the bridge disconnects or
    // the owner explicitly revokes it. A successful response is not a
    // disconnect boundary.
    match receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await {
        Ok(None) => {
            kernel.revoke_agent_bridge(&connection_id);
            Ok(())
        }
        Ok(Some(_)) => {
            kernel.revoke_agent_bridge(&connection_id);
            Err(TransportError::SessionFenced)
        }
        Err(error) => {
            kernel.revoke_agent_bridge(&connection_id);
            Err(error)
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
