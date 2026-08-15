use std::io::{self, Write};
use std::sync::Arc;

use eliot_kernel::{
    KernelBuildError, KernelComposition, KernelConfig, PROTOCOL_VERSION, SERVICE_NAME,
    default_work_root,
};

#[cfg(windows)]
use eliot_ipc::{
    DeliveryOutcome, NamedPipeServer, TransportError, TransportLimits,
    decode_client_hello_frame_unbound, handshake_rejection_frame, server_hello_frame,
};
#[cfg(windows)]
use eliot_kernel::KernelFrameAction;
#[cfg(windows)]
use tokio::sync::{Semaphore, watch};
#[cfg(windows)]
use tokio::task::JoinSet;

#[tokio::main]
async fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    let kernel = Arc::new(match KernelComposition::new(KernelConfig::new(root)) {
        Ok(kernel) => kernel,
        Err(error) => exit_build_error(error),
    });
    #[cfg(windows)]
    {
        let principal = match eliot_platform_windows::current_process_named_pipe_expectation() {
            Ok(expectation) => expectation,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
        };
        let mut front_door = match kernel.bind_authenticated_front_door() {
            Ok(server) => server,
            Err(error) => exit_build_error(error),
        };
        let ready = format!(
            "{{\"service\":\"{SERVICE_NAME}\",\"protocol\":\"{PROTOCOL_VERSION}\",\"ipc\":\"{}\"}}",
            kernel.ipc().name()
        );
        if !write_line(&ready) {
            return;
        }
        const MAX_SESSIONS: usize = 32;
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
                result = front_door.wait_for_authenticated_client(
                    std::time::Duration::from_secs(86_400),
                    &principal,
                ) => {
                    if let Err(error) = result {
                        write_error("FRONT_DOOR_FAILURE", &error.to_string());
                        drop(front_door);
                        front_door = match kernel.bind_authenticated_front_door() {
                            Ok(server) => server,
                            Err(bind_error) => {
                                write_error("FRONT_DOOR_FAILURE", &bind_error.to_string());
                                break;
                            }
                        };
                        continue;
                    }
                    let replacement = match kernel.bind_authenticated_front_door_next() {
                        Ok(server) => server,
                        Err(error) => {
                            write_error("FRONT_DOOR_FAILURE", &error.to_string());
                            break;
                        }
                    };
                    let accepted_server = std::mem::replace(&mut front_door, replacement);
                    let Some(permit) = permits.clone().try_acquire_owned().ok() else {
                        drop(accepted_server);
                        continue;
                    };
                    let task_kernel = Arc::clone(&kernel);
                    let task_shutdown = shutdown_rx.clone();
                    sessions.spawn(async move {
                        let result =
                            serve_connection(task_kernel, accepted_server, task_shutdown).await;
                        drop(permit);
                        result
                    });
                }
            }
        }
        let _ = shutdown_tx.send(true);
        while let Some(joined) = sessions.join_next().await {
            match joined {
                Ok(Ok(())) | Ok(Err(_)) | Err(_) => {}
            }
        }
    }
    #[cfg(not(windows))]
    {
        let ready = format!(
            "{{\"service\":\"{SERVICE_NAME}\",\"protocol\":\"{PROTOCOL_VERSION}\",\"ipc\":\"{}\"}}",
            kernel.ipc().name()
        );
        if !write_line(&ready) {
            return;
        }
        if let Err(error) = tokio::signal::ctrl_c().await {
            exit_error("SIGNAL_FAILURE", &error.to_string());
        }
    }
    let _ = kernel.shutdown().await;
}

#[cfg(windows)]
async fn serve_connection(
    kernel: Arc<KernelComposition>,
    mut front_door: NamedPipeServer,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TransportError> {
    let limits = kernel.ipc().limits();
    let Some(client_frame) =
        receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await?
    else {
        return Ok(());
    };
    let connection_id = client_frame.connection_id.clone();
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
    let peer = front_door.peer_identity().clone();
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
        let Some(frame) = receive_frame_or_shutdown(&mut front_door, limits, &mut shutdown).await?
        else {
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

fn parse_root() -> Result<std::path::PathBuf, std::io::Error> {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => default_work_root(),
        Some(value) if value == "--work-root" => match args.next() {
            Some(root) if args.next().is_none() => std::fs::canonicalize(root),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--work-root requires exactly one path",
            )),
        },
        Some(value) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown argument: {}", value.to_string_lossy()),
        )),
    }
}

fn exit_build_error(error: KernelBuildError) -> ! {
    exit_error("COMPOSITION_FAILURE", &error.to_string())
}

fn exit_error(code: &str, detail: &str) -> ! {
    write_error(code, detail);
    std::process::exit(1);
}

fn write_error(code: &str, detail: &str) {
    let _ = writeln!(
        io::stderr().lock(),
        "{{\"error\":\"{code}\",\"detail\":{detail:?}}}"
    );
}

fn write_line(line: &str) -> bool {
    let mut stdout = io::stdout().lock();
    stdout.write_all(line.as_bytes()).is_ok()
        && stdout.write_all(b"\n").is_ok()
        && stdout.flush().is_ok()
}
