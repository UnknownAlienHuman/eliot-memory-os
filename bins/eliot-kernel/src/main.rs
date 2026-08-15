use std::io::{self, Write};

use eliot_kernel::{
    KernelBuildError, KernelComposition, KernelConfig, PROTOCOL_VERSION, SERVICE_NAME,
    default_work_root,
};

#[cfg(windows)]
use eliot_ipc::{
    NamedPipeServer, TransportError, decode_client_hello_frame, handshake_rejection_frame,
    server_hello_frame,
};
#[cfg(windows)]
use eliot_kernel::KernelFrameAction;

#[tokio::main]
async fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    let kernel = match KernelComposition::new(KernelConfig::new(root)) {
        Ok(kernel) => kernel,
        Err(error) => exit_build_error(error),
    };
    let ready = format!(
        "{{\"service\":\"{SERVICE_NAME}\",\"protocol\":\"{PROTOCOL_VERSION}\",\"ipc\":\"{}\"}}",
        kernel.ipc().name()
    );
    if !write_line(&ready) {
        return;
    }
    #[cfg(windows)]
    {
        let principal = match eliot_platform_windows::current_process_named_pipe_expectation() {
            Ok(expectation) => expectation,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
        };
        let mut connection_number = 0_u64;
        loop {
            connection_number = connection_number.saturating_add(1);
            let connection_id = format!("kernel-connection-{connection_number}");
            let mut front_door = match kernel.bind_authenticated_front_door() {
                Ok(server) => server,
                Err(error) => exit_build_error(error),
            };
            let accepted = tokio::select! {
                result = front_door.wait_for_authenticated_client(
                    std::time::Duration::from_secs(86_400),
                    &principal,
                ) => Some(result),
                result = tokio::signal::ctrl_c() => {
                    if let Err(error) = result {
                        write_error("SIGNAL_FAILURE", &error.to_string());
                    }
                    None
                }
            };
            let Some(accepted) = accepted else {
                break;
            };
            if let Err(error) = accepted {
                write_error("FRONT_DOOR_FAILURE", &error.to_string());
                continue;
            }
            match serve_connection(&kernel, &mut front_door, connection_id).await {
                Ok(ConnectionDisposition::Continue) => {}
                Ok(ConnectionDisposition::Shutdown) => break,
                Err(error) => write_error("SESSION_FAILURE", &error.to_string()),
            }
        }
    }
    #[cfg(not(windows))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        exit_error("SIGNAL_FAILURE", &error.to_string());
    }
    let _ = kernel.shutdown().await;
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionDisposition {
    Continue,
    Shutdown,
}

#[cfg(windows)]
async fn serve_connection(
    kernel: &KernelComposition,
    front_door: &mut NamedPipeServer,
    connection_id: String,
) -> Result<ConnectionDisposition, TransportError> {
    let limits = kernel.ipc().limits();
    let client_frame = front_door.receive_frame(limits).await?;
    let client = match decode_client_hello_frame(&client_frame, &connection_id) {
        Ok(client) => client,
        Err(error) => {
            let rejection = handshake_rejection_frame(&connection_id, error.to_string())?;
            front_door.send_frame(&rejection, limits).await?;
            return Ok(ConnectionDisposition::Continue);
        }
    };
    let peer = front_door.peer_identity().clone();
    let handshake = match kernel.bind_session(connection_id.clone(), peer, &client) {
        Ok(handshake) => handshake,
        Err(error) => {
            let rejection = handshake_rejection_frame(&connection_id, error.to_string())?;
            front_door.send_frame(&rejection, limits).await?;
            return Ok(ConnectionDisposition::Continue);
        }
    };
    let server_frame = server_hello_frame(&connection_id, &handshake.server_hello)?;
    front_door.send_frame(&server_frame, limits).await?;

    let mut session = handshake.session;
    loop {
        let frame = match front_door.receive_frame(limits).await {
            Ok(frame) => frame,
            Err(error) => {
                session.fence();
                return Err(error);
            }
        };
        match kernel.dispatch_frame(&session, &frame)? {
            KernelFrameAction::Reply(reply) => {
                front_door.send_frame(&reply, limits).await?;
            }
            KernelFrameAction::ReplyAndShutdown(reply) => {
                front_door.send_frame(&reply, limits).await?;
                session.fence();
                return Ok(ConnectionDisposition::Shutdown);
            }
            KernelFrameAction::Fence(rejection) => {
                front_door.send_frame(&rejection, limits).await?;
                session.fence();
                return Ok(ConnectionDisposition::Continue);
            }
        }
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
