use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eliot_kernel::{
    KernelBuildError, KernelComposition, KernelConfig, PROTOCOL_VERSION, SERVICE_NAME,
    default_work_root,
};
use eliot_kernel_service::HostStoreBootstrapRequirement;

#[cfg(windows)]
const MAX_SESSIONS: usize = 32;

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

/// Keeps startup, authenticated listener rotation, and fenced shutdown in one
/// ordered authority path.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    let options = match parse_launch_options(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    let prepared_store = match prepare_store_bootstrap(&options) {
        Ok(prepared) => prepared,
        Err(error) => exit_error("INVALID_STORE_BOOTSTRAP", &error),
    };
    let store_is_configured = prepared_store.is_some();
    let mut kernel_config = KernelConfig::new(options.work_root);
    if let Some(prepared) = &prepared_store {
        kernel_config = kernel_config.with_store_bootstrap(prepared.requirement.clone());
    }
    let kernel = Arc::new(match KernelComposition::new(kernel_config) {
        Ok(kernel) => kernel,
        Err(error) => exit_build_error(&error),
    });
    if !kernel.process_execution_configured() {
        exit_error(
            "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the external process authority handoff before Kernel readiness",
        );
    }
    #[cfg(windows)]
    {
        if let Some(prepared) = prepared_store
            && let Err(error) = kernel
                .connect_canonical_store(Duration::from_millis(prepared.requirement.timeout_ms()))
                .await
        {
            exit_build_error(&error);
        }
        let principal = match eliot_platform_windows::current_process_named_pipe_expectation() {
            Ok(expectation) => expectation,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
        };
        let mut front_door = match kernel.bind_authenticated_front_door() {
            Ok(server) => server,
            Err(error) => exit_build_error(&error),
        };
        let ready = ready_line(&kernel, store_is_configured);
        if !write_line(&ready) {
            return;
        }
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
                        front_door = match kernel.bind_authenticated_front_door_next() {
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
                Ok(Ok(()) | Err(_)) | Err(_) => {}
            }
        }
    }
    #[cfg(not(windows))]
    {
        if store_is_configured {
            exit_error(
                "STORE_BOOTSTRAP_UNSUPPORTED",
                "the canonical Store bootstrap requires Windows authenticated named pipes",
            );
        }
        let ready = ready_line(&kernel, false);
        if !write_line(&ready) {
            return;
        }
        if let Err(error) = tokio::signal::ctrl_c().await {
            exit_error("SIGNAL_FAILURE", &error.to_string());
        }
    }
    match kernel.shutdown().await {
        Ok(outcome) if outcome.no_orphans => {}
        Ok(outcome) => exit_error(
            "SHUTDOWN_INCOMPLETE",
            &format!("runtime shutdown outcome: {outcome:?}"),
        ),
        Err(error) => exit_error("SHUTDOWN_FAILURE", &error.to_string()),
    }
}

#[cfg(windows)]
async fn serve_connection(
    kernel: Arc<KernelComposition>,
    mut front_door: NamedPipeServer,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TransportError> {
    let limits = kernel.ipc_limits();
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
                let response = kernel
                    .execute_process_request(&session, session_binding, request)
                    .await;
                let reply = kernel.process_response_frame(&session, request_id, &response)?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoreConfigLocator {
    NeutralDescriptor(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelLaunchOptions {
    work_root: PathBuf,
    store_config: Option<StoreConfigLocator>,
}

struct PreparedStoreBootstrap {
    requirement: HostStoreBootstrapRequirement,
}

fn parse_launch_options<I>(args: I) -> Result<KernelLaunchOptions, std::io::Error>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [] => Ok(KernelLaunchOptions {
            work_root: default_work_root()?,
            store_config: None,
        }),
        [work_flag, work_root] if work_flag == "--work-root" => Ok(KernelLaunchOptions {
            work_root: canonical_directory(work_root)?,
            store_config: None,
        }),
        [work_flag, work_root, store_flag, descriptor]
            if work_flag == "--work-root" && store_flag == "--store-bootstrap" =>
        {
            Ok(KernelLaunchOptions {
                work_root: canonical_directory(work_root)?,
                store_config: Some(StoreConfigLocator::NeutralDescriptor(PathBuf::from(
                    descriptor,
                ))),
            })
        }
        _ => Err(invalid_input(
            "expected no args, --work-root <path>, or --work-root <path> --store-bootstrap <validated descriptor path>",
        )),
    }
}

fn canonical_directory(value: &std::ffi::OsStr) -> Result<PathBuf, std::io::Error> {
    let path = PathBuf::from(value);
    let canonical = std::fs::canonicalize(&path)?;
    if !canonical.is_dir() {
        return Err(invalid_input(
            "configured root must be an existing directory",
        ));
    }
    Ok(canonical)
}

fn invalid_input(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

fn prepare_store_bootstrap(
    options: &KernelLaunchOptions,
) -> Result<Option<PreparedStoreBootstrap>, String> {
    let Some(locator) = &options.store_config else {
        return Ok(None);
    };
    let StoreConfigLocator::NeutralDescriptor(path) = locator;
    let bytes = std::fs::read(path)
        .map_err(|error| format!("read neutral store bootstrap descriptor: {error}"))?;
    let requirement: HostStoreBootstrapRequirement = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse neutral store bootstrap descriptor: {error}"))?;
    requirement
        .validate()
        .map_err(|error| format!("validate neutral store bootstrap descriptor: {error}"))?;
    Ok(Some(PreparedStoreBootstrap { requirement }))
}

fn ready_line(kernel: &KernelComposition, store_is_configured: bool) -> String {
    serde_json::json!({
        "service": SERVICE_NAME,
        "protocol": PROTOCOL_VERSION,
        "ipc": kernel.ipc(),
        "canonical_store": if store_is_configured { "READY" } else { "NOT_CONFIGURED" },
    })
    .to_string()
}

fn exit_build_error(error: &KernelBuildError) -> ! {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "eliot-kernel-options-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(root.join("work")).expect("create test root");
            Self(root)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn descriptor() -> HostStoreBootstrapRequirement {
        use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
        use eliot_platform::PlatformHandle;
        let generation = ResourceGeneration::new(9).expect("generation");
        HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new("store_bridge").expect("route"),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-kernel-main-test")
                .expect("pipe"),
            store_generation: generation,
            state_fence: StateFence::new(AuthorityEpoch::new(7).expect("epoch"), generation),
            launch_nonce: PlatformHandle::new("kernel-main-test").expect("nonce"),
            connection_id: PlatformHandle::new("kernel-store:kernel-main-test")
                .expect("connection"),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
            expected_peer_session_id: 0,
            approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
            approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn neutral_descriptor_args_bind_only_a_validated_descriptor() {
        let root = TempRoot::new();
        let work = root.0.join("work");
        let descriptor_path = root.0.join("store-bootstrap.json");
        std::fs::write(
            &descriptor_path,
            serde_json::to_vec(&descriptor()).expect("descriptor JSON"),
        )
        .expect("descriptor file");
        let options = parse_launch_options([
            "--work-root".into(),
            work.clone().into_os_string(),
            "--store-bootstrap".into(),
            descriptor_path.clone().into_os_string(),
        ])
        .expect("neutral args");
        assert_eq!(
            options.work_root,
            std::fs::canonicalize(work).expect("work")
        );
        assert_eq!(
            options.store_config,
            Some(StoreConfigLocator::NeutralDescriptor(descriptor_path))
        );
        let prepared = prepare_store_bootstrap(&options)
            .expect("prepare descriptor")
            .expect("descriptor present");
        assert_eq!(prepared.requirement.authority_epoch().value(), 7);
        assert_eq!(prepared.requirement.store_generation.value(), 9);
    }

    #[test]
    fn descriptor_args_reject_concrete_store_config_flag() {
        let root = TempRoot::new();
        let result = parse_launch_options([
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-config".into(),
            root.0.join("store.json").into_os_string(),
        ]);
        assert!(result.is_err());
    }
}
