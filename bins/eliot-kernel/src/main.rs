use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_kernel::{
    KernelBuildError, KernelComposition, KernelConfig, PROTOCOL_VERSION, SERVICE_NAME,
    default_work_root,
};
use eliot_kernel_service::HostStoreBootstrapRequirement;
use eliot_platform::PlatformHandle;
use eliot_store_surreal::{StoreLaunchConfig, load_config};

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
    #[cfg(windows)]
    {
        if let Some(prepared) = prepared_store
            && let Err(error) = kernel
                .connect_canonical_store(prepared.connect_timeout)
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
    Protected(PathBuf),
    PortableDev { root: PathBuf, path: PathBuf },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelLaunchOptions {
    work_root: PathBuf,
    store_config: Option<StoreConfigLocator>,
}

struct PreparedStoreBootstrap {
    requirement: HostStoreBootstrapRequirement,
    connect_timeout: Duration,
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
        [work_flag, work_root, store_flag, store_config]
            if work_flag == "--work-root" && store_flag == "--store-config" =>
        {
            Ok(KernelLaunchOptions {
                work_root: canonical_directory(work_root)?,
                store_config: Some(StoreConfigLocator::Protected(PathBuf::from(store_config))),
            })
        }
        [
            portable_flag,
            portable_root,
            work_flag,
            work_root,
            store_flag,
            store_config,
        ] if portable_flag == "--portable-dev-root"
            && work_flag == "--work-root"
            && store_flag == "--store-config" =>
        {
            let portable_root = canonical_directory(portable_root)?;
            let work_root = canonical_directory(work_root)?;
            if !work_root.starts_with(&portable_root) {
                return Err(invalid_input(
                    "portable-dev work root must remain under --portable-dev-root",
                ));
            }
            Ok(KernelLaunchOptions {
                work_root,
                store_config: Some(StoreConfigLocator::PortableDev {
                    root: portable_root,
                    path: PathBuf::from(store_config),
                }),
            })
        }
        _ => Err(invalid_input(
            "expected no args, --work-root <path>, --work-root <path> --store-config <path>, or --portable-dev-root <root> --work-root <path> --store-config <path>",
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
    let config = match locator {
        StoreConfigLocator::Protected(path) => load_config(Some(path))?,
        StoreConfigLocator::PortableDev { root, path } => {
            let root = eliot_platform_windows::UserOwnedRootLease::open_existing(root)
                .map_err(|error| format!("open portable-dev root: {error}"))?;
            eliot_store_surreal::load_portable_dev_config(&root, path)?
        }
    };
    let connect_timeout = Duration::from_millis(config.connect_timeout_ms);
    let requirement = store_bootstrap_requirement(&config)?;
    Ok(Some(PreparedStoreBootstrap {
        requirement,
        connect_timeout,
    }))
}

fn store_bootstrap_requirement(
    config: &StoreLaunchConfig,
) -> Result<HostStoreBootstrapRequirement, String> {
    config.validate()?;
    let authority_epoch = AuthorityEpoch::new(config.authority_epoch)
        .map_err(|error| format!("invalid Store authority epoch: {error}"))?;
    let store_generation = ResourceGeneration::new(config.store_generation)
        .map_err(|error| format!("invalid Store generation: {error}"))?;
    let connection_id = format!(
        "kernel-store:{}:{}",
        config.instance_id, config.launch_nonce
    );
    Ok(HostStoreBootstrapRequirement {
        store_pipe: platform_handle(&config.store_pipe, "store pipe")?,
        store_generation,
        schema_generation: platform_handle(&config.schema_generation, "schema generation")?,
        state_fence: StateFence::new(authority_epoch, store_generation),
        launch_nonce: platform_handle(&config.launch_nonce, "launch nonce")?,
        connection_id: platform_handle(&connection_id, "connection id")?,
        expected_peer_sid: platform_handle(&config.expected_client_sid, "Store peer SID")?,
        expected_peer_session_id: config.expected_client_session_id,
        approved_artifact_hash: platform_handle(
            &config.approved_artifact_hash,
            "Store artifact digest",
        )?,
        approved_config_hash: platform_handle(&config.approved_config_hash, "Store config digest")?,
    })
}

fn platform_handle(value: &str, field: &str) -> Result<PlatformHandle, String> {
    PlatformHandle::new(value).map_err(|error| format!("invalid {field}: {error}"))
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
    use eliot_store_surreal::launch_config_digest;

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

    fn store_config() -> StoreLaunchConfig {
        let mut config = StoreLaunchConfig {
            store_pipe: r"\\.\pipe\eliot\store-kernel-main-test".to_owned(),
            launch_nonce: "kernel-main-test".to_owned(),
            expected_client_sid: "S-1-5-18".to_owned(),
            expected_client_session_id: 0,
            approved_artifact_hash: "a".repeat(64),
            approved_config_hash: String::new(),
            store_generation: 9,
            authority_epoch: 7,
            endpoint: "ws://127.0.0.1:8000".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "store".to_owned(),
            connect_timeout_ms: 5_000,
            query_timeout_ms: 5_000,
            schema_generation: "1.0.0".to_owned(),
            blob_root: r"C:\Eliot\blob".to_owned(),
            instance_id: "kernel-main-test".to_owned(),
            credential_ref: "eliot/store".to_owned(),
        };
        config.approved_config_hash = launch_config_digest(&config).expect("config digest");
        config
    }

    #[test]
    fn portable_dev_args_bind_work_and_config_to_explicit_root() {
        let root = TempRoot::new();
        let work = root.0.join("work");
        let config = root.0.join("store.json");
        let options = parse_launch_options([
            "--portable-dev-root".into(),
            root.0.clone().into_os_string(),
            "--work-root".into(),
            work.clone().into_os_string(),
            "--store-config".into(),
            config.clone().into_os_string(),
        ])
        .expect("portable args");
        assert_eq!(
            options.work_root,
            std::fs::canonicalize(work).expect("work")
        );
        assert_eq!(
            options.store_config,
            Some(StoreConfigLocator::PortableDev {
                root: std::fs::canonicalize(&root.0).expect("root"),
                path: config,
            })
        );
    }

    #[test]
    fn portable_dev_args_reject_work_root_outside_contour() {
        let root = TempRoot::new();
        let outside = TempRoot::new();
        let result = parse_launch_options([
            "--portable-dev-root".into(),
            root.0.clone().into_os_string(),
            "--work-root".into(),
            outside.0.join("work").into_os_string(),
            "--store-config".into(),
            root.0.join("store.json").into_os_string(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn store_bootstrap_uses_non_genesis_config_fence() {
        let config = store_config();
        let requirement = store_bootstrap_requirement(&config).expect("bootstrap requirement");
        assert_eq!(requirement.authority_epoch().value(), 7);
        assert_eq!(requirement.store_generation.value(), 9);
        assert_eq!(requirement.state_fence.resource_generation.value(), 9);
        assert_eq!(
            requirement.approved_config_hash.as_str(),
            config.approved_config_hash
        );
    }
}
