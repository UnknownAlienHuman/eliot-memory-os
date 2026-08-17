use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eliot_kernel::{AuthorityDescriptorContour, KernelBuildError, KernelComposition, KernelConfig};
use eliot_kernel_service::HostStoreBootstrapRequirement;
#[cfg(windows)]
use eliot_kernel_service::{
    KernelControlCommand, control_response_frame, decode_control_request_frame,
};

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

use eliot_contracts::sha256_hex;
#[cfg(windows)]
use eliot_platform_windows::{
    ProtectedPathLease, UserOwnedPathLease, UserOwnedRootLease,
    current_process_named_pipe_expectation, observe_named_pipe_peer_process,
};

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
    let mut kernel_config = KernelConfig::new(options.work_root.clone());
    let pipe_name = match std::env::var("ELIOT_KERNEL_CONTROL_PIPE") {
        Ok(value) => value,
        Err(_) => exit_error(
            "INVALID_CONFIGURATION",
            "Host launch context did not inject the generation-specific Kernel control pipe",
        ),
    };
    kernel_config = kernel_config.with_pipe_name(pipe_name);
    if let Some(prepared) = &prepared_store {
        kernel_config = kernel_config.with_store_bootstrap(prepared.requirement.clone());
    }
    let authority_path = options.authority_descriptor.clone();
    let authority_contour = authority_contour(&options.work_root, &authority_path);
    let kernel = Arc::new(
        match KernelComposition::new_with_authority_descriptor(
            kernel_config,
            &authority_path,
            &options.authority_sha256,
            authority_contour,
        ) {
            Ok(kernel) => kernel,
            Err(error) => exit_build_error(&error),
        },
    );
    if !kernel.process_execution_configured() {
        exit_error(
            "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the external process authority handoff before Kernel readiness",
        );
    }
    #[cfg(windows)]
    {
        if let Some(prepared) = prepared_store {
            let timeout = Duration::from_millis(prepared.requirement.timeout_ms());
            let mut connected = false;
            for attempt in 0..3 {
                match kernel.connect_canonical_store(timeout).await {
                    Ok(_) => {
                        connected = true;
                        break;
                    }
                    Err(error) if attempt < 2 => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let _ = error;
                    }
                    Err(error) => exit_build_error(&error),
                }
            }
            if !connected {
                exit_error("STORE_UNAVAILABLE", "canonical Store did not become ready");
            }
        }
        let host_pid = match std::env::var("ELIOT_HOST_PROCESS_ID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        {
            Some(pid) if pid != 0 => pid,
            _ => exit_error(
                "PRINCIPAL_FAILURE",
                "Host launch context did not inject a valid Host process binding",
            ),
        };
        let host_start = match std::env::var("ELIOT_HOST_PROCESS_START")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(start) if start != 0 => start,
            _ => exit_error(
                "PRINCIPAL_FAILURE",
                "Host launch context did not inject a valid Host process start time",
            ),
        };
        let host_image = match std::env::var("ELIOT_HOST_PROCESS_IMAGE") {
            Ok(image) if !image.trim().is_empty() => image,
            _ => exit_error(
                "PRINCIPAL_FAILURE",
                "Host launch context did not inject a Host process image",
            ),
        };
        let observed_host = match observe_named_pipe_peer_process(host_pid) {
            Ok(binding) => binding,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
        };
        if observed_host.start_time_100ns() != host_start
            || observed_host.image_path() != host_image
        {
            exit_error(
                "PRINCIPAL_FAILURE",
                "live Host process binding changed before Kernel admission",
            );
        }
        let principal = match current_process_named_pipe_expectation()
            .and_then(|expectation| expectation.with_process_binding(observed_host))
        {
            Ok(expectation) => expectation,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
        };
        let mut front_door = match kernel.bind_authenticated_front_door() {
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
        let _ = kernel;
        exit_error(
            "AUTHENTICATED_CONTROL_UNSUPPORTED",
            "Host/Kernel control requires the Windows authenticated named-pipe boundary",
        );
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
    let peer = front_door.peer_identity().clone();
    if decode_control_request_frame(&client_frame).is_ok() {
        return serve_control_connection(kernel, front_door, shutdown, client_frame, peer).await;
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
        let response = kernel
            .apply_control_request(request, &peer, expected_sequence)
            .await?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoreConfigLocator {
    NeutralDescriptor(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelLaunchOptions {
    work_root: PathBuf,
    store_config: Option<StoreConfigLocator>,
    store_sha256: String,
    authority_descriptor: PathBuf,
    authority_sha256: String,
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
        [] => Err(invalid_input("exact Host launch arguments are required")),
        [
            work_flag,
            work_root,
            store_flag,
            descriptor,
            store_digest_flag,
            store_digest,
            authority_flag,
            authority_path,
            authority_digest_flag,
            authority_digest,
        ] if work_flag == "--work-root"
            && store_flag == "--store-bootstrap"
            && store_digest_flag == "--store-bootstrap-sha256"
            && authority_flag == "--authority-descriptor"
            && authority_digest_flag == "--authority-descriptor-sha256" =>
        {
            let store_digest = store_digest.to_string_lossy();
            let authority_digest = authority_digest.to_string_lossy();
            if !is_lower_sha256(&store_digest) || !is_lower_sha256(&authority_digest) {
                return Err(invalid_input(
                    "descriptor digests must be lowercase SHA-256",
                ));
            }
            Ok(KernelLaunchOptions {
                work_root: canonical_directory(work_root)?,
                store_config: Some(StoreConfigLocator::NeutralDescriptor(PathBuf::from(
                    descriptor,
                ))),
                store_sha256: store_digest.into_owned(),
                authority_descriptor: PathBuf::from(authority_path),
                authority_sha256: authority_digest.into_owned(),
            })
        }
        _ => Err(invalid_input(
            "expected the exact 10-value Host launch contour",
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
    let bytes = read_descriptor_bounded(path, &options.work_root)?;
    let expected_digest = options.store_digest();
    if sha256_hex(&bytes) != expected_digest {
        return Err("neutral Store bootstrap descriptor digest mismatch".to_owned());
    }
    let requirement: HostStoreBootstrapRequirement = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse neutral store bootstrap descriptor: {error}"))?;
    requirement
        .validate()
        .map_err(|error| format!("validate neutral store bootstrap descriptor: {error}"))?;
    Ok(Some(PreparedStoreBootstrap { requirement }))
}

impl KernelLaunchOptions {
    fn store_digest(&self) -> &str {
        &self.store_sha256
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn authority_contour(work_root: &Path, path: &Path) -> AuthorityDescriptorContour {
    if path.starts_with(work_root) {
        AuthorityDescriptorContour::PortableCurrentUser {
            root: work_root.to_path_buf(),
        }
    } else {
        AuthorityDescriptorContour::ProgramData
    }
}

#[cfg(windows)]
fn read_descriptor_bounded(path: &Path, work_root: &Path) -> Result<Vec<u8>, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("descriptor path could not be retained: {error}"))?;
    if canonical.starts_with(work_root) {
        let root = UserOwnedRootLease::open_existing(work_root)
            .map_err(|error| format!("user-owned root unavailable: {error}"))?;
        let file = UserOwnedPathLease::open_existing(&root, &canonical)
            .map_err(|error| format!("user-owned descriptor unavailable: {error}"))?;
        file.verify_stable_identity()
            .and_then(|()| file.verify_path_identity())
            .map_err(|error| format!("user-owned descriptor identity changed: {error}"))?;
        file.read_bounded(1024 * 1024)
            .map_err(|error| format!("bounded descriptor read failed: {error}"))
    } else {
        let file = ProtectedPathLease::open_existing_absolute(&canonical)
            .map_err(|error| format!("protected descriptor unavailable: {error}"))?;
        file.verify_stable_identity()
            .and_then(|()| file.verify_path_identity())
            .map_err(|error| format!("protected descriptor identity changed: {error}"))?;
        file.read_bounded(1024 * 1024)
            .map_err(|error| format!("bounded descriptor read failed: {error}"))
    }
}

#[cfg(not(windows))]
fn read_descriptor_bounded(_path: &Path, _work_root: &Path) -> Result<Vec<u8>, String> {
    Err("authenticated descriptor reads require Windows protected leases".to_owned())
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

    #[test]
    fn launch_args_require_the_exact_ordered_ten_values() {
        let root = TempRoot::new();
        let work = root.0.join("work");
        let descriptor_path = root.0.join("store-bootstrap.json");
        let authority_path = root.0.join("authority.json");
        let digest = "a".repeat(64);
        let options = parse_launch_options([
            "--work-root".into(),
            work.clone().into_os_string(),
            "--store-bootstrap".into(),
            descriptor_path.clone().into_os_string(),
            "--store-bootstrap-sha256".into(),
            digest.clone().into(),
            "--authority-descriptor".into(),
            authority_path.clone().into_os_string(),
            "--authority-descriptor-sha256".into(),
            digest.clone().into(),
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
        assert_eq!(options.store_sha256, digest);
        assert_eq!(options.authority_sha256, "a".repeat(64));
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

    #[test]
    fn launch_args_reject_case_variants_duplicates_and_reordering() {
        let root = TempRoot::new();
        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        let valid: Vec<std::ffi::OsString> = vec![
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-bootstrap".into(),
            "store.json".into(),
            "--store-bootstrap-sha256".into(),
            digest_a.into(),
            "--authority-descriptor".into(),
            "authority.json".into(),
            "--authority-descriptor-sha256".into(),
            digest_b.into(),
        ];
        let mut case_variant = valid.clone();
        case_variant[0] = "--Work-root".into();
        assert!(parse_launch_options(case_variant).is_err());
        let mut reordered = valid.clone();
        reordered.swap(2, 4);
        assert!(parse_launch_options(reordered).is_err());
        let mut duplicate = valid;
        duplicate[6] = "--store-bootstrap".into();
        assert!(parse_launch_options(duplicate).is_err());
    }
}
