use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_kernel::{
    AuthorityDescriptorContour, EliotdReceiptRootBinding, KernelBuildError, KernelComposition,
    KernelConfig,
};
use eliot_kernel_service::{EliotdLaunchDescriptor, HostStoreBootstrapRequirement};
#[cfg(windows)]
use eliot_kernel_service::{
    KERNEL_CONTROL_PIPE, KernelControlCommand, control_response_frame, decode_control_request_frame,
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
    NamedPipePeerProcessBinding, ProtectedRuntimePathLease, UserOwnedPathLease, UserOwnedRootLease,
    current_process_named_pipe_expectation, observe_named_pipe_peer_process,
};
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelStartupBinding {
    control_pipe: String,
    host_process_id: u32,
    host_process_start: u64,
    host_process_image: String,
    receipt_root: PathBuf,
    kernel_ors_root: PathBuf,
    runtime_state_roots_digest: String,
    generation_config_digest: String,
    installation_id: String,
    approved_generation: String,
}

#[cfg(windows)]
impl KernelStartupBinding {
    fn from_environment() -> Result<Self, String> {
        Self::parse(
            std::env::var("ELIOT_KERNEL_CONTROL_PIPE").ok(),
            std::env::var("ELIOT_HOST_PROCESS_ID").ok(),
            std::env::var("ELIOT_HOST_PROCESS_START").ok(),
            std::env::var("ELIOT_HOST_PROCESS_IMAGE").ok(),
            std::env::var("ELIOT_KERNEL_RECEIPT_ROOT").ok(),
            std::env::var("ELIOT_KERNEL_ORS_ROOT").ok(),
            std::env::var("ELIOT_RUNTIME_STATE_ROOTS_DIGEST").ok(),
            std::env::var("ELIOT_GENERATION_CONFIG_DIGEST").ok(),
            std::env::var("ELIOT_HOST_INSTALLATION").ok(),
            std::env::var("ELIOT_APPROVED_GENERATION").ok(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn parse(
        control_pipe: Option<String>,
        host_process_id: Option<String>,
        host_process_start: Option<String>,
        host_process_image: Option<String>,
        receipt_root: Option<String>,
        kernel_ors_root: Option<String>,
        runtime_state_roots_digest: Option<String>,
        generation_config_digest: Option<String>,
        installation_id: Option<String>,
        approved_generation: Option<String>,
    ) -> Result<Self, String> {
        let control_pipe = control_pipe
            .filter(|pipe| pipe == KERNEL_CONTROL_PIPE)
            .ok_or_else(|| {
                "Host launch context did not inject the exact Kernel control pipe".to_owned()
            })?;
        let host_process_id = host_process_id
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                "Host launch context did not inject a valid Host process binding".to_owned()
            })?;
        let host_process_start = host_process_start
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                "Host launch context did not inject a valid Host process start time".to_owned()
            })?;
        let host_process_image = host_process_image
            .filter(|image| {
                !image.trim().is_empty()
                    && image == image.trim()
                    && !image.chars().any(char::is_control)
                    && Path::new(image).is_absolute()
            })
            .ok_or_else(|| {
                "Host launch context did not inject a canonical Host process image".to_owned()
            })?;
        let exact_root = |value: Option<String>, label: &str| {
            value
                .map(PathBuf::from)
                .filter(|root| {
                    root.is_absolute()
                        && !root.as_os_str().is_empty()
                        && !root.to_string_lossy().chars().any(char::is_control)
                })
                .ok_or_else(|| format!("Host launch context did not inject the exact {label}"))
        };
        let receipt_root = exact_root(receipt_root, "Kernel receipt root")?;
        let kernel_ors_root = exact_root(kernel_ors_root, "Kernel ORS root")?;
        let runtime_state_roots_digest = runtime_state_roots_digest
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                "Host launch context did not inject the RuntimeStateRoots digest".to_owned()
            })?;
        let generation_config_digest = generation_config_digest
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                "Host launch context did not inject the approved admission-config digest".to_owned()
            })?;
        let exact_identity = |value: Option<String>, label: &str| {
            value
                .filter(|value| {
                    !value.trim().is_empty()
                        && value == value.trim()
                        && !value.chars().any(char::is_control)
                })
                .ok_or_else(|| format!("Host launch context did not inject the exact {label}"))
        };
        let installation_id = exact_identity(installation_id, "installation identity")?;
        let approved_generation = exact_identity(approved_generation, "approved generation")?;
        Ok(Self {
            control_pipe,
            host_process_id,
            host_process_start,
            host_process_image,
            receipt_root,
            kernel_ors_root,
            runtime_state_roots_digest,
            generation_config_digest,
            installation_id,
            approved_generation,
        })
    }

    fn observe_host(&self) -> Result<NamedPipePeerProcessBinding, String> {
        let observed = observe_named_pipe_peer_process(self.host_process_id)
            .map_err(|error| error.to_string())?;
        if !self.matches_observed(
            observed.process_id(),
            observed.start_time_100ns(),
            observed.image_path(),
        ) {
            return Err("live Host process binding changed before Kernel admission".to_owned());
        }
        Ok(observed)
    }

    fn matches_observed(&self, process_id: u32, start_time_100ns: u64, image_path: &str) -> bool {
        self.host_process_id == process_id
            && self.host_process_start == start_time_100ns
            && self.host_process_image == image_path
    }
}

/// Keeps startup, authenticated listener rotation, and fenced shutdown in one
/// ordered authority path.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    let options = match parse_launch_options(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    #[cfg(windows)]
    let startup_binding = match KernelStartupBinding::from_environment() {
        Ok(binding) => binding,
        Err(error) => exit_error("PRINCIPAL_FAILURE", &error),
    };
    let prepared_store = match prepare_store_bootstrap(&options) {
        Ok(prepared) => prepared,
        Err(error) => exit_error("INVALID_STORE_BOOTSTRAP", &error),
    };
    let daemon_launch = match prepare_eliotd_launch(&options) {
        Ok(Some(launch)) => Some(launch),
        Ok(None) => exit_error(
            "ELIOTD_LAUNCH_CONTRACT_REQUIRED",
            "Host launch must inject the exact approved eliotd descriptor and digest",
        ),
        Err(error) => exit_error("INVALID_ELIOTD_LAUNCH", &error),
    };
    let mut kernel_config =
        KernelConfig::new(options.work_root.clone()).require_descriptor_supervision_authority();
    #[cfg(windows)]
    let pipe_name = startup_binding.control_pipe.clone();
    #[cfg(not(windows))]
    let pipe_name = std::env::var("ELIOT_KERNEL_CONTROL_PIPE").unwrap_or_default();
    kernel_config = kernel_config.with_pipe_name(pipe_name);
    #[cfg(windows)]
    {
        let receipt_binding = EliotdReceiptRootBinding::new(
            startup_binding.receipt_root.clone(),
            startup_binding.kernel_ors_root.clone(),
            startup_binding.runtime_state_roots_digest.clone(),
            startup_binding.installation_id.clone(),
            startup_binding.approved_generation.clone(),
        )
        .unwrap_or_else(|error| exit_error("PRINCIPAL_FAILURE", &error));
        kernel_config = kernel_config.with_eliotd_receipt_binding(receipt_binding);
    }
    if let Some(prepared) = &prepared_store {
        kernel_config = kernel_config.with_store_bootstrap(prepared.requirement.clone());
    }
    if let Some(daemon_launch) = daemon_launch {
        kernel_config = kernel_config.with_daemon_launch(daemon_launch);
    }
    let Some(kernel_artifact_sha256) = options.kernel_artifact_sha256.clone() else {
        exit_error(
            "KERNEL_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the independent Kernel executable digest",
        );
    };
    kernel_config = kernel_config.with_kernel_artifact_sha256(kernel_artifact_sha256);
    let Some(eliotd_descriptor_artifact_sha256) = options.daemon_sha256.clone() else {
        exit_error(
            "ELIOTD_LAUNCH_CONTRACT_REQUIRED",
            "Host launch must inject the exact eliotd descriptor file digest",
        );
    };
    kernel_config =
        kernel_config.with_eliotd_descriptor_artifact_sha256(eliotd_descriptor_artifact_sha256);
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
    if kernel.supervision_lease_authority().is_none() {
        exit_error(
            "SUPERVISION_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the installer-provisioned supervision authority before Kernel readiness",
        );
    }
    #[cfg(windows)]
    {
        let observed_host = match startup_binding.observe_host() {
            Ok(binding) => binding,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error),
        };
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
                    std::time::Duration::from_hours(24),
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
                        let result = Box::pin(serve_connection(
                            task_kernel,
                            accepted_server,
                            task_shutdown,
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
#[allow(
    clippy::too_many_lines,
    reason = "authenticated front-door receive, handshake, and control dispatch stay ordered"
)]
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
                let response = kernel
                    .execute_process_request(&session, session_binding, request)
                    .await;
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
    daemon_descriptor: Option<PathBuf>,
    daemon_sha256: Option<String>,
    kernel_artifact_sha256: Option<String>,
}

struct PreparedStoreBootstrap {
    requirement: HostStoreBootstrapRequirement,
}

#[allow(
    clippy::too_many_lines,
    reason = "the ordered startup contract is kept in one parser so production cannot accept partially bound contours"
)]
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
            kernel_artifact_flag,
            kernel_artifact_digest,
            daemon_flag,
            daemon_path,
            daemon_digest_flag,
            daemon_digest,
        ] if work_flag == "--work-root"
            && store_flag == "--store-bootstrap"
            && store_digest_flag == "--store-bootstrap-sha256"
            && authority_flag == "--authority-descriptor"
            && authority_digest_flag == "--authority-descriptor-sha256"
            && kernel_artifact_flag == "--kernel-artifact-sha256"
            && daemon_flag == "--eliotd-descriptor"
            && daemon_digest_flag == "--eliotd-descriptor-sha256" =>
        {
            let store_digest = store_digest.to_string_lossy();
            let authority_digest = authority_digest.to_string_lossy();
            let kernel_artifact_digest = kernel_artifact_digest.to_string_lossy();
            let daemon_digest = daemon_digest.to_string_lossy();
            if !is_lower_sha256(&store_digest)
                || !is_lower_sha256(&authority_digest)
                || !is_lower_sha256(&kernel_artifact_digest)
                || !is_lower_sha256(&daemon_digest)
            {
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
                daemon_descriptor: Some(PathBuf::from(daemon_path)),
                daemon_sha256: Some(daemon_digest.into_owned()),
                kernel_artifact_sha256: Some(kernel_artifact_digest.into_owned()),
            })
        }
        _ => Err(invalid_input(
            "expected the exact mandatory 16-value Host launch contour",
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

fn prepare_eliotd_launch(
    options: &KernelLaunchOptions,
) -> Result<Option<EliotdLaunchDescriptor>, String> {
    let (Some(path), Some(expected_digest)) = (&options.daemon_descriptor, &options.daemon_sha256)
    else {
        return Ok(None);
    };
    let bytes = read_descriptor_bounded(path, &options.work_root)?;
    if sha256_hex(&bytes) != expected_digest.as_str() {
        return Err("eliotd launch descriptor digest mismatch".to_owned());
    }
    let descriptor: EliotdLaunchDescriptor = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse eliotd launch descriptor: {error}"))?;
    descriptor
        .validate()
        .map_err(|error| format!("validate eliotd launch descriptor: {error}"))?;
    Ok(Some(descriptor))
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
        let file = ProtectedRuntimePathLease::open_existing_absolute(&canonical)
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
    fn launch_args_reject_legacy_ten_value_contour() {
        let root = TempRoot::new();
        let work = root.0.join("work");
        let descriptor_path = root.0.join("store-bootstrap.json");
        let authority_path = root.0.join("authority.json");
        let digest = "a".repeat(64);
        let result = parse_launch_options([
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
        ]);
        assert!(
            result.is_err(),
            "legacy contour must not bypass eliotd binding"
        );

        let _ = (work, descriptor_path, digest);
    }

    #[test]
    fn launch_args_reject_descriptor_contour_without_kernel_artifact_domain() {
        let root = TempRoot::new();
        let digest = "a".repeat(64);
        let result = parse_launch_options([
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-bootstrap".into(),
            root.0.join("store-bootstrap.json").into_os_string(),
            "--store-bootstrap-sha256".into(),
            digest.clone().into(),
            "--authority-descriptor".into(),
            root.0.join("authority.json").into_os_string(),
            "--authority-descriptor-sha256".into(),
            digest.clone().into(),
            "--eliotd-descriptor".into(),
            root.0.join("eliotd.json").into_os_string(),
            "--eliotd-descriptor-sha256".into(),
            digest.into(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn launch_args_accept_the_explicit_kernel_and_eliotd_artifact_domains() {
        let root = TempRoot::new();
        let digest = "a".repeat(64);
        let options = parse_launch_options([
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-bootstrap".into(),
            root.0.join("store-bootstrap.json").into_os_string(),
            "--store-bootstrap-sha256".into(),
            digest.clone().into(),
            "--authority-descriptor".into(),
            root.0.join("authority.json").into_os_string(),
            "--authority-descriptor-sha256".into(),
            digest.clone().into(),
            "--kernel-artifact-sha256".into(),
            digest.clone().into(),
            "--eliotd-descriptor".into(),
            root.0.join("eliotd.json").into_os_string(),
            "--eliotd-descriptor-sha256".into(),
            digest.clone().into(),
        ])
        .expect("integrated args");
        assert_eq!(options.kernel_artifact_sha256, Some(digest));
        assert_eq!(options.daemon_descriptor, Some(root.0.join("eliotd.json")));
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
            "--kernel-artifact-sha256".into(),
            "c".repeat(64).into(),
            "--eliotd-descriptor".into(),
            root.0.join("eliotd.json").into_os_string(),
            "--eliotd-descriptor-sha256".into(),
            "d".repeat(64).into(),
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

    #[cfg(windows)]
    fn exact_startup_values() -> [Option<String>; 10] {
        [
            Some(KERNEL_CONTROL_PIPE.to_owned()),
            Some("41".to_owned()),
            Some("73".to_owned()),
            Some(r"C:\eliot\eliot-host.exe".to_owned()),
            Some(r"C:\ProgramData\Eliot\installations\a\host".to_owned()),
            Some(r"C:\ProgramData\Eliot\installations\a\kernel\state".to_owned()),
            Some("a".repeat(64)),
            Some("b".repeat(64)),
            Some("installation-a".to_owned()),
            Some("generation-a".to_owned()),
        ]
    }

    #[cfg(windows)]
    fn parse_startup_values(values: &[Option<String>; 10]) -> Result<KernelStartupBinding, String> {
        KernelStartupBinding::parse(
            values[0].clone(),
            values[1].clone(),
            values[2].clone(),
            values[3].clone(),
            values[4].clone(),
            values[5].clone(),
            values[6].clone(),
            values[7].clone(),
            values[8].clone(),
            values[9].clone(),
        )
    }

    #[cfg(windows)]
    fn exact_startup_binding() -> KernelStartupBinding {
        parse_startup_values(&exact_startup_values()).expect("exact startup binding")
    }

    #[cfg(windows)]
    #[test]
    fn kernel_startup_binding_requires_every_exact_launch_value() {
        let exact = exact_startup_values();
        for missing in 0..exact.len() {
            let mut values = exact.clone();
            values[missing] = None;
            assert!(parse_startup_values(&values).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn kernel_startup_binding_rejects_substituted_authority_values() {
        for (index, substitute) in [
            (0, r"\\.\pipe\eliot\kernel\substitute".to_owned()),
            (1, "0".to_owned()),
            (2, "0".to_owned()),
            (3, "eliot-host.exe".to_owned()),
            (4, "relative-host-root".to_owned()),
            (5, "relative-ors-root".to_owned()),
            (6, "A".repeat(64)),
            (7, "B".repeat(64)),
            (8, " substituted-installation".to_owned()),
            (9, "substituted-generation\n".to_owned()),
        ] {
            let mut values = exact_startup_values();
            values[index] = Some(substitute);
            assert!(parse_startup_values(&values).is_err(), "index {index}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn kernel_startup_binding_rejects_pid_reuse_and_image_substitution() {
        let binding = exact_startup_binding();
        assert!(binding.matches_observed(41, 73, r"C:\eliot\eliot-host.exe"));
        assert!(!binding.matches_observed(42, 73, r"C:\eliot\eliot-host.exe"));
        assert!(!binding.matches_observed(41, 74, r"C:\eliot\eliot-host.exe"));
        assert!(!binding.matches_observed(41, 73, r"C:\eliot\replacement.exe"));
    }
}
