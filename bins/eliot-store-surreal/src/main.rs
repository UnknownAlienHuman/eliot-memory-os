use std::path::PathBuf;
use std::time::Duration;

#[cfg(windows)]
use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SourceId, StateFence,
};
#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::TransportLimits;
#[cfg(windows)]
use eliot_platform::{ClockPort, ClockRequest, PortOutcome};
#[cfg(windows)]
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use eliot_store_surreal::{
    SERVICE_NAME, StoreComposition, StoreHandshakeIdentity, admit_handshake, dispatch, load_config,
    load_portable_dev_config, validate_request_frame,
};

#[derive(Debug, Eq, PartialEq)]
enum LaunchMode {
    Protected {
        config_path: PathBuf,
    },
    PortableDev {
        root: PathBuf,
        config_path: PathBuf,
        initialize_schema_only: bool,
    },
}

#[tokio::main]
// This standalone service has no initialized telemetry sink before startup;
// stderr is the only fail-closed launch diagnostic available to its supervisor.
#[allow(clippy::print_stderr)]
async fn main() {
    if let Err(error) = Box::pin(run()).await {
        eprintln!("{SERVICE_NAME}: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
#[allow(clippy::print_stdout)]
async fn run() -> Result<(), String> {
    let mode = parse_launch_mode(std::env::args_os().skip(1))?;
    let Some(config) = prepare_launch(mode).await? else {
        return Ok(());
    };
    let composition = StoreComposition::new(&config)?;

    let limits = TransportLimits::default();
    let expectation = eliot_platform_windows::NamedPipePeerExpectation::new(
        config.expected_client_sid.clone(),
        config.expected_client_session_id,
    )
    .map_err(|error| format!("invalid peer expectation: {error}"))?;
    let mut server = NamedPipeServer::create(&config.store_pipe, &expectation)
        .map_err(|error| format!("named-pipe creation failed: {error}"))?;
    server
        .wait_for_authenticated_client(
            Duration::from_millis(config.connect_timeout_ms),
            &expectation,
        )
        .await
        .map_err(|error| format!("authenticated client admission failed: {error}"))?;
    let hello_frame = server
        .receive_frame(limits)
        .await
        .map_err(|error| format!("EBP hello receive failed: {error}"))?;
    let handshake_identity = StoreHandshakeIdentity::new(
        composition.operation_manifest_digest().to_owned(),
        serde_json::json!({
            "root_id": composition.blob_owner().root_id(),
            "owner_id": composition.blob_owner().owner_id().as_str(),
            "process_id": composition.blob_owner().process_id(),
            "claim_id": composition.blob_owner().claim_id(),
        }),
    );
    let (mut session, server_hello) =
        admit_handshake(hello_frame, limits, &config, &handshake_identity)?;
    let mut negotiated_limits = limits;
    negotiated_limits.max_frame_bytes = session.max_frame_bytes();
    let handshake_frame = control_frame(
        session.connection_id(),
        session.protocol_version(),
        MessageType::Ready,
        serde_json::to_value(server_hello)
            .map_err(|error| format!("serialize ServerHello: {error}"))?,
    );
    server
        .send_frame(&handshake_frame, negotiated_limits)
        .await
        .map_err(|error| format!("EBP handshake response failed: {error}"))?;

    loop {
        let frame = server
            .receive_frame(negotiated_limits)
            .await
            .map_err(|error| format!("EBP frame rejected: {error}"))?;
        let response = match validate_request_frame(&mut session, &frame) {
            Ok(request) => dispatch(&composition, request).await,
            Err(error) => eliot_store_surreal::Response::Error { error },
        };
        let response_frame = eliot_store_api::response_frame(
            session.connection_id(),
            session.protocol_version(),
            frame.request_id.clone(),
            response,
        )
        .map_err(|error| format!("invalid EBP response: {error}"))?;
        server
            .send_frame(&response_frame, negotiated_limits)
            .await
            .map_err(|error| format!("EBP response failed: {error}"))?;
    }
}

#[cfg(windows)]
#[allow(clippy::print_stdout)]
async fn prepare_launch(
    mode: LaunchMode,
) -> Result<Option<eliot_store_surreal::StoreLaunchConfig>, String> {
    match mode {
        LaunchMode::Protected { config_path } => load_config(Some(&config_path)).map(Some),
        LaunchMode::PortableDev {
            root,
            config_path,
            initialize_schema_only,
        } => {
            let root = eliot_platform_windows::UserOwnedRootLease::open_existing(&root)
                .map_err(|error| format!("open portable-dev root: {error}"))?;
            let config_path = if config_path.is_absolute() {
                config_path
            } else {
                root.path().join(config_path)
            };
            let config = load_portable_dev_config(&root, &config_path)?;
            if initialize_schema_only {
                let composition = StoreComposition::new(&config)?;
                let clock = read_portable_dev_clock(&config)?;
                let receipt = composition
                    .apply_initial_schema_migration(&clock)
                    .await
                    .map_err(|error| error.to_string())?;
                let output = serde_json::json!({
                    "service": SERVICE_NAME,
                    "operation": "initialize_schema_only",
                    "migration_id": receipt.migration_id,
                    "checksum_sha256": receipt.checksum_sha256,
                    "generation_after": receipt.generation_after.as_str(),
                });
                println!(
                    "{}",
                    serde_json::to_string(&output)
                        .map_err(|error| format!("serialize migration receipt: {error}"))?
                );
                return Ok(None);
            }
            Ok(Some(config))
        }
    }
}

#[cfg(windows)]
fn read_portable_dev_clock(
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> Result<eliot_platform::ClockObservation, String> {
    let authority_epoch = AuthorityEpoch::new(config.authority_epoch)
        .map_err(|error| format!("invalid clock authority epoch: {error}"))?;
    let resource_generation = ResourceGeneration::new(config.store_generation)
        .map_err(|error| format!("invalid clock resource generation: {error}"))?;
    let request = ClockRequest {
        context: RequestMetadata {
            request_id: RequestId::new(format!(
                "portable-dev-schema-init-{}-{}",
                config.instance_id, config.launch_nonce
            ))
            .map_err(|error| format!("invalid clock request id: {error}"))?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new(SERVICE_NAME)
                .map_err(|error| format!("invalid clock product id: {error}"))?,
            source_id: SourceId::new(config.instance_id.clone())
                .map_err(|error| format!("invalid clock source id: {error}"))?,
            state_fence: StateFence::new(authority_epoch, resource_generation),
            clock: ClockReading::default(),
        },
    };
    let mut platform = WindowsPlatform::new(config.blob_root.clone())
        .map_err(|error| format!("initialize P-01 clock platform: {error}"))?;
    match platform.read(&request) {
        PortOutcome::Known(observation) => {
            observation
                .validate()
                .map_err(|error| format!("invalid P-01 clock observation: {error}"))?;
            Ok(observation)
        }
        PortOutcome::Partial { .. } => Err("P-01 clock observation was partial".to_owned()),
        PortOutcome::Unknown(reason) => Err(format!("P-01 clock observation unknown: {reason}")),
        PortOutcome::Error(error) => Err(format!("P-01 clock observation failed: {error}")),
    }
}

#[cfg(not(windows))]
async fn run() -> Result<(), String> {
    Err("the production store endpoint requires Windows authenticated named pipes".to_owned())
}

/// Supported launch forms are deliberately closed:
///
/// - `eliot-store-surreal --config <protected .json or .toml path>`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path>`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path> --initialize-schema-only`
fn parse_launch_mode<I>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args = args.into_iter();
    match args.next() {
        None => Err("--config is required; launch config must be explicit".to_owned()),
        Some(value) if value == "--config" => match args.next() {
            Some(path) if args.next().is_none() => Ok(LaunchMode::Protected {
                config_path: PathBuf::from(path),
            }),
            _ => Err("--config requires exactly one path".to_owned()),
        },
        Some(value) if value == "--portable-dev-root" => {
            let root = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--portable-dev-root requires one root path".to_owned())?;
            if !root.is_absolute() {
                return Err("--portable-dev-root requires an absolute root path".to_owned());
            }
            if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
                return Err(
                    "portable-dev launch requires --config immediately after the root".to_owned(),
                );
            }
            let config_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--config requires exactly one path".to_owned())?;
            let initialize_schema_only = match args.next() {
                None => false,
                Some(flag) if flag == "--initialize-schema-only" && args.next().is_none() => true,
                Some(_) => {
                    return Err(
                        "portable-dev launch accepts only --initialize-schema-only after --config"
                            .to_owned(),
                    );
                }
            };
            Ok(LaunchMode::PortableDev {
                root,
                config_path,
                initialize_schema_only,
            })
        }
        Some(value) => Err(format!("unknown argument: {}", value.to_string_lossy())),
    }
}

fn control_frame(
    connection_id: &str,
    protocol_version: ProtocolVersion,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Frame {
    Frame {
        protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.to_owned(),
        request_id: None,
        kind: FrameKind::Control,
        message_type,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn parser_accepts_protected_config_mode() {
        assert_eq!(
            parse_launch_mode(args(&["--config", "C:\\ProgramData\\Eliot\\store.json"]))
                .expect("protected mode should parse"),
            LaunchMode::Protected {
                config_path: PathBuf::from("C:\\ProgramData\\Eliot\\store.json"),
            }
        );
    }

    #[test]
    fn parser_accepts_exact_portable_dev_form() {
        let root = std::env::current_dir().expect("current directory should exist");
        let config = root.join("store.json");
        assert_eq!(
            parse_launch_mode(vec![
                "--portable-dev-root".into(),
                root.clone().into_os_string(),
                "--config".into(),
                config.clone().into_os_string(),
            ])
            .expect("portable-dev mode should parse"),
            LaunchMode::PortableDev {
                root,
                config_path: config,
                initialize_schema_only: false,
            }
        );
    }

    #[test]
    fn parser_accepts_schema_initialization_only_and_rejects_it_for_protected_mode() {
        let root = std::env::current_dir().expect("current directory should exist");
        let config = root.join("store.json");
        assert!(matches!(
            parse_launch_mode(vec![
                "--portable-dev-root".into(),
                root.into_os_string(),
                "--config".into(),
                config.into_os_string(),
                "--initialize-schema-only".into(),
            ])
            .expect("schema initialization mode should parse"),
            LaunchMode::PortableDev {
                initialize_schema_only: true,
                ..
            }
        ));
        assert!(
            parse_launch_mode(args(&[
                "--config",
                "C:\\ProgramData\\Eliot\\store.json",
                "--initialize-schema-only",
            ]))
            .is_err()
        );
    }

    #[test]
    fn parser_rejects_missing_unknown_and_extra_arguments() {
        assert!(parse_launch_mode(args(&[])).is_err());
        assert!(parse_launch_mode(args(&["--unknown", "x"])).is_err());
        assert!(parse_launch_mode(args(&["--config"])).is_err());
        assert!(
            parse_launch_mode(args(&[
                "--portable-dev-root",
                ".",
                "--config",
                "store.json",
            ]))
            .is_err()
        );
        let root = std::env::current_dir().expect("current directory should exist");
        assert!(
            parse_launch_mode(vec![
                "--portable-dev-root".into(),
                root.into_os_string(),
                "--config".into(),
                "store.json".into(),
                "extra".into(),
            ])
            .is_err()
        );
    }
}
