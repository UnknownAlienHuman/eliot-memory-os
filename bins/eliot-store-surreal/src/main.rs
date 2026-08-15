use std::path::PathBuf;
use std::time::Duration;

#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::TransportLimits;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use eliot_store_surreal::{
    SERVICE_NAME, StoreComposition, StoreHandshakeIdentity, admit_handshake, dispatch, load_config,
    validate_request_frame,
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{SERVICE_NAME}: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
async fn run() -> Result<(), String> {
    let config_path = parse_config_path()?;
    let config = load_config(Some(&config_path))?;
    let composition = StoreComposition::new(config.clone())?;

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
        serde_json::to_value(server_hello).expect("server hello is serializable"),
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

#[cfg(not(windows))]
async fn run() -> Result<(), String> {
    Err("the production store endpoint requires Windows authenticated named pipes".to_owned())
}

/// The only supported launch form is
/// eliot-store-surreal --config <explicit .json or .toml path>.
fn parse_config_path() -> Result<PathBuf, String> {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => Err("--config is required; launch config must be explicit".to_owned()),
        Some(value) if value == "--config" => match args.next() {
            Some(path) if args.next().is_none() => Ok(PathBuf::from(path)),
            _ => Err("--config requires exactly one path".to_owned()),
        },
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
