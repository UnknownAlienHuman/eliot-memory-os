use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::{ReplayDisposition, ReplayLedger, TransportLimits};
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange,
    ProtocolVersion, ServerHello,
};
use eliot_store_api::{
    CAPABILITIES, EFFECTS, StateFence, decode_request_frame, response_frame as store_response_frame,
};
use eliot_store_surreal::{
    PROTOCOL_VERSION, Request, Response, SERVICE_NAME, StoreComposition, StoreLaunchConfig,
    load_config,
};

struct Session {
    connection_id: String,
    protocol_version: ProtocolVersion,
    state_fence: StateFence,
    max_frame_bytes: usize,
    capabilities: BTreeSet<String>,
    replay: ReplayLedger,
}

#[tokio::main]
async fn main() {
    #[cfg(not(windows))]
    {
        eprintln!(
            "{SERVICE_NAME}: the production store endpoint requires Windows authenticated named pipes"
        );
        return;
    }
    #[cfg(windows)]
    run_windows().await;
}

#[cfg(windows)]
async fn run_windows() {
    let config_path = match parse_config_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: {error}");
            return;
        }
    };
    let config = match load_config(Some(&config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: {error}");
            return;
        }
    };
    let composition = match StoreComposition::new(config.clone()) {
        Ok(composition) => composition,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: {error}");
            return;
        }
    };

    let limits = TransportLimits::default();
    let expectation = match eliot_platform_windows::NamedPipePeerExpectation::new(
        config.expected_client_sid.clone(),
        config.expected_client_session_id,
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: invalid peer expectation: {error}");
            return;
        }
    };
    let mut server = match NamedPipeServer::create(&config.store_pipe, &expectation) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: named-pipe creation failed: {error}");
            return;
        }
    };
    if let Err(error) = server
        .wait_for_authenticated_client(
            Duration::from_millis(config.connect_timeout_ms),
            &expectation,
        )
        .await
    {
        eprintln!("{SERVICE_NAME}: authenticated client admission failed: {error}");
        return;
    }
    let hello_frame = match server.receive_frame(limits).await {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: EBP hello receive failed: {error}");
            return;
        }
    };
    let (mut session, server_hello) =
        match admit_handshake(hello_frame, limits, &composition, &config) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("{SERVICE_NAME}: EBP handshake rejected: {error}");
                return;
            }
        };
    let mut negotiated_limits = limits;
    negotiated_limits.max_frame_bytes = session.max_frame_bytes;
    let handshake_frame = control_frame(
        &session.connection_id,
        session.protocol_version,
        MessageType::Ready,
        serde_json::to_value(server_hello).expect("server hello is serializable"),
    );
    if let Err(error) = server.send_frame(&handshake_frame, negotiated_limits).await {
        eprintln!("{SERVICE_NAME}: EBP handshake response failed: {error}");
        return;
    }

    loop {
        let frame = match server.receive_frame(negotiated_limits).await {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("{SERVICE_NAME}: EBP frame rejected: {error}");
                break;
            }
        };
        let response = match validate_request_frame(&mut session, &frame) {
            Ok(request) => dispatch(&composition, request).await,
            Err(error) => Response::Error { error },
        };
        let response_frame = match store_response_frame(
            &session.connection_id,
            session.protocol_version,
            frame.request_id.clone(),
            response,
        ) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("{SERVICE_NAME}: invalid EBP response: {error}");
                break;
            }
        };
        if let Err(error) = server.send_frame(&response_frame, negotiated_limits).await {
            eprintln!("{SERVICE_NAME}: EBP response failed: {error}");
            break;
        }
    }
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

fn admit_handshake(
    frame: Frame,
    limits: TransportLimits,
    composition: &StoreComposition,
    config: &StoreLaunchConfig,
) -> Result<(Session, ServerHello), String> {
    if frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Start
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err("first frame must be an uncorrelated Control/Start hello".to_owned());
    }
    let ProtocolPayload::Json(payload) = frame.payload else {
        return Err("EBP hello payload must use json-v1".to_owned());
    };
    let hello: ClientHello =
        serde_json::from_value(payload).map_err(|error| format!("decode ClientHello: {error}"))?;
    hello
        .validate()
        .map_err(|error| format!("validate ClientHello: {error}"))?;
    if hello.module_bridge_identity != SERVICE_NAME {
        return Err(format!(
            "ClientHello module_bridge_identity must be {SERVICE_NAME}"
        ));
    }
    let artifact_hash = hello.artifact_hash.as_str();
    if artifact_hash != config.approved_artifact_hash
        || hello.module_generation.generation.value() != config.store_generation
        || hello.authority_epoch.value() != config.authority_epoch
    {
        return Err("ClientHello is outside the Host-approved store lineage".to_owned());
    }
    let server_range = ProtocolRange {
        minimum: ProtocolVersion::CURRENT,
        maximum: ProtocolVersion::CURRENT,
    };
    let protocol_version = hello
        .protocol_range
        .select(server_range)
        .map_err(|error| format!("negotiate EBP version: {error}"))?;
    if usize::try_from(hello.max_frame).unwrap_or(usize::MAX) > limits.max_frame_bytes {
        return Err("ClientHello max_frame exceeds the bounded transport limit".to_owned());
    }
    let capabilities: Vec<String> = CAPABILITIES
        .iter()
        .filter(|capability| hello.capabilities.iter().any(|value| value == **capability))
        .map(|capability| (*capability).to_owned())
        .collect();
    let effects: Vec<String> = EFFECTS.iter().map(|effect| (*effect).to_owned()).collect();
    let server_hello = ServerHello {
        selected_protocol: protocol_version,
        session_principal_binding: format!("{SERVICE_NAME}:{}", std::process::id()),
        allowed_capabilities: capabilities.clone(),
        allowed_effects: effects,
        config_snapshot: serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "artifact_hash": config.approved_artifact_hash,
            "config_hash": config.approved_config_hash,
            "operation_manifest_digest": composition.operation_manifest_digest(),
            "blob_root_owner": {
                "root_id": composition.blob_owner().root_id(),
                "owner_id": composition.blob_owner().owner_id().as_str(),
                "process_id": composition.blob_owner().process_id(),
                "claim_id": composition.blob_owner().claim_id(),
            },
        }),
        heartbeat_ms: 30_000,
        control_channel: "named_pipe".to_owned(),
        rejection_reason: None,
        authority_epoch: hello.authority_epoch,
    };
    server_hello
        .validate()
        .map_err(|error| format!("validate ServerHello: {error}"))?;
    let state_fence = hello.module_generation.state_fence;
    Ok((
        Session {
            connection_id: frame.connection_id,
            protocol_version,
            state_fence,
            max_frame_bytes: usize::try_from(hello.max_frame)
                .map_err(|_| "ClientHello max_frame does not fit usize".to_owned())?,
            capabilities: capabilities.into_iter().collect(),
            replay: ReplayLedger::default(),
        },
        server_hello,
    ))
}

fn validate_request_frame(session: &mut Session, frame: &Frame) -> Result<Request, String> {
    if frame.protocol_version != session.protocol_version
        || frame.connection_id != session.connection_id
    {
        return Err("request frame is outside the negotiated EBP session".to_owned());
    }
    let (request_id, identity, request) =
        decode_request_frame(frame).map_err(|error| error.to_string())?;
    if identity.request.state_fence != session.state_fence {
        return Err("request identity state fence does not match the handshake fence".to_owned());
    }
    match session.replay.observe(request_id.to_string(), frame) {
        ReplayDisposition::Conflict => {
            return Err("request identity conflicts with a prior frame".to_owned());
        }
        ReplayDisposition::New | ReplayDisposition::Duplicate => {}
    }
    let capability = request.capability();
    if !session.capabilities.contains(capability) {
        return Err(format!("capability is not admitted: {capability}"));
    }
    Ok(request)
}

async fn dispatch(composition: &StoreComposition, request: Request) -> Response {
    match request {
        Request::Health => match composition.health().await {
            Ok(record) => Response::Health { record },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Request::Readiness => match composition.readiness().await {
            Ok(receipt) => Response::Readiness { receipt },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Request::Named { request } => match composition.named(request).await {
            Ok(response) => Response::Named { response },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Request::Apply {
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        } => match composition
            .apply(
                &context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
        {
            Ok(receipt) => Response::from_transaction_receipt(receipt),
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Request::Receipt { operation_id } => match composition.receipt(operation_id).await {
            Ok(receipt) => Response::from_receipt(receipt),
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Request::RevisionHeads { keys } => match composition.revision_heads(keys).await {
            Ok(heads) => Response::RevisionHeads { heads },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
        Request::OrderingHeads { scopes } => match composition.ordering_heads(scopes).await {
            Ok(heads) => Response::OrderingHeads { heads },
            Err(error) => Response::Error {
                error: error.to_string(),
            },
        },
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
