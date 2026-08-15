use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use eliot_ipc::{ReplayDisposition, ReplayLedger, TransportLimits};
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange,
    ProtocolVersion, ServerHello,
};
use eliot_store_api::{
    CAPABILITIES, EFFECTS, ReadinessReceipt, StateFence, decode_request_frame,
    response_frame as store_response_frame,
};
use eliot_store_surreal::{
    PROTOCOL_VERSION, Request, Response, SERVICE_NAME, StoreComposition, load_config,
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
    let composition = match StoreComposition::new(config) {
        Ok(composition) => composition,
        Err(error) => {
            eprintln!("{SERVICE_NAME}: {error}");
            return;
        }
    };

    let limits = TransportLimits::default();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();

    let (mut session, server_hello) = match read_handshake(&mut input, limits, &composition) {
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
    if let Err(error) = write_frame(&mut output, &handshake_frame, negotiated_limits) {
        eprintln!("{SERVICE_NAME}: EBP handshake response failed: {error}");
        return;
    }

    loop {
        let frame = match read_frame(&mut input, negotiated_limits) {
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
        if let Err(error) = write_frame(&mut output, &response_frame, negotiated_limits) {
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

fn read_handshake<R: Read>(
    reader: &mut R,
    limits: TransportLimits,
    composition: &StoreComposition,
) -> Result<(Session, ServerHello), String> {
    let frame = read_frame(reader, limits)?;
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
            "operation_manifest_digest": composition.operation_manifest_digest(),
            "blob_root_owner": {
                "root_id": composition.blob_owner().root_id(),
                "owner_id": composition.blob_owner().owner_id().as_str(),
                "process_id": composition.blob_owner().process_id(),
                "claim_id": composition.blob_owner().claim_id(),
            },
        }),
        heartbeat_ms: 30_000,
        control_channel: "stdio".to_owned(),
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
            Ok(readiness) => {
                let receipt = match readiness {
                    eliot_store_surreal_adapter::SemanticReadiness::Unavailable => {
                        ReadinessReceipt::unavailable()
                    }
                    eliot_store_surreal_adapter::SemanticReadiness::MigrationRequired {
                        expected,
                        observed,
                    } => ReadinessReceipt::migration_required(expected.to_string(), observed),
                    eliot_store_surreal_adapter::SemanticReadiness::Ready { generation } => {
                        ReadinessReceipt::ready(generation.to_string())
                    }
                };
                Response::Readiness { receipt }
            }
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

fn read_frame<R: Read>(reader: &mut R, limits: TransportLimits) -> Result<Frame, String> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| format!("read frame prefix: {error}"))?;
    let length = usize::try_from(u32::from_le_bytes(prefix))
        .map_err(|_| "frame length does not fit usize".to_owned())?;
    if length == 0 || length > limits.max_frame_bytes {
        return Err(format!(
            "frame body length {length} exceeds bounded limit {}",
            limits.max_frame_bytes
        ));
    }
    let mut wire = Vec::with_capacity(4 + length);
    wire.extend_from_slice(&prefix);
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("read frame body: {error}"))?;
    wire.extend_from_slice(&body);
    eliot_ipc::decode_frame(&wire, limits).map_err(|error| error.to_string())
}

fn write_frame<W: Write>(
    writer: &mut W,
    frame: &Frame,
    limits: TransportLimits,
) -> Result<(), String> {
    let wire = eliot_ipc::encode_frame(frame, limits).map_err(|error| error.to_string())?;
    writer
        .write_all(&wire)
        .map_err(|error| format!("write frame: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flush frame: {error}"))
}
