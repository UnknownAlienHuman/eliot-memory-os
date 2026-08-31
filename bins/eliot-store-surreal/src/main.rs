use std::time::Duration;

use eliot_contracts::RequestId;
#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::TransportLimits;
use eliot_protocol::MessageType;
use eliot_store_api::{
    StoreError, StoreFailure, StoreFailureContractError, StoreFailureIdentityContext,
};
use eliot_store_surreal::{
    Response, SERVICE_NAME, StoreComposition, StoreHandshakeIdentity, admit_handshake, dispatch,
    load_config, require_semantic_ready_for_pipe, store_bootstrap_descriptor,
    validate_request_frame,
};

mod launch_mode;
use launch_mode::{LaunchMode, control_frame, parse_launch_mode, prepare_launch};

fn request_frame_failure(
    request_id: RequestId,
) -> Result<Response, StoreFailureContractError> {
    let failure = StoreFailure::from_store_error(
        StoreError::InvalidField {
            field: "request_frame",
            reason: "authenticated request frame rejected",
        },
        StoreFailureIdentityContext {
            request_id: Some(request_id),
            ..StoreFailureIdentityContext::default()
        },
    )?;
    failure.validate()?;
    Ok(Response::Failure { failure })
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
    if let LaunchMode::EmitBootstrapDescriptor {
        config_path,
        output_path,
    } = &mode
    {
        let config = load_config(Some(config_path))?;
        let descriptor = store_bootstrap_descriptor(&config)?;
        let bytes = serde_json::to_vec_pretty(&descriptor)
            .map_err(|error| format!("serialize neutral bootstrap descriptor: {error}"))?;
        std::fs::write(output_path, bytes)
            .map_err(|error| format!("write neutral bootstrap descriptor: {error}"))?;
        return Ok(());
    }
    let Some(config) = prepare_launch(mode).await? else {
        return Ok(());
    };
    let composition = StoreComposition::new(&config)?;
    composition.connect().await?;
    let readiness = composition
        .readiness()
        .await
        .map_err(|error| format!("semantic Store readiness failed: {error}"))?;
    require_semantic_ready_for_pipe(&readiness, &config.schema_generation)?;

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
        let request_id = frame
            .request_id
            .clone()
            .ok_or_else(|| "EBP request frame has no correlation identity".to_owned())?;
        let response = match validate_request_frame(&mut session, &frame) {
            Ok(request) => Box::pin(dispatch(&composition, request_id.clone(), request))
                .await
                .map_err(|_| "typed Store dispatch failure encoding failed".to_owned())?,
            Err(_) => request_frame_failure(request_id.clone())
                .map_err(|_| "typed request-frame failure encoding failed".to_owned())?,
        };
        let response_frame = eliot_store_api::response_frame(
            session.connection_id(),
            session.protocol_version(),
            Some(request_id),
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn request_frame_rejection_is_typed_and_correlated() {
        let request_id = RequestId::new("request-frame-rejected").expect("request id");
        let response = request_frame_failure(request_id.clone()).expect("typed failure");
        let Response::Failure { failure } = response else {
            panic!("request-frame rejection must be a typed failure");
        };
        assert_eq!(failure.request_id.as_ref(), Some(&request_id));
        assert_eq!(failure.reason_code.as_str(), "INVALID_FIELD");
        assert!(failure.operation_id.is_none());
        failure.validate().expect("failure validates");
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
