#![forbid(unsafe_code)]

use std::time::Duration;

#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::TransportLimits;
use eliot_protocol::MessageType;
use eliot_store_surreal::{
    SERVICE_NAME, StoreComposition, StoreHandshakeIdentity, admit_handshake, dispatch,
    load_compatibility_for_config, load_config, require_compatibility_for_writer,
    require_observed_identity_match, require_semantic_ready_for_pipe, store_bootstrap_descriptor,
    validate_request_frame,
};

mod launch_mode;
use launch_mode::{LaunchMode, control_frame, parse_launch_mode, prepare_launch};

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

/// Bounded typed defect for a transport/protocol frame rejected before
/// dispatch (the `validate_request_frame` Err arm). Correlates via the
/// frame's `request_id` when present and admits no untrusted
/// operation/fence identity; the validation detail is additive
/// `human_detail` only, which the contract excludes from `PartialEq` and
/// control semantics. Mirrors `StoreFailure::base` + `defect()`:
/// `InternalDefect` / `INTERNAL_STORE_FAILURE` / `NotAttempted` /
/// `ManualRecovery` / `EscalateInternalDefect`.
#[cfg(windows)]
fn frame_rejection_defect(
    request_id: Option<eliot_contracts::RequestId>,
    error: String,
) -> eliot_store_surreal::Response {
    let human_detail = if error.is_empty()
        || error.len() > eliot_store_api::MAX_STORE_FAILURE_DETAIL_LEN
        || error.chars().any(char::is_control)
    {
        None
    } else {
        Some(error)
    };
    let reason_code = eliot_store_api::StoreReasonCode::new("INTERNAL_STORE_FAILURE")
        .ok()
        .or_else(|| eliot_store_api::StoreReasonCode::new("INTERNAL_DEFECT").ok())
        .or_else(|| eliot_store_api::StoreReasonCode::new("STORE_DEFECT").ok());
    match reason_code {
        Some(reason_code) => {
            let mut failure = eliot_store_api::StoreFailure {
                contract_revision: eliot_store_api::STORE_FAILURE_CONTRACT_REVISION.to_owned(),
                disposition: eliot_store_api::StoreFailureDisposition::InternalDefect,
                reason_code,
                request_id,
                operation_id: None,
                idempotency_key_ref_or_digest: None,
                state_fence_ref_or_exact_safe_projection: None,
                mutation_disposition: eliot_store_api::StoreMutationDisposition::NotAttempted,
                retry_directive: eliot_store_api::StoreRetryDirective::ManualRecovery,
                recovery_action: eliot_store_api::StoreRecoveryAction::EscalateInternalDefect,
                conflict: None,
                retry_after_ms: None,
                retry_after_dependency_revision: None,
                evidence_handles: eliot_store_api::StoreEvidenceHandles::default(),
                evidence_ref: None,
                human_detail,
            };
            if failure.validate().is_err() {
                failure.human_detail = None;
            }
            if failure.validate().is_ok() {
                eliot_store_surreal::Response::Failure { failure }
            } else {
                unreachable!(
                    "frame-rejection defect with absent refs/fence must validate; \
                     incompatible failure-contract revision"
                );
            }
        }
        None => {
            unreachable!(
                "store failure contract rejects static defect tokens; \
                 incompatible failure-contract revision"
            );
        }
    }
}

/// I5.9 compatibility gate (issue #1932).
///
/// Reports the exact active `SurrealDB` version and compatibility decision from
/// the installation-visible `compatibility.toml` sibling of the Store config,
/// then admits the canonical writer only on a recorded qualified decision. An
/// unrecorded or unqualified server binary keeps the installation in visible
/// maintenance instead of silently accepting writes.
#[cfg(windows)]
#[allow(clippy::print_stderr)]
fn enforce_store_compatibility(
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> Result<(), String> {
    let config_path = std::path::Path::new(config.runtime_launch.store_config_path.as_str());
    let file = load_compatibility_for_config(config_path)?;
    let report = require_compatibility_for_writer(
        &file.surrealdb,
        config
            .runtime_launch
            .canonical_store_artifact_digest
            .as_str(),
        &config.schema_generation,
    )?;
    eprintln!("{SERVICE_NAME}: {report}");
    Ok(())
}

#[cfg(windows)]
fn emit_bootstrap_descriptor(mode: &LaunchMode) -> Result<bool, String> {
    if let LaunchMode::EmitBootstrapDescriptor {
        config_path,
        output_path,
    } = mode
    {
        let config = load_config(Some(config_path))?;
        let descriptor = store_bootstrap_descriptor(&config)?;
        let bytes = serde_json::to_vec_pretty(&descriptor)
            .map_err(|error| format!("serialize neutral bootstrap descriptor: {error}"))?;
        std::fs::write(output_path, bytes)
            .map_err(|error| format!("write neutral bootstrap descriptor: {error}"))?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(windows)]
// This standalone service has no initialized telemetry sink before startup;
// stderr is the only fail-closed launch diagnostic available to its supervisor.
#[allow(clippy::print_stderr)]
fn bind_observed_identity(
    composition: &StoreComposition,
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> Result<(), String> {
    let observed = composition
        .observed_provider_identity()
        .ok_or_else(|| "provider identity was not proved by connect".to_owned())?;
    let observed_version = format!(
        "{}.{}.{}",
        observed.version_major, observed.version_minor, observed.version_patch
    );
    let compat_path = std::path::Path::new(config.runtime_launch.store_config_path.as_str());
    let compat_file = load_compatibility_for_config(compat_path)?;
    let bound_report = require_observed_identity_match(
        &compat_file.surrealdb,
        &observed_version,
        &observed.artifact_digest,
    )?;
    eprintln!("{SERVICE_NAME}: {bound_report}");
    Ok(())
}

#[cfg(windows)]
async fn serve_handshake_loop(
    composition: &StoreComposition,
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> Result<(), String> {
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
        admit_handshake(hello_frame, limits, config, &handshake_identity)?;
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
            Ok(request) => Box::pin(dispatch(composition, request)).await,
            Err(error) => frame_rejection_defect(frame.request_id.clone(), error),
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
async fn run() -> Result<(), String> {
    let mode = parse_launch_mode(std::env::args_os().skip(1))?;
    if emit_bootstrap_descriptor(&mode)? {
        return Ok(());
    }
    let Some(config) = prepare_launch(mode).await? else {
        return Ok(());
    };
    enforce_store_compatibility(&config)?;
    let composition = StoreComposition::new(&config)?;
    composition.connect().await?;
    // Post-connect re-verification (issue #1932): the adapter has now proved
    // spawned-artifact identity, listener ownership and server major over its
    // ownership-verified channel. Reload the decision record and require the
    // same admission before serving: a record swapped, revoked or drifted
    // across the provider-startup window must fail closed here, never at the
    // first canonical write.
    enforce_store_compatibility(&config)?;
    // Observed-identity binding (issue #1932, backend handoff §3): the
    // adapter proved the live version and spawn-validated digest over its
    // ownership-verified channel during connect. Bind the record echo to
    // that observation before serving: a rotated binary or drifted record
    // fails closed here, never at the first canonical write.
    bind_observed_identity(&composition, &config)?;
    let readiness = composition
        .readiness()
        .await
        .map_err(|error| format!("semantic Store readiness failed: {error}"))?;
    require_semantic_ready_for_pipe(&readiness, &config.schema_generation)?;
    serve_handshake_loop(&composition, &config).await
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
