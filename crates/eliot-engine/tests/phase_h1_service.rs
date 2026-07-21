use eliot_engine::{
    CredentialProviderService, HookIpcForwarder, IpcGovernorClient, NamedPipeIpcServer,
    ProductionReadinessService, ReadinessFixture, RestartBudgetService, ServiceDoctorIntegration,
    StartupRecoveryService, StdioShimService, WindowsServiceManager, h1_protocol_version,
    hash_secret,
};
use eliot_types::{
    CredentialPurpose, IpcFrame, IpcFrameKind, RuntimeMode, ServiceInstallStatus,
    ServiceReadinessStatus, ServiceRestartReason, ServiceRestartStatus, StartupRecoveryStatus,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn h1_windows_service_config_validates_without_secret_args() {
    let root = unique_root("service-config");
    let manager = service_manager(&root);

    let receipt = manager.validate();

    assert_eq!(receipt.status, ServiceInstallStatus::Succeeded);
    assert!(receipt.errors.is_empty());
    assert!(manager.config().restart_policy.enabled);
    assert!(manager.config().restart_policy.max_restarts_per_window > 0);
    assert!(
        manager
            .config()
            .arguments
            .iter()
            .all(|argument| !argument.contains("token=") && !argument.contains("password="))
    );
}

#[test]
fn h1_named_pipe_ipc_accepts_valid_and_rejects_invalid_handshake() -> TestResult {
    let root = unique_root("ipc-handshake");
    let mut server = started_server(&root)?;
    let token = "h1-token";

    let accepted = server.handshake(&IpcGovernorClient::handshake(
        "stdio-shim",
        RuntimeMode::StdioShim,
        token,
        vec!["mcp.status".to_owned()],
    ));
    let rejected = server.handshake(&IpcGovernorClient::handshake(
        "stdio-shim",
        RuntimeMode::StdioShim,
        "wrong-token",
        vec!["mcp.status".to_owned()],
    ));

    assert!(accepted.accepted);
    assert!(!rejected.accepted);
    assert!(server.status().bind_local_only);
    assert!(server.status().handshake_required);
    Ok(())
}

#[test]
fn h1_ipc_rejects_admin_frames_and_bounds_frame_size() -> TestResult {
    let root = unique_root("ipc-frame");
    let server = started_server(&root)?;
    let frame = IpcFrame {
        frame_id: "frame:h1-admin".to_owned(),
        protocol_version: h1_protocol_version().to_owned(),
        trace_id: "trace:h1-admin".to_owned(),
        request_id: "request:h1-admin".to_owned(),
        kind: IpcFrameKind::AdminRequest,
        payload_ref: None,
        payload_inline: Some(json!({ "action": "restart" })),
        payload_hash: hash_secret("h1-admin-frame"),
        created_at: time::OffsetDateTime::now_utc(),
    };

    let response = IpcGovernorClient::send(&server, &frame)?;

    assert_eq!(response.kind, IpcFrameKind::ErrorResponse);
    assert!(server.status().max_frame_bytes <= 1_048_576);
    Ok(())
}

#[test]
fn h1_stdiomcp_shim_does_not_own_canonical_state_in_daemon_profile() {
    assert!(!StdioShimService::owns_canonical_state(
        RuntimeMode::StdioShim,
        true,
        false
    ));
    assert!(!StdioShimService::owns_canonical_state(
        RuntimeMode::Daemon,
        true,
        false
    ));
    assert!(StdioShimService::owns_canonical_state(
        RuntimeMode::DevSingleProcess,
        false,
        true
    ));
}

#[test]
fn h1_hook_forwarder_spools_without_canonical_write() -> TestResult {
    let root = unique_root("hook-spool");
    let result = HookIpcForwarder::new(root.join("spool"))
        .forward_or_spool(false, &json!({"event": "x"}))?;

    assert_eq!(
        result
            .get("canonical_write")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        result.get("spooled").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(
        result
            .get("spool_ref")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("hook-spool:"))
    );
    Ok(())
}

#[test]
fn h1_credential_report_redacts_values_and_detects_secret_config() {
    let mut provider = CredentialProviderService::new();
    let credential_ref = provider.put_test_secret(
        "credential:ipc",
        CredentialPurpose::IpcHandshakeToken,
        "super-secret",
    );

    let report = provider.report(
        "password = \"bad\"\ntoken_file = \"ok\"",
        &["service".to_owned()],
    );

    assert_eq!(
        provider.resolve_for_internal_use(&credential_ref),
        Some("super-secret")
    );
    assert!(report.secret_values_redacted);
    assert!(report.toml_contains_secret_values);
    assert!(!report.command_line_contains_secret_values);
}

#[test]
fn h1_readiness_requires_required_checks() {
    let ready = ProductionReadinessService::probe("EliotGovernor", &ReadinessFixture::healthy());
    let db_down =
        ProductionReadinessService::probe("EliotGovernor", &ReadinessFixture::db_unavailable());
    let incident = ProductionReadinessService::probe(
        "EliotGovernor",
        &ReadinessFixture {
            blocking_incident: true,
            ..ReadinessFixture::healthy()
        },
    );

    assert_eq!(ready.status, ServiceReadinessStatus::Ready);
    assert_eq!(db_down.status, ServiceReadinessStatus::NotReady);
    assert_eq!(incident.status, ServiceReadinessStatus::IncidentLockdown);
}

#[test]
fn h1_restart_budget_opens_incident_on_exhaustion() {
    let root = unique_root("restart-budget");
    let manager = service_manager(&root);
    let mut budget = RestartBudgetService::new(manager.config().restart_policy.clone());

    let first = budget.record_failure("EliotGovernor", ServiceRestartReason::DbHealthFailed);
    let second = budget.record_failure("EliotGovernor", ServiceRestartReason::DbHealthFailed);

    assert_eq!(first.status, ServiceRestartStatus::Attempted);
    assert_eq!(
        second.status,
        ServiceRestartStatus::BudgetExhaustedIncidentOpened
    );
    assert!(second.incident_ref.is_some());
}

#[test]
fn h1_startup_recovery_removes_stale_lock_after_unclean_shutdown() -> TestResult {
    let root = unique_root("startup-recovery");
    let runtime = root.join("runtime");
    std::fs::create_dir_all(&runtime)?;
    std::fs::write(runtime.join("startup.marker"), "started")?;
    std::fs::write(runtime.join("daemon.lock"), "stale")?;

    let receipt = StartupRecoveryService::new(&root).scan()?;

    assert_eq!(receipt.status, StartupRecoveryStatus::RecoveredWithWarnings);
    assert!(receipt.unclean_shutdown_detected);
    assert!(!runtime.join("daemon.lock").exists());
    assert!(
        root.join("reports")
            .join("startup-recovery")
            .join("latest.json")
            .is_file()
    );
    Ok(())
}

#[test]
fn h1_service_doctor_report_is_bounded() -> TestResult {
    let root = unique_root("doctor");
    let manager = service_manager(&root);
    let service = manager.status();
    let ipc = started_server(&root)?.status();
    let mut provider = CredentialProviderService::new();
    let _ = provider.put_test_secret(
        "credential:ipc",
        CredentialPurpose::IpcHandshakeToken,
        "super-secret",
    );
    let credentials = provider.report("", &[]);
    let readiness =
        ProductionReadinessService::probe("EliotGovernor", &ReadinessFixture::healthy());
    let mut budget = RestartBudgetService::new(manager.config().restart_policy.clone());
    let restart = budget.record_failure("EliotGovernor", ServiceRestartReason::HealthcheckFailed);
    let startup = StartupRecoveryService::new(&root).scan()?;

    let report = ServiceDoctorIntegration::report(
        &service,
        &ipc,
        &credentials,
        &readiness,
        &restart,
        &startup,
        true,
        false,
    );

    assert_eq!(
        report.get("component").and_then(|value| value.as_str()),
        Some("service_doctor")
    );
    assert_eq!(
        report
            .get("credentials")
            .and_then(|value| value.get("redacted"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(
        report
            .get("service")
            .and_then(|value| value.get("service_name"))
            .is_some()
    );
    Ok(())
}

fn service_manager(root: &Path) -> WindowsServiceManager {
    WindowsServiceManager::new(WindowsServiceManager::default_config(
        root,
        Path::new("C:/Eliot/eliot-app.exe"),
    ))
}

fn started_server(root: &Path) -> TestResult<NamedPipeIpcServer> {
    let manager = service_manager(root);
    let mut server =
        NamedPipeIpcServer::in_memory(manager.config().ipc.clone(), hash_secret("h1-token"));
    server.start()?;
    Ok(server)
}

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("eliot-h1-{label}-{nanos}"))
}
