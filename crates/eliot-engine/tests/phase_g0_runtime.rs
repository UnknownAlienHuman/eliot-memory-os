use eliot_engine::{
    AdapterSupervisor, ExchangeEnvelopeService, HealthService, LifecycleService, LogService,
    ModuleRegistryService, ServiceSupervisor, StaticRuntimeService, default_runtime_services,
    shutdown_deadline_after,
};
use eliot_types::{
    AgentSessionId, AuthorityHeader, EliotExchangeEnvelope, EndpointDirection, ExchangeKind,
    ExchangeParty, LogEventKind, LogLevel, ModuleAuthorityProfile, ModuleCapability,
    ModuleEndpoint, ModuleId, ModuleKind, ModuleManifest, ModuleResourceLimits, ModuleTransport,
    ProjectId, RuntimeMode, SchemaRef, ServiceHealthState, ServiceRuntimeStatus, TaintClass,
    TaskId,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn daemon_run_smoke() -> TestResult {
    let mut supervisor = ServiceSupervisor::new(default_runtime_services());

    supervisor.start_all("phase-g0-daemon-run").await?;
    let statuses = supervisor.service_statuses();

    assert_eq!(statuses.len(), 7);
    assert!(statuses.iter().all(|status| status.started));
    assert!(
        statuses
            .iter()
            .all(|status| status.health == ServiceHealthState::Healthy)
    );

    supervisor
        .shutdown_all(shutdown_deadline_after(StdDuration::from_secs(1)))
        .await?;
    Ok(())
}

#[test]
fn daemon_status_smoke() -> TestResult {
    let root = test_root("daemon-status")?;
    let lifecycle = LifecycleService::new(&root);

    let idle = lifecycle.status()?;
    assert_eq!(idle["component"], "lifecycle");
    assert_eq!(idle["single_instance_lock"], false);

    let _lock = lifecycle.acquire_single_instance()?;
    let running = lifecycle.status()?;
    assert_eq!(running["single_instance_lock"], true);
    assert!(running["pid"].as_str().is_some());
    Ok(())
}

#[test]
fn daemon_health_smoke() {
    let health = HealthService::report(
        RuntimeMode::Daemon,
        vec![ServiceRuntimeStatus {
            service_name: "lifecycle".to_owned(),
            health: ServiceHealthState::Healthy,
            started: true,
            restart_budget_remaining: 3,
            message: "started".to_owned(),
        }],
    );

    assert!(health.ready);
    assert_eq!(health.health, ServiceHealthState::Healthy);
    assert!(health.degraded_reasons.is_empty());
}

#[test]
fn daemon_single_instance_guard() -> TestResult {
    let lifecycle = LifecycleService::new(test_root("daemon-single-instance")?);
    let _lock = lifecycle.acquire_single_instance()?;

    let second = lifecycle.acquire_single_instance();

    assert!(second.is_err());
    Ok(())
}

#[tokio::test]
async fn service_supervisor_start_shutdown_order() -> TestResult {
    let mut supervisor = ServiceSupervisor::new(vec![
        Box::new(StaticRuntimeService::healthy("first")),
        Box::new(StaticRuntimeService::healthy("second")),
    ]);

    supervisor.start_all("phase-g0-order").await?;
    supervisor
        .shutdown_all(shutdown_deadline_after(StdDuration::from_secs(1)))
        .await?;

    assert_eq!(supervisor.start_order(), ["first", "second"]);
    assert_eq!(supervisor.shutdown_order(), ["second", "first"]);
    Ok(())
}

#[tokio::test]
async fn service_supervisor_reports_failed_service() {
    let mut supervisor = ServiceSupervisor::new(vec![
        Box::new(StaticRuntimeService::healthy("first")),
        Box::new(StaticRuntimeService::failed("broken")),
    ])
    .with_restart_budget(2);

    let result = supervisor.start_all("phase-g0-failed").await;
    let statuses = supervisor.service_statuses();

    assert!(result.is_err());
    assert!(statuses.iter().any(|status| {
        status.service_name == "broken"
            && status.health == ServiceHealthState::Failed
            && status.restart_budget_remaining == 1
    }));
}

#[test]
fn health_reports_degraded_no_db() {
    let health = HealthService::degraded_no_db(RuntimeMode::Daemon);

    assert!(!health.ready);
    assert_eq!(health.health, ServiceHealthState::DegradedNoDb);
    assert!(
        health
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("memory_db"))
    );
}

#[test]
fn health_reports_degraded_no_verifier() {
    let health = HealthService::degraded_no_verifier(RuntimeMode::Daemon);

    assert!(!health.ready);
    assert_eq!(health.health, ServiceHealthState::DegradedNoVerifier);
    assert!(
        health
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("verifier"))
    );
}

#[test]
fn structured_jsonl_logs_written() -> TestResult {
    let logs = LogService::new(test_root("logs-jsonl")?);
    logs.write_event(LogService::event(
        LogLevel::Info,
        LogEventKind::ServiceStart,
        "phase_g0",
        "service started",
        Some("trace-jsonl".to_owned()),
    ))?;

    let content = fs::read_to_string(logs.log_path())?;
    let first_line = content
        .lines()
        .next()
        .ok_or_else(|| io_error("log line missing"))?;
    let event: Value = serde_json::from_str(first_line)?;

    assert_eq!(event["level"], "info");
    assert_eq!(event["event_kind"], "service_start");
    assert_eq!(event["trace_id"], "trace-jsonl");
    Ok(())
}

#[test]
fn logs_contain_trace_task_agent_fields() -> TestResult {
    let logs = LogService::new(test_root("logs-correlation")?);
    let task_id = TaskId::new_v7();
    let agent_session_id = AgentSessionId::new_v7();
    let mut event = LogService::event(
        LogLevel::Info,
        LogEventKind::MailboxDelivered,
        "phase_g0",
        "mailbox delivered",
        Some("trace-fields".to_owned()),
    );
    event.task_id = Some(task_id);
    event.agent_session_id = Some(agent_session_id);

    logs.write_event(event)?;
    let written = logs.tail(1)?;

    assert_eq!(written.len(), 1);
    assert_eq!(written[0].trace_id.as_deref(), Some("trace-fields"));
    assert_eq!(written[0].task_id, Some(task_id));
    assert_eq!(written[0].agent_session_id, Some(agent_session_id));
    Ok(())
}

#[test]
fn logs_redact_secret_like_values() -> TestResult {
    let logs = LogService::new(test_root("logs-redaction")?);
    let written = logs.write_event(LogService::event(
        LogLevel::Warn,
        LogEventKind::Error,
        "phase_g0",
        "bearer token abc123 leaked",
        Some("trace-redacted".to_owned()),
    ))?;
    let content = fs::read_to_string(logs.log_path())?;
    let report = logs.report()?;

    assert!(written.redaction.secrets_redacted);
    assert!(!content.contains("abc123"));
    assert!(report.redaction_checked);
    Ok(())
}

#[test]
fn module_manifest_validates() -> TestResult {
    let registry = ModuleRegistryService::builtin()?;

    for manifest in registry.manifests() {
        registry.validate_manifest(manifest)?;
    }
    Ok(())
}

#[test]
fn module_registry_lists_builtin_modules() -> TestResult {
    let registry = ModuleRegistryService::builtin()?;
    let report = registry.report();
    let adapter_health = AdapterSupervisor::health_only(registry.manifests());

    assert_eq!(report.manifests_loaded, 4);
    assert!(
        report
            .modules
            .iter()
            .any(|module| module.name == "builtin.memory")
    );
    assert!(
        report
            .modules
            .iter()
            .any(|module| module.name == "builtin.codecortex")
    );
    assert!(report.unknown_capabilities_denied);
    assert!(report.authority_bypass_denied);
    assert_eq!(adapter_health.len(), registry.manifests().len());
    assert!(
        adapter_health
            .iter()
            .all(|health| health.health == ServiceHealthState::Stopped)
    );
    Ok(())
}

#[test]
fn module_unknown_capability_denied() {
    assert!(!ModuleRegistryService::capability_known("raw_db"));
    assert!(!ModuleRegistryService::capability_known("raw_shell"));
    assert!(ModuleRegistryService::capability_known("health_check"));
}

#[test]
fn module_capabilities_do_not_grant_truth_or_patch() -> TestResult {
    let registry = ModuleRegistryService::builtin()?;
    assert!(registry.manifests().iter().all(|manifest| {
        !manifest.authority_profile.can_write_truth
            && !manifest.authority_profile.can_request_patch
            && !manifest.authority_profile.can_finish_task
    }));

    let mut bypass = test_manifest("bypass");
    bypass.authority_profile.can_request_patch = true;
    assert!(ModuleRegistryService::new(vec![bypass]).is_err());
    Ok(())
}

#[test]
fn exchange_envelope_schema_roundtrip() -> TestResult {
    let envelope = ExchangeEnvelopeService::envelope(
        ProjectId::new_v7(),
        Some(TaskId::new_v7()),
        ExchangeParty::Governor,
        ExchangeParty::Module(ModuleId::new_v7()),
        ExchangeKind::ModuleHealth,
        local_tool_authority(vec![ModuleCapability::HealthCheck]),
        json!({ "status": "healthy" }),
    )?;

    let encoded = serde_json::to_string(&envelope)?;
    let decoded: EliotExchangeEnvelope<Value> = serde_json::from_str(&encoded)?;

    assert_eq!(decoded.schema_version, "1");
    assert_eq!(decoded.kind, ExchangeKind::ModuleHealth);
    assert_eq!(decoded.payload["status"], "healthy");
    assert_eq!(decoded.payload_hash, envelope.payload_hash);
    Ok(())
}

#[test]
fn mailbox_exchange_envelope_smoke() -> TestResult {
    let envelope = ExchangeEnvelopeService::envelope(
        ProjectId::new_v7(),
        Some(TaskId::new_v7()),
        ExchangeParty::Governor,
        ExchangeParty::AgentSession(AgentSessionId::new_v7()),
        ExchangeKind::MailboxMessage,
        local_tool_authority(vec![ModuleCapability::SubmitFindingCandidate]),
        json!({ "payload_ref": "mailbox:phase-g0" }),
    )?;

    assert_eq!(envelope.kind, ExchangeKind::MailboxMessage);
    assert_eq!(envelope.authority.taint, TaintClass::LocalTool);
    assert_eq!(envelope.payload["payload_ref"], "mailbox:phase-g0");
    Ok(())
}

#[test]
fn blackboard_exchange_envelope_smoke() -> TestResult {
    let envelope = ExchangeEnvelopeService::envelope(
        ProjectId::new_v7(),
        Some(TaskId::new_v7()),
        ExchangeParty::Module(ModuleId::new_v7()),
        ExchangeParty::Governor,
        ExchangeKind::BlackboardItem,
        local_tool_authority(vec![ModuleCapability::SubmitFindingCandidate]),
        json!({ "payload_ref": "blackboard:phase-g0" }),
    )?;

    assert_eq!(envelope.kind, ExchangeKind::BlackboardItem);
    assert_eq!(envelope.payload["payload_ref"], "blackboard:phase-g0");
    Ok(())
}

#[test]
fn module_event_to_blackboard_candidate_is_tainted() -> TestResult {
    let envelope = ExchangeEnvelopeService::module_blackboard_candidate(
        ModuleId::new_v7(),
        ProjectId::new_v7(),
        Some(TaskId::new_v7()),
        json!({ "finding": "candidate only" }),
    )?;

    assert_eq!(envelope.kind, ExchangeKind::BlackboardItem);
    assert_eq!(envelope.authority.taint, TaintClass::ExternalAgent);
    assert!(
        envelope
            .authority
            .capabilities
            .contains(&ModuleCapability::SubmitFindingCandidate)
    );
    Ok(())
}

#[test]
fn phase_b_c_d_e_f0_f1_f2_f3_non_regression() -> TestResult {
    let repo = repo_root();
    let commands = fs::read_to_string(repo.join("crates/eliot-app/src/commands.rs"))?;
    for marker in [
        "run_phase_b_closeout",
        "run_phase_c_closeout",
        "run_phase_d_closeout",
        "run_phase_e_closeout",
        "run_phase_f0_closeout",
        "run_phase_f1_closeout",
        "run_phase_f2_closeout",
        "run_phase_f3_closeout",
        "run_phase_g0_closeout",
    ] {
        assert!(commands.contains(marker), "{marker} missing");
    }
    Ok(())
}

fn local_tool_authority(capabilities: Vec<ModuleCapability>) -> AuthorityHeader {
    AuthorityHeader {
        role: None,
        capabilities,
        lease_refs: Vec::new(),
        taint: TaintClass::LocalTool,
    }
}

fn test_manifest(name: &str) -> ModuleManifest {
    let schema = SchemaRef {
        schema_id: format!("{name}.health"),
        version: "1".to_owned(),
    };
    ModuleManifest {
        module_id: ModuleId::new_v7(),
        name: name.to_owned(),
        version: "0.1.0".to_owned(),
        description: "phase-g0 test manifest".to_owned(),
        module_kind: ModuleKind::InternalRust,
        transport: ModuleTransport::InProcess,
        capabilities: vec![ModuleCapability::HealthCheck],
        endpoints: vec![ModuleEndpoint {
            endpoint_id: "health".to_owned(),
            name: "health".to_owned(),
            direction: EndpointDirection::Bidirectional,
            schema: schema.clone(),
            max_payload_bytes: 4096,
            requires_ack: true,
        }],
        input_schemas: vec![schema.clone()],
        output_schemas: vec![schema],
        authority_profile: ModuleAuthorityProfile {
            allowed_capabilities: vec![ModuleCapability::HealthCheck],
            ..ModuleAuthorityProfile::default()
        },
        resource_limits: ModuleResourceLimits::default(),
        enabled_by_default: true,
    }
}

fn test_root(name: &str) -> TestResult<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let path = repo_root()
        .join("target")
        .join("phase-g0-tests")
        .join(format!("{name}-{unique}"));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn io_error(message: &str) -> std::io::Error {
    std::io::Error::other(message.to_owned())
}
