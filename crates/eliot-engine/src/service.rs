use crate::EngineError;
use eliot_types::{
    CredentialDiagnosticsReport, CredentialProviderKind, CredentialPurpose, CredentialRef,
    DataRootValidationStatus, IpcConfig, IpcFrame, IpcFrameKind, IpcHandshake,
    IpcHandshakeDecision, IpcHandshakeReason, IpcStatusReport, RuntimeMode, ServiceAccountRef,
    ServiceInstallAction, ServiceInstallReceipt, ServiceInstallStatus, ServiceReadinessCheck,
    ServiceReadinessProbe, ServiceReadinessStatus, ServiceRestartPolicy, ServiceRestartReason,
    ServiceRestartReceipt, ServiceRestartStatus, ServiceStartType, ServiceStatusReport,
    StartupRecoveryReceipt, StartupRecoveryStatus, WindowsServiceConfig,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const H1_PROTOCOL_VERSION: &str = "eliot-ipc-v1";

pub struct WindowsServiceManager {
    config: WindowsServiceConfig,
}

impl WindowsServiceManager {
    #[must_use]
    pub fn new(config: WindowsServiceConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn default_config(data_root: &Path, executable_path: &Path) -> WindowsServiceConfig {
        WindowsServiceConfig {
            service_name: "EliotGovernor".to_owned(),
            display_name: "ELIOT Governor".to_owned(),
            description: "Local ELIOT Governor production runtime service".to_owned(),
            executable_path: executable_path.display().to_string(),
            arguments: vec!["service".to_owned(), "run".to_owned()],
            account: ServiceAccountRef::CurrentUser,
            start_type: ServiceStartType::Manual,
            restart_policy: ServiceRestartPolicy::default(),
            data_root: data_root.display().to_string(),
            log_root: data_root.join("logs").display().to_string(),
            ipc: default_ipc_config(data_root),
        }
    }

    #[must_use]
    pub fn config(&self) -> &WindowsServiceConfig {
        &self.config
    }

    #[must_use]
    pub fn validate(&self) -> ServiceInstallReceipt {
        let (warnings, errors) = validate_service_config(&self.config);
        let status = if errors.is_empty() {
            ServiceInstallStatus::Succeeded
        } else {
            ServiceInstallStatus::Failed
        };
        self.receipt(ServiceInstallAction::Validate, status, warnings, errors)
    }

    #[must_use]
    pub fn install(&self, dry_run: bool) -> ServiceInstallReceipt {
        let (mut warnings, errors) = validate_service_config(&self.config);
        if !errors.is_empty() {
            return self.receipt(
                ServiceInstallAction::Install,
                ServiceInstallStatus::Failed,
                warnings,
                errors,
            );
        }
        if dry_run {
            return self.receipt(
                ServiceInstallAction::Install,
                ServiceInstallStatus::DryRun,
                warnings,
                errors,
            );
        }

        warnings.push(
            "H1 engine does not mutate Windows SCM; use admin service runner for real install"
                .to_owned(),
        );
        self.receipt(
            ServiceInstallAction::Install,
            ServiceInstallStatus::SucceededWithWarnings,
            warnings,
            errors,
        )
    }

    #[must_use]
    pub fn uninstall(&self, dry_run: bool) -> ServiceInstallReceipt {
        let status = if dry_run {
            ServiceInstallStatus::DryRun
        } else {
            ServiceInstallStatus::SucceededWithWarnings
        };
        let warnings = if dry_run {
            Vec::new()
        } else {
            vec![
                "H1 engine reports uninstall intent only; SCM mutation is admin CLI only"
                    .to_owned(),
            ]
        };
        self.receipt(
            ServiceInstallAction::Uninstall,
            status,
            warnings,
            Vec::new(),
        )
    }

    #[must_use]
    pub fn control(&self, action: ServiceInstallAction) -> ServiceInstallReceipt {
        let warnings = vec![
            "H1 does not start/stop SCM from ordinary process; admin CLI boundary is preserved"
                .to_owned(),
        ];
        self.receipt(
            action,
            ServiceInstallStatus::SucceededWithWarnings,
            warnings,
            Vec::new(),
        )
    }

    #[must_use]
    pub fn status(&self) -> ServiceStatusReport {
        let receipt = self.receipt(
            ServiceInstallAction::Status,
            ServiceInstallStatus::SucceededWithWarnings,
            vec!["SCM query is bounded to local status report in H1 tests".to_owned()],
            Vec::new(),
        );
        ServiceStatusReport {
            component: "service_status".to_owned(),
            config: self.config.clone(),
            installed: false,
            running: false,
            install_receipt: receipt,
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    fn receipt(
        &self,
        action: ServiceInstallAction,
        status: ServiceInstallStatus,
        warnings: Vec<String>,
        errors: Vec<String>,
    ) -> ServiceInstallReceipt {
        let created_at = OffsetDateTime::now_utc();
        ServiceInstallReceipt {
            receipt_id: id("service-receipt", created_at),
            service_name: self.config.service_name.clone(),
            action,
            status,
            config_ref: config_ref(&self.config),
            warnings,
            errors,
            created_at,
        }
    }
}

pub struct NamedPipeIpcServer {
    config: IpcConfig,
    protocol_version: String,
    expected_token_hash: String,
    allowed_capabilities: Vec<String>,
    listening: bool,
    last_handshake: Option<IpcHandshakeDecision>,
}

impl NamedPipeIpcServer {
    #[must_use]
    pub fn in_memory(config: IpcConfig, expected_token_hash: String) -> Self {
        Self {
            config,
            protocol_version: H1_PROTOCOL_VERSION.to_owned(),
            expected_token_hash,
            allowed_capabilities: vec![
                "mcp.status".to_owned(),
                "mcp.report".to_owned(),
                "hook.forward".to_owned(),
                "health".to_owned(),
            ],
            listening: false,
            last_handshake: None,
        }
    }

    pub fn start(&mut self) -> Result<(), EngineError> {
        let (_, errors) = validate_ipc_config(&self.config);
        if !errors.is_empty() {
            return Err(service_not_ready("ipc", errors.join("; ")));
        }
        self.listening = true;
        Ok(())
    }

    #[must_use]
    pub fn handshake(&mut self, handshake: &IpcHandshake) -> IpcHandshakeDecision {
        let mut reasons = Vec::new();
        let mut accepted = true;
        if handshake.protocol_version != self.protocol_version {
            accepted = false;
            reasons.push(IpcHandshakeReason::ProtocolMismatch);
        }
        if handshake.token_hash.trim().is_empty() {
            accepted = false;
            reasons.push(IpcHandshakeReason::MissingToken);
        } else if handshake.token_hash != self.expected_token_hash {
            accepted = false;
            reasons.push(IpcHandshakeReason::InvalidToken);
        }
        if !self.config.allowed_client_sids.is_empty()
            && self
                .config
                .allowed_client_sids
                .iter()
                .any(|sid| sid.eq_ignore_ascii_case("deny"))
        {
            accepted = false;
            reasons.push(IpcHandshakeReason::ClientNotAllowed);
        }
        if handshake.runtime_mode == RuntimeMode::AdminCli
            && !handshake
                .requested_capabilities
                .iter()
                .any(|capability| capability == "admin")
        {
            accepted = false;
            reasons.push(IpcHandshakeReason::RuntimeModeDenied);
        }
        if handshake
            .requested_capabilities
            .iter()
            .any(|capability| !self.allowed_capabilities.contains(capability))
        {
            accepted = false;
            reasons.push(IpcHandshakeReason::CapabilityDenied);
        }
        if accepted {
            reasons.push(IpcHandshakeReason::ProtocolAccepted);
        }
        let decision = IpcHandshakeDecision {
            decision_id: id("ipc-handshake", OffsetDateTime::now_utc()),
            accepted,
            reasons,
            granted_capabilities: if accepted {
                handshake.requested_capabilities.clone()
            } else {
                Vec::new()
            },
            created_at: OffsetDateTime::now_utc(),
        };
        self.last_handshake = Some(decision.clone());
        decision
    }

    pub fn handle_frame(&self, frame: &IpcFrame) -> Result<IpcFrame, EngineError> {
        self.enforce_frame_limit(frame)?;
        if frame.kind == IpcFrameKind::AdminRequest {
            return Ok(error_frame(
                frame,
                "admin requests require AdminCli and are not exposed to MCP",
            ));
        }
        Ok(IpcFrame {
            frame_id: id("ipc-frame", OffsetDateTime::now_utc()),
            protocol_version: self.protocol_version.clone(),
            trace_id: frame.trace_id.clone(),
            request_id: frame.request_id.clone(),
            kind: match frame.kind {
                IpcFrameKind::HealthRequest => IpcFrameKind::EventNotification,
                IpcFrameKind::McpRequest | IpcFrameKind::HookEvent => {
                    IpcFrameKind::EventNotification
                }
                _ => IpcFrameKind::ErrorResponse,
            },
            payload_ref: None,
            payload_inline: Some(json!({
                "accepted": true,
                "request_id": frame.request_id,
                "bounded": true
            })),
            payload_hash: hash_value(&json!({
                "accepted": true,
                "request_id": frame.request_id,
                "bounded": true
            })),
            created_at: OffsetDateTime::now_utc(),
        })
    }

    #[must_use]
    pub fn status(&self) -> IpcStatusReport {
        IpcStatusReport {
            component: "ipc_status".to_owned(),
            pipe_name: self.config.pipe_name.clone(),
            transport: "named-pipe-abstraction-in-memory-h1".to_owned(),
            listening: self.listening,
            bind_local_only: self.config.bind_local_only,
            max_frame_bytes: self.config.max_frame_bytes,
            handshake_required: self.config.require_handshake,
            last_handshake: self.last_handshake.clone(),
            warnings: vec![
                "real Windows named-pipe smoke not exercised by this in-memory H1 transport"
                    .to_owned(),
            ],
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    fn enforce_frame_limit(&self, frame: &IpcFrame) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec(frame)?;
        if bytes.len() > self.config.max_frame_bytes {
            return Err(service_not_ready(
                "ipc",
                format!(
                    "IPC frame exceeds max_frame_bytes: {} > {}",
                    bytes.len(),
                    self.config.max_frame_bytes
                ),
            ));
        }
        Ok(())
    }
}

pub struct IpcGovernorClient;

impl IpcGovernorClient {
    #[must_use]
    pub fn handshake(
        client_id: &str,
        runtime_mode: RuntimeMode,
        token: &str,
        requested_capabilities: Vec<String>,
    ) -> IpcHandshake {
        IpcHandshake {
            protocol_version: H1_PROTOCOL_VERSION.to_owned(),
            client_id: client_id.to_owned(),
            runtime_mode,
            token_hash: hash_secret(token),
            requested_capabilities,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn send(server: &NamedPipeIpcServer, frame: &IpcFrame) -> Result<IpcFrame, EngineError> {
        server.handle_frame(frame)
    }
}

pub struct StdioShimService;

impl StdioShimService {
    #[must_use]
    pub fn forwards_to_ipc_in_daemon_profile(
        server: &mut NamedPipeIpcServer,
        token: &str,
    ) -> IpcHandshakeDecision {
        let handshake = IpcGovernorClient::handshake(
            "stdio-shim",
            RuntimeMode::StdioShim,
            token,
            vec!["mcp.status".to_owned(), "mcp.report".to_owned()],
        );
        server.handshake(&handshake)
    }

    #[must_use]
    pub const fn owns_canonical_state(
        runtime_mode: RuntimeMode,
        daemon_ipc_configured: bool,
        explicit_dev_single_process: bool,
    ) -> bool {
        matches!(runtime_mode, RuntimeMode::DevSingleProcess)
            && (!daemon_ipc_configured || explicit_dev_single_process)
    }

    #[must_use]
    pub const fn dev_single_process_allowed(explicit_dev_single_process: bool) -> bool {
        explicit_dev_single_process
    }
}

pub struct HookIpcForwarder {
    spool_root: PathBuf,
}

impl HookIpcForwarder {
    #[must_use]
    pub fn new(spool_root: impl Into<PathBuf>) -> Self {
        Self {
            spool_root: spool_root.into(),
        }
    }

    pub fn forward_or_spool(
        &self,
        daemon_reachable: bool,
        event: &Value,
    ) -> Result<Value, EngineError> {
        if daemon_reachable {
            return Ok(json!({
                "component": "hook_ipc_forwarder",
                "status": "forwarded",
                "canonical_write": false,
                "spooled": false
            }));
        }
        std::fs::create_dir_all(&self.spool_root)?;
        let path = self.spool_root.join(format!(
            "hook-{}.json",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::write(&path, serde_json::to_vec_pretty(event)?)?;
        Ok(json!({
            "component": "hook_ipc_forwarder",
            "status": "spooled",
            "canonical_write": false,
            "spooled": true,
            "spool_ref": format!("hook-spool:{}", hash_value(&path.display().to_string()))
        }))
    }
}

#[derive(Default)]
pub struct CredentialProviderService {
    refs: BTreeMap<String, CredentialRef>,
    secrets: BTreeMap<String, String>,
}

impl CredentialProviderService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_test_secret(
        &mut self,
        credential_id: &str,
        purpose: CredentialPurpose,
        value: &str,
    ) -> CredentialRef {
        let credential_ref = CredentialRef {
            credential_id: credential_id.to_owned(),
            provider: CredentialProviderKind::TestInMemory,
            purpose,
            created_at: OffsetDateTime::now_utc(),
        };
        self.refs
            .insert(credential_id.to_owned(), credential_ref.clone());
        self.secrets
            .insert(credential_id.to_owned(), value.to_owned());
        credential_ref
    }

    #[must_use]
    pub fn resolve_for_internal_use(&self, credential_ref: &CredentialRef) -> Option<&str> {
        self.secrets
            .get(&credential_ref.credential_id)
            .map(String::as_str)
    }

    #[must_use]
    pub fn report(
        &self,
        config_text: &str,
        command_line: &[String],
    ) -> CredentialDiagnosticsReport {
        CredentialDiagnosticsReport {
            component: "credentials_report".to_owned(),
            refs: self.refs.values().cloned().collect(),
            statuses: Vec::new(),
            resolved_count: self
                .refs
                .values()
                .filter(|credential_ref| self.resolve_for_internal_use(credential_ref).is_some())
                .count(),
            secret_values_redacted: true,
            toml_contains_secret_values: contains_secret_assignment(config_text),
            command_line_contains_secret_values: command_line
                .iter()
                .any(|value| secret_like(value)),
            warnings: vec![
                "credential values are resolved only inside CredentialProviderService".to_owned(),
            ],
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    #[must_use]
    pub fn redact(value: &str) -> String {
        if value.is_empty() {
            String::new()
        } else {
            "[redacted]".to_owned()
        }
    }
}

pub struct ProductionReadinessService;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessFixture {
    pub data_root_validated: bool,
    pub credential_refs_resolved: bool,
    pub db_reachable: bool,
    pub writer_self_check: bool,
    pub read_self_check: bool,
    pub ipc_listening: bool,
    pub fast_deterministic_eval_gate_passed: bool,
    pub blocking_incident: bool,
}

impl ReadinessFixture {
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            data_root_validated: true,
            credential_refs_resolved: true,
            db_reachable: true,
            writer_self_check: true,
            read_self_check: true,
            ipc_listening: true,
            fast_deterministic_eval_gate_passed: true,
            blocking_incident: false,
        }
    }

    #[must_use]
    pub const fn db_unavailable() -> Self {
        Self {
            db_reachable: false,
            ..Self::healthy()
        }
    }
}

impl ProductionReadinessService {
    #[must_use]
    pub fn probe(service_name: &str, fixture: &ReadinessFixture) -> ServiceReadinessProbe {
        let mut checks = Vec::new();
        push_check(
            &mut checks,
            fixture.data_root_validated,
            ServiceReadinessCheck::DataRootValidated,
        );
        push_check(
            &mut checks,
            fixture.credential_refs_resolved,
            ServiceReadinessCheck::CredentialRefsResolved,
        );
        push_check(
            &mut checks,
            fixture.db_reachable,
            ServiceReadinessCheck::SurrealDbReachable,
        );
        push_check(
            &mut checks,
            fixture.writer_self_check,
            ServiceReadinessCheck::WriterSelfCheckPassed,
        );
        push_check(
            &mut checks,
            fixture.read_self_check,
            ServiceReadinessCheck::ReadSelfCheckPassed,
        );
        push_check(
            &mut checks,
            fixture.ipc_listening,
            ServiceReadinessCheck::IpcServerListening,
        );
        push_check(
            &mut checks,
            fixture.fast_deterministic_eval_gate_passed,
            ServiceReadinessCheck::FastDeterministicEvalGatePassed,
        );
        push_check(
            &mut checks,
            !fixture.blocking_incident,
            ServiceReadinessCheck::NoBlockingIncidents,
        );
        let ready = fixture.data_root_validated
            && fixture.credential_refs_resolved
            && fixture.db_reachable
            && fixture.writer_self_check
            && fixture.read_self_check
            && fixture.ipc_listening
            && fixture.fast_deterministic_eval_gate_passed
            && !fixture.blocking_incident;
        let status = if fixture.blocking_incident {
            ServiceReadinessStatus::IncidentLockdown
        } else if ready {
            ServiceReadinessStatus::Ready
        } else if fixture.read_self_check && !fixture.writer_self_check {
            ServiceReadinessStatus::DegradedReadOnly
        } else {
            ServiceReadinessStatus::NotReady
        };
        ServiceReadinessProbe {
            probe_id: id("readiness", OffsetDateTime::now_utc()),
            service_name: service_name.to_owned(),
            checks,
            status,
            started_at: OffsetDateTime::now_utc(),
            finished_at: Some(OffsetDateTime::now_utc()),
        }
    }

    #[must_use]
    pub fn data_root_validation_passed(status: DataRootValidationStatus) -> bool {
        matches!(
            status,
            DataRootValidationStatus::Valid | DataRootValidationStatus::ValidWithWarnings
        )
    }
}

pub struct RestartBudgetService {
    policy: ServiceRestartPolicy,
    attempts: u32,
}

impl RestartBudgetService {
    #[must_use]
    pub fn new(policy: ServiceRestartPolicy) -> Self {
        Self {
            policy,
            attempts: 0,
        }
    }

    #[must_use]
    pub fn record_failure(
        &mut self,
        service_name: &str,
        reason: ServiceRestartReason,
    ) -> ServiceRestartReceipt {
        if !self.policy.enabled {
            return restart_receipt(
                service_name,
                reason,
                self.attempts,
                0,
                ServiceRestartStatus::DeniedByPolicy,
                None,
            );
        }
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts > self.policy.max_restarts_per_window {
            let incident_ref = if self.policy.open_incident_on_exhaustion {
                Some(format!(
                    "incident:restart-budget:{service_name}:{}",
                    self.attempts
                ))
            } else {
                None
            };
            return restart_receipt(
                service_name,
                reason,
                self.attempts,
                0,
                ServiceRestartStatus::BudgetExhaustedIncidentOpened,
                incident_ref,
            );
        }
        restart_receipt(
            service_name,
            reason,
            self.attempts,
            self.policy
                .max_restarts_per_window
                .saturating_sub(self.attempts),
            ServiceRestartStatus::Attempted,
            None,
        )
    }
}

pub struct StartupRecoveryService {
    data_root: PathBuf,
}

impl StartupRecoveryService {
    #[must_use]
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
        }
    }

    pub fn scan(&self) -> Result<StartupRecoveryReceipt, EngineError> {
        let runtime = self.data_root.join("runtime");
        std::fs::create_dir_all(&runtime)?;
        let startup_marker = runtime.join("startup.marker");
        let clean_marker = runtime.join("clean-shutdown.marker");
        let unclean = startup_marker.exists() && !clean_marker.exists();
        let stale_lock = runtime.join("daemon.lock");
        let mut stale_locks_removed = Vec::new();
        if unclean && stale_lock.exists() {
            std::fs::remove_file(&stale_lock)?;
            stale_locks_removed.push(stale_lock.display().to_string());
        }
        let status = if unclean && stale_locks_removed.is_empty() {
            StartupRecoveryStatus::Recovered
        } else if unclean {
            StartupRecoveryStatus::RecoveredWithWarnings
        } else {
            StartupRecoveryStatus::Clean
        };
        let receipt = StartupRecoveryReceipt {
            receipt_id: id("startup-recovery", OffsetDateTime::now_utc()),
            data_root: self.data_root.display().to_string(),
            unclean_shutdown_detected: unclean,
            wal_recovered: unclean,
            outbox_reconciled: unclean,
            stale_locks_removed,
            incidents_opened: Vec::new(),
            status,
            created_at: OffsetDateTime::now_utc(),
        };
        let report_path = self
            .data_root
            .join("reports")
            .join("startup-recovery")
            .join("latest.json");
        if let Some(parent) = report_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&report_path, serde_json::to_vec_pretty(&receipt)?)?;
        Ok(receipt)
    }
}

pub struct ServiceDoctorIntegration;

impl ServiceDoctorIntegration {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn report(
        service: &ServiceStatusReport,
        ipc: &IpcStatusReport,
        credentials: &CredentialDiagnosticsReport,
        readiness: &ServiceReadinessProbe,
        restart_receipt: &ServiceRestartReceipt,
        startup_recovery: &StartupRecoveryReceipt,
        fast_deterministic_eval_gate_passed: bool,
        blocking_incidents: bool,
    ) -> Value {
        json!({
            "component": "service_doctor",
            "service": {
                "installed": service.installed,
                "running": service.running,
                "service_name": service.config.service_name
            },
            "daemon_mode": "daemon",
            "ipc": {
                "pipe_configured": !ipc.pipe_name.is_empty(),
                "listening": ipc.listening,
                "handshake_status": ipc.last_handshake.as_ref().map(|decision| decision.accepted)
            },
            "credentials": {
                "refs_present": !credentials.refs.is_empty(),
                "redacted": credentials.secret_values_redacted
            },
            "readiness": readiness.status,
            "restart_budget": restart_receipt.status,
            "startup_recovery": startup_recovery.status,
            "fast_deterministic_eval_gate_passed": fast_deterministic_eval_gate_passed,
            "blocking_incidents": blocking_incidents
        })
    }
}

#[must_use]
pub fn default_ipc_config(data_root: &Path) -> IpcConfig {
    IpcConfig {
        pipe_name: r"\\.\pipe\eliot-governor".to_owned(),
        token_file: data_root
            .join("config")
            .join("ipc.token")
            .display()
            .to_string(),
        max_frame_bytes: 1_048_576,
        request_timeout_ms: 30_000,
        allowed_client_sids: Vec::new(),
        require_handshake: true,
        bind_local_only: true,
    }
}

#[must_use]
pub fn hash_secret(secret: &str) -> String {
    blake3::hash(secret.as_bytes()).to_hex().to_string()
}

#[must_use]
pub fn h1_protocol_version() -> &'static str {
    H1_PROTOCOL_VERSION
}

fn validate_service_config(config: &WindowsServiceConfig) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    for (field, value) in [
        ("service_name", &config.service_name),
        ("display_name", &config.display_name),
        ("executable_path", &config.executable_path),
        ("data_root", &config.data_root),
        ("log_root", &config.log_root),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{field} is required"));
        }
    }
    let (ipc_warnings, ipc_errors) = validate_ipc_config(&config.ipc);
    warnings.extend(ipc_warnings);
    errors.extend(ipc_errors);
    if config.arguments.iter().any(|argument| {
        secret_like(argument) || argument.contains('=') && argument.contains("token")
    }) {
        errors.push("service arguments must not contain secret-like values".to_owned());
    }
    if config.restart_policy.enabled && config.restart_policy.max_restarts_per_window == 0 {
        errors.push("restart policy must not allow zero-budget infinite loop".to_owned());
    }
    if config.restart_policy.enabled && config.restart_policy.backoff_seconds == 0 {
        warnings.push("restart policy backoff is zero; H1 recommends bounded backoff".to_owned());
    }
    if config.restart_policy.enabled
        && (config.restart_policy.max_restarts_per_window != 2
            || config.restart_policy.restart_delays_seconds != [5, 30]
            || config.restart_policy.reset_period_seconds != 86_400)
    {
        errors.push(
            "Governor SCM recovery must be bounded to 5s, 30s, then stop with a 24h reset"
                .to_owned(),
        );
    }
    (warnings, errors)
}

fn validate_ipc_config(config: &IpcConfig) -> (Vec<String>, Vec<String>) {
    let warnings = Vec::new();
    let mut errors = Vec::new();
    if !config.pipe_name.starts_with(r"\\.\pipe\") {
        errors.push("IPC pipe must be a local Windows named pipe".to_owned());
    }
    if config.token_file.trim().is_empty() {
        errors.push("IPC token_file ref is required".to_owned());
    }
    if config.max_frame_bytes == 0 {
        errors.push("IPC max_frame_bytes must be greater than zero".to_owned());
    }
    if !config.require_handshake {
        errors.push("IPC handshake is required".to_owned());
    }
    if !config.bind_local_only {
        errors.push("IPC must bind local only".to_owned());
    }
    (warnings, errors)
}

fn config_ref(config: &WindowsServiceConfig) -> String {
    let redacted = json!({
        "service_name": config.service_name,
        "display_name": config.display_name,
        "executable_path": config.executable_path,
        "arguments": config.arguments,
        "account": config.account,
        "start_type": config.start_type,
        "data_root": config.data_root,
        "log_root": config.log_root,
        "ipc": {
            "pipe_name": config.ipc.pipe_name,
            "max_frame_bytes": config.ipc.max_frame_bytes,
            "request_timeout_ms": config.ipc.request_timeout_ms,
            "require_handshake": config.ipc.require_handshake,
            "bind_local_only": config.ipc.bind_local_only
        }
    });
    format!("h1-config:{}", hash_value(&redacted))
}

fn error_frame(request: &IpcFrame, message: &str) -> IpcFrame {
    let payload = json!({ "error": message, "request_id": request.request_id });
    IpcFrame {
        frame_id: id("ipc-error", OffsetDateTime::now_utc()),
        protocol_version: request.protocol_version.clone(),
        trace_id: request.trace_id.clone(),
        request_id: request.request_id.clone(),
        kind: IpcFrameKind::ErrorResponse,
        payload_ref: None,
        payload_inline: Some(payload.clone()),
        payload_hash: hash_value(&payload),
        created_at: OffsetDateTime::now_utc(),
    }
}

fn push_check(checks: &mut Vec<ServiceReadinessCheck>, passed: bool, check: ServiceReadinessCheck) {
    if passed {
        checks.push(check);
    }
}

fn restart_receipt(
    service_name: &str,
    reason: ServiceRestartReason,
    attempt_number: u32,
    budget_remaining: u32,
    status: ServiceRestartStatus,
    incident_ref: Option<String>,
) -> ServiceRestartReceipt {
    ServiceRestartReceipt {
        receipt_id: id("restart", OffsetDateTime::now_utc()),
        service_name: service_name.to_owned(),
        reason,
        attempt_number,
        budget_remaining,
        status,
        incident_ref,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn contains_secret_assignment(text: &str) -> bool {
    text.lines().any(|line| {
        let lowered = line.trim().to_ascii_lowercase();
        (lowered.starts_with("password")
            || lowered.starts_with("token")
            || lowered.starts_with("secret"))
            && lowered.contains('=')
            && !lowered.contains("_file")
            && !lowered.contains("_ref")
    })
}

fn secret_like(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    ["password=", "token=", "secret=", "bearer "]
        .iter()
        .any(|needle| lowered.contains(needle))
}

fn hash_value<T: Serialize>(value: &T) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    blake3::hash(&encoded).to_hex().to_string()
}

fn id(prefix: &str, now: OffsetDateTime) -> String {
    format!("{prefix}-{}", now.unix_timestamp_nanos())
}

fn service_not_ready(service: &str, reason: impl Into<String>) -> EngineError {
    EngineError::ServiceNotReady {
        service: service.to_owned(),
        reason: reason.into(),
    }
}
