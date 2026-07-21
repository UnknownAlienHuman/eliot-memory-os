use crate::{EngineError, ServiceContext, ServiceHandle, ServiceLifecycle};
use eliot_types::{
    AuthorityHeader, CausalityHeader, EliotExchangeEnvelope, EliotLogEvent, ExchangeKind,
    ExchangeParty, LogEventKind, LogLevel, ModuleCapability, ModuleEndpoint, ModuleHealth,
    ModuleKind, ModuleManifest, ModuleRegistryReport, ModuleResourceLimits, ModuleTransport,
    RedactionInfo, RuntimeHealthReport, RuntimeLogReport, RuntimeMode, RuntimeStatusReport,
    SchemaRef, ServiceHealthState, ServiceRuntimeStatus, TaintClass,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const DEFAULT_RESTART_BUDGET: u32 = 3;

pub struct ServiceSupervisor {
    services: Vec<Box<dyn ServiceLifecycle>>,
    statuses: BTreeMap<String, ServiceRuntimeStatus>,
    start_order: Vec<String>,
    shutdown_order: Vec<String>,
    restart_budget: u32,
}

impl ServiceSupervisor {
    pub fn new(services: Vec<Box<dyn ServiceLifecycle>>) -> Self {
        Self {
            services,
            statuses: BTreeMap::new(),
            start_order: Vec::new(),
            shutdown_order: Vec::new(),
            restart_budget: DEFAULT_RESTART_BUDGET,
        }
    }

    #[must_use]
    pub fn with_restart_budget(mut self, restart_budget: u32) -> Self {
        self.restart_budget = restart_budget;
        self
    }

    pub async fn start_all(&mut self, instance_id: &str) -> Result<(), EngineError> {
        for service in &self.services {
            let service_name = service.service_name().to_owned();
            let ctx = ServiceContext {
                service_name: service_name.clone(),
                instance_id: instance_id.to_owned(),
            };
            self.statuses.insert(
                service_name.clone(),
                ServiceRuntimeStatus {
                    service_name: service_name.clone(),
                    health: ServiceHealthState::Starting,
                    started: false,
                    restart_budget_remaining: self.restart_budget,
                    message: "starting".to_owned(),
                },
            );

            match service.start(ctx).await {
                Ok(handle) => {
                    self.start_order.push(handle.service_name.clone());
                    self.statuses.insert(
                        handle.service_name.clone(),
                        ServiceRuntimeStatus {
                            service_name: handle.service_name,
                            health: ServiceHealthState::Healthy,
                            started: true,
                            restart_budget_remaining: self.restart_budget,
                            message: "started".to_owned(),
                        },
                    );
                }
                Err(error) => {
                    self.statuses.insert(
                        service_name.clone(),
                        ServiceRuntimeStatus {
                            service_name: service_name.clone(),
                            health: ServiceHealthState::Failed,
                            started: false,
                            restart_budget_remaining: self.restart_budget.saturating_sub(1),
                            message: error.to_string(),
                        },
                    );
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub async fn shutdown_all(&mut self, deadline: Instant) -> Result<(), EngineError> {
        for service in self.services.iter().rev() {
            service.shutdown(deadline).await?;
            let service_name = service.service_name().to_owned();
            self.shutdown_order.push(service_name.clone());
            self.statuses.insert(
                service_name.clone(),
                ServiceRuntimeStatus {
                    service_name,
                    health: ServiceHealthState::Stopped,
                    started: false,
                    restart_budget_remaining: self.restart_budget,
                    message: "stopped".to_owned(),
                },
            );
        }
        Ok(())
    }

    pub fn service_statuses(&self) -> Vec<ServiceRuntimeStatus> {
        self.statuses.values().cloned().collect()
    }

    pub fn start_order(&self) -> &[String] {
        &self.start_order
    }

    pub fn shutdown_order(&self) -> &[String] {
        &self.shutdown_order
    }

    pub fn status_report(
        &self,
        mode: RuntimeMode,
        data_root: &Path,
        single_instance_owned: bool,
        ipc_enabled: bool,
    ) -> RuntimeStatusReport {
        RuntimeStatusReport {
            component: "runtime_status".to_owned(),
            mode,
            pid: std::process::id(),
            data_root: data_root.display().to_string(),
            active_profile: mode_name(mode).to_owned(),
            single_instance_owned,
            ipc_enabled,
            services: self.service_statuses(),
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct StaticRuntimeService {
    service_name: &'static str,
    health: ServiceHealthState,
    fail_start: bool,
}

impl StaticRuntimeService {
    pub const fn healthy(service_name: &'static str) -> Self {
        Self {
            service_name,
            health: ServiceHealthState::Healthy,
            fail_start: false,
        }
    }

    pub const fn failed(service_name: &'static str) -> Self {
        Self {
            service_name,
            health: ServiceHealthState::Failed,
            fail_start: true,
        }
    }
}

impl ServiceLifecycle for StaticRuntimeService {
    fn service_name(&self) -> &'static str {
        self.service_name
    }

    fn start(
        &self,
        ctx: ServiceContext,
    ) -> crate::BoxServiceFuture<'_, Result<ServiceHandle, EngineError>> {
        let service_name = self.service_name;
        let fail_start = self.fail_start;
        Box::pin(async move {
            if fail_start {
                return Err(EngineError::ServiceNotReady {
                    service: service_name.to_owned(),
                    reason: "configured test failure".to_owned(),
                });
            }
            Ok(ServiceHandle {
                service_name: ctx.service_name,
                started_at: Instant::now(),
            })
        })
    }

    fn shutdown(&self, _deadline: Instant) -> crate::BoxServiceFuture<'_, Result<(), EngineError>> {
        Box::pin(async { Ok(()) })
    }

    fn health(&self) -> eliot_types::ComponentHealth {
        eliot_types::ComponentHealth {
            component: self.service_name.to_owned(),
            status: if self.health.is_ready() {
                eliot_types::HealthStatus::Ready
            } else if self.health.is_degraded() {
                eliot_types::HealthStatus::Degraded
            } else {
                eliot_types::HealthStatus::NotReady
            },
            message: format!("{:?}", self.health),
        }
    }
}

pub struct LifecycleService {
    data_root: PathBuf,
}

impl LifecycleService {
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
        }
    }

    pub fn acquire_single_instance(&self) -> Result<RuntimeLock, EngineError> {
        let runtime_dir = self.data_root.join("runtime");
        std::fs::create_dir_all(&runtime_dir)?;
        let lock_path = runtime_dir.join("daemon.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    EngineError::ServiceNotReady {
                        service: "lifecycle".to_owned(),
                        reason: format!(
                            "single-instance lock already exists: {}",
                            lock_path.display()
                        ),
                    }
                } else {
                    EngineError::Io(error)
                }
            })?;
        let owner_pid = std::process::id().to_string();
        file.write_all(owner_pid.as_bytes())?;
        file.sync_all()?;
        let pid_path = runtime_dir.join("daemon.pid");
        std::fs::write(&pid_path, &owner_pid)?;
        std::fs::write(
            runtime_dir.join("startup.marker"),
            OffsetDateTime::now_utc().to_string(),
        )?;
        Ok(RuntimeLock {
            lock_path,
            pid_path,
            clean_marker_path: runtime_dir.join("clean-shutdown.marker"),
            _file: file,
        })
    }

    pub fn status(&self) -> Result<Value, EngineError> {
        let runtime_dir = self.data_root.join("runtime");
        let lock_path = runtime_dir.join("daemon.lock");
        let pid_path = runtime_dir.join("daemon.pid");
        let pid = std::fs::read_to_string(&pid_path).ok();
        Ok(serde_json::json!({
            "component": "lifecycle",
            "single_instance_lock": lock_path.exists(),
            "pid": pid.map(|value| value.trim().to_owned()),
            "data_root": self.data_root,
        }))
    }
}

pub struct RuntimeLock {
    lock_path: PathBuf,
    pid_path: PathBuf,
    clean_marker_path: PathBuf,
    _file: File,
}

impl RuntimeLock {
    pub fn mark_clean_shutdown(&self) -> Result<(), EngineError> {
        std::fs::write(
            &self.clean_marker_path,
            OffsetDateTime::now_utc().to_string(),
        )?;
        Ok(())
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

pub struct HealthService;

impl HealthService {
    pub fn report(mode: RuntimeMode, services: Vec<ServiceRuntimeStatus>) -> RuntimeHealthReport {
        let mut degraded_reasons = Vec::new();
        let mut ready = true;
        let mut aggregate = ServiceHealthState::Healthy;
        for service in &services {
            if service.health == ServiceHealthState::Failed {
                ready = false;
                aggregate = ServiceHealthState::Failed;
                degraded_reasons.push(format!(
                    "{} failed: {}",
                    service.service_name, service.message
                ));
            } else if service.health.is_degraded() {
                ready = false;
                if aggregate != ServiceHealthState::Failed {
                    aggregate = service.health;
                }
                degraded_reasons.push(format!(
                    "{} degraded: {}",
                    service.service_name, service.message
                ));
            }
        }
        RuntimeHealthReport {
            component: "runtime_health".to_owned(),
            mode,
            ready,
            health: aggregate,
            degraded_reasons,
            services,
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn degraded_no_db(mode: RuntimeMode) -> RuntimeHealthReport {
        Self::report(
            mode,
            vec![ServiceRuntimeStatus {
                service_name: "memory_db".to_owned(),
                health: ServiceHealthState::DegradedNoDb,
                started: false,
                restart_budget_remaining: 0,
                message: "database unavailable; writes cannot be claimed successful".to_owned(),
            }],
        )
    }

    pub fn degraded_no_verifier(mode: RuntimeMode) -> RuntimeHealthReport {
        Self::report(
            mode,
            vec![ServiceRuntimeStatus {
                service_name: "verifier".to_owned(),
                health: ServiceHealthState::DegradedNoVerifier,
                started: false,
                restart_budget_remaining: 0,
                message: "verifier unavailable; DONE_VERIFIED cannot be granted".to_owned(),
            }],
        )
    }
}

pub struct LogService {
    log_path: PathBuf,
    max_file_bytes: u64,
}

impl LogService {
    pub fn new(log_root: impl Into<PathBuf>) -> Self {
        Self {
            log_path: log_root.into().join("eliot-governor.jsonl"),
            max_file_bytes: 10_485_760,
        }
    }

    #[must_use]
    pub fn with_max_file_bytes(mut self, max_file_bytes: u64) -> Self {
        self.max_file_bytes = max_file_bytes;
        self
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn write_event(&self, mut event: EliotLogEvent) -> Result<EliotLogEvent, EngineError> {
        self.rotate_if_needed()?;
        redact_event(&mut event);
        if let Some(parent) = self.log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        serde_json::to_writer(&mut file, &event)?;
        writeln!(file)?;
        Ok(event)
    }

    pub fn event(
        level: LogLevel,
        event_kind: LogEventKind,
        target: impl Into<String>,
        message: impl Into<String>,
        trace_id: Option<String>,
    ) -> EliotLogEvent {
        EliotLogEvent {
            timestamp: OffsetDateTime::now_utc(),
            level,
            target: target.into(),
            message: message.into(),
            trace_id,
            span_id: None,
            project_id: None,
            task_id: None,
            agent_session_id: None,
            work_item_id: None,
            work_lease_id: None,
            action_lease_id: None,
            patch_run_id: None,
            module_id: None,
            event_kind,
            fields_ref: None,
            redaction: RedactionInfo {
                secrets_redacted: false,
                raw_payload_redacted: false,
                redacted_fields: Vec::new(),
            },
        }
    }

    pub fn tail(&self, limit: usize) -> Result<Vec<EliotLogEvent>, EngineError> {
        let events = self.read_events()?;
        let start = events.len().saturating_sub(limit.max(1));
        Ok(events[start..].to_vec())
    }

    pub fn report(&self) -> Result<RuntimeLogReport, EngineError> {
        let events = self.read_events()?;
        Ok(RuntimeLogReport {
            component: "runtime_logs".to_owned(),
            log_path: self.log_path.display().to_string(),
            jsonl_parse_ok: true,
            event_count: events.len(),
            last_trace_id: events.iter().rev().find_map(|event| event.trace_id.clone()),
            redaction_checked: events.iter().any(|event| event.redaction.secrets_redacted),
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    fn read_events(&self) -> Result<Vec<EliotLogEvent>, EngineError> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.log_path)?;
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn rotate_if_needed(&self) -> Result<(), EngineError> {
        if self.max_file_bytes == 0 || !self.log_path.exists() {
            return Ok(());
        }
        let metadata = std::fs::metadata(&self.log_path)?;
        if metadata.len() <= self.max_file_bytes {
            return Ok(());
        }
        let rotated_path = self.log_path.with_extension("jsonl.1");
        let _ = std::fs::remove_file(&rotated_path);
        std::fs::rename(&self.log_path, rotated_path)?;
        Ok(())
    }
}

pub struct ReportService {
    report_root: PathBuf,
}

impl ReportService {
    pub fn new(report_root: impl Into<PathBuf>) -> Self {
        Self {
            report_root: report_root.into(),
        }
    }

    pub fn write_latest<T: Serialize>(
        &self,
        section: &str,
        report: &T,
        markdown: &str,
    ) -> Result<(PathBuf, PathBuf), EngineError> {
        let dir = self.report_root.join(section);
        std::fs::create_dir_all(&dir)?;
        let json_path = dir.join("latest.json");
        let md_path = dir.join("latest.md");
        let json = serde_json::to_string_pretty(report)?;
        std::fs::write(&json_path, json)?;
        std::fs::write(&md_path, markdown)?;
        self.write_index(section, &json_path, &md_path)?;
        Ok((json_path, md_path))
    }

    fn write_index(
        &self,
        section: &str,
        json_path: &Path,
        md_path: &Path,
    ) -> Result<(), EngineError> {
        std::fs::create_dir_all(&self.report_root)?;
        let index_path = self.report_root.join("index.json");
        let index = serde_json::json!({
            "updated_section": section,
            "latest_json": json_path,
            "latest_md": md_path,
            "updated_at": OffsetDateTime::now_utc(),
        });
        std::fs::write(index_path, serde_json::to_string_pretty(&index)?)?;
        Ok(())
    }
}

pub struct ModuleRegistryService {
    manifests: Vec<ModuleManifest>,
}

impl ModuleRegistryService {
    pub fn new(manifests: Vec<ModuleManifest>) -> Result<Self, EngineError> {
        let service = Self { manifests };
        for manifest in &service.manifests {
            service.validate_manifest(manifest)?;
        }
        Ok(service)
    }

    pub fn builtin() -> Result<Self, EngineError> {
        Self::new(builtin_manifests())
    }

    pub fn manifests(&self) -> &[ModuleManifest] {
        &self.manifests
    }

    pub fn validate_manifest(&self, manifest: &ModuleManifest) -> Result<(), EngineError> {
        if manifest.name.trim().is_empty() {
            return Err(module_rejected("module name is required"));
        }
        if manifest.version.trim().is_empty() {
            return Err(module_rejected("module version is required"));
        }
        if manifest.authority_profile.can_write_truth
            || manifest.authority_profile.can_request_patch
            || manifest.authority_profile.can_finish_task
        {
            return Err(module_rejected(
                "module authority cannot grant truth, patch, or finish authority",
            ));
        }
        if manifest.module_kind == ModuleKind::CandidateAgentAdapter
            && manifest.transport != ModuleTransport::Disabled
        {
            return Err(module_rejected(
                "candidate agent adapters are schema-only in G0 and must be disabled",
            ));
        }
        if manifest
            .endpoints
            .iter()
            .any(|endpoint| endpoint.max_payload_bytes > manifest.resource_limits.max_payload_bytes)
        {
            return Err(module_rejected(
                "endpoint payload exceeds module resource limit",
            ));
        }
        Ok(())
    }

    pub fn capability_known(value: &str) -> bool {
        ModuleCapability::from_wire_name(value).is_some()
    }

    pub fn list_modules(&self) -> Vec<ModuleHealth> {
        self.manifests
            .iter()
            .map(|manifest| ModuleHealth {
                module_id: manifest.module_id,
                name: manifest.name.clone(),
                enabled: manifest.enabled_by_default
                    && manifest.transport != ModuleTransport::Disabled,
                health: if manifest.enabled_by_default
                    && manifest.transport != ModuleTransport::Disabled
                {
                    ServiceHealthState::Healthy
                } else {
                    ServiceHealthState::Stopped
                },
                message: if manifest.transport == ModuleTransport::Disabled {
                    "disabled module contract only".to_owned()
                } else {
                    "health-only internal module".to_owned()
                },
            })
            .collect()
    }

    pub fn report(&self) -> ModuleRegistryReport {
        ModuleRegistryReport {
            component: "module_registry".to_owned(),
            modules: self.list_modules(),
            manifests_loaded: self.manifests.len(),
            unknown_capabilities_denied: !Self::capability_known("raw_db"),
            authority_bypass_denied: self
                .manifests
                .iter()
                .all(|manifest| self.validate_manifest(manifest).is_ok()),
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct RuntimeAdapterSupervisorSkeleton;

impl RuntimeAdapterSupervisorSkeleton {
    pub fn health_only(manifests: &[ModuleManifest]) -> Vec<ModuleHealth> {
        manifests
            .iter()
            .map(|manifest| ModuleHealth {
                module_id: manifest.module_id,
                name: manifest.name.clone(),
                enabled: false,
                health: ServiceHealthState::Stopped,
                message: "G0 adapter supervisor skeleton; external execution disabled".to_owned(),
            })
            .collect()
    }
}

pub struct ExchangeEnvelopeService;

impl ExchangeEnvelopeService {
    pub fn envelope<T: Serialize + Clone>(
        project_id: eliot_types::ProjectId,
        task_id: Option<eliot_types::TaskId>,
        source: ExchangeParty,
        destination: ExchangeParty,
        kind: ExchangeKind,
        authority: AuthorityHeader,
        payload: T,
    ) -> Result<EliotExchangeEnvelope<T>, EngineError> {
        let payload_bytes = serde_json::to_vec(&payload)?;
        let payload_hash = blake3::hash(&payload_bytes).to_hex().to_string();
        let now = OffsetDateTime::now_utc();
        Ok(EliotExchangeEnvelope {
            envelope_id: format!("envelope-{}-{payload_hash}", now.unix_timestamp_nanos()),
            schema_version: "1".to_owned(),
            project_id,
            task_id,
            source,
            destination,
            kind,
            causality: CausalityHeader {
                trace_id: format!("trace-{}", now.unix_timestamp_nanos()),
                parent_envelope_id: None,
                causation_id: None,
                correlation_id: None,
                sequence: 1,
            },
            authority,
            payload,
            payload_hash,
            payload_ref: None,
            created_at: now,
        })
    }

    pub fn module_blackboard_candidate(
        module_id: eliot_types::ModuleId,
        project_id: eliot_types::ProjectId,
        task_id: Option<eliot_types::TaskId>,
        payload: Value,
    ) -> Result<EliotExchangeEnvelope<Value>, EngineError> {
        Self::envelope(
            project_id,
            task_id,
            ExchangeParty::Module(module_id),
            ExchangeParty::Governor,
            ExchangeKind::BlackboardItem,
            AuthorityHeader {
                role: None,
                capabilities: vec![ModuleCapability::SubmitFindingCandidate],
                lease_refs: Vec::new(),
                taint: TaintClass::ExternalAgent,
            },
            payload,
        )
    }
}

pub fn default_runtime_services() -> Vec<Box<dyn ServiceLifecycle>> {
    vec![
        Box::new(StaticRuntimeService::healthy("lifecycle")),
        Box::new(StaticRuntimeService::healthy("memory")),
        Box::new(StaticRuntimeService::healthy("coordination")),
        Box::new(StaticRuntimeService::healthy("module_registry")),
        Box::new(StaticRuntimeService::healthy("adapter_supervisor")),
        Box::new(StaticRuntimeService::healthy("logs")),
        Box::new(StaticRuntimeService::healthy("reports")),
    ]
}

pub fn builtin_manifests() -> Vec<ModuleManifest> {
    vec![
        builtin_manifest(
            "builtin.memory",
            ModuleKind::InternalRust,
            vec![ModuleCapability::ReadMemory],
        ),
        builtin_manifest(
            "builtin.mailbox",
            ModuleKind::InternalRust,
            vec![
                ModuleCapability::HealthCheck,
                ModuleCapability::SubmitFindingCandidate,
            ],
        ),
        builtin_manifest(
            "builtin.codecortex",
            ModuleKind::InternalRust,
            vec![
                ModuleCapability::ReadMemory,
                ModuleCapability::SubmitFindingCandidate,
                ModuleCapability::HealthCheck,
            ],
        ),
        builtin_manifest(
            "builtin.verifier",
            ModuleKind::VerifierAdapter,
            vec![
                ModuleCapability::SubmitVerifierResult,
                ModuleCapability::RunVerifier,
                ModuleCapability::HealthCheck,
            ],
        ),
    ]
}

fn builtin_manifest(
    name: &str,
    module_kind: ModuleKind,
    capabilities: Vec<ModuleCapability>,
) -> ModuleManifest {
    let schema = SchemaRef {
        schema_id: format!("{name}.health"),
        version: "1".to_owned(),
    };
    ModuleManifest {
        module_id: eliot_types::ModuleId::new_v7(),
        name: name.to_owned(),
        version: "0.1.0".to_owned(),
        description: "G0 builtin health-only module contract".to_owned(),
        module_kind,
        transport: ModuleTransport::InProcess,
        capabilities: capabilities.clone(),
        endpoints: vec![ModuleEndpoint {
            endpoint_id: "health".to_owned(),
            name: "health".to_owned(),
            direction: eliot_types::EndpointDirection::Bidirectional,
            schema: schema.clone(),
            max_payload_bytes: 4096,
            requires_ack: true,
        }],
        input_schemas: vec![schema.clone()],
        output_schemas: vec![schema],
        authority_profile: eliot_types::ModuleAuthorityProfile {
            allowed_projects: Vec::new(),
            allowed_roles: Vec::new(),
            allowed_capabilities: capabilities,
            can_write_truth: false,
            can_request_patch: false,
            can_finish_task: false,
        },
        resource_limits: ModuleResourceLimits::default(),
        enabled_by_default: true,
    }
}

fn redact_event(event: &mut EliotLogEvent) {
    let lowered = event.message.to_ascii_lowercase();
    let secret_like = ["password", "secret", "token", "bearer"]
        .iter()
        .any(|marker| lowered.contains(marker));
    if secret_like {
        "[redacted secret-like value]".clone_into(&mut event.message);
        event.redaction.secrets_redacted = true;
        event.redaction.redacted_fields.push("message".to_owned());
    }
}

fn module_rejected(reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "module_registry".to_owned(),
        reason: reason.to_owned(),
    }
}

fn mode_name(mode: RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::DevSingleProcess => "dev-single-process",
        RuntimeMode::Daemon => "daemon",
        RuntimeMode::StdioShim => "stdio-shim",
        RuntimeMode::HookCommand => "hook-command",
        RuntimeMode::AdminCli => "admin-cli",
    }
}

pub fn shutdown_deadline_after(duration: Duration) -> Instant {
    Instant::now() + duration
}
