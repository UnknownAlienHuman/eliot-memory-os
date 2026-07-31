use crate::runtime_supervision::{
    AdapterExecutionContext, CancellationToken, RestartDecision, classify_restart,
};
use crate::{
    BlackboardAddInput, BlackboardService, EngineError, MailboxSendInput, MailboxService,
    OperationRuntimeHandle, WorkState, WriteAdmissionService, WriterHandle,
};
use eliot_store::BlobStore;
use eliot_types::{
    AdapterAuthorityProfile, AdapterCapability, AdapterCircuitState, AdapterClass, AdapterContext,
    AdapterError, AdapterHealth, AdapterLimits, AdapterObservation, AdapterRequest, AdapterResult,
    AdapterResultStatus, AdapterState, BlackboardItem, BlackboardItemKind, BlackboardScope,
    CapabilityManifest, CommandContext, ConfidenceLevel, LifecycleStatus, MailboxMessage,
    MailboxMessageKind, MailboxRecipient, ModuleHealth, ModuleManifest, ModuleTransport,
    OPERATION_RESTART_WINDOW_SCHEMA_VERSION, OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION,
    OperationCancellationState, OperationPhase, OperationReconciliationState,
    OperationRestartWindow, OperationRuntimeCheckpoint, ProcessExecutionPolicy,
    ProviderDispatchState, SemanticCommand, ServiceHealthState, TaintClass,
    ToolObservationRecordCommand, Visibility, WriteId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant, sleep};

pub type BoxAdapterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, EngineError>> + Send + 'a>>;

pub trait Adapter: Send + Sync {
    fn id(&self) -> &str;
    fn manifest(&self) -> &CapabilityManifest;
    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth>;
    fn execute(
        &self,
        request: AdapterRequest,
        context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult>;
    fn shutdown(&self) -> BoxAdapterFuture<'_, ()>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterRegistryReport {
    pub component: String,
    pub adapters: Vec<CapabilityManifest>,
    pub health: Vec<AdapterHealth>,
    pub manifests_loaded: usize,
    pub unknown_capabilities_denied: bool,
    pub authority_bypass_denied: bool,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterObservationReport {
    pub component: String,
    pub observations: Vec<AdapterObservation>,
    pub blackboard_items: Vec<BlackboardItem>,
    pub mailbox_messages: Vec<MailboxMessage>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone)]
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn Adapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: BTreeMap::new(),
        }
    }

    pub fn builtin() -> Result<Self, EngineError> {
        let mut registry = Self::new();
        registry.register(HealthAdapter::new())?;
        registry.register(TestEchoAdapter::new())?;
        registry.register(TestFailingAdapter::new())?;
        registry.register(TestSlowAdapter::new())?;
        registry.register(TestLargeOutputAdapter::new())?;
        Ok(registry)
    }

    pub fn register<A>(&mut self, adapter: A) -> Result<(), EngineError>
    where
        A: Adapter + 'static,
    {
        self.validate_manifest(adapter.manifest())?;
        self.adapters
            .insert(adapter.id().to_owned(), Arc::new(adapter));
        Ok(())
    }

    pub fn manifests(&self) -> Vec<CapabilityManifest> {
        self.adapters
            .values()
            .map(|adapter| adapter.manifest().clone())
            .collect()
    }

    pub fn adapter(&self, adapter_id: &str) -> Result<Arc<dyn Adapter>, EngineError> {
        self.adapters
            .get(adapter_id)
            .cloned()
            .ok_or_else(|| adapter_rejected(format!("unknown adapter: {adapter_id}")))
    }

    pub fn inspect(&self, adapter_id: &str) -> Result<CapabilityManifest, EngineError> {
        Ok(self.adapter(adapter_id)?.manifest().clone())
    }

    pub fn validate_manifest(&self, manifest: &CapabilityManifest) -> Result<(), EngineError> {
        if manifest.adapter_id.trim().is_empty() {
            return Err(adapter_rejected("adapter_id is required"));
        }
        if manifest.name.trim().is_empty() {
            return Err(adapter_rejected("adapter name is required"));
        }
        if manifest.version.trim().is_empty() {
            return Err(adapter_rejected("adapter version is required"));
        }
        if manifest.authority_profile.can_write_truth
            || manifest.authority_profile.can_request_patch
            || manifest.authority_profile.can_finish_task
        {
            return Err(adapter_rejected(
                "adapter authority cannot grant truth, patch, or finish authority",
            ));
        }
        if manifest
            .capabilities
            .iter()
            .any(|capability| capability.is_forbidden_authority())
        {
            return Err(adapter_rejected(
                "adapter capability cannot grant truth, patch, or finish authority",
            ));
        }
        if manifest
            .authority_profile
            .allowed_capabilities
            .iter()
            .any(|capability| capability.is_forbidden_authority())
        {
            return Err(adapter_rejected(
                "adapter authority profile cannot allow truth, patch, or finish capability",
            ));
        }
        if manifest.limits.max_concurrent_requests == 0 {
            return Err(adapter_rejected("max_concurrent_requests must be positive"));
        }
        Ok(())
    }

    pub fn validate_capability_names(
        values: &[String],
    ) -> Result<Vec<AdapterCapability>, EngineError> {
        values
            .iter()
            .map(|value| {
                AdapterCapability::from_wire_name(value)
                    .ok_or_else(|| adapter_rejected(format!("unknown adapter capability: {value}")))
            })
            .collect()
    }

    pub async fn report(&self) -> AdapterRegistryReport {
        let health = AdapterSupervisor::new(self.clone()).health_all().await;
        AdapterRegistryReport {
            component: "adapter_registry".to_owned(),
            adapters: self.manifests(),
            manifests_loaded: self.adapters.len(),
            unknown_capabilities_denied: Self::validate_capability_names(&["raw_shell".to_owned()])
                .is_err(),
            authority_bypass_denied: self
                .adapters
                .values()
                .all(|adapter| self.validate_manifest(adapter.manifest()).is_ok()),
            health,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct CircuitRecord {
    consecutive_failures: u32,
    circuit_open: bool,
    state: AdapterState,
}

impl Default for CircuitRecord {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            circuit_open: false,
            state: AdapterState::Registered,
        }
    }
}

pub struct AdapterSupervisor {
    registry: AdapterRegistry,
    circuits: Arc<Mutex<BTreeMap<String, CircuitRecord>>>,
    hydrated_circuits: Arc<Mutex<BTreeSet<String>>>,
    semaphores: BTreeMap<String, Arc<Semaphore>>,
    runtime_store: OperationRuntimeHandle,
}

impl AdapterSupervisor {
    pub fn new(registry: AdapterRegistry) -> Self {
        Self::with_runtime(registry, OperationRuntimeHandle::disabled())
    }

    pub fn with_runtime(registry: AdapterRegistry, runtime_store: OperationRuntimeHandle) -> Self {
        let semaphores = registry
            .manifests()
            .into_iter()
            .map(|manifest| {
                (
                    manifest.adapter_id,
                    Arc::new(Semaphore::new(
                        manifest.limits.max_concurrent_requests.max(1),
                    )),
                )
            })
            .collect();
        Self {
            registry,
            circuits: Arc::new(Mutex::new(BTreeMap::new())),
            hydrated_circuits: Arc::new(Mutex::new(BTreeSet::new())),
            semaphores,
            runtime_store,
        }
    }

    pub fn builtin() -> Result<Self, EngineError> {
        Ok(Self::new(AdapterRegistry::builtin()?))
    }

    pub fn health_only(manifests: &[ModuleManifest]) -> Vec<ModuleHealth> {
        manifests
            .iter()
            .map(|manifest| ModuleHealth {
                module_id: manifest.module_id,
                name: manifest.name.clone(),
                enabled: false,
                health: ServiceHealthState::Stopped,
                message: if manifest.transport == ModuleTransport::Disabled {
                    "disabled adapter module contract".to_owned()
                } else {
                    "adapter runtime executes only governed built-in adapters".to_owned()
                },
            })
            .collect()
    }

    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }

    pub async fn health_all(&self) -> Vec<AdapterHealth> {
        let mut health = Vec::new();
        for manifest in self.registry.manifests() {
            health.push(self.health_probe(&manifest.adapter_id).await);
        }
        health
    }

    pub async fn health_probe(&self, adapter_id: &str) -> AdapterHealth {
        if let Err(error) = self.hydrate_circuit(adapter_id).await {
            let manifest = match self.registry.adapter(adapter_id) {
                Ok(adapter) => adapter.manifest().clone(),
                Err(error) => {
                    return AdapterHealth {
                        adapter_id: adapter_id.to_owned(),
                        name: adapter_id.to_owned(),
                        state: AdapterState::Unavailable,
                        healthy: false,
                        message: error.to_string(),
                        consecutive_failures: 0,
                        circuit_open: false,
                        checked_at: OffsetDateTime::now_utc(),
                    };
                }
            };
            return Self::unavailable_health(
                &manifest,
                format!("load durable adapter circuit state: {error}"),
            );
        }
        match self.registry.adapter(adapter_id) {
            Ok(adapter) => match adapter.health().await {
                Ok(mut health) => {
                    self.apply_circuit_to_health(&mut health);
                    health
                }
                Err(error) => Self::unavailable_health(adapter.manifest(), error.to_string()),
            },
            Err(error) => AdapterHealth {
                adapter_id: adapter_id.to_owned(),
                name: adapter_id.to_owned(),
                state: AdapterState::Unavailable,
                healthy: false,
                message: error.to_string(),
                consecutive_failures: 0,
                circuit_open: false,
                checked_at: OffsetDateTime::now_utc(),
            },
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "adapter execution is one ordered supervision transaction with shared cleanup"
    )]
    pub async fn execute(
        &self,
        adapter_id: &str,
        request: AdapterRequest,
        blob_store: Option<&BlobStore>,
    ) -> Result<AdapterResult, EngineError> {
        let adapter = self.registry.adapter(adapter_id)?;
        validate_request(adapter.manifest(), &request)?;
        self.hydrate_circuit(adapter_id).await?;
        if self.circuit_is_open(adapter_id) {
            return Ok(rejected_result(
                &request,
                AdapterResultStatus::CircuitOpen,
                "circuit_open",
                "adapter circuit breaker is open",
            ));
        }

        let semaphore = self
            .semaphores
            .get(adapter_id)
            .cloned()
            .ok_or_else(|| adapter_rejected("adapter semaphore is missing"))?;
        let Ok(_permit) = semaphore.try_acquire_owned() else {
            return Ok(rejected_result(
                &request,
                AdapterResultStatus::Unavailable,
                "busy",
                "adapter concurrency is saturated; retry later",
            ));
        };
        let started = Instant::now();
        let timeout_ms = adapter.manifest().limits.timeout_ms;
        let deadline = started
            .checked_add(Duration::from_millis(timeout_ms))
            .unwrap_or(started);
        let operation_id = format!("adapter:{}:{}", adapter_id, request.request_id);
        let cancellation = CancellationToken::new();
        let generation = request.context.operation_generation.unwrap_or(1);
        let context = AdapterExecutionContext {
            operation_id: operation_id.clone(),
            generation,
            cancellation: cancellation.clone(),
            deadline,
            runtime_store: self.runtime_store.clone(),
            role_lease_id: request.context.role_lease_id.clone(),
            role_lease_epoch: request.context.role_lease_epoch,
            runtime_contract_sha256: request.context.runtime_contract_sha256.clone(),
        };
        let now = OffsetDateTime::now_utc();
        let deadline_at =
            now + time::Duration::milliseconds(i64::try_from(timeout_ms).unwrap_or(i64::MAX));
        let mut checkpoint = OperationRuntimeCheckpoint {
            schema_version: OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION.to_owned(),
            operation_id,
            invocation_id: Some(request.request_id.clone()),
            adapter_id: Some(adapter_id.to_owned()),
            generation,
            phase: OperationPhase::Prepared,
            dispatch_state: ProviderDispatchState::NotStarted,
            cancellation_state: OperationCancellationState::NotRequested,
            reconciliation_state: OperationReconciliationState::NotRequired,
            root_pid: None,
            root_process_start_ticks: None,
            root_executable_sha256: None,
            job_object_name: None,
            active_process_count: 0,
            stdin_bytes: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            phase_started_at: now,
            last_progress_at: now,
            phase_deadline_at: deadline_at,
            absolute_deadline_at: deadline_at,
            restart_count: 0,
            restart_window_started_at: None,
            role_lease_id: context.role_lease_id.clone(),
            role_lease_epoch: context.role_lease_epoch,
            runtime_contract_sha256: context.runtime_contract_sha256.clone(),
            last_error_class: None,
            last_evidence_refs: Vec::new(),
        };
        self.runtime_store
            .put_checkpoint(checkpoint.clone())
            .await?;
        let adapter_future = adapter.execute(request.clone(), context.clone());
        tokio::pin!(adapter_future);
        let result = tokio::select! {
            result = &mut adapter_future => Some(result),
            () = tokio::time::sleep_until(deadline) => None,
        };
        let (mut result, mut timed_out, mut cleanup_completed) = match result {
            Some(Ok(result)) => (result, false, true),
            Some(Err(error)) => (
                rejected_result(
                    &request,
                    AdapterResultStatus::Failed,
                    "adapter_error",
                    &error.to_string(),
                ),
                false,
                true,
            ),
            None => {
                cancellation.cancel();
                if let Some(latest) = self
                    .runtime_store
                    .get_checkpoint(checkpoint.operation_id.clone())
                    .await?
                {
                    checkpoint = latest;
                }
                checkpoint.phase = OperationPhase::Cancelling;
                checkpoint.cancellation_state = OperationCancellationState::Requested;
                checkpoint.last_progress_at = OffsetDateTime::now_utc();
                self.runtime_store
                    .put_checkpoint(checkpoint.clone())
                    .await?;
                let cleanup = adapter_future.await;
                let cleanup_completed = cancellation.reap_completed();
                let detail = match (cleanup, cleanup_completed) {
                    (Ok(_), true) => "adapter execution timed out; cancellation and reap completed",
                    (Err(_), true) => {
                        "adapter execution timed out; cancellation reaped the child and returned an error"
                    }
                    (Ok(_) | Err(_), false) => {
                        "adapter execution timed out; process reap receipt is incomplete"
                    }
                };
                (
                    rejected_result(&request, AdapterResultStatus::Timeout, "timeout", detail),
                    true,
                    cleanup_completed,
                )
            }
        };
        if adapter.manifest().adapter_class == AdapterClass::ExternalCandidate
            && self.runtime_store.is_enabled()
            && context.role_lease_id.is_none()
            && matches!(
                result.status,
                AdapterResultStatus::Failed | AdapterResultStatus::Timeout
            )
            && let Some(mut persisted) = self
                .runtime_store
                .get_checkpoint(checkpoint.operation_id.clone())
                .await?
        {
            match classify_restart(&persisted, None, false) {
                RestartDecision::RestartFreshGeneration if persisted.restart_count == 0 => {
                    persisted.generation = persisted.generation.saturating_add(1);
                    persisted.restart_count = 1;
                    persisted.phase = OperationPhase::Prepared;
                    persisted.dispatch_state = ProviderDispatchState::NotStarted;
                    persisted.cancellation_state = OperationCancellationState::NotRequested;
                    persisted.reconciliation_state = OperationReconciliationState::NotRequired;
                    persisted.root_pid = None;
                    persisted.root_process_start_ticks = None;
                    persisted.root_executable_sha256 = None;
                    persisted.job_object_name = None;
                    persisted.active_process_count = 0;
                    persisted.stdin_bytes = 0;
                    persisted.stdout_bytes = 0;
                    persisted.stderr_bytes = 0;
                    persisted.last_error_class = Some("pre_dispatch_restart".to_owned());
                    persisted.last_progress_at = OffsetDateTime::now_utc();
                    persisted.phase_started_at = persisted.last_progress_at;
                    self.runtime_store.put_checkpoint(persisted.clone()).await?;
                    self.persist_safe_restart(adapter_id, "pre_dispatch_transport")
                        .await?;
                    sleep(Duration::from_millis(250)).await;

                    let retry_cancellation = CancellationToken::new();
                    let retry_context = AdapterExecutionContext {
                        operation_id: checkpoint.operation_id.clone(),
                        generation: persisted.generation,
                        cancellation: retry_cancellation.clone(),
                        deadline,
                        runtime_store: self.runtime_store.clone(),
                        role_lease_id: context.role_lease_id.clone(),
                        role_lease_epoch: context.role_lease_epoch,
                        runtime_contract_sha256: context.runtime_contract_sha256.clone(),
                    };
                    let retry_future = adapter.execute(request.clone(), retry_context);
                    tokio::pin!(retry_future);
                    let retry = tokio::select! {
                        result = &mut retry_future => Some(result),
                        () = tokio::time::sleep_until(deadline) => None,
                    };
                    (result, timed_out, cleanup_completed) = match retry {
                        Some(Ok(result)) => (result, false, true),
                        Some(Err(error)) => (
                            rejected_result(
                                &request,
                                AdapterResultStatus::Failed,
                                "adapter_error",
                                &error.to_string(),
                            ),
                            false,
                            true,
                        ),
                        None => {
                            retry_cancellation.cancel();
                            let cleanup = retry_future.await;
                            let cleanup_completed = retry_cancellation.reap_completed();
                            let detail = match (cleanup, cleanup_completed) {
                                (Ok(_), true) => {
                                    "adapter restart timed out; cancellation and reap completed"
                                }
                                (Err(_), true) => {
                                    "adapter restart timed out; child reaped and returned an error"
                                }
                                (Ok(_) | Err(_), false) => {
                                    "adapter restart timed out; process reap receipt is incomplete"
                                }
                            };
                            (
                                rejected_result(
                                    &request,
                                    AdapterResultStatus::Timeout,
                                    "timeout",
                                    detail,
                                ),
                                true,
                                cleanup_completed,
                            )
                        }
                    };
                    checkpoint = self
                        .runtime_store
                        .get_checkpoint(checkpoint.operation_id.clone())
                        .await?
                        .unwrap_or(persisted);
                }
                RestartDecision::ReconcileBeforeAnyRetry => {
                    persisted.reconciliation_state = OperationReconciliationState::Pending;
                    checkpoint = persisted;
                }
                RestartDecision::OpenCircuit => {
                    checkpoint = persisted;
                    if let Some(record) = self.force_open_circuit(adapter_id) {
                        self.persist_circuit(adapter_id, &record, result.status)
                            .await?;
                    }
                }
                RestartDecision::AcceptCapturedTerminalThenReap
                | RestartDecision::RestartFreshGeneration
                | RestartDecision::TerminalFailure => {}
            }
        }
        result.duration_ms = millis(started.elapsed());
        Self::enforce_output_limit(adapter.manifest(), &mut result, blob_store)?;
        checkpoint.phase = if result.status == AdapterResultStatus::Succeeded {
            OperationPhase::Completed
        } else {
            OperationPhase::Failed
        };
        checkpoint.last_progress_at = OffsetDateTime::now_utc();
        if timed_out && cleanup_completed {
            checkpoint.cancellation_state = OperationCancellationState::Reaped;
        }
        checkpoint.last_error_class = result.error.as_ref().map(|error| error.code.clone());
        self.runtime_store.put_checkpoint(checkpoint).await?;
        if let Some(record) = self.update_circuit(adapter_id, result.status) {
            self.persist_circuit(adapter_id, &record, result.status)
                .await?;
        }
        Ok(result)
    }

    pub async fn half_open_probe(&self, adapter_id: &str) -> AdapterHealth {
        if let Err(error) = self.hydrate_circuit(adapter_id).await {
            return match self.registry.adapter(adapter_id) {
                Ok(adapter) => Self::unavailable_health(
                    adapter.manifest(),
                    format!("load durable adapter circuit state: {error}"),
                ),
                Err(_) => AdapterHealth {
                    adapter_id: adapter_id.to_owned(),
                    name: adapter_id.to_owned(),
                    state: AdapterState::Unavailable,
                    healthy: false,
                    message: error.to_string(),
                    consecutive_failures: 0,
                    circuit_open: false,
                    checked_at: OffsetDateTime::now_utc(),
                },
            };
        }
        if let Some(record) = self.set_half_open(adapter_id)
            && let Err(error) = self
                .persist_circuit(adapter_id, &record, AdapterResultStatus::Unavailable)
                .await
        {
            return match self.registry.adapter(adapter_id) {
                Ok(adapter) => Self::unavailable_health(
                    adapter.manifest(),
                    format!("persist half-open adapter circuit state: {error}"),
                ),
                Err(_) => AdapterHealth {
                    adapter_id: adapter_id.to_owned(),
                    name: adapter_id.to_owned(),
                    state: AdapterState::Unavailable,
                    healthy: false,
                    message: error.to_string(),
                    consecutive_failures: 0,
                    circuit_open: true,
                    checked_at: OffsetDateTime::now_utc(),
                },
            };
        }
        let mut health = self.health_probe(adapter_id).await;
        if health.healthy {
            if let Some(record) = self.reset_circuit(adapter_id)
                && let Err(error) = self
                    .persist_circuit(adapter_id, &record, AdapterResultStatus::Succeeded)
                    .await
            {
                health.healthy = false;
                health.state = AdapterState::Unavailable;
                health.message = format!("persist closed adapter circuit state: {error}");
                return health;
            }
            health.circuit_open = false;
            health.consecutive_failures = 0;
            health.state = AdapterState::Healthy;
        }
        health
    }

    pub async fn shutdown(&self) -> Result<(), EngineError> {
        for manifest in self.registry.manifests() {
            let adapter = self.registry.adapter(&manifest.adapter_id)?;
            adapter.shutdown().await?;
        }
        Ok(())
    }

    fn unavailable_health(manifest: &CapabilityManifest, message: String) -> AdapterHealth {
        AdapterHealth {
            adapter_id: manifest.adapter_id.clone(),
            name: manifest.name.clone(),
            state: AdapterState::Unavailable,
            healthy: false,
            message,
            consecutive_failures: 0,
            circuit_open: false,
            checked_at: OffsetDateTime::now_utc(),
        }
    }

    fn apply_circuit_to_health(&self, health: &mut AdapterHealth) {
        if let Some(record) = self.circuit_record(&health.adapter_id) {
            health.consecutive_failures = record.consecutive_failures;
            health.circuit_open = record.circuit_open;
            if record.circuit_open {
                health.healthy = false;
                health.state = AdapterState::CircuitOpen;
                "adapter circuit breaker is open".clone_into(&mut health.message);
            }
        }
    }

    fn enforce_output_limit(
        manifest: &CapabilityManifest,
        result: &mut AdapterResult,
        blob_store: Option<&BlobStore>,
    ) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec(&result.output)?;
        if bytes.len() <= manifest.limits.max_output_bytes {
            return Ok(());
        }
        let blob = match blob_store {
            Some(store) => Some(store.put_bytes(&bytes)?),
            None => None,
        };
        result.output_blob.clone_from(&blob);
        result.output = json!({
            "status": "output_too_large",
            "blob_ref": blob,
            "original_size_bytes": bytes.len()
        });
        for observation in &mut result.observations {
            observation.raw_blob_ref.clone_from(&result.output_blob);
            observation.payload = result.output.clone();
        }
        Ok(())
    }

    fn update_circuit(
        &self,
        adapter_id: &str,
        status: AdapterResultStatus,
    ) -> Option<CircuitRecord> {
        let Ok(mut circuits) = self.circuits.lock() else {
            return None;
        };
        let record = circuits.entry(adapter_id.to_owned()).or_default();
        match status {
            AdapterResultStatus::Succeeded => {
                record.consecutive_failures = 0;
                record.circuit_open = false;
                record.state = AdapterState::Healthy;
            }
            AdapterResultStatus::Failed | AdapterResultStatus::Timeout => {
                record.consecutive_failures += 1;
                let threshold = self
                    .registry
                    .inspect(adapter_id)
                    .map_or(2, |manifest| manifest.limits.circuit_breaker_failures);
                if record.consecutive_failures >= threshold {
                    record.circuit_open = true;
                    record.state = AdapterState::CircuitOpen;
                } else {
                    record.state = AdapterState::Degraded;
                }
            }
            _ => {}
        }
        Some(record.clone())
    }

    fn circuit_is_open(&self, adapter_id: &str) -> bool {
        self.circuit_record(adapter_id)
            .is_some_and(|record| record.circuit_open)
    }

    fn circuit_record(&self, adapter_id: &str) -> Option<CircuitRecord> {
        self.circuits.lock().ok().and_then(|circuits| {
            circuits.get(adapter_id).map(|record| CircuitRecord {
                consecutive_failures: record.consecutive_failures,
                circuit_open: record.circuit_open,
                state: record.state,
            })
        })
    }

    fn set_half_open(&self, adapter_id: &str) -> Option<CircuitRecord> {
        let mut circuits = self.circuits.lock().ok()?;
        let record = circuits.entry(adapter_id.to_owned()).or_default();
        record.circuit_open = false;
        record.state = AdapterState::Degraded;
        Some(record.clone())
    }

    fn force_open_circuit(&self, adapter_id: &str) -> Option<CircuitRecord> {
        let mut circuits = self.circuits.lock().ok()?;
        let record = circuits.entry(adapter_id.to_owned()).or_default();
        record.circuit_open = true;
        record.state = AdapterState::CircuitOpen;
        Some(record.clone())
    }

    async fn hydrate_circuit(&self, adapter_id: &str) -> Result<(), EngineError> {
        if self
            .hydrated_circuits
            .lock()
            .is_ok_and(|hydrated| hydrated.contains(adapter_id))
        {
            return Ok(());
        }
        let window = self.runtime_store.load_restart_window(adapter_id).await?;
        if let Some(window) = window {
            let state = match window.circuit_state {
                AdapterCircuitState::Closed if window.consecutive_failures == 0 => {
                    AdapterState::Healthy
                }
                AdapterCircuitState::Closed | AdapterCircuitState::HalfOpen => {
                    AdapterState::Degraded
                }
                AdapterCircuitState::Open => AdapterState::CircuitOpen,
            };
            let mut circuits = self
                .circuits
                .lock()
                .map_err(|_| adapter_rejected("adapter circuit state lock is poisoned"))?;
            circuits.insert(
                adapter_id.to_owned(),
                CircuitRecord {
                    consecutive_failures: window.consecutive_failures,
                    circuit_open: window.circuit_state == AdapterCircuitState::Open,
                    state,
                },
            );
        }
        self.hydrated_circuits
            .lock()
            .map_err(|_| adapter_rejected("adapter circuit hydration lock is poisoned"))?
            .insert(adapter_id.to_owned());
        Ok(())
    }

    fn reset_circuit(&self, adapter_id: &str) -> Option<CircuitRecord> {
        let mut circuits = self.circuits.lock().ok()?;
        let record = circuits.entry(adapter_id.to_owned()).or_default();
        record.consecutive_failures = 0;
        record.circuit_open = false;
        record.state = AdapterState::Healthy;
        Some(record.clone())
    }

    async fn persist_circuit(
        &self,
        adapter_id: &str,
        record: &CircuitRecord,
        status: AdapterResultStatus,
    ) -> Result<(), EngineError> {
        let now = OffsetDateTime::now_utc();
        let now_epoch = now.unix_timestamp();
        let mut window = self
            .runtime_store
            .load_restart_window(adapter_id)
            .await?
            .unwrap_or_else(|| OperationRestartWindow {
                schema_version: OPERATION_RESTART_WINDOW_SCHEMA_VERSION.to_owned(),
                key: adapter_id.to_owned(),
                restart_timestamps: Vec::new(),
                circuit_state: AdapterCircuitState::Closed,
                consecutive_failures: 0,
                last_failure_class: None,
                updated_at: now_epoch.to_string(),
            });
        window.restart_timestamps.retain(|timestamp| {
            timestamp
                .parse::<i64>()
                .is_ok_and(|observed| observed >= now_epoch.saturating_sub(60))
        });
        match status {
            AdapterResultStatus::Failed | AdapterResultStatus::Timeout => {
                window.restart_timestamps.push(now_epoch.to_string());
                window.last_failure_class = Some(format!("{status:?}").to_ascii_lowercase());
            }
            AdapterResultStatus::Succeeded => {
                window.last_failure_class = None;
            }
            _ => {}
        }
        window.consecutive_failures = record.consecutive_failures;
        window.circuit_state = if record.circuit_open {
            AdapterCircuitState::Open
        } else if record.state == AdapterState::Degraded
            && !matches!(
                status,
                AdapterResultStatus::Failed | AdapterResultStatus::Timeout
            )
        {
            AdapterCircuitState::HalfOpen
        } else {
            AdapterCircuitState::Closed
        };
        window.updated_at = now_epoch.to_string();
        self.runtime_store.put_restart_window(window).await
    }

    async fn persist_safe_restart(
        &self,
        adapter_id: &str,
        reason: &str,
    ) -> Result<(), EngineError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut window = self
            .runtime_store
            .load_restart_window(adapter_id)
            .await?
            .unwrap_or_else(|| OperationRestartWindow {
                schema_version: OPERATION_RESTART_WINDOW_SCHEMA_VERSION.to_owned(),
                key: adapter_id.to_owned(),
                restart_timestamps: Vec::new(),
                circuit_state: AdapterCircuitState::Closed,
                consecutive_failures: 0,
                last_failure_class: None,
                updated_at: now.to_string(),
            });
        window.restart_timestamps.retain(|timestamp| {
            timestamp
                .parse::<i64>()
                .is_ok_and(|observed| observed >= now.saturating_sub(60))
        });
        window.restart_timestamps.push(now.to_string());
        window.last_failure_class = Some(reason.to_owned());
        window.updated_at = now.to_string();
        self.runtime_store.put_restart_window(window).await
    }
}

pub struct AdapterMemoryWriter;

impl AdapterMemoryWriter {
    pub async fn write_observation(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        observation: &mut AdapterObservation,
    ) -> Result<WriteReceiptRef, EngineError> {
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: eliot_types::AgentId::new_v7(),
                session_id: None,
                project_id: observation.project_id,
                task_id: Some(observation.task_id),
                scope: "adapter-observation".to_owned(),
                authority: "eliot-adapter-runtime".to_owned(),
                visibility: Visibility::Internal,
                taint: observation.taint,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: "eliot_adapter_observation".to_owned(),
            observation: observation.summary.clone(),
            payload: serde_json::to_value(&*observation)?,
        });
        let receipt = writer.submit(admission.admit(&command)?).await?;
        let receipt_ref = WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        };
        observation.write_receipt = Some(receipt_ref.clone());
        Ok(receipt_ref)
    }
}

pub struct AdapterObservationBridge;

impl AdapterObservationBridge {
    pub fn to_blackboard_candidate(
        state: &mut WorkState,
        owner_session_id: eliot_types::AgentSessionId,
        observation: &mut AdapterObservation,
    ) -> BlackboardItem {
        let item = BlackboardService.create_item(
            state,
            BlackboardAddInput {
                project_id: observation.project_id,
                task_id: observation.task_id,
                owner_session_id,
                work_item_id: None,
                lease_id: None,
                kind: BlackboardItemKind::FindingCandidate,
                scope: BlackboardScope {
                    memory_scope: vec![format!("adapter:{}", observation.adapter_id)],
                    files: Vec::new(),
                    symbols: Vec::new(),
                    work_items: Vec::new(),
                },
                payload_ref: observation.payload_ref.clone(),
                evidence_refs: observation
                    .write_receipt
                    .as_ref()
                    .map(|receipt| vec![format!("write_receipt:{}", receipt.receipt_id)])
                    .unwrap_or_default(),
                confidence: Some(ConfidenceLevel::Low),
                expires_at: None,
            },
        );
        observation.blackboard_item_id = Some(item.blackboard_item_id);
        item
    }

    pub fn to_mailbox_notification(
        state: &mut WorkState,
        sender_session_id: eliot_types::AgentSessionId,
        observation: &mut AdapterObservation,
    ) -> MailboxMessage {
        let message = MailboxService.send(
            state,
            MailboxSendInput {
                message_id: None,
                project_id: observation.project_id,
                task_id: observation.task_id,
                sender_session_id,
                recipient: MailboxRecipient::Controller,
                kind: MailboxMessageKind::ReviewRequested,
                payload_ref: observation.payload_ref.clone(),
                requires_ack: Some(true),
                expires_at: None,
            },
        );
        observation.mailbox_message_id = Some(message.message_id);
        observation.controller_review_required = true;
        message
    }
}

pub fn normalize_result_to_observation(result: &AdapterResult) -> AdapterObservation {
    let summary = match result.status {
        AdapterResultStatus::Succeeded => {
            format!("adapter {} produced candidate output", result.adapter_id)
        }
        AdapterResultStatus::Failed => format!("adapter {} failed", result.adapter_id),
        AdapterResultStatus::Timeout => format!("adapter {} timed out", result.adapter_id),
        AdapterResultStatus::Rejected => format!("adapter {} request rejected", result.adapter_id),
        AdapterResultStatus::OutputTooLarge => {
            format!("adapter {} output exceeded inline limit", result.adapter_id)
        }
        AdapterResultStatus::CircuitOpen => {
            format!("adapter {} circuit is open", result.adapter_id)
        }
        AdapterResultStatus::Unavailable => format!("adapter {} unavailable", result.adapter_id),
    };
    AdapterObservation {
        observation_id: uuid_like("adapter-observation"),
        adapter_id: result.adapter_id.clone(),
        result_id: result.result_id.clone(),
        project_id: result
            .observations
            .first()
            .map_or_else(eliot_types::ProjectId::new_v7, |observation| {
                observation.project_id
            }),
        task_id: result
            .observations
            .first()
            .map_or_else(eliot_types::TaskId::new_v7, |observation| {
                observation.task_id
            }),
        summary,
        payload: result.output.clone(),
        payload_ref: format!("adapter_result:{}", result.result_id),
        raw_blob_ref: result.output_blob.clone(),
        taint: TaintClass::LocalTool,
        write_receipt: None,
        blackboard_item_id: None,
        mailbox_message_id: None,
        controller_review_required: true,
        generated_at: OffsetDateTime::now_utc(),
    }
}

pub fn test_request(adapter_id: &str, capability: AdapterCapability) -> AdapterRequest {
    AdapterRequest {
        request_id: uuid_like("adapter-request"),
        adapter_id: adapter_id.to_owned(),
        requested_capability: capability,
        context: AdapterContext {
            project_id: eliot_types::ProjectId::new_v7(),
            task_id: eliot_types::TaskId::new_v7(),
            session_id: None,
            trace_id: uuid_like("trace"),
            created_at: OffsetDateTime::now_utc(),
            role_lease_id: None,
            role_lease_epoch: None,
            operation_generation: None,
            runtime_contract_sha256: None,
        },
        input: json!({ "mode": "test" }),
    }
}

pub struct HealthAdapter {
    manifest: CapabilityManifest,
}

impl HealthAdapter {
    pub fn new() -> Self {
        Self {
            manifest: manifest(
                "health",
                "Health Adapter",
                AdapterClass::Health,
                vec![
                    AdapterCapability::HealthCheck,
                    AdapterCapability::ExecuteTest,
                ],
                AdapterLimits::default(),
            ),
        }
    }
}

impl Default for HealthAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for HealthAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move { Ok(healthy(&self.manifest, "health adapter available")) })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        _context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            Ok(success_result(
                &request,
                json!({ "status": "healthy", "adapter": request.adapter_id }),
            ))
        })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub struct TestEchoAdapter {
    manifest: CapabilityManifest,
}

impl TestEchoAdapter {
    pub fn new() -> Self {
        Self {
            manifest: manifest(
                "test-echo",
                "Test Echo Adapter",
                AdapterClass::InternalTest,
                vec![
                    AdapterCapability::HealthCheck,
                    AdapterCapability::ExecuteTest,
                    AdapterCapability::EmitCandidateObservation,
                    AdapterCapability::RequestControllerReview,
                ],
                AdapterLimits::default(),
            ),
        }
    }
}

impl Default for TestEchoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for TestEchoAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move { Ok(healthy(&self.manifest, "test echo adapter available")) })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        _context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            Ok(success_result(
                &request,
                json!({ "echo": request.input, "tainted_candidate": true }),
            ))
        })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub struct TestFailingAdapter {
    manifest: CapabilityManifest,
}

impl TestFailingAdapter {
    pub fn new() -> Self {
        let limits = AdapterLimits {
            circuit_breaker_failures: 5,
            ..AdapterLimits::default()
        };
        Self {
            manifest: manifest(
                "test-failing",
                "Test Failing Adapter",
                AdapterClass::InternalTest,
                vec![
                    AdapterCapability::HealthCheck,
                    AdapterCapability::ExecuteTest,
                ],
                limits,
            ),
        }
    }
}

impl Default for TestFailingAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for TestFailingAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move { Ok(healthy(&self.manifest, "test failing adapter registered")) })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        _context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            Ok(rejected_result(
                &request,
                AdapterResultStatus::Failed,
                "test_failure",
                "intentional test adapter failure",
            ))
        })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub struct TestSlowAdapter {
    manifest: CapabilityManifest,
}

impl TestSlowAdapter {
    pub fn new() -> Self {
        let limits = AdapterLimits {
            timeout_ms: 50,
            ..AdapterLimits::default()
        };
        Self {
            manifest: manifest(
                "test-slow",
                "Test Slow Adapter",
                AdapterClass::InternalTest,
                vec![
                    AdapterCapability::HealthCheck,
                    AdapterCapability::ExecuteTest,
                ],
                limits,
            ),
        }
    }
}

impl Default for TestSlowAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for TestSlowAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move { Ok(healthy(&self.manifest, "test slow adapter registered")) })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            tokio::select! {
                () = sleep(Duration::from_millis(250)) => {
                    Ok(success_result(&request, json!({ "slow": true })))
                }
                () = context.cancellation.cancelled() => {
                    Ok(rejected_result(
                        &request,
                        AdapterResultStatus::Timeout,
                        "cancelled",
                        "test adapter observed cancellation",
                    ))
                }
            }
        })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub struct TestLargeOutputAdapter {
    manifest: CapabilityManifest,
}

impl TestLargeOutputAdapter {
    pub fn new() -> Self {
        let limits = AdapterLimits {
            max_output_bytes: 64,
            ..AdapterLimits::default()
        };
        Self {
            manifest: manifest(
                "test-large-output",
                "Test Large Output Adapter",
                AdapterClass::InternalTest,
                vec![
                    AdapterCapability::HealthCheck,
                    AdapterCapability::ExecuteTest,
                ],
                limits,
            ),
        }
    }
}

impl Default for TestLargeOutputAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for TestLargeOutputAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move {
            Ok(healthy(
                &self.manifest,
                "test large-output adapter registered",
            ))
        })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        _context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            Ok(success_result(
                &request,
                json!({ "raw_text": "x".repeat(1024), "tainted_candidate": true }),
            ))
        })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn validate_request(
    manifest: &CapabilityManifest,
    request: &AdapterRequest,
) -> Result<(), EngineError> {
    if request.adapter_id != manifest.adapter_id {
        return Err(adapter_rejected(
            "request adapter_id does not match selected adapter",
        ));
    }
    if !manifest
        .capabilities
        .contains(&request.requested_capability)
    {
        return Err(adapter_rejected(
            "requested adapter capability is not in manifest",
        ));
    }
    if request.requested_capability.is_forbidden_authority() {
        return Err(adapter_rejected("forbidden adapter authority requested"));
    }
    let payload_len = serde_json::to_vec(&request.input)?.len();
    if payload_len > manifest.limits.max_payload_bytes {
        return Err(adapter_rejected("adapter request payload exceeds limit"));
    }
    Ok(())
}

fn success_result(request: &AdapterRequest, output: Value) -> AdapterResult {
    let mut result = AdapterResult {
        result_id: uuid_like("adapter-result"),
        request_id: request.request_id.clone(),
        adapter_id: request.adapter_id.clone(),
        status: AdapterResultStatus::Succeeded,
        output,
        output_blob: None,
        observations: Vec::new(),
        error: None,
        duration_ms: 0,
        trace_id: request.context.trace_id.clone(),
        created_at: OffsetDateTime::now_utc(),
    };
    let observation = observation_for_request(request, &result);
    result.observations.push(observation);
    result
}

fn rejected_result(
    request: &AdapterRequest,
    status: AdapterResultStatus,
    code: &str,
    message: &str,
) -> AdapterResult {
    let mut result = AdapterResult {
        result_id: uuid_like("adapter-result"),
        request_id: request.request_id.clone(),
        adapter_id: request.adapter_id.clone(),
        status,
        output: json!({ "status": status, "message": message }),
        output_blob: None,
        observations: Vec::new(),
        error: Some(AdapterError {
            code: code.to_owned(),
            message: message.to_owned(),
            retryable: matches!(
                status,
                AdapterResultStatus::Timeout | AdapterResultStatus::Failed
            ),
        }),
        duration_ms: 0,
        trace_id: request.context.trace_id.clone(),
        created_at: OffsetDateTime::now_utc(),
    };
    let observation = observation_for_request(request, &result);
    result.observations.push(observation);
    result
}

fn observation_for_request(request: &AdapterRequest, result: &AdapterResult) -> AdapterObservation {
    AdapterObservation {
        observation_id: uuid_like("adapter-observation"),
        adapter_id: request.adapter_id.clone(),
        result_id: result.result_id.clone(),
        project_id: request.context.project_id,
        task_id: request.context.task_id,
        summary: format!(
            "adapter {} returned {:?}",
            request.adapter_id, result.status
        ),
        payload: result.output.clone(),
        payload_ref: format!("adapter_result:{}", result.result_id),
        raw_blob_ref: result.output_blob.clone(),
        taint: TaintClass::LocalTool,
        write_receipt: None,
        blackboard_item_id: None,
        mailbox_message_id: None,
        controller_review_required: true,
        generated_at: OffsetDateTime::now_utc(),
    }
}

fn healthy(manifest: &CapabilityManifest, message: &str) -> AdapterHealth {
    AdapterHealth {
        adapter_id: manifest.adapter_id.clone(),
        name: manifest.name.clone(),
        state: AdapterState::Healthy,
        healthy: true,
        message: message.to_owned(),
        consecutive_failures: 0,
        circuit_open: false,
        checked_at: OffsetDateTime::now_utc(),
    }
}

fn manifest(
    adapter_id: &str,
    name: &str,
    adapter_class: AdapterClass,
    capabilities: Vec<AdapterCapability>,
    limits: AdapterLimits,
) -> CapabilityManifest {
    CapabilityManifest {
        adapter_id: adapter_id.to_owned(),
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        description: format!("{name} internal governed adapter"),
        adapter_class,
        capabilities: capabilities.clone(),
        authority_profile: AdapterAuthorityProfile {
            allowed_projects: Vec::new(),
            allowed_roles: Vec::new(),
            allowed_capabilities: capabilities,
            can_write_truth: false,
            can_request_patch: false,
            can_finish_task: false,
        },
        limits,
        enabled_by_default: true,
        process_policy: ProcessExecutionPolicy::default(),
    }
}

fn adapter_rejected(message: impl Into<String>) -> EngineError {
    EngineError::WriteRejected(message.into())
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn uuid_like(prefix: &str) -> String {
    format!("{prefix}:{}", eliot_types::OperationId::new_v7())
}
