use eliot_engine::{
    Adapter, AdapterExecutionContext, AdapterMemoryWriter, AdapterObservationBridge,
    AdapterRegistry, AdapterSupervisor, BoxAdapterFuture, EngineError, HealthAdapter,
    TestEchoAdapter, TestFailingAdapter, TestLargeOutputAdapter, TestSlowAdapter, WorkState,
    WriteAdmissionService, WriterActor, WriterConfig, normalize_result_to_observation,
    test_request,
};
use eliot_store::{BlobStore, CanonicalStore, ControlWal};
use eliot_types::{
    AdapterAuthorityProfile, AdapterCapability, AdapterClass, AdapterResult, AdapterResultStatus,
    AdapterState, AgentHostId, BlackboardItemKind, BlobStoreConfig, CapabilityManifest,
    ControlWalConfig, GovernorConfig, MailboxMessageKind, ModuleAuthorityProfile, ModuleCapability,
    OperationPhase, OperationReconciliationState, ProviderDeclaredBudget, ProviderDispatchState,
    ProviderRoutePolicy, TaintClass,
};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct FlakyExternalAdapter {
    manifest: CapabilityManifest,
    echo: TestEchoAdapter,
}

impl FlakyExternalAdapter {
    fn new() -> Self {
        Self {
            manifest: external_test_manifest("flaky-external", 1_000),
            echo: TestEchoAdapter::new(),
        }
    }
}

impl Adapter for FlakyExternalAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, eliot_types::AdapterHealth> {
        self.echo.health()
    }

    fn execute(
        &self,
        request: eliot_types::AdapterRequest,
        context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        if context.generation == 1 {
            Box::pin(async {
                Err(EngineError::RuntimeSupervision(
                    "injected pre-dispatch transport failure".to_owned(),
                ))
            })
        } else {
            self.echo.execute(request, context)
        }
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        self.echo.shutdown()
    }
}

struct PostDispatchHangAdapter {
    manifest: CapabilityManifest,
    executions: Arc<AtomicU32>,
    echo: TestEchoAdapter,
}

impl PostDispatchHangAdapter {
    fn new(executions: Arc<AtomicU32>) -> Self {
        Self {
            manifest: external_test_manifest("post-dispatch-hang", 50),
            executions,
            echo: TestEchoAdapter::new(),
        }
    }
}

impl Adapter for PostDispatchHangAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, eliot_types::AdapterHealth> {
        self.echo.health()
    }

    fn execute(
        &self,
        _request: eliot_types::AdapterRequest,
        context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        let executions = Arc::clone(&self.executions);
        Box::pin(async move {
            executions.fetch_add(1, Ordering::AcqRel);
            let mut checkpoint = context
                .runtime_store
                .get_checkpoint(context.operation_id.clone())
                .await?
                .ok_or_else(|| {
                    EngineError::RuntimeSupervision(
                        "injected adapter checkpoint is absent".to_owned(),
                    )
                })?;
            checkpoint.phase = OperationPhase::Running;
            checkpoint.dispatch_state = ProviderDispatchState::Proven;
            context.runtime_store.put_checkpoint(checkpoint).await?;
            context.cancellation.cancelled().await;
            Err(EngineError::RuntimeSupervision(
                "injected post-dispatch hang observed cancellation".to_owned(),
            ))
        })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        self.echo.shutdown()
    }
}

fn external_test_manifest(adapter_id: &str, timeout_ms: u64) -> CapabilityManifest {
    let mut manifest = TestEchoAdapter::new().manifest().clone();
    adapter_id.clone_into(&mut manifest.adapter_id);
    adapter_id.clone_into(&mut manifest.name);
    manifest.adapter_class = AdapterClass::ExternalCandidate;
    manifest.limits.timeout_ms = timeout_ms;
    manifest
}

fn external_test_request(adapter_id: &str, timeout_ms: u64) -> eliot_types::AdapterRequest {
    let mut request = test_request(adapter_id, AdapterCapability::ExecuteTest);
    let route_policy = ProviderRoutePolicy::for_route(
        AgentHostId::Antigravity,
        "adapter-supervisor-test",
        ProviderDeclaredBudget::new(timeout_ms, 64 * 1024)
            .with_cancellation_grace_ms(1)
            .with_cleanup_grace_ms(1),
    );
    request.input = serde_json::json!({"provider_route_policy": route_policy});
    request
}

#[test]
fn adapter_trait_exists() {
    fn assert_adapter_trait<T: Adapter>() {}

    assert_adapter_trait::<HealthAdapter>();
    assert_adapter_trait::<TestEchoAdapter>();
    assert_adapter_trait::<TestFailingAdapter>();
    assert_adapter_trait::<TestSlowAdapter>();
    assert_adapter_trait::<TestLargeOutputAdapter>();
}

#[test]
fn adapter_registry_registers_builtin_adapters() -> TestResult {
    let registry = AdapterRegistry::builtin()?;
    let manifests = registry.manifests();

    for adapter_id in [
        "health",
        "test-echo",
        "test-failing",
        "test-slow",
        "test-large-output",
    ] {
        assert!(
            manifests
                .iter()
                .any(|manifest| manifest.adapter_id == adapter_id),
            "missing adapter {adapter_id}"
        );
    }
    Ok(())
}

#[test]
fn adapter_manifest_validates() -> TestResult {
    let registry = AdapterRegistry::new();
    registry.validate_manifest(TestEchoAdapter::new().manifest())?;
    Ok(())
}

#[test]
fn adapter_unknown_capability_denied() {
    let result = AdapterRegistry::validate_capability_names(&["raw_shell".to_owned()]);
    assert!(result.is_err());
}

#[test]
fn adapter_truth_patch_finish_capabilities_forbidden() {
    for capability in [
        AdapterCapability::WriteTruth,
        AdapterCapability::RequestPatch,
        AdapterCapability::FinishTask,
    ] {
        let mut manifest = TestEchoAdapter::new().manifest().clone();
        manifest.capabilities.push(capability);
        assert!(AdapterRegistry::new().validate_manifest(&manifest).is_err());
    }
}

#[tokio::test]
async fn adapter_execute_success_test_adapter() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;

    assert_eq!(result.status, AdapterResultStatus::Succeeded);
    assert_eq!(result.adapter_id, "test-echo");
    assert_eq!(result.observations.len(), 1);
    Ok(())
}

#[tokio::test]
async fn adapter_execute_invalid_request() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::EmitArtifactHandle),
            None,
        )
        .await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn adapter_execute_timeout() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-slow",
            test_request("test-slow", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;

    assert_eq!(result.status, AdapterResultStatus::Timeout);
    Ok(())
}

#[tokio::test]
async fn adapter_timeout_is_isolated_from_other_adapter_capacity() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let slow = supervisor.execute(
        "test-slow",
        test_request("test-slow", AdapterCapability::ExecuteTest),
        None,
    );
    tokio::pin!(slow);
    tokio::select! {
        result = &mut slow => {
            return Err(format!("slow adapter completed before isolation probe: {result:?}").into());
        }
        () = sleep(Duration::from_millis(5)) => {}
    }

    let echo = tokio::time::timeout(
        Duration::from_millis(100),
        supervisor.execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        ),
    )
    .await??;
    assert_eq!(echo.status, AdapterResultStatus::Succeeded);
    assert_eq!(slow.await?.status, AdapterResultStatus::Timeout);
    Ok(())
}

#[tokio::test]
async fn adapter_execute_output_too_large_to_blob_ref() -> TestResult {
    let root = test_root("large-output-blob")?;
    let blob_store = BlobStore::open(&BlobStoreConfig {
        root: root.join("blobs").display().to_string(),
    })?;
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-large-output",
            test_request("test-large-output", AdapterCapability::ExecuteTest),
            Some(&blob_store),
        )
        .await?;

    let blob = result
        .output_blob
        .as_ref()
        .ok_or_else(|| std::io::Error::other("large output blob ref missing"))?;
    assert!(blob_store.blob_path(blob).exists());
    assert_eq!(result.observations[0].raw_blob_ref.as_ref(), Some(blob));
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_health_probe() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let health = supervisor.health_probe("test-echo").await;

    assert_eq!(health.adapter_id, "test-echo");
    assert_eq!(health.state, AdapterState::Healthy);
    assert!(health.healthy);
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_circuit_breaker_opens() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;

    for _ in 0..5 {
        let result = supervisor
            .execute(
                "test-failing",
                test_request("test-failing", AdapterCapability::ExecuteTest),
                None,
            )
            .await?;
        assert_eq!(result.status, AdapterResultStatus::Failed);
    }

    let health = supervisor.health_probe("test-failing").await;
    assert_eq!(health.state, AdapterState::CircuitOpen);
    assert!(health.circuit_open);
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_hydrates_durable_open_circuit() -> TestResult {
    let root = test_root("adapter-durable-circuit")?;
    let wal = ControlWal::open(&ControlWalConfig {
        path: root.join("control.redb").display().to_string(),
    })?;
    let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let runtime = writer.operation_runtime();
    let actor_task = tokio::spawn(actor.run());

    let first = AdapterSupervisor::with_runtime(AdapterRegistry::builtin()?, runtime.clone());
    for _ in 0..5 {
        let result = first
            .execute(
                "test-failing",
                test_request("test-failing", AdapterCapability::ExecuteTest),
                None,
            )
            .await?;
        assert_eq!(result.status, AdapterResultStatus::Failed);
    }
    drop(first);

    let restarted = AdapterSupervisor::with_runtime(AdapterRegistry::builtin()?, runtime);
    let rejected = restarted
        .execute(
            "test-failing",
            test_request("test-failing", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;
    assert_eq!(rejected.status, AdapterResultStatus::CircuitOpen);
    drop(restarted);
    drop(writer);
    actor_task.await?;
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_does_not_redispatch_before_provider_dispatch() -> TestResult {
    let root = test_root("adapter-pre-dispatch-restart")?;
    let wal = ControlWal::open(&ControlWalConfig {
        path: root.join("control.redb").display().to_string(),
    })?;
    let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let runtime = writer.operation_runtime();
    let actor_task = tokio::spawn(actor.run());
    let mut registry = AdapterRegistry::new();
    registry.register(FlakyExternalAdapter::new())?;
    let supervisor = AdapterSupervisor::with_runtime(registry, runtime.clone());
    let request = external_test_request("flaky-external", 100);
    let operation_id = format!("adapter:flaky-external:{}", request.request_id);

    let result = supervisor.execute("flaky-external", request, None).await?;
    assert_eq!(result.status, AdapterResultStatus::Failed);
    let checkpoint = runtime
        .get_checkpoint(operation_id.clone())
        .await?
        .ok_or_else(|| std::io::Error::other("restart checkpoint missing"))?;
    assert_eq!(checkpoint.generation, 1);
    assert_eq!(checkpoint.restart_count, 0);
    assert_eq!(checkpoint.phase, OperationPhase::Failed);
    let window = runtime
        .load_restart_window("flaky-external")
        .await?
        .ok_or_else(|| std::io::Error::other("restart window missing"))?;
    assert!(window.restart_timestamps.is_empty());
    assert!(window.last_failure_at.is_some());
    assert!(window.last_success_at.is_none());
    assert!(window.last_failure_class.is_some());
    assert_eq!(
        window.last_terminal_operation_ref.as_deref(),
        Some(operation_id.as_str())
    );

    drop(supervisor);
    drop(runtime);
    drop(writer);
    actor_task.await?;
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_persists_exact_authority_generation_binding() -> TestResult {
    let root = test_root("adapter-authority-binding")?;
    let wal = ControlWal::open(&ControlWalConfig {
        path: root.join("control.redb").display().to_string(),
    })?;
    let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let runtime = writer.operation_runtime();
    let actor_task = tokio::spawn(actor.run());
    let supervisor = AdapterSupervisor::with_runtime(AdapterRegistry::builtin()?, runtime.clone());
    let mut request = test_request("test-echo", AdapterCapability::ExecuteTest);
    request.context.operation_generation = Some(2);
    request.context.role_lease_id = Some("role-lease:g2".to_owned());
    request.context.role_lease_epoch = Some(7);
    request.context.runtime_contract_sha256 = Some("a".repeat(64));
    let operation_id = format!("adapter:test-echo:{}", request.request_id);

    let result = supervisor.execute("test-echo", request, None).await?;
    assert_eq!(result.status, AdapterResultStatus::Succeeded);
    let checkpoint = runtime
        .get_checkpoint(operation_id)
        .await?
        .ok_or_else(|| std::io::Error::other("authority-bound checkpoint missing"))?;
    assert_eq!(checkpoint.generation, 2);
    assert_eq!(checkpoint.role_lease_id.as_deref(), Some("role-lease:g2"));
    assert_eq!(checkpoint.role_lease_epoch, Some(7));
    assert_eq!(
        checkpoint.runtime_contract_sha256.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );

    drop(supervisor);
    drop(runtime);
    drop(writer);
    actor_task.await?;
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_never_restarts_after_dispatch_proof() -> TestResult {
    let root = test_root("adapter-post-dispatch-no-restart")?;
    let wal = ControlWal::open(&ControlWalConfig {
        path: root.join("control.redb").display().to_string(),
    })?;
    let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let runtime = writer.operation_runtime();
    let actor_task = tokio::spawn(actor.run());
    let executions = Arc::new(AtomicU32::new(0));
    let mut registry = AdapterRegistry::new();
    registry.register(PostDispatchHangAdapter::new(Arc::clone(&executions)))?;
    let supervisor = AdapterSupervisor::with_runtime(registry, runtime.clone());
    let request = external_test_request("post-dispatch-hang", 50);
    let operation_id = format!("adapter:post-dispatch-hang:{}", request.request_id);

    let result = supervisor
        .execute("post-dispatch-hang", request, None)
        .await?;
    assert_eq!(result.status, AdapterResultStatus::Timeout);
    assert_eq!(executions.load(Ordering::Acquire), 1);
    let checkpoint = runtime
        .get_checkpoint(operation_id)
        .await?
        .ok_or_else(|| std::io::Error::other("post-dispatch checkpoint missing"))?;
    assert_eq!(checkpoint.generation, 1);
    assert_eq!(checkpoint.restart_count, 0);
    assert_eq!(checkpoint.dispatch_state, ProviderDispatchState::Proven);
    assert_eq!(
        checkpoint.reconciliation_state,
        OperationReconciliationState::Pending
    );

    drop(supervisor);
    drop(runtime);
    drop(writer);
    actor_task.await?;
    Ok(())
}

#[tokio::test]
async fn adapter_supervisor_half_open_probe() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;

    for _ in 0..5 {
        let _ = supervisor
            .execute(
                "test-failing",
                test_request("test-failing", AdapterCapability::ExecuteTest),
                None,
            )
            .await?;
    }

    let health = supervisor.half_open_probe("test-failing").await;
    assert_eq!(health.state, AdapterState::Healthy);
    assert!(!health.circuit_open);
    Ok(())
}

#[tokio::test]
async fn adapter_result_normalized_to_observation() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;
    let observation = normalize_result_to_observation(&result);

    assert_eq!(observation.adapter_id, "test-echo");
    assert_eq!(observation.result_id, result.result_id);
    assert_eq!(
        observation.payload_ref,
        format!("adapter_result:{}", result.result_id)
    );
    Ok(())
}

#[tokio::test]
async fn adapter_observation_tainted_by_default() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;

    assert_eq!(result.observations[0].taint, TaintClass::LocalTool);
    assert_eq!(
        normalize_result_to_observation(&result).taint,
        TaintClass::LocalTool
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn adapter_observation_written_through_writer_actor() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("adapter-observation-write").await?;
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;
    let mut observation = normalize_result_to_observation(&result);
    let (handle, actor) = harness.writer_pair("adapter")?;
    let actor_task = tokio::spawn(actor.run());

    let receipt =
        AdapterMemoryWriter::write_observation(&handle, &WriteAdmissionService, &mut observation)
            .await?;
    drop(handle);
    actor_task.await?;

    assert_eq!(
        observation
            .write_receipt
            .as_ref()
            .map(|stored| stored.write_id),
        Some(receipt.write_id)
    );
    Ok(())
}

#[tokio::test]
async fn adapter_observation_to_blackboard_candidate() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;
    let mut observation = normalize_result_to_observation(&result);
    let mut state = WorkState::default();
    let item = AdapterObservationBridge::to_blackboard_candidate(
        &mut state,
        eliot_types::AgentSessionId::new_v7(),
        &mut observation,
    );

    assert_eq!(item.kind, BlackboardItemKind::FindingCandidate);
    assert_eq!(
        observation.blackboard_item_id,
        Some(item.blackboard_item_id)
    );
    assert_eq!(item.payload_ref, observation.payload_ref);
    Ok(())
}

#[tokio::test]
async fn adapter_observation_to_mailbox_notification() -> TestResult {
    let supervisor = AdapterSupervisor::builtin()?;
    let result = supervisor
        .execute(
            "test-echo",
            test_request("test-echo", AdapterCapability::ExecuteTest),
            None,
        )
        .await?;
    let mut observation = normalize_result_to_observation(&result);
    let mut state = WorkState::default();
    let message = AdapterObservationBridge::to_mailbox_notification(
        &mut state,
        eliot_types::AgentSessionId::new_v7(),
        &mut observation,
    );

    assert_eq!(message.kind, MailboxMessageKind::ReviewRequested);
    assert!(message.requires_ack);
    assert!(observation.controller_review_required);
    assert_eq!(observation.mailbox_message_id, Some(message.message_id));
    Ok(())
}

#[test]
fn module_capability_does_not_grant_authority() {
    let authority = ModuleAuthorityProfile {
        allowed_capabilities: vec![
            ModuleCapability::SubmitFindingCandidate,
            ModuleCapability::RequestActionLease,
        ],
        ..ModuleAuthorityProfile::default()
    };

    assert!(
        authority
            .allowed_capabilities
            .contains(&ModuleCapability::RequestActionLease)
    );
    assert!(!authority.can_write_truth);
    assert!(!authority.can_request_patch);
    assert!(!authority.can_finish_task);

    let adapter_authority = AdapterAuthorityProfile {
        allowed_capabilities: vec![AdapterCapability::EmitCandidateObservation],
        ..AdapterAuthorityProfile::default()
    };
    assert!(!adapter_authority.can_write_truth);
    assert!(!adapter_authority.can_request_patch);
    assert!(!adapter_authority.can_finish_task);
}

#[test]
fn accumulated_capabilities_non_regression() -> TestResult {
    let root = repo_root();
    let writer = fs::read_to_string(root.join("crates/eliot-engine/src/writer.rs"))?;
    let context = fs::read_to_string(root.join("crates/eliot-engine/src/context.rs"))?;
    let codecortex = fs::read_to_string(root.join("crates/eliot-engine/src/codecortex.rs"))?;
    let action = fs::read_to_string(root.join("crates/eliot-engine/src/action.rs"))?;
    let patch = fs::read_to_string(root.join("crates/eliot-engine/src/patch.rs"))?;
    let work = fs::read_to_string(root.join("crates/eliot-engine/src/work.rs"))?;
    let worktree = fs::read_to_string(root.join("crates/eliot-engine/src/worktree.rs"))?;
    let collective = fs::read_to_string(root.join("crates/eliot-engine/src/collective.rs"))?;
    let runtime = fs::read_to_string(root.join("crates/eliot-engine/src/runtime.rs"))?;
    let mcp_stdio = fs::read_to_string(root.join("crates/eliot-app/src/mcp_stdio.rs"))?;

    assert!(writer.contains("pub struct WriterActor"));
    assert!(context.contains("pub struct CognitiveGate"));
    assert!(codecortex.contains("pub struct CodeCortexService"));
    assert!(action.contains("pub struct ActionLeaseService"));
    assert!(patch.contains("pub struct PatchRunner"));
    assert!(work.contains("pub struct WorkLeaseService"));
    assert!(worktree.contains("pub struct WorktreeLeaseService"));
    assert!(collective.contains("pub struct BlackboardService"));
    assert!(runtime.contains("pub struct RuntimeAdapterSupervisorSkeleton"));
    for forbidden in [
        "eliot_adapter_execute_raw",
        "eliot_run_external_agent",
        "eliot_run_gemini",
        "eliot_run_antigravity",
        "eliot_spawn_process",
    ] {
        assert!(!mcp_stdio.contains(forbidden));
    }
    Ok(())
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root = test_root(name)?;
        let mut config = GovernorConfig::default();
        let repo = repo_root();
        config.db.surreal.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")
            .unwrap_or_else(|_| {
                repo.join(".eliot-governor/secrets/surreal_root_password.txt")
                    .display()
                    .to_string()
            });
        config.db.surreal.storage =
            std::env::var("ELIOT_TEST_SURREAL_STORAGE").unwrap_or_else(|_| {
                format!(
                    "rocksdb:{}",
                    repo.join(".eliot-governor/surrealdb-rocks").display()
                )
            });
        if let Ok(bind) = std::env::var("ELIOT_TEST_SURREAL_BIND") {
            config.db.surreal.bind = bind;
        }
        if let Ok(endpoint) = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT") {
            config.db.surreal.endpoint = endpoint;
        }
        let store = CanonicalStore::new(config.db.surreal);
        migrate_schema_locked(&store).await?;
        Ok(Self { root, store })
    }

    fn writer_pair(&self, name: &str) -> TestResult<(eliot_engine::WriterHandle, WriterActor)> {
        let path = self.root.join(name).join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        Ok(WriterActor::channel(
            wal,
            self.store.clone(),
            &WriterConfig::default(),
        ))
    }
}

async fn lock_tests() -> TestLock {
    let lock_path = repo_root().join("target/eliot-governor-shared-db-test.lock");
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_file) => return TestLock { lock_path },
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
}

struct TestLock {
    lock_path: PathBuf,
}

impl Drop for TestLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

async fn migrate_schema_locked(store: &CanonicalStore) -> TestResult {
    let lock_path = repo_root().join("target/adapter-migration-migrate.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let lock_file = loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => break file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    };

    let result = store.migrate_schema().await;
    drop(lock_file);
    let _ = fs::remove_file(lock_path);
    result?;
    Ok(())
}

fn test_root(name: &str) -> TestResult<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let path = repo_root()
        .join("target")
        .join("adapter-migration-tests")
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
