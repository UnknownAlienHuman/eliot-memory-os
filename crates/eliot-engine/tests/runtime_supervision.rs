use eliot_engine::{OperationSupervisor, WriterActor, WriterConfig};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ControlWalConfig, GovernorConfig, OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION,
    OperationCancellationState, OperationPhase, OperationReconciliationState,
    OperationRuntimeCheckpoint, ProviderDispatchState,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn runtime_supervision_watchdog_persists_no_progress_cancellation() -> TestResult {
    let root = test_root("watchdog-no-progress")?;
    let wal = ControlWal::open(&ControlWalConfig {
        path: root.join("control.redb").display().to_string(),
    })?;
    let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let runtime = writer.operation_runtime();
    let actor_task = tokio::spawn(actor.run());
    let supervisor = OperationSupervisor::new(runtime.clone());
    let now = OffsetDateTime::now_utc();
    let checkpoint = OperationRuntimeCheckpoint {
        schema_version: OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION.to_owned(),
        operation_id: "watchdog-no-progress".to_owned(),
        invocation_id: None,
        adapter_id: Some("antigravity-fixture".to_owned()),
        generation: 1,
        phase: OperationPhase::Running,
        dispatch_state: ProviderDispatchState::Proven,
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
        phase_started_at: now - time::Duration::seconds(5),
        last_progress_at: now - time::Duration::seconds(5),
        phase_deadline_at: now - time::Duration::seconds(1),
        absolute_deadline_at: now + time::Duration::seconds(30),
        restart_count: 0,
        restart_window_started_at: None,
        role_lease_id: None,
        role_lease_epoch: None,
        runtime_contract_sha256: None,
        last_error_class: None,
        last_evidence_refs: Vec::new(),
    };
    let cancellation = supervisor.register(checkpoint).await?;

    let cancelled = supervisor.watchdog_once(now).await?;
    assert_eq!(cancelled, vec!["watchdog-no-progress"]);
    assert!(cancellation.is_cancelled());
    let persisted = runtime
        .get_checkpoint("watchdog-no-progress")
        .await?
        .ok_or_else(|| std::io::Error::other("watchdog checkpoint missing"))?;
    assert_eq!(persisted.phase, OperationPhase::Cancelling);
    assert_eq!(
        persisted.cancellation_state,
        OperationCancellationState::Requested
    );
    assert_eq!(
        persisted.last_error_class.as_deref(),
        Some("watchdog_deadline_exceeded")
    );

    drop(supervisor);
    drop(runtime);
    drop(writer);
    actor_task.await?;
    Ok(())
}

fn test_root(name: &str) -> TestResult<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let root = repo_root()
        .join("target")
        .join("runtime-supervision-tests")
        .join(format!("{name}-{unique}"));
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
