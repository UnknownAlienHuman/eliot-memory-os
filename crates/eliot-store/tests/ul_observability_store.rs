use eliot_store::{CanonicalStore, StoreError};
use eliot_types::{
    CredentialProviderKind, CueKind, GovernorConfig, InjectionReceipt,
    OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind, ObservabilityWriteEnvelope,
    ObservabilityWriteStatus, ObservedCue, PendingInjectionBatch, PendingInjectionItem, ProjectId,
    SessionId, TaskId, WriteId,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_store_replay_is_one_row() -> TestResult {
    if rerun_with_isolated_credential_backend("t02_store_replay_is_one_row")? {
        return Ok(());
    }
    let harness = Harness::start("replay").await?;
    let envelope = envelope(json!({"memory_handle": "claim:quartz", "changed": true}));

    let first = harness.store.apply_observability(&envelope).await?;
    let replay = harness.store.apply_observability(&envelope).await?;
    let records = harness
        .store
        .observability_records_by_kind::<Value>(
            envelope.project_id,
            envelope.task_id,
            envelope.kind,
        )
        .await?;
    let stored_receipt = harness
        .store
        .observability_receipt(envelope.write_id)
        .await?
        .ok_or("observability receipt missing")?;

    assert_eq!(first.status, ObservabilityWriteStatus::Committed);
    assert_eq!(replay.status, ObservabilityWriteStatus::IdempotentReplay);
    assert_eq!(first.record_id, replay.record_id);
    assert_eq!(first.write_id, replay.write_id);
    assert_eq!(first.input_hash, replay.input_hash);
    assert_eq!(first.created_at, replay.created_at);
    assert_eq!(records, vec![envelope.payload.clone()]);
    assert_eq!(stored_receipt.status, ObservabilityWriteStatus::Committed);
    assert_eq!(stored_receipt.write_id, envelope.write_id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_store_conflict_preserves_original() -> TestResult {
    if rerun_with_isolated_credential_backend("t02_store_conflict_preserves_original")? {
        return Ok(());
    }
    let harness = Harness::start("conflict").await?;
    let original = envelope(json!({"memory_handle": "claim:quartz", "changed": true}));
    let mut conflicting = original.clone();
    conflicting.payload = json!({"memory_handle": "claim:quartz", "changed": false});
    conflicting.input_hash = payload_hash(&conflicting.payload);

    harness.store.apply_observability(&original).await?;
    let Err(error) = harness.store.apply_observability(&conflicting).await else {
        return Err("changed payload must conflict".into());
    };
    let records = harness
        .store
        .observability_records_by_kind::<Value>(
            original.project_id,
            original.task_id,
            original.kind,
        )
        .await?;
    let receipt = harness
        .store
        .observability_receipt(original.write_id)
        .await?
        .ok_or("original observability receipt missing")?;

    assert!(matches!(error, StoreError::ObservabilityConflict));
    assert_eq!(records, vec![original.payload]);
    assert_eq!(receipt.input_hash, original.input_hash);
    assert_eq!(receipt.status, ObservabilityWriteStatus::Committed);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_pending_batch_is_atomic_restart_safe_and_exactly_dequeued() -> TestResult {
    if rerun_with_isolated_credential_backend(
        "b1_pending_batch_is_atomic_restart_safe_and_exactly_dequeued",
    )? {
        return Ok(());
    }
    let harness = Harness::start("pending-batch").await?;
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let task_id = Some(TaskId::new_v7());
    let first = pending_item("failure:network:session", "fingerprint:first");
    let second = pending_item("invariant:writer:authority", "fingerprint:second");
    let batch = PendingInjectionBatch::new(
        project_id,
        task_id,
        session_id,
        vec![first.clone(), second.clone()],
        time::OffsetDateTime::now_utc(),
    )?;

    let committed = harness.store.apply_pending_injection_batch(&batch).await?;
    let replay = harness.store.apply_pending_injection_batch(&batch).await?;
    assert_eq!(committed.status, ObservabilityWriteStatus::Committed);
    assert_eq!(replay.status, ObservabilityWriteStatus::IdempotentReplay);
    assert_eq!(
        serde_json::to_value(
            harness
                .store
                .load_pending_injections(project_id, session_id)
                .await?
        )?,
        serde_json::to_value([first.clone(), second.clone()])?
    );

    let mut duplicate = second.clone();
    duplicate.source_fingerprint = "fingerprint:conflict".to_owned();
    let rejected = PendingInjectionBatch::new(
        project_id,
        task_id,
        session_id,
        vec![second.clone(), duplicate],
        time::OffsetDateTime::now_utc(),
    )?;
    assert!(
        harness
            .store
            .apply_pending_injection_batch(&rejected)
            .await
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(
            harness
                .store
                .load_pending_injections(project_id, session_id)
                .await?
        )?,
        serde_json::to_value([first.clone(), second.clone()])?
    );

    let wrong_receipt = injection_receipt_envelope(
        project_id,
        task_id,
        session_id,
        &first.item_ref,
        "fingerprint:wrong",
    )?;
    harness.store.apply_observability(&wrong_receipt).await?;
    assert_eq!(
        harness
            .store
            .load_pending_injections(project_id, session_id)
            .await?
            .len(),
        2
    );
    let exact_receipt = injection_receipt_envelope(
        project_id,
        task_id,
        session_id,
        &first.item_ref,
        &first.source_fingerprint,
    )?;
    harness.store.apply_observability(&exact_receipt).await?;
    harness.store.apply_observability(&exact_receipt).await?;
    assert_eq!(
        serde_json::to_value(
            harness
                .store
                .load_pending_injections(project_id, session_id)
                .await?
        )?,
        serde_json::to_value([second])?
    );
    Ok(())
}

fn envelope(payload: Value) -> ObservabilityWriteEnvelope {
    let write_id = WriteId::new_v7();
    ObservabilityWriteEnvelope {
        schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
        write_id,
        project_id: ProjectId::new_v7(),
        task_id: Some(TaskId::new_v7()),
        session_id: Some(SessionId::new_v7()),
        kind: ObservabilityKind::ActivationTrace,
        record_id: format!("activation:{write_id}"),
        input_hash: payload_hash(&payload),
        payload,
        created_at: time::OffsetDateTime::now_utc(),
    }
}

fn payload_hash(payload: &Value) -> String {
    blake3::hash(payload.to_string().as_bytes())
        .to_hex()
        .to_string()
}

fn pending_item(item_ref: &str, source_fingerprint: &str) -> PendingInjectionItem {
    PendingInjectionItem {
        item_ref: item_ref.to_owned(),
        record_kind: "failure_fingerprint".to_owned(),
        preview: "colon-bearing durable item".to_owned(),
        payload: Some(json!({"handle": "claim:quartz:exact"})),
        source_fingerprint: source_fingerprint.to_owned(),
        fired_cues: vec![ObservedCue {
            kind: CueKind::FilePath,
            value: "src/net:session.rs".to_owned(),
        }],
        negative_memory: true,
        invariant: false,
        token_estimate: 7,
        activation_trace_ref: Some("activation:trace:1".to_owned()),
        activation_score_milli: Some(900),
    }
}

fn injection_receipt_envelope(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    session_id: SessionId,
    item_ref: &str,
    source_fingerprint: &str,
) -> TestResult<ObservabilityWriteEnvelope> {
    let write_id = WriteId::new_v7();
    let receipt = InjectionReceipt {
        injection_id: write_id.to_string(),
        session_id,
        task_id,
        surface: "mcp:response:piggyback".to_owned(),
        item_ref: item_ref.to_owned(),
        render_form: "payload".to_owned(),
        fired_cues: Vec::new(),
        token_cost: 7,
        source_fingerprint: source_fingerprint.to_owned(),
        outcome: "delivered".to_owned(),
        policy_reason: None,
    };
    let payload = serde_json::to_value(receipt)?;
    Ok(ObservabilityWriteEnvelope {
        schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
        write_id,
        project_id,
        task_id,
        session_id: Some(session_id),
        kind: ObservabilityKind::InjectionReceipt,
        record_id: write_id.to_string(),
        input_hash: payload_hash(&payload),
        payload,
        created_at: time::OffsetDateTime::now_utc(),
    })
}

fn rerun_with_isolated_credential_backend(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T02_STORE_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let credentials =
        eliot_windows_ipc::test_support::IsolatedTestCredentialFixture::new(test_name)?;
    let mut command = Command::new(std::env::current_exe()?);
    credentials.configure_command(&mut command);
    let status = command
        .env("ELIOT_UL_T02_STORE_CHILD", test_name)
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .args(["--exact", test_name, "--nocapture"])
        .status()?;
    if !status.success() {
        return Err(format!("credential-gated child test failed with {status}").into());
    }
    Ok(true)
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
    surreal: OwnedChild,
}

impl Harness {
    async fn start(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = test_runtime_root()?.join(format!(
            "eliot-ul-t02-store-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        fs::write(root.join("surreal-root.txt"), "ul-t02-test-secret")?;
        let surreal_exe = pinned_surreal_exe()?;
        let port = test_port(name)?;
        let surreal = start_surreal(&surreal_exe, port)?;
        wait_for_tcp(port, Duration::from_secs(20))?;

        let mut config = GovernorConfig::default();
        config.db.surreal.exe = slash(&surreal_exe);
        config.db.surreal.bind = format!("127.0.0.1:{port}");
        config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
        "memory".clone_into(&mut config.db.surreal.storage);
        "ultest".clone_into(&mut config.db.surreal.ns);
        "ultest".clone_into(&mut config.db.surreal.db);
        "root".clone_into(&mut config.db.surreal.user);
        config.db.surreal.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        "test-only/ul-t02-store".clone_into(&mut config.db.surreal.credential_id);
        let run_id = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("test runtime name missing")?;
        config.db.surreal.password_file =
            format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/surreal-root.txt");
        let store = CanonicalStore::new(config.db.surreal);
        store.migrate_schema().await?;
        Ok(Self {
            root,
            store,
            surreal,
        })
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.surreal.stop();
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t02-store-"))
            && self
                .root
                .starts_with(test_runtime_root().unwrap_or_else(|_| PathBuf::new()))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn stop(&mut self) -> TestResult {
        if let Some(mut child) = self.0.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn start_surreal(exe: &Path, port: u16) -> TestResult<OwnedChild> {
    let child = Command::new(exe)
        .env("SURREAL_USER", "root")
        .env("SURREAL_PASS", "ul-t02-test-secret")
        .arg("start")
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--log")
        .arg("warn")
        .arg("--deny-all")
        .arg("--allow-funcs")
        .arg("array,string,time,type,math,vector,search")
        .arg("--deny-net")
        .arg("--")
        .arg("memory")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(OwnedChild(Some(child)))
}

fn pinned_surreal_exe() -> TestResult<PathBuf> {
    let path = std::env::var_os("ELIOT_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    let output = Command::new(&path).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    if !output.status.success() || !version.trim().starts_with("3.1.4") {
        return Err(format!("UL-02 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_port(name: &str) -> TestResult<u16> {
    let port = match name {
        "replay" => 8601,
        "conflict" => 8602,
        "pending-batch" => 8603,
        other => return Err(format!("unknown UL-02 store test {other}").into()),
    };
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("UL-02 store test port {port} is unavailable: {error}"))?;
    drop(listener);
    Ok(port)
}

fn wait_for_tcp(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB did not listen on port {port}").into())
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn test_runtime_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?)
            .join("Eliot")
            .join("tests"),
    )
}
