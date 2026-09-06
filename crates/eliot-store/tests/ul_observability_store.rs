use eliot_store::{CanonicalStore, StoreError};
use eliot_types::{
    ACTION_MEMORY_GRANT_REDEMPTION_SCHEMA_VERSION, ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION,
    ActionMemoryGrantEvidenceClass, ActionMemoryGrantRedemption, ActionMemoryGrantRef,
    ActionProvenanceSet, ActionSourceScope, AgentId, CredentialProviderKind, GovernorConfig,
    IdempotencyOptions, LifecycleStatus, LifecycleWriteOptions,
    MEMORY_DELIVERY_GRANT_SCHEMA_VERSION, MemoryGrantOfferRecord, MemoryRevision,
    MemoryWriteEnvelope, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteStatus, OperationId, ProjectId, ProjectSequence,
    SemanticCommandKind, SessionId, TaintClass, TaskContractInput, TaskContractStatus, TaskId,
    Visibility, WriteId, WriteStatus,
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
async fn t02_memory_grant_offer_is_scoped_and_immutable() -> TestResult {
    if rerun_with_isolated_credential_backend("t02_memory_grant_offer_is_scoped_and_immutable")? {
        return Ok(());
    }
    let harness = Harness::start("memory-grant").await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let grant_uuid = uuid::Uuid::now_v7();
    let grant_id = grant_uuid.to_string();
    let write_id = WriteId::from_uuid(grant_uuid);
    let offered_at = time::OffsetDateTime::now_utc();
    let offer = MemoryGrantOfferRecord {
        schema_version: MEMORY_DELIVERY_GRANT_SCHEMA_VERSION.to_owned(),
        grant_id: grant_id.clone(),
        project_id,
        task_id,
        session_id,
        packet_id: "packet-memory-grant".to_owned(),
        packet_revision_fence: MemoryRevision::new(7),
        task_memory_revision: MemoryRevision::new(11),
        task_contract_ref: "eliot/task/memory-grant@7".to_owned(),
        auth_generation: uuid::Uuid::now_v7().to_string(),
        prior_fingerprint: "private-prior-fingerprint".to_owned(),
        guidance_hash: "private-guidance-hash".to_owned(),
        offer_write_id: write_id,
        token_hash: "opaque-token-hash".to_owned(),
        expires_at: offered_at + time::Duration::minutes(15),
        offered_at,
    };
    let payload = serde_json::to_value(&offer)?;
    let envelope = ObservabilityWriteEnvelope {
        schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
        write_id,
        project_id,
        task_id: Some(task_id),
        session_id: Some(session_id),
        kind: ObservabilityKind::MemoryGrantOffer,
        record_id: grant_id.clone(),
        input_hash: payload_hash(&payload),
        payload,
        created_at: offered_at,
    };

    let receipt = harness.store.apply_observability(&envelope).await?;
    assert_eq!(receipt.status, ObservabilityWriteStatus::Committed);
    assert_eq!(
        harness
            .store
            .memory_grant_offer_by_id(project_id, task_id, session_id, &grant_id)
            .await?,
        Some(offer.clone())
    );
    assert_eq!(
        harness
            .store
            .memory_grant_offer_by_id(project_id, task_id, SessionId::new_v7(), &grant_id)
            .await?,
        None
    );

    let replacement_write_id = WriteId::new_v7();
    let mut replacement_offer = offer.clone();
    replacement_offer.offer_write_id = replacement_write_id;
    replacement_offer.guidance_hash = "substituted-guidance-hash".to_owned();
    let replacement_payload = serde_json::to_value(&replacement_offer)?;
    let replacement = ObservabilityWriteEnvelope {
        write_id: replacement_write_id,
        input_hash: payload_hash(&replacement_payload),
        payload: replacement_payload,
        ..envelope
    };
    assert!(matches!(
        harness.store.apply_observability(&replacement).await,
        Err(StoreError::ObservabilityConflict)
    ));
    assert_eq!(
        harness
            .store
            .memory_grant_offer_by_id(project_id, task_id, session_id, &grant_id)
            .await?,
        Some(offer)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// One durable scenario: redeem, observe atomicity, then prove single use.
// Splitting it would need a shared store fixture and would stop proving that
// the three phases hold against the same live grant.
#[allow(clippy::too_many_lines)]
async fn t02_memory_grant_redemption_is_atomic_durable_and_single_use() -> TestResult {
    if rerun_with_isolated_credential_backend(
        "t02_memory_grant_redemption_is_atomic_durable_and_single_use",
    )? {
        return Ok(());
    }
    let harness = Harness::start("grant-redemption").await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let grant_uuid = uuid::Uuid::now_v7();
    let grant_id = grant_uuid.to_string();
    let offer_write_id = WriteId::from_uuid(grant_uuid);
    let action_write_id = WriteId::new_v7();
    let offered_at = time::OffsetDateTime::now_utc();
    let redeemed_at = offered_at + time::Duration::seconds(1);
    let offer = MemoryGrantOfferRecord {
        schema_version: MEMORY_DELIVERY_GRANT_SCHEMA_VERSION.to_owned(),
        grant_id: grant_id.clone(),
        project_id,
        task_id,
        session_id,
        packet_id: "eliot/packet/grant-redemption".to_owned(),
        packet_revision_fence: MemoryRevision::new(1),
        task_memory_revision: MemoryRevision::new(1),
        task_contract_ref: format!("eliot/task/{task_id}@1"),
        auth_generation: uuid::Uuid::now_v7().to_string(),
        prior_fingerprint: "private-prior-fingerprint".to_owned(),
        guidance_hash: "private-guidance-hash".to_owned(),
        offer_write_id,
        token_hash: "opaque-token-hash".to_owned(),
        expires_at: offered_at + time::Duration::minutes(15),
        offered_at,
    };
    let offer_payload = serde_json::to_value(&offer)?;
    harness
        .store
        .apply_observability(&ObservabilityWriteEnvelope {
            schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
            write_id: offer_write_id,
            project_id,
            task_id: Some(task_id),
            session_id: Some(session_id),
            kind: ObservabilityKind::MemoryGrantOffer,
            record_id: grant_id.clone(),
            input_hash: payload_hash(&offer_payload),
            payload: offer_payload,
            created_at: offered_at,
        })
        .await?;
    assert_eq!(
        harness
            .store
            .memory_grant_offer_by_id(project_id, task_id, session_id, &grant_id)
            .await?,
        Some(offer.clone())
    );

    let grant_ref = ActionMemoryGrantRef {
        schema_version: ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION.to_owned(),
        project_id,
        task_id,
        session_id,
        grant_id: grant_id.clone(),
        offer_write_id,
        packet_id: offer.packet_id.clone(),
        packet_revision_fence: offer.packet_revision_fence,
        task_memory_revision: offer.task_memory_revision,
        task_contract_ref: offer.task_contract_ref.clone(),
        prior_fingerprint: offer.prior_fingerprint.clone(),
        guidance_hash: offer.guidance_hash.clone(),
        expires_at: offer.expires_at,
        redeemed_at,
        evidence_class: ActionMemoryGrantEvidenceClass::AgentReturnedOpaqueGrantAfterServerOffer,
    };
    let provenance = ActionProvenanceSet {
        provenance_set_id: format!("eliot/provenance-set/{action_write_id}"),
        task_id,
        packet_id: offer.packet_id.clone(),
        packet_revision_fence: offer.packet_revision_fence,
        task_contract_ref: offer.task_contract_ref.clone(),
        current_truth_refs: vec![offer.task_contract_ref.clone()],
        exact_evidence_refs: vec!["receipt:task".to_owned()],
        memory_delivery_refs: Vec::new(),
        memory_grant_refs: vec![grant_ref],
        negative_memory_check_ref: "negative-memory:grant-redemption".to_owned(),
        planned_verifier_ref: "verifier:test".to_owned(),
        source_scope: ActionSourceScope {
            kind: "read_only".to_owned(),
            worktree_ref: None,
            branch: None,
            baseline_commit: None,
            baseline_dirty_state_hash: None,
            artifact_paths: Vec::new(),
        },
        resolved_at: redeemed_at,
        resolver_version: "eliot.action-provenance-resolver.v3".to_owned(),
        hash: "b".repeat(64),
    };
    let redemption = ActionMemoryGrantRedemption {
        schema_version: ACTION_MEMORY_GRANT_REDEMPTION_SCHEMA_VERSION.to_owned(),
        project_id,
        task_id,
        session_id,
        grant_id,
        offer_write_id,
        action_write_id,
        action_request_hash: "a".repeat(64),
        provenance_set_id: provenance.provenance_set_id.clone(),
        provenance_set_hash: provenance.hash.clone(),
        packet_id: offer.packet_id,
        packet_revision_fence: offer.packet_revision_fence,
        task_memory_revision: offer.task_memory_revision,
        task_contract_ref: offer.task_contract_ref,
        prior_fingerprint: offer.prior_fingerprint,
        guidance_hash: offer.guidance_hash,
        redeemed_at,
    };
    let task = TaskContractInput {
        task_id,
        title: "atomic memory grant redemption".to_owned(),
        status: TaskContractStatus::Active,
        acceptance_items: Vec::new(),
        expected_revision: None,
        action_lease_id: None,
        understanding_proof_hash: Some("understanding".to_owned()),
        action_provenance: Some(provenance),
        memory_grant_redemptions: vec![redemption.clone()],
        observation_ids: Vec::new(),
        verification_ids: Vec::new(),
        verification_scopes: Vec::new(),
        completion_proof: None,
        completion_write_id: None,
    };
    let action = MemoryWriteEnvelope {
        write_id: action_write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: Some(session_id),
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::TaskContractWrite,
        input_hash: "action-input-hash".to_owned(),
        policy_snapshot_id: None,
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: redeemed_at,
        scope: format!("task:{task_id}"),
        authority: "test-memory-grant-redemption".to_owned(),
        task_contracts: vec![task],
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: Vec::new(),
        failures: Vec::new(),
        claims: Vec::new(),
        verification_runs: Vec::new(),
        relations: Vec::new(),
        lifecycle: LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Project,
            taint: TaintClass::LocalTool,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    };

    assert_eq!(
        harness.store.apply_write_envelope(&action).await?.status,
        WriteStatus::Committed
    );
    assert_eq!(
        harness.store.apply_write_envelope(&action).await?.status,
        WriteStatus::IdempotentReplay
    );
    let stored = harness
        .store
        .task_contract_by_id(task_id)
        .await?
        .ok_or("task contract missing after grant redemption")?;
    assert_eq!(stored.memory_grant_redemptions, vec![redemption.clone()]);

    let mut substituted = action;
    substituted.write_id = WriteId::new_v7();
    substituted.operation_id = OperationId::new_v7();
    substituted.input_hash = "substituted-action-input-hash".to_owned();
    substituted.project_sequence_hint = Some(ProjectSequence::new(2));
    substituted.task_contracts[0].expected_revision = Some(MemoryRevision::new(1));
    substituted.task_contracts[0].memory_grant_redemptions[0].action_write_id =
        substituted.write_id;
    assert!(
        harness
            .store
            .apply_write_envelope(&substituted)
            .await
            .is_err(),
        "a different action write must not rewrite a committed grant redemption"
    );
    let unchanged = harness
        .store
        .task_contract_by_id(task_id)
        .await?
        .ok_or("task contract missing after rejected grant reuse")?;
    assert_eq!(unchanged.memory_revision, MemoryRevision::new(1));
    assert_eq!(unchanged.memory_grant_redemptions, vec![redemption]);
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
        "memory-grant" => 8603,
        "grant-redemption" => 8604,
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
