use eliot_engine::{ReadService, WriteAdmissionService, WriterActor, WriterConfig, WriterHandle};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, CommandContext, ControlWalConfig, CurrentStateRequest,
    EpistemicStatus, EvidenceAtomInput, EvidenceId, EvidenceIngestCommand, FetchAtomsL2Request,
    GovernorConfig, LifecycleStatus, MemoryRevision, MemoryWriteEnvelope, ProjectId,
    ReadConsistencyMode, RelationType, SemanticCommand, SessionId, SourceSnapshotInput, TaintClass,
    TaskId, VerificationResult, VerificationRunInput, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep, timeout};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn idempotency_same_hash_replay() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("idempotency_same_hash_replay").await?;
    let project_id = ProjectId::new_v7();
    let command = evidence_command(project_id, None, "same-hash", json!({ "n": 1 }));
    let envelope = harness.admission.admit(&command)?;

    let first = harness.submit_with_fresh_wal(envelope.clone()).await?;
    let replay = harness.submit_with_fresh_wal(envelope).await?;
    let l2 = harness.fetch_l2(project_id, first.memory_revision).await?;
    let health = harness.store.graph_health().await?;

    assert_eq!(first.status, WriteStatus::Committed);
    assert_eq!(replay.status, WriteStatus::IdempotentReplay);
    assert_eq!(l2.evidence_atoms.len(), 1);
    assert_eq!(health.duplicate_write_ids, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn idempotency_conflict_rejects_different_hash() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("idempotency_conflict_rejects_different_hash").await?;
    let project_id = ProjectId::new_v7();
    let write_id = WriteId::new_v7();
    let first = harness.admission.admit(&evidence_command(
        project_id,
        Some(write_id),
        "conflict",
        json!({ "n": 1 }),
    ))?;
    let conflict = harness.admission.admit(&evidence_command(
        project_id,
        Some(write_id),
        "conflict",
        json!({ "n": 2 }),
    ))?;

    let first_receipt = harness.submit_with_fresh_wal(first).await?;
    let (wal_path, handle, actor_task) = harness.start_writer("conflict-replay")?;
    let result = handle.submit(conflict).await;
    drop(handle);
    actor_task.await?;
    let wal = open_wal(&wal_path)?;
    let l2 = harness
        .fetch_l2(project_id, first_receipt.memory_revision)
        .await?;

    assert!(result.is_err());
    assert_eq!(wal.rejected_count()?, 1);
    assert_eq!(wal.idempotency_conflict_count()?, 1);
    assert_eq!(l2.evidence_atoms.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn recovery_pending_replay_applies_once() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("recovery_pending_replay_applies_once").await?;
    let project_id = ProjectId::new_v7();
    let envelope = harness.admission.admit(&evidence_command(
        project_id,
        None,
        "pending-recovery",
        json!({ "n": 1 }),
    ))?;
    let wal = harness.wal("pending-recovery")?;
    wal.append_pending(&envelope)?;

    let recovered = wal.recover_pending()?;
    assert_eq!(recovered.len(), 1);

    let (handle, actor) =
        WriterActor::channel(wal, harness.store.clone(), &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let receipt = handle.submit(recovered[0].clone()).await?;
    drop(handle);
    actor_task.await?;

    let replay = harness.submit_with_fresh_wal(recovered[0].clone()).await?;
    let l2 = harness
        .fetch_l2(project_id, receipt.memory_revision)
        .await?;

    assert_eq!(replay.status, WriteStatus::IdempotentReplay);
    assert_eq!(l2.evidence_atoms.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn recovery_unknown_commit_reconciles_by_write_id() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("recovery_unknown_commit_reconciles_by_write_id").await?;
    let project_id = ProjectId::new_v7();
    let envelope = harness.admission.admit(&evidence_command(
        project_id,
        None,
        "unknown-recovery",
        json!({ "n": 1 }),
    ))?;
    let first = harness.submit_with_fresh_wal(envelope.clone()).await?;
    let wal = harness.wal("unknown-recovery")?;
    wal.append_pending(&envelope)?;
    wal.mark_unknown_commit(
        &envelope.write_id,
        &eliot_store::StoreError::ConnectionClosed,
    )?;

    let (handle, actor) =
        WriterActor::channel(wal, harness.store.clone(), &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let replay = handle.submit(envelope).await?;
    drop(handle);
    actor_task.await?;

    assert_eq!(first.memory_revision, replay.memory_revision);
    assert_eq!(replay.status, WriteStatus::IdempotentReplay);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn claim_matrix_candidate_supported_verified() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("claim_matrix_candidate_supported_verified").await?;
    let project_id = ProjectId::new_v7();
    let claim_id = ClaimId::new_v7();
    let evidence_id = EvidenceId::new_v7();
    let statement = "claim matrix verified";
    let (wal_path, handle, actor_task) = harness.start_writer("claim-matrix")?;

    let proposed = submit(
        &harness.admission,
        &handle,
        claim_propose(project_id, claim_id, statement),
    )
    .await?;
    let state = harness
        .current_state(project_id, proposed.memory_revision)
        .await?;
    assert_eq!(state.weak_or_candidate.len(), 1);
    assert!(state.supported_now.is_empty());
    assert!(state.verified_now.is_empty());

    submit(
        &harness.admission,
        &handle,
        evidence_command_with_id(project_id, evidence_id, "matrix", json!({ "n": 1 })),
    )
    .await?;
    let supported = submit(
        &harness.admission,
        &handle,
        claim_support(project_id, claim_id, evidence_id, statement),
    )
    .await?;
    let state = harness
        .current_state(project_id, supported.memory_revision)
        .await?;
    assert!(state.weak_or_candidate.is_empty());
    assert_eq!(state.supported_now.len(), 1);
    assert!(state.verified_now.is_empty());

    submit(
        &harness.admission,
        &handle,
        verification_record(project_id, claim_id, VerificationResult::Passed),
    )
    .await?;
    let verified = submit(
        &harness.admission,
        &handle,
        claim_verify(project_id, claim_id, statement, VerificationResult::Passed),
    )
    .await?;
    drop(handle);
    actor_task.await?;
    let wal = open_wal(&wal_path)?;

    let state = harness
        .current_state(project_id, verified.memory_revision)
        .await?;
    assert!(state.weak_or_candidate.is_empty());
    assert!(state.supported_now.is_empty());
    assert_eq!(state.verified_now.len(), 1);
    assert_eq!(wal.committed_count()?, 5);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn claim_matrix_failed_verification_not_verified() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("claim_matrix_failed_verification_not_verified").await?;
    let project_id = ProjectId::new_v7();
    let claim_id = ClaimId::new_v7();
    let evidence_id = EvidenceId::new_v7();
    let (wal_path, handle, actor_task) = harness.start_writer("failed-verification")?;

    submit(
        &harness.admission,
        &handle,
        claim_propose(project_id, claim_id, "failed matrix"),
    )
    .await?;
    submit(
        &harness.admission,
        &handle,
        evidence_command_with_id(project_id, evidence_id, "failed", json!({ "n": 1 })),
    )
    .await?;
    submit(
        &harness.admission,
        &handle,
        claim_support(project_id, claim_id, evidence_id, "failed matrix"),
    )
    .await?;
    let failed = submit(
        &harness.admission,
        &handle,
        verification_record(project_id, claim_id, VerificationResult::Failed),
    )
    .await?;
    let rejected = harness.admission.admit(&claim_verify(
        project_id,
        claim_id,
        "failed matrix",
        VerificationResult::Failed,
    ));
    drop(handle);
    actor_task.await?;
    let wal = open_wal(&wal_path)?;

    let state = harness
        .current_state(project_id, failed.memory_revision)
        .await?;
    assert!(rejected.is_err());
    assert!(state.verified_now.is_empty());
    assert_eq!(state.contested_now.len(), 1);
    assert_eq!(wal.committed_count()?, 4);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn ten_agent_concurrent_writes_are_governed() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("ten_agent_concurrent_writes_are_governed").await?;
    let project_id = ProjectId::new_v7();
    let (wal_path, handle, actor_task) = harness.start_writer("ten-agent")?;
    let mut tasks = Vec::new();

    for agent_idx in 0..10 {
        let agent_handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            let admission = WriteAdmissionService;
            let mut receipts = Vec::new();
            for write_idx in 0..10 {
                let command = evidence_command(
                    project_id,
                    None,
                    &format!("agent-{agent_idx}-{write_idx}"),
                    json!({ "agent": agent_idx, "write": write_idx }),
                );
                let envelope = admission.admit(&command)?;
                receipts.push(agent_handle.submit(envelope).await?);
            }
            TestResult::Ok(receipts)
        }));
    }

    let mut receipts = Vec::new();
    for task in tasks {
        receipts.extend(task.await??);
    }
    drop(handle);
    actor_task.await?;
    let wal = open_wal(&wal_path)?;

    let write_ids = receipts
        .iter()
        .map(|receipt| receipt.write_id)
        .collect::<HashSet<_>>();
    let mut sequences = receipts
        .iter()
        .filter_map(|receipt| receipt.project_sequence)
        .map(eliot_types::ProjectSequence::value)
        .collect::<Vec<_>>();
    sequences.sort_unstable();

    assert_eq!(receipts.len(), 100);
    assert_eq!(write_ids.len(), 100);
    assert_eq!(sequences, (1..=100).collect::<Vec<_>>());
    assert_eq!(wal.committed_count()?, 100);
    assert_eq!(harness.store.graph_health().await?.duplicate_write_ids, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn c5_thirty_two_sessions_across_eight_projects_are_bounded_and_ordered() -> TestResult {
    let _guard = lock_tests().await;
    let harness =
        Harness::new("c5_thirty_two_sessions_across_eight_projects_are_bounded_and_ordered")
            .await?;
    let projects = (0..8).map(|_| ProjectId::new_v7()).collect::<Vec<_>>();
    let (wal_path, handle, actor_task) = harness.start_writer("c5-32x8")?;
    let barrier = Arc::new(Barrier::new(33));
    let mut tasks = Vec::new();

    for session_index in 0..32 {
        let agent_handle = handle.clone();
        let barrier = Arc::clone(&barrier);
        let project_id = projects[session_index % projects.len()];
        tasks.push(tokio::spawn(async move {
            let admission = WriteAdmissionService;
            let session_id = SessionId::new_v7();
            let mut receipts = Vec::new();
            barrier.wait().await;
            for write_index in 0..2 {
                let mut command = evidence_command(
                    project_id,
                    None,
                    &format!("session-{session_index}-write-{write_index}"),
                    json!({
                        "session_index": session_index,
                        "write_index": write_index,
                    }),
                );
                bind_session(&mut command, session_id);
                receipts.push((
                    project_id,
                    agent_handle.submit(admission.admit(&command)?).await?,
                ));
            }
            TestResult::Ok(receipts)
        }));
    }
    barrier.wait().await;

    let mut receipts = Vec::new();
    for task in tasks {
        receipts.extend(task.await??);
    }
    let metrics = handle.metrics();
    drop(handle);
    actor_task.await?;
    let wal = open_wal(&wal_path)?;

    assert_eq!(receipts.len(), 64);
    assert_eq!(metrics.configured_lanes, 4);
    assert!(
        metrics.max_in_flight_projects >= 2,
        "independent projects never overlapped: {metrics:?}"
    );
    assert_eq!(metrics.rejected_backpressure, 0);
    assert_eq!(metrics.paused_projects, 0);
    for project_id in projects {
        let mut sequences = receipts
            .iter()
            .filter(|(receipt_project, _)| *receipt_project == project_id)
            .filter_map(|(_, receipt)| receipt.project_sequence)
            .map(eliot_types::ProjectSequence::value)
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
    }
    assert_eq!(wal.committed_count()?, 64);
    assert_eq!(harness.store.graph_health().await?.duplicate_write_ids, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn c5_retry_timer_releases_its_only_lane_for_an_unrelated_project() -> TestResult {
    let _guard = lock_tests().await;
    let harness =
        Harness::new("c5_retry_timer_releases_its_only_lane_for_an_unrelated_project").await?;
    let delayed_project = ProjectId::new_v7();
    let unrelated_project = ProjectId::new_v7();
    let mut delayed = harness.admission.admit(&evidence_command(
        delayed_project,
        None,
        "delayed-unknown",
        json!({ "project": "delayed" }),
    ))?;
    delayed.project_sequence_hint = Some(eliot_types::ProjectSequence::new(1));
    let unrelated = harness.admission.admit(&evidence_command(
        unrelated_project,
        None,
        "unrelated",
        json!({ "project": "unrelated" }),
    ))?;
    let wal_path = harness.wal_path("c5-retry-isolation");
    let wal = open_wal(&wal_path)?;
    wal.append_pending(&delayed)?;
    wal.mark_unknown_commit(
        &delayed.write_id,
        &eliot_store::StoreError::ConnectionClosed,
    )?;
    let config = WriterConfig {
        lane_count: 1,
        unknown_commit_retry_delay: Duration::from_millis(250),
        ..WriterConfig::default()
    };
    let (handle, actor) = WriterActor::channel(wal, harness.store.clone(), &config);
    let actor_task = tokio::spawn(actor.run());
    let (completion_tx, mut completion_rx) = tokio::sync::mpsc::unbounded_channel();

    let delayed_handle = handle.clone();
    let delayed_completion = completion_tx.clone();
    let delayed_task = tokio::spawn(async move {
        let result = delayed_handle.submit(delayed).await;
        let _ = delayed_completion.send("delayed");
        result
    });
    timeout(Duration::from_secs(2), async {
        while handle.metrics().scheduled_retries == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let unrelated_handle = handle.clone();
    let unrelated_task = tokio::spawn(async move {
        let result = unrelated_handle.submit(unrelated).await;
        let _ = completion_tx.send("unrelated");
        result
    });

    assert_eq!(
        timeout(Duration::from_secs(5), completion_rx.recv()).await?,
        Some("unrelated")
    );
    let unrelated_receipt = unrelated_task.await??;
    let delayed_receipt = delayed_task.await??;
    let metrics = handle.metrics();
    drop(handle);
    actor_task.await?;

    assert_eq!(unrelated_receipt.project_id, unrelated_project);
    assert_eq!(delayed_receipt.project_id, delayed_project);
    assert_eq!(metrics.configured_lanes, 1);
    assert_eq!(metrics.scheduled_retries, 1);
    assert_eq!(metrics.max_in_flight_projects, 1);
    assert_eq!(metrics.paused_projects, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn fetch_l2_returns_relation_neighborhood() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("fetch_l2_returns_relation_neighborhood").await?;
    let project_id = ProjectId::new_v7();
    let claim_id = ClaimId::new_v7();
    let evidence_id = EvidenceId::new_v7();
    let (handle, actor_task) = harness.writer_pair("fetch-l2")?;

    submit(
        &harness.admission,
        &handle,
        evidence_command_with_id(project_id, evidence_id, "l2", json!({ "n": 1 })),
    )
    .await?;
    submit(
        &harness.admission,
        &handle,
        claim_propose(project_id, claim_id, "l2 claim"),
    )
    .await?;
    submit(
        &harness.admission,
        &handle,
        claim_support(project_id, claim_id, evidence_id, "l2 claim"),
    )
    .await?;
    let verified = submit(
        &harness.admission,
        &handle,
        claim_verify(project_id, claim_id, "l2 claim", VerificationResult::Passed),
    )
    .await?;
    drop(handle);
    actor_task.await?;

    let l2 = harness
        .fetch_l2(project_id, verified.memory_revision)
        .await?;
    let relation_types = l2
        .relations
        .iter()
        .map(|relation| relation.relation_type)
        .collect::<HashSet<_>>();

    assert_eq!(l2.claims.len(), 1);
    assert_eq!(l2.evidence_atoms.len(), 1);
    assert_eq!(l2.verification_runs.len(), 1);
    assert!(relation_types.contains(&RelationType::Supports));
    assert!(relation_types.contains(&RelationType::VerifiedBy));
    assert!(l2.relations.iter().any(|relation| {
        relation.relation_type == RelationType::Supports
            && relation.from == claim_id.to_string()
            && relation.to == evidence_id.to_string()
    }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn read_after_write_at_least_revision() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("read_after_write_at_least_revision").await?;
    let project_id = ProjectId::new_v7();
    let receipt = harness
        .submit_with_fresh_wal(harness.admission.admit(&claim_propose(
            project_id,
            ClaimId::new_v7(),
            "raw read consistency",
        ))?)
        .await?;
    let revision = receipt.memory_revision;
    let state = harness.current_state(project_id, revision).await?;
    let l2 = harness.fetch_l2(project_id, revision).await?;

    assert!(revision.is_some());
    assert!(state.memory_revision >= revision.unwrap_or(MemoryRevision::new(0)));
    assert!(l2.at_revision >= revision.unwrap_or(MemoryRevision::new(0)));
    Ok(())
}

#[test]
fn no_public_raw_sql_or_direct_transport() -> TestResult {
    let repo_root = repo_root();
    let store_lib = std::fs::read_to_string(repo_root.join("crates/eliot-store/src/lib.rs"))?;
    let app_main = std::fs::read_to_string(repo_root.join("crates/eliot-app/src/main.rs"))?;
    let surql = std::fs::read_to_string(repo_root.join("crates/eliot-store/src/surql.rs"))?;

    assert!(!store_lib.contains("pub use surreal_rpc::SurrealRpcTransport"));
    assert!(!app_main.contains("RawQuery"));
    assert!(!app_main.contains("RunSql"));
    assert!(!surql.contains("RawQuery"));
    Ok(())
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
    admission: WriteAdmissionService,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "eliot-write-admission-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
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
        Ok(Self {
            root,
            store,
            admission: WriteAdmissionService,
        })
    }

    fn wal(&self, name: &str) -> TestResult<ControlWal> {
        open_wal(&self.wal_path(name))
    }

    fn wal_path(&self, name: &str) -> PathBuf {
        self.root.join(name).join("control.redb")
    }

    fn start_writer(&self, name: &str) -> TestResult<(PathBuf, WriterHandle, JoinHandle<()>)> {
        let path = self.wal_path(name);
        let wal = open_wal(&path)?;
        let (handle, actor) =
            WriterActor::channel(wal, self.store.clone(), &WriterConfig::default());
        Ok((path, handle, tokio::spawn(actor.run())))
    }

    fn writer_pair(&self, name: &str) -> TestResult<(WriterHandle, JoinHandle<()>)> {
        let path = self.wal_path(name);
        let wal = open_wal(&path)?;
        let (handle, actor) =
            WriterActor::channel(wal, self.store.clone(), &WriterConfig::default());
        Ok((handle, tokio::spawn(actor.run())))
    }

    async fn submit_with_fresh_wal(
        &self,
        envelope: MemoryWriteEnvelope,
    ) -> TestResult<eliot_types::WriteReceipt> {
        let wal_name = format!("wal-{}", WriteId::new_v7());
        let (handle, actor_task) = self.writer_pair(&wal_name)?;
        let receipt = handle.submit(envelope).await?;
        drop(handle);
        actor_task.await?;
        Ok(receipt)
    }

    async fn current_state(
        &self,
        project_id: ProjectId,
        revision: Option<MemoryRevision>,
    ) -> TestResult<eliot_types::CurrentStateResponse> {
        Ok(ReadService::new(self.store.clone())
            .current_state(&CurrentStateRequest {
                project_id,
                consistency: revision.map_or(ReadConsistencyMode::Latest, |_| {
                    ReadConsistencyMode::AtLeastRevision
                }),
                at_least_revision: revision,
            })
            .await?)
    }

    async fn fetch_l2(
        &self,
        project_id: ProjectId,
        revision: Option<MemoryRevision>,
    ) -> TestResult<eliot_types::FetchAtomsL2Response> {
        Ok(ReadService::new(self.store.clone())
            .fetch_atoms_l2(&FetchAtomsL2Request {
                project_id,
                handles: Vec::new(),
                continuation: None,
                consistency: revision.map_or(ReadConsistencyMode::Latest, |_| {
                    ReadConsistencyMode::AtLeastRevision
                }),
                at_least_revision: revision,
            })
            .await?)
    }
}

fn bind_session(command: &mut SemanticCommand, session_id: SessionId) {
    if let SemanticCommand::EvidenceIngest(command) = command {
        command.context.session_id = Some(session_id);
    }
}

fn open_wal(path: &Path) -> TestResult<ControlWal> {
    Ok(ControlWal::open(&ControlWalConfig {
        path: path.display().to_string(),
    })?)
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

async fn submit(
    admission: &WriteAdmissionService,
    handle: &WriterHandle,
    command: SemanticCommand,
) -> TestResult<eliot_types::WriteReceipt> {
    Ok(handle.submit(admission.admit(&command)?).await?)
}

async fn migrate_schema_locked(store: &CanonicalStore) -> TestResult {
    let lock_path = repo_root().join("target/write-admission-migrate.lock");
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

fn context(project_id: ProjectId, write_id: Option<WriteId>) -> CommandContext {
    CommandContext {
        write_id: write_id.unwrap_or_else(WriteId::new_v7),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(TaskId::new_v7()),
        scope: "write-idempotency-and-recovery-test".to_owned(),
        authority: "local-test".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn evidence_command(
    project_id: ProjectId,
    write_id: Option<WriteId>,
    label: &str,
    payload: serde_json::Value,
) -> SemanticCommand {
    evidence_command_full(project_id, write_id, EvidenceId::new_v7(), label, payload)
}

fn evidence_command_with_id(
    project_id: ProjectId,
    evidence_id: EvidenceId,
    label: &str,
    payload: serde_json::Value,
) -> SemanticCommand {
    evidence_command_full(project_id, None, evidence_id, label, payload)
}

fn evidence_command_full(
    project_id: ProjectId,
    write_id: Option<WriteId>,
    evidence_id: EvidenceId,
    label: &str,
    payload: serde_json::Value,
) -> SemanticCommand {
    let source_id = format!("source-{evidence_id}");
    SemanticCommand::EvidenceIngest(EvidenceIngestCommand {
        context: context(project_id, write_id),
        source: SourceSnapshotInput {
            source_id: source_id.clone(),
            uri: format!("local://{label}"),
            authority: "local-test".to_owned(),
            content_hash: label.to_owned(),
            excerpt: label.to_owned(),
        },
        evidence: EvidenceAtomInput {
            evidence_id,
            source_id,
            summary: label.to_owned(),
            payload,
        },
    })
}

fn claim_propose(project_id: ProjectId, claim_id: ClaimId, statement: &str) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: context(project_id, None),
        claim: ClaimCardInput {
            claim_id,
            statement: statement.to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({ "state": "candidate" }),
        },
    })
}

fn claim_support(
    project_id: ProjectId,
    claim_id: ClaimId,
    evidence_id: EvidenceId,
    statement: &str,
) -> SemanticCommand {
    SemanticCommand::ClaimSupport(eliot_types::ClaimSupportCommand {
        context: context(project_id, None),
        claim_id,
        evidence_id,
        statement: Some(statement.to_owned()),
        payload: json!({ "state": "supported" }),
    })
}

fn verification_record(
    project_id: ProjectId,
    claim_id: ClaimId,
    result: VerificationResult,
) -> SemanticCommand {
    SemanticCommand::VerificationRecord(eliot_types::VerificationRecordCommand {
        context: context(project_id, None),
        verification: VerificationRunInput {
            verification_id: eliot_types::VerificationId::new_v7(),
            claim_id: Some(claim_id),
            verifier: "write-admission-test".to_owned(),
            result,
            summary: format!("{result:?}"),
            payload: json!({ "result": format!("{result:?}") }),
        },
    })
}

fn claim_verify(
    project_id: ProjectId,
    claim_id: ClaimId,
    statement: &str,
    result: VerificationResult,
) -> SemanticCommand {
    SemanticCommand::ClaimVerify(eliot_types::ClaimVerifyCommand {
        context: context(project_id, None),
        claim_id,
        verification: VerificationRunInput {
            verification_id: eliot_types::VerificationId::new_v7(),
            claim_id: Some(claim_id),
            verifier: "write-admission-test".to_owned(),
            result,
            summary: format!("{result:?}"),
            payload: json!({ "result": format!("{result:?}") }),
        },
        statement: Some(statement.to_owned()),
        payload: json!({ "state": "verified" }),
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
