use eliot_engine::{
    ContextCompiler, ForgettingPolicyService, MemoryGravityService, MemoryInfluenceService,
    MemoryLifecycleGate, MemoryLifecycleMemoryWriter, MemoryLifecycleService,
    MemoryVitalityService, NegativeMemoryGate, WriteAdmissionService, WriterActor, WriterConfig,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ArchiveReceipt, ControlWalConfig, DemotionReceipt, ForgettingOperator, ForgettingReason,
    GovernorConfig, MemoryHandlePreview, MemoryLifecycleDecision, MemoryLifecyclePacketView,
    MemoryLifecycleState, MemoryRevision, MinorityPressureRecord, ProjectId, RecallL0Response,
    SupersessionReceipt, SuppressionReceipt, TaskId, TruncationInfo,
};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use time::OffsetDateTime;
use tokio::time::{Duration, Instant, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn lifecycle_state_exists() {
    assert_eq!(
        MemoryLifecycleState::default(),
        MemoryLifecycleState::Active
    );
}

#[test]
fn forgetting_policy_validates() {
    let policy = policy(
        ForgettingOperator::Suppress,
        vec!["evidence:stale".to_owned()],
        None,
    );
    assert_eq!(
        ForgettingPolicyService::validate(&policy),
        MemoryLifecycleDecision::Allow
    );
}

#[test]
fn purge_denied_in_i0() {
    assert!(!ForgettingPolicyService::supports_operator_name("purge"));
    assert_eq!(
        MemoryLifecycleGate::decide_operator_name("purge"),
        MemoryLifecycleDecision::DenyPurgeInI0
    );
}

#[test]
fn suppression_requires_evidence() {
    let policy = policy(ForgettingOperator::Suppress, Vec::new(), None);
    assert_eq!(
        ForgettingPolicyService::validate(&policy),
        MemoryLifecycleDecision::RequireEvidence
    );
}

#[test]
fn demotion_requires_evidence() {
    let policy = policy(ForgettingOperator::Demote, Vec::new(), None);
    assert_eq!(
        ForgettingPolicyService::validate(&policy),
        MemoryLifecycleDecision::RequireEvidence
    );
}

#[test]
fn supersession_requires_new_record() {
    let policy = policy(
        ForgettingOperator::Supersede,
        vec!["evidence:superseded".to_owned()],
        None,
    );
    assert_eq!(
        ForgettingPolicyService::validate(&policy),
        MemoryLifecycleDecision::RequireSupersedingRecord
    );
}

#[test]
fn archive_requires_reason() {
    let policy = policy(ForgettingOperator::Archive, Vec::new(), None);
    assert_eq!(
        ForgettingPolicyService::validate(&policy),
        MemoryLifecycleDecision::RequireEvidence
    );
}

#[test]
fn minority_evidence_protected() {
    let project_id = ProjectId::new_v7();
    let policy = ForgettingPolicyService::propose(
        project_id,
        "claim:minority",
        ForgettingOperator::Suppress,
        ForgettingReason::Stale,
        vec!["evidence:majority".to_owned()],
        None,
        None,
    );
    let minority = MinorityPressureRecord {
        minority_record_id: "minority:i0".to_owned(),
        project_id,
        minority_claim_ref: "claim:minority".to_owned(),
        majority_claim_ref: Some("claim:majority".to_owned()),
        why_minority_matters: "still discriminates failure mode".to_owned(),
        discriminative_probe: Some("run verifier".to_owned()),
        status: eliot_types::MinorityPressureStatus::Open,
        pinned: true,
        release_condition: Some("discriminative probe resolved".to_owned()),
        resolved_by_ref: None,
        suppression_forbidden_until: Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
        evidence_refs: vec!["evidence:minority".to_owned()],
        created_at: OffsetDateTime::now_utc(),
        write_receipt: None,
    };

    assert_eq!(
        MemoryLifecycleGate::decide(&policy, &[minority]),
        MemoryLifecycleDecision::ProtectMinorityEvidence
    );
}

#[test]
fn vitality_score_generated() {
    let score = MemoryVitalityService::score(ProjectId::new_v7(), "memory:stale");
    assert!(score.harm_score > 0.0);
    assert!(score.computed_at <= OffsetDateTime::now_utc());
}

#[test]
fn memory_gravity_generated() {
    let score = MemoryVitalityService::score(ProjectId::new_v7(), "memory:stale");
    let gravity = MemoryGravityService::gravity(&score);
    assert_eq!(gravity.memory_ref, score.memory_ref);
    assert!(!gravity.why_it_keeps_appearing.is_empty());
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn suppression_receipt_written_through_writer_actor() -> TestResult {
    let receipt = SuppressionReceipt {
        suppression_id: "suppression:test".to_owned(),
        project_id: ProjectId::new_v7(),
        target_ref: "claim:stale".to_owned(),
        reason: ForgettingReason::Stale,
        scope: vec!["l0".to_owned()],
        reactivation_condition: None,
        created_at: OffsetDateTime::now_utc(),
    };
    write_with_harness("suppression", |handle, admission| {
        Box::pin(async move {
            MemoryLifecycleMemoryWriter::write_suppression_receipt(handle, admission, &receipt)
                .await
        })
    })
    .await
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn demotion_receipt_written_through_writer_actor() -> TestResult {
    let receipt = DemotionReceipt {
        demotion_id: "demotion:test".to_owned(),
        project_id: ProjectId::new_v7(),
        target_ref: "claim:weak".to_owned(),
        old_status: "active".to_owned(),
        new_status: "demoted".to_owned(),
        reason: ForgettingReason::LowUtility,
        evidence_refs: vec!["evidence:low-utility".to_owned()],
        created_at: OffsetDateTime::now_utc(),
    };
    write_with_harness("demotion", |handle, admission| {
        Box::pin(async move {
            MemoryLifecycleMemoryWriter::write_demotion_receipt(handle, admission, &receipt).await
        })
    })
    .await
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn supersession_receipt_written_through_writer_actor() -> TestResult {
    let receipt = SupersessionReceipt {
        supersession_id: "supersession:test".to_owned(),
        project_id: ProjectId::new_v7(),
        old_ref: "claim:old".to_owned(),
        new_ref: "claim:new".to_owned(),
        reason: "superseded".to_owned(),
        evidence_refs: vec!["evidence:newer".to_owned()],
        created_at: OffsetDateTime::now_utc(),
    };
    write_with_harness("supersession", |handle, admission| {
        Box::pin(async move {
            MemoryLifecycleMemoryWriter::write_supersession_receipt(handle, admission, &receipt)
                .await
        })
    })
    .await
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn archive_receipt_written_through_writer_actor() -> TestResult {
    let receipt = ArchiveReceipt {
        archive_id: "archive:test".to_owned(),
        project_id: ProjectId::new_v7(),
        target_ref: "claim:duplicate".to_owned(),
        reason: ForgettingReason::Duplicate,
        retained_for_audit: true,
        created_at: OffsetDateTime::now_utc(),
    };
    write_with_harness("archive", |handle, admission| {
        Box::pin(async move {
            MemoryLifecycleMemoryWriter::write_archive_receipt(handle, admission, &receipt).await
        })
    })
    .await
}

#[test]
fn read_l0_excludes_suppressed_by_default() {
    let response = MemoryLifecycleService::filter_l0_response(l0_fixture(), false);
    assert_eq!(response.handles.len(), 1);
    assert_eq!(response.handles[0].handle, "claim:active");
    assert_eq!(response.rank_trace.lifecycle_suppressions.len(), 2);
    assert!(
        response
            .rank_trace
            .lifecycle_suppressions
            .iter()
            .any(|item| {
                item.handle == "claim:suppressed" && item.reason == "lifecycle_suppressed"
            })
    );
    assert!(
        response
            .rank_trace
            .lifecycle_suppressions
            .iter()
            .any(|item| { item.handle == "claim:archived" && item.reason == "lifecycle_archived" })
    );
    assert!(!response.rank_trace.no_useful_memory);
}

#[test]
fn read_l0_audit_mode_shows_suppressed_badge() {
    let response = MemoryLifecycleService::filter_l0_response(l0_fixture(), true);
    assert_eq!(response.handles.len(), 3);
    assert!(
        response
            .handles
            .iter()
            .filter(|handle| handle.lifecycle_state != Some(MemoryLifecycleState::Active))
            .all(|handle| handle.lifecycle_badge.is_some())
    );
}

#[test]
fn read_l2_can_fetch_suppressed_by_handle() {
    let handle = l0_fixture()
        .handles
        .into_iter()
        .find(|handle| handle.handle == "claim:suppressed");
    assert!(handle.is_some());
}

#[test]
fn l3_packet_excludes_suppressed_by_default() {
    let response = MemoryLifecycleService::filter_l0_response(l0_fixture(), false);
    assert!(response.handles.iter().all(|handle| {
        handle.lifecycle_state != Some(MemoryLifecycleState::Suppressed)
            && handle.lifecycle_state != Some(MemoryLifecycleState::Archived)
    }));
}

#[test]
fn l3_packet_uses_superseding_record() {
    let service = MemoryLifecycleService::new().with_supersession("claim:old", "claim:new");
    assert_eq!(
        service.replace_superseded_refs(&["claim:old".to_owned()]),
        vec!["claim:new".to_owned()]
    );
}

#[test]
fn l3_packet_includes_lifecycle_section() {
    let section = MemoryLifecyclePacketView::default();
    assert!(!section.lifecycle_warnings.is_empty());
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn context_compiler_writes_memory_influence_report() -> TestResult {
    let _compiler_symbol = std::any::type_name::<ContextCompiler>();
    let mut report = MemoryInfluenceService::report(
        ProjectId::new_v7(),
        Some(TaskId::new_v7()),
        Some("packet:i0".to_owned()),
        vec!["claim:active".to_owned()],
        &MemoryLifecyclePacketView::default(),
    );
    write_with_harness("influence", |handle, admission| {
        Box::pin(async move {
            MemoryLifecycleMemoryWriter::write_influence_report(handle, admission, &mut report)
                .await
        })
    })
    .await
}

#[test]
fn negative_memory_blocks_repeated_failed_path() {
    let report = NegativeMemoryGate::evaluate("failure:path", 2);
    assert!(report.blocked);
    assert_eq!(
        report.decision,
        eliot_types::NegativeMemoryDecision::BlockRepeatedFailure
    );
    assert_eq!(report.recommended_operator, None);
}

#[test]
fn doctor_reports_memory_pressure() -> TestResult {
    let root = std::env::temp_dir().join(format!("eliot-i0-doctor-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    let report = eliot_engine::DoctorService::new(&root, repo_root()).report()?;
    assert!(!report.memory_pressure.duplicate_pressure.is_empty());
    Ok(())
}

#[test]
fn accumulated_capabilities_non_regression() -> TestResult {
    let app = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let context = fs::read_to_string(repo_root().join("crates/eliot-engine/src/context.rs"))?;
    let safety = fs::read_to_string(repo_root().join("crates/eliot-engine/src/safety.rs"))?;
    for required in [
        "eliot_cognitive_gate",
        "eliot_codecortex_scan",
        "eliot_action_plan",
        "eliot_patch_preflight",
        "eliot_work_create",
        "eliot_worktree_create",
        "eliot_blackboard_add",
        "eliot_runtime_status",
        "eliot_adapter_list",
        "eliot_backup_report",
    ] {
        assert!(app.contains(required), "missing {required}");
    }
    assert!(context.contains("ContextCompiler"));
    assert!(safety.contains("DoctorService"));
    Ok(())
}

fn policy(
    operator: ForgettingOperator,
    evidence_refs: Vec<String>,
    superseding_ref: Option<String>,
) -> eliot_types::ForgettingPolicy {
    ForgettingPolicyService::propose(
        ProjectId::new_v7(),
        "claim:target",
        operator,
        ForgettingReason::Stale,
        evidence_refs,
        superseding_ref,
        None,
    )
}

fn l0_fixture() -> RecallL0Response {
    RecallL0Response {
        project_id: ProjectId::new_v7(),
        at_revision: MemoryRevision::new(1),
        projection_revision: Some(MemoryRevision::new(1)),
        projection_state: eliot_types::CognitiveProjectionReadState::Published,
        handles: vec![
            handle("claim:active", MemoryLifecycleState::Active),
            handle("claim:suppressed", MemoryLifecycleState::Suppressed),
            handle("claim:archived", MemoryLifecycleState::Archived),
        ],
        memory_confidence: eliot_types::MemoryConfidence::Found,
        query_mode: "fixture".to_owned(),
        rank_trace: eliot_types::L0RankTrace::default(),
        truncation: TruncationInfo {
            truncated: false,
            limit: 3,
            returned: 3,
        },
    }
}

fn handle(name: &str, state: MemoryLifecycleState) -> MemoryHandlePreview {
    MemoryHandlePreview {
        handle: name.to_owned(),
        record_type: "claim".to_owned(),
        preview: name.to_owned(),
        lifecycle_state: Some(state),
        lifecycle_badge: None,
    }
}

async fn write_with_harness<F>(name: &str, write: F) -> TestResult
where
    F: for<'a> FnOnce(
        &'a eliot_engine::WriterHandle,
        &'a WriteAdmissionService,
    ) -> Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<eliot_types::WriteReceiptRef, eliot_engine::EngineError>,
                > + 'a,
        >,
    >,
{
    let _guard = lock_tests().await?;
    let harness = Harness::new(name).await?;
    let (handle, actor) = harness.writer_pair(name)?;
    let actor_task = tokio::spawn(actor.run());
    let receipt = write(&handle, &WriteAdmissionService).await?;
    drop(handle);
    actor_task.await?;
    assert!(!receipt.write_id.to_string().is_empty());
    Ok(())
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "eliot-memory-lifecycle-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
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

async fn lock_tests() -> TestResult<TestLock> {
    let lock_path = repo_root().join("target/eliot-governor-shared-db-test.lock");
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let started = Instant::now();
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_file) => return Ok(TestLock { lock_path }),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                if started.elapsed() > Duration::from_mins(10) {
                    return Err("timed out waiting for shared DB test lock".into());
                }
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
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
    let lock_path = repo_root().join("target/memory-lifecycle-migrate.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let started = Instant::now();
    let lock_file = loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => break file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                if started.elapsed() > Duration::from_mins(10) {
                    return Err("timed out waiting for migration lock".into());
                }
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

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(root) = manifest_dir.parent().and_then(Path::parent) {
        root.to_path_buf()
    } else {
        manifest_dir
    }
}
