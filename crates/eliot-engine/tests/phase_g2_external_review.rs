#![allow(clippy::expect_used)]

use eliot_engine::{
    AgentSessionService, ExternalProviderRegistryService, ExternalReviewBridgeService,
    ExternalReviewGate, ExternalReviewGateContext, ExternalReviewJobService,
    ExternalReviewNormalizer, ExternalReviewPacketBuilder, ExternalReviewTaintPolicy,
    WorkClaimRequest, WorkCreateRequest, WorkLeaseService, WorkQueueService, WorkState,
    WriteAdmissionService, WriterActor, WriterConfig, default_lease_ttl_minutes,
    default_work_scope, external_review_request,
};
use eliot_store::{BlobStore, CanonicalStore, ControlWal};
use eliot_types::{
    AgentRole, BlobStoreConfig, ControlWalConfig, ExternalOutputSchemaKind,
    ExternalProposedChangeKind, ExternalProviderKind, ExternalProviderTransport,
    ExternalReviewGateDecisionKind, ExternalReviewJobStatus, ExternalReviewResultStatus,
    ExternalReviewRole, GovernorConfig, TaintClass, WorkLease,
};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn external_provider_profiles_created() {
    let profiles = ExternalProviderRegistryService.profiles();

    assert!(profiles.len() >= 8);
    assert!(
        profiles
            .iter()
            .any(|profile| profile.provider_id == "mock-auditor")
    );
    assert!(
        profiles
            .iter()
            .any(|profile| profile.provider_id == "gemini-cli-disabled")
    );
}

#[test]
fn real_providers_disabled_by_default() {
    assert!(
        ExternalProviderRegistryService
            .profiles()
            .iter()
            .filter(|profile| profile.kind.is_real())
            .all(|profile| !profile.enabled
                && profile.transport == ExternalProviderTransport::Disabled)
    );
}

#[test]
fn mock_provider_enabled() {
    let mock = ExternalProviderRegistryService
        .inspect("mock-auditor")
        .expect("mock-auditor profile");

    assert_eq!(mock.kind, ExternalProviderKind::Mock);
    assert!(mock.enabled);
}

#[test]
fn external_review_request_created() {
    let request = external_review_request(
        "eliot-governor",
        "phase-g2-test",
        "mock-auditor",
        ExternalReviewRole::Auditor,
        "review governed protocol",
    );

    assert!(!request.request_id.is_empty());
    assert_eq!(request.provider_id, "mock-auditor");
}

#[test]
fn external_review_packet_builder_minimal_scope() -> TestResult {
    let request = request();
    let packet = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:test",
        json!({ "evidence": "bounded" }),
    )?;

    assert_eq!(packet.request_id, request.request_id);
    assert!(!packet.allowed_paths.is_empty());
    assert!(packet.byte_len <= packet.max_packet_bytes);
    Ok(())
}

#[test]
fn external_review_packet_redacts_secrets() -> TestResult {
    let mut request = request();
    request.evidence_refs.push("secret-token-ref".to_owned());
    let packet = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:test",
        json!({ "credential": "abc", "safe": "ok" }),
    )?;
    let serialized = serde_json::to_string(&packet)?;

    assert!(!packet.redacted_refs.is_empty());
    assert!(!serialized.contains("abc"));
    assert!(!serialized.contains("secret-token-ref"));
    Ok(())
}

#[test]
fn external_review_packet_enforces_size_limit() {
    let mut request = request();
    request.budget.max_packet_bytes = 64;
    let result = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:test",
        json!({ "large": "x".repeat(4096) }),
    );

    assert!(result.is_err());
}

#[test]
fn external_review_gate_requires_worklease() {
    let request = request();
    let profile = ExternalProviderRegistryService
        .inspect("mock-auditor")
        .expect("profile");
    let decision = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: None,
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: false,
        },
    );

    assert_eq!(
        decision.decision,
        ExternalReviewGateDecisionKind::RequireWorkLease
    );
}

#[test]
fn external_review_gate_requires_worktree_for_changes() {
    let mut request = external_review_request(
        "eliot-governor",
        "phase-g2-test",
        "mock-proposed-change",
        ExternalReviewRole::Worker,
        "propose change",
    );
    let (_state, lease) = active_work_lease(&mut request);
    let profile = ExternalProviderRegistryService
        .inspect("mock-proposed-change")
        .expect("profile");
    let decision = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: Some(&lease),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: false,
        },
    );

    assert_eq!(
        decision.decision,
        ExternalReviewGateDecisionKind::RequireWorktreeLease
    );
}

#[test]
fn external_review_gate_denies_real_provider_execution_in_g2() {
    let mut request = request();
    let (_state, lease) = active_work_lease(&mut request);
    request.provider_id = "gemini-cli-disabled".to_owned();
    let profile = ExternalProviderRegistryService
        .inspect("gemini-cli-disabled")
        .expect("profile");
    let decision = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: Some(&lease),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: false,
        },
    );

    assert_eq!(decision.decision, ExternalReviewGateDecisionKind::Deny);
}

#[test]
fn external_review_gate_requires_provider_integration_eval_gate() {
    let mut request = request();
    let (_state, lease) = active_work_lease(&mut request);
    let profile = ExternalProviderRegistryService
        .inspect("mock-auditor")
        .expect("profile");
    let decision = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: Some(&lease),
            worktree_lease: None,
            provider_integration_eval_gate_passed: false,
            incident_lockdown: false,
        },
    );

    assert_eq!(
        decision.decision,
        ExternalReviewGateDecisionKind::RequireProviderIntegrationEvalGate
    );
}

#[test]
fn external_review_gate_blocks_incident_lockdown() {
    let mut request = request();
    let (_state, lease) = active_work_lease(&mut request);
    let profile = ExternalProviderRegistryService
        .inspect("mock-auditor")
        .expect("profile");
    let decision = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: Some(&lease),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: true,
        },
    );

    assert_eq!(decision.decision, ExternalReviewGateDecisionKind::Deny);
}

#[tokio::test]
async fn mock_provider_job_runs() -> TestResult {
    let (_root, job, _raw) = run_mock_job().await?;

    assert_eq!(job.status, ExternalReviewJobStatus::Succeeded);
    assert!(job.adapter_request_id.is_some());
    Ok(())
}

#[tokio::test]
async fn mock_provider_run_preserves_queued_job_id() -> TestResult {
    let root = test_root("mock-job-preserves-id")?;
    let blob_store = BlobStore::open(&BlobStoreConfig {
        root: root.join("blobs").display().to_string(),
    })?;
    let request = request();
    let profile = ExternalProviderRegistryService.inspect("mock-auditor")?;
    let packet = ExternalReviewPacketBuilder.build(&request, "context", json!({}))?;
    let supervisor = eliot_engine::AdapterSupervisor::builtin()?;
    let queued_job = ExternalReviewJobService.create_job(&request);
    let queued_job_id = queued_job.job_id.clone();

    let (job, _raw) = ExternalReviewJobService
        .run_mock_job(
            &request,
            &profile,
            &packet,
            queued_job,
            &supervisor,
            &blob_store,
        )
        .await?;

    assert_eq!(job.job_id, queued_job_id);
    assert_eq!(job.status, ExternalReviewJobStatus::Succeeded);
    Ok(())
}

#[tokio::test]
async fn mock_provider_output_captured_to_blob() -> TestResult {
    let (root, job, _raw) = run_mock_job().await?;
    let blob = job.raw_output_blob_ref.as_ref().expect("blob ref");

    assert!(
        BlobStore::open(&BlobStoreConfig {
            root: root.join("blobs").display().to_string()
        })?
        .blob_path(blob)
        .is_file()
    );
    Ok(())
}

#[test]
fn malformed_result_rejected() {
    let request = request();
    let job = ExternalReviewJobService.create_job(&request);
    let outcome = ExternalReviewNormalizer.normalize(&request, &job, &json!({ "bad": true }));

    assert_eq!(
        outcome.receipt.status,
        ExternalReviewResultStatus::RejectedMalformed
    );
}

#[test]
fn authority_violating_result_rejected() {
    let request = request();
    let job = ExternalReviewJobService.create_job(&request);
    let outcome = ExternalReviewNormalizer.normalize(
        &request,
        &job,
        &json!({ "candidate_only": false, "forbidden_actions": ["write_truth"] }),
    );

    assert_eq!(
        outcome.receipt.status,
        ExternalReviewResultStatus::RejectedAuthorityViolation
    );
}

#[test]
fn missing_evidence_citation_rejected() {
    let request = request();
    let job = ExternalReviewJobService.create_job(&request);
    let outcome = ExternalReviewNormalizer.normalize(
        &request,
        &job,
        &json!({
            "candidate_only": true,
            "findings": [{
                "finding_id": "missing",
                "title": "missing",
                "detail": "missing",
                "severity": "low",
                "claim_status": "candidate",
                "citations": []
            }]
        }),
    );

    assert_eq!(
        outcome.receipt.status,
        ExternalReviewResultStatus::RejectedMissingEvidence
    );
}

#[test]
fn verified_claim_status_rejected() {
    let request = request();
    let job = ExternalReviewJobService.create_job(&request);
    let outcome = ExternalReviewNormalizer.normalize(
        &request,
        &job,
        &json!({
            "candidate_only": true,
            "findings": [{
                "finding_id": "verified",
                "title": "verified",
                "detail": "verified",
                "severity": "low",
                "claim_status": "verified",
                "citations": [{
                    "citation_id": "citation",
                    "evidence_ref": "codecortex:latest",
                    "file": "crates/eliot-app/src/mcp_stdio.rs",
                    "line": 1,
                    "status": "cited"
                }]
            }]
        }),
    );

    assert_eq!(
        outcome.receipt.status,
        ExternalReviewResultStatus::RejectedVerifiedClaim
    );
}

#[tokio::test]
async fn external_result_candidate_only_and_tainted() -> TestResult {
    let (_root, job, raw) = run_mock_job().await?;
    let request = request();
    let outcome = ExternalReviewNormalizer.normalize(&request, &job, &raw);
    let result = outcome.result.expect("result");

    assert!(result.candidate_only);
    assert_eq!(result.taint, TaintClass::ExternalAgent);
    Ok(())
}

#[tokio::test]
async fn external_result_written_through_writer_actor() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("external-review-write").await?;
    let (_root, job, raw) = run_mock_job().await?;
    let request = request();
    let mut result = ExternalReviewNormalizer
        .normalize(&request, &job, &raw)
        .result
        .expect("result");
    let (handle, actor) = harness.writer_pair("external-review")?;
    let actor_task = tokio::spawn(actor.run());
    let mut state = WorkState::default();

    ExternalReviewBridgeService
        .write_and_route(
            &handle,
            &WriteAdmissionService,
            &mut state,
            eliot_types::AgentSessionId::new_v7(),
            &mut result,
        )
        .await?;
    drop(handle);
    actor_task.await?;

    assert!(result.write_receipt.is_some());
    Ok(())
}

#[tokio::test]
async fn external_findings_to_blackboard_candidates() -> TestResult {
    let (_root, job, raw) = run_mock_job().await?;
    let request = request();
    let result = ExternalReviewNormalizer
        .normalize(&request, &job, &raw)
        .result
        .expect("result");
    let mut observation = ExternalReviewBridgeService.normalize_adapter_observation(&result);
    let mut state = WorkState::default();
    let item = eliot_engine::AdapterObservationBridge::to_blackboard_candidate(
        &mut state,
        eliot_types::AgentSessionId::new_v7(),
        &mut observation,
    );

    assert_eq!(item.payload_ref, observation.payload_ref);
    Ok(())
}

#[tokio::test]
async fn external_review_to_mailbox_review_requested() -> TestResult {
    let (_root, job, raw) = run_mock_job().await?;
    let request = request();
    let result = ExternalReviewNormalizer
        .normalize(&request, &job, &raw)
        .result
        .expect("result");
    let mut observation = ExternalReviewBridgeService.normalize_adapter_observation(&result);
    let mut state = WorkState::default();
    let message = eliot_engine::AdapterObservationBridge::to_mailbox_notification(
        &mut state,
        eliot_types::AgentSessionId::new_v7(),
        &mut observation,
    );

    assert!(message.requires_ack);
    assert!(observation.controller_review_required);
    Ok(())
}

#[test]
fn proposed_change_to_candidate_diff_only() {
    let mut request = external_review_request(
        "eliot-governor",
        "phase-g2-test",
        "mock-proposed-change",
        ExternalReviewRole::Worker,
        "propose change",
    );
    request.output_schema = ExternalOutputSchemaKind::ProposedChanges;
    let packet = ExternalReviewPacketBuilder
        .build(&request, "context", json!({}))
        .expect("packet");
    let raw = json!({
        "candidate_only": true,
        "findings": [{
            "finding_id": "finding",
            "title": "finding",
            "detail": "finding",
            "severity": "low",
            "claim_status": "candidate",
            "citations": [{
                "citation_id": "citation",
                "evidence_ref": packet.evidence_refs[0],
                "file": "crates/eliot-app/src/mcp_stdio.rs",
                "line": 1,
                "status": "cited"
            }]
        }],
        "proposed_changes": [{
            "change_id": "change",
            "kind": "verifier_only",
            "summary": "candidate diff",
            "files": ["crates/eliot-app/src/mcp_stdio.rs"],
            "candidate_diff_id": null,
            "candidate_diff_ref": null
        }]
    });
    let job = ExternalReviewJobService.create_job(&request);
    let result = ExternalReviewNormalizer
        .normalize(&request, &job, &raw)
        .result
        .expect("result");

    assert_eq!(
        result.proposed_changes[0].kind,
        ExternalProposedChangeKind::CandidateDiffOnly
    );
    assert!(result.proposed_changes[0].candidate_diff_ref.is_some());
}

#[tokio::test]
async fn verifier_suggestions_are_candidates_only() -> TestResult {
    let (_root, job, raw) = run_mock_job().await?;
    let request = request();
    let result = ExternalReviewNormalizer
        .normalize(&request, &job, &raw)
        .result
        .expect("result");

    assert!(
        result
            .verifier_suggestions
            .iter()
            .all(|suggestion| suggestion.candidate_only)
    );
    Ok(())
}

#[tokio::test]
async fn external_result_excluded_from_normal_l3() -> TestResult {
    let (_root, job, raw) = run_mock_job().await?;
    let request = request();
    let result = ExternalReviewNormalizer
        .normalize(&request, &job, &raw)
        .result
        .expect("result");

    assert!(!ExternalReviewTaintPolicy.included_in_normal_l3(&result));
    Ok(())
}

#[test]
fn doctor_reports_external_review_status() {
    let status = eliot_engine::ExternalReviewReportService.doctor_status(true);

    assert!(status.real_providers_disabled);
    assert!(status.mock_providers_enabled >= 1);
}

#[test]
fn phase_b_c_d_e_f0_f1_f2_f3_g0_g1_h0_h1_i0_i1_i2_j0_k0_k1_non_regression() -> TestResult {
    let root = repo_root();
    let mcp = fs::read_to_string(root.join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let app = fs::read_to_string(root.join("crates/eliot-app/src/commands.rs"))?;
    let engine = fs::read_to_string(root.join("crates/eliot-engine/src/external_review.rs"))?;

    assert!(mcp.contains("eliot_external_review_providers"));
    assert!(app.contains("run_phase_g2_closeout"));
    assert!(engine.contains("ExternalReviewGate"));
    for forbidden in [
        "surrealdb::",
        "rsa::",
        "eliot_run_gemini",
        "eliot_run_antigravity",
    ] {
        assert!(!engine.contains(forbidden));
    }
    Ok(())
}

async fn run_mock_job() -> TestResult<(PathBuf, eliot_types::ExternalReviewJob, serde_json::Value)>
{
    let root = test_root("mock-job")?;
    let blob_store = BlobStore::open(&BlobStoreConfig {
        root: root.join("blobs").display().to_string(),
    })?;
    let request = request();
    let profile = ExternalProviderRegistryService.inspect("mock-auditor")?;
    let packet = ExternalReviewPacketBuilder.build(&request, "context", json!({}))?;
    let supervisor = eliot_engine::AdapterSupervisor::builtin()?;
    let (job, raw) = ExternalReviewJobService
        .run_mock(&request, &profile, &packet, &supervisor, &blob_store)
        .await?;
    Ok((root, job, raw))
}

fn request() -> eliot_types::ExternalReviewRequest {
    external_review_request(
        "eliot-governor",
        "phase-g2-test",
        "mock-auditor",
        ExternalReviewRole::Auditor,
        "review governed protocol",
    )
}

fn active_work_lease(request: &mut eliot_types::ExternalReviewRequest) -> (WorkState, WorkLease) {
    let mut state = WorkState::default();
    let controller = AgentSessionService.create_controller(&mut state, request.project_id);
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project.clone(),
            task: request.task.clone(),
            goal: request.question.clone(),
            scope: default_work_scope(
                repo_root().display().to_string(),
                request.allowed_paths.clone(),
                Vec::new(),
                vec!["provider-integration".to_owned()],
            ),
            required: true,
            created_by: controller.agent_session_id,
            required_verifiers: Vec::new(),
        },
    );
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let lease_id = decision.work_lease_id.expect("lease granted");
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .expect("lease")
        .clone();
    request.work_lease_id = Some(lease.work_lease_id);
    (state, lease)
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("eliot-phase-g2-{name}-{}", std::process::id()));
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
    let lock_path = repo_root().join("target/phase-g2-migrate.lock");
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
    let root = std::env::temp_dir().join(format!("eliot-phase-g2-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
