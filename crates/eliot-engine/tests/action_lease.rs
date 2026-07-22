use eliot_engine::{
    ActionLeaseEvaluation, ActionLeaseService, WriteAdmissionService, WriterActor, WriterConfig,
    codecortex_report_ref,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ActionKind, ActionRequest, AgentId, AgentRole, AgentSessionId, BlastRadiusView, ChangePlan,
    CodeCortexReport, CodeEvidenceSource, CognitiveGateDecision, CognitiveGateOutcome,
    CognitiveGateReason, DiagnosticEvidence, FileChangeIntent, FileChangeKind, FileEvidence,
    GovernorConfig, InvariantCard, LeaseDecision, LeaseDenyReason, LeaseStatus, ProjectId,
    SymbolChangeIntent, SymbolEvidence, TaskId, UnderstandingProof, UnderstandingProofReceipt,
    VerifierCommandKind, VerifierEvidence, VerifierPlan, VerifierRequirement, WorkItemId,
    WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId,
    WorkLeaseState,
};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn action_lease_denies_without_codecortex() {
    let fixture = Fixture::new();
    let mut request = fixture.request(ActionKind::ChangePlanOnly);
    request.codecortex_report_refs.clear();
    let lease = evaluate(&fixture, &request, &[], Some("e1-test-head"), None);

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::MissingCodeCortexReport)
    );
}

#[test]
fn action_lease_denies_stale_git_head() {
    let fixture = Fixture::new();
    let request = fixture.request(ActionKind::ChangePlanOnly);
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("stale-head"),
        None,
    );

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::StaleGitHead)
    );
}

#[test]
fn action_lease_denies_files_outside_codecortex_report() {
    let fixture = Fixture::new();
    let mut request = fixture.request(ActionKind::ChangePlanOnly);
    request.proposed_change_plan.files[0].path = "crates/eliot-app/src/outside.rs".to_owned();
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        None,
    );

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::FileOutsideCodeCortexReport)
    );
}

#[test]
fn action_lease_denies_missing_verifier_plan() {
    let fixture = Fixture::new();
    let mut request = fixture.request(ActionKind::ChangePlanOnly);
    request.proposed_verifier_plan.required.clear();
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        None,
    );

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::MissingVerifierPlan)
    );
}

#[test]
fn action_lease_denies_weak_claim_used_as_truth() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    receipt
        .validation_errors
        .push(CognitiveGateReason::WeakClaimUsedAsTruth);
    let request = fixture.request(ActionKind::ChangePlanOnly);
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        Some(&receipt),
    );

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::WeakClaimUsedAsTruth)
    );
}

#[test]
fn action_lease_denies_raw_shell() {
    let fixture = Fixture::new();
    let request = fixture.request(ActionKind::ShellExecution);
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        None,
    );

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::RawShellRequested)
    );
}

#[test]
fn action_lease_denies_patch_execution_in_e1() {
    let fixture = Fixture::new();
    let request = fixture.request(ActionKind::PatchExecution);
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        None,
    );

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::PatchExecutionNotAllowedInE1)
    );
}

#[test]
fn action_lease_allows_bounded_plan_only() {
    let fixture = Fixture::new();
    let request = fixture.request(ActionKind::ChangePlanOnly);
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        None,
    );

    assert_eq!(lease.decision, LeaseDecision::AllowChangePlanOnly);
    assert_eq!(lease.status, LeaseStatus::PlannedOnly);
    assert!(lease.allowed_scope.is_some());
    assert!(lease.denial_reasons.is_empty());
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn action_lease_written_through_writer_actor() -> TestResult {
    let _guard = lock_tests().await;
    let fixture = Fixture::new();
    let harness = Harness::new().await?;
    let service = ActionLeaseService;
    let request = fixture.request(ActionKind::ChangePlanOnly);
    let lease = evaluate(
        &fixture,
        &request,
        std::slice::from_ref(&fixture.report),
        Some("e1-test-head"),
        None,
    );
    let wal = ControlWal::open(&harness.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, harness.store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());

    let record = service
        .write_lease(&handle, &WriteAdmissionService, lease)
        .await?;
    drop(handle);
    actor_task.await?;

    assert_eq!(record.lease.decision, LeaseDecision::AllowChangePlanOnly);
    assert!(record.write_receipt.is_some());
    Ok(())
}

#[test]
fn accumulated_capabilities_non_regression() -> TestResult {
    let repo = repo_root();
    let mcp_stdio = fs::read_to_string(repo.join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let context = fs::read_to_string(repo.join("crates/eliot-engine/src/context.rs"))?;

    assert!(mcp_stdio.contains("eliot_current_state"));
    assert!(mcp_stdio.contains("eliot_codecortex_scan"));
    assert!(context.contains("pub struct CognitiveGate"));
    for forbidden in [
        "eliot_shell",
        "eliot_git",
        "eliot_file_write",
        "eliot_run_command",
    ] {
        assert!(!mcp_stdio.contains(forbidden));
    }
    Ok(())
}

fn evaluate(
    fixture: &Fixture,
    request: &ActionRequest,
    reports: &[CodeCortexReport],
    current_git_head: Option<&str>,
    receipt: Option<&UnderstandingProofReceipt>,
) -> eliot_types::ActionLease {
    let fallback_receipt;
    let receipt = if let Some(receipt) = receipt {
        receipt
    } else {
        fallback_receipt = fixture.receipt();
        &fallback_receipt
    };
    let gate = Fixture::gate_decision(receipt);
    ActionLeaseService.evaluate(&ActionLeaseEvaluation {
        request,
        understanding_proof: Some(&fixture.proof),
        understanding_receipt: receipt,
        cognitive_gate_decision: &gate,
        codecortex_reports: reports,
        current_git_head,
        work_lease: Some(&fixture.work_lease),
        incident_lockdown_active: false,
    })
}

struct Fixture {
    project_id: ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    proof: UnderstandingProof,
    report: CodeCortexReport,
    work_lease: WorkLease,
}

impl Fixture {
    fn new() -> Self {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let agent_id = AgentId::new_v7();
        let report = report();
        let report_ref = codecortex_report_ref(&report);
        let proof = UnderstandingProof {
            task_id: task_id.to_string(),
            project_id,
            goal: "Plan an E1 ActionLease change without executing patches".to_owned(),
            code_task: true,
            current_truth_refs: Vec::new(),
            evidence_refs: Vec::new(),
            codecortex_report_refs: vec![report_ref],
            files_to_change: vec![known_file()],
            files_to_inspect: Vec::new(),
            causal_bridge: "CodeCortex grounds the planning target".to_owned(),
            causal_bridge_from_goal_to_code: "The goal maps to the ActionLease planning surface"
                .to_owned(),
            invariants: vec!["no patch execution in E1".to_owned()],
            negative_memory_checked: true,
            unknowns: Vec::new(),
            planned_action: "plan only".to_owned(),
            expected_verifiers: vec!["cargo test".to_owned()],
            blast_radius_acknowledged: true,
            skill_refs: Vec::new(),
            skill_application_rationales: Vec::new(),
            skill_anti_scope_acknowledgements: Vec::new(),
            skill_required_inputs: Vec::new(),
            skill_verifier_plan_refs: Vec::new(),
            risk_level: "low".to_owned(),
        };
        let work_lease = active_work_lease(project_id, task_id, agent_id);
        Self {
            project_id,
            task_id,
            agent_id,
            proof,
            report,
            work_lease,
        }
    }

    fn request(&self, kind: ActionKind) -> ActionRequest {
        let report_ref = codecortex_report_ref(&self.report);
        ActionRequest {
            request_id: eliot_types::ActionRequestId::new_v7(),
            project_id: self.project_id,
            task_id: self.task_id,
            agent_id: self.agent_id,
            goal: "Plan an E1 ActionLease change without executing patches".to_owned(),
            requested_action_kind: kind,
            understanding_proof_ref: "understanding_proof:e1-test".to_owned(),
            cognitive_gate_ref: "cognitive_gate:e1-test".to_owned(),
            codecortex_report_refs: vec![report_ref.clone()],
            skill_refs: Vec::new(),
            skill_activation_decisions: Vec::new(),
            proposed_change_plan: ChangePlan {
                summary: "Plan bounded ActionLease integration".to_owned(),
                files: vec![FileChangeIntent {
                    path: known_file(),
                    reason: "ActionLease planning logic belongs in the engine action module"
                        .to_owned(),
                    expected_change_kind: FileChangeKind::Modify,
                    code_evidence_refs: vec![format!("file:{}", known_file())],
                }],
                symbols: vec![SymbolChangeIntent {
                    symbol: "ActionLeaseService".to_owned(),
                    reason: "The service owns E1 lease decisions".to_owned(),
                    expected_change_kind: FileChangeKind::Modify,
                    code_evidence_refs: vec!["symbol:ActionLeaseService".to_owned()],
                }],
                invariants_to_preserve: vec!["no patch execution in E1".to_owned()],
                risks: vec!["plan can become stale if git head changes".to_owned()],
                rollback_plan: Some("Discard the plan; no patch execution occurred".to_owned()),
            },
            proposed_verifier_plan: VerifierPlan {
                required: vec![VerifierRequirement {
                    name: "cargo check".to_owned(),
                    command_kind: VerifierCommandKind::CargoCheck,
                    command_display: "cargo check --workspace --all-targets --all-features"
                        .to_owned(),
                    scope: vec![known_file()],
                    required_for_done: true,
                    expected_signal: "exit code 0".to_owned(),
                }],
                optional: Vec::new(),
                acceptance_items: vec!["ActionLease plan is bounded".to_owned()],
            },
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn receipt(&self) -> UnderstandingProofReceipt {
        UnderstandingProofReceipt {
            task_id: self.task_id.to_string(),
            project_id: self.project_id,
            accepted: true,
            validation_errors: Vec::new(),
            checked_refs: self.proof.codecortex_report_refs.clone(),
            code_task: true,
            codecortex_report_refs: self.proof.codecortex_report_refs.clone(),
            files_to_change: self.proof.files_to_change.clone(),
            files_to_inspect: Vec::new(),
        }
    }

    fn gate_decision(receipt: &UnderstandingProofReceipt) -> CognitiveGateDecision {
        CognitiveGateDecision {
            task_id: receipt.task_id.clone(),
            project_id: receipt.project_id,
            decision: CognitiveGateOutcome::AllowReadOnly,
            reasons: vec![CognitiveGateReason::Allowed],
        }
    }
}

fn active_work_lease(project_id: ProjectId, task_id: TaskId, agent_id: AgentId) -> WorkLease {
    let now = time::OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id,
        project_id,
        task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: eliot_engine::default_work_scope(
            "C:/repo",
            vec![known_file()],
            vec![known_file()],
            vec!["cargo check".to_owned()],
        ),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "fixture work lease".to_owned(),
            work_lease_id: Some(work_lease_id),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + time::Duration::hours(1)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + time::Duration::hours(1),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    }
}

struct Harness {
    store: CanonicalStore,
    control_wal: eliot_types::ControlWalConfig,
}

impl Harness {
    async fn new() -> TestResult<Self> {
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
            store,
            control_wal: eliot_types::ControlWalConfig {
                path: repo
                    .join(".eliot-governor/control-wal/e1-test.redb")
                    .display()
                    .to_string(),
            },
        })
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
    let lock_path = repo_root().join("target/action-lease-migrate.lock");
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

fn report() -> CodeCortexReport {
    let file_evidence = vec![FileEvidence {
        path: known_file(),
        content_hash: Some("hash-action".to_owned()),
        line_start: Some(1),
        line_end: Some(120),
        excerpt: "pub struct ActionLeaseService".to_owned(),
        source: CodeEvidenceSource::Rg,
    }];
    CodeCortexReport {
        project: "eliot-governor".to_owned(),
        task: "action-lease-test-report".to_owned(),
        goal: "Plan an E1 ActionLease change without executing patches".to_owned(),
        generated_at: time::OffsetDateTime::now_utc(),
        repo_root: repo_root().display().to_string(),
        git_head: Some("e1-test-head".to_owned()),
        dirty: false,
        tracked_files: file_evidence.clone(),
        workspace_members: vec!["eliot-engine".to_owned()],
        crates: vec!["eliot-engine".to_owned(), "eliot-types".to_owned()],
        targets: vec!["eliot_engine".to_owned()],
        file_evidence,
        symbol_evidence: vec![SymbolEvidence {
            name: "ActionLeaseService".to_owned(),
            kind: "struct".to_owned(),
            path: known_file(),
            line: Some(1),
            source: CodeEvidenceSource::Rg,
        }],
        diagnostic_evidence: vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "clean".to_owned(),
            path: None,
            line: None,
            severity: "info".to_owned(),
            message: "cargo check passed".to_owned(),
        }],
        verifier_evidence: vec![VerifierEvidence {
            name: "diagnostics_adapter".to_owned(),
            command: "cargo check --workspace --all-targets --all-features".to_owned(),
            status: "pass".to_owned(),
            summary: "cargo check passed".to_owned(),
            source: CodeEvidenceSource::Diagnostics,
        }],
        blast_radius: BlastRadiusView {
            files: vec![known_file()],
            crates: vec!["eliot-engine".to_owned()],
            reasons: vec!["E1 owns action lease planning".to_owned()],
        },
        invariant_cards: vec![InvariantCard {
            name: "no_patch_execution".to_owned(),
            status: "enforced".to_owned(),
            evidence: "PatchExecution is denied in E1".to_owned(),
        }],
        evidence_sources: vec![CodeEvidenceSource::Rg, CodeEvidenceSource::Diagnostics],
        adapter_notes: Vec::new(),
        memory_receipt: None,
        final_status: "ready".to_owned(),
    }
}

fn known_file() -> String {
    "crates/eliot-engine/src/action.rs".to_owned()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
