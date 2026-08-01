use eliot_engine::{
    CompletionGate, PatchMemoryWriter, PatchRunner, PatchRunnerInput, VerifierHarness,
    WriteAdmissionService, WriterActor, WriterConfig, codecortex_report_ref,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ActionLease, ActionScope, AgentId, AgentRole, AgentSessionId, BlastRadiusView,
    CodeCortexReport, CodeEvidenceSource, CompletionAcceptanceItem, CompletionProof,
    CompletionStatus, DiagnosticEvidence, FileEvidence, GovernorConfig, InvariantCard,
    LeaseDecision, LeaseStatus, PatchRequest, PatchRequestId, PatchRun, PatchRunStatus, ProjectId,
    ReceiptId, SymbolEvidence, TaskId, UnifiedDiff, VerifierCommandKind, VerifierEvidence,
    VerifierPlan, VerifierRequirement, VerifierRun, VerifierStatus, WorkItemId, WorkLease,
    WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState,
    WriteId, WriteReceiptRef,
};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn patch_denied_without_lease() -> TestResult {
    let bundle = Bundle::new("patch-denied-without-lease", value_diff("2"))?;
    let run = bundle.runner().preflight(&bundle.input(None)).await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(
        run.failure_reasons
            .contains(&"missing_action_lease".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn patch_denied_expired_lease() -> TestResult {
    let bundle = Bundle::new("patch-denied-expired-lease", value_diff("2"))?;
    let mut lease = bundle.lease.clone();
    lease.expires_at = Some(time::OffsetDateTime::now_utc() - time::Duration::minutes(1));
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&lease)))
        .await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(run.failure_reasons.contains(&"lease_expired".to_owned()));
    Ok(())
}

#[tokio::test]
async fn patch_denied_stale_git_head() -> TestResult {
    let bundle = Bundle::new("patch-denied-stale-head", value_diff("2"))?;
    let mut lease = bundle.lease.clone();
    if let Some(scope) = lease.allowed_scope.as_mut() {
        scope.git_head = Some("0000000000000000000000000000000000000000".to_owned());
    }
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&lease)))
        .await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(run.failure_reasons.contains(&"stale_git_head".to_owned()));
    Ok(())
}

#[tokio::test]
async fn patch_denied_file_outside_scope() -> TestResult {
    let bundle = Bundle::new("patch-denied-outside-scope", other_file_diff())?;
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&bundle.lease)))
        .await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(
        run.failure_reasons
            .iter()
            .any(|reason| reason.starts_with("file_outside_action_scope:"))
    );
    Ok(())
}

#[tokio::test]
async fn patch_denied_path_traversal() -> TestResult {
    let bundle = Bundle::new("patch-denied-path-traversal", path_traversal_diff())?;
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&bundle.lease)))
        .await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(
        run.failure_reasons
            .contains(&"path_traversal_rejected".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn patch_preflight_accepts_valid_scoped_patch() -> TestResult {
    let bundle = Bundle::new("patch-preflight-valid", value_diff("2"))?;
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&bundle.lease)))
        .await?;

    assert_eq!(run.status, PatchRunStatus::PreflightPassed);
    assert_eq!(run.changed_files, vec!["src/lib.rs"]);
    Ok(())
}

#[tokio::test]
async fn patch_apply_valid_scoped_patch() -> TestResult {
    let bundle = Bundle::new("patch-apply-valid", value_diff("2"))?;
    let (run, verifier_runs) = bundle.apply().await?;

    assert_eq!(run.status, PatchRunStatus::AppliedVerifierPassed);
    assert!(
        verifier_runs
            .iter()
            .any(|run| run.status == VerifierStatus::Passed)
    );
    assert!(fs::read_to_string(bundle.repo_root.join("src/lib.rs"))?.contains("{ 2 }"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn patch_records_patch_run_through_writer_actor() -> TestResult {
    let _guard = lock_tests().await;
    let bundle = Bundle::new("patch-records-writer", value_diff("2"))?;
    let mut patch_run = bundle
        .runner()
        .preflight(&bundle.input(Some(&bundle.lease)))
        .await?;
    let harness = Harness::new("patch-runner-patch-records.redb").await?;
    let wal = ControlWal::open(&harness.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, harness.store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());

    PatchMemoryWriter::write_patch_run(&handle, &WriteAdmissionService, &mut patch_run).await?;
    drop(handle);
    actor_task.await?;

    assert!(patch_run.write_receipt.is_some());
    Ok(())
}

#[tokio::test]
async fn verifier_runs_required_checks() -> TestResult {
    let bundle = Bundle::new("verifier-runs-required", value_diff("2"))?;
    let harness = bundle.verifier();
    let runs = harness
        .run_plan(
            bundle.lease.project_id,
            bundle.lease.task_id,
            bundle.lease.agent_id,
            &bundle.verifier_plan,
        )
        .await?;

    assert!(runs.iter().any(|run| {
        run.required_for_done && run.name == "cargo-check" && run.status == VerifierStatus::Passed
    }));
    Ok(())
}

#[tokio::test]
async fn verifier_failure_blocks_completion_done() -> TestResult {
    let bundle = Bundle::new("verifier-failure-blocks-done", value_diff("\"bad\""))?;
    let (patch_run, verifier_runs) = bundle.apply().await?;
    let proof = completion_proof(&patch_run, &verifier_runs);
    let decision =
        CompletionGate::decide_with_patch_context(&proof, Some(&patch_run), &verifier_runs);

    assert_eq!(patch_run.status, PatchRunStatus::RolledBack);
    assert_eq!(decision.final_status, CompletionStatus::FailedVerifier);
    Ok(())
}

#[tokio::test]
async fn verifier_success_allows_completion_done() -> TestResult {
    let bundle = Bundle::new("verifier-success-allows-done", value_diff("2"))?;
    let (patch_run, verifier_runs) = bundle.apply().await?;
    let proof = completion_proof(&patch_run, &verifier_runs);
    let decision =
        CompletionGate::decide_with_patch_context(&proof, Some(&patch_run), &verifier_runs);

    assert_eq!(decision.final_status, CompletionStatus::DoneVerified);
    Ok(())
}

#[tokio::test]
async fn rollback_on_verifier_failure() -> TestResult {
    let bundle = Bundle::new("rollback-on-verifier-failure", value_diff("\"bad\""))?;
    let (patch_run, _verifier_runs) = bundle.apply().await?;
    let content = fs::read_to_string(bundle.repo_root.join("src/lib.rs"))?;

    assert_eq!(patch_run.status, PatchRunStatus::RolledBack);
    assert!(content.contains("pub fn value() -> u32 { 1 }"));
    Ok(())
}

#[test]
fn accumulated_capabilities_non_regression() -> TestResult {
    let repo = repo_root();
    let action = fs::read_to_string(repo.join("crates/eliot-engine/src/action.rs"))?;
    let context = fs::read_to_string(repo.join("crates/eliot-engine/src/context.rs"))?;
    let mcp = fs::read_to_string(repo.join("crates/eliot-app/src/mcp_stdio.rs"))?;

    assert!(action.contains("PatchExecutionNotAllowedInE1"));
    assert!(context.contains("pub struct CognitiveGate"));
    assert!(mcp.contains("eliot_codecortex_scan"));
    assert!(!mcp.contains("eliot_shell"));
    assert!(!mcp.contains("eliot_git"));
    Ok(())
}

struct Bundle {
    repo_root: PathBuf,
    lease: ActionLease,
    work_lease: WorkLease,
    request: PatchRequest,
    report: CodeCortexReport,
    verifier_plan: VerifierPlan,
}

impl Bundle {
    fn new(name: &str, diff_text: String) -> TestResult<Self> {
        let repo_root = fixture_repo(name)?;
        let report = report(&repo_root)?;
        let verifier_plan = verifier_plan();
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let agent_id = AgentId::new_v7();
        let lease = ActionLease {
            lease_id: eliot_types::ActionLeaseId::new_v7(),
            request_id: eliot_types::ActionRequestId::new_v7(),
            project_id,
            task_id,
            agent_id,
            decision: LeaseDecision::AllowPatchExecution,
            status: LeaseStatus::ApprovedForExecution,
            allowed_scope: Some(ActionScope {
                repo_root: repo_root.display().to_string(),
                git_head: report.git_head.clone(),
                allowed_files: vec!["src/lib.rs".to_owned()],
                allowed_symbols: Vec::new(),
                forbidden_files: Vec::new(),
                max_files: 1,
                max_diff_bytes: 2048,
                max_runtime_seconds: 60,
            }),
            change_plan: None,
            verifier_plan: Some(verifier_plan.clone()),
            skill_refs: Vec::new(),
            denial_reasons: Vec::new(),
            expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
            created_at: time::OffsetDateTime::now_utc(),
        };
        let work_lease = active_work_lease(&lease, &report, &verifier_plan);
        let request = PatchRequest {
            patch_request_id: PatchRequestId::new_v7(),
            project_id,
            task_id,
            agent_id,
            action_lease_id: lease.lease_id,
            repo_root: repo_root.display().to_string(),
            git_head_before: report.git_head.clone(),
            codecortex_report_refs: vec![codecortex_report_ref(&report)],
            verifier_plan_ref: format!("verifier_plan:{}", lease.lease_id),
            diff: UnifiedDiff {
                byte_len: diff_text.len(),
                text: diff_text,
            },
            created_at: time::OffsetDateTime::now_utc(),
        };
        Ok(Self {
            repo_root,
            lease,
            work_lease,
            request,
            report,
            verifier_plan,
        })
    }

    fn runner(&self) -> PatchRunner<'_> {
        PatchRunner::new(&self.repo_root, None)
    }

    fn verifier(&self) -> VerifierHarness<'_> {
        VerifierHarness::new(&self.repo_root, None)
    }

    fn input<'a>(&'a self, lease: Option<&'a ActionLease>) -> PatchRunnerInput<'a> {
        PatchRunnerInput {
            request: &self.request,
            lease,
            work_lease: Some(&self.work_lease),
            codecortex_reports: std::slice::from_ref(&self.report),
            verifier_plan: Some(&self.verifier_plan),
            incident_lockdown_active: false,
        }
    }

    async fn apply(&self) -> TestResult<(PatchRun, Vec<VerifierRun>)> {
        let (mut patch_run, mut verifier_runs) = self
            .runner()
            .apply(&self.input(Some(&self.lease)), &self.verifier())
            .await?;
        patch_run.write_receipt = Some(receipt_ref());
        for verifier_run in &mut verifier_runs {
            verifier_run.write_receipt = Some(receipt_ref());
        }
        Ok((patch_run, verifier_runs))
    }
}

fn receipt_ref() -> WriteReceiptRef {
    WriteReceiptRef {
        receipt_id: ReceiptId::new_v7(),
        write_id: WriteId::new_v7(),
    }
}

fn active_work_lease(
    lease: &ActionLease,
    report: &CodeCortexReport,
    verifier_plan: &VerifierPlan,
) -> WorkLease {
    let now = time::OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    let files = lease
        .allowed_scope
        .as_ref()
        .map(|scope| scope.allowed_files.clone())
        .unwrap_or_default();
    WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id: lease.agent_id,
        project_id: lease.project_id,
        task_id: lease.task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: eliot_engine::default_work_scope(
            report.repo_root.clone(),
            files.clone(),
            files,
            verifier_plan
                .required
                .iter()
                .map(|verifier| verifier.command_display.clone())
                .collect(),
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
    async fn new(wal_name: &str) -> TestResult<Self> {
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
                    .join(".eliot-governor/control-wal")
                    .join(wal_name)
                    .display()
                    .to_string(),
            },
        })
    }
}

fn fixture_repo(name: &str) -> TestResult<PathBuf> {
    let target = repo_root().join("target");
    fs::create_dir_all(&target)?;
    let repo = target.join(name);
    if repo.exists() {
        if !repo.starts_with(&target) {
            return Err("refusing to remove fixture outside target".into());
        }
        fs::remove_dir_all(&repo)?;
    }
    fs::create_dir_all(repo.join("src"))?;
    fs::write(
        repo.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"patch-runner-test-fixture\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2024\"\n\n",
            "[workspace]\n"
        ),
    )?;
    fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 1 }\n")?;
    run_process(&repo, "git", &["init"])?;
    run_process(
        &repo,
        "git",
        &["config", "user.email", "eliot@example.invalid"],
    )?;
    run_process(&repo, "git", &["config", "user.name", "Eliot Governor"])?;
    run_process(&repo, "git", &["add", "."])?;
    run_process(&repo, "git", &["commit", "-m", "init"])?;
    Ok(repo)
}

fn report(repo_root: &Path) -> TestResult<CodeCortexReport> {
    let git_head = git_head(repo_root)?;
    let evidence = FileEvidence {
        path: "src/lib.rs".to_owned(),
        content_hash: Some("fixture-hash".to_owned()),
        line_start: Some(1),
        line_end: Some(1),
        excerpt: "pub fn value() -> u32 { 1 }".to_owned(),
        source: CodeEvidenceSource::Rg,
    };
    Ok(CodeCortexReport {
        project: "patch-runner-fixture".to_owned(),
        task: "patch-runner-test".to_owned(),
        goal: "Patch src/lib.rs".to_owned(),
        generated_at: time::OffsetDateTime::now_utc(),
        repo_root: repo_root.display().to_string(),
        git_head: Some(git_head),
        dirty: false,
        scope_binding: eliot_types::CodeCortexScopeBinding::default(),
        tracked_files: vec![evidence.clone()],
        workspace_members: vec![repo_root.display().to_string()],
        crates: vec!["patch-runner-test-fixture".to_owned()],
        targets: vec!["patch_runner_test_fixture".to_owned()],
        file_evidence: vec![evidence],
        symbol_evidence: vec![SymbolEvidence {
            name: "value".to_owned(),
            kind: "fn".to_owned(),
            path: "src/lib.rs".to_owned(),
            line: Some(1),
            source: CodeEvidenceSource::Rg,
        }],
        diagnostic_evidence: vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "clean".to_owned(),
            path: None,
            line: None,
            severity: "info".to_owned(),
            message: "fixture initialized".to_owned(),
        }],
        verifier_evidence: vec![VerifierEvidence {
            name: "fixture".to_owned(),
            command: "cargo check".to_owned(),
            status: "ready".to_owned(),
            summary: "fixture ready".to_owned(),
            source: CodeEvidenceSource::Diagnostics,
        }],
        blast_radius: BlastRadiusView {
            files: vec!["src/lib.rs".to_owned()],
            crates: vec!["patch-runner-test-fixture".to_owned()],
            reasons: vec!["test fixture".to_owned()],
        },
        invariant_cards: vec![InvariantCard {
            name: "bounded_scope".to_owned(),
            status: "enforced".to_owned(),
            evidence: "src/lib.rs only".to_owned(),
        }],
        evidence_sources: vec![CodeEvidenceSource::Rg, CodeEvidenceSource::Diagnostics],
        adapter_notes: Vec::new(),
        memory_receipt: None,
        operation_status: eliot_types::OperationStatus::OperationCompleted,
    })
}

fn verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "cargo-check".to_owned(),
            command_kind: VerifierCommandKind::CargoCheck,
            command_display: "cargo check".to_owned(),
            scope: vec!["src/lib.rs".to_owned()],
            required_for_done: true,
            expected_signal: "fixture type-checks".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["patch applies and cargo check passes".to_owned()],
    }
}

fn completion_proof(patch_run: &PatchRun, verifier_runs: &[VerifierRun]) -> CompletionProof {
    CompletionProof {
        task_id: patch_run.task_id.to_string(),
        project_id: patch_run.project_id,
        goal: "Patch src/lib.rs".to_owned(),
        changed_files: patch_run.changed_files.clone(),
        memory_refs_used: vec![format!("patch_run:{}", patch_run.patch_run_id)],
        checks_run: verifier_runs.iter().map(|run| run.name.clone()).collect(),
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "patch applies and cargo check passes".to_owned(),
            status: "verified".to_owned(),
            evidence: format!("patch_run:{}", patch_run.patch_run_id),
            verifier: "cargo-check".to_owned(),
            residual_uncertainty: "none".to_owned(),
        }],
        evidence: std::iter::once(format!("patch_run:{}", patch_run.patch_run_id))
            .chain(
                verifier_runs
                    .iter()
                    .map(|run| format!("verifier_run:{}", run.verifier_run_id)),
            )
            .collect(),
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    }
}

fn value_diff(new_value: &str) -> String {
    format!(
        concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -1 +1 @@\n",
            "-pub fn value() -> u32 {{ 1 }}\n",
            "+pub fn value() -> u32 {{ {} }}\n"
        ),
        new_value
    )
}

fn other_file_diff() -> String {
    concat!(
        "diff --git a/src/other.rs b/src/other.rs\n",
        "--- /dev/null\n",
        "+++ b/src/other.rs\n",
        "@@ -0,0 +1 @@\n",
        "+pub fn other() {}\n"
    )
    .to_owned()
}

fn path_traversal_diff() -> String {
    concat!(
        "diff --git a/../evil.rs b/../evil.rs\n",
        "--- a/../evil.rs\n",
        "+++ b/../evil.rs\n",
        "@@ -1 +1 @@\n",
        "-old\n",
        "+new\n"
    )
    .to_owned()
}

fn git_head(repo_root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string().into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_process(cwd: &Path, program: &str, args: &[&str]) -> TestResult {
    let output = Command::new(program).args(args).current_dir(cwd).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string().into());
    }
    Ok(())
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
    let lock_path = repo_root().join("target/patch-runner-migrate.lock");
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
