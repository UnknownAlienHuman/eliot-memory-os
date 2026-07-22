use eliot_engine::{
    CognitiveGate, ContextCompiler, ReadService, UnderstandingProofValidator, codecortex_report_ref,
};
use eliot_store::CanonicalStore;
use eliot_types::{
    BlastRadiusView, CodeCortexReport, CodeEvidenceSource, CognitiveGateOutcome,
    CognitiveGateReason, CognitiveGateRequest, CompilePacketL3Request, DiagnosticEvidence,
    FileEvidence, GovernorConfig, InvariantCard, ProjectId, SymbolEvidence, UnderstandingProof,
    VerifierEvidence,
};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn codecortex_report_included_in_l3_packet() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("d2-l3-codecortex").await?;
    let report = report();
    let packet = ContextCompiler::new(ReadService::new(harness.store.clone()))
        .compile_with_codecortex(
            &CompilePacketL3Request {
                project_id: ProjectId::new_v7(),
                task_id: "phase-d2-code-task".to_owned(),
                goal: "Find the Phase C MCP tools and cognitive gate implementation".to_owned(),
                candidate_handles: Vec::new(),
                max_tokens: 4_000,
            },
            std::slice::from_ref(&report),
        )
        .await?;

    let codecortex = packet
        .codecortex
        .ok_or_else(|| std::io::Error::other("CodeCortex view is missing"))?;
    assert!(
        codecortex
            .report_refs
            .contains(&codecortex_report_ref(&report))
    );
    assert!(
        codecortex
            .file_evidence
            .iter()
            .any(|evidence| evidence.path == "crates/eliot-app/src/mcp_stdio.rs")
    );
    assert!(
        codecortex
            .symbol_evidence
            .iter()
            .any(|evidence| evidence.name == "CognitiveGate")
    );
    assert!(
        codecortex
            .diagnostic_evidence
            .iter()
            .any(|evidence| evidence.status == "clean")
    );
    assert!(!codecortex.verifier_map.is_empty());
    assert!(
        codecortex
            .blast_radius
            .files
            .contains(&"crates/eliot-engine/src/context.rs".to_owned())
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn understanding_proof_requires_codecortex_for_code_task() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("d2-proof-requires-codecortex").await?;
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate_with_codecortex(&code_proof(Vec::new(), vec![known_file()], true, true), &[])
        .await?;

    assert!(!receipt.accepted);
    assert!(
        receipt
            .validation_errors
            .contains(&CognitiveGateReason::MissingCodeCortexReport)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn cognitive_gate_blocks_code_task_without_codecortex() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("d2-gate-missing-codecortex").await?;
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate_with_codecortex(&code_proof(Vec::new(), vec![known_file()], true, true), &[])
        .await?;
    let decision = CognitiveGate::decide(&CognitiveGateRequest {
        receipt,
        requested_action: "inspect grounded code".to_owned(),
    });

    assert_eq!(decision.decision, CognitiveGateOutcome::Block);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn cognitive_gate_blocks_stale_or_missing_code_refs() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("d2-gate-stale-codecortex").await?;
    let report = report();
    let proof = code_proof(
        vec!["codecortex_report:old-task:old-head:old-write".to_owned()],
        vec![known_file()],
        true,
        true,
    );
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate_with_codecortex(&proof, std::slice::from_ref(&report))
        .await?;
    let decision = CognitiveGate::decide(&CognitiveGateRequest {
        receipt,
        requested_action: "inspect grounded code".to_owned(),
    });

    assert_eq!(decision.decision, CognitiveGateOutcome::Block);
    assert!(
        decision
            .reasons
            .contains(&CognitiveGateReason::StaleCodeCortexReport)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn cognitive_gate_allows_grounded_code_task_read_only() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("d2-gate-grounded-code").await?;
    let report = report();
    let proof = code_proof(
        vec![codecortex_report_ref(&report)],
        vec![known_file()],
        true,
        true,
    );
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate_with_codecortex(&proof, std::slice::from_ref(&report))
        .await?;
    assert!(receipt.accepted);

    let decision = CognitiveGate::decide(&CognitiveGateRequest {
        receipt,
        requested_action: "inspect grounded code".to_owned(),
    });

    assert_eq!(decision.decision, CognitiveGateOutcome::AllowReadOnly);
    Ok(())
}

#[test]
fn phase_b_c_d1_non_regression() -> TestResult {
    let mcp_stdio = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let context = fs::read_to_string(repo_root().join("crates/eliot-engine/src/context.rs"))?;

    assert!(mcp_stdio.contains("eliot_current_state"));
    assert!(mcp_stdio.contains("eliot_cognitive_gate"));
    assert!(mcp_stdio.contains("eliot_codecortex_scan"));
    assert!(mcp_stdio.contains("eliot_codecortex_latest"));
    for raw_tool in ["raw_shell", "raw_rg", "raw_ast_grep", "raw_git", "raw_file"] {
        assert!(!mcp_stdio.contains(raw_tool));
    }
    assert!(context.contains("pub struct ContextCompiler"));
    assert!(context.contains("pub struct CognitiveGate"));
    Ok(())
}

struct Harness {
    store: CanonicalStore,
}

impl Harness {
    async fn new(_name: &str) -> TestResult<Self> {
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
        Ok(Self { store })
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
    let lock_path = repo_root().join("target/phase-d2-migrate.lock");
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

fn code_proof(
    codecortex_report_refs: Vec<String>,
    files_to_inspect: Vec<String>,
    code_bridge_present: bool,
    blast_radius_acknowledged: bool,
) -> UnderstandingProof {
    UnderstandingProof {
        task_id: "phase-d2-code-proof".to_owned(),
        project_id: ProjectId::new_v7(),
        goal: "Find the Phase C MCP tools and cognitive gate implementation".to_owned(),
        code_task: true,
        current_truth_refs: Vec::new(),
        evidence_refs: Vec::new(),
        codecortex_report_refs,
        files_to_change: Vec::new(),
        files_to_inspect,
        causal_bridge: "CodeCortex report grounds the read-only code task".to_owned(),
        causal_bridge_from_goal_to_code: if code_bridge_present {
            "Goal maps to mcp_stdio and CognitiveGate implementation".to_owned()
        } else {
            String::new()
        },
        invariants: vec!["no raw tools exposed".to_owned()],
        negative_memory_checked: true,
        unknowns: Vec::new(),
        planned_action: "inspect grounded code".to_owned(),
        expected_verifiers: vec!["cargo test".to_owned()],
        blast_radius_acknowledged,
        skill_refs: Vec::new(),
        skill_application_rationales: Vec::new(),
        skill_anti_scope_acknowledgements: Vec::new(),
        skill_required_inputs: Vec::new(),
        skill_verifier_plan_refs: Vec::new(),
        risk_level: "low".to_owned(),
    }
}

fn report() -> CodeCortexReport {
    let file_evidence = vec![
        FileEvidence {
            path: "crates/eliot-app/src/mcp_stdio.rs".to_owned(),
            content_hash: Some("hash-mcp".to_owned()),
            line_start: Some(18),
            line_end: Some(26),
            excerpt: "const GOVERNED_TOOLS".to_owned(),
            source: CodeEvidenceSource::Rg,
        },
        FileEvidence {
            path: "crates/eliot-engine/src/context.rs".to_owned(),
            content_hash: Some("hash-context".to_owned()),
            line_start: Some(292),
            line_end: Some(333),
            excerpt: "impl CognitiveGate".to_owned(),
            source: CodeEvidenceSource::Rg,
        },
    ];
    CodeCortexReport {
        project: "eliot-governor".to_owned(),
        task: "phase-d2-test-report".to_owned(),
        goal: "Find the Phase C MCP tools and cognitive gate implementation".to_owned(),
        generated_at: time::OffsetDateTime::now_utc(),
        repo_root: repo_root().display().to_string(),
        git_head: Some("d2-test-head".to_owned()),
        dirty: false,
        tracked_files: file_evidence.clone(),
        workspace_members: vec!["eliot-app".to_owned(), "eliot-engine".to_owned()],
        crates: vec!["eliot-app".to_owned(), "eliot-engine".to_owned()],
        targets: vec!["eliot-governor".to_owned()],
        file_evidence,
        symbol_evidence: vec![SymbolEvidence {
            name: "CognitiveGate".to_owned(),
            kind: "struct".to_owned(),
            path: "crates/eliot-engine/src/context.rs".to_owned(),
            line: Some(290),
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
            files: vec![
                "crates/eliot-app/src/mcp_stdio.rs".to_owned(),
                "crates/eliot-engine/src/context.rs".to_owned(),
            ],
            crates: vec!["eliot-app".to_owned(), "eliot-engine".to_owned()],
            reasons: vec!["D2 integration touches MCP stdio and cognitive gate".to_owned()],
        },
        invariant_cards: vec![InvariantCard {
            name: "no_raw_mcp_tools".to_owned(),
            status: "enforced".to_owned(),
            evidence: "Only governed CodeCortex scan/latest tools are exposed".to_owned(),
        }],
        evidence_sources: vec![CodeEvidenceSource::Rg, CodeEvidenceSource::Diagnostics],
        adapter_notes: Vec::new(),
        memory_receipt: None,
        final_status: "ready".to_owned(),
    }
}

fn known_file() -> String {
    "crates/eliot-app/src/mcp_stdio.rs".to_owned()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
