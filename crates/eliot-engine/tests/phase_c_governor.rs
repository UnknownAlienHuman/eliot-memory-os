use eliot_engine::{
    CognitiveGate, CompletionGate, ContextCompiler, ReadService, UnderstandingProofValidator,
    WriteAdmissionService, WriterActor, WriterConfig, WriterHandle,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, CognitiveGateOutcome, CognitiveGateReason,
    CognitiveGateRequest, CommandContext, CompilePacketL3Request, CompletionAcceptanceItem,
    CompletionProof, CompletionStatus, ControlWalConfig, EpistemicStatus, EvidenceAtomInput,
    EvidenceId, EvidenceIngestCommand, FailureRecordCommand, GovernorConfig, LifecycleStatus,
    ProjectId, SemanticCommand, SourceSnapshotInput, TaintClass, UnderstandingProof,
    VerificationResult, VerificationRunInput, Visibility, WriteId,
};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn compile_packet_l3_budgeted() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("compile-budgeted").await?;
    let seed = harness.seed_claim_matrix().await?;
    let packet = ContextCompiler::new(ReadService::new(harness.store.clone()))
        .compile(&CompilePacketL3Request {
            project_id: seed.project,
            task_id: "phase-c-budget".to_owned(),
            goal: "compile a bounded packet".to_owned(),
            candidate_handles: vec![format!("claim:{}", seed.verified_claim)],
            max_tokens: 1_800,
        })
        .await?;

    assert!(packet.token_budget_report.estimated_tokens <= packet.token_budget_report.max_tokens);
    assert_eq!(packet.project_id, seed.project);
    Ok(())
}

#[tokio::test]
async fn compile_packet_l3_separates_verified_supported_weak() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("compile-separates").await?;
    let seed = harness.seed_claim_matrix().await?;
    let packet = ContextCompiler::new(ReadService::new(harness.store.clone()))
        .compile(&CompilePacketL3Request {
            project_id: seed.project,
            task_id: "phase-c-separation".to_owned(),
            goal: "claim".to_owned(),
            candidate_handles: Vec::new(),
            max_tokens: 4_000,
        })
        .await?;

    assert!(
        packet
            .relevant_verified_claims
            .iter()
            .any(|claim| claim.claim_id == seed.verified_claim)
    );
    assert!(
        packet
            .relevant_supported_claims
            .iter()
            .any(|claim| claim.claim_id == seed.supported_claim)
    );
    assert!(
        packet
            .weak_claims_warning
            .iter()
            .any(|claim| claim.claim_id == seed.weak_claim)
    );
    Ok(())
}

#[tokio::test]
async fn understanding_proof_rejects_missing_evidence() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("proof-missing-evidence").await?;
    let seed = harness.seed_claim_matrix().await?;
    let proof = valid_proof(
        &seed,
        vec![format!("claim:{}", seed.verified_claim)],
        Vec::new(),
    );
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate(&proof)
        .await?;

    assert!(!receipt.accepted);
    assert!(
        receipt
            .validation_errors
            .contains(&CognitiveGateReason::MissingEvidence)
    );
    Ok(())
}

#[tokio::test]
async fn understanding_proof_rejects_weak_claim_as_truth() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("proof-weak-truth").await?;
    let seed = harness.seed_claim_matrix().await?;
    let proof = valid_proof(
        &seed,
        vec![format!("claim:{}", seed.weak_claim)],
        vec![format!("evidence:{}", seed.evidence)],
    );
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate(&proof)
        .await?;

    assert!(!receipt.accepted);
    assert!(
        receipt
            .validation_errors
            .contains(&CognitiveGateReason::WeakClaimUsedAsTruth)
    );
    Ok(())
}

#[tokio::test]
async fn cognitive_gate_allows_valid_proof() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("gate-valid").await?;
    let seed = harness.seed_claim_matrix().await?;
    let proof = valid_proof(
        &seed,
        vec![format!("claim:{}", seed.verified_claim)],
        vec![format!("evidence:{}", seed.evidence)],
    );
    let receipt = UnderstandingProofValidator::new(ReadService::new(harness.store.clone()))
        .validate(&proof)
        .await?;
    let decision = CognitiveGate::decide(&CognitiveGateRequest {
        receipt,
        requested_action: "edit governed Rust code with verifier".to_owned(),
    });

    assert_eq!(decision.decision, CognitiveGateOutcome::Allow);
    Ok(())
}

#[test]
fn cognitive_gate_requires_probe_for_missing_evidence() {
    let receipt = eliot_types::UnderstandingProofReceipt {
        task_id: "phase-c-require-probe".to_owned(),
        project_id: ProjectId::new_v7(),
        accepted: false,
        validation_errors: vec![CognitiveGateReason::MissingEvidence],
        checked_refs: Vec::new(),
        code_task: false,
        codecortex_report_refs: Vec::new(),
        files_to_change: Vec::new(),
        files_to_inspect: Vec::new(),
    };
    let decision = CognitiveGate::decide(&CognitiveGateRequest {
        receipt,
        requested_action: "edit governed Rust code".to_owned(),
    });

    assert_eq!(decision.decision, CognitiveGateOutcome::RequireProbe);
}

#[test]
fn completion_gate_rejects_unverified_done() {
    let decision = CompletionGate::decide(&completion_proof("not_verified"));

    assert_eq!(decision.final_status, CompletionStatus::PartialProgress);
}

#[test]
fn completion_gate_accepts_verified_done() {
    let decision = CompletionGate::decide(&completion_proof("verified"));

    assert_eq!(decision.final_status, CompletionStatus::DoneVerified);
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
    admission: WriteAdmissionService,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("eliot-phase-c-{name}-{}", std::process::id()));
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

    async fn seed_claim_matrix(&self) -> TestResult<SeededMemory> {
        let project_id = ProjectId::new_v7();
        let evidence_id = EvidenceId::new_v7();
        let verified_claim_id = ClaimId::new_v7();
        let supported_claim_id = ClaimId::new_v7();
        let weak_claim_id = ClaimId::new_v7();
        let (handle, actor_task) = self.writer_pair("seed")?;

        submit(
            &self.admission,
            &handle,
            evidence_command(project_id, evidence_id, "phase-c evidence"),
        )
        .await?;
        submit(
            &self.admission,
            &handle,
            claim_propose(project_id, verified_claim_id, "verified decision claim"),
        )
        .await?;
        submit(
            &self.admission,
            &handle,
            claim_verify(
                project_id,
                verified_claim_id,
                "verified decision claim",
                VerificationResult::Passed,
            ),
        )
        .await?;
        submit(
            &self.admission,
            &handle,
            claim_propose(project_id, supported_claim_id, "supported claim"),
        )
        .await?;
        submit(
            &self.admission,
            &handle,
            claim_support(
                project_id,
                supported_claim_id,
                evidence_id,
                "supported claim",
            ),
        )
        .await?;
        submit(
            &self.admission,
            &handle,
            claim_propose(project_id, weak_claim_id, "weak candidate claim"),
        )
        .await?;
        submit(
            &self.admission,
            &handle,
            failure_record(project_id, "phase-c-known-failure"),
        )
        .await?;

        drop(handle);
        actor_task.await?;
        Ok(SeededMemory {
            project: project_id,
            evidence: evidence_id,
            verified_claim: verified_claim_id,
            supported_claim: supported_claim_id,
            weak_claim: weak_claim_id,
        })
    }

    fn writer_pair(&self, name: &str) -> TestResult<(WriterHandle, JoinHandle<()>)> {
        let path = self.root.join(name).join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        let (handle, actor) =
            WriterActor::channel(wal, self.store.clone(), &WriterConfig::default());
        Ok((handle, tokio::spawn(actor.run())))
    }
}

struct SeededMemory {
    project: ProjectId,
    evidence: EvidenceId,
    verified_claim: ClaimId,
    supported_claim: ClaimId,
    weak_claim: ClaimId,
}

fn valid_proof(
    seed: &SeededMemory,
    current_truth_refs: Vec<String>,
    evidence_refs: Vec<String>,
) -> UnderstandingProof {
    UnderstandingProof {
        task_id: "phase-c-proof".to_owned(),
        project_id: seed.project,
        goal: "prove governed action".to_owned(),
        code_task: false,
        current_truth_refs,
        evidence_refs,
        codecortex_report_refs: Vec::new(),
        files_to_change: Vec::new(),
        files_to_inspect: Vec::new(),
        causal_bridge: "current truth plus evidence supports the planned action".to_owned(),
        causal_bridge_from_goal_to_code: String::new(),
        invariants: vec!["no raw SQL".to_owned()],
        negative_memory_checked: true,
        unknowns: Vec::new(),
        planned_action: "inspect governed memory with verifiers".to_owned(),
        expected_verifiers: vec!["cargo test".to_owned()],
        blast_radius_acknowledged: false,
        skill_refs: Vec::new(),
        skill_application_rationales: Vec::new(),
        skill_anti_scope_acknowledgements: Vec::new(),
        skill_required_inputs: Vec::new(),
        skill_verifier_plan_refs: Vec::new(),
        risk_level: "low".to_owned(),
    }
}

fn completion_proof(status: &str) -> CompletionProof {
    CompletionProof {
        task_id: "phase-c-completion".to_owned(),
        project_id: ProjectId::new_v7(),
        goal: "finish phase c".to_owned(),
        changed_files: vec!["crates/eliot-engine/src/context.rs".to_owned()],
        memory_refs_used: vec!["claim:verified".to_owned()],
        checks_run: vec!["cargo test".to_owned()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "gate works".to_owned(),
            status: status.to_owned(),
            evidence: "test output".to_owned(),
            verifier: "phase_c_governor".to_owned(),
            residual_uncertainty: "none".to_owned(),
        }],
        evidence: vec!["phase_c_governor passed".to_owned()],
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    }
}

async fn submit(
    admission: &WriteAdmissionService,
    handle: &WriterHandle,
    command: SemanticCommand,
) -> TestResult<eliot_types::WriteReceipt> {
    Ok(handle.submit(admission.admit(&command)?).await?)
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
    let lock_path = repo_root().join("target/phase-c-migrate.lock");
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

fn context(project_id: ProjectId) -> CommandContext {
    CommandContext {
        write_id: WriteId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: None,
        scope: "phase-c-test".to_owned(),
        authority: "local-test".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn evidence_command(
    project_id: ProjectId,
    evidence_id: EvidenceId,
    label: &str,
) -> SemanticCommand {
    let source_id = format!("source-{evidence_id}");
    SemanticCommand::EvidenceIngest(EvidenceIngestCommand {
        context: context(project_id),
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
            payload: json!({ "phase": "c" }),
        },
    })
}

fn claim_propose(project_id: ProjectId, claim_id: ClaimId, statement: &str) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: context(project_id),
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
        context: context(project_id),
        claim_id,
        evidence_id,
        statement: Some(statement.to_owned()),
        payload: json!({ "state": "supported" }),
    })
}

fn claim_verify(
    project_id: ProjectId,
    claim_id: ClaimId,
    statement: &str,
    result: VerificationResult,
) -> SemanticCommand {
    SemanticCommand::ClaimVerify(eliot_types::ClaimVerifyCommand {
        context: context(project_id),
        claim_id,
        verification: VerificationRunInput {
            verification_id: eliot_types::VerificationId::new_v7(),
            claim_id: Some(claim_id),
            verifier: "phase-c-test".to_owned(),
            result,
            summary: format!("{result:?}"),
            payload: json!({ "result": format!("{result:?}") }),
        },
        statement: Some(statement.to_owned()),
        payload: json!({ "state": "verified" }),
    })
}

fn failure_record(project_id: ProjectId, fingerprint: &str) -> SemanticCommand {
    SemanticCommand::FailureRecord(FailureRecordCommand {
        context: context(project_id),
        fingerprint: fingerprint.to_owned(),
        summary: "known failure".to_owned(),
        payload: json!({ "phase": "c" }),
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
