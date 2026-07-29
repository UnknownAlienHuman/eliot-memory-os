use eliot_store::{CanonicalStore, SurrealServerSupervisor};
use eliot_types::{
    AgentId, AutonomyRunContract, AutonomyRunState, AutonomyRunTransitionReceipt,
    CanonicalTraceCompletenessContract, ClaimCardInput, ClaimId, CredentialProviderKind,
    EpistemicStatus, ExperimentalMetaPolicyPayload, ForgettingOperator, ForgettingReason,
    GovernorConfig, HarnessExperimentRecord, HarnessExperimentRecordId, IdempotencyOptions,
    LifecycleStatus, LifecycleWriteOptions, MemoryEcologyDecision, MemoryLifecycleState,
    MemoryRevision, MemoryStateTransition, MemoryTrajectoryCorrectness, MemoryWriteEnvelope,
    MetaCandidateChangeClass, MetaExperimentDecision, MetaPolicyExecutionAction,
    MetaPolicyExecutionReceipt, MinorityPressureRecord, MinorityPressureStatus, OperationId,
    ProjectId, ProjectSequence, ReadConsistencyMode, RecallL0Request, ReplayAudit, ReplayRun,
    ReplayRunId, ReplayRunProfile, ReplayRunStatus, ReplaySetId, SemanticCommandKind,
    SurrealServerConfig, TaintClass, TaskId, ToolObservationInput, Visibility, WriteId,
    WriteStatus,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

struct RestartTestRoot {
    path: Option<PathBuf>,
}

impl RestartTestRoot {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temp = std::env::temp_dir();
        let path = temp.join(format!(
            "eliot-cognitive-contract-restart-{}-{}",
            std::process::id(),
            WriteId::new_v7()
        ));
        if !path.starts_with(&temp) {
            return Err("restart-test root escaped the system temp directory".into());
        }
        let lower = path.to_string_lossy().to_ascii_lowercase();
        if lower.contains("onedrive") || lower.contains("programdata") {
            return Err("restart-test root crossed a forbidden host boundary".into());
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path: Some(path) })
    }

    fn path(&self) -> Result<&Path, Box<dyn Error>> {
        self.path
            .as_deref()
            .ok_or_else(|| "restart-test root was already removed".into())
    }

    fn config(&self, port: u16) -> Result<SurrealServerConfig, Box<dyn Error>> {
        let root = self.path()?;
        let storage = root.join("surrealdb-rocks");
        let password_file = PathBuf::from(std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?);
        let mut config = GovernorConfig::default().db.surreal;
        config.bind = format!("127.0.0.1:{port}");
        config.endpoint = format!("ws://127.0.0.1:{port}/rpc");
        config.storage = format!("rocksdb:{}", slash(&storage));
        config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        "test-only/l10-l12-restart".clone_into(&mut config.credential_id);
        config.password_file = slash(&password_file);
        config.startup_timeout_ms = 20_000;
        Ok(config)
    }

    fn remove(&mut self) -> Result<PathBuf, Box<dyn Error>> {
        let path = self
            .path
            .take()
            .ok_or("restart-test root was already removed")?;
        let temp = std::env::temp_dir();
        if !path.starts_with(&temp) {
            return Err("refused to remove a non-temp restart-test root".into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match fs::remove_dir_all(&path) {
                Ok(()) => return Ok(path),
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for RestartTestRoot {
    fn drop(&mut self) {
        if let Some(path) = self.path.take()
            && path.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn free_local_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn strip_materialized_exact_fields(
    config: &SurrealServerConfig,
    record_ids: &[String],
) -> Result<(), Box<dyn Error>> {
    let ids = record_ids
        .iter()
        .map(|record_id| format!("'{record_id}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "UPDATE canonical_record UNSET trace_ref, candidate_id, canonical_action WHERE record_id IN [{ids}];"
    );
    run_surreal_sql(
        config,
        &query,
        "failed to simulate a pre-exact-lookup store",
    )
}

fn run_surreal_sql(
    config: &SurrealServerConfig,
    query: &str,
    failure_context: &str,
) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new(&config.exe)
        .args([
            "sql",
            "--endpoint",
            &config.endpoint,
            "--auth-level",
            "root",
            "--namespace",
            &config.ns,
            "--database",
            &config.db,
            "--json",
            "--hide-welcome",
        ])
        .env("SURREAL_USER", &config.user)
        .env("SURREAL_PASS", std::env::var("SURREAL_PASS")?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("SurrealDB SQL stdin was not piped")?
        .write_all(query.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "{failure_context}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

async fn seed_operator_page_records(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    count: u64,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut envelope = canonical_envelope(
        project_id,
        Some(task_id),
        1,
        "operator_control_request",
        &json!({}),
    )?;
    let expected_record_ids = (1..=count)
        .map(|sequence| format!("operator-page-{sequence:04}"))
        .collect::<Vec<_>>();
    envelope.tool_observations = expected_record_ids
        .iter()
        .enumerate()
        .map(|(index, record_id)| ToolObservationInput {
            observation_id: record_id.clone(),
            tool_name: "eliot_operator_paging_test".to_owned(),
            observation: "canonical operator paging fixture".to_owned(),
            payload: json!({
                "receipt_kind": "operator_control_request",
                "receipt_body": {
                    "target_ref": format!("approval:{:04}", index + 1),
                    "sequence": index + 1,
                },
                "writer_path": "isolated_store_test",
            }),
        })
        .collect();
    envelope.input_hash = blake3::hash(&serde_json::to_vec(&envelope.tool_observations)?)
        .to_hex()
        .to_string();
    let receipt = store.apply_write_envelope(&envelope).await?;
    assert_eq!(receipt.status, WriteStatus::Committed);
    Ok(expected_record_ids)
}

fn isolated_config() -> Option<SurrealServerConfig> {
    let endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT").ok()?;
    let bind = std::env::var("ELIOT_TEST_SURREAL_BIND").ok()?;
    let password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE").ok()?;
    let storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE").ok()?;
    let mut config = GovernorConfig::default().db.surreal;
    config.endpoint = endpoint;
    config.bind = bind;
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    "test-only/workspace-wrapper".clone_into(&mut config.credential_id);
    config.password_file = password_file;
    config.storage = storage;
    Some(config)
}

fn canonical_envelope<T: Serialize>(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    sequence: u64,
    kind: &str,
    body: &T,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let write_id = WriteId::new_v7();
    let body = serde_json::to_value(body)?;
    let input_hash = blake3::hash(&serde_json::to_vec(&json!({
        "project_id": project_id,
        "task_id": task_id,
        "kind": kind,
        "body": body,
    }))?)
    .to_hex()
    .to_string();
    Ok(MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id,
        command_kind: SemanticCommandKind::ToolObservationRecord,
        input_hash,
        policy_snapshot_id: Some("policy:l10-l12-store-test".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(sequence)),
        created_at: OffsetDateTime::now_utc(),
        scope: "isolated-store-integration".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: vec![ToolObservationInput {
            observation_id: write_id.to_string(),
            tool_name: "eliot_canonical_projection_test".to_owned(),
            observation: format!("persist {kind}"),
            payload: json!({
                "receipt_kind": kind,
                "receipt_body": body,
                "writer_path": "semantic_command_writer_actor",
            }),
        }],
        failures: Vec::new(),
        claims: Vec::new(),
        verification_runs: Vec::new(),
        relations: Vec::new(),
        lifecycle: LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    })
}

fn authority_envelope(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    sequence: u64,
    scope: &str,
    authority: &str,
    tool_name: &str,
    payload: Value,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let mut envelope =
        canonical_envelope(project_id, task_id, sequence, "authority_fixture", &payload)?;
    scope.clone_into(&mut envelope.scope);
    authority.clone_into(&mut envelope.authority);
    tool_name.clone_into(&mut envelope.tool_observations[0].tool_name);
    envelope.tool_observations[0].payload = payload;
    envelope.input_hash = blake3::hash(&serde_json::to_vec(&json!({
        "write_id": envelope.write_id,
        "sequence": sequence,
        "scope": scope,
        "authority": authority,
        "tool_name": tool_name,
        "payload": envelope.tool_observations[0].payload,
    }))?)
    .to_hex()
    .to_string();
    Ok(envelope)
}

fn managed_result_noise_envelope(
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let mut noise = canonical_envelope(
        project_id,
        Some(task_id),
        1,
        "managed_host_launch_result",
        &json!({ "invocation_id": "noise" }),
    )?;
    noise.tool_observations = (1..=257_u16)
        .map(|index| ToolObservationInput {
            observation_id: WriteId::new_v7().to_string(),
            tool_name: "eliot_canonical_projection_test".to_owned(),
            observation: format!("managed result noise {index}"),
            payload: json!({
                "receipt_kind": "managed_host_launch_result",
                "receipt_body": { "invocation_id": format!("noise:{index}") },
            }),
        })
        .collect();
    noise.input_hash = blake3::hash(&serde_json::to_vec(&noise.tool_observations)?)
        .to_hex()
        .to_string();
    Ok(noise)
}

fn managed_result_target_envelope(
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let body = json!({
        "invocation_id": "target:after-256",
        "request_hash": "blake3:target-request",
    });
    let body_hash = format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(&body)?).to_hex()
    );
    authority_envelope(
        project_id,
        Some(task_id),
        2,
        "governed host authority",
        "canonical Eliot host boundary",
        "eliot-governor-host",
        json!({
            "receipt_kind": "managed_host_launch_result",
            "body_hash": body_hash,
            "receipt_body": body,
        }),
    )
}

fn claim_envelope(
    project_id: ProjectId,
    task_id: TaskId,
    claim_id: ClaimId,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let mut envelope =
        canonical_envelope(project_id, Some(task_id), 1, "claim_fixture", &json!({}))?;
    envelope.command_kind = SemanticCommandKind::ClaimPropose;
    envelope.tool_observations.clear();
    envelope.claims = vec![ClaimCardInput {
        claim_id,
        statement: "stale cache must not influence current work".to_owned(),
        status: EpistemicStatus::Candidate,
        payload: json!({ "source": "isolated-test" }),
    }];
    envelope.input_hash = blake3::hash(&serde_json::to_vec(&envelope.claims)?)
        .to_hex()
        .to_string();
    Ok(envelope)
}

async fn persist<T: Serialize>(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    sequence: u64,
    kind: &str,
    body: &T,
) -> Result<MemoryWriteEnvelope, Box<dyn Error>> {
    let envelope = canonical_envelope(project_id, task_id, sequence, kind, body)?;
    let receipt = store.apply_write_envelope(&envelope).await?;
    assert_eq!(receipt.status, WriteStatus::Committed);
    Ok(envelope)
}

#[tokio::test]
// The ordered scenario deliberately spans the full cognitive contract so the same isolated database
// proves cross-contour idempotency, client reconstruction, and scoped retrieval.
#[allow(clippy::too_many_lines)]
async fn canonical_l10_l12_records_are_idempotent_restart_safe_and_bounded()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let other_project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let other_task_id = TaskId::new_v7();
    let claim_id = ClaimId::new_v7();
    store
        .apply_write_envelope(&claim_envelope(project_id, task_id, claim_id)?)
        .await?;

    let transition = MemoryStateTransition {
        transition_id: "transition:suppress-stale-cache".to_owned(),
        project_id,
        target_ref: claim_id.to_string(),
        from_state: MemoryLifecycleState::Active,
        to_state: MemoryLifecycleState::Suppressed,
        operator: ForgettingOperator::Suppress,
        reason: ForgettingReason::Stale,
        policy_ref: "policy:suppress-stale".to_owned(),
        evidence_refs: vec!["verification:stale".to_owned()],
        precondition_refs: vec!["current-truth:v2".to_owned()],
        expected_admission_effect: MemoryEcologyDecision::Suppress,
        reactivation_condition: None,
        reversible: true,
        approval_ref: None,
        performed_by: "governor".to_owned(),
        created_at: OffsetDateTime::now_utc(),
        write_receipt: None,
    };
    let transition_envelope = persist(
        &store,
        project_id,
        Some(task_id),
        2,
        "state_transition",
        &transition,
    )
    .await?;
    let replay_receipt = store.apply_write_envelope(&transition_envelope).await?;
    assert_eq!(replay_receipt.status, WriteStatus::IdempotentReplay);
    assert!(replay_receipt.created_records.contains(&format!(
        "canonical_record:{}",
        transition_envelope.write_id
    )));

    let trajectory = MemoryTrajectoryCorrectness {
        trajectory_id: "trajectory:stale-cache".to_owned(),
        target_ref: claim_id.to_string(),
        transition_refs: vec![transition.transition_id.clone()],
        expected_admission_effect: MemoryEcologyDecision::Suppress,
        observed_admission_effect: MemoryEcologyDecision::Suppress,
        correct: true,
        evidence_refs: vec!["recall:excluded".to_owned()],
        write_receipt: None,
    };
    persist(
        &store,
        project_id,
        Some(task_id),
        3,
        "memory_trajectory_correctness",
        &trajectory,
    )
    .await?;
    let minority = MinorityPressureRecord {
        minority_record_id: "minority:counterexample".to_owned(),
        project_id,
        minority_claim_ref: claim_id.to_string(),
        majority_claim_ref: None,
        why_minority_matters: "prevents over-general suppression".to_owned(),
        discriminative_probe: Some("probe:new-runtime".to_owned()),
        status: MinorityPressureStatus::Open,
        pinned: true,
        release_condition: Some("probe resolved".to_owned()),
        resolved_by_ref: None,
        suppression_forbidden_until: None,
        evidence_refs: vec!["counterexample:1".to_owned()],
        created_at: OffsetDateTime::now_utc(),
        write_receipt: None,
    };
    persist(
        &store,
        project_id,
        Some(task_id),
        4,
        "minority_pressure_record",
        &minority,
    )
    .await?;

    let restarted_store = CanonicalStore::new(config);
    let observations = restarted_store
        .tool_observations_by_kind(project_id, task_id, "state_transition")
        .await?;
    let unfiltered_lifecycle = restarted_store
        .lifecycle_view(project_id, Some(task_id), None, 8)
        .await?;
    assert_eq!(observations.len(), 1);
    assert_eq!(unfiltered_lifecycle.transitions.len(), 1);
    let lifecycle = restarted_store
        .lifecycle_view(project_id, Some(task_id), Some(&claim_id.to_string()), 8)
        .await?;
    assert_eq!(lifecycle.transitions.len(), 1);
    assert_eq!(lifecycle.trajectories.len(), 1);
    assert_eq!(lifecycle.minority_pressure.len(), 1);
    assert!(
        lifecycle.transitions[0]
            .receipt_body
            .write_receipt
            .is_some()
    );
    assert!(
        lifecycle.trajectories[0]
            .receipt_body
            .write_receipt
            .is_some()
    );
    assert!(
        lifecycle.minority_pressure[0]
            .receipt_body
            .write_receipt
            .is_some()
    );
    let recall = restarted_store
        .recall_l0(&RecallL0Request {
            project_id,
            query: "stale cache".to_owned(),
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
            lifecycle_audit: false,
            task_id: None,
            task_class_cues: Vec::new(),
            scope_refs: Vec::new(),
            concept_refs: Vec::new(),
        })
        .await?;
    assert_eq!(recall.handles.len(), 1);
    assert_eq!(
        recall.handles[0].lifecycle_state,
        Some(MemoryLifecycleState::Suppressed)
    );

    let replay_run = ReplayRun {
        replay_run_id: ReplayRunId::new_v7(),
        project_id,
        replay_set_id: ReplaySetId::new_v7(),
        candidate_ref: Some("candidate:v2".to_owned()),
        baseline_ref: Some("baseline:v1".to_owned()),
        run_profile: ReplayRunProfile {
            profile_id: "deterministic-no-mutation".to_owned(),
            deterministic: true,
            no_external_network: true,
            no_mutation: true,
            max_runtime_seconds: 30,
            allowed_services: vec!["report".to_owned()],
        },
        case_results: Vec::new(),
        sealed_input_hash: "sealed-input".to_owned(),
        reproducibility_hash: "reproducible".to_owned(),
        uncertainty: "bounded fixture".to_owned(),
        started_at: OffsetDateTime::now_utc(),
        finished_at: Some(OffsetDateTime::now_utc()),
        status: ReplayRunStatus::Completed,
    };
    persist(
        &restarted_store,
        project_id,
        Some(task_id),
        5,
        "replay_run",
        &replay_run,
    )
    .await?;
    let mut second_run = replay_run.clone();
    second_run.replay_run_id = ReplayRunId::new_v7();
    persist(
        &restarted_store,
        project_id,
        Some(task_id),
        6,
        "replay_run",
        &second_run,
    )
    .await?;
    let replay_audit = ReplayAudit {
        audit_id: "audit:sealed".to_owned(),
        replay_run_id: replay_run.replay_run_id,
        trace_contract_refs: vec!["trace-contract:l9".to_owned()],
        missing_trace_parts: Vec::new(),
        mutation_attempts_blocked: Vec::new(),
        taint_preserved: true,
        authority_mutation_blocked: true,
        created_at: OffsetDateTime::now_utc(),
    };
    persist(
        &restarted_store,
        project_id,
        Some(task_id),
        7,
        "replay_audit",
        &replay_audit,
    )
    .await?;
    let experiment = HarnessExperimentRecord {
        harness_experiment_record_id: HarnessExperimentRecordId::new_v7(),
        eval_run_id: eliot_types::EvalRunId::new_v7(),
        profile_id: "l11".to_owned(),
        verdict_id: None,
        notes: vec!["authorized rejection".to_owned()],
        no_mutation_confirmed: true,
        project_id: Some(project_id),
        candidate_ref: "candidate:v2".to_owned(),
        change_class: MetaCandidateChangeClass::AdmissionRule,
        changed_variables: vec!["admission.weight".to_owned()],
        evaluator_snapshot_ref: "evaluator:v1".to_owned(),
        baseline_policy_hash: "baseline:v1".to_owned(),
        candidate_policy_hash: "candidate:v2".to_owned(),
        fixed_replay_set_ref: "set:fixed".to_owned(),
        holdout_set_ref: "set:holdout".to_owned(),
        replay_run_refs: vec![replay_run.replay_run_id.to_string()],
        holdout_run_refs: vec![second_run.replay_run_id.to_string()],
        primary_metric_refs: vec!["metric:success".to_owned()],
        counter_metric_refs: vec!["metric:false-block".to_owned()],
        reproducibility_hash: "meta-reproducible".to_owned(),
        uncertainty: "none".to_owned(),
        decision: MetaExperimentDecision::Rejected,
        authorized_command_ref: Some("governor-command:meta-disposition:reject".to_owned()),
        rollback_target_ref: "baseline:v1".to_owned(),
        rollback_command_ref: "governor-command:rollback:baseline-v1".to_owned(),
        authoritative_metric_evidence: Vec::new(),
        authoritative_isolation_rejection: None,
        authoritative_policy_candidate: None,
        disposition_receipt: None,
        created_at: OffsetDateTime::now_utc(),
    };
    persist(
        &restarted_store,
        project_id,
        Some(task_id),
        8,
        "harness_disposition",
        &experiment,
    )
    .await?;
    let replay_view = restarted_store
        .replay_view(project_id, Some(task_id), 1)
        .await?;
    assert_eq!(replay_view.replay_runs.len(), 1);
    assert_eq!(replay_view.replay_audits.len(), 1);
    assert_eq!(replay_view.harness_experiments.len(), 1);
    assert_eq!(
        replay_view.replay_runs[0]
            .canonical_receipt
            .write_id
            .to_string(),
        replay_view.replay_runs[0].record_id
    );
    assert!(
        replay_view.harness_experiments[0]
            .receipt_body
            .disposition_receipt
            .is_some()
    );

    for sequence in 9..=10 {
        persist(
            &restarted_store,
            project_id,
            Some(task_id),
            sequence,
            "dream_candidate",
            &json!({
                "dream_candidate_id": format!("dream:{sequence}"),
                "project_id": project_id,
                "source_traces": ["trace:l9"],
                "candidate_only": true,
            }),
        )
        .await?;
    }
    persist(
        &restarted_store,
        project_id,
        Some(other_task_id),
        11,
        "dream_candidate",
        &json!({ "dream_candidate_id": "dream:other-task", "project_id": project_id }),
    )
    .await?;
    persist(
        &restarted_store,
        other_project_id,
        Some(task_id),
        1,
        "dream_candidate",
        &json!({ "dream_candidate_id": "dream:other-project", "project_id": other_project_id }),
    )
    .await?;
    let candidates = restarted_store
        .sleep_candidates(project_id, Some(task_id), 1)
        .await?;
    assert_eq!(candidates.candidates.len(), 1);
    assert!(candidates.truncation.truncated);
    assert!(candidates.candidates[0].receipt_body["candidate_only"] == Value::Bool(true));
    assert_eq!(
        candidates.candidates[0]
            .canonical_receipt
            .write_id
            .to_string(),
        candidates.candidates[0].record_id
    );

    let autonomy_run_id = "autonomy:isolated";
    let contract = AutonomyRunContract {
        autonomy_run_id: autonomy_run_id.to_owned(),
        project_id,
        root_task_id: task_id,
        user_goal: "bounded canonical store proof".to_owned(),
        acceptance_items: vec!["store survives restart".to_owned()],
        contour_route_policy_ref: "route-policy:v1".to_owned(),
        allowed_projects: vec![project_id],
        max_work_items: 2,
        max_active_agents: 2,
        max_model_invocations: 4,
        max_tool_calls: 8,
        max_wall_time_seconds: 300,
        cost_or_token_budget: Some("1000".to_owned()),
        allowed_paths: vec!["crates/eliot-store".to_owned()],
        forbidden_paths: vec!["history.txt".to_owned()],
        forbidden_effects: vec!["service_cutover".to_owned()],
        allowed_risk_tiers: vec!["R0".to_owned(), "R1".to_owned()],
        required_verifiers: vec!["cargo test".to_owned()],
        approval_boundaries: Vec::new(),
        pause_conditions: vec!["tripwire".to_owned()],
        stop_conditions: vec!["budget".to_owned()],
        fallback_routes: Vec::new(),
        recovery_policy_ref: "recovery:v1".to_owned(),
        policy_snapshot_id: "policy:v1".to_owned(),
        created_by: "controller".to_owned(),
        state: AutonomyRunState::Running,
        state_revision: 1,
        created_at: OffsetDateTime::now_utc(),
    };
    persist(
        &restarted_store,
        project_id,
        Some(task_id),
        12,
        "autonomy_run_contract",
        &contract,
    )
    .await?;
    let transition = AutonomyRunTransitionReceipt {
        transition_id: "autonomy-transition:running".to_owned(),
        autonomy_run_id: autonomy_run_id.to_owned(),
        from: AutonomyRunState::Ready,
        to: AutonomyRunState::Running,
        state_revision: 1,
        reason: "start bounded work".to_owned(),
        risk_tier: "R1".to_owned(),
        exact_approval_hash: None,
        verifier_refs: Vec::new(),
        transitioned_at: OffsetDateTime::now_utc(),
        canonical_receipt: None,
    };
    persist(
        &restarted_store,
        project_id,
        Some(task_id),
        13,
        "autonomy_run_transition",
        &transition,
    )
    .await?;
    for (sequence, kind, body) in [
        (
            14,
            "autonomy_budget_ledger",
            json!({ "autonomy_run_id": autonomy_run_id, "revision": 1, "tool_calls": 2 }),
        ),
        (
            15,
            "autonomy_work_graph",
            json!({ "autonomy_run_id": autonomy_run_id, "work_items": ["work:1"] }),
        ),
        (
            16,
            "autonomy_tripwire",
            json!({ "autonomy_run_id": autonomy_run_id, "tripwire_id": "tripwire:1", "kind": "no_novelty" }),
        ),
        (
            17,
            "autonomy_recovery",
            json!({ "autonomy_run_id": autonomy_run_id, "recovery_id": "recovery:1", "action": "reassign" }),
        ),
    ] {
        persist(
            &restarted_store,
            project_id,
            Some(task_id),
            sequence,
            kind,
            &body,
        )
        .await?;
    }
    let autonomy = restarted_store
        .autonomy_run_view(project_id, task_id, autonomy_run_id, 8)
        .await?;
    assert!(autonomy.contract.is_some());
    assert_eq!(
        autonomy
            .contract
            .as_ref()
            .map(|record| record.receipt_body.autonomy_run_id.as_str()),
        Some(autonomy_run_id)
    );
    assert_eq!(autonomy.transitions.len(), 1);
    assert!(
        autonomy.transitions[0]
            .receipt_body
            .canonical_receipt
            .is_some()
    );
    assert_eq!(autonomy.budget_ledgers.len(), 1);
    assert_eq!(autonomy.work_graphs.len(), 1);
    assert_eq!(autonomy.tripwires.len(), 1);
    assert_eq!(autonomy.recoveries.len(), 1);
    Ok(())
}

fn physical_restart_transition(project_id: ProjectId, subject_ref: &str) -> MemoryStateTransition {
    MemoryStateTransition {
        transition_id: "transition:physical-restart".to_owned(),
        project_id,
        target_ref: subject_ref.to_owned(),
        from_state: MemoryLifecycleState::Active,
        to_state: MemoryLifecycleState::Suppressed,
        operator: ForgettingOperator::Suppress,
        reason: ForgettingReason::Stale,
        policy_ref: "policy:physical-restart".to_owned(),
        evidence_refs: vec!["verification:physical-restart".to_owned()],
        precondition_refs: vec!["rocksdb:durable".to_owned()],
        expected_admission_effect: MemoryEcologyDecision::Suppress,
        reactivation_condition: None,
        reversible: true,
        approval_ref: None,
        performed_by: "restart-test".to_owned(),
        created_at: OffsetDateTime::now_utc(),
        write_receipt: None,
    }
}

fn physical_restart_replay(project_id: ProjectId) -> ReplayRun {
    ReplayRun {
        replay_run_id: ReplayRunId::new_v7(),
        project_id,
        replay_set_id: ReplaySetId::new_v7(),
        candidate_ref: Some("candidate:physical-restart".to_owned()),
        baseline_ref: Some("baseline:physical-restart".to_owned()),
        run_profile: ReplayRunProfile {
            profile_id: "physical-restart".to_owned(),
            deterministic: true,
            no_external_network: true,
            no_mutation: true,
            max_runtime_seconds: 30,
            allowed_services: Vec::new(),
        },
        case_results: Vec::new(),
        sealed_input_hash: "sealed:physical-restart".to_owned(),
        reproducibility_hash: "reproducible:physical-restart".to_owned(),
        uncertainty: "none".to_owned(),
        started_at: OffsetDateTime::now_utc(),
        finished_at: Some(OffsetDateTime::now_utc()),
        status: ReplayRunStatus::Completed,
    }
}

fn physical_restart_contract(
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &str,
) -> AutonomyRunContract {
    AutonomyRunContract {
        autonomy_run_id: autonomy_run_id.to_owned(),
        project_id,
        root_task_id: task_id,
        user_goal: "prove RocksDB durability across process replacement".to_owned(),
        acceptance_items: vec!["new process reads canonical state".to_owned()],
        contour_route_policy_ref: "route-policy:physical-restart".to_owned(),
        allowed_projects: vec![project_id],
        max_work_items: 1,
        max_active_agents: 1,
        max_model_invocations: 1,
        max_tool_calls: 4,
        max_wall_time_seconds: 60,
        cost_or_token_budget: None,
        allowed_paths: vec!["crates/eliot-store/tests".to_owned()],
        forbidden_paths: vec!["history.txt".to_owned()],
        forbidden_effects: vec!["live_store_mutation".to_owned()],
        allowed_risk_tiers: vec!["R0".to_owned()],
        required_verifiers: vec!["physical_restart".to_owned()],
        approval_boundaries: Vec::new(),
        pause_conditions: Vec::new(),
        stop_conditions: vec!["durability_verified".to_owned()],
        fallback_routes: Vec::new(),
        recovery_policy_ref: "recovery:physical-restart".to_owned(),
        policy_snapshot_id: "policy:physical-restart".to_owned(),
        created_by: "restart-test".to_owned(),
        state: AutonomyRunState::Running,
        state_revision: 1,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn pre_exact_lookup_trace(
    project_id: ProjectId,
    task_id: TaskId,
    trace_ref: &str,
) -> CanonicalTraceCompletenessContract {
    CanonicalTraceCompletenessContract {
        contract_id: "trace-contract:pre-exact-lookup-upgrade".to_owned(),
        project_id,
        task_id,
        source_task_revision: MemoryRevision::new(7),
        trace_ref: trace_ref.to_owned(),
        evidence: Vec::new(),
        evidence_manifest_hash: "legacy-exact-lookup-evidence".to_owned(),
        replay_allowed: true,
        rejected_reasons: Vec::new(),
        created_at: OffsetDateTime::now_utc(),
    }
}

fn pre_exact_lookup_action(candidate_id: &str) -> MetaPolicyExecutionReceipt {
    MetaPolicyExecutionReceipt {
        execution_id: "meta-policy-promotion:pre-exact-lookup-upgrade".to_owned(),
        candidate_id: candidate_id.to_owned(),
        operator_command_ref: "operator-command:pre-exact-lookup-upgrade".to_owned(),
        action: MetaPolicyExecutionAction::Promote,
        before_hash: "legacy-before".to_owned(),
        after_hash: "legacy-after".to_owned(),
        rollback_target_hash: "legacy-before".to_owned(),
        exact_action_hash: "legacy-exact-action".to_owned(),
        active_policy: ExperimentalMetaPolicyPayload::Unsupported {
            kind: "pre_exact_lookup_upgrade".to_owned(),
            payload: json!({"bounded": true}),
        },
        resulting_candidate: None,
        executed_at: OffsetDateTime::now_utc(),
    }
}

struct PreExactLookupFixture {
    trace_ref: &'static str,
    candidate_id: &'static str,
}

async fn seed_pre_exact_lookup_fixture(
    store: &CanonicalStore,
    config: &SurrealServerConfig,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<PreExactLookupFixture, Box<dyn Error>> {
    let fixture = PreExactLookupFixture {
        trace_ref: "trace:pre-exact-lookup-upgrade",
        candidate_id: "candidate:pre-exact-lookup-upgrade",
    };
    let trace_envelope = persist(
        store,
        project_id,
        Some(task_id),
        4,
        "trace_completeness_contract",
        &pre_exact_lookup_trace(project_id, task_id, fixture.trace_ref),
    )
    .await?;
    let action_envelope = persist(
        store,
        project_id,
        Some(task_id),
        5,
        "meta_policy_promotion",
        &pre_exact_lookup_action(fixture.candidate_id),
    )
    .await?;
    strip_materialized_exact_fields(
        config,
        &[
            trace_envelope.write_id.to_string(),
            action_envelope.write_id.to_string(),
        ],
    )?;
    Ok(fixture)
}

async fn assert_pre_exact_lookup_authority(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    fixture: &PreExactLookupFixture,
) -> Result<(), Box<dyn Error>> {
    assert!(
        store
            .canonical_trace_by_trace_ref(project_id, task_id, fixture.trace_ref)
            .await?
            .is_some(),
        "pre-exact-lookup trace must remain exact-query visible"
    );
    assert_eq!(
        store
            .meta_policy_actions_by_candidate(
                project_id,
                task_id,
                fixture.candidate_id,
                MetaPolicyExecutionAction::Promote,
            )
            .await?
            .len(),
        1,
        "pre-exact-lookup terminal action must remain exact-query visible"
    );
    Ok(())
}

// The exact process identities are acceptance evidence for this test, so the
// normally forbidden stderr output is intentionally restricted to this helper.
#[allow(clippy::print_stderr)]
fn report_physical_restart_evidence(
    first_pid: u32,
    second_pid: u32,
    transition_count: usize,
    replay_count: usize,
    autonomy_preserved: bool,
    temp_root_removed: bool,
) {
    eprintln!(
        "{}",
        json!({
            "component": "physical_surreal_restart_canonical_store",
            "first_pid": first_pid,
            "second_pid": second_pid,
            "same_rocksdb_root": true,
            "same_endpoint": true,
            "idempotent_replay": true,
            "canonical_transition_count": transition_count,
            "replay_run_count": replay_count,
            "autonomy_contract_preserved": autonomy_preserved,
            "temp_root_removed": temp_root_removed,
            "host_configuration_changes": 0,
        })
    );
}

async fn persist_physical_restart_baseline(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    subject_ref: &str,
    autonomy_run_id: &str,
) -> Result<MemoryWriteEnvelope, Box<dyn Error>> {
    let transition = canonical_envelope(
        project_id,
        Some(task_id),
        1,
        "state_transition",
        &physical_restart_transition(project_id, subject_ref),
    )?;
    assert_eq!(
        store.apply_write_envelope(&transition).await?.status,
        WriteStatus::Committed
    );
    persist(
        store,
        project_id,
        Some(task_id),
        2,
        "replay_run",
        &physical_restart_replay(project_id),
    )
    .await?;
    persist(
        store,
        project_id,
        Some(task_id),
        3,
        "autonomy_run_contract",
        &physical_restart_contract(project_id, task_id, autonomy_run_id),
    )
    .await?;
    Ok(transition)
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn physical_surreal_restart_preserves_canonical_l10_l12_records() -> Result<(), Box<dyn Error>>
{
    let mut root = RestartTestRoot::new()?;
    let port = free_local_port()?;
    let config = root.config(port)?;
    let first_server = SurrealServerSupervisor::new(config.clone())
        .start_or_connect()
        .await?;
    let first_pid = first_server
        .started_pid()
        .ok_or("restart-test supervisor did not own the first process")?;

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let subject_ref = "claim:physical-restart";
    let autonomy_run_id = "autonomy:physical-restart";
    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;

    let transition_envelope = persist_physical_restart_baseline(
        &store,
        project_id,
        task_id,
        subject_ref,
        autonomy_run_id,
    )
    .await?;
    let pre_exact_lookup =
        seed_pre_exact_lookup_fixture(&store, &config, project_id, task_id).await?;
    assert_pre_exact_lookup_authority(&store, project_id, task_id, &pre_exact_lookup).await?;

    drop(store);
    assert!(
        first_server
            .shutdown_if_spawned()
            .await?
            .stopped_owned_process
    );
    let second_server = SurrealServerSupervisor::new(config.clone())
        .start_or_connect()
        .await?;
    let second_pid = second_server
        .started_pid()
        .ok_or("restart-test supervisor did not own the second process")?;
    assert_ne!(first_pid, second_pid);

    let restarted_store = CanonicalStore::new(config);
    restarted_store.migrate_schema().await?;
    let replayed = restarted_store
        .apply_write_envelope(&transition_envelope)
        .await?;
    assert_eq!(replayed.status, WriteStatus::IdempotentReplay);
    assert_eq!(replayed.write_id, transition_envelope.write_id);

    let lifecycle = restarted_store
        .lifecycle_view(project_id, Some(task_id), Some(subject_ref), 8)
        .await?;
    assert_eq!(lifecycle.transitions.len(), 1);
    assert_eq!(
        lifecycle.transitions[0].record_id,
        transition_envelope.write_id.to_string()
    );
    assert!(
        lifecycle.transitions[0]
            .receipt_body
            .write_receipt
            .is_some()
    );

    let replay = restarted_store
        .replay_view(project_id, Some(task_id), 8)
        .await?;
    assert_eq!(replay.replay_runs.len(), 1);
    let autonomy = restarted_store
        .autonomy_run_view(project_id, task_id, autonomy_run_id, 8)
        .await?;
    assert_eq!(
        autonomy
            .contract
            .as_ref()
            .map(|record| record.receipt_body.autonomy_run_id.as_str()),
        Some(autonomy_run_id)
    );
    assert_pre_exact_lookup_authority(&restarted_store, project_id, task_id, &pre_exact_lookup)
        .await?;

    drop(restarted_store);
    assert!(
        second_server
            .shutdown_if_spawned()
            .await?
            .stopped_owned_process
    );
    let removed_root = root.remove()?;
    assert!(!removed_root.exists());
    report_physical_restart_evidence(
        first_pid,
        second_pid,
        lifecycle.transitions.len(),
        replay.replay_runs.len(),
        autonomy.contract.is_some(),
        !removed_root.exists(),
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires an authenticated local SurrealDB"]
async fn exact_result_and_latest_authority_queries_survive_bounded_history()
-> Result<(), Box<dyn Error>> {
    let mut root = RestartTestRoot::new()?;
    let config = root.config(free_local_port()?)?;
    let server = SurrealServerSupervisor::new(config.clone())
        .start_or_connect()
        .await?;
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();

    let noise = managed_result_noise_envelope(project_id, task_id)?;
    assert_eq!(
        store.apply_write_envelope(&noise).await?.status,
        WriteStatus::Committed
    );
    let target = managed_result_target_envelope(project_id, task_id)?;
    let target_receipt = store.apply_write_envelope(&target).await?;
    assert_eq!(
        target_receipt.command_kind,
        SemanticCommandKind::ToolObservationRecord
    );
    assert!(
        target_receipt
            .created_records
            .iter()
            .any(|record| record == &target.write_id.to_string())
    );
    let bounded = store
        .tool_observations_by_kind(project_id, task_id, "managed_host_launch_result")
        .await?;
    assert_eq!(bounded.len(), 256);
    assert!(
        bounded
            .iter()
            .all(|entry| entry.observation_id != target.write_id.to_string())
    );
    let exact = store
        .tool_observations_by_write_id(&target.write_id)
        .await?;
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].write_id, target.write_id);

    let lease_id = eliot_types::WorkLeaseId::new_v7();
    let active = authority_envelope(
        project_id,
        Some(task_id),
        3,
        "work/work-lease",
        "eliot-work-coordination-service",
        "eliot_work_coordination",
        json!({ "work_lease": { "work_lease_id": lease_id, "state": "granted" } }),
    )?;
    store.apply_write_envelope(&active).await?;
    let active_exact = store
        .tool_observations_by_write_id(&active.write_id)
        .await?;
    assert_eq!(active_exact.len(), 1);
    assert_eq!(
        active_exact[0].payload["work_lease"]["work_lease_id"],
        lease_id.to_string()
    );
    let revoked = authority_envelope(
        project_id,
        Some(task_id),
        4,
        "work/work-lease",
        "eliot-work-coordination-service",
        "eliot_work_coordination",
        json!({ "work_lease": { "work_lease_id": lease_id, "state": "revoked" } }),
    )?;
    store.apply_write_envelope(&revoked).await?;
    let latest = store
        .latest_authority_observations_by_entity(
            project_id,
            Some(task_id),
            "work_lease",
            &lease_id.to_string(),
        )
        .await?;
    assert_eq!(latest.len(), 2);
    assert_eq!(latest[0].write_id, revoked.write_id);
    assert_eq!(latest[0].payload["work_lease"]["state"], "revoked");

    let finalization_id = "managed-finalization:exact-subject";
    for (sequence, kind) in [
        (5, "managed_finalization_intent"),
        (6, "managed_finalization_aggregate"),
    ] {
        let envelope = canonical_envelope(
            project_id,
            Some(task_id),
            sequence,
            kind,
            &json!({
                "finalization_id": finalization_id,
                "target_ref": "wrong-generic-subject",
                "schema_version": format!("{kind}-v1")
            }),
        )?;
        let receipt = store.apply_write_envelope(&envelope).await?;
        assert_eq!(receipt.status, WriteStatus::Committed);
        let exact = store
            .canonical_record_by_write_id::<Value>(
                project_id,
                Some(task_id),
                &[kind],
                envelope.write_id,
            )
            .await?
            .ok_or("finalization canonical allowlist did not materialize the exact record")?;
        assert_eq!(exact.subject_ref, finalization_id);
        assert_eq!(exact.receipt_body["finalization_id"], finalization_id);
    }
    let finalization_latest = store
        .latest_authority_observations_by_entity(
            project_id,
            Some(task_id),
            "managed_finalization",
            finalization_id,
        )
        .await?;
    assert_eq!(finalization_latest.len(), 2);
    assert_eq!(
        finalization_latest[0].payload["receipt_kind"],
        "managed_finalization_aggregate"
    );

    drop(store);
    assert!(server.shutdown_if_spawned().await?.stopped_owned_process);
    let removed_root = root.remove()?;
    assert!(!removed_root.exists());
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn authenticated_canonical_blob_reference_scan_is_complete_and_evidence_bound()
-> Result<(), Box<dyn Error>> {
    let mut root = RestartTestRoot::new()?;
    let port = free_local_port()?;
    let config = root.config(port)?;
    let server = SurrealServerSupervisor::new(config.clone())
        .start_or_connect()
        .await?;
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let blob_hash = blake3::hash(b"canonical-blob-reference")
        .to_hex()
        .to_string();
    let body = json!({
        "retention_class": "legal_hold",
        "result_blob": {
            "algorithm": "blake3",
            "digest_hex": blob_hash,
            "size_bytes": 24,
            "relative_path": "aa/canonical-blob-reference.blob"
        }
    });
    persist(
        &store,
        project_id,
        Some(task_id),
        1,
        "autonomy_work_graph",
        &body,
    )
    .await?;

    let snapshot = store
        .blob_reference_snapshot("C:/isolated/eliot/blobs", 128)
        .await?;
    assert!(snapshot.complete);
    assert!(!snapshot.snapshot_id.is_empty());
    assert!(!snapshot.source_revision.is_empty());
    assert!(!snapshot.query_hash.is_empty());
    assert!(snapshot.records_scanned > 0);
    assert!(
        snapshot
            .reachable_refs
            .iter()
            .any(|reference| reference.blob_hash == blob_hash
                && !reference.canonical_record_ref.is_empty())
    );
    assert!(
        snapshot
            .retention_refs
            .iter()
            .any(|reference| reference.blob_hash == blob_hash
                && matches!(
                    reference.retention,
                    eliot_types::BlobRetentionClass::LegalHold
                ))
    );

    drop(store);
    assert!(server.shutdown_if_spawned().await?.stopped_owned_process);
    let removed_root = root.remove()?;
    assert!(!removed_root.exists());
    Ok(())
}

#[tokio::test]
async fn canonical_receipt_body_preserves_arbitrary_json_scalars() -> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let subject_refs = [
        "memory:operator-runtime-proof",
        "018fdb63-42f1-7d85-a952-0f8f9169d07c",
        "C:\\Profiles\\Fixture\\AppData\\Local\\Eliot\\proof-file.json",
        "https://example.test/runtime-proof?case=a-b#fragment",
        "sha256:abc-def-0123456789",
    ];
    for (index, target_ref) in subject_refs.iter().enumerate() {
        let transition_envelope = canonical_envelope(
            project_id,
            Some(task_id),
            u64::try_from(index)? + 1,
            "state_transition",
            &physical_restart_transition(project_id, target_ref),
        )?;
        assert_eq!(
            store
                .apply_write_envelope(&transition_envelope)
                .await?
                .status,
            WriteStatus::Committed
        );
        assert_eq!(
            store
                .apply_write_envelope(&transition_envelope)
                .await?
                .status,
            WriteStatus::IdempotentReplay
        );
        let lifecycle = store
            .lifecycle_view(project_id, Some(task_id), Some(target_ref), 8)
            .await?;
        assert_eq!(lifecycle.transitions.len(), 1);
        assert_eq!(
            lifecycle.transitions[0].receipt_body.target_ref,
            *target_ref
        );
    }

    let autonomy_run_id = "autonomy:operator-runtime-proof";
    let body = json!({
        "autonomy_run_id": autonomy_run_id,
        "colon_hyphen": "memory:operator-runtime-proof",
        "uuid_looking": "018fdb63-42f1-7d85-a952-0f8f9169d07c",
        "windows_path": "C:\\Profiles\\Fixture\\AppData\\Local\\Eliot\\proof-file.json",
        "url": "https://example.test/runtime-proof?case=a-b#fragment",
        "exact_approval_hash": "sha256:abc-def-0123456789",
        "enum_string": "blocked_by_approval",
        "unicode": "Память:оператор-готов ✅\nnext\tfield",
        "large_integer": 9_007_199_254_740_993_i64,
        "array": [
            "memory:operator-runtime-proof",
            "https://example.test/a-b",
            "C:\\Temp\\a-b.json",
            null,
            true,
            -42,
            12.5
        ],
        "nested": {
            "colon_hyphen": "record:segment-with-hyphen",
            "values": ["ready", {"deep": "approval:hash-with-hyphen"}]
        }
    });
    let envelope = canonical_envelope(
        project_id,
        Some(task_id),
        6,
        "autonomy_budget_ledger",
        &body,
    )?;
    assert_eq!(
        store.apply_write_envelope(&envelope).await?.status,
        WriteStatus::Committed
    );
    assert_eq!(
        store.apply_write_envelope(&envelope).await?.status,
        WriteStatus::IdempotentReplay
    );
    let view = store
        .autonomy_run_view(project_id, task_id, autonomy_run_id, 8)
        .await?;
    assert_eq!(view.budget_ledgers.len(), 1);
    assert_eq!(view.budget_ledgers[0].receipt_body, body);
    Ok(())
}

#[tokio::test]
async fn canonical_claim_lookup_resolves_exact_candidate_and_project_scope()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let other_project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let claim_id = ClaimId::new_v7();
    let mut envelope = canonical_envelope(
        project_id,
        Some(task_id),
        1,
        "candidate_claim_lookup",
        &json!({ "claim_id": claim_id }),
    )?;
    envelope.command_kind = SemanticCommandKind::ClaimPropose;
    envelope.claims.push(ClaimCardInput {
        claim_id,
        statement: "exact candidate lookup proof".to_owned(),
        status: EpistemicStatus::Candidate,
        payload: json!({
            "candidate_only": true,
            "controller_reconciliation_required": true,
            "provenance_refs": ["verification:store-proof"]
        }),
    });
    envelope.input_hash = blake3::hash(&serde_json::to_vec(&envelope.claims)?)
        .to_hex()
        .to_string();
    assert_eq!(
        store.apply_write_envelope(&envelope).await?.status,
        WriteStatus::Committed
    );

    let candidate = store
        .claim_card_by_id(project_id, claim_id)
        .await?
        .ok_or("exact candidate did not resolve")?;
    assert_eq!(candidate.project_id, project_id);
    assert_eq!(candidate.task_id, Some(task_id));
    assert_eq!(candidate.claim_id, claim_id);
    assert_eq!(candidate.status, EpistemicStatus::Candidate);
    assert_eq!(candidate.write_id, envelope.write_id);
    assert!(
        store
            .claim_card_by_id(other_project_id, claim_id)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn canonical_operator_paging_survives_restart_without_gaps_or_duplicates()
-> Result<(), Box<dyn Error>> {
    let mut root = RestartTestRoot::new()?;
    let port = free_local_port()?;
    let config = root.config(port)?;
    let first_server = SurrealServerSupervisor::new(config.clone())
        .start_or_connect()
        .await?;
    let first_store = CanonicalStore::new(config.clone());
    first_store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let expected = seed_operator_page_records(&first_store, project_id, task_id, 311).await?;
    let mut pages = vec![
        first_store
            .canonical_record_page(
                project_id,
                Some(task_id),
                &["operator_control_request"],
                0,
                100,
            )
            .await?,
        first_store
            .canonical_record_page(
                project_id,
                Some(task_id),
                &["operator_control_request"],
                100,
                100,
            )
            .await?,
    ];
    drop(first_store);
    assert!(
        first_server
            .shutdown_if_spawned()
            .await?
            .stopped_owned_process
    );

    let second_server = SurrealServerSupervisor::new(config.clone())
        .start_or_connect()
        .await?;
    let restarted_store = CanonicalStore::new(config);
    restarted_store.migrate_schema().await?;
    pages.push(
        restarted_store
            .canonical_record_page(
                project_id,
                Some(task_id),
                &["operator_control_request"],
                200,
                100,
            )
            .await?,
    );
    pages.push(
        restarted_store
            .canonical_record_page(
                project_id,
                Some(task_id),
                &["operator_control_request"],
                300,
                100,
            )
            .await?,
    );

    let page_sizes = pages.iter().map(Vec::len).collect::<Vec<_>>();
    assert_eq!(page_sizes, [100, 100, 100, 11]);
    let actual = pages
        .into_iter()
        .flatten()
        .map(|record| record.record_id)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert_eq!(
        actual
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        311
    );
    drop(restarted_store);
    assert!(
        second_server
            .shutdown_if_spawned()
            .await?
            .stopped_owned_process
    );
    let removed_root = root.remove()?;
    assert!(!removed_root.exists());
    Ok(())
}
