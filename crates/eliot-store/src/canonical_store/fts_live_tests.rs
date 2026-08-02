use super::CanonicalStore;
use crate::DbClientSet;
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, CredentialProviderKind, EpistemicStatus, GovernorConfig,
    IdempotencyOptions, LifecycleStatus, LifecycleWriteOptions, MemoryConfidence,
    MemoryWriteEnvelope, OperationId, ProjectId, ProjectSequence, ReadConsistencyMode,
    RecallL0Request, RecallL0Response, SemanticCommandKind, SurrealServerConfig, TaintClass,
    TaskId, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use time::OffsetDateTime;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/run-isolated-tests.ps1 SurrealDB 3.1.4 guardian"]
async fn c7_03b_real_fts_candidates_rank_five_provider_free_cases() -> TestResult {
    let config = isolated_config()?;
    require_exact_surreal_version(&config)?;
    let owned_pid = guardian_pid(&config)?;
    require(
        eliot_windows_ipc::process_is_alive(owned_pid)?,
        "the isolated SurrealDB guardian is not alive",
    )?;

    let clients = Arc::new(DbClientSet::start(config).await?);
    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let body_result = run_five_cases(&store).await;
    let shutdown_result = clients.shutdown().await;

    match (body_result, shutdown_result) {
        (Ok(()), Ok(_)) => require(
            eliot_windows_ipc::process_is_alive(owned_pid)?,
            "DbClientSet shutdown stopped the external isolated guardian",
        ),
        (Err(body_error), Ok(_)) => Err(body_error),
        (Ok(()), Err(shutdown_error)) => Err(Box::new(shutdown_error) as Box<dyn Error>),
        (Err(body_error), Err(shutdown_error)) => Err(format!(
            "FTS live proof failed: {body_error}; explicit DbClientSet shutdown also failed: {shutdown_error}"
        )
        .into()),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_five_cases(store: &CanonicalStore) -> TestResult {
    store.migrate_schema().await?;
    assert_bound_typed_fts_route()?;

    let project_id = ProjectId::new_v7();
    let foreign_project_id = ProjectId::new_v7();

    let foreign_claims = (0..260)
        .map(|ordinal| {
            claim(
                format!("shared project isolation marker foreign distractor {ordinal:03}"),
                "project-isolation-foreign",
            )
        })
        .collect::<Vec<_>>();
    let foreign_handles = foreign_claims
        .iter()
        .map(|item| format!("claim:{}", item.claim_id))
        .collect::<HashSet<_>>();
    require(
        foreign_handles.len() > 257,
        "project-isolation corpus must contain more than 257 foreign same-term rows",
    )?;

    let mut local_claims = (0..32)
        .map(|ordinal| {
            claim(
                format!("english retrieval needle distractor {ordinal:02}"),
                "english-distractor",
            )
        })
        .collect::<Vec<_>>();
    let english_target = claim(
        "english unique retrieval needle alpha omega".to_owned(),
        "english-target",
    );
    let unicode_target = claim(
        "Русская память находит Юникод границу библиотекаря".to_owned(),
        "unicode-target",
    );
    let opaque_target = claim(
        "opaque exact handle target".to_owned(),
        "opaque-handle-target",
    );
    let local_isolation_target = claim(
        "shared project isolation marker local authoritative hit".to_owned(),
        "project-isolation-local",
    );
    let english_handle = format!("claim:{}", english_target.claim_id);
    let unicode_handle = format!("claim:{}", unicode_target.claim_id);
    let opaque_handle = format!("claim:{}", opaque_target.claim_id);
    let local_isolation_handle = format!("claim:{}", local_isolation_target.claim_id);
    local_claims.extend([
        english_target,
        unicode_target,
        opaque_target,
        local_isolation_target,
    ]);

    let foreign_receipt = store
        .apply_write_envelope(&retrieval_envelope(
            foreign_project_id,
            TaskId::new_v7(),
            foreign_claims,
        )?)
        .await?;
    require(
        foreign_receipt.status == WriteStatus::Committed,
        "foreign project corpus did not commit through the canonical typed write path",
    )?;
    let local_receipt = store
        .apply_write_envelope(&retrieval_envelope(
            project_id,
            TaskId::new_v7(),
            local_claims,
        )?)
        .await?;
    require(
        local_receipt.status == WriteStatus::Committed,
        "local project corpus did not commit through the canonical typed write path",
    )?;

    store
        .rebuild_memory_search_projection(foreign_project_id)
        .await?;
    store.rebuild_memory_search_projection(project_id).await?;

    let plan = store
        .memory_search_fts_query_plan(project_id, "english unique retrieval needle alpha omega")
        .await?;
    let plan_text = serde_json::to_string(&plan)?;
    require(
        plan_text.contains("FullTextScan"),
        "SurrealDB EXPLAIN did not select FullTextScan",
    )?;
    require(
        plan_text.contains("idx_memory_search_projection_fts_v1"),
        "SurrealDB EXPLAIN did not select idx_memory_search_projection_fts_v1",
    )?;

    // Case 1: the complete English target must outrank same-corpus distractors.
    let english = store
        .recall_l0_fts_candidate(&recall_request(
            project_id,
            "english unique retrieval needle alpha omega",
        ))
        .await?;
    require_top_handle(&english, &english_handle, "English target")?;

    // Case 2: the production FTS path must retain Unicode terms end to end.
    let unicode = store
        .recall_l0_fts_candidate(&recall_request(
            project_id,
            "Русская память Юникод библиотекаря",
        ))
        .await?;
    require_top_handle(&unicode, &unicode_handle, "Unicode target")?;

    // Case 3: an opaque exact handle bypasses lexical ambiguity and ranks first.
    let opaque = store
        .recall_l0_fts_candidate(&recall_request(project_id, opaque_handle.clone()))
        .await?;
    require_top_handle(&opaque, &opaque_handle, "opaque exact handle")?;
    require(
        opaque
            .rank_trace
            .feature_scores
            .first()
            .is_some_and(|score| score.exact_identifier == 1_000),
        "opaque exact handle did not receive the exact-identifier rank feature",
    )?;

    // Case 4: both an empty normalized term set and a genuine miss are explicit no-memory.
    for (label, query) in [
        ("no normalized terms", "the and or"),
        ("no FTS hit", "quasar telemetry absent"),
    ] {
        let response = store
            .recall_l0_fts_candidate(&recall_request(project_id, query))
            .await?;
        require(
            response.handles.is_empty()
                && response.rank_trace.no_useful_memory
                && response.memory_confidence == MemoryConfidence::None,
            &format!("{label} did not return the explicit no_useful_memory result"),
        )?;
    }

    // Case 5: >257 foreign same-term rows cannot consume the local project's FTS cap.
    let isolated = store
        .recall_l0_fts_candidate(&recall_request(
            project_id,
            "shared project isolation marker",
        ))
        .await?;
    require_top_handle(
        &isolated,
        &local_isolation_handle,
        "project-isolated local hit",
    )?;
    require(
        isolated.rank_trace.candidates_considered <= 256,
        "FTS candidate loader exceeded the 256-row bound",
    )?;
    require(
        isolated
            .handles
            .iter()
            .all(|item| !foreign_handles.contains(&item.handle)),
        "foreign-project FTS rows leaked into the local result",
    )?;

    Ok(())
}

fn assert_bound_typed_fts_route() -> TestResult {
    let query = include_str!("../surql/load_memory_search_fts_candidates.surql");
    require(
        query.contains("search_document @OR@ $query_text"),
        "FTS loader must bind query_text in the checked-in SurQL template",
    )?;

    let source = include_str!("../canonical_store.rs");
    let Some(route_start) = source.find("async fn recall_l0_fts_candidate") else {
        return Err("recall_l0_fts_candidate source anchor is missing".into());
    };
    let route_tail = &source[route_start..];
    let Some(route_end) = route_tail.find("\n    async fn recall_l0_paged") else {
        return Err("recall_l0_fts_candidate end anchor is missing".into());
    };
    let route = &route_tail[..route_end];
    require(
        route.contains("NamedSurqlOp::LoadMemorySearchFtsCandidates")
            && route.contains("\"query_text\": memory_search_query_text(request)")
            && route.contains(".execute_value("),
        "FTS candidate route must use the typed named operation with bound variables",
    )?;
    require(
        !route.contains("execute_admin_sql") && !route.contains("execute_classified"),
        "FTS candidate route must not execute raw SQL",
    )
}

fn isolated_config() -> TestResult<SurrealServerConfig> {
    require(
        std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() == Ok("1"),
        "ELIOT_DISABLE_REAL_PROVIDER=1 is required for this provider-free live proof",
    )?;
    let mut config = GovernorConfig::default().db.surreal;
    config.exe = required_env("ELIOT_SURREAL_EXE")?;
    config.bind = required_env("ELIOT_TEST_SURREAL_BIND")?;
    config.endpoint = required_env("ELIOT_TEST_SURREAL_ENDPOINT")?;
    config.password_file = required_env("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    config.storage = required_env("ELIOT_TEST_SURREAL_STORAGE")?;
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    config.query_timeout_ms = 20_000;
    config.startup_timeout_ms = 20_000;
    Ok(config)
}

fn require_exact_surreal_version(config: &SurrealServerConfig) -> TestResult {
    let output = Command::new(&config.exe).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    require(
        output.status.success() && version.split_whitespace().next() == Some("3.1.4"),
        &format!(
            "C7-03B requires exactly SurrealDB 3.1.4, got {}",
            version.trim()
        ),
    )
}

fn required_env(name: &str) -> TestResult<String> {
    std::env::var(name).map_err(|error| format!("{name} is required: {error}").into())
}

fn guardian_pid(config: &SurrealServerConfig) -> TestResult<u32> {
    let storage = config
        .storage
        .strip_prefix("rocksdb:")
        .ok_or("isolated storage must use rocksdb:")?;
    let storage = PathBuf::from(storage);
    let owned_root = storage
        .parent()
        .ok_or("isolated storage has no owned root")?;
    read_pid(&owned_root.join("tmp").join("owned-surreal.pid"))
}

fn read_pid(path: &Path) -> TestResult<u32> {
    Ok(std::fs::read_to_string(path)?.trim().parse()?)
}

fn retrieval_envelope(
    project_id: ProjectId,
    task_id: TaskId,
    claims: Vec<ClaimCardInput>,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let write_id = WriteId::new_v7();
    let input_hash = blake3::hash(&serde_json::to_vec(&json!({
        "project_id": project_id,
        "claims": claims,
    }))?)
    .to_hex()
    .to_string();
    Ok(MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash,
        policy_snapshot_id: Some("policy:c7-03b-fts-live".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "c7-03b-fts-live".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: Vec::new(),
        failures: Vec::new(),
        claims,
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

fn claim(statement: String, topic: &str) -> ClaimCardInput {
    ClaimCardInput {
        claim_id: ClaimId::new_v7(),
        statement,
        status: EpistemicStatus::Verified,
        payload: json!({ "topic": topic }),
    }
}

fn recall_request(project_id: ProjectId, query: impl Into<String>) -> RecallL0Request {
    RecallL0Request {
        project_id,
        query: query.into(),
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
        lifecycle_audit: false,
        task_id: None,
        task_class_cues: Vec::new(),
        scope_refs: Vec::new(),
        concept_refs: Vec::new(),
    }
}

fn require_top_handle(
    response: &RecallL0Response,
    expected_handle: &str,
    label: &str,
) -> TestResult {
    require(
        response
            .handles
            .first()
            .is_some_and(|item| item.handle == expected_handle),
        &format!("{label} was not the first result"),
    )
}

fn require(condition: bool, message: &str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
