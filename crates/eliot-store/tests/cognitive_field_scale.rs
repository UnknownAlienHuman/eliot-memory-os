use eliot_store::CanonicalStore;
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, EpistemicStatus, EvidenceAtomInput, EvidenceId,
    FailureFingerprintInput, FetchAtomsL2Request, GovernorConfig, IdempotencyOptions,
    LifecycleStatus, LifecycleWriteOptions, MemoryWriteEnvelope, OperationId, ProjectId,
    ProjectSequence, ReadConsistencyMode, RecallL0Request, SemanticCommandKind,
    SourceSnapshotInput, SurrealServerConfig, TaintClass, TaskId, ToolObservationInput, Visibility,
    WriteId, WriteStatus,
};
use serde_json::json;
use std::error::Error;
use std::time::Instant;
use time::OffsetDateTime;

const LOGICAL_RECORDS: usize = 100_000;
const BATCH_SIZE: usize = 1_000;
const HISTORICAL_VERSIONS: usize = 5_000;
const SAMPLE_COUNT: usize = 25;

fn should_capture_historical_claim(ordinal: usize, captured: usize) -> bool {
    ordinal != 0 && captured < HISTORICAL_VERSIONS
}

#[test]
fn r01_history_fixture_keeps_the_search_needle_immutable() {
    assert!(!should_capture_historical_claim(0, 0));
    assert!(should_capture_historical_claim(4, 0));
    assert!(should_capture_historical_claim(
        20_000,
        HISTORICAL_VERSIONS - 1
    ));
    assert!(!should_capture_historical_claim(
        20_004,
        HISTORICAL_VERSIONS
    ));
}

fn isolated_config() -> Option<SurrealServerConfig> {
    let endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT").ok()?;
    let bind = std::env::var("ELIOT_TEST_SURREAL_BIND").ok()?;
    let password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE").ok()?;
    let storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE").ok()?;
    let mut config = GovernorConfig::default().db.surreal;
    config.endpoint = endpoint;
    config.bind = bind;
    config.password_file = password_file;
    config.storage = storage;
    Some(config)
}

#[tokio::test]
#[ignore = "field certification scale gate: seeds 100k logical records in real SurrealDB"]
#[allow(clippy::print_stdout, clippy::too_many_lines)]
async fn r01_large_corpus_retrieval_meets_target_workstation_slos() -> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Err("R01 requires the isolated real SurrealDB harness".into());
    };
    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut historical_claims = Vec::with_capacity(HISTORICAL_VERSIONS);
    let mut target_claim_id = None;
    let seed_started = Instant::now();

    for batch in 0..(LOGICAL_RECORDS / BATCH_SIZE) {
        let mut claims = Vec::with_capacity(BATCH_SIZE / 4);
        let mut evidence_atoms = Vec::with_capacity(BATCH_SIZE / 4);
        let mut failures = Vec::with_capacity(BATCH_SIZE / 4);
        let mut observations = Vec::with_capacity(BATCH_SIZE / 4);
        for offset in 0..(BATCH_SIZE / 4) {
            let ordinal = batch * BATCH_SIZE + offset * 4;
            let claim_id = ClaimId::new_v7();
            let statement = if ordinal == 0 {
                target_claim_id = Some(claim_id);
                "r01 unique retrieval needle alpha omega".to_owned()
            } else {
                format!("r01 claim distractor batch {batch:03} ordinal {ordinal:06}")
            };
            if should_capture_historical_claim(ordinal, historical_claims.len()) {
                historical_claims.push(claim_id);
            }
            claims.push(ClaimCardInput {
                claim_id,
                statement,
                status: EpistemicStatus::Verified,
                payload: json!({"kind":"claim","ordinal":ordinal}),
            });
            evidence_atoms.push(EvidenceAtomInput {
                evidence_id: EvidenceId::new_v7(),
                source_id: format!("r01-source-{ordinal:06}"),
                summary: format!("r01 evidence distractor {ordinal:06}"),
                payload: json!({"kind":"evidence","ordinal":ordinal + 1}),
            });
            failures.push(FailureFingerprintInput {
                fingerprint: format!("r01-failure-{ordinal:06}"),
                summary: format!("r01 failure distractor {ordinal:06}"),
                payload: json!({"kind":"failure","ordinal":ordinal + 2}),
            });
            observations.push(ToolObservationInput {
                observation_id: format!("r01-observation-{ordinal:06}"),
                tool_name: "r01-scale-probe".to_owned(),
                observation: format!("r01 observation distractor {ordinal:06}"),
                payload: json!({"kind":"observation","ordinal":ordinal + 3}),
            });
        }
        let receipt = store
            .apply_write_envelope(&envelope(
                project_id,
                task_id,
                claims,
                evidence_atoms,
                failures,
                observations,
            )?)
            .await?;
        assert_eq!(receipt.status, WriteStatus::Committed);
    }

    for (batch, ids) in historical_claims.chunks(BATCH_SIZE).enumerate() {
        let claims = ids
            .iter()
            .enumerate()
            .map(|(offset, claim_id)| ClaimCardInput {
                claim_id: *claim_id,
                statement: format!(
                    "r01 historical update batch {batch:03} ordinal {:06}",
                    batch * BATCH_SIZE + offset
                ),
                status: EpistemicStatus::Verified,
                payload: json!({"kind":"claim-history","revision":2}),
            })
            .collect();
        let receipt = store
            .apply_write_envelope(&envelope(
                project_id,
                task_id,
                claims,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?)
            .await?;
        assert_eq!(receipt.status, WriteStatus::Committed);
    }
    let seed_ms = seed_started.elapsed().as_millis();
    let target_claim_id = target_claim_id.ok_or("target claim was not seeded")?;
    let query = recall_request(project_id, "r01 unique retrieval needle alpha omega");
    let l2 = l2_request(project_id, vec![format!("claim:{target_claim_id}")]);

    for _ in 0..5 {
        let _ = store.recall_l0(&query).await?;
        let _ = store.fetch_atoms_l2(&l2).await?;
    }
    let mut l0_ms = Vec::with_capacity(SAMPLE_COUNT);
    let mut l2_ms = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        let started = Instant::now();
        let recalled = store.recall_l0(&query).await?;
        l0_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert_eq!(
            recalled
                .handles
                .first()
                .map(|handle| handle.handle.as_str()),
            Some(format!("claim:{target_claim_id}").as_str())
        );

        let started = Instant::now();
        let expanded = store.fetch_atoms_l2(&l2).await?;
        l2_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert_eq!(expanded.claims.len(), 1);
        assert_eq!(expanded.claims[0].claim_id, target_claim_id);
    }
    let l0_p95_ms = percentile_95(&mut l0_ms);
    let l2_p95_ms = percentile_95(&mut l2_ms);
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema_version":"eliot-cognitive-r01-result-v1",
            "logical_records":LOGICAL_RECORDS,
            "historical_versions":HISTORICAL_VERSIONS,
            "mixed_record_kinds":4,
            "samples":SAMPLE_COUNT,
            "seed_ms":seed_ms,
            "warm_l0_p95_ms":l0_p95_ms,
            "small_l2_p95_ms":l2_p95_ms,
        }))?
    );
    assert!(
        l0_p95_ms <= 75.0,
        "warm L0 p95 {l0_p95_ms:.3} ms exceeds 75 ms"
    );
    assert!(
        l2_p95_ms <= 150.0,
        "small exact L2 p95 {l2_p95_ms:.3} ms exceeds 150 ms"
    );
    Ok(())
}

fn envelope(
    project_id: ProjectId,
    task_id: TaskId,
    claims: Vec<ClaimCardInput>,
    evidence_atoms: Vec<EvidenceAtomInput>,
    failures: Vec<FailureFingerprintInput>,
    tool_observations: Vec<ToolObservationInput>,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let write_id = WriteId::new_v7();
    let input_hash = blake3::hash(&serde_json::to_vec(&json!({
        "project_id":project_id,
        "claims":claims,
        "evidence_atoms":evidence_atoms,
        "failures":failures,
        "tool_observations":tool_observations,
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
        policy_snapshot_id: Some("policy:cognitive-field-r01".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "cognitive-field-r01".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::<SourceSnapshotInput>::new(),
        evidence_atoms,
        tool_observations,
        failures,
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

fn l2_request(project_id: ProjectId, handles: Vec<String>) -> FetchAtomsL2Request {
    FetchAtomsL2Request {
        project_id,
        handles,
        continuation: None,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    }
}

fn percentile_95(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let index = ((values.len() * 95).div_ceil(100)).saturating_sub(1);
    values[index]
}
