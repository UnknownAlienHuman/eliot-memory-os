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
use std::future::Future;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const LOGICAL_RECORDS: usize = 100_000;
const BATCH_SIZE: usize = 1_000;
const HISTORICAL_VERSIONS: usize = 5_000;
const SAMPLE_COUNT: usize = 25;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const PF1_LOGICAL_RECORDS: usize = 10_000;
const PF1_HISTORICAL_VERSIONS: usize = 500;
const PF3_SAMPLE_COUNT: usize = 5;
const PF3_L0_READINESS_MS: f64 = 150.0;
const PF3_L2_READINESS_MS: f64 = 300.0;

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
    match std::env::var("ELIOT_COGNITIVE_FIELD_SCALE_STAGE").as_deref() {
        Ok("pf1") => run_pf1().await,
        Ok("pf2") => run_pf2().await,
        Ok("pf3") => run_pf3().await,
        Ok("r01") => run_r01().await,
        Ok(stage) => Err(format!(
            "unknown ELIOT_COGNITIVE_FIELD_SCALE_STAGE {stage:?}; expected pf1, pf2, pf3, or r01"
        )
        .into()),
        Err(_) => Err(
            "set ELIOT_COGNITIVE_FIELD_SCALE_STAGE to pf1, pf2, pf3, or r01; exact R01 is opt-in"
                .into(),
        ),
    }
}

async fn run_pf1() -> Result<(), Box<dyn Error>> {
    let fixture = seed_fixture(PF1_LOGICAL_RECORDS, PF1_HISTORICAL_VERSIONS).await?;
    let measurements = measure_queries(&fixture, 1, 1).await?;
    emit_stage_result("pf1", &fixture, &measurements)?;
    Ok(())
}

async fn run_pf2() -> Result<(), Box<dyn Error>> {
    let fixture = seed_fixture(LOGICAL_RECORDS, HISTORICAL_VERSIONS).await?;
    let measurements = measure_queries(&fixture, 1, 1).await?;
    emit_stage_result("pf2", &fixture, &measurements)?;
    Ok(())
}

async fn run_pf3() -> Result<(), Box<dyn Error>> {
    let fixture = seed_fixture(LOGICAL_RECORDS, HISTORICAL_VERSIONS).await?;
    let measurements = measure_queries(&fixture, 5, PF3_SAMPLE_COUNT).await?;
    let l0_p95_ms = percentile_95(&mut measurements.l0_ms.clone());
    let l2_p95_ms = percentile_95(&mut measurements.l2_ms.clone());
    emit_stage_result("pf3", &fixture, &measurements)?;
    assert!(
        l0_p95_ms <= PF3_L0_READINESS_MS,
        "PF-3 warm L0 p95 {l0_p95_ms:.3} ms exceeds {PF3_L0_READINESS_MS} ms"
    );
    assert!(
        l2_p95_ms <= PF3_L2_READINESS_MS,
        "PF-3 small L2 p95 {l2_p95_ms:.3} ms exceeds {PF3_L2_READINESS_MS} ms"
    );
    Ok(())
}

async fn run_r01() -> Result<(), Box<dyn Error>> {
    let fixture = seed_fixture(LOGICAL_RECORDS, HISTORICAL_VERSIONS).await?;
    let measurements = measure_queries(&fixture, 5, SAMPLE_COUNT).await?;
    let mut l0_ms = measurements.l0_ms.clone();
    let mut l2_ms = measurements.l2_ms.clone();
    let l0_p95_ms = percentile_95(&mut l0_ms);
    let l2_p95_ms = percentile_95(&mut l2_ms);
    emit_stage_result("r01", &fixture, &measurements)?;
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

struct ScaleFixture {
    store: CanonicalStore,
    project_id: ProjectId,
    target_claim_id: ClaimId,
    logical_records: usize,
    historical_versions: usize,
    seed_ms: u128,
}

struct QueryMeasurements {
    l0_ms: Vec<f64>,
    l2_ms: Vec<f64>,
    l0_returned: Vec<usize>,
    l2_claims_returned: Vec<usize>,
    wall_ms: u128,
}

async fn seed_fixture(
    logical_records: usize,
    historical_versions: usize,
) -> Result<ScaleFixture, Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Err("scale ladder requires the isolated real SurrealDB harness".into());
    };
    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut historical_claims = Vec::with_capacity(historical_versions);
    let mut target_claim_id = None;
    let seed_started = Instant::now();

    for batch in 0..(logical_records / BATCH_SIZE) {
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
            if ordinal != 0 && historical_claims.len() < historical_versions {
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
    let target_claim_id = target_claim_id.ok_or("target claim was not seeded")?;
    Ok(ScaleFixture {
        store,
        project_id,
        target_claim_id,
        logical_records,
        historical_versions,
        seed_ms: seed_started.elapsed().as_millis(),
    })
}

async fn measure_queries(
    fixture: &ScaleFixture,
    warmup_count: usize,
    sample_count: usize,
) -> Result<QueryMeasurements, Box<dyn Error>> {
    let query = recall_request(
        fixture.project_id,
        "r01 unique retrieval needle alpha omega",
    );
    let l2 = l2_request(
        fixture.project_id,
        vec![format!("claim:{}", fixture.target_claim_id)],
    );
    for _ in 0..warmup_count {
        let _ = query_with_timeout("warm L0", fixture.store.recall_l0(&query)).await?;
        let _ = query_with_timeout("warm L2", fixture.store.fetch_atoms_l2(&l2)).await?;
    }
    let wall_started = Instant::now();
    let mut l0_ms = Vec::with_capacity(sample_count);
    let mut l2_ms = Vec::with_capacity(sample_count);
    let mut l0_returned = Vec::with_capacity(sample_count);
    let mut l2_claims_returned = Vec::with_capacity(sample_count);
    for sample in 0..sample_count {
        let started = Instant::now();
        let recalled = query_with_timeout(
            &format!("L0 sample {sample}"),
            fixture.store.recall_l0(&query),
        )
        .await?;
        l0_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        l0_returned.push(recalled.handles.len());
        assert_eq!(
            recalled
                .handles
                .first()
                .map(|handle| handle.handle.as_str()),
            Some(format!("claim:{}", fixture.target_claim_id).as_str())
        );

        let started = Instant::now();
        let expanded = query_with_timeout(
            &format!("L2 sample {sample}"),
            fixture.store.fetch_atoms_l2(&l2),
        )
        .await?;
        l2_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        l2_claims_returned.push(expanded.claims.len());
        assert_eq!(expanded.claims.len(), 1);
        assert_eq!(expanded.claims[0].claim_id, fixture.target_claim_id);
    }
    Ok(QueryMeasurements {
        l0_ms,
        l2_ms,
        l0_returned,
        l2_claims_returned,
        wall_ms: wall_started.elapsed().as_millis(),
    })
}

async fn query_with_timeout<T, E>(
    label: &str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, Box<dyn Error>>
where
    E: Error + 'static,
{
    let result = tokio::time::timeout(QUERY_TIMEOUT, future)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{label} exceeded {} ms", QUERY_TIMEOUT.as_millis()),
            )
        })?;
    Ok(result?)
}

// The certification harness consumes this one JSON document from stdout in
// addition to the optional durable result sink.
#[allow(clippy::print_stdout)]
fn emit_stage_result(
    stage: &str,
    fixture: &ScaleFixture,
    measurements: &QueryMeasurements,
) -> Result<(), Box<dyn Error>> {
    let mut l0_ms = measurements.l0_ms.clone();
    let mut l2_ms = measurements.l2_ms.clone();
    let encoded = serde_json::to_string_pretty(&json!({
        "schema_version":"eliot-cognitive-r01-result-v2",
        "stage":stage,
        "logical_records":fixture.logical_records,
        "historical_versions":fixture.historical_versions,
        "mixed_record_kinds":4,
        "samples":measurements.l0_ms.len(),
        "seed_ms":fixture.seed_ms,
        "query_wall_ms":measurements.wall_ms,
        "query_timeout_ms":QUERY_TIMEOUT.as_millis(),
        "warm_l0_p95_ms":percentile_95(&mut l0_ms),
        "small_l2_p95_ms":percentile_95(&mut l2_ms),
        "l0_ms":measurements.l0_ms,
        "l2_ms":measurements.l2_ms,
        "l0_returned":measurements.l0_returned,
        "l2_claims_returned":measurements.l2_claims_returned,
    }))?;
    println!("{encoded}");
    if let Ok(path) = std::env::var("ELIOT_COGNITIVE_FIELD_RESULT_PATH") {
        std::fs::write(path, format!("{encoded}\n"))?;
    }
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
