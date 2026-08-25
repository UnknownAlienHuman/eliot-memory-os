use eliot_store::{CanonicalStore, DEFAULT_DB_READ_POOL_SIZE, DbClientSet, DbClientSetMetrics};
use eliot_types::{
    AgentId, ClaimCard, ClaimCardInput, ClaimId, CredentialProviderKind, EpistemicStatus,
    EvidenceAtomInput, EvidenceId, FailureFingerprintInput, FetchAtomsL2Request, GovernorConfig,
    IdempotencyOptions, LifecycleStatus, LifecycleWriteOptions, MemoryRevision,
    MemoryWriteEnvelope, OperationId, ProjectId, ProjectSequence, ReadConsistencyMode,
    RecallL0Request, RecallL0Response, SemanticCommandKind, SourceSnapshotInput,
    SurrealServerConfig, TaintClass, TaskId, ToolObservationInput, Visibility, WriteId,
    WriteStatus,
};
use serde::Serialize;
use serde_json::json;
use std::error::Error;
use std::fmt::{self, Display};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::Barrier;

const LOGICAL_RECORDS: usize = 100_000;
const BATCH_SIZE: usize = 1_000;
const HISTORICAL_VERSIONS: usize = 5_000;
const SAMPLE_COUNT: usize = 25;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const PF1_LOGICAL_RECORDS: usize = 10_000;
const PF1_HISTORICAL_VERSIONS: usize = 500;
const PF1_L0_MS: f64 = 100.0;
const PF1_L2_MS: f64 = 150.0;
const PF2_L0_MS: f64 = 150.0;
const PF2_L2_MS: f64 = 300.0;
const PF3_L0_P95_MS: f64 = 150.0;
const PF3_L2_P95_MS: f64 = 300.0;
const R01_L0_P95_MS: f64 = 75.0;
const R01_L2_P95_MS: f64 = 150.0;
const PF1_SEED_STOP: Duration = Duration::from_mins(2);
const FINAL_SEED_STOP: Duration = Duration::from_mins(20);
const CONCURRENT_READERS: usize = 16;
const MAX_L0_PREVIEWS: usize = 12;
const MAX_L0_CANDIDATES: usize = 256;

type ScaleResult<T = ()> = Result<T, ScaleStop>;

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

#[test]
fn r01_gate_evaluation_reuses_one_measurement_without_rounding() {
    let measurements = QueryMeasurements {
        measurement_id: "one-measurement".to_owned(),
        warmup_count: 5,
        l0_ms: vec![74.0; SAMPLE_COUNT],
        l2_ms: vec![149.0; SAMPLE_COUNT],
        l0_returned: vec![1; SAMPLE_COUNT],
        l2_claims_returned: vec![1; SAMPLE_COUNT],
        wall_ms: 1,
    };
    let pf2 = evaluate_gate("PF2", &measurements, PF2_L0_MS, PF2_L2_MS, false);
    let pf3 = evaluate_gate("PF3", &measurements, PF3_L0_P95_MS, PF3_L2_P95_MS, true);
    let r01 = evaluate_gate("R01", &measurements, R01_L0_P95_MS, R01_L2_P95_MS, true);
    assert_eq!(pf2.measurement_id, pf3.measurement_id);
    assert_eq!(pf3.measurement_id, r01.measurement_id);
    assert_eq!(r01.status, "passed");
    assert_eq!(r01.l0_observed_ms, Some(74.0));
    assert_eq!(r01.l2_observed_ms, Some(149.0));
}

fn isolated_config() -> Option<SurrealServerConfig> {
    let executable = std::env::var("ELIOT_SURREAL_EXE").ok()?;
    let endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT").ok()?;
    let bind = std::env::var("ELIOT_TEST_SURREAL_BIND").ok()?;
    let password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE").ok()?;
    let storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE").ok()?;
    let mut config = GovernorConfig::default().db.surreal;
    config.exe = executable;
    config.endpoint = endpoint;
    config.bind = bind;
    config.password_file = password_file;
    config.storage = storage;
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    config.query_timeout_ms = 20_000;
    config.startup_timeout_ms = 20_000;
    Some(config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "one-shot C7-03 scale ladder: grows one real SurrealDB corpus from 10k to 100k"]
#[allow(clippy::print_stdout, clippy::too_many_lines)]
async fn r01_large_corpus_retrieval_meets_target_workstation_slos() -> Result<(), Box<dyn Error>> {
    let result_path = required_result_path()?;
    let started = Instant::now();
    let mut artifact = ScaleArtifact::new();
    create_initial_artifact(&result_path, &artifact)?;

    let Some(config) = isolated_config() else {
        let stop = ScaleStop::failed(
            "missing_isolated_harness_config",
            "scale ladder requires scripts/run-isolated-tests.ps1 and its real SurrealDB variables",
        );
        finish_artifact(&result_path, &mut artifact, started, &stop, None)?;
        return Err(Box::new(stop) as Box<dyn Error>);
    };
    if let Err(stop) = validate_scale_environment(&config) {
        finish_artifact(&result_path, &mut artifact, started, &stop, None)?;
        return Err(Box::new(stop) as Box<dyn Error>);
    }
    artifact.surrealdb_version = Some("3.1.4".to_owned());

    let clients = match DbClientSet::start(config).await {
        Ok(clients) => Arc::new(clients),
        Err(error) => {
            let stop = ScaleStop::failed("client_set_start_failed", error.to_string());
            finish_artifact(&result_path, &mut artifact, started, &stop, None)?;
            return Err(Box::new(stop) as Box<dyn Error>);
        }
    };
    artifact.sessions.initial = Some(clients.metrics());
    checkpoint(&result_path, &artifact)?;

    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let body_result = Box::pin(run_scale_ladder(
        &store,
        &clients,
        &result_path,
        &mut artifact,
    ))
    .await;
    artifact.sessions.before_shutdown = Some(clients.metrics());
    let shutdown_result = clients.shutdown().await;
    artifact.sessions.after_shutdown = Some(clients.metrics());

    let mut terminal = match (body_result, shutdown_result) {
        (Ok(()), Ok(_)) => None,
        (Err(stop), Ok(_)) => Some(stop),
        (Ok(()), Err(error)) => {
            artifact.shutdown_error = Some(error.to_string());
            Some(ScaleStop::failed("client_set_shutdown_failed", error))
        }
        (Err(mut stop), Err(error)) => {
            stop.detail = format!(
                "{}; explicit DbClientSet shutdown also failed: {error}",
                stop.detail
            );
            artifact.shutdown_error = Some(error.to_string());
            Some(stop)
        }
    };
    if !artifact
        .sessions
        .after_shutdown
        .is_some_and(|metrics| metrics.shutdown_completed && metrics.active_readers == 0)
    {
        let detail = "DbClientSet shutdown metrics did not reach shutdown_completed=true with zero active readers";
        if let Some(stop) = &mut terminal {
            stop.detail = format!("{}; {detail}", stop.detail);
        } else {
            terminal = Some(ScaleStop::failed("shutdown_metrics_mismatch", detail));
        }
    }

    if let Some(stop) = terminal {
        let shutdown_error = artifact.shutdown_error.clone();
        finish_artifact(&result_path, &mut artifact, started, &stop, shutdown_error)?;
        print_artifact(&artifact)?;
        return Err(Box::new(stop) as Box<dyn Error>);
    }

    artifact.status = "passed".to_owned();
    artifact.total_wall_ms = Some(started.elapsed().as_millis());
    checkpoint(&result_path, &artifact)?;
    print_artifact(&artifact)?;
    Ok(())
}

#[allow(clippy::large_futures, clippy::too_many_lines)]
async fn run_scale_ladder(
    store: &CanonicalStore,
    clients: &Arc<DbClientSet>,
    result_path: &Path,
    artifact: &mut ScaleArtifact,
) -> ScaleResult {
    store
        .migrate_schema()
        .await
        .map_err(|error| ScaleStop::failed("schema_migration_failed", error))?;
    assert_initial_sessions(clients.metrics())?;

    let mut corpus = SeedState::new();
    artifact.corpus.local_project_id = Some(corpus.project_id.to_string());

    let pf1_seed_started = Instant::now();
    seed_logical_range(store, &mut corpus, 0, PF1_LOGICAL_RECORDS).await?;
    seed_historical_range(store, &mut corpus, 0, PF1_HISTORICAL_VERSIONS).await?;
    let pf1_seed_elapsed = pf1_seed_started.elapsed();
    artifact.seed_durations.pf1_ms = Some(pf1_seed_elapsed.as_millis());
    artifact.corpus.pf1_logical_records = Some(corpus.logical_records);
    artifact.corpus.pf1_historical_versions = Some(corpus.historical_versions);
    artifact.corpus.pf1_digest_blake3 = Some(corpus.digest());
    artifact.revisions.pf1_canonical = corpus.last_revision.map(MemoryRevision::value);
    checkpoint(result_path, artifact)?;

    if pf1_seed_elapsed > PF1_SEED_STOP {
        return Err(ScaleStop::failed(
            "pf1_seed_exceeded_120s",
            format!("10k seed took {} ms", pf1_seed_elapsed.as_millis()),
        ));
    }
    let predicted_final_ms = pf1_seed_elapsed
        .as_millis()
        .saturating_mul(u128::try_from(LOGICAL_RECORDS / PF1_LOGICAL_RECORDS).unwrap_or(u128::MAX));
    artifact.seed_durations.predicted_100k_ms = Some(predicted_final_ms);
    if predicted_final_ms > FINAL_SEED_STOP.as_millis() {
        return Err(ScaleStop::failed(
            "predicted_100k_seed_exceeds_20m",
            format!("10k extrapolation predicts {predicted_final_ms} ms"),
        ));
    }

    let pf1_rebuild_started = Instant::now();
    let pf1_projection = store
        .rebuild_memory_search_projection(corpus.project_id)
        .await
        .map_err(|error| ScaleStop::failed("pf1_projection_rebuild_failed", error))?;
    artifact.rebuild_durations.pf1_ms = Some(pf1_rebuild_started.elapsed().as_millis());
    artifact.revisions.pf1_projection = Some(pf1_projection.value());
    require_revision_match(corpus.last_revision, pf1_projection, "PF1")?;

    let target_claim_id = corpus.target_claim()?;
    let pf1_measurement = measure_queries(
        store,
        corpus.project_id,
        target_claim_id,
        None,
        format!("{}:pf1", artifact.measurement_id),
        1,
        1,
    )
    .await?;
    let pf1_gate = evaluate_gate("PF1", &pf1_measurement, PF1_L0_MS, PF1_L2_MS, false);
    artifact.measurements.pf1 = Some(pf1_measurement);
    artifact.gates.pf1 = pf1_gate;
    checkpoint(result_path, artifact)?;
    if artifact.gates.pf1.status != "passed" {
        return Err(ScaleStop::slo(
            "pf1_slo_not_met",
            gate_detail(&artifact.gates.pf1),
        ));
    }

    let final_growth_started = Instant::now();
    seed_logical_range(store, &mut corpus, PF1_LOGICAL_RECORDS, LOGICAL_RECORDS).await?;
    seed_historical_range(
        store,
        &mut corpus,
        PF1_HISTORICAL_VERSIONS,
        HISTORICAL_VERSIONS,
    )
    .await?;
    let final_growth_elapsed = final_growth_started.elapsed();
    artifact.seed_durations.final_growth_ms = Some(final_growth_elapsed.as_millis());
    artifact.seed_durations.total_ms = Some(
        pf1_seed_elapsed
            .as_millis()
            .saturating_add(final_growth_elapsed.as_millis()),
    );
    artifact.corpus.logical_records = Some(corpus.logical_records);
    artifact.corpus.historical_versions = Some(corpus.historical_versions);
    artifact.corpus.mixed_record_kinds = Some(4);
    artifact.corpus.digest_blake3 = Some(corpus.digest());
    artifact.revisions.final_canonical = corpus.last_revision.map(MemoryRevision::value);
    checkpoint(result_path, artifact)?;

    if artifact.seed_durations.total_ms > Some(FINAL_SEED_STOP.as_millis()) {
        return Err(ScaleStop::failed(
            "100k_seed_exceeded_20m",
            format!(
                "100k/5k cumulative seed took {} ms",
                artifact.seed_durations.total_ms.unwrap_or_default()
            ),
        ));
    }

    let (foreign_project_id, foreign_claim_id, foreign_revision, foreign_digest) =
        seed_foreign_canary(store).await?;
    artifact.corpus.foreign_project_id = Some(foreign_project_id.to_string());
    artifact.corpus.foreign_canary_digest_blake3 = Some(foreign_digest);
    artifact.revisions.foreign_canonical = Some(foreign_revision.value());

    let final_rebuild_started = Instant::now();
    let final_projection = store
        .rebuild_memory_search_projection(corpus.project_id)
        .await
        .map_err(|error| ScaleStop::failed("final_projection_rebuild_failed", error))?;
    let foreign_projection = store
        .rebuild_memory_search_projection(foreign_project_id)
        .await
        .map_err(|error| ScaleStop::failed("foreign_projection_rebuild_failed", error))?;
    artifact.rebuild_durations.final_ms = Some(final_rebuild_started.elapsed().as_millis());
    artifact.revisions.final_projection = Some(final_projection.value());
    artifact.revisions.foreign_projection = Some(foreign_projection.value());
    require_revision_match(corpus.last_revision, final_projection, "100k final")?;
    require_revision_match(Some(foreign_revision), foreign_projection, "foreign canary")?;

    verify_fts_plan(store, corpus.project_id).await?;
    verify_project_canary(
        store,
        corpus.project_id,
        target_claim_id,
        foreign_project_id,
        foreign_claim_id,
    )
    .await?;
    checkpoint(result_path, artifact)?;

    let final_measurement = measure_queries(
        store,
        corpus.project_id,
        target_claim_id,
        Some(foreign_claim_id),
        artifact.measurement_id.clone(),
        5,
        SAMPLE_COUNT,
    )
    .await?;
    artifact.gates.pf2 = evaluate_gate("PF2", &final_measurement, PF2_L0_MS, PF2_L2_MS, false);
    artifact.measurements.final_25 = Some(final_measurement.clone());
    checkpoint(result_path, artifact)?;
    if artifact.gates.pf2.status != "passed" {
        return Err(ScaleStop::slo(
            "pf2_slo_not_met",
            gate_detail(&artifact.gates.pf2),
        ));
    }

    artifact.gates.pf3 = evaluate_gate(
        "PF3",
        &final_measurement,
        PF3_L0_P95_MS,
        PF3_L2_P95_MS,
        true,
    );
    checkpoint(result_path, artifact)?;
    if artifact.gates.pf3.status != "passed" {
        return Err(ScaleStop::slo(
            "pf3_slo_not_met",
            gate_detail(&artifact.gates.pf3),
        ));
    }

    artifact.gates.r01 = evaluate_gate(
        "R01",
        &final_measurement,
        R01_L0_P95_MS,
        R01_L2_P95_MS,
        true,
    );
    checkpoint(result_path, artifact)?;
    if artifact.gates.r01.status != "passed" {
        return Err(ScaleStop::slo(
            "r01_slo_not_met",
            gate_detail(&artifact.gates.r01),
        ));
    }

    let before_concurrency = clients.metrics();
    artifact.sessions.before_concurrency = Some(before_concurrency);
    let concurrency = run_concurrent_readers(
        store,
        corpus.project_id,
        target_claim_id,
        foreign_project_id,
        foreign_claim_id,
    )
    .await?;
    let after_concurrency = clients.metrics();
    artifact.sessions.after_concurrency = Some(after_concurrency);
    verify_session_metrics(before_concurrency, after_concurrency)?;
    artifact.gates.concurrent_readers = GateResult::passed_without_latency(
        "G6",
        concurrency.measurement_id.clone(),
        CONCURRENT_READERS,
    );
    artifact.concurrency = Some(concurrency);
    checkpoint(result_path, artifact)?;
    Ok(())
}

fn validate_scale_environment(config: &SurrealServerConfig) -> ScaleResult {
    if std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() != Ok("1") {
        return Err(ScaleStop::failed(
            "provider_disable_guard_missing",
            "ELIOT_DISABLE_REAL_PROVIDER=1 is required for the provider-free scale ladder",
        ));
    }
    let output = Command::new(&config.exe)
        .arg("version")
        .output()
        .map_err(|error| ScaleStop::failed("surreal_version_probe_failed", error))?;
    let version = String::from_utf8(output.stdout)
        .map_err(|error| ScaleStop::failed("surreal_version_decode_failed", error))?;
    if !output.status.success() || version.split_whitespace().next() != Some("3.1.4") {
        return Err(ScaleStop::failed(
            "surreal_version_mismatch",
            format!(
                "C7-03 requires exactly SurrealDB 3.1.4, got {}",
                version.trim()
            ),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct SeedState {
    project_id: ProjectId,
    task_id: TaskId,
    target_claim_id: Option<ClaimId>,
    historical_claims: Vec<ClaimId>,
    logical_records: usize,
    historical_versions: usize,
    last_revision: Option<MemoryRevision>,
    digest: blake3::Hasher,
}

impl SeedState {
    fn new() -> Self {
        Self {
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7(),
            target_claim_id: None,
            historical_claims: Vec::with_capacity(HISTORICAL_VERSIONS),
            logical_records: 0,
            historical_versions: 0,
            last_revision: None,
            digest: blake3::Hasher::new(),
        }
    }

    fn target_claim(&self) -> ScaleResult<ClaimId> {
        self.target_claim_id.ok_or_else(|| {
            ScaleStop::failed("fixture_target_missing", "target claim was not seeded")
        })
    }

    fn digest(&self) -> String {
        self.digest.clone().finalize().to_hex().to_string()
    }

    fn record_receipt(&mut self, receipt: &eliot_types::WriteReceipt) -> ScaleResult {
        if receipt.status != WriteStatus::Committed {
            return Err(ScaleStop::failed(
                "seed_write_not_committed",
                format!("write {} returned {:?}", receipt.write_id, receipt.status),
            ));
        }
        let revision = receipt.memory_revision.ok_or_else(|| {
            ScaleStop::failed(
                "seed_revision_missing",
                format!("write {} omitted memory_revision", receipt.write_id),
            )
        })?;
        self.last_revision = Some(revision);
        self.digest.update(receipt.input_hash.as_bytes());
        self.digest.update(&revision.value().to_le_bytes());
        Ok(())
    }
}

async fn seed_logical_range(
    store: &CanonicalStore,
    state: &mut SeedState,
    start: usize,
    end: usize,
) -> ScaleResult {
    if start != state.logical_records
        || !start.is_multiple_of(BATCH_SIZE)
        || !end.is_multiple_of(BATCH_SIZE)
    {
        return Err(ScaleStop::failed(
            "invalid_seed_range",
            format!(
                "requested {start}..{end} after {} rows",
                state.logical_records
            ),
        ));
    }
    for batch_start in (start..end).step_by(BATCH_SIZE) {
        let batch = batch_start / BATCH_SIZE;
        let mut claims = Vec::with_capacity(BATCH_SIZE / 4);
        let mut evidence_atoms = Vec::with_capacity(BATCH_SIZE / 4);
        let mut failures = Vec::with_capacity(BATCH_SIZE / 4);
        let mut observations = Vec::with_capacity(BATCH_SIZE / 4);
        for offset in 0..(BATCH_SIZE / 4) {
            let ordinal = batch_start + offset * 4;
            let claim_id = ClaimId::new_v7();
            let statement = if ordinal == 0 {
                state.target_claim_id = Some(claim_id);
                "r01 unique retrieval needle alpha omega".to_owned()
            } else {
                format!("r01 claim distractor batch {batch:03} ordinal {ordinal:06}")
            };
            if should_capture_historical_claim(ordinal, state.historical_claims.len()) {
                state.historical_claims.push(claim_id);
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
        let envelope = envelope(
            state.project_id,
            state.task_id,
            claims,
            evidence_atoms,
            failures,
            observations,
        )
        .map_err(|error| ScaleStop::failed("seed_envelope_encode_failed", error))?;
        let receipt = store
            .apply_write_envelope(&envelope)
            .await
            .map_err(|error| ScaleStop::failed("logical_seed_write_failed", error))?;
        state.record_receipt(&receipt)?;
        state.logical_records += BATCH_SIZE;
    }
    Ok(())
}

async fn seed_historical_range(
    store: &CanonicalStore,
    state: &mut SeedState,
    start: usize,
    end: usize,
) -> ScaleResult {
    if start != state.historical_versions || end > state.historical_claims.len() {
        return Err(ScaleStop::failed(
            "invalid_history_range",
            format!(
                "requested {start}..{end} after {} versions with {} captured claims",
                state.historical_versions,
                state.historical_claims.len()
            ),
        ));
    }
    let ids = state.historical_claims[start..end].to_vec();
    for (batch, chunk) in ids.chunks(BATCH_SIZE).enumerate() {
        let claims = chunk
            .iter()
            .enumerate()
            .map(|(offset, claim_id)| ClaimCardInput {
                claim_id: *claim_id,
                statement: format!(
                    "r01 historical update ordinal {:06}",
                    start + batch * BATCH_SIZE + offset
                ),
                status: EpistemicStatus::Verified,
                payload: json!({"kind":"claim-history","revision":2}),
            })
            .collect();
        let envelope = envelope(
            state.project_id,
            state.task_id,
            claims,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .map_err(|error| ScaleStop::failed("history_envelope_encode_failed", error))?;
        let receipt = store
            .apply_write_envelope(&envelope)
            .await
            .map_err(|error| ScaleStop::failed("history_seed_write_failed", error))?;
        state.record_receipt(&receipt)?;
        state.historical_versions += chunk.len();
    }
    Ok(())
}

async fn seed_foreign_canary(
    store: &CanonicalStore,
) -> ScaleResult<(ProjectId, ClaimId, MemoryRevision, String)> {
    let project_id = ProjectId::new_v7();
    let claim_id = ClaimId::new_v7();
    let envelope = envelope(
        project_id,
        TaskId::new_v7(),
        vec![ClaimCardInput {
            claim_id,
            statement: "r01 unique retrieval needle alpha omega foreign project canary".to_owned(),
            status: EpistemicStatus::Verified,
            payload: json!({"kind":"foreign-project-canary"}),
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .map_err(|error| ScaleStop::failed("foreign_envelope_encode_failed", error))?;
    let receipt = store
        .apply_write_envelope(&envelope)
        .await
        .map_err(|error| ScaleStop::failed("foreign_seed_write_failed", error))?;
    if receipt.status != WriteStatus::Committed {
        return Err(ScaleStop::failed(
            "foreign_seed_not_committed",
            format!("foreign write returned {:?}", receipt.status),
        ));
    }
    let revision = receipt.memory_revision.ok_or_else(|| {
        ScaleStop::failed(
            "foreign_revision_missing",
            "foreign canary receipt omitted memory_revision",
        )
    })?;
    let digest = blake3::hash(receipt.input_hash.as_bytes())
        .to_hex()
        .to_string();
    Ok((project_id, claim_id, revision, digest))
}

async fn verify_fts_plan(store: &CanonicalStore, project_id: ProjectId) -> ScaleResult {
    let plan = store
        .memory_search_query_plan(project_id, "r01 unique retrieval needle alpha omega")
        .await
        .map_err(|error| ScaleStop::failed("fts_explain_failed", error))?;
    let encoded = serde_json::to_string(&plan)
        .map_err(|error| ScaleStop::failed("fts_explain_encode_failed", error))?;
    if !encoded.contains("FullTextScan") || !encoded.contains("idx_memory_search_projection_fts_v1")
    {
        return Err(ScaleStop::failed(
            "fts_index_plan_mismatch",
            "SurrealDB EXPLAIN did not select idx_memory_search_projection_fts_v1 FullTextScan",
        ));
    }
    Ok(())
}

async fn verify_project_canary(
    store: &CanonicalStore,
    local_project_id: ProjectId,
    local_claim_id: ClaimId,
    foreign_project_id: ProjectId,
    foreign_claim_id: ClaimId,
) -> ScaleResult {
    let local = query_with_timeout(
        "local project-isolation canary",
        store.recall_l0(&recall_request(
            local_project_id,
            "r01 unique retrieval needle alpha omega",
        )),
    )
    .await?;
    require_l0_target(
        &local,
        local_claim_id,
        Some(foreign_claim_id),
        "local canary",
    )?;
    let foreign = query_with_timeout(
        "foreign project-isolation canary",
        store.recall_l0(&recall_request(
            foreign_project_id,
            "r01 unique retrieval needle alpha omega",
        )),
    )
    .await?;
    require_l0_target(
        &foreign,
        foreign_claim_id,
        Some(local_claim_id),
        "foreign canary",
    )
}

#[derive(Clone, Debug, Serialize)]
struct QueryMeasurements {
    measurement_id: String,
    warmup_count: usize,
    l0_ms: Vec<f64>,
    l2_ms: Vec<f64>,
    l0_returned: Vec<usize>,
    l2_claims_returned: Vec<usize>,
    wall_ms: u128,
}

#[allow(clippy::large_futures, clippy::too_many_arguments)]
async fn measure_queries(
    store: &CanonicalStore,
    project_id: ProjectId,
    target_claim_id: ClaimId,
    forbidden_claim_id: Option<ClaimId>,
    measurement_id: String,
    warmup_count: usize,
    sample_count: usize,
) -> ScaleResult<QueryMeasurements> {
    let query = recall_request(project_id, "r01 unique retrieval needle alpha omega");
    let l2 = l2_request(project_id, vec![format!("claim:{target_claim_id}")]);
    for warmup in 0..warmup_count {
        let recalled =
            query_with_timeout(&format!("warm L0 {warmup}"), store.recall_l0(&query)).await?;
        require_l0_target(&recalled, target_claim_id, forbidden_claim_id, "warm L0")?;
        let expanded =
            query_with_timeout(&format!("warm L2 {warmup}"), store.fetch_atoms_l2(&l2)).await?;
        require_l2_target(&expanded.claims, target_claim_id, "warm L2")?;
    }

    let wall_started = Instant::now();
    let mut l0_ms = Vec::with_capacity(sample_count);
    let mut l2_ms = Vec::with_capacity(sample_count);
    let mut l0_returned = Vec::with_capacity(sample_count);
    let mut l2_claims_returned = Vec::with_capacity(sample_count);
    for sample in 0..sample_count {
        let started = Instant::now();
        let recalled =
            query_with_timeout(&format!("L0 sample {sample}"), store.recall_l0(&query)).await?;
        l0_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        l0_returned.push(recalled.handles.len());
        require_l0_target(
            &recalled,
            target_claim_id,
            forbidden_claim_id,
            &format!("L0 sample {sample}"),
        )?;

        let started = Instant::now();
        let expanded =
            query_with_timeout(&format!("L2 sample {sample}"), store.fetch_atoms_l2(&l2)).await?;
        l2_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        l2_claims_returned.push(expanded.claims.len());
        require_l2_target(
            &expanded.claims,
            target_claim_id,
            &format!("L2 sample {sample}"),
        )?;
    }
    Ok(QueryMeasurements {
        measurement_id,
        warmup_count,
        l0_ms,
        l2_ms,
        l0_returned,
        l2_claims_returned,
        wall_ms: wall_started.elapsed().as_millis(),
    })
}

fn require_l0_target(
    response: &RecallL0Response,
    target_claim_id: ClaimId,
    forbidden_claim_id: Option<ClaimId>,
    label: &str,
) -> ScaleResult {
    let expected = format!("claim:{target_claim_id}");
    if response.handles.first().map(|item| item.handle.as_str()) != Some(expected.as_str()) {
        return Err(ScaleStop::failed(
            "l0_target_mismatch",
            format!("{label} did not rank {expected} first"),
        ));
    }
    if response.handles.len() > MAX_L0_PREVIEWS
        || response.rank_trace.candidates_considered > MAX_L0_CANDIDATES
    {
        return Err(ScaleStop::failed(
            "l0_bound_exceeded",
            format!(
                "{label}: previews={} candidates={}",
                response.handles.len(),
                response.rank_trace.candidates_considered
            ),
        ));
    }
    if let Some(forbidden) = forbidden_claim_id {
        let forbidden = format!("claim:{forbidden}");
        if response.handles.iter().any(|item| item.handle == forbidden) {
            return Err(ScaleStop::failed(
                "project_isolation_failed",
                format!("{label} leaked {forbidden}"),
            ));
        }
    }
    Ok(())
}

fn require_l2_target(claims: &[ClaimCard], target_claim_id: ClaimId, label: &str) -> ScaleResult {
    if claims.len() != 1 || claims[0].claim_id != target_claim_id {
        return Err(ScaleStop::failed(
            "l2_target_mismatch",
            format!("{label} did not return exactly claim:{target_claim_id}"),
        ));
    }
    Ok(())
}

async fn query_with_timeout<T, E>(
    label: &str,
    future: impl Future<Output = Result<T, E>>,
) -> ScaleResult<T>
where
    E: Display,
{
    tokio::time::timeout(QUERY_TIMEOUT, future)
        .await
        .map_err(|_| {
            ScaleStop::failed(
                "query_timeout",
                format!("{label} exceeded {} ms", QUERY_TIMEOUT.as_millis()),
            )
        })?
        .map_err(|error| ScaleStop::failed("query_failed", format!("{label}: {error}")))
}

#[derive(Clone, Debug, Serialize)]
struct ConcurrentReadEvidence {
    measurement_id: String,
    readers: usize,
    local_readers: usize,
    foreign_readers: usize,
    completed_readers: usize,
    wall_ms: u128,
}

#[allow(clippy::large_futures)]
async fn run_concurrent_readers(
    store: &CanonicalStore,
    local_project_id: ProjectId,
    local_claim_id: ClaimId,
    foreign_project_id: ProjectId,
    foreign_claim_id: ClaimId,
) -> ScaleResult<ConcurrentReadEvidence> {
    let measurement_id = format!("concurrency:{}", WriteId::new_v7());
    let barrier = Arc::new(Barrier::new(CONCURRENT_READERS + 1));
    let mut tasks = Vec::with_capacity(CONCURRENT_READERS);
    for reader in 0..CONCURRENT_READERS {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        let (project_id, target, forbidden) = if reader % 2 == 0 {
            (local_project_id, local_claim_id, foreign_claim_id)
        } else {
            (foreign_project_id, foreign_claim_id, local_claim_id)
        };
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = query_with_timeout(
                &format!("concurrent reader {reader} L0"),
                store.recall_l0(&recall_request(
                    project_id,
                    "r01 unique retrieval needle alpha omega",
                )),
            )
            .await?;
            require_l0_target(
                &response,
                target,
                Some(forbidden),
                &format!("concurrent reader {reader} L0"),
            )?;
            let expanded = query_with_timeout(
                &format!("concurrent reader {reader} L2"),
                store.fetch_atoms_l2(&l2_request(project_id, vec![format!("claim:{target}")])),
            )
            .await?;
            require_l2_target(
                &expanded.claims,
                target,
                &format!("concurrent reader {reader} L2"),
            )
        }));
    }
    let started = Instant::now();
    barrier.wait().await;
    let mut completed = 0;
    let mut first_error = None;
    for task in tasks {
        match task.await {
            Ok(Ok(())) => completed += 1,
            Ok(Err(error)) => {
                first_error.get_or_insert(error);
            }
            Err(error) => {
                first_error.get_or_insert_with(|| {
                    ScaleStop::failed("concurrent_reader_join_failed", error)
                });
            }
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(ConcurrentReadEvidence {
        measurement_id,
        readers: CONCURRENT_READERS,
        local_readers: CONCURRENT_READERS / 2,
        foreign_readers: CONCURRENT_READERS / 2,
        completed_readers: completed,
        wall_ms: started.elapsed().as_millis(),
    })
}

fn assert_initial_sessions(metrics: DbClientSetMetrics) -> ScaleResult {
    if metrics.sessions_opened != 6
        || metrics.read_pool_size != DEFAULT_DB_READ_POOL_SIZE
        || metrics.active_readers != 0
        || metrics.reconnect_attempts != 0
        || metrics.reconnect_successes != 0
    {
        return Err(ScaleStop::failed(
            "initial_session_metrics_mismatch",
            format!("initial metrics: {metrics:?}"),
        ));
    }
    Ok(())
}

fn verify_session_metrics(before: DbClientSetMetrics, after: DbClientSetMetrics) -> ScaleResult {
    if after.sessions_opened != 6
        || after.read_pool_size != DEFAULT_DB_READ_POOL_SIZE
        || after.peak_readers != DEFAULT_DB_READ_POOL_SIZE
        || after.active_readers != 0
        || after.reconnect_attempts != 0
        || after.reconnect_successes != 0
        || after.write_queries != before.write_queries
        || after.admin_queries != before.admin_queries
    {
        return Err(ScaleStop::failed(
            "concurrent_session_metrics_mismatch",
            format!("before={before:?}; after={after:?}"),
        ));
    }
    Ok(())
}

fn require_revision_match(
    canonical: Option<MemoryRevision>,
    projection: MemoryRevision,
    label: &str,
) -> ScaleResult {
    if canonical != Some(projection) {
        return Err(ScaleStop::failed(
            "projection_revision_mismatch",
            format!(
                "{label}: canonical={:?}, projection={}",
                canonical.map(MemoryRevision::value),
                projection.value()
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
struct GateResult {
    gate: String,
    status: String,
    measurement_id: Option<String>,
    samples: usize,
    aggregate: String,
    l0_limit_ms: Option<f64>,
    l2_limit_ms: Option<f64>,
    l0_observed_ms: Option<f64>,
    l2_observed_ms: Option<f64>,
}

impl GateResult {
    fn not_run(gate: &str) -> Self {
        Self {
            gate: gate.to_owned(),
            status: "not_run".to_owned(),
            measurement_id: None,
            samples: 0,
            aggregate: "none".to_owned(),
            l0_limit_ms: None,
            l2_limit_ms: None,
            l0_observed_ms: None,
            l2_observed_ms: None,
        }
    }

    fn passed_without_latency(gate: &str, measurement_id: String, samples: usize) -> Self {
        Self {
            gate: gate.to_owned(),
            status: "passed".to_owned(),
            measurement_id: Some(measurement_id),
            samples,
            aggregate: "bounded_concurrency".to_owned(),
            l0_limit_ms: None,
            l2_limit_ms: None,
            l0_observed_ms: None,
            l2_observed_ms: None,
        }
    }
}

fn evaluate_gate(
    gate: &str,
    measurements: &QueryMeasurements,
    l0_limit_ms: f64,
    l2_limit_ms: f64,
    use_p95: bool,
) -> GateResult {
    let l0_observed_ms = if use_p95 {
        percentile_95(&measurements.l0_ms)
    } else {
        measurements.l0_ms.first().copied()
    };
    let l2_observed_ms = if use_p95 {
        percentile_95(&measurements.l2_ms)
    } else {
        measurements.l2_ms.first().copied()
    };
    let passed = l0_observed_ms.is_some_and(|value| value <= l0_limit_ms)
        && l2_observed_ms.is_some_and(|value| value <= l2_limit_ms);
    GateResult {
        gate: gate.to_owned(),
        status: if passed { "passed" } else { "failed" }.to_owned(),
        measurement_id: Some(measurements.measurement_id.clone()),
        samples: measurements.l0_ms.len(),
        aggregate: if use_p95 { "p95" } else { "first_sample" }.to_owned(),
        l0_limit_ms: Some(l0_limit_ms),
        l2_limit_ms: Some(l2_limit_ms),
        l0_observed_ms,
        l2_observed_ms,
    }
}

fn gate_detail(gate: &GateResult) -> String {
    format!(
        "{} {}: L0={:?}/{} ms, L2={:?}/{} ms, measurement_id={}",
        gate.gate,
        gate.aggregate,
        gate.l0_observed_ms,
        gate.l0_limit_ms.unwrap_or_default(),
        gate.l2_observed_ms,
        gate.l2_limit_ms.unwrap_or_default(),
        gate.measurement_id.as_deref().unwrap_or("none")
    )
}

fn percentile_95(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() * 95).div_ceil(100)).saturating_sub(1);
    sorted.get(index).copied()
}

#[derive(Debug, Serialize)]
struct ScaleArtifact {
    schema_version: &'static str,
    status: String,
    stop_reason: Option<String>,
    stop_detail: Option<String>,
    shutdown_error: Option<String>,
    measurement_id: String,
    exact_once: bool,
    provider_calls: u64,
    surrealdb_version: Option<String>,
    query_timeout_ms: u128,
    started_at_unix_nanos: i128,
    total_wall_ms: Option<u128>,
    corpus: CorpusArtifact,
    revisions: RevisionArtifact,
    seed_durations: SeedDurations,
    rebuild_durations: RebuildDurations,
    measurements: MeasurementArtifact,
    gates: GateArtifact,
    concurrency: Option<ConcurrentReadEvidence>,
    sessions: SessionArtifact,
}

impl ScaleArtifact {
    fn new() -> Self {
        Self {
            schema_version: "eliot-c7-03-scale-ladder-v1",
            status: "running".to_owned(),
            stop_reason: None,
            stop_detail: None,
            shutdown_error: None,
            measurement_id: format!("c7-03-scale:{}", WriteId::new_v7()),
            exact_once: true,
            provider_calls: 0,
            surrealdb_version: None,
            query_timeout_ms: QUERY_TIMEOUT.as_millis(),
            started_at_unix_nanos: OffsetDateTime::now_utc().unix_timestamp_nanos(),
            total_wall_ms: None,
            corpus: CorpusArtifact::default(),
            revisions: RevisionArtifact::default(),
            seed_durations: SeedDurations::default(),
            rebuild_durations: RebuildDurations::default(),
            measurements: MeasurementArtifact::default(),
            gates: GateArtifact::new(),
            concurrency: None,
            sessions: SessionArtifact::default(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct CorpusArtifact {
    local_project_id: Option<String>,
    foreign_project_id: Option<String>,
    pf1_logical_records: Option<usize>,
    pf1_historical_versions: Option<usize>,
    pf1_digest_blake3: Option<String>,
    logical_records: Option<usize>,
    historical_versions: Option<usize>,
    mixed_record_kinds: Option<usize>,
    digest_blake3: Option<String>,
    foreign_canary_digest_blake3: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct RevisionArtifact {
    pf1_canonical: Option<u64>,
    pf1_projection: Option<u64>,
    final_canonical: Option<u64>,
    final_projection: Option<u64>,
    foreign_canonical: Option<u64>,
    foreign_projection: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
#[allow(clippy::struct_field_names)]
struct SeedDurations {
    pf1_ms: Option<u128>,
    predicted_100k_ms: Option<u128>,
    final_growth_ms: Option<u128>,
    total_ms: Option<u128>,
}

#[derive(Debug, Default, Serialize)]
struct RebuildDurations {
    pf1_ms: Option<u128>,
    final_ms: Option<u128>,
}

#[derive(Debug, Default, Serialize)]
struct MeasurementArtifact {
    pf1: Option<QueryMeasurements>,
    final_25: Option<QueryMeasurements>,
}

#[derive(Debug, Serialize)]
struct GateArtifact {
    pf1: GateResult,
    pf2: GateResult,
    pf3: GateResult,
    r01: GateResult,
    concurrent_readers: GateResult,
}

impl GateArtifact {
    fn new() -> Self {
        Self {
            pf1: GateResult::not_run("PF1"),
            pf2: GateResult::not_run("PF2"),
            pf3: GateResult::not_run("PF3"),
            r01: GateResult::not_run("R01"),
            concurrent_readers: GateResult::not_run("G6"),
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct SessionArtifact {
    initial: Option<DbClientSetMetrics>,
    before_concurrency: Option<DbClientSetMetrics>,
    after_concurrency: Option<DbClientSetMetrics>,
    before_shutdown: Option<DbClientSetMetrics>,
    after_shutdown: Option<DbClientSetMetrics>,
}

#[derive(Debug)]
struct ScaleStop {
    code: &'static str,
    detail: String,
    slo_not_met: bool,
}

impl ScaleStop {
    fn failed(code: &'static str, detail: impl Display) -> Self {
        Self {
            code,
            detail: detail.to_string(),
            slo_not_met: false,
        }
    }

    fn slo(code: &'static str, detail: impl Display) -> Self {
        Self {
            code,
            detail: detail.to_string(),
            slo_not_met: true,
        }
    }
}

impl Display for ScaleStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for ScaleStop {}

fn required_result_path() -> Result<PathBuf, Box<dyn Error>> {
    let value = std::env::var("ELIOT_COGNITIVE_FIELD_RESULT_PATH").map_err(
        |_| "ELIOT_COGNITIVE_FIELD_RESULT_PATH is required to prevent an unchanged scale rerun",
    )?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("ELIOT_COGNITIVE_FIELD_RESULT_PATH must be absolute".into());
    }
    Ok(path)
}

fn create_initial_artifact(path: &Path, artifact: &ScaleArtifact) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let encoded = serde_json::to_vec_pretty(artifact)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "refusing unchanged scale rerun because result artifact already exists or cannot be created at {}: {error}",
                    path.display()
                ),
            )
        })?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn checkpoint(path: &Path, artifact: &ScaleArtifact) -> ScaleResult {
    let encoded = serde_json::to_vec_pretty(artifact)
        .map_err(|error| ScaleStop::failed("artifact_encode_failed", error))?;
    std::fs::write(path, [encoded.as_slice(), b"\n"].concat())
        .map_err(|error| ScaleStop::failed("artifact_checkpoint_failed", error))
}

fn finish_artifact(
    path: &Path,
    artifact: &mut ScaleArtifact,
    started: Instant,
    stop: &ScaleStop,
    shutdown_error: Option<String>,
) -> Result<(), Box<dyn Error>> {
    artifact.status = if stop.slo_not_met {
        "slo_not_met".to_owned()
    } else {
        "failed".to_owned()
    };
    artifact.stop_reason = Some(stop.code.to_owned());
    artifact.stop_detail = Some(stop.detail.clone());
    artifact.shutdown_error = shutdown_error;
    artifact.total_wall_ms = Some(started.elapsed().as_millis());
    checkpoint(path, artifact).map_err(|error| Box::new(error) as Box<dyn Error>)
}

#[allow(clippy::print_stdout)]
fn print_artifact(artifact: &ScaleArtifact) -> Result<(), Box<dyn Error>> {
    println!("{}", serde_json::to_string_pretty(artifact)?);
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
        policy_snapshot_id: Some("policy:c7-03-scale-ladder".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "c7-03-scale-ladder".to_owned(),
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
