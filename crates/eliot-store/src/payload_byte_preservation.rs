//! Issue #10 store-edge byte preservation (slice R5-#10-A).
//!
//! Historical discriminator (2026-08-05, `SurrealDB` 3.1.4): JSON strings shaped
//! like ``prefix:value-with-hyphen`` came back truncated (e.g.
//! ``memory:operator-runtime-proof`` read back as ``memory:operator``) through the
//! JSON-RPC variable materialization path. Probes on the exact current path
//! confirmed the mechanism on current `main`: the coercion happens at RPC var
//! materialization, before any query executes (`RETURN $v` already returns the
//! truncated value and `type::is_string($v)` is false), so no query-side cast
//! can recover the bytes. The canonical write path therefore carries free-text
//! fields as char-fragment arrays (`envelope_with_text_fragments`) and the
//! `apply_write_envelope` template rejoins them with `array::join(..., '')` —
//! the same mechanism already used for reference/handle fields.
//!
//! This slice covers the free-text `String` fields of the canonical envelope
//! write path: task title; source uri/excerpt; evidence summary; tool
//! name/observation; claim statement; verifier/summary; failure summary.
//!
//! Proof ceiling and remainder (still open on #10): arbitrary JSON `payload`
//! values (only record-shaped string leaves are affected; they need a
//! recursive encoding designed separately), the governed L2/evidence read
//! path, export/import round-trips, remaining write templates outside
//! `apply_write_envelope`, and the historical-data inventory/replay
//! disposition from #10 items 3-7.

use crate::canonical_store::envelope_with_text_fragments;
use crate::{CanonicalClaimCard, CanonicalStore, CanonicalToolObservation, DbClientSet};
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, EpistemicStatus, EvidenceAtomInput, EvidenceId,
    FailureFingerprintInput, GovernorConfig, IdempotencyOptions, LifecycleStatus,
    LifecycleWriteOptions, MemoryWriteEnvelope, OperationId, ProjectId, ProjectSequence,
    SemanticCommandKind, SourceSnapshotInput, TaintClass, TaskContractInput, TaskContractStatus,
    TaskId, ToolObservationInput, VerificationId, VerificationResult, VerificationRunInput,
    Visibility, WriteId,
};
use secrecy::SecretString;
use serde_json::{Map, Value, json};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const TRANSPORT_BIND_SAFE: &str = "127.0.0.1:18097";
const TRANSPORT_BIND_FRAGMENTS: &str = "127.0.0.1:18095";
const CANON_BIND: &str = "127.0.0.1:18096";
const SCRATCH_NAMESPACE: &str = "eliot_r5_i10";
const SCRATCH_USER: &str = "root";

/// Historical matrix from #10 plus adversarial record-like variants.
fn matrix() -> Vec<(String, Value)> {
    [
        "alpha-beta",
        "f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240",
        "observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240",
        "memory:operator-runtime-proof",
        "sha256:abc-def-0123456789",
        "collective:9f2c4a1e-8b3d-4c5e-9a1f-2d3c4b5a6978:1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
        "https://example.invalid/collective/run?task=9f2c4a1e#frag-ment",
        "C:\\ProgramData\\Eliot\\evidence\\collective-proof.json",
        "table:with:two:colons",
        "table:",
        ":bare-id",
        "table:id with space",
        "table:123",
        "table:007",
        "table:true",
        "table:none",
        "table:NULL",
        "table:1e3",
        "table:αβγ-unicode",
        "table:quote\"tick'apos",
        "table:line\nbreak",
        "SELECT * FROM payload_probe",
        "type::record('payload_probe', 'injected')",
        "",
        "table:a-very-long-record-like-suffix-with-many-hyphenated-segments-0123456789-abcdef",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, value)| (format!("m{index:02}"), Value::String(value.to_owned())))
    .collect()
}

/// Matrix entries that survive the vendor boundary verbatim as bare strings
/// (no record-shaped truncation observed): the passing subset pins the safe
/// boundary our unprotected bindings must stay inside.
fn safe_suffixes() -> Vec<&'static str> {
    vec![
        "m00", "m01", "m06", "m07", "m09", "m10", "m12", "m14", "m15", "m16", "m17", "m18", "m21",
        "m22", "m23",
    ]
}

/// Entries the vendor boundary truncates as bare strings are pinned by the
/// fragment round-trip test below, which covers the whole matrix.
fn require_live_edge() -> TestResult<String> {
    if std::env::var("ELIOT_SURREAL_LIVE_EDGE").as_deref() != Ok("1") {
        return Err("set ELIOT_SURREAL_LIVE_EDGE=1 to run this live store-edge proof".into());
    }
    std::env::var("ELIOT_SURREAL_EXE")
        .map_err(|_| "ELIOT_SURREAL_EXE must point at surreal.exe for this live proof".into())
}

/// Owns a scratch `surreal.exe` child and its rocksdb directory. Killing on
/// drop keeps a failed run from orphaning a server holding the temp data root.
struct ScratchServer {
    child: Option<Child>,
    storage_dir: PathBuf,
}

impl ScratchServer {
    fn disarm(&mut self) {
        self.child.take();
    }
}

impl Drop for ScratchServer {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_dir_all(&self.storage_dir);
    }
}

fn spawn_scratch(exe: &str, bind: &str, test_tag: &str) -> TestResult<(ScratchServer, String)> {
    let run_id = Uuid::new_v4().as_simple().to_string();
    let storage_dir = std::env::temp_dir().join(format!("eliot-{test_tag}-{run_id}"));
    std::fs::create_dir_all(&storage_dir)?;
    let storage_arg = format!(
        "rocksdb:{}",
        storage_dir.to_string_lossy().replace('\\', "/")
    );
    let password = format!("probe-{run_id}");
    let mut spawn = Command::new(exe);
    spawn
        .env_clear()
        .env("SURREAL_USER", SCRATCH_USER)
        .env("SURREAL_PASS", &password)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env(
            "SystemRoot",
            std::env::var_os("SystemRoot").unwrap_or_default(),
        )
        .arg("start")
        .arg("--bind")
        .arg(bind)
        .arg("--log")
        .arg("error")
        .arg("--deny-net")
        .arg("--no-banner")
        .arg("--")
        .arg(&storage_arg)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    spawn.creation_flags(0x0800_0000);
    let child = spawn.spawn().map_err(|error| {
        let _ = std::fs::remove_dir_all(&storage_dir);
        format!("failed to spawn scratch surreal ({exe}): {error}")
    })?;
    Ok((
        ScratchServer {
            child: Some(child),
            storage_dir,
        },
        password,
    ))
}

fn first_ok_result(raw: &Value) -> TestResult<&Value> {
    let responses = raw.as_array().ok_or("query response was not an array")?;
    let first = responses.first().ok_or("query response array was empty")?;
    let status = first
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("<missing status>");
    if status != "OK" {
        return Err(format!("query status was {status}: {first}").into());
    }
    first
        .get("result")
        .ok_or_else(|| format!("query response had no result field: {first}").into())
}

fn unit_envelope() -> MemoryWriteEnvelope {
    use eliot_types::ProjectSequence;
    MemoryWriteEnvelope {
        write_id: WriteId::new_v7(),
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id: ProjectId::new_v7(),
        task_id: None,
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash: "input-hash-r5-i10".to_owned(),
        policy_snapshot_id: None,
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "r5-i10-unit".to_owned(),
        authority: "unit-test".to_owned(),
        task_contracts: vec![TaskContractInput {
            task_id: TaskId::new_v7(),
            title: "memory:operator-runtime-proof".to_owned(),
            status: TaskContractStatus::Open,
            acceptance_items: Vec::new(),
            expected_revision: None,
            action_lease_id: None,
            understanding_proof_hash: None,
            action_provenance: None,
            memory_grant_redemptions: Vec::new(),
            observation_ids: Vec::new(),
            verification_ids: Vec::new(),
            verification_scopes: Vec::new(),
            completion_proof: None,
            completion_write_id: None,
        }],
        source_snapshots: vec![SourceSnapshotInput {
            source_id: "src-unit".to_owned(),
            uri: "observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240".to_owned(),
            authority: "unit-test".to_owned(),
            content_hash: "hash-unit".to_owned(),
            excerpt: String::new(),
        }],
        evidence_atoms: vec![EvidenceAtomInput {
            evidence_id: EvidenceId::new_v7(),
            source_id: "src-unit".to_owned(),
            summary: "table:αβγ-unicode".to_owned(),
            payload: json!({ "plain": "no-colon-here" }),
        }],
        tool_observations: vec![ToolObservationInput {
            observation_id: "obs-unit".to_owned(),
            tool_name: "table:quote\"tick".to_owned(),
            observation: "sha256:abc-def-0123456789".to_owned(),
            payload: json!({ "n": 1 }),
        }],
        failures: vec![FailureFingerprintInput {
            fingerprint: "fp-unit".to_owned(),
            summary: "table:line\nbreak".to_owned(),
            payload: Value::Null,
        }],
        claims: vec![ClaimCardInput {
            claim_id: ClaimId::new_v7(),
            statement: "collective:9f2c:1a2b".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({ "plain": "ok" }),
        }],
        verification_runs: vec![VerificationRunInput {
            verification_id: VerificationId::new_v7(),
            claim_id: None,
            verifier: "table:with:two:colons".to_owned(),
            result: VerificationResult::Passed,
            summary: String::new(),
            payload: Value::Null,
        }],
        relations: Vec::new(),
        lifecycle: LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    }
}

#[test]
fn envelope_text_fragments_attach_char_splits() -> TestResult {
    let envelope = unit_envelope();
    let value = envelope_with_text_fragments(&envelope)?;
    let get = |collection: &str, field: &str| -> TestResult<(String, Vec<String>)> {
        let item = value
            .get(collection)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .ok_or(format!("missing {collection}[0]"))?;
        let text = item
            .get(field)
            .and_then(Value::as_str)
            .ok_or(format!("missing {collection}[0].{field}"))?
            .to_owned();
        let fragments: Vec<String> = item
            .get(format!("{field}_fragments"))
            .and_then(Value::as_array)
            .ok_or(format!("missing {collection}[0].{field}_fragments"))?
            .iter()
            .map(|fragment| {
                fragment
                    .as_str()
                    .ok_or(format!("non-string fragment in {collection}[0].{field}"))
                    .map(str::to_owned)
            })
            .collect::<Result<_, _>>()?;
        Ok((text, fragments))
    };

    for (collection, field) in [
        ("task_contracts", "title"),
        ("source_snapshots", "uri"),
        ("source_snapshots", "excerpt"),
        ("evidence_atoms", "summary"),
        ("tool_observations", "tool_name"),
        ("tool_observations", "observation"),
        ("claims", "statement"),
        ("verification_runs", "verifier"),
        ("verification_runs", "summary"),
        ("failures", "summary"),
    ] {
        let (text, fragments) = get(collection, field)?;
        let expected: Vec<String> = text.chars().map(|c| c.to_string()).collect();
        if fragments != expected {
            return Err(format!("{collection}[0].{field}_fragments mismatch for {text:?}").into());
        }
        if fragments.join("").as_str() != text {
            return Err(format!("{collection}[0].{field} fragments do not rejoin").into());
        }
    }
    // Empty strings still attach (empty join reconstitutes exactly).
    let (_, empty_fragments) = get("source_snapshots", "excerpt")?;
    if !empty_fragments.is_empty() {
        return Err("empty excerpt must attach an empty fragments array".into());
    }
    Ok(())
}

async fn transport(
    bind: &str,
) -> TestResult<(ScratchServer, crate::surreal_rpc::SurrealRpcTransport)> {
    use crate::surreal_rpc::SurrealRpcTransport;
    let exe = require_live_edge()?;
    let (scratch, password) = spawn_scratch(&exe, bind, "r5-i10")?;
    let endpoint = format!("ws://{bind}/rpc");
    let mut config = GovernorConfig::default().db.surreal;
    config.endpoint = endpoint;
    config.query_timeout_ms = 10_000;
    let deadline = Instant::now() + Duration::from_mins(1);
    let transport = loop {
        match SurrealRpcTransport::connect(&config, 1_000).await {
            Ok(transport) => break transport,
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(format!("scratch surreal was not ready: {error}").into());
                }
                sleep(Duration::from_millis(250)).await;
            }
        }
    };
    transport
        .signin(SCRATCH_USER, &SecretString::from(password.clone()))
        .await
        .map_err(|error| format!("scratch signin failed: {error}"))?;
    transport
        .use_ns_db(SCRATCH_NAMESPACE, "payload_probe")
        .await
        .map_err(|error| format!("scratch USE failed: {error}"))?;
    Ok((scratch, transport))
}

async fn stop_scratch(scratch: &mut ScratchServer) {
    if let Some(child) = scratch.child.as_mut() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    scratch.disarm();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live edge: requires ELIOT_SURREAL_LIVE_EDGE=1 and ELIOT_SURREAL_EXE pointing at surreal.exe"]
async fn bound_var_safe_strings_survive_verbatim() -> TestResult {
    let (mut scratch, transport) = transport(TRANSPORT_BIND_SAFE).await?;
    let outcome = async {
        let cases = matrix();
        let safe = safe_suffixes();
        if safe.len() != 15 {
            return Err(format!(
                "safe-subset list drifted ({} entries); re-verify the vendor boundary",
                safe.len()
            )
            .into());
        }
        let mut doc = Map::new();
        let mut nested = Map::new();
        let mut items: Vec<Value> = Vec::new();
        for (suffix, value) in &cases {
            if safe.contains(&suffix.as_str()) {
                doc.insert(format!("top_{suffix}"), value.clone());
                nested.insert(format!("inner_{suffix}"), value.clone());
                items.push(value.clone());
            }
        }
        doc.insert("nested".to_owned(), Value::Object(nested));
        doc.insert("items".to_owned(), Value::Array(items.clone()));
        let create_raw = transport
            .query(
                "CREATE payload_probe CONTENT $doc RETURN *;",
                json!({ "doc": doc }),
            )
            .await
            .map_err(|error| format!("CREATE failed: {error}"))?;
        let created_id_value = first_ok_result(&create_raw)?
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("id"))
            .ok_or("CREATE returned no id")?;
        let created_id = match created_id_value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let read_raw = transport
            .query("SELECT * FROM $id;", json!({ "id": created_id }))
            .await
            .map_err(|error| format!("direct readback failed: {error}"))?;
        let row = first_ok_result(&read_raw)?
            .as_array()
            .and_then(|rows| rows.first())
            .ok_or("direct readback returned no row")?;
        let mut mismatches = Vec::new();
        for (suffix, expected) in &cases {
            if !safe.contains(&suffix.as_str()) {
                continue;
            }
            let top_key = format!("top_{suffix}");
            if row.get(&top_key).unwrap_or(&Value::Null) != expected {
                mismatches.push(format!("top-level {top_key} changed"));
            }
            let inner_key = format!("inner_{suffix}");
            if row
                .get("nested")
                .and_then(|nested| nested.get(inner_key.as_str()))
                .unwrap_or(&Value::Null)
                != expected
            {
                mismatches.push(format!("nested {inner_key} changed"));
            }
        }
        let read_items = row
            .get("items")
            .and_then(Value::as_array)
            .ok_or("readback row had no items array")?;
        if read_items != &items {
            mismatches.push("array position changed".to_owned());
        }
        let _cleanup = transport
            .query("DELETE payload_probe;", Value::Object(Map::new()))
            .await;
        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(format!("safe-subset byte changes: {}", mismatches.join("; ")).into())
        }
    }
    .await;
    stop_scratch(&mut scratch).await;
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live edge: requires ELIOT_SURREAL_LIVE_EDGE=1 and ELIOT_SURREAL_EXE pointing at surreal.exe"]
async fn fragment_encoding_round_trips_record_shaped_strings() -> TestResult {
    let (mut scratch, transport) = transport(TRANSPORT_BIND_FRAGMENTS).await?;
    let outcome = async {
        let cases = matrix();
        let mut mismatches = Vec::new();
        for (suffix, expected) in &cases {
            let fragments: Vec<String> = expected
                .as_str()
                .ok_or("matrix case was not a string")?
                .chars()
                .map(|c| c.to_string())
                .collect();
            // Mirrors the canonical template idiom exactly.
            let write_raw = transport
                .query(
                    "CREATE probe_t CONTENT { rebuilt: <string> array::join($fragments.map(|$fragment| <string> $fragment), '') } RETURN rebuilt;",
                    json!({ "fragments": fragments }),
                )
                .await
                .map_err(|error| format!("fragment write failed for {suffix}: {error}"))?;
            let rebuilt = first_ok_result(&write_raw)?
                .as_array()
                .and_then(|rows| rows.first())
                .and_then(|row| row.get("rebuilt"))
                .ok_or("fragment write returned no rebuilt field")?;
            if rebuilt != expected {
                mismatches.push(format!("{suffix}: wrote {expected}, read {rebuilt}"));
            }
        }
        let _cleanup = transport
            .query("DELETE probe_t;", Value::Object(Map::new()))
            .await;
        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "fragment round-trip failures ({}):\n{}",
                mismatches.len(),
                mismatches.join("\n")
            )
            .into())
        }
    }
    .await;
    stop_scratch(&mut scratch).await;
    outcome
}

fn canon_config() -> TestResult<eliot_types::SurrealServerConfig> {
    if std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() != Ok("1") {
        return Err(
            "ELIOT_DISABLE_REAL_PROVIDER=1 is required for this provider-free live proof".into(),
        );
    }
    let exe = require_live_edge()?;
    let run_id = Uuid::new_v4().as_simple().to_string();
    let storage_dir = std::env::temp_dir().join(format!("eliot-r5-i10-canon-{run_id}"));
    std::fs::create_dir_all(&storage_dir)?;
    let mut config = GovernorConfig::default().db.surreal;
    config.exe = exe;
    config.bind = CANON_BIND.to_owned();
    config.endpoint = format!("ws://{CANON_BIND}/rpc");
    config.storage = format!(
        "rocksdb:{}",
        storage_dir.to_string_lossy().replace('\\', "/")
    );
    config.ns = SCRATCH_NAMESPACE.to_owned();
    config.db = "canon_probe".to_owned();
    config.user = SCRATCH_USER.to_owned();
    config.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")
        .map_err(|_| "ELIOT_TEST_SURREAL_PASSWORD_FILE is required for this live proof")?;
    config.query_timeout_ms = 20_000;
    config.startup_timeout_ms = 90_000;
    Ok(config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live edge: requires ELIOT_SURREAL_LIVE_EDGE=1, ELIOT_SURREAL_EXE, ELIOT_DISABLE_REAL_PROVIDER=1 and ELIOT_TEST_SURREAL_PASSWORD_FILE"]
async fn canonical_envelope_free_text_survives_round_trip() -> TestResult {
    let config = canon_config()?;
    let clients = Arc::new(DbClientSet::start(config).await?);
    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let body_result = run_canon_cases(&store).await;
    let shutdown_result = clients.shutdown().await;
    let shutdown_outcome: TestResult = shutdown_result
        .map(|_| ())
        .map_err(|error| format!("client-set shutdown failed: {error}").into());
    body_result.and(shutdown_outcome)
}

#[allow(clippy::too_many_lines)]
async fn run_canon_cases(store: &CanonicalStore) -> TestResult {
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let write_id = WriteId::new_v7();
    let observation_text = "memory:operator-runtime-proof";
    let tool_name = "table:with:two:colons";
    let claim_text = "observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240";
    let verifier_name = "sha256:abc-def-0123456789";
    let verification_summary = "collective:9f2c:1a2b";
    let task_title =
        "table:a-very-long-record-like-suffix-with-many-hyphenated-segments-0123456789";
    let source_uri = "observation:src-9f2c4a1e";
    let source_excerpt = "memory:excerpt-proof";
    let evidence_summary = "table:evidence-summary-proof";
    let failure_summary = "sha256:failure-proof-1";
    let observation_id = format!("obs-{}", Uuid::new_v4().as_simple());
    let claim_id = ClaimId::new_v7();
    let verification_id = VerificationId::new_v7();
    let task_id = TaskId::new_v7();
    let envelope = MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash: "input-hash-r5-i10-canon".to_owned(),
        policy_snapshot_id: None,
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "r5-i10-canon".to_owned(),
        authority: "live-proof".to_owned(),
        task_contracts: vec![TaskContractInput {
            task_id,
            title: task_title.to_owned(),
            status: TaskContractStatus::Open,
            acceptance_items: Vec::new(),
            expected_revision: None,
            action_lease_id: None,
            understanding_proof_hash: None,
            action_provenance: None,
            memory_grant_redemptions: Vec::new(),
            observation_ids: Vec::new(),
            verification_ids: Vec::new(),
            verification_scopes: Vec::new(),
            completion_proof: None,
            completion_write_id: None,
        }],
        source_snapshots: vec![SourceSnapshotInput {
            source_id: "src-r5-i10".to_owned(),
            uri: source_uri.to_owned(),
            authority: "live-proof".to_owned(),
            content_hash: "content-hash-r5-i10".to_owned(),
            excerpt: source_excerpt.to_owned(),
        }],
        evidence_atoms: vec![EvidenceAtomInput {
            evidence_id: EvidenceId::new_v7(),
            source_id: "src-r5-i10".to_owned(),
            summary: evidence_summary.to_owned(),
            payload: json!({ "plain": "no-colon-here", "n": 7 }),
        }],
        tool_observations: vec![ToolObservationInput {
            observation_id: observation_id.clone(),
            tool_name: tool_name.to_owned(),
            observation: observation_text.to_owned(),
            payload: json!({ "plain": "ok" }),
        }],
        failures: vec![FailureFingerprintInput {
            fingerprint: "fp-r5-i10".to_owned(),
            summary: failure_summary.to_owned(),
            payload: Value::Null,
        }],
        claims: vec![ClaimCardInput {
            claim_id,
            statement: claim_text.to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({ "plain": "ok" }),
        }],
        verification_runs: vec![VerificationRunInput {
            verification_id,
            claim_id: Some(claim_id),
            verifier: verifier_name.to_owned(),
            result: VerificationResult::Passed,
            summary: verification_summary.to_owned(),
            payload: Value::Null,
        }],
        relations: Vec::new(),
        lifecycle: LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    };
    store.apply_write_envelope(&envelope).await?;

    let mut mismatches = Vec::new();
    let observations: Vec<CanonicalToolObservation> =
        store.tool_observations_by_write_id(&write_id).await?;
    let Some(observation) = observations
        .iter()
        .find(|item| item.observation_id == observation_id)
    else {
        return Err("canonical write did not store the tool observation".into());
    };
    if observation.observation.as_str() != observation_text {
        mismatches.push(format!(
            "observation: wrote {observation_text:?}, read {:?}",
            observation.observation
        ));
    }
    if observation.tool_name.as_str() != tool_name {
        mismatches.push(format!(
            "tool_name: wrote {tool_name:?}, read {:?}",
            observation.tool_name
        ));
    }
    let claim: CanonicalClaimCard = store
        .claim_card_by_id(project_id, claim_id)
        .await?
        .ok_or("canonical write did not store the claim card")?;
    if claim.statement.as_str() != claim_text {
        mismatches.push(format!(
            "claim statement: wrote {claim_text:?}, read {:?}",
            claim.statement
        ));
    }
    let verification = store
        .verification_run_by_id(verification_id)
        .await?
        .ok_or("canonical write did not store the verification run")?;
    if verification.verifier.as_str() != verifier_name {
        mismatches.push(format!(
            "verifier: wrote {verifier_name:?}, read {:?}",
            verification.verifier
        ));
    }
    if verification.summary.as_str() != verification_summary {
        mismatches.push(format!(
            "verification summary: wrote {verification_summary:?}, read {:?}",
            verification.summary
        ));
    }
    let contract = store
        .task_contract_by_id(task_id)
        .await?
        .ok_or("canonical write did not store the task contract")?;
    if contract.title.as_str() != task_title {
        mismatches.push(format!(
            "task title: wrote {task_title:?}, read {:?}",
            contract.title
        ));
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "canonical free-text round-trip failures:\n{}",
            mismatches.join("\n")
        )
        .into())
    }
}
