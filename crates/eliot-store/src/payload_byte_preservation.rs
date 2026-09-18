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
//! This slice covers exactly the ten free-text `String` fields of the
//! canonical envelope write path named in `envelope_with_text_fragments`
//! (`canonical_store.rs`): task `title`; source `uri`/`excerpt`; evidence
//! `summary`; tool `tool_name`/`observation`; claim `statement`;
//! verification `verifier`/`summary`; failure `summary`. Nothing else in the
//! Store claims transport safety from this slice: this is a bounded slice,
//! NOT a complete core fix for the corruption class.
//!
//! QUEUED remainder (still open on #10; template lines verified against the
//! current checkout on 2026-09-18 — the items below are explicitly NOT
//! covered here):
//! - arbitrary JSON `payload` leaves bound directly in
//!   `surql/apply_write_envelope.surql`: `$evidence.payload` (:298),
//!   `$observation.payload` (:323), `$claim.payload` (:457),
//!   `$verification.payload` (:483), `$failure.payload` (:506); the
//!   `canonical_record.receipt_body` at :428 is likewise payload-derived.
//!   Only record-shaped string leaves are affected there; they need the
//!   recursive encoding designed separately.
//! - other mutation templates that still bind caller-controlled strings
//!   directly (bare `$var` or `<string> $var`, no fragment encoding):
//!   `apply_observability.surql`:19,39,60,63,111-121;
//!   `upsert_cue_rows.surql`:16-27; `upsert_memory_search_projection.surql`:25,
//!   36-44 (incl. `preview`/`search_text`/`search_document`/`cue_text`/
//!   `scope_text`/`concept_text` at :36-41);
//!   `block_cognitive_projection.surql`:49,66 (`$reason`);
//!   `fail_cognitive_projection_retryable.surql`:70-74 (`$error`);
//!   `complete_cognitive_projection_through.surql`:64-69 (rebinds a stored
//!   `blocked_reason`); `publish_cognitive_projection_family_state.surql`:58-66;
//!   `upsert_ul_task_ledger.surql`:19-42;
//!   `assign_ul_experiment_arm.surql`:14-17,25-34;
//!   `upsert_ul_experiment_assignment_explicit.surql`:19-28;
//!   `upsert_ul_task_class_policy.surql`:2 (`CONTENT $policy`);
//!   `upsert_ul_artifact_dirty.surql`:2 (`CONTENT $state`);
//!   `replace_ul_reverse_dependencies.surql`:7-14.
//!
//! Proof ceiling and remainder (still open on #10): the recursive `payload`
//! encoding above, the governed L2/evidence read path, export/import
//! round-trips, the remaining write templates listed above, and the
//! historical-data inventory/replay disposition from #10 items 3-7.
//!
//! Enforced test configurations (feature `live-edge` on `eliot-store`):
//! 1. default `cargo test -p eliot-store` — the three live tests
//!    (`bound_var_safe_strings_survive_verbatim`,
//!    `fragment_encoding_round_trips_record_shaped_strings`,
//!    `canonical_envelope_free_text_survives_round_trip`) plus their
//!    live-only helpers are not compiled; the suite stays green without a
//!    backend.
//! 2. live proof `cargo test -p eliot-store --features live-edge` with
//!    `ELIOT_SURREAL_LIVE_EDGE=1`, `ELIOT_SURREAL_EXE` (surreal.exe 3.1.4),
//!    `ELIOT_DISABLE_REAL_PROVIDER=1`, and
//!    `ELIOT_TEST_SURREAL_PASSWORD_FILE` — backend absence or misconfig
//!    MUST fail via the existing fail-gates (`require_live_edge` /
//!    `canon_config`); silent skips and `#[ignore]` are forbidden.

use crate::canonical_store::envelope_with_text_fragments;
#[cfg(all(test, feature = "live-edge"))]
use crate::{CanonicalClaimCard, CanonicalStore, CanonicalToolObservation, DbClientSet};
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, EpistemicStatus, EvidenceAtomInput, EvidenceId,
    FailureFingerprintInput, IdempotencyOptions, LifecycleStatus, LifecycleWriteOptions,
    MemoryWriteEnvelope, OperationId, ProjectId, SemanticCommandKind, SourceSnapshotInput,
    TaintClass, TaskContractInput, TaskContractStatus, TaskId, ToolObservationInput,
    VerificationId, VerificationResult, VerificationRunInput, Visibility, WriteId,
};
#[cfg(all(test, feature = "live-edge"))]
use eliot_types::{FetchAtomsL2Request, GovernorConfig, ProjectSequence, ReadConsistencyMode};
#[cfg(all(test, feature = "live-edge"))]
use secrecy::SecretString;
#[cfg(all(test, feature = "live-edge"))]
use serde_json::Map;
use serde_json::{Value, json};
use std::error::Error;
#[cfg(all(test, feature = "live-edge"))]
use std::path::PathBuf;
#[cfg(all(test, feature = "live-edge"))]
use std::sync::Arc;
#[cfg(all(test, feature = "live-edge"))]
use std::time::{Duration, Instant};
use time::OffsetDateTime;
#[cfg(all(test, feature = "live-edge"))]
use tokio::process::{Child, Command};
#[cfg(all(test, feature = "live-edge"))]
use tokio::time::sleep;
#[cfg(all(test, feature = "live-edge"))]
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[cfg(all(test, feature = "live-edge"))]
const TRANSPORT_BIND_SAFE: &str = "127.0.0.1:18097";
#[cfg(all(test, feature = "live-edge"))]
const TRANSPORT_BIND_FRAGMENTS: &str = "127.0.0.1:18095";
#[cfg(all(test, feature = "live-edge"))]
const CANON_BIND: &str = "127.0.0.1:18096";
#[cfg(all(test, feature = "live-edge"))]
const SCRATCH_NAMESPACE: &str = "eliot_r5_i10";
#[cfg(all(test, feature = "live-edge"))]
const SCRATCH_USER: &str = "root";

/// Historical matrix from #10 plus adversarial record-like variants, with
/// astral-plane and combining-mark adversaries appended (`m25`..`m28`) so the
/// `m00`..`m24` indices pinned by `safe_suffixes` stay stable.
#[cfg(all(test, feature = "live-edge"))]
fn matrix() -> Vec<(String, Value)> {
    let mut cases: Vec<(String, Value)> = [
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
    .collect();
    // Astral scalar embedded between a record-like head and tail.
    // Astral scalar inside a record-shaped value.
    // Combining mark at a record-like boundary (`e` + U+0301).
    // One long tail: 256 astral scalars plus a 4 KiB record-like suffix.
    let astral_tail = format!(
        "table:{}:{}",
        "\u{1F642}".repeat(256),
        "a-very-long-record-like-suffix-".repeat(128)
    );
    cases.extend(
        [
            "table:before-\u{1F642}-after-record-tail".to_owned(),
            "memory:\u{1D11E}:operator-runtime-proof".to_owned(),
            "e\u{301}:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240".to_owned(),
            astral_tail,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, value)| (format!("m{:02}", index + 25), Value::String(value))),
    );
    cases
}

/// Matrix entries that survive the vendor boundary verbatim as bare strings
/// (no record-shaped truncation observed): the passing subset pins the safe
/// boundary our unprotected bindings must stay inside.
#[cfg(all(test, feature = "live-edge"))]
fn safe_suffixes() -> Vec<&'static str> {
    vec![
        "m00", "m01", "m06", "m07", "m09", "m10", "m12", "m14", "m15", "m16", "m17", "m18", "m21",
        "m22", "m23",
    ]
}

/// Entries the vendor boundary truncates as bare strings are pinned by the
/// fragment round-trip test below, which covers the whole matrix.
#[cfg(all(test, feature = "live-edge"))]
fn require_live_edge() -> TestResult<String> {
    if std::env::var("ELIOT_SURREAL_LIVE_EDGE").as_deref() != Ok("1") {
        return Err("set ELIOT_SURREAL_LIVE_EDGE=1 to run this live store-edge proof".into());
    }
    std::env::var("ELIOT_SURREAL_EXE")
        .map_err(|_| "ELIOT_SURREAL_EXE must point at surreal.exe for this live proof".into())
}

/// Owns a scratch `surreal.exe` child and its rocksdb directory. Killing on
/// drop keeps a failed run from orphaning a server holding the temp data root.
#[cfg(all(test, feature = "live-edge"))]
struct ScratchServer {
    child: Option<Child>,
    storage_dir: PathBuf,
}

#[cfg(all(test, feature = "live-edge"))]
impl ScratchServer {
    fn disarm(&mut self) {
        self.child.take();
    }
}

#[cfg(all(test, feature = "live-edge"))]
impl Drop for ScratchServer {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_dir_all(&self.storage_dir);
    }
}

#[cfg(all(test, feature = "live-edge"))]
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

#[cfg(all(test, feature = "live-edge"))]
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

/// Astral-plane scalars and combining marks survive fragmentation as whole
/// scalar values: every fragment is exactly one Unicode scalar, so no UTF-8
/// code unit is ever split and a combining mark never detaches from its
/// fragment boundary.
#[test]
fn envelope_text_fragments_preserve_astral_and_combining() -> TestResult {
    let astral_smile = "table:before-\u{1F642}-after-record-tail";
    let astral_clef = "memory:\u{1D11E}:operator-runtime-proof";
    let combining = "e\u{301}:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240";
    let mut envelope = unit_envelope();
    envelope.task_contracts[0].title = astral_smile.to_owned();
    envelope.tool_observations[0].observation = astral_clef.to_owned();
    envelope.claims[0].statement = combining.to_owned();
    let value = envelope_with_text_fragments(&envelope)?;
    for (collection, field, text) in [
        ("task_contracts", "title", astral_smile),
        ("tool_observations", "observation", astral_clef),
        ("claims", "statement", combining),
    ] {
        let fragments: Vec<String> = value
            .get(collection)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get(format!("{field}_fragments")))
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
        for fragment in &fragments {
            if fragment.chars().count() != 1 {
                return Err(format!(
                    "{collection}[0].{field} has a non-scalar fragment {fragment:?}"
                )
                .into());
            }
        }
        let expected: Vec<String> = text.chars().map(|c| c.to_string()).collect();
        if fragments != expected {
            return Err(format!("{collection}[0].{field}_fragments mismatch for {text:?}").into());
        }
        if fragments.join("").as_str() != text {
            return Err(format!("{collection}[0].{field} fragments do not rejoin").into());
        }
    }
    Ok(())
}

/// Per-field empty contract: every eligible free-text field attaches an
/// empty fragments array for `""`, so `array::join(..., '')` reconstitutes
/// exactly the empty string without changing field presence.
#[test]
fn envelope_text_fragments_empty_fields_attach_empty_arrays() -> TestResult {
    let mut envelope = unit_envelope();
    envelope.task_contracts[0].title.clear();
    envelope.source_snapshots[0].uri.clear();
    envelope.source_snapshots[0].excerpt.clear();
    envelope.evidence_atoms[0].summary.clear();
    envelope.tool_observations[0].tool_name.clear();
    envelope.tool_observations[0].observation.clear();
    envelope.claims[0].statement.clear();
    envelope.verification_runs[0].verifier.clear();
    envelope.verification_runs[0].summary.clear();
    envelope.failures[0].summary.clear();
    let value = envelope_with_text_fragments(&envelope)?;
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
        let fragments = value
            .get(collection)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get(format!("{field}_fragments")))
            .and_then(Value::as_array)
            .ok_or(format!("missing {collection}[0].{field}_fragments"))?;
        if !fragments.is_empty() {
            return Err(format!(
                "empty {collection}[0].{field} must attach an empty fragments array"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "live-edge"))]
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

#[cfg(all(test, feature = "live-edge"))]
async fn stop_scratch(scratch: &mut ScratchServer) {
    if let Some(child) = scratch.child.as_mut() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    scratch.disarm();
}

// Live edge (NOT ignored): requires ELIOT_SURREAL_LIVE_EDGE=1 and
// ELIOT_SURREAL_EXE pointing at surreal.exe. Missing prerequisites fail
// explicitly via require_live_edge — this test never skips silently.
// Gated behind `live-edge`: default `cargo test -p eliot-store` does not
// compile this test; `--features live-edge` executes it against the backend.
#[cfg(all(test, feature = "live-edge"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

// Live edge (NOT ignored): requires ELIOT_SURREAL_LIVE_EDGE=1 and
// ELIOT_SURREAL_EXE pointing at surreal.exe. Missing prerequisites fail
// explicitly via require_live_edge — this test never skips silently.
// Gated behind `live-edge`: default `cargo test -p eliot-store` does not
// compile this test; `--features live-edge` executes it against the backend.
#[cfg(all(test, feature = "live-edge"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[cfg(all(test, feature = "live-edge"))]
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

// Live edge (NOT ignored): requires ELIOT_SURREAL_LIVE_EDGE=1,
// ELIOT_SURREAL_EXE, ELIOT_DISABLE_REAL_PROVIDER=1 and
// ELIOT_TEST_SURREAL_PASSWORD_FILE. Missing prerequisites fail explicitly
// via canon_config — this test never skips silently.
// Gated behind `live-edge`: default `cargo test -p eliot-store` does not
// compile this test; `--features live-edge` executes it against the backend.
#[cfg(all(test, feature = "live-edge"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_envelope_free_text_survives_round_trip() -> TestResult {
    let config = canon_config()?;
    let clients = Arc::new(DbClientSet::start(config.clone()).await?);
    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let direct = connect_canon_direct(&config).await?;
    let body_result = run_canon_cases(&store, &direct).await;
    let shutdown_result = clients.shutdown().await;
    let shutdown_outcome: TestResult = shutdown_result
        .map(|_| ())
        .map_err(|error| format!("client-set shutdown failed: {error}").into());
    body_result.and(shutdown_outcome)
}

/// Record keys minted per canonical case envelope so packed envelopes never
/// collide on record identity.
#[cfg(all(test, feature = "live-edge"))]
struct CanonCaseIds {
    task_id: TaskId,
    source_id: String,
    evidence_id: EvidenceId,
    observation_id: String,
    claim_id: ClaimId,
    verification_id: VerificationId,
    fingerprint: String,
}

/// Builds one canonical envelope whose ten free-text slots carry the given
/// values in fixed order: title, source uri, source excerpt, evidence
/// summary, tool name, observation, claim statement, verifier, verification
/// summary, failure summary.
#[cfg(all(test, feature = "live-edge"))]
fn canon_case_envelope(
    project_id: ProjectId,
    write_id: WriteId,
    values: [&str; 10],
    tag: &str,
) -> (MemoryWriteEnvelope, CanonCaseIds) {
    let ids = CanonCaseIds {
        task_id: TaskId::new_v7(),
        source_id: format!("src-canon-{tag}"),
        evidence_id: EvidenceId::new_v7(),
        observation_id: format!("obs-canon-{tag}"),
        claim_id: ClaimId::new_v7(),
        verification_id: VerificationId::new_v7(),
        fingerprint: format!("fp-canon-{tag}"),
    };
    let envelope = MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(ids.task_id),
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash: format!("input-hash-canon-{tag}"),
        policy_snapshot_id: None,
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "r5-i10-canon".to_owned(),
        authority: "live-proof".to_owned(),
        task_contracts: vec![TaskContractInput {
            task_id: ids.task_id,
            title: values[0].to_owned(),
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
            source_id: ids.source_id.clone(),
            uri: values[1].to_owned(),
            authority: "live-proof".to_owned(),
            content_hash: "content-hash-r5-i10".to_owned(),
            excerpt: values[2].to_owned(),
        }],
        evidence_atoms: vec![EvidenceAtomInput {
            evidence_id: ids.evidence_id,
            source_id: ids.source_id.clone(),
            summary: values[3].to_owned(),
            payload: json!({ "plain": "no-colon-here", "n": 7 }),
        }],
        tool_observations: vec![ToolObservationInput {
            observation_id: ids.observation_id.clone(),
            tool_name: values[4].to_owned(),
            observation: values[5].to_owned(),
            payload: json!({ "plain": "ok" }),
        }],
        failures: vec![FailureFingerprintInput {
            fingerprint: ids.fingerprint.clone(),
            summary: values[9].to_owned(),
            payload: Value::Null,
        }],
        claims: vec![ClaimCardInput {
            claim_id: ids.claim_id,
            statement: values[6].to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({ "plain": "ok" }),
        }],
        verification_runs: vec![VerificationRunInput {
            verification_id: ids.verification_id,
            claim_id: Some(ids.claim_id),
            verifier: values[7].to_owned(),
            result: VerificationResult::Passed,
            summary: values[8].to_owned(),
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
    (envelope, ids)
}

/// Opens a second, direct RPC connection to the canonical proof server so the
/// test can assert exact `source_snapshot` readback (`uri`, `excerpt`) — the
/// one covered field pair with no governed by-id reader. The password comes
/// from the same test password file the supervisor provisions.
#[cfg(all(test, feature = "live-edge"))]
async fn connect_canon_direct(
    config: &eliot_types::SurrealServerConfig,
) -> TestResult<crate::surreal_rpc::SurrealRpcTransport> {
    use crate::surreal_rpc::SurrealRpcTransport;
    let password = read_canon_test_password(&config.password_file)?;
    let mut transport_config = GovernorConfig::default().db.surreal;
    transport_config.endpoint = config.endpoint.clone();
    transport_config.query_timeout_ms = config.query_timeout_ms;
    let transport = SurrealRpcTransport::connect(&transport_config, 1_000)
        .await
        .map_err(|error| format!("canon direct connect failed: {error}"))?;
    transport
        .signin(SCRATCH_USER, &SecretString::from(password))
        .await
        .map_err(|error| format!("canon direct signin failed: {error}"))?;
    transport
        .use_ns_db(config.ns.as_str(), config.db.as_str())
        .await
        .map_err(|error| format!("canon direct USE failed: {error}"))?;
    Ok(transport)
}

/// Reads the test password from the `%LOCALAPPDATA%`-anchored file named by
/// `ELIOT_TEST_SURREAL_PASSWORD_FILE`.
#[cfg(all(test, feature = "live-edge"))]
fn read_canon_test_password(configured: &str) -> TestResult<String> {
    let suffix = configured
        .strip_prefix("%LOCALAPPDATA%/")
        .or_else(|| configured.strip_prefix("%localappdata%/"))
        .ok_or("canon test password_file must use the %LOCALAPPDATA%/ prefix")?;
    let base = std::env::var("LOCALAPPDATA")
        .map_err(|_| "LOCALAPPDATA is required for the canon direct proof")?;
    let path = PathBuf::from(base).join(suffix.replace('/', std::path::MAIN_SEPARATOR_STR));
    let content = std::fs::read_to_string(&path)
        .map_err(|error| format!("canon test password file unreadable: {error}"))?;
    let trimmed = content.trim().to_owned();
    if trimmed.is_empty() {
        return Err("canon test password file is empty".into());
    }
    Ok(trimmed)
}

/// Live-boundary proof: every matrix value is written through the canonical
/// `apply_write_envelope` RPC-variable path and read back byte-for-byte on
/// all ten free-text slots. Values are packed ten per envelope (plus one
/// all-empty envelope for the per-field empty contract); each assertion
/// carries its matrix id, so a pre-fix truncation fails loudly. Reverting the
/// fragment hunk to bare `$task.title`-style bindings makes this test fail
/// with the historical truncation signature.
#[cfg(all(test, feature = "live-edge"))]
#[allow(clippy::too_many_lines)]
async fn run_canon_cases(
    store: &CanonicalStore,
    direct: &crate::surreal_rpc::SurrealRpcTransport,
) -> TestResult {
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let mut chunks: Vec<Vec<(String, String)>> = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    for (suffix, value) in matrix() {
        let text = value
            .as_str()
            .ok_or("live matrix case was not a string")?
            .to_owned();
        current.push((suffix, text));
        if current.len() == 10 {
            chunks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        while current.len() < 10 {
            current.push((
                format!("pad-{}", current.len()),
                "memory:operator-runtime-proof".to_owned(),
            ));
        }
        chunks.push(current);
    }
    // One all-empty envelope: every eligible field exercises the empty
    // fragments array plus `array::join(..., '')` on the live path.
    chunks.push(
        (0..10)
            .map(|slot| (format!("empty-{slot}"), String::new()))
            .collect(),
    );

    let mut mismatches = Vec::new();
    for (env_index, chunk) in chunks.iter().enumerate() {
        let tag = format!("env{env_index}");
        let values: [&str; 10] = std::array::from_fn(|slot| chunk[slot].1.as_str());
        let write_id = WriteId::new_v7();
        let (envelope, ids) = canon_case_envelope(project_id, write_id, values, &tag);
        store
            .apply_write_envelope(&envelope)
            .await
            .map_err(|error| format!("{tag} canonical write failed: {error}"))?;
        let mut check = |label: &str, matrix_id: &str, expected: &str, actual: &str| {
            if actual != expected {
                mismatches.push(format!(
                    "{tag} {label} (matrix {matrix_id}): wrote {expected:?}, read {actual:?}"
                ));
            }
        };
        let observations: Vec<CanonicalToolObservation> = store
            .tool_observations_by_write_id(&write_id)
            .await
            .map_err(|error| format!("{tag} observation read failed: {error}"))?;
        let Some(observation) = observations
            .iter()
            .find(|item| item.observation_id == ids.observation_id)
        else {
            return Err(format!("{tag} canonical write did not store the tool observation").into());
        };
        check(
            "tool_observations.tool_name",
            &chunk[4].0,
            values[4],
            observation.tool_name.as_str(),
        );
        check(
            "tool_observations.observation",
            &chunk[5].0,
            values[5],
            observation.observation.as_str(),
        );
        let claim: CanonicalClaimCard = store
            .claim_card_by_id(project_id, ids.claim_id)
            .await
            .map_err(|error| format!("{tag} claim read failed: {error}"))?
            .ok_or(format!(
                "{tag} canonical write did not store the claim card"
            ))?;
        check(
            "claims.statement",
            &chunk[6].0,
            values[6],
            claim.statement.as_str(),
        );
        let verification = store
            .verification_run_by_id(ids.verification_id)
            .await
            .map_err(|error| format!("{tag} verification read failed: {error}"))?
            .ok_or(format!(
                "{tag} canonical write did not store the verification run"
            ))?;
        check(
            "verification_runs.verifier",
            &chunk[7].0,
            values[7],
            verification.verifier.as_str(),
        );
        check(
            "verification_runs.summary",
            &chunk[8].0,
            values[8],
            verification.summary.as_str(),
        );
        let contract = store
            .task_contract_by_id(ids.task_id)
            .await
            .map_err(|error| format!("{tag} task read failed: {error}"))?
            .ok_or(format!(
                "{tag} canonical write did not store the task contract"
            ))?;
        check(
            "task_contracts.title",
            &chunk[0].0,
            values[0],
            contract.title.as_str(),
        );
        let l2 = store
            .fetch_atoms_l2(&FetchAtomsL2Request {
                project_id,
                handles: vec![
                    format!("evidence:{evidence_id}", evidence_id = ids.evidence_id),
                    format!("failure:{fingerprint}", fingerprint = ids.fingerprint),
                ],
                continuation: None,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            })
            .await
            .map_err(|error| format!("{tag} L2 read failed: {error}"))?;
        let Some(atom) = l2
            .evidence_atoms
            .iter()
            .find(|atom| atom.evidence_id == ids.evidence_id)
        else {
            return Err(format!("{tag} canonical write did not store the evidence atom").into());
        };
        check(
            "evidence_atoms.summary",
            &chunk[3].0,
            values[3],
            atom.summary.as_str(),
        );
        let Some(failure) = l2
            .failure_fingerprints
            .iter()
            .find(|item| item.fingerprint == ids.fingerprint)
        else {
            return Err(
                format!("{tag} canonical write did not store the failure fingerprint").into(),
            );
        };
        check(
            "failures.summary",
            &chunk[9].0,
            values[9],
            failure.summary.as_str(),
        );
        let raw = direct
            .query(
                "SELECT uri, excerpt FROM source_snapshot WHERE source_id = $source_id;",
                json!({ "source_id": ids.source_id }),
            )
            .await
            .map_err(|error| format!("{tag} source read failed: {error}"))?;
        let row = first_ok_result(&raw)?
            .as_array()
            .and_then(|rows| rows.first())
            .ok_or(format!(
                "{tag} canonical write did not store the source snapshot"
            ))?;
        let uri = row
            .get("uri")
            .and_then(Value::as_str)
            .ok_or(format!("{tag} source row has no uri"))?;
        check("source_snapshots.uri", &chunk[1].0, values[1], uri);
        let excerpt = row
            .get("excerpt")
            .and_then(Value::as_str)
            .ok_or(format!("{tag} source row has no excerpt"))?;
        check("source_snapshots.excerpt", &chunk[2].0, values[2], excerpt);
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "canonical free-text round-trip failures ({}):\n{}",
            mismatches.len(),
            mismatches.join("\n")
        )
        .into())
    }
}
