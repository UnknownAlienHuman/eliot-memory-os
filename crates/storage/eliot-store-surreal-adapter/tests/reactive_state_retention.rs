//! Durable reactive-state retention proof (issue #1941 C4).
//!
//! The closed `ApplyReactiveInjectionState` / `GetReactiveInjectionState`
//! and `ApplyResourceSnapshot` / `GetResourceSnapshot` operations,
//! submitted through the real prepared/admission path against an isolated
//! `surreal.exe` provider (loopback bind, per-test temporary `SurrealKV`
//! roots, redacted test credentials), persist ledger snapshots verbatim
//! with guarded revisions and serve immutable resource bytes with
//! convergent re-apply and closed rewrites. No in-memory stand-in, no
//! production database, no user credentials.
//!
//! Ledger fixtures mirror the real bridge ledger serde shape
//! (`contract`, `next_item_seq`, `next_receipt_seq`, `items`,
//! `receipts`) stamped with the true delivery-record contract: the
//! store preserves the bytes verbatim and verifies the stamp
//! structurally, while delivery semantics stay with the bridge ledger
//! (whose own snapshot/restore round-trip is proven in the bridge
//! suite).
//!
//! Provider evidence (recorded on failure output and in the work item):
//! the pinned `surreal.exe` path plus its SHA-256, the server version
//! handshake enforced by the adapter, the per-test loopback port, and
//! the temporary data/work/tmp roots.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::large_futures, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use eliot_contracts::{
    EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration, SourceId,
    StateFence,
};
use eliot_platform::ClockObservation;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::EffectClass;
use eliot_store_api::{
    CanonicalRequestView, NamedMutationOperation, NamedMutationRequest, NamedReadOperation,
    OperationIdentity, OrderingScopeId, PreparedTransition, ReadConsistency, RequestMeta, ScopeId,
    SecurityContext, StoreError, TransitionClass, WriteReceiptStatus, canonical_request_hash,
    generated_operation_manifests, operation_manifest_set_digest,
};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

/// Isolated provider executable for tests. Overridable for local runs; the
/// default is the pinned local installation probed during implementation.
const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const CONTRACT: &str = "eliot.agent-bridge.reactive-injection-receipts/v1";
const SCOPE: &str = "reactive-state";

fn surreal_exe() -> PathBuf {
    std::env::var("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|_| PathBuf::from(TEST_SURREAL_EXE), PathBuf::from)
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    )
}

fn context(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-reactive-live-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-reactive").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: eliot_contracts::ClockReading::default(),
    }
}

/// Shape-faithful ledger snapshot: the real bridge field layout stamped
/// with the true delivery-record contract.
fn ledger_json(item_count: u32) -> String {
    let cue_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut items = serde_json::Map::new();
    for index in 0..item_count {
        items.insert(
            format!("reactive-item-{index}"),
            json!({
                "item_id": format!("reactive-item-{index}"),
                "session_id": "session-live-1",
                "severity": "Elevated",
                "cue": {
                    "cue_id": format!("cue-{index}"),
                    "kind": "ToolObservation",
                    "source": "tool-surface",
                    "source_revision": "rev-1",
                    "cue_digest": cue_digest,
                },
                "firing": {
                    "rule_id": "exact-rule-7",
                    "cue_id": format!("cue-{index}"),
                    "cue_digest": cue_digest,
                },
                "relations": ["rel-a"],
                "admission": {
                    "scope_id": "scope-1",
                    "status": "active",
                    "risk": "High",
                    "governance_profile_rev": "gov-3",
                    "fence_epoch": "epoch-1",
                    "fence_generation": 2,
                    "admitted_severity": "Elevated",
                },
                "state": {"kind": "Delivered", "receipt_seq": 1},
                "use_outcome": {"kind": "Unknown"},
                "disposition": {"kind": "Open"},
                "invalidated": false,
            }),
        );
    }
    serde_json::to_string(&json!({
        "contract": CONTRACT,
        "next_item_seq": item_count,
        "next_receipt_seq": 1,
        "items": items,
        "receipts": {},
    }))
    .expect("fixture serializes")
}

fn ledger_params(session: &str, ledger: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            eliot_store_api::REACTIVE_PARAM_SESSION_ID.to_owned(),
            json!(session),
        ),
        (
            eliot_store_api::REACTIVE_PARAM_LEDGER_JSON.to_owned(),
            json!(ledger),
        ),
    ])
}

fn snapshot_params(uri: &str, content: &[u8]) -> BTreeMap<String, Value> {
    let request = eliot_store_api::resource_snapshot_mutation_request(uri.to_owned(), content)
        .expect("snapshot builds");
    assert_eq!(
        request.operation,
        NamedMutationOperation::ApplyResourceSnapshot
    );
    request.parameters
}

fn transition_with(
    tag: &str,
    operation: NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
) -> (RequestMeta, PreparedTransition) {
    let ctx = context(tag);
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
            .expect("set digest");
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-reactive-live-{tag}")).expect("operation"),
            idempotency_key: format!("idem-reactive-live-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(SCOPE).expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(SCOPE).expect("ordering")],
        transition_class: TransitionClass::ReactiveState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: "c".repeat(64),
        // Issue #18: placeholder bindings, derived below via
        // `bind_issue18_digests` (empty heads in this helper).
        semantic_source_revisions: Vec::new(),
        admission_digest: String::new(),
        operation_manifest_digest: manifest_digest,
        mutation_plan_digest: String::new(),
        named_operations: vec![NamedMutationRequest {
            operation,
            parameters,
        }],
        event_projection_relation_intents: eliot_store_api::EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    let view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
    // Issue #18: the admission digest covers the canonical hash, so bind
    // after the hash is final.
    eliot_store_api::bind_issue18_digests(&mut transition, Vec::new())
        .expect("fixture digests bind");
    (ctx, transition)
}

fn adapter_config(
    exe: &Path,
    digest: String,
    bind: String,
    data: &Path,
    work: &Path,
    tmp: &Path,
) -> SurrealAdapterConfig {
    let mut config = SurrealAdapterConfig {
        endpoint: format!("ws://{bind}/rpc"),
        namespace: "eliot".to_owned(),
        database: "reactive_1941".to_owned(),
        username: "reactive-test".to_owned(),
        password: SecretString::new("reactive-test-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-test-1941".to_owned(),
        installation_profile: "portable_dev".to_owned(),
        runtime_state_roots_digest: "a".repeat(64),
        provider_executable_path: exe.to_string_lossy().into_owned(),
        provider_artifact_digest: digest,
        provider_arguments: Vec::new(),
        store_data_root: data.to_string_lossy().into_owned(),
        store_work_root: work.to_string_lossy().into_owned(),
        store_temp_root: tmp.to_string_lossy().into_owned(),
        connect_timeout_ms: 60_000,
        query_timeout_ms: 30_000,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    config.provider_arguments = config.expected_provider_arguments();
    config
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("loopback")
        .local_addr()
        .expect("port")
        .port()
}

fn prepare_initial_root_user(exe: &Path, bind: &str, data: &Path, work: &Path, tmp: &Path) {
    let password = SecretString::new("reactive-test-secret".into());
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            "reactive-test",
            "--password",
            password.expose_secret(),
            "--temporary-directory",
            &tmp.to_string_lossy(),
            &data_url,
        ])
        .current_dir(work)
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .env("TEMP", tmp)
        .env("TMP", tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("preparation provider");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if std::net::TcpStream::connect(bind).is_ok() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("preparation provider never bound {bind}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(2));
    child.kill().expect("stop preparation provider");
    let _ = child.wait();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(bind).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "preparation provider never released {bind}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(1));
}

fn observation() -> ClockObservation {
    ClockObservation {
        valid_time_ms: Some(1_000),
        known_time_ms: Some(1_001),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

struct Harness {
    root: PathBuf,
    adapter: Option<SurrealStoreAdapter>,
}

impl Harness {
    async fn fresh(test: &str) -> Self {
        let port = free_port();
        let root = std::env::temp_dir().join(format!(
            "eliot-reactive-1941-{}-{port}-{test}",
            std::process::id()
        ));
        let bin = root.join("bin");
        let data = root.join("store").join("data");
        let work = root.join("store").join("work");
        let tmp = root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("test dirs");
        }
        let source_exe = surreal_exe();
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage provider");
        let digest = eliot_store_api::sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
        println!(
            "reactive-state provider: exe={} sha256={} port={} root={}",
            exe.display(),
            digest,
            port,
            root.display()
        );
        let platform = WindowsPlatform::new(root.clone()).expect("platform");
        let bind = format!("127.0.0.1:{port}");
        prepare_initial_root_user(&exe, &bind, &data, &work, &tmp);
        let lease = platform
            .retain_process_path_lease(&exe, &work, &digest)
            .expect("process lease");
        let config = adapter_config(&exe, digest, bind, &data, &work, &tmp);
        let adapter = SurrealStoreAdapter::new(config, lease).expect("adapter");
        adapter.connect().await.expect("provider connect");
        let migration = SurrealStoreAdapter::v2_baseline_migration();
        if let Err(error) = adapter
            .apply_migration(&migration, &observation(), &fence())
            .await
        {
            panic!("baseline migration: {error:?}");
        }
        Self {
            root,
            adapter: Some(adapter),
        }
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("adapter live")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.adapter = None;
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn ledger_read(session: &str) -> eliot_store_api::NamedReadRequest {
    eliot_store_api::reactive_ledger_read_request(session.to_owned(), fence()).expect("read")
}

fn snapshot_read(uri: &str) -> eliot_store_api::NamedReadRequest {
    eliot_store_api::resource_snapshot_read_request(uri.to_owned(), fence()).expect("read")
}

#[tokio::test]
async fn ledger_upsert_round_trips_verbatim_with_guarded_revision() {
    let harness = Harness::fresh("ledger").await;
    let first = ledger_json(2);
    let (ctx, transition) = transition_with(
        "ledger-1",
        NamedMutationOperation::ApplyReactiveInjectionState,
        ledger_params("session-live-1", &first),
    );
    let receipt = eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("ledger upsert commits");
    assert_eq!(
        receipt.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
    let response = eliot_store_api::CanonicalStoreClient::execute_named(
        harness.adapter(),
        ledger_read("session-live-1"),
    )
    .await
    .expect("ledger reads");
    assert_eq!(
        response.payload.get("ledger_json").and_then(Value::as_str),
        Some(first.as_str()),
        "readback is byte-identical to the admitted snapshot"
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(1)
    );
    // A second admitted snapshot replaces verbatim with a bumped revision.
    let second = ledger_json(4);
    let (ctx, transition) = transition_with(
        "ledger-2",
        NamedMutationOperation::ApplyReactiveInjectionState,
        ledger_params("session-live-1", &second),
    );
    eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("second upsert commits");
    let response = eliot_store_api::CanonicalStoreClient::execute_named(
        harness.adapter(),
        ledger_read("session-live-1"),
    )
    .await
    .expect("ledger re-reads");
    assert_eq!(
        response.payload.get("ledger_json").and_then(Value::as_str),
        Some(second.as_str())
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(2)
    );
    // Same-operation replay resolves the sealed receipt without remutation.
    let (ctx, transition) = transition_with(
        "ledger-2",
        NamedMutationOperation::ApplyReactiveInjectionState,
        ledger_params("session-live-1", &second),
    );
    let replayed = eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("replay resolves");
    assert_eq!(
        replayed.operation_id,
        eliot_store_api::OperationId::new("op-reactive-live-ledger-2").expect("operation"),
        "replay resolves the sealed identity"
    );
    assert_eq!(
        replayed.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
    let response = eliot_store_api::CanonicalStoreClient::execute_named(
        harness.adapter(),
        ledger_read("session-live-1"),
    )
    .await
    .expect("ledger reads after replay");
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(2),
        "replay remutes nothing"
    );
}

#[tokio::test]
async fn snapshot_serves_bytes_with_immutable_uri() {
    let harness = Harness::fresh("snapshot").await;
    // Non-UTF-8 content proves the base64 wire path end to end.
    let content = b"\x00\x01\x02canonical-report\xff\xfe".to_vec();
    let uri = "eliot://report/live-1";
    let (ctx, transition) = transition_with(
        "snap-1",
        NamedMutationOperation::ApplyResourceSnapshot,
        snapshot_params(uri, &content),
    );
    let receipt = eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("snapshot commits");
    assert_eq!(
        receipt.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
    let response =
        eliot_store_api::CanonicalStoreClient::execute_named(harness.adapter(), snapshot_read(uri))
            .await
            .expect("snapshot reads");
    let encoded = response
        .payload
        .get("content_base64")
        .and_then(Value::as_str)
        .expect("bytes served");
    let sha = response
        .payload
        .get("content_sha256")
        .and_then(Value::as_str)
        .expect("digest served");
    assert_eq!(
        eliot_store_api::decode_resource_content(encoded, sha).expect("bytes decode"),
        content,
        "served bytes are exactly the admitted bytes"
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(1)
    );
    // Identical re-apply converges without a revision move.
    let (ctx, transition) = transition_with(
        "snap-2",
        NamedMutationOperation::ApplyResourceSnapshot,
        snapshot_params(uri, &content),
    );
    eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("convergent re-apply commits");
    let response =
        eliot_store_api::CanonicalStoreClient::execute_named(harness.adapter(), snapshot_read(uri))
            .await
            .expect("snapshot re-reads");
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(1),
        "convergent re-apply moves no revision"
    );
    // A rewrite with different bytes fails closed.
    let (ctx, transition) = transition_with(
        "snap-3",
        NamedMutationOperation::ApplyResourceSnapshot,
        snapshot_params(uri, b"forged bytes"),
    );
    assert_eq!(
        eliot_store_api::CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx,
            transition,
            vec![],
            vec![],
        )
        .await
        .map(|_| ()),
        Err(StoreError::IdentityConflict)
    );
    // Unknown URIs project explicit absence.
    let response = eliot_store_api::CanonicalStoreClient::execute_named(
        harness.adapter(),
        snapshot_read("eliot://report/absent"),
    )
    .await
    .expect("absent snapshot reads");
    assert!(
        response
            .payload
            .get("content_base64")
            .is_some_and(Value::is_null)
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(0)
    );
}

#[tokio::test]
async fn foreign_contract_and_digest_mismatch_fail_closed() {
    let harness = Harness::fresh("negative").await;
    let (ctx, transition) = transition_with(
        "neg-1",
        NamedMutationOperation::ApplyReactiveInjectionState,
        ledger_params("session-live-1", r#"{"contract":"foreign"}"#),
    );
    assert!(
        eliot_store_api::CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx,
            transition,
            vec![],
            vec![],
        )
        .await
        .is_err(),
        "foreign ledger contract is rejected"
    );
    let mut tampered = snapshot_params("eliot://report/live-9", b"bytes");
    tampered.insert(
        eliot_store_api::REACTIVE_PARAM_CONTENT_SHA256.to_owned(),
        json!("0".repeat(64)),
    );
    let (ctx, transition) = transition_with(
        "neg-2",
        NamedMutationOperation::ApplyResourceSnapshot,
        tampered,
    );
    assert_eq!(
        eliot_store_api::CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx,
            transition,
            vec![],
            vec![],
        )
        .await
        .map(|_| ()),
        Err(StoreError::InvalidField {
            field: "reactive.content_sha256",
            reason: "digest does not name the snapshot bytes",
        })
    );
}

#[tokio::test]
async fn read_requests_reject_undeclared_scope() {
    let request = eliot_store_api::NamedReadRequest {
        operation: NamedReadOperation::GetReactiveInjectionState,
        scope_id: Some(ScopeId::new("reactive-state").expect("scope")),
        consistency: ReadConsistency::Eventual,
        state_fence: fence(),
        parameters: BTreeMap::from([(
            eliot_store_api::REACTIVE_PARAM_SESSION_ID.to_owned(),
            json!("session-live-1"),
        )]),
    };
    assert_eq!(
        request.validate_against_catalogue(&generated_operation_manifests().expect("catalogue")),
        Err(StoreError::InvalidField {
            field: "scope_id",
            reason: "operation does not address a scope",
        })
    );
}
