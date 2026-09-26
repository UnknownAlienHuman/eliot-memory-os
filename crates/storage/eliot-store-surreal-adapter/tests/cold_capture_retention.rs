//! Durable cold-capture retention proof (issue #1929).
//!
//! An unbound `CaptureObservation` (no task selection anywhere) submitted
//! through the real prepared/admission path against an isolated `surreal.exe`
//! provider (loopback bind, per-test temporary `SurrealKV` roots, redacted
//! test credentials) is durably retained and readable, while task state stays
//! empty: no task memory, support, influence, or finish effects. The
//! pre-provider gate decision (`ColdUnbound`) is proven in the bridge suite;
//! this file proves the durable half on the real contour. No in-memory
//! stand-in, no production database, no user credentials.

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
    SecurityContext, TransitionClass, canonical_request_hash, generated_operation_manifests,
    operation_manifest_set_digest,
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
const SCOPE: &str = "scope-1929-cold";
const SUBJECT: &str = "cold-1929-subject";

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
        request_id: RequestId::new(format!("request-cold-live-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-1929").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: eliot_contracts::ClockReading::default(),
    }
}

fn capture_transition(tag: &str) -> (RequestMeta, PreparedTransition) {
    let ctx = context(tag);
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
            .expect("set digest");
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-cold-live-{tag}")).expect("operation"),
            idempotency_key: format!("idem-cold-live-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(SCOPE).expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(SCOPE).expect("ordering")],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "c".repeat(64),
        // Issue #18: placeholder bindings, derived below via
        // `bind_issue18_digests` (empty heads in this helper).
        semantic_source_revisions: Vec::new(),
        admission_digest: String::new(),
        operation_manifest_digest: manifest_digest,
        mutation_plan_digest: String::new(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!(SUBJECT))]),
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
        database: "capture_1929".to_owned(),
        username: "capture-test".to_owned(),
        password: SecretString::new("capture-test-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-test-1929".to_owned(),
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
    let password = SecretString::new("capture-test-secret".into());
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            "capture-test",
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
            "eliot-cold-1929-{}-{port}-{test}",
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
            "cold-capture provider: exe={} sha256={} port={} root={}",
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

fn read_request(
    operation: NamedReadOperation,
    scope_id: Option<ScopeId>,
    parameters: BTreeMap<String, Value>,
) -> eliot_store_api::NamedReadRequest {
    eliot_store_api::NamedReadRequest {
        operation,
        scope_id,
        consistency: ReadConsistency::Eventual,
        state_fence: fence(),
        parameters,
    }
}

#[tokio::test]
async fn unbound_capture_is_durably_retained_without_task_effects() {
    let harness = Harness::fresh("cold").await;
    // No task selection anywhere: bare capture bytes only.
    let (ctx, transition) = capture_transition("cold-1");
    let receipt = eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("unbound capture commits");
    assert_eq!(
        receipt.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
    // The exact bytes are durably readable through the evidence pack.
    let pack = eliot_store_api::CanonicalStoreClient::execute_named(
        harness.adapter(),
        read_request(
            NamedReadOperation::GetEvidencePack,
            Some(ScopeId::new(SCOPE).expect("scope")),
            BTreeMap::from([
                ("subject".to_owned(), json!(SUBJECT)),
                ("max_records".to_owned(), json!("10")),
            ]),
        ),
    )
    .await
    .expect("evidence pack reads");
    let records = pack
        .payload
        .get("records")
        .and_then(Value::as_array)
        .expect("records array");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("operation").and_then(Value::as_str),
        Some("CaptureObservation")
    );
    assert_eq!(
        records[0]
            .get("parameters")
            .and_then(|parameters| parameters.get("subject"))
            .and_then(Value::as_str),
        Some(SUBJECT)
    );
    // No task was created or affected: task state is exactly empty.
    let task_state = eliot_store_api::CanonicalStoreClient::execute_named(
        harness.adapter(),
        read_request(
            NamedReadOperation::GetTaskState,
            Some(ScopeId::new(SCOPE).expect("scope")),
            BTreeMap::from([
                ("task_id".to_owned(), json!("task-never-bound")),
                ("max_records".to_owned(), json!("10")),
            ]),
        ),
    )
    .await
    .expect("task state reads");
    assert_eq!(
        task_state.payload.get("records").and_then(Value::as_array),
        Some(&Vec::new()),
        "no task rows exist"
    );
    assert!(
        task_state
            .payload
            .get("current")
            .is_some_and(Value::is_null),
        "no current task revision"
    );
}
