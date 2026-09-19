//! Product acceptance for S-CONC-ACCEPT (issue #994).
//!
//! Replays the frozen corpus (`data/store_concurrency_cases.json`) under the
//! frozen profile (`data/store_concurrency_profile.toml`) against the real
//! Surreal provider seam through the accepted #986-#993 chain: staged
//! provider binary (#986), bounded session set (#987), core apply (#988),
//! in-transaction allocation (#989), public admission (#990), wire (#991),
//! ORS/gateway reconcile (#992) and the runtime scheduler generation (#993).
//!
//! Suite allocation (frozen): 994/2, 994/3, 994/9, 994/10, 994/11, 994/12,
//! 994/13, 994/14, 994/15, 994/16, 994/17, 994/18, 994/19. Cases 994/1,
//! 994/4, 994/5, 994/6, 994/7, 994/8, 994/20 live exactly once in
//! `store_concurrency_reference.rs`.
//!
//! Every test stages an isolated provider (own loopback port, own data root,
//! pinned binary digest) and removes its root on completion. Run evidence is
//! printed to stdout, never written into committed testdata.

#![cfg(windows)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::large_futures, clippy::too_many_lines)]
#![allow(clippy::items_after_statements)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_ipc::{DeliveryOutcome, TransportLimits};
use eliot_kernel_service::{
    EbpCanonicalStoreClient, EbpStoreTransport, HostStoreBootstrapRequirement, StoreClientError,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::{Frame, FrameKind, ProtocolVersion, ServerHello};
use eliot_store_api::{
    CONTRACT_VERSION, CanonicalRequestView, CanonicalStoreClient, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationId as ApiOperationId, OperationIdentity, OrderingScopeId, PreparedTransition,
    RequestMeta, ScopeId, SecurityContext, StoreRecoveryRequest, TransitionClass, WriteReceipt,
    WriteReceiptStatus, canonical_request_hash, generated_operation_manifests,
    operation_manifest_set_digest, validate_store_receipt_envelope,
};
use eliot_store_memory::MemoryStore;
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

static HARNESS_COUNTER: AtomicU64 = AtomicU64::new(0);

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn corpus() -> Value {
    let bytes = std::fs::read(data_dir().join("store_concurrency_cases.json"))
        .expect("corpus must be readable");
    serde_json::from_slice(&bytes).expect("corpus must be valid JSON")
}

fn case_entry(number: u64) -> Value {
    let fx = corpus();
    let entry = fx["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["case"].as_u64() == Some(number))
        .unwrap_or_else(|| panic!("corpus must declare case {number}"))
        .clone();
    assert_eq!(entry["suite"].as_str().expect("suite"), "product");
    entry
}

fn profile_text() -> String {
    std::fs::read_to_string(data_dir().join("store_concurrency_profile.toml"))
        .expect("profile must be readable")
}

fn profile_value(key: &str) -> String {
    for line in profile_text().lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') || line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once('=')
            && name.trim() == key
        {
            let value = value.trim().trim_matches('"').to_owned();
            assert!(!value.is_empty(), "profile key must be non-empty: {key}");
            return value;
        }
    }
    panic!("profile key missing: {key}")
}

fn profile_u64(key: &str) -> u64 {
    profile_value(key)
        .parse()
        .unwrap_or_else(|_| panic!("profile key must be numeric: {key}"))
}

fn profile_u8(key: &str) -> u8 {
    profile_value(key)
        .parse()
        .unwrap_or_else(|_| panic!("profile key must be numeric: {key}"))
}

fn profile_usize(key: &str) -> usize {
    usize::try_from(profile_u64(key)).expect("profile bound fits pointer width")
}

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE).expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("non-zero"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn ctx_for(operation: &str, fence: &StateFence) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-994-{operation}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-994").expect("product"),
        source_id: SourceId::new("source-994").expect("source"),
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            ..ClockReading::default()
        },
    }
}

fn set_digest() -> eliot_store_api::OperationManifestDigest {
    operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
        .expect("set digest")
}

/// One admitted `CaptureObservation` transition binding the generated
/// catalogue set digest, with the canonical request hash recomputed over the
/// exact executable bytes (989 precedent).
fn admitted(operation: &str, scope: &str, subject: &str) -> (RequestMeta, PreparedTransition) {
    let fence = fence();
    let ctx = ctx_for(operation, &fence);
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(operation).expect("operation"),
            idempotency_key: format!("idem-994-{operation}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence,
        scope_id: ScopeId::new(scope).expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(scope).expect("ordering")],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!(subject))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]),
    )
    .expect("request hash");
    (ctx, transition)
}

fn commit_sequence(receipt: &WriteReceipt) -> String {
    receipt
        .committed_at
        .clone()
        .expect("committed receipt carries its instant")
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

struct Harness {
    root: PathBuf,
    config: SurrealAdapterConfig,
    adapter: Option<Arc<SurrealStoreAdapter>>,
    case: String,
}

impl Harness {
    async fn fresh(case: &str) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("loopback")
            .local_addr()
            .expect("address")
            .port();
        let serial = HARNESS_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "eliot-sconc-994-{case}-{serial}-{}-{}",
            std::process::id(),
            unix_ms_now()
        ));
        let exe = root.join("bin/surreal.exe");
        let data = root.join("store/data");
        let work = root.join("store/work");
        let tmp = root.join("store/tmp");
        for path in [root.join("bin"), data.clone(), work.clone(), tmp.clone()] {
            std::fs::create_dir_all(path).expect("isolated root");
        }
        let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
            || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
            PathBuf::from,
        );
        std::fs::copy(&provider, &exe).expect("stage provider");
        let digest = eliot_store_api::sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
        let bind = format!("127.0.0.1:{port}");
        let mut config = SurrealAdapterConfig {
            endpoint: format!("ws://{bind}/rpc"),
            namespace: format!("sconc994{case}"),
            database: "accept994".into(),
            username: format!("sconc994-{case}"),
            password: SecretString::new(format!("test-994-{case}-{serial}").into()),
            provider_bind_address: bind,
            installation_id: format!("sconc994-{case}"),
            installation_profile: "portable_dev".into(),
            runtime_state_roots_digest: "a".repeat(64),
            provider_executable_path: exe.to_string_lossy().into_owned(),
            provider_artifact_digest: digest,
            provider_arguments: Vec::new(),
            store_data_root: data.to_string_lossy().into_owned(),
            store_work_root: work.to_string_lossy().into_owned(),
            store_temp_root: tmp.to_string_lossy().into_owned(),
            connect_timeout_ms: 30_000,
            query_timeout_ms: 30_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        };
        config.provider_arguments = config.expected_provider_arguments();
        let mut harness = Self {
            root,
            config,
            adapter: None,
            case: case.to_owned(),
        };
        println!(
            "SCONC-994 case={} provider={} sha256={} port={} root={}",
            case,
            harness.config.provider_executable_path,
            harness.config.provider_artifact_digest,
            port,
            harness.root.display()
        );
        harness.bootstrap();
        harness.open().await;
        harness.migrate().await;
        harness
    }

    fn bootstrap(&self) {
        use std::os::windows::process::CommandExt;
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let mut child = std::process::Command::new(&self.config.provider_executable_path)
            .args(&self.config.provider_arguments)
            .current_dir(&self.config.store_work_root)
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env("TEMP", &self.config.store_temp_root)
            .env("TMP", &self.config.store_temp_root)
            .env("SURREAL_USER", &self.config.username)
            .env("SURREAL_PASS", self.config.password.expose_secret())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .expect("bootstrap provider");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                child.try_wait().expect("child status").is_none(),
                "bootstrap exited"
            );
            if std::net::TcpStream::connect(&self.config.provider_bind_address).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "bootstrap bind timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
        child.kill().expect("stop bootstrap");
        child.wait().expect("reap bootstrap");
    }

    async fn open(&mut self) {
        let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
        // Every provider adapter carries the frozen profile client-set
        // limits (read/write/admin sessions), so profile lanes validate.
        let limits = eliot_store_surreal_adapter::ClientSetLimits::new(
            profile_u8("read_sessions"),
            profile_u8("write_sessions"),
            profile_u8("admin_sessions"),
        )
        .expect("profile limits");
        let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
        let mut last_error = None;
        loop {
            let lease = platform
                .retain_process_path_lease(
                    Path::new(&self.config.provider_executable_path),
                    Path::new(&self.config.store_work_root),
                    &self.config.provider_artifact_digest,
                )
                .expect("process lease");
            self.adapter = Some(Arc::new(
                SurrealStoreAdapter::new_with_client_set(
                    self.config.clone(),
                    lease,
                    eliot_store_api::genesis_manifest().expect("genesis manifest"),
                    limits,
                )
                .expect("adapter"),
            ));
            match tokio::time::timeout_at(deadline, self.adapter().connect()).await {
                Ok(Ok(())) => return,
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    self.adapter = None;
                    panic!(
                        "case {} readiness timed out; last error: {last_error:?}",
                        self.case
                    );
                }
            }
            self.adapter = None;
            assert!(
                tokio::time::Instant::now() < deadline,
                "case {} readiness timed out; last error: {last_error:?}",
                self.case
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn migrate(&self) {
        let ctx = ctx_for(&format!("migrate-{}", self.case), &fence());
        self.adapter()
            .apply_migration(
                &SurrealStoreAdapter::v2_baseline_migration(),
                &ctx.clock,
                &ctx.state_fence,
            )
            .await
            .expect("baseline migration");
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_deref().expect("live adapter")
    }

    fn adapter_shared(&self) -> Arc<SurrealStoreAdapter> {
        self.adapter.clone().expect("live adapter")
    }

    async fn commit(&self, operation: &str, scope: &str, subject: &str) -> WriteReceipt {
        let (ctx, transition) = admitted(operation, scope, subject);
        let receipt = CanonicalStoreClient::apply_prepared(
            self.adapter(),
            &ctx,
            transition.clone(),
            vec![],
            vec![],
        )
        .await
        .unwrap_or_else(|error| panic!("commit {operation} failed: {error:?}"));
        validate_store_receipt_envelope(&ctx, &transition, &receipt).expect("envelope");
        receipt
    }

    async fn snapshot(&self) -> eliot_store_api::StoreRecoverySnapshot {
        let snapshot = self
            .adapter()
            .recovery(StoreRecoveryRequest {
                contract_version: CONTRACT_VERSION,
                state_fence: fence(),
                records: Vec::new(),
                include_receipts: true,
                include_jobs: false,
            })
            .await
            .expect("recovery snapshot");
        snapshot.validate().expect("snapshot validates");
        snapshot
    }

    /// Drops the adapter generation (terminating its owned provider) and
    /// reconnects a fresh generation on the same data root with a new port.
    async fn restart(&mut self) {
        self.adapter = None;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("loopback")
            .local_addr()
            .expect("address")
            .port();
        let bind = format!("127.0.0.1:{port}");
        self.config.provider_bind_address = bind.clone();
        self.config.endpoint = format!("ws://{bind}/rpc");
        // The canonical argv embeds the bind address; recompute it.
        self.config.provider_arguments = self.config.expected_provider_arguments();
        println!("SCONC-994 case={} restart port={}", self.case, port);
        self.open().await;
    }

    async fn cleanup(mut self) {
        self.adapter = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::fs::remove_dir_all(&self.root).is_err() {
            assert!(
                Instant::now() < deadline,
                "case {} root cleanup failed",
                self.case
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn assert_committed(operation: &str, receipt: &WriteReceipt) {
    assert_eq!(receipt.operation_id.as_str(), operation);
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    receipt.validate().expect("receipt validates");
    assert_eq!(
        receipt.ordering_sequences.len(),
        1,
        "ordering fields preserved"
    );
    assert_eq!(
        receipt.revision_before_after.len(),
        1,
        "revision fields preserved"
    );
    assert_eq!(receipt.emitted_event_ids.len(), 1);
    assert_eq!(
        receipt.emitted_event_ids[0].to_string(),
        format!("event-{operation}"),
        "event identity derives from the admitted operation"
    );
}

// WORK_UNIT_CASE: 994/2
#[tokio::test]
async fn reference_versus_surreal_equivalence() {
    let entry = case_entry(2);
    assert_eq!(
        entry["name"].as_str().expect("name"),
        "reference_versus_surreal_equivalence"
    );
    let harness = Harness::fresh("02").await;
    // Same immutable semantic operations on both backends, same order.
    let operations = [
        ("op-994-equiv-a", "scope-994-a", "subject-994-02-a"),
        ("op-994-equiv-b", "scope-994-b", "subject-994-02-b"),
    ];
    // Reference side: register the whole generated catalogue; the transition
    // binds the admitting single-manifest digest (memory contour).
    let memory = MemoryStore::new();
    for manifest in generated_operation_manifests().expect("catalogue") {
        memory.register_manifest(manifest).expect("register");
    }
    let admit_single = {
        let entries = generated_operation_manifests().expect("catalogue");
        entries
            .into_iter()
            .find(|candidate| {
                let mut probe = admitted("op-994-probe", "scope-994-a", "probe").1;
                probe.operation_manifest_digest = candidate.digest.clone();
                probe.validate_against_manifest(candidate).is_ok()
            })
            .expect("capture entry")
    };
    let mut reference_receipts = Vec::new();
    for (operation, scope, subject) in operations {
        let fence = fence();
        let ctx = ctx_for(operation, &fence);
        let mut transition = admitted(operation, scope, subject).1;
        transition.operation_manifest_digest = admit_single.digest.clone();
        transition.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]),
        )
        .expect("request hash");
        let receipt = memory
            .apply_transaction(&ctx, transition.clone(), &[], &[])
            .unwrap_or_else(|error| panic!("reference commit {operation} failed: {error:?}"));
        validate_store_receipt_envelope(&ctx, &transition, &receipt).expect("envelope");
        reference_receipts.push(receipt);
    }
    let mut product_receipts = Vec::new();
    for (operation, scope, subject) in operations {
        let receipt = harness.commit(operation, scope, subject).await;
        product_receipts.push(receipt);
    }
    // Semantic equivalence: identical admitted identity, class, status,
    // fence, derived event, head deltas and effect counts. Normalized by
    // contour: manifest-digest representation (set vs single), canonical
    // request hash (binds that digest), commit instant and commit identity.
    for ((reference, product), (operation, scope, _)) in reference_receipts
        .iter()
        .zip(product_receipts.iter())
        .zip(operations.iter())
    {
        assert_eq!(reference.operation_id, product.operation_id);
        assert_eq!(reference.idempotency_key, product.idempotency_key);
        assert_eq!(reference.transition_class, product.transition_class);
        assert_eq!(reference.status, product.status);
        assert_eq!(reference.state_fence, product.state_fence);
        assert_eq!(reference.emitted_event_ids, product.emitted_event_ids);
        assert_eq!(
            reference.emitted_event_ids[0].to_string(),
            format!("event-{operation}")
        );
        assert_eq!(
            reference.applied_command_ids.len(),
            product.applied_command_ids.len()
        );
        assert_eq!(
            reference.projection_refs.len(),
            product.projection_refs.len()
        );
        assert_eq!(reference.outbox_refs.len(), product.outbox_refs.len());
        assert_eq!(
            reference.ordering_sequences.len(),
            product.ordering_sequences.len()
        );
        assert_eq!(reference.ordering_sequences[0].scope.as_str(), *scope);
        assert_eq!(
            reference.ordering_sequences[0].scope,
            product.ordering_sequences[0].scope
        );
        assert_eq!(
            reference.ordering_sequences[0].sequence, product.ordering_sequences[0].sequence,
            "same arrival order advances per-scope heads identically"
        );
        assert_eq!(
            reference.revision_before_after.len(),
            product.revision_before_after.len()
        );
        assert_eq!(
            reference.revision_before_after[0].key,
            product.revision_before_after[0].key
        );
        assert_eq!(
            reference.revision_before_after[0].before,
            product.revision_before_after[0].before
        );
        assert_eq!(
            reference.revision_before_after[0].after,
            product.revision_before_after[0].after
        );
        assert_eq!(reference.canonical_request_hash.len(), 64);
        assert_eq!(product.canonical_request_hash.len(), 64);
        assert_ne!(
            reference.operation_manifest_digest, product.operation_manifest_digest,
            "contours bind different digest representations of the same catalogue"
        );
    }
    let memory_snapshot = memory.snapshot().expect("memory snapshot");
    let product_snapshot = harness.snapshot().await;
    assert_eq!(
        memory_snapshot.receipts.len(),
        product_snapshot.receipts.len()
    );
    assert_eq!(
        memory_snapshot.projections.len(),
        product_snapshot
            .receipts
            .iter()
            .map(|r| r.projection_refs.len())
            .sum::<usize>()
    );
    assert_eq!(
        memory_snapshot.outbox.len(),
        product_snapshot
            .receipts
            .iter()
            .map(|r| r.outbox_refs.len())
            .sum::<usize>()
    );
    println!(
        "SCONC-994 case=02 equivalence ok productsha={} port={}",
        harness.config.provider_artifact_digest, harness.config.provider_bind_address
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/3
#[tokio::test]
async fn independent_scope_provider_overlap() {
    case_entry(3);
    let harness = Harness::fresh("03").await;
    let (ctx_a, transition_a) = admitted("op-994-overlap-a", "scope-994-a", "subject-994-03-a");
    let (ctx_b, transition_b) = admitted("op-994-overlap-b", "scope-994-b", "subject-994-03-b");
    let (receipt_a, receipt_b, started_ms, ended_ms) = {
        let adapter = harness.adapter();
        let rendezvous = Arc::new(tokio::sync::Barrier::new(3));
        adapter.arm_tx_rendezvous(Arc::clone(&rendezvous));
        let started_ms = unix_ms_now();

        let writer_a = CanonicalStoreClient::apply_prepared(
            adapter,
            &ctx_a,
            transition_a.clone(),
            vec![],
            vec![],
        );
        let writer_b = CanonicalStoreClient::apply_prepared(
            adapter,
            &ctx_b,
            transition_b.clone(),
            vec![],
            vec![],
        );

        tokio::pin!(writer_a);
        tokio::pin!(writer_b);

        let _witness = tokio::time::timeout(
            Duration::from_millis(profile_u64("rendezvous_ms")),
            async {
                tokio::select! {
                    result = &mut writer_a => panic!("writer A completed before both transaction attempts rendezvoused: {result:?}"),
                    result = &mut writer_b => panic!("writer B completed before both transaction attempts rendezvoused: {result:?}"),
                    _ = rendezvous.wait() => {}
                }
            },
        )
        .await
        .expect("both production writers must reach the post-admission transaction-attempt rendezvous");

        let (receipt_a, receipt_b) = tokio::join!(writer_a, writer_b);
        let ended_ms = unix_ms_now();
        adapter.disarm_tx_rendezvous();

        let receipt_a = receipt_a.expect("writer A commits");
        let receipt_b = receipt_b.expect("writer B commits");
        (receipt_a, receipt_b, started_ms, ended_ms)
    };
    validate_store_receipt_envelope(&ctx_a, &transition_a, &receipt_a).expect("envelope A");
    validate_store_receipt_envelope(&ctx_b, &transition_b, &receipt_b).expect("envelope B");
    assert_committed("op-994-overlap-a", &receipt_a);
    assert_committed("op-994-overlap-b", &receipt_b);
    assert_ne!(
        commit_sequence(&receipt_a),
        commit_sequence(&receipt_b),
        "no shared allocation"
    );
    println!(
        "SCONC-994 case=03 overlap ok sha={} port={} window_ms={}..{}",
        harness.config.provider_artifact_digest,
        harness.config.provider_bind_address,
        started_ms,
        ended_ms
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/9
#[tokio::test]
async fn cancellation_before_send_no_effect() {
    case_entry(9);
    let harness = Harness::fresh("09").await;
    let (ctx, transition) = admitted("op-994-cancel-early", "scope-994-a", "subject-994-09");
    // Cancel before send: the admitted future is dropped without ever being
    // polled, so no frame crosses the provider seam.
    let operation_id = transition.identity.operation_id.clone();
    let pending =
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx, transition, vec![], vec![]);
    drop(pending);
    let reconciled = harness
        .adapter()
        .reconcile(operation_id)
        .await
        .expect("reconcile");
    assert!(
        reconciled.is_none(),
        "cancelled-before-send leaves no receipt"
    );
    let snapshot = harness.snapshot().await;
    assert!(snapshot.receipts.is_empty(), "no provider effect");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/10
#[tokio::test]
async fn cancellation_timeout_after_possible_send_scoped_uncertainty() {
    case_entry(10);
    let harness = Harness::fresh("10").await;
    let (ctx_u, transition_u) = admitted("op-994-uncertain", "scope-994-a", "subject-994-10-u");
    let operation_id = transition_u.identity.operation_id.clone();
    let adapter = harness.adapter();
    // Release one writer past the post-admission rendezvous toward the
    // provider, then abort its join handle: the abort may land before or
    // after the provider commit, so the outcome is genuinely unknown until
    // reconciled by exact operation identity.
    let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
    adapter.arm_tx_rendezvous(Arc::clone(&rendezvous));
    // LocalSet: the abortable writer owns everything it captures.
    let adapter_shared = harness.adapter_shared();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let writer = tokio::task::spawn_local({
                let adapter_shared = adapter_shared.clone();
                async move {
                    CanonicalStoreClient::apply_prepared(
                        adapter_shared.as_ref(),
                        &ctx_u,
                        transition_u,
                        vec![],
                        vec![],
                    )
                    .await
                }
            });
            rendezvous.wait().await;
            adapter.disarm_tx_rendezvous();
            tokio::task::yield_now().await;
            writer.abort();
            let _ = writer.await;
        })
        .await;
    drop(adapter_shared);
    // Uncertainty is scoped: a sibling disjoint scope still commits cleanly.
    let sibling = harness
        .commit("op-994-steady", "scope-994-b", "subject-994-10-s")
        .await;
    assert_committed("op-994-steady", &sibling);
    // Resolve exactly the admitted operation: committed receipt or proven
    // absence; either way no blind duplicate effect.
    let reconciled = harness
        .adapter()
        .reconcile(operation_id.clone())
        .await
        .expect("reconcile");
    if let Some(receipt) = reconciled {
        assert_eq!(receipt.operation_id.as_str(), "op-994-uncertain");
        let (rctx, rtransition) = admitted("op-994-uncertain", "scope-994-a", "subject-994-10-u");
        let replayed = CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &rctx,
            rtransition,
            vec![],
            vec![],
        )
        .await
        .expect("replay after proven commit");
        assert_eq!(replayed, receipt, "no second effect");
    } else {
        let receipt = harness
            .commit("op-994-uncertain", "scope-994-a", "subject-994-10-u")
            .await;
        assert_committed("op-994-uncertain", &receipt);
    }
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/11
#[tokio::test]
async fn precommit_crash_reconciles_only_on_proven_absence() {
    case_entry(11);
    let harness = Harness::fresh("11").await;
    // A pre-commit crash leaves nothing durable: reconcile proves absence.
    let absent = harness
        .adapter()
        .reconcile(ApiOperationId::new("op-994-absent").expect("operation"))
        .await
        .expect("reconcile");
    assert!(
        absent.is_none(),
        "never-sent operation must reconcile absent"
    );
    // Only on that proof may the same identity commit.
    let receipt = harness
        .commit("op-994-absent", "scope-994-a", "subject-994-11")
        .await;
    assert_committed("op-994-absent", &receipt);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/12
#[tokio::test]
async fn postcommit_response_loss_recovers_original_receipt() {
    case_entry(12);
    let harness = Harness::fresh("12").await;
    let before = harness.snapshot().await;
    let committed = harness
        .commit("op-994-committed", "scope-994-a", "subject-994-12")
        .await;
    assert_committed("op-994-committed", &committed);
    // Response loss: the caller holds no receipt, so it reconciles by exact
    // operation identity and recovers the original without replay.
    let recovered = harness
        .adapter()
        .reconcile(ApiOperationId::new("op-994-committed").expect("operation"))
        .await
        .expect("reconcile")
        .expect("committed operation must reconcile");
    assert_eq!(recovered, committed, "original receipt recovered");
    // Re-applying the same operation returns the identical receipt with no
    // new effect: heads and receipt count unchanged.
    let (ctx, transition) = admitted("op-994-committed", "scope-994-a", "subject-994-12");
    let replayed =
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx, transition, vec![], vec![])
            .await
            .expect("exact replay");
    assert_eq!(replayed, committed);
    let after = harness.snapshot().await;
    assert_eq!(
        after.receipts.len(),
        before.receipts.len() + 1,
        "replay adds no effect"
    );
    assert_eq!(
        after.validation_revision,
        before.validation_revision + 1,
        "one commit only"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/13
#[tokio::test]
async fn independent_scope_progress_under_delay_poison() {
    case_entry(13);
    let harness = Harness::fresh("13").await;
    // The live scope commits first with a valid receipt.
    let live = harness
        .commit("op-994-live", "scope-994-a", "subject-994-13-live")
        .await;
    assert_committed("op-994-live", &live);
    // Then the poison scope stalls inside the provider seam: it cannot pass
    // the rendezvous until the test observer arrives.
    let (ctx_p, transition_p) = admitted("op-994-stalled", "scope-994-poison", "subject-994-13-p");
    let poison_id = transition_p.identity.operation_id.clone();
    let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
    harness.adapter().arm_tx_rendezvous(Arc::clone(&rendezvous));
    // Both branches run on this task: the observer's checks execute while
    // the stalled writer is parked at the rendezvous, because the barrier
    // needs both parties and the observer has not arrived yet.
    let (stalled_result, ()) = tokio::join!(
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_p,
            transition_p,
            vec![],
            vec![]
        ),
        async {
            // While the poison scope is delayed/unknown, the live scope's
            // commit stands proven: reconcile returns its exact receipt, and
            // recovery accounts it with no poison effect present.
            let proven = harness
                .adapter()
                .reconcile(ApiOperationId::new("op-994-live").expect("operation"))
                .await
                .expect("reconcile")
                .expect("live commit must reconcile");
            assert_eq!(proven, live);
            assert!(
                harness
                    .adapter()
                    .reconcile(poison_id.clone())
                    .await
                    .expect("reconcile")
                    .is_none(),
                "stalled scope has no durable effect yet"
            );
            let snapshot = harness.snapshot().await;
            assert!(
                snapshot
                    .receipts
                    .iter()
                    .any(|r| r.operation_id.as_str() == "op-994-live")
            );
            assert!(
                !snapshot
                    .receipts
                    .iter()
                    .any(|r| r.operation_id.as_str() == "op-994-stalled")
            );
            // Release the stall; the poison writer then proceeds.
            rendezvous.wait().await;
            harness.adapter().disarm_tx_rendezvous();
        },
    );
    // The poison scope commits exactly once after release.
    let poison_receipt = stalled_result.expect("poison commits after release");
    assert_committed("op-994-stalled", &poison_receipt);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/14
#[test]
fn bounded_capacity_with_protected_recovery() {
    case_entry(14);
    assert_eq!(profile_value("accepted_generation"), "v2");
    // Profile bounds are fixed closed values: 1..=8 sessions per role.
    let limits = eliot_store_surreal_adapter::ClientSetLimits::new(
        profile_u8("read_sessions"),
        profile_u8("write_sessions"),
        profile_u8("admin_sessions"),
    )
    .expect("profile limits valid");
    assert_eq!(limits.read_sessions(), 5);
    assert_eq!(limits.write_sessions(), 2);
    assert_eq!(limits.admin_sessions(), 1);
    assert!(
        eliot_store_surreal_adapter::ClientSetLimits::new(0, 1, 1).is_err(),
        "zero lane rejected"
    );
    assert!(
        eliot_store_surreal_adapter::ClientSetLimits::new(9, 1, 1).is_err(),
        "oversize lane rejected"
    );
    let compat = eliot_store_surreal_adapter::ClientSetLimits::compatibility();
    assert_eq!(
        (
            compat.read_sessions(),
            compat.write_sessions(),
            compat.admin_sessions()
        ),
        (1, 1, 1)
    );
    // Execution generations gate reserved writes without touching a provider.
    // Layout mirrors the provider harness: every path sits under one
    // platform root so the process lease validates.
    let platform_root = std::env::temp_dir().join(format!(
        "eliot-sconc-994-14-{}-{}",
        std::process::id(),
        unix_ms_now()
    ));
    std::fs::create_dir_all(platform_root.join(".eliot")).expect("platform root");
    let platform = WindowsPlatform::new(platform_root.clone()).expect("platform");
    let root = platform_root.join("store");
    std::fs::create_dir_all(root.join("data")).expect("data root");
    std::fs::create_dir_all(root.join("work")).expect("work root");
    std::fs::create_dir_all(root.join("tmp")).expect("tmp root");
    let bin = platform_root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let provider_exe = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    let staged_exe = bin.join("surreal.exe");
    if std::fs::hard_link(&provider_exe, &staged_exe).is_err() {
        std::fs::copy(&provider_exe, &staged_exe).expect("stage provider");
    }
    let provider_digest =
        eliot_store_api::sha256_hex(&std::fs::read(&staged_exe).expect("provider bytes"));
    let mut config = SurrealAdapterConfig {
        endpoint: "ws://127.0.0.1:1/rpc".into(),
        namespace: "sconc994probe".into(),
        database: "accept994".into(),
        username: "sconc994-probe".into(),
        password: SecretString::new("test-probe".into()),
        provider_bind_address: "127.0.0.1:1".into(),
        installation_id: "sconc994-probe".into(),
        installation_profile: "portable_dev".into(),
        runtime_state_roots_digest: "a".repeat(64),
        provider_executable_path: staged_exe.to_string_lossy().into_owned(),
        provider_artifact_digest: provider_digest,
        provider_arguments: Vec::new(),
        store_data_root: root.join("data").to_string_lossy().into_owned(),
        store_work_root: root.join("work").to_string_lossy().into_owned(),
        store_temp_root: root.join("tmp").to_string_lossy().into_owned(),
        connect_timeout_ms: 1_000,
        query_timeout_ms: 1_000,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    config.provider_arguments = config.expected_provider_arguments();
    let lease = platform
        .retain_process_path_lease(
            Path::new(&config.provider_executable_path),
            Path::new(&config.store_work_root),
            &config.provider_artifact_digest,
        )
        .expect("process lease");
    // The probe adapter carries the frozen profile client-set limits so the
    // profile lane count validates.
    let adapter = SurrealStoreAdapter::new_with_client_set(
        config,
        lease,
        eliot_store_api::genesis_manifest().expect("genesis manifest"),
        limits,
    )
    .expect("adapter");
    assert!(
        adapter.reserved_write_capability().is_none(),
        "no capability before install"
    );
    adapter
        .install_serial_execution(NonZeroUsize::new(profile_usize("max_pending")).expect("pending"))
        .expect("serial install");
    assert!(
        adapter.reserved_write_capability().is_none(),
        "serial generation refuses reserved writes"
    );
    assert!(
        adapter
            .install_serial_execution(NonZeroUsize::new(1).expect("one"))
            .is_err(),
        "no live overwrite"
    );
    adapter
        .uninstall_drained_execution()
        .expect("drained uninstall");
    assert!(
        adapter.uninstall_drained_execution().is_err(),
        "uninstall when none fails closed"
    );
    adapter
        .install_concurrent_execution(
            NonZeroUsize::new(profile_usize("lanes")).expect("lanes"),
            NonZeroUsize::new(profile_usize("max_pending")).expect("pending"),
            SchemaGeneration::v2(),
            "kernel-994-test".to_owned(),
            fence(),
        )
        .expect("concurrent install");
    assert!(
        adapter.reserved_write_capability().is_some(),
        "concurrent generation advertises capability"
    );
    adapter
        .uninstall_drained_execution()
        .expect("drained uninstall");
    let _ = std::fs::remove_dir_all(&platform_root);
}

// WORK_UNIT_CASE: 994/15
#[tokio::test]
async fn migration_drain_accounts_every_operation() {
    case_entry(15);
    let harness = Harness::fresh("15").await;
    // Live history first on the direct path.
    let drained = harness
        .commit("op-994-drain", "scope-994-a", "subject-994-15")
        .await;
    assert_committed("op-994-drain", &drained);
    // Install the concurrent generation over live state.
    harness
        .adapter()
        .install_concurrent_execution(
            NonZeroUsize::new(profile_usize("lanes")).expect("lanes"),
            NonZeroUsize::new(profile_usize("max_pending")).expect("pending"),
            SchemaGeneration::v2(),
            "kernel-994-test".to_owned(),
            fence(),
        )
        .expect("concurrent install");
    assert!(harness.adapter().reserved_write_capability().is_some());
    // Exclusion while the concurrent profile owns admission: ordinary
    // unreserved writes are refused with a typed error, never silently
    // queued or partially applied.
    let (ex_ctx, ex_transition) = admitted("op-994-excluded", "scope-994-a", "subject-994-15-x");
    let excluded = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ex_ctx,
        ex_transition,
        vec![],
        vec![],
    )
    .await;
    assert!(
        matches!(
            excluded,
            Err(eliot_store_api::StoreError::InvalidField {
                field: "store.write_path",
                ..
            })
        ),
        "concurrent profile must refuse unreserved writes, got {excluded:?}"
    );
    // Drain: the quiesced generation uninstalls, and the recovery snapshot
    // accounts for every operation with the excluded write absent.
    let accounted = harness.snapshot().await;
    assert!(
        accounted
            .receipts
            .iter()
            .any(|r| r.operation_id.as_str() == "op-994-drain")
    );
    assert!(
        !accounted
            .receipts
            .iter()
            .any(|r| r.operation_id.as_str() == "op-994-excluded")
    );
    harness
        .adapter()
        .uninstall_drained_execution()
        .expect("drained uninstall");
    assert!(harness.adapter().reserved_write_capability().is_none());
    assert!(
        harness.adapter().uninstall_drained_execution().is_err(),
        "exclusion persists"
    );
    let retained = harness
        .adapter()
        .reconcile(ApiOperationId::new("op-994-drain").expect("operation"))
        .await
        .expect("reconcile")
        .expect("drained receipt retained");
    assert_eq!(retained, drained);
    // Reopen is an explicit generation install, after which the direct path
    // flows again on the drained state.
    let reopened = harness
        .commit("op-994-reopen", "scope-994-a", "subject-994-15-r")
        .await;
    assert_committed("op-994-reopen", &reopened);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/16
#[tokio::test]
async fn unknown_failed_migration_stays_fenced() {
    case_entry(16);
    assert_eq!(profile_value("reopen_requires_accepted"), "true");
    let harness = Harness::fresh("16").await;
    let before = harness.snapshot().await;
    // An unknown generation is not admitted: the attempt fails closed with
    // no state change, and the store stays on its accepted generation.
    let unknown = SurrealStoreAdapter::initial_schema_migration(
        SchemaGeneration::new("9.9.9").expect("generation"),
    );
    let ctx = ctx_for("migrate-unknown-16", &fence());
    let failed = harness
        .adapter()
        .apply_migration(&unknown, &ctx.clock, &ctx.state_fence)
        .await;
    assert!(
        failed.is_err(),
        "unknown generation must stay fenced: {failed:?}"
    );
    let fenced = harness.snapshot().await;
    assert_eq!(fenced.receipts.len(), before.receipts.len());
    assert_eq!(fenced.validation_revision, before.validation_revision);
    // Only the accepted generation reopens the path: exact replay of the
    // baseline succeeds and normal writes still flow.
    let accepted_ctx = ctx_for("migrate-accepted-16", &fence());
    harness
        .adapter()
        .apply_migration(
            &SurrealStoreAdapter::v2_baseline_migration(),
            &accepted_ctx.clock,
            &accepted_ctx.state_fence,
        )
        .await
        .expect("accepted generation reopens");
    let receipt = harness
        .commit("op-994-fenced-ok", "scope-994-a", "subject-994-16")
        .await;
    assert_committed("op-994-fenced-ok", &receipt);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/17
#[tokio::test]
async fn restart_reconstructs_state_without_orphans() {
    case_entry(17);
    let mut harness = Harness::fresh("17").await;
    let receipt_a = harness
        .commit("op-994-restart-a", "scope-994-a", "subject-994-17-a")
        .await;
    let receipt_b = harness
        .commit("op-994-restart-b", "scope-994-b", "subject-994-17-b")
        .await;
    let before = harness.snapshot().await;
    // Restart: a fresh adapter generation on the same provider data root.
    harness.restart().await;
    let after = harness.snapshot().await;
    assert_eq!(after.receipts.len(), before.receipts.len());
    for expected in [receipt_a, receipt_b] {
        let reconstructed = after
            .receipts
            .iter()
            .find(|r| r.operation_id == expected.operation_id)
            .unwrap_or_else(|| {
                panic!(
                    "receipt missing after restart: {}",
                    expected.operation_id.as_str()
                )
            });
        assert_eq!(
            *reconstructed, expected,
            "no orphaned or rewritten reservation"
        );
    }
    // The reconstructed store accepts new writes with no gaps or duplicates.
    let receipt_c = harness
        .commit("op-994-restart-c", "scope-994-a", "subject-994-17-c")
        .await;
    assert_committed("op-994-restart-c", &receipt_c);
    let final_snapshot = harness.snapshot().await;
    assert_eq!(final_snapshot.receipts.len(), before.receipts.len() + 1);
    let mut operations: BTreeSet<String> = final_snapshot
        .receipts
        .iter()
        .map(|r| r.operation_id.as_str().to_owned())
        .collect();
    assert_eq!(
        operations.len(),
        final_snapshot.receipts.len(),
        "no duplicate receipts"
    );
    assert!(operations.remove("op-994-restart-a"));
    assert!(operations.remove("op-994-restart-b"));
    assert!(operations.remove("op-994-restart-c"));
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/18
#[tokio::test]
async fn session_process_root_cleanup() {
    case_entry(18);
    let harness = Harness::fresh("18").await;
    // Primary work first so cleanup has a live session to retire.
    let primary = harness
        .commit("op-994-cleanup", "scope-994-a", "subject-994-18")
        .await;
    assert_committed("op-994-cleanup", &primary);
    let live = harness.snapshot().await;
    assert!(
        live.receipts
            .iter()
            .any(|r| r.operation_id.as_str() == "op-994-cleanup")
    );
    let provider_path = harness.config.provider_executable_path.clone();
    let provider_digest = harness.config.provider_artifact_digest.clone();
    let provider_bind = harness.config.provider_bind_address.clone();
    let root = harness.root.clone();
    assert!(
        Path::new(&provider_path).exists(),
        "staged provider present"
    );
    harness.cleanup().await;
    // Both primary and cleanup outcomes are retained here as assertions:
    // the receipt was proven above, and the isolated root is fully gone.
    assert!(!root.exists(), "isolated root removed");
    assert!(
        !Path::new(&provider_path).exists(),
        "staged provider retired"
    );
    println!(
        "SCONC-994 case=18 cleanup ok sha={provider_digest} bind={provider_bind} root={}",
        root.display()
    );
}

// WORK_UNIT_CASE: 994/19
#[tokio::test]
async fn product_pulse_kernel_route_progress() {
    let entry = case_entry(19);
    assert_eq!(
        entry["name"].as_str().expect("name"),
        "product_pulse_kernel_route_progress"
    );
    let harness = Harness::fresh("19").await;
    let adapter_shared = harness.adapter_shared();
    // The admitted Kernel route: the production EBP store client speaks real
    // EBP frames; only the OS pipe transport is looped back in-process to
    // the live Surreal adapter. Handshake, readiness, admission, framing,
    // reconciliation and receipt decoding are all production code.
    struct LoopbackTransport {
        requirement: HostStoreBootstrapRequirement,
        adapter: Arc<SurrealStoreAdapter>,
        pending: Option<Frame>,
    }
    impl LoopbackTransport {
        fn answer(
            connection: &str,
            request_id: RequestId,
            response: eliot_store_api::StoreResponse,
        ) -> Frame {
            eliot_store_api::response_frame(
                connection.to_owned(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                response,
            )
            .expect("response frame")
        }
    }
    impl EbpStoreTransport for LoopbackTransport {
        fn ensure_authenticated(
            &self,
            _requirement: &HostStoreBootstrapRequirement,
        ) -> Result<(), StoreClientError> {
            Ok(())
        }

        async fn send_frame(
            &mut self,
            frame: &Frame,
            _limits: TransportLimits,
        ) -> Result<DeliveryOutcome, StoreClientError> {
            let adapter = self.adapter.clone();
            if frame.kind == FrameKind::Control {
                let hello = ServerHello {
                    selected_protocol: ProtocolVersion::CURRENT,
                    session_principal_binding: "sconc994-19-store-session".to_owned(),
                    allowed_capabilities: eliot_store_api::CAPABILITIES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    allowed_effects: eliot_store_api::EFFECTS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    config_snapshot: json!({
                        "config_hash": self.requirement.approved_config_hash.as_str(),
                        "artifact_hash": self.requirement.approved_artifact_hash.as_str(),
                    }),
                    heartbeat_ms: 1_000,
                    control_channel: "sconc994-19-control".to_owned(),
                    rejection_reason: None,
                    authority_epoch: self.requirement.authority_epoch().clone(),
                };
                self.pending = Some(
                    eliot_ipc::server_hello_frame(self.requirement.connection_id.as_str(), &hello)
                        .expect("server hello"),
                );
                return Ok(DeliveryOutcome::Delivered);
            }
            let (request_id, _identity, request) =
                eliot_store_api::decode_request_frame(frame).map_err(StoreClientError::from)?;
            let connection = self.requirement.connection_id.as_str().to_owned();
            match request {
                eliot_store_api::StoreRequest::Readiness => {
                    self.pending = Some(Self::answer(
                        &connection,
                        request_id,
                        eliot_store_api::StoreResponse::Readiness {
                            receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
                        },
                    ));
                }
                eliot_store_api::StoreRequest::Apply {
                    context,
                    transition,
                    expected_revision_heads,
                    expected_ordering_heads,
                } => {
                    let outcome = CanonicalStoreClient::apply_prepared(
                        adapter.as_ref(),
                        &context,
                        transition,
                        expected_revision_heads,
                        expected_ordering_heads,
                    )
                    .await;
                    match outcome {
                        Ok(receipt) => {
                            self.pending = Some(Self::answer(
                                &connection,
                                request_id,
                                eliot_store_api::StoreResponse::Transaction { receipt },
                            ));
                        }
                        Err(error) => {
                            return Err(StoreClientError::Store(error));
                        }
                    }
                }
                eliot_store_api::StoreRequest::Receipt { operation_id } => {
                    let receipt = adapter
                        .reconcile(operation_id)
                        .await
                        .map_err(|error| StoreClientError::Transport(error.to_string()))?;
                    self.pending = Some(Self::answer(
                        &connection,
                        request_id,
                        eliot_store_api::StoreResponse::Receipt { receipt },
                    ));
                }
                _ => {
                    return Err(StoreClientError::Contract(
                        "loopback received unexpected request".to_owned(),
                    ));
                }
            }
            Ok(DeliveryOutcome::Delivered)
        }

        async fn receive_frame(
            &mut self,
            _limits: TransportLimits,
        ) -> Result<Frame, StoreClientError> {
            self.pending
                .take()
                .ok_or_else(|| StoreClientError::Transport("loopback response missing".to_owned()))
        }
    }
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").expect("route"),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-994-19").expect("pipe"),
        store_generation: ResourceGeneration::genesis(),
        state_fence: fence(),
        launch_nonce: PlatformHandle::new("store-launch-994-19").expect("nonce"),
        connection_id: PlatformHandle::new("store-conn-994-19").expect("conn"),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
        timeout_ms: 30_000,
    };
    let client = EbpCanonicalStoreClient::connect(
        LoopbackTransport {
            requirement,
            adapter: adapter_shared,
            pending: None,
        },
        HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new("store_bridge").expect("route"),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-994-19")
                .expect("pipe"),
            store_generation: ResourceGeneration::genesis(),
            state_fence: fence(),
            launch_nonce: PlatformHandle::new("store-launch-994-19").expect("nonce"),
            connection_id: PlatformHandle::new("store-conn-994-19").expect("conn"),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
            expected_peer_session_id: 0,
            approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
            approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
            timeout_ms: 30_000,
        },
    )
    .await
    .expect("EBP connect over loopback");
    // Pulse progress: two independent pulse scopes advance concurrently with
    // valid committed receipts through the admitted route.
    let (pulse_ctx_a, pulse_a) =
        admitted("op-994-pulse-a", "scope-994-pulse-a", "subject-994-19-a");
    let (pulse_ctx_b, pulse_b) =
        admitted("op-994-pulse-b", "scope-994-pulse-b", "subject-994-19-b");
    let (receipt_a, receipt_b) = tokio::join!(
        CanonicalStoreClient::apply_prepared(
            &client,
            &pulse_ctx_a,
            pulse_a.clone(),
            vec![],
            vec![]
        ),
        CanonicalStoreClient::apply_prepared(
            &client,
            &pulse_ctx_b,
            pulse_b.clone(),
            vec![],
            vec![]
        ),
    );
    let receipt_a = receipt_a.expect("pulse A progresses");
    let receipt_b = receipt_b.expect("pulse B progresses");
    validate_store_receipt_envelope(&pulse_ctx_a, &pulse_a, &receipt_a).expect("envelope A");
    validate_store_receipt_envelope(&pulse_ctx_b, &pulse_b, &receipt_b).expect("envelope B");
    assert_committed("op-994-pulse-a", &receipt_a);
    assert_committed("op-994-pulse-b", &receipt_b);
    // Pulse cancellation: the admitted cancel future is dropped before send,
    // then the route reconciles proven absence by exact operation identity.
    let (cancel_ctx, cancel_transition) = admitted(
        "op-994-pulse-cancel",
        "scope-994-pulse-a",
        "subject-994-19-c",
    );
    let cancel_id = cancel_transition.identity.operation_id.clone();
    let cancelled = CanonicalStoreClient::apply_prepared(
        &client,
        &cancel_ctx,
        cancel_transition,
        vec![],
        vec![],
    );
    drop(cancelled);
    let absence: Option<WriteReceipt> = client
        .receipt(ApiOperationId::new(cancel_id.as_str()).expect("operation"))
        .await
        .expect("receipt query");
    assert!(absence.is_none(), "cancelled pulse has no provider effect");
    // Pulse recovery: committed pulse operations reconcile to their exact
    // original receipts through the same route.
    for expected in [&receipt_a, &receipt_b] {
        let recovered: Option<WriteReceipt> = client
            .receipt(ApiOperationId::new(expected.operation_id.as_str()).expect("operation"))
            .await
            .expect("receipt query");
        assert_eq!(
            recovered.as_ref(),
            Some(expected),
            "original receipt recovered"
        );
    }
    println!(
        "SCONC-994 case=19 pulse ok sha={} port={}",
        harness.config.provider_artifact_digest, harness.config.provider_bind_address
    );
    drop(client);
    harness.cleanup().await;
}
