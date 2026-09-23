//! Canonical notification-state provider proofs (issue #1780).
//!
//! Proves the closed `ApplyNotificationState` / `GetNotificationState`
//! operations through the public [`CanonicalStoreClient`] API against an
//! isolated `surreal.exe` provider (loopback bind, per-test temporary
//! `SurrealKV` roots, redacted test credentials): atomic record+outbox
//! persistence, dedup coalescing, delivery/ack visibility, receipt-bound
//! resolution with forged-authority rejection, exact-identity
//! reconciliation, same-fence read projection, and readback after a provider
//! restart. No in-memory stand-in, no production database, no user
//! credentials.
//!
//! Provider evidence (recorded on failure output and in the work item): the
//! pinned `surreal.exe` path plus its SHA-256, the server version handshake
//! enforced by the adapter, the per-test loopback port, and the temporary
//! data/work/tmp roots.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::large_futures, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, OperationId, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TransactionSequence,
};
use eliot_kernel_core::ResolutionAuthorization;
use eliot_platform::ClockObservation;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling,
    ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};
use eliot_store_api::{
    CanonicalRequestView, NamedMutationOperation, NamedMutationRequest, OperationIdentity,
    OrderingScopeId, PreparedTransition, RequestMeta, ScopeId, SecurityContext, StoreError,
    TransitionClass, canonical_request_hash, generated_operation_manifests,
    operation_manifest_set_digest,
};
use eliot_store_api::{EventProjectionRelationIntents, NOTIFY_PARAM_AUTHORIZATION_JSON};
use eliot_store_api::{
    NOTIFY_MUTATION_ACKNOWLEDGE, NOTIFY_MUTATION_DELIVERY, NOTIFY_MUTATION_RESOLVE,
    NOTIFY_MUTATION_UPSERT, NOTIFY_PARAM_CHANNEL, NOTIFY_PARAM_DEDUP_KEY,
    NOTIFY_PARAM_DELIVERY_JSON, NOTIFY_PARAM_DISPOSITION, NOTIFY_PARAM_MUTATION,
    NOTIFY_PARAM_NOTIFICATION_ID, NOTIFY_PARAM_PRINCIPAL, NOTIFY_PARAM_RECORD_JSON,
    NOTIFY_PARAM_SOURCE_RECEIPT_JSON,
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
        request_id: RequestId::new(format!("request-notify-live-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-notify").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn draft_value(key: &str, severity: &str) -> Value {
    json!({
        "notification_id": format!("notification-{key}"),
        "severity": severity,
        "subject": "subject",
        "summary": "summary",
        "evidence_handles": ["evidence-1"],
        "affected_scope": "scope-1",
        "owner": "owner-1",
        "required_action": "review",
        "deadline_or_review": null,
        "dedup_key": key,
        "delivery_channels": ["CONTROL_BOARD", "NATIVE_TOAST"],
        "state_fence": serde_json::to_value(fence()).expect("fence json"),
    })
}

fn source_receipt_for(owner: &str) -> ReceiptEnvelope {
    let fence = fence();
    let request_id = RequestId::new("resolve-request").expect("request id");
    let metadata = RequestMeta {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-notify").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence.clone(),
        clock: ClockReading::default(),
    };
    ReceiptEnvelope::issue(ReceiptCore {
        contract: contract_identity().expect("contract"),
        kind: ReceiptKind::Verification,
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence.clone(),
        },
        task: None,
        session: None,
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata,
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: OperationId::new("resolve-operation").expect("operation"),
            request_id,
            idempotency_key: "resolve-idempotency".to_owned(),
            operation_kind: "notification.resolve".to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-owner-1").expect("authority"),
            authority_owner: owner.to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ReversibleMutation,
            proof_ceiling: ProofCeiling::ScopedVerification,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: ArtifactId::new("evidence-1").expect("artifact"),
            sha256: eliot_contracts::sha256_hex(b"evidence-1"),
            role: ReceiptKind::Artifact,
            source_revision: Some("test".to_owned()),
        }],
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::ScopedVerification,
        },
    })
    .expect("receipt")
}

fn upsert_params(key: &str, severity: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_UPSERT.to_owned()),
        ),
        (
            NOTIFY_PARAM_DEDUP_KEY.to_owned(),
            Value::String(key.to_owned()),
        ),
        (
            NOTIFY_PARAM_RECORD_JSON.to_owned(),
            draft_value(key, severity),
        ),
        (
            NOTIFY_PARAM_SOURCE_RECEIPT_JSON.to_owned(),
            serde_json::to_value(source_receipt_for("owner-1")).expect("receipt json"),
        ),
    ])
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
            operation_id: OperationId::new(format!("op-notify-live-{tag}")).expect("operation"),
            idempotency_key: format!("idem-notify-live-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("notification-state").expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("notification-state").expect("ordering")],
        transition_class: TransitionClass::NotificationState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: "c".repeat(64),
        operation_manifest_digest: manifest_digest,
        // Issue-#18 digests are derived below via `bind_issue18_digests`,
        // never defaulted; no semantic source is bound here (`[]`).
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![NamedMutationRequest {
            operation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
    let view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
    (ctx, transition)
}

struct Harness {
    root: PathBuf,
    port: u16,
    adapter: Option<SurrealStoreAdapter>,
}

impl Harness {
    async fn provision(root: PathBuf, port: u16) -> Self {
        let bin = root.join("bin");
        let data = root.join("store").join("data");
        let work = root.join("store").join("work");
        let tmp = root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("test dirs");
        }
        let source_exe = surreal_exe();
        assert!(
            source_exe.is_file(),
            "pinned test provider is absent: {}",
            source_exe.display()
        );
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage provider");
        let bytes = std::fs::read(&exe).expect("read staged provider");
        let digest = eliot_store_api::sha256_hex(&bytes);
        println!(
            "notification provider: exe={} sha256={} port={} root={}",
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
            port,
            adapter: Some(adapter),
        }
    }

    async fn fresh(test: &str) -> Self {
        let port = free_port();
        let root = std::env::temp_dir().join(format!(
            "eliot-notify-1780-{}-{port}-{test}",
            std::process::id()
        ));
        Self::provision(root, port).await
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("adapter live")
    }

    /// Drops the live adapter (killing its provider child and releasing the
    /// data-root claim) so a reopen can be proven over the same files.
    fn shutdown(&mut self) {
        self.adapter = None;
    }

    /// Reopens the same `SurrealKV` files with a fresh adapter + provider.
    async fn reopen(&mut self) {
        self.shutdown();
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let bin = self.root.join("bin");
            let data = self.root.join("store").join("data");
            let work = self.root.join("store").join("work");
            let tmp = self.root.join("store").join("tmp");
            let exe = bin.join("surreal.exe");
            match (|| -> Result<SurrealStoreAdapter, String> {
                let bytes =
                    std::fs::read(&exe).map_err(|error| format!("read provider: {error}"))?;
                let digest = eliot_store_api::sha256_hex(&bytes);
                let platform = WindowsPlatform::new(self.root.clone())
                    .map_err(|error| format!("{error:?}"))?;
                let lease = platform
                    .retain_process_path_lease(&exe, &work, &digest)
                    .map_err(|error| format!("{error:?}"))?;
                let bind = format!("127.0.0.1:{}", self.port);
                let config = adapter_config(&exe, digest, bind, &data, &work, &tmp);
                SurrealStoreAdapter::new(config, lease).map_err(|error| format!("{error:?}"))
            })() {
                Ok(adapter) => match adapter.connect().await {
                    Ok(()) => {
                        self.adapter = Some(adapter);
                        return;
                    }
                    Err(error) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "reopen connect failed: {error:?}"
                        );
                    }
                },
                Err(error) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "reopen provision failed: {error}"
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.adapter = None;
        if std::env::var("ELIOT_TEST_KEEP_NOTIFY_ROOT").is_ok() {
            println!("keeping notification test root: {}", self.root.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
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
        database: "notification_1780".to_owned(),
        username: "notify-test".to_owned(),
        password: SecretString::new("notify-test-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-test-1780".to_owned(),
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
    let password = SecretString::new("notify-test-secret".into());
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            "notify-test",
            "--password",
            password.expose_secret(),
            "--temporary-directory",
            &tmp.to_string_lossy(),
            "--log-file-enabled",
            "--log-file-path",
            &work.to_string_lossy(),
            "--log-file-name",
            "surrealdb.log",
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

async fn apply(
    harness: &Harness,
    tag: &str,
    operation: NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
) -> Result<eliot_store_api::WriteReceipt, StoreError> {
    let (ctx, transition) = transition_with(tag, operation, parameters);
    eliot_store_api::CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
}

async fn read_payload(harness: &Harness, scope: Option<String>, include_resolved: bool) -> Value {
    let query = eliot_store_api::notification_read_request(
        scope,
        None,
        None,
        include_resolved,
        10,
        None,
        fence(),
    )
    .expect("read builds");
    let response = eliot_store_api::CanonicalStoreClient::execute_named(harness.adapter(), query)
        .await
        .expect("read executes");
    response.payload
}

#[tokio::test]
async fn upsert_persists_and_reads_back_with_atomic_outbox() {
    let harness = Harness::fresh("upsert").await;
    let receipt = apply(
        &harness,
        "live-upsert-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .await
    .expect("upsert commits");
    assert_eq!(
        receipt.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
    assert_eq!(
        receipt.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
    assert!(!receipt.outbox_refs.is_empty());
    let payload = read_payload(&harness, None, true).await;
    let records = payload.get("records").expect("records");
    assert_eq!(records.as_array().expect("array").len(), 1);
    assert_eq!(
        records[0].get("occurrences"),
        Some(&json!(1)),
        "first upsert records one occurrence"
    );
    assert_eq!(
        payload
            .get("metrics")
            .expect("metrics")
            .get("unresolved_total"),
        Some(&json!(1))
    );
}

#[tokio::test]
async fn repeat_dedup_coalesces_and_changed_identity_conflicts() {
    let harness = Harness::fresh("dedup").await;
    apply(
        &harness,
        "live-dedup-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .await
    .expect("first upsert");
    let second = apply(
        &harness,
        "live-dedup-2",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .await
    .expect("repeat upsert");
    assert!(second.commit_id.is_some());
    let payload = read_payload(&harness, None, true).await;
    let records = payload.get("records").expect("records");
    assert_eq!(records.as_array().expect("array").len(), 1);
    assert_eq!(records[0].get("occurrences"), Some(&json!(2)));

    let mut divergent = upsert_params("disk-full", "WARNING");
    if let Some(Value::Object(record)) = divergent.get_mut(NOTIFY_PARAM_RECORD_JSON) {
        record.insert("subject".to_owned(), Value::String("changed".to_owned()));
    }
    assert_eq!(
        apply(
            &harness,
            "live-dedup-1",
            NamedMutationOperation::ApplyNotificationState,
            divergent
        )
        .await,
        Err(StoreError::IdentityConflict)
    );
}

#[tokio::test]
async fn delivery_ack_and_bound_resolve_lifecycle() {
    let harness = Harness::fresh("lifecycle").await;
    apply(
        &harness,
        "live-life-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("backup-failed", "CRITICAL"),
    )
    .await
    .expect("upsert");
    let delivery = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_DELIVERY.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-backup-failed".to_owned()),
        ),
        (
            NOTIFY_PARAM_CHANNEL.to_owned(),
            Value::String("NATIVE_TOAST".to_owned()),
        ),
        (
            NOTIFY_PARAM_DELIVERY_JSON.to_owned(),
            json!({"kind": "FAILED", "reason": "toast provider failed"}),
        ),
    ]);
    apply(
        &harness,
        "live-life-2",
        NamedMutationOperation::ApplyNotificationState,
        delivery,
    )
    .await
    .expect("delivery records");
    let ack = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_ACKNOWLEDGE.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-backup-failed".to_owned()),
        ),
        (
            NOTIFY_PARAM_PRINCIPAL.to_owned(),
            Value::String("operator-1".to_owned()),
        ),
    ]);
    apply(
        &harness,
        "live-life-3",
        NamedMutationOperation::ApplyNotificationState,
        ack,
    )
    .await
    .expect("ack records");
    let payload = read_payload(&harness, None, true).await;
    let metrics = payload.get("metrics").expect("metrics");
    assert_eq!(metrics.get("failed_delivery_unresolved"), Some(&json!(1)));
    assert_eq!(metrics.get("acknowledged_unresolved"), Some(&json!(1)));
    assert_eq!(metrics.get("critical_unresolved"), Some(&json!(1)));

    let authorization = ResolutionAuthorization {
        receipt: source_receipt_for("owner-1"),
        evidence_handles: vec!["evidence-1".to_owned()],
    };
    let resolve = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_RESOLVE.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-backup-failed".to_owned()),
        ),
        (
            NOTIFY_PARAM_DISPOSITION.to_owned(),
            Value::String("rotated and verified".to_owned()),
        ),
        (
            NOTIFY_PARAM_AUTHORIZATION_JSON.to_owned(),
            serde_json::to_value(&authorization).expect("auth json"),
        ),
    ]);
    apply(
        &harness,
        "live-life-4",
        NamedMutationOperation::ApplyNotificationState,
        resolve,
    )
    .await
    .expect("bound resolution commits");
    let closed = read_payload(&harness, None, true).await;
    assert_eq!(
        closed
            .get("metrics")
            .expect("metrics")
            .get("resolved_total"),
        Some(&json!(1))
    );
}

#[tokio::test]
async fn forged_authority_is_rejected() {
    use eliot_kernel_core::ResolutionAuthorization as ModelAuthorization;

    let harness = Harness::fresh("forged").await;
    apply(
        &harness,
        "live-forged-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("kernel-fence", "CRITICAL"),
    )
    .await
    .expect("upsert");
    let authorization = ModelAuthorization {
        receipt: source_receipt_for("intruder"),
        evidence_handles: vec!["evidence-1".to_owned()],
    };
    let resolve = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_RESOLVE.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-kernel-fence".to_owned()),
        ),
        (
            NOTIFY_PARAM_DISPOSITION.to_owned(),
            Value::String("fixed".to_owned()),
        ),
        (
            NOTIFY_PARAM_AUTHORIZATION_JSON.to_owned(),
            serde_json::to_value(authorization).expect("auth json"),
        ),
    ]);
    assert_eq!(
        apply(
            &harness,
            "live-forged-2",
            NamedMutationOperation::ApplyNotificationState,
            resolve
        )
        .await,
        Err(StoreError::EffectCeilingExceeded)
    );
}

#[tokio::test]
async fn restart_readback_sees_unresolved_critical() {
    let mut harness = Harness::fresh("restart").await;
    apply(
        &harness,
        "live-restart-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-critical", "CRITICAL"),
    )
    .await
    .expect("upsert commits");
    harness.reopen().await;
    let payload = read_payload(&harness, None, true).await;
    let records = payload.get("records").expect("records");
    assert_eq!(records.as_array().expect("array").len(), 1);
    assert_eq!(
        records[0].get("dedup_key"),
        Some(&Value::String("disk-critical".to_owned()))
    );
    assert_eq!(
        payload
            .get("metrics")
            .expect("metrics")
            .get("critical_unresolved"),
        Some(&json!(1))
    );
}
