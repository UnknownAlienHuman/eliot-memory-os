//! Real, isolated Surreal provider proof for issue #10. Private raw queries
//! discriminate the codec; canonical writes and evidence reads use the adapter.
#![allow(clippy::expect_used, clippy::print_stdout, clippy::large_futures)]

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
};
use eliot_platform_windows::WindowsPlatform;
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, EffectClass, EventProjectionRelationIntents,
    ExactJsonBytes, NamedMutationOperation, NamedMutationRequest, NamedReadOperation,
    NamedReadRequest, OperationId, OperationIdentity, OrderingScopeId, PayloadSource,
    PreparedTransition, ReadConsistency, RequestMeta, RevisionKey, ScopeId, SecurityContext,
    StateFence, TransitionClass, WriteReceipt, WriteReceiptStatus, canonical_request_hash,
    generated_operation_manifests, operation_manifest_set_digest, sha256_hex,
};
use serde_json::Map;

use super::*;
use crate::{SchemaGeneration, SurrealStoreAdapter};

struct Harness {
    root: PathBuf,
    config: SurrealAdapterConfig,
    adapter: Option<SurrealStoreAdapter>,
}

impl Harness {
    async fn start() -> Self {
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("loopback")
            .local_addr()
            .expect("address")
            .port();
        let root = std::env::temp_dir().join(format!("eliot-issue10-{}", Uuid::new_v4()));
        let exe = root.join("bin/surreal.exe");
        let data = root.join("store/data");
        let work = root.join("store/work");
        let tmp = root.join("store/tmp");
        for dir in [root.join("bin"), data.clone(), work.clone(), tmp.clone()] {
            std::fs::create_dir_all(dir).expect("isolated directory");
        }
        let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
            || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
            PathBuf::from,
        );
        std::fs::copy(provider, &exe).expect("stage pinned provider");
        let digest = sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
        let bind = format!("127.0.0.1:{port}");
        let mut config = SurrealAdapterConfig {
            endpoint: format!("ws://{bind}/rpc"),
            namespace: "issue10".into(),
            database: "original".into(),
            username: "issue10-test".into(),
            password: SecretString::new(format!("test-{}", Uuid::new_v4()).into()),
            provider_bind_address: bind,
            installation_id: "issue10-test".into(),
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
            expected_provider_major: crate::PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        };
        config.provider_arguments = config.expected_provider_arguments();
        let mut harness = Self {
            root,
            config,
            adapter: None,
        };
        // Installation-style credential provisioning in this test's fresh root.
        // Secrets are passed in the child environment, never argv or logs.
        let mut command = Command::new(&exe);
        configure_provider_command(
            &mut command,
            &harness.config,
            &provider_environment(&harness.config).expect("environment"),
        );
        command
            .env("SURREAL_USER", &harness.config.username)
            .env("SURREAL_PASS", harness.config.password.expose_secret());
        let mut child = command.spawn().expect("bootstrap provider");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                child.try_wait().expect("child status").is_none(),
                "bootstrap exited"
            );
            if TcpStream::connect(&harness.config.provider_bind_address)
                .await
                .is_ok()
            {
                break;
            }
            assert!(Instant::now() < deadline, "bootstrap bind timeout");
            sleep(Duration::from_millis(50)).await;
        }
        child.kill().await.expect("stop bootstrap");
        child.wait().await.expect("reap bootstrap");
        harness.open().await;
        println!(
            "ISSUE-10 provider={} sha256={} root={}",
            exe.display(),
            harness.config.provider_artifact_digest,
            harness.root.display()
        );
        harness
    }

    async fn open(&mut self) {
        let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
        let lease = platform
            .retain_process_path_lease(
                Path::new(&self.config.provider_executable_path),
                Path::new(&self.config.store_work_root),
                &self.config.provider_artifact_digest,
            )
            .expect("process lease");
        self.adapter = Some(SurrealStoreAdapter::new(self.config.clone(), lease).expect("adapter"));
        self.adapter()
            .connect()
            .await
            .expect("authenticated provider");
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("live adapter")
    }

    async fn close(&mut self) {
        if let Some(adapter) = self.adapter.take() {
            let transport = adapter
                .client
                .get()
                .expect("connected")
                .as_ref()
                .expect("transport");
            let mut child = transport.provider_child.lock().await;
            child.kill().await.expect("stop provider");
            child.wait().await.expect("reap provider");
        }
    }

    async fn transfer(&self, action: &str, database: &str) {
        let mut command = Command::new(&self.config.provider_executable_path);
        let mut child = command
            .args([
                action,
                "--endpoint",
                &format!("http://{}", self.config.provider_bind_address),
                "--namespace",
                &self.config.namespace,
                "--database",
                database,
            ])
            .arg(self.root.join("payload.surql"))
            .current_dir(&self.root)
            .env_clear()
            .envs(
                provider_environment(&self.config)
                    .expect("environment")
                    .entries,
            )
            .env("SURREAL_USER", &self.config.username)
            .env("SURREAL_PASS", self.config.password.expose_secret())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("export/import child");
        assert!(
            timeout(Duration::from_secs(30), child.wait())
                .await
                .expect("transfer timeout")
                .expect("transfer exit")
                .success(),
            "{action} failed"
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.adapter = None;
        // Only this freshly allocated, uniquely named test root is removed.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn context() -> RequestMeta {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch");
    RequestMeta {
        request_id: RequestId::new("issue10-request").expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("issue10-product").expect("product"),
        source_id: SourceId::new("issue10-source").expect("source"),
        state_fence: StateFence::new(epoch, ResourceGeneration::genesis()),
        clock: ClockReading {
            valid_time_ms: Some(1000),
            known_time_ms: Some(1001),
            ..ClockReading::default()
        },
    }
}

fn matrix() -> Value {
    json!([
        "scope:scope", "observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240",
        "memory:operator-runtime-proof", "sha256:abc-def-0123456789",
        "collective:550e8400-e29b-41d4-a716-446655440000:message-with-suffix",
        "alpha-beta", "550e8400-e29b-41d4-a716-446655440000", "2026-09-15T00:00:00Z",
        "https://example.test/a-b?q=x:y", r"C:\test\path-with-hyphen", "", "雪🦀",
        "a\u{0000}b\n\r\t\u{0008}\u{000c}", "\"; THROW 'injected'; --", "[record:value]",
        {"id": "record:value", "nested": ["record:with-suffix", {"datetime": "2026-09-15T00:00:00Z"}]},
        null, true, false, -42, 1.25
    ])
}

fn transition(ctx: &RequestMeta, authority: &ExactJsonBytes) -> PreparedTransition {
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("issue10-write").expect("operation"),
            idempotency_key: "issue10-idempotency".into(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: ctx.state_fence.clone(),
        scope_id: ScopeId::new("scope").expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope").expect("ordering")],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "a".repeat(64),
        operation_manifest_digest: operation_manifest_set_digest(
            &generated_operation_manifests().expect("catalogue"),
        )
        .expect("manifest digest"),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: authority.decode_object_parameters().expect("parameters"),
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
        &CanonicalRequestView::from_apply(ctx, &transition, &[], &[]),
    )
    .expect("request hash");
    transition
}

async fn assert_readback(
    adapter: &SurrealStoreAdapter,
    ctx: &RequestMeta,
    authority: &ExactJsonBytes,
    receipt: &WriteReceipt,
) {
    assert_eq!(
        adapter
            .receipt(receipt.operation_id.clone())
            .await
            .expect("receipt"),
        Some(receipt.clone())
    );
    let key = RevisionKey::new("scope:scope").expect("revision key");
    let heads = adapter
        .revision_heads(vec![key.clone()])
        .await
        .expect("revision heads");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].key, key);
    let pack = adapter
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: None,
            consistency: ReadConsistency::ExactFence,
            state_fence: ctx.state_fence.clone(),
            parameters: BTreeMap::from([
                ("subject".into(), json!("memory:operator-runtime-proof")),
                ("max_records".into(), json!("8")),
            ]),
        })
        .await
        .expect("exact governed evidence read");
    assert_eq!(
        pack.payload["records"].as_array().expect("records").len(),
        1
    );
    assert_eq!(
        pack.payload["records"][0]["parameters"],
        authority.projection_value().expect("exact projection")
    );
    let transport = adapter
        .client
        .get()
        .expect("connected")
        .as_ref()
        .expect("transport");
    let mut direct = transport
        .query(
            "test.exact_receipt",
            "SELECT * FROM ONLY type::record($table, $key);",
            serde_json::Map::from_iter([
                ("table".into(), json!("write_receipt")),
                ("key".into(), json!(receipt.operation_id.to_string())),
            ]),
        )
        .await
        .expect("direct record read");
    assert!(direct.take_errors().is_empty());
    let row: Value = direct.take(0).expect("exact receipt row");
    assert_eq!(
        row["payload_authority"][0]["bytes_utf8"]
            .as_str()
            .expect("bytes")
            .as_bytes(),
        authority.as_json_str().expect("authority").as_bytes()
    );
    assert_eq!(
        row["payload_authority"][0]["digest_hex"],
        authority.digest_hex()
    );
    assert_eq!(
        row["evidence_records"][0]["parameters"],
        authority.projection_value().expect("parameters")
    );
}

#[tokio::test]
async fn real_surreal_payload_commit_exact_read_reopen_and_export() {
    let mut harness = Harness::start().await;
    let ctx = context();
    let transport = harness
        .adapter()
        .client
        .get()
        .expect("connected")
        .as_ref()
        .expect("transport");
    println!(
        "ISSUE-10 version={}",
        transport.version().await.expect("version")
    );
    // The old JSON-RPC route is the discriminator. Inspect type as well as
    // spelling: a record ID may print identically to the original string.
    let raw = transport
        .request(
            "test.old_codec",
            "query",
            json!([
                "RETURN type::is_string($value);", {"value": "scope:scope"}
            ]),
        )
        .await
        .expect("old codec observation");
    assert_eq!(raw[0]["result"], false);
    let values = matrix();
    for value in values.as_array().expect("matrix") {
        let mut response = transport
            .query(
                "test.codec",
                "RETURN $value; RETURN type::is_string($value);",
                Map::from_iter([("value".into(), value.clone())]),
            )
            .await
            .expect("codec query");
        assert!(response.take_errors().is_empty());
        assert_eq!(response.take::<Value>(0).expect("value"), *value);
        assert_eq!(response.take::<bool>(1).expect("type"), value.is_string());
    }
    let mut errors = transport
        .query(
            "test.statement_error",
            "THROW 'codec-error';",
            Map::from_iter([("value".into(), values.clone())]),
        )
        .await
        .expect("error envelope");
    assert_eq!(errors.take_errors().len(), 1);
    assert!(
        transport
            .query(
                "test.invalid_name",
                "RETURN true;",
                Map::from_iter([("x; THROW 'bad'".into(), Value::Null)])
            )
            .await
            .is_err()
    );

    harness
        .adapter()
        .apply_migration(
            &SurrealStoreAdapter::v2_baseline_migration(),
            &ctx.clock,
            &ctx.state_fence,
        )
        .await
        .expect("baseline schema");
    let raw = format!(
        " {{\n  \"subject\": \"memory:operator-runtime-proof\", \"payload\": {}\n }} ",
        values
    );
    let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw.as_bytes())
        .expect("exact authority");
    let transition = transition(&ctx, &authority);
    let receipt = harness
        .adapter()
        .apply_prepared_with_authority(
            &ctx,
            transition.clone(),
            Vec::new(),
            Vec::new(),
            &[Some(authority.clone())],
        )
        .await
        .expect("real canonical transaction");
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    assert_readback(harness.adapter(), &ctx, &authority, &receipt).await;
    assert_eq!(
        harness
            .adapter()
            .apply_prepared_with_authority(
                &ctx,
                transition,
                Vec::new(),
                Vec::new(),
                &[Some(authority.clone())]
            )
            .await
            .expect("exact replay"),
        receipt
    );
    harness.close().await;
    harness.open().await;
    assert_readback(harness.adapter(), &ctx, &authority, &receipt).await;
    harness.transfer("export", "original").await;
    harness.transfer("import", "restored").await;
    harness.close().await;
    harness.config.database = "restored".into();
    harness.open().await;
    assert_readback(harness.adapter(), &ctx, &authority, &receipt).await;
    harness.close().await;
    std::fs::remove_dir_all(&harness.root).expect("remove isolated test root");
}
