//! Real Surreal storage-edge proof for the closed four-owner owner-write
//! operation. Opaque canonical snapshot fixtures exercise the atomic prepared
//! write and recovery APIs; this does not claim the Governor's semantic
//! activation producer. The adapter owns the isolated provider process.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::large_futures, clippy::print_stdout, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId,
};
use eliot_platform::ClockObservation;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::EffectClass;
use eliot_store_api::{
    AgentActivationOwnerBundle, AgentActivationOwnerFrame, CanonicalRequestView,
    CanonicalStoreClient, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OrderingScopeId, PreparedTransition, RecoveryRecord,
    RecoveryRecordKey, RequestMeta, ScopeId, SecurityContext, StateFence, StoreError,
    StoreRecoveryRequest, StoreRecoverySnapshot, TransitionClass, WriteReceiptStatus,
    CONTRACT_VERSION, OWNER_SNAPSHOT_SCHEMA, bind_issue18_digests, canonical_json_bytes,
    canonical_request_hash, generated_operation_manifests, operation_manifest_set_digest, sha256_hex,
    supported_admission_contract_set_digest,
};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const TEST_USER: &str = "agent-owner-test";
const TEST_SECRET: &str = "agent-owner-test-secret";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const SCOPE: &str = "agent-activation-owner-1838";
const OWNER_KEYS: [&str; 4] = ["task", "session", "coordination", "work_scope"];
const LIVE_ROOT_ENV: &str = "ELIOT_CS3_LIVE_ROOT";
const LANE_SCRATCH_ROOT: &str = r"C:\Development\Rust\projects\eliot-swarm\control-20260923-impl\v2\workers\CS3\scratch\1838";

fn surreal_exe() -> PathBuf {
    std::env::var("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|_| PathBuf::from(TEST_SURREAL_EXE), PathBuf::from)
}

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new(LINEAGE).expect("lineage"),
        NonZeroU64::new(1).expect("epoch sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
}

fn context(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-agent-owner-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-agent-owner-test").expect("product"),
        source_id: SourceId::new("governor-owner-fixture").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn owner_frame(owner_key: &str, expected_revision: u64, fixture: &str) -> AgentActivationOwnerFrame {
    let next_revision = expected_revision + 1;
    let payload = canonical_json_bytes(&json!({
        "fixture": fixture,
        "owner": owner_key,
        "snapshot_revision": next_revision,
    }))
    .expect("canonical owner payload");
    AgentActivationOwnerFrame {
        expected_revision,
        record: RecoveryRecord {
            namespace: "owner".to_owned(),
            key: owner_key.to_owned(),
            state_fence: fence(),
            revision: next_revision,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        },
    }
}

fn supplier_snapshot_fixture(
    fixture: &str,
    expected_revisions: [u64; 4],
) -> AgentActivationOwnerBundle {
    AgentActivationOwnerBundle {
        task: owner_frame("task", expected_revisions[0], fixture),
        session: owner_frame("session", expected_revisions[1], fixture),
        coordination: owner_frame("coordination", expected_revisions[2], fixture),
        work_scope: owner_frame("work_scope", expected_revisions[3], fixture),
    }
}

fn sorted_records(owners: &AgentActivationOwnerBundle) -> Vec<RecoveryRecord> {
    let mut records = vec![
        owners.task.record.clone(),
        owners.session.record.clone(),
        owners.coordination.record.clone(),
        owners.work_scope.record.clone(),
    ];
    records.sort_by_key(RecoveryRecord::record_key);
    records
}

fn prepared_transition(
    tag: &str,
    owners: &AgentActivationOwnerBundle,
) -> (RequestMeta, PreparedTransition) {
    let ctx = context(tag);
    let catalogue = generated_operation_manifests().expect("generated catalogue");
    let mut transition = PreparedTransition {
        contract_version: CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("operation-agent-owner-{tag}"))
                .expect("operation"),
            idempotency_key: format!("idempotency-agent-owner-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(SCOPE).expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(SCOPE).expect("ordering scope")],
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: supported_admission_contract_set_digest()
            .expect("admission contract digest"),
        operation_manifest_digest: operation_manifest_set_digest(&catalogue)
            .expect("operation manifest digest"),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ApplyAgentActivationOwners,
            parameters: BTreeMap::from([(
                "owner_records".to_owned(),
                serde_json::to_value(owners).expect("owner bundle JSON"),
            )]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("prepared-transition digests");
    let request_view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&request_view).expect("canonical request hash");
    (ctx, transition)
}

fn owner_recovery_request() -> StoreRecoveryRequest {
    StoreRecoveryRequest {
        contract_version: CONTRACT_VERSION,
        state_fence: fence(),
        records: OWNER_KEYS
            .into_iter()
            .map(|key| RecoveryRecordKey::new("owner", key).expect("fixed owner key"))
            .collect(),
        include_receipts: true,
        include_jobs: false,
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
        database: "agent_activation_owner_1838".to_owned(),
        username: "agent-owner-test".to_owned(),
        password: SecretString::new("agent-owner-test-secret".into()),
        provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
        provider_bootstrap_password: SecretString::new("provider-bootstrap-fixture-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-agent-owner-test".to_owned(),
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
        .expect("loopback listener")
        .local_addr()
        .expect("loopback address")
        .port()
}

/// Prepares a fresh SurrealKV root user using the same isolated bootstrap
/// contour as the existing real-provider integration suites. The active
/// provider process is subsequently started and owned by the adapter.
/// The bootstrap provider is not the adapter-owned provider. This guard kills
/// and reaps it even when readiness assertions unwind.
struct BootstrapProcess(Child);

impl BootstrapProcess {
    fn stop_and_reap(&mut self) -> std::io::Result<()> {
        if self.0.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(kill_error) = self.0.kill() {
            if self.0.try_wait()?.is_none() {
                return Err(kill_error);
            }
        }
        let _ = self.0.wait()?;
        Ok(())
    }
}

impl Drop for BootstrapProcess {
    fn drop(&mut self) {
        let _ = self.stop_and_reap();
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(*chunk.get(1).unwrap_or(&0));
        let third = u32::from(*chunk.get(2).unwrap_or(&0));
        let block = (first << 16) | (second << 8) | third;
        encoded.push(char::from(ALPHABET[((block >> 18) & 0x3f) as usize]));
        encoded.push(char::from(ALPHABET[((block >> 12) & 0x3f) as usize]));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[((block >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[(block & 0x3f) as usize])
        } else {
            '='
        });
    }
    encoded
}

/// Surreal's HTTP SQL route authenticates the newly provisioned root user and
/// executes a read-only expression, which proves bootstrap completion without
/// a timing sleep.
fn bootstrap_authenticated_ready(bind: &str) -> bool {
    let Ok(address) = bind.to_socket_addrs().and_then(|mut addresses| {
        addresses
            .next()
            .ok_or_else(|| std::io::Error::other("provider bind did not resolve"))
    }) else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let credentials = base64(format!("{TEST_USER}:{TEST_SECRET}").as_bytes());
    let body = "RETURN true;";
    let request = format!(
        "POST /sql HTTP/1.1\r\nHost: {bind}\r\nAuthorization: Basic {credentials}\r\nSurreal-NS: eliot\r\nSurreal-DB: agent_activation_owner_1838\r\nAccept: application/json\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if std::io::Write::write_all(&mut stream, request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    if std::io::Read::read_to_end(&mut stream, &mut response).is_err() {
        return false;
    }
    response
        .split(|byte| *byte == b'\n')
        .next()
        .is_some_and(|status| status.starts_with(b"HTTP/1.1 200 ") || status.starts_with(b"HTTP/1.0 200 "))
}

fn prepare_initial_root_user(exe: &Path, bind: &str, data: &Path, work: &Path, tmp: &Path) {
    let password = SecretString::new(TEST_SECRET.into());
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let temp_directory = tmp.to_string_lossy().into_owned();
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            TEST_USER,
            "--password",
            password.expose_secret(),
            "--temporary-directory",
            temp_directory.as_str(),
            data_url.as_str(),
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
        .expect("isolated provider bootstrap");
    let mut child = BootstrapProcess(child);

    let deadline = Instant::now() + Duration::from_secs(60);
    while !bootstrap_authenticated_ready(bind) {
        assert!(
            child.0.try_wait().expect("bootstrap provider status").is_none(),
            "bootstrap provider exited before authenticated readiness on {bind}"
        );
        assert!(Instant::now() < deadline, "bootstrap provider never became ready at {bind}");
        std::thread::sleep(Duration::from_millis(100));
    }
    child.stop_and_reap().expect("stop and reap bootstrap provider");

    let deadline = Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(bind).is_ok() {
        assert!(
            Instant::now() < deadline,
            "bootstrap provider never released {bind}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(child.0.try_wait().expect("bootstrap provider exit status").is_some());
}

fn observation() -> ClockObservation {
    ClockObservation {
        valid_time_ms: Some(1_000),
        known_time_ms: Some(1_001),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

struct OwnedTestRoot {
    root: PathBuf,
    parent: PathBuf,
}

impl OwnedTestRoot {
    fn create(test: &str, port: u16) -> Self {
        let configured = std::env::var_os(LIVE_ROOT_ENV)
            .unwrap_or_else(|| panic!("{LIVE_ROOT_ENV} must point to lane scratch"));
        let configured = PathBuf::from(configured);
        assert!(configured.is_absolute(), "{LIVE_ROOT_ENV} must be absolute");
        let parent = configured
            .canonicalize()
            .unwrap_or_else(|error| panic!("{LIVE_ROOT_ENV} must be an existing lane scratch directory: {error}"));
        assert!(parent.is_dir(), "{LIVE_ROOT_ENV} must be a directory");
        let expected_parent = Path::new(LANE_SCRATCH_ROOT)
            .canonicalize()
            .expect("the CS3 1838 lane scratch directory exists");
        assert!(
            parent == expected_parent,
            "{LIVE_ROOT_ENV} must resolve to the CS3 1838 lane scratch root {}; got {}",
            expected_parent.display(),
            parent.display()
        );

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        for attempt in 0..16_u8 {
            let path = parent.join(format!(
                "agent-owner-1838-{}-{port}-{nonce}-{attempt}-{test}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    let root = path.canonicalize().expect("canonicalize exclusively-created test root");
                    assert_eq!(root.parent(), Some(parent.as_path()), "owned test root stays in configured lane scratch");
                    return Self { root, parent };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create exclusively-owned test root: {error}"),
            }
        }
        panic!("could not exclusively allocate an unused Surreal test root under {}", parent.display());
    }
}

impl Drop for OwnedTestRoot {
    fn drop(&mut self) {
        if !self.root.exists() {
            return;
        }
        let Ok(resolved) = self.root.canonicalize() else {
            return;
        };
        if resolved.parent() == Some(self.parent.as_path()) {
            let _ = std::fs::remove_dir_all(resolved);
        }
    }
}

struct Harness {
    owned_root: OwnedTestRoot,
    adapter: Option<SurrealStoreAdapter>,
}

impl Harness {
    async fn fresh(test: &str) -> Self {
        let port = free_port();
        let owned_root = OwnedTestRoot::create(test, port);
        let root = owned_root.root.clone();
        let bin = root.join("bin");
        let data = root.join("store").join("data");
        let work = root.join("store").join("work");
        let tmp = root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("isolated test directory");
        }

        let source_exe = surreal_exe();
        assert!(
            source_exe.is_file(),
            "pinned test provider is absent: {}",
            source_exe.display()
        );
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage installed provider");
        let digest = sha256_hex(&std::fs::read(&exe).expect("read provider bytes"));
        println!(
            "agent-owner provider: exe={} sha256={} port={} root={}",
            exe.display(),
            digest,
            port,
            root.display()
        );

        let platform = WindowsPlatform::new(root.clone()).expect("Windows platform");
        let bind = format!("127.0.0.1:{port}");
        prepare_initial_root_user(&exe, &bind, &data, &work, &tmp);
        let lease = platform
            .retain_process_path_lease(&exe, &work, &digest)
            .expect("provider process-path lease");
        let config = adapter_config(&exe, digest, bind, &data, &work, &tmp);
        let adapter = SurrealStoreAdapter::new(config, lease).expect("adapter");
        adapter.connect().await.expect("adapter-owned provider connect");
        let migration = SurrealStoreAdapter::v2_baseline_migration();
        adapter
            .apply_migration(&migration, &observation(), &fence())
            .await
            .expect("baseline schema migration");
        Self {
            owned_root,
            adapter: Some(adapter),
        }
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("adapter live")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Drop the adapter and its process lease before the owned data root.
        self.adapter = None;
    }
}

async fn recovery_snapshot(adapter: &SurrealStoreAdapter) -> StoreRecoverySnapshot {
    CanonicalStoreClient::recovery(adapter, owner_recovery_request())
        .await
        .expect("same-fence owner and receipt readback")
}

#[tokio::test]
async fn four_owner_records_and_receipt_commit_together_and_stale_final_cas_rolls_back() {
    let harness = Harness::fresh("owner-cas").await;
    let owners = supplier_snapshot_fixture("initial-owner-image", [0, 0, 0, 0]);
    let expected_records = sorted_records(&owners);
    let (ctx, transition) = prepared_transition("initial", &owners);
    let receipt = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition.clone(),
        Vec::new(),
        Vec::new(),
    )
    .await
    .expect("four owner rows commit through the canonical write path");

    receipt.validate().expect("canonical receipt validates");
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    assert_eq!(receipt.operation_id, transition.identity.operation_id);
    assert_eq!(receipt.idempotency_key, transition.identity.idempotency_key);
    assert_eq!(
        receipt.canonical_request_hash,
        transition.identity.canonical_request_hash
    );
    assert_eq!(receipt.operation_manifest_digest, transition.operation_manifest_digest);
    assert_eq!(receipt.admission_digest, transition.admission_digest);
    assert_eq!(receipt.mutation_plan_digest, transition.mutation_plan_digest);

    let before = recovery_snapshot(harness.adapter()).await;
    assert_eq!(before.owner_records, expected_records);
    assert!(before.receipts.contains(&receipt));
    assert_eq!(
        CanonicalStoreClient::receipt(harness.adapter(), receipt.operation_id.clone())
            .await
            .expect("resolve original receipt"),
        Some(receipt.clone())
    );

    // The first three owner heads are current. The final WorkScope frame is
    // internally valid but carries stale expected_revision=0, so its provider
    // CAS must roll back the preceding owner updates and canonical receipt.
    let stale = supplier_snapshot_fixture("stale-final-work-scope", [1, 1, 1, 0]);
    stale
        .validate_for_fence(&fence())
        .expect("stale predecessor remains a well-formed supplied CAS");
    let (stale_ctx, stale_transition) = prepared_transition("stale-final", &stale);
    assert_ne!(stale_transition.identity.operation_id, receipt.operation_id);
    let stale_operation_id = stale_transition.identity.operation_id.clone();
    let refusal = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &stale_ctx,
        stale_transition,
        Vec::new(),
        Vec::new(),
    )
    .await;
    assert_eq!(refusal, Err(StoreError::RevisionConflict));

    let after = recovery_snapshot(harness.adapter()).await;
    assert_eq!(after.owner_records, expected_records, "no owner row partially advanced");
    assert_eq!(after.receipts, before.receipts, "the refused transition has no receipt");
    assert_eq!(
        CanonicalStoreClient::receipt(harness.adapter(), stale_operation_id)
            .await
            .expect("resolve refused identity"),
        None
    );
    assert_eq!(
        CanonicalStoreClient::receipt(harness.adapter(), receipt.operation_id.clone())
            .await
            .expect("original committed receipt remains resolvable"),
        Some(receipt)
    );
}
