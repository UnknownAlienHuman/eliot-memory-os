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
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use eliot_contracts::{
    AuthorityEpoch, ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_ipc::{NamedPipeServer, NamedPipeTransport, PeerIdentity, TransportLimits};
use eliot_kernel_core::{GenerationRoute, RouteScope};
use eliot_kernel_service::{
    CompositionReservation, EbpCanonicalStoreClient, HostFileIdentity, HostJobBinding,
    HostJobIdentity, HostJobRoot, HostKernelCandidateBinding, HostProcessBinding,
    HostStoreBootstrapRequirement, KernelActivationPermit, KernelControlCommand,
    KernelReadyReceipt, KernelService, KernelServiceState, KernelStoreGateway, ObservedHead,
    ProcessObservation, RESERVATION_KEY_NAME, RESERVATION_KEY_PROVIDER, RESERVATION_VISIBILITY,
    ReservationSeed, RestartBudget, StoreClientFault, StoreClientFaultHarness,
};
use eliot_ors::test_support::KernelRouteStoreFixture;
use eliot_platform::{KernelActivationNonce, PlatformHandle};
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::{FrameKind, ProtocolVersion, ServerHello};
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};
use eliot_store_api::{
    CONTRACT_VERSION, CanonicalRequestView, CanonicalStoreClient, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationId as ApiOperationId, OperationIdentity, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, RevisionHeadExpectation, RevisionKey, ScopeId,
    SecurityContext, StoreRecoveryRequest, TransitionClass, WriteReceipt, WriteReceiptStatus,
    canonical_request_hash, generated_operation_manifests, operation_manifest_set_digest,
    validate_store_receipt_envelope,
};
use eliot_store_memory::MemoryStore;
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, PoolAdmission, PoolOccupancy, SchemaGeneration, SessionRole,
    SurrealAdapterConfig, SurrealStoreAdapter, join_cleanup_result,
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
        // Issue-#18 digests are derived below via `bind_issue18_digests`,
        // never defaulted; no semantic source is bound here (`[]`).
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
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
    eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
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

    /// Fallible root cleanup for 994/18 follow-up binding (issue #2030):
    /// same removal loop as [`Self::cleanup`], but returns the failure
    /// instead of panicking so the caller can join it with the primary
    /// outcome through `join_cleanup_result` and retain both errors.
    async fn cleanup_result(mut self) -> Result<(), String> {
        self.adapter = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::fs::remove_dir_all(&self.root).is_err() {
            if Instant::now() >= deadline {
                return Err(format!("case {} root cleanup failed", self.case));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
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

/// Head digest per scope for ORS seed observations. The fixture evidence
/// checks shape only (64 lowercase hex); the adapter matches by sequence,
/// so these labels stay fixed while sequences come from live history.
fn head_digest(scope: &str) -> String {
    let byte = match scope {
        "scope-994-a" | "scope-994-pulse-a" => b'a',
        "scope-994-pulse-b" => b'b',
        _ => b'c',
    };
    std::iter::repeat_n(byte as char, 64).collect()
}

/// Reserved-write inputs for the canonical Kernel route: the shared
/// `admitted` transition re-sourced to the active daemon caller (the
/// gateway admits only `eliotd`) and re-sealed over the exact expected
/// heads, plus the ORS reservation seed covering the same scopes.
/// Fresh scopes declare sequence 1 / revision 1, the only values a fresh
/// store accepts (`check_expected_orderings`, `check_expected_revisions`).
fn reserved_inputs(
    operation: &str,
    scope: &str,
    subject: &str,
    expected_sequence: u64,
) -> (
    RequestMeta,
    PreparedTransition,
    Vec<RevisionHeadExpectation>,
    Vec<OrderingHeadExpectation>,
    ReservationSeed,
) {
    let (mut ctx, mut transition) = admitted(operation, scope, subject);
    ctx.source_id = SourceId::new("eliotd").expect("daemon caller");
    let revision = vec![RevisionHeadExpectation {
        key: RevisionKey::new(format!("rev-994-{operation}")).expect("revision key"),
        expected_revision: 1,
        state_fence: fence(),
    }];
    let ordering = vec![OrderingHeadExpectation {
        scope: OrderingScopeId::new(scope).expect("ordering scope"),
        expected_sequence,
        state_fence: fence(),
    }];
    transition.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(&ctx, &transition, &revision, &ordering),
    )
    .expect("request hash");
    let now_ms = i64::try_from(unix_ms_now()).expect("wall clock fits");
    let seed = ReservationSeed {
        reservation_id: format!("reservation-994-{operation}"),
        operation_id: operation.to_owned(),
        recovery_owner: "recovery-owner-994".to_owned(),
        payload_bytes: format!("payload-994-{operation}").into_bytes(),
        key_provider: RESERVATION_KEY_PROVIDER.to_owned(),
        key_name: RESERVATION_KEY_NAME.to_owned(),
        visibility: RESERVATION_VISIBILITY.to_owned(),
        created_at_ms: now_ms,
        known_at_ms: now_ms,
        expires_at_ms: now_ms + 600_000,
        heads: vec![ObservedHead {
            scope: scope.to_owned(),
            expected_sequence,
            expected_head_digest: head_digest(scope),
            revision_head: None,
        }],
    };
    (ctx, transition, revision, ordering, seed)
}

fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:994".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-994".to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: "host-lineage-994".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-994".to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-994".to_owned(),
            sequence: 1,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-994".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-994".to_owned(),
            sequence: 1,
        },
        observation_scope: SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("valid test incarnation")
}

fn candidate_binding() -> HostKernelCandidateBinding {
    HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-994").expect("installation"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: epoch(1),
        activation_id: PlatformHandle::new("activation-994").expect("activation"),
        artifact_hash: PlatformHandle::new("artifact-994").expect("artifact"),
        config_hash: PlatformHandle::new("config-994").expect("config"),
        job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-994").expect("job"),
        pipe_identity: PlatformHandle::new("\\\\.\\pipe\\eliot-kernel-994").expect("pipe"),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-994".to_owned(),
            },
            root: HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: "C:\\eliot\\kernel.exe".to_owned(),
                },
                executable: HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_incarnation(),
        restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

/// Drives a real `KernelService` to `Ready` so the gateway binds live
/// authority. The widened front-door capacities mirror the 994 lanes
/// profile: independent scopes need parallel bounded send windows.
fn ready_service() -> KernelService {
    let mut service = KernelService::new([9; 32], 8, 16).expect("kernel service");
    let candidate = candidate_binding();
    let permit = KernelActivationPermit {
        operation_id: PlatformHandle::new("activation-operation-994").expect("operation"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: PlatformHandle::new("journal-transaction-994").expect("journal"),
        journal_sequence: 7,
        generation: ResourceGeneration::genesis(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: KernelActivationNonce::new(
            PlatformHandle::new(&"a".repeat(64)).expect("nonce handle"),
        )
        .expect("activation nonce"),
    };
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("handoff");
    let activation = service
        .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
        .expect("activation");
    let ready = KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10").expect("process"),
            job_object_id: candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("process-evidence-994").expect("evidence")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![PlatformHandle::new("ready-994").expect("evidence")],
    };
    service.publish_ready(ready).expect("ready");
    assert_eq!(service.state(), KernelServiceState::Ready);
    service
}

struct KernelRoute {
    gateway: Arc<KernelStoreGateway>,
    fixture: KernelRouteStoreFixture,
    reserved_sends: Arc<AtomicUsize>,
    server_task: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

/// Frame pump from the real named-pipe EBP connection into the live
/// Surreal adapter. Control/readiness follow the production handshake;
/// `ReservedWrite` executes against the installed concurrent generation
/// (the only path the adapter admits for reserved writes); `Receipt`
/// reconciles by identity. `Apply` panics: the canonical route under test
/// never falls back to unreserved writes.
async fn serve_store_route(
    mut server: NamedPipeServer,
    connection_id: String,
    artifact_hash: String,
    config_hash: String,
    adapter: Arc<SurrealStoreAdapter>,
    reserved_sends: Arc<AtomicUsize>,
) {
    let limits = TransportLimits::default();
    let frame = server
        .receive_frame(limits)
        .await
        .expect("994 route hello arrives");
    assert_eq!(
        frame.kind,
        FrameKind::Control,
        "994 route expects EBP hello"
    );
    let hello = ServerHello {
        selected_protocol: ProtocolVersion::CURRENT,
        session_principal_binding: "sconc994-route-store-session".to_owned(),
        allowed_capabilities: eliot_store_api::CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        allowed_effects: eliot_store_api::EFFECTS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        config_snapshot: json!({
            "config_hash": config_hash,
            "artifact_hash": artifact_hash,
        }),
        heartbeat_ms: 1_000,
        control_channel: "sconc994-route-control".to_owned(),
        rejection_reason: None,
        authority_epoch: epoch(1),
    };
    server
        .send_frame(
            &eliot_ipc::server_hello_frame(&connection_id, &hello)
                .expect("994 route hello encodes"),
            limits,
        )
        .await
        .expect("994 route hello sends");
    let frame = server
        .receive_frame(limits)
        .await
        .expect("994 route readiness arrives");
    let (request_id, _, store_request) =
        eliot_store_api::decode_request_frame(&frame).expect("994 route readiness decodes");
    assert!(
        matches!(store_request, eliot_store_api::StoreRequest::Readiness),
        "994 route expects readiness"
    );
    server
        .send_frame(
            &eliot_store_api::response_frame(
                connection_id.clone(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                eliot_store_api::StoreResponse::Readiness {
                    receipt: eliot_store_api::ReadinessReceipt::ready(
                        "kernel-route-994".to_owned(),
                    ),
                },
            )
            .expect("994 route readiness encodes"),
            limits,
        )
        .await
        .expect("994 route readiness sends");
    loop {
        let next =
            tokio::time::timeout(Duration::from_secs(30), server.receive_frame(limits)).await;
        let Ok(Ok(frame)) = next else {
            break;
        };
        let Ok((request_id, _, store_request)) = eliot_store_api::decode_request_frame(&frame)
        else {
            break;
        };
        let answer = match store_request {
            eliot_store_api::StoreRequest::ReservedWrite { request } => {
                reserved_sends.fetch_add(1, Ordering::SeqCst);
                match CanonicalStoreClient::apply_reserved_write(adapter.as_ref(), request).await {
                    Ok(receipt) => eliot_store_api::StoreResponse::Transaction { receipt },
                    Err(error) => panic!("994 route reserved execution failed: {error:?}"),
                }
            }
            eliot_store_api::StoreRequest::Receipt { operation_id } => {
                let receipt = adapter
                    .reconcile(operation_id)
                    .await
                    .unwrap_or_else(|error| panic!("994 route reconcile failed: {error:?}"));
                eliot_store_api::StoreResponse::Receipt { receipt }
            }
            eliot_store_api::StoreRequest::Apply { .. } => {
                panic!("994 route must never fall back to unreserved Apply");
            }
            _ => panic!("994 route received an unexpected request kind"),
        };
        let Ok(frame) = eliot_store_api::response_frame(
            connection_id.clone(),
            ProtocolVersion::CURRENT,
            Some(request_id),
            answer,
        ) else {
            break;
        };
        if server.send_frame(&frame, limits).await.is_err() {
            break;
        }
    }
}

/// Composes the real Kernel to ORS to Store route for one case: a `Ready`
/// KernelService, a real named-pipe EBP connection pumping frames into the
/// live Surreal adapter, and the `KernelRouteStoreFixture` ORS bound into
/// the gateway — the constructible runtime + gateway handle #2031 vended.
async fn kernel_route(case: &str, adapter: Arc<SurrealStoreAdapter>) -> KernelRoute {
    let nanos = unix_ms_now();
    let serial = HARNESS_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("eliot-994-kr-{case}-{serial}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("994 route temp root");
    let pipe = format!(r"\\.\pipe\eliot\store-994-kr-{case}-{serial}-{nanos}");
    let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
        .expect("994 route loopback expectation");
    let server = NamedPipeServer::create(&pipe, &expectation).expect("994 route server");
    let client_pipe = pipe.clone();
    let client_expectation = expectation.clone();
    let client_task = tokio::spawn(async move {
        NamedPipeTransport::connect_authenticated(
            &client_pipe,
            Duration::from_secs(10),
            &client_expectation,
        )
        .await
        .expect("994 route loopback connects")
    });
    let mut server = server;
    server
        .wait_for_authenticated_client(Duration::from_secs(10), &expectation)
        .await
        .expect("994 route loopback admits its own process");
    let transport = client_task.await.expect("994 route client task");
    let (peer_sid, peer_session) = match transport.peer_identity() {
        PeerIdentity::Authenticated {
            user_identity,
            session_identity,
            ..
        } => (user_identity.clone(), session_identity.clone()),
        PeerIdentity::Unavailable { .. } => {
            panic!("994 route loopback peer is not authenticated")
        }
    };
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").expect("route"),
        canonical_pipe_identity: PlatformHandle::new(&pipe).expect("pipe"),
        store_generation: ResourceGeneration::genesis(),
        state_fence: fence(),
        launch_nonce: PlatformHandle::new(format!("launch-994-kr-{case}")).expect("nonce"),
        connection_id: PlatformHandle::new(format!("conn-994-kr-{case}")).expect("conn"),
        expected_peer_sid: PlatformHandle::new(&peer_sid).expect("sid"),
        expected_peer_session_id: peer_session.parse().expect("session"),
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
        timeout_ms: 30_000,
    };
    let artifact = requirement.approved_artifact_hash.as_str().to_owned();
    let config = requirement.approved_config_hash.as_str().to_owned();
    let connection_id = requirement.connection_id.as_str().to_owned();
    let reserved_sends = Arc::new(AtomicUsize::new(0));
    let server_task = tokio::spawn(serve_store_route(
        server,
        connection_id,
        artifact,
        config,
        adapter,
        Arc::clone(&reserved_sends),
    ));
    let client = EbpCanonicalStoreClient::connect(transport, requirement)
        .await
        .expect("994 route EBP handshake");
    let fixture =
        KernelRouteStoreFixture::open(&format!("994-kr-{case}")).expect("994 route fixture opens");
    let service = Arc::new(Mutex::new(ready_service()));
    // The route carries the live service's complete epoch tuple; a sequence-only
    // route could no longer be proven current (Implements #64).
    let route_epoch = service
        .lock()
        .expect("994 route service")
        .authority_epoch()
        .clone();
    let route = GenerationRoute::new(
        RouteScope::new("store_bridge").expect("994 route scope"),
        ResourceGeneration::genesis(),
        route_epoch,
    )
    .expect("994 route");
    let gateway = Arc::new(KernelStoreGateway::new(
        service,
        Arc::new(client),
        route,
        Some(Arc::clone(fixture.store())),
    ));
    KernelRoute {
        gateway,
        fixture,
        reserved_sends,
        server_task,
        dir,
    }
}

async fn finish_route(route: KernelRoute) {
    let KernelRoute {
        gateway,
        server_task,
        dir,
        ..
    } = route;
    drop(gateway);
    if tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .is_err()
    {
        panic!("994 route responder did not join");
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn owner_for(fixture: &KernelRouteStoreFixture, context: &RequestMeta) -> CompositionReservation {
    CompositionReservation::bind(
        Arc::clone(fixture.store()),
        eliot_kernel_service::writer_epoch_for_fence(context).expect("994 writer epoch"),
    )
    .expect("994 owner binds")
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

        tokio::time::timeout(
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

// WORK_UNIT_CASE: 994/11 (follow-up binding, issue #2030)
#[tokio::test]
async fn precommit_crash_hook_stays_unknown_without_provider_effect() {
    case_entry(11);
    let harness = Harness::fresh("11h").await;
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
    let route = kernel_route("11h", harness.adapter_shared()).await;
    // Arm the production fault hook (issue #2030) on the proven route and
    // drive the owner-bound reserved path: the crash fires before any
    // provider send, so the write stays unknown with zero provider effect.
    let (ctx, transition, rev, ord, seed) =
        reserved_inputs("op-994-fault-pre", "scope-994-a", "subject-994-11h", 1);
    route.gateway.arm_store_fault(
        &StoreClientFaultHarness::test_harness(),
        StoreClientFault::PreCommitCrash,
    );
    let _ = route
        .gateway
        .apply_reserved(&ctx, transition, rev, ord, seed)
        .await
        .expect_err("armed pre-commit crash stays unknown");
    // Zero provider effect: reconcile proves absence by exact operation identity.
    let absent = harness
        .adapter()
        .reconcile(ApiOperationId::new("op-994-fault-pre").expect("operation"))
        .await
        .expect("reconcile");
    assert!(absent.is_none(), "crashed write left no provider effect");
    // Unknown is never retried blindly: the same reserved inputs are refused
    // while the faulted attempt's ORS reservation stands.
    let (ctx_dup, transition_dup, rev_dup, ord_dup, seed_dup) =
        reserved_inputs("op-994-fault-pre", "scope-994-a", "subject-994-11h", 1);
    let _ = route
        .gateway
        .apply_reserved(&ctx_dup, transition_dup, rev_dup, ord_dup, seed_dup)
        .await
        .expect_err("blind same-identity retry refused");
    // One-shot hook consumed without poisoning the route: a different
    // reserved operation commits normally through the same gateway.
    // (Same-identity retry after unknown is correctly refused while the
    // faulted attempt's ORS reservation stands — unknown is never retried
    // blindly; case 11 proves same-identity commit after proven absence on
    // the direct path.)
    let (ctx2, transition2, rev2, ord2, seed2) =
        reserved_inputs("op-994-fault-next", "scope-994-b", "subject-994-11h", 1);
    let receipt = route
        .gateway
        .apply_reserved(&ctx2, transition2, rev2, ord2, seed2)
        .await
        .expect("route unpoisoned after consumed fault");
    assert_eq!(receipt.operation_id.as_str(), "op-994-fault-next");
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    finish_route(route).await;
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/12 (follow-up binding, issue #2030)
#[tokio::test]
async fn postcommit_loss_hook_recovers_original_receipt() {
    case_entry(12);
    let harness = Harness::fresh("12h").await;
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
    let route = kernel_route("12h", harness.adapter_shared()).await;
    // Arm post-commit response loss: the provider commits, but the caller
    // observes unknown — recovery must return the ORIGINAL receipt.
    let (ctx, transition, rev, ord, seed) =
        reserved_inputs("op-994-fault-post", "scope-994-a", "subject-994-12h", 1);
    route.gateway.arm_store_fault(
        &StoreClientFaultHarness::test_harness(),
        StoreClientFault::PostCommitResponseLoss,
    );
    let _ = route
        .gateway
        .apply_reserved(&ctx, transition, rev, ord, seed)
        .await
        .expect_err("armed post-commit loss stays unknown");
    let recovered = harness
        .adapter()
        .reconcile(ApiOperationId::new("op-994-fault-post").expect("operation"))
        .await
        .expect("reconcile")
        .expect("committed operation must reconcile");
    assert_eq!(recovered.operation_id.as_str(), "op-994-fault-post");
    assert_eq!(recovered.status, WriteReceiptStatus::Committed);
    // Gateway-level recovery returns the same original through the route.
    let via_route: Option<WriteReceipt> = route
        .gateway
        .receipt(&fence(), recovered.operation_id.clone())
        .await
        .expect("receipt query");
    assert_eq!(via_route.as_ref(), Some(&recovered), "same original");
    finish_route(route).await;
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

// WORK_UNIT_CASE: 994/14 (follow-up binding, issue #2030)
#[tokio::test]
async fn capacity_occupancy_admission_live_observation_surface() {
    case_entry(14);
    let harness = Harness::fresh("14o").await;
    // Idle live pool: totals are the fixed construction bounds from the
    // frozen profile, nothing is checked out, every lane admits.
    let occupancy: PoolOccupancy = harness
        .adapter()
        .pool_occupancy()
        .expect("live pool observed");
    assert_eq!(
        (
            occupancy.read.total,
            occupancy.normal_write.total,
            occupancy.health_admin.total
        ),
        (5, 2, 1),
        "pool totals match profile construction bounds"
    );
    assert_eq!(
        (
            occupancy.read.checked_out,
            occupancy.normal_write.checked_out,
            occupancy.health_admin.checked_out
        ),
        (0, 0, 0),
        "idle observation checks nothing out"
    );
    assert!(
        harness
            .adapter()
            .pool_admission(SessionRole::NormalWrite)
            .expect("normal admission")
            .admitted(),
        "idle normal lane admits"
    );
    let protected: PoolAdmission = harness
        .adapter()
        .pool_admission(SessionRole::HealthAdmin)
        .expect("protected admission");
    assert!(protected.admitted(), "protected lane admits independently");
    // No execution installed on the plain harness: honest None, never
    // fabricated zeros.
    assert!(harness.adapter().execution_capacity().is_none());
    assert!(harness.adapter().scheduler_occupancy().is_none());
    assert!(harness.adapter().scheduler_admission().is_none());
    // Install the concurrent generation: live capacity and scheduler
    // snapshots observe real bounds with an empty queue.
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
    let capacity = harness
        .adapter()
        .execution_capacity()
        .expect("installed capacity observed");
    assert_eq!(
        capacity.max_pending,
        profile_usize("max_pending"),
        "capacity bound matches profile"
    );
    assert!(capacity.accepts_submits(), "empty queue accepts submits");
    assert!(
        capacity.protected_progress_open(),
        "protected recovery lane open"
    );
    let scheduled = harness
        .adapter()
        .scheduler_occupancy()
        .expect("scheduler observed");
    assert_eq!(
        (scheduled.pending, scheduled.in_flight, scheduled.uncertain),
        (0, 0, 0),
        "idle scheduler holds nothing"
    );
    assert!(!scheduled.draining, "no drain running");
    assert!(
        harness
            .adapter()
            .scheduler_admission()
            .expect("scheduler admission")
            .admitted(),
        "idle scheduler admits"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 994/15
#[tokio::test]
async fn migration_drain_accounts_every_operation() {
    case_entry(15);
    let harness = Harness::fresh("15").await;
    // The concurrent generation owns admission before any write: reserved
    // writes execute only under the concurrent profile, so the install
    // leads and every write below proves its path explicitly.
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
    // Live history first on the real Kernel to ORS to Store route: the
    // drain operation reserves in the fixture ORS, projects the reserved
    // submission, and commits against the live concurrent generation.
    let route = kernel_route("15", harness.adapter_shared()).await;
    let (d_ctx, d_transition, d_revision, d_ordering, d_seed) =
        reserved_inputs("op-994-drain", "scope-994-a", "subject-994-15", 1);
    let drained = route
        .gateway
        .apply_reserved(&d_ctx, d_transition.clone(), d_revision, d_ordering, d_seed)
        .await
        .unwrap_or_else(|error| panic!("drain commit failed: {error}"));
    validate_store_receipt_envelope(&d_ctx, &d_transition, &drained).expect("envelope");
    assert_committed("op-994-drain", &drained);
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
    // The fixture ORS holds no pending work once the route finalized the
    // drain reservation: the LoopbackTransport shape stages nothing, so an
    // empty unresolved scan is the binding proof.
    let owner = owner_for(&route.fixture, &d_ctx);
    let unresolved =
        eliot_kernel_service::unresolved_reservations(&owner, 64).expect("unresolved scans");
    assert!(
        unresolved.is_empty(),
        "drain reservation finalized in the fixture ORS"
    );
    assert_eq!(
        route.reserved_sends.load(Ordering::SeqCst),
        1,
        "exactly one reserved Store send"
    );
    // Reopen is an explicit generation install, after which the direct path
    // flows again on the drained state. Reserved writes stay refused without
    // the concurrent profile, so reopen commits direct.
    let reopened = harness
        .commit("op-994-reopen", "scope-994-a", "subject-994-15-r")
        .await;
    assert_committed("op-994-reopen", &reopened);
    finish_route(route).await;
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
    // 994/18 follow-up binding (issue #2030): join the proven primary
    // receipt with the fallible cleanup so BOTH errors are retained instead
    // of panicking on cleanup alone.
    let joined = join_cleanup_result(Ok(primary), harness.cleanup_result().await);
    let _primary = joined.expect("case 18 retains primary and cleanup outcomes together");
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
    // The concurrent generation owns admission before any write: reserved
    // writes execute only under the concurrent profile (same setup case 15
    // proves), so the admitted Kernel route below is the real reserved path.
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
    // The admitted Kernel route: a Ready KernelService, a real named-pipe
    // EBP connection pumping frames into the live Surreal adapter, and the
    // fixture ORS bound into the gateway. Handshake, readiness, admission,
    // reservation, framing, reconciliation and receipt decoding are all
    // production code; the ORS reservation lifecycle replaces the
    // hand-rolled loopback that staged nothing.
    let route = kernel_route("19", harness.adapter_shared()).await;
    // Pulse progress: two independent pulse scopes advance concurrently with
    // valid committed receipts through the admitted route.
    let (pulse_ctx_a, pulse_a, pulse_rev_a, pulse_ord_a, pulse_seed_a) =
        reserved_inputs("op-994-pulse-a", "scope-994-pulse-a", "subject-994-19-a", 1);
    let (pulse_ctx_b, pulse_b, pulse_rev_b, pulse_ord_b, pulse_seed_b) =
        reserved_inputs("op-994-pulse-b", "scope-994-pulse-b", "subject-994-19-b", 1);
    let (receipt_a, receipt_b) = tokio::join!(
        route.gateway.apply_reserved(
            &pulse_ctx_a,
            pulse_a.clone(),
            pulse_rev_a,
            pulse_ord_a,
            pulse_seed_a
        ),
        route.gateway.apply_reserved(
            &pulse_ctx_b,
            pulse_b.clone(),
            pulse_rev_b,
            pulse_ord_b,
            pulse_seed_b
        ),
    );
    let receipt_a = receipt_a.expect("pulse A progresses");
    let receipt_b = receipt_b.expect("pulse B progresses");
    validate_store_receipt_envelope(&pulse_ctx_a, &pulse_a, &receipt_a).expect("envelope A");
    validate_store_receipt_envelope(&pulse_ctx_b, &pulse_b, &receipt_b).expect("envelope B");
    assert_committed("op-994-pulse-a", &receipt_a);
    assert_committed("op-994-pulse-b", &receipt_b);
    // Both reservations finalized in the fixture ORS: the loopback shape
    // leaves no ORS trace, so an empty unresolved scan is the binding proof.
    let owner = owner_for(&route.fixture, &pulse_ctx_a);
    let unresolved =
        eliot_kernel_service::unresolved_reservations(&owner, 64).expect("unresolved scans");
    assert!(
        unresolved.is_empty(),
        "pulse reservations finalized in the fixture ORS"
    );
    assert_eq!(
        route.reserved_sends.load(Ordering::SeqCst),
        2,
        "exactly two reserved Store sends"
    );
    // Pulse cancellation: the admitted cancel future is dropped before send,
    // then the route reconciles proven absence by exact operation identity.
    // The lazy gateway future never polls, so nothing stages in ORS and the
    // live adapter never sees the operation.
    let (cancel_ctx, cancel_transition, cancel_rev, cancel_ord, cancel_seed) = reserved_inputs(
        "op-994-pulse-cancel",
        "scope-994-pulse-a",
        "subject-994-19-c",
        1,
    );
    let cancel_id = cancel_transition.identity.operation_id.clone();
    let cancelled = route.gateway.apply_reserved(
        &cancel_ctx,
        cancel_transition,
        cancel_rev,
        cancel_ord,
        cancel_seed,
    );
    drop(cancelled);
    let absence: Option<WriteReceipt> = route
        .gateway
        .receipt(&fence(), cancel_id)
        .await
        .expect("receipt query");
    assert!(absence.is_none(), "cancelled pulse has no provider effect");
    let still_clean =
        eliot_kernel_service::unresolved_reservations(&owner, 64).expect("cancelled scan");
    assert!(
        still_clean.is_empty(),
        "dropped cancel staged nothing in the fixture ORS"
    );
    // Pulse recovery: committed pulse operations reconcile to their exact
    // original receipts through the same route.
    for expected in [&receipt_a, &receipt_b] {
        let recovered: Option<WriteReceipt> = route
            .gateway
            .receipt(&fence(), expected.operation_id.clone())
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
    finish_route(route).await;
    harness.cleanup().await;
}
