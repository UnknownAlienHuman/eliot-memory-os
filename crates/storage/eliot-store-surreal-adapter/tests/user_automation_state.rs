//! Durable user-automation retention proof (issue #1779).
//!
//! The closed `ApplyUserAutomationState` / `GetUserAutomationState`
//! operations, submitted through the real prepared/admission path against
//! an isolated `surreal.exe` provider (loopback bind, per-test temporary
//! `SurrealKV` roots, redacted test credentials), persist immutable
//! revision lineage with pointer compare-and-set, admission-state moves
//! without touching immutable revisions, and manual-occurrence invocation
//! records. No in-memory stand-in, no production database, no user
//! credentials.
//!
//! Revision and invocation documents are built from the REAL Kernel-owned
//! domain types, serialized to the opaque wire JSON, and re-validated
//! through the domain after readback — proving domain fidelity across
//! the opaque store boundary.
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
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration, SourceId,
    StateFence,
};
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationDeliveryTarget, AutomationResourceCeiling,
    AutomationTaskBinding, AutomationTaskKind, AutomationWorkScope, NormalizedSchedule,
    OverlapPolicy, ProviderFingerprintPolicy, RecursionPolicy, RouteCostPolicy, ScheduleKind,
    UserAutomationConfigurationState, UserAutomationExecutionMode, UserAutomationInvocation,
    UserAutomationRevision, UserAutomationTrigger, UserAutomationTriggerOrigin,
};
use eliot_platform::ClockObservation;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::EffectClass;
use eliot_store_api::{
    CanonicalRequestView, NamedMutationOperation, NamedMutationRequest, OperationIdentity,
    OrderingScopeId, PreparedTransition, RequestMeta, ScopeId, SecurityContext, StoreError,
    TransitionClass, WriteReceiptStatus, canonical_request_hash, generated_operation_manifests,
    operation_manifest_set_digest,
};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

/// Isolated provider executable for tests. Overridable for local runs; the
/// default is the pinned local installation probed during implementation.
const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const SCOPE: &str = "user-automation";

fn surreal_exe() -> PathBuf {
    std::env::var("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|_| PathBuf::from(TEST_SURREAL_EXE), PathBuf::from)
}

// The caller must provide an absolute parent before running these tests. The
// harness claims and removes only its unique child beneath that parent.
fn live_scratch_root() -> PathBuf {
    let configured = PathBuf::from(
        std::env::var_os("ELIOT_AUTOMATION_TEST_ROOT")
            .expect("caller must provide ELIOT_AUTOMATION_TEST_ROOT"),
    );
    assert!(
        configured.is_absolute(),
        "ELIOT_AUTOMATION_TEST_ROOT must be an absolute path"
    );
    assert!(
        configured
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "ELIOT_AUTOMATION_TEST_ROOT must not contain relative path components"
    );
    let resolved = configured
        .canonicalize()
        .expect("ELIOT_AUTOMATION_TEST_ROOT must already exist");
    assert!(
        resolved.is_absolute() && resolved.is_dir(),
        "ELIOT_AUTOMATION_TEST_ROOT must resolve to an absolute directory"
    );
    configured
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
        request_id: RequestId::new(format!("request-automation-live-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-automation").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: eliot_contracts::ClockReading::default(),
    }
}

/// Minimal domain-valid revision (deterministic script mode, all
/// capability gates closed).
fn valid_revision(
    automation_id: &str,
    revision: &str,
    state: UserAutomationConfigurationState,
) -> UserAutomationRevision {
    UserAutomationRevision {
        automation_id: automation_id.to_owned(),
        revision: revision.to_owned(),
        supersedes: None,
        owner_principal: "human-1".to_owned(),
        work_scope: AutomationWorkScope {
            scope_id: "scope-1".to_owned(),
            product_id: "product-1".to_owned(),
            workdir_ref: "workdir-1".to_owned(),
        },
        natural_language_intent: "nightly backup".to_owned(),
        schedule: NormalizedSchedule {
            kind: ScheduleKind::OneShot,
            expression: "once".to_owned(),
            calendar: "gregorian".to_owned(),
            timezone: "UTC".to_owned(),
            dst_fold: eliot_kernel_core::user_automation::DstFoldPolicy::First,
            dst_gap: eliot_kernel_core::user_automation::DstGapPolicy::ShiftForward,
            start_at: "2026-09-21T00:00:00Z".to_owned(),
            end_at: None,
            next_occurrences: vec!["2026-09-21T00:00:00Z".to_owned()],
            // This fixture carries a retired shape-only occurrence key, so the
            // owning calendar adapter has not issued a normalization binding
            // for it. Empty evidence can never satisfy the required binding, so
            // the revision stays refused instead of becoming admitted.
            normalization_receipt: Box::new(
                eliot_kernel_core::user_automation::ScheduleNormalizationReceipt {
                    receipt_id: String::new(),
                    normalizer_authority: String::new(),
                    source_digest: String::new(),
                    zone_database_revision:
                        eliot_kernel_core::user_automation::PINNED_ZONE_DATABASE_REVISION.to_owned(),
                    occurrences_digest: String::new(),
                },
            ),
        },
        mode: UserAutomationExecutionMode::DeterministicProcess,
        task: AutomationTaskBinding {
            qualified_ref: "script:backup".to_owned(),
            kind: AutomationTaskKind::QualifiedScript,
            capability_profile: AutomationCapabilityProfile {
                model_access: false,
                provider_access: false,
                automation_scheduling: false,
            },
        },
        portable_skill_package_revision_refs: Vec::new(),
        trusted_tool_definition_refs: Vec::new(),
        workdir_ref: "workdir-1".to_owned(),
        route_cost_policy: RouteCostPolicy {
            route_ref: "local".to_owned(),
            max_cost_units: 1,
            max_duration_ms: 1,
            policy_revision: None,
        },
        provider_policy: ProviderFingerprintPolicy::DeterministicOnly,
        delivery_target: AutomationDeliveryTarget {
            target_ref: "inbox".to_owned(),
            channels: vec![eliot_kernel_core::DeliveryChannel::ControlBoard],
            recipient_refs: Vec::new(),
        },
        preflight_contract_revision: "eliot.user-automation.preflight.v1".to_owned(),
        resource_ceiling: AutomationResourceCeiling {
            max_runtime_ms: 1,
            max_output_bytes: 1,
            max_child_count: 0,
        },
        overlap_policy: OverlapPolicy::ForbidOverlap,
        recursion_policy: RecursionPolicy {
            allow_child_automation: false,
            max_child_depth: 0,
        },
        configuration_state: state,
        work_class: eliot_kernel_core::user_automation::AutomationWorkClass::NormalBackground,
        current_execution_refs: Vec::new(),
        execution_history_query_ref: "history-1".to_owned(),
    }
}

fn revision_json(revision: &UserAutomationRevision) -> String {
    revision
        .validate()
        .expect("fixture revision is domain-valid");
    serde_json::to_string(revision).expect("fixture serializes")
}

fn invocation_for(automation_id: &str, revision: &str, nonce: &str) -> (String, String) {
    let invocation = UserAutomationInvocation {
        automation_id: automation_id.to_owned(),
        automation_revision: revision.to_owned(),
        trigger: UserAutomationTrigger::Manual {
            nonce: nonce.to_owned(),
        },
        mode: UserAutomationExecutionMode::DeterministicProcess,
        principal_ref: "human-1".to_owned(),
        work_scope_ref: "scope-1".to_owned(),
        workdir_ref: "workdir-1".to_owned(),
        trigger_origin: UserAutomationTriggerOrigin::Human,
        child_depth: 0,
        provenance: None,
    };
    invocation.validate().expect("fixture invocation valid");
    let occurrence_id = invocation
        .occurrence_identity()
        .expect("occurrence derives");
    let json = serde_json::to_string(&invocation).expect("fixture serializes");
    (occurrence_id, json)
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
        contract_version: eliot_store_api::CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-automation-live-{tag}")).expect("operation"),
            idempotency_key: format!("idem-automation-live-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(SCOPE).expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(SCOPE).expect("ordering")],
        transition_class: TransitionClass::UserAutomation,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: eliot_store_api::supported_admission_contract_set_digest()
            .expect("supported admission contract set"),
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
        event_projection_relation_intents: eliot_store_api::EventProjectionRelationIntents {
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
        database: "automation_1779".to_owned(),
        username: "automation-test".to_owned(),
        password: SecretString::new("automation-test-secret".into()),
        provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
        provider_bootstrap_password: SecretString::new("provider-bootstrap-fixture-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-test-1779".to_owned(),
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
    let password = SecretString::new("automation-test-secret".into());
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            "automation-test",
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
        .stderr(Stdio::piped())
        .spawn()
        .expect("preparation provider");
    let stderr = child.stderr.take().expect("preparation provider stderr");
    let stderr_reader = std::thread::spawn(move || {
        let mut stderr = stderr;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut stderr, &mut bytes)
            .expect("read preparation provider stderr");
        bytes
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if std::net::TcpStream::connect(bind).is_ok() {
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = stderr_reader
                    .join()
                    .unwrap_or_else(|_| b"preparation provider stderr reader panicked".to_vec());
                let stderr = String::from_utf8_lossy(&stderr);
                panic!(
                    "preparation provider exited before binding {bind} with {status}; stderr:\n{stderr}"
                );
            }
            Ok(None) => {}
            Err(error) => {
                let kill = child.kill();
                let exit = child.wait();
                let stderr = stderr_reader
                    .join()
                    .unwrap_or_else(|_| b"preparation provider stderr reader panicked".to_vec());
                let stderr = String::from_utf8_lossy(&stderr);
                panic!(
                    "preparation provider status check failed before binding {bind}: {error}; kill={kill:?}; exit={exit:?}; stderr:\n{stderr}"
                );
            }
        }
        if std::time::Instant::now() >= deadline {
            let kill = child.kill();
            let exit = child.wait();
            let stderr = stderr_reader
                .join()
                .unwrap_or_else(|_| b"preparation provider stderr reader panicked".to_vec());
            let stderr = String::from_utf8_lossy(&stderr);
            panic!(
                "preparation provider never bound {bind}; kill={kill:?}; exit={exit:?}; stderr:\n{stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(2));
    match child.try_wait() {
        Ok(Some(status)) => {
            let stderr = stderr_reader
                .join()
                .unwrap_or_else(|_| b"preparation provider stderr reader panicked".to_vec());
            let stderr = String::from_utf8_lossy(&stderr);
            panic!(
                "preparation provider exited after binding {bind} with {status}; stderr:\n{stderr}"
            );
        }
        Ok(None) => {}
        Err(error) => {
            let kill = child.kill();
            let exit = child.wait();
            let stderr = stderr_reader
                .join()
                .unwrap_or_else(|_| b"preparation provider stderr reader panicked".to_vec());
            let stderr = String::from_utf8_lossy(&stderr);
            panic!(
                "preparation provider status check failed after binding {bind}: {error}; kill={kill:?}; exit={exit:?}; stderr:\n{stderr}"
            );
        }
    }
    let kill = child.kill();
    let exit = child.wait();
    let stderr = stderr_reader
        .join()
        .unwrap_or_else(|_| b"preparation provider stderr reader panicked".to_vec());
    let stderr = String::from_utf8_lossy(&stderr);
    if let Err(error) = kill {
        panic!(
            "preparation provider stop failed at {bind}: {error}; exit={exit:?}; stderr:\n{stderr}"
        );
    }
    let status = match exit {
        Ok(status) => status,
        Err(error) => {
            panic!("preparation provider wait failed at {bind}: {error}; stderr:\n{stderr}")
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(bind).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "preparation provider never released {bind}; exit={status}; stderr:\n{stderr}"
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
        let scratch_root = live_scratch_root();
        let port = free_port();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root = scratch_root.join(format!(
            "eliot-automation-2860-{}-{port}-{test}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("claim unique test scratch child");
        let mut harness = Self {
            root,
            adapter: None,
        };
        let bin = harness.root.join("bin");
        let data = harness.root.join("store").join("data");
        let work = harness.root.join("store").join("work");
        let tmp = harness.root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("test dirs");
        }
        let source_exe = surreal_exe();
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage provider");
        let digest = eliot_store_api::sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
        println!(
            "automation-state provider: exe={} sha256={} port={} root={}",
            exe.display(),
            digest,
            port,
            harness.root.display()
        );
        let platform = WindowsPlatform::new(harness.root.clone()).expect("platform");
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
        harness.adapter = Some(adapter);
        harness
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

async fn apply(
    adapter: &SurrealStoreAdapter,
    tag: &str,
    parameters: BTreeMap<String, Value>,
) -> Result<eliot_store_api::WriteReceipt, StoreError> {
    let (ctx, transition) = transition_with(
        tag,
        NamedMutationOperation::ApplyUserAutomationState,
        parameters,
    );
    eliot_store_api::CanonicalStoreClient::apply_prepared(adapter, &ctx, transition, vec![], vec![])
        .await
}

async fn read(
    adapter: &SurrealStoreAdapter,
    query: &str,
    automation_id: Option<&str>,
    include_retired: bool,
) -> Value {
    read_page(adapter, query, automation_id, include_retired, 64, None)
        .await
        .expect("read executes")
}

async fn read_page(
    adapter: &SurrealStoreAdapter,
    query: &str,
    automation_id: Option<&str>,
    include_retired: bool,
    max_records: u16,
    cursor: Option<&str>,
) -> Result<Value, StoreError> {
    let mut request = eliot_store_api::automation_read_request(
        query.to_owned(),
        automation_id.map(str::to_owned),
        include_retired,
        max_records,
        fence(),
    )?;
    if let Some(cursor) = cursor {
        request.parameters.insert(
            eliot_store_api::AUTOMATION_PARAM_CURSOR.to_owned(),
            Value::String(cursor.to_owned()),
        );
    }
    eliot_store_api::CanonicalStoreClient::execute_named(adapter, request)
        .await
        .map(|outcome| outcome.payload)
}

async fn read_page_with_fence(
    adapter: &SurrealStoreAdapter,
    query: &str,
    automation_id: Option<&str>,
    include_retired: bool,
    max_records: u16,
    state_fence: StateFence,
) -> Result<Value, StoreError> {
    let request = eliot_store_api::automation_read_request(
        query.to_owned(),
        automation_id.map(str::to_owned),
        include_retired,
        max_records,
        state_fence,
    )?;
    eliot_store_api::CanonicalStoreClient::execute_named(adapter, request)
        .await
        .map(|outcome| outcome.payload)
}

fn page_cursor(payload: &Value) -> &str {
    payload
        .get("completeness")
        .and_then(|completeness| completeness.get(eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR))
        .and_then(Value::as_str)
        .expect("truncated page has an owner cursor")
}

async fn store_revision(
    adapter: &SurrealStoreAdapter,
    automation_id: &str,
    revision: &str,
    previous_revision: Option<&str>,
    tag: &str,
) {
    let mut candidate = valid_revision(
        automation_id,
        revision,
        UserAutomationConfigurationState::Active,
    );
    let parameters = if let Some(previous_revision) = previous_revision {
        candidate.supersedes = Some(previous_revision.to_owned());
        candidate
            .validate_supersedes(&valid_revision(
                automation_id,
                previous_revision,
                UserAutomationConfigurationState::Active,
            ))
            .expect("fixture lineage is domain-valid");
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_edit_params(
            automation_id.to_owned(),
            previous_revision.to_owned(),
            revision.to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&candidate),
        ))
        .parameters
    } else {
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_create_params(
            automation_id.to_owned(),
            revision.to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&candidate),
        ))
        .parameters
    };
    apply(adapter, tag, parameters)
        .await
        .expect("revision commits");
}

async fn store_invocation(
    adapter: &SurrealStoreAdapter,
    automation_id: &str,
    revision: &str,
    occurrence_id: String,
    invocation_json: String,
    tag: &str,
) {
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_run_now_params(
            automation_id.to_owned(),
            revision.to_owned(),
            occurrence_id,
            invocation_json,
        ));
    apply(adapter, tag, request.parameters)
        .await
        .expect("invocation commits");
}

async fn assert_page_replay(
    adapter: &SurrealStoreAdapter,
    query: &str,
    automation_id: &str,
    rows_field: &str,
    identity_field: &str,
    expected_ids: &[String],
) {
    assert_eq!(expected_ids.len(), 3);
    let read_first = || read_page(adapter, query, Some(automation_id), false, 1, None);
    let (first_a, first_b) = tokio::join!(read_first(), read_first());
    let first = first_a.expect("first page reads");
    assert_eq!(first, first_b.expect("replayed first page reads"));
    assert_eq!(
        first[rows_field][0][identity_field].as_str(),
        Some(expected_ids[0].as_str())
    );

    let first_cursor = page_cursor(&first).to_owned();
    let read_second = || {
        read_page(
            adapter,
            query,
            Some(automation_id),
            false,
            1,
            Some(&first_cursor),
        )
    };
    let (second_a, second_b) = tokio::join!(read_second(), read_second());
    let second = second_a.expect("continued page reads");
    assert_eq!(second, second_b.expect("replayed continued page reads"));
    assert_eq!(
        second[rows_field][0][identity_field].as_str(),
        Some(expected_ids[1].as_str())
    );

    let first_after_child = read_page(adapter, query, Some(automation_id), false, 1, None)
        .await
        .expect("first page replays after its continuation is issued");
    assert_eq!(first, first_after_child);

    let last = read_page(
        adapter,
        query,
        Some(automation_id),
        false,
        1,
        Some(page_cursor(&second)),
    )
    .await
    .expect("last page reads");
    assert_eq!(
        last[rows_field][0][identity_field].as_str(),
        Some(expected_ids[2].as_str())
    );
    assert!(
        last["completeness"]
            .get(eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR)
            .is_none()
    );
}

fn assert_automation_page(
    payload: &Value,
    rows_field: &str,
    identity_field: &str,
    expected_ids: &[String],
    expected_coverage: &str,
    expect_cursor: bool,
    label: &str,
) -> (String, Option<String>) {
    let rows = payload
        .get(rows_field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{label} rows array"));
    assert!(rows.len() <= 64, "{label} exceeds max_records=64");
    assert_eq!(rows.len(), expected_ids.len(), "{label} row count");
    for (row, expected_id) in rows.iter().zip(expected_ids) {
        assert_eq!(
            row.get(identity_field).and_then(Value::as_str),
            Some(expected_id.as_str()),
            "{label} logical row identity"
        );
    }

    let completeness = payload
        .get("completeness")
        .unwrap_or_else(|| panic!("{label} owner completeness"));
    assert_eq!(
        completeness.get("coverage").and_then(Value::as_str),
        Some(expected_coverage),
        "{label} owner coverage"
    );
    assert_eq!(
        completeness.get("returned").and_then(Value::as_u64),
        Some(rows.len() as u64),
        "{label} completeness count matches returned rows"
    );
    assert_eq!(
        payload.get("revision").and_then(Value::as_u64),
        Some(rows.len() as u64),
        "{label} projection revision matches returned rows"
    );
    let read_revision = completeness
        .get("read_revision")
        .and_then(Value::as_str)
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| panic!("{label} owner read revision"))
        .to_owned();
    let cursor = completeness
        .get(eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR)
        .and_then(Value::as_str)
        .map(str::to_owned);
    assert_eq!(cursor.is_some(), expect_cursor, "{label} cursor presence");
    (read_revision, cursor)
}

fn automation_page_ids(payload: &Value, rows_field: &str, identity_field: &str) -> Vec<String> {
    payload
        .get(rows_field)
        .and_then(Value::as_array)
        .expect("page rows array")
        .iter()
        .map(|row| {
            row.get(identity_field)
                .and_then(Value::as_str)
                .expect("page identity")
                .to_owned()
        })
        .collect()
}

struct AutomationPageFixture {
    row_count: usize,
    automation_id: String,
    revisions: Vec<String>,
    invocations: Vec<(String, String)>,
}

async fn seed_automation_page_fixture(
    adapter: &SurrealStoreAdapter,
    corpus_id: &str,
    row_count: usize,
) -> AutomationPageFixture {
    let automation_id = format!("auto-page-{corpus_id}");
    let mut revisions = Vec::with_capacity(row_count);
    let mut previous_revision = None;
    for index in 0..row_count {
        let revision = format!("r-{index:03}");
        let tag = format!("{corpus_id}-revision-{index:03}");
        store_revision(
            adapter,
            &automation_id,
            &revision,
            previous_revision.as_deref(),
            &tag,
        )
        .await;
        previous_revision = Some(revision.clone());
        revisions.push(revision);
    }

    let latest_revision = revisions.last().expect("corpus has revisions").clone();
    let mut invocations = (0..row_count)
        .map(|index| {
            invocation_for(
                &automation_id,
                &latest_revision,
                &format!("{corpus_id}-nonce-{index:03}"),
            )
        })
        .collect::<Vec<_>>();
    invocations.sort_by(|left, right| left.0.cmp(&right.0));
    for (index, (occurrence_id, invocation_json)) in invocations.iter().enumerate() {
        let tag = format!("{corpus_id}-invocation-{index:03}");
        store_invocation(
            adapter,
            &automation_id,
            &latest_revision,
            occurrence_id.clone(),
            invocation_json.clone(),
            &tag,
        )
        .await;
    }

    AutomationPageFixture {
        row_count,
        automation_id,
        revisions,
        invocations,
    }
}

async fn assert_automation_page_walk(
    adapter: &SurrealStoreAdapter,
    query: &str,
    automation_id: &str,
    rows_field: &str,
    identity_field: &str,
    expected_ids: &[String],
    label: &str,
) {
    let mut offset = 0;
    let mut cursor: Option<String> = None;
    let mut root_read_revision: Option<String> = None;
    let mut root_page: Option<Value> = None;
    let mut observed_ids = Vec::with_capacity(expected_ids.len());
    let mut page_index = 0;

    loop {
        let page_label = format!("{label} page {page_index}");
        let page = read_page(
            adapter,
            query,
            Some(automation_id),
            false,
            64,
            cursor.as_deref(),
        )
        .await
        .unwrap_or_else(|error| panic!("{page_label}: {error:?}"));
        let page_count = (expected_ids.len() - offset).min(64);
        let expected_page_ids = &expected_ids[offset..offset + page_count];
        let truncated = expected_ids.len() - offset > 64;
        let expected_coverage = if truncated { "TRUNCATED" } else { "COMPLETE" };
        let (read_revision, next_cursor) = assert_automation_page(
            &page,
            rows_field,
            identity_field,
            expected_page_ids,
            expected_coverage,
            truncated,
            &page_label,
        );
        if let Some(root_read_revision) = root_read_revision.as_deref() {
            assert_eq!(
                read_revision, root_read_revision,
                "{page_label} stays on the root read revision"
            );
        } else {
            root_read_revision = Some(read_revision);
        }
        if page_index == 0 {
            root_page = Some(page.clone());
        }
        observed_ids.extend(automation_page_ids(&page, rows_field, identity_field));

        if let Some(cursor_value) = cursor.as_deref() {
            let replay = read_page(
                adapter,
                query,
                Some(automation_id),
                false,
                64,
                Some(cursor_value),
            )
            .await
            .unwrap_or_else(|error| panic!("{page_label} replay: {error:?}"));
            assert_eq!(page, replay, "{page_label} continuation replay is exact");
        }

        offset += page_count;
        page_index += 1;
        cursor = next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    let root_replay = read_page(adapter, query, Some(automation_id), false, 64, None)
        .await
        .unwrap_or_else(|error| panic!("{label} root replay: {error:?}"));
    assert_eq!(
        root_page.as_ref(),
        Some(&root_replay),
        "{label} root replay preserves its page and cursor identity"
    );
    assert_eq!(
        observed_ids, expected_ids,
        "{label} walk returns each row once"
    );
}

fn assert_exact_automation_selector(
    payload: &Value,
    rows_field: &str,
    identity_field: &str,
    expected_id: &str,
    label: &str,
) {
    let rows = payload
        .get(rows_field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{label} rows array"));
    assert!(
        rows.len() <= 1,
        "{label} exact selector returned multiple rows"
    );
    assert_eq!(rows.len(), 1, "{label} exact selector row count");
    assert_eq!(
        rows[0].get(identity_field).and_then(Value::as_str),
        Some(expected_id),
        "{label} exact selector identity"
    );
    if let Some(completeness) = payload.get("completeness") {
        assert!(
            completeness
                .get(eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR)
                .and_then(Value::as_str)
                .is_none(),
            "{label} exact selector does not receive a continuation"
        );
        if completeness.get("returned").is_some() {
            assert_eq!(
                completeness.get("returned").and_then(Value::as_u64),
                Some(1),
                "{label} exact selector completeness count"
            );
        }
        if completeness.get("coverage").is_some() {
            assert_eq!(
                completeness.get("coverage").and_then(Value::as_str),
                Some("COMPLETE"),
                "{label} exact selector coverage"
            );
        }
    }
}

#[tokio::test]
async fn real_provider_automation_history_and_invocation_page_matrix() {
    let harness = Harness::fresh("page-cardinality-matrix").await;
    let adapter = harness.adapter();

    let mut first_page_fixtures = Vec::new();
    for row_count in [63_usize, 64, 65, 66] {
        first_page_fixtures.push(
            seed_automation_page_fixture(adapter, &format!("first-{row_count}"), row_count).await,
        );
    }
    let mut continuation_fixtures = Vec::new();
    for remaining_count in [63_usize, 64, 65, 66] {
        continuation_fixtures.push(
            seed_automation_page_fixture(
                adapter,
                &format!("continuation-{remaining_count}"),
                64 + remaining_count,
            )
            .await,
        );
    }

    // Every corpus above is written through the same-fence canonical owner
    // path before these reads. Other automation rows are real persisted rows,
    // but cannot enter the selected automation's eligible denominator.
    for fixture in &first_page_fixtures {
        let invocation_ids = fixture
            .invocations
            .iter()
            .map(|(occurrence_id, _)| occurrence_id.clone())
            .collect::<Vec<_>>();
        let row_count = fixture.row_count;
        let foreign_rows_label = if row_count == 63 {
            " with persisted foreign automation rows"
        } else {
            ""
        };
        assert_automation_page_walk(
            adapter,
            eliot_store_api::AUTOMATION_QUERY_HISTORY,
            &fixture.automation_id,
            "revisions",
            "revision",
            &fixture.revisions,
            &format!("history {row_count}{foreign_rows_label}"),
        )
        .await;
        assert_automation_page_walk(
            adapter,
            eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
            &fixture.automation_id,
            "invocations",
            "occurrence_id",
            &invocation_ids,
            &format!("invocations {row_count}{foreign_rows_label}"),
        )
        .await;

        if row_count == 66 {
            let requested_revision = &fixture.revisions[32];
            let exact_history = eliot_store_api::automation_revision_read_request(
                eliot_store_api::AUTOMATION_QUERY_HISTORY.to_owned(),
                fixture.automation_id.clone(),
                requested_revision.clone(),
                false,
                64,
                fence(),
            )
            .expect("exact history request");
            let exact_history =
                eliot_store_api::CanonicalStoreClient::execute_named(adapter, exact_history)
                    .await
                    .expect("exact history reads")
                    .payload;
            assert_exact_automation_selector(
                &exact_history,
                "revisions",
                "revision",
                requested_revision,
                "exact history",
            );

            let requested_occurrence = &fixture.invocations[32].0;
            let exact_invocation = eliot_store_api::automation_invocation_read_request(
                fixture.automation_id.clone(),
                requested_occurrence.clone(),
                fence(),
            )
            .expect("exact invocation request");
            let exact_invocation =
                eliot_store_api::CanonicalStoreClient::execute_named(adapter, exact_invocation)
                    .await
                    .expect("exact invocation reads")
                    .payload;
            assert_exact_automation_selector(
                &exact_invocation,
                "invocations",
                "occurrence_id",
                requested_occurrence,
                "exact invocation",
            );
        }
    }

    for fixture in &continuation_fixtures {
        let remaining_count = fixture.row_count - 64;
        let invocation_ids = fixture
            .invocations
            .iter()
            .map(|(occurrence_id, _)| occurrence_id.clone())
            .collect::<Vec<_>>();
        assert_automation_page_walk(
            adapter,
            eliot_store_api::AUTOMATION_QUERY_HISTORY,
            &fixture.automation_id,
            "revisions",
            "revision",
            &fixture.revisions,
            &format!("history continuation with {remaining_count} remaining rows"),
        )
        .await;
        assert_automation_page_walk(
            adapter,
            eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
            &fixture.automation_id,
            "invocations",
            "occurrence_id",
            &invocation_ids,
            &format!("invocation continuation with {remaining_count} remaining rows"),
        )
        .await;
    }

    let mut different_generation = fence();
    different_generation.resource_generation =
        ResourceGeneration::new(2).expect("typed alternate generation");
    let persisted_owner = &first_page_fixtures[0].automation_id;
    for query in [
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
    ] {
        assert!(
            matches!(
                read_page_with_fence(
                    adapter,
                    query,
                    Some(persisted_owner),
                    false,
                    64,
                    different_generation.clone(),
                )
                .await,
                Err(StoreError::FenceMismatch)
            ),
            "{query} refuses a different typed fence for the old-fence corpus"
        );
    }
}

#[tokio::test]
async fn automation_history_and_invocation_pages_replay_same_cursors() {
    let harness = Harness::fresh("automation-page-replay").await;
    let adapter = harness.adapter();
    let automation_id = "auto-page-replay";
    store_revision(adapter, automation_id, "r-1", None, "page-create").await;
    store_revision(adapter, automation_id, "r-2", Some("r-1"), "page-edit-2").await;
    store_revision(adapter, automation_id, "r-3", Some("r-2"), "page-edit-3").await;

    let mut invocations = [
        invocation_for(automation_id, "r-3", "page-replay-a"),
        invocation_for(automation_id, "r-3", "page-replay-b"),
        invocation_for(automation_id, "r-3", "page-replay-c"),
        invocation_for(automation_id, "r-3", "page-replay-d"),
    ];
    invocations.sort_by(|left, right| left.0.cmp(&right.0));
    for (index, (occurrence_id, invocation_json)) in invocations.iter().skip(1).take(3).enumerate()
    {
        let tag = format!("page-run-{index}");
        store_invocation(
            adapter,
            automation_id,
            "r-3",
            occurrence_id.clone(),
            invocation_json.clone(),
            &tag,
        )
        .await;
    }
    assert_page_replay(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        automation_id,
        "revisions",
        "revision",
        &["r-1".to_owned(), "r-2".to_owned(), "r-3".to_owned()],
    )
    .await;
    let invocation_ids = invocations
        .iter()
        .skip(1)
        .take(3)
        .map(|(occurrence_id, _)| occurrence_id.clone())
        .collect::<Vec<_>>();
    assert_page_replay(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        automation_id,
        "invocations",
        "occurrence_id",
        &invocation_ids,
    )
    .await;
}

#[tokio::test]
async fn automation_first_page_replay_refuses_changed_binding_tail_and_snapshot() {
    let harness = Harness::fresh("automation-page-replay-refusal").await;
    let adapter = harness.adapter();
    let automation_id = "auto-page-refusal";
    store_revision(adapter, automation_id, "r-1", None, "refusal-create").await;
    store_revision(adapter, automation_id, "r-2", Some("r-1"), "refusal-edit-2").await;

    let mut invocations = [
        invocation_for(automation_id, "r-2", "refusal-low"),
        invocation_for(automation_id, "r-2", "refusal-middle"),
        invocation_for(automation_id, "r-2", "refusal-high"),
    ];
    invocations.sort_by(|left, right| left.0.cmp(&right.0));
    for (index, (occurrence_id, invocation_json)) in invocations.iter().skip(1).enumerate() {
        let tag = format!("refusal-run-{index}");
        store_invocation(
            adapter,
            automation_id,
            "r-2",
            occurrence_id.clone(),
            invocation_json.clone(),
            &tag,
        )
        .await;
    }

    let history_first = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        Some(automation_id),
        false,
        1,
        None,
    )
    .await
    .expect("first history page reads");
    let history_cursor = page_cursor(&history_first).to_owned();
    let invocation_first = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        Some(automation_id),
        false,
        1,
        None,
    )
    .await
    .expect("first invocation page reads");
    let invocation_cursor = page_cursor(&invocation_first).to_owned();

    let changed_binding = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        Some(automation_id),
        false,
        2,
        Some(&history_cursor),
    )
    .await;
    assert!(matches!(
        changed_binding,
        Err(StoreError::AutomationContinuation(
            eliot_store_api::AutomationContinuationFailure::InvalidOrUnknown
        ))
    ));

    store_invocation(
        adapter,
        automation_id,
        "r-2",
        invocations[0].0.clone(),
        invocations[0].1.clone(),
        "refusal-run-earlier",
    )
    .await;
    let changed_snapshot_first = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        Some(automation_id),
        false,
        1,
        None,
    )
    .await;
    let changed_snapshot_first = changed_snapshot_first.expect("new snapshot first page reads");
    assert_eq!(
        changed_snapshot_first["invocations"][0]["occurrence_id"].as_str(),
        Some(invocations[0].0.as_str())
    );
    let changed_snapshot_cursor = page_cursor(&changed_snapshot_first).to_owned();
    assert_ne!(changed_snapshot_cursor, invocation_cursor);
    let changed_snapshot_second = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        Some(automation_id),
        false,
        1,
        Some(&changed_snapshot_cursor),
    )
    .await
    .expect("new snapshot continuation reads after the new first-page tail");
    assert_eq!(
        changed_snapshot_second["invocations"][0]["occurrence_id"].as_str(),
        Some(invocations[1].0.as_str())
    );
    let old_invocation_snapshot = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        Some(automation_id),
        false,
        1,
        Some(&invocation_cursor),
    )
    .await;
    assert!(matches!(
        old_invocation_snapshot,
        Err(StoreError::AutomationContinuation(
            eliot_store_api::AutomationContinuationFailure::StaleSnapshot
        ))
    ));

    store_revision(adapter, automation_id, "r-3", Some("r-2"), "refusal-edit-3").await;
    let changed_snapshot = read_page(
        adapter,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        Some(automation_id),
        false,
        1,
        Some(&history_cursor),
    )
    .await;
    assert!(matches!(
        changed_snapshot,
        Err(StoreError::AutomationContinuation(
            eliot_store_api::AutomationContinuationFailure::StaleSnapshot
        ))
    ));
}

fn check_domain_revision(payload_json: &str, automation_id: &str, revision: &str) {
    let parsed: UserAutomationRevision =
        serde_json::from_str(payload_json).expect("stored document parses");
    parsed
        .validate()
        .expect("stored document stays domain-valid");
    assert_eq!(parsed.automation_id, automation_id);
    assert_eq!(parsed.revision, revision);
}

#[tokio::test]
async fn lifecycle_persists_lineage_with_pointer_cas() {
    let harness = Harness::fresh("lifecycle").await;
    let adapter = harness.adapter();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_create_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&first),
        ));
    let receipt = apply(adapter, "create-1", request.parameters)
        .await
        .expect("create commits");
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    let payload = read(adapter, "current", Some("auto-1"), false).await;
    assert_eq!(
        payload
            .get("current")
            .and_then(|current| current.get("revision"))
            .and_then(Value::as_str),
        Some("r-1")
    );
    // Edit supersedes with pointer compare-and-set; history keeps both
    // domain-valid documents verbatim.
    let mut second = valid_revision("auto-1", "r-2", UserAutomationConfigurationState::Active);
    second.supersedes = Some("r-1".to_owned());
    second
        .validate_supersedes(&first)
        .expect("fixture lineage is domain-valid");
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_edit_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            "r-2".to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&second),
        ));
    apply(adapter, "edit-1", request.parameters)
        .await
        .expect("edit commits");
    let payload = read(adapter, "history", Some("auto-1"), false).await;
    let revisions = payload
        .get("revisions")
        .and_then(Value::as_array)
        .expect("history array");
    assert_eq!(revisions.len(), 2);
    for entry in revisions {
        check_domain_revision(
            entry
                .get("revision_json")
                .and_then(Value::as_str)
                .expect("document"),
            "auto-1",
            entry.get("revision").and_then(Value::as_str).expect("id"),
        );
    }
    // Pause moves admission state; the immutable row set is untouched.
    let request = eliot_store_api::automation_mutation_request(
        eliot_store_api::automation_state_transition_params(
            "pause".to_owned(),
            "auto-1".to_owned(),
            "r-2".to_owned(),
            eliot_store_api::AUTOMATION_STATE_PAUSED.to_owned(),
        ),
    );
    apply(adapter, "pause-1", request.parameters)
        .await
        .expect("pause commits");
    let payload = read(adapter, "current", Some("auto-1"), false).await;
    assert_eq!(
        payload
            .get("current")
            .and_then(|current| current.get("configuration_state"))
            .and_then(Value::as_str),
        Some("PAUSED")
    );
    // Same-operation replay resolves the sealed receipt without remutation.
    let request = eliot_store_api::automation_mutation_request(
        eliot_store_api::automation_state_transition_params(
            "pause".to_owned(),
            "auto-1".to_owned(),
            "r-2".to_owned(),
            eliot_store_api::AUTOMATION_STATE_PAUSED.to_owned(),
        ),
    );
    let (ctx, transition) = transition_with(
        "pause-1",
        NamedMutationOperation::ApplyUserAutomationState,
        request.parameters,
    );
    let replayed = eliot_store_api::CanonicalStoreClient::apply_prepared(
        adapter,
        &ctx,
        transition,
        vec![],
        vec![],
    )
    .await
    .expect("replay resolves");
    assert_eq!(
        replayed.operation_id,
        eliot_store_api::OperationId::new("op-automation-live-pause-1").expect("operation"),
        "replay resolves the sealed identity"
    );
    // Retire filters from the default list but serves on explicit request.
    let request = eliot_store_api::automation_mutation_request(
        eliot_store_api::automation_state_transition_params(
            "remove".to_owned(),
            "auto-1".to_owned(),
            "r-2".to_owned(),
            eliot_store_api::AUTOMATION_STATE_RETIRED.to_owned(),
        ),
    );
    apply(adapter, "remove-1", request.parameters)
        .await
        .expect("remove commits");
    let payload = read(adapter, "list", None, false).await;
    assert_eq!(
        payload
            .get("currents")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let payload = read(adapter, "list", None, true).await;
    assert_eq!(
        payload
            .get("currents")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
}

#[tokio::test]
async fn run_now_records_invocations_by_occurrence() {
    let harness = Harness::fresh("run-now").await;
    let adapter = harness.adapter();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_create_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&first),
        ));
    apply(adapter, "create-1", request.parameters)
        .await
        .expect("create commits");
    let (occurrence_id, invocation) = invocation_for("auto-1", "r-1", "nonce-7");
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_run_now_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            occurrence_id.clone(),
            invocation,
        ));
    apply(adapter, "run-1", request.parameters)
        .await
        .expect("run-now commits");
    let payload = read(adapter, "invocations", Some("auto-1"), false).await;
    let invocations = payload
        .get("invocations")
        .and_then(Value::as_array)
        .expect("invocations array");
    assert_eq!(invocations.len(), 1);
    let stored = invocations[0]
        .get("invocation_json")
        .and_then(Value::as_str)
        .expect("document");
    let parsed: UserAutomationInvocation =
        serde_json::from_str(stored).expect("stored invocation parses");
    parsed
        .validate()
        .expect("stored invocation stays domain-valid");
    assert_eq!(
        parsed.occurrence_identity().expect("occurrence re-derives"),
        occurrence_id
    );
    // Identical re-record converges.
    let (_, invocation) = invocation_for("auto-1", "r-1", "nonce-7");
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_run_now_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            occurrence_id,
            invocation,
        ));
    apply(adapter, "run-2", request.parameters)
        .await
        .expect("convergent re-record commits");
    let payload = read(adapter, "invocations", Some("auto-1"), false).await;
    assert_eq!(
        payload
            .get("invocations")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "convergent re-record adds no row"
    );
}

#[tokio::test]
async fn lineage_and_key_conflicts_fail_closed() {
    let harness = Harness::fresh("conflicts").await;
    let adapter = harness.adapter();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let create_params = || {
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_create_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&first),
        ))
        .parameters
    };
    apply(adapter, "create-1", create_params())
        .await
        .expect("create commits");
    assert_eq!(
        apply(adapter, "create-2", create_params())
            .await
            .map(|_| ()),
        Err(StoreError::IdentityConflict),
        "double create fails closed"
    );
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_edit_params(
            "auto-1".to_owned(),
            "r-0".to_owned(),
            "r-2".to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&valid_revision(
                "auto-1",
                "r-2",
                UserAutomationConfigurationState::Active,
            )),
        ));
    assert_eq!(
        apply(adapter, "edit-stale", request.parameters)
            .await
            .map(|_| ()),
        Err(StoreError::IdentityConflict),
        "stale lineage base fails closed"
    );
    let (bogus_id, bogus) = invocation_for("auto-1", "r-9", "nonce-8");
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_run_now_params(
            "auto-1".to_owned(),
            "r-9".to_owned(),
            bogus_id,
            bogus,
        ));
    assert!(
        apply(adapter, "run-absent", request.parameters)
            .await
            .is_err(),
        "unknown revisions cannot be invoked"
    );
    let payload = read(adapter, "failure", Some("auto-1"), false).await;
    assert!(payload.get("failure").is_some_and(Value::is_null));
}

/// Canonical failure document for one failure class.
fn failure_json(fingerprint: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "fingerprint": fingerprint,
        "reason": "{\"CanonicalBlockedConfig\":{\"class\":\"provider-fingerprint\"}}",
        "notification_dedup_key": "caller-key",
    }))
    .expect("failure document serializes")
}

#[tokio::test]
async fn failure_leg_records_converges_and_projects_last() {
    let harness = Harness::fresh("failure").await;
    let adapter = harness.adapter();
    let fingerprint = "c".repeat(64);
    // Absence stays explicit before any failure write.
    let payload = read(adapter, "failure", Some("auto-1"), false).await;
    assert!(payload.get("failure").is_some_and(Value::is_null));
    // Unknown revisions fail closed.
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_failure_params(
            "auto-absent".to_owned(),
            "r-1".to_owned(),
            "occ-1".to_owned(),
            failure_json(&fingerprint),
        ));
    assert!(
        apply(adapter, "failure-absent", request.parameters)
            .await
            .is_err(),
        "unknown revision failures fail closed"
    );
    // Create the owning revision, then record the failure.
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_create_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&first),
        ));
    apply(adapter, "create-1", request.parameters)
        .await
        .expect("create commits");
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_failure_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            "occ-1".to_owned(),
            failure_json(&fingerprint),
        ));
    let receipt = apply(adapter, "failure-1", request.parameters)
        .await
        .expect("failure commits");
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    let payload = read(adapter, "failure", Some("auto-1"), false).await;
    let row = payload.get("failure").expect("failure row projects");
    assert_eq!(
        row.get("fingerprint").and_then(Value::as_str),
        Some(fingerprint.as_str())
    );
    assert_eq!(
        row.get("history_ref").and_then(Value::as_str),
        Some(format!("automation-failure:auto-1:r-1:{fingerprint}").as_str()),
    );
    assert_eq!(
        row.get("source_operation_id").and_then(Value::as_str),
        Some("op-automation-live-failure-1")
    );
    // A repeat of one failure class from another occurrence converges:
    // same reference, first-writer provenance kept.
    let request =
        eliot_store_api::automation_mutation_request(eliot_store_api::automation_failure_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            "occ-2".to_owned(),
            failure_json(&fingerprint),
        ));
    apply(adapter, "failure-2", request.parameters)
        .await
        .expect("repeat converges");
    let repeat = read(adapter, "failure", Some("auto-1"), false).await;
    assert_eq!(repeat.get("failure"), payload.get("failure"));
}
