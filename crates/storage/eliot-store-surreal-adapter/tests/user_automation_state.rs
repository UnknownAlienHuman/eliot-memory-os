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
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

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
        database: "automation_1779".to_owned(),
        username: "automation-test".to_owned(),
        password: SecretString::new("automation-test-secret".into()),
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
            "eliot-automation-1779-{}-{port}-{test}",
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
            "automation-state provider: exe={} sha256={} port={} root={}",
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
    let request = eliot_store_api::automation_read_request(
        query.to_owned(),
        automation_id.map(str::to_owned),
        include_retired,
        64,
        fence(),
    )
    .expect("read builds");
    eliot_store_api::CanonicalStoreClient::execute_named(adapter, request)
        .await
        .expect("read executes")
        .payload
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
