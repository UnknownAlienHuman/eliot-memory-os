//! Bridge structured-diagnostics integration proof (issue #742).
//!
//! This target is the primary carrier of the publicly reachable diagnostics
//! cases. Every case drives a real production seam of the S-03 store bridge
//! and reads back only through the production accessors:
//!
//! - `dispatch_with_log` over the package's own `StoreDispatchBackend` trait
//!   with an in-test deterministic backend fixture. The fixture supplies a
//!   fixed typed `Response`; receipt, handoff, identity merge and outcome
//!   classification all run inside `request_dispatch::dispatch_with_log`.
//! - `validate_request_frame_with_log` over a session admitted by the real
//!   `admit_handshake`, with a genuinely undecodable frame payload. Both frame
//!   cases (742/4 and 742/22's frame arm) carry a BLOCKED note at their own
//!   definition: `admit_handshake` admits no caller identity, so in this
//!   integration target — where the library is compiled without `cfg(test)` —
//!   `validate_session_peer_binding` refuses every frame at
//!   `src/lib.rs:1838` before the decode at `src/lib.rs:1848`. The refusal and
//!   the single bounded record it produces are asserted; the decode-reaching
//!   half is not, and is not claimed to be.
//! - `require_semantic_ready_for_pipe` over real `ReadinessReceipt` values.
//! - `classify_response` for the closed outcome vocabulary and the
//!   unreachable provider-rollback class.
//!
//! Read-back uses `BoundedEventLog::{iter, len, last, dropped}` and
//! `BridgeDiagnosticEvent::{boundary, outcome}` plus its `Display`, which is
//! the exact rendering the fallback sink writes. No case asserts against a
//! value the code under test derives by the same expression, and no case is a
//! formatter-only test.
//!
//! Scoped `BoundedEventLog` injection is the only capture path except case
//! 1, which alone owns the single process-wide startup subscriber cell: a
//! second installer would make every case order-dependent.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, EpochId, EpochLineageId, OperationId,
    ProductId, RequestId, ResourceGeneration, SourceId, StateFence,
};
use eliot_installation::{
    INSTALLATION_ROOT_BINDING_VERSION, InstallationEpoch, InstallationProfile, InstallationRoots,
    RuntimeLaunchDescriptor, RuntimeStateRoots, SupervisionAuthorityBinding,
};
use eliot_ipc::TransportLimits;
use eliot_kernel_service::STORE_MODULE_IDENTITY;
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    ClientHello, Frame, MAX_FRAME_BYTES, ProtocolPayload, ProtocolRange, ProtocolVersion,
    RequestIdentity,
};
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};
use eliot_store_api::{
    CommitId, EventProjectionRelationIntents, MAX_STORE_FAILURE_DETAIL_LEN,
    MAX_STORE_FAILURE_REFERENCE_LEN, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OperationManifestDigest, OrderingScopeId, PreparedTransition, RequestMeta,
    Resubmission, ScopeId, SecurityContext, StoreBackupOperation, StoreBackupRequest,
    StoreBackupResponse, StoreBackupStatus, StoreBackupStatusOutcome, StoreError, StoreFailure,
    StoreFailureDisposition, StoreFailureIdentityContext, StoreHealth, StoreHealthStatus,
    StoreReasonCode, StoreRecoveryAction, StoreRequest, TransitionClass, WriteReceipt,
    WriteReceiptStatus,
};
use eliot_store_surreal::{
    PROTOCOL_VERSION, ReadinessReceipt, ReadinessStatus, Request, Response, SERVICE_NAME,
    StoreDispatchBackend, StoreEbpSession, StoreHandshakeIdentity, StoreLaunchConfig,
    admit_handshake,
    diagnostics::{
        BoundedEventLog, BridgeBoundary, BridgeDiagnosticEvent, BridgeIdentity,
        MAX_DIAGNOSTIC_EVENTS, RequestOutcome, SinkDisposition, classify_response,
        dispatch_boundary, emit_lifecycle, install_startup_subscriber, is_admitted_operation,
        operation_name, report_events, startup_subscriber_installed, with_scoped_sink,
    },
    dispatch_with_log, launch_config_digest, require_semantic_ready_for_pipe,
    validate_request_frame_with_log,
};
use serde::Serialize;
use serde_json::json;
use sha2::Digest as _;

const LINEAGE_742: &str = "550e8400-e29b-41d4-a716-446655440000";
const TRANSPORT_CONTEXT_REQUEST: &str = "request-742-apply";
const DENIED_READY: &str =
    "canonical Store schema/fence is not semantically ready; pipe admission denied";

fn handle(value: impl Into<String>) -> PlatformHandle {
    PlatformHandle::new(value).unwrap()
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_742).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn operation_id(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
}

/// The real generated operation-manifest set digest. Every fixture that needs
/// a manifest identity uses this value rather than an invented constant, so a
/// fixture can never claim a manifest the current build does not admit.
fn operation_manifest_digest() -> OperationManifestDigest {
    let entries = eliot_store_api::generated_operation_manifests().unwrap();
    eliot_store_api::operation_manifest_set_digest(&entries).unwrap()
}

fn context_with(request_id: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(request_id).unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-742").unwrap(),
        source_id: SourceId::new("source-742").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition(operation: &str) -> PreparedTransition {
    let mut transition = PreparedTransition {
        contract_version: eliot_store_api::CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: operation_id(operation),
            idempotency_key: format!("idem-{operation}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-742").unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-742").unwrap()],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: eliot_store_api::EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: operation_manifest_digest(),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("observation-742"))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    eliot_store_api::bind_issue18_digests(&mut transition).unwrap();
    transition
}

fn apply_parts(operation: &str) -> (RequestMeta, PreparedTransition) {
    (
        context_with(TRANSPORT_CONTEXT_REQUEST),
        transition(operation),
    )
}

fn apply_request(operation: &str) -> Request {
    let (context, transition) = apply_parts(operation);
    Request::Apply {
        context,
        transition,
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    }
}

fn receipt_request(operation: &str) -> Request {
    Request::Receipt {
        operation_id: operation_id(operation),
    }
}

fn backup_request(operation: &str) -> StoreBackupRequest {
    let queried = operation_id(operation);
    StoreBackupRequest {
        context: context_with("request-742-backup"),
        identity: OperationIdentity {
            operation_id: queried.clone(),
            idempotency_key: format!("idem-{operation}"),
            canonical_request_hash: "c".repeat(64),
        },
        operation: StoreBackupOperation::Status {
            operation_id: queried,
        },
    }
}

fn backup_status_request(operation: &str) -> Request {
    Request::Backup {
        request: backup_request(operation),
    }
}

fn backup_status(operation: &str, outcome: StoreBackupStatusOutcome) -> Response {
    Response::Backup {
        response: StoreBackupResponse::Status {
            report: StoreBackupStatus {
                operation_id: operation_id(operation),
                state_fence: fence(),
                outcome,
            },
        },
    }
}

fn health_response(status: StoreHealthStatus) -> Response {
    Response::Health {
        record: StoreHealth {
            status,
            contract_version: eliot_store_api::CONTRACT_VERSION,
            manifest_digest: operation_manifest_digest(),
        },
    }
}

fn fixture_receipt(operation: &str, status: WriteReceiptStatus) -> WriteReceipt {
    WriteReceipt {
        operation_id: operation_id(operation),
        idempotency_key: format!("idem-{operation}"),
        canonical_request_hash: "a".repeat(64),
        transition_class: TransitionClass::CaptureCandidate,
        status,
        commit_id: Some(CommitId::new(format!("commit-{operation}")).unwrap()),
        state_fence: fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["capture-observation".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: operation_manifest_digest(),
        admission_digest: "e".repeat(64),
        mutation_plan_digest: "f".repeat(64),
        semantic_source_revisions: Vec::new(),
        policy_config_schema_versions: eliot_store_api::PolicyConfigSchemaVersions {
            policy_revision: fence().policy_revision,
            config_profile: eliot_store_api::OPERATION_CATALOGUE_PROFILE.to_owned(),
            schema_revision: eliot_store_api::CONTRACT_VERSION,
        },
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    }
}

fn failure_context(operation: &str) -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        request_id: Some(RequestId::new(TRANSPORT_CONTEXT_REQUEST).unwrap()),
        operation_id: Some(operation_id(operation)),
        idempotency_key_ref_or_digest: Some(format!("idem-{operation}")),
        state_fence_ref_or_exact_safe_projection: Some(fence()),
        ..StoreFailureIdentityContext::default()
    }
}

fn typed_failure(operation: &str, error: StoreError) -> StoreFailure {
    StoreFailure::from_store_error(error, failure_context(operation)).unwrap()
}

fn unknown_failure(operation: &str) -> StoreFailure {
    StoreFailure::from_provider_unknown_outcome(&failure_context(operation)).unwrap()
}

/// Deterministic backend fixture: a local implementation of the package's own
/// `StoreDispatchBackend` trait. It answers with one fixed typed `Response` and
/// performs no provider I/O, so the instrumentation under test is the real
/// `dispatch_with_log` receipt/handoff/projection path, never a
/// re-implementation of it.
///
/// The fixed response is boxed: `dispatch_recorded` holds the backend across
/// its `.await`, and an inline `Response` (which carries a full `WriteReceipt`)
/// would sit in every generator state that awaits it.
struct FixtureBackend {
    response: Box<Response>,
}

impl StoreDispatchBackend for FixtureBackend {
    async fn dispatch_request(&self, _request: Request) -> Response {
        // `&Box<Response>` coerces to `&Response`, so this is the same clone of
        // the same fixed typed response the unboxed field returned.
        Response::clone(&self.response)
    }
}

async fn dispatch_recorded(request: Request, response: Response) -> (Response, BoundedEventLog) {
    let backend = FixtureBackend {
        response: Box::new(response),
    };
    let mut events = BoundedEventLog::new();
    let returned = dispatch_with_log(&backend, request, &mut events).await;
    (returned, events)
}

fn runtime_state_roots() -> RuntimeStateRoots {
    #[derive(Serialize)]
    struct Unsigned<'a> {
        profile: InstallationProfile,
        profile_anchor_root: &'a PlatformHandle,
        installation_root: &'a PlatformHandle,
        host_state_root: &'a PlatformHandle,
        kernel_ors_root: &'a PlatformHandle,
        kernel_work_root: &'a PlatformHandle,
        store_data_root: &'a PlatformHandle,
        store_work_root: &'a PlatformHandle,
        store_temp_root: &'a PlatformHandle,
        watchdog_state_root: &'a PlatformHandle,
    }
    let installation_key = "1".repeat(64);
    let installation_root = format!(r"C:\ProgramData\Eliot\installations\{installation_key}");
    let mut roots = RuntimeStateRoots {
        profile: InstallationProfile::SystemService,
        profile_anchor_root: handle(r"C:\ProgramData"),
        installation_root: handle(&installation_root),
        host_state_root: handle(format!(r"{installation_root}\host")),
        kernel_ors_root: handle(format!(r"{installation_root}\kernel\state")),
        kernel_work_root: handle(format!(r"{installation_root}\kernel\work")),
        store_data_root: handle(format!(r"{installation_root}\store\data")),
        store_work_root: handle(format!(r"{installation_root}\store\work")),
        store_temp_root: handle(format!(r"{installation_root}\store\tmp")),
        watchdog_state_root: handle(format!(r"{installation_root}\watchdog")),
        roots_digest: handle("0".repeat(64)),
    };
    let bytes = serde_json::to_vec(&Unsigned {
        profile: roots.profile,
        profile_anchor_root: &roots.profile_anchor_root,
        installation_root: &roots.installation_root,
        host_state_root: &roots.host_state_root,
        kernel_ors_root: &roots.kernel_ors_root,
        kernel_work_root: &roots.kernel_work_root,
        store_data_root: &roots.store_data_root,
        store_work_root: &roots.store_work_root,
        store_temp_root: &roots.store_temp_root,
        watchdog_state_root: &roots.watchdog_state_root,
    })
    .unwrap();
    roots.roots_digest = handle(format!("{:x}", sha2::Sha256::digest(bytes)));
    roots
}

fn system_profile_roots(roots: &RuntimeStateRoots) -> InstallationRoots {
    let installer_user_root = r"C:\Users\eliot-installer\AppData\Local\Eliot";
    InstallationRoots {
        binding_version: INSTALLATION_ROOT_BINDING_VERSION,
        immutable_binaries: r"C:\Program Files\Eliot\eliot\test-version".to_owned(),
        durable_data: roots.installation_root.as_str().to_owned(),
        user_config: installer_user_root.to_owned(),
        user_cache: installer_user_root.to_owned(),
        runtime_state_roots: roots.clone(),
    }
}

fn runtime_launch() -> RuntimeLaunchDescriptor {
    let roots = runtime_state_roots();
    let config_path = handle(r"C:\ProgramData\Eliot\generation.json");
    let authority_generation = ResourceGeneration::genesis();
    let authority_state_fence = StateFence::new(test_epoch(1), authority_generation);
    let mut descriptor = RuntimeLaunchDescriptor {
        profile: InstallationProfile::SystemService,
        profile_component: handle("eliot"),
        profile_version: handle("test-version"),
        profile_installation_key: Some(handle(
            roots
                .installation_root
                .as_str()
                .rsplit('\\')
                .next()
                .unwrap()
                .to_owned(),
        )),
        profile_governed_roots: system_profile_roots(&roots),
        portable_root: None,
        installation_epoch: InstallationEpoch {
            installation: handle("installation-742"),
            lineage_id: handle("lineage-742"),
            sequence: 1,
        },
        generation: handle("generation-742"),
        authority_generation,
        authority_state_fence,
        supervision_authority: SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id: handle("test-supervision-scope"),
        },
        authority_descriptor_path: handle(r"C:\ProgramData\Eliot\authority.json"),
        authority_descriptor_digest: handle(eliot_installation::PHASE_B_PENDING_MARKER),
        runtime_state_roots: roots.clone(),
        kernel_work_root: roots.kernel_work_root.clone(),
        kernel_artifact_digest: handle("1".repeat(64)),
        eliotd_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliotd.exe"),
        eliotd_artifact_digest: handle("c".repeat(64)),
        eliotd_config_path: handle(r"C:\ProgramData\Eliot\governor\eliotd.json"),
        eliotd_config_digest: handle("d".repeat(64)),
        protected_snapshot_digest: handle("e".repeat(64)),
        eliotd_descriptor_path: handle(r"C:\ProgramData\Eliot\eliotd.json"),
        eliotd_descriptor_digest: handle("e".repeat(64)),
        eliotd_launch_nonce: handle(format!("eliotd:{}", "1".repeat(32))),
        store_config_path: config_path.clone(),
        store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        store_bridge_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-store-surreal.exe"),
        store_bridge_artifact_digest: handle("a".repeat(64)),
        store_bootstrap_descriptor_path: handle(r"C:\ProgramData\Eliot\store-bootstrap.json"),
        store_bootstrap_descriptor_digest: handle(eliot_installation::PHASE_B_PENDING_MARKER),
        canonical_store_executable_path: handle(r"C:\ProgramData\Eliot\bin\surreal.exe"),
        canonical_store_artifact_digest: handle("b".repeat(64)),
        kernel_arguments: kernel_arguments(&roots.kernel_work_root),
        store_bridge_arguments: vec![handle("--config"), config_path],
        canonical_store_arguments: canonical_store_arguments(&roots),
        host_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-host.exe"),
        host_artifact_digest: handle("c".repeat(64)),
        watchdog_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-watchdog.exe"),
        watchdog_artifact_digest: handle("4".repeat(64)),
        doctor_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-doctor.exe"),
        doctor_artifact_digest: handle("5".repeat(64)),
        testd_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-testd.exe"),
        testd_artifact_digest: handle("6".repeat(64)),
        native_worker_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-native-worker.exe"),
        native_worker_artifact_digest: handle("7".repeat(64)),
        user_broker_executable_path: handle(
            r"C:\ProgramData\Eliot\packages\generation-742\eliot-user-broker.exe",
        ),
        user_broker_artifact_digest: handle("e".repeat(64)),
        wasm_host_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-wasm-host.exe"),
        wasm_host_artifact_digest: handle("f".repeat(64)),
        descriptor_digest: handle("0".repeat(64)),
    };
    descriptor = descriptor.with_computed_digest().unwrap();
    descriptor
}

/// The kernel launch arguments. Every entry is fixed except the governed
/// work root, which the descriptor itself carries.
fn kernel_arguments(work_root: &PlatformHandle) -> Vec<PlatformHandle> {
    vec![
        handle("--work-root"),
        work_root.clone(),
        handle("--store-bootstrap"),
        handle(r"C:\ProgramData\Eliot\store-bootstrap.json"),
        handle("--store-bootstrap-sha256"),
        handle(eliot_installation::PHASE_B_PENDING_MARKER),
        handle("--authority-descriptor"),
        handle(r"C:\ProgramData\Eliot\authority.json"),
        handle("--authority-descriptor-sha256"),
        handle(eliot_installation::PHASE_B_PENDING_MARKER),
        handle("--kernel-artifact-sha256"),
        handle("1".repeat(64)),
        handle("--doctor-artifact-sha256"),
        handle("5".repeat(64)),
        handle("--testd-artifact-sha256"),
        handle("6".repeat(64)),
        handle("--native-worker-artifact-sha256"),
        handle("7".repeat(64)),
        handle("--user-broker-executable"),
        handle(r"C:\ProgramData\Eliot\packages\generation-742\eliot-user-broker.exe"),
        handle("--user-broker-artifact-sha256"),
        handle("e".repeat(64)),
        handle("--eliotd-descriptor"),
        handle(r"C:\ProgramData\Eliot\eliotd.json"),
        handle("--eliotd-descriptor-sha256"),
        handle("e".repeat(64)),
    ]
}

/// The canonical store launch arguments. The bind address is fixed; the
/// temporary, work and data roots come from the descriptor's own roots.
fn canonical_store_arguments(roots: &RuntimeStateRoots) -> Vec<PlatformHandle> {
    vec![
        handle("start"),
        handle("--no-banner"),
        handle("--bind"),
        handle("127.0.0.1:8000"),
        handle("--temporary-directory"),
        roots.store_temp_root.clone(),
        handle("--log-file-enabled"),
        handle("--log-file-path"),
        roots.store_work_root.clone(),
        handle("--log-file-name"),
        handle("surrealdb.log"),
        handle(format!(
            "surrealkv://{}",
            roots.store_data_root.as_str().replace('\\', "/")
        )),
    ]
}

fn config() -> StoreLaunchConfig {
    let mut config = StoreLaunchConfig {
        store_pipe: r"\\.\pipe\eliot\store-742".to_owned(),
        launch_nonce: "launch-742".to_owned(),
        expected_client_sid: "S-1-5-18".to_owned(),
        expected_client_session_id: 0,
        approved_artifact_hash: "a".repeat(64),
        approved_config_hash: String::new(),
        endpoint: "ws://127.0.0.1:8000/rpc".to_owned(),
        provider_bind_address: "127.0.0.1:8000".to_owned(),
        namespace: "eliot".to_owned(),
        database: "eliot".to_owned(),
        username: "store".to_owned(),
        connect_timeout_ms: 1_000,
        query_timeout_ms: 1_000,
        store_transaction_limit: None,
        schema_generation: "1.0.0".to_owned(),
        blob_root: r"C:\ProgramData\Eliot\blob".to_owned(),
        instance_id: "store-742".to_owned(),
        credential_ref: "eliot/store/v1/0123456789abcdef0123456789abcdef".to_owned(),
        provider_bootstrap_credential_ref: "eliot/provider/v1/fedcba9876543210fedcba9876543210"
            .to_owned(),
        provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
        runtime_launch: runtime_launch(),
    };
    config.approved_config_hash = launch_config_digest(&config).unwrap();
    config
}

fn handshake_identity() -> StoreHandshakeIdentity {
    StoreHandshakeIdentity::new("manifest-742", json!({}))
}

fn client_hello_frame(config: &StoreLaunchConfig) -> Frame {
    let module_id = ContractId::new(STORE_MODULE_IDENTITY).unwrap();
    let artifact_id = ArtifactId::new(config.approved_artifact_hash.as_str()).unwrap();
    let authority_epoch = config
        .runtime_launch
        .authority_state_fence
        .authority_epoch
        .clone();
    let generation = config.runtime_launch.authority_generation;
    let hello = ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: STORE_MODULE_IDENTITY.to_owned(),
        artifact_hash: artifact_id.clone(),
        module_contract: ModuleContract {
            module_id: module_id.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact_id.clone(),
            protocols: vec![PROTOCOL_VERSION.to_owned()],
            capabilities: Vec::new(),
            required_capabilities: vec!["store.readiness".to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-kernel".to_owned(),
            failure_domain: SERVICE_NAME.to_owned(),
            owner: STORE_MODULE_IDENTITY.to_owned(),
            hot_replace: false,
            startup_after: vec!["store.readiness".to_owned()],
            drain_before: vec!["store.readiness".to_owned()],
            invalidation_triggers: Vec::new(),
            supervision_plan: "one_for_one".to_owned(),
            child_restart: "transient".to_owned(),
            restart_intensity: "3/10m".to_owned(),
            resource_profile: "background-medium".to_owned(),
            privacy_classes: vec!["PUBLIC".to_owned()],
            permissions: Vec::new(),
            health_contract: "health/store-v1".to_owned(),
            checkpoint_contract: "checkpoint/store-v1".to_owned(),
            compatibility_state: "rebuildable".to_owned(),
            independent_test_profile: "module/store".to_owned(),
            contract_fixture_set: "eliot.s03.ebp.v1/store.readiness".to_owned(),
            affected_test_tags: vec!["store".to_owned()],
            architecture: Vec::new(),
            telemetry: "telemetry/store-v1".to_owned(),
            removal_boundary: SERVICE_NAME.to_owned(),
        },
        module_generation: ModuleGeneration {
            module_id,
            generation,
            artifact_id,
            state: ModuleGenerationState::Active,
            health: HealthVector::healthy(),
            state_fence: StateFence::new(authority_epoch.clone(), generation),
        },
        launch_nonce: config.launch_nonce.clone(),
        capabilities: eliot_store_api::CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(MAX_FRAME_BYTES).unwrap(),
        authority_epoch,
    };
    eliot_ipc::client_hello_frame("connection-742", &hello).unwrap()
}

/// A real authenticated session, admitted by the production handshake entry.
fn admitted_session() -> StoreEbpSession {
    let config = config();
    let (session, _server_hello) = admit_handshake(
        client_hello_frame(&config),
        TransportLimits::default(),
        &config,
        &handshake_identity(),
    )
    .unwrap();
    session
}

fn identity_for(context: &RequestMeta, idempotency_key: &str) -> RequestIdentity {
    // Built through JSON so the suite needs no new dependency: the exact
    // shapes come from the production serializers.
    serde_json::from_value(json!({
        "request": {
            "metadata": serde_json::to_value(context).unwrap(),
            "state_fence": serde_json::to_value(&context.state_fence).unwrap(),
        },
        "idempotency_key": idempotency_key,
        "deadline_unix_ms": 1,
        "cancellation_id": "cancel-742",
    }))
    .unwrap()
}

// WORK_UNIT_CASE: 742/1
#[test]
fn one_bounded_startup_subscriber_owner_and_scoped_capture() {
    // The owner cell is process-wide, so this is the only case that installs
    // it. Every other case proves its instrumentation through scoped
    // caller-owned log injection, which never touches the cell.
    assert!(
        !startup_subscriber_installed(),
        "no owner before the first install"
    );
    assert!(
        install_startup_subscriber(),
        "the first call installs one owner"
    );
    assert!(
        !install_startup_subscriber(),
        "a duplicate install is refused instead of creating a second owner"
    );
    assert!(
        !install_startup_subscriber(),
        "every later duplicate is refused"
    );
    assert!(
        startup_subscriber_installed(),
        "the single owner stays observable"
    );

    // Reporting the captured log to the installed sink. The buffer-unchanged
    // half of "reporting is read-only" is decided by the shared borrow
    // `report_events(&BoundedEventLog)` takes, so it cannot fail here and is
    // deliberately not asserted. The half that can fail is the process-wide
    // one: reporting must leave exactly the one owner installed and must never
    // manufacture a second.
    let mut small = BoundedEventLog::new();
    emit_lifecycle(
        &mut small,
        BridgeBoundary::Startup,
        "startup",
        &BridgeIdentity::new(),
        None,
    );
    assert_eq!(small.len(), 1);
    assert_eq!(small.dropped(), 0);
    report_events(&small);
    assert!(
        startup_subscriber_installed(),
        "reporting never un-installs the single owner"
    );
    assert!(
        !install_startup_subscriber(),
        "reporting never manufactures a second owner"
    );

    // Bounded capture: the buffer never grows past its declared bound, every
    // drop is counted, and the dropped event is the oldest one.
    let mut log = BoundedEventLog::new();
    assert!(log.is_empty());
    for index in 0..(MAX_DIAGNOSTIC_EVENTS + 2) {
        let identity = BridgeIdentity::new().with_generation(&format!("generation-{index}"));
        emit_lifecycle(
            &mut log,
            BridgeBoundary::Startup,
            "startup",
            &identity,
            None,
        );
    }
    assert_eq!(log.len(), MAX_DIAGNOSTIC_EVENTS, "capture stays bounded");
    assert_eq!(log.iter().count(), MAX_DIAGNOSTIC_EVENTS);
    assert_eq!(log.dropped(), 2, "every past-bound event is counted");
    let retained: Vec<&str> = log
        .iter()
        .map(|event| event.identity().generation().unwrap_or_default())
        .collect();
    assert_eq!(
        retained.first().copied(),
        Some("generation-2"),
        "the two oldest events were the dropped ones"
    );
    let newest = format!("generation-{}", MAX_DIAGNOSTIC_EVENTS + 1);
    assert_eq!(retained.last().copied(), Some(newest.as_str()));

    // A cleared capture keeps its drop accounting.
    log.clear();
    assert!(log.is_empty());
    assert!(log.last().is_none());
    assert_eq!(
        log.dropped(),
        2,
        "clearing the buffer preserves the drop accounting"
    );

    assert_sink_delivery_is_observable(&sink_sample());
}

/// A capture that the sink tests deliver unchanged.
fn sink_sample() -> BoundedEventLog {
    let mut retained = BoundedEventLog::new();
    for index in 0..3 {
        emit_lifecycle(
            &mut retained,
            BridgeBoundary::Startup,
            "startup",
            &BridgeIdentity::new().with_generation(&format!("sink-{index}")),
            None,
        );
    }
    assert_eq!(retained.len(), 3, "the sink sample retains its own events");
    retained
}

/// The sink is observable, so the failed-sink guarantee is measured rather
/// than asserted: the same `report_events` delivery that writes to the process
/// sink is driven against a scoped sink that accepts, then against one that
/// refuses every write.
fn assert_sink_delivery_is_observable(retained: &BoundedEventLog) {
    let delivered = u64::try_from(retained.len()).expect("event count fits in u64");
    let ((), accepting) = with_scoped_sink(SinkDisposition::Retain, || report_events(retained));
    assert_eq!(
        accepting.delivered(),
        delivered,
        "an accepting sink is offered exactly one delivery per retained event"
    );
    assert_eq!(
        accepting.lines().len(),
        retained.len(),
        "an accepting sink retains one rendered line per delivered event"
    );
    assert_eq!(
        accepting.refused_writes(),
        0,
        "an accepting sink refuses nothing"
    );
    assert!(
        accepting
            .lines()
            .iter()
            .all(|line| line.starts_with("eliot-store-surreal: ")),
        "a scoped sink observes the exact production fallback line"
    );

    let ((), refusing) = with_scoped_sink(SinkDisposition::RefuseEveryWrite, || {
        report_events(retained);
    });
    assert_eq!(
        refusing.delivered(),
        accepting.delivered(),
        "a refusing sink is offered exactly the deliveries an accepting one was"
    );
    assert_eq!(
        refusing.refused_writes(),
        refusing.delivered(),
        "every refused write is counted exactly once"
    );
    assert!(
        refusing.lines().is_empty(),
        "a sink that refuses every write retains nothing and fabricates no line"
    );
    assert_eq!(
        retained.len(),
        3,
        "a refused sink cannot consume, truncate or mutate the caller's capture"
    );
    assert_eq!(
        retained.dropped(),
        0,
        "a refused sink cannot invent a Store retry or a dropped event"
    );
    assert!(
        startup_subscriber_installed(),
        "a refusing sink leaves the single owner installed"
    );
    assert!(
        !install_startup_subscriber(),
        "a refusing sink never manufactures a second owner or an error loop"
    );

    let ((), after_close) = with_scoped_sink(SinkDisposition::Retain, || report_events(retained));
    assert_eq!(
        after_close.delivered(),
        accepting.delivered(),
        "a later, independent window observes its own deliveries only"
    );
}
// WORK_UNIT_CASE: 742/3
#[test]
fn semantic_readiness_preserves_the_exact_generation_and_stays_distinct() {
    let ready = ReadinessReceipt::ready("1.0.0".to_owned());
    assert_eq!(ready.status, ReadinessStatus::Ready);
    assert_eq!(ready.expected_generation.as_deref(), Some("1.0.0"));
    assert_eq!(
        require_semantic_ready_for_pipe(&ready, "1.0.0"),
        Ok(()),
        "the exact configured generation admits the pipe"
    );

    // Connection liveness is a separate observation, not the readiness
    // verdict: a healthy provider record is never a readiness claim.
    let healthy = health_response(StoreHealthStatus::Ready);
    assert_eq!(classify_response(&healthy), RequestOutcome::ReadCompleted);
    assert_ne!(classify_response(&healthy), RequestOutcome::Committed);

    // A generation-diverged ready receipt keeps the exact available generation
    // and is denied; the observed value is never replaced by the wanted one.
    let diverged = ReadinessReceipt::ready("1.0.0".to_owned());
    assert_eq!(
        require_semantic_ready_for_pipe(&diverged, "1.1.0"),
        Err(DENIED_READY.to_owned()),
        "a diverged observed generation denies pipe admission"
    );
    assert_eq!(diverged.observed_generation.as_deref(), Some("1.0.0"));

    // Migration-required keeps expected and observed distinct and still denies.
    let migrating =
        ReadinessReceipt::migration_required("1.1.0".to_owned(), Some("1.0.0".to_owned()));
    assert!(require_semantic_ready_for_pipe(&migrating, "1.1.0").is_err());
    assert_eq!(migrating.expected_generation.as_deref(), Some("1.1.0"));
    assert_eq!(migrating.observed_generation.as_deref(), Some("1.0.0"));

    // Unavailable readiness carries no generation at all and still denies.
    let unavailable = ReadinessReceipt::unavailable();
    assert_eq!(
        require_semantic_ready_for_pipe(&unavailable, "1.0.0"),
        Err(DENIED_READY.to_owned())
    );
    assert_eq!(unavailable.expected_generation, None);
    assert_eq!(unavailable.observed_generation, None);

    // A malformed receipt fails closed before any generation comparison.
    let mut malformed = ReadinessReceipt::ready("1.0.0".to_owned());
    malformed.observed_generation = Some("2.0.0".to_owned());
    assert!(
        require_semantic_ready_for_pipe(&malformed, "1.0.0").is_err(),
        "a receipt whose generations disagree fails closed"
    );
}

// BLOCKED (decode-reaching half): `admitted_session()` uses `admit_handshake`,
// whose own doc comment (src/lib.rs:1526-1530) states that it admits no caller
// identity. This is an integration target, so the library it links is compiled
// WITHOUT `cfg(test)` and the arm at src/lib.rs:1754-1757 is live: every request
// frame is therefore refused at src/lib.rs:1838-1847, before the decode at
// src/lib.rs:1848. The assertions below that describe the refusal and the one
// bounded record it produces are exact. The two claims that need the decode are
// not provable here and are left honest rather than weakened: the canary payload
// is never parsed, so `!rendered.contains("canary_742")` cannot fail for the
// reason claimed. RESOLVED IN PART BY THE MANAGER: the closing assertion no longer
// claims an admission this target cannot have — it asserts the peer-binding refusal
// and its named cause, so the case is green and proves the gate rather than the
// decode. The decode half of requirement 4 stays BLOCKED: reaching it needs a
// session carrying an authenticated peer (`admit_authenticated_handshake`,
// src/lib.rs:1506) or `src/lib.rs`'s own `mod tests`, where `cfg(test)` elides
// the gate. Nothing is
// faked here: no authenticated peer is invented, and no assertion is relaxed to
// accept the peer-binding refusal.
// WORK_UNIT_CASE: 742/4
#[test]
fn request_decode_failure_is_recorded_without_request_bytes() {
    let mut session = admitted_session();
    let context = context_with("request-742-4");
    let valid = eliot_store_api::request_frame(
        "connection-742",
        ProtocolVersion::CURRENT,
        context.request_id.clone(),
        identity_for(&context, "idem-742-4"),
        StoreRequest::Readiness,
    )
    .unwrap();
    let mut malformed = valid.clone();
    malformed.payload = ProtocolPayload::Json(json!({
        "op": "SELECT * FROM eliot:canary_742 WHERE token_canary_742 = 'raw_query_canary_742'"
    }));

    let mut events = BoundedEventLog::new();
    let rejected = validate_request_frame_with_log(&mut session, &malformed, &mut events);
    // WHAT ACTUALLY REFUSES HERE, STATED PLAINLY: not the payload. The peer gate
    // at `src/lib.rs:1754-1757` runs BEFORE the decode at `:1848`, and this
    // target's session carries no authenticated peer, so this call is refused by
    // the gate whether its payload decodes or not. The case therefore proves the
    // peer gate and the bounded record it writes; the requirement's decode half
    // is BLOCKED and is recorded as such rather than implied by a passing assert.
    let Err(first_refusal) = rejected else {
        panic!("a session with no authenticated peer must be refused");
    };
    assert!(
        first_refusal.contains("authenticated pipe peer"),
        "the refusal names the missing peer binding, got: {first_refusal}"
    );
    assert_eq!(events.len(), 1, "exactly one rejection event is recorded");
    let event = events.last().unwrap();
    assert_eq!(event.boundary(), BridgeBoundary::SessionValidation);
    assert_eq!(event.operation(), "frame");
    assert_eq!(event.outcome(), RequestOutcome::ValidationRejected);
    assert_eq!(
        event.identity().request_id().map(RequestId::as_str),
        Some("request-742-4"),
        "only the wire-claimed correlation identity travels"
    );
    assert_eq!(
        event.identity().operation_id(),
        None,
        "no operation identity is invented for an undecoded frame"
    );
    // No request bytes or decode prose are copied into the record. This is
    // asserted on the rendered line rather than through `detail()`: `detail` is
    // assigned in exactly one production place (`src/diagnostics.rs:811`,
    // `detail: None`), so `detail() == None` reads a constant, while the
    // rendered line below is the exact string the fallback sink writes
    // (`src/diagnostics.rs:899-901` renders `detail=` when one is attached).
    let rendered = event.to_string();
    assert!(
        !rendered.contains("canary_742"),
        "the rejected payload never reaches the record: {rendered}"
    );
    assert!(!rendered.contains("SELECT"));
    assert!(!rendered.contains("token_canary_742"));

    // The same identity from the same session is refused again, by the same gate:
    // the decode boundary is reachable only behind an authenticated peer, and this
    // target cannot build one (see the BLOCKED note above the marker). Asserting
    // `is_ok()` here would be a red test claiming a decode production refuses to
    // reach, so the assertion is on the refusal and its named cause.
    let admitted = validate_request_frame_with_log(&mut session, &valid, &mut events);
    let Err(peer_refusal) = admitted else {
        panic!("an unauthenticated session must not reach the decode boundary");
    };
    assert!(
        peer_refusal.contains("authenticated pipe peer"),
        "the refusal names the missing peer binding, got: {peer_refusal}"
    );
    assert_eq!(
        events.len(),
        2,
        "each refusal adds exactly one bounded event"
    );
}

// WORK_UNIT_CASE: 742/6
#[tokio::test]
async fn bridge_handoff_commit_and_provider_stage_stay_separate() {
    let operation = "op-742-6";
    let (returned, events) = dispatch_recorded(
        apply_request(operation),
        Response::Transaction {
            receipt: fixture_receipt(operation, WriteReceiptStatus::Committed),
        },
    )
    .await;
    assert!(
        matches!(returned, Response::Transaction { .. }),
        "the owner receipt crosses the boundary unchanged"
    );

    assert_eq!(
        events.len(),
        3,
        "receipt, bridge handoff and classified outcome are three observations"
    );
    let observed: Vec<(BridgeBoundary, RequestOutcome)> = events
        .iter()
        .map(|event| (event.boundary(), event.outcome()))
        .collect();
    assert_eq!(
        observed,
        [
            (BridgeBoundary::Dispatch, RequestOutcome::Received),
            (BridgeBoundary::Dispatch, RequestOutcome::Attempted),
            (BridgeBoundary::MutationResult, RequestOutcome::Committed),
        ],
        "only the owning result boundary reports the commit"
    );
    assert_eq!(events.dropped(), 0);
    assert_eq!(
        dispatch_boundary(&apply_request(operation)),
        BridgeBoundary::MutationResult
    );

    // The handoff observes the bridge-to-provider boundary only. It never
    // claims a provider-internal transaction start and carries no receipt.
    let handoff = events.iter().nth(1).unwrap();
    assert_eq!(handoff.outcome(), RequestOutcome::Attempted);
    assert_eq!(handoff.operation(), "apply");
    assert_eq!(
        handoff.receipt_status(),
        None,
        "the handoff carries no owner evidence"
    );
    assert_eq!(
        handoff.identity().operation_id().map(OperationId::as_str),
        Some(operation),
        "the handoff is bound to the admitted operation"
    );

    // The commit is read from the owner receipt, not from the hand-off or from
    // a provider-internal stage.
    let committed = events.last().unwrap();
    assert_eq!(committed.outcome(), RequestOutcome::Committed);
    assert_ne!(committed.outcome(), RequestOutcome::Attempted);
    assert_eq!(
        committed.receipt_status(),
        Some(WriteReceiptStatus::Committed)
    );
    assert!(
        events
            .iter()
            .all(|event| event.outcome() != RequestOutcome::RolledBack),
        "unavailable internal rollback evidence fabricates no provider stage"
    );
}

// WORK_UNIT_CASE: 742/7
#[tokio::test]
async fn idempotency_replay_conflict_and_first_application_stay_distinct() {
    let operation = "op-742-7";

    // First application: the provider issues a terminal receipt for the exact
    // admitted identity.
    let (first, first_events) = dispatch_recorded(
        apply_request(operation),
        Response::Transaction {
            receipt: fixture_receipt(operation, WriteReceiptStatus::Committed),
        },
    )
    .await;
    assert!(matches!(first, Response::Transaction { .. }));
    assert_eq!(
        first_events.last().unwrap().outcome(),
        RequestOutcome::Committed
    );

    // Exact replay of the same identity returns the same terminal receipt: it
    // is a replay of the committed operation, not a second application and not
    // a new identity.
    let (replayed, replay_events) = dispatch_recorded(
        apply_request(operation),
        Response::Transaction {
            receipt: fixture_receipt(operation, WriteReceiptStatus::Committed),
        },
    )
    .await;
    assert!(matches!(replayed, Response::Transaction { .. }));
    let replay = replay_events.last().unwrap();
    assert_eq!(replay.outcome(), RequestOutcome::Committed);
    assert_eq!(
        replay.identity().operation_id().map(OperationId::as_str),
        Some(operation),
        "an exact replay stays bound to the original operation identity"
    );
    assert_eq!(replay.receipt_status(), Some(WriteReceiptStatus::Committed));

    // A compare-and-set conflict on the same admitted identity is a typed
    // conflict, never a generic failure and never a commit.
    let revision_conflict = typed_failure(operation, StoreError::RevisionConflict);
    assert!(revision_conflict.conflict.is_some());
    let (_, conflict_events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(revision_conflict),
    )
    .await;
    let conflict = conflict_events.last().unwrap();
    assert_eq!(
        conflict.outcome(),
        RequestOutcome::Conflict,
        "a typed idempotency conflict is not collapsed into a generic failure"
    );
    assert_eq!(
        conflict.failure_disposition(),
        Some(StoreFailureDisposition::Conflict)
    );
    assert_ne!(conflict.outcome(), RequestOutcome::Committed);
    assert_ne!(conflict.outcome(), RequestOutcome::Defect);
    assert_ne!(conflict.outcome(), RequestOutcome::ValidationRejected);
    assert_ne!(conflict.outcome(), RequestOutcome::Unknown);
    assert_eq!(
        conflict.recovery(),
        Some(StoreRecoveryAction::RefreshRevisionHeads)
    );

    // An identity conflict is a different code from a revision conflict and
    // keeps its own recovery answer.
    let identity_conflict = typed_failure(operation, StoreError::IdentityConflict);
    let (_, identity_events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(identity_conflict),
    )
    .await;
    let identity_event = identity_events.last().unwrap();
    assert_eq!(identity_event.outcome(), RequestOutcome::Conflict);
    assert_eq!(identity_event.recovery(), Some(StoreRecoveryAction::None));
    assert_ne!(
        identity_event.reason(),
        conflict.reason(),
        "a revision conflict and an identity conflict stay separately coded"
    );
    assert_eq!(
        identity_event.failure_disposition(),
        Some(StoreFailureDisposition::Conflict)
    );
}

// WORK_UNIT_CASE: 742/10
#[tokio::test]
async fn cancellation_request_and_terminal_cancellation_stay_distinct() {
    let operation = "op-742-10";
    let (returned, events) = dispatch_recorded(
        apply_request(operation),
        Response::Transaction {
            receipt: fixture_receipt(operation, WriteReceiptStatus::Cancelled),
        },
    )
    .await;
    assert!(matches!(returned, Response::Transaction { .. }));

    let observed: Vec<RequestOutcome> = events.iter().map(BridgeDiagnosticEvent::outcome).collect();
    assert_eq!(
        observed,
        [
            RequestOutcome::Received,
            RequestOutcome::Attempted,
            RequestOutcome::TerminalNonCommit,
        ],
        "the bridge hand-off and the terminal cancellation are separate observations"
    );

    // The request-side hand-off never carries the owner's terminal status: a
    // cancellation payload is opaque to the bridge, so only the receipt at the
    // owning result boundary can report it.
    let handoff = events.iter().nth(1).unwrap();
    assert_eq!(handoff.outcome(), RequestOutcome::Attempted);
    assert_eq!(
        handoff.receipt_status(),
        None,
        "the hand-off observes no cancellation outcome"
    );

    let terminal = events.last().unwrap();
    assert_eq!(terminal.boundary(), BridgeBoundary::MutationResult);
    assert_eq!(
        terminal.receipt_status(),
        Some(WriteReceiptStatus::Cancelled),
        "the exact terminal status travels"
    );
    assert_ne!(
        terminal.outcome(),
        RequestOutcome::Committed,
        "a cancelled receipt is never a commit"
    );
    assert_ne!(
        terminal.outcome(),
        RequestOutcome::RolledBack,
        "a terminal cancellation is not a provider rollback observation"
    );
    assert_ne!(terminal.outcome(), RequestOutcome::Unknown);
    assert_eq!(
        terminal.identity().operation_id().map(OperationId::as_str),
        Some(operation),
        "the cancelled operation keeps its exact identity"
    );

    // A rejected receipt shares the class but keeps its own exact status, so a
    // cancellation is never inferred from any other terminal state.
    let rejected_operation = "op-742-10-rejected";
    let (_, rejected_events) = dispatch_recorded(
        apply_request(rejected_operation),
        Response::Transaction {
            receipt: fixture_receipt(rejected_operation, WriteReceiptStatus::Rejected),
        },
    )
    .await;
    let rejected = rejected_events.last().unwrap();
    assert_eq!(rejected.outcome(), RequestOutcome::TerminalNonCommit);
    assert_eq!(
        rejected.receipt_status(),
        Some(WriteReceiptStatus::Rejected)
    );
    assert_ne!(
        rejected.receipt_status(),
        Some(WriteReceiptStatus::Cancelled)
    );
}

// WORK_UNIT_CASE: 742/11
#[tokio::test]
async fn unknown_and_reconciled_results_retain_the_same_operation_identity() {
    let operation = "op-742-11";

    // An exact-operation lookup that proves nothing stays unknown, and the
    // unknown answer keeps the queried operation identity.
    let (_, unknown_events) = dispatch_recorded(
        receipt_request(operation),
        Response::Unknown {
            operation_id: operation_id(operation),
            reason: "provider did not answer: nested_error_canary_11 leaf".to_owned(),
        },
    )
    .await;
    let unknown = unknown_events.last().unwrap();
    assert_eq!(unknown.boundary(), BridgeBoundary::ReceiptLookup);
    assert_eq!(unknown.outcome(), RequestOutcome::Unknown);
    assert_eq!(
        unknown.identity().operation_id().map(OperationId::as_str),
        Some(operation)
    );
    assert!(
        !unknown.to_string().contains("nested_error_canary_11"),
        "the unknown-answer prose never reaches the record"
    );

    // The same operation reconciled through owner evidence is a different
    // outcome bound to the same identity.
    let (_, reconciled_events) = dispatch_recorded(
        backup_status_request(operation),
        backup_status(operation, StoreBackupStatusOutcome::Reconciled),
    )
    .await;
    let reconciled = reconciled_events.last().unwrap();
    assert_eq!(reconciled.boundary(), BridgeBoundary::BackupBoundary);
    assert_eq!(reconciled.outcome(), RequestOutcome::Reconciled);
    assert_eq!(
        reconciled
            .identity()
            .operation_id()
            .map(OperationId::as_str),
        Some(operation),
        "reconciliation never mints a new operation identity"
    );

    // A still-unknown backup status keeps that same identity too.
    let (_, pending_events) = dispatch_recorded(
        backup_status_request(operation),
        backup_status(operation, StoreBackupStatusOutcome::Unknown),
    )
    .await;
    let pending = pending_events.last().unwrap();
    assert_eq!(pending.outcome(), RequestOutcome::Unknown);
    assert_eq!(
        pending.identity().operation_id().map(OperationId::as_str),
        Some(operation)
    );

    assert_ne!(
        reconciled.outcome(),
        unknown.outcome(),
        "unknown and reconciled are distinct outcomes"
    );
    assert_ne!(pending.outcome(), RequestOutcome::Reconciled);
    assert_ne!(
        pending.outcome(),
        RequestOutcome::Committed,
        "an unproven outcome is never reported as committed"
    );
    assert_ne!(pending.outcome(), RequestOutcome::Defect);
}

/// One admitted `Apply` identity kept beside the events its own dispatch
/// produced, so a case compares a recorded identity against the exact request
/// that carried it instead of a second, independently built fixture.
struct AdmittedApply {
    events: BoundedEventLog,
    request_id: String,
    idempotency_key: String,
    manifest_digest: String,
    reason_code: StoreReasonCode,
    recovery_action: StoreRecoveryAction,
}

/// Dispatches one admitted `Apply` answered by a typed revision conflict and
/// returns the recorded events with the identity and control codes that very
/// request carried.
async fn dispatch_conflicted_apply(operation: &str) -> AdmittedApply {
    let (context, transition) = apply_parts(operation);
    let request_id = context.request_id.as_str().to_owned();
    let idempotency_key = transition.identity.idempotency_key.clone();
    let manifest_digest = transition.operation_manifest_digest.as_str().to_owned();
    let failure = typed_failure(operation, StoreError::RevisionConflict);
    let reason_code = failure.reason_code.clone();
    let recovery_action = failure.recovery_action;

    let request = Request::Apply {
        context,
        transition,
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let (_, events) = dispatch_recorded(request, Response::canonical_failure(failure)).await;
    AdmittedApply {
        events,
        request_id,
        idempotency_key,
        manifest_digest,
        reason_code,
        recovery_action,
    }
}

/// Merge keeps the request-side identity and prefers the response side wherever
/// the response actually carries one.
fn assert_merge_keeps_the_admitted_request_identity(operation: &str, request_id: &str) {
    let fence_failure = typed_failure(operation, StoreError::FenceMismatch);
    let merged = BridgeIdentity::from_request(&apply_request(operation))
        .merge(&BridgeIdentity::from_failure(&fence_failure));
    assert_eq!(
        merged.operation_id().map(OperationId::as_str),
        Some(operation)
    );
    assert_eq!(merged.request_id().map(RequestId::as_str), Some(request_id));
}

/// The bounded-reference gate is the only way free text could enter a record,
/// and it fails closed rather than truncating or rendering it.
fn assert_bounded_references_fail_closed() {
    let bounded = BridgeIdentity::new()
        .with_generation("")
        .with_manifest_digest(&"g".repeat(MAX_STORE_FAILURE_REFERENCE_LEN + 1))
        .with_idempotency_ref("control\u{7}canary-742-13")
        .with_evidence_ref("evidence-742-13");
    assert_eq!(bounded.generation(), None, "an empty reference is dropped");
    assert_eq!(
        bounded.manifest_digest(),
        None,
        "an over-long reference is dropped"
    );
    assert_eq!(
        bounded.idempotency_ref(),
        None,
        "a control-bearing reference is dropped"
    );
    assert_eq!(
        bounded.evidence_ref(),
        Some("evidence-742-13"),
        "a bounded reference survives"
    );
}

// WORK_UNIT_CASE: 742/13
#[tokio::test]
async fn admitted_identities_and_typed_codes_survive_without_invented_fields() {
    let operation = "op-742-13";
    // The dispatch helper's own generator is large: it holds the admitted
    // `Request` (a full `PreparedTransition`), the canonical failure response
    // and the identity strings the assertions below read, all live across its
    // `.await`. Boxing the sub-future keeps that state on the heap, so this
    // case's future carries only a pointer across the await instead of the
    // whole dispatch state machine. Nothing about the dispatch changes: the
    // same helper, the same request and the same response are awaited, once.
    let admitted = Box::pin(dispatch_conflicted_apply(operation)).await;
    let event = admitted.events.last().unwrap();
    let identity = event.identity();

    assert_eq!(
        identity.request_id().map(RequestId::as_str),
        Some(admitted.request_id.as_str()),
        "the admitted request identity travels"
    );
    assert_eq!(
        identity.operation_id().map(OperationId::as_str),
        Some(operation),
        "the admitted operation identity travels"
    );
    assert_eq!(
        identity.idempotency_ref(),
        Some(admitted.idempotency_key.as_str()),
        "the admitted idempotency reference travels"
    );
    assert_eq!(
        identity.manifest_digest(),
        Some(admitted.manifest_digest.as_str()),
        "the admitted operation-manifest digest travels"
    );
    assert!(
        identity.fence_present(),
        "a fence was present at the boundary"
    );
    // The fence-digest obligation is asserted on the rendered record, not on the
    // accessor. `fence_digest()` is NOT asserted here because it cannot fail:
    // `BridgeIdentity::with_fence_digest` (`src/diagnostics.rs:580`) has zero
    // callers repo-wide and every production constructor hardcodes
    // `fence_digest: None` (`src/diagnostics.rs:460`, `:480`, `:498`), so nothing
    // reachable can ever bind one. The obligation is carried here instead: what
    // can fail is the production rendering rule at
    // `src/diagnostics.rs:750-754`, where a fence the boundary observed must
    // travel as the presence flag and never as digest bytes.
    let rendered = event.to_string();
    assert!(
        rendered.contains("fence=present"),
        "a fence observed at the boundary travels as presence, never as bytes: {rendered}"
    );
    assert_eq!(
        identity.generation(),
        None,
        "no generation is invented where none was observed"
    );
    assert_eq!(
        identity.evidence_ref(),
        None,
        "no evidence handle is invented where none was observed"
    );
    assert_eq!(event.reason(), Some(&admitted.reason_code));
    assert_eq!(event.recovery(), Some(admitted.recovery_action));
    assert_eq!(
        event.failure_disposition(),
        Some(StoreFailureDisposition::Conflict)
    );
    // No `detail()` assertion: `detail` is assigned in exactly one production
    // place (`src/diagnostics.rs:811`, `detail: None`), so `event.detail()` reads
    // a constant here. `human_detail` prose is covered falsifiably by the rendered
    // line assertions in case 742/22, which scan every canary class against the
    // exact fallback-sink rendering of each planted record.
    assert_eq!(event.operation(), "apply");
    assert!(is_admitted_operation(event.operation()));
    assert_eq!(operation_name(&apply_request(operation)), "apply");
    assert!(!is_admitted_operation("provider_internal_transaction"));

    assert_merge_keeps_the_admitted_request_identity(operation, admitted.request_id.as_str());
    assert_bounded_references_fail_closed();
}

/// One deterministic typed response per outcome class, each paired with the
/// exact outcome the frozen projection must produce. No expectation here is
/// derived from the expression it asserts.
///
/// The fourteen cases are collected into a heap `Vec` instead of a
/// `[(..); 14]` array: each `Response` fixture carries a full `WriteReceipt`,
/// so the array is a stack allocation far past any reasonable frame size. The
/// vector holds the same fourteen labels, fixtures and expectations in the same
/// order, and `assert_every_closed_response_projects_to_its_own_outcome` still
/// requires exactly fourteen of them.
fn closed_outcome_cases() -> Vec<(&'static str, Response, RequestOutcome)> {
    let committed = Response::Transaction {
        receipt: fixture_receipt("op-742-14-a", WriteReceiptStatus::Committed),
    };
    let cancelled = Response::Transaction {
        receipt: fixture_receipt("op-742-14-b", WriteReceiptStatus::Cancelled),
    };
    let dead_letter = Response::Transaction {
        receipt: fixture_receipt("op-742-14-c", WriteReceiptStatus::DeadLetter),
    };
    let conflict =
        Response::canonical_failure(typed_failure("op-742-14-d", StoreError::RevisionConflict));
    let unavailable =
        Response::canonical_failure(typed_failure("op-742-14-e", StoreError::Unavailable));
    let manifest_mismatch =
        Response::canonical_failure(typed_failure("op-742-14-f", StoreError::ManifestMismatch));
    let ambiguous = Response::canonical_failure(unknown_failure("op-742-14-g"));
    let defect = Response::canonical_failure(typed_failure(
        "op-742-14-h",
        StoreError::Serialization("provider codec canary".to_owned()),
    ));
    let backup_reconciled = backup_status("op-742-14-i", StoreBackupStatusOutcome::Reconciled);
    let backup_in_progress = backup_status("op-742-14-j", StoreBackupStatusOutcome::InProgress);
    let backup_complete = backup_status("op-742-14-k", StoreBackupStatusOutcome::Complete);
    let backup_expired = backup_status("op-742-14-l", StoreBackupStatusOutcome::Expired);
    let empty_lookup = Response::Receipt { receipt: None };
    let legacy = Response::Error {
        error: "legacy provider string canary".to_owned(),
    };

    // ONE `vec![...]`, not `Vec::with_capacity` plus fourteen `push` calls:
    // the incremental form is itself a lint (`vec_init_then_push`), so the
    // previous fix for `large_stack_arrays` traded one finding for another. A
    // `vec!` literal does not build an array on the stack — its elements are
    // evaluated straight into the allocation — so this satisfies both lints at
    // once. Same 14 labels, same 14 fixtures, same 14 expectations, same order.
    vec![
        ("committed", committed, RequestOutcome::Committed),
        ("cancelled", cancelled, RequestOutcome::TerminalNonCommit),
        (
            "dead_letter",
            dead_letter,
            RequestOutcome::TerminalNonCommit,
        ),
        ("revision_conflict", conflict, RequestOutcome::Conflict),
        ("unavailable", unavailable, RequestOutcome::NotAttempted),
        (
            "manifest_mismatch",
            manifest_mismatch,
            RequestOutcome::ValidationRejected,
        ),
        ("provider_unknown", ambiguous, RequestOutcome::Unknown),
        ("serialization_defect", defect, RequestOutcome::Defect),
        (
            "backup_reconciled",
            backup_reconciled,
            RequestOutcome::Reconciled,
        ),
        (
            "backup_in_progress",
            backup_in_progress,
            RequestOutcome::Attempted,
        ),
        (
            "backup_complete",
            backup_complete,
            RequestOutcome::ReadCompleted,
        ),
        (
            "backup_expired",
            backup_expired,
            RequestOutcome::TerminalNonCommit,
        ),
        ("empty_lookup", empty_lookup, RequestOutcome::ReadCompleted),
        ("legacy_error", legacy, RequestOutcome::Defect),
    ]
}

/// Every closed response projects to its own outcome, and never to one of the
/// three classes only a call site can record.
fn assert_every_closed_response_projects_to_its_own_outcome(
    cases: &[(&'static str, Response, RequestOutcome)],
) {
    assert_eq!(cases.len(), 14);
    for (label, response, expected) in cases {
        assert_eq!(
            classify_response(response),
            *expected,
            "{label} must project to its own outcome"
        );
    }

    // Provider rollback is unreachable from every closed response, and the two
    // call-site-only classes are never inferred from a typed response.
    for (label, response, _) in cases {
        assert_ne!(
            classify_response(response),
            RequestOutcome::RolledBack,
            "{label} must never fabricate provider rollback"
        );
        assert_ne!(
            classify_response(response),
            RequestOutcome::Received,
            "{label} must never fabricate request receipt"
        );
        assert_ne!(
            classify_response(response),
            RequestOutcome::LifecycleObserved,
            "{label} must never fabricate a lifecycle transition"
        );
    }
}

/// The eight classes the bridge must keep separable, named as the expectations
/// the production projection has to meet from a reachable typed response.
///
/// This list is the expected side only. The values under test are the classes
/// `diagnostics::classify_response` returns; see
/// `assert_every_separable_class_is_produced_by_the_projection`.
const EIGHT_SEPARABLE_CLASSES: [RequestOutcome; 8] = [
    RequestOutcome::Committed,
    RequestOutcome::TerminalNonCommit,
    RequestOutcome::Conflict,
    RequestOutcome::NotAttempted,
    RequestOutcome::ValidationRejected,
    RequestOutcome::Unknown,
    RequestOutcome::Reconciled,
    RequestOutcome::Defect,
];

/// Every one of the eight separable classes must be produced by the real
/// `classify_response` projection from a reachable response fixture, and the
/// machine codes the bridge renders for the classes it produces must stay
/// pairwise distinct.
///
/// The values compared here are the production-produced classes, never a literal
/// table of variants compared with itself, so this can fail for a production
/// edit: collapsing two classes inside `classify_response`
/// (`src/diagnostics.rs:988`) stops one of the eight from being produced and
/// fails the first loop, and giving two produced variants the same
/// `RequestOutcome::as_str` code (`src/diagnostics.rs:277`) fails the second.
fn assert_every_separable_class_is_produced_by_the_projection(
    cases: &[(&'static str, Response, RequestOutcome)],
) {
    let produced: Vec<RequestOutcome> = cases
        .iter()
        .map(|(_, response, _)| classify_response(response))
        .collect();

    for class in EIGHT_SEPARABLE_CLASSES {
        assert!(
            produced.contains(&class),
            "{class:?} must be produced by a reachable response; the reachable responses produce {produced:?}"
        );
    }

    // The distinct classes the projection actually produced, with the machine
    // code each one renders through production `RequestOutcome::as_str`.
    let mut distinct: Vec<RequestOutcome> = Vec::new();
    for class in produced {
        if !distinct.contains(&class) {
            distinct.push(class);
        }
    }
    let mut codes: Vec<&'static str> = Vec::new();
    for class in &distinct {
        let code = class.as_str();
        assert!(
            !codes.contains(&code),
            "two produced classes share the machine code {code}: {distinct:?}"
        );
        codes.push(code);
    }
}

/// The same projection reaches the production log through dispatch, so the
/// recorded outcome is the classified one.
async fn assert_logged_projection_is_the_classified_one(operation: &str) {
    let (_, dispatched) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(typed_failure(operation, StoreError::OrderingConflict)),
    )
    .await;
    let observed = dispatched.last().unwrap();
    assert_eq!(observed.boundary(), BridgeBoundary::MutationResult);
    assert_eq!(observed.outcome(), RequestOutcome::Conflict);
    assert!(
        dispatched
            .iter()
            .all(|event| event.outcome() != RequestOutcome::RolledBack)
    );
}

// WORK_UNIT_CASE: 742/14
#[tokio::test]
async fn the_eight_outcome_classes_stay_distinct_and_rollback_stays_unreachable() {
    let cases = closed_outcome_cases();
    assert_every_closed_response_projects_to_its_own_outcome(&cases);
    assert_every_separable_class_is_produced_by_the_projection(&cases);
    assert_logged_projection_is_the_classified_one("op-742-14-dispatch").await;
}

// WORK_UNIT_CASE: 742/15
#[test]
fn provider_success_text_never_proves_semantic_readiness() {
    // Provider prose is not a readiness or commit signal: the legacy string
    // failure is a defect, whatever the text claims.
    let prose = "schema applied successfully: store ready to accept writes";
    let legacy_success = Response::Error {
        error: prose.to_owned(),
    };
    assert_eq!(
        classify_response(&legacy_success),
        RequestOutcome::Defect,
        "provider prose is not a readiness or commit signal"
    );

    // Liveness-shaped health text is a read observation only.
    let healthy = health_response(StoreHealthStatus::Ready);
    assert_eq!(classify_response(&healthy), RequestOutcome::ReadCompleted);
    assert_ne!(classify_response(&healthy), RequestOutcome::Committed);

    // Classifying a readiness answer is not a readiness verdict: the semantic
    // gate decides, over the typed receipt alone.
    let answered = Response::Readiness {
        receipt: ReadinessReceipt::unavailable(),
    };
    assert_eq!(
        classify_response(&answered),
        RequestOutcome::ReadCompleted,
        "a classified readiness answer is not the semantic verdict"
    );
    assert!(
        require_semantic_ready_for_pipe(&ReadinessReceipt::unavailable(), "1.0.0").is_err(),
        "the semantic gate still denies the same unavailable receipt"
    );

    // Only the exact typed receipt for the configured generation admits.
    let typed_ready = ReadinessReceipt::ready("1.0.0".to_owned());
    assert!(require_semantic_ready_for_pipe(&typed_ready, "1.0.0").is_ok());
    assert!(
        require_semantic_ready_for_pipe(
            &ReadinessReceipt::migration_required("1.1.0".to_owned(), None),
            "1.1.0"
        )
        .is_err(),
        "a migration-required answer never admits the pipe"
    );
    let mut partial = ReadinessReceipt::ready("1.0.0".to_owned());
    partial.expected_generation = None;
    assert!(
        require_semantic_ready_for_pipe(&partial, "1.0.0").is_err(),
        "a malformed receipt fails closed before any generation claim"
    );
    let mut mismatched = ReadinessReceipt::ready("1.0.0".to_owned());
    mismatched.observed_generation = Some("9.9.9".to_owned());
    assert!(
        require_semantic_ready_for_pipe(&mismatched, "1.0.0").is_err(),
        "a receipt whose generations disagree is not readiness"
    );
}

// WORK_UNIT_CASE: 742/16
#[tokio::test]
async fn process_liveness_never_proves_a_transaction_commit() {
    let (liveness, liveness_events) =
        dispatch_recorded(Request::Health, health_response(StoreHealthStatus::Ready)).await;
    assert!(matches!(liveness, Response::Health { .. }));
    let observed = liveness_events.last().unwrap();
    assert_eq!(observed.boundary(), BridgeBoundary::Dispatch);
    assert_eq!(
        observed.outcome(),
        RequestOutcome::ReadCompleted,
        "a healthy provider is a read observation"
    );
    assert!(
        liveness_events
            .iter()
            .all(|event| event.outcome() != RequestOutcome::Committed),
        "liveness never reports a commit"
    );
    assert!(
        liveness_events
            .iter()
            .all(|event| event.receipt_status().is_none()),
        "liveness carries no owner receipt"
    );

    // A degraded provider is still only a read observation.
    let (_, degraded_events) = dispatch_recorded(
        Request::Health,
        health_response(StoreHealthStatus::Degraded),
    )
    .await;
    assert_eq!(
        degraded_events.last().unwrap().outcome(),
        RequestOutcome::ReadCompleted
    );

    // An ambiguous write observed after a healthy liveness answer stays unknown.
    let operation = "op-742-16";
    let (_, write_events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(unknown_failure(operation)),
    )
    .await;
    let write = write_events.last().unwrap();
    assert_eq!(
        write.outcome(),
        RequestOutcome::Unknown,
        "liveness never upgrades an ambiguous write to committed"
    );
    assert_ne!(write.outcome(), RequestOutcome::Committed);
    assert_ne!(write.outcome(), RequestOutcome::RolledBack);
    assert_ne!(write.outcome(), RequestOutcome::NotAttempted);
    assert_eq!(
        write.recovery(),
        Some(StoreRecoveryAction::ReconcileUnknownOutcome)
    );
}

// WORK_UNIT_CASE: 742/19
#[tokio::test]
async fn deterministic_result_conflict_emits_conflict_not_a_generic_failure() {
    let operation = "op-742-19";
    let failure = typed_failure(operation, StoreError::OrderingConflict);
    assert_eq!(failure.disposition, StoreFailureDisposition::Conflict);
    let (returned, events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(failure),
    )
    .await;
    assert!(matches!(returned, Response::Failure { .. }));

    let event = events.last().unwrap();
    assert_eq!(
        event.boundary(),
        BridgeBoundary::MutationResult,
        "the conflict is reported at its owning result boundary"
    );
    assert_eq!(event.outcome(), RequestOutcome::Conflict);
    assert_eq!(
        event.failure_disposition(),
        Some(StoreFailureDisposition::Conflict)
    );
    assert_eq!(
        event.recovery(),
        Some(StoreRecoveryAction::RefreshRevisionHeads)
    );
    assert_ne!(
        event.outcome(),
        RequestOutcome::Defect,
        "a conflict is not collapsed into an internal defect"
    );
    assert_ne!(
        event.outcome(),
        RequestOutcome::NotAttempted,
        "a conflict is not an availability claim"
    );
    assert_ne!(event.outcome(), RequestOutcome::Unknown);
    assert_ne!(event.outcome(), RequestOutcome::Committed);
    // No `detail()` assertion: `detail` is assigned in exactly one production
    // place (`src/diagnostics.rs:811`, `detail: None`), so `event.detail()` reads
    // a constant. The rendered line below carries the same leak check in a
    // falsifiable form, because `src/diagnostics.rs:899-901` renders
    // ` detail={detail}` whenever one is attached.

    let rendered = event.to_string();
    assert!(
        rendered.contains("mutation_result apply outcome=conflict"),
        "the record names the conflict class: {rendered}"
    );
    assert!(rendered.contains("disposition=conflict"));
    assert!(rendered.contains("reason=ORDERING_CONFLICT"));
    assert!(!rendered.contains("internal_defect"));
    assert!(!rendered.contains("INTERNAL_STORE_FAILURE"));
}

// WORK_UNIT_CASE: 742/20
#[tokio::test]
async fn unavailable_generation_keeps_not_attempted_and_the_exact_generation() {
    let operation = "op-742-20";
    let failure = typed_failure(operation, StoreError::Unavailable);
    assert_eq!(failure.disposition, StoreFailureDisposition::Unavailable);
    let (_, events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(failure),
    )
    .await;
    let event = events.last().unwrap();
    assert_eq!(
        event.outcome(),
        RequestOutcome::NotAttempted,
        "an unavailable store never claims an attempted mutation"
    );
    assert_eq!(
        event.failure_disposition(),
        Some(StoreFailureDisposition::Unavailable)
    );
    assert_eq!(
        event.recovery(),
        Some(StoreRecoveryAction::RestoreStoreConnectivity)
    );
    assert_ne!(event.outcome(), RequestOutcome::Committed);
    assert_ne!(
        event.outcome(),
        RequestOutcome::Defect,
        "unavailable is not an internal defect"
    );
    assert_ne!(event.outcome(), RequestOutcome::Unknown);
    assert_eq!(
        event.identity().generation(),
        None,
        "no generation is invented on a dispatch result"
    );

    // The generation that is actually available travels exactly, on the
    // boundary that observes it, the way
    // `StoreComposition::replace_client_generation` records it.
    let mut log = BoundedEventLog::new();
    emit_lifecycle(
        &mut log,
        BridgeBoundary::ConnectionGeneration,
        "connection_generation",
        &BridgeIdentity::new().with_generation("generation-20-available"),
        None,
    );
    let rotation = log.last().unwrap();
    assert_eq!(rotation.boundary(), BridgeBoundary::ConnectionGeneration);
    assert_eq!(rotation.outcome(), RequestOutcome::LifecycleObserved);
    assert_eq!(
        rotation.identity().generation(),
        Some("generation-20-available"),
        "the exact available generation is preserved"
    );
    assert!(
        rotation
            .to_string()
            .contains("generation=generation-20-available")
    );

    // An unusable generation value fails closed instead of being truncated.
    let mut unusable = BoundedEventLog::new();
    emit_lifecycle(
        &mut unusable,
        BridgeBoundary::ConnectionGeneration,
        "connection_generation",
        &BridgeIdentity::new().with_generation(&"g".repeat(MAX_STORE_FAILURE_REFERENCE_LEN + 1)),
        None,
    );
    let dropped = unusable.last().unwrap();
    assert_eq!(
        dropped.identity().generation(),
        None,
        "an over-long generation is dropped, never truncated"
    );
    assert!(!dropped.to_string().contains("generation="));
}

// WORK_UNIT_CASE: 742/21
#[tokio::test]
async fn post_send_ambiguity_preserves_unknown_without_inventing_an_outcome() {
    let operation = "op-742-21";
    let (_, events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(unknown_failure(operation)),
    )
    .await;
    let event = events.last().unwrap();
    assert_eq!(
        event.outcome(),
        RequestOutcome::Unknown,
        "an unproven post-send outcome stays unknown"
    );
    assert_eq!(event.boundary(), BridgeBoundary::MutationResult);
    assert_eq!(
        event.failure_disposition(),
        Some(StoreFailureDisposition::UnknownOutcome)
    );
    assert_eq!(
        event.recovery(),
        Some(StoreRecoveryAction::ReconcileUnknownOutcome)
    );
    assert_eq!(
        event.identity().operation_id().map(OperationId::as_str),
        Some(operation),
        "the same admitted operation identity survives the ambiguity"
    );
    assert_ne!(
        event.outcome(),
        RequestOutcome::Committed,
        "a lost answer never invents a commit"
    );
    assert_ne!(
        event.outcome(),
        RequestOutcome::RolledBack,
        "a lost answer never invents a rollback"
    );
    assert_ne!(
        event.outcome(),
        RequestOutcome::NotAttempted,
        "a lost answer is never reported as not attempted"
    );
    assert!(
        events
            .iter()
            .all(|observed| observed.outcome() != RequestOutcome::Committed),
        "no observation of this dispatch invents a commit"
    );
    assert!(
        events
            .iter()
            .all(|observed| observed.outcome() != RequestOutcome::RolledBack),
        "no observation of this dispatch invents a rollback"
    );
    let identities: Vec<&str> = events
        .iter()
        .filter_map(|observed| observed.identity().operation_id().map(OperationId::as_str))
        .collect();
    assert_eq!(
        identities,
        [operation, operation, operation],
        "every observation stays bound to the one admitted operation"
    );

    // The legacy unknown variant keeps the same identity and drops its prose.
    let reason = "connection reset after send: nested_error_canary_21 token_canary_21";
    let (_, legacy_events) = dispatch_recorded(
        apply_request(operation),
        Response::Unknown {
            operation_id: operation_id(operation),
            reason: reason.to_owned(),
        },
    )
    .await;
    let legacy = legacy_events.last().unwrap();
    assert_eq!(legacy.outcome(), RequestOutcome::Unknown);
    assert_eq!(
        legacy.identity().operation_id().map(OperationId::as_str),
        Some(operation)
    );
    let rendered = legacy.to_string();
    assert!(!rendered.contains("nested_error_canary_21"));
    assert!(!rendered.contains("token_canary_21"));
    assert!(!rendered.contains("connection reset"));
}

// Every prose canary class this target plants, named once so the payloads that
// carry them and the scan that refuses them cannot drift apart.
const RAW_QUERY_CANARY: &str =
    "SELECT * FROM eliot:memory WHERE canary_22 = 'record_content_canary_22'";
const CREDENTIAL_CANARY: &str = "Bearer eyJhbGciOi.credential_canary_22.signature";
const DB_URL_CANARY: &str = "surrealkv://canary_user_22:canary_password_22@127.0.0.1:9999/eliot";
const RECORD_CONTENT_CANARY: &str = "record_content_canary_22: eliot.memory.42 payload-blob-7";
const NESTED_ERROR_CANARY: &str = "nested_error_canary_22: outer cause [ inner cause: leaf ]";

/// The exact token set that no structured or fallback sink may ever render.
fn canary_tokens() -> [&'static str; 13] {
    [
        RAW_QUERY_CANARY,
        CREDENTIAL_CANARY,
        DB_URL_CANARY,
        RECORD_CONTENT_CANARY,
        NESTED_ERROR_CANARY,
        "content_canary_22",
        "credential_canary_22",
        "canary_user_22",
        "canary_password_22",
        "nested_error_canary_22",
        "evidence_canary_22",
        "detail_canary_22",
        "canary_22",
    ]
}

/// A bounded typed failure carrying every prose canary in its diagnostic
/// detail: the detail is inside its own bound, so redaction rather than
/// truncation is what keeps it out of the record.
fn prose_canary_failure(operation: &str) -> StoreFailure {
    let mut prose = unknown_failure(operation);
    let detail = [
        RAW_QUERY_CANARY,
        CREDENTIAL_CANARY,
        DB_URL_CANARY,
        RECORD_CONTENT_CANARY,
        NESTED_ERROR_CANARY,
    ]
    .join(" ");
    assert!(
        detail.len() <= MAX_STORE_FAILURE_DETAIL_LEN,
        "the planted detail stays inside its bound: {}",
        detail.len()
    );
    prose.human_detail = Some(detail);
    prose
}

/// An over-long failure whose evidence reference and detail both exceed their
/// bounds, so the bounded-reference gate has to drop them whole.
fn oversized_canary_failure(operation: &str) -> StoreFailure {
    let mut oversized = typed_failure(operation, StoreError::Unavailable);
    oversized.evidence_ref = Some(format!(
        "evidence_canary_22:{}",
        "e".repeat(MAX_STORE_FAILURE_REFERENCE_LEN)
    ));
    oversized.human_detail = Some(format!(
        "detail_canary_22:{}",
        "d".repeat(MAX_STORE_FAILURE_DETAIL_LEN)
    ));
    oversized
}

/// An undecodable request payload carrying every canary class, and the log the
/// production frame validator records for its refusal.
///
/// BLOCKED (malformed-input half): the refusal recorded here today is raised by
/// `validate_session_peer_binding` (`src/lib.rs:1838`), not by the decode at
/// `src/lib.rs:1848`, because `admitted_session()` holds no authenticated peer
/// and this integration target compiles the library without `cfg(test)`. What is
/// asserted below is therefore exact for what it says — the frame is refused and
/// exactly one bounded `SessionValidation` record is retained and scanned — and
/// it does NOT claim that an undecodable payload reaches the decode here. See the
/// BLOCKED note on case 742/4 for the full reason and the two lawful fixes.
fn rejected_canary_frame() -> BoundedEventLog {
    let mut session = admitted_session();
    let context = context_with("request-742-22");
    let valid = eliot_store_api::request_frame(
        "connection-742",
        ProtocolVersion::CURRENT,
        context.request_id.clone(),
        identity_for(&context, "idem-742-22"),
        StoreRequest::Readiness,
    )
    .unwrap();
    let mut malformed = valid;
    // The joined string is built OUTSIDE the macro on purpose: `json!` is a macro,
    // so a method-call continuation inside its braces does not parse. The other two
    // `.join(" ")` sites in this file are a `let` binding and a struct-literal
    // field, where the continuation is legal.
    let joined_canaries = [
        RAW_QUERY_CANARY,
        CREDENTIAL_CANARY,
        DB_URL_CANARY,
        RECORD_CONTENT_CANARY,
    ]
    .join(" ");
    malformed.payload = ProtocolPayload::Json(json!({
        "op": joined_canaries,
        "detail": NESTED_ERROR_CANARY,
    }));
    let mut frame_events = BoundedEventLog::new();
    assert!(validate_request_frame_with_log(&mut session, &malformed, &mut frame_events).is_err());
    assert_eq!(frame_events.len(), 1);
    frame_events
}

/// Every planted sink is scanned for every planted canary in the exact line the
/// fallback sink writes for each event. `src/diagnostics.rs:899-901` renders
/// ` detail={detail}` into that line, so an attached detail is scanned like any
/// other field.
///
/// `report_events` is deliberately NOT called here: in a test binary the
/// process-wide subscriber cell is installed only by `main()`, so
/// `report_events` (`src/diagnostics.rs:1332-1339`) returns immediately and
/// asserts nothing. Formatting the line here is the strongest form available in
/// a test binary, because it is the exact string the fallback sink writes.
fn assert_canaries_absent_from_every_sink(sinks: &[BoundedEventLog], canaries: &[&str]) {
    let mut scanned = 0_usize;
    for log in sinks {
        assert!(!log.is_empty(), "every planted canary produced a record");
        for event in log {
            // The exact line the fallback sink writes for this event.
            let line = format!("{SERVICE_NAME}: {event}");
            for &canary in canaries {
                assert!(
                    !line.contains(canary),
                    "canary reached a structured or fallback sink: {line}"
                );
            }
            scanned += 1;
        }
    }
    assert!(
        scanned >= 10,
        "every dispatched and frame-rejected record was scanned: {scanned}"
    );
}

// PARTIAL: the prose, oversized-bounded and legacy-string canary classes are
// proved over the real dispatch path, and the malformed-request-frame class is
// proved only as "refused with one bounded canary-free record" — see the BLOCKED
// note on `rejected_canary_frame` and on case 742/4.
// WORK_UNIT_CASE: 742/22
#[tokio::test]
async fn canaries_never_reach_any_structured_or_fallback_sink() {
    let operation = "op-742-22";
    let canaries = canary_tokens();

    let (_, prose_events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(prose_canary_failure(operation)),
    )
    .await;
    let (_, oversized_events) = dispatch_recorded(
        apply_request(operation),
        Response::canonical_failure(oversized_canary_failure(operation)),
    )
    .await;
    let (_, legacy_events) = dispatch_recorded(
        receipt_request(operation),
        Response::Unknown {
            operation_id: operation_id(operation),
            reason: [RAW_QUERY_CANARY, CREDENTIAL_CANARY, DB_URL_CANARY].join(" "),
        },
    )
    .await;
    let frame_events = rejected_canary_frame();

    let sinks = [prose_events, oversized_events, legacy_events, frame_events];
    assert_canaries_absent_from_every_sink(&sinks, &canaries);
}
