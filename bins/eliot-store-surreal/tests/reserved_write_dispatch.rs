//! Store-boundary integration tests for the reserved-write operation (issue #991).
//!
//! Three cases (`991/4`, `991/14`, `991/15`) prove the session capability
//! gate and the unsupported-backend posture through production boundary
//! code: the declared capability is withheld at the handshake, a
//! reserved-write frame is refused before dispatch while ordinary operations
//! keep flowing, and only the exact admitted capability set is ever enabled.
//! Wire mapping and client serialization live in the sibling
//! `reserved_write_wire` and `reserved_write_client` suites; markers are
//! allocated once across the three files.
//!
//! The typed input freezes in
//! `data/reserved-write/reserved-write-request.json`. No provider, adapter,
//! or composition instance is needed: the boundary under test refuses before
//! any provider I/O.

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
    InstallationEpoch, InstallationProfile, RuntimeLaunchDescriptor, RuntimeStateRoots,
    SupervisionAuthorityBinding,
};
use eliot_ipc::TransportLimits;
use eliot_kernel_service::STORE_MODULE_IDENTITY;
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    ClientHello, Frame, ProtocolPayload, ProtocolRange, ProtocolVersion, RequestIdentity,
};
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};
use eliot_store_api::{
    CanonicalStoreClient, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, ReservedScopeBinding, ReservedWriteRequest,
    RevisionHeadExpectation, RevisionKey, ScopeId, SecurityContext, StoreError, StoreRequest,
    WriteAdmissionParams, WriteAdmissionProjection, WriterEpochBinding,
};
use eliot_store_surreal::{
    PROTOCOL_VERSION, SERVICE_NAME, StoreHandshakeIdentity, StoreLaunchConfig, admit_handshake,
    launch_config_digest, validate_request_frame,
};
use serde::Serialize;
use serde_json::json;
use sha2::Digest as _;

const LINEAGE_991: &str = "550e8400-e29b-41d4-a716-446655440000";

fn handle(value: impl Into<String>) -> PlatformHandle {
    PlatformHandle::new(value).unwrap()
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_991).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
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

fn runtime_launch() -> RuntimeLaunchDescriptor {
    let roots = runtime_state_roots();
    let config_path = handle(r"C:\ProgramData\Eliot\generation.json");
    let authority_generation = ResourceGeneration::genesis();
    let authority_state_fence = StateFence::new(test_epoch(1), authority_generation);
    let mut descriptor = RuntimeLaunchDescriptor {
        profile: InstallationProfile::SystemService,
        portable_root: None,
        installation_epoch: InstallationEpoch {
            installation: handle("installation-test"),
            lineage_id: handle("lineage-test"),
            sequence: 1,
        },
        generation: handle("generation-test"),
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
        kernel_arguments: vec![
            handle("--work-root"),
            roots.kernel_work_root.clone(),
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
            handle("--eliotd-descriptor"),
            handle(r"C:\ProgramData\Eliot\eliotd.json"),
            handle("--eliotd-descriptor-sha256"),
            handle("e".repeat(64)),
        ],
        store_bridge_arguments: vec![handle("--config"), config_path],
        canonical_store_arguments: vec![
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
        ],
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
        descriptor_digest: handle("0".repeat(64)),
    };
    descriptor = descriptor.with_computed_digest().unwrap();
    descriptor
}

fn config() -> StoreLaunchConfig {
    let mut config = StoreLaunchConfig {
        store_pipe: r"\\.\pipe\eliot\store-test".to_owned(),
        launch_nonce: "launch-test".to_owned(),
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
        schema_generation: "1.0.0".to_owned(),
        blob_root: r"C:\ProgramData\Eliot\blob".to_owned(),
        instance_id: "store-test".to_owned(),
        credential_ref: "eliot/store/v1/0123456789abcdef0123456789abcdef".to_owned(),
        runtime_launch: runtime_launch(),
    };
    config.approved_config_hash = launch_config_digest(&config).unwrap();
    config
}

fn client_hello_frame(config: &StoreLaunchConfig, extra_capabilities: &[&str]) -> Frame {
    let module_id = ContractId::new(STORE_MODULE_IDENTITY).unwrap();
    let artifact_id = ArtifactId::new(config.approved_artifact_hash.as_str()).unwrap();
    let authority_epoch = config
        .runtime_launch
        .authority_state_fence
        .authority_epoch
        .clone();
    let generation = config.runtime_launch.authority_generation;
    let mut capabilities: Vec<String> = eliot_store_api::CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    for extra in extra_capabilities {
        capabilities.push((*extra).to_owned());
    }
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
            required_capabilities: vec!["store.readiness".to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-kernel".to_owned(),
            failure_domain: SERVICE_NAME.to_owned(),
            hot_replace: false,
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
        capabilities,
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES).unwrap(),
        authority_epoch,
    };
    eliot_ipc::client_hello_frame("connection-test", &hello).unwrap()
}

fn context_with(request_id: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(request_id).unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-991-d").unwrap(),
        source_id: SourceId::new("source-991-d").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition() -> PreparedTransition {
    // The manifest digest is the real generated set digest: the session
    // catalogue gate re-checks it before any provider I/O.
    let entries = eliot_store_api::generated_operation_manifests().unwrap();
    let set_digest = eliot_store_api::operation_manifest_set_digest(&entries).unwrap();
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-991-d1").unwrap(),
            idempotency_key: "idem-991-d1".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-991-d1").unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-991-d1").unwrap()],
        transition_class: eliot_store_api::TransitionClass::CaptureCandidate,
        requested_effect_ceiling: eliot_store_api::EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest,
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("observation-991-d1"))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    }
}

fn valid_request() -> ReservedWriteRequest {
    let transition = transition();
    let params = WriteAdmissionParams {
        reservation_id: "reservation-991-d1".to_owned(),
        reservation_order: 42,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes: vec![ReservedScopeBinding {
            scope: OrderingScopeId::new("scope-991-d1").unwrap(),
            reserved_sequence: 7,
            expected_sequence: 6,
            expected_head_digest: "c".repeat(64),
        }],
        writer_epoch: WriterEpochBinding {
            lineage_id: "epoch-lineage-991-d".to_owned(),
            epoch: 5,
            predecessor_lineage_id: None,
            predecessor_epoch: None,
        },
        state_fence: fence(),
        source_id: "source-991-d".to_owned(),
        created_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        recovery_owner: "recovery-owner-991-d".to_owned(),
    };
    let admission = WriteAdmissionProjection::bind(&transition, params).unwrap();
    ReservedWriteRequest {
        context: context_with("request-991-d1"),
        transition,
        admission,
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new("rev-991-d1").unwrap(),
            expected_revision: 3,
            state_fence: fence(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-991-d1").unwrap(),
            expected_sequence: 6,
            state_fence: fence(),
        }],
    }
}

fn fixture_request() -> ReservedWriteRequest {
    let text = include_str!("data/reserved-write/reserved-write-request.json");
    let request: ReservedWriteRequest = serde_json::from_str(text).unwrap();
    assert_eq!(
        request,
        valid_request(),
        "fixture matches the sealed builder"
    );
    request
}

fn identity_for(context: &RequestMeta, idempotency_key: &str) -> RequestIdentity {
    // Built through JSON so the suite needs no new dependency: the exact
    // shapes come from the production serializers (`RequestMeta` is the
    // `RequestBinding` metadata shape by type alias).
    serde_json::from_value(json!({
        "request": {
            "metadata": serde_json::to_value(context).unwrap(),
            "state_fence": serde_json::to_value(&context.state_fence).unwrap(),
        },
        "idempotency_key": idempotency_key,
        "deadline_unix_ms": 1,
        "cancellation_id": "cancel-991-d",
    }))
    .unwrap()
}

/// Backend without reserved-write support: every required trait method is an
/// explicit refusal, and the reserved-write entry point keeps its default
/// explicit-unsupported body.
struct UnsupportedBackend;

impl CanonicalStoreClient for UnsupportedBackend {
    async fn apply_prepared(
        &self,
        _ctx: &RequestMeta,
        _transition: PreparedTransition,
        _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<eliot_store_api::WriteReceipt, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn receipt(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<eliot_store_api::WriteReceipt>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn revision_heads(
        &self,
        _keys: Vec<eliot_store_api::RevisionKey>,
    ) -> Result<Vec<eliot_store_api::RevisionHead>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn validation_snapshot(
        &self,
    ) -> Result<eliot_store_api::CanonicalValidationSnapshot, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn scope_revision_view(
        &self,
        _scope_id: ScopeId,
    ) -> Result<eliot_store_api::ScopeRevisionView, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn ordering_heads(
        &self,
        _scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<eliot_store_api::OrderingHead>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn execute_named(
        &self,
        _query: eliot_store_api::NamedReadRequest,
    ) -> Result<eliot_store_api::NamedReadResponse, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn health(&self) -> Result<eliot_store_api::StoreHealth, StoreError> {
        Err(StoreError::Unavailable)
    }
}

// WORK_UNIT_CASE: 991/4
#[test]
fn unsupported_reserved_operation_cannot_fall_back_to_ordinary_apply() {
    // The session gate refuses the unadvertised reserved operation before
    // dispatch, while the ordinary operations sharing its identities keep
    // flowing: no fallback, no cross-contamination.
    let config = config();
    let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
    let frame = client_hello_frame(&config, &["store.reserved_write"]);
    let (mut session, hello) =
        admit_handshake(frame, TransportLimits::default(), &config, &identity).unwrap();
    assert!(
        !hello
            .allowed_capabilities
            .contains(&"store.reserved_write".to_owned()),
        "offering the capability must not enable it"
    );
    let request = fixture_request();
    let wire = StoreRequest::ReservedWrite {
        request: request.clone(),
    };
    let reserved_frame = eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        request.context.request_id.clone(),
        identity_for(
            &request.context,
            &request.transition.identity.idempotency_key,
        ),
        wire,
    )
    .unwrap();
    assert_eq!(
        validate_request_frame(&mut session, &reserved_frame),
        Err("capability is not admitted: store.reserved_write".to_owned())
    );
    // Ordinary operations are unaffected by the new variant.
    let ready_context = context_with("request-991-d3");
    let ready_frame = eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        ready_context.request_id.clone(),
        identity_for(&ready_context, "idem-991-d3"),
        StoreRequest::Readiness,
    )
    .unwrap();
    assert!(validate_request_frame(&mut session, &ready_frame).is_ok());
    let apply_context = context_with("request-991-d2");
    let apply = StoreRequest::Apply {
        context: apply_context.clone(),
        transition: transition(),
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new("rev-991-d1").unwrap(),
            expected_revision: 3,
            state_fence: fence(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-991-d1").unwrap(),
            expected_sequence: 6,
            state_fence: fence(),
        }],
    };
    let apply_frame = eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        apply_context.request_id.clone(),
        identity_for(&apply_context, "idem-991-d1"),
        apply,
    )
    .unwrap();
    assert!(
        validate_request_frame(&mut session, &apply_frame).is_ok(),
        "ordinary Apply admission is unchanged by the new variant"
    );
}

// WORK_UNIT_CASE: 991/14
#[test]
fn unsupported_default_backend_prevents_capability_advertising() {
    // Socket liveness, API enum presence, and a client offer are not
    // readiness: the handshake withholds the reserved-write capability even
    // when the client offers it plus an unknown future capability.
    let config = config();
    let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
    let frame = client_hello_frame(&config, &["store.reserved_write", "store.future_x"]);
    let (_, hello) =
        admit_handshake(frame, TransportLimits::default(), &config, &identity).unwrap();
    let allowed = hello.allowed_capabilities;
    assert_eq!(
        allowed,
        eliot_store_api::CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
        "only the exact admitted set is enabled"
    );
    assert!(!allowed.contains(&"store.reserved_write".to_owned()));
    assert!(!allowed.contains(&"store.future_x".to_owned()));
    // The default backend body is the explicit unsupported result: a shaped
    // request refuses without provider I/O and without Apply fallback.
    assert!(fixture_request().validate().is_ok());
}

// WORK_UNIT_CASE: 991/15
#[test]
fn actual_supported_backend_generation_enables_only_exact_admitted_capability() {
    // Generation/fence pinning plus the exact admitted set: a fully capable
    // handshake enables exactly the advertised catalogue — nothing extra —
    // and a generation-diverged hello is rejected before any capability is
    // granted.
    let config = config();
    let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
    let frame = client_hello_frame(&config, &[]);
    let (_, hello) = admit_handshake(
        frame.clone(),
        TransportLimits::default(),
        &config,
        &identity,
    )
    .unwrap();
    assert_eq!(
        hello.allowed_capabilities.len(),
        eliot_store_api::CAPABILITIES.len()
    );
    let ProtocolPayload::Json(payload) = frame.payload else {
        panic!("hello payload must use json-v1");
    };
    let mut diverged: ClientHello = serde_json::from_value(payload).unwrap();
    diverged.module_generation.state_fence = StateFence::new(
        test_epoch(1),
        ResourceGeneration::new(config.runtime_launch.authority_generation.value() + 1).unwrap(),
    );
    let diverged_frame = eliot_ipc::client_hello_frame("connection-test", &diverged).unwrap();
    assert!(
        admit_handshake(
            diverged_frame,
            TransportLimits::default(),
            &config,
            &identity
        )
        .is_err(),
        "a generation-diverged hello grants no capability"
    );
}

#[tokio::test]
async fn default_backend_body_is_explicit_unsupported_without_provider_io() {
    // Companion to 991/14: the default `apply_reserved_write` body validates
    // the closed shape and then refuses with `UnknownOperation` — the
    // explicit unsupported result, never success and never Apply fallback.
    let backend = UnsupportedBackend;
    let request = fixture_request();
    assert_eq!(
        CanonicalStoreClient::apply_reserved_write(&backend, request).await,
        Err(StoreError::UnknownOperation)
    );
}
