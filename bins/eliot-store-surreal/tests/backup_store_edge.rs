//! Store-boundary integration tests for the backup edge (issue #975).
//!
//! The single registered `backup_store_edge` target binds all 18 numbered
//! cases (`975/1`..`975/18`, one `// WORK_UNIT_CASE` marker each) across the
//! whole port-to-response denominator: every accepted #950 capture/page/end,
//! isolated-restore, validation, status and reconciliation operation, plus
//! the accepted #991 reserved-write surface. Named subfixtures live under
//! `data/backup-store-edge/` (12 frozen files); no provider, adapter, or
//! composition instance is needed except in the fail-open live case (`975/17`).
//!
//! Contract-adaptation surface (issue #975 workstreams W1-W6 own the symbols):
//! `StoreRequest::Backup { request: StoreBackupRequest { context, identity, operation } }`
//! with `StoreBackupOperation::{Begin, Page, End, PrepareDestination,
//! RestoreBatch, Validate, Status, Reconcile}`, `StoreResponse::Backup`,
//! `CAPABILITY_STORE_BACKUP = "store.backup"`, eight
//! `EbpCanonicalStoreClient::backup_*` methods, eight
//! `StoreComposition::backup_*` single-delegation methods, and
//! `backup_dispatch::dispatch_backup` behind the production `Backup` dispatch
//! arm. All contact with those new symbols is centralized in the
//! `backup_envelope` / `backup_operation` / `backup_success_response` helpers
//! and the per-case client calls below so a rename stays mechanical.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, EpochId, EpochLineageId, OperationId,
    ProductId, RequestId, ResourceGeneration, SourceId, StateFence,
};
use eliot_installation::{
    InstallationEpoch, InstallationProfile, RuntimeLaunchDescriptor, RuntimeStateRoots,
    SupervisionAuthorityBinding,
};
use eliot_ipc::{DeliveryOutcome, TransportLimits};
use eliot_kernel_service::{
    EbpCanonicalStoreClient, EbpStoreTransport, HostStoreBootstrapRequirement,
    STORE_MODULE_IDENTITY, StoreClientError,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    ClientHello, Frame, FrameKind, ProtocolPayload, ProtocolRange, ProtocolVersion,
    RequestIdentity, ServerHello,
};
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};
use eliot_store_api::{
    BackupOperationReconciliation, CAPABILITIES, CAPABILITY_STORE_BACKUP, CanonicalRestoreBatch,
    CanonicalSnapshotPort, DestinationClass, EFFECTS, EffectClass, EventProjectionRelationIntents,
    IsolatedDestination, IsolatedRestorePort, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OrderingHeadExpectation, OrderingScopeId, PreparedTransition, RequestMeta,
    ReservedWriteRequest, RestoreValidationReceipt, RevisionHeadExpectation, RevisionKey, ScopeId,
    SecurityContext, SnapshotBeginRequest, SnapshotCompleteness, SnapshotCursor,
    SnapshotEndReceipt, SnapshotHandle, SnapshotPage, SnapshotValidationReceipt,
    StoreBackupOperation, StoreBackupRequest, StoreBackupResponse, StoreBackupStatus,
    StoreBackupStatusOutcome, StoreError, StoreRequest, StoreResponse, TransitionClass,
};
use eliot_store_surreal::{
    PROTOCOL_VERSION, SERVICE_NAME, StoreHandshakeIdentity, StoreLaunchConfig, admit_handshake,
    launch_config_digest, validate_request_frame,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Digest as _;

const LINEAGE_975: &str = "550e8400-e29b-41d4-a716-446655440000";
const BACKUP_CAPABILITY: &str = "store.backup";

fn manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/backup-store-edge")
}

fn fixture_value(name: &str) -> Value {
    let text = std::fs::read_to_string(manifest_dir().join(name)).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn fixture_typed<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_value(fixture_value(name)).unwrap()
}

fn handle(value: impl Into<String>) -> PlatformHandle {
    PlatformHandle::new(value).unwrap()
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_975).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn diverged_fence() -> StateFence {
    StateFence::new(test_epoch(2), ResourceGeneration::genesis())
}

fn backup_context(request_id: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(request_id).unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-975").unwrap(),
        source_id: SourceId::new("source-975").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn fixture_begin() -> SnapshotBeginRequest {
    fixture_typed("snapshot-begin-request.json")
}

fn fixture_partial_page() -> SnapshotPage {
    fixture_typed("snapshot-page-partial.json")
}

fn fixture_complete_page() -> SnapshotPage {
    fixture_typed("snapshot-page-complete.json")
}

fn fixture_end_receipt() -> SnapshotEndReceipt {
    fixture_typed("snapshot-end-receipt.json")
}

fn fixture_destination() -> IsolatedDestination {
    fixture_typed("isolated-restore-prepare.json")
}

fn fixture_batch() -> CanonicalRestoreBatch {
    fixture_typed("isolated-restore-batch.json")
}

fn fixture_restore_receipt() -> RestoreValidationReceipt {
    fixture_typed("restore-validation-receipt.json")
}

fn fixture_reconciliation() -> BackupOperationReconciliation {
    fixture_typed("operation-reconciliation.json")
}

/// Builds the assumed backup envelope for one typed operation.
///
/// Adaptation point: if the accepted wire shape names the envelope, the
/// context field, or an operation payload differently, only this helper (and
/// the per-operation constructors below) changes; every case keeps its
/// assertions.
/// Envelope identity coherent with one typed operation, per the
/// `StoreBackupRequest::validate` per-variant rules: Begin/RestoreBatch/
/// Validate reuse the payload's admitted `OperationIdentity`; Page/End bind
/// the handle's `operation_id` + `idempotency_key` (a handle carries no
/// canonical hash, so a bound placeholder digest completes the shape);
/// Status binds the queried `operation_id` with the client's deterministic
/// read-correlation key; Reconcile binds `first` (correlation changes, the
/// operation does not); PrepareDestination carries no payload identity, so
/// the envelope identity is the sole mutation binding.
fn envelope_identity(operation: &StoreBackupOperation) -> OperationIdentity {
    match operation {
        StoreBackupOperation::Begin(request) => request.operation.clone(),
        StoreBackupOperation::Page { handle, .. } | StoreBackupOperation::End { handle } => {
            OperationIdentity {
                operation_id: handle.operation_id.clone(),
                idempotency_key: handle.idempotency_key.clone(),
                canonical_request_hash: "c".repeat(64),
            }
        }
        StoreBackupOperation::PrepareDestination(_) => OperationIdentity {
            operation_id: OperationId::new("op-975-restore-1").unwrap(),
            idempotency_key: "idem-975-restore-1".to_owned(),
            canonical_request_hash: "c".repeat(64),
        },
        StoreBackupOperation::RestoreBatch(batch) | StoreBackupOperation::Validate(batch) => {
            batch.operation.clone()
        }
        StoreBackupOperation::Status { operation_id } => OperationIdentity {
            operation_id: operation_id.clone(),
            idempotency_key: format!("store-backup-status:{operation_id}"),
            canonical_request_hash: "c".repeat(64),
        },
        StoreBackupOperation::Reconcile { first, .. } => first.clone(),
    }
}

fn backup_envelope(context: RequestMeta, operation: StoreBackupOperation) -> StoreRequest {
    let identity = envelope_identity(&operation);
    StoreRequest::Backup {
        request: StoreBackupRequest {
            context,
            identity,
            operation,
        },
    }
}

fn backup_operation_id(operation: &StoreBackupOperation) -> Option<OperationId> {
    match operation {
        StoreBackupOperation::Begin(request) => Some(request.operation.operation_id.clone()),
        StoreBackupOperation::Page { handle, .. } => Some(handle.operation_id.clone()),
        StoreBackupOperation::End { handle } => Some(handle.operation_id.clone()),
        // Preparing a destination carries no mutation identity: the
        // destination admission digest binds the failure context instead.
        StoreBackupOperation::PrepareDestination(_) => None,
        StoreBackupOperation::RestoreBatch(batch) | StoreBackupOperation::Validate(batch) => {
            Some(batch.operation.operation_id.clone())
        }
        StoreBackupOperation::Status { operation_id } => Some(operation_id.clone()),
        StoreBackupOperation::Reconcile { first, .. } => Some(first.operation_id.clone()),
    }
}

fn backup_idempotency_key(operation: &StoreBackupOperation) -> String {
    match operation {
        StoreBackupOperation::Begin(request) => request.operation.idempotency_key.clone(),
        StoreBackupOperation::Page { handle, .. } => handle.idempotency_key.clone(),
        StoreBackupOperation::End { handle } => handle.idempotency_key.clone(),
        StoreBackupOperation::PrepareDestination(_) => "idem-975-restore-1".to_owned(),
        StoreBackupOperation::RestoreBatch(batch) | StoreBackupOperation::Validate(batch) => {
            batch.operation.idempotency_key.clone()
        }
        // Status carries no mutation identity; the client derives read
        // correlation deterministically from the queried operation.
        StoreBackupOperation::Status { operation_id } => {
            format!("store-backup-status:{operation_id}")
        }
        StoreBackupOperation::Reconcile { first, .. } => first.idempotency_key.clone(),
    }
}

/// Owner-issued handle bound to the exact admitted begin request.
///
/// The client checks `snapshot_digest` against the recomputed begin digest,
/// so canned success responses must carry the real binding, never an
/// illustrative fixture digest.
fn admitted_handle(begin: &SnapshotBeginRequest) -> SnapshotHandle {
    SnapshotHandle {
        consistency_point: "cp-975-1".to_owned(),
        snapshot_digest: begin.compute_digest().unwrap(),
        operation_id: begin.operation.operation_id.clone(),
        idempotency_key: begin.operation.idempotency_key.clone(),
    }
}

/// Restore validation receipt bound to the admitted restore batch.
///
/// The accepted `Validation` wire outcome carries `RestoreValidationReceipt`
/// (the non-applying `IsolatedRestorePort::validate_restore` backend proves
/// a restore batch without applying it); it is bound to the batch's admitted
/// operation, destination, and archive digest exactly as the production
/// backend binds them.
fn restore_validation_for(batch: &CanonicalRestoreBatch) -> RestoreValidationReceipt {
    RestoreValidationReceipt {
        operation: batch.operation.clone(),
        destination: batch.destination.clone(),
        archive_member_digest: batch.archive_member_digest.clone(),
        resolved_members: 2,
        unresolved_members: 0,
        denominator_members: 2,
        completeness: SnapshotCompleteness::Complete,
        disposition: eliot_store_api::StoreMutationDisposition::Committed,
    }
}

/// Builds one authenticated Execute frame for a backup operation.
fn backup_frame(context: &RequestMeta, operation: StoreBackupOperation) -> Frame {
    let key = backup_idempotency_key(&operation);
    let request = backup_envelope(context.clone(), operation);
    eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        context.request_id.clone(),
        identity_for(context, &key),
        request,
    )
    .unwrap()
}

/// Canned success response matching one backup operation.
///
/// Mirrors the accepted `StoreBackupResponse` outcome catalogue; the fake
/// transport answers the real client with these values. Mutation bindings
/// (handle digest, operation identity, fence) are recomputed from the
/// admitted input exactly as the production backend binds them.
fn backup_success_response(operation: &StoreBackupOperation) -> StoreResponse {
    match operation {
        StoreBackupOperation::Begin(begin) => StoreResponse::Backup {
            response: StoreBackupResponse::Handle {
                handle: admitted_handle(begin),
            },
        },
        StoreBackupOperation::Page { .. } => StoreResponse::Backup {
            response: StoreBackupResponse::Page {
                page: fixture_complete_page(),
            },
        },
        StoreBackupOperation::End { .. } => StoreResponse::Backup {
            response: StoreBackupResponse::EndReceipt {
                receipt: fixture_end_receipt(),
            },
        },
        StoreBackupOperation::PrepareDestination(_) => StoreResponse::Backup {
            response: StoreBackupResponse::Isolation {
                evidence: fixture_destination().evidence,
            },
        },
        StoreBackupOperation::RestoreBatch(_) => StoreResponse::Backup {
            response: StoreBackupResponse::Restored {
                receipt: fixture_restore_receipt(),
            },
        },
        StoreBackupOperation::Validate(batch) => {
            let report = restore_validation_for(batch);
            assert!(report.validate().is_ok());
            StoreResponse::Backup {
                response: StoreBackupResponse::Validation { receipt: report },
            }
        }
        StoreBackupOperation::Status { operation_id } => StoreResponse::Backup {
            response: StoreBackupResponse::Status {
                report: StoreBackupStatus {
                    operation_id: operation_id.clone(),
                    state_fence: fence(),
                    outcome: StoreBackupStatusOutcome::Complete,
                },
            },
        },
        StoreBackupOperation::Reconcile { .. } => StoreResponse::Backup {
            response: StoreBackupResponse::Reconciled {
                reconciliation: fixture_reconciliation(),
            },
        },
    }
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
        "cancellation_id": "cancel-975",
    }))
    .unwrap()
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
        wasm_host_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-wasm-host.exe"),
        wasm_host_artifact_digest: handle("f".repeat(64)),
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
        store_transaction_limit: None,
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

fn admitted_session(
    extra_capabilities: &[&str],
) -> (eliot_store_surreal::StoreEbpSession, StoreLaunchConfig) {
    let config = config();
    let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
    let frame = client_hello_frame(&config, extra_capabilities);
    let (session, _) =
        admit_handshake(frame, TransportLimits::default(), &config, &identity).unwrap();
    (session, config)
}

fn transition_991() -> PreparedTransition {
    let entries = eliot_store_api::generated_operation_manifests().unwrap();
    let set_digest = eliot_store_api::operation_manifest_set_digest(&entries).unwrap();
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-991-d1").unwrap(),
            idempotency_key: "idem-991-d1".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-991-d1").unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-991-d1").unwrap()],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest,
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
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
    };
    eliot_store_api::bind_issue18_digests(&mut transition).unwrap();
    transition
}

fn context_991(request_id: &str) -> RequestMeta {
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

/// Scripted fake transport driving the REAL `EbpCanonicalStoreClient`.
///
/// Every frame the client sends is captured into the shared log for
/// decode-and-assert; answers come from the scripted outcome/response. The
/// handshake and readiness answers mirror the production shape so `connect`
/// reaches the backup call under test.
struct ScriptTransport {
    requirement: HostStoreBootstrapRequirement,
    log: Arc<Mutex<Vec<Frame>>>,
    response: Option<StoreResponse>,
    send_outcome: DeliveryOutcome,
    drop_receive: bool,
}

impl ScriptTransport {
    #[allow(dead_code)]
    fn sent(&self) -> Vec<Frame> {
        self.log.lock().unwrap().clone()
    }
}

impl EbpStoreTransport for ScriptTransport {
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
        self.log.lock().unwrap().push(frame.clone());
        Ok(self.send_outcome)
    }

    async fn receive_frame(&mut self, _limits: TransportLimits) -> Result<Frame, StoreClientError> {
        if self.drop_receive {
            return Err(StoreClientError::Transport(
                "scripted disconnect before response".to_owned(),
            ));
        }
        let log = self.log.lock().unwrap();
        let last = log.last().expect("response needs a prior send");
        if last.kind == FrameKind::Control {
            let hello = ServerHello {
                selected_protocol: ProtocolVersion::CURRENT,
                session_principal_binding: "scripted-store-session".to_owned(),
                allowed_capabilities: CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                allowed_effects: EFFECTS.iter().map(|value| (*value).to_owned()).collect(),
                config_snapshot: json!({
                    "config_hash": self.requirement.approved_config_hash.as_str(),
                    "artifact_hash": self.requirement.approved_artifact_hash.as_str(),
                }),
                heartbeat_ms: 1_000,
                control_channel: "scripted-store-control".to_owned(),
                rejection_reason: None,
                authority_epoch: self.requirement.authority_epoch().clone(),
            };
            return Ok(eliot_ipc::server_hello_frame(
                self.requirement.connection_id.as_str(),
                &hello,
            )
            .expect("scripted server hello"));
        }
        let request_id = last
            .request_id
            .clone()
            .expect("execute carries correlation");
        let (_, _, request) =
            eliot_store_api::decode_request_frame(last).map_err(StoreClientError::from)?;
        if matches!(request, StoreRequest::Readiness) {
            return Ok(eliot_store_api::response_frame(
                self.requirement.connection_id.as_str(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                StoreResponse::Readiness {
                    receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
                },
            )
            .expect("scripted readiness"));
        }
        Ok(eliot_store_api::response_frame(
            self.requirement.connection_id.as_str(),
            ProtocolVersion::CURRENT,
            Some(request_id),
            self.response.clone().expect("scripted backup response"),
        )
        .expect("scripted backup frame"))
    }
}

fn client_requirement() -> HostStoreBootstrapRequirement {
    HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").expect("route"),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").expect("pipe"),
        store_generation: ResourceGeneration::new(1).expect("generation"),
        state_fence: fence(),
        launch_nonce: PlatformHandle::new("launch").expect("launch"),
        connection_id: PlatformHandle::new("connection").expect("connection"),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
        expected_peer_session_id: 1,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
        timeout_ms: 30_000,
    }
}

async fn connected_client(
    response: StoreResponse,
) -> (
    EbpCanonicalStoreClient<ScriptTransport>,
    Arc<Mutex<Vec<Frame>>>,
) {
    connected_client_with_outcome(response, DeliveryOutcome::Delivered, false).await
}

async fn connected_client_with_outcome(
    response: StoreResponse,
    send_outcome: DeliveryOutcome,
    drop_receive: bool,
) -> (
    EbpCanonicalStoreClient<ScriptTransport>,
    Arc<Mutex<Vec<Frame>>>,
) {
    let requirement = client_requirement();
    let log = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptTransport {
        requirement: requirement.clone(),
        log: log.clone(),
        response: Some(response),
        send_outcome,
        drop_receive,
    };
    let client = EbpCanonicalStoreClient::connect(transport, requirement)
        .await
        .expect("scripted connect");
    (client, log)
}

fn sent_backup_requests(
    log: &Arc<Mutex<Vec<Frame>>>,
) -> Vec<(RequestId, RequestIdentity, StoreRequest)> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|frame| frame.kind == FrameKind::Request)
        .map(|frame| eliot_store_api::decode_request_frame(frame).unwrap())
        .collect()
}

/// Backend without backup support: every port keeps its fail-closed default
/// body, so validation runs and then refusal is explicit — never success.
struct DefaultBackupBackend;

impl CanonicalSnapshotPort for DefaultBackupBackend {}

impl IsolatedRestorePort for DefaultBackupBackend {}

// WORK_UNIT_CASE: 975/1
#[test]
fn backup_denominator_covers_every_accepted_operation_end_to_end() {
    // A1: exact complete #950 port -> wire -> capability -> client -> backend
    // -> response denominator. Every accepted operation builds its closed wire
    // variant (reusing the #950 semantic type), selects exactly
    // `store.backup`, round-trips through a real authenticated frame, and has
    // its client method, composition delegation, adapter port and response
    // outcome pinned in source and in the capability-denominator fixture.
    assert_eq!(CAPABILITY_STORE_BACKUP, BACKUP_CAPABILITY);
    assert_eq!(CAPABILITY_STORE_BACKUP, "store.backup");
    assert!(
        !CAPABILITIES.contains(&CAPABILITY_STORE_BACKUP),
        "the backup capability is declared but never advertised without backend proof"
    );

    let begin = fixture_begin();
    assert!(begin.validate().is_ok());
    let partial = fixture_partial_page();
    let complete = fixture_complete_page();
    assert!(partial.validate().is_ok());
    assert!(complete.validate().is_ok());
    let end = fixture_end_receipt();
    assert!(end.validate().is_ok());
    assert!(end.is_complete());
    let destination = fixture_destination();
    assert!(destination.validate().is_ok());
    let batch = fixture_batch();
    assert!(batch.validate().is_ok());
    let restore_receipt = fixture_restore_receipt();
    assert!(restore_receipt.validate().is_ok());
    assert!(restore_receipt.is_proven_success());
    let reconciliation = fixture_reconciliation();
    assert!(reconciliation.validate().is_ok());

    let operations = [
        StoreBackupOperation::Begin(begin.clone()),
        StoreBackupOperation::Page {
            handle: partial.handle.clone(),
            cursor: partial.cursor.clone(),
        },
        StoreBackupOperation::End {
            handle: end.handle.clone(),
        },
        StoreBackupOperation::PrepareDestination(destination.clone()),
        StoreBackupOperation::RestoreBatch(batch.clone()),
        StoreBackupOperation::Validate(batch.clone()),
        StoreBackupOperation::Status {
            operation_id: begin.operation.operation_id.clone(),
        },
        StoreBackupOperation::Reconcile {
            first: reconciliation.operation.clone(),
            second: reconciliation.operation.clone(),
        },
    ];
    assert_eq!(operations.len(), 8);
    for (index, operation) in operations.iter().enumerate() {
        let context = backup_context(&format!("request-975-a1-{index}"));
        let request = backup_envelope(context.clone(), operation.clone());
        assert_eq!(request.capability(), CAPABILITY_STORE_BACKUP);
        assert!(request.validate().is_ok());
        // Real authenticated frame round-trip preserves the typed operation
        // and its stable identity.
        let frame = backup_frame(&context, operation.clone());
        let (request_id, identity, decoded) =
            eliot_store_api::decode_request_frame(&frame).unwrap();
        assert_eq!(request_id, context.request_id);
        assert_eq!(identity.idempotency_key, backup_idempotency_key(operation));
        assert_eq!(decoded, request);
        assert_eq!(
            backup_operation_id(operation),
            backup_operation_id(match &decoded {
                StoreRequest::Backup { request } => &request.operation,
                other => panic!("backup frame decoded as {other:?}"),
            })
        );
        // The matching success response round-trips through a correlated
        // response frame.
        let response = backup_success_response(operation);
        let response_frame = eliot_store_api::response_frame(
            "connection-test",
            ProtocolVersion::CURRENT,
            Some(context.request_id.clone()),
            response.clone(),
        )
        .unwrap();
        let (response_id, decoded_response) = eliot_store_api::decode_response_frame(
            &response_frame,
            "connection-test",
            ProtocolVersion::CURRENT,
        )
        .unwrap();
        assert_eq!(response_id, context.request_id);
        assert_eq!(decoded_response, response);
    }

    // Envelope/payload coherence is enforced, not assumed: a tampered
    // envelope identity is a typed refusal, never a silent rebind.
    let StoreRequest::Backup { mut request } = backup_envelope(
        backup_context("request-975-a1-tampered"),
        StoreBackupOperation::Begin(begin.clone()),
    ) else {
        panic!("expected a backup envelope");
    };
    request.identity.idempotency_key = "idem-975-tampered".to_owned();
    assert!(matches!(
        request.validate(),
        Err(StoreError::InvalidField {
            field: "backup.identity",
            ..
        })
    ));

    // The frozen capability-denominator fixture pins the same eight rows plus
    // the reserved-write denominator row; every row must name the backup (or
    // reserved-write) capability exactly.
    let denominator = fixture_value("capability-denominator.json");
    assert_eq!(denominator["capability"], json!("store.backup"));
    let rows = denominator["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 9);
    for row in &rows[..8] {
        assert_eq!(row["capability"], json!("store.backup"));
        for column in [
            "port",
            "wire",
            "client",
            "composition",
            "backend",
            "response",
        ] {
            assert!(
                row[column].as_str().is_some_and(|text| !text.is_empty()),
                "denominator row is fully bound: {row}"
            );
        }
    }
    assert_eq!(rows[8]["capability"], json!("store.reserved_write"));

    // Client, composition, dispatch and backend symbols for every row are
    // pinned in production source (adaptation-checked in 975/18; asserted
    // here as the denominator's code half).
    let client_source =
        include_str!("../../../crates/kernel/eliot-kernel-service/src/store_backup_client.rs");
    let composition_source = include_str!("../src/lib.rs");
    let dispatch_source = include_str!("../src/request_dispatch.rs");
    let backup_dispatch_source = include_str!("../src/backup_dispatch.rs");
    for row in &rows[..8] {
        let client = row["client"].as_str().unwrap();
        let composition = row["composition"].as_str().unwrap();
        let method = composition.rsplit("::").next().unwrap();
        assert!(
            client_source.contains(&format!("fn {client}")),
            "client method exists: {client}"
        );
        assert!(
            composition_source.contains(&format!("fn {method}")),
            "composition delegation exists: {composition}"
        );
        assert!(
            backup_dispatch_source.contains(&format!(".{method}(")),
            "dispatch route calls composition once: {composition}"
        );
    }
    assert!(dispatch_source.contains("dispatch_backup"));
}

// WORK_UNIT_CASE: 975/2
#[test]
fn wire_wrappers_reuse_canonical_types_and_old_peers_refuse() {
    // A2: the backup wire wrappers reuse the #950 canonical types byte for
    // byte (no duplicate field/status family, no extensible op string) and
    // old or unsupported peers refuse unknown operations explicitly instead
    // of trial-decoding them.
    let begin = fixture_begin();
    let operation = StoreBackupOperation::Begin(begin.clone());
    let context = backup_context("request-975-a2");
    let request = backup_envelope(context, operation);
    let payload = serde_json::to_value(&request).unwrap();
    // The inner canonical document is embedded unchanged: the wrapper adds
    // the closed `backup_op` tag, never a second field family.
    let inner = serde_json::to_value(&begin).unwrap();
    let mut expected_operation = inner.clone();
    expected_operation["backup_op"] = json!("begin");
    assert_eq!(payload["request"]["operation"], expected_operation);
    assert_eq!(payload["op"], json!("backup"));

    // Closed catalogue: unknown top-level op tags are refused, not
    // trial-decoded.
    for tag in [
        "backup_future_x",
        "snapshot_begin",
        "Backup",
        "BACKUP",
        "apply_backup",
    ] {
        let mut hostile = payload.clone();
        hostile["op"] = json!(tag);
        assert!(
            serde_json::from_value::<StoreRequest>(hostile).is_err(),
            "unknown op tag refused: {tag}"
        );
    }
    // Closed backup-op catalogue: unknown `backup_op` tags are refused,
    // not trial-decoded — an old peer without the new operation fails
    // closed instead of guessing.
    for backup_tag in ["begin_future_x", "Begin", "BEGIN", "snapshot_begin"] {
        let mut hostile_op = payload.clone();
        hostile_op["request"]["operation"]["backup_op"] = json!(backup_tag);
        assert!(
            serde_json::from_value::<StoreRequest>(hostile_op).is_err(),
            "unknown backup op refused: {backup_tag}"
        );
    }
    // `deny_unknown_fields` on every canonical shape: an extra field anywhere
    // fails closed, including inside the backup envelope.
    let mut extended = payload.clone();
    extended["request"]["operation"]["future_field"] = json!(1);
    assert!(serde_json::from_value::<StoreRequest>(extended).is_err());
    assert!(
        serde_json::from_value::<SnapshotBeginRequest>(json!({
            "contract_version": {"major": 1, "minor": 0, "patch": 0},
            "operation": inner["operation"],
            "source": inner["source"],
            "scope": inner["scope"],
            "event_interval": inner["event_interval"],
            "denominator": inner["denominator"],
            "bounds": inner["bounds"],
            "expires_at_unix_ms": inner["expires_at_unix_ms"],
            "privacy_proof_refs": inner["privacy_proof_refs"],
            "unknown_future": true,
        }))
        .is_err()
    );
    // Unsupported page/completeness states stay explicit: only COMPLETE
    // satisfies an is-complete check; PARTIAL/EXPIRED/UNSUPPORTED never do.
    assert!(SnapshotCompleteness::Complete.is_complete());
    for state in [
        SnapshotCompleteness::Partial,
        SnapshotCompleteness::Expired,
        SnapshotCompleteness::Unsupported,
    ] {
        assert!(!state.is_complete());
    }
    // Wire version policy: frames are built only at CURRENT; a mismatched
    // protocol version on the same bytes is a different session, not a
    // compatible peer (decode binds the negotiated version).
    let frame = backup_frame(
        &backup_context("request-975-a2b"),
        StoreBackupOperation::Begin(begin),
    );
    assert_eq!(frame.protocol_version, ProtocolVersion::CURRENT);
}

// WORK_UNIT_CASE: 975/3
#[tokio::test]
async fn real_client_sends_typed_backup_operation_over_transport() {
    // A3: the actual `EbpCanonicalStoreClient` sends the correct typed
    // backup operation over its existing transport. The scripted fake only
    // captures frames and answers the production handshake/readiness shape;
    // the request bytes are produced by the real client method.
    let begin = fixture_begin();
    let operation = StoreBackupOperation::Begin(begin.clone());
    let (client, log) = connected_client(backup_success_response(&operation)).await;
    let context = backup_context("request-975-a3");
    let handle = client
        .backup_begin(&context, begin.clone())
        .await
        .expect("scripted backup begin succeeds");
    // The returned handle carries the real begin binding the client checked:
    // the digest recomputed from the admitted begin request.
    assert_eq!(handle, admitted_handle(&begin));

    let sends = sent_backup_requests(&log);
    // Two sends belong to connect (readiness); the backup call adds exactly
    // one more typed operation.
    assert_eq!(sends.len(), 2, "connect + exactly one backup send");
    let (request_id, identity, request) = &sends[1];
    assert_eq!(request_id, &context.request_id);
    let StoreRequest::Backup { request: envelope } = request else {
        panic!("client sent a non-backup operation: {request:?}");
    };
    assert_eq!(envelope.context, context);
    let StoreBackupOperation::Begin(sent) = &envelope.operation else {
        panic!("client sent the wrong backup operation");
    };
    assert_eq!(sent, &begin);
    assert_eq!(identity.idempotency_key, begin.operation.idempotency_key);
    assert_eq!(
        identity.request.state_fence,
        client.requirement().state_fence
    );
}

// WORK_UNIT_CASE: 975/4
#[test]
fn production_dispatch_routes_backup_to_exactly_one_composition_call() {
    // A4: the actual production Store dispatch calls the accepted adapter
    // port exactly once per backup operation. No composition instance can be
    // built in this suite (it needs real credentials and process leases), so
    // this is the pure-routing proof over the production dispatch target
    // mapping: one `Backup` arm, one `dispatch_backup` route, exactly one
    // composition call per operation, no retry/loop/second-ledger text, and
    // no fallback to any other operation. Live re-verification (counting real
    // adapter-port calls behind `StoreComposition::new`) belongs to the
    // isolated live run in 975/17 and the final #964 class-specific proof.
    let dispatch = include_str!("../src/request_dispatch.rs");
    let route = include_str!("../src/backup_dispatch.rs");
    let composition = include_str!("../src/lib.rs");

    assert_eq!(
        dispatch.matches("dispatch_backup").count(),
        1,
        "exactly one Backup dispatch route"
    );
    for method in [
        "backup_begin",
        "backup_page",
        "backup_end",
        "backup_prepare_destination",
        "backup_restore_batch",
        "backup_validate",
        "backup_status",
        "backup_reconcile",
    ] {
        assert_eq!(
            route.matches(&format!(".{method}(")).count(),
            1,
            "exactly one composition call for {method}"
        );
        assert!(
            composition.contains(&format!("fn {method}")),
            "composition owns the delegation target: {method}"
        );
    }
    let lowered = route.to_lowercase();
    assert!(!lowered.contains("retry"), "no retry on the backup route");
    assert!(!lowered.contains("loop"), "no loop on the backup route");
    assert!(
        !route.contains("Request::Apply")
            && !route.contains("apply_prepared")
            && !route.contains("apply_reserved_write"),
        "no Apply or reserved-write fallback on the backup route"
    );
    assert!(
        !route.contains("todo!") && !route.contains("unimplemented!"),
        "no unfinished route arms"
    );
}

// WORK_UNIT_CASE: 975/5
#[test]
fn admission_rejects_before_any_backend_call() {
    // A5: root principal/session/capability/fence rejection precedes any
    // backend call. No provider, adapter, or composition instance exists in
    // this suite, so any refusal here is structurally before dispatch:
    // `validate_request_frame` returns the typed request on success and never
    // invokes a backend itself.
    let begin = fixture_begin();
    let context = backup_context("request-975-a5");
    let operation = StoreBackupOperation::Begin(begin.clone());
    let frame = backup_frame(&context, operation.clone());

    // Capability gate: the handshake withholds the unadvertised backup
    // capability, so the frame is refused before dispatch.
    let (mut session, _) = admitted_session(&[]);
    assert_eq!(
        validate_request_frame(&mut session, &frame),
        Err(format!("capability is not admitted: {BACKUP_CAPABILITY}"))
    );
    // Offering the capability does not enable it either.
    let (mut offered, hello) = {
        let config = config();
        let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
        let frame = client_hello_frame(&config, &[BACKUP_CAPABILITY]);
        let (session, hello) =
            admit_handshake(frame, TransportLimits::default(), &config, &identity).unwrap();
        (session, hello)
    };
    assert!(
        !hello
            .allowed_capabilities
            .contains(&BACKUP_CAPABILITY.to_owned())
    );
    assert_eq!(
        validate_request_frame(&mut offered, &frame),
        Err(format!("capability is not admitted: {BACKUP_CAPABILITY}"))
    );

    // Fence gate: an identity outside the handshake fence is refused even
    // before the capability check could matter.
    let mut tampered_context = context.clone();
    tampered_context.state_fence = diverged_fence();
    let tampered = backup_frame(&tampered_context, operation.clone());
    let (mut fenced, _) = admitted_session(&[]);
    assert_eq!(
        validate_request_frame(&mut fenced, &tampered),
        Err("request identity state fence does not match the handshake fence".to_owned())
    );

    // Session gate: a frame from another connection is outside the
    // negotiated session.
    let mut foreign = frame.clone();
    foreign.connection_id = "foreign-connection".to_owned();
    let (mut sessioned, _) = admitted_session(&[]);
    assert_eq!(
        validate_request_frame(&mut sessioned, &foreign),
        Err("request frame is outside the negotiated EBP session".to_owned())
    );

    // Principal/generation gate: a generation-diverged hello grants no
    // capability at all.
    let config = config();
    let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
    let hello_frame = client_hello_frame(&config, &[]);
    let ProtocolPayload::Json(payload) = hello_frame.payload.clone() else {
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
        .is_err()
    );
}

// WORK_UNIT_CASE: 975/6
#[tokio::test]
async fn client_rejects_wrong_response_kind_and_misbound_receipts() {
    // A6: wrong response kind, source, destination, snapshot, member, or
    // digest never satisfies the client. A valid frame carrying any
    // non-Backup response for `backup_begin` is a contract error (never
    // success), and the semantic validators reject misbound snapshot,
    // destination, member, and digest evidence.
    let begin = fixture_begin();
    for (label, response) in [
        (
            "readiness",
            StoreResponse::Readiness {
                receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
            },
        ),
        (
            "empty receipt lookup",
            StoreResponse::Receipt { receipt: None },
        ),
        (
            "unknown outcome",
            StoreResponse::Unknown {
                operation_id: begin.operation.operation_id.clone(),
                reason: "unknown-975".to_owned(),
            },
        ),
    ] {
        let (client, _) = connected_client(response).await;
        let context = backup_context(&format!("request-975-a6-{label}"));
        assert!(
            client.backup_begin(&context, begin.clone()).await.is_err(),
            "{label} must never satisfy a backup begin"
        );
    }

    // Misbound snapshot evidence: a page whose cursor belongs to another
    // handle, a batch whose schema or purge revision diverges from its
    // destination, and a reconciliation whose outcome contradicts its digests
    // are all refused by the real validators.
    let mut foreign_page = fixture_complete_page();
    foreign_page.cursor.handle_digest = "9".repeat(64);
    assert!(foreign_page.validate().is_err());
    let mut schema_split = fixture_batch();
    schema_split.target_schema = "eliot.store.other.v1".to_owned();
    assert!(schema_split.validate().is_err());
    let mut purge_split = fixture_batch();
    purge_split.purge_policy_revision = 8;
    assert!(purge_split.validate().is_err());
    let mut member_split = fixture_partial_page();
    member_split.members[0].content_digest = "not-a-digest".to_owned();
    assert!(member_split.validate().is_err());
    let mut conflicted = fixture_reconciliation();
    conflicted.outcome = eliot_store_api::ReconciliationOutcome::IdentityConflict;
    assert!(conflicted.validate().is_err());
}

// WORK_UNIT_CASE: 975/7
#[tokio::test]
async fn fresh_correlation_stays_distinct_from_stable_identity() {
    // A7: fresh transport correlation (`request_id`) and stable
    // mutation/reconciliation identity (`operation_id`, idempotency key,
    // request digest) remain distinct: two sends of the same operation carry
    // different request ids but the identical admitted identity.
    let begin = fixture_begin();
    let operation = StoreBackupOperation::Begin(begin.clone());
    let (client, log) = connected_client(backup_success_response(&operation)).await;
    for request_id in ["request-975-a7-first", "request-975-a7-second"] {
        client
            .backup_begin(&backup_context(request_id), begin.clone())
            .await
            .expect("scripted begin succeeds");
    }
    let sends = sent_backup_requests(&log);
    assert_eq!(sends.len(), 3, "connect + two backup sends");
    let (first_id, first_identity, first_request) = &sends[1];
    let (second_id, second_identity, second_request) = &sends[2];
    assert_ne!(first_id, second_id, "correlation is fresh per send");
    assert_ne!(
        first_identity.cancellation_id, second_identity.cancellation_id,
        "transport cancellation binds the fresh correlation"
    );
    for request in [first_request, second_request] {
        let StoreRequest::Backup { request: envelope } = request else {
            panic!("expected a backup operation");
        };
        assert_eq!(
            envelope.operation,
            StoreBackupOperation::Begin(begin.clone())
        );
    }
    assert_eq!(
        backup_operation_id(match first_request {
            StoreRequest::Backup { request } => &request.operation,
            _ => unreachable!(),
        }),
        Some(begin.operation.operation_id.clone())
    );
    assert_eq!(
        first_identity.idempotency_key, second_identity.idempotency_key,
        "stable mutation identity is unchanged"
    );
    // Same-operation reconciliation binds the stable identity, not the fresh
    // correlation: equal digests replay, changed digests conflict.
    let mut changed = begin.operation.clone();
    changed.canonical_request_hash = "d".repeat(64);
    assert_eq!(
        eliot_store_api::reconcile_same_operation(&begin.operation, &begin.operation).unwrap(),
        eliot_store_api::ReconciliationOutcome::ReplayIdentity
    );
    assert_eq!(
        eliot_store_api::reconcile_same_operation(&begin.operation, &changed).unwrap(),
        eliot_store_api::ReconciliationOutcome::IdentityConflict
    );
}

// WORK_UNIT_CASE: 975/8
#[tokio::test]
async fn pre_send_refusal_is_distinct_from_post_send_possible_effect() {
    // A8: before-send refusal (typed validation error, zero frames sent, no
    // possible effect) is distinct from post-send possible effect
    // (transport unknown after the send, reconciled by exact identity, never
    // success). Timeout/disconnect after the send is unknown for the same
    // admitted operation.
    let begin = fixture_begin();
    let operation = StoreBackupOperation::Begin(begin.clone());

    // Before send: a fence-diverged context is refused with zero new sends.
    let (client, log) = connected_client(backup_success_response(&operation)).await;
    let baseline = sent_backup_requests(&log).len();
    let mut refused_context = backup_context("request-975-a8-refused");
    refused_context.state_fence = diverged_fence();
    let refused = client
        .backup_begin(&refused_context, begin.clone())
        .await
        .expect_err("fence-diverged context is refused before send");
    assert_eq!(refused, StoreError::FenceMismatch);
    assert_eq!(
        sent_backup_requests(&log).len(),
        baseline,
        "refusal sends no frame"
    );

    // After send: an unknown delivery outcome is possible effect for the
    // admitted operation — MissingReceiptEnvelope, never success, one send.
    let (unknown_client, unknown_log) = connected_client_with_outcome(
        backup_success_response(&operation),
        DeliveryOutcome::UnknownOutcome,
        false,
    )
    .await;
    let unknown_baseline = sent_backup_requests(&unknown_log).len();
    let unknown = unknown_client
        .backup_begin(&backup_context("request-975-a8-unknown"), begin.clone())
        .await
        .expect_err("unknown delivery is possible effect, never success");
    assert_eq!(unknown, StoreError::MissingReceiptEnvelope);
    assert_eq!(
        sent_backup_requests(&unknown_log).len() - unknown_baseline,
        1,
        "exactly one send precedes the unknown outcome"
    );

    // Disconnect after the send is the same unknown for the same operation.
    let (dropped_client, dropped_log) = connected_client_with_outcome(
        backup_success_response(&operation),
        DeliveryOutcome::Delivered,
        true,
    )
    .await;
    let dropped_baseline = sent_backup_requests(&dropped_log).len();
    let dropped = dropped_client
        .backup_begin(&backup_context("request-975-a8-dropped"), begin.clone())
        .await
        .expect_err("disconnect after send is unknown, never success");
    assert_eq!(dropped, StoreError::MissingReceiptEnvelope);
    assert_eq!(
        sent_backup_requests(&dropped_log).len() - dropped_baseline,
        1
    );
}

// WORK_UNIT_CASE: 975/9
#[tokio::test]
async fn unknown_effect_triggers_no_new_operation_or_retry() {
    // A9: an unknown effect never triggers a new operation or an automatic
    // retry. The fake counts every frame: after one unknown send there is
    // exactly one mutating Begin frame and no second mutation under any
    // identity; the call itself stays an error.
    let begin = fixture_begin();
    let operation = StoreBackupOperation::Begin(begin.clone());
    let (client, log) = connected_client_with_outcome(
        backup_success_response(&operation),
        DeliveryOutcome::UnknownOutcome,
        false,
    )
    .await;
    let outcome = client
        .backup_begin(&backup_context("request-975-a9"), begin.clone())
        .await
        .expect_err("unknown stays unknown");
    assert_eq!(outcome, StoreError::MissingReceiptEnvelope);
    let mutating = sent_backup_requests(&log)
        .into_iter()
        .filter(|(_, _, request)| {
            matches!(
                request,
                StoreRequest::Backup {
                    request: StoreBackupRequest {
                        operation: StoreBackupOperation::Begin(_)
                            | StoreBackupOperation::Page { .. }
                            | StoreBackupOperation::End { .. }
                            | StoreBackupOperation::PrepareDestination(_)
                            | StoreBackupOperation::RestoreBatch(_),
                        ..
                    }
                }
            )
        })
        .count();
    // Only Backup mutations are counted, and readiness is not one of them.
    assert_eq!(mutating, 1, "no second mutation after unknown: {outcome}");
}

// WORK_UNIT_CASE: 975/10
#[tokio::test]
async fn delivery_acknowledgement_exit_and_liveness_never_prove_success() {
    // A10: transport Delivered, process liveness, or zero exit never
    // satisfies domain or durability proof. Every non-Backup response observed
    // after a Delivered send — including the explicit Unknown outcome — keeps
    // `backup_begin` an error; only the exact Backup response bound to the
    // admitted operation succeeds (proved in 975/3).
    let begin = fixture_begin();
    for (label, response) in [
        (
            "explicit unknown",
            StoreResponse::Unknown {
                operation_id: begin.operation.operation_id.clone(),
                reason: "unknown-975".to_owned(),
            },
        ),
        (
            "readiness observation",
            StoreResponse::Readiness {
                receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
            },
        ),
        (
            "absent receipt lookup",
            StoreResponse::Receipt { receipt: None },
        ),
        (
            "health-style mismatch",
            StoreResponse::ValidationSnapshot {
                snapshot: eliot_store_api::CanonicalValidationSnapshot {
                    state_fence: fence(),
                    revision_heads: vec![eliot_store_api::RevisionHead {
                        key: RevisionKey::new("rev-975-10").unwrap(),
                        revision: 1,
                        state_fence: fence(),
                    }],
                    validation_revision: 1,
                    observed_at_unix_ms: 1700000000000,
                },
            },
        ),
    ] {
        let (client, _) = connected_client(response).await;
        let error = client
            .backup_begin(
                &backup_context(&format!("request-975-a10-{label}")),
                begin.clone(),
            )
            .await
            .expect_err("delivery acknowledgement is not domain proof");
        assert_ne!(
            error.to_string(),
            "ok",
            "no success string is ever synthesized: {label}"
        );
    }
}

// WORK_UNIT_CASE: 975/11
#[test]
fn page_continuation_and_cumulative_bounds_hold_identity() {
    // A11: complete/partial/expired/unknown page states and cumulative-bound
    // identity are preserved: partial -> complete continuation validates,
    // every reversal, fork, or reset is refused, pages stay under the
    // begin-request bounds, and expired/unsupported receipts never pass a
    // completeness check.
    let begin = fixture_begin();
    assert!(begin.validate().is_ok());
    let partial = fixture_partial_page();
    let complete = fixture_complete_page();
    assert!(!partial.is_last);
    assert!(complete.is_last);
    assert!(complete.validate_continuation(&partial).is_ok());
    // Reversal, replay, and cross-handle forks are refused.
    assert!(partial.validate_continuation(&complete).is_err());
    assert!(partial.validate_continuation(&partial).is_err());
    let mut forked = complete.clone();
    forked.handle.snapshot_digest = "9".repeat(64);
    forked.cursor.handle_digest = "9".repeat(64);
    assert!(complete.validate_continuation(&forked).is_err());
    assert!(forked.validate_continuation(&partial).is_err());
    // Cumulative bounds never reset along a continuation.
    let mut reset = complete.clone();
    reset.cumulative_bytes = partial.cumulative_bytes - 1;
    assert!(reset.validate_continuation(&partial).is_err());
    let mut reset_members = complete.clone();
    reset_members.cursor.cumulative_members = 0;
    assert!(reset_members.validate_continuation(&partial).is_err());
    // Pages stay under the begin-request cumulative bounds; an oversized
    // page is refused against the capture that opened it.
    let mut oversized = complete.clone();
    oversized.cumulative_bytes = begin.bounds.max_bytes + 1;
    assert!(oversized.validate_for_begin(&begin).is_err());
    // The frozen fixtures carry illustrative digests, so the negative
    // binding is pinned here; the positive binding is proved by construction.
    assert!(complete.validate_for_begin(&begin).is_err());
    let mut bound = complete.clone();
    bound.handle.snapshot_digest = begin.compute_digest().unwrap();
    bound.cursor.handle_digest = bound.handle.snapshot_digest.clone();
    // The constructed page still fails only on cursor-chain details that the
    // re-digested handle cannot satisfy, never on the digest binding itself.
    assert!(bound.validate_for_begin(&begin).is_ok());
    // Expired and unsupported captures validate as shapes but never pass a
    // completeness check; unknown dispositions never prove success.
    let mut expired = fixture_end_receipt();
    expired.completeness = SnapshotCompleteness::Expired;
    assert!(expired.validate().is_ok());
    assert!(!expired.is_complete());
    let mut unsupported = fixture_end_receipt();
    unsupported.completeness = SnapshotCompleteness::Unsupported;
    assert!(unsupported.validate().is_ok());
    assert!(!unsupported.is_complete());
    let partial_receipt = SnapshotValidationReceipt {
        operation: begin.operation.clone(),
        handle: partial.handle.clone(),
        denominator: begin.denominator.clone(),
        resolved_members: 1,
        unresolved_members: 1,
        completeness: SnapshotCompleteness::Partial,
        disposition: eliot_store_api::StoreMutationDisposition::Partial,
    };
    assert!(partial_receipt.validate().is_ok());
    assert!(!partial_receipt.is_proven_success());
}

// WORK_UNIT_CASE: 975/12
#[test]
fn restore_requires_isolated_destination_and_current_evidence() {
    // A12: restore requires the admitted isolated destination and current
    // purge/reference evidence. Shape validators refuse every non-isolated
    // or stale binding; freshness of the external admission itself (the
    // admitted-at window and the live purge-policy revision) is enforced by
    // the real backend's restore gates and re-proved live in 975/17.
    let destination = fixture_destination();
    assert!(destination.validate().is_ok());
    let batch = fixture_batch();
    assert!(batch.validate().is_ok());

    // Non-isolated classes are refused even with well-formed evidence.
    for class in [
        DestinationClass::Active,
        DestinationClass::Source,
        DestinationClass::Foreign,
    ] {
        let mut non_isolated = destination.clone();
        non_isolated.destination_class = class;
        assert!(non_isolated.validate().is_err());
        let mut batch_split = batch.clone();
        batch_split.destination = non_isolated;
        assert!(batch_split.validate().is_err());
    }
    // The destination must differ from the source and the active
    // installation: restoring "into" the source is refused.
    let mut into_source = destination.clone();
    into_source.destination_id = into_source.source_store_id.clone();
    assert!(into_source.validate().is_err());
    let mut into_active = destination.clone();
    into_active.destination_id = into_active.source_installation_id.clone();
    assert!(into_active.validate().is_err());
    // Stale evidence is refused: purge revision and schema must match the
    // destination's current admission exactly, and revision expectations
    // must be present.
    let mut stale_purge = batch.clone();
    stale_purge.purge_policy_revision = 6;
    assert!(stale_purge.validate().is_err());
    let mut stale_schema = batch.clone();
    stale_schema.target_schema = "eliot.store.stale.v9".to_owned();
    assert!(stale_schema.validate().is_err());
    let mut no_heads = batch.clone();
    no_heads.expected_revision_heads.clear();
    assert!(no_heads.validate().is_err());
    let mut stale_evidence = destination.clone();
    stale_evidence.evidence.purge_policy_revision = 0;
    assert!(stale_evidence.validate().is_err());
    let mut blank_handle = destination.clone();
    blank_handle.evidence.admission_handle = "   ".to_owned();
    assert!(blank_handle.validate().is_err());
    // A well-formed value without current external admission still proves
    // nothing by itself: validation is shape-only, and the live backend
    // re-checks admission currency (admission-age window) before any effect.
    assert!(batch.validate().is_ok());
}

// WORK_UNIT_CASE: 975/13
#[tokio::test]
async fn verify_and_status_paths_cannot_restore_cut_over_or_unblock() {
    // A13: verify/status cannot restore, cut over, or unblock effects. The
    // fail-closed default port bodies validate inputs and then refuse without
    // applying anything; the production Validate/Status route never calls a
    // mutating restore entry point; and success-shaped receipts with
    // unknown/partial dispositions never prove success.
    let backend = DefaultBackupBackend;
    let batch = fixture_batch();
    // Validate-without-apply refuses with no effect; the error is typed
    // refusal, never success and never a manufactured receipt.
    let refused = IsolatedRestorePort::validate_restore(
        &backend,
        &backup_context("request-975-a13"),
        batch.clone(),
    )
    .await
    .expect_err("default validate performs no restore");
    assert_eq!(refused, StoreError::Unavailable);
    // The mutating entries refuse the same way: no alternate path imports.
    assert_eq!(
        IsolatedRestorePort::prepare_isolated_destination(
            &backend,
            &backup_context("request-975-a13b"),
            fixture_destination()
        )
        .await
        .expect_err("default prepare manufactures no evidence"),
        StoreError::UnknownOperation
    );
    assert_eq!(
        IsolatedRestorePort::restore_canonical_batch(
            &backend,
            &backup_context("request-975-a13c"),
            batch.clone()
        )
        .await
        .expect_err("default restore imports nothing"),
        StoreError::UnknownOperation
    );
    // Same-operation reconciliation is pure: two calls agree exactly and no
    // state changes between them.
    let first = backend
        .reconcile_operation(batch.operation.clone(), batch.operation.clone())
        .await
        .unwrap();
    let second = backend
        .reconcile_operation(batch.operation.clone(), batch.operation.clone())
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.outcome,
        eliot_store_api::ReconciliationOutcome::ReplayIdentity
    );
    // Routing proof: the Validate and Status arms never reach a mutating
    // restore entry point and know no cutover vocabulary.
    let route = include_str!("../src/backup_dispatch.rs");
    for arm in ["backup_validate", "backup_status"] {
        let start = route
            .find(&format!("fn {arm}"))
            .unwrap_or_else(|| route.find(arm).expect("validate/status route exists"));
        let window = &route[start..(start + route[start..].len().min(1200))];
        assert!(
            !window.contains("restore_canonical_batch"),
            "{arm} cannot restore"
        );
        assert!(
            !window.contains("prepare_isolated_destination") || arm == "backup_status",
            "{arm} cannot prepare a destination import"
        );
    }
    assert!(!route.to_lowercase().contains("cutover"), "no cutover path");
    assert!(!route.contains("unblock"), "no effect-unblock path");
    // The frozen status-report fixture names a closed outcome bound to the
    // operation and fence: it carries no restore/import/cutover vocabulary
    // and deserializes its load-bearing bindings into the real types.
    let status_report = fixture_value("backup-status-report.json");
    assert_eq!(status_report["phase"], json!("capture_closed"));
    assert_eq!(status_report["completeness"], json!("COMPLETE"));
    assert_eq!(status_report["reconciliation"], Value::Null);
    for forbidden in ["restore", "cutover", "unblock", "revive", "apply"] {
        assert!(
            !status_report.to_string().to_lowercase().contains(forbidden),
            "status report carries no import vocabulary: {forbidden}"
        );
    }
    let status_operation: OperationIdentity =
        serde_json::from_value(status_report["operation"].clone()).unwrap();
    assert_eq!(status_operation.operation_id.as_str(), "op-975-begin-1");
    let status_handle: SnapshotHandle =
        serde_json::from_value(status_report["handle"].clone()).unwrap();
    assert!(status_handle.validate().is_ok());
    // Unknown or partial dispositions never validate as proven success.
    let mut unknown = fixture_restore_receipt();
    unknown.disposition = eliot_store_api::StoreMutationDisposition::Unknown;
    unknown.unresolved_members = 1;
    unknown.resolved_members = 1;
    assert!(!unknown.is_proven_success());
}

// WORK_UNIT_CASE: 975/14
#[tokio::test]
async fn absent_default_implementation_advertises_nothing_and_fails_closed() {
    // A14: an absent/default implementation cannot advertise working
    // capability or return success. The capability stays out of the
    // advertised catalogue, the handshake withholds it even when offered,
    // and every default port body refuses without effects.
    assert!(!CAPABILITIES.contains(&BACKUP_CAPABILITY));
    assert!(!CAPABILITIES.contains(&"store.backup.future"));
    let config = config();
    let identity = StoreHandshakeIdentity::new("manifest-test", json!({}));
    let frame = client_hello_frame(&config, &[BACKUP_CAPABILITY, "store.future_x"]);
    let (_, hello) =
        admit_handshake(frame, TransportLimits::default(), &config, &identity).unwrap();
    assert_eq!(
        hello.allowed_capabilities,
        CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
        "only the exact admitted set is enabled"
    );
    assert!(
        !hello
            .allowed_capabilities
            .contains(&BACKUP_CAPABILITY.to_owned())
    );

    let backend = DefaultBackupBackend;
    let context = backup_context("request-975-a14");
    assert_eq!(
        CanonicalSnapshotPort::begin_snapshot(&backend, &context, fixture_begin())
            .await
            .expect_err("unimplemented capture opens nothing"),
        StoreError::Unavailable
    );
    let page = fixture_partial_page();
    assert_eq!(
        CanonicalSnapshotPort::read_snapshot_page(
            &backend,
            &context,
            page.handle.clone(),
            page.cursor.clone()
        )
        .await
        .expect_err("unimplemented page reads nothing"),
        StoreError::Unavailable
    );
    assert_eq!(
        CanonicalSnapshotPort::end_snapshot(&backend, &context, page.handle)
            .await
            .expect_err("unimplemented close receipts nothing"),
        StoreError::Unavailable
    );
}

// WORK_UNIT_CASE: 975/15
#[test]
fn malformed_duplicate_oversized_wire_refused_and_canaries_redacted() {
    // A15: malformed/duplicate/oversized wire is refused (duplicates are
    // absorbed by the bounded replay ledger, never re-executed) and
    // credential/query/payload canary strings never leak into errors.
    let canaries = fixture_value("wire-canaries.json");
    let probes: Vec<String> = ["credential_probes", "query_probes", "payload_probes"]
        .into_iter()
        .flat_map(|group| {
            canaries[group]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(probes.len() >= 9);
    let mut observed_errors = Vec::new();

    // Malformed wire samples are refused at decode, never trial-decoded.
    for sample in canaries["malformed_wire_samples"].as_array().unwrap() {
        let text = sample.as_str().unwrap();
        let parsed: Result<Value, _> = serde_json::from_str(text);
        match parsed {
            Ok(value) => {
                let decoded = serde_json::from_value::<StoreRequest>(value);
                assert!(decoded.is_err(), "malformed sample refused: {text}");
                observed_errors.push(decoded.expect_err("refused").to_string());
            }
            Err(error) => observed_errors.push(error.to_string()),
        }
    }
    // Oversized wire is refused: 300 revision-head keys exceed the bounded
    // catalogue, and a 1025-member denominator exceeds the snapshot ceiling.
    let many_keys = (0..300)
        .map(|index| eliot_store_api::RevisionKey::new(format!("rev-975-over-{index}")).unwrap())
        .collect::<Vec<_>>();
    let oversized_heads = eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        RequestId::new("request-975-a15-over").unwrap(),
        identity_for(&backup_context("request-975-a15-over"), "idem-975-a15-over"),
        StoreRequest::RevisionHeads { keys: many_keys },
    );
    assert!(oversized_heads.is_err());
    observed_errors.push(oversized_heads.expect_err("oversized").to_string());
    let mut oversized_denominator = fixture_begin().denominator.clone();
    oversized_denominator.members = (0..canaries["oversized_member_count"].as_u64().unwrap())
        .map(|index| eliot_store_api::SnapshotMember {
            member_id: format!("member-975-over-{index}"),
            member_type: eliot_store_api::SnapshotMemberType::Record,
            content_digest: "c".repeat(64),
            residency: eliot_store_api::BlobResidency {
                domain: eliot_store_api::BlobResidencyDomain::InlineCanonical,
                residency_digest: "d".repeat(64),
                byte_count: 8,
            },
            reference_digest: None,
        })
        .collect();
    let oversized_denominator_error = oversized_denominator
        .validate()
        .expect_err("oversized denominator refused");
    observed_errors.push(oversized_denominator_error.to_string());

    // Duplicate member ids are refused inside one page/denominator, while a
    // duplicate transport frame is absorbed by the replay ledger (same
    // request admitted, never a second execution).
    let duplicate_ids: Vec<String> = canaries["duplicate_member_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let mut duplicated = fixture_partial_page();
    duplicated.members.push(duplicated.members[0].clone());
    duplicated.members[1]
        .member_id
        .clone_from(&duplicate_ids[0]);
    duplicated.members[0]
        .member_id
        .clone_from(&duplicate_ids[1]);
    let duplicate_error = duplicated.validate().expect_err("duplicate refused");
    assert_eq!(
        duplicate_error,
        StoreError::Duplicate {
            field: "snapshot.members"
        }
    );
    observed_errors.push(duplicate_error.to_string());
    let (mut session, _) = admitted_session(&[]);
    let ready_context = backup_context("request-975-a15-dup");
    let ready_frame = eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        ready_context.request_id.clone(),
        identity_for(&ready_context, "idem-975-a15-dup"),
        StoreRequest::Readiness,
    )
    .unwrap();
    let first = validate_request_frame(&mut session, &ready_frame).unwrap();
    let second = validate_request_frame(&mut session, &ready_frame).unwrap();
    assert_eq!(first, second, "duplicate frame replays, never re-executes");

    // Hostile values carrying canary secrets fail closed without echoing the
    // secrets: every observed error is scanned for every probe string.
    let mut hostile_page = fixture_partial_page();
    hostile_page.handle.consistency_point = String::new();
    hostile_page.members[0].member_id = probes[0].clone();
    observed_errors.push(
        hostile_page
            .validate()
            .expect_err("blank refused")
            .to_string(),
    );
    let mut hostile_destination = fixture_destination();
    hostile_destination.destination_id = String::new();
    hostile_destination.evidence.admission_handle = probes[1].clone();
    observed_errors.push(
        hostile_destination
            .validate()
            .expect_err("blank refused")
            .to_string(),
    );
    let mut hostile_unknown = serde_json::to_value(backup_envelope(
        backup_context("request-975-a15-unknown"),
        StoreBackupOperation::Begin(fixture_begin()),
    ))
    .unwrap();
    hostile_unknown["request"]["operation"]["injected"] = json!(probes[2].clone());
    hostile_unknown["request"]["operation"]["note"] = json!(probes[3].clone());
    observed_errors.push(
        serde_json::from_value::<StoreRequest>(hostile_unknown)
            .expect_err("unknown field refused")
            .to_string(),
    );
    for error in &observed_errors {
        for probe in &probes {
            assert!(
                !error.contains(probe),
                "error text must never carry canary material"
            );
        }
    }
}

// WORK_UNIT_CASE: 975/16
#[test]
fn reserved_write_dreamer_and_ordinary_operations_stay_compatible() {
    // A16: all preexisting Dreamer, ordinary, and #991 reserved-write
    // operations remain compatible: the reserved-write denominator fixture
    // validates, its capability and dispatch arm are unchanged, ordinary
    // variants keep flowing, and no capability confusion or unreserved
    // bypass appears.
    let reserved: ReservedWriteRequest = fixture_typed("reserved-write-denominator.json");
    assert!(reserved.validate().is_ok());
    let wire = StoreRequest::ReservedWrite {
        request: reserved.clone(),
    };
    assert_eq!(wire.capability(), "store.reserved_write");
    assert!(wire.validate().is_ok());
    let frame = eliot_store_api::request_frame(
        "connection-test",
        ProtocolVersion::CURRENT,
        reserved.context.request_id.clone(),
        identity_for(
            &reserved.context,
            &reserved.transition.identity.idempotency_key,
        ),
        wire,
    )
    .unwrap();
    let (_, _, decoded) = eliot_store_api::decode_request_frame(&frame).unwrap();
    assert!(matches!(decoded, StoreRequest::ReservedWrite { .. }));

    // The reserved-write capability stays declared-but-unadvertised and the
    // session gate still refuses it before dispatch while ordinary
    // operations keep flowing.
    assert!(!CAPABILITIES.contains(&"store.reserved_write"));
    let (mut session, _) = admitted_session(&[]);
    assert_eq!(
        validate_request_frame(&mut session, &frame),
        Err("capability is not admitted: store.reserved_write".to_owned())
    );
    for (label, request) in [
        ("readiness", StoreRequest::Readiness),
        (
            "apply",
            StoreRequest::Apply {
                context: context_991("request-975-a16-apply"),
                transition: transition_991(),
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
            },
        ),
        (
            "receipt",
            StoreRequest::Receipt {
                operation_id: OperationId::new("op-991-d1").unwrap(),
            },
        ),
        ("validation snapshot", StoreRequest::ValidationSnapshot),
    ] {
        let key = format!("idem-975-a16-{label}");
        let context = match &request {
            StoreRequest::Apply { context, .. } => context.clone(),
            _ => backup_context(&format!("request-975-a16-{label}")),
        };
        let frame = eliot_store_api::request_frame(
            "connection-test",
            ProtocolVersion::CURRENT,
            context.request_id.clone(),
            identity_for(&context, &key),
            request,
        )
        .unwrap();
        assert!(
            validate_request_frame(&mut session, &frame).is_ok(),
            "ordinary {label} admission is unchanged by backup registration"
        );
    }

    // Dreamer capability family is intact: all twelve per-operation
    // capabilities remain advertised, and backup registration adds none.
    assert_eq!(
        CAPABILITIES
            .iter()
            .filter(|capability| capability.starts_with("store.dreamer_job."))
            .count(),
        12
    );
    assert_eq!(CAPABILITIES.len(), 22);
    assert!(
        !CAPABILITIES
            .iter()
            .any(|capability| capability.contains("backup"))
    );
}

// WORK_UNIT_CASE: 975/17
#[test]
fn live_windows_capture_and_isolated_restore_through_real_adapter() {
    // A17: actual supported-Windows authenticated Kernel-client ->
    // Store-process capture and isolated restore through the real adapter,
    // including disconnect/reconciliation and complete cleanup. Requires the
    // approved isolated #907/#909/#911 environment with current same-build
    // processes; without it the proof stays open (fail-open, never
    // skipped-to-green).
    let live = std::env::var("ELIOT_BACKUP_EDGE_LIVE").as_deref() == Ok("1");
    if !live {
        panic!("environment missing: real proof open");
    }
    let config_path =
        std::env::var("ELIOT_BACKUP_EDGE_LIVE_CONFIG").expect("live config path is set");
    let bytes = std::fs::read(&config_path).expect("live config is readable");
    let config: StoreLaunchConfig = serde_json::from_slice(&bytes).expect("live config decodes");
    let composition =
        eliot_store_surreal::StoreComposition::new(&config).expect("real composition builds");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("live tokio runtime");
    runtime.block_on(async {
        let context = backup_context("request-975-a17-live");
        // Capture through the real composition: begin, page, end.
        let handle = composition
            .backup_begin(&context, fixture_begin())
            .await
            .expect("live begin snapshots");
        let page = composition
            .backup_page(
                &context,
                handle.clone(),
                SnapshotCursor {
                    handle_digest: handle.snapshot_digest.clone(),
                    page_index: 0,
                    cumulative_members: 0,
                    cumulative_bytes: 0,
                },
            )
            .await
            .expect("live page reads");
        assert_eq!(page.handle.snapshot_digest, handle.snapshot_digest);
        let end = composition
            .backup_end(&context, handle.clone())
            .await
            .expect("live end receipts");
        assert!(end.is_complete());
        // Isolated restore through the real adapter, then validation and
        // reconciliation of the same operation.
        let evidence = composition
            .backup_prepare_destination(&context, fixture_destination())
            .await
            .expect("live destination prepares");
        assert!(!evidence.admission_handle.is_empty());
        let restored = composition
            .backup_restore_batch(&context, fixture_batch())
            .await
            .expect("live batch restores into isolation");
        assert!(restored.is_proven_success());
        let validated = composition
            .backup_validate(&context, fixture_batch())
            .await
            .expect("live validate re-checks without importing");
        assert!(validated.is_proven_success());
        let reconciliation = composition
            .backup_reconcile(end.operation.clone(), end.operation.clone())
            .await
            .expect("live reconcile binds the same operation");
        assert_eq!(
            reconciliation.outcome,
            eliot_store_api::ReconciliationOutcome::ReplayIdentity
        );
        // Disconnect/reconciliation discipline: dropping the composition
        // here releases every lease; the isolated destination is test-scoped
        // and removed by the environment harness after this process exits.
    });
    drop(composition);
    drop(config_path);
    drop(bytes);
}

// WORK_UNIT_CASE: 975/18
#[test]
fn source_api_diff_guard_excludes_alternate_paths_and_half_registration() {
    // A18: source/API/diff guard. No alternate transport/client/database/
    // binary import in the Kernel backup client, no Apply fallback in the
    // backup arms, every preexisting dispatch arm still present, and the
    // wire variant plus all eight client methods, eight composition methods,
    // and all eighteen case markers present — a half-registered wire
    // candidate fails this case.
    let wire = include_str!("../../../crates/storage/eliot-store-api/src/wire.rs");
    let backup_client =
        include_str!("../../../crates/kernel/eliot-kernel-service/src/store_backup_client.rs");
    let kernel_client =
        include_str!("../../../crates/kernel/eliot-kernel-service/src/store_client.rs");
    let route = include_str!("../src/backup_dispatch.rs");
    let dispatch = include_str!("../src/request_dispatch.rs");
    let composition = include_str!("../src/lib.rs");
    let suite = include_str!("backup_store_edge.rs");

    // No alternate transport/client/database/binary import in Kernel backup
    // client code: the client reuses the existing bounded machinery.
    for source in [backup_client, kernel_client] {
        let lowered = source.to_lowercase();
        for forbidden in [
            "surrealdb",
            "surreal::",
            "surrealstoreadapter",
            "rusqlite",
            "sqlx",
            "opendal",
            "aws-sdk",
            "std::process::command",
            "tokio::process::command",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "forbidden Kernel backup import: {forbidden}"
            );
        }
    }
    assert!(!backup_client.contains("todo!"));
    assert!(!backup_client.contains("unimplemented!"));

    // No Apply fallback or semantic duplication in the backup arms.
    assert!(!route.contains("Request::Apply"));
    assert!(!route.contains("apply_prepared"));
    assert!(!route.contains("apply_reserved_write"));
    assert!(!route.to_lowercase().contains("generic json dispatch"));
    assert!(
        !route.contains("query("),
        "no query path on the backup route"
    );

    // Every preexisting dispatch arm is still present beside the new one.
    for arm in [
        "Request::Health",
        "Request::Readiness",
        "Request::Named",
        "Request::Apply",
        "Request::ReservedWrite",
        "Request::Receipt",
        "Request::RevisionHeads",
        "Request::OrderingHeads",
        "Request::ValidationSnapshot",
        "Request::Recovery",
        "Request::InitializeGenesis",
        "Request::DreamerJob",
        "Request::Backup",
    ] {
        assert!(dispatch.contains(arm), "dispatch arm present: {arm}");
    }

    // The wire candidate is fully registered: variant, capability, and
    // validation/conversion arms.
    assert!(wire.contains("CAPABILITY_STORE_BACKUP"));
    assert!(wire.contains("store.backup"));
    assert!(wire.contains("Backup"));
    assert!(wire.contains("deny_unknown_fields"));

    // All eight client methods, all eight composition delegations, and all
    // eighteen case markers are present.
    for method in [
        "backup_begin",
        "backup_page",
        "backup_end",
        "backup_prepare_destination",
        "backup_restore_batch",
        "backup_validate",
        "backup_status",
        "backup_reconcile",
    ] {
        assert!(
            backup_client.contains(&format!("fn {method}")),
            "client method present: {method}"
        );
        assert!(
            kernel_client.contains(method),
            "kernel delegation present: {method}"
        );
        assert!(
            composition.contains(&format!("fn {method}")),
            "composition method present: {method}"
        );
    }
    // The marker needle is split so these assertion lines do not count
    // themselves as case markers.
    let needle = concat!("WORK_UNIT_CASE: 975", "/");
    assert_eq!(
        suite.matches(needle).count(),
        18,
        "exactly eighteen case markers"
    );
    for case in 1..=18 {
        assert!(
            suite.contains(&format!("{needle}{case}")),
            "case marker present: 975/{case}"
        );
    }
}
