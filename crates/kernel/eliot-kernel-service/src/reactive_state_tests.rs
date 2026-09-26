//! Front-door tests for canonical reactive state (issue #1941 C4).
//!
//! A real `KernelService` driven to `Ready` binds the session against live
//! authority; a scripted `CanonicalStoreClient` fake (manufactured frames,
//! never admission authority) proves the handler seam: ledger and snapshot
//! writes return bound receipts with read-back revisions, exact-identity
//! reconcile replays without a second mutation, changed bytes conflict,
//! fences bind, and read projections preserve explicit absence. Backend
//! transition semantics are proven through the adapter suites.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, EpochId, EpochLineageId, OperationId,
    ProductId, RequestId, ResourceGeneration, SourceId, StateFence, TransactionSequence,
};
use eliot_platform::{KernelActivationNonce, PlatformHandle};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling,
    ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, CanonicalValidationSnapshot, CommitId,
    NamedReadOperation, NamedReadRequest, OperationIdentity, OrderingHead, OrderingScopeId,
    RequestMeta, Resubmission, RevisionHead, RevisionKey, ScopeId, ScopeRevisionView, StoreError,
    StoreHealth, TransitionClass, WriteReceipt, WriteReceiptStatus, canonical_request_hash,
    generated_operation_manifests, operation_manifest_set_digest,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::reactive_state::{
    AuthenticatedReactiveSession, ReactiveLedgerReadRequest, ReactiveLedgerRequest,
    ReactiveServiceError, ResourceSnapshotReadRequest, ResourceSnapshotRequest,
    build_reactive_ledger_transition_for_test, build_reactive_snapshot_transition_for_test,
    handle_reactive_ledger_read, handle_reactive_ledger_request, handle_resource_snapshot_read,
    handle_resource_snapshot_request, reconcile_reactive_state,
};
use super::{KernelService, KernelServiceState};
use crate::{
    HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
    HostProcessBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
    ProcessObservation, RestartBudget,
};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_SEQUENCE: u64 = 4;
const GENERATION: u64 = 7;
const CONTRACT: &str = "eliot.agent-bridge.reactive-injection-receipts/v1";

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).expect("valid test handle")
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn live_generation() -> ResourceGeneration {
    ResourceGeneration::new(GENERATION).expect("non-zero test generation")
}

fn live_fence() -> StateFence {
    StateFence::new(test_epoch(EPOCH_SEQUENCE), live_generation())
}

fn ledger_json() -> String {
    serde_json::to_string(&json!({
        "contract": CONTRACT,
        "next_item_seq": 1,
        "next_receipt_seq": 0,
        "items": {},
        "receipts": {},
    }))
    .expect("fixture serializes")
}

fn candidate() -> HostKernelCandidateBinding {
    HostKernelCandidateBinding {
        installation_id: handle("installation-1"),
        host_epoch: AuthorityEpoch::new(1).expect("non-zero test epoch"),
        kernel_epoch: test_epoch(EPOCH_SEQUENCE),
        activation_id: handle("activation-1"),
        artifact_hash: handle("artifact-1"),
        config_hash: handle("config-1"),
        job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
        pipe_identity: handle("\\\\.\\pipe\\eliot-kernel-test"),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
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
        supervision_incarnation: SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-1".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-1".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-1".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-1".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-1".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-epoch-1".to_owned(),
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
        .expect("valid test incarnation"),
        restart_budget: RestartBudget::new(1, 1).expect("valid test budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

fn permit(candidate: &HostKernelCandidateBinding) -> KernelActivationPermit {
    KernelActivationPermit {
        operation_id: handle("activation-operation-1"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("journal-transaction-1"),
        journal_sequence: 7,
        generation: live_generation(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
            .expect("valid test nonce"),
    }
}

fn ready_service() -> KernelService {
    let mut service = KernelService::new([7; 32], 2, 4).expect("test service");
    let candidate = candidate();
    let permit = permit(&candidate);
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("handoff");
    let activation = service
        .activate_permit(&permit, live_generation(), "c".repeat(64))
        .expect("activation");
    service
        .publish_ready(KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process: ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("process-evidence")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ready-evidence")],
        })
        .expect("ready");
    assert_eq!(service.state(), KernelServiceState::Ready);
    service
}

fn session(service: &KernelService) -> AuthenticatedReactiveSession {
    AuthenticatedReactiveSession::bind(service, "reactive-peer:test").expect("test session")
}

fn context() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-reactive-1").expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-reactive").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: live_fence(),
        clock: ClockReading::default(),
    }
}

fn ledger_request(tag: &str) -> ReactiveLedgerRequest {
    ReactiveLedgerRequest {
        operation: OperationIdentity {
            operation_id: OperationId::new(format!("op-reactive-{tag}")).expect("operation"),
            idempotency_key: format!("idem-reactive-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        context: context(),
        state_fence: live_fence(),
        session_id: "session-live-1".to_owned(),
        ledger_json: ledger_json(),
    }
}

fn snapshot_request(tag: &str) -> ResourceSnapshotRequest {
    ResourceSnapshotRequest {
        operation: OperationIdentity {
            operation_id: OperationId::new(format!("op-snapshot-{tag}")).expect("operation"),
            idempotency_key: format!("idem-snapshot-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        context: context(),
        state_fence: live_fence(),
        uri: "eliot://report/live-1".to_owned(),
        content: b"canonical report bytes".to_vec(),
    }
}

fn seal_ledger(request: &mut ReactiveLedgerRequest) {
    let (transition, _) = build_reactive_ledger_transition_for_test(request).expect("transition");
    let view = CanonicalRequestView::from_apply(&request.context, &transition, &[], &[]);
    request.operation.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
}

fn seal_snapshot(request: &mut ResourceSnapshotRequest) {
    let (transition, _, _) =
        build_reactive_snapshot_transition_for_test(request).expect("transition");
    let view = CanonicalRequestView::from_apply(&request.context, &transition, &[], &[]);
    request.operation.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
}

fn authority_envelope(operation: &OperationIdentity, fence: &StateFence) -> ReceiptEnvelope {
    let request_id = RequestId::new("resolve-request").expect("request id");
    let metadata = RequestMeta {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-reactive").expect("product"),
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
            resource_generation: live_generation(),
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
            operation_id: operation.operation_id.clone(),
            request_id,
            idempotency_key: operation.idempotency_key.clone(),
            operation_kind: "reactive.test".to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-owner-1").expect("authority"),
            authority_owner: "owner-1".to_owned(),
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

/// Scripted store double: manufactured frames only, never admission authority.
struct FakeStore {
    receipts: Mutex<BTreeMap<String, WriteReceipt>>,
    apply_result: Mutex<Option<Result<WriteReceipt, StoreError>>>,
    read_payload: Mutex<Value>,
    apply_calls: AtomicUsize,
}

impl FakeStore {
    fn new(read_payload: Value) -> Self {
        Self {
            receipts: Mutex::new(BTreeMap::new()),
            apply_result: Mutex::new(None),
            read_payload: Mutex::new(read_payload),
            apply_calls: AtomicUsize::new(0),
        }
    }

    fn store_receipt(&self, receipt: WriteReceipt) {
        self.receipts
            .lock()
            .expect("fake")
            .insert(receipt.operation_id.to_string(), receipt);
    }
}

impl CanonicalStoreClient for FakeStore {
    async fn apply_prepared(
        &self,
        _ctx: &RequestMeta,
        _transition: eliot_store_api::PreparedTransition,
        _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        self.apply_calls.fetch_add(1, Ordering::SeqCst);
        self.apply_result
            .lock()
            .expect("fake is single-threaded")
            .clone()
            .expect("apply scripted")
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        Ok(self
            .receipts
            .lock()
            .expect("fake")
            .get(&operation_id.to_string())
            .cloned())
    }

    async fn revision_heads(
        &self,
        _keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn scope_revision_view(
        &self,
        _scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn ordering_heads(
        &self,
        _scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<eliot_store_api::NamedReadResponse, StoreError> {
        assert!(matches!(
            query.operation,
            NamedReadOperation::GetReactiveInjectionState | NamedReadOperation::GetResourceSnapshot
        ));
        Ok(eliot_store_api::NamedReadResponse {
            operation: query.operation,
            state_fence: query.state_fence.clone(),
            revision_heads: Vec::new(),
            payload: self.read_payload.lock().expect("fake").clone(),
        })
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        Err(StoreError::Unavailable)
    }
}

fn committed_receipt(
    operation: &OperationIdentity,
    fence: &StateFence,
    envelope: ReceiptEnvelope,
) -> WriteReceipt {
    let manifest =
        operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
            .expect("set digest");
    WriteReceipt {
        operation_id: operation.operation_id.clone(),
        idempotency_key: operation.idempotency_key.clone(),
        canonical_request_hash: operation.canonical_request_hash.clone(),
        transition_class: TransitionClass::ReactiveState,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-test-1").expect("commit")),
        state_fence: fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["command-test-0".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: manifest,
        // Issue #18: standalone fixture with no transition in scope.
        semantic_source_revisions: Vec::new(),
        admission_digest: "f".repeat(64),
        mutation_plan_digest: "f".repeat(64),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: Some(envelope),
    }
}

fn ledger_payload() -> Value {
    json!({
        "session_id": "session-live-1",
        "ledger_json": ledger_json(),
        "revision": 1,
        "state_fence": serde_json::to_value(live_fence()).expect("fence"),
    })
}

fn snapshot_payload() -> Value {
    let content = b"canonical report bytes";
    json!({
        "uri": "eliot://report/live-1",
        "content_sha256": eliot_store_api::sha256_hex(content),
        "content_base64": "Y2Fub25pY2FsIHJlcG9ydCBieXRlcw==",
        "revision": 1,
        "state_fence": serde_json::to_value(live_fence()).expect("fence"),
    })
}

fn scripted_apply(fake: &FakeStore, operation: &OperationIdentity, fence: &StateFence) {
    let envelope = authority_envelope(operation, fence);
    let receipt = committed_receipt(operation, fence, envelope);
    *fake.apply_result.lock().expect("fake") = Some(Ok(receipt));
}

#[tokio::test]
async fn ledger_write_returns_bound_receipt_with_readback_revision() {
    let service = ready_service();
    let session = session(&service);
    let mut request = ledger_request("ledger-1");
    seal_ledger(&mut request);
    let fake = FakeStore::new(ledger_payload());
    scripted_apply(&fake, &request.operation, &request.state_fence);
    let response = handle_reactive_ledger_request(&fake, &service, &session, &request)
        .await
        .expect("ledger round-trips");
    assert!(!response.replayed);
    assert_eq!(response.revision, 1);
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 1);
    let read = ReactiveLedgerReadRequest {
        context: context(),
        state_fence: live_fence(),
        session_id: "session-live-1".to_owned(),
    };
    let page = handle_reactive_ledger_read(&fake, &service, &session, &read)
        .await
        .expect("ledger reads");
    assert_eq!(page.ledger_json.as_deref(), Some(ledger_json().as_str()));
    assert_eq!(page.revision, 1);
}

#[tokio::test]
async fn exact_identity_reconciles_without_second_mutation() {
    let service = ready_service();
    let session = session(&service);
    let mut request = ledger_request("ledger-2");
    seal_ledger(&mut request);
    let envelope = authority_envelope(&request.operation, &request.state_fence);
    let stored = committed_receipt(&request.operation, &request.state_fence, envelope);
    let fake = FakeStore::new(ledger_payload());
    fake.store_receipt(stored);
    let response = handle_reactive_ledger_request(&fake, &service, &session, &request)
        .await
        .expect("reconciles");
    assert!(response.replayed);
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn changed_bytes_conflict_without_dispatch() {
    let service = ready_service();
    let session = session(&service);
    let mut request = ledger_request("ledger-3");
    seal_ledger(&mut request);
    let envelope = authority_envelope(&request.operation, &request.state_fence);
    let mut stored = committed_receipt(&request.operation, &request.state_fence, envelope);
    stored.canonical_request_hash = "f".repeat(64);
    let fake = FakeStore::new(ledger_payload());
    fake.store_receipt(stored);
    let outcome = handle_reactive_ledger_request(&fake, &service, &session, &request).await;
    assert!(matches!(
        outcome,
        Err(ReactiveServiceError::IdentityConflict)
    ));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn snapshot_write_serves_exact_bytes_with_digest() {
    let service = ready_service();
    let session = session(&service);
    let mut request = snapshot_request("snap-1");
    seal_snapshot(&mut request);
    let fake = FakeStore::new(snapshot_payload());
    scripted_apply(&fake, &request.operation, &request.state_fence);
    let response = handle_resource_snapshot_request(&fake, &service, &session, &request)
        .await
        .expect("snapshot round-trips");
    assert!(!response.replayed);
    assert_eq!(response.revision, 1);
    assert_eq!(
        response.content_sha256,
        eliot_store_api::sha256_hex(b"canonical report bytes")
    );
    let read = ResourceSnapshotReadRequest {
        context: context(),
        state_fence: live_fence(),
        uri: "eliot://report/live-1".to_owned(),
    };
    let page = handle_resource_snapshot_read(&fake, &service, &session, &read)
        .await
        .expect("snapshot reads");
    assert_eq!(
        page.content.as_deref(),
        Some(b"canonical report bytes".as_slice())
    );
    assert_eq!(
        page.content_sha256.as_deref(),
        Some(response.content_sha256.as_str())
    );
}

#[tokio::test]
async fn foreign_fence_fails_before_any_dispatch() {
    let service = ready_service();
    let session = session(&service);
    let mut request = ledger_request("ledger-4");
    let foreign = StateFence::new(
        test_epoch(EPOCH_SEQUENCE),
        ResourceGeneration::new(GENERATION + 1).expect("generation"),
    );
    request.state_fence = foreign.clone();
    request.context.state_fence = foreign;
    let fake = FakeStore::new(ledger_payload());
    let outcome = handle_reactive_ledger_request(&fake, &service, &session, &request).await;
    assert!(matches!(outcome, Err(ReactiveServiceError::FenceMismatch)));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconcile_returns_stored_receipt_or_unknown() {
    let service = ready_service();
    let session = session(&service);
    let mut request = ledger_request("ledger-5");
    seal_ledger(&mut request);
    let envelope = authority_envelope(&request.operation, &request.state_fence);
    let stored = committed_receipt(&request.operation, &request.state_fence, envelope.clone());
    let fake = FakeStore::new(ledger_payload());
    fake.store_receipt(stored);
    let found = reconcile_reactive_state(
        &fake,
        &service,
        &session,
        request.operation.operation_id.clone(),
        &request.operation.idempotency_key,
        &request.operation.canonical_request_hash,
    )
    .await
    .expect("reconcile resolves")
    .expect("receipt present");
    assert_eq!(found, envelope);
    let absent = reconcile_reactive_state(
        &fake,
        &service,
        &session,
        OperationId::new("op-absent").expect("operation"),
        "idem-absent",
        &"a".repeat(64),
    )
    .await
    .expect("unknown resolves");
    assert_eq!(absent, None);
}
