//! Front-door tests for lifecycle persistence (issue #1905).
//!
//! A real `KernelService` driven to `Ready` binds the session against live
//! authority; a scripted `CanonicalStoreClient` fake (manufactured frames,
//! never admission authority) proves the persist seam: a verified two-hop
//! chain commits one capture plus hash-chained audit legs with exact
//! subjects/digests/positions, sealed replays resolve without remutation,
//! divergent seals conflict, broken chains and audit mismatches fail
//! before any dispatch, and every emitted event binds back to its
//! admission. Backend transition semantics are proven through the
//! adapter suites.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

use super::lifecycle_persist::{
    AuthenticatedLifecycleSession, LifecyclePersistError, LifecyclePersistRequest,
    build_persist_transitions, handle_lifecycle_persist_request,
};
use super::{KernelService, KernelServiceState};
use crate::{
    HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
    HostProcessBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
    ProcessObservation, RestartBudget,
};
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, EpochId, EpochLineageId, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TransactionSequence,
};
use eliot_epistemic::lifecycle::{
    ActorIdentity, ActorKind, AdmissionOutcome, LifecycleRole, SourceAnchor,
};
use eliot_evidence::EpistemicStatus;
use eliot_memory_curation::admission::CurationAdmission;
use eliot_memory_curation::candidate_admission::{
    ForwardRevisionParams, ObservationGenesisParams, admit_forward_revision,
    admit_observation_genesis,
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
    CanonicalStoreClient, CanonicalValidationSnapshot, CommitId, NamedReadRequest,
    NamedReadResponse, OperationIdentity, OrderingHead, OrderingScopeId, RequestMeta, Resubmission,
    RevisionHead, RevisionKey, ScopeId, ScopeRevisionView, StoreError, StoreHealth,
    TransitionClass, WriteReceipt, WriteReceiptStatus, generated_operation_manifests,
    operation_manifest_set_digest,
};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_SEQUENCE: u64 = 4;
const GENERATION: u64 = 7;

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

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("valid fixture artifact id")
}

fn source(value: &str) -> SourceId {
    SourceId::new(value).expect("valid fixture source id")
}

fn anchor() -> SourceAnchor {
    SourceAnchor {
        source_id: source("fixture-source"),
        revision: Some("r1".to_owned()),
        raw_handle: Some("raw:fixture:r1".to_owned()),
    }
}

fn clock() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1),
        known_time_ms: Some(2),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn actor(kind: ActorKind) -> ActorIdentity {
    ActorIdentity {
        kind,
        identity: "fixture-actor".to_owned(),
        authority_basis: "fixture-grant".to_owned(),
    }
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

fn ready_service() -> KernelService {
    let mut service = KernelService::new([7; 32], 2, 4).expect("test service");
    let candidate = candidate();
    let permit = KernelActivationPermit {
        operation_id: handle("activation-operation-1"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("journal-transaction-1"),
        journal_sequence: 7,
        generation: live_generation(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
            .expect("valid test nonce"),
    };
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

fn session(service: &KernelService) -> AuthenticatedLifecycleSession {
    AuthenticatedLifecycleSession::bind(service, "lifecycle-peer:test").expect("test session")
}

fn context() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-lifecycle-1").expect("request"),
        session_id: Some(eliot_contracts::SessionId::new("session-live-1").expect("session")),
        task_id: None,
        product_id: ProductId::new("product-lifecycle").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: live_fence(),
        clock: ClockReading::default(),
    }
}

/// Builds a verified two-hop chain with preset audit events, mirroring
/// the B4 acceptance flow: the route appoints audit identities first,
/// curation admits with them preset, the seam persists and binds.
fn verified_chain() -> Vec<CurationAdmission> {
    let genesis = admit_observation_genesis(ObservationGenesisParams {
        receipt_id: id("receipt:capture"),
        raw_handle: id("obs:raw-1"),
        source_anchor: anchor(),
        actor: actor(ActorKind::DeterministicTransformer),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: live_fence(),
        proof_digest: eliot_contracts::sha256_hex(b"capture-proof"),
        audit_event_id: Some(id("op-1905-audit-0")),
    })
    .expect("genesis admission");
    let view = admit_forward_revision(
        &[genesis],
        ForwardRevisionParams {
            receipt_id: id("receipt:claim"),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role: LifecycleRole::ObservationCandidate,
            proposed_role: LifecycleRole::Claim,
            prior_status: EpistemicStatus::Observed,
            proposed_status: EpistemicStatus::Supported,
            actor: actor(ActorKind::HumanOperator),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: live_fence(),
            evidence_refs: vec![id("obs:raw-1")],
            counterevidence_refs: Vec::new(),
            outcome: AdmissionOutcome::Admitted,
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_record_id: id("claim:1"),
            proof_digest: eliot_contracts::sha256_hex(b"claim-proof"),
            audit_event_id: Some(id("op-1905-audit-1")),
        },
    )
    .expect("revision admission");
    view.ordered
}

fn persist_request(tag: &str) -> LifecyclePersistRequest {
    LifecyclePersistRequest {
        context: context(),
        state_fence: live_fence(),
        chain: verified_chain(),
        hop_identities: vec![
            OperationIdentity {
                operation_id: eliot_contracts::OperationId::new(format!("op-1905-{tag}-capture"))
                    .expect("operation"),
                idempotency_key: format!("idem-1905-{tag}-capture"),
                canonical_request_hash: "0".repeat(64),
            },
            OperationIdentity {
                operation_id: eliot_contracts::OperationId::new("op-1905-audit-0")
                    .expect("operation"),
                idempotency_key: format!("idem-1905-{tag}-audit-0"),
                canonical_request_hash: "0".repeat(64),
            },
            OperationIdentity {
                operation_id: eliot_contracts::OperationId::new("op-1905-audit-1")
                    .expect("operation"),
                idempotency_key: format!("idem-1905-{tag}-audit-1"),
                canonical_request_hash: "0".repeat(64),
            },
        ],
    }
}

/// Seals every hop identity hash against the exact admitted bytes.
fn seal_request(request: &mut LifecyclePersistRequest) {
    let built = build_persist_transitions(request).expect("transitions build");
    for ((transition, _), identity) in built.iter().zip(request.hop_identities.iter_mut()) {
        let view = eliot_store_api::CanonicalRequestView::from_apply(
            &request.context,
            transition,
            &[],
            &[],
        );
        identity.canonical_request_hash =
            eliot_store_api::canonical_request_hash(&view).expect("hash computes");
    }
}

/// Scripted store double: manufactured frames only, never admission authority.
///
/// Applies build per-transition committed receipts, so emitted event ids
/// echo the admitted transition's event intents exactly like the
/// canonical backends do.
struct FakeStore {
    receipts: Mutex<BTreeMap<String, WriteReceipt>>,
    applied: Mutex<Vec<eliot_store_api::PreparedTransition>>,
    apply_calls: AtomicUsize,
}

impl FakeStore {
    fn new() -> Self {
        Self {
            receipts: Mutex::new(BTreeMap::new()),
            applied: Mutex::new(Vec::new()),
            apply_calls: AtomicUsize::new(0),
        }
    }

    fn store_receipt(&self, receipt: WriteReceipt) {
        self.receipts
            .lock()
            .expect("fake")
            .insert(receipt.operation_id.to_string(), receipt);
    }

    fn transitions(&self) -> Vec<eliot_store_api::PreparedTransition> {
        self.applied.lock().expect("fake").clone()
    }

    fn committed_for(&self, transition: &eliot_store_api::PreparedTransition) -> WriteReceipt {
        let manifest =
            operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
                .expect("set digest");
        let envelope = authority_envelope(
            &OperationIdentity {
                operation_id: transition.identity.operation_id.clone(),
                idempotency_key: transition.identity.idempotency_key.clone(),
                canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            },
            &transition.state_fence,
        );
        WriteReceipt {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            transition_class: transition.transition_class,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-test-1").expect("commit")),
            state_fence: transition.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["command-test-0".to_owned()],
            emitted_event_ids: transition
                .event_projection_relation_intents
                .event_ids
                .clone(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: manifest,
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: Some(envelope),
        }
    }
}

impl CanonicalStoreClient for FakeStore {
    async fn apply_prepared(
        &self,
        _ctx: &RequestMeta,
        transition: eliot_store_api::PreparedTransition,
        _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        self.apply_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(sealed) = self
            .receipts
            .lock()
            .expect("fake")
            .get(&transition.identity.operation_id.to_string())
        {
            return Ok(sealed.clone());
        }
        let receipt = self.committed_for(&transition);
        self.applied.lock().expect("fake").push(transition.clone());
        Ok(receipt)
    }

    async fn receipt(
        &self,
        operation_id: eliot_contracts::OperationId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
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
        _query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        Err(StoreError::Unavailable)
    }
}

fn authority_envelope(operation: &OperationIdentity, fence: &StateFence) -> ReceiptEnvelope {
    let request_id = RequestId::new("resolve-request").expect("request id");
    let metadata = RequestMeta {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-lifecycle").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence.clone(),
        clock: ClockReading::default(),
    };
    ReceiptEnvelope::issue(ReceiptCore {
        contract: contract_identity().expect("contract"),
        kind: ReceiptKind::Verification,
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope").expect("scope"),
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
            operation_kind: "lifecycle.persist".to_owned(),
            effect: EffectClass::Candidate,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-owner-1").expect("authority"),
            authority_owner: "owner-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Candidate,
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
        transition_class: TransitionClass::CaptureCandidate,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-test-1").expect("commit")),
        state_fence: fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["command-test-0".to_owned()],
        emitted_event_ids: vec![eliot_store_api::EventId::new("receipt:test").expect("event")],
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: manifest,
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: Some(envelope),
    }
}

#[tokio::test]
async fn chain_persists_capture_plus_hash_chained_audits() {
    let service = ready_service();
    let session = session(&service);
    let mut request = persist_request("chain-1");
    seal_request(&mut request);
    let fake = FakeStore::new();
    let response = handle_lifecycle_persist_request(&fake, &service, &session, &request)
        .await
        .expect("chain persists");
    assert!(!response.capture_replayed);
    assert_eq!(response.hops.len(), 2);
    assert_eq!(response.links.len(), 2);
    assert!(response.hops.iter().all(|hop| !hop.replayed));
    // Capture subject is the retained raw handle, verbatim.
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 3);
    let applied = fake.transitions();
    assert_eq!(applied.len(), 3);
    let capture_params = &applied[0].named_operations[0].parameters;
    assert_eq!(
        capture_params.get("subject").and_then(Value::as_str),
        Some("obs:raw-1")
    );
    // Audit legs bind receipt digests, previous-link digests, and hop positions.
    let chain = &request.chain;
    for (index, audit) in applied[1..].iter().enumerate() {
        let params = &audit.named_operations[0].parameters;
        let receipt_digest = chain[index].receipt.digest.clone();
        let previous_operation = applied[index].identity.operation_id.to_string();
        assert_eq!(
            params.get("access_digest").and_then(Value::as_str),
            Some(receipt_digest.as_str()),
            "hop {index} binds its curation receipt digest"
        );
        assert_eq!(
            params.get("action_digest").and_then(Value::as_str),
            Some(eliot_store_api::sha256_hex(previous_operation.as_bytes()).as_str()),
            "hop {index} chains the previous appointed identity"
        );
        assert_eq!(
            params.get("expected_revision").and_then(Value::as_str),
            Some(format!("{}", index + 1).as_str()),
            "hop {index} carries its chain position"
        );
        assert_eq!(
            audit.event_projection_relation_intents.event_ids.len(),
            1,
            "hop {index} emits exactly its admission event"
        );
    }
    for (index, link) in response.links.iter().enumerate() {
        assert_eq!(
            link.audit_operation_id,
            request.hop_identities[index + 1].operation_id.to_string()
        );
        assert!(!link.emitted_event_ids.is_empty());
    }
    // Preset audit events match appointed identities exactly.
    assert_eq!(response.links[0].curation_receipt_id, "receipt:capture",);
    assert_eq!(response.links[1].curation_receipt_id, "receipt:claim");
    // Emitted events bind back to the admitted curation receipts.
    assert_eq!(
        response.capture_emitted_event_ids,
        vec!["receipt:capture".to_owned()]
    );
    assert_eq!(
        response.links[0].emitted_event_ids,
        vec!["receipt:capture".to_owned()]
    );
    assert_eq!(
        response.links[1].emitted_event_ids,
        vec!["receipt:claim".to_owned()]
    );
}

#[tokio::test]
async fn sealed_chain_replays_without_remutation() {
    let service = ready_service();
    let session = session(&service);
    let mut request = persist_request("chain-2");
    seal_request(&mut request);
    let fake = FakeStore::new();
    for identity in &request.hop_identities {
        let envelope = authority_envelope(identity, &request.state_fence);
        let stored = committed_receipt(identity, &request.state_fence, envelope);
        fake.store_receipt(stored);
    }
    let response = handle_lifecycle_persist_request(&fake, &service, &session, &request)
        .await
        .expect("replay resolves");
    assert!(response.capture_replayed);
    assert!(response.hops.iter().all(|hop| hop.replayed));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn divergent_seal_conflicts_before_remutation() {
    let service = ready_service();
    let session = session(&service);
    let mut request = persist_request("chain-3");
    seal_request(&mut request);
    let fake = FakeStore::new();
    let mut tampered = request.hop_identities[1].clone();
    tampered.canonical_request_hash = "f".repeat(64);
    let envelope = authority_envelope(&tampered, &request.state_fence);
    let stored = committed_receipt(&tampered, &request.state_fence, envelope);
    fake.store_receipt(stored);
    // Genesis capture has no seal: the fake apply path is unscripted, so
    // this resolves at the audit pre-check. Seed the capture seal first.
    let capture_identity = request.hop_identities[0].clone();
    let capture_envelope = authority_envelope(&capture_identity, &request.state_fence);
    let capture_sealed =
        committed_receipt(&capture_identity, &request.state_fence, capture_envelope);
    fake.store_receipt(capture_sealed);
    let outcome = handle_lifecycle_persist_request(&fake, &service, &session, &request).await;
    assert!(matches!(
        outcome,
        Err(LifecyclePersistError::IdentityConflict)
    ));
}

#[tokio::test]
async fn broken_chain_and_audit_mismatch_fail_before_dispatch() {
    let service = ready_service();
    let session = session(&service);
    let fake = FakeStore::new();
    // Empty chain fails closed.
    let mut empty = persist_request("chain-4");
    empty.chain.clear();
    empty.hop_identities.truncate(1);
    let outcome = handle_lifecycle_persist_request(&fake, &service, &session, &empty).await;
    assert!(matches!(
        outcome,
        Err(LifecyclePersistError::InvalidField { .. })
    ));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
    // Wrong audit appointment fails closed (sealed valid, then tampered).
    let mut request = persist_request("chain-5");
    seal_request(&mut request);
    let mut tampered = request.chain[1].clone();
    tampered.receipt = tampered
        .receipt
        .link_audit(id("op-1905-audit-WRONG"))
        .expect("relink");
    request.chain[1] = tampered;
    let outcome = handle_lifecycle_persist_request(&fake, &service, &session, &request).await;
    assert!(matches!(
        outcome,
        Err(LifecyclePersistError::InvalidField { .. })
    ));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
    // Double genesis breaks chain order (no sealing: verification
    // fails before any hash is checked).
    let mut request = persist_request("chain-5b");
    let genesis = request.chain[0].clone();
    request.chain = vec![genesis.clone(), genesis];
    let outcome = handle_lifecycle_persist_request(&fake, &service, &session, &request).await;
    assert!(matches!(
        outcome,
        Err(LifecyclePersistError::ChainRejected(_))
    ));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn foreign_fence_fails_before_any_dispatch() {
    let service = ready_service();
    let session = session(&service);
    let mut request = persist_request("chain-6");
    let foreign = StateFence::new(
        test_epoch(EPOCH_SEQUENCE),
        ResourceGeneration::new(GENERATION + 1).expect("generation"),
    );
    request.state_fence = foreign.clone();
    request.context.state_fence = foreign;
    let fake = FakeStore::new();
    let outcome = handle_lifecycle_persist_request(&fake, &service, &session, &request).await;
    assert!(matches!(outcome, Err(LifecyclePersistError::FenceMismatch)));
    assert_eq!(fake.apply_calls.load(Ordering::SeqCst), 0);
}
