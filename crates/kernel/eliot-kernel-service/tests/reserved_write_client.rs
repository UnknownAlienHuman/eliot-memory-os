//! Client integration tests for the reserved-write operation (issue #991).
//!
//! Eight cases (`991/5`, `991/6`, `991/7`, `991/8`, `991/9`, `991/10`,
//! `991/11`, `991/12`, `991/13`; `991/4` is owned by the dispatch suite) prove the
//! exact `CanonicalStoreClient` reserved-write implementation: request
//! serialization, fence/identity/binding validation before any send,
//! single-dispatch execution, exact receipt binding, and typed post-send
//! failures with no retry, no second send, and no fallback to ordinary
//! `Apply`.
//!
//! Typed inputs freeze in `data/reserved-write/`: `request.json` is the exact
//! valid request under test, `receipt.json` its matching enveloped receipt.
//! The fake transport below speaks real EBP frames through the production
//! `execute_raw` exchange; it manufactures responses, never admission
//! authority. Shared atomic counters observe send counts from outside the
//! client.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]
// Large EBP-connect futures are inherent to the production exchange shape;
// the tests await them directly (precedent: dreamer_job_store_edge.rs).
#![allow(clippy::large_futures)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_ipc::{DeliveryOutcome, TransportLimits};
use eliot_kernel_service::{
    EbpCanonicalStoreClient, EbpStoreTransport, HostStoreBootstrapRequirement, StoreClientError,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion, ServerHello,
};
use eliot_store_api::{
    CanonicalStoreClient, CommitId, EffectClass, EventProjectionRelationIntents,
    NamedMutationOperation, NamedMutationRequest, OperationIdentity, OperationManifestDigest,
    OrderingHead, OrderingHeadExpectation, OrderingScopeId, PreparedTransition, RequestMeta,
    ReservedScopeBinding, ReservedWriteRequest, Resubmission, RevisionHeadExpectation, RevisionKey,
    ScopeId, SecurityContext, StoreError, StoreFailure, StoreFailureIdentityContext, StoreRequest,
    StoreResponse, TransitionClass, WriteAdmissionParams, WriteAdmissionProjection, WriteReceipt,
    WriteReceiptStatus, WriterEpochBinding, issue_store_receipt_envelope, response_frame,
};
use serde_json::json;

const LINEAGE_991: &str = "550e8400-e29b-41d4-a716-446655440000";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_991).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn requirement() -> HostStoreBootstrapRequirement {
    HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::new(1).unwrap(),
        state_fence: fence(),
        launch_nonce: PlatformHandle::new("launch").unwrap(),
        connection_id: PlatformHandle::new("connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 1,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 30_000,
    }
}

fn context_with(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-991-{tag}")).unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-991-k").unwrap(),
        source_id: SourceId::new("source-991-k").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition_with(tag: &str) -> PreparedTransition {
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-991-{tag}")).unwrap(),
            idempotency_key: format!("idem-991-{tag}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(format!("scope-991-{tag}")).unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(format!("scope-991-{tag}")).unwrap()],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new(format!("manifest-991-{tag}"))
            .unwrap(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("observation-991-k1"))]),
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

fn admission_for(transition: &PreparedTransition) -> WriteAdmissionProjection {
    let scopes: Vec<ReservedScopeBinding> = transition
        .ordering_scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| {
            #[allow(clippy::cast_possible_truncation)]
            let reserved = 7 + index as u64;
            #[allow(clippy::cast_possible_truncation)]
            let expected = 6 + index as u64;
            ReservedScopeBinding {
                scope: scope.clone(),
                reserved_sequence: reserved,
                expected_sequence: expected,
                expected_head_digest: "c".repeat(64),
            }
        })
        .collect();
    let params = WriteAdmissionParams {
        reservation_id: "reservation-991-k1".to_owned(),
        reservation_order: 42,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes,
        writer_epoch: WriterEpochBinding {
            lineage_id: "epoch-lineage-991-k".to_owned(),
            epoch: 5,
            predecessor_lineage_id: None,
            predecessor_epoch: None,
        },
        state_fence: fence(),
        source_id: "source-991-k".to_owned(),
        created_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        recovery_owner: "recovery-owner-991-k".to_owned(),
    };
    WriteAdmissionProjection::bind(transition, params).unwrap()
}

fn valid_request_with(tag: &str) -> ReservedWriteRequest {
    let transition = transition_with(tag);
    let admission = admission_for(&transition);
    let scope = OrderingScopeId::new(format!("scope-991-{tag}")).unwrap();
    ReservedWriteRequest {
        context: context_with(tag),
        transition,
        admission,
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new(format!("rev-991-{tag}")).unwrap(),
            expected_revision: 3,
            state_fence: fence(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope,
            expected_sequence: 6,
            state_fence: fence(),
        }],
    }
}

fn valid_request() -> ReservedWriteRequest {
    valid_request_with("k1")
}

fn receipt_for(request: &ReservedWriteRequest) -> WriteReceipt {
    let transition = &request.transition;
    let scope = request.admission.scopes[0].clone();
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-991-k1").unwrap()),
        state_fence: request.context.state_fence.clone(),
        ordering_sequences: vec![OrderingHead {
            scope: scope.scope,
            sequence: scope.reserved_sequence,
            state_fence: fence(),
        }],
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["capture-observation".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    };
    receipt.envelope =
        Some(issue_store_receipt_envelope(&request.context, transition, &receipt, 1).unwrap());
    receipt.validate().unwrap();
    receipt
}

fn fixture_request() -> ReservedWriteRequest {
    let text = include_str!("data/reserved-write/request.json");
    let request: ReservedWriteRequest = serde_json::from_str(text).unwrap();
    assert_eq!(
        request,
        valid_request(),
        "fixture matches the sealed builder"
    );
    request
}

fn fixture_receipt() -> WriteReceipt {
    let text = include_str!("data/reserved-write/receipt.json");
    serde_json::from_str(text).unwrap()
}

#[derive(Clone, Default)]
struct Counters {
    reserved_write_calls: Arc<AtomicUsize>,
    receipt_calls: Arc<AtomicUsize>,
    receipt_operations: Arc<std::sync::Mutex<Vec<OperationId>>>,
}

/// Fake EBP store transport speaking real frames.
///
/// Responses are manufactured per test; the request path (frame encode,
/// identity binding, correlation, response decode) is the production
/// exchange. An ordinary-`Apply` send panics: the reserved-write client must
/// never fall back to it.
struct FakeTransport {
    requirement: HostStoreBootstrapRequirement,
    pending: Option<Frame>,
    reserved_write_response: Option<StoreResponse>,
    reserved_write_raw: Option<Frame>,
    counters: Counters,
}

impl FakeTransport {
    fn new(requirement: HostStoreBootstrapRequirement, counters: Counters) -> Self {
        Self {
            requirement,
            pending: None,
            reserved_write_response: None,
            reserved_write_raw: None,
            counters,
        }
    }

    fn with_reserved_write_response(mut self, response: StoreResponse) -> Self {
        self.reserved_write_response = Some(response);
        self
    }

    fn with_reserved_write_raw(mut self, frame: Frame) -> Self {
        self.reserved_write_raw = Some(frame);
        self
    }

    fn answer(connection: &str, request_id: RequestId, response: StoreResponse) -> Frame {
        response_frame(
            connection.to_owned(),
            ProtocolVersion::CURRENT,
            Some(request_id),
            response,
        )
        .unwrap()
    }
}

impl EbpStoreTransport for FakeTransport {
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
        if frame.kind == FrameKind::Control {
            let hello = ServerHello {
                selected_protocol: ProtocolVersion::CURRENT,
                session_principal_binding: "fake-store-session".to_owned(),
                allowed_capabilities: eliot_store_api::CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                allowed_effects: eliot_store_api::EFFECTS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                config_snapshot: json!({
                    "config_hash": self.requirement.approved_config_hash.as_str(),
                    "artifact_hash": self.requirement.approved_artifact_hash.as_str(),
                }),
                heartbeat_ms: 1_000,
                control_channel: "fake-store-control".to_owned(),
                rejection_reason: None,
                authority_epoch: self.requirement.authority_epoch().clone(),
            };
            self.pending = Some(
                eliot_ipc::server_hello_frame(self.requirement.connection_id.as_str(), &hello)
                    .unwrap(),
            );
            return Ok(DeliveryOutcome::Delivered);
        }
        let (request_id, _identity, request) =
            eliot_store_api::decode_request_frame(frame).map_err(StoreClientError::from)?;
        let connection = self.requirement.connection_id.as_str().to_owned();
        match request {
            StoreRequest::Readiness => {
                self.pending = Some(Self::answer(
                    &connection,
                    request_id,
                    StoreResponse::Readiness {
                        receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
                    },
                ));
            }
            StoreRequest::ReservedWrite { .. } => {
                self.counters
                    .reserved_write_calls
                    .fetch_add(1, Ordering::SeqCst);
                if let Some(raw) = self.reserved_write_raw.take() {
                    self.pending = Some(raw);
                } else {
                    let response = self.reserved_write_response.take().unwrap();
                    self.pending = Some(Self::answer(&connection, request_id, response));
                }
            }
            StoreRequest::Receipt { operation_id } => {
                self.counters.receipt_calls.fetch_add(1, Ordering::SeqCst);
                self.counters
                    .receipt_operations
                    .lock()
                    .unwrap()
                    .push(operation_id);
                // The reserved-write client must never issue this query after
                // its single send: any receipt lookup is answered absent so a
                // regression surfaces as a typed unknown, never a success.
                self.pending = Some(Self::answer(
                    &connection,
                    request_id,
                    StoreResponse::Receipt { receipt: None },
                ));
            }
            StoreRequest::Apply { .. } => {
                panic!("reserved-write must never fall back to ordinary Apply");
            }
            _ => {
                return Err(StoreClientError::Contract(
                    "fake transport received unexpected request".to_owned(),
                ));
            }
        }
        Ok(DeliveryOutcome::Delivered)
    }

    async fn receive_frame(&mut self, _limits: TransportLimits) -> Result<Frame, StoreClientError> {
        self.pending
            .take()
            .ok_or_else(|| StoreClientError::Transport("fake response missing".to_owned()))
    }
}

async fn connect(counters: &Counters) -> EbpCanonicalStoreClient<FakeTransport> {
    connect_with(&requirement(), counters).await
}

async fn connect_with(
    requirement: &HostStoreBootstrapRequirement,
    counters: &Counters,
) -> EbpCanonicalStoreClient<FakeTransport> {
    EbpCanonicalStoreClient::connect(
        FakeTransport::new(requirement.clone(), counters.clone()),
        requirement.clone(),
    )
    .await
    .unwrap()
}

fn failure_for(error: StoreError, request: &ReservedWriteRequest) -> StoreFailure {
    StoreFailure::from_store_error(
        error,
        StoreFailureIdentityContext {
            request_id: Some(request.context.request_id.clone()),
            operation_id: Some(request.transition.identity.operation_id.clone()),
            idempotency_key_ref_or_digest: Some(
                request.transition.identity.idempotency_key.clone(),
            ),
            state_fence_ref_or_exact_safe_projection: Some(request.context.state_fence.clone()),
            evidence_ref: None,
            transport_unavailable: false,
        },
    )
    .unwrap()
}

// WORK_UNIT_CASE: 991/5
#[tokio::test]
async fn wrong_source_principal_or_generation_fails_before_backend_send() {
    // Identity, fence, and generation pin before any frame leaves the
    // client: a diverted context fence, a diverted admission fence, a foreign
    // generation, and a mirrored-source mismatch all refuse with zero sends.
    let counters = Counters::default();
    let client = connect(&counters).await;
    let mut diverted = valid_request();
    diverted.context.state_fence = StateFence::new(epoch(2), ResourceGeneration::genesis());
    assert_eq!(
        client.apply_reserved_write(diverted).await,
        Err(StoreError::FenceMismatch)
    );
    let mut foreign_admission = valid_request();
    foreign_admission.admission.state_fence =
        StateFence::new(epoch(2), ResourceGeneration::genesis());
    assert_eq!(
        client.apply_reserved_write(foreign_admission).await,
        Err(StoreError::FenceMismatch)
    );
    // A foreign generation is pinned by the Host-approved requirement: a
    // fully valid older-generation request refuses against a newer
    // requirement with zero sends.
    let mut newer_requirement = requirement();
    newer_requirement.state_fence = StateFence::new(epoch(1), ResourceGeneration::new(2).unwrap());
    newer_requirement.store_generation = ResourceGeneration::new(2).unwrap();
    let newer_counters = Counters::default();
    let newer_client = connect_with(&newer_requirement, &newer_counters).await;
    assert_eq!(
        newer_client.apply_reserved_write(valid_request()).await,
        Err(StoreError::FenceMismatch)
    );
    assert_eq!(
        newer_counters.reserved_write_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(newer_counters.receipt_calls.load(Ordering::SeqCst), 0);
    let mut impostor_source = valid_request();
    impostor_source.context.source_id = SourceId::new("source-991-impostor").unwrap();
    assert_eq!(
        client.apply_reserved_write(impostor_source).await,
        Err(StoreError::IdentityConflict)
    );
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(counters.receipt_calls.load(Ordering::SeqCst), 0);
}

// WORK_UNIT_CASE: 991/6
#[tokio::test]
async fn wrong_operation_hash_transition_or_reservation_binding_fails() {
    // The sealed binding is exact: a mutated transition body, a substituted
    // operation identity, and a reordered reservation all refuse before any
    // send, so no binding can be repaired or defaulted into authority.
    let counters = Counters::default();
    let client = connect(&counters).await;
    let mut mutated = valid_request();
    mutated.transition.named_operations[0].parameters =
        BTreeMap::from([("subject".to_owned(), json!("observation-991-tampered"))]);
    assert!(matches!(
        client.apply_reserved_write(mutated).await,
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
    let mut substituted = valid_request();
    substituted.admission.operation_id = OperationId::new("op-991-substituted").unwrap();
    assert_eq!(
        client.apply_reserved_write(substituted).await,
        Err(StoreError::IdentityConflict)
    );
    let mut reordered = valid_request();
    reordered.admission.reservation_order = 43;
    assert!(matches!(
        client.apply_reserved_write(reordered).await,
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(counters.receipt_calls.load(Ordering::SeqCst), 0);
}

// WORK_UNIT_CASE: 991/7
#[tokio::test]
async fn incomplete_or_changed_scope_or_head_set_fails() {
    // The preserved head set must exactly cover the reserved scopes: a
    // dropped head, an extra head, and a diverged expected sequence all
    // refuse before any send.
    let counters = Counters::default();
    let client = connect(&counters).await;
    let mut dropped = valid_request();
    dropped.expected_ordering_heads.clear();
    assert!(matches!(
        client.apply_reserved_write(dropped).await,
        Err(StoreError::InvalidField { .. })
    ));
    let mut extra = valid_request();
    extra.expected_ordering_heads.push(OrderingHeadExpectation {
        scope: OrderingScopeId::new("scope-991-extra").unwrap(),
        expected_sequence: 1,
        state_fence: fence(),
    });
    assert!(matches!(
        client.apply_reserved_write(extra).await,
        Err(StoreError::InvalidField { .. })
    ));
    let mut diverged = valid_request();
    diverged.expected_ordering_heads[0].expected_sequence = 5;
    assert!(matches!(
        client.apply_reserved_write(diverged).await,
        Err(StoreError::InvalidField { .. })
    ));
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(counters.receipt_calls.load(Ordering::SeqCst), 0);
}

// WORK_UNIT_CASE: 991/8
#[tokio::test]
async fn wrong_fence_epoch_or_expiry_binding_fails_at_owning_boundary() {
    // Reservation-internal bindings fail at the owning validation boundary
    // before any send: a non-direct-child epoch edge and a non-ordered
    // owner-supplied time pair are both intrinsic shape refusals.
    let counters = Counters::default();
    let client = connect(&counters).await;
    let mut broken_edge = valid_request();
    broken_edge.admission.writer_epoch.predecessor_lineage_id =
        Some("epoch-lineage-991-k".to_owned());
    broken_edge.admission.writer_epoch.predecessor_epoch = Some(3);
    assert!(matches!(
        client.apply_reserved_write(broken_edge).await,
        Err(StoreError::InvalidField { .. })
    ));
    let mut bad_expiry = valid_request();
    bad_expiry.admission.expires_at_ms = bad_expiry.admission.created_at_ms;
    assert!(matches!(
        client.apply_reserved_write(bad_expiry).await,
        Err(StoreError::InvalidField { .. })
    ));
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(counters.receipt_calls.load(Ordering::SeqCst), 0);
}

// WORK_UNIT_CASE: 991/9
#[tokio::test]
async fn one_valid_dispatch_invokes_the_selected_backend_exactly_once() {
    // A single valid dispatch crosses the transport exactly once and returns
    // the exact enveloped receipt; the ordinary-`Apply` route is never
    // touched (the fake panics on it).
    let request = fixture_request();
    let receipt = fixture_receipt();
    assert_eq!(receipt, receipt_for(&request));
    let counters = Counters::default();
    let requirement = requirement();
    let client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(requirement.clone(), counters.clone()).with_reserved_write_response(
            StoreResponse::Transaction {
                receipt: receipt.clone(),
            },
        ),
        requirement,
    )
    .await
    .unwrap();
    let observed = client.apply_reserved_write(request.clone()).await.unwrap();
    assert_eq!(observed, receipt);
    assert_eq!(
        observed.operation_id,
        request.transition.identity.operation_id
    );
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.receipt_calls.load(Ordering::SeqCst), 0);
}

// WORK_UNIT_CASE: 991/10
#[tokio::test]
async fn missing_foreign_or_malformed_receipt_cannot_be_success() {
    // A foreign operation identity is never adopted: the peer sends a fully
    // valid receipt for another operation, the client returns the typed
    // identity-mismatch validation error with no second send, and an
    // undecodable answer stays unknown — also with no second send.
    let request = fixture_request();
    let foreign_request = valid_request_with("k2");
    assert!(foreign_request.validate().is_ok());
    let foreign = receipt_for(&foreign_request);
    let counters = Counters::default();
    let foreign_requirement = requirement();
    let client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(foreign_requirement.clone(), counters.clone())
            .with_reserved_write_response(StoreResponse::Transaction { receipt: foreign }),
        foreign_requirement,
    )
    .await
    .unwrap();
    assert_eq!(
        client.apply_reserved_write(request.clone()).await,
        Err(StoreError::IdentityConflict)
    );
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        counters.receipt_calls.load(Ordering::SeqCst),
        0,
        "a misbound receipt returns its typed validation error with no second send"
    );
    assert!(
        counters.receipt_operations.lock().unwrap().is_empty(),
        "a misbound receipt issues no receipt query at all"
    );
    // A malformed (envelope-less) receipt observation is an unknown outcome
    // for the exact admitted operation, never success: the frame fails
    // response validation, the exchange keeps the admitted identity (not a
    // contract defect), and the client preserves the typed unknown outcome
    // with no second send.
    let mut malformed = receipt_for(&request);
    malformed.envelope = None;
    let raw = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: "connection".to_owned(),
        request_id: Some(request.context.request_id.clone()),
        kind: FrameKind::Response,
        message_type: MessageType::Result,
        request_identity: None,
        payload: ProtocolPayload::Json(
            serde_json::to_value(StoreResponse::Transaction { receipt: malformed }).unwrap(),
        ),
        trace_context: BTreeMap::new(),
    };
    assert!(
        eliot_store_api::decode_response_frame(&raw, "connection", ProtocolVersion::CURRENT)
            .is_err(),
        "envelope-less transaction is not a decodable success"
    );
    let malformed_counters = Counters::default();
    let malformed_requirement = requirement();
    let malformed_client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(malformed_requirement.clone(), malformed_counters.clone())
            .with_reserved_write_raw(raw),
        malformed_requirement,
    )
    .await
    .unwrap();
    assert_eq!(
        malformed_client.apply_reserved_write(request.clone()).await,
        Err(StoreError::MissingReceiptEnvelope)
    );
    assert_eq!(
        malformed_counters
            .reserved_write_calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        malformed_counters.receipt_calls.load(Ordering::SeqCst),
        0,
        "an undecodable answer stays unknown with no second send"
    );
    assert!(
        malformed_counters
            .receipt_operations
            .lock()
            .unwrap()
            .is_empty(),
        "an undecodable answer issues no receipt query at all"
    );
}

// WORK_UNIT_CASE: 991/11
#[tokio::test]
async fn wrong_response_kind_is_a_typed_contract_error_with_no_second_send() {
    // A valid response of the wrong kind observed after the single send is a
    // typed contract defect, never success and never a second wire operation:
    // exactly one reserved-write send, zero receipt queries.
    let request = fixture_request();
    let counters = Counters::default();
    let kind_requirement = requirement();
    let client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(kind_requirement.clone(), counters.clone())
            .with_reserved_write_response(StoreResponse::Readiness {
                receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
            }),
        kind_requirement,
    )
    .await
    .unwrap();
    assert_eq!(
        client.apply_reserved_write(request.clone()).await,
        Err(StoreError::InvalidReceipt)
    );
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        counters.receipt_calls.load(Ordering::SeqCst),
        0,
        "a wrong-kind response returns its typed contract error with no second send"
    );
    assert!(
        counters.receipt_operations.lock().unwrap().is_empty(),
        "a wrong-kind response issues no receipt query at all"
    );
}

// WORK_UNIT_CASE: 991/12
#[tokio::test]
async fn uncertain_send_preserves_unknown_outcome_with_no_second_send() {
    // Response loss after the send crosses the boundary preserves the typed
    // unknown outcome for the admitted operation: exactly one reserved-write
    // send, no receipt query, no second send, no new identity.
    let request = fixture_request();
    let counters = Counters::default();
    let requirement = requirement();
    let client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(requirement.clone(), counters.clone()).with_reserved_write_response(
            StoreResponse::Unknown {
                operation_id: request.transition.identity.operation_id.clone(),
                reason: "send crossed, answer lost".to_owned(),
            },
        ),
        requirement,
    )
    .await
    .unwrap();
    assert_eq!(
        client.apply_reserved_write(request.clone()).await,
        Err(StoreError::MissingReceiptEnvelope)
    );
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        counters.receipt_calls.load(Ordering::SeqCst),
        0,
        "an unknown outcome preserves the typed unknown error with no second send"
    );
    assert!(
        counters.receipt_operations.lock().unwrap().is_empty(),
        "an unknown outcome issues no receipt query at all"
    );
}

// WORK_UNIT_CASE: 991/13
#[tokio::test]
async fn deterministic_conflict_stays_distinct_from_unknown_commit() {
    // A deterministic not-applied/conflict surfaces typed with no
    // reconciliation query; an unknown-outcome failure preserves the typed
    // unknown error with no second send either.
    let request = fixture_request();
    let counters = Counters::default();
    let conflict_requirement = requirement();
    let client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(conflict_requirement.clone(), counters.clone())
            .with_reserved_write_response(StoreResponse::Failure {
                failure: failure_for(StoreError::RevisionConflict, &request),
            }),
        conflict_requirement,
    )
    .await
    .unwrap();
    assert_eq!(
        client.apply_reserved_write(request.clone()).await,
        Err(StoreError::RevisionConflict)
    );
    assert_eq!(counters.reserved_write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        counters.receipt_calls.load(Ordering::SeqCst),
        0,
        "a proven conflict never reconciles"
    );
    let unknown_counters = Counters::default();
    let unknown_requirement = requirement();
    let unknown_client = EbpCanonicalStoreClient::connect(
        FakeTransport::new(unknown_requirement.clone(), unknown_counters.clone())
            .with_reserved_write_response(StoreResponse::Failure {
                failure: failure_for(StoreError::MissingReceiptEnvelope, &request),
            }),
        unknown_requirement,
    )
    .await
    .unwrap();
    assert_eq!(
        unknown_client.apply_reserved_write(request.clone()).await,
        Err(StoreError::MissingReceiptEnvelope)
    );
    assert_eq!(
        unknown_counters.reserved_write_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        unknown_counters.receipt_calls.load(Ordering::SeqCst),
        0,
        "a typed unknown-outcome failure preserves the unknown error with no second send"
    );
    assert!(
        unknown_counters
            .receipt_operations
            .lock()
            .unwrap()
            .is_empty(),
        "a typed unknown-outcome failure issues no receipt query at all"
    );
}
