//! T12-04 K1 edge proofs (owner #779): `EbpCanonicalStoreClient::dreamer_job`
//! and `KernelStoreGateway::dreamer_job` over the S0 named Dreamer family.
//!
//! The READER-T12-04 brief is absent from this worktree, so the 24-case
//! matrix below is derived from the T12-04 slice assignment (validate,
//! fence, exact `StoreRequest::DreamerJob`, per-op capability, single
//! `execute_raw`, `validate_for` binding, wrong-variant/identity/fence
//! handling, same-identity reconcile, failure-directive preservation, no
//! auto-retry; exchange stable-id extraction; gateway gates mirroring
//! `initialize_genesis` with the K0 `JobRole` caller rule) and the T12
//! acceptance (round trip; dropped response reconciled with the same
//! mutation identity and fresh transport correlation; proven-not-applied
//! distinguished from still-unknown).
//!
//! Case map (`WORK_UNIT_CASE 779/01-24`):
//! - 01 submit round trip: single `DreamerJob` frame, no reconcile query.
//! - 02 status round trip: pure observation with null disposition.
//! - 03 invalid ctx (inverted clock) rejected before any send.
//! - 04 tampered request digest rejected before any send.
//! - 05 ctx fence outside the requirement fence rejected before any send.
//! - 06 ctx fence outside the admitted operation fence rejected pre-send.
//! - 07 role-denied operation (`Requester` + `LEASE_EXACT`) is
//!   `UnknownOperation` with no send.
//! - 08 closed role-permission matrix plus per-op capability mapping.
//! - 09 wrong-variant answer reconciles the admitted identity (still unknown).
//! - 10 foreign-identity answer reconciles the admitted identity.
//! - 11 fence-divergent answer reconciles the admitted identity.
//! - 12 dropped response reconciles the same identity with fresh correlation.
//! - 13 typed unknown-outcome failure reconciles (still unknown).
//! - 14 deterministic conflict preserved verbatim, no reconcile, one send.
//! - 15 deterministic unsupported preserved verbatim, no reconcile, one send.
//! - 16 `UnknownOutcome` delivery reconciles the ADMITTED operation id
//!   (exchange stable-id extraction for `DreamerJob`).
//! - 17 undecodable frame reconciles the admitted operation id.
//! - 18 response-id mismatch reconciles the admitted operation id.
//! - 19 gateway submit round trip over loopback; lease released (2nd call ok).
//! - 20 fenced gateway rejects before any store frame.
//! - 21 foreign-fence request rejected by the route gate, no store frame.
//! - 22 role-denied rejected by the caller rule; non-`eliotd` source passes.
//! - 23 ctx/request fence mismatch rejected before any store frame.
//! - 24 unknown peer answer reconciles same identity with fresh correlation,
//!   exactly once (no retry).
//!
//! Frozen inputs live in `tests/data/dreamer-job-store-edge/` (lineage-A,
//! sequence-1, generation-1 fence domain for cases 01-18). Gateway cases
//! (19-24) reuse the same shapes rebased to the live service fence.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Test futures embed the scripted/loopback transports inline; production
// futures stay boxed at their seams (S2 pattern). Precedent: S1
// `dreamer_job` tests carry the same allowance.
#![allow(clippy::large_futures)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_ipc::{DeliveryOutcome, TransportLimits};
use eliot_kernel_service::{
    EbpCanonicalStoreClient, EbpStoreTransport, HostStoreBootstrapRequirement, StoreClientError,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::dreamer_job::{
    DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation, JobOperationKind,
    JobRole,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion, ServerHello,
};
use eliot_store_api::{
    CAPABILITIES, CanonicalStoreClient, EFFECTS, OperationId, ReadinessReceipt, RequestMeta,
    StoreError, StoreFailure, StoreFailureIdentityContext, StoreRequest, StoreResponse,
    decode_request_frame, dreamer_job_capability, response_frame,
};
use serde_json::Value;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/dreamer-job-store-edge"
);

fn load_fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}")).expect("edge fixture");
    serde_json::from_str(&text).expect("edge fixture json")
}

fn edge_fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE_A).expect("edge lineage"),
            NonZeroU64::new(1).expect("edge sequence"),
        )
        .expect("edge epoch"),
        ResourceGeneration::new(1).expect("edge generation"),
    )
}

fn fence_json(fence: &StateFence) -> Value {
    serde_json::to_value(fence).expect("fence json")
}

fn epoch_json(fence: &StateFence) -> Value {
    serde_json::to_value(&fence.authority_epoch).expect("epoch json")
}

/// Rebases one frozen operation to `fence`, keeping K0-internal equalities
/// (`work_scope == admission.scope`, authority/validity epochs, scalar
/// resource generations) exact.
fn rebase_operation(mut operation: Value, fence: &Value, epoch: &Value, generation: u64) -> Value {
    if let Some(submission) = operation.get_mut("submission") {
        submission["work_scope"]["state_fence"] = fence.clone();
        submission["work_scope"]["resource_generation"] = Value::from(generation);
        let scope = submission["work_scope"].clone();
        submission["admission"]["scope"] = scope;
        submission["admission"]["resource_generation"] = Value::from(generation);
        submission["admission"]["authority"]["state_fence"] = fence.clone();
        submission["admission"]["authority"]["authority_epoch"] = epoch.clone();
        submission["admission"]["validity_epoch"] = epoch.clone();
    }
    if let Some(selector) = operation.get_mut("selector") {
        selector["expected_fence"] = fence.clone();
    }
    if operation.get("expected_fence").is_some() {
        operation["expected_fence"] = fence.clone();
    }
    operation
}

struct EdgeRequest {
    ctx: RequestMeta,
    request: DurableJobRequest,
}

/// Builds one valid edge request: frozen operation rebased to `op_fence`,
/// frozen context bound to `ctx_fence`, stable mutation identity plus fresh
/// transport correlation, digest recomputed over the exact assembled bytes.
#[allow(clippy::too_many_arguments)]
fn build_request(
    operation_fixture: &str,
    role: JobRole,
    op_fence: &StateFence,
    ctx_fence: &StateFence,
    ctx_request_id: &str,
    source_id: &str,
    operation_id: &str,
    idempotency_key: &str,
    transport_key: &str,
) -> EdgeRequest {
    let edge = build_request_raw(
        operation_fixture,
        role,
        op_fence,
        ctx_fence,
        ctx_request_id,
        source_id,
        operation_id,
        idempotency_key,
        transport_key,
    );
    edge.request.validate().expect("edge request validates");
    edge
}

/// Builds one edge request without asserting K0 validity, for callers that
/// intentionally stage a shape-valid but role-denied request.
#[allow(clippy::too_many_arguments)]
fn build_request_raw(
    operation_fixture: &str,
    role: JobRole,
    op_fence: &StateFence,
    ctx_fence: &StateFence,
    ctx_request_id: &str,
    source_id: &str,
    operation_id: &str,
    idempotency_key: &str,
    transport_key: &str,
) -> EdgeRequest {
    let operation_value = rebase_operation(
        load_fixture(operation_fixture),
        &fence_json(op_fence),
        &epoch_json(op_fence),
        op_fence.resource_generation.value(),
    );
    let operation: JobOperation =
        serde_json::from_value(operation_value).expect("edge operation validates");
    let mut ctx_value = load_fixture("context.json");
    ctx_value["state_fence"] = fence_json(ctx_fence);
    ctx_value["request_id"] = Value::String(ctx_request_id.to_owned());
    ctx_value["source_id"] = Value::String(source_id.to_owned());
    let ctx: RequestMeta = serde_json::from_value(ctx_value.clone()).expect("edge ctx validates");
    let kind = operation.kind().as_str().to_owned();
    let fence_value = fence_json(op_fence);
    let mut identity_value = serde_json::json!({
        "request": {
            "request": {"metadata": ctx_value, "state_fence": fence_value.clone()},
            "idempotency_key": transport_key,
            "deadline_unix_ms": 600_000u64,
            "cancellation_id": "cancel-edge-01",
        },
        "operation": {
            "operation_id": operation_id,
            "request_id": "originating-edge",
            "idempotency_key": idempotency_key,
            "operation_kind": kind,
            "effect": "CANDIDATE",
            "state_fence": fence_value,
        },
        "canonical_request_hash": "0".repeat(64),
    });
    // NOTE: the inner correlation metadata above is the *ctx-fence* context
    // only when `op_fence == ctx_fence`. Callers that split the fences get a
    // request whose inner identity follows the operation fence; the outer
    // `ctx` is what crosses the client boundary.
    let mut identity: DurableRequestIdentity =
        serde_json::from_value(identity_value.clone()).expect("edge identity validates");
    identity.canonical_request_hash = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &operation,
        role,
    )
    .expect("edge digest computes");
    identity_value["canonical_request_hash"] =
        Value::String(identity.canonical_request_hash.clone());
    let _ = identity_value;
    let request = DurableJobRequest {
        request_identity: identity,
        role,
        operation,
    };
    EdgeRequest { ctx, request }
}

/// Builds one valid edge request with the inner identity metadata rebound to
/// `inner_ctx` (used when the outer ctx fence must differ from the operation
/// fence while K0 stays valid).
#[allow(clippy::too_many_arguments)]
fn build_request_with_inner_ctx(
    operation_fixture: &str,
    role: JobRole,
    op_fence: &StateFence,
    inner_ctx: &RequestMeta,
    inner_ctx_json: &Value,
    outer_ctx: RequestMeta,
    operation_id: &str,
    idempotency_key: &str,
    transport_key: &str,
) -> EdgeRequest {
    let operation_value = rebase_operation(
        load_fixture(operation_fixture),
        &fence_json(op_fence),
        &epoch_json(op_fence),
        op_fence.resource_generation.value(),
    );
    let operation: JobOperation =
        serde_json::from_value(operation_value).expect("edge operation validates");
    let kind = operation.kind().as_str().to_owned();
    let fence_value = fence_json(op_fence);
    let identity_value = serde_json::json!({
        "request": {
            "request": {"metadata": inner_ctx_json, "state_fence": fence_value.clone()},
            "idempotency_key": transport_key,
            "deadline_unix_ms": 600_000u64,
            "cancellation_id": "cancel-edge-01",
        },
        "operation": {
            "operation_id": operation_id,
            "request_id": "originating-edge",
            "idempotency_key": idempotency_key,
            "operation_kind": kind,
            "effect": "CANDIDATE",
            "state_fence": fence_value,
        },
        "canonical_request_hash": "0".repeat(64),
    });
    let mut identity: DurableRequestIdentity =
        serde_json::from_value(identity_value).expect("edge identity validates");
    identity.canonical_request_hash = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &operation,
        role,
    )
    .expect("edge digest computes");
    let request = DurableJobRequest {
        request_identity: identity,
        role,
        operation,
    };
    request.validate().expect("edge request validates");
    let _ = inner_ctx;
    EdgeRequest {
        ctx: outer_ctx,
        request,
    }
}

fn submit_edge(tag: &str) -> EdgeRequest {
    let fence = edge_fence();
    build_request(
        "submit-operation.json",
        JobRole::Requester,
        &fence,
        &fence,
        &format!("edge-ctx-{tag}"),
        "edge-caller",
        &format!("op-edge-submit-{tag}"),
        &format!("idem-edge-submit-{tag}"),
        &format!("transport-edge-submit-{tag}"),
    )
}

fn status_edge(tag: &str) -> EdgeRequest {
    let fence = edge_fence();
    build_request(
        "status-operation.json",
        JobRole::Requester,
        &fence,
        &fence,
        &format!("edge-ctx-{tag}"),
        "edge-caller",
        &format!("op-edge-status-{tag}"),
        &format!("idem-edge-status-{tag}"),
        &format!("transport-edge-status-{tag}"),
    )
}

/// Binds one frozen response shape to `edge`: exact identity echo plus the
/// owner receipt reference derived from the admitted operation id.
fn build_response(
    shape_fixture: &str,
    edge: &EdgeRequest,
    with_receipt: bool,
) -> DurableJobResponse {
    let mut value = load_fixture(shape_fixture);
    value["request_identity"] =
        serde_json::to_value(&edge.request.request_identity).expect("identity json");
    if with_receipt {
        value["receipt_id"] = Value::String(format!(
            "dreamer-receipt-{}",
            edge.request
                .request_identity
                .operation
                .operation_id
                .as_str()
        ));
    }
    let response: DurableJobResponse =
        serde_json::from_value(value).expect("edge response shape validates");
    response
        .validate_for(&edge.request)
        .expect("edge response answers its request");
    response
}

fn edge_requirement_for(fence: &StateFence) -> HostStoreBootstrapRequirement {
    HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").expect("edge route"),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").expect("edge pipe"),
        store_generation: fence.resource_generation,
        state_fence: fence.clone(),
        launch_nonce: PlatformHandle::new("launch-edge").expect("edge nonce"),
        connection_id: PlatformHandle::new("connection-edge").expect("edge connection"),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("edge sid"),
        expected_peer_session_id: 1,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("edge artifact"),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("edge config"),
        timeout_ms: 30_000,
    }
}

#[derive(Clone)]
enum DreamerReply {
    Fixed(StoreResponse),
    FixedFailure(StoreError),
    UnknownDelivery,
    GarbageFrame,
    WrongRequestId(StoreResponse),
    DropConnection,
}

#[derive(Default)]
struct PeerState {
    dreamer_sends: usize,
    receipt_ops: Vec<String>,
    sent_frames: Vec<(String, String)>,
    dead: bool,
}

struct ScriptedPeer {
    requirement: HostStoreBootstrapRequirement,
    pending: Option<Frame>,
    reply: DreamerReply,
    state: Arc<Mutex<PeerState>>,
}

impl ScriptedPeer {
    fn hello_frame(&self) -> Frame {
        let hello = ServerHello {
            selected_protocol: ProtocolVersion::CURRENT,
            session_principal_binding: "edge-store-session".to_owned(),
            allowed_capabilities: CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            allowed_effects: EFFECTS.iter().map(|value| (*value).to_owned()).collect(),
            config_snapshot: serde_json::json!({
                "config_hash": self.requirement.approved_config_hash.as_str(),
                "artifact_hash": self.requirement.approved_artifact_hash.as_str(),
            }),
            heartbeat_ms: 1_000,
            control_channel: "edge-store-control".to_owned(),
            rejection_reason: None,
            authority_epoch: self.requirement.authority_epoch().clone(),
        };
        eliot_ipc::server_hello_frame(self.requirement.connection_id.as_str(), &hello)
            .expect("edge server hello")
    }

    fn answer_frame(
        &self,
        request_id: eliot_contracts::RequestId,
        response: StoreResponse,
    ) -> Frame {
        response_frame(
            self.requirement.connection_id.as_str(),
            ProtocolVersion::CURRENT,
            Some(request_id),
            response,
        )
        .expect("edge answer encodes")
    }

    fn failure_for(
        error: &StoreError,
        context: &RequestMeta,
        operation_id: &OperationId,
        transport_key: &str,
        fence: &StateFence,
    ) -> StoreFailure {
        StoreFailure::from_store_error(
            error.clone(),
            StoreFailureIdentityContext {
                request_id: Some(context.request_id.clone()),
                operation_id: Some(operation_id.clone()),
                idempotency_key_ref_or_digest: Some(transport_key.to_owned()),
                state_fence_ref_or_exact_safe_projection: Some(fence.clone()),
                evidence_ref: None,
                transport_unavailable: false,
            },
        )
        .expect("edge failure builds")
    }
}

impl EbpStoreTransport for ScriptedPeer {
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
            self.pending = Some(self.hello_frame());
            return Ok(DeliveryOutcome::Delivered);
        }
        let (request_id, _identity, request) =
            decode_request_frame(frame).map_err(StoreClientError::from)?;
        self.record_send(&request, &request_id)?;
        match request {
            StoreRequest::Readiness => {
                self.pending = Some(self.answer_frame(
                    request_id,
                    StoreResponse::Readiness {
                        receipt: ReadinessReceipt::ready("edge-1.0.0".to_owned()),
                    },
                ));
            }
            StoreRequest::DreamerJob { context, request } => {
                return self.answer_dreamer(request_id, &context, &request);
            }
            StoreRequest::Receipt { .. } => {
                self.pending =
                    Some(self.answer_frame(request_id, StoreResponse::Receipt { receipt: None }));
            }
            _ => {
                return Err(StoreClientError::Contract(
                    "edge peer received an unexpected request".to_owned(),
                ));
            }
        }
        Ok(DeliveryOutcome::Delivered)
    }

    async fn receive_frame(&mut self, _limits: TransportLimits) -> Result<Frame, StoreClientError> {
        if self.state.lock().expect("edge peer state").dead {
            return Err(StoreClientError::Transport("edge peer is gone".to_owned()));
        }
        self.pending
            .take()
            .ok_or_else(|| StoreClientError::Transport("edge answer missing".to_owned()))
    }
}

impl ScriptedPeer {
    /// Records one decoded send by variant and, for receipt queries, by
    /// exact admitted identity — even when the dead peer cannot answer it.
    fn record_send(
        &self,
        request: &StoreRequest,
        request_id: &eliot_contracts::RequestId,
    ) -> Result<(), StoreClientError> {
        let variant = match request {
            StoreRequest::Readiness => "readiness",
            StoreRequest::DreamerJob { .. } => "dreamer_job",
            StoreRequest::Receipt { .. } => "receipt",
            _ => "other",
        };
        let mut state = self.state.lock().expect("edge peer state");
        state
            .sent_frames
            .push((variant.to_owned(), request_id.as_str().to_owned()));
        if let StoreRequest::Receipt { operation_id } = request {
            state.receipt_ops.push(operation_id.as_str().to_owned());
        }
        if state.dead {
            return Err(StoreClientError::Transport("edge peer is gone".to_owned()));
        }
        Ok(())
    }

    /// Answers one ledger send from the staged script. Every arm sends at
    /// most one frame and never retries.
    fn answer_dreamer(
        &mut self,
        request_id: eliot_contracts::RequestId,
        context: &RequestMeta,
        request: &DurableJobRequest,
    ) -> Result<DeliveryOutcome, StoreClientError> {
        self.state.lock().expect("edge peer state").dreamer_sends += 1;
        match self.reply.clone() {
            DreamerReply::Fixed(response) => {
                self.pending = Some(self.answer_frame(request_id, response));
            }
            DreamerReply::FixedFailure(error) => {
                let failure = Self::failure_for(
                    &error,
                    context,
                    &request.request_identity.operation.operation_id,
                    &request.request_identity.request.idempotency_key,
                    &request.request_identity.operation.state_fence,
                );
                self.pending =
                    Some(self.answer_frame(request_id, StoreResponse::Failure { failure }));
            }
            DreamerReply::UnknownDelivery => {
                return Ok(DeliveryOutcome::UnknownOutcome);
            }
            DreamerReply::GarbageFrame => {
                self.pending = Some(Frame {
                    protocol_version: ProtocolVersion::CURRENT,
                    encoding_profile: EncodingProfile::JsonV1,
                    connection_id: self.requirement.connection_id.as_str().to_owned(),
                    request_id: Some(request_id),
                    kind: FrameKind::Response,
                    message_type: MessageType::Result,
                    request_identity: None,
                    payload: ProtocolPayload::Json(serde_json::json!({"not": "a store response"})),
                    trace_context: BTreeMap::new(),
                });
            }
            DreamerReply::WrongRequestId(answer) => {
                let wrong = eliot_contracts::RequestId::new("wrong-request-id").expect("wrong id");
                self.pending = Some(self.answer_frame(wrong, answer));
            }
            DreamerReply::DropConnection => {
                self.state.lock().expect("edge peer state").dead = true;
                return Err(StoreClientError::Transport(
                    "edge peer dropped the response".to_owned(),
                ));
            }
        }
        Ok(DeliveryOutcome::Delivered)
    }
}

async fn connect_client(
    reply: DreamerReply,
) -> (EbpCanonicalStoreClient<ScriptedPeer>, Arc<Mutex<PeerState>>) {
    connect_client_for(edge_fence(), reply).await
}

async fn connect_client_for(
    fence: StateFence,
    reply: DreamerReply,
) -> (EbpCanonicalStoreClient<ScriptedPeer>, Arc<Mutex<PeerState>>) {
    let requirement = edge_requirement_for(&fence);
    let state = Arc::new(Mutex::new(PeerState::default()));
    let peer = ScriptedPeer {
        requirement: requirement.clone(),
        pending: None,
        reply,
        state: Arc::clone(&state),
    };
    let client = EbpCanonicalStoreClient::connect(peer, requirement)
        .await
        .expect("edge handshake and readiness");
    assert_eq!(
        state.lock().expect("peer state").dreamer_sends,
        0,
        "handshake must not send ledger frames"
    );
    (client, state)
}

fn peer_snapshot(state: &Arc<Mutex<PeerState>>) -> (usize, Vec<String>, Vec<(String, String)>) {
    let guard = state.lock().expect("peer state");
    (
        guard.dreamer_sends,
        guard.receipt_ops.clone(),
        guard.sent_frames.clone(),
    )
}

// 779/01 — submit round trip: single DreamerJob frame, no reconcile query.
#[tokio::test]
async fn dreamer_job_submit_round_trip_is_one_call_without_reconcile() {
    let edge = submit_edge("01");
    let response = build_response("submit-response-shape.json", &edge, true);
    let (client, state) = connect_client(DreamerReply::Fixed(StoreResponse::DreamerJob {
        response: response.clone(),
    }))
    .await;
    let observed = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request.clone())
        .await
        .expect("779/01 submit answers");
    assert_eq!(observed, response);
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1, "779/01 exactly one ledger send");
    assert!(receipts.is_empty(), "779/01 no reconcile query on success");
}

// 779/02 — status round trip: pure observation with null disposition.
#[tokio::test]
async fn dreamer_job_status_round_trip_carries_no_disposition() {
    let edge = status_edge("02");
    let response = build_response("status-response-shape.json", &edge, false);
    assert!(
        response.disposition.is_none(),
        "779/02 status stays a pure observation"
    );
    let (client, state) = connect_client(DreamerReply::Fixed(StoreResponse::DreamerJob {
        response: response.clone(),
    }))
    .await;
    let observed = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request.clone())
        .await
        .expect("779/02 status answers");
    assert_eq!(observed, response);
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert!(receipts.is_empty());
}

// 779/03 — invalid ctx (inverted clock) rejected before any send.
#[tokio::test]
async fn dreamer_job_rejects_invalid_ctx_before_send() {
    let mut edge = submit_edge("03");
    edge.ctx.clock.known_time_ms = Some(999);
    edge.ctx.clock.valid_time_ms = Some(1_000);
    let (client, state) = connect_client(DreamerReply::DropConnection).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/03 invalid ctx must fail");
    assert!(
        matches!(error, StoreError::Foundation(_)),
        "779/03 foundation clock rejection, got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 0, "779/03 no ledger send");
    assert!(receipts.is_empty());
}

// 779/04 — tampered request digest rejected before any send.
#[tokio::test]
async fn dreamer_job_rejects_tampered_digest_before_send() {
    let mut edge = submit_edge("04");
    edge.request.request_identity.canonical_request_hash = "f".repeat(64);
    let (client, state) = connect_client(DreamerReply::DropConnection).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/04 tampered digest must fail");
    assert_eq!(error, StoreError::IdentityConflict, "779/04 got {error:?}");
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 0);
    assert!(receipts.is_empty());
}

// 779/05 — ctx fence outside the requirement fence rejected before any send.
#[tokio::test]
async fn dreamer_job_rejects_ctx_fence_outside_requirement() {
    let fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE_A).expect("lineage"),
            NonZeroU64::new(2).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    let edge = build_request(
        "submit-operation.json",
        JobRole::Requester,
        &fence,
        &fence,
        "edge-ctx-05",
        "edge-caller",
        "op-edge-submit-05",
        "idem-edge-submit-05",
        "transport-edge-submit-05",
    );
    let (client, state) = connect_client(DreamerReply::DropConnection).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/05 fenced-out ctx must fail");
    assert_eq!(error, StoreError::FenceMismatch, "779/05 got {error:?}");
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 0);
    assert!(receipts.is_empty());
}

// 779/06 — ctx fence outside the admitted operation fence rejected pre-send.
#[tokio::test]
async fn dreamer_job_rejects_ctx_fence_outside_operation_fence() {
    let op_fence = edge_fence();
    let ctx_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE_A).expect("lineage"),
            NonZeroU64::new(2).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    // Inner identity follows the operation fence (K0-valid); the outer ctx
    // presented to the client follows the requirement fence instead.
    let inner = build_request(
        "submit-operation.json",
        JobRole::Requester,
        &op_fence,
        &op_fence,
        "edge-ctx-06",
        "edge-caller",
        "op-edge-submit-06",
        "idem-edge-submit-06",
        "transport-edge-submit-06",
    );
    let mut outer_ctx_value = serde_json::to_value(&inner.ctx).expect("ctx json");
    outer_ctx_value["state_fence"] = fence_json(&ctx_fence);
    let outer_ctx: RequestMeta =
        serde_json::from_value(outer_ctx_value).expect("outer ctx validates");
    let inner_json = serde_json::to_value(&inner.ctx).expect("inner ctx json");
    let edge = build_request_with_inner_ctx(
        "submit-operation.json",
        JobRole::Requester,
        &op_fence,
        &inner.ctx,
        &inner_json,
        outer_ctx,
        "op-edge-submit-06",
        "idem-edge-submit-06",
        "transport-edge-submit-06",
    );
    let (client, state) = connect_client_for(ctx_fence, DreamerReply::DropConnection).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/06 split fence must fail");
    assert_eq!(error, StoreError::FenceMismatch, "779/06 got {error:?}");
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 0);
    assert!(receipts.is_empty());
}

// 779/07 — role-denied operation is UnknownOperation with no send.
#[tokio::test]
async fn dreamer_job_rejects_role_denied_operation_without_send() {
    let fence = edge_fence();
    let edge = build_request_raw(
        "lease-exact-operation.json",
        JobRole::Requester,
        &fence,
        &fence,
        "edge-ctx-07",
        "edge-caller",
        "op-edge-lease-07",
        "idem-edge-lease-07",
        "transport-edge-lease-07",
    );
    // The fixture shape is K0-valid except for the role projection; prove it.
    assert!(
        matches!(
            edge.request.validate(),
            Err(eliot_protocol::dreamer_job::DurableJobError::CapabilityDenied)
        ),
        "779/07 requester must not hold the lease capability"
    );
    let (client, state) = connect_client(DreamerReply::DropConnection).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/07 denied role must fail");
    assert_eq!(error, StoreError::UnknownOperation, "779/07 got {error:?}");
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 0);
    assert!(receipts.is_empty());
}

// 779/08 — closed role-permission matrix plus per-op capability mapping.
#[test]
fn dreamer_job_role_matrix_and_capability_mapping_are_closed() {
    use JobOperationKind as Kind;
    let matrix: &[(JobRole, Kind, bool)] = &[
        (JobRole::Requester, Kind::Submit, true),
        (JobRole::Requester, Kind::LeaseNext, false),
        (JobRole::Requester, Kind::LeaseExact, false),
        (JobRole::Requester, Kind::Renew, false),
        (JobRole::Requester, Kind::Start, false),
        (JobRole::Requester, Kind::Checkpoint, false),
        (JobRole::Requester, Kind::Resume, false),
        (JobRole::Requester, Kind::BeginVerification, false),
        (JobRole::Requester, Kind::Publish, false),
        (JobRole::Requester, Kind::Status, true),
        (JobRole::Requester, Kind::RequestCancel, true),
        (JobRole::Requester, Kind::Reconcile, true),
        (JobRole::Worker, Kind::Submit, false),
        (JobRole::Worker, Kind::LeaseNext, true),
        (JobRole::Worker, Kind::LeaseExact, true),
        (JobRole::Worker, Kind::Renew, true),
        (JobRole::Worker, Kind::Start, true),
        (JobRole::Worker, Kind::Checkpoint, true),
        (JobRole::Worker, Kind::Resume, true),
        (JobRole::Worker, Kind::BeginVerification, true),
        (JobRole::Worker, Kind::Publish, true),
        (JobRole::Worker, Kind::Status, true),
        (JobRole::Worker, Kind::RequestCancel, false),
        (JobRole::Worker, Kind::Reconcile, true),
        (JobRole::Controller, Kind::Submit, false),
        (JobRole::Controller, Kind::LeaseNext, false),
        (JobRole::Controller, Kind::LeaseExact, false),
        (JobRole::Controller, Kind::Renew, false),
        (JobRole::Controller, Kind::Start, false),
        (JobRole::Controller, Kind::Checkpoint, false),
        (JobRole::Controller, Kind::Resume, false),
        (JobRole::Controller, Kind::BeginVerification, false),
        (JobRole::Controller, Kind::Publish, false),
        (JobRole::Controller, Kind::Status, true),
        (JobRole::Controller, Kind::RequestCancel, true),
        (JobRole::Controller, Kind::Reconcile, true),
    ];
    assert_eq!(matrix.len(), 36, "779/08 three roles by twelve kinds");
    for (role, kind, permitted) in matrix {
        assert_eq!(
            role.permits(*kind),
            *permitted,
            "779/08 {role:?} x {kind:?}"
        );
    }
    // The per-op wire capability consulted by the client is pinned per kind.
    let fence = edge_fence();
    let submit = build_request(
        "submit-operation.json",
        JobRole::Requester,
        &fence,
        &fence,
        "edge-ctx-08a",
        "edge-caller",
        "op-edge-submit-08",
        "idem-edge-submit-08",
        "transport-edge-submit-08",
    );
    assert_eq!(
        dreamer_job_capability(&submit.request.operation),
        "store.dreamer_job.submit"
    );
    let status = build_request(
        "status-operation.json",
        JobRole::Requester,
        &fence,
        &fence,
        "edge-ctx-08b",
        "edge-caller",
        "op-edge-status-08",
        "idem-edge-status-08",
        "transport-edge-status-08",
    );
    assert_eq!(
        dreamer_job_capability(&status.request.operation),
        "store.dreamer_job.status"
    );
    let lease = build_request(
        "lease-exact-operation.json",
        JobRole::Worker,
        &fence,
        &fence,
        "edge-ctx-08c",
        "edge-caller",
        "op-edge-lease-08",
        "idem-edge-lease-08",
        "transport-edge-lease-08",
    );
    assert_eq!(
        dreamer_job_capability(&lease.request.operation),
        "store.dreamer_job.lease_exact"
    );
}

// 779/09 — wrong-variant answer reconciles the admitted identity.
#[tokio::test]
async fn dreamer_job_wrong_variant_reconciles_admitted_identity() {
    let edge = submit_edge("09");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let (client, state) = connect_client(DreamerReply::Fixed(StoreResponse::Readiness {
        receipt: ReadinessReceipt::ready("edge-1.0.0".to_owned()),
    }))
    .await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/09 wrong variant must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/09 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1, "779/09 one ledger send, no retry");
    assert_eq!(receipts, vec![admitted], "779/09 same-identity reconcile");
}

// 779/10 — foreign-identity answer reconciles the admitted identity.
#[tokio::test]
async fn dreamer_job_foreign_identity_reconciles_admitted_identity() {
    let edge = submit_edge("10");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let foreign = submit_edge("10-foreign");
    let foreign_response = build_response("submit-response-shape.json", &foreign, true);
    assert!(
        foreign_response.validate_for(&edge.request).is_err(),
        "779/10 foreign answer must not bind the admitted request"
    );
    let (client, state) = connect_client(DreamerReply::Fixed(StoreResponse::DreamerJob {
        response: foreign_response,
    }))
    .await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/10 foreign identity must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/10 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert_eq!(receipts, vec![admitted]);
}

// 779/11 — fence-divergent answer reconciles the admitted identity.
#[tokio::test]
async fn dreamer_job_fence_divergent_answer_reconciles_admitted_identity() {
    let edge = submit_edge("11");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let mut response = build_response("submit-response-shape.json", &edge, true);
    response.scope.state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE_A).expect("lineage"),
            NonZeroU64::new(2).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    assert!(
        response.validate_for(&edge.request).is_err(),
        "779/11 diverged fence must not bind"
    );
    let (client, state) =
        connect_client(DreamerReply::Fixed(StoreResponse::DreamerJob { response })).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/11 diverged fence must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/11 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert_eq!(receipts, vec![admitted]);
}

// 779/12 — dropped response reconciles the same identity, fresh correlation.
#[tokio::test]
async fn dreamer_job_dropped_response_reconciles_with_fresh_correlation() {
    let edge = submit_edge("12");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let (client, state) = connect_client(DreamerReply::DropConnection).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/12 dropped response must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/12 got {error:?}"
    );
    let (sends, receipts, frames) = peer_snapshot(&state);
    assert_eq!(sends, 1, "779/12 one ledger send, no retry");
    assert_eq!(receipts, vec![admitted], "779/12 same-identity reconcile");
    let dreamer_id = frames
        .iter()
        .find(|(variant, _)| variant == "dreamer_job")
        .map(|(_, id)| id.clone())
        .expect("779/12 ledger frame observed");
    let receipt_id = frames
        .iter()
        .find(|(variant, _)| variant == "receipt")
        .map(|(_, id)| id.clone())
        .expect("779/12 reconcile frame observed");
    assert_ne!(
        dreamer_id, receipt_id,
        "779/12 reconcile uses fresh transport correlation"
    );
}

// 779/13 — typed unknown-outcome failure reconciles (proven-not-applied is
// NOT claimed; still-unknown is preserved).
#[tokio::test]
async fn dreamer_job_unknown_failure_reconciles_without_claiming() {
    let edge = submit_edge("13");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let (client, state) = connect_client(DreamerReply::FixedFailure(
        StoreError::MissingReceiptEnvelope,
    ))
    .await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/13 unknown outcome must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/13 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert_eq!(receipts, vec![admitted]);
}

// 779/14 — deterministic conflict preserved verbatim, no reconcile, one send.
#[tokio::test]
async fn dreamer_job_conflict_failure_is_preserved_without_reconcile() {
    let edge = submit_edge("14");
    let (client, state) =
        connect_client(DreamerReply::FixedFailure(StoreError::RevisionConflict)).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/14 conflict must surface");
    assert_eq!(error, StoreError::RevisionConflict, "779/14 got {error:?}");
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1, "779/14 one send, no retry");
    assert!(
        receipts.is_empty(),
        "779/14 deterministic outcome needs no reconcile"
    );
}

// 779/15 — deterministic unsupported preserved verbatim, no reconcile.
#[tokio::test]
async fn dreamer_job_unsupported_failure_is_preserved_without_reconcile() {
    let edge = status_edge("15");
    let (client, state) =
        connect_client(DreamerReply::FixedFailure(StoreError::UnknownOperation)).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/15 unsupported must surface");
    assert_eq!(error, StoreError::UnknownOperation, "779/15 got {error:?}");
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert!(receipts.is_empty());
}

// 779/16 — UnknownOutcome delivery reconciles the ADMITTED operation id.
// Regression pin for the exchange stable-id extraction: without the
// `DreamerJob` arm the client would report a contract defect and never
// reconcile.
#[tokio::test]
async fn dreamer_job_unknown_delivery_reconciles_admitted_operation() {
    let edge = submit_edge("16");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let (client, state) = connect_client(DreamerReply::UnknownDelivery).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/16 unknown delivery must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/16 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert_eq!(receipts, vec![admitted]);
}

// 779/17 — undecodable frame reconciles the admitted operation id.
#[tokio::test]
async fn dreamer_job_garbage_frame_reconciles_admitted_operation() {
    let edge = submit_edge("17");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let (client, state) = connect_client(DreamerReply::GarbageFrame).await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/17 garbage frame must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/17 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert_eq!(receipts, vec![admitted]);
}

// 779/18 — response-id mismatch reconciles the admitted operation id.
#[tokio::test]
async fn dreamer_job_response_id_mismatch_reconciles_admitted_operation() {
    let edge = submit_edge("18");
    let admitted = edge
        .request
        .request_identity
        .operation
        .operation_id
        .as_str()
        .to_owned();
    let response = build_response("submit-response-shape.json", &edge, true);
    let (client, state) = connect_client(DreamerReply::WrongRequestId(StoreResponse::DreamerJob {
        response,
    }))
    .await;
    let error = CanonicalStoreClient::dreamer_job(&client, &edge.ctx, edge.request)
        .await
        .expect_err("779/18 id mismatch must stay unknown");
    assert_eq!(
        error,
        StoreError::MissingReceiptEnvelope,
        "779/18 got {error:?}"
    );
    let (sends, receipts, _) = peer_snapshot(&state);
    assert_eq!(sends, 1);
    assert_eq!(receipts, vec![admitted]);
}

// Gateway cases run against a loopback named-pipe Store (current-process
// peer) plus a real `KernelService` driven to `Ready`, so every gate below
// is proven against live authority and a real EBP transport.
#[cfg(windows)]
mod gateway_cases {
    use super::*;
    use eliot_contracts::AuthorityEpoch;
    use eliot_ipc::{NamedPipeServer, NamedPipeTransport, PeerIdentity, server_hello_frame};
    use eliot_kernel_core::{GenerationRoute, RouteScope};
    use eliot_kernel_service::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
        HostProcessBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
        KernelService, KernelServiceState, KernelStoreGateway, ProcessObservation, RestartBudget,
    };
    use eliot_platform::KernelActivationNonce;
    use eliot_runtime_contracts::{
        HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
        SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    };

    const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";
    const LIVE_SEQUENCE: u64 = 4;
    const LIVE_GENERATION: u64 = 7;

    fn edge_handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("loopback handle")
    }

    fn live_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(LINEAGE_A).expect("live lineage"),
                NonZeroU64::new(LIVE_SEQUENCE).expect("live sequence"),
            )
            .expect("live epoch"),
            ResourceGeneration::new(LIVE_GENERATION).expect("live generation"),
        )
    }

    fn foreign_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(LINEAGE_B).expect("foreign lineage"),
                NonZeroU64::new(LIVE_SEQUENCE).expect("foreign sequence"),
            )
            .expect("foreign epoch"),
            ResourceGeneration::new(LIVE_GENERATION).expect("foreign generation"),
        )
    }

    fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
        SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:edge".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-edge".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-edge".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-edge".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-edge".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-edge".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-lineage-edge".to_owned(),
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
        .expect("loopback incarnation")
    }

    fn candidate() -> HostKernelCandidateBinding {
        HostKernelCandidateBinding {
            installation_id: edge_handle("installation-edge"),
            host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: EpochId::new(
                EpochLineageId::new(LINEAGE_A).expect("lineage"),
                NonZeroU64::new(LIVE_SEQUENCE).expect("sequence"),
            )
            .expect("epoch"),
            activation_id: edge_handle("activation-edge"),
            artifact_hash: edge_handle("artifact-edge"),
            config_hash: edge_handle("config-edge"),
            job_object_id: edge_handle("Local\\Eliot-Host-Kernel-edge"),
            pipe_identity: edge_handle("\\\\.\\pipe\\eliot-kernel-edge"),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-edge".to_owned(),
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
            restart_budget: RestartBudget::new(1, 1).expect("budget"),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    fn ready_service() -> KernelService {
        let mut service = KernelService::new([7; 32], 2, 4).expect("loopback service");
        let candidate = candidate();
        let permit = KernelActivationPermit {
            operation_id: edge_handle("activation-operation-edge"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: edge_handle("journal-transaction-edge"),
            journal_sequence: 7,
            generation: ResourceGeneration::new(LIVE_GENERATION).expect("generation"),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: KernelActivationNonce::new(edge_handle(&"a".repeat(64)))
                .expect("loopback nonce"),
        };
        service.reconcile(candidate.clone()).expect("reconcile");
        service.apply(KernelControlCommand::Shadow).expect("shadow");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff");
        let activation = service
            .activate_permit(
                &permit,
                ResourceGeneration::new(LIVE_GENERATION).expect("gen"),
                "c".repeat(64),
            )
            .expect("activation");
        service
            .publish_ready(KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: activation.operation_id.clone(),
                activation_nonce_digest: activation.activation_nonce_digest.clone(),
                process: ProcessObservation {
                    process_id: edge_handle("pid:42:start:10"),
                    job_object_id: candidate.job_object_id.clone(),
                    state: ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    evidence_refs: vec![edge_handle("process-evidence-edge")],
                },
                health: HealthVector::healthy(),
                evidence_refs: vec![edge_handle("ready-evidence-edge")],
            })
            .expect("ready");
        assert_eq!(service.state(), KernelServiceState::Ready);
        service
    }

    fn live_submit(tag: &str) -> EdgeRequest {
        let live = live_fence();
        build_request(
            "submit-operation.json",
            JobRole::Requester,
            &live,
            &live,
            &format!("loop-ctx-{tag}"),
            "loopback-caller",
            &format!("op-loop-submit-{tag}"),
            &format!("idem-loop-submit-{tag}"),
            &format!("transport-loop-submit-{tag}"),
        )
    }

    fn live_lease_exact_denied(tag: &str) -> EdgeRequest {
        let live = live_fence();
        build_request_raw(
            "lease-exact-operation.json",
            JobRole::Requester,
            &live,
            &live,
            &format!("loop-ctx-{tag}"),
            "loopback-caller",
            &format!("op-loop-lease-{tag}"),
            &format!("idem-loop-lease-{tag}"),
            &format!("transport-loop-lease-{tag}"),
        )
    }

    fn submit_response_for_job(request: &DurableJobRequest) -> DurableJobResponse {
        let JobOperation::Submit { submission } = &request.operation else {
            panic!("loopback store serves submit only");
        };
        let value = serde_json::json!({
            "request_identity": serde_json::to_value(&request.request_identity).expect("identity"),
            "job_id": submission.job_id,
            "attempt_id": submission.attempt_id,
            "scope": serde_json::to_value(&submission.work_scope).expect("scope"),
            "revision": 1u64,
            "state": "QUEUED",
            "disposition": "COMMITTED",
            "receipt_id": format!("dreamer-receipt-{}", request.request_identity.operation.operation_id.as_str()),
            "lease": null,
            "checkpoint": null,
            "result_under_verification": null,
            "outcome": null,
            "selection_coverage": [],
            "selection_frontier": null,
        });
        let response: DurableJobResponse =
            serde_json::from_value(value).expect("loopback response validates");
        response
            .validate_for(request)
            .expect("loopback response answers its request");
        response
    }

    #[derive(Default)]
    struct LoopbackLog {
        dreamer: Vec<(String, String)>,
        receipt: Vec<(String, String)>,
    }

    #[derive(Clone, Copy)]
    enum LoopbackReply {
        FixedSubmit,
        Unknown,
    }

    #[allow(clippy::too_many_lines)]
    async fn serve_loopback(
        mut server: NamedPipeServer,
        connection_id: String,
        artifact_hash: String,
        config_hash: String,
        authority_epoch: EpochId,
        reply: LoopbackReply,
        log: Arc<Mutex<LoopbackLog>>,
    ) {
        let limits = TransportLimits::default();
        let frame = server
            .receive_frame(limits)
            .await
            .expect("loopback hello arrives");
        assert_eq!(frame.kind, FrameKind::Control, "loopback expects EBP hello");
        let hello = ServerHello {
            selected_protocol: ProtocolVersion::CURRENT,
            session_principal_binding: "loopback-store-session".to_owned(),
            allowed_capabilities: CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            allowed_effects: EFFECTS.iter().map(|value| (*value).to_owned()).collect(),
            config_snapshot: serde_json::json!({
                "config_hash": config_hash,
                "artifact_hash": artifact_hash,
            }),
            heartbeat_ms: 1_000,
            control_channel: "loopback-store-control".to_owned(),
            rejection_reason: None,
            authority_epoch,
        };
        server
            .send_frame(
                &server_hello_frame(&connection_id, &hello).expect("loopback hello encodes"),
                limits,
            )
            .await
            .expect("loopback hello sends");
        let frame = server
            .receive_frame(limits)
            .await
            .expect("loopback readiness arrives");
        let (request_id, _, store_request) =
            decode_request_frame(&frame).expect("readiness decodes");
        assert!(
            matches!(store_request, StoreRequest::Readiness),
            "loopback expects readiness"
        );
        server
            .send_frame(
                &response_frame(
                    connection_id.clone(),
                    ProtocolVersion::CURRENT,
                    Some(request_id),
                    StoreResponse::Readiness {
                        receipt: ReadinessReceipt::ready("loopback-1.0.0".to_owned()),
                    },
                )
                .expect("readiness encodes"),
                limits,
            )
            .await
            .expect("readiness sends");
        loop {
            let next =
                tokio::time::timeout(Duration::from_secs(15), server.receive_frame(limits)).await;
            let Ok(Ok(frame)) = next else {
                break;
            };
            let Ok((request_id, _, store_request)) = decode_request_frame(&frame) else {
                break;
            };
            match store_request {
                StoreRequest::DreamerJob { request, .. } => {
                    let operation = request
                        .request_identity
                        .operation
                        .operation_id
                        .as_str()
                        .to_owned();
                    log.lock()
                        .expect("loopback log")
                        .dreamer
                        .push((operation, request_id.as_str().to_owned()));
                    let answer = match reply {
                        LoopbackReply::FixedSubmit => StoreResponse::DreamerJob {
                            response: submit_response_for_job(&request),
                        },
                        LoopbackReply::Unknown => StoreResponse::Unknown {
                            operation_id: request.request_identity.operation.operation_id.clone(),
                            reason: "loopback uncertainty".to_owned(),
                        },
                    };
                    let Ok(frame) = response_frame(
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
                StoreRequest::Receipt { operation_id } => {
                    log.lock().expect("loopback log").receipt.push((
                        operation_id.as_str().to_owned(),
                        request_id.as_str().to_owned(),
                    ));
                    let Ok(frame) = response_frame(
                        connection_id.clone(),
                        ProtocolVersion::CURRENT,
                        Some(request_id),
                        StoreResponse::Receipt { receipt: None },
                    ) else {
                        break;
                    };
                    if server.send_frame(&frame, limits).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    struct LoopbackSetup {
        gateway: Arc<KernelStoreGateway>,
        log: Arc<Mutex<LoopbackLog>>,
        server_task: tokio::task::JoinHandle<()>,
    }

    async fn loopback_setup(reply: LoopbackReply, tag: &str) -> LoopbackSetup {
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("loopback expectation");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("loopback clock")
            .as_nanos();
        let pipe = format!(
            r"\\.\pipe\eliot\k1edge-{tag}-{}-{nanos}",
            std::process::id()
        );
        let mut server = NamedPipeServer::create(&pipe, &expectation).expect("loopback server");
        let client_pipe = pipe.clone();
        let client_expectation = expectation.clone();
        let client_task = tokio::spawn(async move {
            NamedPipeTransport::connect_authenticated(
                &client_pipe,
                Duration::from_secs(10),
                &client_expectation,
            )
            .await
            .expect("loopback connects")
        });
        server
            .wait_for_authenticated_client(Duration::from_secs(10), &expectation)
            .await
            .expect("loopback admits its own process");
        let transport = client_task.await.expect("loopback client task");
        let (peer_sid, peer_session) = match transport.peer_identity() {
            PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } => (user_identity.clone(), session_identity.clone()),
            PeerIdentity::Unavailable { .. } => {
                panic!("loopback peer is not authenticated")
            }
        };
        let live = live_fence();
        let requirement = HostStoreBootstrapRequirement {
            route_identity: edge_handle("store_bridge"),
            canonical_pipe_identity: edge_handle(&pipe),
            store_generation: live.resource_generation,
            state_fence: live.clone(),
            launch_nonce: edge_handle("launch-loopback"),
            connection_id: edge_handle(&format!("conn-loopback-{tag}")),
            expected_peer_sid: edge_handle(&peer_sid),
            expected_peer_session_id: peer_session.parse().expect("loopback session"),
            approved_artifact_hash: edge_handle(&"a".repeat(64)),
            approved_config_hash: edge_handle(&"b".repeat(64)),
            timeout_ms: 30_000,
        };
        let artifact = requirement.approved_artifact_hash.as_str().to_owned();
        let config = requirement.approved_config_hash.as_str().to_owned();
        let connection_id = requirement.connection_id.as_str().to_owned();
        let log = Arc::new(Mutex::new(LoopbackLog::default()));
        let server_task = tokio::spawn(serve_loopback(
            server,
            connection_id,
            artifact,
            config,
            live.authority_epoch.clone(),
            reply,
            Arc::clone(&log),
        ));
        let client = EbpCanonicalStoreClient::connect(transport, requirement)
            .await
            .expect("loopback EBP handshake");
        let service = Arc::new(Mutex::new(ready_service()));
        service
            .lock()
            .expect("loopback service")
            .acquire_admission()
            .expect("loopback admission is live");
        let route = GenerationRoute::new(
            RouteScope::new("store_bridge").expect("loopback scope"),
            live.resource_generation,
            AuthorityEpoch::new(LIVE_GENERATION).expect("loopback epoch"),
        )
        .expect("loopback route");
        let gateway = Arc::new(KernelStoreGateway::new(service, Arc::new(client), route));
        LoopbackSetup {
            gateway,
            log,
            server_task,
        }
    }

    async fn finish_loopback(setup: LoopbackSetup) {
        drop(setup.gateway);
        tokio::time::timeout(Duration::from_secs(15), setup.server_task)
            .await
            .expect("loopback server joins")
            .expect("loopback server task");
    }

    fn admitted_operation(edge: &EdgeRequest) -> String {
        edge.request
            .request_identity
            .operation
            .operation_id
            .as_str()
            .to_owned()
    }

    // 779/19 — gateway submit round trip; admission lease released (2nd call ok).
    #[tokio::test]
    async fn gateway_submit_round_trip_releases_admission_lease() {
        let setup = loopback_setup(LoopbackReply::FixedSubmit, "19").await;
        let first = live_submit("19a");
        let first_response = setup
            .gateway
            .dreamer_job(&first.ctx, first.request.clone())
            .await
            .expect("779/19 gateway submit answers");
        first_response
            .validate_for(&first.request)
            .expect("779/19 answer binds its request");
        let second = live_submit("19b");
        setup
            .gateway
            .dreamer_job(&second.ctx, second.request.clone())
            .await
            .expect("779/19 second call proves deterministic lease release");
        let (dreamer, receipt) = {
            let log = setup.log.lock().expect("loopback log");
            (log.dreamer.clone(), log.receipt.clone())
        };
        assert_eq!(dreamer.len(), 2, "779/19 two ledger calls");
        assert_eq!(
            dreamer[0].0,
            admitted_operation(&first),
            "779/19 first call carries its identity"
        );
        assert_eq!(
            dreamer[1].0,
            admitted_operation(&second),
            "779/19 second call carries its identity"
        );
        assert!(receipt.is_empty(), "779/19 no reconcile on success");
        finish_loopback(setup).await;
    }

    // 779/20 — fenced gateway rejects before any store frame.
    #[tokio::test]
    async fn gateway_fenced_rejects_before_store_frames() {
        let setup = loopback_setup(LoopbackReply::FixedSubmit, "20").await;
        setup.gateway.fence();
        let edge = live_submit("20");
        let error = setup
            .gateway
            .dreamer_job(&edge.ctx, edge.request)
            .await
            .expect_err("779/20 fenced gateway must reject");
        assert!(error.contains("fenced"), "779/20 got {error:?}");
        let (dreamer, receipt) = {
            let log = setup.log.lock().expect("loopback log");
            (log.dreamer.clone(), log.receipt.clone())
        };
        assert!(dreamer.is_empty(), "779/20 no ledger frame");
        assert!(receipt.is_empty());
        finish_loopback(setup).await;
    }

    // 779/21 — foreign-fence request rejected by the route gate, no frame.
    #[tokio::test]
    async fn gateway_foreign_fence_rejected_by_route_gate() {
        let setup = loopback_setup(LoopbackReply::FixedSubmit, "21").await;
        let foreign = foreign_fence();
        let edge = build_request(
            "submit-operation.json",
            JobRole::Requester,
            &foreign,
            &foreign,
            "loop-ctx-21",
            "loopback-caller",
            "op-loop-submit-21",
            "idem-loop-submit-21",
            "transport-loop-submit-21",
        );
        let error = setup
            .gateway
            .dreamer_job(&edge.ctx, edge.request)
            .await
            .expect_err("779/21 foreign lineage must fail the route gate");
        assert!(
            error.contains("epoch") || error.contains("generation") || error.contains("route"),
            "779/21 got {error:?}"
        );
        let dreamer = { setup.log.lock().expect("loopback log").dreamer.clone() };
        assert!(dreamer.is_empty(), "779/21 no ledger frame");
        finish_loopback(setup).await;
    }

    // 779/22 — role-denied rejected by the caller rule; the rule is the K0
    // role, never the `eliotd` source check (every case here uses a
    // non-`eliotd` source, and 779/19 passes with it).
    #[tokio::test]
    async fn gateway_caller_rule_is_k0_role_not_source_id() {
        let setup = loopback_setup(LoopbackReply::FixedSubmit, "22").await;
        let edge = live_lease_exact_denied("22");
        assert_eq!(edge.ctx.source_id.as_str(), "loopback-caller");
        let error = setup
            .gateway
            .dreamer_job(&edge.ctx, edge.request)
            .await
            .expect_err("779/22 denied role must fail");
        assert!(error.contains("role"), "779/22 got {error:?}");
        assert!(
            !error.contains("eliotd") && !error.contains("daemon"),
            "779/22 caller rule must not be a source check, got {error:?}"
        );
        let dreamer = { setup.log.lock().expect("loopback log").dreamer.clone() };
        assert!(dreamer.is_empty(), "779/22 no ledger frame");
        finish_loopback(setup).await;
    }

    // 779/23 — ctx/request fence mismatch rejected before any store frame.
    #[tokio::test]
    async fn gateway_ctx_request_fence_mismatch_rejected_pre_store() {
        let setup = loopback_setup(LoopbackReply::FixedSubmit, "23").await;
        let frozen = edge_fence();
        let inner = build_request(
            "submit-operation.json",
            JobRole::Requester,
            &frozen,
            &frozen,
            "loop-ctx-23",
            "loopback-caller",
            "op-loop-submit-23",
            "idem-loop-submit-23",
            "transport-loop-submit-23",
        );
        let live = live_fence();
        let mut outer_value = serde_json::to_value(&inner.ctx).expect("ctx json");
        outer_value["state_fence"] = fence_json(&live);
        let outer_ctx: RequestMeta = serde_json::from_value(outer_value).expect("outer ctx");
        let inner_json = serde_json::to_value(&inner.ctx).expect("inner ctx json");
        let edge = build_request_with_inner_ctx(
            "submit-operation.json",
            JobRole::Requester,
            &frozen,
            &inner.ctx,
            &inner_json,
            outer_ctx,
            "op-loop-submit-23",
            "idem-loop-submit-23",
            "transport-loop-submit-23",
        );
        let error = setup
            .gateway
            .dreamer_job(&edge.ctx, edge.request)
            .await
            .expect_err("779/23 split fence must fail");
        assert!(error.contains("fence"), "779/23 got {error:?}");
        let dreamer = { setup.log.lock().expect("loopback log").dreamer.clone() };
        assert!(dreamer.is_empty(), "779/23 no ledger frame");
        finish_loopback(setup).await;
    }

    // 779/24 — unknown peer answer reconciles same identity, fresh
    // correlation, exactly once (no retry).
    #[tokio::test]
    async fn gateway_unknown_answer_reconciles_once_with_fresh_correlation() {
        let setup = loopback_setup(LoopbackReply::Unknown, "24").await;
        let edge = live_submit("24");
        let admitted = admitted_operation(&edge);
        let error = setup
            .gateway
            .dreamer_job(&edge.ctx, edge.request)
            .await
            .expect_err("779/24 unknown answer must stay unknown");
        assert!(error.contains("receipt"), "779/24 got {error:?}");
        let (dreamer, receipt) = {
            let log = setup.log.lock().expect("loopback log");
            (log.dreamer.clone(), log.receipt.clone())
        };
        assert_eq!(
            dreamer.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>(),
            vec![admitted.clone()],
            "779/24 exactly one ledger send, no retry"
        );
        assert_eq!(
            receipt.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>(),
            vec![admitted],
            "779/24 same-identity reconcile"
        );
        assert_ne!(
            dreamer[0].1, receipt[0].1,
            "779/24 reconcile uses fresh transport correlation"
        );
        finish_loopback(setup).await;
    }
}
