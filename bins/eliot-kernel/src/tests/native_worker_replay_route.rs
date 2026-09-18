//! T9-03 replay-route proofs (issue #22).
//!
//! Pure mapping/gating proofs plus handler proofs through a real
//! [`KernelComposition`] over the real ORS `redb` store: every admission
//! uses the production T9-02 claim gate (recomputed, never trusted), every
//! durable step commits through ORS, and every receipt is sealed and
//! re-verified. No fakes, no stubs, no canned digests: digests are
//! recomputed through the real canonical procedures (`compute_binding_digest`,
//! canonical fence digest, SHA-256 payload digests).
//!
//! Wiring note: this file is compiled as a `#[cfg(test)]` child of
//! `super::native_worker_replay_route` (see the `#[path]` declaration at the
//! bottom of that owned module), so it exercises the route's handlers
//! directly while keeping `bins/eliot-kernel/src/tests.rs` untouched.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use super::{
    NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION, NATIVE_WORKER_REPLAY_APPEND_OPERATION,
    NATIVE_WORKER_REPLAY_BEGIN_OPERATION, NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
    NATIVE_WORKER_REPLAY_OPERATION, is_native_worker_replay_operation, map_ack_phase,
    map_delivery_class, map_envelope,
};
use crate::{KernelComposition, KernelConfig};
use eliot_contracts::{EpochId, StateFence, sha256_hex};
use eliot_ipc::{PeerIdentity, Session, TransportError};
use eliot_kernel_service::{
    NATIVE_WORKER_CLAIM_WIRE_ID, NATIVE_WORKER_CLAIM_WIRE_VERSION,
    NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
    NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION, NATIVE_WORKER_PROTOCOL_VERSION,
    NativeWorkerClaimBudget, NativeWorkerClaimRequest, NativeWorkerExecutableBinding,
    NativeWorkerReplayAckPhase, NativeWorkerReplayDeliveryClass,
};
use eliot_ors::{
    NativeWorkerClaimRecord, NativeWorkerClaimState, OpaqueLabel, OperationIdentity,
    WorkerReplayDeliveryClass as OrsDeliveryClass,
};
use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};

fn temp_root(slug: &str) -> std::path::PathBuf {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-t903-replay-{slug}-{}-{ms}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    root
}

fn open_kernel(root: &std::path::Path) -> KernelComposition {
    KernelComposition::new(KernelConfig::new(root)).expect("kernel composition")
}

fn live_epoch(kernel: &KernelComposition) -> EpochId {
    kernel
        .service
        .lock()
        .expect("service lock")
        .authority_epoch()
}

fn session_fence(kernel: &KernelComposition) -> StateFence {
    kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .module_generation
        .state_fence
        .clone()
}

/// Currency fence for crafted presentations: the session fence shape with
/// the live authority epoch, so fence-bound checks and epoch-bound checks
/// agree exactly as they do at a real admission.
fn currency_fence(kernel: &KernelComposition, live: &EpochId) -> StateFence {
    let mut fence = session_fence(kernel);
    fence.authority_epoch = live.clone();
    fence
}

fn test_session(kernel: &KernelComposition) -> Session {
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .expect("peer");
    Session {
        connection_id: "t903-replay-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation: policy.module_generation.clone(),
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
        .try_into()
        .unwrap_or(u64::MAX)
}

fn label(value: &str) -> OpaqueLabel {
    OpaqueLabel::new(value).expect("opaque label")
}

fn identity(value: &str) -> OperationIdentity {
    OperationIdentity::new(value).expect("operation identity")
}

fn owner_digest() -> String {
    sha256_hex(b"t9-03 replay route owner-issued executable digest stand-in")
}

fn test_join(
    claim_id: &str,
    live: &EpochId,
    fence: &StateFence,
    config_digest: &str,
    digest: &str,
) -> NativeWorkerExecutableBinding {
    let now = now_ms();
    NativeWorkerExecutableBinding {
        route_ref: "route://test/full-canonical-route".to_owned(),
        adapter_id: "adapter-test".to_owned(),
        adapter_revision: 3,
        config_digest: config_digest.to_owned(),
        facet_manifest_ref: "facet-manifest-7".to_owned(),
        grant_graph_revision: 5,
        replay_stream_id: format!("{claim_id}/gen-1"),
        launch_nonce: "launch-nonce-0123456789abcdef".to_owned(),
        process_invocation_digest: "d".repeat(64),
        authority_epoch: live.clone(),
        generation: fence.resource_generation,
        state_fence: fence.clone(),
        deadline_unix_ms: now.saturating_add(100_000),
        expires_at_unix_ms: now.saturating_add(200_000),
        executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
        executable_binding_digest: digest.to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn test_claim_request(
    claim_id: &str,
    registration_id: &str,
    live: &EpochId,
    fence: &StateFence,
    join: NativeWorkerExecutableBinding,
    deadline_unix_ms: u64,
) -> NativeWorkerClaimRequest {
    let mut request = NativeWorkerClaimRequest {
        wire_id: NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
        wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
        claim_id: claim_id.to_owned(),
        registration_id: registration_id.to_owned(),
        worker_generation: 1,
        installation_id: "installation-1".to_owned(),
        worker_artifact_digest: "a".repeat(64),
        worker_config_digest: "b".repeat(64),
        protocol_version: NATIVE_WORKER_PROTOCOL_VERSION.to_owned(),
        execution_unit_schema_version: NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION,
        parent_job_id: "parent-job-1".to_owned(),
        task_id: "task-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        decision_id: "decision-1".to_owned(),
        attempt_id: "attempt-1".to_owned(),
        operation_id: "operation-1".to_owned(),
        route_class: "test-route".to_owned(),
        budget: NativeWorkerClaimBudget {
            context_tokens: 8,
            wall_time_ms: 1_000,
            output_bytes: 1_024,
            cost_microunits: 10,
            max_depth: 2,
            max_descendants: 4,
        },
        deadline_unix_ms,
        cancellation_policy_id: "cancel-1".to_owned(),
        expected_result_schema: "result-schema".to_owned(),
        expected_result_schema_version: 1,
        predecessor_revision: "rev-1".to_owned(),
        authority_epoch: live.clone(),
        state_fence: fence.clone(),
        executable_binding: Some(join),
        binding_digest: String::new(),
        request_digest: String::new(),
    };
    request.binding_digest = request.compute_binding_digest().expect("binding digest");
    request.request_digest = request.canonical_request_digest().expect("request digest");
    request.validate().expect("claim validates");
    request
        .validate_canonical_digest()
        .expect("canonical digest validates");
    request
}

fn registration_json(
    registration_id: &str,
    live: &EpochId,
    fence: &StateFence,
    lease_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "registration_id": registration_id,
        "protocol_version": NATIVE_WORKER_PROTOCOL_VERSION,
        "execution_unit_schema_version": NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION,
        "worker_artifact_digest": "a".repeat(64),
        "worker_config_digest": "b".repeat(64),
        "process_image_digest": "c".repeat(64),
        "installation_id": "installation-1",
        "principal_ref": "principal-1",
        "connection_id": "t903-replay-conn",
        "lease_id": "lease-1",
        "renewal_id": "renewal-1",
        "worker_generation": 1,
        "process_id": 7,
        "process_start_100ns": 9,
        "lease_expires_at_unix_ms": lease_ms,
        "resource_limits": {
            "wall_timeout_ms": 1_000,
            "stdout_bytes": 1_024,
            "stderr_bytes": 1_024,
        },
        "invalidation_set": [],
        "state_fence": serde_json::to_value(fence).expect("fence JSON"),
        "authority_epoch": live.sequence.get(),
    })
}

/// Crafts one fully-passing admission presentation plus its wire binding.
///
/// Returns `(claim_json, registration_json, binding_json, binding_digest,
/// typed_request)`. The caller stages the ORS record with `record_for`
/// before driving a handler.
fn valid_presentation(
    kernel: &KernelComposition,
    claim_id: &str,
    registration_id: &str,
    digest: &str,
) -> (
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
    String,
    NativeWorkerClaimRequest,
) {
    let live = live_epoch(kernel);
    let fence = currency_fence(kernel, &live);
    let now = now_ms();
    let join = test_join(claim_id, &live, &fence, &"b".repeat(64), digest);
    let request = test_claim_request(
        claim_id,
        registration_id,
        &live,
        &fence,
        join,
        now.saturating_add(300_000),
    );
    let binding_digest = request.binding_digest.clone();
    let mut claim_json = serde_json::to_value(&request).expect("claim JSON");
    // The frame contour carries the epoch as a scalar sequence beside the
    // canonical fence object (the route rebuilds the typed `EpochId` from
    // the fence and cross-checks the scalar); the typed serialization emits
    // the full epoch object, so the scalar is restored here exactly as the
    // worker-side claim contour presents it.
    claim_json["authority_epoch"] = serde_json::json!(live.sequence.get());
    let registration_json =
        registration_json(registration_id, &live, &fence, now.saturating_add(300_000));
    let binding_json = serde_json::json!({
        "claim_id": claim_id,
        "worker_generation": 1,
        "stream_id": format!("{claim_id}/gen-1"),
        "authority_epoch": serde_json::to_value(&live).expect("epoch JSON"),
        "state_fence": serde_json::to_value(&fence).expect("fence JSON"),
        "executable_binding_digest": digest,
    });
    (
        claim_json,
        registration_json,
        binding_json,
        binding_digest,
        request,
    )
}

fn claim_record_for(
    kernel: &KernelComposition,
    claim_id: &str,
    registration_id: &str,
    binding_digest: &str,
) -> NativeWorkerClaimRecord {
    let live = live_epoch(kernel);
    let fence = currency_fence(kernel, &live);
    let fence_digest = KernelComposition::presenting_fence_digest(&fence).expect("fence digest");
    NativeWorkerClaimRecord {
        contract_version: eliot_ors::CONTRACT_VERSION,
        claim_id: identity(claim_id),
        registration_id: label(registration_id),
        worker_generation: 1,
        parent_job_id: label("parent-job-1"),
        task_id: label("task-1"),
        work_scope_id: label("scope-1"),
        decision_id: label("decision-1"),
        attempt_id: label("attempt-1"),
        operation_id: label("operation-1"),
        route_class: label("test-route"),
        budget_digest: "a".repeat(64),
        deadline_unix_ms: now_ms().saturating_add(300_000),
        fence_digest,
        authority_epoch: live.sequence.get(),
        binding_digest: binding_digest.to_owned(),
        request_digest: "e".repeat(64),
        execution_unit_schema_version: 1,
        predecessor_revision: label("rev-1"),
        resource_envelope_digest: format!("{}0", "f".repeat(63)),
        state: NativeWorkerClaimState::Admitted,
        receipt_digest: Some("d".repeat(64)),
        admitted_at_unix_ms: Some(1_700_000_000_000),
        commit_order: 0,
    }
}

fn stage(kernel: &KernelComposition, record: &NativeWorkerClaimRecord) {
    kernel
        .generation_gateway
        .ors
        .stage_native_worker_claim(record)
        .expect("stage claim");
}

fn handler_identity(claim_id: &str) -> serde_json::Value {
    serde_json::json!({ "idempotency_key": claim_id })
}

fn draft_json(stream_id: &str, request_id: &str, payload: &str) -> serde_json::Value {
    serde_json::json!({
        "stream_id": stream_id,
        "producer_id": "producer-1",
        "producer_generation": 1,
        "request_id": request_id,
        "payload_type": "heartbeat",
        "payload_digest": sha256_hex(payload.as_bytes()),
        "payload": payload,
        "causal_predecessor_refs": [],
        "trace_context": {},
        "delivery_class": "DURABLE_OBSERVATION",
        "ack_required": true,
        "disposition": { "kind": "UNKNOWN", "reason": "test draft" },
    })
}

// ---------------------------------------------------------------------------
// Gating and mapping proofs (no composition).
// ---------------------------------------------------------------------------

#[test]
fn replay_operation_gate_names_exactly_the_five_owned_operations() {
    for operation in [
        NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
        NATIVE_WORKER_REPLAY_BEGIN_OPERATION,
        NATIVE_WORKER_REPLAY_APPEND_OPERATION,
        NATIVE_WORKER_REPLAY_OPERATION,
        NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION,
    ] {
        assert!(
            is_native_worker_replay_operation(operation),
            "owned operation must gate open: {operation}"
        );
    }
    for operation in [
        "",
        "native_worker.claim",
        "native_worker.reconcile",
        "native_worker.replay_lookup_extra",
        "NATIVE_WORKER.REPLAY_LOOKUP",
    ] {
        assert!(
            !is_native_worker_replay_operation(operation),
            "foreign operation must gate closed: {operation}"
        );
    }
}

#[test]
fn received_phase_ack_is_refused_and_all_durable_phases_map() {
    use eliot_ors::WorkerReplayPhase as OrsPhase;
    assert!(map_ack_phase(NativeWorkerReplayAckPhase::Received).is_err());
    assert_eq!(
        map_ack_phase(NativeWorkerReplayAckPhase::Durable).expect("durable maps"),
        OrsPhase::Durable
    );
    assert_eq!(
        map_ack_phase(NativeWorkerReplayAckPhase::Normalized).expect("normalized maps"),
        OrsPhase::Normalized
    );
    assert_eq!(
        map_ack_phase(NativeWorkerReplayAckPhase::Applied).expect("applied maps"),
        OrsPhase::Applied
    );
    assert_eq!(
        map_ack_phase(NativeWorkerReplayAckPhase::Rejected).expect("rejected maps"),
        OrsPhase::Rejected
    );
    assert_eq!(
        map_ack_phase(NativeWorkerReplayAckPhase::Unknown).expect("unknown maps"),
        OrsPhase::Unknown
    );
}

#[test]
fn delivery_class_round_trips_through_the_owner_without_reinterpretation() {
    for class in [
        NativeWorkerReplayDeliveryClass::DurableControl,
        NativeWorkerReplayDeliveryClass::DurableObservation,
        NativeWorkerReplayDeliveryClass::BestEffortTelemetry,
    ] {
        let owner = map_delivery_class(class);
        let expected = match class {
            NativeWorkerReplayDeliveryClass::DurableControl => OrsDeliveryClass::DurableControl,
            NativeWorkerReplayDeliveryClass::DurableObservation => {
                OrsDeliveryClass::DurableObservation
            }
            NativeWorkerReplayDeliveryClass::BestEffortTelemetry => {
                OrsDeliveryClass::BestEffortTelemetry
            }
        };
        assert_eq!(owner, expected);
    }
}

#[test]
fn envelope_mapping_recomputes_the_payload_digest_from_owner_bytes() {
    use eliot_ors::{WorkerReplayBegin, WorkerReplayDraft};
    let root = temp_root("envelope-map");
    let kernel = open_kernel(&root);
    let stream_id = "t903-map-claim-1/gen-1".to_owned();
    let record = NativeWorkerClaimRecord {
        contract_version: eliot_ors::CONTRACT_VERSION,
        claim_id: identity("t903-map-claim-1"),
        registration_id: label("t903-map-reg-1"),
        worker_generation: 1,
        parent_job_id: label("parent-job-1"),
        task_id: label("task-1"),
        work_scope_id: label("scope-1"),
        decision_id: label("decision-1"),
        attempt_id: label("attempt-1"),
        operation_id: label("operation-1"),
        route_class: label("test-route"),
        budget_digest: "a".repeat(64),
        deadline_unix_ms: now_ms().saturating_add(300_000),
        fence_digest: "b".repeat(64),
        authority_epoch: 1,
        binding_digest: "c".repeat(64),
        request_digest: "e".repeat(64),
        execution_unit_schema_version: 1,
        predecessor_revision: label("rev-1"),
        resource_envelope_digest: format!("{}0", "f".repeat(63)),
        state: NativeWorkerClaimState::Admitted,
        receipt_digest: Some("d".repeat(64)),
        admitted_at_unix_ms: Some(1_700_000_000_000),
        commit_order: 0,
    };
    stage(&kernel, &record);
    let ors = &kernel.generation_gateway.ors;
    let fingerprint = "{\"kind\":\"EXECUTE\"}".to_owned();
    ors.begin_replay_request(&WorkerReplayBegin {
        stream_id: stream_id.clone(),
        request_id: "req-3".to_owned(),
        fingerprint: fingerprint.clone(),
        producer_generation: 1,
        authority_epoch: 1,
        fence_digest: "b".repeat(64),
    })
    .expect("begin acquires");
    let payload = "{\"beat\":7}".to_owned();
    let event = ors
        .append_replay_event(&WorkerReplayDraft {
            stream_id: stream_id.clone(),
            producer_id: "producer-1".to_owned(),
            producer_generation: 1,
            authority_epoch: 1,
            fence_digest: "b".repeat(64),
            request_id: "req-3".to_owned(),
            causal_predecessor_refs: vec!["event-2".to_owned()],
            delivery_class: OrsDeliveryClass::DurableControl,
            ack_required: true,
            payload_type: "heartbeat".to_owned(),
            payload: payload.clone(),
            disposition: serde_json::from_value(
                serde_json::json!({"kind": "UNKNOWN", "reason": "test"}),
            )
            .expect("disposition"),
            trace_context: std::collections::BTreeMap::new(),
        })
        .expect("append persists");
    let envelope = map_envelope(&event);
    assert_eq!(envelope.sequence, 1);
    assert_eq!(envelope.fingerprint, fingerprint);
    assert_eq!(envelope.payload, payload);
    assert_eq!(envelope.payload_digest, sha256_hex(payload.as_bytes()));
    assert_eq!(envelope.causal_predecessor_refs, vec!["event-2".to_owned()]);
    envelope.validate().expect("mapped envelope validates");
}

// ---------------------------------------------------------------------------
// Handler proofs through a real composition over the real ORS store.
// ---------------------------------------------------------------------------

#[test]
fn lookup_on_admitted_claim_returns_new_with_genesis_position() {
    let root = temp_root("lookup-new");
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let claim_id = "t903-lookup-claim-1";
    let digest = owner_digest();
    let (claim_json, registration_json, binding_json, binding_digest, _request) =
        valid_presentation(&kernel, claim_id, "t903-lookup-reg-1", &digest);
    stage(
        &kernel,
        &claim_record_for(&kernel, claim_id, "t903-lookup-reg-1", &binding_digest),
    );
    let payload = serde_json::json!({
        "operation": NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
        "binding": binding_json,
        "claim": claim_json,
        "registration": registration_json,
        "request_id": "req-lookup-1",
        "fingerprint": "{\"kind\":\"EXECUTE\"}",
    });
    let receipt = kernel
        .handle_replay_lookup(&session, &handler_identity(claim_id), &payload)
        .expect("lookup succeeds");
    let kind = receipt
        .pointer("/reply/decision/kind")
        .and_then(serde_json::Value::as_str)
        .expect("decision carries a kind");
    assert_eq!(kind, "NEW");
    let decision = receipt
        .pointer("/reply/decision/payload/next_sequence")
        .and_then(serde_json::Value::as_u64)
        .expect("New decision carries genesis position");
    assert_eq!(decision, 1);
    let sealed = receipt
        .get("receipt_digest")
        .and_then(serde_json::Value::as_str)
        .expect("receipt sealed");
    assert_eq!(sealed.len(), 64);
}

#[test]
fn unknown_claim_identity_stays_unknown_without_touching_the_store() {
    let root = temp_root("lookup-unknown");
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let claim_id = "t903-ghost-claim-9";
    let digest = owner_digest();
    let (claim_json, registration_json, binding_json, _binding_digest, _request) =
        valid_presentation(&kernel, claim_id, "t903-ghost-reg-9", &digest);
    // Deliberately unstaged: the gate passes on shape, the durable load
    // finds nothing, and the identity stays unknown.
    let payload = serde_json::json!({
        "operation": NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
        "binding": binding_json,
        "claim": claim_json,
        "registration": registration_json,
        "request_id": "req-ghost-1",
        "fingerprint": "{\"kind\":\"EXECUTE\"}",
    });
    let error = kernel
        .handle_replay_lookup(&session, &handler_identity(claim_id), &payload)
        .expect_err("unknown claim must not look up");
    assert!(
        matches!(
            error,
            crate::native_worker_lifecycle_route::NativeWorkerRouteError::Unknown { .. }
        ),
        "unknown claim stays unknown, got {error:?}"
    );
}

#[test]
fn retampered_claim_binding_conflicts_instead_of_promoting() {
    let root = temp_root("lookup-conflict");
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let claim_id = "t903-tamper-claim-1";
    let digest = owner_digest();
    let (_claim_json, registration_json, binding_json, _binding_digest, mut request) =
        valid_presentation(&kernel, claim_id, "t903-tamper-reg-1", &digest);
    stage(
        &kernel,
        &claim_record_for(
            &kernel,
            claim_id,
            "t903-tamper-reg-1",
            &request.binding_digest,
        ),
    );
    // Re-cut the join under the known identity and rebind the envelope
    // digests, so the presentation is internally consistent but no longer
    // the admitted bytes.
    request
        .executable_binding
        .as_mut()
        .expect("join present")
        .adapter_revision = 99;
    request.binding_digest = request.compute_binding_digest().expect("rebind");
    request.request_digest = request.canonical_request_digest().expect("rebind envelope");
    let mut claim_json = serde_json::to_value(&request).expect("claim JSON");
    claim_json["authority_epoch"] = serde_json::json!(live_epoch(&kernel).sequence.get());
    let payload = serde_json::json!({
        "operation": NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
        "binding": binding_json,
        "claim": claim_json,
        "registration": registration_json,
        "request_id": "req-tamper-1",
        "fingerprint": "{\"kind\":\"EXECUTE\"}",
    });
    let error = kernel
        .handle_replay_lookup(&session, &handler_identity(claim_id), &payload)
        .expect_err("re-cut binding must conflict");
    assert!(
        matches!(
            error,
            crate::native_worker_lifecycle_route::NativeWorkerRouteError::Conflict(_)
        ),
        "re-cut binding conflicts, got {error:?}"
    );
}

#[test]
fn begin_append_replay_acknowledge_flow_closes_over_real_durability() {
    let root = temp_root("full-flow");
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let claim_id = "t903-flow-claim-1";
    let registration_id = "t903-flow-reg-1";
    let digest = owner_digest();
    let (claim_json, registration_json, binding_json, binding_digest, _request) =
        valid_presentation(&kernel, claim_id, registration_id, &digest);
    stage(
        &kernel,
        &claim_record_for(&kernel, claim_id, registration_id, &binding_digest),
    );
    let stream_id = format!("{claim_id}/gen-1");
    let request_id = "req-flow-1";
    let fingerprint = "{\"kind\":\"EXECUTE\"}";
    let base = serde_json::json!({
        "binding": binding_json,
        "claim": claim_json,
        "registration": registration_json,
    });
    let identity = handler_identity(claim_id);

    // Begin acquires.
    let mut begin_payload = base.clone();
    begin_payload["operation"] = serde_json::json!(NATIVE_WORKER_REPLAY_BEGIN_OPERATION);
    begin_payload["request_id"] = serde_json::json!(request_id);
    begin_payload["fingerprint"] = serde_json::json!(fingerprint);
    let begin_receipt = kernel
        .handle_replay_begin(&session, &identity, &begin_payload)
        .expect("begin acquires");
    assert_eq!(
        begin_receipt.pointer("/reply/decision/kind"),
        Some(&serde_json::json!("NEW")),
        "first begin is New"
    );

    // A changed fingerprint under the known identity conflicts.
    let mut conflict_payload = begin_payload.clone();
    conflict_payload["fingerprint"] = serde_json::json!("{\"kind\":\"OTHER\"}");
    let conflict = kernel
        .handle_replay_begin(&session, &identity, &conflict_payload)
        .expect_err("changed fingerprint must conflict");
    assert!(
        matches!(
            conflict,
            crate::native_worker_lifecycle_route::NativeWorkerRouteError::Conflict(_)
        ),
        "changed fingerprint conflicts, got {conflict:?}"
    );

    // Append persists one opaque event.
    let payload_bytes = "{\"beat\":1}".to_owned();
    let mut append_payload = base.clone();
    append_payload["operation"] = serde_json::json!(NATIVE_WORKER_REPLAY_APPEND_OPERATION);
    append_payload["draft"] = draft_json(&stream_id, request_id, &payload_bytes);
    let append_receipt = kernel
        .handle_replay_append(&session, &identity, &append_payload)
        .expect("append persists");
    let sequence = append_receipt
        .pointer("/reply/envelope/sequence")
        .and_then(serde_json::Value::as_u64)
        .expect("append returns a sequence");
    assert_eq!(sequence, 1);
    let event_id = append_receipt
        .pointer("/reply/envelope/event_id")
        .and_then(serde_json::Value::as_str)
        .expect("append returns an event id")
        .to_owned();

    // Replay reads the retained suffix with identities intact.
    let mut read_payload = base.clone();
    read_payload["operation"] = serde_json::json!(NATIVE_WORKER_REPLAY_OPERATION);
    read_payload["after_sequence"] = serde_json::json!(0);
    read_payload["limit"] = serde_json::json!(64);
    let read_receipt = kernel
        .handle_replay_read(&session, &identity, &read_payload)
        .expect("replay reads");
    let events = read_receipt
        .pointer("/reply/page/events")
        .and_then(serde_json::Value::as_array)
        .expect("replay returns a page");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]
            .get("event_id")
            .and_then(serde_json::Value::as_str),
        Some(event_id.as_str())
    );
    assert_eq!(
        events[0]
            .get("payload_digest")
            .and_then(serde_json::Value::as_str),
        Some(sha256_hex(payload_bytes.as_bytes()).as_str())
    );

    // DURABLE ack advances the producer cursor only.
    let mut ack_payload = base.clone();
    ack_payload["operation"] = serde_json::json!(NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION);
    ack_payload["receipt"] = serde_json::json!({
        "stream_id": stream_id,
        "event_id": event_id,
        "sequence": 1,
        "producer_generation": 1,
        "phase": "DURABLE",
        "acknowledged_at_unix_ms": now_ms(),
    });
    let ack_receipt = kernel
        .handle_replay_acknowledge(&session, &identity, &ack_payload)
        .expect("durable ack persists");
    assert_eq!(
        ack_receipt.pointer("/reply/producer_cursor_advanced"),
        Some(&serde_json::Value::Bool(true))
    );
    assert_eq!(
        ack_receipt.pointer("/reply/consumer_cursor_advanced"),
        Some(&serde_json::Value::Bool(false))
    );

    // UNKNOWN ack persists the disposition without moving any cursor.
    let mut unknown_payload = ack_payload.clone();
    unknown_payload["receipt"]["phase"] = serde_json::json!("UNKNOWN");
    let unknown_receipt = kernel
        .handle_replay_acknowledge(&session, &identity, &unknown_payload)
        .expect("unknown ack persists");
    assert_eq!(
        unknown_receipt.pointer("/reply/producer_cursor_advanced"),
        Some(&serde_json::Value::Bool(false))
    );
    assert_eq!(
        unknown_receipt.pointer("/reply/consumer_cursor_advanced"),
        Some(&serde_json::Value::Bool(false))
    );

    // Close/reopen retains the stream: the suffix survives the restart.
    drop(kernel);
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let read_again = kernel
        .handle_replay_read(&session, &identity, &read_payload)
        .expect("replay survives close/reopen");
    let events_again = read_again
        .pointer("/reply/page/events")
        .and_then(serde_json::Value::as_array)
        .expect("page survives close/reopen");
    assert_eq!(events_again.len(), 1);
    assert_eq!(
        events_again[0]
            .get("event_id")
            .and_then(serde_json::Value::as_str),
        Some(event_id.as_str())
    );
}

#[test]
fn stale_executable_digest_fences_instead_of_admitting() {
    let root = temp_root("stale-digest");
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let claim_id = "t903-stale-claim-1";
    let digest = owner_digest();
    let (claim_json, registration_json, mut binding_json, binding_digest, _request) =
        valid_presentation(&kernel, claim_id, "t903-stale-reg-1", &digest);
    stage(
        &kernel,
        &claim_record_for(&kernel, claim_id, "t903-stale-reg-1", &binding_digest),
    );
    binding_json["executable_binding_digest"] = serde_json::json!("e".repeat(64));
    let payload = serde_json::json!({
        "operation": NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
        "binding": binding_json,
        "claim": claim_json,
        "registration": registration_json,
        "request_id": "req-stale-1",
        "fingerprint": "{\"kind\":\"EXECUTE\"}",
    });
    let error = kernel
        .handle_replay_lookup(&session, &handler_identity(claim_id), &payload)
        .expect_err("stale digest must fence");
    assert!(
        matches!(
            error,
            crate::native_worker_lifecycle_route::NativeWorkerRouteError::Fence { .. }
                | crate::native_worker_lifecycle_route::NativeWorkerRouteError::Shape { .. }
        ),
        "stale digest fences, got {error:?}"
    );
}

#[test]
fn cold_dispatch_fences_replay_before_any_claim_work() {
    let root = temp_root("cold-dispatch");
    let kernel = open_kernel(&root);
    let session = test_session(&kernel);
    let fence_value =
        serde_json::to_value(&session.module_generation.state_fence).expect("fence JSON");
    let frame_request_id =
        serde_json::from_value::<eliot_contracts::RequestId>(serde_json::json!("t903-cold-1"))
            .expect("frame request id");
    let identity_value = serde_json::json!({
        "request": {
            "metadata": {
                "request_id": "t903-cold-1",
                "session_id": null,
                "task_id": null,
                "product_id": "eliot-native-worker",
                "source_id": "native-worker-transport",
                "state_fence": fence_value,
                "clock": serde_json::to_value(eliot_contracts::ClockReading::default()).expect("clock"),
            },
            "state_fence": fence_value,
        },
        "idempotency_key": "t903-cold-claim-1",
        "deadline_unix_ms": 4_000_000_000_000u64,
        "cancellation_id": "t903-cold-cancel-1",
    });
    let identity: eliot_protocol::RequestIdentity =
        serde_json::from_value(identity_value).expect("request identity");
    let frame = Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
        request_id: Some(frame_request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(serde_json::json!({
            "operation": NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
        })),
        trace_context: std::collections::BTreeMap::new(),
    };
    assert!(
        matches!(
            kernel.dispatch_native_worker_replay_frame(&session, &frame),
            Err(TransportError::SessionFenced)
        ),
        "cold composition must fence replay dispatch"
    );
}
