//! Durable original host-request readback proof for issue #1838 A1.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_ors::{
    CONTRACT_VERSION, HostRequestKind, HostRequestRecord, HostRequestState, OpaqueLabel,
    OperationIdentity, RedbRecoveryStore,
};
use serde_json::{Value, json};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence(epoch: u64) -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("valid lineage");
    let authority_epoch = EpochId::new(
        lineage,
        NonZeroU64::new(epoch).expect("epoch is nonzero"),
    )
    .expect("valid authority epoch");
    StateFence::new(
        authority_epoch,
        ResourceGeneration::new(3).expect("valid generation"),
    )
}

fn digest(value: &Value) -> String {
    sha256_hex(&canonical_json_bytes(value).expect("JSON value canonicalizes"))
}

fn label(value: &str) -> OpaqueLabel {
    OpaqueLabel::new(value).expect("valid label")
}

fn requested_record(
    operation_id: OperationIdentity,
    request_digest: &str,
    state_fence: StateFence,
    payload: &Value,
) -> HostRequestRecord {
    let fence_digest = digest(&serde_json::to_value(&state_fence).expect("fence serializes"));
    HostRequestRecord {
        contract_version: CONTRACT_VERSION,
        send_claim_protocol_version: 0,
        transport_channel_binding_sha256: None,
        operation_id,
        kind: HostRequestKind::Invocation,
        request_id: label("req-1838-retained-reopen"),
        correlation_projection: None,
        idempotency_key: label("req-1838-retained-reopen:invoke"),
        cancellation_id: label("req-1838-retained-reopen:invoke:cancel"),
        parent_operation_id: None,
        request_digest: request_digest.to_owned(),
        payload_digest: digest(payload),
        payload_schema_id: Some(label("eliot.query.v1")),
        payload_body: None,
        connection_ref: label("conn-1838-retained-reopen"),
        session_ref: Some(label("session-1838-retained-reopen")),
        task_ref: Some(label("task-1838-retained-reopen")),
        scope_ref: None,
        capability_ref: label("eliot.query"),
        fence_digest,
        admitted_state_fence: Some(state_fence.clone()),
        authority_epoch: state_fence.authority_epoch,
        generation: state_fence.resource_generation.value(),
        deadline_unix_ms: 9_999_999,
        state: HostRequestState::Requested,
        attempt: None,
        attempt_history: Vec::new(),
        cancellation_target: None,
        result_digest: None,
        result_response: None,
        result_evidence: None,
        result_lineage: None,
        commit_order: 0,
    }
}

fn temp_path() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "eliot-1838-host-request-retained-{}-{nonce}.redb",
        std::process::id()
    ))
}

#[test]
fn original_fence_and_retained_bytes_survive_reopen_and_changed_identity_is_refused() {
    let path = temp_path();
    let request_digest = "d".repeat(64);
    let operation_id = OperationIdentity::new(format!("hostreq:{request_digest}"))
        .expect("valid operation id");
    let original_fence = fence(7);
    let payload = json!({"tool": "GetEvidencePack", "subject": "evidence-1838"});
    let result = json!({
        "request_id": "req-1838-retained-reopen",
        "idempotency_key": "req-1838-retained-reopen:invoke",
        "canonical_tool_name": "eliot.query",
        "content": {
            "operation": "GetEvidencePack",
            "evidence_pack": {"subject": "evidence-1838"},
            "revision_heads": [{"key": "scope:scope-1838", "revision": 3}],
        },
    });
    let original = requested_record(
        operation_id.clone(),
        &request_digest,
        original_fence.clone(),
        &payload,
    );

    {
        let store = RedbRecoveryStore::open(&path).expect("owner store opens");
        store.stage_host_request(&original).expect("original stages");
        store
            .advance_host_request(
                &operation_id,
                &request_digest,
                HostRequestState::Admitted,
                None,
            )
            .expect("operation admits");
        store
            .bind_host_request_payload(&operation_id, &request_digest, &payload)
            .expect("exact admitted input is retained");
        store
            .persist_host_request_result(
                &operation_id,
                &request_digest,
                &digest(&result),
                &result,
                None,
                None,
            )
            .expect("exact result is retained");
    }

    let reopened = RedbRecoveryStore::open(&path).expect("owner store reopens");
    let retained = reopened
        .load_host_request(&operation_id, &request_digest)
        .expect("exact owner lookup succeeds")
        .expect("original row remains present");
    assert_eq!(retained.admitted_state_fence.as_ref(), Some(&original_fence));
    assert_eq!(retained.fence_digest, digest(&serde_json::to_value(&original_fence).unwrap()));
    assert_eq!(retained.payload_body.as_ref(), Some(&payload));
    assert_eq!(retained.payload_digest, digest(&payload));
    assert_eq!(retained.result_response.as_ref(), Some(&result));
    assert_eq!(retained.result_digest.as_deref(), Some(digest(&result).as_str()));

    let changed_request_digest = "e".repeat(64);
    assert!(reopened
        .load_host_request(&operation_id, &changed_request_digest)
        .expect("altered digest lookup succeeds")
        .is_none());

    let changed_snapshot = requested_record(
        operation_id.clone(),
        &request_digest,
        fence(8),
        &payload,
    );
    assert!(matches!(
        reopened.stage_host_request(&changed_snapshot),
        Err(eliot_ors::OrsError::HostRequestIdentityConflict { .. })
    ));

    drop(reopened);
    let _ = std::fs::remove_file(path);
}
