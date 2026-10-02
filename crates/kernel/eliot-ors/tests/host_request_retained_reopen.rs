//! Durable original host-request readback proof for issue #1838 A1.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_ors::{
    CONTRACT_VERSION, HostRequestEffectEvidence, HostRequestKind, HostRequestRecord,
    HostRequestState, OpaqueLabel, OperationIdentity, RedbRecoveryStore,
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

fn admitted_input_bytes(
    state_fence: &StateFence,
    payload: &Value,
    work_scope_id: Option<&str>,
) -> Vec<u8> {
    canonical_json_bytes(&json!({
        "wire_id": "eliot.protocol.host-request",
        "wire_version": 1,
        "kind": "INVOCATION",
        "connection_id": "conn-1838-retained-reopen",
        "identity": {
            "request_id": "req-1838-retained-reopen",
            "idempotency_key": "req-1838-retained-reopen:invoke",
            "cancellation_id": "req-1838-retained-reopen:invoke:cancel",
            "parent_operation_id": null,
            "deadline_unix_ms": 9_999_999,
            "capability": "eliot.query",
            "session_id": "session-1838-retained-reopen",
            "task_id": "task-1838-retained-reopen",
            "work_scope_id": work_scope_id,
            "payload_schema_id": "eliot.query.v1",
            "payload_sha256": digest(payload),
        },
        "state_fence": serde_json::to_value(state_fence).expect("fence serializes"),
        "descriptor_sha256": "a".repeat(64),
        "peer_admission_receipt_sha256": "b".repeat(64),
        "activation_binding": null,
        "envelope_sha256": "",
    }))
    .expect("unsigned envelope canonicalizes")
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
        admitted_input_bytes: None,
        payload_digest: digest(payload),
        payload_schema_id: Some(label("eliot.query.v1")),
        payload_body: None,
        connection_ref: label("conn-1838-retained-reopen"),
        session_ref: Some(label("session-1838-retained-reopen")),
        task_ref: Some(label("task-1838-retained-reopen")),
        scope_ref: Some(label("scope-1838-retained-reopen")),
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

fn local_read_attempt(
    operation_id: &OperationIdentity,
    state_fence: &StateFence,
    scope_id: &str,
) -> Value {
    json!({
        "wire_id": "eliot.protocol.local-read-attempt",
        "wire_version": 1,
        "operation_id": operation_id.as_str(),
        "attempt_id": "local-read-attempt-1838",
        "fencing_generation": 2,
        "session_id": "session-1838-retained-reopen",
        "authority_epoch": serde_json::to_value(state_fence.authority_epoch)
            .expect("epoch serializes"),
        "scope_id": scope_id,
        "facet_method": "eliot.query",
        "expires_at_unix_ms": 9_999_999,
        "use_budget": 1,
    })
}

fn actual_route_receipt(
    operation_id: &OperationIdentity,
    request_digest: &str,
    result_digest: &str,
    state_fence: &StateFence,
) -> (String, Value) {
    let mut receipt = json!({
        "kind": "local_read_actual_route",
        "operation_id": operation_id.as_str(),
        "request_digest": request_digest,
        "result_digest": result_digest,
        "invoked_operation": "local_read",
        "named_operation": {"operation": "GetEvidencePack"},
        "state_fence": serde_json::to_value(state_fence).expect("fence serializes"),
        "route_facts": {"selected_endpoint": "authenticated-gateway-1838"},
    });
    let receipt_digest = digest(&receipt);
    receipt["receipt_digest"] = Value::String(receipt_digest.clone());
    (receipt_digest, receipt)
}

fn activation_resolution_result(state_fence: &StateFence) -> Value {
    let mut result = json!({
        "wire_id": "eliot.protocol.agent-activation-resolution-result",
        "wire_version": 3,
        "ticket_id": "activation-ticket-1838",
        "ticket_sha256": "c".repeat(64),
        "ticket_state_fence": serde_json::to_value(state_fence).expect("fence serializes"),
        "cancellation_id": "req-1838-retained-reopen:invoke:cancel",
        "resolved_at_unix_ms": 10,
        "disposition": {
            "kind": "RESOLVED",
            "binding": {
                "principal_id": "principal-1838",
                "session_id": "session-1838-retained-reopen",
                "task_id": "task-1838-retained-reopen",
                "work_unit_id": "unit-1838",
                "work_scope_id": "scope-1838-retained-reopen",
                "task_revision": "3",
                "plan_id": "plan-1838",
                "plan_revision": "4",
            },
        },
        "dependency_observation": null,
        "owner_evidence": null,
        "cold_start_question": null,
        "result_sha256": "",
    });
    let result_digest = digest(&result);
    result["result_sha256"] = Value::String(result_digest);
    result
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
    let original_fence = fence(7);
    let payload = json!({"tool": "GetEvidencePack", "subject": "evidence-1838"});
    let input_bytes = admitted_input_bytes(
        &original_fence,
        &payload,
        Some("scope-1838-retained-reopen"),
    );
    let request_digest = sha256_hex(&input_bytes);
    let operation_id = OperationIdentity::new(format!("hostreq:{request_digest}"))
        .expect("valid operation id");
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
    let result_digest = digest(&result);
    let (actual_route_digest, route_receipt) = actual_route_receipt(
        &operation_id,
        &request_digest,
        &result_digest,
        &original_fence,
    );
    let effect_evidence = HostRequestEffectEvidence {
        operation_id: label(operation_id.as_str()),
        input_handle: Some(request_digest.clone()),
        output_handle: Some(result_digest.clone()),
        side_effects: Some("none".to_owned()),
        actual_route: Some(actual_route_digest),
        actual_route_receipt: Some(route_receipt.clone()),
        local_read_attempt: Some(local_read_attempt(
            &operation_id,
            &original_fence,
            "scope-1838-retained-reopen",
        )),
        activation_resolution_result: Some(activation_resolution_result(&original_fence)),
        invoked_operation: Some("local_read".to_owned()),
        adapter_identity: Some("adapter-1838".to_owned()),
        executor_identity: Some("executor-1838".to_owned()),
    };
    let mut original = requested_record(
        operation_id.clone(),
        &request_digest,
        original_fence.clone(),
        &payload,
    );
    original.admitted_input_bytes = Some(input_bytes.clone());

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
                &result_digest,
                &result,
                Some(&effect_evidence),
                None,
            )
            .expect("exact result is retained");
    }

    let reopened = RedbRecoveryStore::open(&path).expect("owner store reopens");
    let retained = reopened
        .load_host_request(&operation_id, &request_digest)
        .expect("exact owner lookup succeeds")
        .expect("original row remains present");
    assert_eq!(retained.operation_id, operation_id);
    assert_eq!(retained.request_digest, request_digest);
    assert_eq!(retained.admitted_input_bytes.as_deref(), Some(input_bytes.as_slice()));
    assert_eq!(retained.admitted_state_fence.as_ref(), Some(&original_fence));
    assert_eq!(retained.fence_digest, digest(&serde_json::to_value(&original_fence).unwrap()));
    assert_eq!(retained.payload_body.as_ref(), Some(&payload));
    assert_eq!(retained.payload_digest, digest(&payload));
    assert_eq!(retained.result_response.as_ref(), Some(&result));
    assert_eq!(retained.result_digest.as_deref(), Some(digest(&result).as_str()));
    assert_eq!(retained.state, HostRequestState::ResultReceived);
    let retained_evidence = retained
        .result_evidence
        .as_ref()
        .expect("original result evidence remains retained");
    assert_eq!(retained_evidence.actual_route_receipt.as_ref(), Some(&route_receipt));
    assert_eq!(
        retained_evidence.local_read_attempt.as_ref(),
        effect_evidence.local_read_attempt.as_ref()
    );
    assert_eq!(
        retained_evidence.activation_resolution_result.as_ref(),
        effect_evidence.activation_resolution_result.as_ref()
    );

    let changed_request_digest = "e".repeat(64);
    assert!(reopened
        .load_host_request(&operation_id, &changed_request_digest)
        .expect("altered digest lookup succeeds")
        .is_none());

    let mut changed_snapshot = requested_record(
        operation_id.clone(),
        &request_digest,
        fence(8),
        &payload,
    );
    changed_snapshot.admitted_input_bytes = Some(input_bytes.clone());
    assert!(matches!(
        reopened.stage_host_request(&changed_snapshot),
        Err(eliot_ors::OrsError::HostRequestIdentityConflict { .. })
    ));

    let mut omitted_retained_fence = original.clone();
    omitted_retained_fence.admitted_state_fence = None;
    assert!(matches!(
        reopened.stage_host_request(&omitted_retained_fence),
        Err(eliot_ors::OrsError::HostRequestIdentityConflict { .. })
    ));

    let mut omitted_retained_input = original.clone();
    omitted_retained_input.admitted_input_bytes = None;
    assert!(matches!(
        reopened.stage_host_request(&omitted_retained_input),
        Err(eliot_ors::OrsError::HostRequestIdentityConflict { .. })
    ));

    let mut substituted_fence = requested_record(
        operation_id.clone(),
        &request_digest,
        fence(8),
        &payload,
    );
    substituted_fence.admitted_input_bytes = Some(input_bytes.clone());
    assert!(matches!(
        reopened.stage_host_request(&substituted_fence),
        Err(eliot_ors::OrsError::HostRequestIdentityConflict { .. })
    ));

    let mut mismatched_fence_digest = original.clone();
    mismatched_fence_digest.admitted_state_fence = Some(fence(8));
    assert!(matches!(
        mismatched_fence_digest.validate(),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_admitted_state_fence",
            ..
        })
    ));

    let mut substituted_input = original.clone();
    let mut substituted_input_bytes = input_bytes.clone();
    substituted_input_bytes[0] = b'[';
    substituted_input.admitted_input_bytes = Some(substituted_input_bytes);
    assert!(matches!(
        reopened.stage_host_request(&substituted_input),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_admitted_input_bytes",
            ..
        })
    ));

    let substituted_payload = json!({"tool": "GetEvidencePack", "subject": "substituted"});
    let mut substituted_payload_row = retained.clone();
    substituted_payload_row.payload_body = Some(substituted_payload.clone());
    assert!(matches!(
        substituted_payload_row.validate(),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_payload_body",
            ..
        })
    ));
    assert!(matches!(
        reopened.bind_host_request_payload(&operation_id, &request_digest, &substituted_payload),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_payload_body",
            ..
        })
    ));

    let substituted_result = json!({"result": "substituted"});
    let mut substituted_result_row = retained.clone();
    substituted_result_row.result_response = Some(substituted_result.clone());
    assert!(matches!(
        substituted_result_row.validate(),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_result_response",
            ..
        })
    ));
    assert!(matches!(
        reopened.persist_host_request_result(
            &operation_id,
            &request_digest,
            &digest(&result),
            &substituted_result,
            None,
            None,
        ),
        Err(eliot_ors::OrsError::HostRequestIdentityConflict { .. })
    ));

    let mut substituted_receipt_row = retained.clone();
    let mut substituted_evidence = retained_evidence.clone();
    let mut substituted_receipt = substituted_evidence
        .actual_route_receipt
        .clone()
        .expect("original actual-route receipt remains retained");
    substituted_receipt["route_facts"] = json!({"selected_endpoint": "substituted"});
    substituted_evidence.actual_route_receipt = Some(substituted_receipt);
    substituted_receipt_row.result_evidence = Some(substituted_evidence);
    assert!(matches!(
        substituted_receipt_row.validate(),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_effect_evidence_actual_route_receipt",
            ..
        })
    ));

    let mut substituted_attempt_row = retained.clone();
    let mut substituted_attempt_evidence = retained_evidence.clone();
    let mut substituted_attempt = substituted_attempt_evidence
        .local_read_attempt
        .clone()
        .expect("original local-read attempt remains retained");
    substituted_attempt["session_id"] = Value::String("other-session".to_owned());
    substituted_attempt_evidence.local_read_attempt = Some(substituted_attempt);
    substituted_attempt_row.result_evidence = Some(substituted_attempt_evidence);
    assert!(matches!(
        substituted_attempt_row.validate(),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_effect_evidence_local_read_attempt",
            ..
        })
    ));

    let mut substituted_activation_row = retained.clone();
    let mut substituted_activation_evidence = retained_evidence.clone();
    let mut substituted_activation_result = substituted_activation_evidence
        .activation_resolution_result
        .clone()
        .expect("original activation result remains retained");
    substituted_activation_result["disposition"]["binding"]["principal_id"] =
        Value::String("substituted-principal".to_owned());
    substituted_activation_evidence.activation_resolution_result = Some(substituted_activation_result);
    substituted_activation_row.result_evidence = Some(substituted_activation_evidence);
    assert!(matches!(
        substituted_activation_row.validate(),
        Err(eliot_ors::OrsError::InvalidField {
            field: "host_request_effect_evidence_activation_resolution_result",
            ..
        })
    ));

    let unchanged = reopened
        .load_host_request(&operation_id, &request_digest)
        .expect("original owner row remains readable")
        .expect("original owner row remains retained");
    assert_eq!(unchanged.admitted_state_fence.as_ref(), Some(&original_fence));
    assert_eq!(unchanged.admitted_input_bytes.as_deref(), Some(input_bytes.as_slice()));
    assert_eq!(unchanged.payload_body.as_ref(), Some(&payload));
    assert_eq!(unchanged.result_response.as_ref(), Some(&result));
    assert_eq!(
        unchanged
            .result_evidence
            .as_ref()
            .and_then(|evidence| evidence.actual_route_receipt.as_ref()),
        Some(&route_receipt)
    );

    drop(reopened);
    let _ = std::fs::remove_file(path);
}

#[test]
fn historical_missing_fence_stays_missing_after_exact_retry_and_reopen() {
    let path = temp_path();
    let original_fence = fence(11);
    let payload = json!({"tool": "GetEvidencePack", "subject": "historical-1838"});
    let input_bytes = admitted_input_bytes(
        &original_fence,
        &payload,
        Some("scope-1838-retained-reopen"),
    );
    let request_digest = sha256_hex(&input_bytes);
    let operation_id = OperationIdentity::new(format!("hostreq:{request_digest}"))
        .expect("valid operation id");
    let result = json!({"result": "historical-1838"});
    let mut historical = requested_record(
        operation_id.clone(),
        &request_digest,
        original_fence.clone(),
        &payload,
    );
    historical.admitted_state_fence = None;

    {
        let store = RedbRecoveryStore::open(&path).expect("owner store opens");
        store.stage_host_request(&historical).expect("historical row stages");
        store
            .advance_host_request(
                &operation_id,
                &request_digest,
                HostRequestState::Admitted,
                None,
            )
            .expect("historical operation admits");
        store
            .bind_host_request_payload(&operation_id, &request_digest, &payload)
            .expect("historical admitted input is retained");
        store
            .persist_host_request_result(
                &operation_id,
                &request_digest,
                &digest(&result),
                &result,
                None,
                None,
            )
            .expect("historical result is retained");
    }

    {
        let reopened = RedbRecoveryStore::open(&path).expect("owner store reopens");
        let retained = reopened
            .load_host_request(&operation_id, &request_digest)
            .expect("historical owner lookup succeeds")
            .expect("historical row remains present");
        assert_eq!(retained.operation_id, operation_id);
        assert_eq!(retained.request_digest, request_digest);
        assert_eq!(retained.admitted_state_fence, None);

        let mut retry_with_original_fence = requested_record(
            operation_id.clone(),
            &request_digest,
            original_fence,
            &payload,
        );
        retry_with_original_fence.admitted_input_bytes = Some(input_bytes.clone());
        let winner = reopened
            .stage_host_request(&retry_with_original_fence)
            .expect("matching historical retry resolves to the durable owner");
        assert_eq!(winner.admitted_state_fence, None);
        assert_eq!(winner.admitted_input_bytes, None);
    }

    let final_reopen = RedbRecoveryStore::open(&path).expect("owner store reopens again");
    let retained = final_reopen
        .load_host_request(&operation_id, &request_digest)
        .expect("historical owner lookup succeeds after retry")
        .expect("historical row is still retained");
    assert_eq!(retained.admitted_state_fence, None);
    assert_eq!(retained.admitted_input_bytes, None);
    assert_eq!(retained.payload_body.as_ref(), Some(&payload));
    assert_eq!(retained.result_response.as_ref(), Some(&result));

    drop(final_reopen);
    let _ = std::fs::remove_file(path);
}
