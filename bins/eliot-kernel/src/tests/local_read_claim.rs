//! Kernel local-read claim tests — acceptance-only scope.
//!
//! Covers the outbound-only eliotd poller pair (`local_read_claim` /
//! `local_read_result`, Implements #18): an admitted `eliot.query` pair is
//! queued by the host-request side, claimed by a fake daemon poller, bound
//! via the ORS result path, and read back exactly. Empty claims poll null
//! (not error), exactly like the activation ticket `None` case.

#![cfg(windows)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]

use super::*;
use eliot_ors::{HostRequestState, OperationIdentity};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HOST_REQUEST_WIRE_ID, HostRequestEnvelope,
    HostRequestIdentity, HostRequestKind, HostRequestResultBody,
};

fn tool_digest(tool: &serde_json::Value) -> String {
    let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
    eliot_contracts::sha256_hex(&bytes)
}

fn query_tool() -> serde_json::Value {
    serde_json::json!({"name":"eliot.query","arguments":{
        "intent":{
            "mode":"verification",
            "time_scope":"session-window",
            "branch_environment_scope":"branch",
            "freshness_policy":"exact-fence",
            "required_assurance":"evidence-provenance"
        },
        "query":"subject:evidence-alpha",
        "exact_resource_uri": null
    }})
}

fn query_envelope(
    fence: &StateFence,
    deadline_unix_ms: u64,
    request_id: &str,
    tool_digest: &str,
) -> HostRequestEnvelope {
    HostRequestEnvelope {
        wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
        wire_version: HostRequestEnvelope::CONTRACT_VERSION,
        kind: HostRequestKind::Invocation,
        connection_id: "conn-test-1".to_owned(),
        identity: HostRequestIdentity {
            request_id: eliot_contracts::RequestId::new(request_id).expect("valid request id"),
            idempotency_key: format!("{request_id}:invoke"),
            cancellation_id: format!("{request_id}:invoke:cancel"),
            parent_operation_id: None,
            deadline_unix_ms,
            capability: "eliot.query".to_owned(),
            session_id: Some("kernel-session-1".to_owned()),
            task_id: None,
            work_scope_id: None,
            payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
            payload_sha256: tool_digest.to_owned(),
        },
        state_fence: fence.clone(),
        descriptor_sha256: "d".repeat(64),
        peer_admission_receipt_sha256: "e".repeat(64),
        activation_binding: None,
        envelope_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("envelope must digest")
}

fn daemon_session_for(policy: &eliot_ipc::ServerHandshakePolicy) -> Session {
    Session {
        connection_id: "authenticated-eliotd-connection".to_owned(),
        protocol_version: policy.protocol_range.maximum,
        peer: PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
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

fn result_body_for(envelope: &HostRequestEnvelope) -> HostRequestResultBody {
    let response = serde_json::json!({
        "operation": "GetEvidencePack",
        "subject": "evidence-alpha",
        "evidence_pack": { "subject": "evidence-alpha" },
        "revision_heads": [{ "key": "scope:kernel-session-1", "revision": 3 }],
    });
    let digest = {
        let bytes =
            eliot_contracts::canonical_json_bytes(&response).expect("body must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    };
    HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: eliot_protocol::host_request_operation_id(envelope),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: digest,
        response,
    }
}

fn stage_admitted(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
) -> eliot_ors::HostRequestRecord {
    let requested = host_request_route::requested_host_request_record(envelope)
        .expect("record must build");
    kernel
        .generation_gateway
        .ors
        .stage_host_request(&requested)
        .expect("stage must succeed");
    let operation_id = OperationIdentity::new(eliot_protocol::host_request_operation_id(envelope))
        .expect("operation identity");
    kernel
        .generation_gateway
        .ors
        .advance_host_request(
            &operation_id,
            &envelope.envelope_sha256,
            HostRequestState::Admitted,
            None,
        )
        .expect("advance must succeed")
        .expect("admitted record must read back")
}

#[allow(
    clippy::too_many_lines,
    reason = "the claim/submit roundtrip stages, claims, persists, replays, conflicts, and expires one admitted pair in a single focused flow"
)]
#[test]
fn local_read_claim_submit_roundtrip_with_exact_replay_conflict_and_expiry() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-local-read-claim-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let fence = policy.module_generation.state_fence.clone();
    let daemon_session = daemon_session_for(&policy);

    // Empty queue polls null, not error — exactly like the ticket None case.
    assert!(
        kernel
            .claim_local_read_pair()
            .expect("empty claim must not fail")
            .is_none(),
        "empty local-read queue must poll null"
    );

    let tool = query_tool();
    let envelope = query_envelope(&fence, unix_ms().saturating_add(60_000), "host-request-1", &tool_digest(&tool));
    assert!(
        host_request_route::check_local_read_admission(&envelope, &tool)
            .expect("admitted query must validate")
            .is_some(),
        "the admitted query carries selectors and is queue-eligible"
    );
    stage_admitted(&kernel, &envelope);

    // Exact replay never duplicates the queued pair.
    kernel
        .enqueue_local_read_pair(&envelope, &tool)
        .expect("enqueue must succeed");
    kernel
        .enqueue_local_read_pair(&envelope, &tool)
        .expect("replay enqueue must stay idempotent");

    let (claimed_envelope, claimed_tool) = kernel
        .claim_local_read_pair()
        .expect("claim must not fail")
        .expect("queued pair must claim");
    assert_eq!(
        claimed_envelope.envelope_sha256, envelope.envelope_sha256,
        "the claim returns the exact admitted envelope"
    );
    assert_eq!(claimed_tool, tool, "the claim returns the exact tool bytes");
    assert!(
        kernel
            .claim_local_read_pair()
            .expect("lease check must not fail")
            .is_none(),
        "a leased pair is not served twice before submit"
    );

    let body = result_body_for(&envelope);
    body.validate().expect("result body must validate");
    let persisted = kernel
        .submit_local_read_result(&daemon_session, &body)
        .expect("submit must persist");
    assert_eq!(persisted.state, HostRequestState::ResultReceived);
    assert_eq!(persisted.result_digest.as_deref(), Some(body.result_digest.as_str()));
    assert_eq!(persisted.result_response.as_ref(), Some(&body.response));

    // Read back the exact body through the durable record and the replay leg.
    let operation_id = OperationIdentity::new(eliot_protocol::host_request_operation_id(&envelope))
        .expect("operation identity");
    let stored = kernel
        .generation_gateway
        .ors
        .load_host_request(&operation_id, &envelope.envelope_sha256)
        .expect("load must succeed")
        .expect("resulted record must exist");
    assert_eq!(stored.result_response.as_ref(), Some(&body.response));
    let receipt =
        eliot_protocol::HostRequestAdmissionReceipt::issue(&envelope).expect("receipt must issue");
    let replayed = host_request_route::local_read_replay_response(&receipt, &stored, &envelope)
        .expect("replay must not fail")
        .expect("resulted row must replay");
    assert_eq!(
        replayed["value"]["record"]["result_response"], body.response,
        "the replay carries the exact stored body"
    );

    // Exact replay stays idempotent, even for the same bytes twice.
    let replayed_submit = kernel
        .submit_local_read_result(&daemon_session, &body)
        .expect("exact replay must stay idempotent");
    assert_eq!(
        replayed_submit.result_digest, persisted.result_digest,
        "replay preserves the exact digest"
    );

    // A changed body under the same identity conflicts and never overwrites.
    let mut conflicting_response = body.response.clone();
    conflicting_response["revision_heads"] =
        serde_json::json!([{ "key": "scope:kernel-session-1", "revision": 4 }]);
    let conflicting_digest = {
        let bytes = eliot_contracts::canonical_json_bytes(&conflicting_response)
            .expect("conflict must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    };
    let conflicting = HostRequestResultBody {
        result_digest: conflicting_digest,
        response: conflicting_response,
        ..body.clone()
    };
    assert_eq!(
        kernel.submit_local_read_result(&daemon_session, &conflicting),
        Err(TransportError::IdentityConflict),
        "a changed same-identity body must conflict"
    );

    // An elapsed deadline skips claim and times out on submit.
    let expired_tool = query_tool();
    let expired = query_envelope(&fence, 1, "host-request-expired", &tool_digest(&expired_tool));
    stage_admitted(&kernel, &expired);
    kernel
        .enqueue_local_read_pair(&expired, &expired_tool)
        .expect("expired enqueue must succeed");
    assert!(
        kernel
            .claim_local_read_pair()
            .expect("expired claim must not fail")
            .is_none(),
        "expired pairs never claim"
    );
    let expired_body = result_body_for(&expired);
    assert_eq!(
        kernel.submit_local_read_result(&daemon_session, &expired_body),
        Err(TransportError::Timeout),
        "an elapsed deadline must time out"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn local_read_claim_daemon_poll_returns_null_when_empty() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-local-read-poll-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let session = daemon_session_for(&policy);

    let frame = kernel
        .execute_daemon_request(
            &session,
            RequestId::new("local-read-claim-poll-1").expect("request id"),
            "local_read_claim",
            serde_json::json!({ "operation": "local_read_claim" }),
        )
        .await
        .expect("empty claim must poll, not fence");
    let ProtocolPayload::Json(value) = &frame.payload else {
        panic!("daemon reply must carry a JSON payload");
    };
    assert_eq!(value.get("status"), Some(&serde_json::json!("known")));
    assert_eq!(
        value.pointer("/value/pair"),
        Some(&serde_json::Value::Null),
        "empty claim must return a null pair"
    );
    assert_eq!(value.get("recovery"), Some(&serde_json::Value::Null));

    // A widened claim payload fences; a result without a body fences.
    assert!(
        kernel
            .execute_daemon_request(
                &session,
                RequestId::new("local-read-claim-poll-2").expect("request id"),
                "local_read_claim",
                serde_json::json!({ "operation": "local_read_claim", "extra": null }),
            )
            .await
            .is_err(),
        "a widened claim payload must fence"
    );
    assert!(
        kernel
            .execute_daemon_request(
                &session,
                RequestId::new("local-read-result-poll-1").expect("request id"),
                "local_read_result",
                serde_json::json!({ "operation": "local_read_result" }),
            )
            .await
            .is_err(),
        "a result without a body must fence"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}
