//! Kernel local-read governed-attempt tests — acceptance-only scope.
//!
//! Covers the outbound-only eliotd poller pair (`local_read_claim` /
//! `local_read_result`, Implements #18) under governed attempt ownership: an
//! admitted `eliot.query` pair is queued by the host-request side, claimed by
//! a fake daemon poller for a fenced attempt capability, bound via the ORS
//! result path only for the current fencing generation, and read back
//! exactly. Empty claims poll null (not error), exactly like the activation
//! ticket `None` case. Replaced or revoked attempts quarantine as stale
//! observations and never reach the waiter.

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
    HostRequestIdentity, HostRequestKind, HostRequestResultBody, LocalReadAttempt,
};
use eliot_store_api::EVIDENCE_PACK_MAX_RECORDS;
use host_request_route::{
    LocalReadEnqueueDisposition, LocalReadSubmitDisposition, StaleLocalReadReason,
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
        "exact_resource_uri": null,
        "max_records":"32"
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
            work_scope_id: Some("work-scope-1".to_owned()),
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
    daemon_session_for_with(
        policy,
        "authenticated-eliotd-connection",
        policy.launch_nonce.clone(),
        1,
    )
}

fn daemon_session_for_with(
    policy: &eliot_ipc::ServerHandshakePolicy,
    connection_id: &str,
    launch_nonce: String,
    session_epoch: u64,
) -> Session {
    Session {
        connection_id: connection_id.to_owned(),
        protocol_version: policy.protocol_range.maximum,
        peer: PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation: policy.module_generation.clone(),
        launch_nonce,
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch,
        state: eliot_ipc::SessionState::Open,
    }
}

fn evidence_response_for(envelope: &HostRequestEnvelope, revision: u32) -> serde_json::Value {
    let scope_id = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .expect("local-read envelope must carry a trusted WorkScope");
    let canonical_request_sha256 = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&(
            envelope.envelope_sha256.clone(),
            envelope.identity.request_id.as_str().to_owned(),
            envelope.identity.idempotency_key.clone(),
        ))
        .expect("request tuple must canonicalize"),
    );
    let content = serde_json::json!({
        "operation": "GetEvidencePack",
        "subject": "evidence-alpha",
        "scope_id": scope_id,
        "evidence_pack": {
            "version": 1,
            "subject": "evidence-alpha",
            "scope_id": scope_id,
            "records": [{
                "capture_index": 0,
                "operation": "CaptureObservation",
                "parameters": {"subject": "evidence-alpha"}
            }],
            "provenance": {
                "state_fence": envelope.state_fence,
                "matched_total": 1,
                "returned": 1,
                "max_records": EVIDENCE_PACK_MAX_RECORDS,
                "truncated": false
            }
        },
        "revision_heads": [{
            "key": format!("scope:{scope_id}"),
            "revision": revision,
            "state_fence": envelope.state_fence,
        }]
    });
    let recall_metadata = serde_json::json!({
        "disposition": "INCOMPLETE_COVERAGE",
        "admission_observations": {
            "corpus_empty": null,
            "candidates_considered": null,
            "visible_count": null,
            "scope_suppressed_count": null,
            "projection_state": null,
            "coverage_complete": null,
            "conflicted": null,
            "top_score": null
        },
        "receipt": {
            "scope_id": scope_id,
            "state_fence": envelope.state_fence,
            "source_revision": null,
            "projection_revision": null,
            "freshness": "UNAVAILABLE",
            "matched_total": 1,
            "returned": 1,
            "visible_count": null,
            "suppressed_count": null,
            "reason": "required server observation unavailable; candidate-only evidence has no authoritative admission or ranking trace"
        },
        "rank_trace": {
            "status": "UNAVAILABLE",
            "handle": null,
            "candidates_considered": null,
            "candidates_returned": null,
            "reason": "candidate-only evidence has no FusedRankTrace or equivalent"
        },
        "admitted_max_records": EVIDENCE_PACK_MAX_RECORDS
    });
    serde_json::json!({
        "request_id": envelope.identity.request_id.as_str(),
        "idempotency_key": envelope.identity.idempotency_key,
        "canonical_request_sha256": canonical_request_sha256,
        "kind": "PROJECTION",
        "canonical_tool_name": "eliot.query",
        "recall_disposition": "INCOMPLETE_COVERAGE",
        "recall_metadata": recall_metadata,
        "content": content,
        "artifacts": [],
        "proof_ceiling": "SCOPED_VERIFICATION",
        "resource": null,
        "job": null
    })
}

fn result_body_for(
    envelope: &HostRequestEnvelope,
    attempt: Option<LocalReadAttempt>,
) -> HostRequestResultBody {
    let response = evidence_response_for(envelope, 3);
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
        attempt,
    }
}

fn stage_admitted(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
) -> eliot_ors::HostRequestRecord {
    let requested =
        host_request_route::requested_host_request_record(envelope).expect("record must build");
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
            .claim_local_read_pair(&daemon_session)
            .expect("empty claim must not fail")
            .is_none(),
        "empty local-read queue must poll null"
    );

    let tool = query_tool();
    let envelope = query_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-1",
        &tool_digest(&tool),
    );
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

    let (claimed_envelope, claimed_tool, attempt) = kernel
        .claim_local_read_pair(&daemon_session)
        .expect("claim must not fail")
        .expect("queued pair must claim");
    assert_eq!(
        claimed_envelope.envelope_sha256, envelope.envelope_sha256,
        "the claim returns the exact admitted envelope"
    );
    assert_eq!(claimed_tool, tool, "the claim returns the exact tool bytes");
    assert_eq!(
        attempt.fencing_generation, 1,
        "the first claim mints fencing generation 1"
    );
    attempt
        .validate()
        .expect("the minted capability must validate");
    // A re-claim by the same owner session returns the identical current
    // capability: lost-answer retry without a new identity.
    let (_, _, reattempt) = kernel
        .claim_local_read_pair(&daemon_session)
        .expect("re-claim must not fail")
        .expect("the owned pair must re-claim");
    assert_eq!(
        reattempt.attempt_id, attempt.attempt_id,
        "same-owner re-claim returns the identical attempt"
    );
    assert_eq!(
        reattempt.fencing_generation, attempt.fencing_generation,
        "same-owner re-claim never bumps the generation"
    );

    // A changed body under the same identity, built for the conflict proof
    // after the first completion below.
    let mut conflicting = result_body_for(&envelope, Some(attempt.clone()));
    conflicting.response["content"]["revision_heads"][0]["revision"] = serde_json::json!(4);
    conflicting.result_digest = {
        let bytes = eliot_contracts::canonical_json_bytes(&conflicting.response)
            .expect("conflict must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    };

    let body = result_body_for(&envelope, Some(attempt.clone()));
    body.validate().expect("result body must validate");
    let persisted = match kernel
        .submit_local_read_result(&daemon_session, &body)
        .expect("submit must not fail")
    {
        LocalReadSubmitDisposition::Persisted(record) => record,
        LocalReadSubmitDisposition::StaleAttempt(observation) => {
            panic!("current attempt must persist, got stale: {observation:?}")
        }
    };
    assert_eq!(persisted.state, HostRequestState::ResultReceived);
    assert_eq!(
        persisted.result_digest.as_deref(),
        Some(body.result_digest.as_str())
    );
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
    let selectors = host_request_route::check_local_read_admission(&envelope, &tool)
        .expect("local-read admission must validate")
        .expect("the query must retain selectors");
    let replayed = host_request_route::local_read_replay_response(
        &receipt,
        &stored,
        &envelope,
        Some(&selectors),
    )
    .expect("replay must not fail")
    .expect("resulted row must replay");
    assert_eq!(
        replayed["value"]["record"]["result_response"], body.response,
        "the replay carries the exact stored body"
    );

    // Exact replay stays idempotent, even for the same bytes twice.
    let replayed_submit = match kernel
        .submit_local_read_result(&daemon_session, &body)
        .expect("exact replay must not fail")
    {
        LocalReadSubmitDisposition::Persisted(record) => record,
        LocalReadSubmitDisposition::StaleAttempt(observation) => {
            panic!("exact replay must stay idempotent, got stale: {observation:?}")
        }
    };
    assert_eq!(
        replayed_submit.result_digest, persisted.result_digest,
        "replay preserves the exact digest"
    );

    // A changed body after completion fails closed as an identity conflict.
    // The durable record is terminal with a stored result, so a different
    // body is neither a second completion nor a stale observation: the
    // refusal is typed and the stored answer stays authoritative.
    assert!(
        matches!(
            kernel.submit_local_read_result(&daemon_session, &conflicting),
            Err(TransportError::IdentityConflict)
        ),
        "a changed body after completion must fail closed as an identity conflict"
    );

    // A completed operation is no longer dispatchable. The enqueue gate
    // re-reads the durable record, refuses anything that is not `Admitted`,
    // retires the reference, and reports the refusal; the poller therefore
    // never sees a second read for a finished operation.
    assert_eq!(
        kernel
            .enqueue_local_read_pair(&envelope, &tool)
            .expect("enqueue must not fail"),
        LocalReadEnqueueDisposition::Retired,
        "a resulted record is refused, not re-queued"
    );
    assert!(
        kernel
            .claim_local_read_pair(&daemon_session)
            .expect("claim must not fail")
            .is_none(),
        "a retired completed pair is never re-claimed"
    );
    // Explicit retirement stays available and is a no-op once the gate has
    // already retired the pair.
    kernel.retire_local_read_pair(
        &eliot_protocol::host_request_operation_id(&envelope),
        &envelope.envelope_sha256,
    );

    // An elapsed deadline skips claim and times out on submit.
    let expired_tool = query_tool();
    let expired = query_envelope(
        &fence,
        1,
        "host-request-expired",
        &tool_digest(&expired_tool),
    );
    stage_admitted(&kernel, &expired);
    kernel
        .enqueue_local_read_pair(&expired, &expired_tool)
        .expect("expired enqueue must succeed");
    assert!(
        kernel
            .claim_local_read_pair(&daemon_session)
            .expect("expired claim must not fail")
            .is_none(),
        "expired pairs never claim"
    );
    let expired_body = result_body_for(&expired, None);
    assert!(
        matches!(
            kernel.submit_local_read_result(&daemon_session, &expired_body),
            Err(TransportError::Timeout)
        ),
        "an elapsed deadline must time out"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

fn waiter_record(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
) -> eliot_ors::HostRequestRecord {
    let operation_id = OperationIdentity::new(eliot_protocol::host_request_operation_id(envelope))
        .expect("operation identity");
    kernel
        .generation_gateway
        .ors
        .load_host_request(&operation_id, &envelope.envelope_sha256)
        .expect("load must succeed")
        .expect("waited record must exist")
}

fn body_with_revision(
    envelope: &HostRequestEnvelope,
    attempt: LocalReadAttempt,
    revision: u32,
) -> HostRequestResultBody {
    let mut body = result_body_for(envelope, Some(attempt));
    body.response["content"]["revision_heads"][0]["revision"] = serde_json::json!(revision);
    body.result_digest = {
        let bytes =
            eliot_contracts::canonical_json_bytes(&body.response).expect("body must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    };
    body.validate().expect("body must validate");
    body
}

fn governed_claim_replacement(
    kernel: &KernelComposition,
    fence: &StateFence,
    owner: &Session,
    rival: &Session,
) -> (HostRequestEnvelope, LocalReadAttempt, LocalReadAttempt) {
    let tool = query_tool();
    let envelope = query_envelope(
        fence,
        unix_ms().saturating_add(60_000),
        "host-request-governed-1",
        &tool_digest(&tool),
    );
    stage_admitted(kernel, &envelope);
    kernel
        .enqueue_local_read_pair(&envelope, &tool)
        .expect("enqueue must succeed");
    let (_, _, first) = kernel
        .claim_local_read_pair(owner)
        .expect("owner claim must not fail")
        .expect("pair must claim");
    assert_eq!(first.fencing_generation, 1);
    let (_, _, second) = kernel
        .claim_local_read_pair(rival)
        .expect("rival claim must not fail")
        .expect("pair must re-claim");
    assert_eq!(
        second.fencing_generation, 2,
        "reassignment bumps the fencing generation"
    );
    assert_ne!(
        second.attempt_id, first.attempt_id,
        "reassignment mints a fresh attempt identity"
    );
    (envelope, first, second)
}

fn governed_stale_then_current(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
    first: LocalReadAttempt,
    second: LocalReadAttempt,
    owner: &Session,
    rival: &Session,
) -> HostRequestResultBody {
    let stale_body = body_with_revision(envelope, first, 3);
    match kernel
        .submit_local_read_result(owner, &stale_body)
        .expect("stale submit must not fail")
    {
        LocalReadSubmitDisposition::StaleAttempt(observation) => {
            assert_eq!(
                observation.reason,
                StaleLocalReadReason::Superseded,
                "replacement projects as superseded"
            );
            assert_eq!(observation.current_generation, Some(2));
        }
        LocalReadSubmitDisposition::Persisted(_) => {
            panic!("a superseded attempt must never persist")
        }
    }
    let waiter = waiter_record(kernel, envelope);
    assert!(
        waiter.result_digest.is_none() && waiter.result_response.is_none(),
        "the waiter must observe no stale result"
    );
    let current_body = body_with_revision(envelope, second, 4);
    match kernel
        .submit_local_read_result(rival, &current_body)
        .expect("current submit must not fail")
    {
        LocalReadSubmitDisposition::Persisted(record) => {
            assert_eq!(record.state, HostRequestState::ResultReceived);
            assert_eq!(
                record.result_response.as_ref(),
                Some(&current_body.response)
            );
        }
        LocalReadSubmitDisposition::StaleAttempt(observation) => {
            panic!("the current attempt must persist, got stale: {observation:?}")
        }
    }
    // The replaced attempt stays refused after completion. The record is
    // terminal with a result, so a superseded capability presenting a
    // different body is an identity conflict rather than a stale
    // observation, and it never persists over the current completion.
    assert!(
        matches!(
            kernel.submit_local_read_result(owner, &stale_body),
            Err(TransportError::IdentityConflict)
        ),
        "a replaced attempt must stay refused after completion"
    );
    let waiter = waiter_record(kernel, envelope);
    assert_eq!(
        waiter.result_response.as_ref(),
        Some(&current_body.response),
        "the waiter keeps exactly the current completion"
    );
    current_body
}

fn governed_revocation_roundtrip(kernel: &KernelComposition, fence: &StateFence, owner: &Session) {
    let revoked_tool = query_tool();
    let revoked = query_envelope(
        fence,
        unix_ms().saturating_add(60_000),
        "host-request-governed-2",
        &tool_digest(&revoked_tool),
    );
    stage_admitted(kernel, &revoked);
    kernel
        .enqueue_local_read_pair(&revoked, &revoked_tool)
        .expect("enqueue must succeed");
    let (_, _, revoked_attempt) = kernel
        .claim_local_read_pair(owner)
        .expect("claim must not fail")
        .expect("pair must claim");
    kernel.fence_host_requests_for_connection("conn-test-1");
    let revoked_body = body_with_revision(&revoked, revoked_attempt, 5);
    match kernel
        .submit_local_read_result(owner, &revoked_body)
        .expect("revoked submit must not fail")
    {
        LocalReadSubmitDisposition::StaleAttempt(observation) => {
            assert_eq!(
                observation.reason,
                StaleLocalReadReason::Unclaimed,
                "revocation projects as unclaimed"
            );
            assert_eq!(observation.current_generation, None);
        }
        LocalReadSubmitDisposition::Persisted(_) => {
            panic!("a revoked attempt must never persist")
        }
    }
    let waiter = waiter_record(kernel, &revoked);
    assert!(
        waiter.result_digest.is_none() && waiter.result_response.is_none(),
        "the waiter must observe no revoked result"
    );
    // Revocation retires the pair: fencing moved the durable record off
    // `Admitted`, so the enqueue gate refuses it and no daemon read leg can
    // be entered. A revoked operation is never resurrected by re-invocation.
    assert_eq!(
        kernel
            .enqueue_local_read_pair(&revoked, &revoked_tool)
            .expect("enqueue must not fail"),
        LocalReadEnqueueDisposition::Retired,
        "a revoked record is refused, not re-queued"
    );
    assert!(
        kernel
            .claim_local_read_pair(owner)
            .expect("claim must not fail")
            .is_none(),
        "a retired revoked pair is never re-claimed"
    );

    // Recovery after revocation is a new operation identity, not a
    // re-invocation of the revoked one: a fresh admitted pair claims and
    // completes normally.
    let recovery_tool = query_tool();
    let recovery = query_envelope(
        fence,
        unix_ms().saturating_add(60_000),
        "host-request-governed-3",
        &tool_digest(&recovery_tool),
    );
    stage_admitted(kernel, &recovery);
    assert_eq!(
        kernel
            .enqueue_local_read_pair(&recovery, &recovery_tool)
            .expect("enqueue must not fail"),
        LocalReadEnqueueDisposition::Queued,
        "a new admitted operation queues after revocation"
    );
    let (_, _, fresh) = kernel
        .claim_local_read_pair(owner)
        .expect("claim must not fail")
        .expect("a new admitted pair must claim");
    let fresh_body = body_with_revision(&recovery, fresh, 6);
    assert!(
        matches!(
            kernel.submit_local_read_result(owner, &fresh_body),
            Ok(LocalReadSubmitDisposition::Persisted(_))
        ),
        "a new operation completes after revocation"
    );
}

/// Acceptance (#1808): exactly one completion per current fencing generation.
/// A superseded attempt quarantines as stale and leaves the waiter clean,
/// then the current attempt completes; a revoked attempt quarantines as
/// stale and its pair is retired rather than re-dispatched, then a new
/// operation identity completes.
#[test]
fn governed_attempt_replacement_and_revocation_quarantine_stale_and_current_completes() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-governed-attempt-{}",
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
    let owner = daemon_session_for(&policy);
    let rival = daemon_session_for_with(
        &policy,
        "reconnected-eliotd-connection",
        "reconnected-launch-nonce".to_owned(),
        2,
    );
    let (envelope, first, second) = governed_claim_replacement(&kernel, &fence, &owner, &rival);
    let _current = governed_stale_then_current(&kernel, &envelope, first, second, &owner, &rival);
    governed_revocation_roundtrip(&kernel, &fence, &owner);
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
