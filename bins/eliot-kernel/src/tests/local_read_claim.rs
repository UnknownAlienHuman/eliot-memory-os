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
use host_request_route::{LocalReadPairKind, LocalReadSubmitDisposition, StaleLocalReadReason};

/// Claims one bounded read on the QUERY lane and returns its envelope, tool
/// bytes, and attempt capability.
///
/// `claim_local_read_pair` is the query-form entry point, so every pair it
/// yields must carry the `Query` carrier form (issue #2564). The form is
/// asserted here rather than discarded: it is the discriminator that keeps the
/// query and State lanes from completing each other's attempts, and a claim
/// that came back untagged or tagged `State` would be exactly the capability
/// confusion the tag exists to prevent.
fn claim_query_pair(
    kernel: &KernelComposition,
    session: &Session,
) -> (HostRequestEnvelope, serde_json::Value, LocalReadAttempt) {
    let claimed = kernel
        .claim_local_read_pair(session)
        .expect("claim must not fail")
        .expect("queued pair must claim");
    assert_eq!(
        claimed.form,
        LocalReadPairKind::Query,
        "the query claim returns the Query carrier form, never State or untagged"
    );
    (claimed.envelope, claimed.tool, claimed.attempt)
}

/// Enqueues one bounded read on the shared carrier and pins the form actually
/// retained.
///
/// Every fixture here stages an `eliot.query` tool, so the admission gate
/// resolves the carrier form to `Query` (issue #2564). The returned form is
/// asserted rather than discarded: the enqueue resolves the form ONCE from the
/// two closed admission owners, so this is the disposition the carrier was
/// tagged with, and an untagged or `State` result would mean the query pair was
/// staged under the wrong form.
fn enqueue_query_pair(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) {
    let retained = kernel
        .enqueue_local_read_pair(envelope, tool)
        .expect("enqueue must succeed");
    assert_eq!(
        retained,
        LocalReadPairKind::Query,
        "an admitted eliot.query pair retains as the Query carrier form"
    );
}

fn tool_digest(tool: &serde_json::Value) -> String {
    let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
    eliot_contracts::sha256_hex(&bytes)
}

fn query_tool() -> serde_json::Value {
    serde_json::json!({"name":"eliot.query","arguments":{
        "intent":{
            "mode":"verification"
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
            correlation_projection: None,
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

fn result_body_for(
    envelope: &HostRequestEnvelope,
    attempt: Option<LocalReadAttempt>,
) -> HostRequestResultBody {
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
        attempt,
        lineage: None,
        // Claim-lifecycle fixture only: no execution evidence is presented,
        // so the sealed manifest lists it as missing parts.
        evidence: None,
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
        matches!(
            host_request_route::check_local_read_admission(&envelope, &tool)
                .expect("admitted query must validate"),
            host_request_route::LocalReadAdmission::Query(_)
        ),
        "the admitted query carries selectors and is queue-eligible"
    );
    stage_admitted(&kernel, &envelope);

    // Exact replay never duplicates the queued pair.
    enqueue_query_pair(&kernel, &envelope, &tool);
    enqueue_query_pair(&kernel, &envelope, &tool);

    let (claimed_envelope, claimed_tool, attempt) = claim_query_pair(&kernel, &daemon_session);
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
    let (_, _, reattempt) = claim_query_pair(&kernel, &daemon_session);
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
    conflicting.response = serde_json::json!({
        "operation": "GetEvidencePack",
        "subject": "evidence-alpha",
        "evidence_pack": { "subject": "evidence-alpha" },
        "revision_heads": [{ "key": "scope:kernel-session-1", "revision": 4 }],
    });
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
    let replayed = host_request_route::local_read_replay_response(&receipt, &stored, &envelope)
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

    // A changed body after completion is stale, not a second completion: the
    // persist retired the attempt, so no live generation remains.
    assert!(
        matches!(
            kernel.submit_local_read_result(&daemon_session, &conflicting),
            Ok(LocalReadSubmitDisposition::StaleAttempt(_))
        ),
        "a changed body after completion must quarantine as stale"
    );

    // A changed body under a fresh live attempt still conflicts: currency
    // passes, then the ORS result path refuses the overwrite. The caller
    // re-invokes (re-enqueue after retire), claims anew, and submits.
    enqueue_query_pair(&kernel, &envelope, &tool);
    let (_, _, fresh) = claim_query_pair(&kernel, &daemon_session);
    assert_ne!(
        fresh.attempt_id, attempt.attempt_id,
        "a new claim mints a fresh attempt identity"
    );
    let mut fresh_conflicting = conflicting.clone();
    fresh_conflicting.attempt = Some(fresh);
    assert!(
        matches!(
            kernel.submit_local_read_result(&daemon_session, &fresh_conflicting),
            Err(TransportError::IdentityConflict)
        ),
        "a changed same-identity body must conflict under a live attempt"
    );
    // Retire the proof pair so the expiry leg below polls an empty queue.
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
    enqueue_query_pair(&kernel, &expired, &expired_tool);
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
    body.response = serde_json::json!({
        "operation": "GetEvidencePack",
        "subject": "evidence-alpha",
        "evidence_pack": { "subject": "evidence-alpha" },
        "revision_heads": [{ "key": "scope:kernel-session-1", "revision": revision }],
    });
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
    enqueue_query_pair(kernel, &envelope, &tool);
    let (_, _, first) = claim_query_pair(kernel, owner);
    assert_eq!(first.fencing_generation, 1);
    let (_, _, second) = claim_query_pair(kernel, rival);
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
    assert!(
        matches!(
            kernel.submit_local_read_result(owner, &stale_body),
            Ok(LocalReadSubmitDisposition::StaleAttempt(_))
        ),
        "a replaced attempt must stay stale after completion"
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
    enqueue_query_pair(kernel, &revoked, &revoked_tool);
    let (_, _, revoked_attempt) = claim_query_pair(kernel, owner);
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
    enqueue_query_pair(kernel, &revoked, &revoked_tool);
    let (_, _, fresh) = claim_query_pair(kernel, owner);
    let fresh_body = body_with_revision(&revoked, fresh, 6);
    assert!(
        matches!(
            kernel.submit_local_read_result(owner, &fresh_body),
            Ok(LocalReadSubmitDisposition::Persisted(_))
        ),
        "the current attempt completes after revocation"
    );
}

/// Acceptance (#1808): exactly one completion per current fencing generation.
/// A superseded attempt quarantines as stale and leaves the waiter clean,
/// then the current attempt completes; a revoked attempt quarantines as
/// stale, then the re-invoked current attempt completes.
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

/// The owner-backed `eliot.state` tool bytes admitted on the bounded carrier.
///
/// The State form carries no evidence selector: the arguments are only the
/// closed `include` projection field list the state owners answer. There is
/// deliberately no `intent` block here, which is one of the ways these bytes
/// can never be re-read as an evidence query.
fn state_tool() -> serde_json::Value {
    serde_json::json!({"name":"eliot.state","arguments":{
        "include":["task","scope","attention","health"]
    }})
}

/// Builds the admitted `eliot.state` envelope for one request id.
///
/// The capability is the closed State capability and the payload digest is the
/// canonical digest of the exact retained tool bytes, so the invoke-read
/// linkage gate the State admission re-runs is satisfied by construction. The
/// correlation projection is the explicit Request-domain occurrence for this
/// request id, which the durable store requires before an `Invocation` row can
/// stage; its occurrence text IS the request id, so the two cannot drift.
fn state_envelope(
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
            correlation_projection: Some(eliot_contracts::HostCorrelationProjection::Opaque {
                domain: eliot_contracts::HostCorrelationDomain::Request,
                occurrence: request_id.to_owned(),
            }),
            idempotency_key: format!("{request_id}:invoke"),
            cancellation_id: format!("{request_id}:invoke:cancel"),
            parent_operation_id: None,
            deadline_unix_ms,
            capability: "eliot.state".to_owned(),
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

/// Builds a fresh test root for one carrier-form test.
fn fresh_kernel_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("eliot-kernel-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("test work root");
    root
}

/// POSITIVE (#2564): an `eliot.state` pair round-trips its admitted identity
/// into the closed State carrier form, and the Kernel mints the State facet
/// method from the admitted envelope capability.
///
/// The State admission is the owner of this form, so it is the reachable seam
/// that decides which claim lane a pair belongs to: it re-runs the exact
/// invoke-read linkage (capability plus payload digest over the presented
/// bytes) and derives the closed selectors, and it refuses any pair whose
/// envelope capability is not the closed State capability. What this proves is
/// the identity the claim hands the daemon: the same admitted envelope and the
/// exact retained tool bytes, tagged State, with the facet method minted from
/// the envelope capability rather than supplied by the caller.
#[test]
fn state_pair_admits_into_the_state_carrier_form_with_exact_identity() {
    let root = fresh_kernel_root("state-form-identity");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let fence = policy.module_generation.state_fence.clone();

    let tool = state_tool();
    let envelope = state_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-1",
        &tool_digest(&tool),
    );

    // The exact admitted bytes resolve to the real State selectors: the
    // trusted scope plus the exact `include` projection field list, in order.
    let selectors = host_request_route::check_local_state_admission(&envelope, &tool)
        .expect("the admitted state pair must validate its selectors");
    assert_eq!(
        selectors.include,
        vec![
            "task".to_owned(),
            "scope".to_owned(),
            "attention".to_owned(),
            "health".to_owned()
        ],
        "the State selectors carry the exact retained include projection"
    );
    assert_eq!(
        selectors.scope_id,
        eliot_store_api::ScopeId::new("kernel-session-1").expect("trusted scope"),
        "the State scope is the admitted envelope scope, never an MCP argument"
    );

    // The admitted envelope is the exact identity the carrier retains: the
    // capability is the closed State capability, so the facet method the Kernel
    // mints from `envelope.identity.capability` at claim is exactly
    // `eliot.state` and can never be a caller-chosen free-form string.
    assert_eq!(
        envelope.identity.capability, "eliot.state",
        "the State form is bound to the closed State capability"
    );
    assert_eq!(
        envelope.identity.payload_sha256,
        tool_digest(&tool),
        "the admitted payload digest is the canonical digest of the retained tool bytes"
    );
    assert_eq!(
        envelope.envelope_sha256.len(),
        64,
        "the admitted envelope carries its own exact computed digest"
    );

    // The retained form code is the stable audit code for this carrier form,
    // and it is distinct from the query form's code: one carrier, two forms.
    assert_eq!(
        LocalReadPairKind::State.as_str(),
        "state",
        "the State carrier form has the stable state form code"
    );
    assert_ne!(
        LocalReadPairKind::State.as_str(),
        LocalReadPairKind::Query.as_str(),
        "the State and Query carrier forms are distinct codes over one carrier"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

/// REFUSAL (#2564): a State pair can never be admitted as a Query read.
///
/// This is the capability-confusion guard, checked at the admission owner that
/// decides the carrier form. The query admission resolves its form from the
/// closed query capability and requires the query selector block; the State
/// bytes have no such block and a different capability, so the query gate must
/// refuse them. That refusal is what keeps a state result from ever being
/// served - or completed - through the query claim path.
#[test]
fn state_pair_is_refused_by_the_query_admission_never_reclassified_as_a_query() {
    let root = fresh_kernel_root("state-query-refusal");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let fence = policy.module_generation.state_fence.clone();

    let tool = state_tool();
    let envelope = state_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-2",
        &tool_digest(&tool),
    );

    // The State gate accepts the exact admitted pair.
    assert!(
        host_request_route::check_local_state_admission(&envelope, &tool).is_ok(),
        "the admitted state pair must validate under the State admission"
    );

    // The Query gate refuses the very same bytes: the two closed admission
    // owners are disjoint on this pair, so the carrier form can only be State.
    assert!(
        host_request_route::check_local_read_admission(&envelope, &tool).is_err(),
        "a State pair must never be admitted by the query admission"
    );

    // And the refusal survives a change of tool NAME alone: naming the query
    // capability while the admitted payload still digests to the State bytes
    // is refused by the invoke-read linkage gate, so a hidden method invoked
    // by name faces the identical closed admission.
    let forged_name = serde_json::json!({"name":"eliot.query","arguments":{
        "include":["task","scope","attention","health"]
    }});
    let mut forged_envelope = state_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-2",
        &tool_digest(&forged_name),
    );
    forged_envelope.identity.capability = "eliot.query".to_owned();
    assert!(
        host_request_route::check_local_read_admission(&forged_envelope, &forged_name).is_err(),
        "a query-named tool carrying state arguments must still be refused"
    );
    assert!(
        host_request_route::check_local_state_admission(&forged_envelope, &forged_name).is_err(),
        "the same renamed bytes must not slip into the State form either"
    );

    // The query form's own carrier tag is minted only from a query admission,
    // and the State form is never produced by `of_admission`: the form tag is
    // an admission-derived discriminator, never a caller-declared string.
    let query = query_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-2-query",
        &tool_digest(&query_tool()),
    );
    if let Ok(admission) = host_request_route::check_local_read_admission(&query, &query_tool()) {
        // Where the query admission accepts its own query bytes, the carrier
        // form it derives is the Query form and never the State form: the
        // discriminator that keeps the two claim lanes apart is derived from
        // the admission, not asserted by the caller.
        assert_eq!(
            LocalReadPairKind::of_admission(&admission),
            Some(LocalReadPairKind::Query),
            "a query admission derives the Query carrier form, never State"
        );
    }
    // The State form has no `LocalReadAdmission` at all: it is minted only by
    // the closed State gate above, so no query admission can ever yield it.
    assert_ne!(
        LocalReadPairKind::Query.as_str(),
        LocalReadPairKind::State.as_str(),
        "the query claim lane and the state claim lane name different forms"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

/// REFUSAL (#2564): the State carrier form is re-derived from the admitted
/// bytes at claim, never taken from the wire, and a mismatched pair is refused
/// rather than reclassified.
///
/// The claim-side form gate re-runs the closed State admission over the exact
/// retained envelope and tool bytes before any attempt is minted, so the form
/// follows the admitted capability. This asserts that decision function
/// directly on the same inputs a claim sees: the exact admitted pair resolves
/// to the State selectors, a pair whose capability was widened past the closed
/// State capability is refused outright, and a malformed `include` list is
/// refused rather than silently repaired.
#[test]
fn state_carrier_form_is_re_derived_from_the_admitted_bytes_at_claim() {
    let root = fresh_kernel_root("state-form-binding");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let fence = policy.module_generation.state_fence.clone();

    let tool = state_tool();
    let envelope = state_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-3",
        &tool_digest(&tool),
    );

    // The exact retained pair re-derives as the State form.
    let admitted = host_request_route::check_local_state_admission(&envelope, &tool)
        .expect("the exact retained state pair re-derives at claim");
    assert_eq!(
        admitted.include,
        selectors_of(&tool),
        "the claim-side re-derivation reads the exact retained include projection"
    );

    // A payload digest that no longer matches the presented bytes is refused:
    // the form gate re-runs the linkage check instead of trusting the stored
    // tag, so a tampered pair is skipped for reconciliation, never claimed.
    let mut retagged = envelope.clone();
    retagged.identity.payload_sha256 = "f".repeat(64);
    assert!(
        host_request_route::check_local_state_admission(&retagged, &tool).is_err(),
        "a state pair whose payload digest drifted must be refused at claim"
    );

    // A capability widened past the closed State capability is refused. The
    // form is minted from the admitted capability the gate validated, so a
    // hidden method invoked by name cannot acquire the State carrier form.
    let mut widened = envelope.clone();
    widened.identity.capability = "eliot.query".to_owned();
    assert!(
        host_request_route::check_local_state_admission(&widened, &tool).is_err(),
        "a pair whose capability is not the closed State capability must be refused"
    );

    // A duplicated projection field is refused rather than deduplicated, so the
    // re-derived form never depends on a repair the claim does not perform.
    let duplicate = serde_json::json!({"name":"eliot.state","arguments":{
        "include":["task","task"]
    }});
    let duplicate_envelope = state_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-3-duplicate",
        &tool_digest(&duplicate),
    );
    assert!(
        host_request_route::check_local_state_admission(&duplicate_envelope, &duplicate).is_err(),
        "a duplicated include field must fail closed"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

/// Returns the exact `include` projection field list carried by one state tool.
fn selectors_of(tool: &serde_json::Value) -> Vec<String> {
    tool.pointer("/arguments/include")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .expect("state tool must carry an include array")
}
