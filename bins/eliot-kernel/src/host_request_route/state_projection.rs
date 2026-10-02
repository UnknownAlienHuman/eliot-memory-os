//! Owner-receipt binding for the bounded `eliot.state` result leg (issue
//! #1739 W5).
//!
//! #2564 built the state CARRIER: the `eliot.state` row is retained on the
//! shared bounded local-read carrier under its own
//! [`LocalReadPairKind::State`](super::LocalReadPairKind) form, claimed under
//! a fenced attempt, and submitted back through
//! [`KernelComposition::submit_local_state_result`](super::KernelComposition::submit_local_state_result).
//! That carrier carries the REQUEST end of the operation. This module owns
//! the ANSWER end: the join that makes a persisted state result an
//! owner-backed outcome rather than a bare body.
//!
//! Why it exists, precisely. The shared submit gate
//! (`super::KernelComposition::submit_claimed_result`) validated an
//! `eliot.query` result with
//! [`HostRequestResultBody::validate_local_read_submission`], which requires
//! the producer's explicit result lineage, but validated every OTHER capability
//! with the weaker `validate_for_submission`, which accepts a body carrying NO
//! lineage at all. The state row was in that weaker group, so it could persist
//! a result with no owner receipt. The bridge's
//! `require_submit_completion_receipt` already lists `eliot.state` as an
//! owner-flight row, so such a row could never be served: it was a durable
//! answer no caller could read. The retained-outcome rule therefore applies to
//! the state row exactly as it already applied to `eliot.observe`, and this
//! module is that rule's one owner for this lane.
//!
//! Two joins, both pure (no IO, no digest recomputation, no promotion):
//!
//! 1. [`check_state_result_receipt`] — the submission gate. The producer must
//!    present its explicit result lineage, AND that lineage must not claim the
//!    canonical write-receipt class. A state answer is a bounded read of
//!    already-retained owner state (I01-08 read path); letting it claim
//!    `CanonicalWriteReceipt` would let a read projection be laundered into an
//!    admitted canonical record by presenting a receipt reference, and
//!    [`HostRequestResultBody::validate`] refuses the inverse but not this
//!    direction for this lane's class.
//! 2. [`same_state_owner_receipt`] — the replay gate. Exact replay serves the
//!    same retained outcome only when the presented body carries the SAME
//!    owner receipt the durable row retained. A receiptless or foreign-receipt
//!    body over identical bytes is a different claim, not this retained
//!    outcome, so it declines the replay arm and falls through to the
//!    submission gate, which fails closed.

use eliot_ors::HostRequestRecord;
use eliot_protocol::{HostRequestResultBody, HostRequestResultClass};

use super::TransportError;

/// Requires the projection owner's receipt on one submitted `eliot.state`
/// result (issue #1739 W5).
///
/// The state answer is produced by a semantic owner flight, so the producer's
/// explicit result lineage is the actual owner receipt bound to the exact
/// result digest by [`HostRequestResultBody::validate`]. A body with no lineage
/// carries no semantic admission, so it can never complete the operation as
/// its retained outcome — it fails closed as `SessionFenced`, the same typed
/// family as a receiptless observe result, never as a bare admission that
/// would lose the answer.
///
/// The class half is the direction the protocol contract leaves to the
/// serving lane: `validate_class` already refuses a canonical class with no
/// receipt and a receipt on a non-canonical class, but a state result
/// presenting a self-consistent `CanonicalWriteReceipt` lineage would pass
/// every shape check. It is refused HERE because this lane only ever serves a
/// bounded read of already-retained owner state, which is never an admitted
/// canonical write (I01-08 read path; I05.19 receipt classes are limited to
/// the five named classes and this is not one of them for a read).
///
/// Pure: validation performs no IO by construction.
pub(super) fn check_state_result_receipt(
    body: &HostRequestResultBody,
) -> Result<(), TransportError> {
    let Some(lineage) = body.lineage.as_ref() else {
        return Err(TransportError::SessionFenced);
    };
    if lineage.result_class == HostRequestResultClass::CanonicalWriteReceipt {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

/// Reports whether one submitted `eliot.state` body presents the same owner
/// receipt the durable row retained (issue #1739 W5).
///
/// Both sides are ORIGINALLY RECORDED values: the presented lineage already
/// binds `body.result_digest` through [`HostRequestResultBody::validate`], and
/// the retained lineage already binds `stored.result_digest` through the ORS
/// persist path, so equal digests plus the equal receipt reference mean the
/// presentation repeats THIS retained outcome rather than a receiptless or
/// foreign-receipt body over identical bytes. A row that retained no receipt
/// has no same receipt to present.
///
/// Pure: no IO, no digest recomputation, no promotion — a mismatch simply
/// declines the replay arm, and the submission then faces
/// [`check_state_result_receipt`], which fails closed.
pub(super) fn same_state_owner_receipt(
    stored: &HostRequestRecord,
    body: &HostRequestResultBody,
) -> bool {
    match (&stored.result_lineage, &body.lineage) {
        (Some(retained), Some(presented)) => {
            presented.output_digest == retained.output_digest
                && presented.semantic_receipt_ref == retained.semantic_receipt_ref
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]
mod state_read_wire_tests {
    use super::super::*;
    use crate::KernelConfig;
    use eliot_contracts::StateFence;
    use eliot_ipc::{PeerIdentityUnavailable, SessionState, ServerHandshakePolicy};
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestResultClass, HostRequestResultLineage,
        HostRequestResultSourceRevision,
    };

    fn tool_digest(tool: &serde_json::Value) -> String {
        let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    }

    /// The canonical `eliot.state` tool bytes the MCP contract admits. The
    /// `include` list is the caller's projection-field selector; the Kernel
    /// never invents one.
    fn state_tool() -> serde_json::Value {
        serde_json::json!({"name":"eliot.state","arguments":{
            "include":["task","attention"]
        }})
    }

    fn state_envelope(
        fence: &StateFence,
        deadline_unix_ms: u64,
        request_id: &str,
        payload: &str,
    ) -> HostRequestEnvelope {
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: RequestId::new(request_id).expect("valid request id"),
                correlation_projection: None,
                idempotency_key: format!("{request_id}:invoke"),
                cancellation_id: format!("{request_id}:invoke:cancel"),
                parent_operation_id: None,
                deadline_unix_ms,
                capability: STATE_CAPABILITY.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
                payload_sha256: payload.to_owned(),
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

    fn daemon_session(policy: &ServerHandshakePolicy) -> Session {
        Session {
            connection_id: "authenticated-eliotd-connection".to_owned(),
            protocol_version: policy.protocol_range.maximum,
            peer: PeerIdentity::Unavailable {
                reason: PeerIdentityUnavailable::ProviderProofNotComposed,
            },
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
            module_generation: policy.module_generation.clone(),
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            effects: policy.allowed_effects.clone(),
            session_epoch: 1,
            state: SessionState::Open,
        }
    }

    fn stage_admitted(kernel: &KernelComposition, envelope: &HostRequestEnvelope) {
        let requested = requested_host_request_record(envelope).expect("record must build");
        kernel
            .generation_gateway
            .ors
            .stage_host_request(&requested)
            .expect("stage must succeed");
        let operation_id =
            OperationIdentity::new(host_request_operation_id(envelope)).expect("operation identity");
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
            .expect("admitted record must read back");
    }

    fn stored_record(kernel: &KernelComposition, envelope: &HostRequestEnvelope) -> HostRequestRecord {
        let operation_id =
            OperationIdentity::new(host_request_operation_id(envelope)).expect("operation identity");
        kernel
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &envelope.envelope_sha256)
            .expect("load must succeed")
            .expect("staged record must exist")
    }

    /// The projection owner's answer for one claimed State pair.
    ///
    /// The Kernel never authors this payload — it is the owner's bounded
    /// projection, bound here to the exact result digest and the exact
    /// completing attempt, with the owner's source revisions and fence. The
    /// lineage class is the read class, because a state answer is a bounded
    /// read of already-retained owner state (I01-08 read path).
    fn owner_projection_body(
        envelope: &HostRequestEnvelope,
        attempt: LocalReadAttempt,
        fence: &StateFence,
    ) -> HostRequestResultBody {
        let response = serde_json::json!({
            "kind": "Projection",
            "content": {
                "task": {"goal": "wire the state leg", "readiness": "ready"},
                "attention": [],
                "scope": "kernel-session-1",
            },
            "revision_heads": [{"key": "scope:kernel-session-1", "revision": 3}],
        });
        let digest = {
            let bytes = eliot_contracts::canonical_json_bytes(&response)
                .expect("owner projection must canonicalize");
            eliot_contracts::sha256_hex(&bytes)
        };
        let body = HostRequestResultBody {
            wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
            wire_version: HostRequestResultBody::CONTRACT_VERSION,
            operation_id: host_request_operation_id(envelope),
            request_sha256: envelope.envelope_sha256.clone(),
            result_digest: digest.clone(),
            response,
            attempt: Some(attempt),
            lineage: Some(HostRequestResultLineage {
                output_artifact_ref: None,
                output_digest: digest,
                producer_ref: Some("eliotd-state-projection-owner".to_owned()),
                source_revisions: Some(vec![HostRequestResultSourceRevision {
                    key: "scope:kernel-session-1".to_owned(),
                    revision: 3,
                    state_fence: fence.clone(),
                }]),
                source_state_fence: Some(fence.clone()),
                input_refs: None,
                transformation_lineage: None,
                closure_refs: None,
                policy_fence: None,
                origin_evidence_refs: None,
                semantic_receipt_ref: None,
                result_class: HostRequestResultClass::ExistingEvidenceRead,
                proof_ceiling: None,
                influence_state: eliot_security_contracts::InfluenceState::Unknown,
                instruction_taint: None,
            }),
            // Read-only owner flight: no external effect was produced, so this
            // leg reports no effect evidence. That absence is recorded as an
            // explicit missing part by the trace manifest, never invented.
            evidence: None,
        };
        body.validate_for_submission()
            .expect("the owner's receipted result must validate");
        body
    }

    /// Positive case for the wired state/read leg (#1739 W5): a real permitted
    /// `eliot.state` request retains a State-form pair on the bounded carrier,
    /// is claimed under a fenced attempt, is answered by the projection owner
    /// with an owner-receipted result, that result PERSISTS, and the ordinary
    /// readback serves it.
    ///
    /// The query claim is polled in the middle as the capability-confusion
    /// proof: the retained State pair is not claimable on the query form, so
    /// the two lanes can never complete each other's attempts.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the roundtrip admits, retains, claims, answers, persists, reads back and replays one state pair in a single focused flow"
    )]
    fn state_pair_reaches_its_owner_and_persists_an_owner_receipted_result() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-state-wire-{}",
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
        let session = daemon_session(&policy);

        let tool = state_tool();
        let envelope = state_envelope(
            &fence,
            unix_ms().saturating_add(60_000),
            "host-request-state-1",
            &tool_digest(&tool),
        );

        // The linkage gate content-compares the presented bytes against the
        // admitted payload digest and derives the closed selectors.
        let selectors = check_local_state_admission(&envelope, &tool)
            .expect("the admitted state pair must validate");
        assert_eq!(selectors.scope_id.as_str(), "kernel-session-1");
        assert_eq!(selectors.include, vec!["task", "attention"]);
        // A forged identity is refused by the same gate: a query's bytes under
        // a state envelope no longer bind the admitted payload digest.
        assert!(
            check_local_state_admission(
                &envelope,
                &serde_json::json!({"name":"eliot.query","arguments":{}})
            )
            .is_err(),
            "bytes that do not bind the admitted state payload must be refused"
        );

        stage_admitted(&kernel, &envelope);
        let retained = kernel
            .enqueue_local_read_pair(&envelope, &tool)
            .expect("the state pair must retain");
        assert_eq!(
            retained,
            LocalReadPairKind::State,
            "an admitted eliot.state pair retains under the State carrier form"
        );
        assert!(
            kernel
                .claim_local_read_pair(&session)
                .expect("query claim must not fail")
                .is_none(),
            "a State pair is never claimable on the query form"
        );

        let claimed = kernel
            .claim_local_state_pair(&session)
            .expect("state claim must not fail")
            .expect("the queued state pair must claim");
        assert_eq!(claimed.form, LocalReadPairKind::State);
        assert_eq!(claimed.envelope.envelope_sha256, envelope.envelope_sha256);
        assert_eq!(claimed.tool, tool);
        assert_eq!(
            claimed.attempt.fencing_generation, 1,
            "the first state claim mints fencing generation 1"
        );

        let body = owner_projection_body(&envelope, claimed.attempt.clone(), &fence);
        let persisted = match kernel
            .submit_local_state_result(&session, &body)
            .expect("the owner's result must submit")
        {
            LocalReadSubmitDisposition::Persisted(record) => record,
            LocalReadSubmitDisposition::StaleAttempt(observation) => {
                panic!("the current attempt must persist, got stale: {observation:?}")
            }
        };
        assert_eq!(persisted.state, HostRequestState::ResultReceived);
        assert_eq!(
            persisted.result_digest.as_deref(),
            Some(body.result_digest.as_str())
        );
        assert_eq!(persisted.result_response.as_ref(), Some(&body.response));
        assert!(
            persisted.result_lineage.is_some(),
            "the persisted state result carries the owner's receipt, so the bridge can read it back"
        );

        // The ordinary readback consumer serves the retained owner-backed
        // result without re-dispatching anything.
        let receipt =
            HostRequestAdmissionReceipt::issue(&envelope).expect("receipt must issue");
        let replayed = local_read_replay_response(&receipt, &persisted, &envelope)
            .expect("readback must not fail")
            .expect("a resulted state row must read back");
        assert_eq!(
            replayed["value"]["record"]["result_response"], body.response,
            "readback carries the exact owner projection"
        );
        assert_eq!(
            replayed["value"]["record"]["result_lineage"]["result_class"], "EXISTING_EVIDENCE_READ",
            "readback carries the owner's retained receipt class"
        );

        // Exact replay under the same identity is idempotent: the same retained
        // outcome, no second completion, no duplicated effect.
        let replay_submit = match kernel
            .submit_local_state_result(&session, &body)
            .expect("exact replay must not fail")
        {
            LocalReadSubmitDisposition::Persisted(record) => record,
            LocalReadSubmitDisposition::StaleAttempt(observation) => {
                panic!("exact replay must stay idempotent, got stale: {observation:?}")
            }
        };
        assert_eq!(replay_submit.result_digest, persisted.result_digest);

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Refusal case for the wired state/read leg (#1739 W5). A receiptless
    /// state result, a laundered canonical-write-receipt class, and a
    /// receiptless presentation of already-retained bytes are all refused,
    /// and the digest-only submit entry no longer acknowledges a state
    /// envelope at all — so no state row can become a durable answer nobody
    /// is allowed to read.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the refusals cover the submit entry, the receipt gate, the laundered class and the replay gate on one admitted pair"
    )]
    fn state_result_without_the_owner_receipt_is_refused_and_never_persists() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-state-receipt-{}",
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
        let session = daemon_session(&policy);

        let tool = state_tool();
        let envelope = state_envelope(
            &fence,
            unix_ms().saturating_add(60_000),
            "host-request-state-2",
            &tool_digest(&tool),
        );
        stage_admitted(&kernel, &envelope);

        // The digest-only submit entry is closed for this row: a state
        // envelope there retains no bytes, so it is refused rather than
        // acknowledged with a handle nothing can answer.
        assert!(
            matches!(
                kernel.admit_and_queue_observe_submit(&envelope, None),
                Err(TransportError::SessionFenced)
            ),
            "a state envelope on the digest-only submit entry must be refused"
        );

        assert_eq!(
            kernel
                .enqueue_local_read_pair(&envelope, &tool)
                .expect("the state pair must retain"),
            LocalReadPairKind::State
        );
        let attempt = kernel
            .claim_local_state_pair(&session)
            .expect("state claim must not fail")
            .expect("the queued state pair must claim")
            .attempt;

        let owner = owner_projection_body(&envelope, attempt.clone(), &fence);

        // A receiptless body over the owner's exact bytes: no lineage at all.
        let mut receiptless = owner.clone();
        receiptless.lineage = None;
        assert!(
            matches!(
                kernel.submit_local_state_result(&session, &receiptless),
                Err(TransportError::SessionFenced)
            ),
            "a receiptless state result must not complete the row"
        );
        assert!(
            stored_record(&kernel, &envelope).result_digest.is_none(),
            "a refused state result must leave the durable row clean"
        );

        // A laundered canonical write receipt: a read projection may not be
        // presented as an admitted canonical record.
        let mut laundered = owner.clone();
        if let Some(lineage) = laundered.lineage.as_mut() {
            lineage.result_class = HostRequestResultClass::CanonicalWriteReceipt;
            lineage.semantic_receipt_ref = Some("write-receipt-1".to_owned());
        }
        assert!(
            matches!(
                kernel.submit_local_state_result(&session, &laundered),
                Err(TransportError::SessionFenced)
            ),
            "a state result claiming the canonical write-receipt class must be refused"
        );
        assert!(
            stored_record(&kernel, &envelope).result_digest.is_none(),
            "a refused laundered result must leave the durable row clean"
        );

        // The owner-backed result is accepted and persists.
        let persisted = match kernel
            .submit_local_state_result(&session, &owner)
            .expect("the owner's receipted result must submit")
        {
            LocalReadSubmitDisposition::Persisted(record) => record,
            LocalReadSubmitDisposition::StaleAttempt(observation) => {
                panic!("the current attempt must persist, got stale: {observation:?}")
            }
        };
        assert!(
            persisted.result_lineage.is_some(),
            "only the owner-receipted result persists"
        );

        // A receiptless presentation of the ALREADY retained bytes is not this
        // retained outcome: the replay arm declines it and the submission gate
        // fails closed, so identical bytes can never launder away the receipt.
        let mut receiptless_replay = owner.clone();
        receiptless_replay.lineage = None;
        assert!(
            matches!(
                kernel.submit_local_state_result(&session, &receiptless_replay),
                Err(TransportError::SessionFenced)
            ),
            "a receiptless replay over retained bytes must be refused"
        );
        assert_eq!(
            stored_record(&kernel, &envelope).result_digest,
            persisted.result_digest,
            "the refused replay must not alter the retained outcome"
        );

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }
}
