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
    use super::{check_state_result_receipt, same_state_owner_receipt};
    use crate::KernelConfig;
    use eliot_contracts::{HostCorrelationDomain, HostCorrelationProjection, StateFence};
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestIdentity, HostRequestResultClass,
        HostRequestResultLineage, HostRequestResultSourceRevision,
    };

    /// The exact admitted Session identity every fixture binds.
    const SESSION_ID: &str = "kernel-session-1";

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

    /// Builds an HONESTLY admitted `eliot.state` `Invocation` envelope.
    ///
    /// The correlation projection is load-bearing, not decoration. An
    /// `Invocation` is admitted only when its correlation is RESOLVED, and
    /// three independent real gates enforce that:
    ///
    /// * `HostRequestIdentity::validate_for_kind` binds the projection's
    ///   `occurrence_text()` to the exact `request_id`, refuses the
    ///   `KernelOperational` profile on a host envelope, and requires the
    ///   REQUEST domain on an invocation;
    /// * `RedbRecoveryStore::stage_host_request` refuses to stage an
    ///   `Invocation` row whose correlation is still unresolved
    ///   (`OrsError::HostRequestLegacyCorrelationUnresolved`);
    /// * the kernel-service `admit_and_stage` gate refuses the same shape as
    ///   `PortFailure::LegacyCorrelationUnresolved`.
    ///
    /// A fixture with `correlation_projection: None` is therefore refused in
    /// staging and never reaches the code under test — the projection is
    /// what makes this envelope honestly admitted, and `None` is reserved for
    /// historical rows.
    ///
    /// The host-native OPAQUE profile is the exact construction a non-MCP host
    /// uses for its own occurrence, copied from the bridge's bounded request
    /// decode (`bins/eliot-agent-bridge/src/main.rs` `decode_bounded_request`)
    /// and from the bridge's own operational-envelope construction
    /// (`bins/eliot-agent-bridge/src/kernel_host_request_client.rs`
    /// `build_restore_envelope`).
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
                correlation_projection: Some(HostCorrelationProjection::Opaque {
                    domain: HostCorrelationDomain::Request,
                    occurrence: request_id.to_owned(),
                }),
                idempotency_key: format!("{request_id}:invoke"),
                cancellation_id: format!("{request_id}:invoke:cancel"),
                parent_operation_id: None,
                deadline_unix_ms,
                capability: STATE_CAPABILITY.to_owned(),
                session_id: Some(SESSION_ID.to_owned()),
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

    /// Stages one envelope through the REAL ORS admission gate and advances it
    /// to `Admitted`, then reads the durable row back.
    ///
    /// This is the proof that the fixture is honestly admitted rather than
    /// merely well-shaped: ORS itself refuses an unresolved correlation, so a
    /// regression that dropped the projection fails HERE with the typed
    /// `HostRequestLegacyCorrelationUnresolved` instead of silently reaching
    /// the receipt gate.
    fn staged_admitted_record(
        kernel: &KernelComposition,
        envelope: &HostRequestEnvelope,
    ) -> HostRequestRecord {
        let requested = requested_host_request_record(envelope).expect("record must build");
        kernel
            .generation_gateway
            .ors
            .stage_host_request(&requested)
            .expect("an honestly correlated invocation must stage");
        let operation_id = OperationIdentity::new(host_request_operation_id(envelope))
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

    /// The fenced attempt capability the Kernel would mint at the state claim.
    ///
    /// Shape-valid on its own terms (`attempt_id` distinct from the operation
    /// handle, positive generation and use budget, the attempt epoch matching
    /// the lineage's source fence), so a body carrying it clears every
    /// pre-gate shape check in `submit_claimed_result` — including
    /// `validate_for_submission`'s attempt requirement — and is refused, if at
    /// all, by the owner-receipt gate this module owns.
    fn owner_attempt(envelope: &HostRequestEnvelope, fence: &StateFence) -> LocalReadAttempt {
        let operation_id = host_request_operation_id(envelope);
        LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            attempt_id: format!("{operation_id}:attempt:0000000000000001:1:1"),
            operation_id,
            fencing_generation: 1,
            session_id: SESSION_ID.to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            scope_id: SESSION_ID.to_owned(),
            facet_method: STATE_CAPABILITY.to_owned(),
            expires_at_unix_ms: envelope.identity.deadline_unix_ms,
            use_budget: 1,
        }
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
            attempt: Some(owner_attempt(envelope, fence)),
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
        // The control: this body clears EVERY shape check that runs before the
        // owner-receipt gate in `submit_claimed_result`, so a refusal below is
        // attributable to the receipt gate alone and not to a malformed body.
        body.validate()
            .expect("the owner's receipted result must be a valid result body");
        body.validate_for_submission()
            .expect("the owner's receipted result must be submittable");
        body
    }

    /// The durable row as the ORS persist path would retain it: the owner's
    /// result digest, response, and the owner's receipt projected through the
    /// one production mapping.
    fn retained_owner_record(
        envelope: &HostRequestEnvelope,
        body: &HostRequestResultBody,
    ) -> HostRequestRecord {
        let provenance = super::super::retained_result_provenance(body)
            .expect("retained projection must map");
        let mut record = requested_host_request_record(envelope).expect("record must build");
        record.state = HostRequestState::ResultReceived;
        record.result_digest = Some(body.result_digest.clone());
        record.result_response = Some(body.response.clone());
        record.result_lineage = provenance.result_lineage;
        record
    }

    /// Positive case for the wired state/read leg (#1739 W5): an honestly
    /// admitted `eliot.state` request reaches its projection owner, and the
    /// owner's receipted answer is ACCEPTED by the submission gate and is
    /// recognised as the SAME retained receipt on exact replay.
    ///
    /// What this deliberately does not drive is the bounded carrier's
    /// enqueue/claim leg. That leg is gated by
    /// `host_request_connection_gate_under_transition`, which requires a live,
    /// authenticated AND activated agent-bridge transport in
    /// `agent_bridge_connections`; a bare `KernelComposition` has
    /// `agent_bridge_profile: None`, so that leg is unreachable from a unit
    /// fixture without forging a transport receipt. Forging one here would
    /// manufacture the very admission this lane is supposed to prove, so this
    /// test starts at the last honestly reachable point: a really-admitted
    /// operation, and the two receipt joins the submit gate runs on it.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the flow admits one state envelope through the real staging gate, proves the carrier admission, and then proves both receipt joins on the owner's answer"
    )]
    fn admitted_state_pair_reaches_the_projection_owner_receipt_gate() {
        let root =
            std::env::temp_dir().join(format!("eliot-kernel-state-wire-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("test work root");
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

        // The envelope satisfies the closed contract INCLUDING the per-kind
        // identity rules, which is where a projection-less invocation is
        // refused.
        envelope
            .validate()
            .expect("the state envelope must satisfy the closed envelope contract");
        envelope
            .identity
            .validate_for_kind(HostRequestKind::Invocation)
            .expect("an invocation must carry a resolved request-domain correlation");

        // The carrier admission gate content-compares the presented bytes
        // against the admitted payload digest and derives the closed selectors.
        let selectors = check_local_state_admission(&envelope, &tool)
            .expect("the admitted state pair must validate");
        assert_eq!(selectors.scope_id.as_str(), SESSION_ID);
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

        // The row is honestly admitted: ORS itself accepts the staging.
        let admitted = staged_admitted_record(&kernel, &envelope);
        assert_eq!(admitted.state, HostRequestState::Admitted);
        assert_eq!(
            admitted.capability_ref.as_str(),
            STATE_CAPABILITY,
            "the admitted row is the state capability's own operation"
        );
        assert_eq!(
            admitted.correlation_projection,
            envelope.identity.correlation_projection,
            "the durable row retains the exact resolved correlation it was admitted with"
        );

        // The owner's answer is ACCEPTED by the submission gate.
        let owner = owner_projection_body(&envelope, &fence);
        assert_eq!(
            check_state_result_receipt(&owner),
            Ok(()),
            "the owner's explicit receipt is what completes the state row"
        );

        // Exact replay presents the SAME retained receipt, so the replay gate
        // recognises this retained outcome rather than declining it.
        let retained = retained_owner_record(&envelope, &owner);
        assert!(
            same_state_owner_receipt(&retained, &owner),
            "an exact replay under the same receipt is the same retained outcome"
        );

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Refusal case for the wired state/read leg (#1739 W5). A receiptless
    /// state result and a laundered canonical-write-receipt class are both
    /// refused by the submission gate, a receiptless presentation of
    /// already-retained bytes does not replay, a foreign-receipt presentation
    /// does not replay either, and the digest-only submit entry refuses a
    /// state envelope outright — so no state row can become a durable answer
    /// the bridge's owner-flight readback is forbidden to serve.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the refusals cover the receipt gate, the laundered class, the replay gate and the digest-only submit entry on one honestly admitted pair"
    )]
    fn state_result_without_the_owner_receipt_is_refused_by_the_submission_gate() {
        let root =
            std::env::temp_dir().join(format!("eliot-kernel-state-receipt-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("test work root");
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
        staged_admitted_record(&kernel, &envelope);

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

        let owner = owner_projection_body(&envelope, &fence);

        // A receiptless body over the owner's exact bytes: no lineage at all.
        let mut receiptless = owner.clone();
        receiptless.lineage = None;
        assert!(
            matches!(
                check_state_result_receipt(&receiptless),
                Err(TransportError::SessionFenced)
            ),
            "a receiptless state result must not complete the row"
        );

        // A laundered canonical write receipt: a read projection may not be
        // presented as an admitted canonical record. This body is otherwise
        // SELF-CONSISTENT — `validate_class` accepts a canonical class that
        // names its exact receipt — so the lane's own gate is the only thing
        // that can refuse it.
        let mut laundered = owner.clone();
        if let Some(lineage) = laundered.lineage.as_mut() {
            lineage.result_class = HostRequestResultClass::CanonicalWriteReceipt;
            lineage.semantic_receipt_ref = Some("write-receipt-1".to_owned());
        }
        laundered
            .validate()
            .expect("the laundered body is shape- and class-consistent by construction");
        assert!(
            matches!(
                check_state_result_receipt(&laundered),
                Err(TransportError::SessionFenced)
            ),
            "a state result claiming the canonical write-receipt class must be refused"
        );

        // The owner-backed answer is still the only accepted one.
        assert_eq!(check_state_result_receipt(&owner), Ok(()));

        // The replay gate: only the SAME retained receipt replays. A receiptless
        // presentation of the already-retained bytes and a foreign-receipt
        // presentation of the same bytes are both different claims, so the
        // replay arm declines them and the submission gate fails closed —
        // identical bytes can never launder away the receipt.
        let retained = retained_owner_record(&envelope, &owner);
        assert!(
            !same_state_owner_receipt(&retained, &receiptless),
            "a receiptless presentation is not the retained outcome"
        );
        assert!(
            !same_state_owner_receipt(&retained, &laundered),
            "a foreign-receipt presentation is not the retained outcome"
        );
        assert!(
            same_state_owner_receipt(&retained, &owner),
            "the owner's own receipt is the retained outcome"
        );

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }
}