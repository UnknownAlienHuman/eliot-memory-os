//! Kernel activation claim tests — acceptance-only scope.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md` :: A2.3 and `ARCH-MOD-01` — modular architecture, ordinary module boundary.
//! - `ELIOT_IMPLEMENTATION.md` :: I2.2 and `I2.16` — crate capability extraction and crate-size/Agent Context Envelope.
//!
//! This module owns no runtime authority and exercises only the Kernel composition
//! boundary via `super::*`. It is an ordinary module kept under 10k LOC.

use super::*;

#[cfg(windows)]
fn activation_test_entry(deadline: u64) -> (String, AgentActivationPending) {
    let state_fence = StateFence::new(
        AuthorityEpoch::new(1).expect("authority epoch"),
        ResourceGeneration::new(1).expect("resource generation"),
    );
    let request_id = RequestId::new("activation-request-test").expect("request id");
    let request: AgentBridgeActivationRequest = serde_json::from_value(serde_json::json!({
        "wire_id": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_ID,
        "wire_version": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_VERSION,
        "operation": AGENT_BRIDGE_ACTIVATION_OPERATION,
        "demand_id": "activation-demand-test",
        "connection_id": "activation-connection-test",
        "attach_kind": "MANAGED",
        "pre_attach_blind_interval": null,
        "request_identity": {
            "request": {
                "metadata": {
                    "request_id": request_id.as_str(),
                    "session_id": null,
                    "task_id": null,
                    "product_id": "eliot-agent-bridge",
                    "source_id": "agent-bridge-test",
                    "state_fence": state_fence.clone(),
                    "clock": {
                        "valid_time_ms": null,
                        "known_time_ms": null,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    }
                },
                "state_fence": state_fence.clone()
            },
            "idempotency_key": "activation-idempotency-test",
            "deadline_unix_ms": deadline,
            "cancellation_id": "activation-cancellation-test"
        },
        "peer_admission_receipt_sha256": "b".repeat(64),
        "request_sha256": "a".repeat(64)
    }))
    .expect("activation request");
    let ticket_id = "activation-ticket-test".to_owned();
    let ticket = AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: ticket_id.clone(),
        activation_request_id: request_id,
        activation_request_sha256: request.request_sha256.clone(),
        peer_admission_receipt_sha256: request.peer_admission_receipt_sha256.clone(),
        connection_id: request.connection_id.clone(),
        state_fence,
        kernel_deadline_unix_ms: deadline,
        ticket_sha256: "c".repeat(64),
    };
    (
        ticket_id,
        AgentActivationPending {
            ticket,
            request,
            decision: None,
            claim_lease_until_unix_ms: None,
        },
    )
}

#[cfg(windows)]
fn activation_test_decision(ticket_id: &str) -> AgentActivationResolutionDecision {
    AgentActivationResolutionDecision {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID.to_owned(),
        wire_version: AgentActivationResolutionDecision::CONTRACT_VERSION,
        ticket_id: ticket_id.to_owned(),
        ticket_sha256: "c".repeat(64),
        state_fence: StateFence::new(
            AuthorityEpoch::new(1).expect("authority epoch"),
            ResourceGeneration::new(1).expect("resource generation"),
        ),
        principal_id: "principal-test".to_owned(),
        session_id: "session-test".to_owned(),
        task_id: "task-test".to_owned(),
        work_unit_id: "work-unit-test".to_owned(),
        work_scope_id: "scope-test".to_owned(),
        task_revision: "task-revision-test".to_owned(),
        plan_id: "plan-test".to_owned(),
        plan_revision: "plan-revision-test".to_owned(),
        decision_sha256: "d".repeat(64),
    }
}

#[cfg(windows)]
#[test]
fn activation_claim_lease_retries_transient_resolution_without_duplicate_claim() {
    let (ticket_id, entry) = activation_test_entry(2_000);
    let mut pending = AgentActivationPendingState::default();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id, entry);

    let first = pending.claim_at(1).expect("first claim");
    assert_eq!(first.ticket_id, "activation-ticket-test");
    assert!(pending.claim_at(AGENT_ACTIVATION_CLAIM_LEASE_MS).is_none());
    let retry = pending
        .claim_at(AGENT_ACTIVATION_CLAIM_LEASE_MS + 1)
        .expect("claim after lease expiry");
    assert_eq!(retry, first, "retry reuses the exact Kernel ticket");
}

#[cfg(windows)]
#[test]
fn activation_claim_expires_at_deadline_and_decided_ticket_is_not_reclaimed() {
    let (ticket_id, mut entry) = activation_test_entry(2_000);
    let mut pending = AgentActivationPendingState::default();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id.clone(), entry.clone());
    assert!(pending.claim_at(2_000).is_none(), "deadline is inclusive");

    entry.decision = Some(activation_test_decision(&ticket_id));
    pending.fifo.clear();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id, entry);
    assert!(
        pending.claim_at(1).is_none(),
        "decided tickets are terminal"
    );
}

#[cfg(windows)]
#[test]
fn activation_decision_replay_is_exact_and_conflicts_are_rejected() {
    let first = activation_test_decision("activation-ticket-test");
    assert_eq!(
        classify_activation_decision(None, &first),
        ActivationDecisionDisposition::Commit
    );
    assert_eq!(
        classify_activation_decision(Some(&first), &first),
        ActivationDecisionDisposition::ExactReplay
    );
    let mut conflicting = first.clone();
    conflicting.plan_id = "different-plan".to_owned();
    assert_eq!(
        classify_activation_decision(Some(&first), &conflicting),
        ActivationDecisionDisposition::Conflict
    );
}
