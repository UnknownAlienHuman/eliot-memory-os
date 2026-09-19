//! Proof tests for the protocol-owned invalid-ticket terminal artifact
//! (issue #202, owner decision ii).
//!
//! Every property is proved here: raw bytes preserved, ticket identity
//! preserved, callable pre-Governor (no Governor handle in or out), no
//! digest-bound construction from the invalid ticket, no retry, and explicit
//! distinction from digest-bound results.

use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
use eliot_protocol::{
    AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID,
    AgentActivationInvalidTicket, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolutionTicket, ProtocolError,
    UNKNOWN_INVALID_TICKET_ID,
};
use serde_json::Value;

const OBSERVED_AT_UNIX_MS: u64 = 9_000;

fn test_epoch(sequence: u64) -> Result<EpochId, ProtocolError> {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").map_err(|error| {
        ProtocolError::Provider {
            provider: "eliot-contracts",
            reason: error.to_string(),
        }
    })?;
    let sequence = std::num::NonZeroU64::new(sequence).ok_or(ProtocolError::InvalidField {
        field: "test_epoch.sequence",
        reason: "must be greater than zero",
    })?;
    EpochId::new(lineage, sequence).map_err(|error| ProtocolError::Provider {
        provider: "eliot-contracts",
        reason: error.to_string(),
    })
}

fn valid_ticket() -> Result<AgentActivationResolutionTicket, ProtocolError> {
    AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: "activation-ticket-invalid-1".to_owned(),
        activation_request_id: RequestId::new("activation-request-invalid-1")?,
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "activation-connection-invalid-1".to_owned(),
        state_fence: StateFence::new(test_epoch(7)?, ResourceGeneration::new(11)?),
        kernel_deadline_unix_ms: 10_000,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
}

fn ticket_bytes(ticket: &AgentActivationResolutionTicket) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(ticket).map_err(|error| ProtocolError::Json(error.to_string()))
}

/// The same ticket bytes with a corrupted digest: JSON parses, validation fails.
fn digest_corrupted_bytes() -> Result<Vec<u8>, ProtocolError> {
    let ticket = valid_ticket()?;
    let mut value =
        serde_json::to_value(&ticket).map_err(|error| ProtocolError::Json(error.to_string()))?;
    value["ticket_sha256"] = Value::String("0".repeat(64));
    serde_json::to_vec(&value).map_err(|error| ProtocolError::Json(error.to_string()))
}

#[test]
fn raw_bytes_are_preserved_verbatim() -> Result<(), ProtocolError> {
    let raw = digest_corrupted_bytes()?;
    let artifact = AgentActivationInvalidTicket::rejected(
        raw.clone(),
        "ticket digest mismatch",
        OBSERVED_AT_UNIX_MS,
    )?;
    assert_eq!(artifact.ticket_bytes, raw);
    assert_eq!(
        artifact.ticket_bytes_sha256,
        eliot_contracts::sha256_hex(&raw)
    );
    artifact.validate()?;
    Ok(())
}

#[test]
fn ticket_identity_is_preserved() -> Result<(), ProtocolError> {
    let raw = digest_corrupted_bytes()?;
    let artifact =
        AgentActivationInvalidTicket::rejected(raw, "ticket digest mismatch", OBSERVED_AT_UNIX_MS)?;
    assert_eq!(artifact.ticket_id, "activation-ticket-invalid-1");
    artifact.validate()?;
    Ok(())
}

#[test]
fn unparseable_bytes_preserve_bytes_with_unknown_identity() -> Result<(), ProtocolError> {
    let raw = b"not-json{".to_vec();
    let artifact = AgentActivationInvalidTicket::rejected(
        raw.clone(),
        "ticket unparseable",
        OBSERVED_AT_UNIX_MS,
    )?;
    assert_eq!(artifact.ticket_bytes, raw);
    assert_eq!(artifact.ticket_id, UNKNOWN_INVALID_TICKET_ID);
    artifact.validate()?;
    Ok(())
}

#[test]
fn construction_is_pre_governor_with_no_governor_surface() -> Result<(), ProtocolError> {
    // The constructor takes only claimed bytes, a reason, and a clock: no
    // Governor handle enters, and validation needs none either.
    let raw = digest_corrupted_bytes()?;
    let artifact =
        AgentActivationInvalidTicket::rejected(raw, "ticket digest mismatch", OBSERVED_AT_UNIX_MS)?;
    artifact.validate()?;
    let encoded =
        serde_json::to_string(&artifact).map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert!(!encoded.to_lowercase().contains("governor"));
    Ok(())
}

#[test]
fn no_digest_bound_result_can_be_built_from_the_invalid_ticket() -> Result<(), ProtocolError> {
    // The corrupted bytes still decode to the ticket shape, so the
    // digest-bound constructor is reachable but must refuse.
    let raw = digest_corrupted_bytes()?;
    let ticket: AgentActivationResolutionTicket =
        serde_json::from_slice(&raw).map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert!(ticket.validate().is_err());
    let attempt = AgentActivationResolutionResult::new(
        &ticket,
        OBSERVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "daemon.mapping-failure:RESOLVED:recovery".to_owned(),
        },
    );
    assert!(attempt.is_err());
    // The terminal artifact is the only constructible outcome for these bytes.
    assert!(
        AgentActivationInvalidTicket::rejected(raw, "ticket digest mismatch", OBSERVED_AT_UNIX_MS)
            .is_ok()
    );
    Ok(())
}

#[test]
fn invalid_ticket_is_terminal_with_no_retry_surface() -> Result<(), ProtocolError> {
    let raw = digest_corrupted_bytes()?;
    let artifact =
        AgentActivationInvalidTicket::rejected(raw, "ticket digest mismatch", OBSERVED_AT_UNIX_MS)?;
    assert!(artifact.is_terminal());
    let encoded: Value =
        serde_json::to_value(&artifact).map_err(|error| ProtocolError::Json(error.to_string()))?;
    let object = encoded.as_object().ok_or(ProtocolError::InvalidField {
        field: "agent_activation_invalid_ticket.encoding",
        reason: "must serialize as a JSON object",
    })?;
    for forbidden in [
        "disposition",
        "result_sha256",
        "retry",
        "not_before_unix_ms",
        "recovery_handle",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "must not carry {forbidden}"
        );
    }
    Ok(())
}

#[test]
fn invalid_ticket_is_distinct_from_digest_bound_results() -> Result<(), ProtocolError> {
    assert_ne!(
        AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID,
        AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID
    );
    let raw = digest_corrupted_bytes()?;
    let artifact =
        AgentActivationInvalidTicket::rejected(raw, "ticket digest mismatch", OBSERVED_AT_UNIX_MS)?;
    let encoded =
        serde_json::to_value(&artifact).map_err(|error| ProtocolError::Json(error.to_string()))?;
    // Neither direction trial-decodes: the shapes are structurally disjoint.
    assert!(serde_json::from_value::<AgentActivationResolutionResult>(encoded).is_err());
    let ticket = valid_ticket()?;
    let result = AgentActivationResolutionResult::new(
        &ticket,
        OBSERVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "daemon.mapping-failure:RESOLVED:recovery".to_owned(),
        },
    )?;
    let result_encoded =
        serde_json::to_value(&result).map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert!(serde_json::from_value::<AgentActivationInvalidTicket>(result_encoded).is_err());
    Ok(())
}

#[test]
fn artifact_round_trips_and_rejects_tampering() -> Result<(), ProtocolError> {
    let raw = ticket_bytes(&valid_ticket()?)?;
    let artifact =
        AgentActivationInvalidTicket::rejected(raw, "ticket fence mismatch", OBSERVED_AT_UNIX_MS)?;
    let encoded =
        serde_json::to_vec(&artifact).map_err(|error| ProtocolError::Json(error.to_string()))?;
    let decoded: AgentActivationInvalidTicket =
        serde_json::from_slice(&encoded).map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert_eq!(decoded, artifact);
    decoded.validate()?;

    let mut tampered =
        serde_json::to_value(&artifact).map_err(|error| ProtocolError::Json(error.to_string()))?;
    tampered["reason"] = Value::String("rewritten".to_owned());
    let tampered: AgentActivationInvalidTicket =
        serde_json::from_value(tampered).map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert!(tampered.validate().is_err());
    Ok(())
}

#[test]
fn fail_closed_inputs_are_rejected() -> Result<(), ProtocolError> {
    assert!(
        AgentActivationInvalidTicket::rejected(
            Vec::new(),
            "empty bytes carry no identity",
            OBSERVED_AT_UNIX_MS
        )
        .is_err()
    );
    assert!(
        AgentActivationInvalidTicket::rejected(
            digest_corrupted_bytes()?,
            "ticket digest mismatch",
            0
        )
        .is_err()
    );
    assert!(
        AgentActivationInvalidTicket::rejected(digest_corrupted_bytes()?, "", OBSERVED_AT_UNIX_MS)
            .is_err()
    );
    assert!(
        AgentActivationInvalidTicket::rejected(
            digest_corrupted_bytes()?,
            "x".repeat(513),
            OBSERVED_AT_UNIX_MS
        )
        .is_err()
    );
    Ok(())
}
