//! Daemon claim-arm wiring proof for issue #202 (owner decision ii).
//!
//! The protocol-owned `AgentActivationInvalidTicket` terminal artifact merged
//! via PR #2071 is wired here in `bins/eliotd` only: the claim arm
//! classifies validate-first; on an invalid ticket it constructs the terminal
//! artifact with no Governor read, idles the flight, and continues the loop.
//! No typed-result submit, no reconcile of typed results, no retry of the
//! rejected revision. Every property below runs through the real production
//! helpers (`eliotd::classify_claimed_ticket_value`,
//! `eliotd::terminal_for_invalid_ticket`, and the protocol constructor) with
//! no Governor object in scope: pre-Governor callability is proved by
//! construction, not by prose.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
use eliot_protocol::{
    AgentActivationInvalidTicket, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolutionTicket,
};
use eliotd::{classify_claimed_ticket_value, terminal_for_invalid_ticket, ActivationClaim};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const OBSERVED_AT_UNIX_MS: u64 = 9_000;

fn test_epoch(sequence: u64) -> TestResult<EpochId> {
    let lineage = EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
    let sequence = NonZeroU64::new(sequence).ok_or("non-zero test sequence")?;
    EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}").into())
}

fn test_fence() -> TestResult<StateFence> {
    Ok(StateFence::new(
        test_epoch(7)?,
        ResourceGeneration::new(11).map_err(|error| format!("generation: {error}"))?,
    ))
}

fn valid_ticket() -> TestResult<AgentActivationResolutionTicket> {
    AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: "activation-ticket-202-1".to_owned(),
        activation_request_id: RequestId::new("activation-request-202-1")
            .map_err(|error| format!("request id: {error}"))?,
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "activation-connection-202-1".to_owned(),
        state_fence: test_fence()?,
        kernel_deadline_unix_ms: 10_000,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| format!("digest: {error}").into())
}

fn digest_corrupted_value() -> TestResult<serde_json::Value> {
    let ticket = valid_ticket()?;
    let mut value = serde_json::to_value(&ticket).map_err(|error| format!("encode: {error}"))?;
    value["ticket_sha256"] = serde_json::Value::String("0".repeat(64));
    Ok(value)
}

fn manifest_source(relative: &str) -> TestResult<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    std::fs::read_to_string(&path).map_err(|error| format!("read {path}: {error}").into())
}

#[test]
fn empty_null_claim_idles_without_artifact() -> TestResult {
    match classify_claimed_ticket_value(&serde_json::Value::Null) {
        ActivationClaim::Empty => Ok(()),
        other => Err(format!("null claim must be Empty, got {other:?}").into()),
    }
}

#[test]
fn valid_claim_passes_through_validated() -> TestResult {
    let ticket = valid_ticket()?;
    let value = serde_json::to_value(&ticket).map_err(|error| format!("encode: {error}"))?;
    match classify_claimed_ticket_value(&value) {
        ActivationClaim::Valid(decoded) => {
            assert_eq!(decoded.ticket_id, ticket.ticket_id);
            decoded
                .validate()
                .map_err(|error| format!("valid claim must validate: {error}"))?;
            Ok(())
        }
        other => Err(format!("valid claim must be Valid, got {other:?}").into()),
    }
}

#[test]
fn digest_corrupted_claim_is_invalid_with_verbatim_bytes() -> TestResult {
    let value = digest_corrupted_value()?;
    let raw = serde_json::to_vec(&value).map_err(|error| format!("raw: {error}"))?;
    match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => {
            assert_eq!(ticket_bytes, raw, "raw bytes must be preserved verbatim");
            assert!(!reason.trim().is_empty(), "reason must be non-blank");
            assert!(reason.len() <= 512, "reason must stay bounded");
            assert!(
                !reason.chars().any(char::is_control),
                "reason must carry no control characters"
            );
            Ok(())
        }
        other => Err(format!("corrupted claim must be Invalid, got {other:?}").into()),
    }
}

#[test]
fn invalid_terminal_constructs_pre_governor_and_validates() -> TestResult {
    // No Governor object exists in this test: construction takes only the
    // preserved bytes, the bounded reason, and the observation clock.
    let value = digest_corrupted_value()?;
    let (raw, reason) = match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => (ticket_bytes, reason),
        other => return Err(format!("expected Invalid, got {other:?}").into()),
    };
    let artifact = terminal_for_invalid_ticket(raw.clone(), &reason, OBSERVED_AT_UNIX_MS)
        .map_err(|error| format!("terminal construction: {error}"))?;
    artifact
        .validate()
        .map_err(|error| format!("terminal must validate: {error}"))?;
    assert!(artifact.is_terminal(), "terminal must always hold");
    assert_eq!(artifact.ticket_id, "activation-ticket-202-1");
    assert_eq!(artifact.ticket_bytes, raw);
    assert_eq!(
        artifact.ticket_bytes_sha256,
        eliot_contracts::sha256_hex(&raw)
    );
    Ok(())
}

#[test]
fn invalid_terminal_carries_no_retry_or_digest_surface() -> TestResult {
    let value = digest_corrupted_value()?;
    let (raw, reason) = match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => (ticket_bytes, reason),
        other => return Err(format!("expected Invalid, got {other:?}").into()),
    };
    let artifact = terminal_for_invalid_ticket(raw, &reason, OBSERVED_AT_UNIX_MS)
        .map_err(|error| format!("terminal construction: {error}"))?;
    let encoded: serde_json::Value =
        serde_json::to_value(&artifact).map_err(|error| format!("encode: {error}"))?;
    let object = encoded
        .as_object()
        .ok_or("terminal must serialize as a JSON object")?;
    for forbidden in [
        "disposition",
        "result_sha256",
        "retry",
        "not_before_unix_ms",
        "recovery_handle",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "terminal must not carry {forbidden}"
        );
    }
    assert!(
        serde_json::from_value::<AgentActivationResolutionResult>(encoded.clone()).is_err(),
        "terminal must not decode as a digest-bound result"
    );
    Ok(())
}

#[test]
fn digest_bound_result_never_binds_an_invalid_ticket() -> TestResult {
    let value = digest_corrupted_value()?;
    let raw = serde_json::to_vec(&value).map_err(|error| format!("raw: {error}"))?;
    let ticket: AgentActivationResolutionTicket =
        serde_json::from_slice(&raw).map_err(|error| format!("decode: {error}"))?;
    assert!(
        ticket.validate().is_err(),
        "corrupted ticket must not validate"
    );
    let attempt = AgentActivationResolutionResult::new(
        &ticket,
        OBSERVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "daemon.mapping-failure:RESOLVED:recovery".to_owned(),
        },
    );
    assert!(
        attempt.is_err(),
        "no digest-bound result may be built from the invalid ticket"
    );
    let (bytes, reason) = match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => (ticket_bytes, reason),
        other => return Err(format!("expected Invalid, got {other:?}").into()),
    };
    assert!(
        terminal_for_invalid_ticket(bytes, &reason, OBSERVED_AT_UNIX_MS).is_ok(),
        "the terminal artifact is the only constructible outcome"
    );
    Ok(())
}

#[test]
fn wrong_shape_claim_is_invalid_without_governor() -> TestResult {
    let value = serde_json::json!({"ticket_id": 7});
    match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => {
            assert_eq!(
                ticket_bytes,
                serde_json::to_vec(&value).map_err(|error| format!("raw: {error}"))?
            );
            assert!(reason.contains("unparseable"));
            let artifact = terminal_for_invalid_ticket(ticket_bytes, &reason, OBSERVED_AT_UNIX_MS)
                .map_err(|error| format!("terminal: {error}"))?;
            artifact
                .validate()
                .map_err(|error| format!("terminal must validate: {error}"))?;
            Ok(())
        }
        other => Err(format!("wrong-shape claim must be Invalid, got {other:?}").into()),
    }
}

#[test]
fn non_json_bytes_yield_unknown_identity_terminal() -> TestResult {
    let raw = b"not-json{".to_vec();
    let artifact =
        terminal_for_invalid_ticket(raw.clone(), "ticket unparseable", OBSERVED_AT_UNIX_MS)
            .map_err(|error| format!("terminal: {error}"))?;
    assert_eq!(artifact.ticket_bytes, raw);
    assert_eq!(
        artifact.ticket_id,
        eliot_protocol::UNKNOWN_INVALID_TICKET_ID
    );
    artifact
        .validate()
        .map_err(|error| format!("terminal must validate: {error}"))?;
    Ok(())
}

#[test]
fn malformed_wire_and_unknown_version_rejected_before_governor() -> TestResult {
    let mut malformed = valid_ticket()?;
    malformed.wire_id = "eliot.agent.activation.resolution.ticket.malformed".to_owned();
    malformed.ticket_sha256 = malformed
        .compute_digest()
        .map_err(|error| format!("digest: {error}"))?;
    let malformed_value =
        serde_json::to_value(&malformed).map_err(|error| format!("encode: {error}"))?;
    match classify_claimed_ticket_value(&malformed_value) {
        ActivationClaim::Invalid { reason, .. } => assert!(reason.contains("invalid")),
        other => return Err(format!("malformed wire must be Invalid, got {other:?}").into()),
    }

    let mut future = valid_ticket()?;
    future.wire_version = AgentActivationResolutionTicket::CONTRACT_VERSION + 1;
    future.ticket_sha256 = future
        .compute_digest()
        .map_err(|error| format!("digest: {error}"))?;
    let future_value = serde_json::to_value(&future).map_err(|error| format!("encode: {error}"))?;
    match classify_claimed_ticket_value(&future_value) {
        ActivationClaim::Invalid { reason, .. } => assert!(reason.contains("invalid")),
        other => {
            return Err(format!("unknown version must be Invalid, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn tampered_ticket_identity_never_rebinds() -> TestResult {
    let mut ticket = valid_ticket()?;
    ticket.ticket_id = "ticket-tampered".to_owned();
    assert!(
        ticket.validate().is_err(),
        "tampered ticket must not validate"
    );
    let value = serde_json::to_value(&ticket).map_err(|error| format!("encode: {error}"))?;
    match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => {
            let artifact = terminal_for_invalid_ticket(ticket_bytes, &reason, OBSERVED_AT_UNIX_MS)
                .map_err(|error| format!("terminal: {error}"))?;
            assert_eq!(artifact.ticket_id, "ticket-tampered");
            assert!(artifact.is_terminal());
            Ok(())
        }
        other => Err(format!("tampered claim must be Invalid, got {other:?}").into()),
    }
}

#[test]
fn fail_closed_terminal_inputs_are_rejected() -> TestResult {
    let value = digest_corrupted_value()?;
    let raw = serde_json::to_vec(&value).map_err(|error| format!("raw: {error}"))?;
    assert!(
        terminal_for_invalid_ticket(Vec::new(), "ticket invalid", OBSERVED_AT_UNIX_MS).is_err(),
        "empty bytes must not yield a terminal"
    );
    assert!(
        terminal_for_invalid_ticket(raw.clone(), "ticket invalid", 0).is_err(),
        "zero clock must not yield a terminal"
    );
    assert!(
        terminal_for_invalid_ticket(raw.clone(), "", OBSERVED_AT_UNIX_MS).is_err(),
        "blank reason must not yield a terminal"
    );
    assert!(
        terminal_for_invalid_ticket(raw, &"x".repeat(513), OBSERVED_AT_UNIX_MS).is_err(),
        "oversize reason must not yield a terminal"
    );
    let oversize = vec![b'x'; eliot_protocol::MAX_INVALID_TICKET_BYTES + 1];
    assert!(
        terminal_for_invalid_ticket(oversize, "ticket invalid", OBSERVED_AT_UNIX_MS).is_err(),
        "oversize bytes must not yield a terminal"
    );
    Ok(())
}

#[test]
fn invalid_path_wiring_is_terminal_without_submit_reconcile_retry_or_governor() -> TestResult {
    // The invalid arm idles the flight and continues the loop: no
    // typed-result submit, no reconcile of typed results, no retry, and no
    // Governor-backed resolution on that path.
    let runtime = manifest_source("src/daemon_runtime.rs")?;
    let arm_start = runtime
        .find("ActivationClaim::Invalid")
        .ok_or("runtime must handle ActivationClaim::Invalid")?;
    let arm_end = runtime[arm_start..]
        .find("ActivationClaim::Valid")
        .map(|offset| arm_start + offset)
        .ok_or("invalid arm must be followed by the valid-ticket branch")?;
    let arm = &runtime[arm_start..arm_end];
    assert!(
        arm.contains("settle_invalid_claim"),
        "invalid arm must settle through the terminal helper"
    );
    assert!(
        arm.contains("ActivationFlight::Idle"),
        "invalid arm must idle the flight"
    );
    assert!(
        arm.contains("continue"),
        "invalid arm must continue the loop"
    );
    for forbidden in [
        "submit_agent_activation_result",
        "reconcile_agent_activation_result",
        "resolve_agent_activation_v2",
        "terminal_for_invalid_ticket",
        ".governor",
        "GovernorComposition",
    ] {
        assert!(
            !arm.contains(forbidden),
            "invalid arm must not contain {forbidden}"
        );
    }
    assert!(
        !arm.contains("retry"),
        "invalid arm must not retry the rejected revision"
    );

    // The terminal helper itself constructs the artifact with no Governor
    // read, no typed-result submit, no reconcile, and no retry.
    let settle_start = runtime
        .find("fn settle_invalid_claim")
        .ok_or("runtime must define settle_invalid_claim")?;
    let settle_end = runtime[settle_start..]
        .find("\n/// Settled outcome of one local-read poll step")
        .map(|offset| settle_start + offset)
        .ok_or("settle helper must end before the local-read section")?;
    let settle = &runtime[settle_start..settle_end];
    assert!(
        settle.contains("terminal_for_invalid_ticket"),
        "settle helper must construct the terminal artifact"
    );
    assert!(
        settle.contains("is_terminal"),
        "settle helper must keep the terminal marker"
    );
    for forbidden in [
        "submit_agent_activation_result",
        "reconcile_agent_activation_result",
        "resolve_agent_activation_v2",
        ".governor",
        "GovernorComposition",
        "retry",
    ] {
        assert!(
            !settle.contains(forbidden),
            "settle helper must not contain {forbidden}"
        );
    }

    // Validate-first ordering: the invalid classification precedes the first
    // Governor-backed resolution on the claim path.
    let resolve_pos = runtime
        .find("resolve_agent_activation_v2")
        .ok_or("runtime must keep the v2 resolution for valid tickets")?;
    assert!(
        arm_start < resolve_pos,
        "invalid handling must precede Governor-backed resolution"
    );

    // Pre-Governor construction surface: the terminal constructor takes only
    // bytes, reason, and clock -- exercised above with no Governor object in
    // scope -- and stays terminal with no retry directive.
    let value = digest_corrupted_value()?;
    let (raw, reason) = match classify_claimed_ticket_value(&value) {
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => (ticket_bytes, reason),
        other => return Err(format!("expected Invalid, got {other:?}").into()),
    };
    let artifact: AgentActivationInvalidTicket =
        terminal_for_invalid_ticket(raw, &reason, OBSERVED_AT_UNIX_MS)
            .map_err(|error| format!("terminal: {error}"))?;
    assert!(artifact.is_terminal());
    Ok(())
}
