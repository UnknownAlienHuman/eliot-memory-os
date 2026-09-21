//! C6 route-aware token measurement proof: measured observations project
//! exact costs into tool-result receipts, while missing or misbound evidence
//! withholds projection instead of estimating.

use eliot_agent_bridge_core::{
    ActivationPortOutcome, ActivationPortResult, AgentBridgeCore, AttachRequest, BridgeError,
    ConnectionId, CursorPolicy, DeliveryStatus, DemandId, Generation, HostActivationPort,
    PrincipalId, ProviderFailure, ProviderReadiness, ResourceUri, RouteFingerprint,
    RouteTokenObservation, RouteTokenizer, SessionId, TaskId, UnmeasuredReason, WorkUnitId,
};
use eliot_contracts::{EpochId, EpochLineageId};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const TEST_TOKENIZER_HASH: &str =
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

struct StaticHost {
    result: ActivationPortResult,
}

impl HostActivationPort for StaticHost {
    fn activate(
        &mut self,
        _request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
    }
}

fn attached_bridge() -> Result<AgentBridgeCore, Box<dyn std::error::Error>> {
    let generation = Generation::new(1)?;
    let fence = eliot_agent_bridge_core::FencingToken::new(
        test_epoch(1),
        Generation::new(1)?,
        "fence-1".to_owned(),
    )?;
    let result = ActivationPortResult::authenticated(
        PrincipalId::new("principal-1")?,
        SessionId::new("session-1")?,
        generation,
        fence,
        TaskId::new("task-1")?,
        WorkUnitId::new("work-unit-1")?,
        "scope-1",
        "task-revision-1",
        "plan-1",
        "plan-revision-1",
    )?;
    let mut bridge = AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(StaticHost { result })),
        None,
        CursorPolicy::new(
            eliot_agent_bridge_core::AckPhase::Durable,
            eliot_agent_bridge_core::AckPhase::Normalized,
        )?,
    );
    bridge.attach(AttachRequest::managed(
        DemandId::new("demand-1")?,
        ConnectionId::new("connection-1")?,
    ))?;
    Ok(bridge)
}

fn detached_bridge() -> Result<AgentBridgeCore, Box<dyn std::error::Error>> {
    let generation = Generation::new(1)?;
    let fence = eliot_agent_bridge_core::FencingToken::new(
        test_epoch(1),
        Generation::new(1)?,
        "fence-1".to_owned(),
    )?;
    let result = ActivationPortResult::authenticated(
        PrincipalId::new("principal-1")?,
        SessionId::new("session-1")?,
        generation,
        fence,
        TaskId::new("task-1")?,
        WorkUnitId::new("work-unit-1")?,
        "scope-1",
        "task-revision-1",
        "plan-1",
        "plan-revision-1",
    )?;
    Ok(AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(StaticHost { result })),
        None,
        CursorPolicy::new(
            eliot_agent_bridge_core::AckPhase::Durable,
            eliot_agent_bridge_core::AckPhase::Normalized,
        )?,
    ))
}

fn test_route() -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
    let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let route: RouteFingerprint = serde_json::from_value(json!({
        "host_family": "test-host",
        "adapter": "test-adapter",
        "protocol_transport": "test-transport",
        "runtime_hash": digest,
        "adapter_hash": digest,
        "provider": "test-provider",
        "model": "test-model",
        "auth_billing": "test-billing",
        "serializer_hash": digest,
        "tool_semantics_hash": digest,
        "reasoning_mode": "test-reasoning",
        "continuation_behavior": "test-continuation",
        "feature_flags_hash": digest,
    }))?;
    Ok(route)
}

fn test_tokenizer() -> Result<RouteTokenizer, Box<dyn std::error::Error>> {
    Ok(RouteTokenizer::new(
        test_route()?,
        "test-tokenizer".to_owned(),
        "1.0.0".to_owned(),
        TEST_TOKENIZER_HASH.to_owned(),
    )?)
}

#[test]
fn measured_full_tool_result_projects_exact_owner_observed_cost()
-> Result<(), Box<dyn std::error::Error>> {
    let bridge = attached_bridge()?;
    let result_bytes = b"exact delivered tool result bytes";
    let observation = RouteTokenObservation::new(test_tokenizer()?, sha256_hex(result_bytes), 42)?;

    let receipt = bridge.project_measured_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&observation),
        DeliveryStatus::Full,
    )?;

    assert_eq!(receipt.tokens_rendered(), 42);
    assert_eq!(receipt.result_digest(), sha256_hex(result_bytes));
    assert_eq!(receipt.bytes_rendered(), result_bytes.len());
    assert_eq!(receipt.delivery(), DeliveryStatus::Full);
    assert!(receipt.check_complete_evidence().is_ok());
    Ok(())
}

#[test]
fn measured_truncated_tool_result_keeps_cost_but_fails_evidence_gate()
-> Result<(), Box<dyn std::error::Error>> {
    let bridge = attached_bridge()?;
    let result_bytes = b"truncated delivered tool result bytes";
    let observation = RouteTokenObservation::new(test_tokenizer()?, sha256_hex(result_bytes), 17)?;

    let receipt = bridge.project_measured_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&observation),
        DeliveryStatus::Truncated,
    )?;

    assert_eq!(receipt.tokens_rendered(), 17);
    assert_eq!(receipt.result_digest(), sha256_hex(result_bytes));
    assert!(matches!(
        receipt.check_complete_evidence(),
        Err(BridgeError::IncompleteDelivery {
            delivery: DeliveryStatus::Truncated
        })
    ));
    Ok(())
}

#[test]
fn missing_observation_withholds_projection_without_estimate()
-> Result<(), Box<dyn std::error::Error>> {
    let bridge = attached_bridge()?;
    let result_bytes = b"tool result bytes with no owner observation";

    let withheld = bridge.project_measured_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        None,
        DeliveryStatus::Full,
    );

    assert!(matches!(
        withheld,
        Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::NoObservation
        })
    ));
    Ok(())
}

#[test]
fn observation_for_other_bytes_withholds_projection_without_misattribution()
-> Result<(), Box<dyn std::error::Error>> {
    let bridge = attached_bridge()?;
    let result_bytes = b"these exact bytes were delivered";
    let other_bytes = b"the observation was reported for different bytes";
    let observation = RouteTokenObservation::new(test_tokenizer()?, sha256_hex(other_bytes), 99)?;

    let withheld = bridge.project_measured_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&observation),
        DeliveryStatus::Full,
    );

    assert!(matches!(
        withheld,
        Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::DigestMismatch
        })
    ));
    Ok(())
}

#[test]
fn invalid_tokenizer_identity_is_rejected_before_measurement()
-> Result<(), Box<dyn std::error::Error>> {
    let blank_id = RouteTokenizer::new(
        test_route()?,
        "   ".to_owned(),
        "1.0.0".to_owned(),
        TEST_TOKENIZER_HASH.to_owned(),
    );
    assert!(matches!(blank_id, Err(BridgeError::InvalidContract { .. })));

    let bad_hash = RouteTokenizer::new(
        test_route()?,
        "test-tokenizer".to_owned(),
        "1.0.0".to_owned(),
        "NOT-A-DIGEST".to_owned(),
    );
    assert!(matches!(bad_hash, Err(BridgeError::InvalidContract { .. })));
    Ok(())
}

#[test]
fn detached_core_denies_even_digest_bound_measurement() -> Result<(), Box<dyn std::error::Error>> {
    let bridge = detached_bridge()?;
    let result_bytes = b"exact delivered tool result bytes";
    let observation = RouteTokenObservation::new(test_tokenizer()?, sha256_hex(result_bytes), 42)?;

    let denied = bridge.project_measured_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&observation),
        DeliveryStatus::Full,
    );

    assert!(matches!(denied, Err(BridgeError::NotAttached)));
    Ok(())
}
