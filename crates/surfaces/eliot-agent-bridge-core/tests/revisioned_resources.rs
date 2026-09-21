//! Issue 1941 acceptance proof: revisioned resources stay handle-first and
//! truncated tool results never satisfy complete evidence.

use eliot_agent_bridge_core::{
    ActivationPortOutcome, ActivationPortResult, AgentBridgeCore, AttachRequest, BridgeError,
    ConnectionId, CursorPolicy, DeliveryStatus, DemandId, Generation, HostActivationPort,
    MAX_PREVIEW_BYTES, PrincipalId, ProviderFailure, ProviderReadiness, ResourceKind, ResourceUri,
    SessionId, TaskId, WorkUnitId,
};
use eliot_contracts::{EpochId, EpochLineageId};
use std::num::NonZeroU64;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

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

fn large_evidence_bytes() -> Vec<u8> {
    let finding = r#"{"check":"evidence-item","verdict":"holds","detail":""#;
    let mut content = String::from("[");
    while content.len() < MAX_PREVIEW_BYTES * 4 {
        content.push_str(finding);
        content.push_str(&"x".repeat(64));
        content.push_str(r#""},"#);
    }
    content.push(']');
    content.into_bytes()
}

#[test]
fn large_evidence_returns_bounded_preview_plus_handle_and_expands_immutable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bridge = attached_bridge()?;
    let content = large_evidence_bytes();
    assert!(content.len() > MAX_PREVIEW_BYTES);

    let view = bridge.publish_evidence(content.clone())?;

    assert_eq!(view.kind(), ResourceKind::Evidence);
    assert!(
        view.handle()
            .uri()
            .as_str()
            .starts_with("eliot://evidence/")
    );
    assert!(view.preview().len() <= MAX_PREVIEW_BYTES);
    assert!(view.is_truncated());
    assert_eq!(view.total_bytes(), content.len());
    assert_eq!(view.preview(), &content[..view.preview().len()]);

    let expanded = bridge.expand_resource(view.handle())?;
    assert_eq!(expanded, content);
    Ok(())
}

#[test]
fn token_truncated_tool_result_is_receipted_and_rejected_as_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let bridge = attached_bridge()?;
    let source = ResourceUri::parse("eliot://evidence/source")?;
    let result_bytes = vec![b'r'; 3000];
    let tokens_rendered = 750_u64;

    let receipt = bridge.project_tool_result(
        &result_bytes,
        source,
        tokens_rendered,
        DeliveryStatus::Truncated,
    )?;

    assert_eq!(receipt.delivery(), DeliveryStatus::Truncated);
    assert_eq!(receipt.bytes_rendered(), result_bytes.len());
    assert_eq!(receipt.tokens_rendered(), tokens_rendered);
    assert_eq!(receipt.result_digest().len(), 64);

    let rejected = receipt.check_complete_evidence();
    assert!(matches!(
        rejected,
        Err(BridgeError::IncompleteDelivery {
            delivery: DeliveryStatus::Truncated
        })
    ));

    let full = bridge.project_tool_result(
        &result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        tokens_rendered,
        DeliveryStatus::Full,
    )?;
    assert!(full.check_complete_evidence().is_ok());
    Ok(())
}

#[test]
fn unknown_handles_and_rewritten_immutable_uris_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    use serde_json::json;

    let mut bridge = attached_bridge()?;

    let view = bridge.publish_evidence(b"first-bytes".to_vec())?;
    let unknown: eliot_agent_bridge_core::ResourceHandle = serde_json::from_value(json!({
        "uri": "eliot://evidence/3f79bb7b435b05321651daefd374cd5c5cde7ef75ffdbd045c55a852a736f",
        "digest": "3f79bb7b435b05321651daefd374cd5c5cde7ef75ffdbd045c55a852a736f"
    }))?;
    assert!(matches!(
        bridge.expand_resource(&unknown),
        Err(BridgeError::UnknownResource { .. })
    ));

    let tampered: eliot_agent_bridge_core::ResourceHandle = serde_json::from_value(json!({
        "uri": view.handle().uri().as_str(),
        "digest": "0000000000000000000000000000000000000000000000000000000000000000"
    }))?;
    assert!(matches!(
        bridge.expand_resource(&tampered),
        Err(BridgeError::ResourceDigestMismatch)
    ));

    let uri = ResourceUri::parse("eliot://report/quarterly")?;
    bridge.publish_resource(&uri, b"v1".to_vec())?;
    assert!(matches!(
        bridge.publish_resource(&uri, b"v2".to_vec()),
        Err(BridgeError::ResourceImmutableConflict)
    ));

    assert!(ResourceUri::parse("eliot://task/t-1").is_err());
    Ok(())
}
