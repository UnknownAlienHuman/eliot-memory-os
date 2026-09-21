//! C6 admitted-route byte-bound token measurement proof: an attested
//! count passes through the versioned measurement wire unaltered only under
//! full verification (version, bounds, self digest, admission linkage,
//! matched route, exact evidence bytes); every missing axis withholds
//! honestly, and a route that emits nothing stays unavailable.

use eliot_agent_api::{
    AdmittedRouteReceipt, CONTRACT_VERSION, CandidateSelectionDisposition, ClockReading,
    EventCursor, ExecutionOutcome, ExecutionUnit, NativeSession, NativeSessionLocator,
    PhysicalRouteObservationReceipt, PolicyRevision, ProviderExecutionBinding, RequestId,
    ResourceGeneration, RouteObservationState, RouteSelectionCandidate, StateFence, UsageReceipt,
    candidate_digest_for, route_divergence_fields,
};
use eliot_agent_bridge_core::{
    ActivationPortOutcome, ActivationPortResult, AgentBridgeCore, AttachRequest, BridgeError,
    ConnectionId, CursorPolicy, DeliveryStatus, DemandId, Generation, HostActivationPort,
    MAX_MEASUREMENT_WIRE_BYTES, PrincipalId, ProviderFailure, ProviderReadiness, ResourceUri,
    RouteFingerprint, SessionId, TOKEN_MEASUREMENT_VERSION, TaskId, TokenMeasurementPayload,
    UnmeasuredReason, WorkUnitId,
};
use eliot_contracts::{EpochId, EpochLineageId};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(test_epoch(1), ResourceGeneration::new(1)?))
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

fn bridge(active: bool) -> Result<AgentBridgeCore, Box<dyn std::error::Error>> {
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
    if active {
        bridge.attach(AttachRequest::managed(
            DemandId::new("demand-1")?,
            ConnectionId::new("connection-1")?,
        ))?;
    }
    Ok(bridge)
}

fn digest(value: &str) -> String {
    value.to_owned()
}

fn test_route() -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
    let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let route: RouteFingerprint = serde_json::from_value(json!({
        "host_family": "test-host",
        "adapter": "test-adapter",
        "protocol_transport": "test-transport",
        "runtime_hash": hex,
        "adapter_hash": hex,
        "provider": "test-provider",
        "model": "test-model",
        "auth_billing": "test-billing",
        "serializer_hash": hex,
        "tool_semantics_hash": hex,
        "reasoning_mode": "test-reasoning",
        "continuation_behavior": "test-continuation",
        "feature_flags_hash": hex,
    }))?;
    Ok(route)
}

fn lease(value: &str) -> Result<eliot_agent_api::WorkLeaseId, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": value,
    }))?)
}

fn binding(
    route: &RouteFingerprint,
    fence: &StateFence,
) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
    Ok(ProviderExecutionBinding {
        attempt_id: eliot_agent_api::AgentAttemptId::new("attempt-1")?,
        lease_id: lease("lease-1")?,
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        route: route.clone(),
        session_id: None,
        provider_scope_ref: "scope:test".to_owned(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
        execution_unit: ExecutionUnit::new("test-provider", "unit-1")?,
        start_request_id: RequestId::new("req-1")?,
        start_request_sha256: sha256_hex(b"req-1"),
    })
}

fn admission(
    decision: &str,
    route: &RouteFingerprint,
    fence: &StateFence,
) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
    let candidate = RouteSelectionCandidate {
        capability: "test-capability".to_owned(),
        query_intent: "test-intent".to_owned(),
        scope_ref: "scope:test".to_owned(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![route.clone()],
        selected: Some(route.clone()),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".to_owned()],
    };
    candidate.validate()?;
    let candidate_digest = candidate_digest_for(&candidate)?;
    let route_json = serde_json::to_value(route)?;
    let mut receipt: AdmittedRouteReceipt = serde_json::from_value(json!({
        "schema_version": CONTRACT_VERSION,
        "decision_id": decision,
        "candidate_digest": candidate_digest.as_str(),
        "attempt_id": "attempt-1",
        "lease_id": {"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"},
        "state_fence": {
            "authority_epoch": {"lineage_id": TEST_LINEAGE_A, "sequence": 1},
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null,
        },
        "runtime_generation": 1,
        "policy_revision": 3,
        "requested_route": route_json,
        "selected_route": route_json,
        "no_route": null,
        "evidence_refs": ["evidence-1"],
        "proof_ceiling": "CANDIDATE_ARTIFACT",
        "self_digest": digest(
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    }))?;
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    assert_eq!(receipt.state_fence, *fence);
    Ok(receipt)
}

fn observation(
    route: &RouteFingerprint,
    binding: &ProviderExecutionBinding,
    admission: &AdmittedRouteReceipt,
    state: RouteObservationState,
    observed: Option<RouteFingerprint>,
    evidence_digest: Option<String>,
) -> Result<PhysicalRouteObservationReceipt, Box<dyn std::error::Error>> {
    let (diverged_fields, unobserved_reason, recovery_ref) = match state {
        RouteObservationState::Matched => (Vec::new(), None, None),
        RouteObservationState::Diverged => {
            let seen = observed.clone().expect("diverged needs observed");
            (
                route_divergence_fields(route, &seen),
                None,
                Some("quarantine-diverged".to_owned()),
            )
        }
        RouteObservationState::Unobserved => (
            Vec::new(),
            Some("route not observed on this delivery".to_owned()),
            None,
        ),
    };
    let (raw_evidence_digest, raw_evidence_ref) = match evidence_digest {
        Some(hex) => (
            Some(serde_json::from_value::<eliot_agent_api::LowercaseSha256>(
                serde_json::Value::String(hex),
            )?),
            Some("tool-result:invoke-1".to_owned()),
        ),
        None => (None, None),
    };
    let mut receipt = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: eliot_agent_api::AgentAttemptId::new("attempt-1")?,
        state_fence: fence()?,
        runtime_generation: ResourceGeneration::new(1)?,
        admitted_route_digest: admission.self_digest.clone(),
        binding: binding.clone(),
        requested_route: route.clone(),
        observed_route: observed,
        route_state: state,
        diverged_fields,
        execution_outcome: ExecutionOutcome::Observed,
        request_digest: serde_json::from_value(serde_json::Value::String(sha256_hex(
            b"request-1",
        )))?,
        translation_digest: None,
        raw_evidence_digest,
        raw_evidence_ref,
        // Turn-level usage is the adapter's own record and is never read as
        // a result cost: the wire attestation below carries the count.
        usage: UsageReceipt {
            input_tokens: Some(10),
            output_tokens: Some(99),
            cost_microunits: None,
            quota: eliot_agent_api::QuotaKnowledge::Unknown,
        },
        started: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading {
            valid_time_ms: Some(2_000),
            known_time_ms: Some(2_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        event_cursor: EventCursor::new("cursor-1")?,
        event_sequence: 1,
        cancellation: None,
        unobserved_reason,
        recovery_ref,
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: serde_json::from_value(serde_json::Value::String(digest(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )))?,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    receipt.validate_against(binding, admission)?;
    Ok(receipt)
}

fn payload(
    route: &RouteFingerprint,
    binding: &ProviderExecutionBinding,
    admission: &AdmittedRouteReceipt,
    state: RouteObservationState,
    observed: Option<RouteFingerprint>,
    evidence_digest: Option<String>,
    tokens: u64,
) -> Result<TokenMeasurementPayload, Box<dyn std::error::Error>> {
    let seen = observation(route, binding, admission, state, observed, evidence_digest)?;
    let result_digest = seen.raw_evidence_digest.as_ref().map_or_else(
        || sha256_hex(b"no-evidence-bound"),
        |bound| bound.as_str().to_owned(),
    );
    Ok(TokenMeasurementPayload {
        contract_version: TOKEN_MEASUREMENT_VERSION,
        observation: seen,
        result_digest,
        tokens,
    })
}

fn live_set() -> Result<
    (
        RouteFingerprint,
        StateFence,
        ProviderExecutionBinding,
        AdmittedRouteReceipt,
    ),
    Box<dyn std::error::Error>,
> {
    let route = test_route()?;
    let fence = fence()?;
    let bound = binding(&route, &fence)?;
    let admitted = admission("decision-1", &route, &fence)?;
    Ok((route, fence, bound, admitted))
}

#[test]
fn wire_round_trip_projects_attested_count_unaltered() -> TestResult {
    let bridge = bridge(true)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"exact delivered tool result bytes";
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(result_bytes)),
        20,
    )?;
    assert_eq!(seen.observation.usage.output_tokens, Some(99));
    let wire = seen.encode()?;
    assert!(wire.len() <= MAX_MEASUREMENT_WIRE_BYTES);
    let decoded = TokenMeasurementPayload::decode(&wire)?;

    let receipt = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&decoded),
        &admitted,
        &bound,
        DeliveryStatus::Full,
    )?;

    // The attested count (20) passes through unaltered: the receipt's
    // turn-level usage (99) is never substituted, summed, or read.
    assert_eq!(receipt.tokens_rendered(), 20);
    assert_eq!(receipt.result_digest(), sha256_hex(result_bytes));
    assert_eq!(receipt.bytes_rendered(), result_bytes.len());
    assert!(receipt.check_complete_evidence().is_ok());
    Ok(())
}

#[test]
fn produced_truncated_tool_result_keeps_cost_but_fails_evidence_gate() -> TestResult {
    let bridge = bridge(true)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"truncated delivered tool result bytes";
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(result_bytes)),
        17,
    )?;

    let receipt = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &admitted,
        &bound,
        DeliveryStatus::Truncated,
    )?;

    assert_eq!(receipt.tokens_rendered(), 17);
    assert!(matches!(
        receipt.check_complete_evidence(),
        Err(BridgeError::IncompleteDelivery {
            delivery: DeliveryStatus::Truncated
        })
    ));
    Ok(())
}

#[test]
fn tampered_evidence_digest_withholds_without_misattribution() -> TestResult {
    let bridge = bridge(true)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"these exact bytes were delivered";
    let mut seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(result_bytes)),
        99,
    )?;
    seen.result_digest = sha256_hex(b"different bytes were evidenced");

    let withheld = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &admitted,
        &bound,
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
fn other_bytes_withhold_against_honest_evidence() -> TestResult {
    let bridge = bridge(true)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(b"evidenced bytes")),
        99,
    )?;

    let withheld = bridge.project_produced_tool_result(
        b"different delivered bytes",
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &admitted,
        &bound,
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
fn wrong_wire_version_is_rejected_at_decode() -> TestResult {
    let (route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"exact delivered tool result bytes";
    let mut seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(result_bytes)),
        20,
    )?;
    seen.contract_version = TOKEN_MEASUREMENT_VERSION + 1;
    let wire = serde_json::to_vec(&seen)?;

    let rejected = TokenMeasurementPayload::decode(&wire);

    assert!(matches!(rejected, Err(BridgeError::InvalidContract { .. })));
    Ok(())
}

#[test]
fn oversize_wire_is_rejected_before_parsing() -> TestResult {
    let big = vec![0u8; MAX_MEASUREMENT_WIRE_BYTES + 1];

    let rejected = TokenMeasurementPayload::decode(&big);

    assert!(matches!(rejected, Err(BridgeError::InvalidContract { .. })));
    Ok(())
}

#[test]
fn unobserved_route_withholds_despite_attested_count() -> TestResult {
    let bridge = bridge(true)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"result bytes with no observed route";
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Unobserved,
        None,
        Some(sha256_hex(result_bytes)),
        30,
    )?;

    let withheld = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &admitted,
        &bound,
        DeliveryStatus::Full,
    );

    assert!(matches!(
        withheld,
        Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::RouteUnobserved
        })
    ));
    Ok(())
}

#[test]
fn diverged_route_withholds_despite_attested_count() -> TestResult {
    let bridge = bridge(true)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let mut other = route.clone();
    other.model = "other-model".to_owned();
    let result_bytes = b"result bytes from a diverged route";
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Diverged,
        Some(other),
        Some(sha256_hex(result_bytes)),
        30,
    )?;

    let withheld = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &admitted,
        &bound,
        DeliveryStatus::Full,
    );

    assert!(matches!(
        withheld,
        Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::RouteDiverged
        })
    ));
    Ok(())
}

#[test]
fn observation_for_another_admission_withholds() -> TestResult {
    let bridge = bridge(true)?;
    let (route, fence, bound, admitted) = live_set()?;
    let other_admission = admission("decision-2", &route, &fence)?;
    assert_ne!(
        admitted.self_digest.as_str(),
        other_admission.self_digest.as_str()
    );
    let result_bytes = b"result bytes bound to the first admission";
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(result_bytes)),
        20,
    )?;

    let withheld = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &other_admission,
        &bound,
        DeliveryStatus::Full,
    );

    assert!(matches!(
        withheld,
        Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::AdmissionMismatch
        })
    ));
    Ok(())
}

#[test]
fn missing_payload_is_honest_unavailable_not_zero() -> TestResult {
    let bridge = bridge(true)?;
    let (_route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"result bytes the route never measured";

    let withheld = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        None,
        &admitted,
        &bound,
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
fn detached_core_denies_even_wire_bound_production() -> TestResult {
    let bridge = bridge(false)?;
    let (route, _fence, bound, admitted) = live_set()?;
    let result_bytes = b"exact delivered tool result bytes";
    let seen = payload(
        &route,
        &bound,
        &admitted,
        RouteObservationState::Matched,
        Some(route.clone()),
        Some(sha256_hex(result_bytes)),
        20,
    )?;

    let denied = bridge.project_produced_tool_result(
        result_bytes,
        ResourceUri::parse("eliot://evidence/source")?,
        Some(&seen),
        &admitted,
        &bound,
        DeliveryStatus::Full,
    );

    assert!(matches!(denied, Err(BridgeError::NotAttached)));
    Ok(())
}

#[test]
fn invalid_route_identity_is_rejected_before_attestation() -> TestResult {
    use eliot_agent_bridge_core::RouteTokenizer;
    let mut route = test_route()?;
    route.provider = "   ".to_owned();
    assert!(matches!(
        RouteTokenizer::new(route),
        Err(BridgeError::InvalidContract { .. })
    ));
    Ok(())
}
