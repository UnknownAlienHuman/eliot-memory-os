//! Route disposition tests for issue #369 S4 (T4 §5.2).
//!
//! Package-local only: no provider, network, credentials, or model execution.
//! Deferred to later slices (see commit body "Deferred cases"): idempotent
//! replay versus conflicting observation, legacy v5 decoder paths, old-wire
//! rejection beyond the result-forgery fixtures, candidate no-route detail,
//! and coordinator intake behavior.

use eliot_agent_api::{
    AdmittedRouteReceipt, AttemptId, CONTRACT_VERSION, CandidateSelectionDisposition, ClockReading,
    ContractError, DecisionId, EpochId, EventCursor, ExecutionOutcome, ExecutionUnit,
    LowercaseSha256, NativeSession, NativeSessionLocator, PhysicalRouteObservationReceipt,
    PolicyRevision, ProofCeiling, ProviderExecutionBinding, QuotaKnowledge, RequestId,
    ResourceGeneration, RouteFingerprint, RouteObservationState, RouteSelectionCandidate,
    StateFence, UsageReceipt, WorkLeaseId, candidate_digest_for,
};
use eliot_contracts::EpochLineageId;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn fixture_digest(value: &str) -> Result<LowercaseSha256, serde_json::Error> {
    serde_json::from_value(serde_json::json!(value))
}

fn zero_digest() -> Result<LowercaseSha256, serde_json::Error> {
    fixture_digest("0000000000000000000000000000000000000000000000000000000000000000")
}

fn route() -> Result<RouteFingerprint, serde_json::Error> {
    Ok(RouteFingerprint {
        host_family: "test-host".into(),
        adapter: "test-adapter".into(),
        protocol_transport: "loopback".into(),
        runtime_hash: fixture_digest(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )?,
        adapter_hash: fixture_digest(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )?,
        provider: "provider".into(),
        model: "model".into(),
        auth_billing: "subscription".into(),
        serializer_hash: fixture_digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?,
        tool_semantics_hash: fixture_digest(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?,
        reasoning_mode: "visible".into(),
        continuation_behavior: "native_resume".into(),
        feature_flags_hash: fixture_digest(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )?,
    })
}

fn diverged_route(base: &RouteFingerprint) -> RouteFingerprint {
    let mut observed = base.clone();
    observed.model = "model-b".to_owned();
    observed
}

fn lease(value: &str) -> Result<WorkLeaseId, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": value,
    }))
}

fn fence() -> Result<StateFence, eliot_contracts::ContractError> {
    Ok(StateFence::new(
        test_epoch(TEST_LINEAGE_A, 1),
        ResourceGeneration::new(1)?,
    ))
}

fn binding(
    attempt: &AttemptId,
    lease_id: &WorkLeaseId,
    route: &RouteFingerprint,
    fence: &StateFence,
) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
    Ok(ProviderExecutionBinding {
        attempt_id: attempt.clone(),
        lease_id: lease_id.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        route: route.clone(),
        session_id: None,
        provider_scope_ref: "scope:test".into(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
        execution_unit: ExecutionUnit::new("test-provider", "unit-1")?,
        start_request_id: RequestId::new("req-1")?,
        start_request_sha256: eliot_contracts::sha256_hex(b"req-1"),
    })
}

fn admission(
    decision: &str,
    attempt: &AttemptId,
    lease_id: &WorkLeaseId,
    route: &RouteFingerprint,
    fence: &StateFence,
) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
    let candidate = RouteSelectionCandidate {
        capability: "test-capability".into(),
        query_intent: "test-intent".into(),
        scope_ref: "scope:test".into(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![route.clone()],
        selected: Some(route.clone()),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".into()],
    };
    candidate.validate()?;
    let mut receipt = AdmittedRouteReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new(decision)?,
        candidate_digest: candidate_digest_for(&candidate)?,
        attempt_id: attempt.clone(),
        lease_id: lease_id.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        policy_revision: PolicyRevision::new(3)?,
        requested_route: route.clone(),
        selected_route: Some(route.clone()),
        no_route: None,
        evidence_refs: vec!["evidence-1".into()],
        proof_ceiling: ProofCeiling::CandidateArtifact,
        self_digest: zero_digest()?,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    Ok(receipt)
}

fn known_clock(valid_ms: i64, known_ms: i64) -> ClockReading {
    ClockReading {
        valid_time_ms: Some(valid_ms),
        known_time_ms: Some(known_ms),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn seal(
    mut observation: PhysicalRouteObservationReceipt,
) -> Result<PhysicalRouteObservationReceipt, serde_json::Error> {
    observation.self_digest = observation.compute_digest()?;
    Ok(observation)
}

fn base_observation(
    attempt: &AttemptId,
    route: &RouteFingerprint,
    fence: &StateFence,
    admission: &AdmittedRouteReceipt,
    binding: &ProviderExecutionBinding,
) -> Result<PhysicalRouteObservationReceipt, Box<dyn std::error::Error>> {
    Ok(PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: attempt.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        admitted_route_digest: admission.self_digest.clone(),
        binding: binding.clone(),
        requested_route: route.clone(),
        observed_route: Some(route.clone()),
        route_state: RouteObservationState::Matched,
        diverged_fields: Vec::new(),
        execution_outcome: ExecutionOutcome::Observed,
        request_digest: fixture_digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?,
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: UsageReceipt {
            input_tokens: None,
            output_tokens: None,
            cost_microunits: None,
            quota: QuotaKnowledge::Unknown,
        },
        started: known_clock(1_000, 1_001),
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: known_clock(2_000, 2_001),
        event_cursor: EventCursor::new("cursor-1")?,
        event_sequence: 1,
        cancellation: None,
        unobserved_reason: None,
        recovery_ref: None,
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: zero_digest()?,
    })
}

#[test]
fn matched_observation_preserves_both_fingerprints() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-matched-1")?;
    let lease_id = lease("lease-matched-1")?;
    let fence = fence()?;
    let admission = admission("decision-matched-1", &attempt, &lease_id, &route, &fence)?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let observation = seal(base_observation(
        &attempt, &route, &fence, &admission, &binding,
    )?)?;
    observation.validate()?;
    observation.validate_against(&binding, &admission)?;
    assert_eq!(observation.route_state, RouteObservationState::Matched);
    assert_eq!(observation.observed_route.as_ref(), Some(&route));
    assert_eq!(observation.requested_route, route);
    assert!(observation.diverged_fields.is_empty());
    Ok(())
}

#[test]
fn diverged_observation_preserves_both_fingerprints_and_diff() -> TestResult {
    let route = route()?;
    let observed = diverged_route(&route);
    assert_ne!(observed, route);
    let attempt = AttemptId::new("attempt-diverged-1")?;
    let lease_id = lease("lease-diverged-1")?;
    let fence = fence()?;
    let admission = admission("decision-diverged-1", &attempt, &lease_id, &route, &fence)?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let mut record = base_observation(&attempt, &route, &fence, &admission, &binding)?;
    record.observed_route = Some(observed.clone());
    record.route_state = RouteObservationState::Diverged;
    record.diverged_fields = vec!["model".to_owned()];
    record.recovery_ref = Some("reconcile-diverged-1".into());
    record.usage = UsageReceipt {
        input_tokens: Some(100),
        output_tokens: Some(50),
        cost_microunits: Some(7),
        quota: QuotaKnowledge::Known,
    };
    let record = seal(record)?;
    record.validate()?;
    record.validate_against(&binding, &admission)?;
    // Both exact fingerprints survive; the divergence is classified, usage
    // is retained, and the ceiling stays capped at the admitted ceiling.
    assert_eq!(record.requested_route, route);
    assert_eq!(record.observed_route.as_ref(), Some(&observed));
    assert_eq!(record.diverged_fields, vec!["model".to_owned()]);
    assert_eq!(record.usage.input_tokens, Some(100));
    assert!(record.recovery_ref.is_some());
    assert!(
        record
            .observation_ceiling()
            .is_at_most(admission.proof_ceiling)
    );
    Ok(())
}

#[test]
fn unobserved_observation_carries_no_fabricated_route() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-unobserved-1")?;
    let lease_id = lease("lease-unobserved-1")?;
    let fence = fence()?;
    let admission = admission("decision-unobserved-1", &attempt, &lease_id, &route, &fence)?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let mut record = base_observation(&attempt, &route, &fence, &admission, &binding)?;
    record.observed_route = None;
    record.route_state = RouteObservationState::Unobserved;
    record.unobserved_reason = Some("route-not-exposed-by-adapter".into());
    let record = seal(record)?;
    record.validate()?;
    record.validate_against(&binding, &admission)?;
    assert_eq!(record.observed_route, None);
    assert_eq!(
        record.unobserved_reason.as_deref(),
        Some("route-not-exposed-by-adapter")
    );
    Ok(())
}

#[test]
fn changed_self_digest_is_rejected() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-digest-1")?;
    let lease_id = lease("lease-digest-1")?;
    let fence = fence()?;
    let admission = admission("decision-digest-1", &attempt, &lease_id, &route, &fence)?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let observation = seal(base_observation(
        &attempt, &route, &fence, &admission, &binding,
    )?)?;
    observation.validate()?;
    let mut tampered = observation;
    tampered.self_digest =
        fixture_digest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?;
    assert_eq!(tampered.validate(), Err(ContractError::DigestMismatch));
    assert_eq!(
        tampered.validate_against(&binding, &admission),
        Err(ContractError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn mismatched_admitted_link_is_rejected() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-link-1")?;
    let lease_id = lease("lease-link-1")?;
    let fence = fence()?;
    let admitted = admission("decision-link-1", &attempt, &lease_id, &route, &fence)?;
    let other = admission("decision-link-2", &attempt, &lease_id, &route, &fence)?;
    assert_ne!(admitted.self_digest, other.self_digest);
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let observation = seal(base_observation(
        &attempt, &route, &fence, &admitted, &binding,
    )?)?;
    observation.validate_against(&binding, &admitted)?;
    assert_eq!(
        observation.validate_against(&binding, &other),
        Err(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn unknown_outcome_retains_independently_known_route() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-unknown-1")?;
    let lease_id = lease("lease-unknown-1")?;
    let fence = fence()?;
    let admission = admission("decision-unknown-1", &attempt, &lease_id, &route, &fence)?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let mut record = base_observation(&attempt, &route, &fence, &admission, &binding)?;
    record.execution_outcome = ExecutionOutcome::UnknownOutcome;
    record.terminal = ClockReading::default();
    record.recovery_ref = Some("recovery-unknown-1".into());
    let record = seal(record)?;
    record.validate()?;
    record.validate_against(&binding, &admission)?;
    // The route axes stay independently known while the outcome is unknown:
    // no effect or termination is asserted.
    assert_eq!(record.route_state, RouteObservationState::Matched);
    assert_eq!(record.observed_route.as_ref(), Some(&route));
    assert_eq!(record.execution_outcome, ExecutionOutcome::UnknownOutcome);
    assert_eq!(record.terminal.valid_time_ms, None);
    assert!(record.recovery_ref.is_some());
    Ok(())
}

#[test]
fn candidate_selecting_absent_route_is_rejected() -> TestResult {
    let route = route()?;
    let absent = diverged_route(&route);
    assert!(!vec![route.clone()].contains(&absent));
    let candidate = RouteSelectionCandidate {
        capability: "test-capability".into(),
        query_intent: "test-intent".into(),
        scope_ref: "scope:test".into(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![route.clone()],
        selected: Some(absent),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".into()],
    };
    // The preserved mismatch arm: a candidate selecting an absent route is
    // selector error, while physical divergence remains valid evidence.
    assert_eq!(candidate.validate(), Err(ContractError::RouteMismatch));
    let valid = RouteSelectionCandidate {
        capability: "test-capability".into(),
        query_intent: "test-intent".into(),
        scope_ref: "scope:test".into(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![route.clone()],
        selected: Some(route),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".into()],
    };
    valid.validate()?;
    Ok(())
}
