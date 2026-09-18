//! S6 closed host-event tests for issue #371.
//!
//! Proportionate only (4 tests, not the full 36-case matrix): closed
//! kind/payload binding, session/execution-unit authority separation,
//! replay/conflict behavior, and digest sensitivity. All digests are real
//! SHA-256 over canonical bytes; no hardcoded pass values.

use eliot_agent_api::{
    AdmittedRouteReceipt, AssistantDeltaObservation, AttemptId, CandidateSelectionDisposition,
    ClockReading, ContractError, DecisionId, EpochId, EventCursor, EventId, ExecutionUnit,
    ExecutionUnitObservation, HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM,
    HostEventDeliveryDisposition, HostEventNormalizationReceipt, HostEventPrivacyClass,
    HostEventQuarantineReason, HostEventReplayDisposition, LowercaseSha256, NativeSession,
    NativeSessionLocator, NormalizationCoverage, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, PolicyRevision, ProofCeiling, ProviderExecutionBinding,
    ProviderObservationLineage, QualifiedSourceDigest, RawSourceRecord, RequestId,
    ResourceGeneration, RestrictedRawSourceHandle, RouteFingerprint, RouteSelectionCandidate,
    SessionLifecycleObservation, SessionLifecycleTransition, SessionObservation, StateFence,
    UnsupportedDisposition, UnsupportedEventObservation, UnsupportedEventReason, WorkLeaseId,
    candidate_digest_for,
};
use eliot_contracts::{EpochLineageId, sha256_hex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn fixture_digest(bytes: &[u8]) -> Result<LowercaseSha256, serde_json::Error> {
    serde_json::from_value(serde_json::json!(sha256_hex(bytes)))
}

fn route() -> Result<RouteFingerprint, serde_json::Error> {
    let digest = |seed: &str| fixture_digest(format!("host-event-fixture-{seed}").as_bytes());
    Ok(RouteFingerprint {
        host_family: "test-host".into(),
        adapter: "test-adapter".into(),
        protocol_transport: "loopback".into(),
        runtime_hash: digest("runtime")?,
        adapter_hash: digest("adapter")?,
        provider: "provider".into(),
        model: "model".into(),
        auth_billing: "subscription".into(),
        serializer_hash: digest("serializer")?,
        tool_semantics_hash: digest("tools")?,
        reasoning_mode: "visible".into(),
        continuation_behavior: "native_resume".into(),
        feature_flags_hash: digest("features")?,
    })
}

fn lease(value: &str) -> Result<WorkLeaseId, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": value,
    }))
}

fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(
        test_epoch(TEST_LINEAGE_A, 1),
        ResourceGeneration::new(1)?,
    ))
}

fn binding(turn: &str) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
    let route = route().map_err(|error| format!("fixture route must build: {error}"))?;
    Ok(ProviderExecutionBinding {
        attempt_id: AttemptId::new("attempt-host-event-1")?,
        lease_id: lease("lease-host-event-1")?,
        state_fence: fence()?,
        runtime_generation: ResourceGeneration::new(1)?,
        route,
        session_id: None,
        provider_scope_ref: "scope:test".into(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-host-1")?),
        execution_unit: ExecutionUnit::new("test-provider", turn)?,
        start_request_id: RequestId::new("req-host-event-1")?,
        start_request_sha256: sha256_hex(b"req-host-event-1"),
    })
}

fn admission(
    binding: &ProviderExecutionBinding,
) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
    let candidate = RouteSelectionCandidate {
        capability: "test-capability".into(),
        query_intent: "test-intent".into(),
        scope_ref: "scope:test".into(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![binding.route.clone()],
        selected: Some(binding.route.clone()),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".into()],
    };
    candidate.validate()?;
    let zero = fixture_digest(b"host-event-fixture-zero")
        .map_err(|error| format!("fixture digest must build: {error}"))?;
    let mut receipt = AdmittedRouteReceipt {
        schema_version: eliot_agent_api::CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new("decision-host-event-1")?,
        candidate_digest: candidate_digest_for(&candidate)?,
        attempt_id: binding.attempt_id.clone(),
        lease_id: binding.lease_id.clone(),
        state_fence: binding.state_fence.clone(),
        runtime_generation: binding.runtime_generation,
        policy_revision: PolicyRevision::new(3)?,
        requested_route: binding.route.clone(),
        selected_route: Some(binding.route.clone()),
        no_route: None,
        evidence_refs: vec!["evidence-1".into()],
        proof_ceiling: ProofCeiling::CandidateArtifact,
        self_digest: zero,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    Ok(receipt)
}

fn raw_source(seed: &str) -> Result<(RawSourceRecord, Vec<u8>), Box<dyn std::error::Error>> {
    let bytes = format!("host-event-source-bytes-{seed}").into_bytes();
    Ok((
        RawSourceRecord {
            handle: RestrictedRawSourceHandle::new(format!("restricted-source:{seed}"))?,
            digest: QualifiedSourceDigest {
                algorithm: HOST_EVENT_DIGEST_ALGORITHM.to_owned(),
                digest: fixture_digest(&bytes)
                    .map_err(|error| format!("fixture digest must build: {error}"))?,
            },
        },
        bytes,
    ))
}

fn receipt_for(raw: &RawSourceRecord) -> Result<HostEventNormalizationReceipt, serde_json::Error> {
    Ok(HostEventNormalizationReceipt {
        normalizer_identity: "test-adapter".into(),
        normalizer_version: "test-adapter/v3".into(),
        input_handle: raw.handle.clone(),
        input_digest: raw.digest.clone(),
        output_schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        output_digest: fixture_digest(b"host-event-fixture-placeholder")?,
        omitted_fields: Vec::new(),
        warnings: Vec::new(),
        unsupported_disposition: UnsupportedDisposition::None,
        privacy_class: HostEventPrivacyClass::RedactedSummary,
        coverage: NormalizationCoverage::Complete,
        proof_ceiling: ProofCeiling::Observation,
    })
}

fn observed_at() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1_700_000_000_000),
        known_time_ms: Some(1_700_000_000_001),
        transaction_sequence: None,
        monotonic_ns: Some(9_000),
    }
}

fn unit_envelope() -> Result<NormalizedHostEventEnvelope, Box<dyn std::error::Error>> {
    let bound = binding("turn-1")?;
    let recorded = admission(&bound)?;
    let (raw, _) = raw_source("unit-1")?;
    let mut envelope = NormalizedHostEventEnvelope {
        schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        event_id: EventId::new("evt-unit-1")?,
        cursor: EventCursor::new("cursor-unit-1")?,
        lineage: ProviderObservationLineage::ExecutionUnitObservation(Box::new(
            ExecutionUnitObservation {
                binding: bound,
                cursor: EventCursor::new("cursor-unit-1")?,
                sequence: 1,
            },
        )),
        producer_adapter_identity: "test-adapter".into(),
        adapter_contract_version: "test-adapter/v3".into(),
        sequence: 1,
        causal_predecessors: Vec::new(),
        payload: NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
            delta_chars: 12,
            truncated: false,
        }),
        admitted_route_digest: Some(recorded.self_digest.clone()),
        raw_source: raw.clone(),
        normalization: receipt_for(&raw)?,
        observed_at: observed_at(),
        delivery: HostEventDeliveryDisposition::DurableOrdered,
    };
    envelope.seal()?;
    Ok(envelope)
}

fn session_envelope() -> Result<NormalizedHostEventEnvelope, Box<dyn std::error::Error>> {
    let (raw, _) = raw_source("session-1")?;
    let mut envelope = NormalizedHostEventEnvelope {
        schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        event_id: EventId::new("evt-session-1")?,
        cursor: EventCursor::new("cursor-session-1")?,
        lineage: ProviderObservationLineage::SessionObservation(SessionObservation {
            session_id: None,
            native: NativeSession::Native(NativeSessionLocator::new("thread-host-1")?),
        }),
        producer_adapter_identity: "test-adapter".into(),
        adapter_contract_version: "test-adapter/v3".into(),
        sequence: 1,
        causal_predecessors: Vec::new(),
        payload: NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
            transition: SessionLifecycleTransition::Started,
            detail_ref: None,
        }),
        admitted_route_digest: None,
        raw_source: raw.clone(),
        normalization: receipt_for(&raw)?,
        observed_at: observed_at(),
        delivery: HostEventDeliveryDisposition::BestEffortOrdered,
    };
    envelope.seal()?;
    Ok(envelope)
}

#[test]
fn closed_payload_rejects_wrong_pairing_and_unknown_fields() -> TestResult {
    let bound = binding("turn-1")?;
    let recorded = admission(&bound)?;
    // Session-lifecycle payload cannot ride execution-unit lineage.
    let mut mismatched = unit_envelope()?;
    mismatched.payload =
        NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
            transition: SessionLifecycleTransition::Suspended,
            detail_ref: None,
        });
    mismatched.seal()?;
    assert_eq!(
        mismatched.validate_for_lineage(&bound, &recorded),
        Err(ContractError::BindingMismatch)
    );
    // Execution-unit payload cannot ride session-only lineage.
    let mut session = session_envelope()?;
    session.payload = NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
        delta_chars: 3,
        truncated: false,
    });
    session.seal()?;
    assert_eq!(
        session.validate_as_session_observation(),
        Err(ContractError::BindingMismatch)
    );
    // Unknown wire fields never enter the closed schema.
    let mut wire = serde_json::to_value(unit_envelope()?)?;
    wire["normalized_payload"] = serde_json::json!({"assistant_delta": "raw text"});
    assert!(serde_json::from_value::<NormalizedHostEventEnvelope>(wire).is_err());
    // An unknown payload tag never enters the closed family.
    let mut unknown_tag = serde_json::to_value(unit_envelope()?)?;
    unknown_tag["payload"] = serde_json::json!({"payload_kind": "COMPLETED", "detail": "done"});
    assert!(serde_json::from_value::<NormalizedHostEventEnvelope>(unknown_tag).is_err());
    // The legacy generic v6 wire never deserializes as the v7 closed schema.
    let legacy = serde_json::json!({
        "event_id": "evt-unit-1",
        "attempt_id": "attempt-host-event-1",
        "sequence": 1,
        "cursor": "cursor-unit-1",
        "kind": "completed",
        "route": serde_json::to_value(route()?)?,
        "raw_payload_digest": sha256_hex(b"legacy"),
        "normalized_payload": {"text": "done"},
        "parent_event_id": null,
        "observed_at": "2026-09-13T00:00:00Z",
    });
    assert!(serde_json::from_value::<NormalizedHostEventEnvelope>(legacy).is_err());
    Ok(())
}

#[test]
fn session_only_carries_no_attempt_authority() -> TestResult {
    // A session-only observation validates on the session path only.
    session_envelope()?.validate_as_session_observation()?;
    // The same envelope presented with attempt authority fails closed.
    let bound = binding("turn-1")?;
    let recorded = admission(&bound)?;
    assert_eq!(
        session_envelope()?.validate_for_lineage(&bound, &recorded),
        Err(ContractError::BindingMismatch)
    );
    // Same thread, different provider turn: the foreign turn cannot enter the
    // recorded attempt.
    let mut foreign = unit_envelope()?;
    let other = binding("turn-2")?;
    foreign.lineage =
        ProviderObservationLineage::ExecutionUnitObservation(Box::new(ExecutionUnitObservation {
            binding: other,
            cursor: EventCursor::new("cursor-unit-1")?,
            sequence: 1,
        }));
    foreign.seal()?;
    assert_eq!(
        foreign.validate_for_lineage(&bound, &recorded),
        Err(ContractError::BindingMismatch)
    );
    // A session-only envelope carrying an admission reference claims
    // authority it does not have.
    let mut smuggled = session_envelope()?;
    smuggled.admitted_route_digest = Some(recorded.self_digest.clone());
    smuggled.seal()?;
    assert_eq!(
        smuggled.validate_as_session_observation(),
        Err(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn replay_is_idempotent_and_conflict_is_quarantined() -> TestResult {
    let envelope = unit_envelope()?;
    assert_eq!(
        envelope.check_replay_against(&envelope)?,
        HostEventReplayDisposition::IdempotentReplay
    );
    // Same identity, different typed payload: quarantined with its dimension.
    let mut payload_conflict = envelope.clone();
    payload_conflict.payload =
        NormalizedHostEventPayload::UnsupportedQuarantined(UnsupportedEventObservation {
            source_namespace: "test-provider/unknown".into(),
            source_version: None,
            reason: UnsupportedEventReason::UnknownMethod,
            detail_ref: None,
        });
    payload_conflict.normalization.unsupported_disposition =
        UnsupportedDisposition::UnsupportedMethodQuarantined;
    payload_conflict.seal()?;
    assert_eq!(
        payload_conflict.check_replay_against(&envelope)?,
        HostEventReplayDisposition::Quarantined {
            reason: HostEventQuarantineReason::ConflictingPayload,
        }
    );
    // Same identity, different lineage: quarantined as lineage conflict.
    let mut lineage_conflict = envelope.clone();
    lineage_conflict.cursor = EventCursor::new("cursor-unit-2")?;
    lineage_conflict.sequence = 2;
    lineage_conflict.lineage =
        ProviderObservationLineage::ExecutionUnitObservation(Box::new(ExecutionUnitObservation {
            binding: binding("turn-1")?,
            cursor: EventCursor::new("cursor-unit-2")?,
            sequence: 2,
        }));
    lineage_conflict.seal()?;
    assert_eq!(
        lineage_conflict.check_replay_against(&envelope)?,
        HostEventReplayDisposition::Quarantined {
            reason: HostEventQuarantineReason::ConflictingLineage,
        }
    );
    // Same identity, different source bytes: quarantined as source conflict.
    let mut source_conflict = envelope.clone();
    let (raw, _) = raw_source("unit-1-altered")?;
    source_conflict.raw_source = raw.clone();
    source_conflict.normalization.input_handle = raw.handle.clone();
    source_conflict.normalization.input_digest = raw.digest.clone();
    source_conflict.seal()?;
    assert_eq!(
        source_conflict.check_replay_against(&envelope)?,
        HostEventReplayDisposition::Quarantined {
            reason: HostEventQuarantineReason::ConflictingSource,
        }
    );
    // A different event identity is not a replay at all.
    let mut other = envelope.clone();
    other.event_id = EventId::new("evt-unit-2")?;
    other.seal()?;
    assert_eq!(
        other.check_replay_against(&envelope),
        Err(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn digest_changes_with_source_lineage_payload_and_loss() -> TestResult {
    let baseline = unit_envelope()?;
    let baseline_digest = baseline.compute_digest()?;
    // Determinism: rebuilding the identical envelope reproduces the digest.
    assert_eq!(unit_envelope()?.compute_digest()?, baseline_digest);
    // Source change alters the bound digest.
    let mut source_changed = baseline.clone();
    let (raw, _) = raw_source("unit-1-changed")?;
    source_changed.raw_source = raw.clone();
    source_changed.normalization.input_handle = raw.handle.clone();
    source_changed.normalization.input_digest = raw.digest.clone();
    source_changed.seal()?;
    assert_ne!(source_changed.compute_digest()?, baseline_digest);
    // Lineage change alters the bound digest.
    let mut lineage_changed = baseline.clone();
    lineage_changed.cursor = EventCursor::new("cursor-unit-9")?;
    lineage_changed.sequence = 9;
    lineage_changed.lineage =
        ProviderObservationLineage::ExecutionUnitObservation(Box::new(ExecutionUnitObservation {
            binding: binding("turn-1")?,
            cursor: EventCursor::new("cursor-unit-9")?,
            sequence: 9,
        }));
    lineage_changed.seal()?;
    assert_ne!(lineage_changed.compute_digest()?, baseline_digest);
    // Payload change alters the bound digest.
    let mut payload_changed = baseline.clone();
    payload_changed.payload =
        NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
            delta_chars: 13,
            truncated: false,
        });
    payload_changed.seal()?;
    assert_ne!(payload_changed.compute_digest()?, baseline_digest);
    // Declared loss alters the bound digest.
    let mut loss_changed = baseline.clone();
    loss_changed.normalization.coverage = NormalizationCoverage::LossyOmission;
    loss_changed.normalization.omitted_fields = vec!["provider.extra".into()];
    loss_changed.seal()?;
    assert_eq!(
        loss_changed.validate_as_session_observation(),
        Err(ContractError::BindingMismatch)
    );
    assert_ne!(loss_changed.compute_digest()?, baseline_digest);
    // An empty loss manifest with discarded source fields fails closed.
    let mut empty_manifest = baseline.clone();
    empty_manifest.normalization.coverage = NormalizationCoverage::LossyOmission;
    empty_manifest.seal()?;
    let bound = binding("turn-1")?;
    let recorded = admission(&bound)?;
    assert_eq!(
        empty_manifest.validate_for_lineage(&bound, &recorded),
        Err(ContractError::InvalidRouteDisposition)
    );
    Ok(())
}
