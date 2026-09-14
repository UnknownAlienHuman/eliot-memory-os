use eliot_agent_api::{
    AdmittedRouteReceipt, AttemptId, CONTRACT_VERSION, ContractError, EventCursor, EventId,
    ExecutionUnit, ExecutionUnitObservation, HostEventDeliveryDisposition, LowercaseSha256,
    NativeSession, NativeSessionLocator, NormalizedHostEventEnvelope, NormalizedHostEventPayload,
    ProviderExecutionBinding, ProviderObservationLineage, ProviderTerminalStatus, QuotaKnowledge,
    RestrictedRawSourceHandle, SessionId, SessionObservation,
};
use eliot_agent_codex::{
    CODEX_NORMALIZER_IDENTITY, CODEX_NORMALIZER_VERSION, CodexAdapterError, CodexHostEventInput,
    CodexSessionBinding, CodexWireMessage, codex_route, normalize_codex_event,
};
use eliot_contracts::{ClockReading, EpochId, EpochLineageId, sha256_hex};
use serde_json::Value;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn fixture_digest(seed: &str) -> LowercaseSha256 {
    serde_json::from_value(serde_json::json!(eliot_contracts::sha256_hex(
        format!("codex-turn-{seed}").as_bytes()
    )))
    .expect("valid fixture digest")
}

fn route() -> eliot_agent_api::RouteFingerprint {
    codex_route(
        fixture_digest("runtime"),
        fixture_digest("adapter"),
        "provider-1",
        "model-1",
        "subscription-1",
        fixture_digest("serializer"),
        fixture_digest("tools"),
        "visible",
        "native_resume",
        fixture_digest("features"),
    )
}

fn session() -> Result<CodexSessionBinding, Box<dyn std::error::Error>> {
    Ok(CodexSessionBinding {
        session_id: SessionId::new("session-1")?,
        thread_id: "thread-1".to_owned(),
        runtime_hash: fixture_digest("runtime"),
        working_directory: "C:\\workspace".to_owned(),
    })
}

fn binding() -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
    Ok(ProviderExecutionBinding {
        attempt_id: AttemptId::new("attempt-1")?,
        lease_id: serde_json::from_value::<eliot_agent_api::WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
        )?,
        state_fence: eliot_agent_api::StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            eliot_agent_api::ResourceGeneration::new(1)?,
        ),
        runtime_generation: eliot_agent_api::ResourceGeneration::new(1)?,
        route: route(),
        session_id: Some(SessionId::new("session-1")?),
        provider_scope_ref: "scope-1".to_owned(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
        execution_unit: ExecutionUnit::new("codex", "turn-1")?,
        start_request_id: eliot_agent_api::RequestId::new("req-1")?,
        start_request_sha256: sha256_hex(b"req-1"),
    })
}

fn admission_for(
    binding: &ProviderExecutionBinding,
) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
    use eliot_agent_api::{
        CandidateSelectionDisposition, PolicyRevision, RouteSelectionCandidate,
        candidate_digest_for,
    };
    use eliot_contracts::DecisionId;
    let candidate = RouteSelectionCandidate {
        capability: "codex".to_owned(),
        query_intent: "test-intent".to_owned(),
        scope_ref: "scope:test".to_owned(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![binding.route.clone()],
        selected: Some(binding.route.clone()),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".to_owned()],
    };
    candidate.validate()?;
    let zero: LowercaseSha256 = serde_json::from_value(serde_json::json!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ))?;
    let mut receipt = AdmittedRouteReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new("decision-1")?,
        candidate_digest: candidate_digest_for(&candidate)?,
        attempt_id: binding.attempt_id.clone(),
        lease_id: binding.lease_id.clone(),
        state_fence: binding.state_fence.clone(),
        runtime_generation: binding.runtime_generation,
        policy_revision: PolicyRevision::new(3)?,
        requested_route: binding.route.clone(),
        selected_route: Some(binding.route.clone()),
        no_route: None,
        evidence_refs: vec!["evidence-1".to_owned()],
        proof_ceiling: eliot_agent_api::ProofCeiling::CandidateArtifact,
        self_digest: zero,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    Ok(receipt)
}

fn lineage(
    binding: &ProviderExecutionBinding,
    sequence: u64,
) -> Result<ProviderObservationLineage, Box<dyn std::error::Error>> {
    Ok(ProviderObservationLineage::ExecutionUnitObservation(
        Box::new(ExecutionUnitObservation {
            binding: binding.clone(),
            cursor: EventCursor::new(format!("turn-1:{sequence}"))?,
            sequence,
        }),
    ))
}

fn clock() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1_786_000_000_000),
        known_time_ms: Some(1_786_000_000_000),
        transaction_sequence: None,
        monotonic_ns: Some(1),
    }
}

fn normalize_envelope(
    method: &str,
    params: Value,
) -> Result<NormalizedHostEventEnvelope, Box<dyn std::error::Error>> {
    let bound = binding()?;
    let admission = admission_for(&bound)?;
    let message = CodexWireMessage::notification(method, Some(params));
    let raw = serde_json::to_vec(&message)?;
    let (envelope, _) = normalize_codex_event(CodexHostEventInput {
        message: &message,
        lineage: lineage(&bound, 1)?,
        event_id: EventId::new("turn-1:1")?,
        cursor: EventCursor::new("turn-1:1")?,
        sequence: 1,
        previous_sequence: None,
        predecessors: Vec::new(),
        raw_source_bytes: &raw,
        raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:1")?,
        observed_at: clock(),
        delivery: HostEventDeliveryDisposition::BestEffortOrdered,
        admission: Some(&admission),
    })?;
    Ok(envelope)
}

/// Concrete-error normalization for quarantine assertions.
fn normalize_raw(
    method: &str,
    params: Value,
) -> Result<NormalizedHostEventEnvelope, CodexAdapterError> {
    let bound = binding().expect("fixture binding");
    let admission = admission_for(&bound).expect("fixture admission");
    let message = CodexWireMessage::notification(method, Some(params));
    let raw = serde_json::to_vec(&message).expect("fixture raw");
    let observed = lineage(&bound, 1).expect("fixture lineage");
    let (envelope, _) = normalize_codex_event(CodexHostEventInput {
        message: &message,
        lineage: observed,
        event_id: EventId::new("turn-1:1").expect("fixture event"),
        cursor: EventCursor::new("turn-1:1").expect("fixture cursor"),
        sequence: 1,
        previous_sequence: None,
        predecessors: Vec::new(),
        raw_source_bytes: &raw,
        // The handle outlives the call via the raw bytes reference scope below:
        // construct inline and leak the borrow through a two-step call.
        raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:1")
            .expect("fixture handle"),
        observed_at: clock(),
        delivery: HostEventDeliveryDisposition::BestEffortOrdered,
        admission: Some(&admission),
    })?;
    Ok(envelope)
}

fn normalize_raw_result(
    method: &str,
    params: Value,
) -> Result<NormalizedHostEventEnvelope, CodexAdapterError> {
    normalize_raw(method, params)
}

fn terminal_status(
    method: &str,
    params: Value,
) -> Result<Option<ProviderTerminalStatus>, Box<dyn std::error::Error>> {
    let envelope = normalize_envelope(method, params)?;
    match envelope.payload {
        NormalizedHostEventPayload::ProviderTerminalObserved(observation) => {
            Ok(Some(observation.status))
        }
        NormalizedHostEventPayload::UnsupportedQuarantined(_) => Ok(None),
        other => panic!("unexpected typed payload for terminal case: {other:?}"),
    }
}

#[test]
fn canonical_turn_status_controls_terminal_event_kind() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        terminal_status(
            "turn/completed",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "completed"}
            }),
        )?,
        Some(ProviderTerminalStatus::CompletedObserved),
    );
    assert_eq!(
        terminal_status(
            "turn/completed",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "failed"}
            }),
        )?,
        Some(ProviderTerminalStatus::FailedObserved),
    );
    Ok(())
}

#[test]
fn legacy_terminal_aliases_are_quarantined() -> Result<(), Box<dyn std::error::Error>> {
    for method in ["turn/completion", "turn/cancelled"] {
        let envelope = normalize_envelope(
            method,
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "completed"}
            }),
        )?;
        assert!(
            matches!(
                envelope.payload,
                NormalizedHostEventPayload::UnsupportedQuarantined(_)
            ),
            "unadmitted alias {method} must quarantine, never claim terminal",
        );
        assert_eq!(
            envelope.normalization.unsupported_disposition,
            eliot_agent_api::UnsupportedDisposition::UnsupportedMethodQuarantined
        );
    }
    Ok(())
}

#[test]
fn noncompleted_canonical_statuses_never_become_completed() -> Result<(), Box<dyn std::error::Error>>
{
    // Exact bound turn with a non-terminal status quarantines as typed
    // evidence (never terminal success).
    for params in [
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "interrupted"}
        }),
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "unknown"}
        }),
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "inProgress"}
        }),
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": 42}
        }),
    ] {
        assert_eq!(terminal_status("turn/completed", params)?, None);
    }
    // Missing or non-string turn identity quarantines instead of classifying.
    for params in [
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"status": "completed"}
        }),
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": 42, "status": "completed"}
        }),
        serde_json::json!({"threadId": "thread-1"}),
    ] {
        assert!(
            matches!(
                normalize_raw_result("turn/completed", params),
                Err(CodexAdapterError::Contract(ContractError::BindingMismatch))
            ),
            "missing turn identity must quarantine",
        );
    }
    Ok(())
}

#[test]
fn nonterminal_method_keeps_its_existing_classification() -> Result<(), Box<dyn std::error::Error>>
{
    let envelope = normalize_envelope(
        "turn/started",
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "failed"}
        }),
    )?;
    assert!(matches!(
        envelope.payload,
        NormalizedHostEventPayload::ExecutionStarted(_)
    ));
    Ok(())
}

#[test]
fn wrong_thread_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let admission = admission_for(&bound)?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "other-thread",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    let raw = serde_json::to_vec(&message)?;
    assert!(matches!(
        normalize_codex_event(CodexHostEventInput {
            message: &message,
            lineage: lineage(&bound, 1)?,
            event_id: EventId::new("turn-1:1")?,
            cursor: EventCursor::new("turn-1:1")?,
            sequence: 1,
            previous_sequence: None,
            predecessors: Vec::new(),
            raw_source_bytes: &raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:1")?,
            observed_at: clock(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        }),
        Err(eliot_agent_codex::CodexAdapterError::SessionMismatch)
    ));
    Ok(())
}

#[test]
fn foreign_turn_never_yields_bound_attempt_output() {
    assert!(matches!(
        normalize_raw_result(
            "turn/completed",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-2", "status": "completed"}
            }),
        ),
        Err(CodexAdapterError::Contract(ContractError::BindingMismatch))
    ));
}

#[test]
fn session_only_thread_events_carry_no_attempt_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let bound = binding()?;
    let session_only = ProviderObservationLineage::SessionObservation(SessionObservation {
        session_id: bound.session_id.clone(),
        native: bound.native_session.clone(),
    });
    let message = CodexWireMessage::notification(
        "thread/started",
        Some(serde_json::json!({ "threadId": "thread-1" })),
    );
    let raw = serde_json::to_vec(&message)?;
    let (envelope, receipt) = normalize_codex_event(CodexHostEventInput {
        message: &message,
        lineage: session_only.clone(),
        event_id: EventId::new("session-1:1")?,
        cursor: EventCursor::new("session-1:1")?,
        sequence: 1,
        previous_sequence: None,
        predecessors: Vec::new(),
        raw_source_bytes: &raw,
        raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:session-1")?,
        observed_at: clock(),
        delivery: HostEventDeliveryDisposition::BestEffortOrdered,
        admission: None,
    })?;
    // Session-only stays session-only: no admission reference, session
    // lifecycle payload, and no attributable execution binding.
    assert!(envelope.admitted_route_digest.is_none());
    assert!(matches!(
        envelope.payload,
        NormalizedHostEventPayload::SessionLifecycle(_)
    ));
    assert!(session_only.attributable_binding().is_err());
    assert!(envelope.lineage.attributable_binding().is_err());
    envelope.validate_as_session_observation()?;
    assert_eq!(envelope.normalization, receipt);
    Ok(())
}

#[test]
fn recorded_observation_must_match_the_claimed_stream_position()
-> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let admission = admission_for(&bound)?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    let raw = serde_json::to_vec(&message)?;
    assert!(matches!(
        normalize_codex_event(CodexHostEventInput {
            message: &message,
            lineage: lineage(&bound, 9)?,
            event_id: EventId::new("turn-1:9")?,
            cursor: EventCursor::new("turn-1:9")?,
            sequence: 1,
            previous_sequence: None,
            predecessors: Vec::new(),
            raw_source_bytes: &raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:9")?,
            observed_at: clock(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        }),
        Err(CodexAdapterError::Contract(ContractError::BindingMismatch))
    ));
    Ok(())
}

#[test]
fn cursor_and_sequence_are_monotonic() -> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let admission = admission_for(&bound)?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    let raw = serde_json::to_vec(&message)?;
    assert!(matches!(
        normalize_codex_event(CodexHostEventInput {
            message: &message,
            lineage: lineage(&bound, 2)?,
            event_id: EventId::new("turn-1:2")?,
            cursor: EventCursor::new("turn-1:2")?,
            sequence: 2,
            previous_sequence: Some(2),
            predecessors: Vec::new(),
            raw_source_bytes: &raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:2")?,
            observed_at: clock(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        }),
        Err(eliot_agent_codex::CodexAdapterError::Contract(
            eliot_agent_api::ContractError::NonMonotonicEvent
        ))
    ));
    Ok(())
}

#[test]
fn terminal_translation_preserves_event_identity_raw_digest_and_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let params = serde_json::json!({
        "threadId": "thread-1",
        "turn": {"id": "turn-1", "status": "completed"},
        "opaque": {"vendor": "value"}
    });
    let message = CodexWireMessage::notification("turn/completed", Some(params));
    let raw = serde_json::to_vec(&message)?;
    let bound = binding()?;
    let admission = admission_for(&bound)?;
    let (envelope, receipt) = normalize_codex_event(CodexHostEventInput {
        message: &message,
        lineage: lineage(&bound, 1)?,
        event_id: EventId::new("turn-1:1")?,
        cursor: EventCursor::new("turn-1:1")?,
        sequence: 1,
        previous_sequence: None,
        predecessors: Vec::new(),
        raw_source_bytes: &raw,
        raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:1")?,
        observed_at: clock(),
        delivery: HostEventDeliveryDisposition::BestEffortOrdered,
        admission: Some(&admission),
    })?;

    // The recorded cursor is preserved end-to-end; no synthesized identity.
    assert_eq!(envelope.event_id.as_str(), "turn-1:1");
    assert_eq!(envelope.cursor.as_str(), "turn-1:1");
    assert_eq!(envelope.sequence, 1);
    assert_eq!(
        envelope.lineage.attributable_binding()?.attempt_id,
        bound.attempt_id
    );
    assert_eq!(
        envelope.admitted_route_digest.as_ref(),
        Some(&admission.self_digest)
    );
    assert_eq!(envelope.observed_at.valid_time_ms, Some(1_786_000_000_000));
    assert!(matches!(
        envelope.payload,
        NormalizedHostEventPayload::ProviderTerminalObserved(ref observation)
            if observation.status == ProviderTerminalStatus::CompletedObserved
    ));
    // Canonical SHA-256 over the exact raw source bytes (never blake3, never
    // a caller string); raw bytes stay behind the restricted handle and never
    // enter the public payload.
    let expected_digest = sha256_hex(&raw);
    assert_eq!(envelope.raw_source.digest.digest.as_str(), expected_digest);
    assert_eq!(
        envelope.raw_source.handle.as_str(),
        "restricted-codex:turn-1:1"
    );
    assert_eq!(receipt.input_digest, envelope.raw_source.digest);
    assert_eq!(
        envelope.producer_adapter_identity,
        CODEX_NORMALIZER_IDENTITY
    );
    assert_eq!(envelope.adapter_contract_version, CODEX_NORMALIZER_VERSION);
    assert_eq!(envelope.normalization, receipt);
    envelope.validate_for_lineage(envelope.lineage.attributable_binding()?, &admission)?;
    let payload_value = serde_json::to_value(&envelope.payload)?;
    assert!(!payload_value.to_string().contains("vendor"));
    Ok(())
}

#[test]
fn usage_without_quota_is_typed_not_exposed() -> Result<(), Box<dyn std::error::Error>> {
    let envelope = normalize_envelope(
        "turn/usage",
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1"},
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }),
    )?;
    match envelope.payload {
        NormalizedHostEventPayload::Usage(usage) => {
            assert_eq!(usage.input_tokens, Some(10));
            assert_eq!(usage.output_tokens, Some(5));
            // Absent native quota evidence stays typed NotExposed, never zero.
            assert_eq!(usage.quota, QuotaKnowledge::NotExposed);
        }
        other => panic!("expected typed Usage payload, got {other:?}"),
    }
    Ok(())
}

#[test]
fn mismatched_recorded_cursor_never_repoints() -> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let admission = admission_for(&bound)?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    let raw = serde_json::to_vec(&message)?;
    // Caller cursor disagrees with the recorded observation cursor: fail
    // closed instead of synthesizing or re-pointing.
    assert!(matches!(
        normalize_codex_event(CodexHostEventInput {
            message: &message,
            lineage: lineage(&bound, 1)?,
            event_id: EventId::new("turn-1:999")?,
            cursor: EventCursor::new("turn-1:999")?,
            sequence: 1,
            previous_sequence: None,
            predecessors: Vec::new(),
            raw_source_bytes: &raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:turn-1:999")?,
            observed_at: clock(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        }),
        Err(CodexAdapterError::Contract(ContractError::BindingMismatch))
    ));
    Ok(())
}

#[test]
fn session_binding_stays_a_session_locator() -> Result<(), Box<dyn std::error::Error>> {
    // The session binding never mints attempt authority on its own: the same
    // locator validates for attach-shaped checks while event attribution still
    // requires the exact recorded turn binding.
    let bound = binding()?;
    session()?.validate(&route())?;
    assert_eq!(
        bound.native_session,
        NativeSession::Native(NativeSessionLocator::new("thread-1")?)
    );
    Ok(())
}
