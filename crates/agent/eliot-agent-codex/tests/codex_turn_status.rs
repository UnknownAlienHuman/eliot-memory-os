use eliot_agent_api::{
    AttemptId, ContractError, EventCursor, ExecutionUnit, ExecutionUnitObservation,
    HostEventEnvelope, HostEventKind, NativeSession, NativeSessionLocator,
    ProviderExecutionBinding, ProviderObservationLineage, SessionId, SessionObservation,
};
use eliot_agent_codex::{
    CodexAdapterError, CodexSessionBinding, CodexWireMessage, codex_route, translate_host_event,
};
use eliot_contracts::{ClockReading, sha256_hex};
use serde_json::Value;

fn route() -> eliot_agent_api::RouteFingerprint {
    codex_route(
        "runtime-1",
        "adapter-1",
        "provider-1",
        "model-1",
        "subscription-1",
        "serializer-1",
        "tools-1",
        "visible",
        "native_resume",
        "features-1",
    )
}

fn session() -> Result<CodexSessionBinding, Box<dyn std::error::Error>> {
    Ok(CodexSessionBinding {
        session_id: SessionId::new("session-1")?,
        thread_id: "thread-1".to_owned(),
        runtime_hash: "runtime-1".to_owned(),
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
            eliot_agent_api::AuthorityEpoch::new(1)?,
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

fn translate_envelope(
    method: &str,
    params: Value,
) -> Result<HostEventEnvelope, Box<dyn std::error::Error>> {
    let bound = binding()?;
    let message = CodexWireMessage::notification(method, Some(params));
    Ok(translate_host_event(
        &message,
        &lineage(&bound, 1)?,
        1,
        None,
        &clock(),
    )?)
}

/// Concrete-error translation for quarantine assertions.
fn translate_raw(method: &str, params: Value) -> Result<HostEventEnvelope, CodexAdapterError> {
    let bound = binding().expect("fixture binding");
    let message = CodexWireMessage::notification(method, Some(params));
    let observed = lineage(&bound, 1).expect("fixture lineage");
    translate_host_event(&message, &observed, 1, None, &clock())
}

fn translate(method: &str, params: Value) -> Result<HostEventKind, Box<dyn std::error::Error>> {
    Ok(translate_envelope(method, params)?.kind)
}

#[test]
fn canonical_turn_status_controls_terminal_event_kind() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        translate(
            "turn/completed",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "completed"}
            }),
        )?,
        HostEventKind::Completed,
    );
    assert_eq!(
        translate(
            "turn/completed",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "failed"}
            }),
        )?,
        HostEventKind::Failed,
    );
    Ok(())
}

#[test]
fn legacy_terminal_aliases_are_quarantined() -> Result<(), Box<dyn std::error::Error>> {
    for method in ["turn/completion", "turn/cancelled"] {
        assert_eq!(
            translate(
                method,
                serde_json::json!({
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed"}
                }),
            )?,
            HostEventKind::Unknown,
            "unadmitted alias {method} must not claim a terminal event",
        );
    }
    Ok(())
}

#[test]
fn noncompleted_canonical_statuses_never_become_completed() -> Result<(), Box<dyn std::error::Error>>
{
    // Exact bound turn with a non-terminal status keeps its classification.
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
        assert_eq!(translate("turn/completed", params)?, HostEventKind::Unknown);
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
                translate_raw("turn/completed", params),
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
    assert_eq!(
        translate(
            "turn/started",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "failed"}
            }),
        )?,
        HostEventKind::PromptSubmitted,
    );
    Ok(())
}

#[test]
fn wrong_thread_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "other-thread",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    assert!(matches!(
        translate_host_event(&message, &lineage(&bound, 1)?, 1, None, &clock(),),
        Err(eliot_agent_codex::CodexAdapterError::SessionMismatch)
    ));
    Ok(())
}

#[test]
fn foreign_turn_never_yields_bound_attempt_output() {
    assert!(matches!(
        translate_raw(
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
    assert!(matches!(
        translate_host_event(&message, &session_only, 1, None, &clock(),),
        Err(CodexAdapterError::Contract(ContractError::BindingMismatch))
    ));
    Ok(())
}

#[test]
fn recorded_observation_must_match_the_claimed_stream_position()
-> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    assert!(matches!(
        translate_host_event(&message, &lineage(&bound, 9)?, 1, None, &clock(),),
        Err(CodexAdapterError::Contract(ContractError::BindingMismatch))
    ));
    Ok(())
}

#[test]
fn cursor_and_sequence_are_monotonic() -> Result<(), Box<dyn std::error::Error>> {
    let bound = binding()?;
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "status": "completed"}
        })),
    );
    assert!(matches!(
        translate_host_event(&message, &lineage(&bound, 2)?, 2, Some(2), &clock(),),
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
    let message = CodexWireMessage::notification("turn/completed", Some(params.clone()));
    let bytes = serde_json::to_vec(&message)?;
    let bound = binding()?;
    let envelope = translate_host_event(&message, &lineage(&bound, 1)?, 1, None, &clock())?;

    // The recorded cursor is preserved end-to-end; no synthesized identity.
    assert_eq!(envelope.event_id.as_str(), "turn-1:1");
    assert_eq!(envelope.cursor.as_str(), "turn-1:1");
    assert_eq!(envelope.sequence, 1);
    assert_eq!(envelope.attempt_id, bound.attempt_id);
    assert_eq!(envelope.route, bound.route);
    assert_eq!(envelope.observed_at, "1786000000000");
    assert_eq!(envelope.kind, HostEventKind::Completed);
    assert_eq!(envelope.normalized_payload, params);
    assert_eq!(
        envelope.raw_payload_digest,
        blake3::hash(&bytes).to_hex().to_string()
    );
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
