use eliot_agent_api::{AttemptId, HostEventEnvelope, HostEventKind, SessionId};
use eliot_agent_codex::{CodexSessionBinding, CodexWireMessage, codex_route, translate_host_event};
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

fn session() -> Result<CodexSessionBinding, eliot_agent_api::ContractError> {
    Ok(CodexSessionBinding {
        session_id: SessionId::new("session-1")?,
        thread_id: "thread-1".to_owned(),
        runtime_hash: "runtime-1".to_owned(),
        working_directory: "C:\\workspace".to_owned(),
    })
}

fn translate_envelope(
    method: &str,
    params: Value,
) -> Result<HostEventEnvelope, Box<dyn std::error::Error>> {
    let message = CodexWireMessage::notification(method, Some(params));
    Ok(translate_host_event(
        &message,
        AttemptId::new("attempt-1")?,
        &route(),
        &session()?,
        1,
        None,
        "2026-08-30T20:00:00Z",
    )?)
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
        serde_json::json!({
            "threadId": "thread-1",
            "turn": {"id": "turn-1"}
        }),
        serde_json::json!({"threadId": "thread-1"}),
    ] {
        assert_eq!(translate("turn/completed", params)?, HostEventKind::Unknown);
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
                "turn": {"status": "failed"}
            }),
        )?,
        HostEventKind::PromptSubmitted,
    );
    Ok(())
}

#[test]
fn wrong_thread_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "other-thread",
            "turn": {"status": "completed"}
        })),
    );
    assert!(matches!(
        translate_host_event(
            &message,
            AttemptId::new("attempt-1")?,
            &route(),
            &session()?,
            1,
            None,
            "2026-08-30T20:00:00Z",
        ),
        Err(eliot_agent_codex::CodexAdapterError::SessionMismatch)
    ));
    Ok(())
}

#[test]
fn cursor_and_sequence_are_monotonic() -> Result<(), Box<dyn std::error::Error>> {
    let message = CodexWireMessage::notification(
        "turn/completed",
        Some(serde_json::json!({
            "threadId": "thread-1",
            "turn": {"status": "completed"}
        })),
    );
    assert!(matches!(
        translate_host_event(
            &message,
            AttemptId::new("attempt-1")?,
            &route(),
            &session()?,
            2,
            Some(2),
            "2026-08-30T20:00:00Z",
        ),
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
    let envelope = translate_host_event(
        &message,
        AttemptId::new("attempt-1")?,
        &route(),
        &session()?,
        1,
        None,
        "2026-08-30T20:00:00Z",
    )?;

    assert_eq!(envelope.event_id.as_str(), "codex:1");
    assert_eq!(envelope.cursor.as_str(), "codex:1");
    assert_eq!(envelope.kind, HostEventKind::Completed);
    assert_eq!(envelope.normalized_payload, params);
    assert_eq!(
        envelope.raw_payload_digest,
        blake3::hash(&bytes).to_hex().to_string()
    );
    Ok(())
}
