use eliot_agent_api::{AttemptId, HostEventKind, SessionId};
use eliot_agent_codex::{
    CodexAdapterError, CodexSessionBinding, CodexWireMessage, codex_route,
    translate_host_event,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

fn session() -> TestResult<CodexSessionBinding> {
    Ok(CodexSessionBinding {
        session_id: SessionId::new("session-1")?,
        thread_id: "thread-1".to_owned(),
        runtime_hash: "runtime-1".to_owned(),
        working_directory: r"C:\workspace".to_owned(),
    })
}

fn turn_completed(status: Value, thread_id: &str) -> CodexWireMessage {
    CodexWireMessage::notification(
        "turn/completed",
        Some(json!({
            "threadId": thread_id,
            "turn": {"id": "turn-1", "status": status}
        })),
    )
}

fn translate(
    message: &CodexWireMessage,
    session: &CodexSessionBinding,
) -> Result<eliot_agent_api::HostEventEnvelope, CodexAdapterError> {
    translate_host_event(
        message,
        AttemptId::new("attempt-1")?,
        &route(),
        session,
        1,
        None,
        "2026-08-31T09:00:00Z",
    )
}

#[test]
fn completed_and_failed_statuses_remain_distinct() -> TestResult {
    let session = session()?;
    assert_eq!(
        translate(&turn_completed(json!("completed"), "thread-1"), &session)?.kind,
        HostEventKind::Completed
    );
    assert_eq!(
        translate(&turn_completed(json!("failed"), "thread-1"), &session)?.kind,
        HostEventKind::Failed
    );
    Ok(())
}

#[test]
fn interrupted_in_progress_and_unknown_status_never_become_completed() -> TestResult {
    let session = session()?;
    for status in ["interrupted", "inProgress", "future-status"] {
        let event = translate(&turn_completed(json!(status), "thread-1"), &session)?;
        assert_eq!(event.kind, HostEventKind::Unknown);
        assert_ne!(event.kind, HostEventKind::Completed);
        assert_ne!(event.kind, HostEventKind::CancelRequested);
    }
    Ok(())
}

#[test]
fn missing_or_non_string_terminal_status_fails_closed() -> TestResult {
    let session = session()?;
    let missing = CodexWireMessage::notification(
        "turn/completed",
        Some(json!({"threadId": "thread-1", "turn": {"id": "turn-1"}})),
    );
    let non_string = turn_completed(json!(7), "thread-1");

    assert!(matches!(
        translate(&missing, &session),
        Err(CodexAdapterError::MalformedWire(_))
    ));
    assert!(matches!(
        translate(&non_string, &session),
        Err(CodexAdapterError::MalformedWire(_))
    ));
    Ok(())
}

#[test]
fn wrong_thread_still_fails_before_terminal_status_is_admitted() -> TestResult {
    let session = session()?;
    assert!(matches!(
        translate(&turn_completed(json!("completed"), "wrong-thread"), &session),
        Err(CodexAdapterError::SessionMismatch)
    ));
    Ok(())
}

#[test]
fn nonterminal_notifications_keep_their_existing_classification() -> TestResult {
    let session = session()?;
    let started = CodexWireMessage::notification(
        "turn/started",
        Some(json!({"threadId": "thread-1", "turn": {"id": "turn-1"}})),
    );
    assert_eq!(
        translate(&started, &session)?.kind,
        HostEventKind::PromptSubmitted
    );
    Ok(())
}

#[test]
fn stale_completion_and_cancel_aliases_cannot_manufacture_terminal_semantics() -> TestResult {
    let session = session()?;
    for method in ["turn/completion", "turn/cancelled"] {
        let message = CodexWireMessage::notification(
            method,
            Some(json!({"threadId": "thread-1", "turn": {"id": "turn-1"}})),
        );
        let event = translate(&message, &session)?;
        assert_eq!(event.kind, HostEventKind::Unknown);
        assert_ne!(event.kind, HostEventKind::Completed);
        assert_ne!(event.kind, HostEventKind::CancelRequested);
    }
    Ok(())
}

#[test]
fn terminal_payload_and_event_identity_are_preserved() -> TestResult {
    let session = session()?;
    let message = turn_completed(json!("failed"), "thread-1");
    let event = translate(&message, &session)?;

    assert_eq!(event.normalized_payload["turn"]["status"], "failed");
    assert!(!event.raw_payload_digest.is_empty());
    assert_eq!(event.sequence, 1);
    Ok(())
}
