use std::error::Error;

use eliot_agent_api::{AttemptId, HostEventKind, SessionId};
use eliot_agent_codex::{
    CodexSessionBinding, CodexWireMessage, codex_route, translate_host_event,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn failed_turn_completed_notification_is_not_normalized_as_success() -> TestResult {
    let route = codex_route(
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
    );
    let session = CodexSessionBinding {
        session_id: SessionId::new("session-1")?,
        thread_id: "thread-1".to_owned(),
        runtime_hash: "runtime-1".to_owned(),
        working_directory: "C:\\workspace".to_owned(),
    };
    let message = CodexWireMessage::parse_line(
        br#"{
            "method":"turn/completed",
            "params":{
                "threadId":"thread-1",
                "turn":{"id":"turn-1","status":"failed"}
            }
        }"#,
    )?;

    let event = translate_host_event(
        &message,
        AttemptId::new("attempt-1")?,
        &route,
        &session,
        1,
        None,
        "2026-08-31T08:00:00Z",
    )?;

    assert_eq!(event.kind, HostEventKind::Failed);
    Ok(())
}
