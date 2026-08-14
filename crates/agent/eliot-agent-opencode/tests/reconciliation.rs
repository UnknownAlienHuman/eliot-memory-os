use eliot_agent_opencode::{
    ActualRouteState, AuthorityCeiling, BasicAuth, LoopbackEndpoint, ModelSelection,
    OpenCodeClient, OpenCodeRunError, OpenCodeRunPolicy, ReadOnlyRunRequest, RunStatus,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const DIRECTORY: &str = r"C:\Scratch";
const SESSION_ID: &str = "ses_reconcile";
const MESSAGE_ID: &str = "msg_reconcile";
const PROVIDER: &str = "opencode-go";
const MODEL: &str = "deepseek-v4-flash";

#[tokio::test]
async fn stale_idle_before_dispatch_does_not_complete() -> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    responses.push(chunked_sse(&sse_event(&json!({
        "type": "session.status",
        "properties": {"sessionID": SESSION_ID, "status": {"type": "idle"}},
    }))));
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(json_response(br"[]"));
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(json_response(br"[]"));
    responses.push(json_response(br"[]"));

    let client = client_for(responses).await?;
    let error = client.run_read_only(&request(None)?).await;
    match error {
        Err(OpenCodeRunError::Protocol(message)) => {
            assert!(message.contains("correlated completion"));
        }
        Err(other) => panic!("stale idle returned unexpected error: {other}"),
        Ok(result) => panic!("stale idle unexpectedly completed: {result:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn sse_eof_after_correlated_completion_reconciles_to_success()
-> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    responses.push(chunked_sse(&completed_events(false)));
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(messages_response()?);
    responses.push(json_response(br"[]"));

    let client = client_for(responses).await?;
    let result = client.run_read_only(&request(None)?).await?;
    assert_eq!(result.status, RunStatus::Succeeded);
    assert_eq!(result.authority, AuthorityCeiling::CandidateOnly);
    assert!(result.candidate_only);
    assert_eq!(result.actual_route.state, ActualRouteState::Observed);
    Ok(())
}

#[tokio::test]
async fn partial_sse_reconnects_from_last_event_id_without_joining_frames()
-> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    let message_updated = json!({
        "type": "message.updated",
        "properties": {"sessionID": SESSION_ID, "info": {
            "id": "msg_assistant_reconcile", "sessionID": SESSION_ID,
            "parentID": MESSAGE_ID, "role": "assistant",
            "time": {"created": 2, "completed": 3},
            "providerID": PROVIDER, "modelID": MODEL, "finish": "stop"
        }}
    });
    let mut first_stream = format!("id: evt-1\nretry: 1\ndata: {message_updated}\n\n").into_bytes();
    first_stream.extend_from_slice(b"data: {\"type\":\"message.part.updated\"");
    responses.push(chunked_sse(&first_stream));
    responses.push(no_content());
    let step_finish = json!({
        "type": "message.part.updated",
        "properties": {"sessionID": SESSION_ID, "part": {
            "sessionID": SESSION_ID, "messageID": "msg_assistant_reconcile",
            "type": "step-finish", "reason": "stop"
        }}
    });
    let idle = json!({
        "type": "session.status",
        "properties": {"sessionID": SESSION_ID, "status": {"type": "idle"}}
    });
    responses.push(chunked_sse(
        format!("id: evt-2\ndata: {step_finish}\n\nid: evt-3\ndata: {idle}\n\n").as_bytes(),
    ));
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(messages_response()?);
    responses.push(json_response(br"[]"));

    let (client, captured) = client_for_with_requests(responses).await?;
    let result = client.run_read_only(&request(None)?).await?;
    assert_eq!(result.status, RunStatus::Succeeded);
    let requests = captured.lock().await;
    let reconnect = requests
        .get(7)
        .ok_or("reconnect request was not captured")?;
    let reconnect = String::from_utf8_lossy(reconnect);
    assert!(reconnect.starts_with("GET /event?directory=C%3A%5CScratch HTTP/1.1\r\n"));
    assert_eq!(reconnect.matches("Last-Event-ID: evt-1\r\n").count(), 1);
    Ok(())
}

#[tokio::test]
async fn omitted_idle_status_reconciles_through_bound_session_read()
-> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    let session_response = responses
        .get(3)
        .cloned()
        .ok_or("fixture session response is missing")?;
    responses.push(chunked_sse(&completed_events(true)));
    responses.push(no_content());
    responses.push(json_response(br"{}"));
    responses.push(session_response);
    responses.push(messages_response()?);
    responses.push(json_response(br"[]"));

    let client = client_for(responses).await?;
    let result = client.run_read_only(&request(None)?).await?;
    assert_eq!(result.status, RunStatus::Succeeded);
    assert!(result.diff.is_empty());
    Ok(())
}

#[tokio::test]
async fn permission_is_aborted_and_reconciled() -> Result<(), Box<dyn std::error::Error>> {
    let baseline = vec![];
    let mut responses = preamble(false, &baseline)?;
    responses.push(chunked_sse(&sse_event(&json!({
        "type": "permission.asked",
        "properties": {"sessionID": SESSION_ID, "id": "perm_read"},
    }))));
    responses.push(no_content());
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(json_response(br"[]"));
    responses.push(json_response(br"[]"));

    let client = client_for(responses).await?;
    match client.run_read_only(&request(None)?).await {
        Err(OpenCodeRunError::PermissionRequested { permission_id }) => {
            assert_eq!(permission_id, "perm_read");
        }
        Err(other) => panic!("permission returned unexpected error: {other}"),
        Ok(result) => panic!("permission unexpectedly completed: {result:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn completion_racing_with_abort_is_not_reported_as_permission_only()
-> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    responses.push(chunked_sse(&sse_event(&json!({
        "type": "permission.asked",
        "properties": {"sessionID": SESSION_ID, "id": "perm_race"},
    }))));
    responses.push(no_content());
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(messages_response()?);
    responses.push(json_response(br"[]"));

    let client = client_for(responses).await?;
    match client.run_read_only(&request(None)?).await {
        Err(OpenCodeRunError::CompletedAfterAbort { message_id }) => {
            assert_eq!(message_id, "msg_assistant_reconcile");
        }
        Err(other) => return Err(format!("abort race returned unexpected error: {other}").into()),
        Ok(result) => {
            return Err(format!("abort race unexpectedly completed: {result:?}").into());
        }
    }
    Ok(())
}

#[tokio::test]
async fn provider_auth_error_is_aborted_and_stays_typed() -> Result<(), Box<dyn std::error::Error>>
{
    let mut responses = preamble(false, &[])?;
    responses.push(chunked_sse(&sse_event(&json!({
        "type": "session.error",
        "properties": {
            "sessionID": SESSION_ID,
            "error": {"name": "ProviderAuthError", "data": {"message": "credential rejected"}}
        }
    }))));
    responses.push(no_content());
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(json_response(br"[]"));
    responses.push(json_response(br"[]"));

    let client = client_for(responses).await?;
    match client.run_read_only(&request(None)?).await {
        Err(OpenCodeRunError::Provider { kind, message }) => {
            assert_eq!(kind, "ProviderAuthError");
            assert_eq!(message, "credential rejected");
        }
        Err(other) => panic!("provider error returned unexpected error: {other}"),
        Ok(result) => panic!("provider error unexpectedly completed: {result:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn failed_abort_produces_unknown_outcome() -> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    responses.push(chunked_sse(&sse_event(&json!({
        "type": "permission.asked",
        "properties": {"sessionID": SESSION_ID, "id": "perm_write"},
    }))));
    responses.push(no_content());
    responses.push(status_response(500, br"abort failed"));

    let client = client_for(responses).await?;
    match client.run_read_only(&request(None)?).await {
        Err(OpenCodeRunError::UnknownOutcome { cause, .. }) => {
            assert!(cause.contains("permission"));
        }
        Err(other) => panic!("failed abort returned unexpected error: {other}"),
        Ok(result) => panic!("failed abort unexpectedly completed: {result:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn busy_status_produces_unknown_outcome() -> Result<(), Box<dyn std::error::Error>> {
    let mut responses = preamble(false, &[])?;
    responses.push(chunked_sse(&sse_event(&json!({
        "type": "permission.asked",
        "properties": {"sessionID": SESSION_ID, "id": "perm_busy"},
    }))));
    responses.push(no_content());
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"busy"}}"#));

    let client = client_for(responses).await?;
    match client.run_read_only(&request(None)?).await {
        Err(OpenCodeRunError::UnknownOutcome { cause, .. }) => {
            assert!(cause.contains("permission"));
        }
        Err(other) => panic!("busy status returned unexpected error: {other}"),
        Ok(result) => panic!("busy status unexpectedly completed: {result:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn reused_session_accepts_unchanged_nonempty_baseline()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline = vec![json!({
        "file": "notes.md",
        "patch": "@@ baseline @@",
        "additions": 1,
        "deletions": 0,
        "status": "modified"
    })];
    let mut responses = preamble(true, &baseline)?;
    responses.push(chunked_sse(&completed_events(true)));
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(messages_response()?);
    responses.push(json_response(&serde_json::to_vec(&baseline)?));

    let client = client_for(responses).await?;
    let result = client.run_read_only(&request(Some(SESSION_ID))?).await?;
    assert_eq!(result.status, RunStatus::Succeeded);
    assert!(result.diff.is_empty());
    Ok(())
}

#[tokio::test]
async fn reused_session_changed_diff_is_mutation_observed() -> Result<(), Box<dyn std::error::Error>>
{
    let baseline = vec![json!({
        "file": "notes.md",
        "patch": "@@ baseline @@",
        "additions": 1,
        "deletions": 0,
        "status": "modified"
    })];
    let changed = vec![json!({
        "file": "notes.md",
        "patch": "@@ changed @@",
        "additions": 2,
        "deletions": 0,
        "status": "modified"
    })];
    let mut responses = preamble(true, &baseline)?;
    responses.push(chunked_sse(&completed_events(true)));
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_reconcile":{"type":"idle"}}"#));
    responses.push(messages_response()?);
    responses.push(json_response(&serde_json::to_vec(&changed)?));

    let client = client_for(responses).await?;
    match client.run_read_only(&request(Some(SESSION_ID))?).await {
        Err(OpenCodeRunError::MutationObserved { count }) => assert_eq!(count, 1),
        Err(other) => panic!("changed diff returned unexpected error: {other}"),
        Ok(result) => panic!("changed diff unexpectedly completed: {result:?}"),
    }
    Ok(())
}

fn request(session_id: Option<&str>) -> Result<ReadOnlyRunRequest, Box<dyn std::error::Error>> {
    let mut request =
        ReadOnlyRunRequest::new("Return JSON status.", ModelSelection::new(PROVIDER, MODEL)?)?
            .with_message_id(MESSAGE_ID)?;
    request.session_id = session_id.map(str::to_owned);
    Ok(request)
}

async fn client_for(responses: Vec<Vec<u8>>) -> Result<OpenCodeClient, Box<dyn std::error::Error>> {
    Ok(client_for_with_requests(responses).await?.0)
}

async fn client_for_with_requests(
    responses: Vec<Vec<u8>>,
) -> Result<(OpenCodeClient, Arc<Mutex<Vec<Vec<u8>>>>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(serve(listener, responses, Arc::clone(&captured)));
    let endpoint = format!("http://127.0.0.1:{port}").parse::<LoopbackEndpoint>()?;
    let policy = OpenCodeRunPolicy::new(Path::new(DIRECTORY))?
        .with_timeouts(Duration::from_secs(2), Duration::from_millis(100));
    Ok((
        OpenCodeClient::new(
            endpoint,
            BasicAuth::new("opencode", SecretString::from("secret".to_owned()))?,
            policy,
        )?,
        captured,
    ))
}

async fn serve(listener: TcpListener, responses: Vec<Vec<u8>>, captured: Arc<Mutex<Vec<Vec<u8>>>>) {
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    loop {
        let Some(response) = responses.lock().await.pop_front() else {
            break;
        };
        let accepted = listener.accept().await;
        let Ok((mut stream, _)) = accepted else {
            break;
        };
        let mut raw = Vec::<u8>::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..read]);
            let Some(head_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let content_length = String::from_utf8_lossy(&raw[..head_end])
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if raw.len() >= head_end + 4 + content_length {
                break;
            }
        }
        captured.lock().await.push(raw);
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
    }
}

fn preamble(reused: bool, baseline: &[Value]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut responses = vec![
        json_response(br#"{"healthy":true,"version":"1.4.3"}"#),
        json_response(br#"{"all":[{"id":"opencode-go","models":{"deepseek-v4-flash":{"id":"deepseek-v4-flash"}}}],"default":{},"connected":["opencode-go"]}"#),
        json_response(br#"[{"name":"plan","mode":"primary","permission":{},"options":{}}]"#),
    ];
    let session = serde_json::to_vec(&json!({
        "id": SESSION_ID,
        "slug": "reconcile",
        "projectID": "p",
        "directory": DIRECTORY,
        "title": "ELIOT",
        "version": "1.4.3",
        "time": {"created": 1, "updated": 1},
        "permission": [
            {"permission": "*", "pattern": "*", "action": "deny"},
            {"permission": "read", "pattern": "*", "action": "allow"},
            {"permission": "read", "pattern": "*.env", "action": "deny"},
            {"permission": "read", "pattern": "*.env.*", "action": "deny"},
            {"permission": "glob", "pattern": "*", "action": "allow"},
            {"permission": "grep", "pattern": "*", "action": "allow"},
            {"permission": "list", "pattern": "*", "action": "allow"}
        ]
    }))?;
    responses.push(json_response(&session));
    responses.push(json_response(&serde_json::to_vec(baseline)?));
    let _ = reused;
    Ok(responses)
}

fn completed_events(include_idle: bool) -> Vec<u8> {
    let mut events = vec![
        sse_event(
            &json!({"type":"message.updated","properties":{"sessionID":SESSION_ID,"info":{
                "id":"msg_assistant_reconcile","sessionID":SESSION_ID,"parentID":MESSAGE_ID,"role":"assistant",
                "time":{"created":2,"completed":3},"providerID":PROVIDER,"modelID":MODEL,"finish":"stop"
            }}}),
        ),
        sse_event(
            &json!({"type":"message.part.updated","properties":{"sessionID":SESSION_ID,"part":{
                "sessionID":SESSION_ID,"messageID":"msg_assistant_reconcile","type":"step-finish","reason":"stop"
            }}}),
        ),
    ];
    if include_idle {
        events.push(sse_event(&json!({"type":"session.status","properties":{"sessionID":SESSION_ID,"status":{"type":"idle"}}})));
    }
    events.concat()
}

fn messages_response() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let assistant = json!({"info": {"id":"msg_assistant_reconcile","sessionID":SESSION_ID,"role":"assistant",
        "time":{"created":2,"completed":3},"parentID":MESSAGE_ID,"modelID":MODEL,"providerID":PROVIDER,
        "mode":"plan","agent":"plan","path":{"cwd":DIRECTORY,"root":DIRECTORY},"cost":0.01,
        "tokens":{"total":12,"input":7,"output":5,"reasoning":0,"cache":{"read":0,"write":0}},
        "finish":"stop"},
        "parts":[{"id":"part_text","sessionID":SESSION_ID,"messageID":"msg_assistant_reconcile","type":"text","text":"{\"status\":\"ready\"}"},{"id":"part_1","sessionID":SESSION_ID,"messageID":"msg_assistant_reconcile","type":"step-finish","reason":"stop"}]});
    let user = json!({"info":{"id":MESSAGE_ID,"sessionID":SESSION_ID,"role":"user","time":{"created":1},
        "format":{"type":"text"},"agent":"plan",
        "model":{"providerID":PROVIDER,"modelID":MODEL}},"parts":[]});
    Ok(json_response(&serde_json::to_vec(&json!([
        user, assistant
    ]))?))
}

fn sse_event(event: &Value) -> Vec<u8> {
    let encoded = event.to_string();
    format!("data: {encoded}\n\n").into_bytes()
}

fn chunked_sse(body: &[u8]) -> Vec<u8> {
    let mut response =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    response.extend_from_slice(format!("{:X}\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    response
}

fn json_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec()
}

fn status_response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}
