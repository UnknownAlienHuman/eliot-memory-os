use eliot_agent_codex::{correlate_response, CodexAdapterError, CodexWireMessage};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mixed_request_and_success_response_is_rejected_during_parsing() {
    let mixed = br#"{
        "id":"models-1",
        "method":"model/list",
        "params":{"includeHidden":false},
        "result":{"data":[]}
    }"#;

    assert!(matches!(
        CodexWireMessage::parse_line(mixed),
        Err(CodexAdapterError::MalformedWire(_))
    ));
}

#[test]
fn response_correlation_cannot_accept_a_mixed_envelope() {
    let mixed = CodexWireMessage {
        id: Some(Value::String("models-1".to_owned())),
        message_type: None,
        method: Some("model/list".to_owned()),
        params: Some(json!({"includeHidden": false})),
        result: Some(json!({"data": []})),
        error: None,
    };

    assert!(matches!(
        correlate_response(&mixed, "models-1"),
        Err(CodexAdapterError::MalformedWire(_))
    ));
}

#[test]
fn request_notification_success_and_error_are_disjoint_valid_classes() -> TestResult {
    let request = CodexWireMessage::parse_line(
        br#"{"id":"server-1","method":"server/request","params":{"value":1}}"#,
    )?;
    let notification = CodexWireMessage::parse_line(
        br#"{"method":"server/notification","params":{"value":1}}"#,
    )?;
    let success =
        CodexWireMessage::parse_line(br#"{"id":"server-1","result":{"value":1}}"#)?;
    let error = CodexWireMessage::parse_line(
        br#"{"id":"server-1","error":{"message":"provider-private"}}"#,
    )?;

    assert!(correlate_response(&request, "server-1").is_err());
    assert!(correlate_response(&notification, "server-1").is_err());
    assert_eq!(correlate_response(&success, "server-1")?["value"], 1);

    let public_error = correlate_response(&error, "server-1")
        .expect_err("provider errors must not become successful responses")
        .to_string();
    assert!(!public_error.contains("provider-private"));
    Ok(())
}

#[test]
fn response_params_and_other_mixed_shapes_are_rejected() {
    for line in [
        br#"{"id":"1","result":{},"params":{}}"#.as_slice(),
        br#"{"id":"1","error":{},"params":{}}"#.as_slice(),
        br#"{"method":"x","result":{}}"#.as_slice(),
        br#"{"method":"x","error":{}}"#.as_slice(),
        br#"{"id":"1","method":"x","error":{}}"#.as_slice(),
        br#"{"id":"1"}"#.as_slice(),
        br#"{"result":{}}"#.as_slice(),
        br#"{"error":{}}"#.as_slice(),
    ] {
        assert!(CodexWireMessage::parse_line(line).is_err());
    }
}

#[test]
fn method_and_compatibility_type_labels_are_bounded_text() {
    for line in [
        br#"{"method":""}"#.as_slice(),
        br#"{"method":" model/list","params":{}}"#.as_slice(),
        br#"{"method":"model/list ","params":{}}"#.as_slice(),
        b"{\"method\":\"model/\\u0000list\",\"params\":{}}".as_slice(),
        br#"{"id":"1","result":{},"type":" response"}"#.as_slice(),
    ] {
        assert!(CodexWireMessage::parse_line(line).is_err());
    }
}

#[test]
fn stable_request_constructors_still_emit_request_only_envelopes() -> TestResult {
    for message in [
        CodexWireMessage::initialize("initialize-1", "eliot", "0.1.0"),
        CodexWireMessage::model_list("models-1", None, false, Some(64)),
        CodexWireMessage::account_rate_limits("quota-1"),
        CodexWireMessage::thread_start("thread-1", r"C:\workspace"),
        CodexWireMessage::turn_start(
            "turn-1",
            "thread-1",
            &json!([{"type":"text","text":"x"}]),
        ),
        CodexWireMessage::turn_interrupt("interrupt-1", "thread-1", "turn-1"),
    ] {
        let bytes = serde_json::to_vec(&message)?;
        let parsed = CodexWireMessage::parse_line(&bytes)?;
        assert!(parsed.id.is_some());
        assert!(parsed.method.is_some());
        assert!(parsed.result.is_none());
        assert!(parsed.error.is_none());
    }

    let initialized = CodexWireMessage::initialized();
    let bytes = serde_json::to_vec(&initialized)?;
    let parsed = CodexWireMessage::parse_line(&bytes)?;
    assert!(parsed.id.is_none());
    assert_eq!(parsed.method.as_deref(), Some("initialized"));
    assert!(parsed.result.is_none());
    assert!(parsed.error.is_none());
    Ok(())
}
