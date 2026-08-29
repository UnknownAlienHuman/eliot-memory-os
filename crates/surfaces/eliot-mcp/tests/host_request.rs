#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{collections::BTreeMap, error::Error};

use eliot_mcp::{
    ClientCapabilities, HostCancellationRequest, HostContractError, HostCorrelationId,
    HostEventStreamId, HostInvocationRequest, HostObservedContext, HostObservedEventCursor,
    HostObservedResourceRef, HostOperationHandle, McpProtocolVersion, StateInput, ToolRequest,
    MAX_HOST_CORRELATION_BYTES, MAX_HOST_DEADLINE_PREFERENCE_MS, MAX_HOST_EVENT_CURSORS,
    MAX_HOST_RESOURCE_REF_BYTES, MAX_HOST_RESOURCE_REFS, MAX_HOST_TRACE_ENTRIES,
    canonical_schema,
};
use serde_json::{Value, json};

fn invocation() -> Result<HostInvocationRequest, HostContractError> {
    Ok(HostInvocationRequest {
        protocol_version: McpProtocolVersion::Final2026_07_28,
        correlation_id: HostCorrelationId::new("host-request-1")?,
        client_capabilities: ClientCapabilities { tasks: true },
        tool: ToolRequest::State(StateInput {
            include: vec!["task".to_owned(), "attention".to_owned()],
        }),
        deadline_preference_ms: Some(5_000),
        observed_context: HostObservedContext {
            host_session_hint: Some("host-turn-7".to_owned()),
            observed_resource_refs: vec![HostObservedResourceRef::new(
                "host-resource:editor-buffer-1",
            )?],
            event_cursors: vec![HostObservedEventCursor::new(
                HostEventStreamId::new("host-events:editor-1")?,
                42,
            )?],
            trace_context: BTreeMap::from([("traceparent".to_owned(), "trace-1".to_owned())]),
        },
    })
}

#[test]
fn host_invocation_omits_kernel_identity_and_authority() -> Result<(), Box<dyn Error>> {
    let request = invocation()?;
    request.validate()?;
    let value = serde_json::to_value(&request)?;
    let object = value.as_object().expect("request must be an object");
    for forbidden in [
        "request_identity",
        "identity",
        "session",
        "session_id",
        "principal",
        "principal_id",
        "task_id",
        "work_scope_id",
        "state_fence",
        "authority_epoch",
        "lease",
        "effect_ceiling",
        "idempotency_key",
        "cancellation_id",
        "deadline_unix_ms",
    ] {
        assert!(!object.contains_key(forbidden), "forbidden field {forbidden}");
    }

    let mut forged = value;
    forged
        .as_object_mut()
        .expect("request must be an object")
        .insert("request_identity".to_owned(), json!({"forged": true}));
    assert!(serde_json::from_value::<HostInvocationRequest>(forged).is_err());
    Ok(())
}

#[test]
fn host_invoke_and_cancel_roundtrip() -> Result<(), Box<dyn Error>> {
    let invocation = invocation()?;
    let encoded = serde_json::to_vec(&invocation)?;
    let decoded: HostInvocationRequest = serde_json::from_slice(&encoded)?;
    decoded.validate()?;
    assert_eq!(decoded, invocation);

    let cancel = HostCancellationRequest {
        protocol_version: McpProtocolVersion::Final2026_07_28,
        correlation_id: HostCorrelationId::new("host-cancel-1")?,
        operation_handle: HostOperationHandle::new("kernel-operation-handle-1")?,
        reason: None,
        deadline_preference_ms: Some(2_000),
        observed_context: HostObservedContext::default(),
    };
    cancel.validate()?;
    let encoded = serde_json::to_vec(&cancel)?;
    let decoded: HostCancellationRequest = serde_json::from_slice(&encoded)?;
    decoded.validate()?;
    assert_eq!(decoded, cancel);
    Ok(())
}

#[test]
fn host_context_bounds_and_stream_identity_are_enforced() -> Result<(), Box<dyn Error>> {
    let mut request = invocation()?;
    request.deadline_preference_ms = Some(0);
    assert!(request.validate().is_err());
    request.deadline_preference_ms = Some(MAX_HOST_DEADLINE_PREFERENCE_MS + 1);
    assert!(request.validate().is_err());
    assert!(HostCorrelationId::new("x".repeat(MAX_HOST_CORRELATION_BYTES + 1)).is_err());
    assert!(
        HostObservedResourceRef::new("x".repeat(MAX_HOST_RESOURCE_REF_BYTES + 1)).is_err()
    );

    let mut request = invocation()?;
    request.observed_context.host_session_hint = Some("x".repeat(513));
    assert!(request.validate().is_err());

    let mut request = invocation()?;
    request.observed_context.observed_resource_refs = (0..=MAX_HOST_RESOURCE_REFS)
        .map(|index| HostObservedResourceRef::new(format!("resource-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(request.validate().is_err());

    let mut request = invocation()?;
    let duplicated = HostObservedResourceRef::new("resource-1")?;
    request.observed_context.observed_resource_refs = vec![duplicated.clone(), duplicated];
    assert!(request.validate().is_err());

    let mut request = invocation()?;
    request.observed_context.event_cursors = (0..=MAX_HOST_EVENT_CURSORS)
        .map(|index| {
            HostObservedEventCursor::new(
                HostEventStreamId::new(format!("stream-{index}"))?,
                u64::try_from(index + 1).expect("bounded fixture index"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(request.validate().is_err());

    let mut request = invocation()?;
    let stream = HostEventStreamId::new("stream-1")?;
    request.observed_context.event_cursors = vec![
        HostObservedEventCursor::new(stream.clone(), 1)?,
        HostObservedEventCursor::new(stream, 2)?,
    ];
    assert!(request.validate().is_err());

    assert!(
        HostObservedEventCursor::new(HostEventStreamId::new("stream-zero")?, 0).is_err()
    );

    let mut request = invocation()?;
    request
        .observed_context
        .trace_context
        .insert("bad\nkey".to_owned(), "value".to_owned());
    assert!(request.validate().is_err());

    let mut request = invocation()?;
    request.observed_context.trace_context = (0..=MAX_HOST_TRACE_ENTRIES)
        .map(|index| (format!("trace-{index}"), "value".to_owned()))
        .collect();
    assert!(request.validate().is_err());
    Ok(())
}

#[test]
fn cancellation_reason_is_optional_and_bounded() -> Result<(), Box<dyn Error>> {
    let mut cancel = HostCancellationRequest {
        protocol_version: McpProtocolVersion::Final2026_07_28,
        correlation_id: HostCorrelationId::new("host-cancel-2")?,
        operation_handle: HostOperationHandle::new("kernel-operation-handle-2")?,
        reason: None,
        deadline_preference_ms: None,
        observed_context: HostObservedContext::default(),
    };
    cancel.validate()?;

    cancel.reason = Some("  ".to_owned());
    assert!(cancel.validate().is_err());
    cancel.reason = Some("x".repeat(1_025));
    assert!(cancel.validate().is_err());
    Ok(())
}

#[test]
fn operation_handle_is_opaque_and_unknown_fields_fail_closed() -> Result<(), Box<dyn Error>> {
    let handle = HostOperationHandle::new("opaque:operation:1")?;
    assert_eq!(handle.as_str(), "opaque:operation:1");
    assert!(HostOperationHandle::new("\n").is_err());

    let mut value = serde_json::to_value(invocation()?)?;
    value
        .get_mut("observed_context")
        .and_then(Value::as_object_mut)
        .expect("observed context must be an object")
        .insert("session_id".to_owned(), Value::String("forged".to_owned()));
    assert!(serde_json::from_value::<HostInvocationRequest>(value).is_err());

    let mut value = serde_json::to_value(invocation()?)?;
    value
        .as_object_mut()
        .expect("request must be an object")
        .insert("effect_ceiling".to_owned(), Value::String("critical".to_owned()));
    assert!(serde_json::from_value::<HostInvocationRequest>(value).is_err());

    let cancel = HostCancellationRequest {
        protocol_version: McpProtocolVersion::Final2026_07_28,
        correlation_id: HostCorrelationId::new("host-cancel-forgery")?,
        operation_handle: HostOperationHandle::new("operation-forgery")?,
        reason: None,
        deadline_preference_ms: None,
        observed_context: HostObservedContext::default(),
    };
    let mut value = serde_json::to_value(cancel)?;
    value
        .as_object_mut()
        .expect("cancellation must be an object")
        .insert("cancellation_id".to_owned(), Value::String("forged".to_owned()));
    assert!(serde_json::from_value::<HostCancellationRequest>(value).is_err());
    Ok(())
}

#[test]
fn host_contracts_use_generated_schema_path() -> Result<(), Box<dyn Error>> {
    let invocation_schema = canonical_schema::<HostInvocationRequest>()?;
    let cancellation_schema = canonical_schema::<HostCancellationRequest>()?;
    assert!(invocation_schema.is_object());
    assert!(cancellation_schema.is_object());
    Ok(())
}
