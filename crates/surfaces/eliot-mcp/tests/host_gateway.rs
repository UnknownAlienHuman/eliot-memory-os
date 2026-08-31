#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{collections::BTreeMap, error::Error};

use eliot_mcp::{
    ClientCapabilities, HostCancellationOutcome, HostCancellationPortOutcome,
    HostCancellationRequest, HostContractError, HostCorrelationId, HostGatewayError,
    HostInvocationOutcome, HostInvocationPortOutcome, HostInvocationRequest, HostObservedContext,
    HostOperationHandle, HostRequestGateway, KernelHostRequestPort, McpProtocolVersion,
    McpResponse, PortFailure, ResponseKind, StateInput, ToolRequest,
};
use eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
use eliot_receipts::ProofCeiling;
use serde_json::json;

#[derive(Default)]
struct FakePort {
    invoke_calls: usize,
    cancel_calls: usize,
    last_invoke: Option<HostInvocationRequest>,
    last_cancel: Option<HostCancellationRequest>,
    invoke_result: Option<Result<HostInvocationPortOutcome, PortFailure>>,
    cancel_result: Option<Result<HostCancellationPortOutcome, PortFailure>>,
}

impl KernelHostRequestPort for FakePort {
    fn invoke(
        &mut self,
        request: &HostInvocationRequest,
    ) -> Result<HostInvocationPortOutcome, PortFailure> {
        self.invoke_calls += 1;
        self.last_invoke = Some(request.clone());
        self.invoke_result.take().unwrap_or_else(|| {
            Err(PortFailure::Unsupported {
                capability: "host.invoke".to_owned(),
                reason: "fixture result missing".to_owned(),
            })
        })
    }

    fn cancel(
        &mut self,
        request: &HostCancellationRequest,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        self.cancel_calls += 1;
        self.last_cancel = Some(request.clone());
        self.cancel_result.take().unwrap_or_else(|| {
            Err(PortFailure::Unsupported {
                capability: "host.cancel".to_owned(),
                reason: "fixture result missing".to_owned(),
            })
        })
    }
}

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
            observed_resource_refs: Vec::new(),
            event_cursors: Vec::new(),
            trace_context: BTreeMap::from([("traceparent".to_owned(), "trace-1".to_owned())]),
        },
    })
}

fn cancellation() -> Result<HostCancellationRequest, HostContractError> {
    Ok(HostCancellationRequest {
        protocol_version: McpProtocolVersion::Final2026_07_28,
        correlation_id: HostCorrelationId::new("host-cancel-1")?,
        operation_handle: HostOperationHandle::new("kernel-operation-1")?,
        reason: None,
        deadline_preference_ms: Some(2_000),
        observed_context: HostObservedContext::default(),
    })
}

fn response(tool: &str) -> McpResponse {
    McpResponse {
        request_id: "kernel-request-1".to_owned(),
        idempotency_key: "kernel-idempotency-1".to_owned(),
        canonical_request_sha256: "a".repeat(64),
        kind: ResponseKind::Projection,
        canonical_tool_name: tool.to_owned(),
        content: json!({"projection": "current"}),
        artifacts: Vec::new(),
        proof_ceiling: ProofCeiling::Observation,
        resource: None,
        job: None,
        compatibility_correlation_hint: None,
    }
}

#[test]
fn valid_invocation_is_correlated_and_forwarded_unchanged() -> Result<(), Box<dyn Error>> {
    let request = invocation()?;
    let expected = request.clone();
    let operation_handle = HostOperationHandle::new("kernel-operation-responded")?;
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Responded {
            operation_handle: operation_handle.clone(),
            response: Box::new(response("eliot.state")),
        })),
        ..FakePort::default()
    };

    let result = HostRequestGateway.invoke(&mut port, &request)?;
    assert_eq!(result.correlation_id().as_str(), "host-request-1");
    match result.outcome() {
        HostInvocationOutcome::Responded {
            operation_handle: observed,
            response,
        } => {
            assert_eq!(observed, &operation_handle);
            assert_eq!(response.canonical_tool_name, "eliot.state");
            assert_eq!(response.request_id, "kernel-request-1");
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(port.invoke_calls, 1);
    assert_eq!(port.last_invoke, Some(expected));
    Ok(())
}

#[test]
fn accepted_invocation_preserves_kernel_operation_handle() -> Result<(), Box<dyn Error>> {
    let request = invocation()?;
    let operation_handle = HostOperationHandle::new("kernel-operation-pending")?;
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Accepted {
            operation_handle: operation_handle.clone(),
        })),
        ..FakePort::default()
    };

    let result = HostRequestGateway.invoke(&mut port, &request)?;
    assert!(matches!(
        result.outcome(),
        HostInvocationOutcome::Accepted { operation_handle: observed }
            if observed == &operation_handle
    ));
    assert_eq!(
        result.correlation_id().as_str(),
        request.correlation_id.as_str()
    );
    Ok(())
}

#[test]
fn typed_port_failure_remains_correlated() -> Result<(), Box<dyn Error>> {
    let request = invocation()?;
    let failure = PortFailure::PlanGap {
        missing_capability: "kernel.host-request.bind".to_owned(),
        reason: "identity binding not admitted".to_owned(),
    };
    let mut port = FakePort {
        invoke_result: Some(Err(failure.clone())),
        ..FakePort::default()
    };

    let result = HostRequestGateway.invoke(&mut port, &request)?;
    assert_eq!(result.correlation_id().as_str(), "host-request-1");
    assert!(matches!(
        result.outcome(),
        HostInvocationOutcome::Rejected { failure: observed } if observed == &failure
    ));
    assert_eq!(port.invoke_calls, 1);
    Ok(())
}

#[test]
fn invalid_host_input_never_calls_the_port() -> Result<(), Box<dyn Error>> {
    let mut request = invocation()?;
    request.deadline_preference_ms = Some(0);
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Accepted {
            operation_handle: HostOperationHandle::new("must-not-be-issued")?,
        })),
        ..FakePort::default()
    };

    let error = HostRequestGateway
        .invoke(&mut port, &request)
        .expect_err("invalid input must fail before the trusted port");
    assert!(matches!(error, HostGatewayError::HostContract(_)));
    assert_eq!(port.invoke_calls, 0);
    assert!(port.last_invoke.is_none());
    Ok(())
}

#[test]
fn mismatched_or_overclaiming_provider_projection_fails_closed() -> Result<(), Box<dyn Error>> {
    let request = invocation()?;
    let mut mismatched = response("eliot.query");
    mismatched.proof_ceiling = ProofCeiling::ScopedVerification;
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Responded {
            operation_handle: HostOperationHandle::new("kernel-operation-mismatch")?,
            response: Box::new(mismatched),
        })),
        ..FakePort::default()
    };
    let error = HostRequestGateway
        .invoke(&mut port, &request)
        .expect_err("provider cannot substitute another canonical operation");
    assert!(matches!(
        error,
        HostGatewayError::InvalidPortResult {
            field: "response.canonical_tool_name",
            ..
        }
    ));

    let mut overclaim = response("eliot.state");
    overclaim.proof_ceiling = ProofCeiling::ObservedExternalEffect;
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Responded {
            operation_handle: HostOperationHandle::new("kernel-operation-overclaim")?,
            response: Box::new(overclaim),
        })),
        ..FakePort::default()
    };
    let error = HostRequestGateway
        .invoke(&mut port, &request)
        .expect_err("MCP projection cannot claim external-effect proof");
    assert!(matches!(
        error,
        HostGatewayError::InvalidPortResult {
            field: "response.proof_ceiling",
            ..
        }
    ));
    Ok(())
}

#[test]
fn malformed_digest_and_oversized_response_fail_closed() -> Result<(), Box<dyn Error>> {
    let request = invocation()?;
    let mut malformed = response("eliot.state");
    malformed.canonical_request_sha256 = "not-a-digest".to_owned();
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Responded {
            operation_handle: HostOperationHandle::new("kernel-operation-digest")?,
            response: Box::new(malformed),
        })),
        ..FakePort::default()
    };
    assert!(matches!(
        HostRequestGateway.invoke(&mut port, &request),
        Err(HostGatewayError::InvalidPortResult {
            field: "response.canonical_request_sha256",
            ..
        })
    ));

    let mut oversized = response("eliot.state");
    oversized.content = json!({"payload": "x".repeat(HARD_STRUCTURED_RESPONSE_BYTES)});
    let mut port = FakePort {
        invoke_result: Some(Ok(HostInvocationPortOutcome::Responded {
            operation_handle: HostOperationHandle::new("kernel-operation-oversized")?,
            response: Box::new(oversized),
        })),
        ..FakePort::default()
    };
    assert!(matches!(
        HostRequestGateway.invoke(&mut port, &request),
        Err(HostGatewayError::ResponseTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn cancellation_without_prose_echoes_exact_target() -> Result<(), Box<dyn Error>> {
    let request = cancellation()?;
    let expected = request.clone();
    let mut port = FakePort {
        cancel_result: Some(Ok(HostCancellationPortOutcome::Accepted)),
        ..FakePort::default()
    };

    let result = HostRequestGateway.cancel(&mut port, &request)?;
    assert_eq!(result.correlation_id().as_str(), "host-cancel-1");
    assert_eq!(result.operation_handle().as_str(), "kernel-operation-1");
    assert_eq!(result.outcome(), &HostCancellationOutcome::Accepted);
    assert_eq!(port.cancel_calls, 1);
    assert_eq!(port.last_cancel, Some(expected));
    Ok(())
}

#[test]
fn cancellation_failure_and_terminal_state_remain_exact() -> Result<(), Box<dyn Error>> {
    let request = cancellation()?;
    let mut terminal_port = FakePort {
        cancel_result: Some(Ok(HostCancellationPortOutcome::AlreadyTerminal)),
        ..FakePort::default()
    };
    let terminal = HostRequestGateway.cancel(&mut terminal_port, &request)?;
    assert_eq!(
        terminal.outcome(),
        &HostCancellationOutcome::AlreadyTerminal
    );
    assert_eq!(
        terminal.operation_handle().as_str(),
        request.operation_handle.as_str()
    );

    let failure = PortFailure::FenceMismatch;
    let mut rejected_port = FakePort {
        cancel_result: Some(Err(failure.clone())),
        ..FakePort::default()
    };
    let rejected = HostRequestGateway.cancel(&mut rejected_port, &request)?;
    assert!(matches!(
        rejected.outcome(),
        HostCancellationOutcome::Rejected { failure: observed } if observed == &failure
    ));
    assert_eq!(rejected.operation_handle().as_str(), "kernel-operation-1");
    Ok(())
}
