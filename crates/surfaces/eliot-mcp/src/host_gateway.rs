//! Stateless host-request correlation and trusted-port translation.
//!
//! This module validates inert host input, delegates identity/session/task/
//! authority binding to an injected Kernel/Governor port, and restores the
//! caller's opaque correlation on every result. It owns no durable state,
//! request identity, retry ledger, authority, semantic admission, or finish.

use eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
use serde::Serialize;
use thiserror::Error;

use crate::{
    ContractViolation, HostCancellationRequest, HostContractError, HostCorrelationId,
    HostInvocationRequest, HostOperationHandle, McpResponse, PortFailure, RequestCorrelation,
    validate_proof_ceiling,
};

/// Stable revision of the stateless host-request gateway contract.
pub const HOST_REQUEST_GATEWAY_CONTRACT_REVISION: &str = "1.0.0";

/// Trusted Kernel/Governor boundary for inert host invocation and cancellation.
///
/// The implementation owns authentication, application Session/task binding,
/// RequestIdentity issuance, absolute deadline, idempotency, authority/fence
/// validation, semantic dispatch, cancellation targeting, and reconciliation.
/// This crate only validates and correlates the host-facing contract.
pub trait KernelHostRequestPort {
    /// Binds and dispatches one validated inert host invocation.
    fn invoke(
        &mut self,
        request: &HostInvocationRequest,
    ) -> Result<HostInvocationPortOutcome, PortFailure>;

    /// Binds and submits one validated cancellation request.
    fn cancel(
        &mut self,
        request: &HostCancellationRequest,
    ) -> Result<HostCancellationPortOutcome, PortFailure>;
}

/// Positive result returned by the trusted port for one invocation.
///
/// A typed [`PortFailure`] is returned through the trait error and is converted
/// into a correlated `Rejected` host result by [`HostRequestGateway`].
#[derive(Clone, Debug, PartialEq)]
pub enum HostInvocationPortOutcome {
    /// Kernel admitted the operation and returned its opaque handle; a later
    /// response/job/event resolves the operation.
    Accepted {
        /// Opaque Kernel-issued operation handle.
        operation_handle: HostOperationHandle,
    },
    /// Kernel/Governor returned one bounded MCP candidate/projection response.
    Responded {
        /// Opaque Kernel-issued operation handle.
        operation_handle: HostOperationHandle,
        /// Existing bounded MCP response contract.
        response: Box<McpResponse>,
    },
}

/// Positive result returned by the trusted port for one cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCancellationPortOutcome {
    /// Cancellation was accepted for the exact operation.
    Accepted,
    /// The exact operation was already terminal; no new cancellation effect was issued.
    AlreadyTerminal,
}

/// Correlated host-facing invocation disposition.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostInvocationOutcome {
    /// Kernel admitted the operation and returned its opaque handle.
    Accepted {
        /// Opaque Kernel-issued operation handle.
        operation_handle: HostOperationHandle,
    },
    /// Kernel/Governor returned a bounded candidate/projection response.
    Responded {
        /// Opaque Kernel-issued operation handle.
        operation_handle: HostOperationHandle,
        /// Existing MCP response; it is not a finish or authority verdict.
        response: Box<McpResponse>,
    },
    /// The trusted owner returned a typed non-success disposition.
    Rejected {
        /// Provider-neutral typed failure with no loss of host correlation.
        failure: PortFailure,
    },
}

/// One host invocation result correlated by the gateway, not by the provider.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostInvocationResult {
    correlation_id: HostCorrelationId,
    outcome: HostInvocationOutcome,
}

impl HostInvocationResult {
    /// Returns the exact opaque host correlation from the request.
    #[must_use]
    pub const fn correlation_id(&self) -> &HostCorrelationId {
        &self.correlation_id
    }

    /// Returns the typed invocation disposition.
    #[must_use]
    pub const fn outcome(&self) -> &HostInvocationOutcome {
        &self.outcome
    }

    /// Builds the immutable completion receipt bound to this result's correlation.
    ///
    /// Owner-reported deadline and cancellation keep their exact meaning; any
    /// other typed rejection stays a rejection with its failure preserved.
    /// Nothing here infers success, failure, or timeout from missing host/UI
    /// observability: a response that was emitted and flushed but whose host
    /// completion is unobserved keeps its admitted/responded disposition with
    /// a recovery directive instead of becoming a timeout.
    #[must_use]
    pub fn completion_receipt(&self) -> HostCorrelationReceipt {
        let outcome = match &self.outcome {
            HostInvocationOutcome::Accepted { operation_handle } => {
                HostCompletionOutcome::Admitted {
                    operation_handle: operation_handle.clone(),
                }
            }
            HostInvocationOutcome::Responded {
                operation_handle,
                response,
            } => HostCompletionOutcome::RespondedInline {
                operation_handle: operation_handle.clone(),
                correlation: response.correlation(),
            },
            HostInvocationOutcome::Rejected { failure } => match failure {
                PortFailure::DeadlineExceeded => HostCompletionOutcome::OwnerDeadlineExceeded,
                PortFailure::Cancelled => HostCompletionOutcome::OwnerCancelled,
                other => HostCompletionOutcome::OwnerRejected {
                    failure: other.clone(),
                },
            },
        };
        let recovery = match &outcome {
            HostCompletionOutcome::Admitted { operation_handle }
            | HostCompletionOutcome::RespondedInline {
                operation_handle, ..
            } => CompletionRecovery::ReconnectAndReconcile {
                operation_handle: operation_handle.clone(),
            },
            HostCompletionOutcome::OwnerDeadlineExceeded
            | HostCompletionOutcome::OwnerCancelled
            | HostCompletionOutcome::OwnerRejected { .. } => CompletionRecovery::RefreshStatus,
        };
        HostCorrelationReceipt {
            correlation_id: self.correlation_id.clone(),
            outcome,
            recovery,
        }
    }
}

/// Correlated host-facing cancellation disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostCancellationOutcome {
    /// Cancellation was accepted for the exact target operation.
    Accepted,
    /// The exact target was already terminal and was not cancelled again.
    AlreadyTerminal,
    /// The trusted owner returned a typed non-success disposition.
    Rejected {
        /// Provider-neutral typed failure with no loss of host correlation.
        failure: PortFailure,
    },
}

/// One cancellation result. The gateway always echoes the caller's exact target
/// handle so the trusted port cannot silently redirect the host-visible result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCancellationResult {
    correlation_id: HostCorrelationId,
    operation_handle: HostOperationHandle,
    outcome: HostCancellationOutcome,
}

impl HostCancellationResult {
    /// Returns the exact opaque host correlation from the cancellation request.
    #[must_use]
    pub const fn correlation_id(&self) -> &HostCorrelationId {
        &self.correlation_id
    }

    /// Returns the exact caller-supplied Kernel operation handle.
    #[must_use]
    pub const fn operation_handle(&self) -> &HostOperationHandle {
        &self.operation_handle
    }

    /// Returns the typed cancellation disposition.
    #[must_use]
    pub const fn outcome(&self) -> &HostCancellationOutcome {
        &self.outcome
    }
}

/// Immutable receipt binding one host correlation to its completion disposition.
///
/// Built by the gateway from the exact request correlation and the trusted
/// port outcome, then carried into the bridge stdio bytes so the request,
/// response, emission, and host completion stay bound without inferring
/// success, failure, or timeout from missing observability.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCorrelationReceipt {
    correlation_id: HostCorrelationId,
    outcome: HostCompletionOutcome,
    recovery: CompletionRecovery,
}

impl HostCorrelationReceipt {
    /// Returns the exact opaque host correlation from the request.
    #[must_use]
    pub const fn correlation_id(&self) -> &HostCorrelationId {
        &self.correlation_id
    }

    /// Returns the typed host-side completion outcome.
    #[must_use]
    pub const fn outcome(&self) -> &HostCompletionOutcome {
        &self.outcome
    }

    /// Returns the recovery directive for this disposition.
    ///
    /// Admitted and inline-responded completions reconcile the exact Kernel
    /// operation handle after a reconnect; every other disposition refreshes
    /// bridge status without issuing a new invocation effect.
    #[must_use]
    pub const fn recovery(&self) -> &CompletionRecovery {
        &self.recovery
    }
}

/// Typed host-side completion outcome.
///
/// Owner-reported timeout and cancellation are distinct from every other
/// disposition. A completed response whose host completion is unobserved keeps
/// its admitted/responded shape; it is never rewritten into a timeout here.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostCompletionOutcome {
    /// Kernel admitted the operation; the handle resolves completion later.
    Admitted {
        /// Opaque Kernel-issued operation handle.
        operation_handle: HostOperationHandle,
    },
    /// Kernel/Governor returned a bounded response inline with its correlation.
    RespondedInline {
        /// Opaque Kernel-issued operation handle.
        operation_handle: HostOperationHandle,
        /// Immutable request binding echoed by the inline response.
        correlation: RequestCorrelation,
    },
    /// The trusted owner reported its own deadline; the operation did not run.
    OwnerDeadlineExceeded,
    /// The trusted owner reported cancellation by the canonical identity.
    OwnerCancelled,
    /// The trusted owner returned any other typed non-success disposition.
    OwnerRejected {
        /// Provider-neutral typed failure with no loss of host correlation.
        failure: PortFailure,
    },
}

/// Recovery directive for one correlated host completion.
///
/// It names only the bridge-owned recovery route (reconnect, refresh, status);
/// it issues no new invocation effect and mints no identity or authority.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletionRecovery {
    /// Reconnect the bridge transport and reconcile the exact operation.
    ReconnectAndReconcile {
        /// Opaque Kernel-issued operation handle to reconcile.
        operation_handle: HostOperationHandle,
    },
    /// Refresh bridge status; no new invocation effect may be issued.
    RefreshStatus,
}

/// Pure stateless host-request gateway.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostRequestGateway;

impl HostRequestGateway {
    /// Validates and sends one inert invocation through the trusted port.
    ///
    /// Semantic/provider rejection is returned as a correlated host result.
    /// Only malformed host input or a malformed trusted-port response is a
    /// gateway error.
    pub fn invoke<P: KernelHostRequestPort + ?Sized>(
        &self,
        port: &mut P,
        request: &HostInvocationRequest,
    ) -> Result<HostInvocationResult, HostGatewayError> {
        self.invoke_with_receipt(port, request)
            .map(|paired| paired.0)
    }

    /// Validates and sends one inert invocation, returning the correlated
    /// result together with its immutable completion receipt.
    ///
    /// The receipt binds the exact host correlation to the trusted-port
    /// disposition and its recovery directive; error semantics match
    /// [`HostRequestGateway::invoke`].
    pub fn invoke_with_receipt<P: KernelHostRequestPort + ?Sized>(
        &self,
        port: &mut P,
        request: &HostInvocationRequest,
    ) -> Result<(HostInvocationResult, HostCorrelationReceipt), HostGatewayError> {
        request.validate()?;
        let correlation_id = request.correlation_id.clone();
        let expected_tool = request.tool.canonical_name();
        let outcome = match port.invoke(request) {
            Ok(HostInvocationPortOutcome::Accepted { operation_handle }) => {
                HostInvocationOutcome::Accepted { operation_handle }
            }
            Ok(HostInvocationPortOutcome::Responded {
                operation_handle,
                response,
            }) => {
                validate_port_response(expected_tool, &response)?;
                HostInvocationOutcome::Responded {
                    operation_handle,
                    response,
                }
            }
            Err(failure) => HostInvocationOutcome::Rejected { failure },
        };
        let result = HostInvocationResult {
            correlation_id,
            outcome,
        };
        let receipt = result.completion_receipt();
        Ok((result, receipt))
    }

    /// Validates and sends one inert cancellation through the trusted port.
    ///
    /// The host correlation and exact cancellation target are copied from the
    /// caller after validation; the port returns only the target disposition.
    pub fn cancel<P: KernelHostRequestPort + ?Sized>(
        &self,
        port: &mut P,
        request: &HostCancellationRequest,
    ) -> Result<HostCancellationResult, HostGatewayError> {
        request.validate()?;
        let correlation_id = request.correlation_id.clone();
        let operation_handle = request.operation_handle.clone();
        let outcome = match port.cancel(request) {
            Ok(HostCancellationPortOutcome::Accepted) => HostCancellationOutcome::Accepted,
            Ok(HostCancellationPortOutcome::AlreadyTerminal) => {
                HostCancellationOutcome::AlreadyTerminal
            }
            Err(failure) => HostCancellationOutcome::Rejected { failure },
        };
        Ok(HostCancellationResult {
            correlation_id,
            operation_handle,
            outcome,
        })
    }
}

/// Fail-closed validation error at the host-request gateway boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HostGatewayError {
    /// Inert host input violated its public contract.
    #[error(transparent)]
    HostContract(#[from] HostContractError),
    /// The trusted port returned an internally inconsistent public projection.
    #[error("trusted host port returned invalid field {field}: {reason}")]
    InvalidPortResult {
        /// Stable public field path.
        field: &'static str,
        /// Stable public reason.
        reason: &'static str,
    },
    /// The returned response could not be serialized for a deterministic size check.
    #[error("trusted host port response serialization failed: {0}")]
    ResponseSerialization(String),
    /// The returned response exceeds the hard structured-response ceiling.
    #[error("trusted host port response exceeds the structured limit: {actual} > {maximum}")]
    ResponseTooLarge {
        /// Exact serialized byte length.
        actual: usize,
        /// Hard protocol byte ceiling.
        maximum: usize,
    },
}

fn validate_port_response(
    expected_tool: &str,
    response: &McpResponse,
) -> Result<(), HostGatewayError> {
    public_text(&response.request_id, "response.request_id")?;
    public_text(&response.idempotency_key, "response.idempotency_key")?;
    exact_sha256(
        &response.canonical_request_sha256,
        "response.canonical_request_sha256",
    )?;
    public_text(
        &response.canonical_tool_name,
        "response.canonical_tool_name",
    )?;
    if response.canonical_tool_name != expected_tool {
        return Err(HostGatewayError::InvalidPortResult {
            field: "response.canonical_tool_name",
            reason: "must match the requested canonical tool",
        });
    }
    validate_proof_ceiling(response.proof_ceiling).map_err(port_contract_violation)?;
    let encoded = serde_json::to_vec(response)
        .map_err(|error| HostGatewayError::ResponseSerialization(error.to_string()))?;
    if encoded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(HostGatewayError::ResponseTooLarge {
            actual: encoded.len(),
            maximum: HARD_STRUCTURED_RESPONSE_BYTES,
        });
    }
    Ok(())
}

fn public_text(value: &str, field: &'static str) -> Result<(), HostGatewayError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(HostGatewayError::InvalidPortResult {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn exact_sha256(value: &str, field: &'static str) -> Result<(), HostGatewayError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(HostGatewayError::InvalidPortResult {
            field,
            reason: "must be a lowercase SHA-256 hex digest",
        });
    }
    Ok(())
}

fn port_contract_violation(value: ContractViolation) -> HostGatewayError {
    match value {
        ContractViolation::InvalidField { field, reason } => {
            HostGatewayError::InvalidPortResult { field, reason }
        }
    }
}
