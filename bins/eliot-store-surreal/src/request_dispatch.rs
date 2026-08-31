//! Closed request dispatch seam for `eliot-store-surreal`.
//!
//! Architecture: A12.3 One governed write path, A13.2 Kernel and failure domains,
//! ARCH-AUTH-01 authority/fence-bound execution, ARCH-SEC-02 session/capability boundary,
//! ARCH-RES-01 bounded closed dispatch.
//! Implementation: I5.1 provider-owned store seam, I5.9 explicit receipt reconciliation,
//! I5.11 closed Request catalogue, B.2 bounded error surface, I14.21 deterministic dispatch,
//! I2.2 crate ownership, I2.23 seam cohesion.
//!
//! Store remains the durable owner. This module only dispatches already
//! session-validated closed `Request`s, preserves exact operation identity and
//! `UnknownOutcome` without fabricating success, and never interprets Governor
//! semantics, mints authority, or owns capability/session admission (root remains
//! responsible for handshake, replay, fence and capability validation).

use eliot_contracts::RequestId;
use eliot_store_api::{
    CanonicalStoreClient, OperationId, PreparedTransition, RequestMeta, StoreError, StoreFailure,
    StoreFailureContractError, StoreFailureIdentityContext, StoreGenesisRequest, WriteReceipt,
    validate_genesis_receipt_envelope, validate_store_receipt_envelope,
};
#[cfg(test)]
use eliot_store_api::StoreRecoverySnapshot;

use crate::Request;
use crate::Response;
use crate::StoreComposition;
use crate::StoreCompositionError;

const PROVIDER_OPERATION_ID_MATCH: &str = "store:provider-operation-identity-match";
const PROVIDER_OPERATION_ID_MISMATCH: &str = "store:provider-operation-identity-mismatch";
const RECEIPT_OPERATION_ID_MISMATCH: &str = "store:receipt-operation-identity-mismatch";
const RECEIPT_INVALID: &str = "store:receipt-invalid";
const RECEIPT_ENVELOPE_MISSING: &str = "store:receipt-envelope-missing";

fn request_failure_context(
    request_id: RequestId,
    request: &Request,
) -> StoreFailureIdentityContext {
    let mut context = StoreFailureIdentityContext {
        request_id: Some(request_id),
        ..StoreFailureIdentityContext::default()
    };
    match request {
        Request::Named { request } => {
            context.state_fence_ref_or_exact_safe_projection = Some(request.state_fence.clone());
        }
        Request::Recovery { request } => {
            context.state_fence_ref_or_exact_safe_projection = Some(request.state_fence.clone());
        }
        Request::Apply {
            context: request_context,
            transition,
            ..
        } => {
            context.operation_id = Some(transition.identity.operation_id.clone());
            context.idempotency_key_ref_or_digest =
                Some(transition.identity.idempotency_key.clone());
            context.state_fence_ref_or_exact_safe_projection =
                Some(request_context.state_fence.clone());
        }
        Request::InitializeGenesis {
            context: request_context,
            request,
        } => {
            context.operation_id = Some(request.operation_id.clone());
            context.idempotency_key_ref_or_digest = Some(request.idempotency_key.clone());
            context.state_fence_ref_or_exact_safe_projection =
                Some(request_context.state_fence.clone());
        }
        Request::Receipt { operation_id } => {
            context.operation_id = Some(operation_id.clone());
        }
        Request::Health
        | Request::Readiness
        | Request::RevisionHeads { .. }
        | Request::OrderingHeads { .. }
        | Request::ValidationSnapshot => {}
    }
    context
}

fn typed_failure_response(
    error: StoreError,
    context: StoreFailureIdentityContext,
) -> Result<Response, StoreFailureContractError> {
    let failure = StoreFailure::from_store_error(error, context)?;
    failure.validate()?;
    Ok(Response::Failure { failure })
}

fn typed_provider_unknown_response(
    mut context: StoreFailureIdentityContext,
    evidence_ref: &'static str,
) -> Result<Response, StoreFailureContractError> {
    context.evidence_ref = Some(evidence_ref.to_owned());
    let failure = StoreFailure::provider_unknown_outcome(context)?;
    failure.validate()?;
    Ok(Response::Failure { failure })
}

fn map_provider_unknown_outcome(
    context: StoreFailureIdentityContext,
    observed_operation_id: &OperationId,
) -> Result<Response, StoreFailureContractError> {
    let evidence_ref = match context.operation_id.as_ref() {
        Some(admitted) if admitted == observed_operation_id => PROVIDER_OPERATION_ID_MATCH,
        _ => PROVIDER_OPERATION_ID_MISMATCH,
    };
    typed_provider_unknown_response(context, evidence_ref)
}

fn map_apply_receipt(
    context: &RequestMeta,
    transition: &PreparedTransition,
    failure_context: StoreFailureIdentityContext,
    receipt: WriteReceipt,
) -> Result<Response, StoreFailureContractError> {
    match validate_store_receipt_envelope(context, transition, &receipt) {
        Ok(()) => Ok(Response::Transaction { receipt }),
        Err(StoreError::MissingReceiptEnvelope) => {
            typed_provider_unknown_response(failure_context, RECEIPT_ENVELOPE_MISSING)
        }
        Err(_) => typed_provider_unknown_response(failure_context, RECEIPT_INVALID),
    }
}

fn map_genesis_receipt(
    context: &RequestMeta,
    request: &StoreGenesisRequest,
    failure_context: StoreFailureIdentityContext,
    receipt: WriteReceipt,
) -> Result<Response, StoreFailureContractError> {
    match validate_genesis_receipt_envelope(context, request, &receipt) {
        Ok(()) => Ok(Response::Genesis { receipt }),
        Err(StoreError::MissingReceiptEnvelope) => {
            typed_provider_unknown_response(failure_context, RECEIPT_ENVELOPE_MISSING)
        }
        Err(_) => typed_provider_unknown_response(failure_context, RECEIPT_INVALID),
    }
}

fn map_receipt_lookup(
    queried_operation_id: &OperationId,
    failure_context: StoreFailureIdentityContext,
    receipt: Option<WriteReceipt>,
) -> Result<Response, StoreFailureContractError> {
    let Some(receipt) = receipt else {
        return Ok(Response::Receipt { receipt: None });
    };
    if &receipt.operation_id != queried_operation_id {
        return typed_provider_unknown_response(
            failure_context,
            RECEIPT_OPERATION_ID_MISMATCH,
        );
    }
    if receipt.validate().is_err() {
        return typed_provider_unknown_response(failure_context, RECEIPT_INVALID);
    }
    if receipt.require_reconciliation_envelope().is_err() {
        return typed_provider_unknown_response(failure_context, RECEIPT_ENVELOPE_MISSING);
    }
    Ok(Response::Receipt {
        receipt: Some(receipt),
    })
}

#[allow(async_fn_in_trait)]
pub trait StoreDispatchBackend: Send + Sync {
    async fn dispatch_request(
        &self,
        request_id: RequestId,
        request: Request,
    ) -> Result<Response, StoreFailureContractError>;
}

pub async fn dispatch<B: StoreDispatchBackend + ?Sized>(
    backend: &B,
    request_id: RequestId,
    request: Request,
) -> Result<Response, StoreFailureContractError> {
    backend.dispatch_request(request_id, request).await
}

impl StoreDispatchBackend for StoreComposition {
    async fn dispatch_request(
        &self,
        request_id: RequestId,
        request: Request,
    ) -> Result<Response, StoreFailureContractError> {
        let failure_context = request_failure_context(request_id, &request);
        match request {
            Request::Health => match self.health().await {
                Ok(record) => Ok(Response::Health { record }),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::Readiness => match self.readiness().await {
                Ok(receipt) => Ok(Response::Readiness { receipt }),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::Named { request } => match self.named(request).await {
                Ok(response) => Ok(Response::Named { response }),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::Apply {
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            } => {
                let result = self
                    .apply(
                        &context,
                        transition.clone(),
                        expected_revision_heads,
                        expected_ordering_heads,
                    )
                    .await;
                match result {
                    Ok(receipt) => {
                        map_apply_receipt(&context, &transition, failure_context, receipt)
                    }
                    Err(StoreCompositionError::UnknownOutcome {
                        operation_id,
                        reason: _,
                    }) => map_provider_unknown_outcome(failure_context, &operation_id),
                    Err(StoreCompositionError::Store(error)) => {
                        typed_failure_response(error, failure_context)
                    }
                }
            }
            Request::Receipt { operation_id } => match self.receipt(operation_id.clone()).await {
                Ok(receipt) => map_receipt_lookup(&operation_id, failure_context, receipt),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::RevisionHeads { keys } => match self.revision_heads(keys).await {
                Ok(heads) => Ok(Response::RevisionHeads { heads }),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::OrderingHeads { scopes } => match self.ordering_heads(scopes).await {
                Ok(heads) => Ok(Response::OrderingHeads { heads }),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::ValidationSnapshot => match self.validation_snapshot().await {
                Ok(snapshot) => Ok(Response::ValidationSnapshot { snapshot }),
                Err(error) => typed_failure_response(error, failure_context),
            },
            Request::Recovery { request } => {
                match CanonicalStoreClient::recovery(&self.store, request).await {
                    Ok(snapshot) => Ok(Response::Recovery { snapshot }),
                    Err(error) => typed_failure_response(error, failure_context),
                }
            }
            Request::InitializeGenesis { context, request } => {
                let result = CanonicalStoreClient::initialize_genesis(
                    &self.store,
                    &context,
                    request.clone(),
                )
                .await;
                match result {
                    Ok(receipt) => {
                        map_genesis_receipt(&context, &request, failure_context, receipt)
                    }
                    Err(error) => typed_failure_response(error, failure_context),
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) const UNKNOWN_GENESIS_REASON: &str =
    "genesis receipt envelope is missing; reconcile by exact operation identity";

#[cfg(test)]
pub(crate) fn map_recovery_dispatch_result(
    result: Result<StoreRecoverySnapshot, StoreError>,
) -> Response {
    match result {
        Ok(snapshot) => Response::Recovery { snapshot },
        Err(error) => Response::Error {
            error: error.to_string(),
        },
    }
}

#[cfg(test)]
pub(crate) fn map_genesis_dispatch_result(
    request: StoreGenesisRequest,
    result: Result<WriteReceipt, StoreError>,
) -> Response {
    match result {
        Ok(receipt) => Response::Genesis { receipt },
        Err(StoreError::MissingReceiptEnvelope) => Response::Unknown {
            operation_id: request.operation_id,
            reason: UNKNOWN_GENESIS_REASON.to_owned(),
        },
        Err(error) => Response::Error {
            error: error.to_string(),
        },
    }
}

#[cfg(test)]
mod typed_failure_tests;
