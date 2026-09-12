//! Store EBP exchange cell — bounded frame transport and exact-operation reconciliation.
//!
//! This cell owns only the raw EBP exchange: bounded `Frame` send/receive,
//! `DeliveryOutcome::UnknownOutcome` classification, per-operation `RequestId`
//! allocation, `RequestIdentity` construction, and exact `OperationId` receipt
//! reconciliation. It never builds provider queries, mints authority, or decides
//! completion.
//!
//! Architecture anchors: `docs/architecture/ELIOT_ARCHITECTURE.md` §A12.3
//! (single governed write path), §A13.2 (Kernel failure domains),
//! `ARCH-AUTH-01` (explicit, scoped, fenced authority), `ARCH-SEC-02` (one
//! canonical transition path), and `ARCH-RES-01` (fail locally, recover
//! globally) — the exchange stays neutral, bounded, and fail-closed.
//!
//! Implementation anchors: `docs/architecture/ELIOT_IMPLEMENTATION.md` §R2
//! (canonical substrate), §I5.1 (storage boundary), §I5.9 (`SurrealDB`
//! implementation), §I5.11 (storage replacement), §B.2 (Kernel↔Store), and
//! §I2.23 (capability-family topology) — the cell is a narrow transport
//! boundary with no semantic synthesis.
//!
//! This cell owns no Governor semantic types and no Store semantic ownership;
//! those concerns remain in their owning layers.

use std::sync::atomic::Ordering;

use eliot_contracts::ClockReading;
use eliot_contracts::ProductId;
use eliot_contracts::RequestId;
use eliot_contracts::SourceId;
use eliot_ipc::DeliveryOutcome;
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::OperationId;
use eliot_store_api::RequestMeta;
use eliot_store_api::StoreError;
use eliot_store_api::StoreFailure;
use eliot_store_api::StoreFailureDisposition;
use eliot_store_api::StoreRequest;
use eliot_store_api::StoreResponse;
use eliot_store_api::WriteReceipt;

use super::EbpCanonicalStoreClient;
use super::EbpStoreTransport;
use super::StoreClientError;

#[derive(Debug)]
pub(super) enum RequestFailure {
    Store(StoreError),
    /// Verified typed store failure as a lossless owning projection. Retains
    /// the complete `StoreFailure` without flattening and without parsing
    /// `human_detail` prose; the box keeps the error enum inline size small.
    Failure(Box<StoreFailure>),
    Contract(StoreClientError),
    Unknown {
        operation_id: OperationId,
        reason: String,
    },
}

impl RequestFailure {
    pub(super) fn unknown_or_transport(
        error: StoreClientError,
        operation_id: Option<OperationId>,
    ) -> Self {
        match operation_id {
            Some(operation_id) => Self::Unknown {
                operation_id,
                reason: error.to_string(),
            },
            None => Self::Contract(error),
        }
    }

    pub(super) fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error,
            Self::Failure(failure) => failure_into_store_error(&failure),
            Self::Contract(error) => StoreError::Serialization(error.to_string()),
            Self::Unknown { reason, .. } => {
                let _ = reason;
                StoreError::Unavailable
            }
        }
    }

    /// Reports whether this failure is a typed unknown-outcome failure bound
    /// to the admitted operation. Callers reconcile exactly that operation via
    /// `receipt_exact`/`reconcile_genesis` and never adopt a peer identity.
    pub(super) fn is_unknown_outcome_failure(&self) -> bool {
        matches!(
            self,
            Self::Failure(failure)
                if failure.disposition == StoreFailureDisposition::UnknownOutcome
        )
    }
}

/// Projects a verified typed failure onto the `StoreError` boundary without
/// parsing prose. Only the typed `disposition` and the closed `reason_code`
/// token set produced by `StoreFailure::from_store_error` steer the mapping;
/// `human_detail` never does. Deterministic rejections never project to the
/// retryable `Unavailable` signal, and unknown outcomes never claim
/// non-application.
fn failure_into_store_error(failure: &StoreFailure) -> StoreError {
    match failure.disposition {
        StoreFailureDisposition::Conflict => match failure.reason_code.as_str() {
            "STATE_FENCE_MISMATCH" => StoreError::FenceMismatch,
            "REVISION_CONFLICT" => StoreError::RevisionConflict,
            "ORDERING_CONFLICT" => StoreError::OrderingConflict,
            _ => StoreError::IdentityConflict,
        },
        StoreFailureDisposition::DeterministicRejection => match failure.reason_code.as_str() {
            "RECEIPT_NOT_FOUND" => StoreError::ReceiptNotFound,
            "PAYLOAD_TOO_LARGE" => StoreError::PayloadTooLarge,
            _ => StoreError::InvalidField {
                field: "store.operation",
                reason: "deterministic store rejection",
            },
        },
        StoreFailureDisposition::Unavailable
        | StoreFailureDisposition::Backpressured
        | StoreFailureDisposition::DeadlineExceeded
        | StoreFailureDisposition::MigrationRequired => StoreError::Unavailable,
        StoreFailureDisposition::Unsupported => match failure.reason_code.as_str() {
            "OPERATION_MANIFEST_MISMATCH" => StoreError::ManifestMismatch,
            "TRANSITION_CLASS_EXCEEDED" => StoreError::TransitionClassExceeded,
            "EFFECT_CEILING_EXCEEDED" => StoreError::EffectCeilingExceeded,
            _ => StoreError::UnknownOperation,
        },
        StoreFailureDisposition::UnknownOutcome => StoreError::MissingReceiptEnvelope,
        StoreFailureDisposition::InternalDefect => match failure.reason_code.as_str() {
            "INVALID_PROJECTION" => StoreError::InvalidProjection,
            "INVALID_OUTBOX" => StoreError::InvalidOutbox,
            "INVALID_RECEIPT" => StoreError::InvalidReceipt,
            _ => StoreError::Serialization("store reported an internal defect".to_owned()),
        },
    }
}

/// Surfaces a protocol defect for a failure that cannot be bound to the
/// admitted request. When the admitted write may have crossed the effect
/// boundary the outcome stays unknown for the admitted operation so callers
/// reconcile it; reads cross no effect boundary and surface an identity
/// conflict instead of claiming anything about a peer identity.
fn failure_defect(
    admitted_operation: Option<&OperationId>,
    reason: &'static str,
) -> RequestFailure {
    match admitted_operation {
        Some(operation_id) => RequestFailure::Unknown {
            operation_id: operation_id.clone(),
            reason: reason.to_owned(),
        },
        None => RequestFailure::Store(StoreError::IdentityConflict),
    }
}

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
    pub(super) async fn execute_raw(
        &self,
        request: StoreRequest,
        context: Option<&RequestMeta>,
        idempotency_key: &str,
    ) -> Result<StoreResponse, RequestFailure> {
        let request_id = match context {
            Some(value) => value.request_id.clone(),
            None => self
                .next_request_id(idempotency_key)
                .map_err(RequestFailure::Contract)?,
        };
        let metadata = match context {
            Some(value) => value.clone(),
            None => self
                .read_metadata(request_id.clone())
                .map_err(RequestFailure::Contract)?,
        };
        if metadata.state_fence != self.requirement.state_fence {
            return Err(RequestFailure::Store(StoreError::FenceMismatch));
        }
        let identity = RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: self.requirement.state_fence.clone(),
            },
            idempotency_key: idempotency_key.to_owned(),
            deadline_unix_ms: super::unix_ms().saturating_add(30_000),
            cancellation_id: format!("{request_id}:cancel"),
        };
        let operation_id = match &request {
            StoreRequest::Apply { transition, .. } => {
                Some(transition.identity.operation_id.clone())
            }
            StoreRequest::InitializeGenesis { request, .. } => Some(request.operation_id.clone()),
            StoreRequest::Receipt { operation_id } => Some(operation_id.clone()),
            _ => None,
        };
        let frame = eliot_store_api::request_frame(
            self.requirement.connection_id.as_str(),
            self.protocol_version,
            request_id.clone(),
            identity,
            request,
        )
        .map_err(|error| RequestFailure::Contract(error.into()))?;
        let mut transport = self.transport.lock().await;
        let outcome = transport
            .send_frame(&frame, self.limits)
            .await
            .map_err(|error| RequestFailure::unknown_or_transport(error, operation_id.clone()))?;
        if outcome == DeliveryOutcome::UnknownOutcome {
            return Err(RequestFailure::unknown_or_transport(
                StoreClientError::Transport("store apply delivery is unknown".to_owned()),
                operation_id.clone(),
            ));
        }
        let response_frame = transport
            .receive_frame(self.limits)
            .await
            .map_err(|error| RequestFailure::unknown_or_transport(error, operation_id.clone()))?;
        let (response_id, response) = eliot_store_api::decode_response_frame(
            &response_frame,
            self.requirement.connection_id.as_str(),
            self.protocol_version,
        )
        .map_err(|error| match operation_id.clone() {
            Some(operation_id) => RequestFailure::Unknown {
                operation_id,
                reason: error.to_string(),
            },
            None => RequestFailure::Contract(error.into()),
        })?;
        if response_id != request_id {
            return Err(match operation_id {
                Some(operation_id) => RequestFailure::Unknown {
                    operation_id,
                    reason: "response request_id does not match the sent request".to_owned(),
                },
                None => RequestFailure::Store(StoreError::IdentityConflict),
            });
        }
        response
            .validate()
            .map_err(|error| RequestFailure::Contract(error.into()))?;
        self.classify_response(
            response,
            &request_id,
            operation_id.as_ref(),
            idempotency_key,
        )
    }

    /// Binds one validated response to the admitted request. A typed failure
    /// is verified against the admitted request/operation/fence/idempotency
    /// identity before it is retained; anything misbound is a protocol defect
    /// that retains the unknown outcome for an admitted write.
    fn classify_response(
        &self,
        response: StoreResponse,
        request_id: &RequestId,
        admitted_operation: Option<&OperationId>,
        idempotency_key: &str,
    ) -> Result<StoreResponse, RequestFailure> {
        match response {
            StoreResponse::Failure { failure } => {
                Err(self.bind_failure(failure, request_id, admitted_operation, idempotency_key))
            }
            // Legacy v1 `Error` is a protocol defect on the current v2
            // session. The peer prose is discarded, never classified: the
            // transport demonstrably delivered this frame, so the
            // compatibility classification is always the internal-defect
            // branch, and an admitted write keeps its unknown outcome.
            StoreResponse::Error { error } => {
                let _ = error;
                Err(failure_defect(
                    admitted_operation,
                    "store returned legacy v1 Error on a current v2 session",
                ))
            }
            StoreResponse::Unknown {
                operation_id,
                reason,
            } => Err(RequestFailure::Unknown {
                operation_id,
                reason,
            }),
            response => Ok(response),
        }
    }

    /// Verifies a typed failure against the admitted identity without parsing
    /// prose. `StoreFailure::validate` already checked the wire shape and
    /// cross-field invariants during `response.validate()`; this binding step
    /// additionally pins request, operation, fence, and idempotency key to
    /// the exact values this call admitted. Operation B's failure never
    /// reconciles operation A.
    fn bind_failure(
        &self,
        failure: StoreFailure,
        request_id: &RequestId,
        admitted_operation: Option<&OperationId>,
        idempotency_key: &str,
    ) -> RequestFailure {
        if failure.validate().is_err() {
            return failure_defect(
                admitted_operation,
                "store failure violates the typed failure contract",
            );
        }
        if let Some(observed) = failure.request_id.as_ref()
            && observed != request_id
        {
            return failure_defect(
                admitted_operation,
                "store failure request_id does not match the admitted request",
            );
        }
        match (admitted_operation, failure.operation_id.as_ref()) {
            (Some(admitted), Some(observed)) if observed != admitted => {
                return failure_defect(
                    admitted_operation,
                    "store failure operation_id does not match the admitted operation",
                );
            }
            (None, Some(_)) => {
                return failure_defect(
                    admitted_operation,
                    "store failure carries an operation identity the read never admitted",
                );
            }
            _ => {}
        }
        if let Some(observed) = failure.state_fence_ref_or_exact_safe_projection.as_ref()
            && observed != &self.requirement.state_fence
        {
            return failure_defect(
                admitted_operation,
                "store failure fence does not match the admitted state fence",
            );
        }
        // The binding accepts an exact echo of the admitted key or its
        // canonical digest form; anything else cannot be bound to this call.
        let idempotency_digest = eliot_store_api::sha256_hex(idempotency_key.as_bytes());
        if let Some(observed) = failure.idempotency_key_ref_or_digest.as_deref()
            && observed != idempotency_key
            && observed != idempotency_digest.as_str()
        {
            return failure_defect(
                admitted_operation,
                "store failure idempotency binding does not match the admitted key",
            );
        }
        RequestFailure::Failure(Box::new(failure))
    }

    pub(super) async fn receipt_exact(
        &self,
        operation_id: OperationId,
    ) -> Result<WriteReceipt, StoreError> {
        let expected = operation_id.clone();
        let response = self
            .execute_raw(
                StoreRequest::Receipt { operation_id },
                None,
                "store-reconcile-receipt",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::Receipt {
            receipt: Some(receipt),
        } = response
        else {
            return Err(StoreError::Unavailable);
        };
        if receipt.operation_id != expected {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt)
    }

    fn next_request_id(&self, operation: &str) -> Result<RequestId, StoreClientError> {
        let counter = self.request_counter.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!(
            "{}:{operation}:{counter}",
            self.requirement.connection_id.as_str(),
        ))
        .map_err(|error| StoreClientError::Contract(error.to_string()))
    }

    fn read_metadata(&self, request_id: RequestId) -> Result<RequestMeta, StoreClientError> {
        Ok(RequestMeta {
            request_id,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("eliot-kernel")
                .map_err(|error| StoreClientError::Contract(error.to_string()))?,
            source_id: SourceId::new("eliot-kernel-store-client")
                .map_err(|error| StoreClientError::Contract(error.to_string()))?,
            state_fence: self.requirement.state_fence.clone(),
            clock: ClockReading::default(),
        })
    }
}
