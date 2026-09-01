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
use eliot_store_api::StoreRequest;
use eliot_store_api::StoreResponse;
use eliot_store_api::WriteReceipt;

use super::EbpCanonicalStoreClient;
use super::EbpStoreTransport;
use super::StoreClientError;

#[derive(Debug)]
pub(super) enum RequestFailure {
    Store(StoreError),
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
            Self::Contract(error) => StoreError::Serialization(error.to_string()),
            Self::Unknown { reason, .. } => {
                let _ = reason;
                StoreError::Unavailable
            }
        }
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
        match response {
            StoreResponse::Error { error } => {
                Err(RequestFailure::Store(StoreError::Serialization(error)))
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
