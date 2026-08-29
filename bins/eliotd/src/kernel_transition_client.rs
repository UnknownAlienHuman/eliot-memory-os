//! Neutral authenticated Kernel transition client for the daemon.
//!
//! This module owns only the `KernelTransitionPort` transport adapter: caller
//! metadata, transition/head validation, explicit request identity construction,
//! and exact write-receipt decoding. Store owns canonical persistence and
//! Kernel owns route/fence admission; Governor retains semantic transition
//! planning. Architecture: A2.3, A12.3, A13.2, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I1.8, I2.2, I2.23, P.3, I14.21, I14.26.
//! Forbidden authority: no Store/provider SDK, canonical ownership, semantic
//! Governor reconstruction, retry/default synthesis, or alternate transport.

use eliot_contracts::{OperationId, RequestMetadata};
use eliot_governor::{KernelPortError, KernelPortFuture, KernelTransitionPort};
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, StoreHealth, WriteReceipt,
    validate_store_receipt_envelope,
};

use super::{DaemonKernelClient, SERVICE_NAME, kernel_port_error, kind_value, unix_ms};

impl KernelTransitionPort for DaemonKernelClient {
    fn apply_prepared<'a>(
        &'a self,
        request: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        let request = request.clone();
        Box::pin(async move {
            request
                .validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if request.source_id.as_str() != SERVICE_NAME {
                return Err(KernelPortError::Contract(
                    "daemon transition source is not the fixed eliotd identity".to_owned(),
                ));
            }
            transition
                .validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if transition.state_fence != request.state_fence {
                return Err(KernelPortError::Contract(
                    "daemon transition fence does not match caller metadata".to_owned(),
                ));
            }
            for head in &expected_revision_heads {
                head.validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                if head.state_fence != request.state_fence {
                    return Err(KernelPortError::Contract(
                        "daemon revision head fence does not match caller metadata".to_owned(),
                    ));
                }
            }
            for head in &expected_ordering_heads {
                head.validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                if head.state_fence != request.state_fence {
                    return Err(KernelPortError::Contract(
                        "daemon ordering head fence does not match caller metadata".to_owned(),
                    ));
                }
            }
            let expected_transition = transition.clone();
            let identity = RequestIdentity {
                request: RequestBinding {
                    metadata: request.clone(),
                    state_fence: request.state_fence.clone(),
                },
                idempotency_key: transition.identity.idempotency_key.clone(),
                deadline_unix_ms: unix_ms().saturating_add(30_000),
                cancellation_id: format!("{}:cancel", transition.identity.operation_id.as_str()),
            };
            identity
                .validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            let value = self
                .transact_async_with_identity(
                    "apply_prepared",
                    serde_json::json!({
                        "context": request.clone(),
                        "transition": transition,
                        "expected_revision_heads": expected_revision_heads,
                        "expected_ordering_heads": expected_ordering_heads,
                    }),
                    identity,
                )
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "write_receipt")?;
            let receipt: WriteReceipt = serde_json::from_value(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            validate_store_receipt_envelope(&request, &expected_transition, &receipt)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            Ok(receipt)
        })
    }

    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        let state_fence = self.kernel_binding.state_fence.clone();
        Box::pin(async move {
            let value = self
                .transact_async(
                    "receipt",
                    serde_json::json!({
                        "operation_id": operation_id.clone(),
                        "state_fence": state_fence.clone(),
                    }),
                )
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "receipt")?;
            let Some(receipt) = serde_json::from_value::<Option<WriteReceipt>>(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?
            else {
                return Ok(None);
            };
            receipt
                .validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if receipt.operation_id != operation_id || receipt.state_fence != state_fence {
                return Err(KernelPortError::Contract(
                    "daemon receipt does not match the requested operation and active state fence"
                        .to_owned(),
                ));
            }
            Ok(Some(receipt))
        })
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        Box::pin(async move {
            let value = self
                .transact_async("health", serde_json::json!({}))
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "health")?;
            serde_json::from_value(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))
        })
    }
}
