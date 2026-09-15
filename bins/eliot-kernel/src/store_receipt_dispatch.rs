//! Authenticated exact Store receipt lookup projection.
//!
//! Architecture traceability: `A12.3`, `A13.2`, `A13.6`, `ARCH-AUTH-01`,
//! `ARCH-SEC-02`, and `ARCH-RES-01` require one scoped, authenticated,
//! fail-closed Kernel route to canonical Store evidence. Implementation
//! anchors are `I1.8`, `I5.1`, `I5.9`, `I5.11`, `B.2`, `P.3`, `I14.21`,
//! and `I2.23`: Store owns the durable lookup, Kernel admits the exact session
//! fence and projects the typed result, and Governor remains outside this
//! neutral boundary.
//!
//! Forbidden authority: no Governor interpretation, semantic authority,
//! alternate Store client or gateway, retry, cache, default, capability,
//! durable-job, apply/recovery/genesis, or fabricated success path.

use super::{KernelComposition, Session, TransportError, validate_store_session_fence};
use crate::kernel_diagnostics::{
    EntrypointStage, observe_entrypoint_with_detail, observe_terminal_error,
};
use serde::Deserialize;

#[cfg(windows)]
use eliot_contracts::{OperationId, StateFence};
#[cfg(windows)]
use eliot_store_api::WriteReceipt;

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreReceiptOperation {
    operation_id: OperationId,
    state_fence: StateFence,
}

#[cfg(windows)]
pub(super) async fn dispatch(
    kernel: &KernelComposition,
    session: &Session,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    // F-LOG-KERNEL-2 (#899): receipt query/readback/validation boundary.
    // Request correlation (transport payload) stays separate from stable
    // operation identity (owner-validated fence/operation). One terminal per
    // failed receipt operation; Store commit versus Kernel response delivery
    // stay distinct. Only fixed phases plus the stable `receipt` kind are
    // emitted, never payload bodies, fences, queries, or error strings.
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.receipt_requested",
    );
    let Ok(operation): Result<StoreReceiptOperation, _> = serde_json::from_value(payload) else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.receipt_rejected:prepare",
        );
        observe_terminal_error("SESSION_FENCED");
        return Err(TransportError::SessionFenced);
    };
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.receipt_prepared",
    );
    if validate_store_session_fence(session, &operation.state_fence).is_err() {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.receipt_rejected:fence",
        );
        observe_terminal_error("SESSION_FENCED");
        return Err(TransportError::SessionFenced);
    }
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.receipt_fence_validated",
    );
    let Ok(gateway) = kernel.retained_store_gateway() else {
        // Prepared but not submitted: deterministic pre-send refusal
        // proves no Store send occurred.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.receipt_rejected:not_submitted",
        );
        observe_terminal_error("SESSION_FENCED");
        return Err(TransportError::SessionFenced);
    };
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.receipt_submitted",
    );
    match gateway
        .receipt(&operation.state_fence, operation.operation_id)
        .await
    {
        Ok(receipt) => {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.receipt_returned",
            );
            let response = store_receipt_response(receipt.as_ref());
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.receipt_response_delivered",
            );
            Ok(response)
        }
        Err(error) => {
            // Store query failed but Kernel delivery of the typed error
            // projection succeeds: commit versus delivery stay distinct.
            // The owner error string is never emitted, only the stable
            // projection outcome.
            let unknown = error == eliot_store_api::StoreError::MissingReceiptEnvelope.to_string();
            if unknown {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.receipt_unknown",
                );
            } else {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.receipt_query_failed",
                );
            }
            observe_terminal_error(if unknown {
                "STORE_UNKNOWN"
            } else {
                "STORE_ERROR"
            });
            Ok(KernelComposition::store_error_response_text(
                "receipt", &error,
            ))
        }
    }
}

#[cfg(not(windows))]
pub(super) async fn dispatch(
    _kernel: &KernelComposition,
    _session: &Session,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let _ = payload;
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.receipt_rejected:unsupported",
    );
    observe_terminal_error("SESSION_FENCED");
    Err(TransportError::SessionFenced)
}

#[cfg(windows)]
fn store_receipt_response(receipt: Option<&WriteReceipt>) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "receipt", "value": receipt },
        "recovery": null,
    })
}
