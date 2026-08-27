//! Authenticated exact Store receipt lookup projection.
//!
//! Architecture traceability: `A12.3`, `A13.2`, `A13.6`, `ARCH-AUTH-01`,
//! `ARCH-SEC-02`, and `ARCH-RES-01` require one scoped, authenticated,
//! fail-closed Kernel route to canonical Store evidence. Implementation
//! anchors are `I1.8`, `I5.1`, `I5.9`, `I5.11`, `B.2`, `P.3`, `I14.21`,
//! `I2.2`, and `I2.23`: Store owns the durable lookup, Kernel admits the
//! exact session fence and projects the typed result, and Governor remains
//! outside this neutral boundary.
//!
//! Forbidden authority: no Governor interpretation, semantic authority,
//! alternate Store client or gateway, retry, cache, default, capability,
//! durable-job, apply/recovery/genesis, or fabricated success path.

use super::{KernelComposition, Session, TransportError, validate_store_session_fence};
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
    let operation: StoreReceiptOperation =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    validate_store_session_fence(session, &operation.state_fence)?;
    let gateway = kernel.retained_store_gateway()?;
    match gateway
        .receipt(&operation.state_fence, operation.operation_id)
        .await
    {
        Ok(receipt) => Ok(store_receipt_response(receipt.as_ref())),
        Err(error) => Ok(KernelComposition::store_error_response_text(
            "receipt", &error,
        )),
    }
}

#[cfg(not(windows))]
pub(super) async fn dispatch(
    _kernel: &KernelComposition,
    _session: &Session,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let _ = payload;
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
