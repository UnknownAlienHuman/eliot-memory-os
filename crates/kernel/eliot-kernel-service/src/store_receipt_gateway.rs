//! Kernel-owned exact canonical Store receipt lookup.
//!
//! Verified architecture references: `A12.3` requires one governed path to a
//! canonical receipt; `A13.2` keeps Kernel failure handling independent of
//! Store and provider semantics; `A13.6` limits recovery observations to
//! exact operation identity and opaque durable evidence. `ARCH-AUTH-01`
//! requires explicit, scoped, fenced authority; `ARCH-SEC-02` forbids a
//! second transition or storage path; and `ARCH-RES-01` requires local failure
//! without fabricating global success.
//!
//! Verified implementation references: `I5.1` keeps the domain on the
//! `CanonicalStoreClient` boundary; `I5.9` keeps SDK/query details in the
//! Store bridge; `I5.11` binds replacement to generation cutover and receipt;
//! `B.2` names `ResolveReceipt` as the Kernel-to-Store surface; `I2.23`
//! requires an executable seam with an explicit owner rather than a
//! speculative crate split. Kernel is neutral and Governor-free: this module
//! performs only route/fence and Store-owned receipt validation, never payload
//! interpretation, authority creation, retry, cache, defaulting, or fallback.

use eliot_contracts::{OperationId, StateFence};
use eliot_store_api::{CanonicalStoreClient, WriteReceipt};

use super::KernelStoreGateway;

pub(super) async fn receipt(
    gateway: &KernelStoreGateway,
    state_fence: &StateFence,
    operation_id: OperationId,
) -> Result<Option<WriteReceipt>, String> {
    let _flight = gateway.flight.enter()?;
    if gateway.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    state_fence.validate().map_err(|error| error.to_string())?;
    gateway.validate_active_route(state_fence)?;

    let receipt_result = gateway
        .store
        .receipt(operation_id.clone())
        .await
        .map_err(|error| error.to_string());

    if gateway.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    gateway.validate_active_route(state_fence)?;

    let receipt = receipt_result?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    receipt.validate().map_err(|error| error.to_string())?;
    if receipt.operation_id != operation_id {
        return Err("Store receipt operation identity does not match request".to_owned());
    }
    if receipt.state_fence != *state_fence {
        return Err("Store receipt fence does not match request".to_owned());
    }
    Ok(Some(receipt))
}
