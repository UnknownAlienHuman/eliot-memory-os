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
use eliot_ors::{ReservationRecord, WriterReservationToken};
use eliot_store_api::{CanonicalStoreClient, ReservedWriteRequest, WriteReceipt};

use super::KernelStoreGateway;
use crate::store_write_reservation::{
    CompositionReservation, finalize_reservation, reconcile_receipt,
    writer_epoch_for_fence_from_epoch,
};

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

/// Reconciles one reserved write by its exact admitted request and observed
/// receipt, then closes the reservation disposition (issue #992).
///
/// The caller presents the admitted [`ReservedWriteRequest`] it sent, the
/// observed [`WriteReceipt`], and the reservation token: reconciliation keeps
/// the same `OperationId` throughout and never adopts a peer identity. The
/// shared #991 verifier binds receipt to request (operation, idempotency,
/// hash, class, fence, scope/sequence coverage, reconciliation envelope);
/// [`reconcile_receipt`] binds receipt to token; the ORS owner verifies
/// through the composition-bound evidence provider and finalizes or releases
/// all token scopes atomically. A forged, foreign, partial, or stale receipt
/// fails here with the token state unchanged. Cancellation, timeout, or
/// socket replacement cannot reach this path with a fabricated receipt: only
/// exact evidence closes the token.
pub(super) fn reconcile_reserved(
    gateway: &KernelStoreGateway,
    token: &WriterReservationToken,
    request: &ReservedWriteRequest,
    receipt: &WriteReceipt,
) -> Result<ReservationRecord, String> {
    let _flight = gateway.flight.enter()?;
    if gateway.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    receipt.validate().map_err(|error| error.to_string())?;
    request.validate().map_err(|error| error.to_string())?;
    if request.transition.identity.operation_id.as_str() != token.operation_id.as_str() {
        return Err(
            "reconciliation request operation does not match the reservation operation".to_owned(),
        );
    }
    gateway.validate_active_route(&receipt.state_fence)?;
    // The one receipt-binding authority: the exact #991 verifier pinned to
    // the Host-approved requirement fence inside the Store client.
    gateway
        .store
        .check_reserved_write_receipt(request, receipt)
        .map_err(|error| error.to_string())?;
    if gateway.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    gateway.validate_active_route(&receipt.state_fence)?;
    let commit_ors = gateway.commit_ors.clone().ok_or_else(|| {
        "reserved writes require the composition-bound ORS; cannot reconcile".to_owned()
    })?;
    let owner = {
        let service = gateway
            .service
            .lock()
            .map_err(|_| "Kernel service lock poisoned".to_owned())?;
        let live_epoch = service.authority_epoch();
        if !live_epoch.is_same_authority(&receipt.state_fence.authority_epoch) {
            return Err("canonical-store route is outside the active Kernel epoch".to_owned());
        }
        let writer_epoch =
            writer_epoch_for_fence_from_epoch(&live_epoch).map_err(|error| error.to_string())?;
        CompositionReservation::bind(commit_ors, writer_epoch).map_err(|error| error.to_string())?
    };
    let reconciliation = reconcile_receipt(token, receipt).map_err(|error| error.to_string())?;
    finalize_reservation(&owner, &reconciliation).map_err(|error| error.to_string())
}
