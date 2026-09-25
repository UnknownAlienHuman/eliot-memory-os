//! Closed Store backup dispatch seam for `eliot-store-surreal` (issue #975).
//!
//! This module owns only the backup match/delegation glue: one production
//! arm per #950 operation delegates exactly once through
//! [`StoreComposition`] to the canonical adapter port and maps the outcome
//! through the shared typed-failure seam. It holds no local state, lease,
//! snapshot map, or alternate persistence path, and it never interprets
//! Governor semantics, mints authority, or owns capability/session
//! admission. Session admission (handshake capability, fence, replay) is
//! owned by [`crate::validate_request_frame`] before dispatch is reachable;
//! the envelope's backup capability declaration is what that check enforces
//! via `Request::capability`.
//!
//! Production caller chain: [`crate::validate_request_frame`] admits the
//! frame, [`crate::StoreDispatchBackend::dispatch_request`] matches the
//! `Backup` arm, that arm builds [`failure_context_for_backup`](crate::request_dispatch::failure_context_for_backup)
//! and delegates here, each arm calls exactly one
//! `StoreComposition::backup_*` method, and each method performs exactly one
//! accepted #951/#952 adapter-port call.

use eliot_store_api::{
    StoreBackupOperation, StoreBackupRequest, StoreBackupResponse, StoreFailureIdentityContext,
};

use crate::request_dispatch::map_composition_error;
use crate::{Response, StoreComposition};

/// Delegates one closed backup envelope to the canonical composition
/// exactly once and maps the outcome through the shared typed-failure seam.
///
/// This is the single production backup route used by the
/// [`crate::StoreDispatchBackend`] implementation: thin input/result/error
/// passthrough with no cache, snapshot map, retry, or semantic
/// interpretation. `UnknownOutcome` from the composition is preserved
/// through [`map_composition_error`] with the admitted identity context as
/// the sole reconciliation key; deterministic port refusals
/// (`Unavailable`/`UnknownOperation`) pass through unchanged with zero
/// effects. An unsupported operation never falls back to `Apply` or any
/// other operation.
pub(crate) async fn dispatch_backup(
    composition: &StoreComposition,
    request: StoreBackupRequest,
    failure_context: StoreFailureIdentityContext,
) -> Response {
    let outcome = match request.operation {
        StoreBackupOperation::Begin(begin) => composition
            .backup_begin(&request.context, begin)
            .await
            .map(|handle| StoreBackupResponse::Handle { handle }),
        StoreBackupOperation::Page { handle, cursor } => composition
            .backup_page(&request.context, handle, cursor)
            .await
            .map(|page| StoreBackupResponse::Page { page }),
        StoreBackupOperation::End { handle } => composition
            .backup_end(&request.context, handle)
            .await
            .map(|receipt| StoreBackupResponse::EndReceipt { receipt }),
        StoreBackupOperation::PrepareDestination(destination) => composition
            .backup_prepare_destination(&request.context, destination)
            .await
            .map(|evidence| StoreBackupResponse::Isolation { evidence }),
        StoreBackupOperation::RestoreBatch(batch) => composition
            .backup_restore_batch(&request.context, batch)
            .await
            .map(|receipt| StoreBackupResponse::Restored { receipt }),
        // The accepted #952 validation backend proves a restore batch
        // without applying it and reports `RestoreValidationReceipt`; that
        // is the receipt this arm projects. It cannot be honestly
        // converted into the `SnapshotValidationReceipt` currently named
        // by the `Validation` response variant (a snapshot handle plus its
        // authoritative member denominator are not carried by the batch and
        // must not be invented), so this arm stays pinned to the backend
        // truth until the wire variant carries the restore receipt.
        StoreBackupOperation::Validate(batch) => composition
            .backup_validate(&request.context, batch)
            .await
            .map(|receipt| StoreBackupResponse::Validation { receipt }),
        StoreBackupOperation::Status { operation_id } => composition
            .backup_status(operation_id)
            .await
            .map(|report| StoreBackupResponse::Status { report }),
        StoreBackupOperation::Reconcile { first, second } => composition
            .backup_reconcile(first, second)
            .await
            .map(|reconciliation| StoreBackupResponse::Reconciled { reconciliation }),
    };
    match outcome {
        Ok(response) => Response::Backup { response },
        Err(error) => map_composition_error(error, failure_context),
    }
}
