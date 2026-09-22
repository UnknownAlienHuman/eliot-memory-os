//! Closed Store backup dispatch seam for `eliot-store-surreal` (issue #975).
//!
//! This module owns only the backup match/delegation glue: one production
//! arm per #950 operation delegates exactly once through [`StoreComposition`]
//! to the canonical adapter port and maps the outcome through the shared
//! typed-failure seam. It holds no local state, lease, snapshot map, or
//! alternate persistence path, and it never interprets Governor semantics,
//! mints authority, or owns capability/session admission (the root remains
//! responsible for handshake, replay, fence and capability validation).
//!
//! Until the #951/#952 backends land, the composition reports the
//! unimplemented port as [`eliot_store_api::StoreError::UnknownOperation`]
//! without effects; that typed refusal is preserved here, never widened
//! into success and never fallen back to another operation.

use eliot_store_api::{StoreBackupEnvelope, StoreBackupOperation, StoreBackupOutcome};

use crate::request_dispatch::{failure_context_for_backup, map_store_error};
use crate::{Response, StoreComposition};

/// Delegates one closed backup envelope to the canonical composition exactly
/// once and maps the outcome through the shared typed-failure seam.
///
/// This is the single production backup route used by the
/// [`crate::StoreDispatchBackend`] implementation: thin input/result/error
/// passthrough with no cache, snapshot map, retry, or semantic
/// interpretation.
pub(crate) async fn dispatch_backup(
    composition: &StoreComposition,
    request: StoreBackupEnvelope,
) -> Response {
    let failure_context = failure_context_for_backup(&request);
    let operation_id = request.operation.operation_id().clone();
    let state_fence = request.state_fence.clone();
    let outcome = match request.operation.clone() {
        StoreBackupOperation::Begin { request } => composition
            .backup_begin(request)
            .await
            .map(|consistency| StoreBackupOutcome::Begun { consistency }),
        StoreBackupOperation::Page { request } => composition
            .backup_page(request)
            .await
            .map(|page| StoreBackupOutcome::Page { page }),
        StoreBackupOperation::End { request } => composition
            .backup_end(request)
            .await
            .map(|receipt| StoreBackupOutcome::Completion { receipt }),
        StoreBackupOperation::IsolatedRestore { request } => composition
            .backup_isolated_restore(request)
            .await
            .map(|receipt| StoreBackupOutcome::Completion { receipt }),
        StoreBackupOperation::Validate { request } => composition
            .backup_validate(request)
            .await
            .map(|receipt| StoreBackupOutcome::Validation { receipt }),
        StoreBackupOperation::Status { request } => composition
            .backup_status(request)
            .await
            .map(|report| StoreBackupOutcome::Status { report }),
        StoreBackupOperation::Reconcile { request } => composition
            .backup_reconcile(request)
            .await
            .map(|reconciliation| StoreBackupOutcome::Reconciliation { reconciliation }),
    };
    match outcome {
        Ok(outcome) => Response::Backup {
            response: eliot_store_api::StoreBackupEnvelopeResponse {
                operation_id,
                state_fence,
                outcome,
            },
        },
        Err(error) => map_store_error(error, failure_context),
    }
}
