//! Closed Store backup dispatch seam for `eliot-store-surreal` (issue #975).
//!
//! This module owns only the backup match/delegation glue: one production
//! arm per #950 operation delegates exactly once through [`StoreComposition`]
//! to the canonical adapter port and maps the outcome through the shared
//! typed-failure seam. It holds no local state, lease, snapshot map, or
//! alternate persistence path, and it never interprets Governor semantics,
//! mints authority, or owns capability/session admission. Per-request
//! session admission (handshake capability token per I15-02, fence, replay)
//! is owned by [`crate::validate_request_frame`] before dispatch is
//! reachable (see the service loop); the envelope's
//! [`eliot_store_api::StoreBackupEnvelope::required_capability`]
//! declaration is what that check enforces via `Request::capability`.
//! Restore carries distinct admission semantics on top (issues #954/#975):
//! capture operations require the session capability, while isolated
//! restore additionally requires the per-operation provisional admission
//! verified explicitly below and again by the backend. A restore-specific
//! capability split stays root-owned future work; none is invented here.

use eliot_store_api::{StoreBackupEnvelope, StoreBackupOperation, StoreBackupOutcome};

use crate::request_dispatch::{failure_context_for_backup, map_store_error};
use crate::{Response, StoreComposition};

/// Delegates one closed backup envelope to the canonical composition exactly
/// once and maps the outcome through the shared typed-failure seam.
///
/// This is the single production backup route used by the
/// [`crate::StoreDispatchBackend`] implementation: thin input/result/error
/// passthrough with no cache, snapshot map, retry, or semantic
/// interpretation. The isolated-restore arm verifies the provisional
/// per-operation admission up front with a distinct refusal, before any
/// delegation; all other arms delegate shape validation to the
/// composition, which re-verifies every envelope.
pub(crate) async fn dispatch_backup(
    composition: &StoreComposition,
    request: StoreBackupEnvelope,
) -> Response {
    let failure_context = failure_context_for_backup(&request);
    let operation_id = request.operation.operation_id().clone();
    let state_fence = request.state_fence.clone();
    if let StoreBackupOperation::IsolatedRestore { request: restore } = &request.operation {
        // Distinct restore admission semantics (issues #954/#975): the
        // session capability admitted this envelope at the frame layer,
        // but capability alone never authorizes a restore. The
        // per-operation provisional admission must verify here, with a
        // distinct refusal, before any delegation; the backend binds it
        // to the independent canonical anchors again before any write.
        if let Err(error) = restore.admission.validate() {
            return map_store_error(error, failure_context.clone());
        }
    }
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
