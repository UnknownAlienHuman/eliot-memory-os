//! Authenticated owner-facts pull handling for process-stream admission.
//!
//! The daemon re-reads its one current Governor WorkScope owner. It does not
//! treat the TestD submit frame or its product/source strings as scope,
//! policy, or source authority. The current tree has no canonical process
//! source-receipt resolver or typed Blob policy/residency/causal issuer, so
//! this producer returns the corresponding closed refusal instead of
//! constructing a partial `Available` fact set.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_blob_api::wire::{
    BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID, BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION,
    BlobProcessStreamOwnerFactsPullOutcome, BlobProcessStreamOwnerFactsPullRequest,
    BlobProcessStreamOwnerFactsPullResponse, BlobProcessStreamOwnerFactsUnavailableReason,
};

use crate::DaemonComposition;

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Produces a closed owner answer for one Kernel-retained pull.
///
/// A positive result requires a canonical source receipt and Blob-specific
/// policy, residency, causal, and authority owners in addition to the checked
/// WorkScope guard. Since the source-receipt owner is not present on this
/// composition, a matched scope still cannot produce an `Available` result.
pub fn resolve_blob_owner_facts(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    request
        .validate()
        .map_err(|error| format!("invalid blob owner-facts pull: {error}"))?;
    let reason = if unix_ms() >= request.deadline_ms {
        BlobProcessStreamOwnerFactsUnavailableReason::DeadlineElapsed
    } else {
        match composition.current_testd_blob_work_scope(&request.state_fence) {
            Err(_) => BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            Ok(None) => BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
            Ok(Some(snapshot)) => {
                match request.expected_work_scope_ref.as_deref() {
                    Some(expected) if expected != snapshot.binding.scope.scope_ref.as_str() => {
                        BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding
                    }
                    // Without a verified Kernel-selected scope ref, the
                    // current singleton owner snapshot is not evidence that
                    // its scope governs this product/source/task identity.
                    None => BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
                    Some(_) => {
                        // The canonical source-receipt owner is a distinct
                        // required fact. Neither the ProcessExecutionBinding
                        // nor Blob's ready-receipt reference is that source
                        // receipt.
                        BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable
                    }
                }
            }
        }
    };
    let response = BlobProcessStreamOwnerFactsPullResponse {
        wire_id: BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID.to_owned(),
        wire_revision: BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION,
        pull_ref: request.pull_ref.clone(),
        job_id: request.job_id.clone(),
        invocation_id: request.invocation_id.clone(),
        process_binding_sha256: request.process_binding_sha256.clone(),
        outer_request_sha256: request.outer_request_sha256.clone(),
        // This echoes the exact requested owner-facts fence. The refusal reason
        // carries any stale/missing disposition; no current owner fact is
        // asserted when the read could not be completed at this fence.
        observed_state_fence: request.state_fence.clone(),
        outcome: BlobProcessStreamOwnerFactsPullOutcome::Unavailable { reason },
    };
    response
        .validate_for_request(request)
        .map_err(|error| format!("invalid blob owner-facts response: {error}"))?;
    Ok(response)
}
