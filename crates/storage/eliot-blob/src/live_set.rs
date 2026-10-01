//! Explicit fail-closed live-set provider for roots whose independent
//! canonical reachability owners are not yet composed.
//!
//! Capture, exact-operation recovery, and readback do not consult this port.
//! GC does: every operation fails before deletion, and no absent source is
//! represented as an empty complete set.

use eliot_blob_api::{BlobDeletionReconciliation, BlobError, BlobLiveSetProof, BlobLocator};

use crate::{BlobLiveSetPort, ConditionalDeleteOutcome, LiveSetRevalidation};

/// Fail-closed placeholder used only when independently owned live-set
/// authorities are not configured. It can never authorize collection.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableBlobLiveSetPort;

impl BlobLiveSetPort for UnavailableBlobLiveSetPort {
    fn revalidate(
        &mut self,
        _proof: &BlobLiveSetProof,
    ) -> Result<LiveSetRevalidation, BlobError> {
        Err(BlobError::PlanGap(
            "independent canonical live-set sources are unavailable; Blob GC is refused".to_owned(),
        ))
    }

    fn reconcile_delete(
        &mut self,
        _operation_id: &str,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _intent_revision: u64,
        _residency_sha256: &str,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        Ok(BlobDeletionReconciliation::Unknown)
    }

    fn compare_and_delete_observed(
        &mut self,
        _operation_id: &str,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _intent_revision: u64,
        _residency_sha256: &str,
        _delete: &mut dyn FnMut() -> Result<(), BlobError>,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        Err(BlobError::PlanGap(
            "independent canonical live-set sources are unavailable; Blob GC is refused".to_owned(),
        ))
    }

    fn compare_and_delete(
        &mut self,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _delete: &mut dyn FnMut() -> Result<(), BlobError>,
    ) -> Result<ConditionalDeleteOutcome, BlobError> {
        Err(BlobError::PlanGap(
            "independent canonical live-set sources are unavailable; Blob GC is refused".to_owned(),
        ))
    }
}
