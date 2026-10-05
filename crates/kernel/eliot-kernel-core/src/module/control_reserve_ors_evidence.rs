//! I14.3 Kernel composition join for ORS owner evidence (issue #1679, W3 ORS wave).
//!
//! The Kernel ORS owner enforces and reports its own capacities through
//! `eliot_ors::OrsReserve::publish_owner_rows`; this module is the Kernel
//! composition step that validates those two published rows and joins them
//! into the [`BottleneckOwnerEvidence`] records the profile compiler consumes.
//! It observes no reserve, performs no allocation beyond the two records it
//! returns, grants no authority and acquires no capacity: every quantity in
//! the result is copied from an owner-published row, and the configuration
//! snapshot and Authority Epoch bound into the records are exactly the values
//! the composition resolved. A contradictory or non-canonical owner claim
//! fails here through the existing typed failures rather than being reported
//! as a healthy dimension.
//!
//! Consequently this join currently has no in-tree caller. The production
//! composition that resolves the configuration snapshot, Authority Epoch and
//! reference strings does not exist in this tree. `STITCH`: the join is landed
//! without a caller rather than given a manufactured one (no startup hook, no
//! `fn main` call, no discarded-result statement). Full installed-saturation
//! proof stays #11 Product scope.

use eliot_contracts::EpochId;
use eliot_runtime_contracts::{BottleneckCapacityProfile, CapacityBottleneck};

use crate::error::{KernelError, KernelResult};
use crate::module::control_reserve_profile_compiler::BottleneckOwnerEvidence;

/// The exact ORS dimensions this join accepts, in frozen contract order.
const ORS_DIMENSIONS: [CapacityBottleneck; 2] = [
    CapacityBottleneck::OrsTransactionSlots,
    CapacityBottleneck::OrsDurableQueueBytes,
];

/// Validates the ORS owner's published rows and joins them into the two
/// composition-bound evidence records for the frozen ORS dimensions.
///
/// The result carries exactly one record per ORS dimension, in frozen contract
/// order. Each row is accepted only when the existing
/// [`BottleneckCapacityProfile::validate`] accepts it, so a row with a missing
/// owner, generation, physical total, protected partition, enforcement, proof,
/// evidence or invalidation reference fails here rather than joining as a
/// claimed guarantee. Rows for any other bottleneck are refused outright: one
/// owner's numbers are never presented as proof for another dimension, and the
/// frozen owner-match itself stays with the profile compiler, which already
/// refuses a `CLAIMED` row naming an owner the frozen owner map does not bind
/// to that dimension.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when the composition-supplied
/// configuration snapshot reference is blank. Returns
/// [`KernelError::ControlReserveEvidenceContradiction`] when any row names a
/// non-ORS bottleneck, when either ORS dimension is missing or claimed twice,
/// or when a row is not contract-canonical.
pub fn join_ors_owner_evidence(
    rows: &[BottleneckCapacityProfile],
    config_snapshot_ref: &str,
    authority_epoch_ref: &EpochId,
) -> KernelResult<[BottleneckOwnerEvidence; 2]> {
    if config_snapshot_ref.trim().is_empty() {
        return Err(KernelError::InvalidField {
            field: "control_reserve.config_snapshot_ref",
            reason: "must be non-blank",
        });
    }
    for row in rows {
        if !ORS_DIMENSIONS.contains(&row.bottleneck) {
            return Err(contradiction(
                row.bottleneck,
                "NON_ORS_ROW: this join accepts only the two frozen ORS dimensions",
            ));
        }
    }
    let transaction = evidence_for(
        CapacityBottleneck::OrsTransactionSlots,
        rows,
        config_snapshot_ref,
        authority_epoch_ref,
    )?;
    let durable = evidence_for(
        CapacityBottleneck::OrsDurableQueueBytes,
        rows,
        config_snapshot_ref,
        authority_epoch_ref,
    )?;
    Ok([transaction, durable])
}

/// Joins exactly one owner row for one ORS dimension into its evidence record.
///
/// The row's quantities are copied unchanged; only the composition-resolved
/// configuration snapshot and Authority Epoch are bound around them.
fn evidence_for(
    bottleneck: CapacityBottleneck,
    rows: &[BottleneckCapacityProfile],
    config_snapshot_ref: &str,
    authority_epoch_ref: &EpochId,
) -> KernelResult<BottleneckOwnerEvidence> {
    let mut matches = rows.iter().filter(|row| row.bottleneck == bottleneck);
    let row = matches.next().ok_or_else(|| {
        contradiction(
            bottleneck,
            "MISSING_ORS_EVIDENCE: the ORS owner published no row for this dimension",
        )
    })?;
    if matches.next().is_some() {
        return Err(contradiction(
            bottleneck,
            "DUPLICATE_ORS_EVIDENCE: two owner rows claim one dimension",
        ));
    }
    row.validate()?;
    Ok(BottleneckOwnerEvidence {
        config_snapshot_ref: config_snapshot_ref.to_owned(),
        authority_epoch_ref: authority_epoch_ref.clone(),
        row: row.clone(),
    })
}

/// Names the exact dimension whose owner evidence cannot be joined.
fn contradiction(bottleneck: CapacityBottleneck, reason: &'static str) -> KernelError {
    KernelError::ControlReserveEvidenceContradiction {
        bottleneck: bottleneck.as_contract_str(),
        reason,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    #[test]
    fn join_ors_owner_evidence_rejects_blank_snapshot_ref() {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::MIN,
        )
        .expect("epoch");

        let error = join_ors_owner_evidence(&[], "", &epoch).expect_err("blank snapshot must fail");

        match error {
            KernelError::InvalidField { field, .. } => {
                assert_eq!(field, "control_reserve.config_snapshot_ref");
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }
}
