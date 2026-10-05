//! I14.3 multidimensional control-reserve profile compiler (issue #1679, W2).
//!
//! The frozen contract in
//! `crates/foundation/eliot-runtime-contracts/control-reserve.contract.toml`
//! names this step's owner: "Kernel composition over owner-produced capacity
//! evidence". This module is that composition step and nothing more. It joins
//! owner-supplied evidence into exactly one canonical row for every
//! [`CapacityBottleneck`], in the frozen contract order published by
//! [`frozen_bottleneck_owner_map`], and returns the profile only after the
//! existing [`ControlReserveProfile::validate`] accepts it.
//!
//! The contract itself is unchanged: this module neither weakens
//! [`ControlReserveProfile::validate`] nor adds a second legality check beside
//! it. A contradictory owner claim therefore fails through the frozen
//! validator, and a claim that is merely stale is lowered to an explicit
//! `UNKNOWN` row before it can be validated.
//!
//! What the compiler deliberately does not do:
//!
//! - it allocates nothing beyond the profile value it returns: no queue, no
//!   semaphore, no permit, no lease, no cache, no second capacity store;
//! - it grants no authority and acquires no capacity;
//! - it observes no owner. Every quantity in the result is copied from a
//!   [`BottleneckOwnerEvidence`] record an owner published;
//! - it substitutes no default. A dimension with no current record, or with a
//!   record taken under another configuration snapshot or Authority Epoch,
//!   becomes an explicit `UNKNOWN` row and its guarantee is named in
//!   [`ControlReserveProfile::unsupported_or_unknown_guarantees`];
//! - it never reuses another owner's counter. A `CLAIMED` record must name
//!   the owner the frozen owner map binds to that exact dimension.
//!
//! Two limits of what this step can decide, stated so no reader infers more
//! coverage than exists:
//!
//! - Owner-generation staleness is not checked here. The frozen
//!   [`frozen_bottleneck_owner_map`] binding carries no owner-generation
//!   value, and [`ControlReserveProfile`] carries no expected-generation
//!   field, so the compiler has no current generation to compare an owner's
//!   `owner_generation_ref` against. It binds the reference the owner
//!   published; detecting that the owner has since changed generation
//!   requires the owner adapters (issue #1679 W3).
//! - The owner record publishers are that same owner-wave migration. Until an
//!   owner adapter publishes a record, its dimension stays `UNKNOWN` here
//!   rather than being described from a neighbouring owner's numbers.
//!
//! Consequently this compiler currently has no in-tree call site. The
//! production caller the contract names is the Kernel composition that joins
//! owner evidence, and that edge does not exist in this tree. `STITCH`: the
//! compiler is landed without a caller rather than given a manufactured one
//! (no startup hook, no `fn main` call, no discarded-result statement).

use eliot_contracts::EpochId;
use eliot_runtime_contracts::{
    BottleneckCapacityProfile, BottleneckCoverageState, BottleneckOwnerBinding, CapacityBottleneck,
    ControlReserveProfile, frozen_bottleneck_owner_map,
};

use crate::error::{KernelError, KernelResult};

/// Owner-supplied capacity evidence for exactly one bottleneck dimension.
///
/// The owner publishes this record; the compiler never fills one in on an
/// owner's behalf. Two records for one dimension are a contradiction, and a
/// `CLAIMED` record must name the owner the frozen owner map binds to its
/// exact dimension, so one owner's numbers can never be presented as proof
/// for another dimension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BottleneckOwnerEvidence {
    /// Exact configuration snapshot the owner read its limits from.
    pub config_snapshot_ref: String,
    /// Exact canonical Authority Epoch the owner observed under.
    pub authority_epoch_ref: EpochId,
    /// The owner-produced row for its own bottleneck dimension.
    pub row: BottleneckCapacityProfile,
}

/// Composition-supplied identity of one compiled control-reserve profile.
///
/// The composition owns every field here and the compiler reads none of them
/// from a default: product identity, generation references, configuration
/// snapshot, profile revision, Authority Epoch, evidence references and
/// invalidation set are exactly the values the composition resolved. The
/// compiler itself opens no clock and consults no environment, so
/// `compiled_at_ms` can only be the composition's own existing clock reading.
///
/// The frozen [`ControlReserveProfile::validate`] checks the denominator, every
/// row, and the canonicity of the set-like fields. It does not police the
/// scalar identity strings, so supplying a real resolved configuration
/// snapshot, product identity, profile revision, and clock reading is the
/// composition's obligation; this step neither re-derives nor defaults them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReserveProfileIdentity {
    /// Stable profile identity.
    pub profile_id: String,
    /// Immutable revision of this profile.
    pub profile_revision: String,
    /// Exact product identity this profile describes.
    pub product_identity_ref: String,
    /// Source, build, and runtime generation references this profile binds.
    pub source_build_and_runtime_generation_refs: Vec<String>,
    /// Exact configuration snapshot the rows were read from.
    pub config_snapshot_ref: String,
    /// Canonical typed Authority Epoch every row is bound to.
    pub authority_epoch_ref: EpochId,
    /// Current clock reading in Unix milliseconds.
    pub compiled_at_ms: u64,
    /// Current profile-level evidence references.
    pub profile_evidence_refs: Vec<String>,
    /// Exact profile-level invalidation set.
    pub invalidation_set: Vec<String>,
}

/// Compiles the complete current capacity profile from owner evidence.
///
/// The result carries exactly one row per [`CapacityBottleneck`] in the frozen
/// contract order. A dimension whose record is missing, or whose record was
/// taken under a different configuration snapshot or Authority Epoch, is
/// lowered to an explicit `UNKNOWN` row with no capacity, owner, proof, or
/// evidence claim; a dimension whose owner declares no guarantee is lowered to
/// the state that owner declared. The profile is returned only when the frozen
/// [`ControlReserveProfile::validate`] accepts it, so a contradictory owner
/// claim fails here rather than being reported as a healthy dimension.
///
/// # Errors
///
/// Returns [`KernelError::ControlReserveEvidenceContradiction`] when two owner
/// records claim one dimension, or when a `CLAIMED` record names an owner the
/// frozen owner map does not bind to that dimension. Returns the existing
/// runtime-contract error when the joined rows or the identity are not
/// contract-canonical, for example when the disjoint partitions of a claimed
/// row exceed its physical total.
pub fn compile_control_reserve_profile(
    identity: ControlReserveProfileIdentity,
    owner_evidence: &[BottleneckOwnerEvidence],
) -> KernelResult<ControlReserveProfile> {
    let owner_map = frozen_bottleneck_owner_map();
    for (index, evidence) in owner_evidence.iter().enumerate() {
        if owner_evidence[..index]
            .iter()
            .any(|earlier| earlier.row.bottleneck == evidence.row.bottleneck)
        {
            return Err(contradiction(
                evidence.row.bottleneck,
                "DUPLICATE_OWNER_EVIDENCE: two owner records claim one dimension",
            ));
        }
    }

    let mut rows = Vec::with_capacity(owner_map.len());
    let mut lowered_guarantees = Vec::new();
    for bound in &owner_map {
        let current = owner_evidence
            .iter()
            .find(|evidence| evidence.row.bottleneck == bound.bottleneck);
        match current {
            Some(evidence) if is_current(evidence, &identity) => {
                if evidence.row.coverage_state == BottleneckCoverageState::Claimed
                    && evidence.row.owner_ref != bound.owner
                {
                    return Err(contradiction(
                        bound.bottleneck,
                        "CONTRADICTORY_OWNER: a claimed row names an owner the frozen owner map does not bind to this dimension",
                    ));
                }
                let coverage = evidence.row.coverage_state;
                rows.push(evidence.row.clone());
                if coverage != BottleneckCoverageState::Claimed {
                    lowered_guarantees.push(lowered_guarantee(bound.bottleneck, coverage));
                }
            }
            Some(_) | None => {
                // Missing or stale evidence lowers the dependent guarantee. No
                // limit, owner, generation, enforcement, proof profile, or
                // evidence reference is substituted for the missing record.
                rows.push(unclaimed_row(bound));
                lowered_guarantees.push(lowered_guarantee(
                    bound.bottleneck,
                    BottleneckCoverageState::Unknown,
                ));
            }
        }
    }
    // The frozen contract requires the lowered-guarantee set to be canonical
    // and duplicate-free, and this compiler is the only producer of it.
    lowered_guarantees.sort_unstable();

    let profile = ControlReserveProfile {
        profile_id: identity.profile_id,
        profile_revision: identity.profile_revision,
        product_identity_ref: identity.product_identity_ref,
        source_build_and_runtime_generation_refs: identity.source_build_and_runtime_generation_refs,
        config_snapshot_ref: identity.config_snapshot_ref,
        authority_epoch_ref: identity.authority_epoch_ref,
        compiled_at_ms: identity.compiled_at_ms,
        bottleneck_rows: rows,
        unsupported_or_unknown_guarantees: lowered_guarantees,
        profile_evidence_refs: identity.profile_evidence_refs,
        invalidation_set: identity.invalidation_set,
    };
    profile.validate()?;
    Ok(profile)
}

/// Reports whether one owner record was produced under the profile's exact
/// configuration snapshot and Authority Epoch.
///
/// The epoch comparison is the exact `(lineage, sequence)` tuple rule of
/// `types.EpochId`; two lineages at the same sequence are unrelated, never
/// merely current, so a record from another lineage lowers its guarantee
/// instead of being replayed.
fn is_current(
    evidence: &BottleneckOwnerEvidence,
    identity: &ControlReserveProfileIdentity,
) -> bool {
    evidence.config_snapshot_ref == identity.config_snapshot_ref
        && evidence
            .authority_epoch_ref
            .is_same_authority(&identity.authority_epoch_ref)
}

/// Builds the explicit row for a dimension with no current owner record.
///
/// The row binds the frozen bottleneck and unit and states `UNKNOWN`. It
/// carries no owner, owner generation, physical total, partition,
/// enforcement, proof profile, evidence reference, or invalidation entry,
/// because none of those is established without a current owner record, and a
/// coverage state asserted without a source is exactly the claim the frozen
/// contract refuses.
fn unclaimed_row(bound: &BottleneckOwnerBinding) -> BottleneckCapacityProfile {
    BottleneckCapacityProfile {
        bottleneck: bound.bottleneck,
        coverage_state: BottleneckCoverageState::Unknown,
        owner_ref: String::new(),
        owner_generation_ref: String::new(),
        unit: bound.unit,
        physical_total_limit: None,
        normal_work_applicable: false,
        normal_limit: None,
        protected_limit: None,
        emergency_limit: None,
        enforcement: None,
        proof_profile_ref: String::new(),
        evidence_refs: Vec::new(),
        invalidation_set: Vec::new(),
    }
}

/// Names the exact guarantee lowered for one dimension.
///
/// The name is the frozen contract identifier of the dimension followed by its
/// frozen coverage state, so a reader resolves the lowered guarantee from the
/// contract alone and no second vocabulary is introduced.
fn lowered_guarantee(bottleneck: CapacityBottleneck, coverage: BottleneckCoverageState) -> String {
    format!(
        "{}:{}",
        bottleneck.as_contract_str(),
        coverage.as_contract_str()
    )
}

/// Names the exact dimension whose owner evidence cannot be joined.
fn contradiction(bottleneck: CapacityBottleneck, reason: &'static str) -> KernelError {
    KernelError::ControlReserveEvidenceContradiction {
        bottleneck: bottleneck.as_contract_str(),
        reason,
    }
}

/// The observable face of exactly one compiled profile row (issue #1679, W10).
///
/// The nested [`BottleneckCapacityProfile`] is copied whole and in its own
/// unit: quantities from different bottlenecks are never summed, averaged, or
/// otherwise joined here, so bytes, handles, transactions and slots can never
/// collapse into one percentage. The row carries no permit semantics; holding
/// a projected row grants no capacity and admits no operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReserveStatusRow {
    /// The exact compiled row for one bottleneck dimension.
    pub row: BottleneckCapacityProfile,
    /// Whether this dimension's guarantee is lowered, i.e. its
    /// `bottleneck:coverage` name appears in the profile's
    /// `unsupported_or_unknown_guarantees`.
    pub guarantee_lowered: bool,
}

/// A bounded status and recovery snapshot of one compiled profile.
///
/// One row per bottleneck, in the profile's own order, plus the canonical
/// lowered-guarantee names a recovery consumer needs to name the exhausted
/// resource without re-deriving it. The snapshot is read-only data: it opens
/// no clock, reads no environment, performs no owner I/O, allocates nothing
/// beyond the snapshot itself, and grants no authority.
///
/// Consequently this projection currently has no in-tree consumer. The status
/// and recovery surfaces that render it do not exist in this tree. `STITCH`:
/// the projection is landed without a caller rather than given a manufactured
/// one (no startup hook, no `fn main` call, no discarded-result statement).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReserveStatusSnapshot {
    /// Stable profile identity of the projected profile.
    pub profile_id: String,
    /// Immutable revision of the projected profile.
    pub profile_revision: String,
    /// Exact configuration snapshot the projected rows were read from.
    pub config_snapshot_ref: String,
    /// Canonical typed Authority Epoch the projected rows are bound to.
    pub authority_epoch_ref: EpochId,
    /// Composition-supplied compilation time in Unix milliseconds.
    pub compiled_at_ms: u64,
    /// Exactly one row per bottleneck, in the profile's own row order.
    pub rows: Vec<ControlReserveStatusRow>,
    /// Canonical lowered-guarantee names of the projected profile.
    pub lowered_guarantees: Vec<String>,
}

/// Projects the complete current profile into a bounded status snapshot.
///
/// The profile is accepted only when the existing
/// [`ControlReserveProfile::validate`] accepts it, so a hand-built profile
/// that is not denominator-canonical fails here rather than projecting a
/// partial vector as a complete one. No second legality check is added.
///
/// # Errors
///
/// Returns the existing runtime-contract error when the profile is not
/// contract-canonical.
pub fn project_control_reserve_status(
    profile: &ControlReserveProfile,
) -> KernelResult<ControlReserveStatusSnapshot> {
    profile.validate()?;
    let mut rows = Vec::with_capacity(profile.bottleneck_rows.len());
    for row in &profile.bottleneck_rows {
        let lowered_name = lowered_guarantee(row.bottleneck, row.coverage_state);
        rows.push(ControlReserveStatusRow {
            row: row.clone(),
            guarantee_lowered: profile
                .unsupported_or_unknown_guarantees
                .contains(&lowered_name),
        });
    }
    Ok(ControlReserveStatusSnapshot {
        profile_id: profile.profile_id.clone(),
        profile_revision: profile.profile_revision.clone(),
        config_snapshot_ref: profile.config_snapshot_ref.clone(),
        authority_epoch_ref: profile.authority_epoch_ref.clone(),
        compiled_at_ms: profile.compiled_at_ms,
        rows,
        lowered_guarantees: profile.unsupported_or_unknown_guarantees.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn compile_empty_evidence_yields_fifteen_unknown_rows() -> KernelResult<()> {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch");
        let identity = ControlReserveProfileIdentity {
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-1".to_owned(),
            product_identity_ref: "product-1".to_owned(),
            source_build_and_runtime_generation_refs: vec!["gen-1".to_owned()],
            config_snapshot_ref: "snap-1".to_owned(),
            authority_epoch_ref: epoch,
            compiled_at_ms: 1_000,
            profile_evidence_refs: Vec::new(),
            invalidation_set: Vec::new(),
        };

        let profile = compile_control_reserve_profile(identity, &[])?;

        assert_eq!(profile.bottleneck_rows.len(), 15);
        assert!(
            profile
                .bottleneck_rows
                .iter()
                .all(|row| row.coverage_state == BottleneckCoverageState::Unknown)
        );
        Ok(())
    }

    #[test]
    fn project_compiled_unknown_profile_marks_every_guarantee_lowered() -> KernelResult<()> {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch");
        let identity = ControlReserveProfileIdentity {
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-1".to_owned(),
            product_identity_ref: "product-1".to_owned(),
            source_build_and_runtime_generation_refs: vec!["gen-1".to_owned()],
            config_snapshot_ref: "snap-1".to_owned(),
            authority_epoch_ref: epoch,
            compiled_at_ms: 1_000,
            profile_evidence_refs: Vec::new(),
            invalidation_set: Vec::new(),
        };

        let profile = compile_control_reserve_profile(identity, &[])?;
        let status = project_control_reserve_status(&profile)?;

        assert_eq!(status.rows.len(), 15);
        assert!(status.rows.iter().all(|row| row.guarantee_lowered));
        assert_eq!(status.lowered_guarantees.len(), 15);
        Ok(())
    }

    #[test]
    fn compile_duplicate_owner_evidence_fails_closed() -> KernelResult<()> {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch");
        let identity = ControlReserveProfileIdentity {
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-1".to_owned(),
            product_identity_ref: "product-1".to_owned(),
            source_build_and_runtime_generation_refs: vec!["gen-1".to_owned()],
            config_snapshot_ref: "snap-1".to_owned(),
            authority_epoch_ref: epoch.clone(),
            compiled_at_ms: 1_000,
            profile_evidence_refs: Vec::new(),
            invalidation_set: Vec::new(),
        };

        // Two records for one dimension: only the bottleneck matters for the
        // duplicate check, and `unclaimed_row` binds the frozen bottleneck and
        // unit with no invented capacity (issue #1679 A1).
        let map = frozen_bottleneck_owner_map();
        let row = unclaimed_row(&map[0]);
        let evidence = BottleneckOwnerEvidence {
            config_snapshot_ref: "snap-1".to_owned(),
            authority_epoch_ref: epoch,
            row,
        };

        let Err(err) = compile_control_reserve_profile(identity, &[evidence.clone(), evidence])
        else {
            panic!("two records for one dimension must contradict");
        };
        assert!(matches!(
            err,
            KernelError::ControlReserveEvidenceContradiction { bottleneck, .. }
                if bottleneck == map[0].bottleneck.as_contract_str()
        ));
        Ok(())
    }
}
