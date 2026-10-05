//! W1 (#1679): the fifteen frozen owner rows carry partition, generation,
//! evidence and invalidation at the profile-row level.
//!
//! The frozen denominator (`frozen_bottleneck_owner_map`, mirroring the
//! `[[bottleneck_contract]]` rows of `control-reserve.contract.toml`) names
//! only bottleneck, unit and owner: generation, evidence and invalidation are
//! runtime per-claim values and cannot be frozen. They ride on the
//! `BottleneckCapacityProfile` row built from each binding, where
//! `validate` enforces all four for a CLAIMED row: disjoint partitions with an
//! enforcement mechanism, a non-blank owner generation, non-empty evidence
//! refs, and a non-empty invalidation set. These tests pin that mapping for
//! every one of the fifteen rows.
use eliot_runtime_contracts::{
    BottleneckCapacityProfile, BottleneckCoverageState, BottleneckOwnerBinding,
    CapacityEnforcement, CapacityLimit, frozen_bottleneck_owner_map,
};
use std::num::NonZeroU64;

fn limit(binding: &BottleneckOwnerBinding, quantity: u64) -> CapacityLimit {
    CapacityLimit {
        unit: binding.unit,
        quantity: NonZeroU64::new(quantity).expect("test quantity is positive"),
    }
}

/// A CLAIMED profile row built from one frozen owner binding, carrying all
/// four W1 properties: partitions (normal + protected under a physical total
/// with an enforcement mechanism), owner generation, evidence, invalidation.
fn claimed_row(binding: &BottleneckOwnerBinding) -> BottleneckCapacityProfile {
    BottleneckCapacityProfile {
        bottleneck: binding.bottleneck,
        coverage_state: BottleneckCoverageState::Claimed,
        owner_ref: binding.owner.to_owned(),
        owner_generation_ref: "resource-generation:7".to_owned(),
        unit: binding.unit,
        physical_total_limit: Some(limit(binding, 16)),
        normal_work_applicable: true,
        normal_limit: Some(limit(binding, 8)),
        protected_limit: Some(limit(binding, 4)),
        emergency_limit: None,
        enforcement: Some(CapacityEnforcement::PhysicalPartition),
        proof_profile_ref: "proof-profile:owner-capacity-proof".to_owned(),
        evidence_refs: vec!["evidence:owner-capacity-observation".to_owned()],
        invalidation_set: vec!["invalidation:epoch-close".to_owned()],
    }
}

#[test]
fn every_owner_row_claims_partition_generation_evidence_and_invalidation() {
    let map = frozen_bottleneck_owner_map();
    assert_eq!(map.len(), 15, "the frozen denominator is fifteen rows");
    for binding in &map {
        claimed_row(binding)
            .validate()
            .expect("a fully populated row from the frozen owner map validates");
    }
}

#[test]
fn claimed_row_without_owner_generation_fails_closed() {
    let binding = &frozen_bottleneck_owner_map()[0];
    let mut row = claimed_row(binding);
    row.owner_generation_ref.clear();
    assert!(row.validate().is_err(), "generation is required");
}

#[test]
fn claimed_row_without_evidence_fails_closed() {
    let binding = &frozen_bottleneck_owner_map()[0];
    let mut row = claimed_row(binding);
    row.evidence_refs.clear();
    assert!(row.validate().is_err(), "evidence is required");
}

#[test]
fn claimed_row_without_invalidation_fails_closed() {
    let binding = &frozen_bottleneck_owner_map()[0];
    let mut row = claimed_row(binding);
    row.invalidation_set.clear();
    assert!(row.validate().is_err(), "invalidation set is required");
}

#[test]
fn claimed_row_without_protected_partition_fails_closed() {
    let binding = &frozen_bottleneck_owner_map()[0];
    let mut row = claimed_row(binding);
    row.protected_limit = None;
    row.enforcement = None;
    assert!(row.validate().is_err(), "partition is required");
}
