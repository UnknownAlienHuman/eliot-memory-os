//! Owner-seam proof for the retention schedule the Policy owner issues.
//!
//! The seam under test is `eliot_governor::PolicyOwner`: at recovery it issues
//! the owner-issued `RetentionSchedule` from the admitted
//! `ConfigPolicySnapshot`'s declared `retention_and_backup_policy` set, and
//! `resolve_retention_read` then admits or refuses against that schedule.
//!
//! One positive case (a declared ref is admitted as `Readable`) and the
//! refusals that keep the seam honest: an undeclared ref is refused as
//! `ExperienceRetentionReadPosture::UnknownPolicy { retention_policy_ref }`,
//! and a schedule whose fence is incompatible with the record's is refused the
//! same way. Both refusals use the existing typed posture; none of them is a
//! string, a boolean, or a relabelled default.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "owner-seam tests assert exact admitted and refused shapes with real owner inputs"
)]

use eliot_config::{
    COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS, ConfigPolicySnapshot, HumanOwner, Setting,
    SourceCompleteness, retention_policy_setting_key,
};
use eliot_contracts::{
    EpochId, EpochLineageId, PolicyRevision, ResourceGeneration, StateFence, canonical_json_bytes,
    sha256_hex,
};
use eliot_governor::{
    KernelNamedReadReply, OWNER_SNAPSHOT_SCHEMA, PolicyOwner, PolicyOwnerSnapshot, RecoveryOwner,
};
use eliot_observation_contracts::{
    ExperienceRetentionReadPosture, PrivacyRetentionDisclosure, resolve_retention_read,
};
use eliot_security_contracts::PolicyFence;
use std::num::NonZeroU64;

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence_at(generation: u64) -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("lineage id");
    let sequence = NonZeroU64::new(1).expect("nonzero sequence");
    let epoch = EpochId::new(lineage, sequence).expect("epoch id");
    let resource = ResourceGeneration::new(generation).expect("generation");
    StateFence::new(epoch, resource)
}

/// The admitted snapshot, declaring exactly the given retention policy rows.
fn policy_snapshot(fence: &StateFence, declared: &[&str]) -> ConfigPolicySnapshot {
    let mut settings = vec![Setting {
        key: "mode".to_owned(),
        value_ref: "ref:mode".to_owned(),
        owner_ref: "human-1".to_owned(),
    }];
    for policy_ref in declared {
        settings.push(Setting {
            key: retention_policy_setting_key(policy_ref),
            value_ref: format!("policy:{policy_ref}"),
            owner_ref: "human-1".to_owned(),
        });
    }
    ConfigPolicySnapshot {
        snapshot_id: "policy-snapshot-retention".to_owned(),
        machine_id: "policy-machine".to_owned(),
        scope_id: "governor".to_owned(),
        revision: PolicyRevision::new(1).expect("policy revision"),
        source_completeness: SourceCompleteness::Complete,
        settings,
        policy_owner: HumanOwner {
            owner_ref: "human-1".to_owned(),
        },
        policy_fence: PolicyFence {
            policy_snapshot_id: "policy-snapshot-retention".to_owned(),
            state_fence: fence.clone(),
        },
        state_fence: fence.clone(),
        parent_snapshot_id: None,
        rollback_of: None,
    }
}

/// The named-read reply the Kernel would serve for this snapshot.
fn policy_reply(snapshot: &ConfigPolicySnapshot) -> KernelNamedReadReply {
    let policy_digest = sha256_hex(&canonical_json_bytes(snapshot).expect("bytes"));
    let wire = PolicyOwnerSnapshot {
        state_fence: snapshot.state_fence.clone(),
        revision: snapshot.revision.value(),
        policy_digest,
        snapshot: snapshot.clone(),
    };
    let payload = canonical_json_bytes(&wire).expect("wire bytes");
    let value_digest = sha256_hex(&payload);
    KernelNamedReadReply {
        owner: RecoveryOwner::Policy,
        state_fence: snapshot.state_fence.clone(),
        revision: snapshot.revision.value(),
        schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
        value_digest,
        payload,
    }
}

/// A second, incompatible generation on the same authority epoch.
fn other_generation(fence: &StateFence) -> StateFence {
    let mut moved = fence.clone();
    moved.resource_generation = ResourceGeneration::new(2).expect("next generation");
    moved
}

fn owner_for(declared: &[&str]) -> PolicyOwner {
    let fence = fence_at(1);
    let snapshot = policy_snapshot(&fence, declared);
    let reply = policy_reply(&snapshot);
    PolicyOwner::recover(&reply, &fence).expect("policy owner recovery")
}

fn disclosure(policy_ref: &str) -> PrivacyRetentionDisclosure {
    PrivacyRetentionDisclosure {
        privacy_domain_ref: "governor-experience".to_owned(),
        retention_policy_ref: policy_ref.to_owned(),
        disclosure_class: "internal".to_owned(),
    }
}

#[test]
fn declared_policy_ref_is_admitted_as_readable() {
    let owner = owner_for(&[COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0]]);
    let schedule = owner.retention_schedule();

    // The schedule attests the declared set, not a defaulted or empty one.
    assert_eq!(
        schedule.known_policy_refs,
        COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS.map(str::to_owned),
        "the owner must attest the declared configuration, not a placeholder set"
    );
    schedule.validate().expect("issued schedule validates");

    let record_fence = fence_at(1);
    let posture = resolve_retention_read(
        &disclosure(COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0]),
        schedule,
        &record_fence,
        None,
    )
    .expect("retention read");
    assert_eq!(
        posture,
        ExperienceRetentionReadPosture::Readable {
            policy_ref: COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0].to_owned(),
        },
        "a record whose retention_policy_ref the declared configuration names is readable"
    );
}

#[test]
fn an_abstaining_snapshot_still_attests_the_compiled_default() {
    // No `retention_and_backup_policy` row: the owner abstains, and the
    // compiled declared vocabulary carries forward rather than an always-refusing
    // empty set.
    let owner = owner_for(&[]);
    let schedule = owner.retention_schedule();
    assert_eq!(
        schedule.known_policy_refs,
        COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS.map(str::to_owned)
    );
    let posture = resolve_retention_read(
        &disclosure(COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0]),
        schedule,
        &fence_at(1),
        None,
    )
    .expect("retention read");
    assert!(matches!(
        posture,
        ExperienceRetentionReadPosture::Readable { .. }
    ));
}

#[test]
fn an_undeclared_policy_ref_is_refused_as_unknown_policy() {
    let owner = owner_for(&[]);
    let schedule = owner.retention_schedule();
    let undeclared = "eliot.governor.retention.forever:1.0.0";
    assert!(
        !schedule.knows(undeclared),
        "a ref outside the declared set is not attested"
    );
    let posture = resolve_retention_read(&disclosure(undeclared), schedule, &fence_at(1), None)
        .expect("retention read");
    assert_eq!(
        posture,
        ExperienceRetentionReadPosture::UnknownPolicy {
            retention_policy_ref: undeclared.to_owned(),
        },
        "an undeclared ref is the existing typed UnknownPolicy gap, not a default"
    );
}

#[test]
fn an_incompatible_record_fence_is_refused_as_unknown_policy() {
    let owner = owner_for(&[]);
    let schedule = owner.retention_schedule();
    // The schedule was issued at generation 1; a record observed at generation 2
    // was not governed by it, so the schedule was not in force at the record.
    let record_fence = other_generation(&fence_at(1));
    let posture = resolve_retention_read(
        &disclosure(COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0]),
        schedule,
        &record_fence,
        None,
    )
    .expect("retention read");
    assert_eq!(
        posture,
        ExperienceRetentionReadPosture::UnknownPolicy {
            retention_policy_ref: COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0].to_owned(),
        },
        "a schedule not in force at the record is the same typed gap"
    );
}

#[test]
fn a_snapshot_declaring_an_undeclared_ref_fails_owner_recovery() {
    // The snapshot itself is well formed; the declared ref is what the compiled
    // vocabulary does not name. I3.9 permits narrowing only, so the owner must
    // refuse rather than attest an out-of-vocabulary policy.
    let fence = fence_at(1);
    let snapshot = policy_snapshot(&fence, &["eliot.governor.retention.forever:1.0.0"]);
    let reply = policy_reply(&snapshot);
    assert!(
        PolicyOwner::recover(&reply, &fence).is_err(),
        "an expanding retention declaration must fail the owner recovery closed"
    );
}

#[test]
fn the_issued_schedule_is_bound_to_the_admitted_snapshot_stream() {
    let fence = fence_at(1);
    let snapshot = policy_snapshot(&fence, &[]);
    let reply = policy_reply(&snapshot);
    let owner = PolicyOwner::recover(&reply, &fence).expect("policy owner");
    let schedule = owner.retention_schedule();
    assert_eq!(
        schedule.schedule_revision,
        owner.revision(),
        "the schedule revision tracks the durable policy revision of its own stream"
    );
    assert_eq!(
        schedule.schedule_id,
        format!("eliot.retention.schedule:{}", snapshot.snapshot_id),
        "the schedule identity is the admitted snapshot's own stream id"
    );
    assert_eq!(
        schedule.fence, fence,
        "the schedule is in force at the fence the recovery correlated"
    );
}
