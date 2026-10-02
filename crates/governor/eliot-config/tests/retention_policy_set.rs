//! Proof for the declared retention policy set: the I3.11
//! `retention_and_backup_policy` value the schedule owner attests.
//!
//! One positive case (a narrower layer's declared ref narrows the compiled
//! vocabulary) and the refusals that keep the set a closed declaration: an
//! expansion outside the vocabulary, an empty set, and a duplicate ref.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "declared-set tests assert exact accepted and refused shapes with real owner inputs"
)]

use eliot_config::{
    COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS, ConfigError, ConfigPolicySnapshot, HumanOwner,
    MAX_DECLARED_RETENTION_POLICY_REFS, RETENTION_POLICY_SETTING_KEY, Setting, SourceCompleteness,
    compiled_default_retention_policy_refs, declared_retention_policy_ref,
    declared_retention_policy_refs, narrow_retention_policy_refs, retention_policy_setting_key,
};
use eliot_contracts::{EpochId, EpochLineageId, PolicyRevision, ResourceGeneration, StateFence};
use eliot_security_contracts::PolicyFence;
use std::num::NonZeroU64;

/// The compiled declared vocabulary, read through the owner constant so this
/// proof cannot drift from the declaration it proves.
const STANDARD: &str = COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[0];

fn declaration(policy_ref: &str) -> Setting {
    Setting {
        key: retention_policy_setting_key(policy_ref),
        value_ref: format!("policy:{policy_ref}"),
        owner_ref: "human-1".to_owned(),
    }
}

fn policy_ref_for(key: &str) -> Option<String> {
    declared_retention_policy_ref(key).map(ToOwned::to_owned)
}

#[test]
fn setting_key_round_trips_the_declared_policy_ref() {
    let key = retention_policy_setting_key(STANDARD);
    assert!(
        key.starts_with(RETENTION_POLICY_SETTING_KEY),
        "a declared policy must sit under the documented I3.11 field name"
    );
    assert_eq!(policy_ref_for(&key), Some(STANDARD.to_owned()));
    assert_eq!(
        policy_ref_for(RETENTION_POLICY_SETTING_KEY),
        None,
        "the bare field name declares no ref, so absence is not an empty ref"
    );
    assert_eq!(policy_ref_for("task.budget.per_job"), None);
}

#[test]
fn a_narrower_layer_narrows_the_compiled_vocabulary() {
    let running = compiled_default_retention_policy_refs();
    assert_eq!(running, vec![STANDARD.to_owned()]);
    let narrowed = narrow_retention_policy_refs(&running, &[STANDARD.to_owned()])
        .expect("the compiled ref may be restated by a narrower layer");
    assert_eq!(narrowed, running, "a restatement narrows to the same set");
}

#[test]
fn expansion_outside_the_vocabulary_is_refused() {
    let running = compiled_default_retention_policy_refs();
    let error = narrow_retention_policy_refs(
        &running,
        &[
            STANDARD.to_owned(),
            "eliot.governor.retention.forever:1.0.0".to_owned(),
        ],
    )
    .expect_err("I3.9:15 permits narrowing only");
    assert!(
        matches!(
            error,
            ConfigError::UndeclaredRetentionPolicy { ref policy_ref } if policy_ref == "eliot.governor.retention.forever:1.0.0"
        ),
        "unexpected: {error}"
    );
}

#[test]
fn empty_and_duplicate_and_overbounded_sets_are_refused() {
    let running = compiled_default_retention_policy_refs();
    assert_eq!(
        narrow_retention_policy_refs(&running, &[]).expect_err("an empty set refuses"),
        ConfigError::EmptyRetentionPolicySet,
        "an empty attestation would refuse every retention read"
    );
    assert!(matches!(
        narrow_retention_policy_refs(&running, &[STANDARD.to_owned(), STANDARD.to_owned()])
            .expect_err("a repeated ref is ambiguous"),
        ConfigError::DuplicateRetentionPolicy { .. }
    ));
    // The count is checked before membership, so an over-long list is refused as
    // over-long rather than as an expansion of its first undeclared ref.
    let overbounded: Vec<String> = (0..=MAX_DECLARED_RETENTION_POLICY_REFS)
        .map(|index| format!("policy-{index}"))
        .collect();
    assert!(matches!(
        narrow_retention_policy_refs(&running, &overbounded)
            .expect_err("an overbounded set refuses"),
        ConfigError::TooManyRetentionPolicyRefs { .. }
    ));
}

#[test]
fn compiled_vocabulary_is_non_empty_and_bounded() {
    assert!(
        !COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS.is_empty(),
        "the compiled broadest layer must attest at least one ref, or every read refuses"
    );
    assert!(
        COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS.len() <= MAX_DECLARED_RETENTION_POLICY_REFS
    );
}

fn snapshot_with(settings: Vec<Setting>) -> ConfigPolicySnapshot {
    let fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    );
    ConfigPolicySnapshot {
        snapshot_id: "policy-snapshot-1".to_owned(),
        machine_id: "machine-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        revision: PolicyRevision::new(1).expect("policy revision"),
        source_completeness: SourceCompleteness::Complete,
        settings,
        policy_owner: HumanOwner {
            owner_ref: "human-1".to_owned(),
        },
        policy_fence: PolicyFence {
            policy_snapshot_id: "policy-snapshot-1".to_owned(),
            state_fence: fence.clone(),
        },
        state_fence: fence,
        parent_snapshot_id: None,
        rollback_of: None,
    }
}

#[test]
fn declared_refs_read_from_the_admitted_snapshot() {
    // Positive: the admitted policy snapshot names the compiled ref under the
    // documented I3.11 field, and that declared set is what the owner attests.
    let declared = snapshot_with(vec![declaration(STANDARD)]);
    assert_eq!(
        declared_retention_policy_refs(&declared).expect("declared set"),
        vec![STANDARD.to_owned()]
    );
    assert_eq!(
        declared_retention_policy_ref(&declaration(STANDARD).key),
        Some(STANDARD)
    );

    // A snapshot that declares nothing under the field abstains: it carries the
    // compiled vocabulary forward rather than an always-refusing empty set.
    let abstaining = snapshot_with(vec![Setting {
        key: "mode".to_owned(),
        value_ref: "ref:mode".to_owned(),
        owner_ref: "human-1".to_owned(),
    }]);
    assert_eq!(
        declared_retention_policy_refs(&abstaining).expect("abstaining set"),
        compiled_default_retention_policy_refs()
    );

    // Refusal: a snapshot declaring a ref outside the compiled vocabulary is
    // not a declaration, so the owner refuses it rather than attesting it.
    let expanding = snapshot_with(vec![declaration("eliot.governor.retention.forever:1.0.0")]);
    assert!(matches!(
        declared_retention_policy_refs(&expanding).expect_err("expansion refuses"),
        ConfigError::UndeclaredRetentionPolicy { .. }
    ));
}
