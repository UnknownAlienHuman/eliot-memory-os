//! A-03 authoritative update-set equivalence and discriminability (issue 610/11).
//!
//! Cell `smart.dreamer.contracts` owns vocabulary, equality, and materiality
//! judgments; the A-17b planner owns only admission gating on already-owned
//! descriptor dimensions and consumes the predeclared classification below
//! without inferring its own. Proof: equal, order-insensitive, duplicates
//! policy, distinct (including owner-digest participation), and the
//! discriminability classification over branch update sets.

#![allow(clippy::expect_used)]

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::rival::{RivalModelRef, RivalPredictionRef};
use eliot_dreamer_contracts::{
    GapUpdateMeaning, PossibleResultSchema, PossibleResultValue, ProbeObjectiveRef, ResultBranch,
    ResultTarget, ResultUpdate, ResultUpdateDiscriminability, RivalUpdateMeaning,
    update_sets_equal,
};

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("valid test artifact id")
}

fn objective(id: &str, digest_seed: &str) -> ProbeObjectiveRef {
    ProbeObjectiveRef {
        objective_id: aid(id),
        objective_digest: digest_seed.repeat(64),
    }
}

fn gap_update(digest_seed: &str, meaning: GapUpdateMeaning) -> ResultUpdate {
    ResultUpdate::Gap {
        objective: objective("objective-610", digest_seed),
        meaning,
    }
}

fn rival_update(
    model_digest_seed: &str,
    prediction_digest_seed: &str,
    meaning: RivalUpdateMeaning,
) -> ResultUpdate {
    ResultUpdate::Rival {
        model: RivalModelRef {
            model_id: aid("model-610"),
            model_revision: 1,
            declaration_digest: model_digest_seed.repeat(64),
        },
        prediction: Some(RivalPredictionRef {
            prediction_id: aid("pred-610"),
            prediction_digest: prediction_digest_seed.repeat(64),
        }),
        meaning,
    }
}

fn branch(id: &str, updates: Vec<ResultUpdate>) -> ResultBranch {
    ResultBranch {
        result_id: aid(id),
        value: PossibleResultValue::Unknown {
            reason: "branch pending".to_owned(),
        },
        updates,
    }
}

fn gap_schema(id: &str, objective_id: &str, branches: Vec<ResultBranch>) -> PossibleResultSchema {
    let target = objective("objective-610", objective_id);
    PossibleResultSchema::new(
        aid(id),
        vec![ResultTarget::Gap { objective: target }],
        branches,
    )
    .expect("equivalence fixture schema must validate")
}

// WORK_UNIT_CASE: 610/11 (equal)
#[test]
fn equal_update_sets_match() {
    let left = vec![
        gap_update("a", GapUpdateMeaning::Addressed),
        rival_update("a", "b", RivalUpdateMeaning::Strengthened),
    ];
    let right = left.clone();
    assert!(update_sets_equal(&left, &right));
    assert!(update_sets_equal(&[], &[]));
}

// WORK_UNIT_CASE: 610/11 (order-insensitive)
#[test]
fn update_set_equality_is_order_insensitive() {
    let first = gap_update("a", GapUpdateMeaning::Addressed);
    let second = rival_update("a", "b", RivalUpdateMeaning::Weakened);
    assert!(update_sets_equal(
        &[first.clone(), second.clone()],
        &[second, first]
    ));
}

// WORK_UNIT_CASE: 610/11 (duplicates policy)
#[test]
fn update_set_equality_uses_set_semantics() {
    let update = gap_update("a", GapUpdateMeaning::RemainsOpen);
    // Repetition alone never manufactures a distinction: update lists compare
    // as sets.
    assert!(update_sets_equal(
        &[update.clone(), update.clone()],
        &[update]
    ));
    // The set reading is sound because construction fails closed on a
    // repeated target, so set equality coincides with multiset equality on
    // every valid branch.
    let target = objective("objective-610", "a");
    let duplicate = branch(
        "dup-branch",
        vec![
            ResultUpdate::Gap {
                objective: target.clone(),
                meaning: GapUpdateMeaning::Addressed,
            },
            ResultUpdate::Gap {
                objective: target.clone(),
                meaning: GapUpdateMeaning::RemainsOpen,
            },
        ],
    );
    assert!(
        PossibleResultSchema::new(
            aid("dup-schema"),
            vec![ResultTarget::Gap { objective: target }],
            vec![duplicate],
        )
        .is_err(),
        "a branch naming one target twice must fail closed"
    );
}

// WORK_UNIT_CASE: 610/11 (distinct)
#[test]
fn distinct_update_sets_do_not_match() {
    assert!(!update_sets_equal(
        &[gap_update("a", GapUpdateMeaning::Addressed)],
        &[gap_update("a", GapUpdateMeaning::RemainsOpen)]
    ));
    assert!(!update_sets_equal(
        &[rival_update("a", "b", RivalUpdateMeaning::Strengthened)],
        &[rival_update("a", "b", RivalUpdateMeaning::Weakened)]
    ));
    assert!(!update_sets_equal(
        &[gap_update("a", GapUpdateMeaning::Addressed)],
        &[gap_update("b", GapUpdateMeaning::Addressed)]
    ));
    assert!(!update_sets_equal(
        &[ResultUpdate::Unknown {
            target: ResultTarget::Gap {
                objective: objective("objective-610", "a"),
            },
            reason: "first".to_owned(),
        }],
        &[ResultUpdate::Unknown {
            target: ResultTarget::Gap {
                objective: objective("objective-610", "a"),
            },
            reason: "second".to_owned(),
        }]
    ));
    assert!(!update_sets_equal(
        &[gap_update("a", GapUpdateMeaning::Addressed)],
        &[]
    ));
}

// WORK_UNIT_CASE: 610/11 (canonical typed equality, never Debug rendering)
#[test]
fn typed_equality_covers_owner_supplied_digests() {
    // A lossy string fingerprint that drops declaration digests would call
    // these equal; canonical typed equality does not.
    assert!(!update_sets_equal(
        &[rival_update("a", "b", RivalUpdateMeaning::Strengthened)],
        &[rival_update("c", "b", RivalUpdateMeaning::Strengthened)]
    ));
    assert!(!update_sets_equal(
        &[rival_update("a", "b", RivalUpdateMeaning::Strengthened)],
        &[rival_update("a", "d", RivalUpdateMeaning::Strengthened)]
    ));
}

// WORK_UNIT_CASE: 610/11 (discriminability: identical branches)
#[test]
fn identical_branch_update_sets_are_non_discriminating() {
    let single = gap_schema(
        "single-schema",
        "a",
        vec![branch(
            "single-branch",
            vec![gap_update("a", GapUpdateMeaning::RemainsOpen)],
        )],
    );
    assert_eq!(
        single.update_discriminability(),
        ResultUpdateDiscriminability::NonDiscriminating
    );
    let repeated = gap_schema(
        "repeated-schema",
        "a",
        vec![
            branch(
                "repeated-one",
                vec![gap_update("a", GapUpdateMeaning::Addressed)],
            ),
            branch(
                "repeated-two",
                vec![gap_update("a", GapUpdateMeaning::Addressed)],
            ),
        ],
    );
    assert_eq!(
        repeated.update_discriminability(),
        ResultUpdateDiscriminability::NonDiscriminating
    );
}

// WORK_UNIT_CASE: 610/11 (discriminability: split branches, order-insensitive)
#[test]
fn split_branch_update_sets_are_discriminating() {
    let split = gap_schema(
        "split-schema",
        "a",
        vec![
            branch(
                "split-one",
                vec![gap_update("a", GapUpdateMeaning::Addressed)],
            ),
            branch(
                "split-two",
                vec![gap_update("a", GapUpdateMeaning::RemainsOpen)],
            ),
        ],
    );
    assert_eq!(
        split.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    // Branch order and branch identity never decide: permuting the branches
    // of an equivalent pair keeps the classification.
    let reordered = gap_schema(
        "reordered-schema",
        "a",
        vec![
            branch(
                "reordered-two",
                vec![gap_update("a", GapUpdateMeaning::RemainsOpen)],
            ),
            branch(
                "reordered-one",
                vec![gap_update("a", GapUpdateMeaning::Addressed)],
            ),
        ],
    );
    assert_eq!(
        reordered.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    assert!(update_sets_equal(
        &split.branches[0].updates,
        &reordered.branches[1].updates
    ));
    assert!(update_sets_equal(
        &split.branches[1].updates,
        &reordered.branches[0].updates
    ));
}
