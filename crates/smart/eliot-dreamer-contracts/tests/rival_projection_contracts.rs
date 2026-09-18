//! Contract tests for the owner-neutral rival-model projection.
//!
//! Cell `smart.dreamer.contracts` (issue #1236, contracts half). Behaviour
//! proof only: positive, duplicate, mismatch, bounds, digest, ordering, and
//! unknown-dimension cases with deterministic replay. No algorithm, provider,
//! I/O, or A-16b implementation surface.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
};
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::rival::{ConditionAssumptionRef, MaterialClaimRef};
use eliot_dreamer_contracts::rival::{
    RIVAL_MODEL_SET_SCHEMA_VERSION, RequirementFacet, RequirementReason, RetainedDiscriminator,
    RivalCoverageDeclaration, RivalCoverageReceipt, RivalCoverageStatus, RivalCoverageSummary,
    RivalDeclarationSet, RivalDeclarationSetParams, RivalDeclarationSetRef, RivalModelRef,
    RivalModelSet, RivalModelSetParams, RivalPredictionRef, UnresolvedDiscriminatorRequirement,
};
use eliot_epistemic_contracts::{PropositionId, ValidityBounds};
use eliot_evaluation_contracts::ExpectedObservableSpec;

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("valid test artifact id")
}

fn tid() -> TaskId {
    TaskId::new("task-1236").expect("valid test task id")
}

fn scope() -> String {
    "scope-1236".to_owned()
}

fn model_ref(name: &str, revision: u64, seed: u64) -> RivalModelRef {
    RivalModelRef {
        model_id: aid(name),
        model_revision: revision,
        declaration_digest: format!("{seed:064}"),
    }
}

fn prediction_ref(name: &str, seed: u64) -> RivalPredictionRef {
    RivalPredictionRef {
        prediction_id: aid(name),
        prediction_digest: format!("{seed:064}"),
    }
}

fn claim_ref(name: &str, proposition: &str, seed: u64) -> MaterialClaimRef {
    MaterialClaimRef {
        claim_id: name.to_owned(),
        proposition: PropositionId::new(proposition).expect("valid test proposition"),
        claim_preimage_digest: format!("{seed:064}"),
    }
}

fn assumption_ref(name: &str, seed: u64) -> ConditionAssumptionRef {
    ConditionAssumptionRef {
        assumption_id: name.to_owned(),
        assumption_digest: format!("{seed:064}"),
    }
}

fn bounds() -> ValidityBounds {
    ValidityBounds {
        scope: scope(),
        window_start_ms: None,
        window_end_ms: None,
        version: "v1".to_owned(),
        precision: "file".to_owned(),
    }
}

fn observable(property: &str) -> ExpectedObservableSpec {
    ExpectedObservableSpec {
        property: property.to_owned(),
        matcher: "equals".to_owned(),
        artifact_selector: "artifact-a".to_owned(),
    }
}

fn discriminator(tag: &str, seed: u64) -> RetainedDiscriminator {
    RetainedDiscriminator {
        expected_model: model_ref(&format!("model-expected-{tag}"), 1, seed),
        expected_prediction: prediction_ref(&format!("pred-expected-{tag}"), seed + 1),
        falsifying_model: model_ref(&format!("model-falsifying-{tag}"), 1, seed + 2),
        falsifying_prediction: prediction_ref(&format!("pred-falsifying-{tag}"), seed + 3),
        target: claim_ref(&format!("claim-{tag}"), &format!("prop-{tag}"), seed + 4),
        applicability: bounds(),
        condition_assumptions: BTreeSet::new(),
        observable: observable(&format!("property-{tag}")),
    }
}

fn requirement(
    row: u32,
    facet: RequirementFacet,
    reason: RequirementReason,
) -> UnresolvedDiscriminatorRequirement {
    let entry = match facet {
        RequirementFacet::Expected | RequirementFacet::Falsifier => Some(row),
        RequirementFacet::PredictionReferences | RequirementFacet::ModelFrontier => None,
    };
    UnresolvedDiscriminatorRequirement {
        model_row: row,
        prediction_ref_entry: entry,
        facet,
        peer: None,
        reason,
    }
}

fn unknown_coverage(label: &str) -> RivalCoverageDeclaration {
    RivalCoverageDeclaration::Unknown {
        denominator_digest: None,
        receipt: RivalCoverageReceipt::Unavailable {
            receipt_digest: None,
            reason: format!("no receipt for {label}"),
        },
        reason: format!("{label} denominator not supplied"),
    }
}

fn declaration_set() -> RivalDeclarationSet {
    RivalDeclarationSet::new(RivalDeclarationSetParams {
        set_id: aid("decl-set-1236"),
        task_id: tid(),
        scope: scope(),
        state_fence: fence(),
        models: Vec::new(),
        related_models: Vec::new(),
        claims: Vec::new(),
        assumptions: Vec::new(),
        predictions: Vec::new(),
        sources: Vec::new(),
        model_coverage: unknown_coverage("models"),
        source_coverage: unknown_coverage("sources"),
        unresolved: BTreeSet::new(),
    })
    .expect("declaration set fixture must validate")
}

fn unknown_summary() -> RivalCoverageSummary {
    RivalCoverageSummary {
        status: RivalCoverageStatus::Unknown,
        denominator_digest: None,
    }
}

fn projection_params(
    declaration: &RivalDeclarationSet,
    discriminators: Vec<RetainedDiscriminator>,
    unresolved: Vec<UnresolvedDiscriminatorRequirement>,
    frontier: Vec<ArtifactId>,
) -> RivalModelSetParams {
    RivalModelSetParams {
        set_id: aid("projection-1236"),
        task_id: tid(),
        scope: scope(),
        state_fence: fence(),
        bundle_digest: "b".repeat(64),
        validated_input_digest: "c".repeat(64),
        declaration_set: RivalDeclarationSetRef {
            set_id: declaration.set_id.clone(),
            digest: declaration.digest.clone(),
        },
        policy_id: "policy-1236".to_owned(),
        policy_digest: "d".repeat(64),
        discriminators,
        unresolved,
        model_coverage: unknown_summary(),
        source_coverage: unknown_summary(),
        omission_frontier: frontier,
    }
}

fn fixture_projection() -> RivalModelSet {
    let declaration = declaration_set();
    RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("alpha", 100), discriminator("beta", 200)],
        vec![requirement(
            7,
            RequirementFacet::ModelFrontier,
            RequirementReason::OutsideAnalysisFrontier,
        )],
        vec![aid("frontier-1")],
    ))
    .expect("projection fixture must validate")
}

#[test]
fn positive_projection_validates_and_replays() {
    let set = fixture_projection();
    assert_eq!(set.schema_version, RIVAL_MODEL_SET_SCHEMA_VERSION);
    assert!(set.validate().is_ok(), "fixture projection must validate");
    assert!(set.validate().is_ok(), "validation must be stable");
    assert_eq!(
        set.compute_digest().expect("digest must compute"),
        set.digest,
        "computed digest must match frozen digest"
    );
    assert_eq!(set.discriminators.len(), 2);
    assert_eq!(set.unresolved.len(), 1);
}

#[test]
fn replay_is_deterministic() {
    let declaration = declaration_set();
    let first = RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("alpha", 100), discriminator("beta", 200)],
        vec![requirement(
            7,
            RequirementFacet::ModelFrontier,
            RequirementReason::OutsideAnalysisFrontier,
        )],
        vec![aid("frontier-1")],
    ))
    .expect("first replay must build");
    let second = RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("alpha", 100), discriminator("beta", 200)],
        vec![requirement(
            7,
            RequirementFacet::ModelFrontier,
            RequirementReason::OutsideAnalysisFrontier,
        )],
        vec![aid("frontier-1")],
    ))
    .expect("second replay must build");
    assert_eq!(first, second, "exact replay must be deterministic");
    assert_eq!(first.digest, second.digest);
}

#[test]
fn set_only_permutations_preserve_digest() {
    let declaration = declaration_set();
    let canonical = RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("alpha", 100), discriminator("beta", 200)],
        vec![
            requirement(3, RequirementFacet::Expected, RequirementReason::Unknown),
            requirement(
                7,
                RequirementFacet::ModelFrontier,
                RequirementReason::OutsideAnalysisFrontier,
            ),
        ],
        vec![aid("frontier-1"), aid("frontier-2")],
    ))
    .expect("canonical order must build");
    let permuted = RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("beta", 200), discriminator("alpha", 100)],
        vec![
            requirement(
                7,
                RequirementFacet::ModelFrontier,
                RequirementReason::OutsideAnalysisFrontier,
            ),
            requirement(3, RequirementFacet::Expected, RequirementReason::Unknown),
        ],
        vec![aid("frontier-2"), aid("frontier-1")],
    ))
    .expect("permuted order must build");
    assert!(permuted.validate().is_ok());
    assert_eq!(
        canonical.digest, permuted.digest,
        "set-only permutations must preserve the digest"
    );
}

#[test]
fn semantic_changes_alter_digest() {
    let declaration = declaration_set();
    let baseline = RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("alpha", 100)],
        Vec::new(),
        Vec::new(),
    ))
    .expect("baseline must build");
    let changed_observable = RivalModelSet::new(projection_params(
        &declaration,
        vec![RetainedDiscriminator {
            observable: observable("property-changed"),
            ..discriminator("alpha", 100)
        }],
        Vec::new(),
        Vec::new(),
    ))
    .expect("changed observable must build");
    assert_ne!(
        baseline.digest, changed_observable.digest,
        "observable change must alter the digest"
    );
    let changed_policy = RivalModelSet::new(RivalModelSetParams {
        policy_id: "policy-changed".to_owned(),
        ..projection_params(
            &declaration,
            vec![discriminator("alpha", 100)],
            Vec::new(),
            Vec::new(),
        )
    })
    .expect("changed policy must build");
    assert_ne!(
        baseline.digest, changed_policy.digest,
        "policy change must alter the digest"
    );
}

#[test]
fn duplicate_entries_fail() {
    let declaration = declaration_set();
    let duplicate_discriminator = RivalModelSet::new(projection_params(
        &declaration,
        vec![discriminator("alpha", 100), discriminator("alpha", 100)],
        Vec::new(),
        Vec::new(),
    ));
    assert!(
        matches!(
            duplicate_discriminator,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "duplicate discriminators must fail"
    );
    let duplicate_requirement = RivalModelSet::new(projection_params(
        &declaration,
        Vec::new(),
        vec![
            requirement(3, RequirementFacet::Expected, RequirementReason::Unknown),
            requirement(3, RequirementFacet::Expected, RequirementReason::Unknown),
        ],
        Vec::new(),
    ));
    assert!(
        matches!(
            duplicate_requirement,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "duplicate requirements must fail"
    );
    let duplicate_frontier = RivalModelSet::new(projection_params(
        &declaration,
        Vec::new(),
        Vec::new(),
        vec![aid("frontier-1"), aid("frontier-1")],
    ));
    assert!(
        matches!(
            duplicate_frontier,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "duplicate frontier addresses must fail"
    );
}

#[test]
fn same_identity_with_changed_meaning_conflicts() {
    let declaration = declaration_set();
    let changed_observable = RivalModelSet::new(projection_params(
        &declaration,
        vec![
            discriminator("alpha", 100),
            RetainedDiscriminator {
                observable: observable("property-changed"),
                ..discriminator("alpha", 100)
            },
        ],
        Vec::new(),
        Vec::new(),
    ));
    assert!(
        matches!(
            changed_observable,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same discriminator identity with changed meaning must conflict"
    );
    let changed_reason = RivalModelSet::new(projection_params(
        &declaration,
        Vec::new(),
        vec![
            requirement(3, RequirementFacet::Expected, RequirementReason::Unknown),
            requirement(
                3,
                RequirementFacet::Expected,
                RequirementReason::Unavailable,
            ),
        ],
        Vec::new(),
    ));
    assert!(
        matches!(
            changed_reason,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same requirement address with changed reason must conflict"
    );
}

#[test]
fn unresolved_accounting_rules_hold() {
    assert!(
        requirement(3, RequirementFacet::Expected, RequirementReason::Unknown)
            .validate()
            .is_ok()
    );
    assert!(
        UnresolvedDiscriminatorRequirement {
            model_row: 3,
            prediction_ref_entry: None,
            facet: RequirementFacet::Expected,
            peer: None,
            reason: RequirementReason::Unknown,
        }
        .validate()
        .is_err(),
        "expected facet without a prediction entry must fail"
    );
    assert!(
        UnresolvedDiscriminatorRequirement {
            model_row: 3,
            prediction_ref_entry: Some(3),
            facet: RequirementFacet::ModelFrontier,
            peer: None,
            reason: RequirementReason::OutsideAnalysisFrontier,
        }
        .validate()
        .is_err(),
        "frontier facet with a prediction entry must fail"
    );
    assert!(
        requirement(
            3,
            RequirementFacet::Expected,
            RequirementReason::OutsideAnalysisFrontier
        )
        .validate()
        .is_err(),
        "frontier reason on a non-frontier facet must fail"
    );
}

#[test]
fn bounds_reject_overflow_and_malformed_shape() {
    let declaration = declaration_set();
    let mut many = Vec::new();
    for index in 0..257 {
        many.push(discriminator(&format!("bulk-{index}"), 10_000 + index * 10));
    }
    let overflow = RivalModelSet::new(projection_params(
        &declaration,
        many,
        Vec::new(),
        Vec::new(),
    ));
    assert!(
        matches!(overflow, Err(ContractViolation::OutOfBounds { .. })),
        "discriminator overflow must fail with OutOfBounds"
    );
    let long_policy = RivalModelSet::new(RivalModelSetParams {
        policy_id: "p".repeat(4097),
        ..projection_params(&declaration, Vec::new(), Vec::new(), Vec::new())
    });
    assert!(long_policy.is_err(), "over-long policy identity must fail");
    let self_match = RetainedDiscriminator {
        falsifying_model: model_ref("model-expected-solo", 1, 500),
        falsifying_prediction: prediction_ref("pred-expected-solo", 501),
        expected_model: model_ref("model-expected-solo", 1, 500),
        expected_prediction: prediction_ref("pred-expected-solo", 501),
        target: claim_ref("claim-solo", "prop-solo", 502),
        applicability: bounds(),
        condition_assumptions: BTreeSet::from([assumption_ref("assumption-solo", 503)]),
        observable: observable("property-solo"),
    };
    assert!(
        self_match.validate().is_err(),
        "identical expected/falsifying endpoints must fail"
    );
    let empty = RivalModelSet::new(projection_params(
        &declaration,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ))
    .expect("empty tables must build");
    assert!(empty.validate().is_ok(), "empty projection must validate");
}

#[test]
fn tampered_digest_and_noncanonical_order_fail() {
    let mut tampered = fixture_projection();
    tampered.digest = "e".repeat(64);
    assert!(
        matches!(
            tampered.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "tampered digest must fail"
    );
    let mut reordered = fixture_projection();
    reordered.discriminators.swap(0, 1);
    assert!(
        matches!(
            reordered.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "non-canonical discriminator order must fail"
    );
    let mut wrong_version = fixture_projection();
    wrong_version.schema_version = 99;
    assert!(
        wrong_version.validate().is_err(),
        "wrong schema version must fail"
    );
}

#[test]
fn coverage_accounting_stays_explicit() {
    assert!(
        RivalCoverageSummary {
            status: RivalCoverageStatus::Complete,
            denominator_digest: None,
        }
        .validate()
        .is_err(),
        "complete coverage without a denominator must fail"
    );
    assert!(
        RivalCoverageSummary {
            status: RivalCoverageStatus::Unknown,
            denominator_digest: Some("f".repeat(64)),
        }
        .validate()
        .is_err(),
        "unknown coverage must not bind a denominator"
    );
    assert!(
        RivalCoverageSummary {
            status: RivalCoverageStatus::Complete,
            denominator_digest: Some("f".repeat(64)),
        }
        .validate()
        .is_ok()
    );
    assert!(
        RivalCoverageSummary {
            status: RivalCoverageStatus::Partial,
            denominator_digest: None,
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn unknown_requirements_never_read_as_retained() {
    let declaration = declaration_set();
    let set = RivalModelSet::new(projection_params(
        &declaration,
        Vec::new(),
        vec![
            requirement(1, RequirementFacet::Expected, RequirementReason::Unknown),
            requirement(
                2,
                RequirementFacet::Falsifier,
                RequirementReason::Unavailable,
            ),
        ],
        Vec::new(),
    ))
    .expect("unknown requirements must build");
    assert!(set.validate().is_ok());
    assert!(
        set.discriminators.is_empty(),
        "unresolved requirements must not appear as retained discriminators"
    );
    assert_eq!(set.unresolved.len(), 2);
    assert!(
        set.unresolved
            .iter()
            .all(|item| item.reason == RequirementReason::Unknown
                || item.reason == RequirementReason::Unavailable)
    );
}

#[test]
fn projection_source_has_no_implementation_owner_or_stubs() {
    const SOURCE: &str = include_str!("../src/rival/projection.rs");
    const FORBIDDEN: &[&str] = &[
        "eliot_dreamer_rival_model",
        "eliot-dreamer-rival-model",
        "dreamer_rival_model",
        "dreamer-rival-model",
        "from_validated",
        concat!("todo", "!"),
        concat!("unimplemented", "!"),
        concat!("serde_json::", "Value"),
        "unsafe ",
    ];
    assert!(!SOURCE.is_empty(), "projection source must be non-empty");
    for token in FORBIDDEN {
        assert!(
            !SOURCE.contains(token),
            "projection source must not contain {token}"
        );
    }
}
