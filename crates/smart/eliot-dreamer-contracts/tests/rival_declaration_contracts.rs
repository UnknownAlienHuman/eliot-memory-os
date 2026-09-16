//! Contract tests for canonical rival declarations and prediction contracts.
//!
//! Cell `smart.dreamer.contracts` (issue #1064, declaration half). Behaviour
//! proof only: schema versions, closed wire, canonical digests, bounds,
//! reference closure, duplicate-versus-changed identities, partial/missing
//! denominators, nontruth/noncausal boundaries, canonical permutation, inner
//! ordering, crate-root reexports, and `module.toml` outputs — with
//! deterministic replay. No algorithm, provider, I/O, coalescing,
//! equivalence, winner selection, or experiment surface.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, SourceId,
    StateFence, TaskId,
};
// Crate-root reexport proof: every rival declaration type used here resolves
// through the hub root, not only through `rival::`.
use eliot_dreamer_contracts::{
    ClaimDeclarations, CommonModeDisclosure, ConditionAssumptionRef, ContractViolation,
    CurrentPositionAvailability, CurrentPositionBinding, DeclarationAvailability,
    ForecastAvailability, MaterialClaimRef, PredictionAvailability,
    RIVAL_DECLARATION_SET_SCHEMA_VERSION, RIVAL_MODEL_SCHEMA_VERSION,
    RIVAL_PREDICTION_SCHEMA_VERSION, RelatedRivalModelReference, RivalAssumptionSlot,
    RivalClaimSlot, RivalCoverageDeclaration, RivalCoverageReceipt, RivalDeclarationSet,
    RivalDeclarationSetParams, RivalDependency, RivalForecast, RivalModelDeclaration,
    RivalModelDeclarationParams, RivalModelRef, RivalModelSlot, RivalPrediction,
    RivalPredictionParams, RivalPredictionRef, RivalPredictionSlot, RivalSourceSlot,
    SuppliedLineage, TemporalAvailability, VerifierAvailability,
    grounding::{
        ClaimKind, MaterialClaim, PrecisionPayload, component_content_digest,
        proposition_content_digest,
    },
    rival::RIVAL_MODEL_SCHEMA_VERSION as RIVAL_MODEL_SCHEMA_VERSION_VIA_MOD,
};
use eliot_epistemic_contracts::{
    AssumptionRecord, AssumptionRecordParams, CausalClaim, CausalClaimParams, CausalStatus,
    CoverageDenominator, CoverageDenominatorParams, DenominatorKind, EvidenceGrade, LineageRootId,
    PaginationBounds, PositionId, PositionRevision, PropositionId, SnapshotRef, SourceAssurance,
    SourceLineage, SourceRevisionId, TemporalRecord, ValidityBounds,
};
use eliot_evaluation_contracts::{ExpectedObservableSpec, PlannedVerifierRef};
use eliot_receipts::ProofCeiling;

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
    TaskId::new("task-1064").expect("valid test task id")
}

fn scope() -> String {
    "scope-1064".to_owned()
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

fn observable(property: &str) -> ExpectedObservableSpec {
    ExpectedObservableSpec {
        property: property.to_owned(),
        matcher: "equals".to_owned(),
        artifact_selector: "artifact-a".to_owned(),
    }
}

fn unknown_claims(label: &str) -> ClaimDeclarations {
    ClaimDeclarations::Unknown {
        reason: format!("{label} not supplied by owner"),
    }
}

fn not_applicable_entries<T>(label: &str) -> DeclarationAvailability<T> {
    DeclarationAvailability::NotApplicable {
        reason: format!("{label} does not apply"),
    }
}

fn unknown_lineage(label: &str) -> SuppliedLineage {
    SuppliedLineage::Unknown {
        closure_digest: None,
        reason: format!("{label} lineage not supplied"),
    }
}

fn unknown_forecast(label: &str) -> RivalForecast {
    RivalForecast {
        verifier_verdict: ForecastAvailability::Unknown {
            reason: format!("{label} verifier verdict not declared"),
        },
        diagnostic_change: ForecastAvailability::NotApplicable {
            reason: format!("{label} diagnostic change does not apply"),
        },
        effect_blast_radius: ForecastAvailability::Observable {
            spec: observable(&format!("{label}-blast-radius")),
        },
        expected_value_or_range: ForecastAvailability::Unknown {
            reason: format!("{label} value range not declared"),
        },
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

fn prediction_params(name: &str) -> RivalPredictionParams {
    RivalPredictionParams {
        prediction_id: aid(name),
        target: claim_ref("claim-p", "prop-p", 21),
        applicability: bounds(),
        condition_assumptions: BTreeSet::from([assumption_ref("asm-p", 22)]),
        expected: PredictionAvailability::Declared {
            observable: observable("property-p"),
        },
        falsifier: PredictionAvailability::Unknown {
            reason: "no falsifying observable declared".to_owned(),
        },
        forecast: unknown_forecast(name),
        verifier: VerifierAvailability::NotApplicable,
    }
}

fn fixture_prediction(name: &str) -> RivalPrediction {
    RivalPrediction::new(prediction_params(name)).expect("prediction fixture must validate")
}

fn fixture_prediction_ref() -> RivalPredictionRef {
    RivalPredictionRef::from_prediction(&fixture_prediction("pred-a"))
        .expect("prediction reference must derive")
}

fn model_params(name: &str, revision: u64) -> RivalModelDeclarationParams {
    RivalModelDeclarationParams {
        model_id: aid(name),
        model_revision: revision,
        predecessors: BTreeSet::new(),
        task_id: tid(),
        state_fence: fence(),
        applicability: bounds(),
        question: format!("which rival mechanism explains the observed delta for {name}"),
        explanations: vec![claim_ref("claim-a", "prop-a", 11)],
        assumptions: DeclarationAvailability::Supplied {
            entries: vec![assumption_ref("asm-a", 12)],
        },
        prediction_refs: DeclarationAvailability::Supplied {
            entries: vec![fixture_prediction_ref()],
        },
        dependency_refs: DeclarationAvailability::Supplied {
            entries: vec![RivalDependency::Record {
                record_id: aid("src-1"),
                content_digest: format!("{:064}", 31),
                source_revision: "rev-src-1".to_owned(),
            }],
        },
        support_observations: not_applicable_entries("support"),
        causal_readings: not_applicable_entries("causal readings"),
        conflicts: not_applicable_entries("conflicts"),
        supporting_claims: unknown_claims("supporting"),
        counterevidence_claims: unknown_claims("counterevidence"),
        revision_conditions: unknown_claims("revision"),
        invalidation_conditions: unknown_claims("invalidation"),
        successful_transfers: unknown_claims("successful transfers"),
        failed_transfers: unknown_claims("failed transfers"),
        downstream_effects: unknown_claims("downstream effects"),
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no current-position view applies".to_owned(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "temporal evidence not supplied".to_owned(),
        },
        lineage: unknown_lineage(name),
        common_mode: CommonModeDisclosure::Unknown {
            reason: "common mode not disclosed".to_owned(),
        },
        unresolved: BTreeSet::new(),
    }
}

fn fixture_model() -> RivalModelDeclaration {
    RivalModelDeclaration::new(model_params("model-a", 1)).expect("model fixture must validate")
}

fn unavailable_claim(name: &str, proposition: &str, seed: u64) -> RivalClaimSlot {
    RivalClaimSlot::Unavailable {
        claim_id: name.to_owned(),
        proposition: Some(PropositionId::new(proposition).expect("valid test proposition")),
        claim_preimage_digest: Some(format!("{seed:064}")),
        reason: format!("{name} payload unavailable in this carrier"),
    }
}

fn unavailable_assumption(name: &str, seed: u64) -> RivalAssumptionSlot {
    RivalAssumptionSlot::Unavailable {
        assumption_id: name.to_owned(),
        assumption_digest: Some(format!("{seed:064}")),
        reason: format!("{name} payload unavailable in this carrier"),
    }
}

fn unavailable_source(name: &str, seed: u64) -> RivalSourceSlot {
    RivalSourceSlot::Unavailable {
        handle: aid(name),
        content_digest: Some(format!("{seed:064}")),
        source_revision: Some(format!("rev-{name}")),
        reason: format!("{name} payload unavailable in this carrier"),
    }
}

fn set_params() -> RivalDeclarationSetParams {
    RivalDeclarationSetParams {
        set_id: aid("decl-set-1064"),
        task_id: tid(),
        scope: scope(),
        state_fence: fence(),
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(fixture_model()),
        }],
        related_models: Vec::new(),
        claims: vec![
            unavailable_claim("claim-a", "prop-a", 11),
            unavailable_claim("claim-p", "prop-p", 21),
        ],
        assumptions: vec![
            unavailable_assumption("asm-a", 12),
            unavailable_assumption("asm-p", 22),
        ],
        predictions: vec![RivalPredictionSlot::Retained {
            prediction: Box::new(fixture_prediction("pred-a")),
        }],
        sources: vec![RivalSourceSlot::Unavailable {
            handle: aid("src-1"),
            content_digest: Some(format!("{:064}", 31)),
            source_revision: Some("rev-src-1".to_owned()),
            reason: "src-1 payload unavailable in this carrier".to_owned(),
        }],
        model_coverage: unknown_coverage("models"),
        source_coverage: unknown_coverage("sources"),
        unresolved: BTreeSet::new(),
    }
}

fn fixture_set() -> RivalDeclarationSet {
    RivalDeclarationSet::new(set_params()).expect("declaration set fixture must validate")
}

#[test]
fn schema_versions_are_pinned() {
    assert_eq!(RIVAL_MODEL_SCHEMA_VERSION, 1);
    assert_eq!(RIVAL_PREDICTION_SCHEMA_VERSION, 1);
    assert_eq!(RIVAL_DECLARATION_SET_SCHEMA_VERSION, 1);
    assert_eq!(
        RIVAL_MODEL_SCHEMA_VERSION_VIA_MOD, RIVAL_MODEL_SCHEMA_VERSION,
        "module path and root reexport must agree"
    );
    assert_eq!(fixture_model().schema_version, RIVAL_MODEL_SCHEMA_VERSION);
    assert_eq!(
        fixture_prediction("pred-a").schema_version,
        RIVAL_PREDICTION_SCHEMA_VERSION
    );
    assert_eq!(
        fixture_set().schema_version,
        RIVAL_DECLARATION_SET_SCHEMA_VERSION
    );
}

#[test]
fn positive_model_prediction_and_set_validate_and_replay() {
    let model = fixture_model();
    assert!(model.validate().is_ok(), "fixture model must validate");
    assert!(model.validate().is_ok(), "model validation must be stable");
    assert_eq!(
        model.compute_digest().expect("model digest must compute"),
        model.digest,
        "model digest must match its frozen digest"
    );
    let prediction = fixture_prediction("pred-a");
    assert!(
        prediction.validate().is_ok(),
        "fixture prediction must validate"
    );
    assert_eq!(
        prediction
            .compute_digest()
            .expect("prediction digest must compute"),
        prediction.digest,
        "prediction digest must match its frozen digest"
    );
    let set = fixture_set();
    assert!(set.validate().is_ok(), "fixture set must validate");
    assert!(set.validate().is_ok(), "set validation must be stable");
    assert_eq!(
        set.compute_digest().expect("set digest must compute"),
        set.digest,
        "set digest must match its frozen digest"
    );
}

#[test]
fn replay_is_deterministic() {
    assert_eq!(
        fixture_model(),
        fixture_model(),
        "exact model replay must be deterministic"
    );
    assert_eq!(
        fixture_prediction("pred-a"),
        fixture_prediction("pred-a"),
        "exact prediction replay must be deterministic"
    );
    assert_eq!(
        fixture_set(),
        fixture_set(),
        "exact set replay must be deterministic"
    );
    assert_eq!(fixture_set().digest, fixture_set().digest);
}

#[test]
fn wire_roundtrip_is_closed() {
    let model = fixture_model();
    let model_value = serde_json::to_value(&model).expect("model must serialize");
    let model_roundtrip: RivalModelDeclaration =
        serde_json::from_value(model_value.clone()).expect("model must roundtrip");
    assert_eq!(model, model_roundtrip);
    let mut open_model = model_value;
    open_model["unexpected_field"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<RivalModelDeclaration>(open_model).is_err(),
        "model wire must reject unknown fields"
    );

    let prediction = fixture_prediction("pred-a");
    let prediction_value = serde_json::to_value(&prediction).expect("prediction must serialize");
    let prediction_roundtrip: RivalPrediction =
        serde_json::from_value(prediction_value.clone()).expect("prediction must roundtrip");
    assert_eq!(prediction, prediction_roundtrip);
    let mut open_prediction = prediction_value;
    open_prediction["unexpected_field"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<RivalPrediction>(open_prediction).is_err(),
        "prediction wire must reject unknown fields"
    );

    let set = fixture_set();
    let set_value = serde_json::to_value(&set).expect("set must serialize");
    let set_roundtrip: RivalDeclarationSet =
        serde_json::from_value(set_value.clone()).expect("set must roundtrip");
    assert_eq!(set, set_roundtrip);
    let mut open_set = set_value;
    open_set["unexpected_field"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<RivalDeclarationSet>(open_set).is_err(),
        "set wire must reject unknown fields"
    );
}

#[test]
fn tampered_digests_fail() {
    let mut model = fixture_model();
    model.digest = "e".repeat(64);
    assert!(
        matches!(
            model.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "tampered model digest must fail"
    );
    let mut prediction = fixture_prediction("pred-a");
    prediction.digest = "e".repeat(64);
    assert!(
        matches!(
            prediction.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "tampered prediction digest must fail"
    );
    let mut set = fixture_set();
    set.digest = "e".repeat(64);
    assert!(
        matches!(
            set.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "tampered set digest must fail"
    );
}

#[test]
fn wrong_schema_versions_fail() {
    let mut model = fixture_model();
    model.schema_version = 99;
    assert!(
        model.validate().is_err(),
        "wrong model schema version must fail"
    );
    let mut prediction = fixture_prediction("pred-a");
    prediction.schema_version = 99;
    assert!(
        prediction.validate().is_err(),
        "wrong prediction schema version must fail"
    );
    let mut set = fixture_set();
    set.schema_version = 99;
    assert!(
        set.validate().is_err(),
        "wrong set schema version must fail"
    );
}

#[test]
fn bounds_reject_overflow_and_overlong_text() {
    let overflow_explanations = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: (0..257u64)
            .map(|index| {
                claim_ref(
                    &format!("bulk-{index}"),
                    &format!("prop-{index}"),
                    10_000 + index,
                )
            })
            .collect(),
        ..model_params("model-overflow", 1)
    });
    assert!(
        matches!(
            overflow_explanations,
            Err(ContractViolation::OutOfBounds { .. })
        ),
        "explanation overflow must fail with OutOfBounds"
    );
    let long_question = RivalModelDeclaration::new(RivalModelDeclarationParams {
        question: "q".repeat(4097),
        ..model_params("model-long", 1)
    });
    assert!(long_question.is_err(), "over-long question text must fail");
    let overflow_unresolved = RivalModelDeclaration::new(RivalModelDeclarationParams {
        unresolved: (0..257).map(|index| format!("open-{index}")).collect(),
        ..model_params("model-open", 1)
    });
    assert!(
        matches!(
            overflow_unresolved,
            Err(ContractViolation::OutOfBounds { .. })
        ),
        "unresolved overflow must fail with OutOfBounds"
    );
    let overflow_models = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: (0..257)
            .map(|index| RivalModelSlot::Unavailable {
                model_id: aid(&format!("bulk-model-{index}")),
                model_revision: Some(1),
                declaration_digest: Some(format!("{:064}", 9_000 + index)),
                reason: format!("bulk model {index} unavailable"),
            })
            .collect(),
        ..set_params()
    });
    assert!(
        matches!(overflow_models, Err(ContractViolation::OutOfBounds { .. })),
        "model table overflow must fail with OutOfBounds"
    );
}

#[test]
fn duplicate_stable_identities_in_tables_fail() {
    let model = fixture_model();
    let duplicate_models = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model.clone()),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model),
            },
        ],
        ..set_params()
    });
    assert!(
        matches!(
            duplicate_models,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "duplicate model identities must fail"
    );
    let duplicate_claims = RivalDeclarationSet::new(RivalDeclarationSetParams {
        claims: vec![
            unavailable_claim("claim-a", "prop-a", 11),
            unavailable_claim("claim-a", "prop-a", 11),
        ],
        ..set_params()
    });
    assert!(
        matches!(
            duplicate_claims,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "duplicate claim identities must fail"
    );
    let duplicate_predictions = RivalDeclarationSet::new(RivalDeclarationSetParams {
        predictions: vec![
            RivalPredictionSlot::Retained {
                prediction: Box::new(fixture_prediction("pred-a")),
            },
            RivalPredictionSlot::Unavailable {
                prediction_id: aid("pred-a"),
                prediction_digest: None,
                reason: "duplicate prediction slot".to_owned(),
            },
        ],
        ..set_params()
    });
    assert!(
        duplicate_predictions.is_err(),
        "duplicate prediction identities must fail"
    );
}

#[test]
fn identical_repeats_hold_but_changed_same_id_content_conflicts() {
    let repeated = claim_ref("claim-a", "prop-a", 11);
    let identical_repeat = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: vec![repeated.clone(), repeated],
        ..model_params("model-repeat", 1)
    });
    assert!(
        identical_repeat.is_ok(),
        "byte-identical repeats carry no conflicting content"
    );
    let changed_digest = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: vec![
            claim_ref("claim-a", "prop-a", 11),
            claim_ref("claim-a", "prop-a", 12),
        ],
        ..model_params("model-changed-claim", 1)
    });
    assert!(
        matches!(
            changed_digest,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same claim identity with a changed digest must conflict"
    );
    let changed_proposition = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: vec![
            claim_ref("claim-a", "prop-a", 11),
            claim_ref("claim-a", "prop-b", 11),
        ],
        ..model_params("model-changed-prop", 1)
    });
    assert!(
        matches!(
            changed_proposition,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same claim identity with a changed proposition must conflict"
    );
    let changed_assumption = RivalModelDeclaration::new(RivalModelDeclarationParams {
        assumptions: DeclarationAvailability::Supplied {
            entries: vec![assumption_ref("asm-a", 12), assumption_ref("asm-a", 13)],
        },
        ..model_params("model-changed-asm", 1)
    });
    assert!(
        matches!(
            changed_assumption,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same assumption identity with a changed digest must conflict"
    );
    let changed_prediction = RivalModelDeclaration::new(RivalModelDeclarationParams {
        prediction_refs: DeclarationAvailability::Supplied {
            entries: vec![prediction_ref("pred-x", 41), prediction_ref("pred-x", 42)],
        },
        ..model_params("model-changed-pred", 1)
    });
    assert!(
        matches!(
            changed_prediction,
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same prediction identity with a changed digest must conflict"
    );
}

#[test]
fn dangling_references_fail_closure() {
    let dangling_claim = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(
                RivalModelDeclaration::new(RivalModelDeclarationParams {
                    explanations: vec![claim_ref("ghost-claim", "prop-ghost", 51)],
                    ..model_params("model-ghost-claim", 1)
                })
                .expect("standalone model needs no set closure"),
            ),
        }],
        ..set_params()
    });
    assert!(
        dangling_claim.is_err(),
        "explanation without a claim slot must fail closure"
    );
    let dangling_assumption = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(
                RivalModelDeclaration::new(RivalModelDeclarationParams {
                    assumptions: DeclarationAvailability::Supplied {
                        entries: vec![assumption_ref("ghost-asm", 52)],
                    },
                    ..model_params("model-ghost-asm", 1)
                })
                .expect("standalone model needs no set closure"),
            ),
        }],
        ..set_params()
    });
    assert!(
        dangling_assumption.is_err(),
        "assumption without a slot must fail closure"
    );
    let dangling_prediction = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(
                RivalModelDeclaration::new(RivalModelDeclarationParams {
                    prediction_refs: DeclarationAvailability::Supplied {
                        entries: vec![prediction_ref("ghost-pred", 53)],
                    },
                    ..model_params("model-ghost-pred", 1)
                })
                .expect("standalone model needs no set closure"),
            ),
        }],
        ..set_params()
    });
    assert!(
        dangling_prediction.is_err(),
        "prediction reference without a slot must fail closure"
    );
    let dangling_predecessor = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(
                RivalModelDeclaration::new(RivalModelDeclarationParams {
                    predecessors: BTreeSet::from([model_ref("ghost-model", 1, 54)]),
                    ..model_params("model-ghost-pred-model", 1)
                })
                .expect("standalone model needs no set closure"),
            ),
        }],
        ..set_params()
    });
    assert!(
        dangling_predecessor.is_err(),
        "predecessor without a model or related slot must fail closure"
    );
    let dangling_source = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(
                RivalModelDeclaration::new(RivalModelDeclarationParams {
                    dependency_refs: DeclarationAvailability::Supplied {
                        entries: vec![RivalDependency::Record {
                            record_id: aid("ghost-src"),
                            content_digest: format!("{:064}", 55),
                            source_revision: "rev-ghost".to_owned(),
                        }],
                    },
                    ..model_params("model-ghost-src", 1)
                })
                .expect("standalone model needs no set closure"),
            ),
        }],
        ..set_params()
    });
    assert!(
        dangling_source.is_err(),
        "record dependency without a source slot must fail closure"
    );
}

#[test]
fn related_models_anchor_external_predecessors() {
    let current = fixture_model();
    let predecessor = RivalModelRef::from_model(&current).expect("reference must derive");
    let successor = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: aid("model-b"),
        predecessors: BTreeSet::from([predecessor.clone()]),
        explanations: vec![claim_ref("claim-p", "prop-p", 21)],
        assumptions: not_applicable_entries("assumptions"),
        prediction_refs: not_applicable_entries("prediction refs"),
        ..model_params("model-b-ignored", 1)
    })
    .expect("successor model must build standalone");
    assert_eq!(successor.model_id, aid("model-b"));
    // Predecessor retained in the current table: closure holds without a related entry.
    let with_current = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(current.clone()),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(successor.clone()),
            },
        ],
        claims: vec![
            unavailable_claim("claim-a", "prop-a", 11),
            unavailable_claim("claim-p", "prop-p", 21),
        ],
        assumptions: vec![unavailable_assumption("asm-a", 12)],
        predictions: vec![RivalPredictionSlot::Unavailable {
            prediction_id: aid("pred-a"),
            prediction_digest: Some(fixture_prediction_ref().prediction_digest.clone()),
            reason: "pred-a payload unavailable here".to_owned(),
        }],
        ..set_params()
    });
    assert!(
        with_current.is_ok(),
        "predecessor retained in the current table must close"
    );
    // Predecessor known only as an external related reference: closure holds
    // through the related table with an explicit unavailable reason.
    let via_related = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(successor.clone()),
        }],
        related_models: vec![RelatedRivalModelReference {
            reference: predecessor.clone(),
            payload_unavailable_reason: "prior declaration retained by its owner".to_owned(),
        }],
        claims: vec![
            unavailable_claim("claim-a", "prop-a", 11),
            unavailable_claim("claim-p", "prop-p", 21),
        ],
        assumptions: vec![unavailable_assumption("asm-a", 12)],
        predictions: vec![RivalPredictionSlot::Unavailable {
            prediction_id: aid("pred-a"),
            prediction_digest: Some(fixture_prediction_ref().prediction_digest.clone()),
            reason: "pred-a payload unavailable here".to_owned(),
        }],
        ..set_params()
    });
    assert!(
        via_related.is_ok(),
        "external predecessor must close through the related table"
    );
    // A related entry that disagrees with the retained current declaration is
    // a conflict, never a silent overwrite.
    let conflicting_related = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(current),
        }],
        related_models: vec![RelatedRivalModelReference {
            reference: model_ref("model-a", 1, 77),
            payload_unavailable_reason: "stale external copy".to_owned(),
        }],
        ..set_params()
    });
    assert!(
        conflicting_related.is_err(),
        "related digest conflicting with current identity must fail"
    );
}

#[test]
fn unavailable_slots_keep_known_digests_honest() {
    let mismatched_claim = RivalDeclarationSet::new(RivalDeclarationSetParams {
        claims: vec![
            unavailable_claim("claim-a", "prop-a", 99),
            unavailable_claim("claim-p", "prop-p", 21),
        ],
        ..set_params()
    });
    assert!(
        mismatched_claim.is_err(),
        "unavailable claim digest conflicting with a reference must fail"
    );
    let mismatched_assumption = RivalDeclarationSet::new(RivalDeclarationSetParams {
        assumptions: vec![
            unavailable_assumption("asm-a", 98),
            unavailable_assumption("asm-p", 22),
        ],
        ..set_params()
    });
    assert!(
        mismatched_assumption.is_err(),
        "unavailable assumption digest conflicting with a reference must fail"
    );
    let mismatched_prediction = RivalDeclarationSet::new(RivalDeclarationSetParams {
        predictions: vec![RivalPredictionSlot::Unavailable {
            prediction_id: aid("pred-a"),
            prediction_digest: Some(format!("{:064}", 97)),
            reason: "stale digest copy".to_owned(),
        }],
        ..set_params()
    });
    assert!(
        mismatched_prediction.is_err(),
        "unavailable prediction digest conflicting with a reference must fail"
    );
    let mismatched_source = RivalDeclarationSet::new(RivalDeclarationSetParams {
        sources: vec![RivalSourceSlot::Unavailable {
            handle: aid("src-1"),
            content_digest: Some(format!("{:064}", 96)),
            source_revision: Some("rev-src-1".to_owned()),
            reason: "stale digest copy".to_owned(),
        }],
        ..set_params()
    });
    assert!(
        mismatched_source.is_err(),
        "unavailable source digest conflicting with a reference must fail"
    );
}

#[test]
fn retained_prediction_target_and_assumptions_must_resolve() {
    let dangling_target = RivalPrediction::new(RivalPredictionParams {
        target: claim_ref("ghost-target", "prop-ghost", 61),
        ..prediction_params("pred-ghost-target")
    })
    .expect("standalone prediction needs no set closure");
    let dangling_target_set = RivalDeclarationSet::new(RivalDeclarationSetParams {
        predictions: vec![RivalPredictionSlot::Retained {
            prediction: Box::new(dangling_target),
        }],
        ..set_params()
    });
    assert!(
        dangling_target_set.is_err(),
        "prediction target without a claim slot must fail closure"
    );
    let dangling_condition = RivalPrediction::new(RivalPredictionParams {
        condition_assumptions: BTreeSet::from([assumption_ref("ghost-condition", 62)]),
        ..prediction_params("pred-ghost-condition")
    })
    .expect("standalone prediction needs no set closure");
    let dangling_condition_set = RivalDeclarationSet::new(RivalDeclarationSetParams {
        predictions: vec![RivalPredictionSlot::Retained {
            prediction: Box::new(dangling_condition),
        }],
        ..set_params()
    });
    assert!(
        dangling_condition_set.is_err(),
        "prediction condition without an assumption slot must fail closure"
    );
    // A forecast carried as an exact retained-claim reference closes through
    // the claim table; absence of that claim is a failure, not a default.
    let forecast_claim = RivalPrediction::new(RivalPredictionParams {
        forecast: RivalForecast {
            verifier_verdict: ForecastAvailability::Unknown {
                reason: "verifier verdict not declared".to_owned(),
            },
            diagnostic_change: ForecastAvailability::NotApplicable {
                reason: "diagnostic change does not apply".to_owned(),
            },
            effect_blast_radius: ForecastAvailability::Claim {
                reference: claim_ref("claim-p", "prop-p", 21),
            },
            expected_value_or_range: ForecastAvailability::Unknown {
                reason: "value range not declared".to_owned(),
            },
        },
        ..prediction_params("pred-forecast-claim")
    })
    .expect("forecast-claim prediction must build standalone");
    let forecast_claim_set = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: Vec::new(),
        predictions: vec![RivalPredictionSlot::Retained {
            prediction: Box::new(forecast_claim),
        }],
        claims: vec![unavailable_claim("claim-p", "prop-p", 21)],
        assumptions: vec![unavailable_assumption("asm-p", 22)],
        sources: Vec::new(),
        ..set_params()
    });
    assert!(
        forecast_claim_set.is_ok(),
        "forecast claim reference must close through the claim table"
    );
}

#[test]
fn unknown_and_missing_denominators_stay_explicit() {
    assert!(
        unknown_coverage("models").validate().is_ok(),
        "unknown coverage with no denominator must validate"
    );
    assert!(
        RivalCoverageDeclaration::Unknown {
            denominator_digest: Some(format!("{:064}", 71)),
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: "receipt unavailable".to_owned(),
            },
            reason: "denominator digest known, payload missing".to_owned(),
        }
        .validate()
        .is_ok(),
        "known denominator digest with a missing payload must validate as unknown"
    );
    assert!(
        RivalCoverageDeclaration::Unknown {
            denominator_digest: None,
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: String::new(),
            },
            reason: "denominator not supplied".to_owned(),
        }
        .validate()
        .is_err(),
        "empty receipt reason must fail"
    );
    assert!(
        RivalCoverageDeclaration::Unknown {
            denominator_digest: None,
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: "receipt unavailable".to_owned(),
            },
            reason: String::new(),
        }
        .validate()
        .is_err(),
        "empty coverage reason must fail"
    );
    assert!(
        ClaimDeclarations::Unknown {
            reason: String::new(),
        }
        .validate("rival.test.claims")
        .is_err(),
        "empty unknown-claim reason must fail"
    );
    assert!(
        RivalModelDeclaration::new(RivalModelDeclarationParams {
            assumptions: DeclarationAvailability::Supplied {
                entries: Vec::new()
            },
            prediction_refs: not_applicable_entries("prediction refs"),
            ..model_params("model-empty-supplied", 1)
        })
        .is_ok(),
        "explicit empty supplied availability must validate"
    );
    // An empty declaration set with both denominators unknown is an honest
    // empty carrier: no completeness is claimed.
    let empty = RivalDeclarationSet::new(RivalDeclarationSetParams {
        set_id: aid("decl-set-empty"),
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
    .expect("empty set with unknown coverage must build");
    assert!(empty.validate().is_ok());
}

fn supplied_model_denominator(
    scope_value: &str,
    roles: &[&str],
    members: &[&str],
) -> CoverageDenominator {
    CoverageDenominator::new(CoverageDenominatorParams {
        class: "rival-model".to_owned(),
        schema: "schema-1064".to_owned(),
        revision: "rev-1064".to_owned(),
        scope: scope_value.to_owned(),
        fence: fence(),
        members: members.iter().map(|member| aid(member)).collect(),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        query: None,
        frontier: None,
        snapshot: SnapshotRef::new(
            "snapshot-1064",
            SourceId::new("owner-1064").expect("valid source"),
        )
        .expect("valid snapshot"),
        exclusions: Vec::new(),
        bounds: PaginationBounds::new(0, members.len().max(1) as u64, members.len() as u64, false)
            .expect("valid bounds"),
        validity: ValidityBounds {
            scope: scope_value.to_owned(),
            window_start_ms: None,
            window_end_ms: None,
            version: "v1".to_owned(),
            precision: "file".to_owned(),
        },
        kind: DenominatorKind::CompleteScope,
    })
    .expect("denominator fixture must validate")
}

#[test]
fn supplied_denominator_must_match_table_exactly() {
    let exact = RivalDeclarationSet::new(RivalDeclarationSetParams {
        model_coverage: RivalCoverageDeclaration::Supplied {
            denominator: Box::new(supplied_model_denominator(
                &scope(),
                &["rival-model"],
                &["model-a"],
            )),
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: "receipt not retained".to_owned(),
            },
        },
        ..set_params()
    });
    assert!(
        exact.is_ok(),
        "denominator with one role and exactly the table IDs must validate"
    );
    let wrong_scope = RivalDeclarationSet::new(RivalDeclarationSetParams {
        model_coverage: RivalCoverageDeclaration::Supplied {
            denominator: Box::new(supplied_model_denominator(
                "other-scope",
                &["rival-model"],
                &["model-a"],
            )),
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: "receipt not retained".to_owned(),
            },
        },
        ..set_params()
    });
    assert!(
        wrong_scope.is_err(),
        "denominator scope differing from the set must fail"
    );
    let two_roles = RivalDeclarationSet::new(RivalDeclarationSetParams {
        model_coverage: RivalCoverageDeclaration::Supplied {
            denominator: Box::new(supplied_model_denominator(
                &scope(),
                &["rival-model", "second-role"],
                &["model-a"],
            )),
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: "receipt not retained".to_owned(),
            },
        },
        ..set_params()
    });
    assert!(two_roles.is_err(), "denominator with two roles must fail");
    let foreign_member = RivalDeclarationSet::new(RivalDeclarationSetParams {
        model_coverage: RivalCoverageDeclaration::Supplied {
            denominator: Box::new(supplied_model_denominator(
                &scope(),
                &["rival-model"],
                &["ghost-model"],
            )),
            receipt: RivalCoverageReceipt::Unavailable {
                receipt_digest: None,
                reason: "receipt not retained".to_owned(),
            },
        },
        ..set_params()
    });
    assert!(
        foreign_member.is_err(),
        "denominator with a foreign member must fail"
    );
}

fn verifier_for(observed: ExpectedObservableSpec) -> PlannedVerifierRef {
    PlannedVerifierRef {
        verifier_id: ContractId::new("verifier-1064").expect("valid verifier id"),
        scope: scope(),
        verifier_config_hash: "config-1064".to_owned(),
        expected_observable: observed,
        environment_binding: "local fixture".to_owned(),
        verifier_authority_ref: "authority:test".to_owned(),
        contract_revision: ContractVersion::new(1, 0, 0),
        proof_ceiling: ProofCeiling::ScopedVerification,
    }
}

#[test]
fn forecast_and_verifier_nontruth_boundaries_hold() {
    assert!(
        PredictionAvailability::Unknown {
            reason: "expected observable not declared".to_owned(),
        }
        .validate("rival.test.expected")
        .is_ok()
    );
    assert!(
        PredictionAvailability::Declared {
            observable: ExpectedObservableSpec {
                property: String::new(),
                matcher: "equals".to_owned(),
                artifact_selector: "artifact-a".to_owned(),
            },
        }
        .validate("rival.test.expected")
        .is_err(),
        "declared observable with empty property must fail"
    );
    assert!(
        VerifierAvailability::NotApplicable.validate().is_ok(),
        "purely epistemic predictions carry no verifier"
    );
    assert!(
        VerifierAvailability::Unavailable {
            reason: "verifier expected but unavailable".to_owned(),
        }
        .validate()
        .is_ok()
    );
    // A supplied verifier must bind the known expected observable; a
    // mismatched verifier is rejected rather than executed or trusted.
    let mismatched = RivalPrediction::new(RivalPredictionParams {
        verifier: VerifierAvailability::Supplied {
            verifier: verifier_for(observable("other-property")),
        },
        ..prediction_params("pred-mismatched-verifier")
    });
    assert!(
        mismatched.is_err(),
        "verifier not binding the expected observable must fail"
    );
    let matched = RivalPrediction::new(RivalPredictionParams {
        prediction_id: aid("pred-verified"),
        verifier: VerifierAvailability::Supplied {
            verifier: verifier_for(observable("property-p")),
        },
        ..prediction_params("pred-verified")
    });
    assert!(
        matched.is_ok(),
        "verifier binding the expected observable must validate"
    );
    // Transfer evidence stays inert declaration data: unknown transfers
    // validate as unknown and never promote a winner.
    let transfers_unknown = fixture_model();
    assert!(
        matches!(
            transfers_unknown.successful_transfers,
            ClaimDeclarations::Unknown { .. }
        ) && matches!(
            transfers_unknown.failed_transfers,
            ClaimDeclarations::Unknown { .. }
        )
    );
}

fn causal_fixture(test_scope: &str) -> CausalClaim {
    let source = SourceId::new("source-causal").expect("valid source");
    let revision = SourceRevisionId::new("rev-causal").expect("valid revision");
    let proof_digest = format!("{:064}", 81);
    CausalClaim::new(CausalClaimParams {
        subject: PropositionId::new("prop-causal").expect("valid proposition"),
        status: CausalStatus::Association,
        mechanism: "observed co-variation sketch".to_owned(),
        rivals: BTreeSet::from(["rival sketch".to_owned()]),
        confounders: BTreeSet::new(),
        evidence_refs: BTreeSet::from([aid("evidence-causal")]),
        outcome: "delta observed under condition".to_owned(),
        control: "baseline condition".to_owned(),
        source: source.clone(),
        source_lineage: SourceLineage::new(
            source.clone(),
            revision.clone(),
            format!("{:064}", 82),
            None,
            BTreeSet::new(),
            None,
        )
        .expect("valid source lineage"),
        assurance: SourceAssurance::new(source, revision, proof_digest.clone())
            .expect("valid assurance"),
        lineage: LineageRootId::new("root-causal").expect("valid lineage root"),
        fence: fence(),
        temporal: TemporalRecord::new(1, 2, 3, 4, 5).expect("valid temporal record"),
        proof_digest,
        ceiling: EvidenceGrade::Orienting,
        scope: test_scope.to_owned(),
    })
    .expect("causal fixture must validate")
}

#[test]
fn causal_readings_keep_owner_scope_and_never_infer() {
    // A supplied causal reading under the model's own scope and fence is
    // preserved as supplied data.
    let preserved = RivalModelDeclaration::new(RivalModelDeclarationParams {
        causal_readings: DeclarationAvailability::Supplied {
            entries: vec![causal_fixture(&scope())],
        },
        ..model_params("model-causal", 1)
    });
    assert!(
        preserved.is_ok(),
        "owner-scoped causal reading must be preserved"
    );
    // A reading from another scope is refused: the carrier never absorbs a
    // foreign causal verdict as its own.
    let foreign_scope = RivalModelDeclaration::new(RivalModelDeclarationParams {
        causal_readings: DeclarationAvailability::Supplied {
            entries: vec![causal_fixture("other-scope")],
        },
        ..model_params("model-foreign-causal", 1)
    });
    assert!(
        foreign_scope.is_err(),
        "causal reading with a foreign scope must fail"
    );
    // No reading at all is an explicit absence, not a default association.
    assert!(
        matches!(
            fixture_model().causal_readings,
            DeclarationAvailability::NotApplicable { .. }
        ),
        "fixture carries no causal reading by default"
    );
}

fn retained_claim(id: &str, proposition: &str, handle: &str) -> MaterialClaim {
    let proposition_id = PropositionId::new(proposition).expect("valid proposition");
    let payload = PrecisionPayload::NumericQuantified {
        value: "42".into(),
        unit: "items".into(),
        denominator: Some("100".into()),
        interval: None,
        rounding: None,
        uncertainty: Some("exact".into()),
    };
    let mut claim = MaterialClaim {
        claim_id: id.into(),
        proposition: proposition_id.clone(),
        proposition_digest: proposition_content_digest(&ClaimKind::NumericQuantified, &payload)
            .expect("proposition digest"),
        kind: ClaimKind::NumericQuantified,
        payload,
        subclaim_ids: BTreeSet::new(),
        proposed_support: BTreeSet::from([aid(handle)]),
        proposed_counterevidence: BTreeSet::new(),
        component_digests: BTreeMap::from([(
            "value".into(),
            component_content_digest(&proposition_id, "value").expect("component digest"),
        )]),
        screen_target: None,
        source_preimage_digest: String::new(),
    };
    claim.source_preimage_digest = claim.computed_digest().expect("claim digest");
    claim
}

fn retained_assumption(id: &str) -> AssumptionRecord {
    AssumptionRecord::new(AssumptionRecordParams {
        assumption_id: id.to_owned(),
        statement: format!("taken statement for {id}"),
        origin: "owner review".to_owned(),
        necessity: "inquiry cannot proceed without it".to_owned(),
        failure_mode: "dependents fall on refutation".to_owned(),
        dependents: BTreeSet::new(),
        bounds: bounds(),
        holder: SourceId::new("holder-1064").expect("valid holder"),
        task_id: tid(),
        fence: fence(),
    })
    .expect("assumption fixture must validate")
}

#[test]
fn retained_claim_and_assumption_slots_close_against_refs() {
    let claim = retained_claim("claim-r", "prop-r", "evidence-r");
    claim
        .validate_for_context(&tid(), &scope(), &fence())
        .expect("retained claim must hold for the set context");
    let claim_reference =
        MaterialClaimRef::from_claim(&claim).expect("claim reference must derive");
    let assumption = retained_assumption("asm-r");
    let assumption_reference = ConditionAssumptionRef {
        assumption_id: assumption.assumption_id.clone(),
        assumption_digest: assumption.digest.clone(),
    };
    let model = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: vec![claim_reference.clone()],
        assumptions: DeclarationAvailability::Supplied {
            entries: vec![assumption_reference],
        },
        prediction_refs: not_applicable_entries("prediction refs"),
        ..model_params("model-retained", 1)
    })
    .expect("model over retained slots must build standalone");
    let set = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![RivalModelSlot::Retained {
            declaration: Box::new(model),
        }],
        claims: vec![
            RivalClaimSlot::Retained {
                claim: Box::new(claim),
            },
            unavailable_claim("claim-a", "prop-a", 11),
        ],
        assumptions: vec![
            RivalAssumptionSlot::Retained {
                assumption: Box::new(assumption),
            },
            unavailable_assumption("asm-a", 12),
        ],
        predictions: Vec::new(),
        sources: vec![
            unavailable_source("evidence-r", 83),
            RivalSourceSlot::Unavailable {
                handle: aid("src-1"),
                content_digest: Some(format!("{:064}", 31)),
                source_revision: Some("rev-src-1".to_owned()),
                reason: "src-1 payload unavailable in this carrier".to_owned(),
            },
        ],
        model_coverage: unknown_coverage("models"),
        source_coverage: unknown_coverage("sources"),
        unresolved: BTreeSet::new(),
        ..set_params()
    });
    assert!(
        set.is_ok(),
        "retained claim and assumption slots must close against exact references"
    );
    // The derived claim reference binds the complete retained payload: a
    // changed digest no longer binds the same claim.
    let mut changed = claim_reference.clone();
    changed.claim_preimage_digest = format!("{:064}", 84);
    assert!(
        changed
            .validate_against(&retained_claim("claim-r", "prop-r", "evidence-r"))
            .is_err(),
        "changed preimage digest must not bind the retained claim"
    );
}

#[test]
fn canonical_permutation_of_outer_tables_preserves_digest() {
    let model_b = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: aid("model-b"),
        explanations: vec![claim_ref("claim-b", "prop-b", 31)],
        assumptions: not_applicable_entries("assumptions"),
        prediction_refs: not_applicable_entries("prediction refs"),
        ..model_params("model-b-ignored", 1)
    })
    .expect("second model must build");
    assert_eq!(model_b.model_id, aid("model-b"));
    let canonical = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(fixture_model()),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b.clone()),
            },
        ],
        claims: vec![
            unavailable_claim("claim-a", "prop-a", 11),
            unavailable_claim("claim-b", "prop-b", 31),
            unavailable_claim("claim-p", "prop-p", 21),
        ],
        ..set_params()
    })
    .expect("canonical order must build");
    let permuted = RivalDeclarationSet::new(RivalDeclarationSetParams {
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(fixture_model()),
            },
        ],
        claims: vec![
            unavailable_claim("claim-p", "prop-p", 21),
            unavailable_claim("claim-b", "prop-b", 31),
            unavailable_claim("claim-a", "prop-a", 11),
        ],
        ..set_params()
    })
    .expect("permuted order must build");
    assert!(permuted.validate().is_ok());
    assert_eq!(
        canonical.digest, permuted.digest,
        "outer-table permutations must preserve the digest"
    );
    // Hand-reordered tables outside the constructor are not canonical.
    let mut reordered = canonical.clone();
    reordered.models.swap(0, 1);
    assert!(
        reordered.validate().is_err(),
        "non-canonical model order must fail"
    );
}

#[test]
fn inner_declaration_order_is_meaningful() {
    let first = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: vec![
            claim_ref("claim-a", "prop-a", 11),
            claim_ref("claim-b", "prop-b", 31),
        ],
        ..model_params("model-order", 1)
    })
    .expect("ordered explanations must build");
    let swapped = RivalModelDeclaration::new(RivalModelDeclarationParams {
        explanations: vec![
            claim_ref("claim-b", "prop-b", 31),
            claim_ref("claim-a", "prop-a", 11),
        ],
        ..model_params("model-order", 1)
    })
    .expect("swapped explanations must build");
    assert_ne!(
        first.digest, swapped.digest,
        "meaningful inner order must alter the digest"
    );
    let pred_a = fixture_prediction_ref();
    let pred_b = RivalPredictionRef::from_prediction(
        &RivalPrediction::new(RivalPredictionParams {
            prediction_id: aid("pred-b"),
            ..prediction_params("pred-b")
        })
        .expect("second prediction must build"),
    )
    .expect("second prediction reference must derive");
    let refs_first = RivalModelDeclaration::new(RivalModelDeclarationParams {
        prediction_refs: DeclarationAvailability::Supplied {
            entries: vec![pred_a.clone(), pred_b.clone()],
        },
        ..model_params("model-pred-order", 1)
    })
    .expect("ordered prediction refs must build");
    let refs_swapped = RivalModelDeclaration::new(RivalModelDeclarationParams {
        prediction_refs: DeclarationAvailability::Supplied {
            entries: vec![pred_b, pred_a],
        },
        ..model_params("model-pred-order", 1)
    })
    .expect("swapped prediction refs must build");
    assert_ne!(
        refs_first.digest, refs_swapped.digest,
        "prediction reference order must alter the digest"
    );
}

#[test]
fn model_and_prediction_refs_bind_exact_declarations() {
    let model = fixture_model();
    let reference = RivalModelRef::from_model(&model).expect("model reference must derive");
    assert!(reference.validate().is_ok());
    assert!(
        reference.validate_against(&model).is_ok(),
        "reference must bind its retained declaration"
    );
    let mut changed_digest = reference.clone();
    changed_digest.declaration_digest = format!("{:064}", 91);
    assert!(
        changed_digest.validate_against(&model).is_err(),
        "changed digest must not bind the declaration"
    );
    let mut changed_revision = reference.clone();
    changed_revision.model_revision = model.model_revision + 1;
    assert!(
        changed_revision.validate_against(&model).is_err(),
        "changed revision must not bind the declaration"
    );
    assert!(
        model_ref("model-a", 0, 11).validate().is_err(),
        "zero model revision must fail"
    );

    let prediction = fixture_prediction("pred-a");
    let prediction_reference =
        RivalPredictionRef::from_prediction(&prediction).expect("prediction ref must derive");
    assert!(prediction_reference.validate().is_ok());
    let mut stale_prediction = prediction_reference.clone();
    stale_prediction.prediction_digest = format!("{:064}", 92);
    assert!(
        RivalModelDeclaration::new(RivalModelDeclarationParams {
            prediction_refs: DeclarationAvailability::Supplied {
                entries: vec![stale_prediction],
            },
            ..model_params("model-stale-pred", 1)
        })
        .is_ok(),
        "standalone model cannot resolve prediction digests"
    );
}

#[test]
fn current_position_temporal_lineage_and_common_mode_availability() {
    assert!(
        CurrentPositionAvailability::NotApplicable {
            reason: "no current-position view applies".to_owned(),
        }
        .validate("rival.test.position")
        .is_ok()
    );
    assert!(
        CurrentPositionAvailability::Referenced {
            binding: CurrentPositionBinding {
                position_id: PositionId::new("position-1064").expect("valid position"),
                position_revision: PositionRevision::genesis(),
                view_digest: format!("{:064}", 93),
            },
        }
        .validate("rival.test.position")
        .is_ok()
    );
    assert!(
        CurrentPositionAvailability::Unknown {
            position_id: None,
            position_revision: None,
            view_digest: None,
            reason: "position view unavailable".to_owned(),
        }
        .validate("rival.test.position")
        .is_ok()
    );
    assert!(
        TemporalAvailability::Supplied {
            temporal: TemporalRecord::new(1, 2, 3, 4, 5).expect("valid temporal record"),
        }
        .validate("rival.test.temporal")
        .is_ok()
    );
    assert!(
        unknown_lineage("model")
            .validate("rival.test.lineage")
            .is_ok()
    );
    assert!(
        SuppliedLineage::Unknown {
            closure_digest: None,
            reason: String::new(),
        }
        .validate("rival.test.lineage")
        .is_err(),
        "empty lineage reason must fail"
    );
    assert!(
        CommonModeDisclosure::Supplied {
            lineage_roots: BTreeSet::from([
                LineageRootId::new("root-1064").expect("valid lineage root")
            ]),
            basis: unknown_claims("common mode basis"),
        }
        .validate("rival.test.common_mode")
        .is_ok()
    );
    assert!(
        CommonModeDisclosure::Supplied {
            lineage_roots: BTreeSet::new(),
            basis: unknown_claims("common mode basis"),
        }
        .validate("rival.test.common_mode")
        .is_err(),
        "supplied common mode without roots must fail"
    );
    let disclosed = RivalModelDeclaration::new(RivalModelDeclarationParams {
        common_mode: CommonModeDisclosure::Supplied {
            lineage_roots: BTreeSet::from([
                LineageRootId::new("root-1064").expect("valid lineage root")
            ]),
            basis: unknown_claims("common mode basis"),
        },
        ..model_params("model-common-mode", 1)
    });
    assert!(
        disclosed.is_ok(),
        "model with disclosed common mode must validate"
    );
}

#[test]
fn module_toml_declares_rival_outputs() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("module.toml");
    let text = std::fs::read_to_string(&manifest).expect("module.toml must be readable");
    for token in [
        "RivalModelDeclaration",
        "RivalDeclarationSet",
        "prediction",
        "falsifier",
    ] {
        assert!(
            text.contains(token),
            "module.toml outputs must declare {token}"
        );
    }
}

#[test]
fn rival_sources_contain_no_algorithm_or_stub_surface() {
    const SOURCES: &[&str] = &[
        include_str!("../src/rival/mod.rs"),
        include_str!("../src/rival/model.rs"),
        include_str!("../src/rival/prediction.rs"),
        include_str!("../src/rival/validation.rs"),
    ];
    const FORBIDDEN: &[&str] = &[
        "eliot_dreamer_rival_model",
        "eliot-dreamer-rival-model",
        "dreamer_rival_model",
        "dreamer-rival-model",
        concat!("todo", "!"),
        concat!("unimplemented", "!"),
        concat!("serde_json::", "Value"),
        "unsafe ",
    ];
    for source in SOURCES {
        assert!(!source.is_empty(), "rival source must be non-empty");
        for token in FORBIDDEN {
            assert!(
                !source.contains(token),
                "rival declaration source must not contain {token}"
            );
        }
    }
}
