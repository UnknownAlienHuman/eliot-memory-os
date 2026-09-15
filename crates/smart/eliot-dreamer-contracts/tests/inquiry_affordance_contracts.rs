//! Contract tests for closed inquiry-affordance descriptors and sets.
//!
//! Cell `smart.dreamer.contracts` (issue #1236, contracts half). Behaviour
//! proof only: positive, duplicate, mismatch, bounds, digest, ordering, and
//! unknown-dimension cases with deterministic replay. Descriptors stay
//! descriptive and non-authorizing: no execution API exists anywhere in the
//! contract surface.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
};
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::probe::{
    AffordanceKind, AffordanceTarget, AuthorityDimension, ConsentDimension, ContextDimension,
    CostDimension, EffectDimension, FeasibilityDimension, HumanAttentionDimension,
    INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION, InformationDimension, InquiryAffordanceDescriptor,
    InquiryAffordanceDescriptorParams, InquiryAffordanceSet, InquiryAffordanceSetParams,
    LatencyDimension, PossibleResultSchema, PossibleResultValue, PrivacyDimension,
    ProbeObjectiveRef, ProbeOwnerRef, ResourceDimension, ResultBranch, ResultTarget, ResultUpdate,
    ReversibilityDimension, RivalUpdateMeaning,
};
use eliot_dreamer_contracts::rival::{
    ConditionAssumptionRef, MaterialClaimRef, RivalModelRef, RivalPredictionRef,
};
use eliot_epistemic_contracts::{PropositionId, ValidityBounds};

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

fn bounds() -> ValidityBounds {
    ValidityBounds {
        scope: scope(),
        window_start_ms: None,
        window_end_ms: None,
        version: "v1".to_owned(),
        precision: "file".to_owned(),
    }
}

fn owner() -> ProbeOwnerRef {
    ProbeOwnerRef::Unavailable {
        reason: "owner not supplied".to_owned(),
    }
}

fn rival_target() -> (RivalModelRef, RivalPredictionRef, ResultTarget) {
    let model = RivalModelRef {
        model_id: aid("model-aff"),
        model_revision: 1,
        declaration_digest: "a".repeat(64),
    };
    let prediction = RivalPredictionRef {
        prediction_id: aid("pred-aff"),
        prediction_digest: "b".repeat(64),
    };
    let target = ResultTarget::Rival {
        model: model.clone(),
        prediction: Some(prediction.clone()),
    };
    (model, prediction, target)
}

fn branch(tag: &str, meaning: RivalUpdateMeaning) -> ResultBranch {
    let (model, prediction, _) = rival_target();
    ResultBranch {
        result_id: aid(&format!("result-{tag}")),
        value: PossibleResultValue::Unknown {
            reason: format!("branch {tag} pending"),
        },
        updates: vec![ResultUpdate::Rival {
            model,
            prediction: Some(prediction),
            meaning,
        }],
    }
}

fn result_schema(tag: &str, reversed_branches: bool) -> PossibleResultSchema {
    let (_, _, target) = rival_target();
    let first = branch(&format!("{tag}-one"), RivalUpdateMeaning::Strengthened);
    let second = branch(&format!("{tag}-two"), RivalUpdateMeaning::Weakened);
    let branches = if reversed_branches {
        vec![second, first]
    } else {
        vec![first, second]
    };
    PossibleResultSchema::new(aid(&format!("schema-{tag}")), vec![target], branches)
        .expect("schema fixture must validate")
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture wires all twelve dimensions"
)]
fn descriptor_params(id: &str, schema: PossibleResultSchema) -> InquiryAffordanceDescriptorParams {
    let (_, _, _) = rival_target();
    InquiryAffordanceDescriptorParams {
        affordance_id: aid(id),
        kind: AffordanceKind::EvidenceInspection,
        target: AffordanceTarget::RivalPredictions {
            left: RivalPredictionRef {
                prediction_id: aid("pred-left"),
                prediction_digest: "c".repeat(64),
            },
            right: RivalPredictionRef {
                prediction_id: aid("pred-right"),
                prediction_digest: "d".repeat(64),
            },
        },
        applicability: bounds(),
        owner: owner(),
        result_schema: schema,
        information: InformationDimension::Moderate {
            detail: "narrows two rivals".to_owned(),
        },
        cost: CostDimension::Low {
            detail: "one lookup".to_owned(),
        },
        latency: LatencyDimension::Interactive {
            detail: "answered within the turn".to_owned(),
        },
        context: ContextDimension::Narrow {
            detail: "needs the claim text".to_owned(),
        },
        resource: ResourceDimension::Bounded {
            detail: "one cached record".to_owned(),
        },
        privacy: PrivacyDimension::Contained {
            detail: "local only".to_owned(),
        },
        consent: ConsentDimension::RequiresGrant {
            reason: "no standing grant".to_owned(),
        },
        authority: AuthorityDimension::RequiresApproval {
            reason: "no standing approval".to_owned(),
        },
        effect: EffectDimension::ObservableOnly {
            detail: "reads only".to_owned(),
        },
        reversibility: ReversibilityDimension::Reversible {
            detail: "no retained change".to_owned(),
        },
        feasibility: FeasibilityDimension::Feasible {
            detail: "record exists".to_owned(),
        },
        attention: HumanAttentionDimension::Brief {
            detail: "one glance".to_owned(),
        },
    }
}

fn descriptor(id: &str, schema: PossibleResultSchema) -> InquiryAffordanceDescriptor {
    InquiryAffordanceDescriptor::new(descriptor_params(id, schema))
        .expect("descriptor fixture must validate")
}

fn set_params(descriptors: Vec<InquiryAffordanceDescriptor>) -> InquiryAffordanceSetParams {
    InquiryAffordanceSetParams {
        set_id: aid("affordance-set-1236"),
        task_id: tid(),
        scope: scope(),
        state_fence: fence(),
        descriptors,
    }
}

fn unknown_params(id: &str, schema: PossibleResultSchema) -> InquiryAffordanceDescriptorParams {
    let mut params = descriptor_params(id, schema);
    let reason = "not assessed".to_owned();
    params.information = InformationDimension::Unknown {
        reason: reason.clone(),
    };
    params.cost = CostDimension::Unknown {
        reason: reason.clone(),
    };
    params.latency = LatencyDimension::Unknown {
        reason: reason.clone(),
    };
    params.context = ContextDimension::Unknown {
        reason: reason.clone(),
    };
    params.resource = ResourceDimension::Unknown {
        reason: reason.clone(),
    };
    params.privacy = PrivacyDimension::Unknown {
        reason: reason.clone(),
    };
    params.consent = ConsentDimension::Unknown {
        reason: reason.clone(),
    };
    params.authority = AuthorityDimension::Unknown {
        reason: reason.clone(),
    };
    params.effect = EffectDimension::Unknown {
        reason: reason.clone(),
    };
    params.reversibility = ReversibilityDimension::Unknown {
        reason: reason.clone(),
    };
    params.feasibility = FeasibilityDimension::Unknown {
        reason: reason.clone(),
    };
    params.attention = HumanAttentionDimension::Unknown { reason };
    params
}

#[test]
fn positive_descriptor_and_set_validate() {
    let schema = result_schema("base", false);
    let first = descriptor("affordance-one", schema.clone());
    let second = descriptor("affordance-two", schema);
    assert!(first.validate().is_ok());
    let set = InquiryAffordanceSet::new(set_params(vec![first, second]))
        .expect("affordance set fixture must validate");
    assert_eq!(set.schema_version, INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION);
    assert!(set.validate().is_ok(), "fixture set must validate");
    assert!(set.validate().is_ok(), "validation must be stable");
    assert_eq!(
        set.compute_digest().expect("digest must compute"),
        set.digest
    );
}

#[test]
fn all_target_kinds_validate() {
    let schema = result_schema("targets", false);
    let claim = MaterialClaimRef {
        claim_id: "claim-aff".to_owned(),
        proposition: PropositionId::new("prop-aff").expect("valid proposition"),
        claim_preimage_digest: "e".repeat(64),
    };
    let assumption = ConditionAssumptionRef {
        assumption_id: "assumption-aff".to_owned(),
        assumption_digest: "f".repeat(64),
    };
    let objective = ProbeObjectiveRef {
        objective_id: aid("objective-aff"),
        objective_digest: "a".repeat(64),
    };
    for (tag, target) in [
        (
            "gap",
            AffordanceTarget::EvidenceGap {
                claim: claim.clone(),
            },
        ),
        (
            "assumption",
            AffordanceTarget::Assumption {
                assumption,
                claim: Some(claim.clone()),
            },
        ),
        ("objective", AffordanceTarget::Objective { objective }),
    ] {
        let mut params = descriptor_params(&format!("affordance-{tag}"), schema.clone());
        params.target = target;
        assert!(
            InquiryAffordanceDescriptor::new(params).is_ok(),
            "{tag} target must validate"
        );
    }
    let mut ambiguous = descriptor_params("affordance-ambiguous", schema);
    ambiguous.target = AffordanceTarget::RivalPredictions {
        left: RivalPredictionRef {
            prediction_id: aid("pred-same"),
            prediction_digest: "c".repeat(64),
        },
        right: RivalPredictionRef {
            prediction_id: aid("pred-same"),
            prediction_digest: "c".repeat(64),
        },
    };
    assert!(
        InquiryAffordanceDescriptor::new(ambiguous).is_err(),
        "identical rival endpoints must fail"
    );
}

#[test]
fn descriptor_permutations_preserve_set_digest() {
    let schema = result_schema("permute", false);
    let canonical = InquiryAffordanceSet::new(set_params(vec![
        descriptor("affordance-one", schema.clone()),
        descriptor("affordance-two", schema.clone()),
        descriptor("affordance-three", schema.clone()),
    ]))
    .expect("canonical order must build");
    let permuted = InquiryAffordanceSet::new(set_params(vec![
        descriptor("affordance-three", schema.clone()),
        descriptor("affordance-one", schema.clone()),
        descriptor("affordance-two", schema),
    ]))
    .expect("permuted order must build");
    assert!(permuted.validate().is_ok());
    assert_eq!(
        canonical.digest, permuted.digest,
        "descriptor-only permutations must preserve the digest"
    );
}

#[test]
fn branch_reorder_is_semantically_visible() {
    let ordered = result_schema("branch", false);
    let reversed = result_schema("branch", true);
    assert_ne!(
        ordered.digest, reversed.digest,
        "branch reorder must alter the schema digest"
    );
    let first = InquiryAffordanceSet::new(set_params(vec![descriptor("affordance-one", ordered)]))
        .expect("ordered set must build");
    let second =
        InquiryAffordanceSet::new(set_params(vec![descriptor("affordance-one", reversed)]))
            .expect("reversed set must build");
    assert_ne!(
        first.digest, second.digest,
        "semantic branch order must stay visible in the set digest"
    );
}

#[test]
fn finite_result_schema_cover_is_enforced() {
    let (_, _, target) = rival_target();
    let partial = ResultBranch {
        result_id: aid("result-partial"),
        value: PossibleResultValue::Unknown {
            reason: "partial".to_owned(),
        },
        updates: Vec::new(),
    };
    assert!(
        PossibleResultSchema::new(
            aid("schema-empty-updates"),
            vec![target.clone()],
            vec![partial]
        )
        .is_err(),
        "branches must cover every target exactly once"
    );
    assert!(
        PossibleResultSchema::new(aid("schema-no-branches"), vec![target], Vec::new()).is_err(),
        "finite schemas require at least one branch"
    );
}

#[test]
fn duplicate_and_changed_meaning_descriptors_fail() {
    let schema = result_schema("dupe", false);
    let duplicate = InquiryAffordanceSet::new(set_params(vec![
        descriptor("affordance-one", schema.clone()),
        descriptor("affordance-one", schema.clone()),
    ]));
    assert!(
        matches!(duplicate, Err(ContractViolation::BindingMismatch { .. })),
        "duplicate descriptors must fail"
    );
    let mut changed = descriptor_params("affordance-one", schema.clone());
    changed.cost = CostDimension::High {
        detail: "changed meaning".to_owned(),
    };
    let changed = InquiryAffordanceDescriptor::new(changed).expect("changed must build");
    assert_ne!(
        descriptor("affordance-one", schema.clone()).digest,
        changed.digest
    );
    let conflict = InquiryAffordanceSet::new(set_params(vec![
        descriptor("affordance-one", schema),
        changed,
    ]));
    assert!(
        matches!(conflict, Err(ContractViolation::BindingMismatch { .. })),
        "same affordance identity with changed meaning must conflict"
    );
}

#[test]
fn bounds_reject_overflow() {
    let schema = result_schema("bulk", false);
    let mut many = Vec::new();
    for index in 0..257 {
        many.push(descriptor(
            &format!("affordance-bulk-{index}"),
            schema.clone(),
        ));
    }
    let overflow = InquiryAffordanceSet::new(set_params(many));
    assert!(
        matches!(overflow, Err(ContractViolation::OutOfBounds { .. })),
        "descriptor overflow must fail with OutOfBounds"
    );
    let empty = InquiryAffordanceSet::new(set_params(Vec::new())).expect("empty set must build");
    assert!(empty.validate().is_ok(), "explicit empty set must validate");
}

#[test]
fn tampered_digest_and_noncanonical_order_fail() {
    let schema = result_schema("tamper", false);
    let set = InquiryAffordanceSet::new(set_params(vec![
        descriptor("affordance-one", schema.clone()),
        descriptor("affordance-two", schema.clone()),
    ]))
    .expect("fixture set must build");
    let mut tampered = set.clone();
    tampered.digest = "e".repeat(64);
    assert!(
        matches!(
            tampered.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "tampered digest must fail"
    );
    let mut reordered = set.clone();
    reordered.descriptors.swap(0, 1);
    assert!(
        matches!(
            reordered.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "non-canonical descriptor order must fail"
    );
    let mut tampered_descriptor = set.descriptors[0].clone();
    tampered_descriptor.digest = "e".repeat(64);
    assert!(
        tampered_descriptor.validate().is_err(),
        "tampered descriptor digest must fail"
    );
}

#[test]
fn unknown_dimensions_never_read_as_positive() {
    let schema = result_schema("unknown", false);
    let params = unknown_params("affordance-unknown", schema);
    let unknown = InquiryAffordanceDescriptor::new(params).expect("unknown must build");
    assert!(
        unknown.validate().is_ok(),
        "explicit unknown dimensions must validate"
    );
    assert!(!unknown.information.is_known());
    assert!(!unknown.information.has_expected_gain());
    assert!(!unknown.cost.is_known());
    assert!(!unknown.cost.is_negligible());
    assert!(!unknown.latency.is_known());
    assert!(!unknown.latency.is_immediate());
    assert!(!unknown.context.is_known());
    assert!(!unknown.context.is_self_contained());
    assert!(!unknown.resource.is_known());
    assert!(!unknown.resource.is_trivial());
    assert!(!unknown.privacy.is_known());
    assert!(!unknown.privacy.is_contained());
    assert!(!unknown.consent.is_known());
    assert!(!unknown.consent.is_granted());
    assert!(!unknown.authority.is_known());
    assert!(!unknown.authority.is_permitted());
    assert!(!unknown.effect.is_known());
    assert!(!unknown.effect.is_side_effect_free());
    assert!(!unknown.reversibility.is_known());
    assert!(!unknown.reversibility.is_reversible());
    assert!(!unknown.feasibility.is_known());
    assert!(!unknown.feasibility.is_feasible());
    assert!(!unknown.attention.is_known());
    assert!(!unknown.attention.needs_human());
}

#[test]
fn unavailable_and_not_applicable_stay_non_positive() {
    let reason = "withheld".to_owned();
    assert!(
        !CostDimension::Unavailable {
            reason: reason.clone()
        }
        .is_negligible()
    );
    assert!(
        !PrivacyDimension::Unavailable {
            reason: reason.clone()
        }
        .is_contained()
    );
    assert!(
        !FeasibilityDimension::Unavailable {
            reason: reason.clone()
        }
        .is_feasible()
    );
    assert!(
        !AuthorityDimension::Unavailable {
            reason: reason.clone()
        }
        .is_permitted()
    );
    assert!(
        !ConsentDimension::Unavailable {
            reason: reason.clone()
        }
        .is_granted()
    );
    assert!(
        !EffectDimension::Unavailable {
            reason: reason.clone()
        }
        .is_side_effect_free()
    );
    assert!(
        !ReversibilityDimension::Unavailable {
            reason: reason.clone()
        }
        .is_reversible()
    );
    assert!(
        !InformationDimension::Unavailable {
            reason: reason.clone()
        }
        .has_expected_gain()
    );
    assert!(
        ContextDimension::NotApplicable {
            reason: reason.clone()
        }
        .is_known()
    );
    assert!(
        !ContextDimension::NotApplicable {
            reason: reason.clone()
        }
        .is_self_contained()
    );
    assert!(
        !HumanAttentionDimension::NotApplicable {
            reason: reason.clone()
        }
        .needs_human()
    );
    assert!(!ResourceDimension::NotApplicable { reason }.is_trivial());
}

#[test]
fn effectful_descriptors_stay_representable_without_authority() {
    let schema = result_schema("effectful", false);
    let mut params = descriptor_params("affordance-effectful", schema);
    params.effect = EffectDimension::StateChanging {
        detail: "would rewrite the cached record".to_owned(),
    };
    params.reversibility = ReversibilityDimension::Irreversible {
        reason: "rewrite cannot be undone".to_owned(),
    };
    params.authority = AuthorityDimension::Denied {
        reason: "no standing".to_owned(),
    };
    params.consent = ConsentDimension::RequiresGrant {
        reason: "grant required first".to_owned(),
    };
    let effectful = InquiryAffordanceDescriptor::new(params).expect("effectful must build");
    assert!(effectful.validate().is_ok());
    assert!(!effectful.effect.is_side_effect_free());
    assert!(!effectful.reversibility.is_reversible());
    assert!(!effectful.authority.is_permitted());
    assert!(!effectful.consent.is_granted());
    assert!(effectful.feasibility.is_feasible());
}

#[test]
fn affordance_source_has_no_execution_or_stub_surface() {
    const SOURCE: &str = include_str!("../src/probe/affordance.rs");
    const FORBIDDEN: &[&str] = &[
        "execute_effect",
        "std::fs",
        "std::net",
        "std::process",
        "tokio",
        "reqwest",
        "provider_sdk",
        concat!("todo", "!"),
        concat!("unimplemented", "!"),
        concat!("serde_json::", "Value"),
        "unsafe ",
        "Command::",
        "Store<",
        "fn execute",
        "fn authorize",
    ];
    assert!(!SOURCE.is_empty(), "affordance source must be non-empty");
    for token in FORBIDDEN {
        assert!(
            !SOURCE.contains(token),
            "affordance source must not contain {token}"
        );
    }
}
