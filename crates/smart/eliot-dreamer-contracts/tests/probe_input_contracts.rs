//! Contract tests for closed probe input declarations.
//!
//! Cell `smart.dreamer.contracts` (issue #1073, contracts half). Behaviour
//! proof only: positive, digest, bounds, duplicate, tamper, unknown, receipt,
//! and no-execution-surface cases with deterministic replay. Inputs stay
//! descriptive and non-authorizing: no execution API exists anywhere in the
//! contract surface.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence, TaskId};
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::job::{JobClass, Requester, RequesterOrigin};
use eliot_dreamer_contracts::probe::{
    PROBE_INPUT_SCHEMA_VERSION, PossibleResultSchema, PossibleResultValue, ProbeAffordanceRef,
    ProbeCapabilityAvailability, ProbeExternalOwners, ProbeGroundingRef, ProbeInput, ProbeInputParams,
    ProbeLifecycle, ProbeObjectiveRef, ProbeOwnerRef, ProbeParam, ProbeRepeatRef, ProbeSourceRef,
    ResultBranch, ResultTarget, ResultUpdate, RivalUpdateMeaning,
};
use eliot_dreamer_contracts::rival::{RivalDeclarationSetRef, RivalModelRef, RivalPredictionRef};
use eliot_epistemic_contracts::{
    CoverageDenominator, CoverageDenominatorParams, DenominatorKind, FrontierRevision, FrontierSpec,
    PaginationBounds, QueryRevision, QuerySpec, SnapshotRef, ValidityBounds,
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
    TaskId::new("task-1073").expect("valid test task id")
}

fn scope() -> String {
    "scope-1073".to_owned()
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

fn external_owners() -> ProbeExternalOwners {
    ProbeExternalOwners {
        admission: ProbeOwnerRef::Unavailable {
            reason: "admission owner not supplied".to_owned(),
        },
        execution: ProbeOwnerRef::Unavailable {
            reason: "execution owner not supplied".to_owned(),
        },
        evidence: ProbeOwnerRef::Unavailable {
            reason: "evidence owner not supplied".to_owned(),
        },
        verifier: ProbeOwnerRef::Unavailable {
            reason: "verifier owner not supplied".to_owned(),
        },
    }
}

fn capability() -> ProbeCapabilityAvailability {
    ProbeCapabilityAvailability::Available {
        detail: "probe capability available".to_owned(),
    }
}

fn requester() -> Requester {
    Requester {
        origin: RequesterOrigin::Human,
        principal: "alice".to_owned(),
        session: None,
    }
}

fn observable() -> ExpectedObservableSpec {
    ExpectedObservableSpec {
        property: "property-1073".to_owned(),
        matcher: "equals".to_owned(),
        artifact_selector: "artifact-1073".to_owned(),
    }
}

fn verifier() -> PlannedVerifierRef {
    PlannedVerifierRef {
        verifier_id: ContractId::new("verifier-1073").expect("valid verifier id"),
        scope: scope(),
        verifier_config_hash: "config-1073".to_owned(),
        expected_observable: observable(),
        environment_binding: "local fixture".to_owned(),
        verifier_authority_ref: "authority:test".to_owned(),
        contract_revision: ContractVersion::new(1, 0, 0),
        proof_ceiling: ProofCeiling::ScopedVerification,
    }
}

fn coverage() -> CoverageDenominator {
    CoverageDenominator::new(CoverageDenominatorParams {
        class: "source-record".to_owned(),
        schema: "schema-1073".to_owned(),
        revision: "rev-1073".to_owned(),
        scope: scope(),
        fence: fence(),
        members: BTreeSet::from([aid("member-1073")]),
        roles: BTreeSet::from(["primary".to_owned()]),
        query: Some(
            QuerySpec::new("query-1073", QueryRevision("query-rev-1073".to_owned()))
                .expect("valid query"),
        ),
        frontier: Some(
            FrontierSpec::new("frontier-1073", FrontierRevision("frontier-rev-1073".to_owned()))
                .expect("valid frontier"),
        ),
        snapshot: SnapshotRef::new(
            "snapshot-coverage-1073",
            SourceId::new("owner-1073").expect("valid source"),
        )
        .expect("valid snapshot"),
        exclusions: Vec::new(),
        bounds: PaginationBounds::new(0, 1, 1, false).expect("valid bounds"),
        validity: bounds(),
        kind: DenominatorKind::CompleteScope,
    })
    .expect("coverage fixture must validate")
}

fn snapshot() -> SnapshotRef {
    SnapshotRef::new(
        "snapshot-input-1073",
        SourceId::new("owner-1073").expect("valid source"),
    )
    .expect("valid snapshot")
}

fn lifecycle() -> ProbeLifecycle {
    ProbeLifecycle {
        cancellation: "cancel via owner request".to_owned(),
        cleanup_rollback: "no retained change to roll back".to_owned(),
        reconciliation: "reconcile unknown effects via owner review".to_owned(),
        repeat: ProbeRepeatRef {
            requirement_id: "repeat-1073".to_owned(),
            reason: "prior attempt inconclusive".to_owned(),
        },
    }
}

fn rival_target() -> (RivalModelRef, RivalPredictionRef, ResultTarget) {
    let model = RivalModelRef {
        model_id: aid("model-1073"),
        model_revision: 1,
        declaration_digest: "a".repeat(64),
    };
    let prediction = RivalPredictionRef {
        prediction_id: aid("pred-1073"),
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
        result_id: aid(&format!("result-1073-{tag}")),
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

fn result_schema() -> PossibleResultSchema {
    let (_, _, target) = rival_target();
    let first = branch("one", RivalUpdateMeaning::Strengthened);
    let second = branch("two", RivalUpdateMeaning::Weakened);
    PossibleResultSchema::new(aid("schema-1073"), vec![target], vec![first, second])
        .expect("result schema fixture must validate")
}

fn objective_ref() -> ProbeObjectiveRef {
    ProbeObjectiveRef {
        objective_id: aid("objective-1073"),
        objective_digest: "e".repeat(64),
    }
}

fn affordance_ref() -> ProbeAffordanceRef {
    ProbeAffordanceRef {
        affordance_id: aid("affordance-1073"),
        affordance_digest: "f".repeat(64),
    }
}

fn grounding() -> ProbeGroundingRef {
    ProbeGroundingRef {
        candidate_digest: "c".repeat(64),
    }
}

fn sources() -> BTreeSet<ProbeSourceRef> {
    BTreeSet::from([ProbeSourceRef {
        handle: aid("source-1073"),
        content_digest: "d".repeat(64),
        source_revision: "rev-1".to_owned(),
    }])
}

fn params() -> BTreeSet<ProbeParam> {
    BTreeSet::from([ProbeParam {
        name: "param-1073".to_owned(),
        value: "value-1073".to_owned(),
    }])
}

fn input_params() -> ProbeInputParams {
    ProbeInputParams {
        input_id: aid("input-1073"),
        task_id: tid(),
        scope: scope(),
        state_fence: fence(),
        job_class: JobClass::Orientation,
        requester: requester(),
        operation_id: "op-1073".to_owned(),
        attempt_id: "attempt-1".to_owned(),
        manifest_digest: "9".repeat(64),
        sources: sources(),
        grounding: grounding(),
        rival_set: RivalDeclarationSetRef {
            set_id: aid("decl-set-1073"),
            digest: "8".repeat(64),
        },
        rival_models: BTreeSet::from([RivalModelRef {
            model_id: aid("model-1073"),
            model_revision: 1,
            declaration_digest: "a".repeat(64),
        }]),
        rival_predictions: BTreeSet::from([RivalPredictionRef {
            prediction_id: aid("pred-1073"),
            prediction_digest: "b".repeat(64),
        }]),
        objective: objective_ref(),
        result_schema: result_schema(),
        affordance: affordance_ref(),
        expected_observable: observable(),
        verifier: verifier(),
        coverage: coverage(),
        applicability: bounds(),
        owner: owner(),
        external_owners: external_owners(),
        capability: capability(),
        params: params(),
        snapshot: snapshot(),
        lifecycle: lifecycle(),
    }
}

fn fixture_input() -> ProbeInput {
    ProbeInput::new(input_params()).expect("input fixture must validate")
}

#[test]
fn positive_input_validates_and_replays() {
    let input = fixture_input();
    assert_eq!(input.schema_version, PROBE_INPUT_SCHEMA_VERSION);
    assert!(input.validate().is_ok(), "fixture input must validate");
    assert!(input.validate().is_ok(), "validation must be stable");
    assert_eq!(
        input.compute_digest().expect("digest must compute"),
        input.digest,
        "computed digest must match frozen digest"
    );
}

#[test]
fn input_digest_is_canonical_and_deterministic() {
    let first = fixture_input();
    let second = fixture_input();
    assert_eq!(first.digest, second.digest, "replay must be deterministic");
    let mut changed = input_params();
    changed.operation_id = "op-1073-changed".to_owned();
    let altered = ProbeInput::new(changed).expect("changed input must build");
    assert_ne!(
        first.digest, altered.digest,
        "semantic change must alter the digest"
    );
    let mut reordered = input_params();
    let extra = ProbeParam {
        name: "param-extra".to_owned(),
        value: "extra".to_owned(),
    };
    reordered.params.insert(extra.clone());
    let with_extra = ProbeInput::new(reordered).expect("extra param must build");
    assert_ne!(first.digest, with_extra.digest);
    let mut swapped = input_params();
    swapped.params = BTreeSet::from([extra, ProbeParam {
        name: "param-1073".to_owned(),
        value: "value-1073".to_owned(),
    }]);
    let rebuilt = ProbeInput::new(swapped).expect("rebuilt params must build");
    assert_eq!(
        with_extra.digest, rebuilt.digest,
        "set-only insertion order must preserve the digest"
    );
}

#[test]
fn duplicate_and_changed_meaning_inputs_fail() {
    let mut dupe = input_params();
    dupe.params = BTreeSet::from([
        ProbeParam {
            name: "param-dupe".to_owned(),
            value: "same".to_owned(),
        },
        ProbeParam {
            name: "param-dupe".to_owned(),
            value: "changed".to_owned(),
        },
    ]);
    assert!(
        matches!(
            ProbeInput::new(dupe),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same param name with changed value must conflict"
    );
    let mut models = input_params();
    models.rival_models = BTreeSet::from([
        RivalModelRef {
            model_id: aid("model-dupe"),
            model_revision: 1,
            declaration_digest: "a".repeat(64),
        },
        RivalModelRef {
            model_id: aid("model-dupe"),
            model_revision: 1,
            declaration_digest: "b".repeat(64),
        },
    ]);
    assert!(
        matches!(
            ProbeInput::new(models),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "same model identity with changed digest must conflict"
    );
}

#[test]
fn bounds_reject_overflow_and_malformed() {
    let mut overflow = input_params();
    let mut many = BTreeSet::new();
    for index in 0..257 {
        many.insert(ProbeParam {
            name: format!("param-{index}"),
            value: "v".to_owned(),
        });
    }
    overflow.params = many;
    assert!(
        matches!(
            ProbeInput::new(overflow),
            Err(ContractViolation::OutOfBounds { .. })
        ),
        "param overflow must fail with OutOfBounds"
    );
    let mut bad_digest = input_params();
    bad_digest.manifest_digest = "not-hex".to_owned();
    assert!(
        ProbeInput::new(bad_digest).is_err(),
        "malformed manifest digest must fail"
    );
    let mut blank_scope = input_params();
    blank_scope.scope = "   ".to_owned();
    assert!(
        ProbeInput::new(blank_scope).is_err(),
        "blank scope must fail"
    );
    let mut wrong_version = fixture_input();
    wrong_version.schema_version = 999;
    assert!(
        wrong_version.validate().is_err(),
        "wrong schema version must fail"
    );
}

#[test]
fn tampered_digest_fails() {
    let input = fixture_input();
    let mut tampered = input.clone();
    tampered.digest = "e".repeat(64);
    assert!(
        matches!(
            tampered.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ),
        "tampered digest must fail"
    );
}

#[test]
fn unknown_capability_never_reads_as_available() {
    let reason = "not assessed".to_owned();
    let unknown = ProbeCapabilityAvailability::Unknown {
        reason: reason.clone(),
    };
    assert!(unknown.validate().is_ok());
    assert!(!unknown.is_known());
    assert!(!unknown.is_available());
    let unavailable = ProbeCapabilityAvailability::Unavailable {
        reason: reason.clone(),
    };
    assert!(!unavailable.is_available());
    let not_applicable = ProbeCapabilityAvailability::NotApplicable { reason };
    assert!(!not_applicable.is_available());
    let available = capability();
    assert!(available.is_known());
    assert!(available.is_available());
}

#[test]
fn input_join_invents_no_validation_receipt() {
    const SOURCE: &str = include_str!("../src/probe/input.rs");
    assert!(!SOURCE.is_empty(), "input source must be non-empty");
    assert!(
        !SOURCE.contains("ValidationReceipt"),
        "input join must not invent a validation receipt"
    );
    assert!(
        SOURCE.contains("ValidatedGroundingCandidate"),
        "input must reuse the A05 grounding candidate owner type"
    );
    assert!(
        SOURCE.contains("ProbeGroundingRef"),
        "input must pin grounding by digest"
    );
    let input = fixture_input();
    assert!(input.validate().is_ok());
    assert_eq!(input.grounding.candidate_digest.len(), 64);
}

#[test]
fn input_source_has_no_execution_or_stub_surface() {
    const SOURCE: &str = include_str!("../src/probe/input.rs");
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
        "fn reserve",
        "fn acquire",
    ];
    assert!(!SOURCE.is_empty(), "input source must be non-empty");
    for token in FORBIDDEN {
        assert!(
            !SOURCE.contains(token),
            "input source must not contain {token}"
        );
    }
}
