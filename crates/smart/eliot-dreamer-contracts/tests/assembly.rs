//! Validation proofs for the lossless A-03 recipe and assembly contract.
//!
//! Covers the residual Validation clause of issue #1056 against the source
//! slice landed via #1057 (`src/assembly/{mod,recipe,material,result}.rs`):
//! recipe/role closure, lossless input/output retention, exact
//! Context/Curation joins, deterministic encoding, and honest
//! incomplete/omission accounting.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_context_contracts::{LossPolicy as ContextLossPolicy, MeasurementUnit};
use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_dreamer_contracts::grounding::AttemptIdentity;
use eliot_dreamer_contracts::{
    AssemblyFrontier, AssemblyOmissionAccounting, AssemblyOmissionConstraint, AssemblyReserve,
    AssemblyReserveSet, AssemblyStop, AssemblyStopReason, BudgetLimits, DreamInputRole,
    DreamJobInput, DreamJobRecipe, JobClass, MaterialDisposition, MaterialLedgerEntry,
    MaterialOutcomeReason, MaterialRepresentation, OmissionHandle, RECIPE_SCHEMA_VERSION,
    RecipeInput, RecipeRole, Requester, RequesterOrigin, RoleDisposition, RoleOmissionPolicy,
    RoleOutcome, RoleOutcomeState, SourceRule, SourceRuleKind, SuppliedItemIdentity, digest_hex,
    required_roles,
};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn budget() -> BudgetLimits {
    BudgetLimits {
        input_bytes: Some(1_048_576),
        output_bytes: Some(524_288),
        source_width: Some(32),
        reference_width: Some(32),
        model_calls: Some(4),
        attempts: Some(2),
        candidates: Some(2),
        wall_ms: Some(1_000),
        work_fan_out: Some(2),
        report_bytes: Some(1_024),
        max_stu: Some(10),
    }
}

fn job() -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Orientation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "assembly-test".into(),
            session: None,
        },
        operation_id: "operation-assembly".into(),
        idempotency_key: "idempotency-assembly".into(),
        task_id: "task-assembly-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        privacy_profile: "local_only".into(),
        contract_ref: "contract-assembly-1".into(),
        policy_ref: "policy-1".into(),
        budget: budget(),
        deadline_ms: None,
        frozen_manifest_digest: DIGEST_A.into(),
    }
}

fn source_free_rule() -> SourceRule {
    SourceRule {
        kind: SourceRuleKind::None,
        allowed_owner: None,
        allowed_privacy: Vec::new(),
        allowed_authority: Vec::new(),
        allowed_proof: Vec::new(),
        allowed_disclosure: Vec::new(),
    }
}

fn required_role(role: DreamInputRole) -> RecipeRole {
    RecipeRole {
        role,
        disposition: RoleDisposition::Required,
        minimum: 1,
        maximum: 1,
        interpretation_dependencies: Vec::new(),
        source_priority: 0,
        source_rule: source_free_rule(),
        protected: false,
        representation_loss: ContextLossPolicy::NonDroppable,
        omission_policy: RoleOmissionPolicy::NonDroppable,
        condition: None,
    }
}

fn na_role(role: DreamInputRole) -> RecipeRole {
    RecipeRole {
        role,
        disposition: RoleDisposition::NotApplicable,
        minimum: 0,
        maximum: 0,
        interpretation_dependencies: Vec::new(),
        source_priority: 0,
        source_rule: source_free_rule(),
        protected: false,
        representation_loss: ContextLossPolicy::NonDroppable,
        omission_policy: RoleOmissionPolicy::NotApplicable,
        condition: None,
    }
}

fn inputs() -> Vec<RecipeInput> {
    vec![
        RecipeInput::ExactQuestion {
            text: "What is the current orientation state for scope-1?".into(),
        },
        RecipeInput::OutputSchema {
            schema_id: ArtifactId::new("schema-orientation").expect("fixture schema id"),
            schema_version: 1,
            schema_digest: DIGEST_B.into(),
        },
        RecipeInput::ForbiddenEffects {
            effects: vec!["effect.delete".into(), "effect.exfiltrate".into()],
        },
    ]
}

fn roles() -> Vec<RecipeRole> {
    let mut roles = vec![
        required_role(DreamInputRole::ExactQuestion),
        required_role(DreamInputRole::Requester),
        required_role(DreamInputRole::PrivacyProfile),
        required_role(DreamInputRole::Budget),
        required_role(DreamInputRole::OutputSchema),
        required_role(DreamInputRole::ForbiddenEffects),
        na_role(DreamInputRole::Architecture),
        na_role(DreamInputRole::Implementation),
        na_role(DreamInputRole::CurationSourceSnapshot),
        na_role(DreamInputRole::CurationSourceDenominator),
        na_role(DreamInputRole::CurationScreenProfile),
        na_role(DreamInputRole::CurationProtectionCoverage),
        na_role(DreamInputRole::CurationSubtypePayload),
        na_role(DreamInputRole::CurationTargetSet),
        na_role(DreamInputRole::CurationEvidenceSet),
        na_role(DreamInputRole::CurationTargetDenominator),
        na_role(DreamInputRole::CurationTargetScreens),
        na_role(DreamInputRole::CurationTargetDispositions),
    ];
    roles.sort_by_key(|role| role.role);
    roles
}

fn reserves() -> AssemblyReserveSet {
    let reserve = |value: u64| AssemblyReserve {
        profile: ArtifactId::new("reserve-profile").expect("fixture reserve profile"),
        unit: MeasurementUnit::Utf8Bytes,
        value,
    };
    AssemblyReserveSet {
        fixed: reserve(128),
        protocol: reserve(64),
        model_output: reserve(1_024),
        grounding: reserve(256),
        review: reserve(256),
        headroom: reserve(512),
    }
}

fn recipe() -> DreamJobRecipe {
    let job = job();
    let mut value = DreamJobRecipe {
        schema_version: RECIPE_SCHEMA_VERSION,
        recipe_id: "recipe-orientation-1".into(),
        recipe_revision: "rev-1".into(),
        recipe_digest: "0".repeat(64),
        job: job.clone(),
        attempt: AttemptIdentity {
            attempt_id: "attempt-assembly-1".into(),
            attempt_number: 1,
            maximum_attempts: 2,
        },
        inputs: inputs(),
        context_required: false,
        roles: roles(),
        limits: job.budget,
        reserves: reserves(),
    };
    value.recipe_digest = value.computed_digest().expect("fixture recipe digest");
    value
}

fn with_digest(mut value: DreamJobRecipe) -> DreamJobRecipe {
    value.recipe_digest = value.computed_digest().expect("mutated recipe digest");
    value
}

// WORK_UNIT_CASE: 1056/1 — recipe validates and binds its job losslessly.
#[test]
fn orientation_recipe_validates_and_binds_job_losslessly() {
    let job = job();
    job.validate().expect("fixture job validates");
    let recipe = recipe();
    recipe.validate().expect("orientation recipe validates");
    recipe
        .bind_job(&job)
        .expect("recipe binds its exact job identity");
    let mut drifted = job.clone();
    drifted.operation_id = "operation-other".into();
    assert!(
        recipe.bind_job(&drifted).is_err(),
        "rewritten job identity must not bind"
    );
    assert_eq!(
        recipe.recipe_digest,
        recipe.computed_digest().expect("stable digest"),
        "digest must be stable across calls"
    );
    let profile = ArtifactId::new("reserve-profile").expect("reserve profile");
    assert_eq!(
        recipe
            .reserves
            .total_for(&profile, MeasurementUnit::Utf8Bytes)
            .expect("reserve total"),
        128 + 64 + 1_024 + 256 + 256 + 512,
        "independent reserves must sum without conversion"
    );
    let wire = serde_json::to_string(&recipe).expect("encode recipe");
    let back: DreamJobRecipe = serde_json::from_str(&wire).expect("decode recipe");
    assert_eq!(back, recipe, "JSON round-trip must retain the recipe");
    back.validate().expect("round-tripped recipe validates");
    assert_eq!(back.recipe_digest, recipe.recipe_digest);
}

// WORK_UNIT_CASE: 1056/2 — role denominator closure rejects drift.
#[test]
fn recipe_role_closure_rejects_duplicate_and_missing_required() {
    let base = recipe();
    let mut duplicate = base.clone();
    let first = duplicate.roles[0].clone();
    duplicate.roles.push(first);
    let duplicate = with_digest(duplicate);
    assert!(
        duplicate.validate().is_err(),
        "duplicate role must fail closure"
    );
    let mut missing = base.clone();
    missing
        .roles
        .retain(|role| role.role != DreamInputRole::Requester);
    let missing = with_digest(missing);
    assert!(
        missing.validate().is_err(),
        "absent required role must fail closure"
    );
    assert_eq!(
        DreamInputRole::parse("exact_question").expect("known role"),
        DreamInputRole::ExactQuestion
    );
    assert!(DreamInputRole::parse("other").is_err());
    assert!(serde_json::from_str::<DreamInputRole>("\"other\"").is_err());
    assert!(
        required_roles(JobClass::Orientation).contains(&DreamInputRole::Budget),
        "orientation keeps its required denominator"
    );
}

// WORK_UNIT_CASE: 1056/3 — deterministic encoding and tamper evidence.
#[test]
fn recipe_encoding_is_deterministic_and_tamper_evident() {
    let recipe = recipe();
    let first = recipe.computed_digest().expect("digest");
    let second = recipe.computed_digest().expect("digest again");
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    let clone = recipe.clone();
    assert_eq!(
        clone.computed_digest().expect("clone digest"),
        first,
        "clones must share identity"
    );
    let mut mutated = recipe.clone();
    mutated.recipe_id = "recipe-orientation-2".into();
    assert_ne!(
        mutated.computed_digest().expect("mutated digest"),
        first,
        "identity change must change the digest"
    );
    let question = recipe
        .source_free_value_digest(DreamInputRole::ExactQuestion)
        .expect("question digest");
    let again = recipe
        .source_free_value_digest(DreamInputRole::ExactQuestion)
        .expect("question digest again");
    assert_eq!(question, again);
    assert!(question.is_some(), "typed input must hash stably");
    let mut tampered = recipe.clone();
    tampered.recipe_digest = "c".repeat(64);
    assert!(
        tampered.validate().is_err(),
        "digest mismatch must fail validation"
    );
}

// WORK_UNIT_CASE: 1056/4 — incomplete and omission accounting stays honest.
#[test]
#[allow(clippy::too_many_lines)]
fn omission_accounting_is_honest() {
    RoleOutcome {
        role: DreamInputRole::Requester,
        state: RoleOutcomeState::Applicable,
        supplied_count: 2,
        retained_count: 1,
        reason: None,
    }
    .validate()
    .expect("applicable outcome validates");
    assert!(
        RoleOutcome {
            role: DreamInputRole::Requester,
            state: RoleOutcomeState::Applicable,
            supplied_count: 1,
            retained_count: 2,
            reason: None,
        }
        .validate()
        .is_err(),
        "retained cannot exceed supplied"
    );
    RoleOutcome {
        role: DreamInputRole::Budget,
        state: RoleOutcomeState::Missing,
        supplied_count: 0,
        retained_count: 0,
        reason: Some(MaterialOutcomeReason::Missing),
    }
    .validate()
    .expect("missing outcome with typed reason validates");
    assert!(
        RoleOutcome {
            role: DreamInputRole::Budget,
            state: RoleOutcomeState::Missing,
            supplied_count: 0,
            retained_count: 0,
            reason: None,
        }
        .validate()
        .is_err(),
        "missing without a reason must fail"
    );
    assert!(
        RoleOutcome {
            role: DreamInputRole::Budget,
            state: RoleOutcomeState::Unresolved,
            supplied_count: 1,
            retained_count: 0,
            reason: None,
        }
        .validate()
        .is_err(),
        "unresolved without a reason must fail"
    );
    MaterialLedgerEntry {
        role: DreamInputRole::ExactQuestion,
        ordinal: 0,
        handle: None,
        content_digest: Some(DIGEST_A.into()),
        source_revision: None,
        disposition: MaterialDisposition::Included,
        reason: None,
        omission: None,
        note: None,
        omission_accounting: None,
    }
    .validate()
    .expect("included source-free item validates");
    assert!(
        MaterialLedgerEntry {
            role: DreamInputRole::ExactQuestion,
            ordinal: 0,
            handle: None,
            content_digest: Some(DIGEST_A.into()),
            source_revision: None,
            disposition: MaterialDisposition::Included,
            reason: Some(MaterialOutcomeReason::Missing),
            omission: None,
            note: None,
            omission_accounting: None,
        }
        .validate()
        .is_err(),
        "included item cannot carry a failure reason"
    );
    let handle = ArtifactId::new("mat-1").expect("fixture handle");
    let omission = OmissionHandle {
        handle: "mat-1".into(),
        reason: "over role maximum".into(),
        reversible: true,
        scope_id: "scope-1".into(),
        task_id: "task-assembly-1".into(),
        digest: DIGEST_A.into(),
        nonrecoverable_reason: None,
    };
    let bare_omitted = MaterialLedgerEntry {
        role: DreamInputRole::Evidence,
        ordinal: 0,
        handle: Some(handle.clone()),
        content_digest: Some(DIGEST_A.into()),
        source_revision: Some("revision-1".into()),
        disposition: MaterialDisposition::Omitted,
        reason: Some(MaterialOutcomeReason::Unprocessed),
        omission: Some(omission.clone()),
        note: None,
        omission_accounting: None,
    };
    assert!(
        bare_omitted.validate().is_err(),
        "omitted item without accounting must fail"
    );
    MaterialLedgerEntry {
        omission_accounting: Some(AssemblyOmissionAccounting {
            measured: None,
            constraints: vec![AssemblyOmissionConstraint::RoleMaximum {
                maximum: 1,
                supplied_count: 2,
            }],
            coverage: None,
        }),
        ..bare_omitted
    }
    .validate()
    .expect("omitted item with exact accounting validates");
}

// WORK_UNIT_CASE: 1056/5 — stop and frontier accounting stays honest.
#[test]
fn stop_and_frontier_accounting_is_honest() {
    AssemblyStop {
        reason: AssemblyStopReason::Completed,
        detail: None,
    }
    .validate()
    .expect("completed stop carries no detail");
    assert!(
        AssemblyStop {
            reason: AssemblyStopReason::Completed,
            detail: Some("done".into()),
        }
        .validate()
        .is_err(),
        "completed stop cannot carry a detail"
    );
    assert!(
        AssemblyStop {
            reason: AssemblyStopReason::Incomplete,
            detail: None,
        }
        .validate()
        .is_err(),
        "incomplete stop requires an explicit detail"
    );
    let handle = ArtifactId::new("mat-1").expect("fixture handle");
    let frontier = AssemblyFrontier {
        roles: vec![DreamInputRole::Evidence],
        references: vec![handle.clone()],
        supplied_items: vec![SuppliedItemIdentity {
            role: DreamInputRole::ExactQuestion,
            ordinal: 0,
            handle: None,
            content_digest: Some(DIGEST_A.into()),
            source_revision: None,
        }],
    };
    frontier.validate().expect("frontier validates");
    assert!(
        AssemblyFrontier {
            roles: vec![DreamInputRole::Evidence, DreamInputRole::Evidence],
            references: vec![handle],
            supplied_items: Vec::new(),
        }
        .validate()
        .is_err(),
        "frontier roles must be unique"
    );
}

// WORK_UNIT_CASE: 1056/6 — Curation dispositions and material joins stay exact.
#[test]
fn curation_dispositions_and_material_joins_are_exact() {
    let base = recipe();
    let mut curation_required = base.clone();
    let role = curation_required
        .roles
        .iter_mut()
        .find(|role| role.role == DreamInputRole::CurationSourceSnapshot)
        .expect("curation role present");
    role.disposition = RoleDisposition::Required;
    role.minimum = 1;
    role.maximum = 1;
    role.omission_policy = RoleOmissionPolicy::NonDroppable;
    let curation_required = with_digest(curation_required);
    assert!(
        curation_required.validate().is_err(),
        "non-Curation job cannot require a Curation role"
    );
    let content = "assembly-fixture-content";
    let representation = MaterialRepresentation::Utf8 {
        representation_id: ArtifactId::new("rep-1").expect("fixture representation"),
        content: content.into(),
    };
    representation
        .validate_for(&digest_hex(content.as_bytes()))
        .expect("exact representation binds its digest");
    assert!(
        representation.validate_for(&"0".repeat(64)).is_err(),
        "representation bound to another digest must fail"
    );
    MaterialRepresentation::HandleOnly {
        representation_id: ArtifactId::new("rep-1").expect("fixture representation"),
    }
    .validate_for(&"0".repeat(64))
    .expect("handle-only carries no content digest");
    assert!(
        SuppliedItemIdentity {
            role: DreamInputRole::ExactQuestion,
            ordinal: 0,
            handle: None,
            content_digest: Some(DIGEST_A.into()),
            source_revision: Some("revision-1".into()),
        }
        .validate()
        .is_err(),
        "source-free identity cannot carry a source revision"
    );
    assert!(
        SuppliedItemIdentity {
            role: DreamInputRole::Evidence,
            ordinal: 0,
            handle: Some(ArtifactId::new("mat-1").expect("fixture handle")),
            content_digest: Some(DIGEST_A.into()),
            source_revision: None,
        }
        .validate()
        .is_err(),
        "handle-backed identity requires its source revision"
    );
}
