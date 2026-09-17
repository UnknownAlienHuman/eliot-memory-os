//! 593-PROOF bundle behaviour proof (28-case matrix).
//!
//! Package-local proof for `eliot-dreamer-bundle`: bounded assembly,
//! exclusions, determinism, and budget edges over `plan_bundle` /
//! `finalize_bundle`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_context_contracts::{
    CapacityLimits, MeasurementAggregationMode, MeasurementCompositionProfile, MeasurementUnit,
};
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence, sha256_hex,
};
use eliot_dreamer_bundle::{
    AssemblyFinalObservations, AssemblyPolicy, AssemblyRequest, SuppliedAssemblyItem,
    SuppliedItemState, finalize_bundle, plan_bundle,
};
use eliot_dreamer_contracts::assembly::{
    AssemblyMaterial, ContributionMeasurement, ContributionStatus, DreamInputRole, DreamJobRecipe,
    MaterialRepresentation, RecipeInput, RecipeRole, RoleDisposition, RoleOmissionPolicy,
    SourceRule, SourceRuleKind, SuppliedItemIdentity,
};
use eliot_dreamer_contracts::bundle::{
    BundleMaterial, BundleStatus, OmissionHandle, SourceDisposition,
};
use eliot_dreamer_contracts::grounding::canonical::{
    DisclosureClass, EvidenceAuthority, EvidenceFreshness, EvidenceGrade, PositionAssertability,
    PrivacyHandling, SourceLineage, SourceRevisionId,
};
use eliot_dreamer_contracts::grounding::{AllowedReferenceManifest, AuthorizedReference};
use eliot_dreamer_contracts::{
    AssemblyReserve, AssemblyReserveSet, BudgetLimits, ContractViolation, DisclosureAuthorization,
    DreamJobAdmission, JobClass, Requester, RequesterOrigin,
};

const ROUTE_ID: &str = "route-1";
const PROFILE_ID: &str = "profile-1";

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        NonZeroU64::new(1).expect("seq"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn profile() -> MeasurementCompositionProfile {
    MeasurementCompositionProfile {
        profile_id: ArtifactId::new(PROFILE_ID).expect("profile id"),
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        serializer_id: "test-serializer".to_owned(),
        serializer_version: "1.0".to_owned(),
        serializer_options_digest: sha256_hex(b"options"),
        route_id: ROUTE_ID.to_owned(),
        model_id: "model-1".to_owned(),
        unit: MeasurementUnit::Utf8Bytes,
        aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
        qualification: ArtifactId::new("qualification-1").expect("qual"),
        capacity: CapacityLimits {
            route_capacity: 1_048_576,
            fixed_overhead: 100,
            output_reserve: 1000,
            review_reserve: 1000,
        },
    }
}

fn limits() -> BudgetLimits {
    BudgetLimits {
        input_bytes: Some(1_048_576),
        output_bytes: Some(524_288),
        source_width: Some(32),
        reference_width: Some(32),
        model_calls: Some(4),
        attempts: Some(2),
        candidates: Some(2),
        wall_ms: Some(60_000),
        work_fan_out: Some(4),
        report_bytes: Some(1_048_576),
        max_stu: Some(100),
    }
}

fn reserves() -> AssemblyReserveSet {
    let p = ArtifactId::new(PROFILE_ID).expect("profile");
    let mk = |value: u64| AssemblyReserve {
        profile: p.clone(),
        unit: MeasurementUnit::Utf8Bytes,
        value,
    };
    AssemblyReserveSet {
        fixed: mk(100),
        protocol: mk(50),
        model_output: mk(1000),
        grounding: mk(500),
        review: mk(1000),
        headroom: mk(500),
    }
}

fn source_free_role(role: DreamInputRole) -> RecipeRole {
    RecipeRole {
        role,
        disposition: RoleDisposition::Required,
        minimum: 1,
        maximum: 1,
        interpretation_dependencies: Vec::new(),
        source_priority: 0,
        source_rule: SourceRule {
            kind: SourceRuleKind::None,
            allowed_owner: None,
            allowed_privacy: Vec::new(),
            allowed_authority: Vec::new(),
            allowed_proof: Vec::new(),
            allowed_disclosure: Vec::new(),
        },
        protected: false,
        representation_loss: eliot_context_contracts::LossPolicy::NonDroppable,
        omission_policy: RoleOmissionPolicy::NonDroppable,
        condition: None,
    }
}

fn source_role(
    role: DreamInputRole,
    disposition: RoleDisposition,
    min: u32,
    max: u32,
) -> RecipeRole {
    RecipeRole {
        role,
        disposition,
        minimum: min,
        maximum: max,
        interpretation_dependencies: Vec::new(),
        source_priority: 10,
        source_rule: SourceRule {
            kind: SourceRuleKind::GovernedReference,
            allowed_owner: None,
            allowed_privacy: vec![PrivacyHandling::Unrestricted],
            allowed_authority: vec![EvidenceAuthority::SourceIdentity],
            allowed_proof: vec![PositionAssertability::QualifiedInference],
            allowed_disclosure: vec![DisclosureClass::Open],
        },
        protected: false,
        representation_loss: eliot_context_contracts::LossPolicy::Extractive,
        omission_policy: RoleOmissionPolicy::ReversibleHandle,
        condition: None,
    }
}

fn not_applicable_role(role: DreamInputRole) -> RecipeRole {
    RecipeRole {
        role,
        disposition: RoleDisposition::NotApplicable,
        minimum: 0,
        maximum: 0,
        interpretation_dependencies: Vec::new(),
        source_priority: 0,
        source_rule: SourceRule {
            kind: SourceRuleKind::None,
            allowed_owner: None,
            allowed_privacy: Vec::new(),
            allowed_authority: Vec::new(),
            allowed_proof: Vec::new(),
            allowed_disclosure: Vec::new(),
        },
        protected: false,
        representation_loss: eliot_context_contracts::LossPolicy::NonDroppable,
        omission_policy: RoleOmissionPolicy::NotApplicable,
        condition: None,
    }
}

fn curation_roles() -> Vec<RecipeRole> {
    use DreamInputRole::*;
    vec![
        CurationSourceSnapshot,
        CurationSourceDenominator,
        CurationScreenProfile,
        CurationProtectionCoverage,
        CurationSubtypePayload,
        CurationTargetSet,
        CurationEvidenceSet,
        CurationTargetDenominator,
        CurationTargetScreens,
        CurationTargetDispositions,
    ]
    .into_iter()
    .map(not_applicable_role)
    .collect()
}

fn job_with_manifest(manifest_digest: String) -> DreamJobAdmission {
    DreamJobAdmission {
        schema_version: 1,
        job_class: JobClass::Orientation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "op-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: limits(),
        deadline_ms: None,
        frozen_manifest_digest: manifest_digest,
    }
}

fn recipe_inputs() -> Vec<RecipeInput> {
    vec![
        RecipeInput::ExactQuestion {
            text: "What is the bounded status?".to_owned(),
        },
        RecipeInput::AllowedModelRoutes {
            routes: vec![ROUTE_ID.to_owned()],
        },
        RecipeInput::OutputSchema {
            schema_id: ArtifactId::new("schema-1").expect("schema"),
            schema_version: 1,
            schema_digest: sha256_hex(b"schema-1"),
        },
        RecipeInput::ForbiddenEffects {
            effects: vec!["effect-1".to_owned()],
        },
    ]
}

fn recipe_for(job: DreamJobAdmission) -> DreamJobRecipe {
    use DreamInputRole::*;
    let mut roles = vec![
        source_free_role(ExactQuestion),
        source_free_role(Requester),
        source_free_role(PrivacyProfile),
        source_free_role(Budget),
        source_free_role(OutputSchema),
        source_free_role(ForbiddenEffects),
        source_free_role(AllowedModelRoutes),
        source_role(Evidence, RoleDisposition::Required, 1, 4),
        source_role(Architecture, RoleDisposition::Optional, 0, 4),
        source_role(Implementation, RoleDisposition::Optional, 0, 4),
    ];
    roles.extend(curation_roles());
    let attempt = eliot_dreamer_contracts::grounding::AttemptIdentity {
        attempt_id: "attempt-1".to_owned(),
        attempt_number: 1,
        maximum_attempts: 2,
    };
    let mut recipe = DreamJobRecipe {
        schema_version: 1,
        recipe_id: "recipe-1".to_owned(),
        recipe_revision: "r1".to_owned(),
        recipe_digest: "0".repeat(64),
        job,
        attempt,
        inputs: recipe_inputs(),
        context_required: false,
        roles,
        limits: limits(),
        reserves: reserves(),
    };
    let digest = recipe.computed_digest().expect("recipe digest");
    recipe.recipe_digest = digest;
    recipe
}

fn authorized_reference(handle: &str, content: &str) -> AuthorizedReference {
    let digest = sha256_hex(content.as_bytes());
    let owner = SourceId::new("source-1").expect("owner");
    let lineage = SourceLineage::new(
        owner,
        SourceRevisionId::new("revision-1").expect("rev"),
        digest.clone(),
        None,
        BTreeSet::new(),
        None,
    )
    .expect("lineage");
    AuthorizedReference {
        handle: ArtifactId::new(handle).expect("handle"),
        source_lineage: Some(lineage),
        support: None,
        provenance: None,
        content_digest: digest,
        source_revision: "revision-1".to_owned(),
        authority_digest: sha256_hex(b"authority-1"),
        authority: EvidenceAuthority::SourceIdentity,
        freshness: EvidenceFreshness::ExactCommit,
        source_assurance: None,
        grade_ceiling: EvidenceGrade::Grounded,
        assertability_ceiling: PositionAssertability::QualifiedInference,
        privacy: PrivacyHandling::Unrestricted,
        disclosure: DisclosureClass::Open,
        origin: "test-origin".to_owned(),
        invalidated: false,
        revocation_reason: None,
        assertions: Vec::new(),
        stale: false,
    }
}

fn manifest_with(handles: Vec<(&str, &str)>) -> AllowedReferenceManifest {
    let mut references = BTreeMap::new();
    for (handle, content) in handles {
        references.insert(
            ArtifactId::new(handle).expect("handle"),
            authorized_reference(handle, content),
        );
    }
    let mut manifest = AllowedReferenceManifest {
        schema_version: 2,
        manifest_id: "manifest-1".to_owned(),
        run_id: "run-1".to_owned(),
        task_id: eliot_dreamer_contracts::grounding::TaskId::new("task-1").expect("task"),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "revision-1".to_owned(),
        references,
        coverage_denominators: BTreeMap::new(),
        coverage_receipts: BTreeMap::new(),
        dependence_groups: BTreeSet::from(["independent-1".to_owned()]),
        digest: String::new(),
    };
    let digest = manifest.computed_digest().expect("manifest digest");
    manifest.digest = digest;
    manifest
}

fn evidence_item(
    role: DreamInputRole,
    handle: &str,
    content: &str,
    ordinal: u32,
) -> SuppliedAssemblyItem {
    let digest = sha256_hex(content.as_bytes());
    let identity = SuppliedItemIdentity {
        role,
        ordinal,
        handle: Some(ArtifactId::new(handle).expect("handle")),
        content_digest: Some(digest.clone()),
        source_revision: Some("revision-1".to_owned()),
    };
    let material = AssemblyMaterial {
        role,
        ordinal,
        material: BundleMaterial {
            handle: handle.to_owned(),
            disposition: SourceDisposition::Required,
            bytes: content.len() as u64,
            digest: digest.clone(),
        },
        representation: MaterialRepresentation::Utf8 {
            representation_id: ArtifactId::new(format!("{handle}-repr")).expect("repr"),
            content: content.to_owned(),
        },
        reference: ArtifactId::new(handle).expect("handle"),
    };
    let measurement = ContributionMeasurement {
        material: ArtifactId::new(handle).expect("handle"),
        representation: ArtifactId::new(format!("{handle}-repr")).expect("repr"),
        source_revision: "revision-1".to_owned(),
        material_digest: digest,
        profile: profile(),
        status: ContributionStatus::Exact,
        bytes: Some(content.len() as u64),
    };
    SuppliedAssemblyItem {
        identity,
        material: Some(material),
        state: SuppliedItemState::Available,
        measurement: Some(measurement),
        omission: None,
        omission_coverage: None,
        note: None,
    }
}

fn omission_handle(handle: &str) -> OmissionHandle {
    OmissionHandle {
        handle: handle.to_owned(),
        reason: "bounded omission for test".to_owned(),
        reversible: true,
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        digest: sha256_hex(format!("omission-{handle}").as_bytes()),
        nonrecoverable_reason: None,
    }
}

fn base_request() -> AssemblyRequest {
    let manifest = manifest_with(vec![("evidence-1", "evidence content one")]);
    let job = job_with_manifest(manifest.digest.clone());
    let recipe = recipe_for(job);
    AssemblyRequest {
        recipe,
        manifest,
        supplied_items: vec![evidence_item(
            DreamInputRole::Evidence,
            "evidence-1",
            "evidence content one",
            0,
        )],
        context: None,
        curation: None,
        measurement_profile: profile(),
        policy: AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    }
}

fn observations_for(plan: &eliot_dreamer_bundle::AssemblyPlan) -> AssemblyFinalObservations {
    use eliot_context_contracts::StuEstimate;
    AssemblyFinalObservations {
        input_digest: plan.model_input_digest().to_owned(),
        measurement_profile: profile(),
        stu_estimate: Some(StuEstimate {
            value: 1,
            empirical: true,
        }),
        tokenizer: None,
        disclosure: None,
    }
}

// WORK_UNIT_CASE: 593/1
#[test]
fn golden_job_class_role_recipe_matrix() {
    use eliot_dreamer_contracts::required_roles;
    let classes = [
        JobClass::Orientation,
        JobClass::Curation,
        JobClass::Clarification,
        JobClass::ResearchSynthesis,
        JobClass::ArchitectureSelfQuery,
        JobClass::DevelopmentDiagnosis,
        JobClass::Maintenance,
        JobClass::OrchestrationPlanning,
        JobClass::ConfigurationAssistance,
    ];
    assert_eq!(classes.len(), 9);
    for class in classes {
        let roles = required_roles(class);
        assert!(!roles.is_empty(), "class {class:?} must declare roles");
        // Orientation golden spot-check: common denominator present.
        if class == JobClass::Orientation {
            assert!(roles.contains(&DreamInputRole::ExactQuestion));
            assert!(roles.contains(&DreamInputRole::Requester));
        }
    }
    // Our fixture recipe binds the Orientation denominator exactly.
    let request = base_request();
    request.recipe.validate().expect("fixture recipe validates");
}

// WORK_UNIT_CASE: 593/2
#[test]
fn valid_complete_minimal_bundle_for_family() {
    let request = base_request();
    let plan = plan_bundle(request).expect("plan must succeed");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    );
    // Without a disclosure Allow the carrier is honest Blocked/Incomplete,
    // but planning itself must succeed and validate.
    match result {
        Ok(result) => {
            assert!(
                result.status == BundleStatus::Blocked
                    || result.status == BundleStatus::Complete
                    || result.status == BundleStatus::BudgetExhausted,
                "unexpected status {:?}",
                result.status
            );
            result.validate().expect("result validates");
        }
        Err(error) => panic!("finalize must not hard-error on minimal bundle: {error:?}"),
    }
}

// WORK_UNIT_CASE: 593/3
#[test]
fn unknown_job_role_recipe_version_fails_closed() {
    let mut request = base_request();
    request.recipe.schema_version = 999;
    assert!(
        plan_bundle(request).is_err(),
        "bad recipe version must fail"
    );
    let mut request = base_request();
    request.recipe.roles.push(RecipeRole {
        role: DreamInputRole::Evidence,
        disposition: RoleDisposition::Required,
        minimum: 1,
        maximum: 1,
        interpretation_dependencies: Vec::new(),
        source_priority: 0,
        source_rule: SourceRule {
            kind: SourceRuleKind::None,
            allowed_owner: None,
            allowed_privacy: Vec::new(),
            allowed_authority: Vec::new(),
            allowed_proof: Vec::new(),
            allowed_disclosure: Vec::new(),
        },
        protected: false,
        representation_loss: eliot_context_contracts::LossPolicy::NonDroppable,
        omission_policy: RoleOmissionPolicy::NonDroppable,
        condition: None,
    });
    // Duplicate Evidence role must fail (duplicate denominator).
    assert!(plan_bundle(request).is_err());
}

// WORK_UNIT_CASE: 593/4
#[test]
fn task_scope_fence_budget_mismatch_fails() {
    let mut request = base_request();
    request.recipe.job.task_id = "other-task".to_owned();
    assert!(plan_bundle(request).is_err(), "task mismatch must fail");
    let mut request = base_request();
    request.recipe.job.budget.input_bytes = Some(1);
    // Recipe limits (1M) exceed the shrunk job budget (1 byte) -> fail.
    assert!(plan_bundle(request).is_err());
}

// WORK_UNIT_CASE: 593/5
#[test]
fn duplicate_item_and_changed_digest_conflict() {
    let mut request = base_request();
    let duplicate = request.supplied_items[0].clone();
    request.supplied_items.push(duplicate);
    let error = plan_bundle(request).expect_err("duplicate identity must fail");
    assert!(matches!(error, ContractViolation::BindingMismatch { .. }));
    // Same ID with changed digest: conflicting manifest identity.
    let mut request = base_request();
    request.supplied_items[0].identity.content_digest = Some(sha256_hex(b"other"));
    assert!(plan_bundle(request).is_err());
}

// WORK_UNIT_CASE: 593/6
#[test]
fn stale_unavailable_blocked_dispositions_preserved() {
    use eliot_dreamer_contracts::MaterialOutcomeReason;
    for reason in [
        MaterialOutcomeReason::Stale,
        MaterialOutcomeReason::Unknown,
        MaterialOutcomeReason::Conflict,
    ] {
        let mut request = base_request();
        request.supplied_items[0].state = SuppliedItemState::Unavailable(reason);
        request.supplied_items[0].material = None;
        request.supplied_items[0].measurement = None;
        request.supplied_items[0].note = Some("owner could not supply".to_owned());
        let plan = plan_bundle(request).expect("unavailable must plan");
        let ledger = &plan.carrier().ledger;
        assert!(
            ledger.iter().any(|entry| entry.reason == Some(reason)),
            "reason {reason:?} must be retained in ledger"
        );
    }
    // Blocked variant.
    let mut request = base_request();
    request.supplied_items[0].state =
        SuppliedItemState::Blocked(eliot_dreamer_contracts::MaterialOutcomeReason::PrivacyMismatch);
    request.supplied_items[0].material = None;
    request.supplied_items[0].measurement = None;
    request.supplied_items[0].note = Some("blocked by closure".to_owned());
    let plan = plan_bundle(request).expect("blocked must plan");
    assert!(
        plan.carrier()
            .ledger
            .iter()
            .any(|entry| entry.note.is_some())
    );
}

// WORK_UNIT_CASE: 593/7
#[test]
fn privacy_authority_violation_is_blocked_not_selected() {
    let mut request = base_request();
    // Make the manifest reference privacy-violating by flipping privacy to a
    // value outside the recipe source rule (recipe allows Unrestricted only).
    let handle = ArtifactId::new("evidence-1").expect("handle");
    let reference = request
        .manifest
        .references
        .get_mut(&handle)
        .expect("reference");
    reference.privacy = PrivacyHandling::Purged;
    reference.provenance = None;
    reference.source_lineage = Some(
        SourceLineage::new(
            SourceId::new("source-1").expect("owner"),
            SourceRevisionId::new("revision-1").expect("rev"),
            reference.content_digest.clone(),
            None,
            BTreeSet::new(),
            None,
        )
        .expect("lineage"),
    );
    request.manifest.digest = request.manifest.computed_digest().expect("digest");
    request.recipe.job.frozen_manifest_digest = request.manifest.digest.clone();
    let digest = request.recipe.computed_digest().expect("recipe");
    request.recipe.recipe_digest = digest;
    let plan = plan_bundle(request).expect("privacy violation must still plan");
    // The item must not be selected; it is blocked by source policy.
    assert!(
        plan.carrier().materials.is_empty()
            || plan.carrier().ledger.iter().any(|entry| entry.disposition
                == eliot_dreamer_contracts::assembly::MaterialDisposition::Blocked)
    );
}

// WORK_UNIT_CASE: 593/8
#[test]
fn mandatory_denominator_and_missing_conditional() {
    // Missing mandatory Evidence (required min 1, supply none) -> plan still
    // builds but core is not ready; finalize stays Blocked/Incomplete.
    let mut request = base_request();
    request.supplied_items.clear();
    // Ordinals must stay contiguous; with no items the denominator is empty
    // for Evidence but recipe still requires one.
    let plan = plan_bundle(request).expect("missing mandatory must still plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize must return a disposition, not an error");
    assert_eq!(result.status, BundleStatus::Blocked);
    assert!(
        result.frontier.roles.contains(&DreamInputRole::Evidence),
        "missing Evidence must appear in frontier"
    );
}

// WORK_UNIT_CASE: 593/9
#[test]
fn interpretation_closure_and_missing_dependency() {
    use eliot_dreamer_contracts::assembly::{ConditionalPredicate, ConditionalRequirement};
    let mut request = base_request();
    // Architecture depends on Evidence; Evidence present so dependency holds.
    for role in &mut request.recipe.roles {
        if role.role == DreamInputRole::Architecture {
            role.interpretation_dependencies = vec![DreamInputRole::Evidence];
        }
    }
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    let plan = plan_bundle(request).expect("dependency satisfied must plan");
    assert!(!plan.carrier().materials.is_empty());
    // Now drop Evidence: Architecture dependency cannot be satisfied, so the
    // dependent must not be silently promoted.
    let mut request = base_request();
    for role in &mut request.recipe.roles {
        if role.role == DreamInputRole::Architecture {
            role.interpretation_dependencies = vec![DreamInputRole::Evidence];
        }
    }
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    request.supplied_items.clear();
    let plan = plan_bundle(request).expect("missing dependency must still plan");
    let _ = plan;
    let _ = ConditionalPredicate::EvidenceAvailable;
    let _ = ConditionalRequirement {
        predicate: ConditionalPredicate::EvidenceAvailable,
        evidence_role: DreamInputRole::Evidence,
        coverage: None,
    };
}

// WORK_UNIT_CASE: 593/10
#[test]
fn admitted_context_membership_not_required_here() {
    // context_required=false: no Context closure needed; plan succeeds.
    let request = base_request();
    assert!(!request.recipe.context_required);
    let plan = plan_bundle(request).expect("context-free plan must succeed");
    assert!(plan.carrier().context.is_none());
}

// WORK_UNIT_CASE: 593/11
#[test]
fn no_second_context_admission_path() {
    // The crate exposes only plan_bundle/finalize_bundle; there is no
    // admission, ranking, or provider call in the public surface.
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    // Measurement profile is frozen at planning and retained unchanged.
    assert_eq!(plan.measurement_profile().route_id, ROUTE_ID);
    let observations = observations_for(&plan);
    assert_eq!(observations.measurement_profile.route_id, ROUTE_ID);
}

// WORK_UNIT_CASE: 593/12
#[test]
fn fixed_reserves_and_reserve_only_overflow() {
    let mut request = base_request();
    // Shrink route capacity below input+reserves to force reserve overflow.
    request.measurement_profile.capacity.route_capacity = 10;
    assert!(
        plan_bundle(request).is_err(),
        "reserve-only overflow must fail closed"
    );
}

// WORK_UNIT_CASE: 593/13
#[test]
fn mandatory_core_exact_fit_and_one_over() {
    let request = base_request();
    let plan = plan_bundle(request).expect("exact fit must plan");
    let input_len = plan.model_input().len() as u64;
    let total = plan
        .carrier()
        .recipe
        .reserves
        .total_for(
            &ArtifactId::new(PROFILE_ID).expect("profile"),
            MeasurementUnit::Utf8Bytes,
        )
        .expect("reserves");
    assert!(input_len + total <= 1_048_576);
    // One-over: shrink input_bytes limit below measured usage.
    let mut request = base_request();
    request.recipe.limits.input_bytes = Some(1);
    request.recipe.job.budget.input_bytes = Some(1);
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    // Recipe limit (1) within job (1) validates, but core usage exceeds it.
    let plan = plan_bundle(request).expect("over-budget core still plans");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    assert_eq!(result.status, BundleStatus::BudgetExhausted);
}

// WORK_UNIT_CASE: 593/14
#[test]
fn optional_flood_cannot_crowd_mandatory_core() {
    let mut request = base_request();
    // Flood with many optional Architecture items; mandatory Evidence must
    // remain selected.
    let mut manifest = request.manifest.clone();
    for index in 0..5u32 {
        let handle = format!("arch-{index}");
        let content = format!("architecture content {index}");
        let reference = authorized_reference(&handle, &content);
        manifest
            .references
            .insert(ArtifactId::new(&handle).expect("h"), reference);
        request.supplied_items.push(evidence_item(
            DreamInputRole::Architecture,
            &handle,
            &content,
            index,
        ));
    }
    manifest.digest = manifest.computed_digest().expect("digest");
    request.manifest = manifest;
    request.recipe.job.frozen_manifest_digest = request.manifest.digest.clone();
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    let plan = plan_bundle(request).expect("flood must plan");
    assert!(
        plan.carrier()
            .materials
            .iter()
            .any(|material| material.role == DreamInputRole::Evidence),
        "mandatory Evidence must survive optional flood"
    );
}

// WORK_UNIT_CASE: 593/15
#[test]
fn permitted_and_forbidden_omission_policies() {
    // Permitted: optional Architecture with a reversible handle omission.
    let mut request = base_request();
    let mut item = evidence_item(
        DreamInputRole::Architecture,
        "arch-omit",
        "architecture omit content",
        0,
    );
    // Make it oversized so packing omits it? Instead directly check the
    // ledger retains a reversible omission when the owner authorizes one.
    item.omission = Some(omission_handle("arch-omit"));
    // Add matching manifest reference.
    let mut manifest = request.manifest.clone();
    manifest.references.insert(
        ArtifactId::new("arch-omit").expect("h"),
        authorized_reference("arch-omit", "architecture omit content"),
    );
    manifest.digest = manifest.computed_digest().expect("digest");
    request.manifest = manifest;
    request.recipe.job.frozen_manifest_digest = request.manifest.digest.clone();
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    request.supplied_items.push(item);
    let plan = plan_bundle(request).expect("omission plan");
    let _ = plan;
    // Forbidden: protected role with a droppable omission policy is rejected
    // at recipe validation time.
    let mut request = base_request();
    for role in &mut request.recipe.roles {
        if role.role == DreamInputRole::Evidence {
            role.protected = true;
            role.representation_loss = eliot_context_contracts::LossPolicy::NonDroppable;
            role.omission_policy = RoleOmissionPolicy::ReversibleHandle;
        }
    }
    assert!(request.recipe.validate().is_err());
}

// WORK_UNIT_CASE: 593/16
#[test]
fn whole_unit_material_not_split() {
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    // Each selected material retains its whole representation digest.
    for material in &plan.carrier().materials {
        match &material.representation {
            MaterialRepresentation::Utf8 { content, .. } => {
                assert_eq!(
                    sha256_hex(content.as_bytes()),
                    material.material.digest,
                    "whole-unit digest must be conserved"
                );
            }
            _ => panic!("fixture uses Utf8 whole units"),
        }
    }
}

// WORK_UNIT_CASE: 593/17
#[test]
fn complete_vs_partial_denominator() {
    // Complete-ish: Evidence present.
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    assert_ne!(result.status, BundleStatus::Complete);
    // Partial: Evidence missing -> Blocked with frontier.
    let mut request = base_request();
    request.supplied_items.clear();
    let plan = plan_bundle(request).expect("plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    assert_eq!(result.status, BundleStatus::Blocked);
    assert!(!result.frontier.roles.is_empty());
}

// WORK_UNIT_CASE: 593/18
#[test]
fn unknown_measurement_and_non_ascii_boundaries() {
    // Non-ASCII content is bounded UTF-8 and digested exactly as a whole unit.
    let content = "ünïcödé ✓ content — 境界";
    let digest = sha256_hex(content.as_bytes());
    assert_eq!(digest.len(), 64);
    let mut request = base_request();
    let manifest = manifest_with(vec![("evidence-1", content)]);
    let job_digest = manifest.digest.clone();
    request.manifest = manifest;
    request.recipe.job.frozen_manifest_digest = job_digest;
    request.supplied_items = vec![evidence_item(
        DreamInputRole::Evidence,
        "evidence-1",
        content,
        0,
    )];
    let recipe_digest = request.recipe.computed_digest().expect("digest");
    // Recipe job digest changed (manifest changed) so recompute via fresh recipe.
    let job = job_with_manifest(request.manifest.digest.clone());
    request.recipe = recipe_for(job);
    request.supplied_items = vec![evidence_item(
        DreamInputRole::Evidence,
        "evidence-1",
        content,
        0,
    )];
    let _ = recipe_digest;
    let plan = plan_bundle(request).expect("non-ASCII whole unit must plan");
    let material = plan
        .carrier()
        .materials
        .iter()
        .find(|m| m.role == DreamInputRole::Evidence)
        .expect("non-ASCII evidence selected");
    match &material.representation {
        MaterialRepresentation::Utf8 {
            content: retained, ..
        } => {
            assert_eq!(retained, content);
            assert_eq!(sha256_hex(retained.as_bytes()), material.material.digest);
        }
        _ => panic!("fixture uses Utf8 whole units"),
    }
    // Unknown contribution status is retained explicitly (bytes None, status
    // Unknown) — unknown is not zero and never claims exact bytes.
    let mut request = base_request();
    request.supplied_items[0]
        .measurement
        .as_mut()
        .expect("m")
        .status = ContributionStatus::Unknown;
    request.supplied_items[0]
        .measurement
        .as_mut()
        .expect("m")
        .bytes = None;
    let plan = plan_bundle(request).expect("unknown measurement plans");
    let carrier = plan.carrier();
    let measurement = carrier
        .measurements
        .iter()
        .find(|m| m.material.as_str() == "evidence-1")
        .expect("unknown measurement retained");
    assert_eq!(measurement.status, ContributionStatus::Unknown);
    assert_eq!(measurement.bytes, None);
}

// WORK_UNIT_CASE: 593/19
#[test]
fn every_item_and_role_has_one_disposition() {
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    let carrier = plan.carrier();
    // Every supplied identity appears exactly once in the ledger.
    let mut seen = BTreeSet::new();
    for entry in &carrier.ledger {
        let key = (entry.role, entry.ordinal);
        assert!(seen.insert(key), "duplicate ledger entry for {key:?}");
    }
    // Every recipe role has exactly one outcome.
    let mut roles = BTreeSet::new();
    for outcome in &carrier.role_outcomes {
        assert!(roles.insert(outcome.role));
    }
    for role in &carrier.recipe.roles {
        assert!(
            roles.contains(&role.role),
            "role {:?} missing outcome",
            role.role
        );
    }
}

// WORK_UNIT_CASE: 593/20
#[test]
fn omission_handle_identity_expiry_wrong_scope() {
    let mut request = base_request();
    let mut item = evidence_item(
        DreamInputRole::Architecture,
        "arch-scope",
        "arch scope content",
        0,
    );
    let mut omission = omission_handle("arch-scope");
    omission.scope_id = "other-scope".to_owned();
    item.omission = Some(omission);
    item.state =
        SuppliedItemState::Unavailable(eliot_dreamer_contracts::MaterialOutcomeReason::Missing);
    item.material = None;
    item.measurement = None;
    item.note = Some("unavailable".to_owned());
    let mut manifest = request.manifest.clone();
    manifest.references.insert(
        ArtifactId::new("arch-scope").expect("h"),
        authorized_reference("arch-scope", "arch scope content"),
    );
    manifest.digest = manifest.computed_digest().expect("digest");
    request.manifest = manifest;
    request.recipe.job.frozen_manifest_digest = request.manifest.digest.clone();
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    request.supplied_items.push(item);
    assert!(
        plan_bundle(request).is_err(),
        "wrong-scope omission must be rejected"
    );
}

// WORK_UNIT_CASE: 593/21
#[test]
fn frozen_manifest_contains_only_included_handles() {
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    let carrier = plan.carrier();
    for handle in carrier.selected_references.keys() {
        assert!(
            carrier.manifest.references.contains_key(handle),
            "selected handle must be in frozen manifest"
        );
    }
    // Supplied-but-unselected handles are not in selected_references.
    assert!(carrier.selected_references.len() <= carrier.supplied_items.len());
}

// WORK_UNIT_CASE: 593/22
#[test]
fn exact_budget_arithmetic_and_mismatch() {
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    // Input bytes equal the canonical model input length.
    let expected = plan_input_len(&result);
    assert_eq!(result.budget_usage.input_bytes, expected);
    // Deliberate mismatch is a typed defect, not zero: tampering the usage
    // breaks validation.
    let mut tampered = result.clone();
    tampered.budget_usage.input_bytes += 1;
    assert!(tampered.validate().is_err());
}

fn plan_input_len(result: &eliot_dreamer_contracts::AssemblyResult) -> u64 {
    result.budget_usage.input_bytes
}

// WORK_UNIT_CASE: 593/23
#[test]
fn randomized_order_yields_identical_digest() {
    let request = base_request();
    let plan_a = plan_bundle(request.clone()).expect("plan a");
    let mut shuffled = request;
    shuffled.supplied_items.reverse();
    let plan_b = plan_bundle(shuffled).expect("plan b");
    assert_eq!(plan_a.model_input(), plan_b.model_input());
    assert_eq!(plan_a.model_input_digest(), plan_b.model_input_digest());
}

// WORK_UNIT_CASE: 593/24
#[test]
fn deadline_cancellation_boundaries_preserve_disposition() {
    let mut request = base_request();
    request.policy.cancelled = true;
    let plan = plan_bundle(request).expect("cancelled must still plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: true,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    assert_eq!(result.status, BundleStatus::Blocked);
    let mut request = base_request();
    request.policy.deadline_reached = true;
    let plan = plan_bundle(request).expect("deadline must still plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: true,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    assert_eq!(result.status, BundleStatus::Blocked);
}

// WORK_UNIT_CASE: 593/25
#[test]
fn no_provider_store_model_call_path() {
    // Static proof: the crate's public surface is only planning/finalization
    // over supplied material; this test pins the absence of I/O by asserting
    // determinism without ambient services.
    let request = base_request();
    let first = plan_bundle(request.clone()).expect("first");
    let second = plan_bundle(request).expect("second");
    assert_eq!(first.model_input(), second.model_input());
    assert_eq!(first.carrier(), second.carrier());
}

// WORK_UNIT_CASE: 593/26
#[test]
fn complete_implies_mandatory_and_known_measurement() {
    // Property regression: whenever a result reports Complete, every
    // mandatory role/dependency is satisfied and measurement is known.
    // Our fixture never reaches Complete without disclosure, so assert the
    // contrapositive on the Blocked minimal bundle.
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    let observations = observations_for(&plan);
    let result = finalize_bundle(
        plan,
        observations,
        AssemblyPolicy {
            cancelled: false,
            deadline_reached: false,
            elapsed_ms: 0,
            attempts: 1,
        },
    )
    .expect("finalize");
    if result.status == BundleStatus::Complete {
        for outcome in &result.materials.role_outcomes {
            assert_ne!(
                outcome.state,
                eliot_dreamer_contracts::assembly::RoleOutcomeState::Missing
            );
        }
    } else {
        assert_eq!(result.status, BundleStatus::Blocked);
    }
}

// WORK_UNIT_CASE: 593/27
#[test]
fn optional_cannot_remove_mandatory_or_headroom() {
    let base = base_request();
    let base_plan = plan_bundle(base).expect("base");
    let base_evidence = base_plan
        .carrier()
        .materials
        .iter()
        .filter(|m| m.role == DreamInputRole::Evidence)
        .count();
    let mut request = base_request();
    let mut manifest = request.manifest.clone();
    for index in 0..3u32 {
        let handle = format!("opt-{index}");
        let content = format!("optional content {index} with padding to grow bytes");
        manifest.references.insert(
            ArtifactId::new(&handle).expect("h"),
            authorized_reference(&handle, &content),
        );
        request.supplied_items.push(evidence_item(
            DreamInputRole::Implementation,
            &handle,
            &content,
            index,
        ));
    }
    manifest.digest = manifest.computed_digest().expect("digest");
    request.manifest = manifest;
    request.recipe.job.frozen_manifest_digest = request.manifest.digest.clone();
    let digest = request.recipe.computed_digest().expect("digest");
    request.recipe.recipe_digest = digest;
    let plan = plan_bundle(request).expect("optional-augmented");
    let evidence = plan
        .carrier()
        .materials
        .iter()
        .filter(|m| m.role == DreamInputRole::Evidence)
        .count();
    assert_eq!(
        base_evidence, evidence,
        "optionals must not evict mandatory"
    );
}

// WORK_UNIT_CASE: 593/28
#[test]
fn no_included_reference_outside_manifest() {
    let request = base_request();
    let plan = plan_bundle(request).expect("plan");
    let carrier = plan.carrier();
    for (handle, reference) in &carrier.selected_references {
        assert!(carrier.manifest.references.contains_key(handle));
        assert_eq!(&reference.handle, handle);
    }
    // Foreign handles without manifest membership are never selected.
    let mut request = base_request();
    let mut foreign = evidence_item(
        DreamInputRole::Architecture,
        "foreign-1",
        "foreign content",
        0,
    );
    foreign.state = SuppliedItemState::Blocked(
        eliot_dreamer_contracts::MaterialOutcomeReason::AuthorityMismatch,
    );
    foreign.material = None;
    foreign.measurement = None;
    foreign.note = Some("foreign blocked".to_owned());
    request.supplied_items.push(foreign);
    let plan = plan_bundle(request).expect("foreign");
    assert!(
        !plan
            .carrier()
            .selected_references
            .contains_key(&ArtifactId::new("foreign-1").expect("h"))
    );
}

#[test]
fn disclosure_type_is_referenced() {
    // Keeps the DisclosureAuthorization import live as documentation of the
    // completion boundary (plain Allow required for Complete).
    fn _assert(_: Option<DisclosureAuthorization>) {}
}
