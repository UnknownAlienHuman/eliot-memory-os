//! A-04 bundle stage for admitted Dreamer jobs (issue #702, Slice 2).
//!
//! After the [#806 controller step](crate::controller::step_admitted_cycle),
//! the binary plans the bounded frozen input bundle through the #593 owner
//! ([`plan_bundle`](eliot_dreamer_bundle::plan_bundle)) exactly once per
//! admitted job. This module performs no local fetch, ranking, compression,
//! or model work: the [`AssemblyRequest`] arrives Governor-resolved (later
//! slices), and the returned owner [`AssemblyPlan`](eliot_dreamer_bundle::AssemblyPlan)
//! is surfaced unmodified so the frozen complete/partial/incomplete role
//! denominator is preserved losslessly (I9.4: the denominator arrives with
//! governed material; Dreamer never selects it).

use eliot_dreamer_bundle::{AssemblyPlan, AssemblyRequest, plan_bundle};
use eliot_dreamer_contracts::ContractViolation;

use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Resolves the A-04 request for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-plan calls. The Governor-issued recipe, manifest, supplied
/// items, and measurement profile arrive through a source-owner port in a
/// later slice; until then resolution refuses rather than synthesizing bundle
/// inputs, because locally selected materials would be self-issued authority
/// (I9.2: bundle construction runs via Governor handles).
pub(crate) fn resolve_bundle_request(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<AssemblyRequest, DreamerError> {
    verify_admitted_binding(admission, job)?;
    Err(DreamerError::InvalidAdmission(
        "admitted bundle request requires Governor-resolved recipe and manifest",
    ))
}

/// Plans the admitted A-04 bundle exactly once.
///
/// `plan_once` is `FnOnce`: the owner assembly cannot run twice for one
/// admission through this seam. Production passes
/// [`plan_bundle`](eliot_dreamer_bundle::plan_bundle); deterministic tests
/// pass a counting wrapper around the real function to prove the
/// once-per-admission call shape. The resulting plan is returned unmodified:
/// no role outcome is dropped, thinned, or re-selected here, so the owner
/// denominator (one outcome per recipe role, including empty roles) and the
/// complete/partial/incomplete states it carries are preserved exactly.
pub(crate) fn plan_admitted_bundle_with(
    request: AssemblyRequest,
    plan_once: impl FnOnce(AssemblyRequest) -> Result<AssemblyPlan, ContractViolation>,
) -> Result<AssemblyPlan, DreamerError> {
    plan_once(request).map_err(|error| bundle_denied(&error))
}

/// Production entry: the real A-04 bundle plan, once per admission.
pub(crate) fn plan_admitted_bundle(
    request: AssemblyRequest,
) -> Result<AssemblyPlan, DreamerError> {
    plan_admitted_bundle_with(request, plan_bundle)
}

/// Maps an owner assembly refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the bundle
/// inputs were not. Dynamic payloads (handles, digests, reasons) are dropped
/// in favor of bounded static field names; nothing secret flows.
fn bundle_denied(error: &ContractViolation) -> DreamerError {
    match error {
        ContractViolation::UnknownVariant { field, .. }
        | ContractViolation::OutOfBounds { field, .. }
        | ContractViolation::BindingMismatch { field, .. }
        | ContractViolation::Malformed { field, .. }
        | ContractViolation::MissingField(field)
        | ContractViolation::ImplicitDefault(field)
        | ContractViolation::CrossStage(field) => DreamerError::InvalidAdmission(field),
        ContractViolation::Budget { dimension, .. } => DreamerError::InvalidAdmission(dimension),
        ContractViolation::KindPayload(_) => {
            DreamerError::InvalidAdmission("kind/payload mismatch")
        }
        ContractViolation::Registry(_) => {
            DreamerError::InvalidAdmission("handler registry conflict")
        }
        ContractViolation::ScreenIneligible(_) => {
            DreamerError::InvalidAdmission("screen ineligible")
        }
        ContractViolation::Preservation(_) => {
            DreamerError::InvalidAdmission("preservation failure")
        }
        ContractViolation::ForbiddenCarry(_) => {
            DreamerError::InvalidAdmission("forbidden candidate carry")
        }
    }
}

#[cfg(test)]
mod slice_2_bundle_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_context_contracts::{
        CONTEXT_CONTRACT_VERSION, CapacityLimits, LossPolicy, MeasurementAggregationMode,
        MeasurementCompositionProfile, MeasurementUnit,
    };
    use eliot_contracts::{
        ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId, sha256_hex,
    };
    use eliot_dreamer_bundle::AssemblyPolicy;
    use eliot_dreamer_contracts::assembly::{
        DreamInputRole, DreamJobRecipe, RecipeInput, RecipeRole, RoleDisposition, RoleOmissionPolicy,
        SourceRule, SourceRuleKind,
    };
    use eliot_dreamer_contracts::grounding::{
        AllowedReferenceManifest, AttemptIdentity, GROUNDING_SCHEMA_VERSION,
    };
    use eliot_dreamer_contracts::{
        AssemblyReserve, AssemblyReserveSet, BudgetLimits, DreamJobAdmission, JobClass, Requester,
        RequesterOrigin,
    };

    use crate::KERNEL_ADMISSION_REQUIRED;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ROUTE_ID: &str = "route-slice-2";
    const PROFILE_ID: &str = "profile-slice-2";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission_with_deadline(deadline_unix_ms: u64) -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-2".to_owned(),
            attempt_id: "attempt-slice-2".to_owned(),
            scope_id: "scope-slice-2".to_owned(),
            request_id: "request-slice-2".to_owned(),
            idempotency_key: "job-slice-2:attempt-slice-2".to_owned(),
            cancellation_id: "cancel-slice-2".to_owned(),
            deadline_unix_ms,
            state_fence: fence(),
        }
    }

    fn job_for(admission: &KernelJobAdmission) -> DreamJobInput {
        DreamJobInput {
            job_id: admission.job_id.clone(),
            job_class: JobClass::Orientation,
            exact_question: "What does ELIOT know about this scope?".to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: admission.scope_id.clone(),
            task_id: None,
            state_fence: "kernel-owned".to_owned(),
            evidence_handles: Vec::new(),
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: Vec::new(),
            privacy_profile: "local_only".to_owned(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec![ROUTE_ID.to_owned()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".to_owned(),
            forbidden_effects: Vec::new(),
        }
    }

    /// Stale Kernel input fails closed at resolution with zero plan calls.
    #[test]
    fn stale_admission_fails_closed_before_any_plan() {
        let admission = admission_with_deadline(1);
        let job = job_for(&admission);
        let refused = resolve_bundle_request(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero plan calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_plan() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.scope_id = "caller-switched-scope".to_owned();
        let refused = resolve_bundle_request(&admission, &job);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A valid admission with matching identity reaches the material
    /// boundary: the refusal names the missing Governor-resolved recipe and
    /// manifest instead of selecting bundle inputs locally.
    #[test]
    fn valid_admission_waits_for_governed_material() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let refused = resolve_bundle_request(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "admitted bundle request requires Governor-resolved recipe and manifest"
                ))
            ),
            "valid input must wait for governed material, got {refused:?}"
        );
    }

    fn profile() -> MeasurementCompositionProfile {
        MeasurementCompositionProfile {
            profile_id: ArtifactId::new(PROFILE_ID).expect("profile id"),
            schema_version: CONTEXT_CONTRACT_VERSION,
            serializer_id: "test-serializer".to_owned(),
            serializer_version: "1.0".to_owned(),
            serializer_options_digest: sha256_hex(b"options"),
            route_id: ROUTE_ID.to_owned(),
            model_id: "model-1".to_owned(),
            unit: MeasurementUnit::Utf8Bytes,
            aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
            qualification: ArtifactId::new("qualification-1").expect("qualification"),
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
        let profile = ArtifactId::new(PROFILE_ID).expect("profile");
        let slot = |value: u64| AssemblyReserve {
            profile: profile.clone(),
            unit: MeasurementUnit::Utf8Bytes,
            value,
        };
        AssemblyReserveSet {
            fixed: slot(100),
            protocol: slot(50),
            model_output: slot(1000),
            grounding: slot(500),
            review: slot(1000),
            headroom: slot(500),
        }
    }

    /// Source-free recipe role: exactly one typed input, no governed source.
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
            representation_loss: LossPolicy::NonDroppable,
            omission_policy: RoleOmissionPolicy::NonDroppable,
            condition: None,
        }
    }

    /// Non-Curation classes declare every Curation role not-applicable.
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
            representation_loss: LossPolicy::NonDroppable,
            omission_policy: RoleOmissionPolicy::NotApplicable,
            condition: None,
        }
    }

    /// Class-agnostic bundle fixture: the A-04 seam below never dispatches by
    /// class (dispatch is Slice-A/1 work that already ran), so the fixture
    /// uses the smallest role denominator with no governed source roles —
    /// Clarification needs no evidence item, only typed inputs.
    fn clarification_request() -> AssemblyRequest {
        let manifest = AllowedReferenceManifest {
            schema_version: GROUNDING_SCHEMA_VERSION,
            manifest_id: "manifest-slice-2".to_owned(),
            run_id: "run-slice-2".to_owned(),
            task_id: TaskId::new("task-slice-2").expect("task"),
            scope_id: "scope-slice-2".to_owned(),
            state_fence: fence(),
            source_snapshot: "snapshot-slice-2".to_owned(),
            source_revision: "revision-slice-2".to_owned(),
            references: BTreeMap::new(),
            coverage_denominators: BTreeMap::new(),
            coverage_receipts: BTreeMap::new(),
            dependence_groups: BTreeSet::new(),
            digest: String::new(),
        };
        let manifest_digest = manifest.computed_digest().expect("manifest digest");
        let manifest = AllowedReferenceManifest {
            digest: manifest_digest.clone(),
            ..manifest
        };
        let job = DreamJobAdmission {
            // I9.4: the admission envelope schema version is exactly 1.
            schema_version: 1,
            job_class: JobClass::Clarification,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "test-harness".to_owned(),
                session: None,
            },
            operation_id: "op-slice-2".to_owned(),
            idempotency_key: "idem-slice-2".to_owned(),
            task_id: "task-slice-2".to_owned(),
            scope_id: "scope-slice-2".to_owned(),
            state_fence: fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-slice-2".to_owned(),
            policy_ref: "policy-slice-2".to_owned(),
            budget: limits(),
            deadline_ms: None,
            frozen_manifest_digest: manifest_digest,
        };
        let mut roles = vec![
            source_free_role(DreamInputRole::ExactQuestion),
            source_free_role(DreamInputRole::Requester),
            source_free_role(DreamInputRole::ConflictsAndUnknowns),
            source_free_role(DreamInputRole::PrivacyProfile),
            source_free_role(DreamInputRole::Budget),
            source_free_role(DreamInputRole::OutputSchema),
            source_free_role(DreamInputRole::ForbiddenEffects),
            source_free_role(DreamInputRole::AllowedModelRoutes),
        ];
        roles.extend(
            [
                DreamInputRole::CurationSourceSnapshot,
                DreamInputRole::CurationSourceDenominator,
                DreamInputRole::CurationScreenProfile,
                DreamInputRole::CurationProtectionCoverage,
                DreamInputRole::CurationSubtypePayload,
                DreamInputRole::CurationTargetSet,
                DreamInputRole::CurationEvidenceSet,
                DreamInputRole::CurationTargetDenominator,
                DreamInputRole::CurationTargetScreens,
                DreamInputRole::CurationTargetDispositions,
            ]
            .into_iter()
            .map(not_applicable_role),
        );
        let mut recipe = DreamJobRecipe {
            schema_version: 1,
            recipe_id: "recipe-slice-2".to_owned(),
            recipe_revision: "r1".to_owned(),
            recipe_digest: "0".repeat(64),
            job,
            attempt: AttemptIdentity {
                attempt_id: "attempt-slice-2".to_owned(),
                attempt_number: 1,
                maximum_attempts: 2,
            },
            inputs: vec![
                RecipeInput::ExactQuestion {
                    text: "What is missing from this scope?".to_owned(),
                },
                RecipeInput::ConflictsAndUnknowns {
                    content: "No explicit conflict set was supplied.".to_owned(),
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
            ],
            context_required: false,
            roles,
            limits: limits(),
            reserves: reserves(),
        };
        let digest = recipe.computed_digest().expect("recipe digest");
        recipe.recipe_digest = digest;
        AssemblyRequest {
            recipe,
            manifest,
            supplied_items: Vec::new(),
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

    /// The real A-04 assembly runs exactly once per admitted admission: one
    /// counting wrapper around the production function over a digest-corrupted
    /// request, one call, one typed fail-closed refusal with the
    /// request-rejected code.
    #[test]
    fn owner_plan_runs_exactly_once_per_admission() {
        let mut request = clarification_request();
        request.recipe.recipe_digest = "0".repeat(64);
        let calls = AtomicU64::new(0);
        let refused = plan_admitted_bundle_with(request, |request| {
            calls.fetch_add(1, Ordering::SeqCst);
            plan_bundle(request)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner assembly must run exactly once per admission"
        );
        let Err(error) = refused else {
            panic!("digest-corrupted bundle inputs must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "bundle refusal must not borrow the Kernel-admission code"
        );
    }

    /// A valid plan preserves the owner denominator losslessly: one role
    /// outcome per recipe role (including empty roles), every recipe role
    /// present, and the frozen model-input digest bound. The seam returns the
    /// owner plan unmodified — no role is dropped, thinned, or re-selected
    /// here.
    #[test]
    fn valid_plan_preserves_bundle_denominator() {
        let request = clarification_request();
        let denominator = request.recipe.roles.len();
        assert!(
            denominator >= 8,
            "fixture must carry the class denominator, got {denominator}"
        );
        let plan = plan_admitted_bundle(request).expect("valid bundle request must plan");
        let outcomes = plan.carrier().role_outcomes.clone();
        assert_eq!(
            outcomes.len(),
            denominator,
            "plan must preserve one outcome per recipe role"
        );
        for role in plan.carrier().recipe.roles.clone() {
            assert_eq!(
                outcomes.iter().filter(|outcome| outcome.role == role.role).count(),
                1,
                "role {:?} must appear exactly once in the preserved denominator",
                role.role
            );
        }
        assert!(
            !plan.model_input_digest().is_empty(),
            "planned bundle must bind its frozen model-input digest"
        );
    }

    /// Every owner assembly refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("request.material_denominator"),
            ContractViolation::ImplicitDefault("schema_version"),
            ContractViolation::CrossStage("raw"),
            ContractViolation::UnknownVariant {
                field: "job_class",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "role.minimum_or_maximum",
                min: 1,
                max: 1,
                got: 0,
            },
            ContractViolation::BindingMismatch {
                field: "request.manifest",
                reason: "manifest differs".to_owned(),
            },
            ContractViolation::Malformed {
                field: "recipe.input.content",
                reason: "blank".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "source_width",
                reason: "over".to_owned(),
            },
            ContractViolation::KindPayload("kind".to_owned()),
            ContractViolation::Registry("registry".to_owned()),
            ContractViolation::ScreenIneligible("screen".to_owned()),
            ContractViolation::Preservation("preservation".to_owned()),
            ContractViolation::ForbiddenCarry("carry".to_owned()),
        ];
        assert_eq!(cases.len(), 13);
        for error in cases {
            let refused = bundle_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
        }
    }
}
