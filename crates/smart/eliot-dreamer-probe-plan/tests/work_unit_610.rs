//! Work-unit 610 slice 4: bounded discriminative probe planner, cases 1..11
//! (valid two-rival probe, multi-rival result matrix, exact
//! objective/result/affordance/disposition vocabulary, bound-input
//! mismatch, duplicate collapse, vague/no-gain objective gating,
//! exact evidence/verifier-gap plannability, per-descriptor scope
//! exclusion, bounded closed result schema, open/unbounded rejection,
//! identical-updates rejection).
//!
//! Cases 610/1, 610/4 and 610/5 are marked on the existing planner
//! behaviour tests in `tests/probe_plan.rs`. Cases 610/12..42 (confirmation,
//! affordance/execution, safety, budget/dominance, replay and no-execution
//! proof) remain QUEUED on issue #610.
//!
//! Ownership ruling 610/6-10 (planner-side descriptor gating only; no new
//! APIs): 610/6 OWNED via `InformationDimension::has_expected_gain` false
//! for `NoGain`/`Unavailable` and the planner `Unprobeable` gate; 610/7
//! OWNED via the 1:1 `AffordanceTarget` -> `ProbeTarget` projection for
//! `EvidenceGap`/`Objective` with exact result schemas; 610/8 SPLIT -
//! per-descriptor applicability-scope exclusion OWNED via the planner scope
//! gate, while resolved/nonmaterial materiality judgment stays with A-03
//! `ProbeObjective` declarations (planner sees only `ProbeObjectiveRef`);
//! 610/9 OWNED via the A-03 `PossibleResultSchema` closed denominator
//! preserved verbatim by the planner (`probe.result_schema` validates and
//! keeps the exact two-branch cover); 610/10 OWNED via the A-03
//! `PossibleResultSchema::new` fail-closed boundary (empty targets/branches,
//! incomplete cover, duplicate identity, undeclared target all rejected
//! before any descriptor can plan); 610/11 OWNED via the planner
//! identical-updates gate (multi-branch matrices with the same update set on
//! every branch are Unprobeable; single-branch defers to 610/38 readiness).
//! Docs route=sha256:1b9bbbd8b5bb5e2de4737b4fa03e7e3672daba4394afef443dd3d8476554c7fa read=sha256:ea79ca7e06dbc95bb6ebceb4b5d904a848f265540ab58d6e82d93d5878599ec6 bundle=5ca78f97ee5f6485f6ab552d6687ade11da053a68be0cb38339167aeac0be7f3 (generic-source; verified bundle read in full plus I09-03, I09-05, I21-03, I12-18, I12-22, I13-07, I15-02, I15-04, I05-27, I05-16, I07-20 read directly).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::num::NonZeroU64;

use eliot_dreamer_contracts::{
    AffordanceKind, AffordanceTarget, AuthorityDimension, BudgetLimits, BundleCompleteness,
    ConditionAssumptionRef, ConsentDimension, ContextDimension, CostDimension, DreamInputBundle,
    EffectDimension, FeasibilityDimension, GapUpdateMeaning, HumanAttentionDimension,
    InformationDimension, InquiryAffordanceDescriptor, InquiryAffordanceDescriptorParams,
    InquiryAffordanceSet, InquiryAffordanceSetParams, LatencyDimension, MaterialClaimRef,
    PossibleResultSchema, PossibleResultValue, PrivacyDimension, ProbeObjectiveRef, ProbeOwnerRef,
    ResourceDimension, ResultBranch, ResultTarget, ResultUpdate, ReversibilityDimension,
    RivalCoverageStatus, RivalCoverageSummary, RivalDeclarationSetRef, RivalModelSet,
    RivalModelSetParams, RivalPredictionRef, ValidatedDreamDraft, ValidationReceipt,
    grounding::canonical::{
        ArtifactId, EpochId, EpochLineageId, Precision, PropositionId, ResourceGeneration,
        StateFence, TaskId, ValidityBounds, sha256_hex,
    },
};
use eliot_dreamer_probe_plan::{OmissionKind, ProbePlan, ProbePlanParams, ProbeTarget};

fn must<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected fixture error: {error:?}"),
    }
}

fn fence() -> StateFence {
    let lineage = must(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000"));
    let sequence = must(NonZeroU64::new(1).ok_or("sequence must be non-zero"));
    let epoch = must(EpochId::new(lineage, sequence));
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn artifact(id: &str) -> ArtifactId {
    must(ArtifactId::new(id))
}

fn task() -> TaskId {
    must(TaskId::new("task-1"))
}

fn digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
}

fn bounds() -> ValidityBounds {
    bounds_scoped("scope-1")
}

fn bounds_scoped(scope: &str) -> ValidityBounds {
    must(ValidityBounds::new(
        scope,
        None,
        None,
        "v1",
        Precision("file".to_owned()),
    ))
}

fn bundle() -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: digest("manifest"),
        materials: Vec::new(),
        omissions: Vec::new(),
        completeness: BundleCompleteness::Unknown,
        authoritative_denominator: None,
    }
}

fn receipt() -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "validator-1".to_owned(),
        validator_policy: "policy-1".to_owned(),
        job_id: "job-1".to_owned(),
        draft_digest: digest("draft"),
        bundle_digest: digest("bundle"),
        manifest_digest: digest("manifest"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: digest("validator-input"),
        output_digest: digest("validator-output"),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: digest("preservation"),
        budget_digest: digest("budget"),
    }
}

fn draft() -> ValidatedDreamDraft {
    ValidatedDreamDraft {
        receipt: receipt(),
        draft_digest: digest("draft"),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
    }
}

fn rivals() -> RivalModelSet {
    must(RivalModelSet::new(RivalModelSetParams {
        set_id: artifact("rival-set-1"),
        task_id: task(),
        scope: "scope-1".to_owned(),
        state_fence: fence(),
        bundle_digest: digest("bundle"),
        validated_input_digest: digest("validated"),
        declaration_set: RivalDeclarationSetRef {
            set_id: artifact("rival-decl-1"),
            digest: digest("decl"),
        },
        policy_id: "policy-1".to_owned(),
        policy_digest: digest("policy"),
        discriminators: Vec::new(),
        unresolved: Vec::new(),
        model_coverage: RivalCoverageSummary {
            status: RivalCoverageStatus::Unknown,
            denominator_digest: None,
        },
        source_coverage: RivalCoverageSummary {
            status: RivalCoverageStatus::Unknown,
            denominator_digest: None,
        },
        omission_frontier: Vec::new(),
    }))
}

fn objective(id: &str) -> ProbeObjectiveRef {
    ProbeObjectiveRef {
        objective_id: artifact(id),
        objective_digest: digest(id),
    }
}

fn result_schema(id: &str, objective_id: &str) -> PossibleResultSchema {
    let target = objective(objective_id);
    must(PossibleResultSchema::new(
        artifact(id),
        vec![ResultTarget::Gap {
            objective: target.clone(),
        }],
        vec![ResultBranch {
            result_id: artifact(&format!("{id}-branch")),
            value: PossibleResultValue::Unknown {
                reason: "outcome not yet observed".to_owned(),
            },
            updates: vec![ResultUpdate::Gap {
                objective: target,
                meaning: GapUpdateMeaning::RemainsOpen,
            }],
        }],
    ))
}

fn prediction(id: &str) -> RivalPredictionRef {
    RivalPredictionRef {
        prediction_id: artifact(id),
        prediction_digest: digest(id),
    }
}

fn claim(id: &str) -> MaterialClaimRef {
    MaterialClaimRef {
        claim_id: id.to_owned(),
        proposition: must(PropositionId::new("prop-1")),
        claim_preimage_digest: digest(id),
    }
}

fn rival_target(left: &str, right: &str) -> AffordanceTarget {
    AffordanceTarget::RivalPredictions {
        left: prediction(left),
        right: prediction(right),
    }
}

fn gap_target(id: &str) -> AffordanceTarget {
    AffordanceTarget::EvidenceGap { claim: claim(id) }
}

fn assumption_target(id: &str) -> AffordanceTarget {
    AffordanceTarget::Assumption {
        assumption: ConditionAssumptionRef {
            assumption_id: id.to_owned(),
            assumption_digest: digest(id),
        },
        claim: None,
    }
}

fn objective_target(id: &str) -> AffordanceTarget {
    AffordanceTarget::Objective {
        objective: objective(id),
    }
}

fn descriptor_params(id: &str, target: AffordanceTarget) -> InquiryAffordanceDescriptorParams {
    InquiryAffordanceDescriptorParams {
        affordance_id: artifact(id),
        kind: AffordanceKind::EvidenceInspection,
        target,
        applicability: bounds(),
        owner: ProbeOwnerRef::Unavailable {
            reason: "owner withheld for planning".to_owned(),
        },
        result_schema: result_schema(&format!("{id}-schema"), &format!("{id}-objective")),
        information: InformationDimension::High {
            detail: "splits the named disagreement".to_owned(),
        },
        cost: CostDimension::Low {
            detail: "one retained read".to_owned(),
        },
        latency: LatencyDimension::Interactive {
            detail: "answered within the attempt".to_owned(),
        },
        context: ContextDimension::Narrow {
            detail: "needs the named claim only".to_owned(),
        },
        resource: ResourceDimension::Bounded {
            detail: "one source handle".to_owned(),
        },
        privacy: PrivacyDimension::Contained {
            detail: "retained material only".to_owned(),
        },
        consent: ConsentDimension::Granted {
            detail: "planning consent supplied".to_owned(),
        },
        authority: AuthorityDimension::Permitted {
            detail: "standing supplied".to_owned(),
        },
        effect: EffectDimension::ObservableOnly {
            detail: "reads retained bytes".to_owned(),
        },
        reversibility: ReversibilityDimension::Reversible {
            detail: "no state touched".to_owned(),
        },
        feasibility: FeasibilityDimension::Feasible {
            detail: "channel available".to_owned(),
        },
        attention: HumanAttentionDimension::Unneeded {
            detail: "no human required".to_owned(),
        },
    }
}

fn descriptor(id: &str, target: AffordanceTarget) -> InquiryAffordanceDescriptor {
    must(InquiryAffordanceDescriptor::new(descriptor_params(
        id, target,
    )))
}

fn affordance_set(descriptors: Vec<InquiryAffordanceDescriptor>) -> InquiryAffordanceSet {
    must(InquiryAffordanceSet::new(InquiryAffordanceSetParams {
        set_id: artifact("affordance-set-1"),
        task_id: task(),
        scope: "scope-1".to_owned(),
        state_fence: fence(),
        descriptors,
    }))
}

fn limits(candidates: Option<u64>) -> BudgetLimits {
    BudgetLimits {
        input_bytes: Some(1024),
        output_bytes: Some(1024),
        source_width: Some(8),
        reference_width: Some(8),
        model_calls: Some(4),
        attempts: Some(2),
        candidates,
        wall_ms: Some(10_000),
        work_fan_out: Some(2),
        report_bytes: Some(1024),
        max_stu: Some(100),
    }
}

fn plan_for(descriptors: Vec<InquiryAffordanceDescriptor>, candidates: Option<u64>) -> ProbePlan {
    let bundle = bundle();
    let draft = draft();
    let rivals = rivals();
    let affordances = affordance_set(descriptors);
    let limits = limits(candidates);
    must(ProbePlan::new(ProbePlanParams {
        plan_id: artifact("plan-1"),
        bundle: &bundle,
        draft: &draft,
        rivals: &rivals,
        affordances: &affordances,
        limits: &limits,
    }))
}

// WORK_UNIT_CASE: 610/2
#[test]
fn multi_rival_result_matrix() {
    let plan = plan_for(
        vec![
            descriptor("aff-matrix-a", rival_target("pred-a-left", "pred-a-right")),
            descriptor("aff-matrix-b", rival_target("pred-b-left", "pred-b-right")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    let mut endpoints = Vec::new();
    let mut schema_ids = Vec::new();
    for probe in &plan.probes {
        match &probe.target {
            ProbeTarget::RivalDisagreement { left, right } => {
                assert_ne!(left.prediction_id, right.prediction_id);
                endpoints.push((
                    left.prediction_id.as_str().to_owned(),
                    right.prediction_id.as_str().to_owned(),
                ));
            }
            other => panic!("matrix probe must name a disagreement, got {other:?}"),
        }
        must(probe.result_schema.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        schema_ids.push(probe.result_schema.result_schema_id.as_str().to_owned());
    }
    endpoints.sort();
    assert_eq!(
        endpoints,
        vec![
            ("pred-a-left".to_owned(), "pred-a-right".to_owned()),
            ("pred-b-left".to_owned(), "pred-b-right".to_owned()),
        ]
    );
    assert_eq!(schema_ids.len(), 2);
    assert_ne!(schema_ids[0], schema_ids[1]);
}

// WORK_UNIT_CASE: 610/3
#[test]
fn objective_result_affordance_disposition_vocabulary() {
    let kinds = [
        AffordanceKind::EvidenceInspection,
        AffordanceKind::RecordLookup,
        AffordanceKind::ConsistencyCheck,
        AffordanceKind::HumanConsultation,
        AffordanceKind::CrossReference,
    ];
    assert_eq!(kinds.len(), 5);
    let mut descriptors = Vec::new();
    for (index, kind) in kinds.into_iter().enumerate() {
        let target = match index {
            0 => rival_target("pred-v-left", "pred-v-right"),
            1 => gap_target("claim-v"),
            2 => assumption_target("assume-v"),
            _ => objective_target(&format!("objective-v-{index}")),
        };
        let mut params = descriptor_params(&format!("aff-vocab-{index}"), target);
        params.kind = kind;
        descriptors.push(must(InquiryAffordanceDescriptor::new(params)));
    }
    let plan = plan_for(descriptors, Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 5);

    let mut seen_rival = false;
    let mut seen_gap = false;
    let mut seen_assumption = false;
    let mut seen_objective = false;
    for probe in &plan.probes {
        match &probe.target {
            ProbeTarget::RivalDisagreement { .. } => seen_rival = true,
            ProbeTarget::EvidenceUnknown { .. } => seen_gap = true,
            ProbeTarget::AssumptionUnknown { .. } => seen_assumption = true,
            ProbeTarget::ObjectiveUnknown { .. } => seen_objective = true,
        }
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.expected_discrimination.trim().is_empty());
    }
    assert!(seen_rival && seen_gap && seen_assumption && seen_objective);

    let omission_kinds = [
        OmissionKind::Unprobeable,
        OmissionKind::OverBudget,
        OmissionKind::AuthorityBlocked,
    ];
    assert_eq!(omission_kinds.len(), 3);
    assert!(omission_kinds.windows(2).all(|pair| pair[0] != pair[1]));
    assert_ne!(omission_kinds[0], omission_kinds[2]);
}

// WORK_UNIT_CASE: 610/6
#[test]
fn vague_no_gain_objective_is_unprobeable() {
    let mut vague_params = descriptor_params("aff-vague", gap_target("claim-vague"));
    vague_params.information = InformationDimension::NoGain {
        reason: "curiosity read with no expected gain".to_owned(),
    };
    let vague = must(InquiryAffordanceDescriptor::new(vague_params));
    assert!(!vague.information.has_expected_gain());

    let mut withheld_params = descriptor_params("aff-withheld", gap_target("claim-withheld"));
    withheld_params.information = InformationDimension::Unavailable {
        reason: "gain characterization withheld".to_owned(),
    };
    let withheld = must(InquiryAffordanceDescriptor::new(withheld_params));
    assert!(!withheld.information.has_expected_gain());

    let plan = plan_for(vec![vague, withheld], Some(16));
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 2);
    for omission in &plan.omissions {
        assert_eq!(omission.kind, OmissionKind::Unprobeable);
        must(omission.target.validate());
        assert!(
            omission.reason.contains("NO_GAIN") || omission.reason.contains("UNAVAILABLE"),
            "vague objective must cite the information gate, got {}",
            omission.reason
        );
    }
}

// WORK_UNIT_CASE: 610/7
#[test]
fn exact_evidence_verifier_gap_objective_is_plannable() {
    let gap = descriptor("aff-exact-gap", gap_target("claim-exact"));
    let objective_descriptor =
        descriptor("aff-exact-objective", objective_target("objective-exact"));
    let plan = plan_for(vec![gap, objective_descriptor], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    let mut seen_gap = false;
    let mut seen_objective = false;
    for probe in &plan.probes {
        match &probe.target {
            ProbeTarget::EvidenceUnknown { claim } => {
                assert_eq!(claim.claim_id.as_str(), "claim-exact");
                seen_gap = true;
            }
            ProbeTarget::ObjectiveUnknown { objective } => {
                assert_eq!(objective.objective_id.as_str(), "objective-exact");
                seen_objective = true;
            }
            other => panic!("exact gap probe must name a gap or objective, got {other:?}"),
        }
        must(probe.result_schema.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.expected_discrimination.trim().is_empty());
    }
    assert!(seen_gap && seen_objective);
}

// WORK_UNIT_CASE: 610/8
#[test]
fn out_of_scope_descriptor_is_unprobeable() {
    let mut scoped_params = descriptor_params("aff-foreign", gap_target("claim-foreign"));
    scoped_params.applicability = bounds_scoped("scope-other");
    let foreign = must(InquiryAffordanceDescriptor::new(scoped_params));
    let local = descriptor("aff-local", gap_target("claim-local"));
    let plan = plan_for(vec![foreign, local], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.probes[0].probe_id.as_str(), "aff-local");
    assert_eq!(plan.omissions.len(), 1);
    let omission = &plan.omissions[0];
    assert_eq!(omission.kind, OmissionKind::Unprobeable);
    assert_eq!(omission.affordance.affordance_id.as_str(), "aff-foreign");
    assert!(omission.reason.contains("applicability scope"));
}

// WORK_UNIT_CASE: 610/9
#[test]
fn bounded_closed_result_schema_is_plannable() {
    let target_objective = objective("objective-closed");
    let targets = vec![ResultTarget::Gap {
        objective: target_objective.clone(),
    }];
    let branches = vec![
        ResultBranch {
            result_id: artifact("closed-branch-addressed"),
            value: PossibleResultValue::Unknown {
                reason: "outcome not yet observed".to_owned(),
            },
            updates: vec![ResultUpdate::Gap {
                objective: target_objective.clone(),
                meaning: GapUpdateMeaning::Addressed,
            }],
        },
        ResultBranch {
            result_id: artifact("closed-branch-open"),
            value: PossibleResultValue::Unknown {
                reason: "outcome not yet observed".to_owned(),
            },
            updates: vec![ResultUpdate::Gap {
                objective: target_objective.clone(),
                meaning: GapUpdateMeaning::RemainsOpen,
            }],
        },
    ];
    let schema = must(PossibleResultSchema::new(
        artifact("closed-schema"),
        targets,
        branches,
    ));
    must(schema.validate());
    assert_eq!(schema.targets.len(), 1);
    assert_eq!(schema.branches.len(), 2);
    assert!(!schema.digest.trim().is_empty());

    let mut params = descriptor_params("aff-closed", gap_target("claim-closed"));
    params.result_schema = schema.clone();
    let closed = must(InquiryAffordanceDescriptor::new(params));
    let plan = plan_for(vec![closed], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert!(plan.omissions.is_empty());
    let probe = &plan.probes[0];
    must(probe.result_schema.validate());
    assert_eq!(probe.result_schema.digest, schema.digest);
    assert_eq!(probe.result_schema.branches.len(), 2);
    assert_ne!(
        probe.result_schema.branches[0].result_id,
        probe.result_schema.branches[1].result_id
    );
}

// WORK_UNIT_CASE: 610/10
#[test]
fn open_unbounded_result_space_is_rejected() {
    let target_objective = objective("objective-open");
    let targets = vec![ResultTarget::Gap {
        objective: target_objective.clone(),
    }];
    let closed_branch = ResultBranch {
        result_id: artifact("open-branch"),
        value: PossibleResultValue::Unknown {
            reason: "outcome not yet observed".to_owned(),
        },
        updates: vec![ResultUpdate::Gap {
            objective: target_objective.clone(),
            meaning: GapUpdateMeaning::RemainsOpen,
        }],
    };

    assert!(
        PossibleResultSchema::new(
            artifact("open-empty-targets"),
            Vec::new(),
            vec![closed_branch.clone()]
        )
        .is_err(),
        "empty target denominator must fail closed"
    );
    assert!(
        PossibleResultSchema::new(artifact("open-empty-branches"), targets.clone(), Vec::new())
            .is_err(),
        "empty branch set must fail closed"
    );
    assert!(
        PossibleResultSchema::new(
            artifact("open-incomplete-cover"),
            targets.clone(),
            vec![ResultBranch {
                result_id: artifact("open-incomplete"),
                value: PossibleResultValue::Unknown {
                    reason: "outcome not yet observed".to_owned(),
                },
                updates: Vec::new(),
            }],
        )
        .is_err(),
        "branch without full target cover must fail closed"
    );
    assert!(
        PossibleResultSchema::new(
            artifact("open-duplicate-id"),
            targets.clone(),
            vec![closed_branch.clone(), closed_branch.clone()],
        )
        .is_err(),
        "duplicate result identity must fail closed"
    );
    let foreign_objective = objective("objective-foreign");
    assert!(
        PossibleResultSchema::new(
            artifact("open-undeclared-target"),
            targets.clone(),
            vec![ResultBranch {
                result_id: artifact("open-foreign"),
                value: PossibleResultValue::Unknown {
                    reason: "outcome not yet observed".to_owned(),
                },
                updates: vec![ResultUpdate::Gap {
                    objective: foreign_objective,
                    meaning: GapUpdateMeaning::RemainsOpen,
                }],
            }],
        )
        .is_err(),
        "update to an undeclared target must fail closed"
    );
}

// WORK_UNIT_CASE: 610/11
#[test]
fn identical_updates_for_all_outcomes_are_unprobeable() {
    fn two_branch_schema(
        id: &str,
        objective_id: &str,
        first: GapUpdateMeaning,
        second: GapUpdateMeaning,
    ) -> PossibleResultSchema {
        let target = objective(objective_id);
        must(PossibleResultSchema::new(
            artifact(id),
            vec![ResultTarget::Gap {
                objective: target.clone(),
            }],
            vec![
                ResultBranch {
                    result_id: artifact(&format!("{id}-a")),
                    value: PossibleResultValue::Unknown {
                        reason: "outcome not yet observed".to_owned(),
                    },
                    updates: vec![ResultUpdate::Gap {
                        objective: target.clone(),
                        meaning: first,
                    }],
                },
                ResultBranch {
                    result_id: artifact(&format!("{id}-b")),
                    value: PossibleResultValue::Unknown {
                        reason: "outcome not yet observed".to_owned(),
                    },
                    updates: vec![ResultUpdate::Gap {
                        objective: target,
                        meaning: second,
                    }],
                },
            ],
        ))
    }

    let identical_schema = two_branch_schema(
        "identical-schema",
        "objective-identical",
        GapUpdateMeaning::RemainsOpen,
        GapUpdateMeaning::RemainsOpen,
    );
    must(identical_schema.validate());
    let mut identical_params = descriptor_params("aff-identical", gap_target("claim-identical"));
    identical_params.result_schema = identical_schema;
    let identical = must(InquiryAffordanceDescriptor::new(identical_params));

    let identical_plan = plan_for(vec![identical], Some(16));
    must(identical_plan.validate());
    assert!(
        identical_plan.probes.is_empty(),
        "identical updates cannot plan a probe"
    );
    assert_eq!(identical_plan.omissions.len(), 1);
    assert_eq!(identical_plan.omissions[0].kind, OmissionKind::Unprobeable);
    assert!(
        identical_plan.omissions[0].reason.contains("identical"),
        "identical-updates gap must cite the discrimination gate, got {}",
        identical_plan.omissions[0].reason
    );

    let split_schema = two_branch_schema(
        "split-schema",
        "objective-split",
        GapUpdateMeaning::Addressed,
        GapUpdateMeaning::RemainsOpen,
    );
    must(split_schema.validate());
    let mut split_params = descriptor_params("aff-split", gap_target("claim-split"));
    split_params.result_schema = split_schema;
    let split = must(InquiryAffordanceDescriptor::new(split_params));

    let split_plan = plan_for(vec![split], Some(16));
    must(split_plan.validate());
    assert_eq!(split_plan.probes.len(), 1);
    assert!(split_plan.omissions.is_empty());
    let probe = &split_plan.probes[0];
    must(probe.result_schema.validate());
    assert_eq!(probe.result_schema.branches.len(), 2);
    assert_ne!(
        probe.result_schema.branches[0].updates, probe.result_schema.branches[1].updates,
        "discriminative probe must keep two differently updating outcomes"
    );
}
