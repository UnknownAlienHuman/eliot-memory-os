//! Executable work-unit coverage for the live #610 denominator. Each case is
//! mapped to behavior owned by this pure planner or, where the public A-03
//! contract has no required field, to a fail-closed bounded gap recorded in
//! the delivery report. Ready candidates remain inert declarations: no
//! provider, route, credential, process, Store, execution, result grading,
//! rival resolution, promotion, or Finish path is present.
//!
//! The planner consumes the exact public contract types. It validates closed
//! result matrices, rejects confirmation-only or unrelated updates, gates
//! failed/unknown mandatory safety dimensions, preserves every advisory vector,
//! coalesces only full semantic equivalents, and admits only the explicit
//! candidate bound. Per-candidate usage, causal controls/confounders,
//! cleanup/rollback declarations, and objective-disposition tables are not
//! representable by the current owner contracts; the tests keep those paths
//! conservative and the delivery report names the exact handoffs.
//!
//! Documentation route receipt: sha256:a4bf61db4fa1ed897c719fc9bd7d28b2e0310d3de61b79ced7690462d46c98df.
//! Documentation read receipt: sha256:9af8ac62604f7eae0d802e25407068fc1996af4ea5c266149a6019feaff5041a.
//! Verified bundle SHA-256: 58c54ca3902fc57d0d319bb8b962cd35b9652579133c87dffae6265bac4705dd.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

mod support;

use std::num::NonZeroU64;

use eliot_dreamer_contracts::{
    AffordanceKind, AffordanceTarget, AuthorityDimension, BudgetDimension, BudgetLimits,
    BundleCompleteness, ConditionAssumptionRef, ConsentDimension, ContextDimension, CostDimension,
    DreamInputBundle, EffectDimension, FeasibilityDimension, GapUpdateMeaning,
    HumanAttentionDimension, InformationDimension, InquiryAffordanceDescriptor,
    InquiryAffordanceDescriptorParams, InquiryAffordanceSet, InquiryAffordanceSetParams,
    LatencyDimension, MaterialClaimRef, PossibleResultSchema, PossibleResultValue,
    PrivacyDimension, ProbeObjectiveRef, ProbeOrderingPolicy, ProbeOwnerRef, ResourceDimension,
    ResultBranch, ResultTarget, ResultUpdate, ResultUpdateDiscriminability, ReversibilityDimension,
    RivalCoverageStatus, RivalCoverageSummary, RivalDeclarationSetRef, RivalModelRef,
    RivalModelSet, RivalModelSetParams, RivalPredictionRef, RivalUpdateMeaning,
    ValidatedDreamDraft, ValidationReceipt, canonical_bytes,
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
        validated_input_digest: digest("validator-input"),
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

fn rival_model(id: &str) -> RivalModelRef {
    RivalModelRef {
        model_id: artifact(id),
        model_revision: 1,
        declaration_digest: digest(id),
    }
}

fn result_schema_for_target(id: &str, target: &AffordanceTarget) -> PossibleResultSchema {
    let (targets, branches) = match target {
        AffordanceTarget::RivalPredictions { left, right } => {
            let left_model = rival_model(&format!("{id}-left-model"));
            let right_model = rival_model(&format!("{id}-right-model"));
            let targets = vec![
                ResultTarget::Rival {
                    model: left_model.clone(),
                    prediction: Some(left.clone()),
                },
                ResultTarget::Rival {
                    model: right_model.clone(),
                    prediction: Some(right.clone()),
                },
            ];
            let branch = |result_id: String, left_meaning, right_meaning| ResultBranch {
                result_id: artifact(&result_id),
                value: PossibleResultValue::Unknown {
                    reason: "outcome not yet observed".to_owned(),
                },
                updates: vec![
                    ResultUpdate::Rival {
                        model: left_model.clone(),
                        prediction: Some(left.clone()),
                        meaning: left_meaning,
                    },
                    ResultUpdate::Rival {
                        model: right_model.clone(),
                        prediction: Some(right.clone()),
                        meaning: right_meaning,
                    },
                ],
            };
            (
                targets,
                vec![
                    branch(
                        format!("{id}-branch-left"),
                        RivalUpdateMeaning::Strengthened,
                        RivalUpdateMeaning::Weakened,
                    ),
                    branch(
                        format!("{id}-branch-right"),
                        RivalUpdateMeaning::Weakened,
                        RivalUpdateMeaning::Strengthened,
                    ),
                ],
            )
        }
        AffordanceTarget::EvidenceGap { .. } | AffordanceTarget::Assumption { .. } => {
            let target = objective(&format!("{id}-objective"));
            let branch = |result_id: String, meaning| ResultBranch {
                result_id: artifact(&result_id),
                value: PossibleResultValue::Unknown {
                    reason: "outcome not yet observed".to_owned(),
                },
                updates: vec![ResultUpdate::Gap {
                    objective: target.clone(),
                    meaning,
                }],
            };
            (
                vec![ResultTarget::Gap {
                    objective: target.clone(),
                }],
                vec![
                    branch(
                        format!("{id}-branch-addressed"),
                        GapUpdateMeaning::Addressed,
                    ),
                    branch(format!("{id}-branch-open"), GapUpdateMeaning::RemainsOpen),
                ],
            )
        }
        AffordanceTarget::Objective { objective: target } => {
            let target_for_branches = target.clone();
            let branch = |result_id: String, meaning| ResultBranch {
                result_id: artifact(&result_id),
                value: PossibleResultValue::Unknown {
                    reason: "outcome not yet observed".to_owned(),
                },
                updates: vec![ResultUpdate::Gap {
                    objective: target_for_branches.clone(),
                    meaning,
                }],
            };
            (
                vec![ResultTarget::Gap {
                    objective: target_for_branches.clone(),
                }],
                vec![
                    branch(
                        format!("{id}-branch-addressed"),
                        GapUpdateMeaning::Addressed,
                    ),
                    branch(format!("{id}-branch-open"), GapUpdateMeaning::RemainsOpen),
                ],
            )
        }
    };
    support::schema_with_acceptance(id, targets, branches)
}

fn gap_matrix(
    id: &str,
    objective_ref: ProbeObjectiveRef,
    meanings: &[GapUpdateMeaning],
) -> PossibleResultSchema {
    let target = ResultTarget::Gap {
        objective: objective_ref.clone(),
    };
    let branches = meanings
        .iter()
        .enumerate()
        .map(|(index, meaning)| ResultBranch {
            result_id: artifact(&format!("{id}-branch-{index}")),
            value: PossibleResultValue::Unknown {
                reason: "outcome not yet observed".to_owned(),
            },
            updates: vec![ResultUpdate::Gap {
                objective: objective_ref.clone(),
                meaning: *meaning,
            }],
        })
        .collect();
    support::schema_with_acceptance(id, vec![target], branches)
}

fn unknown_update_matrix(
    id: &str,
    objective_ref: ProbeObjectiveRef,
    reasons: &[&str],
) -> PossibleResultSchema {
    let target = ResultTarget::Gap {
        objective: objective_ref.clone(),
    };
    let branches = reasons
        .iter()
        .enumerate()
        .map(|(index, reason)| ResultBranch {
            result_id: artifact(&format!("{id}-branch-{index}")),
            value: PossibleResultValue::Unknown {
                reason: "outcome not yet observed".to_owned(),
            },
            updates: vec![ResultUpdate::Unknown {
                target: target.clone(),
                reason: (*reason).to_owned(),
            }],
        })
        .collect();
    must(PossibleResultSchema::new(
        artifact(id),
        vec![target],
        branches,
    ))
}

fn descriptor_with_schema(
    id: &str,
    target: AffordanceTarget,
    result_schema: PossibleResultSchema,
) -> InquiryAffordanceDescriptor {
    let mut params = descriptor_params(id, target);
    params.result_schema = result_schema;
    let target = params.target.clone();
    let descriptor = must(InquiryAffordanceDescriptor::new(params));
    match support::ready_semantics(&target) {
        Some(semantics) => must(descriptor.with_planning_semantics(semantics)),
        None => descriptor,
    }
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
    AffordanceTarget::Objective {
        objective: objective(id),
    }
}

fn evidence_gap_target(id: &str) -> AffordanceTarget {
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
        target: target.clone(),
        applicability: bounds(),
        owner: ProbeOwnerRef::Unavailable {
            reason: "owner withheld for planning".to_owned(),
        },
        result_schema: result_schema_for_target(&format!("{id}-schema"), &target),
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
    descriptor_from_params(descriptor_params(id, target))
}

fn descriptor_from_params(
    params: InquiryAffordanceDescriptorParams,
) -> InquiryAffordanceDescriptor {
    let target = params.target.clone();
    let descriptor = must(InquiryAffordanceDescriptor::new(params));
    let ready_target = matches!(
        &target,
        AffordanceTarget::RivalPredictions { .. } | AffordanceTarget::Objective { .. }
    );
    if ready_target && let Some(semantics) = support::ready_semantics(&target) {
        return must(descriptor.with_planning_semantics(semantics));
    }
    descriptor
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

fn ordering_policy() -> ProbeOrderingPolicy {
    must(ProbeOrderingPolicy::v1())
}

fn plan_for(descriptors: Vec<InquiryAffordanceDescriptor>, candidates: Option<u64>) -> ProbePlan {
    let bundle = bundle();
    let draft = draft();
    let rivals = rivals();
    let affordances = affordance_set(descriptors);
    let limits = limits(candidates);
    let policy = ordering_policy();
    must(ProbePlan::new(ProbePlanParams {
        plan_id: artifact("plan-1"),
        bundle: &bundle,
        draft: &draft,
        rivals: &rivals,
        affordances: &affordances,
        limits: &limits,
        policy: &policy,
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
            1 => evidence_gap_target("claim-v"),
            2 => assumption_target("assume-v"),
            _ => objective_target(&format!("objective-v-{index}")),
        };
        let mut params = descriptor_params(&format!("aff-vocab-{index}"), target);
        params.kind = kind;
        descriptors.push(descriptor_from_params(params));
    }
    let plan = plan_for(descriptors, Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 3);
    assert_eq!(plan.omissions.len(), 2);

    let mut seen_rival = false;
    let mut seen_objective = false;
    for probe in &plan.probes {
        match &probe.target {
            ProbeTarget::RivalDisagreement { .. } => seen_rival = true,
            ProbeTarget::ObjectiveUnknown { .. } => seen_objective = true,
            other => panic!("only canonically linked targets may be ready, got {other:?}"),
        }
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.expected_discrimination.trim().is_empty());
    }
    assert!(seen_rival && seen_objective);
    assert!(
        plan.omissions
            .iter()
            .any(|omission| matches!(omission.target, ProbeTarget::EvidenceUnknown { .. }))
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| matches!(omission.target, ProbeTarget::AssumptionUnknown { .. }))
    );

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
fn evidence_gap_without_exact_objective_linkage_is_unprobeable() {
    let gap = descriptor("aff-exact-gap", evidence_gap_target("claim-exact"));
    let objective_descriptor =
        descriptor("aff-exact-objective", objective_target("objective-exact"));
    let plan = plan_for(vec![gap, objective_descriptor], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.omissions.len(), 1);

    let objective_probe = &plan.probes[0];
    match &objective_probe.target {
        ProbeTarget::ObjectiveUnknown { objective } => {
            assert_eq!(objective.objective_id.as_str(), "objective-exact");
        }
        other => panic!("canonically linked objective must remain plannable, got {other:?}"),
    }
    must(objective_probe.result_schema.validate());
    assert_eq!(
        objective_probe.probe_id,
        objective_probe.affordance.affordance_id
    );
    assert!(!objective_probe.expected_discrimination.trim().is_empty());

    let omission = &plan.omissions[0];
    assert_eq!(omission.affordance.affordance_id.as_str(), "aff-exact-gap");
    assert_eq!(omission.kind, OmissionKind::Unprobeable);
    assert!(
        omission
            .reason
            .contains("exact canonical objective linkage")
    );
    match &omission.target {
        ProbeTarget::EvidenceUnknown { claim } => {
            assert_eq!(claim.claim_id.as_str(), "claim-exact");
        }
        other => panic!("unlinked evidence gap must remain typed, got {other:?}"),
    }
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
    let schema = support::schema_with_acceptance("closed-schema", targets, branches);
    must(schema.validate());
    assert_eq!(schema.targets.len(), 1);
    assert_eq!(schema.branches.len(), 2);
    assert!(!schema.digest.trim().is_empty());

    let mut params = descriptor_params("aff-closed", objective_target("objective-closed"));
    params.result_schema = schema.clone();
    let target = params.target.clone();
    let closed = must(InquiryAffordanceDescriptor::new(params));
    let closed = must(closed.with_planning_semantics(
        support::ready_semantics(&target).expect("objective target semantics"),
    ));
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

// WORK_UNIT_CASE: 610/17
#[test]
fn typed_affordance_unknown_unavailable_states_gate_closed() {
    let kinds = [
        AffordanceKind::EvidenceInspection,
        AffordanceKind::RecordLookup,
        AffordanceKind::ConsistencyCheck,
        AffordanceKind::HumanConsultation,
        AffordanceKind::CrossReference,
    ];
    assert_eq!(kinds.len(), 5);

    let mut unknown_feas_params =
        descriptor_params("aff-unknown-feas", gap_target("claim-unk-feas"));
    unknown_feas_params.feasibility = FeasibilityDimension::Unknown {
        reason: "channel state not yet characterized".to_owned(),
    };
    let unknown_feas = must(InquiryAffordanceDescriptor::new(unknown_feas_params));
    assert!(!unknown_feas.feasibility.is_feasible());
    assert!(!unknown_feas.feasibility.is_known());

    let mut unavailable_feas_params =
        descriptor_params("aff-unavail-feas", gap_target("claim-unavail-feas"));
    unavailable_feas_params.feasibility = FeasibilityDimension::Unavailable {
        reason: "channel retired".to_owned(),
    };
    let unavailable_feas = must(InquiryAffordanceDescriptor::new(unavailable_feas_params));
    assert!(!unavailable_feas.feasibility.is_feasible());

    let mut unavailable_info_params =
        descriptor_params("aff-unavail-info", gap_target("claim-unavail-info"));
    unavailable_info_params.information = InformationDimension::Unavailable {
        reason: "gain characterization withheld".to_owned(),
    };
    let unavailable_info = must(InquiryAffordanceDescriptor::new(unavailable_info_params));
    assert!(!unavailable_info.information.has_expected_gain());

    let mut unknown_auth_params =
        descriptor_params("aff-unknown-auth", gap_target("claim-unknown-auth"));
    unknown_auth_params.authority = AuthorityDimension::Unknown {
        reason: "standing not yet attested".to_owned(),
    };
    let unknown_auth = must(InquiryAffordanceDescriptor::new(unknown_auth_params));
    assert!(!unknown_auth.authority.is_permitted());
    assert!(!unknown_auth.authority.is_known());

    let mut unavailable_auth_params =
        descriptor_params("aff-unavail-auth", gap_target("claim-unavail-auth"));
    unavailable_auth_params.authority = AuthorityDimension::Unavailable {
        reason: "standing source withheld".to_owned(),
    };
    let unavailable_auth = must(InquiryAffordanceDescriptor::new(unavailable_auth_params));
    assert!(!unavailable_auth.authority.is_permitted());

    let mut unknown_consent_params =
        descriptor_params("aff-unknown-consent", gap_target("claim-unknown-consent"));
    unknown_consent_params.consent = ConsentDimension::Unknown {
        reason: "consent state not yet supplied".to_owned(),
    };
    let unknown_consent = must(InquiryAffordanceDescriptor::new(unknown_consent_params));
    assert!(!unknown_consent.consent.is_granted());
    assert!(!unknown_consent.consent.is_known());

    let plan = plan_for(
        vec![
            unknown_feas,
            unavailable_feas,
            unavailable_info,
            unknown_auth,
            unavailable_auth,
            unknown_consent,
        ],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 6);

    let mut unprobeable = 0;
    let mut blocked = 0;
    for omission in &plan.omissions {
        must(omission.target.validate());
        match omission.kind {
            OmissionKind::Unprobeable => {
                unprobeable += 1;
                assert!(
                    omission.reason.contains("UNKNOWN") || omission.reason.contains("UNAVAILABLE"),
                    "unprobeable gap must cite the unknown/unavailable gate, got {}",
                    omission.reason
                );
            }
            OmissionKind::AuthorityBlocked => {
                blocked += 1;
                assert!(
                    omission.reason.contains("UNKNOWN") || omission.reason.contains("UNAVAILABLE"),
                    "authority gap must cite the unknown/unavailable gate, got {}",
                    omission.reason
                );
            }
            OmissionKind::OverBudget => {
                panic!("unknown/unavailable gating must not mint over-budget gaps");
            }
        }
    }
    assert_eq!(unprobeable, 3);
    assert_eq!(blocked, 3);
}

// WORK_UNIT_CASE: 610/21
#[test]
fn safe_read_only_candidate_plans_candidate_only() {
    let mut safe_params = descriptor_params("aff-safe-read", gap_target("claim-safe"));
    safe_params.effect = EffectDimension::SideEffectFree {
        detail: "reads retained bytes only".to_owned(),
    };
    safe_params.reversibility = ReversibilityDimension::Reversible {
        detail: "no state touched".to_owned(),
    };
    safe_params.privacy = PrivacyDimension::Contained {
        detail: "retained material only".to_owned(),
    };
    safe_params.authority = AuthorityDimension::Permitted {
        detail: "standing supplied".to_owned(),
    };
    safe_params.consent = ConsentDimension::Granted {
        detail: "planning consent supplied".to_owned(),
    };
    safe_params.feasibility = FeasibilityDimension::Feasible {
        detail: "channel available".to_owned(),
    };
    let safe = descriptor_from_params(safe_params);
    assert!(safe.effect.is_side_effect_free());
    assert!(safe.privacy.is_contained());
    assert!(safe.reversibility.is_reversible());
    assert!(safe.authority.is_permitted());
    assert!(safe.consent.is_granted());
    assert!(safe.feasibility.is_feasible());

    let plan = plan_for(vec![safe], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert!(plan.omissions.is_empty());

    let probe = &plan.probes[0];
    assert_eq!(probe.probe_id.as_str(), "aff-safe-read");
    assert_eq!(probe.rank, 0);
    assert_eq!(probe.probe_id, probe.affordance.affordance_id);
    assert!(probe.merged_affordances.is_empty());
    assert!(!probe.expected_discrimination.trim().is_empty());
    assert!(probe.expected_discrimination.contains("claim-safe"));
    must(probe.result_schema.validate());
    must(probe.dimensions.validate());
    match &probe.dimensions.effect {
        EffectDimension::SideEffectFree { detail } => {
            assert_eq!(detail.as_str(), "reads retained bytes only");
        }
        other => panic!("safe probe must preserve its effect vector, got {other:?}"),
    }
    match &probe.dimensions.authority {
        AuthorityDimension::Permitted { detail } => {
            assert_eq!(detail.as_str(), "standing supplied");
        }
        other => panic!("safe probe must preserve its authority vector, got {other:?}"),
    }
    match &probe.dimensions.privacy {
        PrivacyDimension::Contained { detail } => {
            assert_eq!(detail.as_str(), "retained material only");
        }
        other => panic!("safe probe must preserve its privacy vector, got {other:?}"),
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/32
#[test]
fn explicit_lexicographic_order_with_stable_tie_break() {
    let mut costly_params = descriptor_params("aff-lex-costly", gap_target("claim-lex-costly"));
    costly_params.information = InformationDimension::High {
        detail: "splits the named disagreement".to_owned(),
    };
    costly_params.cost = CostDimension::High {
        detail: "wide retained scan".to_owned(),
    };
    let costly = descriptor_from_params(costly_params);

    let mut cheap_params = descriptor_params("aff-lex-cheap", gap_target("claim-lex-cheap"));
    cheap_params.information = InformationDimension::Low {
        detail: "weak split of the gap".to_owned(),
    };
    cheap_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    let cheap = descriptor_from_params(cheap_params);

    let mut unknown_params = descriptor_params("aff-lex-unknown", gap_target("claim-lex-unknown"));
    unknown_params.information = InformationDimension::Unknown {
        reason: "gain not yet characterized".to_owned(),
    };
    unknown_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    let unknown = descriptor_from_params(unknown_params);
    assert!(!unknown.information.has_expected_gain());
    let plan = plan_for(
        vec![
            cheap,
            unknown,
            descriptor("aff-lex-tie-b", gap_target("claim-lex-tie-b")),
            costly,
            descriptor("aff-lex-tie-a", gap_target("claim-lex-tie-a")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 5);
    assert!(plan.omissions.is_empty());

    let order: Vec<&str> = plan
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(
        order,
        vec![
            "aff-lex-tie-a",
            "aff-lex-tie-b",
            "aff-lex-costly",
            "aff-lex-cheap",
            "aff-lex-unknown",
        ]
    );
    for (index, probe) in plan.probes.iter().enumerate() {
        let rank = u32::try_from(index).expect("rank must fit u32");
        assert_eq!(probe.rank, rank);
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
    }

    let pos = |id: &str| {
        order
            .iter()
            .position(|probe| *probe == id)
            .expect("probe planned")
    };
    let costly_pos = pos("aff-lex-costly");
    let cheap_pos = pos("aff-lex-cheap");
    assert!(
        costly_pos < cheap_pos,
        "information rank must dominate cost rank: High-information/High-cost precedes Low-information/Negligible-cost, proving no scalar averaging"
    );

    let unknown_pos = pos("aff-lex-unknown");
    assert_eq!(unknown_pos, order.len() - 1);
    assert!(
        cheap_pos < unknown_pos,
        "unknown information must sort after every known gain inside its dimension even with the cheapest cost"
    );

    let tie_a_pos = pos("aff-lex-tie-a");
    let tie_peer_pos = pos("aff-lex-tie-b");
    assert_eq!(tie_peer_pos, tie_a_pos + 1);
    assert!(
        tie_a_pos < tie_peer_pos,
        "equal vectors must break ties by stable affordance identity"
    );

    let costly_probe = &plan.probes[costly_pos];
    match &costly_probe.dimensions.cost {
        CostDimension::High { detail } => assert_eq!(detail.as_str(), "wide retained scan"),
        other => panic!("cost vector must stay visible, got {other:?}"),
    }
    let unknown_probe = &plan.probes[unknown_pos];
    match &unknown_probe.dimensions.information {
        InformationDimension::Unknown { reason } => {
            assert_eq!(reason.as_str(), "gain not yet characterized");
        }
        other => panic!("unknown vector must stay visible, got {other:?}"),
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/36
#[test]
fn irrelevant_input_order_preserves_plan_and_digest() {
    let first = descriptor("aff-order-a", gap_target("claim-order-a"));
    let mut second_params = descriptor_params("aff-order-b", gap_target("claim-order-b"));
    second_params.information = InformationDimension::Low {
        detail: "weak split of the gap".to_owned(),
    };
    let second = descriptor_from_params(second_params);
    let mut third_params = descriptor_params("aff-order-c", gap_target("claim-order-c"));
    third_params.information = InformationDimension::Moderate {
        detail: "partial split of the gap".to_owned(),
    };
    let third = descriptor_from_params(third_params);
    let mut fourth_params = descriptor_params("aff-order-d", gap_target("claim-order-d"));
    fourth_params.information = InformationDimension::Unknown {
        reason: "gain not yet characterized".to_owned(),
    };
    let fourth = descriptor_from_params(fourth_params);

    let forward = plan_for(
        vec![first.clone(), second.clone(), third.clone(), fourth.clone()],
        Some(16),
    );
    let backward = plan_for(
        vec![fourth.clone(), third.clone(), second.clone(), first.clone()],
        Some(16),
    );
    let rotated = plan_for(
        vec![third.clone(), first.clone(), fourth.clone(), second.clone()],
        Some(16),
    );
    must(forward.validate());
    must(backward.validate());
    must(rotated.validate());

    assert_eq!(forward, backward);
    assert_eq!(forward, rotated);
    assert_eq!(forward.digest, backward.digest);
    assert_eq!(forward.digest, rotated.digest);
    assert_eq!(must(forward.compute_digest()), forward.digest);

    let order: Vec<&str> = forward
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(
        order,
        vec!["aff-order-a", "aff-order-c", "aff-order-b", "aff-order-d"]
    );
    let orders: Vec<Vec<&str>> = [&backward, &rotated]
        .iter()
        .map(|plan| {
            plan.probes
                .iter()
                .map(|probe| probe.probe_id.as_str())
                .collect()
        })
        .collect();
    assert_eq!(orders, vec![order.clone(), order]);
    assert!(forward.omissions.is_empty());
}

// WORK_UNIT_CASE: 610/18
#[test]
fn no_shell_value_sdk_payload() {
    let plan = plan_for(
        vec![
            descriptor("aff-typed-a", rival_target("pred-ns-left", "pred-ns-right")),
            descriptor("aff-typed-b", gap_target("claim-typed")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    for probe in &plan.probes {
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.affordance.affordance_digest.trim().is_empty());
        assert!(!probe.expected_discrimination.trim().is_empty());
        for branch in &probe.result_schema.branches {
            match &branch.value {
                PossibleResultValue::Unknown { reason }
                | PossibleResultValue::Unavailable { reason }
                | PossibleResultValue::InstrumentationFailure { reason } => {
                    assert!(!reason.trim().is_empty());
                }
                PossibleResultValue::Observable { .. }
                | PossibleResultValue::Coverage { .. }
                | PossibleResultValue::Verifier { .. } => {
                    must(branch.value.validate());
                }
            }
            assert!(!branch.updates.is_empty());
        }
        let rendered = format!("{probe:?}");
        for token in [
            "shell",
            "Shell",
            "SDK",
            "Sdk",
            "serde_json",
            "Value(",
            "Command",
            "exec(",
        ] {
            assert!(
                !rendered.contains(token),
                "candidate probe must carry no {token} payload, got {rendered}"
            );
        }
    }

    let wire = must(canonical_bytes(&plan));
    let text = String::from_utf8(wire).expect("canonical plan wire must be UTF-8");
    let folded = text.to_lowercase();
    for key in [
        "\"shell\"",
        "\"sdk\"",
        "\"command\"",
        "\"payload\"",
        "\"argv\"",
        "\"serde_json\"",
    ] {
        assert!(
            !folded.contains(key),
            "canonical plan wire must carry no {key} payload key"
        );
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/19
#[test]
fn no_live_route_credential_lease_handle() {
    let plan = plan_for(
        vec![
            descriptor(
                "aff-nolive-a",
                rival_target("pred-nl-left", "pred-nl-right"),
            ),
            descriptor("aff-nolive-b", gap_target("claim-nolive")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    for probe in &plan.probes {
        must(probe.target.validate());
        must(probe.affordance.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.affordance.affordance_digest.trim().is_empty());
        for merged in &probe.merged_affordances {
            assert_ne!(*merged, probe.probe_id);
        }
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        let rendered = format!("{probe:?}");
        for token in [
            "route",
            "credential",
            "Credential",
            "lease",
            "Lease",
            "secret",
            "reservation",
            "Reservation",
            "std::process",
            "process::Command",
        ] {
            // `Permitted`/`RequiresGrant` authority spellings are legitimate
            // candidate-only standing descriptions, not live handles; the
            // lowercase `permit` substring is therefore excluded here.
            assert!(
                !rendered.contains(token),
                "candidate probe must carry no live {token} handle, got {rendered}"
            );
        }
    }

    let wire = must(canonical_bytes(&plan));
    let text = String::from_utf8(wire).expect("canonical plan wire must be UTF-8");
    let folded = text.to_lowercase();
    for key in [
        "\"route\"",
        "\"credential\"",
        "\"lease\"",
        "\"secret\"",
        "\"token\"",
        "\"password\"",
        "\"reservation\"",
        "\"process\"",
        "\"handle\"",
    ] {
        assert!(
            !folded.contains(key),
            "canonical plan wire must carry no live {key} handle key"
        );
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/26
#[test]
fn unknown_cost_capacity_is_not_zero() {
    let mut unknown_cost_params =
        descriptor_params("aff-unknown-cost", gap_target("claim-unknown-cost"));
    unknown_cost_params.cost = CostDimension::Unknown {
        reason: "cost not yet characterized".to_owned(),
    };
    let unknown_cost = descriptor_from_params(unknown_cost_params);
    assert!(!unknown_cost.cost.is_known());
    assert!(!unknown_cost.cost.is_negligible());

    let mut unknown_resource_params =
        descriptor_params("aff-unknown-resource", gap_target("claim-unknown-resource"));
    unknown_resource_params.resource = ResourceDimension::Unknown {
        reason: "capacity not yet characterized".to_owned(),
    };
    let unknown_resource = descriptor_from_params(unknown_resource_params);
    assert!(!unknown_resource.resource.is_known());

    let mut negligible_params =
        descriptor_params("aff-known-cheap", gap_target("claim-known-cheap"));
    negligible_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    let negligible = descriptor_from_params(negligible_params);
    assert!(negligible.cost.is_known());
    assert!(negligible.cost.is_negligible());

    let bounded = descriptor("aff-known-bounded", gap_target("claim-known-bounded"));

    let plan = plan_for(
        vec![unknown_cost, unknown_resource, negligible, bounded],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 4);
    assert!(plan.omissions.is_empty());

    let order: Vec<&str> = plan
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(
        order,
        vec![
            "aff-known-cheap",
            "aff-known-bounded",
            "aff-unknown-resource",
            "aff-unknown-cost",
        ]
    );
    for (index, probe) in plan.probes.iter().enumerate() {
        let rank = u32::try_from(index).expect("rank must fit u32");
        assert_eq!(probe.rank, rank);
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
    }

    let unknown_probe = &plan.probes[3];
    assert_eq!(unknown_probe.probe_id.as_str(), "aff-unknown-cost");
    match &unknown_probe.dimensions.cost {
        CostDimension::Unknown { reason } => {
            assert_eq!(reason.as_str(), "cost not yet characterized");
        }
        other => panic!("unknown cost must stay visible, got {other:?}"),
    }
    let resource_probe = &plan.probes[2];
    assert_eq!(resource_probe.probe_id.as_str(), "aff-unknown-resource");
    match &resource_probe.dimensions.resource {
        ResourceDimension::Unknown { reason } => {
            assert_eq!(reason.as_str(), "capacity not yet characterized");
        }
        other => panic!("unknown capacity must stay visible, got {other:?}"),
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);

    let mut unbudgeted_params = descriptor_params("aff-unbudgeted", gap_target("claim-unbudgeted"));
    unbudgeted_params.cost = CostDimension::Unknown {
        reason: "cost not yet characterized".to_owned(),
    };
    let unbudgeted = plan_for(vec![descriptor_from_params(unbudgeted_params)], None);
    must(unbudgeted.validate());
    assert!(unbudgeted.probes.is_empty());
    assert_eq!(unbudgeted.omissions.len(), 1);
    let gap = &unbudgeted.omissions[0];
    assert_eq!(gap.kind, OmissionKind::OverBudget);
    assert!(
        gap.reason.contains("unknown"),
        "unknown bound must cite the missing limit, got {}",
        gap.reason
    );
    match &gap.dimensions.cost {
        CostDimension::Unknown { .. } => {}
        other => panic!("over-budget gap must preserve the unknown cost, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 610/28
#[test]
fn exact_equivalent_merge_retains_lineage() {
    let target = rival_target("pred-merge-left", "pred-merge-right");
    let shared_schema = result_schema_for_target("merge-shared-schema", &target);
    let later = descriptor_with_schema("aff-merge-b", target.clone(), shared_schema.clone());
    let earlier = descriptor_with_schema("aff-merge-a", target, shared_schema);
    let solo = descriptor("aff-merge-solo", gap_target("claim-merge-solo"));
    let plan = plan_for(vec![later, earlier, solo], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    let order: Vec<&str> = plan
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(order, vec!["aff-merge-a", "aff-merge-solo"]);

    let merged = &plan.probes[0];
    assert_eq!(merged.probe_id.as_str(), "aff-merge-a");
    assert_eq!(merged.rank, 0);
    assert_eq!(merged.affordance.affordance_id.as_str(), "aff-merge-a");
    assert!(!merged.affordance.affordance_digest.trim().is_empty());
    assert_eq!(merged.merged_affordances.len(), 1);
    assert!(
        merged.merged_affordances.contains(&artifact("aff-merge-b")),
        "merge must retain the collapsed lineage, got {:?}",
        merged.merged_affordances
    );
    match &merged.target {
        ProbeTarget::RivalDisagreement { left, right } => {
            assert_eq!(left.prediction_id.as_str(), "pred-merge-left");
            assert_eq!(right.prediction_id.as_str(), "pred-merge-right");
        }
        other => panic!("merged probe must name the shared disagreement, got {other:?}"),
    }
    must(merged.target.validate());
    must(merged.result_schema.validate());
    must(merged.dimensions.validate());
    assert!(!merged.expected_discrimination.trim().is_empty());

    let single = &plan.probes[1];
    assert_eq!(single.probe_id.as_str(), "aff-merge-solo");
    assert_eq!(single.rank, 1);
    assert!(single.merged_affordances.is_empty());
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/30
#[test]
fn cheaper_riskier_alternative_is_retained() {
    let mut cheap_params =
        descriptor_params("aff-tradeoff-cheap", gap_target("claim-tradeoff-cheap"));
    cheap_params.information = InformationDimension::High {
        detail: "splits the named disagreement".to_owned(),
    };
    cheap_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    cheap_params.resource = ResourceDimension::Heavy {
        detail: "retains a wide source working set".to_owned(),
    };
    cheap_params.attention = HumanAttentionDimension::Sustained {
        detail: "requires a sustained operator watch".to_owned(),
    };
    cheap_params.latency = LatencyDimension::Deferred {
        detail: "waits for a bounded retained scan".to_owned(),
    };
    let cheap_risky = descriptor_from_params(cheap_params);

    let mut safe_params = descriptor_params("aff-tradeoff-safe", gap_target("claim-tradeoff-safe"));
    safe_params.information = InformationDimension::High {
        detail: "splits the named disagreement".to_owned(),
    };
    safe_params.cost = CostDimension::High {
        detail: "wide retained scan".to_owned(),
    };
    safe_params.effect = EffectDimension::SideEffectFree {
        detail: "reads retained bytes only".to_owned(),
    };
    safe_params.reversibility = ReversibilityDimension::Reversible {
        detail: "no state touched".to_owned(),
    };
    safe_params.privacy = PrivacyDimension::Contained {
        detail: "retained material only".to_owned(),
    };
    let safe_costly = descriptor_from_params(safe_params);

    let plan = plan_for(vec![safe_costly, cheap_risky], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    let order: Vec<&str> = plan
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(order, vec!["aff-tradeoff-cheap", "aff-tradeoff-safe"]);

    let cheap = &plan.probes[0];
    assert_eq!(cheap.rank, 0);
    assert!(cheap.merged_affordances.is_empty());
    match &cheap.dimensions.cost {
        CostDimension::Negligible { detail } => {
            assert_eq!(detail.as_str(), "trivial retained read");
        }
        other => panic!("cheap trade-off must preserve its cost vector, got {other:?}"),
    }
    match &cheap.dimensions.resource {
        ResourceDimension::Heavy { detail } => {
            assert_eq!(detail.as_str(), "retains a wide source working set");
        }
        other => panic!("cheap trade-off must preserve its resource vector, got {other:?}"),
    }
    match &cheap.dimensions.attention {
        HumanAttentionDimension::Sustained { detail } => {
            assert_eq!(detail.as_str(), "requires a sustained operator watch");
        }
        other => panic!("cheap trade-off must preserve its attention vector, got {other:?}"),
    }
    match &cheap.dimensions.latency {
        LatencyDimension::Deferred { detail } => {
            assert_eq!(detail.as_str(), "waits for a bounded retained scan");
        }
        other => panic!("cheap trade-off must preserve its latency vector, got {other:?}"),
    }
    must(cheap.target.validate());
    must(cheap.result_schema.validate());
    must(cheap.dimensions.validate());

    let safe = &plan.probes[1];
    assert_eq!(safe.rank, 1);
    assert!(safe.merged_affordances.is_empty());
    match &safe.dimensions.cost {
        CostDimension::High { detail } => assert_eq!(detail.as_str(), "wide retained scan"),
        other => panic!("safe trade-off must preserve its cost vector, got {other:?}"),
    }
    match &safe.dimensions.effect {
        EffectDimension::SideEffectFree { detail } => {
            assert_eq!(detail.as_str(), "reads retained bytes only");
        }
        other => panic!("safe trade-off must preserve its effect vector, got {other:?}"),
    }
    must(safe.target.validate());
    must(safe.result_schema.validate());
    must(safe.dimensions.validate());
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/31
#[test]
fn no_scalar_averaged_risk() {
    let mut high_params = descriptor_params("aff-noscalar-high", gap_target("claim-noscalar-high"));
    high_params.information = InformationDimension::High {
        detail: "splits the named disagreement".to_owned(),
    };
    high_params.cost = CostDimension::High {
        detail: "wide retained scan".to_owned(),
    };
    let high = descriptor_from_params(high_params);

    let mut mid_params = descriptor_params("aff-noscalar-mid", gap_target("claim-noscalar-mid"));
    mid_params.information = InformationDimension::Moderate {
        detail: "partial split of the gap".to_owned(),
    };
    mid_params.cost = CostDimension::Moderate {
        detail: "one retained read".to_owned(),
    };
    let mid = descriptor_from_params(mid_params);

    let mut low_params = descriptor_params("aff-noscalar-low", gap_target("claim-noscalar-low"));
    low_params.information = InformationDimension::Low {
        detail: "weak split of the gap".to_owned(),
    };
    low_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    let low = descriptor_from_params(low_params);

    let plan = plan_for(vec![low, mid, high], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 3);
    assert!(plan.omissions.is_empty());

    let order: Vec<&str> = plan
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(
        order,
        vec!["aff-noscalar-high", "aff-noscalar-mid", "aff-noscalar-low"]
    );
    for (index, probe) in plan.probes.iter().enumerate() {
        let rank = u32::try_from(index).expect("rank must fit u32");
        assert_eq!(probe.rank, rank);
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert!(probe.merged_affordances.is_empty());
        let rendered = format!("{probe:?}");
        for token in ["score", "Score", "average", "Average", "utility", "Utility"] {
            assert!(
                !rendered.contains(token),
                "ranked probe must carry no scalar {token}, got {rendered}"
            );
        }
    }

    let wire = must(canonical_bytes(&plan));
    let text = String::from_utf8(wire).expect("canonical plan wire must be UTF-8");
    let folded = text.to_lowercase();
    for key in [
        "\"score\"",
        "\"risk_score\"",
        "\"average\"",
        "\"utility\"",
        "\"expected_value\"",
    ] {
        assert!(
            !folded.contains(key),
            "canonical plan wire must carry no scalar {key} key"
        );
    }
    for key in ["\"information\"", "\"cost\"", "\"effect\""] {
        assert!(
            folded.contains(key),
            "canonical plan wire must preserve the {key} dimension vector"
        );
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/34
#[test]
fn observed_result_evidence_resolution_injection_is_rejected() {
    let plan = plan_for(
        vec![
            descriptor(
                "aff-inject-a",
                rival_target("pred-inj-left", "pred-inj-right"),
            ),
            descriptor("aff-inject-b", gap_target("claim-inject")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    for probe in &plan.probes {
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.result_schema.branches.is_empty());
        for branch in &probe.result_schema.branches {
            match &branch.value {
                PossibleResultValue::Unknown { reason }
                | PossibleResultValue::Unavailable { reason }
                | PossibleResultValue::InstrumentationFailure { reason } => {
                    assert!(!reason.trim().is_empty());
                }
                PossibleResultValue::Observable { .. }
                | PossibleResultValue::Coverage { .. }
                | PossibleResultValue::Verifier { .. } => {
                    must(branch.value.validate());
                }
            }
            assert!(
                !branch.updates.is_empty(),
                "every possible-result branch must carry its update matrix, never a resolution"
            );
        }
    }

    let wire = must(canonical_bytes(&plan));
    let text = String::from_utf8(wire).expect("canonical plan wire must be UTF-8");
    let folded = text.to_lowercase();
    for key in [
        "\"observed_result\"",
        "\"observed\"",
        "\"acquired\"",
        "\"evidence_grade\"",
    ] {
        assert!(
            !folded.contains(key),
            "canonical plan wire must carry no injected {key} evidence key"
        );
    }

    let mut tampered = plan.clone();
    let branch = &mut tampered.probes[0].result_schema.branches[0];
    branch.value = PossibleResultValue::Unknown {
        reason: "injected observed outcome".to_owned(),
    };
    if let Ok(redigest) = tampered.compute_digest() {
        assert_ne!(
            redigest, plan.digest,
            "an injected observed-result rewrite must not preserve the frozen plan digest"
        );
    }
    assert!(
        tampered.validate().is_err(),
        "an injected observed-result rewrite must fail the frozen plan digest"
    );
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/35
#[test]
fn replay_and_changed_input_policy_conflict() {
    let base = plan_for(
        vec![
            descriptor("aff-replay-a", gap_target("claim-replay-a")),
            descriptor("aff-replay-b", gap_target("claim-replay-b")),
        ],
        Some(16),
    );
    must(base.validate());
    assert_eq!(base.probes.len(), 2);
    assert!(base.omissions.is_empty());

    let replay = plan_for(
        vec![
            descriptor("aff-replay-a", gap_target("claim-replay-a")),
            descriptor("aff-replay-b", gap_target("claim-replay-b")),
        ],
        Some(16),
    );
    must(replay.validate());
    assert_eq!(base, replay);
    assert_eq!(base.digest, replay.digest);
    assert_eq!(must(replay.compute_digest()), base.digest);

    let tight = plan_for(
        vec![
            descriptor("aff-replay-a", gap_target("claim-replay-a")),
            descriptor("aff-replay-b", gap_target("claim-replay-b")),
        ],
        Some(1),
    );
    must(tight.validate());
    assert_eq!(tight.probes.len(), 1);
    assert_eq!(tight.omissions.len(), 1);
    assert_eq!(tight.omissions[0].kind, OmissionKind::OverBudget);
    assert_ne!(tight.digest, base.digest);
    assert_ne!(tight, base);

    let altered = plan_for(
        vec![
            descriptor("aff-replay-a", gap_target("claim-replay-a")),
            descriptor("aff-replay-c", gap_target("claim-replay-c")),
        ],
        Some(16),
    );
    must(altered.validate());
    assert_ne!(altered.digest, base.digest);
    assert_ne!(altered, base);

    let mut foreign = base.clone();
    foreign.digest.clone_from(&tight.digest);
    assert!(
        foreign.validate().is_err(),
        "replaying a foreign policy digest against unchanged tables must fail closed"
    );

    let mut reranked = base.clone();
    reranked.probes[0].rank = reranked.probes[0].rank.saturating_add(1);
    assert!(
        reranked.validate().is_err(),
        "a tampered replay with a rewritten rank must fail closed"
    );

    let mut blanked = base.clone();
    blanked.digest = "0".repeat(64);
    assert!(
        blanked.validate().is_err(),
        "a replay with a blanked digest must fail closed"
    );
    assert_eq!(must(base.compute_digest()), base.digest);
}

// WORK_UNIT_CASE: 610/37
#[test]
fn bounded_malformed_inputs_fail_closed_without_panic() {
    malformed_identities_fail_closed();
    malformed_schema_inputs_fail_closed();
    malformed_plan_bindings_fail_closed();
    tampered_and_empty_plans_stay_bounded();
}

fn malformed_identities_fail_closed() {
    for seed in ["", "   ", "bad\u{0}id"] {
        assert!(
            ArtifactId::new(seed).is_err(),
            "malformed artifact identity must fail closed"
        );
        assert!(
            TaskId::new(seed).is_err(),
            "malformed task identity must fail closed"
        );
    }
    assert!(EpochLineageId::new("not-a-uuid").is_err());
    assert!(EpochLineageId::new("").is_err());
}

fn malformed_schema_inputs_fail_closed() {
    assert!(
        ValidityBounds::new("", None, None, "v1", Precision("file".to_owned())).is_err(),
        "blank validity scope must fail closed"
    );
    assert!(
        ValidityBounds::new(
            "scope-1",
            Some(10),
            Some(5),
            "v1",
            Precision("file".to_owned())
        )
        .is_err(),
        "an inverted validity window must fail closed"
    );

    let target_objective = objective("objective-malformed");
    let targets = vec![ResultTarget::Gap {
        objective: target_objective.clone(),
    }];
    let branch = ResultBranch {
        result_id: artifact("malformed-branch"),
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
            artifact("malformed-empty-targets"),
            Vec::new(),
            vec![branch.clone()]
        )
        .is_err(),
        "empty target denominator must fail closed"
    );
    assert!(
        PossibleResultSchema::new(
            artifact("malformed-empty-branches"),
            targets.clone(),
            Vec::new()
        )
        .is_err(),
        "empty branch set must fail closed"
    );
}

fn malformed_plan_bindings_fail_closed() {
    let bundle = bundle();
    let bound_draft = draft();
    let rivals = rivals();
    let bound_limits = limits(Some(16));
    let descriptors = vec![descriptor("aff-malformed", gap_target("claim-malformed"))];

    let wrong_scope = must(InquiryAffordanceSet::new(InquiryAffordanceSetParams {
        set_id: artifact("affordance-set-1"),
        task_id: task(),
        scope: "scope-other".to_owned(),
        state_fence: fence(),
        descriptors: descriptors.clone(),
    }));
    assert!(
        ProbePlan::new(ProbePlanParams {
            plan_id: artifact("plan-1"),
            bundle: &bundle,
            draft: &bound_draft,
            rivals: &rivals,
            affordances: &wrong_scope,
            limits: &bound_limits,
            policy: &ordering_policy(),
        })
        .is_err(),
        "scope disagreement must fail the planner closed"
    );

    let lineage = must(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000"));
    let sequence = must(NonZeroU64::new(2).ok_or("sequence must be non-zero"));
    let drifted_epoch = must(EpochId::new(lineage, sequence));
    let mut drifted = bound_draft.clone();
    drifted.state_fence = StateFence::new(drifted_epoch, ResourceGeneration::genesis());
    let affordances = affordance_set(descriptors);
    assert!(
        ProbePlan::new(ProbePlanParams {
            plan_id: artifact("plan-1"),
            bundle: &bundle,
            draft: &drifted,
            rivals: &rivals,
            affordances: &affordances,
            limits: &bound_limits,
            policy: &ordering_policy(),
        })
        .is_err(),
        "fence disagreement must fail the planner closed"
    );

    let mut over = bound_limits;
    over.candidates = Some(17);
    assert!(
        ProbePlan::new(ProbePlanParams {
            plan_id: artifact("plan-1"),
            bundle: &bundle,
            draft: &bound_draft,
            rivals: &rivals,
            affordances: &affordances,
            limits: &over,
            policy: &ordering_policy(),
        })
        .is_err(),
        "an over-ceiling candidate bound must fail the planner closed"
    );
}

fn tampered_and_empty_plans_stay_bounded() {
    let plan = plan_for(
        vec![descriptor(
            "aff-malformed-ok",
            gap_target("claim-malformed-ok"),
        )],
        Some(16),
    );
    must(plan.validate());
    let mut blanked = plan.clone();
    blanked.digest = "0".repeat(64);
    assert!(blanked.validate().is_err());
    let mut reranked = plan.clone();
    reranked.probes[0].rank = reranked.probes[0].rank.saturating_add(1);
    assert!(reranked.validate().is_err());
    assert_eq!(must(plan.compute_digest()), plan.digest);

    let empty = plan_for(Vec::new(), Some(16));
    must(empty.validate());
    assert!(empty.probes.is_empty());
    assert!(empty.omissions.is_empty());
}

fn rivals_with(set_id: &str, policy_digest_seed: &str) -> RivalModelSet {
    must(RivalModelSet::new(RivalModelSetParams {
        set_id: artifact(set_id),
        task_id: task(),
        scope: "scope-1".to_owned(),
        state_fence: fence(),
        bundle_digest: digest("bundle"),
        validated_input_digest: digest("validator-input"),
        declaration_set: RivalDeclarationSetRef {
            set_id: artifact("rival-decl-1"),
            digest: digest("decl"),
        },
        policy_id: "policy-1".to_owned(),
        policy_digest: digest(policy_digest_seed),
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

fn plan_for_with(
    descriptors: Vec<InquiryAffordanceDescriptor>,
    rivals: &RivalModelSet,
    candidates: Option<u64>,
) -> ProbePlan {
    let bundle = bundle();
    let draft = draft();
    let affordances = affordance_set(descriptors);
    let limits = limits(candidates);
    must(ProbePlan::new(ProbePlanParams {
        plan_id: artifact("plan-1"),
        bundle: &bundle,
        draft: &draft,
        rivals,
        affordances: &affordances,
        limits: &limits,
        policy: &ordering_policy(),
    }))
}

// WORK_UNIT_CASE: 610/41
#[test]
fn changed_rival_affordance_policy_invalidates_identity() {
    let base = plan_for(
        vec![descriptor("aff-identity-a", gap_target("claim-identity-a"))],
        Some(16),
    );
    must(base.validate());
    assert_eq!(base.probes.len(), 1);
    assert!(!base.rival_digest.trim().is_empty());
    assert!(!base.affordance_digest.trim().is_empty());

    let rival_set_changed = plan_for_with(
        vec![descriptor("aff-identity-a", gap_target("claim-identity-a"))],
        &rivals_with("rival-set-2", "policy"),
        Some(16),
    );
    must(rival_set_changed.validate());
    assert_ne!(
        rival_set_changed.rival_digest, base.rival_digest,
        "a changed rival set must invalidate the bound rival identity"
    );
    assert_eq!(rival_set_changed.affordance_digest, base.affordance_digest);
    assert_ne!(rival_set_changed.digest, base.digest);
    assert_ne!(rival_set_changed, base);

    let rival_policy_changed = plan_for_with(
        vec![descriptor("aff-identity-a", gap_target("claim-identity-a"))],
        &rivals_with("rival-set-1", "policy-rotated"),
        Some(16),
    );
    must(rival_policy_changed.validate());
    assert_ne!(
        rival_policy_changed.rival_digest, base.rival_digest,
        "a changed rival policy must invalidate the bound rival identity"
    );
    assert_ne!(rival_policy_changed.digest, base.digest);
    assert_ne!(rival_policy_changed, base);

    let affordance_changed = plan_for(
        vec![descriptor("aff-identity-b", gap_target("claim-identity-b"))],
        Some(16),
    );
    must(affordance_changed.validate());
    assert_ne!(
        affordance_changed.affordance_digest, base.affordance_digest,
        "a changed affordance denominator must invalidate the bound affordance identity"
    );
    assert_eq!(affordance_changed.rival_digest, base.rival_digest);
    assert_ne!(affordance_changed.digest, base.digest);
    assert_ne!(affordance_changed, base);

    let tight = plan_for(
        vec![
            descriptor("aff-identity-a", gap_target("claim-identity-a")),
            descriptor("aff-identity-c", gap_target("claim-identity-c")),
        ],
        Some(1),
    );
    let loose = plan_for(
        vec![
            descriptor("aff-identity-a", gap_target("claim-identity-a")),
            descriptor("aff-identity-c", gap_target("claim-identity-c")),
        ],
        Some(16),
    );
    must(tight.validate());
    must(loose.validate());
    assert_eq!(tight.probes.len(), 1);
    assert_eq!(tight.omissions.len(), 1);
    assert_eq!(tight.omissions[0].kind, OmissionKind::OverBudget);
    assert_ne!(
        tight.digest, loose.digest,
        "a changed candidate policy must invalidate the plan identity"
    );
    assert_ne!(tight, loose);

    let mut foreign = base.clone();
    foreign.digest.clone_from(&rival_set_changed.digest);
    assert!(
        foreign.validate().is_err(),
        "replaying a foreign rival-bound digest against unchanged tables must fail closed"
    );
    let mut foreign_affordance = base.clone();
    foreign_affordance
        .digest
        .clone_from(&affordance_changed.digest);
    assert!(
        foreign_affordance.validate().is_err(),
        "replaying a foreign affordance-bound digest against unchanged tables must fail closed"
    );
    assert_eq!(must(base.compute_digest()), base.digest);
}

// WORK_UNIT_CASE: 610/42
#[test]
fn no_execution_reservation_promotion_finish_path() {
    let plan = plan_for(
        vec![
            descriptor(
                "aff-noexec-a",
                rival_target("pred-ne-left", "pred-ne-right"),
            ),
            descriptor("aff-noexec-b", gap_target("claim-noexec")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());

    for probe in &plan.probes {
        must(probe.target.validate());
        must(probe.affordance.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        assert!(!probe.affordance.affordance_digest.trim().is_empty());
        for merged in &probe.merged_affordances {
            assert_ne!(*merged, probe.probe_id);
        }
        assert!(!probe.expected_discrimination.trim().is_empty());
        assert_rendered_has_no_execution_path(&format!("{probe:?}"));
    }

    assert_rendered_has_no_execution_path(&format!("{plan:?}"));
    assert_wire_has_no_execution_key(&plan);
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/20
#[test]
fn exact_external_owner_preserved_verbatim() {
    fn owned(id: &str, target: AffordanceTarget, reason: &str) -> InquiryAffordanceDescriptor {
        let mut params = descriptor_params(id, target);
        params.owner = ProbeOwnerRef::Unavailable {
            reason: reason.to_owned(),
        };
        descriptor_from_params(params)
    }
    fn owner_reason(owner: &ProbeOwnerRef) -> &str {
        match owner {
            ProbeOwnerRef::Unavailable { reason } => reason.as_str(),
            other => panic!("owner must be preserved verbatim, got {other:?}"),
        }
    }

    let alpha = owned(
        "aff-owner-alpha",
        gap_target("claim-owner-alpha"),
        "owner withheld: alpha",
    );
    let beta = owned(
        "aff-owner-beta",
        gap_target("claim-owner-beta"),
        "owner withheld: beta",
    );
    let plan = plan_for(vec![alpha, beta], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());
    for probe in &plan.probes {
        must(probe.target.validate());
        must(probe.result_schema.validate());
        must(probe.dimensions.validate());
        assert_eq!(probe.probe_id, probe.affordance.affordance_id);
        let expected = if probe.probe_id.as_str() == "aff-owner-alpha" {
            "owner withheld: alpha"
        } else if probe.probe_id.as_str() == "aff-owner-beta" {
            "owner withheld: beta"
        } else {
            panic!("unexpected probe {}", probe.probe_id.as_str());
        };
        assert_eq!(owner_reason(&probe.owner), expected);
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);

    let dup_alpha = owned(
        "aff-owner-dup-a",
        rival_target("pred-dup-left", "pred-dup-right"),
        "owner withheld: alpha",
    );
    let dup_beta = owned(
        "aff-owner-dup-b",
        rival_target("pred-dup-left", "pred-dup-right"),
        "owner withheld: beta",
    );
    let dup = plan_for(vec![dup_alpha, dup_beta], Some(16));
    must(dup.validate());
    assert_eq!(dup.probes.len(), 2);
    assert!(dup.omissions.is_empty());
    for probe in &dup.probes {
        must(probe.target.validate());
        assert!(probe.merged_affordances.is_empty());
        let expected = if probe.probe_id.as_str() == "aff-owner-dup-a" {
            "owner withheld: alpha"
        } else if probe.probe_id.as_str() == "aff-owner-dup-b" {
            "owner withheld: beta"
        } else {
            panic!(
                "unexpected duplicate-owner probe {}",
                probe.probe_id.as_str()
            );
        };
        assert_eq!(owner_reason(&probe.owner), expected);
    }
    assert_eq!(must(dup.compute_digest()), dup.digest);

    let gamma = owned(
        "aff-owner-gamma",
        gap_target("claim-owner-gamma"),
        "owner withheld: gamma",
    );
    let delta = owned(
        "aff-owner-delta",
        gap_target("claim-owner-delta"),
        "owner withheld: delta",
    );
    let tight = plan_for(vec![gamma, delta], Some(1));
    must(tight.validate());
    assert_eq!(tight.probes.len(), 1);
    assert_eq!(tight.omissions.len(), 1);
    assert_eq!(tight.omissions[0].kind, OmissionKind::OverBudget);
    assert_eq!(tight.probes[0].probe_id.as_str(), "aff-owner-delta");
    assert_eq!(
        owner_reason(&tight.probes[0].owner),
        "owner withheld: delta"
    );
    assert_eq!(
        tight.omissions[0].affordance.affordance_id.as_str(),
        "aff-owner-gamma"
    );
    assert_eq!(
        owner_reason(&tight.omissions[0].owner),
        "owner withheld: gamma"
    );
    assert_eq!(must(tight.compute_digest()), tight.digest);
}

// WORK_UNIT_CASE: 610/22
#[test]
fn effectful_candidate_stays_candidate_only_pending_external_admission() {
    // A state-changing declaration remains inert but is not ready: the
    // planner preserves it as an explicit blocked disposition until an
    // external owner supplies the required admission and reconciliation.
    let mut permitted_params =
        descriptor_params("aff-effect-permitted", gap_target("claim-effect-permitted"));
    permitted_params.effect = EffectDimension::StateChanging {
        detail: "touches scratch state".to_owned(),
    };
    let permitted = must(InquiryAffordanceDescriptor::new(permitted_params));

    let mut unapproved_params = descriptor_params(
        "aff-effect-unapproved",
        gap_target("claim-effect-unapproved"),
    );
    unapproved_params.effect = EffectDimension::StateChanging {
        detail: "touches scratch state".to_owned(),
    };
    unapproved_params.authority = AuthorityDimension::RequiresApproval {
        reason: "standing needs a governor grant".to_owned(),
    };
    let unapproved = must(InquiryAffordanceDescriptor::new(unapproved_params));
    assert!(!unapproved.authority.is_permitted());

    let plan = plan_for(vec![permitted, unapproved], Some(16));
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 2);
    assert_wire_has_no_execution_key(&plan);

    for omission in &plan.omissions {
        assert_eq!(omission.kind, OmissionKind::AuthorityBlocked);
        match omission.affordance.affordance_id.as_str() {
            "aff-effect-permitted" => assert!(omission.reason.contains("STATE_CHANGING")),
            "aff-effect-unapproved" => assert!(omission.reason.contains("REQUIRES_APPROVAL")),
            other => panic!("unexpected effectful omission {other}"),
        }
        match &omission.dimensions.effect {
            EffectDimension::StateChanging { detail } => {
                assert_eq!(detail.as_str(), "touches scratch state");
            }
            other => panic!("blocked effect vector must stay visible, got {other:?}"),
        }
        must(omission.target.validate());
        must(omission.dimensions.validate());
    }
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/11
#[test]
fn identical_result_updates_are_unprobeable() {
    let target = gap_target("claim-identical-updates");
    let schema = gap_matrix(
        "schema-identical-updates",
        objective("objective-identical-updates"),
        &[GapUpdateMeaning::RemainsOpen, GapUpdateMeaning::RemainsOpen],
    );
    assert_eq!(
        schema.update_discriminability(),
        ResultUpdateDiscriminability::NonDiscriminating
    );
    let plan = plan_for(
        vec![descriptor_with_schema(
            "aff-identical-updates",
            target,
            schema,
        )],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 1);
    assert_eq!(plan.omissions[0].kind, OmissionKind::Unprobeable);
    assert!(plan.omissions[0].reason.contains("identical"));
}

// WORK_UNIT_CASE: 610/12
#[test]
fn confirmation_only_result_matrix_is_unprobeable() {
    let target = objective_target("objective-confirmation-only");
    let schema = gap_matrix(
        "schema-confirmation-only",
        objective("objective-confirmation-only"),
        &[
            GapUpdateMeaning::Addressed,
            GapUpdateMeaning::PartiallyAddressed,
        ],
    );
    assert_eq!(
        schema.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    let plan = plan_for(
        vec![descriptor_with_schema(
            "aff-confirmation-only",
            target,
            schema,
        )],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 1);
    assert_eq!(plan.omissions[0].kind, OmissionKind::Unprobeable);
    assert!(plan.omissions[0].reason.contains("confirmation-only"));
}

// WORK_UNIT_CASE: 610/13
#[test]
fn unknown_self_report_updates_do_not_create_a_probe() {
    let schema = unknown_update_matrix(
        "schema-self-report",
        objective("objective-self-report"),
        &["self-report says resolved", "self-report says unresolved"],
    );
    assert_eq!(
        schema.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    let plan = plan_for(
        vec![descriptor_with_schema(
            "aff-self-report",
            objective_target("objective-self-report"),
            schema,
        )],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 1);
    assert!(plan.omissions[0].reason.contains("meaningful"));
}

// WORK_UNIT_CASE: 610/14
#[test]
fn unrelated_proxy_result_target_is_unprobeable() {
    let schema = gap_matrix(
        "schema-unrelated-proxy",
        objective("objective-unrelated-proxy"),
        &[GapUpdateMeaning::Addressed, GapUpdateMeaning::RemainsOpen],
    );
    let plan = plan_for(
        vec![descriptor_with_schema(
            "aff-unrelated-proxy",
            objective_target("objective-live"),
            schema,
        )],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 1);
    assert!(plan.omissions[0].reason.contains("does not update"));
}

// WORK_UNIT_CASE: 610/15
#[test]
fn correlation_only_result_is_not_causal_evidence() {
    let schema = unknown_update_matrix(
        "schema-correlation-only",
        objective("objective-correlation-only"),
        &["temporal correlation observed", "temporal order observed"],
    );
    let plan = plan_for(
        vec![descriptor_with_schema(
            "aff-correlation-only",
            objective_target("objective-correlation-only"),
            schema,
        )],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions[0].kind, OmissionKind::Unprobeable);
    assert!(plan.omissions[0].reason.contains("meaningful"));
}

// WORK_UNIT_CASE: 610/16
#[test]
fn causal_controls_and_confounders_cannot_be_invented() {
    let schema = unknown_update_matrix(
        "schema-causal-controls",
        objective("objective-causal-controls"),
        &["controls are omitted", "confounders are omitted"],
    );
    let plan = plan_for(
        vec![descriptor_with_schema(
            "aff-causal-controls",
            objective_target("objective-causal-controls"),
            schema,
        )],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions[0].kind, OmissionKind::Unprobeable);
    assert!(plan.omissions[0].reason.contains("meaningful"));
}

// WORK_UNIT_CASE: 610/23
#[test]
fn mandatory_safety_violations_are_explicitly_blocked() {
    let mut privacy = descriptor_params("aff-safety-privacy", gap_target("claim-safety-privacy"));
    privacy.privacy = PrivacyDimension::Elevated {
        reason: "principal disclosure is not contained".to_owned(),
    };
    let mut consent = descriptor_params("aff-safety-consent", gap_target("claim-safety-consent"));
    consent.consent = ConsentDimension::RequiresGrant {
        reason: "human decision required".to_owned(),
    };
    let mut authority =
        descriptor_params("aff-safety-authority", gap_target("claim-safety-authority"));
    authority.authority = AuthorityDimension::RequiresApproval {
        reason: "external owner has not admitted the action".to_owned(),
    };
    let mut effect = descriptor_params("aff-safety-effect", gap_target("claim-safety-effect"));
    effect.effect = EffectDimension::StateChanging {
        detail: "writes scratch state".to_owned(),
    };
    let mut reversible = descriptor_params(
        "aff-safety-reversibility",
        gap_target("claim-safety-reversibility"),
    );
    reversible.reversibility = ReversibilityDimension::Irreversible {
        reason: "cleanup cannot be guaranteed".to_owned(),
    };
    let descriptors = vec![
        must(InquiryAffordanceDescriptor::new(privacy)),
        must(InquiryAffordanceDescriptor::new(consent)),
        must(InquiryAffordanceDescriptor::new(authority)),
        must(InquiryAffordanceDescriptor::new(effect)),
        must(InquiryAffordanceDescriptor::new(reversible)),
    ];
    let plan = plan_for(descriptors, Some(16));
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 5);
    assert!(
        plan.omissions
            .iter()
            .all(|omission| omission.kind == OmissionKind::AuthorityBlocked)
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("ELEVATED"))
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("REQUIRES_GRANT"))
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("REQUIRES_APPROVAL"))
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("STATE_CHANGING"))
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("rollback"))
    );
}

// WORK_UNIT_CASE: 610/24
#[test]
fn possible_effect_or_rollback_uncertainty_stays_blocked() {
    let mut effect = descriptor_params("aff-unknown-effect", gap_target("claim-unknown-effect"));
    effect.effect = EffectDimension::Unknown {
        reason: "outcome side effects are uncharacterized".to_owned(),
    };
    let mut rollback =
        descriptor_params("aff-unknown-rollback", gap_target("claim-unknown-rollback"));
    rollback.reversibility = ReversibilityDimension::Unknown {
        reason: "cleanup and rollback are uncharacterized".to_owned(),
    };
    let plan = plan_for(
        vec![
            must(InquiryAffordanceDescriptor::new(effect)),
            must(InquiryAffordanceDescriptor::new(rollback)),
        ],
        Some(16),
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 2);
    assert!(
        plan.omissions
            .iter()
            .all(|omission| omission.kind == OmissionKind::AuthorityBlocked)
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("UNKNOWN_OR_UNAVAILABLE"))
    );
    assert!(
        plan.omissions
            .iter()
            .any(|omission| omission.reason.contains("rollback"))
    );
}

// WORK_UNIT_CASE: 610/25
#[test]
fn every_declared_budget_ceiling_fails_closed_one_over() {
    let bundle = bundle();
    let draft = draft();
    let rivals = rivals();
    let affordances = affordance_set(vec![descriptor("aff-budget", gap_target("claim-budget"))]);
    let dimensions = [
        BudgetDimension::InputBytes,
        BudgetDimension::OutputBytes,
        BudgetDimension::SourceWidth,
        BudgetDimension::ReferenceWidth,
        BudgetDimension::ModelCalls,
        BudgetDimension::Attempts,
        BudgetDimension::Candidates,
        BudgetDimension::WallMs,
        BudgetDimension::WorkFanOut,
        BudgetDimension::ReportBytes,
    ];
    for dimension in dimensions {
        let mut limits = limits(Some(1));
        let over = dimension.ceiling() + 1;
        match dimension {
            BudgetDimension::InputBytes => limits.input_bytes = Some(over),
            BudgetDimension::OutputBytes => limits.output_bytes = Some(over),
            BudgetDimension::SourceWidth => limits.source_width = Some(over),
            BudgetDimension::ReferenceWidth => limits.reference_width = Some(over),
            BudgetDimension::ModelCalls => limits.model_calls = Some(over),
            BudgetDimension::Attempts => limits.attempts = Some(over),
            BudgetDimension::Candidates => limits.candidates = Some(over),
            BudgetDimension::WallMs => limits.wall_ms = Some(over),
            BudgetDimension::WorkFanOut => limits.work_fan_out = Some(over),
            BudgetDimension::ReportBytes => limits.report_bytes = Some(over),
        }
        assert!(
            ProbePlan::new(ProbePlanParams {
                plan_id: artifact("plan-budget"),
                bundle: &bundle,
                draft: &draft,
                rivals: &rivals,
                affordances: &affordances,
                limits: &limits,
                policy: &ordering_policy(),
            })
            .is_err(),
            "one-over {} must fail closed",
            dimension as u8
        );
    }
    let mut stu_limits = limits(Some(1));
    stu_limits.max_stu = Some(eliot_dreamer_contracts::budget::STU_CEILING + 1);
    assert!(
        ProbePlan::new(ProbePlanParams {
            plan_id: artifact("plan-budget-stu"),
            bundle: &bundle,
            draft: &draft,
            rivals: &rivals,
            affordances: &affordances,
            limits: &stu_limits,
            policy: &ordering_policy(),
        })
        .is_err()
    );
}

// WORK_UNIT_CASE: 610/27
#[test]
fn budget_dimensions_do_not_subsidize_an_unknown_candidate_bound() {
    let plan = plan_for(
        vec![
            descriptor("aff-budget-a", gap_target("claim-budget-a")),
            descriptor("aff-budget-b", gap_target("claim-budget-b")),
        ],
        None,
    );
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 2);
    assert!(
        plan.omissions
            .iter()
            .all(|omission| omission.kind == OmissionKind::OverBudget)
    );
    assert!(
        plan.omissions
            .iter()
            .all(|omission| omission.reason.contains("unknown"))
    );
}

// WORK_UNIT_CASE: 610/29
#[test]
fn unknown_or_incomparable_dimensions_are_not_dominated_away() {
    let target = gap_target("claim-dominance");
    let shared_schema = result_schema_for_target("schema-dominance", &target);
    let mut known_params = descriptor_params("aff-dominance-known", target.clone());
    known_params.result_schema = shared_schema.clone();
    known_params.cost = CostDimension::High {
        detail: "wide retained scan".to_owned(),
    };
    let mut unknown_params = descriptor_params("aff-dominance-unknown", target);
    unknown_params.result_schema = shared_schema;
    unknown_params.information = InformationDimension::Unknown {
        reason: "gain is incomparable".to_owned(),
    };
    unknown_params.resource = ResourceDimension::Unknown {
        reason: "capacity is incomparable".to_owned(),
    };
    let plan = plan_for(
        vec![
            descriptor_from_params(known_params),
            descriptor_from_params(unknown_params),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 2);
    assert!(plan.omissions.is_empty());
    assert!(
        plan.probes
            .iter()
            .all(|probe| probe.merged_affordances.is_empty())
    );
    assert!(plan.probes.iter().any(|probe| matches!(
        probe.dimensions.information,
        InformationDimension::Unknown { .. }
    )));
}

// WORK_UNIT_CASE: 610/33
#[test]
fn every_source_affordance_has_one_explicit_frontier_disposition() {
    let mut blocked_params =
        descriptor_params("aff-frontier-blocked", gap_target("claim-frontier-blocked"));
    blocked_params.authority = AuthorityDimension::Denied {
        reason: "no standing".to_owned(),
    };
    let mut unprobeable_params = descriptor_params(
        "aff-frontier-unprobeable",
        gap_target("claim-frontier-unprobeable"),
    );
    unprobeable_params.feasibility = FeasibilityDimension::Unknown {
        reason: "channel state is unknown".to_owned(),
    };
    let plan = plan_for(
        vec![
            descriptor("aff-frontier-ready", gap_target("claim-frontier-ready")),
            must(InquiryAffordanceDescriptor::new(blocked_params)),
            must(InquiryAffordanceDescriptor::new(unprobeable_params)),
        ],
        Some(1),
    );
    must(plan.validate());
    let mut emitted = Vec::new();
    emitted.extend(
        plan.probes
            .iter()
            .map(|probe| probe.probe_id.as_str().to_owned()),
    );
    emitted.extend(
        plan.omissions
            .iter()
            .map(|omission| omission.affordance.affordance_id.as_str().to_owned()),
    );
    emitted.sort();
    assert_eq!(
        emitted,
        vec![
            "aff-frontier-blocked".to_owned(),
            "aff-frontier-ready".to_owned(),
            "aff-frontier-unprobeable".to_owned(),
        ]
    );
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.omissions.len(), 2);
}

// WORK_UNIT_CASE: 610/38
#[test]
fn every_ready_probe_has_two_differently_updating_valid_outcomes() {
    let plan = plan_for(
        vec![descriptor(
            "aff-ready-matrix",
            rival_target("pred-ready-left", "pred-ready-right"),
        )],
        Some(16),
    );
    must(plan.validate());
    let probe = &plan.probes[0];
    assert!(probe.result_schema.branches.len() >= 2);
    assert_eq!(
        probe.result_schema.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    for branch in &probe.result_schema.branches {
        must(branch.value.validate());
        assert!(!branch.updates.is_empty());
    }
    assert!(
        probe
            .result_schema
            .branches
            .windows(2)
            .any(|pair| { pair[0].updates != pair[1].updates })
    );
}

// WORK_UNIT_CASE: 610/39
#[test]
fn ready_probe_has_no_unknown_mandatory_safety_dimension() {
    let plan = plan_for(
        vec![descriptor(
            "aff-safe-mandatory",
            gap_target("claim-safe-mandatory"),
        )],
        Some(16),
    );
    must(plan.validate());
    let probe = &plan.probes[0];
    assert!(matches!(
        probe.dimensions.privacy,
        PrivacyDimension::Contained { .. }
    ));
    assert!(matches!(
        probe.dimensions.consent,
        ConsentDimension::Granted { .. }
    ));
    assert!(matches!(
        probe.dimensions.authority,
        AuthorityDimension::Permitted { .. }
    ));
    assert!(matches!(
        probe.dimensions.effect,
        EffectDimension::SideEffectFree { .. } | EffectDimension::ObservableOnly { .. }
    ));
    assert!(matches!(
        probe.dimensions.reversibility,
        ReversibilityDimension::Reversible { .. }
    ));
    assert!(matches!(
        probe.dimensions.feasibility,
        FeasibilityDimension::Feasible { .. }
    ));
    assert!(!matches!(
        probe.dimensions.attention,
        HumanAttentionDimension::Unknown { .. } | HumanAttentionDimension::Unavailable { .. }
    ));
}

// WORK_UNIT_CASE: 610/40
#[test]
fn each_material_unknown_is_retained_in_one_gap_disposition() {
    let mut feasibility = descriptor_params(
        "aff-unknown-material-feasibility",
        gap_target("claim-material-feasibility"),
    );
    feasibility.feasibility = FeasibilityDimension::Unknown {
        reason: "channel not characterized".to_owned(),
    };
    let mut information = descriptor_params(
        "aff-unknown-material-information",
        gap_target("claim-material-information"),
    );
    information.information = InformationDimension::Unknown {
        reason: "expected gain not characterized".to_owned(),
    };
    let mut consent = descriptor_params(
        "aff-unknown-material-consent",
        gap_target("claim-material-consent"),
    );
    consent.consent = ConsentDimension::Unknown {
        reason: "consent state not supplied".to_owned(),
    };
    let plan = plan_for(
        vec![
            descriptor_from_params(feasibility),
            descriptor_from_params(information),
            descriptor_from_params(consent),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.omissions.len(), 2);
    let mut ids: Vec<&str> = plan
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .chain(
            plan.omissions
                .iter()
                .map(|omission| omission.affordance.affordance_id.as_str()),
        )
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3);
    assert_eq!(
        plan.probes[0].probe_id.as_str(),
        "aff-unknown-material-information"
    );
    assert!(plan.omissions.iter().all(|omission| matches!(
        omission.kind,
        OmissionKind::Unprobeable | OmissionKind::AuthorityBlocked
    )));
}

fn assert_rendered_has_no_execution_path(rendered: &str) {
    for token in [
        "provider",
        "Provider",
        "reservation",
        "Reservation",
        "promotion",
        "Promotion",
        "Finish",
        "schedule",
        "Schedule",
        "process::Command",
        "std::process",
        "tokio",
        "reqwest",
        "hyper",
        "Agent::",
        "Network",
        "Store::",
    ] {
        assert!(
            !rendered.contains(token),
            "candidate plan must carry no {token} execution path, got {rendered}"
        );
    }
}

fn assert_wire_has_no_execution_key(plan: &ProbePlan) {
    let wire = must(canonical_bytes(plan));
    let text = String::from_utf8(wire).expect("canonical plan wire must be UTF-8");
    let folded = text.to_lowercase();
    for key in [
        "\"provider\"",
        "\"tool\"",
        "\"agent\"",
        "\"process\"",
        "\"network\"",
        "\"store\"",
        "\"reservation\"",
        "\"promotion\"",
        "\"finish\"",
        "\"schedule\"",
        "\"route\"",
        "\"credential\"",
        "\"lease\"",
        "\"secret\"",
        "\"token\"",
        "\"handle\"",
    ] {
        assert!(
            !folded.contains(key),
            "canonical plan wire must carry no {key} execution key"
        );
    }
    if !plan.probes.is_empty() {
        for key in [
            "\"probes\"",
            "\"omissions\"",
            "\"result_schema\"",
            "\"expected_discrimination\"",
        ] {
            assert!(
                folded.contains(key),
                "canonical plan wire must preserve the candidate-only {key} shape"
            );
        }
    }
}
