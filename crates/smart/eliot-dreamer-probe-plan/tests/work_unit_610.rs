//! Work-unit 610 slice 1: bounded discriminative probe planner, cases 1..5
//! (valid two-rival probe, multi-rival result matrix, exact
//! objective/result/affordance/disposition vocabulary, bound-input
//! mismatch, duplicate collapse).
//!
//! Cases 610/1, 610/4 and 610/5 are marked on the existing planner
//! behaviour tests in `tests/probe_plan.rs`. Cases 610/6..42 (objective
//! semantics, result-schema discipline, budget/dominance, replay and
//! no-execution proof) remain QUEUED on issue #610.

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
    must(ValidityBounds::new(
        "scope-1",
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
