//! Work-unit 610 slices 1-5 plus slice 6: bounded discriminative probe
//! planner, cases 1..10 plus 610/17, 610/21, 610/32, 610/36 and 610/18-19
//! (typed affordance Unknown/Unavailable gating, safe read-only
//! candidate-only admission, explicit lexicographic order with stable
//! tie-break, input-order-independent plan/digest stability, no
//! shell/Value/SDK payload, and no live route/credential/lease handle).
//!
//! Cases 610/1, 610/4 and 610/5 are marked on the existing planner
//! behaviour tests in `tests/probe_plan.rs`. Cases 610/11..16, 610/38
//! (identical-updates / confirmation-only / tautology / proxy /
//! correlation-causality / causal-controls / two-outcome readiness) remain
//! UPSTREAM-BLOCKED on issue #610: deciding branch-update equivalence or
//! causal/material relevance is an A-03 materiality judgment, and `src/plan.rs`
//! contains zero `ResultUpdate`/`RivalUpdateMeaning` inspections, so no
//! planner-only implementation exists without inventing APIs (slice-4 Opus
//! audit ruling on 610/11 applies identically). Cases 610/22,
//! 610/26-28, 610/30-31, 610/34-35, 610/37, 610/41-42 (effect-policy,
//! budget/dominance/disposition/replay/no-execution) are QUEUED and out of
//! this batch; 610/20 needs `src/` owner preservation, 610/23-25 need policy
//! or budget enforcement the planner explicitly declines (`plan.rs`: effect,
//! privacy, reversibility and non-candidate budgets stay advisory).
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
//! before any descriptor can plan).
//! Ownership ruling 610/17,21 (this slice, planner-side gating/admission
//! only; no new APIs, zero `src/` changes): 610/17 OWNED via the existing
//! `classify_dimensions` closed gates (feasibility UNKNOWN/UNAVAILABLE and
//! information UNAVAILABLE map to `Unprobeable`; authority
//! UNKNOWN/UNAVAILABLE maps to `AuthorityBlocked`; consent UNKNOWN stays
//! plannable but never reads as granted); 610/21 OWNED via safe-descriptor
//! admission (SideEffectFree/Permitted/Granted/Feasible/Contained/Reversible
//! plans to a ranked candidate-only probe with all vectors preserved and no
//! execution handle).
//! Ownership ruling 610/32,36 (this slice, planner-side order/digest only;
//! no new APIs, zero `src/` changes): 610/32 OWNED via the existing
//! vector-preserving lexicographic order observed through plan order
//! (information rank dominates cost rank, so High-information/High-cost
//! precedes Low-information/Negligible-cost; Unknown information sorts after
//! every known gain inside its dimension; equal vectors break ties by stable
//! affordance identity); 610/36 OWNED via canonical construction (affordance
//! set sorts by identity, groups collapse deterministically, probes rank by
//! vector key then identity, omissions sort canonically), so set-only input
//! permutations preserve the plan value and frozen digest.
//! Ownership ruling 610/18-19 (this slice, planner-side absence only;
//! no new APIs, zero `src/` changes): 610/18 OWNED via the closed typed
//! plan shape observed through `canonical_bytes` (every probe carries only
//! `kind`/`target`/`result_schema`/`dimensions` plus the id/digest binding;
//! every result branch stays `PossibleResultValue::Unknown` with exact cover,
//! and the canonical wire contains no shell/Value/SDK payload keys);
//! 610/19 OWNED via the candidate-only binding observed through the plan
//! value (every probe binds only `ProbeAffordanceRef` id/digest with lineage,
//! and the canonical wire contains no live route/credential/lease/permit-handle
//! keys, so nothing reserves or addresses execution).
//! Docs route=sha256:1b9bbbd8b5bb5e2de4737b4fa03e7e3672daba4394afef443dd3d8476554c7fa read=sha256:ea79ca7e06dbc95bb6ebceb4b5d904a848f265540ab58d6e82d93d5878599ec6 bundle=5ca78f97ee5f6485f6ab552d6687ade11da053a68be0cb38339167aeac0be7f3 (generic-source; verified bundle read in full; plan.rs/model.rs plus contracts affordance/result/objective/budget sources read directly).

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
    canonical_bytes,
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
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.omissions.len(), 5);

    let probe = &plan.probes[0];
    assert_eq!(probe.probe_id.as_str(), "aff-unknown-consent");
    assert!(!probe.dimensions.consent.is_granted());
    must(probe.target.validate());
    must(probe.result_schema.validate());

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
    assert_eq!(blocked, 2);
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
    let safe = must(InquiryAffordanceDescriptor::new(safe_params));
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
    let costly = must(InquiryAffordanceDescriptor::new(costly_params));

    let mut cheap_params = descriptor_params("aff-lex-cheap", gap_target("claim-lex-cheap"));
    cheap_params.information = InformationDimension::Low {
        detail: "weak split of the gap".to_owned(),
    };
    cheap_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    let cheap = must(InquiryAffordanceDescriptor::new(cheap_params));

    let mut unknown_params = descriptor_params("aff-lex-unknown", gap_target("claim-lex-unknown"));
    unknown_params.information = InformationDimension::Unknown {
        reason: "gain not yet characterized".to_owned(),
    };
    unknown_params.cost = CostDimension::Negligible {
        detail: "trivial retained read".to_owned(),
    };
    let unknown = must(InquiryAffordanceDescriptor::new(unknown_params));
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
    let second = must(InquiryAffordanceDescriptor::new(second_params));
    let mut third_params = descriptor_params("aff-order-c", gap_target("claim-order-c"));
    third_params.information = InformationDimension::Moderate {
        detail: "partial split of the gap".to_owned(),
    };
    let third = must(InquiryAffordanceDescriptor::new(third_params));
    let mut fourth_params = descriptor_params("aff-order-d", gap_target("claim-order-d"));
    fourth_params.information = InformationDimension::Unknown {
        reason: "gain not yet characterized".to_owned(),
    };
    let fourth = must(InquiryAffordanceDescriptor::new(fourth_params));

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
