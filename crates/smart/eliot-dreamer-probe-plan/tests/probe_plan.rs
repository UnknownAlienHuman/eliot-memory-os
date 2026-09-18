//! Package-local behaviour proof for the bounded discriminative probe planner.
//!
//! Main behaviours only: target naming, deterministic ordering with
//! set-permutation stability, duplicate collapse, vector preservation,
//! explicit gaps with no fallback, and fail-closed bounds/digest validation.

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
    fence_with_sequence(1)
}

fn fence_with_sequence(sequence: u64) -> StateFence {
    let lineage = must(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000"));
    let sequence = must(NonZeroU64::new(sequence).ok_or("sequence must be non-zero"));
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
    affordance_set_scoped("scope-1", descriptors)
}

fn affordance_set_scoped(
    scope: &str,
    descriptors: Vec<InquiryAffordanceDescriptor>,
) -> InquiryAffordanceSet {
    must(InquiryAffordanceSet::new(InquiryAffordanceSetParams {
        set_id: artifact("affordance-set-1"),
        task_id: task(),
        scope: scope.to_owned(),
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

// (a) Every probe names its target disagreement or unknown.
// WORK_UNIT_CASE: 610/1
#[test]
fn probe_names_its_discriminator_or_unknown_target() {
    let plan = plan_for(
        vec![
            descriptor("aff-rival", rival_target("pred-left", "pred-right")),
            descriptor("aff-gap", gap_target("claim-7")),
            descriptor("aff-assumption", assumption_target("assume-3")),
        ],
        Some(16),
    );
    must(plan.validate());
    assert_eq!(plan.probes.len(), 3);
    assert!(plan.omissions.is_empty());

    let rival = plan
        .probes
        .iter()
        .find(|probe| probe.probe_id.as_str() == "aff-rival")
        .unwrap_or_else(|| panic!("rival probe must be planned"));
    match &rival.target {
        ProbeTarget::RivalDisagreement { left, right } => {
            assert_eq!(left.prediction_id.as_str(), "pred-left");
            assert_eq!(right.prediction_id.as_str(), "pred-right");
        }
        other => panic!("rival probe must name a disagreement, got {other:?}"),
    }
    assert!(rival.expected_discrimination.contains("pred-left"));
    assert!(rival.expected_discrimination.contains("pred-right"));

    let gap = plan
        .probes
        .iter()
        .find(|probe| probe.probe_id.as_str() == "aff-gap")
        .unwrap_or_else(|| panic!("gap probe must be planned"));
    match &gap.target {
        ProbeTarget::EvidenceUnknown { claim } => {
            assert_eq!(claim.claim_id.as_str(), "claim-7");
        }
        other => panic!("gap probe must name an unknown, got {other:?}"),
    }
    assert!(gap.expected_discrimination.contains("claim-7"));

    let assumption = plan
        .probes
        .iter()
        .find(|probe| probe.probe_id.as_str() == "aff-assumption")
        .unwrap_or_else(|| panic!("assumption probe must be planned"));
    match &assumption.target {
        ProbeTarget::AssumptionUnknown { assumption, .. } => {
            assert_eq!(assumption.assumption_id.as_str(), "assume-3");
        }
        other => panic!("assumption probe must name an unknown, got {other:?}"),
    }
    assert!(assumption.expected_discrimination.contains("assume-3"));
}

// (b) Deterministic ordering with set-permutation stability.
#[test]
fn ordering_is_deterministic_and_permutation_stable() {
    let cheap = descriptor("aff-cheap", gap_target("claim-cheap"));
    let mut pricey_params = descriptor_params("aff-pricey", gap_target("claim-pricey"));
    pricey_params.information = InformationDimension::Low {
        detail: "weak split of the gap".to_owned(),
    };
    pricey_params.cost = CostDimension::High {
        detail: "wide retained scan".to_owned(),
    };
    let pricey = must(InquiryAffordanceDescriptor::new(pricey_params));
    let mut unknown_params = descriptor_params("aff-unknown", gap_target("claim-unknown"));
    unknown_params.information = InformationDimension::Unknown {
        reason: "gain not yet characterized".to_owned(),
    };
    let unknown = must(InquiryAffordanceDescriptor::new(unknown_params));

    let forward = plan_for(
        vec![cheap.clone(), pricey.clone(), unknown.clone()],
        Some(16),
    );
    let backward = plan_for(
        vec![unknown.clone(), pricey.clone(), cheap.clone()],
        Some(16),
    );
    must(forward.validate());
    must(backward.validate());
    assert_eq!(forward.digest, backward.digest);
    assert_eq!(forward, backward);

    let order: Vec<&str> = forward
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(order, vec!["aff-cheap", "aff-pricey", "aff-unknown"]);
    for (index, probe) in forward.probes.iter().enumerate() {
        let rank = must(u32::try_from(index).map_err(|_| "rank must fit u32"));
        assert_eq!(probe.rank, rank);
    }

    let again = plan_for(vec![cheap, pricey, unknown], Some(16));
    assert_eq!(forward.digest, again.digest);
}

// (c) Duplicate probes collapse onto the lowest affordance identity.
// WORK_UNIT_CASE: 610/5
#[test]
fn duplicate_probes_collapse() {
    let first = descriptor("aff-dup-a", gap_target("claim-same"));
    let mut params = descriptor_params("aff-dup-b", gap_target("claim-same"));
    params.cost = CostDimension::Moderate {
        detail: "same channel, costlier read".to_owned(),
    };
    let second = must(InquiryAffordanceDescriptor::new(params));

    let plan = plan_for(vec![second, first], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    let probe = &plan.probes[0];
    assert_eq!(probe.probe_id.as_str(), "aff-dup-a");
    assert_eq!(probe.affordance.affordance_id.as_str(), "aff-dup-a");
    let merged: Vec<&str> = probe
        .merged_affordances
        .iter()
        .map(ArtifactId::as_str)
        .collect();
    assert_eq!(merged, vec!["aff-dup-b"]);
    match &probe.target {
        ProbeTarget::EvidenceUnknown { claim } => {
            assert_eq!(claim.claim_id.as_str(), "claim-same");
        }
        other => panic!("collapsed probe must keep its target, got {other:?}"),
    }
}

// (d) Cost, risk, and authority vectors are preserved verbatim, never scalar-hidden.
#[test]
fn cost_risk_authority_vectors_are_preserved() {
    let mut params = descriptor_params("aff-risky", gap_target("claim-risky"));
    params.information = InformationDimension::Moderate {
        detail: "partial split of the gap".to_owned(),
    };
    params.cost = CostDimension::High {
        detail: "wide retained scan".to_owned(),
    };
    params.effect = EffectDimension::StateChanging {
        detail: "touches scratch state".to_owned(),
    };
    params.reversibility = ReversibilityDimension::Irreversible {
        reason: "scratch write cannot be undone".to_owned(),
    };
    params.privacy = PrivacyDimension::Elevated {
        reason: "names a principal".to_owned(),
    };
    let risky = must(InquiryAffordanceDescriptor::new(params));

    let plan = plan_for(vec![risky], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    let probe = &plan.probes[0];
    match &probe.dimensions.cost {
        CostDimension::High { detail } => assert_eq!(detail.as_str(), "wide retained scan"),
        other => panic!("cost vector must stay visible, got {other:?}"),
    }
    match &probe.dimensions.effect {
        EffectDimension::StateChanging { detail } => {
            assert_eq!(detail.as_str(), "touches scratch state");
        }
        other => panic!("effect vector must stay visible, got {other:?}"),
    }
    match &probe.dimensions.reversibility {
        ReversibilityDimension::Irreversible { reason } => {
            assert_eq!(reason.as_str(), "scratch write cannot be undone");
        }
        other => panic!("reversibility vector must stay visible, got {other:?}"),
    }
    match &probe.dimensions.privacy {
        PrivacyDimension::Elevated { reason } => {
            assert_eq!(reason.as_str(), "names a principal");
        }
        other => panic!("privacy vector must stay visible, got {other:?}"),
    }
    match &probe.dimensions.authority {
        AuthorityDimension::Permitted { detail } => {
            assert_eq!(detail.as_str(), "standing supplied");
        }
        other => panic!("authority vector must stay visible, got {other:?}"),
    }
}

// (e) Unprobeable, over-budget, and authority-blocked gaps are explicit.
#[test]
fn gaps_are_explicit_with_no_fallback_action() {
    let admitted = descriptor("aff-admitted", gap_target("claim-in"));
    let mut blocked_params = descriptor_params("aff-blocked", gap_target("claim-blocked"));
    blocked_params.authority = AuthorityDimension::Denied {
        reason: "no standing for this source".to_owned(),
    };
    let blocked = must(InquiryAffordanceDescriptor::new(blocked_params));
    let mut stuck_params = descriptor_params("aff-stuck", gap_target("claim-stuck"));
    stuck_params.feasibility = FeasibilityDimension::Infeasible {
        reason: "channel retired".to_owned(),
    };
    let stuck = must(InquiryAffordanceDescriptor::new(stuck_params));
    let extra = descriptor("aff-extra", gap_target("claim-extra"));

    let plan = plan_for(vec![admitted, blocked, stuck, extra], Some(1));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.probes[0].probe_id.as_str(), "aff-admitted");
    assert_eq!(plan.omissions.len(), 3);

    let kinds: Vec<OmissionKind> = plan.omissions.iter().map(|gap| gap.kind).collect();
    assert!(kinds.contains(&OmissionKind::Unprobeable));
    assert!(kinds.contains(&OmissionKind::OverBudget));
    assert!(kinds.contains(&OmissionKind::AuthorityBlocked));

    for gap in &plan.omissions {
        assert!(!gap.reason.trim().is_empty());
        match gap.kind {
            OmissionKind::Unprobeable => {
                assert_eq!(gap.affordance.affordance_id.as_str(), "aff-stuck");
                assert!(gap.reason.contains("INFEASIBLE"));
            }
            OmissionKind::AuthorityBlocked => {
                assert_eq!(gap.affordance.affordance_id.as_str(), "aff-blocked");
                assert!(gap.reason.contains("DENIED"));
            }
            OmissionKind::OverBudget => {
                assert_eq!(gap.affordance.affordance_id.as_str(), "aff-extra");
                assert!(gap.reason.contains("candidate bound"));
            }
        }
    }
    for probe in &plan.probes {
        assert_ne!(probe.probe_id.as_str(), "aff-blocked");
        assert_ne!(probe.probe_id.as_str(), "aff-stuck");
        assert_ne!(probe.probe_id.as_str(), "aff-extra");
    }
}

// (e, continued) Unknown candidate bound admits nothing: everything ranked
// becomes an over-budget gap instead of reading unknown as unlimited.
#[test]
fn unknown_candidate_bound_admits_nothing() {
    let plan = plan_for(vec![descriptor("aff-only", gap_target("claim-only"))], None);
    must(plan.validate());
    assert!(plan.probes.is_empty());
    assert_eq!(plan.omissions.len(), 1);
    assert_eq!(plan.omissions[0].kind, OmissionKind::OverBudget);
    assert!(plan.omissions[0].reason.contains("unknown"));
}

// (f) Bounds and digest failures fail closed.
#[test]
fn bounds_and_digest_failures_fail_closed() {
    let plan = plan_for(
        vec![descriptor("aff-firm", gap_target("claim-firm"))],
        Some(16),
    );
    must(plan.validate());

    let mut tampered = plan.clone();
    tampered.digest = "0".repeat(64);
    assert!(tampered.validate().is_err());

    let mut reranked = plan.clone();
    reranked.probes[0].rank = 7;
    assert!(reranked.validate().is_err());

    let mut blanked = plan.clone();
    blanked.probes[0].expected_discrimination = "   ".to_owned();
    assert!(blanked.validate().is_err());

    let mut unbound = plan.clone();
    unbound.probes[0]
        .merged_affordances
        .insert(artifact("aff-firm"));
    assert!(unbound.validate().is_err());

    assert!(!plan.digest.is_empty());
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// (f, continued) Cross-input binding mismatches fail the planner closed.
// WORK_UNIT_CASE: 610/4
#[test]
fn binding_mismatches_fail_the_planner_closed() {
    let bundle = bundle();
    let bound_draft = draft();
    let rivals = rivals();
    let limits = limits(Some(16));

    let wrong_scope = affordance_set_scoped("scope-2", vec![descriptor("aff-x", gap_target("c"))]);
    let scoped = ProbePlan::new(ProbePlanParams {
        plan_id: artifact("plan-1"),
        bundle: &bundle,
        draft: &bound_draft,
        rivals: &rivals,
        affordances: &wrong_scope,
        limits: &limits,
    });
    assert!(scoped.is_err());

    let mut drifted = bound_draft.clone();
    drifted.state_fence = fence_with_sequence(2);
    let affordances = affordance_set(vec![descriptor("aff-x", gap_target("c"))]);
    let fenced = ProbePlan::new(ProbePlanParams {
        plan_id: artifact("plan-1"),
        bundle: &bundle,
        draft: &drifted,
        rivals: &rivals,
        affordances: &affordances,
        limits: &limits,
    });
    assert!(fenced.is_err());

    let mut over = limits;
    over.candidates = Some(17);
    let budgeted = ProbePlan::new(ProbePlanParams {
        plan_id: artifact("plan-1"),
        bundle: &bundle,
        draft: &bound_draft,
        rivals: &rivals,
        affordances: &affordances,
        limits: &over,
    });
    assert!(budgeted.is_err());
}

// Empty denominators plan to an empty, digest-stable plan.
#[test]
fn empty_denominator_plans_empty() {
    let first = plan_for(Vec::new(), Some(16));
    let second = plan_for(Vec::new(), Some(16));
    must(first.validate());
    assert!(first.probes.is_empty());
    assert!(first.omissions.is_empty());
    assert_eq!(first.digest, second.digest);
}
