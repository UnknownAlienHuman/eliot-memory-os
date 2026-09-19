//! Planner consumption of the A-03 predeclared update-set classification
//! (issue 610/11, case 610/11 needs).
//!
//! Cell `smart.dreamer.probe_plan` (A-17b) owns only admission gating on
//! already-owned descriptor dimensions; vocabulary, equality, and
//! materiality judgments belong to A-03 (`dreamer-contracts`). The planner
//! therefore consumes [`ResultUpdateDiscriminability`] verbatim when
//! collapsing duplicate descriptors and performs zero update, meaning, or
//! materiality inference of its own. Proof: update-equivalent (but
//! byte-distinct) descriptors collapse onto one probe consuming the
//! predeclared value, while descriptors whose predeclared classifications
//! differ stay split.
//!
//! Cases 610/11..16, 610/38 remain otherwise governed by the ownership
//! ruling recorded in `tests/work_unit_610.rs`: no planner-side
//! branch-update equivalence or causal/material relevance judgment exists
//! here.

use std::num::NonZeroU64;

use eliot_dreamer_contracts::{
    AffordanceKind, AffordanceTarget, AuthorityDimension, BudgetLimits, BundleCompleteness,
    ConsentDimension, ContextDimension, CostDimension, DreamInputBundle, EffectDimension,
    FeasibilityDimension, GapUpdateMeaning, HumanAttentionDimension, InformationDimension,
    InquiryAffordanceDescriptor, InquiryAffordanceDescriptorParams, InquiryAffordanceSet,
    InquiryAffordanceSetParams, LatencyDimension, MaterialClaimRef, PossibleResultSchema,
    PossibleResultValue, PrivacyDimension, ProbeObjectiveRef, ProbeOwnerRef, ResourceDimension,
    ResultBranch, ResultTarget, ResultUpdate, ResultUpdateDiscriminability, ReversibilityDimension,
    RivalCoverageStatus, RivalCoverageSummary, RivalDeclarationSetRef, RivalModelSet,
    RivalModelSetParams, ValidatedDreamDraft, ValidationReceipt,
    grounding::canonical::{
        ArtifactId, EpochId, EpochLineageId, Precision, PropositionId, ResourceGeneration,
        StateFence, TaskId, ValidityBounds, sha256_hex,
    },
};
use eliot_dreamer_probe_plan::{ProbePlan, ProbePlanParams};

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

fn claim(id: &str) -> MaterialClaimRef {
    MaterialClaimRef {
        claim_id: id.to_owned(),
        proposition: must(PropositionId::new("prop-1")),
        claim_preimage_digest: digest(id),
    }
}

fn gap_target(id: &str) -> AffordanceTarget {
    AffordanceTarget::EvidenceGap { claim: claim(id) }
}

/// A single-target Gap schema whose branches carry exactly `meanings` in
/// order. Schema identity, branch identity, and branch order are caller
/// chosen and never participate in A-03 update-set equivalence.
fn gap_schema(
    schema_id: &str,
    objective_id: &str,
    meanings: &[GapUpdateMeaning],
) -> PossibleResultSchema {
    let target = objective(objective_id);
    let branches = meanings
        .iter()
        .enumerate()
        .map(|(index, meaning)| ResultBranch {
            result_id: artifact(&format!("{schema_id}-branch-{index}")),
            value: PossibleResultValue::Unknown {
                reason: "outcome not yet observed".to_owned(),
            },
            updates: vec![ResultUpdate::Gap {
                objective: target.clone(),
                meaning: *meaning,
            }],
        })
        .collect();
    must(PossibleResultSchema::new(
        artifact(schema_id),
        vec![ResultTarget::Gap { objective: target }],
        branches,
    ))
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
        result_schema: gap_schema(
            &format!("{id}-schema"),
            &format!("{id}-objective"),
            &[GapUpdateMeaning::RemainsOpen],
        ),
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

fn descriptor_with_schema(
    id: &str,
    target: AffordanceTarget,
    schema: PossibleResultSchema,
) -> InquiryAffordanceDescriptor {
    let mut params = descriptor_params(id, target);
    params.result_schema = schema;
    must(InquiryAffordanceDescriptor::new(params))
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

// WORK_UNIT_CASE: 610/11 (identical-consumes-predeclared)
#[test]
fn identical_update_sets_consume_predeclared_equivalence() {
    let target = gap_target("claim-equiv");
    // Same update sets over the same declared objective, but byte-distinct
    // schemas: different schema and branch identities, permuted branch order.
    let schema_a = gap_schema(
        "equiv-schema-a",
        "equiv-objective",
        &[GapUpdateMeaning::Addressed, GapUpdateMeaning::RemainsOpen],
    );
    let schema_b = gap_schema(
        "equiv-schema-b",
        "equiv-objective",
        &[GapUpdateMeaning::RemainsOpen, GapUpdateMeaning::Addressed],
    );
    assert_eq!(
        schema_a.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    assert_eq!(
        schema_b.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    assert_ne!(
        schema_a.digest, schema_b.digest,
        "fixtures must be byte-distinct so the merge proves update-set consumption, not byte equality"
    );
    must(schema_a.validate());
    must(schema_b.validate());

    let descriptor_b = descriptor_with_schema("aff-equiv-b", target.clone(), schema_b);
    let descriptor_a = descriptor_with_schema("aff-equiv-a", target, schema_a);
    let plan = plan_for(vec![descriptor_b, descriptor_a], Some(16));
    must(plan.validate());
    assert_eq!(plan.probes.len(), 1);
    assert!(plan.omissions.is_empty());

    let probe = &plan.probes[0];
    assert_eq!(probe.probe_id.as_str(), "aff-equiv-a");
    assert_eq!(probe.rank, 0);
    assert!(
        probe.merged_affordances.contains(&artifact("aff-equiv-b")),
        "merge must retain the collapsed lineage, got {:?}",
        probe.merged_affordances
    );
    must(probe.result_schema.validate());
    assert_eq!(
        probe.result_schema.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating,
        "the planned probe carries the predeclared classification"
    );
    assert_eq!(must(plan.compute_digest()), plan.digest);
}

// WORK_UNIT_CASE: 610/11 (split-stays-split)
#[test]
fn distinct_predeclared_classifications_stay_split() {
    let target = gap_target("claim-split");
    let plain = gap_schema(
        "split-schema-plain",
        "split-objective",
        &[GapUpdateMeaning::RemainsOpen],
    );
    let split = gap_schema(
        "split-schema-split",
        "split-objective",
        &[GapUpdateMeaning::Addressed, GapUpdateMeaning::RemainsOpen],
    );
    assert_eq!(
        plain.update_discriminability(),
        ResultUpdateDiscriminability::NonDiscriminating
    );
    assert_eq!(
        split.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );

    let first = descriptor_with_schema("aff-split-a", target.clone(), plain);
    let second = descriptor_with_schema("aff-split-b", target, split);
    let forward = plan_for(vec![first.clone(), second.clone()], Some(16));
    let backward = plan_for(vec![second, first], Some(16));
    must(forward.validate());
    must(backward.validate());
    // Same kind and target, yet the declared discriminability boundary holds:
    // no merge across predeclared classifications.
    assert_eq!(forward.probes.len(), 2);
    assert!(forward.omissions.is_empty());
    let order: Vec<&str> = forward
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(order, vec!["aff-split-a", "aff-split-b"]);
    for probe in &forward.probes {
        assert!(
            probe.merged_affordances.is_empty(),
            "split probes must not absorb each other, got {:?}",
            probe.merged_affordances
        );
        must(probe.result_schema.validate());
    }
    assert_eq!(
        forward.probes[0].result_schema.update_discriminability(),
        ResultUpdateDiscriminability::NonDiscriminating
    );
    assert_eq!(
        forward.probes[1].result_schema.update_discriminability(),
        ResultUpdateDiscriminability::Discriminating
    );
    assert_eq!(forward.digest, backward.digest);
    assert_eq!(must(forward.compute_digest()), forward.digest);
}
