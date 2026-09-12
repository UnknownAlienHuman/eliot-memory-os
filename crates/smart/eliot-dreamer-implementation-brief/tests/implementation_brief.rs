#![allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]

mod support;

use eliot_conformance_contracts::{
    ContractMaturity, EvidenceDomain, EvidenceExecutionStatus, ImplementationSupport,
    SupportObservationState,
};
use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_contracts::{JobClass, SelfQueryOutputProfile};
use eliot_dreamer_implementation_brief::{
    ArchitectureAlignment, EvidenceVerdict, ImplementationBriefDisposition,
    ImplementationBriefError, ImplementationBriefInput, ImplementationGapClass,
    ImplementationSourceStatus, MechanismDisposition, ProofStage, StageDisposition,
    IMPLEMENTATION_BRIEF_PROOF_CEILING, project_implementation_brief,
};
use eliot_epistemic_contracts::{PositionAssertability, PrivacyHandling};
use eliot_receipts::{EffectClass, ProofCeiling};
use support::{fixture, reseal, set_single_stage};

fn first_stage(input: &ImplementationBriefInput) -> StageDisposition {
    project_implementation_brief(input).expect("projection").mechanisms[0].obligations[0]
        .stages[0]
        .disposition
}

fn set_status(
    input: &mut ImplementationBriefInput,
    observation: SupportObservationState,
    support: ImplementationSupport,
    execution: EvidenceExecutionStatus,
    verdict: EvidenceVerdict,
) {
    let row = &mut input.conformance.support_rows[0];
    row.support_observation_state = observation;
    row.implementation_support = support;
    row.evidence_execution_status = execution;
    if support != ImplementationSupport::CurrentVerified {
        row.proof_profile_ref = None;
    }
    let coverage = input
        .conformance
        .domain_coverage
        .iter_mut()
        .find(|coverage| coverage.domain == EvidenceDomain::Source)
        .expect("source coverage");
    coverage.state = observation;
    if observation == SupportObservationState::Unknown {
        coverage.source_handles.clear();
        coverage.evidence_refs.clear();
        coverage.invalidation_set.clear();
        coverage.observed_at_ms = None;
        coverage.expires_at_ms = None;
    } else {
        coverage.source_handles = vec!["implementation-source".to_owned()];
        coverage.evidence_refs = vec!["source-evidence-1".to_owned()];
        coverage.invalidation_set = vec!["source-tree".to_owned()];
        coverage.observed_at_ms = Some(90);
        coverage.expires_at_ms = Some(200);
    }
    input.evidence[0].verdict = verdict;
    reseal(input);
}

fn require_stages(input: &mut ImplementationBriefInput, stages: Vec<ProofStage>) {
    input.obligations[0].required_stages = stages;
    reseal(input);
}

fn without_source() -> ImplementationBriefInput {
    let mut input = fixture();
    input.implementation_source = None;
    input.mechanisms.clear();
    input.obligations.clear();
    input.evidence.clear();
    input.conformance.support_rows.clear();
    input.denominator.mechanism_ids.clear();
    input.denominator.obligation_ids.clear();
    input.denominator.evidence_ids.clear();
    input.denominator.complete = false;
    reseal(&mut input);
    input
}

fn add_second_mechanism(input: &mut ImplementationBriefInput) {
    let mut statement = input.implementation_source.as_ref().unwrap().statements[0].clone();
    statement.statement_id = "statement-2".to_owned();
    statement.mechanism_id = "mechanism-2".to_owned();
    statement.text = "A second owner provides an independently accounted interface.".to_owned();
    statement.statement_digest.clear();
    input
        .implementation_source
        .as_mut()
        .unwrap()
        .statements
        .push(statement);

    let mut mechanism = input.mechanisms[0].clone();
    mechanism.mechanism_id = "mechanism-2".to_owned();
    mechanism.owner = "adapter-owner".to_owned();
    mechanism.statement_refs = vec!["statement-2".to_owned()];
    mechanism.dependency_refs = vec!["mechanism-1".to_owned()];
    mechanism.obligation_refs = vec!["obligation-2".to_owned()];
    mechanism.contract_refs = vec!["implementation-contract-v2".to_owned()];
    mechanism.mechanism_digest.clear();
    input.mechanisms.push(mechanism);

    let mut obligation = input.obligations[0].clone();
    obligation.obligation_id = "obligation-2".to_owned();
    obligation.mechanism_id = "mechanism-2".to_owned();
    obligation.owner = "adapter-owner".to_owned();
    obligation.statement_refs = vec!["statement-2".to_owned()];
    obligation.obligation_digest.clear();
    input.obligations.push(obligation);

    let mut row = input.conformance.support_rows[0].clone();
    row.contract_ref = "implementation-contract-v2".to_owned();
    row.support_claim_ref = "support-claim-2".to_owned();
    row.evidence_refs = vec!["source-evidence-2".to_owned()];
    input.conformance.support_rows.push(row);

    let mut evidence = input.evidence[0].clone();
    evidence.evidence_id = "evidence-2".to_owned();
    evidence.mechanism_id = "mechanism-2".to_owned();
    evidence.obligation_id = "obligation-2".to_owned();
    evidence.support_claim_ref = "support-claim-2".to_owned();
    evidence.target.source_tree_digest = sha256_hex(b"source-tree-652");
    evidence.target.target_digest.clear();
    evidence.evidence_digest.clear();
    input.evidence.push(evidence);

    input.denominator.mechanism_ids.push("mechanism-2".to_owned());
    input.denominator.obligation_ids.push("obligation-2".to_owned());
    input.denominator.evidence_ids.push("evidence-2".to_owned());
    reseal(input);
}

fn add_contradictory_evidence(input: &mut ImplementationBriefInput) {
    let mut row = input.conformance.support_rows[0].clone();
    row.contract_ref = "independent-evaluator-v1".to_owned();
    row.support_claim_ref = "support-claim-negative".to_owned();
    row.evidence_refs = vec!["negative-evidence".to_owned()];
    row.implementation_support = ImplementationSupport::CurrentUnverified;
    row.proof_profile_ref = None;
    input.conformance.support_rows.push(row);

    let mut evidence = input.evidence[0].clone();
    evidence.evidence_id = "evidence-negative".to_owned();
    evidence.support_claim_ref = "support-claim-negative".to_owned();
    evidence.verdict = EvidenceVerdict::Failed;
    evidence.detail = "independent negative observation contradicts the favorable result".to_owned();
    evidence.evidence_digest.clear();
    input.evidence.push(evidence);
    input
        .denominator
        .evidence_ids
        .push("evidence-negative".to_owned());
    reseal(input);
}

// WORK_UNIT_CASE: 651/1
#[test]
fn minimal_implementation_brief() {
    let input = fixture();
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.disposition, ImplementationBriefDisposition::Complete);
    assert_eq!(output.mechanisms.len(), 1);
    assert_eq!(output.proof_ceiling, IMPLEMENTATION_BRIEF_PROOF_CEILING);
    output.validate_against(&input).expect("binding");
}

// WORK_UNIT_CASE: 651/2
#[test]
fn multi_owner_multi_mechanism() {
    let mut input = fixture();
    add_second_mechanism(&mut input);
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.mechanisms.len(), 2);
    assert_eq!(output.mechanisms[0].owner.as_deref(), Some("governor-transition-owner"));
    assert_eq!(output.mechanisms[1].owner.as_deref(), Some("adapter-owner"));
    assert!(output.mechanisms.iter().all(|value| value.disposition == MechanismDisposition::Supported));
}

// WORK_UNIT_CASE: 651/3
#[test]
fn exact_job_and_output_profile_only() {
    project_implementation_brief(&fixture()).expect("accepted profile");
    let mut wrong_profile = fixture();
    wrong_profile.self_query.profile.output_profile = SelfQueryOutputProfile::ArchitectureBrief;
    wrong_profile.self_query.profile.profile_digest = wrong_profile
        .self_query
        .profile
        .compute_digest()
        .expect("profile digest");
    wrong_profile.input_digest.clear();
    assert!(wrong_profile.seal().is_err());

    let mut wrong_job = fixture();
    wrong_job.self_query.validated_candidate.job.job_class = JobClass::Orientation;
    wrong_job.input_digest.clear();
    assert!(wrong_job.seal().is_err());
}

// WORK_UNIT_CASE: 651/4
#[test]
fn source_lifecycle_is_preserved() {
    let accepted = project_implementation_brief(&fixture()).expect("accepted");
    assert_eq!(accepted.implementation_source_status, Some(ImplementationSourceStatus::Accepted));
    for status in [
        ImplementationSourceStatus::Draft,
        ImplementationSourceStatus::Rejected,
        ImplementationSourceStatus::Superseded,
        ImplementationSourceStatus::Stale,
        ImplementationSourceStatus::Unavailable,
    ] {
        let mut input = fixture();
        let source = input.implementation_source.as_mut().unwrap();
        source.status = status;
        source.acceptance_receipt = None;
        source.complete = false;
        reseal(&mut input);
        let output = project_implementation_brief(&input).expect("bounded output");
        assert_eq!(output.implementation_source_status, Some(status));
        assert_eq!(output.disposition, ImplementationBriefDisposition::Unsupported);
    }
}

// WORK_UNIT_CASE: 651/5
#[test]
fn pair_revision_and_digest_mismatch_fail() {
    let mut revision = fixture();
    let source = revision.implementation_source.as_mut().unwrap();
    source.revision = "implementation-r2".to_owned();
    source.statements[0].source_revision = "implementation-r2".to_owned();
    revision.input_digest.clear();
    assert!(revision.seal().is_err());

    let mut digest = fixture();
    let changed = sha256_hex(b"changed implementation");
    let source = digest.implementation_source.as_mut().unwrap();
    source.source_digest = changed.clone();
    source.statements[0].source_digest = changed;
    digest.input_digest.clear();
    assert!(digest.seal().is_err());
}

// WORK_UNIT_CASE: 651/6
#[test]
fn duplicate_conflicting_evidence_identity_fails() {
    let mut input = fixture();
    let mut duplicate = input.evidence[0].clone();
    duplicate.verdict = EvidenceVerdict::Failed;
    duplicate.evidence_digest.clear();
    input.evidence.push(duplicate);
    input.denominator.complete = false;
    input.input_digest.clear();
    assert!(input.seal().is_err());
}

// WORK_UNIT_CASE: 651/7
#[test]
fn task_scope_fence_bundle_and_grounding_mismatch_fail() {
    let mut task = fixture();
    task.self_query.validated_candidate.job.task_id = "other-task".to_owned();
    task.input_digest.clear();
    assert!(task.seal().is_err());

    let mut scope = fixture();
    scope.self_query.validated_candidate.bundle.scope_id = "other-scope".to_owned();
    scope.input_digest.clear();
    assert!(scope.seal().is_err());

    let mut fence = fixture();
    fence.self_query.validated_candidate.bundle.state_fence = StateFence::new(
        AuthorityEpoch::new(2).expect("epoch"),
        ResourceGeneration::new(2).expect("generation"),
    );
    fence.input_digest.clear();
    assert!(fence.seal().is_err());

    let mut grounding = fixture();
    grounding.self_query.validated_candidate.grounded.job_id = "other-job".to_owned();
    grounding.input_digest.clear();
    assert!(grounding.seal().is_err());
}

// WORK_UNIT_CASE: 651/8
#[test]
fn governing_architecture_binding_is_retained() {
    let input = fixture();
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.architecture_source_handle.as_deref(), Some("architecture-source"));
    assert_eq!(output.mechanisms[0].architecture_refs, vec!["arch-1"]);
    assert_eq!(output.implementation_source_handle.as_deref(), Some("implementation-source"));
}

// WORK_UNIT_CASE: 651/9
#[test]
fn constitutional_conflict_blocks_without_rewrite() {
    let mut input = fixture();
    input.implementation_source.as_mut().unwrap().statements[0].alignment = ArchitectureAlignment::Conflict;
    reseal(&mut input);
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.disposition, ImplementationBriefDisposition::Blocked);
    assert_eq!(output.mechanisms[0].disposition, MechanismDisposition::Deviated);
    assert!(output.gaps.iter().any(|gap| gap.class == ImplementationGapClass::ArchitectureConflict && gap.owner == "architecture-precedence-owner"));
}

// WORK_UNIT_CASE: 651/10
#[test]
fn unspecified_mechanism_remains_unknown() {
    let mut input = fixture();
    input.denominator.mechanism_ids.push("mechanism-unspecified".to_owned());
    input.denominator.complete = false;
    reseal(&mut input);
    let output = project_implementation_brief(&input).expect("projection");
    let unknown = output
        .mechanisms
        .iter()
        .find(|value| value.mechanism_id == "mechanism-unspecified")
        .expect("unknown mechanism");
    assert_eq!(unknown.disposition, MechanismDisposition::Unknown);
}

// WORK_UNIT_CASE: 651/11
#[test]
fn source_presence_does_not_prove_package() {
    let mut input = fixture();
    require_stages(&mut input, vec![ProofStage::Source, ProofStage::Package]);
    let output = project_implementation_brief(&input).expect("projection");
    let stages = &output.mechanisms[0].obligations[0].stages;
    assert_eq!(stages[0].disposition, StageDisposition::CurrentVerified);
    assert_eq!(stages[1].disposition, StageDisposition::Missing);
    assert_ne!(output.disposition, ImplementationBriefDisposition::Complete);
}

// WORK_UNIT_CASE: 651/12
#[test]
fn compile_only_does_not_prove_package() {
    let mut input = fixture();
    input.obligations[0].required_stages = vec![ProofStage::Compile, ProofStage::Package];
    input.evidence[0].stage = ProofStage::Compile;
    reseal(&mut input);
    let stages = project_implementation_brief(&input).unwrap().mechanisms[0].obligations[0]
        .stages
        .clone();
    assert_eq!(stages[0].disposition, StageDisposition::CurrentVerified);
    assert_eq!(stages[1].disposition, StageDisposition::Missing);
}

// WORK_UNIT_CASE: 651/13
#[test]
fn unit_property_and_package_stages_remain_distinct() {
    for stage in [ProofStage::Unit, ProofStage::Property, ProofStage::Package] {
        let mut input = fixture();
        set_single_stage(&mut input, stage);
        let output = project_implementation_brief(&input).expect("projection");
        assert_eq!(output.mechanisms[0].obligations[0].stages[0].stage, stage);
        assert_eq!(first_stage(&input), StageDisposition::CurrentVerified);
    }
}

// WORK_UNIT_CASE: 651/14
#[test]
fn integration_and_real_edge_are_not_collapsed() {
    for stage in [ProofStage::Integration, ProofStage::Edge] {
        let mut input = fixture();
        set_single_stage(&mut input, stage);
        let output = project_implementation_brief(&input).expect("projection");
        assert_eq!(output.mechanisms[0].obligations[0].stages[0].stage, stage);
    }
}

// WORK_UNIT_CASE: 651/15
#[test]
fn runtime_is_an_independent_stage() {
    let mut input = fixture();
    set_single_stage(&mut input, ProofStage::Runtime);
    assert_eq!(first_stage(&input), StageDisposition::CurrentVerified);
}

// WORK_UNIT_CASE: 651/16
#[test]
fn product_is_an_independent_stage() {
    let mut input = fixture();
    set_single_stage(&mut input, ProofStage::Product);
    assert_eq!(first_stage(&input), StageDisposition::CurrentVerified);
}

// WORK_UNIT_CASE: 651/17
#[test]
fn release_is_an_independent_stage() {
    let mut input = fixture();
    set_single_stage(&mut input, ProofStage::Release);
    assert_eq!(first_stage(&input), StageDisposition::CurrentVerified);
}

// WORK_UNIT_CASE: 651/18
#[test]
fn support_axes_are_independent_not_a_total_ladder() {
    let output = project_implementation_brief(&fixture()).expect("projection");
    let evidence = &output.mechanisms[0].obligations[0].stages[0].evidence[0];
    assert_eq!(evidence.contract_maturity, ContractMaturity::Stable);
    assert_eq!(evidence.implementation_support, ImplementationSupport::CurrentVerified);
    assert_eq!(evidence.evidence_execution_status, EvidenceExecutionStatus::Executed);
    assert_eq!(evidence.support_observation_state, SupportObservationState::Observed);
    assert_eq!(evidence.claim_domain, Some(EvidenceDomain::Source));
}

// WORK_UNIT_CASE: 651/19
#[test]
fn target_requirement_is_not_current_support() {
    let mut input = fixture();
    set_status(
        &mut input,
        SupportObservationState::Observed,
        ImplementationSupport::Target,
        EvidenceExecutionStatus::NotExecuted,
        EvidenceVerdict::Passed,
    );
    assert_eq!(first_stage(&input), StageDisposition::CurrentUnverified);
    assert_ne!(project_implementation_brief(&input).unwrap().disposition, ImplementationBriefDisposition::Complete);
}

// WORK_UNIT_CASE: 651/20
#[test]
fn package_pass_does_not_imply_edge_or_runtime() {
    let mut input = fixture();
    input.obligations[0].required_stages = vec![ProofStage::Package, ProofStage::Edge, ProofStage::Runtime];
    input.evidence[0].stage = ProofStage::Package;
    reseal(&mut input);
    let stages = project_implementation_brief(&input).unwrap().mechanisms[0].obligations[0]
        .stages
        .clone();
    assert_eq!(stages[0].disposition, StageDisposition::CurrentVerified);
    assert_eq!(stages[1].disposition, StageDisposition::Missing);
    assert_eq!(stages[2].disposition, StageDisposition::Missing);
}

// WORK_UNIT_CASE: 651/21
#[test]
fn process_or_model_success_is_not_semantic_support() {
    let mut input = fixture();
    set_status(
        &mut input,
        SupportObservationState::Observed,
        ImplementationSupport::CurrentUnverified,
        EvidenceExecutionStatus::Executed,
        EvidenceVerdict::Passed,
    );
    assert_eq!(first_stage(&input), StageDisposition::CurrentUnverified);
}

// WORK_UNIT_CASE: 651/22
#[test]
fn stale_and_incompatible_target_evidence_remain_visible() {
    let mut stale = fixture();
    set_status(
        &mut stale,
        SupportObservationState::Stale,
        ImplementationSupport::Stale,
        EvidenceExecutionStatus::Executed,
        EvidenceVerdict::Passed,
    );
    assert_eq!(first_stage(&stale), StageDisposition::Stale);

    let mut incompatible = fixture();
    incompatible.evidence[0].target.platform = "wrong-platform".to_owned();
    incompatible.evidence[0].target.features = vec!["wrong-feature".to_owned()];
    incompatible.evidence[0].target.artifact_digest = Some(sha256_hex(b"wrong-artifact"));
    incompatible.evidence[0].verdict = EvidenceVerdict::Conflicted;
    reseal(&mut incompatible);
    let output = project_implementation_brief(&incompatible).expect("projection");
    let evidence = &output.mechanisms[0].obligations[0].stages[0].evidence[0];
    assert_eq!(evidence.target.platform, "wrong-platform");
    assert_eq!(evidence.target.features, vec!["wrong-feature"]);
    assert_eq!(output.mechanisms[0].obligations[0].stages[0].disposition, StageDisposition::Conflicted);
}

// WORK_UNIT_CASE: 651/23
#[test]
fn skipped_required_proof_blocks_completion() {
    let mut input = fixture();
    set_status(
        &mut input,
        SupportObservationState::Observed,
        ImplementationSupport::Target,
        EvidenceExecutionStatus::NotExecuted,
        EvidenceVerdict::Skipped,
    );
    assert_eq!(first_stage(&input), StageDisposition::Skipped);
    assert_ne!(project_implementation_brief(&input).unwrap().disposition, ImplementationBriefDisposition::Complete);
}

// WORK_UNIT_CASE: 651/24
#[test]
fn missing_and_failed_are_distinct() {
    let mut missing = fixture();
    missing.evidence.clear();
    missing.denominator.complete = false;
    reseal(&mut missing);
    assert_eq!(first_stage(&missing), StageDisposition::Missing);

    let mut failed = fixture();
    set_status(
        &mut failed,
        SupportObservationState::Observed,
        ImplementationSupport::CurrentUnverified,
        EvidenceExecutionStatus::Executed,
        EvidenceVerdict::Failed,
    );
    assert_eq!(first_stage(&failed), StageDisposition::Failed);
}

// WORK_UNIT_CASE: 651/25
#[test]
fn contradictory_evidence_is_retained() {
    let mut input = fixture();
    add_contradictory_evidence(&mut input);
    let output = project_implementation_brief(&input).expect("projection");
    let stage = &output.mechanisms[0].obligations[0].stages[0];
    assert_eq!(stage.evidence.len(), 2);
    assert_eq!(stage.disposition, StageDisposition::Failed);
    assert!(stage.evidence.iter().any(|item| item.verdict == EvidenceVerdict::Passed));
    assert!(stage.evidence.iter().any(|item| item.verdict == EvidenceVerdict::Failed));
}

// WORK_UNIT_CASE: 651/26
#[test]
fn partial_denominator_cannot_claim_all_current() {
    let mut input = fixture();
    input.denominator.complete = false;
    input.denominator.mechanism_ids.push("mechanism-missing".to_owned());
    reseal(&mut input);
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.disposition, ImplementationBriefDisposition::Partial);
    assert!(!output.gaps.is_empty());
}

// WORK_UNIT_CASE: 651/27
#[test]
fn status_vector_and_missing_obligation_are_both_exposed() {
    let mut input = fixture();
    require_stages(&mut input, vec![ProofStage::Source, ProofStage::Edge]);
    let output = project_implementation_brief(&input).expect("projection");
    let source = &output.mechanisms[0].obligations[0].stages[0].evidence[0];
    assert_eq!(source.implementation_support, ImplementationSupport::CurrentVerified);
    assert!(output.gaps.iter().any(|gap| gap.stage == Some(ProofStage::Edge)));
}

// WORK_UNIT_CASE: 651/28
#[test]
fn gap_handoff_names_owner_not_work_plan() {
    let mut input = fixture();
    require_stages(&mut input, vec![ProofStage::Source, ProofStage::Product]);
    let output = project_implementation_brief(&input).expect("projection");
    let gap = output.gaps.iter().find(|gap| gap.stage == Some(ProofStage::Product)).unwrap();
    assert_eq!(gap.owner, "governor-transition-owner");
    assert!(!gap.detail.to_ascii_lowercase().contains("issue"));
    assert!(!gap.detail.to_ascii_lowercase().contains("work plan"));
}

// WORK_UNIT_CASE: 651/29
#[test]
fn bounded_output_retains_omissions() {
    let input = without_source();
    let output = project_implementation_brief(&input).expect("bounded output");
    assert_eq!(output.disposition, ImplementationBriefDisposition::NoSource);
    assert!(output.omissions.iter().any(|item| item.omission_id == "implementation-source-unavailable"));
}

// WORK_UNIT_CASE: 651/30
#[test]
fn privacy_authority_effect_and_proof_ceiling_are_bound() {
    let input = fixture();
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.proof_ceiling, "candidate-only");
    assert_eq!(input.self_query.policy.privacy, PrivacyHandling::Unrestricted);
    assert_eq!(input.self_query.policy.authority_ceiling, PositionAssertability::PlanningOnly);

    let mut effect = fixture();
    effect.self_query.policy.effect_ceiling = EffectClass::ExternalEffect;
    effect.input_digest.clear();
    assert!(effect.seal().is_err());

    let mut proof = fixture();
    proof.self_query.policy.proof_ceiling = ProofCeiling::ObservedExternalEffect;
    proof.input_digest.clear();
    assert!(proof.seal().is_err());
}

// WORK_UNIT_CASE: 651/31
#[test]
fn independent_bounds_fail_one_over() {
    let mut work = fixture();
    work.self_query.policy.max_work = 1;
    reseal(&mut work);
    assert!(matches!(project_implementation_brief(&work), Err(ImplementationBriefError::Bound { field: "projection.work_units", .. })));

    let mut output = fixture();
    output.self_query.policy.max_output_bytes = 1;
    reseal(&mut output);
    assert!(matches!(project_implementation_brief(&output), Err(ImplementationBriefError::Bound { field: "projection.output_wire", .. })));

    let mut text = fixture();
    text.mechanisms[0].description = "x".repeat(64 * 1024 + 1);
    text.input_digest.clear();
    assert!(text.seal().is_err());
}

// WORK_UNIT_CASE: 651/32
#[test]
fn set_order_is_deterministic() {
    let mut left = fixture();
    left.invalidation_conditions = vec!["z-change".to_owned(), "a-change".to_owned()];
    reseal(&mut left);
    let mut right = fixture();
    right.invalidation_conditions = vec!["a-change".to_owned(), "z-change".to_owned()];
    reseal(&mut right);
    assert_eq!(left.input_digest, right.input_digest);
    assert_eq!(project_implementation_brief(&left).unwrap(), project_implementation_brief(&right).unwrap());
}

// WORK_UNIT_CASE: 651/33
#[test]
fn replay_is_stable_and_changed_input_changes_identity() {
    let input = fixture();
    let first = project_implementation_brief(&input).unwrap();
    let second = project_implementation_brief(&input).unwrap();
    assert_eq!(first, second);

    let mut changed = input.clone();
    changed.self_query.question = "What changed in the exact implementation?".to_owned();
    reseal(&mut changed);
    let changed_output = project_implementation_brief(&changed).unwrap();
    assert_ne!(first.input_digest, changed_output.input_digest);
    assert_ne!(first.output_digest, changed_output.output_digest);
    assert!(first.validate_against(&changed).is_err());
}

// WORK_UNIT_CASE: 651/34
#[test]
fn seven_dimensions_and_upstream_receipt_are_consumed_intrinsically() {
    let input = fixture();
    let receipt_before = input.self_query.validated_candidate.validated.receipt.clone();
    assert_eq!(input.self_query.preservation.verdicts.len(), 7);
    let output = project_implementation_brief(&input).expect("projection");
    assert_eq!(output.disposition, ImplementationBriefDisposition::Complete);
    assert_eq!(input.self_query.validated_candidate.validated.receipt, receipt_before);
}

// WORK_UNIT_CASE: 651/35
#[test]
fn malformed_and_oversized_input_fails_boundedly() {
    let mut value = serde_json::to_value(fixture()).expect("json");
    value.as_object_mut().unwrap().insert("unknown_control".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<ImplementationBriefInput>(value).is_err());

    let mut control = fixture();
    control.mechanisms[0].owner = "bad\nowner".to_owned();
    control.input_digest.clear();
    assert!(control.seal().is_err());

    let mut oversized = fixture();
    oversized.self_query.question = "q".repeat(64 * 1024 + 1);
    oversized.input_digest.clear();
    assert!(oversized.seal().is_err());
}

// WORK_UNIT_CASE: 651/36
#[test]
fn evidence_claim_retains_all_identity_status_and_proof_axes() {
    let mut input = fixture();
    input.evidence[0].target.source_tree_digest = sha256_hex(b"other-tree");
    input.evidence[0].target.artifact_digest = Some(sha256_hex(b"other-artifact"));
    input.evidence[0].target.configuration_digest = Some(sha256_hex(b"other-config"));
    input.evidence[0].target.platform = "other-platform".to_owned();
    input.evidence[0].target.toolchain = "other-toolchain".to_owned();
    input.evidence[0].target.features = vec!["feature-a".to_owned(), "feature-b".to_owned()];
    input.evidence[0].target.environment_digest = sha256_hex(b"other-env");
    input.evidence[0].target.observation_window_ref = "window-2".to_owned();
    input.evidence[0].verdict = EvidenceVerdict::Conflicted;
    reseal(&mut input);
    let output = project_implementation_brief(&input).expect("projection");
    let evidence = &output.mechanisms[0].obligations[0].stages[0].evidence[0];
    assert_eq!(evidence.target.platform, "other-platform");
    assert_eq!(evidence.target.toolchain, "other-toolchain");
    assert_eq!(evidence.target.features, vec!["feature-a", "feature-b"]);
    assert_eq!(evidence.verdict, EvidenceVerdict::Conflicted);
    assert_eq!(evidence.contract_maturity, ContractMaturity::Stable);
    assert_eq!(evidence.evidence_execution_status, EvidenceExecutionStatus::Executed);
    assert_eq!(evidence.support_observation_state, SupportObservationState::Observed);
}

// WORK_UNIT_CASE: 651/37
#[test]
fn removed_receipt_invalidates_corresponding_claim() {
    let mut source_receipt = fixture();
    source_receipt.implementation_source.as_mut().unwrap().acceptance_receipt = None;
    source_receipt.input_digest.clear();
    assert!(source_receipt.seal().is_err());

    let mut support_receipt = fixture();
    support_receipt.conformance.support_rows.clear();
    support_receipt.input_digest.clear();
    assert!(support_receipt.seal().is_err());
}

// WORK_UNIT_CASE: 651/38
#[test]
fn mechanism_binds_accepted_implementation_and_architecture() {
    let input = fixture();
    let output = project_implementation_brief(&input).expect("projection");
    let mechanism = &output.mechanisms[0];
    assert_eq!(output.implementation_source_status, Some(ImplementationSourceStatus::Accepted));
    assert_eq!(output.implementation_source_digest, input.implementation_source.as_ref().map(|value| value.source_digest.clone()));
    assert_eq!(mechanism.statement_refs, vec!["statement-1"]);
    assert_eq!(mechanism.architecture_refs, vec!["arch-1"]);
}

// WORK_UNIT_CASE: 651/39
#[test]
fn projector_has_no_io_effect_status_mutation_or_finish() {
    let input = fixture();
    let before = serde_json::to_vec(&input).expect("input bytes");
    let output = project_implementation_brief(&input).expect("projection");
    let after = serde_json::to_vec(&input).expect("input bytes");
    let rendered = serde_json::to_string(&output).expect("output json");
    assert_eq!(before, after);
    assert_eq!(output.proof_ceiling, "candidate-only");
    assert!(!rendered.to_ascii_lowercase().contains("verified_complete"));
    assert!(!rendered.to_ascii_lowercase().contains("finish"));
}
