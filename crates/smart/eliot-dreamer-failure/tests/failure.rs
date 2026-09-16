#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use eliot_dreamer_contracts::{canonical_bytes, digest_hex};
use eliot_dreamer_failure::{
    ApplicabilityAssessment, FailureDisposition, OutcomeAssessment, TriggerAssessment,
    propose_failure_fingerprint,
};
use eliot_dreamer_contracts::{
    CandidateDisposition, ContractViolation, FailureComparator, FailureCoverage,
    FailureDimensionValue, FailureObservationState,
};

fn prepared() -> (
    eliot_dreamer_contracts::FailureInput,
    eliot_dreamer_failure::FailurePolicy,
) {
    let mut input = support::full_input();
    let policy = support::sealed_policy();
    input.policy_digest.clone_from(&policy.digest);
    input.proposal.policy_digest.clone_from(&policy.digest);
    input.validate().expect("adapted A03 fixture validates");
    (input, policy)
}

#[test]
fn exact_failure_produces_sealed_hypothesis_decision() {
    let (input, policy) = prepared();
    let decision = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("positive current attempt path");
    assert_eq!(decision.result.disposition, FailureDisposition::Hypothesis);
    assert_eq!(decision.assessment.trigger, TriggerAssessment::Exact);
    assert_eq!(
        decision.assessment.outcome,
        OutcomeAssessment::ExecutedButSemanticallyFailed
    );
    assert!(!decision.decision_id.is_empty());
    assert!(decision.preflight().is_ok());
    assert!(decision.result.validate_against(&input).is_ok());
}

#[test]
fn declared_history_near_match_is_retained() {
    let (mut input, policy) = prepared();
    input.history.entries[0].near_match = true;
    input.history.near_match_count = 1;
    input.proposal.history = input.history.clone();
    let decision = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("near match remains a typed degradation");
    assert_eq!(decision.assessment.trigger, TriggerAssessment::Exact);
    assert_eq!(decision.assessment.counts.near_match_count, 1);
    assert_eq!(
        decision.result.common_disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
    let original_trigger_digest = decision.assessment.current_trigger_digest.clone();
    input.history.entries[0].fingerprint_id = input.proposal.fingerprint.clone();
    input.history.entries[0].trigger_digest = original_trigger_digest.clone();
    input.proposal.history = input.history.clone();
    input.validate().expect("joined history trigger validates");
    let joined = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("declared trigger join remains assessable");
    assert_eq!(joined.assessment.counts.history_trigger_match_count, 1);
    input.environment.environment_id = "env-new".into();
    input.proposal.environment = input.environment.clone();
    input.proposal.applicability.environment_id = "env-new".into();
    for dimension in input
        .proposal
        .comparison
        .dimensions
        .iter_mut()
        .chain(input.proposal.trigger.iter_mut())
    {
        if dimension.name == "environment" {
            dimension.value =
                eliot_dreamer_contracts::FailureDimensionValue::Text("env-new".into());
        }
    }
    input.proposal.history = input.history.clone();
    input.validate().expect("changed typed trigger validates");
    let changed = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("changed typed trigger remains assessable");
    assert_ne!(
        changed.assessment.current_trigger_digest,
        original_trigger_digest
    );
    assert_eq!(changed.assessment.counts.history_trigger_match_count, 0);
}

#[test]
fn unknown_effect_is_not_semantic_failure() {
    let (mut input, policy) = prepared();
    input.action_evidence.outcome.failure_state =
        Some(eliot_dreamer_contracts::FailureObservationState::UnknownOutcome);
    input.history.coverage = eliot_dreamer_contracts::FailureCoverage::Partial;
    input.proposal.outcome = input.action_evidence.outcome.clone();
    input.proposal.history = input.history.clone();
    input
        .validate()
        .expect("partial history remains a valid closure");
    let decision = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("unknown effect remains explicit");
    assert_eq!(
        decision.assessment.outcome,
        OutcomeAssessment::UnknownOutcome
    );
    assert_eq!(
        decision.result.common_disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
    let coverage = decision
        .result
        .final_preservation
        .verdicts
        .iter()
        .find(|verdict| {
            verdict.dimension == eliot_dreamer_contracts::RelationPreservationDimension::Coverage
        })
        .expect("coverage predicate is returned");
    assert!(!coverage.passed);
}

#[test]
fn changed_environment_is_narrowed() {
    let (mut input, policy) = prepared();
    input.environment.environment_id = "env-new".into();
    input.proposal.environment = input.environment.clone();
    for dimension in input
        .proposal
        .comparison
        .dimensions
        .iter_mut()
        .chain(input.proposal.trigger.iter_mut())
    {
        if dimension.name == "environment" {
            dimension.value =
                eliot_dreamer_contracts::FailureDimensionValue::Text("env-new".into());
        }
    }
    let decision = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("changed environment remains scoped");
    assert_eq!(
        decision.assessment.applicability,
        ApplicabilityAssessment::ChangedEnvironment
    );
    assert_eq!(
        decision.result.common_disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
}

#[test]
fn policy_digest_is_bound() {
    let (input, policy) = prepared();
    let decision = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("replay fixture succeeds");
    let replay = propose_failure_fingerprint(
        &input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    )
    .expect("replay remains deterministic");
    assert_eq!(decision, replay);
    let mut output_preimage = decision.clone();
    output_preimage.output_digest = "0".repeat(64);
    assert_eq!(
        decision.output_digest,
        digest_hex(&canonical_bytes(&output_preimage).unwrap())
    );
    let mut reordered_input = input.clone();
    reordered_input.proposal.trigger.reverse();
    reordered_input.proposal.comparison.dimensions.reverse();
    reordered_input
        .validate()
        .expect("reordered admitted history validates");
    let reordered = propose_failure_fingerprint(
        &reordered_input,
        &reordered_input.proposal,
        &reordered_input.action_evidence,
        &reordered_input.environment,
        &reordered_input.history,
        &policy,
    )
    .expect("reordered history remains deterministic");
    assert_eq!(decision.decision_id, reordered.decision_id);
    let mut drifted = policy.clone();
    drifted.max_work = drifted.max_work.saturating_sub(1);
    assert!(drifted.validate().is_err());
    assert!(
        propose_failure_fingerprint(
            &input,
            &input.proposal,
            &input.action_evidence,
            &input.environment,
            &input.history,
            &drifted,
        )
        .is_err()
    );
}

// ---- 663 proof helpers (append-only; the 5 tests above are untouched) ----

fn call(
    input: &eliot_dreamer_contracts::FailureInput,
    policy: &eliot_dreamer_failure::FailurePolicy,
) -> Result<eliot_dreamer_failure::FailureHandlerDecision, ContractViolation> {
    propose_failure_fingerprint(
        input,
        &input.proposal,
        &input.action_evidence,
        &input.environment,
        &input.history,
        policy,
    )
}

#[allow(dead_code)]
fn rebind_policy(input: &mut eliot_dreamer_contracts::FailureInput, policy: &eliot_dreamer_failure::FailurePolicy) {
    input.policy_digest.clone_from(&policy.digest);
    input.proposal.policy_digest.clone_from(&policy.digest);
}

#[allow(dead_code)]
fn rebind_job_digest(input: &mut eliot_dreamer_contracts::FailureInput) {
    let digest = digest_hex(&canonical_bytes(&input.job).expect("job bytes"));
    input.item.job_digest = digest;
    let item_digest = input
        .item
        .item_digest(&input.grounded)
        .expect("item digest recomputes");
    input.screen.item_digest = item_digest.clone();
    if let Some(binding) = input.request.screen_binding.as_mut() {
        binding.item_digest = item_digest;
    }
}

fn rebind_history(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.history = input.history.clone();
}

fn rebind_outcome(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.outcome = input.action_evidence.outcome.clone();
}

#[allow(dead_code)]
fn rebind_action(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.action = input.action_evidence.action.clone();
}

fn rebind_environment(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.environment = input.environment.clone();
}

#[allow(dead_code)]
fn resealed_policy(mut policy: eliot_dreamer_failure::FailurePolicy) -> eliot_dreamer_failure::FailurePolicy {
    policy.seal().expect("mutated policy seals");
    policy
}

fn set_declared(
    input: &mut eliot_dreamer_contracts::FailureInput,
    state: FailureObservationState,
) {
    input.action_evidence.outcome.failure_state = Some(state);
    rebind_outcome(input);
}

// WORK_UNIT_CASE: 663/1
#[test]
fn proof_01_exact_block_capable_candidate() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("exact positive path executes");
    assert_eq!(decision.result.disposition, FailureDisposition::Hypothesis);
    assert_eq!(decision.assessment.trigger, TriggerAssessment::Exact);
    assert_eq!(
        decision.assessment.outcome,
        OutcomeAssessment::ExecutedButSemanticallyFailed
    );
    assert_eq!(decision.assessment.applicability, ApplicabilityAssessment::Scoped);
    assert!(decision.assessment.supports_candidate());
    // Candidate-only ceiling: the handler never grants block authority itself;
    // block-capable means the exact trigger/scope/verifier bundle is complete
    // for the external incident owner. Dependency-closure stays unknown by
    // design, so the common disposition remains Partial (advisory ceiling).
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Partial
    );
    assert_eq!(
        decision.result.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert!(decision.result.validate_against(&input).is_ok());
    assert!(decision.preflight().is_ok());
    assert!(!decision.decision_id.is_empty());
    assert_eq!(decision.assessment.missing_evidence_refs.len(), 0);
    assert!(!decision.assessment.evidence_refs.is_empty());
    let coverage = decision
        .result
        .final_preservation
        .verdicts
        .iter()
        .find(|v| v.dimension == eliot_dreamer_contracts::RelationPreservationDimension::Coverage)
        .expect("coverage dimension present");
    assert!(coverage.passed);
}

// WORK_UNIT_CASE: 663/2
#[test]
fn proof_02_advisory_revalidation_from_one_occurrence() {
    let (mut input, policy) = prepared();
    input.history.coverage = FailureCoverage::Partial;
    rebind_history(&mut input);
    input.validate().expect("partial history validates");
    let decision = call(&input, &policy).expect("single-occurrence advisory executes");
    assert_eq!(decision.result.disposition, FailureDisposition::Hypothesis);
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Partial
    );
    assert_eq!(
        decision.result.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert!(!input.proposal.lifecycle.reopen_condition.is_empty());
    assert!(!input.proposal.lifecycle.extinction_condition.is_empty());
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/3
#[test]
fn proof_03_exact_vocabulary() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("vocabulary path executes");
    assert_eq!(
        input.proposal.class,
        eliot_dreamer_contracts::FailureClass::PartialOrUnknownEffect
    );
    assert_eq!(
        input.proposal.comparison.comparator,
        FailureComparator::ExactEquality
    );
    assert_eq!(input.proposal.trigger.len(), 2);
    assert_eq!(
        input.action_evidence.outcome.failure_state,
        Some(FailureObservationState::ExecutedButSemanticallyFailed)
    );
    assert_eq!(input.proposal.violated_invariant, "invariant");
    assert_eq!(input.proposal.lifecycle.reopen_condition, "new evidence");
    assert_eq!(input.proposal.lifecycle.extinction_condition, "superseded");
    assert_eq!(input.proposal.mitigation.owner, "owner");
    assert_eq!(input.proposal.mitigation.safe_reattempt_verifier, "verifier-1");
    assert_eq!(decision.result.proposal.violated_invariant, "invariant");
    assert_eq!(
        decision.result.proposal.lifecycle.reopen_condition,
        "new evidence"
    );
    assert_eq!(
        decision.result.proposal.lifecycle.extinction_condition,
        "superseded"
    );
}

// WORK_UNIT_CASE: 663/4
#[test]
fn proof_04_wrong_curation_kind_payload() {
    let (mut input, policy) = prepared();
    input.item.kind_spelling = "concept".to_owned();
    assert!(matches!(
        call(&input, &policy),
        Err(ContractViolation::KindPayload(_))
    ));
    let (mut input, policy) = prepared();
    if let eliot_dreamer_contracts::curation::CurationPayload::Failure(payload) =
        &mut input.item.payload
    {
        payload.fingerprint = "other-fp".to_owned();
    }
    assert!(call(&input, &policy).is_err());
}

// WORK_UNIT_CASE: 663/5
#[test]
fn proof_05_task_scope_fence_bundle_mismatch() {
    let (mut input, policy) = prepared();
    input.operation.task_id = "other-task".to_owned();
    assert!(call(&input, &policy).is_err());
    let (mut input, policy) = prepared();
    input.operation.scope_id = "other-scope".to_owned();
    assert!(call(&input, &policy).is_err());
    let (mut input, policy) = prepared();
    input.bundle.manifest_digest = "f".repeat(64);
    assert!(call(&input, &policy).is_err());
    let (mut input, policy) = prepared();
    input.grounded.draft_digest = "e".repeat(64);
    assert!(call(&input, &policy).is_err());
}

// WORK_UNIT_CASE: 663/6
#[test]
fn proof_06_duplicate_and_same_id_changed_payload() {
    let (mut input, policy) = prepared();
    let dup = input.history.entries[0].history_id.clone();
    input.history.entries[1].history_id = dup;
    rebind_history(&mut input);
    assert!(call(&input, &policy).is_err());
    let (input, policy) = prepared();
    let mut changed = input.proposal.clone();
    changed.signature = "changed-sig".to_owned();
    let err = propose_failure_fingerprint(
        &input,
        &changed,
        &input.action_evidence,
        &input.environment,
        &input.history,
        &policy,
    );
    assert!(matches!(
        err,
        Err(ContractViolation::BindingMismatch { field, .. })
            if field == "failure.grounded_failure_draft"
    ));
}

// WORK_UNIT_CASE: 663/7
#[test]
fn proof_07_requested_admitted_attempted_observed_verified() {
    let (mut input, policy) = prepared();
    let decision = call(&input, &policy).expect("distinction baseline executes");
    assert_eq!(decision.result.handler_result.request_id, "req-1");
    assert_eq!(input.operation.request_id, "req-1");
    assert_eq!(input.operation.attempt_id, "attempt-1");
    assert_eq!(input.operation.candidate_id, "cand-1");
    assert_ne!(
        input.action_evidence.action_operation.request_id,
        input.operation.request_id
    );
    assert_eq!(decision.assessment.declared_outcome_state, Some(FailureObservationState::ExecutedButSemanticallyFailed));
    set_declared(&mut input, FailureObservationState::VerifierFailed);
    input.validate().expect("declared-only change validates");
    let changed = call(&input, &policy).expect("declared change executes");
    assert_eq!(changed.assessment.declared_outcome_state, Some(FailureObservationState::VerifierFailed));
    assert_eq!(changed.assessment.outcome, OutcomeAssessment::VerifierFailed);
    assert_ne!(changed.assessment.outcome, decision.assessment.outcome);
}

// WORK_UNIT_CASE: 663/8
#[test]
fn proof_08_policy_rejection_vs_mechanism_failure() {
    let (mut input, policy) = prepared();
    set_declared(&mut input, FailureObservationState::Rejected);
    input.validate().expect("rejected declaration validates");
    let decision = call(&input, &policy).expect("rejected path executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::Rejected);
    assert_eq!(decision.result.disposition, FailureDisposition::Abstention);
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Abstention
    );
    assert!(!decision.assessment.causal.causal_claim_permitted);
}

// WORK_UNIT_CASE: 663/9
#[test]
fn proof_09_infrastructure_unavailable_vs_semantic_failure() {
    let (mut input, policy) = prepared();
    set_declared(&mut input, FailureObservationState::Unavailable);
    input.validate().expect("unavailable declaration validates");
    let decision = call(&input, &policy).expect("unavailable path executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::Unavailable);
    assert_eq!(decision.result.disposition, FailureDisposition::Abstention);
    assert_ne!(
        decision.assessment.outcome,
        OutcomeAssessment::ExecutedButSemanticallyFailed
    );
}

// WORK_UNIT_CASE: 663/10
#[test]
fn proof_10_tool_response_without_semantic_verifier() {
    let (mut input, policy) = prepared();
    for evidence in input
        .action_evidence
        .evidence
        .iter_mut()
        .chain(input.history.historical_evidence.iter_mut())
    {
        if evidence.evidence_id == "e-1" {
            evidence.kind = eliot_dreamer_contracts::FailureEvidenceKind::Attempt;
        }
    }
    rebind_history(&mut input);
    input.validate().expect("non-semantic evidence validates");
    let decision = call(&input, &policy).expect("missing-verifier path executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::UnknownOutcome);
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Partial
    );
    assert_ne!(
        decision.assessment.outcome,
        OutcomeAssessment::ExecutedButSemanticallyFailed
    );
}

// WORK_UNIT_CASE: 663/11
#[test]
fn proof_11_partial_unknown_external_effect() {
    let (mut input, policy) = prepared();
    input.action_evidence.coverage = FailureCoverage::Partial;
    input.action_evidence.outcome.coverage = FailureCoverage::Partial;
    input.history.coverage = FailureCoverage::Partial;
    rebind_outcome(&mut input);
    rebind_history(&mut input);
    input.validate().expect("partial coverages validate");
    let decision = call(&input, &policy).expect("partial effect executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::UnknownOutcome);
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Partial
    );
    let coverage = decision
        .result
        .final_preservation
        .verdicts
        .iter()
        .find(|v| v.dimension == eliot_dreamer_contracts::RelationPreservationDimension::Coverage)
        .expect("coverage present");
    assert!(!coverage.passed);
}

// WORK_UNIT_CASE: 663/12
#[test]
fn proof_12_missing_failed_verifier() {
    let (mut input, policy) = prepared();
    set_declared(&mut input, FailureObservationState::VerifierFailed);
    input.validate().expect("verifier-failed declares");
    let decision = call(&input, &policy).expect("verifier-failed executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::VerifierFailed);
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    let (mut input, policy) = prepared();
    input.proposal.mitigation.verifier_digest = "ff".repeat(32);
    assert!(call(&input, &policy).is_err());
    let (mut input, policy) = prepared();
    input.proposal.mitigation.verifier_revision = "0.9.0".to_owned();
    assert!(call(&input, &policy).is_err());
}

// WORK_UNIT_CASE: 663/13
#[test]
fn proof_13_exact_violated_invariant() {
    let (input, policy) = prepared();
    let baseline = call(&input, &policy).expect("invariant baseline executes");
    assert_eq!(input.proposal.violated_invariant, "invariant");
    assert_eq!(baseline.result.proposal.violated_invariant, "invariant");
    let mut changed = input.clone();
    changed.proposal.violated_invariant = "other-invariant".to_owned();
    changed.validate().expect("changed invariant validates");
    let other = call(&changed, &policy).expect("changed invariant executes");
    assert_ne!(
        baseline.assessment.current_trigger_digest,
        other.assessment.current_trigger_digest
    );
    assert_ne!(baseline.decision_id, other.decision_id);
}

// WORK_UNIT_CASE: 663/14
#[test]
fn proof_14_incomplete_instrumentation_unknown() {
    let (mut input, policy) = prepared();
    input.action_evidence.coverage = FailureCoverage::Unknown;
    input.action_evidence.outcome.coverage = FailureCoverage::Unknown;
    input.action_evidence.outcome.failure_state = Some(FailureObservationState::UnknownOutcome);
    rebind_outcome(&mut input);
    input.validate().expect("unknown instrumentation validates");
    let decision = call(&input, &policy).expect("unknown path executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::UnknownOutcome);
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    assert_ne!(
        decision.assessment.outcome,
        OutcomeAssessment::ExecutedButSemanticallyFailed
    );
}

// WORK_UNIT_CASE: 663/15
#[test]
fn proof_15_exact_trigger_positive() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("exact trigger executes");
    assert_eq!(decision.assessment.trigger, TriggerAssessment::Exact);
    assert_eq!(
        input.proposal.comparison.comparator,
        FailureComparator::ExactEquality
    );
    assert!(input.proposal.comparison.missing_dimensions.is_empty());
    assert!(!input.proposal.comparison.dimensions.is_empty());
    assert_eq!(
        input.proposal.trigger.len(),
        input.proposal.comparison.dimensions.len()
    );
    assert_eq!(decision.assessment.current_trigger_digest.len(), 64);
    assert!(decision.assessment.supports_candidate());
}

// WORK_UNIT_CASE: 663/16
#[test]
fn proof_16_near_match_control_not_blocked() {
    let (mut input, policy) = prepared();
    input.history.entries[0].near_match = true;
    input.history.near_match_count = 1;
    rebind_history(&mut input);
    input.validate().expect("near-match history validates");
    let decision = call(&input, &policy).expect("near-match control executes");
    assert_eq!(decision.assessment.counts.near_match_count, 1);
    assert_ne!(decision.result.disposition, FailureDisposition::Blocked);
    assert_ne!(
        decision.result.common_disposition,
        CandidateDisposition::Blocked
    );
    assert_eq!(decision.assessment.counts.semantic_success_count, 1);
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/17
#[test]
fn proof_17_missing_trigger_field_restricts() {
    let (mut input, policy) = prepared();
    input.proposal.trigger.retain(|d| d.name != "target");
    input.proposal.comparison.dimensions.retain(|d| d.name != "target");
    input.proposal.comparison.missing_dimensions = vec!["target".to_owned()];
    input.validate().expect("missing dimension validates");
    let decision = call(&input, &policy).expect("missing trigger executes");
    assert_eq!(decision.assessment.trigger, TriggerAssessment::Missing);
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    assert!(!decision.assessment.supports_candidate());
}

// WORK_UNIT_CASE: 663/18
#[test]
fn proof_18_changed_environment_requires_revalidation() {
    let (mut input, policy) = prepared();
    input.environment.environment_id = "env-new".to_owned();
    rebind_environment(&mut input);
    for dimension in input
        .proposal
        .trigger
        .iter_mut()
        .chain(input.proposal.comparison.dimensions.iter_mut())
    {
        if dimension.name == "environment" {
            dimension.value = FailureDimensionValue::Text("env-new".to_owned());
        }
    }
    input.validate().expect("changed environment validates");
    let decision = call(&input, &policy).expect("changed env executes");
    assert_eq!(
        decision.assessment.applicability,
        ApplicabilityAssessment::ChangedEnvironment
    );
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    let mut tooled = input.clone();
    tooled.environment.tool_revision = "tool-v2".to_owned();
    tooled.proposal.environment.tool_revision = "tool-v2".to_owned();
    tooled.validate().expect("retooled env validates");
    let retooled = call(&tooled, &policy).expect("retooled executes");
    assert_eq!(
        retooled.assessment.applicability,
        ApplicabilityAssessment::ChangedEnvironment
    );
}

// WORK_UNIT_CASE: 663/19
#[test]
fn proof_19_scope_target_effect_leakage() {
    let (mut input, policy) = prepared();
    input.proposal.applicability.target_id = "b".to_owned();
    input.validate().expect("leaked target validates as scoped input");
    let decision = call(&input, &policy).expect("leakage check executes");
    assert_eq!(
        decision.assessment.applicability,
        ApplicabilityAssessment::ScopeMismatch
    );
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    // Scope leakage narrows applicability without rewriting the exact
    // failure observation: the outcome stays semantic-failure while the
    // candidate is withheld from Hypothesis.
    assert_eq!(
        decision.assessment.outcome,
        OutcomeAssessment::ExecutedButSemanticallyFailed
    );
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/20
#[test]
fn proof_20_counts_cannot_prove_causality() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("causal ceiling executes");
    assert_eq!(
        decision.assessment.causal.status,
        eliot_dreamer_contracts::FailureCausalStatus::Unknown
    );
    assert!(!decision.assessment.causal.may_describe_correlation);
    assert!(!decision.assessment.causal.causal_claim_permitted);
    assert!(decision
        .assessment
        .causal
        .limitation_refs
        .contains(&"causal_mechanism_requires_intervention_evidence".to_owned()));
    assert_eq!(decision.assessment.counts.represented_total, 2);
    assert_eq!(decision.assessment.counts.independent_count, 2);
}

// WORK_UNIT_CASE: 663/21
#[test]
fn proof_21_causal_rivals_confounders() {
    let (mut input, policy) = prepared();
    input.proposal.causal.rival_refs = vec!["e-1".to_owned()];
    input.proposal.causal.confounder_refs = vec!["history-evidence".to_owned()];
    input.validate().expect("rival/confounder refs validate");
    let decision = call(&input, &policy).expect("rival path executes");
    assert_eq!(
        decision.result.proposal.causal.rival_refs,
        vec!["e-1".to_owned()]
    );
    assert_eq!(
        decision.result.proposal.causal.confounder_refs,
        vec!["history-evidence".to_owned()]
    );
    assert_eq!(
        decision.assessment.causal.status,
        eliot_dreamer_contracts::FailureCausalStatus::Unknown
    );
    assert!(!decision.assessment.causal.causal_claim_permitted);
}

// WORK_UNIT_CASE: 663/22
#[test]
fn proof_22_empirical_unknown_mechanism_lower_ceiling() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("empirical path executes");
    assert_eq!(
        decision.assessment.causal.status,
        eliot_dreamer_contracts::FailureCausalStatus::Unknown
    );
    assert_eq!(
        decision.result.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert_eq!(
        decision.result.handler_result.disposition,
        decision.result.common_disposition
    );
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/23
#[test]
fn proof_23_dependent_repetitions_do_not_inflate() {
    let (mut input, policy) = prepared();
    input.history.entries[0].independent = false;
    rebind_history(&mut input);
    input.validate().expect("dependent history validates");
    let decision = call(&input, &policy).expect("dependent path executes");
    assert_eq!(decision.assessment.counts.independent_count, 1);
    assert_eq!(decision.assessment.counts.represented_total, 2);
    assert_eq!(decision.result.disposition, FailureDisposition::Hypothesis);
}

// WORK_UNIT_CASE: 663/24
#[test]
fn proof_24_exact_recurrence_denominator() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("denominator executes");
    assert_eq!(input.history.expected_total, 2);
    assert_eq!(decision.assessment.counts.expected_total, 2);
    assert_eq!(decision.assessment.counts.represented_total, 2);
    assert_eq!(decision.assessment.counts.success_count, 1);
    let mut bad = input.clone();
    bad.history.expected_total = 99;
    bad.proposal.history.expected_total = 99;
    assert!(call(&bad, &policy).is_err());
}

// WORK_UNIT_CASE: 663/25
#[test]
fn proof_25_same_trigger_success_retained() {
    let (mut input, policy) = prepared();
    let baseline = call(&input, &policy).expect("baseline executes");
    let digest = baseline.assessment.current_trigger_digest.clone();
    input.history.entries[1].fingerprint_id = input.proposal.fingerprint.clone();
    input.history.entries[1].trigger_digest = digest.clone();
    rebind_history(&mut input);
    input.validate().expect("same-trigger success validates");
    let decision = call(&input, &policy).expect("same-trigger executes");
    assert_eq!(decision.assessment.counts.history_trigger_success_count, 1);
    assert_eq!(decision.assessment.counts.success_count, 1);
    assert_eq!(decision.assessment.counts.semantic_success_count, 1);
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/26
#[test]
fn proof_26_false_activations_narrow_candidate() {
    let (mut input, policy) = prepared();
    input.history.entries[0].false_activation = true;
    input.history.false_activation_count = 1;
    rebind_history(&mut input);
    input.validate().expect("false-activation validates");
    let decision = call(&input, &policy).expect("false-activation executes");
    assert_eq!(decision.assessment.counts.false_activation_count, 1);
    assert!(!decision.assessment.supports_candidate());
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
    assert!(decision
        .assessment
        .causal
        .limitation_refs
        .contains(&"false_activation_history_retained".to_owned()));
}

// WORK_UNIT_CASE: 663/27
#[test]
fn proof_27_partial_history_no_always_fails() {
    let (mut input, policy) = prepared();
    input.history.coverage = FailureCoverage::Partial;
    input.proposal.history.coverage = FailureCoverage::Partial;
    rebind_history(&mut input);
    input.validate().expect("partial history validates");
    let decision = call(&input, &policy).expect("partial executes");
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Partial
    );
    assert_eq!(decision.assessment.counts.success_count, 1);
    let coverage = decision
        .result
        .final_preservation
        .verdicts
        .iter()
        .find(|v| v.dimension == eliot_dreamer_contracts::RelationPreservationDimension::Coverage)
        .expect("coverage present");
    assert!(!coverage.passed);
}

// WORK_UNIT_CASE: 663/28
#[test]
fn proof_28_mitigation_owner_verifier_required() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("mitigation executes");
    assert_eq!(decision.result.proposal.mitigation.owner, "owner");
    assert_eq!(
        decision.result.proposal.mitigation.safe_reattempt_verifier,
        "verifier-1"
    );
    assert!(!decision.result.proposal.mitigation.do_not_repeat_until.is_empty());
    let (mut input, policy) = prepared();
    input.proposal.mitigation.owner = String::new();
    assert!(call(&input, &policy).is_err());
}

// WORK_UNIT_CASE: 663/29
#[test]
fn proof_29_reopen_condition_required() {
    let (input, policy) = prepared();
    assert_eq!(input.proposal.lifecycle.reopen_condition, "new evidence");
    let decision = call(&input, &policy).expect("reopen executes");
    assert_eq!(
        decision.result.proposal.lifecycle.reopen_condition,
        "new evidence"
    );
    let (mut input, policy) = prepared();
    input.proposal.lifecycle.reopen_condition = String::new();
    assert!(call(&input, &policy).is_err());
}

// WORK_UNIT_CASE: 663/30
#[test]
fn proof_30_extinction_condition_expiry_required() {
    let (input, policy) = prepared();
    assert_eq!(
        input.proposal.lifecycle.extinction_condition,
        "superseded"
    );
    let decision = call(&input, &policy).expect("extinction executes");
    assert_eq!(
        decision.result.proposal.lifecycle.extinction_condition,
        "superseded"
    );
    let (mut input, policy) = prepared();
    input.proposal.lifecycle.extinction_condition = String::new();
    assert!(call(&input, &policy).is_err());
    let (mut input, policy) = prepared();
    input.proposal.lifecycle.expiry_ms = Some(1_000);
    input.validate().expect("expiry validates");
    let with_expiry = call(&input, &policy).expect("expiry executes");
    assert_eq!(with_expiry.result.proposal.lifecycle.expiry_ms, Some(1_000));
}

// WORK_UNIT_CASE: 663/31
#[test]
fn proof_31_absent_instrumentation_no_extinction() {
    let (mut input, policy) = prepared();
    input.history.coverage = FailureCoverage::Unknown;
    input.action_evidence.coverage = FailureCoverage::Partial;
    input.action_evidence.outcome.coverage = FailureCoverage::Partial;
    input.action_evidence.outcome.failure_state = Some(FailureObservationState::UnknownOutcome);
    rebind_outcome(&mut input);
    rebind_history(&mut input);
    input.validate().expect("absent instrumentation validates");
    let decision = call(&input, &policy).expect("absent path executes");
    assert_eq!(decision.assessment.outcome, OutcomeAssessment::UnknownOutcome);
    assert_ne!(decision.result.disposition, FailureDisposition::Extinguished);
    assert_ne!(decision.result.disposition, FailureDisposition::Stale);
    assert_eq!(decision.result.disposition, FailureDisposition::Partial);
}

// WORK_UNIT_CASE: 663/32
#[test]
fn proof_32_extinction_retains_history() {
    let (mut input, policy) = prepared();
    input.proposal.lifecycle.raw_history_refs =
        vec!["history-failed".to_owned(), "history-control".to_owned()];
    input.validate().expect("raw history refs validate");
    let decision = call(&input, &policy).expect("retention executes");
    assert_eq!(decision.result.input.history.entries.len(), 2);
    assert_eq!(decision.result.proposal.history.entries.len(), 2);
    assert!(decision
        .result
        .rollback
        .raw_history_refs
        .contains(&"history-failed".to_owned()));
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/33
#[test]
fn proof_33_exact_duplicate_idempotent_replay() {
    let (input, policy) = prepared();
    let first = call(&input, &policy).expect("first executes");
    let second = call(&input, &policy).expect("second executes");
    assert_eq!(first, second);
    assert_eq!(first.decision_id, second.decision_id);
    assert_eq!(first.output_digest, second.output_digest);
    let mut dup = input.clone();
    let digest = first.assessment.current_trigger_digest.clone();
    dup.history.entries[0].fingerprint_id = dup.proposal.fingerprint.clone();
    dup.history.entries[0].trigger_digest = digest;
    dup.history.entries[0].near_match = false;
    rebind_history(&mut dup);
    dup.validate().expect("duplicate history validates");
    let with_dup = call(&dup, &policy).expect("duplicate executes");
    assert_eq!(with_dup.assessment.counts.history_trigger_match_count, 1);
    let replay = call(&dup, &policy).expect("duplicate replay executes");
    assert_eq!(with_dup, replay);
}

// WORK_UNIT_CASE: 663/34
#[test]
fn proof_34_narrowing_refinement_with_predecessor() {
    let (mut input, policy) = prepared();
    let predecessor = "ab".repeat(32);
    input.proposal.lifecycle.predecessor_fingerprint = Some(predecessor.clone());
    input.proposal.lifecycle.current_fingerprint_revision = "r2".to_owned();
    input.validate().expect("predecessor validates");
    let decision = call(&input, &policy).expect("predecessor executes");
    assert_eq!(decision.result.rollback.predecessor, Some(predecessor));
    assert_eq!(
        decision.result.proposal.lifecycle.current_fingerprint_revision,
        "r2"
    );
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/35
#[test]
fn proof_35_unsupported_broadening() {
    let (mut input, policy) = prepared();
    input.proposal.comparison.comparator = FailureComparator::Unsupported;
    input.proposal.comparison.definition.comparator = FailureComparator::Unsupported;
    // Recompute the retained definition bytes so the join still validates and
    // the assessment reaches Unsupported on semantic grounds, not on a
    // malformed envelope.
    let rebuilt = eliot_dreamer_contracts::FailureProfileDefinition::from_parts(
        input.proposal.comparison.definition.owner.clone(),
        input.proposal.comparison.definition.profile_id.clone(),
        input.proposal.comparison.definition.schema_version,
        input.proposal.comparison.definition.revision.clone(),
        FailureComparator::Unsupported,
        input
            .proposal
            .comparison
            .definition
            .descriptors
            .clone(),
        input.proposal.comparison.definition.source_handle.clone(),
    )
    .expect("unsupported definition rebuilds");
    let old_digest = input.proposal.comparison.definition.definition_digest.clone();
    let old_handle = input.proposal.comparison.definition.source_handle.clone();
    input.proposal.comparison.definition = rebuilt;
    for member in input.source_members.iter_mut() {
        if member.handle == old_handle {
            member.bytes = input.proposal.comparison.definition.definition_bytes.clone();
            member.digest = input.proposal.comparison.definition.definition_digest.clone();
        }
    }
    for material in input.bundle.materials.iter_mut() {
        if material.handle == old_handle {
            material.digest = input.proposal.comparison.definition.definition_digest.clone();
            material.bytes = input.proposal.comparison.definition.definition_bytes.len() as u64;
        }
    }
    assert_ne!(old_digest, input.proposal.comparison.definition.definition_digest);
    input.validate().expect("unsupported profile validates");
    let decision = call(&input, &policy).expect("unsupported executes");
    assert_eq!(decision.assessment.trigger, TriggerAssessment::Unsupported);
    assert_eq!(decision.result.disposition, FailureDisposition::Unsupported);
    assert!(!decision.assessment.supports_candidate());
}

// WORK_UNIT_CASE: 663/36
#[test]
fn proof_36_contradictory_history_preserved() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("contradiction executes");
    assert_eq!(decision.assessment.counts.success_count, 1);
    assert_eq!(decision.assessment.counts.semantic_success_count, 1);
    assert_eq!(decision.result.input.history.entries.len(), 2);
    let failed = decision
        .result
        .input
        .history
        .entries
        .iter()
        .find(|e| !e.semantic_success)
        .expect("failed entry retained");
    let success = decision
        .result
        .input
        .history
        .entries
        .iter()
        .find(|e| e.semantic_success)
        .expect("success entry retained");
    assert_ne!(failed.fingerprint_id, success.fingerprint_id);
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/37
#[test]
fn proof_37_extinguished_no_silent_reactivation() {
    let (input, policy) = prepared();
    let baseline = call(&input, &policy).expect("baseline executes");
    assert_eq!(baseline.assessment.counts.history_trigger_match_count, 0);
    // A new invariant yields a new trigger digest without matching history:
    // the old fingerprint is retained, never silently reactivated.
    let mut changed = input.clone();
    changed.proposal.violated_invariant = "fp-new-invariant".to_owned();
    changed.validate().expect("new invariant validates");
    let other = call(&changed, &policy).expect("new invariant executes");
    assert_ne!(baseline.decision_id, other.decision_id);
    assert_ne!(
        baseline.assessment.current_trigger_digest,
        other.assessment.current_trigger_digest
    );
    assert_eq!(other.assessment.counts.history_trigger_match_count, 0);
    assert_eq!(other.result.input.history.entries.len(), 2);
}

// WORK_UNIT_CASE: 663/38
#[test]
fn proof_38_repair_handoff_only() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("handoff executes");
    assert!(decision.result.rollback.note.contains("candidate-only"));
    assert_eq!(
        decision.result.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert_ne!(decision.result.disposition, FailureDisposition::Blocked);
    assert!(decision.result.validate_against(&input).is_ok());
}

// WORK_UNIT_CASE: 663/39
#[test]
fn proof_39_seven_preservation_dimensions_no_a05_invoke() {
    let (input, policy) = prepared();
    let decision = call(&input, &policy).expect("preservation executes");
    assert_eq!(decision.result.preservation.verdicts.len(), 7);
    assert_eq!(decision.result.final_preservation.verdicts.len(), 7);
    assert_eq!(input.preservation, input.proposal.preservation);
    assert_eq!(input.item.receipt.validator_contract, "a05-validator");
    let replay = call(&input, &policy).expect("replay executes");
    assert_eq!(decision, replay);
}

// WORK_UNIT_CASE: 663/40
#[test]
fn proof_40_partial_budget_deadline_cancellation() {
    let (input, policy) = prepared();
    let mut cancelled = policy.clone();
    cancelled.cancellation_requested = true;
    let cancelled = resealed_policy(cancelled);
    let mut cancelled_input = input.clone();
    rebind_policy(&mut cancelled_input, &cancelled);
    cancelled_input
        .validate()
        .expect("cancellation input validates");
    let decision =
        call(&cancelled_input, &cancelled).expect("cancellation executes");
    assert_eq!(decision.result.disposition, FailureDisposition::Cancelled);
    assert_eq!(
        decision.result.common_disposition,
        CandidateDisposition::Abstention
    );
    let (mut input, policy) = prepared();
    input.job.budget.candidates = Some(0);
    rebind_job_digest(&mut input);
    // Zero candidates authorizes no work: the envelope itself is rejected,
    // and the handler independently refuses with a Budget error (no panic).
    assert!(matches!(
        call(&input, &policy),
        Err(ContractViolation::Budget { .. })
    ));
    let (mut input, policy) = prepared();
    input.job.deadline_ms = Some(1_000);
    rebind_job_digest(&mut input);
    input.validate().expect("deadline input validates as envelope");
    assert!(matches!(
        call(&input, &policy),
        Err(ContractViolation::Budget { .. })
    ));
}
