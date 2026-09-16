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

fn rebind_policy(input: &mut eliot_dreamer_contracts::FailureInput, policy: &eliot_dreamer_failure::FailurePolicy) {
    input.policy_digest.clone_from(&policy.digest);
    input.proposal.policy_digest.clone_from(&policy.digest);
}

fn rebind_job_digest(input: &mut eliot_dreamer_contracts::FailureInput) {
    let digest = digest_hex(&canonical_bytes(&input.job).expect("job bytes"));
    input.item.job_digest = digest;
}

fn rebind_history(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.history = input.history.clone();
}

fn rebind_outcome(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.outcome = input.action_evidence.outcome.clone();
}

fn rebind_action(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.action = input.action_evidence.action.clone();
}

fn rebind_environment(input: &mut eliot_dreamer_contracts::FailureInput) {
    input.proposal.environment = input.environment.clone();
}

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
    assert_eq!(decision.assessment.causal.causal_claim_permitted, false);
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
