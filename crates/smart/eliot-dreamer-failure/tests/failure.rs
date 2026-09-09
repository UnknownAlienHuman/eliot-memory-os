#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use eliot_dreamer_contracts::{canonical_bytes, digest_hex};
use eliot_dreamer_failure::{
    ApplicabilityAssessment, FailureDisposition, OutcomeAssessment, TriggerAssessment,
    propose_failure_fingerprint,
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
