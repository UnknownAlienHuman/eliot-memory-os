#![allow(clippy::unwrap_used)]

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_dreamer_contracts::{
    FailureAction, FailureActionEvidence, FailureComparator, FailureComparisonProfile,
    FailureCoverage, FailureDimension, FailureDimensionDescriptor, FailureDimensionSource,
    FailureDimensionValue, FailureEvidence, FailureEvidenceKind, FailureHistory,
    FailureHistoryEntry, FailureObservationState, FailureOperation, FailureOutcome,
    FailureProfileDefinition, Requester, RequesterOrigin,
};

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
fn operation() -> FailureOperation {
    FailureOperation {
        operation_id: "op-1".into(),
        idempotency_key: "idem-1".into(),
        request_id: "req-1".into(),
        candidate_id: "cand-1".into(),
        attempt_id: "attempt-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".into(),
            session: None,
        },
    }
}
fn action() -> FailureAction {
    FailureAction {
        action_id: "action-1".into(),
        operation_id: "op-1".into(),
        attempt_id: "attempt-1".into(),
        target_id: "target-1".into(),
        input_schema: "schema-1".into(),
        input_digest: "a".repeat(64),
        effect_id: "effect-1".into(),
        effect_class: eliot_receipts::EffectClass::Candidate,
        owner: "owner-1".into(),
        contract_revision: "r1".into(),
        contract_digest: "b".repeat(64),
    }
}
fn outcome() -> FailureOutcome {
    use eliot_dreamer_contracts::{FailureExpectation, FailureExpectedState};
    use eliot_receipts::ReceiptDisposition;
    FailureOutcome {
        intended: FailureExpectation {
            expected: FailureExpectedState::Failure,
            verifier: "verify-1".into(),
        },
        attempted: Some(FailureExpectation {
            expected: FailureExpectedState::Failure,
            verifier: "verify-1".into(),
        }),
        observed: ReceiptDisposition::Unknown {
            reason: "effect unavailable".into(),
        },
        verified: ReceiptDisposition::Unknown {
            reason: "verification unavailable".into(),
        },
        failure_state: None,
        observed_receipt_ref: None,
        verified_receipt_ref: None,
        output_digest: None,
        possible_effects: vec!["unknown".into()],
        receipt_refs: vec![],
        coverage: FailureCoverage::Partial,
    }
}

fn profile_definition() -> FailureProfileDefinition {
    FailureProfileDefinition::from_parts(
        "profile-owner".into(),
        "exact-v1".into(),
        1,
        "profile-r1".into(),
        FailureComparator::ExactEquality,
        vec![
            FailureDimensionDescriptor {
                source: FailureDimensionSource::Action,
                field: "target_id".into(),
                name: "target".into(),
            },
            FailureDimensionDescriptor {
                source: FailureDimensionSource::Action,
                field: "input_digest".into(),
                name: "input".into(),
            },
            FailureDimensionDescriptor {
                source: FailureDimensionSource::Environment,
                field: "environment_id".into(),
                name: "environment".into(),
            },
        ],
        "profile".into(),
    )
    .unwrap()
}

#[test]
fn exact_profile_keeps_missing_dimensions_explicit() {
    let profile = FailureComparisonProfile {
        profile_id: "exact-v1".into(),
        schema_version: 1,
        comparator: FailureComparator::ExactEquality,
        definition: profile_definition(),
        dimensions: vec![
            FailureDimension {
                source: FailureDimensionSource::Action,
                field: "target_id".into(),
                name: "target".into(),
                value: FailureDimensionValue::Text("target-1".into()),
            },
            FailureDimension {
                source: FailureDimensionSource::Action,
                field: "input_digest".into(),
                name: "input".into(),
                value: FailureDimensionValue::Digest("a".repeat(64)),
            },
        ],
        missing_dimensions: vec!["environment".into()],
    };
    assert!(profile.validate().is_ok());
    let mut bad = profile;
    bad.missing_dimensions.push("target".into());
    assert!(bad.validate().is_err());
}

#[test]
fn duplicate_evidence_is_rejected_before_a_join_can_pass() {
    let op = operation();
    let a = action();
    let e = FailureEvidence {
        evidence_id: "e-1".into(),
        kind: FailureEvidenceKind::Attempt,
        operation_id: "op-1".into(),
        request_id: "request-1".into(),
        idempotency_key: "idem-1".into(),
        action_id: "action-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        digest: "c".repeat(64),
        envelope_digest: "d".repeat(64),
        material_handle: "material-1".into(),
        material_digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        material_bytes: vec![0; 0],
        owner: "owner-1".into(),
        coverage: FailureCoverage::Complete,
    };
    let value = FailureActionEvidence {
        action_operation: op,
        action: a,
        outcome: outcome(),
        evidence: vec![e.clone(), e],
        receipts: vec![],
        receipt_materials: vec![],
        evidence_envelopes: vec![],
        omitted_envelope_refs: vec!["d".repeat(64)],
        coverage: FailureCoverage::Partial,
    };
    assert!(value.validate().is_err());
}

#[test]
fn history_preserves_unknown_and_false_activation_counts() {
    let entry = FailureHistoryEntry {
        history_id: "h-1".into(),
        operation_id: "op-1".into(),
        request_id: "request-1".into(),
        idempotency_key: "idem-1".into(),
        fingerprint_id: "fp-1".into(),
        trigger_digest: "d".repeat(64),
        outcome: eliot_receipts::ReceiptDisposition::Unknown {
            reason: "not observed".into(),
        },
        failure_state: Some(FailureObservationState::UnknownOutcome),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        independent: true,
        semantic_success: false,
        near_match: false,
        false_activation: true,
        observed: true,
        evidence_refs: vec![],
        receipt_refs: vec![],
        coverage: FailureCoverage::Partial,
    };
    let history = FailureHistory {
        coverage: FailureCoverage::Partial,
        expected_total: 1,
        entries: vec![entry],
        omitted_refs: vec![],
        success_count: 0,
        near_match_count: 0,
        false_activation_count: 1,
        unknown_count: 1,
        receipts: vec![],
        receipt_materials: vec![],
        historical_evidence: vec![],
        historical_evidence_envelopes: vec![],
        omitted_evidence_envelope_refs: vec![],
    };
    assert!(history.validate().is_ok());
    assert_eq!(history.coverage, FailureCoverage::Partial);
}
