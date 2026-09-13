//! Proportionate first-pass classifier fixtures for issue #217.
//!
//! These integration tests exercise only the public Governor admission edge
//! (`admit_record_family_v2`, `ObservationSubmission::validate` via
//! `ObservationJournal::admit`). They cover the previously missing rows:
//! determinism, ambiguous fallback preservation, no epistemic promotion, and
//! exact replay identity, plus fail-closed conflicting-hint behavior.

use eliot_contracts::{ClockReading, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_observation::{
    AmbiguousOrdinaryRecordV2, CandidateDisposition, CaptureMode, CaptureRoute,
    CoverageDisposition, CoverageEvidence, CoverageInterval, Durability,
    ObservationAdmissionResult, ObservationEventCore, ObservationEventIdentity, ObservationJournal,
    ObservationKind, ObservationRecordEnvelope, ObservationRecordEnvelopeV2, ObservationRecordKind,
    ObservationScope, ObservationSubmission, PrivacyRetentionDisclosure, ProducerTrace,
    RecordFamilyClassification, RecordFamilyPayloadV2, admit_record_family_v2,
};
use eliot_observation_contracts::{AuditRecord, TelemetryRecord};

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn fence() -> StateFence {
    StateFence::new(
        test_epoch(TEST_LINEAGE_A, 1),
        ResourceGeneration::genesis(),
    )
}

fn event() -> ObservationEventCore {
    let work_scope = "scope:test"
        .parse()
        .unwrap_or_else(|_| panic!("fixture work scope must parse"));
    let interval =
        CoverageInterval::new(1, 1).unwrap_or_else(|_| panic!("fixture interval must be valid"));
    ObservationEventCore {
        event_id_and_time: ObservationEventIdentity {
            event_id: "event:test".to_owned(),
            clock: ClockReading::default(),
        },
        producer_generation_and_trace: ProducerTrace {
            producer: "producer:test".to_owned(),
            generation: "generation:test".to_owned(),
            trace_ref: None,
        },
        kind: ObservationKind::QueueResource,
        affected_scope: ObservationScope {
            work_scope,
            task_ref: None,
            attempt_ref: None,
            module_or_route_ref: None,
        },
        observed_delta: "queue observed".to_owned(),
        expected_baseline: None,
        evidence_and_raw_handles: vec!["raw:test".to_owned()],
        coverage_and_blind_intervals: CoverageEvidence {
            disposition: CoverageDisposition::Complete,
            denominator_source_ref: "denominator:test".to_owned(),
            interval: Some(interval),
            blind_intervals: Vec::new(),
            observed_count: 1,
        },
        privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
            privacy_domain_ref: "privacy:test".to_owned(),
            retention_policy_ref: "retention:test".to_owned(),
            disclosure_class: "internal".to_owned(),
        },
        candidate_importance: 1,
        dedup_key: "dedup:test".to_owned(),
    }
}

fn exact_audit_v2(record_id: &str) -> ObservationRecordEnvelopeV2 {
    ObservationRecordEnvelopeV2 {
        payload: RecordFamilyPayloadV2::Audit(AuditRecord {
            record_id: record_id.to_owned(),
            core: event(),
            audit_action: "checked".to_owned(),
            state_fence: fence(),
        }),
        caller_family_hint: Some(ObservationRecordKind::Audit),
        parent_record_id: None,
    }
}

fn ambiguous_v2(
    record_id: &str,
    hint: Option<ObservationRecordKind>,
) -> ObservationRecordEnvelopeV2 {
    ObservationRecordEnvelopeV2 {
        payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
            record_id: record_id.to_owned(),
            event: event(),
            source_contract_ref: "source:generic".to_owned(),
            ambiguity_reason_ref: "family-fields-unavailable".to_owned(),
        }),
        caller_family_hint: hint,
        parent_record_id: None,
    }
}

fn submission_with_v2(
    operation_id: &str,
    idempotency_key: &str,
    record_id: &str,
    kind: ObservationRecordKind,
    record_v2: Option<ObservationRecordEnvelopeV2>,
) -> ObservationSubmission {
    ObservationSubmission {
        operation_id: operation_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        state_fence: fence(),
        record: ObservationRecordEnvelope {
            record_id: record_id.to_owned(),
            kind,
            event: Some(event()),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        },
        record_v2,
        capture_route: CaptureRoute::OperationalLog,
        durability: Durability::Volatile,
        plan: None,
        task_selection: None,
        evidence: None,
    }
}

#[test]
fn same_input_gives_identical_result() {
    let exact = exact_audit_v2("record:deterministic");
    let first_exact = admit_record_family_v2(&exact)
        .unwrap_or_else(|error| panic!("valid exact record rejected: {error}"));
    let second_exact = admit_record_family_v2(&exact)
        .unwrap_or_else(|error| panic!("valid exact record rejected: {error}"));
    assert_eq!(first_exact, second_exact);
    assert_eq!(
        first_exact,
        eliot_observation::RecordFamilyAdmission::AcceptedExact {
            family: ObservationRecordKind::Audit,
        }
    );

    let ambiguous = ambiguous_v2(
        "record:deterministic-ambiguous",
        Some(ObservationRecordKind::Telemetry),
    );
    let first_ambiguous = admit_record_family_v2(&ambiguous)
        .unwrap_or_else(|error| panic!("valid ambiguous record rejected: {error}"));
    let second_ambiguous = admit_record_family_v2(&ambiguous)
        .unwrap_or_else(|error| panic!("valid ambiguous record rejected: {error}"));
    assert_eq!(first_ambiguous, second_ambiguous);
    assert_eq!(
        first_ambiguous,
        eliot_observation::RecordFamilyAdmission::Cold {
            classification: RecordFamilyClassification::CompatibleHint {
                hinted_family: ObservationRecordKind::Telemetry,
            },
        }
    );
}

#[test]
fn ambiguous_v2_admission_fallback_preserved_as_candidate() {
    let submission = submission_with_v2(
        "operation:ambiguous",
        "idempotency:ambiguous",
        "record:ambiguous",
        ObservationRecordKind::Telemetry,
        Some(ambiguous_v2(
            "record:ambiguous",
            Some(ObservationRecordKind::Telemetry),
        )),
    );
    let mut journal = ObservationJournal::default();
    let result = journal
        .admit(submission)
        .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let ObservationAdmissionResult::Rejected { rejection } = result else {
        panic!("ambiguous material must not be accepted");
    };
    assert!(
        rejection
            .all_contract_errors
            .iter()
            .any(|error| error.contains("non-exact v2 record-family"))
    );
    let fallback = rejection
        .safe_capture_fallback
        .as_ref()
        .unwrap_or_else(|| panic!("ambiguous rejection must preserve a safe candidate"));
    assert_eq!(fallback.disposition, CandidateDisposition::Cold);
    assert_eq!(fallback.record.record_id, "record:ambiguous");
    assert!(fallback.evidence.is_none());
    assert_eq!(journal.snapshot().len(), 1);
}

#[test]
fn no_result_raises_support_assertability_or_influence() {
    let mut journal = ObservationJournal::default();
    let exact_submission = submission_with_v2(
        "operation:epistemic-exact",
        "idempotency:epistemic-exact",
        "record:epistemic-exact",
        ObservationRecordKind::Audit,
        Some(exact_audit_v2("record:epistemic-exact")),
    );
    let exact_result = journal
        .admit(exact_submission)
        .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let ObservationAdmissionResult::Accepted { receipt } = exact_result else {
        panic!("exact material should be accepted");
    };
    assert!(receipt.evidence.is_none());
    assert!(receipt.evidence_digest.is_none());
    assert_eq!(receipt.candidate_disposition, CandidateDisposition::Cold);

    let ambiguous_submission = submission_with_v2(
        "operation:epistemic-ambiguous",
        "idempotency:epistemic-ambiguous",
        "record:epistemic-ambiguous",
        ObservationRecordKind::Telemetry,
        Some(ambiguous_v2(
            "record:epistemic-ambiguous",
            Some(ObservationRecordKind::Telemetry),
        )),
    );
    let ambiguous_result = journal
        .admit(ambiguous_submission)
        .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let ObservationAdmissionResult::Rejected { rejection } = ambiguous_result else {
        panic!("ambiguous material must not be accepted");
    };
    let fallback = rejection
        .safe_capture_fallback
        .as_ref()
        .unwrap_or_else(|| panic!("ambiguous rejection must preserve a safe candidate"));
    assert!(fallback.evidence.is_none());
    assert_eq!(fallback.disposition, CandidateDisposition::Cold);
}

#[test]
fn v2_exact_replay_returns_identical_accepted_disposition() {
    let submission = submission_with_v2(
        "operation:replay",
        "idempotency:replay",
        "record:replay",
        ObservationRecordKind::Audit,
        Some(exact_audit_v2("record:replay")),
    );
    let mut journal = ObservationJournal::default();
    let first = journal
        .admit(submission.clone())
        .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let ObservationAdmissionResult::Accepted {
        receipt: first_receipt,
    } = first
    else {
        panic!("exact material should be accepted");
    };
    let second = journal
        .admit(submission)
        .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let ObservationAdmissionResult::Replayed {
        receipt: replayed_receipt,
    } = second
    else {
        panic!("identical resubmission must replay the original disposition");
    };
    assert_eq!(first_receipt, replayed_receipt);
}

#[test]
fn conflicting_hint_fails_closed_with_candidate_preserved() {
    let conflicting = ObservationRecordEnvelopeV2 {
        payload: RecordFamilyPayloadV2::Audit(AuditRecord {
            record_id: "record:conflict".to_owned(),
            core: event(),
            audit_action: "checked".to_owned(),
            state_fence: fence(),
        }),
        caller_family_hint: Some(ObservationRecordKind::Telemetry),
        parent_record_id: None,
    };
    let direct = admit_record_family_v2(&conflicting);
    assert!(
        direct.is_err(),
        "wrong-hint conflict must fail closed, not report a family"
    );

    let telemetry_conflict = ObservationRecordEnvelopeV2 {
        payload: RecordFamilyPayloadV2::Telemetry(TelemetryRecord {
            record_id: "record:conflict".to_owned(),
            core: event(),
            capture_mode: CaptureMode::Sampled,
            sample_count: 1,
            raw_evidence_handle: Some("blob:1".to_owned()),
        }),
        caller_family_hint: Some(ObservationRecordKind::Audit),
        parent_record_id: None,
    };
    let submission = submission_with_v2(
        "operation:conflict",
        "idempotency:conflict",
        "record:conflict",
        ObservationRecordKind::Telemetry,
        Some(telemetry_conflict),
    );
    let mut journal = ObservationJournal::default();
    let result = journal
        .admit(submission)
        .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let ObservationAdmissionResult::Rejected { rejection } = result else {
        panic!("conflicting material must not be accepted");
    };
    assert!(
        rejection
            .all_contract_errors
            .iter()
            .any(|error| error.contains("hint")
                || error.contains("family")
                || error.contains("Hint")),
        "conflict rejection must keep its typed identity, got: {:?}",
        rejection.all_contract_errors
    );
    assert!(
        rejection.safe_capture_fallback.is_some(),
        "conflict rejection must preserve the safe candidate"
    );
}
