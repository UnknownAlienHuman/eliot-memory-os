//! Proportionate first-pass classifier fixtures for issue #217.
//!
//! These integration tests exercise only the public Governor admission edge
//! (`admit_record_family_v2`, `ObservationSubmission::validate` via
//! `ObservationJournal::admit`). They cover the previously missing rows:
//! determinism, ambiguous fallback preservation, no epistemic promotion, and
//! exact replay identity, plus fail-closed conflicting-hint behavior.

use eliot_contracts::{
    ClockReading, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
};
use eliot_observation::{
    AmbiguousOrdinaryRecordV2, CandidateDisposition, CaptureMode, CaptureRoute,
    CoverageDisposition, CoverageEvidence, CoverageInterval, Durability,
    ObservationAdmissionResult, ObservationEventCore, ObservationEventIdentity, ObservationJournal,
    ObservationKind, ObservationRecordEnvelope, ObservationRecordEnvelopeV2, ObservationRecordKind,
    ObservationScope, ObservationSubmission, PrivacyRetentionDisclosure, ProducerTrace,
    RecordFamilyClassification, RecordFamilyPayloadV2, admit_record_family_v2,
};
use eliot_observation_contracts::{
    AuditRecord, MaintenanceRecord, TelemetryRecord, record_family_contract_identity,
};

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
}

fn event() -> ObservationEventCore {
    event_of(ObservationKind::QueueResource)
}

fn event_of(kind: ObservationKind) -> ObservationEventCore {
    let work_scope = "scope:test"
        .parse()
        .unwrap_or_else(|_| panic!("fixture work scope must parse"));
    let interval =
        CoverageInterval::new(1, 1).unwrap_or_else(|_| panic!("fixture interval must be valid"));
    ObservationEventCore {
        event_id_and_time: ObservationEventIdentity {
            event_id: format!("event:{kind:?}"),
            clock: ClockReading::default(),
        },
        producer_generation_and_trace: ProducerTrace {
            producer: "producer:test".to_owned(),
            generation: "generation:test".to_owned(),
            trace_ref: None,
        },
        kind,
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

/// A real `MaintenanceRecord` family, shaped exactly as the production producer
/// `crates/governor/eliot-governor/src/observation_reconciliation.rs::
/// maintenance_result_submission` builds it.
fn maintenance_family_v2(record_id: &str) -> ObservationRecordEnvelopeV2 {
    ObservationRecordEnvelopeV2 {
        payload: RecordFamilyPayloadV2::Maintenance(MaintenanceRecord {
            record_id: record_id.to_owned(),
            core: event_of(ObservationKind::Maintenance),
            maintenance_action: "rebuild projection".to_owned(),
            trigger_ref: "problem:1".to_owned(),
            result: None,
        }),
        caller_family_hint: Some(ObservationRecordKind::Maintenance),
        parent_record_id: None,
    }
}

fn maintenance_submission(record_id: &str) -> ObservationSubmission {
    let record_v2 = maintenance_family_v2(record_id);
    ObservationSubmission {
        operation_id: format!("operation:{record_id}"),
        idempotency_key: format!("idempotency:{record_id}"),
        state_fence: fence(),
        record: ObservationRecordEnvelope {
            record_id: record_id.to_owned(),
            kind: ObservationRecordKind::Maintenance,
            event: Some(event_of(ObservationKind::Maintenance)),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        },
        record_v2: Some(record_v2),
        capture_route: CaptureRoute::OperationalLog,
        durability: Durability::Volatile,
        plan: None,
        task_selection: None,
        evidence: None,
    }
}

/// A1: the versioned compatibility rule is ESTABLISHED from the record-family
/// owner at admission, so the receipt is bound to the one field-level owner
/// rather than to a caller-supplied label. The rule is derived, not selected.
#[test]
fn admission_records_the_record_family_contract_identity_of_its_owner() {
    let mut journal = ObservationJournal::default();
    let result = journal
        .admit(maintenance_submission("record:owner"))
        .unwrap_or_else(|error| panic!("exact maintenance family must be admitted: {error}"));
    let ObservationAdmissionResult::Accepted { receipt } = result else {
        panic!("an exact maintenance family must be accepted");
    };
    assert_eq!(receipt.record_id, "record:owner");
    let owner_identity = record_family_contract_identity()
        .unwrap_or_else(|error| panic!("record-family identity must resolve: {error}"));
    assert_eq!(
        receipt.record_family_contract,
        Some(owner_identity.clone()),
        "the receipt must record the identity the record-family owner publishes"
    );
    owner_identity
        .validate()
        .unwrap_or_else(|error| panic!("recorded identity must validate: {error}"));
    assert_eq!(
        owner_identity.version,
        eliot_observation_contracts::RECORD_FAMILY_CONTRACT_VERSION,
        "the recorded rule must be the owner's current v2 compatibility rule"
    );
}

/// Positive case: a real record family validates through the new caller. The
/// receipt round-trips through the ordinary persisted read/restart consumer,
/// which re-proves the recorded identity instead of trusting it.
#[test]
fn real_record_family_revalidates_through_the_recorded_identity_on_rebuild() {
    let mut journal = ObservationJournal::default();
    let result = journal
        .admit(maintenance_submission("record:rebuild"))
        .unwrap_or_else(|error| panic!("exact maintenance family must be admitted: {error}"));
    let ObservationAdmissionResult::Accepted { receipt } = result else {
        panic!("an exact maintenance family must be accepted");
    };
    assert!(receipt.record_v2.is_some());
    receipt
        .validate()
        .unwrap_or_else(|error| panic!("admitted receipt must re-validate: {error}"));
    let rebuilt = ObservationJournal::from_entries(journal.snapshot())
        .unwrap_or_else(|error| panic!("journal must rebuild: {error}"));
    let entry = rebuilt
        .get(&receipt.idempotency_key)
        .unwrap_or_else(|| panic!("rebuilt journal must retain the accepted receipt"));
    let ObservationAdmissionResult::Accepted {
        receipt: rebuilt_receipt,
    } = &entry.result
    else {
        panic!("rebuilt entry must stay the original accepted receipt");
    };
    assert_eq!(rebuilt_receipt, &receipt);
}

/// Refusal case: a family whose recorded record-family identity does not match
/// the owner's is refused — the recorded value is never rewritten to match, and
/// the typed mismatch identity is preserved through the rebuild consumer.
#[test]
fn receipt_recorded_under_another_record_family_identity_is_refused() {
    let mut journal = ObservationJournal::default();
    let result = journal
        .admit(maintenance_submission("record:refused"))
        .unwrap_or_else(|error| panic!("exact maintenance family must be admitted: {error}"));
    let ObservationAdmissionResult::Accepted {
        receipt: mut receipt,
    } = result
    else {
        panic!("an exact maintenance family must be accepted");
    };
    // A different-but-well-formed identity: the same owner name under another
    // rule revision. The shape digest stays valid, so only the identity
    // comparison can refuse this receipt.
    let admitted_identity = receipt
        .record_family_contract
        .clone()
        .unwrap_or_else(|| panic!("admitted receipt must carry an identity"));
    receipt.record_family_contract = Some(eliot_contracts::ContractIdentity {
        version: ContractVersion::new(2, 0, 1),
        ..admitted_identity.clone()
    });
    let refused = match receipt.validate() {
        Ok(()) => panic!("a receipt admitted under another record-family identity must be refused"),
        Err(error) => error,
    };
    match &refused {
        eliot_observation::GovernorObservationError::RecordFamilyContractMismatch {
            recorded,
            current,
        } => assert_eq!(
            (recorded.version, current.version),
            (ContractVersion::new(2, 0, 1), admitted_identity.version),
            "the refusal reports both sides verbatim; the recorded value is never rewritten"
        ),
        other => panic!("refusal must keep its typed mismatch identity, got: {other:?}"),
    }
    let entry = eliot_observation::ObservationJournalEntry {
        idempotency_key: receipt.idempotency_key.clone(),
        request_digest: receipt.request_digest.clone(),
        result: ObservationAdmissionResult::Accepted { receipt },
    };
    assert!(
        ObservationJournal::from_entries([entry]).is_err(),
        "rebuild must refuse a receipt admitted under another record-family identity"
    );
}
