//! Package fixtures for the owner-typed experience journal slice.
//!
//! Fixtures use owner-typed records only: `CoverageGap`-kind records (all
//! scalar fields) assemble, while an ordinary record without its required
//! event is rejected by the owner's own `validate()`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_experience_projection::{ExperienceError, ExperienceJournalSlice};
use eliot_observation_contracts::{
    CoverageGap, GapDisposition, ObservationRecordKind, SystemObservationJournalRecord,
};

fn gap_record(id: &str) -> SystemObservationJournalRecord {
    SystemObservationJournalRecord {
        record_id: id.to_owned(),
        kind: ObservationRecordKind::CoverageGap,
        event: None,
        coverage_gap: Some(CoverageGap {
            gap_id: format!("{id}-gap"),
            obligation_profile_ref: "obligation-profile-1".to_owned(),
            reason_ref: "producer-offline".to_owned(),
            affected_interval: None,
            disposition: GapDisposition::Continue,
            protected: false,
            evidence_refs: vec![],
        }),
        journal_control_event: false,
        parent_record_id: None,
    }
}

fn eventless_audit(id: &str) -> SystemObservationJournalRecord {
    SystemObservationJournalRecord {
        record_id: id.to_owned(),
        kind: ObservationRecordKind::Audit,
        event: None,
        coverage_gap: None,
        journal_control_event: false,
        parent_record_id: None,
    }
}

fn slice() -> ExperienceJournalSlice {
    ExperienceJournalSlice::assemble(vec![gap_record("rec-1"), gap_record("rec-2")])
        .expect("fixture slice")
}

#[test]
fn gap_records_assemble_with_supplied_set_accounting() {
    let made = slice();
    made.validate().expect("valid slice");
    assert_eq!(made.supplied, 2);
    assert_eq!(made.records.len(), 2);
    assert_eq!(made.gaps().len(), 2);
    assert_eq!(made.gaps()[0].gap_id, "rec-1-gap");
}

#[test]
fn records_of_filters_by_owner_family() {
    let made = slice();
    assert_eq!(
        made.records_of(ObservationRecordKind::CoverageGap).len(),
        2
    );
    assert!(made.records_of(ObservationRecordKind::Audit).is_empty());
}

#[test]
fn gap_only_slice_names_no_coverage_refs() {
    let made = slice();
    assert!(made.denominator_source_refs().is_empty());
}

#[test]
fn ordinary_record_without_event_is_rejected_by_the_owner() {
    let error = ExperienceJournalSlice::assemble(vec![eventless_audit("rec-9")])
        .expect_err("eventless ordinary record must fail");
    assert!(matches!(error, ExperienceError::Upstream(_)));
}

#[test]
fn count_mismatch_is_rejected() {
    let mut made = slice();
    made.supplied = 9;
    let error = made.validate().expect_err("count mismatch must fail");
    assert!(matches!(error, ExperienceError::CountMismatch { .. }));
}

#[test]
fn version_drift_is_rejected() {
    let mut made = slice();
    made.contract_version = eliot_contracts::ContractVersion::new(9, 9, 9);
    let error = made.validate().expect_err("drift must fail");
    assert!(matches!(error, ExperienceError::VersionMismatch));
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "contract_version": {"major": 1, "minor": 0, "patch": 0},
        "records": [],
        "supplied": 0,
        "declared_total": 0
    });
    let error = serde_json::from_value::<ExperienceJournalSlice>(json)
        .expect_err("unknown field must fail");
    assert!(error.to_string().contains("declared_total"));
}

#[test]
fn slice_roundtrips_over_the_wire() {
    let made = slice();
    let wire = serde_json::to_string(&made).expect("serialize slice");
    let back: ExperienceJournalSlice =
        serde_json::from_str(&wire).expect("deserialize slice");
    assert_eq!(made, back);
}
