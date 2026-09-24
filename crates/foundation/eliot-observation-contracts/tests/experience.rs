//! System Experience cell entrypoint: fail-closed admission denominators.
//!
//! The experience cell (`src/experience.rs`) admits bank/feedback record
//! shapes only against an explicit denominator: an empty source set and an
//! absent consent marker both fail closed before any binding is validated.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_observation_contracts::{
    AgentFeedbackRecord, CoverageDisposition, CoverageEvidence, CoverageInterval,
    ExperienceBankRecord, FeedbackClass, ObservationError, ObservationScope,
    PrivacyRetentionDisclosure, ProducerTrace, ProjectionCoverage,
};

fn fence() -> StateFence {
    let lineage =
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("fixture sequence"))
        .expect("fixture epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn scope() -> Result<ObservationScope, ObservationError> {
    Ok(ObservationScope {
        work_scope: "scope:test".parse()?,
        task_ref: None,
        attempt_ref: None,
        module_or_route_ref: None,
    })
}

fn coverage() -> Result<ProjectionCoverage, ObservationError> {
    Ok(ProjectionCoverage {
        evidence: CoverageEvidence {
            disposition: CoverageDisposition::Complete,
            denominator_source_ref: "cursor:task".to_owned(),
            interval: Some(CoverageInterval::new(1, 1)?),
            blind_intervals: Vec::new(),
            observed_count: 1,
        },
        coverage_digest: "0".repeat(64),
    })
}

fn retention() -> PrivacyRetentionDisclosure {
    PrivacyRetentionDisclosure {
        privacy_domain_ref: "self".to_owned(),
        retention_policy_ref: "default".to_owned(),
        disclosure_class: "internal".to_owned(),
    }
}

#[test]
fn bank_admission_rejects_empty_source_denominator() -> Result<(), ObservationError> {
    let err = ExperienceBankRecord::admit(
        ArtifactId::new("bank-1").expect("fixture handle"),
        1,
        Vec::new(),
        scope()?,
        fence(),
        coverage()?,
        retention(),
        None,
        "summary".to_owned(),
    )
    .expect_err("empty source refs must fail closed");
    assert!(
        matches!(
            err,
            ObservationError::InvalidField {
                field: "bank_record.source_journal_refs",
                ..
            }
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn feedback_admission_rejects_absent_consent() -> Result<(), ObservationError> {
    let err = AgentFeedbackRecord::admit(
        ArtifactId::new("feedback-1").expect("fixture handle"),
        1,
        ProducerTrace {
            producer: "producer".to_owned(),
            generation: "generation-1".to_owned(),
            trace_ref: None,
        },
        String::new(),
        FeedbackClass::UsefulnessSignal,
        None,
        scope()?,
        fence(),
        retention(),
        "note".to_owned(),
    )
    .expect_err("absent consent must fail closed");
    assert!(
        matches!(
            err,
            ObservationError::InvalidField {
                field: "feedback_record.consent_ref",
                ..
            }
        ),
        "unexpected error: {err}"
    );
    Ok(())
}
