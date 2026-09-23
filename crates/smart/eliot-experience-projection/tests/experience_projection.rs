//! Package fixtures for the owner-framed experience read-aid view.
//!
//! Fixtures use owner vocabulary only: revision cursors, scopes, fences,
//! coverage evidence, and closed omission classes are all constructible
//! from scalars. Pose-style acceptance with execution belongs to package
//! proof; these fixtures pin the view contract shape.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_experience_projection::ExperienceView;
use eliot_observation_contracts::{
    CoverageDisposition, CoverageEvidence, ExperienceRecordRef, ExperienceSourceFamily,
    ObservationScope, ProjectionCoverage, ProjectionOmission, ProjectionOmissionClass,
    SourceRevisionHandle,
};
use eliot_receipts::WorkScopeId;

fn hex64() -> String {
    "0123456789abcdef".repeat(4)
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

fn scope() -> ObservationScope {
    ObservationScope {
        work_scope: WorkScopeId::new("scope-exp").expect("fixture scope"),
        task_ref: None,
        attempt_ref: None,
        module_or_route_ref: None,
    }
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(1).expect("non-zero"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn other_fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(7).expect("non-zero"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn record_ref(handle: &str) -> ExperienceRecordRef {
    ExperienceRecordRef {
        handle: aid(handle),
        revision: SourceRevisionHandle {
            source_id: "bank-1".to_owned(),
            revision: "r1".to_owned(),
            content_sha256: hex64(),
            byte_length: 100,
        },
        scope: scope(),
        fence: fence(),
    }
}

fn coverage(observed: u64) -> ProjectionCoverage {
    ProjectionCoverage {
        evidence: CoverageEvidence {
            disposition: CoverageDisposition::Partial,
            denominator_source_ref: "owner-enumeration-1".to_owned(),
            interval: None,
            blind_intervals: vec![],
            observed_count: observed,
        },
        coverage_digest: hex64(),
    }
}

fn omission(handle: &str) -> ProjectionOmission {
    ProjectionOmission {
        handle: aid(handle),
        class: ProjectionOmissionClass::TruncatedAtBound,
        detail: "assembly bound 1024".to_owned(),
    }
}

fn view() -> ExperienceView {
    ExperienceView::assemble(
        ExperienceSourceFamily::SystemExperienceBank,
        scope(),
        fence(),
        vec![record_ref("exp-1"), record_ref("exp-2")],
        coverage(2),
        vec![],
    )
    .expect("fixture view")
}

#[test]
fn valid_view_assembles_without_claiming_completeness() {
    let made = view();
    made.validate().expect("valid view");
    assert_eq!(made.refs.len(), 2);
    assert_eq!(made.coverage.evidence.observed_count, 2);
    let handles: Vec<&str> = made
        .handles()
        .iter()
        .map(|handle| handle.as_str())
        .collect();
    assert_eq!(handles, vec!["exp-1", "exp-2"]);
}

#[test]
fn complete_posture_is_structurally_rejected() {
    let mut echoing = coverage(2);
    echoing.evidence.disposition = CoverageDisposition::Complete;
    let error = ExperienceView::assemble(
        ExperienceSourceFamily::SystemExperienceBank,
        scope(),
        fence(),
        vec![record_ref("exp-1"), record_ref("exp-2")],
        echoing,
        vec![],
    )
    .expect_err("complete posture must fail");
    assert!(matches!(
        error,
        eliot_observation_contracts::ObservationError::CoverageIncomplete { .. }
    ));
}

#[test]
fn over_count_against_observed_volume_is_rejected() {
    let error = ExperienceView::assemble(
        ExperienceSourceFamily::SystemExperienceBank,
        scope(),
        fence(),
        vec![record_ref("exp-1"), record_ref("exp-2")],
        coverage(1),
        vec![],
    )
    .expect_err("over-count must fail");
    assert!(matches!(
        error,
        eliot_observation_contracts::ObservationError::CoverageIncomplete { .. }
    ));
}

#[test]
fn ref_scope_mismatch_is_rejected() {
    let mut stray = record_ref("exp-9");
    stray.scope = ObservationScope {
        work_scope: WorkScopeId::new("scope-other").expect("fixture scope"),
        task_ref: None,
        attempt_ref: None,
        module_or_route_ref: None,
    };
    let error = ExperienceView::assemble(
        ExperienceSourceFamily::SystemExperienceBank,
        scope(),
        fence(),
        vec![stray],
        coverage(1),
        vec![],
    )
    .expect_err("scope mismatch must fail");
    assert!(matches!(
        error,
        eliot_observation_contracts::ObservationError::InvalidField { .. }
    ));
}

#[test]
fn ref_fence_incompatibility_is_rejected() {
    let mut stray = record_ref("exp-9");
    stray.fence = other_fence();
    let error = ExperienceView::assemble(
        ExperienceSourceFamily::SystemExperienceBank,
        scope(),
        fence(),
        vec![stray],
        coverage(1),
        vec![],
    )
    .expect_err("fence mismatch must fail");
    assert!(matches!(
        error,
        eliot_observation_contracts::ObservationError::InvalidField { .. }
    ));
}

#[test]
fn named_omissions_travel_with_closed_classes() {
    let made = ExperienceView::assemble(
        ExperienceSourceFamily::AgentFeedback,
        scope(),
        fence(),
        vec![record_ref("exp-1")],
        coverage(2),
        vec![omission("exp-9")],
    )
    .expect("omissions travel");
    assert_eq!(made.omissions.len(), 1);
    assert_eq!(
        made.omissions[0].class,
        ProjectionOmissionClass::TruncatedAtBound
    );
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "family": "SYSTEM_EXPERIENCE_BANK",
        "scope": {
            "work_scope": "scope-exp",
            "task_ref": null,
            "attempt_ref": null,
            "module_or_route_ref": null
        },
        "fence": {
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "refs": [],
        "coverage": {
            "evidence": {
                "disposition": "PARTIAL",
                "denominator_source_ref": "owner-enumeration-1",
                "interval": null,
                "blind_intervals": [],
                "observed_count": 0
            },
            "coverage_digest": hex64(),
        },
        "omissions": [],
        "declared_total": 0
    });
    let error =
        serde_json::from_value::<ExperienceView>(json).expect_err("unknown field must fail");
    assert!(error.to_string().contains("declared_total"));
}

#[test]
fn view_roundtrips_over_the_wire() {
    let made = view();
    let wire = serde_json::to_string(&made).expect("serialize view");
    let back: ExperienceView = serde_json::from_str(&wire).expect("deserialize view");
    assert_eq!(made, back);
}
