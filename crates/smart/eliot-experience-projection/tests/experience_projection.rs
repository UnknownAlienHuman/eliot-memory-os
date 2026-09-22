//! Package fixtures for the immutable experience projection view.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_experience_projection::{
    ExperienceError, ExperienceEvidenceKind, ExperienceEvidenceRef, ExperienceOmission,
    ExperienceProjectionView,
};
use eliot_receipts::WorkScopeId;

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-exp").expect("fixture scope")
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
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

fn evidence(handle: &str, kind: ExperienceEvidenceKind) -> ExperienceEvidenceRef {
    ExperienceEvidenceRef {
        handle: aid(handle),
        kind,
    }
}

fn omission(handle: &str) -> ExperienceOmission {
    ExperienceOmission {
        handle: aid(handle),
        reason: "superseded-before-count".to_owned(),
    }
}

fn view() -> ExperienceProjectionView {
    ExperienceProjectionView::assemble(
        scope(),
        fence(),
        vec![
            evidence("exp-1", ExperienceEvidenceKind::SystemObservation),
            evidence("exp-2", ExperienceEvidenceKind::ExperienceBankRecord),
            evidence("exp-3", ExperienceEvidenceKind::AgentFeedback),
        ],
        4,
        vec![omission("exp-9")],
    )
    .expect("fixture view")
}

#[test]
fn valid_view_assembles_with_exact_denominator() {
    let assembled = view();
    assembled.validate().expect("valid view");
    assert_eq!(assembled.refs.len(), 3);
    assert_eq!(assembled.omissions.len(), 1);
    assert_eq!(assembled.declared_total, 4);
}

#[test]
fn handles_of_filters_by_family_in_supply_order() {
    let assembled = view();
    let bank: Vec<&str> = assembled
        .handles_of(ExperienceEvidenceKind::ExperienceBankRecord)
        .iter()
        .map(|handle| handle.as_str())
        .collect();
    assert_eq!(bank, vec!["exp-2"]);
    assert!(
        assembled
            .handles_of(ExperienceEvidenceKind::SystemObservation)
            .iter()
            .any(|handle| handle.as_str() == "exp-1")
    );
}

#[test]
fn denominator_contradiction_fails_closed() {
    let error = ExperienceProjectionView::assemble(
        scope(),
        fence(),
        vec![evidence("exp-1", ExperienceEvidenceKind::SystemObservation)],
        9,
        vec![],
    )
    .expect_err("contradicted denominator must fail");
    assert!(matches!(
        error,
        ExperienceError::DenominatorContradiction { .. }
    ));
}

#[test]
fn duplicate_handles_are_rejected() {
    let error = ExperienceProjectionView::assemble(
        scope(),
        fence(),
        vec![
            evidence("exp-1", ExperienceEvidenceKind::SystemObservation),
            evidence("exp-1", ExperienceEvidenceKind::AgentFeedback),
        ],
        2,
        vec![],
    )
    .expect_err("duplicates must fail");
    assert!(matches!(error, ExperienceError::DuplicateHandle { .. }));
}

#[test]
fn duplicate_ref_and_omission_handles_are_rejected() {
    let error = ExperienceProjectionView::assemble(
        scope(),
        fence(),
        vec![evidence("exp-1", ExperienceEvidenceKind::SystemObservation)],
        2,
        vec![omission("exp-1")],
    )
    .expect_err("ref/omission collision must fail");
    assert!(matches!(error, ExperienceError::DuplicateHandle { .. }));
}

#[test]
fn blank_omission_reason_is_rejected() {
    let error = ExperienceProjectionView::assemble(
        scope(),
        fence(),
        vec![evidence("exp-1", ExperienceEvidenceKind::SystemObservation)],
        2,
        vec![ExperienceOmission {
            handle: aid("exp-9"),
            reason: String::new(),
        }],
    )
    .expect_err("blank reason must fail");
    assert!(matches!(error, ExperienceError::InvalidField { .. }));
}

#[test]
fn oversized_scope_is_rejected() {
    let wide = "s".repeat(300);
    let error = ExperienceProjectionView::assemble(
        WorkScopeId::new(wide).expect("wide scope text"),
        fence(),
        vec![],
        0,
        vec![],
    )
    .expect_err("oversized scope must fail");
    assert!(matches!(error, ExperienceError::Bounds { .. }));
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "handle": "exp-1",
        "kind": "SYSTEM_OBSERVATION",
        "captured_at": "2026-09-22"
    });
    let error = serde_json::from_value::<ExperienceEvidenceRef>(json)
        .expect_err("unknown field must fail");
    assert!(error.to_string().contains("captured_at"));
}

#[test]
fn view_roundtrips_over_the_wire() {
    let assembled = view();
    let wire = serde_json::to_string(&assembled).expect("serialize view");
    let back: ExperienceProjectionView =
        serde_json::from_str(&wire).expect("deserialize view");
    assert_eq!(assembled, back);
}
