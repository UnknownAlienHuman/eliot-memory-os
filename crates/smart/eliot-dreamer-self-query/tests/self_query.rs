//! Package fixtures for the bounded Dreamer self-query.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_dreamer_self_query::{SelfQueryCandidate, SelfQueryError, SelfQueryRequest, SelfQuerySubject, pose};
use eliot_receipts::WorkScopeId;

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-selfquery").expect("fixture scope")
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

fn subject() -> SelfQuerySubject {
    SelfQuerySubject {
        question: "which rival explains the failed rollout?".to_owned(),
        task_family: "deployment-diagnosis".to_owned(),
    }
}

fn request() -> SelfQueryRequest {
    SelfQueryRequest::new(
        subject(),
        scope(),
        fence(),
        aid("view-1"),
        vec![aid("src-1"), aid("src-2")],
    )
    .expect("fixture request")
}

#[test]
fn pose_freezes_a_deterministic_digest() {
    let first = pose(&request()).expect("valid pose");
    let second = pose(&request()).expect("valid pose");
    assert_eq!(first.request_digest, second.request_digest);
    assert_eq!(first.request_digest.len(), 64);
    first.validate().expect("posed candidate validates");
}

#[test]
fn digest_changes_with_the_question() {
    let mut other = request();
    other.subject.question = "which rival explains the slow rollout?".to_owned();
    let first = pose(&request()).expect("valid pose");
    let second = pose(&other).expect("valid pose");
    assert_ne!(first.request_digest, second.request_digest);
}

#[test]
fn tampered_digest_is_rejected() {
    let mut candidate = pose(&request()).expect("valid pose");
    candidate.request_digest = "0".repeat(64);
    let error = candidate.validate().expect_err("tampered digest must fail");
    assert!(matches!(error, SelfQueryError::InvalidField { .. }));
}

#[test]
fn blank_question_is_rejected() {
    let mut bad = request();
    bad.subject.question = "   ".to_owned();
    let error = pose(&bad).expect_err("blank question must fail");
    assert!(matches!(error, SelfQueryError::InvalidField { .. }));
}

#[test]
fn oversized_question_is_rejected() {
    let mut bad = request();
    bad.subject.question = "q".repeat(2000);
    let error = pose(&bad).expect_err("oversized question must fail");
    assert!(matches!(error, SelfQueryError::Bounds { .. }));
}

#[test]
fn ref_overflow_is_rejected() {
    let refs: Vec<ArtifactId> = (0..40).map(|n| aid(&format!("src-{n:02}"))).collect();
    let error = SelfQueryRequest::new(subject(), scope(), fence(), aid("view-1"), refs)
        .expect_err("ref overflow must fail");
    assert!(matches!(error, SelfQueryError::Bounds { .. }));
}

#[test]
fn duplicate_refs_are_rejected() {
    let error = SelfQueryRequest::new(
        subject(),
        scope(),
        fence(),
        aid("view-1"),
        vec![aid("src-1"), aid("src-1")],
    )
    .expect_err("duplicate refs must fail");
    assert!(matches!(error, SelfQueryError::InvalidField { .. }));
}

#[test]
fn blank_view_ref_is_rejected() {
    // ArtifactId validates on construction and on wire decode, so a blank
    // view ref fails at the boundary before request validation runs.
    let json = serde_json::json!({
        "subject": {"question": "q?", "task_family": "f"},
        "scope_id": "scope-selfquery",
        "state_fence": {
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "view_ref": "   ",
        "source_refs": []
    });
    serde_json::from_value::<SelfQueryRequest>(json).expect_err("blank view ref must fail");
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "subject": {"question": "q?", "task_family": "f"},
        "scope_id": "scope-selfquery",
        "state_fence": {
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "view_ref": "view-1",
        "source_refs": [],
        "model_hint": "answer directly"
    });
    let error =
        serde_json::from_value::<SelfQueryRequest>(json).expect_err("unknown field must fail");
    assert!(error.to_string().contains("model_hint"));
}

#[test]
fn candidate_roundtrips_over_the_wire() {
    let posed = pose(&request()).expect("valid pose");
    let wire = serde_json::to_string(&posed).expect("serialize candidate");
    let back: SelfQueryCandidate = serde_json::from_str(&wire).expect("deserialize candidate");
    assert_eq!(posed, back);
}
