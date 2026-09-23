//! Package fixtures for source citation and the pose receipt.
//!
//! The projection, refs, pair binding, and cited triples are all
//! constructible from scalar owner vocabulary, so citation currency is
//! pinned directly: exact triples pass, drifted or unknown handles fail
//! closed. Pose acceptance with an owner-valid `SelfQueryInput` pipeline
//! fixture executes at package proof, where the owner's own suite already
//! covers validate-then-digest behavior.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
};
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, AcceptedSourceRef, ArchitectureSourceStatus, NormativePairBinding,
};
use eliot_dreamer_self_query::{CitedSource, SelfQueryPoseReceipt, check_citations};

fn hex64(seed: &str) -> String {
    let mut out = String::new();
    while out.len() < 64 {
        out.push_str(seed);
    }
    out.truncate(64);
    out
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

fn pair() -> NormativePairBinding {
    NormativePairBinding {
        architecture_digest: hex64("a1"),
        implementation_digest: hex64("b2"),
        pair_key: format!("sha256:{}", hex64("c3")),
        document_set: "arch-docs".to_owned(),
        architecture_revision: "4.5-draft".to_owned(),
        implementation_revision: "0.29-draft".to_owned(),
        accepted_by: SourceId::new("owner-1").expect("fixture owner"),
        acceptance_receipt: ReceiptId::new("rc-1").expect("fixture receipt"),
    }
}

fn source_ref(handle: &str, revision: &str) -> AcceptedSourceRef {
    AcceptedSourceRef {
        source_handle: aid(handle),
        owner: SourceId::new("owner-1").expect("fixture owner"),
        revision: revision.to_owned(),
        digest: hex64("d4"),
        status: ArchitectureSourceStatus::Accepted,
        acceptance_receipt: ReceiptId::new("rc-1").expect("fixture receipt"),
    }
}

fn projection() -> AcceptedSourceProjection {
    AcceptedSourceProjection::project(
        aid("proj-1"),
        pair(),
        fence(),
        vec![source_ref("src-1", "r1"), source_ref("src-2", "r2")],
    )
    .expect("fixture projection")
}

fn cited(handle: &str, revision: &str) -> CitedSource {
    CitedSource {
        handle: aid(handle),
        revision: revision.to_owned(),
        digest: hex64("d4"),
    }
}

#[test]
fn project_validates_and_freezes_a_stable_digest() {
    let first = projection();
    first.validate().expect("valid projection");
    assert_eq!(first.digest.len(), 64);
    let second = projection();
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.sources.len(), 2);
}

#[test]
fn non_accepted_status_is_rejected() {
    let mut bad = source_ref("src-9", "r1");
    bad.status = ArchitectureSourceStatus::Draft;
    let error = AcceptedSourceProjection::project(aid("proj-9"), pair(), fence(), vec![bad])
        .expect_err("non-accepted ref must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::Conflict { .. }
    ));
}

#[test]
fn duplicate_handles_are_rejected() {
    let error = AcceptedSourceProjection::project(
        aid("proj-9"),
        pair(),
        fence(),
        vec![source_ref("src-1", "r1"), source_ref("src-1", "r2")],
    )
    .expect_err("duplicate handles must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::Duplicate { .. }
    ));
}

#[test]
fn tampered_digest_is_rejected() {
    let mut made = projection();
    made.digest = "0".repeat(64);
    let error = made.validate().expect_err("tampered digest must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::DigestMismatch { .. }
    ));
}

#[test]
fn exact_triples_pass_citation() {
    let sources = projection();
    check_citations(&[cited("src-1", "r1"), cited("src-2", "r2")], &sources)
        .expect("exact triples pass");
}

#[test]
fn revised_triple_is_stale() {
    let sources = projection();
    let error =
        check_citations(&[cited("src-1", "r2")], &sources).expect_err("revised triple must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::BindingMismatch { .. }
    ));
}

#[test]
fn unknown_handle_is_uncited() {
    let sources = projection();
    let error =
        check_citations(&[cited("src-9", "r1")], &sources).expect_err("unknown handle must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::BindingMismatch { .. }
    ));
}

#[test]
fn blank_cited_revision_is_rejected() {
    let sources = projection();
    let mut bad = cited("src-1", "r1");
    bad.revision = "   ".to_owned();
    let error = check_citations(&[bad], &sources).expect_err("blank revision must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::Missing { .. }
    ));
}

#[test]
fn malformed_cited_digest_is_rejected() {
    let sources = projection();
    let mut bad = cited("src-1", "r1");
    bad.digest = "not-a-digest".to_owned();
    let error = check_citations(&[bad], &sources).expect_err("malformed digest must fail");
    assert!(matches!(
        error,
        eliot_dreamer_contracts::self_query::SelfQueryContractError::InvalidDigest { .. }
    ));
}

fn receipt() -> SelfQueryPoseReceipt {
    SelfQueryPoseReceipt {
        input_digest: hex64("e5"),
        schema_version: 1,
        cited: Vec::new(),
    }
}

#[test]
fn valid_receipt_passes_shape_check() {
    receipt().validate().expect("valid receipt");
}

#[test]
fn malformed_receipt_digest_is_rejected() {
    let mut bad = receipt();
    bad.input_digest = "not-a-digest".to_owned();
    bad.validate().expect_err("malformed digest must fail");
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "input_digest": hex64("e5"),
        "schema_version": 1,
        "model_hint": "answer directly"
    });
    let error =
        serde_json::from_value::<SelfQueryPoseReceipt>(json).expect_err("unknown field must fail");
    assert!(error.to_string().contains("model_hint"));
}

#[test]
fn receipt_roundtrips_over_the_wire() {
    let made = receipt();
    let wire = serde_json::to_string(&made).expect("serialize receipt");
    let back: SelfQueryPoseReceipt = serde_json::from_str(&wire).expect("deserialize receipt");
    assert_eq!(made, back);
}
