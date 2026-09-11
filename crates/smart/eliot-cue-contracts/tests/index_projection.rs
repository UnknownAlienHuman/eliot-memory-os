//! Focused proofs for the additive snapshot-build candidate envelope.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    AuthorityEpoch, ReceiptId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_cue_contracts::*;
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};
use eliot_security_contracts::PrivacyClass;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
}
fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("index-test-source").unwrap(),
        capture_route: "unit".into(),
        scope: "scope-1".into(),
        raw_handle: None,
        revision: None,
    }
}
fn context() -> CueContext {
    let f = fence();
    CueContext::new(
        TaskId::new("task-1").unwrap(),
        WorkScopeId::new("scope-1").unwrap(),
        f.clone(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: provenance(),
            verification: None,
            state_fence: f,
        },
        LifecycleState::Active,
        PrivacyClass::Public,
        ProofCeiling::Observation,
    )
}
fn profile() -> NormalizationProfile {
    NormalizationProfile::new("symbol-v1".into(), 1, digest(1))
}
fn source(target: &str) -> SourceHandle {
    SourceHandle::new(TargetHandle::new(target).unwrap(), digest(2), provenance())
}
fn normalized(value: &str, id: &str, target: &str) -> NormalizedCue {
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new(id).unwrap(),
        CueKind::Symbol,
        value.into(),
        digest(3),
    );
    let observed = ObservedCue::new(
        CONTRACT_REVISION.into(),
        ObservedCueId::new(format!("obs-{id}")).unwrap(),
        CueKind::Symbol,
        value.into(),
        source(target),
        context(),
    );
    let key = ComparisonKey::new(
        ComparisonKeyId::new(format!("key-{id}")).unwrap(),
        profile(),
        value.into(),
        MatchMode::Exact,
        ComparisonForm::Exact,
    );
    NormalizedCue::new(
        CONTRACT_REVISION.into(),
        observed,
        profile(),
        Some(canonical),
        vec![key],
        NormalizationOutcome::Lossless,
        Vec::new(),
    )
}
fn projection(id: &str, cue: &str, target: &str, seed: u8) -> AdmittedCueBindingProjection {
    let normalized = normalized(cue, id, target);
    let candidate = CueBindingCandidate::new(
        BindingCandidateId::new(format!("candidate-{id}")).unwrap(),
        normalized.canonical.clone().unwrap(),
        TargetHandle::new(target).unwrap(),
        BindingRole::Names,
        EvidenceFreshness::ExactCandidate,
        BindingDisposition::Withheld,
        digest(seed),
    );
    let admission = CueBindingAdmissionRef::new(
        ReceiptIdentity {
            receipt_id: ReceiptId::new(format!(
                "receipt-{}",
                digest(seed.wrapping_add(1)).as_str()
            ))
            .unwrap(),
            canonical_sha256: digest(seed.wrapping_add(1)).as_str().into(),
        },
        candidate.binding_candidate_id.clone(),
        candidate.digest.clone(),
        TaskId::new("task-1").unwrap(),
        WorkScopeId::new("scope-1").unwrap(),
        fence(),
    );
    AdmittedCueBindingProjection::new(candidate, normalized, admission)
}
fn snapshot(projections: &[AdmittedCueBindingProjection]) -> CueSnapshot {
    let members = projections
        .iter()
        .map(|p| SnapshotMember::new(p.candidate.canonical.clone(), p.candidate.target.clone()))
        .collect();
    let mut sources = Vec::new();
    for projection in projections {
        let source = projection.normalized.observed.source.clone();
        if !sources.iter().any(|known: &SourceHandle| known == &source) {
            sources.push(source);
        }
    }
    let mut result = CueSnapshot::new(
        CONTRACT_REVISION.into(),
        SnapshotId::new("snapshot-1").unwrap(),
        members,
        RebuildIdentity::new(profile(), sources, digest(9)),
        fence(),
    );
    result.rebuild.digest = result.canonical_digest().unwrap();
    result
}

#[test]
fn withhold_proposal_is_a_valid_build_candidate() -> TestResult {
    let p = projection("one", "TaskContract", "src/a.rs", 10);
    let original_candidate = p.candidate.clone();
    let original_receipt = p.admission.receipt.clone();
    let candidate = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1")?,
        snapshot(std::slice::from_ref(&p)),
        vec![p],
        Vec::new(),
    )?;
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(candidate.admitted_bindings[0].candidate, original_candidate);
    assert_eq!(
        candidate.admitted_bindings[0].candidate.disposition,
        BindingDisposition::Withheld
    );
    assert_eq!(
        candidate.admitted_bindings[0].admission.receipt,
        original_receipt
    );
    candidate.validate()?;
    Ok(())
}

#[test]
fn joins_reject_tampered_candidate_and_rejected_disposition() {
    let mut p = projection("one", "TaskContract", "src/a.rs", 10);
    p.admission.candidate_digest = digest(11);
    let result = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").unwrap(),
        snapshot(std::slice::from_ref(&projection(
            "one",
            "TaskContract",
            "src/a.rs",
            10,
        ))),
        vec![p],
        Vec::new(),
    );
    assert!(result.is_err());
    let mut rejected = projection("one", "TaskContract", "src/a.rs", 10);
    rejected.candidate.disposition = BindingDisposition::Rejected;
    assert!(
        CueSnapshotBuildCandidate::seal(
            WorkScopeId::new("scope-1").unwrap(),
            snapshot(std::slice::from_ref(&rejected)),
            vec![rejected],
            Vec::new()
        )
        .is_err()
    );
}

#[test]
fn outer_set_order_is_canonical_and_edges_need_members() -> TestResult {
    let first = projection("one", "TaskContract", "src/a.rs", 10);
    let second = projection("two", "Other", "src/b.rs", 12);
    let edge = RelationEdge::new(
        RelationEdgeId::new("edge-one")?,
        RelationKind::Supports,
        TargetHandle::new("src/a.rs")?,
        TargetHandle::new("src/b.rs")?,
        CONTRACT_REVISION.into(),
        digest(14),
        context().evidence,
    );
    let left = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1")?,
        snapshot(&[first.clone(), second.clone()]),
        vec![first.clone(), second.clone()],
        vec![edge.clone()],
    )?;
    let right = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1")?,
        snapshot(&[second.clone(), first.clone()]),
        vec![second, first],
        vec![edge],
    )?;
    assert_eq!(left.build_digest, right.build_digest);
    assert_eq!(
        left.canonical_payload_bytes()?,
        right.canonical_payload_bytes()?
    );
    let bad_edge = RelationEdge::new(
        RelationEdgeId::new("edge-bad")?,
        RelationKind::Supports,
        TargetHandle::new("src/a.rs")?,
        TargetHandle::new("src/missing.rs")?,
        CONTRACT_REVISION.into(),
        digest(15),
        context().evidence,
    );
    assert!(
        CueSnapshotBuildCandidate::seal(
            WorkScopeId::new("scope-1")?,
            snapshot(&[projection("one", "TaskContract", "src/a.rs", 10)]),
            vec![projection("one", "TaskContract", "src/a.rs", 10)],
            vec![bad_edge],
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn comparison_key_sets_sort_but_transformations_keep_order() -> TestResult {
    let mut first = projection("one", "TaskContract", "src/a.rs", 10);
    first.normalized.comparison_keys.push(ComparisonKey::new(
        ComparisonKeyId::new("key-extra")?,
        profile(),
        "taskcontract-alt".into(),
        MatchMode::Exact,
        ComparisonForm::Exact,
    ));
    first.normalized.transformation_evidence = vec![
        TransformationStep::new("first".into(), "TaskContract".into()),
        TransformationStep::new("second".into(), "TaskContract".into()),
    ];
    let mut reordered = first.clone();
    reordered.normalized.comparison_keys.reverse();
    let ordered = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1")?,
        snapshot(std::slice::from_ref(&first)),
        vec![first],
        Vec::new(),
    )?;
    let reordered_keys = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1")?,
        snapshot(std::slice::from_ref(&reordered)),
        vec![reordered.clone()],
        Vec::new(),
    )?;
    assert_eq!(ordered.build_digest, reordered_keys.build_digest);
    reordered.normalized.transformation_evidence.reverse();
    let reordered_steps = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1")?,
        snapshot(std::slice::from_ref(&reordered)),
        vec![reordered],
        Vec::new(),
    )?;
    assert_ne!(ordered.build_digest, reordered_steps.build_digest);
    Ok(())
}

#[test]
fn empty_snapshot_keeps_explicit_scope_and_zero_edges() -> TestResult {
    let mut empty = CueSnapshot::new(
        CONTRACT_REVISION.into(),
        SnapshotId::new("empty-snapshot")?,
        Vec::new(),
        RebuildIdentity::new(profile(), Vec::new(), digest(19)),
        fence(),
    );
    empty.rebuild.digest = empty.canonical_digest()?;
    let candidate = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-empty")?,
        empty,
        Vec::new(),
        Vec::new(),
    )?;
    assert_eq!(candidate.scope_id.as_str(), "scope-empty");
    candidate.validate()?;
    Ok(())
}

#[test]
fn nested_observation_bound_is_checked_before_build() {
    let mut p = projection("one", "TaskContract", "src/a.rs", 10);
    p.normalized.observed.original_value = "x".repeat(8_193);
    let result = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").unwrap(),
        snapshot(std::slice::from_ref(&p)),
        vec![p],
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(CueContractError::BoundExceeded {
            field: "index.observed.value",
            ..
        })
    ));
}
