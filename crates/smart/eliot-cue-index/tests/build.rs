//! Focused behavior tests for the A-13 snapshot builder.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::ReceiptId;
use eliot_contracts::{AuthorityEpoch, ResourceGeneration, SourceId, StateFence, TaskId};
use eliot_cue_contracts::*;
use eliot_cue_contracts::{PrivacyClass, ProofCeiling, WorkScopeId};
use eliot_cue_index::{build_cue_snapshot, rebuild_cue_snapshot};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance, RelationKind,
};
use eliot_receipts::ReceiptIdentity;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("index-builder-tests").expect("source"),
        capture_route: "unit".into(),
        scope: "scope-1".into(),
        raw_handle: None,
        revision: None,
    }
}

fn context() -> CueContext {
    let state_fence = fence();
    CueContext::new(
        TaskId::new("task-1").expect("task"),
        WorkScopeId::new("scope-1").expect("scope"),
        state_fence.clone(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: provenance(),
            verification: None,
            state_fence,
        },
        LifecycleState::Active,
        PrivacyClass::Public,
        ProofCeiling::Observation,
    )
}

fn profile() -> NormalizationProfile {
    NormalizationProfile::new("index-profile".into(), 1, digest(1))
}

fn projection(number: usize, target: &str) -> AdmittedCueBindingProjection {
    let number_u8 = u8::try_from(number).expect("fixture index");
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{number}")).expect("canonical id"),
        CueKind::Symbol,
        format!("Symbol{number}"),
        digest(number_u8 + 10),
    );
    let observed = ObservedCue::new(
        CONTRACT_REVISION.into(),
        ObservedCueId::new(format!("observed-{number}")).expect("observed id"),
        CueKind::Symbol,
        format!("Symbol{number}"),
        SourceHandle::new(
            TargetHandle::new(target).expect("target"),
            digest(number_u8 + 40),
            provenance(),
        ),
        context(),
    );
    let normalized = NormalizedCue::new(
        CONTRACT_REVISION.into(),
        observed,
        profile(),
        Some(canonical.clone()),
        vec![ComparisonKey::new(
            ComparisonKeyId::new(format!("key-{number}")).expect("key id"),
            profile(),
            format!("symbol{number}"),
            MatchMode::Exact,
            ComparisonForm::Exact,
        )],
        NormalizationOutcome::Lossless,
        Vec::new(),
    );
    let candidate = CueBindingCandidate::new(
        BindingCandidateId::new(format!("candidate-{number}")).expect("candidate id"),
        canonical,
        TargetHandle::new(target).expect("target"),
        BindingRole::Names,
        EvidenceFreshness::ExactCandidate,
        BindingDisposition::Withheld,
        digest(number_u8 + 70),
    );
    let receipt_digest = digest(number_u8 + 100);
    let admission = CueBindingAdmissionRef::new(
        ReceiptIdentity {
            receipt_id: ReceiptId::new(format!("receipt-{}", receipt_digest.as_str()))
                .expect("receipt id"),
            canonical_sha256: receipt_digest.as_str().into(),
        },
        candidate.binding_candidate_id.clone(),
        candidate.digest.clone(),
        TaskId::new("task-1").expect("task"),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
    );
    AdmittedCueBindingProjection::new(candidate, normalized, admission)
}

fn edge(from: &str, to: &str) -> RelationEdge {
    RelationEdge::new(
        RelationEdgeId::new("edge-1").expect("edge id"),
        RelationKind::Supports,
        TargetHandle::new(from).expect("from"),
        TargetHandle::new(to).expect("to"),
        "registry-1".into(),
        digest(200),
        context().evidence,
    )
}

#[test]
fn builds_zero_edge_candidate_and_retains_withheld_lineage() -> TestResult {
    let projection = projection(1, "src/a.rs");
    let candidate = build_cue_snapshot(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        std::slice::from_ref(&projection),
        &[],
        None,
    )?;
    candidate.validate()?;
    assert_eq!(
        candidate.admitted_bindings[0].candidate,
        projection.candidate
    );
    assert_eq!(
        candidate.admitted_bindings[0].candidate.disposition,
        BindingDisposition::Withheld
    );
    assert_eq!(
        candidate.admitted_bindings[0].admission,
        projection.admission
    );
    assert!(candidate.relation_edges.is_empty());
    Ok(())
}

#[test]
fn typed_edge_and_rebuild_are_deterministic() -> TestResult {
    let first = projection(1, "src/a.rs");
    let second = projection(2, "src/b.rs");
    let first_source = first.normalized.observed.source.clone();
    let second_source = second.normalized.observed.source.clone();
    let expected_edge = edge("src/a.rs", "src/b.rs");
    let left = build_cue_snapshot(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &[first.clone(), second.clone()],
        std::slice::from_ref(&expected_edge),
        Some("registry-1"),
    )?;
    let right = build_cue_snapshot(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &[second, first],
        std::slice::from_ref(&expected_edge),
        Some("registry-1"),
    )?;
    assert_eq!(left.build_digest, right.build_digest);
    assert_eq!(left.admitted_bindings.len(), 2);
    assert_eq!(left.snapshot.members, right.snapshot.members);
    assert_eq!(left.snapshot.members.len(), 2);
    assert_eq!(left.snapshot.rebuild.source_denominator.len(), 2);
    assert!(
        left.snapshot
            .rebuild
            .source_denominator
            .contains(&first_source)
    );
    assert!(
        left.snapshot
            .rebuild
            .source_denominator
            .contains(&second_source)
    );
    assert_eq!(left.relation_edges, vec![expected_edge.clone()]);
    assert_eq!(
        left.canonical_payload_bytes()?,
        right.canonical_payload_bytes()?
    );
    let rebuilt = rebuild_cue_snapshot(&left, Some("registry-1"))?;
    assert_eq!(rebuilt.build_digest, left.build_digest);
    assert_eq!(
        rebuilt.snapshot.rebuild.digest,
        left.snapshot.rebuild.digest
    );
    Ok(())
}

#[test]
fn invalid_scope_disposition_and_dangling_edge_are_rejected() -> TestResult {
    let projection = projection(1, "src/a.rs");
    assert!(
        build_cue_snapshot(
            &WorkScopeId::new("other-scope")?,
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            std::slice::from_ref(&projection),
            &[],
            None,
        )
        .is_err()
    );
    let mut rejected = projection.clone();
    rejected.candidate.disposition = BindingDisposition::Rejected;
    assert!(
        build_cue_snapshot(
            &WorkScopeId::new("scope-1")?,
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            std::slice::from_ref(&rejected),
            &[],
            None,
        )
        .is_err()
    );
    assert!(
        build_cue_snapshot(
            &WorkScopeId::new("scope-1")?,
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            std::slice::from_ref(&projection),
            &[edge("src/a.rs", "src/missing.rs")],
            Some("registry-1"),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn explicit_empty_sets_are_a_scoped_candidate() -> TestResult {
    let candidate = build_cue_snapshot(
        &WorkScopeId::new("scope-empty")?,
        SnapshotId::new("snapshot-empty")?,
        profile(),
        fence(),
        &[],
        &[],
        None,
    )?;
    assert_eq!(candidate.scope_id.as_str(), "scope-empty");
    assert!(candidate.snapshot.members.is_empty());
    candidate.validate()?;
    Ok(())
}

#[test]
fn binding_and_edge_limits_are_checked_before_work() -> TestResult {
    let projection = projection(1, "src/a.rs");
    let too_many = vec![projection; 129];
    let result = build_cue_snapshot(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &too_many,
        &[],
        None,
    );
    assert!(matches!(
        result,
        Err(CueContractError::BoundExceeded {
            field: "index.bindings",
            ..
        })
    ));
    let too_many_edges = vec![edge("src/a.rs", "src/b.rs"); 129];
    let edge_result = build_cue_snapshot(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &[],
        &too_many_edges,
        Some("registry-1"),
    );
    assert!(matches!(
        edge_result,
        Err(CueContractError::BoundExceeded {
            field: "index.edges",
            ..
        })
    ));
    Ok(())
}
