//! Focused behavior tests for the A-13 snapshot builder.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::ReceiptId;
use eliot_contracts::{
    ArtifactId, ContractId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId,
};
use eliot_cue_contracts::*;
use eliot_cue_contracts::{PrivacyClass, ProofCeiling, WorkScopeId};
use eliot_cue_index::{
    build_cue_snapshot, build_cue_snapshot_closed, rebuild_cue_snapshot,
    rebuild_cue_snapshot_closed,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance, RelationKind, VerificationBinding,
};
use eliot_receipts::ReceiptIdentity;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(), ResourceGeneration::genesis())
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

fn projection_with(
    number: usize,
    target: &str,
    kind: CueKind,
    value: &str,
    key_value: &str,
) -> AdmittedCueBindingProjection {
    let number_u8 = u8::try_from(number).expect("fixture index");
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{number}")).expect("canonical id"),
        kind,
        value.to_owned(),
        digest(number_u8 + 10),
    );
    let observed = ObservedCue::new(
        CONTRACT_REVISION.into(),
        ObservedCueId::new(format!("observed-{number}")).expect("observed id"),
        kind,
        value.to_owned(),
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
            key_value.to_owned(),
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

fn denominator(
    expected_rows: usize,
    expected_edges: usize,
    omitted_rows: usize,
    omitted_edges: usize,
) -> CueProjectionDenominator {
    CueProjectionDenominator::new(
        expected_rows,
        expected_edges,
        omitted_rows,
        omitted_edges,
        1,
    )
}

#[test]
fn closed_build_freezes_denominator_and_row_identity() -> TestResult {
    let projections = vec![projection_with(
        1,
        "src/a.rs",
        CueKind::Symbol,
        "Task",
        "task",
    )];
    let candidate = build_cue_snapshot_closed(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &projections,
        &[],
        None,
        &denominator(1, 0, 0, 0),
        &[],
    )?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 1);
    let rebuilt = rebuild_cue_snapshot_closed(&candidate, None, &denominator(1, 0, 0, 0), &[])?;
    assert_eq!(rebuilt.build_digest, candidate.build_digest);
    // A denominator that disagrees with the built rows fails closed.
    assert!(
        build_cue_snapshot_closed(
            &WorkScopeId::new("scope-1")?,
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &projections,
            &[],
            None,
            &denominator(2, 0, 0, 0),
            &[],
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn duplicate_semantic_binding_is_rejected_by_closed_build() -> TestResult {
    let first = projection_with(1, "src/a.rs", CueKind::Symbol, "Shared", "shared-a");
    let second = projection_with(2, "src/a.rs", CueKind::Symbol, "Shared", "shared-b");
    let open = build_cue_snapshot(
        &WorkScopeId::new("scope-1")?,
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &[first, second],
        &[],
        None,
    )?;
    assert_eq!(
        open.snapshot.members.len(),
        2,
        "the open build keeps both spellings; closure rejects the binding"
    );
    let first = projection_with(1, "src/a.rs", CueKind::Symbol, "Shared", "shared-a");
    let second = projection_with(2, "src/a.rs", CueKind::Symbol, "Shared", "shared-b");
    assert!(matches!(
        build_cue_snapshot_closed(
            &WorkScopeId::new("scope-1")?,
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &[first, second],
            &[],
            None,
            &denominator(2, 0, 0, 0),
            &[],
        ),
        Err(CueContractError::DuplicateIdentity {
            field: "snapshot.semantic_binding"
        })
    ));
    Ok(())
}

#[test]
fn empty_complete_closed_build_differs_from_partial() -> TestResult {
    let empty = build_cue_snapshot_closed(
        &WorkScopeId::new("scope-empty")?,
        SnapshotId::new("snapshot-empty")?,
        profile(),
        fence(),
        &[],
        &[],
        None,
        &denominator(0, 0, 0, 0),
        &[],
    )?;
    assert!(empty.snapshot.members.is_empty());
    assert!(denominator(0, 0, 0, 0).is_empty_complete());

    // An explicitly partial denominator reconciles but never classifies as
    // empty-complete; a disagreeing one fails closed.
    let partial = denominator(1, 0, 1, 0);
    assert!(!partial.is_empty_complete());
    assert!(
        build_cue_snapshot_closed(
            &WorkScopeId::new("scope-empty")?,
            SnapshotId::new("snapshot-empty")?,
            profile(),
            fence(),
            &[],
            &[],
            None,
            &denominator(2, 0, 1, 0),
            &[],
        )
        .is_err()
    );
    Ok(())
}

// ============================================================================
// Issue #624 proof matrix: `WORK_UNIT_CASE 624/1..42`.
//
// Reading attestation (issue #624 body is authoritative): docs route receipt
// `sha256:2c32769880236360f43329a96fdc754588ebf8a54865c10e40b7ad422dd32a87`,
// read receipt
// `sha256:903d33aa6a2624383e571552b46db45b8ece96b0ee6d721d63bec05a1ca65fd6`
// (routes `generic-source`, `memory-context`; bundle
// `sha256:178c836a9b027d13168486c642bcdb6e22c1294e88d6ba8f98692b780e234fc6`,
// 35 required items), plus direct reads of `I12-06`, `I12-07`, `I12-15`,
// `I12-26`, `I05-18`, `I05-16`, `I05-27`, `I07-20`.
//
// Each test below carries exactly one case marker line for its matrix
// number, placed immediately above its test attribute, in matrix order. Fixtures are
// real admitted-binding projections assembled through the owning A-10
// constructors; every assertion executes the real `build_cue_snapshot`,
// closed-build, or rebuild entry points. Where the matrix names a state word
// the vocabulary spells differently (cases 7 and 19), the test pins the
// exact vocabulary enums (`LifecycleState`, `EpistemicStatus`,
// `EvidenceFreshness`) and records the mapping in a comment.
// ============================================================================

fn scope_id(value: &str) -> WorkScopeId {
    WorkScopeId::new(value).expect("scope id")
}

fn fence_at(sequence: u64) -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn named_profile(id: &str, revision: u32, seed: u8) -> NormalizationProfile {
    NormalizationProfile::new(id.to_owned(), revision, digest(seed))
}

fn named_edge(id: &str, from: &str, to: &str, kind: RelationKind) -> RelationEdge {
    RelationEdge::new(
        RelationEdgeId::new(id).expect("edge id"),
        kind,
        TargetHandle::new(from).expect("from"),
        TargetHandle::new(to).expect("to"),
        "registry-1".into(),
        digest(210),
        context().evidence,
    )
}

fn edge_weight(edge: &str, milli: u16) -> SnapshotEdgeWeight {
    SnapshotEdgeWeight::new(RelationEdgeId::new(edge).expect("edge id"), milli)
}

fn verification_binding() -> VerificationBinding {
    VerificationBinding {
        contract_id: ContractId::new("eval-contract").expect("contract"),
        run_id: ArtifactId::new("run-1").expect("run"),
        revision: "1".into(),
    }
}

/// A projection whose evidence carries `Verified` status through its lawful
/// companions: an assertable envelope plus a current verification binding.
/// `Verified` without both is rejected by the evidence owner before the
/// builder's own currency gate ever runs.
fn verified_projection(number: usize, target: &str) -> AdmittedCueBindingProjection {
    let mut projection = projection(number, target);
    let evidence = &mut projection.normalized.observed.context.evidence;
    evidence.status = EpistemicStatus::Verified;
    evidence.assertability = Assertability::Assertable;
    evidence.verification = Some(verification_binding());
    projection
}

fn verified_edge(id: &str, from: &str, to: &str) -> RelationEdge {
    let mut edge = named_edge(id, from, to, RelationKind::Supports);
    edge.evidence.status = EpistemicStatus::Verified;
    edge.evidence.assertability = Assertability::Assertable;
    edge.evidence.verification = Some(verification_binding());
    edge
}

/// Rebinds every fence field of one projection (context, evidence envelope,
/// admission reference) to a new fence so the re-fenced projection still
/// joins exactly.
fn re_fence(
    mut projection: AdmittedCueBindingProjection,
    fence: &StateFence,
) -> AdmittedCueBindingProjection {
    projection.normalized.observed.context.state_fence = fence.clone();
    projection.normalized.observed.context.evidence.state_fence = fence.clone();
    projection.admission.state_fence = fence.clone();
    projection
}

/// Rebinds one projection (profile plus every comparison-key profile) to a
/// new normalization profile so the re-profiled projection still joins.
fn re_profile(
    mut projection: AdmittedCueBindingProjection,
    profile: &NormalizationProfile,
) -> AdmittedCueBindingProjection {
    projection.normalized.profile = profile.clone();
    for key in &mut projection.normalized.comparison_keys {
        key.profile = profile.clone();
    }
    projection
}

fn open_candidate(
    projections: &[AdmittedCueBindingProjection],
    edges: &[RelationEdge],
    registry: Option<&str>,
) -> Result<CueSnapshotBuildCandidate, CueContractError> {
    build_cue_snapshot(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1").expect("snapshot id"),
        profile(),
        fence(),
        projections,
        edges,
        registry,
    )
}

/// Row-count limb of case 624/29: the package count gate is exact, with 129
/// rows failing closed before any owner work while any fitting count builds.
fn assert_row_count_gate() -> TestResult {
    let fitting: Vec<_> = (1..=100usize)
        .map(|number| projection(number, "src/a.rs"))
        .collect();
    let built = open_candidate(&fitting, &[], None)?;
    assert_eq!(built.snapshot.members.len(), 100);
    let over_count: Vec<_> = (1..=129usize)
        .map(|number| projection(number, "src/a.rs"))
        .collect();
    assert!(matches!(
        open_candidate(&over_count, &[], None),
        Err(CueContractError::BoundExceeded {
            field: "index.bindings",
            ..
        })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 624/1
#[test]
fn minimal_single_row_zero_edge_snapshot() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs")];
    let candidate = open_candidate(&inputs, &[], None)?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 1);
    assert_eq!(
        candidate.snapshot.members[0]
            .canonical
            .canonical_cue_id
            .as_str(),
        "canonical-1"
    );
    assert_eq!(candidate.snapshot.members[0].target.as_str(), "src/a.rs");
    assert_eq!(candidate.admitted_bindings.len(), 1);
    assert_eq!(
        candidate.admitted_bindings[0].candidate,
        inputs[0].candidate
    );
    assert!(candidate.relation_edges.is_empty());
    assert_eq!(candidate.snapshot.rebuild.source_denominator.len(), 1);
    assert_eq!(
        candidate.snapshot.rebuild.source_denominator[0],
        inputs[0].normalized.observed.source
    );
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    Ok(())
}

// WORK_UNIT_CASE: 624/2
#[test]
fn multiple_rows_and_edges_snapshot() -> TestResult {
    let inputs = vec![
        projection(1, "src/a.rs"),
        projection(2, "src/b.rs"),
        projection(3, "src/c.rs"),
    ];
    let edges = vec![
        named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports),
        named_edge("edge-2", "src/b.rs", "src/c.rs", RelationKind::Counters),
    ];
    let candidate = open_candidate(&inputs, &edges, Some("registry-1"))?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 3);
    assert_eq!(candidate.admitted_bindings.len(), 3);
    assert_eq!(candidate.relation_edges.len(), 2);
    // Members are canonicalized by (canonical id, target), not by input order.
    let ids: Vec<_> = candidate
        .snapshot
        .members
        .iter()
        .map(|member| member.canonical.canonical_cue_id.as_str())
        .collect();
    assert_eq!(ids, vec!["canonical-1", "canonical-2", "canonical-3"]);
    let closed = build_cue_snapshot_closed(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &inputs,
        &edges,
        Some("registry-1"),
        &denominator(3, 2, 0, 0),
        &[edge_weight("edge-1", 500), edge_weight("edge-2", 250)],
    )?;
    closed.validate()?;
    assert_eq!(closed.snapshot.members.len(), 3);
    assert_eq!(closed.relation_edges.len(), 2);
    Ok(())
}

// WORK_UNIT_CASE: 624/3
#[test]
fn exact_row_edge_lifecycle_publication_vocabulary() -> TestResult {
    for role in [
        BindingRole::Names,
        BindingRole::Touched,
        BindingRole::ExpectedReuse,
    ] {
        for disposition in [BindingDisposition::Admitted, BindingDisposition::Withheld] {
            let mut input = projection(1, "src/a.rs");
            input.candidate.role = role;
            input.candidate.disposition = disposition;
            let candidate = open_candidate(std::slice::from_ref(&input), &[], None)?;
            candidate.validate()?;
            assert_eq!(candidate.admitted_bindings[0].candidate.role, role);
            assert_eq!(
                candidate.admitted_bindings[0].candidate.disposition,
                disposition
            );
        }
    }
    let candidate = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    // Exact publication vocabulary: A-10 cue revision on the snapshot,
    // independent A-10 index envelope revision on the candidate, and the
    // inert candidate-artifact ceiling (never a live/current claim).
    assert_eq!(candidate.snapshot.schema_revision, CONTRACT_REVISION);
    assert_eq!(candidate.schema_revision, INDEX_CONTRACT_REVISION);
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert!(
        candidate
            .proof_ceiling
            .is_at_most(ProofCeiling::ScopedVerification)
    );
    assert!(
        !candidate
            .proof_ceiling
            .is_at_most(ProofCeiling::Observation)
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/4
#[test]
fn wrong_task_scope_fence_source_profile_identity() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs")];
    // The builder binds task through the admission/context join: there is no
    // separate attempt identity in this surface; `task_id` is the
    // attempt-scoping identity and a wrong one fails the join.
    let mut wrong_task = inputs[0].clone();
    wrong_task.admission.task_id = TaskId::new("task-2")?;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&wrong_task), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.context"
        })
    ));
    // Wrong scope at the build call fails the binding join.
    assert!(matches!(
        build_cue_snapshot(
            &scope_id("scope-2"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &[],
            None,
        ),
        Err(CueContractError::Foundation {
            field: "index.binding"
        })
    ));
    // Wrong scope inside the recorded context fails the admission join first.
    let mut wrong_context_scope = inputs[0].clone();
    wrong_context_scope.normalized.observed.context.scope_id = scope_id("scope-2");
    assert!(matches!(
        open_candidate(std::slice::from_ref(&wrong_context_scope), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.context"
        })
    ));
    // Wrong fence fails the binding join.
    assert!(matches!(
        build_cue_snapshot(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence_at(2),
            &inputs,
            &[],
            None,
        ),
        Err(CueContractError::Foundation {
            field: "index.binding"
        })
    ));
    // Wrong profile fails the binding join.
    assert!(matches!(
        build_cue_snapshot(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            named_profile("other-profile", 1, 9),
            fence(),
            &inputs,
            &[],
            None,
        ),
        Err(CueContractError::Foundation {
            field: "index.binding"
        })
    ));
    // Wrong source scope fails the source join: both provenances move
    // together (the observation keeps its provenance-equality gate), and the
    // sealed denominator rejects the foreign scope with its exact reason.
    let mut wrong_source = inputs[0].clone();
    wrong_source.normalized.observed.source.provenance.scope = "scope-9".into();
    wrong_source
        .normalized
        .observed
        .context
        .evidence
        .provenance
        .scope = "scope-9".into();
    assert!(matches!(
        open_candidate(std::slice::from_ref(&wrong_source), &[], None),
        Err(CueContractError::Foundation {
            field: "index.source.scope"
        })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 624/5
#[test]
fn raw_candidate_forms_rejected_structurally() -> TestResult {
    // A raw A-12 proposal cannot bypass admission: only the joined
    // `AdmittedCueBindingProjection` shape is accepted, and a Governor-side
    // `Rejected` disposition fails closed with its exact reason.
    let mut rejected = projection(1, "src/a.rs");
    rejected.candidate.disposition = BindingDisposition::Rejected;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&rejected), &[], None),
        Err(CueContractError::Foundation {
            field: "projection.rejected"
        })
    ));
    // A tampered candidate digest no longer joins its admission receipt.
    let mut tampered = projection(1, "src/a.rs");
    tampered.candidate.digest = digest(99);
    assert!(matches!(
        open_candidate(std::slice::from_ref(&tampered), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    ));
    // A normalized side that disagrees with the admitted candidate cannot
    // enter the index.
    let mut forked = projection(1, "src/a.rs");
    let mut other_canonical = forked.candidate.canonical.clone();
    other_canonical.canonical_value = "Forked".into();
    forked.normalized.canonical = Some(other_canonical);
    assert!(matches!(
        open_candidate(std::slice::from_ref(&forked), &[], None),
        Err(CueContractError::Foundation {
            field: "projection.canonical"
        })
    ));
    // Governor-admitted proposals keep their exact disposition: `Withheld`
    // lineage is retained, never promoted, and an explicit `Admitted`
    // proposal is retained as admitted.
    let withheld = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    assert_eq!(
        withheld.admitted_bindings[0].candidate.disposition,
        BindingDisposition::Withheld
    );
    let mut admitted = projection(1, "src/a.rs");
    admitted.candidate.disposition = BindingDisposition::Admitted;
    let built = open_candidate(std::slice::from_ref(&admitted), &[], None)?;
    assert_eq!(
        built.admitted_bindings[0].candidate.disposition,
        BindingDisposition::Admitted
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/6
#[test]
fn missing_or_invalid_admission_receipt() -> TestResult {
    // Receipt identity must spell `receipt-<canonical sha>` exactly.
    let mut wrong_id = projection(1, "src/a.rs");
    wrong_id.admission.receipt.receipt_id = ReceiptId::new("receipt-deadbeef")?;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&wrong_id), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    ));
    // A well-formed receipt identity naming a different digest does not
    // join: the identity must spell `receipt-<this receipt's sha>` exactly.
    let mut wrong_digest = projection(1, "src/a.rs");
    wrong_digest.admission.receipt.receipt_id =
        ReceiptId::new(format!("receipt-{}", digest(77).as_str()))?;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&wrong_digest), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    ));
    // A receipt naming a different candidate does not join.
    let mut wrong_candidate = projection(1, "src/a.rs");
    wrong_candidate.admission.candidate_id =
        BindingCandidateId::new("candidate-2").expect("candidate id");
    assert!(matches!(
        open_candidate(std::slice::from_ref(&wrong_candidate), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    ));
    // A blank receipt identity is rejected at the text boundary.
    let mut blank = projection(1, "src/a.rs");
    blank.admission.receipt.canonical_sha256 = String::new();
    assert!(open_candidate(std::slice::from_ref(&blank), &[], None).is_err());
    // A non-digest receipt body is rejected by the digest gate.
    let mut garbage = projection(1, "src/a.rs");
    garbage.admission.receipt.canonical_sha256 = "not-a-digest-at-all".into();
    assert!(matches!(
        open_candidate(std::slice::from_ref(&garbage), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 624/7
#[test]
fn lifecycle_status_freshness_states_distinct() -> TestResult {
    // Matrix words from the issue mapped onto the exact vocabulary: row
    // currency is `LifecycleState`, epistemic currency is `EpistemicStatus`,
    // and recency is `EvidenceFreshness`. Only `Active` rows with supported
    // status and exact freshness may become members.
    for lifecycle in [
        LifecycleState::Archived,
        LifecycleState::Quarantined,
        LifecycleState::Suppressed,
        LifecycleState::Extinguished,
    ] {
        let mut input = projection(1, "src/a.rs");
        input.normalized.observed.context.lifecycle = lifecycle;
        assert!(
            matches!(
                open_candidate(std::slice::from_ref(&input), &[], None),
                Err(CueContractError::Foundation {
                    field: "index.currentness"
                })
            ),
            "lifecycle {lifecycle:?} must fail closed"
        );
    }
    for status in [
        EpistemicStatus::Contested,
        EpistemicStatus::Stale,
        EpistemicStatus::Superseded,
        EpistemicStatus::Rejected,
        EpistemicStatus::Unknown,
    ] {
        let mut input = projection(1, "src/a.rs");
        input.normalized.observed.context.evidence.status = status;
        assert!(
            matches!(
                open_candidate(std::slice::from_ref(&input), &[], None),
                Err(CueContractError::Foundation {
                    field: "index.currentness"
                })
            ),
            "status {status:?} must fail closed"
        );
    }
    for freshness in [
        EvidenceFreshness::KnownOlderSnapshot,
        EvidenceFreshness::Stale,
        EvidenceFreshness::Unknown,
    ] {
        let mut input = projection(1, "src/a.rs");
        input.candidate.freshness = freshness;
        input.normalized.observed.context.evidence.freshness = freshness;
        assert!(
            matches!(
                open_candidate(std::slice::from_ref(&input), &[], None),
                Err(CueContractError::Foundation {
                    field: "index.currentness"
                })
            ),
            "freshness {freshness:?} must fail closed"
        );
    }
    // The supported states each build: active lifecycle, observed/supported
    // status, and every exact freshness on both the candidate and the
    // recorded evidence.
    for freshness in [
        EvidenceFreshness::ExactCandidate,
        EvidenceFreshness::ExactCommit,
        EvidenceFreshness::ExactQuiescedWorktree,
    ] {
        let mut input = projection(1, "src/a.rs");
        input.candidate.freshness = freshness;
        input.normalized.observed.context.evidence.freshness = freshness;
        open_candidate(std::slice::from_ref(&input), &[], None)?;
    }
    let mut supported = projection(1, "src/a.rs");
    supported.normalized.observed.context.evidence.status = EpistemicStatus::Supported;
    open_candidate(std::slice::from_ref(&supported), &[], None)?;
    verified_projection(1, "src/a.rs");
    open_candidate(&[verified_projection(1, "src/a.rs")], &[], None)?;
    Ok(())
}

// WORK_UNIT_CASE: 624/8
#[test]
fn cue_key_profile_target_source_mismatch() -> TestResult {
    // Original cue kind versus canonical kind: the canonical side must agree
    // with the observed original.
    let mut kind_fork = projection(1, "src/a.rs");
    kind_fork
        .normalized
        .canonical
        .as_mut()
        .expect("canonical")
        .kind = CueKind::FilePath;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&kind_fork), &[], None),
        Err(CueContractError::Foundation {
            field: "canonical.kind"
        })
    ));
    // Comparison-key profile must be the profile the row was folded under.
    let mut key_profile = projection(1, "src/a.rs");
    key_profile.normalized.comparison_keys[0].profile = named_profile("other-profile", 1, 9);
    assert!(matches!(
        open_candidate(std::slice::from_ref(&key_profile), &[], None),
        Err(CueContractError::Foundation {
            field: "comparison_key.profile"
        })
    ));
    // Prefix matching is inadmissible for symbol cues: an unsupported
    // kind/mode combination fails closed.
    let mut key_mode = projection(1, "src/a.rs");
    key_mode.normalized.comparison_keys[0].match_mode = MatchMode::Prefix;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&key_mode), &[], None),
        Err(CueContractError::Foundation {
            field: "comparison_key.match_mode"
        })
    ));
    // The bound target is preserved exactly as admitted: never retargeted,
    // never normalized into a different handle.
    let candidate = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    assert_eq!(candidate.snapshot.members[0].target.as_str(), "src/a.rs");
    assert_eq!(
        candidate.snapshot.members[0].target,
        candidate.admitted_bindings[0].candidate.target
    );
    // The source denominator carries the exact observed source handle.
    assert_eq!(
        candidate.snapshot.rebuild.source_denominator,
        vec![
            candidate.admitted_bindings[0]
                .normalized
                .observed
                .source
                .clone()
        ]
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/9
#[test]
fn exact_duplicate_rejected_shared_source_retained() -> TestResult {
    // An exact duplicate (same binding-candidate identity twice) conflicts;
    // it is never coalesced silently.
    let duplicate = vec![projection(1, "src/a.rs"), projection(1, "src/a.rs")];
    assert!(matches!(
        open_candidate(&duplicate, &[], None),
        Err(CueContractError::DuplicateIdentity {
            field: "index.candidate_ids"
        })
    ));
    // Two distinct candidates converging on one (canonical, target) member
    // also conflict rather than electing a winner.
    let convergent_first = projection(1, "src/a.rs");
    let mut convergent_second = projection(2, "src/a.rs");
    convergent_second.candidate.canonical = convergent_first.candidate.canonical.clone();
    convergent_second.normalized.canonical = Some(convergent_first.candidate.canonical.clone());
    let convergent = vec![convergent_first, convergent_second];
    assert!(matches!(
        open_candidate(&convergent, &[], None),
        Err(CueContractError::DuplicateIdentity {
            field: "index.members"
        })
    ));
    // Permitted sharing is retained with full lineage: two distinct bindings
    // observed from one identical source keep both members and both
    // admission joins while the denominator holds the source once.
    let first = projection(1, "src/a.rs");
    let mut second = projection(2, "src/b.rs");
    second.normalized.observed.source = first.normalized.observed.source.clone();
    let shared = open_candidate(&[first, second], &[], None)?;
    shared.validate()?;
    assert_eq!(shared.snapshot.members.len(), 2);
    assert_eq!(shared.admitted_bindings.len(), 2);
    assert_eq!(shared.snapshot.rebuild.source_denominator.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 624/10
#[test]
fn same_id_changed_payload_conflicts() {
    // Same canonical id with changed canonical content conflicts, even when
    // the member slots differ.
    let mut first = projection(1, "src/a.rs");
    let mut second = projection(2, "src/b.rs");
    let mut changed = second.candidate.canonical.clone();
    changed.canonical_cue_id = first.candidate.canonical.canonical_cue_id.clone();
    changed.canonical_value = "Changed".into();
    first.candidate.canonical = first.candidate.canonical.clone();
    second.candidate.canonical = changed.clone();
    second.normalized.canonical = Some(changed);
    assert!(matches!(
        open_candidate(&[first, second], &[], None),
        Err(CueContractError::DuplicateIdentity {
            field: "index.canonical_ids"
        })
    ));
    // Same binding id with a changed digest no longer joins its receipt.
    let mut stale_receipt = projection(1, "src/a.rs");
    stale_receipt.candidate.digest = digest(99);
    assert!(matches!(
        open_candidate(std::slice::from_ref(&stale_receipt), &[], None),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    ));
    // Same source key with a changed source record conflicts rather than
    // overwriting the recorded source.
    let first = projection(1, "src/a.rs");
    let mut second = projection(2, "src/b.rs");
    second.normalized.observed.source = first.normalized.observed.source.clone();
    // Both provenances move together so the observation's own
    // provenance-equality gate still passes and the duplicate is decided at
    // the source-denominator join, not earlier.
    second.normalized.observed.source.provenance.capture_route = "other-route".into();
    second
        .normalized
        .observed
        .context
        .evidence
        .provenance
        .capture_route = "other-route".into();
    assert!(matches!(
        open_candidate(&[first, second], &[], None),
        Err(CueContractError::DuplicateIdentity {
            field: "index.sources"
        })
    ));
}

// WORK_UNIT_CASE: 624/11
#[test]
fn shared_key_bindings_remain_distinct() -> TestResult {
    // Different bindings that folded to one comparison value stay distinct
    // rows: key equality never coalesces admitted bindings.
    let first = projection_with(1, "src/a.rs", CueKind::Symbol, "Shared", "shared");
    let second = projection_with(2, "src/b.rs", CueKind::Symbol, "Shared", "shared");
    let candidate = open_candidate(&[first.clone(), second.clone()], &[], None)?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 2);
    let values: Vec<_> = candidate
        .admitted_bindings
        .iter()
        .map(|projection| projection.normalized.comparison_keys[0].key_value.clone())
        .collect();
    assert_eq!(values, vec!["shared".to_owned(), "shared".to_owned()]);
    assert_ne!(
        candidate.admitted_bindings[0]
            .candidate
            .binding_candidate_id,
        candidate.admitted_bindings[1]
            .candidate
            .binding_candidate_id
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/12
#[test]
fn no_collision_winner_from_order_confidence_or_recency() -> TestResult {
    // A same-identity conflict errors in both input orders: no position,
    // confidence, or recency signal can elect a winner because the surface
    // carries none of those fields.
    let forward = vec![projection(1, "src/a.rs"), projection(1, "src/a.rs")];
    let mut backward = forward.clone();
    backward.reverse();
    assert!(open_candidate(&forward, &[], None).is_err());
    assert!(open_candidate(&backward, &[], None).is_err());
    // Valid inputs permute to one identical snapshot: input order contributes
    // nothing to identity.
    let left = open_candidate(
        &[projection(1, "src/a.rs"), projection(2, "src/b.rs")],
        &[],
        None,
    )?;
    let right = open_candidate(
        &[projection(2, "src/b.rs"), projection(1, "src/a.rs")],
        &[],
        None,
    )?;
    assert_eq!(left.build_digest, right.build_digest);
    assert_eq!(
        left.canonical_payload_bytes()?,
        right.canonical_payload_bytes()?
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/13
#[test]
fn typed_directed_edges_accepted() -> TestResult {
    // Every canonical relation family is accepted as a typed directed edge.
    for (index, kind) in [
        RelationKind::Supports,
        RelationKind::Counters,
        RelationKind::Supersedes,
        RelationKind::DerivedFrom,
        RelationKind::AppliesTo,
        RelationKind::ObservedIn,
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("edge-{index}");
        let edge = named_edge(&id, "src/a.rs", "src/b.rs", kind);
        let candidate = open_candidate(
            &[projection(1, "src/a.rs"), projection(2, "src/b.rs")],
            std::slice::from_ref(&edge),
            Some("registry-1"),
        )?;
        candidate.validate()?;
        assert_eq!(candidate.relation_edges[0].kind, kind);
        assert_eq!(candidate.relation_edges[0].from.as_str(), "src/a.rs");
        assert_eq!(candidate.relation_edges[0].to.as_str(), "src/b.rs");
    }
    // Direction is endpoint order, preserved exactly: the reverse edge is a
    // distinct directed edge, not a duplicate and not a normalization.
    let pair = vec![
        named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports),
        named_edge("edge-2", "src/b.rs", "src/a.rs", RelationKind::Supports),
    ];
    let candidate = open_candidate(
        &[projection(1, "src/a.rs"), projection(2, "src/b.rs")],
        &pair,
        Some("registry-1"),
    )?;
    assert_eq!(candidate.relation_edges.len(), 2);
    assert_ne!(
        candidate.relation_edges[0].from,
        candidate.relation_edges[0].to
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/14
#[test]
fn unknown_or_unsupported_kind_or_direction_rejected() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    // A weight naming an unknown edge cannot close the snapshot.
    assert!(
        build_cue_snapshot_closed(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &edges,
            Some("registry-1"),
            &denominator(2, 1, 0, 0),
            &[edge_weight("edge-9", 500)],
        )
        .is_err()
    );
    // A weight above unity is rejected with its exact bound.
    assert!(matches!(
        build_cue_snapshot_closed(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &edges,
            Some("registry-1"),
            &denominator(2, 1, 0, 0),
            &[edge_weight("edge-1", 1001)],
        ),
        Err(CueContractError::BoundExceeded {
            field: "snapshot.edge.weight",
            ..
        })
    ));
    // Prefix matching is an unsupported matching direction for symbol cues.
    let mut unsupported = projection(1, "src/a.rs");
    unsupported.normalized.comparison_keys[0].match_mode = MatchMode::Prefix;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&unsupported), &[], None),
        Err(CueContractError::Foundation {
            field: "comparison_key.match_mode"
        })
    ));
    // A symbol-qualified comparison form is unsupported for path cues.
    let mut path = projection_with(1, "src/a.rs", CueKind::FilePath, "src/a.rs", "src/a.rs");
    path.normalized.comparison_keys[0].form = ComparisonForm::SymbolQualified;
    path.normalized.comparison_keys[0].match_mode = MatchMode::Exact;
    assert!(matches!(
        open_candidate(std::slice::from_ref(&path), &[], None),
        Err(CueContractError::Foundation {
            field: "comparison_key.form"
        })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 624/15
#[test]
fn wrong_registry_revision_rejected() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    // An edge resolved under a different registry revision fails the join.
    assert!(matches!(
        open_candidate(&inputs, &edges, Some("registry-2")),
        Err(CueContractError::Foundation {
            field: "index.edge_binding"
        })
    ));
    // A non-empty edge set without an explicit revision fails closed rather
    // than defaulting to whatever revision happens to be current.
    assert!(matches!(
        open_candidate(&inputs, &edges, None),
        Err(CueContractError::Foundation {
            field: "index.registry_revision"
        })
    ));
    // The matching revision builds.
    open_candidate(&inputs, &edges, Some("registry-1"))?;
    Ok(())
}

// WORK_UNIT_CASE: 624/16
#[test]
fn dangling_source_endpoint_rejected() {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let dangling = vec![named_edge(
        "edge-1",
        "src/ghost.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    assert!(matches!(
        open_candidate(&inputs, &dangling, Some("registry-1")),
        Err(CueContractError::Foundation {
            field: "index.edge.endpoint"
        })
    ));
}

// WORK_UNIT_CASE: 624/17
#[test]
fn dangling_target_endpoint_rejected() {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let dangling = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/ghost.rs",
        RelationKind::Supports,
    )];
    assert!(matches!(
        open_candidate(&inputs, &dangling, Some("registry-1")),
        Err(CueContractError::Foundation {
            field: "index.edge.endpoint"
        })
    ));
    let both_dangling = vec![named_edge(
        "edge-1",
        "src/ghost-a.rs",
        "src/ghost-b.rs",
        RelationKind::Supports,
    )];
    assert!(matches!(
        open_candidate(&inputs, &both_dangling, Some("registry-1")),
        Err(CueContractError::Foundation {
            field: "index.edge.endpoint"
        })
    ));
}

// WORK_UNIT_CASE: 624/18
#[test]
fn cross_scope_or_wrong_fence_edge_rejected() {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    // An edge captured outside the build scope cannot join this snapshot.
    let mut foreign = named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports);
    foreign.evidence.provenance.scope = "scope-9".into();
    assert!(matches!(
        open_candidate(&inputs, std::slice::from_ref(&foreign), Some("registry-1")),
        Err(CueContractError::Foundation {
            field: "index.edge_binding"
        })
    ));
    // An edge fenced at a different causal snapshot cannot join either.
    let mut stale_fence = named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports);
    stale_fence.evidence.state_fence = fence_at(2);
    assert!(matches!(
        open_candidate(
            &inputs,
            std::slice::from_ref(&stale_fence),
            Some("registry-1")
        ),
        Err(CueContractError::Foundation {
            field: "index.edge_binding"
        })
    ));
}

// WORK_UNIT_CASE: 624/19
#[test]
fn edge_currency_states_distinct() -> TestResult {
    // Edges carry no lifecycle of their own: their currency is the evidence
    // envelope's freshness and epistemic status, gated by the same supported
    // sets as rows (case 7) through the edge join.
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    for freshness in [
        EvidenceFreshness::KnownOlderSnapshot,
        EvidenceFreshness::Stale,
        EvidenceFreshness::Unknown,
    ] {
        let mut edge = named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports);
        edge.evidence.freshness = freshness;
        assert!(
            matches!(
                open_candidate(&inputs, std::slice::from_ref(&edge), Some("registry-1")),
                Err(CueContractError::Foundation {
                    field: "index.edge_binding"
                })
            ),
            "edge freshness {freshness:?} must fail closed"
        );
    }
    for status in [
        EpistemicStatus::Contested,
        EpistemicStatus::Stale,
        EpistemicStatus::Superseded,
        EpistemicStatus::Rejected,
        EpistemicStatus::Unknown,
    ] {
        let mut edge = named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports);
        edge.evidence.status = status;
        assert!(
            matches!(
                open_candidate(&inputs, std::slice::from_ref(&edge), Some("registry-1")),
                Err(CueContractError::Foundation {
                    field: "index.edge_binding"
                })
            ),
            "edge status {status:?} must fail closed"
        );
    }
    for freshness in [
        EvidenceFreshness::ExactCandidate,
        EvidenceFreshness::ExactCommit,
        EvidenceFreshness::ExactQuiescedWorktree,
    ] {
        let mut edge = named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports);
        edge.evidence.freshness = freshness;
        open_candidate(&inputs, std::slice::from_ref(&edge), Some("registry-1"))?;
    }
    let mut supported = named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports);
    supported.evidence.status = EpistemicStatus::Supported;
    open_candidate(
        &inputs,
        std::slice::from_ref(&supported),
        Some("registry-1"),
    )?;
    open_candidate(
        &inputs,
        std::slice::from_ref(&verified_edge("edge-1", "src/a.rs", "src/b.rs")),
        Some("registry-1"),
    )?;
    Ok(())
}

// WORK_UNIT_CASE: 624/20
#[test]
fn duplicate_or_changed_edge_id_conflicts() {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    // The same edge identity twice conflicts, even with identical payloads.
    let duplicated = vec![
        named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports),
        named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports),
    ];
    assert!(matches!(
        open_candidate(&inputs, &duplicated, Some("registry-1")),
        Err(CueContractError::DuplicateIdentity {
            field: "index.edge_ids"
        })
    ));
    // A changed payload under a reused edge identity still collides on the
    // identity: there is no silent edge replacement.
    let changed = vec![
        named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports),
        named_edge("edge-1", "src/b.rs", "src/a.rs", RelationKind::Counters),
    ];
    assert!(matches!(
        open_candidate(&inputs, &changed, Some("registry-1")),
        Err(CueContractError::DuplicateIdentity {
            field: "index.edge_ids"
        })
    ));
}

// WORK_UNIT_CASE: 624/21
#[test]
fn no_edges_inferred_from_key_cooccurrence_or_similarity() -> TestResult {
    // Two bindings sharing one comparison value and one target-adjacent
    // neighborhood still yield zero edges: the builder never mines equality,
    // co-occurrence, chronology, similarity, or model text into relations
    // (I05.18: similarity/co-occurrence cannot become causal relation without
    // a separate governed transition, which this package does not perform).
    let first = projection_with(1, "src/a.rs", CueKind::Symbol, "Shared", "shared");
    let second = projection_with(2, "src/a.rs", CueKind::Symbol, "Shared", "shared");
    let candidate = open_candidate(&[first, second], &[], None)?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 2);
    assert!(candidate.relation_edges.is_empty());
    let nearby = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let candidate = open_candidate(&nearby, &[], None)?;
    assert!(candidate.relation_edges.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 624/22
#[test]
fn zero_edge_snapshot_valid_for_later_direct_activation() -> TestResult {
    // A zero-edge snapshot is complete for direct exact firing (I12.26:
    // exact cues stay usable with an empty graph); edges arrive later
    // through a new build, never by mutation.
    let candidate = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 1);
    let row_id = candidate.snapshot.members[0].row_id("scope-1", MatchMode::Exact, "symbol1")?;
    assert!(row_id.starts_with("cuev2:"));
    // An explicit revision is also accepted for the empty edge set.
    let with_revision = open_candidate(&[projection(1, "src/a.rs")], &[], Some("registry-1"))?;
    with_revision.validate()?;
    assert_eq!(with_revision.snapshot.members.len(), 1);
    // The explicitly empty build remains a scoped candidate.
    let empty = build_cue_snapshot(
        &scope_id("scope-empty"),
        SnapshotId::new("snapshot-empty")?,
        profile(),
        fence(),
        &[],
        &[],
        None,
    )?;
    empty.validate()?;
    assert!(empty.snapshot.members.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 624/23
#[test]
fn exact_complete_source_row_and_edge_denominators() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    let complete = denominator(2, 1, 0, 0);
    assert!(complete.is_complete());
    let candidate = build_cue_snapshot_closed(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &inputs,
        &edges,
        Some("registry-1"),
        &complete,
        &[edge_weight("edge-1", 500)],
    )?;
    candidate.validate()?;
    complete.validate_against(2, 1)?;
    // The known-empty claim is exact: zero expected with zero omissions.
    let known_empty = denominator(0, 0, 0, 0);
    assert!(known_empty.is_empty_complete());
    assert!(known_empty.is_complete());
    build_cue_snapshot_closed(
        &scope_id("scope-empty"),
        SnapshotId::new("snapshot-empty")?,
        profile(),
        fence(),
        &[],
        &[],
        None,
        &known_empty,
        &[],
    )?;
    // Any count disagreement fails closed.
    assert!(
        build_cue_snapshot_closed(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &edges,
            Some("registry-1"),
            &denominator(3, 1, 0, 0),
            &[edge_weight("edge-1", 500)],
        )
        .is_err()
    );
    assert!(
        build_cue_snapshot_closed(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &edges,
            Some("registry-1"),
            &denominator(2, 2, 0, 0),
            &[edge_weight("edge-1", 500)],
        )
        .is_err()
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/24
#[test]
fn partial_or_unavailable_source_never_complete_or_known_empty() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs")];
    // A denominator that claims rows the build did not supply fails closed.
    assert!(
        build_cue_snapshot_closed(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &[],
            None,
            &denominator(2, 0, 0, 0),
            &[],
        )
        .is_err()
    );
    // A denominator that claims edges the build did not supply fails closed.
    assert!(
        build_cue_snapshot_closed(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &inputs,
            &[],
            None,
            &denominator(1, 1, 0, 0),
            &[],
        )
        .is_err()
    );
    // Omissions beyond the declared totals are rejected at the denominator.
    let over_omitted = denominator(1, 0, 2, 0);
    assert!(over_omitted.validate().is_err());
    assert!(over_omitted.validate_against(0, 0).is_err());
    // A partial denominator never classifies as complete or known-empty,
    // even when nothing is present.
    let partial = denominator(2, 0, 1, 0);
    assert!(!partial.is_complete());
    assert!(!partial.is_empty_complete());
    Ok(())
}

// WORK_UNIT_CASE: 624/25
#[test]
fn exactly_one_disposition_per_source_row_and_edge() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    let candidate = open_candidate(&inputs, &edges, Some("registry-1"))?;
    candidate.validate()?;
    // Nothing is silently dropped and nothing is duplicated: the member set,
    // the retained projections, and the retained edges reconcile exactly.
    assert_eq!(candidate.snapshot.members.len(), inputs.len());
    assert_eq!(candidate.admitted_bindings.len(), inputs.len());
    assert_eq!(candidate.relation_edges.len(), edges.len());
    for member in &candidate.snapshot.members {
        let hits = candidate
            .admitted_bindings
            .iter()
            .filter(|projection| {
                projection.candidate.canonical == member.canonical
                    && projection.candidate.target == member.target
            })
            .count();
        assert_eq!(
            hits, 1,
            "member {member:?} must have exactly one source row"
        );
    }
    let mut edge_ids: Vec<_> = candidate
        .relation_edges
        .iter()
        .map(|edge| edge.relation_edge_id.as_str())
        .collect();
    edge_ids.sort_unstable();
    edge_ids.dedup();
    assert_eq!(edge_ids.len(), edges.len());
    Ok(())
}

// WORK_UNIT_CASE: 624/26
#[test]
fn omitted_source_yields_declared_partial_result() -> TestResult {
    // An unavailable row is declared in the frozen denominator (`omitted`
    // counts), never dropped invisibly: the result is partial by profile,
    // with the held-back row reconciled rather than missing.
    let inputs = vec![projection(1, "src/a.rs")];
    let partial = denominator(2, 0, 1, 0);
    let candidate = build_cue_snapshot_closed(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &inputs,
        &[],
        None,
        &partial,
        &[],
    )?;
    candidate.validate()?;
    assert_eq!(candidate.snapshot.members.len(), 1);
    assert!(!partial.is_complete());
    assert!(!partial.is_empty_complete());
    partial.validate_against(1, 0)?;
    let rebuilt = rebuild_cue_snapshot_closed(&candidate, None, &partial, &[])?;
    assert_eq!(rebuilt.build_digest, candidate.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 624/27
#[test]
fn invalid_load_bearing_member_fails_the_candidate() -> TestResult {
    // An invalid load-bearing member yields no candidate at all: the build
    // is `Err`, so there is no partial publication to mistake for success.
    let mut rejected = projection(1, "src/a.rs");
    rejected.candidate.disposition = BindingDisposition::Rejected;
    assert!(open_candidate(std::slice::from_ref(&rejected), &[], None).is_err());
    let mut broken_receipt = projection(1, "src/a.rs");
    broken_receipt.candidate.digest = digest(99);
    assert!(open_candidate(std::slice::from_ref(&broken_receipt), &[], None).is_err());
    // Failure is pure: the same inputs minus the invalid member still build,
    // and an earlier valid candidate is untouched by later failures.
    let prior = open_candidate(&[projection(2, "src/b.rs")], &[], None)?;
    prior.validate()?;
    assert_eq!(prior.snapshot.members.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 624/28
#[test]
fn rejected_member_keeps_exact_handle_and_reason() {
    let input = projection(1, "src/a.rs");
    let mut rejected = input.clone();
    rejected.candidate.disposition = BindingDisposition::Rejected;
    let error = open_candidate(std::slice::from_ref(&rejected), &[], None)
        .expect_err("rejected member must fail");
    // The rejection names its exact machine-readable reason: no prose
    // parsing is needed to act on it (I07.20 classifiable failures).
    assert_eq!(
        error,
        CueContractError::Foundation {
            field: "projection.rejected"
        }
    );
    // The supplied member is borrowed, never consumed or repaired: its
    // handle and reason survive the failed build for the caller to report.
    assert_eq!(rejected, {
        let mut again = input.clone();
        again.candidate.disposition = BindingDisposition::Rejected;
        again
    });
    assert_eq!(
        rejected.candidate.binding_candidate_id.as_str(),
        "candidate-1"
    );
    // The reason is deterministic across repeated builds.
    let repeat = open_candidate(std::slice::from_ref(&rejected), &[], None)
        .expect_err("rejected member must fail deterministically");
    assert_eq!(repeat, error);
}

// WORK_UNIT_CASE: 624/29
#[test]
fn row_edge_text_bounds_and_one_over() -> TestResult {
    assert_row_count_gate()?;
    // At the count ceiling the contract byte budget binds first for full
    // projections: 128 x 32 KiB structure reservations exceed the exact
    // 4 MiB input budget, so the bound hit names the byte gate and limit.
    let full_house: Vec<_> = (1..=128usize)
        .map(|number| projection(number, "src/a.rs"))
        .collect();
    assert!(matches!(
        open_candidate(&full_house, &[], None),
        Err(CueContractError::BoundExceeded {
            field: "index.projection.structure",
            limit: 4_194_304,
        })
    ));
    // Exactly 128 edges build against two member endpoints; 129 fail closed.
    let members = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges_at_limit: Vec<_> = (1..=128usize)
        .map(|number| {
            named_edge(
                &format!("edge-{number}"),
                "src/a.rs",
                "src/b.rs",
                RelationKind::Supports,
            )
        })
        .collect();
    let with_edges = open_candidate(&members, &edges_at_limit, Some("registry-1"))?;
    assert_eq!(with_edges.relation_edges.len(), 128);
    let mut edges_over = edges_at_limit.clone();
    edges_over.push(named_edge(
        "edge-129",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    ));
    assert!(matches!(
        open_candidate(&members, &edges_over, Some("registry-1")),
        Err(CueContractError::BoundExceeded {
            field: "index.edges",
            ..
        })
    ));
    // Oversized text fails at the measured-text bound, not at allocation.
    let oversized = "x".repeat(9 * 1024);
    assert!(matches!(
        build_cue_snapshot(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            named_profile(&oversized, 1, 1),
            fence(),
            &members,
            &[],
            None,
        ),
        Err(CueContractError::BoundExceeded {
            field: "index.profile",
            ..
        })
    ));
    // Oversized and blank identities are rejected at their constructors;
    // the receipts scope carries no length cap of its own, so an oversized
    // scope fails at the build input budget instead.
    assert!(WorkScopeId::new(String::new()).is_err());
    assert!(WorkScopeId::new("has\ncontrol").is_err());
    assert!(SnapshotId::new(String::new()).is_err());
    assert!(SnapshotId::new("x".repeat(513)).is_err());
    assert!(TargetHandle::new("has\ncontrol").is_err());
    assert!(
        build_cue_snapshot(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &members,
            &[],
            None,
        )
        .is_ok()
    );
    assert!(matches!(
        build_cue_snapshot(
            &WorkScopeId::new("s".repeat(9 * 1024)).expect("long scope"),
            SnapshotId::new("snapshot-1")?,
            profile(),
            fence(),
            &members,
            &[],
            None,
        ),
        Err(CueContractError::BoundExceeded {
            field: "index.scope",
            ..
        })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 624/30
#[test]
fn bound_hit_never_complete_and_preserves_omissions() -> TestResult {
    // A bound hit emits no candidate: there is no complete snapshot to
    // mistake the failure for.
    let mut too_many = vec![projection(1, "src/a.rs"); 129];
    for (index, projection) in too_many.iter_mut().enumerate() {
        let number = format!("candidate-{index}");
        projection.candidate.binding_candidate_id =
            BindingCandidateId::new(number).expect("candidate id");
    }
    assert!(matches!(
        open_candidate(&too_many, &[], None),
        Err(CueContractError::BoundExceeded {
            field: "index.bindings",
            ..
        })
    ));
    // Declared omissions reconcile as partial and stay partial: the frozen
    // denominator preserves expected/omitted counts and never classifies the
    // result complete, even with zero rows present.
    let partial = denominator(1, 0, 1, 0);
    assert_eq!(partial.expected_rows, 1);
    assert_eq!(partial.omitted_rows, 1);
    let held_back = build_cue_snapshot_closed(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &[],
        &[],
        None,
        &partial,
        &[],
    )?;
    held_back.validate()?;
    assert!(held_back.snapshot.members.is_empty());
    assert!(!partial.is_complete());
    assert!(!partial.is_empty_complete());
    Ok(())
}

// WORK_UNIT_CASE: 624/31
#[test]
fn input_permutation_preserves_canonical_bytes_and_digest() -> TestResult {
    let inputs = vec![
        projection(1, "src/a.rs"),
        projection(2, "src/b.rs"),
        projection(3, "src/c.rs"),
    ];
    let edges = vec![
        named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports),
        named_edge("edge-2", "src/b.rs", "src/c.rs", RelationKind::Counters),
    ];
    let forward = open_candidate(&inputs, &edges, Some("registry-1"))?;
    let mut reversed_inputs = inputs.clone();
    reversed_inputs.reverse();
    let mut reversed_edges = edges.clone();
    reversed_edges.reverse();
    let reversed = open_candidate(&reversed_inputs, &reversed_edges, Some("registry-1"))?;
    assert_eq!(
        forward.canonical_payload_bytes()?,
        reversed.canonical_payload_bytes()?
    );
    assert_eq!(forward.build_digest, reversed.build_digest);
    assert_eq!(
        forward.snapshot.rebuild.digest,
        reversed.snapshot.rebuild.digest
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/32
#[test]
fn any_member_change_changes_or_invalidates_identity() -> TestResult {
    let baseline = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    // A different snapshot identity builds a different snapshot.
    let renamed = build_cue_snapshot(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-2")?,
        profile(),
        fence(),
        &[projection(1, "src/a.rs")],
        &[],
        None,
    )?;
    assert_ne!(renamed.build_digest, baseline.build_digest);
    // A different profile builds a different snapshot.
    let other_profile = named_profile("profile-2", 2, 44);
    let reprofiled_input = re_profile(projection(1, "src/a.rs"), &other_profile);
    let reprofiled = build_cue_snapshot(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        other_profile,
        fence(),
        std::slice::from_ref(&reprofiled_input),
        &[],
        None,
    )?;
    assert_ne!(reprofiled.build_digest, baseline.build_digest);
    // A different fence builds a different snapshot.
    let other_fence = fence_at(2);
    let refenced_input = re_fence(projection(1, "src/a.rs"), &other_fence);
    let refenced = build_cue_snapshot(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        other_fence,
        std::slice::from_ref(&refenced_input),
        &[],
        None,
    )?;
    assert_ne!(refenced.build_digest, baseline.build_digest);
    // A swapped row at identical counts builds a different snapshot.
    let swapped = open_candidate(&[projection(2, "src/a.rs")], &[], None)?;
    assert_ne!(swapped.build_digest, baseline.build_digest);
    // A changed source digest builds a different snapshot.
    let mut changed_source = projection(1, "src/a.rs");
    changed_source.normalized.observed.source =
        SourceHandle::new(TargetHandle::new("src/a.rs")?, digest(77), provenance());
    let resourced = open_candidate(std::slice::from_ref(&changed_source), &[], None)?;
    assert_ne!(resourced.build_digest, baseline.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 624/33
#[test]
fn exact_manifest_rebuild_succeeds() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    let candidate = open_candidate(&inputs, &edges, Some("registry-1"))?;
    let rebuilt = rebuild_cue_snapshot(&candidate, Some("registry-1"))?;
    assert_eq!(rebuilt.build_digest, candidate.build_digest);
    assert_eq!(
        rebuilt.canonical_payload_bytes()?,
        candidate.canonical_payload_bytes()?
    );
    assert_eq!(rebuilt.admitted_bindings, candidate.admitted_bindings);
    assert_eq!(rebuilt.relation_edges, candidate.relation_edges);
    assert_eq!(
        rebuilt.snapshot.rebuild.digest,
        candidate.snapshot.rebuild.digest
    );
    // The closed manifest rebuilds too, re-proving its denominator closure.
    let complete = denominator(2, 1, 0, 0);
    let closed = build_cue_snapshot_closed(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &inputs,
        &edges,
        Some("registry-1"),
        &complete,
        &[edge_weight("edge-1", 500)],
    )?;
    let closed_rebuilt = rebuild_cue_snapshot_closed(
        &closed,
        Some("registry-1"),
        &complete,
        &[edge_weight("edge-1", 500)],
    )?;
    assert_eq!(closed_rebuilt.build_digest, closed.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 624/34
#[test]
fn missing_source_member_fails_rebuild() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    let candidate = open_candidate(&inputs, &edges, Some("registry-1"))?;
    // A dropped member no longer matches the sealed digest.
    let mut dropped_member = candidate.clone();
    dropped_member.snapshot.members.pop();
    assert!(rebuild_cue_snapshot(&dropped_member, Some("registry-1")).is_err());
    // A dropped admitted binding breaks member coverage.
    let mut dropped_binding = candidate.clone();
    dropped_binding.admitted_bindings.pop();
    assert!(rebuild_cue_snapshot(&dropped_binding, Some("registry-1")).is_err());
    // A dropped source breaks denominator coverage.
    let mut dropped_source = candidate.clone();
    dropped_source.snapshot.rebuild.source_denominator.pop();
    assert!(rebuild_cue_snapshot(&dropped_source, Some("registry-1")).is_err());
    // A dropped edge breaks the sealed edge set.
    let mut dropped_edge = candidate.clone();
    dropped_edge.relation_edges.pop();
    assert!(rebuild_cue_snapshot(&dropped_edge, Some("registry-1")).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 624/35
#[test]
fn changed_order_profile_endpoint_or_admission_fails_rebuild() -> TestResult {
    let mut inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    inputs[0]
        .normalized
        .comparison_keys
        .push(ComparisonKey::new(
            ComparisonKeyId::new("key-1b").expect("key id"),
            profile(),
            "symbol1b".into(),
            MatchMode::Exact,
            ComparisonForm::Exact,
        ));
    let candidate = open_candidate(&inputs, &[], None)?;
    // Set-like ordering is canonicalized: reordering comparison keys keeps
    // the exact identity and still rebuilds.
    let mut reordered = candidate.clone();
    let keys = std::mem::take(&mut reordered.admitted_bindings[0].normalized.comparison_keys);
    let mut reversed_keys = keys;
    reversed_keys.reverse();
    reordered.admitted_bindings[0].normalized.comparison_keys = reversed_keys;
    let rebuilt = rebuild_cue_snapshot(&reordered, None)?;
    assert_eq!(rebuilt.build_digest, candidate.build_digest);
    // Changed key content invalidates the manifest.
    let mut changed_key = candidate.clone();
    changed_key.admitted_bindings[0].normalized.comparison_keys[0].key_value =
        "something-else".into();
    assert!(rebuild_cue_snapshot(&changed_key, None).is_err());
    // A changed profile invalidates the manifest.
    let mut changed_profile = candidate.clone();
    changed_profile.snapshot.rebuild.normalization_profile = named_profile("profile-2", 2, 44);
    assert!(rebuild_cue_snapshot(&changed_profile, None).is_err());
    // A changed edge endpoint invalidates the manifest even when the new
    // endpoint still resolves: identity binds endpoints, not just validity.
    let edged = open_candidate(
        &inputs,
        &[named_edge(
            "edge-1",
            "src/a.rs",
            "src/b.rs",
            RelationKind::Supports,
        )],
        Some("registry-1"),
    )?;
    let mut changed_endpoint = edged.clone();
    changed_endpoint.relation_edges[0].to = TargetHandle::new("src/a.rs")?;
    assert!(rebuild_cue_snapshot(&changed_endpoint, Some("registry-1")).is_err());
    // A swapped edge direction is a different snapshot, not the same one
    // reordered: direction is semantic and part of identity.
    let swapped = open_candidate(
        &inputs,
        &[named_edge(
            "edge-1",
            "src/b.rs",
            "src/a.rs",
            RelationKind::Supports,
        )],
        Some("registry-1"),
    )?;
    assert_ne!(swapped.build_digest, edged.build_digest);
    // A changed admission receipt invalidates the manifest.
    let mut changed_receipt = candidate.clone();
    let replacement = digest(78);
    changed_receipt.admitted_bindings[0]
        .admission
        .receipt
        .receipt_id = ReceiptId::new(format!("receipt-{}", replacement.as_str()))?;
    changed_receipt.admitted_bindings[0]
        .admission
        .receipt
        .canonical_sha256 = replacement.as_str().into();
    assert!(rebuild_cue_snapshot(&changed_receipt, None).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 624/36
#[test]
fn matching_counts_without_identity_cannot_prove_rebuild() -> TestResult {
    // Same shape, same counts, different rows: different identities.
    let first = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    let second = open_candidate(&[projection(2, "src/b.rs")], &[], None)?;
    assert_eq!(first.snapshot.members.len(), second.snapshot.members.len());
    assert_ne!(first.build_digest, second.build_digest);
    // Cross-wired materials (one snapshot's members, another's bindings)
    // fail validation and therefore fail rebuild.
    let mut crossed = first.clone();
    crossed.admitted_bindings = second.admitted_bindings.clone();
    assert!(crossed.validate().is_err());
    assert!(rebuild_cue_snapshot(&crossed, None).is_err());
    // A transplanted digest fails validation: counts plus a copied digest
    // prove nothing without byte equality.
    let mut copied_digest = first.clone();
    copied_digest.build_digest = second.build_digest.clone();
    assert!(copied_digest.validate().is_err());
    assert!(rebuild_cue_snapshot(&copied_digest, None).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 624/37
#[test]
fn publication_manifest_names_owner_without_switching_state() -> TestResult {
    let candidate = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    // The inert publication manifest names the exact external owner
    // (scope), the snapshot identity, and the sealed digest — and nothing
    // else can publish or switch a current generation from this surface.
    assert_eq!(candidate.scope_id, scope_id("scope-1"));
    assert_eq!(candidate.snapshot.snapshot_id.as_str(), "snapshot-1");
    assert_eq!(candidate.build_digest.as_str().len(), 64);
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    // The causal fence is preserved, never advanced: building is not a
    // transition and performs no current-generation compare-and-swap.
    assert_eq!(candidate.snapshot.state_fence, fence());
    // Rebuilding is pure: the original value is byte-identical afterwards.
    let before = candidate.clone();
    let rebuilt = rebuild_cue_snapshot(&candidate, None)?;
    assert_eq!(candidate, before);
    assert_eq!(rebuilt.build_digest, before.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 624/38
#[test]
fn failed_build_cannot_mutate_previous_snapshot() -> TestResult {
    let prior = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    prior.validate()?;
    let bytes_before = prior.canonical_payload_bytes()?;
    // A failed build returns `Err` with no candidate to install anywhere.
    let mut rejected = projection(2, "src/b.rs");
    rejected.candidate.disposition = BindingDisposition::Rejected;
    assert!(open_candidate(std::slice::from_ref(&rejected), &[], None).is_err());
    // The previous candidate is untouched: it still validates, still
    // rebuilds, and its bytes are unchanged.
    prior.validate()?;
    assert_eq!(prior.canonical_payload_bytes()?, bytes_before);
    let rebuilt = rebuild_cue_snapshot(&prior, None)?;
    assert_eq!(rebuilt.build_digest, prior.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 624/39
#[test]
fn wire_rejects_malformed_values_and_protects_shape() -> TestResult {
    // Identity constructors ARE the wire boundary: every newtype's serde
    // `Deserialize` impl routes through `new`, so constructor rejection is
    // wire rejection for unknown/malformed field values.
    for bad in ["", "   ", "has\ncontrol", "has\ttab"] {
        assert!(SnapshotId::new(bad).is_err(), "snapshot id {bad:?}");
        assert!(TargetHandle::new(bad).is_err(), "target {bad:?}");
        assert!(
            BindingCandidateId::new(bad).is_err(),
            "candidate id {bad:?}"
        );
        assert!(RelationEdgeId::new(bad).is_err(), "edge id {bad:?}");
    }
    assert!(SnapshotId::new("x".repeat(513)).is_err());
    for bad in [
        String::new(),
        "short".into(),
        "z".repeat(64),
        "ABCDEF0123456789".repeat(4),
    ] {
        assert!(Digest::new(bad.clone()).is_err(), "digest {bad:?}");
    }
    // Required revisions have no blanket default: revision zero is rejected.
    assert!(named_profile("index-profile", 0, 1).validate().is_err());
    // The canonical envelope carries exactly the declared fields: the
    // tamper-evident digest is computed over the payload, never stored in
    // it, and the ceiling is pinned to the inert candidate spelling.
    let candidate = open_candidate(&[projection(1, "src/a.rs")], &[], None)?;
    let bytes = candidate.canonical_payload_bytes()?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(text.starts_with("{\"admitted_bindings\":"));
    assert!(text.ends_with('}'));
    assert!(text.contains("\"proof_ceiling\":\"CANDIDATE_ARTIFACT\""));
    assert!(!text.contains("build_digest"));
    Ok(())
}

// WORK_UNIT_CASE: 624/40
#[test]
fn bounded_malformed_input_cannot_panic_or_allocate_unboundedly() -> TestResult {
    // A property sweep over malformed identities, digests, and texts: every
    // input fails closed with a bounded error, none panics.
    let malformed_texts = [
        String::new(),
        "   ".into(),
        "line\nbreak".into(),
        "tab\there".into(),
        "x".repeat(513),
        "y".repeat(64 * 1024),
    ];
    for bad in &malformed_texts {
        assert!(SnapshotId::new(bad.clone()).is_err(), "snapshot {bad:?}");
        assert!(
            TargetHandle::new(bad.clone()).is_err(),
            "target len {}",
            bad.len()
        );
        assert!(
            Digest::new(bad.clone()).is_err(),
            "digest len {}",
            bad.len()
        );
    }
    // Oversized profile text is measured before any owner work: the 512 KiB
    // input budget is enforced by accounting, not by allocation.
    let members = vec![projection(1, "src/a.rs")];
    assert!(matches!(
        build_cue_snapshot(
            &scope_id("scope-1"),
            SnapshotId::new("snapshot-1")?,
            named_profile(&"p".repeat(600 * 1024), 1, 1),
            fence(),
            &members,
            &[],
            None,
        ),
        Err(CueContractError::BoundExceeded { .. })
    ));
    // Count bounds fail before per-record work on both dimensions.
    assert!(open_candidate(&vec![projection(1, "src/a.rs"); 129], &[], None).is_err());
    assert!(
        open_candidate(
            &[],
            &vec![named_edge("edge-1", "src/a.rs", "src/b.rs", RelationKind::Supports); 129],
            Some("registry-1"),
        )
        .is_err()
    );
    Ok(())
}

// WORK_UNIT_CASE: 624/41
#[test]
fn api_guard_excludes_query_normalization_admission_mining_and_store() -> TestResult {
    /// Exact type of the open-build entry point, pinned at compile time.
    type OpenBuild = fn(
        &WorkScopeId,
        SnapshotId,
        NormalizationProfile,
        StateFence,
        &[AdmittedCueBindingProjection],
        &[RelationEdge],
        Option<&str>,
    ) -> Result<CueSnapshotBuildCandidate, CueContractError>;
    // The public surface is exactly four pure functions over supplied
    // projections: no Store handle, no query, no clock, no normalization or
    // admission entry point. The function-pointer types below pin that
    // exclusion at compile time.
    let open: OpenBuild = build_cue_snapshot;
    let rebuild: fn(
        &CueSnapshotBuildCandidate,
        Option<&str>,
    ) -> Result<CueSnapshotBuildCandidate, CueContractError> = rebuild_cue_snapshot;
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let first = open(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &inputs,
        &[],
        None,
    )?;
    // No normalization is performed: the retained normalized sections equal
    // the supplied ones byte for byte.
    for (index, retained) in first.admitted_bindings.iter().enumerate() {
        assert_eq!(retained.normalized, inputs[index].normalized);
    }
    // No admission is performed: the retained admission references equal the
    // supplied ones, and dispositions are never promoted or decided here.
    for (index, retained) in first.admitted_bindings.iter().enumerate() {
        assert_eq!(retained.admission, inputs[index].admission);
        assert_eq!(retained.candidate, inputs[index].candidate);
    }
    // No clock or ambient query: repeated builds are byte-identical, and a
    // rebuild through the pinned entry point reproduces the candidate.
    let second = open(
        &scope_id("scope-1"),
        SnapshotId::new("snapshot-1")?,
        profile(),
        fence(),
        &inputs,
        &[],
        None,
    )?;
    assert_eq!(
        first.canonical_payload_bytes()?,
        second.canonical_payload_bytes()?
    );
    assert_eq!(rebuild(&first, None)?.build_digest, first.build_digest);
    // No mining, publication, or delivery: zero supplied edges means zero
    // retained edges, the ceiling stays inert, and the fence is unchanged.
    assert!(first.relation_edges.is_empty());
    assert_eq!(first.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(first.snapshot.state_fence, fence());
    Ok(())
}

// WORK_UNIT_CASE: 624/42
#[test]
fn every_row_has_compatible_receipt_and_frozen_denominator() -> TestResult {
    let inputs = vec![projection(1, "src/a.rs"), projection(2, "src/b.rs")];
    let edges = vec![named_edge(
        "edge-1",
        "src/a.rs",
        "src/b.rs",
        RelationKind::Supports,
    )];
    let candidate = open_candidate(&inputs, &edges, Some("registry-1"))?;
    candidate.validate()?;
    // Every active row traces to exactly one compatible admitted receipt:
    // the receipt joins the candidate id and digest and agrees on scope and
    // fence with the build.
    for member in &candidate.snapshot.members {
        let hits: Vec<_> = inputs
            .iter()
            .filter(|projection| {
                projection.candidate.canonical == member.canonical
                    && projection.candidate.target == member.target
            })
            .collect();
        assert_eq!(hits.len(), 1, "row {member:?} must trace to one receipt");
        let hit = hits[0];
        hit.admission
            .validate_against(&hit.candidate, &hit.normalized)?;
        assert_eq!(
            hit.admission.candidate_id,
            hit.candidate.binding_candidate_id
        );
        assert_eq!(hit.admission.candidate_digest, hit.candidate.digest);
        assert_eq!(hit.admission.scope_id, scope_id("scope-1"));
        assert_eq!(hit.admission.state_fence, fence());
    }
    // The snapshot comes solely from the frozen supplied denominator: the
    // exact supplied source set, no more and no fewer.
    let mut expected: Vec<_> = inputs
        .iter()
        .map(|projection| projection.normalized.observed.source.clone())
        .collect();
    expected.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.digest.cmp(&right.digest))
    });
    expected.dedup();
    let mut actual = candidate.snapshot.rebuild.source_denominator.clone();
    actual.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.digest.cmp(&right.digest))
    });
    assert_eq!(actual, expected);
    assert_eq!(
        candidate.snapshot.rebuild.digest,
        candidate.snapshot.canonical_digest()?
    );
    Ok(())
}
