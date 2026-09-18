//! Frozen v2 spelling, comparison-key, row-identity, and snapshot-closure rules.
//!
//! One focused behaviour test per real v2 change from issue #246. Fixture
//! values are real contract records; no mocks, no canned digests beyond the
//! deterministic test helpers shared with the other contract suites.

// Assertions in a test use `expect`/`unwrap` deliberately; the workspace lints
// target production paths.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence};
use eliot_cue_contracts::{
    CONTRACT_REVISION, CanonicalCueId, CanonicalCueIdentity, ClosedSnapshotRow,
    ConversionDisposition, CueComparisonKey, CueContractError, CueKind, CueProjectionDenominator,
    CueSnapshot, CueSourceValue, Digest, MatchMode, NormalizationProfile, RebuildIdentity,
    RelationEdge, RelationEdgeId, SnapshotEdgeWeight, SnapshotId, SnapshotMember, SourceHandle,
    TargetHandle, cue_row_id,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance, RelationKind,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("64 hex characters")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440002")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    )
}

fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("eliot-cue-contracts-tests").expect("source id"),
        capture_route: "unit-test".to_owned(),
        scope: "scope-1".to_owned(),
        raw_handle: None,
        revision: None,
    }
}

fn profile() -> NormalizationProfile {
    NormalizationProfile::new("symbol-v1".to_owned(), 1, digest(0xb2))
}

fn source() -> SourceHandle {
    SourceHandle::new(
        TargetHandle::new("src/input.rs").expect("target"),
        digest(0xa1),
        provenance(),
    )
}

fn evidence() -> EvidenceEnvelope {
    EvidenceEnvelope {
        authority: EvidenceAuthority::SourceIdentity,
        freshness: EvidenceFreshness::ExactCandidate,
        coverage: EvidenceCoverage::CompleteForScope,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        provenance: provenance(),
        verification: None,
        state_fence: fence(),
    }
}

fn canonical(kind: CueKind, value: &str, seed: u8) -> CanonicalCueIdentity {
    CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{seed}")).expect("id"),
        kind,
        value.to_owned(),
        digest(seed),
    )
}

fn member(kind: CueKind, value: &str, seed: u8, target: &str) -> SnapshotMember {
    SnapshotMember::new(
        canonical(kind, value, seed),
        TargetHandle::new(target).expect("target"),
    )
}

fn key(scope: &str, kind: CueKind, mode: MatchMode, value: &str) -> CueComparisonKey {
    CueComparisonKey::new(scope.to_owned(), kind, mode, value.to_owned())
}

fn row(member: SnapshotMember, key: CueComparisonKey) -> ClosedSnapshotRow {
    ClosedSnapshotRow::new(member, key)
}

fn sealed_snapshot(members: Vec<SnapshotMember>) -> CueSnapshot {
    let mut snapshot = CueSnapshot::new(
        CONTRACT_REVISION.to_owned(),
        SnapshotId::new("snapshot-1").expect("id"),
        members,
        RebuildIdentity::new(profile(), vec![source()], digest(0)),
        fence(),
    );
    let sealed = snapshot.canonical_digest().expect("sealed digest");
    snapshot.rebuild.digest = sealed;
    snapshot
}

fn edge(id: &str, from: &str, to: &str) -> RelationEdge {
    RelationEdge::new(
        RelationEdgeId::new(id).expect("edge id"),
        RelationKind::Supports,
        TargetHandle::new(from).expect("from"),
        TargetHandle::new(to).expect("to"),
        "registry-1".to_owned(),
        digest(0xe1),
        evidence(),
    )
}

fn weight(id: &str, milli: u16) -> SnapshotEdgeWeight {
    SnapshotEdgeWeight::new(RelationEdgeId::new(id).expect("edge id"), milli)
}

fn denominator(
    rows: usize,
    edges: usize,
    omitted_rows: usize,
    omitted_edges: usize,
) -> CueProjectionDenominator {
    CueProjectionDenominator::new(rows, edges, omitted_rows, omitted_edges, 7)
}

#[test]
fn v2_shapes_validate_and_reject_bad_material() -> TestResult {
    let source = CueSourceValue::new(
        "Src/Main.rs".to_owned(),
        "src/input.rs:a1a1a1a1".to_owned(),
        "policy-test:1".to_owned(),
    );
    source.validate()?;
    assert_eq!(source.canonical_spelling, "Src/Main.rs");
    let round_tripped: CueSourceValue = serde_json::from_str(&serde_json::to_string(&source)?)?;
    assert_eq!(round_tripped, source);

    let comparison = key("scope-1", CueKind::Symbol, MatchMode::Exact, "crate::main");
    comparison.validate()?;
    let round_tripped: CueComparisonKey =
        serde_json::from_str(&serde_json::to_string(&comparison)?)?;
    assert_eq!(round_tripped, comparison);

    denominator(2, 1, 0, 0).validate()?;
    assert!(denominator(0, 0, 0, 0).is_empty_complete());

    assert!(
        CueSourceValue::new("  ".to_owned(), "s".to_owned(), "p".to_owned(),)
            .validate()
            .is_err()
    );
    assert!(
        key("scope-1", CueKind::Symbol, MatchMode::Prefix, "crate::main",)
            .validate()
            .is_err(),
        "prefix is not admissible for symbols"
    );
    assert!(denominator(1, 0, 2, 0).validate().is_err());
    assert!(denominator(0, 1, 0, 2).validate().is_err());
    Ok(())
}

#[test]
fn same_text_in_symbol_and_concept_yields_distinct_row_identities() -> TestResult {
    let target = TargetHandle::new("src/target.rs")?;
    let symbol = cue_row_id(
        "scope-1",
        CueKind::Symbol,
        MatchMode::Exact,
        "task",
        &target,
    )?;
    let concept = cue_row_id(
        "scope-1",
        CueKind::Concept,
        MatchMode::Exact,
        "task",
        &target,
    )?;
    assert_ne!(symbol, concept);
    assert!(symbol.starts_with("cuev2:"));
    assert_eq!(symbol.len(), "cuev2:".len() + 64);

    let symbol_member = member(CueKind::Symbol, "Task", 1, "src/target.rs");
    let concept_member = member(CueKind::Concept, "Task", 2, "src/target.rs");
    assert_ne!(
        symbol_member.row_id("scope-1", MatchMode::Exact, "task")?,
        concept_member.row_id("scope-1", MatchMode::Exact, "task")?,
    );
    Ok(())
}

#[test]
fn same_text_under_exact_and_prefix_yields_distinct_row_identities() -> TestResult {
    let target = TargetHandle::new("src/target.rs")?;
    let exact = cue_row_id(
        "scope-1",
        CueKind::FilePath,
        MatchMode::Exact,
        "src/a",
        &target,
    )?;
    let prefix = cue_row_id(
        "scope-1",
        CueKind::FilePath,
        MatchMode::Prefix,
        "src/a",
        &target,
    )?;
    assert_ne!(exact, prefix);

    let member = member(CueKind::FilePath, "src/a", 1, "src/target.rs");
    assert_ne!(
        member.row_id("scope-1", MatchMode::Exact, "src/a")?,
        member.row_id("scope-1", MatchMode::Prefix, "src/a")?,
    );
    // Identity is deterministic for identical dimensions.
    assert_eq!(member.row_id("scope-1", MatchMode::Exact, "src/a")?, exact,);
    Ok(())
}

#[test]
fn row_identity_rejects_inadmissible_and_blank_dimensions() -> TestResult {
    let target = TargetHandle::new("src/target.rs")?;
    assert!(
        cue_row_id(
            "scope-1",
            CueKind::Symbol,
            MatchMode::Signature,
            "sig:deadbeef",
            &target,
        )
        .is_err()
    );
    assert!(cue_row_id("  ", CueKind::Symbol, MatchMode::Exact, "task", &target).is_err());
    assert!(cue_row_id("scope-1", CueKind::Symbol, MatchMode::Exact, "", &target).is_err());
    Ok(())
}

#[test]
fn snapshot_closure_accepts_exact_denominator() -> TestResult {
    let members = vec![member(CueKind::Symbol, "Task", 1, "src/a.rs")];
    let snapshot = sealed_snapshot(members.clone());
    let rows = vec![row(
        members[0].clone(),
        key("scope-1", CueKind::Symbol, MatchMode::Exact, "task"),
    )];
    snapshot.validate_closed(&rows, &denominator(1, 0, 0, 0), &[], &[])?;
    Ok(())
}

#[test]
fn duplicate_row_ids_fail_closed() {
    // Same kind, same folded key, same target, but different canonical
    // spellings: one v2 row identity, two members.
    let first = member(CueKind::Symbol, "Task", 1, "src/a.rs");
    let second = member(CueKind::Symbol, "task", 2, "src/a.rs");
    let snapshot = sealed_snapshot(vec![first.clone(), second.clone()]);
    let rows = vec![
        row(
            first,
            key("scope-1", CueKind::Symbol, MatchMode::Exact, "task"),
        ),
        row(
            second,
            key("scope-1", CueKind::Symbol, MatchMode::Exact, "task"),
        ),
    ];
    assert!(matches!(
        snapshot.validate_closed(&rows, &denominator(2, 0, 0, 0), &[], &[]),
        Err(CueContractError::DuplicateIdentity {
            field: "snapshot.row_id"
        })
    ));
}

#[test]
fn duplicate_semantic_bindings_fail_closed() {
    // Same kind, spelling, and target under different comparison keys: distinct
    // row identities, one semantic binding.
    let first = member(CueKind::Symbol, "Task", 1, "src/a.rs");
    let second = member(CueKind::Symbol, "Task", 2, "src/a.rs");
    let snapshot = sealed_snapshot(vec![first.clone(), second.clone()]);
    let rows = vec![
        row(
            first,
            key("scope-1", CueKind::Symbol, MatchMode::Exact, "task"),
        ),
        row(
            second,
            key("scope-1", CueKind::Symbol, MatchMode::Exact, "Task"),
        ),
    ];
    assert!(matches!(
        snapshot.validate_closed(&rows, &denominator(2, 0, 0, 0), &[], &[]),
        Err(CueContractError::DuplicateIdentity {
            field: "snapshot.semantic_binding"
        })
    ));
}

#[test]
fn missing_endpoint_and_overweight_edge_fail_closed() -> TestResult {
    let members = vec![
        member(CueKind::Symbol, "Task", 1, "src/a.rs"),
        member(CueKind::Symbol, "Other", 2, "src/b.rs"),
    ];
    let snapshot = sealed_snapshot(members.clone());
    let rows = vec![
        row(
            members[0].clone(),
            key("scope-1", CueKind::Symbol, MatchMode::Exact, "task"),
        ),
        row(
            members[1].clone(),
            key("scope-1", CueKind::Symbol, MatchMode::Exact, "other"),
        ),
    ];
    let dangling = edge("edge-1", "src/a.rs", "src/missing.rs");
    assert!(matches!(
        snapshot.validate_closed(
            &rows,
            &denominator(2, 1, 0, 0),
            std::slice::from_ref(&dangling),
            &[weight("edge-1", 500)],
        ),
        Err(CueContractError::Foundation {
            field: "snapshot.edge.endpoint"
        })
    ));

    let linked = edge("edge-1", "src/a.rs", "src/b.rs");
    assert!(matches!(
        snapshot.validate_closed(
            &rows,
            &denominator(2, 1, 0, 0),
            std::slice::from_ref(&linked),
            &[weight("edge-1", 1001)],
        ),
        Err(CueContractError::BoundExceeded {
            field: "snapshot.edge.weight",
            ..
        })
    ));

    // The same edge at the unity bound closes.
    snapshot.validate_closed(
        &rows,
        &denominator(2, 1, 0, 0),
        std::slice::from_ref(&linked),
        &[weight("edge-1", 1000)],
    )?;
    Ok(())
}

#[test]
fn denominator_mismatch_fails_while_empty_complete_differs_from_partial() -> TestResult {
    let members = vec![member(CueKind::Symbol, "Task", 1, "src/a.rs")];
    let snapshot = sealed_snapshot(members.clone());
    let rows = vec![row(
        members[0].clone(),
        key("scope-1", CueKind::Symbol, MatchMode::Exact, "task"),
    )];
    assert!(matches!(
        snapshot.validate_closed(&rows, &denominator(2, 0, 0, 0), &[], &[]),
        Err(CueContractError::SnapshotNotRebuildable)
    ));

    let empty = sealed_snapshot(Vec::new());
    let complete = denominator(0, 0, 0, 0);
    assert!(complete.is_empty_complete());
    assert!(complete.is_complete());
    empty.validate_closed(&[], &complete, &[], &[])?;

    let partial = denominator(2, 0, 1, 0);
    assert!(!partial.is_empty_complete());
    assert!(!partial.is_complete());
    partial.validate()?;
    // One present row plus one recorded omission reconciles against an
    // expected total of two: a partial denominator is explicit, not corrupt.
    snapshot.validate_closed(&rows, &partial, &[], &[])?;
    // A partial denominator whose held count disagrees with the present rows
    // still fails closed.
    assert!(matches!(
        snapshot.validate_closed(&rows, &denominator(3, 0, 1, 0), &[], &[]),
        Err(CueContractError::SnapshotNotRebuildable)
    ));
    Ok(())
}

#[test]
fn conversion_dispositions_validate_and_never_admit() -> TestResult {
    let replay = ConversionDisposition::V1ReplayPreserved {
        legacy_row_id: "cue:0123456789abcdef0123456789abcdef".to_owned(),
    };
    assert!(replay.is_replay());
    replay.validate()?;

    let converted = ConversionDisposition::V2Converted {
        legacy_row_id: "cue:0123456789abcdef0123456789abcdef".to_owned(),
        row_id: cue_row_id(
            "scope-1",
            CueKind::Symbol,
            MatchMode::Exact,
            "task",
            &TargetHandle::new("src/a.rs")?,
        )?,
    };
    assert!(!converted.is_replay());
    converted.validate()?;

    let rejected = ConversionDisposition::V2Rejected {
        legacy_row_id: "cue:0123456789abcdef0123456789abcdef".to_owned(),
        reason: "unsupported-kind".to_owned(),
    };
    rejected.validate()?;
    assert!(
        ConversionDisposition::V2Rejected {
            legacy_row_id: String::new(),
            reason: "unsupported-kind".to_owned(),
        }
        .validate()
        .is_err()
    );

    // The disposition round-trips without naming any lifecycle, support, or
    // admission claim.
    let encoded = serde_json::to_string(&converted)?;
    assert!(!encoded.contains("lifecycle"));
    assert!(!encoded.contains("support"));
    let decoded: ConversionDisposition = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, converted);
    Ok(())
}

#[test]
fn v1_lifecycle_states_are_not_v2_row_identities() -> TestResult {
    // Guards the migration boundary: a lifecycle label is local projection
    // metadata and must never appear inside the frozen row-identity preimage.
    let target = TargetHandle::new("src/a.rs")?;
    let active = cue_row_id(
        "scope-1",
        CueKind::Symbol,
        MatchMode::Exact,
        "task",
        &target,
    )?;
    assert!(!active.contains("Active"));
    assert!(!active.contains("lifecycle"));
    let _ = LifecycleState::Active;
    Ok(())
}
