use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_cue_contracts::{CueProjectionDenominator, ProofCeiling, cue_row_id};
use eliot_cues::{
    ActivationEdge, CueError, CueKey, CueKind, CueRecord, CueSnapshot, CueStrength, Freshness,
    InvalidationCause, MatchMode, ObservedCue,
};
use eliot_evidence::LifecycleState;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn record(target: &str) -> Result<CueRecord, Box<dyn std::error::Error>> {
    let key = CueKey::new("test", CueKind::Concept, "usable cue")?;
    Ok(CueRecord::new(
        key,
        ArtifactId::new(target)?,
        "test-target".to_owned(),
        CueStrength::Primary,
        Freshness::Unbounded,
        1,
    )?)
}

fn snapshot(record: CueRecord) -> CueSnapshot {
    CueSnapshot {
        revision: 1,
        fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
        records: vec![record],
        edges: Vec::new(),
    }
}

#[test]
fn normalized_empty_path_cues_are_rejected() -> TestResult {
    for value in ["./", "///./", r"\.\."] {
        assert!(matches!(
            CueKey::new("test", CueKind::FilePath, value),
            Err(CueError::InvalidValue)
        ));
    }

    let key = CueKey::new(" test ", CueKind::FilePath, r"Src\Lib.rs")?;
    assert_eq!(key.scope, "test");
    assert_eq!(key.value, "src/lib.rs");
    Ok(())
}

#[test]
fn deletion_extinguishes_an_active_row() -> TestResult {
    let mut row = record("artifact:active")?;
    row.invalidate(InvalidationCause::Deleted)?;
    assert_eq!(row.lifecycle, LifecycleState::Extinguished);
    Ok(())
}

#[test]
fn supersession_extinguishes_a_quarantined_row() -> TestResult {
    let mut row = record("artifact:quarantined")?;
    row.transition(LifecycleState::Quarantined)?;
    row.invalidate(InvalidationCause::Superseded)?;
    assert_eq!(row.lifecycle, LifecycleState::Extinguished);
    Ok(())
}

#[test]
fn extinguished_rows_are_terminal() -> TestResult {
    let mut row = record("artifact:terminal")?;
    row.invalidate(InvalidationCause::Deleted)?;
    let result = row.transition(LifecycleState::Active);
    assert!(matches!(
        result,
        Err(CueError::InvalidLifecycle {
            from: LifecycleState::Extinguished,
            to: LifecycleState::Active,
        })
    ));
    Ok(())
}

#[test]
fn archived_rows_cannot_be_suppressed() -> TestResult {
    let mut row = record("artifact:archived")?;
    row.transition(LifecycleState::Archived)?;
    let result = row.transition(LifecycleState::Suppressed);
    assert!(matches!(
        result,
        Err(CueError::InvalidLifecycle {
            from: LifecycleState::Archived,
            to: LifecycleState::Suppressed,
        })
    ));
    Ok(())
}

#[test]
fn facade_normalization_seam_keeps_single_path_shape() -> TestResult {
    let key = CueKey::new("scope", CueKind::FilePath, r"Src\.\Lib/RS.rs")?;
    assert_eq!(key.value, "src/lib/rs.rs");
    assert_eq!(key.mode, MatchMode::Exact);
    Ok(())
}

#[test]
fn observed_cues_normalize_through_the_single_facade_seam() -> TestResult {
    let observed = ObservedCue {
        scope: " scope ".to_owned(),
        kind: CueKind::Symbol,
        value: "Foo::::Bar".to_owned(),
    };
    let key = observed.normalize()?;
    assert_eq!(key.scope, "scope");
    assert_eq!(key.value, "foo::bar");
    let dir = ObservedCue {
        scope: "scope".to_owned(),
        kind: CueKind::DirPath,
        value: r"SRC\Sub".to_owned(),
    };
    let dir_key = dir.normalize()?;
    assert_eq!(dir_key.value, "src/sub");
    assert_eq!(dir_key.mode, MatchMode::Prefix);
    Ok(())
}

#[test]
fn snapshot_invalidation_requires_and_uses_a_new_revision() -> TestResult {
    let target = ArtifactId::new("artifact:next")?;
    let mut targets = BTreeSet::new();
    targets.insert(target);
    let current = snapshot(record("artifact:next")?);

    let next = current.invalidate(&targets, InvalidationCause::Deleted, current.revision + 1)?;
    assert_eq!(next.revision, 2);
    assert_eq!(next.records[0].lifecycle, LifecycleState::Extinguished);

    for revision in [current.revision, 0] {
        assert!(matches!(
            current.invalidate(&targets, InvalidationCause::Deleted, revision),
            Err(CueError::StaleSnapshot)
        ));
    }
    Ok(())
}

fn denominator(
    rows: usize,
    edges: usize,
    omitted_rows: usize,
    omitted_edges: usize,
) -> CueProjectionDenominator {
    CueProjectionDenominator::new(rows, edges, omitted_rows, omitted_edges, 1)
}

fn closed_snapshot(records: Vec<CueRecord>, edges: Vec<ActivationEdge>) -> CueSnapshot {
    CueSnapshot {
        revision: 1,
        fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
        records,
        edges,
    }
}

fn dupe_record(key: &CueKey) -> Result<CueRecord, Box<dyn std::error::Error>> {
    Ok(CueRecord::new(
        key.clone(),
        ArtifactId::new("artifact:dupe")?,
        "test-target".to_owned(),
        CueStrength::Primary,
        Freshness::Unbounded,
        1,
    )?)
}

fn linked_edge(to: &str, weight_milli: u16) -> Result<ActivationEdge, Box<dyn std::error::Error>> {
    Ok(ActivationEdge {
        from: ArtifactId::new("artifact:active")?,
        to: ArtifactId::new(to)?,
        weight_milli,
    })
}

#[test]
fn explicit_case_policy_splits_path_keys_without_touching_v1() -> TestResult {
    let legacy = CueKey::new("test", CueKind::FilePath, "Src/Lib.rs")?;
    assert_eq!(legacy.value, "src/lib.rs");

    let sensitive = CueKey::with_case_policy("test", CueKind::FilePath, "Src/Lib.rs", true)?;
    assert_eq!(sensitive.value, "Src/Lib.rs");
    assert_eq!(sensitive.mode, MatchMode::Exact);
    let folded = CueKey::with_case_policy("test", CueKind::FilePath, "Src/Lib.rs", false)?;
    assert_eq!(folded, legacy);

    let sensitive_key = sensitive.comparison_key();
    let folded_key = folded.comparison_key();
    assert_eq!(sensitive_key.normalized_value, "Src/Lib.rs");
    assert_eq!(folded_key.normalized_value, "src/lib.rs");

    let observed = ObservedCue {
        scope: "test".to_owned(),
        kind: CueKind::FilePath,
        value: "Src/Lib.rs".to_owned(),
    };
    let source = observed.source_value("src/lib.rs:rev-1", "policy-sensitive:1")?;
    assert_eq!(source.canonical_spelling, "Src/Lib.rs");
    Ok(())
}

#[test]
fn v1_replay_preserves_identity_and_reports_ceiling() -> TestResult {
    let record = record("artifact:active")?;
    let snapshot = closed_snapshot(vec![record.clone()], Vec::new());
    let before = snapshot.clone();

    let report = snapshot.migrate_v1_snapshot();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].legacy_row_id, record.row_id);
    assert!(report.rows[0].disposition.is_replay());
    assert_eq!(report.ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(snapshot, before, "migration borrows; v1 bytes never change");

    // The facade v2 view equals the frozen owner-neutral function exactly.
    let target = eliot_cue_contracts::TargetHandle::new("artifact:active")?;
    let expected = cue_row_id(
        "test",
        eliot_cue_contracts::CueKind::Concept,
        eliot_cue_contracts::MatchMode::Exact,
        "usable cue",
        &target,
    )?;
    assert_eq!(record.row_id_v2()?, expected);
    assert!(record.row_id.starts_with("cue:"));
    assert!(expected.starts_with("cuev2:"));
    Ok(())
}

#[test]
fn closed_validation_catches_duplicates_bad_endpoint_weight_and_denominator() -> TestResult {
    let key = CueKey::new("test", CueKind::Concept, "usable cue")?;
    // Identical inputs share one v2 row identity: the facade cannot express a
    // semantic-only duplicate (spelling is already lost in v1 bytes), so the
    // row-identity gate fires first. The semantic gate is proven isolated at
    // the contract boundary where spellings still exist.
    assert!(matches!(
        closed_snapshot(vec![dupe_record(&key)?, dupe_record(&key)?], Vec::new())
            .validate_closed(&denominator(2, 0, 0, 0)),
        Err(CueError::DuplicateRowId)
    ));

    assert!(matches!(
        closed_snapshot(
            vec![record("artifact:active")?],
            vec![linked_edge("artifact:ghost", 500)?]
        )
        .validate_closed(&denominator(1, 1, 0, 0)),
        Err(CueError::UnknownEndpoint)
    ));
    assert!(matches!(
        closed_snapshot(
            vec![record("artifact:active")?],
            vec![linked_edge("artifact:active", 1001)?]
        )
        .validate_closed(&denominator(1, 1, 0, 0)),
        Err(CueError::InvalidWeight)
    ));
    assert!(matches!(
        closed_snapshot(vec![record("artifact:active")?], Vec::new())
            .validate_closed(&denominator(2, 0, 0, 0)),
        Err(CueError::DenominatorMismatch)
    ));

    closed_snapshot(vec![record("artifact:active")?], Vec::new())
        .validate_closed(&denominator(1, 0, 0, 0))?;
    let empty = closed_snapshot(Vec::new(), Vec::new());
    empty.validate_closed(&denominator(0, 0, 0, 0))?;
    assert!(denominator(0, 0, 0, 0).is_empty_complete());
    // An explicitly partial denominator reconciles but never classifies as
    // empty-complete.
    empty.validate_closed(&denominator(1, 0, 1, 0))?;
    assert!(!denominator(1, 0, 1, 0).is_empty_complete());
    Ok(())
}
