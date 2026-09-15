use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_cues::{
    CueError, CueKey, CueKind, CueRecord, CueSnapshot, CueStrength, Freshness, InvalidationCause,
    MatchMode, ObservedCue,
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
