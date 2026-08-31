use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_cues::{
    CueError, CueKey, CueKind, CueRecord, CueSnapshot, CueStrength, Freshness, InvalidationCause,
};
use eliot_evidence::LifecycleState;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
        fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
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
