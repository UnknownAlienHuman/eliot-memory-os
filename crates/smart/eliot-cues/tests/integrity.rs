use std::collections::BTreeSet;
use std::error::Error;

use eliot_contracts::{ArtifactId, AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_cues::{
    CueError, CueKey, CueKind, CueRecord, CueSnapshot, CueStrength, Freshness,
    InvalidationCause,
};
use eliot_evidence::LifecycleState;

type TestResult = Result<(), Box<dyn Error>>;

fn record(target: &str, source_revision: u64) -> Result<CueRecord, Box<dyn Error>> {
    let key = CueKey::new("scope:test", CueKind::FilePath, "src/lib.rs")?;
    Ok(CueRecord::new(
        key,
        ArtifactId::new(target)?,
        "memory_record".to_owned(),
        CueStrength::Primary,
        Freshness::Unbounded,
        source_revision,
    )?)
}

fn snapshot(revision: u64) -> Result<CueSnapshot, Box<dyn Error>> {
    Ok(CueSnapshot {
        revision,
        fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        records: vec![record("artifact:cue-target", revision)?],
        edges: Vec::new(),
    })
}

#[test]
fn normalized_empty_path_is_rejected() {
    for value in ["./", "///./", ".\\.\\"] {
        assert_eq!(
            CueKey::new("scope:test", CueKind::DirPath, value),
            Err(CueError::InvalidValue)
        );
    }
}

#[test]
fn deletion_and_supersession_extinguish_non_terminal_rows() -> TestResult {
    let mut deleted = record("artifact:deleted", 1)?;
    deleted.invalidate(InvalidationCause::Deleted)?;
    assert_eq!(deleted.lifecycle, LifecycleState::Extinguished);

    let mut superseded = record("artifact:superseded", 1)?;
    superseded.transition(LifecycleState::Quarantined)?;
    superseded.invalidate(InvalidationCause::Superseded)?;
    assert_eq!(superseded.lifecycle, LifecycleState::Extinguished);
    Ok(())
}

#[test]
fn extinguished_state_is_terminal() -> TestResult {
    let mut row = record("artifact:terminal", 1)?;
    row.invalidate(InvalidationCause::Deleted)?;

    assert_eq!(
        row.transition(LifecycleState::Active),
        Err(CueError::InvalidLifecycle {
            from: LifecycleState::Extinguished,
            to: LifecycleState::Active,
        })
    );
    assert_eq!(row.lifecycle, LifecycleState::Extinguished);
    Ok(())
}

#[test]
fn archived_to_suppressed_remains_forbidden() -> TestResult {
    let mut row = record("artifact:archived", 1)?;
    row.transition(LifecycleState::Archived)?;

    assert_eq!(
        row.transition(LifecycleState::Suppressed),
        Err(CueError::InvalidLifecycle {
            from: LifecycleState::Archived,
            to: LifecycleState::Suppressed,
        })
    );
    assert_eq!(row.lifecycle, LifecycleState::Archived);
    Ok(())
}

#[test]
fn snapshot_invalidation_requires_a_strictly_newer_revision() -> TestResult {
    let current = snapshot(3)?;
    let target = current.records[0].target.clone();
    let targets = BTreeSet::from([target]);

    let next = current.invalidate(&targets, InvalidationCause::Deleted, 4)?;
    assert_eq!(next.revision, 4);
    assert_eq!(next.records[0].lifecycle, LifecycleState::Extinguished);

    assert_eq!(
        current.invalidate(&targets, InvalidationCause::Deleted, 3),
        Err(CueError::StaleSnapshot)
    );
    assert_eq!(
        current.invalidate(&targets, InvalidationCause::Deleted, 2),
        Err(CueError::StaleSnapshot)
    );
    Ok(())
}
