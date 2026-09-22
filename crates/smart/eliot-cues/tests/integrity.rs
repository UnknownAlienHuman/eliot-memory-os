//! Facade integrity: replay preservation and owner-path checks.
//!
//! Duplicate-behavior pins from the retired duplicate implementation were
//! removed with it; their behavior lives with the owner cells and is
//! proven by the owner suites plus `tests/legacy_facade.rs` (30-case
//! matrix, issue #833). What remains here: inert v1 replay preservation
//! byte-identity, the owner path without facade fallback, and reexport
//! identity. Dropped duplicate pins and their owner coverage:
//! - row/transition/invalidation lifecycle rules → `eliot-cue-index`
//!   lifecycle rules and snapshot validation;
//! - snapshot `validate`/`validate_closed`/`invalidate` → owner
//!   `CueSnapshot::validate` / `validate_closed` (A-13);
//! - local normalization folding/case-policy → A-11 `normalize_cue`
//!   under explicit policy (matrix cases 9-11);
//! - local firing traversal/scoring → A-14a `evaluate_activation`
//!   (matrix case 14).

#![allow(clippy::expect_used)]

use eliot_cue_contracts::{ProofCeiling, cue_row_id};
use eliot_cues::{preserve_v1_row, preserve_v1_snapshot};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn v1_replay_preserves_identity_and_reports_ceiling() -> TestResult {
    let first = preserve_v1_row("cue:0123456789abcdef0123456789abcdef")?;
    assert!(first.disposition.is_replay());
    assert_eq!(first.legacy_row_id, "cue:0123456789abcdef0123456789abcdef");
    let report = preserve_v1_snapshot(&[
        "cue:0123456789abcdef0123456789abcdef".to_owned(),
        "cue:fedcba9876543210fedcba9876543210".to_owned(),
    ])?;
    assert_eq!(report.rows.len(), 2);
    assert_eq!(
        report.rows[0].legacy_row_id,
        "cue:0123456789abcdef0123456789abcdef"
    );
    assert!(report.rows[0].disposition.is_replay());
    assert_eq!(report.ceiling, ProofCeiling::CandidateArtifact);
    assert!(preserve_v1_row("").is_err());
    assert!(preserve_v1_snapshot(&[String::new()]).is_err());
    Ok(())
}

#[test]
fn facade_row_id_matches_frozen_owner_function() -> TestResult {
    let target = eliot_cue_contracts::TargetHandle::new("artifact:active")?;
    let expected = cue_row_id(
        "test",
        eliot_cue_contracts::CueKind::Concept,
        eliot_cue_contracts::MatchMode::Exact,
        "usable cue",
        &target,
    )?;
    let adapted = eliot_cues::legacy_adapter::legacy_row_id_v2(
        "test",
        "concept",
        "exact",
        "usable cue",
        &target,
    )?;
    assert_eq!(adapted, expected);
    assert!(expected.starts_with("cuev2:"));
    Ok(())
}

#[test]
fn ledger_1143_owner_path_validates_without_facade_fallback() -> TestResult {
    assert!(eliot_cue_contracts::is_supported_schema_revision("2.0.0"));
    assert!(!eliot_cue_contracts::is_supported_schema_revision("1.0.0"));
    let target = eliot_cue_contracts::TargetHandle::new("artifact:ledger-1143")?;
    let key = eliot_cue_contracts::CueComparisonKey::new(
        "ledger1143".to_owned(),
        eliot_cue_contracts::CueKind::Concept,
        eliot_cue_contracts::MatchMode::Exact,
        "usable cue".to_owned(),
    );
    key.validate()?;
    let first = cue_row_id(
        "ledger1143",
        eliot_cue_contracts::CueKind::Concept,
        eliot_cue_contracts::MatchMode::Exact,
        "usable cue",
        &target,
    )?;
    let again = cue_row_id(
        "ledger1143",
        eliot_cue_contracts::CueKind::Concept,
        eliot_cue_contracts::MatchMode::Exact,
        "usable cue",
        &target,
    )?;
    assert_eq!(first, again);
    assert!(first.starts_with("cuev2:"));
    let rescoped = cue_row_id(
        "other-scope",
        eliot_cue_contracts::CueKind::Concept,
        eliot_cue_contracts::MatchMode::Exact,
        "usable cue",
        &target,
    )?;
    assert_ne!(first, rescoped);
    let source = eliot_cue_contracts::CueSourceValue::new(
        "Src/Lib.rs".to_owned(),
        "src/lib.rs:rev-1".to_owned(),
        "policy-sensitive:1".to_owned(),
    );
    source.validate()?;
    assert_eq!(source.canonical_spelling, "Src/Lib.rs");
    Ok(())
}
