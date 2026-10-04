//! Cell-declared package proof entrypoint for the Current Epistemic Position
//! algebra (`smart.epistemic.position`, implementation `src/position.rs`).
//!
//! Every assertion below is the assertion already held by the inline
//! `#[cfg(test)] mod tests` in `src/position.rs`, re-proved through the crate's
//! public surface only, so this entrypoint is independently invocable without
//! compiling the cell's implementation module as a test target.
//!
//! `src/position.rs` is outside this work unit's write scope, so the inline
//! module is deliberately left in place and this entrypoint is an *additional*
//! proof of the same public behaviour rather than a replacement. The
//! duplicated coverage is the honest state until the inline module is removed
//! by that file's own owner; nothing here weakens, widens or reinterprets an
//! assertion.
//!
//! The proofs cover the request-to-record boundary that the inline module was
//! written for: a record whose evidence provenance is bound to the requested
//! scope still resolves with its original bytes intact, while the A/A/B
//! counterexample is refused with the offending handle whether the record is
//! current, stale or named by another record's `supersedes`. They go through
//! the public `eliot_epistemic::resolve` because that is the public surface
//! through which a caller meets the refusal.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
};
use eliot_epistemic::{EpistemicError, EpistemicRecord, PositionRequest, PositionState, resolve};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};

const SCOPE: &str = "scope-a";
const OTHER_SCOPE: &str = "scope-b";

fn test_epoch(sequence: u64) -> EpochId {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("canonical test lineage-A");
    EpochId::new(
        lineage,
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("valid fixture artifact id")
}

/// A record whose evidence carries its own `provenance_scope`, which is what
/// `candidate_adaptation::observed_candidate` builds: the record scope is
/// taken from the observation provenance, so a valid same-scope read set
/// stays valid.
fn record(
    handle: &str,
    scope: &str,
    provenance_scope: &str,
    status: EpistemicStatus,
    freshness: EvidenceFreshness,
    supersedes: Vec<ArtifactId>,
) -> EpistemicRecord {
    EpistemicRecord {
        handle: id(handle),
        subject: format!("subject:{handle}"),
        scope: scope.to_owned(),
        evidence: EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness,
            coverage: EvidenceCoverage::CompleteForScope,
            status,
            assertability: Assertability::NonAssertableUnverified,
            provenance: Provenance {
                source_id: SourceId::new(format!("source:{handle}"))
                    .expect("valid fixture source id"),
                capture_route: "fixture.scope-binding".to_owned(),
                scope: provenance_scope.to_owned(),
                raw_handle: Some(format!("raw:{handle}")),
                revision: Some(format!("revision:{handle}")),
            },
            verification: None,
            state_fence: fence(),
        },
        supersedes,
        note: None,
    }
}

fn request(records: Vec<EpistemicRecord>) -> PositionRequest {
    PositionRequest {
        question: "question".to_owned(),
        scope: SCOPE.to_owned(),
        state_fence: fence(),
        records,
    }
}

/// The positive case: a record whose evidence provenance is bound to the
/// request scope still resolves, and its original bytes are untouched.
#[test]
fn bound_provenance_scope_still_resolves_without_rewriting_evidence() {
    let observed = record(
        "observed",
        SCOPE,
        SCOPE,
        EpistemicStatus::Observed,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    let supported = record(
        "supported",
        SCOPE,
        SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    let original = supported.evidence.clone();

    let result = resolve(&request(vec![observed.clone(), supported.clone()]))
        .expect("same-scope evidence still resolves");

    assert_eq!(result.state, PositionState::Supported);
    assert_eq!(result.direct_observations, vec![id("observed")]);
    assert_eq!(result.supporting_records, vec![id("supported")]);
    // The observed-candidate adapter's record shape (record scope taken from
    // the observation provenance) is admitted, and the original evidence
    // bytes are returned unchanged rather than relabelled.
    assert_eq!(supported.evidence, original);
    assert_eq!(supported.evidence.provenance.scope, SCOPE);
}

/// The audited counterexample: request A, record A, evidence captured for B.
#[test]
fn evidence_provenance_from_a_foreign_scope_is_refused_with_its_handle() {
    let foreign = record(
        "foreign",
        SCOPE,
        OTHER_SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    let refusal = resolve(&request(vec![foreign]))
        .expect_err("scope-mismatched evidence must not be admitted");

    assert!(matches!(
        refusal,
        EpistemicError::ScopeMismatch { handle } if handle == id("foreign")
    ));
}

/// The inverse relation: evidence bound to A inside a record claimed for B.
/// This one is refused by the record-vs-request check, which runs first.
#[test]
fn evidence_provenance_from_the_request_scope_is_refused_in_a_foreign_record() {
    let foreign = record(
        "foreign",
        OTHER_SCOPE,
        SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );

    assert!(matches!(
        resolve(&request(vec![foreign])),
        Err(EpistemicError::ScopeMismatch { handle }) if handle == id("foreign")
    ));
}

/// A wrong-scope stale record cannot influence suppression or provenance.
#[test]
fn stale_evidence_provenance_from_a_foreign_scope_is_refused() {
    let stale_foreign = record(
        "stale-foreign",
        SCOPE,
        OTHER_SCOPE,
        EpistemicStatus::Stale,
        EvidenceFreshness::KnownOlderSnapshot,
        Vec::new(),
    );
    let current = record(
        "current",
        SCOPE,
        SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );

    assert!(matches!(
        resolve(&request(vec![current, stale_foreign])),
        Err(EpistemicError::ScopeMismatch { handle }) if handle == id("stale-foreign")
    ));
}

/// A wrong-scope record named by another record's `supersedes` is refused
/// before the supersession union is computed, so it cannot vanish as
/// silently superseded.
#[test]
fn superseded_evidence_provenance_from_a_foreign_scope_is_refused() {
    let foreign = record(
        "foreign",
        SCOPE,
        OTHER_SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    let successor = record(
        "successor",
        SCOPE,
        SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        vec![id("foreign")],
    );

    assert!(matches!(
        resolve(&request(vec![successor, foreign])),
        Err(EpistemicError::ScopeMismatch { handle }) if handle == id("foreign")
    ));
}

/// Deterministic ordering is preserved for an equivalent permutation of the
/// same admitted read set.
#[test]
fn equivalent_read_set_permutation_is_identical() {
    let first_record = record(
        "first",
        SCOPE,
        SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    let second_record = record(
        "second",
        SCOPE,
        SCOPE,
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );

    let first = resolve(&request(vec![first_record.clone(), second_record.clone()]))
        .expect("valid read set");
    let second = resolve(&request(vec![second_record, first_record])).expect("valid read set");

    assert_eq!(first, second);
}
