//! Cell-declared package proof entrypoint for the epistemic resolver
//! (`smart.epistemic.position`, implementation `src/resolver.rs`).
//!
//! Every assertion below is the assertion already held by the inline
//! `#[cfg(test)] mod tests` in `src/lib.rs`, re-proved through the crate's
//! public surface only (`eliot_epistemic::resolve` plus the re-exported
//! position algebra), so this entrypoint is independently invocable without
//! compiling the cell's implementation module as a test target.
//!
//! `src/lib.rs` is outside this work unit's write scope, so the inline module
//! is deliberately left in place and this entrypoint is an *additional*
//! proof of the same public behaviour rather than a replacement. The
//! duplicated coverage is the honest state until the inline module is removed
//! by the file's own owner; nothing here weakens, widens or reinterprets an
//! assertion.
//!
//! The resolver never manufactures truth and never mutates a source record.
//! These proofs pin that: only exact current verified evidence supports a
//! position, everything refused is refused with its offending handle, and
//! every admitted record stays addressable in provenance whatever its state.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
};
use eliot_epistemic::{EpistemicError, EpistemicRecord, PositionRequest, PositionState, resolve};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance, VerificationBinding,
};

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

fn envelope(
    status: EpistemicStatus,
    freshness: EvidenceFreshness,
    source: &str,
    revision: &str,
) -> EvidenceEnvelope {
    let assertability = match status {
        EpistemicStatus::Supported | EpistemicStatus::Verified => Assertability::Assertable,
        _ => Assertability::NonAssertableUnverified,
    };
    let verification = (status == EpistemicStatus::Verified).then(|| VerificationBinding {
        contract_id: ContractId::new(format!("contract:{source}"))
            .expect("valid fixture contract id"),
        run_id: id(&format!("run:{source}:{revision}")),
        revision: revision.to_owned(),
    });
    EvidenceEnvelope {
        authority: EvidenceAuthority::DeterministicRuntimeTest,
        freshness,
        coverage: EvidenceCoverage::CompleteForScope,
        status,
        assertability,
        provenance: Provenance {
            source_id: SourceId::new(source).expect("valid fixture source id"),
            capture_route: "fixture.epistemic".to_owned(),
            scope: "scope".to_owned(),
            raw_handle: Some(format!("raw:{source}:{revision}")),
            revision: Some(revision.to_owned()),
        },
        verification,
        state_fence: fence(),
    }
}

fn record(
    handle: &str,
    status: EpistemicStatus,
    freshness: EvidenceFreshness,
    supersedes: Vec<ArtifactId>,
) -> EpistemicRecord {
    EpistemicRecord {
        handle: id(handle),
        subject: format!("subject:{handle}"),
        scope: "scope".to_owned(),
        evidence: envelope(status, freshness, &format!("source:{handle}"), handle),
        supersedes,
        note: None,
    }
}

fn request(records: Vec<EpistemicRecord>) -> PositionRequest {
    PositionRequest {
        question: "question".to_owned(),
        scope: "scope".to_owned(),
        state_fence: fence(),
        records,
    }
}

#[test]
fn only_exact_current_verified_evidence_supports_position() {
    let current = record(
        "current",
        EpistemicStatus::Verified,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    let older = record(
        "older",
        EpistemicStatus::Verified,
        EvidenceFreshness::KnownOlderSnapshot,
        Vec::new(),
    );
    let unknown = record(
        "unknown",
        EpistemicStatus::Verified,
        EvidenceFreshness::Unknown,
        Vec::new(),
    );
    let result = resolve(&request(vec![current, older, unknown])).expect("valid request");

    assert_eq!(result.state, PositionState::Supported);
    assert_eq!(result.supporting_records, vec![id("current")]);
    assert_eq!(result.direct_observations, Vec::<ArtifactId>::new());
    assert_eq!(result.rival_records, Vec::<ArtifactId>::new());
    assert_eq!(result.stale_records, vec![id("older"), id("unknown")]);
    assert_eq!(
        result.provenance.record_handles,
        vec![id("current"), id("older"), id("unknown")]
    );
    assert_eq!(
        result.provenance.revisions,
        vec!["current", "older", "unknown"]
    );
    assert_eq!(
        result.provenance.raw_handles,
        vec![
            "raw:source:current:current",
            "raw:source:older:older",
            "raw:source:unknown:unknown"
        ]
    );
}

#[test]
fn missing_predecessor_is_rejected_against_admitted_request_set() {
    let successor = record(
        "successor",
        EpistemicStatus::Verified,
        EvidenceFreshness::ExactCommit,
        vec![id("missing")],
    );

    assert!(matches!(
        resolve(&request(vec![successor])),
        Err(EpistemicError::MissingPredecessor { handle, predecessor })
            if handle == id("successor") && predecessor == id("missing")
    ));
}

#[test]
fn self_and_duplicate_predecessors_are_rejected() {
    let self_reference = record(
        "self",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        vec![id("self")],
    );
    assert!(matches!(
        resolve(&request(vec![self_reference])),
        Err(EpistemicError::SelfSupersession { handle }) if handle == id("self")
    ));

    let duplicate = record(
        "successor",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        vec![id("predecessor"), id("predecessor")],
    );
    let predecessor = record(
        "predecessor",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCandidate,
        Vec::new(),
    );
    assert!(matches!(
        resolve(&request(vec![duplicate, predecessor])),
        Err(EpistemicError::DuplicatePredecessor { handle, predecessor })
            if handle == id("successor") && predecessor == id("predecessor")
    ));
}

#[test]
fn stale_and_unknown_freshness_remain_addressable_without_current_promotion() {
    let older = record(
        "older",
        EpistemicStatus::Verified,
        EvidenceFreshness::KnownOlderSnapshot,
        Vec::new(),
    );
    let unknown = record(
        "unknown",
        EpistemicStatus::Unknown,
        EvidenceFreshness::Unknown,
        Vec::new(),
    );
    let result = resolve(&request(vec![older, unknown])).expect("valid request");

    assert_eq!(result.state, PositionState::Stale);
    assert!(result.direct_observations.is_empty());
    assert!(result.supporting_records.is_empty());
    assert!(result.rival_records.is_empty());
    assert_eq!(result.stale_records, vec![id("older"), id("unknown")]);
    assert!(result.unknowns.contains(&"subject:unknown".to_owned()));
    assert!(result.provenance.record_handles.contains(&id("older")));
    assert!(result.provenance.record_handles.contains(&id("unknown")));
}

#[test]
fn superseded_lineage_and_provenance_are_permutation_invariant() {
    let predecessor_a = record(
        "predecessor-a",
        EpistemicStatus::Verified,
        EvidenceFreshness::ExactCommit,
        Vec::new(),
    );
    let predecessor_z = record(
        "predecessor-z",
        EpistemicStatus::Verified,
        EvidenceFreshness::ExactCommit,
        Vec::new(),
    );
    let successor = record(
        "successor",
        EpistemicStatus::Verified,
        EvidenceFreshness::ExactCandidate,
        vec![id("predecessor-z"), id("predecessor-a")],
    );
    let original_verification = successor.evidence.verification.clone();

    let first = resolve(&request(vec![
        successor.clone(),
        predecessor_z.clone(),
        predecessor_a.clone(),
    ]))
    .expect("valid request");

    let mut reordered_successor = successor.clone();
    reordered_successor.supersedes.reverse();
    let second = resolve(&request(vec![
        predecessor_a,
        reordered_successor,
        predecessor_z,
    ]))
    .expect("valid request");

    assert_eq!(first, second);
    assert_eq!(first.supporting_records, vec![id("successor")]);
    assert_eq!(
        first.superseded_records,
        vec![id("predecessor-a"), id("predecessor-z")]
    );
    assert_eq!(
        first.provenance.record_handles,
        vec![id("predecessor-a"), id("predecessor-z"), id("successor")]
    );
    assert_eq!(successor.evidence.verification, original_verification);
}
