//! Package test entrypoint for the `eliot-epistemic` cell (#238).
//!
//! This crate declares `[dev-dependencies] serde_json` and shipped no
//! `tests/` target, so its cells had no independently invocable test
//! entrypoint and no executable ModuleTestCapsule (I2.20). This file IS that
//! entrypoint: it reaches the cell only through its public surface —
//! [`PositionRequest`], [`EpistemicRecord`] and [`resolve`] — and asserts
//! exactly the outcome the crate's own internal unit test already asserts
//! for the same path. It adds no new behavioural claim, no new fixture
//! semantics and no new assertion about behaviour this cell does not
//! already state.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
};
use eliot_epistemic::{EpistemicRecord, PositionRequest, PositionState, resolve};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance, VerificationBinding,
};

fn test_epoch(sequence: u64) -> EpochId {
    let lineage =
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("canonical test lineage-A");
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
        evidence: envelope(
            status,
            freshness,
            &format!("source:{handle}"),
            handle,
        ),
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
    assert_eq!(result.stale_records, vec![id("older"), id("unknown")]);
}
