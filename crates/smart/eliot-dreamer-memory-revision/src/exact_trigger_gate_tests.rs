//! The exact/near-match boundary gate for one extinction candidate.
//!
//! `docs/architecture/I12-19-negative-memory.md:3` is the governing sentence:
//! "Exact deterministic trigger can block/requires probe within matching scope.
//! Semantic similarity only warns." The candidate therefore carries the exact
//! trigger identity in its own member
//! ([`crate::NegativeMemoryExtinctionCandidate::trigger`]) beside the composite
//! failure fingerprint, and
//! [`crate::NegativeMemoryExtinctionCandidate::recheck_exact_trigger`] is the
//! only place an exact-trigger requirement is decided. One case satisfies that
//! requirement on the exact identity; one case is a semantic near-match over
//! otherwise valid content and is refused with the existing typed error.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_observation_contracts::{FailureOmission, FailureOmissionClass};

use crate::{
    AdvisoryNarrowing, CANDIDATE_CONTRACT_VERSION, CandidateDisposition, CandidateState,
    ClosureDenominator, NegativeMemoryExtinctionCandidate, RevisionError,
};

/// The governing exact trigger identity, copied verbatim from the Governor
/// owner through `SafetyProjection::negative_memory_triggers`.
const GOVERNING_EXACT_TRIGGER: &str = "trigger-blocked-retry";

/// Composite failure fingerprint content: the owner failure memory as its
/// owner admitted it (trigger, failed action and outcome identity). It contains
/// the governing exact trigger verbatim, which is exactly why its presence
/// proves nothing about an exact-trigger requirement.
const COMPOSITE_FINGERPRINT: &str = "trigger-blocked-retry|action-retry|outcome-refused";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn candidate(
    trigger: &str,
    fingerprint: &str,
    state: CandidateState,
    missing: Vec<String>,
) -> NegativeMemoryExtinctionCandidate {
    let mut denominator = ClosureDenominator {
        fence: fence(),
        enumerated: vec![id("journal-handle-262-s10")],
        exclusions: vec![FailureOmission {
            handle: None,
            class: FailureOmissionClass::JournalBlind,
            note: "blind journal interval carried verbatim".to_owned(),
        }],
        recheck_digest: String::new(),
        complete: true,
    };
    denominator.recheck_digest = denominator.compute_digest().expect("denominator digest");
    let mut candidate = NegativeMemoryExtinctionCandidate {
        contract_version: CANDIDATE_CONTRACT_VERSION,
        candidate_id: id("candidate-262-s10"),
        observation_ref: id("observation-262-s10"),
        trigger: trigger.to_owned(),
        fingerprint: fingerprint.to_owned(),
        query_digest: "b".repeat(64),
        narrowing: AdvisoryNarrowing {
            suppress_activation: false,
            quarantine: false,
            archive: false,
        },
        disposition: CandidateDisposition::AdvisoryNarrow,
        denominator,
        state,
        missing,
        digest: String::new(),
    };
    candidate.digest = candidate.compute_digest().expect("candidate digest");
    candidate
}

fn exact_block_candidate(trigger: &str) -> NegativeMemoryExtinctionCandidate {
    candidate(
        trigger,
        COMPOSITE_FINGERPRINT,
        CandidateState::Unsupported,
        vec!["safety.negative_memory_triggers".to_owned()],
    )
}

/// Positive: the candidate's exact trigger identity is verbatim in the
/// governing set, so the exact-trigger requirement is satisfied.
#[test]
fn exact_trigger_identity_satisfies_its_requirement() {
    let governing = vec![GOVERNING_EXACT_TRIGGER.to_owned()];
    let candidate = exact_block_candidate(GOVERNING_EXACT_TRIGGER);
    candidate.validate().expect("exact candidate is valid");
    assert_eq!(candidate.recheck_exact_trigger(&governing), Ok(()));
}

/// Refusal: the composite fingerprint content is valid and identical to the
/// positive case, and it even contains the governing trigger as a substring,
/// but the candidate's exact trigger identity is only near it. The gate
/// compares the exact identity and refuses with the existing typed
/// [`RevisionError`], never a boolean and never a message string.
#[test]
fn semantic_near_match_over_valid_content_is_refused() {
    let governing = vec![GOVERNING_EXACT_TRIGGER.to_owned()];
    let candidate = exact_block_candidate("trigger-blocked-retry-eu-west");
    candidate
        .validate()
        .expect("near-match content is otherwise valid");
    assert_eq!(
        candidate.recheck_exact_trigger(&governing),
        Err(RevisionError::ScopeMismatch {
            field: "candidate.exact_trigger",
        }),
    );
}

/// Refusal, other direction: an exact trigger fired in the governing set and
/// the candidate does not record the exact-trigger block, so it is refused
/// rather than allowed to read as satisfied.
#[test]
fn exact_trigger_without_the_recorded_block_is_refused() {
    let governing = vec![GOVERNING_EXACT_TRIGGER.to_owned()];
    let candidate = candidate(
        GOVERNING_EXACT_TRIGGER,
        COMPOSITE_FINGERPRINT,
        CandidateState::Complete,
        Vec::new(),
    );
    candidate.validate().expect("candidate shape is valid");
    assert_eq!(
        candidate.recheck_exact_trigger(&governing),
        Err(RevisionError::ScopeMismatch {
            field: "candidate.exact_trigger",
        }),
    );
}
