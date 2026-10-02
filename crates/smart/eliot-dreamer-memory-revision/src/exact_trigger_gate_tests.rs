//! The exact/near-match boundary gate for one extinction candidate.
//!
//! `docs/architecture/I12-19-negative-memory.md:3` is the governing sentence:
//! "Exact deterministic trigger can block/requires probe within matching scope.
//! Semantic similarity only warns." The candidate therefore carries the exact
//! trigger in its own typed member ([`crate::ExactTrigger`], recorded on
//! [`crate::NegativeMemoryExtinctionCandidate::trigger`]) beside the composite
//! failure fingerprint, and the candidate's existing `validate()` enforces that
//! closed shape while
//! [`crate::NegativeMemoryExtinctionCandidate::recheck_exact_trigger`] is the
//! only place an exact-trigger requirement is decided over A CANDIDATE'S OWN
//! RECORDED trigger. The other such comparison in this crate is the private
//! `classify`'s, at src/lib.rs:828-832, which decides the same requirement over
//! the INTAKE's trigger rather than a candidate's: it compares
//! `intake.observation.trigger` against
//! `intake.safety.negative_memory_triggers`. `classify`'s own doc
//! (src/lib.rs:821-826) calls that first refusal "the only exact-trigger
//! comparison in this crate", and both claims are true at once because the two
//! read different members: `observation.trigger` upstream of a candidate
//! existing, and `candidate.trigger.identity` after it does.
//!
//! One case satisfies that requirement on the exact identity. Every refusal is
//! an existing typed [`crate::RevisionError`], and there are SIX of them, not
//! four: a composite near-match promoted into the exact-trigger slot, an exact
//! trigger bound to another observation, an exact trigger read under a foreign
//! fence, an exact-trigger block recorded with an EMPTY identity, a near-match
//! identity refused by the requirement check itself, and an exact trigger that
//! fired in the governing set with NO recorded block.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_observation_contracts::{FailureOmission, FailureOmissionClass};

use crate::{
    AdvisoryNarrowing, CANDIDATE_CONTRACT_VERSION, CandidateDisposition, CandidateState,
    ClosureDenominator, ExactTrigger, NegativeMemoryExtinctionCandidate, RevisionError,
};

/// The governing exact trigger identity, copied verbatim from the Governor
/// owner through `SafetyProjection::negative_memory_triggers`.
const GOVERNING_EXACT_TRIGGER: &str = "trigger-blocked-retry";

/// Composite failure fingerprint content: the owner failure memory as its
/// owner admitted it (trigger, failed action and outcome identity). It contains
/// the governing exact trigger verbatim, which is exactly why its presence
/// proves nothing about an exact-trigger requirement.
const COMPOSITE_FINGERPRINT: &str = "trigger-blocked-retry|action-retry|outcome-refused";

/// The observation handle the candidate bears on.
const OBSERVATION_REF: &str = "observation-262-s10";

/// A second observation handle, for the refusal that binds an exact trigger to
/// a failure it did not fire under.
const OTHER_OBSERVATION_REF: &str = "observation-262-s10-other";

/// Authority lineage of the governing fence.
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

/// Authority lineage of a fence that is not the governing one.
const FOREIGN_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440001";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn foreign_fence() -> StateFence {
    let lineage = EpochLineageId::new(FOREIGN_LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

/// Build one candidate whose exact-trigger member carries `identity` under
/// `trigger_observation_ref` and `trigger_fence`, exactly as the production
/// construction site does.
fn candidate_with(
    identity: &str,
    trigger_observation_ref: &str,
    trigger_fence: StateFence,
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
        observation_ref: id(OBSERVATION_REF),
        trigger: ExactTrigger {
            identity: identity.to_owned(),
            observation_ref: id(trigger_observation_ref),
            state_fence: trigger_fence,
        },
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

/// The recorded exact-trigger block: the exact identity fired, so the candidate
/// is `Unsupported` naming the governing trigger set as its missing evidence.
fn exact_block_candidate(identity: &str) -> NegativeMemoryExtinctionCandidate {
    candidate_with(
        identity,
        OBSERVATION_REF,
        fence(),
        COMPOSITE_FINGERPRINT,
        CandidateState::Unsupported,
        vec!["safety.negative_memory_triggers".to_owned()],
    )
}

/// Positive: the candidate's exact trigger identity is verbatim in the
/// governing set, so the closed shape validates and the requirement it records
/// is satisfied.
#[test]
fn exact_trigger_identity_satisfies_its_requirement() {
    let governing = vec![GOVERNING_EXACT_TRIGGER.to_owned()];
    let candidate = exact_block_candidate(GOVERNING_EXACT_TRIGGER);
    candidate.validate().expect("exact candidate is valid");
    // The only oracles here are production ones. `recheck_exact_trigger`
    // returning `Ok` already requires the recorded identity to be a member of
    // the governing set AND the state to be `Unsupported`, so no assertion
    // here restates a fixture literal back at itself.
    assert_eq!(candidate.recheck_exact_trigger(&governing), Ok(()));
}

/// Refusal by `validate()`: the composite near-match description is offered as
/// the exact trigger. This is the promotion the donor forbids, and the same
/// validator that already recomputes the digest refuses it.
#[test]
fn composite_near_match_promoted_into_the_exact_slot_is_refused() {
    let candidate = exact_block_candidate(COMPOSITE_FINGERPRINT);
    assert_eq!(
        candidate.validate(),
        Err(RevisionError::ScopeMismatch {
            field: "candidate.trigger.identity",
        }),
    );
}

/// Refusal by `validate()`: an exact trigger bound to another observation than
/// the one this candidate bears on does not bind the recorded failure at all.
#[test]
fn exact_trigger_bound_to_another_observation_is_refused() {
    let candidate = candidate_with(
        GOVERNING_EXACT_TRIGGER,
        OTHER_OBSERVATION_REF,
        fence(),
        COMPOSITE_FINGERPRINT,
        CandidateState::Unsupported,
        vec!["safety.negative_memory_triggers".to_owned()],
    );
    assert_eq!(
        candidate.validate(),
        Err(RevisionError::ScopeMismatch {
            field: "candidate.trigger.observation_ref",
        }),
    );
}

/// Refusal by `validate()`: an exact trigger read under a foreign authority
/// lineage is outside the matching scope, so it cannot back a block here.
#[test]
fn exact_trigger_under_a_foreign_fence_is_refused() {
    let candidate = candidate_with(
        GOVERNING_EXACT_TRIGGER,
        OBSERVATION_REF,
        foreign_fence(),
        COMPOSITE_FINGERPRINT,
        CandidateState::Unsupported,
        vec!["safety.negative_memory_triggers".to_owned()],
    );
    assert_eq!(
        candidate.validate(),
        Err(RevisionError::FenceMismatch {
            field: "candidate.trigger.state_fence",
        }),
    );
}

/// Refusal by `validate()`: an exact-trigger block recorded with an empty
/// identity satisfies nothing by omission.
#[test]
fn exact_trigger_block_recorded_without_an_identity_is_refused() {
    let candidate = exact_block_candidate("   ");
    assert_eq!(
        candidate.validate(),
        Err(RevisionError::DigestMismatch {
            field: "candidate.trigger.identity",
        }),
    );
}

/// Refusal: the composite fingerprint content is valid and identical to the
/// positive case, and it even contains the governing trigger as a substring,
/// but the candidate's exact trigger identity is only near it. The requirement
/// check compares the exact identity and refuses with the existing typed
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
    let candidate = candidate_with(
        GOVERNING_EXACT_TRIGGER,
        OBSERVATION_REF,
        fence(),
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
