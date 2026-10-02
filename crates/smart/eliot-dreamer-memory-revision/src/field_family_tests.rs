//! The corrected field family of [`crate::NegativeMemoryExtinctionCandidate`],
//! member by member.
//!
//! Issue #262 (`R-UNRESOLVED-ROWS`) measured a divergence between the r6
//! wave-09 `NegativeMemoryExtinctionCandidate` field contract and the shipped
//! Rust candidate. It was decided in this crate's own `module.toml` row
//! `field_family_authority`: the field contract was the stale side, because
//! `docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md:97-98`
//! states "Memory revision/reconsolidation is represented through the existing
//! canonical `MemoryTransition` / `WriteReceipt` owner and a derived
//! `MemoryRevisionEvidence`, not a second memory system:", which makes the nine
//! `revision_*` names the field list of `MemoryRevisionEvidence` rather than of
//! any candidate, and
//! `docs/architecture/I12-19-negative-memory.md:6-17` is a `FailureFingerprint:`
//! block for a shape this crate already reaches by reference through
//! `RevisionIntake::observation`. So the corrected family is the shipped shape:
//! no member was added, removed or renamed, and these tests hold the corrected
//! family to that decision.
//!
//! Four properties are covered, and all four use the one existing validator
//! [`crate::NegativeMemoryExtinctionCandidate::validate`]. No second validator,
//! no new error variant and no new dependency is introduced.
//!
//! 1. The corrected family is complete and accepted: a candidate carrying all
//!    twelve members, each bound to the datum the production path holds, passes
//!    `validate()`.
//! 2. Every member's binding is a real comparison, not a restatement: each
//!    member is checked against a crate constant, another real member, or a
//!    value recomputed by the crate, and each member's name is checked against
//!    the name the LIVE `module.toml` declares. Nothing in the table is prose
//!    that no assertion reads, so deleting an entry's check removes a check.
//! 3. No member satisfies its requirement by presence. Each of the twelve has a
//!    rebinding that moves it off the datum it claims, and each rebinding is
//!    refused with the exact existing [`crate::RevisionError`] naming the field
//!    that discriminates it. Six of the twelve have a member-specific rule
//!    (`contract_version`, `observation_ref`, `fingerprint`, `denominator`,
//!    `state` and `missing`); for the other six the frozen `digest` is the
//!    binding, and the refusal is `candidate.digest`.
//! 4. The manifest is the owner-located copy of this contract, so the family it
//!    declares is read from the manifest's own bytes and compared, in order,
//!    with the family exercised here. That comparison is also what refuses any
//!    re-add of a superseded `revision_*`, `failure_fingerprint_*` or
//!    `extinction_evaluation_*` name.
//!
//! The exact-trigger refusals that belong to
//! `candidate_exact_deterministic_trigger_with_its_observation_and_fence` are in
//! the crate's `exact_trigger_gate_tests` module; this file adds the
//! family-binding case for that member and does not repeat them.
//!
//! One asymmetry is reported rather than encoded: `candidate_stable_identity`
//! is bounded at the production construction site
//! (`check_candidate_id`, called from `finish`), which is private to this
//! crate, and `validate()` does not re-check it. The observable refusal for a
//! swapped candidate identity is therefore the frozen digest, and no test here
//! claims a `validate()` rule that does not exist.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
};
use eliot_observation_contracts::{FailureOmission, FailureOmissionClass};

use crate::{
    AdvisoryNarrowing, CANDIDATE_CONTRACT_VERSION, CandidateDisposition, CandidateState,
    ClosureDenominator, ExactTrigger, MAX_ID_CHARS, MAX_MISSING_ENTRIES,
    NegativeMemoryExtinctionCandidate, RevisionError,
};

/// The candidate identity the production path is given.
const CANDIDATE_REF: &str = "candidate-262-field-family";

/// The observed failure handle the production path is given.
const OBSERVATION_REF: &str = "observation-262-field-family";

/// A second observed failure handle, for the refusal that makes the candidate
/// claim a failure its recorded exact trigger did not fire under.
const OTHER_OBSERVATION_REF: &str = "observation-262-field-family-other";

/// A second candidate identity, for the refusal that swaps a sealed identity.
const OTHER_CANDIDATE_REF: &str = "candidate-262-field-family-swapped";

/// Authority lineage of the governing fence.
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440002";

/// The exact deterministic trigger identity the production path reads from the
/// observation, as the Governor owner copied it verbatim.
const GOVERNING_EXACT_TRIGGER: &str = "trigger-blocked-retry";

/// A semantic near-match of that identity: an exact-trigger-shaped identity that
/// is not the one the observation fired under, and the value this file refuses
/// as an unbound rebinding of the trigger member.
const NEAR_MATCH_TRIGGER: &str = "trigger-blocked-retry-eu-west";

/// Composite failure fingerprint content, the semantic description of the owner
/// failure memory. It contains the governing exact trigger verbatim, which is
/// exactly why it may never occupy the exact-trigger slot.
const COMPOSITE_FINGERPRINT: &str = "trigger-blocked-retry|action-retry|outcome-refused";

/// The one journal handle the closure denominator enumerates.
const JOURNAL_REF: &str = "journal-handle-262-field-family";

/// The self-query digest the production path recomputes from the posed query.
const QUERY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

/// The bounded, control-character-free identity rule this crate already applies
/// to `intake.candidate_id` and to the exact-trigger identity in `validate`.
fn is_bounded_identity(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.chars().any(char::is_control)
        && value.chars().count() <= MAX_ID_CHARS
}

/// The digest form the owner recomputes and `validate_intake` echoes before it
/// reaches the candidate: lowercase SHA-256 hex, the form
/// `ClosureDenominator::compute_digest` produces.
fn is_owner_digest_form(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// One candidate carrying every member of the corrected field family, bound the
/// way `finish` binds it and sealed with a digest computed over exactly those
/// members.
fn bound_candidate() -> NegativeMemoryExtinctionCandidate {
    let mut denominator = ClosureDenominator {
        fence: fence(),
        enumerated: vec![id(JOURNAL_REF)],
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
        candidate_id: id(CANDIDATE_REF),
        observation_ref: id(OBSERVATION_REF),
        trigger: ExactTrigger {
            identity: GOVERNING_EXACT_TRIGGER.to_owned(),
            observation_ref: id(OBSERVATION_REF),
            state_fence: fence(),
        },
        fingerprint: COMPOSITE_FINGERPRINT.to_owned(),
        query_digest: QUERY_DIGEST.to_owned(),
        narrowing: AdvisoryNarrowing {
            suppress_activation: true,
            quarantine: false,
            archive: false,
        },
        disposition: CandidateDisposition::AdvisoryNarrow,
        denominator,
        state: CandidateState::Complete,
        missing: Vec::new(),
        digest: String::new(),
    };
    candidate.digest = candidate.compute_digest().expect("candidate digest");
    candidate
}

/// Apply `rebind` to a sealed candidate without resealing it, so the frozen
/// digest still covers the members exactly as the production path bound them
/// and the refusal under test is the one that member's binding produces.
fn unsealed(
    rebind: fn(&mut NegativeMemoryExtinctionCandidate),
) -> NegativeMemoryExtinctionCandidate {
    let mut candidate = bound_candidate();
    rebind(&mut candidate);
    candidate
}

// ---------------------------------------------------------------------------
// The real binding of each member. Every one of these compares a real member
// against a real datum — a crate constant, another real member, or a value the
// crate recomputes — so none of them can pass by restating the fixture.
// ---------------------------------------------------------------------------

/// `contract_version` against the crate's own frozen version constant.
fn contract_version_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if candidate.contract_version == CANDIDATE_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(format!(
            "contract_version is {contract_version:?}, not CANDIDATE_CONTRACT_VERSION",
            contract_version = candidate.contract_version,
        ))
    }
}

/// `candidate_id` against the identity rule `check_candidate_id` applies at the
/// production construction site, using the crate's own `MAX_ID_CHARS`.
fn candidate_id_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if is_bounded_identity(candidate.candidate_id.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "candidate_id is not a bounded identity: {identity:?}",
            identity = candidate.candidate_id.as_str(),
        ))
    }
}

/// `observation_ref` against the real cross-binding `validate` enforces: the
/// candidate bears on the observation its own exact trigger fired under.
fn observation_ref_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if candidate.observation_ref == candidate.trigger.observation_ref {
        Ok(())
    } else {
        Err("observation_ref does not name the observed failure the trigger fired under".to_owned())
    }
}

/// `trigger` against the four real rules: the bounded identity form, the
/// composite near-match exclusion, the observation it fired under, and the
/// closure fence compatibility.
fn trigger_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if !is_bounded_identity(&candidate.trigger.identity) {
        return Err("trigger.identity is not a bounded identity".to_owned());
    }
    if candidate.trigger.identity == candidate.fingerprint {
        return Err("trigger.identity carries the composite near-match".to_owned());
    }
    if candidate.trigger.observation_ref != candidate.observation_ref {
        return Err("trigger.observation_ref names another observation".to_owned());
    }
    if !candidate
        .trigger
        .state_fence
        .is_compatible_with(&candidate.denominator.fence)
    {
        return Err("trigger.state_fence is outside the closure fence".to_owned());
    }
    Ok(())
}

/// `fingerprint` against the owner's composite failure memory: a bounded
/// identity that embeds the exact trigger verbatim and is wider than it, which
/// is exactly why its presence proves nothing about an exact trigger.
fn fingerprint_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if !is_bounded_identity(&candidate.fingerprint) {
        return Err("fingerprint is not a bounded identity".to_owned());
    }
    if !candidate.fingerprint.contains(&candidate.trigger.identity) {
        return Err("fingerprint does not echo the exact trigger verbatim".to_owned());
    }
    if candidate.fingerprint.chars().count() <= candidate.trigger.identity.chars().count() {
        return Err("fingerprint is not wider than the exact trigger it embeds".to_owned());
    }
    Ok(())
}

/// `query_digest` against the digest form the owner recomputes and
/// `validate_intake` echoes before the candidate is built.
fn query_digest_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if is_owner_digest_form(&candidate.query_digest) {
        Ok(())
    } else {
        Err(format!(
            "query_digest is not the owner digest form: {digest:?}",
            digest = candidate.query_digest,
        ))
    }
}

/// `narrowing` against the classification rule `classify` implements: advisory
/// suppression is proposed exactly when coverage is complete.
fn narrowing_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if candidate.narrowing.suppress_activation == (candidate.state == CandidateState::Complete) {
        Ok(())
    } else {
        Err("narrowing.suppress_activation disagrees with the classified completeness".to_owned())
    }
}

/// `disposition` against the classification rule: the exact-trigger block is
/// `Unsupported` with the advisory disposition, never Mechanism Review.
fn disposition_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if candidate.state == CandidateState::Unsupported
        && candidate.disposition == CandidateDisposition::MechanismReview
    {
        return Err(
            "a recorded exact-trigger block must carry the advisory disposition".to_owned(),
        );
    }
    Ok(())
}

/// `denominator` against a value the crate recomputes from its own members, and
/// against the fence the exact trigger was read under.
fn denominator_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    let recomputed = candidate
        .denominator
        .compute_digest()
        .map_err(|error| format!("denominator is not digestible: {error}"))?;
    if candidate.denominator.recheck_digest != recomputed {
        return Err("denominator.recheck_digest does not recompute".to_owned());
    }
    if candidate.denominator.fence != candidate.trigger.state_fence {
        return Err(
            "denominator.fence is not the fence the exact trigger was read under".to_owned(),
        );
    }
    Ok(())
}

/// `state` against the two members that decide completeness. The converse is the
/// real check: `validate` refuses an incomplete Complete, and this refuses a
/// Complete-looking intake recorded as something else.
fn state_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    let complete = candidate.missing.is_empty() && candidate.denominator.complete;
    if complete == (candidate.state == CandidateState::Complete) {
        Ok(())
    } else {
        Err("state disagrees with the missing-evidence and closure completeness".to_owned())
    }
}

/// `missing` against the crate's own `MAX_MISSING_ENTRIES` and against the
/// `complete_rule`, which makes the list empty exactly in the Complete state.
fn missing_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    if candidate.missing.len() > MAX_MISSING_ENTRIES {
        return Err("missing exceeds MAX_MISSING_ENTRIES".to_owned());
    }
    if candidate.missing.is_empty() == (candidate.state == CandidateState::Complete) {
        Ok(())
    } else {
        Err("missing must be empty exactly when the state is Complete".to_owned())
    }
}

/// `digest` against the value the crate recomputes over every other member.
fn digest_binding(candidate: &NegativeMemoryExtinctionCandidate) -> Result<(), String> {
    let recomputed = candidate
        .compute_digest()
        .map_err(|error| format!("candidate is not digestible: {error}"))?;
    if candidate.digest == recomputed {
        Ok(())
    } else {
        Err("digest does not cover the members as bound".to_owned())
    }
}

// ---------------------------------------------------------------------------
// The corrected field family, in the order this crate's own `module.toml`
// declares it. Each entry is a member that already exists, so this list is the
// decision itself and not an inventory of work still owed.
// ---------------------------------------------------------------------------

/// One member of the corrected field family: the exact name the live
/// `module.toml` declares for it, the real binding that member must satisfy, the
/// rebinding that moves it off that binding, and the exact existing refusal that
/// rebinding produces.
#[derive(Debug)]
struct FamilyMember {
    /// Exact name in the `fields` list of this crate's own live `module.toml`.
    family_name: &'static str,
    /// The member's real binding, checked against the real candidate.
    binding: fn(&NegativeMemoryExtinctionCandidate) -> Result<(), String>,
    /// Moves the member off its bound datum.
    rebind: fn(&mut NegativeMemoryExtinctionCandidate),
    /// The existing refusal a binding mismatch on this member produces.
    refusal: fn() -> RevisionError,
}

fn digest_refusal() -> RevisionError {
    RevisionError::DigestMismatch {
        field: "candidate.digest",
    }
}

fn version_refusal() -> RevisionError {
    RevisionError::DigestMismatch {
        field: "candidate.contract_version",
    }
}

fn trigger_observation_refusal() -> RevisionError {
    RevisionError::ScopeMismatch {
        field: "candidate.trigger.observation_ref",
    }
}

fn trigger_identity_refusal() -> RevisionError {
    RevisionError::ScopeMismatch {
        field: "candidate.trigger.identity",
    }
}

fn denominator_refusal() -> RevisionError {
    RevisionError::DigestMismatch {
        field: "candidate.denominator.recheck_digest",
    }
}

fn missing_refusal() -> RevisionError {
    RevisionError::DigestMismatch {
        field: "candidate.missing",
    }
}

fn missing_bounds_refusal() -> RevisionError {
    RevisionError::Bounds {
        field: "candidate.missing",
    }
}

/// Members 1-4: the identity of the candidate, the identity of the failure it
/// bears on, the exact trigger it fired under, and the composite fingerprint.
fn identity_and_observation_members() -> Vec<FamilyMember> {
    vec![
        FamilyMember {
            family_name: "candidate_contract_version",
            binding: contract_version_binding,
            rebind: |candidate| {
                candidate.contract_version = ContractVersion::new(1, 0, 1);
            },
            refusal: version_refusal,
        },
        FamilyMember {
            family_name: "candidate_stable_identity",
            binding: candidate_id_binding,
            rebind: |candidate| {
                candidate.candidate_id = id(OTHER_CANDIDATE_REF);
            },
            refusal: digest_refusal,
        },
        FamilyMember {
            family_name: "candidate_observed_failure_handle",
            binding: observation_ref_binding,
            rebind: |candidate| {
                candidate.observation_ref = id(OTHER_OBSERVATION_REF);
            },
            refusal: trigger_observation_refusal,
        },
        FamilyMember {
            family_name: "candidate_exact_deterministic_trigger_with_its_observation_and_fence",
            binding: trigger_binding,
            rebind: |candidate| {
                candidate.trigger.identity = NEAR_MATCH_TRIGGER.to_owned();
            },
            refusal: digest_refusal,
        },
    ]
}

/// Members 5-8: the composite fingerprint, the posed self-query digest, the
/// reversible narrowing and the disposition.
fn fingerprint_and_narrowing_members() -> Vec<FamilyMember> {
    vec![
        FamilyMember {
            family_name: "candidate_composite_failure_fingerprint_echoed_verbatim",
            binding: fingerprint_binding,
            rebind: |candidate| {
                let claimed_exact_trigger = candidate.trigger.identity.clone();
                candidate.fingerprint = claimed_exact_trigger;
            },
            refusal: trigger_identity_refusal,
        },
        FamilyMember {
            family_name: "candidate_posed_self_query_digest",
            binding: query_digest_binding,
            rebind: |candidate| {
                candidate.query_digest = "c".repeat(64);
            },
            refusal: digest_refusal,
        },
        FamilyMember {
            family_name: "candidate_reversible_advisory_narrowing_only",
            binding: narrowing_binding,
            rebind: |candidate| {
                candidate.narrowing.quarantine = true;
            },
            refusal: digest_refusal,
        },
        FamilyMember {
            family_name: "candidate_disposition",
            binding: disposition_binding,
            rebind: |candidate| {
                candidate.disposition = CandidateDisposition::MechanismReview;
            },
            refusal: digest_refusal,
        },
    ]
}

/// Members 9-12: the closure denominator, the terminal state, the exact missing
/// evidence, and the frozen digest.
fn closure_and_state_members() -> Vec<FamilyMember> {
    vec![
        FamilyMember {
            family_name: "candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest",
            binding: denominator_binding,
            rebind: |candidate| {
                candidate
                    .denominator
                    .enumerated
                    .push(id("journal-handle-262-field-family-unsealed"));
            },
            refusal: denominator_refusal,
        },
        FamilyMember {
            family_name: "candidate_terminal_state",
            binding: state_binding,
            rebind: |candidate| {
                candidate.state = CandidateState::Inconclusive;
                candidate.missing.clear();
            },
            refusal: missing_refusal,
        },
        FamilyMember {
            family_name: "candidate_exact_missing_evidence",
            binding: missing_binding,
            rebind: |candidate| {
                candidate.missing = vec!["missing".to_owned(); MAX_MISSING_ENTRIES + 1];
            },
            refusal: missing_bounds_refusal,
        },
        FamilyMember {
            family_name: "candidate_frozen_digest",
            binding: digest_binding,
            rebind: |candidate| {
                candidate.digest = "0".repeat(64);
            },
            refusal: digest_refusal,
        },
    ]
}

/// The corrected field family, in the order the live `module.toml` declares it.
fn corrected_field_family() -> Vec<FamilyMember> {
    let mut family = identity_and_observation_members();
    family.extend(fingerprint_and_narrowing_members());
    family.extend(closure_and_state_members());
    family
}

/// Read the `fields` list of the `[[field_contract]]` row out of this crate's
/// own manifest bytes, so the contract an agent reads is the contract the tests
/// hold rather than a restatement of it.
fn declared_field_family() -> Vec<String> {
    let manifest = include_str!("../module.toml");
    let declaration = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("fields = ["))
        .expect("the manifest declares a fields list");
    let names = declaration
        .trim_start()
        .trim_start_matches("fields = ")
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    names
        .split(',')
        .map(|name| name.trim().trim_matches('"').to_owned())
        .collect()
}

/// Positive, one case per member: the corrected family is the shipped shape, so
/// a candidate carrying all twelve members bound as the production path binds
/// them is accepted by the one existing validator, and each member's name and
/// binding are both checked against real sources.
#[test]
fn every_corrected_field_family_member_is_bound_and_accepted() {
    let declared = declared_field_family();
    let candidate = bound_candidate();
    candidate
        .validate()
        .expect("a candidate over the corrected family is valid");
    for member in corrected_field_family() {
        let family_name = member.family_name;
        let named_by_the_live_manifest = declared.contains(&family_name.to_owned());
        let binding = (member.binding)(&candidate);
        assert!(
            named_by_the_live_manifest && binding.is_ok(),
            "{family_name}: named by the live module.toml: {named_by_the_live_manifest}; \
             real binding: {binding:?}",
        );
    }
}

/// Refusal, one case per member: a member re-bound after the candidate was
/// sealed is refused by the one existing validator, so no member of the
/// corrected family can satisfy its requirement by being present.
#[test]
fn no_corrected_field_family_member_satisfies_its_requirement_by_presence() {
    for member in corrected_field_family() {
        let family_name = member.family_name;
        assert_eq!(
            unsealed(member.rebind).validate(),
            Err((member.refusal)()),
            "{family_name}: a rebound member must be refused by the existing validate()",
        );
    }
}

/// The corrected family is the one the live `module.toml` declares, in order.
/// This is also the refusal for the decision itself: re-adding any superseded
/// `revision_*`, `failure_fingerprint_*` or `extinction_evaluation_*` name to
/// the crate's field contract fails here.
#[test]
fn the_manifest_declares_exactly_the_corrected_field_family() {
    let declared = declared_field_family();
    let exercised: Vec<String> = corrected_field_family()
        .into_iter()
        .map(|member| member.family_name.to_owned())
        .collect();
    assert_eq!(declared, exercised);
}

/// Refusal, the `complete_rule` guarantee under the corrected
/// `candidate_terminal_state` and `candidate_exact_missing_evidence`: a Complete
/// state that still names a missing evidence entry is not Complete.
#[test]
fn a_complete_state_naming_missing_evidence_is_refused() {
    let mut candidate = bound_candidate();
    candidate.missing.push("revision.evidence_refs".to_owned());
    candidate.digest = candidate.compute_digest().expect("candidate digest");
    assert_eq!(
        candidate.validate(),
        Err(RevisionError::DigestMismatch {
            field: "candidate.complete_denominator",
        }),
    );
}

/// Refusal, the same rule from the other side: a Complete state whose closure
/// denominator is not complete is refused, which is what keeps the corrected
/// `candidate_reversible_advisory_narrowing_only` unable to claim a suppression
/// the closure does not support.
#[test]
fn a_complete_state_over_an_incomplete_closure_is_refused() {
    let mut candidate = bound_candidate();
    candidate.denominator.complete = false;
    candidate.denominator.recheck_digest = candidate
        .denominator
        .compute_digest()
        .expect("denominator digest");
    candidate.digest = candidate.compute_digest().expect("candidate digest");
    assert_eq!(
        candidate.validate(),
        Err(RevisionError::DigestMismatch {
            field: "candidate.complete_denominator",
        }),
    );
}
