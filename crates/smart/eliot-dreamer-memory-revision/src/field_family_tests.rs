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
//! ## What this file proves
//!
//! Three properties, and every assertion ABOUT A CANDIDATE in it goes either
//! through the one existing validator
//! [`crate::NegativeMemoryExtinctionCandidate::validate`] or
//! through the crate's own [`crate::NegativeMemoryExtinctionCandidate::compute_digest`]
//! / [`crate::ClosureDenominator::compute_digest`]. Three assertions read the live
//! `module.toml` instead of a candidate, and they are the stated exception: the
//! block-count anchor in `declared_field_family`, which refuses an absent,
//! repeated or misidentified `[[field_contract]]` block; the name-membership
//! check in property 1, which refuses any name this file exercises that the live
//! manifest does not declare; and the ordered comparison in property 3, which
//! refuses any re-add or reordering of a declared name. No second validator, no
//! new error variant, no new dependency, and no test-only rule dressed as a
//! guarantee.
//!
//! 1. The corrected family is the shipped shape: a candidate carrying all
//!    twelve members, bound the way `finish` binds them, is accepted by
//!    `validate()`, and every name this file exercises is a name the LIVE
//!    `module.toml` declares.
//! 2. No member satisfies its requirement by presence. Fourteen cases cover the
//!    twelve members, so ONE manifest name carries three entries: inside
//!    `candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest`,
//!    `denominator.recheck_digest` and `denominator.fence` are two separate
//!    member-specific rules, so each gets its own rebinding, and
//!    `denominator.exclusions` has no rule of its own but is reached through the
//!    `denominator.recheck_digest` rule, so it gets a third rebinding reporting
//!    that same discriminator. The other eleven names carry exactly one entry
//!    each. (The exact-trigger name covers three family members but has one entry
//!    here: its `observation_ref` and `state_fence` members are exercised in the
//!    crate's `exact_trigger_gate_tests` module, which this file's closing
//!    paragraph names.) Each rebinding is applied
//!    after the candidate was sealed, and each is refused by `validate()` with
//!    the exact existing [`crate::RevisionError`] naming the field that
//!    discriminates it. These are production refusals: each one is a call into
//!    the shipped validator, so deleting a case removes an observation of real
//!    behaviour rather than of a rule this file invented.
//! 3. The manifest is the owner-located copy of this contract, so the family it
//!    declares is read from the manifest's own bytes and compared, in order,
//!    with the family exercised here. That comparison is also what refuses any
//!    re-add of a superseded `revision_*`, `failure_fingerprint_*` or
//!    `extinction_evaluation_*` name.
//!
//! ## Which protection each member actually has
//!
//! Two protections are real, and this file states per member which one applies
//! instead of implying that they are the same. A *member-specific rule* is a
//! comparison `validate()` makes about that member; *frozen digest* means the
//! member's only production protection is commitment by `candidate.digest`,
//! which the crate's own `compute_digest` (src/lib.rs:325-341) covers over
//! `contract_version` (327), `candidate_id` (328), `observation_ref` (329),
//! `trigger` (330), `fingerprint` (331), `query_digest` (332), `narrowing`
//! (333), `disposition` (334), `denominator` (335), `state` (336) and `missing`
//! (337), and which `validate()` compares at src/lib.rs:463.
//!
//! One row below is NEITHER, and says so in its own cell: `denominator.exclusions`
//! has no member-specific rule of its own. Its protection is the separate
//! `denominator.recheck_digest`, which `validate()` recomputes from
//! `ClosureDenominator::compute_digest` (src/lib.rs:197-206, hashing the fence,
//! the members and these exclusions) and compares at src/lib.rs:442. Calling
//! that *frozen digest* would name the wrong protecting digest: frozen-digest
//! protection as this file defines it is commitment by `candidate.digest`,
//! compared at the single line 463.
//!
//! | # | `module.toml` name | candidate member | protection |
//! | -- | ---- | ---- | ---- |
//! | 1 | `candidate_contract_version` | `contract_version` | member-specific rule, src/lib.rs:381 |
//! | 2 | `candidate_stable_identity` | `candidate_id` | frozen digest only, src/lib.rs:328 and :463 |
//! | 3 | `candidate_observed_failure_handle` | `observation_ref` | member-specific rule, src/lib.rs:412 |
//! | 4 | `candidate_exact_deterministic_trigger_with_its_observation_and_fence` | `trigger.identity` | member-specific rule, src/lib.rs:393, AND committed to by the frozen digest, src/lib.rs:463 |
//! | 4 | same | `trigger.observation_ref` | member-specific rule, src/lib.rs:412 |
//! | 4 | same | `trigger.state_fence` | member-specific rule, src/lib.rs:433 |
//! | 5 | `candidate_composite_failure_fingerprint_echoed_verbatim` | `fingerprint` | member-specific rule for the near-match exclusion only, src/lib.rs:407; the echoed content itself is frozen digest only, src/lib.rs:331 and :463 |
//! | 6 | `candidate_posed_self_query_digest` | `query_digest` | frozen digest only, src/lib.rs:332 and :463 |
//! | 7 | `candidate_reversible_advisory_narrowing_only` | `narrowing` | frozen digest only, src/lib.rs:333 and :463 |
//! | 8 | `candidate_disposition` | `disposition` | frozen digest only, src/lib.rs:334 and :463 |
//! | 9 | `candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest` | `denominator.fence` | member-specific rule, src/lib.rs:436, where it is compared for fence compatibility against `trigger.state_fence`; also covered by `ClosureDenominator::compute_digest`, src/lib.rs:197-206 |
//! | 9 | same | `denominator.recheck_digest` | member-specific rule, src/lib.rs:442 |
//! | 9 | same | `denominator.complete` | member-specific rule, src/lib.rs:449 |
//! | 9 | same | `denominator.enumerated` | member-specific bounds rule past `MAX_CLOSURE_MEMBERS`, src/lib.rs:198, reached from `validate()` through src/lib.rs:442 |
//! | 9 | same | `denominator.exclusions` | no member-specific rule of its own: it is covered by the frozen `denominator.recheck_digest`, which `validate()` recomputes with the crate's own `ClosureDenominator::compute_digest` (src/lib.rs:197-206, over the fence, the members and these exclusions) and compares at src/lib.rs:442. That is a DIFFERENT member's rule, and a different comparison from the `candidate.digest` one at 463 that the frozen-digest rows above name |
//! | 10 | `candidate_terminal_state` | `state` | member-specific rule, src/lib.rs:447-462 |
//! | 11 | `candidate_exact_missing_evidence` | `missing` | member-specific rule, src/lib.rs:386, :449 and :456 |
//! | 12 | `candidate_frozen_digest` | `digest` | member-specific rule, src/lib.rs:463 |
//!
//! Four of the twelve members have NO member-specific rule anywhere in
//! `validate()`: `candidate_id`, `query_digest`, `narrowing` and `disposition`.
//! A fifth, `denominator.exclusions`, has none of its own either and is covered
//! by another member's rule, as its own row states. Directly, `validate()` reads
//! `contract_version` (381), `missing` (386, 447-462),
//! `trigger.identity` (393, 407), `trigger.observation_ref` (412),
//! `observation_ref` (412), `fingerprint` (407), `trigger.state_fence` (433),
//! `denominator.recheck_digest` (442), `denominator.complete` (449),
//! `denominator.fence` (436), `state` (447) and `digest` (463), and directly it
//! reads nothing else. It does read `denominator.enumerated` and
//! `denominator.exclusions` TRANSITIVELY, at the same 442 comparison: recomputing
//! `denominator.recheck_digest` runs `ClosureDenominator::compute_digest`
//! (src/lib.rs:197-206), which bounds `enumerated` at 198 and hashes `exclusions`
//! at 203. That is the reach the `denominator.enumerated` row of the table above
//! already records, and it is why `validate()` never mentions either member by
//! name. Of the four wholly unprotected members, `candidate_id` occurs in the
//! `validate` range exactly once -- in the comment at src/lib.rs:392 -- and
//! `query_digest`, `narrowing` and `disposition` occur in the `validate` body
//! zero times. For all four the whole protection is the frozen
//! `candidate.digest`, so their four refusal cases observe
//! `RevisionError::DigestMismatch` at `candidate.digest` and this file claims
//! nothing stronger. It asserts no
//! member-specific rule for them, and it deliberately does not re-implement a
//! private production helper or restate a digest form to manufacture one: a
//! `Complete` candidate with `narrowing.suppress_activation == false`, or with
//! `disposition == MechanismReview`, is accepted by `validate()` today, and
//! this file does not pretend otherwise.
//!
//! One further asymmetry is reported rather than encoded: `candidate_id` is
//! additionally bounded at the production construction site by
//! `check_candidate_id` (src/lib.rs:694), which is private to this crate and
//! called only from `finish`, so the production path refuses an unbounded
//! identity there and `validate()` does not re-check it.
//!
//! The exact-trigger refusals that belong to
//! `candidate_exact_deterministic_trigger_with_its_observation_and_fence` are in
//! the crate's `exact_trigger_gate_tests` module; this file adds the
//! family-binding case for that member and does not repeat them.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
};
use eliot_observation_contracts::{FailureOmission, FailureOmissionClass};

use crate::{
    AdvisoryNarrowing, CANDIDATE_CONTRACT_VERSION, CandidateDisposition, CandidateState,
    ClosureDenominator, ExactTrigger, MAX_MISSING_ENTRIES, NegativeMemoryExtinctionCandidate,
    RevisionError,
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

/// Authority lineage of a fence the exact trigger was not read under, for the
/// refusal that restates the closure denominator's fence onto a foreign one.
const FOREIGN_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440003";

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

/// The contract id this crate's own manifest declares for the corrected family.
const CONTRACT_ID: &str = "NegativeMemoryExtinctionCandidate";

/// The table header of the manifest block that owns a field contract.
const FIELD_CONTRACT_TABLE: &str = "[[field_contract]]";

/// How many immediate repeats the manifest-completeness comparison collapses.
///
/// It is TWO, and it is declared here so it cannot drift silently. Fourteen cases
/// fold to the manifest's twelve names, so exactly one name is represented more
/// than once: the closure denominator's, whose `denominator.recheck_digest`,
/// `denominator.fence` and `denominator.exclusions` entries are three ADJACENT
/// entries under it. A run of three adjacent entries folds to one name by
/// dropping two, which is why three cases under one name is two repeats here and
/// not three. (The exact-trigger manifest name covers three family members but
/// contributes one entry to this list, because its other two members are
/// exercised in the crate's `exact_trigger_gate_tests` module.)
///
/// The number is asserted rather than assumed because the fold that produces it
/// also hides a mistake: a case inserted next to an existing entry and reusing
/// its `family_name` is invisible to the folded comparison. Adding, removing or
/// reordering cases that reuse a name means reviewing this constant, and the
/// assertion in [`the_manifest_declares_exactly_the_corrected_field_family`]
/// fails until it matches.
const ADJACENT_REPEAT_CASES: usize = 2;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

/// A fence the recorded exact trigger was not read under: a different authority
/// lineage, which `StateFence::is_compatible_with` refuses outright.
fn foreign_fence() -> StateFence {
    let lineage = EpochLineageId::new(FOREIGN_LINEAGE).expect("foreign lineage");
    let epoch =
        EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("foreign epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

/// One candidate carrying every member of the corrected field family, bound the
/// way `finish` binds it and sealed with a digest computed over exactly those
/// members by the crate's own `compute_digest`.
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
// The corrected field family, in the order this crate's own `module.toml`
// declares it. Each entry is a member that already exists, so this list is the
// decision itself and not an inventory of work still owed. Each entry carries
// only what a refusal case needs: the name the manifest declares, the rebinding
// that moves the member off the datum the production path bound it to, and the
// existing refusal that rebinding produces. No entry carries a local rule,
// because a rule only this file applies would prove nothing about production.
// ---------------------------------------------------------------------------

/// One member of the corrected field family: the exact name the live
/// `module.toml` declares for it, the rebinding that moves the member off its
/// bound datum, and the exact existing refusal that rebinding produces.
#[derive(Debug)]
struct FamilyMember {
    /// Exact name in the `fields` list of this crate's own live `module.toml`.
    family_name: &'static str,
    /// Moves the member off its bound datum.
    rebind: fn(&mut NegativeMemoryExtinctionCandidate),
    /// The existing production refusal a mismatch on this member produces.
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

/// A fence incompatibility is reported against the TRIGGER's fence member, not
/// against the denominator's, because src/lib.rs:433-436 is
/// `self.trigger.state_fence.is_compatible_with(&self.denominator.fence)`:
/// the comparison names `trigger.state_fence` as the receiver it inspects. The
/// full span is cited rather than just its last line, because that last line is
/// the only one carrying the comparison itself while the earlier lines carry the
/// receiver it is made against; citing 436 alone would understate where the
/// condition starts. The two table rows that cite this condition's halves
/// separately -- src/lib.rs:433 for `trigger.state_fence` and src/lib.rs:436
/// for `denominator.fence` -- are consistent with that and are left as they
/// are. The `denominator.fence` case below therefore rebounds the denominator's
/// fence and is still refused naming `candidate.trigger.state_fence`, and this
/// file asserts the value the code actually reports rather than the intuitive
/// one.
fn denominator_fence_refusal() -> RevisionError {
    RevisionError::FenceMismatch {
        field: "candidate.trigger.state_fence",
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
/// The protection each one has is the one stated in the module header: a
/// member-specific rule inside `validate()` for `contract_version`,
/// `observation_ref` and the trigger, and the frozen `digest` for
/// `candidate_id`.
fn identity_and_observation_members() -> Vec<FamilyMember> {
    vec![
        FamilyMember {
            family_name: "candidate_contract_version",
            // Member-specific rule: src/lib.rs:381.
            rebind: |candidate| {
                candidate.contract_version = ContractVersion::new(1, 0, 1);
            },
            refusal: version_refusal,
        },
        FamilyMember {
            family_name: "candidate_stable_identity",
            // Frozen `digest` only: `validate()` never reads `candidate_id`, so
            // the unsealed swap is refused at src/lib.rs:463.
            rebind: |candidate| {
                candidate.candidate_id = id(OTHER_CANDIDATE_REF);
            },
            refusal: digest_refusal,
        },
        FamilyMember {
            family_name: "candidate_observed_failure_handle",
            // Member-specific rule: src/lib.rs:412.
            rebind: |candidate| {
                candidate.observation_ref = id(OTHER_OBSERVATION_REF);
            },
            refusal: trigger_observation_refusal,
        },
        FamilyMember {
            family_name: "candidate_exact_deterministic_trigger_with_its_observation_and_fence",
            // Frozen `digest` only for the identity itself (src/lib.rs:463): the
            // bounded-identity rule at src/lib.rs:393 accepts this near-match,
            // which is the residual the module header and `validate`'s own doc
            // comment record rather than close.
            rebind: |candidate| {
                candidate.trigger.identity = NEAR_MATCH_TRIGGER.to_owned();
            },
            refusal: digest_refusal,
        },
    ]
}

/// Members 5-8: the composite fingerprint, the posed self-query digest, the
/// reversible narrowing and the disposition. Three of the four are frozen-digest
/// only; `fingerprint` has a member-specific rule for the near-match exclusion
/// and nothing else.
fn fingerprint_and_narrowing_members() -> Vec<FamilyMember> {
    vec![
        FamilyMember {
            family_name: "candidate_composite_failure_fingerprint_echoed_verbatim",
            // Member-specific rule: src/lib.rs:407 refuses the composite content
            // in the exact-trigger slot.
            rebind: |candidate| {
                let claimed_exact_trigger = candidate.trigger.identity.clone();
                candidate.fingerprint = claimed_exact_trigger;
            },
            refusal: trigger_identity_refusal,
        },
        FamilyMember {
            family_name: "candidate_posed_self_query_digest",
            // Frozen `digest` only: `validate()` never reads `query_digest`, so
            // the unsealed substitution is refused at src/lib.rs:463.
            rebind: |candidate| {
                candidate.query_digest = "c".repeat(64);
            },
            refusal: digest_refusal,
        },
        FamilyMember {
            family_name: "candidate_reversible_advisory_narrowing_only",
            // Frozen `digest` only: `validate()` never reads `narrowing`, so
            // the unsealed quarantine is refused at src/lib.rs:463.
            rebind: |candidate| {
                candidate.narrowing.quarantine = true;
            },
            refusal: digest_refusal,
        },
        FamilyMember {
            family_name: "candidate_disposition",
            // Frozen `digest` only: `validate()` never reads `disposition`, so
            // the unsealed rebinding is refused at src/lib.rs:463.
            rebind: |candidate| {
                candidate.disposition = CandidateDisposition::MechanismReview;
            },
            refusal: digest_refusal,
        },
    ]
}

/// Members 9-12: the closure denominator, the terminal state, the exact missing
/// evidence, and the frozen digest. Each of the four has a member-specific rule
/// inside `validate()`, so these SIX entries cover four manifest names: the
/// closure denominator's name carries three of them.
fn closure_and_state_members() -> Vec<FamilyMember> {
    vec![
        FamilyMember {
            family_name: "candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest",
            // Member-specific rule: src/lib.rs:442 recomputes the denominator
            // digest with the crate's own `compute_digest`.
            rebind: |candidate| {
                candidate
                    .denominator
                    .enumerated
                    .push(id("journal-handle-262-field-family-unsealed"));
            },
            refusal: denominator_refusal,
        },
        FamilyMember {
            family_name: "candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest",
            // Member-specific rule: src/lib.rs:436 compares `denominator.fence`
            // against `trigger.state_fence`. Rebinding ONLY the denominator's
            // fence onto a foreign authority lineage leaves the sealed digest
            // covering the datum the production path bound, and `validate()`
            // refuses it as a `FenceMismatch` -- naming
            // `candidate.trigger.state_fence`, because :436 reads the trigger's
            // fence as the receiver of the comparison. See
            // `denominator_fence_refusal`.
            rebind: |candidate| {
                candidate.denominator.fence = foreign_fence();
            },
            refusal: denominator_fence_refusal,
        },
        FamilyMember {
            family_name: "candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest",
            // No member-specific rule of its own, and this case says so rather
            // than borrowing a stronger claim: `validate()` never mentions
            // `exclusions` by name. Clearing the exclusions the production path
            // bound leaves the sealed `recheck_digest` covering the datum that
            // was bound, and src/lib.rs:442 refuses it while RECOMPUTING that
            // digest through `ClosureDenominator::compute_digest`, which hashes
            // `exclusions` at src/lib.rs:203. The refusal is therefore the same
            // `candidate.denominator.recheck_digest` discriminator the
            // `denominator.enumerated` case above reports -- which is exactly the
            // protection this member has, so the two cases are separate
            // rebindings of one protecting rule and not two rules. See
            // `denominator_refusal`.
            rebind: |candidate| {
                candidate.denominator.exclusions.clear();
            },
            refusal: denominator_refusal,
        },
        FamilyMember {
            family_name: "candidate_terminal_state",
            // Member-specific rule: src/lib.rs:447-462. The `missing.clear()`
            // is NECESSARY, not incidental, and that necessity is exactly why
            // this case's refusal does not name a field belonging to `state`.
            // The `Inconclusive | Unsupported` arm at src/lib.rs:455-461 refuses
            // an EMPTY `missing` list at its own first check; a candidate whose
            // `state` was rebound while its `missing` stayed NON-empty would sail
            // past that arm and be refused later, at src/lib.rs:463, naming
            // `candidate.digest` and proving nothing about `state`. Clearing
            // `missing` is what makes the arm's emptiness check the verdict. The
            // bound candidate ships `missing` empty already, so the clear is also
            // a no-op on the datum, and this file says so rather than presenting
            // it as a second meaningful rebinding.
            //
            // Two consequences, stated rather than hidden. The case rebinds TWO
            // members, so it does not move THE member off its bound datum the
            // way `FamilyMember::rebind` describes. And the discriminator it
            // reports is `candidate.missing` -- the same FIELD the
            // `candidate_exact_missing_evidence` case reports, under a different
            // variant (`RevisionError::DigestMismatch` here,
            // `RevisionError::Bounds` there). So this case does NOT independently
            // demonstrate a `state` rule: in this file the `state` rule is
            // indistinguishable from the `missing` rule, and the
            // member-satisfaction test's doc makes that visible by counting six
            // distinct field discriminators over eight member-specific cases.
            //
            // Isolating `state` is not merely omitted here, it is not reachable
            // by this file's construction: `state` has no discriminator of its
            // own in `validate()`, because the only refusals its arms produce
            // name `candidate.missing` or `candidate.complete_denominator`. A
            // resealed candidate with `state = Inconclusive` and a non-empty
            // `missing` is ACCEPTED, not refused, so the one rule `state` does
            // drive is the `complete_denominator` coherence rule that
            // `a_complete_state_over_an_incomplete_closure_is_refused` already
            // observes from the `Complete` side. That is a different construction
            // from this file's unsealed-rebinding rule and is reported here
            // rather than added.
            rebind: |candidate| {
                candidate.state = CandidateState::Inconclusive;
                candidate.missing.clear();
            },
            refusal: missing_refusal,
        },
        FamilyMember {
            family_name: "candidate_exact_missing_evidence",
            // Member-specific rule: src/lib.rs:386 against the crate's own
            // `MAX_MISSING_ENTRIES`.
            rebind: |candidate| {
                candidate.missing = vec!["missing".to_owned(); MAX_MISSING_ENTRIES + 1];
            },
            refusal: missing_bounds_refusal,
        },
        FamilyMember {
            family_name: "candidate_frozen_digest",
            // Member-specific rule: src/lib.rs:463.
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

/// Split the manifest into its own tables, each one starting with its table
/// header line and carrying the rest of that table's lines. Splitting on the
/// header is what keeps a `fields = [` line belonging to any other table out of
/// the field-contract read below.
fn manifest_tables(manifest: &str) -> Vec<Vec<&str>> {
    let mut tables: Vec<Vec<&str>> = Vec::new();
    for line in manifest.lines() {
        if line.trim().starts_with('[') {
            tables.push(vec![line]);
            continue;
        }
        if let Some(table) = tables.last_mut() {
            table.push(line);
        }
    }
    tables
}

/// The `id` a manifest line declares, if it is an `id = "..."` line at all.
fn declared_id(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("id = ")
        .map(|value| value.trim().trim_matches('"'))
}

/// Read the `fields` list of the `[[field_contract]]` block whose `id` is
/// [`CONTRACT_ID`], out of this crate's own manifest bytes, so the contract an
/// agent reads is the contract the tests hold rather than a restatement of it.
/// The read is anchored to that one block: an absent, repeated or misidentified
/// block is refused here instead of silently yielding some other `fields` line.
fn declared_field_family() -> Vec<String> {
    let manifest = include_str!("../module.toml");
    let tables = manifest_tables(manifest);
    let owning: Vec<&[&str]> = tables
        .iter()
        .filter(|table| {
            table
                .first()
                .is_some_and(|header| header.trim() == FIELD_CONTRACT_TABLE)
                && table
                    .iter()
                    .any(|line| declared_id(line) == Some(CONTRACT_ID))
        })
        .map(Vec::as_slice)
        .collect();
    assert_eq!(
        owning.len(),
        1,
        "{FIELD_CONTRACT_TABLE} blocks naming {CONTRACT_ID}"
    );
    let declaration = owning
        .first()
        .and_then(|table| {
            table
                .iter()
                .find(|line| line.trim_start().starts_with("fields = ["))
        })
        .unwrap_or_else(|| panic!("the block naming {CONTRACT_ID} declares no fields list"));
    declaration
        .trim_start()
        .trim_start_matches("fields = ")
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|name| name.trim().trim_matches('"').to_owned())
        .collect()
}

/// Positive: the corrected family is the shipped shape, so a candidate carrying
/// all twelve members bound the way `finish` binds them is accepted by the one
/// existing validator, and every name this file exercises is a name the live
/// manifest declares.
///
/// No per-member enforcement is asserted here, because for five of the twelve
/// there is none to assert: `candidate_id`, `query_digest`, `narrowing` and
/// `disposition` are read by no rule inside `validate()` at all, and
/// `denominator.exclusions` is read only transitively through the
/// `denominator.recheck_digest` rule (see the module header). The first four are
/// protected by commitment to the frozen `candidate.digest`, which the acceptance
/// assertion above and the refusal cases below both exercise through production
/// code; `denominator.exclusions` is protected by `denominator.recheck_digest`
/// instead, and its case below observes that.
#[test]
fn the_corrected_field_family_is_accepted_and_named_by_the_live_manifest() {
    let declared = declared_field_family();
    let candidate = bound_candidate();
    candidate
        .validate()
        .expect("a candidate over the corrected family is valid");
    for member in corrected_field_family() {
        let family_name = member.family_name;
        assert!(
            declared.contains(&family_name.to_owned()),
            "{family_name}: the live module.toml declares this name",
        );
    }
}

/// Refusal, one case per family member that has a protection to observe: a
/// member re-bound after the candidate was sealed is refused by the one existing
/// validator, so no member of the corrected family can satisfy its requirement
/// by being present. There are FOURTEEN cases over twelve members, and each is
/// the refusal production code produces -- `candidate.digest` for the SIX whose
/// whole protection is that digest (the four members `validate()` never reads,
/// plus `trigger.identity` and `digest` itself) -- and a member-specific field
/// discriminator for the other EIGHT.
///
/// Those eight report SIX distinct field discriminators rather than eight, and
/// the count is stated that way on purpose instead of as "eight member-specific
/// discriminators", because two of the eight deliberately share one. The
/// `denominator.enumerated` and `denominator.exclusions` cases are both refused
/// naming `candidate.denominator.recheck_digest`, because `exclusions` has no
/// rule of its own and is reached through the `recheck_digest` rule -- so they
/// are two members under one protecting rule, not two rules. The
/// `candidate_terminal_state` case is refused naming `candidate.missing`, a
/// discriminator that belongs to `missing`, because the arm it must reach refuses
/// an empty list first; that case therefore does NOT independently demonstrate a
/// `state` rule, and nothing here claims it does (see its own comment). `state`
/// has no discriminator of its own in `validate()`: the `Complete` arm reports
/// `candidate.complete_denominator` instead.
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
///
/// The manifest declares TWELVE names, while fourteen refusal cases exercise
/// them, because ONE manifest name carries three entries:
/// `candidate_closure_denominator_named_fence_members_exclusions_and_recheck_digest`
/// carries `denominator.recheck_digest`, `denominator.fence` and
/// `denominator.exclusions`. Those three entries are adjacent, so this
/// comparison collapses two immediate repeats and still asserts the declared
/// twelve names in the declared order -- a reordering, a rename or a re-add all
/// still fail here.
///
/// The fold is KEPT but it is no longer silent, which is the point of the
/// [`ADJACENT_REPEAT_CASES`] assertion below. Collapsing an immediate repeat is
/// what lets one manifest name carry several cases, but it also means a case
/// inserted immediately after an existing entry and reusing that entry's
/// `family_name` leaves this comparison byte-identical and this test green --
/// before the reshape the same edit was red. Pinning how much the fold collapses
/// converts that hole into a stated invariant: the unfolded list is built
/// alongside the folded one and its adjacent-repeat count must equal the two
/// declared in [`ADJACENT_REPEAT_CASES`], so a future case that reuses a
/// neighbouring name has to update the number deliberately and fails here until
/// it does. A case inserted anywhere else -- a new name, or one placed away from
/// its neighbours -- still fails the ordered comparison below, because neither
/// the folded list nor the declared twelve gains a thirteenth entry.
#[test]
fn the_manifest_declares_exactly_the_corrected_field_family() {
    let declared = declared_field_family();
    let unfolded: Vec<String> = corrected_field_family()
        .into_iter()
        .map(|member| member.family_name.to_owned())
        .collect();
    let collapsed = unfolded
        .iter()
        .zip(unfolded.iter().skip(1))
        .filter(|(first, second)| first == second)
        .count();
    assert_eq!(
        collapsed, ADJACENT_REPEAT_CASES,
        "the fold must collapse exactly {ADJACENT_REPEAT_CASES} immediate repeats",
    );
    let exercised: Vec<String> =
        unfolded
            .into_iter()
            .fold(Vec::new(), |mut names: Vec<String>, name| {
                if names.last() != Some(&name) {
                    names.push(name);
                }
                names
            });
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
