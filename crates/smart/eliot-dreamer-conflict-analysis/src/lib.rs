//! Bounded candidate-only conflict analysis (A-39).
//!
//! Pure deterministic stateless zero-effect owner of exactly one bounded
//! [`ConflictSet`] projection. The handler preserves every position,
//! objection, source, counterexample, minority view, assumption and unknown
//! without selecting a winner, resolving the conflict, tallying votes,
//! acquiring sources, executing probes, or emitting any Concilium plan,
//! mutation, authority, effect, or finish signal.
//!
//! Cell `smart.dreamer.conflict_analysis`, order 39. All inputs are immutable
//! and caller supplied. Every identity, receipt, draft, grounding,
//! `ConflictSet`, lineage, objection, probe, policy, budget, deadline, and
//! digest binding is explicit. The A-05 receipt is checked intrinsically through its own
//! validation entry points and is never re-executed here. No screening,
//! grounding, common validation, peer transport, Concilium launch, provider,
//! model, store, governor, clock, or finish surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the six typed
//! parameters of [`analyze_conflict`], never decoded from ambient bytes.
//!
//! [`ConflictAnalysisPolicy`] is the one shape here that also carries a closed
//! wire form, because it is a mandatory member of the production Orientation
//! carrier (`bins/eliot-dreamer`) that an owner channel must supply across a
//! process boundary. That form is closed and typed, not an intake path: it
//! states `deny_unknown_fields`, it decodes nothing on this crate's behalf, and
//! a decoded value reaches the analysis only through [`analyze_conflict`],
//! which re-proves its recorded fields before any stage runs. No other shape
//! below gained a deserializer, and none of the legacy declaration shapes
//! gained one either.
//!
//! Runtime boundary: a malformed, mismatched, over-bound, cancelled, or
//! past-deadline request fails closed as [`ConflictAnalysisError`] with zero
//! effects. Semantic shortfalls (partial denominators, blocked probes,
//! nondiscriminative probes, unnameable decision owners) are inert terminal
//! outcomes carried by [`ConflictAnalysisCandidate`], never errors that invite
//! a blind retry. A complete analysis remains unresolved without a separately
//! supplied external resolution receipt, which is retained verbatim and never
//! reissued or reinterpreted here.
//!
//! Two completeness rules are load-bearing. First, the incompleteness reason
//! is read from the analysis itself, never from the permission to emit partial
//! output: an incomplete analysis is [`ConflictOutcome::Partial`] when the
//! policy admits a partial emission and is otherwise the same typed
//! [`ConflictOutcome::Abstention`], so a stricter emission policy can withhold
//! a candidate but can never promote an incomplete one to
//! [`ConflictOutcome::Complete`]. Second, a probe is qualified by exact
//! identity and typed outcome distinction only: a rationale that mentions an
//! unknown names nothing, and a recommended probe lists only the positions the
//! `ConflictSet` itself binds to it, never the whole set by default.
//!
//! A third rule bounds every claim a position makes about its relationship to
//! the others. The typed comparison mapping is qualified ONCE per position and
//! reduced to a single relation, and the emitted disposition, the typed mapping,
//! and the note are all read from that one result, so they cannot disagree
//! about the proof ceiling. Only an owner-issued comparison under
//! [`SupplementVersion::OwnerRecordV2`] qualifies a relation: an absent
//! comparison, a legacy declaration, or any unresolved canonical dimension
//! leaves [`CompatibilityRelation::Ambiguous`] and a non-assertive note, so an
//! absent or unnormalizable comparison can never assert equal conditions.
//! Disjoint assumption handles are never a comparison, so they cannot make a
//! position a [`PositionDispositionKind::CompatibleResidue`] one; only an
//! owner-proven difference on a condition dimension can.
//!
//! Every terminal outcome is read from input the analysis already holds; none
//! is invented, defaulted, or inferred from prose. Cancellation and the frozen
//! deadline give [`ConflictOutcome::Blocked`] and [`ConflictOutcome::Stale`].
//! The canonical `ConflictSet` lifecycle gives [`ConflictOutcome::Rejected`]
//! for a set its owner already decided, which this cell never reissues;
//! [`ConflictOutcome::Unsupported`] for a supersession that names no resolved
//! part and is therefore unproven; and [`ConflictOutcome::Abstention`] for a
//! closed set with empty residue, which leaves no open conflict and so no
//! partial path. Each of those three preserves every position, objection, and
//! lineage group of the set it was handed, and none of them resolves it.
//! [`DecisionOwnerKind::Unknown`] is read the same way: the set's own authority
//! owners either name a decision owner or they do not, and where they do not,
//! the recommendation stays unnamed instead of adopting a kind-derived default.
//!
//! A fourth rule bounds the position denominator itself. Fewer than
//! [`MINIMUM_CONFLICT_POSITIONS`] positions is not a conflict, and a position
//! the set declares as an unresolved owner but does not supply has left the
//! denominator rather than been decided in it, so it is refused instead of
//! counted away. Both legs are read from the set's own declaration: a bare count
//! of the supplied `positions` would let a caller drop a declared member and
//! receive a clean analysis of a narrower conflict than the one that exists.
//! There is no typed missing-rival exception here yet, and the reason is
//! structural rather than an oversight: a `ConflictPosition` carries no
//! availability axis, and the crate's one omission type,
//! [`RivalDenominator`], is scoped to a causal claim's rival/confounder models
//! and says nothing about how many conflict positions exist.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal beyond the bounded member lists, source acquisition, probe
//! execution, route or budget reservation, peer transport, Concilium planning,
//! model or tool call, ambient-state read, authority, effect, or
//! terminal-completion call by construction; the only cryptography is the
//! canonical digest below, and the only fallible work is pure bounded
//! validation. There are no placeholder, mock, canned, or pseudo paths:
//! every branch binds an explicit input field. The retained legacy comparison
//! and causal supplement shapes are version 1 declarations: their values
//! are preserved and digested, but never treated as owner evidence. They do
//! not qualify equality, difference, prediction support, intervention, or
//! causal attribution. A comparison reaches a relation only as the
//! [`OwnerComparison`] above derives it from admitted owner records. No legacy
//! bytes are deserialized into a stronger shape.
//!
//! # Owner map and what production wiring must supply
//!
//! This cell CONSUMES owner-issued records and never acquires, upgrades, or
//! reissues one. The producer and authoritative identity for each class is
//! recorded in the owner-map table above the [`SourceMemberRecord`] type. The
//! runtime producer must supply, through [`OwnerRecords`]:
//!
//! - one [`SourceMemberRecord`] per `ConflictSet` position whose owner
//!   retained bytes, an immutable handle, a canonical digest, a source
//!   revision/snapshot, and the current task, scope, and fence;
//! - one [`OwnerComparison`] per compared pair, carrying a single
//!   [`OwnerComparisonProfile`] and one [`DimensionObservation`] per source per
//!   canonical dimension. A caller submits no `Equal`/`Differing` verdict:
//!   [`CompatibilityRelation`] is derived from the admitted values;
//! - one [`CausalEvidenceRecord`] per causal or predictive claim, carrying the
//!   mechanism claim identity, revision, and the retained claim bytes its
//!   recorded digest reproduces, the falsifier specification and its
//!   observed status, the matched control and the competent evaluator result,
//!   the intervention execution and receipt where one is claimed, the
//!   rival/confounder denominator with its omissions, and the retained
//!   [`EvidenceRecord`] envelopes. Each envelope's named owner is the source
//!   identity the envelope itself records, and its receipt digest is reproduced
//!   by the receipt bytes its owner retained, so the evaluator identity and the
//!   intervention receipt a claim leans on are read from owner-issued records
//!   rather than from strings chosen beside them.
//!
//! Absent, stale, mixed-fence, or incomplete owner records are an explicit
//! inert result: the relation stays [`CompatibilityRelation::Ambiguous`], the
//! causal state stays [`CausalClaimState::Unknown`], the valid observations are
//! still preserved, and the named gap travels with the candidate. That is the
//! whole of the owner-unavailable path — there is no fetch, no retry, no
//! fallback owner, and no acquisition surface here.
//!
//! # What makes a record owner-bound rather than merely well formed
//!
//! Shape is never authority here. Each of the following is checked against the
//! record that carries it, and a well-formed string satisfies none of them on
//! its own:
//!
//! - a source member's retained bytes must reproduce the digest the owner
//!   RECORDED for them ([`SourceMemberRecord::validate`]). The recorded value is
//!   the original and is never recomputed and substituted for the check.
//! - a [`SourceRecordCommitment`] is a pointer, not evidence. It becomes a
//!   binding only because [`check_owner_comparison_members`] requires a
//!   retained member recording exactly its digest and
//!   [`OwnerComparison::validate`] requires an admitted profile whose
//!   definition bytes reproduce its profile digest.
//! - a profile's definition bytes must reproduce its owner-recorded digest, and
//!   its descriptors must be exactly the canonical eight in canonical order.
//! - every observed value names its source, the member digest it was read from,
//!   and the descriptor it answers, so a value cannot be re-attached to another
//!   position or answer a dimension it was not read under.
//! - a causal record is joined to ITS OWN source's retained material, never to
//!   the union of every member in the analysis, and its mechanism claim must be
//!   read at that member's retained revision.
//! - the mechanism claim's retained bytes must reproduce the digest the owner
//!   RECORDED for them, the same recorded-digest pairing a source member gets.
//!   A claim digest matching no retained bytes is a string, not the source's own
//!   declared claim.
//! - an intervention receipt must be the receipt of a retained evidence
//!   envelope, and that envelope's own receipt identity must be reproduced by
//!   the receipt bytes its owner retained. A 64-character digest matching no
//!   envelope is a string, not an execution receipt, and a digest matching an
//!   envelope whose retained receipt bytes do not reproduce it is still one.
//! - an evidence envelope's named owner must be the source identity the
//!   envelope itself records in its provenance. Otherwise the rule that the
//!   evaluator verdict belongs to the control owner that issued it compares two
//!   caller strings instead of an owner identity to the record that issued it.
//! - every envelope's own fence must match the current item fence by exact
//!   tuple, because the envelope contract proves a fence is well formed, not
//!   that it is the current one; its provenance must name the current scope and
//!   exactly the revision of the retained material it is joined to, which is the
//!   `claim -> evidence handle -> source revision` link of I21.8 and the same
//!   join the reactive context contracts already apply.
//! - the competent/unqualified/absent evaluator verdict must belong to the
//!   control owner the record names, and must be carried by an envelope that
//!   owner issued. A verdict paired with somebody else's retained envelope is a
//!   caller assertion with a handle on it. That comparison is only a comparison
//!   at all because [`EvidenceRecord::validate`] requires the envelope's named
//!   owner to equal the source identity the envelope itself records, so
//!   `control.owner` is read against an owner-issued record rather than against
//!   a second string the same caller chose.
//!
//! Three rules bound the causal ceiling, and each is read from a denominator
//! that is independent of the others. An envelope's own recorded COVERAGE is the
//! first: an envelope that records partial, not-applicable, or unknown coverage
//! never qualifies, so partial valid evidence is preserved and named but cannot
//! authorize an evidence-qualified state. The second is the retained evidence
//! SET, whose coverage
//! [`CausalEvidenceRecord::derived_evidence_coverage`] derives from what the
//! envelopes themselves record rather than from a second copy of a caller list.
//! The third is the rival/confounder denominator, which is already checked
//! against the retained evidence. Neither set may report the other complete, and
//! [`CausalClaimRecord::coverage`] is the weaker of the two so a caller cannot
//! publish a complete causal cell by pointing at the complete one.
//!
//! The declared label and the derived assessment are separated in both
//! directions, and the separation is carried in the data rather than asserted in
//! prose: [`CausalClaimRecord::declared_state`] is the source's claim verbatim
//! beside the revision it was read at, and
//! [`CausalClaimRecord::effective_state`] is a separate value computed from
//! typed evidence records alone. Nothing short of the declared state's own
//! requirements promotes it, and an observed falsifier that came back
//! `Inconsistent` assesses the claim [`CausalClaimState::Refuted`] whatever the
//! source called it: a refuted prediction, structural, correlational, or causal
//! claim is never published under the label it was declared with. Refutation
//! reaches no leg that grants causality, so closing a claim down never mixes the
//! states together.
//!
//! Prediction, intervention, and attribution stay separate because the state
//! derivation MATCHES ON the accepted shared relation vocabulary — I12.18's
//! seven readings, which [`FailureCausalStatus`] already carries — rather than
//! on this crate's own spellings of them
//! ([`CausalClaimState::relation_status`]). Prediction support, intervention
//! support, and causal attribution are then three arms of one exhaustive match,
//! each naming only what its own reading requires, rather than a single verdict
//! that could stand for all three. Reusing the owner's enum also means a reading
//! added there stops this crate compiling until it has been decided here.
//!
//! A claim whose position has no admitted source member is refused at
//! admission rather than assessed against nothing. Nothing here raises a
//! ceiling: an unverifiable input keeps the unverified/unknown result.
//!
//! Test coverage note: 65 of 68 `WORK_UNIT_CASE 673/*` cases execute here
//! (673/1 valid completes, 673/2 wrong job and scope fail closed, 673/3
//! empty and single position are not conflicts, 673/5 duplicate and changed
//! identities fail closed, 673/6 complete/partial/stale/blocked/withheld
//! denominators stay explicit, 673/7 exact replay preserves digest while
//! changed content moves it, 673/8 no model, tool, store, peer, Concilium,
//! or decision mutation, 673/9 independent families stay two roots,
//! 673/10 shared lineage stays one root, 673/11 derived citation chain stays
//! one root, 673/12 shared context and route stays a common-mode risk,
//! 673/13 unknown lineage is not independent, 673/14
//! majority count cannot choose a winner, 673/15 minority position retained,
//! 673/16 every objection, counterexample, and unknown retained, 673/17
//! stale, refuted, and superseded history stays addressable, 673/18
//! contradiction under equal conditions, 673/19 compatible scope stays
//! residue, 673/20 owner-proved supersession retained while timestamp alone
//! is not supersession, 673/21 definition, unit, and denominator mismatch
//! stays compatible residue, 673/22 objective and value disagreement routes
//! to the Human and Task Controller owner, 673/23 policy, authority, and
//! effect disagreement routes to the Governor owner, 673/24 evidence quality,
//! coverage, and measurement disagreement stays live with the evidence-source
//! owner, 673/25 predictive and causal mechanism disagreement stays live
//! without a winner, 673/26 partial overlap retains a compatible residue,
//! 673/27 multiple canonical classes retained in precedence order, 673/28
//! required primary follows canonical precedence rather than first match,
//! 673/29 normalization preserves original propositions verbatim, 673/30
//! ambiguous prose gains no invented class, 673/31 chronology and correlation
//! stay non-causal without a winner, 673/32 bare causal hypotheses stay live
//! until mechanism, falsifier, and confounders are grounded, 673/33 prediction
//! support stays defeasible without intervention support, 673/34 missing matched
//! control and evaluator verdicts limit the causal claim, 673/36 unsupported
//! numeric, time, version, and causal precision gains no support, 673/37 rivals
//! and counterevidence stay live without truth selection, 673/38 a supplied
//! probe discriminates two live positions, 673/39 a supplied probe resolves one
//! load-bearing unknown, 673/41 exact outcome and owner, verifier, cost,
//! risk, privacy, and effect bounds preserved verbatim, 673/42 blocked and
//! over-budget probes stay visible but unrecommended, 673/43 duplicate probe
//! identity fails closed without a changed-condition exemption, 673/44
//! supplied probe content and semantic order preserved, 673/35 shared model
//! and evaluator limits independence, 673/40
//! nondiscriminative probe rejected, 673/51 Concilium-review
//! recommendation carries no plan, 673/4 receipt and fence mismatch fails
//! closed, 673/56 exact pre-handler receipt plus seven preservation dimensions,
//! 673/57 failed and unknown dimensions stay independent without borrowing,
//! 673/60 irrelevant order preserves digest, 673/61 exact and one-over
//! limits fail closed, 673/62 cancellation and deadline emit blocked/stale,
//! 673/64 every expected position and objection stays visible,
//! 673/65 independent count never exceeds unique authoritative roots,
//! 673/66 discriminative probe carries differing outcomes or an exact
//! unknown-resolution criterion, 673/67 classification, resolution, and proof
//! stay within grounded evidence, 673/68 bounded malformed input stays
//! panic-free with no winner, resolution, authority, execution, or Finish,
//! 673/45 recommended probes carry declarations only with no execution, route,
//! budget, or effect receipt, 673/46 epistemic disagreement names the
//! evidence-source owner with its evidence contract, 673/47 shared evaluator
//! lineage names the evaluator-verifier owner, 673/48 plan value disagreement
//! names the Human and Task Controller owner, 673/49 authority and effect
//! disagreement names the Governor owner, 673/50 intent-satisfiability
//! disagreement names the Architecture and Implementation owner, 673/52
//! privacy handling names the security and privacy owner, 673/54 owner
//! recommendation carries a naming-only rationale and contract with no
//! assignment or authority, 673/55 complete analysis stays unresolved
//! without an external receipt and retains a supplied receipt verbatim,
//! 673/63 diagnostics stay bounded and redacted).
//! The remaining 3 of 68 are deferred per queue-item scope; workspace
//! admission (#969), Product Pulse, and Edge proof remain separate. Deferred: 673/53,
//! 673/58, 673/59.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use eliot_contracts::{StateFence, canonical_json_bytes, fences_match_exact, sha256_hex};
use eliot_dreamer_contracts::{
    CurationRejectionCode, FailureCausalStatus, GroundedDreamDraft, PossibleResultSchema,
    PreservationDimension, ProbeObjective, ResultTarget, ResultUpdate, ValidatedCurationItem,
    ValidatedDreamDraft, ValidationReceipt, check_fence, is_hex64_lower,
};
use eliot_epistemic_contracts::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictSet,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum positions admitted in one analysis.
pub const MAX_POSITIONS: usize = 32;
/// Minimum positions admitted in one analysis.
///
/// I13.1 and I13.2 type a conflict as a disagreement between distinct claims,
/// so a set of zero or one position holds no disagreement to analyze. This is
/// the same minimum the canonical `ConflictSet` contract enforces when the set
/// is constructed; it is named here because the denominator this cell actually
/// reads is the one it restates, and because a rule that can only be found by
/// re-reading a bare literal is a rule nobody can check.
pub const MINIMUM_CONFLICT_POSITIONS: usize = 2;
/// Maximum sources admitted in one analysis.
pub const MAX_SOURCES: usize = 64;
/// Maximum objections admitted in one analysis.
pub const MAX_OBJECTIONS: usize = 64;
/// Maximum supplied probes admitted in one analysis.
pub const MAX_PROBES: usize = 16;
/// Maximum lineage attributions admitted in one analysis.
pub const MAX_LINEAGE: usize = 64;
/// Maximum evidence strings admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle or identity field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for task, scope, and policy fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any bounded note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Expected preservation dimensions attested by every candidate.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;
/// Maximum caller-supplied typed comparisons admitted in one analysis.
pub const MAX_COMPARISONS: usize = 64;
/// Maximum caller-supplied causal claims admitted in one analysis.
pub const MAX_CAUSAL_CLAIMS: usize = 64;
/// Canonical dimensions every supplied comparison must cover exactly once.
pub const EXPECTED_COMPARISON_DIMENSIONS: usize = 8;
/// Maximum owner-issued source members admitted in one analysis.
pub const MAX_SOURCE_MEMBERS: usize = 64;
/// Maximum owner-issued causal evidence records admitted in one analysis.
pub const MAX_CAUSAL_EVIDENCE_RECORDS: usize = 64;
/// Maximum evidence envelopes bound to one causal evidence record.
pub const MAX_ENVELOPES_PER_RECORD: usize = 16;
/// Maximum retained source bytes per owner-issued source member.
pub const MAX_RETAINED_SOURCE_BYTES: usize = 65_536;
/// Maximum retained mechanism claim bytes per owner-issued causal record.
pub const MAX_MECHANISM_CLAIM_BYTES: usize = 16_384;
/// Maximum retained receipt bytes per owner-issued evidence envelope.
pub const MAX_RECEIPT_BYTES: usize = 65_536;
/// Maximum owner-issued comparison profile descriptors.
pub const MAX_PROFILE_DESCRIPTORS: usize = 8;
/// Maximum bytes for one owner-issued profile definition.
pub const MAX_PROFILE_DEFINITION_BYTES: usize = 16_384;
/// Maximum normalization rules carried by one owner-issued profile.
pub const MAX_NORMALIZATION_RULES: usize = 16;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const CONFLICT_PROOF_NOTE: &str = "a-39 candidate-only aggregation: bounded rival analysis preserved; legacy v1 comparison and causal declarations remain unverified and never qualify equality, difference, prediction, intervention, or causality; owner-record v2 relations and causal states are derived only from admitted owner source, profile, value, and evidence records and never exceed their evidence, coverage, or authority ceiling; no Concilium planning, vote tally, source acquisition, probe execution, mutation, authority, effect, store, governor, model, clock, or finish";

// ---------------------------------------------------------------------------
// Small pure helpers (no ambient clock, no allocation of authority).
// ---------------------------------------------------------------------------

/// Returns true when the value carries any control character.
fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Redacts a value to a bounded printable prefix for errors and notes.
fn redact(value: &str) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_REDACTED_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Lowercases a note without allocating authority.
fn lowered(note: &str) -> String {
    note.to_lowercase()
}

/// Returns true when the haystack contains the needle as a substring.
fn contains_marker(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

/// Returns true when any marker occurs in the lowered haystack.
fn mentions_any(lowered_haystack: &str, markers: &[&str]) -> bool {
    let mut index = 0usize;
    while index < markers.len() {
        if let Some(marker) = markers.get(index)
            && contains_marker(lowered_haystack, marker)
        {
            return true;
        }
        index = index.saturating_add(1);
    }
    false
}

/// Substrings that mark a chronology-proves-causality overreach.
const CHRONOLOGY_MARKERS: &[&str] = &["before", "earlier", "preceded", "after", "followed"];
/// Substrings that mark a causal conclusion drawn from bare order.
const CAUSAL_MARKERS: &[&str] = &[
    "therefore causes",
    "hence causes",
    "proves caus",
    "is the cause",
    "caused by order",
];

/// Returns true when the text claims bare order proves causation.
fn claims_chronology_is_causality(note: &str) -> bool {
    let low = lowered(note);
    mentions_any(&low, CHRONOLOGY_MARKERS) && mentions_any(&low, CAUSAL_MARKERS)
}

/// Returns true when the text offers count, confidence, or recency as truth.
fn claims_count_is_truth(note: &str) -> bool {
    let low = lowered(note);
    contains_marker(&low, "majority proves")
        || contains_marker(&low, "count proves")
        || contains_marker(&low, "confidence proves truth")
        || contains_marker(&low, "most recent therefore true")
        || contains_marker(&low, "newest therefore true")
        || contains_marker(&low, "model agreement proves")
}

// ---------------------------------------------------------------------------
// Public vocabulary: outcomes, dispositions, owners, inputs, outputs.
// ---------------------------------------------------------------------------

/// Terminal outcome of one conflict analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictOutcome {
    /// Bounded analysis complete; the conflict itself stays unresolved.
    Complete,
    /// Explicit partial coverage with named open members.
    Partial,
    /// The analysis path is blocked (cancelled, over-budget, unprobeable).
    Blocked,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// No analysis is offered (unsupported shape with no partial path).
    Abstention,
    /// The request is unsupported here with a boundary handoff.
    Unsupported,
    /// The request is rejected with a boundary handoff.
    Rejected,
}

impl ConflictOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Blocked => "blocked",
            Self::Stale => "stale",
            Self::Abstention => "abstention",
            Self::Unsupported => "unsupported",
            Self::Rejected => "rejected",
        }
    }
}

/// Exactly-one disposition per analyzed position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PositionDispositionKind {
    /// Live position preserved verbatim with its lineage.
    LivePreserved,
    /// Recorded minority preserved; count never weakens it.
    MinorityPreserved,
    /// Compatible residual claim preserved alongside the contradiction.
    CompatibleResidue,
    /// Superseded or refuted history retained as addressable history.
    SupersededHistory,
    /// Expected position explicitly withheld in the denominator.
    Withheld,
    /// Expected position explicitly unavailable in the denominator.
    Unavailable,
    /// Position is stale under the frozen receipt.
    Stale,
    /// Position is refuted by preserved counterevidence, retained as history.
    Refuted,
}

impl PositionDispositionKind {
    /// Returns the canonical spelling of this disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LivePreserved => "live_preserved",
            Self::MinorityPreserved => "minority_preserved",
            Self::CompatibleResidue => "compatible_residue",
            Self::SupersededHistory => "superseded_history",
            Self::Withheld => "withheld",
            Self::Unavailable => "unavailable",
            Self::Stale => "stale",
            Self::Refuted => "refuted",
        }
    }
}

/// Closed external decision-owner recommendation kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecisionOwnerKind {
    /// Evidence or source owner must supply or qualify evidence.
    EvidenceSource,
    /// Evaluator or verifier owner must check the observable.
    EvaluatorVerifier,
    /// Human or Task Controller owns the objective or value trade-off.
    HumanTaskController,
    /// Governor owns authority or effect permission.
    Governor,
    /// Architecture or Implementation owns the intent-satisfiability call.
    ArchitectureImplementation,
    /// Concilium review is recommended; this cell never launches it.
    ConciliumReview,
    /// Security or privacy owner must clear the handling boundary.
    SecurityPrivacy,
    /// No single owner can be named from the grounded evidence.
    Unknown,
    /// Multiple owners remain in conflict.
    Multiple,
}

impl DecisionOwnerKind {
    /// Returns the canonical spelling of this owner kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceSource => "evidence_source",
            Self::EvaluatorVerifier => "evaluator_verifier",
            Self::HumanTaskController => "human_task_controller",
            Self::Governor => "governor",
            Self::ArchitectureImplementation => "architecture_implementation",
            Self::ConciliumReview => "concilium_review",
            Self::SecurityPrivacy => "security_privacy",
            Self::Unknown => "unknown",
            Self::Multiple => "multiple",
        }
    }
}

/// Canonical precedence of the eight conflict kinds (I13.1 order).
pub const KIND_PRECEDENCE: [ConflictKind; 8] = [
    ConflictKind::Epistemic,
    ConflictKind::State,
    ConflictKind::Plan,
    ConflictKind::Authority,
    ConflictKind::Artifact,
    ConflictKind::Instruction,
    ConflictKind::Resource,
    ConflictKind::Architecture,
];

/// Closed policy governing one conflict analysis.
///
/// Every field is a bounded scalar or bounded text, so the whole record is data
/// and crosses a wire without a callback: this policy is a mandatory member of
/// the production Orientation carrier (`bins/eliot-dreamer`), which receives it
/// from the Governor supply channel rather than building one locally, and an
/// in-process reference cannot express that. `deny_unknown_fields` keeps a
/// decoded record from silently dropping a field this revision does not define.
///
/// Decoding proves nothing. A value read off a wire is untrusted input and
/// reaches this cell through [`analyze_conflict`], which re-proves the ORIGINAL
/// RECORDED fields of whichever instance it is called on - a non-default
/// `policy_revision`, ceilings inside their exact bounds, bounded identity
/// text, and `policy_id` equal to the item receipt's own validator policy. No
/// field is defaulted on decode and none is read from ambient state, so a
/// forged ceiling or a drifted policy identity is refused rather than admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictAnalysisPolicy {
    /// Governing policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Policy revision; zero is rejected as a defaulted binding.
    pub policy_revision: u32,
    /// Maximum positions admitted in the emitted analysis.
    pub max_positions: usize,
    /// Maximum sources admitted in the emitted analysis.
    pub max_sources: usize,
    /// Maximum objections admitted in the emitted analysis.
    pub max_objections: usize,
    /// Maximum supplied probes admitted in the emitted analysis.
    pub max_probes: usize,
    /// True selects explicit partial emission; false selects all-or-nothing.
    pub allow_partial: bool,
    /// True when the caller cancelled this analysis before emission.
    pub cancelled: bool,
    /// Explicit observation time in milliseconds, when bounded.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, when bounded.
    pub deadline_ms: Option<u64>,
    /// Bounded note naming the analysis boundary.
    pub analysis_note: String,
}

/// One source-to-lineage-root attribution supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageAttribution {
    /// Source handle attributed to a lineage root.
    pub source_handle: String,
    /// Authoritative lineage root; opaque to this cell beyond equality.
    pub lineage_root: String,
    /// False marks unknown lineage, which is unknown independence.
    pub known: bool,
}

/// One preserved objection supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppliedObjection {
    /// Stable objection identity.
    pub objection_id: String,
    /// Source holding the challenged position.
    pub target_source: String,
    /// Original objection statement, preserved verbatim.
    pub statement: String,
    /// True when the objection is grounded in admitted evidence.
    pub grounded: bool,
}

/// One supplied structured probe candidate (declaration only, never executed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppliedProbe {
    /// Stable probe identity.
    pub probe_id: String,
    /// Canonical probe objective declaration.
    pub objective: ProbeObjective,
    /// Canonical possible-result schema with the discriminating matrix.
    pub schema: PossibleResultSchema,
    /// Owner bound to the follow-up.
    pub owner_note: String,
    /// Verifier bound to the follow-up.
    pub verifier: String,
    /// Cost bound for the follow-up.
    pub cost_note: String,
    /// Risk bound for the follow-up.
    pub risk_note: String,
    /// Privacy bound for the follow-up.
    pub privacy_note: String,
    /// Effect bound for the follow-up.
    pub effect_note: String,
    /// True when the probe path is blocked (remains visible, never reserved).
    pub blocked: bool,
    /// True when the probe is over budget (remains visible, never reserved).
    pub over_budget: bool,
}

/// Separately supplied external resolution status (retained, never reissued).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalResolution {
    /// Digest of the external decision receipt.
    pub decision_digest: String,
    /// Owner that issued the external decision.
    pub decided_by: String,
    /// Bounded note naming the external decision boundary.
    pub note: String,
}

/// The eight canonical comparison dimensions of algorithm step 4, in canonical
/// order. Two claims are compared only over these typed fields; no other
/// difference is normalized, and a field that cannot be normalized stays
/// ambiguous rather than being smoothed into agreement or difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComparisonDimension {
    /// Canonical subject or entity under discussion.
    SubjectEntity,
    /// Scope, population, and environment the claim is bounded to.
    ScopePopulationEnvironment,
    /// Time window and version the claim is bounded to.
    TimeVersion,
    /// Definition, unit, and denominator the claim is measured against.
    DefinitionUnitDenominator,
    /// Precision and modality the claim asserts.
    PrecisionModality,
    /// Goal or value the claim serves.
    GoalValue,
    /// Policy, authority, and effect permission the claim assumes.
    PolicyAuthorityEffect,
    /// Factual, predictive, or causal character of the claim.
    FactualPredictiveCausal,
}

impl ComparisonDimension {
    /// Returns the canonical spelling of this dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubjectEntity => "subject_entity",
            Self::ScopePopulationEnvironment => "scope_population_environment",
            Self::TimeVersion => "time_version",
            Self::DefinitionUnitDenominator => "definition_unit_denominator",
            Self::PrecisionModality => "precision_modality",
            Self::GoalValue => "goal_value",
            Self::PolicyAuthorityEffect => "policy_authority_effect",
            Self::FactualPredictiveCausal => "factual_predictive_causal",
        }
    }
}

/// The eight canonical comparison dimensions in canonical order.
pub const COMPARISON_DIMENSIONS: [ComparisonDimension; EXPECTED_COMPARISON_DIMENSIONS] = [
    ComparisonDimension::SubjectEntity,
    ComparisonDimension::ScopePopulationEnvironment,
    ComparisonDimension::TimeVersion,
    ComparisonDimension::DefinitionUnitDenominator,
    ComparisonDimension::PrecisionModality,
    ComparisonDimension::GoalValue,
    ComparisonDimension::PolicyAuthorityEffect,
    ComparisonDimension::FactualPredictiveCausal,
];

/// The three canonical dimensions that bound a claim to its conditions.
///
/// Only an owner-proven difference on one of these can make two claims
/// compatible residue. A proven difference on any other dimension is a typed
/// difference that says nothing about the scope, time window, or definition the
/// claims were measured against, so it cannot discharge the conflict.
const CONDITION_DIMENSIONS: [ComparisonDimension; 3] = [
    ComparisonDimension::ScopePopulationEnvironment,
    ComparisonDimension::TimeVersion,
    ComparisonDimension::DefinitionUnitDenominator,
];

/// Legacy caller-declared outcome for one canonical comparison dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DimensionOutcome {
    /// The legacy caller declares the same value for both positions. This is
    /// not an owner-bound observation and cannot establish equality.
    Equal {
        /// The caller-declared value, preserved verbatim and unverified.
        value: String,
    },
    /// The legacy caller declares different values for the positions. This is
    /// not an owner-bound observation and cannot establish a difference.
    Differing {
        /// Caller-declared value for the left position, preserved verbatim.
        left: String,
        /// Caller-declared value for the right position, preserved verbatim.
        right: String,
    },
    /// The caller declares the field unnormalizable. It stays unverified and
    /// cannot be promoted to an evidence-backed relation.
    Unnormalizable {
        /// Bounded reason the field cannot be normalized.
        reason: String,
    },
}

/// One legacy caller-declared outcome for a canonical comparison dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionComparison {
    /// Which canonical dimension this entry compares.
    pub dimension: ComparisonDimension,
    /// Typed outcome for this dimension.
    pub outcome: DimensionOutcome,
}

/// Legacy version 1 caller declaration for two positions over the canonical
/// dimensions. No source bytes, revisions, owner-issued profile, or admitted
/// dimension records accompany this shape, so declarations are never
/// qualified as equality or difference. Rust callers may continue constructing
/// it for compatibility; this crate does not deserialize legacy bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppliedComparison {
    /// Source handle of the left position.
    pub left_source: String,
    /// Source handle of the right position.
    pub right_source: String,
    /// Exactly one entry per canonical dimension.
    pub dimensions: Vec<DimensionComparison>,
}

// ---------------------------------------------------------------------------
// Owner-record contract (issue #2869, algorithm steps 1-6 and 8).
//
// Every record below is CONSUMED, never acquired or upgraded, by this cell. The
// producer and the authoritative identity for each class are:
///
/// | record | producer | authoritative identity |
///// |---|---|---|
/// | [`SourceMemberRecord`] | the source owner that retained the bytes | `position_source` + `record_digest` + `source_revision` under one `state_fence` |
/// | [`OwnerComparisonProfile`] | the normalization/comparison profile owner | `profile_id` + `owner` + `definition_digest` |
/// | [`DimensionObservation`] | the profile owner, applied to one source member | `source` + `dimension` + `source_member_digest` |
/// | [`EvidenceRecord`] | the evidence-source owner | `evidence_id` + `envelope` provenance (`source_id`) + `receipt_digest` over `receipt_bytes` |
/// | [`CausalEvidenceRecord`] | the evaluator/verifier owner | `source_handle` + `mechanism.claim_id` + `mechanism.claim_digest` over `claim_bytes` + fence |
///
/// A-39 reads those identities, validates them against the item's own
/// task/scope/fence and retained bytes, and derives no stronger state than the
/// records support. It never mints, upgrades, or reissues one.
/// ---------------------------------------------------------------------------
/// One versioned source member binding a `ConflictSet` position to the
/// immutable material the source owner retained for it.
///
/// The retained bytes and the owner-recorded [`Self::record_digest`] are the
/// pair that matters: the digest is the value the owner recorded, and the bytes
/// are what it retained, so a member whose bytes do not reproduce its recorded
/// digest is refused rather than admitted as merely well-formed. This cell
/// acquires nothing; it only checks that the record it was handed is
/// self-consistent and bound to the exact position it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMemberRecord {
    /// `ConflictSet` position source handle this member is bound to.
    pub position_source: String,
    /// Authoritative owner identity that retained this material.
    pub source_owner: String,
    /// Immutable artifact or retained-handle reference for the material.
    pub retained_handle: String,
    /// Exact bytes the source owner retained for this position.
    pub retained_bytes: Vec<u8>,
    /// Canonical digest the source owner RECORDED for the retained bytes.
    ///
    /// This is the original recorded value. It is never recomputed here and
    /// substituted for the check: the retained bytes are compared against it.
    pub record_digest: String,
    /// Source revision or snapshot the material was read at.
    pub source_revision: String,
    /// Immutable snapshot identity behind the revision.
    pub source_snapshot: String,
    /// Task the member was admitted under.
    pub task_id: String,
    /// `WorkScope` the member was admitted under.
    pub scope_id: String,
    /// Fence the member was admitted under.
    pub state_fence: StateFence,
}

impl SourceMemberRecord {
    /// Validates the intrinsic shape and the recorded-digest/retained-bytes
    /// binding of one source member.
    ///
    /// The digest is the owner-recorded value; the retained bytes must reproduce
    /// it. A member that merely carries a well-formed digest is not admitted.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.position_source, "source_member.position_source")?;
        check_handle(&self.source_owner, "source_member.source_owner")?;
        check_handle(&self.retained_handle, "source_member.retained_handle")?;
        check_bounded_text(
            &self.source_revision,
            "source_member.source_revision",
            MAX_SCOPE_BYTES,
        )?;
        check_bounded_text(
            &self.source_snapshot,
            "source_member.source_snapshot",
            MAX_SCOPE_BYTES,
        )?;
        check_bounded_text(&self.task_id, "source_member.task_id", MAX_SCOPE_BYTES)?;
        check_bounded_text(&self.scope_id, "source_member.scope_id", MAX_SCOPE_BYTES)?;
        check_digest(&self.record_digest, "source_member.record_digest")?;
        if self.retained_bytes.is_empty() || self.retained_bytes.len() > MAX_RETAINED_SOURCE_BYTES {
            return Err(ConflictAnalysisError::Bounds {
                phase: "source_member.retained_bytes".to_owned(),
                detail: "retained source bytes are empty or exceed their ceiling".to_owned(),
            });
        }
        if sha256_hex(&self.retained_bytes) != self.record_digest {
            return Err(ConflictAnalysisError::Digest {
                detail: "retained source bytes do not reproduce the recorded digest".to_owned(),
            });
        }
        check_fence(&self.state_fence).map_err(|err| receipt_err(&err.to_string()))?;
        Ok(())
    }
}

/// How an owner-issued profile records a dimension it cannot resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DispositionKind {
    /// The owner records the field as unnormalizable under this profile.
    Unnormalizable,
    /// The owner records the field as outside this profile's support.
    Unsupported,
}

impl DispositionKind {
    /// Returns the canonical spelling of this disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unnormalizable => "unnormalizable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One owner-issued comparison profile.
///
/// The profile is the single authority for normalization: it binds its owner,
/// schema revision, canonical definition bytes and their recorded digest, all
/// eight canonical descriptors, the normalization rules, and the disposition for
/// both a missing and an unsupported dimension. A caller cannot submit an
/// `Equal`/`Differing` verdict as authority; the profile only says how a value
/// is read, and [`OwnerComparison`] carries the observed values it read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerComparisonProfile {
    /// Profile identity as issued by its owner.
    pub profile_id: String,
    /// Authoritative owner identity that issued this profile.
    pub owner: String,
    /// Profile schema revision; never defaulted.
    pub schema_revision: u32,
    /// Canonical definition bytes as issued by the owner.
    pub definition_bytes: Vec<u8>,
    /// Digest the owner RECORDED for the definition bytes.
    pub definition_digest: String,
    /// The eight canonical descriptors, in [`COMPARISON_DIMENSIONS`] order.
    pub descriptors: Vec<ComparisonDimension>,
    /// Owner-issued normalization rules.
    pub normalization_rules: Vec<String>,
    /// Disposition for a dimension whose value is missing.
    pub missing_disposition: DispositionKind,
    /// Disposition for a dimension this profile does not support.
    pub unsupported_disposition: DispositionKind,
}

impl OwnerComparisonProfile {
    /// Validates the profile's owner, revision, definition binding, and full
    /// canonical descriptor coverage.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.profile_id, "profile.profile_id")?;
        check_handle(&self.owner, "profile.owner")?;
        if self.schema_revision == 0 {
            return Err(ConflictAnalysisError::Policy {
                detail: "profile schema_revision must be explicit, not defaulted".to_owned(),
            });
        }
        check_digest(&self.definition_digest, "profile.definition_digest")?;
        if self.definition_bytes.is_empty()
            || self.definition_bytes.len() > MAX_PROFILE_DEFINITION_BYTES
        {
            return Err(ConflictAnalysisError::Bounds {
                phase: "profile.definition_bytes".to_owned(),
                detail: "profile definition bytes are empty or exceed their ceiling".to_owned(),
            });
        }
        if sha256_hex(&self.definition_bytes) != self.definition_digest {
            return Err(ConflictAnalysisError::Digest {
                detail: "profile definition bytes do not reproduce the recorded digest".to_owned(),
            });
        }
        if self.descriptors.len() != EXPECTED_COMPARISON_DIMENSIONS
            || self.descriptors.len() > MAX_PROFILE_DESCRIPTORS
        {
            return Err(ConflictAnalysisError::Denominator {
                detail: format!(
                    "an owner-issued profile must carry exactly {EXPECTED_COMPARISON_DIMENSIONS} canonical descriptors"
                ),
            });
        }
        for (index, dimension) in COMPARISON_DIMENSIONS.iter().enumerate() {
            if self.descriptors[index] != *dimension {
                return Err(ConflictAnalysisError::Denominator {
                    detail: format!(
                        "profile descriptor {index} is {} rather than {}",
                        self.descriptors[index].as_str(),
                        dimension.as_str()
                    ),
                });
            }
        }
        if self.normalization_rules.is_empty()
            || self.normalization_rules.len() > MAX_NORMALIZATION_RULES
        {
            return Err(ConflictAnalysisError::Denominator {
                detail: "an owner-issued profile must carry its normalization rules".to_owned(),
            });
        }
        for rule in &self.normalization_rules {
            check_bounded_text(rule, "profile.normalization_rule", MAX_NOTE_BYTES)?;
        }
        Ok(())
    }
}

/// One observed dimension value, bound to the source member and descriptor it
/// was read from.
///
/// The observation names its source and that source's member digest, so a value
/// cannot be re-attached to a different position, and it names the canonical
/// descriptor it answers, so a value cannot answer a dimension it was not read
/// under. It is a single-source value, never a verdict about a pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionObservation {
    /// Source handle whose member this value was read from.
    pub source: String,
    /// Owner-issued [`SourceMemberRecord::record_digest`] of that member.
    pub source_member_digest: String,
    /// Canonical dimension this value answers.
    pub dimension: ComparisonDimension,
    /// Descriptor spelling this value was read under.
    pub descriptor: String,
    /// Normalized value the profile owner read from the member.
    pub value: String,
}

impl DimensionObservation {
    /// Validates one observed dimension value's shape and member binding.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.source, "observation.source")?;
        check_digest(
            &self.source_member_digest,
            "observation.source_member_digest",
        )?;
        check_bounded_text(&self.descriptor, "observation.descriptor", MAX_TEXT_BYTES)?;
        check_bounded_text(&self.value, "observation.value", MAX_TEXT_BYTES)?;
        Ok(())
    }
}

/// One owner-issued evidence envelope joined to its retained material and
/// receipt through canonical digest identity.
///
/// There is no `trusted`, `verified`, or `complete` Boolean here. Authority,
/// freshness, coverage, epistemic status, and assertability are read from the
/// envelope itself and validated by its own contract, so a caller cannot
/// assert a ceiling it did not earn.
///
/// Two identities on this record are checked against the envelope's OWN
/// recorded content rather than against a parallel caller field, because both
/// otherwise carry a verdict as a pair of free strings. `owner` must equal the
/// envelope's own `provenance.source_id`, the source it records as having
/// produced or contained it; without that the "the evaluator verdict belongs to
/// the control owner that issued it" rule would compare
/// [`CausalEvidenceRecord::control`]'s owner string against
/// [`EvidenceRecord::owner`], which is the same caller supplying both sides.
/// `receipt_digest` must equal the digest the retained receipt bytes reproduce,
/// the recorded-digest/retained-bytes pairing
/// [`SourceMemberRecord::validate`] already applies to a source member and
/// [`MechanismBinding::validate`] to a declaration; a receipt identity matching
/// no retained receipt is a string, not a receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Evidence identity as issued by its owner.
    pub evidence_id: String,
    /// Authoritative owner identity that captured this evidence; it must equal
    /// the source identity the envelope itself records.
    pub owner: String,
    /// The normalized evidence envelope.
    pub envelope: EvidenceEnvelope,
    /// Canonical digest of the retained material this evidence is tied to.
    pub material_digest: String,
    /// Canonical digest the receipt owner RECORDED for the retained receipt.
    pub receipt_digest: String,
    /// Exact bytes the receipt owner retained for the issuing receipt.
    pub receipt_bytes: Vec<u8>,
}

impl EvidenceRecord {
    /// Validates the envelope intrinsically plus the material, issuer, and
    /// receipt bindings.
    ///
    /// The envelope's own contract supplies the status, authority, and
    /// assertability invariants, including that `Verified` carries an actual
    /// verification binding. The receipt digest is the value the owner recorded;
    /// the retained bytes are compared against it and are never recomputed here
    /// and substituted for the check.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.evidence_id, "evidence.evidence_id")?;
        check_handle(&self.owner, "evidence.owner")?;
        check_digest(&self.material_digest, "evidence.material_digest")?;
        check_digest(&self.receipt_digest, "evidence.receipt_digest")?;
        self.envelope
            .validate()
            .map_err(|err| ConflictAnalysisError::Binding {
                field: "evidence.envelope".to_owned(),
                detail: redact(&err.to_string()),
            })?;
        if self.owner != self.envelope.provenance.source_id.as_str() {
            return Err(ConflictAnalysisError::Binding {
                field: "evidence.owner".to_owned(),
                detail: "the named owner is not the source identity the envelope records"
                    .to_owned(),
            });
        }
        if self.receipt_bytes.is_empty() || self.receipt_bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ConflictAnalysisError::Bounds {
                phase: "evidence.receipt_bytes".to_owned(),
                detail: "retained receipt bytes are empty or exceed their ceiling".to_owned(),
            });
        }
        if sha256_hex(&self.receipt_bytes) != self.receipt_digest {
            return Err(ConflictAnalysisError::Digest {
                detail: "retained receipt bytes do not reproduce the recorded digest".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns whether this record's authority can qualify an evidence-bound
    /// state.
    ///
    /// Model interpretation and heuristic static evidence keep their lower
    /// authority ceiling: they are preserved and may support a review, but they
    /// never promote a declaration to an evidence-qualified state. A stale,
    /// contested, superseded, or rejected envelope likewise qualifies nothing.
    ///
    /// The envelope's OWN recorded coverage is read here as well, which is the
    /// fifth dimension the type documentation above already claimed was read
    /// from the envelope and which no code path previously read. I21.6 makes
    /// `complete_scope` the only basis on which a scoped absence may be
    /// claimed, and I5.16 makes an absent or unestablished coverage record
    /// `unknown` rather than unrestricted, so an envelope recording partial,
    /// not-applicable, or unknown coverage never qualifies. This is the owner
    /// RECORDED value carried by the envelope, not a field of this record, so
    /// there is no caller-side value to raise it with.
    #[must_use]
    pub fn qualifies(&self) -> bool {
        matches!(
            self.envelope.authority,
            EvidenceAuthority::SourceIdentity
                | EvidenceAuthority::CompilerLanguage
                | EvidenceAuthority::CompilerDerivedSemantics
                | EvidenceAuthority::DeterministicRuntimeTest
        ) && matches!(
            self.envelope.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        ) && matches!(
            self.envelope.status,
            EpistemicStatus::Supported | EpistemicStatus::Verified
        ) && self.envelope.assertability == Assertability::Assertable
            && self.envelope.coverage == EvidenceCoverage::CompleteForScope
    }
}

/// Owner-issued binding of a mechanism claim to the revision it was read at.
///
/// The claim's own retained bytes are what make this a binding rather than a
/// pointer. `claim_digest` is the value the owner RECORDED for those bytes, and
/// [`CausalEvidenceRecord::validate`] requires the bytes to reproduce it — the
/// same recorded-digest/retained-bytes pairing [`SourceMemberRecord::validate`]
/// already applies to a source member, applied here to the declaration. Without
/// that pairing the claim's verbatim text rides along as a 64-character string
/// that could stand for any text at all, and the source's own declared claim
/// would not be the claim this cell preserves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismBinding {
    /// Mechanism claim identity as issued by its owner.
    pub claim_id: String,
    /// Source revision the mechanism claim was read at.
    pub source_revision: String,
    /// Exact bytes the owner retained for the mechanism claim.
    pub claim_bytes: Vec<u8>,
    /// Canonical digest the owner RECORDED for the mechanism claim.
    ///
    /// This is the original recorded value. It is never recomputed here and
    /// substituted for the check: the retained bytes are compared against it.
    pub claim_digest: String,
}

impl MechanismBinding {
    /// Validates the mechanism claim's shape and its recorded-digest/retained-
    /// bytes binding.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.claim_id, "causal_evidence.mechanism.claim_id")?;
        check_bounded_text(
            &self.source_revision,
            "causal_evidence.mechanism.source_revision",
            MAX_SCOPE_BYTES,
        )?;
        check_digest(&self.claim_digest, "causal_evidence.mechanism.claim_digest")?;
        if self.claim_bytes.is_empty() || self.claim_bytes.len() > MAX_MECHANISM_CLAIM_BYTES {
            return Err(ConflictAnalysisError::Bounds {
                phase: "causal_evidence.mechanism.claim_bytes".to_owned(),
                detail: "retained mechanism claim bytes are empty or exceed their ceiling"
                    .to_owned(),
            });
        }
        if sha256_hex(&self.claim_bytes) != self.claim_digest {
            return Err(ConflictAnalysisError::Digest {
                detail: "retained mechanism claim bytes do not reproduce the recorded digest"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

/// Observed status of an owner-issued falsifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FalsifierStatus {
    /// The falsifier was specified but not observed.
    Unobserved,
    /// The falsifier ran and the claim survived it.
    Consistent,
    /// The falsifier ran and refuted the claim.
    Inconsistent,
}

impl FalsifierStatus {
    /// Returns the canonical spelling of this falsifier status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unobserved => "unobserved",
            Self::Consistent => "consistent",
            Self::Inconsistent => "inconsistent",
        }
    }
}

/// Owner-issued falsifier specification plus its observed status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FalsifierBinding {
    /// Bounded falsifier specification.
    pub specification: String,
    /// Status the owner observed.
    pub observed: FalsifierStatus,
    /// Evidence identity the observation is traced to.
    pub evidence_id: String,
}

/// Result a competent evaluator or verifier returned for a matched control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvaluatorResult {
    /// A competent evaluator/verifier returned a usable result.
    Competent,
    /// The evaluator is present but not competent for this claim.
    Unqualified,
    /// No evaluator or verifier result exists.
    Absent,
}

impl EvaluatorResult {
    /// Returns the canonical spelling of this evaluator result.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Competent => "competent",
            Self::Unqualified => "unqualified",
            Self::Absent => "absent",
        }
    }
}

/// Owner-issued matched control and the evaluator/verifier result for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlBinding {
    /// Matched control identity.
    pub control_id: String,
    /// Owner that issued the control.
    pub owner: String,
    /// Result a competent evaluator or verifier returned.
    pub evaluator_result: EvaluatorResult,
    /// Evidence identity the result is traced to.
    pub evidence_id: String,
}

/// Owner-issued intervention execution and its receipt.
///
/// The receipt is the proof that the execution happened, so it is read as the
/// receipt of a retained evidence envelope rather than as a digest string:
/// [`CausalEvidenceRecord::validate`] refuses a record whose receipt matches no
/// retained envelope, and that envelope's own `receipt_digest` is in turn
/// refused unless the receipt bytes its owner retained reproduce it. Without
/// both joins an intervention would be supportable on any well-formed
/// 64-character digest, which is precisely the "two hashes look right"
/// substitution the owner contract exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterventionBinding {
    /// Execution identity of the intervention.
    pub execution_id: String,
    /// Canonical digest of the receipt proving that execution.
    pub receipt_digest: String,
}

/// Rival/confounder denominator with its own independent completeness check.
///
/// Completeness is decided against the retained evidence records, never against
/// a second copy of the caller's own expected list: every expected rival must
/// appear in `observed`, no member may be both observed and omitted, and
/// [`EvidenceCoverage::CompleteForScope`] cannot coexist with an omission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RivalDenominator {
    /// Rival/confounder handles the owner set out to cover.
    pub expected: Vec<String>,
    /// Rival/confounder handles the owner actually observed.
    pub observed: Vec<String>,
    /// Handles the owner did not cover, named explicitly.
    pub omitted: Vec<String>,
    /// Owner-declared coverage of this denominator.
    pub coverage: EvidenceCoverage,
}

impl RivalDenominator {
    /// Validates the denominator against the independent retained evidence set.
    ///
    /// `evidence_ids` is the set of evidence identities actually retained for
    /// this record. An observed rival that no retained evidence names is a
    /// coverage shortfall, and complete coverage is refused outright.
    pub fn validate(&self, evidence_ids: &[String]) -> Result<(), ConflictAnalysisError> {
        bound_list_length("rivals.expected", self.expected.len(), MAX_EVIDENCE_ITEMS)?;
        bound_list_length("rivals.observed", self.observed.len(), MAX_EVIDENCE_ITEMS)?;
        bound_list_length("rivals.omitted", self.omitted.len(), MAX_EVIDENCE_ITEMS)?;
        for handle in self
            .expected
            .iter()
            .chain(self.observed.iter())
            .chain(self.omitted.iter())
        {
            check_handle(handle, "rivals.handle")?;
        }
        for handle in &self.omitted {
            if self.observed.contains(handle) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: "a rival cannot be both observed and omitted".to_owned(),
                });
            }
            if !self.expected.contains(handle) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: "an omitted rival is not in the expected denominator".to_owned(),
                });
            }
        }
        for handle in &self.observed {
            if !evidence_ids.contains(handle) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: format!(
                        "observed rival {} is not backed by retained evidence",
                        redact(handle)
                    ),
                });
            }
            if !self.expected.contains(handle) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: "an observed rival is not in the expected denominator".to_owned(),
                });
            }
        }
        if self.coverage == EvidenceCoverage::CompleteForScope && !self.omitted.is_empty() {
            return Err(ConflictAnalysisError::Denominator {
                detail: "complete rival coverage cannot coexist with an omission".to_owned(),
            });
        }
        if self.coverage == EvidenceCoverage::CompleteForScope {
            for handle in &self.expected {
                if !self.observed.contains(handle) {
                    return Err(ConflictAnalysisError::Denominator {
                        detail: format!(
                            "complete rival coverage omits expected member {}",
                            redact(handle)
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns the coverage this cell derives from the retained evidence,
    /// independent of the coverage the owner declared.
    #[must_use]
    pub fn derived_coverage(&self) -> EvidenceCoverage {
        if self.observed.len() == self.expected.len()
            && self
                .expected
                .iter()
                .all(|handle| self.observed.contains(handle))
            && self.omitted.is_empty()
        {
            EvidenceCoverage::CompleteForScope
        } else if self.observed.is_empty() {
            EvidenceCoverage::Unknown
        } else {
            EvidenceCoverage::PartialForScope
        }
    }
}

/// One owner-issued causal or predictive evidence record.
///
/// The declared state is preserved verbatim and separately from the assessment
/// this cell computes, and it is the source's own text: `mechanism.claim_bytes`
/// must reproduce the digest the owner recorded for the claim, so the
/// declaration this cell carries is the one the source owner retained rather
/// than a label attached to a well-formed digest. Prediction support,
/// intervention execution, and causal attribution stay distinct: this record can
/// carry all three and still promote only the one the declaration claims.
///
/// Two coverage denominators hang off this record and neither substitutes for
/// the other: [`Self::rivals`], the rival/confounder denominator, and the
/// retained evidence set itself, whose coverage
/// [`Self::derived_evidence_coverage`] derives from the envelopes' own recorded
/// coverage. Every leg this record must support — the falsifier observation,
/// the control's evaluator result, and the intervention receipt when one is
/// claimed — is joined to a retained envelope, the control's verdict belongs to
/// the control owner that issued it, and no envelope may join material or
/// receipt it does not name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalEvidenceRecord {
    /// Source handle holding the claim.
    pub source_handle: String,
    /// State the source declared, preserved verbatim.
    pub declared_state: CausalClaimState,
    /// Mechanism claim identity and the revision it was read at.
    pub mechanism: MechanismBinding,
    /// Falsifier specification and its observed status.
    pub falsifier: FalsifierBinding,
    /// Matched control and the competent evaluator/verifier result.
    pub control: ControlBinding,
    /// Intervention execution and receipt, when one exists.
    pub intervention: Option<InterventionBinding>,
    /// Rival/confounder denominator with its omissions and coverage.
    pub rivals: RivalDenominator,
    /// Retained evidence envelopes joined to material and receipts.
    pub evidence: Vec<EvidenceRecord>,
    /// Task the record was admitted under.
    pub task_id: String,
    /// `WorkScope` the record was admitted under.
    pub scope_id: String,
    /// Fence the record was admitted under.
    pub state_fence: StateFence,
}

impl CausalEvidenceRecord {
    /// Validates the record's shape, evidence, and rival denominator.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.source_handle, "causal_evidence.source_handle")?;
        self.mechanism.validate()?;
        check_bounded_text(
            &self.falsifier.specification,
            "causal_evidence.falsifier.specification",
            MAX_TEXT_BYTES,
        )?;
        check_handle(
            &self.falsifier.evidence_id,
            "causal_evidence.falsifier.evidence_id",
        )?;
        check_handle(
            &self.control.control_id,
            "causal_evidence.control.control_id",
        )?;
        check_handle(&self.control.owner, "causal_evidence.control.owner")?;
        check_handle(
            &self.control.evidence_id,
            "causal_evidence.control.evidence_id",
        )?;
        if let Some(intervention) = &self.intervention {
            check_handle(
                &intervention.execution_id,
                "causal_evidence.intervention.execution_id",
            )?;
            check_digest(
                &intervention.receipt_digest,
                "causal_evidence.intervention.receipt_digest",
            )?;
        }
        check_bounded_text(&self.task_id, "causal_evidence.task_id", MAX_SCOPE_BYTES)?;
        check_bounded_text(&self.scope_id, "causal_evidence.scope_id", MAX_SCOPE_BYTES)?;
        check_fence(&self.state_fence).map_err(|err| receipt_err(&err.to_string()))?;
        bound_list_length(
            "causal_evidence.evidence",
            self.evidence.len(),
            MAX_ENVELOPES_PER_RECORD,
        )?;
        let mut evidence_ids: Vec<String> = Vec::with_capacity(self.evidence.len());
        let mut receipt_digests: Vec<String> = Vec::with_capacity(self.evidence.len());
        for record in &self.evidence {
            record.validate()?;
            if evidence_ids.contains(&record.evidence_id) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: "duplicate causal evidence identity".to_owned(),
                });
            }
            evidence_ids.push(record.evidence_id.clone());
            receipt_digests.push(record.receipt_digest.clone());
        }
        if !evidence_ids.contains(&self.falsifier.evidence_id) {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.falsifier.evidence_id".to_owned(),
                detail: "falsifier observation is not traced to retained evidence".to_owned(),
            });
        }
        if !evidence_ids.contains(&self.control.evidence_id) {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.control.evidence_id".to_owned(),
                detail: "evaluator result is not traced to retained evidence".to_owned(),
            });
        }
        // The competent/unqualified/absent verdict is the CONTROL OWNER's own
        // statement about a matched control, so the envelope carrying it has to
        // be one that same owner issued. Naming an evaluator handle and pairing
        // it with any retained envelope would otherwise make `Competent` a
        // caller-set field with a handle attached rather than a matched control
        // backed by a competent evaluator's own record. The comparison below is
        // only that comparison because `EvidenceRecord::validate` already
        // required the envelope's `owner` to equal the source identity the
        // envelope itself records, so this joins an owner identity to an
        // owner-issued record rather than one caller string to another.
        if let Some(control_evidence) = self
            .evidence
            .iter()
            .find(|record| record.evidence_id == self.control.evidence_id)
            && control_evidence.owner != self.control.owner
        {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.control.owner".to_owned(),
                detail: "the evaluator result is not an envelope issued by the named control owner"
                    .to_owned(),
            });
        }
        // An intervention execution is proven by the receipt that owner
        // issued, so the receipt is read as that receipt rather than as a
        // well-formed digest. A digest matching no retained envelope is the
        // same unbound string the other two legs refuse: without this join an
        // intervention state would be reachable on any 64 hex characters. The
        // envelope's own `receipt_digest` is itself reproduced by the receipt
        // bytes `EvidenceRecord::validate` requires, so the matched receipt is
        // a retained receipt rather than another well-formed digest.
        if let Some(intervention) = &self.intervention
            && !receipt_digests.contains(&intervention.receipt_digest)
        {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.intervention.receipt_digest".to_owned(),
                detail: "intervention receipt is not the receipt of a retained evidence envelope"
                    .to_owned(),
            });
        }
        self.rivals.validate(&evidence_ids)
    }

    /// Returns the coverage this record's own retained evidence set derives,
    /// independent of the rival/confounder denominator.
    ///
    /// The expected set here is NOT a second copy of a caller-declared list: it
    /// is the coverage the retained envelopes themselves RECORD, and the members
    /// are the envelopes this record already had to prove. Declaring fewer or
    /// fewer-named members therefore cannot produce a complete set, which is the
    /// same independence [`RivalDenominator::derived_coverage`] relies on and the
    /// same rule the comparison cell applies against the canonical eight
    /// dimensions. The two cells stay separate: complete causal evidence with an
    /// incomplete rival denominator is still an incomplete causal claim, and the
    /// reverse holds too.
    ///
    /// An empty set is [`EvidenceCoverage::Unknown`] (I5.16: an absent coverage
    /// record means `unknown`, not unrestricted/complete), a set that holds any
    /// complete or partial member but is not wholly complete is
    /// [`EvidenceCoverage::PartialForScope`], and only a set every member of
    /// which records complete coverage is
    /// [`EvidenceCoverage::CompleteForScope`].
    #[must_use]
    pub fn derived_evidence_coverage(&self) -> EvidenceCoverage {
        if self.evidence.is_empty() {
            return EvidenceCoverage::Unknown;
        }
        if self
            .evidence
            .iter()
            .all(|record| record.envelope.coverage == EvidenceCoverage::CompleteForScope)
        {
            return EvidenceCoverage::CompleteForScope;
        }
        if self.evidence.iter().any(|record| {
            matches!(
                record.envelope.coverage,
                EvidenceCoverage::CompleteForScope | EvidenceCoverage::PartialForScope
            )
        }) {
            return EvidenceCoverage::PartialForScope;
        }
        EvidenceCoverage::Unknown
    }
}

/// One owner-issued comparison admitted under a single owner-issued profile.
///
/// The pair carries its source commitments and the observed values for both
/// sources; the relation itself is DERIVED here from those values. A caller
/// supplies no verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerComparison {
    /// Lexicographically lesser source handle of the pair.
    pub first_source: String,
    /// Owner-issued commitment for `first_source`.
    pub first_commitment: SourceRecordCommitment,
    /// Lexicographically greater source handle of the pair.
    pub second_source: String,
    /// Owner-issued commitment for `second_source`.
    pub second_commitment: SourceRecordCommitment,
    /// The single owner-issued profile both sources were read under.
    pub profile: OwnerComparisonProfile,
    /// Observed values, one per source per canonical dimension.
    pub observations: Vec<DimensionObservation>,
    /// Dimensions this profile recorded as unnormalizable.
    pub unnormalizable_dimensions: Vec<ComparisonDimension>,
    /// Dimensions this profile recorded as unsupported.
    pub unsupported_dimensions: Vec<ComparisonDimension>,
}

impl OwnerComparison {
    /// Validates the pair's orientation, profile, commitments, and observations.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        check_handle(&self.first_source, "owner_comparison.first_source")?;
        check_handle(&self.second_source, "owner_comparison.second_source")?;
        if self.first_source >= self.second_source {
            return Err(ConflictAnalysisError::Binding {
                field: "owner_comparison.order".to_owned(),
                detail: "owner comparison requires first_source < second_source".to_owned(),
            });
        }
        check_commitment_binding(
            &self.first_commitment,
            &self.first_source,
            "owner_comparison.first",
        )?;
        check_commitment_binding(
            &self.second_commitment,
            &self.second_source,
            "owner_comparison.second",
        )?;
        self.profile.validate()?;
        for commitment in [&self.first_commitment, &self.second_commitment] {
            if commitment.profile() != self.profile.profile_id {
                return Err(ConflictAnalysisError::Binding {
                    field: "owner_comparison.profile".to_owned(),
                    detail: "a source commitment names a different profile".to_owned(),
                });
            }
            if commitment.profile_digest() != self.profile.definition_digest {
                return Err(ConflictAnalysisError::Binding {
                    field: "owner_comparison.profile_digest".to_owned(),
                    detail: "a source commitment names a different profile revision".to_owned(),
                });
            }
        }
        self.validate_observations()
    }

    /// Validates that every canonical dimension has one value from each source,
    /// each bound to that source's committed member digest.
    fn validate_observations(&self) -> Result<(), ConflictAnalysisError> {
        let expected = EXPECTED_COMPARISON_DIMENSIONS * 2;
        bound_list_length(
            "owner_comparison.observations",
            self.observations.len(),
            expected,
        )?;
        if self.observations.len() != expected {
            return Err(ConflictAnalysisError::Denominator {
                detail: format!(
                    "an owner comparison must carry {expected} observed values, one per source per dimension"
                ),
            });
        }
        for entry in &self.observations {
            entry.validate()?;
            if entry.source != self.first_source && entry.source != self.second_source {
                return Err(ConflictAnalysisError::Binding {
                    field: "owner_comparison.observation.source".to_owned(),
                    detail: "an observation names a source outside this pair".to_owned(),
                });
            }
            if entry.dimension.as_str() != entry.descriptor {
                return Err(ConflictAnalysisError::Binding {
                    field: "owner_comparison.observation.descriptor".to_owned(),
                    detail: format!(
                        "observation descriptor {} does not answer dimension {}",
                        entry.descriptor,
                        entry.dimension.as_str()
                    ),
                });
            }
            let commitment = if entry.source == self.first_source {
                &self.first_commitment
            } else {
                &self.second_commitment
            };
            if entry.source_member_digest != commitment.record_digest() {
                return Err(ConflictAnalysisError::Binding {
                    field: "owner_comparison.observation.source_member_digest".to_owned(),
                    detail: format!(
                        "observation for {} names a different member revision than the commitment",
                        redact(&entry.source)
                    ),
                });
            }
        }
        for dimension in COMPARISON_DIMENSIONS {
            for source in [&self.first_source, &self.second_source] {
                let matches = self
                    .observations
                    .iter()
                    .filter(|entry| entry.dimension == dimension && entry.source == *source)
                    .count();
                if matches != 1 {
                    return Err(ConflictAnalysisError::Denominator {
                        detail: format!(
                            "dimension {} must carry exactly one value from each source",
                            dimension.as_str()
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns the value this source contributed for one canonical dimension.
    #[must_use]
    pub fn value_for(&self, source: &str, dimension: ComparisonDimension) -> Option<&str> {
        self.observations
            .iter()
            .find(|entry| entry.dimension == dimension && entry.source == source)
            .map(|entry| entry.value.as_str())
    }
}

/// Owner-issued comparison and causal evidence bound to one `ConflictSet`.
///
/// These are the records production wiring must supply. A-39 consumes them
/// exactly as it consumes legacy declarations: it validates them against the
/// item's own task/scope/fence and the retained bytes, derives the strongest
/// state they support, and never acquires or upgrades one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnerRecords {
    /// Versioned source members, one per admitted position.
    pub source_members: Vec<SourceMemberRecord>,
    /// Owner-issued comparisons admitted under one profile each.
    pub comparisons: Vec<OwnerComparison>,
    /// Owner-issued causal and predictive evidence records.
    pub causal_evidence: Vec<CausalEvidenceRecord>,
}

/// Commitment binding one source handle to the record and profile it names.
///
/// This is a POINTER, not the owner evidence. Its own constructor checks only
/// that the handle and the two digests are well formed, and private fields do
/// not make a string constructor into an owner boundary: a well-formed
/// commitment establishes nothing by itself. What carries the authority is the
/// pair of records it points at — the [`SourceMemberRecord`] whose retained
/// bytes must reproduce the digest this commitment names, and the
/// [`OwnerComparisonProfile`] whose definition bytes must reproduce the profile
/// digest. [`check_owner_comparison_members`] and
/// [`OwnerComparison::validate`] are what turn a pointer into a binding; a
/// commitment naming a digest no retained member records is refused as stale
/// or conflicting rather than read as current evidence.
///
/// The commitment carries the handle it is issued for, so it cannot be detached
/// from its source and re-attached to another. Normalizing a comparison pair
/// moves a source and its commitment as one unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRecordCommitment {
    source: String,
    record_digest: String,
    profile: String,
    profile_digest: String,
}

impl SourceRecordCommitment {
    /// Declares the commitment for one source handle.
    ///
    /// This constructor checks SHAPE ONLY: a handle, a record digest, a profile
    /// handle, and a profile digest. It performs no I/O, reads no retained
    /// bytes, and admits no owner; a value that passes here is a pointer, and
    /// it becomes a binding only when [`check_owner_comparison_members`] finds a
    /// [`SourceMemberRecord`] recording that exact digest and
    /// [`OwnerComparison::validate`] finds an [`OwnerComparisonProfile`] whose
    /// definition bytes reproduce `profile_digest`. `profile` names the
    /// owner-issued comparison profile the record was admitted under; a
    /// commitment without both digests is refused rather than admitted as
    /// unverified.
    pub fn new(
        source: &str,
        record_digest: &str,
        profile: &str,
        profile_digest: &str,
    ) -> Result<Self, ConflictAnalysisError> {
        check_handle(source, "commitment.source")?;
        check_digest(record_digest, "commitment.record_digest")?;
        check_handle(profile, "commitment.profile")?;
        check_digest(profile_digest, "commitment.profile_digest")?;
        Ok(Self {
            source: source.to_owned(),
            record_digest: record_digest.to_owned(),
            profile: profile.to_owned(),
            profile_digest: profile_digest.to_owned(),
        })
    }

    /// Source handle this commitment is issued for.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Digest of the owner-issued source record.
    #[must_use]
    pub fn record_digest(&self) -> &str {
        &self.record_digest
    }

    /// Owner-issued comparison profile the record was admitted under.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Digest of that comparison profile.
    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }
}

/// One canonical dimension outcome whose value stays coupled to its source.
///
/// `first_value` belongs to [`CanonicalComparisonPair::first_source`] and
/// `second_value` belongs to [`CanonicalComparisonPair::second_source`]. The two
/// values are never ordered independently of the sources that supplied them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalDimensionOutcome {
    /// Both positions declare the same value. The compared source identities
    /// stay bound by the enclosing pair.
    Equal {
        /// The value both positions declare.
        value: String,
    },
    /// The positions declare different values, each coupled to its own source.
    Differing {
        /// Value supplied by the pair's first source.
        first_value: String,
        /// Value supplied by the pair's second source.
        second_value: String,
    },
    /// The field cannot be normalized. The reason stays bound to this exact
    /// pair, profile and dimension.
    Unnormalizable {
        /// Bounded reason the field cannot be normalized.
        reason: String,
    },
}

/// One canonical dimension of an admitted comparison pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalDimensionEntry {
    /// Which canonical dimension this entry compares.
    pub dimension: ComparisonDimension,
    /// Outcome whose values are coupled to the pair's ordered sources.
    pub outcome: CanonicalDimensionOutcome,
}

/// One admitted comparison in its single canonical orientation.
///
/// `first_source` is the lexicographically lesser of the two handles, under the
/// same ordering the unordered pair key applies, so pair identity and canonical
/// orientation cannot disagree. Orientation is a property of this value and
/// never of the caller's field order: the mirrored declarations `A/B` carrying
/// `(a,b)` and `B/A` carrying `(b,a)` both normalize to the same pair, while
/// swapping the handles without their values does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalComparisonPair {
    /// Lexicographically lesser source handle of the pair.
    pub first_source: String,
    /// Owner-issued commitment for `first_source`; it travels with that source.
    pub first_source_commitment: SourceRecordCommitment,
    /// Lexicographically greater source handle of the pair.
    pub second_source: String,
    /// Owner-issued commitment for `second_source`; it travels with that source.
    pub second_source_commitment: SourceRecordCommitment,
    /// One entry per canonical dimension, in [`COMPARISON_DIMENSIONS`] order.
    pub dimensions: Vec<CanonicalDimensionEntry>,
}

/// Confirms one commitment is bound to the position it is supplied for.
///
/// A commitment carries the handle it was issued for, so a mismatch means the
/// evidence names a different position than the one being admitted.
fn check_commitment_binding(
    commitment: &SourceRecordCommitment,
    source: &str,
    field: &str,
) -> Result<(), ConflictAnalysisError> {
    if commitment.source() == source {
        return Ok(());
    }
    Err(ConflictAnalysisError::Binding {
        field: format!("{field}_commitment"),
        detail: format!(
            "commitment names source {} but is bound to comparison position {}",
            redact(commitment.source()),
            redact(source)
        ),
    })
}

/// Maps one caller-declared dimension onto the canonical orientation.
///
/// `swapped` is the single ordering decision taken by the pair. The values move
/// with the source that declared them, so a mirrored declaration carrying the
/// same associations yields the same outcome, and one carrying different
/// associations does not.
fn canonical_dimension_outcome(
    entry: &DimensionComparison,
    swapped: bool,
) -> Result<CanonicalDimensionOutcome, ConflictAnalysisError> {
    match &entry.outcome {
        DimensionOutcome::Equal { value } => {
            check_bounded_text(value, "comparison.equal", MAX_TEXT_BYTES)?;
            Ok(CanonicalDimensionOutcome::Equal {
                value: value.clone(),
            })
        }
        DimensionOutcome::Differing { left, right } => {
            check_bounded_text(left, "comparison.left_value", MAX_TEXT_BYTES)?;
            check_bounded_text(right, "comparison.right_value", MAX_TEXT_BYTES)?;
            if left == right {
                return Err(ConflictAnalysisError::Denominator {
                    detail: format!(
                        "a differing dimension must state two distinct values, not {} twice",
                        entry.dimension.as_str()
                    ),
                });
            }
            let (first_value, second_value) = if swapped {
                (right.clone(), left.clone())
            } else {
                (left.clone(), right.clone())
            };
            Ok(CanonicalDimensionOutcome::Differing {
                first_value,
                second_value,
            })
        }
        DimensionOutcome::Unnormalizable { reason } => {
            check_bounded_text(reason, "comparison.unnormalizable", MAX_NOTE_BYTES)?;
            Ok(CanonicalDimensionOutcome::Unnormalizable {
                reason: reason.clone(),
            })
        }
    }
}

impl CanonicalComparisonPair {
    /// Normalizes one caller declaration into its single canonical orientation.
    ///
    /// The commitments are supplied in the caller's own orientation — the first
    /// is for `supplied.left_source` — and are moved together with the values
    /// that source declared. Sources and values are therefore never sorted
    /// independently: swapping the handles without their values produces a
    /// different pair instead of a second spelling of the first one.
    ///
    /// Dimensions are emitted in [`COMPARISON_DIMENSIONS`] order, so an
    /// irrelevant input dimension order cannot change the pair.
    pub fn from_supplied(
        supplied: &SuppliedComparison,
        left_commitment: &SourceRecordCommitment,
        right_commitment: &SourceRecordCommitment,
    ) -> Result<Self, ConflictAnalysisError> {
        check_handle(&supplied.left_source, "comparison.left")?;
        check_handle(&supplied.right_source, "comparison.right")?;
        if supplied.left_source == supplied.right_source {
            return Err(ConflictAnalysisError::Binding {
                field: "comparison.pair".to_owned(),
                detail: "a comparison must name two distinct positions".to_owned(),
            });
        }
        check_commitment_binding(left_commitment, &supplied.left_source, "comparison.left")?;
        check_commitment_binding(right_commitment, &supplied.right_source, "comparison.right")?;
        if supplied.dimensions.len() != EXPECTED_COMPARISON_DIMENSIONS {
            return Err(ConflictAnalysisError::Denominator {
                detail: format!(
                    "each comparison must cover exactly {EXPECTED_COMPARISON_DIMENSIONS} canonical dimensions"
                ),
            });
        }

        // One ordering decision, taken once, and every value and commitment
        // below follows it.
        let swapped = supplied.left_source > supplied.right_source;
        let (first_source, first_commitment, second_source, second_commitment) = if swapped {
            (
                supplied.right_source.as_str(),
                right_commitment,
                supplied.left_source.as_str(),
                left_commitment,
            )
        } else {
            (
                supplied.left_source.as_str(),
                left_commitment,
                supplied.right_source.as_str(),
                right_commitment,
            )
        };

        let mut dimensions = Vec::with_capacity(EXPECTED_COMPARISON_DIMENSIONS);
        for dimension in COMPARISON_DIMENSIONS {
            let Some(entry) = supplied
                .dimensions
                .iter()
                .find(|entry| entry.dimension == dimension)
            else {
                return Err(ConflictAnalysisError::Denominator {
                    detail: format!(
                        "comparison does not cover canonical dimension {}",
                        dimension.as_str()
                    ),
                });
            };
            let outcome = canonical_dimension_outcome(entry, swapped)?;
            dimensions.push(CanonicalDimensionEntry { dimension, outcome });
        }

        let pair = Self {
            first_source: first_source.to_owned(),
            first_source_commitment: first_commitment.clone(),
            second_source: second_source.to_owned(),
            second_source_commitment: second_commitment.clone(),
            dimensions,
        };
        pair.validate()?;
        Ok(pair)
    }

    /// Returns the order-independent identity of this canonical pair.
    ///
    /// The spelling commits each source to its own value and commitment, so a
    /// pair that pairs a source with another source's value cannot produce the
    /// same key as the pair it claims to be.
    #[must_use]
    pub fn canonical_key(&self) -> String {
        let mut parts = [
            self.canonical_position_key(0),
            self.canonical_position_key(1),
        ];
        parts.sort_unstable();
        format!("{}|{}", parts[0], parts[1])
    }

    /// Returns the value this source contributed for one canonical dimension.
    ///
    /// A consumer identifies value ownership from the pair alone, without
    /// knowing the original caller order.
    #[must_use]
    pub fn value_for(&self, source: &str, dimension: ComparisonDimension) -> Option<&str> {
        let entry = self
            .dimensions
            .iter()
            .find(|entry| entry.dimension == dimension)?;
        let is_first = source == self.first_source;
        let is_second = source == self.second_source;
        if !is_first && !is_second {
            return None;
        }
        match &entry.outcome {
            CanonicalDimensionOutcome::Equal { value } => Some(value.as_str()),
            CanonicalDimensionOutcome::Differing {
                first_value,
                second_value,
            } => Some(if is_first {
                first_value.as_str()
            } else {
                second_value.as_str()
            }),
            CanonicalDimensionOutcome::Unnormalizable { .. } => None,
        }
    }

    /// Confirms the pair carries one canonical orientation and full commitments.
    fn validate(&self) -> Result<(), ConflictAnalysisError> {
        if self.first_source >= self.second_source {
            return Err(ConflictAnalysisError::Binding {
                field: "canonical_pair.order".to_owned(),
                detail: "canonical pair requires first_source < second_source".to_owned(),
            });
        }
        if self.first_source_commitment.source() != self.first_source {
            return Err(ConflictAnalysisError::Binding {
                field: "canonical_pair.first_commitment".to_owned(),
                detail: "first commitment is not bound to first_source".to_owned(),
            });
        }
        if self.second_source_commitment.source() != self.second_source {
            return Err(ConflictAnalysisError::Binding {
                field: "canonical_pair.second_commitment".to_owned(),
                detail: "second commitment is not bound to second_source".to_owned(),
            });
        }
        if self.dimensions.len() != EXPECTED_COMPARISON_DIMENSIONS {
            return Err(ConflictAnalysisError::Denominator {
                detail: format!(
                    "canonical pair must carry exactly {EXPECTED_COMPARISON_DIMENSIONS} dimensions"
                ),
            });
        }
        for (index, dimension) in COMPARISON_DIMENSIONS.iter().enumerate() {
            if self.dimensions[index].dimension != *dimension {
                return Err(ConflictAnalysisError::Denominator {
                    detail: format!(
                        "canonical pair dimension {index} is {} rather than {}",
                        self.dimensions[index].dimension.as_str(),
                        dimension.as_str()
                    ),
                });
            }
        }
        Ok(())
    }

    /// Returns the length-prefixed spelling of one position's own contribution.
    fn canonical_position_key(&self, position: usize) -> String {
        let (source, commitment) = if position == 0 {
            (&self.first_source, &self.first_source_commitment)
        } else {
            (&self.second_source, &self.second_source_commitment)
        };
        let mut key = format!(
            "{}:{}|{}:{}|{}:{}|{}:{}",
            source.len(),
            source,
            commitment.record_digest().len(),
            commitment.record_digest(),
            commitment.profile().len(),
            commitment.profile(),
            commitment.profile_digest().len(),
            commitment.profile_digest()
        );
        for entry in &self.dimensions {
            let value = match &entry.outcome {
                CanonicalDimensionOutcome::Equal { value } => value.clone(),
                CanonicalDimensionOutcome::Differing {
                    first_value,
                    second_value,
                } => {
                    if position == 0 {
                        first_value.clone()
                    } else {
                        second_value.clone()
                    }
                }
                CanonicalDimensionOutcome::Unnormalizable { reason } => reason.clone(),
            };
            let _ = write!(
                key,
                "|{}:{}:{}:{}",
                entry.dimension.as_str().len(),
                entry.dimension.as_str(),
                value.len(),
                value
            );
        }
        key
    }
}

/// Typed relation between two positions over the canonical dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompatibilityRelation {
    /// Every canonical dimension carries an equal admitted value from both
    /// sources under one owner-issued profile. DERIVED by
    /// [`derive_owner_relation`], never submitted: a legacy declaration
    /// cannot reach it and no owner-issued record means it is not emitted.
    EqualConditions,
    /// The admitted values differ on at least one canonical dimension under one
    /// owner-issued profile, with every dimension resolved. DERIVED the same
    /// way, so a legacy declaration cannot reach it either.
    TypedDifference,
    /// No relation is proven: a legacy declaration has no owner-bound records,
    /// or an admitted comparison leaves a canonical dimension unresolved.
    Ambiguous,
}

impl CompatibilityRelation {
    /// Returns the canonical spelling of this relation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EqualConditions => "equal_conditions",
            Self::TypedDifference => "typed_difference",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// One position's preserved mapping against another.
///
/// [`Self::outcomes`] carries the retained dimension outcomes in
/// [`COMPARISON_DIMENSIONS`] order. `relation` is DERIVED here, never supplied:
/// under [`SupplementVersion::LegacyV1Unverified`] it stays
/// [`CompatibilityRelation::Ambiguous`] because no owner-bound source, profile,
/// or value records exist, and under [`SupplementVersion::OwnerRecordV2`] it is
/// the relation the admitted typed values support and no stronger. The declared
/// differing and unnormalizable dimensions are retained in every case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionCompatibility {
    /// Source handle of the other position.
    pub other_source: String,
    /// Relation derived from the admitted values, or ambiguous when unproven.
    pub relation: CompatibilityRelation,
    /// Proof ceiling for these retained declarations.
    pub supplement_version: SupplementVersion,
    /// Every dimension outcome in canonical order, values preserved.
    pub outcomes: Vec<DimensionComparison>,
    /// Dimensions derived to differ, in canonical order.
    pub differing_dimensions: Vec<ComparisonDimension>,
    /// Dimensions the owner recorded unnormalizable, in canonical order.
    pub unnormalizable_dimensions: Vec<ComparisonDimension>,
    /// Dimensions the owner recorded unsupported, in canonical order.
    pub unsupported_dimensions: Vec<ComparisonDimension>,
    /// Coverage derived for this comparison against the canonical denominator.
    pub coverage: EvidenceCoverage,
    /// Bounded reason for the derived relation and its ceiling.
    pub derivation_note: String,
}

/// Version and proof ceiling of a retained caller-supplied supplement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SupplementVersion {
    /// Legacy caller declarations with no owner-bound records; never verified.
    LegacyV1Unverified,
    /// Owner-issued source, profile, and evidence records; derivable.
    OwnerRecordV2,
}

impl SupplementVersion {
    /// Canonical spelling of the supplement version and proof ceiling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyV1Unverified => "legacy_v1_unverified",
            Self::OwnerRecordV2 => "owner_record_v2",
        }
    }
}

/// Distinct states a causal or predictive claim may hold (algorithm step 7).
/// These never collapse into one another and never imply a winner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CausalClaimState {
    /// Topology or structure only; no causal claim is made.
    Structural,
    /// Co-occurrence or association only.
    Correlational,
    /// A causal claim whose mechanism is stated but not established.
    CausalHypothesis,
    /// A claim about a future observation.
    Prediction,
    /// A claim about the effect of an intervention.
    Intervention,
    /// Refuted by preserved counterevidence.
    Refuted,
    /// Not established; the claim stays open.
    Unknown,
}

impl CausalClaimState {
    /// Returns the canonical spelling of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::Correlational => "correlational",
            Self::CausalHypothesis => "causal_hypothesis",
            Self::Prediction => "prediction",
            Self::Intervention => "intervention",
            Self::Refuted => "refuted",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the accepted shared relation status this declared state stands
    /// for.
    ///
    /// I12.18 types exactly seven relation readings —
    /// `STRUCTURAL | BEHAVIORAL_CORRELATION | CAUSAL_HYPOTHESIS |
    /// PREDICTION_SUPPORTED | INTERVENTION_SUPPORTED | REFUTED | UNKNOWN` — and
    /// [`FailureCausalStatus`] already carries that set one for one, so this
    /// crate reads the accepted vocabulary instead of deciding a second spelling
    /// of it. The two names differ only in precision: the shared names are the
    /// longer ones (`BehavioralCorrelation` for what this cell calls
    /// correlation, `PredictionSupported` and `InterventionSupported` for the
    /// two supported readings), so no state is widened or collapsed crossing
    /// over.
    ///
    /// This is the vocabulary the crate's own proof ceiling and its state
    /// derivation MATCH ON, so a reading added to the accepted contract stops
    /// this crate compiling until it has been decided here rather than passing
    /// through a catch-all arm as if it did not exist. That is the point of
    /// reusing the owner's enum instead of re-declaring the set: the reuse is
    /// load-bearing, not decorative.
    #[must_use]
    pub const fn relation_status(self) -> FailureCausalStatus {
        match self {
            Self::Structural => FailureCausalStatus::Structural,
            Self::Correlational => FailureCausalStatus::BehavioralCorrelation,
            Self::CausalHypothesis => FailureCausalStatus::CausalHypothesis,
            Self::Prediction => FailureCausalStatus::PredictionSupported,
            Self::Intervention => FailureCausalStatus::InterventionSupported,
            Self::Refuted => FailureCausalStatus::Refuted,
            Self::Unknown => FailureCausalStatus::Unknown,
        }
    }
}

/// One legacy version 1 caller declaration of a causal or predictive claim.
///
/// The prose fields are declarations, not evidence records. Nonblank mechanism,
/// falsifier, control/evaluator, and rival/confounder text cannot qualify a
/// causal or intervention state. This compatibility shape has no owner-issued
/// observation, verification receipt, or coverage denominator and is never
/// deserialized from old bytes into a stronger contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppliedCausalClaim {
    /// Source handle holding the claim.
    pub source_handle: String,
    /// State the caller declares for this claim.
    pub declared_state: CausalClaimState,
    /// Caller-declared mechanism prose, not owner evidence.
    pub mechanism: String,
    /// Caller-declared falsifier prose, not an observed falsifier result.
    pub falsifier: String,
    /// Caller-declared control/evaluator prose, not a matched owner record.
    pub control_evaluator: String,
    /// Caller-declared rival/confounder prose, not a covered denominator.
    pub rivals_or_confounders: String,
}

/// One preserved causal declaration and its evidence-qualified assessment.
///
/// `declared_state` is the source's own claim, preserved verbatim, together
/// with the source identity and revision it was read at. `effective_state` is a
/// SEPARATE value derived only from typed evidence records: it equals the
/// declared state only when the owner-issued evidence supports that exact state,
/// and is [`CausalClaimState::Unknown`] otherwise. A declaration is never
/// recomputed, widened, or defaulted from the assessment, the assessment never
/// overwrites the declaration, and prose never promotes either.
///
/// The declaration carries its own `declaration_revision` and, where an owner
/// record supplies one, its `mechanism_claim_id`. A reader can therefore tell
/// which snapshot the source's claim was read at independently of the evidence
/// that was judged against it, which is what keeps the two separable rather than
/// one value standing in for the other. Both are `None` on the legacy path,
/// which is what that path's unverified ceiling means: it retains a
/// declaration with no source revision behind it and says so.
///
/// The two coverage cells are reported SEPARATELY and neither stands in for the
/// other. `evidence_coverage` is what the retained envelopes themselves record;
/// `rival_coverage` is what the rival/confounder denominator derives. `coverage`
/// is the weaker of the two, so a claim whose evidence set or whose rival
/// denominator is incomplete can never be published as a complete causal cell
/// by reporting the other one complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalClaimRecord {
    /// Source handle holding the claim.
    pub source_handle: String,
    /// State the source declared, preserved verbatim and never recomputed.
    pub declared_state: CausalClaimState,
    /// State after the algorithm step 7 evidence rule is applied.
    ///
    /// This is the assessment, and it is computed from typed evidence records
    /// only. It is never the declaration copied: a claim whose evidence falls
    /// short reports [`CausalClaimState::Unknown`] here while `declared_state`
    /// still carries what the source said.
    pub effective_state: CausalClaimState,
    /// Source revision the preserved declaration was read at, when an owner
    /// record supplies one.
    pub declaration_revision: Option<String>,
    /// Proof ceiling for this supplement.
    pub supplement_version: SupplementVersion,
    /// Bounded reason for reduction or unverified preservation.
    pub reduction_reason: String,
    /// The weaker of `evidence_coverage` and `rival_coverage`.
    pub coverage: EvidenceCoverage,
    /// Coverage derived from the retained evidence envelopes' own records.
    pub evidence_coverage: EvidenceCoverage,
    /// Rival/confounder coverage derived from the rival denominator.
    pub rival_coverage: EvidenceCoverage,
    /// Owner mechanism claim identity this assessment is bound to, when any.
    pub mechanism_claim_id: Option<String>,
}

/// Caller-supplied supplements bound to one `ConflictSet` analysis.
///
/// This type carries BOTH kinds of input, kept apart rather than merged, and
/// the two are never interchangeable:
///
/// - `comparisons` and `causal_claims` are RETAINED UNVERIFIED DECLARATIONS.
///   They are preserved and digested as legacy version 1 and stay at
///   [`SupplementVersion::LegacyV1Unverified`]: their values and prose are
///   declarations, never evidence, and they cannot qualify equality, difference,
///   prediction, intervention, or attribution.
/// - `owner_records` is the OWNER-BOUND INPUT: source members carrying retained
///   bytes and their owner-recorded digest, one owner-issued comparison profile
///   with the observed value for each source on each canonical dimension, and
///   causal evidence joined to its own source's material and receipts. It is
///   the only input from which [`CompatibilityRelation`] and
///   [`CausalClaimState`] are derived, and it reaches
///   [`SupplementVersion::OwnerRecordV2`].
///
/// A declaration is never promoted by the presence of an owner record for a
/// different source, and an owner record is never inferred from a declaration.
///
/// This type has no byte deserializer that could silently fill defaults while
/// upgrading old serialized values into a stronger schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictSupplements {
    /// Expected A-05 receipt the item and draft receipts bind against.
    pub expected_receipt: ValidationReceipt,
    /// Frozen bundle digest the analysis replays against.
    pub frozen_bundle_digest: String,
    /// Frozen manifest digest the analysis replays against.
    pub frozen_manifest_digest: String,
    /// Source-to-lineage attributions in any order.
    pub lineage: Vec<LineageAttribution>,
    /// Preserved objections in any order.
    pub objections: Vec<SuppliedObjection>,
    /// Preserved counterevidence handles or notes.
    pub counterevidence: Vec<String>,
    /// Preserved assumption notes.
    pub assumptions: Vec<String>,
    /// Preserved unknown notes (load-bearing unknowns stay open).
    pub unknowns: Vec<String>,
    /// Supplied structured probe candidates in any order.
    pub supplied_probes: Vec<SuppliedProbe>,
    /// Legacy v1 caller declarations over canonical dimensions; never qualified.
    pub comparisons: Vec<SuppliedComparison>,
    /// Legacy v1 causal/predictive declarations; prose is not evidence.
    pub causal_claims: Vec<SuppliedCausalClaim>,
    /// Externally supplied resolution status, when one exists.
    pub external_resolution: Option<ExternalResolution>,
    /// Owner-issued source, profile, and causal evidence records.
    ///
    /// Empty means no owner admitted a record for this analysis, and every
    /// comparison and causal state then stays at its legacy unverified ceiling.
    pub owner_records: OwnerRecords,
}

/// One analyzed position with its original proposition preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionAnalysis {
    /// Index into the `ConflictSet` declaration order.
    pub position_index: usize,
    /// Source holding this position.
    pub source_handle: String,
    /// Original stance text, preserved verbatim.
    pub stance: String,
    /// Whether the `ConflictSet` records this position as a minority.
    pub minority: bool,
    /// Exactly-one disposition for this position.
    pub disposition: PositionDispositionKind,
    /// All applicable conflict classes (primary first by precedence).
    pub conflict_classes: Vec<ConflictKind>,
    /// Compatibility note naming the equal-condition or residue boundary.
    pub compatibility_note: String,
    /// Original assumptions, preserved verbatim.
    pub assumptions: Vec<String>,
    /// Original counter handles, preserved verbatim.
    pub counters: Vec<String>,
    /// Exact typed compatibility mapping against every compared position.
    ///
    /// Empty when the caller supplied no comparison. Absence is recorded as
    /// absence and is never read as equal conditions.
    pub compatibility: Vec<PositionCompatibility>,
}

/// One lineage group with its member sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageGroup {
    /// Authoritative lineage root, or `unknown` for unattributed sources.
    pub lineage_root: String,
    /// False when the root is unknown independence.
    pub known: bool,
    /// Member source handles in sorted order.
    pub member_sources: Vec<String>,
}

/// One common-mode risk shared across positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonModeRisk {
    /// Closed risk kind spelling.
    pub kind: String,
    /// Bounded description naming the shared dependence.
    pub description: String,
    /// Affected source handles in sorted order.
    pub affected_sources: Vec<String>,
}

/// One recommended discriminative probe (declaration only, never executed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecommendedProbe {
    /// Supplied probe identity recommended here.
    pub probe_id: String,
    /// Digest of the supplied objective declaration.
    pub objective_digest: String,
    /// Digest of the supplied result schema.
    pub result_digest: String,
    /// Position sources this probe separates, in sorted order.
    ///
    /// Populated only from the `ConflictSet`'s own discriminative-probe
    /// binding, so an unbound probe names none rather than inheriting every
    /// position in the set.
    pub discriminates_positions: Vec<String>,
    /// Load-bearing unknown this probe resolves, when any.
    ///
    /// Set only on exact identity against a supplied unknown, never on a
    /// rationale that happens to mention one.
    pub resolves_unknown: Option<String>,
    /// Owner bound to the follow-up.
    pub owner: String,
    /// Verifier bound to the follow-up.
    pub verifier: String,
    /// Preserved cost, risk, privacy, and effect bounds.
    pub cost_note: String,
    /// Preserved risk bound.
    pub risk_note: String,
    /// Preserved privacy bound.
    pub privacy_note: String,
    /// Preserved effect bound.
    pub effect_note: String,
}

/// External decision-owner recommendation (naming only, never assignment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionOwnerRecommendation {
    /// Closed owner kind.
    pub kind: DecisionOwnerKind,
    /// Owner handle named by the recommendation.
    pub owner_handle: String,
    /// Bounded rationale naming the affected boundary.
    pub rationale: String,
    /// Contract or evidence the owner needs before deciding.
    pub contract_needed: String,
}

/// One preservation verdict for this transformation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionVerdict {
    /// Dimension under judgement.
    pub dimension: PreservationDimension,
    /// Whether the dimension passed.
    pub passed: bool,
    /// Whether the dimension was actually judged (`false` means unknown).
    pub known: bool,
    /// Exact note supporting the verdict (non-blank).
    pub note: String,
}

/// Seven independent dimension verdicts with no averaging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservationReport {
    /// Exactly seven verdicts, one per dimension.
    pub verdicts: Vec<DimensionVerdict>,
}

impl PreservationReport {
    /// Validates report shape: exactly seven verdicts, one per dimension.
    pub fn validate(&self) -> Result<(), ConflictAnalysisError> {
        if self.verdicts.len() != EXPECTED_PRESERVATION_DIMENSIONS {
            return Err(ConflictAnalysisError::Denominator {
                detail: "preservation report must carry exactly seven verdicts".to_owned(),
            });
        }
        let mut seen: Vec<PreservationDimension> = Vec::with_capacity(7);
        for verdict in &self.verdicts {
            if verdict.note.trim().is_empty() {
                return Err(ConflictAnalysisError::Shape {
                    field: "preservation.note".to_owned(),
                    detail: "preservation note must be non-blank".to_owned(),
                });
            }
            if verdict.note.len() > MAX_NOTE_BYTES || has_control(&verdict.note) {
                return Err(ConflictAnalysisError::Shape {
                    field: "preservation.note".to_owned(),
                    detail: "preservation note exceeds its bound".to_owned(),
                });
            }
            if seen.contains(&verdict.dimension) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: "duplicate preservation dimension".to_owned(),
                });
            }
            seen.push(verdict.dimension);
        }
        for dimension in [
            PreservationDimension::Coverage,
            PreservationDimension::Faithfulness,
            PreservationDimension::Lineage,
            PreservationDimension::Reversibility,
            PreservationDimension::AuthorityCeiling,
            PreservationDimension::DependencyClosure,
            PreservationDimension::ProvenanceRetention,
        ] {
            if !seen.contains(&dimension) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: "missing preservation dimension".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Judges the report with no averaging.
    pub fn overall(&self) -> Result<(), ConflictAnalysisError> {
        self.validate()?;
        for verdict in &self.verdicts {
            if !verdict.known {
                return Err(ConflictAnalysisError::Denominator {
                    detail: redact(&format!(
                        "preservation dimension {} is unknown",
                        verdict.dimension.as_str()
                    )),
                });
            }
            if !verdict.passed {
                return Err(ConflictAnalysisError::Denominator {
                    detail: redact(&format!(
                        "preservation dimension {} failed",
                        verdict.dimension.as_str()
                    )),
                });
            }
        }
        Ok(())
    }
}

/// Complete inert conflict-analysis candidate envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictAnalysisCandidate {
    /// Terminal outcome for this analysis (never a resolution).
    pub outcome: ConflictOutcome,
    /// Conflict identity analyzed here.
    pub conflict_id: String,
    /// Scope the conflict is localized to.
    pub scope: String,
    /// One analysis per expected position in declaration order.
    pub positions: Vec<PositionAnalysis>,
    /// Lineage groups in sorted-root order.
    pub lineage_groups: Vec<LineageGroup>,
    /// Count of unique known authoritative roots (diagnostic only).
    pub independent_root_count: usize,
    /// Common-mode risks in sorted-kind order.
    pub common_mode_risks: Vec<CommonModeRisk>,
    /// Preserved objections in sorted-id order.
    pub objections: Vec<SuppliedObjection>,
    /// Preserved counterevidence in sorted order.
    pub counterevidence: Vec<String>,
    /// Preserved unknowns in sorted order.
    pub unknowns: Vec<String>,
    /// Preserved assumptions in sorted order.
    pub assumptions: Vec<String>,
    /// Recommended discriminative probes in sorted-id order.
    pub recommended_probes: Vec<RecommendedProbe>,
    /// External decision-owner recommendation (naming only).
    pub recommended_owner: DecisionOwnerRecommendation,
    /// Seven-dimension preservation report for this transformation.
    pub preservation: PreservationReport,
    /// Invalidation conditions that reopen this analysis.
    pub invalidation_conditions: Vec<String>,
    /// Deterministic digest binding the analyzed inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
    /// Separately supplied external resolution, retained verbatim.
    pub resolution_status: Option<ExternalResolution>,
    /// Preserved causal claims with declared and effective states, sorted by
    /// source handle.
    pub causal_states: Vec<CausalClaimRecord>,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `ConflictAnalysisCandidate`.
// ---------------------------------------------------------------------------

/// Typed fail-closed conflict-analysis error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictAnalysisError {
    /// A bound or ceiling check failed in the named phase.
    Bounds {
        /// Phase that failed its bound.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Deterministic ordering was violated in the named phase.
    Order {
        /// Phase that failed ordering.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// A shape check failed on the named field.
    Shape {
        /// Field that failed its shape.
        field: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Two envelopes disagree on a shared binding.
    Binding {
        /// Closed binding name.
        field: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// The bundled A-05 receipt is intrinsically invalid or incompatible.
    Receipt {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The governing policy is malformed or out of bounds.
    Policy {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A target or member denominator is malformed or incomplete.
    Denominator {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A digest shape or replay pin is wrong.
    Digest {
        /// Bounded redacted reason.
        detail: String,
    },
}

impl core::fmt::Display for ConflictAnalysisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds { phase, detail } => write!(f, "bounds[{phase}]: {detail}"),
            Self::Order { phase, detail } => write!(f, "order[{phase}]: {detail}"),
            Self::Shape { field, detail } => write!(f, "shape[{field}]: {detail}"),
            Self::Binding { field, detail } => write!(f, "binding[{field}]: {detail}"),
            Self::Receipt { detail } => write!(f, "receipt: {detail}"),
            Self::Policy { detail } => write!(f, "policy: {detail}"),
            Self::Denominator { detail } => write!(f, "denominator: {detail}"),
            Self::Digest { detail } => write!(f, "digest: {detail}"),
        }
    }
}

impl core::error::Error for ConflictAnalysisError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(value: &str, field: &str, max: usize) -> Result<(), ConflictAnalysisError> {
    if value.trim().is_empty() {
        return Err(ConflictAnalysisError::Shape {
            field: field.to_owned(),
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ConflictAnalysisError::Shape {
            field: field.to_owned(),
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(ConflictAnalysisError::Shape {
            field: field.to_owned(),
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one optional evidence field for control characters and byte ceiling,
/// permitting an empty value.
///
/// An absent piece of declaration text is a legitimate input. Whether it is
/// blank or nonblank, legacy prose is not owner evidence and cannot raise a
/// causal proof ceiling. Rejecting blank text as malformed would hide the same
/// semantic unknown behind a request error.
fn check_optional_text(value: &str, field: &str, max: usize) -> Result<(), ConflictAnalysisError> {
    if has_control(value) {
        return Err(ConflictAnalysisError::Shape {
            field: field.to_owned(),
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(ConflictAnalysisError::Shape {
            field: field.to_owned(),
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &str) -> Result<(), ConflictAnalysisError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(ConflictAnalysisError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ConflictAnalysisError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &str) -> Result<(), ConflictAnalysisError> {
    if !is_hex64_lower(value) {
        return Err(ConflictAnalysisError::Digest {
            detail: format!("{field} must be 64 lowercase hex sha256"),
        });
    }
    Ok(())
}

/// Rejects a list length above its independent ceiling.
fn bound_list_length(phase: &str, got: usize, max: usize) -> Result<(), ConflictAnalysisError> {
    if got > max {
        return Err(ConflictAnalysisError::Bounds {
            phase: phase.to_owned(),
            detail: "list exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

/// Counts bytes across a slice of text values with saturation.
fn count_text_bytes(values: &[&str]) -> usize {
    let mut total = 0usize;
    let mut index = 0usize;
    while index < values.len() {
        if let Some(value) = values.get(index) {
            total = total.saturating_add(value.len());
        }
        index = index.saturating_add(1);
    }
    total
}

// ---------------------------------------------------------------------------
// Preflight bounds (shape only; semantic shortfalls stay outcomes).
// ---------------------------------------------------------------------------

/// Counts bytes across the whole owner-record surface with saturation.
///
/// Owner records arrive after [`ConflictSupplements`] is declared, so they are
/// counted in their own pass rather than folded into the legacy lists. The
/// aggregate ceiling therefore covers retained source bytes, profile
/// definitions, observed values, and evidence identities together.
fn count_owner_record_bytes(records: &OwnerRecords) -> usize {
    let mut total = 0usize;
    for member in &records.source_members {
        total = total.saturating_add(count_text_bytes(&[
            member.position_source.as_str(),
            member.source_owner.as_str(),
            member.retained_handle.as_str(),
            member.record_digest.as_str(),
            member.source_revision.as_str(),
            member.source_snapshot.as_str(),
            member.task_id.as_str(),
            member.scope_id.as_str(),
        ]));
        total = total.saturating_add(member.retained_bytes.len());
    }
    for comparison in &records.comparisons {
        total = total.saturating_add(count_text_bytes(&[
            comparison.first_source.as_str(),
            comparison.second_source.as_str(),
            comparison.profile.profile_id.as_str(),
            comparison.profile.owner.as_str(),
            comparison.profile.definition_digest.as_str(),
        ]));
        total = total.saturating_add(comparison.profile.definition_bytes.len());
        for rule in &comparison.profile.normalization_rules {
            total = total.saturating_add(rule.len());
        }
        for entry in &comparison.observations {
            total = total.saturating_add(count_text_bytes(&[
                entry.source.as_str(),
                entry.source_member_digest.as_str(),
                entry.descriptor.as_str(),
                entry.value.as_str(),
            ]));
        }
    }
    total = total.saturating_add(count_causal_evidence_bytes(&records.causal_evidence));
    total
}

/// Counts bytes across the owner-issued causal evidence surface.
fn count_causal_evidence_bytes(records: &[CausalEvidenceRecord]) -> usize {
    let mut total = 0usize;
    for record in records {
        total = total.saturating_add(count_text_bytes(&[
            record.source_handle.as_str(),
            record.mechanism.claim_id.as_str(),
            record.mechanism.source_revision.as_str(),
            record.mechanism.claim_digest.as_str(),
            record.falsifier.specification.as_str(),
            record.falsifier.evidence_id.as_str(),
            record.control.control_id.as_str(),
            record.control.owner.as_str(),
            record.control.evidence_id.as_str(),
            record.task_id.as_str(),
            record.scope_id.as_str(),
        ]));
        // The retained claim bytes are counted against the same total as the
        // source member's, so a record cannot buy unbounded declaration text
        // with a digest that costs 64 bytes on the ceiling.
        total = total.saturating_add(record.mechanism.claim_bytes.len());
        if let Some(intervention) = &record.intervention {
            total = total.saturating_add(count_text_bytes(&[
                intervention.execution_id.as_str(),
                intervention.receipt_digest.as_str(),
            ]));
        }
        for handle in record
            .rivals
            .expected
            .iter()
            .chain(record.rivals.observed.iter())
            .chain(record.rivals.omitted.iter())
        {
            total = total.saturating_add(handle.len());
        }
        for evidence in &record.evidence {
            total = total.saturating_add(count_text_bytes(&[
                evidence.evidence_id.as_str(),
                evidence.owner.as_str(),
                evidence.material_digest.as_str(),
                evidence.receipt_digest.as_str(),
            ]));
            // The retained receipt bytes are counted the same way the mechanism
            // claim's are: a record cannot buy unbounded receipt text with a
            // digest that costs 64 bytes on the ceiling.
            total = total.saturating_add(evidence.receipt_bytes.len());
        }
    }
    total
}

/// Preflights supplement list lengths against policy and global ceilings.
fn preflight_supplement_bounds(
    supplements: &ConflictSupplements,
    policy: &ConflictAnalysisPolicy,
) -> Result<(), ConflictAnalysisError> {
    bound_list_length(
        "lineage",
        supplements.lineage.len(),
        policy.max_sources.min(MAX_LINEAGE),
    )?;
    bound_list_length(
        "objections",
        supplements.objections.len(),
        policy.max_objections.min(MAX_OBJECTIONS),
    )?;
    bound_list_length(
        "counterevidence",
        supplements.counterevidence.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    bound_list_length(
        "assumptions",
        supplements.assumptions.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    bound_list_length("unknowns", supplements.unknowns.len(), MAX_EVIDENCE_ITEMS)?;
    bound_list_length(
        "supplied-probes",
        supplements.supplied_probes.len(),
        policy.max_probes.min(MAX_PROBES),
    )?;
    bound_list_length(
        "comparisons",
        supplements.comparisons.len(),
        MAX_COMPARISONS,
    )?;
    bound_list_length(
        "causal-claims",
        supplements.causal_claims.len(),
        MAX_CAUSAL_CLAIMS,
    )?;
    bound_list_length(
        "source-members",
        supplements.owner_records.source_members.len(),
        MAX_SOURCE_MEMBERS,
    )?;
    bound_list_length(
        "owner-comparisons",
        supplements.owner_records.comparisons.len(),
        MAX_COMPARISONS,
    )?;
    bound_list_length(
        "owner-causal-evidence",
        supplements.owner_records.causal_evidence.len(),
        MAX_CAUSAL_EVIDENCE_RECORDS,
    )?;
    Ok(())
}

/// Preflights aggregate text bytes across the whole analysis surface.
fn preflight_total_bytes(
    supplements: &ConflictSupplements,
    policy: &ConflictAnalysisPolicy,
    conflict_set: &ConflictSet,
) -> Result<(), ConflictAnalysisError> {
    let mut total = 0usize;
    total = total.saturating_add(count_text_bytes(&[
        &policy.policy_id,
        &policy.analysis_note,
        &conflict_set.conflict_id,
        &conflict_set.scope,
    ]));
    for entry in &supplements.counterevidence {
        total = total.saturating_add(entry.len());
    }
    for entry in &supplements.assumptions {
        total = total.saturating_add(entry.len());
    }
    for entry in &supplements.unknowns {
        total = total.saturating_add(entry.len());
    }
    for objection in &supplements.objections {
        total = total.saturating_add(count_text_bytes(&[
            &objection.objection_id,
            &objection.target_source,
            &objection.statement,
        ]));
    }
    for attribution in &supplements.lineage {
        total = total.saturating_add(count_text_bytes(&[
            &attribution.source_handle,
            &attribution.lineage_root,
        ]));
    }
    for comparison in &supplements.comparisons {
        total = total.saturating_add(count_text_bytes(&[
            &comparison.left_source,
            &comparison.right_source,
        ]));
        for entry in &comparison.dimensions {
            match &entry.outcome {
                DimensionOutcome::Equal { value } => {
                    total = total.saturating_add(value.len());
                }
                DimensionOutcome::Differing { left, right } => {
                    total = total.saturating_add(left.len());
                    total = total.saturating_add(right.len());
                }
                DimensionOutcome::Unnormalizable { reason } => {
                    total = total.saturating_add(reason.len());
                }
            }
        }
    }
    for claim in &supplements.causal_claims {
        total = total.saturating_add(count_text_bytes(&[
            &claim.source_handle,
            &claim.mechanism,
            &claim.falsifier,
            &claim.control_evaluator,
            &claim.rivals_or_confounders,
        ]));
    }
    total = total.saturating_add(count_owner_record_bytes(&supplements.owner_records));
    for position in &conflict_set.positions {
        total = total.saturating_add(position.stance.len());
        for assumption in &position.assumptions {
            total = total.saturating_add(assumption.len());
        }
    }
    if total > MAX_TOTAL_BYTES {
        return Err(ConflictAnalysisError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input exceeds the total byte ceiling".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shape validation (malformed input only).
// ---------------------------------------------------------------------------

/// Validates policy intrinsic shapes and ceilings.
fn validate_policy_shapes(policy: &ConflictAnalysisPolicy) -> Result<(), ConflictAnalysisError> {
    check_handle(&policy.policy_id, "policy.id")?;
    if policy.policy_revision == 0 {
        return Err(ConflictAnalysisError::Policy {
            detail: "policy_revision must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.max_positions == 0 || policy.max_positions > MAX_POSITIONS {
        return Err(ConflictAnalysisError::Policy {
            detail: format!("max_positions must cover 1..={MAX_POSITIONS}"),
        });
    }
    if policy.max_sources == 0 || policy.max_sources > MAX_SOURCES {
        return Err(ConflictAnalysisError::Policy {
            detail: format!("max_sources must cover 1..={MAX_SOURCES}"),
        });
    }
    if policy.max_objections > MAX_OBJECTIONS {
        return Err(ConflictAnalysisError::Policy {
            detail: format!("max_objections must cover 0..={MAX_OBJECTIONS}"),
        });
    }
    if policy.max_probes > MAX_PROBES {
        return Err(ConflictAnalysisError::Policy {
            detail: format!("max_probes must cover 0..={MAX_PROBES}"),
        });
    }
    check_bounded_text(&policy.analysis_note, "policy.note", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates supplement text shapes and digest pins.
fn validate_supplement_shapes(
    supplements: &ConflictSupplements,
) -> Result<(), ConflictAnalysisError> {
    check_digest(&supplements.frozen_bundle_digest, "frozen-bundle")?;
    check_digest(&supplements.frozen_manifest_digest, "frozen-manifest")?;
    for attribution in &supplements.lineage {
        check_handle(&attribution.source_handle, "lineage.source")?;
        check_handle(&attribution.lineage_root, "lineage.root")?;
    }
    for objection in &supplements.objections {
        check_handle(&objection.objection_id, "objection.id")?;
        check_handle(&objection.target_source, "objection.target")?;
        check_bounded_text(&objection.statement, "objection.statement", MAX_TEXT_BYTES)?;
    }
    for entry in supplements
        .counterevidence
        .iter()
        .chain(supplements.assumptions.iter())
        .chain(supplements.unknowns.iter())
    {
        check_bounded_text(entry, "evidence.entry", MAX_TEXT_BYTES)?;
    }
    for probe in &supplements.supplied_probes {
        check_handle(&probe.probe_id, "probe.id")?;
        check_bounded_text(&probe.owner_note, "probe.owner", MAX_NOTE_BYTES)?;
        check_bounded_text(&probe.verifier, "probe.verifier", MAX_HANDLE_BYTES)?;
        check_bounded_text(&probe.cost_note, "probe.cost", MAX_NOTE_BYTES)?;
        check_bounded_text(&probe.risk_note, "probe.risk", MAX_NOTE_BYTES)?;
        check_bounded_text(&probe.privacy_note, "probe.privacy", MAX_NOTE_BYTES)?;
        check_bounded_text(&probe.effect_note, "probe.effect", MAX_NOTE_BYTES)?;
        probe
            .objective
            .validate()
            .map_err(|err| ConflictAnalysisError::Shape {
                field: "probe.objective".to_owned(),
                detail: redact(&err.to_string()),
            })?;
        probe
            .schema
            .validate()
            .map_err(|err| ConflictAnalysisError::Shape {
                field: "probe.schema".to_owned(),
                detail: redact(&err.to_string()),
            })?;
    }
    if let Some(resolution) = &supplements.external_resolution {
        check_digest(&resolution.decision_digest, "resolution.digest")?;
        check_bounded_text(&resolution.decided_by, "resolution.owner", MAX_HANDLE_BYTES)?;
        check_bounded_text(&resolution.note, "resolution.note", MAX_NOTE_BYTES)?;
    }
    Ok(())
}

/// Validates `ConflictSet` denominator shapes without judging semantics.
///
/// The position denominator is checked as CONTENT, not as a count of the
/// supplied `positions` vector. A count alone is defeated by suppression: a
/// caller can hand over two positions while the set itself declares a third
/// unresolved owner, and the analysis would then report a clean two-sided
/// conflict over a denominator that is really three members wide. The set's own
/// `unresolved_owners` declaration is what makes that suppression visible, so
/// every declared member must be present as a position and the refused member is
/// named rather than counted away.
///
/// A declared member with no position is refused here rather than preserved as
/// a withheld or unavailable disposition. [`PositionDispositionKind::Withheld`]
/// and [`PositionDispositionKind::Unavailable`] name that outcome, but this cell
/// has no typed INPUT that can carry one: a `ConflictPosition` is stance text
/// plus its assumptions, counters, and minority flag, with no availability axis,
/// and the closest existing omission type, [`RivalDenominator`], is scoped to a
/// causal claim's rival/confounder models and says nothing about how many
/// conflict positions exist. Admitting the exception on a caller-set flag would
/// hand back exactly the power this check removes, so the refusal stands until
/// a typed missing-position declaration exists to carry it.
fn validate_conflict_denominators(
    conflict_set: &ConflictSet,
    policy: &ConflictAnalysisPolicy,
) -> Result<(), ConflictAnalysisError> {
    check_bounded_text(&conflict_set.conflict_id, "conflict.id", MAX_SCOPE_BYTES)?;
    check_bounded_text(&conflict_set.scope, "conflict.scope", MAX_SCOPE_BYTES)?;
    bound_list_length(
        "positions",
        conflict_set.positions.len(),
        policy.max_positions.min(MAX_POSITIONS),
    )?;
    if conflict_set.positions.len() < MINIMUM_CONFLICT_POSITIONS {
        return Err(ConflictAnalysisError::Denominator {
            detail: format!("conflict requires at least {MINIMUM_CONFLICT_POSITIONS} positions"),
        });
    }
    let mut seen_sources: Vec<String> = Vec::with_capacity(conflict_set.positions.len());
    for position in &conflict_set.positions {
        let source_text = position.source.as_str();
        check_handle(source_text, "position.source")?;
        check_bounded_text(&position.stance, "position.stance", MAX_TEXT_BYTES)?;
        for assumption in &position.assumptions {
            check_bounded_text(assumption.as_str(), "position.assumption", MAX_TEXT_BYTES)?;
        }
        if seen_sources.contains(&source_text.to_owned()) {
            return Err(ConflictAnalysisError::Denominator {
                detail: "duplicate position source identity".to_owned(),
            });
        }
        seen_sources.push(source_text.to_owned());
    }
    seen_sources.sort();
    let mut deduped = seen_sources.clone();
    deduped.dedup();
    if deduped.len() != seen_sources.len() {
        return Err(ConflictAnalysisError::Denominator {
            detail: "duplicate position source identity".to_owned(),
        });
    }
    for owner in &conflict_set.unresolved_owners {
        if !seen_sources
            .iter()
            .any(|source| source.as_str() == owner.as_str())
        {
            return Err(ConflictAnalysisError::Denominator {
                detail: format!(
                    "a declared unresolved owner has no position and would leave the denominator: {}",
                    redact(owner.as_str())
                ),
            });
        }
    }
    Ok(())
}

/// Returns the sorted source handles of every position in the set.
fn position_source_handles(conflict_set: &ConflictSet) -> Vec<String> {
    let mut handles: Vec<String> = conflict_set
        .positions
        .iter()
        .map(|position| position.source.as_str().to_owned())
        .collect();
    handles.sort();
    handles
}

/// Returns the order-independent identity of one position pair.
///
/// Each element is length-prefixed, so no source handle can forge another pair's
/// key by containing the separator: the pairs `("a->b", "c")` and `("a", "b->c")`
/// are distinct, and a list may legitimately carry both.
fn comparison_pair_key(left: &str, right: &str) -> String {
    let mut pair = [left, right];
    pair.sort_unstable();
    format!(
        "{}:{}|{}:{}",
        pair[0].len(),
        pair[0],
        pair[1].len(),
        pair[1]
    )
}

/// Validates legacy declarations before they are preserved in the candidate.
///
/// Every comparison must name two distinct positions that exist in the set and
/// must cover each canonical dimension exactly once. A mirrored duplicate pair
/// is rejected so the emitted mapping is order-independent.
fn validate_comparisons(
    conflict_set: &ConflictSet,
    comparisons: &[SuppliedComparison],
) -> Result<(), ConflictAnalysisError> {
    let handles = position_source_handles(conflict_set);
    let mut seen_pairs: Vec<String> = Vec::with_capacity(comparisons.len());
    for comparison in comparisons {
        check_handle(&comparison.left_source, "comparison.left")?;
        check_handle(&comparison.right_source, "comparison.right")?;
        if comparison.left_source == comparison.right_source {
            return Err(ConflictAnalysisError::Binding {
                field: "comparison.pair".to_owned(),
                detail: "a comparison must name two distinct positions".to_owned(),
            });
        }
        for source in [&comparison.left_source, &comparison.right_source] {
            if !handles.contains(source) {
                return Err(ConflictAnalysisError::Binding {
                    field: "comparison.source".to_owned(),
                    detail: format!(
                        "comparison names a source outside the position denominator: {}",
                        redact(source)
                    ),
                });
            }
        }
        if comparison.dimensions.len() != EXPECTED_COMPARISON_DIMENSIONS {
            return Err(ConflictAnalysisError::Denominator {
                detail: format!(
                    "each comparison must cover exactly {EXPECTED_COMPARISON_DIMENSIONS} canonical dimensions"
                ),
            });
        }
        let mut seen_dimensions: Vec<ComparisonDimension> =
            Vec::with_capacity(EXPECTED_COMPARISON_DIMENSIONS);
        for entry in &comparison.dimensions {
            if seen_dimensions.contains(&entry.dimension) {
                return Err(ConflictAnalysisError::Denominator {
                    detail: format!(
                        "duplicate comparison dimension {}",
                        entry.dimension.as_str()
                    ),
                });
            }
            seen_dimensions.push(entry.dimension);
            match &entry.outcome {
                DimensionOutcome::Equal { value } => {
                    check_bounded_text(value, "comparison.equal", MAX_TEXT_BYTES)?;
                }
                DimensionOutcome::Differing { left, right } => {
                    check_bounded_text(left, "comparison.left_value", MAX_TEXT_BYTES)?;
                    check_bounded_text(right, "comparison.right_value", MAX_TEXT_BYTES)?;
                    if left == right {
                        return Err(ConflictAnalysisError::Denominator {
                            detail: format!(
                                "a differing dimension must state two distinct values, not {} twice",
                                entry.dimension.as_str()
                            ),
                        });
                    }
                }
                DimensionOutcome::Unnormalizable { reason } => {
                    check_bounded_text(reason, "comparison.unnormalizable", MAX_NOTE_BYTES)?;
                }
            }
        }
        let key = comparison_pair_key(&comparison.left_source, &comparison.right_source);
        if seen_pairs.contains(&key) {
            return Err(ConflictAnalysisError::Denominator {
                detail: "duplicate comparison pair".to_owned(),
            });
        }
        seen_pairs.push(key);
    }
    Ok(())
}

/// Validates supplied causal claims against the position denominator.
fn validate_causal_claims(
    conflict_set: &ConflictSet,
    claims: &[SuppliedCausalClaim],
) -> Result<(), ConflictAnalysisError> {
    let handles = position_source_handles(conflict_set);
    let mut seen: Vec<String> = Vec::with_capacity(claims.len());
    for claim in claims {
        check_handle(&claim.source_handle, "causal.source")?;
        if !handles.contains(&claim.source_handle) {
            return Err(ConflictAnalysisError::Binding {
                field: "causal.source".to_owned(),
                detail: format!(
                    "causal claim names a source outside the position denominator: {}",
                    redact(&claim.source_handle)
                ),
            });
        }
        check_optional_text(&claim.mechanism, "causal.mechanism", MAX_NOTE_BYTES)?;
        check_optional_text(&claim.falsifier, "causal.falsifier", MAX_NOTE_BYTES)?;
        check_optional_text(&claim.control_evaluator, "causal.control", MAX_NOTE_BYTES)?;
        check_optional_text(
            &claim.rivals_or_confounders,
            "causal.rivals",
            MAX_NOTE_BYTES,
        )?;
        if seen.contains(&claim.source_handle) {
            return Err(ConflictAnalysisError::Denominator {
                detail: "duplicate causal claim source".to_owned(),
            });
        }
        seen.push(claim.source_handle.clone());
    }
    Ok(())
}

/// Validates owner-issued source members against the position denominator and
/// the item's own task, scope, and fence.
///
/// A member that names no position in the set is refused: equal handle text is
/// not a binding to the exact `ConflictSet` member. A member admitted under a
/// different task, scope, or fence than the item is refused too, because a
/// record captured outside the current boundary cannot qualify anything here.
fn validate_source_members(
    item: &ValidatedCurationItem,
    conflict_set: &ConflictSet,
    members: &[SourceMemberRecord],
) -> Result<(), ConflictAnalysisError> {
    let handles = position_source_handles(conflict_set);
    let mut seen: Vec<String> = Vec::with_capacity(members.len());
    for member in members {
        member.validate()?;
        if !handles.contains(&member.position_source) {
            return Err(ConflictAnalysisError::Binding {
                field: "source_member.position_source".to_owned(),
                detail: format!(
                    "source member names a position outside the conflict denominator: {}",
                    redact(&member.position_source)
                ),
            });
        }
        if seen.contains(&member.position_source) {
            return Err(ConflictAnalysisError::Denominator {
                detail: "duplicate source member identity".to_owned(),
            });
        }
        seen.push(member.position_source.clone());
        check_owner_boundary(
            &member.task_id,
            &member.scope_id,
            &member.state_fence,
            item,
            "source_member",
        )?;
    }
    Ok(())
}

/// Confirms one owner record was admitted under the item's current task, scope,
/// and fence.
fn check_owner_boundary(
    task_id: &str,
    scope_id: &str,
    fence: &StateFence,
    item: &ValidatedCurationItem,
    field: &str,
) -> Result<(), ConflictAnalysisError> {
    if task_id != item.task_id || scope_id != item.scope_id {
        return Err(ConflictAnalysisError::Binding {
            field: format!("{field}.task_scope"),
            detail: "owner record was admitted under a different task or scope".to_owned(),
        });
    }
    if !fences_match_exact(fence, &item.state_fence) {
        return Err(ConflictAnalysisError::Binding {
            field: format!("{field}.state_fence"),
            detail: "owner record was admitted under a different fence".to_owned(),
        });
    }
    Ok(())
}

/// Returns the owner source member admitted for one position handle.
fn find_source_member<'a>(
    members: &'a [SourceMemberRecord],
    position_source: &str,
) -> Option<&'a SourceMemberRecord> {
    members
        .iter()
        .find(|member| member.position_source == position_source)
}

/// Validates one owner-issued comparison against the retained source members.
///
/// The pair's commitments are the owner-issued binding, so the retained member
/// for each source must carry exactly the digest the commitment names. A
/// source byte or revision that changed under an old commitment is refused here
/// rather than being compared as though it were current.
fn check_owner_comparison_members(
    comparison: &OwnerComparison,
    members: &[SourceMemberRecord],
) -> Result<(), ConflictAnalysisError> {
    for (source, commitment) in [
        (&comparison.first_source, &comparison.first_commitment),
        (&comparison.second_source, &comparison.second_commitment),
    ] {
        let member =
            find_source_member(members, source).ok_or_else(|| ConflictAnalysisError::Binding {
                field: "owner_comparison.source_member".to_owned(),
                detail: format!(
                    "no owner source member is admitted for position {}",
                    redact(source)
                ),
            })?;
        if member.record_digest != commitment.record_digest() {
            return Err(ConflictAnalysisError::Binding {
                field: "owner_comparison.source_member".to_owned(),
                detail: format!(
                    "retained member for {} records a different digest than the comparison commitment, so that commitment is stale or conflicting",
                    redact(source)
                ),
            });
        }
    }
    Ok(())
}

/// Validates owner-issued comparisons against the position denominator.
fn validate_owner_comparisons(
    conflict_set: &ConflictSet,
    records: &OwnerRecords,
) -> Result<(), ConflictAnalysisError> {
    let handles = position_source_handles(conflict_set);
    let mut seen_pairs: Vec<String> = Vec::with_capacity(records.comparisons.len());
    for comparison in &records.comparisons {
        comparison.validate()?;
        for source in [&comparison.first_source, &comparison.second_source] {
            if !handles.contains(source) {
                return Err(ConflictAnalysisError::Binding {
                    field: "owner_comparison.source".to_owned(),
                    detail: format!(
                        "owner comparison names a position outside the denominator: {}",
                        redact(source)
                    ),
                });
            }
        }
        check_owner_comparison_members(comparison, &records.source_members)?;
        let key = comparison_pair_key(&comparison.first_source, &comparison.second_source);
        if seen_pairs.contains(&key) {
            return Err(ConflictAnalysisError::Denominator {
                detail: "duplicate owner comparison pair".to_owned(),
            });
        }
        seen_pairs.push(key);
    }
    Ok(())
}

/// Validates owner-issued causal evidence against the position denominator and
/// the item's current boundary.
///
/// Every evidence envelope is validated by its own contract and must be joined
/// to the retained material it claims. The A-05 receipt attests the curation
/// item and draft boundary only, so a causal record may not present that
/// receipt as its own evidence receipt.
fn validate_causal_evidence(
    item: &ValidatedCurationItem,
    conflict_set: &ConflictSet,
    records: &OwnerRecords,
) -> Result<(), ConflictAnalysisError> {
    let handles = position_source_handles(conflict_set);
    let mut seen: Vec<String> = Vec::with_capacity(records.causal_evidence.len());
    for record in &records.causal_evidence {
        record.validate()?;
        if !handles.contains(&record.source_handle) {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.source_handle".to_owned(),
                detail: "causal evidence names a position outside the denominator".to_owned(),
            });
        }
        if seen.contains(&record.source_handle) {
            return Err(ConflictAnalysisError::Denominator {
                detail: "duplicate causal evidence source".to_owned(),
            });
        }
        seen.push(record.source_handle.clone());
        check_owner_boundary(
            &record.task_id,
            &record.scope_id,
            &record.state_fence,
            item,
            "causal_evidence",
        )?;
        // The claim's material belongs to the claim's own position, so its
        // member is resolved here ONCE and both the revision check and the
        // material join below read that one record. A claim naming a position
        // with no admitted source member has nothing to read its mechanism
        // claim from: that is a refusal, not a check that may be skipped, and
        // skipping it is what let a claim reach an evidence-qualified state
        // with no retained material of its own behind it.
        let Some(member) = find_source_member(&records.source_members, &record.source_handle)
        else {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.source_member".to_owned(),
                detail: format!(
                    "no owner source member is admitted for position {}",
                    redact(&record.source_handle)
                ),
            });
        };
        check_mechanism_revision(record, member)?;
        check_evidence_joins(record, item, member)?;
    }
    Ok(())
}

/// Confirms one mechanism claim was read at its own source's retained revision.
fn check_mechanism_revision(
    record: &CausalEvidenceRecord,
    member: &SourceMemberRecord,
) -> Result<(), ConflictAnalysisError> {
    if member.source_revision == record.mechanism.source_revision {
        return Ok(());
    }
    Err(ConflictAnalysisError::Binding {
        field: "causal_evidence.mechanism.source_revision".to_owned(),
        detail: "mechanism claim revision drifts from the retained source revision".to_owned(),
    })
}

/// Joins every retained envelope to its own source's material and keeps the A-05
/// receipt out of the causal evidence set.
///
/// The join is against the ONE member the claim's own position retained, never
/// against the union of every member in the analysis. An envelope backed by a
/// different position's bytes is not evidence about this position, so reading
/// it as though it were would let one source's retained material qualify
/// another source's claim.
///
/// The envelope's own fence is compared to the current item fence by exact
/// tuple. The envelope contract validates that a fence is well formed, not
/// that it is the CURRENT one, so a stale or mixed-fence envelope is otherwise
/// well-formed evidence: without this comparison it would qualify a claim
/// under a lease or epoch the analysis does not hold.
///
/// The envelope's own provenance is read the same way and to the same end. The
/// I21.8 claim chain is `claim -> evidence handle -> source revision -> ...`:
/// an envelope whose recorded revision is not the revision of the retained
/// material it is joined to, or that was captured in another scope, is evidence
/// about a different snapshot, and a missing revision names no snapshot at all.
/// The exact comparison used here (revision present AND equal, scope exactly
/// equal) is the same one the reactive context contracts already apply to an
/// admitted owner closure, so an envelope cannot qualify a causal claim through
/// a weaker join than the rest of the repository uses.
fn check_evidence_joins(
    record: &CausalEvidenceRecord,
    item: &ValidatedCurationItem,
    member: &SourceMemberRecord,
) -> Result<(), ConflictAnalysisError> {
    for evidence in &record.evidence {
        if evidence.material_digest != member.record_digest {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.material_digest".to_owned(),
                detail: "evidence is not joined to the retained material of its own source"
                    .to_owned(),
            });
        }
        if !fences_match_exact(&evidence.envelope.state_fence, &item.state_fence) {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.envelope.state_fence".to_owned(),
                detail: "evidence was captured under a different fence than the current one"
                    .to_owned(),
            });
        }
        if evidence.envelope.provenance.scope != item.scope_id {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.envelope.provenance.scope".to_owned(),
                detail: "evidence was captured in a different scope than the current one"
                    .to_owned(),
            });
        }
        if evidence.envelope.provenance.revision.as_deref() != Some(member.source_revision.as_str())
        {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.envelope.provenance.revision".to_owned(),
                detail:
                    "evidence names no source revision or one other than the retained material it is joined to"
                        .to_owned(),
            });
        }
        if evidence.receipt_digest == item.receipt.bundle_digest {
            return Err(ConflictAnalysisError::Binding {
                field: "causal_evidence.receipt_digest".to_owned(),
                detail:
                    "the A-05 receipt attests the curation boundary only and is not causal evidence"
                        .to_owned(),
            });
        }
    }
    Ok(())
}

/// Validates the whole owner-record surface before any interpretation.
fn validate_owner_records(
    item: &ValidatedCurationItem,
    conflict_set: &ConflictSet,
    records: &OwnerRecords,
) -> Result<(), ConflictAnalysisError> {
    validate_source_members(item, conflict_set, &records.source_members)?;
    validate_owner_comparisons(conflict_set, records)?;
    validate_causal_evidence(item, conflict_set, records)
}

/// Rejects duplicate supplement identities before interpretation.
fn check_supplement_identity_uniqueness(
    supplements: &ConflictSupplements,
) -> Result<(), ConflictAnalysisError> {
    let mut objection_ids: Vec<String> = supplements
        .objections
        .iter()
        .map(|objection| objection.objection_id.clone())
        .collect();
    objection_ids.sort();
    let mut deduped = objection_ids.clone();
    deduped.dedup();
    if deduped.len() != objection_ids.len() {
        return Err(ConflictAnalysisError::Denominator {
            detail: "duplicate objection identity".to_owned(),
        });
    }
    let mut probe_ids: Vec<String> = supplements
        .supplied_probes
        .iter()
        .map(|probe| probe.probe_id.clone())
        .collect();
    probe_ids.sort();
    let mut deduped_probes = probe_ids.clone();
    deduped_probes.dedup();
    if deduped_probes.len() != probe_ids.len() {
        return Err(ConflictAnalysisError::Denominator {
            detail: "duplicate probe identity".to_owned(),
        });
    }
    let mut source_handles: Vec<String> = supplements
        .lineage
        .iter()
        .map(|entry| entry.source_handle.clone())
        .collect();
    source_handles.sort();
    let mut deduped_sources = source_handles.clone();
    deduped_sources.dedup();
    if deduped_sources.len() != source_handles.len() {
        return Err(ConflictAnalysisError::Denominator {
            detail: "duplicate lineage source identity".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Intrinsic checks (A-05 receipt intrinsically, never re-executed).
// ---------------------------------------------------------------------------

/// Maps a contract violation into a redacted receipt error.
fn receipt_err(detail: &str) -> ConflictAnalysisError {
    ConflictAnalysisError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the A-05 receipts intrinsically plus item, draft, and grounding.
fn intrinsic_receipt_checks(
    item: &ValidatedCurationItem,
    draft: &ValidatedDreamDraft,
    grounded: &GroundedDreamDraft,
    supplements: &ConflictSupplements,
) -> Result<(), ConflictAnalysisError> {
    item.receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    draft
        .receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    draft
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    supplements
        .expected_receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    item.receipt
        .validate_binding(&supplements.expected_receipt)
        .map_err(|err| receipt_err(&err.to_string()))?;
    draft
        .receipt
        .validate_binding(&supplements.expected_receipt)
        .map_err(|err| receipt_err(&err.to_string()))?;
    item.validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    grounded
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if item.receipt.terminal_disposition != "accepted"
        && item.receipt.terminal_disposition != "partial"
    {
        return Err(ConflictAnalysisError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    check_fence(&item.state_fence).map_err(|err| receipt_err(&err.to_string()))?;
    check_fence(&draft.state_fence).map_err(|err| receipt_err(&err.to_string()))?;
    Ok(())
}

/// Checks bundle, manifest, draft, task, scope, fence, and `ConflictSet` pins.
fn intrinsic_binding_checks(
    item: &ValidatedCurationItem,
    draft: &ValidatedDreamDraft,
    grounded: &GroundedDreamDraft,
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
) -> Result<(), ConflictAnalysisError> {
    if item.receipt.bundle_digest != supplements.frozen_bundle_digest {
        return Err(ConflictAnalysisError::Binding {
            field: "bundle_digest".to_owned(),
            detail: "frozen bundle digest drifts from the receipt binding".to_owned(),
        });
    }
    if item.receipt.manifest_digest != supplements.frozen_manifest_digest {
        return Err(ConflictAnalysisError::Binding {
            field: "manifest_digest".to_owned(),
            detail: "frozen manifest digest drifts from the receipt binding".to_owned(),
        });
    }
    if item.receipt.draft_digest != grounded.draft_digest {
        return Err(ConflictAnalysisError::Binding {
            field: "draft_digest".to_owned(),
            detail: "grounded draft digest drifts from the receipt binding".to_owned(),
        });
    }
    if grounded.job_id != item.receipt.job_id {
        return Err(ConflictAnalysisError::Binding {
            field: "job_id".to_owned(),
            detail: "grounded job drifts from the receipt binding".to_owned(),
        });
    }
    if draft.draft_digest != item.receipt.draft_digest {
        return Err(ConflictAnalysisError::Binding {
            field: "draft_digest".to_owned(),
            detail: "validated draft digest drifts from the item receipt".to_owned(),
        });
    }
    if item.task_id != item.receipt.task_id || item.scope_id != item.receipt.scope_id {
        return Err(ConflictAnalysisError::Binding {
            field: "task_scope".to_owned(),
            detail: "item task or scope drifts from the receipt binding".to_owned(),
        });
    }
    if draft.task_id != item.receipt.task_id || draft.scope_id != item.receipt.scope_id {
        return Err(ConflictAnalysisError::Binding {
            field: "draft_task_scope".to_owned(),
            detail: "validated draft task or scope drifts from the receipt".to_owned(),
        });
    }
    if conflict_set.scope != item.scope_id {
        return Err(ConflictAnalysisError::Binding {
            field: "conflict_scope".to_owned(),
            detail: "conflict scope drifts from the item scope binding".to_owned(),
        });
    }
    if let Some(task_id) = &conflict_set.task_id
        && task_id.as_str() != item.task_id.as_str()
    {
        return Err(ConflictAnalysisError::Binding {
            field: "conflict_task".to_owned(),
            detail: "conflict task drifts from the item task binding".to_owned(),
        });
    }
    if conflict_set.receipt_digest != supplements.frozen_bundle_digest {
        return Err(ConflictAnalysisError::Binding {
            field: "conflict_receipt".to_owned(),
            detail: "conflict receipt digest drifts from the frozen bundle".to_owned(),
        });
    }
    conflict_set
        .validate()
        .map_err(|err| ConflictAnalysisError::Binding {
            field: "conflict_set".to_owned(),
            detail: redact(&err.to_string()),
        })?;
    Ok(())
}

/// Checks deadline and cancellation before any emission work.
fn check_deadline_and_cancel(policy: &ConflictAnalysisPolicy) -> Option<ConflictOutcome> {
    if policy.cancelled {
        return Some(ConflictOutcome::Blocked);
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return Some(ConflictOutcome::Stale);
    }
    None
}

/// Checks the canonical `ConflictSet` lifecycle before any interpretation.
///
/// Every leg reads the set's own state axis (I13.2
/// `state: open | investigating | decided | superseded | resolved`) and never
/// repairs it. A set its owner already decided is refused and handed back to
/// that boundary, because this cell never reissues or reinterprets a decision.
/// A supersession that names no resolved part is unproven, and an unproven
/// supersession is neither a live set nor addressable history, so the request is
/// handed to the boundary that can prove it. A closed set with empty residue
/// leaves no open conflict, so no analysis and no partial path is offered. The
/// three legs are disjoint: only one lifecycle value can apply, and closure
/// implies the empty residue it requires.
fn check_lifecycle_boundary(conflict_set: &ConflictSet) -> Option<(ConflictOutcome, &'static str)> {
    if conflict_set.lifecycle == ConflictLifecycle::Decided {
        return Some((
            ConflictOutcome::Rejected,
            "the set is already decided by its named owner; this cell reissues no decision and hands the request back to that boundary",
        ));
    }
    if conflict_set.lifecycle == ConflictLifecycle::Superseded
        && conflict_set.resolved_parts.is_empty()
    {
        return Some((
            ConflictOutcome::Unsupported,
            "the set claims supersession but names no resolved part, so the supersession is unproven and this boundary cannot support the request",
        ));
    }
    if conflict_set.is_closed() {
        return Some((
            ConflictOutcome::Abstention,
            "the set is closed with empty residue, so no open conflict is left to analyze and no partial path is offered",
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// Lineage grouping (authoritative roots, never agent or citation counts).
// ---------------------------------------------------------------------------

/// Groups position sources by their authoritative lineage roots.
fn group_lineage(
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
) -> (Vec<LineageGroup>, usize) {
    let mut table: BTreeMap<String, (bool, BTreeSet<String>)> = BTreeMap::new();
    let mut attribution: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for entry in &supplements.lineage {
        attribution.insert(
            entry.source_handle.clone(),
            (entry.lineage_root.clone(), entry.known),
        );
    }
    for position in &conflict_set.positions {
        let source_text = position.source.as_str().to_owned();
        let (root, known) = attribution
            .get(&source_text)
            .cloned()
            .unwrap_or_else(|| ("unknown".to_owned(), false));
        let slot = table.entry(root).or_insert_with(|| (true, BTreeSet::new()));
        if !known {
            slot.0 = false;
        }
        slot.1.insert(source_text);
    }
    let mut groups: Vec<LineageGroup> = Vec::with_capacity(table.len());
    for (root, (all_known, members)) in table {
        let known = all_known && root != "unknown";
        let member_sources: Vec<String> = members.into_iter().collect();
        groups.push(LineageGroup {
            lineage_root: root,
            known,
            member_sources,
        });
    }
    groups.sort_by(|left, right| left.lineage_root.cmp(&right.lineage_root));
    let mut roots: BTreeSet<String> = BTreeSet::new();
    for group in &groups {
        if group.known {
            roots.insert(group.lineage_root.clone());
        }
    }
    let independent = roots.len();
    (groups, independent)
}

/// Collects common-mode risks from shared roots and canonical markers.
fn collect_common_mode_risks(
    groups: &[LineageGroup],
    conflict_set: &ConflictSet,
) -> Vec<CommonModeRisk> {
    let mut risks: Vec<CommonModeRisk> = Vec::new();
    for group in groups {
        if !group.known {
            risks.push(CommonModeRisk {
                kind: "unknown_lineage".to_owned(),
                description: "unknown lineage is unknown independence".to_owned(),
                affected_sources: group.member_sources.clone(),
            });
        } else if group.member_sources.len() > 1 {
            risks.push(CommonModeRisk {
                kind: "shared_primary_source".to_owned(),
                description: format!(
                    "sources share one authoritative root {}",
                    group.lineage_root
                ),
                affected_sources: group.member_sources.clone(),
            });
        }
        let low = lowered(&group.lineage_root);
        if group.known
            && (contains_marker(&low, "model")
                || contains_marker(&low, "evaluator")
                || contains_marker(&low, "context")
                || contains_marker(&low, "route")
                || contains_marker(&low, "holdout"))
        {
            risks.push(CommonModeRisk {
                kind: "shared_model_evaluator_context_route".to_owned(),
                description: "shared model, evaluator, context, or route limits independence"
                    .to_owned(),
                affected_sources: group.member_sources.clone(),
            });
        }
    }
    if !conflict_set.common_lineage.is_empty() {
        let mut affected: Vec<String> = conflict_set
            .positions
            .iter()
            .map(|position| position.source.as_str().to_owned())
            .collect();
        affected.sort();
        affected.dedup();
        let mut roots: Vec<String> = conflict_set
            .common_lineage
            .iter()
            .map(|root| root.as_str().to_owned())
            .collect();
        roots.sort();
        risks.push(CommonModeRisk {
            kind: "canonical_common_lineage".to_owned(),
            description: format!("canonical common lineage {}", roots.join(",")),
            affected_sources: affected,
        });
    }
    risks.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.description.cmp(&right.description))
    });
    risks
}

// ---------------------------------------------------------------------------
// Classification (multiple applicable classes, never first-match loss).
// ---------------------------------------------------------------------------

/// Infers additional conflict classes from stance and assumption markers.
fn infer_additional_classes(conflict_set: &ConflictSet) -> Vec<ConflictKind> {
    let mut texts: Vec<String> = Vec::new();
    for position in &conflict_set.positions {
        texts.push(lowered(&position.stance));
        for assumption in &position.assumptions {
            texts.push(lowered(assumption.as_str()));
        }
    }
    let joined = texts.join("\n");
    let mut extra: BTreeSet<usize> = BTreeSet::new();
    let markers: &[(usize, &[&str])] = &[
        (1, &["revision", "fence", "write race", "state race"]),
        (2, &["task path", "competing plan", "plan conflict"]),
        (
            3,
            &["permission", "policy", "authority", "effect permission"],
        ),
        (4, &["output", "patch", "artifact"]),
        (
            5,
            &[
                "constraint",
                "instruction",
                "skill constraint",
                "human constraint",
            ],
        ),
        (6, &["queue", "budget", "module contention", "resource"]),
        (7, &["implementation", "intent", "architecture"]),
    ];
    for (offset, words) in markers {
        if mentions_any(&joined, words) {
            extra.insert(*offset);
        }
    }
    if mentions_any(
        &joined,
        &["causal", "mechanism", "evidence", "claim", "model"],
    ) || claims_chronology_is_causality(&joined)
    {
        extra.insert(0);
    }
    let mut out: Vec<ConflictKind> = Vec::new();
    for offset in extra {
        if let Some(kind) = KIND_PRECEDENCE.get(offset) {
            out.push(*kind);
        }
    }
    out
}

/// Returns all applicable classes with the canonical primary first.
fn classify_conflict(conflict_set: &ConflictSet) -> Vec<ConflictKind> {
    let mut applicable: BTreeSet<usize> = BTreeSet::new();
    for (index, kind) in KIND_PRECEDENCE.iter().enumerate() {
        if *kind == conflict_set.kind {
            applicable.insert(index);
        }
    }
    for kind in infer_additional_classes(conflict_set) {
        for (index, canonical) in KIND_PRECEDENCE.iter().enumerate() {
            if *canonical == kind {
                applicable.insert(index);
            }
        }
    }
    let mut out: Vec<ConflictKind> = Vec::new();
    for index in applicable {
        if let Some(kind) = KIND_PRECEDENCE.get(index) {
            out.push(*kind);
        }
    }
    out
}

/// Returns the canonical joined spelling of compared dimensions.
fn spell_dimensions(dimensions: &[ComparisonDimension]) -> String {
    dimensions
        .iter()
        .map(|dimension| dimension.as_str())
        .collect::<Vec<&str>>()
        .join("+")
}

/// Returns a deterministic spelling of one dimension outcome for the digest.
///
/// The two values of a `Differing` are spelled in sorted order because the
/// analysis never reads them in an orientation-dependent way: without this the
/// digest would be strictly more sensitive than the analysis it hashes, and the
/// same comparison supplied from either side would produce two digests for one
/// result.
fn dimension_outcome_spelling(outcome: &DimensionOutcome) -> String {
    match outcome {
        DimensionOutcome::Equal { value } => format!("equal:{}:{}", value.len(), value),
        DimensionOutcome::Differing { left, right } => {
            let mut values = [left.as_str(), right.as_str()];
            values.sort_unstable();
            format!(
                "differing:{}:{}{}:{}",
                values[0].len(),
                values[0],
                values[1].len(),
                values[1]
            )
        }
        DimensionOutcome::Unnormalizable { reason } => {
            format!("unnormalizable:{}:{}", reason.len(), reason)
        }
    }
}

/// Returns the peer source handle of one comparison for `source_handle`.
///
/// Every comparison naming this position contributes one entry, from either
/// side, so the mapping is symmetric.
fn comparison_peer<'a>(first: &'a str, second: &'a str, source_handle: &str) -> Option<&'a str> {
    if first == source_handle {
        Some(second)
    } else if second == source_handle {
        Some(first)
    } else {
        None
    }
}

/// Reorders one dimension's two admitted values into canonical pair order.
///
/// `swapped` is the single ordering decision the pair makes; the values move
/// with the source that declared them.
fn pair_dimension_outcome(
    _dimension: ComparisonDimension,
    first_value: &str,
    second_value: &str,
) -> DimensionOutcome {
    if first_value == second_value {
        DimensionOutcome::Equal {
            value: first_value.to_owned(),
        }
    } else {
        DimensionOutcome::Differing {
            left: first_value.to_owned(),
            right: second_value.to_owned(),
        }
    }
}

/// One comparison's locally derived relation and the records it came from.
struct DerivedRelation {
    relation: CompatibilityRelation,
    outcomes: Vec<DimensionComparison>,
    differing: Vec<ComparisonDimension>,
    coverage: EvidenceCoverage,
    note: String,
}

/// Collects one dimension's outcome from both admitted values, recording a
/// dimension as unresolved when either side is missing.
fn collect_dimension_outcome(
    comparison: &OwnerComparison,
    dimension: ComparisonDimension,
    unresolved: &mut Vec<ComparisonDimension>,
) -> DimensionOutcome {
    let first = comparison.value_for(&comparison.first_source, dimension);
    let second = comparison.value_for(&comparison.second_source, dimension);
    let (Some(left), Some(right)) = (first, second) else {
        {
            unresolved.push(dimension);
            return DimensionOutcome::Unnormalizable {
                reason: format!(
                    "no admitted value for dimension {} under owner profile {}",
                    dimension.as_str(),
                    comparison.profile.profile_id
                ),
            };
        }
    };
    pair_dimension_outcome(dimension, left, right)
}

/// Folds the owner-issued unnormalizable and unsupported dimensions into the
/// unresolved set, so an explicit owner gap can never be read as agreement.
fn collect_unresolved_dimensions(
    comparison: &OwnerComparison,
    unresolved: &mut Vec<ComparisonDimension>,
) {
    for dimension in comparison
        .unnormalizable_dimensions
        .iter()
        .chain(comparison.unsupported_dimensions.iter())
    {
        if !unresolved.contains(dimension) {
            unresolved.push(*dimension);
        }
    }
}

/// Derives the coverage of one comparison against the canonical denominator.
///
/// The expected set is the canonical eight dimensions this cell holds itself,
/// never a copy of the owner's own observed list.
fn derive_comparison_coverage(
    outcomes: &[DimensionComparison],
    all_resolved: bool,
) -> EvidenceCoverage {
    if all_resolved {
        return EvidenceCoverage::CompleteForScope;
    }
    let any_admitted = outcomes.iter().any(|entry| {
        matches!(
            entry.outcome,
            DimensionOutcome::Differing { .. } | DimensionOutcome::Equal { .. }
        )
    });
    if any_admitted {
        EvidenceCoverage::PartialForScope
    } else {
        EvidenceCoverage::Unknown
    }
}

/// Writes the bounded note naming the derived relation and its ceiling.
fn relation_note(
    comparison: &OwnerComparison,
    all_resolved: bool,
    differing: &[ComparisonDimension],
    unresolved: &[ComparisonDimension],
    coverage: EvidenceCoverage,
) -> String {
    let profile = &comparison.profile;
    if !all_resolved {
        return format!(
            "owner records retain dimensions {} unresolved, so no relation is derived; coverage is {}",
            spell_dimensions(unresolved),
            coverage_spelling(coverage)
        );
    }
    if differing.is_empty() {
        return format!(
            "all {EXPECTED_COMPARISON_DIMENSIONS} canonical dimensions carry equal admitted values under owner profile {}@{}; coverage is complete",
            profile.profile_id, profile.schema_revision
        );
    }
    format!(
        "admitted values differ in {} under owner profile {}@{}; coverage is complete",
        spell_dimensions(differing),
        profile.profile_id,
        profile.schema_revision
    )
}

/// Derives one comparison's relation from its admitted typed values.
///
/// The caller supplied no verdict. For every canonical dimension both exact
/// source values are required under the same admitted profile; only when all
/// eight are present and equal does the relation become
/// [`CompatibilityRelation::EqualConditions`], only when all eight are present
/// and at least one differs does it become [`CompatibilityRelation::TypedDifference`],
/// and a competent owner-issued unnormalizable or unsupported result, a
/// missing value, or partial coverage yields [`CompatibilityRelation::Ambiguous`]
/// while every declaration is preserved.
fn derive_owner_relation(comparison: &OwnerComparison) -> DerivedRelation {
    let mut outcomes: Vec<DimensionComparison> = Vec::with_capacity(EXPECTED_COMPARISON_DIMENSIONS);
    let mut differing: Vec<ComparisonDimension> = Vec::new();
    let mut unresolved: Vec<ComparisonDimension> = Vec::new();
    for dimension in COMPARISON_DIMENSIONS {
        let outcome = collect_dimension_outcome(comparison, dimension, &mut unresolved);
        if matches!(outcome, DimensionOutcome::Differing { .. }) {
            differing.push(dimension);
        }
        outcomes.push(DimensionComparison { dimension, outcome });
    }
    collect_unresolved_dimensions(comparison, &mut unresolved);
    let all_resolved = unresolved.is_empty();
    let coverage = derive_comparison_coverage(&outcomes, all_resolved);
    let relation = if !all_resolved {
        CompatibilityRelation::Ambiguous
    } else if differing.is_empty() {
        CompatibilityRelation::EqualConditions
    } else {
        CompatibilityRelation::TypedDifference
    };
    let note = relation_note(comparison, all_resolved, &differing, &unresolved, coverage);
    DerivedRelation {
        relation,
        outcomes,
        differing,
        coverage,
        note,
    }
}

/// Returns the canonical spelling of one evidence coverage value.
fn coverage_spelling(coverage: EvidenceCoverage) -> &'static str {
    match coverage {
        EvidenceCoverage::CompleteForScope => "complete_for_scope",
        EvidenceCoverage::PartialForScope => "partial_for_scope",
        EvidenceCoverage::NotApplicable => "not_applicable",
        EvidenceCoverage::Unknown => "unknown",
    }
}

/// Builds one compatibility entry for an owner-issued comparison.
fn owner_compatibility_entry(
    source_handle: &str,
    comparison: &OwnerComparison,
) -> Option<PositionCompatibility> {
    let peer = comparison_peer(
        &comparison.first_source,
        &comparison.second_source,
        source_handle,
    )?;
    let derived = derive_owner_relation(comparison);
    let mut unnormalizable: Vec<ComparisonDimension> = comparison.unnormalizable_dimensions.clone();
    unnormalizable.sort();
    unnormalizable.dedup();
    let mut unsupported: Vec<ComparisonDimension> = comparison.unsupported_dimensions.clone();
    unsupported.sort();
    unsupported.dedup();
    Some(PositionCompatibility {
        other_source: peer.to_owned(),
        relation: derived.relation,
        supplement_version: SupplementVersion::OwnerRecordV2,
        outcomes: derived.outcomes,
        differing_dimensions: derived.differing,
        unnormalizable_dimensions: unnormalizable,
        unsupported_dimensions: unsupported,
        coverage: derived.coverage,
        derivation_note: derived.note,
    })
}

/// Builds one compatibility entry for a legacy declaration.
fn legacy_compatibility_entry(
    source_handle: &str,
    comparison: &SuppliedComparison,
) -> Option<PositionCompatibility> {
    let peer = comparison_peer(
        &comparison.left_source,
        &comparison.right_source,
        source_handle,
    )?;
    // Canonical order comes from the dimension table, not from the order the
    // caller happened to supply the entries in. Sorting here as well as in
    // the digest is what keeps the two in step: otherwise two supplements
    // differing only in entry order would share a digest while emitting
    // byte-different analyses.
    let mut outcomes: Vec<DimensionComparison> = Vec::with_capacity(EXPECTED_COMPARISON_DIMENSIONS);
    let mut differing: Vec<ComparisonDimension> = Vec::new();
    let mut unnormalizable: Vec<ComparisonDimension> = Vec::new();
    for dimension in COMPARISON_DIMENSIONS {
        let Some(entry) = comparison
            .dimensions
            .iter()
            .find(|entry| entry.dimension == dimension)
        else {
            continue;
        };
        match &entry.outcome {
            DimensionOutcome::Differing { .. } => differing.push(dimension),
            DimensionOutcome::Unnormalizable { .. } => unnormalizable.push(dimension),
            DimensionOutcome::Equal { .. } => {}
        }
        outcomes.push(DimensionComparison {
            dimension,
            outcome: entry.outcome.clone(),
        });
    }
    Some(PositionCompatibility {
        other_source: peer.to_owned(),
        relation: CompatibilityRelation::Ambiguous,
        supplement_version: SupplementVersion::LegacyV1Unverified,
        outcomes,
        differing_dimensions: differing,
        unnormalizable_dimensions: unnormalizable,
        unsupported_dimensions: Vec::new(),
        coverage: EvidenceCoverage::Unknown,
        derivation_note: "legacy v1 declaration: no owner-bound source, profile, or value records, so no relation is derived".to_owned(),
    })
}

/// Builds one position's preserved mapping against every compared position.
///
/// An owner-issued comparison is preferred for a given peer, because it is the
/// only one that can carry a derived relation; a legacy declaration for the
/// same peer is still preserved under its own unverified ceiling rather than
/// being dropped or silently overwritten.
fn build_compatibility(
    source_handle: &str,
    supplements: &ConflictSupplements,
) -> Vec<PositionCompatibility> {
    let mut out: Vec<PositionCompatibility> = Vec::new();
    for comparison in &supplements.owner_records.comparisons {
        if let Some(entry) = owner_compatibility_entry(source_handle, comparison) {
            out.push(entry);
        }
    }
    for comparison in &supplements.comparisons {
        let Some(entry) = legacy_compatibility_entry(source_handle, comparison) else {
            continue;
        };
        if out
            .iter()
            .any(|existing| existing.other_source == entry.other_source)
        {
            continue;
        }
        out.push(entry);
    }
    out.sort_by(|left, right| left.other_source.cmp(&right.other_source));
    out
}

/// Renders the typed dimension mapping as a deterministic note clause.
///
/// The subject is the position that owns the note, so the clause names only the
/// other position; printing both would read as a source being in equal
/// conditions with itself. Growth is bounded by the input ceilings rather than
/// by a separate output ceiling.
fn compatibility_clause(mapping: &[PositionCompatibility]) -> String {
    let mut clauses: Vec<String> = Vec::with_capacity(mapping.len());
    for entry in mapping {
        let differing = if entry.differing_dimensions.is_empty() {
            String::new()
        } else {
            format!(
                " differing={}",
                spell_dimensions(&entry.differing_dimensions)
            )
        };
        let unnormalizable = if entry.unnormalizable_dimensions.is_empty() {
            String::new()
        } else {
            format!(
                " unnormalizable={}",
                spell_dimensions(&entry.unnormalizable_dimensions)
            )
        };
        clauses.push(format!(
            "against {}: {} {} coverage={}{}{}",
            entry.other_source,
            entry.relation.as_str(),
            entry.supplement_version.as_str(),
            coverage_spelling(entry.coverage),
            differing,
            unnormalizable
        ));
    }
    clauses.sort();
    format!("typed dimension mapping {}", clauses.join(","))
}

/// Extends one position's compatibility note with its typed dimension mapping.
///
/// A position with no supplied comparison keeps its note unchanged: an absent
/// mapping is recorded as absent and is never phrased as equal conditions.
fn compatibility_note_with_mapping(base: &str, mapping: &[PositionCompatibility]) -> String {
    if mapping.is_empty() {
        return base.to_owned();
    }
    format!("{base}; {}", compatibility_clause(mapping))
}

/// The one qualified comparison result a position's note and disposition share.
///
/// This is the only relation the analyzer may read out of the typed mapping. A
/// position's note and its [`PositionDispositionKind`] are both derived from
/// this single value, so prose and typing cannot disagree about the ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualifiedPositionRelation {
    /// No comparison of any kind names this position.
    Absent,
    /// A comparison names this position but no owner-issued record qualifies it,
    /// or a compared dimension could not be normalized.
    Unverified,
    /// An owner-issued comparison proves every canonical dimension equal.
    EqualConditions,
    /// An owner-issued comparison proves a difference on at least one condition
    /// dimension, so the claims are compatible residual claims.
    ConditionDifference,
    /// An owner-issued comparison proves a difference, but on no condition
    /// dimension; it does not establish compatible residue.
    OtherDimensionDifference,
}

impl QualifiedPositionRelation {
    /// Returns the non-assertive note this qualified result supports.
    ///
    /// Nothing here names equality or compatible residue unless the owner-issued
    /// comparison established it, so a missing or unnormalizable comparison can
    /// never assert equal conditions.
    fn note(self) -> String {
        match self {
            Self::Absent => String::from(
                "live position preserved; no supplied comparison establishes a relation with the other positions",
            ),
            Self::Unverified => String::from(
                "live position preserved; the supplied comparison carries no owner-issued record that resolves every canonical dimension, so no relation is established",
            ),
            Self::EqualConditions => String::from(
                "contradiction under equal subject, scope, time, version, and definition",
            ),
            Self::ConditionDifference => String::from(
                "compatible residual claim under different scope, population, or definition",
            ),
            Self::OtherDimensionDifference => String::from(
                "live position preserved; the owner-issued comparison proves a typed difference that does not bound scope, time, or definition",
            ),
        }
    }
}

/// Returns the single qualified relation one position's mapping supports.
///
/// The mapping is already the product of the owner-issued qualification in
/// [`build_compatibility`]: an entry reaches
/// [`SupplementVersion::OwnerRecordV2`] only when owner records resolved all
/// eight canonical dimensions, and a legacy declaration stays
/// [`SupplementVersion::LegacyV1Unverified`] with
/// [`CompatibilityRelation::Ambiguous`]. This reduction therefore reads no
/// source prose and adds no second classifier; it only resolves that mapping to
/// the one relation the position note and disposition may use. A position
/// compared against several others keeps the weakest result any of them
/// supports, so one qualified pair cannot lift a position past an unverified
/// comparison against a third position.
fn qualified_position_relation(mapping: &[PositionCompatibility]) -> QualifiedPositionRelation {
    if mapping.is_empty() {
        return QualifiedPositionRelation::Absent;
    }
    let mut all_equal = true;
    let mut condition_difference = false;
    for entry in mapping {
        if entry.supplement_version != SupplementVersion::OwnerRecordV2 {
            return QualifiedPositionRelation::Unverified;
        }
        match entry.relation {
            CompatibilityRelation::EqualConditions => {}
            CompatibilityRelation::TypedDifference => {
                all_equal = false;
                if entry
                    .differing_dimensions
                    .iter()
                    .any(|dimension| CONDITION_DIMENSIONS.contains(dimension))
                {
                    condition_difference = true;
                }
            }
            CompatibilityRelation::Ambiguous => {
                return QualifiedPositionRelation::Unverified;
            }
        }
    }
    if condition_difference {
        QualifiedPositionRelation::ConditionDifference
    } else if all_equal {
        QualifiedPositionRelation::EqualConditions
    } else {
        QualifiedPositionRelation::OtherDimensionDifference
    }
}

/// Applies the legacy v1 proof ceiling to one supplied declaration.
///
/// Caller prose is not owner-issued evidence. Causal and intervention claims
/// therefore stay [`CausalClaimState::Unknown`] regardless of whether all four
/// prose fields are nonblank. Lower-level structural, correlational, and
/// prediction declarations are preserved as declarations and explicitly
/// marked unverified; none is evidence-qualified by this projection.
///
/// The arms are the accepted shared relation vocabulary's readings, so this
/// ceiling is decided in the same vocabulary the owner-record path is and there
/// is no second spelling of the set to drift. The match is total and each
/// reading returns the state it may keep TOGETHER WITH the reason it is
/// reported there, which is why the pair is returned rather than assigned into
/// two pre-seeded locals: no reading of the vocabulary leaves the reason unset,
/// so a declared `unknown` cannot reach the candidate with a blank
/// `reduction_reason` the way a fall-through chain would let it.
fn effective_causal_claim(claim: &SuppliedCausalClaim) -> CausalClaimRecord {
    let (effective, reduction_reason) = match claim.declared_state.relation_status() {
        FailureCausalStatus::Structural | FailureCausalStatus::BehavioralCorrelation => (
            claim.declared_state,
            format!(
                "declared {} retained as legacy v1 unverified; declaration is not support evidence",
                claim.declared_state.as_str()
            ),
        ),
        FailureCausalStatus::CausalHypothesis | FailureCausalStatus::InterventionSupported => (
            CausalClaimState::Unknown,
            format!(
                "declared {} retained as legacy v1 unverified: owner-bound evidence and coverage are absent",
                claim.declared_state.as_str()
            ),
        ),
        FailureCausalStatus::PredictionSupported | FailureCausalStatus::Refuted => (
            CausalClaimState::Unknown,
            format!(
                "declared {} retained as legacy v1 unverified: outcome and verifier records are absent",
                claim.declared_state.as_str()
            ),
        ),
        FailureCausalStatus::Unknown => (
            CausalClaimState::Unknown,
            String::from(
                "declared unknown retained as legacy v1 unverified; no owner-bound evidence was supplied",
            ),
        ),
    };
    CausalClaimRecord {
        source_handle: claim.source_handle.clone(),
        declared_state: claim.declared_state,
        effective_state: effective,
        // A legacy declaration has no owner-issued revision behind it. Reporting
        // `None` rather than borrowing the mechanism revision keeps the
        // unverified ceiling honest: there is no snapshot this declaration was
        // read at, and inventing one would be exactly the widening the
        // separation forbids.
        declaration_revision: None,
        supplement_version: SupplementVersion::LegacyV1Unverified,
        reduction_reason,
        coverage: EvidenceCoverage::Unknown,
        evidence_coverage: EvidenceCoverage::Unknown,
        rival_coverage: EvidenceCoverage::Unknown,
        mechanism_claim_id: None,
    }
}

/// Returns the weaker of two coverage values.
///
/// `EvidenceCoverage` ranks a scope claim rather than being a plain scale, so
/// the ceiling a cell may report is the weaker of the two inputs: a complete
/// evidence set and a complete rival denominator each need the other before the
/// causal cell as a whole is complete, and an unknown on either side keeps the
/// whole unknown rather than smoothing it away.
fn lower_coverage(left: EvidenceCoverage, right: EvidenceCoverage) -> EvidenceCoverage {
    let rank = |coverage: EvidenceCoverage| -> u8 {
        match coverage {
            EvidenceCoverage::CompleteForScope => 3,
            EvidenceCoverage::PartialForScope => 2,
            EvidenceCoverage::NotApplicable => 1,
            EvidenceCoverage::Unknown => 0,
        }
    };
    if rank(left) <= rank(right) {
        left
    } else {
        right
    }
}

/// Returns the first evidence leg that blocks an evidence-qualified state, or
/// `None` when every required leg is present and qualifying.
///
/// The legs are checked in the order the issue names them so the reported
/// reason is the first real gap rather than an arbitrary one.
fn blocking_causal_leg(record: &CausalEvidenceRecord) -> Option<String> {
    if record.evidence.is_empty() {
        return Some("no owner evidence envelope is bound to this claim".to_owned());
    }
    if !record.evidence.iter().all(EvidenceRecord::qualifies) {
        return Some(
            "an envelope retains a lower authority, freshness, coverage, or assertability ceiling"
                .to_owned(),
        );
    }
    // The evidence set and the rival denominator are independent denominators,
    // so each is read on its own terms. Partial valid evidence is preserved and
    // still blocks the qualified state; it is never read as complete because the
    // OTHER denominator happened to be complete.
    let evidence_coverage = record.derived_evidence_coverage();
    if evidence_coverage != EvidenceCoverage::CompleteForScope {
        return Some(format!(
            "the retained evidence set is {} rather than complete",
            coverage_spelling(evidence_coverage)
        ));
    }
    if record.falsifier.observed == FalsifierStatus::Unobserved {
        return Some("the falsifier is specified but no status was observed".to_owned());
    }
    if record.control.evaluator_result != EvaluatorResult::Competent {
        return Some(format!(
            "the matched control carries an {} evaluator result",
            record.control.evaluator_result.as_str()
        ));
    }
    let coverage = record.rivals.derived_coverage();
    if coverage != EvidenceCoverage::CompleteForScope {
        return Some(format!(
            "the rival/confounder denominator is {} rather than complete",
            coverage_spelling(coverage)
        ));
    }
    None
}

/// Derives one causal assessment from its owner-issued evidence record.
///
/// The declared state is preserved verbatim. Prediction support, intervention
/// execution, and causal attribution stay distinct: each leg is checked against
/// the state the source actually declared, so a supported prediction never
/// becomes an intervention, an executed intervention never becomes a causal
/// attribution on its own, and correlation and chronology never promote
/// either. Anything short of the declared state's own requirements stays
/// [`CausalClaimState::Unknown`].
///
/// One step goes the other way and is equally load-bearing: an observed
/// falsifier that came back `Inconsistent` assesses the claim as
/// [`CausalClaimState::Refuted`] whatever label the source declared, so
/// counterevidence is carried into the assessment rather than dropped. It
/// reaches no leg that grants causality, so this does not merge the states
/// together.
///
/// Reaching [`CausalClaimState::Intervention`] additionally depends on admission
/// having proved the execution's receipt: [`CausalEvidenceRecord::validate`]
/// refuses a record whose `intervention.receipt_digest` is not the receipt of
/// one of its own retained envelopes. So the `Some(_)` arm below is reached
/// only for an owner-issued execution, never for a well-formed digest.
fn derive_causal_state(record: &CausalEvidenceRecord) -> CausalClaimState {
    if blocking_causal_leg(record).is_some() {
        return CausalClaimState::Unknown;
    }
    // The record's own observed falsifier is read against EVERY declared state
    // it can bear on, not against a hypothesis alone. An `Inconsistent` verdict
    // withdraws the claim whatever label the source gave it: publishing the
    // declared label as the effective state over evidence that contradicts it
    // is the one promotion this cell must never make, and it also drops
    // preserved counterevidence on the way out. `Refuted` is not a promotion
    // either — it takes the declared state away rather than granting a stronger
    // one, and it never reaches `InterventionSupported`, so a refuted
    // prediction still cannot become an intervention.
    if record.falsifier.observed == FalsifierStatus::Inconsistent
        && falsifier_bears_on(record.declared_state.relation_status())
    {
        return CausalClaimState::Refuted;
    }
    // The arms below are the accepted shared relation vocabulary's readings, not
    // this crate's own spellings, so the separation between prediction support,
    // intervention support, and attribution is decided once in the vocabulary
    // the rest of the system already reads. It is decided ARM BY ARM, and each
    // arm names only what its own reading requires: a supported prediction
    // returns the prediction reading and has no arm that could return the
    // intervention one, an intervention needs its own proved execution, and
    // structural and correlational edges reach nothing above themselves. There
    // is deliberately no arm here that grants one reading on the strength of
    // another's evidence.
    match record.declared_state.relation_status() {
        FailureCausalStatus::Structural => CausalClaimState::Structural,
        FailureCausalStatus::BehavioralCorrelation => CausalClaimState::Correlational,
        FailureCausalStatus::CausalHypothesis => CausalClaimState::CausalHypothesis,
        FailureCausalStatus::PredictionSupported => CausalClaimState::Prediction,
        FailureCausalStatus::InterventionSupported => match &record.intervention {
            Some(_) => CausalClaimState::Intervention,
            None => CausalClaimState::Unknown,
        },
        FailureCausalStatus::Refuted => match record.falsifier.observed {
            FalsifierStatus::Inconsistent => CausalClaimState::Refuted,
            _ => CausalClaimState::Unknown,
        },
        FailureCausalStatus::Unknown => CausalClaimState::Unknown,
    }
}

/// Returns whether an observed falsifier verdict bears on this declared reading.
///
/// This is the W7 separation read in the shared vocabulary: a refutation
/// withdraws a structural, correlational, hypothesis, or prediction claim, and
/// it withdraws nothing else. `INTERVENTION_SUPPORTED` is excluded on purpose.
/// An intervention is not falsified by the claim's own mechanism falsifier
/// running inconsistent — the falsifier tests the mechanism, and folding that
/// into the intervention reading would let a mechanism refutation read as an
/// intervention refutation, merging two readings the contract keeps apart.
fn falsifier_bears_on(status: FailureCausalStatus) -> bool {
    matches!(
        status,
        FailureCausalStatus::Structural
            | FailureCausalStatus::BehavioralCorrelation
            | FailureCausalStatus::CausalHypothesis
            | FailureCausalStatus::PredictionSupported
    )
}

/// Builds one causal assessment from an owner-issued evidence record.
fn owner_causal_record(record: &CausalEvidenceRecord) -> CausalClaimRecord {
    let rival_coverage = record.rivals.derived_coverage();
    let evidence_coverage = record.derived_evidence_coverage();
    let coverage = lower_coverage(evidence_coverage, rival_coverage);
    let effective = derive_causal_state(record);
    let reduction_reason = match blocking_causal_leg(record) {
        Some(gap) => format!(
            "declared {} stays unknown under owner records: {gap}; evidence coverage is {} and rival coverage is {}",
            record.declared_state.as_str(),
            coverage_spelling(evidence_coverage),
            coverage_spelling(rival_coverage)
        ),
        None if effective == record.declared_state => format!(
            "declared {} retained under owner mechanism claim {}@{} with complete evidence and rival coverage",
            record.declared_state.as_str(),
            record.mechanism.claim_id,
            record.mechanism.source_revision
        ),
        None => format!(
            "declared {} qualified down to {} under owner records: the evidence supports the lower state only",
            record.declared_state.as_str(),
            effective.as_str()
        ),
    };
    CausalClaimRecord {
        source_handle: record.source_handle.clone(),
        declared_state: record.declared_state,
        effective_state: effective,
        // The declaration is reported with the revision it was read at, and
        // admission has already compared that revision to the retained source
        // member's own (`check_mechanism_revision`), so this is the revision
        // whose bytes the preserved declaration came out of. It travels beside
        // `declared_state` rather than inside the assessment so the source's
        // claim and the evidence judged against it stay separately traceable.
        declaration_revision: Some(record.mechanism.source_revision.clone()),
        supplement_version: SupplementVersion::OwnerRecordV2,
        reduction_reason,
        coverage,
        evidence_coverage,
        rival_coverage,
        mechanism_claim_id: Some(record.mechanism.claim_id.clone()),
    }
}

/// Preserves every supplied and every owner-issued causal claim.
///
/// Both are kept, at their own ceilings, even when they name the same source.
/// An owner-issued record carries the evidence-qualified assessment; a legacy
/// declaration for that source is still preserved under its own unverified
/// ceiling rather than dropped. Collapsing the two would let an owner record
/// silently delete a source's own declared claim, and W6's first requirement is
/// that the declaration survive verbatim. They stay distinguishable because
/// `supplement_version` is read on each record, so the unverified entry cannot
/// be mistaken for the qualified one, and neither is recomputed from the other.
fn collect_causal_claims(supplements: &ConflictSupplements) -> Vec<CausalClaimRecord> {
    let mut out: Vec<CausalClaimRecord> = supplements
        .owner_records
        .causal_evidence
        .iter()
        .map(owner_causal_record)
        .collect();
    for claim in &supplements.causal_claims {
        out.push(effective_causal_claim(claim));
    }
    // `SupplementVersion` carries no `Ord`, so the ceiling is ordered by its
    // canonical spelling. The spelling is total and distinct per variant, so the
    // order is deterministic without adding an ordering the enum does not need
    // for anything else.
    out.sort_by(|left, right| {
        left.source_handle.cmp(&right.source_handle).then(
            left.supplement_version
                .as_str()
                .cmp(right.supplement_version.as_str()),
        )
    });
    out
}

/// Returns the history disposition this position's canonical record supports.
///
/// History is retained on its own evidence and is never gated on the comparison
/// axis: a superseded or refuted position keeps its addressable history whatever
/// the comparison establishes. A minority position is not refuted by a defeated
/// counterexample, so the refutation leg is skipped for it.
fn history_disposition(
    conflict_set: &ConflictSet,
    minority: bool,
    counters: &[String],
) -> Option<(PositionDispositionKind, String)> {
    if conflict_set.lifecycle == ConflictLifecycle::Superseded
        && !conflict_set.resolved_parts.is_empty()
    {
        return Some((
            PositionDispositionKind::SupersededHistory,
            String::from("superseded history retained as addressable history"),
        ));
    }
    if minority || counters.is_empty() {
        return None;
    }
    // `defeated_refs` holds `ArtifactId`, so it is projected to its string form
    // once and compared as text, the same way the pre-existing superseded check
    // reads it. Comparing `&String` against the set directly would not compile,
    // and the projection is a membership question, not a second value.
    let defeated: Vec<&str> = conflict_set
        .defeated_refs
        .iter()
        .map(eliot_contracts::ArtifactId::as_str)
        .collect();
    for counter in counters {
        if defeated.contains(&counter.as_str()) {
            return Some((
                PositionDispositionKind::Refuted,
                String::from("refuted position retained as addressable history"),
            ));
        }
    }
    None
}

/// Disposes one position without choosing a winner.
///
/// The comparison axis is read once. [`build_compatibility`] produces the typed
/// mapping, [`qualified_position_relation`] reduces it to the single relation
/// that mapping supports, and both the disposition and the note are taken from
/// that one value. The minority and history axes stay independent of it, so no
/// disposition is collapsed into a single flag.
fn dispose_position(
    index: usize,
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    classes: &[ConflictKind],
) -> PositionAnalysis {
    let empty_position = conflict_set.positions.get(index);
    let (source_handle, stance, minority, assumptions, counters) = match empty_position {
        Some(position) => (
            position.source.as_str().to_owned(),
            position.stance.clone(),
            position.minority,
            position
                .assumptions
                .iter()
                .map(|item| item.as_str().to_owned())
                .collect::<Vec<String>>(),
            position
                .counters
                .iter()
                .map(|item| item.as_str().to_owned())
                .collect::<Vec<String>>(),
        ),
        None => (
            "unknown".to_owned(),
            String::new(),
            false,
            Vec::new(),
            Vec::new(),
        ),
    };
    // The comparison axis is read exactly once. The note and the disposition
    // below are both projections of this single qualified value, so neither can
    // claim a proof ceiling the typed mapping does not carry.
    let compatibility_map = build_compatibility(&source_handle, supplements);
    let relation = qualified_position_relation(&compatibility_map);
    let mut disposition = PositionDispositionKind::LivePreserved;
    let mut compatibility = relation.note();
    if minority {
        disposition = PositionDispositionKind::MinorityPreserved;
        compatibility =
            String::from("minority position retained; majority count does not determine support");
    } else if relation == QualifiedPositionRelation::ConditionDifference {
        disposition = PositionDispositionKind::CompatibleResidue;
    }
    if let Some((history, history_note)) = history_disposition(conflict_set, minority, &counters) {
        disposition = history;
        compatibility = history_note;
    }
    if claims_chronology_is_causality(&stance) || claims_count_is_truth(&stance) {
        compatibility = format!(
            "{compatibility}; chronology, count, confidence, recency, or topology is not causal or truth evidence"
        );
    }
    let compatibility_note = compatibility_note_with_mapping(&compatibility, &compatibility_map);
    PositionAnalysis {
        position_index: index,
        source_handle,
        stance,
        minority,
        disposition,
        conflict_classes: classes.to_vec(),
        compatibility_note,
        assumptions,
        counters,
        compatibility: compatibility_map,
    }
}

// ---------------------------------------------------------------------------
// Probe discrimination (supplied declarations only, never executed).
// ---------------------------------------------------------------------------

/// Returns the digest-bearing identity of one update target for comparison.
fn update_fingerprint(update: &ResultUpdate) -> String {
    match update {
        ResultUpdate::Rival {
            model,
            prediction,
            meaning,
        } => {
            let prediction_text = prediction.as_ref().map_or_else(
                || "none".to_owned(),
                |reference| {
                    format!(
                        "{}@{}",
                        reference.prediction_id.as_str(),
                        reference.prediction_digest
                    )
                },
            );
            format!(
                "rival:{}@{}:{}:{prediction_text}:{}",
                model.model_id.as_str(),
                model.model_revision,
                model.declaration_digest,
                match meaning {
                    eliot_dreamer_contracts::RivalUpdateMeaning::Strengthened => "strengthened",
                    eliot_dreamer_contracts::RivalUpdateMeaning::Weakened => "weakened",
                    eliot_dreamer_contracts::RivalUpdateMeaning::Unchanged => "unchanged",
                }
            )
        }
        ResultUpdate::Gap { objective, meaning } => format!(
            "gap:{}@{}:{}",
            objective.objective_id.as_str(),
            objective.objective_digest,
            match meaning {
                eliot_dreamer_contracts::GapUpdateMeaning::Addressed => "addressed",
                eliot_dreamer_contracts::GapUpdateMeaning::PartiallyAddressed => {
                    "partially_addressed"
                }
                eliot_dreamer_contracts::GapUpdateMeaning::RemainsOpen => "remains_open",
            }
        ),
        ResultUpdate::Unknown { target, reason } => {
            let target_text = match target {
                ResultTarget::Rival { model, prediction } => format!(
                    "rival-target:{}:{}",
                    model.model_id.as_str(),
                    prediction.as_ref().map_or_else(
                        || "none".to_owned(),
                        |reference| reference.prediction_id.as_str().to_owned()
                    )
                ),
                ResultTarget::Gap { objective } => {
                    format!("gap-target:{}", objective.objective_id.as_str())
                }
            };
            format!("unknown:{target_text}:{reason}")
        }
    }
}

/// Returns true when the schema branches differ in at least one update.
fn branches_discriminate(schema: &PossibleResultSchema) -> bool {
    if schema.branches.len() < 2 {
        return false;
    }
    let first_fingerprint = schema.branches.first().map(|branch| {
        let mut parts: Vec<String> = branch.updates.iter().map(update_fingerprint).collect();
        parts.sort();
        parts
    });
    for branch in schema.branches.iter().skip(1) {
        let mut parts: Vec<String> = branch.updates.iter().map(update_fingerprint).collect();
        parts.sort();
        if Some(&parts) != first_fingerprint.as_ref() {
            return true;
        }
    }
    false
}

/// Returns the unknown this probe resolves, when its objective names one.
///
/// Qualification is exact identity, never containment. The objective's own
/// invalidation condition must carry the unknown's text verbatim, so a
/// rationale that merely mentions an unknown resolves nothing and a shorter
/// identity never matches a longer one. Nothing here is prose-smoothed: the
/// returned unknown is the caller's own declaration, copied back unchanged.
fn resolves_unknown(probe: &SuppliedProbe, unknowns: &[String]) -> Option<String> {
    for condition in &probe.objective.invalidation_conditions {
        for unknown in unknowns {
            if condition.assumption_id == *unknown {
                return Some(unknown.clone());
            }
        }
    }
    None
}

/// Returns the positions the `ConflictSet` itself proves a probe separates.
///
/// The only target-to-position binding the canonical probe contracts carry is
/// the set's own `discriminative_probe` handle: when it names this probe
/// exactly, the set declares that the probe separates its own positions.
/// Rival-model and gap-objective result targets carry no position `SourceId`,
/// so any other probe has no proven mapping here and names none, rather than
/// inheriting every position in the set.
fn proven_target_position_coverage(
    conflict_set: &ConflictSet,
    probe: &SuppliedProbe,
    position_sources: &[String],
) -> Vec<String> {
    if conflict_set.probe.as_deref() != Some(probe.probe_id.as_str()) {
        return Vec::new();
    }
    let mut covered: Vec<String> = position_sources.to_vec();
    covered.sort();
    covered.dedup();
    covered
}

/// Builds the recommended probe list from supplied declarations only.
fn recommend_probes(
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    position_sources: &[String],
) -> Vec<RecommendedProbe> {
    let mut out: Vec<RecommendedProbe> = Vec::new();
    for probe in &supplements.supplied_probes {
        if probe.blocked || probe.over_budget {
            continue;
        }
        let matrix_separates = branches_discriminate(&probe.schema);
        let resolved = resolves_unknown(probe, &supplements.unknowns);
        if !matrix_separates && resolved.is_none() {
            continue;
        }
        let covered = proven_target_position_coverage(conflict_set, probe, position_sources);
        out.push(RecommendedProbe {
            probe_id: probe.probe_id.clone(),
            objective_digest: probe.objective.digest.clone(),
            result_digest: probe.schema.digest.clone(),
            discriminates_positions: covered,
            resolves_unknown: resolved,
            owner: probe.owner_note.clone(),
            verifier: probe.verifier.clone(),
            cost_note: probe.cost_note.clone(),
            risk_note: probe.risk_note.clone(),
            privacy_note: probe.privacy_note.clone(),
            effect_note: probe.effect_note.clone(),
        });
    }
    out.sort_by(|left, right| left.probe_id.cmp(&right.probe_id));
    out
}

// ---------------------------------------------------------------------------
// Owner recommendation (naming only, never assignment or authority).
// ---------------------------------------------------------------------------

/// Recommends the exact external owner for the affected boundary.
///
/// The kind is named, never assigned: no owner is messaged, launched, or
/// authorized here, and the recommendation is a proposal that the emitted
/// candidate carries. Where the set's own authority evidence names no decider,
/// the kind stays [`DecisionOwnerKind::Unknown`] rather than falling back to the
/// conflict-kind default.
fn recommend_owner(
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    groups: &[LineageGroup],
    recommended_probes: &[RecommendedProbe],
) -> DecisionOwnerRecommendation {
    let base = match conflict_set.kind {
        ConflictKind::Epistemic => DecisionOwnerKind::EvidenceSource,
        ConflictKind::State | ConflictKind::Authority | ConflictKind::Resource => {
            DecisionOwnerKind::Governor
        }
        ConflictKind::Plan | ConflictKind::Instruction => DecisionOwnerKind::HumanTaskController,
        ConflictKind::Artifact | ConflictKind::Architecture => {
            DecisionOwnerKind::ArchitectureImplementation
        }
    };
    let mut kind = base;
    let mut rationale = format!(
        "affected {} boundary in scope {}",
        kind_to_spelling(conflict_set.kind),
        conflict_set.scope
    );
    let mut contract_needed =
        String::from("grounded evidence and decision receipt for the affected boundary");
    let joined_unknowns = lowered(&supplements.unknowns.join("\n"));
    if contains_marker(&joined_unknowns, "privacy") || contains_marker(&joined_unknowns, "security")
    {
        kind = DecisionOwnerKind::SecurityPrivacy;
        rationale = String::from("privacy or security handling boundary requires clearance");
        contract_needed = String::from("privacy and security handling contract with verifier");
    } else {
        let mut shared_evaluator = false;
        for group in groups {
            let low = lowered(&group.lineage_root);
            if group.known && (contains_marker(&low, "evaluator") || contains_marker(&low, "model"))
            {
                shared_evaluator = true;
            }
        }
        if shared_evaluator {
            kind = DecisionOwnerKind::EvaluatorVerifier;
            rationale = String::from("shared model or evaluator limits independence");
            contract_needed = String::from("independent evaluator verdict with holdout evidence");
        } else if conflict_set.positions.len() >= 3 && recommended_probes.is_empty() {
            kind = DecisionOwnerKind::ConciliumReview;
            rationale =
                String::from("multi-position conflict with no discriminative probe needs review");
            contract_needed = String::from(
                "Concilium review request with preserved dissent; this cell launches nothing",
            );
        } else if conflict_set.owners.len() > 1 && conflict_set.unresolved_owners.len() > 1 {
            kind = DecisionOwnerKind::Multiple;
            rationale = String::from("multiple unresolved owners remain in conflict");
            contract_needed = String::from("owner-scoped evidence for each unresolved owner");
        } else if !conflict_set.owners.contains(&conflict_set.decision_owner) {
            // I13.2 keeps `authority_and_owners` and `decision_owner` as two
            // separate fields. When the named decider is not one of the set's
            // own authority owners, that evidence names no decider, and with the
            // multiple-owner leg already excluded there is no single owner left
            // to name. Adopting the kind-derived default here would report a
            // coverage the grounded evidence does not carry.
            kind = DecisionOwnerKind::Unknown;
            rationale = String::from(
                "the set names a decision owner outside its own authority owner set, so no single owner can be named from the grounded evidence",
            );
            contract_needed = String::from(
                "authority owner set containing the decision owner, or an owner-issued assignment naming the decider",
            );
        }
    }
    let owner_handle = conflict_set.decision_owner.as_str().to_owned();
    DecisionOwnerRecommendation {
        kind,
        owner_handle,
        rationale,
        contract_needed,
    }
}

// ---------------------------------------------------------------------------
// Preservation (seven independent dimensions, no averaging).
// ---------------------------------------------------------------------------

/// Checks the seven preservation dimensions for this transformation.
#[allow(clippy::too_many_lines)]
fn check_preservation(
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    positions: &[PositionAnalysis],
    groups: &[LineageGroup],
    recommended_probes: &[RecommendedProbe],
    owner: &DecisionOwnerRecommendation,
) -> PreservationReport {
    let coverage_passed = positions.len() == conflict_set.positions.len()
        && supplements.objections.len() <= MAX_OBJECTIONS
        && supplements.supplied_probes.len() <= MAX_PROBES;
    let coverage_note = if coverage_passed {
        format!(
            "every expected position, objection, and source retained or explicitly unavailable ({} positions)",
            positions.len()
        )
    } else {
        "coverage shortfall: expected members missing".to_owned()
    };
    let faithfulness_passed = !positions.is_empty()
        && !claims_count_is_truth(
            &positions
                .iter()
                .map(|p| p.stance.as_str())
                .collect::<Vec<&str>>()
                .join("\n"),
        );
    let faithfulness_note = if faithfulness_passed {
        "analysis preserves dissent; count, confidence, and recency choose no winner".to_owned()
    } else {
        "faithfulness shortfall: count or confidence offered as truth".to_owned()
    };
    let mut lineage_passed = true;
    for position in positions {
        if position.source_handle.trim().is_empty() {
            lineage_passed = false;
        }
    }
    for group in groups {
        if group.member_sources.is_empty() {
            lineage_passed = false;
        }
    }
    let lineage_note = if lineage_passed {
        "every claim traces to its source and lineage handles".to_owned()
    } else {
        "lineage shortfall: untraced claim".to_owned()
    };
    let reversibility_passed = !positions.is_empty();
    let reversibility_note = if reversibility_passed {
        "analysis rolls back by dropping the candidate; invalidation conditions reopen review"
            .to_owned()
    } else {
        "reversibility shortfall: no rollback boundary".to_owned()
    };
    let authority_passed = !owner.owner_handle.trim().is_empty();
    let authority_note = if owner.kind == DecisionOwnerKind::Unknown {
        String::from(
            "candidate claims no authority beyond proposal; no owner could be named from the grounded evidence, so the unnamed recommendation and its gap stay visible",
        )
    } else {
        String::from(
            "candidate claims no authority beyond proposal; recommendation names the external owner",
        )
    };
    let dependency_passed = groups.len() <= MAX_LINEAGE && recommended_probes.len() <= MAX_PROBES;
    let dependency_note = if dependency_passed {
        "all lineage, probe, and owner dependencies are closed and named".to_owned()
    } else {
        "dependency shortfall: open dependency".to_owned()
    };
    let mut provenance_passed = true;
    for (index, position) in positions.iter().enumerate() {
        if let Some(original) = conflict_set.positions.get(index) {
            if position.stance != original.stance
                || position.minority != original.minority
                || position.source_handle != original.source.as_str()
            {
                provenance_passed = false;
            }
        } else {
            provenance_passed = false;
        }
    }
    let provenance_note = if provenance_passed {
        "original propositions, minority flags, and provenance retained verbatim".to_owned()
    } else {
        "provenance shortfall: original rewritten".to_owned()
    };
    PreservationReport {
        verdicts: vec![
            DimensionVerdict {
                dimension: PreservationDimension::Coverage,
                passed: coverage_passed,
                known: true,
                note: coverage_note,
            },
            DimensionVerdict {
                dimension: PreservationDimension::Faithfulness,
                passed: faithfulness_passed,
                known: true,
                note: faithfulness_note,
            },
            DimensionVerdict {
                dimension: PreservationDimension::Lineage,
                passed: lineage_passed,
                known: true,
                note: lineage_note,
            },
            DimensionVerdict {
                dimension: PreservationDimension::Reversibility,
                passed: reversibility_passed,
                known: true,
                note: reversibility_note,
            },
            DimensionVerdict {
                dimension: PreservationDimension::AuthorityCeiling,
                passed: authority_passed,
                known: true,
                note: authority_note,
            },
            DimensionVerdict {
                dimension: PreservationDimension::DependencyClosure,
                passed: dependency_passed,
                known: true,
                note: dependency_note,
            },
            DimensionVerdict {
                dimension: PreservationDimension::ProvenanceRetention,
                passed: provenance_passed,
                known: true,
                note: provenance_note,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Digest and emission.
// ---------------------------------------------------------------------------

/// Builds the sorted digest parts binding the legacy v1 comparison and causal
/// declaration inputs.
///
/// Both lists are bound whole: a caller that changes a declared value, outcome,
/// or causal prose moves the candidate digest. This digest binds declarations,
/// not their truth or owner qualification. The comparison pair key is
/// order-independent, so supplying the same pair from either side yields the
/// same digest.
fn comparison_and_causal_digest_parts(supplements: &ConflictSupplements) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for comparison in &supplements.comparisons {
        let mut dimensions: Vec<String> = comparison
            .dimensions
            .iter()
            .map(|entry| {
                format!(
                    "{}={}",
                    entry.dimension.as_str(),
                    dimension_outcome_spelling(&entry.outcome)
                )
            })
            .collect();
        dimensions.sort();
        parts.push(format!(
            "comparison:{}:{}",
            comparison_pair_key(&comparison.left_source, &comparison.right_source),
            dimensions.join(",")
        ));
    }
    for claim in &supplements.causal_claims {
        parts.push(format!(
            "causal:{}:{}:{}:{}:{}:{}",
            claim.source_handle,
            claim.declared_state.as_str(),
            claim.mechanism,
            claim.falsifier,
            claim.control_evaluator,
            claim.rivals_or_confounders
        ));
    }
    parts.sort();
    parts
}

/// Builds the digest parts committing the owner-issued source records, profile,
/// observed values, evidence receipts, and coverage.
///
/// The candidate identity binds the exact owner material, not the assertions
/// made about it: a changed source byte or revision, a changed profile
/// definition, a changed receipt, or a changed observed value all move the
/// digest, so a changed owner record can never share a candidate identity with
/// the analysis that admitted the earlier one.
fn owner_record_digest_parts(records: &OwnerRecords) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for member in &records.source_members {
        parts.push(format!(
            "source_member:{}:{}:{}:{}:{}",
            member.position_source,
            member.source_owner,
            member.record_digest,
            member.source_revision,
            member.source_snapshot
        ));
    }
    for comparison in &records.comparisons {
        let derived = derive_owner_relation(comparison);
        parts.push(format!(
            "owner_profile:{}:{}:{}:{}:{}:{}:{}:{}",
            comparison.first_source,
            comparison.second_source,
            comparison.profile.profile_id,
            comparison.profile.owner,
            comparison.profile.schema_revision,
            comparison.profile.definition_digest,
            comparison.profile.missing_disposition.as_str(),
            comparison.profile.unsupported_disposition.as_str()
        ));
        for dimension in COMPARISON_DIMENSIONS {
            for source in [&comparison.first_source, &comparison.second_source] {
                let value = comparison.value_for(source, dimension).unwrap_or("absent");
                parts.push(format!(
                    "owner_value:{source}:{}:{value}",
                    dimension.as_str()
                ));
            }
        }
        parts.push(format!(
            "owner_relation:{}:{}:{}:{}",
            comparison.first_source,
            comparison.second_source,
            derived.relation.as_str(),
            coverage_spelling(derived.coverage)
        ));
    }
    for record in &records.causal_evidence {
        parts.extend(causal_evidence_digest_parts(record));
    }
    parts.sort();
    parts
}

/// Builds the digest parts committing one owner-issued causal evidence record.
fn causal_evidence_digest_parts(record: &CausalEvidenceRecord) -> Vec<String> {
    let mut parts: Vec<String> = vec![format!(
        "causal_evidence:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        record.source_handle,
        record.declared_state.as_str(),
        record.mechanism.claim_id,
        record.mechanism.source_revision,
        record.mechanism.claim_digest,
        record.falsifier.observed.as_str(),
        record.falsifier.evidence_id,
        record.control.control_id,
        record.control.owner,
        record.control.evaluator_result.as_str(),
        record.control.evidence_id
    )];
    // `map_or` cannot unify an `&str` default with a `String` closure result,
    // and the two branches are genuinely different types, so this is an
    // explicit match rather than a coerced default.
    let intervention = match record.intervention.as_ref() {
        Some(binding) => format!("{}:{}", binding.execution_id, binding.receipt_digest),
        None => String::from("absent"),
    };
    parts.push(format!(
        "causal_intervention:{}:{intervention}",
        record.source_handle
    ));
    for handle in &record.rivals.omitted {
        parts.push(format!("rival_omitted:{}:{handle}", record.source_handle));
    }
    for evidence in &record.evidence {
        // The envelope's own coverage and provenance are bound here because
        // admission and qualification now both read them: a preimage that
        // omitted them would keep one candidate identity across a changed
        // coverage ceiling or a changed capture revision.
        let revision = evidence
            .envelope
            .provenance
            .revision
            .as_deref()
            .unwrap_or("absent");
        parts.push(format!(
            "causal_evidence_envelope:{}:{}:{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{:?}:{}:{revision}",
            record.source_handle,
            evidence.evidence_id,
            evidence.owner,
            evidence.material_digest,
            evidence.receipt_digest,
            evidence.envelope.status,
            evidence.envelope.authority,
            evidence.envelope.freshness,
            evidence.envelope.assertability,
            evidence.envelope.coverage,
            evidence.envelope.provenance.scope,
        ));
    }
    // The derived assessment is committed as well as the inputs it is derived
    // from: a preimage that binds the committed inputs but not the mapping they
    // produce does not bind the mapping, so a changed derived state or derived
    // coverage would otherwise keep one candidate identity. The published
    // record's own fields are read here rather than re-derived, so this part
    // cannot disagree with the `CausalClaimRecord` the analysis emits. The two
    // coverage cells are committed separately because they are separate
    // denominators, and the weaker combined one is committed with them. #2870's
    // versioned candidate preimage is the consumer that depends on this
    // binding; it still has to read the published surfaces itself.
    let derived = owner_causal_record(record);
    // The declaration's own revision is committed with the assessment. It is
    // already committed above as the mechanism claim's revision, and admission
    // has proved the two are the same string, so this is not a second copy of
    // the value: it is the published cell's separate declaration field entering
    // the preimage, which is what keeps one candidate identity from spanning a
    // change to the snapshot the source's claim was read at.
    parts.push(format!(
        "causal_derived:{}:{}:{}:{}:{}:{}:{}",
        derived.source_handle,
        derived.declared_state.as_str(),
        derived.declaration_revision.as_deref().unwrap_or("absent"),
        derived.effective_state.as_str(),
        coverage_spelling(derived.coverage),
        coverage_spelling(derived.evidence_coverage),
        coverage_spelling(derived.rival_coverage)
    ));
    parts
}

/// Computes the deterministic digest binding the analyzed inputs.
pub fn compute_candidate_digest(
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    policy: &ConflictAnalysisPolicy,
    positions: &[PositionAnalysis],
    recommended_probes: &[RecommendedProbe],
    owner: &DecisionOwnerRecommendation,
    outcome_spelling: &str,
) -> Result<String, ConflictAnalysisError> {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("conflict:{}", conflict_set.conflict_id));
    parts.push(format!("kind:{}", kind_to_spelling(conflict_set.kind)));
    parts.push(format!("scope:{}", conflict_set.scope));
    parts.push(format!("digest:{}", conflict_set.digest));
    parts.push(format!("outcome:{outcome_spelling}"));
    parts.push(format!(
        "policy:{}@{}",
        policy.policy_id, policy.policy_revision
    ));
    parts.push(format!("bundle:{}", supplements.frozen_bundle_digest));
    parts.push(format!("manifest:{}", supplements.frozen_manifest_digest));
    let mut index = 0usize;
    while index < positions.len() {
        if let Some(position) = positions.get(index) {
            parts.push(format!(
                "position:{}|{}|{}|{}|{}",
                position.position_index,
                position.source_handle,
                position.disposition.as_str(),
                position.stance,
                // The note is where the qualified relation is spelled out, so a
                // disposition or mapping that changed its proof ceiling cannot
                // hide behind an unchanged position identity.
                position.compatibility_note
            ));
            let mut classes: Vec<String> = position
                .conflict_classes
                .iter()
                .map(|kind| kind_to_spelling(*kind))
                .collect();
            classes.sort();
            for class in classes {
                parts.push(format!("class:{}:{class}", position.position_index));
            }
        }
        index = index.saturating_add(1);
    }
    let mut objections: Vec<String> = supplements
        .objections
        .iter()
        .map(|objection| {
            format!(
                "objection:{}:{}",
                objection.objection_id, objection.statement
            )
        })
        .collect();
    objections.sort();
    parts.extend(objections);
    let mut evidence: Vec<String> = supplements
        .counterevidence
        .iter()
        .map(|entry| format!("counter:{entry}"))
        .chain(
            supplements
                .unknowns
                .iter()
                .map(|entry| format!("unknown:{entry}")),
        )
        .chain(
            supplements
                .assumptions
                .iter()
                .map(|entry| format!("assumption:{entry}")),
        )
        .collect();
    evidence.sort();
    parts.extend(evidence);
    let mut probes: Vec<String> = recommended_probes
        .iter()
        .map(|probe| {
            format!(
                "probe:{}:{}:{}",
                probe.probe_id, probe.objective_digest, probe.result_digest
            )
        })
        .collect();
    probes.sort();
    parts.extend(probes);
    parts.extend(comparison_and_causal_digest_parts(supplements));
    parts.extend(owner_record_digest_parts(&supplements.owner_records));
    parts.push(format!(
        "owner:{}:{}",
        owner.kind.as_str(),
        owner.owner_handle
    ));
    parts.sort();
    canonical_json_bytes(&parts)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| ConflictAnalysisError::Digest {
            detail: redact(&err.to_string()),
        })
}

/// Returns the canonical spelling of one conflict kind.
fn kind_to_spelling(kind: ConflictKind) -> String {
    match kind {
        ConflictKind::Epistemic => "EPISTEMIC".to_owned(),
        ConflictKind::State => "STATE".to_owned(),
        ConflictKind::Plan => "PLAN".to_owned(),
        ConflictKind::Authority => "AUTHORITY".to_owned(),
        ConflictKind::Artifact => "ARTIFACT".to_owned(),
        ConflictKind::Instruction => "INSTRUCTION".to_owned(),
        ConflictKind::Resource => "RESOURCE".to_owned(),
        ConflictKind::Architecture => "ARCHITECTURE".to_owned(),
    }
}

/// Builds invalidation conditions that reopen this analysis.
fn build_invalidation_conditions(
    supplements: &ConflictSupplements,
    groups: &[LineageGroup],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for unknown in &supplements.unknowns {
        out.push(format!("if {unknown} resolves, reopen the analysis"));
    }
    for assumption in &supplements.assumptions {
        out.push(format!("if {assumption} is withdrawn, reopen the analysis"));
    }
    for group in groups {
        if !group.known {
            out.push(format!(
                "if lineage for {} becomes known, regroup independence",
                group.member_sources.join(",")
            ));
        }
    }
    out.push("if the frozen bundle, manifest, draft, or receipt binding moves, replay".to_owned());
    out.push("if an external resolution receipt arrives, retain it with dissent".to_owned());
    out.sort();
    out.dedup();
    out
}

/// Emits the terminal candidate envelope for one resolved outcome.
#[allow(clippy::too_many_arguments)]
fn emit_candidate(
    outcome: ConflictOutcome,
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    policy: &ConflictAnalysisPolicy,
    positions: &[PositionAnalysis],
    groups: &[LineageGroup],
    independent: usize,
    risks: &[CommonModeRisk],
    recommended_probes: &[RecommendedProbe],
    owner: &DecisionOwnerRecommendation,
    note: &str,
) -> Result<ConflictAnalysisCandidate, ConflictAnalysisError> {
    let preservation = check_preservation(
        conflict_set,
        supplements,
        positions,
        groups,
        recommended_probes,
        owner,
    );
    preservation.validate()?;
    let digest = compute_candidate_digest(
        conflict_set,
        supplements,
        policy,
        positions,
        recommended_probes,
        owner,
        outcome.as_str(),
    )?;
    let mut sorted_positions = positions.to_vec();
    sorted_positions.sort_by_key(|left| left.position_index);
    let mut sorted_objections = supplements.objections.clone();
    sorted_objections.sort_by(|left, right| left.objection_id.cmp(&right.objection_id));
    let mut counterevidence = supplements.counterevidence.clone();
    counterevidence.sort();
    let mut unknowns = supplements.unknowns.clone();
    unknowns.sort();
    let mut assumptions = supplements.assumptions.clone();
    assumptions.sort();
    let mut sorted_risks = risks.to_vec();
    sorted_risks.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.description.cmp(&right.description))
    });
    let mut sorted_groups = groups.to_vec();
    sorted_groups.sort_by(|left, right| left.lineage_root.cmp(&right.lineage_root));
    let mut sorted_probes = recommended_probes.to_vec();
    sorted_probes.sort_by(|left, right| left.probe_id.cmp(&right.probe_id));
    let invalidation_conditions = build_invalidation_conditions(supplements, groups);
    Ok(ConflictAnalysisCandidate {
        outcome,
        conflict_id: conflict_set.conflict_id.clone(),
        scope: conflict_set.scope.clone(),
        positions: sorted_positions,
        lineage_groups: sorted_groups,
        independent_root_count: independent,
        common_mode_risks: sorted_risks,
        objections: sorted_objections,
        counterevidence,
        unknowns,
        assumptions,
        recommended_probes: sorted_probes,
        recommended_owner: owner.clone(),
        preservation,
        invalidation_conditions,
        candidate_digest: digest,
        note: note.to_owned(),
        resolution_status: supplements.external_resolution.clone(),
        causal_states: collect_causal_claims(supplements),
    })
}

// ---------------------------------------------------------------------------
// Typed operation.
// ---------------------------------------------------------------------------

/// Analyzes one exact bounded `ConflictSet` into a candidate-only envelope.
///
/// The six explicit parameters bind the curation input, the validated draft,
/// the grounded draft, the canonical `ConflictSet`, the caller-supplied lineage,
/// objection, counterevidence, unknown, probe, and external-resolution
/// supplements, and the governing policy. The A-05 receipt is checked
/// intrinsically through its own validation entry points and is never
/// re-executed here. Returned candidates are inert: every probe names the
/// external owner that must run or decline it, and the owner recommendation
/// names but never assigns, messages, launches, or authorizes anything.
///
/// Malformed or mismatched inputs fail closed as [`ConflictAnalysisError`].
/// Semantic shortfalls emit inert terminal outcomes without effect: the
/// cancellation and frozen-deadline envelope gives
/// [`ConflictOutcome::Blocked`] or [`ConflictOutcome::Stale`], the canonical
/// `ConflictSet` lifecycle gives [`ConflictOutcome::Rejected`],
/// [`ConflictOutcome::Unsupported`], or [`ConflictOutcome::Abstention`] through
/// [`check_lifecycle_boundary`]. A coverage shortfall is decided from the
/// analysis alone: an incomplete analysis is
/// [`ConflictOutcome::Partial`] only when the policy admits a partial emission
/// and is otherwise the same typed [`ConflictOutcome::Abstention`], so a
/// stricter emission policy can withhold a candidate but never promotes an
/// incomplete one to [`ConflictOutcome::Complete`]. Each terminal leg still
/// preserves every position, objection, and lineage group of the set it was
/// handed, together with the named gap; none resolves the conflict.
///
/// # Errors
///
/// Returns [`ConflictAnalysisError`] on any blank, controlled, overlong,
/// unordered-where-required, duplicated, misshapen, mismatched, stale,
/// over-budget, past-deadline, or unbound field.
#[allow(clippy::too_many_lines)]
pub fn analyze_conflict(
    item: &ValidatedCurationItem,
    draft: &ValidatedDreamDraft,
    grounded: &GroundedDreamDraft,
    conflict_set: &ConflictSet,
    supplements: &ConflictSupplements,
    policy: &ConflictAnalysisPolicy,
) -> Result<ConflictAnalysisCandidate, ConflictAnalysisError> {
    preflight_supplement_bounds(supplements, policy)?;
    preflight_total_bytes(supplements, policy, conflict_set)?;
    validate_policy_shapes(policy)?;
    validate_supplement_shapes(supplements)?;
    validate_conflict_denominators(conflict_set, policy)?;
    validate_comparisons(conflict_set, &supplements.comparisons)?;
    validate_causal_claims(conflict_set, &supplements.causal_claims)?;
    validate_owner_records(item, conflict_set, &supplements.owner_records)?;
    check_supplement_identity_uniqueness(supplements)?;
    if policy.policy_id != item.receipt.validator_policy {
        return Err(ConflictAnalysisError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    intrinsic_receipt_checks(item, draft, grounded, supplements)?;
    intrinsic_binding_checks(item, draft, grounded, conflict_set, supplements)?;
    item.denominator
        .validate()
        .map_err(|err| ConflictAnalysisError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    let terminal = check_deadline_and_cancel(policy)
        .map(|outcome| {
            (
                outcome,
                "cancelled or past-deadline requests emit no effect",
            )
        })
        .or_else(|| check_lifecycle_boundary(conflict_set));
    if let Some((early, early_note)) = terminal {
        let classes = classify_conflict(conflict_set);
        let mut positions: Vec<PositionAnalysis> = Vec::with_capacity(conflict_set.positions.len());
        let mut index = 0usize;
        while index < conflict_set.positions.len() {
            positions.push(dispose_position(index, conflict_set, supplements, &classes));
            index = index.saturating_add(1);
        }
        let (groups, independent) = group_lineage(conflict_set, supplements);
        let risks = collect_common_mode_risks(&groups, conflict_set);
        let owner = recommend_owner(conflict_set, supplements, &groups, &[]);
        return emit_candidate(
            early,
            conflict_set,
            supplements,
            policy,
            &positions,
            &groups,
            independent,
            &risks,
            &[],
            &owner,
            early_note,
        );
    }
    let classes = classify_conflict(conflict_set);
    let mut positions: Vec<PositionAnalysis> = Vec::with_capacity(conflict_set.positions.len());
    let mut index = 0usize;
    while index < conflict_set.positions.len() {
        positions.push(dispose_position(index, conflict_set, supplements, &classes));
        index = index.saturating_add(1);
    }
    let (groups, independent) = group_lineage(conflict_set, supplements);
    let risks = collect_common_mode_risks(&groups, conflict_set);
    let position_sources: Vec<String> = positions
        .iter()
        .map(|position| position.source_handle.clone())
        .collect();
    let recommended = recommend_probes(conflict_set, supplements, &position_sources);
    let owner = recommend_owner(conflict_set, supplements, &groups, &recommended);
    // The incompleteness reason is read from the analysis itself, never from
    // the permission to emit partial output: a stricter emission policy can
    // withhold a partial candidate but can never make missing evidence
    // complete. Every leg below preserves the same positions, groups, risks,
    // owner recommendation, and named gap; only the terminal outcome differs.
    let has_unknown_lineage = groups.iter().any(|group| !group.known);
    let unrecommendable_probes = recommended.is_empty() && !supplements.supplied_probes.is_empty();
    let undecided_without_unknown = conflict_set.acceptability == ArgumentAcceptability::Undecided
        && supplements.unknowns.is_empty();
    let incompleteness = if has_unknown_lineage || unrecommendable_probes {
        Some("incomplete coverage: named open lineage or probe gaps remain")
    } else if undecided_without_unknown {
        Some("incomplete coverage: undecided acceptability and no load-bearing unknown is supplied")
    } else {
        None
    };
    if let Some(note) = incompleteness {
        // With no partial path admitted, an incomplete analysis is withheld
        // rather than promoted: [`ConflictOutcome::Abstention`] is the existing
        // typed "no analysis is offered" result and carries the same members
        // and the same named gap as the partial leg.
        let outcome = if policy.allow_partial {
            ConflictOutcome::Partial
        } else {
            ConflictOutcome::Abstention
        };
        return emit_candidate(
            outcome,
            conflict_set,
            supplements,
            policy,
            &positions,
            &groups,
            independent,
            &risks,
            &recommended,
            &owner,
            note,
        );
    }
    emit_candidate(
        ConflictOutcome::Complete,
        conflict_set,
        supplements,
        policy,
        &positions,
        &groups,
        independent,
        &risks,
        &recommended,
        &owner,
        CONFLICT_PROOF_NOTE,
    )
}

/// Maps a terminal outcome to the closest hub rejection hint, if any.
///
/// The hint is a lossy convenience for a caller that already speaks the closed
/// hub vocabulary, never the outcome itself: [`ConflictOutcome`] and its
/// `as_str` spelling stay the exact, lossless discriminator. `Blocked` and
/// `Stale` map to the code that names their single production site
/// ([`CurationRejectionCode::Cancelled`] for `policy.cancelled`,
/// [`CurationRejectionCode::DeadlineExceeded`] for the frozen deadline).
/// `Abstention` and `Rejected` share `IdentityMismatch` because the eight hub
/// codes have no counterpart for either boundary handoff, so the hint must not
/// pretend to distinguish what it cannot name; the typed outcome does.
#[must_use]
pub fn outcome_rejection_hint(outcome: &ConflictOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        ConflictOutcome::Complete => None,
        ConflictOutcome::Partial => Some(CurationRejectionCode::PreservationFailed),
        ConflictOutcome::Blocked => Some(CurationRejectionCode::Cancelled),
        ConflictOutcome::Stale => Some(CurationRejectionCode::DeadlineExceeded),
        ConflictOutcome::Abstention | ConflictOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
        ConflictOutcome::Unsupported => Some(CurationRejectionCode::UnsupportedJobShape),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SourceId};
    use eliot_dreamer_contracts::{
        AtomicityMode, ClaimResidue, ConditionAssumptionRef, PossibleResultValue,
        ProbeObjectiveOrigin, ProbeObjectiveTarget, ProbeOwnerRef, Requester, RequesterOrigin,
        ResultBranch, ResultUpdate, RivalModelRef, RivalPredictionRef, RivalUpdateMeaning,
        SupportState, TargetDenominator,
        curation::{ProcedurePayload, TargetEvidence},
    };
    use eliot_epistemic_contracts::{
        ConflictPosition, ConflictSetParams, ContractError, LineageRootId, Precision,
        ValidityBounds,
    };
    use std::collections::BTreeSet;
    use std::num::NonZeroU64;

    /// Returns the test state fence at genesis.
    fn test_fence() -> eliot_contracts::StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("canonical test lineage-A"),
            NonZeroU64::new(1).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    /// Returns a valid A-05 receipt for the test job and digests.
    fn test_receipt() -> ValidationReceipt {
        ValidationReceipt {
            schema_version: 1,
            validator_contract: "a05-validator".to_owned(),
            validator_policy: "policy-7".to_owned(),
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            bundle_digest: "b".repeat(64),
            manifest_digest: "c".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            input_digest: "d".repeat(64),
            output_digest: "e".repeat(64),
            terminal_disposition: "accepted".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            state_fence: test_fence(),
            preservation_digest: "f".repeat(64),
            budget_digest: "0".repeat(64),
        }
    }

    /// Returns a grounded draft bound to the test receipt digests.
    fn test_grounded() -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            residues: vec![ClaimResidue {
                claim: "the cache claim holds for warm keys".to_owned(),
                state: SupportState::Supported,
                detail: "ep-1 shows warm-key support".to_owned(),
            }],
            coverage_note: "one claim accounted".to_owned(),
        }
    }

    /// Returns a validated draft bound to the test receipt.
    fn test_draft() -> ValidatedDreamDraft {
        ValidatedDreamDraft {
            receipt: test_receipt(),
            draft_digest: "a".repeat(64),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            state_fence: test_fence(),
        }
    }

    /// Returns a curation item bound to the test receipt.
    fn test_item() -> ValidatedCurationItem {
        let payload = eliot_dreamer_contracts::CurationPayload::Procedure(ProcedurePayload {
            procedure: "rotate-caption".to_owned(),
            steps: 1,
            target_evidence: TargetEvidence {
                targets: vec!["mem-1".to_owned()],
                evidence_refs: vec!["e-1".to_owned()],
            },
        });
        ValidatedCurationItem {
            receipt: test_receipt(),
            kind_spelling: "procedure".to_owned(),
            family_spelling: "procedure".to_owned(),
            payload,
            denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: vec!["mem-1".to_owned()],
                expected_total: 1,
            },
            source_digest: "1".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            job_digest: "2".repeat(64),
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "op-1".to_owned(),
                session: None,
            },
            budget_note: "within budget".to_owned(),
        }
    }

    fn test_position(source: &str, stance: &str, minority: bool) -> ConflictPosition {
        ConflictPosition::new(
            SourceId::new(source).expect("valid source"),
            stance.to_owned(),
            BTreeSet::from(["assumption-1".to_owned()]),
            BTreeSet::new(),
            minority,
        )
        .expect("valid position")
    }

    /// Returns a minimal two-position conflict set bound to the test bundle.
    fn test_conflict() -> ConflictSet {
        test_conflict_naming_probe(None)
    }

    /// Returns the same conflict set with its own `discriminative_probe`
    /// handle set. That set-side handle is the only target-to-position binding
    /// the canonical contracts carry, so a supplied probe claims covered
    /// positions only when the set itself names it.
    fn test_conflict_naming_probe(probe_id: Option<&str>) -> ConflictSet {
        let receipt = test_receipt();
        ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-1".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: probe_id.map(str::to_owned),
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("valid conflict set")
    }

    fn test_validity() -> ValidityBounds {
        ValidityBounds::new("scope-1", None, None, "v1", Precision("file".to_owned()))
            .expect("valid bounds")
    }

    fn test_model_ref(id: &str) -> RivalModelRef {
        RivalModelRef {
            model_id: ArtifactId::new(id).expect("valid artifact"),
            model_revision: 1,
            declaration_digest: "a".repeat(64),
        }
    }

    fn test_prediction_ref(id: &str) -> RivalPredictionRef {
        RivalPredictionRef {
            prediction_id: ArtifactId::new(id).expect("valid artifact"),
            prediction_digest: "b".repeat(64),
        }
    }

    /// Returns a discriminative supplied probe separating two positions.
    fn test_discriminative_probe(probe_id: &str) -> SuppliedProbe {
        let left = test_prediction_ref("pred-left");
        let right = test_prediction_ref("pred-right");
        let objective = ProbeObjective::new(
            ArtifactId::new(format!("{probe_id}-obj")).expect("valid artifact"),
            ProbeObjectiveOrigin::RivalPredictionDifference,
            ProbeObjectiveTarget::RivalPredictions {
                left: left.clone(),
                right: right.clone(),
            },
            test_validity(),
            "separates the two live cache positions".to_owned(),
            BTreeSet::from([ArtifactId::new("e-1").expect("valid artifact")]),
            Vec::new(),
            ProbeOwnerRef::Source {
                owner: SourceId::new("source-a").expect("valid source"),
            },
        )
        .expect("valid objective");
        let model_left = test_model_ref("model-left");
        let model_right = test_model_ref("model-right");
        let targets = vec![
            ResultTarget::Rival {
                model: model_left.clone(),
                prediction: None,
            },
            ResultTarget::Rival {
                model: model_right.clone(),
                prediction: None,
            },
        ];
        let branch_one = ResultBranch {
            result_id: ArtifactId::new("branch-one").expect("valid artifact"),
            value: PossibleResultValue::Unknown {
                reason: "hit rate high".to_owned(),
            },
            updates: vec![
                ResultUpdate::Rival {
                    model: model_left.clone(),
                    prediction: None,
                    meaning: RivalUpdateMeaning::Strengthened,
                },
                ResultUpdate::Rival {
                    model: model_right.clone(),
                    prediction: None,
                    meaning: RivalUpdateMeaning::Weakened,
                },
            ],
        };
        let branch_two = ResultBranch {
            result_id: ArtifactId::new("branch-two").expect("valid artifact"),
            value: PossibleResultValue::Unknown {
                reason: "hit rate low".to_owned(),
            },
            updates: vec![
                ResultUpdate::Rival {
                    model: model_left,
                    prediction: None,
                    meaning: RivalUpdateMeaning::Weakened,
                },
                ResultUpdate::Rival {
                    model: model_right,
                    prediction: None,
                    meaning: RivalUpdateMeaning::Strengthened,
                },
            ],
        };
        let schema = PossibleResultSchema::new(
            ArtifactId::new(format!("{probe_id}-schema")).expect("valid artifact"),
            targets,
            vec![branch_one, branch_two],
        )
        .expect("valid schema");
        SuppliedProbe {
            probe_id: probe_id.to_owned(),
            objective,
            schema,
            owner_note: "source-a owns the follow-up".to_owned(),
            verifier: "verifier-7".to_owned(),
            cost_note: "one read of admitted evidence".to_owned(),
            risk_note: "read-only with rollback".to_owned(),
            privacy_note: "no personal data".to_owned(),
            effect_note: "no canonical effect".to_owned(),
            blocked: false,
            over_budget: false,
        }
    }

    /// Returns a nondiscriminative probe with identical branch outcomes.
    fn test_nondiscriminative_probe() -> SuppliedProbe {
        let mut probe = test_discriminative_probe("probe-nondisc");
        let identical = probe.schema.branches.first().expect("first branch").clone();
        probe.schema = PossibleResultSchema::new(
            ArtifactId::new("probe-nondisc-schema-2").expect("valid artifact"),
            probe.schema.targets.clone(),
            vec![
                identical.clone(),
                ResultBranch {
                    result_id: ArtifactId::new("branch-copy").expect("valid artifact"),
                    ..identical
                },
            ],
        )
        .expect("valid schema");
        probe.probe_id = String::from("probe-nondisc");
        probe
    }

    /// Returns valid supplements bound to the test receipt and conflict.
    fn test_supplements() -> ConflictSupplements {
        let receipt = test_receipt();
        ConflictSupplements {
            expected_receipt: receipt.clone(),
            frozen_bundle_digest: receipt.bundle_digest.clone(),
            frozen_manifest_digest: receipt.manifest_digest.clone(),
            lineage: vec![
                LineageAttribution {
                    source_handle: "source-a".to_owned(),
                    lineage_root: "root-primary".to_owned(),
                    known: true,
                },
                LineageAttribution {
                    source_handle: "source-b".to_owned(),
                    lineage_root: "root-rival".to_owned(),
                    known: true,
                },
            ],
            objections: vec![SuppliedObjection {
                objection_id: "obj-1".to_owned(),
                target_source: "source-a".to_owned(),
                statement: "cold start unaffected".to_owned(),
                grounded: true,
            }],
            counterevidence: vec!["cold start unaffected".to_owned()],
            assumptions: vec!["assumption-1".to_owned()],
            unknowns: vec!["hit rate under load".to_owned()],
            supplied_probes: vec![test_discriminative_probe("probe-1")],
            comparisons: Vec::new(),
            causal_claims: Vec::new(),
            external_resolution: None,
            owner_records: OwnerRecords::default(),
        }
    }

    /// Returns the retained bytes one owner source member holds for a position.
    fn test_member_bytes(position_source: &str) -> Vec<u8> {
        format!("retained bytes for {position_source}").into_bytes()
    }

    /// Returns the owner-recorded digest of one member's retained bytes.
    fn test_member_digest(position_source: &str) -> String {
        sha256_hex(&test_member_bytes(position_source))
    }

    /// Returns the owner-issued source members for `source-a` and `source-b`.
    ///
    /// The member carries the bytes it says it retained, and the digest the owner
    /// recorded for them, so the intrinsic digest check is satisfied by the
    /// original recorded value rather than by a recomputed stand-in.
    fn test_source_members() -> Vec<SourceMemberRecord> {
        ["source-a", "source-b"]
            .into_iter()
            .map(|source| SourceMemberRecord {
                position_source: source.to_owned(),
                source_owner: "owner-evidence-1".to_owned(),
                retained_handle: format!("retained-{source}"),
                retained_bytes: test_member_bytes(source),
                record_digest: test_member_digest(source),
                source_revision: "rev-1".to_owned(),
                source_snapshot: format!("snapshot-{source}"),
                task_id: "task-1".to_owned(),
                scope_id: "scope-1".to_owned(),
                state_fence: test_fence(),
            })
            .collect()
    }

    /// Returns the owner-issued comparison profile both test sources read under.
    fn test_owner_profile() -> OwnerComparisonProfile {
        let definition_bytes = b"canonical comparison definition v1".to_vec();
        OwnerComparisonProfile {
            profile_id: "profile-comparison-v2".to_owned(),
            owner: "owner-evidence-1".to_owned(),
            schema_revision: 1,
            definition_digest: sha256_hex(&definition_bytes),
            definition_bytes,
            descriptors: COMPARISON_DIMENSIONS.to_vec(),
            normalization_rules: vec!["trim and casefold".to_owned()],
            missing_disposition: DispositionKind::Unnormalizable,
            unsupported_disposition: DispositionKind::Unsupported,
        }
    }

    /// Returns the owner-issued comparison between `source-a` and `source-b`.
    ///
    /// `differing` names the one canonical dimension the two positions were read
    /// as differing on; every other dimension carries the same observed value
    /// from both. Passing `None` produces an all-equal pair. The caller supplies
    /// no verdict: the relation is derived from these values by the analyzer.
    fn test_owner_comparison(differing: Option<ComparisonDimension>) -> OwnerComparison {
        let profile = test_owner_profile();
        let mut observations: Vec<DimensionObservation> = Vec::new();
        for dimension in COMPARISON_DIMENSIONS {
            for source in ["source-a", "source-b"] {
                let value = if Some(dimension) == differing {
                    format!("{} under {source}", dimension.as_str())
                } else {
                    dimension.as_str().to_owned()
                };
                observations.push(DimensionObservation {
                    source: source.to_owned(),
                    source_member_digest: test_member_digest(source),
                    dimension,
                    descriptor: dimension.as_str().to_owned(),
                    value,
                });
            }
        }
        OwnerComparison {
            first_source: "source-a".to_owned(),
            first_commitment: SourceRecordCommitment::new(
                "source-a",
                &test_member_digest("source-a"),
                &profile.profile_id,
                &profile.definition_digest,
            )
            .expect("valid source-a commitment"),
            second_source: "source-b".to_owned(),
            second_commitment: SourceRecordCommitment::new(
                "source-b",
                &test_member_digest("source-b"),
                &profile.profile_id,
                &profile.definition_digest,
            )
            .expect("valid source-b commitment"),
            profile,
            observations,
            unnormalizable_dimensions: Vec::new(),
            unsupported_dimensions: Vec::new(),
        }
    }

    /// Returns owner records carrying one comparison between the two positions.
    fn test_owner_records(differing: Option<ComparisonDimension>) -> OwnerRecords {
        OwnerRecords {
            source_members: test_source_members(),
            comparisons: vec![test_owner_comparison(differing)],
            causal_evidence: Vec::new(),
        }
    }

    /// Returns a valid governing policy for the test analysis.
    fn test_policy() -> ConflictAnalysisPolicy {
        ConflictAnalysisPolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_positions: MAX_POSITIONS,
            max_sources: MAX_SOURCES,
            max_objections: MAX_OBJECTIONS,
            max_probes: MAX_PROBES,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            analysis_note: "bounded rival analysis".to_owned(),
        }
    }

    // WORK_UNIT_CASE: 673/1
    #[test]
    fn case_01_valid_conflict_completes_without_resolution() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("valid conflict analysis: {err:?}"),
            };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.conflict_id, "conflict-1");
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.objections.len(), 1);
        assert_eq!(candidate.recommended_probes.len(), 1);
        assert_eq!(candidate.resolution_status, None);
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
        assert!(candidate.preservation.validate().is_ok());
        assert!(candidate.preservation.overall().is_ok());
        assert!(!candidate.invalidation_conditions.is_empty());
    }

    // WORK_UNIT_CASE: 673/2
    #[test]
    fn case_02_wrong_job_and_scope_input_fails_closed() {
        let item = test_item();
        let draft = test_draft();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        let mut drifted_grounded = test_grounded();
        drifted_grounded.job_id = String::from("job-9");
        let err = match analyze_conflict(
            &item,
            &draft,
            &drifted_grounded,
            &conflict,
            &supplements,
            &policy,
        ) {
            Ok(candidate) => panic!("drifted job must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ConflictAnalysisError::Binding { field, .. } if field == "job_id"
        ));
        let receipt = test_receipt();
        let scoped_conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-wrong-scope".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-9".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("scoped conflict shape stays valid");
        let err = match analyze_conflict(
            &item,
            &draft,
            &test_grounded(),
            &scoped_conflict,
            &supplements,
            &policy,
        ) {
            Ok(candidate) => panic!("drifted scope must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ConflictAnalysisError::Binding { field, .. } if field == "conflict_scope"
        ));
    }

    // WORK_UNIT_CASE: 673/3
    #[test]
    fn case_03_empty_and_single_position_are_not_conflicts() {
        let receipt = test_receipt();
        let owners = BTreeSet::from([SourceId::new("source-a").expect("valid source")]);
        let empty = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-empty".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: Vec::new(),
            evidence_refs: BTreeSet::new(),
            owners: owners.clone(),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: owners.clone(),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        });
        assert!(
            matches!(
                empty,
                Err(ContractError::EmptyCollection { field })
                if field == "conflict.positions"
            ),
            "empty positions are rejected before analysis"
        );
        let single = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-single".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![test_position("source-a", "cache helps tail latency", false)],
            evidence_refs: BTreeSet::new(),
            owners: owners.clone(),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: owners,
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        });
        assert!(
            matches!(
                single,
                Err(ContractError::EmptyCollection { field })
                if field == "conflict.positions"
            ),
            "one position without a qualified missing-rival denominator is not a conflict"
        );
    }

    // WORK_UNIT_CASE: 673/10
    #[test]
    fn case_10_shared_lineage_stays_one_root() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-shared".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps", false),
                test_position("source-b", "cache helps slowly", false),
                test_position("source-c", "cache helps rarely", false),
                test_position("source-d", "cache helps sometimes", false),
                test_position("source-e", "cache helps mostly", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-e").expect("valid source"),
            ]),
            common_lineage: BTreeSet::from(
                [LineageRootId::new("root-shared").expect("valid root")],
            ),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["help rate".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("valid shared conflict");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-c".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-d".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-e".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
        ];
        supplements.supplied_probes = vec![test_discriminative_probe("probe-shared")];
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("shared lineage analysis: {err:?}"),
            };
        assert_eq!(candidate.independent_root_count, 1);
        assert!(
            candidate
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "shared_primary_source"
                    || risk.kind == "canonical_common_lineage")
        );
        assert_eq!(candidate.positions.len(), 5);
    }

    // WORK_UNIT_CASE: 673/14
    #[test]
    fn case_14_majority_count_cannot_choose_winner() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-majority".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps", false),
                test_position("source-b", "cache helps", false),
                test_position("source-c", "cache helps", false),
                test_position("source-d", "cache helps", false),
                ConflictPosition::new(
                    SourceId::new("source-e").expect("valid source"),
                    "cache harms under load".to_owned(),
                    BTreeSet::from(["assumption-minority".to_owned()]),
                    BTreeSet::new(),
                    true,
                )
                .expect("valid minority"),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-e").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["load effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-e").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("valid majority conflict");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "root-a".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "root-b".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-c".to_owned(),
                lineage_root: "root-c".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-d".to_owned(),
                lineage_root: "root-d".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-e".to_owned(),
                lineage_root: "root-minority".to_owned(),
                known: true,
            },
        ];
        supplements.supplied_probes = vec![test_discriminative_probe("probe-majority")];
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("majority analysis: {err:?}"),
            };
        assert_eq!(candidate.positions.len(), 5);
        let minority: Vec<&PositionAnalysis> = candidate
            .positions
            .iter()
            .filter(|position| position.minority)
            .collect();
        assert_eq!(minority.len(), 1);
        assert_eq!(
            minority.first().expect("minority").disposition,
            PositionDispositionKind::MinorityPreserved
        );
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/19
    #[test]
    fn case_19_compatible_scope_stays_residue() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-scope".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                ConflictPosition::new(
                    SourceId::new("source-a").expect("valid source"),
                    "cache helps for warm keys".to_owned(),
                    BTreeSet::from(["scope warm keys".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
                ConflictPosition::new(
                    SourceId::new("source-b").expect("valid source"),
                    "cache harms for cold start".to_owned(),
                    BTreeSet::from(["scope cold start".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["scope boundary".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("valid scope conflict");
        // The residue rests on the owner-issued scope difference, not on the two
        // disjoint assumption handles above: distinct identifiers establish no
        // scope, time, or definition comparison.
        let mut supplements = test_supplements();
        supplements.owner_records =
            test_owner_records(Some(ComparisonDimension::ScopePopulationEnvironment));
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("scope analysis: {err:?}"),
            };
        assert!(
            candidate
                .positions
                .iter()
                .any(|position| position.disposition == PositionDispositionKind::CompatibleResidue)
        );
        for position in &candidate.positions {
            assert_eq!(
                position.compatibility[0].relation,
                CompatibilityRelation::TypedDifference,
                "the residue rests on the owner-issued condition difference"
            );
            assert_eq!(
                position.compatibility[0].supplement_version,
                SupplementVersion::OwnerRecordV2
            );
        }
        assert_eq!(candidate.scope, "scope-1");
    }

    // WORK_UNIT_CASE: 673/40
    #[test]
    fn case_40_nondiscriminative_probe_rejected() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![test_nondiscriminative_probe()];
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("nondiscriminative analysis: {err:?}"),
            };
        assert_eq!(
            candidate.outcome,
            ConflictOutcome::Abstention,
            "a supplied probe that can never be recommended leaves an open probe gap; \
             with no partial path admitted the analysis is withheld, not promoted to complete"
        );
        assert!(candidate.recommended_probes.is_empty());
        assert!(!candidate.invalidation_conditions.is_empty());
    }

    // WORK_UNIT_CASE: 673/51
    #[test]
    fn case_51_concilium_review_recommends_without_plan() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-concilium".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps", false),
                test_position("source-b", "cache harms", false),
                test_position("source-c", "cache is neutral", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Investigating,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("valid concilium conflict");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "root-a".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "root-b".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-c".to_owned(),
                lineage_root: "root-c".to_owned(),
                known: true,
            },
        ];
        supplements.supplied_probes = vec![test_nondiscriminative_probe()];
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("concilium analysis: {err:?}"),
            };
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::ConciliumReview
        );
        assert!(candidate.recommended_probes.is_empty());
        assert!(!candidate.note.contains("ConciliumPlan"));
        assert_eq!(candidate.resolution_status, None);
        assert_eq!(
            candidate.outcome,
            ConflictOutcome::Abstention,
            "an unrecommendable supplied probe is an open probe gap; the owner \
             recommendation survives and the analysis is withheld, not completed"
        );
    }

    // WORK_UNIT_CASE: 673/4
    #[test]
    fn case_04_receipt_and_fence_mismatch_fails_closed() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let mut supplements = test_supplements();
        supplements.frozen_bundle_digest = "0".repeat(64);
        let policy = test_policy();
        let err = match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy)
        {
            Ok(candidate) => panic!("mismatched bundle must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ConflictAnalysisError::Binding { field, .. } if field == "bundle_digest"
        ));
        let mut drifted_item = test_item();
        drifted_item.task_id = String::from("task-9");
        let err = match analyze_conflict(
            &drifted_item,
            &draft,
            &grounded,
            &conflict,
            &test_supplements(),
            &policy,
        ) {
            Ok(candidate) => panic!("drifted task must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ConflictAnalysisError::Binding { .. } | ConflictAnalysisError::Receipt { .. }
        ));
    }

    // WORK_UNIT_CASE: 673/60
    #[test]
    fn case_60_irrelevant_order_preserves_digest() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        let first =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("first replay: {err:?}"),
            };
        let mut reordered = supplements.clone();
        reordered.lineage.reverse();
        reordered.objections.reverse();
        reordered.counterevidence.reverse();
        let second =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &reordered, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("second replay: {err:?}"),
            };
        assert_eq!(first.candidate_digest, second.candidate_digest);
        assert_eq!(first.outcome, second.outcome);
        assert!(is_hex64_lower(&first.candidate_digest));
        let _ = ConditionAssumptionRef {
            assumption_id: "assumption-1".to_owned(),
            assumption_digest: "a".repeat(64),
        };
    }

    // WORK_UNIT_CASE: 673/5
    #[test]
    fn case_05_duplicate_and_changed_identities_fail_closed() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let policy = test_policy();
        let duplicate_positions = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-duplicate".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-a", "cache helps tail latency greatly", false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("duplicate source shape stays constructible");
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &duplicate_positions,
            &test_supplements(),
            &policy,
        ) {
            Ok(candidate) => panic!("duplicate position must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "duplicate position source identity fails closed: {err:?}"
        );
        let mut duplicate_objections = test_supplements();
        duplicate_objections.objections.push(SuppliedObjection {
            objection_id: "obj-1".to_owned(),
            target_source: "source-b".to_owned(),
            statement: "changed objection meaning for the same identity".to_owned(),
            grounded: false,
        });
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &duplicate_objections,
            &policy,
        ) {
            Ok(candidate) => panic!("duplicate objection must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "duplicate objection identity fails closed: {err:?}"
        );
        let mut duplicate_lineage = test_supplements();
        duplicate_lineage.lineage.push(LineageAttribution {
            source_handle: "source-a".to_owned(),
            lineage_root: "root-changed".to_owned(),
            known: true,
        });
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &duplicate_lineage,
            &policy,
        ) {
            Ok(candidate) => panic!("duplicate lineage must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "duplicate lineage source identity fails closed: {err:?}"
        );
    }

    // WORK_UNIT_CASE: 673/6
    #[test]
    fn case_06_denominators_stay_explicit() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let complete = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("complete denominator: {err:?}"),
        };
        assert_eq!(complete.outcome, ConflictOutcome::Complete);
        assert_eq!(complete.positions.len(), 2);
        let mut withheld = test_supplements();
        withheld
            .lineage
            .retain(|entry| entry.source_handle != "source-b");
        let mut partial_policy = test_policy();
        partial_policy.allow_partial = true;
        let partial = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &withheld,
            &partial_policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("partial denominator: {err:?}"),
        };
        assert_eq!(partial.outcome, ConflictOutcome::Partial);
        assert_eq!(partial.positions.len(), 2);
        assert!(
            partial
                .lineage_groups
                .iter()
                .any(|group| !group.known && group.member_sources.contains(&"source-b".to_owned()))
        );
        assert!(
            partial
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "unknown_lineage")
        );
        assert!(
            partial.independent_root_count < complete.independent_root_count
                || partial.independent_root_count == 1
        );
        let mut stale_policy = test_policy();
        stale_policy.observation_time_ms = Some(1_800_000_000_000);
        stale_policy.deadline_ms = Some(1_800_000_000_000);
        let stale = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &test_supplements(),
            &stale_policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("stale denominator: {err:?}"),
        };
        assert_eq!(stale.outcome, ConflictOutcome::Stale);
        assert_eq!(stale.positions.len(), 2);
        let mut blocked_policy = test_policy();
        blocked_policy.cancelled = true;
        let blocked = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &test_supplements(),
            &blocked_policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("blocked denominator: {err:?}"),
        };
        assert_eq!(blocked.outcome, ConflictOutcome::Blocked);
        assert_eq!(blocked.positions.len(), 2);
        assert!(blocked.recommended_probes.is_empty());
    }

    // WORK_UNIT_CASE: 673/7
    #[test]
    fn case_07_exact_replay_matches_changed_content_moves_digest() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        let first =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("first replay: {err:?}"),
            };
        let second =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("second replay: {err:?}"),
            };
        assert_eq!(first.candidate_digest, second.candidate_digest);
        assert_eq!(first.outcome, second.outcome);
        assert!(is_hex64_lower(&first.candidate_digest));
        let receipt = test_receipt();
        let changed = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-1".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency greatly", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("changed stance stays valid");
        let third =
            match analyze_conflict(&item, &draft, &grounded, &changed, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("changed content: {err:?}"),
            };
        assert_ne!(
            first.candidate_digest, third.candidate_digest,
            "changed operation content must move the digest"
        );
        assert_eq!(third.outcome, ConflictOutcome::Complete);
    }

    // WORK_UNIT_CASE: 673/61
    #[test]
    #[allow(clippy::too_many_lines)]
    fn case_61_exact_and_one_over_limits_fail_closed() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let mut tight = test_policy();
        tight.max_positions = 2;
        tight.max_sources = 2;
        tight.max_objections = 1;
        tight.max_probes = 1;
        let exact = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &test_supplements(),
            &tight,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("exact limits: {err:?}"),
        };
        assert_eq!(exact.outcome, ConflictOutcome::Complete);
        let three_positions = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-1".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps", false),
                test_position("source-b", "cache harms", false),
                test_position("source-c", "cache is neutral", false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("three positions stay within the canonical ceiling");
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &three_positions,
            &test_supplements(),
            &tight,
        ) {
            Ok(candidate) => panic!("one-over positions must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ConflictAnalysisError::Bounds { phase, .. } if phase == "positions"));
        let mut one_over_lineage = test_supplements();
        one_over_lineage.lineage.push(LineageAttribution {
            source_handle: "source-extra".to_owned(),
            lineage_root: "root-extra".to_owned(),
            known: true,
        });
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &one_over_lineage,
            &tight,
        ) {
            Ok(candidate) => panic!("one-over lineage must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ConflictAnalysisError::Bounds { phase, .. } if phase == "lineage"));
        let mut one_over_objections = test_supplements();
        one_over_objections.objections.push(SuppliedObjection {
            objection_id: "obj-2".to_owned(),
            target_source: "source-b".to_owned(),
            statement: "second objection".to_owned(),
            grounded: true,
        });
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &one_over_objections,
            &tight,
        ) {
            Ok(candidate) => panic!("one-over objections must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Bounds { phase, .. } if phase == "objections")
        );
        let mut one_over_probes = test_supplements();
        one_over_probes
            .supplied_probes
            .push(test_discriminative_probe("probe-2"));
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &one_over_probes,
            &tight,
        ) {
            Ok(candidate) => panic!("one-over probes must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Bounds { phase, .. } if phase == "supplied-probes")
        );
        let mut one_over_evidence = test_supplements();
        one_over_evidence.counterevidence = (0..65)
            .map(|index| format!("evidence-{index:02}"))
            .collect();
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &one_over_evidence,
            &test_policy(),
        ) {
            Ok(candidate) => panic!("one-over evidence must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Bounds { phase, .. } if phase == "counterevidence")
        );
        let exact_text = "x".repeat(MAX_TEXT_BYTES);
        let exact_conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-1".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                ConflictPosition::new(
                    SourceId::new("source-a").expect("valid source"),
                    exact_text,
                    BTreeSet::from(["assumption-1".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("exact text stays valid"),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("exact text conflict stays constructible");
        assert!(
            analyze_conflict(
                &item,
                &draft,
                &grounded,
                &exact_conflict,
                &test_supplements(),
                &test_policy()
            )
            .is_ok(),
            "exact text ceiling admits the analysis"
        );
        let over_text = "x".repeat(MAX_TEXT_BYTES + 1);
        let over_conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-1".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                ConflictPosition::new(
                    SourceId::new("source-a").expect("valid source"),
                    over_text,
                    BTreeSet::from(["assumption-1".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("one-over text stays within the canonical ceiling"),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("one-over text stays within the canonical ceiling");
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &over_conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("one-over text must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Shape { field, .. } if field == "position.stance")
        );
    }

    // WORK_UNIT_CASE: 673/62
    #[test]
    fn case_62_cancellation_and_deadline_emit_blocked_or_stale() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let mut cancelled = test_policy();
        cancelled.cancelled = true;
        let blocked = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &cancelled,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("cancelled analysis: {err:?}"),
        };
        assert_eq!(blocked.outcome, ConflictOutcome::Blocked);
        assert!(blocked.recommended_probes.is_empty());
        assert_eq!(blocked.positions.len(), 2);
        assert!(!blocked.invalidation_conditions.is_empty());
        assert!(blocked.preservation.validate().is_ok());
        let mut past_deadline = test_policy();
        past_deadline.observation_time_ms = Some(1_800_000_000_001);
        past_deadline.deadline_ms = Some(1_800_000_000_000);
        let stale = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &past_deadline,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("past-deadline analysis: {err:?}"),
        };
        assert_eq!(stale.outcome, ConflictOutcome::Stale);
        assert!(stale.recommended_probes.is_empty());
        assert_eq!(stale.positions.len(), 2);
        let mut at_deadline = test_policy();
        at_deadline.observation_time_ms = Some(1_800_000_000_000);
        at_deadline.deadline_ms = Some(1_800_000_000_000);
        let edge = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &at_deadline,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("deadline-edge analysis: {err:?}"),
        };
        assert_eq!(edge.outcome, ConflictOutcome::Stale);
        let live = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("live analysis: {err:?}"),
        };
        assert_eq!(live.outcome, ConflictOutcome::Complete);
        assert_eq!(live.recommended_probes.len(), 1);
    }

    // WORK_UNIT_CASE: 673/9
    #[test]
    fn case_09_independent_source_families_stay_two_roots() {
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("independent families analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.independent_root_count, 2);
        assert_eq!(candidate.lineage_groups.len(), 2);
        assert!(candidate.lineage_groups.iter().all(|group| group.known));
        assert!(
            !candidate
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "shared_primary_source"),
            "distinct families carry no shared-source risk: {:?}",
            candidate.common_mode_risks
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/11
    #[test]
    fn case_11_derived_citation_chain_stays_one_root() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-citation".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache helps tail latency per summary", false),
                test_position("source-c", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-c").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-c").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("citation chain conflict stays valid");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "root-primary".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "root-primary".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-c".to_owned(),
                lineage_root: "root-rival".to_owned(),
                known: true,
            },
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("citation chain analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.independent_root_count, 2);
        let primary = candidate
            .lineage_groups
            .iter()
            .find(|group| group.lineage_root == "root-primary")
            .expect("primary root group stays visible");
        assert_eq!(
            primary.member_sources,
            vec!["source-a".to_owned(), "source-b".to_owned()]
        );
        assert!(
            candidate
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "shared_primary_source"
                    && risk.affected_sources.contains(&"source-a".to_owned())
                    && risk.affected_sources.contains(&"source-b".to_owned())),
            "restated primary work is one family, not two votes: {:?}",
            candidate.common_mode_risks
        );
        assert_eq!(candidate.positions.len(), 3);
    }

    // WORK_UNIT_CASE: 673/12
    #[test]
    fn case_12_shared_context_route_stays_common_mode_risk() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-context-route".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("shared route conflict stays valid");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "shared-context-route".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "shared-context-route".to_owned(),
                known: true,
            },
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("shared route analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.independent_root_count, 1);
        assert!(
            candidate
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "shared_model_evaluator_context_route"
                    && risk.affected_sources.contains(&"source-a".to_owned())
                    && risk.affected_sources.contains(&"source-b".to_owned())),
            "shared context and route limits independence: {:?}",
            candidate.common_mode_risks
        );
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::Multiple,
            "two unresolved owners stay multiple while the route risk stays explicit"
        );
        assert_eq!(candidate.positions.len(), 2);
    }

    // WORK_UNIT_CASE: 673/13
    #[test]
    fn case_13_unknown_lineage_is_not_independent() {
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "root-primary".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "root-rival".to_owned(),
                known: false,
            },
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("unknown lineage analysis: {err:?}"),
        };
        assert_eq!(
            candidate.outcome,
            ConflictOutcome::Abstention,
            "an unknown lineage group is an open evidence gap; with allow_partial \
             false the analysis is withheld and never promoted to complete"
        );
        assert_eq!(
            candidate.independent_root_count, 1,
            "unknown lineage contributes no independent root"
        );
        let unknown = candidate
            .lineage_groups
            .iter()
            .find(|group| !group.known)
            .expect("unknown lineage group stays visible");
        assert!(unknown.member_sources.contains(&"source-b".to_owned()));
        assert!(
            candidate
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "unknown_lineage"
                    && risk.affected_sources.contains(&"source-b".to_owned())),
            "unknown lineage is unknown independence: {:?}",
            candidate.common_mode_risks
        );
        assert_eq!(candidate.positions.len(), 2);
    }

    // WORK_UNIT_CASE: 673/35
    #[test]
    fn case_35_shared_model_evaluator_limits_independence() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-model-evaluator".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("shared model conflict stays valid");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "model-evaluator-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "model-evaluator-shared".to_owned(),
                known: true,
            },
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("shared model analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.independent_root_count, 1,
            "one shared model root is one family, not two votes"
        );
        assert!(
            candidate
                .common_mode_risks
                .iter()
                .any(|risk| risk.kind == "shared_model_evaluator_context_route"
                    && risk.affected_sources.contains(&"source-a".to_owned())
                    && risk.affected_sources.contains(&"source-b".to_owned())),
            "shared model and evaluator limits independence: {:?}",
            candidate.common_mode_risks
        );
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::EvaluatorVerifier
        );
        assert_eq!(candidate.positions.len(), 2);
    }

    // WORK_UNIT_CASE: 673/56
    #[test]
    fn case_56_exact_prehandler_receipt_plus_seven_preservation_dimensions() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        assert_eq!(
            supplements.expected_receipt.job_id, item.receipt.job_id,
            "pre-handler receipt binds the exact job"
        );
        assert_eq!(
            supplements.frozen_bundle_digest, item.receipt.bundle_digest,
            "frozen bundle replays the receipt binding"
        );
        assert_eq!(
            supplements.frozen_manifest_digest, item.receipt.manifest_digest,
            "frozen manifest replays the receipt binding"
        );
        assert_eq!(
            policy.policy_id, item.receipt.validator_policy,
            "policy stays on the receipt validator policy"
        );
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("pre-handler receipt analysis: {err:?}"),
            };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.resolution_status, None);
        assert_eq!(
            candidate.preservation.verdicts.len(),
            EXPECTED_PRESERVATION_DIMENSIONS
        );
        for dimension in [
            PreservationDimension::Coverage,
            PreservationDimension::Faithfulness,
            PreservationDimension::Lineage,
            PreservationDimension::Reversibility,
            PreservationDimension::AuthorityCeiling,
            PreservationDimension::DependencyClosure,
            PreservationDimension::ProvenanceRetention,
        ] {
            let verdict = candidate
                .preservation
                .verdicts
                .iter()
                .find(|verdict| verdict.dimension == dimension)
                .unwrap_or_else(|| panic!("missing preservation dimension {dimension:?}"));
            assert!(verdict.known, "dimension {dimension:?} is judged");
            assert!(verdict.passed, "dimension {dimension:?} passes");
            assert!(!verdict.note.trim().is_empty());
        }
        assert!(candidate.preservation.validate().is_ok());
        assert!(candidate.preservation.overall().is_ok());
        let mut drifted = supplements.clone();
        drifted.expected_receipt.job_id = String::from("job-9");
        let err = match analyze_conflict(&item, &draft, &grounded, &conflict, &drifted, &policy) {
            Ok(candidate) => panic!(
                "drifted pre-handler receipt must fail: {:?}",
                candidate.outcome
            ),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Receipt { .. }),
            "exact pre-handler receipt binding fails closed without re-invoking the validator: {err:?}"
        );
    }

    // WORK_UNIT_CASE: 673/57
    #[test]
    fn case_57_failed_unknown_dimensions_stay_independent_without_borrowing() {
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("baseline preservation analysis: {err:?}"),
        };
        assert!(candidate.preservation.overall().is_ok());
        let mut failed = candidate.preservation.clone();
        let coverage = failed
            .verdicts
            .iter_mut()
            .find(|verdict| verdict.dimension == PreservationDimension::Coverage)
            .expect("coverage verdict stays addressable");
        coverage.passed = false;
        coverage.note = String::from("coverage shortfall: expected members missing");
        assert!(failed.validate().is_ok());
        let err = match failed.overall() {
            Ok(()) => panic!("one failed dimension must fail overall"),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "failed coverage fails overall without averaging: {err:?}"
        );
        assert!(
            failed
                .verdicts
                .iter()
                .filter(|verdict| verdict.dimension != PreservationDimension::Coverage)
                .all(|verdict| verdict.known && verdict.passed),
            "sibling dimensions stay passed while coverage fails"
        );
        let mut unknown = candidate.preservation.clone();
        let lineage = unknown
            .verdicts
            .iter_mut()
            .find(|verdict| verdict.dimension == PreservationDimension::Lineage)
            .expect("lineage verdict stays addressable");
        lineage.known = false;
        lineage.passed = false;
        lineage.note = String::from("lineage unknown: unattributed source stays open");
        assert!(unknown.validate().is_ok());
        assert!(
            matches!(
                unknown.overall(),
                Err(ConflictAnalysisError::Denominator { .. })
            ),
            "unknown lineage cannot borrow the valid input receipt"
        );
    }

    // WORK_UNIT_CASE: 673/64
    #[test]
    fn case_64_every_expected_position_and_objection_stays_visible() {
        let conflict = test_conflict();
        let supplements = test_supplements();
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("denominator visibility analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.positions.len(), conflict.positions.len());
        for (index, original) in conflict.positions.iter().enumerate() {
            let analyzed = candidate
                .positions
                .iter()
                .find(|position| position.position_index == index)
                .unwrap_or_else(|| panic!("expected position {index} stays visible"));
            assert_eq!(analyzed.source_handle, original.source.as_str());
            assert_eq!(analyzed.stance, original.stance);
            assert_eq!(analyzed.minority, original.minority);
        }
        assert_eq!(candidate.objections.len(), supplements.objections.len());
        for expected in &supplements.objections {
            let kept = candidate
                .objections
                .iter()
                .find(|objection| objection.objection_id == expected.objection_id)
                .unwrap_or_else(|| {
                    panic!("expected objection {} stays visible", expected.objection_id)
                });
            assert_eq!(kept.target_source, expected.target_source);
            assert_eq!(kept.statement, expected.statement);
        }
        assert_eq!(
            PositionDispositionKind::Withheld.as_str(),
            "withheld",
            "withheld stays a closed explicit denominator state"
        );
        assert_eq!(
            PositionDispositionKind::Unavailable.as_str(),
            "unavailable",
            "unavailable stays a closed explicit denominator state"
        );
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/65
    #[test]
    #[allow(clippy::too_many_lines)]
    fn case_65_independent_count_never_exceeds_unique_roots() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let distinct = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("distinct-roots analysis: {err:?}"),
        };
        assert_eq!(distinct.independent_root_count, 2);
        assert!(distinct.independent_root_count <= distinct.positions.len());
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-count".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps", false),
                test_position("source-b", "cache helps slowly", false),
                test_position("source-c", "cache harms", false),
                test_position("source-d", "cache is neutral", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-c").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["load effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("valid count conflict");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "root-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-c".to_owned(),
                lineage_root: "root-c".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-d".to_owned(),
                lineage_root: "root-d".to_owned(),
                known: false,
            },
        ];
        supplements.supplied_probes = vec![test_discriminative_probe("probe-count")];
        let candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("shared-roots analysis: {err:?}"),
        };
        assert_eq!(candidate.positions.len(), 4);
        assert_eq!(candidate.independent_root_count, 2);
        assert!(candidate.independent_root_count <= candidate.positions.len());
        let mut known_roots: Vec<String> = supplements
            .lineage
            .iter()
            .filter(|entry| entry.known)
            .map(|entry| entry.lineage_root.clone())
            .collect();
        known_roots.sort();
        known_roots.dedup();
        assert_eq!(candidate.independent_root_count, known_roots.len());
        let unknown_group = candidate
            .lineage_groups
            .iter()
            .find(|group| !group.known)
            .expect("unknown lineage stays grouped without independence");
        assert!(
            unknown_group
                .member_sources
                .contains(&"source-d".to_owned())
        );
    }

    // WORK_UNIT_CASE: 673/66
    #[test]
    fn case_66_discriminative_probe_needs_differing_outcomes_or_unknown_criterion() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let policy = test_policy();
        let mut discriminative = test_supplements();
        discriminative.supplied_probes = vec![test_discriminative_probe("probe-66-disc")];
        let bound = test_conflict_naming_probe(Some("probe-66-disc"));
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &bound, &discriminative, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("discriminative probe analysis: {err:?}"),
            };
        assert_eq!(candidate.recommended_probes.len(), 1);
        let recommended = candidate
            .recommended_probes
            .first()
            .expect("discriminative probe stays recommended");
        assert_eq!(recommended.probe_id, "probe-66-disc");
        let supplied = discriminative
            .supplied_probes
            .first()
            .expect("supplied probe stays addressable");
        assert_eq!(recommended.objective_digest, supplied.objective.digest);
        assert_eq!(recommended.result_digest, supplied.schema.digest);
        assert_eq!(recommended.owner, supplied.owner_note);
        assert_eq!(recommended.verifier, supplied.verifier);
        assert_eq!(recommended.cost_note, supplied.cost_note);
        assert_eq!(recommended.risk_note, supplied.risk_note);
        assert_eq!(recommended.privacy_note, supplied.privacy_note);
        assert_eq!(recommended.effect_note, supplied.effect_note);
        assert_eq!(recommended.discriminates_positions.len(), 2);
        assert!(!branches_discriminate(
            &test_nondiscriminative_probe().schema
        ));
        assert!(branches_discriminate(&supplied.schema));
        let mut unknown_probe = test_nondiscriminative_probe();
        unknown_probe.probe_id = String::from("probe-66-unknown");
        unknown_probe.objective.invalidation_conditions = vec![ConditionAssumptionRef {
            assumption_id: "hit rate under load".to_owned(),
            assumption_digest: "a".repeat(64),
        }];
        unknown_probe.objective.digest = unknown_probe
            .objective
            .compute_digest()
            .expect("recomputed unknown probe digest stays valid");
        assert!(
            resolves_unknown(&unknown_probe, &test_supplements().unknowns).is_some(),
            "exact unknown-resolution criterion binds the load-bearing unknown"
        );
        let mut unknown_supplements = test_supplements();
        unknown_supplements.supplied_probes = vec![unknown_probe];
        let unknown_candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &unknown_supplements,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("unknown-resolving probe analysis: {err:?}"),
        };
        assert_eq!(unknown_candidate.recommended_probes.len(), 1);
        assert_eq!(
            unknown_candidate
                .recommended_probes
                .first()
                .expect("unknown probe stays recommended")
                .resolves_unknown,
            Some("hit rate under load".to_owned())
        );
        let mut rejected = test_supplements();
        rejected.supplied_probes = vec![test_nondiscriminative_probe()];
        let rejected_candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &rejected, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("nondiscriminative probe analysis: {err:?}"),
            };
        assert!(rejected_candidate.recommended_probes.is_empty());
    }

    // WORK_UNIT_CASE: 673/67
    #[test]
    fn case_67_classification_resolution_and_proof_stay_within_grounded_evidence() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("grounded analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        for position in &candidate.positions {
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "canonical grounded kind stays classified: {:?}",
                position.conflict_classes
            );
            for class in &position.conflict_classes {
                assert!(
                    KIND_PRECEDENCE.contains(class),
                    "classification never exceeds the canonical precedence table: {class:?}"
                );
            }
            assert!(
                !position.compatibility_note.trim().is_empty(),
                "compatibility mapping stays explicit without rewriting the original"
            );
            assert_eq!(
                position.stance,
                conflict.positions[position.position_index].stance
            );
        }
        assert_eq!(
            candidate.note, CONFLICT_PROOF_NOTE,
            "proof stays at the routing-only candidate ceiling"
        );
        assert_eq!(candidate.resolution_status, None);
        assert_eq!(supplements.external_resolution, None);
        let mut ordered_counter = supplements.counterevidence.clone();
        ordered_counter.sort();
        assert_eq!(candidate.counterevidence, ordered_counter);
        let mut ordered_unknowns = supplements.unknowns.clone();
        ordered_unknowns.sort();
        assert_eq!(candidate.unknowns, ordered_unknowns);
        let mut ordered_assumptions = supplements.assumptions.clone();
        ordered_assumptions.sort();
        assert_eq!(candidate.assumptions, ordered_assumptions);
        assert!(
            !candidate.invalidation_conditions.is_empty(),
            "proof carries explicit reopening conditions instead of a verdict"
        );
    }

    // WORK_UNIT_CASE: 673/68
    #[test]
    #[allow(clippy::too_many_lines)]
    fn case_68_bounded_malformed_input_stays_panic_free_without_winner_or_finish() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        let mut defaulted_policy = policy.clone();
        defaulted_policy.policy_revision = 0;
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &defaulted_policy,
        ) {
            Ok(candidate) => panic!("defaulted policy must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Policy { .. }),
            "defaulted policy fails closed: {err:?}"
        );
        let mut blank_owner = supplements.clone();
        blank_owner.supplied_probes = vec![{
            let mut probe = test_discriminative_probe("probe-68");
            probe.owner_note = String::from("   ");
            probe
        }];
        let err = match analyze_conflict(&item, &draft, &grounded, &conflict, &blank_owner, &policy)
        {
            Ok(candidate) => panic!("blank probe owner must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Shape { ref field, .. } if field == "probe.owner"),
            "blank probe owner fails closed: {err:?}"
        );
        let mut blank_objection = supplements.clone();
        blank_objection.objections = vec![SuppliedObjection {
            objection_id: "obj-blank".to_owned(),
            target_source: "source-a".to_owned(),
            statement: String::from("   "),
            grounded: true,
        }];
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &blank_objection,
            &policy,
        ) {
            Ok(candidate) => panic!("blank objection must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                ConflictAnalysisError::Shape { ref field, .. } if field == "objection.statement"
            ),
            "blank objection fails closed: {err:?}"
        );
        let mut duplicate_lineage = supplements.clone();
        duplicate_lineage.lineage.push(LineageAttribution {
            source_handle: "source-a".to_owned(),
            lineage_root: "root-changed".to_owned(),
            known: true,
        });
        let err = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &duplicate_lineage,
            &policy,
        ) {
            Ok(candidate) => panic!("duplicate lineage must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "duplicate lineage fails closed: {err:?}"
        );
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("bounded valid analysis: {err:?}"),
            };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.resolution_status, None);
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
        assert_eq!(candidate.note, CONFLICT_PROOF_NOTE);
        assert!(
            !candidate.note.contains("Finish"),
            "candidate carries no terminal-completion claim"
        );
        for position in &candidate.positions {
            assert!(
                matches!(
                    position.disposition,
                    PositionDispositionKind::LivePreserved
                        | PositionDispositionKind::MinorityPreserved
                        | PositionDispositionKind::CompatibleResidue
                        | PositionDispositionKind::SupersededHistory
                        | PositionDispositionKind::Withheld
                        | PositionDispositionKind::Unavailable
                        | PositionDispositionKind::Stale
                        | PositionDispositionKind::Refuted
                ),
                "disposition preserves without naming a winner"
            );
        }
        for probe in &candidate.recommended_probes {
            assert!(!probe.probe_id.trim().is_empty());
            assert!(!probe.effect_note.trim().is_empty());
        }
    }

    // WORK_UNIT_CASE: 673/8
    #[test]
    fn case_08_no_mutation_effect_or_execution() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let conflict = test_conflict();
        let supplements = test_supplements();
        let policy = test_policy();
        let candidate =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("bounded analysis: {err:?}"),
            };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.resolution_status, None,
            "no decision is issued by the analyzer"
        );
        assert_eq!(candidate.note, CONFLICT_PROOF_NOTE);
        assert!(!candidate.note.contains("Finish"));
        assert!(!candidate.note.contains("ConciliumPlan"));
        for probe in &candidate.recommended_probes {
            assert!(!probe.probe_id.trim().is_empty());
            assert!(!probe.owner.trim().is_empty());
            assert!(!probe.verifier.trim().is_empty());
            assert!(!probe.cost_note.trim().is_empty());
            assert!(!probe.risk_note.trim().is_empty());
            assert!(!probe.privacy_note.trim().is_empty());
            assert!(!probe.effect_note.trim().is_empty());
        }
        let replay =
            match analyze_conflict(&item, &draft, &grounded, &conflict, &supplements, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("replay analysis: {err:?}"),
            };
        assert_eq!(candidate.candidate_digest, replay.candidate_digest);
        assert_eq!(
            candidate.positions.len(),
            conflict.positions.len(),
            "analysis preserves without mutating the input set"
        );
        assert!(
            !candidate.invalidation_conditions.is_empty(),
            "reopening conditions stay explicit instead of an execution receipt"
        );
    }

    // WORK_UNIT_CASE: 673/15
    #[test]
    fn case_15_minority_position_retained() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-minority".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                ConflictPosition::new(
                    SourceId::new("source-b").expect("valid source"),
                    "cache harms tail latency under burst load".to_owned(),
                    BTreeSet::from(["assumption-burst".to_owned()]),
                    BTreeSet::new(),
                    true,
                )
                .expect("valid minority"),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("minority conflict stays valid");
        let candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("minority analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.positions.len(), 2);
        let minority = candidate
            .positions
            .iter()
            .find(|position| position.source_handle == "source-b")
            .expect("minority position stays visible");
        assert!(minority.minority);
        assert_eq!(
            minority.disposition,
            PositionDispositionKind::MinorityPreserved
        );
        assert_eq!(minority.stance, "cache harms tail latency under burst load");
        assert_eq!(minority.assumptions, vec!["assumption-burst".to_owned()]);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/16
    #[test]
    fn case_16_every_objection_counterexample_and_unknown_retained() {
        let mut supplements = test_supplements();
        supplements.objections = vec![
            SuppliedObjection {
                objection_id: "obj-1".to_owned(),
                target_source: "source-a".to_owned(),
                statement: "cold start unaffected".to_owned(),
                grounded: true,
            },
            SuppliedObjection {
                objection_id: "obj-2".to_owned(),
                target_source: "source-b".to_owned(),
                statement: "burst load reverses the effect".to_owned(),
                grounded: false,
            },
        ];
        supplements.counterevidence = vec![
            "burst load reverses the effect".to_owned(),
            "cold start unaffected".to_owned(),
        ];
        supplements.unknowns = vec![
            "burst load threshold".to_owned(),
            "hit rate under load".to_owned(),
        ];
        supplements.assumptions = vec!["assumption-1".to_owned()];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("objection retention analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.objections.len(), 2);
        for expected in &supplements.objections {
            let kept = candidate
                .objections
                .iter()
                .find(|objection| objection.objection_id == expected.objection_id)
                .unwrap_or_else(|| panic!("objection {} stays visible", expected.objection_id));
            assert_eq!(kept.target_source, expected.target_source);
            assert_eq!(kept.statement, expected.statement);
            assert_eq!(kept.grounded, expected.grounded);
        }
        let mut ordered_counters = supplements.counterevidence.clone();
        ordered_counters.sort();
        assert_eq!(candidate.counterevidence, ordered_counters);
        let mut ordered_unknowns = supplements.unknowns.clone();
        ordered_unknowns.sort();
        assert_eq!(candidate.unknowns, ordered_unknowns);
        assert!(!candidate.invalidation_conditions.is_empty());
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/17
    #[test]
    #[allow(clippy::too_many_lines)]
    fn case_17_stale_refuted_and_superseded_history_stays_addressable() {
        let receipt = test_receipt();
        let superseded = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-superseded".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::from(["warm key effect".to_owned()]),
            unresolved: BTreeSet::from(["burst load effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Superseded,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("superseded conflict stays valid");
        let superseded_candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &superseded,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("superseded analysis: {err:?}"),
        };
        assert_eq!(superseded_candidate.positions.len(), 2);
        assert!(
            superseded_candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::SupersededHistory)
        );
        let refuted_position = ConflictPosition::new(
            SourceId::new("source-a").expect("valid source"),
            "cache helps tail latency".to_owned(),
            BTreeSet::from(["assumption-1".to_owned()]),
            BTreeSet::from([ArtifactId::new("ctr-1").expect("valid artifact")]),
            false,
        )
        .expect("refuted position stays valid");
        let refuted = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-refuted".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                refuted_position,
                test_position("source-b", "cache harms tail latency", false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::from([ArtifactId::new("ctr-1").expect("valid artifact")]),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("refuted conflict stays valid");
        let refuted_candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &refuted,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("refuted analysis: {err:?}"),
        };
        let refuted_entry = refuted_candidate
            .positions
            .iter()
            .find(|position| position.source_handle == "source-a")
            .expect("refuted position stays addressable");
        assert_eq!(refuted_entry.disposition, PositionDispositionKind::Refuted);
        assert_eq!(refuted_entry.counters, vec!["ctr-1".to_owned()]);
        let mut stale_policy = test_policy();
        stale_policy.observation_time_ms = Some(1_800_000_000_000);
        stale_policy.deadline_ms = Some(1_800_000_000_000);
        let stale = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &superseded,
            &test_supplements(),
            &stale_policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("stale history analysis: {err:?}"),
        };
        assert_eq!(stale.outcome, ConflictOutcome::Stale);
        assert_eq!(stale.positions.len(), 2);
        assert!(
            stale
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::SupersededHistory)
        );
    }

    // WORK_UNIT_CASE: 673/18
    #[test]
    fn case_18_contradiction_under_equal_conditions() {
        let item = test_item();
        let draft = test_draft();
        let grounded = test_grounded();
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-contradiction".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                ConflictPosition::new(
                    SourceId::new("source-a").expect("valid source"),
                    "cache helps tail latency".to_owned(),
                    BTreeSet::from(["assumption-1".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
                ConflictPosition::new(
                    SourceId::new("source-b").expect("valid source"),
                    "cache harms tail latency".to_owned(),
                    BTreeSet::from(["assumption-1".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("contradiction conflict stays valid");
        // Equal conditions are asserted only because the owner-issued comparison
        // proves all eight dimensions equal; without it the honest note is the
        // non-assertive missing-comparison one.
        let mut supplements = test_supplements();
        supplements.owner_records = test_owner_records(None);
        let candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("contradiction analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.positions.len(), 2);
        for position in &candidate.positions {
            assert_eq!(position.disposition, PositionDispositionKind::LivePreserved);
            assert!(
                position
                    .compatibility_note
                    .contains("contradiction under equal"),
                "equal-condition contradiction stays explicit: {}",
                position.compatibility_note
            );
            assert_eq!(
                position.compatibility[0].relation,
                CompatibilityRelation::EqualConditions,
                "the note and the typed mapping read one owner-issued qualification"
            );
            assert_eq!(
                position.compatibility[0].supplement_version,
                SupplementVersion::OwnerRecordV2
            );
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "canonical kind stays classified: {:?}",
                position.conflict_classes
            );
            assert_eq!(
                position.stance,
                conflict.positions[position.position_index].stance
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/20
    #[test]
    fn case_20_owner_proved_supersession_versus_timestamp_only() {
        let receipt = test_receipt();
        let proved = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-supersession-proved".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::from(["warm key effect".to_owned()]),
            unresolved: BTreeSet::from(["burst load effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Superseded,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("owner-proved supersession stays valid");
        let proved_candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &proved,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("supersession analysis: {err:?}"),
        };
        assert_eq!(proved_candidate.outcome, ConflictOutcome::Complete);
        assert!(
            proved_candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::SupersededHistory)
        );
        assert_eq!(proved_candidate.resolution_status, None);
        let timestamp_only = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-timestamp-only".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "rate 5 per 100 measured monday", false),
                test_position(
                    "source-b",
                    "rate 7 per 100 measured friday, newer run",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("timestamp-only conflict stays valid");
        let timestamp_candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &timestamp_only,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("timestamp analysis: {err:?}"),
        };
        assert_eq!(timestamp_candidate.outcome, ConflictOutcome::Complete);
        assert!(
            timestamp_candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "a newer timestamp alone is not owner-proved supersession"
        );
        assert_eq!(timestamp_candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/21
    #[test]
    fn case_21_definition_unit_and_denominator_mismatch() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-definition".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                ConflictPosition::new(
                    SourceId::new("source-a").expect("valid source"),
                    "rate 5 per 100 warm keys under definition D1".to_owned(),
                    BTreeSet::from(["definition D1 per 100 warm keys".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
                ConflictPosition::new(
                    SourceId::new("source-b").expect("valid source"),
                    "rate 7 per 1000 cold starts under definition D2".to_owned(),
                    BTreeSet::from(["definition D2 per 1000 cold starts".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["rate comparison".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("definition conflict stays valid");
        // The unit and denominator mismatch is proven by the owner-issued
        // comparison on that dimension, not asserted from caller prose.
        let mut supplements = test_supplements();
        supplements.owner_records =
            test_owner_records(Some(ComparisonDimension::DefinitionUnitDenominator));
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("definition analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .any(|position| position.disposition == PositionDispositionKind::CompatibleResidue)
        );
        for position in &candidate.positions {
            assert_eq!(
                position.compatibility[0].differing_dimensions,
                vec![ComparisonDimension::DefinitionUnitDenominator],
                "the unit and denominator difference is the proven condition difference"
            );
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original propositions stay preserved"
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/22
    #[test]
    fn case_22_objective_value_disagreement_routes_to_human_controller() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-objective".to_owned(),
            kind: ConflictKind::Instruction,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "prefer latency objective under human constraint",
                    false,
                ),
                test_position(
                    "source-b",
                    "prefer cost objective under human constraint",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["objective trade-off".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-objective".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("objective conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("objective analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::HumanTaskController
        );
        assert!(!candidate.recommended_owner.rationale.trim().is_empty());
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .trim()
                .is_empty()
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/23
    #[test]
    fn case_23_policy_authority_effect_routes_to_governor() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-authority".to_owned(),
            kind: ConflictKind::Authority,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "allow effect under permission policy A", false),
                test_position("source-b", "deny effect under permission policy B", false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["effect permission".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-effect".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("authority conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("authority analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::Governor
        );
        assert!(!candidate.recommended_owner.rationale.trim().is_empty());
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .trim()
                .is_empty()
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/24
    #[test]
    fn case_24_evidence_quality_coverage_measurement_disagreement() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-evidence-quality".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "coverage 80 percent under method M1 supports the warm-key finding",
                    false,
                ),
                test_position(
                    "source-b",
                    "coverage 40 percent under method M2 disputes the warm-key finding",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["measurement coverage".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("evidence-quality conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("evidence-quality analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::EvidenceSource
        );
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "measurement disagreement stays live; no winner is issued"
        );
        for position in &candidate.positions {
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "evidence disagreement stays epistemic: {:?}",
                position.conflict_classes
            );
            assert_eq!(
                position.stance,
                conflict.positions[position.position_index].stance
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/25
    #[test]
    fn case_25_predictive_causal_mechanism_disagreement() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-causal-mechanism".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "mechanism M predicts the warm-key outcome through causal path P",
                    false,
                ),
                test_position(
                    "source-b",
                    "rival mechanism N predicts the same outcome through a different causal path",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["causal mechanism".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("causal-mechanism conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("causal-mechanism analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "rival mechanisms stay live; prediction alone is not causal proof"
        );
        for position in &candidate.positions {
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "mechanism disagreement stays epistemic: {:?}",
                position.conflict_classes
            );
            assert!(
                !position.compatibility_note.trim().is_empty(),
                "every mechanism position carries a compatibility note"
            );
            assert_eq!(
                position.stance,
                conflict.positions[position.position_index].stance
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/26
    #[test]
    fn case_26_partial_overlap_retains_compatible_residue() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-partial-overlap".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                ConflictPosition::new(
                    SourceId::new("source-a").expect("valid source"),
                    "cache helps warm-key reads in scope S1".to_owned(),
                    BTreeSet::from(["scope warm keys".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
                ConflictPosition::new(
                    SourceId::new("source-b").expect("valid source"),
                    "cache helps warm-key reads in scope S2".to_owned(),
                    BTreeSet::from(["scope cold starts".to_owned()]),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid position"),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["scope overlap".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("partial-overlap conflict stays valid");
        // The partial overlap is proven by the owner-issued scope difference.
        let mut supplements = test_supplements();
        supplements.owner_records =
            test_owner_records(Some(ComparisonDimension::ScopePopulationEnvironment));
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("partial-overlap analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .any(|position| position.disposition == PositionDispositionKind::CompatibleResidue),
            "partial overlap keeps a compatible residue"
        );
        for position in &candidate.positions {
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original propositions stay preserved"
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/27
    #[test]
    fn case_27_multiple_conflict_classes_retained_without_first_match_loss() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-multiple-classes".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "allow effect under permission policy alpha while implementation intent stays satisfied",
                    false,
                ),
                test_position(
                    "source-b",
                    "deny effect under permission policy beta while implementation architecture diverges",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["permission and intent".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-effect".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("multi-class conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("multi-class analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        let expected = vec![
            ConflictKind::Epistemic,
            ConflictKind::Authority,
            ConflictKind::Architecture,
        ];
        for position in &candidate.positions {
            assert_eq!(
                position.conflict_classes, expected,
                "every position retains all applicable classes in precedence order"
            );
        }
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/28
    #[test]
    fn case_28_required_primary_follows_canonical_precedence_not_first_match() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-precedence-primary".to_owned(),
            kind: ConflictKind::Architecture,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "evidence supports the rival causal mechanism claim for warm-key behavior",
                    false,
                ),
                test_position(
                    "source-b",
                    "evidence disputes the rival causal mechanism claim for warm-key behavior",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["mechanism support".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("precedence-primary conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("precedence-primary analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        let expected = vec![ConflictKind::Epistemic, ConflictKind::Architecture];
        for position in &candidate.positions {
            assert_eq!(
                position.conflict_classes, expected,
                "canonical precedence names the primary even when declared last"
            );
        }
        assert_eq!(
            candidate.positions[0].conflict_classes[0],
            ConflictKind::Epistemic,
            "first match in declaration order must not win the primary"
        );
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/29
    #[test]
    fn case_29_normalization_preserves_original_propositions_verbatim() {
        let receipt = test_receipt();
        let stance_a = "p99 latency 120ms over 1000 warm-key requests under definition D1";
        let stance_b = "p50 latency 80ms over 10000 mixed requests under definition D2";
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-normalization-preserves".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", stance_a, false),
                test_position("source-b", stance_b, false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["latency definition".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("normalization conflict stays valid");
        let run_once = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("normalization analysis: {err:?}"),
        };
        let run_twice = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("normalization replay: {err:?}"),
        };
        assert_eq!(run_once.outcome, ConflictOutcome::Complete);
        for position in &run_once.positions {
            let original = &conflict.positions[position.position_index].stance;
            assert_eq!(
                &position.stance, original,
                "typed comparison must not rewrite either original proposition"
            );
            assert_eq!(
                position.disposition,
                PositionDispositionKind::LivePreserved,
                "differing units stay live, never smoothed into agreement"
            );
        }
        assert_eq!(
            run_once.candidate_digest, run_twice.candidate_digest,
            "normalization is deterministic and preserves the originals"
        );
        let provenance = run_once
            .preservation
            .verdicts
            .iter()
            .find(|verdict| verdict.dimension == PreservationDimension::ProvenanceRetention)
            .expect("provenance verdict present");
        assert!(provenance.passed, "originals retained verbatim");
        assert_eq!(run_once.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/30
    #[test]
    fn case_30_ambiguous_prose_gains_no_invented_class() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-ambiguous-class".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache feels faster on some mornings", false),
                test_position("source-b", "cache feels slower on some mornings", false),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["felt speed".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("ambiguous conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("ambiguous analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        for position in &candidate.positions {
            assert_eq!(
                position.conflict_classes,
                vec![ConflictKind::Epistemic],
                "unsupported or ambiguous prose gains no invented class"
            );
            assert_eq!(
                position.disposition,
                PositionDispositionKind::LivePreserved,
                "ambiguity stays live, never resolved by prose smoothing"
            );
            assert!(
                !position.compatibility_note.contains("equal"),
                "an absent comparison never asserts equal conditions: {}",
                position.compatibility_note
            );
        }
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/31
    #[test]
    fn case_31_chronology_and_correlation_are_not_causal_proof() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-chronology-not-causal".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "cache deploy preceded the latency drop and therefore causes the improvement",
                    false,
                ),
                test_position(
                    "source-b",
                    "cache deploy preceded the latency drop yet the cause remains unknown",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["latency cause".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("chronology conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("chronology analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .any(|position| position.compatibility_note.contains("not causal")),
            "bare order must be marked as non-causal evidence"
        );
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "topology and co-change keep both positions live with no winner"
        );
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/32
    #[test]
    fn case_32_causal_hypothesis_requires_mechanism_falsifier_confounders() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-causal-hypothesis-needs-grounds".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "warming the cache causes the latency drop through mechanism M with no stated falsifier",
                    false,
                ),
                test_position(
                    "source-b",
                    "warming the cache moves with the latency drop while rival confounders stay open",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from([
                "causal mechanism".to_owned(),
                "falsifier".to_owned(),
                "confounders".to_owned(),
            ]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("causal-hypothesis conflict stays valid");
        let mut supplements = test_supplements();
        supplements.unknowns = vec![
            "falsifier for mechanism M is unstated".to_owned(),
            "mechanism M carries no measured evidence".to_owned(),
            "rival confounder disposition is unknown".to_owned(),
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("causal-hypothesis analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "a bare causal hypothesis stays live until mechanism, falsifier, and confounders are grounded"
        );
        for position in &candidate.positions {
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "causal-hypothesis disagreement stays epistemic: {:?}",
                position.conflict_classes
            );
            assert!(
                !position.compatibility_note.trim().is_empty(),
                "every causal position carries a compatibility note"
            );
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original causal propositions stay preserved verbatim"
            );
        }
        for unknown in &supplements.unknowns {
            assert!(
                candidate.unknowns.contains(unknown),
                "load-bearing causal unknown stays open: {unknown}"
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/33
    #[test]
    fn case_33_prediction_support_stays_defeasible_without_intervention() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-prediction-versus-intervention".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "model M predicts the warm-key outcome under predeclared prediction Q",
                    false,
                ),
                test_position(
                    "source-b",
                    "the warm-key causal claim needs an intervention trial which is still missing",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["prediction versus intervention support".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("prediction-intervention conflict stays valid");
        let mut supplements = test_supplements();
        supplements.unknowns =
            vec!["intervention discriminator for the warm-key claim is missing".to_owned()];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("prediction-intervention analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "prediction support stays defeasible without intervention support; no winner is issued"
        );
        for position in &candidate.positions {
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "prediction and intervention positions stay epistemic: {:?}",
                position.conflict_classes
            );
            assert!(
                !position.compatibility_note.trim().is_empty(),
                "every prediction position carries a compatibility note"
            );
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original prediction propositions stay preserved verbatim"
            );
        }
        for unknown in &supplements.unknowns {
            assert!(
                candidate.unknowns.contains(unknown),
                "missing intervention support stays an open unknown: {unknown}"
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/34
    #[test]
    fn case_34_missing_matched_control_and_evaluator_limits_claim() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-missing-control-evaluator".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "the treated group shows lower latency so the cache change improves warm keys",
                    false,
                ),
                test_position(
                    "source-b",
                    "no matched control group or separate evaluator verdict backs the cache change claim",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from([
                "matched control".to_owned(),
                "evaluator verdict".to_owned(),
            ]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-b").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("missing-control conflict stays valid");
        let mut supplements = test_supplements();
        supplements.unknowns = vec![
            "independent evaluator verdict is missing".to_owned(),
            "matched control group is missing".to_owned(),
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("missing-control analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "a claim without matched control or evaluator evidence stays live and limited, never proven"
        );
        for position in &candidate.positions {
            assert!(
                position.conflict_classes.contains(&ConflictKind::Epistemic),
                "control-limited disagreement stays epistemic: {:?}",
                position.conflict_classes
            );
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original control-limited propositions stay preserved verbatim"
            );
        }
        for unknown in &supplements.unknowns {
            assert!(
                candidate.unknowns.contains(unknown),
                "missing control and evaluator gaps stay open: {unknown}"
            );
        }
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::EvidenceSource,
            "the evidence-source owner must supply the missing control evidence"
        );
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/36
    #[test]
    fn case_36_unsupported_precision_gains_no_support() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-unsupported-precision".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "the cache cuts p99 latency by exactly 42.7 percent at line 118 since v2.3.1 through mechanism M",
                    false,
                ),
                test_position(
                    "source-b",
                    "the cache effect is file-level only with no supported line, version, or causal precision",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["supported precision ceiling".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("unsupported-precision conflict stays valid");
        let mut supplements = test_supplements();
        supplements.unknowns = vec![
            "highest supported precision is file level only".to_owned(),
            "numeric, time, version, and causal precision lack grounded support".to_owned(),
        ];
        supplements.supplied_probes = Vec::new();
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("unsupported-precision analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .all(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "unsupported precision stays live without invented support"
        );
        for position in &candidate.positions {
            assert_eq!(
                position.conflict_classes,
                vec![ConflictKind::Epistemic],
                "unsupported precision gains no invented class: {:?}",
                position.conflict_classes
            );
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original precision-claimed propositions stay preserved verbatim"
            );
            assert!(
                !position.compatibility_note.trim().is_empty(),
                "every precision-limited position carries a compatibility note"
            );
        }
        for unknown in &supplements.unknowns {
            assert!(
                candidate.unknowns.contains(unknown),
                "unsupported precision gap stays an open unknown: {unknown}"
            );
        }
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/37
    #[test]
    fn case_37_rivals_and_counterevidence_stay_live_without_truth_selection() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-rivals-without-selection".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("rival conflict stays valid");
        let mut supplements = test_supplements();
        supplements.counterevidence = vec![
            "cold start unaffected".to_owned(),
            "rival warm-key trial contradicts the tail claim".to_owned(),
        ];
        supplements.assumptions = vec!["assumption-1".to_owned()];
        supplements.unknowns = vec!["hit rate under load".to_owned()];
        supplements.supplied_probes = Vec::new();
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("rival-preservation analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .any(|position| position.disposition == PositionDispositionKind::LivePreserved),
            "rival positions stay live without truth selection"
        );
        assert!(
            candidate.positions.iter().any(|position| position.minority
                && position.disposition == PositionDispositionKind::MinorityPreserved),
            "minority rival evidence stays explicitly preserved"
        );
        for position in &candidate.positions {
            assert_eq!(
                position.stance, conflict.positions[position.position_index].stance,
                "original rival propositions stay preserved verbatim"
            );
        }
        let mut ordered_counter = supplements.counterevidence.clone();
        ordered_counter.sort();
        assert_eq!(candidate.counterevidence, ordered_counter);
        assert_eq!(candidate.objections.len(), 1);
        assert_eq!(candidate.unknowns, supplements.unknowns);
        assert_eq!(candidate.assumptions, supplements.assumptions);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/38
    #[test]
    fn case_38_supplied_probe_discriminates_two_live_positions() {
        let conflict = test_conflict_naming_probe(Some("probe-38-disc"));
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![test_discriminative_probe("probe-38-disc")];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("discriminative-probe analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            candidate
                .positions
                .iter()
                .all(
                    |position| position.disposition == PositionDispositionKind::LivePreserved
                        || position.disposition == PositionDispositionKind::MinorityPreserved
                ),
            "discriminated positions stay live; the probe recommends, never resolves"
        );
        assert_eq!(candidate.recommended_probes.len(), 1);
        let recommended = candidate
            .recommended_probes
            .first()
            .expect("discriminative probe stays recommended");
        let supplied = supplements
            .supplied_probes
            .first()
            .expect("supplied probe stays addressable");
        assert_eq!(recommended.probe_id, "probe-38-disc");
        assert_eq!(recommended.objective_digest, supplied.objective.digest);
        assert_eq!(recommended.result_digest, supplied.schema.digest);
        assert_eq!(recommended.owner, supplied.owner_note);
        assert_eq!(recommended.verifier, supplied.verifier);
        assert_eq!(recommended.cost_note, supplied.cost_note);
        assert_eq!(recommended.risk_note, supplied.risk_note);
        assert_eq!(recommended.privacy_note, supplied.privacy_note);
        assert_eq!(recommended.effect_note, supplied.effect_note);
        assert_eq!(recommended.discriminates_positions.len(), 2);
        assert!(
            recommended
                .discriminates_positions
                .contains(&"source-a".to_owned())
        );
        assert!(
            recommended
                .discriminates_positions
                .contains(&"source-b".to_owned())
        );
        assert!(branches_discriminate(&supplied.schema));
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/39
    #[test]
    fn case_39_supplied_probe_resolves_one_load_bearing_unknown() {
        let conflict = test_conflict();
        let mut probe = test_nondiscriminative_probe();
        probe.probe_id = String::from("probe-39-unknown");
        probe.objective.invalidation_conditions = vec![ConditionAssumptionRef {
            assumption_id: "hit rate under load".to_owned(),
            assumption_digest: "a".repeat(64),
        }];
        probe.objective.digest = probe
            .objective
            .compute_digest()
            .expect("recomputed unknown probe digest stays valid");
        assert!(
            resolves_unknown(&probe, &test_supplements().unknowns).is_some(),
            "probe declaration binds the load-bearing unknown before analysis"
        );
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![probe];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("unknown-resolving probe analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.recommended_probes.len(), 1);
        let recommended = candidate
            .recommended_probes
            .first()
            .expect("unknown-resolving probe stays recommended");
        assert_eq!(recommended.probe_id, "probe-39-unknown");
        assert_eq!(
            recommended.resolves_unknown,
            Some("hit rate under load".to_owned())
        );
        assert!(
            candidate
                .unknowns
                .contains(&"hit rate under load".to_owned()),
            "the load-bearing unknown stays open until the probe is executed elsewhere"
        );
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/41
    #[test]
    fn case_41_exact_probe_bounds_preserved_verbatim() {
        let conflict = test_conflict_naming_probe(Some("probe-41-bounds"));
        let mut supplied = test_discriminative_probe("probe-41-bounds");
        supplied.owner_note = String::from("source-b owns the follow-up under evidence authority");
        supplied.verifier = String::from("verifier-41");
        supplied.cost_note = String::from("two admitted reads within budget");
        supplied.risk_note = String::from("read-only with explicit rollback");
        supplied.privacy_note = String::from("no personal data leaves the freeze");
        supplied.effect_note = String::from("no canonical effect or mutation");
        assert!(
            branches_discriminate(&supplied.schema),
            "case 41 binds a discriminative outcome matrix"
        );
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![supplied.clone()];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("exact-bounds probe analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.recommended_probes.len(), 1);
        let recommended = candidate
            .recommended_probes
            .first()
            .expect("exact-bounds probe stays recommended");
        assert_eq!(recommended.probe_id, "probe-41-bounds");
        assert_eq!(recommended.objective_digest, supplied.objective.digest);
        assert_eq!(recommended.result_digest, supplied.schema.digest);
        assert_eq!(recommended.owner, supplied.owner_note);
        assert_eq!(recommended.verifier, supplied.verifier);
        assert_eq!(recommended.cost_note, supplied.cost_note);
        assert_eq!(recommended.risk_note, supplied.risk_note);
        assert_eq!(recommended.privacy_note, supplied.privacy_note);
        assert_eq!(recommended.effect_note, supplied.effect_note);
        assert_eq!(recommended.discriminates_positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/42
    #[test]
    fn case_42_blocked_and_over_budget_probes_stay_visible_unrecommended() {
        let conflict = test_conflict();
        let valid = test_discriminative_probe("probe-42-valid");
        let mut blocked = test_discriminative_probe("probe-42-blocked");
        blocked.blocked = true;
        let mut over_budget = test_discriminative_probe("probe-42-over");
        over_budget.over_budget = true;
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![valid, blocked.clone(), over_budget.clone()];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("blocked-probe analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.recommended_probes.len(), 1);
        assert_eq!(
            candidate
                .recommended_probes
                .first()
                .expect("valid probe stays recommended")
                .probe_id,
            "probe-42-valid"
        );
        assert_eq!(
            supplements.supplied_probes.len(),
            3,
            "blocked and over-budget probes stay visible in the denominator"
        );
        let mut only_blocked = test_supplements();
        only_blocked.supplied_probes = vec![blocked, over_budget];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &only_blocked,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("all-blocked probe analysis: {err:?}"),
        };
        assert_eq!(
            candidate.outcome,
            ConflictOutcome::Abstention,
            "every supplied probe blocked or over budget is an open probe gap; the \
             analysis is withheld rather than completed"
        );
        assert!(candidate.recommended_probes.is_empty());
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/43
    #[test]
    fn case_43_duplicate_probe_without_changed_condition_fails_closed() {
        let conflict = test_conflict();
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![
            test_discriminative_probe("probe-dup"),
            test_discriminative_probe("probe-dup"),
        ];
        let err = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => panic!("duplicate probe must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "duplicate probe identity fails closed: {err:?}"
        );
        let mut changed = test_nondiscriminative_probe();
        changed.probe_id = String::from("probe-dup");
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![test_discriminative_probe("probe-dup"), changed];
        let err = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => panic!("same-id changed content must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ConflictAnalysisError::Denominator { .. }),
            "no changed-condition exemption is invented for a duplicate probe id: {err:?}"
        );
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![
            test_discriminative_probe("probe-dup-a"),
            test_discriminative_probe("probe-dup-b"),
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("distinct probe analysis: {err:?}"),
        };
        assert_eq!(candidate.recommended_probes.len(), 2);
        assert_eq!(
            candidate
                .recommended_probes
                .first()
                .expect("first probe")
                .probe_id,
            "probe-dup-a"
        );
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/44
    #[test]
    fn case_44_supplied_probe_content_and_semantic_order_preserved() {
        let conflict = test_conflict();
        let probe_a = test_discriminative_probe("probe-44-a");
        let probe_b = test_discriminative_probe("probe-44-b");
        assert!(branches_discriminate(&probe_a.schema));
        assert!(branches_discriminate(&probe_b.schema));
        let mut forward = test_supplements();
        forward.supplied_probes = vec![probe_a.clone(), probe_b.clone()];
        let mut reverse = test_supplements();
        reverse.supplied_probes = vec![probe_b.clone(), probe_a.clone()];
        let first = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &forward,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("forward probe analysis: {err:?}"),
        };
        let second = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &reverse,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("reverse probe analysis: {err:?}"),
        };
        assert_eq!(first.recommended_probes.len(), 2);
        assert_eq!(first.recommended_probes[0].probe_id, "probe-44-a");
        assert_eq!(first.recommended_probes[1].probe_id, "probe-44-b");
        assert_eq!(
            first.candidate_digest, second.candidate_digest,
            "recommendation order is semantic sorted-id, not input order"
        );
        for recommended in &first.recommended_probes {
            let supplied = forward
                .supplied_probes
                .iter()
                .find(|probe| probe.probe_id == recommended.probe_id)
                .expect("recommended probe binds its supplied declaration");
            assert_eq!(recommended.objective_digest, supplied.objective.digest);
            assert_eq!(recommended.result_digest, supplied.schema.digest);
            assert_eq!(recommended.owner, supplied.owner_note);
            assert_eq!(recommended.verifier, supplied.verifier);
        }
        assert_eq!(probe_a.schema.branches.len(), 2);
        assert_eq!(probe_b.schema.branches.len(), 2);
        assert_eq!(first.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/45
    #[test]
    fn case_45_recommended_probe_carries_no_execution_or_receipt() {
        let conflict = test_conflict();
        let mut supplements = test_supplements();
        supplements.supplied_probes = vec![test_discriminative_probe("probe-45-decl")];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("declaration-only probe analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(candidate.recommended_probes.len(), 1);
        let recommended = candidate
            .recommended_probes
            .first()
            .expect("discriminative probe stays recommended");
        assert_eq!(recommended.probe_id, "probe-45-decl");
        assert!(!recommended.owner.trim().is_empty());
        assert!(!recommended.verifier.trim().is_empty());
        assert!(!recommended.cost_note.trim().is_empty());
        assert!(!recommended.risk_note.trim().is_empty());
        assert!(!recommended.privacy_note.trim().is_empty());
        assert!(!recommended.effect_note.trim().is_empty());
        let debug = format!("{candidate:?}");
        let probe_debug = format!("{recommended:?}");
        assert!(
            !debug.contains("ConciliumPlan"),
            "recommendation carries no Concilium plan: {debug}"
        );
        assert!(
            !debug.contains("Finish"),
            "recommendation carries no Finish signal: {debug}"
        );
        assert!(
            !probe_debug.to_lowercase().contains("executed"),
            "recommended probe carries no execution receipt: {probe_debug}"
        );
        assert!(
            !probe_debug.to_lowercase().contains("route reservation")
                && !probe_debug.to_lowercase().contains("budget receipt"),
            "recommended probe reserves no route and carries no budget receipt: {probe_debug}"
        );
        assert_eq!(candidate.note, CONFLICT_PROOF_NOTE);
        assert!(
            candidate.note.contains("probe execution"),
            "proof ceiling names probe execution as absent: {}",
            candidate.note
        );
        assert_eq!(candidate.resolution_status, None);
        assert!(
            !candidate.invalidation_conditions.is_empty(),
            "reopening conditions stay explicit instead of an execution receipt"
        );
    }

    // WORK_UNIT_CASE: 673/46
    #[test]
    fn case_46_epistemic_disagreement_names_evidence_source_owner() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-46-evidence-owner".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "warm-key coverage supports the cache finding",
                    false,
                ),
                test_position(
                    "source-b",
                    "narrow coverage disputes the cache finding",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["coverage sufficiency".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("evidence-owner conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("evidence-owner analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::EvidenceSource
        );
        assert_eq!(candidate.recommended_owner.owner_handle, "source-a");
        assert!(
            !candidate.recommended_owner.rationale.trim().is_empty(),
            "evidence owner carries a boundary rationale"
        );
        assert!(
            candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("evidence"),
            "evidence owner names its evidence contract: {}",
            candidate.recommended_owner.contract_needed
        );
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("assign"),
            "recommendation names the owner without assigning: {}",
            candidate.recommended_owner.contract_needed
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/47
    #[test]
    fn case_47_shared_evaluator_names_evaluator_verifier_owner() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-47-evaluator-owner".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position("source-a", "cache helps tail latency", false),
                test_position("source-b", "cache harms tail latency", true),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["tail latency effect".to_owned()]),
            unresolved_owners: BTreeSet::from([
                SourceId::new("source-a").expect("valid source"),
                SourceId::new("source-b").expect("valid source"),
            ]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("evaluator-owner conflict stays valid");
        let mut supplements = test_supplements();
        supplements.lineage = vec![
            LineageAttribution {
                source_handle: "source-a".to_owned(),
                lineage_root: "evaluator-holdout-shared".to_owned(),
                known: true,
            },
            LineageAttribution {
                source_handle: "source-b".to_owned(),
                lineage_root: "evaluator-holdout-shared".to_owned(),
                known: true,
            },
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("evaluator-owner analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::EvaluatorVerifier
        );
        assert_eq!(candidate.recommended_owner.owner_handle, "source-a");
        assert!(
            candidate
                .recommended_owner
                .rationale
                .to_lowercase()
                .contains("evaluator"),
            "evaluator owner names the independence limit: {}",
            candidate.recommended_owner.rationale
        );
        assert!(
            candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("evaluator"),
            "evaluator owner names its verifier contract: {}",
            candidate.recommended_owner.contract_needed
        );
        assert_eq!(candidate.independent_root_count, 1);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/48
    #[test]
    fn case_48_plan_value_disagreement_names_human_controller_owner() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-48-plan-value".to_owned(),
            kind: ConflictKind::Plan,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "prefer the latency-optimal plan under human value trade-off",
                    false,
                ),
                test_position(
                    "source-b",
                    "prefer the cost-optimal plan under human value trade-off",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["plan value trade-off".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-plan".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("plan-value conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("plan-value analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::HumanTaskController
        );
        assert_eq!(candidate.recommended_owner.owner_handle, "source-a");
        assert!(!candidate.recommended_owner.rationale.trim().is_empty());
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .trim()
                .is_empty()
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/49
    #[test]
    fn case_49_authority_effect_disagreement_names_governor_owner() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-49-governor-effect".to_owned(),
            kind: ConflictKind::Authority,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "grant the cache effect under governor permission P",
                    false,
                ),
                test_position(
                    "source-b",
                    "withhold the cache effect under governor permission Q",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["effect permission".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-effect".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("governor-effect conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("governor-effect analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::Governor
        );
        assert_eq!(candidate.recommended_owner.owner_handle, "source-a");
        assert!(
            !candidate.recommended_owner.rationale.trim().is_empty(),
            "governor owner carries a boundary rationale"
        );
        assert!(
            candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("evidence"),
            "governor owner names its decision contract: {}",
            candidate.recommended_owner.contract_needed
        );
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("assign"),
            "recommendation names the owner without assigning: {}",
            candidate.recommended_owner.contract_needed
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/50
    #[test]
    fn case_50_intent_satisfiability_names_architecture_owner() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-50-architecture-intent".to_owned(),
            kind: ConflictKind::Architecture,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "the implementation satisfies the stated cache intent under the current build",
                    false,
                ),
                test_position(
                    "source-b",
                    "the implementation cannot satisfy the stated cache intent under the current build",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["intent satisfiability".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-build".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("architecture-intent conflict stays valid");
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("architecture-intent analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::ArchitectureImplementation
        );
        assert_eq!(candidate.recommended_owner.owner_handle, "source-a");
        assert!(
            !candidate.recommended_owner.rationale.trim().is_empty(),
            "architecture owner carries a boundary rationale"
        );
        assert!(
            candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("evidence"),
            "architecture owner names its decision contract: {}",
            candidate.recommended_owner.contract_needed
        );
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("assign"),
            "recommendation names the owner without assigning: {}",
            candidate.recommended_owner.contract_needed
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/52
    #[test]
    fn case_52_privacy_handling_names_security_privacy_owner() {
        let receipt = test_receipt();
        let conflict = ConflictSet::new(ConflictSetParams {
            conflict_id: "conflict-52-privacy-owner".to_owned(),
            kind: ConflictKind::Epistemic,
            scope: "scope-1".to_owned(),
            task_id: None,
            positions: vec![
                test_position(
                    "source-a",
                    "warm-key coverage supports the cache finding",
                    false,
                ),
                test_position(
                    "source-b",
                    "narrow coverage disputes the cache finding",
                    false,
                ),
            ],
            evidence_refs: BTreeSet::new(),
            owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            common_lineage: BTreeSet::new(),
            resolved_parts: BTreeSet::new(),
            unresolved: BTreeSet::from(["coverage sufficiency".to_owned()]),
            unresolved_owners: BTreeSet::from([SourceId::new("source-a").expect("valid source")]),
            acceptability: ArgumentAcceptability::Contested,
            defeated_refs: BTreeSet::new(),
            probe: None,
            decision_owner: SourceId::new("source-a").expect("valid source"),
            affected_actions: vec!["decide-cache".to_owned()],
            lifecycle: ConflictLifecycle::Open,
            receipt_digest: receipt.bundle_digest.clone(),
        })
        .expect("privacy-owner conflict stays valid");
        let mut supplements = test_supplements();
        supplements.unknowns = vec![
            "privacy handling boundary for the warm-key evidence requires clearance".to_owned(),
        ];
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("privacy-owner analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert_eq!(
            candidate.recommended_owner.kind,
            DecisionOwnerKind::SecurityPrivacy
        );
        assert_eq!(candidate.recommended_owner.owner_handle, "source-a");
        assert!(
            candidate
                .recommended_owner
                .rationale
                .to_lowercase()
                .contains("privacy"),
            "security owner names the handling boundary: {}",
            candidate.recommended_owner.rationale
        );
        assert!(
            candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("privacy"),
            "security owner names its handling contract: {}",
            candidate.recommended_owner.contract_needed
        );
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .to_lowercase()
                .contains("assign"),
            "recommendation names the owner without assigning: {}",
            candidate.recommended_owner.contract_needed
        );
        assert_eq!(candidate.positions.len(), 2);
        assert_eq!(candidate.resolution_status, None);
    }

    // WORK_UNIT_CASE: 673/54
    #[test]
    fn case_54_owner_recommendation_is_naming_only_contract() {
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("recommendation-contract analysis: {err:?}"),
        };
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
        assert!(
            !candidate.recommended_owner.owner_handle.trim().is_empty(),
            "recommendation names the owner handle"
        );
        assert!(
            !candidate.recommended_owner.rationale.trim().is_empty(),
            "recommendation carries a boundary rationale"
        );
        assert!(
            !candidate
                .recommended_owner
                .contract_needed
                .trim()
                .is_empty(),
            "recommendation names the contract the owner needs"
        );
        let contract = format!(
            "{} {} {}",
            candidate.recommended_owner.owner_handle,
            candidate.recommended_owner.rationale,
            candidate.recommended_owner.contract_needed
        );
        let low = contract.to_lowercase();
        for forbidden in ["assign", "authoriz", "launch", "execut"] {
            assert!(
                !low.contains(forbidden),
                "recommendation names without {forbidden}: {contract}"
            );
        }
        assert_eq!(candidate.resolution_status, None);
        assert_eq!(candidate.note, CONFLICT_PROOF_NOTE);
        assert!(
            !candidate.invalidation_conditions.is_empty(),
            "reopening conditions stay explicit instead of an assignment receipt"
        );
    }

    // WORK_UNIT_CASE: 673/55
    #[test]
    fn case_55_complete_without_receipt_unresolved_with_receipt_verbatim() {
        let plain = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("unresolved analysis: {err:?}"),
        };
        assert_eq!(plain.outcome, ConflictOutcome::Complete);
        assert_eq!(
            plain.resolution_status, None,
            "complete analysis stays unresolved without an external receipt"
        );
        assert_eq!(plain.positions.len(), 2);
        let mut resolved_supplements = test_supplements();
        resolved_supplements.external_resolution = Some(ExternalResolution {
            decision_digest: "c".repeat(64),
            decided_by: "human-owner".to_owned(),
            note: "external decision retained with dissent".to_owned(),
        });
        let retained = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &resolved_supplements,
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("retained-resolution analysis: {err:?}"),
        };
        assert_eq!(retained.outcome, ConflictOutcome::Complete);
        let status = retained
            .resolution_status
            .expect("supplied receipt stays retained");
        assert_eq!(status.decision_digest, "c".repeat(64));
        assert_eq!(status.decided_by, "human-owner");
        assert_eq!(status.note, "external decision retained with dissent");
        assert_eq!(
            retained.positions.len(),
            2,
            "a retained receipt never resolves the preserved rivals here"
        );
        assert!(
            retained
                .invalidation_conditions
                .iter()
                .any(|condition| condition.contains("external resolution receipt")),
            "arrival of an external receipt reopens review: {:?}",
            retained.invalidation_conditions
        );
        let mut malformed = test_supplements();
        malformed.external_resolution = Some(ExternalResolution {
            decision_digest: "not-a-digest".to_owned(),
            decided_by: "human-owner".to_owned(),
            note: "malformed receipt".to_owned(),
        });
        let err = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &malformed,
            &test_policy(),
        ) {
            Ok(candidate) => panic!("malformed receipt must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ConflictAnalysisError::Digest { .. }));
    }

    // WORK_UNIT_CASE: 673/63
    #[test]
    fn case_63_diagnostics_stay_bounded_and_redacted() {
        let long = "x".repeat(MAX_REDACTED_CHARS + 20);
        let truncated = redact(&long);
        assert_eq!(truncated.len(), MAX_REDACTED_CHARS + 3);
        assert!(truncated.ends_with("..."));
        assert_eq!(
            &truncated[..MAX_REDACTED_CHARS],
            &long[..MAX_REDACTED_CHARS]
        );
        let cleaned = redact("ab\x00cd\x1bEF\x7f");
        assert!(
            !cleaned.chars().any(char::is_control),
            "control characters never leak into diagnostics"
        );
        assert!(cleaned.contains('?'));
        assert_eq!(redact("plain diagnostic"), "plain diagnostic");
        let rendered = ConflictAnalysisError::Denominator {
            detail: redact(&long),
        }
        .to_string();
        assert!(!rendered.chars().any(char::is_control));
        assert!(rendered.len() <= "denominator: ".len() + MAX_REDACTED_CHARS + 3);
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("redaction-path analysis: {err:?}"),
        };
        assert_eq!(candidate.note, CONFLICT_PROOF_NOTE);
        assert!(!candidate.note.chars().any(char::is_control));
        for condition in &candidate.invalidation_conditions {
            assert!(
                !condition.chars().any(char::is_control),
                "invalidation condition stays printable: {condition:?}"
            );
        }
        let mut drifted_grounded = test_grounded();
        drifted_grounded.job_id = String::from("job-9");
        let err = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &drifted_grounded,
            &test_conflict(),
            &test_supplements(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("drifted job must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            !err.to_string().chars().any(char::is_control),
            "error diagnostics stay printable: {err:?}"
        );
    }
}
