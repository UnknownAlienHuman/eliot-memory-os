//! Lineage-preserving identity structure repair candidate (A-27).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one typed merge, split, or accepted prior false-merge reversal. The
//! handler proposes one reversible candidate that preserves complete lineage,
//! raw history, counterexamples, minority and residual distinctions, and
//! every affected dependency. It never allocates identifiers, mutates
//! canonical state, rewrites relations, executes providers, stores, models,
//! or tools, and never carries authority, effect, or finish.
//!
//! Cell `smart.dreamer.structure_repair`, order 27. All inputs are immutable
//! and caller supplied. The A-05 receipt is checked intrinsically through its
//! own validation entry points and is never re-executed here. A-30
//! provenance, influence, false-relation, stale-view, and representation
//! repairs without identity surgery are rejected distinctly: they own no
//! [`CurationKind::Merge`] or [`CurationKind::Split`] payload and must not
//! route here. Reversal without a representable canonical payload returns to
//! A-03. No screening, grounding, common validation, canonical mutation,
//! authority, effect, store, governor, model, clock, or finish surface exists
//! in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the six typed
//! parameters of [`propose_structure_repair`], never decoded from ambient
//! bytes.
//!
//! Runtime boundary: malformed or mismatched inputs fail closed as
//! [`StructureRepairError`]. Semantic shortfalls (insufficient equivalence,
//! shared-lineage-only support, unresolved distinctions, raised ceilings,
//! partial closure, unknown effects, stale revisions, duplicates) are inert
//! terminal dispositions carried by [`StructureRepairCandidate`], never
//! errors that invite a blind retry. A blocked, malformed, over-budget,
//! past-deadline, or cancelled-before-emission request emits zero effects.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal beyond the bounded member and dependent lists, relation
//! mutation, provider, model, tool, ambient-state, authority, effect, or
//! terminal-completion calls by construction; the only fallible work is pure
//! bounded validation, and the only cryptography is the canonical digest
//! below. There are no placeholder, mock, canned, or pseudo paths: every
//! branch binds an explicit input field.
//!
//! Test coverage note: 8 of 56 `WORK_UNIT_CASE 665/*` cases execute here
//! (665/1 valid merge completes, 665/3 nonidentity A-30 repair rejected,
//! 665/4 bundle mismatch fails closed, 665/5 replay and duplicate identity
//! disposition, 665/11 shared lineage without equivalence stays
//! insufficient, 665/19 two-part split completes, 665/33 clean inverse
//! reversal completes, 665/45 rollback and invalidation closure present).
//! The 8 tests also substantively exercise 665/9 grounded semantic
//! equivalence, 665/18 the complete merge rewrite manifest, 665/20 exact
//! union and disjointness, 665/30 prior merge receipt and ancestry, 665/38
//! merged-revision lineage retention, 665/43 seven independent dimensions,
//! 665/46 no applied transition surface, and 665/53 per-member split
//! accounting. The remaining 40 of 56 are deferred per START.md s1; #966
//! admission is separate. Deferred: 665/2, 665/6, 665/7, 665/8, 665/10,
//! 665/12, 665/13, 665/14, 665/15, 665/16, 665/17, 665/21, 665/22, 665/23,
//! 665/24, 665/25, 665/26, 665/27, 665/28, 665/29, 665/31, 665/32, 665/34,
//! 665/35, 665/36, 665/37, 665/39, 665/40, 665/41, 665/42, 665/44, 665/47,
//! 665/48, 665/49, 665/50, 665/51, 665/52, 665/54, 665/55, 665/56.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    CurationKind, CurationPayload, GroundedDreamDraft, PRESERVATION_DIMENSIONS, PreservationDimension,
    PreservationReport, ValidatedCurationItem, check_fence, is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum source members admitted in one repair proposal.
pub const MAX_MEMBERS: usize = 64;
/// Maximum dependents admitted in one dependency projection.
pub const MAX_DEPENDENTS: usize = 128;
/// Maximum partitions admitted in one split or reversal proposal.
pub const MAX_PARTITIONS: usize = 8;
/// Maximum members admitted inside any single partition.
pub const MAX_PARTITION_MEMBERS: usize = 64;
/// Maximum evidence refs admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum closure refs admitted in any single closure list.
pub const MAX_CLOSURE_REFS: usize = 256;
/// Maximum distinctions admitted in any single distinction list.
pub const MAX_DISTINCTIONS: usize = 32;
/// Maximum rollback steps admitted in one rollback plan.
pub const MAX_ROLLBACK_STEPS: usize = 256;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for any identity field bound into digests.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum bytes for an allocation-request handle.
pub const MAX_ALLOC_HANDLE_BYTES: usize = 256;
/// Maximum bytes for task, scope, authority, and proof-ceiling fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any bounded note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Expected preservation dimensions attested through the receipt digest.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const REPAIR_PROOF_NOTE: &str = "a-27 candidate-only aggregation: one typed merge, split, or accepted false-merge reversal preserved without screening, grounding, common validation, canonical mutation, identifier allocation, authority, effect, store, governor, model, clock, or finish";

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

/// Returns true when values are sorted strictly ascending with no duplicates.
fn is_sorted_unique(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        if index > 0 {
            let prev_ok = values.get(index.saturating_sub(1));
            let cur_ok = values.get(index);
            if let (Some(prev), Some(cur)) = (prev_ok, cur_ok) {
                if prev >= cur {
                    return false;
                }
            } else {
                return false;
            }
        }
        index = index.saturating_add(1);
    }
    true
}

/// Lowercases a note without allocating authority.
fn lowered(note: &str) -> String {
    note.to_lowercase()
}

/// Returns true when the haystack contains the needle as a substring.
fn contains_marker(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

// ---------------------------------------------------------------------------
// Closed forbidden markers (similarity overreach, ceiling raises).
// ---------------------------------------------------------------------------

/// Substrings that mark a similarity or confidence proof overreach.
///
/// Lexical overlap, vector similarity, co-retrieval, and bare confidence
/// never establish identity equivalence; only scoped semantic equivalence
/// grounded in the supplied evidence refs does.
pub const SIMILARITY_MARKERS: &[&str] = &[
    "similar",
    "looks like",
    "confidence proves",
    "embedding proves",
    "vector similarity proves",
    "co-retrieval proves",
    "same wording proves",
];

/// Substrings that mark a support, authority, privacy, or influence raise.
///
/// A repair candidate preserves every ceiling verbatim; any claimed raise is
/// refused without compensation from other dimensions.
pub const CEILING_RAISE_MARKERS: &[&str] = &[
    "raise support",
    "raise authority",
    "raise privacy",
    "elevated support",
    "elevated authority",
    "expanded authority",
    "escalate privilege",
    "wider influence",
];

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

// ---------------------------------------------------------------------------
// Public vocabulary: subtypes, outcomes, members, dependents, policy.
// ---------------------------------------------------------------------------

/// Exactly-one repair subtype selected from the typed curation payload.
///
/// No third global kind exists: a reversal is always carried by a
/// representable canonical [`CurationKind::Merge`] or
/// [`CurationKind::Split`] payload plus the accepted prior-transition
/// evidence. A reversal without such a payload returns to A-03.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepairSubtype {
    /// Two or more equivalent sources proposed under one allocation request.
    Merge,
    /// One whole partitioned into disjoint children plus optional residue.
    Split,
    /// Accepted inverse of one exact prior false merge.
    Reversal,
}

impl RepairSubtype {
    /// Returns the canonical spelling of this subtype.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Split => "split",
            Self::Reversal => "reversal",
        }
    }
}

/// Terminal outcome of one structure-repair proposal.
///
/// Fail-closed ordering applies: malformed inputs are
/// [`StructureRepairError`], while every semantic shortfall below is an
/// inert outcome that preserves all source branches without effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepairOutcome {
    /// One complete candidate with full accounting and proof.
    Complete,
    /// A candidate with named partial coverage; completeness is blocked.
    Partial,
    /// The proposed repair duplicates an already known identity.
    Duplicate,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// The request is rejected with a boundary handoff.
    Rejected,
    /// No proposal is offered under the governing policy.
    Abstention,
    /// Unknown effects block the candidate until the owner reconciles.
    Blocked,
    /// Equivalence or distinction evidence is insufficient for the subtype.
    Insufficient,
}

impl RepairOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Duplicate => "duplicate",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::Abstention => "abstention",
            Self::Blocked => "blocked",
            Self::Insufficient => "insufficient",
        }
    }
}

/// Exactly-one disposition per source member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberDispositionKind {
    /// Member is retained with full revision and history, untouched.
    RetainedWithHistory,
    /// Member is proposed for retarget to the typed allocation request.
    RetargetToAllocation,
    /// Member is proposed for restore to its pre-merge identity.
    RestoredToPremerge,
    /// Member is held as unresolved residue, assigned nowhere.
    ResidueHeld,
}

impl MemberDispositionKind {
    /// Returns the canonical spelling of this member disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetainedWithHistory => "retained_with_history",
            Self::RetargetToAllocation => "retarget_to_allocation",
            Self::RestoredToPremerge => "restored_to_premerge",
            Self::ResidueHeld => "residue_held",
        }
    }
}

/// Exactly-one disposition per affected dependent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DependentDispositionKind {
    /// Dependent is unchanged, carried with its supporting evidence.
    UnchangedWithEvidence,
    /// Dependent endpoint is proposed for retarget to the new identity.
    Retarget,
    /// Derived dependent is proposed for scoped semantic duplication.
    ScopedSemanticDuplication,
    /// Dependent must be invalidated, rebuilt, and verified by its owner.
    InvalidateRebuildVerify,
    /// Dependent is quarantined for reconciliation by its owning handler.
    QuarantineReconcileByOwner,
    /// Dependent mutation is unknown and blocks ready qualification.
    BlockedUnknown,
}

impl DependentDispositionKind {
    /// Returns the canonical spelling of this dependent disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnchangedWithEvidence => "unchanged_with_evidence",
            Self::Retarget => "retarget",
            Self::ScopedSemanticDuplication => "scoped_semantic_duplication",
            Self::InvalidateRebuildVerify => "invalidate_rebuild_verify",
            Self::QuarantineReconcileByOwner => "quarantine_reconcile_by_owner",
            Self::BlockedUnknown => "blocked_unknown",
        }
    }
}

/// Frozen bundle binding the proposal replays against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenBundle {
    /// Frozen bundle digest; must equal the receipt bundle digest.
    pub bundle_digest: String,
    /// Frozen manifest digest; must equal the receipt manifest digest.
    pub manifest_digest: String,
}

/// One source member of the repair denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    /// Stable member identity unique inside the proposal.
    pub member_id: String,
    /// Current revision of this member.
    pub revision: String,
    /// Source handle backing this member.
    pub source_ref: String,
    /// Immutable raw-episode ref preserving this member's history.
    pub raw_episode_ref: String,
    /// Evidence digest binding this member (64 lowercase hex).
    pub evidence_digest: String,
    /// Record type; must be compatible across a merge and with the subject.
    pub record_type: String,
    /// Owning handler of this member.
    pub owner: String,
    /// Schema identity of this member.
    pub schema: String,
}

/// One requested child partition of a split or reversal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionRequest {
    /// Requested child basename; the issued identity stays an allocation.
    pub partition_basename: String,
    /// Member identities assigned to this child, sorted and unique.
    pub member_ids: Vec<String>,
    /// Discriminator naming the boundary this child is split on.
    pub discriminator: String,
    /// Counterexamples this child must keep answering, scoped from supply.
    pub counterexamples: Vec<String>,
}

/// Exact prior false-merge transition a reversal inverts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorTransition {
    /// Prior merge operation identity.
    pub prior_operation_id: String,
    /// Prior merge idempotency key.
    pub prior_idempotency_key: String,
    /// Prior merge receipt digest (64 lowercase hex).
    pub prior_receipt_digest: String,
    /// Pre-merge member identities in sorted unique order.
    pub premerge_ids: Vec<String>,
    /// Pre-merge member revisions parallel to `premerge_ids`.
    pub premerge_revisions: Vec<String>,
    /// Merged identity the prior transition produced.
    pub merged_id: String,
    /// Merged revision the prior transition produced.
    pub merged_revision: String,
    /// Transition fence of the prior merge.
    pub fence: eliot_contracts::StateFence,
    /// Authority that owned the prior merge.
    pub authority: String,
    /// Reconciliation note naming how later effects were accounted.
    pub reconciliation_note: String,
    /// True when later writes force forward repair instead of an inverse.
    pub has_later_writes: bool,
    /// True when unknown effects block any unsafe rollback.
    pub has_unknown_effects: bool,
}

/// Structural projection bounding one repair proposal.
///
/// The member denominator plus the payload-proposed identity must exactly
/// cover the curation denominator: members plus `merged` for a merge,
/// members plus `whole` for a split or reversal. Split and reversal
/// partitions plus residue must then account for every member exactly once;
/// the subject (the whole under partition) is the partitioned parent and is
/// retained with history rather than assigned into a child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuralProjection {
    /// Subject identity; must equal the payload proposed identity.
    pub subject_id: String,
    /// Current subject revision.
    pub subject_revision: String,
    /// Subject record type bounding compatibility.
    pub record_type: String,
    /// Subject owner bounding compatibility.
    pub owner: String,
    /// Subject schema bounding compatibility.
    pub schema: String,
    /// Complete source member denominator.
    pub members: Vec<MemberRecord>,
    /// Scoped semantic-equivalence note grounding a merge.
    pub equivalence_note: String,
    /// Evidence refs proving equivalence; empty means lineage-only support.
    pub equivalence_refs: Vec<String>,
    /// Material distinctions that block a merge while unresolved.
    pub unresolved_distinctions: Vec<String>,
    /// Counterexample refs retained through the repair.
    pub counterexample_refs: Vec<String>,
    /// Minority refs that must survive the repair.
    pub minority_refs: Vec<String>,
    /// Residual refs that must survive the repair.
    pub residual_refs: Vec<String>,
    /// Shared-lineage refs; never independent support for equivalence.
    pub shared_lineage_refs: Vec<String>,
    /// Support ceiling preserved verbatim, never raised.
    pub support_ceiling: String,
    /// Authority ceiling preserved verbatim, never raised.
    pub authority_ceiling: String,
    /// Privacy ceiling preserved verbatim, never raised.
    pub privacy_ceiling: String,
    /// Requested target basename; must equal the subject identity.
    pub requested_target_basename: String,
    /// Requested child partitions for a split or reversal.
    pub partitions: Vec<PartitionRequest>,
    /// Members held out of every partition, blocking completeness.
    pub unresolved_residue: Vec<String>,
    /// Accepted prior false merge; present selects the reversal subtype.
    pub prior_transition: Option<PriorTransition>,
    /// Retained immutable raw-history refs.
    pub raw_history_refs: Vec<String>,
    /// Ancestry refs proving the subject descends from the prior merge.
    pub ancestry_refs: Vec<String>,
    /// Known subject identities for replay and duplicate disposition.
    pub known_subject_ids: Vec<String>,
    /// Known candidate digests for replay disposition.
    pub known_candidate_digests: Vec<String>,
    /// Exact subject this proposal duplicates, when any.
    pub duplicate_of: Option<String>,
    /// Verifier bound to the rollback and invalidation plans.
    pub verifier: String,
}

/// One affected dependent of the repair denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependentRef {
    /// Stable dependent identity unique inside the projection.
    pub dependent_id: String,
    /// Dependent kind driving the single disposition for this dependent.
    pub dependent_kind: String,
    /// Endpoint handle of this dependent.
    pub endpoint: String,
    /// Relation spelling binding this dependent to the subject.
    pub relation: String,
    /// Owner that must verify or reconcile this dependent.
    pub owner: String,
    /// Current revision of this dependent.
    pub revision: String,
}

/// Dependency projection bounding closure over every affected dependent.
///
/// The denominator includes every affected incoming and outgoing relation,
/// derived summary, concept, procedure, view, context, cue, index, support,
/// accessibility, influence, disclosure derivation, negative memory,
/// fingerprint, task, decision, artifact, provenance, audit, and recovery
/// reference. Each is affected, unaffected with evidence, stale, blocked,
/// unavailable, unknown, or justified not-applicable; an empty dependent
/// list without qualified closure is not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyProjection {
    /// Every affected dependent in sorted unique identity order.
    pub dependents: Vec<DependentRef>,
    /// True only with current policy-required closure over all dependents.
    pub closure_complete: bool,
    /// Note qualifying the closure claim.
    pub closure_note: String,
}

/// Closed policy governing one structure-repair proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructureRepairPolicy {
    /// Governing policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Policy revision; zero is rejected as a defaulted binding.
    pub policy_revision: u32,
    /// Maximum members admitted in the structural denominator.
    pub max_members: usize,
    /// Maximum dependents admitted in the dependency projection.
    pub max_dependents: usize,
    /// Maximum partitions admitted in a split or reversal.
    pub max_partitions: usize,
    /// Maximum evidence items admitted per list.
    pub max_evidence_items: usize,
    /// True selects explicit partial emission; false selects abstention.
    pub allow_partial: bool,
    /// True when the caller cancelled this proposal before emission.
    pub cancelled: bool,
    /// Explicit observation time in milliseconds, when bounded.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, when bounded.
    pub deadline_ms: Option<u64>,
    /// External owner of identifier allocation; this cell mints nothing.
    pub allocator_owner: String,
    /// Bounded note naming the repair intent for the allocating owner.
    pub repair_note: String,
}

/// Typed external allocation request.
///
/// New identities are always requests to the allocating owner named by the
/// policy, never minted target identifiers. There is no issued-identity
/// field by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationRequest {
    /// Requested handle spelling proposed to the allocating owner.
    pub requested_handle: String,
    /// Allocating owner that must issue or decline the identity.
    pub owner: String,
    /// Bounded reason naming the evidence behind the request.
    pub reason: String,
}

/// One per-member disposition carried in member order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberDisposition {
    /// Member identity this disposition accounts for.
    pub member_id: String,
    /// Closed disposition kind for this member.
    pub kind: MemberDispositionKind,
    /// Target handle or retained identity for this member.
    pub target: String,
    /// Bounded reason naming the evidence behind this disposition.
    pub reason: String,
    /// Evidence ref backing this disposition.
    pub evidence_ref: String,
    /// Member revision this disposition is bound to.
    pub revision: String,
    /// Verifier bound to this member.
    pub verifier: String,
    /// Inverse note restoring this member's before state.
    pub inverse_note: String,
}

/// One per-dependent disposition carried in dependent order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependentDisposition {
    /// Dependent identity this disposition accounts for.
    pub dependent_id: String,
    /// Closed disposition kind for this dependent.
    pub kind: DependentDispositionKind,
    /// Owner that owns this dependent.
    pub owner: String,
    /// Bounded reason naming the evidence behind this disposition.
    pub reason: String,
    /// Evidence ref backing this disposition.
    pub evidence_ref: String,
    /// Verifier bound to this dependent.
    pub verifier: String,
    /// Inverse or compensation note for this dependent.
    pub inverse_note: String,
}

/// Equivalence report distinguishing proof from shared lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivalenceReport {
    /// True only with explicit scoped semantic equivalence.
    pub equivalent: bool,
    /// Bounded basis note; never echoes free-text input verbatim.
    pub basis_note: String,
    /// Evidence refs proving equivalence.
    pub equivalence_refs: Vec<String>,
    /// Shared-lineage refs carried as lineage only, never as support.
    pub shared_lineage_refs: Vec<String>,
    /// Material distinctions preserved through the repair.
    pub distinction_notes: Vec<String>,
}

/// Rollback plan restoring the before state without applying anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackPlan {
    /// Ordered rollback steps naming retained revisions and verifiers.
    pub steps: Vec<String>,
    /// Verifier that checks rollback completion.
    pub verifier: String,
    /// Exact inverse restoring the before state.
    pub inverse_note: String,
}

/// Dependent-invalidation plan verified without applying anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidationPlan {
    /// One entry per dependent naming disposition, verifier, and inverse.
    pub entries: Vec<String>,
    /// Verifier that checks invalidation completion.
    pub verifier: String,
}

/// Complete lineage-preserving structure-repair candidate envelope.
///
/// The envelope is never an applied transition, never a reservation, and
/// never a finish signal. Every new identity is a typed allocation request
/// to the external allocating owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructureRepairCandidate {
    /// Exactly-one repair subtype carried by this candidate.
    pub subtype: RepairSubtype,
    /// Terminal outcome for this proposal.
    pub outcome: RepairOutcome,
    /// Subject identity this candidate repairs.
    pub subject_id: String,
    /// Allocation request for the merge target or retained parent.
    pub target_allocation: AllocationRequest,
    /// One allocation request per child partition, in partition order.
    pub child_allocations: Vec<AllocationRequest>,
    /// One disposition per member in member order.
    pub member_dispositions: Vec<MemberDisposition>,
    /// One disposition per dependent in dependent order.
    pub dependent_dispositions: Vec<DependentDisposition>,
    /// Equivalence report distinguishing proof from shared lineage.
    pub equivalence: EquivalenceReport,
    /// Seven independent preservation verdicts with no averaging.
    pub preservation: PreservationReport,
    /// Rollback plan with verifier and inverse.
    pub rollback: RollbackPlan,
    /// Dependent-invalidation plan with verifier.
    pub invalidation: InvalidationPlan,
    /// Primary verifier bound to the candidate.
    pub verifier: String,
    /// Deterministic digest binding the proposal inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `StructureRepairCandidate`.
// ---------------------------------------------------------------------------

/// Typed fail-closed structure-repair error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StructureRepairError {
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
    /// A member or dependency denominator is malformed or incomplete.
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

impl core::fmt::Display for StructureRepairError {
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

impl core::error::Error for StructureRepairError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(value: &str, field: &str, max: usize) -> Result<(), StructureRepairError> {
    if value.trim().is_empty() {
        return Err(StructureRepairError::Shape {
            field: field.to_owned(),
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(StructureRepairError::Shape {
            field: field.to_owned(),
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(StructureRepairError::Shape {
            field: field.to_owned(),
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &str) -> Result<(), StructureRepairError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(StructureRepairError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(StructureRepairError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one identity field for blank, control, and byte ceiling.
fn check_identity(value: &str, field: &str) -> Result<(), StructureRepairError> {
    if value.trim().is_empty() {
        return Err(StructureRepairError::Shape {
            field: field.to_owned(),
            detail: "blank identity is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(StructureRepairError::Shape {
            field: field.to_owned(),
            detail: "identity carries control characters".to_owned(),
        });
    }
    if value.len() > MAX_ID_BYTES {
        return Err(StructureRepairError::Bounds {
            phase: field.to_owned(),
            detail: "identity exceeds the identity ceiling".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &str) -> Result<(), StructureRepairError> {
    if !is_hex64_lower(value) {
        return Err(StructureRepairError::Digest {
            detail: redact(&format!("{field} must be 64 lowercase hex sha256")),
        });
    }
    Ok(())
}

/// Checks one sorted-unique ref list for handle shape and ordering.
fn check_sorted_refs(values: &[String], field: &str) -> Result<(), StructureRepairError> {
    for value in values {
        check_handle(value, field)?;
    }
    if !is_sorted_unique(values) {
        return Err(StructureRepairError::Order {
            phase: field.to_owned(),
            detail: "refs must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

/// Checks one sorted-unique digest list for digest shape and ordering.
fn check_sorted_digests(values: &[String], field: &str) -> Result<(), StructureRepairError> {
    for value in values {
        check_digest(value, field)?;
    }
    if !is_sorted_unique(values) {
        return Err(StructureRepairError::Order {
            phase: field.to_owned(),
            detail: "digests must be sorted and unique".to_owned(),
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

/// Rejects a list length above its independent ceiling.
fn bound_list_length(phase: &str, got: usize, max: usize) -> Result<(), StructureRepairError> {
    if got > max {
        return Err(StructureRepairError::Bounds {
            phase: phase.to_owned(),
            detail: "list exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Preflight bounds (shape only; semantic shortfalls stay outcomes).
// ---------------------------------------------------------------------------

/// Preflights the policy ceilings against the global independent bounds.
fn preflight_policy_bounds(policy: &StructureRepairPolicy) -> Result<(), StructureRepairError> {
    bound_list_length("policy.max-members", policy.max_members, MAX_MEMBERS)?;
    bound_list_length(
        "policy.max-dependents",
        policy.max_dependents,
        MAX_DEPENDENTS,
    )?;
    bound_list_length(
        "policy.max-partitions",
        policy.max_partitions,
        MAX_PARTITIONS,
    )?;
    bound_list_length(
        "policy.max-evidence",
        policy.max_evidence_items,
        MAX_EVIDENCE_ITEMS,
    )?;
    if policy.max_members == 0 || policy.max_dependents == 0 || policy.max_partitions == 0 {
        return Err(StructureRepairError::Policy {
            detail: "policy ceilings must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.max_evidence_items == 0 {
        return Err(StructureRepairError::Policy {
            detail: "policy evidence ceiling must be explicit, not defaulted".to_owned(),
        });
    }
    Ok(())
}

/// Preflights structural and dependency list lengths against policy.
fn preflight_list_bounds(
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
) -> Result<(), StructureRepairError> {
    bound_list_length(
        "structural.members",
        structural.members.len(),
        policy.max_members,
    )?;
    bound_list_length(
        "dependency.dependents",
        dependency.dependents.len(),
        policy.max_dependents,
    )?;
    bound_list_length(
        "structural.partitions",
        structural.partitions.len(),
        policy.max_partitions,
    )?;
    let ceiling = policy.max_evidence_items.min(MAX_EVIDENCE_ITEMS);
    bound_list_length(
        "structural.equivalence-refs",
        structural.equivalence_refs.len(),
        ceiling,
    )?;
    bound_list_length(
        "structural.counterexamples",
        structural.counterexample_refs.len(),
        ceiling,
    )?;
    bound_list_length(
        "structural.minority-refs",
        structural.minority_refs.len(),
        ceiling,
    )?;
    bound_list_length(
        "structural.residual-refs",
        structural.residual_refs.len(),
        ceiling,
    )?;
    bound_list_length(
        "structural.lineage-refs",
        structural.shared_lineage_refs.len(),
        MAX_CLOSURE_REFS,
    )?;
    bound_list_length(
        "structural.raw-history-refs",
        structural.raw_history_refs.len(),
        MAX_CLOSURE_REFS,
    )?;
    bound_list_length(
        "structural.ancestry-refs",
        structural.ancestry_refs.len(),
        MAX_CLOSURE_REFS,
    )?;
    bound_list_length(
        "structural.residue",
        structural.unresolved_residue.len(),
        policy.max_members,
    )?;
    bound_list_length(
        "structural.distinctions",
        structural.unresolved_distinctions.len(),
        MAX_DISTINCTIONS,
    )?;
    for partition in &structural.partitions {
        bound_list_length(
            "partition.members",
            partition.member_ids.len(),
            MAX_PARTITION_MEMBERS,
        )?;
        bound_list_length(
            "partition.counterexamples",
            partition.counterexamples.len(),
            ceiling,
        )?;
    }
    if let Some(prior) = &structural.prior_transition {
        bound_list_length("prior.premerge-ids", prior.premerge_ids.len(), MAX_MEMBERS)?;
    }
    Ok(())
}

/// Preflights aggregate text bytes across the whole proposal surface.
fn preflight_total_bytes(
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
) -> Result<(), StructureRepairError> {
    let mut total = 0usize;
    total = total.saturating_add(count_text_bytes(&[
        &structural.subject_id,
        &structural.subject_revision,
        &structural.record_type,
        &structural.owner,
        &structural.schema,
        &structural.equivalence_note,
        &structural.support_ceiling,
        &structural.authority_ceiling,
        &structural.privacy_ceiling,
        &structural.requested_target_basename,
        &structural.verifier,
        &dependency.closure_note,
        &policy.policy_id,
        &policy.allocator_owner,
        &policy.repair_note,
    ]));
    for member in &structural.members {
        total = total.saturating_add(count_text_bytes(&[
            &member.member_id,
            &member.revision,
            &member.source_ref,
            &member.raw_episode_ref,
            &member.record_type,
            &member.owner,
            &member.schema,
        ]));
    }
    for partition in &structural.partitions {
        total = total.saturating_add(count_text_bytes(&[
            &partition.partition_basename,
            &partition.discriminator,
        ]));
    }
    for dependent in &dependency.dependents {
        total = total.saturating_add(count_text_bytes(&[
            &dependent.dependent_id,
            &dependent.dependent_kind,
            &dependent.endpoint,
            &dependent.relation,
            &dependent.owner,
            &dependent.revision,
        ]));
    }
    for value in structural.equivalence_refs.iter().chain(
        structural
            .counterexample_refs
            .iter()
            .chain(structural.minority_refs.iter())
            .chain(structural.residual_refs.iter())
            .chain(structural.shared_lineage_refs.iter())
            .chain(structural.raw_history_refs.iter())
            .chain(structural.ancestry_refs.iter())
            .chain(structural.unresolved_residue.iter())
            .chain(structural.unresolved_distinctions.iter()),
    ) {
        total = total.saturating_add(value.len());
    }
    if total > MAX_TOTAL_BYTES {
        return Err(StructureRepairError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input exceeds the total byte ceiling".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shape validation (malformed input only).
// ---------------------------------------------------------------------------

/// Validates the frozen bundle digest shapes.
fn validate_frozen_shapes(frozen: &FrozenBundle) -> Result<(), StructureRepairError> {
    check_digest(&frozen.bundle_digest, "frozen-bundle")?;
    check_digest(&frozen.manifest_digest, "frozen-manifest")?;
    Ok(())
}

/// Validates one member record shape without judging semantics.
fn validate_one_member_shape(member: &MemberRecord) -> Result<(), StructureRepairError> {
    check_identity(&member.member_id, "member.id")?;
    check_bounded_text(&member.revision, "member.revision", MAX_ID_BYTES)?;
    check_handle(&member.source_ref, "member.source")?;
    check_handle(&member.raw_episode_ref, "member.raw-episode")?;
    check_digest(&member.evidence_digest, "member.evidence")?;
    check_bounded_text(&member.record_type, "member.type", MAX_ID_BYTES)?;
    check_bounded_text(&member.owner, "member.owner", MAX_ID_BYTES)?;
    check_bounded_text(&member.schema, "member.schema", MAX_ID_BYTES)?;
    Ok(())
}

/// Validates one partition request shape without judging semantics.
fn validate_one_partition_shape(partition: &PartitionRequest) -> Result<(), StructureRepairError> {
    check_handle(&partition.partition_basename, "partition.basename")?;
    if partition.member_ids.is_empty() {
        return Err(StructureRepairError::Shape {
            field: "partition.members".to_owned(),
            detail: "every partition must be nonempty".to_owned(),
        });
    }
    check_sorted_refs(&partition.member_ids, "partition.members")?;
    check_bounded_text(
        &partition.discriminator,
        "partition.discriminator",
        MAX_NOTE_BYTES,
    )?;
    check_sorted_refs(&partition.counterexamples, "partition.counterexamples")?;
    Ok(())
}

/// Validates the prior-transition shape without judging ancestry.
fn validate_prior_shapes(prior: &PriorTransition) -> Result<(), StructureRepairError> {
    check_identity(&prior.prior_operation_id, "prior.operation")?;
    check_identity(&prior.prior_idempotency_key, "prior.idempotency")?;
    check_digest(&prior.prior_receipt_digest, "prior.receipt")?;
    if prior.premerge_ids.is_empty() {
        return Err(StructureRepairError::Shape {
            field: "prior.premerge".to_owned(),
            detail: "pre-merge members must be nonempty".to_owned(),
        });
    }
    check_sorted_refs(&prior.premerge_ids, "prior.premerge-ids")?;
    if prior.premerge_revisions.len() != prior.premerge_ids.len() {
        return Err(StructureRepairError::Shape {
            field: "prior.premerge-revisions".to_owned(),
            detail: "pre-merge revisions must parallel pre-merge members".to_owned(),
        });
    }
    for revision in &prior.premerge_revisions {
        check_bounded_text(revision, "prior.premerge-revision", MAX_ID_BYTES)?;
    }
    check_identity(&prior.merged_id, "prior.merged")?;
    check_bounded_text(&prior.merged_revision, "prior.merged-revision", MAX_ID_BYTES)?;
    check_fence(&prior.fence).map_err(|err| StructureRepairError::Shape {
        field: "prior.fence".to_owned(),
        detail: redact(&err.to_string()),
    })?;
    check_bounded_text(&prior.authority, "prior.authority", MAX_ID_BYTES)?;
    check_bounded_text(
        &prior.reconciliation_note,
        "prior.reconciliation",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates structural text shapes, orderings, and member identity order.
fn validate_structural_shapes(structural: &StructuralProjection) -> Result<(), StructureRepairError> {
    check_identity(&structural.subject_id, "structural.subject")?;
    check_bounded_text(
        &structural.subject_revision,
        "structural.revision",
        MAX_ID_BYTES,
    )?;
    check_bounded_text(&structural.record_type, "structural.type", MAX_ID_BYTES)?;
    check_bounded_text(&structural.owner, "structural.owner", MAX_ID_BYTES)?;
    check_bounded_text(&structural.schema, "structural.schema", MAX_ID_BYTES)?;
    if structural.members.is_empty() {
        return Err(StructureRepairError::Shape {
            field: "structural.members".to_owned(),
            detail: "at least one source member is required".to_owned(),
        });
    }
    bound_list_length("structural.members", structural.members.len(), MAX_MEMBERS)?;
    let mut member_ids: Vec<String> = Vec::with_capacity(structural.members.len());
    for member in &structural.members {
        validate_one_member_shape(member)?;
        member_ids.push(member.member_id.clone());
    }
    if !is_sorted_unique(&member_ids) {
        return Err(StructureRepairError::Order {
            phase: "structural.members".to_owned(),
            detail: "member identities must be sorted and unique".to_owned(),
        });
    }
    check_bounded_text(
        &structural.equivalence_note,
        "structural.equivalence",
        MAX_NOTE_BYTES,
    )?;
    check_sorted_refs(&structural.equivalence_refs, "structural.equivalence-refs")?;
    for distinction in &structural.unresolved_distinctions {
        check_bounded_text(distinction, "structural.distinction", MAX_NOTE_BYTES)?;
    }
    check_sorted_refs(
        &structural.counterexample_refs,
        "structural.counterexamples",
    )?;
    check_sorted_refs(&structural.minority_refs, "structural.minority")?;
    check_sorted_refs(&structural.residual_refs, "structural.residual")?;
    check_sorted_refs(&structural.shared_lineage_refs, "structural.lineage")?;
    check_bounded_text(
        &structural.support_ceiling,
        "structural.support-ceiling",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &structural.authority_ceiling,
        "structural.authority-ceiling",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &structural.privacy_ceiling,
        "structural.privacy-ceiling",
        MAX_NOTE_BYTES,
    )?;
    check_handle(
        &structural.requested_target_basename,
        "structural.target-basename",
    )?;
    for partition in &structural.partitions {
        validate_one_partition_shape(partition)?;
    }
    let mut basenames: Vec<String> = Vec::with_capacity(structural.partitions.len());
    for partition in &structural.partitions {
        basenames.push(partition.partition_basename.clone());
    }
    if !is_sorted_unique(&basenames) {
        return Err(StructureRepairError::Order {
            phase: "structural.partitions".to_owned(),
            detail: "partition basenames must be sorted and unique".to_owned(),
        });
    }
    check_sorted_refs(&structural.unresolved_residue, "structural.residue")?;
    if let Some(prior) = &structural.prior_transition {
        validate_prior_shapes(prior)?;
    }
    check_sorted_refs(&structural.raw_history_refs, "structural.raw-history")?;
    check_sorted_refs(&structural.ancestry_refs, "structural.ancestry")?;
    check_sorted_refs(&structural.known_subject_ids, "structural.known-subjects")?;
    check_sorted_digests(
        &structural.known_candidate_digests,
        "structural.known-digests",
    )?;
    if let Some(duplicate) = &structural.duplicate_of {
        check_identity(duplicate, "structural.duplicate-of")?;
    }
    check_bounded_text(&structural.verifier, "structural.verifier", MAX_ID_BYTES)?;
    Ok(())
}

/// Validates dependency shapes and deterministic dependent ordering.
fn validate_dependency_shapes(dependency: &DependencyProjection) -> Result<(), StructureRepairError> {
    bound_list_length(
        "dependency.dependents",
        dependency.dependents.len(),
        MAX_DEPENDENTS,
    )?;
    let mut ids: Vec<String> = Vec::with_capacity(dependency.dependents.len());
    for dependent in &dependency.dependents {
        check_identity(&dependent.dependent_id, "dependent.id")?;
        check_bounded_text(&dependent.dependent_kind, "dependent.kind", MAX_ID_BYTES)?;
        check_handle(&dependent.endpoint, "dependent.endpoint")?;
        check_bounded_text(&dependent.relation, "dependent.relation", MAX_ID_BYTES)?;
        check_bounded_text(&dependent.owner, "dependent.owner", MAX_ID_BYTES)?;
        check_bounded_text(&dependent.revision, "dependent.revision", MAX_ID_BYTES)?;
        ids.push(dependent.dependent_id.clone());
    }
    if !is_sorted_unique(&ids) {
        return Err(StructureRepairError::Order {
            phase: "dependency.dependents".to_owned(),
            detail: "dependent identities must be sorted and unique".to_owned(),
        });
    }
    check_bounded_text(
        &dependency.closure_note,
        "dependency.closure-note",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates policy intrinsic shapes and ceilings.
fn validate_policy_shapes(policy: &StructureRepairPolicy) -> Result<(), StructureRepairError> {
    check_handle(&policy.policy_id, "policy.id")?;
    if policy.policy_revision == 0 {
        return Err(StructureRepairError::Policy {
            detail: "policy_revision must be explicit, not defaulted".to_owned(),
        });
    }
    check_bounded_text(
        &policy.allocator_owner,
        "policy.allocator",
        MAX_ID_BYTES,
    )?;
    check_bounded_text(&policy.repair_note, "policy.repair-note", MAX_NOTE_BYTES)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Intrinsic checks (A-05 receipt intrinsically, never re-executed).
// ---------------------------------------------------------------------------

/// Maps a contract violation into a redacted receipt error.
fn receipt_err(detail: &str) -> StructureRepairError {
    StructureRepairError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the A-05 receipt intrinsically plus item and draft validity.
fn intrinsic_receipt_checks(
    item: &ValidatedCurationItem,
    grounded: &GroundedDreamDraft,
) -> Result<(), StructureRepairError> {
    item.receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    item.validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    grounded
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if item.receipt.terminal_disposition != "accepted"
        && item.receipt.terminal_disposition != "partial"
    {
        return Err(StructureRepairError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    Ok(())
}

/// Checks bundle, manifest, draft, task, scope, and fence bindings.
fn intrinsic_binding_checks(
    item: &ValidatedCurationItem,
    grounded: &GroundedDreamDraft,
    frozen: &FrozenBundle,
) -> Result<(), StructureRepairError> {
    if item.receipt.bundle_digest != frozen.bundle_digest {
        return Err(StructureRepairError::Binding {
            field: "bundle_digest".to_owned(),
            detail: "frozen bundle digest drifts from the receipt binding".to_owned(),
        });
    }
    if item.receipt.manifest_digest != frozen.manifest_digest {
        return Err(StructureRepairError::Binding {
            field: "manifest_digest".to_owned(),
            detail: "frozen manifest digest drifts from the receipt binding".to_owned(),
        });
    }
    if item.receipt.draft_digest != grounded.draft_digest {
        return Err(StructureRepairError::Binding {
            field: "draft_digest".to_owned(),
            detail: "grounded draft digest drifts from the receipt binding".to_owned(),
        });
    }
    if grounded.job_id != item.receipt.job_id {
        return Err(StructureRepairError::Binding {
            field: "job_id".to_owned(),
            detail: "grounded job drifts from the receipt binding".to_owned(),
        });
    }
    if item.task_id != item.receipt.task_id || item.scope_id != item.receipt.scope_id {
        return Err(StructureRepairError::Binding {
            field: "task_scope".to_owned(),
            detail: "item task or scope drifts from the receipt binding".to_owned(),
        });
    }
    if item.state_fence != item.receipt.state_fence {
        return Err(StructureRepairError::Binding {
            field: "state_fence".to_owned(),
            detail: "item fence drifts from the receipt binding".to_owned(),
        });
    }
    Ok(())
}

/// Checks the denominator shape and accepts only Merge or Split payloads.
///
/// A-30 nonidentity repairs carry [`CurationKind::Repair`] and own no
/// identity surgery; they fail here with a distinct binding naming the A-30
/// boundary instead of routing into merge, split, or reversal logic.
fn intrinsic_denominator_checks(item: &ValidatedCurationItem) -> Result<(), StructureRepairError> {
    item.denominator
        .validate()
        .map_err(|err| StructureRepairError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    if item.kind_spelling == CurationKind::Repair.as_str() {
        return Err(StructureRepairError::Binding {
            field: "kind_spelling".to_owned(),
            detail: "nonidentity A-30 repair without identity surgery is not supported here"
                .to_owned(),
        });
    }
    if item.kind_spelling != CurationKind::Merge.as_str()
        && item.kind_spelling != CurationKind::Split.as_str()
    {
        return Err(StructureRepairError::Binding {
            field: "kind_spelling".to_owned(),
            detail: "curation item is not a merge or split kind".to_owned(),
        });
    }
    if item.family_spelling != "structure_repair" {
        return Err(StructureRepairError::Binding {
            field: "family_spelling".to_owned(),
            detail: "curation item is not a structure_repair family".to_owned(),
        });
    }
    let is_supported = matches!(
        item.payload,
        CurationPayload::Merge(_) | CurationPayload::Split(_)
    );
    if !is_supported {
        return Err(StructureRepairError::Binding {
            field: "payload".to_owned(),
            detail: "curation payload is not a merge or split payload".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Subtype selection and denominator binding (exactly one repair subtype).
// ---------------------------------------------------------------------------

/// Selects exactly one repair subtype from the typed payload and prior.
///
/// A present prior transition selects reversal; otherwise the Merge payload
/// selects merge and the Split payload selects split. Any other combination
/// fails closed without inventing a third global kind.
fn select_subtype(
    item: &ValidatedCurationItem,
    structural: &StructuralProjection,
) -> Result<RepairSubtype, StructureRepairError> {
    if structural.prior_transition.is_some() {
        return Ok(RepairSubtype::Reversal);
    }
    match &item.payload {
        CurationPayload::Merge(_) => Ok(RepairSubtype::Merge),
        CurationPayload::Split(_) => Ok(RepairSubtype::Split),
        _ => Err(StructureRepairError::Binding {
            field: "payload".to_owned(),
            detail: "curation payload selects no supported repair subtype".to_owned(),
        }),
    }
}

/// Binds the subject, payload identities, and denominator into one cover.
///
/// Merge requires members plus `merged` to equal the denominator; split and
/// reversal require members plus `whole` to equal the denominator. Payload
/// identities must be pairwise distinct so no key collision silently merges
/// a record with itself or its own target.
#[allow(clippy::too_many_lines)]
fn check_subject_denominator_binding(
    item: &ValidatedCurationItem,
    structural: &StructuralProjection,
    subtype: RepairSubtype,
) -> Result<(), StructureRepairError> {
    let mut member_ids: Vec<String> = Vec::with_capacity(structural.members.len());
    for member in &structural.members {
        member_ids.push(member.member_id.clone());
    }
    member_ids.sort();
    let mut denominator = item.denominator.members.clone();
    denominator.sort();
    match (&item.payload, subtype) {
        (CurationPayload::Merge(payload), RepairSubtype::Merge) => {
            if structural.subject_id != payload.merged {
                return Err(StructureRepairError::Binding {
                    field: "subject_id".to_owned(),
                    detail: "merge subject must equal the payload merged identity".to_owned(),
                });
            }
            if structural.requested_target_basename != structural.subject_id {
                return Err(StructureRepairError::Binding {
                    field: "target_basename".to_owned(),
                    detail: "merge target basename must equal the subject identity".to_owned(),
                });
            }
            if payload.left == payload.right
                || payload.left == payload.merged
                || payload.right == payload.merged
            {
                return Err(StructureRepairError::Binding {
                    field: "payload.identities".to_owned(),
                    detail: "merge identities collide; distinct keys are required".to_owned(),
                });
            }
            if !structural.partitions.is_empty() {
                return Err(StructureRepairError::Shape {
                    field: "structural.partitions".to_owned(),
                    detail: "merge carries no partitions".to_owned(),
                });
            }
            if member_ids.iter().any(|id| id == &payload.merged) {
                return Err(StructureRepairError::Binding {
                    field: "payload.identities".to_owned(),
                    detail: "merge target collides with a source member".to_owned(),
                });
            }
            let mut expected = member_ids.clone();
            expected.push(payload.merged.clone());
            expected.sort();
            if expected != denominator {
                return Err(StructureRepairError::Denominator {
                    detail: "merge members plus merged must exactly cover the denominator"
                        .to_owned(),
                });
            }
        }
        (CurationPayload::Split(payload), RepairSubtype::Split | RepairSubtype::Reversal) => {
            if structural.subject_id != payload.whole {
                return Err(StructureRepairError::Binding {
                    field: "subject_id".to_owned(),
                    detail: "split subject must equal the payload whole identity".to_owned(),
                });
            }
            if structural.requested_target_basename != structural.subject_id {
                return Err(StructureRepairError::Binding {
                    field: "target_basename".to_owned(),
                    detail: "split target basename must equal the subject identity".to_owned(),
                });
            }
            if payload.whole == payload.first
                || payload.whole == payload.second
                || payload.first == payload.second
            {
                return Err(StructureRepairError::Binding {
                    field: "payload.identities".to_owned(),
                    detail: "split identities collide; distinct keys are required".to_owned(),
                });
            }
            if member_ids.iter().any(|id| id == &payload.whole) {
                return Err(StructureRepairError::Binding {
                    field: "payload.identities".to_owned(),
                    detail: "split whole collides with a partitioned member".to_owned(),
                });
            }
            let mut expected = member_ids.clone();
            expected.push(payload.whole.clone());
            expected.sort();
            if expected != denominator {
                return Err(StructureRepairError::Denominator {
                    detail: "split members plus whole must exactly cover the denominator"
                        .to_owned(),
                });
            }
            if structural.partitions.is_empty() {
                return Err(StructureRepairError::Shape {
                    field: "structural.partitions".to_owned(),
                    detail: "split requires at least the canonical minimum partitions".to_owned(),
                });
            }
            let basenames: Vec<String> = structural
                .partitions
                .iter()
                .map(|partition| partition.partition_basename.clone())
                .collect();
            if !basenames.iter().any(|name| name == &payload.first)
                || !basenames.iter().any(|name| name == &payload.second)
            {
                return Err(StructureRepairError::Binding {
                    field: "partition.basenames".to_owned(),
                    detail: "split partitions must cover the payload child identities".to_owned(),
                });
            }
            check_partition_cover(structural, &member_ids)?;
        }
        (CurationPayload::Merge(_) | CurationPayload::Split(_), _) => {
            return Err(StructureRepairError::Binding {
                field: "payload".to_owned(),
                detail: "payload kind and selected subtype disagree".to_owned(),
            });
        }
        _ => {
            return Err(StructureRepairError::Binding {
                field: "payload".to_owned(),
                detail: "curation payload selects no supported repair subtype".to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks pairwise disjointness and exact cover of members by partitions.
///
/// Every member appears exactly once across partitions plus residue; a lost
/// member fails as a denominator gap and a duplicated member fails as an
/// ordering violation. The subject whole is the partitioned parent and is
/// never assigned into a child.
fn check_partition_cover(
    structural: &StructuralProjection,
    member_ids: &[String],
) -> Result<(), StructureRepairError> {
    let mut covered: Vec<String> = Vec::with_capacity(member_ids.len());
    for partition in &structural.partitions {
        for member in &partition.member_ids {
            if covered.iter().any(|seen| seen == member) {
                return Err(StructureRepairError::Order {
                    phase: "structural.partitions".to_owned(),
                    detail: "a member is assigned to more than one partition".to_owned(),
                });
            }
            if structural.unresolved_residue.iter().any(|held| held == member) {
                return Err(StructureRepairError::Order {
                    phase: "structural.residue".to_owned(),
                    detail: "a member is both partitioned and held as residue".to_owned(),
                });
            }
            if !member_ids.iter().any(|known| known == member) {
                return Err(StructureRepairError::Denominator {
                    detail: "a partition assigns a member outside the denominator".to_owned(),
                });
            }
            covered.push(member.clone());
        }
        for counterexample in &partition.counterexamples {
            let in_global = structural
                .counterexample_refs
                .iter()
                .any(|known| known == counterexample)
                || structural
                    .residual_refs
                    .iter()
                    .any(|known| known == counterexample);
            if !in_global {
                return Err(StructureRepairError::Binding {
                    field: "partition.counterexamples".to_owned(),
                    detail: "child counterexamples must scope to supplied distinctions".to_owned(),
                });
            }
        }
    }
    let mut accounted = covered.clone();
    for held in &structural.unresolved_residue {
        accounted.push(held.clone());
    }
    accounted.sort();
    let mut want = member_ids.to_vec();
    want.sort();
    if accounted != want {
        return Err(StructureRepairError::Denominator {
            detail: "partitions plus residue must account for every member exactly once"
                .to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deadline and cancellation (no ambient clock; explicit inputs only).
// ---------------------------------------------------------------------------

/// Checks deadline and cancellation before any emission work.
fn check_deadline_and_cancel(
    policy: &StructureRepairPolicy,
) -> Result<Option<RepairOutcome>, StructureRepairError> {
    if policy.cancelled {
        return Ok(Some(RepairOutcome::Rejected));
    }
    if let (Some(deadline), Some(observed)) = (policy.deadline_ms, policy.observation_time_ms)
        && observed >= deadline
    {
        return Err(StructureRepairError::Policy {
            detail: "observation is at or beyond the frozen deadline".to_owned(),
        });
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Semantic judgement (shortfalls stay inert outcomes, never blind retries).
// ---------------------------------------------------------------------------

/// Seven-dimension boolean judgement with the terminal outcome and note.
///
/// Seven independent booleans are the contract here: each maps to exactly
/// one A-03/I9.7 preservation dimension with no averaging, so a state
/// machine or merged enum would hide the per-dimension proof the reviewer
/// verifies.
#[allow(clippy::struct_excessive_bools)]
struct SemanticJudgement {
    outcome: RepairOutcome,
    equivalent: bool,
    basis_note: String,
    coverage_ok: bool,
    faithfulness_ok: bool,
    lineage_ok: bool,
    reversibility_ok: bool,
    ceiling_ok: bool,
    closure_ok: bool,
    provenance_ok: bool,
    note: String,
}

/// Returns true when any dependent carries an unknown mutation.
fn has_unknown_dependent(dependency: &DependencyProjection) -> bool {
    for dependent in &dependency.dependents {
        if lowered(&dependent.dependent_kind) == "unknown" {
            return true;
        }
    }
    false
}

/// Returns true when any ceiling note claims a raise.
fn ceilings_raise(structural: &StructuralProjection) -> bool {
    for ceiling in [
        &structural.support_ceiling,
        &structural.authority_ceiling,
        &structural.privacy_ceiling,
    ] {
        if mentions_any(&lowered(ceiling), CEILING_RAISE_MARKERS) {
            return true;
        }
    }
    false
}

/// Returns true when every member matches the subject type, owner, schema.
fn members_compatible(structural: &StructuralProjection) -> bool {
    for member in &structural.members {
        if member.record_type != structural.record_type
            || member.owner != structural.owner
            || member.schema != structural.schema
        {
            return false;
        }
    }
    true
}

/// Judges merge semantics: equivalence, distinctions, ceilings, closure.
fn judge_merge(
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
) -> SemanticJudgement {
    let similarity_overreach = mentions_any(&lowered(&structural.equivalence_note), SIMILARITY_MARKERS);
    let equivalent = !structural.equivalence_refs.is_empty() && !similarity_overreach;
    let faithfulness_ok = equivalent && structural.unresolved_distinctions.is_empty();
    let ceiling_ok = !ceilings_raise(structural);
    let compatible = members_compatible(structural);
    let lineage_ok = !structural.raw_history_refs.is_empty();
    let provenance_ok = !structural.counterexample_refs.is_empty()
        && !structural.minority_refs.is_empty()
        && !structural.residual_refs.is_empty();
    let closure_ok =
        dependency.closure_complete && !has_unknown_dependent(dependency);
    let basis_note = if structural.equivalence_refs.is_empty() {
        "no equivalence refs: shared lineage stays lineage-only".to_owned()
    } else if similarity_overreach {
        "similarity overreach refused: wording and vectors never prove identity".to_owned()
    } else {
        "scoped semantic equivalence grounded in supplied refs".to_owned()
    };
    let (outcome, note) = if has_unknown_dependent(dependency) {
        (
            RepairOutcome::Blocked,
            "unknown dependent mutation blocks ready qualification".to_owned(),
        )
    } else if !faithfulness_ok {
        (
            RepairOutcome::Insufficient,
            "merge refused: equivalence unproven or a material distinction stands".to_owned(),
        )
    } else if !ceiling_ok {
        (
            RepairOutcome::Insufficient,
            "merge refused: a ceiling raise is never admitted".to_owned(),
        )
    } else if !compatible {
        (
            RepairOutcome::Insufficient,
            "merge refused: incompatible types, owners, or schemas".to_owned(),
        )
    } else if !lineage_ok || !provenance_ok {
        (
            RepairOutcome::Partial,
            "merge partial: raw history or retained distinctions are incomplete".to_owned(),
        )
    } else if !closure_ok {
        if policy.allow_partial {
            (
                RepairOutcome::Partial,
                "merge partial: dependency closure is incomplete".to_owned(),
            )
        } else {
            (
                RepairOutcome::Abstention,
                "merge abstains: partial closure without partial permission".to_owned(),
            )
        }
    } else {
        (RepairOutcome::Complete, REPAIR_PROOF_NOTE.to_owned())
    };
    SemanticJudgement {
        outcome,
        equivalent,
        basis_note,
        coverage_ok: true,
        faithfulness_ok,
        lineage_ok,
        reversibility_ok: true,
        ceiling_ok,
        closure_ok,
        provenance_ok,
        note,
    }
}

/// Judges split semantics: disjoint cover, discriminators, residue, closure.
fn judge_split(
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
) -> SemanticJudgement {
    let mut children_evidenced = true;
    for partition in &structural.partitions {
        if partition.counterexamples.is_empty() {
            children_evidenced = false;
        }
    }
    let faithfulness_ok =
        children_evidenced && structural.partitions.len() >= 2;
    let ceiling_ok = !ceilings_raise(structural);
    let compatible = members_compatible(structural);
    let lineage_ok = !structural.raw_history_refs.is_empty();
    let provenance_ok = !structural.counterexample_refs.is_empty()
        && !structural.minority_refs.is_empty()
        && !structural.residual_refs.is_empty();
    let residue_open = !structural.unresolved_residue.is_empty()
        || !structural.unresolved_distinctions.is_empty();
    let closure_ok =
        dependency.closure_complete && !has_unknown_dependent(dependency);
    let basis_note = "split boundaries grounded in per-child discriminators".to_owned();
    let (outcome, note) = if has_unknown_dependent(dependency) {
        (
            RepairOutcome::Blocked,
            "unknown dependent mutation blocks ready qualification".to_owned(),
        )
    } else if !faithfulness_ok {
        (
            RepairOutcome::Insufficient,
            "split refused: a child lacks its discriminator counterexamples".to_owned(),
        )
    } else if !ceiling_ok {
        (
            RepairOutcome::Insufficient,
            "split refused: a ceiling raise is never admitted".to_owned(),
        )
    } else if !compatible {
        (
            RepairOutcome::Insufficient,
            "split refused: incompatible types, owners, or schemas".to_owned(),
        )
    } else if !lineage_ok || !provenance_ok || residue_open || !closure_ok {
        if policy.allow_partial {
            (
                RepairOutcome::Partial,
                "split partial: residue, distinctions, history, or closure stays open".to_owned(),
            )
        } else {
            (
                RepairOutcome::Abstention,
                "split abstains: open residue or closure without partial permission".to_owned(),
            )
        }
    } else {
        (RepairOutcome::Complete, REPAIR_PROOF_NOTE.to_owned())
    };
    SemanticJudgement {
        outcome,
        equivalent: true,
        basis_note,
        coverage_ok: true,
        faithfulness_ok,
        lineage_ok,
        reversibility_ok: true,
        ceiling_ok,
        closure_ok,
        provenance_ok,
        note,
    }
}

/// Judges reversal semantics: prior ancestry, later writes, unknown effects.
#[allow(clippy::too_many_lines)]
fn judge_reversal(
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
) -> SemanticJudgement {
    let Some(prior) = &structural.prior_transition else {
        return SemanticJudgement {
            outcome: RepairOutcome::Insufficient,
            equivalent: false,
            basis_note: "reversal needs its accepted prior transition".to_owned(),
            coverage_ok: false,
            faithfulness_ok: false,
            lineage_ok: false,
            reversibility_ok: false,
            ceiling_ok: true,
            closure_ok: false,
            provenance_ok: false,
            note: "reversal refused: current disagreement alone never proves a prior merge"
                .to_owned(),
        };
    };
    let ancestry_ok = structural
        .ancestry_refs
        .iter()
        .any(|anchor| anchor == &prior.merged_id);
    let revision_moved = structural.subject_revision != prior.merged_revision;
    let premerge_covers = {
        let mut premerge = prior.premerge_ids.clone();
        premerge.sort();
        let mut members: Vec<String> = structural
            .members
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        members.sort();
        premerge == members && prior.merged_id == structural.subject_id
    };
    let ceiling_ok = !ceilings_raise(structural);
    let compatible = members_compatible(structural);
    let lineage_ok =
        ancestry_ok && premerge_covers && !structural.raw_history_refs.is_empty();
    let provenance_ok = !structural.counterexample_refs.is_empty()
        && !structural.minority_refs.is_empty()
        && !structural.residual_refs.is_empty();
    let residue_open = !structural.unresolved_residue.is_empty();
    let closure_ok =
        dependency.closure_complete && !has_unknown_dependent(dependency);
    let reversibility_ok = !prior.has_unknown_effects;
    let basis_note = "reversal grounded in the exact prior merge receipt".to_owned();
    let (outcome, note) = if !revision_moved {
        (
            RepairOutcome::Stale,
            "reversal stale: subject revision never moved past the merge".to_owned(),
        )
    } else if prior.has_unknown_effects || has_unknown_dependent(dependency) {
        (
            RepairOutcome::Blocked,
            "rollback blocked: unknown effects forbid unsafe restore".to_owned(),
        )
    } else if !lineage_ok {
        (
            RepairOutcome::Blocked,
            "rollback blocked: ancestry, pre-merge cover, or raw history is missing".to_owned(),
        )
    } else if !ceiling_ok {
        (
            RepairOutcome::Insufficient,
            "reversal refused: historical ceilings are never restored as current".to_owned(),
        )
    } else if !compatible {
        (
            RepairOutcome::Insufficient,
            "reversal refused: incompatible types, owners, or schemas".to_owned(),
        )
    } else if prior.has_later_writes {
        (
            RepairOutcome::Partial,
            "forward repair: later writes moved past the merge; no exact inverse".to_owned(),
        )
    } else if !provenance_ok || residue_open || !closure_ok {
        if policy.allow_partial {
            (
                RepairOutcome::Partial,
                "reversal partial: distinctions, residue, or closure stays open".to_owned(),
            )
        } else {
            (
                RepairOutcome::Abstention,
                "reversal abstains: open residue or closure without partial permission".to_owned(),
            )
        }
    } else {
        (RepairOutcome::Complete, REPAIR_PROOF_NOTE.to_owned())
    };
    SemanticJudgement {
        outcome,
        equivalent: true,
        basis_note,
        coverage_ok: lineage_ok,
        faithfulness_ok: lineage_ok,
        lineage_ok,
        reversibility_ok,
        ceiling_ok,
        closure_ok,
        provenance_ok,
        note,
    }
}

// ---------------------------------------------------------------------------
// Preservation, dispositions, rollback, invalidation (no averaging).
// ---------------------------------------------------------------------------

/// Builds the seven independent preservation verdicts with no averaging.
///
/// Any single failed dimension blocks a complete qualification; six passing
/// dimensions never outweigh one failed dimension.
fn build_preservation(
    judgement: &SemanticJudgement,
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
) -> PreservationReport {
    let member_count = structural.members.len();
    let dependent_count = dependency.dependents.len();
    let verdicts = vec![
        DimensionVerdict {
            dimension: PreservationDimension::Coverage,
            passed: judgement.coverage_ok,
            known: true,
            note: format!("{member_count} members exactly cover the denominator"),
        },
        DimensionVerdict {
            dimension: PreservationDimension::Faithfulness,
            passed: judgement.faithfulness_ok,
            known: true,
            note: if judgement.faithfulness_ok {
                "candidate says only what its sources support".to_owned()
            } else {
                "faithfulness unproven under current evidence".to_owned()
            },
        },
        DimensionVerdict {
            dimension: PreservationDimension::Lineage,
            passed: judgement.lineage_ok,
            known: true,
            note: if judgement.lineage_ok {
                "raw history and ancestry retained and addressable".to_owned()
            } else {
                "lineage or raw history is incomplete".to_owned()
            },
        },
        DimensionVerdict {
            dimension: PreservationDimension::Reversibility,
            passed: judgement.reversibility_ok,
            known: true,
            note: if judgement.reversibility_ok {
                "rollback restores the before state via retained revisions".to_owned()
            } else {
                "unknown effects forbid rollback until reconciled".to_owned()
            },
        },
        DimensionVerdict {
            dimension: PreservationDimension::AuthorityCeiling,
            passed: judgement.ceiling_ok,
            known: true,
            note: if judgement.ceiling_ok {
                "support, authority, and privacy ceilings preserved verbatim".to_owned()
            } else {
                "a ceiling raise was refused".to_owned()
            },
        },
        DimensionVerdict {
            dimension: PreservationDimension::DependencyClosure,
            passed: judgement.closure_ok,
            known: true,
            note: if judgement.closure_ok {
                format!("{dependent_count} dependents closed with evidence")
            } else {
                "dependency closure is incomplete or unknown".to_owned()
            },
        },
        DimensionVerdict {
            dimension: PreservationDimension::ProvenanceRetention,
            passed: judgement.provenance_ok,
            known: true,
            note: if judgement.provenance_ok {
                "counterexamples, minority, and residual distinctions retained".to_owned()
            } else {
                "retained distinctions are incomplete".to_owned()
            },
        },
    ];
    debug_assert_eq!(verdicts.len(), PRESERVATION_DIMENSIONS.len());
    debug_assert_eq!(verdicts.len(), EXPECTED_PRESERVATION_DIMENSIONS);
    PreservationReport { verdicts }
}

/// Builds the typed allocation request for one basename.
fn allocation_for(
    basename: &str,
    policy: &StructureRepairPolicy,
    reason: &str,
) -> Result<AllocationRequest, StructureRepairError> {
    let requested_handle = format!("alloc:{basename}");
    if requested_handle.len() > MAX_ALLOC_HANDLE_BYTES {
        return Err(StructureRepairError::Bounds {
            phase: "allocation.handle".to_owned(),
            detail: "allocation handle exceeds its independent ceiling".to_owned(),
        });
    }
    check_bounded_text(reason, "allocation.reason", MAX_NOTE_BYTES)?;
    Ok(AllocationRequest {
        requested_handle,
        owner: policy.allocator_owner.clone(),
        reason: reason.to_owned(),
    })
}

/// Returns the child allocation handle for one partition basename.
fn child_handle(basename: &str) -> String {
    format!("alloc:{basename}")
}

/// Selects the single dependent disposition for one dependent kind.
///
/// Derived summaries, concepts, procedures, and views duplicate with scoped
/// semantics; relations, cues, indexes, and claims retarget; support,
/// accessibility, authority, influence, lifecycle, privacy, provenance, and
/// audit records stay unchanged with evidence; tasks, decisions, artifacts,
/// recovery, and fingerprint records invalidate, rebuild, and verify;
/// unknown mutation blocks; anything else quarantines for its owner.
fn disposition_for_kind(kind: &str) -> DependentDispositionKind {
    let lowered_kind = lowered(kind);
    let value = lowered_kind.as_str();
    if value == "unknown" {
        DependentDispositionKind::BlockedUnknown
    } else if value == "summary"
        || value == "view"
        || value == "concept"
        || value == "procedure"
    {
        DependentDispositionKind::ScopedSemanticDuplication
    } else if value == "relation" || value == "cue" || value == "index" || value == "claim" {
        DependentDispositionKind::Retarget
    } else if value == "support"
        || value == "accessibility"
        || value == "authority"
        || value == "influence"
        || value == "lifecycle"
        || value == "privacy"
        || value == "provenance"
        || value == "audit"
    {
        DependentDispositionKind::UnchangedWithEvidence
    } else if value == "task"
        || value == "decision"
        || value == "artifact"
        || value == "recovery"
        || value == "fingerprint"
    {
        DependentDispositionKind::InvalidateRebuildVerify
    } else {
        DependentDispositionKind::QuarantineReconcileByOwner
    }
}

/// Builds one disposition per member in member order.
///
/// Complete merges retarget sources to the allocation request; complete
/// splits retarget partitioned members to their child request and hold
/// residue; clean reversals restore pre-merge identities; every other
/// outcome retains every member with history so no failure loses a branch.
#[allow(clippy::too_many_lines)]
fn build_member_dispositions(
    subtype: RepairSubtype,
    outcome: RepairOutcome,
    structural: &StructuralProjection,
    target_handle: &str,
) -> Vec<MemberDisposition> {
    let mut out: Vec<MemberDisposition> = Vec::with_capacity(structural.members.len());
    for member in &structural.members {
        let (kind, target) = match (subtype, outcome) {
            (RepairSubtype::Merge, RepairOutcome::Complete) => (
                MemberDispositionKind::RetargetToAllocation,
                target_handle.to_owned(),
            ),
            (RepairSubtype::Split | RepairSubtype::Reversal, RepairOutcome::Complete) => {
                let mut holder: Option<String> = None;
                for partition in &structural.partitions {
                    if partition.member_ids.iter().any(|id| id == &member.member_id) {
                        holder = Some(child_handle(&partition.partition_basename));
                    }
                }
                match holder {
                    Some(handle) => {
                        let kind = if subtype == RepairSubtype::Reversal {
                            MemberDispositionKind::RestoredToPremerge
                        } else {
                            MemberDispositionKind::RetargetToAllocation
                        };
                        (kind, handle)
                    }
                    None => (
                        MemberDispositionKind::ResidueHeld,
                        member.member_id.clone(),
                    ),
                }
            }
            _ => {
                if structural
                    .unresolved_residue
                    .iter()
                    .any(|held| held == &member.member_id)
                {
                    (
                        MemberDispositionKind::ResidueHeld,
                        member.member_id.clone(),
                    )
                } else {
                    (
                        MemberDispositionKind::RetainedWithHistory,
                        member.member_id.clone(),
                    )
                }
            }
        };
        let reason = match kind {
            MemberDispositionKind::RetargetToAllocation => {
                format!("member {} proposed for {}", member.member_id, target)
            }
            MemberDispositionKind::RestoredToPremerge => {
                format!("member {} proposed for restore to {}", member.member_id, target)
            }
            MemberDispositionKind::ResidueHeld => {
                format!("member {} held as unresolved residue", member.member_id)
            }
            MemberDispositionKind::RetainedWithHistory => {
                format!("member {} retained with revision {}", member.member_id, member.revision)
            }
        };
        out.push(MemberDisposition {
            member_id: member.member_id.clone(),
            kind,
            target,
            reason,
            evidence_ref: member.source_ref.clone(),
            revision: member.revision.clone(),
            verifier: structural.verifier.clone(),
            inverse_note: format!(
                "restore {}@{} from retained history",
                member.member_id, member.revision
            ),
        });
    }
    out
}

/// Builds one disposition per dependent in dependent order.
fn build_dependent_dispositions(
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    target_handle: &str,
) -> Vec<DependentDisposition> {
    let mut out: Vec<DependentDisposition> = Vec::with_capacity(dependency.dependents.len());
    for dependent in &dependency.dependents {
        let kind = disposition_for_kind(&dependent.dependent_kind);
        let reason = match kind {
            DependentDispositionKind::UnchangedWithEvidence => {
                format!("dependent {} unchanged with evidence", dependent.dependent_id)
            }
            DependentDispositionKind::Retarget => {
                format!("dependent {} proposed for {}", dependent.dependent_id, target_handle)
            }
            DependentDispositionKind::ScopedSemanticDuplication => {
                format!("dependent {} scoped-duplicated under {}", dependent.dependent_id, target_handle)
            }
            DependentDispositionKind::InvalidateRebuildVerify => {
                format!("dependent {} invalidates for owner rebuild", dependent.dependent_id)
            }
            DependentDispositionKind::QuarantineReconcileByOwner => {
                format!("dependent {} quarantined for owner reconcile", dependent.dependent_id)
            }
            DependentDispositionKind::BlockedUnknown => {
                format!("dependent {} blocks on unknown mutation", dependent.dependent_id)
            }
        };
        out.push(DependentDisposition {
            dependent_id: dependent.dependent_id.clone(),
            kind,
            owner: dependent.owner.clone(),
            reason,
            evidence_ref: dependent.endpoint.clone(),
            verifier: structural.verifier.clone(),
            inverse_note: format!(
                "restore {}@{} from retained binding",
                dependent.dependent_id, dependent.revision
            ),
        });
    }
    out
}

/// Builds the rollback plan restoring the before state.
fn build_rollback(
    subtype: RepairSubtype,
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    target_handle: &str,
) -> Result<RollbackPlan, StructureRepairError> {
    let mut steps: Vec<String> = Vec::new();
    for member in &structural.members {
        steps.push(format!(
            "retain {}@{} with history for {}",
            member.member_id, member.revision, structural.subject_id
        ));
    }
    for dependent in &dependency.dependents {
        steps.push(format!(
            "verify {} via {} before any use",
            dependent.dependent_id, structural.verifier
        ));
    }
    let inverse_note = match subtype {
        RepairSubtype::Merge => format!(
            "inverse: split {target_handle} back into retained members"
        ),
        RepairSubtype::Split => format!(
            "inverse: rejoin child allocations into {}",
            structural.subject_id
        ),
        RepairSubtype::Reversal => match &structural.prior_transition {
            Some(prior) => format!(
                "forward guard: re-apply {} only through its owner",
                prior.prior_operation_id
            ),
            None => format!("no inverse without the prior transition for {}", structural.subject_id),
        },
    };
    steps.push(format!("inverse owned externally: {inverse_note}"));
    bound_list_length("rollback.steps", steps.len(), MAX_ROLLBACK_STEPS)?;
    Ok(RollbackPlan {
        steps,
        verifier: structural.verifier.clone(),
        inverse_note,
    })
}

/// Builds the dependent-invalidation plan with one entry per dependent.
fn build_invalidation(
    structural: &StructuralProjection,
    dispositions: &[DependentDisposition],
) -> Result<InvalidationPlan, StructureRepairError> {
    let mut entries: Vec<String> = Vec::with_capacity(dispositions.len());
    for disposition in dispositions {
        entries.push(format!(
            "{} {} verifier {} inverse {}",
            disposition.dependent_id,
            disposition.kind.as_str(),
            disposition.verifier,
            disposition.inverse_note
        ));
    }
    bound_list_length(
        "invalidation.entries",
        entries.len(),
        MAX_DEPENDENTS,
    )?;
    Ok(InvalidationPlan {
        entries,
        verifier: structural.verifier.clone(),
    })
}

// ---------------------------------------------------------------------------
// Deterministic digest (canonical bytes plus lowercase hex; no free text).
// ---------------------------------------------------------------------------

/// Computes the deterministic candidate digest over the proposal inputs.
///
/// The preimage covers subtype, outcome, subject, sorted member identities
/// with revisions, partition bindings, allocation handles, equivalence and
/// dependent bindings, prior operation, policy, and frozen digests. Free-text
/// notes never enter the hash: scalar, set, identity, or binding drift stays
/// digest-visible while prose rewording does not fork identity.
///
/// # Errors
///
/// Returns [`StructureRepairError::Digest`] when canonical serialization fails.
#[allow(clippy::too_many_arguments)]
pub fn compute_candidate_digest(
    subtype: RepairSubtype,
    outcome_spelling: &str,
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
    frozen: &FrozenBundle,
    target_handle: &str,
    child_handles: &[String],
) -> Result<String, StructureRepairError> {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("subtype:{}", subtype.as_str()));
    parts.push(format!("outcome:{outcome_spelling}"));
    parts.push(format!("subject:{}", structural.subject_id));
    parts.push(format!("revision:{}", structural.subject_revision));
    parts.push(format!(
        "type:{}|{}|{}",
        structural.record_type, structural.owner, structural.schema
    ));
    parts.push(format!("target:{target_handle}"));
    for handle in child_handles {
        parts.push(format!("child:{handle}"));
    }
    for member in &structural.members {
        parts.push(format!(
            "member:{}@{}|{}|{}",
            member.member_id, member.revision, member.record_type, member.evidence_digest
        ));
    }
    for partition in &structural.partitions {
        parts.push(format!(
            "partition:{}|{}",
            partition.partition_basename, partition.discriminator
        ));
        for id in &partition.member_ids {
            parts.push(format!("assign:{}->{}", partition.partition_basename, id));
        }
    }
    for held in &structural.unresolved_residue {
        parts.push(format!("residue:{held}"));
    }
    for reference in &structural.equivalence_refs {
        parts.push(format!("equivalence:{reference}"));
    }
    for reference in &structural.shared_lineage_refs {
        parts.push(format!("lineage:{reference}"));
    }
    for dependent in &dependency.dependents {
        parts.push(format!(
            "dependent:{}|{}|{}@{}",
            dependent.dependent_id,
            dependent.dependent_kind,
            dependent.endpoint,
            dependent.revision
        ));
    }
    if let Some(prior) = &structural.prior_transition {
        parts.push(format!("prior:{}|{}", prior.prior_operation_id, prior.prior_receipt_digest));
        parts.push(format!("merged:{}@{}", prior.merged_id, prior.merged_revision));
    }
    parts.push(format!("policy:{}@{}", policy.policy_id, policy.policy_revision));
    parts.push(format!("allocator:{}", policy.allocator_owner));
    parts.push(format!("bundle:{}", frozen.bundle_digest));
    parts.push(format!("manifest:{}", frozen.manifest_digest));
    parts.push(format!("verifier:{}", structural.verifier));
    canonical_json_bytes(&parts)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| StructureRepairError::Digest {
            detail: redact(&err.to_string()),
        })
}

// ---------------------------------------------------------------------------
// Duplicate selection and emission.
// ---------------------------------------------------------------------------

/// Selects replay or duplicate disposition from known identities.
///
/// Exact subject and digest bindings only; similarity never disposes.
fn select_duplicate_disposition(
    structural: &StructuralProjection,
    preliminary_digest: &str,
) -> Option<RepairOutcome> {
    if let Some(duplicate) = &structural.duplicate_of
        && duplicate == &structural.subject_id
    {
        return Some(RepairOutcome::Duplicate);
    }
    if structural
        .known_subject_ids
        .iter()
        .any(|known| known == &structural.subject_id)
    {
        return Some(RepairOutcome::Duplicate);
    }
    if structural
        .known_candidate_digests
        .iter()
        .any(|known| known == preliminary_digest)
    {
        return Some(RepairOutcome::Duplicate);
    }
    None
}

/// Emits the terminal candidate envelope for one resolved outcome.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn emit_candidate(
    subtype: RepairSubtype,
    outcome: RepairOutcome,
    judgement: &SemanticJudgement,
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
    frozen: &FrozenBundle,
) -> Result<StructureRepairCandidate, StructureRepairError> {
    let target_allocation = allocation_for(
        &structural.subject_id,
        policy,
        "typed allocation request for the repair subject; the owner issues or declines",
    )?;
    let target_handle = target_allocation.requested_handle.clone();
    let mut child_allocations: Vec<AllocationRequest> = Vec::with_capacity(structural.partitions.len());
    let mut child_handles: Vec<String> = Vec::with_capacity(structural.partitions.len());
    if matches!(subtype, RepairSubtype::Split | RepairSubtype::Reversal) {
        for partition in &structural.partitions {
            let request = allocation_for(
                &partition.partition_basename,
                policy,
                "typed allocation request for one child partition; the owner issues or declines",
            )?;
            child_handles.push(request.requested_handle.clone());
            child_allocations.push(request);
        }
    }
    let member_dispositions =
        build_member_dispositions(subtype, outcome, structural, &target_handle);
    let dependent_dispositions =
        build_dependent_dispositions(structural, dependency, &target_handle);
    let preservation = build_preservation(judgement, structural, dependency);
    if outcome == RepairOutcome::Complete
        && let Err(err) = preservation.overall()
    {
        return Err(StructureRepairError::Denominator {
            detail: redact(&err.to_string()),
        });
    }
    let rollback = build_rollback(subtype, structural, dependency, &target_handle)?;
    let invalidation = build_invalidation(structural, &dependent_dispositions)?;
    if rollback.steps.is_empty() || invalidation.entries.len() != dependency.dependents.len() {
        return Err(StructureRepairError::Denominator {
            detail: "rollback and invalidation must close over every member and dependent"
                .to_owned(),
        });
    }
    let digest = compute_candidate_digest(
        subtype,
        outcome.as_str(),
        structural,
        dependency,
        policy,
        frozen,
        &target_handle,
        &child_handles,
    )?;
    Ok(StructureRepairCandidate {
        subtype,
        outcome,
        subject_id: structural.subject_id.clone(),
        target_allocation,
        child_allocations,
        member_dispositions,
        dependent_dispositions,
        equivalence: EquivalenceReport {
            equivalent: judgement.equivalent,
            basis_note: judgement.basis_note.clone(),
            equivalence_refs: structural.equivalence_refs.clone(),
            shared_lineage_refs: structural.shared_lineage_refs.clone(),
            distinction_notes: structural.unresolved_distinctions.clone(),
        },
        preservation,
        rollback,
        invalidation,
        verifier: structural.verifier.clone(),
        candidate_digest: digest,
        note: judgement.note.clone(),
    })
}

// ---------------------------------------------------------------------------
// Canonical operation.
// ---------------------------------------------------------------------------

/// Proposes one lineage-preserving structure-repair candidate.
///
/// The six explicit parameters bind the validated curation item, the frozen
/// bundle, the grounded draft, the structural projection, the dependency
/// projection, and the governing policy. The A-05 receipt is checked
/// intrinsically through its own validation entry points and is never
/// re-executed here. Returned candidates are inert: every new identity is a
/// typed allocation request and every member and dependent carries exactly
/// one disposition.
///
/// Malformed or mismatched inputs fail closed as [`StructureRepairError`].
/// Semantic shortfalls emit inert terminal dispositions without effect.
///
/// # Errors
///
/// Returns [`StructureRepairError`] on any blank, controlled, overlong,
/// unordered, duplicated, misshapen, mismatched, stale-binding, over-budget,
/// past-deadline, or unbound field.
#[allow(clippy::too_many_lines)]
pub fn propose_structure_repair(
    item: &ValidatedCurationItem,
    frozen: &FrozenBundle,
    grounded: &GroundedDreamDraft,
    structural: &StructuralProjection,
    dependency: &DependencyProjection,
    policy: &StructureRepairPolicy,
) -> Result<StructureRepairCandidate, StructureRepairError> {
    preflight_policy_bounds(policy)?;
    preflight_list_bounds(structural, dependency, policy)?;
    preflight_total_bytes(structural, dependency, policy)?;
    validate_frozen_shapes(frozen)?;
    validate_structural_shapes(structural)?;
    validate_dependency_shapes(dependency)?;
    validate_policy_shapes(policy)?;
    if policy.policy_id != item.receipt.validator_policy {
        return Err(StructureRepairError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    intrinsic_receipt_checks(item, grounded)?;
    intrinsic_binding_checks(item, grounded, frozen)?;
    intrinsic_denominator_checks(item)?;
    item.denominator
        .validate()
        .map_err(|err| StructureRepairError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    let subtype = select_subtype(item, structural)?;
    check_subject_denominator_binding(item, structural, subtype)?;
    if let Some(early) = check_deadline_and_cancel(policy)? {
        let judgement = SemanticJudgement {
            outcome: early,
            equivalent: false,
            basis_note: "cancelled before emission; no equivalence judged".to_owned(),
            coverage_ok: false,
            faithfulness_ok: false,
            lineage_ok: false,
            reversibility_ok: false,
            ceiling_ok: true,
            closure_ok: false,
            provenance_ok: false,
            note: "cancelled or past-deadline requests emit no effect".to_owned(),
        };
        return emit_candidate(subtype, early, &judgement, structural, dependency, policy, frozen);
    }
    let preliminary = compute_candidate_digest(
        subtype,
        RepairOutcome::Complete.as_str(),
        structural,
        dependency,
        policy,
        frozen,
        &format!("alloc:{}", structural.subject_id),
        &structural
            .partitions
            .iter()
            .map(|partition| child_handle(&partition.partition_basename))
            .collect::<Vec<String>>(),
    )?;
    if let Some(duplicate) = select_duplicate_disposition(structural, &preliminary) {
        let judgement = SemanticJudgement {
            outcome: duplicate,
            equivalent: false,
            basis_note: "duplicate emits no new equivalence judgement".to_owned(),
            coverage_ok: true,
            faithfulness_ok: false,
            lineage_ok: true,
            reversibility_ok: true,
            ceiling_ok: true,
            closure_ok: true,
            provenance_ok: true,
            note: "repair identity already known; original records unchanged".to_owned(),
        };
        return emit_candidate(
            subtype,
            duplicate,
            &judgement,
            structural,
            dependency,
            policy,
            frozen,
        );
    }
    let judgement = match subtype {
        RepairSubtype::Merge => judge_merge(structural, dependency, policy),
        RepairSubtype::Split => judge_split(structural, dependency, policy),
        RepairSubtype::Reversal => judge_reversal(structural, dependency, policy),
    };
    emit_candidate(
        subtype,
        judgement.outcome,
        &judgement,
        structural,
        dependency,
        policy,
        frozen,
    )
}

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &RepairOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        RepairOutcome::Complete => None,
        RepairOutcome::Partial | RepairOutcome::Blocked => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        RepairOutcome::Insufficient => Some(CurationRejectionCode::UnsupportedPrecision),
        RepairOutcome::Duplicate
        | RepairOutcome::Stale
        | RepairOutcome::Rejected
        | RepairOutcome::Abstention => Some(CurationRejectionCode::IdentityMismatch),
    }
}
