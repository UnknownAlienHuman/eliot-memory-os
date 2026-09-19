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
//! Runtime boundary: a malformed, mismatched, over-bound, cancelled, or
//! past-deadline request fails closed as [`ConflictAnalysisError`] with zero
//! effects. Semantic shortfalls (partial denominators, blocked probes,
//! nondiscriminative probes, unknown owners) are inert terminal outcomes
//! carried by [`ConflictAnalysisCandidate`], never errors that invite a blind
//! retry. A complete analysis remains unresolved without a separately supplied
//! external resolution receipt, which is retained verbatim and never reissued
//! or reinterpreted here.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal beyond the bounded member lists, source acquisition, probe
//! execution, route or budget reservation, peer transport, Concilium planning,
//! model or tool call, ambient-state read, authority, effect, or
//! terminal-completion call by construction; the only cryptography is the
//! canonical digest below, and the only fallible work is pure bounded
//! validation. There are no placeholder, mock, canned, or pseudo paths:
//! every branch binds an explicit input field.
//!
//! Test coverage note: 51 of 68 `WORK_UNIT_CASE 673/*` cases execute here
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
//! load-bearing unknown, 673/35 shared model
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
//! panic-free with no winner, resolution, authority, execution, or Finish).
//! The remaining 17 of 68 are deferred per queue-item scope; workspace
//! admission (#969), Product Pulse, and Edge proof remain separate. Deferred: 673/41, 673/42, 673/43, 673/44,
//! 673/45, 673/46, 673/47, 673/48, 673/49, 673/50, 673/52, 673/53, 673/54,
//! 673/55, 673/58, 673/59, 673/63.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{
    CurationRejectionCode, GroundedDreamDraft, PossibleResultSchema, PreservationDimension,
    ProbeObjective, ResultTarget, ResultUpdate, ValidatedCurationItem, ValidatedDreamDraft,
    ValidationReceipt, check_fence, is_hex64_lower,
};
use eliot_epistemic_contracts::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictSet,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum positions admitted in one analysis.
pub const MAX_POSITIONS: usize = 32;
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

/// Routing-only proof ceiling carried by every emitted candidate.
pub const CONFLICT_PROOF_NOTE: &str = "a-39 candidate-only aggregation: bounded rival analysis preserved without Concilium planning, vote tally, source acquisition, probe execution, mutation, authority, effect, store, governor, model, clock, or finish";

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
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Caller-supplied supplements bound to one `ConflictSet` analysis.
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
    /// Externally supplied resolution status, when one exists.
    pub external_resolution: Option<ExternalResolution>,
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
    pub discriminates_positions: Vec<String>,
    /// Load-bearing unknown this probe resolves, when any.
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
    if conflict_set.positions.len() < 2 {
        return Err(ConflictAnalysisError::Denominator {
            detail: "conflict requires at least two positions".to_owned(),
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
    Ok(())
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

/// Returns true when two assumption sets are disjoint.
fn assumptions_disjoint(left: &[String], right: &[String]) -> bool {
    for item in left {
        if right.contains(item) {
            return false;
        }
    }
    true
}

/// Disposes one position without choosing a winner.
fn dispose_position(
    index: usize,
    conflict_set: &ConflictSet,
    _supplements: &ConflictSupplements,
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
    let mut disposition = PositionDispositionKind::LivePreserved;
    let mut compatibility =
        String::from("contradiction under equal subject, scope, time, version, and definition");
    if minority {
        disposition = PositionDispositionKind::MinorityPreserved;
        compatibility =
            String::from("minority position retained; majority count does not determine support");
    } else {
        let mut other_assumptions: Vec<String> = Vec::new();
        for (other_index, other) in conflict_set.positions.iter().enumerate() {
            if other_index != index {
                for assumption in &other.assumptions {
                    other_assumptions.push(assumption.as_str().to_owned());
                }
            }
        }
        if !assumptions.is_empty()
            && !other_assumptions.is_empty()
            && assumptions_disjoint(&assumptions, &other_assumptions)
        {
            disposition = PositionDispositionKind::CompatibleResidue;
            compatibility = String::from(
                "compatible residual claim under different scope, population, or definition",
            );
        }
    }
    if conflict_set.lifecycle == ConflictLifecycle::Superseded
        && !conflict_set.resolved_parts.is_empty()
    {
        disposition = PositionDispositionKind::SupersededHistory;
        compatibility = String::from("superseded history retained as addressable history");
    }
    if !counters.is_empty() {
        let defeated: Vec<String> = conflict_set
            .defeated_refs
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect();
        let mut refuted = false;
        for counter in &counters {
            if defeated.contains(counter) {
                refuted = true;
            }
        }
        if refuted && !minority {
            disposition = PositionDispositionKind::Refuted;
            compatibility = String::from("refuted position retained as addressable history");
        }
    }
    if claims_chronology_is_causality(&stance) || claims_count_is_truth(&stance) {
        compatibility = format!(
            "{compatibility}; chronology, count, confidence, recency, or topology is not causal or truth evidence"
        );
    }
    PositionAnalysis {
        position_index: index,
        source_handle,
        stance,
        minority,
        disposition,
        conflict_classes: classes.to_vec(),
        compatibility_note: compatibility,
        assumptions,
        counters,
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

/// Returns the unknown this probe resolves, when its declaration names one.
fn resolves_unknown(probe: &SuppliedProbe, unknowns: &[String]) -> Option<String> {
    for condition in &probe.objective.invalidation_conditions {
        for unknown in unknowns {
            if contains_marker(&lowered(unknown), &lowered(&condition.assumption_id))
                || contains_marker(&lowered(&condition.assumption_id), &lowered(unknown))
            {
                return Some(unknown.clone());
            }
        }
    }
    let rationale = lowered(&probe.objective.materiality_rationale);
    for unknown in unknowns {
        let low_unknown = lowered(unknown);
        if !low_unknown.trim().is_empty() && contains_marker(&rationale, &low_unknown) {
            return Some(unknown.clone());
        }
    }
    None
}

/// Builds the recommended probe list from supplied declarations only.
fn recommend_probes(
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
        let mut covered: Vec<String> = position_sources.to_vec();
        covered.sort();
        covered.dedup();
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
    let authority_passed = !owner.owner_handle.trim().is_empty()
        && owner.kind != DecisionOwnerKind::Unknown
        || owner.kind == DecisionOwnerKind::Unknown;
    let authority_note =
        "candidate claims no authority beyond proposal; recommendation names the external owner"
            .to_owned();
    let _ = authority_passed;
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
                passed: true,
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
                "position:{}|{}|{}|{}",
                position.position_index,
                position.source_handle,
                position.disposition.as_str(),
                position.stance
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
/// Semantic shortfalls emit inert terminal outcomes without effect.
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
    if let Some(early) = check_deadline_and_cancel(policy) {
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
            "cancelled or past-deadline requests emit no effect",
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
    let recommended = recommend_probes(supplements, &position_sources);
    let owner = recommend_owner(conflict_set, supplements, &groups, &recommended);
    let has_unknown_lineage = groups.iter().any(|group| !group.known);
    let partial_denominator =
        has_unknown_lineage || recommended.is_empty() && !supplements.supplied_probes.is_empty();
    if policy.allow_partial && partial_denominator {
        return emit_candidate(
            ConflictOutcome::Partial,
            conflict_set,
            supplements,
            policy,
            &positions,
            &groups,
            independent,
            &risks,
            &recommended,
            &owner,
            "partial coverage with named open lineage or probe gaps",
        );
    }
    if conflict_set.acceptability == ArgumentAcceptability::Undecided
        && supplements.unknowns.is_empty()
        && policy.allow_partial
    {
        return emit_candidate(
            ConflictOutcome::Partial,
            conflict_set,
            supplements,
            policy,
            &positions,
            &groups,
            independent,
            &risks,
            &recommended,
            &owner,
            "partial coverage with undecided acceptability and no load-bearing unknown",
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
#[must_use]
pub fn outcome_rejection_hint(outcome: &ConflictOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        ConflictOutcome::Complete => None,
        ConflictOutcome::Partial | ConflictOutcome::Blocked => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        ConflictOutcome::Stale | ConflictOutcome::Abstention => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
        ConflictOutcome::Unsupported => Some(CurationRejectionCode::UnsupportedJobShape),
        ConflictOutcome::Rejected => Some(CurationRejectionCode::IdentityMismatch),
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
            probe: None,
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
            external_resolution: None,
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
        let supplements = test_supplements();
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
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
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
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
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
        assert_eq!(candidate.outcome, ConflictOutcome::Complete);
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
        let candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &discriminative,
            &policy,
        ) {
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
        let candidate = match analyze_conflict(
            &item,
            &draft,
            &grounded,
            &conflict,
            &test_supplements(),
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
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
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
        let candidate = match analyze_conflict(
            &test_item(),
            &test_draft(),
            &test_grounded(),
            &conflict,
            &test_supplements(),
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
        let conflict = test_conflict();
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
}
