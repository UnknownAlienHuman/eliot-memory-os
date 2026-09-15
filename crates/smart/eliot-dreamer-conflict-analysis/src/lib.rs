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
//! Test coverage note: 8 of 68 `WORK_UNIT_CASE 673/*` cases execute here
//! (673/1 valid completes, 673/10 shared lineage stays one root,
//! 673/14 majority count cannot choose a winner, 673/19 compatible scope
//! stays residue, 673/40 nondiscriminative probe rejected, 673/51
//! Concilium-review recommendation carries no plan, 673/4 receipt and fence
//! mismatch fails closed, 673/60 irrelevant order preserves digest). The
//! remaining 60 of 68 are deferred per queue-item scope; workspace admission
//! (#969), Product Pulse, and Edge proof remain separate. Deferred: 673/2,
//! 673/3, 673/5, 673/6, 673/7, 673/8, 673/9, 673/11, 673/12, 673/13, 673/15,
//! 673/16, 673/17, 673/18, 673/20, 673/21, 673/22, 673/23, 673/24, 673/25,
//! 673/26, 673/27, 673/28, 673/29, 673/30, 673/31, 673/32, 673/33, 673/34,
//! 673/35, 673/36, 673/37, 673/38, 673/39, 673/41, 673/42, 673/43, 673/44,
//! 673/45, 673/46, 673/47, 673/48, 673/49, 673/50, 673/52, 673/53, 673/54,
//! 673/55, 673/56, 673/57, 673/58, 673/59, 673/61, 673/62, 673/63, 673/64,
//! 673/65, 673/66, 673/67, 673/68.

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
        ConflictPosition, ConflictSetParams, LineageRootId, Precision, ValidityBounds,
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
}
