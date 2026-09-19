//! Falsifiable anti-proxy development diagnosis (A-40).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one bounded falsifiable [`DevelopmentDiagnosisCandidate`] bound to the
//! actual Product Objective, the exact current discriminator, the complete
//! repair history, and an explicit rival-mechanism set. The handler binds a
//! user-visible Product gap, preserves every rival mechanism with its
//! predictions, falsifier, assumptions, confounders, support, counterevidence
//! and common-mode lineage, and recommends the minimum admissible
//! discriminating experiment from the declared finite alternatives, or an
//! explicit insufficiency. It never prescribes an executable repair as truth,
//! never executes a patch, configuration, or test, and never creates an
//! issue, work unit, agent, status promotion, authority, effect, or finish
//! signal.
//!
//! Cell `smart.dreamer.development_diagnosis`, order 40. All inputs are
//! immutable and caller supplied. The pre-handler A-05 receipt is checked
//! intrinsically through its own validation entry points and is never
//! re-executed here. The frozen conflict-analysis bytes are consumed as an
//! immutable input and are never recomputed, resolved, or re-derived here;
//! this cell holds no dependency on any candidate-validation or
//! conflict-analysis algorithm crate. No screening, grounding, production
//! registry construction, canonical mutation, authority, effect, store,
//! governor, model, clock, or finish surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the ten typed
//! parameters of [`diagnose_development_gap`], never decoded from ambient
//! bytes.
//!
//! Runtime boundary: a malformed, over-bound, cancelled-before-emission, or
//! past-deadline request emits zero effects and fails closed as
//! [`DiagnosisError`]. Semantic shortfalls (proxy-only gap, passing or
//! nonreplayable discriminator, post-hoc evidence without independent
//! confirmation, equivalent retry without new information, missing mandatory
//! conflict analysis, unfalsifiable rival, unsupported mechanism claim,
//! nondiscriminative experiment set, partial coverage, stale revision) are
//! inert terminal dispositions carried by
//! [`DevelopmentDiagnosisCandidate`], never errors that invite a blind retry.
//! A failed repair never falsifies a mechanism it did not exercise, and local
//! proxy improvement never confirms Product causality: repair outcomes are
//! preserved verbatim and are never used to eliminate rivals.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal beyond the bounded rival and experiment lists, run-book
//! execution, provider, model, tool, ambient-state, authority, effect, or
//! terminal-completion calls by construction; the only cryptography is the
//! canonical digest below, and the only fallible work is pure bounded
//! validation. There are no placeholder, mock, canned, or pseudo paths:
//! every branch binds an explicit input field.
//!
//! Test coverage note: 11 of 51 `WORK_UNIT_CASE 675/*` cases execute here
//! (675/1 valid two-rival diagnosis with minimal experiment, 675/2 exact
//! Objective/acceptance/recovery/identity binding, 675/3 wrong job/payload
//! fails closed, 675/4 fence and receipt mismatch fails closed, 675/5
//! wrong/stale source context fails closed, 675/8 proxy metric cannot prove
//! Product delta, 675/11 current-pass discriminator cannot prove failure,
//! 675/15 unchanged equivalent retry requires mechanism review, 675/21
//! mandatory conflict analysis missing yields insufficiency, 675/32
//! identical rival predictions are nondiscriminative, 675/45 exact replay is
//! deterministic). The remaining 40 of 51 are deferred per START.md s1;
//! #969 admission is separate. Deferred: 675/6, 675/7,
//! 675/9, 675/10, 675/12, 675/13, 675/14, 675/16, 675/17, 675/18, 675/19,
//! 675/20, 675/22, 675/23, 675/24, 675/25, 675/26, 675/27, 675/28, 675/29,
//! 675/30, 675/31, 675/33, 675/34, 675/35, 675/36, 675/37, 675/38, 675/39,
//! 675/40, 675/41, 675/42, 675/43, 675/44, 675/46, 675/47, 675/48, 675/49,
//! 675/50, 675/51.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    CurrentDiscriminator, CurrentObservation, DreamJobAdmission, JobClass, MechanismExercise,
    PreservationDimension, PreservationReport, ProductContext, RepairEventOutcome,
    RepairHistoryPresence, RepairLineage, RepeatReason, ValidatedDreamDraft, check_fence,
    is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum rivals admitted in one diagnosis request.
pub const MAX_RIVALS: usize = 16;
/// Maximum experiments admitted in one diagnosis request.
pub const MAX_EXPERIMENTS: usize = 16;
/// Maximum repair attempts admitted in one history.
pub const MAX_ATTEMPTS: usize = 64;
/// Maximum evidence refs admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum predictions admitted on any single rival.
pub const MAX_PREDICTIONS: usize = 32;
/// Maximum assumptions admitted on any single rival.
pub const MAX_ASSUMPTIONS: usize = 32;
/// Maximum confounders admitted on any single rival.
pub const MAX_CONFOUNDERS: usize = 32;
/// Maximum controlled variables admitted on any single experiment.
pub const MAX_CONTROLLED_VARIABLES: usize = 32;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle or identity field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for any identity field bound into digests.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum bytes for task, scope, owner, and proof-ceiling fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any bounded note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Expected preservation dimensions attested on every emitted candidate.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const DIAGNOSIS_PROOF_NOTE: &str = "a-40 candidate-only aggregation: inert falsifiable diagnosis preserved without screening, grounding, common validation, conflict recomputation, canonical mutation, authority, effect, store, governor, model, clock, or finish";
/// Product Pulse that remains external to this candidate-only cell.
pub const NEXT_EVIDENCE_PULSE: &str = "D3A_ADVISORY_DIAGNOSIS_PLANNING_PULSE_01";

/// Cases covered by the first bounded implementation slice.
///
/// This slice adds the package boundary for the canonical A03 evidence
/// records. The existing candidate algorithm remains independently bounded
/// below until the rival, `ConflictAnalysis`, finite-experiment and recipe
/// contracts are available to replace its transitional normalized inputs.
pub const SLICE1_IMPLEMENTED_CASES: &[u8] = &[1, 4, 8, 11, 15, 21, 32, 45];

/// Cases deliberately left for later contract and edge slices.
pub const SLICE1_REMAINDER_CASES: &[u8] = &[
    2, 3, 5, 6, 7, 9, 10, 12, 13, 14, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 46, 47, 48, 49, 50, 51,
];

/// Cases covered by the second bounded implementation slice.
///
/// Step-1 input and binding identity: exact Objective/acceptance/recovery
/// identity (675/2), wrong job/payload rejection (675/3), and wrong/stale
/// source-context rejection (675/5). Every path binds existing transitional
/// inputs; no new canonical contracts are required.
pub const SLICE2_IMPLEMENTED_CASES: &[u8] = &[2, 3, 5];

/// Cases deliberately left for later slices after slice 2.
pub const SLICE2_REMAINDER_CASES: &[u8] = &[
    6, 7, 9, 10, 12, 13, 14, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 46, 47, 48, 49, 50, 51,
];

/// Canonical A03 evidence supplied to the first A40 package boundary.
///
/// The records remain owned by `eliot-dreamer-contracts`; this view carries
/// references only and performs no conversion into handler-local DTOs.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalDiagnosisEvidence<'a> {
    /// Exact product objective, identity, environment and evidence envelope.
    pub product_context: &'a ProductContext,
    /// Current-path discriminator and its replay/verifier evidence.
    pub current_discriminator: &'a CurrentDiscriminator,
    /// Ordered, denominator-bearing repair lineage.
    pub repair_lineage: &'a RepairLineage,
}

impl CanonicalDiagnosisEvidence<'_> {
    /// Validates the three canonical A03 records and their product join.
    ///
    /// The canonical owners perform intrinsic bounds, digest and nested
    /// binding checks. A40 adds only the cross-record join that the
    /// discriminator names the exact product-context digest supplied here.
    pub fn validate(&self) -> Result<(), DiagnosisError> {
        self.product_context
            .validate()
            .map_err(|error| canonical_evidence_error("canonical.product_context", error))?;
        self.current_discriminator
            .validate()
            .map_err(|error| canonical_evidence_error("canonical.current_discriminator", error))?;
        self.repair_lineage
            .validate()
            .map_err(|error| canonical_evidence_error("canonical.repair_lineage", error))?;
        if self.current_discriminator.product_context_digest != self.product_context.digest {
            return Err(DiagnosisError::Binding {
                field: "canonical.current_discriminator.product_context_digest",
                detail: "current discriminator is bound to a different product context digest"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Returns a deterministic digest for the validated canonical evidence
    /// tuple.
    ///
    /// This digest is an evidence-boundary identifier only. It must never be
    /// consumed as input to diagnosis recommendation, experiment selection,
    /// or any Product-facing decision.
    pub fn canonical_digest(&self) -> Result<String, DiagnosisError> {
        self.validate()?;
        let parts = [
            self.product_context.digest.clone(),
            self.current_discriminator.digest.clone(),
            self.repair_lineage.digest.clone(),
        ];
        canonical_json_bytes(&parts).map_or_else(
            |error| {
                Err(DiagnosisError::Digest {
                    detail: redact(&error.to_string()),
                })
            },
            |bytes| Ok(sha256_hex(&bytes)),
        )
    }
}

/// Validates the canonical A03 evidence boundary and returns its tuple digest.
///
/// The returned digest is an evidence-boundary identifier only. It must never
/// be consumed as input to diagnosis recommendation, experiment selection, or
/// any Product-facing decision.
pub fn canonical_diagnosis_evidence_digest(
    product_context: &ProductContext,
    current_discriminator: &CurrentDiscriminator,
    repair_lineage: &RepairLineage,
) -> Result<String, DiagnosisError> {
    CanonicalDiagnosisEvidence {
        product_context,
        current_discriminator,
        repair_lineage,
    }
    .canonical_digest()
}

fn canonical_evidence_error(field: &'static str, error: impl core::fmt::Display) -> DiagnosisError {
    DiagnosisError::Binding {
        field,
        detail: redact(&error.to_string()),
    }
}

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

/// Returns true when values hold no duplicates, preserving order.
fn has_no_duplicates(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        let mut inner = index.saturating_add(1);
        while inner < values.len() {
            let left = values.get(index);
            let right = values.get(inner);
            if let (Some(left), Some(right)) = (left, right) {
                if left == right {
                    return false;
                }
            } else {
                return false;
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    true
}

/// Returns true when values are sorted strictly ascending with no duplicates.
fn is_sorted_unique(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        if index > 0 {
            let prev = values.get(index.saturating_sub(1));
            let current = values.get(index);
            if let (Some(prev), Some(current)) = (prev, current) {
                if prev >= current {
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
// Closed forbidden markers (oracle weakening, unrelated scope escape).
// ---------------------------------------------------------------------------

/// Substrings that mark an oracle, acceptance, or verifier weakening claim.
pub const ORACLE_MARKERS: &[&str] = &[
    "weaken oracle",
    "relax acceptance",
    "lower bar",
    "lower threshold to pass",
    "delete discriminator",
    "skip verifier",
    "ignore verifier",
    "drop the oracle",
];

/// Substrings that mark an unrelated refactor or scope-escape claim.
pub const SCOPE_ESCAPE_MARKERS: &[&str] = &[
    "unrelated refactor",
    "rewrite unrelated",
    "bypass scope",
    "expand scope silently",
    "execute repair as truth",
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
// Public vocabulary: gap, discriminator, repairs, conflict, rivals.
// ---------------------------------------------------------------------------

/// Closed kind of the supplied Product gap declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProductGapKind {
    /// A user-visible Product failure against the bound Objective.
    ProductFailure,
    /// A partially observed Product gap; completeness is blocked.
    ProductPartial,
    /// Instrumentation is missing or partial; the gap stays unknown.
    Unknown,
    /// Only activity or proxy signals are supplied; no Product delta.
    ProxyOnly,
}

impl ProductGapKind {
    /// Returns the canonical spelling of this gap kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProductFailure => "product_failure",
            Self::ProductPartial => "product_partial",
            Self::Unknown => "unknown",
            Self::ProxyOnly => "proxy_only",
        }
    }

    /// Parses the canonical spelling of a gap kind.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosisError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, DiagnosisError> {
        match spelling {
            "product_failure" => Ok(Self::ProductFailure),
            "product_partial" => Ok(Self::ProductPartial),
            "unknown" => Ok(Self::Unknown),
            "proxy_only" => Ok(Self::ProxyOnly),
            _ => Err(DiagnosisError::Shape {
                field: "product.kind",
                detail: redact(spelling),
            }),
        }
    }
}

/// Supplied Product gap bound to one Objective, acceptance, and source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductGap {
    /// Canonical Product Objective identity.
    pub objective_id: String,
    /// Exact Objective revision under diagnosis.
    pub objective_revision: u32,
    /// Digest of the bound acceptance contract projection.
    pub acceptance_digest: String,
    /// Digest of the bound recovery acceptance profile.
    pub recovery_digest: String,
    /// Canonical Product identity under diagnosis.
    pub product_id: String,
    /// Exact source revision under diagnosis, never latest-by-time.
    pub source_revision: String,
    /// Feature binding the gap is observed under.
    pub feature_ref: String,
    /// Workflow binding the gap is observed under.
    pub workflow_ref: String,
    /// User-outcome binding the gap is observed under.
    pub user_outcome_ref: String,
    /// Closed kind of the declared gap.
    pub kind: ProductGapKind,
    /// Bounded note describing the user-visible gap.
    pub gap_note: String,
    /// Evidence-backed user-outcome mapping, required for proxy signals.
    pub proxy_mapping_note: Option<String>,
    /// Evidence refs backing the gap claim, in sorted unique order.
    pub evidence_refs: Vec<String>,
    /// Digest binding this gap to its context bytes.
    pub context_digest: String,
}

/// Supplied current-path discriminator evidence for the gap.
///
/// Four independent declaration flags are kept explicit: each binds a
/// distinct discriminator semantic (predeclaration, independent
/// confirmation, precondition satisfaction, replayability), and grouping
/// them would hide load-bearing distinctions.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscriminatorEvidence {
    /// Stable discriminator identity.
    pub discriminator_id: String,
    /// Owner that admits the discriminator.
    pub owner: String,
    /// Expected observable under the bound Objective.
    pub expected_note: String,
    /// Observed result on the current path.
    pub observed_note: String,
    /// Current observation state from the canonical hub vocabulary.
    pub observation: CurrentObservation,
    /// True only when the discriminator was declared before observation.
    pub predeclared: bool,
    /// True only when post-hoc evidence carries independent confirmation.
    pub independently_confirmed: bool,
    /// True only when every exact precondition holds on the current path.
    pub preconditions_satisfied: bool,
    /// Bounded note naming the precondition state.
    pub precondition_note: String,
    /// True only when the discriminator carries a replay contract.
    pub replayable: bool,
    /// Replay identity binding the discriminator.
    pub replay_id: String,
    /// Digest of the exact replay inputs, when replayable.
    pub replay_input_digest: Option<String>,
    /// Digest of the Product context this discriminator observes.
    pub context_digest: String,
    /// Bounded note naming instrument coverage and censoring.
    pub coverage_note: String,
}

/// Bounded evidence-backed justification for a controlled repair repeat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlledRepeat {
    /// Closed repeat reason from the canonical hub vocabulary.
    pub reason: RepeatReason,
    /// Identifier of the earlier attempt being repeated.
    pub prior_attempt_id: String,
    /// Bounded explanation of what makes this repeat controlled.
    pub explanation: String,
    /// True only when genuinely new hypothesis or evidence is bound.
    pub new_information: bool,
    /// True only when operating conditions genuinely changed.
    pub changed_conditions: bool,
}

/// One retained prior repair attempt with its structured mechanism content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairAttemptSummary {
    /// Stable attempt identity.
    pub attempt_id: String,
    /// Digest over load-bearing changes only; cosmetic edits share it.
    pub equivalence_digest: String,
    /// Mechanism identity exercised by this attempt.
    pub mechanism_id: String,
    /// Bounded note naming the exercised mechanism.
    pub mechanism_note: String,
    /// Whether the mechanism was exercised, from the hub vocabulary.
    pub exercise: MechanismExercise,
    /// Typed outcome of the attempt, from the hub vocabulary.
    pub outcome: RepairEventOutcome,
    /// Controlled-repeat justification, when this attempt repeats another.
    pub controlled_repeat: Option<ControlledRepeat>,
}

/// Complete repair-history denominator for the diagnosed gap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairHistory {
    /// Presence declaration from the canonical hub vocabulary.
    pub presence: RepairHistoryPresence,
    /// Stable lineage identity.
    pub lineage_id: String,
    /// Expected attempt identities in supplied chronology.
    pub expected_attempt_ids: Vec<String>,
    /// Retained attempts in supplied chronology, never reordered.
    pub attempts: Vec<RepairAttemptSummary>,
    /// Digest binding the whole lineage.
    pub lineage_digest: String,
}

/// Frozen conflict-analysis bytes consumed as an immutable input.
///
/// This struct carries only the frozen projection identity, scope, and
/// coverage notes supplied by the runtime producer. It never recomputes,
/// resolves, or re-derives conflict analysis; optional absence is not an
/// automatic failure, while a mandatory missing projection prevents a
/// complete diagnosis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenConflictAnalysis {
    /// True only when the recipe requires conflict analysis here.
    pub required: bool,
    /// True only when the frozen projection is supplied.
    pub present: bool,
    /// Digest of the frozen projection bytes; empty when absent.
    pub digest: String,
    /// Bounded note naming the projection scope and fence.
    pub scope_note: String,
    /// Bounded note naming rival and objection coverage.
    pub coverage_note: String,
}

/// Liveness of one rival mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RivalStatus {
    /// The rival stays open with a falsifiable prediction.
    Live,
    /// A load-bearing prediction was falsified under compatible conditions.
    Falsified,
}

impl RivalStatus {
    /// Returns the canonical spelling of this rival status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Falsified => "falsified",
        }
    }
}

/// One grounded rival mechanism with its full epistemic accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RivalMechanism {
    /// Stable rival identity.
    pub rival_id: String,
    /// Owner of the rival causal boundary.
    pub owner: String,
    /// Causal boundary naming what this mechanism covers.
    pub causal_boundary: String,
    /// Falsifiable predicted observations in causal order.
    pub predicted_observations: Vec<String>,
    /// Supporting evidence refs.
    pub support_refs: Vec<String>,
    /// Explicitly unknown evidence refs.
    pub unknown_refs: Vec<String>,
    /// Counterevidence refs, required when falsified.
    pub counterevidence_refs: Vec<String>,
    /// Assumptions and dependencies in causal order.
    pub assumptions: Vec<String>,
    /// Known confounders in causal order.
    pub confounders: Vec<String>,
    /// Exact falsifier: the observation that would eliminate this rival.
    pub falsifier: String,
    /// Relation of this rival to the prior repair history.
    pub prior_repair_relation: String,
    /// Product invariant this rival affects.
    pub affected_invariant: String,
    /// Current liveness of this rival.
    pub status: RivalStatus,
    /// Bounded reason for the current liveness.
    pub status_reason: String,
}

/// Shared-model lineage disclosure preserved across every diagnosis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonModeDisclosure {
    /// Bounded note naming the shared model lineage, or its absence.
    pub shared_model_note: String,
    /// Bounded note naming the shared source lineage, or its absence.
    pub shared_source_note: String,
    /// Bounded note naming the shared evaluator lineage, or its absence.
    pub shared_evaluator_note: String,
    /// Bounded note naming the shared fixture lineage, or its absence.
    pub shared_fixture_note: String,
    /// Bounded note naming the residual common-mode uncertainty.
    pub uncertainty_note: String,
}

// ---------------------------------------------------------------------------
// Public vocabulary: experiments, policy, outcome, candidate.
// ---------------------------------------------------------------------------

/// Closed material outcome kinds every experiment must map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExperimentOutcomeKind {
    /// The experiment succeeds under its verifier.
    Success,
    /// The experiment runs with no observable change.
    NoChange,
    /// The experiment regresses the observed Product signal.
    Regression,
    /// The experiment cannot run; its slot stays unavailable.
    Unavailable,
    /// The experiment outcome is unknown or censored.
    Unknown,
    /// Instrumentation fails; nothing about rivals is learned.
    InstrumentFailure,
}

impl ExperimentOutcomeKind {
    /// Returns the canonical spelling of this outcome kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NoChange => "no_change",
            Self::Regression => "regression",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
            Self::InstrumentFailure => "instrument_failure",
        }
    }

    /// All six material outcome kinds in canonical order.
    pub const ALL: [Self; 6] = [
        Self::Success,
        Self::NoChange,
        Self::Regression,
        Self::Unavailable,
        Self::Unknown,
        Self::InstrumentFailure,
    ];
}

/// One material outcome mapped to its rival effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentOutcomeMapping {
    /// Material outcome kind being mapped.
    pub outcome: ExperimentOutcomeKind,
    /// Bounded note naming what this outcome means for the live rivals.
    pub rival_effect: String,
}

/// One finite inert discriminating experiment alternative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscriminatingExperiment {
    /// Stable experiment identity.
    pub experiment_id: String,
    /// External owner that must run or decline the experiment.
    pub owner: String,
    /// Independent verifier that checks the experiment observable.
    pub verifier: String,
    /// First live rival this experiment separates.
    pub primary_rival: String,
    /// Second live rival this experiment separates.
    pub secondary_rival: String,
    /// Blocking assumption this experiment resolves, when any.
    pub resolves_assumption: Option<String>,
    /// Controlled variables held fixed across arms.
    pub controlled_variables: Vec<String>,
    /// Complete material-outcome matrix, exactly the six kinds once each.
    pub outcome_matrix: Vec<ExperimentOutcomeMapping>,
    /// Bounded cost note.
    pub cost_note: String,
    /// Bounded risk note.
    pub risk_note: String,
    /// Bounded effect and privacy note.
    pub effect_note: String,
    /// Bounded time and deadline note.
    pub time_note: String,
    /// Bounded cancellation note.
    pub cancel_note: String,
    /// Bounded cleanup note.
    pub cleanup_note: String,
    /// Bounded rollback note.
    pub rollback_note: String,
}

/// Closed policy governing one development diagnosis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosisPolicy {
    /// Governing policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Policy revision; zero is rejected as a defaulted binding.
    pub policy_revision: u32,
    /// Maximum rivals admitted in this request.
    pub max_rivals: usize,
    /// Maximum experiments admitted in this request.
    pub max_experiments: usize,
    /// Maximum evidence items admitted per list.
    pub max_evidence_items: usize,
    /// True selects explicit partial emission; false selects all-or-nothing.
    pub allow_partial: bool,
    /// True when the caller cancelled this diagnosis before emission.
    pub cancelled: bool,
    /// Explicit observation time in milliseconds, when bounded.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, when bounded.
    pub deadline_ms: Option<u64>,
    /// Bounded note naming the receiving owner context.
    pub owner_note: String,
}

/// Terminal outcome of one development diagnosis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiagnosisOutcome {
    /// One complete falsifiable diagnosis with a discriminating experiment.
    Complete,
    /// A diagnosis with named partial coverage; completeness is blocked.
    Partial,
    /// Inputs are well-formed but insufficient for a complete diagnosis.
    Insufficient,
    /// An equivalent repair repeats without new information; review first.
    MechanismReviewRequired,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// The request is rejected with a boundary handoff.
    Rejected,
}

impl DiagnosisOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Insufficient => "insufficient",
            Self::MechanismReviewRequired => "mechanism_review_required",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
        }
    }
}

/// One rival assessment preserved in the emitted candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RivalAssessment {
    /// Rival identity this assessment accounts for.
    pub rival_id: String,
    /// Preserved liveness of this rival.
    pub status: RivalStatus,
    /// Bounded reason naming the evidence behind this assessment.
    pub reason: String,
    /// Falsifying evidence identity, when falsified.
    pub falsifying_evidence: Option<String>,
}

/// Inert repair-scope recommendation carried by the candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairRecommendation {
    /// Exact canonical next owner; this cell creates no work unit.
    pub owner: String,
    /// Smallest justified repair or investigation surface.
    pub minimal_scope: String,
    /// Forbidden paths that stay closed for the next owner.
    pub forbidden_paths: Vec<String>,
    /// Current discriminator the next work replays against.
    pub old_discriminator: String,
    /// Discriminator the next work must establish or preserve.
    pub new_discriminator: String,
    /// Rollback boundary the next owner must honor.
    pub rollback_note: String,
}

/// Complete inert development-diagnosis candidate envelope.
///
/// The envelope is never an applied receipt, never a reservation, and never
/// a finish signal. The recommended experiment names the external owner that
/// must run or decline it; nothing here executes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevelopmentDiagnosisCandidate {
    /// Terminal outcome for this diagnosis.
    pub outcome: DiagnosisOutcome,
    /// Stable diagnosis handle for this candidate.
    pub diagnosis_handle: String,
    /// Product identity under diagnosis.
    pub product_id: String,
    /// Source revision under diagnosis.
    pub source_revision: String,
    /// Objective identity under diagnosis.
    pub objective_id: String,
    /// Canonical spelling of the established gap kind.
    pub gap_kind: String,
    /// One assessment per rival in supplied causal order.
    pub rivals: Vec<RivalAssessment>,
    /// Count of live rivals preserved.
    pub rivals_live: usize,
    /// Count of falsified rivals preserved.
    pub rivals_falsified: usize,
    /// Strongest-current rival, only with exact elimination evidence.
    pub strongest_current: Option<String>,
    /// Bounded limits note qualifying any strongest-current claim.
    pub strongest_limits_note: String,
    /// Preserved common-mode disclosure.
    pub common_mode: CommonModeDisclosure,
    /// Recommended experiment, inert and owner-bound, when selected.
    pub recommended_experiment: Option<DiscriminatingExperiment>,
    /// Owner, minimal scope, and forbidden-surface recommendation.
    pub recommendation: RepairRecommendation,
    /// Expected next Edge or Product Pulse evidence, externally produced.
    pub next_evidence_note: String,
    /// Seven-dimension preservation report for this candidate.
    pub preservation: PreservationReport,
    /// Output digest of the input A-05 receipt this diagnosis replays.
    pub input_receipt_digest: String,
    /// Expected attempt identities accounted, in supplied order.
    pub attempt_denominator: Vec<String>,
    /// Experiments considered from the declared alternative set.
    pub experiments_considered: usize,
    /// Deterministic digest binding the diagnosis inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `DevelopmentDiagnosisCandidate`.
// ---------------------------------------------------------------------------

/// Typed fail-closed development-diagnosis error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiagnosisError {
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
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Two envelopes disagree on a shared binding.
    Binding {
        /// Closed binding name.
        field: &'static str,
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
    /// A rival, attempt, evidence, or experiment denominator is malformed.
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

impl core::fmt::Display for DiagnosisError {
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

impl core::error::Error for DiagnosisError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(value: &str, field: &'static str, max: usize) -> Result<(), DiagnosisError> {
    if value.trim().is_empty() {
        return Err(DiagnosisError::Shape {
            field,
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(DiagnosisError::Shape {
            field,
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(DiagnosisError::Shape {
            field,
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &'static str) -> Result<(), DiagnosisError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(DiagnosisError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(DiagnosisError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &'static str) -> Result<(), DiagnosisError> {
    if !is_hex64_lower(value) {
        return Err(DiagnosisError::Digest {
            detail: ["digest ", field, " must be 64 lowercase hex sha256"].concat(),
        });
    }
    Ok(())
}

/// Checks one sorted-unique ref list for handle shape and ordering.
fn check_sorted_refs(values: &[String], field: &'static str) -> Result<(), DiagnosisError> {
    for value in values {
        check_handle(value, field)?;
    }
    if !is_sorted_unique(values) {
        return Err(DiagnosisError::Order {
            phase: field.to_owned(),
            detail: "refs must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

/// Checks one order-preserving list for handle shape and uniqueness.
fn check_unique_refs(values: &[String], field: &'static str) -> Result<(), DiagnosisError> {
    for value in values {
        check_handle(value, field)?;
    }
    if !has_no_duplicates(values) {
        return Err(DiagnosisError::Order {
            phase: field.to_owned(),
            detail: "refs must hold no duplicates".to_owned(),
        });
    }
    Ok(())
}

/// Checks one order-preserving text list for shape and uniqueness.
fn check_unique_texts(
    values: &[String],
    field: &'static str,
    max: usize,
) -> Result<(), DiagnosisError> {
    for value in values {
        check_bounded_text(value, field, max)?;
    }
    if !has_no_duplicates(values) {
        return Err(DiagnosisError::Order {
            phase: field.to_owned(),
            detail: "entries must hold no duplicates".to_owned(),
        });
    }
    Ok(())
}

/// Rejects a list length above its independent ceiling.
fn bound_list_length(phase: &'static str, got: usize, max: usize) -> Result<(), DiagnosisError> {
    if got > max {
        return Err(DiagnosisError::Bounds {
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
// Shape validation per input family (malformed input only).
// ---------------------------------------------------------------------------

/// Validates Product gap shapes without judging Product semantics.
fn validate_product_shapes(product: &ProductGap) -> Result<(), DiagnosisError> {
    check_bounded_text(&product.objective_id, "product.objective", MAX_ID_BYTES)?;
    if product.objective_revision == 0 {
        return Err(DiagnosisError::Shape {
            field: "product.objective-revision",
            detail: "objective revision must be explicit, not defaulted".to_owned(),
        });
    }
    check_digest(&product.acceptance_digest, "product.acceptance")?;
    check_digest(&product.recovery_digest, "product.recovery")?;
    check_bounded_text(&product.product_id, "product.identity", MAX_ID_BYTES)?;
    check_bounded_text(&product.source_revision, "product.source", MAX_ID_BYTES)?;
    check_bounded_text(&product.feature_ref, "product.feature", MAX_SCOPE_BYTES)?;
    check_bounded_text(&product.workflow_ref, "product.workflow", MAX_SCOPE_BYTES)?;
    check_bounded_text(
        &product.user_outcome_ref,
        "product.user-outcome",
        MAX_SCOPE_BYTES,
    )?;
    check_bounded_text(&product.gap_note, "product.gap", MAX_NOTE_BYTES)?;
    if let Some(mapping) = &product.proxy_mapping_note {
        check_bounded_text(mapping, "product.proxy-mapping", MAX_NOTE_BYTES)?;
    }
    bound_list_length(
        "product.evidence",
        product.evidence_refs.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    check_sorted_refs(&product.evidence_refs, "product.evidence")?;
    check_digest(&product.context_digest, "product.context")?;
    Ok(())
}

/// Validates discriminator shapes without judging discriminator semantics.
fn validate_discriminator_shapes(
    discriminator: &DiscriminatorEvidence,
) -> Result<(), DiagnosisError> {
    check_handle(&discriminator.discriminator_id, "discriminator.id")?;
    check_bounded_text(&discriminator.owner, "discriminator.owner", MAX_ID_BYTES)?;
    check_bounded_text(
        &discriminator.expected_note,
        "discriminator.expected",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &discriminator.observed_note,
        "discriminator.observed",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &discriminator.precondition_note,
        "discriminator.preconditions",
        MAX_NOTE_BYTES,
    )?;
    check_handle(&discriminator.replay_id, "discriminator.replay")?;
    if let Some(digest) = &discriminator.replay_input_digest {
        check_digest(digest, "discriminator.replay-input")?;
    }
    check_digest(&discriminator.context_digest, "discriminator.context")?;
    check_bounded_text(
        &discriminator.coverage_note,
        "discriminator.coverage",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates one repair attempt shape without judging repair semantics.
fn validate_one_attempt_shape(attempt: &RepairAttemptSummary) -> Result<(), DiagnosisError> {
    check_handle(&attempt.attempt_id, "repair.attempt")?;
    check_digest(&attempt.equivalence_digest, "repair.equivalence")?;
    check_bounded_text(&attempt.mechanism_id, "repair.mechanism", MAX_ID_BYTES)?;
    check_bounded_text(
        &attempt.mechanism_note,
        "repair.mechanism-note",
        MAX_NOTE_BYTES,
    )?;
    if let Some(repeat) = &attempt.controlled_repeat {
        check_handle(&repeat.prior_attempt_id, "repair.repeat-prior")?;
        check_bounded_text(&repeat.explanation, "repair.repeat-why", MAX_NOTE_BYTES)?;
    }
    Ok(())
}

/// Validates repair-history shapes without judging repair semantics.
fn validate_repair_shapes(history: &RepairHistory) -> Result<(), DiagnosisError> {
    check_handle(&history.lineage_id, "repair.lineage")?;
    bound_list_length("repair.attempts", history.attempts.len(), MAX_ATTEMPTS)?;
    bound_list_length(
        "repair.expected",
        history.expected_attempt_ids.len(),
        MAX_ATTEMPTS,
    )?;
    for identity in &history.expected_attempt_ids {
        check_handle(identity, "repair.expected")?;
    }
    if !has_no_duplicates(&history.expected_attempt_ids) {
        return Err(DiagnosisError::Order {
            phase: "repair.expected".to_owned(),
            detail: "expected attempt identities must hold no duplicates".to_owned(),
        });
    }
    for attempt in &history.attempts {
        validate_one_attempt_shape(attempt)?;
    }
    let mut seen: Vec<&str> = Vec::with_capacity(history.attempts.len());
    for attempt in &history.attempts {
        if seen.contains(&attempt.attempt_id.as_str()) {
            return Err(DiagnosisError::Order {
                phase: "repair.attempts".to_owned(),
                detail: "attempt identities must hold no duplicates".to_owned(),
            });
        }
        seen.push(attempt.attempt_id.as_str());
    }
    check_digest(&history.lineage_digest, "repair.lineage-digest")?;
    Ok(())
}

/// Validates frozen conflict-analysis shapes without recomputing anything.
fn validate_conflict_shapes(conflict: &FrozenConflictAnalysis) -> Result<(), DiagnosisError> {
    if conflict.present {
        check_digest(&conflict.digest, "conflict.digest")?;
    } else if !conflict.digest.is_empty() {
        return Err(DiagnosisError::Shape {
            field: "conflict.digest",
            detail: "absent projection must carry an empty digest".to_owned(),
        });
    }
    check_bounded_text(&conflict.scope_note, "conflict.scope", MAX_NOTE_BYTES)?;
    check_bounded_text(&conflict.coverage_note, "conflict.coverage", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates one rival shape without judging causal semantics.
fn validate_one_rival_shape(rival: &RivalMechanism) -> Result<(), DiagnosisError> {
    check_handle(&rival.rival_id, "rival.id")?;
    check_bounded_text(&rival.owner, "rival.owner", MAX_ID_BYTES)?;
    check_bounded_text(&rival.causal_boundary, "rival.boundary", MAX_NOTE_BYTES)?;
    bound_list_length(
        "rival.predictions",
        rival.predicted_observations.len(),
        MAX_PREDICTIONS,
    )?;
    check_unique_texts(
        &rival.predicted_observations,
        "rival.predictions",
        MAX_NOTE_BYTES,
    )?;
    bound_list_length(
        "rival.support",
        rival.support_refs.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    check_unique_refs(&rival.support_refs, "rival.support")?;
    bound_list_length(
        "rival.unknowns",
        rival.unknown_refs.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    check_unique_refs(&rival.unknown_refs, "rival.unknowns")?;
    bound_list_length(
        "rival.counterevidence",
        rival.counterevidence_refs.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    check_unique_refs(&rival.counterevidence_refs, "rival.counterevidence")?;
    bound_list_length(
        "rival.assumptions",
        rival.assumptions.len(),
        MAX_ASSUMPTIONS,
    )?;
    check_unique_texts(&rival.assumptions, "rival.assumptions", MAX_NOTE_BYTES)?;
    bound_list_length(
        "rival.confounders",
        rival.confounders.len(),
        MAX_CONFOUNDERS,
    )?;
    check_unique_texts(&rival.confounders, "rival.confounders", MAX_NOTE_BYTES)?;
    check_bounded_text(&rival.falsifier, "rival.falsifier", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &rival.prior_repair_relation,
        "rival.prior-repairs",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&rival.affected_invariant, "rival.invariant", MAX_NOTE_BYTES)?;
    check_bounded_text(&rival.status_reason, "rival.status", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates rival denominator shapes without judging causal semantics.
fn validate_rival_shapes(
    rivals: &[RivalMechanism],
    policy: &DiagnosisPolicy,
) -> Result<(), DiagnosisError> {
    let ceiling = policy.max_rivals.min(MAX_RIVALS);
    bound_list_length("rivals", rivals.len(), ceiling)?;
    for rival in rivals {
        validate_one_rival_shape(rival)?;
    }
    let mut seen: Vec<&str> = Vec::with_capacity(rivals.len());
    for rival in rivals {
        if seen.contains(&rival.rival_id.as_str()) {
            return Err(DiagnosisError::Order {
                phase: "rivals".to_owned(),
                detail: "rival identities must hold no duplicates".to_owned(),
            });
        }
        seen.push(rival.rival_id.as_str());
    }
    Ok(())
}

/// Validates common-mode disclosure shapes.
fn validate_common_mode_shapes(common_mode: &CommonModeDisclosure) -> Result<(), DiagnosisError> {
    check_bounded_text(
        &common_mode.shared_model_note,
        "common-mode.model",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &common_mode.shared_source_note,
        "common-mode.source",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &common_mode.shared_evaluator_note,
        "common-mode.evaluator",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &common_mode.shared_fixture_note,
        "common-mode.fixture",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &common_mode.uncertainty_note,
        "common-mode.uncertainty",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates one experiment shape without judging experiment semantics.
fn validate_one_experiment_shape(
    experiment: &DiscriminatingExperiment,
) -> Result<(), DiagnosisError> {
    check_handle(&experiment.experiment_id, "experiment.id")?;
    check_bounded_text(&experiment.owner, "experiment.owner", MAX_ID_BYTES)?;
    check_bounded_text(&experiment.verifier, "experiment.verifier", MAX_ID_BYTES)?;
    check_handle(&experiment.primary_rival, "experiment.primary")?;
    check_handle(&experiment.secondary_rival, "experiment.secondary")?;
    if let Some(assumption) = &experiment.resolves_assumption {
        check_bounded_text(assumption, "experiment.assumption", MAX_NOTE_BYTES)?;
    }
    bound_list_length(
        "experiment.controlled",
        experiment.controlled_variables.len(),
        MAX_CONTROLLED_VARIABLES,
    )?;
    check_unique_texts(
        &experiment.controlled_variables,
        "experiment.controlled",
        MAX_NOTE_BYTES,
    )?;
    bound_list_length(
        "experiment.matrix",
        experiment.outcome_matrix.len(),
        ExperimentOutcomeKind::ALL.len(),
    )?;
    for mapping in &experiment.outcome_matrix {
        check_bounded_text(
            &mapping.rival_effect,
            "experiment.rival-effect",
            MAX_NOTE_BYTES,
        )?;
    }
    check_bounded_text(&experiment.cost_note, "experiment.cost", MAX_NOTE_BYTES)?;
    check_bounded_text(&experiment.risk_note, "experiment.risk", MAX_NOTE_BYTES)?;
    check_bounded_text(&experiment.effect_note, "experiment.effect", MAX_NOTE_BYTES)?;
    check_bounded_text(&experiment.time_note, "experiment.time", MAX_NOTE_BYTES)?;
    check_bounded_text(&experiment.cancel_note, "experiment.cancel", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &experiment.cleanup_note,
        "experiment.cleanup",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &experiment.rollback_note,
        "experiment.rollback",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates experiment denominator shapes without judging semantics.
fn validate_experiment_shapes(
    experiments: &[DiscriminatingExperiment],
    policy: &DiagnosisPolicy,
) -> Result<(), DiagnosisError> {
    let ceiling = policy.max_experiments.min(MAX_EXPERIMENTS);
    bound_list_length("experiments", experiments.len(), ceiling)?;
    for experiment in experiments {
        validate_one_experiment_shape(experiment)?;
    }
    let mut seen: Vec<&str> = Vec::with_capacity(experiments.len());
    for experiment in experiments {
        if seen.contains(&experiment.experiment_id.as_str()) {
            return Err(DiagnosisError::Order {
                phase: "experiments".to_owned(),
                detail: "experiment identities must hold no duplicates".to_owned(),
            });
        }
        seen.push(experiment.experiment_id.as_str());
    }
    Ok(())
}

/// Validates policy intrinsic shapes and ceilings.
fn validate_policy_shapes(policy: &DiagnosisPolicy) -> Result<(), DiagnosisError> {
    check_handle(&policy.policy_id, "policy.id")?;
    if policy.policy_revision == 0 {
        return Err(DiagnosisError::Policy {
            detail: "policy_revision must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.max_rivals == 0 || policy.max_rivals > MAX_RIVALS {
        return Err(DiagnosisError::Policy {
            detail: "max_rivals must cover a nonempty bounded range".to_owned(),
        });
    }
    if policy.max_experiments == 0 || policy.max_experiments > MAX_EXPERIMENTS {
        return Err(DiagnosisError::Policy {
            detail: "max_experiments must cover a nonempty bounded range".to_owned(),
        });
    }
    if policy.max_evidence_items == 0 || policy.max_evidence_items > MAX_EVIDENCE_ITEMS {
        return Err(DiagnosisError::Policy {
            detail: "max_evidence_items must cover a nonempty bounded range".to_owned(),
        });
    }
    check_bounded_text(&policy.owner_note, "policy.owner", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Preflights aggregate text bytes across the whole diagnosis surface.
fn preflight_total_bytes(
    product: &ProductGap,
    discriminator: &DiscriminatorEvidence,
    history: &RepairHistory,
    rivals: &[RivalMechanism],
    experiments: &[DiscriminatingExperiment],
    policy: &DiagnosisPolicy,
) -> Result<(), DiagnosisError> {
    let mut total = 0usize;
    total = total.saturating_add(count_text_bytes(&[
        &product.objective_id,
        &product.product_id,
        &product.source_revision,
        &product.gap_note,
        &discriminator.owner,
        &discriminator.expected_note,
        &discriminator.observed_note,
        &discriminator.coverage_note,
        &policy.policy_id,
        &policy.owner_note,
    ]));
    for attempt in &history.attempts {
        total = total.saturating_add(count_text_bytes(&[
            &attempt.attempt_id,
            &attempt.mechanism_id,
            &attempt.mechanism_note,
        ]));
    }
    for rival in rivals {
        total = total.saturating_add(count_text_bytes(&[
            &rival.rival_id,
            &rival.owner,
            &rival.causal_boundary,
            &rival.falsifier,
            &rival.status_reason,
        ]));
        for prediction in &rival.predicted_observations {
            total = total.saturating_add(prediction.len());
        }
    }
    for experiment in experiments {
        total = total.saturating_add(count_text_bytes(&[
            &experiment.experiment_id,
            &experiment.owner,
            &experiment.verifier,
            &experiment.cost_note,
            &experiment.rollback_note,
        ]));
    }
    if total > MAX_TOTAL_BYTES {
        return Err(DiagnosisError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input exceeds the total byte ceiling".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Intrinsic checks (A-05 receipt intrinsically, never re-executed).
// ---------------------------------------------------------------------------

/// Maps a contract violation into a redacted receipt error.
fn receipt_err(detail: &str) -> DiagnosisError {
    DiagnosisError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the A-05 receipt intrinsically plus the draft binding.
fn intrinsic_receipt_checks(draft: &ValidatedDreamDraft) -> Result<(), DiagnosisError> {
    draft
        .receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    draft
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if draft.receipt.terminal_disposition != "accepted"
        && draft.receipt.terminal_disposition != "partial"
    {
        return Err(DiagnosisError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    Ok(())
}

/// Checks job, draft, task, scope, fence, budget, and policy bindings.
fn intrinsic_binding_checks(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    policy: &DiagnosisPolicy,
) -> Result<(), DiagnosisError> {
    job.validate().map_err(|err| DiagnosisError::Binding {
        field: "job",
        detail: redact(&err.to_string()),
    })?;
    if job.job_class != JobClass::DevelopmentDiagnosis {
        return Err(DiagnosisError::Binding {
            field: "job_class",
            detail: "dream job is not a development-diagnosis job".to_owned(),
        });
    }
    check_fence(&job.state_fence).map_err(|err| DiagnosisError::Binding {
        field: "state_fence",
        detail: redact(&err.to_string()),
    })?;
    job.budget
        .validate()
        .map_err(|err| DiagnosisError::Policy {
            detail: redact(&err.to_string()),
        })?;
    if draft.receipt.task_id != job.task_id || draft.task_id != job.task_id {
        return Err(DiagnosisError::Binding {
            field: "task_id",
            detail: "draft task drifts from the job binding".to_owned(),
        });
    }
    if draft.receipt.scope_id != job.scope_id || draft.scope_id != job.scope_id {
        return Err(DiagnosisError::Binding {
            field: "scope_id",
            detail: "draft scope drifts from the job binding".to_owned(),
        });
    }
    if draft.state_fence != job.state_fence || draft.receipt.state_fence != job.state_fence {
        return Err(DiagnosisError::Binding {
            field: "state_fence",
            detail: "draft fence drifts from the job fence".to_owned(),
        });
    }
    if policy.policy_id != draft.receipt.validator_policy {
        return Err(DiagnosisError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    Ok(())
}

/// Checks the repair denominator: expected identities exactly cover attempts.
fn intrinsic_repair_denominator(history: &RepairHistory) -> Result<(), DiagnosisError> {
    if matches!(history.presence, RepairHistoryPresence::ZeroPriorRepairs)
        && (!history.expected_attempt_ids.is_empty() || !history.attempts.is_empty())
    {
        return Err(DiagnosisError::Denominator {
            detail: "zero prior repairs requires an empty attempt history".to_owned(),
        });
    }
    if matches!(history.presence, RepairHistoryPresence::OneOrMore)
        && history.expected_attempt_ids.is_empty()
    {
        return Err(DiagnosisError::Denominator {
            detail: "one-or-more history requires at least one expected attempt".to_owned(),
        });
    }
    let mut covered = 0usize;
    for identity in &history.expected_attempt_ids {
        let mut found = false;
        for attempt in &history.attempts {
            if attempt.attempt_id.as_str() == identity.as_str() {
                found = true;
                break;
            }
        }
        if !found {
            return Err(DiagnosisError::Denominator {
                detail: "expected attempt identity has no retained attempt".to_owned(),
            });
        }
        covered = covered.saturating_add(1);
    }
    if covered != history.attempts.len() {
        return Err(DiagnosisError::Denominator {
            detail: "retained attempts must exactly cover the expected denominator".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic evaluation (shortfalls stay inert outcomes, never blind retries).
// ---------------------------------------------------------------------------

/// Closed semantic verdict of the Product gap declaration.
enum GapVerdict {
    /// A user-visible Product failure is established.
    Failure,
    /// A partially observed Product gap is established.
    Partial,
    /// The gap stays unknown; only insufficiency is admissible.
    Unknown,
    /// Only proxy signals are supplied; no Product delta exists.
    ProxyOnly,
}

/// Classifies the supplied gap kind without promoting proxies.
fn evaluate_gap(product: &ProductGap) -> Result<GapVerdict, DiagnosisError> {
    match product.kind {
        ProductGapKind::ProductFailure => {
            if product.evidence_refs.is_empty() {
                return Err(DiagnosisError::Shape {
                    field: "product.evidence",
                    detail: "a claimed product failure requires cited evidence".to_owned(),
                });
            }
            Ok(GapVerdict::Failure)
        }
        ProductGapKind::ProductPartial => {
            if product.evidence_refs.is_empty() {
                return Err(DiagnosisError::Shape {
                    field: "product.evidence",
                    detail: "a claimed partial gap requires cited evidence".to_owned(),
                });
            }
            Ok(GapVerdict::Partial)
        }
        ProductGapKind::Unknown => Ok(GapVerdict::Unknown),
        ProductGapKind::ProxyOnly => Ok(GapVerdict::ProxyOnly),
    }
}

/// Closed semantic verdict of the current-path discriminator.
enum DiscriminatorVerdict {
    /// A currently failing discriminator on the exact current path.
    Failing,
    /// A currently passing discriminator cannot prove failure.
    Passing,
    /// Preconditions, replay, or shape keep it from proving anything.
    Invalid,
    /// Explicit unknown, censored, or infrastructure-only observation.
    Insufficient,
    /// Post-hoc evidence without independent confirmation.
    Unconfirmed,
}

/// Returns the observation class of a hub current observation.
fn observation_class(observation: &CurrentObservation) -> &'static str {
    match observation {
        CurrentObservation::Pass { .. } => "pass",
        CurrentObservation::Fail { .. } => "fail",
        CurrentObservation::Partial { .. } => "partial",
        CurrentObservation::Unknown { .. } => "unknown",
        CurrentObservation::Censored { .. } => "censored",
        CurrentObservation::InfrastructureFailure { .. } => "infrastructure",
    }
}

/// Classifies the discriminator without editing or weakening the oracle.
fn evaluate_discriminator(discriminator: &DiscriminatorEvidence) -> DiscriminatorVerdict {
    if !discriminator.preconditions_satisfied {
        return DiscriminatorVerdict::Invalid;
    }
    if !discriminator.replayable || discriminator.replay_input_digest.is_none() {
        return DiscriminatorVerdict::Invalid;
    }
    match observation_class(&discriminator.observation) {
        "pass" => DiscriminatorVerdict::Passing,
        "fail" | "partial" => {
            if discriminator.predeclared || discriminator.independently_confirmed {
                DiscriminatorVerdict::Failing
            } else {
                DiscriminatorVerdict::Unconfirmed
            }
        }
        _ => DiscriminatorVerdict::Insufficient,
    }
}

/// Finds the first attempt index carrying the digest before `before`.
fn first_index_with_digest(history: &RepairHistory, digest: &str, before: usize) -> Option<usize> {
    let mut index = 0usize;
    while index < before {
        if let Some(attempt) = history.attempts.get(index)
            && attempt.equivalence_digest.as_str() == digest
        {
            return Some(index);
        }
        index = index.saturating_add(1);
    }
    None
}

/// Returns the attempt identity at an index, or an empty marker.
fn attempt_id_at(history: &RepairHistory, index: usize) -> &str {
    history
        .attempts
        .get(index)
        .map_or("", |attempt| attempt.attempt_id.as_str())
}

/// Detects an unjustified equivalent retry by structured mechanism content.
///
/// Equivalence groups by load-bearing digest, never by cosmetic labels. A
/// repeat is controlled only when it names its prior attempt and binds
/// genuinely new information or changed conditions with an explanation.
fn equivalent_retry_without_justification(history: &RepairHistory) -> bool {
    let mut index = 0usize;
    while index < history.attempts.len() {
        if let Some(attempt) = history.attempts.get(index) {
            let first = first_index_with_digest(history, &attempt.equivalence_digest, index);
            if let Some(first) = first {
                let justified = match &attempt.controlled_repeat {
                    Some(repeat) => {
                        repeat.prior_attempt_id.as_str() == attempt_id_at(history, first)
                            && !repeat.explanation.trim().is_empty()
                            && (repeat.new_information || repeat.changed_conditions)
                    }
                    None => false,
                };
                if !justified {
                    return true;
                }
            }
        }
        index = index.saturating_add(1);
    }
    false
}

/// Checks that every controlled repeat names a genuinely earlier attempt.
fn validate_repeat_predecessors(history: &RepairHistory) -> Result<(), DiagnosisError> {
    let mut index = 0usize;
    while index < history.attempts.len() {
        if let Some(attempt) = history.attempts.get(index)
            && let Some(repeat) = &attempt.controlled_repeat
        {
            let mut found = false;
            let mut prior = 0usize;
            while prior < index {
                if let Some(earlier) = history.attempts.get(prior)
                    && earlier.attempt_id.as_str() == repeat.prior_attempt_id.as_str()
                {
                    found = true;
                    break;
                }
                prior = prior.saturating_add(1);
            }
            if !found {
                return Err(DiagnosisError::Binding {
                    field: "repair.repeat-prior",
                    detail: "controlled repeat names no earlier retained attempt".to_owned(),
                });
            }
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Returns true when the rival carries support or explicitly unknown evidence.
fn has_support_or_unknown(rival: &RivalMechanism) -> bool {
    !rival.support_refs.is_empty() || !rival.unknown_refs.is_empty()
}

/// Returns true when the rival text trips an oracle-weakening marker.
fn trips_oracle_markers(text: &str) -> bool {
    mentions_any(&lowered(text), ORACLE_MARKERS)
}

/// Validates rival semantics; every shortfall names the offending rival.
fn validate_rival_semantics(rival: &RivalMechanism) -> Result<(), DiagnosisError> {
    if rival.predicted_observations.is_empty() {
        return Err(DiagnosisError::Denominator {
            detail: "every rival requires at least one falsifiable prediction".to_owned(),
        });
    }
    if rival.falsifier.trim() == rival.rival_id.trim() {
        return Err(DiagnosisError::Denominator {
            detail: "a rival label is not its own falsifier".to_owned(),
        });
    }
    if !has_support_or_unknown(rival) {
        return Err(DiagnosisError::Denominator {
            detail: "every rival requires support or explicitly unknown evidence".to_owned(),
        });
    }
    if matches!(rival.status, RivalStatus::Falsified) && rival.counterevidence_refs.is_empty() {
        return Err(DiagnosisError::Denominator {
            detail: "a falsified rival requires its falsifying counterevidence".to_owned(),
        });
    }
    if trips_oracle_markers(&rival.falsifier) || trips_oracle_markers(&rival.status_reason) {
        return Err(DiagnosisError::Denominator {
            detail: "rival reasoning must not weaken the oracle".to_owned(),
        });
    }
    Ok(())
}

/// Returns true when the experiment matrix covers all six kinds exactly once.
fn matrix_is_complete(experiment: &DiscriminatingExperiment) -> bool {
    if experiment.outcome_matrix.len() != ExperimentOutcomeKind::ALL.len() {
        return false;
    }
    let mut seen = [false; 6];
    for mapping in &experiment.outcome_matrix {
        let slot = match mapping.outcome {
            ExperimentOutcomeKind::Success => 0,
            ExperimentOutcomeKind::NoChange => 1,
            ExperimentOutcomeKind::Regression => 2,
            ExperimentOutcomeKind::Unavailable => 3,
            ExperimentOutcomeKind::Unknown => 4,
            ExperimentOutcomeKind::InstrumentFailure => 5,
        };
        if seen[slot] {
            return false;
        }
        seen[slot] = true;
    }
    let mut index = 0usize;
    while index < seen.len() {
        if !seen[index] {
            return false;
        }
        index = index.saturating_add(1);
    }
    true
}

/// Returns true when the experiment text trips any forbidden marker.
fn experiment_trips_markers(experiment: &DiscriminatingExperiment) -> bool {
    let fields = [
        experiment.cost_note.as_str(),
        experiment.risk_note.as_str(),
        experiment.effect_note.as_str(),
        experiment.time_note.as_str(),
        experiment.cancel_note.as_str(),
        experiment.cleanup_note.as_str(),
        experiment.rollback_note.as_str(),
    ];
    let mut index = 0usize;
    while index < fields.len() {
        if let Some(field) = fields.get(index) {
            let low = lowered(field);
            if mentions_any(&low, ORACLE_MARKERS) || mentions_any(&low, SCOPE_ESCAPE_MARKERS) {
                return true;
            }
        }
        index = index.saturating_add(1);
    }
    for mapping in &experiment.outcome_matrix {
        let low = lowered(&mapping.rival_effect);
        if mentions_any(&low, ORACLE_MARKERS) || mentions_any(&low, SCOPE_ESCAPE_MARKERS) {
            return true;
        }
    }
    false
}

/// Collects the predicted observations of a live rival by identity.
fn predictions_of<'a>(rivals: &'a [RivalMechanism], identity: &str) -> Option<&'a [String]> {
    for rival in rivals {
        if rival.rival_id.as_str() == identity {
            return Some(rival.predicted_observations.as_slice());
        }
    }
    None
}

/// Returns true when the rival identity is currently live.
fn is_live_rival(rivals: &[RivalMechanism], identity: &str) -> bool {
    for rival in rivals {
        if rival.rival_id.as_str() == identity && matches!(rival.status, RivalStatus::Live) {
            return true;
        }
    }
    false
}

/// Returns true when the assumption is declared by a live rival.
fn assumption_is_live(rivals: &[RivalMechanism], assumption: &str) -> bool {
    for rival in rivals {
        if matches!(rival.status, RivalStatus::Live) {
            for declared in &rival.assumptions {
                if declared.as_str() == assumption {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns true when two prediction sets are identical as sorted sets.
fn predictions_identical(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut ordered_left = left.to_vec();
    let mut ordered_right = right.to_vec();
    ordered_left.sort();
    ordered_right.sort();
    ordered_left == ordered_right
}

/// Returns true when the experiment separates two live divergent rivals.
fn separates_live_rivals(experiment: &DiscriminatingExperiment, rivals: &[RivalMechanism]) -> bool {
    if experiment.primary_rival.as_str() == experiment.secondary_rival.as_str() {
        return false;
    }
    if !is_live_rival(rivals, &experiment.primary_rival) {
        return false;
    }
    if !is_live_rival(rivals, &experiment.secondary_rival) {
        return false;
    }
    let left = predictions_of(rivals, &experiment.primary_rival);
    let right = predictions_of(rivals, &experiment.secondary_rival);
    match (left, right) {
        (Some(left), Some(right)) => !predictions_identical(left, right),
        (Some(_) | None, None) | (None, Some(_)) => false,
    }
}

/// Returns true when the experiment resolves one live blocking assumption.
fn resolves_live_assumption(
    experiment: &DiscriminatingExperiment,
    rivals: &[RivalMechanism],
) -> bool {
    match &experiment.resolves_assumption {
        Some(assumption) => assumption_is_live(rivals, assumption),
        None => false,
    }
}

/// Returns true when the experiment is fully qualified for selection.
fn experiment_is_qualified(
    experiment: &DiscriminatingExperiment,
    rivals: &[RivalMechanism],
) -> bool {
    if experiment.controlled_variables.is_empty() {
        return false;
    }
    if !matrix_is_complete(experiment) {
        return false;
    }
    if experiment_trips_markers(experiment) {
        return false;
    }
    separates_live_rivals(experiment, rivals) || resolves_live_assumption(experiment, rivals)
}

/// Selects the minimum admissible experiment under the explicit order.
///
/// Noncompensating order with a stable tie-break: the lowest-index
/// experiment separating two live divergent rivals wins first; only when no
/// such experiment exists, the lowest-index experiment resolving a live
/// blocking assumption wins. No weighted utility is ever computed.
fn select_experiment(
    experiments: &[DiscriminatingExperiment],
    rivals: &[RivalMechanism],
) -> Option<usize> {
    let mut index = 0usize;
    while index < experiments.len() {
        if let Some(experiment) = experiments.get(index) {
            if experiment.controlled_variables.is_empty()
                || !matrix_is_complete(experiment)
                || experiment_trips_markers(experiment)
            {
                index = index.saturating_add(1);
                continue;
            }
            if separates_live_rivals(experiment, rivals) {
                return Some(index);
            }
        }
        index = index.saturating_add(1);
    }
    let mut fallback = 0usize;
    while fallback < experiments.len() {
        if let Some(experiment) = experiments.get(fallback)
            && experiment_is_qualified(experiment, rivals)
            && resolves_live_assumption(experiment, rivals)
        {
            return Some(fallback);
        }
        fallback = fallback.saturating_add(1);
    }
    None
}

// ---------------------------------------------------------------------------
// Emission.
// ---------------------------------------------------------------------------

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &DiagnosisOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        DiagnosisOutcome::Complete => None,
        DiagnosisOutcome::Partial => Some(CurationRejectionCode::PreservationFailed),
        DiagnosisOutcome::Insufficient => Some(CurationRejectionCode::UnsupportedPrecision),
        DiagnosisOutcome::MechanismReviewRequired
        | DiagnosisOutcome::Stale
        | DiagnosisOutcome::Rejected => Some(CurationRejectionCode::IdentityMismatch),
    }
}

/// Builds the seven-dimension preservation report for one candidate.
fn build_preservation() -> Result<PreservationReport, DiagnosisError> {
    let notes = [
        (
            "coverage",
            "every attempt, rival, evidence, and experiment denominator is accounted without silent drops",
        ),
        (
            "faithfulness",
            "proxy signals are never promoted to product delta; repair outcomes never eliminate rivals",
        ),
        (
            "lineage",
            "gap, discriminator, lineage, conflict, rival, and experiment bindings trace to supplied inputs",
        ),
        (
            "reversibility",
            "the inert recommendation carries an owned rollback boundary and changes nothing",
        ),
        (
            "authority_ceiling",
            "the candidate proposes only; ownership, execution, promotion, and finish stay external",
        ),
        (
            "dependency_closure",
            "only the contracts hub is imported; conflict bytes stay frozen and no algorithm is invoked",
        ),
        (
            "provenance_retention",
            "live and falsified rivals, counterevidence, unknowns, and common-mode lineage are retained",
        ),
    ];
    let mut verdicts: Vec<DimensionVerdict> = Vec::with_capacity(EXPECTED_PRESERVATION_DIMENSIONS);
    let mut index = 0usize;
    while index < notes.len() {
        if let Some((dimension, note)) = notes.get(index) {
            let parsed = match PreservationDimension::parse(dimension) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(DiagnosisError::Denominator {
                        detail: redact(&err.to_string()),
                    });
                }
            };
            verdicts.push(DimensionVerdict {
                dimension: parsed,
                passed: true,
                known: true,
                note: note.to_string(),
            });
        }
        index = index.saturating_add(1);
    }
    let report = PreservationReport { verdicts };
    report
        .validate()
        .map_err(|err| DiagnosisError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    Ok(report)
}

/// Builds one assessment per rival in supplied causal order.
fn build_rival_assessments(rivals: &[RivalMechanism]) -> Vec<RivalAssessment> {
    let mut out: Vec<RivalAssessment> = Vec::with_capacity(rivals.len());
    for rival in rivals {
        let falsifying = match rival.status {
            RivalStatus::Live => None,
            RivalStatus::Falsified => rival.counterevidence_refs.first().cloned(),
        };
        out.push(RivalAssessment {
            rival_id: rival.rival_id.clone(),
            status: rival.status,
            reason: rival.status_reason.clone(),
            falsifying_evidence: falsifying,
        });
    }
    out
}

/// Counts live and falsified rivals in the supplied set.
fn count_rival_statuses(rivals: &[RivalMechanism]) -> (usize, usize) {
    let mut live = 0usize;
    let mut falsified = 0usize;
    for rival in rivals {
        match rival.status {
            RivalStatus::Live => live = live.saturating_add(1),
            RivalStatus::Falsified => falsified = falsified.saturating_add(1),
        }
    }
    (live, falsified)
}

/// Collects the exact expected-attempt denominator in supplied order.
fn attempt_denominator_of(history: &RepairHistory) -> Vec<String> {
    history.expected_attempt_ids.clone()
}

/// Computes the deterministic digest binding the diagnosis inputs.
///
/// Ten explicit bindings mirror the canonical typed equivalent of the
/// development-diagnosis contract; bundling them would hide load-bearing
/// distinctions at the digest boundary.
#[allow(clippy::too_many_arguments)]
fn compute_diagnosis_digest(
    handle: &str,
    outcome_spelling: &str,
    product: &ProductGap,
    discriminator: &DiscriminatorEvidence,
    history: &RepairHistory,
    conflict: &FrozenConflictAnalysis,
    rivals: &[RivalMechanism],
    selected: Option<&DiscriminatingExperiment>,
    policy: &DiagnosisPolicy,
    receipt_digest: &str,
) -> Result<String, DiagnosisError> {
    let mut parts: Vec<String> = vec![
        ["handle:", handle].concat(),
        ["outcome:", outcome_spelling].concat(),
        ["product:", &product.product_id].concat(),
        ["source:", &product.source_revision].concat(),
        ["objective:", &product.objective_id].concat(),
        ["gap:", product.kind.as_str()].concat(),
        ["discriminator:", &discriminator.discriminator_id].concat(),
        [
            "observation:",
            observation_class(&discriminator.observation),
        ]
        .concat(),
        ["lineage:", &history.lineage_id].concat(),
        ["conflict:", &conflict.digest].concat(),
        ["policy:", &policy.policy_id].concat(),
        ["receipt:", receipt_digest].concat(),
    ];
    for attempt in &history.attempts {
        parts.push(
            [
                "attempt:",
                &attempt.attempt_id,
                "|",
                &attempt.equivalence_digest,
            ]
            .concat(),
        );
    }
    for rival in rivals {
        parts.push(["rival:", &rival.rival_id, "|", rival.status.as_str()].concat());
    }
    match selected {
        Some(experiment) => {
            parts.push(["experiment:", &experiment.experiment_id].concat());
        }
        None => parts.push("experiment:none".to_owned()),
    }
    canonical_json_bytes(&parts).map_or_else(
        |err| {
            Err(DiagnosisError::Digest {
                detail: redact(&err.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

/// Builds the fixed forbidden-surface list for every recommendation.
fn forbidden_paths() -> Vec<String> {
    [
        "oracle, acceptance, or verifier weakening",
        "unrelated refactor outside the recommended scope",
        "source, artifact, configuration, or runtime mutation beyond the recommended scope",
        "executing a repair as established truth; the recommendation is inert",
    ]
    .iter()
    .map(|entry| (*entry).to_owned())
    .collect()
}

/// Emits one inert candidate envelope for the decided outcome.
///
/// Twelve explicit bindings keep every emission input visible at the single
/// construction boundary; bundling them would hide load-bearing distinctions.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn emit_candidate(
    outcome: DiagnosisOutcome,
    product: &ProductGap,
    discriminator: &DiscriminatorEvidence,
    history: &RepairHistory,
    conflict: &FrozenConflictAnalysis,
    rivals: &[RivalMechanism],
    common_mode: &CommonModeDisclosure,
    selected: Option<DiscriminatingExperiment>,
    experiments: &[DiscriminatingExperiment],
    policy: &DiagnosisPolicy,
    receipt_digest: &str,
    note: &str,
) -> Result<DevelopmentDiagnosisCandidate, DiagnosisError> {
    let handle = ["diag-", &discriminator.discriminator_id].concat();
    check_handle(&handle, "diagnosis.handle")?;
    let (live, falsified) = count_rival_statuses(rivals);
    let strongest = if live == 1 && falsified >= 1 {
        let mut found: Option<String> = None;
        for rival in rivals {
            if matches!(rival.status, RivalStatus::Live) {
                found = Some(rival.rival_id.clone());
                break;
            }
        }
        found
    } else {
        None
    };
    let strongest_limits = if strongest.is_some() {
        "strongest-current only with exact elimination evidence and candidate-only limits"
    } else {
        "no single strongest rival is claimed"
    }
    .to_owned();
    let recommendation = match &selected {
        Some(experiment) => {
            let scope = if separates_live_rivals(experiment, rivals) {
                [
                    "experiment ",
                    &experiment.experiment_id,
                    " by ",
                    &experiment.owner,
                    " separating ",
                    &experiment.primary_rival,
                    " and ",
                    &experiment.secondary_rival,
                    " under discriminator ",
                    &discriminator.discriminator_id,
                    " within product ",
                    &product.product_id,
                    "@",
                    &product.source_revision,
                ]
                .concat()
            } else {
                [
                    "experiment ",
                    &experiment.experiment_id,
                    " by ",
                    &experiment.owner,
                    " resolving blocking assumption ",
                    experiment
                        .resolves_assumption
                        .as_deref()
                        .unwrap_or("unknown"),
                    " under discriminator ",
                    &discriminator.discriminator_id,
                ]
                .concat()
            };
            RepairRecommendation {
                owner: experiment.owner.clone(),
                minimal_scope: scope,
                forbidden_paths: forbidden_paths(),
                old_discriminator: discriminator.discriminator_id.clone(),
                new_discriminator: discriminator.discriminator_id.clone(),
                rollback_note: experiment.rollback_note.clone(),
            }
        }
        None => RepairRecommendation {
            owner: "human-or-architecture-owner".to_owned(),
            minimal_scope: "no safe discriminating experiment exists in the declared set"
                .to_owned(),
            forbidden_paths: forbidden_paths(),
            old_discriminator: discriminator.discriminator_id.clone(),
            new_discriminator: discriminator.discriminator_id.clone(),
            rollback_note: "no experiment runs, so no rollback is owed".to_owned(),
        },
    };
    let next_evidence = match &selected {
        Some(experiment) => [
            "external edge evidence from ",
            &experiment.owner,
            " running ",
            &experiment.experiment_id,
            " verified by ",
            &experiment.verifier,
            "; product pulse ",
            NEXT_EVIDENCE_PULSE,
            " remains external",
        ]
        .concat(),
        None => [
            "human or architecture owner supplies the blocking evidence; product pulse ",
            NEXT_EVIDENCE_PULSE,
            " remains external",
        ]
        .concat(),
    };
    let preservation = build_preservation()?;
    let digest = compute_diagnosis_digest(
        &handle,
        outcome.as_str(),
        product,
        discriminator,
        history,
        conflict,
        rivals,
        selected.as_ref(),
        policy,
        receipt_digest,
    )?;
    Ok(DevelopmentDiagnosisCandidate {
        outcome,
        diagnosis_handle: handle,
        product_id: product.product_id.clone(),
        source_revision: product.source_revision.clone(),
        objective_id: product.objective_id.clone(),
        gap_kind: product.kind.as_str().to_owned(),
        rivals: build_rival_assessments(rivals),
        rivals_live: live,
        rivals_falsified: falsified,
        strongest_current: strongest,
        strongest_limits_note: strongest_limits,
        common_mode: common_mode.clone(),
        recommended_experiment: selected,
        recommendation,
        next_evidence_note: next_evidence,
        preservation,
        input_receipt_digest: receipt_digest.to_owned(),
        attempt_denominator: attempt_denominator_of(history),
        experiments_considered: experiments.len(),
        candidate_digest: digest,
        note: note.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Canonical entry point.
// ---------------------------------------------------------------------------

/// Diagnoses one bounded development gap as a falsifiable candidate.
///
/// The ten parameters are the canonical typed equivalent of
/// `diagnose_development_gap`: the validated job, the validated draft with
/// its pre-handler A-05 receipt, the Product gap, the current discriminator
/// evidence, the complete repair history, the frozen optional conflict
/// projection, the rival set, the shared common-mode disclosure, the finite
/// experiment alternatives, and the governing policy. Every parameter is an
/// immutable supplied observation; nothing is queried, executed, or created.
///
/// # Errors
///
/// Returns [`DiagnosisError`] only for malformed, mismatched, over-bound, or
/// stale inputs. Every semantic shortfall is an inert
/// [`DevelopmentDiagnosisCandidate`] outcome instead.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn diagnose_development_gap(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    product: &ProductGap,
    discriminator: &DiscriminatorEvidence,
    repairs: &RepairHistory,
    conflict: &FrozenConflictAnalysis,
    rivals: &[RivalMechanism],
    common_mode: &CommonModeDisclosure,
    experiments: &[DiscriminatingExperiment],
    policy: &DiagnosisPolicy,
) -> Result<DevelopmentDiagnosisCandidate, DiagnosisError> {
    validate_policy_shapes(policy)?;
    validate_product_shapes(product)?;
    validate_discriminator_shapes(discriminator)?;
    validate_repair_shapes(repairs)?;
    validate_conflict_shapes(conflict)?;
    validate_rival_shapes(rivals, policy)?;
    validate_common_mode_shapes(common_mode)?;
    validate_experiment_shapes(experiments, policy)?;
    preflight_total_bytes(product, discriminator, repairs, rivals, experiments, policy)?;
    intrinsic_receipt_checks(draft)?;
    intrinsic_binding_checks(job, draft, policy)?;
    intrinsic_repair_denominator(repairs)?;
    validate_repeat_predecessors(repairs)?;
    for rival in rivals {
        if let Err(err) = validate_rival_semantics(rival) {
            let detail = err.to_string();
            return emit_candidate(
                DiagnosisOutcome::Rejected,
                product,
                discriminator,
                repairs,
                conflict,
                rivals,
                common_mode,
                None,
                experiments,
                policy,
                &draft.receipt.output_digest,
                &redact(&detail),
            );
        }
    }
    if discriminator.context_digest != product.context_digest {
        return Err(DiagnosisError::Binding {
            field: "discriminator.context",
            detail: "discriminator context drifts from the product context".to_owned(),
        });
    }
    if policy.cancelled {
        return emit_candidate(
            DiagnosisOutcome::Rejected,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "cancelled before emission; zero effects were produced",
        );
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return emit_candidate(
            DiagnosisOutcome::Stale,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "observation is at or beyond the frozen deadline; replay against the new revision",
        );
    }
    let gap = evaluate_gap(product)?;
    if matches!(gap, GapVerdict::ProxyOnly) {
        return emit_candidate(
            DiagnosisOutcome::Rejected,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "proxy or activity signals cannot prove product delta without an evidence-backed user-outcome mapping",
        );
    }
    match evaluate_discriminator(discriminator) {
        DiscriminatorVerdict::Passing => {
            return emit_candidate(
                DiagnosisOutcome::Rejected,
                product,
                discriminator,
                repairs,
                conflict,
                rivals,
                common_mode,
                None,
                experiments,
                policy,
                &draft.receipt.output_digest,
                "a current passing discriminator cannot prove a current failure",
            );
        }
        DiscriminatorVerdict::Invalid => {
            return emit_candidate(
                DiagnosisOutcome::Rejected,
                product,
                discriminator,
                repairs,
                conflict,
                rivals,
                common_mode,
                None,
                experiments,
                policy,
                &draft.receipt.output_digest,
                "unsatisfied preconditions or a missing replay contract keep the discriminator from proving anything",
            );
        }
        DiscriminatorVerdict::Unconfirmed => {
            return emit_candidate(
                DiagnosisOutcome::Insufficient,
                product,
                discriminator,
                repairs,
                conflict,
                rivals,
                common_mode,
                None,
                experiments,
                policy,
                &draft.receipt.output_digest,
                "post-hoc evidence requires independent confirmation before it can ground a diagnosis",
            );
        }
        DiscriminatorVerdict::Insufficient => {
            return emit_candidate(
                DiagnosisOutcome::Insufficient,
                product,
                discriminator,
                repairs,
                conflict,
                rivals,
                common_mode,
                None,
                experiments,
                policy,
                &draft.receipt.output_digest,
                "explicit unknown, censored, or infrastructure-only observation supports only insufficiency",
            );
        }
        DiscriminatorVerdict::Failing => {}
    }
    if matches!(gap, GapVerdict::Unknown) {
        return emit_candidate(
            DiagnosisOutcome::Insufficient,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "unknown instrumentation is neither success nor failure",
        );
    }
    if equivalent_retry_without_justification(repairs) {
        return emit_candidate(
            DiagnosisOutcome::MechanismReviewRequired,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "an equivalent repair repeats without new hypothesis, evidence, discriminator, conditions, or justified controlled repetition",
        );
    }
    if conflict.required && !conflict.present {
        return emit_candidate(
            DiagnosisOutcome::Insufficient,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "the recipe requires conflict analysis and the mandatory projection is missing",
        );
    }
    if matches!(repairs.presence, RepairHistoryPresence::Unknown) {
        return emit_candidate(
            DiagnosisOutcome::Insufficient,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "unknown repair-history presence leaves the attempt denominator incomplete",
        );
    }
    let (live, _) = count_rival_statuses(rivals);
    if live == 0 {
        return emit_candidate(
            DiagnosisOutcome::Insufficient,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "no live falsifiable rival remains in the declared set",
        );
    }
    let selected_index = select_experiment(experiments, rivals);
    match selected_index {
        Some(index) => {
            let selected = match experiments.get(index) {
                Some(selected) => selected.clone(),
                None => {
                    return Err(DiagnosisError::Denominator {
                        detail: "selected experiment index is out of range".to_owned(),
                    });
                }
            };
            let note = if matches!(gap, GapVerdict::Partial) {
                "partial product gap with a discriminating experiment and named open unknowns"
            } else {
                DIAGNOSIS_PROOF_NOTE
            };
            let outcome = if matches!(gap, GapVerdict::Partial) {
                DiagnosisOutcome::Partial
            } else {
                DiagnosisOutcome::Complete
            };
            emit_candidate(
                outcome,
                product,
                discriminator,
                repairs,
                conflict,
                rivals,
                common_mode,
                Some(selected),
                experiments,
                policy,
                &draft.receipt.output_digest,
                note,
            )
        }
        None => emit_candidate(
            DiagnosisOutcome::Insufficient,
            product,
            discriminator,
            repairs,
            conflict,
            rivals,
            common_mode,
            None,
            experiments,
            policy,
            &draft.receipt.output_digest,
            "no safe experiment in the declared set separates live rivals or resolves a blocking assumption",
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests (proportionate: 11 of 51 cases; remainder deferred per START.md s1).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::CommonModeDisclosure;
    use super::ControlledRepeat;
    use super::DevelopmentDiagnosisCandidate;
    use super::DiagnosisOutcome;
    use super::DiagnosisPolicy;
    use super::DiscriminatingExperiment;
    use super::DiscriminatorEvidence;
    use super::ExperimentOutcomeKind;
    use super::ExperimentOutcomeMapping;
    use super::FrozenConflictAnalysis;
    use super::ProductGap;
    use super::ProductGapKind;
    use super::RepairAttemptSummary;
    use super::RepairHistory;
    use super::RivalMechanism;
    use super::RivalStatus;
    use super::SLICE1_IMPLEMENTED_CASES;
    use super::SLICE1_REMAINDER_CASES;
    use super::SLICE2_IMPLEMENTED_CASES;
    use super::SLICE2_REMAINDER_CASES;
    use super::diagnose_development_gap;
    use super::is_hex64_lower;
    use super::outcome_rejection_hint;
    use eliot_contracts::EpochId;
    use eliot_contracts::EpochLineageId;
    use eliot_contracts::ResourceGeneration;
    use eliot_dreamer_contracts::BudgetLimits;
    use eliot_dreamer_contracts::CurrentObservation;
    use eliot_dreamer_contracts::DreamJobAdmission;
    use eliot_dreamer_contracts::JobClass;
    use eliot_dreamer_contracts::MechanismExercise;
    use eliot_dreamer_contracts::RepairEventOutcome;
    use eliot_dreamer_contracts::RepairHistoryPresence;
    use eliot_dreamer_contracts::RepeatReason;
    use eliot_dreamer_contracts::Requester;
    use eliot_dreamer_contracts::RequesterOrigin;
    use eliot_dreamer_contracts::UnavailableEvidence;
    use eliot_dreamer_contracts::UnavailableField;
    use eliot_dreamer_contracts::ValidatedDreamDraft;
    use eliot_dreamer_contracts::ValidationReceipt;
    use std::num::NonZeroU64;

    /// Returns the test state fence at genesis.
    fn test_fence() -> eliot_contracts::StateFence {
        let Ok(lineage) = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("test sequence must be nonzero");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("test epoch must build");
        };
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    /// Returns test budget limits covering every dimension.
    fn test_budget() -> BudgetLimits {
        BudgetLimits {
            input_bytes: Some(1024),
            output_bytes: Some(1024),
            source_width: Some(8),
            reference_width: Some(8),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(1000),
            work_fan_out: Some(2),
            report_bytes: Some(1024),
            max_stu: Some(10),
        }
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

    /// Returns a development-diagnosis job bound to the test receipt.
    fn test_job() -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::DevelopmentDiagnosis,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-1".to_owned(),
            policy_ref: "policy-1".to_owned(),
            budget: test_budget(),
            deadline_ms: None,
            frozen_manifest_digest: "c".repeat(64),
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

    /// Returns a valid product failure gap with cited evidence.
    fn test_product() -> ProductGap {
        ProductGap {
            objective_id: "obj-1".to_owned(),
            objective_revision: 3,
            acceptance_digest: "1".repeat(64),
            recovery_digest: "2".repeat(64),
            product_id: "product-1".to_owned(),
            source_revision: "rev-9".to_owned(),
            feature_ref: "feature-checkout".to_owned(),
            workflow_ref: "workflow-purchase".to_owned(),
            user_outcome_ref: "outcome-order-placed".to_owned(),
            kind: ProductGapKind::ProductFailure,
            gap_note: "checkout confirmation never renders for order batch seven".to_owned(),
            proxy_mapping_note: None,
            evidence_refs: ["ev-1".to_owned()].to_vec(),
            context_digest: "3".repeat(64),
        }
    }

    /// Returns a valid currently failing predeclared discriminator.
    fn test_discriminator() -> DiscriminatorEvidence {
        DiscriminatorEvidence {
            discriminator_id: "disc-1".to_owned(),
            owner: "owner-1".to_owned(),
            expected_note: "confirmation renders within two seconds of order placement".to_owned(),
            observed_note: "confirmation absent after sixty seconds on run seven".to_owned(),
            observation: CurrentObservation::Fail {
                summary: "confirmation observable absent on the current path".to_owned(),
                observed: None,
                unavailable: Some(UnavailableEvidence {
                    field: UnavailableField::ObservedValue,
                    reason: "no canonical observation was recorded for run seven".to_owned(),
                }),
            },
            predeclared: true,
            independently_confirmed: false,
            preconditions_satisfied: true,
            precondition_note: "order batch seven placed under config nine".to_owned(),
            replayable: true,
            replay_id: "replay-1".to_owned(),
            replay_input_digest: Some("4".repeat(64)),
            context_digest: "3".repeat(64),
            coverage_note: "full instrument coverage without censoring".to_owned(),
        }
    }

    /// Returns one repair attempt with the given identity and digest.
    fn test_attempt(identity: &str, digest: &str) -> RepairAttemptSummary {
        RepairAttemptSummary {
            attempt_id: identity.to_owned(),
            equivalence_digest: digest.to_owned(),
            mechanism_id: ["mech-", identity].concat(),
            mechanism_note: ["exercised mechanism for ", identity].concat(),
            exercise: MechanismExercise::Exercised,
            outcome: RepairEventOutcome::Failed {
                summary: ["repair ", identity, " left the gap unchanged"].concat(),
            },
            controlled_repeat: None,
        }
    }

    /// Returns a valid two-attempt repair history with distinct mechanisms.
    fn test_repairs() -> RepairHistory {
        RepairHistory {
            presence: RepairHistoryPresence::OneOrMore,
            lineage_id: "lin-1".to_owned(),
            expected_attempt_ids: ["att-1".to_owned(), "att-2".to_owned()].to_vec(),
            attempts: [
                test_attempt("att-1", &"a".repeat(64)),
                test_attempt("att-2", &"b".repeat(64)),
            ]
            .to_vec(),
            lineage_digest: "5".repeat(64),
        }
    }

    /// Returns an optional-absent frozen conflict projection.
    fn test_conflict() -> FrozenConflictAnalysis {
        FrozenConflictAnalysis {
            required: false,
            present: false,
            digest: String::new(),
            scope_note: "conflict analysis is optional under the test recipe".to_owned(),
            coverage_note: "optional absence carries no rival coverage".to_owned(),
        }
    }

    /// Returns one live rival with the given identity and prediction.
    fn test_rival(identity: &str, prediction: &str) -> RivalMechanism {
        RivalMechanism {
            rival_id: identity.to_owned(),
            owner: ["owner-", identity].concat(),
            causal_boundary: ["mechanism boundary for ", identity].concat(),
            predicted_observations: [prediction.to_owned()].to_vec(),
            support_refs: ["ev-1".to_owned()].to_vec(),
            unknown_refs: Vec::new(),
            counterevidence_refs: Vec::new(),
            assumptions: ["assumption-load-holds".to_owned()].to_vec(),
            confounders: ["confounder-cache-warmth".to_owned()].to_vec(),
            falsifier: ["confirmation observed on replay under load for ", identity].concat(),
            prior_repair_relation: "prior repairs exercised a different mechanism".to_owned(),
            affected_invariant: "invariant-order-confirmation".to_owned(),
            status: RivalStatus::Live,
            status_reason: ["load-bearing prediction open for ", identity].concat(),
        }
    }

    /// Returns two live rivals with divergent predictions.
    fn test_rivals() -> Vec<RivalMechanism> {
        [
            test_rival("rival-a", "confirmation stays absent under load L"),
            test_rival("rival-b", "confirmation renders late under load L"),
        ]
        .to_vec()
    }

    /// Returns the shared common-mode disclosure.
    fn test_common_mode() -> CommonModeDisclosure {
        CommonModeDisclosure {
            shared_model_note: "no shared model lineage across rivals".to_owned(),
            shared_source_note: "both rivals read run seven from source rev nine".to_owned(),
            shared_evaluator_note: "verifier nine evaluates both rivals".to_owned(),
            shared_fixture_note: "no shared fixture lineage across rivals".to_owned(),
            uncertainty_note: "shared run seven keeps a common-mode observation risk".to_owned(),
        }
    }

    /// Returns the complete six-kind outcome matrix.
    fn test_matrix() -> Vec<ExperimentOutcomeMapping> {
        [
            (
                ExperimentOutcomeKind::Success,
                "rival-a falsified, rival-b stays live",
            ),
            (
                ExperimentOutcomeKind::NoChange,
                "both rivals stay live without new information",
            ),
            (
                ExperimentOutcomeKind::Regression,
                "both rivals stay live; escalation is owed",
            ),
            (
                ExperimentOutcomeKind::Unavailable,
                "experiment unavailable; both rivals stay live",
            ),
            (
                ExperimentOutcomeKind::Unknown,
                "unknown outcome preserves both rivals",
            ),
            (
                ExperimentOutcomeKind::InstrumentFailure,
                "instrument failure preserves both rivals",
            ),
        ]
        .iter()
        .map(|(outcome, effect)| ExperimentOutcomeMapping {
            outcome: *outcome,
            rival_effect: (*effect).to_owned(),
        })
        .collect()
    }

    /// Returns one qualified experiment separating the two test rivals.
    fn test_experiment() -> DiscriminatingExperiment {
        DiscriminatingExperiment {
            experiment_id: "exp-1".to_owned(),
            owner: "owner-9".to_owned(),
            verifier: "verifier-9".to_owned(),
            primary_rival: "rival-a".to_owned(),
            secondary_rival: "rival-b".to_owned(),
            resolves_assumption: None,
            controlled_variables: ["load-L".to_owned(), "config-nine".to_owned()].to_vec(),
            outcome_matrix: test_matrix(),
            cost_note: "one replay run under load L".to_owned(),
            risk_note: "read-only replay without production writes".to_owned(),
            effect_note: "no effect beyond the replay sandbox".to_owned(),
            time_note: "completes within five minutes".to_owned(),
            cancel_note: "cancel before replay start leaves no residue".to_owned(),
            cleanup_note: "replay sandbox is dropped after the run".to_owned(),
            rollback_note: "no production change is made, so no rollback is owed".to_owned(),
        }
    }

    /// Returns a valid governing policy for the test diagnosis.
    fn test_policy() -> DiagnosisPolicy {
        DiagnosisPolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_rivals: super::MAX_RIVALS,
            max_experiments: super::MAX_EXPERIMENTS,
            max_evidence_items: super::MAX_EVIDENCE_ITEMS,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            owner_note: "diagnosis owned by the dreamer cell".to_owned(),
        }
    }

    /// Runs the full valid fixture set through the entry point.
    fn run_valid() -> DevelopmentDiagnosisCandidate {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();
        let Ok(candidate) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("valid diagnosis must complete");
        };
        candidate
    }

    #[test]
    fn slice1_remainder_map_covers_the_declared_denominator() {
        let mut seen = [false; 52];
        for case in SLICE1_IMPLEMENTED_CASES
            .iter()
            .chain(SLICE1_REMAINDER_CASES.iter())
        {
            assert!((1..=51).contains(case));
            assert!(!seen[usize::from(*case)]);
            seen[usize::from(*case)] = true;
        }
        assert!(seen[1..].iter().all(|present| *present));
    }

    #[test]
    fn slice2_remainder_map_covers_the_declared_denominator() {
        let mut seen = [false; 52];
        for case in SLICE1_IMPLEMENTED_CASES
            .iter()
            .chain(SLICE2_IMPLEMENTED_CASES.iter())
            .chain(SLICE2_REMAINDER_CASES.iter())
        {
            assert!((1..=51).contains(case));
            assert!(!seen[usize::from(*case)]);
            seen[usize::from(*case)] = true;
        }
        assert!(seen[1..].iter().all(|present| *present));
    }

    // WORK_UNIT_CASE: 675/1
    #[test]
    fn case_01_valid_two_rival_diagnosis_recommends_minimal_experiment() {
        let candidate = run_valid();
        assert_eq!(candidate.outcome, DiagnosisOutcome::Complete);
        assert_eq!(candidate.diagnosis_handle, "diag-disc-1");
        assert_eq!(candidate.product_id, "product-1");
        assert_eq!(candidate.rivals.len(), 2);
        assert_eq!(candidate.rivals_live, 2);
        assert_eq!(candidate.rivals_falsified, 0);
        assert_eq!(candidate.strongest_current, None);
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert!(candidate.preservation.overall().is_ok());
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        let Some(selected) = candidate.recommended_experiment.as_ref() else {
            panic!("complete diagnosis must recommend an experiment");
        };
        assert_eq!(selected.experiment_id, "exp-1");
        assert_eq!(selected.outcome_matrix.len(), 6);
        assert_eq!(candidate.recommendation.owner, "owner-9");
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // WORK_UNIT_CASE: 675/2
    #[test]
    fn case_02_exact_objective_acceptance_recovery_identity_binds() {
        let candidate = run_valid();
        assert_eq!(candidate.objective_id, "obj-1");
        assert_eq!(candidate.product_id, "product-1");
        assert_eq!(candidate.source_revision, "rev-9");
        assert_eq!(candidate.gap_kind, "product_failure");

        let job = test_job();
        let draft = test_draft();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();

        let mut defaulted = test_product();
        defaulted.objective_revision = 0;
        let result = diagnose_development_gap(
            &job,
            &draft,
            &defaulted,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("defaulted objective revision must fail");
        };
        assert!(matches!(
            err,
            super::DiagnosisError::Shape {
                field: "product.objective-revision",
                ..
            }
        ));

        let mut bad_acceptance = test_product();
        bad_acceptance.acceptance_digest = "not-a-digest".to_owned();
        let result = diagnose_development_gap(
            &job,
            &draft,
            &bad_acceptance,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("inexact acceptance digest must fail");
        };
        assert!(matches!(err, super::DiagnosisError::Digest { .. }));

        let mut bad_recovery = test_product();
        bad_recovery.recovery_digest = "Z".repeat(64);
        let result = diagnose_development_gap(
            &job,
            &draft,
            &bad_recovery,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("inexact recovery digest must fail");
        };
        assert!(matches!(err, super::DiagnosisError::Digest { .. }));
    }

    // WORK_UNIT_CASE: 675/3
    #[test]
    fn case_03_wrong_job_payload_fails_closed() {
        let draft = test_draft();
        let product = test_product();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();

        let mut wrong_class = test_job();
        wrong_class.job_class = JobClass::Curation;
        let result = diagnose_development_gap(
            &wrong_class,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("non-diagnosis job class must fail");
        };
        assert!(matches!(
            err,
            super::DiagnosisError::Binding {
                field: "job_class",
                ..
            }
        ));

        let mut task_drift = test_job();
        task_drift.task_id = "task-other".to_owned();
        let result = diagnose_development_gap(
            &task_drift,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("task drift between job and draft must fail");
        };
        assert!(matches!(
            err,
            super::DiagnosisError::Binding {
                field: "task_id",
                ..
            }
        ));

        let mut scope_drift = test_job();
        scope_drift.scope_id = "scope-other".to_owned();
        let result = diagnose_development_gap(
            &scope_drift,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("scope drift between job and draft must fail");
        };
        assert!(matches!(
            err,
            super::DiagnosisError::Binding {
                field: "scope_id",
                ..
            }
        ));
    }

    // WORK_UNIT_CASE: 675/4
    #[test]
    fn case_04_fence_and_receipt_mismatch_fails_closed() {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let mut policy = test_policy();
        policy.policy_id = "policy-other".to_owned();
        let result = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("policy drift must fail");
        };
        assert!(matches!(err, super::DiagnosisError::Policy { .. }));
    }

    // WORK_UNIT_CASE: 675/5
    #[test]
    fn case_05_stale_source_context_drift_fails_closed() {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();

        let mut stale_discriminator = test_discriminator();
        stale_discriminator.context_digest = "9".repeat(64);
        let result = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &stale_discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("discriminator context drift must fail");
        };
        assert!(matches!(
            err,
            super::DiagnosisError::Binding {
                field: "discriminator.context",
                ..
            }
        ));

        let mut stale_product = test_product();
        stale_product.context_digest = "8".repeat(64);
        let discriminator = test_discriminator();
        let result = diagnose_development_gap(
            &job,
            &draft,
            &stale_product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        );
        let Err(err) = result else {
            panic!("product context drift must fail");
        };
        assert!(matches!(
            err,
            super::DiagnosisError::Binding {
                field: "discriminator.context",
                ..
            }
        ));
    }

    // WORK_UNIT_CASE: 675/8
    #[test]
    fn case_08_proxy_metric_cannot_prove_product_delta() {
        let job = test_job();
        let draft = test_draft();
        let mut product = test_product();
        product.kind = ProductGapKind::ProxyOnly;
        product.evidence_refs = Vec::new();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();
        let Ok(candidate) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("proxy gap stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DiagnosisOutcome::Rejected);
        assert_eq!(candidate.recommended_experiment, None);
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 675/11
    #[test]
    fn case_11_current_pass_discriminator_cannot_prove_failure() {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let mut discriminator = test_discriminator();
        discriminator.observation = CurrentObservation::Pass {
            summary: "confirmation rendered on the current path".to_owned(),
            observed: None,
            unavailable: Some(UnavailableEvidence {
                field: UnavailableField::ObservedValue,
                reason: "value withheld by the test producer".to_owned(),
            }),
        };
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();
        let Ok(candidate) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("passing discriminator stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DiagnosisOutcome::Rejected);
        assert_eq!(candidate.recommended_experiment, None);
    }

    // WORK_UNIT_CASE: 675/15
    #[test]
    fn case_15_unchanged_equivalent_retry_requires_mechanism_review() {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let discriminator = test_discriminator();
        let mut repairs = test_repairs();
        let mut repeated = test_attempt("att-3", &"a".repeat(64));
        repeated.controlled_repeat = None;
        repairs.expected_attempt_ids.push("att-3".to_owned());
        repairs.attempts.push(repeated);
        let conflict = test_conflict();
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();
        let Ok(candidate) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("equivalent retry stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DiagnosisOutcome::MechanismReviewRequired);
        assert_eq!(candidate.recommended_experiment, None);
        let mut justified = test_repairs();
        let mut repeated_ok = test_attempt("att-3", &"a".repeat(64));
        repeated_ok.controlled_repeat = Some(ControlledRepeat {
            reason: RepeatReason::ControlledComparison,
            prior_attempt_id: "att-1".to_owned(),
            explanation: "repeats att-1 under new load evidence with the same mechanism".to_owned(),
            new_information: true,
            changed_conditions: false,
        });
        justified.expected_attempt_ids.push("att-3".to_owned());
        justified.attempts.push(repeated_ok);
        let Ok(controlled) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &justified,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("controlled repeat stays admissible");
        };
        assert_eq!(controlled.outcome, DiagnosisOutcome::Complete);
    }

    // WORK_UNIT_CASE: 675/21
    #[test]
    fn case_21_mandatory_conflict_missing_yields_insufficiency() {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = FrozenConflictAnalysis {
            required: true,
            present: false,
            digest: String::new(),
            scope_note: "the recipe requires conflict analysis here".to_owned(),
            coverage_note: "no frozen projection was supplied".to_owned(),
        };
        let rivals = test_rivals();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();
        let Ok(candidate) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("missing mandatory conflict stays inert");
        };
        assert_eq!(candidate.outcome, DiagnosisOutcome::Insufficient);
        assert_eq!(candidate.recommended_experiment, None);
    }

    // WORK_UNIT_CASE: 675/32
    #[test]
    fn case_32_identical_predictions_are_nondiscriminative() {
        let job = test_job();
        let draft = test_draft();
        let product = test_product();
        let discriminator = test_discriminator();
        let repairs = test_repairs();
        let conflict = test_conflict();
        let rivals = [
            test_rival("rival-a", "confirmation stays absent under load L"),
            test_rival("rival-b", "confirmation stays absent under load L"),
        ]
        .to_vec();
        let common_mode = test_common_mode();
        let experiments = [test_experiment()].to_vec();
        let policy = test_policy();
        let Ok(candidate) = diagnose_development_gap(
            &job,
            &draft,
            &product,
            &discriminator,
            &repairs,
            &conflict,
            &rivals,
            &common_mode,
            &experiments,
            &policy,
        ) else {
            panic!("nondiscriminative set stays inert");
        };
        assert_eq!(candidate.outcome, DiagnosisOutcome::Insufficient);
        assert_eq!(candidate.recommended_experiment, None);
    }

    // WORK_UNIT_CASE: 675/45
    #[test]
    fn case_45_exact_replay_is_deterministic() {
        let first = run_valid();
        let second = run_valid();
        assert_eq!(first.outcome, DiagnosisOutcome::Complete);
        assert_eq!(first.candidate_digest, second.candidate_digest);
        assert_eq!(first, second);
    }
}
